package service

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/lefterry/synoharbor/internal/broker"
	"github.com/lefterry/synoharbor/internal/dsm"
	"github.com/lefterry/synoharbor/internal/model"
	"github.com/lefterry/synoharbor/internal/store"
)

type replacement struct {
	model.Meta
	Old        model.CertificateProfile `json:"old"`
	NewID      string                   `json:"newId"`
	WasDefault bool                     `json:"wasDefault"`
	Done       bool                     `json:"done"`
}

// A durable replacement keeps the old live certificate until its fresh key,
// native certificate, service bindings and HTTPS endpoints have all succeeded.
// Restart/retry always resumes the same new profile and stored material.
func (a *App) ReplaceCertificate(ctx context.Context, id string) error {
	var record replacement
	e := a.Store.Get("replacements", id, &record)
	if e != nil && !store.NotFound(e) {
		return e
	}
	if store.NotFound(e) {
		var old model.CertificateProfile
		if e = a.Store.Get("certificates", id, &old); e != nil {
			return e
		}
		if old.ExternalDeleted || old.NativeID == "" || old.Staging {
			return errors.New("select an existing deployed production certificate")
		}
		var info map[string]string
		if e = a.Broker.Call(ctx, broker.Request{Action: "native-certificate-info", ID: old.NativeID}, &info); e != nil {
			return e
		}
		fp, _, e := dsm.Fingerprint([]byte(info["certificate"]))
		if e != nil || fp != old.Fingerprint {
			return errors.New("native certificate changed; refresh before replacing it")
		}
		record = replacement{Meta: model.Meta{ID: id}, Old: old, NewID: uuid.NewString(), WasDefault: info["isDefault"] == "true"}
		if e = a.Store.Put("replacements", &record.Meta, &record); e != nil {
			return e
		}
	}
	if record.Done {
		return nil
	}
	var old model.CertificateProfile
	if a.Store.Get("certificates", id, &old) == nil && old.Managed {
		old.Managed = false
		old.AutoRenew = false
		old.Status = "replacing"
		old.Message = "Serving the previous certificate until replacement is verified"
		if e = a.Store.Put("certificates", &old.Meta, &old); e != nil {
			return e
		}
	}
	a.ACME.Stop(id)
	var fresh model.CertificateProfile
	if e = a.Store.Get("certificates", record.NewID, &fresh); store.NotFound(e) {
		fresh = record.Old
		fresh.Meta = model.Meta{ID: record.NewID}
		fresh.NativeID = ""
		fresh.Fingerprint = ""
		fresh.PendingFingerprint = ""
		fresh.ExpiresAt = time.Time{}
		fresh.LastDeployed = time.Time{}
		fresh.Managed = true
		fresh.AutoRenew = record.Old.AutoRenew
		fresh.Status = "queued"
		fresh.Message = "Fresh independent certificate replacement"
		if e = a.Store.Put("certificates", &fresh.Meta, &fresh); e != nil {
			return e
		}
	} else if e != nil {
		return e
	}
	if fresh.NativeID == "" || fresh.PendingFingerprint != "" || fresh.Fingerprint == "" {
		if e = a.Certificate(ctx, fresh.ID, false, false); e != nil {
			return e
		}
		if e = a.Store.Get("certificates", fresh.ID, &fresh); e != nil {
			return e
		}
	}
	fresh.Status = "linking"
	fresh.Message = "Moving native service assignments to the new certificate"
	if e = a.Store.Put("certificates", &fresh.Meta, &fresh); e != nil {
		return e
	}
	if e = a.withDSM(ctx, false, "", func(c *dsm.Client) error {
		snap, e := c.Snapshot(ctx)
		if e != nil {
			return e
		}
		if nativeObject(snap.Certificates, record.Old.NativeID) != nil {
			if e = a.rememberCertificate(ctx, snap, record.Old.NativeID); e != nil {
				return e
			}
			if e = a.rememberBindings(snap, record.Old.NativeID, fresh.NativeID); e != nil {
				return e
			}
		}
		if record.WasDefault {
			state := a.recoveryState()
			if state.DefaultBefore == "" {
				state.DefaultBefore = record.Old.NativeID
			}
			state.DefaultAfter = fresh.NativeID
			if e = a.Store.Put("recovery", &state.Meta, &state); e != nil {
				return e
			}
		}
		return c.ReplaceBindings(ctx, record.Old.NativeID, fresh.NativeID, record.WasDefault)
	}); e != nil {
		return e
	}
	var hosts []model.ProxyHost
	if e = a.Store.List("proxies", &hosts); e != nil {
		return e
	}
	for _, host := range hosts {
		if host.ExternalDeleted || (host.CertificateID != id && host.CertificateID != fresh.ID) {
			continue
		}
		if host.CertificateID != fresh.ID {
			host.CertificateID = fresh.ID
			host.Status = "queued"
			if e = a.Store.Put("proxies", &host.Meta, &host); e != nil {
				return e
			}
		}
		if host.Enabled {
			if e = a.Proxy(ctx, host.ID); e != nil {
				return e
			}
		}
	}
	// Native service checks prevent removing a certificate still used elsewhere.
	if e = a.Delete(ctx, "certificates", id); e != nil && !store.NotFound(e) {
		return e
	}
	if e = a.Store.Get("certificates", fresh.ID, &fresh); e != nil {
		return e
	}
	fresh.Status = "ready"
	fresh.Message = "Fresh certificate and native assignments verified"
	if e = a.Store.Put("certificates", &fresh.Meta, &fresh); e != nil {
		return e
	}
	record.Done = true
	return a.Store.Put("replacements", &record.Meta, &record)
}
