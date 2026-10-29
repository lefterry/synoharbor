package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/lefterry/synoharbor/internal/broker"
	"github.com/lefterry/synoharbor/internal/dsm"
	"github.com/lefterry/synoharbor/internal/model"
	"github.com/lefterry/synoharbor/internal/recovery"
	"github.com/lefterry/synoharbor/internal/store"
)

// Before-images are captured before the first native mutation. Private keys are
// encrypted in secrets, never exposed by the journal or a recovery preview.
type NativeChange struct {
	model.Meta
	Kind              string          `json:"kind"`
	Name              string          `json:"name,omitempty"`
	NativeID          string          `json:"nativeId"`
	LoopbackPort      int             `json:"loopbackPort"`
	Before            model.DSMObject `json:"before,omitempty"`
	BeforeCertificate string          `json:"beforeCertificate,omitempty"`
	ExpectedHash      string          `json:"expectedHash"`
	Removed           bool            `json:"removed"`
	Restored          bool            `json:"restored"`
	RestoredID        string          `json:"restoredId,omitempty"`
}
type RecoveryState struct {
	model.Meta
	CapturedAt    time.Time `json:"capturedAt"`
	DefaultBefore string    `json:"defaultBefore"`
	DefaultAfter  string    `json:"defaultAfter"`
	HTTP2Before   *bool     `json:"http2Before,omitempty"`
	HTTP2After    *bool     `json:"http2After,omitempty"`
	Prepared      bool      `json:"prepared"`
	Preparing     bool      `json:"preparing"`
	BackupID      string    `json:"backupId"`
}
type RecoveryItem struct {
	Action   string `json:"action"`
	Kind     string `json:"kind"`
	NativeID string `json:"nativeId"`
	Name     string `json:"name"`
	Message  string `json:"message,omitempty"`
}
type RecoveryPlan struct {
	Items     []RecoveryItem `json:"items"`
	Conflicts []string       `json:"conflicts"`
	Token     string         `json:"token"`
	Prepared  bool           `json:"prepared"`
}

func (a *App) recoveryState() RecoveryState {
	var s RecoveryState
	_ = a.Store.Get("recovery", "main", &s)
	s.ID = "main"
	return s
}
func (a *App) managementPaused() bool { s := a.recoveryState(); return s.Preparing || s.Prepared }
func (a *App) RecoveryPaused() bool   { return a.managementPaused() }
func certificateFor(snap model.DSMSnapshot, proxy string) string {
	for _, c := range snap.Certificates {
		services, _ := c["services"].([]any)
		for _, v := range services {
			s, _ := v.(map[string]any)
			if dsm.String(s, "subscriber") == "ReverseProxy" && dsm.String(s, "service") == proxy {
				return dsm.ID(c)
			}
		}
	}
	return ""
}
func nativeObject(objects []model.DSMObject, id string) model.DSMObject {
	for _, o := range objects {
		if dsm.ID(o) == id {
			return o
		}
	}
	return nil
}
func (a *App) rememberProxy(snap model.DSMSnapshot, p model.ProxyHost) error {
	id := "proxy-" + p.ID
	var change NativeChange
	if e := a.Store.Get("native-changes", id, &change); e == nil {
		return nil
	} else if !store.NotFound(e) {
		return e
	}
	before := nativeObject(snap.Proxies, p.NativeID)
	change = NativeChange{Meta: model.Meta{ID: id}, Kind: "proxy", Name: p.Hostname, NativeID: p.NativeID, LoopbackPort: p.LoopbackPort, Before: before, BeforeCertificate: certificateFor(snap, p.NativeID)}
	if before != nil {
		change.ExpectedHash = model.Hash(before)
		if e := a.rememberCertificate(context.Background(), snap, change.BeforeCertificate); e != nil {
			return e
		}
	}
	return a.Store.Put("native-changes", &change.Meta, &change)
}
func (a *App) rememberCertificate(ctx context.Context, snap model.DSMSnapshot, id string) error {
	if id == "" {
		return nil
	}
	key := "certificate-" + id
	var change NativeChange
	if e := a.Store.Get("native-changes", key, &change); e == nil {
		return nil
	} else if !store.NotFound(e) {
		return e
	}
	before := nativeObject(snap.Certificates, id)
	if before == nil {
		return errors.New("cannot capture missing native certificate")
	}
	var material map[string]string
	if e := a.Broker.Call(ctx, broker.Request{Action: "native-certificate", ID: id}, &material); e != nil {
		return e
	}
	fp, _, e := dsm.Fingerprint([]byte(material["certificate"]))
	if e != nil {
		return e
	}
	if e = a.Store.PutSecret("recovery:"+id, material); e != nil {
		return e
	}
	change = NativeChange{Meta: model.Meta{ID: key}, Kind: "certificate", NativeID: id, Before: before, ExpectedHash: fp}
	if e = a.Store.Put("native-changes", &change.Meta, &change); e != nil {
		return e
	}
	var info map[string]string
	if e = a.Broker.Call(ctx, broker.Request{Action: "native-certificate-info", ID: id}, &info); e != nil {
		return e
	}
	if info["isDefault"] == "true" {
		s := a.recoveryState()
		if s.DefaultBefore == "" {
			s.DefaultBefore = id
			s.CapturedAt = time.Now().UTC()
			return a.Store.Put("recovery", &s.Meta, &s)
		}
	}
	return nil
}
func (a *App) recordProxy(p model.ProxyHost, o model.DSMObject) error {
	var ch NativeChange
	if e := a.Store.Get("native-changes", "proxy-"+p.ID, &ch); e != nil {
		return e
	}
	ch.NativeID = p.NativeID
	ch.ExpectedHash = model.Hash(o)
	ch.Removed = false
	return a.Store.Put("native-changes", &ch.Meta, &ch)
}
func (a *App) recordCertificate(p model.CertificateProfile) error {
	var ch NativeChange
	id := "certificate-" + p.NativeID
	e := a.Store.Get("native-changes", id, &ch)
	if store.NotFound(e) {
		ch = NativeChange{Meta: model.Meta{ID: id}, Kind: "certificate", NativeID: p.NativeID}
	} else if e != nil {
		return e
	}
	ch.Name = p.Domain
	ch.ExpectedHash = p.Fingerprint
	return a.Store.Put("native-changes", &ch.Meta, &ch)
}
func (a *App) markRemoved(kind, id string) error {
	var ch NativeChange
	if e := a.Store.Get("native-changes", kind+"-"+id, &ch); store.NotFound(e) {
		return nil
	} else if e != nil {
		return e
	}
	ch.Removed = true
	return a.Store.Put("native-changes", &ch.Meta, &ch)
}
func (a *App) rememberBindings(snap model.DSMSnapshot, oldID, newID string) error {
	old := nativeObject(snap.Certificates, oldID)
	services, _ := old["services"].([]any)
	for _, v := range services {
		s, _ := v.(map[string]any)
		if s == nil {
			continue
		}
		id := "binding-" + model.Hash(dsm.ServiceKey(s))
		var ch NativeChange
		e := a.Store.Get("native-changes", id, &ch)
		if store.NotFound(e) {
			ch = NativeChange{Meta: model.Meta{ID: id}, Kind: "binding", Before: model.DSMObject(s), NativeID: dsm.ServiceKey(s), BeforeCertificate: oldID}
		} else if e != nil {
			return e
		}
		ch.ExpectedHash = newID
		if e = a.Store.Put("native-changes", &ch.Meta, &ch); e != nil {
			return e
		}
	}
	return nil
}
func serviceCertificate(snap model.DSMSnapshot, key string) string {
	for _, c := range snap.Certificates {
		services, _ := c["services"].([]any)
		for _, v := range services {
			s, _ := v.(map[string]any)
			if dsm.ServiceKey(s) == key {
				return dsm.ID(c)
			}
		}
	}
	return ""
}
func (a *App) CreateBackup(ctx context.Context, reason string) (recovery.Backup, error) {
	var b recovery.Backup
	// execute() or the offline backup command holds the exclusive gate.
	a.ACME.Close()
	p := filepath.Join(a.Store.Dir, recovery.ExportDB)
	_ = os.Remove(p)
	defer os.Remove(p)
	if e := a.Store.Backup(ctx, p); e != nil {
		return b, e
	}
	if e := a.Broker.Call(ctx, broker.Request{Action: "backup-create", Message: reason}, &b); e != nil {
		return b, e
	}
	raw, _ := json.Marshal(b)
	return b, os.WriteFile(filepath.Join(a.Store.Dir, "last-full-backup.json"), raw, 0600)
}
func (a *App) Backups(ctx context.Context) ([]recovery.Backup, error) {
	var list []recovery.Backup
	e := a.Broker.Call(ctx, broker.Request{Action: "backup-list"}, &list)
	return list, e
}
func recoveryName(ch NativeChange) string {
	if ch.Name != "" {
		return ch.Name
	}
	if ch.Kind == "proxy" {
		return dsm.String(dsm.Object(ch.Before, "frontend"), "fqdn")
	}
	return dsm.String(ch.Before, "desc")
}
func nativeBefore(ch NativeChange) model.DSMObject {
	if ch.Before == nil {
		return nil
	}
	entry := model.DSMObject{}
	for k, v := range ch.Before {
		entry[k] = v
	}
	entry["UUID"] = ch.NativeID
	return entry
}
func buildRecoveryPlan(changes []NativeChange, state RecoveryState, snap model.DSMSnapshot) RecoveryPlan {
	p := RecoveryPlan{Items: []RecoveryItem{}, Conflicts: []string{}, Prepared: state.Prepared}
	ownedPorts := map[int]bool{}
	ownedIDs := map[string]bool{}
	restoredIDs := map[string]string{}
	for _, ch := range changes {
		if ch.Kind == "certificate" && ch.RestoredID != "" {
			restoredIDs[ch.NativeID] = ch.RestoredID
		}
	}
	for _, ch := range changes {
		if ch.Kind == "proxy" {
			ownedIDs[ch.NativeID] = true
			if ch.LoopbackPort > 0 {
				ownedPorts[ch.LoopbackPort] = true
			}
			if o := nativeObject(snap.Proxies, ch.NativeID); o != nil {
				b := dsm.Object(o, "backend")
				if dsm.String(b, "fqdn") == "127.0.0.1" {
					ownedPorts[dsm.Number(b, "port")] = true
				}
			}
		}
	}
	for _, ch := range changes {
		if ch.Removed || ch.Restored {
			continue
		}
		name := recoveryName(ch)
		if name == "" {
			if ch.Kind == "proxy" {
				name = dsm.String(dsm.Object(nativeObject(snap.Proxies, ch.NativeID), "frontend"), "fqdn")
			}
			if ch.Kind == "certificate" {
				name = dsm.String(nativeObject(snap.Certificates, ch.NativeID), "desc")
			}
		}
		if name == "" {
			name = ch.NativeID
		}
		if ch.Kind == "proxy" {
			o := nativeObject(snap.Proxies, ch.NativeID)
			if o == nil {
				continue
			}
			if ch.ExpectedHash != "" && model.Hash(o) != ch.ExpectedHash && !(state.Preparing && ch.Before != nil && model.Hash(o) == model.Hash(nativeBefore(ch))) {
				p.Conflicts = append(p.Conflicts, "Proxy changed in DSM: "+dsm.String(dsm.Object(o, "frontend"), "fqdn"))
				continue
			}
			action := "Remove created proxy"
			if ch.Before != nil {
				action = "Restore original proxy"
			}
			p.Items = append(p.Items, RecoveryItem{Action: action, Kind: ch.Kind, NativeID: ch.NativeID, Name: name})
		} else if ch.Kind == "binding" {
			current := serviceCertificate(snap, ch.NativeID)
			if current == "" {
				continue
			}
			if current != ch.ExpectedHash && current != ch.BeforeCertificate && current != restoredIDs[ch.BeforeCertificate] {
				p.Conflicts = append(p.Conflicts, "SSL assignment changed in DSM: "+dsm.String(ch.Before, "display_name"))
				continue
			}
			p.Items = append(p.Items, RecoveryItem{Action: "Restore original SSL assignment", Kind: "binding", NativeID: ch.NativeID, Name: dsm.String(ch.Before, "display_name")})
		} else if ch.Kind == "certificate" {
			if ch.Before != nil {
				p.Items = append(p.Items, RecoveryItem{Action: "Retain or restore original certificate", Kind: ch.Kind, NativeID: ch.NativeID, Name: name})
			} else if nativeObject(snap.Certificates, ch.NativeID) != nil {
				p.Items = append(p.Items, RecoveryItem{Action: "Remove certificate only if unused", Kind: ch.Kind, NativeID: ch.NativeID, Name: name, Message: "Shared native assignments preserve this certificate"})
			}
		}
	}
	for _, o := range snap.Proxies {
		if ownedIDs[dsm.ID(o)] {
			continue
		}
		b := dsm.Object(o, "backend")
		if dsm.String(b, "fqdn") == "127.0.0.1" && ownedPorts[dsm.Number(b, "port")] {
			p.Conflicts = append(p.Conflicts, "Another DSM proxy uses a SynoHarbor listener: "+dsm.String(dsm.Object(o, "frontend"), "fqdn"))
		}
	}
	if state.DefaultAfter != "" {
		p.Items = append(p.Items, RecoveryItem{Action: "Restore previous default certificate", Kind: "default", NativeID: state.DefaultBefore, Name: state.DefaultBefore})
	}
	if state.HTTP2Before != nil {
		p.Items = append(p.Items, RecoveryItem{Action: "Restore previous global HTTP/2 setting", Kind: "http2", Name: fmt.Sprint(*state.HTTP2Before)})
	}
	sort.Slice(p.Items, func(i, j int) bool { return p.Items[i].Kind+p.Items[i].NativeID < p.Items[j].Kind+p.Items[j].NativeID })
	sort.Strings(p.Conflicts)
	// Fingerprint includes the full fresh native snapshot and before-images, so
	// confirmations expire whenever relevant state changes after preview.
	p.Token = model.Hash(struct {
		Changes               []NativeChange
		State                 RecoveryState
		Proxies, Certificates []model.DSMObject
		HTTP2                 bool
	}{changes, state, snap.Proxies, snap.Certificates, snap.HTTP2})
	return p
}

// An old settings backup can predate the ownership journal. Never infer that
// an empty journal means there are no native dependencies to restore/remove.
func (a *App) validateRecoveryScope(plan *RecoveryPlan, changes []NativeChange, snap model.DSMSnapshot) error {
	var hosts []model.ProxyHost
	var profiles []model.CertificateProfile
	if e := a.Store.List("proxies", &hosts); e != nil {
		return e
	}
	if e := a.Store.List("certificates", &profiles); e != nil {
		return e
	}
	tracked := map[string]bool{}
	known := map[string]bool{}
	ports := map[int]bool{}
	for _, ch := range changes {
		if !ch.Removed {
			known[ch.Kind+"-"+ch.NativeID] = true
		}
		if ch.LoopbackPort > 0 {
			ports[ch.LoopbackPort] = true
		}
		if !ch.Removed && !ch.Restored {
			tracked[ch.Kind+"-"+ch.NativeID] = true
		}
	}
	for _, p := range hosts {
		if p.LoopbackPort > 0 {
			ports[p.LoopbackPort] = true
		}
		if p.Managed && !p.ExternalDeleted && p.NativeID != "" && nativeObject(snap.Proxies, p.NativeID) != nil && !known["proxy-"+p.NativeID] {
			plan.Conflicts = append(plan.Conflicts, "Original ownership record is missing for proxy "+p.Hostname+"; keep services or recover a newer backup")
		}
	}
	for _, p := range profiles {
		if p.Managed && !p.ExternalDeleted && p.NativeID != "" && nativeObject(snap.Certificates, p.NativeID) != nil && !known["certificate-"+p.NativeID] {
			plan.Conflicts = append(plan.Conflicts, "Original ownership record is missing for certificate "+p.Domain+"; keep services or recover a newer backup")
		}
	}
	for _, o := range snap.Proxies {
		b := dsm.Object(o, "backend")
		if dsm.String(b, "fqdn") == "127.0.0.1" && ports[dsm.Number(b, "port")] && !tracked["proxy-"+dsm.ID(o)] {
			plan.Conflicts = append(plan.Conflicts, "Untracked native proxy still uses a SynoHarbor listener: "+dsm.String(dsm.Object(o, "frontend"), "fqdn"))
		}
	}
	return nil
}
func (a *App) RecoveryPreview(ctx context.Context) (RecoveryPlan, error) {
	var plan RecoveryPlan
	e := a.withDSM(ctx, false, "", func(c *dsm.Client) error {
		snap, e := c.Snapshot(ctx)
		if e != nil {
			return e
		}
		snap.HTTP2, e = c.HTTP2(ctx)
		if e != nil {
			return e
		}
		var changes []NativeChange
		if e = a.Store.List("native-changes", &changes); e != nil {
			return e
		}
		state := a.recoveryState()
		plan = buildRecoveryPlan(changes, state, snap)
		if e = a.validateRecoveryScope(&plan, changes, snap); e != nil {
			return e
		}
		if e = a.checkRestoreDefault(ctx, state, changes); e != nil {
			plan.Conflicts = append(plan.Conflicts, e.Error())
		}
		return nil
	})
	return plan, e
}
func (a *App) checkRestoreDefault(ctx context.Context, state RecoveryState, changes []NativeChange) error {
	if state.DefaultAfter == "" {
		return nil
	}
	ids := []string{state.DefaultAfter, state.DefaultBefore}
	for _, ch := range changes {
		if ch.NativeID == state.DefaultBefore && ch.RestoredID != "" {
			ids = append(ids, ch.RestoredID)
		}
	}
	for _, id := range ids {
		if id == "" {
			continue
		}
		var info map[string]string
		if a.Broker.Call(ctx, broker.Request{Action: "native-certificate-info", ID: id}, &info) == nil && info["isDefault"] == "true" {
			return nil
		}
	}
	return errors.New("default certificate changed outside SynoHarbor; choose the intended default in DSM before rollback")
}

// PrepareUninstall performs an explicitly confirmed, scoped rollback while the
// app is still installed. DSM preuninst only checks its receipt; it never tries
// to rewrite NAS configuration from a half-uninstalled package.
func (a *App) PrepareUninstall(ctx context.Context, token string) error {
	state := a.recoveryState()
	if state.Prepared {
		return nil
	}
	a.ACME.Close()
	return a.withDSM(ctx, false, "", func(c *dsm.Client) error {
		snap, e := c.Snapshot(ctx)
		if e != nil {
			return e
		}
		snap.HTTP2, e = c.HTTP2(ctx)
		if e != nil {
			return e
		}
		var changes []NativeChange
		if e = a.Store.List("native-changes", &changes); e != nil {
			return e
		}
		plan := buildRecoveryPlan(changes, state, snap)
		if e = a.validateRecoveryScope(&plan, changes, snap); e != nil {
			return e
		}
		if len(plan.Conflicts) > 0 {
			return errors.New("DSM changes conflict with rollback; review the recovery preview")
		}
		if !state.Preparing && token != plan.Token {
			return errors.New("DSM state changed; preview the restore again")
		}
		if e = a.checkRestoreDefault(ctx, state, changes); e != nil {
			return e
		}
		if state.HTTP2Before != nil && state.HTTP2After != nil && snap.HTTP2 != *state.HTTP2Before && snap.HTTP2 != *state.HTTP2After {
			return errors.New("global HTTP/2 changed outside SynoHarbor")
		}
		// Ensure every required original certificate remains valid before making
		// any mutation. Expired before-images are never deployed silently.
		for _, ch := range changes {
			if ch.Kind != "certificate" || ch.Before == nil || ch.Removed {
				continue
			}
			var material map[string]string
			id := ch.NativeID
			if ch.RestoredID != "" {
				id = ch.RestoredID
			}
			if nativeObject(snap.Certificates, id) != nil {
				e = a.Broker.Call(ctx, broker.Request{Action: "native-certificate-info", ID: id}, &material)
			} else {
				e = a.Store.Secret("recovery:"+ch.NativeID, &material)
			}
			if e != nil {
				return errors.New("original certificate backup unavailable")
			}
			_, leaf, e := dsm.Fingerprint([]byte(material["certificate"]))
			if e != nil || time.Now().After(leaf.NotAfter) || time.Now().Before(leaf.NotBefore) {
				return errors.New("an original certificate is expired; assign a valid replacement in DSM before rollback")
			}
		}
		if !state.Preparing {
			b, e := a.CreateBackup(ctx, "before-uninstall")
			if e != nil {
				return e
			}
			state.BackupID = b.ID
			state.Preparing = true
			if e = a.Store.Put("recovery", &state.Meta, &state); e != nil {
				return e
			}
		}
		// Restore certificates first, preserving IDs where possible. Imported
		// replacements receive a durable original→restored ID mapping.
		ids := map[string]string{}
		for i := range changes {
			ch := &changes[i]
			if ch.Kind != "certificate" || ch.Before == nil || ch.Removed {
				continue
			}
			id := ch.NativeID
			if ch.RestoredID != "" {
				id = ch.RestoredID
			}
			if nativeObject(snap.Certificates, id) == nil {
				var material map[string]string
				if e = a.Store.Secret("recovery:"+ch.NativeID, &material); e != nil {
					return e
				}
				id, e = c.ImportCertificate(ctx, "", dsm.String(ch.Before, "desc"), []byte(material["key"]), []byte(material["certificate"]))
				if e != nil {
					return e
				}
				ch.RestoredID = id
				if e = a.Store.Put("native-changes", &ch.Meta, ch); e != nil {
					return e
				}
			}
			ids[ch.NativeID] = id
		}
		for i := range changes {
			ch := &changes[i]
			if ch.Kind != "proxy" || ch.Removed || ch.Restored {
				continue
			}
			current := nativeObject(snap.Proxies, ch.NativeID)
			if current == nil {
				ch.Removed = true
			} else if ch.Before == nil {
				if e = c.DeleteProxy(ctx, ch.NativeID); e != nil {
					return e
				}
			} else {
				if e = c.RestoreProxy(ctx, nativeBefore(*ch)); e != nil {
					return e
				}
				cert := ch.BeforeCertificate
				if mapped := ids[cert]; mapped != "" {
					cert = mapped
				}
				if cert != "" {
					if e = c.Bind(ctx, cert, ch.NativeID); e != nil {
						return e
					}
				}
			}
			ch.Restored = true
			if e = a.Store.Put("native-changes", &ch.Meta, ch); e != nil {
				return e
			}
		}
		for i := range changes {
			ch := &changes[i]
			if ch.Kind != "binding" || ch.Removed || ch.Restored {
				continue
			}
			id := ch.BeforeCertificate
			if mapped := ids[id]; mapped != "" {
				id = mapped
			}
			if e = c.RestoreBinding(ctx, ch.Before, ch.ExpectedHash, id); e != nil {
				return e
			}
			ch.Restored = true
			if e = a.Store.Put("native-changes", &ch.Meta, ch); e != nil {
				return e
			}
		}
		if state.DefaultAfter != "" {
			id := state.DefaultBefore
			if mapped := ids[id]; mapped != "" {
				id = mapped
			}
			if e = c.RestoreDefault(ctx, state.DefaultAfter, id); e != nil {
				return e
			}
		}
		if state.HTTP2Before != nil {
			now, e := c.HTTP2(ctx)
			if e != nil {
				return e
			}
			if now != *state.HTTP2Before {
				if state.HTTP2After == nil || now != *state.HTTP2After {
					return errors.New("global HTTP/2 changed outside SynoHarbor")
				}
				if e = c.SetHTTP2(ctx, *state.HTTP2Before); e != nil {
					return e
				}
			}
		}
		// Re-read dependencies before deleting any created certificate. External
		// uses retain the certificate instead of damaging unrelated services.
		snap, e = c.Snapshot(ctx)
		if e != nil {
			return e
		}
		for _, ch := range changes {
			if ch.Kind != "certificate" || ch.Before != nil || ch.Removed {
				continue
			}
			o := nativeObject(snap.Certificates, ch.NativeID)
			if o == nil {
				continue
			}
			services, _ := o["services"].([]any)
			if len(services) > 0 {
				continue
			}
			var current map[string]string
			if e = a.Broker.Call(ctx, broker.Request{Action: "native-certificate-info", ID: ch.NativeID}, &current); e != nil {
				return e
			}
			fp, _, e := dsm.Fingerprint([]byte(current["certificate"]))
			if e != nil {
				return e
			}
			if fp != ch.ExpectedHash {
				continue
			}
			if e = c.DeleteCertificate(ctx, ch.NativeID); e != nil {
				return e
			}
		}
		var hosts []model.ProxyHost
		var certs []model.CertificateProfile
		if e = a.Store.List("proxies", &hosts); e != nil {
			return e
		}
		if e = a.Store.List("certificates", &certs); e != nil {
			return e
		}
		// Re-read immediately before removing loopback rules. Another DSM object
		// may have acquired a dependency while the multi-step rollback ran.
		final, e := c.Snapshot(ctx)
		if e != nil {
			return e
		}
		ports := map[int]bool{}
		for _, p := range hosts {
			ports[p.LoopbackPort] = true
		}
		for _, ch := range changes {
			if ch.LoopbackPort > 0 {
				ports[ch.LoopbackPort] = true
			}
		}
		for _, o := range final.Proxies {
			b := dsm.Object(o, "backend")
			if dsm.String(b, "fqdn") == "127.0.0.1" && ports[dsm.Number(b, "port")] {
				return errors.New("native proxy still needs a SynoHarbor listener; Advanced rules retained and cleanup stopped")
			}
		}
		for _, p := range hosts {
			p.Managed = false
			p.Enabled = false
			p.Status = "restored"
			p.Message = "Detached after restoring DSM"
			if e = a.Store.Put("proxies", &p.Meta, &p); e != nil {
				return e
			}
		}
		for _, p := range certs {
			p.Managed = false
			p.AutoRenew = false
			p.Status = "restored"
			p.Message = "Automatic renewal stopped for uninstall"
			if e = a.Store.Put("certificates", &p.Meta, &p); e != nil {
				return e
			}
		}
		if e = a.ApplyRules(ctx); e != nil {
			return e
		}
		state.Prepared = true
		state.Preparing = false
		if e = a.Store.Put("recovery", &state.Meta, &state); e != nil {
			return e
		}
		raw, _ := json.Marshal(state)
		return os.WriteFile(filepath.Join(a.Store.Dir, "uninstall-ready.json"), raw, 0600)
	})
}

func (a *App) ValidateUninstall(ctx context.Context) error {
	state := a.recoveryState()
	if !state.Prepared || state.Preparing {
		return errors.New("Open SynoHarbor Settings → Backup & Recovery, preview and complete the DSM restore first. No private data was erased.")
	}
	var receipt RecoveryState
	raw, e := os.ReadFile(filepath.Join(a.Store.Dir, "uninstall-ready.json"))
	if e != nil || json.Unmarshal(raw, &receipt) != nil || !receipt.Prepared {
		return errors.New("successful DSM restore receipt is missing; uninstall stopped")
	}
	return a.withDSM(ctx, false, "", func(c *dsm.Client) error {
		snap, e := c.Snapshot(ctx)
		if e != nil {
			return e
		}
		var changes []NativeChange
		if e = a.Store.List("native-changes", &changes); e != nil {
			return e
		}
		ports := map[int]bool{}
		for _, ch := range changes {
			if ch.LoopbackPort > 0 {
				ports[ch.LoopbackPort] = true
			}
		}
		for _, o := range snap.Proxies {
			b := dsm.Object(o, "backend")
			if dsm.String(b, "fqdn") == "127.0.0.1" && ports[dsm.Number(b, "port")] {
				return errors.New("a DSM proxy still depends on SynoHarbor Advanced rules; uninstall cleanup stopped")
			}
		}
		return nil
	})
}

// SeedRecovery is an operator-only bridge for an installation predating the
// journal. Input is piped locally on the NAS from its private pre-install backup.
// It is not a DNSACME import and no secrets travel through HTTP or tool output.
type RecoverySeed struct {
	Snapshot  model.DSMSnapshot            `json:"snapshot"`
	DefaultID string                       `json:"defaultId"`
	Materials map[string]map[string]string `json:"materials"`
}

func (a *App) SeedRecovery(ctx context.Context, seed RecoverySeed) error {
	var existing []NativeChange
	if e := a.Store.List("native-changes", &existing); e != nil {
		return e
	}
	if len(existing) > 0 {
		return errors.New("recovery baseline is already recorded")
	}
	if seed.Snapshot.Error != "" || seed.Snapshot.SuccessAt.IsZero() {
		return errors.New("successful original DSM snapshot required")
	}
	var hosts []model.ProxyHost
	var certs []model.CertificateProfile
	if e := a.Store.List("proxies", &hosts); e != nil {
		return e
	}
	if e := a.Store.List("certificates", &certs); e != nil {
		return e
	}
	for _, p := range hosts {
		ch := NativeChange{Meta: model.Meta{ID: "proxy-" + p.ID}, Kind: "proxy", Name: p.Hostname, NativeID: p.NativeID, LoopbackPort: p.LoopbackPort, Before: nativeObject(seed.Snapshot.Proxies, p.NativeID), BeforeCertificate: certificateFor(seed.Snapshot, p.NativeID), ExpectedHash: p.NativeHash}
		if e := a.Store.Put("native-changes", &ch.Meta, &ch); e != nil {
			return e
		}
	}
	for id, material := range seed.Materials {
		before := nativeObject(seed.Snapshot.Certificates, id)
		if before == nil || !model.ValidID(id) {
			return errors.New("invalid original certificate")
		}
		fp, _, e := dsm.Fingerprint([]byte(material["certificate"]))
		if e != nil {
			return e
		}
		if e = a.Store.PutSecret("recovery:"+id, material); e != nil {
			return e
		}
		ch := NativeChange{Meta: model.Meta{ID: "certificate-" + id}, Kind: "certificate", NativeID: id, Before: before, ExpectedHash: fp}
		if e = a.Store.Put("native-changes", &ch.Meta, &ch); e != nil {
			return e
		}
	}
	for _, p := range certs {
		if _, ok := seed.Materials[p.NativeID]; !ok {
			if e := a.recordCertificate(p); e != nil {
				return e
			}
		}
	}
	var current model.DSMSnapshot
	if e := a.withDSM(ctx, false, "", func(c *dsm.Client) error { var e error; current, e = c.Snapshot(ctx); return e }); e != nil {
		return e
	}
	owned := map[string]bool{}
	for _, p := range certs {
		owned[p.NativeID] = true
	}
	for _, cert := range seed.Snapshot.Certificates {
		services, _ := cert["services"].([]any)
		for _, v := range services {
			s, _ := v.(map[string]any)
			if s == nil {
				continue
			}
			now := serviceCertificate(current, dsm.ServiceKey(s))
			if !owned[now] || now == dsm.ID(cert) {
				continue
			}
			ch := NativeChange{Meta: model.Meta{ID: "binding-" + model.Hash(dsm.ServiceKey(s))}, Kind: "binding", NativeID: dsm.ServiceKey(s), Before: model.DSMObject(s), BeforeCertificate: dsm.ID(cert), ExpectedHash: now}
			if e := a.Store.Put("native-changes", &ch.Meta, &ch); e != nil {
				return e
			}
		}
	}
	state := a.recoveryState()
	state.CapturedAt = seed.Snapshot.SuccessAt
	state.DefaultBefore = seed.DefaultID
	for _, p := range certs {
		var info map[string]string
		if e := a.Broker.Call(ctx, broker.Request{Action: "native-certificate-info", ID: p.NativeID}, &info); e != nil {
			return e
		}
		if info["isDefault"] == "true" {
			state.DefaultAfter = p.NativeID
		}
	}
	return a.Store.Put("recovery", &state.Meta, &state)
}
