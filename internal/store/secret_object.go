package store

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/lefterry/synoharbor/internal/model"
)

// Metadata CAS and its encrypted secret must commit together. Otherwise a stale
// edit could change a token/password even though saving its metadata failed.
func (s *Store) PutSecretObject(kind string, meta *model.Meta, value any, secretID string, secret any) (err error) {
	old := *meta
	defer func() {
		if err != nil {
			*meta = old
		}
	}()
	if meta.ID == "" {
		meta.ID = uuid.NewString()
	}
	if !model.ValidID(meta.ID) {
		return errors.New("invalid object ID")
	}
	meta.Version++
	meta.UpdatedAt = time.Now().UTC()
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(secret)
	if err != nil {
		return err
	}
	nonce := make([]byte, s.cipher.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	encrypted := s.cipher.Seal(nonce, nonce, raw, []byte(secretID))
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var changed int64
	if old.Version == 0 {
		r, e := tx.Exec("INSERT INTO objects(kind,id,version,body) VALUES(?,?,?,?) ON CONFLICT DO NOTHING", kind, meta.ID, meta.Version, body)
		if e != nil {
			return e
		}
		changed, _ = r.RowsAffected()
	} else {
		r, e := tx.Exec("UPDATE objects SET version=?,body=? WHERE kind=? AND id=? AND version=?", meta.Version, body, kind, meta.ID, old.Version)
		if e != nil {
			return e
		}
		changed, _ = r.RowsAffected()
	}
	if changed != 1 {
		return ErrConflict
	}
	if _, err = tx.Exec("INSERT INTO secrets(id,value) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value", secretID, encrypted); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) DeleteCredential(id string, version int) error {
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	r, e := tx.Exec("DELETE FROM objects WHERE kind='credentials' AND id=? AND version=?", id, version)
	if e != nil {
		return e
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return ErrConflict
	}
	if _, e = tx.Exec("DELETE FROM secrets WHERE id=?", "cloudflare:"+id); e != nil {
		return e
	}
	return tx.Commit()
}
