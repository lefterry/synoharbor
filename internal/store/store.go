package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/lefterry/synoharbor/internal/model"
	_ "modernc.org/sqlite"
)

var ErrConflict = errors.New("the object changed; refresh before saving")

type Store struct {
	DB     *sql.DB
	Dir    string
	cipher cipher.AEAD
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	key, err := privateKey(dir)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, _ := cipher.NewGCM(block)
	db, err := sql.Open("sqlite", filepath.Join(dir, "synoharbor.sqlite")+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{DB: db, Dir: dir, cipher: aead}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS objects(kind TEXT NOT NULL,id TEXT NOT NULL,version INTEGER NOT NULL,body BLOB NOT NULL,PRIMARY KEY(kind,id)); CREATE TABLE IF NOT EXISTS secrets(id TEXT PRIMARY KEY,value BLOB NOT NULL); CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY,kind TEXT NOT NULL,object_id TEXT NOT NULL,state TEXT NOT NULL,stage TEXT NOT NULL DEFAULT '',message TEXT NOT NULL DEFAULT '',attempts INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL,started_at TEXT,finished_at TEXT,request BLOB); CREATE INDEX IF NOT EXISTS operation_queue ON operations(state,created_at); CREATE UNIQUE INDEX IF NOT EXISTS operation_active ON operations(kind,object_id) WHERE state IN ('queued','running'); CREATE TABLE IF NOT EXISTS ports(id TEXT PRIMARY KEY,port INTEGER UNIQUE NOT NULL); PRAGMA user_version=1;`)
	if err != nil {
		db.Close()
		return nil, err
	}
	os.Chmod(filepath.Join(dir, "synoharbor.sqlite"), 0600)
	return s, nil
}
func (s *Store) Close() error { return s.DB.Close() }
func (s *Store) Get(kind, id string, out any) error {
	var b []byte
	err := s.DB.QueryRow("SELECT body FROM objects WHERE kind=? AND id=?", kind, id).Scan(&b)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}
func (s *Store) List(kind string, out any) error {
	rows, err := s.DB.Query("SELECT body FROM objects WHERE kind=? ORDER BY id", kind)
	if err != nil {
		return err
	}
	defer rows.Close()
	v := []json.RawMessage{}
	for rows.Next() {
		var b []byte
		if err = rows.Scan(&b); err != nil {
			return err
		}
		v = append(v, b)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	b, _ := json.Marshal(v)
	return json.Unmarshal(b, out)
}
func (s *Store) Put(kind string, meta *model.Meta, value any) error {
	if meta.ID == "" {
		meta.ID = uuid.NewString()
	}
	if !model.ValidID(meta.ID) {
		return errors.New("invalid object ID")
	}
	old := meta.Version
	meta.Version++
	meta.UpdatedAt = time.Now().UTC()
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var r sql.Result
	if old == 0 {
		r, err = s.DB.Exec("INSERT INTO objects(kind,id,version,body) VALUES(?,?,?,?) ON CONFLICT DO NOTHING", kind, meta.ID, meta.Version, b)
	} else {
		r, err = s.DB.Exec("UPDATE objects SET version=?,body=? WHERE kind=? AND id=? AND version=?", meta.Version, b, kind, meta.ID, old)
	}
	if err != nil {
		meta.Version = old
		return err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		meta.Version = old
		return ErrConflict
	}
	return nil
}
func (s *Store) Delete(kind, id string, version int) error {
	r, e := s.DB.Exec("DELETE FROM objects WHERE kind=? AND id=? AND version=?", kind, id, version)
	if e != nil {
		return e
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return ErrConflict
	}
	return nil
}
func (s *Store) Secret(id string, out any) error {
	var b []byte
	if err := s.DB.QueryRow("SELECT value FROM secrets WHERE id=?", id).Scan(&b); err != nil {
		return err
	}
	n := s.cipher.NonceSize()
	if len(b) < n {
		return errors.New("invalid secret")
	}
	raw, e := s.cipher.Open(nil, b[:n], b[n:], []byte(id))
	if e != nil {
		return errors.New("cannot decrypt private state")
	}
	return json.Unmarshal(raw, out)
}
func (s *Store) PutSecret(id string, value any) error {
	raw, e := json.Marshal(value)
	if e != nil {
		return e
	}
	nonce := make([]byte, s.cipher.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	b := s.cipher.Seal(nonce, nonce, raw, []byte(id))
	_, e = s.DB.Exec("INSERT INTO secrets(id,value) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value", id, b)
	return e
}
func (s *Store) DeleteSecret(id string) error {
	_, e := s.DB.Exec("DELETE FROM secrets WHERE id=?", id)
	return e
}
func (s *Store) Enqueue(kind, id string, request any) (model.Operation, error) {
	// Deduplicate active work, while allowing an explicit retry after failure.
	var existing string
	if s.DB.QueryRow("SELECT id FROM operations WHERE kind=? AND object_id=? AND state IN ('queued','running') LIMIT 1", kind, id).Scan(&existing) == nil {
		return s.Operation(existing)
	}
	op := model.Operation{Meta: model.Meta{ID: uuid.NewString(), UpdatedAt: time.Now().UTC()}, Kind: kind, ObjectID: id, State: "queued"}
	b, _ := json.Marshal(request)
	_, e := s.DB.Exec("INSERT INTO operations(id,kind,object_id,state,created_at,request) VALUES(?,?,?,'queued',?,?)", op.ID, kind, id, op.UpdatedAt.Format(time.RFC3339Nano), b)
	return op, e
}
func (s *Store) Operation(id string) (model.Operation, error) {
	var o model.Operation
	var created string
	var started, finished sql.NullString
	e := s.DB.QueryRow("SELECT id,kind,object_id,state,stage,message,attempts,created_at,started_at,finished_at,request FROM operations WHERE id=?", id).Scan(&o.ID, &o.Kind, &o.ObjectID, &o.State, &o.Stage, &o.Message, &o.Attempts, &created, &started, &finished, &o.Request)
	o.UpdatedAt, _ = time.Parse(time.RFC3339Nano, created)
	o.StartedAt, _ = time.Parse(time.RFC3339Nano, started.String)
	o.FinishedAt, _ = time.Parse(time.RFC3339Nano, finished.String)
	return o, e
}
func (s *Store) Operations() ([]model.Operation, error) {
	rows, e := s.DB.Query("SELECT id FROM operations ORDER BY created_at DESC LIMIT 200")
	if e != nil {
		return nil, e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	out := []model.Operation{}
	for _, id := range ids {
		o, e := s.Operation(id)
		if e != nil {
			return nil, e
		}
		out = append(out, o)
	}
	return out, nil
}
func (s *Store) Claim() (model.Operation, error) {
	var id string
	e := s.DB.QueryRow("UPDATE operations SET state='running',attempts=attempts+1,started_at=? WHERE id=(SELECT id FROM operations WHERE state='queued' ORDER BY created_at LIMIT 1) RETURNING id", time.Now().UTC().Format(time.RFC3339Nano)).Scan(&id)
	if e != nil {
		return model.Operation{}, e
	}
	return s.Operation(id)
}
func (s *Store) Stage(id, stage string) error {
	_, e := s.DB.Exec("UPDATE operations SET stage=?,message='' WHERE id=?", stage, id)
	return e
}
func (s *Store) Finish(id string, err error) error {
	state, msg := "succeeded", "Completed"
	if err != nil {
		state, msg = "failed", err.Error()
	}
	_, e := s.DB.Exec("UPDATE operations SET state=?,message=?,finished_at=? WHERE id=?", state, msg, time.Now().UTC().Format(time.RFC3339Nano), id)
	return e
}
func (s *Store) Recover() error {
	_, e := s.DB.Exec("UPDATE operations SET state='queued',message='Resuming interrupted operation' WHERE state='running'")
	return e
}
func (s *Store) Backup(ctx context.Context, path string) error {
	if filepath.Dir(path) != s.Dir {
		return errors.New("backup must remain in private storage")
	}
	_, e := s.DB.ExecContext(ctx, "VACUUM INTO ?", path)
	if e == nil {
		e = os.Chmod(path, 0600)
	}
	return e
}
func NotFound(err error) bool   { return errors.Is(err, sql.ErrNoRows) }
func (s *Store) String() string { return fmt.Sprintf("private store (%s)", s.Dir) }

func (s *Store) ReservePort(id string) (int, error) {
	var port int
	if e := s.DB.QueryRow("SELECT port FROM ports WHERE id=?", id).Scan(&port); e == nil {
		return port, nil
	}
	e := s.DB.QueryRow(`WITH RECURSIVE candidates(port) AS (VALUES(18080) UNION ALL SELECT port+1 FROM candidates WHERE port<18999) INSERT INTO ports(id,port) SELECT ?,port FROM candidates WHERE port NOT IN (SELECT port FROM ports) ORDER BY port LIMIT 1 ON CONFLICT(id) DO UPDATE SET id=excluded.id RETURNING port`, id).Scan(&port)
	return port, e
}

func privateKey(dir string) ([]byte, error) {
	lock, e := os.OpenFile(filepath.Join(dir, ".init.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	defer lock.Close()
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); e != nil {
		return nil, e
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	path := filepath.Join(dir, "master.key")
	key, e := os.ReadFile(path)
	if e == nil {
		if len(key) != 32 {
			return nil, errors.New("private storage key is invalid")
		}
		return key, nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	key = make([]byte, 32)
	if _, e = rand.Read(key); e != nil {
		return nil, e
	}
	f, e := os.CreateTemp(dir, ".master-*")
	if e != nil {
		return nil, e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(key); e == nil {
		e = f.Sync()
	}
	if ce := f.Close(); e == nil {
		e = ce
	}
	if e != nil {
		return nil, e
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return nil, e
	}
	return key, nil
}
