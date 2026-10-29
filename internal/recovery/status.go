package recovery

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const StatusFile = "/var/run/synoharbor-recovery.json"

type Status struct {
	ID        string    `json:"id"`
	State     string    `json:"state"`
	Message   string    `json:"message"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func ReadStatus() (Status, error) {
	var s Status
	b, e := os.ReadFile(StatusFile)
	if e == nil {
		e = json.Unmarshal(b, &s)
	}
	return s, e
}
func WriteStatus(s Status) error {
	s.UpdatedAt = time.Now().UTC()
	b, e := json.Marshal(s)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(StatusFile), ".synoharbor-recovery-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	_ = f.Chmod(0600)
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	if ce := f.Close(); e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return os.Rename(f.Name(), StatusFile)
}
