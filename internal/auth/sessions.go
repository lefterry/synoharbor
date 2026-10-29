package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lefterry/synoharbor/internal/dsm"
	"github.com/lefterry/synoharbor/internal/model"
	"github.com/lefterry/synoharbor/internal/store"
)

const SessionCookie = "__Host-synoharbor_session"

type sessionRecord struct {
	model.Meta
	User    string `json:"user"`
	Expires int64  `json:"expires"`
}
type sessionSecret struct {
	User    string           `json:"user"`
	Native  dsm.SessionProof `json:"native"`
	Expires int64            `json:"expires"`
}
type Sessions struct {
	Store        *store.Store
	VerifyNative func(context.Context, Env) (string, string, int, error)
	NewDSM       func(model.Settings, model.ConnectionSecret) *dsm.Client
	Now          func() time.Time
}

func NewSessions(s *store.Store) *Sessions {
	return &Sessions{Store: s, VerifyNative: Native().Verify, NewDSM: dsm.New, Now: time.Now}
}
func sessionID(value string) (string, error) {
	raw, e := hex.DecodeString(value)
	if e != nil || len(raw) != 32 {
		return "", errors.New("invalid session")
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
func OwnCookie(env Env) (string, bool, error) {
	r := http.Request{Header: http.Header{"Cookie": []string{env("HTTP_COOKIE")}}}
	value := ""
	found := false
	for _, c := range r.Cookies() {
		if c.Name == SessionCookie {
			if found || c.Value == "" {
				return "", true, errors.New("invalid session")
			}
			value = c.Value
			found = true
		}
	}
	return value, found, nil
}
func (s *Sessions) settings() model.Settings {
	var cfg model.Settings
	_ = s.Store.Get("settings", "main", &cfg)
	if cfg.Port == 0 {
		cfg.Port = 5001
	}
	return cfg
}
func (s *Sessions) nativeEnv(p dsm.SessionProof) Env {
	cfg := s.settings()
	values := map[string]string{"HTTP_COOKIE": "id=" + p.SID, "HTTP_X_SYNO_TOKEN": p.Token, "REMOTE_ADDR": "127.0.0.1", "SERVER_ADDR": "127.0.0.1", "SERVER_PORT": strconv.Itoa(cfg.Port), "HTTPS": "on", "HTTP_HOST": "127.0.0.1", "SERVER_PROTOCOL": "HTTP/1.1", "REQUEST_METHOD": "GET", "QUERY_STRING": "route=session", "SCRIPT_NAME": "/webman/3rdparty/synoharbor/api.cgi", "REQUEST_URI": "/webman/3rdparty/synoharbor/api.cgi?route=session"}
	return func(k string) string { return values[k] }
}
func (s *Sessions) Verify(ctx context.Context, env Env) (string, string, int, error) {
	value, present, e := OwnCookie(env)
	if !present || e != nil {
		return "", "", 401, errors.New("sign in to SynoHarbor")
	}
	id, e := sessionID(value)
	if e != nil {
		return "", "", 401, errors.New("sign in to SynoHarbor")
	}
	var proof sessionSecret
	if s.Store.Secret("browser-session:"+id, &proof) != nil || proof.Expires <= s.Now().Unix() {
		return "", "", 401, errors.New("SynoHarbor session expired; sign in again")
	}
	name, sid, status, e := s.VerifyNative(ctx, s.nativeEnv(proof.Native))
	if e != nil || name != proof.User || sid != proof.Native.SID {
		if e == nil {
			e = errors.New("session verification failed")
			status = 401
		}
		return "", "", status, e
	}
	return name, sid, 200, nil
}
func (s *Sessions) Login(ctx context.Context, account, password, otp string) (*http.Cookie, string, error) {
	if account == "" || len(account) > 256 || password == "" || len(password) > 4096 || strings.ContainsAny(account, "\x00\r\n") || len(otp) != 0 && (len(otp) != 6 || strings.Trim(otp, "0123456789") != "") {
		return nil, "", errors.New("enter a DSM administrator account, password and current OTP when required")
	}
	// Browser authentication never uses the worker's stored password or trusted
	// device. Only credentials supplied for this interactive login are passed.
	c := s.NewDSM(s.settings(), model.ConnectionSecret{Password: password})
	c.Account = account
	c.BrowserOnly = true
	if e := c.Login(ctx, otp); e != nil {
		return nil, "", errors.New("DSM sign-in failed; check your credentials and current OTP")
	}
	c.Secret.Password = ""
	proof := c.SessionProof()
	name, _, _, e := s.VerifyNative(ctx, s.nativeEnv(proof))
	if e != nil || name != account {
		c.Logout(context.Background())
		return nil, "", errors.New("DSM administrator access required")
	}
	raw := make([]byte, 32)
	if _, e = rand.Read(raw); e != nil {
		c.Logout(context.Background())
		return nil, "", e
	}
	value := hex.EncodeToString(raw)
	id, _ := sessionID(value)
	expiry := s.Now().Add(8 * time.Hour).Unix()
	record := sessionRecord{Meta: model.Meta{ID: id}, User: name, Expires: expiry}
	secret := sessionSecret{User: name, Native: proof, Expires: expiry}
	if e = s.Store.PutSecretObject("browser-sessions", &record.Meta, &record, "browser-session:"+id, secret); e != nil {
		c.Logout(context.Background())
		return nil, "", e
	}
	return &http.Cookie{Name: SessionCookie, Value: value, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: 8 * 60 * 60, Expires: time.Unix(expiry, 0)}, name, nil
}
func (s *Sessions) Logout(ctx context.Context, env Env) error {
	value, present, e := OwnCookie(env)
	if !present || e != nil {
		return nil
	}
	id, e := sessionID(value)
	if e != nil {
		return nil
	}
	var proof sessionSecret
	if s.Store.Secret("browser-session:"+id, &proof) == nil {
		dsm.FromSession(s.settings(), proof.Native).Logout(ctx)
	}
	var record sessionRecord
	if s.Store.Get("browser-sessions", id, &record) == nil {
		if e = s.Store.Delete("browser-sessions", id, record.Version); e != nil {
			return e
		}
	}
	return s.Store.DeleteSecret("browser-session:" + id)
}
func ClearSessionCookie() *http.Cookie {
	return &http.Cookie{Name: SessionCookie, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0)}
}
