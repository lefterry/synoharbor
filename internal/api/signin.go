package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lefterry/synoharbor/internal/model"
)

// This is the only public CGI. It can create a browser session, never read
// configuration or use the worker's trusted device. Passwords/OTPs stay in memory.
func (a *API) SignIn(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != "POST" {
		reply(w, 405, nil, errors.New("POST required"))
		return
	}
	origin, e := url.Parse(r.Header.Get("Origin"))
	allowed := e == nil && origin.Scheme == "https" && origin.Host != "" && origin.User == nil && origin.Path == "" && origin.RawQuery == "" && origin.Fragment == ""
	if allowed {
		direct := strings.EqualFold(origin.Host, a.Env("HTTP_HOST")) && a.Env("HTTPS") == "on"
		var proxies []model.ProxyHost
		if e = a.App.Store.List("proxies", &proxies); e != nil {
			reply(w, 503, nil, errors.New("sign-in unavailable"))
			return
		}
		allowed = direct
		for _, p := range proxies {
			if p.AppUI && p.Enabled && !p.ExternalDeleted && !p.AdvancedBypassed && origin.Host == p.Hostname {
				allowed = true
			}
		}
	}
	if !allowed {
		reply(w, 403, nil, errors.New("open the configured HTTPS SynoHarbor address to sign in"))
		return
	}
	media, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || media != "application/json" {
		reply(w, 415, nil, errors.New("application/json required"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	var req struct {
		Account  string `json:"account"`
		Password string `json:"password"`
		OTP      string `json:"otp"`
	}
	if e = decode(r, &req); e != nil {
		reply(w, 400, nil, e)
		return
	}
	req.Account = strings.TrimSpace(req.Account)
	unlock, e := a.App.Store.Gate(r.Context(), false)
	if e != nil {
		reply(w, 503, nil, errors.New("settings recovery in progress"))
		return
	}
	defer unlock()
	if !a.loginBudget(r, req.Account) {
		reply(w, 429, nil, errors.New("too many sign-in attempts; wait five minutes"))
		return
	}
	// Revoke a previous browser session on successful replacement only.
	cookie, user, e := a.Sessions.Login(r.Context(), req.Account, req.Password, req.OTP)
	req.Password = ""
	req.OTP = ""
	if e != nil {
		reply(w, 401, nil, e)
		return
	}
	_ = a.Sessions.Logout(r.Context(), a.Env)
	http.SetCookie(w, cookie)
	reply(w, 200, map[string]string{"user": user}, nil)
}

func (a *API) loginBudget(r *http.Request, account string) bool {
	db := a.App.Store.DB
	if _, e := db.Exec(`CREATE TABLE IF NOT EXISTS login_attempts (id TEXT PRIMARY KEY,window INTEGER NOT NULL,attempts INTEGER NOT NULL)`); e != nil {
		return false
	}
	// The native proxy supplies X-Real-IP. Arbitrary forwarding chains and browser
	// account spellings cannot give an unlimited budget for a single remote IP.
	ip := a.Env("HTTP_X_REAL_IP")
	if net.ParseIP(ip) == nil {
		ip = a.Env("REMOTE_ADDR")
	}
	window := time.Now().Unix() / 300
	tx, e := db.BeginTx(r.Context(), nil)
	if e != nil {
		return false
	}
	defer tx.Rollback()
	for _, key := range []string{"ip:" + ip, "account:" + strings.ToLower(account)} {
		hash := sha256.Sum256([]byte(key))
		var attempts int
		e = tx.QueryRow(`INSERT INTO login_attempts(id,window,attempts) VALUES(?,?,1) ON CONFLICT(id) DO UPDATE SET window=excluded.window,attempts=CASE WHEN login_attempts.window=excluded.window THEN login_attempts.attempts+1 ELSE 1 END RETURNING attempts`, hex.EncodeToString(hash[:]), window).Scan(&attempts)
		if e != nil || attempts > 10 {
			if e == nil {
				_ = tx.Commit()
			}
			return false
		}
	}
	_, e = tx.Exec("DELETE FROM login_attempts WHERE window < ?", window-1)
	return e == nil && tx.Commit() == nil
}
