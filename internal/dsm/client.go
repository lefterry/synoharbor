// DSM login and multipart import adapted from DNSACME, modified for native IDs.
// Copyright DNSACME contributors and SynoHarbor contributors. Apache-2.0.
package dsm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lefterry/synoharbor/internal/model"
)

type APIError struct {
	API  string
	Code int
}

func (e *APIError) Error() string { return fmt.Sprintf("DSM %s failed (code %d)", e.API, e.Code) }
func TerminalAuth(err error) bool {
	var e *APIError
	return errors.As(err, &e) && e.API == "authentication" && (e.Code == 400 || e.Code == 401 || e.Code == 402 || e.Code == 403 || e.Code == 404 || e.Code == 406 || e.Code == 407 || e.Code == 408 || e.Code == 409)
}

type Client struct {
	BaseURL    string
	HTTP       *http.Client
	sid, token string
	Account    string
	Secret     model.ConnectionSecret
}

func New(settings model.Settings, secret model.ConnectionSecret) *Client {
	port := settings.Port
	if port == 0 {
		port = 5001
	}
	// Credentials are sent only to the literal NAS loopback. DSM's management
	// certificate normally has a public hostname, never 127.0.0.1.
	return &Client{BaseURL: "https://127.0.0.1:" + strconv.Itoa(port), Account: settings.Account, Secret: secret, HTTP: &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}}
}
func (c *Client) form(ctx context.Context, api, method string, params map[string]any, out any) error {
	v := url.Values{"api": {api}, "method": {method}, "version": {"1"}}
	if api == "SYNO.API.Auth" {
		v.Set("version", "6")
	}
	if c.sid != "" {
		v.Set("_sid", c.sid)
		v.Set("SynoToken", c.token)
	}
	for k, p := range params {
		switch t := p.(type) {
		case string:
			v.Set(k, t)
		default:
			b, _ := json.Marshal(p)
			v.Set(k, string(b))
		}
	}
	req, e := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/webapi/entry.cgi", strings.NewReader(v.Encode()))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-SYNO-TOKEN", c.token)
	return c.do(req, api, out)
}
func (c *Client) do(req *http.Request, api string, out any) error {
	resp, e := c.HTTP.Do(req)
	if e != nil {
		return errors.New("DSM request failed; check the local management port")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("DSM returned HTTP %d", resp.StatusCode)
	}
	var env struct {
		Success bool            `json:"success"`
		Data    json.RawMessage `json:"data"`
		Error   struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if e = json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&env); e != nil {
		return errors.New("invalid DSM response")
	}
	if !env.Success {
		return &APIError{API: api, Code: env.Error.Code}
	}
	if out != nil && len(env.Data) > 0 {
		return json.Unmarshal(env.Data, out)
	}
	return nil
}
func (c *Client) Login(ctx context.Context, otp string) error {
	p := map[string]any{"account": c.Account, "passwd": c.Secret.Password, "session": "Core", "format": "sid", "enable_syno_token": "yes"}
	if otp != "" {
		p["otp_code"] = otp
		p["enable_device_token"] = "yes"
		p["device_name"] = "SynoHarbor"
	} else if c.Secret.DeviceID != "" {
		p["device_id"] = c.Secret.DeviceID
		p["device_name"] = c.Secret.DeviceName
	}
	var out struct {
		SID      string `json:"sid"`
		Token    string `json:"synotoken"`
		DID      string `json:"did"`
		DeviceID string `json:"device_id"`
	}
	if err := c.form(ctx, "SYNO.API.Auth", "login", p, &out); err != nil {
		var a *APIError
		if errors.As(err, &a) {
			a.API = "authentication"
		}
		return err
	}
	if out.SID == "" || out.Token == "" {
		return errors.New("DSM did not return a complete session")
	}
	c.sid, c.token = out.SID, out.Token
	if out.DeviceID != "" {
		c.Secret.DeviceID = out.DeviceID
	} else if out.DID != "" {
		c.Secret.DeviceID = out.DID
	}
	if otp != "" {
		c.Secret.DeviceName = "SynoHarbor"
		if c.Secret.DeviceID == "" {
			c.Logout(ctx)
			return errors.New("DSM did not create a trusted device")
		}
	}
	return nil
}
func (c *Client) Logout(ctx context.Context) {
	if c.sid != "" {
		_ = c.form(ctx, "SYNO.API.Auth", "logout", map[string]any{"session": "Core"}, nil)
		c.sid, c.token = "", ""
	}
}
func (c *Client) Snapshot(ctx context.Context) (model.DSMSnapshot, error) {
	var certs struct {
		Certificates []model.DSMObject `json:"certificates"`
	}
	var proxies struct {
		Entries []model.DSMObject `json:"entries"`
	}
	if e := c.form(ctx, "SYNO.Core.Certificate.CRT", "list", nil, &certs); e != nil {
		return model.DSMSnapshot{}, e
	}
	if e := c.form(ctx, "SYNO.Core.AppPortal.ReverseProxy", "list", nil, &proxies); e != nil {
		return model.DSMSnapshot{}, e
	}
	return model.DSMSnapshot{Certificates: certs.Certificates, Proxies: proxies.Entries, SuccessAt: time.Now().UTC()}, nil
}
func ID(o model.DSMObject) string {
	if s, _ := o["id"].(string); s != "" {
		return s
	}
	s, _ := o["UUID"].(string)
	return s
}
func String(o map[string]any, k string) string { s, _ := o[k].(string); return s }
func Number(o map[string]any, k string) int {
	switch v := o[k].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case json.Number:
		i, _ := v.Int64()
		return int(i)
	}
	return 0
}
func Object(o map[string]any, k string) map[string]any {
	m, _ := o[k].(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}
func ProxyEntry(p model.ProxyHost) model.DSMObject {
	frontend := map[string]any{"fqdn": p.Hostname, "port": 443, "protocol": 1, "https": map[string]any{"hsts": false}, "acl": nil}
	headers := []map[string]any{}
	if p.Advanced.WebSockets {
		headers = append(headers, map[string]any{"name": "Upgrade", "value": "$http_upgrade"}, map[string]any{"name": "Connection", "value": "$connection_upgrade"})
	}
	entry := model.DSMObject{"description": "SynoHarbor: " + p.Hostname, "frontend": frontend, "backend": map[string]any{"fqdn": "127.0.0.1", "port": p.LoopbackPort, "protocol": 0}, "customize_headers": headers, "proxy_connect_timeout": 60, "proxy_read_timeout": max(60, p.Advanced.ReadTimeout), "proxy_send_timeout": max(60, p.Advanced.SendTimeout), "proxy_http_version": 1, "proxy_intercept_errors": false}
	if p.NativeID != "" {
		entry["UUID"] = p.NativeID
	}
	return entry
}
func (c *Client) SaveProxy(ctx context.Context, p model.ProxyHost) (string, error) {
	method := "create"
	if p.NativeID != "" {
		method = "update"
	}
	var out map[string]any
	if e := c.form(ctx, "SYNO.Core.AppPortal.ReverseProxy", method, map[string]any{"entry": ProxyEntry(p)}, &out); e != nil {
		return "", e
	}
	snap, e := c.Snapshot(ctx)
	if e != nil {
		return "", e
	}
	for _, o := range snap.Proxies {
		f := Object(o, "frontend")
		if String(f, "fqdn") == p.Hostname && Number(f, "port") == 443 {
			return ID(o), nil
		}
	}
	return "", errors.New("DSM proxy was not found after save")
}
func (c *Client) DeleteProxy(ctx context.Context, id string) error {
	return c.form(ctx, "SYNO.Core.AppPortal.ReverseProxy", "delete", map[string]any{"uuids": []string{id}}, nil)
}
func (c *Client) DeleteCertificate(ctx context.Context, id string) error {
	return c.form(ctx, "SYNO.Core.Certificate.CRT", "delete", map[string]any{"ids": []string{id}}, nil)
}

func (c *Client) ReplaceBindings(ctx context.Context, oldID, newID string, asDefault bool) error {
	snap, e := c.Snapshot(ctx)
	if e != nil {
		return e
	}
	settings := []map[string]any{}
	for _, cert := range snap.Certificates {
		if ID(cert) != oldID {
			continue
		}
		services, _ := cert["services"].([]any)
		for _, item := range services {
			service, _ := item.(map[string]any)
			if service != nil {
				settings = append(settings, map[string]any{"service": service, "old_id": oldID, "id": newID})
			}
		}
	}
	if len(settings) > 0 {
		if e = c.form(ctx, "SYNO.Core.Certificate.Service", "set", map[string]any{"settings": settings}, nil); e != nil {
			return e
		}
	}
	if asDefault {
		desc := ""
		for _, cert := range snap.Certificates {
			if ID(cert) == newID {
				desc = String(cert, "desc")
			}
		}
		if desc == "" {
			return errors.New("replacement certificate description unavailable")
		}
		return c.form(ctx, "SYNO.Core.Certificate.CRT", "set", map[string]any{"id": newID, "desc": desc, "as_default": true}, nil)
	}
	return nil
}
func Fingerprint(certPEM []byte) (string, *x509.Certificate, error) {
	b, _ := pem.Decode(certPEM)
	if b == nil {
		return "", nil, errors.New("certificate PEM missing")
	}
	c, e := x509.ParseCertificate(b.Bytes)
	if e != nil {
		return "", nil, e
	}
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:]), c, nil
}
func (c *Client) ImportCertificate(ctx context.Context, id, desc string, keyPEM, chainPEM []byte) (string, error) {
	leaf, rest := pem.Decode(chainPEM)
	if leaf == nil {
		return "", errors.New("certificate missing")
	}
	if _, e := tls.X509KeyPair(chainPEM, keyPEM); e != nil {
		return "", errors.New("certificate and key do not match")
	}
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	for k, v := range map[string]string{"id": id, "desc": desc} {
		if e := w.WriteField(k, v); e != nil {
			return "", e
		}
	}
	for _, f := range []struct {
		name string
		b    []byte
	}{{"key", keyPEM}, {"cert", pem.EncodeToMemory(leaf)}, {"inter_cert", rest}} {
		if len(f.b) == 0 {
			continue
		}
		part, e := w.CreateFormFile(f.name, f.name+".pem")
		if e != nil {
			return "", e
		}
		if _, e = part.Write(f.b); e != nil {
			return "", e
		}
	}
	if e := w.Close(); e != nil {
		return "", e
	}
	q := url.Values{"api": {"SYNO.Core.Certificate"}, "version": {"1"}, "method": {"import"}, "_sid": {c.sid}, "SynoToken": {c.token}}
	req, e := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/webapi/entry.cgi?"+q.Encode(), &body)
	if e != nil {
		return "", e
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("X-SYNO-TOKEN", c.token)
	var out map[string]any
	if e = c.do(req, "certificate import", &out); e != nil {
		return "", e
	}
	if id != "" {
		return id, nil
	}
	if id = String(out, "id"); id != "" {
		return id, nil
	}
	snap, e := c.Snapshot(ctx)
	if e != nil {
		return "", e
	}
	for _, o := range snap.Certificates {
		if String(o, "desc") == desc {
			return ID(o), nil
		}
	}
	return "", errors.New("imported certificate ID unavailable")
}
func (c *Client) Bind(ctx context.Context, certificateID, proxyID string) error {
	snap, err := c.Snapshot(ctx)
	if err != nil {
		return err
	}
	for _, cert := range snap.Certificates {
		services, _ := cert["services"].([]any)
		for _, item := range services {
			service, _ := item.(map[string]any)
			if String(service, "subscriber") == "ReverseProxy" && String(service, "service") == proxyID {
				if ID(cert) == certificateID {
					return nil
				}
				setting := map[string]any{"service": service, "old_id": ID(cert), "id": certificateID}
				return c.form(ctx, "SYNO.Core.Certificate.Service", "set", map[string]any{"settings": []any{setting}}, nil)
			}
		}
	}
	return errors.New("native proxy certificate service is not available yet; retry deployment")
}
func (c *Client) HTTP2(ctx context.Context) (bool, error) {
	var settings map[string]any
	if e := c.form(ctx, "SYNO.Core.Web.DSM", "get", map[string]any{"version": "2"}, &settings); e != nil {
		return false, e
	}
	enabled, _ := settings["enable_spdy"].(bool)
	return enabled, nil
}
func (c *Client) SetHTTP2(ctx context.Context, enabled bool) error {
	var current map[string]any
	if e := c.form(ctx, "SYNO.Core.Web.DSM", "get", map[string]any{"version": "2"}, &current); e != nil {
		return e
	}
	params := map[string]any{"version": "2", "enable_spdy": enabled}
	for _, key := range []string{"enable_max_connections", "max_connections", "enable_server_header", "server_header", "enable_reuseport"} {
		if v, ok := current[key]; ok {
			params[key] = v
		}
	}
	return c.form(ctx, "SYNO.Core.Web.DSM", "set", params, nil)
}
