package externalcas

import (
	"crypto/ecdsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newDashTestStore swaps in a temp cert store and restores the previous one.
func newDashTestStore(t *testing.T) {
	t.Helper()
	old := globalStore
	s, err := newCertStore(filepath.Join(t.TempDir(), "dash.db"))
	if err != nil {
		t.Fatalf("newCertStore: %v", err)
	}
	globalStore = s
	t.Cleanup(func() {
		globalStore = old
		_ = s.close()
	})
}

func dashTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	setDashCreds(dashboard{Username: "admin", Password: "testpass"})
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", dashLoginChecker())
	mux.HandleFunc("POST /api/logout", dashLogout)
	mux.Handle("GET /api/certs", dashAuth(dashList(globalStoreAllIssued)))
	mux.Handle("GET /api/failed", dashAuth(dashFailed))
	mux.Handle("GET /api/overview", dashAuth(dashOverview))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func login(t *testing.T, srv *httptest.Server, user, pass string) *http.Response {
	t.Helper()
	resp, err := srv.Client().Post(srv.URL+"/api/login", "application/json",
		strings.NewReader(`{"username":"`+user+`","password":"`+pass+`"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	return resp
}

func TestDashboard_Login(t *testing.T) {
	srv := dashTestServer(t)

	if resp := login(t, srv, "admin", "testpass"); resp.StatusCode != http.StatusNoContent {
		t.Errorf("valid login status = %d, want 204", resp.StatusCode)
	}
	if resp := login(t, srv, "admin", "wrong"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad password status = %d, want 401", resp.StatusCode)
	}
	if resp := login(t, srv, "root", "testpass"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad user status = %d, want 401", resp.StatusCode)
	}
	// Regression: both fields wrong must never authenticate (the == variant
	// of the comparison authenticated any wrong-user + wrong-pass pair).
	if resp := login(t, srv, "hacker", "hacker"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("both-wrong status = %d, want 401 (AUTH BYPASS)", resp.StatusCode)
	}
}

func TestDashboard_UnauthorizedWithoutSession(t *testing.T) {
	srv := dashTestServer(t)
	resp, err := srv.Client().Get(srv.URL + "/api/certs")
	if err != nil {
		t.Fatalf("get certs: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no-session status = %d, want 401", resp.StatusCode)
	}
}

func TestDashboard_APIWithSession(t *testing.T) {
	newDashTestStore(t)
	srv := dashTestServer(t)

	// Seed records: one success, one failure.
	if err := globalStore.recordIssued(CertRecord{
		Serial: "abc123", CommonName: "ok.example.com", SANs: "ok.example.com",
		IssuedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(89 * 24 * time.Hour),
		Status: "success", ClientIP: "192.0.2.10",
	}); err != nil {
		t.Fatalf("recordIssued: %v", err)
	}
	if err := globalStore.recordIssued(CertRecord{
		CommonName: "bad.example.com", SANs: "bad.example.com",
		Status: "failure", ClientIP: "192.0.2.99", Error: "upstream said no",
	}); err != nil {
		t.Fatalf("recordIssued failure: %v", err)
	}

	// Login and keep the session cookie.
	client := srv.Client()
	client.Jar = nil // use default transport cookie handling via login below
	resp, err := client.Post(srv.URL+"/api/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"testpass"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()

	// The httptest client does not persist cookies across calls without a Jar;
	// extract the cookie manually.
	loginResp, _ := client.Post(srv.URL+"/api/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"testpass"}`))
	var session string
	for _, c := range loginResp.Cookies() {
		if c.Name == "acmeproxy_session" {
			session = c.Value
		}
	}
	loginResp.Body.Close()
	if session == "" {
		t.Fatal("login did not set a session cookie")
	}

	get := func(path string) (int, []byte) {
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		req.AddCookie(&http.Cookie{Name: "acmeproxy_session", Value: session})
		r, err := client.Do(req)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, b
	}

	// /api/certs returns both records newest-first.
	code, body := get("/api/certs")
	if code != http.StatusOK {
		t.Fatalf("certs status = %d, want 200", code)
	}
	var certs []dashView
	if err := json.Unmarshal(body, &certs); err != nil {
		t.Fatalf("unmarshal certs: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("certs len = %d, want 2", len(certs))
	}
	if certs[0].CommonName != "bad.example.com" || certs[0].ClientIP != "192.0.2.99" || certs[0].Error != "upstream said no" {
		t.Errorf("newest record = %+v, want bad.example.com failure with IP and error", certs[0])
	}

	// /api/failed returns only the failure.
	code, body = get("/api/failed")
	if code != http.StatusOK {
		t.Fatalf("failed status = %d, want 200", code)
	}
	var failed []dashView
	if err := json.Unmarshal(body, &failed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if len(failed) != 1 || failed[0].CommonName != "bad.example.com" {
		t.Errorf("failed = %+v, want one bad.example.com record", failed)
	}

	// /api/overview counts match.
	code, body = get("/api/overview")
	if code != http.StatusOK {
		t.Fatalf("overview status = %d, want 200", code)
	}
	var ov struct {
		IssuedTotal  int `json:"issued_total"`
		FailedTotal  int `json:"failed_total"`
		RevokedTotal int `json:"revoked_total"`
	}
	if err := json.Unmarshal(body, &ov); err != nil {
		t.Fatalf("unmarshal overview: %v", err)
	}
	if ov.IssuedTotal != 1 || ov.FailedTotal != 1 || ov.RevokedTotal != 0 {
		t.Errorf("overview counts = %+v, want issued=1 failed=1 revoked=0", ov)
	}
}

func TestDashboard_LoginLockout(t *testing.T) {
	setDashCreds(dashboard{Username: "admin", Password: "testpass"})
	t.Cleanup(func() {
		dashLoginMu.Lock()
		dashLoginFailures = map[string]dashLoginState{}
		dashLoginMu.Unlock()
	})
	handler := dashLoginChecker()

	login := func(remoteAddr, user, pass string) int {
		req := httptest.NewRequest("POST", "/api/login",
			strings.NewReader(`{"username":"`+user+`","password":"`+pass+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = remoteAddr
		rec := httptest.NewRecorder()
		handler(rec, req)
		return rec.Code
	}

	for i := 0; i < dashLoginMaxFails; i++ {
		if code := login("203.0.113.77:49152", "admin", "wrong"); code != http.StatusUnauthorized {
			t.Fatalf("bad attempt %d status = %d, want 401", i+1, code)
		}
	}
	// Locked out: even CORRECT credentials must be rejected, with the same
	// error body (no lockout disclosure).
	if code := login("203.0.113.77:49152", "admin", "testpass"); code != http.StatusUnauthorized {
		t.Errorf("correct login while locked out = %d, want 401", code)
	}
	// A different client IP is unaffected.
	if code := login("203.0.113.99:49152", "admin", "testpass"); code != http.StatusNoContent {
		t.Errorf("login from other IP = %d, want 204", code)
	}
}

func TestDashSecurityHeaders(t *testing.T) {
	h := dashSecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	want := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
		"Cache-Control":           "no-store",
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("header %q = %q, want %q", k, got, v)
		}
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (wrapper must not alter it)", rec.Code)
	}
}

func TestDashboard_ContentTypeEnforced(t *testing.T) {
	cases := []struct {
		name string
		ct   string
		want int
	}{
		{"no content-type", "", http.StatusUnsupportedMediaType},
		{"text/plain", "text/plain", http.StatusUnsupportedMediaType},
		{"application/json passes the gate", "application/json", http.StatusBadRequest},
		{"application/json with charset", "application/json; charset=utf-8", http.StatusBadRequest},
	}
	for _, tc := range cases {
		for _, h := range []struct {
			name     string
			handler  http.HandlerFunc
			needsEnv bool
		}{
			{"settings", dashSettingsPut, true},
			{"acl", dashACLPut, false},
		} {
			t.Run(tc.name+"/"+h.name, func(t *testing.T) {
				if h.needsEnv {
					// settings save needs a live config to reach the decode
					// error (400) instead of the "not started" 503.
					setupSettingsEnv(t)
				}
				req := httptest.NewRequest("PUT", "/api/"+h.name, strings.NewReader("not-json"))
				if tc.ct != "" {
					req.Header.Set("Content-Type", tc.ct)
				}
				rec := httptest.NewRecorder()
				h.handler(rec, req)
				if rec.Code != tc.want {
					t.Errorf("status = %d, want %d", rec.Code, tc.want)
				}
			})
		}
	}
}

func TestDashboard_LoadOrCreateKeyPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "dash.pem")
	k1, err := loadOrCreateKey(path)
	if err != nil {
		t.Fatalf("loadOrCreateKey: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("key file not created: %v", err)
	}
	k2, err := loadOrCreateKey(path)
	if err != nil {
		t.Fatalf("second loadOrCreateKey: %v", err)
	}
	e1, ok1 := k1.(*ecdsa.PrivateKey)
	e2, ok2 := k2.(*ecdsa.PrivateKey)
	if !ok1 || !ok2 || !e1.Equal(e2) {
		t.Error("reloaded key differs from generated key")
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestDashboard_ConfigValidation(t *testing.T) {
	// Dashboard config lives at the top level of ca.json now; validate()
	// is driven directly with the struct (loadTopLevelConfig feeds it).
	cases := []struct {
		name    string
		d       dashboard
		m       metrics
		wantErr bool
	}{
		{"disabled by default", dashboard{}, metrics{}, false},
		{"enabled with data_source", dashboard{Port: 8080, DataSource: "/tmp/x.db", Username: "admin", Password: "secret"}, metrics{}, false},
		{"enabled without data_source", dashboard{Port: 8080, Username: "admin", Password: "secret"}, metrics{}, true},
		{"enabled without credentials", dashboard{Port: 8080, DataSource: "/tmp/x.db"}, metrics{}, true},
		{"inherits metrics dataSource", dashboard{Port: 8080, Username: "admin", Password: "secret"}, metrics{Port: 9234, DataSource: "/tmp/m.db"}, false},
		{"tls half set", dashboard{Port: 8080, DataSource: "/tmp/x.db", Username: "admin", Password: "secret", TLSCert: "c.pem"}, metrics{}, true},
		{"tls_domain deprecated", dashboard{Port: 8080, DataSource: "/tmp/x.db", Username: "admin", Password: "secret", TLSDomain: "dash.example.com"}, metrics{}, true},
		{"tls_cert ok", dashboard{Port: 8080, DataSource: "/tmp/x.db", Username: "admin", Password: "secret", TLSCert: "c.pem", TLSKey: "k.pem"}, metrics{}, false},
		{"bad bind", dashboard{Port: 8080, DataSource: "/tmp/x.db", Username: "admin", Password: "secret", Bind: "not-an-ip"}, metrics{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.d.validate(tc.m)
			if (err != nil) != tc.wantErr {
				t.Errorf("validate err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
