package externalcas

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/esnet/acme-proxy/acl"
	"github.com/esnet/acme-proxy/reqmeta"
	stepconfig "github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/cas/apiv1"
)

//go:embed web/index.html
var webFS embed.FS

const (
	dashboardSessionTTL = 12 * time.Hour
)

// Login brute-force lockout: per-IP failure counter with a temporary lock.
const (
	dashLoginMaxFails   = 5
	dashLoginLockout    = 5 * time.Minute
	dashLoginTrackerCap = 4096
)

var (
	dashOnce       sync.Once
	dashSessions   = map[string]time.Time{} // token -> expiry
	dashSessionsMu sync.Mutex

	// dashLoginFailures tracks per-client-IP failed login attempts; at
	// dashLoginMaxFails within a lockout window the IP is locked out.
	dashLoginMu       sync.Mutex
	dashLoginFailures = map[string]dashLoginState{}

	// dashCreds holds the active login credentials; hot-swapped by the
	// settings reload without restarting the listener.
	dashUser atomic.Pointer[string]
	dashPass atomic.Pointer[string]

	// dashCfg holds the active dashboard config (tls_max_age_days etc.) for
	// the renewal loop; hot-swapped by the settings reload.
	dashCfgPtr atomic.Pointer[dashboard]

	// dashMaintOnce guards the hourly dashboard maintenance goroutine so
	// re-instantiation (SIGHUP reload → New) cannot start a second one.
	dashMaintOnce sync.Once
)

// dashLoginState is the per-IP login throttle state.
type dashLoginState struct {
	fails       int
	lockedUntil time.Time
}

// setDashCreds swaps the active dashboard credentials (empty fields keep the
// current value).
func setDashCreds(d dashboard) {
	if d.Username != "" {
		u := d.Username
		dashUser.Store(&u)
	}
	if d.Password != "" {
		p := d.Password
		dashPass.Store(&p)
	}
}

func currentDashUser() string {
	if v := dashUser.Load(); v != nil {
		return *v
	}
	return ""
}

func currentDashPass() string {
	if v := dashPass.Load(); v != nil {
		return *v
	}
	return ""
}

// invalidateDashSessions drops every active session (used when credentials
// change so old sessions cannot outlive a rotation).
func invalidateDashSessions() {
	dashSessionsMu.Lock()
	dashSessions = map[string]time.Time{}
	dashSessionsMu.Unlock()
}

func setDashConfig(d dashboard) {
	dashCfgPtr.Store(&d)
}

func getDashConfig() dashboard {
	if v := dashCfgPtr.Load(); v != nil {
		return *v
	}
	return dashboard{}
}

// startDashboardServer starts the admin web dashboard once when configured.
// It is a separate listener from the ACME client-facing server, the challenge
// listeners, and the metrics server, so it cannot interfere with them.
func startDashboardServer(cas *ExternalCAS, cfg *acmeProxyConfig, d dashboard) error {
	if !d.enabled {
		return nil
	}
	if globalStore == nil {
		slog.Warn("dashboard enabled without a cert store; history will be empty")
	}
	setDashConfig(d)
	setDashCreds(d)

	var startErr error
	dashOnce.Do(func() {
		mux := http.NewServeMux()
		index, err := webFS.ReadFile("web/index.html")
		if err != nil {
			startErr = err
			return
		}
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(index) //nolint:noctx
		})
		mux.HandleFunc("POST /api/login", dashLoginChecker())
		mux.HandleFunc("POST /api/logout", dashLogout)
		mux.Handle("GET /api/overview", dashAuth(dashOverview))
		mux.Handle("GET /api/certs", dashAuth(dashList(globalStoreAllIssued)))
		mux.Handle("GET /api/revoked", dashAuth(dashList(globalStoreAllRevoked)))
		mux.Handle("GET /api/failed", dashAuth(dashFailed))
		mux.Handle("GET /api/cached", dashAuth(dashList(globalStoreAllCached)))
		mux.Handle("GET /api/requests", dashAuth(dashRequests))
		mux.Handle("GET /api/certs/domains", dashAuth(dashCertDomains))
		mux.Handle("GET /api/certs/domains/{domain}", dashAuth(dashCertDomainDetail))
		mux.Handle("DELETE /api/cached/{key}", dashAuth(dashCacheDelete))
		mux.Handle("GET /api/acl", dashAuth(dashACLGet))
		mux.Handle("PUT /api/acl", dashAuth(dashACLPut))
		mux.Handle("GET /api/settings", dashAuth(dashSettingsGet))
		mux.Handle("PUT /api/settings", dashAuth(dashSettingsPut))
		dashMux = mux

		rt, err := dashTLSConfig(cas, cfg, d)
		if err != nil {
			// Never take the CA down because the dashboard's TLS setup
			// failed; serve plain HTTP now and let the hourly maintainer
			// retry the bootstrap and upgrade to HTTPS in place.
			slog.Error("dashboard TLS setup failed, serving plain HTTP (will retry hourly)", "error", err)
		}
		if rt != nil {
			dashTLSRT.Store(rt)
			dashTLSCfg.Store(rt.cfg)
		}
	})

	if startErr == nil {
		startErr = restartDashboardListener(d)
	}
	if startErr == nil {
		dashMaintOnce.Do(func() {
			go func() {
				// Immediate pass (drives renewal / retry), then hourly.
				maintainDashTLS(cas, cfg, d)
				ticker := time.NewTicker(time.Hour)
				defer ticker.Stop()
				for range ticker.C {
					maintainDashTLS(cas, cfg, getDashConfig())
					// Opportunistic store prune; Prune itself enforces a
					// 24h cadence, so this is cheap when there is nothing to do.
					if globalStore != nil {
						if err := globalStore.Prune(time.Now()); err != nil {
							slog.Debug("cert store prune failed", "error", err)
						}
					}
				}
			}()
		})
	}
	return startErr
}

var (
	dashMux    *http.ServeMux
	dashSrvMu  sync.Mutex
	dashSrv    *http.Server
	dashAddr   string // address dashSrv is bound to ("" before first bind)
	dashSrvTLS bool   // whether dashSrv serves TLS
	dashTLSCfg atomic.Pointer[tls.Config]
)

// dashSecurityHeaders sets defensive response headers on every dashboard
// response (page and API). The page is fully inline (no external assets), so
// the CSP needs 'unsafe-inline' for script/style; applying the same headers
// to API responses is harmless and keeps the middleware uniform.
func dashSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// restartDashboardListener binds a dashboard listener for d's address using
// the active TLS config and drains the previous one. Called at startup and by
// the settings reload when port/bind/TLS files change. A bind failure leaves
// the previous listener serving. When neither the address nor the TLS mode
// changed, this is a no-op: the old listener keeps serving (a SIGHUP reload
// re-instantiates the CA and would otherwise hit EADDRINUSE rebinding the
// same address while the previous listener is still draining).
func restartDashboardListener(d dashboard) error {
	dashSrvMu.Lock()
	defer dashSrvMu.Unlock()

	addr := net.JoinHostPort(d.Bind, strconv.Itoa(d.Port))
	tlsConf := dashTLSCfg.Load()
	if dashSrv != nil && addr == dashAddr && (tlsConf != nil) == dashSrvTLS {
		slog.Debug("dashboard listener unchanged; keeping current listener", "addr", addr)
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("cannot bind dashboard listener %s: %w", addr, err)
	}
	if dashSrv != nil {
		old := dashSrv
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = old.Shutdown(ctx)
		}()
	}
	srv := &http.Server{
		Handler: dashSecurityHeaders(dashMux),
		// Close idle keep-alives before NAT tables forget them.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig:         tlsConf,
	}
	dashSrv = srv
	dashAddr = addr
	dashSrvTLS = tlsConf != nil
	go func() {
		var err error
		if tlsConf != nil {
			err = srv.ServeTLS(ln, "", "")
		} else {
			err = srv.Serve(ln)
		}
		if err != nil && err != http.ErrServerClosed {
			slog.Error("dashboard server stopped", "error", err)
		}
	}()
	scheme := "http"
	if tlsConf != nil {
		scheme = "https"
	}
	slog.Info("dashboard listening", "addr", scheme+"://"+addr)
	if scheme == "http" {
		slog.Warn("dashboard running without TLS; restrict network access or configure tls_cert/tls_key")
	}
	return nil
}

// reloadManualDashTLS rebuilds the dashboard TLS config from d's tls_cert/
// tls_key files (manual mode). On success the new config is swapped in;
// on failure the previous config keeps serving.
func reloadManualDashTLS(d dashboard) error {
	if d.TLSCert == "" || d.TLSKey == "" {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(d.TLSCert, d.TLSKey)
	if err != nil {
		return fmt.Errorf("dashboard tls_cert/tls_key: %w", err)
	}
	dashTLSCfg.Store(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	return nil
}

// dashTLSRuntime bundles the live dashboard TLS material with its renewal
// function, so the background maintainer can retry a failed bootstrap.
type dashTLSRuntime struct {
	cfg   *tls.Config
	renew func()
}

var dashTLSRT atomic.Pointer[dashTLSRuntime]

// dashTLSConfig resolves the dashboard TLS mode:
//   - tls_cert + tls_key: serve those PEM files.
//   - default: SHARE the client-facing :443 certificate. The CSR is built
//     from the same persistent key (tls_key.pem next to ca.json) and the
//     same CN/dnsNames, so CreateCertificate is a cache hit on the very
//     certificate :443 serves and the dashboard never issues its own
//     certificate, keeping the upstream rate budget untouched. A copy is
//     kept next to the sidecar store so restarts work even if the shared
//     cache entry is overwritten by a client order.
//   - no ca.json identity available: plain HTTP.
//
// The returned runtime's renew function is driven by maintainDashTLS.
func dashTLSConfig(cas *ExternalCAS, cfg *acmeProxyConfig, d dashboard) (*dashTLSRuntime, error) {
	if d.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(d.TLSCert, d.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("dashboard tls_cert/tls_key: %w", err)
		}
		return &dashTLSRuntime{
			cfg:   &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
			renew: func() {},
		}, nil
	}

	// Same key material as the :443 listener (see authority tlsKeyPath).
	if stepconfig.LoadedFilepath == "" {
		return nil, nil
	}
	top := loadTopLevelConfig()
	cn := top.CommonName
	if cn == "" && len(top.DNSNames) > 0 {
		cn = top.DNSNames[0]
	}
	if cn == "" || len(top.DNSNames) == 0 {
		slog.Warn("dashboard TLS disabled: ca.json dnsNames/commonName missing")
		return nil, nil
	}
	keyPath := filepath.Join(filepath.Dir(stepconfig.LoadedFilepath), "tls_key.pem")
	certPath := filepath.Join(filepath.Dir(d.DataSource), "dashboard-tls-cert.pem")
	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		return nil, err
	}

	maxAge := func() time.Duration { return getDashConfig().tlsMaxAge() }
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		// No local copy yet: this resolves via the shared cache (same key
		// + names as :443), so normally no upstream issuance happens.
		cert, err = obtainDashboardCert(cas, cn, top.DNSNames, key)
		if err != nil {
			return nil, fmt.Errorf("dashboard TLS (sharing %q): %w", cn, err)
		}
		if err := writeCertPEM(certPath, cert.Certificate); err != nil {
			return nil, fmt.Errorf("dashboard TLS: saving certificate copy: %w", err)
		}
	}
	var current atomic.Pointer[tls.Certificate]
	current.Store(&cert)

	// Renewal: when the certificate's cache age is exhausted
	// (tls_max_age_days) or it is inside the last third of its lifetime,
	// obtain a fresh one, persist it, and swap it in atomically. The :443
	// listener renews through the same shared cache, so both listeners stay
	// on one issuance cadence. A failed renewal keeps serving the previous
	// certificate.
	renew := func() {
		leaf, err := x509.ParseCertificate(current.Load().Certificate[0])
		if err != nil {
			return
		}
		age := time.Since(leaf.NotBefore)
		remaining := time.Until(leaf.NotAfter)
		// Lifetime-relative trigger (mirrors step-ca's renewer default):
		// renew inside the last third of the certificate's lifetime. For a
		// 90-day cert that is the last 30 days; short-lived certs renew
		// proportionally earlier instead of hanging on to a fixed 14 days.
		if age < maxAge() && remaining >= leaf.NotAfter.Sub(leaf.NotBefore)/3 {
			return
		}
		slog.Info("dashboard certificate past its cache age (or expiring), renewing",
			"cn", cn, "age", age.Round(time.Hour), "remaining", remaining.Round(time.Hour))
		newCert, err := obtainDashboardCert(cas, cn, top.DNSNames, key)
		if err != nil {
			slog.Error("dashboard cert renewal failed; keep serving previous certificate",
				"cn", cn, "error", err)
			return
		}
		if newLeaf, err := x509.ParseCertificate(newCert.Certificate[0]); err == nil &&
			newLeaf.SerialNumber.String() == leaf.SerialNumber.String() {
			// Cache hit returned the certificate already being served:
			// nothing changed, so do not rewrite files or log a renewal.
			return
		}
		if err := writeCertPEM(certPath, newCert.Certificate); err != nil {
			slog.Error("dashboard cert renewal: saving certificate failed", "error", err)
			return
		}
		current.Store(&newCert)
		slog.Info("dashboard certificate renewed and activated", "cn", cn)
	}

	return &dashTLSRuntime{
		cfg: &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return current.Load(), nil
			},
		},
		renew: renew,
	}, nil
}

// maintainDashTLS runs hourly from the dashboard goroutine. When TLS failed
// to bootstrap at startup it RETRIES the bootstrap and upgrades the running
// listener from plain HTTP to HTTPS in place; otherwise it drives renewal.
func maintainDashTLS(cas *ExternalCAS, cfg *acmeProxyConfig, d dashboard) {
	if dashTLSCfg.Load() != nil {
		if rt := dashTLSRT.Load(); rt != nil {
			rt.renew()
		}
		return
	}
	rt, err := dashTLSConfig(cas, cfg, d)
	if err != nil {
		slog.Error("dashboard TLS bootstrap retry failed; still serving plain HTTP", "error", err)
		return
	}
	if rt == nil {
		return // TLS intentionally unavailable (no identity)
	}
	dashTLSRT.Store(rt)
	dashTLSCfg.Store(rt.cfg)
	slog.Info("dashboard TLS bootstrap succeeded on retry; upgrading listener to HTTPS")
	if err := restartDashboardListener(getDashConfig()); err != nil {
		slog.Error("dashboard listener upgrade failed; previous listener keeps serving", "error", err)
	}
}

// loadOrCreateKey loads the persistent TLS private key shared with the
// client-facing listener, creating it on first use when missing. Accepts
// EC SEC1 and PKCS#8 (EC/RSA/Ed25519) PEM forms.
func loadOrCreateKey(path string) (crypto.Signer, error) {
	if b, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, fmt.Errorf("TLS key %s is not valid PEM", path)
		}
		if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return k, nil
		}
		if any, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			if s, ok := any.(crypto.Signer); ok {
				return s, nil
			}
			return nil, fmt.Errorf("TLS key %s is not a signing key", path)
		}
		return nil, fmt.Errorf("TLS key %s could not be parsed", path)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// tlsMaxAge returns the maximum age of the proxy's own certificate before
// background renewal kicks in. Defaults to 30 days.
func (d dashboard) tlsMaxAge() time.Duration {
	if d.TLSMaxAgeDays > 0 {
		return time.Duration(d.TLSMaxAgeDays) * 24 * time.Hour
	}
	return 30 * 24 * time.Hour
}

// writeCertPEM persists a DER chain as PEM certificates.
func writeCertPEM(path string, chain [][]byte) error {
	var buf bytes.Buffer
	for _, der := range chain {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			return err
		}
	}
	return os.WriteFile(path, buf.Bytes(), 0o600)
}

// obtainDashboardCert resolves the certificate for cn/sans via the proxy's
// upstream flow. With the shared :443 key and identical names this is a
// cache hit on the certificate the client-facing listener already serves.
func obtainDashboardCert(cas *ExternalCAS, cn string, sans []string, key crypto.Signer) (tls.Certificate, error) {
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: sans,
	}, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return tls.Certificate{}, err
	}
	resp, err := cas.CreateCertificate(&apiv1.CreateCertificateRequest{
		CSR:      csr,
		Template: &x509.Certificate{},
	})
	if err != nil {
		return tls.Certificate{}, err
	}
	chain := make([][]byte, 0, 1+len(resp.CertificateChain))
	chain = append(chain, resp.Certificate.Raw)
	for _, c := range resp.CertificateChain {
		chain = append(chain, c.Raw)
	}
	return tls.Certificate{Certificate: chain, PrivateKey: key}, nil
}

// dashLoginChecker returns a handler that validates credentials against the
// ACTIVE values (hot-swappable via settings) and sets a session cookie.
// Repeated failures from one client IP are throttled: after 5 bad attempts
// the IP is locked out for 5 minutes (without disclosing the lockout).
func dashLoginChecker() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		ip := reqmeta.RemoteIP(r)

		dashLoginMu.Lock()
		st, tracked := dashLoginFailures[ip]
		locked := tracked && time.Now().Before(st.lockedUntil)
		dashLoginMu.Unlock()
		if locked {
			time.Sleep(500 * time.Millisecond)
			http.Error(w, "invalid username or password", http.StatusUnauthorized)
			return
		}

		username, password := currentDashUser(), currentDashPass()
		userHash := sha256.Sum256([]byte(username))
		passHash := sha256.Sum256([]byte(password))
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		inUser := sha256.Sum256([]byte(body.Username))
		inPass := sha256.Sum256([]byte(body.Password))
		// Constant-time AND: both comparisons must match (==1).
		ok := subtle.ConstantTimeCompare(inUser[:], userHash[:])&
			subtle.ConstantTimeCompare(inPass[:], passHash[:]) == 1
		if !ok {
			// Slow down brute-force attempts.
			time.Sleep(500 * time.Millisecond)
			dashLoginMu.Lock()
			st := dashLoginFailures[ip]
			st.fails++
			if st.fails >= dashLoginMaxFails {
				st.lockedUntil = time.Now().Add(dashLoginLockout)
				st.fails = 0
			}
			dashLoginFailures[ip] = st
			if len(dashLoginFailures) > dashLoginTrackerCap {
				sweepDashLoginFailuresLocked(time.Now())
			}
			dashLoginMu.Unlock()
			http.Error(w, "invalid username or password", http.StatusUnauthorized)
			return
		}
		dashLoginMu.Lock()
		delete(dashLoginFailures, ip)
		dashLoginMu.Unlock()
		token := make([]byte, 32)
		if _, err := rand.Read(token); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		sid := hex.EncodeToString(token)
		now := time.Now()
		dashSessionsMu.Lock()
		// Opportunistic sweep: drop sessions that expired without being
		// presented again, so the map cannot grow without bound.
		for k, exp := range dashSessions {
			if now.After(exp) {
				delete(dashSessions, k)
			}
		}
		dashSessions[sid] = now.Add(dashboardSessionTTL)
		dashSessionsMu.Unlock()
		secure := dashTLSCfg.Load() != nil
		http.SetCookie(w, &http.Cookie{
			Name:     "acmeproxy_session",
			Value:    sid,
			Path:     "/",
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(dashboardSessionTTL.Seconds()),
		})
		w.WriteHeader(http.StatusNoContent)
	}
}

// sweepDashLoginFailuresLocked bounds the login tracker: expired lockouts
// are dropped first, then (still over cap) the oldest lockout entries in
// one batch. Caller must hold dashLoginMu.
func sweepDashLoginFailuresLocked(now time.Time) {
	for ip, st := range dashLoginFailures {
		if now.After(st.lockedUntil) {
			delete(dashLoginFailures, ip)
		}
	}
	if len(dashLoginFailures) <= dashLoginTrackerCap {
		return
	}
	type kv struct {
		ip  string
		exp time.Time
	}
	all := make([]kv, 0, len(dashLoginFailures))
	for ip, st := range dashLoginFailures {
		all = append(all, kv{ip, st.lockedUntil})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].exp.Before(all[j].exp) })
	drop := len(all) - dashLoginTrackerCap
	for _, e := range all[:drop] {
		delete(dashLoginFailures, e.ip)
	}
}

func dashLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("acmeproxy_session"); err == nil {
		dashSessionsMu.Lock()
		delete(dashSessions, c.Value)
		dashSessionsMu.Unlock()
	}
	w.WriteHeader(http.StatusNoContent)
}

// dashAuth wraps a handler with session-cookie authentication.
func dashAuth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, cookieErr := r.Cookie("acmeproxy_session")
		dashSessionsMu.Lock()
		var ok bool
		if cookieErr == nil {
			exp, present := dashSessions[c.Value]
			if present && time.Now().After(exp) {
				delete(dashSessions, c.Value)
				present = false
			}
			ok = present
		}
		if !ok && len(dashSessions) > 1000 {
			// Cheap amortized cleanup: unauthenticated scanners should not
			// let the session map grow without bound between logins (the
			// full sweep only runs on successful login).
			now := time.Now()
			for k, exp := range dashSessions {
				if now.After(exp) {
					delete(dashSessions, k)
				}
			}
		}
		dashSessionsMu.Unlock()
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	writeJSONStatus(w, http.StatusOK, v)
}

func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("failed to encode dashboard response", "error", err)
	}
}

func globalStoreAllIssued() []CertRecord {
	if globalStore == nil {
		return nil
	}
	return globalStore.allIssued()
}

func globalStoreAllRevoked() []CertRecord {
	if globalStore == nil {
		return nil
	}
	return globalStore.allRevoked()
}

func globalStoreAllCached() []CertRecord {
	if globalStore == nil {
		return nil
	}
	return globalStore.allCached()
}

func globalStoreAllCachedMeta() []CertRecord {
	if globalStore == nil {
		return nil
	}
	return globalStore.allCachedMeta()
}

// cachedDomainSet builds a lowercase set of every individual domain covered
// by a cached certificate, in one pass over the cache (without copying PEM
// payloads).
func cachedDomainSet() map[string]bool {
	set := map[string]bool{}
	for _, c := range globalStoreAllCachedMeta() {
		for _, d := range strings.Split(c.SANs, ",") {
			if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
				set[d] = true
			}
		}
	}
	return set
}

// dashView is the JSON shape served to the dashboard.
type dashView struct {
	Serial          string  `json:"serial"`
	CommonName      string  `json:"common_name"`
	Issuer          string  `json:"issuer,omitempty"`
	SANs            string  `json:"sans"`
	IssuedAt        string  `json:"issued_at,omitempty"`
	ExpiresAt       string  `json:"expires_at,omitempty"`
	DurationSeconds float64 `json:"duration_seconds,omitempty"`
	Status          string  `json:"status"`
	ClientIP        string  `json:"client_ip,omitempty"`
	Error           string  `json:"error,omitempty"`
	RecordedAt      string  `json:"recorded_at"`

	at time.Time `json:"-"` // full-precision RecordedAt for sorting
}

func toView(r CertRecord) dashView {
	v := dashView{
		Serial:          r.Serial,
		CommonName:      r.CommonName,
		Issuer:          r.Issuer,
		SANs:            r.SANs,
		DurationSeconds: r.DurationSeconds,
		Status:          r.Status,
		ClientIP:        r.ClientIP,
		Error:           r.Error,
		at:              r.RecordedAt,
	}
	if !r.IssuedAt.IsZero() {
		v.IssuedAt = r.IssuedAt.UTC().Format(time.RFC3339)
	}
	if !r.ExpiresAt.IsZero() {
		v.ExpiresAt = r.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if !r.RecordedAt.IsZero() {
		v.RecordedAt = r.RecordedAt.UTC().Format(time.RFC3339)
	}
	return v
}

// dashList serves a record list newest-first.
func dashList(src func() []CertRecord) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		records := src()
		out := make([]dashView, len(records))
		for i, rec := range records {
			out[i] = toView(rec)
		}
		sortViewsNewestFirst(out)
		writeJSON(w, out)
	}
}

func sortViewsNewestFirst(v []dashView) {
	sort.SliceStable(v, func(i, j int) bool { return v[i].at.After(v[j].at) })
}

// dashFailed serves only failed issuance records.
func dashFailed(w http.ResponseWriter, r *http.Request) {
	var out []dashView
	for _, rec := range globalStoreAllIssued() {
		if rec.Status == "failure" {
			out = append(out, toView(rec))
		}
	}
	if out == nil {
		out = []dashView{}
	}
	sortViewsNewestFirst(out)
	writeJSON(w, out)
}

func dashRequests(w http.ResponseWriter, r *http.Request) {
	events := reqmeta.Events()
	if len(events) > 200 {
		events = events[:200]
	}
	if events == nil {
		events = []reqmeta.Event{}
	}
	writeJSON(w, events)
}

// domainSummary aggregates every issuance record (success and failure) that
// mentions one domain, for the domain-grouped certificate list.
type domainSummary struct {
	Domain          string   `json:"domain"`
	RequestCount    int      `json:"request_count"`
	SuccessCount    int      `json:"success_count"`
	FailureCount    int      `json:"failure_count"`
	LastRequestedAt string   `json:"last_requested_at"`
	LastStatus      string   `json:"last_status"`
	LastError       string   `json:"last_error,omitempty"`
	UniqueIPs       int      `json:"unique_ips"`
	UniqueIPList    []string `json:"unique_ip_list"`
	Serial          string   `json:"serial,omitempty"`
	ExpiresAt       string   `json:"expires_at,omitempty"`
	Expired         bool     `json:"expired"`
	Cached          bool     `json:"cached"`

	lastAt time.Time `json:"-"`
}

// recordDomains returns every domain a record mentions (SANs + CommonName),
// de-duplicated.
func recordDomains(r CertRecord) []string {
	seen := map[string]bool{}
	var out []string
	add := func(d string) {
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	add(r.CommonName)
	for _, d := range r.domains() {
		add(d)
	}
	return out
}

func recordMentionsDomain(r CertRecord, domain string) bool {
	for _, d := range recordDomains(r) {
		if strings.EqualFold(d, domain) {
			return true
		}
	}
	return false
}

// pageParams reads page/per_page with sane bounds (page >= 1, per_page 1..200,
// default 25).
func pageParams(r *http.Request) (page, perPage int) {
	page, _ = strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ = strconv.Atoi(r.URL.Query().Get("per_page"))
	if page < 1 {
		page = 1
	}
	switch {
	case perPage < 1:
		perPage = 25
	case perPage > 200:
		perPage = 200
	}
	return page, perPage
}

func paginate[T any](items []T, page, perPage int) []T {
	start := (page - 1) * perPage
	if start >= len(items) {
		return nil
	}
	end := start + perPage
	if end > len(items) {
		end = len(items)
	}
	return items[start:end]
}

// aggregateDomains groups issuance records per domain name. cachedSans is a
// set of lowercase individual domain names covered by cached certificates.
func aggregateDomains(records []CertRecord, cachedSans map[string]bool) map[string]*domainSummary {
	aggs := map[string]*domainSummary{}
	ips := map[string]map[string]bool{}
	for _, rec := range records {
		for _, domain := range recordDomains(rec) {
			agg, ok := aggs[domain]
			if !ok {
				agg = &domainSummary{Domain: domain}
				aggs[domain] = agg
				ips[domain] = map[string]bool{}
			}
			agg.RequestCount++
			if rec.Status == "success" {
				agg.SuccessCount++
				// Records arrive in chronological order, so the latest
				// successful cert keeps overwriting serial/expiry.
				if rec.Serial != "" {
					agg.Serial = rec.Serial
					agg.ExpiresAt = rfc3339(rec.ExpiresAt)
					agg.Expired = !rec.ExpiresAt.IsZero() && time.Now().After(rec.ExpiresAt)
				}
			} else {
				agg.FailureCount++
			}
			if rec.ClientIP != "" {
				ips[domain][rec.ClientIP] = true
			}
			// newest record wins for last_* fields (records are appended in
			// chronological order by the store)
			if rec.RecordedAt.After(time.Time{}) {
				agg.LastRequestedAt = rfc3339(rec.RecordedAt)
				agg.LastStatus = rec.Status
				agg.LastError = rec.Error
				if rec.RecordedAt.After(agg.lastAt) {
					agg.lastAt = rec.RecordedAt
				}
			}
		}
	}
	for domain, agg := range aggs {
		for ip := range ips[domain] {
			agg.UniqueIPList = append(agg.UniqueIPList, ip)
		}
		sortStrings(agg.UniqueIPList)
		agg.UniqueIPs = len(agg.UniqueIPList)
		agg.Cached = cachedSans[strings.ToLower(domain)]
	}
	return aggs
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func sortStrings(s []string) {
	sort.Strings(s) //nolint
}

// dashCertDomains serves the domain-grouped certificate list with
// server-side pagination and search.
func dashCertDomains(w http.ResponseWriter, r *http.Request) {
	page, perPage := pageParams(r)
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))

	aggs := aggregateDomains(globalStoreAllIssued(), cachedDomainSet())

	list := make([]*domainSummary, 0, len(aggs))
	for _, agg := range aggs {
		if q != "" && !strings.Contains(strings.ToLower(agg.Domain), q) {
			continue
		}
		list = append(list, agg)
	}
	// most recently active first (zero times sink)
	sort.SliceStable(list, func(i, j int) bool { return list[i].lastAt.After(list[j].lastAt) })

	total := len(list)
	totalPages := (total + perPage - 1) / perPage
	if totalPages < 1 {
		totalPages = 1
	}
	writeJSON(w, map[string]any{
		"domains":     paginate(list, page, perPage),
		"total":       total,
		"page":        page,
		"per_page":    perPage,
		"total_pages": totalPages,
	})
}

// dashCertDomainDetail serves every request record mentioning one domain,
// newest first, with pagination and the domain's cached certificate.
func dashCertDomainDetail(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if domain == "" {
		http.Error(w, "missing domain", http.StatusBadRequest)
		return
	}
	page, perPage := pageParams(r)

	var views []dashView
	for _, rec := range globalStoreAllIssued() {
		if recordMentionsDomain(rec, domain) {
			views = append(views, toView(rec))
		}
	}
	// newest first by full-precision timestamp; records without one (legacy)
	// sink to the bottom in a stable order.
	sort.SliceStable(views, func(i, j int) bool { return views[i].at.After(views[j].at) })

	var cachedCert map[string]string
	for _, c := range globalStoreAllCachedMeta() {
		for _, d := range strings.Split(c.SANs, ",") {
			if strings.EqualFold(strings.TrimSpace(d), domain) {
				cachedCert = map[string]string{
					"sans":       c.SANs,
					"serial":     c.Serial,
					"expires_at": rfc3339(c.ExpiresAt),
				}
			}
		}
	}

	total := len(views)
	totalPages := (total + perPage - 1) / perPage
	if totalPages < 1 {
		totalPages = 1
	}
	resp := map[string]any{
		"domain":      domain,
		"total":       total,
		"page":        page,
		"per_page":    perPage,
		"total_pages": totalPages,
		"requests":    views,
	}
	if cachedCert != nil {
		resp["cached_cert"] = cachedCert
	}
	writeJSON(w, resp)
}

// dashCacheDelete drops one cached domain set so the next request for it
// must obtain a fresh certificate upstream.
func dashCacheDelete(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if key == "" || globalStore == nil {
		http.Error(w, "missing key", http.StatusBadRequest)
		return
	}
	existed, err := globalStore.dropCached(key)
	if err != nil {
		http.Error(w, "failed to delete cache entry", http.StatusInternalServerError)
		return
	}
	if !existed {
		http.Error(w, "not cached", http.StatusNotFound)
		return
	}
	slog.Info("certificate cache entry deleted from dashboard", "domains", key)
	w.WriteHeader(http.StatusNoContent)
}

// dashSettingsGet returns the editable ca.json settings with their values.
func dashSettingsGet(w http.ResponseWriter, r *http.Request) {
	settings, err := currentSettings()
	if err != nil {
		slog.Error("failed to build settings payload", "error", err)
		http.Error(w, "settings unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, settings)
}

// dashSettingsPut validates, persists, and hot-applies ca.json changes.
func dashSettingsPut(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	applied, err := saveSettings(body)
	if err != nil {
		status := http.StatusInternalServerError
		if se, ok := err.(*settingsError); ok {
			status = se.status
		}
		// Client-input validation messages are user-facing by design; any
		// other failure (disk I/O, provider internals) is logged server-side
		// only and answered with a generic message.
		if status >= 400 && status < 500 {
			writeJSONStatus(w, status, map[string]any{"error": err.Error()})
			return
		}
		slog.Error("settings save failed", "error", err)
		writeJSONStatus(w, status, map[string]any{"error": "settings unavailable"})
		return
	}
	writeJSON(w, map[string]any{
		"applied": applied,
	})
}

// dashACLGet returns the raw ACL file content for in-browser editing.
func dashACLGet(w http.ResponseWriter, r *http.Request) {
	content, err := acl.Content()
	if err != nil {
		slog.Error("failed to read acl file", "error", err)
		http.Error(w, "acl unavailable", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]string{
		"file":    acl.Path(),
		"content": content,
	})
}

// dashACLPut validates and saves new ACL content. Edits apply on the
// next request.
func dashACLPut(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	var body struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if bad := acl.Validate(body.Content); len(bad) > 0 {
		writeJSON(w, map[string]any{
			"error":   "invalid entries (nothing saved)",
			"invalid": bad,
		})
		return
	}
	if err := acl.Save(body.Content); err != nil {
		slog.Error("failed to save acl file", "error", err)
		http.Error(w, "acl unavailable", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func dashOverview(w http.ResponseWriter, r *http.Request) {
	var issued, failed, revoked, last24 int
	type expiringT struct {
		Serial     string `json:"serial"`
		CommonName string `json:"common_name"`
		SANs       string `json:"sans"`
		ExpiresAt  string `json:"expires_at"`
	}
	var expiring []expiringT
	now := time.Now()
	for _, rec := range globalStoreAllIssued() {
		switch {
		case rec.Status != "success":
			failed++
		default:
			issued++
		}
		if !rec.RecordedAt.IsZero() && now.Sub(rec.RecordedAt) < 24*time.Hour {
			last24++
		}
		if rec.Status == "success" && rec.ExpiresAt.After(now) && rec.ExpiresAt.Sub(now) < 7*24*time.Hour {
			expiring = append(expiring, expiringT{
				Serial:     rec.Serial,
				CommonName: rec.CommonName,
				SANs:       rec.SANs,
				ExpiresAt:  rec.ExpiresAt.UTC().Format(time.RFC3339),
			})
		}
	}
	for range globalStoreAllRevoked() {
		revoked++
	}
	events := reqmeta.Events()
	if len(events) > 20 {
		events = events[:20]
	}
	if events == nil {
		events = []reqmeta.Event{}
	}
	if expiring == nil {
		expiring = []expiringT{}
	}
	writeJSON(w, map[string]any{
		"issued_total":       issued,
		"failed_total":       failed,
		"revoked_total":      revoked,
		"cached_total":       len(globalStoreAllCached()),
		"issued_last_24h":    last24,
		"expiring_within_7d": expiring,
		"recent":             events,
	})
}
