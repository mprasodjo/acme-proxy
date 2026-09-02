// Package reqmeta records per-request metadata (client IP) at the ACME API
// layer and serves it to the externalcas plugin, which sits behind an
// interface that cannot carry a client IP.
//
// The API layer correlates a finalize request to its CSR public key; the CAS
// later looks the IP up by the same key. New-order and revoke events are kept
// in a small ring buffer as a request log for the dashboard.
package reqmeta

import (
	"crypto/sha256"
	"crypto/x509"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Event is one ACME API request log entry.
type Event struct {
	At     time.Time `json:"at"`
	IP     string    `json:"ip"`
	Kind   string    `json:"kind"` // "new-order", "finalize", "revoke"
	Detail string    `json:"detail"`
}

const logSize = 1000

// entryTTL bounds how long pending finalize/revoke attributions are kept.
const entryTTL = time.Hour

// entryCap bounds the attribution maps; past the cap the oldest entries are
// pruned so unauthenticated traffic cannot grow memory without limit.
const entryCap = 4096

var (
	mu       sync.RWMutex
	log      []Event
	finalize = map[[32]byte]entry{} // CSR public key hash -> attribution
	revoke   = map[string]entry{}   // cert serial (decimal) -> attribution
	trustXFF bool                   // honor X-Forwarded-For (set when running behind a reverse proxy)
)

type entry struct {
	ip string
	at time.Time
}

// Record is the entry point wired into the fork's ACME API hook. It logs the
// event and, when a CSR or serial is present, remembers the client IP so the
// CAS layer can attribute the issuance/revocation to this client.
func Record(r *http.Request, kind, detail string, csr *x509.CertificateRequest, serial string) {
	ip := RemoteIP(r)
	RecordEvent(ip, kind, detail)
	if csr != nil {
		RecordFinalize(csr, ip)
	}
	if serial != "" {
		RecordRevoke(serial, ip)
	}
}

// SetTrustForwardedFor controls whether RemoteIP honors the
// X-Forwarded-For header. Enable it ONLY when acme-proxy sits behind a
// reverse proxy that sets the header; otherwise a client could spoof its
// address to bypass IP-based controls such as the ACL. Default: off.
func SetTrustForwardedFor(trust bool) {
	mu.Lock()
	trustXFF = trust
	mu.Unlock()
}

// TrustForwardedFor reports the current X-Forwarded-For trust setting.
func TrustForwardedFor() bool {
	mu.RLock()
	defer mu.RUnlock()
	return trustXFF
}

// RemoteIP returns the client IP for r. It uses the first X-Forwarded-For
// value only when SetTrustForwardedFor(true) has been called (reverse-proxy
// deployments); otherwise the socket peer address is authoritative.
func RemoteIP(r *http.Request) string {
	if TrustForwardedFor() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i >= 0 {
				xff = xff[:i]
			}
			if ip := strings.TrimSpace(xff); ip != "" {
				return ip
			}
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// RecordEvent appends an ACME API event to the request log.
func RecordEvent(ip, kind, detail string) {
	mu.Lock()
	defer mu.Unlock()
	log = append(log, Event{At: time.Now().UTC(), IP: ip, Kind: kind, Detail: detail})
	if len(log) > logSize {
		log = log[len(log)-logSize:]
	}
}

// RecordFinalize associates a CSR with the client that submitted the finalize
// request, so the issuance record can be attributed to that client IP.
func RecordFinalize(csr *x509.CertificateRequest, ip string) {
	if csr == nil {
		return
	}
	pub, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	pruneLocked()
	finalize[sha256.Sum256(pub)] = entry{ip: ip, at: time.Now()}
}

// LookupFinalize returns (and forgets) the client IP recorded for this CSR.
func LookupFinalize(csr *x509.CertificateRequest) string {
	if csr == nil {
		return ""
	}
	pub, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return ""
	}
	key := sha256.Sum256(pub)
	mu.Lock()
	defer mu.Unlock()
	e, ok := finalize[key]
	if ok {
		delete(finalize, key)
	}
	if !ok || time.Since(e.at) > entryTTL {
		return ""
	}
	return e.ip
}

// RecordRevoke associates a certificate serial (decimal) with the client that
// requested revocation.
func RecordRevoke(serial, ip string) {
	if serial == "" {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	pruneLocked()
	revoke[serial] = entry{ip: ip, at: time.Now()}
}

// LookupRevoke returns (and forgets) the client IP recorded for this serial.
func LookupRevoke(serial string) string {
	mu.Lock()
	defer mu.Unlock()
	e, ok := revoke[serial]
	if ok {
		delete(revoke, serial)
	}
	if !ok || time.Since(e.at) > entryTTL {
		return ""
	}
	return e.ip
}

// pruneLocked drops expired entries and, when the maps are still over the
// cap, the oldest quarter of what remains. Caller must hold mu.
func pruneLocked() {
	expired := time.Now().Add(-entryTTL)
	for k, e := range finalize {
		if e.at.Before(expired) {
			delete(finalize, k)
		}
	}
	for k, e := range revoke {
		if e.at.Before(expired) {
			delete(revoke, k)
		}
	}
	if len(finalize) <= entryCap && len(revoke) <= entryCap {
		return
	}
	if len(finalize) > entryCap {
		trimToCap(finalize, entryCap)
	}
	if len(revoke) > entryCap {
		trimToCapSerial(revoke, entryCap)
	}
}

// trimToCap removes roughly the oldest quarter of m's finalize entries.
func trimToCap(m map[[32]byte]entry, cap int) {
	if len(m) <= cap {
		return
	}
	type kv struct {
		k [32]byte
		t time.Time
	}
	all := make([]kv, 0, len(m))
	for k, e := range m {
		all = append(all, kv{k, e.at})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
	for _, e := range all[:len(m)-cap] {
		delete(m, e.k)
	}
}

// trimToCapSerial removes roughly the oldest quarter of m's revoke entries.
func trimToCapSerial(m map[string]entry, cap int) {
	if len(m) <= cap {
		return
	}
	type kv struct {
		k string
		t time.Time
	}
	all := make([]kv, 0, len(m))
	for k, e := range m {
		all = append(all, kv{k, e.at})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
	for _, e := range all[:len(m)-cap] {
		delete(m, e.k)
	}
}

// Events returns a copy of the request log, newest first.
func Events() []Event {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Event, len(log))
	copy(out, log)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}
