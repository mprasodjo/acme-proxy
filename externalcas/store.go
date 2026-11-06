package externalcas

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/smallstep/certificates/cas/apiv1"
	bolt "go.etcd.io/bbolt"
)

var (
	issuedBucket  = []byte("issued_certs")
	revokedBucket = []byte("revoked_certs")
	cachedBucket  = []byte("cached_certs")
)

// CertRecord holds persisted metadata for a single certificate operation.
// Fields are populated from the *x509.Certificate returned by the external CA.
// For failed issuances, Serial/Issuer/IssuedAt/ExpiresAt are left as zero values;
// CommonName and SANs are sourced from the CSR instead.
type CertRecord struct {
	Serial          string    `json:"serial"` // hex-encoded; empty for failed issuances
	CommonName      string    `json:"common_name"`
	Issuer          string    `json:"issuer"`              // cert.Issuer.CommonName; empty for failed issuances
	SANs            string    `json:"sans"`                // comma-separated DNS SANs
	IssuedAt        time.Time `json:"issued_at"`           // cert.NotBefore; zero for failed issuances
	ExpiresAt       time.Time `json:"expires_at"`          // cert.NotAfter;  zero for failed issuances
	DurationSeconds float64   `json:"duration_seconds"`    // seconds the external CA took
	Status          string    `json:"status"`              // "success" or "failure"
	ClientIP        string    `json:"client_ip,omitempty"` // ACME client that requested the cert
	Error           string    `json:"error,omitempty"`     // failure reason; empty on success
	RecordedAt      time.Time `json:"recorded_at"`         // when this record was persisted
	CertPEM         []byte    `json:"cert_pem,omitempty"`  // full PEM bundle (leaf + chain) for caching
}

// certStore manages a plugin-owned sidecar bbolt database and in-memory caches
// for issued and revoked certificate records. step-ca owns db/bbolt.db under an
// exclusive lock; this store uses a separate file so there is no lock contention.
type certStore struct {
	db        *bolt.DB
	mu        sync.RWMutex
	issued    []CertRecord
	revoked   []CertRecord
	certCache map[string]CertRecord // key: sorted comma-joined domains
}

// cacheKey builds a deterministic cache key from a list of domain names.
func cacheKey(domains []string) string {
	sorted := make([]string, len(domains))
	copy(sorted, domains)
	sort.Strings(sorted)
	return strings.Join(sorted, ",")
}

// domains returns the list of domain names from the SANs field.
func (r CertRecord) domains() []string {
	if r.SANs == "" {
		return nil
	}
	return strings.Split(r.SANs, ",")
}

// matchesCSR reports whether the cached certificate's leaf public key equals
// the CSR's public key. A cached certificate can only ever be served for a
// CSR carrying the same key: certificates are bound to their public key, and
// e.g. step-ca bootstraps with a fresh in-memory key on every start.
func (r CertRecord) matchesCSR(csr *x509.CertificateRequest) bool {
	if csr == nil || len(r.CertPEM) == 0 {
		return false
	}
	block, _ := pem.Decode(r.CertPEM)
	if block == nil {
		return false
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	certPub, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return false
	}
	csrPub, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return false
	}
	return bytes.Equal(certPub, csrPub)
}

// cacheFreshEnough reports whether a cached record may still be served:
// enough remaining validity AND not older than the configured maximum
// cache age. The age rule bounds the renewal cadence even for long-lived
// upstream certificates. Zero IssuedAt (legacy records) skips the age rule.
func cacheFreshEnough(r *CertRecord, cfg *acmeProxyConfig) bool {
	if time.Until(r.ExpiresAt) < cfg.CertCacheMinValidityDuration() {
		return false
	}
	if !r.IssuedAt.IsZero() && time.Since(r.IssuedAt) >= cfg.CertCacheMaxAgeDuration() {
		return false
	}
	return true
}

// toResponse converts a cached CertRecord into a CreateCertificateResponse.
func (r CertRecord) toResponse() (*apiv1.CreateCertificateResponse, error) {
	var certs []*x509.Certificate
	remaining := r.CertPEM
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse cached certificate: %w", err)
			}
			certs = append(certs, cert)
		}
		remaining = rest
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in cached bundle")
	}
	leaf := certs[0]
	var chain []*x509.Certificate
	if len(certs) > 1 {
		chain = certs[1:]
	}
	return &apiv1.CreateCertificateResponse{
		Certificate:      leaf,
		CertificateChain: chain,
	}, nil
}

// newCertStore opens (or creates) the sidecar bbolt database at path, creates
// the required buckets, and loads existing records into the in-memory caches.
func newCertStore(path string) (*certStore, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("failed to open sidecar db at %s: %w", path, err)
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(issuedBucket); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(revokedBucket); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(cachedBucket)
		return err
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialise buckets: %w", err)
	}

	s := &certStore{db: db, certCache: make(map[string]CertRecord)}
	if err := s.load(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to load existing records: %w", err)
	}
	// Bound the in-memory failure history on startup.
	s.issued = pruneFailuresLocked(s.issued, time.Now().Add(-failureRetention))
	return s, nil
}

// load reads all records from both buckets into the in-memory caches and
// loads cached certificates into the certCache index. Stale cache entries
// are pruned here too (defaults; live config is not known at load time).
func (s *certStore) load() error {
	var staleKeys [][]byte
	if err := s.db.View(func(tx *bolt.Tx) error {
		if err := tx.Bucket(issuedBucket).ForEach(func(_, v []byte) error {
			var r CertRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			s.issued = append(s.issued, r)
			return nil
		}); err != nil {
			return err
		}
		if err := tx.Bucket(revokedBucket).ForEach(func(_, v []byte) error {
			var r CertRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			s.revoked = append(s.revoked, r)
			return nil
		}); err != nil {
			return err
		}
		return tx.Bucket(cachedBucket).ForEach(func(k, v []byte) error {
			var r CertRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			if r.Status == "success" && len(r.CertPEM) > 0 {
				if !cacheFreshEnough(&r, &acmeProxyConfig{}) {
					// k is only valid inside the transaction; copy it.
					staleKeys = append(staleKeys, append([]byte(nil), k...))
					return nil
				}
				key := cacheKey(r.domains())
				s.certCache[key] = r
			}
			return nil
		})
	}); err != nil {
		return err
	}
	if len(staleKeys) > 0 {
		if err := s.db.Update(func(tx *bolt.Tx) error {
			for _, k := range staleKeys {
				if err := tx.Bucket(cachedBucket).Delete(k); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

// storeKey returns a stable bbolt key for r.
// Successful records use the hex serial (globally unique).
// Failed records have no serial, so a CN + nanosecond timestamp is used so
// each failed attempt is stored as a distinct entry. The timestamp comes
// from RecordedAt so the key is deterministic (recomputable for eviction);
// it falls back to the current time only for legacy zero-time records.
func storeKey(r CertRecord) []byte {
	if r.Serial != "" {
		return []byte(r.Serial)
	}
	ts := r.RecordedAt
	if ts.IsZero() {
		ts = time.Now()
	}
	return []byte("failure:" + r.CommonName + ":" + fmt.Sprint(ts.UnixNano()))
}

func (s *certStore) persist(bucket, key []byte, r CertRecord) error {
	data, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("failed to marshal record: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucket).Put(key, data)
	})
}

// failureRetention bounds how long failure records are kept; older ones are
// pruned at load and on append so the issuance history cannot grow forever.
const failureRetention = 30 * 24 * time.Hour

// recordIssued persists r to the issued_certs bucket and appends it to the
// in-memory slice so subsequent Prometheus scrapes pick it up immediately.
// Failed issuances older than failureRetention are pruned, and the slice is
// capped at maxHistoryRecords (oldest entries dropped, their bucket keys
// deleted alongside).
func (s *certStore) recordIssued(r CertRecord) error {
	if r.RecordedAt.IsZero() {
		r.RecordedAt = time.Now().UTC()
	}
	if err := s.persist(issuedBucket, storeKey(r), r); err != nil {
		return err
	}
	s.mu.Lock()
	if r.Status != "success" {
		s.issued = pruneFailuresLocked(s.issued, time.Now().Add(-failureRetention))
	}
	s.issued = append(s.issued, r)
	var evicted []CertRecord
	if len(s.issued) > maxHistoryRecords {
		drop := len(s.issued) - maxHistoryRecords
		evicted = append(evicted, s.issued[:drop]...)
		s.issued = append([]CertRecord(nil), s.issued[drop:]...)
	}
	s.mu.Unlock()
	if err := s.deleteKeys(issuedBucket, evicted); err != nil {
		// In-memory eviction already happened; the orphaned bbolt entries
		// are removed by the daily prune.
		slog.Warn("failed to delete evicted issued records from bbolt", "error", err)
	}
	return nil
}

// pruneFailuresLocked drops failure records older than cutoff, in place.
// Caller must hold s.mu.
func pruneFailuresLocked(records []CertRecord, cutoff time.Time) []CertRecord {
	out := records[:0]
	for _, r := range records {
		if r.Status != "success" && !r.RecordedAt.IsZero() && r.RecordedAt.Before(cutoff) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// recordRevoked persists r to the revoked_certs bucket and appends it to the
// in-memory slice (capped at maxHistoryRecords, mirroring recordIssued).
func (s *certStore) recordRevoked(r CertRecord) error {
	if r.RecordedAt.IsZero() {
		r.RecordedAt = time.Now().UTC()
	}
	if err := s.persist(revokedBucket, storeKey(r), r); err != nil {
		return err
	}
	s.mu.Lock()
	s.revoked = append(s.revoked, r)
	var evicted []CertRecord
	if len(s.revoked) > maxHistoryRecords {
		drop := len(s.revoked) - maxHistoryRecords
		evicted = append(evicted, s.revoked[:drop]...)
		s.revoked = append([]CertRecord(nil), s.revoked[drop:]...)
	}
	s.mu.Unlock()
	if err := s.deleteKeys(revokedBucket, evicted); err != nil {
		slog.Warn("failed to delete evicted revoked records from bbolt", "error", err)
	}
	return nil
}

// deleteKeys removes the bucket entries for records evicted from an
// in-memory history slice. Keys are recomputed with storeKey; failure keys
// are deterministic because RecordedAt is always set before persisting.
func (s *certStore) deleteKeys(bucket []byte, records []CertRecord) error {
	if len(records) == 0 {
		return nil
	}
	keys := make([][]byte, 0, len(records))
	for _, r := range records {
		keys = append(keys, storeKey(r))
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, k := range keys {
			if err := tx.Bucket(bucket).Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

// maxCachedCerts bounds the cert cache; when full, inserting a new domain
// set evicts the entry with the oldest expiry.
const maxCachedCerts = 1000

// maxHistoryRecords bounds the issued/revoked history; evicted entries are
// deleted from bbolt too.
const maxHistoryRecords = 5000

// cacheCert stores a successful certificate in the cache bucket and updates
// the in-memory index. If a cert for the same domains already exists, it is
// overwritten (only the latest valid cert is kept per domain set). When the
// cache is at maxCachedCerts, the entry with the oldest ExpiresAt is evicted.
func (s *certStore) cacheCert(r CertRecord) error {
	if r.Status != "success" || len(r.CertPEM) == 0 {
		return nil
	}
	if r.RecordedAt.IsZero() {
		r.RecordedAt = time.Now().UTC()
	}
	key := cacheKey(r.domains())

	// Pick an eviction victim (oldest expiry) before touching anything so a
	// failed persist leaves the cache untouched.
	s.mu.Lock()
	evictKey := ""
	if _, exists := s.certCache[key]; !exists && len(s.certCache) >= maxCachedCerts {
		var oldest time.Time
		first := true
		for k, rec := range s.certCache {
			if first || rec.ExpiresAt.Before(oldest) {
				evictKey, oldest, first = k, rec.ExpiresAt, false
			}
		}
	}
	s.mu.Unlock()

	if err := s.db.Update(func(tx *bolt.Tx) error {
		if evictKey != "" {
			if err := tx.Bucket(cachedBucket).Delete([]byte(evictKey)); err != nil {
				return err
			}
		}
		data, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("failed to marshal record: %w", err)
		}
		return tx.Bucket(cachedBucket).Put([]byte(key), data)
	}); err != nil {
		return err
	}
	s.mu.Lock()
	if evictKey != "" {
		delete(s.certCache, evictKey)
	}
	s.certCache[key] = r
	s.mu.Unlock()
	return nil
}

// dropCached removes a cached certificate (key = comma-joined domain set)
// from the in-memory index and the bucket. Returns (existed, error).
func (s *certStore) dropCached(key string) (bool, error) {
	s.mu.Lock()
	_, ok := s.certCache[key]
	if ok {
		delete(s.certCache, key)
	}
	s.mu.Unlock()
	if !ok {
		return false, nil
	}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(cachedBucket).Delete([]byte(key))
	}); err != nil {
		return true, err
	}
	return true, nil
}

// dropCachedIfStale removes the cache entry for domains when it no longer
// satisfies the freshness predicate (lookup-time cleanup; best effort).
func (s *certStore) dropCachedIfStale(domains []string, cfg *acmeProxyConfig) {
	key := cacheKey(domains)
	s.mu.Lock()
	r, ok := s.certCache[key]
	if ok && cacheFreshEnough(&r, cfg) {
		s.mu.Unlock()
		return
	}
	if ok {
		delete(s.certCache, key)
	}
	s.mu.Unlock()
	if !ok {
		return
	}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(cachedBucket).Delete([]byte(key))
	}); err != nil {
		slog.Debug("failed to drop stale cache entry", "domains", key, "error", err)
	}
}

// findCachedCert looks up a cached certificate covering all requested domains.
// Returns nil if no valid cached certificate is found.
func (s *certStore) findCachedCert(domains []string) *CertRecord {
	key := cacheKey(domains)
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.certCache[key]
	if !ok {
		return nil
	}
	return &r
}

// allIssued returns a snapshot copy of all issued cert records.
func (s *certStore) allIssued() []CertRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]CertRecord, len(s.issued))
	copy(out, s.issued)
	return out
}

// allRevoked returns a snapshot copy of all revoked cert records.
func (s *certStore) allRevoked() []CertRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]CertRecord, len(s.revoked))
	copy(out, s.revoked)
	return out
}

// allCached returns a snapshot copy of all cached certificate records.
func (s *certStore) allCached() []CertRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]CertRecord, 0, len(s.certCache))
	for _, r := range s.certCache {
		out = append(out, r)
	}
	return out
}

// allCachedMeta returns a snapshot of all cached records WITHOUT the PEM
// payload (CertPEM zeroed in the copy) for dashboard aggregation, so
// building domain maps does not copy megabytes of certificate material.
func (s *certStore) allCachedMeta() []CertRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]CertRecord, 0, len(s.certCache))
	for _, r := range s.certCache {
		r.CertPEM = nil
		out = append(out, r)
	}
	return out
}

// lastPruneMu guards lastPrune so opportunistic Prune callers run it at
// most once per 24 hours.
var (
	lastPruneMu sync.Mutex
	lastPrune   time.Time
)

// Prune deletes retention-expired records from the sidecar store in a single
// db.Update: issued failures recorded more than 30 days ago, issued/revoked
// successes older than 180 days, and cached entries that no longer satisfy
// the freshness predicate. The in-memory slices and cache are rebuilt from
// what remains. Prune is a no-op when the last run was less than 24 hours
// ago, so callers may invoke it opportunistically (hourly tick, startup).
func (s *certStore) Prune(now time.Time) error {
	lastPruneMu.Lock()
	if !lastPrune.IsZero() && now.Sub(lastPrune) < 24*time.Hour {
		lastPruneMu.Unlock()
		return nil
	}
	lastPrune = now
	lastPruneMu.Unlock()

	failCutoff := now.Add(-failureRetention)
	successCutoff := now.Add(-180 * 24 * time.Hour)

	var issued, revoked []CertRecord
	certCache := make(map[string]CertRecord)
	err := s.db.Update(func(tx *bolt.Tx) error {
		ib := tx.Bucket(issuedBucket)
		if err := ib.ForEach(func(k, v []byte) error {
			var r CertRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			switch {
			case r.Status != "success" && !r.RecordedAt.IsZero() && r.RecordedAt.Before(failCutoff):
				return ib.Delete(k)
			case r.Status == "success" && !r.IssuedAt.IsZero() && r.IssuedAt.Before(successCutoff):
				return ib.Delete(k)
			}
			issued = append(issued, r)
			return nil
		}); err != nil {
			return err
		}
		rb := tx.Bucket(revokedBucket)
		if err := rb.ForEach(func(k, v []byte) error {
			var r CertRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			t := r.RecordedAt
			if t.IsZero() {
				t = r.IssuedAt
			}
			if !t.IsZero() && t.Before(successCutoff) {
				return rb.Delete(k)
			}
			revoked = append(revoked, r)
			return nil
		}); err != nil {
			return err
		}
		cb := tx.Bucket(cachedBucket)
		return cb.ForEach(func(k, v []byte) error {
			var r CertRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			if r.Status == "success" && len(r.CertPEM) > 0 && cacheFreshEnough(&r, &acmeProxyConfig{}) {
				certCache[cacheKey(r.domains())] = r
				return nil
			}
			return cb.Delete(k)
		})
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.issued = issued
	s.revoked = revoked
	s.certCache = certCache
	s.mu.Unlock()
	return nil
}

func (s *certStore) close() error {
	return s.db.Close()
}
