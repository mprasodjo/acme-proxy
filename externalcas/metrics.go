package externalcas

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// certMetaCollector is a custom Prometheus Collector that emits per-certificate
// metadata metrics on each scrape, reading from the in-memory cache in certStore.
type certMetaCollector struct {
	store              *certStore
	issuedInfo         *prometheus.Desc
	issuedAt           *prometheus.Desc
	expiresAt          *prometheus.Desc
	requestDuration    *prometheus.Desc
	revokedInfo        *prometheus.Desc
	revocationDuration *prometheus.Desc
}

func newCertMetaCollector(s *certStore) *certMetaCollector {
	idLabels := []string{"serial", "common_name"}
	allLabels := []string{"serial", "common_name", "issuer", "sans", "status"}
	durationLabels := []string{"serial", "common_name", "status"}
	return &certMetaCollector{
		store: s,
		issuedInfo: prometheus.NewDesc(
			"externalcas_certificate_info",
			"Metadata for each issued certificate (value is always 1)",
			allLabels, nil,
		),
		issuedAt: prometheus.NewDesc(
			"externalcas_certificate_issued_timestamp_seconds",
			"Unix timestamp when the certificate was issued (NotBefore)",
			idLabels, nil,
		),
		expiresAt: prometheus.NewDesc(
			"externalcas_certificate_expiry_timestamp_seconds",
			"Unix timestamp when the certificate expires (NotAfter)",
			idLabels, nil,
		),
		requestDuration: prometheus.NewDesc(
			"externalcas_certificate_signing_duration_seconds",
			"Time in seconds the external CA took to sign this specific certificate",
			durationLabels, nil,
		),
		revokedInfo: prometheus.NewDesc(
			"externalcas_certificate_revocation_info",
			"Metadata for each revoked certificate (value is always 1)",
			allLabels, nil,
		),
		revocationDuration: prometheus.NewDesc(
			"externalcas_certificate_revocation_duration_seconds",
			"Time in seconds the external CA took to revoke the certificate",
			durationLabels, nil,
		),
	}
}

// maxCollectRecords bounds how many issued/revoked records a single scrape
// may emit. The store's slices grow with the certificate history (capped at
// thousands of entries); emitting 4+ metrics per record for all of them on
// every scrape would blow up Prometheus cardinality and scrape time. The
// slices are chronological (newest last), so only the newest window is kept.
const maxCollectRecords = 500

// lastRecords returns at most the last n records of a chronological slice
// (newest last).
func lastRecords[T any](records []T, n int) []T {
	if len(records) > n {
		return records[len(records)-n:]
	}
	return records
}

// Describe sends all metric descriptors to Prometheus.
func (c *certMetaCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.issuedInfo
	ch <- c.issuedAt
	ch <- c.expiresAt
	ch <- c.requestDuration
	ch <- c.revokedInfo
	ch <- c.revocationDuration
}

// Collect emits per-certificate metrics for the issued and revoked certs in
// the sidecar store, newest-first windowed to maxCollectRecords per bucket
// (see maxCollectRecords). Called by Prometheus on each scrape.
//
// Label order for issued metrics:
//
//	issuedInfo:      serial, common_name, issuer, sans, status
//	issuedAt:        serial, common_name
//	expiresAt:       serial, common_name
//	requestDuration: serial, common_name, status
//
// Label order for revoked metrics:
//
//	revokedInfo:         serial, common_name, issuer, sans, status
//	revocationDuration:  serial, common_name, status
func (c *certMetaCollector) Collect(ch chan<- prometheus.Metric) {
	for _, r := range lastRecords(c.store.allIssued(), maxCollectRecords) {
		// Skip failure records: serial and issuer are empty, so all failures for
		// the same CN/SAN collapse to identical label sets causing duplicate metric
		// errors at scrape time. Failures are already counted by
		// externalcas_certificates_issued_total{status="failure"}.
		if r.Status != "success" {
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.issuedInfo, prometheus.GaugeValue, 1,
			r.Serial, r.CommonName, r.Issuer, r.SANs, r.Status)
		ch <- prometheus.MustNewConstMetric(c.requestDuration, prometheus.GaugeValue, r.DurationSeconds,
			r.Serial, r.CommonName, r.Status)
		ch <- prometheus.MustNewConstMetric(c.issuedAt, prometheus.GaugeValue, float64(r.IssuedAt.Unix()),
			r.Serial, r.CommonName)
		ch <- prometheus.MustNewConstMetric(c.expiresAt, prometheus.GaugeValue, float64(r.ExpiresAt.Unix()),
			r.Serial, r.CommonName)
	}
	for _, r := range lastRecords(c.store.allRevoked(), maxCollectRecords) {
		ch <- prometheus.MustNewConstMetric(c.revokedInfo, prometheus.GaugeValue, 1,
			r.Serial, r.CommonName, r.Issuer, r.SANs, r.Status)
		ch <- prometheus.MustNewConstMetric(c.revocationDuration, prometheus.GaugeValue, r.DurationSeconds,
			r.Serial, r.CommonName, r.Status)
	}
}

// StartMetricsServer starts the Prometheus metrics HTTP server once.
// DataSource is guaranteed non-empty by AcmeProxyConfig.Validate() when enabled.
// The cert store must already be opened (globalStore) by New(); this fails
// server startup when it is missing.
func StartMetricsServer(m metrics, caURL string) error {
	if !m.Enabled {
		return nil
	}
	var startErr error
	metricsServerOnce.Do(func() {
		if globalStore == nil {
			startErr = errors.New("cert store not initialized")
			return
		}
		if err := registry.Register(newCertMetaCollector(globalStore)); err != nil {
			startErr = fmt.Errorf("failed to register cert meta collector: %w", err)
			return
		}

		metricsEnabled = true
		go runCAHealthProbe(caURL, 30*time.Second)

		port := m.Port
		if port == 0 {
			port = 9123
		}
		// Empty Bind keeps the historical all-interfaces ":port" behaviour.
		addr := net.JoinHostPort(m.Bind, strconv.Itoa(port))
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
		go func() {
			slog.Info("starting metrics server", "addr", addr)
			srv := &http.Server{
				Addr:              addr,
				Handler:           mux,
				ReadHeaderTimeout: 10 * time.Second,
				// Close idle keep-alives before middleboxes forget them.
				IdleTimeout: 60 * time.Second,
			}
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("metrics server stopped", "error", err)
			}
		}()
	})
	return startErr
}

// runCAHealthProbe periodically GETs caURL and updates externalCAStatus.
// A 2xx response sets the gauge to 1 (up); any error or non-2xx sets it to 0 (down).
func runCAHealthProbe(initialURL string, interval time.Duration) {
	client := &http.Client{Timeout: 10 * time.Second}
	// lastURL tracks the previously exported ca_url label; when the URL
	// changes (hot reload) the old gauge series is deleted so it cannot
	// linger as a stale "0" zombie forever.
	var lastURL string
	probe := func() {
		caURL := initialURL
		// Honor hot-reloaded ca_url.
		if cas := currentCAS.Load(); cas != nil {
			if u := cas.conf().CaURL; u != "" {
				caURL = u
			}
		}
		if caURL != lastURL {
			if lastURL != "" {
				externalCAStatus.DeleteLabelValues(lastURL)
			}
			lastURL = caURL
		}
		resp, err := client.Get(caURL) //nolint:noctx
		if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			externalCAStatus.WithLabelValues(caURL).Set(0)
			if err != nil {
				slog.Debug("external CA health probe failed", "url", caURL, "error", err)
			} else {
				resp.Body.Close()
				slog.Debug("external CA health probe non-2xx", "url", caURL, "status", resp.StatusCode)
			}
			return
		}
		resp.Body.Close()
		externalCAStatus.WithLabelValues(caURL).Set(1)
	}
	probe() // run once immediately so the gauge is meaningful before the first tick
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		probe()
	}
}

var (
	// metricsServerOnce ensures the metrics HTTP server starts exactly once
	metricsServerOnce sync.Once

	// metricsEnabled is set to true when the metrics server starts successfully
	metricsEnabled bool

	// globalStore is the sidecar cert store; nil when DataSource is not configured
	globalStore *certStore

	// Prometheus registry for all externalcas metrics; isolated from the default registry
	// so Go/process collectors added here don't collide with any host-level defaults.
	registry = func() *prometheus.Registry {
		r := prometheus.NewRegistry()
		r.MustRegister(
			collectors.NewGoCollector(),
			collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		)
		return r
	}()

	// Counters
	certificatesIssuedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "externalcas_certificates_issued_total",
			Help: "Total number of certificates issued from external CA, labeled by status (success/failure)",
		},
		[]string{"status"},
	)

	certificatesRevokedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "externalcas_certificates_revoked_total",
			Help: "Total number of certificates revoked at external CA, labeled by status (success/failure)",
		},
		[]string{"status"},
	)

	// Histograms
	certificateRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "externalcas_certificate_request_duration_seconds",
			Help: "Time taken to obtain or revoke a certificate from the external CA (in seconds)",
			// Buckets: 1s, 2.5s, 5s, 10s, 30s, 60s, 120s
			Buckets: []float64{1, 2.5, 5, 10, 30, 60, 120},
		},
		[]string{"operation"}, // operation: issue, revoke
	)

	acmeRoundtripDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "externalcas_acme_roundtrip_duration_seconds",
			Help: "Time taken for individual ACME API calls (in seconds)",
			// Buckets: 100ms, 250ms, 500ms, 1s, 2.5s, 5s, 10s
			Buckets: []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"acme_operation"}, // acme_operation: register, obtain, revoke
	)

	certificateExpirationTime = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "externalcas_certificate_expiration_seconds",
			Help: "Distribution of certificate lifetimes (NotAfter - NotBefore, in seconds)",
			// Buckets: 1 day, 7 days, 30 days, 60 days, 90 days, 365 days
			Buckets: []float64{86400, 604800, 2592000, 5184000, 7776000, 31536000},
		},
		[]string{"status"}, // status: issued, renewed
	)

	// Gauges
	externalCAStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "externalcas_external_ca_up",
			Help: "Status of external CA (1 = up/healthy, 0 = down/unhealthy)",
		},
		[]string{"ca_url"},
	)

	lastSuccessfulCertificateTimestamp = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "externalcas_last_successful_certificate_timestamp_seconds",
			Help: "Unix timestamp of the last successfully issued certificate",
		},
	)
)

func init() {
	registry.MustRegister(
		certificatesIssuedTotal,
		certificatesRevokedTotal,
		certificateRequestDuration,
		acmeRoundtripDuration,
		certificateExpirationTime,
		externalCAStatus,
		lastSuccessfulCertificateTimestamp,
	)
}
