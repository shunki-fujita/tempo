// Package ingest holds end-to-end tests that exercise the Kafka client wiring
// in pkg/ingest against a real broker started by grafana/e2e. These tests
// follow the same pattern as Mimir's ingest storage Kafka authentication
// tests (grafana/mimir#14307, #14550) and are skipped from the default Go
// test runs via the integration/ directory exclusion in the Makefile.
package e2e

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"testing"
	"time"

	e2edb "github.com/grafana/e2e/db"
	"github.com/stretchr/testify/require"

	"github.com/grafana/tempo/integration/util"
	"github.com/grafana/tempo/pkg/ingest"
)

const (
	configOverlaySASL = "config-overlay-sasl.yaml"
	configOverlayMTLS = "config-overlay-mtls.yaml"

	// tlsClientCertContainerPath / tlsClientKeyContainerPath are the paths the
	// Tempo containers read the test-generated client cert and key from. The
	// test writes them to the corresponding host-side paths via
	// e2edb.KafkaService.WriteCertificate.
	tlsClientCertContainerPath = "/shared/kafka-tls/client.crt"
	tlsClientKeyContainerPath  = "/shared/kafka-tls/client.key"
	tlsCACertContainerPath     = "/shared/" + e2edb.KafkaTLSCACertFile
)

// TestKafkaAuth boots Tempo against a Kafka broker configured for each
// supported authentication method and verifies that traces written through
// the distributor make it through the SASL/TLS-protected ingest path and are
// queryable on the read path.
func TestKafkaAuth(t *testing.T) {
	tests := map[string]struct {
		authMode      e2edb.KafkaAuthMode
		saslMechanism string
	}{
		"no_auth": {
			authMode: e2edb.KafkaAuthNone,
		},
		"sasl_plain": {
			authMode:      e2edb.KafkaAuthSASLPlain,
			saslMechanism: ingest.SASLMechanismPlain,
		},
		"sasl_scram_sha_256": {
			authMode:      e2edb.KafkaAuthSASLScramSHA256,
			saslMechanism: ingest.SASLMechanismScramSHA256,
		},
		"sasl_scram_sha_512": {
			authMode:      e2edb.KafkaAuthSASLScramSHA512,
			saslMechanism: ingest.SASLMechanismScramSHA512,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := util.TestHarnessConfig{
				KafkaAuthMode: tc.authMode,
			}
			if tc.saslMechanism != "" {
				cfg.ConfigOverlay = configOverlaySASL
				cfg.ConfigTemplateData = map[string]any{
					"SASLUsername":  e2edb.KafkaSASLUsername,
					"SASLPassword":  e2edb.KafkaSASLPassword,
					"SASLMechanism": tc.saslMechanism,
				}
			}

			util.RunIntegrationTests(t, cfg, func(h *util.TempoHarness) {
				produceAndQuery(t, h)
			})
		})
	}
}

// TestKafkaAuth_MTLS is split from TestKafkaAuth because the client cert is
// generated dynamically from the Kafka broker's embedded CA, and needs the
// broker to be running before the cert files exist.
func TestKafkaAuth_MTLS(t *testing.T) {
	util.RunIntegrationTests(t, util.TestHarnessConfig{
		KafkaAuthMode: e2edb.KafkaAuthMTLS,
		ConfigOverlay: configOverlayMTLS,
		ConfigTemplateData: map[string]any{
			"TLSCAPath":   tlsCACertContainerPath,
			"TLSCertPath": tlsClientCertContainerPath,
			"TLSKeyPath":  tlsClientKeyContainerPath,
		},
		PreTempoHook: func(h *util.TempoHarness) error {
			// Sign a Tempo client certificate from the broker's CA and write
			// it next to the CA in the scenario's shared directory so the
			// Tempo containers can mount and read it.
			hostCertPath := filepath.Join(h.TestScenario.SharedDir(), "kafka-tls", "client.crt")
			hostKeyPath := filepath.Join(h.TestScenario.SharedDir(), "kafka-tls", "client.key")
			if err := h.Kafka.WriteCertificate(&x509.Certificate{
				Subject:     pkix.Name{CommonName: "tempo"},
				NotAfter:    time.Now().Add(1 * time.Hour),
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}, hostCertPath, hostKeyPath); err != nil {
				return err
			}
			// The default 0600 mode prevents the non-root Tempo user inside the
			// container from reading the key. Loosen it for these throwaway
			// test artifacts.
			return os.Chmod(hostKeyPath, 0o644)
		},
	}, func(h *util.TempoHarness) {
		produceAndQuery(t, h)
	})
}

// produceAndQuery writes a small Jaeger batch through the distributor and
// confirms it lands on the read path. The assertion catches both the produce
// side (distributor authenticates to Kafka) and the consume side (live-store
// authenticates and ingests the partition).
func produceAndQuery(t *testing.T, h *util.TempoHarness) {
	h.WaitTracesWritable(t)

	batch := util.MakeThriftBatchWithSpanCount(2)
	require.NoError(t, h.WriteJaegerBatch(batch, ""))

	h.WaitTracesQueryable(t, 1)
}
