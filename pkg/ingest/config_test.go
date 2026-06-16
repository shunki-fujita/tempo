package ingest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/stretchr/testify/require"
	"github.com/twmb/franz-go/pkg/kfake"
	"github.com/twmb/franz-go/pkg/kmsg"
)

func TestSetDefaultNumberOfPartitionsForAutocreatedTopics(t *testing.T) {
	cluster, err := kfake.NewCluster(kfake.NumBrokers(1))
	require.NoError(t, err)
	t.Cleanup(cluster.Close)

	addrs := cluster.ListenAddrs()
	require.Len(t, addrs, 1)

	cfg := KafkaConfig{
		Address:                          addrs[0],
		AutoCreateTopicDefaultPartitions: 100,
	}

	cluster.ControlKey(kmsg.AlterConfigs.Int16(), func(request kmsg.Request) (kmsg.Response, error, bool) {
		r := request.(*kmsg.AlterConfigsRequest)

		require.Len(t, r.Resources, 1)
		res := r.Resources[0]
		require.Equal(t, kmsg.ConfigResourceTypeBroker, res.ResourceType)
		require.Len(t, res.Configs, 1)
		cfg := res.Configs[0]
		require.Equal(t, "num.partitions", cfg.Name)
		require.NotNil(t, *cfg.Value)
		require.Equal(t, "100", *cfg.Value)

		return &kmsg.AlterConfigsResponse{}, nil, true
	})

	cfg.SetDefaultNumberOfPartitionsForAutocreatedTopics(log.NewNopLogger())
}

func TestKafkaConfig_Validate(t *testing.T) {
	certPath, keyPath, caPath := writeTestCertificates(t)

	baseValid := func() KafkaConfig {
		cfg := KafkaConfig{}
		cfg.RegisterFlags(flag.NewFlagSet("test", flag.ContinueOnError))
		cfg.Address = "localhost:9092"
		cfg.Topic = "traces"
		return cfg
	}

	for _, tc := range []struct {
		name    string
		mutate  func(*KafkaConfig)
		wantErr error
	}{
		{
			name:   "defaults are valid",
			mutate: func(*KafkaConfig) {},
		},
		{
			name: "SASL disabled with empty mechanism is valid",
			mutate: func(cfg *KafkaConfig) {
				// Simulate programmatic construction that does not seed
				// the sasl_mechanism flag default; this must still validate
				// because no SASL credentials are configured.
				cfg.SASLMechanism = ""
			},
		},
		{
			name: "SASL disabled with stray mechanism is ignored",
			mutate: func(cfg *KafkaConfig) {
				// Shared overlays may carry a sasl_mechanism placeholder even
				// when SASL is unused. The mechanism is consumed only when
				// credentials are configured, so an unrecognized value here
				// must not fail validation.
				cfg.SASLMechanism = "OAUTHBEARER"
			},
		},
		{
			name: "SASL PLAIN with credentials is valid",
			mutate: func(cfg *KafkaConfig) {
				cfg.SASLUsername = "tempo"
				_ = cfg.SASLPassword.Set("hunter2")
				cfg.SASLMechanism = SASLMechanismPlain
			},
		},
		{
			name: "SASL SCRAM-SHA-512 with credentials is valid",
			mutate: func(cfg *KafkaConfig) {
				cfg.SASLUsername = "tempo"
				_ = cfg.SASLPassword.Set("hunter2")
				cfg.SASLMechanism = SASLMechanismScramSHA512
			},
		},
		{
			name: "SASL mechanism is case sensitive",
			mutate: func(cfg *KafkaConfig) {
				cfg.SASLUsername = "tempo"
				_ = cfg.SASLPassword.Set("hunter2")
				cfg.SASLMechanism = "scram-sha-256"
			},
			wantErr: ErrInvalidSASLMechanism,
		},
		{
			name: "SASL credentials with empty mechanism default to PLAIN",
			mutate: func(cfg *KafkaConfig) {
				cfg.SASLUsername = "tempo"
				_ = cfg.SASLPassword.Set("hunter2")
				cfg.SASLMechanism = ""
			},
		},
		{
			name: "unknown SASL mechanism is rejected",
			mutate: func(cfg *KafkaConfig) {
				cfg.SASLUsername = "tempo"
				_ = cfg.SASLPassword.Set("hunter2")
				cfg.SASLMechanism = "OAUTHBEARER"
			},
			wantErr: ErrInvalidSASLMechanism,
		},
		{
			name: "SASL username without password is rejected",
			mutate: func(cfg *KafkaConfig) {
				cfg.SASLUsername = "tempo"
			},
			wantErr: ErrInconsistentSASLCredentials,
		},
		{
			name: "TLS without client cert is valid",
			mutate: func(cfg *KafkaConfig) {
				cfg.TLSEnabled = true
			},
		},
		{
			name: "mTLS with valid cert/key/CA is valid",
			mutate: func(cfg *KafkaConfig) {
				cfg.TLSEnabled = true
				cfg.TLS.CAPath = caPath
				cfg.TLS.CertPath = certPath
				cfg.TLS.KeyPath = keyPath
			},
		},
		{
			name: "TLS with missing CA file is rejected",
			mutate: func(cfg *KafkaConfig) {
				cfg.TLSEnabled = true
				cfg.TLS.CAPath = filepath.Join(t.TempDir(), "missing.pem")
			},
		},
		{
			name: "TLS with cert but no key is rejected via dskit",
			mutate: func(cfg *KafkaConfig) {
				cfg.TLSEnabled = true
				cfg.TLS.CertPath = certPath
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseValid()
			tc.mutate(&cfg)
			err := cfg.Validate()
			switch {
			case tc.wantErr != nil:
				require.ErrorIs(t, err, tc.wantErr)
			case tc.name == "TLS with missing CA file is rejected", tc.name == "TLS with cert but no key is rejected via dskit":
				require.Error(t, err)
			default:
				require.NoError(t, err)
			}
		})
	}
}

func TestCommonKafkaClientOptions_SASLAndTLS(t *testing.T) {
	certPath, keyPath, caPath := writeTestCertificates(t)

	for _, tc := range []struct {
		name   string
		mutate func(*KafkaConfig)
	}{
		{
			name:   "no auth, no TLS",
			mutate: func(*KafkaConfig) {},
		},
		{
			name: "SASL PLAIN",
			mutate: func(cfg *KafkaConfig) {
				cfg.SASLUsername = "tempo"
				_ = cfg.SASLPassword.Set("hunter2")
				cfg.SASLMechanism = SASLMechanismPlain
			},
		},
		{
			name: "SASL with empty mechanism defaults to PLAIN",
			mutate: func(cfg *KafkaConfig) {
				cfg.SASLUsername = "tempo"
				_ = cfg.SASLPassword.Set("hunter2")
				// SASLMechanism intentionally left empty.
			},
		},
		{
			name: "SASL SCRAM-SHA-256",
			mutate: func(cfg *KafkaConfig) {
				cfg.SASLUsername = "tempo"
				_ = cfg.SASLPassword.Set("hunter2")
				cfg.SASLMechanism = SASLMechanismScramSHA256
			},
		},
		{
			name: "SASL SCRAM-SHA-512",
			mutate: func(cfg *KafkaConfig) {
				cfg.SASLUsername = "tempo"
				_ = cfg.SASLPassword.Set("hunter2")
				cfg.SASLMechanism = SASLMechanismScramSHA512
			},
		},
		{
			name: "TLS without client cert",
			mutate: func(cfg *KafkaConfig) {
				cfg.TLSEnabled = true
				cfg.TLS.CAPath = caPath
			},
		},
		{
			name: "mTLS with client cert and SCRAM-SHA-512",
			mutate: func(cfg *KafkaConfig) {
				cfg.SASLUsername = "tempo"
				_ = cfg.SASLPassword.Set("hunter2")
				cfg.SASLMechanism = SASLMechanismScramSHA512
				cfg.TLSEnabled = true
				cfg.TLS.CAPath = caPath
				cfg.TLS.CertPath = certPath
				cfg.TLS.KeyPath = keyPath
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := KafkaConfig{Address: "localhost:9092", Topic: "traces"}
			tc.mutate(&cfg)
			opts, err := commonKafkaClientOptions(cfg, nil, log.NewNopLogger())
			require.NoError(t, err)
			require.NotEmpty(t, opts)
		})
	}
}

func TestCommonKafkaClientOptions_ErrorWhenValidateSkipped(t *testing.T) {
	t.Run("unknown SASL mechanism", func(t *testing.T) {
		cfg := KafkaConfig{
			Address:       "localhost:9092",
			Topic:         "traces",
			SASLUsername:  "tempo",
			SASLMechanism: "OAUTHBEARER",
		}
		_ = cfg.SASLPassword.Set("hunter2")
		_, err := commonKafkaClientOptions(cfg, nil, log.NewNopLogger())
		require.ErrorIs(t, err, ErrInvalidSASLMechanism)
	})

	t.Run("TLS with missing CA file", func(t *testing.T) {
		cfg := KafkaConfig{
			Address:    "localhost:9092",
			Topic:      "traces",
			TLSEnabled: true,
		}
		cfg.TLS.CAPath = filepath.Join(t.TempDir(), "missing-ca.pem")
		_, err := commonKafkaClientOptions(cfg, nil, log.NewNopLogger())
		require.Error(t, err)
	})
}

// writeTestCertificates emits a throwaway CA, leaf cert, and key into t.TempDir()
// so the tests can exercise the full dstls.GetTLSConfig() loading path.
func writeTestCertificates(t *testing.T) (certPath, keyPath, caPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tempo-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	caPath = filepath.Join(dir, "ca.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(caPath, certPEM, 0o600))

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	return certPath, keyPath, caPath
}
