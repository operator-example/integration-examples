package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

var (
	testOperatorKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	testRootKey     = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	testNow         = time.Unix(1_700_000_000, 999_000_000)
)

var b64 = base64.StdEncoding.EncodeToString

func testConfig() Config {
	return Config{
		RootPublicKey: b64(testRootKey.Public().(ed25519.PublicKey)),
		PrivateKey:    b64(testOperatorKey.Seed()),
		KeyID:         "test-key",
		OperatorID:    "test-operator",
	}
}

func newTestService(t *testing.T) *Service {
	t.Helper()
	s, err := New(testConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.now = func() time.Time { return testNow }
	return s
}

func randomKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func nonceAt(unixMilli int64) string {
	var b [16]byte
	rand.Read(b[6:])
	for i := range 6 {
		b[i] = byte(uint64(unixMilli) >> (40 - 8*i))
	}
	b[6] = 0x70 | b[6]&0x0F
	b[8] = 0x80 | b[8]&0x3F
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr string
	}{
		{name: "valid config"},
		{name: "root public key missing", modify: func(c *Config) { c.RootPublicKey = "" }, wantErr: "ROOT_PUBLIC_KEY"},
		{name: "root public key not base64", modify: func(c *Config) { c.RootPublicKey = "not base64!!" }, wantErr: "ROOT_PUBLIC_KEY"},
		{name: "root public key wrong length", modify: func(c *Config) { c.RootPublicKey = b64(make([]byte, 31)) }, wantErr: "ROOT_PUBLIC_KEY"},
		{name: "private key missing", modify: func(c *Config) { c.PrivateKey = "" }, wantErr: "PRIVATE_KEY"},
		{name: "private key is 64-byte form, not seed", modify: func(c *Config) { c.PrivateKey = b64(testOperatorKey) }, wantErr: "PRIVATE_KEY"},
		{name: "private key with a line break", modify: func(c *Config) { c.PrivateKey = c.PrivateKey[:4] + "\n" + c.PrivateKey[4:] }, wantErr: "PRIVATE_KEY is not valid base64"},
		{name: "private key with a trailing line feed", modify: func(c *Config) { c.PrivateKey += "\n" }, wantErr: "PRIVATE_KEY is not valid base64"},
		{name: "root public key with non-zero trailing bits", modify: func(c *Config) { c.RootPublicKey = withNonZeroTrailingBits(c.RootPublicKey) }},
		{name: "key id missing", modify: func(c *Config) { c.KeyID = "" }, wantErr: "KEY_ID"},
		{name: "operator id missing", modify: func(c *Config) { c.OperatorID = "" }, wantErr: "OPERATOR_ID"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			if tt.modify != nil {
				tt.modify(&cfg)
			}
			s, err := New(cfg)

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !s.privateKey.Equal(testOperatorKey) || !s.rootPublicKey.Equal(testRootKey.Public()) {
					t.Fatal("keys were not decoded from the configuration")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestNewReportsEveryProblem(t *testing.T) {
	_, err := New(Config{KeyID: "", OperatorID: " ", PrivateKey: "not base64!!", RootPublicKey: b64(make([]byte, 48))})

	want := strings.Join([]string{
		"invalid configuration:",
		"KEY_ID is not set",
		"OPERATOR_ID is not set",
		"PRIVATE_KEY is not valid base64",
		"ROOT_PUBLIC_KEY must be a 32-byte raw Ed25519 key, got 48 bytes",
	}, "\n")
	if err == nil || err.Error() != want {
		t.Fatalf("New() error = %v, want %q", err, want)
	}
}

func TestConfigErrorsNeverContainTheSecret(t *testing.T) {
	secret := b64([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
	cfg := testConfig()
	cfg.PrivateKey = secret

	_, err := New(cfg)

	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("error = %v, want an error that does not contain the key", err)
	}
}
