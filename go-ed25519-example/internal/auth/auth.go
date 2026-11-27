package auth

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const keyLength = 32

type Config struct {
	RootPublicKey string
	PrivateKey    string
	KeyID         string
	OperatorID    string
}

type Service struct {
	rootPublicKey ed25519.PublicKey
	privateKey    ed25519.PrivateKey
	keyID         string
	operatorID    string
	now           func() time.Time

	mu          sync.Mutex
	usedNonces  map[string]time.Time
	nonceExpiry []usedNonce
}

type usedNonce struct {
	nonce     string
	expiresAt time.Time
}

func New(cfg Config) (*Service, error) {
	seed, seedErr := decodeKey("PRIVATE_KEY", cfg.PrivateKey)
	rootPublicKey, rootErr := decodeKey("ROOT_PUBLIC_KEY", cfg.RootPublicKey)
	if err := errors.Join(
		requireNonBlank("KEY_ID", cfg.KeyID),
		requireNonBlank("OPERATOR_ID", cfg.OperatorID),
		seedErr,
		rootErr,
	); err != nil {
		return nil, fmt.Errorf("invalid configuration:\n%w", err)
	}

	return &Service{
		rootPublicKey: rootPublicKey,
		privateKey:    ed25519.NewKeyFromSeed(seed),
		keyID:         cfg.KeyID,
		operatorID:    cfg.OperatorID,
		now:           time.Now,
		usedNonces:    make(map[string]time.Time),
	}, nil
}

func requireNonBlank(name, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is not set", name)
	}
	return nil
}

func decodeKey(name, value string) ([]byte, error) {
	if err := requireNonBlank(name, value); err != nil {
		return nil, err
	}
	key, ok := decodeBase64(value)
	if !ok {
		return nil, fmt.Errorf("%s is not valid base64", name)
	}
	if len(key) != keyLength {
		return nil, fmt.Errorf("%s must be a %d-byte raw Ed25519 key, got %d bytes", name, keyLength, len(key))
	}
	return key, nil
}
