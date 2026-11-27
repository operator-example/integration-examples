package auth

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/google/uuid"
)

var ErrInvalidUTF8 = errors.New("body is not valid UTF-8")

type SignedData struct {
	KeyID      string
	OperatorID string
	Payload    string
	Signature  []byte
}

func (s *Service) Sign(data []byte) (SignedData, error) {
	if !utf8.Valid(data) {
		return SignedData{}, ErrInvalidUTF8
	}

	nonce, err := uuid.NewV7()
	if err != nil {
		return SignedData{}, fmt.Errorf("generate nonce: %w", err)
	}

	payload, err := json.Marshal(struct {
		Data  string `json:"data"`
		Nonce string `json:"nonce"`
	}{Data: string(data), Nonce: nonce.String()})
	if err != nil {
		return SignedData{}, fmt.Errorf("marshal payload: %w", err)
	}
	payload = escapeForHeader(payload)
	return SignedData{
		KeyID:      s.keyID,
		OperatorID: s.operatorID,
		Payload:    string(payload),
		Signature:  ed25519.Sign(s.privateKey, payload),
	}, nil
}

func escapeForHeader(payload []byte) []byte {
	out := make([]byte, 0, len(payload))
	var units [2]uint16
	for _, r := range string(payload) {
		if r < 0x7F {
			out = append(out, byte(r))
			continue
		}
		for _, u := range utf16.AppendRune(units[:0], r) {
			out = fmt.Appendf(out, `\u%04X`, u)
		}
	}
	return out
}
