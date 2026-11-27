package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	signVersion    = "2"
	expectedDomain = "five-gaming"
	nonceMaxAge    = 5 * time.Minute
	nonceClockSkew = time.Minute
	nonceTTL       = nonceMaxAge + nonceClockSkew

	maxPayloadDepth = 64
)

var integerPattern = regexp.MustCompile(`^-?[0-9]+$`)

type VerifyRequest struct {
	Domain                string
	IntermediatePublicKey string
	IntermediateSignature string
	IntermediateNotBefore string
	IntermediateNotAfter  string
	Nonce                 string
	Payload               string
	Signature             string
	Version               string
}

func (s *Service) Verify(req VerifyRequest, body []byte) bool {
	if req.Version != signVersion {
		return false
	}
	intermediatePublicKey, ok := decodeBase64(req.IntermediatePublicKey)
	if !ok || len(intermediatePublicKey) != ed25519.PublicKeySize {
		return false
	}

	intermediateSignature, ok := decodeBase64(req.IntermediateSignature)
	if !ok || len(intermediateSignature) != ed25519.SignatureSize {
		return false
	}

	signature, ok := decodeBase64(req.Signature)
	if !ok || len(signature) != ed25519.SignatureSize {
		return false
	}

	notBefore, ok := parseInteger(req.IntermediateNotBefore)
	if !ok {
		return false
	}

	notAfter, ok := parseInteger(req.IntermediateNotAfter)
	if !ok {
		return false
	}

	now := time.Unix(s.now().Unix(), 0)
	if now.Unix() < notBefore || now.Unix() > notAfter {
		return false
	}

	certificate := fmt.Appendf(nil, `{"not_after":%d,"not_before":%d,"public_key":"%s"}`,
		notAfter, notBefore, base64.StdEncoding.EncodeToString(intermediatePublicKey))

	if !ed25519.Verify(s.rootPublicKey, certificate, intermediateSignature) {
		return false
	}

	signedPayload := []byte(req.Payload)
	if !ed25519.Verify(intermediatePublicKey, signedPayload, signature) {
		return false
	}

	document, ok := parsePayload(signedPayload)
	if !ok {
		return false
	}

	if domain, ok := stringField(document, "domain"); !ok || domain != expectedDomain {
		return false
	}
	if nonce, ok := stringField(document, "nonce"); !ok || nonce != req.Nonce {
		return false
	}
	if data, ok := stringField(document, "data"); !ok || data != string(body) {
		return false
	}
	if req.Domain != expectedDomain {
		return false
	}

	if !isNonceFresh(req.Nonce, now) {
		return false
	}

	return s.markNonceUsed(req.Nonce, now)
}

func parseInteger(value string) (int64, bool) {
	if !integerPattern.MatchString(value) {
		return 0, false
	}
	n, err := strconv.ParseInt(value, 10, 64)
	return n, err == nil
}

func parsePayload(payload []byte) (map[string]json.RawMessage, bool) {
	if !utf8.Valid(payload) || hasLoneSurrogate(payload) || exceedsDepth(payload, maxPayloadDepth) {
		return nil, false
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(payload, &document); err != nil || document == nil {
		return nil, false
	}
	return document, true
}

func hasLoneSurrogate(payload []byte) bool {
	for i := 0; i < len(payload); i++ {
		if payload[i] != '\\' {
			continue
		}
		code, ok := unicodeEscapeAt(payload, i)
		if !ok {
			i++
			continue
		}
		switch {
		case utf16.IsSurrogate(rune(code)) && code < 0xDC00:
			low, ok := unicodeEscapeAt(payload, i+6)
			if !ok || low < 0xDC00 || low > 0xDFFF {
				return true
			}
			i += 11
		case utf16.IsSurrogate(rune(code)):
			return true
		default:
			i += 5
		}
	}
	return false
}

func exceedsDepth(payload []byte, max int) bool {
	depth := 0
	inString := false
	for i := 0; i < len(payload); i++ {
		c := payload[i]
		if inString {
			switch c {
			case '\\':
				i++
			case '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > max {
				return true
			}
		case '}', ']':
			depth--
		}
	}
	return false
}

func unicodeEscapeAt(payload []byte, i int) (uint16, bool) {
	if i+6 > len(payload) || payload[i] != '\\' || payload[i+1] != 'u' {
		return 0, false
	}
	code, err := strconv.ParseUint(string(payload[i+2:i+6]), 16, 16)
	return uint16(code), err == nil
}

func stringField(document map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := document[key]
	if !ok || len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	return value, true
}

func isNonceFresh(nonce string, now time.Time) bool {
	if len(nonce) < 13 {
		return false
	}
	unixMilli, err := strconv.ParseUint(nonce[:8]+nonce[9:13], 16, 64)
	if err != nil {
		return false
	}
	signedAt := time.Unix(int64(unixMilli/1000), 0)

	age := now.Sub(signedAt)
	return age <= nonceMaxAge && age >= -nonceClockSkew
}

func (s *Service) markNonceUsed(nonce string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for len(s.nonceExpiry) > 0 && s.nonceExpiry[0].expiresAt.Before(now) {
		delete(s.usedNonces, s.nonceExpiry[0].nonce)
		s.nonceExpiry = s.nonceExpiry[1:]
	}

	if _, used := s.usedNonces[nonce]; used {
		return false
	}

	expiresAt := now.Add(nonceTTL)
	s.usedNonces[nonce] = expiresAt
	s.nonceExpiry = append(s.nonceExpiry, usedNonce{nonce: nonce, expiresAt: expiresAt})
	return true
}
