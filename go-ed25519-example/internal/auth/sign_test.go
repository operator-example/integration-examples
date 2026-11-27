package auth

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"
)

var (
	printableASCII = regexp.MustCompile(`^[\x20-\x7E]*$`)
	uuidV7Pattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

func TestSign(t *testing.T) {
	bodies := []string{
		`{"order_id":"A123","amount":100}`,
		`{"name":"測試會員","emoji":"🎰","html":"<b>&</b>"}`,
		"line1\nline2\t\x01",
		"del\x7f",
		"bmp \uffff, surrogate pair 𝄞, quote \" backslash \\",
		"",
	}

	for _, body := range bodies {
		t.Run(fmt.Sprintf("%.30q", body), func(t *testing.T) {
			s := newTestService(t)
			before := time.Now().UnixMilli()
			signed, err := s.Sign([]byte(body))
			after := time.Now().UnixMilli()
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			if signed.KeyID != "test-key" || signed.OperatorID != "test-operator" {
				t.Errorf("ids = %q / %q", signed.KeyID, signed.OperatorID)
			}
			if !ed25519.Verify(testOperatorKey.Public().(ed25519.PublicKey), []byte(signed.Payload), signed.Signature) {
				t.Error("signature does not verify with the operator public key")
			}

			if !printableASCII.MatchString(signed.Payload) {
				t.Errorf("payload is not printable ASCII: %q", signed.Payload)
			}

			var payload struct {
				Data  *string `json:"data"`
				Nonce *string `json:"nonce"`
			}
			if err := json.Unmarshal([]byte(signed.Payload), &payload); err != nil {
				t.Fatalf("payload is not valid JSON: %v", err)
			}
			if payload.Data == nil || *payload.Data != body {
				t.Errorf("payload data = %v, want %q", payload.Data, body)
			}
			if payload.Nonce == nil {
				t.Fatal("payload has no nonce")
			}

			nonce := *payload.Nonce
			if !uuidV7Pattern.MatchString(nonce) {
				t.Errorf("nonce %q is not a UUIDv7", nonce)
			}
			ms, _ := strconv.ParseInt(nonce[:8]+nonce[9:13], 16, 64)
			if ms < before || ms > after {
				t.Errorf("nonce timestamp %d not in [%d, %d]", ms, before, after)
			}
		})
	}
}

func TestSignRejectsInvalidUTF8(t *testing.T) {
	s := newTestService(t)
	for _, body := range [][]byte{{0xff}, {0xc3}, {0xed, 0xa0, 0x80}} {
		if _, err := s.Sign(body); !errors.Is(err, ErrInvalidUTF8) {
			t.Errorf("Sign(% x) error = %v, want ErrInvalidUTF8", body, err)
		}
	}
}

func TestEscapeForHeader(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{in: "plain ~", want: "plain ~"},
		{in: "\x7f", want: `\u007F`},
		{in: "\u00e9", want: `\u00E9`},
		{in: "\uffff", want: `\uFFFF`},
		{in: "\ufffd", want: `\uFFFD`},
		{in: "\U0001D11E", want: `\uD834\uDD1E`},
		{in: "a\U0001F3B0b", want: `a\uD83C\uDFB0b`},
	}
	for _, tt := range tests {
		if got := string(escapeForHeader([]byte(tt.in))); got != tt.want {
			t.Errorf("escapeForHeader(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSignPayloadEscapingCases(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/payload-escaping-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Cases []struct {
			Name     string `json:"name"`
			BodyHex  string `json:"bodyHex"`
			Rejected bool   `json:"rejected"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Cases) <= 100 {
		t.Fatalf("expected more than 100 cases, got %d", len(document.Cases))
	}

	s := newTestService(t)
	for _, c := range document.Cases {
		t.Run(c.Name, func(t *testing.T) {
			body, err := hex.DecodeString(c.BodyHex)
			if err != nil {
				t.Fatal(err)
			}

			signed, err := s.Sign(body)
			if c.Rejected {
				if !errors.Is(err, ErrInvalidUTF8) {
					t.Fatalf("Sign error = %v, want ErrInvalidUTF8", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}

			if !printableASCII.MatchString(signed.Payload) {
				t.Errorf("payload is not printable ASCII: %q", signed.Payload)
			}
			var payload struct {
				Data *string `json:"data"`
			}
			if err := json.Unmarshal([]byte(signed.Payload), &payload); err != nil || payload.Data == nil {
				t.Fatalf("payload is not a JSON object with data: %v", err)
			}
			if *payload.Data != string(body) {
				t.Errorf("data = %q, want %q", *payload.Data, body)
			}
			if !ed25519.Verify(testOperatorKey.Public().(ed25519.PublicKey), []byte(signed.Payload), signed.Signature) {
				t.Error("signature does not verify")
			}
		})
	}
}

func TestSignUsesFreshNonce(t *testing.T) {
	s := newTestService(t)
	a, _ := s.Sign([]byte("same"))
	b, _ := s.Sign([]byte("same"))
	if a.Payload == b.Payload {
		t.Fatal("two signatures of the same data produced the same payload")
	}
}
