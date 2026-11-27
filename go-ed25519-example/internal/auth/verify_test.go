package auth

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

type signedRequest struct {
	body          string
	data          any
	payloadDomain string
	nonce         string
	notBefore     int64
	notAfter      int64
	root          ed25519.PrivateKey
	payloadSigner ed25519.PrivateKey
	rawPayload    []byte
}

func newSignedRequest() *signedRequest {
	return &signedRequest{
		body:          `{"amount":100}`,
		payloadDomain: expectedDomain,
		nonce:         nonceAt(testNow.UnixMilli()),
		notBefore:     testNow.Unix() - 60,
		notAfter:      testNow.Unix() + 3600,
		root:          testRootKey,
	}
}

func (sr *signedRequest) build(t *testing.T) (VerifyRequest, []byte) {
	t.Helper()
	intermediate := randomKey(t)
	intermediatePub := intermediate.Public().(ed25519.PublicKey)

	certificate := fmt.Appendf(nil, `{"not_after":%d,"not_before":%d,"public_key":"%s"}`,
		sr.notAfter, sr.notBefore, b64(intermediatePub))

	payload := sr.rawPayload
	if payload == nil {
		var data any = sr.body
		if sr.data != nil {
			data = sr.data
		}
		var err error
		payload, err = json.Marshal(map[string]any{"data": data, "domain": sr.payloadDomain, "nonce": sr.nonce})
		if err != nil {
			t.Fatal(err)
		}
	}

	payloadSigner := sr.payloadSigner
	if payloadSigner == nil {
		payloadSigner = intermediate
	}

	return VerifyRequest{
		Version:               signVersion,
		Domain:                expectedDomain,
		Nonce:                 sr.nonce,
		Payload:               string(payload),
		Signature:             b64(ed25519.Sign(payloadSigner, payload)),
		IntermediatePublicKey: b64(intermediatePub),
		IntermediateSignature: b64(ed25519.Sign(sr.root, certificate)),
		IntermediateNotBefore: strconv.FormatInt(sr.notBefore, 10),
		IntermediateNotAfter:  strconv.FormatInt(sr.notAfter, 10),
	}, []byte(sr.body)
}

func nestedPayload(r *signedRequest, depth int) []byte {
	arrays := depth - 1
	return fmt.Appendf(nil, `{"data":%q,"domain":"five-gaming","nonce":%q,"x":%s%s}`,
		r.body, r.nonce, strings.Repeat("[", arrays), strings.Repeat("]", arrays))
}

func TestVerify(t *testing.T) {
	nowMilli := testNow.UnixMilli()
	nowSec := testNow.Unix()

	tests := []struct {
		name   string
		setup  func(*signedRequest)
		tamper func(req *VerifyRequest, body *[]byte)
		want   bool
	}{
		{name: "valid request", want: true},
		{name: "unicode body", setup: func(r *signedRequest) { r.body = `{"name":"Joë’s Café — €5","emoji":"🎰"}` }, want: true},
		{name: "empty body", setup: func(r *signedRequest) { r.body = "" }, want: true},
		{name: "nonce slightly in the future, within clock skew", setup: func(r *signedRequest) { r.nonce = nonceAt(nowMilli + 30_000) }, want: true},

		{name: "wrong version", tamper: func(req *VerifyRequest, _ *[]byte) { req.Version = "1" }},
		{name: "missing version", tamper: func(req *VerifyRequest, _ *[]byte) { req.Version = "" }},

		{name: "signature not base64", tamper: func(req *VerifyRequest, _ *[]byte) { req.Signature = "not-base64!!" }},
		{name: "signature base64 with a line feed", tamper: func(req *VerifyRequest, _ *[]byte) { req.Signature = req.Signature[:4] + "\n" + req.Signature[4:] }},
		{name: "signature base64 with a CRLF", tamper: func(req *VerifyRequest, _ *[]byte) { req.Signature = req.Signature[:4] + "\r\n" + req.Signature[4:] }},
		{name: "signature base64 with a trailing line feed", tamper: func(req *VerifyRequest, _ *[]byte) { req.Signature += "\n" }},
		{name: "intermediate public key with non-zero trailing bits", tamper: func(req *VerifyRequest, _ *[]byte) {
			req.IntermediatePublicKey = withNonZeroTrailingBits(req.IntermediatePublicKey)
		}, want: true},
		{name: "signature wrong length", tamper: func(req *VerifyRequest, _ *[]byte) { req.Signature = b64(make([]byte, 63)) }},
		{name: "signature missing", tamper: func(req *VerifyRequest, _ *[]byte) { req.Signature = "" }},
		{name: "intermediate public key wrong length", tamper: func(req *VerifyRequest, _ *[]byte) { req.IntermediatePublicKey = b64(make([]byte, 31)) }},
		{name: "intermediate signature missing", tamper: func(req *VerifyRequest, _ *[]byte) { req.IntermediateSignature = "" }},

		{name: "certificate signed by another root", setup: func(r *signedRequest) { r.root = randomKey(t) }},
		{name: "validity extended after signing", tamper: func(req *VerifyRequest, _ *[]byte) { req.IntermediateNotAfter = "9999999999" }},
		{name: "not-after not a number", tamper: func(req *VerifyRequest, _ *[]byte) { req.IntermediateNotAfter = "soon" }},
		{name: "certificate expired", setup: func(r *signedRequest) { r.notAfter = nowSec - 1 }},
		{name: "certificate not yet valid", setup: func(r *signedRequest) { r.notBefore = nowSec + 600 }},
		{name: "certificate expires this second", setup: func(r *signedRequest) { r.notAfter = nowSec }, want: true},
		{name: "certificate valid from this second", setup: func(r *signedRequest) { r.notBefore = nowSec }, want: true},
		{name: "certificate valid from next second", setup: func(r *signedRequest) { r.notBefore = nowSec + 1 }},

		{name: "payload signed by another key", setup: func(r *signedRequest) { r.payloadSigner = randomKey(t) }},
		{name: "payload header tampered", tamper: func(req *VerifyRequest, _ *[]byte) { req.Payload = strings.Replace(req.Payload, "100", "999", 1) }},

		{name: "payload not JSON", setup: func(r *signedRequest) { r.rawPayload = []byte("not json") }},
		{name: "payload is a JSON array", setup: func(r *signedRequest) { r.rawPayload = []byte("[1,2]") }},
		{name: "payload data is not a string", setup: func(r *signedRequest) { r.data = 100 }},
		{name: "payload domain mismatch", setup: func(r *signedRequest) { r.payloadDomain = "evil" }},
		{name: "header domain mismatch", tamper: func(req *VerifyRequest, _ *[]byte) { req.Domain = "evil" }},
		{name: "nonce header does not match payload", tamper: func(req *VerifyRequest, _ *[]byte) { req.Nonce = nonceAt(nowMilli) }},
		{name: "body tampered", tamper: func(_ *VerifyRequest, body *[]byte) { *body = []byte(`{"amount":999}`) }},

		{name: "payload keys differ in case", setup: func(r *signedRequest) {
			r.rawPayload = fmt.Appendf(nil, `{"DATA":%q,"Domain":"five-gaming","Nonce":%q}`, r.body, r.nonce)
		}},
		{name: "valid surrogate pair in data", setup: func(r *signedRequest) {
			r.body = "\U0001F680"
			r.rawPayload = fmt.Appendf(nil, `{"data":"\ud83d\ude80","domain":"five-gaming","nonce":%q}`, r.nonce)
		}, want: true},
		{name: "lone low surrogate in data", setup: func(r *signedRequest) {
			r.body = "\ufffd"
			r.rawPayload = fmt.Appendf(nil, `{"data":"\udcff","domain":"five-gaming","nonce":%q}`, r.nonce)
		}},
		{name: "high surrogate not followed by low surrogate", setup: func(r *signedRequest) {
			r.body = "\ufffda"
			r.rawPayload = fmt.Appendf(nil, `{"data":"\ud83da","domain":"five-gaming","nonce":%q}`, r.nonce)
		}},
		{name: "lone surrogate in an unused key", setup: func(r *signedRequest) {
			r.rawPayload = fmt.Appendf(nil, `{"data":%q,"domain":"five-gaming","nonce":%q,"x":"\udcff"}`, r.body, r.nonce)
		}},
		{name: "escaped backslash before u is not a surrogate", setup: func(r *signedRequest) {
			r.body = `\udcff`
			r.rawPayload = fmt.Appendf(nil, `{"data":"\\udcff","domain":"five-gaming","nonce":%q}`, r.nonce)
		}, want: true},
		{name: "invalid UTF-8 byte in payload", setup: func(r *signedRequest) {
			r.body = "\ufffd"
			r.rawPayload = fmt.Appendf(nil, "{\"data\":\"\xff\",\"domain\":\"five-gaming\",\"nonce\":%q}", r.nonce)
		}},
		{name: "payload starts with a byte order mark", setup: func(r *signedRequest) {
			r.rawPayload = fmt.Appendf(nil, "\xEF\xBB\xBF{\"data\":%q,\"domain\":\"five-gaming\",\"nonce\":%q}", r.body, r.nonce)
		}},
		{name: "payload nested 64 levels deep", setup: func(r *signedRequest) {
			r.rawPayload = nestedPayload(r, 64)
		}, want: true},
		{name: "payload nested 65 levels deep", setup: func(r *signedRequest) { r.rawPayload = nestedPayload(r, 65) }},
		{name: "brackets inside strings do not count as nesting", setup: func(r *signedRequest) {
			r.body = strings.Repeat("[", 100) + `\"` + strings.Repeat("{", 100)
			r.rawPayload = nil
		}, want: true},
		{name: "not-before with a plus sign", tamper: func(req *VerifyRequest, _ *[]byte) { req.IntermediateNotBefore = "+" + req.IntermediateNotBefore }},

		{name: "nonce too old", setup: func(r *signedRequest) { r.nonce = nonceAt(nowMilli - 6*60_000) }},
		{name: "nonce too far in the future", setup: func(r *signedRequest) { r.nonce = nonceAt(nowMilli + 2*60_000) }},
		{name: "nonce centuries in the future", setup: func(r *signedRequest) { r.nonce = nonceAt((nowSec + 18446744073) * 1000) }},
		{name: "nonce too short", setup: func(r *signedRequest) { r.nonce = "abc" }},
		{name: "nonce not hex", setup: func(r *signedRequest) { r.nonce = "zzzzzzzz-zzzz-7zzz-8zzz-zzzzzzzzzzzz" }},

		{name: "nonce exactly at max age", setup: func(r *signedRequest) { r.nonce = nonceAt((nowSec - 300) * 1000) }, want: true},
		{name: "nonce one millisecond past max age second", setup: func(r *signedRequest) { r.nonce = nonceAt((nowSec-300)*1000 - 1) }},
		{name: "nonce at the end of the clock skew second", setup: func(r *signedRequest) { r.nonce = nonceAt((nowSec+60)*1000 + 999) }, want: true},
		{name: "nonce one second beyond clock skew", setup: func(r *signedRequest) { r.nonce = nonceAt((nowSec + 61) * 1000) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := newSignedRequest()
			if tt.setup != nil {
				tt.setup(sr)
			}
			req, body := sr.build(t)
			if tt.tamper != nil {
				tt.tamper(&req, &body)
			}

			got := newTestService(t).Verify(req, body)
			if got != tt.want {
				t.Fatalf("Verified = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifyUsesRealClockByDefault(t *testing.T) {
	s, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	sr := newSignedRequest()
	sr.nonce = nonceAt(now.UnixMilli())
	sr.notBefore = now.Unix() - 60
	sr.notAfter = now.Unix() + 3600
	req, body := sr.build(t)

	if !s.Verify(req, body) {
		t.Fatal("request signed now should be accepted with the default clock")
	}
}

func TestVerifyRejectsReplay(t *testing.T) {
	s := newTestService(t)
	req, body := newSignedRequest().build(t)

	if !s.Verify(req, body) {
		t.Fatal("first request should be accepted")
	}
	if s.Verify(req, body) {
		t.Fatal("replayed request should be rejected")
	}
}

func TestVerifyFailedRequestDoesNotUseUpNonce(t *testing.T) {
	s := newTestService(t)
	req, body := newSignedRequest().build(t)

	if s.Verify(req, []byte("wrong body")) {
		t.Fatal("request with wrong body should be rejected")
	}
	if !s.Verify(req, body) {
		t.Fatal("valid request should still be accepted after a failed attempt with the same nonce")
	}
}

func TestVerifyConcurrentReplayOnlyOneWins(t *testing.T) {
	s := newTestService(t)
	req, body := newSignedRequest().build(t)

	const attempts = 50
	results := make(chan bool, attempts)
	for range attempts {
		go func() { results <- s.Verify(req, body) }()
	}

	accepted := 0
	for range attempts {
		if <-results {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("%d of %d concurrent identical requests were accepted, want exactly 1", accepted, attempts)
	}
}

func TestMarkNonceUsedForgetsExpiredNonces(t *testing.T) {
	s := newTestService(t)
	now := time.Unix(testNow.Unix(), 0)

	if !s.markNonceUsed("old", now) {
		t.Fatal("first use should succeed")
	}
	if s.markNonceUsed("old", now.Add(nonceTTL)) {
		t.Fatal("nonce should still be remembered right at its expiry time")
	}

	s.markNonceUsed("new", now.Add(nonceTTL+time.Second))
	if _, ok := s.usedNonces["old"]; ok {
		t.Error("expired nonce was not removed from the map")
	}
	if len(s.nonceExpiry) != 1 || s.nonceExpiry[0].nonce != "new" {
		t.Errorf("expiry queue = %+v, want only the new nonce", s.nonceExpiry)
	}
}

func withNonZeroTrailingBits(encoded string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	last := len(strings.TrimRight(encoded, "=")) - 1
	return encoded[:last] + string(alphabet[strings.IndexByte(alphabet, encoded[last])|1]) + encoded[last+1:]
}
