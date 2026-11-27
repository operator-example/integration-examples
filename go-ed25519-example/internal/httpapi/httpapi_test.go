package httpapi

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go-ed25519-example/internal/auth"
)

type fakeService struct {
	signData auth.SignedData
	signErr  error
	verified bool

	gotSignData   []byte
	signCalls     int
	gotVerifyReq  auth.VerifyRequest
	gotVerifyBody []byte
	verifyCalls   int
}

func (f *fakeService) Sign(data []byte) (auth.SignedData, error) {
	f.signCalls++
	f.gotSignData = data
	return f.signData, f.signErr
}

func (f *fakeService) Verify(req auth.VerifyRequest, body []byte) bool {
	f.verifyCalls++
	f.gotVerifyReq = req
	f.gotVerifyBody = body
	return f.verified
}

func serve(t *testing.T, fake *fakeService, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	New(fake).ServeHTTP(rec, req)
	return rec
}

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &buf
}

func signHeaderValues() map[string]string {
	return map[string]string{
		"X-Sign-Version":                 "2",
		"X-Sign-Domain":                  "five-gaming",
		"X-Sign-Nonce":                   "nonce-value",
		"X-Sign-Payload":                 `{"data":"x"}`,
		"X-Sign-Signature":               "signature-value",
		"X-Sign-Intermediate-Public-Key": "public-key-value",
		"X-Sign-Intermediate-Signature":  "intermediate-signature-value",
		"X-Sign-Intermediate-Not-Before": "100",
		"X-Sign-Intermediate-Not-After":  "200",
	}
}

func newVerifyRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/Auth/verify", strings.NewReader(body))
	for k, v := range signHeaderValues() {
		req.Header.Set(k, v)
	}
	return req
}

func assertResponse(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int, wantBody string) {
	t.Helper()
	if rec.Code != wantStatus {
		t.Errorf("status = %d, want %d", rec.Code, wantStatus)
	}
	if got := rec.Body.String(); got != wantBody {
		t.Errorf("body = %s, want %s", got, wantBody)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestVerifyPassesHeadersAndBodyToService(t *testing.T) {
	fake := &fakeService{verified: true}
	rec := serve(t, fake, newVerifyRequest(`{"amount":100}`))

	assertResponse(t, rec, http.StatusOK, `{"verified":true}`)

	want := auth.VerifyRequest{
		Version:               "2",
		Domain:                "five-gaming",
		Nonce:                 "nonce-value",
		Payload:               `{"data":"x"}`,
		Signature:             "signature-value",
		IntermediatePublicKey: "public-key-value",
		IntermediateSignature: "intermediate-signature-value",
		IntermediateNotBefore: "100",
		IntermediateNotAfter:  "200",
	}
	if fake.gotVerifyReq != want {
		t.Errorf("service got %+v\nwant %+v", fake.gotVerifyReq, want)
	}
	if string(fake.gotVerifyBody) != `{"amount":100}` {
		t.Errorf("service got body %q", fake.gotVerifyBody)
	}
}

func TestVerifyRejectedByService(t *testing.T) {
	fake := &fakeService{verified: false}
	rec := serve(t, fake, newVerifyRequest("x"))

	assertResponse(t, rec, http.StatusUnauthorized, `{"verified":false}`)
}

func TestVerifyRejectsDuplicatedHeaders(t *testing.T) {
	for name := range signHeaderValues() {
		t.Run(name, func(t *testing.T) {
			fake := &fakeService{verified: true}
			req := newVerifyRequest("x")
			req.Header.Add(name, "second-value")

			rec := serve(t, fake, req)

			assertResponse(t, rec, http.StatusUnauthorized, `{"verified":false}`)
			if fake.verifyCalls != 0 {
				t.Error("service should not be called when a header is duplicated")
			}
		})
	}
}

func TestVerifyBodyTooLarge(t *testing.T) {
	fake := &fakeService{verified: true}
	rec := serve(t, fake, newVerifyRequest(strings.Repeat("a", maxBodySize+1)))

	assertResponse(t, rec, http.StatusRequestEntityTooLarge, `{"error":"body is too large"}`)
	if fake.verifyCalls != 0 {
		t.Error("service should not be called when the body is too large")
	}
}

func TestSign(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		fake       fakeService
		wantStatus int
		wantBody   string
		wantCalled bool
		wantLog    string
	}{
		{
			name: "signed",
			body: `{"amount":100}`,
			fake: fakeService{signData: auth.SignedData{
				KeyID:      "key-1",
				OperatorID: "operator-1",
				Payload:    `{"data":"x","nonce":"n"}`,
				Signature:  []byte{1, 2, 3},
			}},
			wantStatus: http.StatusOK,
			wantBody:   `{"key_id":"key-1","operator_id":"operator-1","payload":"{\"data\":\"x\",\"nonce\":\"n\"}","signature":"AQID"}`,
			wantCalled: true,
		},
		{
			name:       "service error",
			body:       "x",
			fake:       fakeService{signErr: errors.New("boom")},
			wantStatus: http.StatusInternalServerError,
			wantBody:   `{"error":"internal server error"}`,
			wantCalled: true,
			wantLog:    `msg="sign failed" error=boom`,
		},
		{
			name:       "invalid UTF-8",
			body:       "\xff",
			fake:       fakeService{signErr: auth.ErrInvalidUTF8},
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"error":"body is not valid UTF-8"}`,
			wantCalled: true,
		},
		{
			name:       "body too large",
			body:       strings.Repeat("a", maxBodySize+1),
			wantStatus: http.StatusRequestEntityTooLarge,
			wantBody:   `{"error":"body is too large"}`,
		},
		{
			name:       "body at limit",
			body:       strings.Repeat("a", maxBodySize),
			wantStatus: http.StatusOK,
			wantBody:   `{"key_id":"","operator_id":"","payload":"","signature":""}`,
			wantCalled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureLogs(t)
			fake := tt.fake
			req := httptest.NewRequest(http.MethodPost, "/Auth/sign", strings.NewReader(tt.body))

			rec := serve(t, &fake, req)

			assertResponse(t, rec, tt.wantStatus, tt.wantBody)
			if !tt.wantCalled {
				if fake.signCalls != 0 {
					t.Error("service should not be called")
				}
				return
			}
			if fake.signCalls != 1 || string(fake.gotSignData) != tt.body {
				t.Errorf("service got %d calls with data %.40q, want the raw body once", fake.signCalls, fake.gotSignData)
			}
			if tt.wantLog != "" && !strings.Contains(logs.String(), tt.wantLog) {
				t.Errorf("logs = %q, want them to contain %q", logs.String(), tt.wantLog)
			}
		})
	}
}

func TestRoutesOnlyAcceptPost(t *testing.T) {
	for _, path := range []string{"/Auth/sign", "/Auth/verify"} {
		t.Run(path, func(t *testing.T) {
			rec := serve(t, &fakeService{}, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("GET %s status = %d, want %d", path, rec.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}
