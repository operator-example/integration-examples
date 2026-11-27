package httpapi

import (
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"go-ed25519-example/internal/auth"
)

const maxBodySize = 8 << 20

var signHeaders = []string{
	"X-Sign-Version",
	"X-Sign-Domain",
	"X-Sign-Nonce",
	"X-Sign-Payload",
	"X-Sign-Signature",
	"X-Sign-Intermediate-Public-Key",
	"X-Sign-Intermediate-Signature",
	"X-Sign-Intermediate-Not-Before",
	"X-Sign-Intermediate-Not-After",
}

type Service interface {
	Sign(data []byte) (auth.SignedData, error)
	Verify(req auth.VerifyRequest, body []byte) bool
}

type handler struct {
	service Service
}

func New(svc Service) http.Handler {
	h := &handler{service: svc}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /Auth/sign", h.sign)
	mux.HandleFunc("POST /Auth/verify", h.verify)
	return mux
}

func (h *handler) sign(w http.ResponseWriter, r *http.Request) {
	data, ok := readBody(w, r)
	if !ok {
		return
	}
	signed, err := h.service.Sign(data)
	if errors.Is(err, auth.ErrInvalidUTF8) {
		writeError(w, r, http.StatusBadRequest, "body is not valid UTF-8")
		return
	}
	if err != nil {
		slog.ErrorContext(r.Context(), "sign failed", "error", err)
		writeError(w, r, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, r, http.StatusOK, signResponse{
		KeyID:      signed.KeyID,
		OperatorID: signed.OperatorID,
		Payload:    signed.Payload,
		Signature:  base64.StdEncoding.EncodeToString(signed.Signature),
	})
}

func (h *handler) verify(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}

	for _, name := range signHeaders {
		if len(r.Header.Values(name)) > 1 {
			writeJSON(w, r, http.StatusUnauthorized, verifyResponse{Verified: false})
			return
		}
	}

	req := auth.VerifyRequest{
		Domain:                r.Header.Get("X-Sign-Domain"),
		IntermediatePublicKey: r.Header.Get("X-Sign-Intermediate-Public-Key"),
		IntermediateSignature: r.Header.Get("X-Sign-Intermediate-Signature"),
		IntermediateNotBefore: r.Header.Get("X-Sign-Intermediate-Not-Before"),
		IntermediateNotAfter:  r.Header.Get("X-Sign-Intermediate-Not-After"),
		Nonce:                 r.Header.Get("X-Sign-Nonce"),
		Payload:               r.Header.Get("X-Sign-Payload"),
		Signature:             r.Header.Get("X-Sign-Signature"),
		Version:               r.Header.Get("X-Sign-Version"),
	}

	if !h.service.Verify(req, body) {
		writeJSON(w, r, http.StatusUnauthorized, verifyResponse{Verified: false})
		return
	}
	writeJSON(w, r, http.StatusOK, verifyResponse{Verified: true})
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodySize))
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, r, http.StatusRequestEntityTooLarge, "body is too large")
		return nil, false
	}
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid body")
		return nil, false
	}
	return body, true
}
