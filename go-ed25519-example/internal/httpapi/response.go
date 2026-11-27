package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

type signResponse struct {
	KeyID      string `json:"key_id"`
	OperatorID string `json:"operator_id"`
	Payload    string `json:"payload"`
	Signature  string `json:"signature"`
}

type verifyResponse struct {
	Verified bool `json:"verified"`
}

type errorResponse struct {
	Error string `json:"error"`
}

var internalServerErrorBody = []byte(`{"error":"internal server error"}`)

func writeJSON(w http.ResponseWriter, r *http.Request, statusCode int, data any) {
	body, err := json.Marshal(data)
	if err != nil {
		slog.ErrorContext(r.Context(), "encode response failed", "error", err)
		statusCode, body = http.StatusInternalServerError, internalServerErrorBody
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if _, err := w.Write(body); err != nil {
		slog.DebugContext(r.Context(), "write response failed", "error", err)
	}
}

func writeError(w http.ResponseWriter, r *http.Request, statusCode int, message string) {
	writeJSON(w, r, statusCode, errorResponse{Error: message})
}
