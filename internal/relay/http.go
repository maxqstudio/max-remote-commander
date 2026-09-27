package relay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const maxRequestBytes int64 = 1 << 20

type HTTPServer struct {
	Store *Store
	Now   func() time.Time
}

type commandBody struct {
	RequestID string          `json:"request_id"`
	Payload   json.RawMessage `json:"payload"`
}

type resultBody struct {
	RequestID string          `json:"request_id"`
	Payload   json.RawMessage `json:"payload"`
}

func (s *HTTPServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("POST /v1/devices/{device}/session", s.register)
	mux.HandleFunc("POST /v1/devices/{device}/commands", s.queueCommand)
	mux.HandleFunc("GET /v1/devices/{device}/commands/next", s.nextCommand)
	mux.HandleFunc("POST /v1/devices/{device}/results", s.submitResult)
	mux.HandleFunc("GET /v1/results/{request}/events", s.resultEvents)
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (s *HTTPServer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func bearer(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	value := r.Header.Get("Authorization")
	if !strings.HasPrefix(value, prefix) {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(value, prefix))
	return token, token != ""
}

func (s *HTTPServer) requireController(w http.ResponseWriter, r *http.Request) bool {
	token, ok := bearer(r)
	if !ok || !s.Store.ControllerAuthorized(token) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return false
	}
	return true
}

func decodeBody(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return errors.New("multiple JSON values")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func relayStatus(err error) int {
	switch {
	case errors.Is(err, ErrUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, ErrInvalidIdentifier):
		return http.StatusBadRequest
	case errors.Is(err, ErrUnknownDevice), errors.Is(err, ErrUnknownRequest):
		return http.StatusNotFound
	case errors.Is(err, ErrQueueFull):
		return http.StatusTooManyRequests
	case errors.Is(err, ErrDuplicateRequest):
		return http.StatusConflict
	case errors.Is(err, ErrWrongDevice):
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

func (s *HTTPServer) register(w http.ResponseWriter, r *http.Request) {
	token, ok := bearer(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	session, err := s.Store.Register(r.PathValue("device"), token, s.now())
	if err != nil {
		writeError(w, relayStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, session)
}

func (s *HTTPServer) queueCommand(w http.ResponseWriter, r *http.Request) {
	if !s.requireController(w, r) {
		return
	}
	var body commandBody
	if err := decodeBody(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	payload, err := json.Marshal(body.Payload)
	if err != nil || len(body.Payload) == 0 {
		writeError(w, http.StatusBadRequest, "payload is required")
		return
	}
	if err := s.Store.QueueCommand(r.PathValue("device"), Command{RequestID: body.RequestID, Payload: payload}); err != nil {
		writeError(w, relayStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "queued"})
}

func (s *HTTPServer) nextCommand(w http.ResponseWriter, r *http.Request) {
	token, ok := bearer(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	wait := 25 * time.Second
	if raw := r.URL.Query().Get("wait_ms"); raw != "" {
		ms, err := strconv.Atoi(raw)
		if err != nil || ms < 0 || ms > 30000 {
			writeError(w, http.StatusBadRequest, "wait_ms must be 0..30000")
			return
		}
		wait = time.Duration(ms) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(r.Context(), wait)
	defer cancel()
	command, err := s.Store.NextCommand(ctx, r.PathValue("device"), token, s.now)
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeError(w, relayStatus(err), err.Error())
		return
	}
	var payload json.RawMessage = append([]byte(nil), command.Payload...)
	writeJSON(w, http.StatusOK, commandBody{RequestID: command.RequestID, Payload: payload})
}

func (s *HTTPServer) submitResult(w http.ResponseWriter, r *http.Request) {
	token, ok := bearer(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var body resultBody
	if err := decodeBody(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	payload, err := json.Marshal(body.Payload)
	if err != nil || len(body.Payload) == 0 {
		writeError(w, http.StatusBadRequest, "payload is required")
		return
	}
	err = s.Store.SubmitResult(r.PathValue("device"), token, Result{RequestID: body.RequestID, Payload: payload}, s.now())
	if err != nil {
		writeError(w, relayStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

func (s *HTTPServer) resultEvents(w http.ResponseWriter, r *http.Request) {
	if !s.requireController(w, r) {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, err := s.Store.WaitResult(ctx, r.PathValue("request"))
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeError(w, relayStatus(err), err.Error())
		return
	}
	payload := base64.RawURLEncoding.EncodeToString(result.Payload)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Connection", "keep-alive")
	_, _ = fmt.Fprintf(w, "event: result\ndata: %s\n\n", payload)
	flusher.Flush()
}
