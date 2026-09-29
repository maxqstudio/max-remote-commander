package relay

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const maxRequestBytes int64 = 1 << 20

type HTTPServer struct {
	Store             *Store
	Now               func() time.Time
	HeartbeatInterval time.Duration
	HeartbeatTimeout  time.Duration
}

type commandBody struct {
	RequestID string          `json:"request_id"`
	Payload   json.RawMessage `json:"payload"`
}

type resultBody struct {
	RequestID string          `json:"request_id"`
	Payload   json.RawMessage `json:"payload"`
}

type pairingOfferBody struct {
	CodeHash        string `json:"code_hash"`
	DevicePublicKey string `json:"device_public_key"`
	TTLSeconds      int64  `json:"ttl_seconds"`
}

type pairingRedeemBody struct {
	Code                string `json:"code"`
	ControllerPublicKey string `json:"controller_public_key"`
}

func (s *HTTPServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("POST /v1/devices/{device}/bootstrap-session", s.bootstrapSession)
	mux.HandleFunc("POST /v1/devices/{device}/session", s.deviceSession)
	mux.HandleFunc("POST /v1/devices/{device}/pairing-offer", s.publishPairingOffer)
	mux.HandleFunc("GET /v1/devices/{device}/pairing/status", s.pairingStatus)
	mux.HandleFunc("POST /v1/devices/{device}/pairing/redeem", s.redeemPairing)
	mux.HandleFunc("POST /v1/devices/{device}/controller-session", s.controllerSession)
	mux.HandleFunc("DELETE /v1/devices/{device}/pairing", s.revokePairing)
	mux.HandleFunc("POST /v1/devices/{device}/commands", s.queueCommand)
	mux.HandleFunc("GET /v1/devices/{device}/stream", s.deviceStream)
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

func (s *HTTPServer) requirePairedController(w http.ResponseWriter, r *http.Request, deviceID string) bool {
	token, ok := bearer(r)
	if !ok || !s.Store.PairedControllerAuthorized(deviceID, token, s.now()) {
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
	} else if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func decodeFixedBase64(value string, size int) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != size {
		return nil, ErrInvalidIdentifier
	}
	return raw, nil
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
	case errors.Is(err, ErrUnauthorized), errors.Is(err, ErrDeviceAssertion), errors.Is(err, ErrDeviceIdentityRequired):
		return http.StatusUnauthorized
	case errors.Is(err, ErrPairingCodeInvalid), errors.Is(err, ErrControllerAssertion), errors.Is(err, ErrPairingReceipt):
		return http.StatusUnauthorized
	case errors.Is(err, ErrInvalidIdentifier), errors.Is(err, ErrInvalidPublicKey), errors.Is(err, ErrPairingMismatch), errors.Is(err, ErrInvalidCommandEnvelope):
		return http.StatusBadRequest
	case errors.Is(err, ErrUnknownDevice), errors.Is(err, ErrUnknownRequest), errors.Is(err, ErrPairingOfferMissing), errors.Is(err, ErrNotPaired):
		return http.StatusNotFound
	case errors.Is(err, ErrPairingOfferExpired):
		return http.StatusGone
	case errors.Is(err, ErrQueueFull), errors.Is(err, ErrPairingAttempts):
		return http.StatusTooManyRequests
	case errors.Is(err, ErrDuplicateRequest), errors.Is(err, ErrAlreadyPaired), errors.Is(err, ErrControllerReplay), errors.Is(err, ErrDeviceReplay), errors.Is(err, ErrCommandReplay), errors.Is(err, ErrPairingGeneration), errors.Is(err, ErrAgentSessionMismatch), errors.Is(err, ErrDeviceOffline):
		return http.StatusConflict
	case errors.Is(err, ErrWrongDevice):
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

func (s *HTTPServer) bootstrapSession(w http.ResponseWriter, r *http.Request) {
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

func (s *HTTPServer) deviceSession(w http.ResponseWriter, r *http.Request) {
	var assertion DeviceAssertion
	if err := decodeBody(w, r, &assertion); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if assertion.DeviceID != r.PathValue("device") {
		writeError(w, http.StatusBadRequest, "device id mismatch")
		return
	}
	session, err := s.Store.AuthenticateDevice(assertion, s.now())
	if err != nil {
		writeError(w, relayStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, session)
}

func (s *HTTPServer) publishPairingOffer(w http.ResponseWriter, r *http.Request) {
	token, ok := bearer(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var body pairingOfferBody
	if err := decodeBody(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	codeHashRaw, err := decodeFixedBase64(body.CodeHash, 32)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid code hash")
		return
	}
	publicRaw, err := decodeFixedBase64(body.DevicePublicKey, ed25519.PublicKeySize)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid device public key")
		return
	}
	var codeHash [32]byte
	copy(codeHash[:], codeHashRaw)
	receipt, err := s.Store.PublishPairingOfferWithReceipt(
		r.PathValue("device"),
		token,
		codeHash,
		ed25519.PublicKey(publicRaw),
		time.Duration(body.TTLSeconds)*time.Second,
		s.now(),
	)
	if err != nil {
		writeError(w, relayStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"status": "pairing-offer-created",
		"receipt_token": receipt.Token,
		"receipt_expires_at": receipt.ExpiresAt,
	})
}

func (s *HTTPServer) pairingStatus(w http.ResponseWriter, r *http.Request) {
	receiptToken, ok := bearer(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	pairing, paired, err := s.Store.PairingStatus(r.PathValue("device"), receiptToken, s.now())
	if err != nil {
		writeError(w, relayStatus(err), err.Error())
		return
	}
	if !paired {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"device_id": pairing.DeviceID,
		"generation": pairing.Generation,
		"controller_public_key": base64.RawURLEncoding.EncodeToString(pairing.ControllerPublicKey),
		"paired_at": pairing.PairedAt,
	})
}

func (s *HTTPServer) redeemPairing(w http.ResponseWriter, r *http.Request) {
	var body pairingRedeemBody
	if err := decodeBody(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	publicRaw, err := decodeFixedBase64(body.ControllerPublicKey, ed25519.PublicKeySize)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid controller public key")
		return
	}
	pairing, err := s.Store.RedeemPairing(r.PathValue("device"), body.Code, ed25519.PublicKey(publicRaw), s.now())
	if err != nil {
		writeError(w, relayStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"device_id": pairing.DeviceID,
		"generation": pairing.Generation,
		"paired_at": pairing.PairedAt,
	})
}

func (s *HTTPServer) controllerSession(w http.ResponseWriter, r *http.Request) {
	var assertion ControllerAssertion
	if err := decodeBody(w, r, &assertion); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if assertion.DeviceID != r.PathValue("device") {
		writeError(w, http.StatusBadRequest, "device id mismatch")
		return
	}
	session, err := s.Store.AuthenticateController(assertion, s.now())
	if err != nil {
		writeError(w, relayStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, session)
}

func (s *HTTPServer) revokePairing(w http.ResponseWriter, r *http.Request) {
	token, ok := bearer(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := s.Store.RevokePairing(r.PathValue("device"), token, s.now()); err != nil {
		writeError(w, relayStatus(err), err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *HTTPServer) queueCommand(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("device")
	token, ok := bearer(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
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
	if err := s.Store.QueuePairedCommand(deviceID, token, Command{RequestID: body.RequestID, Payload: payload}, s.now()); err != nil {
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
	requestID := r.PathValue("request")
	deviceID, err := s.Store.RequestOwner(requestID)
	if err != nil {
		writeError(w, relayStatus(err), err.Error())
		return
	}
	if !s.requirePairedController(w, r, deviceID) {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, err := s.Store.WaitResult(ctx, requestID)
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
