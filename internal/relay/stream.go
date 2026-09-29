package relay

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/maxqstudio/max-remote-commander/internal/protocol"
)

const (
	defaultStreamHeartbeatInterval = 20 * time.Second
	defaultStreamHeartbeatTimeout  = 5 * time.Second
	streamWriteTimeout             = 10 * time.Second
)

func (s *HTTPServer) streamHeartbeatInterval() time.Duration {
	if s.HeartbeatInterval > 0 {
		return s.HeartbeatInterval
	}
	return defaultStreamHeartbeatInterval
}

func (s *HTTPServer) streamHeartbeatTimeout() time.Duration {
	if s.HeartbeatTimeout > 0 {
		return s.HeartbeatTimeout
	}
	return defaultStreamHeartbeatTimeout
}

func (s *HTTPServer) deviceStream(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("device")
	token, ok := bearer(r)
	if !ok || !s.Store.DeviceSessionAuthorized(deviceID, token, s.now()) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(1024)

	baseCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	streamCtx := conn.CloseRead(baseCtx)
	errs := make(chan error, 2)

	go func() {
		errs <- s.writeDeviceCommands(streamCtx, conn, deviceID, token)
	}()
	go func() {
		errs <- s.heartbeatDeviceStream(streamCtx, conn, deviceID, token)
	}()

	err = <-errs
	cancel()
	if errors.Is(err, ErrUnauthorized) {
		_ = conn.Close(websocket.StatusPolicyViolation, "session expired")
		return
	}
	if errors.Is(err, context.Canceled) || websocket.CloseStatus(err) != -1 {
		return
	}
	_ = conn.Close(websocket.StatusInternalError, "stream closed")
}

func (s *HTTPServer) writeDeviceCommands(ctx context.Context, conn *websocket.Conn, deviceID, token string) error {
	for {
		command, err := s.Store.NextCommand(ctx, deviceID, token, s.now)
		if err != nil {
			return err
		}
		if !json.Valid(command.Payload) {
			return ErrInvalidCommandEnvelope
		}
		data, err := protocol.EncodeStreamMessage(protocol.StreamMessage{
			Version: protocol.StreamVersion,
			Type: protocol.StreamTypeCommand,
			RequestID: command.RequestID,
			Payload: json.RawMessage(append([]byte(nil), command.Payload...)),
		})
		if err != nil {
			return err
		}
		writeCtx, cancel := context.WithTimeout(ctx, streamWriteTimeout)
		err = conn.Write(writeCtx, websocket.MessageText, data)
		cancel()
		if err != nil {
			return err
		}
		if _, err := s.Store.WaitResult(ctx, command.RequestID); err != nil {
			return err
		}
	}
}

func (s *HTTPServer) heartbeatDeviceStream(ctx context.Context, conn *websocket.Conn, deviceID, token string) error {
	ticker := time.NewTicker(s.streamHeartbeatInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if !s.Store.DeviceSessionAuthorized(deviceID, token, s.now()) {
				return ErrUnauthorized
			}
			pingCtx, cancel := context.WithTimeout(ctx, s.streamHeartbeatTimeout())
			err := conn.Ping(pingCtx)
			cancel()
			if err != nil {
				return err
			}
		}
	}
}
