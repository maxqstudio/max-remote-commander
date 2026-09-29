package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/maxqstudio/max-remote-commander/internal/relay"
)

func durableStateConfig() (string, []byte, error) {
	path := os.Getenv("MAXRC_STATE_FILE")
	encodedKey := os.Getenv("MAXRC_STATE_KEY")
	if path == "" && encodedKey == "" {
		return "", nil, nil
	}
	if path == "" || encodedKey == "" {
		return "", nil, errors.New("MAXRC_STATE_FILE and MAXRC_STATE_KEY must be configured together")
	}
	key, err := base64.RawURLEncoding.DecodeString(encodedKey)
	if err != nil || len(key) != 32 {
		return "", nil, errors.New("MAXRC_STATE_KEY must be an unpadded base64url encoding of exactly 32 random bytes")
	}
	return path, key, nil
}

func main() {
	statePath, stateKey, err := durableStateConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "max-relay:", err)
		os.Exit(2)
	}
	registrationKey := os.Getenv("MAXRC_REGISTRATION_KEY")
	store, err := relay.NewStore(relay.Config{
		RegistrationKey: registrationKey,
		SessionTTL: 15 * time.Minute,
		LeaseTTL: 30 * time.Second,
		MaxQueue: 128,
		MaxResults: 1024,
		StatePath: statePath,
		StateKey: stateKey,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "max-relay:", err)
		os.Exit(2)
	}
	server := &relay.HTTPServer{Store: store}
	addr := os.Getenv("MAXRC_LISTEN")
	if addr == "" {
		addr = "127.0.0.1:8787"
	}
	if statePath == "" {
		fmt.Fprintln(os.Stderr, "max-relay warning: durable state disabled")
	}
	fmt.Fprintln(os.Stderr, "max-relay listening on", addr)
	httpServer := &http.Server{
		Addr: addr,
		Handler: server.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 35 * time.Second,
		WriteTimeout: 35 * time.Second,
		IdleTimeout: 60 * time.Second,
	}
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, "max-relay:", err)
		os.Exit(1)
	}
}
