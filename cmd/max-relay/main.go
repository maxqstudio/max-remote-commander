package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/maxqstudio/max-remote-commander/internal/relay"
)

func main() {
	registrationKey := os.Getenv("MAXRC_REGISTRATION_KEY")
	controllerKey := os.Getenv("MAXRC_CONTROLLER_KEY")
	store, err := relay.NewStore(relay.Config{
		RegistrationKey: registrationKey,
		ControllerKey: controllerKey,
		SessionTTL: 15 * time.Minute,
		LeaseTTL: 30 * time.Second,
		MaxQueue: 128,
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
