package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"noaddx/internal/auth"
	"noaddx/internal/chat"
	"noaddx/internal/config"
	"noaddx/internal/cryptoengine"
	"noaddx/internal/database"
	"noaddx/internal/encryption"
	"noaddx/internal/pow"
	"noaddx/internal/server"
	"noaddx/internal/utils"
)

// shutdownGrace bounds how long in-flight requests may finish after SIGINT/SIGTERM
const shutdownGrace = 10 * time.Second

var mainLogger = utils.NewLogger("MAIN")

func main() {
	if config.IsProductionMode() {
		mainLogger.Info("Starting noaddx. backend (production)")
	} else {
		mainLogger.Info("Starting noaddx. backend (development)")
	}

	// Known-answer self-test of the compiled crypto engine before any key or user data is touched
	if err := cryptoengine.SelfTest(); err != nil {
		mainLogger.Error("Crypto engine self-test failed: %v", err)
		log.Fatal("Crypto engine self-test failed")
	}
	mainLogger.Info("Crypto engine: %s (%s), self-test passed", cryptoengine.EngineName(), cryptoengine.EngineVersion())

	if err := database.ValidateStartupConfig(); err != nil {
		mainLogger.Error("Configuration validation failed: %v", err)
		log.Fatal("Configuration error")
	}

	database.Init()

	// Every goroutine and request context derives from this: a signal cancels them all
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	utils.SafeGoSupervised(ctx, "pow-cleanup", pow.RunCleanup)
	utils.SafeGoSupervised(ctx, "retention", chat.NewService().RunRetention)

	srv := &http.Server{
		Addr:              ":" + config.GetBackendPort(),
		Handler:           server.NewMux(),
		ReadHeaderTimeout: config.GetServerReadHeaderTimeout(),
		ReadTimeout:       config.GetServerReadTimeout(),
		WriteTimeout:      config.GetServerWriteTimeout(),
		IdleTimeout:       config.GetServerIdleTimeout(),
		MaxHeaderBytes:    config.GetServerMaxHeaderBytes(),
		// Long-lived SSE streams end as soon as shutdown begins
		BaseContext: func(net.Listener) context.Context { return ctx },
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.ListenAndServe()
	}()
	mainLogger.Info("Server is ready to accept connections")

	select {
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			mainLogger.LogError("ListenAndServe", err)
		}
	case <-ctx.Done():
		mainLogger.Info("Shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		mainLogger.LogError("Shutdown", err)
	}
	auth.StopCleanup()
	encryption.ZeroizeAllKeys()
	mainLogger.Info("Server stopped; key material zeroized")
}
