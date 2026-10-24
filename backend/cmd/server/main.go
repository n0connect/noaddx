package main

import (
	"log"
	"net/http"

	"noaddress/internal/config"
	"noaddress/internal/database"
	"noaddress/internal/pow"
	"noaddress/internal/server"
	"noaddress/internal/utils"
)

var mainLogger = utils.NewLogger("MAIN")

func main() {
	// Log environment mode
	if config.IsProductionMode() {
		mainLogger.Info("Application is Running in PRODUCTION mode")
	} else {
		mainLogger.Info("Application is Running in DEVELOPMENT mode")
	}

	mainLogger.Info("Starting noaddress backend server...")

	// Validate database configuration at startup
	mainLogger.Debug("Validating startup configuration...")
	if err := database.ValidateStartupConfig(); err != nil {
		mainLogger.Error("Configuration validation failed: %v", err)
		log.Fatalf("Configuration error: %v", err)
	}
	mainLogger.Info("Configuration validation passed!")

	// Initialize PoW system
	mainLogger.Debug("Initializing PoW system...")
	pow.InitPoW()

	// Initialize database
	mainLogger.Debug("Initializing database connection...")
	database.Init()

	// Setup routes
	mainLogger.Debug("Setting up HTTP routes...")

	// -- Server Mux Settings
	mainLogger.Debug("Setting mux for HTTP server...")
	mux := server.NewMux()

	mainLogger.Info("HTTP routes configured successfully")

	backendPort := config.GetBackendPort()
	if backendPort == "" {
		mainLogger.Error("BACKEND_PORT is required")
		log.Fatal("Configuration error: BACKEND_PORT is required")
	}
	mainLogger.Info("Server starting on port %s", backendPort)

	// -- Server custom srv settings
	mainLogger.Info("Setting Custom server settings for HTTP server...")
	addr := ":" + backendPort
	readHeaderTimeout := config.GetServerReadHeaderTimeout()
	readTimeout := config.GetServerReadTimeout()
	writeTimeout := config.GetServerWriteTimeout()
	idleTimeout := config.GetServerIdleTimeout()
	maxHeaderBytes := config.GetServerMaxHeaderBytes()

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}

	mainLogger.Info("Server is ready to accept connections")
	log.Fatal(srv.ListenAndServe())
}
