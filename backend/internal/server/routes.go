// Package server wires handlers to routes. Shared by cmd/server and integration tests
// so tests exercise the exact production middleware chains.
package server

import (
	"net/http"

	"noaddx/internal/handlers"
	"noaddx/internal/middleware"
	"noaddx/internal/utils"
)

var serverLogger = utils.NewLogger("SERVER")

// public wraps an unauthenticated endpoint with the base security chain:
// headers -> CORS (exact origins) -> same-origin proof for writes -> content-type whitelist
func public(h http.HandlerFunc) http.HandlerFunc {
	return middleware.SecurityHeadersMiddleware(middleware.CORSMiddleware(
		middleware.SameOriginWritesMiddleware(middleware.ContentTypeMiddleware(h))))
}

// protected additionally requires a valid, non-revoked session
func protected(h http.HandlerFunc) http.HandlerFunc {
	return public(middleware.JWTMiddleware(h))
}

// NewMux builds the complete HTTP surface with its middleware chains.
// Using http.NewServeMux() for explicit route registration (rejects unregistered endpoints)
func NewMux() *http.ServeMux {
	mux := http.NewServeMux()
	routes := []struct {
		pattern string
		handler http.HandlerFunc
	}{
		{"/api/v2/pow/challenge", public(handlers.PoWChallengeHandler)},
		{"/api/v2/register", public(handlers.RegisterHandler)},
		{"/api/v2/login", public(middleware.RateLimitMiddleware(handlers.LoginHandler))},
		{"/api/v2/logout", public(handlers.LogoutHandler)},
		{"/api/v2/me", protected(handlers.MeHandler)},
		{"/api/v2/invites", protected(handlers.CreateInviteHandler)},
		{"/api/v2/invites/redeem", protected(handlers.RedeemInviteHandler)},
		{"/api/v2/conversations", protected(handlers.ConversationsHandler)},
		{"/api/v2/conversations/", protected(handlers.ConversationsHandler)},
		{"/api/v2/events", protected(handlers.EventsHandler)},
	}
	for _, route := range routes {
		serverLogger.Debug("Registering route: %s", route.pattern)
		mux.HandleFunc(route.pattern, route.handler)
	}

	// Request Path Whitelist: Handle unknown paths with 404
	// Only registered paths are allowed, all others return 404
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		serverLogger.Debug("Unknown path requested")
		http.Error(w, "Not Found", http.StatusNotFound)
	})

	serverLogger.Info("All routes registered successfully")
	return mux
}
