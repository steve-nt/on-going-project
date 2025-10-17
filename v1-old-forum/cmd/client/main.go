// Package main is the entry point for the forum client (frontend) server
// This server serves static files (HTML, CSS, JS) and renders the homepage
// It's separate from the API server, demonstrating a microservices approach
// Learn about microservices: https://martinfowler.com/articles/microservices.html
package main

import (
	"log"        // Standard library for logging
	"net/http"   // HTTP client and server implementations

	// Client-specific packages for configuration and request handling
	"github.com/arnald/forum/cmd/client/config"    // Client configuration (port, timeouts)
	"github.com/arnald/forum/cmd/client/handler"   // HTTP request handlers for client
	"github.com/arnald/forum/internal/pkg/path"    // Path resolution utilities
)

// main function starts the client server that serves the frontend
// This is a separate server from the API server, running on a different port
func main() {
	// STEP 1: Load client-specific configuration
	// This includes port number, timeouts, and environment settings
	cfg, err := config.LoadClientConfig()
	if err != nil {
		// Exit immediately if configuration cannot be loaded
		log.Fatalf("Configuration error: %v", err)
	}

	// STEP 2: Set up HTTP routing for client requests
	// Routes determine which handler function responds to which URL path
	router := setupRoutes()

	// STEP 3: Create HTTP server with specific configuration
	// The ampersand (&) creates a pointer to the struct literal
	// Learn about struct literals: https://golang.org/ref/spec#Composite_literals
	client := &http.Server{
		Addr:              ":" + cfg.Port,                     // Server address (e.g., ":3000")
		Handler:           router,                             // Request router/multiplexer
		ReadHeaderTimeout: cfg.HTTPTimeouts.ReadHeader,       // Max time to read request headers
		ReadTimeout:       cfg.HTTPTimeouts.Read,             // Max time to read entire request
		WriteTimeout:      cfg.HTTPTimeouts.Write,            // Max time to write response
		IdleTimeout:       cfg.HTTPTimeouts.Idle,             // Max time for idle connections
	}

	// STEP 4: Log server startup information for debugging
	// Printf formats and prints to standard output without exiting
	log.Printf("Client started port: %s (%s environment)", cfg.Port, cfg.Environment)

	// STEP 5: Start the HTTP server (this blocks until server stops)
	// ListenAndServe listens on the TCP network address and serves HTTP requests
	err = client.ListenAndServe()
	if err != nil {
		// log.Fatal prints error and exits with status code 1
		log.Fatal("Client error: ", err)
	}
}

// setupRoutes configures URL routing for the client server
// It returns a ServeMux (HTTP request multiplexer) that matches URLs to handlers
// Learn about HTTP routing: https://golang.org/pkg/net/http/#ServeMux
func setupRoutes() *http.ServeMux {
	// Create new ServeMux - Go's built-in HTTP request router
	// ServeMux matches incoming request URLs to registered patterns
	router := http.NewServeMux()

	// Create path resolver to find files relative to project root
	// This handles different working directories during development vs deployment
	resolver := path.NewResolver()

	// ROUTE 1: Static file serving for CSS, JavaScript, images, etc.
	// "/static/" pattern matches any URL starting with /static/
	// http.StripPrefix removes "/static/" from URL before passing to file server
	// http.FileServer serves files from the specified directory
	// http.Dir converts string path to http.FileSystem interface
	// Example: GET /static/css/style.css → serves frontend/static/css/style.css
	// Learn about file servers: https://golang.org/pkg/net/http/#FileServer
	router.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(resolver.GetPath("frontend/static/")))))

	// ROUTE 2: Homepage handler for the root URL "/"
	// HandleFunc registers a handler function for the given pattern
	// Any request to "/" will be handled by handler.HomePage function
	router.HandleFunc("/", handler.HomePage)

	// Return the configured router to be used by the HTTP server
	return router
}
