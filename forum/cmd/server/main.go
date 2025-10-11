// Package main is the entry point for the forum API server
// This file demonstrates Clean Architecture principles and dependency injection
// Learn more about Go: https://golang.org/doc/tutorial/getting-started
// Learn about Clean Architecture: https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html
package main

import (
	"log"  // Standard library for logging - https://pkg.go.dev/log
	"os"   // Operating system interface - https://pkg.go.dev/os

	// Internal packages following Go module naming convention
	// Learn about Go modules: https://golang.org/doc/tutorial/create-module
	"github.com/arnald/forum/internal/app"                    // Application layer (use cases)
	"github.com/arnald/forum/internal/config"                 // Configuration management
	"github.com/arnald/forum/internal/infra"                  // Infrastructure layer
	"github.com/arnald/forum/internal/infra/logger"           // Custom logging implementation
	"github.com/arnald/forum/internal/infra/storage/sqlite"   // SQLite database implementation
)

// main is the entry point function for the server application
// Every Go program starts execution in the main function of the main package
// Learn about Go program structure: https://golang.org/doc/code
func main() {
	// STEP 1: Load configuration from environment variables and .env file
	// The asterisk (*) dereferences the pointer returned by LoadConfig()
	// Learn about pointers: https://golang.org/doc/effective_go#pointers_vs_values
	cfg, err := config.LoadConfig()
	if err != nil {
		// log.Fatalf prints an error message and exits the program with status code 1
		// The %v verb prints the default representation of the error value
		// Learn about string formatting: https://pkg.go.dev/fmt#hdr-Printing
		log.Fatalf("Configuration error: %v", err)
	}

	// STEP 2: Initialize database connection using the loaded configuration
	// SQLite is a self-contained, serverless, zero-configuration database
	// Learn about SQLite: https://www.sqlite.org/about.html
	db, err := sqlite.InitializeDB(*cfg)
	if err != nil {
		log.Fatalf("Database error: %v", err)
	}
	// defer ensures db.Close() is called when main() returns
	// This prevents database connection leaks - a common source of bugs
	// Learn about defer: https://golang.org/doc/effective_go#defer
	defer db.Close()

	// STEP 3: Set up dependency injection chain following Clean Architecture
	// This creates layers from innermost (domain) to outermost (infrastructure)

	// Create repository layer - handles data persistence
	// The repository pattern abstracts data access logic
	// Learn about Repository pattern: https://martinfowler.com/eaaCatalog/repository.html
	userRepo := sqlite.NewRepo(db)

	// Create logger instance for structured logging throughout the application
	// os.Stdout means log output goes to standard output (terminal)
	// logger.LevelInfo sets minimum log level to INFO (filters out DEBUG messages)
	logger := logger.New(os.Stdout, logger.LevelInfo)

	// Create infrastructure providers - contains all external dependencies
	// This follows Dependency Inversion Principle (DIP) from SOLID principles
	// Learn about SOLID: https://en.wikipedia.org/wiki/SOLID
	infraProviders := infra.NewInfraProviders(userRepo.DB)

	// Create application services - contains business logic and use cases
	// This layer orchestrates the flow of data between UI and database
	appServices := app.NewServices(infraProviders.UserRepository)

	// Create HTTP server - handles incoming web requests
	// This is the outermost layer that communicates with the external world
	infraHTTPServer := infra.NewHTTPServer(cfg, db, logger, appServices)

	// STEP 4: Start the HTTP server and listen for incoming requests
	// This is a blocking call - the program will wait here for HTTP requests
	// The server will run until manually stopped (Ctrl+C) or encounters an error
	// Learn about HTTP servers: https://golang.org/doc/articles/wiki/
	infraHTTPServer.ListenAndServe()
}
