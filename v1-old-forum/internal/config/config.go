// Package config handles loading and validation of application configuration
// It reads settings from environment variables and .env file with fallback defaults
// Learn about configuration patterns: https://12factor.net/config
package config

import (
	"errors"   // Standard library for creating custom error types
	"os"       // Operating system interface for file operations
	"strconv"  // String conversion utilities (string to int, etc.)
	"strings"  // String manipulation functions
	"time"     // Time duration and formatting

	"github.com/arnald/forum/internal/pkg/helpers"  // Helper functions for env parsing
	"github.com/arnald/forum/internal/pkg/path"     // Path resolution utilities
)

// Constants define default values for various timeout and configuration settings
// Using constants makes the code more maintainable and prevents magic numbers
// Learn about constants: https://golang.org/ref/spec#Constants
const (
	readTimeout         = 5      // Default HTTP read timeout in seconds
	writeTimeout        = 10     // Default HTTP write timeout in seconds
	idleTimeout         = 15     // Default HTTP idle timeout in seconds
	configParts         = 2      // Expected number of parts when parsing config
	defaultExpiry       = 86400  // Default session expiry in seconds (24 hours)
	cleanupInternal     = 3600   // Session cleanup interval in seconds (1 hour)
	maxSessionsPerUser  = 5      // Maximum concurrent sessions per user
	sessionIDLenght     = 32     // Length of session ID string
	userRegisterTimeout = 15     // Timeout for user registration requests in seconds
	refreshTokenExpiry  = 30     // Refresh token expiry in days
	userLoginTimeout    = 15     // Timeout for user login requests in seconds
)

// Package-level error variables define specific error types for configuration validation
// Using var instead of const allows these to be compared with errors.Is()
// Learn about error handling: https://golang.org/doc/effective_go#errors
var (
	ErrMissingServerHost    = errors.New("missing SERVER_HOST in config")
	ErrServerPortNotInteger = errors.New("invalid SERVER_PORT: must be integer")
)

// ServerConfig holds all configuration for the API server
// Struct tags could be added for JSON/YAML serialization if needed
// Learn about structs: https://golang.org/doc/effective_go#composite_literals
type ServerConfig struct {
	Host           string                // Server host address (e.g., "localhost", "0.0.0.0")
	Port           string                // Server port number (e.g., "8080")
	Environment    string                // Environment name (dev, staging, production)
	APIContext     string                // API base path (e.g., "/api/v1")
	Database       DatabaseConfig        // Database connection settings
	SessionManager SessionManagerConfig  // Session management configuration
	Timeouts       TimeoutsConfig        // Request timeout settings
	ReadTimeout    time.Duration         // HTTP read timeout
	WriteTimeout   time.Duration         // HTTP write timeout
	IdleTimeout    time.Duration         // HTTP idle connection timeout
}

// DatabaseConfig contains all database-related configuration
// This supports SQLite but could be extended for PostgreSQL, MySQL, etc.
type DatabaseConfig struct {
	Driver         string  // Database driver name (e.g., "sqlite3", "postgres")
	Path           string  // Database file path for SQLite or connection string for others
	Pragma         string  // SQLite-specific pragma settings for performance/behavior
	MigrateOnStart bool    // Whether to run database migrations on application start
	SeedOnStart    bool    // Whether to seed initial data on application start
	OpenConn       int     // Maximum number of open database connections
}

// SessionManagerConfig contains all session management settings
// Sessions are used to maintain user authentication state
// Learn about web sessions: https://developer.mozilla.org/en-US/docs/Web/HTTP/Session_management
type SessionManagerConfig struct {
	CookieName         string         // Name of the session cookie (e.g., "session_id")
	CookiePath         string         // Cookie path scope (e.g., "/", "/api")
	CookieDomain       string         // Cookie domain scope (empty for same domain)
	SameSite           string         // SameSite cookie attribute ("Strict", "Lax", "None")
	DefaultExpiry      time.Duration  // How long sessions last before expiring
	CleanupInterval    time.Duration  // How often to clean up expired sessions
	MaxSessionsPerUser int            // Maximum concurrent sessions per user
	SessionIDLength    int            // Length of session ID (longer = more secure)
	SecureCookie       bool           // Whether cookies require HTTPS (true for production)
	HTTPOnlyCookie     bool           // Whether cookies are inaccessible to JavaScript (XSS protection)
	EnablePersistence  bool           // Whether sessions persist across server restarts
	LogSessions        bool           // Whether to log session creation/destruction
	RefreshTokenExpiry time.Duration  // How long refresh tokens last
}

// TimeoutsConfig groups different types of timeout settings
// Timeouts prevent requests from hanging indefinitely
type TimeoutsConfig struct {
	HandlerTimeouts  HandlerTimeoutsConfig   // Timeouts for HTTP request handlers
	UseCasesTimeouts UseCasesTimeoutsConfig  // Timeouts for business logic operations
}

// HandlerTimeoutsConfig defines timeouts for specific HTTP endpoints
// Different endpoints may need different timeout values based on complexity
type HandlerTimeoutsConfig struct {
	UserRegister time.Duration  // Timeout for user registration endpoint
	UserLogin    time.Duration  // Timeout for user login endpoint
}

// UseCasesTimeoutsConfig defines timeouts for business logic operations
// Not fully implemented yet, but provides structure for future timeout settings
// This follows the principle of planning for extensibility
type UseCasesTimeoutsConfig struct {
	UserRegister time.Duration  // Timeout for user registration business logic
}

// LoadConfig reads configuration from environment variables and .env file
// It returns a fully populated ServerConfig struct with validation
// This follows the 12-factor app methodology for configuration management
// Learn about 12-factor config: https://12factor.net/config
func LoadConfig() (*ServerConfig, error) {
	// Create path resolver to find .env file relative to project root
	resolver := path.NewResolver()

	// Read .env file from project root (errors are ignored - env vars take precedence)
	// The underscore (_) discards the error since .env file is optional
	envFile, _ := os.ReadFile(resolver.GetPath(".env"))

	// Parse .env file content into a map for easy lookup
	// This map provides fallback values when environment variables aren't set
	envMap := helpers.ParseEnv(string(envFile))

	// Create ServerConfig struct with values from env vars, .env file, or defaults
	// The helpers.GetEnv functions check: 1) OS env vars, 2) .env file, 3) defaults
	// Using struct literal with field names makes initialization explicit and clear
	cfg := &ServerConfig{
		Host:         helpers.GetEnv("SERVER_HOST", envMap, "localhost"),              // Server host address
		Port:         helpers.GetEnv("SERVER_PORT", envMap, "8080"),                  // Server port number
		Environment:  helpers.GetEnv("SERVER_ENVIRONMENT", envMap, "development"),    // Deployment environment
		APIContext:   helpers.GetEnv("API_CONTEXT", envMap, "/api/v1"),              // API base path
		ReadTimeout:  helpers.GetEnvDuration("SERVER_READ_TIMEOUT", envMap, readTimeout),   // HTTP read timeout
		WriteTimeout: helpers.GetEnvDuration("SERVER_WRITE_TIMEOUT", envMap, writeTimeout), // HTTP write timeout
		IdleTimeout:  helpers.GetEnvDuration("SERVER_IDLE_TIMEOUT", envMap, idleTimeout),   // HTTP idle timeout

		// Database configuration - nested struct initialization
		Database: DatabaseConfig{
			Driver:         helpers.GetEnv("DB_DRIVER", envMap, "sqlite3"),                                    // Database driver
			Path:           resolver.GetPath(helpers.GetEnv("DB_PATH", envMap, "data/forum.db")),            // Database file path
			MigrateOnStart: helpers.GetEnvBool("DB_MIGRATE_ON_START", envMap, true),                         // Auto-migrate flag
			SeedOnStart:    helpers.GetEnvBool("DB_SEED_ON_START", envMap, true),                           // Auto-seed flag
			Pragma:         helpers.GetEnv("DB_PRAGMA", envMap, "_foreign_keys=on&_journal_mode=WAL"),      // SQLite settings
			OpenConn:       helpers.GetEnvInt("DB_OPEN_CONN", envMap, 1),                                   // Connection pool size
		},

		// Session management configuration - handles user authentication state
		SessionManager: SessionManagerConfig{
			DefaultExpiry:      helpers.GetEnvDuration("SESSION_DEFAULT_EXPIRY", envMap, defaultExpiry),        // Session lifetime
			SecureCookie:       helpers.GetEnvBool("SESSION_SECURE_COOKIE", envMap, false),                     // HTTPS-only cookies
			CookieName:         helpers.GetEnv("SESSION_COOKIE_NAME", envMap, "session_id"),                    // Cookie identifier
			CookiePath:         helpers.GetEnv("SESSION_COOKIE_PATH", envMap, "/"),                             // Cookie scope path
			CookieDomain:       helpers.GetEnv("SESSION_COOKIE_DOMAIN", envMap, ""),                           // Cookie domain scope
			HTTPOnlyCookie:     helpers.GetEnvBool("SESSION_HTTPONLY_COOKIE", envMap, true),                   // XSS protection
			SameSite:           helpers.GetEnv("SESSION_SAMESITE", envMap, "Lax"),                             // CSRF protection
			CleanupInterval:    helpers.GetEnvDuration("SESSION_CLEANUP_INTERVAL", envMap, cleanupInternal),   // Cleanup frequency
			MaxSessionsPerUser: helpers.GetEnvInt("SESSION_MAX_SESSIONS_PER_USER", envMap, maxSessionsPerUser), // Session limit
			SessionIDLength:    helpers.GetEnvInt("SESSION_ID_LENGTH", envMap, sessionIDLenght),               // ID length
			EnablePersistence:  helpers.GetEnvBool("SESSION_ENABLE_PERSISTENCE", envMap, true),               // Persist across restarts
			LogSessions:        helpers.GetEnvBool("SESSION_LOG_SESSIONS", envMap, false),                     // Debug logging
			RefreshTokenExpiry: helpers.GetEnvDuration("SESSION_REFRESH_TOKEN_EXPIRY", envMap, refreshTokenExpiry), // Refresh token lifetime
		},

		// Request timeout configuration for different operations
		Timeouts: TimeoutsConfig{
			HandlerTimeouts: HandlerTimeoutsConfig{
				UserRegister: helpers.GetEnvDuration("HANDLER_TIMEOUT_REGISTER", envMap, userRegisterTimeout), // Registration timeout
				UserLogin:    helpers.GetEnvDuration("HANDLER_TIMEOUT_LOGIN", envMap, userLoginTimeout),       // Login timeout
			},
		},
	}

	// Validation: Ensure required configuration is present and valid

	// Check that server host is specified (empty string is not valid)
	if cfg.Host == "" {
		return nil, ErrMissingServerHost
	}

	// Validate that port number is a valid integer
	// strings.TrimPrefix removes ":" if present (supports both "8080" and ":8080")
	// strconv.Atoi converts string to integer, returning error if invalid
	_, err := strconv.Atoi(strings.TrimPrefix(cfg.Port, ":"))
	if err != nil {
		return nil, ErrServerPortNotInteger
	}

	// Return validated configuration
	return cfg, nil
}
