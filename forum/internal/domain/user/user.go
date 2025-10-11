// Package user contains the core User domain entity and related business logic
// This package follows Domain-Driven Design (DDD) principles - it contains pure business logic
// with no dependencies on external frameworks or infrastructure
// Learn about DDD: https://martinfowler.com/bliki/DomainDrivenDesign.html
package user

import (
	"time"  // Standard library for time handling
)

// User represents a user entity in the forum application
// This is the core domain model that encapsulates user data and business rules
// Field ordering follows a logical grouping: identity, credentials, profile, metadata
// Learn about Go structs: https://golang.org/doc/effective_go#composite_literals
type User struct {
	// Identity fields - unique identifiers for the user
	ID       string  // Unique user identifier (UUID format)
	Username string  // Unique username for login and display
	Email    string  // Unique email address for login and notifications

	// Authentication fields - security-related data
	Password string  // Hashed password (never store plaintext passwords!)
	Role     string  // User role (e.g., "user", "admin", "moderator")

	// Profile fields - user customization and metadata
	AvatarURL *string    // Optional profile picture URL (pointer allows nil/null)
	CreatedAt time.Time  // When the user account was created

	// Note: AvatarURL is a pointer (*string) instead of string to differentiate between:
	// - nil: no avatar set (database NULL)
	// - empty string "": avatar was set but is empty
	// Learn about pointers vs values: https://golang.org/doc/effective_go#pointers_vs_values
}
