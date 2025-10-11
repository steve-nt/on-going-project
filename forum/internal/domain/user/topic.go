// Package user contains domain entities related to users, including topics they create
// Topics logically belong to users since users own and manage their topics
package user

import "github.com/arnald/forum/internal/domain/comments"  // Import comments domain for composition

// Topic represents a forum topic/post created by a user
// This entity aggregates a topic with its associated comments (aggregate root pattern)
// In Domain-Driven Design, this is an aggregate that maintains consistency boundaries
// Learn about DDD aggregates: https://martinfowler.com/bliki/DDD_Aggregate.html
type Topic struct {
	// Primary identification
	ID int  // Unique topic identifier (auto-increment integer)

	// Ownership and categorization
	UserID        string  // ID of the user who created this topic (foreign key to User)
	OwnerUsername string  // Username of the topic owner (denormalized for display)
	CategoryID    int     // ID of the category this topic belongs to

	// Content fields
	Title     string  // Topic title/subject (required)
	Content   string  // Topic body/description (required)
	ImagePath string  // Optional path to attached image file

	// Timestamps - stored as strings for easier JSON serialization
	// Note: In a more robust system, these might be time.Time with custom JSON marshaling
	CreatedAt string  // When the topic was first created (ISO format)
	UpdatedAt string  // When the topic was last modified (ISO format)

	// Related entities - composition pattern
	Comments []comments.Comment  // All comments associated with this topic

	// Field ordering rationale:
	// 1. ID first (primary key)
	// 2. Foreign keys and relationships
	// 3. Content data
	// 4. Metadata (timestamps)
	// 5. Related entities last
	// Learn about struct field ordering: https://golang.org/doc/effective_go#embedding
}
