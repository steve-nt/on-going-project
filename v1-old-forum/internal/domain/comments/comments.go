// Package comments contains the Comment domain entity
// Comments are responses to forum topics, forming discussion threads
// This package represents a bounded context in Domain-Driven Design
package comments

import "time"  // Standard library for timestamp handling

// Comment represents a single comment/reply on a forum topic
// Comments form a flat structure (no nested replies in this version)
// Each comment belongs to exactly one topic and one user
type Comment struct {
	// Primary identification
	ID int  // Unique comment identifier (auto-increment integer)

	// Relationships - foreign keys to other entities
	TopicID int     // ID of the topic this comment belongs to
	UserID  string  // ID of the user who wrote this comment

	// Denormalized data for performance
	// Note: Username is duplicated here to avoid JOIN queries when displaying comments
	// This is a trade-off between normalization and query performance
	Username string  // Username of the comment author (denormalized from User)

	// Content
	Content string  // The actual comment text/body

	// Timestamps - using time.Time for proper date handling
	// Unlike Topic, these use time.Time for more precise timestamp operations
	CreatedAt time.Time  // When the comment was first posted
	UpdatedAt time.Time  // When the comment was last edited

	// Design considerations:
	// 1. ID comes first as primary identifier
	// 2. Foreign keys group together for clarity
	// 3. Denormalized fields are clearly marked
	// 4. Content follows relationships
	// 5. Timestamps come last as metadata
	//
	// Future enhancements could include:
	// - ParentCommentID for nested replies
	// - IsEdited boolean flag
	// - EditHistory []CommentEdit
	// - Likes/Dislikes counts
}
