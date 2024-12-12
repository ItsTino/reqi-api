package models

import "time"

type LogSearchRequest struct {
	LoggerID     string     `json:"logger_id,omitempty"`
	Method       []string   `json:"methods,omitempty"` // Filter by HTTP methods (GET, POST, etc)
	PathContains string     `json:"path_contains,omitempty"`
	BodyContains string     `json:"body_contains,omitempty"`
	HeaderKey    string     `json:"header_key,omitempty"`   // Search for specific header
	HeaderValue  string     `json:"header_value,omitempty"` // Search for header value
	DateFrom     *time.Time `json:"date_from,omitempty"`
	DateTo       *time.Time `json:"date_to,omitempty"`
	SortBy       string     `json:"sort_by,omitempty"`    // created_at, method, path
	SortOrder    string     `json:"sort_order,omitempty"` // asc, desc
	Page         int        `json:"page,omitempty"`       // Pagination
	PageSize     int        `json:"page_size,omitempty"`
}

type LogSearchResponse struct {
	Logs        []LogDetail `json:"logs"`
	Total       int64       `json:"total"`
	PageCount   int         `json:"page_count"`
	CurrentPage int         `json:"current_page"`
	HasMore     bool        `json:"has_more"`
}
