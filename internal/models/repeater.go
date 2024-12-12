package models

import "time"

type Repeater struct {
	ID           string    `json:"id"`
	LoggerID     string    `json:"logger_id"`
	ForwardURL   string    `json:"forward_url"`
	IsActive     bool      `json:"is_active"`
	PreserveHost bool      `json:"preserve_host"` // Whether to forward original Host header
	Timeout      int       `json:"timeout"`       // Timeout in seconds
	RetryCount   int       `json:"retry_count"`   // Number of retries on failure
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
