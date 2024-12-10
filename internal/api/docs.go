// internal/api/docs.go
package api

import "time"

// These types are for Swagger documentation
type LoggerResponse struct {
    UUID      string    `json:"uuid" example:"123e4567-e89b-12d3-a456-426614174000"`
    URL       string    `json:"url" example:"/log/123e4567-e89b-12d3-a456-426614174000"`
    IsPublic  bool      `json:"is_public" example:"false"`
    CreatedAt time.Time `json:"created_at"`
}

type CreateLoggerRequest struct {
    IsPublic bool `json:"is_public" example:"false"`
}

type RegisterRequest struct {
    Email    string `json:"email" example:"user@example.com"`
    Password string `json:"password" example:"password123"`
}

type LoginRequest struct {
    Email    string `json:"email" example:"user@example.com"`
    Password string `json:"password" example:"password123"`
}

type APIKeyRequest struct {
    Name     string `json:"name" example:"My API Key"`
    IsPublic bool   `json:"is_public" example:"false"`
}

type ErrorResponse struct {
    Error string `json:"error" example:"Error message"`
}