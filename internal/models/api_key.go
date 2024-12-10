package models

import "time"

type APIKey struct {
    ID        string    `json:"id"`
    UserID    string    `json:"user_id,omitempty"`
    Name      string    `json:"name"`
    APIKey    string    `json:"APIKey"`
    IsPublic  bool      `json:"is_public"`
    IsActive  bool      `json:"is_active"`
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
}
