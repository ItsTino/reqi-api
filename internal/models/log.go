package models

import "time"

type Log struct {
    ID        string    `json:"id"`
    APIKeyID  string    `json:"api_key_id"`
    UUID      string    `json:"uuid"`
    Body      string    `json:"body"`
    CreatedAt time.Time `json:"created_at"`
}