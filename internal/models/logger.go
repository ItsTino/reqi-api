package models

import "time"

type Logger struct {
    ID        string    `json:"id"`
    UserID    string    `json:"user_id"`
    UUID      string    `json:"uuid"`
    IsPublic  bool      `json:"is_public"`
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
}

type LogEntry struct {
    ID        string    `json:"id"`
    LoggerID  string    `json:"logger_id"`
    Method    string    `json:"method"`
    Path      string    `json:"path"`
    Headers   string    `json:"headers"`
    Body      string    `json:"body"`
    Query     string    `json:"query"`
    CreatedAt time.Time `json:"created_at"`
}

type LoggerSummary struct {
    UUID      string    `json:"uuid"`
    IsPublic  bool      `json:"is_public"`
    CreatedAt time.Time `json:"created_at"`
}

type LogDetail struct {
    UUID      string            `json:"uuid"`
    Method    string            `json:"method"`
    Path      string            `json:"path"`
    Headers   map[string]string `json:"headers"`
    Query     string           `json:"query"`
    Body      interface{}      `json:"body,omitempty"`
    CreatedAt time.Time        `json:"created_at"`
}