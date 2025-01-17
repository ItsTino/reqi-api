package models

import "time"

type Team struct {
    ID            string    `json:"id"`
    Name          string    `json:"name"`
    EncryptionKey string    `json:"-"`
    CreatedAt     time.Time `json:"created_at"`
    UpdatedAt     time.Time `json:"updated_at"`
}

type TeamMember struct {
    ID        string    `json:"id"`
    TeamID    string    `json:"team_id"`
    UserID    string    `json:"user_id"`
    Role      string    `json:"role"`
    Status    string    `json:"status"`
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
}

type TeamInvite struct {
    Email string `json:"email" binding:"required,email"`
}