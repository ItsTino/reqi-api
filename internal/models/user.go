package models

import "time"

type User struct {
    ID        string    `json:"id"`
    Email     string    `json:"email" binding:"required"`
    Password  string    `json:"password" binding:"required"`
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
}