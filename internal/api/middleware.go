// internal/api/middleware.go
package api

import (
	"database/sql"
	"net/http"
	"reqi-api/internal/auth"
	"strings"

	"github.com/gin-gonic/gin"
)

func AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.JSON(401, gin.H{"error": "Authorization header required"})
            c.Abort()
            return
        }

        bearerToken := strings.Split(authHeader, " ")
        if len(bearerToken) != 2 {
            c.JSON(401, gin.H{"error": "Invalid authorization header"})
            c.Abort()
            return
        }

        userID, err := auth.ValidateToken(bearerToken[1])
        if err != nil {
            c.JSON(401, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }

        c.Set("user_id", userID)
        c.Next()
    }
}

func APIKeyMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        apiKey := c.GetHeader("X-API-Key")
        if apiKey == "" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "API key required"})
            c.Abort()
            return
        }

        db := c.MustGet("db").(*sql.DB)
        var userID string
        var isActive bool
        err := db.QueryRow(`
            SELECT user_id, is_active 
            FROM api_keys 
            WHERE api_key = ?`, apiKey).Scan(&userID, &isActive)

        if err == sql.ErrNoRows {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
            c.Abort()
            return
        } else if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
            c.Abort()
            return
        }

        if !isActive {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "API key has been revoked"})
            c.Abort()
            return
        }

        c.Set("user_id", userID)
        c.Next()
    }
}