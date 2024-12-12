// internal/api/middleware/ratelimit.go
package middleware

import (
	"fmt"
	"net/http"
	"reqi-api/internal/constants"
	"reqi-api/internal/ratelimit"
	"time"

	"github.com/gin-gonic/gin"
)

func RateLimitMiddleware(rl *ratelimit.RateLimiter, key string, limit int, window time.Duration) gin.HandlerFunc {
    return func(c *gin.Context) {
        allowed, count, err := rl.Allow(key, limit, window)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Rate limit check failed"})
            c.Abort()
            return
        }

        // Set rate limit headers
        c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
        c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", limit-count))
        c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(window).Unix()))

        if !allowed {
            c.JSON(http.StatusTooManyRequests, gin.H{
                "error": "Rate limit exceeded",
                "retry_after": window.Seconds(),
            })
            c.Abort()
            return
        }

        c.Next()
    }
}

// Specific rate limit middlewares
func AuthRateLimit(rl *ratelimit.RateLimiter) gin.HandlerFunc {
    return RateLimitMiddleware(rl, "global:auth", constants.GlobalAuthLimit, time.Minute)
}

func RepeaterRateLimit(rl *ratelimit.RateLimiter) gin.HandlerFunc {
    return RateLimitMiddleware(rl, "global:repeater", constants.GlobalRepeaterLimit, time.Minute)
}

func PublicRateLimit(rl *ratelimit.RateLimiter) gin.HandlerFunc {
    return RateLimitMiddleware(rl, "global:repeater", constants.PublicLogLimit, time.Minute)
}

// Configurable rate limit for other endpoints
func ConfigurableRateLimit(rl *ratelimit.RateLimiter, endpoint string, limit int, window time.Duration) gin.HandlerFunc {
    if limit <= 0 {
        // If no limit set, skip rate limiting
        return func(c *gin.Context) {
            c.Next()
        }
    }
    return RateLimitMiddleware(rl, fmt.Sprintf("endpoint:%s", endpoint), limit, window)
}