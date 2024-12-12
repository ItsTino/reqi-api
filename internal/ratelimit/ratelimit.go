// internal/ratelimit/ratelimit.go
package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type RateLimiter struct {
    redis *redis.Client
}

func NewRateLimiter(redisURL string) (*RateLimiter, error) {
    opt, err := redis.ParseURL(redisURL)
    if err != nil {
        return nil, fmt.Errorf("invalid redis URL: %v", err)
    }

    client := redis.NewClient(opt)
    if err := client.Ping(context.Background()).Err(); err != nil {
        return nil, fmt.Errorf("redis connection failed: %v", err)
    }

    return &RateLimiter{
        redis: client,
    }, nil
}

func (rl *RateLimiter) Allow(key string, limit int, window time.Duration) (bool, int, error) {
    ctx := context.Background()
    now := time.Now().Unix()
    windowKey := fmt.Sprintf("%s:%d", key, now/int64(window.Seconds()))

    pipe := rl.redis.Pipeline()
    incr := pipe.Incr(ctx, windowKey)
    pipe.Expire(ctx, windowKey, window)
    
    _, err := pipe.Exec(ctx)
    if err != nil {
        return false, 0, err
    }

    count := int(incr.Val())
    return count <= limit, count, nil
}

func (rl *RateLimiter) Close() error {
    return rl.redis.Close()
}