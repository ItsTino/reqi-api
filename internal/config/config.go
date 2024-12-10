// internal/config/config.go
package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
    Database DatabaseConfig
    Server   ServerConfig
    JWT      JWTConfig
    Env      string
}

type DatabaseConfig struct {
    Host     string
    Port     string
    User     string
    Password string
    DBName   string
}

type ServerConfig struct {
    Port string
}

type JWTConfig struct {
    Secret string
}

func LoadConfig() (*Config, error) {
    // Load .env file if it exists
    if err := godotenv.Load(); err != nil {
        log.Printf("Warning: .env file not found")
    }

    config := &Config{
        Database: DatabaseConfig{
            Host:     getEnv("DB_HOST", "localhost"),
            Port:     getEnv("DB_PORT", "3306"),
            User:     getEnv("DB_USER", ""),
            Password: getEnv("DB_PASSWORD", ""),
            DBName:   getEnv("DB_NAME", "reqi"),
        },
        Server: ServerConfig{
            Port: getEnv("SERVER_PORT", "8080"),
        },
        JWT: JWTConfig{
            Secret: getEnv("JWT_SECRET", "your-default-secret-key"),
        },
        Env: getEnv("ENVIRONMENT", "development"),
    }

    return config, nil
}

func getEnv(key, defaultValue string) string {
    if value, exists := os.LookupEnv(key); exists {
        return value
    }
    return defaultValue
}