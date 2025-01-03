// cmd/server/main.go
package main

import (
	"fmt"
	"log"
	_ "reqi-api/docs" // Required for Swagger
	"reqi-api/internal/api"
	"reqi-api/internal/auth"
	"reqi-api/internal/config"
	"reqi-api/internal/ratelimit"
	"reqi-api/internal/storage"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

// cmd/server/main.go

// @title           Reqi API
// @version         1.0
// @description     API for capturing and managing webhook requests and callbacks
// @termsOfService  http://swagger.io/terms/

// @contact.name   API Support
// @contact.url    http://www.swagger.io/support
// @contact.email  support@swagger.io

// @license.name  Apache 2.0
// @license.url   http://www.apache.org/licenses/LICENSE-2.0.html

// @host      localhost:8080
// @BasePath  /

// @securityDefinitions.apikey  ApiKeyAuth
// @in                         header
// @name                       X-API-Key

// @securityDefinitions.apikey  BearerAuth
// @in                         header
// @name                       Authorization
func main() {

	gin.SetMode(gin.ReleaseMode)
	// Load configuration from .env
	if err := godotenv.Load(); err != nil {
		log.Printf("No .env file found, using system environment variables")
	}

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize JWT with config
	auth.InitJWT(cfg)

	// Create database configuration
	dbConfig := storage.Config{
		Host:     cfg.Database.Host,
		Port:     cfg.Database.Port,
		User:     cfg.Database.User,
		Password: cfg.Database.Password,
		DBName:   cfg.Database.DBName,
	}

	// Create database if it doesn't exist
	rootDb, err := storage.NewDB(storage.Config{
		Host:     dbConfig.Host,
		Port:     dbConfig.Port,
		User:     dbConfig.User,
		Password: dbConfig.Password,
		DBName:   "",
	})
	if err != nil {
		log.Fatalf("Failed to connect to MySQL: %v", err)
	}

	_, err = rootDb.Exec("CREATE DATABASE IF NOT EXISTS " + dbConfig.DBName)
	if err != nil {
		log.Fatalf("Failed to create database: %v", err)
	}
	rootDb.Close()

	// Connect to the application database
	db, err := storage.NewDB(dbConfig)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	if err := storage.RunMigrations(db); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	rateLimiter, err := ratelimit.NewRateLimiter(cfg.Redis.URL)
	if err != nil {
		log.Fatalf("Failed to initialize rate limiter: %v", err)
	}
	defer rateLimiter.Close()

	// Set up and start the server
	router := api.SetupRouter(db, rateLimiter)

	serverAddr := fmt.Sprintf(":%s", cfg.Server.Port)
	if cfg.Env == "development" {
		log.Printf("Server starting on http://localhost%s", serverAddr)
		log.Printf("Swagger UI available at http://localhost%s/swagger/index.html", serverAddr)
	}

	if err := router.Run(serverAddr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
