// internal/api/routes.go
package api

import (
	"database/sql"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func SetupRouter(db *sql.DB) *gin.Engine {
	router := gin.Default()
	handler := NewHandler(db)

	// Add swagger
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Middleware to provide db to all routes
	router.Use(func(c *gin.Context) {
		c.Set("db", db)
		c.Next()
	})

	// User authentication routes (JWT-based)
	auth := router.Group("/auth")
	{
		auth.POST("/register", handler.Register)
		auth.POST("/login", handler.Login)
	}

	// API key management (requires JWT)
	keys := router.Group("/keys")
	keys.Use(AuthMiddleware())
	{
		keys.POST("/create", handler.CreateAPIKey)
		keys.GET("/list", handler.ListAPIKeys)
		keys.DELETE("/:key", handler.RevokeAPIKey)
	}

	// Logger operations (requires API key)
	api := router.Group("/api")
	api.Use(APIKeyMiddleware())
	{
		api.POST("/logger", handler.CreateLogger)                         // Create a new logger
		api.GET("/loggers", handler.ListLoggers)                          // List all loggers
		api.GET("/logs/:uuid", handler.ShowAllLogs)                       // Show all logs for a logger
		api.GET("/log/:logger_uuid/:request_uuid", handler.GetLogDetail)  // Get specific log details
		api.POST("/logger/:logger_uuid/repeater", handler.CreateRepeater) //Create repeater for logger
		api.GET("/logger/:logger_uuid/repeaters", handler.ListRepeaters)  //List all repeaters
		api.DELETE("/repeater/:id", handler.DeleteRepeater)               //Delete configured repeater
		api.PUT("/repeater/:id", handler.UpdateRepeater)                  //Update repeater configuration
	}

	// Public logging endpoint (no auth required for public loggers)
	router.Any("/log/:uuid/*path", handler.HandleLog)

	return router
}
