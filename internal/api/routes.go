// internal/api/routes.go
package api

import (
	"database/sql"
	"reqi-api/internal/api/handlers"
	"reqi-api/internal/api/middleware"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func SetupRouter(db *sql.DB) *gin.Engine {
	router := gin.Default()
	h := handlers.NewHandler(db)

	router.Use(func(c *gin.Context) {
		c.Set("db", db)
		c.Next()
	})

	//Swagger Route
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Auth routes
	auth := router.Group("/auth")
	{
		auth.POST("/register", h.Register)
		auth.POST("/login", h.Login)
	}

	// Protected routes
	keys := router.Group("/keys")
	keys.Use(middleware.AuthMiddleware())
	{
		keys.POST("/create", h.CreateAPIKey)
		keys.GET("/list", h.ListAPIKeys)
		keys.DELETE("/:key", h.RevokeAPIKey)
	}

	// Logger operations (requires API key)
	api := router.Group("/api")
	api.Use(APIKeyMiddleware())
	{
		api.POST("/logger", h.CreateLogger)                         // Create a new logger
		api.GET("/loggers", h.ListLoggers)                          // List all loggers
		api.GET("/logs/:uuid", h.ShowAllLogs)                       // Show all logs for a logger
		api.GET("/log/:logger_uuid/:request_uuid", h.GetLogDetail)  // Get specific log details
		api.POST("/logger/:logger_uuid/repeater", h.CreateRepeater) //Create repeater for logger
		api.GET("/logger/:logger_uuid/repeaters", h.ListRepeaters)  //List all repeaters
		api.DELETE("/repeater/:id", h.DeleteRepeater)               //Delete configured repeater
		api.PUT("/repeater/:id", h.UpdateRepeater)                  //Update repeater configuration
	}

	// Public logging endpoint (no auth required for public loggers)
	router.Any("/log/:uuid/*path", h.HandleLog)

	return router
}
