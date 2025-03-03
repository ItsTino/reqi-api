// internal/api/routes.go
package api

import (
	"database/sql"
	"reqi-api/internal/api/handlers"
	"reqi-api/internal/api/middleware"
	"reqi-api/internal/ratelimit"
	"time"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func SetupRouter(db *sql.DB, rateLimiter *ratelimit.RateLimiter) *gin.Engine {
	router := gin.Default()
	h := handlers.NewHandler(db, rateLimiter) // Pass the rate limiter instance

	router.Use(func(c *gin.Context) {
		c.Set("db", db)
		c.Next()
	})

	//Swagger Route
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	router.GET("/", h.Home)

	// Auth routes
	auth := router.Group("/auth")
	auth.Use(middleware.AuthRateLimit(rateLimiter)) //RateLimit
	{
		auth.POST("/register", h.Register)
		auth.POST("/login", h.Login)
	}

	// Protected routes
	keys := router.Group("/keys")
	keys.Use(middleware.AuthMiddleware())
	keys.Use(middleware.ConfigurableRateLimit(rateLimiter, "api_keys", 0, time.Minute)) //api_keys disable default
	{
		keys.POST("/create", h.CreateAPIKey)
		keys.GET("/list", h.ListAPIKeys)
		keys.DELETE("/:key", h.RevokeAPIKey)
	}

	api := router.Group("/api")
	api.Use(APIKeyMiddleware())
	{
		// Logger management endpoints
		api.Use(middleware.ConfigurableRateLimit(rateLimiter, "logger_ops", 0, time.Minute))
		{
			api.POST("/logger", h.CreateLogger)
			api.GET("/loggers", h.ListLoggers)
			api.GET("/logs/:uuid", h.ShowAllLogs)
			api.GET("/log/:logger_uuid/:request_uuid", h.GetLogDetail)
			api.POST("/search/logs", h.SearchLogs)
		}

		// Repeater endpoints with specific rate limit
		repeater := api.Group("")
		repeater.Use(middleware.RepeaterRateLimit(rateLimiter))
		{
			repeater.POST("/logger/:logger_uuid/repeater", h.CreateRepeater)
			repeater.GET("/logger/:logger_uuid/repeaters", h.ListRepeaters)
			repeater.DELETE("/repeater/:id", h.DeleteRepeater)
			repeater.PUT("/repeater/:id", h.UpdateRepeater)
		}
	}

	teams := router.Group("/teams")
	teams.Use(middleware.AuthMiddleware())
	{
		teams.POST("/create", h.CreateTeam)
		teams.POST("/invite", h.InviteToTeam)
		teams.POST("/accept", h.AcceptInvite)
		teams.GET("/my-team", h.GetMyTeam)
		teams.DELETE("/leave", h.LeaveTeam) // New endpoint to leave team
	}

	// Public logging endpoint (no auth required for public loggers)
	router.Any("/log/:uuid/*path",
		middleware.PublicRateLimit(rateLimiter),
		h.HandleLog,
	)

	return router
}
