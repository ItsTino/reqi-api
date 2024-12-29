package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h *Handler) Home(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Hi :)",
		"status":  http.StatusOK,
		"server":  "reqi-api",
	})
}
