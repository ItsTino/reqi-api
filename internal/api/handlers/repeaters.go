package handlers

import (
	"database/sql"
	"net/http"
	"reqi-api/internal/models"
	"reqi-api/internal/utils"
	"time"

	"github.com/gin-gonic/gin"
)

func (h *Handler) CreateRepeater(c *gin.Context) {
	userID := c.GetString("user_id")
	loggerUUID := c.Param("logger_uuid")

	var request struct {
		ForwardURL   string `json:"forward_url" binding:"required,url"`
		PreserveHost bool   `json:"preserve_host"`
		Timeout      int    `json:"timeout"`
		RetryCount   int    `json:"retry_count"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Verify logger ownership
	var loggerID string
	err := h.db.QueryRow(`
        SELECT id FROM loggers 
        WHERE uuid = ? AND user_id = ?`, loggerUUID, userID).Scan(&loggerID)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Logger not found"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	repeater := models.Repeater{
		ID:           utils.GenerateUUID(),
		LoggerID:     loggerID,
		ForwardURL:   request.ForwardURL,
		IsActive:     true,
		PreserveHost: request.PreserveHost,
		Timeout:      request.Timeout,
		RetryCount:   request.RetryCount,
	}

	query := `INSERT INTO repeaters (id, logger_id, forward_url, is_active, preserve_host, timeout, retry_count) 
              VALUES (?, ?, ?, ?, ?, ?, ?)`
	_, err = h.db.Exec(query,
		repeater.ID,
		repeater.LoggerID,
		repeater.ForwardURL,
		repeater.IsActive,
		repeater.PreserveHost,
		repeater.Timeout,
		repeater.RetryCount,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create repeater"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "Repeater created successfully",
		"repeater": repeater,
	})
}

// ListRepeaters godoc
// @Summary List all repeaters for a logger
// @Description Get a list of all repeaters configured for a specific logger
// @Tags repeaters
// @Produce json
// @Security ApiKeyAuth
// @Param logger_uuid path string true "Logger UUID"
// @Success 200 {object} object{repeaters=[]object{id=string,forward_url=string,preserve_host=boolean,timeout=integer,retry_count=integer,is_active=boolean,created_at=time.Time}}
// @Failure 401 {object} object{error=string}
// @Failure 404 {object} object{error=string}
// @Failure 500 {object} object{error=string}
// @Router /api/logger/{logger_uuid}/repeaters [get]
func (h *Handler) ListRepeaters(c *gin.Context) {
	userID := c.GetString("user_id")
	loggerUUID := c.Param("logger_uuid")

	// Verify logger ownership
	var loggerID string
	err := h.db.QueryRow(`
        SELECT id 
        FROM loggers 
        WHERE uuid = ? AND user_id = ?`, loggerUUID, userID).Scan(&loggerID)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Logger not found"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// Get repeaters for this logger
	rows, err := h.db.Query(`
        SELECT id, forward_url, preserve_host, timeout, retry_count, is_active, created_at
        FROM repeaters 
        WHERE logger_id = ?
        ORDER BY created_at DESC`, loggerID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch repeaters"})
		return
	}
	defer rows.Close()

	var repeaters []gin.H
	for rows.Next() {
		var repeater struct {
			ID           string
			ForwardURL   string
			PreserveHost bool
			Timeout      int
			RetryCount   int
			IsActive     bool
			CreatedAt    time.Time
		}

		if err := rows.Scan(
			&repeater.ID,
			&repeater.ForwardURL,
			&repeater.PreserveHost,
			&repeater.Timeout,
			&repeater.RetryCount,
			&repeater.IsActive,
			&repeater.CreatedAt,
		); err != nil {
			continue
		}

		repeaters = append(repeaters, gin.H{
			"id":            repeater.ID,
			"forward_url":   repeater.ForwardURL,
			"preserve_host": repeater.PreserveHost,
			"timeout":       repeater.Timeout,
			"retry_count":   repeater.RetryCount,
			"is_active":     repeater.IsActive,
			"created_at":    repeater.CreatedAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{"repeaters": repeaters})
}

// DeleteRepeater godoc
// @Summary Delete a repeater
// @Description Delete a configured repeater
// @Tags repeaters
// @Produce json
// @Security ApiKeyAuth
// @Param id path string true "Repeater ID"
// @Success 200 {object} object{message=string}
// @Failure 401 {object} object{error=string}
// @Failure 404 {object} object{error=string}
// @Failure 500 {object} object{error=string}
// @Router /api/repeater/{id} [delete]
func (h *Handler) DeleteRepeater(c *gin.Context) {
	userID := c.GetString("user_id")
	repeaterID := c.Param("id")

	// Verify repeater ownership through logger
	result, err := h.db.Exec(`
        DELETE r FROM repeaters r
        JOIN loggers l ON r.logger_id = l.id
        WHERE r.id = ? AND l.user_id = ?`, repeaterID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete repeater"})
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify deletion"})
		return
	}

	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Repeater not found or unauthorized"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Repeater deleted successfully"})
}

// UpdateRepeater godoc
// @Summary Update a repeater
// @Description Update a configured repeater's settings
// @Tags repeaters
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param id path string true "Repeater ID"
// @Param request body object{forward_url=string,preserve_host=boolean,timeout=integer,retry_count=integer,is_active=boolean} true "Repeater settings"
// @Success 200 {object} object{message=string,repeater=object}
// @Failure 400 {object} object{error=string}
// @Failure 401 {object} object{error=string}
// @Failure 404 {object} object{error=string}
// @Failure 500 {object} object{error=string}
// @Router /api/repeater/{id} [put]
func (h *Handler) UpdateRepeater(c *gin.Context) {
	userID := c.GetString("user_id")
	repeaterID := c.Param("id")

	var request struct {
		ForwardURL   string `json:"forward_url" binding:"required,url"`
		PreserveHost bool   `json:"preserve_host"`
		Timeout      int    `json:"timeout" binding:"min=1,max=300"`
		RetryCount   int    `json:"retry_count" binding:"min=0,max=10"`
		IsActive     bool   `json:"is_active"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	// Verify repeater ownership and update
	result, err := h.db.Exec(`
        UPDATE repeaters r
        JOIN loggers l ON r.logger_id = l.id
        SET 
            r.forward_url = ?,
            r.preserve_host = ?,
            r.timeout = ?,
            r.retry_count = ?,
            r.is_active = ?
        WHERE r.id = ? AND l.user_id = ?`,
		request.ForwardURL,
		request.PreserveHost,
		request.Timeout,
		request.RetryCount,
		request.IsActive,
		repeaterID,
		userID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update repeater"})
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify update"})
		return
	}

	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Repeater not found or unauthorized"})
		return
	}

	// Fetch updated repeater data
	var repeater struct {
		ID           string    `json:"id"`
		ForwardURL   string    `json:"forward_url"`
		PreserveHost bool      `json:"preserve_host"`
		Timeout      int       `json:"timeout"`
		RetryCount   int       `json:"retry_count"`
		IsActive     bool      `json:"is_active"`
		CreatedAt    time.Time `json:"created_at"`
	}

	err = h.db.QueryRow(`
        SELECT id, forward_url, preserve_host, timeout, retry_count, is_active, created_at
        FROM repeaters
        WHERE id = ?`, repeaterID).Scan(
		&repeater.ID,
		&repeater.ForwardURL,
		&repeater.PreserveHost,
		&repeater.Timeout,
		&repeater.RetryCount,
		&repeater.IsActive,
		&repeater.CreatedAt,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch updated repeater"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "Repeater updated successfully",
		"repeater": repeater,
	})
}
