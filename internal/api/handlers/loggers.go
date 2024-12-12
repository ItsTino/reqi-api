package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"reqi-api/internal/models"
	"reqi-api/internal/utils"
	"time"

	"github.com/gin-gonic/gin"
)

// @Summary Create a new logger
// @Description Create a new logger for capturing requests
// @Tags loggers
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param logger body object{is_public=boolean} true "Logger creation details"
// @Success 200 {object} object{message=string,logger=object{uuid=string,url=string,is_public=boolean}}
// @Failure 401 {object} object{error=string}
// @Failure 500 {object} object{error=string}
// @Router /api/logger [post]
func (h *Handler) CreateLogger(c *gin.Context) {
	userID := c.GetString("user_id")

	var request struct {
		IsPublic bool `json:"is_public"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	logger := models.Logger{
		ID:       utils.GenerateUUID(),
		UserID:   userID,
		UUID:     utils.GenerateUUID(), // This UUID will be used in the log URL
		IsPublic: request.IsPublic,
	}

	query := `INSERT INTO loggers (id, user_id, uuid, is_public) VALUES (?, ?, ?, ?)`
	_, err := h.db.Exec(query, logger.ID, logger.UserID, logger.UUID, logger.IsPublic)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create logger"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Logger created successfully",
		"logger": gin.H{
			"uuid":      logger.UUID,
			"url":       fmt.Sprintf("/log/%s", logger.UUID),
			"is_public": logger.IsPublic,
		},
	})
}

// ListLoggers godoc
// @Summary List all loggers
// @Description Get a list of all loggers for the authenticated user
// @Tags loggers
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} map[string]interface{} "List of loggers"
// @Failure 401 {object} object{error=string}
// @Failure 500 {object} object{error=string}
// @Router /api/loggers [get]
func (h *Handler) ListLoggers(c *gin.Context) {
	userID := c.GetString("user_id")

	rows, err := h.db.Query(`
        SELECT uuid, is_public, created_at 
        FROM loggers 
        WHERE user_id = ? 
        ORDER BY created_at DESC`, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch loggers"})
		return
	}
	defer rows.Close()

	var loggers []gin.H
	for rows.Next() {
		var uuid string
		var isPublic bool
		var createdAt time.Time

		if err := rows.Scan(&uuid, &isPublic, &createdAt); err != nil {
			continue
		}

		loggers = append(loggers, gin.H{
			"uuid":       uuid,
			"url":        fmt.Sprintf("/log/%s", uuid),
			"is_public":  isPublic,
			"created_at": createdAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{"loggers": loggers})
}

// ShowAllLogs godoc
// @Summary Show all logs for a logger
// @Description Get a list of all captured requests for a specific logger
// @Tags logs
// @Produce json
// @Security ApiKeyAuth
// @Param uuid path string true "Logger UUID"
// @Success 200 {object} object{logs=[]object{id=string,method=string,path=string,created_at=time.Time}}
// @Failure 401 {object} object{error=string}
// @Failure 404 {object} object{error=string}
// @Failure 500 {object} object{error=string}
// @Router /api/logs/{uuid} [get]
func (h *Handler) ShowAllLogs(c *gin.Context) {
	userID := c.GetString("user_id")
	loggerUUID := c.Param("uuid")

	// Verify logger ownership
	var isPublic bool
	err := h.db.QueryRow(`
        SELECT is_public 
        FROM loggers 
        WHERE uuid = ? AND user_id = ?`, loggerUUID, userID).Scan(&isPublic)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Logger not found"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// Get all logs for this logger
	rows, err := h.db.Query(`
        SELECT le.id, le.method, le.path, le.created_at
        FROM log_entries le
        JOIN loggers l ON le.logger_id = l.id
        WHERE l.uuid = ?
        ORDER BY le.created_at DESC`, loggerUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch logs"})
		return
	}
	defer rows.Close()

	var logs []gin.H
	for rows.Next() {
		var id, method, path string
		var createdAt time.Time

		if err := rows.Scan(&id, &method, &path, &createdAt); err != nil {
			continue
		}

		logs = append(logs, gin.H{
			"id":         id,
			"method":     method,
			"path":       path,
			"created_at": createdAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{"logs": logs})
}

// GetLogDetail godoc
// @Summary Get log details
// @Description Get detailed information about a specific logged request
// @Tags logs
// @Produce json
// @Security ApiKeyAuth
// @Param logger_uuid path string true "Logger UUID"
// @Param request_uuid path string true "Request UUID"
// @Success 200 {object} object{method=string,path=string,headers=object,query=string,body=object,created_at=string}
// @Failure 401 {object} object{error=string}
// @Failure 404 {object} object{error=string}
// @Failure 500 {object} object{error=string}
// @Router /api/log/{logger_uuid}/{request_uuid} [get]
func (h *Handler) GetLogDetail(c *gin.Context) {
	userID := c.GetString("user_id")
	loggerUUID := c.Param("logger_uuid")
	requestUUID := c.Param("request_uuid")

	// Get encryptor for the user
	encryptor, err := h.getEncryptor(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption error"})
		return
	}

	// Verify logger ownership and get log details
	var logDetail struct {
		Method    string
		Path      string
		Headers   string
		Query     string
		Body      string
		CreatedAt time.Time
	}

	err = h.db.QueryRow(`
        SELECT le.method, le.path, le.headers, le.query, le.body, le.created_at
        FROM log_entries le
        JOIN loggers l ON le.logger_id = l.id
        WHERE l.uuid = ? AND le.id = ? AND l.user_id = ?`,
		loggerUUID, requestUUID, userID).Scan(
		&logDetail.Method,
		&logDetail.Path,
		&logDetail.Headers,
		&logDetail.Query,
		&logDetail.Body,
		&logDetail.CreatedAt,
	)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Log entry not found"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// Decrypt headers
	decryptedHeaders, err := encryptor.Decrypt(logDetail.Headers)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt headers"})
		return
	}

	// Parse decrypted headers
	var headers map[string]string
	if err := json.Unmarshal([]byte(decryptedHeaders), &headers); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse headers"})
		return
	}

	// Initialize body as interface
	var body interface{} = nil

	// Decrypt and parse body if present
	if logDetail.Body != "" {
		decryptedBody, err := encryptor.Decrypt(logDetail.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt body"})
			return
		}

		// Try to parse as JSON first
		var jsonBody interface{}
		if err := json.Unmarshal([]byte(decryptedBody), &jsonBody); err == nil {
			body = jsonBody
		} else {
			// If not JSON, use as string
			body = decryptedBody
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"method":     logDetail.Method,
		"path":       logDetail.Path,
		"headers":    headers,
		"query":      logDetail.Query,
		"body":       body,
		"created_at": logDetail.CreatedAt,
	})
}
