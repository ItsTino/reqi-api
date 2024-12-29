package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"reqi-api/internal/constants"
	"reqi-api/internal/models"
	"reqi-api/internal/utils"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

func (h *Handler) forwardRequest(repeater models.Repeater, originalReq *http.Request, logID string) {
	// Check rate limit first
	allowed, _, err := h.rateLimiter.Allow("global:repeater", constants.GlobalRepeaterLimit, time.Minute)
	if err != nil {
		log.Printf("Rate limit check failed for repeater: %v", err)
		return
	}
	if !allowed {
		log.Printf("Rate limit exceeded for repeater")
		return
	}

	// Create new request
	body, err := io.ReadAll(originalReq.Body)
	if err != nil {
		log.Printf("Error reading request body for forwarding: %v", err)
		return
	}
	originalReq.Body = io.NopCloser(bytes.NewBuffer(body))

	// Create forwarding request
	req, err := http.NewRequest(
		originalReq.Method,
		repeater.ForwardURL,
		bytes.NewBuffer(body),
	)
	if err != nil {
		log.Printf("Error creating forward request: %v", err)
		return
	}

	// Copy headers
	for key, values := range originalReq.Header {
		if key != "Host" || repeater.PreserveHost {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}

	// Add custom headers
	req.Header.Set("X-Reqi-Request-ID", logID)
	req.Header.Set("X-Reqi-Forwarded", "true")

	// Create client with timeout
	client := &http.Client{
		Timeout: time.Duration(repeater.Timeout) * time.Second,
	}

	// Attempt forwarding with retries
	var lastErr error
	for i := 0; i <= repeater.RetryCount; i++ {
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(time.Second * time.Duration(i+1)) // Exponential backoff
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			log.Printf("Successfully forwarded request to %s", repeater.ForwardURL)
			return
		}

		lastErr = fmt.Errorf("received status code: %d", resp.StatusCode)
		time.Sleep(time.Second * time.Duration(i+1))
	}

	log.Printf("Failed to forward request after %d attempts: %v",
		repeater.RetryCount+1, lastErr)
}

func getHeadersAsJSON(headers http.Header) string {
	headerMap := make(map[string]string)
	for key, values := range headers {
		// If there are multiple values, join them with comma
		headerMap[key] = strings.Join(values, ",")
	}
	jsonBytes, _ := json.Marshal(headerMap)
	return string(jsonBytes)
}

// HandleLog godoc
// @Summary Capture incoming request
// @Description Capture and store details of incoming request
// @Tags logs
// @Accept json
// @Produce json
// @Param uuid path string true "Logger UUID"
// @Param path path string true "Capture path"
// @Success 200 {object} object{message=string,request=object{id=string,timestamp=string,method=string,path=string,headers=object,body=object}}
// @Failure 404 {object} object{error=string}
// @Failure 500 {object} object{error=string}
// @Router /log/{uuid}/{path} [post]
func (h *Handler) HandleLog(c *gin.Context) {
	loggerUUID := c.Param("uuid")
	path := c.Param("path")

	// Get logger details
	var logger models.Logger
	err := h.db.QueryRow(`
        SELECT id, user_id, is_public 
        FROM loggers 
        WHERE uuid = ?`, loggerUUID).Scan(
		&logger.ID,
		&logger.UserID,
		&logger.IsPublic,
	)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Logger not found"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// Get encryptor for the logger's user
	encryptor, err := h.getEncryptor(logger.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption error"})
		return
	}

	// Read request body
	var bodyBytes []byte
	if c.Request.Body != nil {
		bodyBytes, err = io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read request body"})
			return
		}
		// Restore the body for potential further middleware
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	// Encrypt headers
	encryptedHeaders, err := encryptor.Encrypt(getHeadersAsJSON(c.Request.Header))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt headers"})
		return
	}

	// Create log entry
	logEntry := models.LogEntry{
		ID:       utils.GenerateUUID(),
		LoggerID: logger.ID,
		Method:   c.Request.Method,
		Path:     path,
		Headers:  encryptedHeaders,
		Query:    c.Request.URL.RawQuery,
	}

	// Process and encrypt body if present
	if len(bodyBytes) > 0 {
		var bodyToEncrypt string
		// Try to pretty-print JSON body
		if json.Valid(bodyBytes) {
			var prettyJSON bytes.Buffer
			if err := json.Indent(&prettyJSON, bodyBytes, "", "  "); err == nil {
				bodyToEncrypt = prettyJSON.String()
			} else {
				bodyToEncrypt = string(bodyBytes)
			}
		} else {
			bodyToEncrypt = string(bodyBytes)
		}

		// Encrypt the body
		encryptedBody, err := encryptor.Encrypt(bodyToEncrypt)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt body"})
			return
		}
		logEntry.Body = encryptedBody
	}

	// Store the log entry
	query := `INSERT INTO log_entries (
        id, logger_id, method, path, headers, query, body
    ) VALUES (?, ?, ?, ?, ?, ?, ?)`

	_, err = h.db.Exec(query,
		logEntry.ID,
		logEntry.LoggerID,
		logEntry.Method,
		logEntry.Path,
		logEntry.Headers,
		logEntry.Query,
		logEntry.Body,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store log entry"})
		return
	}

	// Check for and process repeaters
	rows, err := h.db.Query(`
        SELECT id, forward_url, preserve_host, timeout, retry_count 
        FROM repeaters 
        WHERE logger_id = ? AND is_active = true`, logger.ID)
	if err != nil {
		log.Printf("Error checking repeaters: %v", err)
	} else {
		defer rows.Close()
		for rows.Next() {
			var repeater models.Repeater
			err := rows.Scan(
				&repeater.ID,
				&repeater.ForwardURL,
				&repeater.PreserveHost,
				&repeater.Timeout,
				&repeater.RetryCount,
			)
			if err != nil {
				continue
			}
			// Forward request asynchronously
			go h.forwardRequest(repeater, c.Request, logEntry.ID)
		}
	}

	// Prepare response (using original, unencrypted data for response)
	response := gin.H{
		"id":        logEntry.ID,
		"timestamp": time.Now().UTC(),
		"method":    logEntry.Method,
		"path":      logEntry.Path,
		"query":     logEntry.Query,
	}

	// Add original headers to response
	var headers map[string]string
	headersJSON := getHeadersAsJSON(c.Request.Header)
	json.Unmarshal([]byte(headersJSON), &headers)
	response["headers"] = headers

	// Add original body to response
	if len(bodyBytes) > 0 {
		if json.Valid(bodyBytes) {
			var jsonBody interface{}
			if err := json.Unmarshal(bodyBytes, &jsonBody); err == nil {
				response["body"] = jsonBody
			} else {
				response["body"] = string(bodyBytes)
			}
		} else {
			response["body"] = string(bodyBytes)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Request logged successfully",
		"request": response,
	})
}
