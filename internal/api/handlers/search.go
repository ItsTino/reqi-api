package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"reqi-api/internal/models"
	"strings"

	"github.com/gin-gonic/gin"
)

func (h *Handler) SearchLogs(c *gin.Context) {
	userID := c.GetString("user_id")
	var req models.LogSearchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request format"})
		return
	}

	// Validate and set defaults with strict whitelist validation
	if err := validateSearchRequest(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Use prepared statement with fixed query structure
	query, args := buildSearchQuery(userID, &req)

	// Execute query using prepared statement
	stmt, err := h.db.Prepare(query)
	if err != nil {
		log.Printf("Failed to prepare search query: %v", err)
		c.JSON(500, gin.H{"error": "Internal server error"})
		return
	}
	defer stmt.Close()

	rows, err := stmt.Query(args...)
	if err != nil {
		log.Printf("Failed to execute search query: %v", err)
		c.JSON(500, gin.H{"error": "Internal server error"})
		return
	}
	defer rows.Close()

	var logs []models.LogDetail
	var totalCount int64

	// Get encryptor for decryption
	encryptor, err := h.getEncryptor(userID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Encryption error"})
		return
	}

	for rows.Next() {
		var log models.LogDetail
		var encryptedHeaders, encryptedBody string

		err := rows.Scan(
			&log.UUID,
			&log.Method,
			&log.Path,
			&encryptedHeaders,
			&encryptedBody,
			&log.Query,
			&log.CreatedAt,
			&totalCount,
		)
		if err != nil {
			continue
		}

		// internal/api/handlers/search.go
		if encryptedHeaders != "" {
			decryptedHeaders, err := encryptor.Decrypt(encryptedHeaders)
			if err == nil {
				var headers map[string]string // Changed to match LogDetail model
				if err := json.Unmarshal([]byte(decryptedHeaders), &headers); err == nil {
					// Filter by header if requested
					if req.HeaderKey != "" {
						if val, ok := headers[req.HeaderKey]; !ok {
							continue
						} else if req.HeaderValue != "" && val != req.HeaderValue {
							continue
						}
					}
					log.Headers = headers
				}
			}
		}

		// Decrypt and parse body
		if encryptedBody != "" {
			decryptedBody, err := encryptor.Decrypt(encryptedBody)
			if err == nil {
				var jsonBody interface{}
				if json.Valid([]byte(decryptedBody)) {
					json.Unmarshal([]byte(decryptedBody), &jsonBody)
					log.Body = jsonBody

					// Filter by body content if requested
					if req.BodyContains != "" {
						bodyStr := strings.ToLower(decryptedBody)
						if !strings.Contains(bodyStr, strings.ToLower(req.BodyContains)) {
							continue
						}
					}
				} else {
					log.Body = decryptedBody
				}
			}
		}

		logs = append(logs, log)
	}

	pageCount := (int(totalCount) + req.PageSize - 1) / req.PageSize
	hasMore := req.Page < pageCount

	c.JSON(200, models.LogSearchResponse{
		Logs:        logs,
		Total:       totalCount,
		PageCount:   pageCount,
		CurrentPage: req.Page,
		HasMore:     hasMore,
	})
}

func buildSearchQuery(userID string, req *models.LogSearchRequest) (string, []interface{}) {
	// Base query with placeholder for dynamic conditions
	baseQuery := `
        SELECT 
            le.id, 
            le.method, 
            le.path, 
            le.headers, 
            le.body, 
            le.query, 
            le.created_at,
            COUNT(*) OVER() as total_count
        FROM log_entries le
        JOIN loggers l ON le.logger_id = l.id
        WHERE l.user_id = ?
        AND %s
        ORDER BY le.%s %s
        LIMIT ? OFFSET ?`

	var conditions []string
	var args []interface{}
	args = append(args, userID)

	// Build conditions safely
	if req.LoggerID != "" {
		conditions = append(conditions, "l.uuid = ?")
		args = append(args, req.LoggerID)
	}

	if len(req.Method) > 0 {
		placeholders := make([]string, len(req.Method))
		for i := range req.Method {
			placeholders[i] = "?"
			args = append(args, req.Method[i])
		}
		conditions = append(conditions, fmt.Sprintf("le.method IN (%s)", strings.Join(placeholders, ",")))
	}

	if req.PathContains != "" {
		conditions = append(conditions, "le.path LIKE ?")
		args = append(args, "%"+req.PathContains+"%")
	}

	if req.DateFrom != nil {
		conditions = append(conditions, "le.created_at >= ?")
		args = append(args, req.DateFrom)
	}

	if req.DateTo != nil {
		conditions = append(conditions, "le.created_at <= ?")
		args = append(args, req.DateTo)
	}

	// If no conditions, use TRUE
	whereClause := "TRUE"
	if len(conditions) > 0 {
		whereClause = strings.Join(conditions, " AND ")
	}

	// Add sorting and pagination args
	query := fmt.Sprintf(baseQuery, whereClause, req.SortBy, req.SortOrder)
	offset := (req.Page - 1) * req.PageSize
	args = append(args, req.PageSize, offset)

	return query, args
}

func validateSearchRequest(req *models.LogSearchRequest) error {
	// Validate pagination
	if req.Page < 1 {
		req.Page = 1
	}
	if req.PageSize < 1 || req.PageSize > 100 {
		req.PageSize = 20
	}

	// Validate sorting
	allowedSortFields := map[string]bool{
		"created_at": true,
		"method":     true,
		"path":       true,
	}

	if req.SortBy == "" {
		req.SortBy = "created_at"
	} else if !allowedSortFields[req.SortBy] {
		return fmt.Errorf("invalid sort field: %s", req.SortBy)
	}

	if req.SortOrder != "asc" && req.SortOrder != "desc" {
		req.SortOrder = "desc"
	}

	// Validate methods if provided
	if len(req.Method) > 0 {
		allowedMethods := map[string]bool{
			"GET":     true,
			"POST":    true,
			"PUT":     true,
			"DELETE":  true,
			"PATCH":   true,
			"OPTIONS": true,
			"HEAD":    true,
		}

		for _, method := range req.Method {
			if !allowedMethods[strings.ToUpper(method)] {
				return fmt.Errorf("invalid HTTP method: %s", method)
			}
		}
	}

	// Validate dates
	if req.DateFrom != nil && req.DateTo != nil {
		if req.DateFrom.After(*req.DateTo) {
			return errors.New("date_from must be before date_to")
		}
	}

	return nil
}
