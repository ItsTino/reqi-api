// internal/api/handlers.go
package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reqi-api/internal/auth"
	"reqi-api/internal/models"
	"reqi-api/internal/utils"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
    db *sql.DB
}

func NewHandler(db *sql.DB) *Handler {
    return &Handler{db: db}
}


// Register godoc
// @Summary Register a new user
// @Description Register a new user with email and password
// @Tags auth
// @Accept json
// @Produce json
// @Param user body object{email=string,password=string} true "User registration details"
// @Success 200 {object} object{message=string,user=object{id=string,email=string,created_at=string,updated_at=string}}
// @Failure 400 {object} object{error=string}
// @Failure 500 {object} object{error=string}
// @Router /auth/register [post]
func (h *Handler) Register(c *gin.Context) {
    var request struct {
        Email    string `json:"email" binding:"required"`
        Password string `json:"password" binding:"required"`
    }

    if err := c.ShouldBindJSON(&request); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Email and password are required"})
        return
    }

    if len(request.Password) < 6 {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 6 characters"})
        return
    }

    // Check if user exists
    var exists bool
    err := h.db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)", request.Email).Scan(&exists)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
        return
    }
    if exists {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Email already registered"})
        return
    }

    // Hash password and create user
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
        return
    }

    user := models.User{
        ID:       utils.GenerateUUID(),
        Email:    request.Email,
        Password: string(hashedPassword),
    }

    // Insert user
    query := `INSERT INTO users (id, email, password) VALUES (?, ?, ?)`
    _, err = h.db.Exec(query, user.ID, user.Email, string(hashedPassword))
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
        return
    }

    // Fetch user details
    err = h.db.QueryRow(`
        SELECT id, email, created_at, updated_at 
        FROM users 
        WHERE id = ?`, user.ID).Scan(
        &user.ID,
        &user.Email,
        &user.CreatedAt,
        &user.UpdatedAt,
    )
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user details"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "message": "User registered successfully",
        "user":    user,
    })
}

// RegisterAPI godoc
// @Summary Register a new API key
// @Description Create a new API key for the authenticated user
// @Tags api-keys
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body object{is_public=boolean} true "API key creation details"
// @Success 200 {object} object{message=string,api_key=object{id=string,user_id=string,api_key=string,is_public=boolean,created_at=string,updated_at=string}}
// @Failure 401 {object} object{error=string}
// @Failure 500 {object} object{error=string}
// @Router /api/register [post]
func (h *Handler) RegisterAPI(c *gin.Context) {
    userID, exists := c.Get("user_id")
    if !exists {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        return
    }

    var apiKey models.APIKey
    if err := c.ShouldBindJSON(&apiKey); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    apiKey.ID = utils.GenerateUUID()
    apiKey.UserID = userID.(string)
    apiKey.APIKey = "api_" + utils.GenerateUUID()

    query := `INSERT INTO api_keys (id, user_id, api_key, is_public) VALUES (?, ?, ?, ?)`
    _, err := h.db.Exec(query, apiKey.ID, apiKey.UserID, apiKey.APIKey, apiKey.IsPublic)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create API key"})
        return
    }

    // Fetch the complete API key record including timestamps
    err = h.db.QueryRow(`
        SELECT id, user_id, api_key, is_public, created_at, updated_at 
        FROM api_keys 
        WHERE id = ?`, apiKey.ID).Scan(
        &apiKey.ID,
        &apiKey.UserID,
        &apiKey.APIKey,
        &apiKey.IsPublic,
        &apiKey.CreatedAt,
        &apiKey.UpdatedAt,
    )
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch API key details"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "message": "API key created successfully",
        "api_key": apiKey,
    })
}

// Login godoc
// @Summary Login user
// @Description Authenticate user and return JWT token
// @Tags auth
// @Accept json
// @Produce json
// @Param credentials body object{email=string,password=string} true "Login credentials"
// @Success 200 {object} object{message=string,token=string,user=object{id=string,email=string}}
// @Failure 401 {object} object{error=string}
// @Failure 500 {object} object{error=string}
// @Router /auth/login [post]
func (h *Handler) Login(c *gin.Context) {
    var credentials struct {
        Email    string `json:"email" binding:"required"`
        Password string `json:"password" binding:"required"`
    }

    if err := c.ShouldBindJSON(&credentials); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Email and password are required"})
        return
    }

    // Get user from database
    var user models.User
    var storedHash string
    err := h.db.QueryRow("SELECT id, email, password FROM users WHERE email = ?", 
        credentials.Email).Scan(&user.ID, &user.Email, &storedHash)

    if err == sql.ErrNoRows {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
        return
    } else if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
        return
    }

    // Verify password
    err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(credentials.Password))
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
        return
    }

    // Fetch complete user details
    err = h.db.QueryRow(`
        SELECT created_at, updated_at 
        FROM users 
        WHERE id = ?`, user.ID).Scan(
        &user.CreatedAt,
        &user.UpdatedAt,
    )
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Error fetching user details"})
        return
    }

    // Generate JWT token
    token, err := auth.GenerateToken(user.ID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "message": "Login successful",
        "token":   token,
    })
}

// Log godoc
// @Summary Log a request (Deprecated)
// @Description Legacy endpoint for logging requests (use HandleLog instead)
// @Tags logs
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body object{uuid=string,body=string} true "Log details"
// @Success 200 {object} object{message=string,log=object}
// @Failure 401 {object} object{error=string}
// @Failure 500 {object} object{error=string}
// @Router /api/log [post]
func (h *Handler) Log(c *gin.Context) {
    apiKeyHeader := c.GetHeader("X-API-Key")
    if apiKeyHeader == "" {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "API key required"})
        return
    }

    // Verify API key
    var apiKey models.APIKey
    err := h.db.QueryRow("SELECT id, is_public FROM api_keys WHERE api_key = ?", apiKeyHeader).
        Scan(&apiKey.ID, &apiKey.IsPublic)
    if err == sql.ErrNoRows {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
        return
    } else if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
        return
    }

    var log models.Log
    if err := c.ShouldBindJSON(&log); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    log.ID = utils.GenerateUUID()
    log.APIKeyID = apiKey.ID

    query := `INSERT INTO logs (id, api_key_id, uuid, body) VALUES (?, ?, ?, ?)`
    _, err = h.db.Exec(query, log.ID, log.APIKeyID, log.UUID, log.Body)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create log"})
        return
    }

    // Fetch the complete log record including timestamp
    err = h.db.QueryRow(`
        SELECT id, api_key_id, uuid, body, created_at 
        FROM logs 
        WHERE id = ?`, log.ID).Scan(
        &log.ID,
        &log.APIKeyID,
        &log.UUID,
        &log.Body,
        &log.CreatedAt,
    )
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch log details"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "message": "Log created successfully",
        "log":     log,
    })
}

// CreateAPIKey godoc
// @Summary Create a new API key
// @Description Create a new named API key for the authenticated user
// @Tags api-keys
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body object{name=string,is_public=boolean} true "API key creation details"
// @Success 200 {object} object{message=string,api_key=object{id=string,name=string,api_key=string,is_public=boolean,is_active=boolean}}
// @Failure 401 {object} object{error=string}
// @Failure 500 {object} object{error=string}
// @Router /keys/create [post]
func (h *Handler) CreateAPIKey(c *gin.Context) {
    userID, _ := c.Get("user_id")

    var request struct {
        Name     string `json:"name" binding:"required"`
        IsPublic bool   `json:"is_public"`
    }

    if err := c.ShouldBindJSON(&request); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    apiKey := models.APIKey{
        ID:       utils.GenerateUUID(),
        UserID:   userID.(string),
        Name:     request.Name,
        APIKey:      "ak_" + utils.GenerateUUID(),
        IsPublic: request.IsPublic,
        IsActive: true,
    }

    query := `INSERT INTO api_keys (id, user_id, name, api_key, is_public, is_active) 
              VALUES (?, ?, ?, ?, ?, ?)`
    _, err := h.db.Exec(query, apiKey.ID, apiKey.UserID, apiKey.Name, 
        apiKey.APIKey, apiKey.IsPublic, apiKey.IsActive)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create API key"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "message": "API key created successfully",
        "api_key": apiKey,
    })
}

// ListAPIKeys godoc
// @Summary List all API keys
// @Description Get a list of all API keys for the authenticated user
// @Tags api-keys
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string][]object{id=string,name=string,api_key=string,is_public=boolean,is_active=boolean,created_at=time.Time}
// @Failure 401 {object} object{error=string}
// @Failure 500 {object} object{error=string}
// @Router /keys/list [get]
func (h *Handler) ListAPIKeys(c *gin.Context) {
    userID, _ := c.Get("user_id")

    rows, err := h.db.Query(`
        SELECT id, name, api_key, is_public, is_active, created_at 
        FROM api_keys 
        WHERE user_id = ?
        ORDER BY created_at DESC`, userID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch API keys"})
        return
    }
    defer rows.Close()

    var apiKeys []models.APIKey
    for rows.Next() {
        var key models.APIKey
        err := rows.Scan(&key.ID, &key.Name, &key.APIKey, &key.IsPublic, 
            &key.IsActive, &key.CreatedAt)
        if err != nil {
            continue
        }
        apiKeys = append(apiKeys, key)
    }

    c.JSON(http.StatusOK, gin.H{
        "api_keys": apiKeys,
    })
}

// RevokeAPIKey godoc
// @Summary Revoke an API key
// @Description Deactivate an existing API key
// @Tags api-keys
// @Produce json
// @Security BearerAuth
// @Param key path string true "API key to revoke"
// @Success 200 {object} object{message=string}
// @Failure 401 {object} object{error=string}
// @Failure 404 {object} object{error=string}
// @Failure 500 {object} object{error=string}
// @Router /keys/{key} [delete]
func (h *Handler) RevokeAPIKey(c *gin.Context) {
    userID, _ := c.Get("user_id")
    keyToRevoke := c.Param("key")

    result, err := h.db.Exec(`
        UPDATE api_keys 
        SET is_active = false 
        WHERE user_id = ? AND api_key = ?`, userID, keyToRevoke)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke API key"})
        return
    }

    rowsAffected, _ := result.RowsAffected()
    if rowsAffected == 0 {
        c.JSON(http.StatusNotFound, gin.H{"error": "API key not found"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "message": "API key revoked successfully",
    })
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

    // Create log entry
    logEntry := models.LogEntry{
        ID:        utils.GenerateUUID(),
        LoggerID:  logger.ID,
        Method:    c.Request.Method,
        Path:      path,
        Headers:   getHeadersAsJSON(c.Request.Header),
        Query:     c.Request.URL.RawQuery,
    }

    // Store body if present
    if len(bodyBytes) > 0 {
        // Try to pretty-print JSON body
        var prettyJSON bytes.Buffer
        if json.Valid(bodyBytes) {
            if err := json.Indent(&prettyJSON, bodyBytes, "", "  "); err == nil {
                logEntry.Body = prettyJSON.String()
            } else {
                logEntry.Body = string(bodyBytes)
            }
        } else {
            logEntry.Body = string(bodyBytes)
        }
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

    // Return the captured request details
    response := gin.H{
        "id":         logEntry.ID,
        "timestamp":  time.Now().UTC(),
        "method":     logEntry.Method,
        "path":       logEntry.Path,
        "query":      logEntry.Query,
    }

    // Parse headers for response
    var headers map[string]string
    json.Unmarshal([]byte(logEntry.Headers), &headers)
    response["headers"] = headers

    // Add body to response if present
    if logEntry.Body != "" {
        // Try to parse JSON body for response
        var jsonBody interface{}
        if err := json.Unmarshal([]byte(logEntry.Body), &jsonBody); err == nil {
            response["body"] = jsonBody
        } else {
            response["body"] = logEntry.Body
        }
    }

    c.JSON(http.StatusOK, gin.H{
        "message": "Request logged successfully",
        "request": response,
    })
}

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
            "uuid": logger.UUID,
            "url": fmt.Sprintf("/log/%s", logger.UUID),
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
            "uuid": uuid,
            "url": fmt.Sprintf("/log/%s", uuid),
            "is_public": isPublic,
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
            "id": id,
            "method": method,
            "path": path,
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

    // Verify logger ownership and get log details
    var logDetail struct {
        Method    string
        Path      string
        Headers   string
        Query     string
        Body      string
        CreatedAt time.Time
    }

    err := h.db.QueryRow(`
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

    // Parse headers
    var headers map[string]string
    json.Unmarshal([]byte(logDetail.Headers), &headers)

    // Parse body if it's JSON
    var body interface{} = logDetail.Body
    if logDetail.Body != "" {
        var jsonBody interface{}
        if err := json.Unmarshal([]byte(logDetail.Body), &jsonBody); err == nil {
            body = jsonBody
        }
    }

    c.JSON(http.StatusOK, gin.H{
        "method": logDetail.Method,
        "path": logDetail.Path,
        "headers": headers,
        "query": logDetail.Query,
        "body": body,
        "created_at": logDetail.CreatedAt,
    })
}