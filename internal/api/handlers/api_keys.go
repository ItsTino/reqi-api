package handlers

import (
	"net/http"
	"reqi-api/internal/models"
	"reqi-api/internal/utils"

	"github.com/gin-gonic/gin"
)

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
		APIKey:   "ak_" + utils.GenerateUUID(),
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
