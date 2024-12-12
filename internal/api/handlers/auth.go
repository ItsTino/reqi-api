package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"net/http"
	"reqi-api/internal/auth"
	"reqi-api/internal/models"
	"reqi-api/internal/utils"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

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

	encryptionKey := make([]byte, 32)
	if _, err := rand.Read(encryptionKey); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate encryption key"})
		return
	}

	user := models.User{
		ID:            utils.GenerateUUID(),
		Email:         request.Email,
		Password:      string(hashedPassword),
		EncryptionKey: base64.StdEncoding.EncodeToString(encryptionKey),
	}

	// Insert user
	query := `INSERT INTO users (id, email, password, encryption_key) VALUES (?, ?, ?, ?)`
	_, err = h.db.Exec(query, user.ID, user.Email, user.Password, user.EncryptionKey)
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
