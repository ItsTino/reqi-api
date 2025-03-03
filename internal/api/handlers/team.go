package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"net/http"
	"reqi-api/internal/models"
	"reqi-api/internal/utils"

	"github.com/gin-gonic/gin"
)

func (h *Handler) CreateTeam(c *gin.Context) {
    userID := c.GetString("user_id")

    // Check if user is already in a team
    var existingTeamID string
    err := h.db.QueryRow(`
        SELECT team_id FROM team_members 
        WHERE user_id = ? AND status = 'active'`, userID).Scan(&existingTeamID)
    if err == nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "User already belongs to a team"})
        return
    }

    var request struct {
        Name string `json:"name" binding:"required"`
    }

    if err := c.ShouldBindJSON(&request); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    // Generate team encryption key
    encryptionKey := make([]byte, 32)
    if _, err := rand.Read(encryptionKey); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate encryption key"})
        return
    }
    encodedKey := base64.StdEncoding.EncodeToString(encryptionKey)

    // Start transaction
    tx, err := h.db.Begin()
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
        return
    }

    team := models.Team{
        ID:            utils.GenerateUUID(),
        Name:          request.Name,
        EncryptionKey: encodedKey,
    }

    // Create team
    _, err = tx.Exec(`
        INSERT INTO teams (id, name, encryption_key) 
        VALUES (?, ?, ?)`,
        team.ID, team.Name, team.EncryptionKey)
    if err != nil {
        tx.Rollback()
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create team"})
        return
    }

    // Add creator as admin
    _, err = tx.Exec(`
        INSERT INTO team_members (id, team_id, user_id, role, status) 
        VALUES (?, ?, ?, 'admin', 'active')`,
        utils.GenerateUUID(), team.ID, userID)
    if err != nil {
        tx.Rollback()
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add team member"})
        return
    }

    if err := tx.Commit(); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "message": "Team created successfully",
        "team": gin.H{
            "id": team.ID,
            "name": team.Name,
        },
    })
}

func (h *Handler) InviteToTeam(c *gin.Context) {
    userID := c.GetString("user_id")
    
    // Verify user is team admin
    var teamID string
    err := h.db.QueryRow(`
        SELECT team_id FROM team_members 
        WHERE user_id = ? AND role = 'admin' AND status = 'active'`, 
        userID).Scan(&teamID)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Must be team admin"})
        return
    }

    var invite models.TeamInvite
    if err := c.ShouldBindJSON(&invite); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    // Get invited user
    var invitedUserID string
    err = h.db.QueryRow("SELECT id FROM users WHERE email = ?", invite.Email).Scan(&invitedUserID)
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
        return
    }

    // Check if user is already in a team
    var existingTeamID string
    err = h.db.QueryRow(`
        SELECT team_id FROM team_members 
        WHERE user_id = ? AND status = 'active'`, 
        invitedUserID).Scan(&existingTeamID)
    if err == nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "User already belongs to a team"})
        return
    }

    // Create invitation
    _, err = h.db.Exec(`
        INSERT INTO team_members (id, team_id, user_id, role, status) 
        VALUES (?, ?, ?, 'member', 'invited')`,
        utils.GenerateUUID(), teamID, invitedUserID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create invitation"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Invitation sent successfully"})
}

func (h *Handler) AcceptInvite(c *gin.Context) {
    userID := c.GetString("user_id")

    // Check if user already has an active team membership
    var existingTeamID string
    err := h.db.QueryRow(`
        SELECT team_id FROM team_members 
        WHERE user_id = ? AND status = 'active'`, 
        userID).Scan(&existingTeamID)
    if err == nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Already a member of a team"})
        return
    }

    // Get and accept invitation
    result, err := h.db.Exec(`
        UPDATE team_members 
        SET status = 'active' 
        WHERE user_id = ? AND status = 'invited'`,
        userID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to accept invitation"})
        return
    }

    rows, _ := result.RowsAffected()
    if rows == 0 {
        c.JSON(http.StatusNotFound, gin.H{"error": "No pending invitation found"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Invitation accepted successfully"})
}

func (h *Handler) LeaveTeam(c *gin.Context) {
    userID := c.GetString("user_id")

    // Check if user is team admin
    var isAdmin bool
    err := h.db.QueryRow(`
        SELECT role = 'admin' 
        FROM team_members 
        WHERE user_id = ? AND status = 'active'`, 
        userID).Scan(&isAdmin)
    
    if err == sql.ErrNoRows {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Not a member of any team"})
        return
    }

    if isAdmin {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Team admin must remove all members before leaving"})
        return
    }

    // Start transaction
    tx, err := h.db.Begin()
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
        return
    }

    // Remove team association from user's loggers
    _, err = tx.Exec(`
        UPDATE loggers 
        SET team_id = NULL 
        WHERE user_id = ?`, userID)
    if err != nil {
        tx.Rollback()
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update loggers"})
        return
    }

    // Remove user from team
    _, err = tx.Exec(`
        DELETE FROM team_members 
        WHERE user_id = ?`, userID)
    if err != nil {
        tx.Rollback()
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to leave team"})
        return
    }

    if err := tx.Commit(); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit changes"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Successfully left team"})
}