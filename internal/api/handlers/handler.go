package handlers

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"reqi-api/internal/crypto"
	"sync"
)

type Handler struct {
	db         *sql.DB
	encryptors map[string]*crypto.Encryptor // Cache of user encryptors
	mu         sync.RWMutex                 // Mutex for encryptors map
}

func NewHandler(db *sql.DB) *Handler {
	return &Handler{
		db:         db,
		encryptors: make(map[string]*crypto.Encryptor),
	}
}

func (h *Handler) getEncryptor(userID string) (*crypto.Encryptor, error) {
	h.mu.RLock()
	enc, exists := h.encryptors[userID]
	h.mu.RUnlock()

	if exists {
		return enc, nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Check again in case another goroutine created it
	if enc, exists = h.encryptors[userID]; exists {
		return enc, nil
	}

	// Get user's encryption key
	var encryptedKey string
	err := h.db.QueryRow("SELECT encryption_key FROM users WHERE id = ?", userID).Scan(&encryptedKey)
	if err != nil {
		return nil, err
	}

	// Decode the base64 key back to bytes
	keyBytes, err := base64.StdEncoding.DecodeString(encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption key: %v", err)
	}

	enc, err = crypto.NewEncryptor(string(keyBytes))
	if err != nil {
		return nil, err
	}

	h.encryptors[userID] = enc
	return enc, nil
}
