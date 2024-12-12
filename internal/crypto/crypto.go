package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

type Encryptor struct {
	key []byte
}

func NewEncryptor(key string) (*Encryptor, error) {
	// Key must be 32 bytes for AES-256
	if len(key) != 32 {
		return nil, errors.New("encryption key must be 32 bytes")
	}
	return &Encryptor{key: []byte(key)}, nil
}

func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", err
	}

	// Never use more than 2^32 random nonces with a given key
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext := aesgcm.Seal(nil, nonce, []byte(plaintext), nil)

	// Combine nonce and ciphertext for storage
	combined := make([]byte, len(nonce)+len(ciphertext))
	copy(combined, nonce)
	copy(combined[len(nonce):], ciphertext)

	return base64.StdEncoding.EncodeToString(combined), nil
}

func (e *Encryptor) Decrypt(ciphertext string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(decoded) < 12 {
		return "", errors.New("ciphertext too short")
	}

	nonce := decoded[:12]
	ciphertextBytes := decoded[12:]

	plaintext, err := aesgcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
