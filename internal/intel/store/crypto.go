package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"

	"gowaf/internal/infra/logger"
)

var (
	encryptionKey []byte
	keyOnce       sync.Once
	keyErr        error
)

func getEncryptionKey() ([]byte, error) {
	keyOnce.Do(func() {
		keyHex := os.Getenv("GOWAF_INTEL_ENCRYPT_KEY")
		if keyHex == "" {
			logger.Warn("GOWAF_INTEL_ENCRYPT_KEY not set, using default key (NOT for production)")
			keyHex = "default_dev_key_32bytes_pad!!"
		}
		if len(keyHex) == 64 {
			key, err := hex.DecodeString(keyHex)
			if err != nil {
				keyErr = fmt.Errorf("invalid GOWAF_INTEL_ENCRYPT_KEY hex: %w", err)
				return
			}
			encryptionKey = key
		} else {
			key := []byte(keyHex)
			if len(key) < 32 {
				padded := make([]byte, 32)
				copy(padded, key)
				key = padded
			}
			encryptionKey = key[:32]
		}
	})
	return encryptionKey, keyErr
}

func EncryptAESGCM(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	key, err := getEncryptionKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), nil
}

func DecryptAESGCM(ciphertextHex string) (string, error) {
	if ciphertextHex == "" {
		return "", nil
	}
	key, err := getEncryptionKey()
	if err != nil {
		return "", err
	}
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode hex: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}
	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}
	return string(plaintext), nil
}
