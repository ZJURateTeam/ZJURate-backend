// services/keystore.go
package services

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// KeyStore manages the secure storage of private keys.
type KeyStore struct {
	// 这是一个更安全、持久的存储后端。
	PrivateKeyStore *SQLiteKeyStore
}

func NewKeyStore(dbPath string) (*KeyStore, error) {
	sqliteStore, err := NewSQLiteKeyStore(dbPath)
	if err != nil {
		return nil, err
	}
	return &KeyStore{
		PrivateKeyStore: sqliteStore,
	}, nil
}

// GenerateKeyPair generates an RSA key pair and stores the private key in the database.
func (ks *KeyStore) GenerateKeyPair(studentID string) (*rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	privateKeyPEM, err := ks.PrivateKeyToPEM(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}

	// 保存私钥到数据库
	if err := ks.PrivateKeyStore.SavePrivateKey(studentID, privateKeyPEM); err != nil {
		return nil, fmt.Errorf("failed to save private key: %w", err)
	}

	return &privateKey.PublicKey, nil
}

// GetPrivateKey retrieves a private key for a given student ID from the database.
func (ks *KeyStore) GetPrivateKey(studentID string) (*rsa.PrivateKey, error) {
	privateKeyPEM, err := ks.PrivateKeyStore.GetPrivateKey(studentID)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return privateKey, nil
}

// Sign signs a message with the user's private key.
func (ks *KeyStore) Sign(studentID string, message []byte) ([]byte, error) {
	privateKey, err := ks.GetPrivateKey(studentID)
	if err != nil {
		return nil, err
	}

	hashed := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}
	return signature, nil
}

// PrivateKeyToPEM converts a private key to a PEM-encoded string.
func (ks *KeyStore) PrivateKeyToPEM(privateKey *rsa.PrivateKey) ([]byte, error) {
	privateBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateBytes,
	})
	return privatePEM, nil
}

// PublicKeyToPEM converts a public key to a PEM-encoded string.
func (ks *KeyStore) PublicKeyToPEM(publicKey *rsa.PublicKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubBytes,
	})
	return string(pubPEM), nil
}
