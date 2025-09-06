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
	"sync"
)

// KeyStore manages the secure storage of private keys.
type KeyStore struct {
	// In a real application, this would be a secure, encrypted database or an HSM.
	privateKeys map[string]*rsa.PrivateKey
	mu          sync.RWMutex
}

func NewKeyStore() *KeyStore {
	return &KeyStore{
		privateKeys: make(map[string]*rsa.PrivateKey),
	}
}

// GenerateKeyPair generates an RSA key pair and stores the private key.
func (ks *KeyStore) GenerateKeyPair(studentID string) (*rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	ks.mu.Lock()
	ks.privateKeys[studentID] = privateKey
	ks.mu.Unlock()

	return &privateKey.PublicKey, nil
}

// GetPrivateKey retrieves a private key for a given student ID.
func (ks *KeyStore) GetPrivateKey(studentID string) (*rsa.PrivateKey, error) {
	ks.mu.RLock()
	privateKey, ok := ks.privateKeys[studentID]
	ks.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("private key not found for student ID: %s", studentID)
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
