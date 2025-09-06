// services/blockchain.go
package services

import (
	"fmt"

	"github.com/ZJURateTeam/ZJURate-backend/models"
	"golang.org/x/crypto/bcrypt"
)

// BlockchainService manages interactions with the Hyperledger Fabric network.
type BlockchainService struct {
	keyStore *KeyStore
	// In a real app, you would have a separate user service or database
	// for storing user credentials. Here we'll use a simple map for demonstration.
	userPasswords map[string]string
}

// NewBlockchainService creates a new instance of the blockchain service.
// This is where you'd load the Fabric connection profile and set up the client.
func NewBlockchainService(ks *KeyStore) (*BlockchainService, error) {
	fmt.Println("Blockchain service initialized (placeholder)")
	return &BlockchainService{
		keyStore:      ks,
		userPasswords: make(map[string]string),
	}, nil
}

// RegisterUser generates a key pair and records the public key on the blockchain.
func (s *BlockchainService) RegisterUser(user models.UserRegister) error {
	// 1. Hash the password (This should ideally be done in a separate user service layer,
	// but for this example, we'll keep it here for simplicity)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	s.userPasswords[user.StudentID] = string(hashedPassword)

	// 2. Generate a key pair and store the private key securely.
	publicKey, err := s.keyStore.GenerateKeyPair(user.StudentID)
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	publicKeyPEM, err := s.keyStore.PublicKeyToPEM(publicKey)
	if err != nil {
		return fmt.Errorf("failed to encode public key: %w", err)
	}

	// 3. Prepare the data to be put on the blockchain.
	bcUser := struct {
		StudentID string `json:"studentId"`
		Username  string `json:"username"`
		PublicKey string `json:"publicKey"`
	}{
		StudentID: user.StudentID,
		Username:  user.Username,
		PublicKey: publicKeyPEM,
	}

	// 4. TODO: Use the blockchain service to submit a transaction
	// to register the user with their public key.
	fmt.Printf("Submitting RegisterUser transaction with public key for studentId: %s\n", bcUser.StudentID)

	// Simulation of success
	return nil
}

// LoginUser authenticates a user and returns their blockchain key.
func (s *BlockchainService) LoginUser(login models.UserLogin) (*models.User, error) {
	// 1. Check if the user exists
	hashedPassword, ok := s.userPasswords[login.StudentID]
	if !ok {
		return nil, fmt.Errorf("user not found")
	}

	// 2. Authenticate the password
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(login.Password)); err != nil {
		return nil, fmt.Errorf("invalid password")
	}

	// TODO: Retrieve user's public key from the blockchain
	// For now, we'll simulate a successful login
	fmt.Printf("User with studentId: %s authenticated successfully\n", login.StudentID)
	return &models.User{StudentID: login.StudentID, Username: "犬戎"}, nil
}

// GetAllMerchants fetches all merchants from the blockchain.
func (s *BlockchainService) GetAllMerchants() ([]models.MerchantSummary, error) {
	// TODO: Call chaincode to query all merchants.
	fmt.Println("Querying all merchants from the blockchain...")
	return []models.MerchantSummary{}, nil
}

// GetMerchant fetches a single merchant and their reviews.
func (s *BlockchainService) GetMerchant(merchantID string) (*models.MerchantDetails, error) {
	// TODO: Call chaincode to get a specific merchant and their reviews.
	fmt.Printf("Querying merchant %s and their reviews...\n", merchantID)
	return nil, nil
}

// CreateReview submits a new review to the blockchain.
func (s *BlockchainService) CreateReview(studentID string, review models.ReviewCreate) (string, error) {
	// 1. Convert the review object into a format suitable for signing (e.g., JSON bytes).
	// In a real app, you would define a canonical format for signing payloads.
	reviewBytes := []byte(fmt.Sprintf("%+v", review))

	// 2. Use the KeyStore to sign the review data.
	signature, err := s.keyStore.Sign(studentID, reviewBytes)
	if err != nil {
		return "", err
	}

	// 3. TODO: Call chaincode to submit the new review transaction,
	// including the review data and the signature.
	// The chaincode will then verify the signature using the author's public key
	// stored on the blockchain.
	fmt.Printf("Submitting new review for merchant %s, signed by user %s\n", review.MerchantID, studentID)
	fmt.Printf("Signature: %x\n", signature)

	// The chaincode would return a transaction ID.
	return "fake_tx_id", nil
}

// GetReviewsByUser fetches reviews by a specific user ID.
func (s *BlockchainService) GetReviewsByUser(userID string) ([]models.Review, error) {
	// TODO: Call chaincode to query reviews by the author's ID.
	fmt.Printf("Querying reviews by user %s\n", userID)
	return []models.Review{}, nil
}
