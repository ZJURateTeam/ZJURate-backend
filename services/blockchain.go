// services/blockchain.go
package services

import (
	"fmt"
	"sync"
	"time"

	"github.com/ZJURateTeam/ZJURate-backend/models"
	"golang.org/x/crypto/bcrypt"
)

// BlockchainService manages interactions with a mock Hyperledger Fabric network.
// This mock implementation simulates the blockchain's ledger in memory.
type BlockchainService struct {
	keyStore  *KeyStore
	userStore *SQLiteKeyStore
	// In-memory ledgers to simulate blockchain state
	merchants map[string]models.MerchantDetails
	reviews   map[string]models.Review
	mu        sync.RWMutex // Mutex to protect concurrent access to the mock ledger
}

// NewBlockchainService creates a new instance of the mock blockchain service.
func NewBlockchainService(ks *KeyStore) (*BlockchainService, error) {
	fmt.Println("Mock Blockchain service initialized (simulating in-memory ledger)")
	userStore, err := NewSQLiteKeyStore("user.db")
	if err != nil {
		return nil, fmt.Errorf("failed to create user store: %w", err)
	}

	return &BlockchainService{
		keyStore:  ks,
		userStore: userStore,
		merchants: make(map[string]models.MerchantDetails),
		reviews:   make(map[string]models.Review),
		mu:        sync.RWMutex{},
	}, nil
}

// RegisterUser generates a key pair and records the public key in the mock ledger.
func (s *BlockchainService) RegisterUser(user models.UserRegister) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Save user data to the persistent store
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	if err := s.userStore.SaveUser(user.StudentID, user.Username, string(hashedPassword)); err != nil {
		return fmt.Errorf("failed to save user to store: %w", err)
	}

	// 2. Generate a key pair and store the private key securely.
	if _, err := s.keyStore.GenerateKeyPair(user.StudentID); err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	// 3. Simulate a blockchain transaction for user registration.
	// In a real scenario, this is where a Fabric SDK call would go.
	// We'll just print a confirmation for now.
	fmt.Printf("Mock Blockchain: Registered user %s. Public key would be submitted to ledger.\n", user.StudentID)

	return nil
}

// LoginUser authenticates a user.
func (s *BlockchainService) LoginUser(login models.UserLogin) (*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, err := s.userStore.GetUser(login.StudentID)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(login.Password)); err != nil {
		return nil, fmt.Errorf("invalid password")
	}

	fmt.Printf("Mock Blockchain: User %s authenticated successfully.\n", login.StudentID)
	return &models.User{StudentID: user.StudentID, Username: user.Username}, nil
}

// GetAllMerchants fetches all merchants from the mock ledger.
func (s *BlockchainService) GetAllMerchants() ([]models.MerchantSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	merchants := make([]models.MerchantSummary, 0, len(s.merchants))
	for _, m := range s.merchants {
		// Calculate average rating dynamically for the mock data
		var totalRating int
		var reviewCount int
		for _, r := range s.reviews {
			if r.MerchantID == m.ID {
				totalRating += r.Rating
				reviewCount++
			}
		}
		avgRating := 0.0
		if reviewCount > 0 {
			avgRating = float64(totalRating) / float64(reviewCount)
		}

		merchants = append(merchants, models.MerchantSummary{
			ID:            m.ID,
			Name:          m.Name,
			Category:      m.Category,
			AverageRating: avgRating,
		})
	}
	return merchants, nil
}

// GetMerchant fetches a single merchant and their reviews from the mock ledger.
func (s *BlockchainService) GetMerchant(merchantID string) (*models.MerchantDetails, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	merchant, ok := s.merchants[merchantID]
	if !ok {
		return nil, fmt.Errorf("merchant not found")
	}

	// Fetch all reviews for this merchant
	var reviews []models.Review
	var totalRating int
	var reviewCount int
	for _, r := range s.reviews {
		if r.MerchantID == merchantID {
			reviews = append(reviews, r)
			totalRating += r.Rating
			reviewCount++
		}
	}

	avgRating := 0.0
	if reviewCount > 0 {
		avgRating = float64(totalRating) / float64(reviewCount)
	}

	details := &models.MerchantDetails{
		ID:            merchant.ID,
		Name:          merchant.Name,
		Address:       merchant.Address,
		Category:      merchant.Category,
		AverageRating: avgRating,
		Reviews:       reviews,
	}
	return details, nil
}

// CreateMerchant simulates creating a new merchant on the mock ledger.
func (s *BlockchainService) CreateMerchant(studentID string, merchant models.MerchantDetails) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.merchants[merchant.ID]; exists {
		return "", fmt.Errorf("merchant with this ID already exists")
	}

	// Simulate signing the transaction payload.
	payload := fmt.Sprintf("%s-%s-%s", merchant.ID, merchant.Name, studentID)
	_, err := s.keyStore.Sign(studentID, []byte(payload))
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	// In a real scenario, chaincode would validate the signature and a unique ID.
	txID := fmt.Sprintf("mock_merchant_tx_%d", time.Now().UnixNano())

	// Add the merchant to our in-memory ledger
	s.merchants[merchant.ID] = merchant

	fmt.Printf("Mock Blockchain: New merchant '%s' created by user '%s' with txID %s.\n", merchant.Name, studentID, txID)
	return txID, nil
}

// CreateReview simulates submitting a new review to the mock ledger.
func (s *BlockchainService) CreateReview(studentID string, review models.ReviewCreate) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Simulate signing the transaction payload.
	payload := fmt.Sprintf("%s-%d-%s", review.MerchantID, review.Rating, studentID)
	_, err := s.keyStore.Sign(studentID, []byte(payload))
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	// In a real scenario, chaincode would create a unique ID.
	txID := fmt.Sprintf("mock_review_tx_%d", time.Now().UnixNano())

	newReview := models.Review{
		ID:         txID,
		MerchantID: review.MerchantID,
		AuthorID:   studentID,
		Rating:     review.Rating,
		Comment:    review.Comment,
		Timestamp:  time.Now().Format(time.RFC3339),
	}

	// Add the review to our in-memory ledger
	s.reviews[txID] = newReview

	fmt.Printf("Mock Blockchain: New review for merchant '%s' submitted by user '%s' with txID %s.\n", review.MerchantID, studentID, txID)
	return txID, nil
}

// GetReviewsByUser fetches reviews by a specific user ID from the mock ledger.
func (s *BlockchainService) GetReviewsByUser(userID string) ([]models.Review, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var userReviews []models.Review
	for _, r := range s.reviews {
		if r.AuthorID == userID {
			userReviews = append(userReviews, r)
		}
	}
	return userReviews, nil
}
