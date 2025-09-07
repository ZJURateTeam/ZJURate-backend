// services/blockchain.go
package services

import (
    "crypto/x509"
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "strconv"
    "sync"
    "time"

    "github.com/ZJURateTeam/ZJURate-backend/models"
    "golang.org/x/crypto/bcrypt"
    "github.com/hyperledger/fabric-gateway/pkg/client"
    "github.com/hyperledger/fabric-gateway/pkg/identity"
    "github.com/hyperledger/fabric-gateway/pkg/hash"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
)

// BlockchainService manages interactions with the Hyperledger Fabric network.
// This implementation uses the real Fabric gateway instead of mock in-memory ledger but without auth logic
type BlockchainService struct {
    keyStore  *KeyStore
    userStore *SQLiteKeyStore  // For local password storage
    gateway   *client.Gateway   // Real Fabric gateway connection
    mu        sync.RWMutex      // Mutex to protect concurrent access
}

// NewBlockchainService creates a new instance of the blockchain service.
func NewBlockchainService(ks *KeyStore) (*BlockchainService, error) {
    fmt.Println("Blockchain service initialized with real Fabric gateway")
    userStore, err := NewSQLiteKeyStore("user.db")
    if err != nil {
        return nil, fmt.Errorf("failed to create user store: %w", err)
    }

    // Initialize Fabric gateway connection
    clientConnection, err := newGrpcConnection()
    if err != nil {
        return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
    }

    id, err := newIdentity()
    if err != nil {
        return nil, fmt.Errorf("failed to create identity: %w", err)
    }

    sign, err := newSign()
    if err != nil {
        return nil, fmt.Errorf("failed to create sign: %w", err)
    }

    gw, err := client.Connect(
        id,
        client.WithSign(sign),
        client.WithHash(hash.SHA256),
        client.WithClientConnection(clientConnection),
        client.WithEvaluateTimeout(5*time.Second),
        client.WithEndorseTimeout(15*time.Second),
        client.WithSubmitTimeout(5*time.Second),
        client.WithCommitStatusTimeout(1*time.Minute),
    )
    if err != nil {
        return nil, fmt.Errorf("failed to connect to gateway: %w", err)
    }

    return &BlockchainService{
        keyStore:  ks,
        userStore: userStore,
        gateway:   gw,
        mu:        sync.RWMutex{},
    }, nil
}

// RegisterUser generates a key pair and records the user in the ledger.
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

    // 3. Submit user registration to the real blockchain ledger.
    network := s.gateway.GetNetwork("mychannel")
    contract := network.GetContract("review")
    _, err = contract.SubmitTransaction("CreateUser", user.StudentID, user.Username)
    if err != nil {
        return fmt.Errorf("failed to create user on blockchain: %w", err)
    }

    fmt.Printf("Blockchain: Registered user %s. Submitted to ledger.\n", user.StudentID)
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

    // Verify user existence on blockchain
    network := s.gateway.GetNetwork("mychannel")
    contract := network.GetContract("review")
    _, err = contract.EvaluateTransaction("GetUserByID", login.StudentID)
    if err != nil {
        return nil, fmt.Errorf("user not found on blockchain: %w", err)
    }

    fmt.Printf("Blockchain: User %s authenticated successfully.\n", login.StudentID)
    return &models.User{StudentID: user.StudentID, Username: user.Username}, nil
}

// GetAllMerchants fetches all merchants from the ledger.
func (s *BlockchainService) GetAllMerchants() ([]models.MerchantSummary, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    network := s.gateway.GetNetwork("mychannel")
    contract := network.GetContract("review")

    result, err := contract.EvaluateTransaction("GetAllMerchants")
    if err != nil {
        return nil, err
    }
	fmt.Println("Raw result:", string(result))

    var merchants []models.MerchantSummary
    err = json.Unmarshal(result, &merchants)
    if err != nil {
        return nil, err
    }

    // Calculate average rating dynamically
    for i := range merchants {
        reviewsResult, err := contract.EvaluateTransaction("GetReviewsByMerchant", merchants[i].ID)
        if err == nil {
            var reviews []models.Review
            json.Unmarshal(reviewsResult, &reviews)
            if len(reviews) > 0 {
                total := 0
                for _, r := range reviews {
                    total += r.Rating
                }
                merchants[i].AverageRating = float64(total) / float64(len(reviews))
            }
        }
    }
    return merchants, nil
}

// GetMerchant fetches a single merchant and their reviews from the ledger.
func (s *BlockchainService) GetMerchant(merchantID string) (*models.MerchantDetails, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    network := s.gateway.GetNetwork("mychannel")
    contract := network.GetContract("review")

    merchantResult, err := contract.EvaluateTransaction("GetMerchantByID", merchantID)
    if err != nil {
        return nil, err
    }

    var merchant models.MerchantDetails
    err = json.Unmarshal(merchantResult, &merchant)
    if err != nil {
        return nil, err
    }

    reviewsResult, err := contract.EvaluateTransaction("GetReviewsByMerchant", merchantID)
    if err == nil {
        var reviews []models.Review
        json.Unmarshal(reviewsResult, &reviews)
        merchant.Reviews = reviews
        if len(reviews) > 0 {
            total := 0
            for _, r := range reviews {
                total += r.Rating
            }
            merchant.AverageRating = float64(total) / float64(len(reviews))
        }
    }

    return &merchant, nil
}

// CreateMerchant submits a new merchant to the ledger.
func (s *BlockchainService) CreateMerchant(studentID string, merchant models.MerchantDetails) (string, error) {
    s.mu.Lock()
    defer s.mu.Unlock()

    // Simulate signing the transaction payload.
    payload := fmt.Sprintf("%s-%s-%s", merchant.ID, merchant.Name, studentID)
    _, err := s.keyStore.Sign(studentID, []byte(payload))
    if err != nil {
        return "", fmt.Errorf("failed to sign transaction: %w", err)
    }

    // Submit to real blockchain
    network := s.gateway.GetNetwork("mychannel")
    contract := network.GetContract("review")
    txIDBytes, err := contract.SubmitTransaction("CreateMerchant", merchant.ID, merchant.Name, merchant.Address, merchant.Category)
    if err != nil {
        return "", err
    }
    txID := string(txIDBytes)

    fmt.Printf("Blockchain: New merchant '%s' created by user '%s' with txID %s.\n", merchant.Name, studentID, txID)
    return txID, nil
}

// CreateReview submits a new review to the ledger.
func (s *BlockchainService) CreateReview(studentID string, review models.ReviewCreate) (string, error) {
    s.mu.Lock()
    defer s.mu.Unlock()

    // Simulate signing the transaction payload.
    payload := fmt.Sprintf("%s-%d-%s", review.MerchantID, review.Rating, studentID)
    _, err := s.keyStore.Sign(studentID, []byte(payload))
    if err != nil {
        return "", fmt.Errorf("failed to sign transaction: %w", err)
    }

    // Submit to real blockchain
    network := s.gateway.GetNetwork("mychannel")
    contract := network.GetContract("review")
    txIDBytes, err := contract.SubmitTransaction("CreateReview", review.MerchantID, studentID, strconv.Itoa(review.Rating), review.Comment)
    if err != nil {
        return "", err
    }
    txID := string(txIDBytes)

    fmt.Printf("Blockchain: New review for merchant '%s' submitted by user '%s' with txID %s.\n", review.MerchantID, studentID, txID)
    return txID, nil
}

// GetReviewsByUser fetches reviews by a specific user ID from the ledger.
func (s *BlockchainService) GetReviewsByUser(userID string) ([]models.Review, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    network := s.gateway.GetNetwork("mychannel")
    contract := network.GetContract("review")

    result, err := contract.EvaluateTransaction("GetReviewsByAuthor", userID)
    if err != nil {
        return nil, err
    }

    var reviews []models.Review
    err = json.Unmarshal(result, &reviews)
    if err != nil {
        return nil, err
    }
    return reviews, nil
}

// Close closes the gateway connection.
func (s *BlockchainService) Close() {
    if s.gateway != nil {
        s.gateway.Close()
    }
}

// newGrpcConnection creates a gRPC connection to the Gateway server.
func newGrpcConnection() (*grpc.ClientConn, error) {
    certPath := filepath.Join("wallet", "appUser", "tlscacerts", "tls-ca-cert.pem")  // 调整为您的 TLS CA 路径
    certificatePEM, err := os.ReadFile(certPath)
    if err != nil {
        return nil, fmt.Errorf("failed to read TLS certificate: %w", err)
    }

    certificate, err := identity.CertificateFromPEM(certificatePEM)
    if err != nil {
        return nil, err
    }

    certPool := x509.NewCertPool()
    certPool.AddCert(certificate)
    transportCredentials := credentials.NewClientTLSFromCert(certPool, "localhost")  // 调整 gateway host 如果非 localhost

    connection, err := grpc.Dial("localhost:7051", grpc.WithTransportCredentials(transportCredentials))  // 调整 peer endpoint
    if err != nil {
        return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
    }

    return connection, nil
}

// newIdentity creates a client identity using an X.509 certificate.
func newIdentity() (*identity.X509Identity, error) {
    certPath := filepath.Join("wallet", "appUser", "signcerts", "cert.pem")  // 调整为您的 cert 路径
    certificatePEM, err := os.ReadFile(certPath)
    if err != nil {
        return nil, fmt.Errorf("failed to read certificate: %w", err)
    }

    certificate, err := identity.CertificateFromPEM(certificatePEM)
    if err != nil {
        return nil, err
    }

    id, err := identity.NewX509Identity("Org1MSP", certificate)  // MSP ID 调整为您的组织
    if err != nil {
        return nil, err
    }

    return id, nil
}

// newSign creates a function that generates a digital signature from a message digest using a private key.
func newSign() (identity.Sign, error) {
    keyPath := filepath.Join("wallet", "appUser", "keystore", "priv_sk")  // 调整为您的私钥路径
    privateKeyPEM, err := os.ReadFile(keyPath)
    if err != nil {
        return nil, fmt.Errorf("failed to read private key: %w", err)
    }

    privateKey, err := identity.PrivateKeyFromPEM(privateKeyPEM)
    if err != nil {
        return nil, err
    }

    sign, err := identity.NewPrivateKeySign(privateKey)
    if err != nil {
        return nil, err
    }

    return sign, nil
}