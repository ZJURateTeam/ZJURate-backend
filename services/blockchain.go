package services

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/ZJURateTeam/ZJURate-backend/models"
	calib "github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
)

// BlockchainService manages interactions with the Hyperledger Fabric network.
// 暂时考虑单 org
type BlockchainService struct {
	userStore *SQLiteKeyStore

	caCfg   CAConfig
	caAdmin *calib.Client

	conns   map[string]*grpc.ClientConn // 多 peer 连接池（可只配一个）
	primary string                      // 首选 peer 地址

	mu sync.RWMutex
}

// PeerEndpoint `yaml` tag is added for go-yaml unmarshalling.
type PeerEndpoint struct {
	Address            string `yaml:"address"`
	ServerNameOverride string `yaml:"serverNameOverride"`
	TlsCACertPath      string `yaml:"tlsCACertPath"`
}

// NewBlockchainService creates a new instance of the blockchain service.
// 移除了 keyStore 参数，并直接接收 CAConfig 结构体
func NewBlockchainService(caCfg CAConfig, peers []PeerEndpoint) (*BlockchainService, error) {
	userStore, err := NewSQLiteKeyStore("user.db")
	if err != nil {
		return nil, fmt.Errorf("failed to create user store: %w", err)
	}

	// Initialize Fabric gateway connection
	conns := make(map[string]*grpc.ClientConn)
	for _, p := range peers {
		conn, err := newGrpcConnection(p.Address, p.ServerNameOverride, p.TlsCACertPath)
		if err != nil {
			return nil, fmt.Errorf("dial %s: %w", p.Address, err)
		}
		conns[p.Address] = conn
	}
	if len(conns) == 0 {
		return nil, fmt.Errorf("no peer connections")
	}
	primary := peers[0].Address

	if err := os.MkdirAll(caCfg.HomeDir, 0o755); err != nil {
		for _, c := range conns {
			_ = c.Close()
		}
		return nil, fmt.Errorf("prepare registrar home: %w", err)
	}
	caAdmin, err := NewRegistrarClient(caCfg)
	if err != nil {
		for _, c := range conns {
			_ = c.Close()
		}
		return nil, fmt.Errorf("new registrar: %w", err)
	}

	return &BlockchainService{
		userStore: userStore,
		caCfg:     caCfg,
		caAdmin:   caAdmin,
		conns:     conns,
		primary:   primary,
		mu:        sync.RWMutex{},
	}, nil
}

// Close closes the gateway connection.
func (s *BlockchainService) Close() {
	if s.userStore != nil {
		s.userStore.Close()
	}
	for _, c := range s.conns {
		c.Close()
	}
}

// RegisterUser generates a key pair and records the user in the ledger.
func (s *BlockchainService) RegisterUser(user models.UserRegister) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	if err := s.userStore.SaveUser(user.StudentID, user.Username, string(hashedPassword)); err != nil {
		return fmt.Errorf("failed to save user to store: %w", err)
	}

	if err := s.ensureUserEnrolled(user.StudentID); err != nil {
		return fmt.Errorf("issue cert: %w", err)
	}

	return s.withUserGateway(user.StudentID, "Org1MSP", func(gw *client.Gateway) error {
		fmt.Println("entering createuser with chain")
		network := gw.GetNetwork("mychannel")
		contract := network.GetContract("review")
		if _, err := contract.SubmitTransaction("CreateUser", user.StudentID, user.Username); err != nil {
			return fmt.Errorf("failed to create user on blockchain: %w", err)
		}
		fmt.Printf("Blockchain: Registered user %s (own cert) & submitted to ledger.\n", user.StudentID)
		return nil
	})
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

	if _, err := os.Stat(filepath.Join(s.caCfg.HomeDir, login.StudentID, "msp", "signcerts", "cert.pem")); err != nil {
		return nil, fmt.Errorf("no enrollment; please re-register")
	}

	if err := s.withUserGateway(login.StudentID, "Org1MSP", func(gw *client.Gateway) error {
		network := gw.GetNetwork("mychannel")
		contract := network.GetContract("review")
		_, e := contract.EvaluateTransaction("GetUserByID", login.StudentID)
		return e
	}); err != nil {
		return nil, fmt.Errorf("user not found on blockchain: %w", err)
	}

	fmt.Printf("Blockchain: User %s authenticated successfully.\n", login.StudentID)
	return &models.User{StudentID: user.StudentID, Username: user.Username}, nil
}

// GetAllMerchants fetches all merchants from the ledger.
func (s *BlockchainService) GetAllMerchants() ([]models.MerchantSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := s.ensureUserEnrolled("reader"); err != nil {
		return nil, fmt.Errorf("ensure reader enrolled: %w", err)
	}

	var merchants []models.MerchantSummary
	err := s.withUserGateway("reader", "Org1MSP", func(gw *client.Gateway) error {
		network := gw.GetNetwork("mychannel")
		contract := network.GetContract("review")

		result, err := contract.EvaluateTransaction("GetAllMerchants")
		if err != nil {
			return err
		}
		fmt.Println("Raw result:", string(result))

		if err := json.Unmarshal(result, &merchants); err != nil {
			return err
		}

		for i := range merchants {
			reviewsResult, e := contract.EvaluateTransaction("GetReviewsByMerchant", merchants[i].ID)
			if e == nil {
				var reviews []models.Review
				_ = json.Unmarshal(reviewsResult, &reviews)
				if len(reviews) > 0 {
					total := 0
					for _, r := range reviews {
						total += r.Rating
					}
					merchants[i].AverageRating = float64(total) / float64(len(reviews))
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return merchants, nil
}

// GetMerchant fetches a single merchant and their reviews from the ledger.
func (s *BlockchainService) GetMerchant(merchantID string) (*models.MerchantDetails, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := s.ensureUserEnrolled("reader"); err != nil {
		return nil, fmt.Errorf("ensure reader enrolled: %w", err)
	}

	var merchant models.MerchantDetails
	err := s.withUserGateway("reader", "Org1MSP", func(gw *client.Gateway) error {
		network := gw.GetNetwork("mychannel")
		contract := network.GetContract("review")

		merchantResult, err := contract.EvaluateTransaction("GetMerchantByID", merchantID)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(merchantResult, &merchant); err != nil {
			return err
		}

		reviewsResult, err := contract.EvaluateTransaction("GetReviewsByMerchant", merchantID)
		if err == nil {
			var reviews []models.Review
			_ = json.Unmarshal(reviewsResult, &reviews)
			merchant.Reviews = reviews
			if len(reviews) > 0 {
				total := 0
				for _, r := range reviews {
					total += r.Rating
				}
				merchant.AverageRating = float64(total) / float64(len(reviews))
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &merchant, nil
}

// CreateMerchant submits a new merchant to the ledger.
func (s *BlockchainService) CreateMerchant(studentID string, merchant models.MerchantDetails) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var txID string
	err := s.withUserGateway(studentID, "Org1MSP", func(gw *client.Gateway) error {
		network := gw.GetNetwork("mychannel")
		contract := network.GetContract("review")
		b, e := contract.SubmitTransaction("CreateMerchant", merchant.ID, merchant.Name, merchant.Address, merchant.Category)
		if e != nil {
			return e
		}
		txID = string(b)
		return nil
	})
	if err != nil {
		return "", err
	}

	fmt.Printf("Blockchain: New merchant '%s' created by user '%s' with txID %s.\n", merchant.Name, studentID, txID)
	return txID, nil
}

// CreateReview submits a new review to the ledger.
func (s *BlockchainService) CreateReview(studentID string, review models.ReviewCreate) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var txID string
	err := s.withUserGateway(studentID, "Org1MSP", func(gw *client.Gateway) error {
		network := gw.GetNetwork("mychannel")
		contract := network.GetContract("review")
		b, e := contract.SubmitTransaction("CreateReview", review.MerchantID, studentID, strconv.Itoa(review.Rating), review.Comment)
		if e != nil {
			return e
		}
		txID = string(b)
		return nil
	})
	if err != nil {
		return "", err
	}

	fmt.Printf("Blockchain: New review for merchant '%s' submitted by user '%s' with txID %s.\n", review.MerchantID, studentID, txID)
	return txID, nil
}

// GetReviewsByUser fetches reviews by a specific user ID from the ledger.
func (s *BlockchainService) GetReviewsByUser(userID string) ([]models.Review, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := s.ensureUserEnrolled("reader"); err != nil {
		return nil, fmt.Errorf("ensure reader enrolled: %w", err)
	}

	var reviews []models.Review
	err := s.withUserGateway("reader", "Org1MSP", func(gw *client.Gateway) error {
		network := gw.GetNetwork("mychannel")
		contract := network.GetContract("review")

		result, err := contract.EvaluateTransaction("GetReviewsByAuthor", userID)
		if err != nil {
			return err
		}
		return json.Unmarshal(result, &reviews)
	})
	if err != nil {
		return nil, err
	}
	return reviews, nil
}
