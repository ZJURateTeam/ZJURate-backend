package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
	"encoding/json"
	"strconv"
	"crypto/x509"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"github.com/hyperledger/fabric-gateway/pkg/hash"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// --- Models --- (保持原样)
type UserRegister struct {
	StudentID string `json:"studentId"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

type UserLogin struct {
	StudentID string `json:"studentId"`
	Password  string `json:"password"`
}

type User struct {
	StudentID string `json:"studentId"`
	Username  string `json:"username"`
}

type Token struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

type Review struct {
	ID         string `json:"id"`
	MerchantID string `json:"merchantId"`
	AuthorID   string `json:"authorId"`
	Rating     int    `json:"rating"`
	Comment    string `json:"comment"`
	Timestamp  string `json:"timestamp"`
}

type MerchantSummary struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	Category      string  `json:"category"`
	AverageRating float64 `json:"averageRating"`
}

type MerchantDetails struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Address       string   `json:"address"`
	Category      string   `json:"category"`
	AverageRating float64  `json:"averageRating"`
	Reviews       []Review `json:"reviews"`
}

type ReviewCreate struct {
	MerchantID string `json:"merchantId"`
	Rating     int    `json:"rating"`
	Comment    string `json:"comment"`
}

type Message struct {
	Message string `json:"message"`
}

type TxResponse struct {
	Message string `json:"message"`
	TxID    string `json:"txId"`
}

// --- Fake Data ---

var loggedInUser = User{StudentID: "3240100001", Username: "犬戎"}

// --- Fabric Gateway (新版 SDK 初始化) ---

var gateway *client.Gateway

func initGateway() error {
	clientConnection, err := newGrpcConnection()
	if err != nil {
		return fmt.Errorf("failed to create gRPC connection: %w", err)
	}

	id, err := newIdentity()
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}

	sign, err := newSign()
	if err != nil {
		return fmt.Errorf("failed to create sign: %w", err)
	}

	gateway, err = client.Connect(
		id,
		client.WithSign(sign),
		client.WithHash(hash.SHA256),
		client.WithClientConnection(clientConnection),
		client.WithEvaluateTimeout(5 * time.Second),
		client.WithEndorseTimeout(15 * time.Second),
		client.WithSubmitTimeout(5 * time.Second),
		client.WithCommitStatusTimeout(1 * time.Minute),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to gateway: %w", err)
	}

	return nil
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

// --- Main ---

func main() {
	err := initGateway()
	if err != nil {
		fmt.Printf("Gateway init failed: %v\n", err)
		os.Exit(1)
	}
	defer gateway.Close()

	router := gin.Default()

	// CORS middleware
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "*")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "*")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(200)
			return
		}
		c.Next()
	})

	// Root
	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ZJURate!"})
	})

	// Auth
	router.POST("/api/auth/register", func(c *gin.Context) {
		var user UserRegister
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid input"})
			return
		}
		time.Sleep(500 * time.Millisecond)
		fmt.Printf("Register: %s (%s)\n", user.Username, user.StudentID)
		c.JSON(http.StatusOK, Message{Message: "Register Successful"})
	})

	router.POST("/api/auth/login", func(c *gin.Context) {
		var login UserLogin
		if err := c.ShouldBindJSON(&login); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid input"})
			return
		}
		time.Sleep(500 * time.Millisecond)
		fmt.Printf("Login: %s\n", login.StudentID)
		if login.StudentID == "3240100001" {
			c.JSON(http.StatusOK, Token{
				Token: "fake.jwt.token.string.for.testing",
				User:  loggedInUser,
			})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"message": "Student ID or password incorrect"})
	})

	router.GET("/api/auth/me", func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		time.Sleep(200 * time.Millisecond)
		if auth == "Bearer fake.jwt.token.string.for.testing" {
			c.JSON(http.StatusOK, loggedInUser)
			return
		}
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized or token expired"})
	})

	// Merchants (使用新版 Contract)
	router.GET("/api/merchants", func(c *gin.Context) {
		network := gateway.GetNetwork("mychannel")
		contract := network.GetContract("reviews")

		result, err := contract.EvaluateTransaction("GetAllMerchants")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Query failed: " + err.Error()})
			return
		}

		var merchants []MerchantSummary
		err = json.Unmarshal(result, &merchants)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Unmarshal failed"})
			return
		}

		// 可选: 计算 AverageRating
		for i := range merchants {
			reviewsResult, _ := contract.EvaluateTransaction("GetReviewsByMerchant", merchants[i].ID)
			var reviews []Review
			json.Unmarshal(reviewsResult, &reviews)
			if len(reviews) > 0 {
				total := 0
				for _, r := range reviews {
					total += r.Rating
				}
				merchants[i].AverageRating = float64(total) / float64(len(reviews))
			}
		}
		c.JSON(http.StatusOK, merchants)
	})

	router.GET("/api/merchants/:id", func(c *gin.Context) {
		id := c.Param("id")

		network := gateway.GetNetwork("mychannel")
		contract := network.GetContract("reviews")

		merchantResult, err := contract.EvaluateTransaction("GetMerchantByID", id)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"message": "Merchant not found: " + err.Error()})
			return
		}

		var merchant MerchantDetails
		err = json.Unmarshal(merchantResult, &merchant)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Unmarshal failed"})
			return
		}

		reviewsResult, err := contract.EvaluateTransaction("GetReviewsByMerchant", id)
		if err == nil {
			var reviews []Review
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

		c.JSON(http.StatusOK, merchant)
	})
	
	// Reviews
	router.POST("/api/reviews", func(c *gin.Context) {
		var review ReviewCreate
		auth := c.GetHeader("Authorization")
		if auth != "Bearer fake.jwt.token.string.for.testing" {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
			return
		}
		if err := c.ShouldBindJSON(&review); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid input"})
			return
		}

		network := gateway.GetNetwork("mychannel")
		contract := network.GetContract("reviews")

		txID, err := contract.SubmitTransaction("CreateReview", review.MerchantID, strconv.Itoa(review.Rating), review.Comment)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Submit failed: " + err.Error()})
			return
		}

		c.JSON(http.StatusOK, TxResponse{
			Message: "Review submitted successfully, waiting for blockchain confirmation",
			TxID:    string(txID),
		})
	})

	router.GET("/api/reviews/my", func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if auth != "Bearer fake.jwt.token.string.for.testing" {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
			return
		}

		// 假设从 token 或上下文获取 authorID
		authorID := loggedInUser.StudentID  // 替换为真实获取

		network := gateway.GetNetwork("mychannel")
		contract := network.GetContract("reviews")

		result, err := contract.EvaluateTransaction("GetReviewsByAuthor", authorID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Query failed: " + err.Error()})
			return
		}

		var myReviews []Review
		err = json.Unmarshal(result, &myReviews)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Unmarshal failed"})
			return
		}
		c.JSON(http.StatusOK, myReviews)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	router.Run(":" + port)
}