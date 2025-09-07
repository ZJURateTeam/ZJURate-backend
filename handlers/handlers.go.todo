// handlers/handlers.go
package handlers

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/ZJURateTeam/ZJURate-backend/models"
	"github.com/ZJURateTeam/ZJURate-backend/services"
	"golang.org/x/crypto/bcrypt"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// AuthHandler handles user authentication logic.
type AuthHandler struct {
	blockchainService *services.BlockchainService
	// 用于 JWT 签名的密钥
	jwtSecretKey []byte
}

func NewAuthHandler(bs *services.BlockchainService) *AuthHandler {
	secretKey := os.Getenv("JWT_SECRET_KEY")
	if secretKey == "" {
		secretKey = "supersecretjwtkeyforzjurate"
		fmt.Println("Warning: JWT_SECRET_KEY environment variable not set, using default key.")
	}
	return &AuthHandler{
		blockchainService: bs,
		jwtSecretKey:      []byte(secretKey),
	}
}

// generateToken generates a JWT for a user.
func (h *AuthHandler) generateToken(user models.User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"studentId": user.StudentID,
		"username":  user.Username,
		"exp":       time.Now().Add(time.Hour * 24).Unix(), // Token expires in 24 hours
	})
	return token.SignedString(h.jwtSecretKey)
}

// Register handles user registration.
func (h *AuthHandler) Register(c *gin.Context) {
	var user models.UserRegister
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid input"})
		return
	}

	// 1. Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to hash password"})
		return
	}

	user.Password = string(hashedPassword) // Store the hashed password

	// 2. Call blockchain service to register the user
	if err := h.blockchainService.RegisterUser(user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Registration failed", "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.Message{Message: "Register Successful"})
}

// Login handles user login and token generation.
func (h *AuthHandler) Login(c *gin.Context) {
	var login models.UserLogin
	if err := c.ShouldBindJSON(&login); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid input"})
		return
	}

	// 1. Call blockchain service to authenticate the user
	user, err := h.blockchainService.LoginUser(login)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Authentication failed", "error": err.Error()})
		return
	}

	// 2. Generate a JWT token
	tokenString, err := h.generateToken(*user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, models.Token{
		Token: tokenString,
		User:  *user,
	})
}

// GetMe retrieves the current logged-in user's info.
func (h *AuthHandler) GetMe(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
		return
	}
	c.JSON(http.StatusOK, user)
}

// MerchantsHandler handles merchant-related logic.
type MerchantsHandler struct {
	blockchainService *services.BlockchainService
}

func NewMerchantsHandler(bs *services.BlockchainService) *MerchantsHandler {
	return &MerchantsHandler{blockchainService: bs}
}

// ListMerchants fetches all merchants from the blockchain.
func (h *MerchantsHandler) ListMerchants(c *gin.Context) {
	// TODO: Call h.blockchainService.GetAllMerchants()
	c.JSON(http.StatusOK, []models.MerchantSummary{})
}

// GetMerchant fetches a single merchant and their reviews.
func (h *MerchantsHandler) GetMerchant(c *gin.Context) {
	id := c.Param("id")
	// TODO: Call h.blockchainService.GetMerchant(id)
	c.JSON(http.StatusOK, models.MerchantDetails{ID: id})
}

// CreateMerchant handles the creation of a new merchant.
func (h *MerchantsHandler) CreateMerchant(c *gin.Context) {
	// TODO: Add logic for creating a new merchant on the blockchain
	c.JSON(http.StatusOK, models.Message{Message: "Merchant creation submitted"})
}

// ReviewsHandler handles review-related logic.
type ReviewsHandler struct {
	blockchainService *services.BlockchainService
}

func NewReviewsHandler(bs *services.BlockchainService) *ReviewsHandler {
	return &ReviewsHandler{blockchainService: bs}
}

// CreateReview submits a new review to the blockchain.
func (h *ReviewsHandler) CreateReview(c *gin.Context) {
	var review models.ReviewCreate
	if err := c.ShouldBindJSON(&review); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid input"})
		return
	}

	// 从上下文中获取已认证的用户信息
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
		return
	}
	loggedInUser := user.(models.User)

	// 调用服务层，传入用户学号以进行签名
	txID, err := h.blockchainService.CreateReview(loggedInUser.StudentID, review)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to submit review", "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.TxResponse{
		Message: "Review submitted successfully, waiting for blockchain confirmation",
		TxID:    txID,
	})
}

// GetMyReviews fetches reviews written by the current user.
func (h *ReviewsHandler) GetMyReviews(c *gin.Context) {
	// TODO: Get user ID from context, call h.blockchainService.GetReviewsByUser(userID)
	c.JSON(http.StatusOK, []models.Review{})
}
