// handlers/handlers.go
package handlers

import (
	"net/http"
	"time"

	"github.com/ZJURateTeam/ZJURate-backend/models"
	"github.com/ZJURateTeam/ZJURate-backend/services"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// AuthHandler handles user authentication logic.
type AuthHandler struct {
	blockchainService *services.BlockchainService
	// 用于 JWT 签名的密钥
	jwtSecretKey []byte
}

// NewAuthHandler now takes the JWT secret key from the configuration.
func NewAuthHandler(bs *services.BlockchainService, jwtSecret string) *AuthHandler {
	return &AuthHandler{
		blockchainService: bs,
		jwtSecretKey:      []byte(jwtSecret),
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

	user, err := h.blockchainService.LoginUser(login)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Authentication failed", "error": err.Error()})
		return
	}

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
	merchants, err := h.blockchainService.GetAllMerchants()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to get merchants", "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, merchants)
}

// GetMerchant fetches a single merchant and their reviews.
func (h *MerchantsHandler) GetMerchant(c *gin.Context) {
	id := c.Param("id")
	merchant, err := h.blockchainService.GetMerchant(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "Merchant not found", "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, merchant)
}

// CreateMerchant handles the creation of a new merchant.
func (h *MerchantsHandler) CreateMerchant(c *gin.Context) {
	var merchant models.MerchantDetails
	if err := c.ShouldBindJSON(&merchant); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid input"})
		return
	}

	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
		return
	}
	loggedInUser := user.(models.User)

	txID, err := h.blockchainService.CreateMerchant(loggedInUser.StudentID, merchant)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to submit merchant creation", "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.TxResponse{
		Message: "Merchant creation submitted successfully",
		TxID:    txID,
	})
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
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
		return
	}
	loggedInUser := user.(models.User)

	reviews, err := h.blockchainService.GetReviewsByUser(loggedInUser.StudentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to get my reviews", "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, reviews)
}
