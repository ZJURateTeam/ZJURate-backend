package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

// --- Models ---

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

var fakeReviews = []Review{
	{"REV5001", "MER001", "3240100008", 5, "好吃！就是人有点多。", time.Now().Format(time.RFC3339)},
	{"REV5002", "MER001", "3240100015", 4, "价格实惠，分量足。", time.Now().Format(time.RFC3339)},
	{"REV5003", "MER002", "3240100008", 5, "打印速度超快，老板人很好。", time.Now().Format(time.RFC3339)},
	{"REV5003", "MER002", "3240100009", 1, "全价四万了盗我整理的讲义卖", time.Now().Format(time.RFC3339)},
	{"REV5004", "MER003", "3240100001", 3, "东西还行，就是有点贵。", time.Now().Format(time.RFC3339)},
}

var fakeMerchantsDetails = []MerchantDetails{
	{"MER001", "银泉食堂", "北教旁边", "餐饮", 4.5, filterReviews("MER001")},
	{"MER002", "蓝田文印店", "蓝田大门西侧50米", "打印", 3.0, filterReviews("MER002")},
	{"MER003", "启真教育超市", "白沙1幢楼下", "超市", 3.0, filterReviews("MER003")},
}

var fakeMerchantsSummary = []MerchantSummary{
	{"MER001", "银泉食堂", "餐饮", 4.5},
	{"MER002", "蓝田文印店", "打印", 3.0},
	{"MER003", "启真教育超市", "超市", 3.0},
}

// --- Helper Functions ---

func filterReviews(merchantID string) []Review {
	result := []Review{}
	for _, r := range fakeReviews {
		if r.MerchantID == merchantID {
			result = append(result, r)
		}
	}
	return result
}

// --- Main ---

func main() {
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

	// Merchants
	router.GET("/api/merchants", func(c *gin.Context) {
		c.JSON(http.StatusOK, fakeMerchantsSummary)
	})

	router.GET("/api/merchants/:id", func(c *gin.Context) {
		id := c.Param("id")
		for _, m := range fakeMerchantsDetails {
			if m.ID == id {
				c.JSON(http.StatusOK, m)
				return
			}
		}
		c.JSON(http.StatusNotFound, gin.H{"message": "Merchant not found"})
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
		fmt.Printf("Simulate creating review: %+v\n", review)
		c.JSON(http.StatusOK, TxResponse{
			Message: "Review submitted successfully, waiting for blockchain confirmation",
			TxID:    "fake_tx_id_" + time.Now().Format("20060102150405"),
		})
	})

	router.GET("/api/reviews/my", func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if auth != "Bearer fake.jwt.token.string.for.testing" {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
			return
		}
		myReviews := []Review{}
		for _, r := range fakeReviews {
			if r.AuthorID == loggedInUser.StudentID {
				myReviews = append(myReviews, r)
			}
		}
		c.JSON(http.StatusOK, myReviews)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	router.Run(":" + port)
}
