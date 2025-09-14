// main.go
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/ZJURateTeam/ZJURate-backend/handlers"
	"github.com/ZJURateTeam/ZJURate-backend/services"

	"github.com/gin-gonic/gin"
)

func main() {
	// NewBlockchainService 函数签名已修改，不再需要 keyStore 参数
	peers := []services.PeerEndpoint{
		{
			Address:            "localhost:7051",         // 你的 peer/gateway 入口
			ServerNameOverride: "peer0.org1.example.com", // 必须匹配该 peer TLS 证书的 CN/SAN
			TlsCACertPath:      "/home/kwanny/ZJURate-backend/wallet/org1/tlscacerts/tls-peer-ca.pem",
		},
	}
	caCfgPath := "/home/kwanny/ZJURate-backend/services/ca_config.json"
	blockchainService, err := services.NewBlockchainService(caCfgPath, peers)
	if err != nil {
		log.Fatalf("Failed to create blockchain service: %v", err)
	}
	defer blockchainService.Close()

	router := gin.Default()

	// CORS middleware
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusOK)
			return
		}
		c.Next()
	})

	// Inject the blockchain service into the handlers
	authHandler := handlers.NewAuthHandler(blockchainService)
	merchantsHandler := handlers.NewMerchantsHandler(blockchainService)
	reviewsHandler := handlers.NewReviewsHandler(blockchainService)
	uploadHandler := handlers.NewUploadHandler()

	// Root
	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ZJURate Backend API"})
	})

	api := router.Group("/api")
	{
		// Auth Routes
		auth := api.Group("/auth")
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
			auth.GET("/me", handlers.AuthMiddleware, authHandler.GetMe)
		}

		// Merchants Routes
		merchants := api.Group("/merchants")
		{
			merchants.GET("/", merchantsHandler.ListMerchants)
			merchants.GET("/:id", merchantsHandler.GetMerchant)
			merchants.POST("/", handlers.AuthMiddleware, merchantsHandler.CreateMerchant) // New endpoint
		}

		// Reviews Routes
		reviews := api.Group("/reviews")
		{
			reviews.POST("/", handlers.AuthMiddleware, reviewsHandler.CreateReview)
			reviews.GET("/my", handlers.AuthMiddleware, reviewsHandler.GetMyReviews)
		}

		// Upload Routes
		upload := api.Group("/upload")
		{
			upload.POST("/image", handlers.AuthMiddleware, uploadHandler.UploadImage)
		}
	}

	router.Static("/uploads", "./uploads")

	// 确保 'uploads' 目录存在
	if _, err := os.Stat("./uploads"); os.IsNotExist(err) {
		os.Mkdir("./uploads", 0755)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	router.Run(":" + port)
}
