package main

import (
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/ZJURateTeam/ZJURate-backend/handlers"
	"github.com/ZJURateTeam/ZJURate-backend/services"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v2"
)

// Config holds all application configurations.
type Config struct {
	App struct {
		Port int `yaml:"port"`
	} `yaml:"app"`
	Fabric struct {
		CA struct {
			URL       string `yaml:"url"`
			CAName    string `yaml:"caName"`
			TLSCACert string `yaml:"tlsCACert"`
		} `yaml:"ca"`
		Client struct {
			HomeDir string `yaml:"homeDir"`
			MSPDir  string `yaml:"mspDir"`
		} `yaml:"client"`
		Registrar struct {
			ID     string `yaml:"id"`
			Secret string `yaml:"secret"`
		} `yaml:"registrar"`
		Peers []services.PeerEndpoint `yaml:"peers"`
	} `yaml:"fabric"`
	JWT struct {
		SecretKey string `yaml:"secretKey"`
	} `yaml:"jwt"`
}

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "config.yml", "Path to the configuration file")
	flag.Parse()

	configFile, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Fatalf("Fatal error reading config file '%s': %s", configPath, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(configFile, &cfg); err != nil {
		log.Fatalf("Fatal error unmarshalling config: %s", err)
	}

	caConfig := services.CAConfig{
		URL:             cfg.Fabric.CA.URL,
		CAName:          cfg.Fabric.CA.CAName,
		TLSCACert:       cfg.Fabric.CA.TLSCACert,
		HomeDir:         cfg.Fabric.Client.HomeDir,
		RegistrarID:     cfg.Fabric.Registrar.ID,
		RegistrarSecret: cfg.Fabric.Registrar.Secret,
	}

	blockchainService, err := services.NewBlockchainService(caConfig, cfg.Fabric.Peers)
	if err != nil {
		log.Fatalf("Failed to create blockchain service: %v", err)
	}
	defer blockchainService.Close()

	router := gin.Default()

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

	authHandler := handlers.NewAuthHandler(blockchainService, cfg.JWT.SecretKey)
	merchantsHandler := handlers.NewMerchantsHandler(blockchainService)
	reviewsHandler := handlers.NewReviewsHandler(blockchainService)
	uploadHandler := handlers.NewUploadHandler()

	authMiddleware := handlers.AuthMiddleware(cfg.JWT.SecretKey)

	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ZJURate Backend API"})
	})

	api := router.Group("/api")
	{
		auth := api.Group("/auth")
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
			auth.GET("/me", authMiddleware, authHandler.GetMe)
		}

		merchants := api.Group("/merchants")
		{
			merchants.GET("/", merchantsHandler.ListMerchants)
			merchants.GET("/:id", merchantsHandler.GetMerchant)
			merchants.POST("/", authMiddleware, merchantsHandler.CreateMerchant)
		}

		reviews := api.Group("/reviews")
		{
			reviews.POST("/", authMiddleware, reviewsHandler.CreateReview)
			reviews.GET("/my", authMiddleware, reviewsHandler.GetMyReviews)
		}

		upload := api.Group("/upload")
		{
			upload.POST("/image", authMiddleware, uploadHandler.UploadImage)
		}
	}

	router.Static("/uploads", "./uploads")
	if _, err := os.Stat("./uploads"); os.IsNotExist(err) {
		os.Mkdir("./uploads", 0755)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = strconv.Itoa(cfg.App.Port)
	}
	router.Run(":" + port)
}
