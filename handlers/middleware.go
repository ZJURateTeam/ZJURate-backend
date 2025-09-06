// handlers/middleware.go
package handlers

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/ZJURateTeam/ZJURate-backend/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// AuthMiddleware is a placeholder for real JWT token validation.
func AuthMiddleware(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Authorization header is required"})
		c.Abort()
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader { // 如果没有 "Bearer " 前缀
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token format, expected 'Bearer <token>'"})
		c.Abort()
		return
	}

	secretKey := os.Getenv("JWT_SECRET_KEY")
	if secretKey == "" {
		secretKey = "supersecretjwtkeyforzjurate" // 确保与 AuthHandler 中的密钥一致
	}

	// 解析和验证 token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secretKey), nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid or expired token", "error": err.Error()})
		c.Abort()
		return
	}

	// 从 claims 中提取用户信息
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token claims"})
		c.Abort()
		return
	}

	// 将用户信息设置到 context 中
	studentID, ok := claims["studentId"].(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Token does not contain student ID"})
		c.Abort()
		return
	}

	username, _ := claims["username"].(string)

	c.Set("user", models.User{StudentID: studentID, Username: username})
	c.Next()
}
