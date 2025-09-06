// handlers/middleware.go
package handlers

import (
	"net/http"
	"strings"

	"github.com/ZJURateTeam/ZJURate-backend/models"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware is a placeholder for real JWT token validation.
func AuthMiddleware(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Authorization header is required"})
		c.Abort()
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" || token != "fake.jwt.token.string.for.testing" {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid or expired token"})
		c.Abort()
		return
	}

	// In a real application, you would validate the JWT and get the user info.
	// For this example, we'll just set a fake user in the context.
	c.Set("user", models.User{StudentID: "3240100001", Username: "犬戎"})
	c.Next()
}
