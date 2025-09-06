// handlers/upload.go
package handlers

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"time"

	"github.com/ZJURateTeam/ZJURate-backend/models"

	"github.com/gin-gonic/gin"
)

// UploadHandler handles file upload logic.
type UploadHandler struct {
	// A service might be injected here for more complex logic,
	// but for now, we'll keep it simple.
}

func NewUploadHandler() *UploadHandler {
	return &UploadHandler{}
}

// UploadImage handles the image upload and returns its hash and path.
func (h *UploadHandler) UploadImage(c *gin.Context) {
	// 验证用户身份，从 context 中获取用户信息
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "User not authenticated"})
		return
	}
	loggedInUser := user.(models.User)

	// 获取文件
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "No file is received"})
		return
	}

	// 打开文件
	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to open file"})
		return
	}
	defer src.Close()

	// 计算文件哈希
	hash := sha256.New()
	if _, err := io.Copy(hash, src); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to calculate file hash"})
		return
	}
	imageHash := fmt.Sprintf("%x", hash.Sum(nil))

	// 重置文件读取位置，以便后续保存
	src.Seek(0, 0)

	// 定义文件存储路径
	// 实际项目中应使用更健壮的存储方案，如云存储
	// 这里我们使用一个简单的本地文件路径
	filename := fmt.Sprintf("%s_%s%s", loggedInUser.StudentID, time.Now().Format("20060102150405"), filepath.Ext(file.Filename))
	dst := fmt.Sprintf("uploads/%s", filename)

	// 保存文件到本地
	if err := c.SaveUploadedFile(file, dst); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to save file"})
		return
	}

	// 在生产环境中，你会将图片上传到云存储，然后只返回一个 URL
	imageURL := "/uploads/" + filename

	c.JSON(http.StatusOK, gin.H{
		"message":   "Image uploaded successfully",
		"uploader":  loggedInUser,
		"imageHash": imageHash,
		"imageURL":  imageURL,
	})
}
