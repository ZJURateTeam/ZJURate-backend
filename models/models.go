// models/models.go
package models

// --- Auth Models ---

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

// --- Merchant Models ---

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

// --- Review Models ---

type Review struct {
	ID         string `json:"id"`
	MerchantID string `json:"merchantId"`
	AuthorID   string `json:"authorId"`
	Rating     int    `json:"rating"`
	Comment    string `json:"comment"`
	Timestamp  string `json:"timestamp"`
}

type ReviewCreate struct {
	MerchantID string `json:"merchantId"`
	Rating     int    `json:"rating"`
	Comment    string `json:"comment"`
	// For image, you would handle a file upload separately and just store the hash here.
	ImageHash string `json:"imageHash,omitempty"`
}

// --- General API Models ---

type Message struct {
	Message string `json:"message"`
}

type TxResponse struct {
	Message string `json:"message"`
	TxID    string `json:"txId"`
}

// UploadedImage represents a successfully uploaded image.
type UploadedImage struct {
	ImageHash string `json:"imageHash"`
	ImageURL  string `json:"imageURL"`
	Uploader  User   `json:"uploader"`
}
