package review

// Merchant 结构体：商户信息（基于 MerchantDetails）
type Merchant struct {
    ID       string `json:"id"`
    Name     string `json:"name"`
    Address  string `json:"address"`
    Category string `json:"category"`
}

// User 结构体：用户信息（基于 User）
type User struct {
    StudentID string `json:"studentId"`
    Username  string `json:"username"`
    PublicKey string `json:"publicKey"`  // 新增：PEM 格式公钥
}

// Review 结构体：评论信息
type Review struct {
    ID         string `json:"id"`
    MerchantID string `json:"merchantId"`
    AuthorID   string `json:"authorId"`
    Rating     int    `json:"rating"`
    Comment    string `json:"comment"`
    Timestamp  string `json:"timestamp"`
}