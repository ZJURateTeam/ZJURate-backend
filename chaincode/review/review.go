package review

import (
    "encoding/json"
    "fmt"
    "time"

    "github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// createReviewInternal：内部创建函数，用于初始化（不验证身份）
func (s *ReviewContract) createReviewInternal(ctx contractapi.TransactionContextInterface, id string, merchantID string, authorID string, rating int, comment string, timestamp string) error {
    // 复合键：用于 merchant 查询和 author 查询
    merchantKey, err := ctx.GetStub().CreateCompositeKey("review~merchant", []string{merchantID, id})
    if err != nil {
        return err
    }
    authorKey, err := ctx.GetStub().CreateCompositeKey("review~author", []string{authorID, id})
    if err != nil {
        return err
    }

    // 检查是否存在
    existing, err := ctx.GetStub().GetState(merchantKey)
    if err != nil || existing != nil {
        return fmt.Errorf("review %s already exists or error", id)
    }

    review := Review{
        ID:         id,
        MerchantID: merchantID,
        AuthorID:   authorID,
        Rating:     rating,
        Comment:    comment,
        Timestamp:  timestamp,
    }

    reviewJSON, err := json.Marshal(review)
    if err != nil {
        return err
    }

    // 存储到 ledger：使用 merchantKey 作为主键，也存储 authorKey 作为索引
    err = ctx.GetStub().PutState(merchantKey, reviewJSON)
    if err != nil {
        return err
    }
    // 额外存储 author 索引键，值为 reviewJSON
    return ctx.GetStub().PutState(authorKey, reviewJSON)
}

// CreateReview：创建评论（对应 POST /api/reviews），验证商户和用户存在
func (s *ReviewContract) CreateReview(ctx contractapi.TransactionContextInterface, merchantID string, rating int, comment string) error {
    // 生成 ID 和 timestamp
    id := "REV" + time.Now().Format("20060102150405")
    timestamp := time.Now().Format(time.RFC3339)

    // 获取作者 ID 从客户端身份（Fabric MSP）
    authorID, err := getAuthorIDFromContext(ctx)
    if err != nil {
        return err
    }

    // 验证商户存在
    _, err = s.GetMerchantByID(ctx, merchantID)
    if err != nil {
        return fmt.Errorf("merchant %s does not exist: %v", merchantID, err)
    }

    // 验证用户存在
    _, err = s.GetUserByID(ctx, authorID)
    if err != nil {
        return fmt.Errorf("user %s does not exist: %v", authorID, err)
    }

    // 验证评分
    if rating < 1 || rating > 5 {
        return fmt.Errorf("rating must be between 1 and 5")
    }

    return s.createReviewInternal(ctx, id, merchantID, authorID, rating, comment, timestamp)
}

// GetReviewByID：查询单个评论
func (s *ReviewContract) GetReviewByID(ctx contractapi.TransactionContextInterface, merchantID string, id string) (*Review, error) {
    key, err := ctx.GetStub().CreateCompositeKey("review~merchant", []string{merchantID, id})
    if err != nil {
        return nil, err
    }
    reviewJSON, err := ctx.GetStub().GetState(key)
    if err != nil || reviewJSON == nil {
        return nil, fmt.Errorf("review %s not found", id)
    }
    var review Review
    err = json.Unmarshal(reviewJSON, &review)
    if err != nil {
        return nil, err
    }
    return &review, nil
}

// GetReviewsByMerchant：查询商户所有评论（对应 GET /api/merchants/:id 的 reviews）
func (s *ReviewContract) GetReviewsByMerchant(ctx contractapi.TransactionContextInterface, merchantID string) ([]*Review, error) {
    resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("review~merchant", []string{merchantID})
    if err != nil {
        return nil, err
    }
    defer resultsIterator.Close()

    var reviews []*Review
    for resultsIterator.HasNext() {
        queryResponse, err := resultsIterator.Next()
        if err != nil {
            return nil, err
        }
        var review Review
        err = json.Unmarshal(queryResponse.Value, &review)
        if err != nil {
            return nil, err
        }
        reviews = append(reviews, &review)
    }
    return reviews, nil
}

// GetReviewsByAuthor：查询用户自己的评论（对应 GET /api/reviews/my）
func (s *ReviewContract) GetReviewsByAuthor(ctx contractapi.TransactionContextInterface, authorID string) ([]*Review, error) {
    resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("review~author", []string{authorID})
    if err != nil {
        return nil, err
    }
    defer resultsIterator.Close()

    var reviews []*Review
    for resultsIterator.HasNext() {
        queryResponse, err := resultsIterator.Next()
        if err != nil {
            return nil, err
        }
        var review Review
        err = json.Unmarshal(queryResponse.Value, &review)
        if err != nil {
            return nil, err
        }
        reviews = append(reviews, &review)
    }
    return reviews, nil
}