package contract

import (
    "encoding/json"
    "fmt"
    "time"

    "github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/ZJURateTeam/ZJURate-backend/models"
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

    review := models.Review{
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

// CreateReview：创建评论（POST /api/reviews）——保持接口不变：只返回 error
func (s *ReviewContract) CreateReview(ctx contractapi.TransactionContextInterface, merchantID string, authorID string, rating int, comment string) error {
    // 用提案上下文的 TxID 作为确定性的 review ID（各背书节点一致）
    id := ctx.GetStub().GetTxID()

    // 用提案时间戳作为确定性时间（来自相同提案，各节点一致）
    ts, err := ctx.GetStub().GetTxTimestamp()
    if err != nil {
        return fmt.Errorf("get tx timestamp: %w", err)
    }
    timestamp := time.Unix(ts.Seconds, int64(ts.Nanos)).UTC().Format(time.RFC3339)

    if _, err = s.GetMerchantByID(ctx, merchantID); err != nil {
        return fmt.Errorf("merchant %s does not exist: %v", merchantID, err)
    }
    if _, err = s.GetUserByID(ctx, authorID); err != nil {
        return fmt.Errorf("user %s does not exist: %v", authorID, err)
    }
    if rating < 1 || rating > 5 {
        return fmt.Errorf("rating must be between 1 and 5")
    }

    // 调用ReviewInternal写入账本
    return s.createReviewInternal(ctx, id, merchantID, authorID, rating, comment, timestamp)
}


// GetReviewByID：查询单个评论
func (s *ReviewContract) GetReviewByID(ctx contractapi.TransactionContextInterface, merchantID string, id string) (*models.Review, error) {
    key, err := ctx.GetStub().CreateCompositeKey("review~merchant", []string{merchantID, id})
    if err != nil {
        return nil, err
    }
    reviewJSON, err := ctx.GetStub().GetState(key)
    if err != nil || reviewJSON == nil {
        return nil, fmt.Errorf("review %s not found", id)
    }
    var review models.Review
    err = json.Unmarshal(reviewJSON, &review)
    if err != nil {
        return nil, err
    }
    return &review, nil
}

// GetReviewsByMerchant：查询商户所有评论（对应 GET /api/merchants/:id 的 reviews）
func (s *ReviewContract) GetReviewsByMerchant(ctx contractapi.TransactionContextInterface, merchantID string) ([]*models.Review, error) {
    resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("review~merchant", []string{merchantID})
    if err != nil {
        return nil, err
    }
    defer resultsIterator.Close()

    var reviews []*models.Review
    for resultsIterator.HasNext() {
        queryResponse, err := resultsIterator.Next()
        if err != nil {
            return nil, err
        }
        var review models.Review
        err = json.Unmarshal(queryResponse.Value, &review)
        if err != nil {
            return nil, err
        }
        reviews = append(reviews, &review)
    }
    return reviews, nil
}

// GetReviewsByAuthor：查询用户自己的评论（对应 GET /api/reviews/my）
func (s *ReviewContract) GetReviewsByAuthor(ctx contractapi.TransactionContextInterface, authorID string) ([]*models.Review, error) {
    resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("review~author", []string{authorID})
    if err != nil {
        return nil, err
    }
    defer resultsIterator.Close()

    var reviews []*models.Review
    for resultsIterator.HasNext() {
        queryResponse, err := resultsIterator.Next()
        if err != nil {
            return nil, err
        }
        var review models.Review
        err = json.Unmarshal(queryResponse.Value, &review)
        if err != nil {
            return nil, err
        }
        reviews = append(reviews, &review)
    }
    return reviews, nil
}