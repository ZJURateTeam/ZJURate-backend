package contract

import (
    "time"

    "github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/ZJURateTeam/ZJURate-backend/models"
)

// ReviewContract 合约：扩展管理商户、用户和评论
type ReviewContract struct {
    contractapi.Contract
}

// InitLedger：初始化 ledger，添加初始商户、用户和评论（类似于 fake data）
func (s *ReviewContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
    // 初始商户数据
    merchants := []models.MerchantDetails{
        {"MER001", "银泉食堂", "北教旁边", "餐饮", 0.0, nil},
        {"MER002", "蓝田文印店", "蓝田大门西侧50米", "打印", 0.0, nil},
        {"MER003", "启真教育超市", "白沙1幢楼下", "超市", 0.0, nil},
    }
    for _, merchant := range merchants {
        err := s.CreateMerchant(ctx, merchant.ID, merchant.Name, merchant.Address, merchant.Category)
        if err != nil {
            return err
        }
    }

    // 初始用户数据（PublicKey 为空或模拟值）
    users := []models.User{
        {"3240100001", "犬戎"},
        {"3240100008", "用户8"},
        {"3240100015", "用户15"},
        {"3240100009", "用户9"},
    }
    for _, user := range users {
        err := s.CreateUser(ctx, user.StudentID, user.Username) // PublicKey 已移除
        if err != nil {
            return err
        }
    }

    // 初始评论数据
    reviews := []models.Review{
        {"REV5001", "MER001", "3240100008", 5, "好吃！就是人有点多。", time.Now().Format(time.RFC3339)},
        {"REV5002", "MER001", "3240100015", 4, "价格实惠，分量足。", time.Now().Format(time.RFC3339)},
        {"REV5003", "MER002", "3240100008", 5, "打印速度超快，老板人很好。", time.Now().Format(time.RFC3339)},
        {"REV5004", "MER002", "3240100009", 1, "全价四万了盗我整理的讲义卖", time.Now().Format(time.RFC3339)},
        {"REV5005", "MER003", "3240100001", 3, "东西还行，就是有点贵。", time.Now().Format(time.RFC3339)},
    }
    for _, review := range reviews {
        err := s.createReviewInternal(ctx, review.ID, review.MerchantID, review.AuthorID, review.Rating, review.Comment, review.Timestamp)
        if err != nil {
            return err
        }
    }
    return nil
}