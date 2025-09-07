package contract

import (
    "encoding/json"
    "fmt"
	
    "github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/ZJURateTeam/ZJURate-backend/models"
)

// CreateMerchant：创建商户
func (s *ReviewContract) CreateMerchant(ctx contractapi.TransactionContextInterface, id string, name string, address string, category string) error {
    key, err := ctx.GetStub().CreateCompositeKey("merchant", []string{id})
    if err != nil {
        return err
    }
    existing, err := ctx.GetStub().GetState(key)
    if err != nil || existing != nil {
        return fmt.Errorf("merchant %s already exists or error", id)
    }

    merchant := models.MerchantDetails{
        ID:            id,
        Name:          name,
        Address:       address,
        Category:      category,
        AverageRating: 0.0,
        Reviews:       nil,
    }
    merchantJSON, err := json.Marshal(merchant)
    if err != nil {
        return err
    }
    return ctx.GetStub().PutState(key, merchantJSON)
}

// GetMerchantByID：查询单个商户
func (s *ReviewContract) GetMerchantByID(ctx contractapi.TransactionContextInterface, id string) (*models.MerchantDetails, error) {
    key, err := ctx.GetStub().CreateCompositeKey("merchant", []string{id})
    if err != nil {
        return nil, err
    }
    merchantJSON, err := ctx.GetStub().GetState(key)
    if err != nil || merchantJSON == nil {
        return nil, fmt.Errorf("merchant %s not found", id)
    }
    var merchant models.MerchantDetails
    err = json.Unmarshal(merchantJSON, &merchant)
    if err != nil {
        return nil, err
    }
    if merchant.Reviews == nil {
        merchant.Reviews = []models.Review{}
    }
    return &merchant, nil
}

// GetAllMerchants：查询所有商户（使用范围查询）
func (s *ReviewContract) GetAllMerchants(ctx contractapi.TransactionContextInterface) ([]*models.MerchantDetails, error) {
    resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("merchant", []string{})
    if err != nil {
        return nil, err
    }
    defer resultsIterator.Close()

    var merchants []*models.MerchantDetails
    for resultsIterator.HasNext() {
        queryResponse, err := resultsIterator.Next()
        if err != nil {
            return nil, err
        }
        var merchant models.MerchantDetails
        err = json.Unmarshal(queryResponse.Value, &merchant)
        if err != nil {
            return nil, err
        }
        if merchant.Reviews == nil {
            merchant.Reviews = []models.Review{}
        }
        merchants = append(merchants, &merchant)
    }
    return merchants, nil
}