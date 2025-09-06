package review

import (
    "encoding/json"
    "fmt"

    "github.com/hyperledger/fabric-contract-api-go/contractapi"
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

    merchant := Merchant{
        ID:       id,
        Name:     name,
        Address:  address,
        Category: category,
    }
    merchantJSON, err := json.Marshal(merchant)
    if err != nil {
        return err
    }
    return ctx.GetStub().PutState(key, merchantJSON)
}

// GetMerchantByID：查询单个商户
func (s *ReviewContract) GetMerchantByID(ctx contractapi.TransactionContextInterface, id string) (*Merchant, error) {
    key, err := ctx.GetStub().CreateCompositeKey("merchant", []string{id})
    if err != nil {
        return nil, err
    }
    merchantJSON, err := ctx.GetStub().GetState(key)
    if err != nil || merchantJSON == nil {
        return nil, fmt.Errorf("merchant %s not found", id)
    }
    var merchant Merchant
    err = json.Unmarshal(merchantJSON, &merchant)
    if err != nil {
        return nil, err
    }
    return &merchant, nil
}

// GetAllMerchants：查询所有商户（使用范围查询）
func (s *ReviewContract) GetAllMerchants(ctx contractapi.TransactionContextInterface) ([]*Merchant, error) {
    resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("merchant", []string{})
    if err != nil {
        return nil, err
    }
    defer resultsIterator.Close()

    var merchants []*Merchant
    for resultsIterator.HasNext() {
        queryResponse, err := resultsIterator.Next()
        if err != nil {
            return nil, err
        }
        var merchant Merchant
        err = json.Unmarshal(queryResponse.Value, &merchant)
        if err != nil {
            return nil, err
        }
        merchants = append(merchants, &merchant)
    }
    return merchants, nil
}