package contract

import (
    "encoding/json"
    "fmt"

    "github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/ZJURateTeam/ZJURate-backend/models"
)

// CreateUser：创建用户
func (s *ReviewContract) CreateUser(ctx contractapi.TransactionContextInterface, studentID string, username string) error {
    key, err := ctx.GetStub().CreateCompositeKey("user", []string{studentID})
    if err != nil {
        return err
    }
    existing, err := ctx.GetStub().GetState(key)
    if err != nil || existing != nil {
        return fmt.Errorf("user %s already exists or error", studentID)
    }

    user := models.User{
        StudentID: studentID,
        Username:  username,
    }
    userJSON, err := json.Marshal(user)
    if err != nil {
        return err
    }
    return ctx.GetStub().PutState(key, userJSON)
}

// GetUserByID：查询单个用户
func (s *ReviewContract) GetUserByID(ctx contractapi.TransactionContextInterface, studentID string) (*models.User, error) {
    key, err := ctx.GetStub().CreateCompositeKey("user", []string{studentID})
    if err != nil {
        return nil, err
    }
    userJSON, err := ctx.GetStub().GetState(key)
    if err != nil || userJSON == nil {
        return nil, fmt.Errorf("user %s not found", studentID)
    }
    var user models.User
    err = json.Unmarshal(userJSON, &user)
    if err != nil {
        return nil, err
    }
    return &user, nil
}

// GetAllUsers：查询所有用户（使用范围查询）
func (s *ReviewContract) GetAllUsers(ctx contractapi.TransactionContextInterface) ([]*models.User, error) {
    resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("user", []string{})
    if err != nil {
        return nil, err
    }
    defer resultsIterator.Close()

    var users []*models.User
    for resultsIterator.HasNext() {
        queryResponse, err := resultsIterator.Next()
        if err != nil {
            return nil, err
        }
        var user models.User
        err = json.Unmarshal(queryResponse.Value, &user)
        if err != nil {
            return nil, err
        }
        users = append(users, &user)
    }
    return users, nil
}