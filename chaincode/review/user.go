package review

import (
    "encoding/json"
    "fmt"

    "github.com/hyperledger/fabric-contract-api-go/contractapi"
    "crypto/ecdsa"
    "crypto/x509"
    "encoding/pem"
    "crypto/sha256"
)

// CreateUser：创建用户（添加 publicKey 参数）
func (s *ReviewContract) CreateUser(ctx contractapi.TransactionContextInterface, studentID string, username string, publicKey string) error {
    key, err := ctx.GetStub().CreateCompositeKey("user", []string{studentID})
    if err != nil {
        return err
    }
    existing, err := ctx.GetStub().GetState(key)
    if err != nil || existing != nil {
        return fmt.Errorf("user %s already exists or error", studentID)
    }

    user := User{
        StudentID: studentID,
        Username:  username,
        PublicKey: publicKey,  // 新增参数
    }
    userJSON, err := json.Marshal(user)
    if err != nil {
        return err
    }
    return ctx.GetStub().PutState(key, userJSON)
}

// GetUserByID：查询单个用户
func (s *ReviewContract) GetUserByID(ctx contractapi.TransactionContextInterface, studentID string) (*User, error) {
    key, err := ctx.GetStub().CreateCompositeKey("user", []string{studentID})
    if err != nil {
        return nil, err
    }
    userJSON, err := ctx.GetStub().GetState(key)
    if err != nil || userJSON == nil {
        return nil, fmt.Errorf("user %s not found", studentID)
    }
    var user User
    err = json.Unmarshal(userJSON, &user)
    if err != nil {
        return nil, err
    }
    return &user, nil
}

// VerifyUserSignature：验证用户签名
func (s *ReviewContract) VerifyUserSignature(ctx contractapi.TransactionContextInterface, studentID string, message string, signature []byte) (bool, error) {
    user, err := s.GetUserByID(ctx, studentID)
    if err != nil {
        return false, err
    }
    block, _ := pem.Decode([]byte(user.PublicKey))
    pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return false, err
    }
    ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
    if !ok {
        return false, fmt.Errorf("invalid public key")
    }
    hash := sha256.Sum256([]byte(message))
    return ecdsa.VerifyASN1(ecdsaPubKey, hash[:], signature), nil
}