package review

import (
    "fmt"

    "github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// getAuthorIDFromContext：从上下文获取作者 ID（简化，实际用 MSP ID 或 StudentID）
func getAuthorIDFromContext(ctx contractapi.TransactionContextInterface) (string, error) {
    clientID, err := ctx.GetClientIdentity().GetID()
    if err != nil {
        return "", fmt.Errorf("failed to get client identity: %v", err)
    }
    // 假设 clientID 是 StudentID；实际需映射
    return clientID, nil
}