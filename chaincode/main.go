package main
// To setup chaincode

import (
    "log"

    "github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/zgyxclyty/ZJURate-backend/chaincode/review"
)

func main() {
    chaincode, err := contractapi.NewChaincode(&review.ReviewContract{})
    if err != nil {
        log.Panicf("Error creating chaincode: %v", err)
    }

    if err := chaincode.Start(); err != nil {
        log.Panicf("Error starting chaincode: %v", err)
    }
}