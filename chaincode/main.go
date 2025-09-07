package main
// To setup chaincode

import (
    "log"

    "github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/ZJURateTeam/ZJURate-backend/chaincode/contract"
)

func main() {
    chaincode, err := contractapi.NewChaincode(&contract.ReviewContract{})
    if err != nil {
        log.Panicf("Error creating chaincode: %v", err)
    }

    if err := chaincode.Start(); err != nil {
        log.Panicf("Error starting chaincode: %v", err)
    }
}