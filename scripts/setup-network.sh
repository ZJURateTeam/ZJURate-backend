#!/bin/bash

# 定义路径变量
FABRIC_PATH=~/fabric-samples
BACKEND_PATH=~/ZJURate-backend

rm -rf $BACKEND_PATH/wallet/org1
rm -f keystore.db
rm -f user.db
cd $FABRIC_PATH/test-network
./network.sh down
./network.sh up createChannel -c mychannel -ca
./network.sh deployCC -ccn review -ccp $BACKEND_PATH/chaincode -ccl go -ccep "OR('Org1MSP.peer')" -cci InitLedger

mkdir -p "$BACKEND_PATH/wallet/org1/tlscacerts"
cp "$FABRIC_PATH/test-network/organizations/peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem" \
   "$BACKEND_PATH/wallet/org1/tlscacerts/tls-peer-ca.pem"

cp "$FABRIC_PATH/test-network/organizations/fabric-ca/org1/ca-cert.pem" \
   "$BACKEND_PATH/wallet/org1/tlscacerts/tls-ca-cert.pem"