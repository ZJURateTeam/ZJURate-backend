#!/bin/bash

# 定义路径变量
FABRIC_PATH=~/fabric-samples
BACKEND_PATH=~/ZJURate-backend

cd $FABRIC_PATH/test-network
./network.sh down
./network.sh up createChannel -c mychannel -ca
./network.sh deployCC -ccn review -ccp $BACKEND_PATH/chaincode -ccl go -ccep "OR('Org1MSP.peer')" -cci InitLedger

export FABRIC_CA_CLIENT_HOME=${PWD}/organizations/peerOrganizations/org1.example.com/

fabric-ca-client enroll \
  -u https://admin:adminpw@localhost:7054 \
  --caname ca-org1 \
  --tls.certfiles ${PWD}/organizations/fabric-ca/org1/tls-cert.pem

fabric-ca-client register \
  --caname ca-org1 \
  --id.name appUser \
  --id.secret appUserpw \
  --id.type client \
  --id.affiliation org1.department1 \
  --tls.certfiles ${PWD}/organizations/fabric-ca/org1/tls-cert.pem

fabric-ca-client enroll \
  -u https://appUser:appUserpw@localhost:7054 \
  --caname ca-org1 \
  -M ${PWD}/organizations/peerOrganizations/org1.example.com/users/appUser@org1.example.com/msp \
  --tls.certfiles ${PWD}/organizations/fabric-ca/org1/tls-cert.pem

mkdir -p $BACKEND_PATH/wallet/appUser
cp -r organizations/peerOrganizations/org1.example.com/users/appUser@org1.example.com/msp/* \
   $BACKEND_PATH/wallet/appUser

mkdir -p $BACKEND_PATH/wallet/appUser/tlscacerts/
cp organizations/peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem \
   $BACKEND_PATH/wallet/appUser/tlscacerts/tls-ca-cert.pem

cd $BACKEND_PATH/wallet/appUser
rm -f keystore/priv_sk
mv keystore/*_sk keystore/priv_sk
