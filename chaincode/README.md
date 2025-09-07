# ZJURate Chaincode

## Overview
This Chaincode (smart contract) is built for the ZJURate system on Hyperledger Fabric. It manages merchants, users, and reviews in a blockchain environment, ensuring data immutability and efficient querying. The contract handles creation, retrieval, and verification operations for entities like merchants (static info), users (with public keys for signature verification), and reviews (ratings and comments).

Key features:
- Composite keys for efficient querying (e.g., by merchant or author).
- Initialization with sample data.
- Signature verification for passwordless authentication using public keys.
- Validation for existence of merchants and users before creating reviews.

This Chaincode is written in Go and uses the Fabric Contract API.

## Dependencies
- Go 1.21+
- github.com/hyperledger/fabric-contract-api-go v1.2.2
- Standard Go libraries: encoding/json, fmt, time, crypto/ecdsa, crypto/x509, encoding/pem, crypto/sha256

Install dependencies:
```
go mod tidy
```

## Deployment
1. Start the Fabric test network (from fabric-samples/test-network):
   ```
   ./network.sh up createChannel -ca -c mychannel
   ```
2. Deploy the Chaincode:
   ```
   ./network.sh deployCC -ccn reviews -ccp /path/to/chaincode -ccl go -ccv 1 -ccs 1 -cci InitLedger
   ```
   - `-cci InitLedger`: Calls the initialization function to populate sample data.

## Functions
All functions are methods of the `ReviewContract` struct. They are invoked via Fabric SDK or peer CLI.

### InitLedger
Initializes the ledger with sample merchants, users, and reviews.

- **Parameters**: None (uses TransactionContextInterface internally).
- **Returns**: error (nil on success).
- **Example CLI Invocation**:
  ```
  peer chaincode invoke -C mychannel -n reviews -c '{"function":"InitLedger","Args":[]}'
  ```
- **Notes**: Called during deployment. Populates data similar to the fake backend's static arrays.

### CreateMerchant
Creates a new merchant.

- **Parameters**:
  - id (string): Unique merchant ID (e.g., "MER001").
  - name (string): Merchant name.
  - address (string): Merchant address.
  - category (string): Merchant category (e.g., "餐饮").
- **Returns**: error (nil on success).
- **Example CLI Invocation**:
  ```
  peer chaincode invoke -C mychannel -n reviews -c '{"function":"CreateMerchant","Args":["MER004","New Cafe","Somewhere","Food"]}'
  ```
- **Notes**: Checks for duplicates. Stored with composite key "merchant~id".

### GetMerchantByID
Retrieves a merchant by ID.

- **Parameters**:
  - id (string): Merchant ID.
- **Returns**: *Merchant, error.
- **Example CLI Invocation**:
  ```
  peer chaincode query -C mychannel -n reviews -c '{"Args":["GetMerchantByID","MER001"]}'
  ```
- **Output**: JSON of Merchant struct.

### GetAllMerchants
Retrieves all merchants.

- **Parameters**: None.
- **Returns**: []*Merchant, error.
- **Example CLI Invocation**:
  ```
  peer chaincode query -C mychannel -n reviews -c '{"Args":["GetAllMerchants"]}'
  ```
- **Output**: JSON array of Merchant structs.

### CreateUser
Creates a new user.

- **Parameters**:
  - studentID (string): Unique student ID (e.g., "3240100001").
  - username (string): Username.
  - publicKey (string): PEM-encoded public key (optional, can be empty).
- **Returns**: error (nil on success).
- **Example CLI Invocation**:
  ```
  peer chaincode invoke -C mychannel -n reviews -c '{"function":"CreateUser","Args":["3240109999","NewUser","-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----"]}'
  ```
- **Notes**: Checks for duplicates. Stored with composite key "user~studentID".

### GetUserByID
Retrieves a user by studentID.

- **Parameters**:
  - studentID (string): Student ID.
- **Returns**: *User, error.
- **Example CLI Invocation**:
  ```
  peer chaincode query -C mychannel -n reviews -c '{"Args":["GetUserByID","3240100001"]}'
  ```
- **Output**: JSON of User struct.

### VerifyUserSignature
Verifies a user's signature using their stored public key.

- **Parameters**:
  - studentID (string): Student ID.
  - message (string): Message that was signed (e.g., nonce).
  - signature ([]byte): ASN.1 encoded signature.
- **Returns**: bool, error (true if valid).
- **Example CLI Invocation** (Note: byte arrays are tricky in CLI; better via SDK):
  ```
  peer chaincode invoke -C mychannel -n reviews -c '{"function":"VerifyUserSignature","Args":["3240100001","nonce message","base64_encoded_signature"]}'
  ```
- **Notes**: Uses ECDSA verification. Signature must be base64 or hex in CLI.

### CreateReview
Creates a new review.

- **Parameters**:
  - merchantID (string): Merchant ID.
  - rating (int): Rating (1-5).
  - comment (string): Comment text.
- **Returns**: error (nil on success).
- **Example CLI Invocation**:
  ```
  peer chaincode invoke -C mychannel -n reviews -c '{"function":"CreateReview","Args":["MER001","4","Nice place"]}'
  ```
- **Notes**: Generates ID and timestamp. Validates merchant/user existence and rating. AuthorID from context.

### GetReviewByID
Retrieves a review by merchantID and ID.

- **Parameters**:
  - merchantID (string): Merchant ID.
  - id (string): Review ID.
- **Returns**: *Review, error.
- **Example CLI Invocation**:
  ```
  peer chaincode query -C mychannel -n reviews -c '{"Args":["GetReviewByID","MER001","REV5001"]}'
  ```
- **Output**: JSON of Review struct.

### GetReviewsByMerchant
Retrieves all reviews for a merchant.

- **Parameters**:
  - merchantID (string): Merchant ID.
- **Returns**: []*Review, error.
- **Example CLI Invocation**:
  ```
  peer chaincode query -C mychannel -n reviews -c '{"Args":["GetReviewsByMerchant","MER001"]}'
  ```
- **Output**: JSON array of Review structs.

### GetReviewsByAuthor
Retrieves all reviews by an author.

- **Parameters**:
  - authorID (string): Author ID (StudentID).
- **Returns**: []*Review, error.
- **Example CLI Invocation**:
  ```
  peer chaincode query -C mychannel -n reviews -c '{"Args":["GetReviewsByAuthor","3240100001"]}'
  ```
- **Output**: JSON array of Review structs.

### Internal Functions (Not Exported)
- createReviewInternal: Helper for review creation (not callable directly).
- getAuthorIDFromContext: Extracts author ID from transaction context (utility).

## Testing
- Unit tests: Use `go test ./...` with mocks (e.g., testify).
- Integration: Deploy to test-network, use peer CLI for invoke/query.
- Example: After deployment, query GetAllMerchants to verify init data.

## Security Notes
- Public keys are stored on-chain for verification (safe as they are public).
- No passwords on-chain; use signature verification for auth.
- Validate inputs to prevent invalid data.
