# Configuration

The application uses a `config.yml` file to manage all service configurations. A sample file is provided below. You can specify a different path using the `-config` flag when running the application.

### `config.yml` Format

```yaml
app:
  port: 8080 # The port on which the API server will listen.

fabric:
  ca:
    url: "https://your-ca-server:7054" # The URL of the Fabric CA server.
    caName: "ca-org1" # The name of the CA.
    tlsCACert: "path/to/ca-tls-cert.pem" # Path to the CA's TLS certificate.
  client:
    homeDir: "./data" # The directory for storing MSP and cryptographic materials.
    mspDir: "msp" # The subdirectory for MSP.
  registrar:
    id: "admin" # The ID of the registrar user.
    secret: "adminpw" # The password for the registrar user.
  peers:
    - url: "grpc://peer0.org1.example.com:7051" # A list of Fabric peer endpoints.
      name: "peer0.org1.example.com"
      tlsRootCert: "path/to/peer-tls-cert.pem" # Path to the peer's TLS certificate.

jwt:
  secretKey: "YourSuperSecretJWTKey" # The secret key for signing JWT tokens.
```

**Note:** For production, it's highly recommended to use environment variables to store sensitive information like the `jwt.secretKey` instead of hardcoding it in the configuration file.

## Project Structure 📁

The project is organized into logical packages:

  - **`main.go`**: The entry point of the application. It loads the configuration, initializes services, and sets up the Gin router and its routes.
  - **`handlers/`**: Contains the API handlers that process incoming requests, interact with services, and send responses.
      - `handlers.go`: Contains the core handlers for authentication, merchants, and reviews.
      - `middleware.go`: Defines the JWT authentication middleware used to protect routes.
      - `upload.go`: Handles the image upload logic.
  - **`services/`**: Contains the business logic and external service interactions.
      - `blockchain.go`: [Binary File] Likely handles all interactions with the Hyperledger Fabric network.
      - `sqlitestore.go`: Manages user data persistence in a local SQLite database.
  - **`models/`**: Defines the data structures (structs) used throughout the application for requests, responses, and internal data representation.