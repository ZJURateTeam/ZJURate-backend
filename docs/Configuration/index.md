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
