// services/cagen.go
package services

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
    "time"
    "crypto/x509"

	caapi "github.com/hyperledger/fabric-ca/api"
	calib "github.com/hyperledger/fabric-ca/lib"
	catls "github.com/hyperledger/fabric-ca/lib/tls"
	
    "github.com/hyperledger/fabric-gateway/pkg/client"
    "github.com/hyperledger/fabric-gateway/pkg/identity"
    "github.com/hyperledger/fabric-gateway/pkg/hash"
    "google.golang.org/grpc/credentials"
    "google.golang.org/grpc"
)

type CAConfig struct {
	URL             string // e.g. "https://localhost:7054"
	CAName          string // e.g. "ca-org1"
	TLSCACert       string // path to server TLS CA cert (PEM)
	HomeDir         string // 客户端工作目录，生成本地 msp/，e.g. "/tmp/ca-admin"
	RegistrarID     string // e.g. "admin"
	RegistrarSecret string // e.g. "adminpw"
}

type rawConfig struct {
	CA struct {
		URL       string `json:"url"`
		CAName    string `json:"caName"`
		TLSCACert string `json:"tlsCACert"`
	} `json:"ca"`

	Client struct {
		HomeDir string `json:"homeDir"`
		MSPDir  string `json:"mspDir"`
	} `json:"client"`

	Registrar struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	} `json:"registrar"`
}

// NewClient: 创建并初始化 Fabric-CA 客户端；若 registrar 未登记则自动登记一次
func NewClient(cfg CAConfig) (*calib.Client, error) {
	c := &calib.Client{
		HomeDir: cfg.HomeDir,
		Config: &calib.ClientConfig{
			URL:    cfg.URL,
			CAName: cfg.CAName,
			TLS: catls.ClientTLSConfig{
				Enabled:   true,
				CertFiles: []string{cfg.TLSCACert},
			},
		},
	}
	if err := c.Init(); err != nil {
		return nil, fmt.Errorf("init ca client: %w", err)
	}
	// 确保 registrar 已经 enroll
	if err := c.CheckEnrollment(); err != nil {
		resp, err := c.Enroll(&caapi.EnrollmentRequest{
			Name:   cfg.RegistrarID,
			Secret: cfg.RegistrarSecret,
			CAName: cfg.CAName,
			Type:   "x509",
		})
		if err != nil {
			return nil, fmt.Errorf("enroll registrar: %w", err)
		}
		if resp != nil && resp.Identity != nil {
			if err := resp.Identity.Store(); err != nil {
				return nil, fmt.Errorf("store registrar identity: %w", err)
			}
		}
	}
	return c, nil
}

// RegisterClient: 使用 registrar 注册一个 client 身份
// 传入 secret 可选：传 "" 则由 CA 随机生成并返回
func RegisterClient(c *calib.Client, userID, secret string) (string, error) {
	registrar, err := c.LoadMyIdentity()
	if err != nil {
		return "", fmt.Errorf("load registrar identity: %w", err)
	}
	req := &caapi.RegistrationRequest{
		Name: userID,
		Type: "client",
		// 不设置 Affiliation、Attributes 等一切可选字段
	}
	if secret != "" {
		req.Secret = secret
	}
	resp, err := registrar.Register(req)
	if err != nil {
		return "", fmt.Errorf("register client: %w", err)
	}
	return resp.Secret, nil
}

// EnrollToUserHome: 调用 CA 进行登记，并把证书和私钥写入 userHome/msp 目录
func EnrollToUserHome(cfg CAConfig, userID, secret, userHome string) error {
    c := &calib.Client{
        HomeDir: userHome,
        Config: &calib.ClientConfig{
            URL:    cfg.URL,
            CAName: cfg.CAName,
            TLS: catls.ClientTLSConfig{
                Enabled:   true,
                CertFiles: []string{cfg.TLSCACert},
            },
        },
    }
    if err := c.Init(); err != nil {
        return fmt.Errorf("init ca client: %w", err)
    }

    // 执行 Enroll
    resp, err := c.Enroll(&caapi.EnrollmentRequest{
        Name:   userID,
        Secret: secret,
        CAName: cfg.CAName,
        Type:   "x509",
    })
    if err != nil {
        return fmt.Errorf("enroll user: %w", err)
    }
	if resp != nil && resp.Identity != nil {
		if err := resp.Identity.Store(); err != nil {
			return fmt.Errorf("store user identity: %w", err)
		}
	}

    return nil
}

// 从 JSON 文件加载 CAConfig
func LoadCAConfigFromFile(path string) (CAConfig, error) {
	var rc rawConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return CAConfig{}, fmt.Errorf("read config file: %w", err)
	}
	if err := json.Unmarshal(data, &rc); err != nil {
		return CAConfig{}, fmt.Errorf("parse config json: %w", err)
	}

	cfg := CAConfig{
		URL:             rc.CA.URL,
		CAName:          rc.CA.CAName,
		TLSCACert:       rc.CA.TLSCACert,
		HomeDir:         rc.Client.HomeDir,
		RegistrarID:     rc.Registrar.ID,
		RegistrarSecret: rc.Registrar.Secret,
	}

	return cfg, nil
}

func NewRegistrarClient(cfg CAConfig) (*calib.Client, error) {
	adminPath := filepath.Join(cfg.HomeDir,"admin")
	c := &calib.Client{
		HomeDir: adminPath, // registrar 的工作目录，例如 wallet/org1/admin
		Config: &calib.ClientConfig{
			URL:    cfg.URL,
			CAName: cfg.CAName,
			TLS: catls.ClientTLSConfig{
				Enabled:   true,
				CertFiles: []string{cfg.TLSCACert},
			},
		},
	}

	if err := c.Init(); err != nil {
		return nil, fmt.Errorf("init ca client: %w", err)
	}

	// 确保 registrar 已经 enroll
	if err := c.CheckEnrollment(); err != nil {
		resp, err := c.Enroll(&caapi.EnrollmentRequest{
			Name:   cfg.RegistrarID,
			Secret: cfg.RegistrarSecret,
			CAName: cfg.CAName,
			Type:   "x509",
		})
		if err != nil {
			return nil, fmt.Errorf("enroll registrar: %w", err)
		}
		if resp != nil && resp.Identity != nil {
			if err := resp.Identity.Store(); err != nil {
				return nil, fmt.Errorf("store registrar identity: %w", err)
			}
		}
	}
	return c, nil
}

// 内部辅助函数
// newGrpcConnection creates a gRPC connection to the Gateway server.
func newGrpcConnection(peerEndpoint, serverNameOverride, tlsCACertPath string) (*grpc.ClientConn, error) {
	caPEM, err := os.ReadFile(tlsCACertPath)
	if err != nil { 
        return nil, fmt.Errorf("read TLS CA: %w", err) 
    }
	cert, err := identity.CertificateFromPEM(caPEM)
	if err != nil { 
        return nil, err 
    }

	cp := x509.NewCertPool()
	cp.AddCert(cert)
	creds := credentials.NewClientTLSFromCert(cp, serverNameOverride)

	return grpc.NewClient(
		peerEndpoint, // e.g. "localhost:7051"
		grpc.WithTransportCredentials(creds),
	)
}

// pickConn choose an available connection from conns with peers in the org. 
func (s *BlockchainService) pickConn() *grpc.ClientConn {
    s.mu.RLock(); defer s.mu.RUnlock()
    if c, ok := s.conns[s.primary]; ok { return c }
    for _, c := range s.conns { return c }
    return nil
}

// newIdentityFromWallet 从 userHome/msp 读取身份
func newIdentityFromWallet(userHome, mspID string) (*identity.X509Identity, error) {
	certPath := filepath.Join(userHome, "msp", "signcerts", "cert.pem")
	pem, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read signcert: %w", err)
	}
	cert, err := identity.CertificateFromPEM(pem)
	if err != nil {
		return nil, err
	}
	return identity.NewX509Identity(mspID, cert)
}

// newSignFromWallet 从 userHome/msp/keystore读取私钥 原理为遍历文件
func newSignFromWallet(userHome string) (identity.Sign, error) {
	ks := filepath.Join(userHome, "msp", "keystore")
	ents, err := os.ReadDir(ks)
	if err != nil {
		return nil, fmt.Errorf("read keystore: %w", err)
	}
	if len(ents) == 0 {
		return nil, fmt.Errorf("no private key in keystore")
	}
	keyPEM, err := os.ReadFile(filepath.Join(ks, ents[0].Name()))
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	pk, err := identity.PrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	return identity.NewPrivateKeySign(pk)
}

// withUserGateway 根据用户身份建立 gateway 回调 fn 执行链码操作 读取 HomeDir/studentID 下的文件
func (s *BlockchainService) withUserGateway(studentID, mspID string, fn func(gw *client.Gateway) error) error {
	conn := s.pickConn()
	if conn == nil {
		return fmt.Errorf("no available peer connection")
	}
	userHome := filepath.Join(s.caCfg.HomeDir, studentID)

	id, err := newIdentityFromWallet(userHome, mspID)
	if err != nil {
		return err
	}
	sign, err := newSignFromWallet(userHome)
	if err != nil {
		return err
	}

	gw, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithHash(hash.SHA256),
		client.WithClientConnection(conn), 
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		return err
	}
	defer gw.Close()
	return fn(gw)
}

// ensureUserEnrolled 若 studentID 对应的用户在链上不存在 则调用 register + enroll 到 homeDir/msp
func (s *BlockchainService) ensureUserEnrolled(studentID string) error {
	userHome := filepath.Join(s.caCfg.HomeDir, studentID)
	if _, err := os.Stat(filepath.Join(userHome, "msp", "signcerts", "cert.pem")); err == nil {
		return nil // 已经有证书
	}
	if err := os.MkdirAll(userHome, 0o755); err != nil {
		return fmt.Errorf("prepare user home: %w", err)
	}
	secret, err := RegisterClient(s.caAdmin, studentID, "")
	if err != nil {
		return fmt.Errorf("ca register: %w", err)
	}
	if err := EnrollToUserHome(s.caCfg, studentID, secret, userHome); err != nil {
		return fmt.Errorf("ca enroll: %w", err)
	}
	return nil
}
