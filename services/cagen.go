package services

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"time"

	caapi "github.com/hyperledger/fabric-ca/api"
	calib "github.com/hyperledger/fabric-ca/lib"
	catls "github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/hash"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/yaml.v2"
)

type CAConfig struct {
	URL             string
	CAName          string
	TLSCACert       string
	HomeDir         string
	RegistrarID     string
	RegistrarSecret string
}

type rawConfig struct {
	CA struct {
		URL       string `yaml:"url"`
		CAName    string `yaml:"caName"`
		TLSCACert string `yaml:"tlsCACert"`
	} `yaml:"ca"`

	Client struct {
		HomeDir string `yaml:"homeDir"`
		MSPDir  string `yaml:"mspDir"`
	} `yaml:"client"`

	Registrar struct {
		ID     string `yaml:"id"`
		Secret string `yaml:"secret"`
	} `yaml:"registrar"`
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

// LoadCAConfigFromFile is no longer needed but kept for context.
func LoadCAConfigFromFile(path string) (CAConfig, error) {
	var rc rawConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return CAConfig{}, fmt.Errorf("read config file: %w", err)
	}
	// Use go-yaml to unmarshal the raw config structure.
	if err := yaml.Unmarshal(data, &rc); err != nil {
		return CAConfig{}, fmt.Errorf("parse config yaml: %w", err)
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
	adminPath := filepath.Join(cfg.HomeDir, "admin")
	c := &calib.Client{
		HomeDir: adminPath,
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
		peerEndpoint,
		grpc.WithTransportCredentials(creds),
	)
}

func (s *BlockchainService) pickConn() *grpc.ClientConn {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.conns[s.primary]; ok {
		return c
	}
	for _, c := range s.conns {
		return c
	}
	return nil
}

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
