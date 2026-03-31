// certgen/main.go - 国密证书生成工具
package main

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

func main() {
	certDir := filepath.Join("..", "certs")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		fmt.Printf("创建证书目录失败: %v\n", err)
		os.Exit(1)
	}

	// ── 生成 CA ──────────────────────────────────────────────
	fmt.Println("正在生成 SM2 CA 密钥对...")
	caKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("生成 CA 密钥失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("正在生成 CA 证书...")
	caCertDER, err := generateCACert(caKey)
	if err != nil {
		fmt.Printf("生成 CA 证书失败: %v\n", err)
		os.Exit(1)
	}
	caCert, _ := x509.ParseCertificate(caCertDER)
	caKeyDer, err := x509.MarshalSm2PrivateKey(caKey, nil)
	if err != nil {
		fmt.Printf("序列化 CA 私钥失败: %v\n", err)
		os.Exit(1)
	}
	writePEM(filepath.Join(certDir, "ca.crt"), "CERTIFICATE", caCertDER)
	writePEM(filepath.Join(certDir, "ca.key"), "SM2 PRIVATE KEY", caKeyDer)
	fmt.Println("✓ CA 证书已保存")

	// ── 生成服务端双证书（国密规范：签名证书 + 加密证书）────
	//
	// 国密 GMSSL 规范要求服务端必须持有两张独立证书：
	//   签名证书 (Sign Cert)：KeyUsage = DigitalSignature
	//                         用于握手阶段的身份认证与签名
	//   加密证书 (Enc Cert) ：KeyUsage = KeyEncipherment
	//                         用于密钥交换时加密预主密钥
	// 两张证书使用不同的密钥对，私钥分开存储。

	fmt.Println("\n正在生成服务端签名密钥对...")
	serverSignKey, _ := sm2.GenerateKey(rand.Reader)
	fmt.Println("正在生成服务端签名证书...")
	serverSignCertDER, err := generateServerSignCert(serverSignKey, caKey, caCert)
	if err != nil {
		fmt.Printf("生成服务端签名证书失败: %v\n", err)
		os.Exit(1)
	}
	serverSignKeyDer, err := x509.MarshalSm2PrivateKey(serverSignKey, nil)
	if err != nil {
		fmt.Printf("序列化服务端签名私钥失败: %v\n", err)
		os.Exit(1)
	}
	writePEM(filepath.Join(certDir, "server_sign.crt"), "CERTIFICATE", serverSignCertDER)
	writePEM(filepath.Join(certDir, "server_sign.key"), "SM2 PRIVATE KEY", serverSignKeyDer)
	fmt.Println("✓ 服务端签名证书已保存 (server_sign.crt / server_sign.key)")

	fmt.Println("\n正在生成服务端加密密钥对...")
	serverEncKey, _ := sm2.GenerateKey(rand.Reader)
	fmt.Println("正在生成服务端加密证书...")
	serverEncCertDER, err := generateServerEncCert(serverEncKey, caKey, caCert)
	if err != nil {
		fmt.Printf("生成服务端加密证书失败: %v\n", err)
		os.Exit(1)
	}
	serverEncKeyDer, err := x509.MarshalSm2PrivateKey(serverEncKey, nil)
	if err != nil {
		fmt.Printf("序列化服务端加密私钥失败: %v\n", err)
		os.Exit(1)
	}
	writePEM(filepath.Join(certDir, "server_enc.crt"), "CERTIFICATE", serverEncCertDER)
	writePEM(filepath.Join(certDir, "server_enc.key"), "SM2 PRIVATE KEY", serverEncKeyDer)
	fmt.Println("✓ 服务端加密证书已保存 (server_enc.crt / server_enc.key)")

	// ── 生成客户端证书 ────────────────────────────────────────
	fmt.Println("\n正在生成客户端密钥对...")
	clientKey, _ := sm2.GenerateKey(rand.Reader)
	fmt.Println("正在生成客户端证书...")
	clientCertDER, err := generateClientCert(clientKey, caKey, caCert)
	if err != nil {
		fmt.Printf("生成客户端证书失败: %v\n", err)
		os.Exit(1)
	}
	clientKeyDer, err := x509.MarshalSm2PrivateKey(clientKey, nil)
	if err != nil {
		fmt.Printf("序列化 Client 私钥失败: %v\n", err)
		os.Exit(1)
	}
	writePEM(filepath.Join(certDir, "client.crt"), "CERTIFICATE", clientCertDER)
	writePEM(filepath.Join(certDir, "client.key"), "SM2 PRIVATE KEY", clientKeyDer)
	fmt.Println("✓ 客户端证书已保存")

	fmt.Println("\n========================================")
	fmt.Println("  国密证书生成完成!")
	fmt.Println("  签名证书: server_sign.crt / server_sign.key")
	fmt.Println("  加密证书: server_enc.crt  / server_enc.key")
	fmt.Println("========================================")
}

// generateCACert 生成自签名 CA 根证书
func generateCACert(key *sm2.PrivateKey) ([]byte, error) {
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	cert := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Province:           []string{"Beijing"},
			Locality:           []string{"Beijing"},
			Organization:       []string{"GMTLS Demo CA"},
			OrganizationalUnit: []string{"CA"},
			CommonName:         "GMTLS Demo CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	return x509.CreateCertificate(cert, cert, &key.PublicKey, key)
}

// generateServerSignCert 生成服务端签名证书
// KeyUsage 仅含 DigitalSignature，用于握手阶段的身份认证与签名
func generateServerSignCert(key, caKey *sm2.PrivateKey, caCert *x509.Certificate) ([]byte, error) {
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	cert := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Province:           []string{"Beijing"},
			Locality:           []string{"Beijing"},
			Organization:       []string{"GMTLS Demo"},
			OrganizationalUnit: []string{"Server Sign"},
			CommonName:         "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature, // 仅签名
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{"localhost", "127.0.0.1"},
	}
	return x509.CreateCertificate(cert, caCert, &key.PublicKey, caKey)
}

// generateServerEncCert 生成服务端加密证书
// KeyUsage 仅含 KeyEncipherment，用于密钥交换时加密预主密钥
func generateServerEncCert(key, caKey *sm2.PrivateKey, caCert *x509.Certificate) ([]byte, error) {
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	cert := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Province:           []string{"Beijing"},
			Locality:           []string{"Beijing"},
			Organization:       []string{"GMTLS Demo"},
			OrganizationalUnit: []string{"Server Enc"},
			CommonName:         "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment, // 仅加密
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{"localhost", "127.0.0.1"},
	}
	return x509.CreateCertificate(cert, caCert, &key.PublicKey, caKey)
}

// generateClientCert 生成客户端证书
func generateClientCert(key, caKey *sm2.PrivateKey, caCert *x509.Certificate) ([]byte, error) {
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	cert := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Province:           []string{"Beijing"},
			Locality:           []string{"Beijing"},
			Organization:       []string{"GMTLS Demo"},
			OrganizationalUnit: []string{"Client"},
			CommonName:         "GMTLS Client",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	return x509.CreateCertificate(cert, caCert, &key.PublicKey, caKey)
}

func writePEM(path, blockType string, data []byte) {
	pemFile, _ := os.Create(path)
	pem.Encode(pemFile, &pem.Block{Type: blockType, Bytes: data})
	pemFile.Close()
}
