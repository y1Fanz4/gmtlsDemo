// client/main.go - 国密 TLS 客户端 (交互版)
package main

import (
	"bufio"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/tjfoc/gmsm/gmtls"
	"github.com/tjfoc/gmsm/x509"
)

func main() {
	certDir := filepath.Join("..", "certs")

	// 加载客户端证书
	clientCert, err := gmtls.LoadX509KeyPair(
		filepath.Join(certDir, "client.crt"),
		filepath.Join(certDir, "client.key"),
	)
	if err != nil {
		log.Fatalf("加载客户端证书失败: %v", err)
	}

	// 加载 CA 证书，校验 PEM 块是否有效
	caCertPEM, err := os.ReadFile(filepath.Join(certDir, "ca.crt"))
	if err != nil {
		log.Fatalf("读取 CA 证书失败: %v", err)
	}
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		log.Fatal("CA 证书 PEM 解析失败：文件格式无效")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("解析 CA 证书失败: %v", err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)

	// 配置国密 TLS 客户端
	config := &gmtls.Config{
		GMSupport:          &gmtls.GMSupport{},
		Certificates:       []gmtls.Certificate{clientCert},
		RootCAs:            certPool,
		ServerName:         "localhost",
		InsecureSkipVerify: true, // 演示环境跳过域名验证
	}

	fmt.Println("========================================")
	fmt.Println("  正在连接国密 TLS 服务端...")
	fmt.Println("  地址: localhost:8443")
	fmt.Println("  协议: GMSSL 1.0 (SM2+SM3+SM4)")
	fmt.Println("========================================")

	conn, err := gmtls.Dial("tcp", "localhost:8443", config)
	if err != nil {
		log.Fatalf("连接服务端失败: %v", err)
	}
	defer conn.Close()

	// 主动触发 TLS 握手，确保握手完成后再读取连接状态
	if err := conn.Handshake(); err != nil {
		log.Fatalf("TLS 握手失败: %v", err)
	}

	// 打印 TLS 握手信息
	state := conn.ConnectionState()
	fmt.Println("\n✓ 国密 TLS 握手成功")
	fmt.Printf("  密码套件: 0x%04X\n", state.CipherSuite)
	if len(state.PeerCertificates) > 0 {
		fmt.Printf("  服务端证书 CN: %s\n", state.PeerCertificates[0].Subject.CommonName)
	}
	fmt.Println("\n  输入消息后回车发送，输入 'exit' 退出")
	fmt.Println("========================================\n")

	// bufio.Reader 保证按行完整读取服务端响应
	connReader := bufio.NewReader(conn)
	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("请输入要发送的消息 > ")
		if !scanner.Scan() {
			// 区分 EOF 与真实错误
			if err := scanner.Err(); err != nil {
				log.Printf("读取输入失败: %v", err)
			}
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if strings.ToLower(input) == "exit" {
			break
		}
		// 跳过空行，避免发送无意义消息
		if input == "" {
			continue
		}

		// 发送消息，以 '\n' 作为帧结束标志
		if _, err := fmt.Fprintf(conn, "%s\n", input); err != nil {
			log.Printf("发送消息失败: %v", err)
			break
		}

		// ReadString 阻塞直到读到 '\n'，保证接收完整响应
		response, err := connReader.ReadString('\n')
		if err != nil {
			log.Printf("读取响应失败: %v", err)
			break
		}

		response = strings.TrimRight(response, "\r\n")
		fmt.Println("----------------------------------------")
		fmt.Printf("  服务端响应 (%d 字节):\n", len(response))
		fmt.Printf("  %s\n", response)
		fmt.Println("----------------------------------------\n")
	}

	fmt.Println("\n========================================")
	fmt.Println("  国密 TLS 通信结束")
	fmt.Println("========================================")
}
