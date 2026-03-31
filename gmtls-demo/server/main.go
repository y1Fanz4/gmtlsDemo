// server/main.go - 国密 TLS 服务端 (交互版)
package main

import (
	"bufio"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/tjfoc/gmsm/gmtls"
	"github.com/tjfoc/gmsm/x509"
)

// logger 用互斥锁保护多 goroutine 并发打印，避免输出交错
var (
	logMu sync.Mutex
)

func logf(format string, args ...interface{}) {
	logMu.Lock()
	defer logMu.Unlock()
	fmt.Printf(format, args...)
}

func main() {
	certDir := filepath.Join("..", "certs")

	// 国密双证书：签名证书用于握手认证，加密证书用于密钥交换
	serverSignCert, err := gmtls.LoadX509KeyPair(
		filepath.Join(certDir, "server_sign.crt"),
		filepath.Join(certDir, "server_sign.key"),
	)
	if err != nil {
		log.Fatalf("加载服务端签名证书失败: %v", err)
	}

	serverEncCert, err := gmtls.LoadX509KeyPair(
		filepath.Join(certDir, "server_enc.crt"),
		filepath.Join(certDir, "server_enc.key"),
	)
	if err != nil {
		log.Fatalf("加载服务端加密证书失败: %v", err)
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

	// 配置国密 TLS
	config := &gmtls.Config{
		GMSupport: &gmtls.GMSupport{},
		// 国密双证书：第一个为签名证书，第二个为加密证书，两者密钥对不同
		Certificates: []gmtls.Certificate{serverSignCert, serverEncCert},
		ClientCAs:    certPool,
		ClientAuth:   gmtls.NoClientCert, // 演示环境不要求客户端证书
	}

	listener, err := gmtls.Listen("tcp", "localhost:8443", config)
	if err != nil {
		log.Fatalf("启动 TLS 监听失败: %v", err)
	}
	defer listener.Close()

	fmt.Println("========================================")
	fmt.Println("  国密 TLS 服务端已启动")
	fmt.Println("  监听地址: localhost:8443")
	fmt.Println("========================================\n")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("接受连接失败: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Accept 返回的是 *gmtls.Conn，需类型断言后才能调用 Handshake / ConnectionState
	gmConn, ok := conn.(*gmtls.Conn)
	if !ok {
		logf("[%s] 类型断言失败：非国密 TLS 连接\n", conn.RemoteAddr())
		return
	}

	// 强制完成服务端 TLS 握手，确保 ConnectionState 正确
	if err := gmConn.Handshake(); err != nil {
		logf("[%s] TLS 握手失败: %v\n", conn.RemoteAddr(), err)
		return
	}

	remoteAddr := conn.RemoteAddr().String()

	// 打印握手信息
	state := gmConn.ConnectionState()
	logf("[%s] 新连接建立 | 密码套件: 0x%04X\n", remoteAddr, state.CipherSuite)
	if len(state.PeerCertificates) > 0 {
		logf("[%s] 客户端证书 CN: %s\n", remoteAddr, state.PeerCertificates[0].Subject.CommonName)
	}

	// bufio.Reader 按行读取，与客户端 '\n' 帧协议对齐
	reader := bufio.NewReader(conn)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			// 连接正常关闭（EOF）不打印错误
			if err.Error() != "EOF" {
				logf("[%s] 读取消息失败: %v\n", remoteAddr, err)
			} else {
				logf("[%s] 连接已关闭\n", remoteAddr)
			}
			return
		}

		// 去掉帧结束符，得到干净的消息内容
		msg := strings.TrimRight(line, "\r\n")
		if msg == "" {
			continue
		}

		logf("[%s] 收到消息 (%d 字节): %s\n", remoteAddr, len(msg), msg)

		// 构造响应，末尾加 '\n' 作为帧结束标志
		response := fmt.Sprintf("服务端已收到消息[%s]\n", msg)
		if _, err := fmt.Fprint(conn, response); err != nil {
			logf("[%s] 发送响应失败: %v\n", remoteAddr, err)
			return
		}
	}
}
