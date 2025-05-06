package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath" // 用于处理文件路径
	"time"
)

const (
	listenPort    = ":5678"    // 服务器监听端口
	maxUploadSize = 10 << 20   // 10 MB，最大上传文件大小
	staticDir     = "./static" // 静态文件存放目录
)

// VerificationResponse 定义了返回给客户端的 JSON 结构体
type VerificationResponse struct {
	LocalFileHash  string `json:"local_file_hash"`  // 本地文件的 Hash 值
	RemoteFileHash string `json:"remote_file_hash"` // 远程文件的 Hash 值
	Match          bool   `json:"match"`            // Hash 值是否匹配
	Error          string `json:"error,omitempty"`  // 错误信息（如果发生错误）
}

// calculateHash 计算 reader 提供的数据的 SHA256 hash 值
func calculateHash(r io.Reader) (string, error) {
	hasher := sha256.New()
	if _, err := io.Copy(hasher, r); err != nil {
		return "", fmt.Errorf("无法复制数据到 hasher: %w", err)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// verifyHandler 处理 /verify API 端点的请求
func verifyHandler(w http.ResponseWriter, r *http.Request) {
	// 确保是 POST 请求
	if r.Method != http.MethodPost {
		http.Error(w, "仅支持 POST 方法", http.StatusMethodNotAllowed)
		return
	}

	// 1. 获取表单中的 remote_file_url
	remoteFileURL := r.FormValue("remote_file_url")
	if remoteFileURL == "" {
		respondWithError(w, "请求参数 'remote_file_url' 不能为空", "", "", false, http.StatusBadRequest)
		return
	}

	// 2. 处理本地上传文件
	// 限制请求体大小，防止过大文件上传
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		msg := fmt.Sprintf("无法解析表单数据: %v. 文件可能过大 (最大 %dMB)", err, maxUploadSize/(1<<20))
		respondWithError(w, msg, "", "", false, http.StatusBadRequest)
		return
	}

	uploadedFile, _, err := r.FormFile("local_file") // "local_file" 对应 HTML 表单中的 name
	if err != nil {
		respondWithError(w, "无法获取上传的文件 ('local_file'): "+err.Error(), "", "", false, http.StatusBadRequest)
		return
	}
	defer uploadedFile.Close()

	// 计算本地文件的 Hash
	localFileHash, err := calculateHash(uploadedFile)
	if err != nil {
		log.Printf("计算本地文件 hash 失败: %v\n", err)
		respondWithError(w, "计算本地文件 hash 失败: "+err.Error(), "", "", false, http.StatusInternalServerError)
		return
	}
	log.Printf("本地文件 Hash: %s\n", localFileHash)

	// 3. 下载远程文件并计算其 Hash
	var remoteFileHash string
	client := &http.Client{Timeout: 30 * time.Second} // 设置 HTTP client 超时
	resp, err := client.Get(remoteFileURL)
	if err != nil {
		log.Printf("下载远程文件失败 (%s): %v\n", remoteFileURL, err)
		respondWithError(w, fmt.Sprintf("下载远程文件失败 (%s): %v", remoteFileURL, err), localFileHash, "", false, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("下载远程文件时 HTTP 状态码错误: %d - %s\n", resp.StatusCode, resp.Status)
		errMsg := fmt.Sprintf("下载远程文件时 HTTP 状态码错误: %d - %s", resp.StatusCode, resp.Status)
		respondWithError(w, errMsg, localFileHash, "", false, resp.StatusCode)
		return
	}

	// 计算远程文件的 Hash
	remoteFileHash, err = calculateHash(resp.Body)
	if err != nil {
		log.Printf("计算远程文件 hash 失败: %v\n", err)
		respondWithError(w, "计算远程文件 hash 失败: "+err.Error(), localFileHash, "", false, http.StatusInternalServerError)
		return
	}
	log.Printf("远程文件 Hash (%s): %s\n", remoteFileURL, remoteFileHash)

	// 4. 比较 Hash 值并返回结果
	match := localFileHash == remoteFileHash
	response := VerificationResponse{
		LocalFileHash:  localFileHash,
		RemoteFileHash: remoteFileHash,
		Match:          match,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // 明确设置成功状态码
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("编码 JSON 响应失败: %v\n", err)
		http.Error(w, "服务器内部错误，无法编码响应", http.StatusInternalServerError)
	}
}

// respondWithError 是一个辅助函数，用于发送包含错误的 JSON 响应
func respondWithError(w http.ResponseWriter, errMsg string, localHash string, remoteHash string, match bool, statusCode int) {
	response := VerificationResponse{
		LocalFileHash:  localHash,
		RemoteFileHash: remoteHash,
		Match:          match,
		Error:          errMsg,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode) // 设置传入的状态码
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("编码错误 JSON 响应失败: %v\n", err)
		// 如果JSON编码也失败，则发送纯文本错误
		http.Error(w, errMsg, statusCode)
	}
}

// serveIndexHandler 处理对根路径 ("/") 的请求，提供 index.html 网页
func serveIndexHandler(w http.ResponseWriter, r *http.Request) {
	// 如果请求的不是根路径，则返回 404
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	// 构建 index.html 的完整路径
	htmlFilePath := filepath.Join(staticDir, "index.html")
	http.ServeFile(w, r, htmlFilePath)
}

func main() {
	// 检查静态文件目录和 index.html 是否存在
	indexPath := filepath.Join(staticDir, "index.html")
	if _, err := os.Stat(indexPath); os.IsNotExist(err) {
		log.Printf("警告: %s 文件未找到。Web 界面将不可用。", indexPath)
		log.Printf("请确保在项目根目录下的 '%s' 文件夹中有名为 'index.html' 的文件。", staticDir)
	} else {
		log.Printf("静态文件 index.html 路径: %s", indexPath)
	}

	// 设置路由处理器
	http.HandleFunc("/verify", verifyHandler) // API 端点
	http.HandleFunc("/", serveIndexHandler)   // 网页界面

	log.Printf("服务器正在启动，监听端口 %s\n", listenPort)
	log.Printf("请通过浏览器访问 http://localhost%s 来使用 Web 界面\n", listenPort)

	// 启动 HTTP 服务器
	if err := http.ListenAndServe(listenPort, nil); err != nil {
		log.Fatalf("无法启动服务器: %s\n", err)
	}
}
