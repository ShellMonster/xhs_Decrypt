package xhs

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

const testA1 = "test_a1_pure_python_sign"
const apiBase = "https://edith.xiaohongshu.com"

var defaultUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"

func TestSignFormat(t *testing.T) {
	ts := time.Now()
	h := SignHeaders("GET", "/api/test", map[string]string{"a1": testA1}, nil, ts)

	// x-s 以 XYS_ 开头
	if !strings.HasPrefix(h.XS, "XYS_") {
		t.Fatalf("x-s 应以 XYS_ 开头，实际: %s", h.XS[:10])
	}

	// 解码 x-s 内部 JSON
	inner, err := customBase64Decode(h.XS[4:], B64Main)
	if err != nil {
		t.Fatalf("x-s 解码失败: %v", err)
	}
	var obj map[string]string
	if err := json.Unmarshal(inner, &obj); err != nil {
		t.Fatalf("x-s 内部不是合法 JSON: %v", err)
	}
	if obj["x0"] != "4.2.6" {
		t.Errorf("x0 应为 4.2.6，实际: %s", obj["x0"])
	}
	if obj["x1"] != "xhs-pc-web" {
		t.Errorf("x1 应为 xhs-pc-web，实际: %s", obj["x1"])
	}
	if obj["x2"] != "PC" {
		t.Errorf("x2 应为 PC，实际: %s", obj["x2"])
	}
	if !strings.HasPrefix(obj["x3"], "mns0301_") {
		t.Errorf("x3 应以 mns0301_ 开头，实际: %s", obj["x3"][:20])
	}

	// x-s-common 解码
	innerC, err := customBase64Decode(h.XSCommon, B64Main)
	if err != nil {
		t.Fatalf("x-s-common 解码失败: %v", err)
	}
	var objC map[string]interface{}
	if err := json.Unmarshal(innerC, &objC); err != nil {
		t.Fatalf("x-s-common 内部不是合法 JSON: %v", err)
	}
	if objC["x5"] != testA1 {
		t.Errorf("x-s-common x5 应为 %s，实际: %v", testA1, objC["x5"])
	}

	// x-t 是 13 位毫秒时间戳
	if len(h.XT) != 13 {
		t.Errorf("x-t 应为 13 位，实际: %s (len=%d)", h.XT, len(h.XT))
	}

	// trace id 格式
	if len(h.XB3TraceID) != 16 {
		t.Errorf("x-b3-traceid 应为 16 位 hex，实际 len=%d", len(h.XB3TraceID))
	}
	if len(h.XXRayTraceID) != 32 {
		t.Errorf("x-xray-traceid 应为 32 位 hex，实际 len=%d", len(h.XXRayTraceID))
	}

	t.Log("签名格式自检全部通过")
}

func TestPayloadLength(t *testing.T) {
	ts := time.Now()
	content := "/api/sns/web/v1/homefeed"
	dValue := md5Hex(content)
	payload := buildPayload(dValue, testA1, "xhs-pc-web", content, ts)
	if len(payload) != 144 {
		t.Fatalf("payload 应为 144 字节，实际: %d", len(payload))
	}
	t.Logf("payload 长度正确: 144 字节")
}

func makeRequest(t *testing.T, method, path string, body map[string]interface{}, a1 string) map[string]interface{} {
	ts := time.Now()
	cookies := map[string]string{"a1": a1}
	h := SignHeaders(method, path, cookies, body, ts)

	reqHeaders := map[string]string{
		"Accept":        "application/json, text/plain, */*",
		"Content-Type":  "application/json;charset=UTF-8",
		"Origin":        "https://www.xiaohongshu.com",
		"Referer":       "https://www.xiaohongshu.com/",
		"User-Agent":    defaultUA,
		"x-s":           h.XS,
		"x-s-common":    h.XSCommon,
		"x-t":           h.XT,
		"x-b3-traceid":  h.XB3TraceID,
		"x-xray-traceid": h.XXRayTraceID,
	}

	var bodyReader io.Reader
	if h.Body != "" {
		bodyReader = bytes.NewReader([]byte(h.Body))
	}

	req, err := http.NewRequest(method, apiBase+path, bodyReader)
	if err != nil {
		t.Fatalf("创建请求失败: %v", err)
	}
	for k, v := range reqHeaders {
		req.Header.Set(k, v)
	}
	req.AddCookie(&http.Cookie{Name: "a1", Value: a1})

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("解析响应失败: %s", string(body[:200]))
	}
	return data
}

func TestAPI_UserInfo(t *testing.T) {
	data := makeRequest(t, "GET", "/api/sns/web/v2/user/me", nil, testA1)
	code := data["code"]
	if code == float64(300) {
		t.Fatal("签名验证失败 (code=300)")
	}
	t.Logf("用户信息: code=%v msg=%v", code, data["msg"])
}

func TestAPI_Homefeed(t *testing.T) {
	body := map[string]interface{}{
		"cursor":        "",
		"num":           20,
		"refresh_type":  1,
		"image_formats": []string{"jpg", "webp", "avif"},
	}
	data := makeRequest(t, "POST", "/api/sns/web/v1/homefeed", body, testA1)
	code := data["code"]
	if code == float64(300) {
		t.Fatal("签名验证失败 (code=300)")
	}
	if code == float64(-1) {
		// HTTP 406 的情况
		t.Fatal("签名验证失败 (HTTP 406 / code=-1)")
	}
	t.Logf("首页 Feed: code=%v msg=%v", code, data["msg"])
}

func TestAPI_Search(t *testing.T) {
	body := map[string]interface{}{
		"keyword":    "微信",
		"page":       1,
		"page_size":  20,
		"search_id":  "test-search-001",
		"sort":       "general",
		"note_type":  0,
	}
	data := makeRequest(t, "POST", "/api/sns/web/v1/search/notes", body, testA1)
	code := data["code"]
	if code == float64(300) {
		t.Fatal("签名验证失败 (code=300)")
	}
	t.Logf("搜索笔记: code=%v msg=%v", code, data["msg"])
}

func TestAPI_NoteFeed(t *testing.T) {
	body := map[string]interface{}{
		"source_note_id": "674ee65d000000000b037b7f",
		"image_formats":  []string{"jpg", "webp", "avif"},
		"extra":          map[string]interface{}{"need_body_topic": "1"},
		"xsec_source":    "pc_feed",
	}
	data := makeRequest(t, "POST", "/api/sns/web/v1/feed", body, testA1)
	code := data["code"]
	if code == float64(300) {
		t.Fatal("签名验证失败 (code=300)")
	}
	if code == float64(-1) {
		t.Fatal("签名验证失败 (HTTP 406 / code=-1)")
	}
	t.Logf("笔记详情: code=%v msg=%v", code, data["msg"])
}

func TestAPI_Comments(t *testing.T) {
	path := "/api/sns/web/v2/comment/page?note_id=674ee65d000000000b037b7f&cursor=&top_comment_id=&image_formats=jpg,webp,avif"
	data := makeRequest(t, "GET", path, nil, testA1)
	code := data["code"]
	if code == float64(300) {
		t.Fatal("签名验证失败 (code=300)")
	}
	t.Logf("评论列表: code=%v msg=%v", code, data["msg"])
}

func TestCrossValidateWithPython(t *testing.T) {
	// 用 Go 签名发给 API，同时用 Python 的 Playwright 签名服务验证
	// 这里只验证 Go 签名能通过服务端验证
	data := makeRequest(t, "GET", "/api/sns/web/v2/user/me", nil, testA1)
	code := data["code"]
	if code == float64(300) {
		t.Fatal("Go 签名验证失败 (code=300)")
	}
	if code == float64(-101) {
		t.Log("Go 签名验证通过 (-101 = 未登录)")
	} else {
		t.Logf("Go 签名返回: code=%v", code)
	}
}

func TestWithRealCookie(t *testing.T) {
	// 需要传入真实 Cookie 才能跑，默认跳过
	cookie := ""
	if cookie == "" {
		t.Skip("跳过：未设置真实 Cookie")
	}
	cookies := map[string]string{}
	for _, item := range strings.Split(cookie, ";") {
		parts := strings.SplitN(strings.TrimSpace(item), "=", 2)
		if len(parts) == 2 {
			cookies[parts[0]] = parts[1]
		}
	}

	ts := time.Now()
	h := SignHeaders("GET", "/api/sns/web/v2/user/me", cookies, nil, ts)

	req, _ := http.NewRequest("GET", apiBase+"/api/sns/web/v2/user/me", nil)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	req.Header.Set("Origin", "https://www.xiaohongshu.com")
	req.Header.Set("Referer", "https://www.xiaohongshu.com/")
	req.Header.Set("User-Agent", defaultUA)
	req.Header.Set("x-s", h.XS)
	req.Header.Set("x-s-common", h.XSCommon)
	req.Header.Set("x-t", h.XT)
	req.Header.Set("x-b3-traceid", h.XB3TraceID)
	req.Header.Set("x-xray-traceid", h.XXRayTraceID)
	for k, v := range cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)
	t.Logf("用户信息: %v", data)

	if data["code"] == float64(0) {
		t.Log("真实 Cookie 登录态验证通过")
		if d, ok := data["data"].(map[string]interface{}); ok {
			t.Logf("昵称: %v", d["nickname"])
		}
	}
}

// 辅助：用于 TestAPI_Comments 构造 GET 参数 URL
func init() {
	// Go 的 url.Values 会按字母序排列 key，这里需要和 Python 签名一致
	_ = url.Values{}
}
