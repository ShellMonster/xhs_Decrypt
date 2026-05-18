package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"xhs-sign"
)

const apiBase = "https://edith.xiaohongshu.com"
const defaultUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"

func parseCookie(raw string) map[string]string {
	m := make(map[string]string)
	for _, item := range strings.Split(raw, ";") {
		item = strings.TrimSpace(item)
		if idx := strings.Index(item, "="); idx > 0 {
			m[item[:idx]] = item[idx+1:]
		}
	}
	return m
}

func doRequest(client *http.Client, method, path string, body map[string]interface{}, cookies map[string]string) map[string]interface{} {
	ts := time.Now()
	h := xhs.SignHeaders(method, path, cookies, body, ts)

	req, _ := http.NewRequest(method, apiBase+path, nil)
	if h.Body != "" {
		req, _ = http.NewRequest(method, apiBase+path, strings.NewReader(h.Body))
	}

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

	resp, err := client.Do(req)
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	var data map[string]interface{}
	json.Unmarshal(bodyBytes, &data)
	data["_status"] = resp.StatusCode
	return data
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("用法: test_real_cookie <cookie字符串>")
		fmt.Println("示例: test_real_cookie 'a1=xxx;web_session=xxx'")
		os.Exit(1)
	}
	cookieRaw := os.Args[1]

	cookies := parseCookie(cookieRaw)
	client := &http.Client{Timeout: 15 * time.Second}

	fmt.Println("=== 1. 用户信息 ===")
	r := doRequest(client, "GET", "/api/sns/web/v2/user/me", nil, cookies)
	code, _ := r["code"].(float64)
	fmt.Printf("code=%.0f msg=%v\n", code, r["msg"])
	if d, ok := r["data"].(map[string]interface{}); ok && code == 0 {
		fmt.Printf("昵称: %v  red_id: %v\n", d["nickname"], d["red_id"])
	}

	fmt.Println("\n=== 2. 首页 Feed ===")
	r = doRequest(client, "POST", "/api/sns/web/v1/homefeed", map[string]interface{}{
		"cursor": "", "num": 20, "refresh_type": 1,
		"image_formats": []string{"jpg", "webp", "avif"},
	}, cookies)
	code, _ = r["code"].(float64)
	fmt.Printf("code=%.0f msg=%v\n", code, r["msg"])
	if d, ok := r["data"].(map[string]interface{}); ok {
		if items, ok := d["items"].([]interface{}); ok {
			fmt.Printf("Feed 条数: %d\n", len(items))
			for i, item := range items {
				if i >= 3 {
					break
				}
				if nc, ok := item.(map[string]interface{})["note_card"].(map[string]interface{}); ok {
					title, _ := nc["title"].(string)
					user, _ := nc["user"].(map[string]interface{})
					nickname, _ := user["nickname"].(string)
					ii, _ := nc["interact_info"].(map[string]interface{})
					liked, _ := ii["liked_count"].(string)
					if len(title) > 40 {
						title = title[:40]
					}
					fmt.Printf("  - %s | 作者: %s | 赞: %s\n", title, nickname, liked)
				}
			}
		}
	}

	fmt.Println("\n=== 3. 搜索笔记 ===")
	r = doRequest(client, "POST", "/api/sns/web/v1/search/notes", map[string]interface{}{
		"keyword": "微信", "page": 1, "page_size": 20,
		"search_id": "test-search-go-001", "sort": "general", "note_type": 0,
	}, cookies)
	code, _ = r["code"].(float64)
	fmt.Printf("code=%.0f msg=%v\n", code, r["msg"])
	if d, ok := r["data"].(map[string]interface{}); ok {
		if items, ok := d["items"].([]interface{}); ok {
			fmt.Printf("搜索结果: %d 条\n", len(items))
			for i, item := range items {
				if i >= 3 {
					break
				}
				if nc, ok := item.(map[string]interface{})["note_card"].(map[string]interface{}); ok {
					title, _ := nc["title"].(string)
					user, _ := nc["user"].(map[string]interface{})
					nickname, _ := user["nickname"].(string)
					if len(title) > 40 {
						title = title[:40]
					}
					fmt.Printf("  - %s | 作者: %s\n", title, nickname)
				}
			}
		}
	}

	fmt.Println("\n=== 4. 笔记详情 ===")
	r = doRequest(client, "POST", "/api/sns/web/v1/feed", map[string]interface{}{
		"source_note_id": "674ee65d000000000b037b7f",
		"image_formats":  []string{"jpg", "webp", "avif"},
		"extra":          map[string]interface{}{"need_body_topic": "1"},
		"xsec_source":    "pc_feed",
	}, cookies)
	code, _ = r["code"].(float64)
	fmt.Printf("code=%.0f msg=%v\n", code, r["msg"])

	fmt.Println("\n=== 5. 评论 ===")
	r = doRequest(client, "GET", "/api/sns/web/v2/comment/page?note_id=674ee65d000000000b037b7f&cursor=&top_comment_id=&image_formats=jpg,webp,avif", nil, cookies)
	code, _ = r["code"].(float64)
	fmt.Printf("code=%.0f msg=%v\n", code, r["msg"])

	fmt.Println("\n=== 总结 ===")
	fmt.Println("Go 版签名算法验证完毕")
}
