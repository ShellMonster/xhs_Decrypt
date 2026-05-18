package xhs

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// 自定义 Base64 字符表
const (
	B64Main = "ZmserbBoHQtNP+wOcza/LpngG8yJq42KWYj0DSfdikx3VT16IlUAFM97hECvuRX5"
	B64X3   = "MfgqrsbcyzPQRStuvC7mn501HIJBo2DEFTKdeNOwxWXYZap89+/A4UVLhijkl63G"
	B64Std  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)

// XOR 变换密钥（144 字节）
var xorKey []byte

func init() {
	h, _ := hex.DecodeString(
		"71a302257793271ddd273bcee3e4b98d9d7935e1da33f5765e2ea8afb6dc77a5" +
			"1a499d23b67c20660025860cbf13d4540d92497f58686c574e508f46e1956344" +
			"f39139bf4faf22a3eef120b79258145b2feb5193b6478669961298e79bedca64" +
			"6e1a693a926154a5a7a1bd1cf0dedb742f917a747a1e388b234f2277516db711" +
			"6035439730fa61e9822a0eca7bff72d8")
	xorKey = h
}

var (
	versionBytes = []byte{121, 104, 96, 41}
	a3Prefix     = []byte{2, 97, 51, 16}
)

var hashIV = [4]uint32{1831565813, 461845907, 2246822507, 3266489909}

var envTable = [15]byte{115, 248, 83, 102, 103, 201, 181, 131, 99, 94, 4, 68, 250, 132, 21}
var envChecks = [15]byte{0, 1, 18, 1, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0}

// CRC32 多项式
const crc32Poly uint32 = 0xEDB88320

var crcTable [256]uint32

func init() {
	for i := 0; i < 256; i++ {
		r := uint32(i)
		for j := 0; j < 8; j++ {
			if r&1 != 0 {
				r = (r >> 1) ^ crc32Poly
			} else {
				r >>= 1
			}
		}
		crcTable[i] = r
	}
}

// SignedHeaders 签名结果
type SignedHeaders struct {
	XS           string `json:"x-s"`
	XSCommon     string `json:"x-s-common"`
	XT           string `json:"x-t"`
	XB3TraceID   string `json:"x-b3-traceid"`
	XXRayTraceID string `json:"x-xray-traceid"`
	Body         string `json:"_body,omitempty"`
}

// md5Hex 计算 MD5 十六进制
func md5Hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// rotateLeft32 32位循环左移
func rotateLeft32(val uint32, n uint) uint32 {
	return (val << n) | (val >> (32 - n))
}

// customBase64Encode 自定义 Base64 编码
func customBase64Encode(data []byte, alphabet string) string {
	std := base64.StdEncoding.EncodeToString(data)
	lookup := make(map[byte]byte)
	for i := 0; i < 64; i++ {
		lookup[B64Std[i]] = alphabet[i]
	}
	result := make([]byte, len(std))
	for i, ch := range []byte(std) {
		if replacement, ok := lookup[ch]; ok {
			result[i] = replacement
		} else {
			result[i] = ch // '=' 保持不变
		}
	}
	return string(result)
}

// customBase64Decode 自定义 Base64 解码
func customBase64Decode(encoded, alphabet string) ([]byte, error) {
	lookup := make(map[byte]byte)
	for i := 0; i < 64; i++ {
		lookup[alphabet[i]] = B64Std[i]
	}
	raw := make([]byte, len(encoded))
	for i, ch := range []byte(encoded) {
		if replacement, ok := lookup[ch]; ok {
			raw[i] = replacement
		} else {
			raw[i] = ch
		}
	}
	return base64.StdEncoding.DecodeString(string(raw))
}

// crc32JS JS 风格 CRC32
func crc32JS(data string) int32 {
	c := uint32(0xFFFFFFFF)
	for _, ch := range data {
		b := byte(ch)
		c = crcTable[(c&0xFF)^uint32(b)] ^ (c >> 8)
	}
	u := ^c ^ crc32Poly
	return int32(u)
}

// customHashV2 4 轮混合哈希
func customHashV2(input []byte) []byte {
	s0, s1, s2, s3 := hashIV[0], hashIV[1], hashIV[2], hashIV[3]
	length := uint32(len(input))

	s0 ^= length
	s1 ^= length << 8
	s2 ^= length << 16
	s3 ^= length << 24

	for i := 0; i+8 <= len(input); i += 8 {
		v0 := binary.LittleEndian.Uint32(input[i : i+4])
		v1 := binary.LittleEndian.Uint32(input[i+4 : i+8])
		s0 = rotateLeft32(((s0+v0)&0xFFFFFFFF)^s2, 7)
		s1 = rotateLeft32(((v0^s1)+s3)&0xFFFFFFFF, 11)
		s2 = rotateLeft32(((s2+v1)&0xFFFFFFFF)^s0, 13)
		s3 = rotateLeft32(((s3^v1)+s1)&0xFFFFFFFF, 17)
	}

	t0 := s0 ^ length
	t1 := s1 ^ t0
	t2 := (s2 + t1) & 0xFFFFFFFF
	t3 := s3 ^ t2

	s0 = (rotateLeft32(t0, 9) + rotateLeft32(t2, 17)) & 0xFFFFFFFF
	s1 = rotateLeft32(t1, 13) ^ rotateLeft32(t3, 19)
	s2 = (rotateLeft32(t2, 17) + s0) & 0xFFFFFFFF
	s3 = rotateLeft32(t3, 19) ^ s1

	result := make([]byte, 16)
	binary.LittleEndian.PutUint32(result[0:4], s0)
	binary.LittleEndian.PutUint32(result[4:8], s1)
	binary.LittleEndian.PutUint32(result[8:12], s2)
	binary.LittleEndian.PutUint32(result[12:16], s3)
	return result
}

// xorTransform XOR 变换
func xorTransform(payload []byte) []byte {
	result := make([]byte, len(payload))
	for i, b := range payload {
		if i < len(xorKey) {
			result[i] = b ^ xorKey[i]
		} else {
			result[i] = b
		}
	}
	return result
}

// extractAPIPath 从 URI+body 中提取纯 API 路径
func extractAPIPath(s string) string {
	brace := strings.Index(s, "{")
	question := strings.Index(s, "?")
	if brace >= 0 && question >= 0 {
		if brace < question {
			return s[:brace]
		}
		return s[:question]
	} else if brace >= 0 {
		return s[:brace]
	} else if question >= 0 {
		return s[:question]
	}
	return s
}

// buildContentString 构建签名用内容字符串
func buildContentString(method, uri string, payload map[string]interface{}) string {
	method = strings.ToUpper(method)
	if method == "POST" {
		bodyJSON, _ := json.Marshal(payload)
		return uri + string(bodyJSON)
	}
	if len(payload) == 0 {
		return uri
	}
	parts := make([]string, 0, len(payload))
	for k, v := range payload {
		var valStr string
		switch tv := v.(type) {
		case []interface{}:
			strs := make([]string, len(tv))
			for i, item := range tv {
				strs[i] = fmt.Sprintf("%v", item)
			}
			valStr = strings.Join(strs, ",")
		case nil:
			valStr = ""
		default:
			valStr = fmt.Sprintf("%v", tv)
		}
		valStr = strings.ReplaceAll(valStr, "=", "%3D")
		parts = append(parts, k+"="+valStr)
	}
	return uri + "?" + strings.Join(parts, "&")
}

// buildPayload 构建 144 字节 payload
func buildPayload(hexParam, a1, appID, stringParam string, timestamp time.Time) []byte {
	seed := rand.Uint32()
	seedByte := byte(seed & 0xFF)

	payload := make([]byte, 0, 144)

	// 版本 (4B)
	payload = append(payload, versionBytes...)

	// 随机种子 (4B)
	seedBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(seedBuf, seed)
	payload = append(payload, seedBuf...)

	// 当前时间戳 ms (8B LE)
	tsMs := timestamp.UnixMilli()
	tsBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(tsBuf, uint64(tsMs))
	payload = append(payload, tsBuf...)

	// 页面加载时间戳 (8B LE)
	offset := rand.Intn(40) + 10
	effectiveTs := timestamp.Add(-time.Duration(offset) * time.Second).UnixMilli()
	etBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(etBuf, uint64(effectiveTs))
	payload = append(payload, etBuf...)

	// 序列值 (4B)
	seqBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(seqBuf, uint32(rand.Intn(35)+15))
	payload = append(payload, seqBuf...)

	// window.props 长度 (4B)
	wpBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(wpBuf, uint32(rand.Intn(200)+1000))
	payload = append(payload, wpBuf...)

	// URI 长度 (4B)
	uriBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(uriBuf, uint32(len(stringParam)))
	payload = append(payload, uriBuf...)

	// MD5 XOR (8B)
	md5Bytes, _ := hex.DecodeString(hexParam)
	md5XOR := make([]byte, 8)
	for i := 0; i < 8 && i < len(md5Bytes); i++ {
		md5XOR[i] = md5Bytes[i] ^ seedByte
	}
	payload = append(payload, md5XOR...)

	// a1 (1B 长度 + 52B 数据)
	a1Bytes := []byte(a1)
	if len(a1Bytes) > 52 {
		a1Bytes = a1Bytes[:52]
	}
	a1Padded := make([]byte, 52)
	copy(a1Padded, a1Bytes)
	payload = append(payload, byte(len(a1Padded)))
	payload = append(payload, a1Padded...)

	// app_id (1B 长度 + 10B 数据)
	appBytes := []byte(appID)
	if len(appBytes) > 10 {
		appBytes = appBytes[:10]
	}
	appPadded := make([]byte, 10)
	copy(appPadded, appBytes)
	payload = append(payload, byte(len(appPadded)))
	payload = append(payload, appPadded...)

	// 环境检测 (16B)
	env := make([]byte, 16)
	env[0] = 1
	env[1] = seedByte ^ envTable[0]
	for i := 1; i < 15; i++ {
		env[i+1] = envTable[i] ^ envChecks[i]
	}
	payload = append(payload, env...)

	// a3 hash (4B 前缀 + 16B hash)
	apiPath := extractAPIPath(stringParam)
	pathMD5 := md5Hex(apiPath)
	pathMD5Bytes, _ := hex.DecodeString(pathMD5)

	hashInput := make([]byte, 8+len(pathMD5Bytes))
	copy(hashInput[:8], tsBuf)
	copy(hashInput[8:], pathMD5Bytes)
	hashResult := customHashV2(hashInput)

	a3Data := make([]byte, 20)
	copy(a3Data[:4], a3Prefix)
	for i, b := range hashResult {
		a3Data[4+i] = b ^ seedByte
	}
	payload = append(payload, a3Data...)

	if len(payload) > 144 {
		return payload[:144]
	}
	return payload
}

// SignXS 生成 x-s 签名头
func SignXS(method, uri, a1 string, payload map[string]interface{}, timestamp time.Time) string {
	content := buildContentString(method, uri, payload)
	dValue := md5Hex(content)

	rawPayload := buildPayload(dValue, a1, "xhs-pc-web", content, timestamp)
	xored := xorTransform(rawPayload)
	x3B64 := customBase64Encode(xored, B64X3)

	x4 := ""
	if payload != nil && len(payload) > 0 {
		x4 = "object"
	}

	signData := map[string]string{
		"x0": "4.2.6",
		"x1": "xhs-pc-web",
		"x2": "PC",
		"x3": "mns0301_" + x3B64,
		"x4": x4,
	}
	signJSON, _ := json.Marshal(signData)
	return "XYS_" + customBase64Encode(signJSON, B64Main)
}

// SignXSCommon 生成 x-s-common 签名头
func SignXSCommon(a1 string) string {
	obj := map[string]interface{}{
		"s0":  5,
		"s1":  "",
		"x0":  "1",
		"x1":  "4.2.6",
		"x2":  "Windows",
		"x3":  "xhs-pc-web",
		"x4":  "4.86.0",
		"x5":  a1,
		"x6":  "",
		"x7":  "",
		"x8":  "",
		"x9":  int(crc32JS("")),
		"x10": 0,
		"x11": "normal",
	}
	signJSON, _ := json.Marshal(obj)
	return customBase64Encode(signJSON, B64Main)
}

// SignHeaders 生成完整签名头集合
func SignHeaders(method, uri string, cookies map[string]string, payload map[string]interface{}, timestamp time.Time) *SignedHeaders {
	a1 := cookies["a1"]
	if a1 == "" {
		a1 = cookies["a1"]
	}

	xs := SignXS(method, uri, a1, payload, timestamp)
	xsc := SignXSCommon(a1)
	xt := fmt.Sprintf("%d", timestamp.UnixMilli())

	// b3 trace id
	b3 := make([]byte, 8)
	rand.Read(b3)
	b3Hex := hex.EncodeToString(b3)

	// xray trace id
	tsInt := uint64(timestamp.UnixMilli())
	seq := rand.Intn(0x7FFFFF)
	part1 := fmt.Sprintf("%016x", (tsInt<<23)|uint64(seq))
	part2Bytes := make([]byte, 8)
	rand.Read(part2Bytes)
	part2 := fmt.Sprintf("%x", part2Bytes)
	if len(part2) > 16 {
		part2 = part2[:16]
	}
	for len(part2) < 16 {
		part2 = "0" + part2
	}
	xray := part1 + part2

	result := &SignedHeaders{
		XS:           xs,
		XSCommon:     xsc,
		XT:           xt,
		XB3TraceID:   b3Hex,
		XXRayTraceID: xray,
	}

	if strings.ToUpper(method) == "POST" && payload != nil {
		bodyJSON, _ := json.Marshal(payload)
		result.Body = string(bodyJSON)
	}

	return result
}
