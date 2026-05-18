# 小红书 Web 签名算法逆向

逆向自小红书 Web 端 `sec_ds_script.js` / `vendor-dynamic.js` 中的 mnsv2 签名链路，纯算法实现，不依赖浏览器环境。

## 签名原理

小红书 Web 端的业务请求（`edith.xiaohongshu.com`）需要携带以下签名头：

| 头字段 | 说明 |
|--------|------|
| `x-s` | 主签名，包含 mnsv2 算法生成的 x3 payload |
| `x-s-common` | 设备指纹签名 |
| `x-t` | 毫秒时间戳 |
| `x-b3-traceid` | 随机 trace id |
| `x-xray-traceid` | 链路追踪 id |

### x-s 签名链路

```
1. 构建 144 字节 payload（版本 + 随机种子 + 时间戳 + MD5 + a1 + 环境指纹 + 哈希）
2. 用 144 字节固定密钥做 XOR 变换
3. 用 X3 自定义 Base64 编码
4. 加 "mns0301_" 前缀
5. 组装 JSON {x0, x1, x2, x3, x4}
6. 用主自定义 Base64 编码 JSON
7. 加 "XYS_" 前缀
```

### 144 字节 Payload 布局

| 偏移 | 长度 | 字段 |
|------|------|------|
| 0 | 4 | 版本标识 |
| 4 | 4 | 随机种子 |
| 8 | 8 | 当前时间戳（毫秒，小端序） |
| 16 | 8 | 页面加载时间戳（毫秒，小端序） |
| 24 | 4 | 序列值 |
| 28 | 4 | window.props 长度 |
| 32 | 4 | URI 长度 |
| 36 | 8 | MD5 XOR |
| 44 | 53 | a1 cookie（1 字节长度 + 52 字节数据） |
| 97 | 11 | app_id（1 字节长度 + 10 字节数据） |
| 108 | 16 | 环境检测指纹 |
| 124 | 20 | a3 哈希（4 字节前缀 + 16 字节哈希值） |

## 项目结构

```
├── Python/
│   ├── xhs_pure_sign.py        # 签名核心算法
│   ├── xiaohongshu_client.py   # API 客户端
│   └── test_xhs_sign.py        # 全量测试
│
├── Go/
│   ├── xhs_sign.go             # 签名核心算法
│   ├── xhs_sign_test.go        # 单元测试 + 接口测试
│   ├── go.mod
│   └── cmd/test_real_cookie/   # 真实 Cookie 集成验证
│       └── main.go
│
└── README.md
```

## 使用方法

### Python

```python
from xhs_pure_sign import sign_headers

# 生成签名头
headers = sign_headers("GET", "/api/sns/web/v2/user/me", {"a1": "your_a1_cookie"})

# headers 包含: x-s, x-s-common, x-t, x-b3-traceid, x-xray-traceid
# POST 请求额外返回 _body 字段（紧凑 JSON，确保签名一致性）
```

```bash
# 运行测试
python test_xhs_sign.py

# 使用客户端
python xiaohongshu_client.py --cookie 'a1=xxx;web_session=xxx' --probe
```

### Go

```go
import xhs "xhs-sign"

headers := xhs.SignHeaders("GET", "/api/sns/web/v2/user/me",
    map[string]string{"a1": "your_a1_cookie"},
    nil, time.Now())
```

```bash
# 运行测试
go test -v ./...

# 真实 Cookie 验证
go run cmd/test_real_cookie/main.go
```

## 测试结果

使用测试 a1 cookie（无登录态）：

| 接口 | 方法 | 结果 |
|------|------|------|
| 用户信息 `/api/sns/web/v2/user/me` | GET | 通过（-101 未登录） |
| 首页 Feed `/api/sns/web/v1/homefeed` | POST | 通过（-101 未登录） |
| 搜索笔记 `/api/sns/web/v1/search/notes` | POST | 通过（-101 未登录） |
| 笔记详情 `/api/sns/web/v1/feed` | POST | 通过（-101 未登录） |
| 评论列表 `/api/sns/web/v2/comment/page` | GET | 通过（-101 未登录） |

- 返回 `-101` 表示签名正确但未登录，返回 `406` 或 `code=300` 才是签名错误。
- 传入真实 `a1` + `web_session` cookie 后，所有接口返回 `code=0` 正常业务数据。

## 技术说明

- mnsv2 算法被 jsvmp（JS 虚拟机保护）包裹，核心逻辑在自定义字节码虚拟机中执行。
- 本项目通过逆向 jsvmp 字节码，提取出完整的 payload 构建逻辑、XOR 密钥、自定义 Base64 字符表和哈希算法。
- Python 和 Go 实现完全等价，签名结果均可通过服务端验证。

## Cookie 获取

Chrome 登录 `xiaohongshu.com` → F12 Network → 找到 `edith.xiaohongshu.com` 的请求 → 复制 Cookie 头。关键字段：

- `a1`：设备指纹，必须固定，不能每次换新
- `web_session`：登录凭证

## 许可证

[MIT License](LICENSE)
