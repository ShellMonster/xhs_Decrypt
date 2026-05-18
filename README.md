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

| 接口 | 方法 | 匿名态（仅 a1） | 登录态（a1 + web_session） |
|------|------|-----------------|---------------------------|
| 用户信息 `/api/sns/web/v2/user/me` | GET | code=-101 未登录 | code=0，返回昵称、用户ID |
| 首页 Feed `/api/sns/web/v1/homefeed` | POST | code=-101 未登录 | code=0，返回推荐笔记列表 |
| 搜索笔记 `/api/sns/web/v1/search/notes` | POST | code=-101 未登录 | code=0，返回搜索结果 |
| 笔记详情 `/api/sns/web/v1/feed` | POST | code=-101 未登录 | code=0，返回笔记内容（笔记有效时） |
| 评论列表 `/api/sns/web/v2/comment/page` | GET | code=-101 未登录 | code=0，返回评论数据（笔记有效时） |

- 返回 `-101` 表示签名正确但未登录，返回 `406` 或 `code=300` 才是签名错误。
- Python 测试 19/19 通过，Go 测试 8/8 通过。

## 技术说明

- mnsv2 算法被 jsvmp（JS 虚拟机保护）包裹，核心逻辑在自定义字节码虚拟机中执行。
- 本项目通过逆向 jsvmp 字节码，提取出完整的 payload 构建逻辑、XOR 密钥、自定义 Base64 字符表和哈希算法。
- **纯算法实现，零外部依赖**：Python 版仅使用标准库（`hashlib`、`json`、`base64` 等），Go 版同样仅使用标准库。不依赖 Playwright 浏览器、Node.js、jsvmp 虚拟机或任何第三方 SDK。
- Python 和 Go 实现完全等价，签名结果均可通过服务端验证。
- 签名通过后，所有 `edith.xiaohongshu.com` 接口均可正常访问，能否拿到数据取决于登录态。

## Cookie 获取

Chrome 登录 `xiaohongshu.com` → F12 Network → 找到 `edith.xiaohongshu.com` 的请求 → 复制 Cookie 头。关键字段：

- `a1`：设备指纹，必须固定，不能每次换新
- `web_session`：登录凭证

## 免责声明

本项目仅供学习、研究和技术交流之用，严禁用于任何商业用途。

- 本项目与小红书（行吟信息科技）没有任何关联，未获得任何官方授权或认可。
- 本项目中的算法实现仅是对公开前端脚本的技术分析成果，不涉及服务端攻击、数据窃取等行为。
- 使用本项目所产生的一切法律后果由使用者自行承担，开发者不对任何因使用本项目导致的直接或间接损失负责。
- 请在遵守当地法律法规和小红书用户服务协议的前提下使用本项目。任何违反法律法规或平台规则的行为与本项目无关。
- 如小红书官方认为本项目侵犯其合法权益，请通过 GitHub Issue 或邮件联系，我们将第一时间配合处理。

## 许可证

[MIT License](LICENSE)
