#!/usr/bin/env python3
"""小红书签名算法 - 纯 Python 实现。

逆向自小红书前端 sec_ds_script.js / vendor-dynamic.js 的 mnsv2 签名链路。
算法结构：
  1. 构建 144 字节 payload（版本+随机种子+时间戳+MD5+a1+环境指纹+hash）
  2. 用固定 144 字节密钥 XOR 变换
  3. 用 X3 自定义 Base64 编码
  4. 加 "mns0301_" 前缀得到 x3
  5. 组装 JSON {x0:版本, x1:appid, x2:平台, x3:x3, x4:类型}
  6. 用主自定义 Base64 编码 JSON
  7. 加 "XYS_" 前缀得到 x-s
  8. x-s-common: 浏览器指纹 → CRC32 → 自定义 Base64
"""

import hashlib
import json
import os
import random
import struct
import time
import urllib.parse

# ============================================================
# 常量 - 从字节码字符串表和 VM 内存提取
# ============================================================

# 自定义 Base64 字符表（主表）
B64_MAIN = "ZmserbBoHQtNP+wOcza/LpngG8yJq42KWYj0DSfdikx3VT16IlUAFM97hECvuRX5"
# X3 专用 Base64 字符表
B64_X3 = "MfgqrsbcyzPQRStuvC7mn501HIJBo2DEFTKdeNOwxWXYZap89+/A4UVLhijkl63G"
# 标准 Base64
B64_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# XOR 变换密钥（144 字节，从字节码常量池提取）
XOR_KEY = bytes.fromhex(
    "71a302257793271ddd273bcee3e4b98d9d7935e1da33f5765e2ea8afb6dc77a5"
    "1a499d23b67c20660025860cbf13d4540d92497f58686c574e508f46e1956344"
    "f39139bf4faf22a3eef120b79258145b2feb5193b6478669961298e79bedca64"
    "6e1a693a926154a5a7a1bd1cf0dedb742f917a747a1e388b234f2277516db711"
    "6035439730fa61e9822a0eca7bff72d8"
)

# Payload 构建常量
VERSION_BYTES = [121, 104, 96, 41]  # yhX)
A3_PREFIX = [2, 97, 51, 16]         # a3 前缀
HASH_IV = (1831565813, 461845907, 2246822507, 3266489909)
ENV_TABLE = [115, 248, 83, 102, 103, 201, 181, 131, 99, 94, 4, 68, 250, 132, 21]
ENV_CHECKS = [0, 1, 18, 1, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0]

# x-s-common 模板
XSC_TEMPLATE = {
    "s0": 5, "s1": "", "x0": "1", "x1": "4.2.6", "x2": "Windows",
    "x3": "xhs-pc-web", "x4": "4.86.0", "x5": "", "x6": "", "x7": "",
    "x8": "", "x9": 0, "x10": 0, "x11": "normal",
}

# x-s 签名数据模板
XS_TEMPLATE = {"x0": "4.2.6", "x1": "xhs-pc-web", "x2": "PC", "x3": "", "x4": ""}

# b1 RC4 密钥
B1_KEY = b"xhswebmplfbt"

# CRC32 多项式
CRC32_POLY = 0xEDB88320


# ============================================================
# 基础工具
# ============================================================

def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def int_to_le(val: int, length: int = 4) -> list[int]:
    """整数转小端字节列表"""
    result = []
    for _ in range(length):
        result.append(val & 0xFF)
        val >>= 8
    return result


def rotate_left_32(val: int, n: int) -> int:
    """32 位循环左移"""
    return ((val << n) | (val >> (32 - n))) & 0xFFFFFFFF


# ============================================================
# 自定义 Base64
# ============================================================

def _b64_encode(data: bytes, alphabet: str) -> str:
    """通用自定义 Base64 编码"""
    std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    import base64
    encoded = base64.b64encode(data).decode("ascii")
    table = str.maketrans(std, alphabet)
    return encoded.translate(table)


def _b64_decode(text: str, alphabet: str) -> bytes:
    """通用自定义 Base64 解码"""
    std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    import base64
    table = str.maketrans(alphabet, std)
    return base64.b64decode(text.translate(table))


def b64_encode_main(data: bytes) -> str:
    return _b64_encode(data, B64_MAIN)


def b64_encode_x3(data: bytes) -> str:
    return _b64_encode(data, B64_X3)


# ============================================================
# CRC32（JS 兼容版本）
# ============================================================

_crc_table = None

def _ensure_crc_table():
    global _crc_table
    if _crc_table is not None:
        return
    _crc_table = [0] * 256
    for i in range(256):
        r = i
        for _ in range(8):
            r = ((r >> 1) ^ CRC32_POLY) if (r & 1) else (r >> 1)
            r &= 0xFFFFFFFF
        _crc_table[i] = r


def crc32_js(data: str) -> int:
    """JS 风格 CRC32，返回有符号 32 位整数"""
    _ensure_crc_table()
    c = 0xFFFFFFFF
    for ch in data:
        b = ord(ch) & 0xFF
        c = (_crc_table[(c & 0xFF) ^ b] ^ (c >> 8)) & 0xFFFFFFFF
    # (-1 ^ c ^ POLY) >>> 0
    u = (0xFFFFFFFF ^ c ^ CRC32_POLY) & 0xFFFFFFFF
    # 转有符号
    return u - 0x100000000 if (u & 0x80000000) else u


# ============================================================
# custom_hash_v2（a3 字段生成）
# ============================================================

def custom_hash_v2(input_bytes: list[int]) -> list[int]:
    """4 轮混合哈希，输出 16 字节"""
    s0, s1, s2, s3 = HASH_IV
    length = len(input_bytes)

    s0 ^= length
    s1 ^= length << 8
    s2 ^= length << 16
    s3 ^= length << 24

    for i in range(length // 8):
        v0 = struct.unpack_from("<I", bytes(input_bytes[i * 8:i * 8 + 4]))[0]
        v1 = struct.unpack_from("<I", bytes(input_bytes[i * 8 + 4:i * 8 + 8]))[0]
        s0 = rotate_left_32(((s0 + v0) & 0xFFFFFFFF) ^ s2, 7)
        s1 = rotate_left_32(((v0 ^ s1) + s3) & 0xFFFFFFFF, 11)
        s2 = rotate_left_32(((s2 + v1) & 0xFFFFFFFF) ^ s0, 13)
        s3 = rotate_left_32(((s3 ^ v1) + s1) & 0xFFFFFFFF, 17)

    t0 = s0 ^ length
    t1 = s1 ^ t0
    t2 = (s2 + t1) & 0xFFFFFFFF
    t3 = s3 ^ t2

    s0 = (rotate_left_32(t0, 9) + rotate_left_32(t2, 17)) & 0xFFFFFFFF
    s1 = rotate_left_32(t1, 13) ^ rotate_left_32(t3, 19)
    s2 = (rotate_left_32(t2, 17) + s0) & 0xFFFFFFFF
    s3 = rotate_left_32(t3, 19) ^ s1

    result = []
    for s in [s0, s1, s2, s3]:
        result.extend(int_to_le(s, 4))
    return result


# ============================================================
# XOR 变换
# ============================================================

def xor_transform(payload: list[int]) -> bytearray:
    """用 144 字节密钥 XOR 变换 payload"""
    result = bytearray(len(payload))
    for i in range(len(payload)):
        if i < len(XOR_KEY):
            result[i] = (payload[i] ^ XOR_KEY[i]) & 0xFF
        else:
            result[i] = payload[i] & 0xFF
    return result


# ============================================================
# 提取 API 路径
# ============================================================

def extract_api_path(uri_with_data: str) -> str:
    """从 URI+body 混合字符串中提取纯 API 路径"""
    brace = uri_with_data.find("{")
    question = uri_with_data.find("?")
    if brace >= 0 and question >= 0:
        return uri_with_data[: min(brace, question)]
    elif brace >= 0:
        return uri_with_data[:brace]
    elif question >= 0:
        return uri_with_data[:question]
    return uri_with_data


# ============================================================
# 构建请求内容字符串
# ============================================================

def build_content_string(method: str, uri: str, payload: dict | None = None) -> str:
    """构建签名用的内容字符串（url + body 拼接）"""
    payload = payload or {}
    if method.upper() == "POST":
        return uri + json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    else:
        if not payload:
            return uri
        parts = []
        for key, value in payload.items():
            if isinstance(value, (list, tuple)):
                val_str = ",".join(str(v) for v in value)
            elif value is not None:
                val_str = str(value)
            else:
                val_str = ""
            encoded = val_str.replace("=", "%3D")
            parts.append(f"{key}={encoded}")
        return f"{uri}?{'&'.join(parts)}"


# ============================================================
# 构建 144 字节 payload 数组
# ============================================================

def build_payload(
    hex_param: str,
    a1: str,
    app_id: str = "xhs-pc-web",
    string_param: str = "",
    timestamp: float | None = None,
) -> list[int]:
    """
    构建 144 字节 payload。

    布局：
      [0:4]   版本标识 (4B)
      [4:8]   随机种子 (4B)
      [8:16]  当前时间戳 ms (8B LE)
      [16:24] 页面加载时间戳 (8B LE)
      [24:28] 序列值 (4B)
      [28:32] window.props 长度 (4B)
      [32:36] URI 长度 (4B)
      [36:44] MD5 XOR (8B)
      [44:97] a1 (1B 长度 + 52B 数据)
      [97:108] app_id (1B 长度 + 10B 数据)
      [108:124] 环境检测 (16B)
      [124:144] a3 hash (4B 前缀 + 16B hash)
    """
    if timestamp is None:
        timestamp = time.time()

    seed = random.randint(0, 0xFFFFFFFF)
    seed_byte = seed & 0xFF

    payload: list[int] = []

    # 版本 (4B)
    payload.extend(VERSION_BYTES)

    # 随机种子 (4B)
    payload.extend(int_to_le(seed, 4))

    # 当前时间戳 ms (8B LE)
    ts_ms = int(timestamp * 1000)
    payload.extend(int_to_le(ts_ms, 8))

    # 页面加载时间戳 (8B LE) - 模拟浏览器
    offset = random.randint(10, 50)
    effective_ts = int((timestamp - offset) * 1000)
    payload.extend(int_to_le(effective_ts, 8))

    # 序列值 (4B)
    payload.extend(int_to_le(random.randint(15, 50), 4))

    # window.props 长度 (4B)
    payload.extend(int_to_le(random.randint(1000, 1200), 4))

    # URI 长度 (4B)
    uri_len = len(string_param.encode("utf-8"))
    payload.extend(int_to_le(uri_len, 4))

    # MD5 XOR (8B) - hex_param 的前 8 字节 XOR seed
    md5_bytes = bytes.fromhex(hex_param)
    payload.extend([md5_bytes[i] ^ seed_byte for i in range(8)])

    # a1 (1B 长度 + 52B 数据)
    a1_bytes = a1.encode("utf-8")[:52].ljust(52, b"\x00")
    payload.append(len(a1_bytes))
    payload.extend(a1_bytes)

    # app_id (1B 长度 + 10B 数据)
    app_bytes = app_id.encode("utf-8")[:10].ljust(10, b"\x00")
    payload.append(len(app_bytes))
    payload.extend(app_bytes)

    # 环境检测 (16B: 1字节常量 + seed^ENV_TABLE[0] + 14字节校验)
    env = [1, seed_byte ^ ENV_TABLE[0]] + [ENV_TABLE[i] ^ ENV_CHECKS[i] for i in range(1, 15)]
    payload.extend(env)

    # a3 hash (4B 前缀 + 16B hash)
    api_path = extract_api_path(string_param)
    api_path_bytes = api_path.encode("utf-8")
    md5_path = hashlib.md5(api_path_bytes).hexdigest()
    md5_path_bytes = [int(md5_path[i:i + 2], 16) for i in range(0, 32, 2)]

    ts_bytes = int_to_le(ts_ms, 8)
    hash_input = ts_bytes + md5_path_bytes
    hash_result = custom_hash_v2(hash_input)
    payload.extend(A3_PREFIX + [b ^ seed_byte for b in hash_result])

    return payload[:144]


# ============================================================
# 主签名函数
# ============================================================

def sign_xs(method: str, uri: str, a1: str, payload: dict | None = None,
            timestamp: float | None = None) -> str:
    """生成 x-s 签名头"""
    if timestamp is None:
        timestamp = time.time()

    content = build_content_string(method, uri, payload)
    d_value = md5_hex(content)

    # 构建 payload 并 XOR 变换
    raw_payload = build_payload(d_value, a1, "xhs-pc-web", content, timestamp)
    xored = xor_transform(raw_payload)

    # X3 Base64 编码
    x3_b64 = b64_encode_x3(bytes(xored[:144]))

    # 组装签名数据
    sign_data = dict(XS_TEMPLATE)
    sign_data["x3"] = "mns0301_" + x3_b64
    sign_data["x4"] = "object" if payload else ""

    sign_json = json.dumps(sign_data, separators=(",", ":"), ensure_ascii=False)
    return "XYS_" + b64_encode_main(sign_json.encode("utf-8"))


def sign_xs_common(a1: str) -> str:
    """生成 x-s-common 签名头"""
    obj = dict(XSC_TEMPLATE)
    obj["x5"] = a1
    # x8 和 x9 简化处理
    obj["x9"] = crc32_js("")
    sign_json = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    return b64_encode_main(sign_json.encode("utf-8"))


def sign_headers(method: str, uri: str, cookies: dict[str, str],
                 payload: dict | None = None,
                 timestamp: float | None = None) -> dict[str, str]:
    """生成完整的签名头集合。

    返回的 dict 包含签名头，以及可选的 _body 字段。
    _body 是序列化后的 body 字符串（紧凑 JSON），客户端应直接用 data=_body 发送，
    不能用 json=payload（因为 requests 的 json 会加空格，导致签名不一致）。
    """
    if timestamp is None:
        timestamp = time.time()

    a1 = cookies.get("a1", "")
    if not a1:
        raise ValueError("缺少 a1 cookie")

    xs = sign_xs(method, uri, a1, payload, timestamp)
    xsc = sign_xs_common(a1)
    xt = str(int(timestamp * 1000))
    b3 = os.urandom(8).hex()

    # xray trace id
    ts_int = int(timestamp * 1000)
    seq = random.randint(0, 0x7FFFFF)
    part1 = format((ts_int << 23) | seq, "016x")
    part2 = "".join(random.choice("abcdef0123456789") for _ in range(16))
    xray = part1 + part2

    result = {
        "x-s": xs,
        "x-s-common": xsc,
        "x-t": xt,
        "x-b3-traceid": b3,
        "x-xray-traceid": xray,
    }

    # POST 请求需要返回序列化后的 body，确保和签名一致
    if method.upper() == "POST" and payload:
        result["_body"] = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)

    return result


# ============================================================
# 测试
# ============================================================

if __name__ == "__main__":
    import requests as http_requests

    print("=== 纯 Python 签名测试 ===")

    # 1. 自测签名生成
    ts = time.time()
    a1 = "test_a1_value_1234567890"

    headers = sign_headers("GET", "/api/sns/web/v2/user/me", {"a1": a1}, timestamp=ts)
    print("签名头:")
    for k, v in headers.items():
        print(f"  {k}: {v[:80]}{'...' if len(v) > 80 else ''}")
    print(f"  x-s 长度: {len(headers['x-s'])}")

    # 2. 对比 Playwright 签名服务的输出
    print("\n--- 对比 Playwright 签名 ---")
    try:
        r = http_requests.post(
            "http://127.0.0.1:19231/sign",
            json={"url": "/api/sns/web/v2/user/me", "body": None, "a1": a1},
            timeout=5,
        )
        pw_headers = r.json()
        print("Playwright x-s 长度:", len(pw_headers.get("x-s", "")))
        print("Python   x-s 长度:", len(headers["x-s"]))
    except Exception as e:
        print(f"Playwright 签名服务不可用: {e}")

    # 3. 发起实际 API 请求验证
    print("\n--- 实际 API 请求验证 ---")
    req_h = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json;charset=UTF-8",
        "Origin": "https://www.xiaohongshu.com",
        "Referer": "https://www.xiaohongshu.com/",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
    }
    req_h.update(headers)

    resp = http_requests.get(
        "https://edith.xiaohongshu.com/api/sns/web/v2/user/me",
        headers=req_h,
        cookies={"a1": a1},
        timeout=15,
    )
    print(f"HTTP {resp.status_code}")
    data = resp.json()
    print(f"code: {data.get('code')}, msg: {data.get('msg')}")
    if data.get("code") == -101:
        print("签名验证通过（-101 = 未登录，非签名错误）")
    elif data.get("code") == 300:
        print("签名验证失败（300 = 签名错误）")
    else:
        print(f"返回: {json.dumps(data, ensure_ascii=False)[:200]}")
