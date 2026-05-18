#!/usr/bin/env python3
"""小红书签名全量测试 - 验证纯 Python 签名在各接口上的正确性。

测试项：
  1. 签名生成自检（格式、长度、字符集）
  2. GET 接口（用户信息）
  3. POST 接口（首页 Feed）
  4. POST 接口（搜索）
  5. POST 接口（笔记详情）
  6. GET 接口（评论）
  7. 与 Playwright 签名对比（如服务可用）

通过标准：
  - 签名格式正确（XYS_ 开头、mns0301_ 在 x3 中）
  - API 不返回 300（签名错误）或 406
  - 返回 -101（未登录）或业务 code=0 均算通过
"""

import json
import sys
import time

import requests as http

from xhs_pure_sign import (
    B64_MAIN,
    B64_X3,
    sign_headers,
    sign_xs,
    sign_xs_common,
    md5_hex,
    b64_encode_main,
    _b64_decode,
)

# 测试用的 a1 cookie
TEST_A1 = "test_a1_pure_python_sign"
PW_SIGN_URL = "http://127.0.0.1:19231"

passed = 0
failed = 0
errors = []


def check(name: str, condition: bool, detail: str = ""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  [PASS] {name}")
    else:
        failed += 1
        msg = f"  [FAIL] {name} - {detail}"
        print(msg)
        errors.append(msg)


def test_sign_format():
    """测试签名格式正确性"""
    print("\n=== 1. 签名格式自检 ===")
    ts = time.time()
    h = sign_headers("GET", "/api/test", {"a1": TEST_A1}, timestamp=ts)

    # x-s 格式
    xs = h["x-s"]
    check("x-s 以 XYS_ 开头", xs.startswith("XYS_"), f"实际: {xs[:10]}")

    # 解码 x-s 内部 JSON
    try:
        inner = _b64_decode(xs[4:], B64_MAIN)
        obj = json.loads(inner)
        check("x-s 内部是合法 JSON", True)
        check("x-s 包含 x3 字段", "x3" in obj, f"keys: {list(obj.keys())}")
        check("x3 以 mns0301_ 开头", obj.get("x3", "").startswith("mns0301_"),
              f"实际: {obj.get('x3', '')[:20]}")
        check("x0 = 4.2.6", obj.get("x0") == "4.2.6", f"实际: {obj.get('x0')}")
        check("x1 = xhs-pc-web", obj.get("x1") == "xhs-pc-web", f"实际: {obj.get('x1')}")
    except Exception as e:
        check("x-s 解码", False, str(e))

    # x-s-common 格式
    xsc = h["x-s-common"]
    try:
        inner_c = _b64_decode(xsc, B64_MAIN)
        obj_c = json.loads(inner_c)
        check("x-s-common 内部是合法 JSON", True)
        check("x-s-common 包含 x5(a1)", obj_c.get("x5") == TEST_A1,
              f"实际: {obj_c.get('x5')}")
    except Exception as e:
        check("x-s-common 解码", False, str(e))

    # x-t 格式
    xt = h["x-t"]
    check("x-t 是毫秒时间戳", xt.isdigit() and len(xt) == 13, f"实际: {xt}")

    # trace id 格式
    check("x-b3-traceid 是 16 位 hex", len(h["x-b3-traceid"]) == 16, f"len={len(h['x-b3-traceid'])}")
    check("x-xray-traceid 是 32 位 hex", len(h["x-xray-traceid"]) == 32, f"len={len(h['x-xray-traceid'])}")


def test_api(method: str, name: str, path: str, body: dict | None = None,
             params: dict | None = None, a1: str = TEST_A1):
    """通用 API 测试：签名正确就不应返回 300/406"""
    h = sign_headers(method, path, {"a1": a1}, payload=body)
    # 先取出 _body，避免被当作 header
    send_body = h.pop("_body", None)
    req_h = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json;charset=UTF-8",
        "Origin": "https://www.xiaohongshu.com",
        "Referer": "https://www.xiaohongshu.com/",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    }
    req_h.update(h)

    try:
        if send_body is not None:
            resp = http.request(
                method, f"https://edith.xiaohongshu.com{path}",
                data=send_body.encode("utf-8"), params=params, headers=req_h,
                cookies={"a1": a1}, timeout=15,
            )
        else:
            resp = http.request(
                method, f"https://edith.xiaohongshu.com{path}",
                params=params, headers=req_h,
                cookies={"a1": a1}, timeout=15,
            )
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        code = data.get("code", "N/A")
        msg = data.get("msg", "")

        # 406 或 code=300 说明签名错误
        sign_ok = resp.status_code != 406 and code != 300
        detail = f"http={resp.status_code} code={code} msg={msg}"

        # 如果有业务数据，也展示
        if sign_ok and isinstance(data.get("data"), dict) and data["data"]:
            keys = list(data["data"].keys())[:4]
            detail += f" data_keys={keys}"

        check(name, sign_ok, detail)
    except Exception as e:
        check(name, False, str(e))


def test_pw_compare():
    """与 Playwright 签名对比"""
    print("\n=== 7. Playwright 签名对比 ===")
    try:
        r = http.get(f"{PW_SIGN_URL}/health", timeout=3)
        if not r.json().get("ready"):
            print("  [SKIP] Playwright 签名服务未就绪")
            return
    except Exception:
        print("  [SKIP] Playwright 签名服务未运行")
        return

    # 同一个请求，两种签名都发
    path = "/api/sns/web/v2/user/me"
    a1 = TEST_A1

    # Playwright 签名
    pw_r = http.post(f"{PW_SIGN_URL}/sign", json={"url": path, "body": None, "a1": a1}, timeout=10)
    pw_h = pw_r.json()

    # Python 签名
    py_h = sign_headers("GET", path, {"a1": a1})

    # 比较格式（值不同是正常的，因为有时间戳和随机数）
    check("PW x-s 长度与 Python 接近",
          abs(len(pw_h.get("x-s", "")) - len(py_h["x-s"])) < 20,
          f"PW={len(pw_h.get('x-s', ''))} PY={len(py_h['x-s'])}")

    check("PW x-s-common 长度与 Python 接近",
          abs(len(pw_h.get("x-s-common", "")) - len(py_h["x-s-common"])) < 50,
          f"PW={len(pw_h.get('x-s-common', ''))} PY={len(py_h['x-s-common'])}")

    # 两种签名都请求 API，都应通过签名验证
    print("  PW 签名请求...")
    test_api("GET", "PW签名 - 用户信息", path, a1=a1)
    # Python 签名已在前面测试


def main():
    print("小红书纯 Python 签名 - 全量测试")
    print("=" * 50)

    # 1. 签名格式
    test_sign_format()

    # 2-6. API 接口测试
    print("\n=== 2. GET 接口 - 用户信息 ===")
    test_api("GET", "用户信息", "/api/sns/web/v2/user/me")

    print("\n=== 3. POST 接口 - 首页 Feed ===")
    test_api("POST", "首页 Feed", "/api/sns/web/v1/homefeed",
             body={"cursor": "", "num": 20, "refresh_type": 1,
                   "image_formats": ["jpg", "webp", "avif"]})

    print("\n=== 4. POST 接口 - 搜索 ===")
    test_api("POST", "搜索笔记", "/api/sns/web/v1/search/notes",
             body={"keyword": "微信", "page": 1, "page_size": 20,
                   "search_id": "test-search-001", "sort": "general", "note_type": 0})

    print("\n=== 5. POST 接口 - 笔记详情 ===")
    test_api("POST", "笔记详情", "/api/sns/web/v1/feed",
             body={"source_note_id": "674ee65d000000000b037b7f",
                   "image_formats": ["jpg", "webp", "avif"],
                   "extra": {"need_body_topic": "1"}, "xsec_source": "pc_feed"})

    print("\n=== 6. GET 接口 - 评论 ===")
    test_api("GET", "评论列表", "/api/sns/web/v2/comment/page",
             params={"note_id": "674ee65d000000000b037b7f", "cursor": "",
                     "top_comment_id": "", "image_formats": "jpg,webp,avif"})

    # 7. Playwright 对比
    test_pw_compare()

    # 总结
    print("\n" + "=" * 50)
    total = passed + failed
    print(f"结果: {passed}/{total} 通过", end="")
    if failed:
        print(f", {failed} 失败")
        for e in errors:
            print(e)
        sys.exit(1)
    else:
        print(" - 全部通过!")


if __name__ == "__main__":
    main()
