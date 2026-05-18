#!/usr/bin/env python3
"""小红书 API 客户端（纯 Python 签名，无外部依赖）。

用法：
    # 匿名态探测
    python xiaohongshu_client.py --probe

    # 带 Cookie 探测
    python xiaohongshu_client.py --cookie 'a1=xxx;web_session=xxx' --probe

    # 搜索单个接口
    python xiaohongshu_client.py --cookie 'a1=xxx' --path /api/sns/web/v2/user/me
"""

from __future__ import annotations

import argparse
import json
import uuid
from pathlib import Path
from typing import Any

import requests

from xhs_pure_sign import sign_headers

API_BASE = "https://edith.xiaohongshu.com"
DEFAULT_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/148.0.0.0 Safari/537.36"
)


def parse_cookie(raw: str | None) -> dict[str, str]:
    if not raw:
        return {}
    return {
        k.strip(): v.strip()
        for item in raw.split(";")
        if "=" in item
        for k, v in [item.split("=", 1)]
    }


class XhsClient:
    """小红书 API 客户端。纯 Python 签名，零外部依赖。"""

    def __init__(self, cookie: dict[str, str] | None = None):
        self.cookies = cookie or {}
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json;charset=UTF-8",
            "Origin": "https://www.xiaohongshu.com",
            "Referer": "https://www.xiaohongshu.com/",
            "User-Agent": DEFAULT_UA,
        })

    def _sign(self, method: str, path: str, params: dict | None = None,
              body: dict | None = None) -> dict[str, str]:
        return sign_headers(method, path, self.cookies, payload=body)

    def request(self, method: str, path: str, params: dict | None = None,
                body: dict | None = None, timeout: int = 15) -> dict[str, Any]:
        signed = self._sign(method, path, params, body)
        # 先取出 _body，避免被当作 header
        send_body = signed.pop("_body", None)
        headers = {**self.session.headers, **signed}
        if send_body is not None:
            resp = self.session.request(
                method=method, url=f"{API_BASE}{path}",
                params=params, data=send_body.encode("utf-8"), headers=headers,
                cookies=self.cookies, timeout=timeout,
            )
        else:
            resp = self.session.request(
                method=method, url=f"{API_BASE}{path}",
                params=params, json=body, headers=headers,
                cookies=self.cookies, timeout=timeout,
            )
        try:
            data = resp.json()
        except Exception:
            data = resp.text[:2000]
        return {"status_code": resp.status_code, "json": data}

    def get(self, path: str, params: dict | None = None, **kw) -> dict:
        return self.request("GET", path, params=params, **kw)

    def post(self, path: str, body: dict | None = None, **kw) -> dict:
        return self.request("POST", path, body=body, **kw)

    # ---- 常用 API ----

    def get_user_info(self):
        return self.get("/api/sns/web/v2/user/me")

    def get_homefeed(self):
        return self.post("/api/sns/web/v1/homefeed", body={
            "cursor": "", "num": 20, "refresh_type": 1,
            "image_formats": ["jpg", "webp", "avif"],
        })

    def get_note_feed(self, note_id: str, xsec_token: str = ""):
        body = {
            "source_note_id": note_id,
            "image_formats": ["jpg", "webp", "avif"],
            "extra": {"need_body_topic": "1"},
            "xsec_source": "pc_feed",
        }
        if xsec_token:
            body["xsec_token"] = xsec_token
        return self.post("/api/sns/web/v1/feed", body=body)

    def get_comments(self, note_id: str, xsec_token: str = ""):
        params = {
            "note_id": note_id, "cursor": "",
            "top_comment_id": "", "image_formats": "jpg,webp,avif",
        }
        if xsec_token:
            params["xsec_token"] = xsec_token
        return self.get("/api/sns/web/v2/comment/page", params=params)

    def search_notes(self, keyword: str):
        return self.post("/api/sns/web/v1/search/notes", body={
            "keyword": keyword, "page": 1, "page_size": 20,
            "search_id": str(uuid.uuid4()), "sort": "general", "note_type": 0,
        })


def run_probe(client: XhsClient) -> None:
    has_a1 = bool(client.cookies.get("a1"))
    has_session = bool(client.cookies.get("web_session"))
    print(f"Cookie: a1={'有' if has_a1 else '无'}, web_session={'有' if has_session else '无'}")
    print()

    tests = [
        ("用户信息", lambda: client.get_user_info()),
        ("首页 Feed", lambda: client.get_homefeed()),
        ("搜索笔记", lambda: client.search_notes("微信")),
        ("笔记详情", lambda: client.get_note_feed("674ee65d000000000b037b7f")),
        ("评论列表", lambda: client.get_comments("674ee65d000000000b037b7f")),
    ]

    for name, fn in tests:
        try:
            r = fn()
            data = r.get("json")
            if isinstance(data, dict):
                code, msg = data.get("code"), data.get("msg", "")
                extra = ""
                if isinstance(data.get("data"), dict) and data.get("code") == 0:
                    extra = f" data_keys={list(data['data'].keys())[:6]}"
                print(f"  [{name}] code={code} msg={msg}{extra}")
            else:
                print(f"  [{name}] status={r.get('status_code')} raw={str(data)[:80]}")
        except Exception as e:
            print(f"  [{name}] ERROR: {e}")


def main():
    parser = argparse.ArgumentParser(description="小红书 API 客户端（纯 Python 签名）")
    parser.add_argument("--cookie", help="浏览器 Cookie 字符串")
    parser.add_argument("--cookie-file", help="Cookie JSON 文件")
    parser.add_argument("--probe", action="store_true", help="批量探测")
    parser.add_argument("--path", help="API 路径")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("--params", help="GET 参数 JSON")
    parser.add_argument("--body", help="POST body JSON")
    parser.add_argument("--timeout", type=int, default=15)
    args = parser.parse_args()

    cookie = {}
    if args.cookie:
        cookie = parse_cookie(args.cookie)
    elif args.cookie_file:
        data = json.loads(Path(args.cookie_file).read_text())
        cookie = data if isinstance(data, dict) else parse_cookie(data)

    client = XhsClient(cookie=cookie)

    if args.probe:
        run_probe(client)
        return

    if args.path:
        result = client.request(
            method=args.method, path=args.path,
            params=json.loads(args.params) if args.params else None,
            body=json.loads(args.body) if args.body else None,
            timeout=args.timeout,
        )
        print(json.dumps(result.get("json") if isinstance(result.get("json"), dict) else result,
                         ensure_ascii=False, indent=2)[:2000])
        return

    parser.print_help()
    print("\n示例:")
    print("  python xiaohongshu_client.py --probe")
    print("  python xiaohongshu_client.py --cookie 'a1=xxx;web_session=xxx' --probe")


if __name__ == "__main__":
    main()
