"""Campus Lab 1.0: deliberately vulnerable local-only textbook companion.

Python 3.10+ standard library. All data are fictional and kept in memory.
--mode fixed demonstrates six specific repairs, not production readiness.
"""
import argparse
import hashlib
import hmac
import html
import json
import secrets
import socket
import sqlite3
import threading
from email.parser import BytesParser
from email.policy import default
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

VERSION = "1.0"
MAX_BODY = 65536
CSS = """body{font:17px/1.8 system-ui,'Microsoft YaHei',sans-serif;max-width:850px;
margin:45px auto;padding:0 22px;color:#26343d;background:#f7f6f2}h1{font-size:30px}
nav a{margin-right:15px}input,textarea,button{font:inherit;padding:7px;margin:5px}
textarea{width:90%;height:90px}pre{background:#fff;padding:16px;overflow:auto}
.mode{font-size:14px;color:#80552a}article{padding:10px;border-bottom:1px solid #ddd}"""


class LocalServer(ThreadingHTTPServer):
    allow_reuse_address = False

    def server_bind(self):
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def password_hash(value, salt):
    return hashlib.pbkdf2_hmac("sha256", value.encode(), salt, 120000).hex()


class State:
    def __init__(self, mode, port):
        self.mode, self.port = mode, port
        self.lock = threading.RLock()
        self.db = sqlite3.connect(":memory:", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("CREATE TABLE users(id INTEGER PRIMARY KEY,name TEXT,password TEXT,salt BLOB,email TEXT,secret TEXT)")
        for uid, name in [(1, "alice"), (2, "bob")]:
            salt = secrets.token_bytes(16)
            self.db.execute("INSERT INTO users VALUES(?,?,?,?,?,?)", (uid, name, password_hash(name, salt), salt, name + "@example.test", name + "-private-note"))
        self.db.commit()
        self.sessions, self.comments, self.files = {}, [], {}


def make_handler(state, attacker=False):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            # Do not print submitted passwords, tokens or payloads.
            pass

        def response(self, text, status=200, kind="text/html; charset=utf-8", headers=None):
            data = text if isinstance(text, bytes) else text.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(data)

        def page(self, title, body, status=200, headers=None):
            nav = '<nav><a href="/">首页</a><a href="/login">登录</a><a href="/account">账户</a><a href="/search">搜索</a><a href="/comments">留言</a><a href="/upload">上传</a></nav>'
            self.response(f'<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>{html.escape(title)}</title><style>{CSS}</style><body>{nav}<p class="mode">Campus Lab {VERSION} · {state.mode} · 虚构数据 · 仅本地教学</p><h1>{html.escape(title)}</h1>{body}</body></html>', status, headers=headers)

        def session(self):
            cookie = SimpleCookie()
            try:
                cookie.load(self.headers.get("Cookie", ""))
                sid = cookie["sid"].value if "sid" in cookie else ""
            except Exception:
                sid = ""
            return state.sessions.get(sid)

        def form(self):
            n = int(self.headers.get("Content-Length", "0"))
            if n < 0 or n > MAX_BODY:
                raise ValueError("正文必须小于 64 KiB")
            raw = self.rfile.read(n)
            if len(raw) != n:
                raise ValueError("正文长度不完整")
            return raw

        def do_GET(self):
            with state.lock:
                self.get()

        def get(self):
            path = urlsplit(self.path).path
            q = parse_qs(urlsplit(self.path).query)
            if attacker:
                if path != "/":
                    return self.response("Not found", 404)
                target = f"http://127.0.0.1:{state.port}/account/email"
                return self.page("实验用诱导页面", f'<p>这是虚构实验中的另一个源。点击按钮，会向靶场提交修改邮箱表单。</p><form method="post" action="{target}"><input type="hidden" name="email" value="changed@example.test"><button>领取实验积分</button></form>')
            if path == "/health":
                return self.response(json.dumps({"version": VERSION, "mode": state.mode}), kind="application/json")
            if path == "/":
                return self.page("校园活动站", '<p>使用 alice / alice 或 bob / bob 登录。这里只保存虚构活动账户、留言和上传记录。</p><p>先观察正常行为，再修改一个输入，并保留前后证据。</p><ul><li>账户与越权：/account 和 /profile?id=1</li><li>SQL 注入：/login</li><li>XSS：/search 和 /comments</li><li>CSRF：/account/email</li><li>上传校验：/upload</li></ul>')
            if path == "/login":
                return self.page("登录", '<form method="post"><label>用户名<input name="username" required></label><br><label>密码<input type="password" name="password" required></label><br><button>登录</button></form>')
            if path == "/search":
                value = q.get("q", [""])[0]
                shown = html.escape(value) if state.mode == "fixed" else value
                return self.page("活动搜索", '<form><input name="q" placeholder="输入搜索词"><button>搜索</button></form><p>你的搜索词</p><div id="result">' + shown + '</div>')
            if path == "/comments":
                form = '<form method="post"><textarea name="message" required></textarea><br><button>发布留言</button></form>'
                items = "".join('<article class="comment">' + (html.escape(x) if state.mode == "fixed" else x) + '</article>' for x in state.comments)
                return self.page("活动留言", form + items)
            if path in ("/account", "/profile"):
                ses = self.session()
                if not ses:
                    return self.page("请先登录", '<a href="/login">前往登录</a>', 401)
                uid = ses["uid"]
                if path == "/profile":
                    try:
                        uid = int(q.get("id", [str(uid)])[0])
                    except ValueError:
                        return self.response("Invalid id", 400)
                    if state.mode == "fixed" and uid != ses["uid"]:
                        return self.page("访问被拒绝", "<p>当前账户没有查看这个私有资料的权限。</p>", 403)
                row = state.db.execute("SELECT id,name,email,secret FROM users WHERE id=?", (uid,)).fetchone()
                if row is None:
                    return self.response("Not found", 404)
                data = html.escape(json.dumps(dict(row), ensure_ascii=False, indent=2))
                if path == "/profile":
                    return self.page("私有资料", '<pre id="profile">' + data + '</pre>')
                token = f'<input type="hidden" name="csrf" value="{ses["csrf"]}">' if state.mode == "fixed" else ""
                return self.page("我的账户", '<pre id="profile">' + data + '</pre><p><a href="/profile?id=' + str(uid) + '">查看私有资料</a></p><form method="post" action="/account/email">' + token + '<label>邮箱<input name="email" value="' + html.escape(row["email"], quote=True) + '"></label><button>修改邮箱</button></form>')
            if path == "/upload":
                items = "".join('<li><a href="/files?name=' + key + '">' + html.escape(key) + '</a></li>' for key in state.files)
                return self.page("活动附件", '<p>教学规则：vulnerable 只信任客户端声明的 image/jpeg；fixed 只收 UTF-8 纯文本 .txt 并随机命名。</p><form method="post" enctype="multipart/form-data"><input type="file" name="file" required><button>上传</button></form><ul>' + items + '</ul>')
            if path == "/files":
                name = q.get("name", [""])[0]
                if name not in state.files:
                    return self.response("Not found", 404)
                # Teaching files are always downloaded as plain text and never executed.
                return self.response(state.files[name], kind="text/plain; charset=utf-8", headers={"Content-Disposition": 'attachment; filename="lesson.txt"'})
            return self.response("Not found", 404)

        def do_POST(self):
            with state.lock:
                try:
                    self.post()
                except (ValueError, UnicodeError) as exc:
                    self.page("请求格式错误", '<p>' + html.escape(str(exc)) + '</p>', 400)

        def post(self):
            if attacker:
                return self.response("Method not allowed", 405)
            path = urlsplit(self.path).path
            raw = self.form()
            if path == "/upload":
                ct = self.headers.get("Content-Type", "")
                if not ct.startswith("multipart/form-data;"):
                    raise ValueError("上传需要 multipart/form-data")
                msg = BytesParser(policy=default).parsebytes(('Content-Type: ' + ct + '\r\nMIME-Version: 1.0\r\n\r\n').encode() + raw)
                parts = list(msg.iter_parts()) if msg.is_multipart() else []
                file = next((p for p in parts if p.get_param("name", header="content-disposition") == "file"), None)
                if file is None:
                    raise ValueError("缺少 file 字段")
                name = file.get_filename() or ""
                mime = file.get_content_type()
                content = file.get_payload(decode=True) or b""
                if not name or any(x in name for x in ['/', '\\', '\r', '\n', '?', '&', '#', '"', '<', '>']):
                    raise ValueError("文件名格式错误")
                if state.mode == "vulnerable":
                    if mime != "image/jpeg":
                        return self.page("上传被拒绝", '<p>需要声明 image/jpeg。</p>', 415)
                else:
                    if not name.lower().endswith(".txt") or mime != "text/plain":
                        return self.page("上传被拒绝", '<p>只接受 .txt 与 text/plain。</p>', 415)
                    decoded = content.decode("utf-8")
                    if any(ord(c) < 32 and c not in '\t\n\r' for c in decoded):
                        raise ValueError("需要可读 UTF-8 文本")
                    name = secrets.token_hex(8) + ".txt"
                state.files[name] = content
                return self.page("上传记录已保存", '<p id="saved-name">' + html.escape(name) + '</p><p>保存不代表执行。本环境没有 PHP 解释器，也不运行上传内容。</p>')
            fields = parse_qs(raw.decode("utf-8"), keep_blank_values=True)
            if path == "/login":
                username = fields.get("username", [""])[0]
                password = fields.get("password", [""])[0]
                # A teaching login query includes both name and a derived password hash.
                if state.mode == "vulnerable":
                    salt_row = state.db.execute("SELECT salt FROM users WHERE name=?", (username,)).fetchone()
                    salt = salt_row["salt"] if salt_row else b"unknown-user-teaching-salt"
                    candidate = password_hash(password, salt)
                    sql = f"SELECT id,name FROM users WHERE name='{username}' AND password='{candidate}'"
                    try:
                        row = state.db.execute(sql).fetchone()
                    except sqlite3.Error:
                        return self.page("登录失败", "<p>数据库查询格式错误。</p>", 400)
                    ok = row is not None
                else:
                    row = state.db.execute("SELECT id,name,password,salt FROM users WHERE name=?", (username,)).fetchone()
                    ok = row is not None and hmac.compare_digest(password_hash(password, row["salt"]), row["password"])
                if not ok:
                    return self.page("登录失败", "<p>用户名或密码错误。</p>", 401)
                sid = secrets.token_urlsafe(24)
                state.sessions[sid] = {"uid": row["id"], "csrf": secrets.token_urlsafe(24)}
                return self.page("登录成功", '<p>当前用户 <strong id="user">' + html.escape(row["name"]) + '</strong></p><a href="/account">进入账户</a>', headers={"Set-Cookie": f"sid={sid}; Path=/; HttpOnly; SameSite=Lax"})
            if path == "/comments":
                value = fields.get("message", [""])[0]
                if not value or len(value) > 2000:
                    raise ValueError("留言应为 1 至 2000 字符")
                state.comments.append(value)
                return self.page("留言已保存", '<a href="/comments">刷新留言页面</a>')
            if path == "/account/email":
                ses = self.session()
                if not ses:
                    return self.page("请先登录", "<p>没有有效会话。</p>", 401)
                if state.mode == "fixed":
                    token = fields.get("csrf", [""])[0]
                    if not hmac.compare_digest(token, ses["csrf"]):
                        return self.page("修改被拒绝", "<p>CSRF token 无效或缺失。</p>", 403)
                email = fields.get("email", [""])[0]
                if len(email) > 100 or '@' not in email or '\n' in email:
                    raise ValueError("邮箱格式错误")
                state.db.execute("UPDATE users SET email=? WHERE id=?", (email, ses["uid"]))
                state.db.commit()
                return self.page("邮箱已修改", '<a href="/account">查看账户</a>')
            return self.response("Not found", 404)

    return Handler


def start(mode="vulnerable", port=8765, attacker_port=8766):
    state = State(mode, port)
    servers = [LocalServer(("127.0.0.1", port), make_handler(state)), LocalServer(("127.0.0.1", attacker_port), make_handler(state, True))]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    return state, servers


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["vulnerable", "fixed"], default="vulnerable")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--attacker-port", type=int, default=8766)
    args = parser.parse_args()
    state, servers = start(args.mode, args.port, args.attacker_port)
    print(f"Campus Lab {VERSION} {args.mode}: http://127.0.0.1:{args.port}", flush=True)
    print(f"CSRF lesson: http://127.0.0.1:{args.attacker_port} · Ctrl+C to stop", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        for server in servers:
            server.shutdown()
            server.server_close()
