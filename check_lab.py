"""Meaningful request-level checks for vulnerable/fixed controls and valid actions."""
import http.client
import json
import re
import unittest
from urllib.parse import urlencode
import lab


class LabChecks(unittest.TestCase):
    def request(self, path, fields=None, cookie="", raw=None, kind=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.state.port, timeout=5)
        headers = {"Cookie": cookie} if cookie else {}
        body = None
        method = "GET"
        if fields is not None:
            body = urlencode(fields).encode()
            method = "POST"
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if raw is not None:
            body, method = raw, "POST"
            headers["Content-Type"] = kind
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        answer = (response.status, response.read().decode("utf-8"), response.getheader("Set-Cookie", ""))
        conn.close()
        return answer

    def upload(self, name, mime, content):
        boundary = "textbook-boundary"
        body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\nContent-Type: {mime}\r\n\r\n'.encode() + content + f'\r\n--{boundary}--\r\n'.encode())
        return self.request("/upload", raw=body, kind="multipart/form-data; boundary=" + boundary)

    def test_modes_and_controls(self):
        for mode, port in [("vulnerable", 18865), ("fixed", 18875)]:
            with self.subTest(mode=mode):
                self.state, servers = lab.start(mode, port, port + 1)
                try:
                    self.assertEqual(json.loads(self.request("/health")[1])["mode"], mode)
                    self.assertEqual(self.request("/profile?id=2")[0], 401)
                    self.assertEqual(self.request("/login", {"username": "alice", "password": "wrong"})[0], 401)
                    status, _, cookie = self.request("/login", {"username": "alice", "password": "alice"})
                    self.assertEqual(status, 200)
                    cookie = cookie.split(";")[0]
                    self.assertEqual(self.request("/profile?id=1", cookie=cookie)[0], 200)
                    status, data, _ = self.request("/profile?id=2", cookie=cookie)
                    self.assertEqual(status, 200 if mode == "vulnerable" else 403)
                    self.assertEqual("bob-private-note" in data, mode == "vulnerable")
                    status, data, _ = self.request("/login", {"username": "alice' -- ", "password": "wrong"})
                    self.assertEqual(status, 200 if mode == "vulnerable" else 401)
                    marker = '<script>document.body.dataset.lesson="reflected"</script>'
                    _, data, _ = self.request("/search?" + urlencode({"q": marker}))
                    self.assertEqual(marker in data, mode == "vulnerable")
                    self.assertEqual(self.request("/comments", {"message": marker})[0], 200)
                    self.assertEqual(marker in self.request("/comments")[1], mode == "vulnerable")
                    self.assertEqual(self.request("/account/email", {"email": "changed@example.test"}, cookie)[0], 200 if mode == "vulnerable" else 403)
                    if mode == "fixed":
                        data = self.request("/account", cookie=cookie)[1]
                        token = re.search(r'name="csrf" value="([^"]+)"', data).group(1)
                        self.assertEqual(self.request("/account/email", {"email": "ok@example.test", "csrf": token}, cookie)[0], 200)
                    status, _, _ = self.upload("lesson.php", "image/jpeg", b"LESSON FILE ONLY")
                    self.assertEqual(status, 200 if mode == "vulnerable" else 415)
                    if mode == "fixed":
                        self.assertEqual(self.upload("note.txt", "text/plain", b"normal text")[0], 200)
                        self.assertEqual(self.upload("note.txt", "text/plain", b"\x00bad")[0], 400)
                    self.assertEqual(self.request("/unknown")[0], 404)
                finally:
                    for server in servers:
                        server.shutdown()
                        server.server_close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
