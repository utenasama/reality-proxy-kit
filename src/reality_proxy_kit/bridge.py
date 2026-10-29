"""Loopback-only filter over native subscriptions. It is not an account portal."""
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import urllib.request
from .client import filter_native
from .config import allowed_routes, panel_template
from .files import revision
from .model import Deployment
from .panel import snapshot

BASE = Path("/etc/reality-proxy-kit")


def subscription(path, *, base=BASE):
    match = re.fullmatch(r"/(s|m|x)/([A-Za-z0-9_-]{16,128})", path)
    if not match:
        raise ValueError("Invalid subscription path")
    kind, token = match.groups()
    spec = Deployment(json.loads((base / "deployment.json").read_text()))
    seed = json.loads((base / "state.json").read_text())
    live, _, before = snapshot(spec, seed)
    account = next((a for a in live["accounts"] if hmac.compare_digest(a["sub_id"], token)), None)
    if not account or not account["enabled"] or not account["routes"]:
        raise ValueError("No authorized nodes")
    # The generated runtime must reflect the policy being exposed. During updates,
    # stale/racing data yields an error rather than an over-broad subscription.
    runtime = json.loads(Path("/usr/local/x-ui/bin/config.json").read_text())
    runtime_routes = allowed_routes(spec, live["accounts"], runtime, account)
    numbers = {spec.routes[r]["number"] for r in set(account["routes"]) & set(runtime_routes)}
    if not numbers:
        raise ValueError("Policy is not active yet")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request("http://127.0.0.1:2096" + path,
                                     headers={"User-Agent": "clash.meta" if kind == "m" else "v2rayN", "Accept": "*/*"})
    with opener.open(request, timeout=10) as response:
        body = response.read(4 * 1024 * 1024 + 1)
    if len(body) > 4 * 1024 * 1024:
        raise ValueError("Native subscription exceeds limit")
    result = filter_native(body, kind, numbers)
    if snapshot(spec, seed)[2] != before:
        raise ValueError("Policy changed during subscription generation")
    return result, {"s": "text/plain", "m": "application/yaml", "x": "application/json"}[kind]


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            body, kind = subscription(self.path)
            self.send_response(200)
            self.send_header("Content-Type", kind + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "private, no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, *args):
        # URL tokens are credentials and must never enter request logs.
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 2097), Handler).serve_forever()
