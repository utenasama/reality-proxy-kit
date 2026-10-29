"""Disposable DNS/HTTP/TLS fixture using reserved documentation addresses."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import threading

dns_queries = []


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"peer": self.client_address[0], "dns": dns_queries[-200:]}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def log_message(self, *args):
        pass


def dns():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 53))
    while True:
        data, peer = sock.recvfrom(4096)
        try:
            at, labels = 12, []
            while data[at]:
                size = data[at]; at += 1; labels.append(data[at:at + size].decode()); at += size
            at += 1
            qtype = struct.unpack("!H", data[at:at + 2])[0]
            end = at + 4
            name = ".".join(labels)
            dns_queries.append({"name": name, "source": peer[0]})
            address = "127.0.0.1" if name.startswith("private.") else "192.0.2.2"
            answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04" + socket.inet_aton(address) if qtype == 1 else b""
            response = data[:2] + b"\x81\x80\x00\x01" + struct.pack("!H", bool(answer)) + b"\0" * 4 + data[12:end] + answer
            sock.sendto(response, peer)
        except Exception:
            continue


class TLSServer(ThreadingHTTPServer):
    def finish_request(self, request, address):
        # REALITY intentionally mirrors only part of an upstream handshake.
        # Perform TLS negotiation inside each worker, never in the accept loop.
        request.settimeout(30)
        try:
            with self.context.wrap_socket(request, server_side=True) as tls:
                super().finish_request(tls, address)
        except (ssl.SSLError, TimeoutError, OSError):
            pass


if __name__ == "__main__":
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=remote.example.org", "-addext", "subjectAltName=DNS:remote.example.org,DNS:test.example.org", "-keyout", "/tmp/fixture.key", "-out", "/tmp/fixture.pem"], check=True, capture_output=True)
    Path("/tmp/fixture.key").chmod(0o600)
    threading.Thread(target=dns, daemon=True).start()
    threading.Thread(target=ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever, daemon=True).start()
    server = TLSServer(("0.0.0.0", 443), Handler)
    server.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.context.load_cert_chain("/tmp/fixture.pem", "/tmp/fixture.key")
    server.context.set_alpn_protocols(["h2", "http/1.1"])
    server.serve_forever()
