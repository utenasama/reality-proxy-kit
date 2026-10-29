import importlib.util
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest


class TLSFixture(unittest.TestCase):
    def test_partial_handshake_does_not_block_other_connections(self):
        spec = importlib.util.spec_from_file_location("target_fixture", Path(__file__).parent / "lab/target.py")
        fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
        with tempfile.TemporaryDirectory() as tmp:
            key, cert = Path(tmp) / "key.pem", Path(tmp) / "cert.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
            server = fixture.TLSServer(("127.0.0.1", 0), fixture.Handler)
            server.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); server.context.load_cert_chain(cert, key)
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            try:
                context = ssl._create_unverified_context()
                incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
                incomplete = context.wrap_bio(incoming, outgoing, server_hostname="localhost")
                try: incomplete.do_handshake()
                except ssl.SSLWantReadError: pass
                with socket.create_connection(server.server_address, timeout=3) as partial:
                    partial.sendall(outgoing.read())
                    with socket.create_connection(server.server_address, timeout=3) as connection, context.wrap_socket(connection, server_hostname="localhost") as tls:
                        tls.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                        self.assertIn(b"200", tls.recv(1024).split(b"\r\n", 1)[0])
            finally:
                server.shutdown(); server.server_close(); thread.join(timeout=5)
