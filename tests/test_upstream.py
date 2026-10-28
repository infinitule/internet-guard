import http.server
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import dns.message
import dns.rrset

from internet_guard.upstream import DoHUpstream, UpstreamError


class TLSServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass  # Expected disconnects during timeout/certificate-negative tests.


class LocalDoH(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        query = dns.message.from_wire(body)
        self.server.seen.append((self.path, dict(self.headers), query))
        reply = dns.message.make_response(query)
        reply.answer.append(dns.rrset.from_text("good.test.", 60, "IN", "A", "9.9.9.9"))
        raw = reply.to_wire(max_size=65535)
        behavior = self.server.behavior
        if behavior == "slow_headers":
            self.connection.sendall(b"HTTP/1.1 200 OK\r\nX-Slow: ")
            for _ in range(30):
                time.sleep(0.03)
                self.connection.sendall(b"x")
            return
        self.send_response(302 if behavior == "redirect" else 200)
        self.send_header(
            "Content-Type", "text/html" if behavior == "wrong_type" else "application/dns-message"
        )
        if behavior == "encoded":
            self.send_header("Content-Encoding", "gzip")
        if behavior == "aged":
            self.send_header("Age", "55")
        if behavior == "invalid_age":
            self.send_header("Age", "-1")
        if behavior == "chunked":
            self.send_header("Transfer-Encoding", "chunked")
        elif behavior != "oversize_stream":
            self.send_header("Content-Length", str(70000 if behavior == "oversize_header" else len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        if behavior == "oversize_stream":
            self.wfile.write(b"x" * 65536)
        elif behavior == "chunked":
            self.wfile.write(f"{len(raw):x}\r\n".encode() + raw + b"\r\n0\r\n\r\n")
        else:
            self.wfile.write(raw)


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL CLI required for ephemeral TLS test certificates")
class UpstreamTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.cert = Path(cls.temp.name) / "test.crt"
        cls.key = Path(cls.temp.name) / "test.key"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-keyout",
                str(cls.key),
                "-out",
                str(cls.cert),
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @contextmanager
    def server(self, behavior="normal"):
        server = TLSServer(("127.0.0.1", 0), LocalDoH)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.behavior = behavior
        server.seen = []
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def upstream(self, server, *, hostname="localhost", timeout=1):
        context = ssl.create_default_context(cafile=str(self.cert))
        return DoHUpstream(
            f"https://{hostname}:{server.server_port}/dns-query", "127.0.0.1", timeout, context=context
        )

    def query(self):
        return dns.message.make_query("good.test", "A").to_wire()

    def test_verified_tls_post_without_bootstrap_dns_lookup(self):
        with self.server() as server:
            upstream = self.upstream(server)
            with patch(
                "socket.getaddrinfo", side_effect=AssertionError("must not resolve bootstrap hostname")
            ):
                response = dns.message.from_wire(upstream.exchange(self.query()))
            self.assertEqual(response.answer[0][0].address, "9.9.9.9")
            self.assertEqual(server.seen[0][0], "/dns-query")
            self.assertEqual(server.seen[0][1]["Content-Type"], "application/dns-message")

    def test_untrusted_certificate_is_rejected(self):
        with self.server() as server:
            upstream = DoHUpstream(f"https://localhost:{server.server_port}/dns-query", "127.0.0.1", 1)
            with self.assertRaises(UpstreamError):
                upstream.exchange(self.query())
            self.assertFalse(server.seen)

    def test_wrong_hostname_is_rejected_even_with_trusted_certificate(self):
        with self.server() as server:
            with self.assertRaises(UpstreamError):
                self.upstream(server, hostname="wrong.test").exchange(self.query())
            self.assertFalse(server.seen)

    def test_http_failures_and_oversize_bodies_are_rejected(self):
        for behavior in (
            "redirect",
            "wrong_type",
            "encoded",
            "oversize_header",
            "oversize_stream",
            "invalid_age",
        ):
            with self.subTest(behavior=behavior), self.server(behavior) as server:
                with self.assertRaises(UpstreamError):
                    self.upstream(server).exchange(self.query())
                self.assertEqual(len(server.seen), 1)

    def test_chunked_body_is_supported(self):
        with self.server("chunked") as server:
            response = dns.message.from_wire(self.upstream(server).exchange(self.query()))
            self.assertEqual(response.answer[0][0].address, "9.9.9.9")

    def test_http_age_reduces_dns_ttl(self):
        with self.server("aged") as server:
            response = dns.message.from_wire(self.upstream(server).exchange(self.query()))
            self.assertEqual(response.answer[0].ttl, 5)

    def test_absolute_deadline_stops_slow_drip_headers(self):
        with self.server("slow_headers") as server:
            started = time.monotonic()
            with self.assertRaises(UpstreamError):
                self.upstream(server, timeout=0.2).exchange(self.query())
            self.assertLess(time.monotonic() - started, 0.8)


class UpstreamConfigurationTests(unittest.TestCase):
    def test_insecure_or_ambiguous_urls_rejected(self):
        for url in (
            "http://dns.test/dns-query",
            "https://u:p@dns.test/dns-query",
            "https://dns.test/dns-query#fragment",
            "https://dns.test/dns-query?q=x",
            "https://dns.test/a\r\nHeader:x",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                DoHUpstream(url)

    def test_bootstrap_must_be_numeric(self):
        with self.assertRaises(ValueError):
            DoHUpstream(bootstrap="dns.test")

    def test_tls_validation_cannot_be_disabled(self):
        with self.assertRaises(ValueError):
            DoHUpstream(context=ssl._create_unverified_context())


if __name__ == "__main__":
    unittest.main()
