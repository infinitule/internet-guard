import io
import socket
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path

import dns.message
import dns.rcode

from internet_guard.demo import DemoUpstream, run_demo
from internet_guard.policy import PolicyStore
from internet_guard.resolver import Audit, GuardResolver
from internet_guard.server import GuardServer, WorkGate, receive_exact


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        path = Path(self.temp.name) / "policy.toml"
        path.write_text('version=1\nblock_domains=["malware.test"]\n')
        self.resolver = GuardResolver(PolicyStore(path), DemoUpstream(), Audit(io.StringIO()))

    def test_offline_demo_passes_over_udp_and_tcp(self):
        result = run_demo()
        self.assertTrue(result["passed"])
        self.assertEqual(len(result["checks"]), 12)

    def test_public_or_hostname_listeners_rejected(self):
        for address in ("0.0.0.0", "::", "192.168.1.1", "example.com"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                GuardServer(self.resolver, address, 0)

    def test_worker_queue_is_bounded(self):
        gate = WorkGate(workers=1)
        release = threading.Event()
        entered = threading.Event()
        try:

            def held():
                entered.set()
                release.wait(2)

            self.assertTrue(gate.submit(held))
            self.assertTrue(entered.wait(1))
            self.assertFalse(gate.submit(lambda: None))
            self.assertEqual(gate.rejected, 1)
        finally:
            release.set()
            gate.close()

    def test_rate_budget_is_shared_and_bounded(self):
        gate = WorkGate(rate=0.01, burst=2)
        try:
            self.assertTrue(gate.allow_query())
            self.assertTrue(gate.allow_query())
            self.assertFalse(gate.allow_query())
        finally:
            gate.close()

    def test_tcp_multiple_queries_have_correct_framing(self):
        with GuardServer(self.resolver, port=0) as server:
            with socket.create_connection(server.address, timeout=2) as client:
                for name, expected in (("good.test", dns.rcode.NOERROR), ("malware.test", dns.rcode.REFUSED)):
                    query = dns.message.make_query(name, "A")
                    raw = query.to_wire()
                    client.sendall(struct.pack("!H", len(raw)) + raw)
                    deadline = time.monotonic() + 2
                    length = struct.unpack("!H", receive_exact(client, 2, deadline))[0]
                    response = dns.message.from_wire(receive_exact(client, length, deadline))
                    self.assertEqual(response.id, query.id)
                    self.assertEqual(response.rcode(), expected)

    def test_idle_tcp_connections_expire(self):
        with GuardServer(self.resolver, port=0, client_timeout=0.15) as server:
            with socket.create_connection(server.address, timeout=2) as client:
                client.settimeout(2)
                self.assertEqual(client.recv(1), b"")

    def test_oversized_tcp_frame_is_rejected_before_body(self):
        with GuardServer(self.resolver, port=0) as server:
            with socket.create_connection(server.address, timeout=2) as client:
                client.sendall(struct.pack("!H", 65535))
                self.assertEqual(client.recv(1), b"")

    def test_partial_tcp_header_deadline(self):
        with GuardServer(self.resolver, port=0, client_timeout=0.15) as server:
            with socket.create_connection(server.address, timeout=2) as client:
                client.sendall(b"\x00")
                self.assertEqual(client.recv(1), b"")

    @unittest.skipUnless(socket.has_ipv6, "IPv6 unavailable")
    def test_ipv6_loopback_listener(self):
        try:
            server = GuardServer(self.resolver, "::1", 0)
        except OSError as exc:
            self.skipTest(str(exc))
        with server:
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as client:
                client.settimeout(2)
                client.sendto(dns.message.make_query("malware.test", "A").to_wire(), server.address)
                response = dns.message.from_wire(client.recv(4096))
                self.assertEqual(response.rcode(), dns.rcode.REFUSED)


if __name__ == "__main__":
    unittest.main()
