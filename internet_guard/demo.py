"""Deterministic, fully offline exercise through real local DNS sockets."""

import io
import socket
import struct
import tempfile
from pathlib import Path

import dns.message
import dns.rcode
import dns.rrset

from .policy import PolicyStore
from .resolver import Audit, GuardResolver
from .server import GuardServer, receive_exact


class DemoUpstream:
    """Synthetic fixture. Never used by the serve command."""

    def exchange(self, wire):
        query = dns.message.from_wire(wire)
        response = dns.message.make_response(query, recursion_available=True)
        name = query.question[0].name.to_text()
        if name == "alias.test.":
            response.answer.append(dns.rrset.from_text(name, 30, "IN", "CNAME", "malware.test."))
        elif name == "rebind.test.":
            response.answer.append(dns.rrset.from_text(name, 30, "IN", "A", "127.0.0.1"))
        elif name == "hint.test.":
            response.answer.append(
                dns.rrset.from_text(name, 30, "IN", "HTTPS", '1 . ipv4hint="169.254.169.254"')
            )
        else:
            response.answer.append(dns.rrset.from_text(name, 30, "IN", "A", "93.184.216.34"))
        return response.to_wire()


def run_demo():
    with tempfile.TemporaryDirectory(prefix="internet-guard-demo-") as temporary:
        path = Path(temporary) / "policy.toml"
        path.write_text('version=1\nmode="enforce"\nblock_domains=["malware.test"]\n', encoding="utf-8")
        audit_stream = io.StringIO()
        resolver = GuardResolver(PolicyStore(path), DemoUpstream(), Audit(audit_stream))
        cases = [
            ("domain", "malware.test", "A", "REFUSED"),
            ("subdomain", "child.malware.test", "A", "REFUSED"),
            ("alias", "alias.test", "A", "REFUSED"),
            ("private_answer", "rebind.test", "A", "REFUSED"),
            ("https_ip_hint", "hint.test", "HTTPS", "REFUSED"),
            ("allowed", "good.test", "A", "NOERROR"),
        ]
        results = []
        with GuardServer(resolver, port=0) as server:
            for transport in ("udp", "tcp"):
                for label, name, kind, expected in cases:
                    query = dns.message.make_query(name, kind)
                    raw = query.to_wire()
                    with socket.socket(
                        socket.AF_INET, socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
                    ) as client:
                        client.settimeout(2)
                        client.connect(server.address)
                        if transport == "udp":
                            client.send(raw)
                            reply = client.recv(65535)
                        else:
                            import time

                            client.sendall(struct.pack("!H", len(raw)) + raw)
                            deadline = time.monotonic() + 2
                            size = struct.unpack("!H", receive_exact(client, 2, deadline))[0]
                            reply = receive_exact(client, size, deadline)
                    actual = dns.rcode.to_text(dns.message.from_wire(reply).rcode())
                    results.append(
                        {
                            "case": label,
                            "transport": transport,
                            "expected": expected,
                            "actual": actual,
                            "passed": actual == expected,
                        }
                    )
        return {
            "offline": True,
            "synthetic_fixtures": True,
            "passed": all(r["passed"] for r in results),
            "checks": results,
            "audit_counts": dict(resolver.audit.counts),
        }
