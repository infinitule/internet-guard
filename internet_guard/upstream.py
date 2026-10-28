"""Bounded DNS-over-HTTPS transport, with an explicit numeric bootstrap IP."""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit

import dns.exception
import dns.message
import dns.rdatatype

MAX_DNS_BYTES = 65535


class UpstreamError(Exception):
    pass


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to an operator-selected IP while verifying the URL hostname.

    'Pinned' means DNS bootstrap, not certificate pinning. Normal CA and
    hostname verification are mandatory. No system DNS or proxy is used.
    """

    def __init__(self, host, port, bootstrap, context, timeout):
        super().__init__(host, port=port, context=context, timeout=timeout)
        self.bootstrap = bootstrap

    def connect(self):
        started = time.monotonic()
        address = ipaddress.ip_address(self.bootstrap)
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        raw = socket.socket(family, socket.SOCK_STREAM)
        try:
            raw.settimeout(self.timeout)
            raw.connect((str(address), self.port))
            remaining = self.timeout - (time.monotonic() - started)
            if remaining <= 0:
                raise TimeoutError("upstream connect deadline")
            raw.settimeout(remaining)
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class DoHUpstream:
    def __init__(
        self,
        url="https://dns.quad9.net/dns-query",
        bootstrap="9.9.9.9",
        timeout=3.0,
        *,
        context: ssl.SSLContext | None = None,
    ):
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or parsed.query
            or any(ord(c) <= 32 or ord(c) >= 127 for c in url)
        ):
            raise ValueError("upstream must be an ASCII HTTPS URL without credentials, query, or fragment")
        ipaddress.ip_address(bootstrap)
        if not 0.1 <= timeout <= 30:
            raise ValueError("upstream timeout must be between 0.1 and 30 seconds")
        self.host = parsed.hostname
        self.port = parsed.port or 443
        self.path = parsed.path or "/dns-query"
        self.bootstrap = bootstrap
        self.timeout = timeout
        self.context = context or ssl.create_default_context()
        if not self.context.check_hostname or self.context.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError("certificate and hostname verification must be enabled")
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.set_alpn_protocols(["http/1.1"])

    def exchange(self, wire: bytes) -> bytes:
        start = time.monotonic()
        connection = PinnedHTTPSConnection(self.host, self.port, self.bootstrap, self.context, self.timeout)
        timer = None
        try:
            connection.connect()
            remaining = self.timeout - (time.monotonic() - start)
            if remaining <= 0:
                raise TimeoutError("upstream deadline")
            sock = connection.sock
            sock.settimeout(remaining)

            def interrupt():
                # A total HTTP deadline also interrupts slow-drip headers/body.
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            timer = threading.Timer(remaining, interrupt)
            timer.daemon = True
            timer.start()
            connection.request(
                "POST",
                self.path,
                body=wire,
                headers={
                    "Accept": "application/dns-message",
                    "Content-Type": "application/dns-message",
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                    "User-Agent": "internet-guard/0.1.0",
                },
            )
            response = connection.getresponse()
            if response.status != 200:
                raise UpstreamError("upstream_http_status")  # Redirects are never followed.
            if (
                response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
                != "application/dns-message"
            ):
                raise UpstreamError("upstream_content_type")
            if response.getheader("Content-Encoding", "identity").lower() != "identity":
                raise UpstreamError("upstream_content_encoding")
            length = response.getheader("Content-Length")
            transfer = response.getheader("Transfer-Encoding")
            if transfer is not None and (transfer.lower() != "chunked" or length is not None):
                raise UpstreamError("upstream_transfer_encoding")
            if length is not None and (
                not length.isascii() or not length.isdecimal() or not 12 <= int(length) <= MAX_DNS_BYTES
            ):
                raise UpstreamError("upstream_content_length")
            body = response.read(MAX_DNS_BYTES + 1)
            if not 12 <= len(body) <= MAX_DNS_BYTES:
                raise UpstreamError("upstream_body_size")
            if length is not None and len(body) != int(length):
                raise UpstreamError("upstream_incomplete_body")
            if time.monotonic() - start >= self.timeout:
                raise UpstreamError("upstream_deadline")
            age_text = response.getheader("Age", "0")
            if not age_text.isascii() or not age_text.isdecimal() or len(age_text) > 10:
                raise UpstreamError("upstream_invalid_age")
            age = int(age_text)
            if age:
                # RFC 8484: cached HTTP responses must not revive expired DNS
                # TTLs, even though this forwarder has no cache of its own.
                message = dns.message.from_wire(body, ignore_trailing=False)
                for section in (message.answer, message.authority, message.additional):
                    for rrset in section:
                        ttl = rrset.ttl
                        if rrset.rdtype == dns.rdatatype.SOA:
                            ttl = min(ttl, *(record.minimum for record in rrset))
                        rrset.ttl = max(0, ttl - age)
                body = message.to_wire(max_size=MAX_DNS_BYTES)
            return body
        except (OSError, ValueError, http.client.HTTPException, dns.exception.DNSException) as exc:
            raise UpstreamError("upstream_transport_error") from exc
        finally:
            if timer:
                timer.cancel()
            connection.close()
