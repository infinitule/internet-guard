"""Loopback-only UDP/TCP listeners with shared bounded admission control."""

from __future__ import annotations

import ipaddress
import socket
import socketserver
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .resolver import MAX_QUERY_BYTES


class WorkGate:
    def __init__(self, workers=16, rate=100.0, burst=200):
        if not 1 <= workers <= 128 or rate <= 0 or burst < 1:
            raise ValueError("invalid admission limits")
        self.pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="guard")
        self.slots = threading.BoundedSemaphore(workers)
        self.rate, self.burst = rate, burst
        self.tokens = float(burst)
        self.last = time.monotonic()
        self.lock = threading.Lock()
        self.rejected = 0

    def allow_query(self):
        with self.lock:
            now = time.monotonic()
            self.tokens = min(self.burst, self.tokens + (now - self.last) * self.rate)
            self.last = now
            if self.tokens < 1:
                self.rejected += 1
                return False
            self.tokens -= 1
            return True

    def submit(self, function):
        if not self.slots.acquire(blocking=False):
            with self.lock:
                self.rejected += 1
            return False

        def run():
            try:
                function()
            finally:
                self.slots.release()

        try:
            self.pool.submit(run)
        except RuntimeError:
            self.slots.release()
            return False
        return True

    def close(self):
        self.pool.shutdown(wait=True, cancel_futures=True)


class BoundedServer:
    allow_reuse_address = False

    def process_request(self, request, client_address):
        def finish():
            try:
                self.finish_request(request, client_address)
            except (OSError, TimeoutError, ValueError):
                pass
            except Exception:
                # Do not leak a query or a stack trace to the audit stream.
                self.resolver.audit.emit("internal_error", reason="request_handler")
            finally:
                self.shutdown_request(request)

        if not self.gate.submit(finish):
            self.shutdown_request(request)


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        wire, sock = self.request
        if not self.server.gate.allow_query():
            return
        response = self.server.resolver.handle(wire, "udp")
        if response is not None:
            sock.sendto(response, self.client_address)


def receive_exact(sock, length, deadline):
    pieces = bytearray()
    while len(pieces) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("client frame deadline")
        sock.settimeout(remaining)
        chunk = sock.recv(length - len(pieces))
        if not chunk:
            raise ConnectionError("client closed the stream")
        pieces.extend(chunk)
    return bytes(pieces)


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        for _ in range(16):
            if self.server.stopping.is_set():
                return
            deadline = time.monotonic() + self.server.client_timeout
            size = struct.unpack("!H", receive_exact(self.request, 2, deadline))[0]
            if not 12 <= size <= MAX_QUERY_BYTES:
                return
            wire = receive_exact(self.request, size, deadline)
            if not self.server.gate.allow_query():
                return
            response = self.server.resolver.handle(wire, "tcp")
            if response is None:
                return
            self.request.settimeout(self.server.client_timeout)
            self.request.sendall(struct.pack("!H", len(response)) + response)


class UDPServer(BoundedServer, socketserver.UDPServer):
    # Read one extra byte to identify oversize datagrams without parsing a
    # silently truncated prefix as a valid request.
    max_packet_size = MAX_QUERY_BYTES + 1


class TCPServer(BoundedServer, socketserver.TCPServer):
    request_queue_size = 32


class GuardServer:
    def __init__(
        self, resolver, host="127.0.0.1", port=5533, *, workers=16, rate=100.0, burst=200, client_timeout=2.0
    ):
        address = ipaddress.ip_address(host)
        if not address.is_loopback or getattr(address, "scope_id", None):
            raise ValueError("this release only listens on literal loopback addresses")
        if type(port) is not int or not 0 <= port <= 65535:
            raise ValueError("invalid listen port")
        if not 0.1 <= client_timeout <= 30:
            raise ValueError("invalid client timeout")
        self.gate = WorkGate(workers, rate, burst)
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        self.servers = []
        self.threads = []
        try:
            for base, handler in ((TCPServer, TCPHandler), (UDPServer, UDPHandler)):
                server_type = type("Local" + base.__name__, (base,), {"address_family": family})
                server = server_type((str(address), port), handler)
                self.servers.append(server)
                port = server.server_address[1]
                server.gate = self.gate
                server.resolver = resolver
                server.client_timeout = client_timeout
                server.stopping = threading.Event()
        except BaseException:
            for server in self.servers:
                server.server_close()
            self.gate.close()
            raise
        self.address = (str(address), port)

    def start(self):
        if self.threads:
            raise RuntimeError("server is already running")
        for server in self.servers:
            thread = threading.Thread(
                target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
            )
            thread.start()
            self.threads.append(thread)
        return self

    def close(self):
        for server in self.servers:
            server.stopping.set()
        if self.threads:
            for server in self.servers:
                server.shutdown()
            for thread in self.threads:
                thread.join()
            self.threads.clear()
        self.gate.close()
        for server in self.servers:
            server.server_close()

    def __enter__(self):
        return self.start()

    def __exit__(self, *args):
        self.close()
