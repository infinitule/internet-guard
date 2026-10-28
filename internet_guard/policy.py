"""Strict, immutable domain/IP policy and atomic local feed imports."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import tempfile
import threading
import tomllib
from dataclasses import dataclass
from pathlib import Path

import dns.name

MAX_CONFIG_BYTES = 2 * 1024 * 1024
MAX_FEED_BYTES = 16 * 1024 * 1024
MAX_RULES = 100_000
LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\Z")
Domain = tuple[bytes, ...]
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class PolicyError(ValueError):
    pass


def bounded_read(path: Path, maximum: int) -> bytes:
    with path.open("rb") as source:
        data = source.read(maximum + 1)
    if len(data) > maximum:
        raise PolicyError(f"file exceeds {maximum} bytes: {path.name}")
    return data


def parse_domain(value: str) -> Domain:
    if not isinstance(value, str) or not value or value != value.strip():
        raise PolicyError("domains must be nonempty strings without surrounding whitespace")
    text = value.removesuffix(".").lower()
    try:
        text.encode("ascii")
    except UnicodeEncodeError as exc:
        raise PolicyError("use ASCII IDNA A-labels (xn--) for international domains") from exc
    labels = text.split(".")
    if len(text) > 253 or any(not LABEL.fullmatch(label) for label in labels):
        raise PolicyError(f"invalid domain: {value!r}; wildcards and URLs are unsupported")
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return tuple(label.encode("ascii") for label in labels)
    raise PolicyError("put IP ranges in block_networks, not domain lists")


def labels_for(name: dns.name.Name) -> Domain:
    return tuple(label.lower() for label in name.labels if label)


def matches(labels: Domain, rules: frozenset[Domain]) -> bool:
    return any(labels[index:] in rules for index in range(len(labels)))


def parse_feed(data: bytes, kind: str = "domains") -> frozenset[Domain]:
    if len(data) > MAX_FEED_BYTES:
        raise PolicyError("feed is too large")
    if kind not in {"domains", "hosts"}:
        raise PolicyError("feed format must be domains or hosts")
    try:
        lines = data.decode("utf-8-sig").splitlines()
    except UnicodeDecodeError as exc:
        raise PolicyError("feed is not UTF-8") from exc
    result: set[Domain] = set()
    for line_number, line in enumerate(lines, 1):
        tokens = line.split("#", 1)[0].split()
        if not tokens:
            continue
        if kind == "hosts":
            if len(tokens) < 2 or tokens[0] not in {"0.0.0.0", "127.0.0.1", "::", "::1"}:  # noqa: S104 - hosts-file sink values, not listeners
                raise PolicyError(f"line {line_number}: expected a sinkhole hosts entry")
            tokens = tokens[1:]
        elif len(tokens) != 1:
            raise PolicyError(f"line {line_number}: expected one domain")
        for token in tokens:
            if kind == "hosts" and token.lower().removesuffix(".") in {"localhost", "localhost.localdomain"}:
                continue
            domain = parse_domain(token)
            if len(domain) < 2:
                raise PolicyError(f"line {line_number}: single-label/TLD feed rules are rejected")
            result.add(domain)
            if len(result) > MAX_RULES:
                raise PolicyError("too many feed rules")
    if not result:
        raise PolicyError("feed has no usable domains")
    return frozenset(result)


@dataclass(frozen=True)
class Policy:
    mode: str
    default_action: str
    blocked: frozenset[Domain]
    allowed: frozenset[Domain]
    private_exceptions: frozenset[Domain]
    networks: tuple[Network, ...]
    block_non_global: bool
    revision: str

    def name_reason(self, name: dns.name.Name, *, explicit_only: bool = False) -> str | None:
        labels = labels_for(name)
        if matches(labels, self.blocked):
            return "blocked_domain"
        if not explicit_only and self.default_action == "block" and not matches(labels, self.allowed):
            return "not_allowlisted"
        return None

    def address_reason(self, value: str, origin: dns.name.Name) -> str | None:
        address = ipaddress.ip_address(value)
        addresses = [address]
        if isinstance(address, ipaddress.IPv6Address):
            if address.ipv4_mapped:
                addresses.append(address.ipv4_mapped)
            if address.sixtofour:
                addresses.append(address.sixtofour)
            if address.teredo:
                addresses.extend(address.teredo)
            # The well-known NAT64 /96 prefix. Custom translator prefixes are
            # outside this DNS-only control's coverage.
            if address in ipaddress.ip_network("64:ff9b::/96"):
                addresses.append(ipaddress.IPv4Address(int(address) & 0xFFFFFFFF))
        if any(ip.version == net.version and ip in net for ip in addresses for net in self.networks):
            return "blocked_network"
        if self.block_non_global and not matches(labels_for(origin), self.private_exceptions):
            if any(not ip.is_global or ip.is_multicast or ip.is_reserved for ip in addresses):
                return "non_global_address"
        return None


def load_policy(path: str | Path) -> Policy:
    path = Path(path)
    raw = bounded_read(path, MAX_CONFIG_BYTES)
    try:
        config = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise PolicyError("invalid UTF-8 TOML policy") from exc
    known = {
        "version",
        "mode",
        "default_action",
        "block_domains",
        "allow_domains",
        "allow_private_for",
        "block_networks",
        "block_non_global",
        "feed_files",
    }
    if unknown := config.keys() - known:
        raise PolicyError(f"unknown policy keys: {', '.join(sorted(unknown))}")
    if type(config.get("version")) is not int or config["version"] != 1:
        raise PolicyError("policy version must be 1")
    mode = config.get("mode", "enforce")
    action = config.get("default_action", "allow")
    if mode not in ("enforce", "observe") or action not in ("allow", "block"):
        raise PolicyError("invalid mode or default_action")
    non_global = config.get("block_non_global", True)
    if type(non_global) is not bool:
        raise PolicyError("block_non_global must be a boolean")

    def strings(key: str) -> list[str]:
        values = config.get(key, [])
        if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
            raise PolicyError(f"{key} must be a list of strings")
        if len(values) > MAX_RULES:
            raise PolicyError(f"too many entries in {key}")
        return values

    blocked = set(map(parse_domain, strings("block_domains")))
    allowed = frozenset(map(parse_domain, strings("allow_domains")))
    exceptions = frozenset(map(parse_domain, strings("allow_private_for")))
    if len(strings("feed_files")) > 16:
        raise PolicyError("at most 16 feed files are supported")
    for filename in strings("feed_files"):
        if not filename:
            raise PolicyError("feed path must not be empty")
        feed = bounded_read(path.parent / filename, MAX_FEED_BYTES)
        blocked.update(parse_feed(feed))
        if len(blocked) > MAX_RULES:
            raise PolicyError("too many combined block rules")
    if len(blocked) + len(allowed) + len(exceptions) > MAX_RULES:
        raise PolicyError("too many combined domain rules")
    try:
        networks = tuple(ipaddress.ip_network(value, strict=True) for value in strings("block_networks"))
    except ValueError as exc:
        raise PolicyError("block_networks must contain canonical IP addresses or CIDRs") from exc
    if len(networks) > 1024:
        raise PolicyError("at most 1024 network rules are supported")

    def texts(domains):
        return sorted(b".".join(domain).decode("ascii") for domain in domains)

    canonical = json.dumps(
        {
            "version": 1,
            "mode": mode,
            "default_action": action,
            "blocked": texts(blocked),
            "allowed": texts(allowed),
            "private_exceptions": texts(exceptions),
            "block_non_global": non_global,
            "networks": sorted(map(str, networks)),
        },
        sort_keys=True,
    ).encode()
    return Policy(
        mode,
        action,
        frozenset(blocked),
        allowed,
        exceptions,
        networks,
        non_global,
        hashlib.sha256(canonical).hexdigest()[:24],
    )


class PolicyStore:
    """A query holds one complete snapshot, even during a successful reload."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._policy = load_policy(self.path)

    def snapshot(self) -> Policy:
        with self._lock:
            return self._policy

    def reload(self) -> Policy:
        candidate = load_policy(self.path)  # Invalid updates never replace the live snapshot.
        with self._lock:
            self._policy = candidate
        return candidate


def import_feed(source: Path, destination: Path, kind: str) -> int:
    """Validate the complete input before atomically replacing the destination."""
    if source.resolve() == destination.resolve():
        raise PolicyError("input and output must be different files")
    data = bounded_read(source, MAX_FEED_BYTES)
    domains = parse_feed(data, kind)
    header = f"# Imported from operator-selected data; not independently verified.\n# input-sha256: {hashlib.sha256(data).hexdigest()}\n"
    body = "\n".join(sorted(b".".join(d).decode("ascii") for d in domains)) + "\n"
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="ascii", dir=destination.parent, prefix=".guard-feed-", delete=False
        ) as target:
            temporary = Path(target.name)
            target.write(header + body)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, destination)
        temporary = None
        if hasattr(os, "O_DIRECTORY"):
            fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return len(domains)
