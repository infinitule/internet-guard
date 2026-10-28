"""DNS request validation, policy decisions, and privacy-preserving audit events."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import struct
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timezone

import dns.edns
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype

from .policy import Policy, PolicyStore
from .upstream import UpstreamError

MAX_QUERY_BYTES = 4096
MAX_UDP_BYTES = 1232
TARGET_FIELDS = {
    "CNAME": "target",
    "DNAME": "target",
    "NS": "target",
    "PTR": "target",
    "MX": "exchange",
    "SRV": "target",
    "SVCB": "target",
    "HTTPS": "target",
    "NAPTR": "replacement",
}


class Audit:
    def __init__(self, stream=None):
        self.stream = sys.stderr if stream is None else stream
        self._key = secrets.token_bytes(32)
        self._lock = threading.Lock()
        self.counts = Counter()

    def emit(self, event: str, **fields):
        name = fields.pop("name", None)
        if name is not None:
            fields["name_token"] = hmac.new(
                self._key, name.canonicalize().to_wire(), hashlib.sha256
            ).hexdigest()[:32]
        record = {"time": datetime.now(timezone.utc).isoformat(), "event": event, **fields}
        with self._lock:
            self.counts[event] += 1
            try:
                self.stream.write(json.dumps(record, sort_keys=True) + "\n")
                self.stream.flush()
            except (OSError, ValueError):
                # Losing a log sink must not turn a block into an allow.
                self.counts["audit_write_error"] += 1


def synthetic(query, rcode, *, ede=None):
    response = dns.message.make_response(query, recursion_available=True, our_payload=MAX_UDP_BYTES)
    response.flags &= ~(dns.flags.AD | dns.flags.AA | dns.flags.CD)
    response.set_rcode(rcode)
    if query.edns >= 0:
        options = [] if ede is None else [dns.edns.EDEOption(ede)]
        response.use_edns(edns=0, payload=MAX_UDP_BYTES, options=options)
    return response


def encode_response(response, query, transport):
    maximum = (
        65535
        if transport == "tcp"
        else min(MAX_UDP_BYTES, max(512, query.payload if query.edns >= 0 else 512))
    )
    return response.to_wire(max_size=maximum, prefer_truncation=True)


def answer_reason(policy: Policy, response, origin: dns.name.Name):
    for section in (response.answer, response.authority, response.additional):
        for rrset in section:
            reason = policy.name_reason(rrset.name, explicit_only=True)
            if reason:
                return reason
            kind = dns.rdatatype.to_text(rrset.rdtype)
            for record in rrset:
                field = TARGET_FIELDS.get(kind)
                if field:
                    target = getattr(record, field)
                    if target != dns.name.root:
                        # Delegation names in authority/additional sections are
                        # subject to explicit denies, not the strict allowlist.
                        explicit = section is not response.answer
                        reason = policy.name_reason(target, explicit_only=explicit)
                        if reason:
                            return reason
                if kind in {"A", "AAAA"}:
                    reason = policy.address_reason(record.address, origin)
                    if reason:
                        return reason
                if kind in {"SVCB", "HTTPS"}:
                    for key in (4, 6):  # ipv4hint and ipv6hint; not a separate DNS lookup.
                        parameter = record.params.get(key)
                        if parameter:
                            for address in parameter.addresses:
                                reason = policy.address_reason(address, origin)
                                if reason:
                                    return reason
    return None


class GuardResolver:
    def __init__(self, policies: PolicyStore, upstream, audit: Audit | None = None):
        self.policies = policies
        self.upstream = upstream
        self.audit = audit or Audit()

    def handle(self, wire: bytes, transport="udp") -> bytes | None:
        started = time.monotonic()
        if len(wire) < 12 or len(wire) > MAX_QUERY_BYTES:
            self.audit.emit("malformed", reason="query_size")
            return None
        identifier, flags, qd, an, ns, ar = struct.unpack("!6H", wire[:12])
        if flags & dns.flags.QR:
            return None  # Never answer an answer.
        if (
            flags & 0x7800
            or qd != 1
            or an
            or ns
            or ar > 1
            or flags & ~(dns.flags.RD | dns.flags.AD | dns.flags.CD)
        ):
            self.audit.emit("malformed", reason="query_header")
            return struct.pack(
                "!6H", identifier, dns.flags.QR | (flags & dns.flags.RD) | dns.rcode.FORMERR, 0, 0, 0, 0
            )
        try:
            query = dns.message.from_wire(wire, ignore_trailing=False)
        except (dns.exception.DNSException, ValueError):
            self.audit.emit("malformed", reason="query_parse")
            return struct.pack(
                "!6H", identifier, dns.flags.QR | (flags & dns.flags.RD) | dns.rcode.FORMERR, 0, 0, 0, 0
            )
        if query.additional or query.had_tsig or query.edns > 0:
            return encode_response(synthetic(query, dns.rcode.REFUSED), query, transport)
        question = query.question[0]
        if question.rdclass != dns.rdataclass.IN or question.rdtype in {
            dns.rdatatype.AXFR,
            dns.rdatatype.IXFR,
            dns.rdatatype.ANY,
            dns.rdatatype.OPT,
            dns.rdatatype.TSIG,
            0,
            249,
            253,
            254,
        }:
            return encode_response(synthetic(query, dns.rcode.REFUSED), query, transport)

        policy = self.policies.snapshot()
        reason = policy.name_reason(question.name)

        def finish(response, event, why):
            self.audit.emit(
                event,
                name=question.name,
                reason=why,
                policy=policy.revision,
                qtype=int(question.rdtype),
                mode=policy.mode,
                transport=transport,
                elapsed_ms=round((time.monotonic() - started) * 1000, 2),
            )
            return encode_response(response, query, transport)

        if reason and policy.mode == "enforce":
            return finish(synthetic(query, dns.rcode.REFUSED, ede=15), "blocked", reason)

        # Rebuild rather than forwarding client options (ECS, cookies, padding),
        # TSIG, arbitrary additional records, or the DNSSEC-check-disable bit.
        forwarded = dns.message.make_query(
            question.name,
            question.rdtype,
            question.rdclass,
            use_edns=0,
            payload=MAX_UDP_BYTES,
            want_dnssec=bool(query.ednsflags & dns.flags.DO),
        )
        forwarded.flags = query.flags & (dns.flags.RD | dns.flags.AD)
        try:
            raw_response = self.upstream.exchange(forwarded.to_wire())
            if not 12 <= len(raw_response) <= 65535:
                raise UpstreamError("invalid_dns_size")
            response = dns.message.from_wire(raw_response, ignore_trailing=False)
            if (
                not forwarded.is_response(response)
                or len(response.question) != 1
                or response.question != forwarded.question
                or response.flags & dns.flags.TC
                or response.had_tsig
                or response.edns > 0
            ):
                raise UpstreamError("invalid_dns_response")
            answer_block = answer_reason(policy, response, question.name)
            reason = reason or answer_block
        except (UpstreamError, dns.exception.DNSException, OSError, ValueError):
            return finish(synthetic(query, dns.rcode.SERVFAIL, ede=23), "upstream_error", "upstream_unusable")

        if reason and policy.mode == "enforce":
            return finish(synthetic(query, dns.rcode.REFUSED, ede=15), "blocked", reason)
        response.id = query.id
        response.question = query.question
        response.flags &= ~(dns.flags.CD | dns.flags.RD)
        response.flags |= query.flags & dns.flags.RD
        # AD is an upstream assertion, not a local DNSSEC validation result.
        if not (query.flags & dns.flags.AD or query.ednsflags & dns.flags.DO):
            response.flags &= ~dns.flags.AD
        rcode = response.rcode()
        safe_options = [option for option in response.options if isinstance(option, dns.edns.EDEOption)]
        if query.edns >= 0:
            response.use_edns(
                edns=0, payload=MAX_UDP_BYTES, ednsflags=query.ednsflags & dns.flags.DO, options=safe_options
            )
        else:
            response.use_edns(edns=False)
            if rcode > 15:
                return finish(
                    synthetic(query, dns.rcode.SERVFAIL), "upstream_error", "extended_rcode_without_edns"
                )
        response.set_rcode(rcode)
        return finish(response, "would_block" if reason else "forwarded", reason or "policy_pass")
