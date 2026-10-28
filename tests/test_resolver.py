import io
import json
import random
import struct
import tempfile
import unittest
from pathlib import Path

import dns.edns
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rrset

from internet_guard.policy import PolicyStore
from internet_guard.resolver import Audit, GuardResolver
from internet_guard.upstream import UpstreamError


class FixtureUpstream:
    def __init__(self):
        self.calls = []
        self.records = []
        self.additional = []
        self.error = None
        self.mutate = lambda r: r

    def exchange(self, wire):
        query = dns.message.from_wire(wire)
        self.calls.append(query)
        if self.error:
            raise self.error
        response = dns.message.make_response(query, recursion_available=True)
        response.answer.extend(self.records)
        response.additional.extend(self.additional)
        return self.mutate(response).to_wire(max_size=65535)


class ResolverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "policy.toml"
        self.upstream = FixtureUpstream()
        self.log = io.StringIO()
        self.configure()

    def configure(self, extra=""):
        self.path.write_text('version=1\nblock_domains=["malware.test"]\n' + extra)
        self.guard = GuardResolver(PolicyStore(self.path), self.upstream, Audit(self.log))

    def ask(self, name="good.test", kind="A", transport="udp", query=None):
        query = query or dns.message.make_query(name, kind, use_edns=0)
        return dns.message.from_wire(self.guard.handle(query.to_wire(), transport))

    def record(self, kind, data, name="good.test."):
        self.upstream.records = [dns.rrset.from_text(name, 60, "IN", kind, data)]

    def test_direct_block_never_contacts_upstream(self):
        response = self.ask("x.MALWARE.test.")
        self.assertEqual(response.rcode(), dns.rcode.REFUSED)
        self.assertEqual(self.upstream.calls, [])
        self.assertEqual(response.options[0].code, 15)
        self.assertFalse(response.flags & (dns.flags.AD | dns.flags.AA))

    def test_suffix_lookalikes_are_not_blocked(self):
        self.assertEqual(self.ask("notmalware.test").rcode(), dns.rcode.NOERROR)
        self.assertEqual(self.ask("malware.test.other.test").rcode(), dns.rcode.NOERROR)

    def test_dotted_wire_label_is_not_split(self):
        self.configure('default_action="block"\nallow_domains=["good.test"]')
        name = dns.name.Name((b"good.test", b""))
        self.assertEqual(self.ask(query=dns.message.make_query(name, "A")).rcode(), dns.rcode.REFUSED)

    def test_alias_and_service_targets_are_checked(self):
        for kind, data in (
            ("CNAME", "malware.test."),
            ("DNAME", "malware.test."),
            ("MX", "10 malware.test."),
            ("SRV", "0 0 443 malware.test."),
            ("HTTPS", "1 malware.test."),
            ("SVCB", "0 malware.test."),
            ("NS", "malware.test."),
            ("PTR", "malware.test."),
            ("NAPTR", '10 10 "s" "SIP+D2U" "" malware.test.'),
        ):
            with self.subTest(kind=kind):
                self.record(kind, data)
                self.assertEqual(self.ask(kind=kind).rcode(), dns.rcode.REFUSED)

    def test_strict_mode_checks_alias_allowlist(self):
        self.configure('default_action="block"\nallow_domains=["good.test"]')
        self.record("CNAME", "unlisted.test.")
        self.assertEqual(self.ask().rcode(), dns.rcode.REFUSED)

    def test_answer_owner_explicit_block(self):
        self.record("A", "9.9.9.9", name="malware.test.")
        self.assertEqual(self.ask().rcode(), dns.rcode.REFUSED)

    def test_private_ipv4_ipv6_and_metadata_addresses(self):
        for kind, address in (
            ("A", "169.254.169.254"),
            ("A", "127.0.0.1"),
            ("AAAA", "::1"),
            ("AAAA", "::ffff:10.0.0.1"),
        ):
            with self.subTest(address=address):
                self.record(kind, address)
                self.assertEqual(self.ask(kind=kind).rcode(), dns.rcode.REFUSED)

    def test_private_svcb_hints_are_checked(self):
        for kind, parameter in (("HTTPS", 'ipv4hint="127.0.0.1"'), ("SVCB", 'ipv6hint="::1"')):
            with self.subTest(kind=kind):
                self.record(kind, "1 . " + parameter)
                self.assertEqual(self.ask(kind=kind).rcode(), dns.rcode.REFUSED)

    def test_additional_glue_is_checked(self):
        self.upstream.additional = [dns.rrset.from_text("glue.test.", 60, "IN", "A", "10.1.1.1")]
        self.assertEqual(self.ask().rcode(), dns.rcode.REFUSED)

    def test_public_response_is_forwarded_with_client_id(self):
        self.record("A", "9.9.9.9")
        query = dns.message.make_query("good.test", "A")
        query.id = 1234
        response = self.ask(query=query)
        self.assertEqual(response.id, 1234)
        self.assertEqual(response.answer[0][0].address, "9.9.9.9")

    def test_query_options_and_check_disable_are_not_forwarded(self):
        query = dns.message.make_query(
            "good.test", "A", use_edns=0, options=[dns.edns.ECSOption("192.0.2.1", 24)], want_dnssec=True
        )
        query.flags |= dns.flags.CD
        self.ask(query=query)
        forwarded = self.upstream.calls[-1]
        self.assertEqual(forwarded.options, ())
        self.assertFalse(forwarded.flags & dns.flags.CD)
        self.assertTrue(forwarded.ednsflags & dns.flags.DO)

    def test_response_ecs_is_removed(self):
        def mutate(response):
            response.use_edns(options=[dns.edns.ECSOption("192.0.2.1", 24)])
            return response

        self.upstream.mutate = mutate
        self.assertEqual(self.ask().options, ())

    def test_observe_logs_without_enforcing_domain_or_ip_block(self):
        self.configure('mode="observe"')
        self.record("A", "127.0.0.1", name="malware.test.")
        self.assertEqual(self.ask("malware.test").rcode(), dns.rcode.NOERROR)
        self.assertEqual(self.guard.audit.counts["would_block"], 1)

    def test_failure_never_falls_back(self):
        self.upstream.error = UpstreamError("timeout")
        self.assertEqual(self.ask().rcode(), dns.rcode.SERVFAIL)
        self.assertEqual(len(self.upstream.calls), 1)

    def test_observe_still_rejects_upstream_failure(self):
        self.configure('mode="observe"')
        self.upstream.error = UpstreamError("timeout")
        self.assertEqual(self.ask().rcode(), dns.rcode.SERVFAIL)

    def test_response_id_question_and_truncation_are_validated(self):
        def bad_id(response):
            response.id ^= 1
            return response

        def bad_question(response):
            response.question = dns.message.make_query("wrong.test", "A").question
            return response

        def truncated(response):
            response.flags |= dns.flags.TC
            return response

        for mutate in (bad_id, bad_question, truncated):
            with self.subTest(mutate=mutate.__name__):
                self.upstream.mutate = mutate
                self.assertEqual(self.ask().rcode(), dns.rcode.SERVFAIL)

    def test_large_udp_reply_truncates_but_tcp_preserves(self):
        self.upstream.records = [
            dns.rrset.from_text(
                "good.test.", 60, "IN", "TXT", *['"' + str(i) + "x" * 230 + '"' for i in range(20)]
            )
        ]
        query = dns.message.make_query("good.test", "TXT")
        udp = self.guard.handle(query.to_wire(), "udp")
        self.assertLessEqual(len(udp), 512)
        self.assertTrue(dns.message.from_wire(udp).flags & dns.flags.TC)
        tcp = self.guard.handle(query.to_wire(), "tcp")
        self.assertGreater(len(tcp), 1232)
        self.assertFalse(dns.message.from_wire(tcp).flags & dns.flags.TC)

    def test_oversize_edns_payload_cannot_expand_udp_limit(self):
        self.upstream.records = [
            dns.rrset.from_text(
                "good.test.", 60, "IN", "TXT", *['"' + str(i) + "x" * 230 + '"' for i in range(20)]
            )
        ]
        query = dns.message.make_query("good.test", "TXT", use_edns=0, payload=65535)
        self.assertLessEqual(len(self.guard.handle(query.to_wire())), 1232)

    def test_log_uses_ephemeral_hmac_not_plaintext(self):
        self.ask("private-query.test")
        value = self.log.getvalue()
        self.assertNotIn("private-query", value)
        self.assertNotIn("127.0.0.1", value)
        first = json.loads(value.splitlines()[-1])["name_token"]
        other = io.StringIO()
        Audit(other).emit("test", name=dns.name.from_text("private-query.test"))
        self.assertNotEqual(first, json.loads(other.getvalue())["name_token"])

    def test_broken_audit_sink_does_not_allow_blocked_request(self):
        self.log.close()
        self.assertEqual(self.ask("malware.test").rcode(), dns.rcode.REFUSED)
        self.assertEqual(self.guard.audit.counts["audit_write_error"], 1)

    def test_query_replies_are_dropped(self):
        query = dns.message.make_query("good.test", "A")
        self.assertIsNone(self.guard.handle(dns.message.make_response(query).to_wire()))

    def test_meta_types_refused(self):
        for kind in ("ANY", "AXFR", "IXFR"):
            with self.subTest(kind=kind):
                self.assertEqual(self.ask(kind=kind).rcode(), dns.rcode.REFUSED)
        self.assertFalse(self.upstream.calls)

    def test_multiple_questions_refused(self):
        query = dns.message.make_query("good.test", "A")
        query.question.extend(dns.message.make_query("other.test", "A").question)
        self.assertEqual(self.ask(query=query).rcode(), dns.rcode.FORMERR)
        self.assertFalse(self.upstream.calls)

    def test_compression_loop_is_rejected(self):
        packet = struct.pack("!6H", 1, 256, 1, 0, 0, 0) + b"\xc0\x0c\x00\x01\x00\x01"
        self.assertEqual(dns.message.from_wire(self.guard.handle(packet)).rcode(), dns.rcode.FORMERR)

    def test_trailing_junk_is_rejected(self):
        wire = dns.message.make_query("good.test", "A").to_wire() + b"extra"
        self.assertEqual(dns.message.from_wire(self.guard.handle(wire)).rcode(), dns.rcode.FORMERR)

    def test_deterministic_malformed_wire_corpus(self):
        rng = random.Random(1819)
        self.upstream.error = UpstreamError("offline corpus")
        valid = dns.message.make_query("good.test", "A").to_wire()
        for index in range(3000):
            if index % 2:
                raw = bytearray(valid)
                for _ in range(rng.randrange(1, 8)):
                    raw[rng.randrange(len(raw))] = rng.randrange(256)
                raw = bytes(raw)
            else:
                raw = rng.randbytes(rng.randrange(0, 400))
            result = self.guard.handle(raw)
            if result is not None:
                self.assertLessEqual(len(result), 1232)
                dns.message.from_wire(result)


if __name__ == "__main__":
    unittest.main()
