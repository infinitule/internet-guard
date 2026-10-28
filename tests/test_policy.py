import tempfile
import unittest
from pathlib import Path

import dns.name

from internet_guard.policy import (
    PolicyError,
    PolicyStore,
    import_feed,
    load_policy,
    matches,
    parse_domain,
    parse_feed,
)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "guard.toml"

    def policy(self, text=""):
        self.path.write_text("version=1\n" + text, encoding="utf-8")
        return load_policy(self.path)

    def test_suffix_boundary_case_and_trailing_dot(self):
        rules = frozenset([parse_domain("EVIL.test.")])
        self.assertTrue(matches(parse_domain("a.evil.test"), rules))
        self.assertFalse(matches(parse_domain("notevil.test"), rules))
        self.assertFalse(matches(parse_domain("evil.test.attacker.test"), rules))

    def test_rule_inputs_are_unambiguous(self):
        for value in (
            "",
            ".",
            "*.example.com",
            "https://example.com",
            "example..com",
            " example.com",
            "example.com ",
            "exämple.com",
            "127.0.0.1",
            "-bad.com",
            "a" * 64 + ".com",
            "example.com..",
            "bad\\046test",
            "a\n.test",
        ):
            with self.subTest(value=value), self.assertRaises(PolicyError):
                parse_domain(value)
        self.assertEqual(parse_domain("xn--bcher-kva.test"), (b"xn--bcher-kva", b"test"))

    def test_deny_precedes_allow(self):
        p = self.policy(
            'default_action="block"\nallow_domains=["example.com"]\nblock_domains=["bad.example.com"]'
        )
        self.assertIsNone(p.name_reason(dns.name.from_text("api.example.com")))
        self.assertEqual(p.name_reason(dns.name.from_text("bad.example.com")), "blocked_domain")
        self.assertEqual(p.name_reason(dns.name.from_text("other.test")), "not_allowlisted")

    def test_strict_types_and_unknown_keys(self):
        for text in (
            "versions=1",
            'mode="silent"',
            "mode=[]",
            "default_action=true",
            'block_non_global="false"',
            'block_domains="x.test"',
            "block_domains=[1]",
            'block_networks=["10.0.0.1/8"]',
            'feed_files=[""]',
        ):
            with self.subTest(text=text), self.assertRaises(PolicyError):
                self.policy(text)

    def test_boolean_is_not_version_one(self):
        self.path.write_text("version=true")
        with self.assertRaises(PolicyError):
            load_policy(self.path)

    def test_non_global_and_embedded_addresses(self):
        p = self.policy()
        for address in (
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "224.0.0.1",
            "0.0.0.0",
            "::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "64:ff9b::7f00:1",
            "2002:7f00:0001::1",
        ):
            with self.subTest(address=address):
                self.assertEqual(
                    p.address_reason(address, dns.name.from_text("public.test")), "non_global_address"
                )
        self.assertIsNone(p.address_reason("9.9.9.9", dns.name.from_text("public.test")))

    def test_private_exception_is_scoped_and_does_not_override_explicit_network_deny(self):
        p = self.policy('allow_private_for=["internal.test"]\nblock_networks=["10.0.0.0/8"]')
        self.assertIsNone(p.address_reason("192.168.1.2", dns.name.from_text("db.internal.test")))
        self.assertEqual(
            p.address_reason("192.168.1.2", dns.name.from_text("other.test")), "non_global_address"
        )
        self.assertEqual(p.address_reason("10.0.0.1", dns.name.from_text("internal.test")), "blocked_network")

    def test_ipv4_network_rule_applies_to_mapped_ipv6(self):
        p = self.policy('block_non_global=false\nblock_networks=["9.9.9.0/24"]')
        self.assertEqual(p.address_reason("::ffff:9.9.9.9", dns.name.root), "blocked_network")

    def test_feed_normalization_and_comments(self):
        self.assertEqual(
            parse_feed(b"# comment\nEVIL.test.\nevil.test # same\n"), frozenset([parse_domain("evil.test")])
        )
        self.assertEqual(len(parse_feed(b"0.0.0.0 evil.test other.test\n127.0.0.1 localhost\n", "hosts")), 2)

    def test_feed_rejects_bad_entire_input(self):
        for value in (
            b"",
            b"# only comment",
            b"com",
            b"good.test\nhttps://bad.test/",
            b"a.test b.test",
            b"\xff",
        ):
            with self.subTest(value=value), self.assertRaises(PolicyError):
                parse_feed(value)
        with self.assertRaises(PolicyError):
            parse_feed(b"9.9.9.9 domain.test", "hosts")

    def test_invalid_import_keeps_old_file(self):
        source = Path(self.temp.name) / "source.txt"
        destination = Path(self.temp.name) / "feed.domains"
        source.write_text("good.test\ninvalid*\n")
        destination.write_text("old.test\n")
        with self.assertRaises(PolicyError):
            import_feed(source, destination, "domains")
        self.assertEqual(destination.read_text(), "old.test\n")

    def test_import_writes_valid_atomic_output(self):
        source = Path(self.temp.name) / "source.txt"
        destination = Path(self.temp.name) / "feed.domains"
        source.write_text("evil.test\nEVIL.test\n")
        self.assertEqual(import_feed(source, destination, "domains"), 1)
        self.assertEqual(parse_feed(destination.read_bytes()), frozenset([parse_domain("evil.test")]))
        self.assertEqual(list(Path(self.temp.name).glob(".guard-feed-*")), [])

    def test_relative_feed_included_in_revision(self):
        feed = self.path.parent / "feed.txt"
        feed.write_text("evil.test\n")
        p = self.policy('feed_files=["feed.txt"]')
        self.assertEqual(p.name_reason(dns.name.from_text("a.evil.test")), "blocked_domain")
        feed.write_text("other.test\n")
        self.assertNotEqual(p.revision, load_policy(self.path).revision)

    def test_policy_reload_is_atomic(self):
        self.policy('block_domains=["old.test"]')
        store = PolicyStore(self.path)
        old = store.snapshot()
        self.path.write_text("broken TOML")
        with self.assertRaises(PolicyError):
            store.reload()
        self.assertIs(store.snapshot(), old)
        self.policy('block_domains=["new.test"]')
        new = store.reload()
        self.assertNotEqual(old.revision, new.revision)
        self.assertEqual(old.name_reason(dns.name.from_text("old.test")), "blocked_domain")

    def test_revision_ignores_formatting(self):
        first = self.policy('block_domains=["one.test", "two.test"]')
        second = self.policy('# rearranged\nblock_domains=["two.test", "one.test"]')
        self.assertEqual(first.revision, second.revision)


if __name__ == "__main__":
    unittest.main()
