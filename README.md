# Internet Guard

**Working code for one defensive layer: a local protective DNS forwarder.**

It evaluates domains before resolution and checks returned aliases, IP addresses,
and HTTPS/SVCB address hints before handing an answer to a client. Version 0.1.0
is an experimental reference implementation, with automated tests and an offline
demo. It is not a claim that Internet security, endpoint security, or AI safety
has been solved.

## Run the offline demonstration

Requires Python 3.11 or newer. From this repository's root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
.venv/bin/python -m internet_guard demo
```

The demo uses synthetic DNS answers and temporary loopback sockets. It makes no
external DNS queries. It verifies 12 cases: domain blocking, subdomain blocking,
CNAME blocking, private-address blocking, HTTPS address-hint blocking, and an
allowed answer, each over UDP and TCP. It exits nonzero if a case fails.

On Windows use `.venv\Scripts\python.exe` instead of `.venv/bin/python`.

## Run the guard

```bash
.venv/bin/python -m internet_guard check --policy examples/guard.toml
.venv/bin/python -m internet_guard serve --policy examples/guard.toml
```

This starts UDP and TCP DNS on **127.0.0.1:5533**. It does not change system DNS,
firewall rules, routes, browser settings, or other devices. The upstream is
`https://dns.quad9.net/dns-query`, reached at `9.9.9.9` with CA and hostname
verification. Quad9 describes this endpoint as providing threat blocking and
DNSSEC validation; see its [service documentation](https://quad9.net/service/service-addresses-and-features/).
That live upstream service supplies real threat intelligence. The bundled local
blocklist contains only `malware.test` and `phishing.test`, which are test fixtures.

With the guard running, these commands exercise it if `dig` is installed:

```bash
dig @127.0.0.1 -p 5533 malware.test A
dig @127.0.0.1 -p 5533 example.com A
dig @127.0.0.1 -p 5533 example.com A +tcp
```

The first query should return `REFUSED` without contacting the upstream. The
other queries require an Internet connection. Failed or unverifiable upstream
responses produce `SERVFAIL`; the guard never falls back to plaintext DNS.

Only software configured to send queries to this listener uses this policy.
Port 5533 is a development port; ordinary operating-system DNS configuration
usually expects port 53. Integration with an existing resolver, a reviewed local
port-53 service, or an application with an explicit DNS-server setting is a
separate deployment step. See [operations](docs/OPERATIONS.md).

## Capabilities and boundaries

| Implemented control | What it covers |
|---|---|
| Domain rules | Exact labels plus descendants; case insensitive; no substring matching |
| Strict allowlist | Unknown query names and answer connection targets refused; explicit denies win |
| Alias inspection | CNAME, DNAME, NS, PTR, MX, SRV, SVCB, HTTPS, NAPTR replacement names |
| Address inspection | A/AAAA answers and HTTPS/SVCB IP hints; explicit CIDRs and non-global addresses |
| Encrypted forwarding | HTTPS POST, verified TLS, literal bootstrap IP, bounded body, absolute deadline |
| Input validation | Single-question Internet-class DNS; bounded wire input; no transfers or ANY |
| Resource limits | Shared worker cap, query token bucket, bounded TCP frames and idle deadlines |
| Policy updates | Full validation before atomic in-memory replacement; failed reload keeps old policy |
| Audit | JSON events with per-run keyed domain tokens; no plaintext domain or client IP logging |

It cannot stop direct-IP connections, alternate DNS/DoH, compromised local
administrators, malicious payloads on allowed domains, stolen credentials,
unpatched software, or prompt injection. An AI agent needs process isolation,
tool authorization, and enforceable egress controls in addition to this DNS
policy. Custom NAT64 translations and names/addresses hidden in opaque DNS
record payloads are outside the inspection coverage.

`observe` mode records local would-block decisions but forwards the response.
The selected upstream may still perform its own blocking. Invalid packets and
transport failures remain rejected in either mode.

## Policy

Start with [examples/guard.toml](examples/guard.toml). For an AI-agent test
environment, [examples/agent-allowlist.toml](examples/agent-allowlist.toml) starts
with `default_action = "block"`. Replace its example domain with your approved
destinations and any required service aliases.

Rules are ASCII domains; use IDNA A-labels (`xn--...`) for international names.
A rule for `example.com` also covers `a.example.com`, but not
`notexample.com` or `example.com.attacker.test`. Wildcards and URLs are rejected.
Explicit domain denies always take precedence over allows.

Non-global addresses are blocked by default, including loopback, private,
link-local, shared, multicast, and reserved ranges according to Python's
`ipaddress` definitions. IPv4-mapped IPv6, 6to4, Teredo, and the well-known
NAT64 /96 prefix are also inspected for embedded IPv4 addresses. Internal zones
can be explicitly placed in `allow_private_for`; this never overrides a matching
`block_networks` rule. Private-address filtering can disrupt internal services.

## Import a reviewed threat feed

The importer reads a local operator-selected file; it does not fetch or trust
arbitrary feeds automatically. Review source, license, freshness, and false
positives before using a feed.

```bash
.venv/bin/python -m internet_guard import-feed \
  --input reviewed-hosts.txt --format hosts --output examples/threats.domains
```

Set `feed_files = ["threats.domains"]` in `examples/guard.toml`, then validate
the policy. One-domain-per-line feeds use `--format domains`. The entire input
must validate before output is replaced. Single-label/TLD feed entries are
rejected. This is syntax validation, not proof that a domain is malicious.

On POSIX, `kill -HUP <guard-process-id>` reloads policy and referenced feeds.
On Windows, restart the process. In-flight requests finish using their original
immutable policy snapshot. Clients may retain earlier DNS cache entries until
their TTL expires.

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -v
```

The TLS tests generate temporary certificates with the OpenSSL CLI. They verify
CA rejection, hostname rejection, HTTP bounds, response age handling, and a
slow-drip deadline against a local TLS server. If OpenSSL is missing those tests
are explicitly skipped. The malformed-input corpus is deterministic and contains
3,000 cases; it is not an exhaustive fuzzing or penetration test.

See [validation](docs/VALIDATION.md) for the recorded results and untested
deployment conditions, [threat model](docs/THREAT_MODEL.md) for trust boundaries,
and [SECURITY.md](SECURITY.md) for security review and reporting.

## Source layout

- `internet_guard/policy.py`: immutable policy, matching, validation, feed imports.
- `internet_guard/resolver.py`: DNS request/response checks and decisions.
- `internet_guard/upstream.py`: bounded, certificate-verified HTTPS transport.
- `internet_guard/server.py`: loopback UDP/TCP listeners and admission limits.
- `internet_guard/demo.py`: isolated synthetic exercise.
- `tests/`: policy, malformed traffic, transport, TLS, and lifecycle checks.

Runtime dependency: `dnspython==2.9.0`, pinned with a wheel hash in
`requirements.lock`. Its [release notes](https://dnspython.readthedocs.io/en/stable/whatsnew.html)
document a name-decompression CPU-consumption fix. Keep Python and this dependency
patched; a pinned hash ensures artifact integrity, not perpetual security.

Protocol references: [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035),
[RFC 8484](https://www.rfc-editor.org/rfc/rfc8484),
[RFC 8914](https://www.rfc-editor.org/rfc/rfc8914).

License: MIT. No affiliation with Quad9 or dnspython is implied.
