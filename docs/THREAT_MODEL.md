# Threat model and trust boundaries

## Protected path

A local client sends a DNS question to the loopback listener. The guard takes a
policy snapshot, validates the question, and applies domain policy. Permitted
questions are rebuilt without ECS, cookies, extra records, or CD, then sent to
the configured DoH endpoint. The reply must match the request before name and
address policy is applied. Local policy blocks return REFUSED; transport and
unusable-response errors return SERVFAIL. There is no alternate plaintext path.

This protects only that DNS path. Merely running the process does not route
applications through it or force them to accept its decisions.

## Trusted components

- The host OS, Python interpreter, trust store, dnspython dependency, and operator.
- The policy file and imported feed content. Syntax validation cannot establish
  threat accuracy, authenticity, freshness, or licensing.
- The selected upstream for recursive answers, its own filtering, and DNSSEC
  validation. This program does not perform local DNSSEC validation. AD is passed
  only as an upstream assertion when the client requests AD or DNSSEC records.
- Applications to use this resolver and honor its results. Strong adversarial
  egress enforcement requires a separately controlled firewall or proxy.

## Attacks and controls

| Attempt | Control and limit |
|---|---|
| Contact a configured malicious domain | Exact-label suffix policy before upstream traffic; unknown domains can pass in default-allow mode |
| Redirect an allowed query to a denied alias | Inspect supported target-bearing records; opaque TXT/URI/NAPTR regex content is not interpreted |
| Return loopback, private, or metadata-service IPs | Inspect all A/AAAA and known service-binding hints; scoped operator exceptions are explicit |
| Return mismatched or unsolicited DNS data | Check QR, ID, question, opcode, parsing, and truncation on a single TLS exchange |
| Observe/manipulate upstream traffic in transit | TLS CA/hostname verification; the configured upstream remains a trusted party |
| Exploit bootstrap DNS recursion | Connect directly to an explicit IP while keeping URL-hostname TLS authentication |
| Stall workers with slow traffic | Upstream total deadline, client-frame deadline, finite query count, worker cap, query rate cap |
| Flood an exposed public resolver | Non-loopback listening addresses rejected; same-host resource exhaustion is still possible |
| Insert a partly written or malformed policy/feed | Full validation and snapshot swap; importer uses atomic file replacement |
| Infer browsing from a log file | No plaintext domains or client IPs; ephemeral keyed tokens, with residual timing correlation |

## Semantics that need operational care

Explicit denies always win. An allowlist is not an override for a domain block.
In strict mode, direct answer target names must also be allowlisted. Names only
present as authority/additional delegation targets receive explicit-deny checks,
not default-deny checks; otherwise normal DNS delegations would be unusable.
All returned address records still receive address policy.

The alias inspector examines complete DNS responses, not HTTP redirects. A later
DNS query for an HTTP redirect is checked if it uses this guard. Direct IP URLs,
application caches, other resolvers, custom IPv6 translation prefixes, DNS tunnels
within allowed domains, and content served from a compromised allowed host remain
possible bypasses. IP classifications can change between Python releases.

No DNS answer cache is maintained here. HTTP Age is subtracted from forwarded
TTLs; downstream caches can retain previously allowed answers until expiration.
An in-flight request retains the old policy snapshot through a reload.

`observe` deliberately forwards local policy violations. The upstream's own
threat filtering may still block them. Observe mode is useful for assessing
false positives, and is not a local protection mode.

The guard does not authenticate loopback clients. A separate process with the
same host access can consume capacity, tamper with files it can write, or bypass
DNS. Per-query HTTPS connections prioritize implementation simplicity over high
throughput; capacity and availability need independent measurement.

## Before wider deployment

Review the source and packet formats independently, perform coverage-guided
fuzzing, test resolver compatibility and sustained load, evaluate feed provenance
and rollback, and design high availability and enforced egress for the target
platform. These are outstanding engineering gates, not completed work.
