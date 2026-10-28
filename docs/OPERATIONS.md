# Operating the local prototype

## Start and stop

Run the documented `serve` command from the repository root as an unprivileged
user. The defaults are loopback IPv4, port 5533, 16 active workers, a shared
100-query/second token bucket with burst 200, a 2-second TCP frame deadline,
16 queries per TCP connection, and a 3-second upstream deadline. UDP replies are
capped at the smaller of the client's advertised size and 1,232 bytes; clients
without EDNS get at most 512 bytes and can retry with TCP when TC is set.

Use Ctrl-C or SIGTERM to stop. No system configuration is automatically changed,
so there is no system rollback to perform for the demo/default launch. A later
deployment that changes system DNS must record and restore the previous resolver
configuration separately.

IPv6 loopback is supported with `--listen ::1`. This release intentionally rejects
LAN and public bind addresses; it is not a router or ISP resolver release.

## Configuration and availability

Keep policy and feed files writable only by the operator. Run `check` before a
reload. On POSIX, SIGHUP requests a reload outside the signal handler. The complete
candidate loads before the live snapshot changes; a rejected update emits
`policy_reload_rejected`. Config and feed edits should themselves be atomic.

Watch for `ready`, `blocked`, `would_block`, `forwarded`, `upstream_error`,
`malformed`, `policy_reloaded`, `policy_reload_rejected`, and `internal_error`
events on stderr. `forwarded` means the local policy accepted a valid upstream
response; it does not mean the queried site exists, is trustworthy, or was not
blocked by the upstream. The stop event includes aggregate admission rejections.
Malformed requests are never forwarded. UDP overload is dropped; saturated TCP
connections are closed.

Audit output is a stream, not an internally rotated file. Configure bounded
retention in your process supervisor if persisting it. A broken audit sink does
not disable policy blocking. A blocked log pipe can affect performance.

An upstream outage produces SERVFAIL. There is no automatic fallback and no
redundant upstream in 0.1.0. Test availability and false-positive behavior before
making any dependent application rely on it. TLS uses the platform CA store.
Environments that require an HTTP proxy cannot use this direct-IP transport
unchanged; it deliberately ignores environment proxy settings.

## AI-agent integration

Use the strict sample policy in an isolated test environment. Populate permitted
destinations and required service aliases. Confirm rejected lookups do not cause
the agent to use another DNS server or hard-coded IP. An enforced sandbox egress
rule, scoped tool credentials, data-exfiltration controls, and human authorization
for impactful tool actions are separate controls; this prototype installs none.

## GitHub publication

The repository includes tests, a dependency lock, and a CI workflow. Before
publication, keep local policy, feeds, logs, credentials, temporary TLS keys, and
virtual environments out of Git. Create a private repository unless the owner
explicitly chooses public visibility. Upload source only; publication does not
deploy or activate the resolver on any device.

If using a separately installed and authenticated GitHub CLI, from this folder:

```bash
gh repo create internet-guard --private --source=. --remote=origin --push
```

This command assumes the folder has an initial Git commit and no conflicting
repository or origin. The archive also includes an optional Git bundle that can
recreate the prepared history without assuming an authenticated session here.
After extracting the archive, this recreates the committed source in a new folder:

```bash
git clone internet-guard.bundle internet-guard-from-history
```

The included wheel can also be installed after the locked dependency:

```bash
python -m pip install --no-deps internet_guard-0.1.0-py3-none-any.whl
```

Run these two commands from the archive's outer directory, where the bundle and
wheel are located. Repository source and example policies are under `internet-guard/`.
