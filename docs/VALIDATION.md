# Validation record — 2026-10-29

## Executed locally

Environment: Linux, CPython 3.12.14, dnspython 2.9.0, OpenSSL CLI available.
Checks were repeated in a clean virtual environment containing only the runtime
dependency after source formatting.

| Check | Result |
|---|---|
| Unit and integration suite | 60 tests passed; no skips |
| Offline UDP/TCP demonstration | 12 of 12 cases passed |
| Deterministic malformed-wire corpus | 3,000 inputs handled without an uncaught exception in that test |
| Local TLS positive path | Verified HTTPS POST works without a bootstrap hostname lookup |
| Local TLS negative paths | Untrusted CA and wrong hostname rejected |
| HTTP response handling | Redirect, wrong type, compressed body, oversize body, invalid age rejected; chunked body supported |
| Resource deadlines | Slow-drip HTTP headers, idle TCP, and partial TCP framing covered |
| Policy failures | Invalid import/reload preserves previous valid output/snapshot |
| Static lint | Ruff 0.17.3 passed configured correctness, import, bug-risk, and security rules |
| Dependency vulnerability query | pip-audit 2.10.1 reported no known vulnerabilities for dnspython 2.9.0 at check time |
| Hash-verified installation | Runtime wheel installed from requirements.lock in a clean virtual environment |
| Installable package | Wheel built and installed; CLI startup, UDP block, SIGHUP reload, rejected update, and graceful shutdown passed |

The dependency scan is not a source-code audit, does not cover Python or OS
components, and cannot establish the absence of undisclosed vulnerabilities.
Its machine-readable result is [dependency-audit.json](dependency-audit.json).
Lint exclusions in tests cover intentional negative fixtures; the production
sinkhole-format literal is annotated as not being a listening address.

## Remote CI evidence

[Verify run 40764139710](https://github.com/infinitule/internet-guard/actions/runs/40764139710)
completed successfully for commit `cbc4775db00dd3455821cfb54e0e3a9f714c7d8b`.
All four jobs passed: Python 3.11, 3.12, 3.13, and 3.14. Each job completed
dependency installation, the OpenSSL prerequisite check, the test suite, the
offline UDP/TCP demonstration, both policy checks, and source compilation.

The initial publication's workflow was rejected before jobs started because
the dependency-install command needed YAML block quoting. The referenced
successful run includes that correction. It does not include a public-upstream
connectivity or live-threat-detection check.

## Not verified here

The live public Quad9 HTTPS probe could not connect from this runtime:
`OSError: [Errno 101] Network is unreachable`. Local TLS tests exercise the
transport implementation, but do not verify public routing, Quad9 availability,
its current threat detections, or certificate-chain compatibility on a target
device. The offline demo uses synthetic answers, not live malware.

The GitHub workflow targets Python 3.11, 3.12, 3.13, and 3.14. Only Python 3.12
was executed in the local preparation environment. Remote outcomes are recorded
in the repository's [Actions runs](https://github.com/infinitule/internet-guard/actions);
inspect the run for the commit you intend to use. The pinned GitHub Action
references were resolved from the official repositories' v6 tag API responses
on the preparation date. Local results above do not imply a remote matrix pass.

No automatic OS/router deployment, independent penetration test, sustained-load
benchmark, broad resolver interoperability test, kernel egress enforcement, or
life-critical deployment assessment has been completed. There is no measured
Internet-wide security impact from this prototype.
