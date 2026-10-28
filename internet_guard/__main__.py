from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
from pathlib import Path

from . import __version__
from .policy import PolicyError, PolicyStore, import_feed, load_policy
from .resolver import Audit, GuardResolver
from .server import GuardServer
from .upstream import DoHUpstream


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Experimental loopback-only protective DNS; no system settings are changed."
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="start UDP and TCP listeners")
    serve.add_argument("--policy", type=Path, required=True)
    serve.add_argument("--listen", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=5533)
    serve.add_argument("--upstream", default="https://dns.quad9.net/dns-query")
    serve.add_argument("--bootstrap", default="9.9.9.9")
    serve.add_argument("--timeout", type=float, default=3.0)
    serve.add_argument("--workers", type=int, default=16)
    check = commands.add_parser("check", help="validate a policy without network access")
    check.add_argument("--policy", type=Path, required=True)
    feed = commands.add_parser(
        "import-feed", help="validate a local feed and atomically write normalized domains"
    )
    feed.add_argument("--input", type=Path, required=True)
    feed.add_argument("--output", type=Path, required=True)
    feed.add_argument("--format", choices=("domains", "hosts"), default="domains")
    commands.add_parser("demo", help="run synthetic offline checks over real local UDP/TCP sockets")
    args = parser.parse_args(argv)
    try:
        if args.command == "check":
            policy = load_policy(args.policy)
            print(
                json.dumps(
                    {
                        "valid": True,
                        "revision": policy.revision,
                        "mode": policy.mode,
                        "default_action": policy.default_action,
                        "blocked_domains": len(policy.blocked),
                        "allowed_domains": len(policy.allowed),
                        "blocked_networks": len(policy.networks),
                    }
                )
            )
        elif args.command == "import-feed":
            count = import_feed(args.input, args.output, args.format)
            print(json.dumps({"imported_domains": count, "output": str(args.output)}))
        elif args.command == "demo":
            from .demo import run_demo

            result = run_demo()
            print(json.dumps(result, indent=2))
            return 0 if result["passed"] else 1
        else:
            store = PolicyStore(args.policy)
            audit = Audit()
            upstream = DoHUpstream(args.upstream, args.bootstrap, args.timeout)
            resolver = GuardResolver(store, upstream, audit)
            stop = threading.Event()
            reload_requested = threading.Event()
            signal.signal(signal.SIGINT, lambda *_: stop.set())
            signal.signal(signal.SIGTERM, lambda *_: stop.set())
            if hasattr(signal, "SIGHUP"):
                signal.signal(signal.SIGHUP, lambda *_: reload_requested.set())
            with GuardServer(resolver, args.listen, args.port, workers=args.workers) as server:
                audit.emit(
                    "ready",
                    listen=server.address[0],
                    port=server.address[1],
                    policy=store.snapshot().revision,
                    mode=store.snapshot().mode,
                    upstream_host=upstream.host,
                    experimental=True,
                )
                while not stop.wait(0.2):
                    if reload_requested.is_set():
                        reload_requested.clear()
                        try:
                            policy = store.reload()
                            audit.emit("policy_reloaded", policy=policy.revision, mode=policy.mode)
                        except (OSError, PolicyError):
                            audit.emit(
                                "policy_reload_rejected",
                                reason="invalid_update",
                                policy=store.snapshot().revision,
                            )
            audit.emit("stopped", admission_rejections=server.gate.rejected)
        return 0
    except (OSError, PolicyError, ValueError) as exc:
        print(f"internet-guard: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
