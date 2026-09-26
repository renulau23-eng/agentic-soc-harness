"""Command-line entry point: ``ash serve``, ``ash demo``, ``ash hash-password``, ``ash verify-audit``."""

from __future__ import annotations

import argparse
import json
import sys

from ash import __version__


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from ash.api import create_app

    uvicorn.run(create_app(), host=args.host, port=args.port, log_level="info")
    return 0


def cmd_hash_password(args: argparse.Namespace) -> int:
    from ash.governance.auth import hash_password

    print(hash_password(args.password))
    return 0


def cmd_verify_audit(_: argparse.Namespace) -> int:
    from ash.runtime import Harness

    result = Harness.build().audit.verify()
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 2


def cmd_demo(args: argparse.Namespace) -> int:
    from scripts.demo import run_demo

    return run_demo(verbose=not args.quiet)


def cmd_worker(_: argparse.Namespace) -> int:
    from ash.worker import run

    run()
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ash", description=f"Agentic SOC Harness {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the API server")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=8080)
    s.set_defaults(fn=cmd_serve)

    h = sub.add_parser("hash-password", help="hash a password for users.yaml")
    h.add_argument("password")
    h.set_defaults(fn=cmd_hash_password)

    v = sub.add_parser("verify-audit", help="verify audit-chain integrity")
    v.set_defaults(fn=cmd_verify_audit)

    d = sub.add_parser("demo", help="run an incident end to end with the offline playbook model")
    d.add_argument("--quiet", action="store_true")
    d.set_defaults(fn=cmd_demo)

    w = sub.add_parser("worker", help="run a Redis external-agent worker")
    w.set_defaults(fn=cmd_worker)

    args = p.parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":
    sys.exit(main())
