"""CLI: python -m hibp_password_check (prompt) or pass via env HIBP_CHECK_PASSWORD for scripts."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys

from hibp_password_check.check import lookup_pwned_count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check if a password appears in HIBP (k-anonymity; full hash not sent)."
    )
    parser.add_argument(
        "--password-env",
        default="HIBP_CHECK_PASSWORD",
        help="Read password from this env var instead of prompt (automation only)",
    )
    args = parser.parse_args(argv)

    pwd = os.environ.get(args.password_env, "").strip()
    if not pwd:
        try:
            pwd = getpass.getpass("Password (not echoed): ")
        except (KeyboardInterrupt, EOFError):
            return 130

    result = lookup_pwned_count(pwd)
    if not result.get("ok"):
        print(result.get("error", "failed"), file=sys.stderr)
        return 2

    safe = {k: v for k, v in result.items()}
    print(json.dumps(safe, indent=2))
    if result.get("pwned"):
        print(
            f"\nAppears in {result['count']:,} known breaches. Pick a new password.",
            file=sys.stderr,
        )
        return 1
    print("\nNot found in HIBP range response (does not guarantee strength).", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())