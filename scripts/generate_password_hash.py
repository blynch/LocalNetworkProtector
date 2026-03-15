#!/usr/bin/env python3
"""Generate a password hash for LocalNetworkProtector web auth."""

from __future__ import annotations

import argparse
import getpass
import sys

from werkzeug.security import generate_password_hash


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a Werkzeug password hash for web.password_hash."
    )
    parser.add_argument(
        "--password",
        help="Password to hash. If omitted, prompt securely.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    password = args.password or getpass.getpass("Password: ")
    if not password:
        print("Password cannot be empty.", file=sys.stderr)
        return 1
    print(generate_password_hash(password))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
