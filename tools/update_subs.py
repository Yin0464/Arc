#!/usr/bin/env python3
"""Refresh every node source in the private bundle.

    update_subs.py            run each provider in bundle.toml order
    update_subs.py ID [ARGS]  run one provider, passing ARGS to it
                              (for example a verification code on stdin)

Each provider module lives in the bundle and exposes run(ctx, argv) -> int.
It writes through ctx.write_subscription(), which keeps the old file when the
new body lost every proxy of the required type, and writes atomically (0600).
Exit code: the first non-zero provider result, else 0.
"""

from __future__ import annotations

import os
import sys

import private
from common import Tool

T = Tool("update_subs")


def main(argv: list[str]) -> int:
    os.umask(0o077)  # whatever a provider writes stays private
    try:
        b = private.load()
        if argv and not argv[0].startswith("-"):
            pid, rest = argv[0], argv[1:]
            if pid not in b.by_id:
                T.die(f"no provider {pid!r} in bundle.toml")
            todo = [(b.by_id[pid], rest)]
        elif argv:
            T.die("options go after a provider id")
        else:
            todo = [(p, []) for p in b.providers]
        rc = 0
        for p, rest in todo:
            print(f"==> {p.id}")
            mod = private.load_module(b, p)
            r = int(mod.run(private.Context(b, p), rest) or 0)
            rc = rc or r
        return rc
    except private.BundleError as exc:
        T.die(str(exc))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
