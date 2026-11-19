"""Helpers shared by the tools/ scripts and private provider modules: prefixed
log/die, a retrying HTTP GET, atomic file writes, proxy bypass, and the
subscription overwrite guard (proxy / DNS fingerprints)."""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path
from collections import Counter
from typing import Any, Callable, NoReturn
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

TIMEOUT = 60
RETRIES = 4


class Tool:
    """Prefixed stdout log and stderr die for one script."""

    def __init__(self, name: str) -> None:
        self.name = name

    def log(self, msg: str) -> None:
        print(f"{self.name}: {msg}")

    def die(self, msg: str, code: int = 1) -> NoReturn:
        print(f"{self.name}: {msg}", file=sys.stderr)
        raise SystemExit(code)


def permanent(exc: Exception) -> bool:
    """A 4xx other than 408/429 will not change on retry."""
    return isinstance(exc, HTTPError) and 400 <= exc.code < 500 and exc.code not in (408, 429)


def fetch(url: str, *, ua: str, die: Callable[[str], NoReturn], retries: int = RETRIES,
          timeout: int = TIMEOUT, sleep: Callable[[float], None] = time.sleep) -> bytes:
    req = Request(url, headers={"User-Agent": ua})
    last: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            with urlopen(req, timeout=timeout) as resp:
                if resp.status != 200:
                    raise HTTPError(url, resp.status, resp.reason, resp.headers, None)
                data = resp.read()
            if not data:
                raise RuntimeError(f"empty body: {url}")
            return data
        except (HTTPError, URLError, TimeoutError, RuntimeError, OSError) as exc:
            last = exc
            if permanent(exc):
                break
            if attempt < retries:
                sleep(min(2 ** attempt, 8))
    die(f"download failed: {url}: {last}")


def atomic_write(path: Path, data: bytes, mode: int = 0o644) -> None:
    """Write via a temp file in the same directory and rename over path, so a
    crash or full disk never leaves a truncated file behind."""
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


PROXY_VARS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)


def clear_proxy_env() -> None:
    for key in PROXY_VARS:
        os.environ.pop(key, None)


def write0600(path: Path, data: bytes) -> None:
    atomic_write(path, data, 0o600)


def proxy_fingerprint(doc: bytes) -> list[tuple]:
    import yaml

    try:
        obj = yaml.safe_load(doc)
    except Exception:
        return []
    proxies = obj.get("proxies") if isinstance(obj, dict) else None
    if not isinstance(proxies, list):
        return []
    out = []
    for p in proxies:
        if not isinstance(p, dict):
            continue
        ss = p.get("ss-opts") if isinstance(p.get("ss-opts"), dict) else {}
        out.append(
            (
                str(p.get("type", "")).lower(),
                str(p.get("name", "")),
                str(p.get("server", "")),
                str(p.get("port", "")),
                str(p.get("password", "")),
                str(p.get("sni") or p.get("servername") or ""),
                str(p.get("network") or ""),
                str(p.get("skip-cert-verify")),
                str(ss.get("enabled")),
                str(ss.get("method")),
                str(ss.get("password")),
                str(p.get("udp")),
                str(p.get("uuid", "")),
            )
        )
    return out


def dns_fingerprint(doc: bytes) -> list:
    import yaml

    try:
        obj = yaml.safe_load(doc)
    except Exception:
        return []
    if not isinstance(obj, dict):
        return []
    dns = obj.get("dns") if isinstance(obj.get("dns"), dict) else {}
    return [
        dns.get("nameserver"),
        dns.get("fallback"),
        dns.get("proxy-server-nameserver"),
        dns.get("direct-nameserver"),
        dns.get("nameserver-policy"),
        obj.get("nameserver"),
    ]


def type_count(fp: list, typ: str) -> int:
    want = typ.lower()
    return sum(1 for row in fp if row and str(row[0]).lower() == want)


def type_counts(fp: list) -> Counter[str]:
    return Counter(str(row[0]).lower() for row in fp if row)


def overwrite_subscription(path: Path, body: bytes, *, required_type: str) -> dict[str, Any]:
    old = path.read_bytes() if path.is_file() else b""
    old_p, new_p = proxy_fingerprint(old), proxy_fingerprint(body)
    old_d, new_d = dns_fingerprint(old), dns_fingerprint(body)
    old_required = type_count(old_p, required_type)
    new_required = type_count(new_p, required_type)
    if old_required and not new_required:
        sys.stderr.write(
            f"new body has no type: {required_type}; left {path.name} unchanged "
            f"(old_{required_type}={old_required} new_proxies={len(new_p)})\n"
        )
        overwritten = False
    else:
        write0600(path, body)
        overwritten = True
    return {
        "overwritten": overwritten,
        "nodes_same": old_p == new_p,
        "dns_same": old_d == new_d,
        "old_proxies": len(old_p),
        "new_proxies": len(new_p),
        "old_types": dict(type_counts(old_p)),
        "new_types": dict(type_counts(new_p)),
    }
