#!/usr/bin/env python3
"""Fetch the latest rule-library sources into OUTDIR for codegen.

Usage: fetch_rules.py OUTDIR

Called by ~/build.sh on every build with a fresh temp dir (removed after the
build); can also be run on its own. Always takes upstream's current state,
nothing is pinned or cached. Downloads geoip, operator, china-list and
Loyalsoldier geosite.dat, plus one tarball of v2fly domain-list-community
master; the lists reached from google / geolocation-cn / geolocation-!cn are
resolved from that tarball and geolocation-!cn is also written flattened.
User-Agent is Arc-rules/1. Prints the sha256 of every downloaded input.

Exit 0 on success, 1 on any download or validation failure.
"""

from __future__ import annotations

import hashlib
import io
import sys
import tarfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from common import Tool
from common import fetch as net_fetch

TOOLS = Path(__file__).resolve().parent
REPO = TOOLS.parent

UA = "Arc-rules/1"
TIMEOUT = 60
RETRIES = 4

GEOIP = "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/"
CHINA_LIST = "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/"
OPERATOR = "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/"
LOYAL_GEOSITE = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
V2FLY_TARBALL = "https://codeload.github.com/v2fly/domain-list-community/tar.gz/refs/heads/master"

V2FLY_ROOTS = ("google", "geolocation-cn", "geolocation-!cn")
FLAT_NOT_CN = "v2fly_geolocation-!cn.txt"
DIRECT = {
    "geoip_cn.txt": GEOIP + "cn.txt",
    "geoip_google.txt": GEOIP + "google.txt",
    "operator_china.txt": OPERATOR + "china.txt",
    "operator_china6.txt": OPERATOR + "china6.txt",
    "accelerated-domains.china.conf": CHINA_LIST + "accelerated-domains.china.conf",
    "loyalsoldier_geosite.dat": LOYAL_GEOSITE,
}
V2FLY_KEY = "v2fly domain-list-community"

T = Tool("fetch_rules")
die = T.die


def fetch(url: str) -> bytes:
    return net_fetch(url, ua=UA, die=die, retries=RETRIES, timeout=TIMEOUT)


def parse_v2fly_lines(text: str):
    """(entry, attrs, drop) per rule line; on include: lines attrs is the keep filter."""
    for raw in text.splitlines():
        line = raw.split("#", 1)[0]
        fields = line.split()
        if not fields:
            continue
        attrs: list[str] = []
        drop: list[str] = []
        for a in fields[1:]:
            if a.startswith("@-"):
                drop.append(a[2:])
            elif a.startswith("@"):
                attrs.append(a[1:])
        yield fields[0], attrs, drop


def untar_v2fly(blob: bytes) -> tuple[dict[str, bytes], str]:
    """All data/<name> files of the tarball, read in memory (nothing is
    extracted to disk), and the commit id git archive records."""
    lists: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
            commit = str(tf.pax_headers.get("comment", "")).strip()
            for m in tf:
                parts = m.name.split("/")
                if not m.isfile() or len(parts) != 3 or parts[1] != "data" or not parts[2]:
                    continue
                f = tf.extractfile(m)
                if f is None:
                    die(f"v2fly tarball: unreadable {m.name}")
                lists[parts[2]] = f.read()
    except (tarfile.TarError, OSError, EOFError) as exc:
        die(f"v2fly tarball: {exc}")
    return lists, commit


def reachable_v2fly(lists: dict[str, bytes]) -> dict[str, bytes]:
    """The roots and every list they include, recursively."""
    out: dict[str, bytes] = {}
    pending = list(V2FLY_ROOTS)
    while pending:
        name = pending.pop()
        if name in out:
            continue
        data = lists.get(name)
        if data is None:
            die(f"v2fly list not in tarball: {name}")
        out[name] = data
        for entry, _attrs, _drop in parse_v2fly_lines(data.decode("utf-8", errors="replace")):
            if entry.startswith("include:"):
                inc = entry[len("include:") :]
                if inc and inc not in out:
                    pending.append(inc)
    return out


def flatten_not_cn(lists: dict[str, bytes]) -> str:
    """geolocation-!cn with includes resolved: kind:host[:@a,@b], sorted."""
    lines_out: dict[tuple[str, str], list[str]] = {}
    seen: set[str] = set()

    def walk(name: str, keep: list[str], drop: list[str]) -> None:
        key = name + "|" + ",".join(keep) + "|" + ",".join(drop)
        if key in seen:
            return
        seen.add(key)
        data = lists.get(name)
        if data is None:
            die(f"missing v2fly list while flattening: {name}")
        for entry, attrs, inc_drop in parse_v2fly_lines(data.decode("utf-8", errors="replace")):
            if entry.startswith("include:"):
                walk(entry[len("include:") :], attrs, inc_drop)
                continue
            if keep and any(k not in attrs for k in keep):
                continue
            if drop and any(k in attrs for k in drop):
                continue
            kind, sep, host = entry.partition(":")
            if not sep:
                kind, host = "domain", entry
            if kind not in ("domain", "full", "keyword", "regexp"):
                continue
            if kind in ("domain", "full"):
                host = host.lower()
            host = host.strip()
            if not host:
                continue
            slot = lines_out.setdefault((kind, host), [])
            for a in attrs:
                if a not in slot:
                    slot.append(a)

    walk("geolocation-!cn", [], [])
    out = [f"{k}:{h}:@{','.join(a)}" if a else f"{k}:{h}" for (k, h), a in lines_out.items()]
    out.sort()
    return "\n".join(out) + "\n"


def text_lines(data: bytes) -> list[str]:
    return data.decode("utf-8", errors="replace").splitlines()


def validate(files: dict[str, bytes]) -> None:
    """Size floors that no real upstream copy is anywhere near; a truncated or
    error-page download fails here instead of shipping a hollow table."""
    flat_n = sum(1 for l in text_lines(files[FLAT_NOT_CN]) if l.strip())
    if flat_n < 1000:
        die(f"{FLAT_NOT_CN} too short ({flat_n} lines)")
    op4 = text_lines(files["operator_china.txt"])
    op6 = text_lines(files["operator_china6.txt"])
    if len(op4) < 3000 or len(op6) < 1000:
        die(f"operator lists truncated: china {len(op4)}, china6 {len(op6)}")
    geo = text_lines(files["geoip_cn.txt"])
    goog = text_lines(files["geoip_google.txt"])
    if len(geo) < 1000:
        die(f"geoip_cn.txt truncated: {len(geo)} lines")
    if len(goog) < 100:
        die(f"geoip_google.txt truncated: {len(goog)} lines")
    china = 0
    for line in text_lines(files["accelerated-domains.china.conf"]):
        parts = line.strip().split("/")
        if len(parts) >= 3 and parts[0] == "server=":
            china += 1
    if china < 50000:
        die(f"accelerated-domains.china.conf truncated: {china} server= lines")
    dat = files["loyalsoldier_geosite.dat"]
    if len(dat) < 100_000:
        die(f"loyalsoldier_geosite.dat too small: {len(dat)} bytes")
    for root in V2FLY_ROOTS:
        if f"v2fly_{root}" not in files:
            die(f"missing v2fly root {root}")


def build(downloads: dict[str, bytes]) -> tuple[dict[str, bytes], str]:
    """Downloads (DIRECT names + V2FLY_KEY) -> files for codegen, v2fly commit."""
    files = {name: downloads[name] for name in DIRECT}
    lists, commit = untar_v2fly(downloads[V2FLY_KEY])
    reach = reachable_v2fly(lists)
    for name, data in reach.items():
        files[f"v2fly_{name}"] = data
    files[FLAT_NOT_CN] = flatten_not_cn(reach).encode()
    validate(files)
    return files, commit


def outdir(arg: str) -> Path:
    d = Path(arg).resolve()
    if not d.is_dir():
        die(f"{arg}: not a directory")
    if d == REPO or REPO in d.parents:
        die("OUTDIR must be outside the repository: rule data is fetched per build, never committed")
    if any(d.iterdir()):
        die(f"{arg}: not empty")
    return d


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    out = outdir(argv[0])
    urls = dict(DIRECT, **{V2FLY_KEY: V2FLY_TARBALL})
    with ThreadPoolExecutor(max_workers=len(urls)) as pool:
        futs = {name: pool.submit(fetch, url) for name, url in urls.items()}
        downloads = {name: f.result() for name, f in futs.items()}
    files, commit = build(downloads)
    for name, data in sorted(downloads.items()):
        extra = f" @ {commit}" if name == V2FLY_KEY and commit else ""
        print(f"  {hashlib.sha256(data).hexdigest()}  {name}{extra} ({len(data)} bytes)")
    for name, data in files.items():
        (out / name).write_bytes(data)
    v2n = sum(1 for k in files if k.startswith("v2fly_")) - 1
    flat_n = sum(1 for l in text_lines(files[FLAT_NOT_CN]) if l.strip())
    T.log(f"{len(files)} files: {v2n} v2fly lists, {FLAT_NOT_CN} {flat_n} lines")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        die("interrupted")
