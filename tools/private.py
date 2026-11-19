#!/usr/bin/env python3
"""Private bundle loader, validator and leak check.

The public tree holds only generic machinery. Everything tied to a node
source (credentials, client keys, fetch logic, extraction rules, fetched
subscriptions, sessions, device identity, the signing key, the generated node
table) lives in the private bundle: $ARC_PRIVATE, default ~/arc-private.

    private.py check                 validate the bundle (schema, files, modes)
    private.py emit                  write out/codegen-input.json + out/overlay.json
    private.py init                  create an empty bundle skeleton + signing key
    private.py fix-modes             chmod the bundle to 700/600 (after a git clone)
    private.py set-secret ID KEY     read one secret value from stdin into secrets.toml
    private.py export-template DIR   copy the shareable part (no secrets/state/keys)
    private.py test                  run provider tests in the bundle
    private.py leakcheck MODE        scan the public repo for private values

Errors name the field or file, never a value.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tomllib
from pathlib import Path
from urllib.parse import quote, urlsplit

TOOLS = Path(__file__).resolve().parent
REPO = TOOLS.parent
sys.path.insert(0, str(TOOLS))

from common import Tool, atomic_write, overwrite_subscription  # noqa: E402

T = Tool("private")
SCHEMA = 1
PROTOS = ("anytls", "trojan")
ID_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
SKIP_DIRS = {".git", "__pycache__"}


class BundleError(Exception):
    pass


def bundle_root() -> Path:
    return Path(os.environ.get("ARC_PRIVATE") or Path.home() / "arc-private").expanduser()


def _inside(a: Path, b: Path) -> bool:
    try:
        a.resolve().relative_to(b.resolve())
        return True
    except ValueError:
        return False


def _toml(path: Path, what: str) -> dict:
    if not path.is_file():
        raise BundleError(f"missing {what}: {path.name}")
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise BundleError(f"{path.name}: invalid TOML ({exc.__class__.__name__} at line {getattr(exc, 'lineno', '?')})") from None


def _need(tbl: dict, key: str, typ, where: str):
    if key not in tbl:
        raise BundleError(f"{where}: missing '{key}'")
    v = tbl[key]
    if not isinstance(v, typ) or (isinstance(v, (str, list, dict)) and not v):
        raise BundleError(f"{where}.{key}: must be a non-empty {typ.__name__ if isinstance(typ, type) else 'value'}")
    return v


def check_modes(root: Path) -> None:
    uid = os.getuid()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in [None] + filenames:
            p = Path(dirpath) if name is None else Path(dirpath) / name
            st = p.lstat()
            if stat.S_ISLNK(st.st_mode):
                raise BundleError(f"symlink not allowed in bundle: {p.relative_to(root)}")
            if st.st_uid != uid:
                raise BundleError(f"not owned by you: {p.relative_to(root) or '.'}")
            if st.st_mode & 0o077:
                kind = "directory" if name is None else "file"
                raise BundleError(f"{kind} readable by others: {p.relative_to(root) or '.'} "
                                  f"(mode {stat.S_IMODE(st.st_mode):o}; want {'700' if name is None else '600'})")


class Provider:
    def __init__(self, b: "Bundle", tbl: dict, i: int):
        where = f"bundle.toml providers[{i}]"
        self.id = _need(tbl, "id", str, where)
        if not ID_RE.match(self.id):
            raise BundleError(f"{where}.id: must match {ID_RE.pattern}")
        self.module = b.root / _need(tbl, "module", str, where)
        if not _inside(self.module, b.root) or not self.module.is_file():
            raise BundleError(f"{where}.module: file not found inside the bundle")
        self.proto = _need(tbl, "proto", str, where)
        if self.proto not in PROTOS:
            raise BundleError(f"{where}.proto: must be one of {', '.join(PROTOS)}")
        self.require_type = _need(tbl, "require_type", str, where)
        keys = _need(tbl, "secrets", list, where)
        sec = b.secrets.get("providers", {}).get(self.id)
        if not isinstance(sec, dict):
            raise BundleError(f"secrets.toml: missing [providers.{self.id}]")
        for k in keys:
            if not isinstance(sec.get(k), str) or not sec[k].strip():
                raise BundleError(f"secrets.toml providers.{self.id}: missing '{k}'")
        self.secrets = {k: sec[k] for k in keys}
        self.state_dir = b.root / "state" / self.id
        self.sub_file = b.root / "subs" / f"{self.id}.yaml"


class Bundle:
    def __init__(self, root: Path, *, modes: bool = True):
        self.root = root
        if not root.is_dir():
            raise BundleError(f"private bundle not found (ARC_PRIVATE or ~/arc-private): {root}")
        if _inside(root, REPO) or _inside(REPO, root):
            raise BundleError("private bundle must live outside the public repository")
        if modes:
            check_modes(root)
        self.cfg = _toml(root / "bundle.toml", "bundle.toml")
        self.secrets = _toml(root / "secrets.toml", "secrets.toml")
        for name, doc in (("bundle.toml", self.cfg), ("secrets.toml", self.secrets)):
            if doc.get("schema_version") != SCHEMA:
                raise BundleError(f"{name}: schema_version must be {SCHEMA}")
        build = _need(self.cfg, "build", dict, "bundle.toml")
        self.keys_dir = root / _need(build, "keys_dir", str, "bundle.toml build")
        provs = _need(self.cfg, "providers", list, "bundle.toml")
        self.providers = [Provider(self, t, i) for i, t in enumerate(provs)]
        ids = [p.id for p in self.providers]
        if len(set(ids)) != len(ids):
            raise BundleError("bundle.toml: duplicate provider id")
        self.by_id = {p.id: p for p in self.providers}
        self.rules = _toml(root / "rules" / "catalog.toml", "rules/catalog.toml")
        self._check_rules()

    def _check_rules(self) -> None:
        r = self.rules
        if r.get("schema_version") != SCHEMA:
            raise BundleError(f"rules/catalog.toml: schema_version must be {SCHEMA}")
        naming = _need(r, "naming", dict, "catalog.toml")
        for k in ("regular", "residential"):
            v = _need(naming, k, str, "catalog.toml naming")
            if "{country}" not in v or not re.search(r"\{n(:0\d)?\}", v):
                raise BundleError(f"catalog.toml naming.{k}: needs {{country}} and {{n}}")
        region = r.get("region", {})
        if not isinstance(region, dict):
            raise BundleError("catalog.toml region: must be a table")
        srcs = _need(r, "source", list, "catalog.toml")
        seen = set()
        for i, s in enumerate(srcs):
            where = f"catalog.toml source[{i}]"
            pid = _need(s, "provider", str, where)
            if pid not in self.by_id:
                raise BundleError(f"{where}.provider: no such provider in bundle.toml")
            if pid in seen:
                raise BundleError(f"{where}.provider: used twice")
            seen.add(pid)
            _need(s, "types", list, where)
        if seen != set(self.by_id):
            raise BundleError("catalog.toml: every provider needs exactly one [[source]]")
        protos = [p.proto for p in self.providers]
        if len(set(protos)) != len(protos):
            raise BundleError("bundle.toml: one provider per protocol")

    def codegen_input(self) -> dict:
        r = self.rules
        sources = []
        for s in r["source"]:
            p = self.by_id[s["provider"]]
            clean = s.get("name_clean", {})
            sources.append({
                "id": p.id,
                "proto": p.proto,
                "sub": str(p.sub_file),
                "types": s["types"],
                "name_prefix": s.get("name_prefix", ""),
                "region_regex": s.get("region_regex", ""),
                "clean_from_first_han": bool(clean.get("from_first_han", False)),
                "clean_cut_at": clean.get("cut_at", ""),
                "residential_match": s.get("residential_match", ""),
            })
        region = r.get("region", {})
        keys = r.get("yaml_keys", {})
        return {
            "schema_version": SCHEMA,
            "sources": sources,
            "aliases": region.get("aliases", {}),
            "other_first": region.get("other_first", []),
            "naming": {"regular": r["naming"]["regular"], "residential": r["naming"]["residential"]},
            "yaml_keys": {"padding": keys.get("padding", ""), "metadata": keys.get("metadata", "")},
        }

    def overlay(self) -> dict:
        """go -overlay map: each file under tests/go/<pkg>/ joins core/<pkg>/ as private_<name>."""
        repl = {}
        base = self.root / "tests" / "go"
        if base.is_dir():
            for f in sorted(base.rglob("*_test.go")):
                rel = f.relative_to(base)
                dest = REPO / "core" / rel.parent / f"private_{rel.name}"
                if not dest.parent.is_dir():
                    raise BundleError(f"tests/go/{rel}: no such package core/{rel.parent}")
                repl[str(dest)] = str(f)
        return {"Replace": repl}


def load(*, modes: bool = True) -> Bundle:
    return Bundle(bundle_root(), modes=modes)


def emit(b: Bundle) -> None:
    out = b.root / "out"
    out.mkdir(mode=0o700, exist_ok=True)
    for p in b.providers:
        if not p.sub_file.is_file():
            raise BundleError(f"missing subscription subs/{p.id}.yaml (run ~/update.sh)")
    atomic_write(out / "codegen-input.json", (json.dumps(b.codegen_input(), ensure_ascii=False, indent=1) + "\n").encode(), 0o600)
    atomic_write(out / "overlay.json", (json.dumps(b.overlay(), indent=1) + "\n").encode(), 0o600)


# ---------------------------------------------------------------- providers

class Context:
    """What a provider module gets: its own secrets and paths plus helpers."""

    def __init__(self, b: Bundle, p: Provider):
        self.id = p.id
        self.secrets = dict(p.secrets)
        self.state_dir = p.state_dir
        self.sub_file = p.sub_file
        self.require_type = p.require_type
        self.log, self.die = Tool(p.id).log, Tool(p.id).die
        for d in (p.state_dir, p.sub_file.parent):
            d.mkdir(mode=0o700, parents=True, exist_ok=True)

    def write_subscription(self, body: bytes) -> dict:
        return overwrite_subscription(self.sub_file, body, required_type=self.require_type)


def load_module(b: Bundle, p: Provider):
    for d in (p.module.parent, b.root / "providers"):
        if str(d) not in sys.path:
            sys.path.insert(0, str(d))
    spec = importlib.util.spec_from_file_location(f"arc_provider_{p.id}", p.module)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for attr in ("run", "REQUIRED_SECRETS"):
        if not hasattr(mod, attr):
            raise BundleError(f"provider {p.id}: module has no {attr}")
    missing = [k for k in mod.REQUIRED_SECRETS if k not in p.secrets]
    if missing:
        raise BundleError(f"provider {p.id}: bundle.toml secrets list lacks {', '.join(missing)}")
    return mod


# ---------------------------------------------------------------- init / template

def init() -> None:
    root = bundle_root()
    if _inside(root, REPO):
        raise BundleError("private bundle must live outside the public repository")
    for d in ("", "keys", "providers", "rules", "state", "subs", "out", "tests/go", "docs"):
        (root / d).mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(root / d, 0o700)
    sec = root / "secrets.toml"
    if not sec.exists():
        atomic_write(sec, f"schema_version = {SCHEMA}\n".encode(), 0o600)
    jks, props = root / "keys" / "arc-release.jks", root / "keys" / "keystore.properties"
    if not jks.exists():
        pw = base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("=")
        keytool = Path(os.environ.get("JAVA_HOME", "/opt/jdk/current")) / "bin" / "keytool"
        env = dict(os.environ, ARC_KS_PW=pw)
        subprocess.run([str(keytool if keytool.exists() else "keytool"), "-genkeypair", "-keystore", str(jks),
                        "-storetype", "PKCS12", "-alias", "arc", "-keyalg", "RSA", "-keysize", "4096",
                        "-validity", "36500", "-dname", "CN=Arc", "-storepass:env", "ARC_KS_PW",
                        "-keypass:env", "ARC_KS_PW"], check=True, env=env, capture_output=True)
        os.chmod(jks, 0o600)
        atomic_write(props, (f"storeFile=arc-release.jks\nstorePassword={pw}\nkeyAlias=arc\nkeyPassword={pw}\n").encode(), 0o600)
        T.log("generated a new signing key in keys/")
    subprocess.run(["git", "-C", str(REPO), "config", "core.hooksPath", "tools/hooks"], check=False)
    T.log(f"bundle ready at {root}")


def fix_modes() -> None:
    """git keeps only 644/755: a cloned or restored bundle needs this once."""
    root = bundle_root()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        os.chmod(dirpath, 0o700)
        for name in filenames:
            f = Path(dirpath) / name
            if not f.is_symlink():
                os.chmod(f, 0o600)
    T.log(f"modes fixed under {root}")


def set_secret(pid: str, key: str) -> None:
    if not ID_RE.match(pid) or not re.match(r"^[a-z][a-z0-9_]*$", key):
        raise BundleError("bad provider id or key name")
    value = sys.stdin.readline().rstrip("\n")
    if not value:
        raise BundleError("empty value on stdin")
    root = bundle_root()
    path = root / "secrets.toml"
    doc = _toml(path, "secrets.toml") if path.exists() else {"schema_version": SCHEMA}
    doc.setdefault("providers", {}).setdefault(pid, {})[key] = value
    lines = [f"schema_version = {SCHEMA}", ""]
    for p, tbl in doc.get("providers", {}).items():
        lines.append(f"[providers.{p}]")
        lines += [f"{k} = {json.dumps(v, ensure_ascii=False)}" for k, v in tbl.items()]
        lines.append("")
    atomic_write(path, "\n".join(lines).encode(), 0o600)
    T.log(f"saved providers.{pid}.{key}")


TEMPLATE_PARTS = ("bundle.toml", "providers", "rules", "tests", "docs", "leak-denylist.txt", ".gitignore")
# Owner-specific even inside shareable parts: pinned node counts of one
# account, and old notes. Never in a template.
TEMPLATE_SKIP = ("__pycache__", "expected-counts.json", "README-*.md")


def export_template(dest: Path) -> None:
    root = bundle_root()
    if dest.exists():
        raise BundleError(f"{dest} already exists")
    dest.mkdir(mode=0o700, parents=True)
    for part in TEMPLATE_PARTS:
        src = root / part
        if src.is_dir():
            shutil.copytree(src, dest / part, ignore=shutil.ignore_patterns(*TEMPLATE_SKIP))
        elif src.is_file():
            shutil.copy2(src, dest / part)
    for d in ("keys", "state", "subs", "out"):
        (dest / d).mkdir(mode=0o700)
    T.log(f"template written to {dest} (no secrets, keys, state, subscriptions)")


def run_provider_tests() -> int:
    b = load()
    env = dict(os.environ, ARC_PRIVATE=str(b.root), PYTHONPATH=os.pathsep.join([str(TOOLS), str(b.root / "providers")]))
    rc = 0
    for p in b.providers:
        tests = p.module.parent / "tests"
        if tests.is_dir():
            r = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", str(tests), "-t", str(tests)],
                               env=env, cwd=str(p.module.parent))
            rc |= r.returncode
    return rc


# ---------------------------------------------------------------- leak check

PLACEHOLDER_UUID = re.compile(rb"00000000-0000-4000-8000-0000000000[0-9a-f]{2}", re.I)
UUID = re.compile(rb"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
PEM = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")
SECRET_SUFFIX = (".apk", ".aab", ".jks", ".keystore", ".p12", ".pfx")
# Third-party data (the committed rule-list excerpt the offline tests build
# their tables from): exact private values only, no denylist words.
DATA_ONLY = ("core/cmd/codegen/testdata/rules/",)
# Build products that build.sh regenerates every build; never committed.
BUILD_PRODUCT = re.compile(r"^(core/internal/router/[^/]+\.bin|android/app/src/main/jniLibs/.*)$")
# Well-known public resolvers a subscription may also list; not private.
PUBLIC_RESOLVERS = {
    "doh.pub", "dot.pub", "dns.alidns.com", "dns.google", "dns.google.com", "cloudflare-dns.com",
    "one.one.one.one", "dns.quad9.net", "doh.360.cn", "dns.twnic.tw", "dns.adguard-dns.com",
    "223.5.5.5", "223.6.6.6", "119.29.29.29", "120.53.53.53", "1.12.12.12", "180.76.76.76",
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "114.114.114.114",
}
MIN_VALUE = 6


def word_rule(word: str) -> bytes:
    """Case-insensitive word that also matches at camelCase / snake_case edges."""
    w = re.escape(word.encode())
    return rb"(?:(?<![A-Za-z0-9])|(?<=[a-z0-9])(?=[A-Z]))(?i:" + w + rb")(?![a-z0-9])"


class Rules:
    def __init__(self, b: Bundle | None):
        self.values: dict[bytes, str] = {}
        self.deny: list[tuple[str, re.Pattern]] = []
        if b is not None:
            self._collect(b)
        alts = sorted(self.values, key=len, reverse=True)
        self.value_re = re.compile(b"|".join(re.escape(v) for v in alts), re.I) if alts else None
        h = hashlib.sha256()
        for v in alts:
            h.update(v + b"\0")
        for name, rx in self.deny:
            h.update(name.encode() + rx.pattern + b"\0")
        self.fingerprint = h.hexdigest()

    def add(self, v, kind: str) -> None:
        if not isinstance(v, str):
            return
        v = v.strip()
        if len(v) < MIN_VALUE or v.isdigit() or v.lower() in PUBLIC_RESOLVERS:
            return
        for form in {v, quote(v, safe="")}:
            self.values.setdefault(form.lower().encode(), kind)

    def _collect(self, b: Bundle) -> None:
        def walk(o, kind):
            if isinstance(o, dict):
                for x in o.values():
                    walk(x, kind)
            elif isinstance(o, list):
                for x in o:
                    walk(x, kind)
            else:
                self.add(o, kind)

        for p in b.providers:
            for v in p.secrets.values():
                self.add(v, "secret")
                raw = v.encode()
                self.add(base64.b64encode(raw).decode().rstrip("="), "secret-b64")
                self.add(base64.urlsafe_b64encode(raw).decode().rstrip("="), "secret-b64")
                host = urlsplit(v).hostname if "://" in v else None
                self.add(host, "secret-host")
        try:
            import yaml
        except ImportError:
            yaml = None
        for sub in sorted((b.root / "subs").glob("*.yaml")):
            doc = yaml.safe_load(sub.read_bytes()) if yaml else None
            if not isinstance(doc, dict):
                continue
            for px in doc.get("proxies") or []:
                if isinstance(px, dict):
                    for k in ("server", "sni", "servername", "password", "uuid"):
                        self.add(str(px.get(k) or ""), "subscription")
                    ss = px.get("ss-opts")
                    if isinstance(ss, dict):
                        self.add(str(ss.get("password") or ""), "subscription")
            dns = doc.get("dns")
            if isinstance(dns, dict):
                def hosts(o):
                    if isinstance(o, dict):
                        for k, x in o.items():
                            hosts(k)
                            hosts(x)
                    elif isinstance(o, list):
                        for x in o:
                            hosts(x)
                    elif isinstance(o, str) and "://" in o:
                        self.add(urlsplit(o).hostname, "subscription-dns")
                hosts(dns)
        nodes = b.root / "out" / "nodes.json"
        if nodes.is_file():
            cat = json.loads(nodes.read_text())
            for e in cat.get("endpoints", []):
                self.add(e, "node-table")
            for p in cat.get("profiles", []):
                for u in p.get("doh", []):
                    self.add(urlsplit(u).hostname, "node-table")
                key = base64.b64decode(p.get("key", "") or "")
                self.add(key.hex(), "node-table-key")
                if key.isascii():
                    self.add(key.decode(), "node-table-key")
                self.add(p.get("ss_password", ""), "node-table")
            for r in cat.get("regions", []):
                self.add(r.get("sni", ""), "node-table")
                for n in r.get("nodes", []):
                    self.add(n.get("sni", ""), "node-table")
        for kp in sorted((b.root / "providers").rglob("keys.py")):
            for hx in re.findall(r"[0-9a-fA-F]{32,}", kp.read_text()):
                self.add(hx, "client-key")
        props = b.keys_dir / "keystore.properties"
        if props.is_file():
            for line in props.read_text().splitlines():
                k, _, v = line.partition("=")
                if k.strip() in ("storePassword", "keyPassword"):
                    self.add(v, "signing")
        state = b.root / "state"
        for f in sorted(state.rglob("*")) if state.is_dir() else []:
            if f.is_file():
                text = f.read_text(errors="replace")
                try:
                    walk(json.loads(text), "state")
                except ValueError:
                    self.add(text, "state")
        dl = b.root / "leak-denylist.txt"
        if dl.is_file():
            for i, line in enumerate(dl.read_text(encoding="utf-8").splitlines(), 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                kind, _, val = line.partition(":")
                if kind == "word":
                    rx = word_rule(val)
                elif kind == "str":
                    rx = re.escape(val.encode())
                    rx = b"(?i:" + rx + b")"
                elif kind == "re":
                    rx = val.encode()
                else:
                    raise BundleError(f"leak-denylist.txt line {i}: want word:/str:/re:")
                self.deny.append((f"denylist#{i}", re.compile(rx)))

    def scan(self, data: bytes, path: str = "") -> list[tuple[int, str]]:
        hits: list[tuple[int, str]] = []
        data_only = path.startswith(DATA_ONLY)

        def line_of(pos: int) -> int:
            return data.count(b"\n", 0, pos) + 1

        if self.value_re is not None:
            for m in self.value_re.finditer(data):
                hits.append((line_of(m.start()), f"value({self.values.get(m.group(0).lower(), 'private')})"))
        if data[:4] == b"\xfe\xed\xfe\xed":
            hits.append((1, "keystore-bytes"))
        if not data_only:
            for name, rx in self.deny:
                for m in rx.finditer(data):
                    hits.append((line_of(m.start()), name))
            for m in UUID.finditer(data):
                if not PLACEHOLDER_UUID.fullmatch(m.group(0)):
                    hits.append((line_of(m.start()), "uuid"))
            for m in PEM.finditer(data):
                hits.append((line_of(m.start()), "private-key"))
            if b'"profiles"' in data and b'"endpoints"' in data:
                try:
                    cat = json.loads(data)
                    if any(not str(e).endswith(".invalid") for e in cat.get("endpoints", [])):
                        hits.append((1, "node-table-with-real-endpoints"))
                except (ValueError, AttributeError):
                    pass
        return hits

    def scan_path(self, path: str) -> list[str]:
        out = []
        if path.lower().endswith(SECRET_SUFFIX):
            out.append("secret-file-type")
        if BUILD_PRODUCT.match(path):
            out.append("build-product")
        for _, r in self.scan(path.encode(), path if path.startswith(DATA_ONLY) else ""):
            out.append(r)
        return out


def git(*args: str, input: bytes | None = None) -> bytes:
    return subprocess.run(["git", "-C", str(REPO), *args], check=True, capture_output=True, input=input).stdout


def tree_blobs(rev: str | None) -> list[tuple[str, str]]:
    """(path, blob sha) for the index (rev None) or a commit tree."""
    out = []
    if rev is None:
        for line in git("ls-files", "-s", "-z").split(b"\0"):
            if line:
                meta, path = line.split(b"\t", 1)
                out.append((path.decode(), meta.split()[1].decode()))
    else:
        for line in git("ls-tree", "-r", "-z", rev).split(b"\0"):
            if line:
                meta, path = line.split(b"\t", 1)
                if meta.split()[1] == b"blob":
                    out.append((path.decode(), meta.split()[2].decode()))
    return out


class Scanner:
    def __init__(self, rules: Rules):
        self.rules = rules
        self.findings: list[str] = []
        self.cache_path = Path(git("rev-parse", "--git-dir").decode().strip())
        if not self.cache_path.is_absolute():
            self.cache_path = REPO / self.cache_path
        self.cache_path = self.cache_path / "arc-leakcheck-clean"
        self.clean: set[str] = set()
        if self.cache_path.is_file():
            lines = self.cache_path.read_text().split()
            if lines and lines[0] == rules.fingerprint:
                self.clean = set(lines[1:])
        self.seen: set[str] = set()

    def blobs(self, items: list[tuple[str, str]], where: str) -> None:
        for path, sha in items:
            for r in self.rules.scan_path(path):
                self.findings.append(f"{where}{path}: path: {r}")
        todo = [(p, s) for p, s in items if (s + ":" + p.startswith(DATA_ONLY).__str__()) not in self.clean
                and (s, p.startswith(DATA_ONLY)) not in self.seen]
        if not todo:
            return
        proc = subprocess.Popen(["git", "-C", str(REPO), "cat-file", "--batch"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        for path, sha in todo:
            proc.stdin.write(sha.encode() + b"\n")
            proc.stdin.flush()
            header = proc.stdout.readline().split()
            size = int(header[2])
            data = proc.stdout.read(size)
            proc.stdout.read(1)
            key = (sha, path.startswith(DATA_ONLY))
            self.seen.add(key)
            hits = self.rules.scan(data, path)
            for line, rule in hits:
                self.findings.append(f"{where}{path}:{line}: {rule}")
            if not hits:
                self.clean.add(f"{sha}:{key[1]}")
        proc.stdin.close()
        proc.wait()

    def message(self, text: bytes, where: str) -> None:
        for line, rule in self.rules.scan(text, ""):
            self.findings.append(f"{where}message:{line}: {rule}")

    def history(self, rev_args: list[str]) -> int:
        revs = git("rev-list", *rev_args).decode().split()
        for c in revs:
            self.message(git("log", "-1", "--format=%an%n%ae%n%cn%n%ce%n%B", c), f"{c[:12]} ")
            self.blobs(tree_blobs(c), f"{c[:12]} ")
        return len(revs)

    def save(self) -> None:
        try:
            self.cache_path.write_text(self.rules.fingerprint + "\n" + "\n".join(sorted(self.clean)) + "\n")
        except OSError:
            pass


def leakcheck(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="private.py leakcheck")
    ap.add_argument("--staged", action="store_true", help="the index (pre-commit)")
    ap.add_argument("--tree", action="store_true", help="HEAD's tree")
    ap.add_argument("--msg", help="a commit message file (commit-msg)")
    ap.add_argument("--history", action="store_true", help="every commit reachable from HEAD")
    ap.add_argument("--pre-push", action="store_true", help="read pre-push refs on stdin")
    ap.add_argument("--public-only", action="store_true", help="no bundle: generic rules only")
    a = ap.parse_args(argv)
    public_only = a.public_only or os.environ.get("ARC_LEAKCHECK_PUBLIC_ONLY") == "1"
    if public_only:
        print("leakcheck: WARNING public-only mode, private values are NOT checked", file=sys.stderr)
        rules = Rules(None)
    else:
        try:
            rules = Rules(load())
        except BundleError as exc:
            T.die(f"leakcheck needs the private bundle: {exc}")
    sc = Scanner(rules)
    n = 0
    if a.staged:
        sc.blobs(tree_blobs(None), "index ")
    if a.tree:
        sc.blobs(tree_blobs("HEAD"), "HEAD ")
    if a.msg:
        sc.message(Path(a.msg).read_bytes(), "")
    if a.history:
        n += sc.history(["HEAD"])
    if a.pre_push:
        for line in sys.stdin.read().splitlines():
            parts = line.split()
            if len(parts) != 4 or set(parts[1]) == {"0"}:
                continue
            local, remote = parts[1], parts[3]
            n += sc.history([local] if set(remote) == {"0"} else [local, f"^{remote}"])
    sc.save()
    if sc.findings:
        for f in sc.findings:
            print(f"leakcheck: {f}", file=sys.stderr)
        print(f"leakcheck: {len(sc.findings)} finding(s); values are never printed", file=sys.stderr)
        return 1
    print(f"leakcheck: clean ({len(rules.values)} private values, {len(rules.deny)} denylist rules"
          + (f", {n} commits" if n else "") + ")")
    return 0


# ---------------------------------------------------------------- cli

def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    cmd, rest = argv[0], argv[1:]
    try:
        if cmd == "check":
            b = load()
            for p in b.providers:
                load_module(b, p)
            T.log(f"bundle ok: {len(b.providers)} providers")
        elif cmd == "emit":
            emit(load())
            T.log("wrote out/codegen-input.json and out/overlay.json")
        elif cmd == "init":
            init()
        elif cmd == "fix-modes":
            fix_modes()
        elif cmd == "set-secret" and len(rest) == 2:
            set_secret(*rest)
        elif cmd == "export-template" and len(rest) == 1:
            export_template(Path(rest[0]))
        elif cmd == "test":
            return run_provider_tests()
        elif cmd == "leakcheck":
            return leakcheck(rest)
        else:
            T.die(f"unknown command: {' '.join(argv)}")
    except BundleError as exc:
        T.die(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
