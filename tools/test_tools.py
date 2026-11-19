#!/usr/bin/env python3
"""Offline regression tests for the tools/ scripts: python3 tools/test_tools.py"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parent))

import common  # noqa: E402
import private  # noqa: E402
import update_subs  # noqa: E402
import update_pins  # noqa: E402
import fetch_rules  # noqa: E402


def tmpdir(t: unittest.TestCase) -> Path:
    d = tempfile.TemporaryDirectory()
    t.addCleanup(d.cleanup)
    return Path(d.name)


class PinReplacement(unittest.TestCase):
    def plan(self, changes, files: dict[str, str]):
        d = tmpdir(self)
        texts = {}
        for name, text in files.items():
            (d / name).write_text(text)
            texts[d / name] = text
        with mock.patch.object(update_pins, "REPO", d):
            out = update_pins.plan_replacements([(o, n, tuple(d / f for f in fs)) for o, n, fs in changes], texts)
        return {p.name: t for p, t in out.items()}

    def test_bump_leaves_same_version_of_other_dependency(self):
        out = self.plan([("1.3.0", "1.3.1", ["app.kts", "README.md"])], {
            "app.kts": 'implementation("androidx.datastore:datastore-preferences:1.3.0")\n',
            "README.md": "| DataStore Preferences | 1.3.0 |\n| x | 21.3.0.1 |\n",
            "go.mod": "require github.com/andybalholm/brotli v1.3.0 // indirect\n",
        })
        self.assertNotIn("go.mod", out)
        self.assertIn("datastore-preferences:1.3.1", out["app.kts"])
        self.assertIn("| 1.3.1 |", out["README.md"])
        self.assertIn("21.3.0.1", out["README.md"])

    def test_go_forms(self):
        out = self.plan([("1.27.4", "1.28.0", ["go.mod", "README.md"])], {
            "go.mod": "go 1.27.4\n",
            "README.md": "| Go | 1.27.4 |\ncurl -fLO https://go.dev/dl/go1.27.4.linux-amd64.tar.gz\n",
        })
        self.assertEqual(out["README.md"].count("1.28.0"), 2)

    def test_missing_pin_fails_before_writing(self):
        with self.assertRaises(SystemExit):
            self.plan([("9.9.1", "9.9.2", ["build.sh", "README.md"])], {
                "build.sh": "/opt/gradle/gradle-9.9.1/bin\n",
                "README.md": "Gradle drifted to 9.9.0\n",
            })

    @unittest.skipUnless(Path("/opt/jdk/current").exists(), "needs the box JDK link")
    def test_every_bump_finds_its_sites_in_the_repo(self):
        """Run main() offline with every pin bumped and check that each change
        is found in each file it names, without writing anything."""
        seen = []

        def apply(changes):
            texts = {p: update_pins.read_text(p) for _o, _n, fs in changes for p in fs}
            seen.extend(changes)
            update_pins.plan_replacements(changes, texts)

        cur_jdk = update_pins.current_jdk_version()
        major = str(int(cur_jdk.split(".")[0]) + 1)
        p = mock.patch.object
        with p(update_pins, "latest_google", lambda *a, **k: "99999999.0.0"), \
                p(update_pins, "latest_central", lambda *a, **k: "99999999.0.0"), \
                p(update_pins, "latest_gradle", lambda: "99.0"), \
                p(update_pins, "latest_go", lambda: "99999999.0.0"), \
                p(update_pins, "latest_ndk", lambda cur: "99.0.1"), \
                p(update_pins, "latest_compile_minor", lambda m, c: c + 1), \
                p(update_pins, "install_platform", lambda *a: None), \
                p(update_pins, "latest_jdk_major", lambda: major), \
                p(update_pins, "latest_jdk_patch", lambda m: m + ".0.1"), \
                p(update_pins, "install_jdk", lambda m: f"jdk-{m}.0.1+1"), \
                p(update_pins, "current_jdk_version", lambda: cur_jdk), \
                p(update_pins, "java_version", lambda h: major + ".0.1"), \
                p(update_pins, "install_gradle", lambda v: "/opt/gradle/gradle-" + v), \
                p(update_pins, "install_go", lambda v: "/usr/local/go"), \
                p(update_pins, "install_ndk", lambda v: v), \
                p(update_pins, "write_pin_env", lambda **k: None), \
                p(update_pins, "atomic_write", lambda *a: None), \
                p(update_pins, "apply_replacements", apply), \
                p(update_pins, "log", lambda m: None):
            self.assertEqual(update_pins.main(), 0)
        self.assertEqual(len(seen), 18, [c[0] for c in seen])


class Fetch(unittest.TestCase):
    def test_permanent_4xx_is_not_retried(self):
        calls = []

        def urlopen(req, timeout):
            calls.append(1)
            raise HTTPError(req.full_url, 404, "Not Found", {}, None)

        def die(msg):
            raise SystemExit(msg)

        with mock.patch.object(common, "urlopen", urlopen), self.assertRaises(SystemExit):
            common.fetch("https://example.invalid/x", ua="t", die=die, sleep=lambda s: None)
        self.assertEqual(len(calls), 1)

    def test_5xx_is_retried(self):
        calls = []

        def urlopen(req, timeout):
            calls.append(1)
            raise HTTPError(req.full_url, 503, "busy", {}, None)

        with mock.patch.object(common, "urlopen", urlopen), self.assertRaises(SystemExit):
            common.fetch("https://example.invalid/x", ua="t", die=lambda m: (_ for _ in ()).throw(SystemExit(m)),
                         retries=3, sleep=lambda s: None)
        self.assertEqual(len(calls), 3)


class AtomicWrite(unittest.TestCase):
    def test_mode_and_no_temp_left(self):
        d = tmpdir(self)
        f = d / "x"
        f.write_text("old")
        common.atomic_write(f, b"new", 0o600)
        self.assertEqual(f.read_bytes(), b"new")
        self.assertEqual(f.stat().st_mode & 0o777, 0o600)
        self.assertEqual(sorted(p.name for p in d.iterdir()), ["x"])

    def test_failed_write_keeps_old_file(self):
        d = tmpdir(self)
        f = d / "x"
        f.write_text("old")
        with mock.patch.object(common.os, "replace", side_effect=OSError("disk full")), self.assertRaises(OSError):
            common.atomic_write(f, b"new")
        self.assertEqual(f.read_text(), "old")
        self.assertEqual(sorted(p.name for p in d.iterdir()), ["x"])


def v2fly_tarball(lists: dict[str, str], commit: str = "c0ffee") -> bytes:
    import io
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.PAX_FORMAT, pax_headers={"comment": commit}) as tf:
        for name, text in {**lists, "../README.md": "x"}.items():
            data = text.encode()
            ti = tarfile.TarInfo("domain-list-community-master/data/" + name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


class FetchRules(unittest.TestCase):
    LISTS = {
        "google": "include:google-ads\ngoogle.com\n",
        "google-ads": "full:ads.google.com @ads\n",
        "geolocation-cn": "baidu.com\n",
        "geolocation-!cn": "include:a @cn\ninclude:b @-cn\nfull:X.Example # c\nkeyword:foo\n",
        "a": "a1.example @cn\na2.example\n",
        "b": "b1.example @cn\nb2.example @ads\n",
        "unrelated": "zz.example\n",
    }

    def test_parse_v2fly_attrs(self):
        rows = list(fetch_rules.parse_v2fly_lines("include:foo @cn @-ads # c\nfull:a.example @ads\n\n# x\n"))
        self.assertEqual(rows, [("include:foo", ["cn"], ["ads"]), ("full:a.example", ["ads"], [])])

    def test_tarball_reach_and_flatten(self):
        lists, commit = fetch_rules.untar_v2fly(v2fly_tarball(self.LISTS))
        self.assertEqual(commit, "c0ffee")
        self.assertNotIn("../README.md", lists)
        reach = fetch_rules.reachable_v2fly(lists)
        self.assertEqual(sorted(reach), ["a", "b", "geolocation-!cn", "geolocation-cn", "google", "google-ads"])
        flat = fetch_rules.flatten_not_cn(reach)
        self.assertEqual(flat, "domain:a1.example:@cn\ndomain:b2.example:@ads\nfull:x.example\nkeyword:foo\n")

    def test_missing_include_fails(self):
        lists = {k: v.encode() for k, v in dict(self.LISTS, google="include:gone\n").items()}
        with mock.patch("sys.stderr"), self.assertRaises(SystemExit):
            fetch_rules.reachable_v2fly(lists)

    def test_truncated_download_fails(self):
        downloads = {name: b"x\n" for name in fetch_rules.DIRECT}
        downloads[fetch_rules.V2FLY_KEY] = v2fly_tarball(self.LISTS)
        with mock.patch("sys.stderr"), self.assertRaises(SystemExit):
            fetch_rules.build(downloads)

    def test_corrupt_tarball_fails(self):
        with mock.patch("sys.stderr"), self.assertRaises(SystemExit):
            fetch_rules.untar_v2fly(b"<html>rate limited</html>")

    def test_outdir_must_be_empty_and_outside_repo(self):
        d = tmpdir(self)
        self.assertEqual(fetch_rules.outdir(str(d)), d.resolve())
        (d / "x").write_text("")
        with mock.patch("sys.stderr"), self.assertRaises(SystemExit):
            fetch_rules.outdir(str(d))
        with mock.patch("sys.stderr"), self.assertRaises(SystemExit):
            fetch_rules.outdir(str(fetch_rules.REPO / "core"))


FAKE_MODULE = """
REQUIRED_SECRETS = ("subscribe_url",)

def run(ctx, argv):
    body = ("proxies:\\n  - {name: 香港 01, type: anytls, server: a1.example.invalid, port: 443, "
            "password: synthetic-pass-1}\\n").encode()
    ctx.write_subscription(body)
    (ctx.state_dir / "seen").write_text(ctx.secrets["subscribe_url"])
    return 0
"""


def make_bundle(t: unittest.TestCase) -> Path:
    """A synthetic private bundle with one fake provider; nothing real in it."""
    root = tmpdir(t) / "bundle"
    for d in ("", "keys", "providers/fake", "rules", "state", "subs", "out"):
        (root / d).mkdir(mode=0o700, parents=True, exist_ok=True)
    for d in (root / "providers", root / "providers/fake"):
        os.chmod(d, 0o700)
    files = {
        "bundle.toml": 'schema_version = 1\n[build]\nkeys_dir = "keys"\n[[providers]]\nid = "fake"\n'
                       'module = "providers/fake/fetch.py"\nproto = "anytls"\nrequire_type = "anytls"\n'
                       'secrets = ["subscribe_url"]\n',
        "secrets.toml": 'schema_version = 1\n[providers.fake]\nsubscribe_url = "https://sub.example.invalid/zzsecretpath"\n',
        "rules/catalog.toml": 'schema_version = 1\n[naming]\nregular = "{country} {n:02}"\n'
                              'residential = "{country}R {n}"\n[[source]]\nprovider = "fake"\ntypes = ["anytls"]\n',
        "providers/fake/fetch.py": FAKE_MODULE,
        "leak-denylist.txt": "# synthetic\nword:zzbrand\n",
    }
    for name, text in files.items():
        (root / name).write_text(text)
        os.chmod(root / name, 0o600)
    t.enterContext(mock.patch.dict(os.environ, {"ARC_PRIVATE": str(root)}))
    return root


class PrivateBundle(unittest.TestCase):
    def test_check_emit_and_orchestrate(self):
        root = make_bundle(self)
        with mock.patch("builtins.print"):
            self.assertEqual(update_subs.main([]), 0)
        self.assertEqual((root / "state/fake/seen").read_text(), "https://sub.example.invalid/zzsecretpath")
        self.assertEqual((root / "subs/fake.yaml").stat().st_mode & 0o777, 0o600)
        private.emit(private.load())
        inp = json.loads((root / "out/codegen-input.json").read_text())
        self.assertEqual(inp["sources"][0]["proto"], "anytls")
        self.assertEqual(inp["sources"][0]["sub"], str(root / "subs/fake.yaml"))

    def test_loose_mode_rejected_and_fixed(self):
        root = make_bundle(self)
        os.chmod(root / "secrets.toml", 0o644)
        with self.assertRaisesRegex(private.BundleError, "secrets.toml"):
            private.load()
        private.fix_modes()
        private.load()

    def test_errors_never_print_values(self):
        root = make_bundle(self)
        (root / "secrets.toml").write_text('schema_version = 1\n[providers.fake]\nother = "zzvalue123"\n')
        with self.assertRaises(private.BundleError) as cm:
            private.load()
        self.assertIn("subscribe_url", str(cm.exception))
        self.assertNotIn("zzvalue123", str(cm.exception))

    def test_bundle_inside_repo_rejected(self):
        with mock.patch.dict(os.environ, {"ARC_PRIVATE": str(private.REPO / "core")}):
            with self.assertRaisesRegex(private.BundleError, "outside"):
                private.Bundle(private.bundle_root(), modes=False)

    def test_leak_rules(self):
        make_bundle(self)
        r = private.Rules(private.load())
        def hits(text):
            return [h for _, h in r.scan(text.encode(), "x.go")]
        self.assertTrue(hits("u := \"https://sub.example.invalid/zzsecretpath\""))
        self.assertTrue(hits("host sub.example.invalid"))
        self.assertTrue(hits("ZZBRAND app"))
        self.assertTrue(hits("type zzbrandDialer"))
        self.assertTrue(hits("func dialZzbrand()"))
        self.assertFalse(hits("zzbranding is another word"))
        self.assertTrue(hits("id " + "-".join(["3f2c1a9e", "1b2c", "4d3e", "8f90", "112233445566"])))
        self.assertFalse(hits("id 00000000-0000-4000-8000-000000000001"))
        self.assertEqual(r.scan_path("keys/x.jks"), ["secret-file-type"])
        fx = "core/cmd/codegen/testdata/rules/list"
        self.assertEqual(r.scan(b"zzbrand", fx), [], "third-party data: values only")
        self.assertTrue(r.scan(b"sub.example.invalid", fx))
        self.assertTrue(hits("zzbrand"), "router/ code is not data")
        for p in ("core/internal/router/dom.bin", "android/app/src/main/jniLibs/arm64-v8a/libarc.so"):
            self.assertIn("build-product", r.scan_path(p))
        self.assertEqual(r.scan_path("core/internal/router/cndata.go"), [])


if __name__ == "__main__":
    unittest.main()
