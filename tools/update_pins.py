#!/usr/bin/env python3
"""Check and apply usable build-tool and library pins.

Called by ~/update.sh, and can also be run on its own.
Upgrades to the newest usable version on the current channel, installs
toolchain packages when needed, and rewrites the pin strings in Gradle
files, build.sh, README.md, and core/go.mod. minSdk is never changed.
Canary / nightly / snapshot / dev releases are skipped. AndroidX
libraries that are already on a stable pin stay on latest stable.
AGP, Kotlin, and compose-bom-beta stay on their existing pre-release
channel (including a later beta/rc/stable of that line). JDK tracks the
newest GA Temurin feature release (majors included), installed under
~/jdk with /opt/jdk/current pointing at it; a major bump also raises the
Java/Kotlin language level in app/build.gradle.kts. compileSdk may take a newer
minor of the same major API, but not a canary platform or a new major.

Exit 0 on success (whether or not anything changed), 1 on failure.
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import quote

from common import Tool, atomic_write
from common import fetch as net_fetch

TOOLS = Path(__file__).resolve().parent
REPO = TOOLS.parent
PIN_ENV = TOOLS / ".pin_env"
JDK_PRUNE = TOOLS / ".jdk_prune"  # old JDK dir for build.sh to delete once a build passes

ANDROID_HOME = Path(os.environ.get("ANDROID_HOME") or Path.home() / "android-sdk")
TIMEOUT = 60
RETRIES = 4

ROOT_GRADLE = REPO / "android" / "build.gradle.kts"
APP_GRADLE = REPO / "android" / "app" / "build.gradle.kts"
GRADLE_PROPS = REPO / "android" / "gradle.properties"
BUILD_SH = REPO / "build.sh"
README = REPO / "README.md"
GO_MOD = REPO / "core" / "go.mod"
DOC_FILES = (ROOT_GRADLE, APP_GRADLE, GRADLE_PROPS, BUILD_SH, README, GO_MOD)

GOOGLE_MAVEN = "https://dl.google.com/android/maven2/"
CENTRAL = "https://repo1.maven.org/maven2/"


T = Tool("update_pins")
die, log = T.die, T.log


def fetch(url: str) -> bytes:
    return net_fetch(url, ua=pin_user_agent(), die=die, retries=RETRIES, timeout=TIMEOUT)


def fetch_to(url: str, dest: Path, expect_sha: str | None = None) -> None:
    data = fetch(url)
    if expect_sha:
        got = hashlib.sha256(data).hexdigest()
        if got != expect_sha.lower():
            die(f"sha256 mismatch for {url}: got {got}, expected {expect_sha}")
    atomic_write(dest, data)


# version tuple: (numeric_parts, pre_rank, pre_n) with pre_rank 10 = stable
_SKIP_PRE = {"snapshot", "dev", "canary", "preview", "sp", "alpha-dev", "beta-dev"}
_PRE_RANK = {"": 10, "alpha": 1, "a": 1, "beta": 2, "b": 2, "rc": 3, "cr": 3, "m": 0}


def parse_ver(s: str) -> tuple[tuple[int, ...], int, int] | None:
    s = s.strip()
    m = re.match(r"^(\d+(?:\.\d+)*)(?:[-.]([A-Za-z]+)[.-]?(\d*))?$", s)
    if not m:
        return None
    parts = tuple(int(x) for x in m.group(1).split("."))
    pre = (m.group(2) or "").lower()
    if pre in _SKIP_PRE:
        return None
    if pre not in _PRE_RANK:
        return None
    pre_n = int(m.group(3) or 0)
    return (parts, _PRE_RANK[pre], pre_n)


def _cmp_parsed(a, b) -> int:
    n = max(len(a[0]), len(b[0]))
    aa = (a[0] + (0,) * (n - len(a[0])), a[1], a[2])
    bb = (b[0] + (0,) * (n - len(b[0])), b[1], b[2])
    return (aa > bb) - (aa < bb)


def ver_gt(a: str, b: str) -> bool:
    pa, pb = parse_ver(a), parse_ver(b)
    if pa is None or pb is None:
        return False
    return _cmp_parsed(pa, pb) > 0


def newest(versions: list[str], *, allow_prerelease: bool) -> str | None:
    best: str | None = None
    best_key = None
    for v in versions:
        p = parse_ver(v)
        if p is None or (not allow_prerelease and p[1] != 10):
            continue
        if best is None or _cmp_parsed(p, best_key) > 0:
            best, best_key = v, p
    return best


def metadata_versions(base: str, group: str, artifact: str) -> list[str]:
    path = "/".join(group.split(".")) + f"/{artifact}/maven-metadata.xml"
    xml = fetch(base + path)
    root = ET.fromstring(xml)
    return [v.text.strip() for v in root.findall(".//version") if v is not None and v.text]


def _filter_major(versions: list[str], major: str | None) -> list[str]:
    if major is None:
        return versions
    prefix = major + "."
    return [v for v in versions if v == major or v.startswith(prefix)]


def latest_google(group: str, artifact: str, *, allow_prerelease: bool, major: str | None = None, line: str | None = None) -> str:
    vers = _filter_line(_filter_major(metadata_versions(GOOGLE_MAVEN, group, artifact), major), line)
    v = newest(vers, allow_prerelease=allow_prerelease)
    if not v:
        die(f"no usable version for {group}:{artifact}")
    return v


def latest_central(group: str, artifact: str, *, allow_prerelease: bool, major: str | None = None, line: str | None = None) -> str:
    vers = _filter_line(_filter_major(metadata_versions(CENTRAL, group, artifact), major), line)
    v = newest(vers, allow_prerelease=allow_prerelease)
    if not v:
        die(f"no usable version for {group}:{artifact}")
    return v


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def current_from(pattern: str, path: Path) -> str:
    m = re.search(pattern, read_text(path))
    if not m:
        die(f"cannot read current pin with {pattern!r} in {path}")
    return m.group(1)


def pin_user_agent() -> str:
    return "ArcBuild/" + current_from(r'versionName\s*=\s*"([^"]+)"', APP_GRADLE)


def _filter_line(versions: list[str], current: str | None) -> list[str]:
    if current is None:
        return versions
    cur = parse_ver(current)
    if cur is None or len(cur[0]) < 2:
        die(f"cannot derive pin line from {current}")
    major, minor = cur[0][0], cur[0][1]
    out: list[str] = []
    for v in versions:
        parsed = parse_ver(v)
        if parsed is None or len(parsed[0]) < 2:
            continue
        if parsed[0][0] == major and parsed[0][1] == minor:
            out.append(v)
    return out


def run(cmd: list[str], *, sudo: bool = False, check: bool = True, env=None) -> subprocess.CompletedProcess:
    full = (["sudo", "-n"] + cmd) if sudo else cmd
    return subprocess.run(full, check=check, env=env, text=True, capture_output=True)


def install_gradle(version: str) -> str:
    dest = Path(f"/opt/gradle/gradle-{version}")
    exe = dest / "bin" / "gradle"
    if exe.is_file():
        log(f"Gradle {version} already installed at {dest}")
        return str(dest)
    url = f"https://services.gradle.org/distributions/gradle-{version}-bin.zip"
    sha = fetch(url + ".sha256").decode().strip().split()[0]
    log(f"installing Gradle {version}")
    with tempfile.TemporaryDirectory(prefix="arc-gradle-") as td:
        zpath = Path(td) / f"gradle-{version}-bin.zip"
        fetch_to(url, zpath, sha)
        # unzip to /opt/gradle (creates gradle-VERSION/)
        run(["mkdir", "-p", "/opt/gradle"], sudo=True)
        run(["unzip", "-q", "-o", str(zpath), "-d", "/opt/gradle"], sudo=True)
    if not exe.is_file():
        die(f"Gradle install missing {exe}")
    return str(dest)


def install_go(version: str) -> str:
    # version like 1.27.4
    gover = f"go{version}"
    existing = Path("/usr/local/go/bin/go")
    if existing.is_file():
        out = subprocess.run([str(existing), "version"], check=True, text=True, capture_output=True).stdout
        if f" {gover} " in out:
            log(f"Go {version} already installed")
            return "/usr/local/go"
    data = json.loads(fetch("https://go.dev/dl/?mode=json&include=all").decode())
    sha = None
    fname = f"{gover}.linux-amd64.tar.gz"
    for rel in data:
        if rel.get("version") != gover:
            continue
        for f in rel.get("files") or []:
            if f.get("filename") == fname:
                sha = f.get("sha256")
                break
    if not sha:
        die(f"no linux-amd64 archive for {gover}")
    url = f"https://go.dev/dl/{fname}"
    log(f"installing Go {version}")
    with tempfile.TemporaryDirectory(prefix="arc-go-") as td:
        tpath = Path(td) / fname
        fetch_to(url, tpath, sha)
        run(["rm", "-rf", "/usr/local/go"], sudo=True)
        run(["tar", "-C", "/usr/local", "-xzf", str(tpath)], sudo=True)
    if not existing.is_file():
        die("Go install missing /usr/local/go/bin/go")
    out = subprocess.run([str(existing), "version"], check=True, text=True, capture_output=True).stdout
    if version not in out:
        die(f"Go install mismatch: {out.strip()}")
    return "/usr/local/go"


def latest_gradle() -> str:
    data = json.loads(fetch("https://services.gradle.org/versions/current").decode())
    v = data.get("version")
    if not v or parse_ver(v) is None:
        die(f"unexpected Gradle current: {data!r}")
    return v


def latest_go() -> str:
    data = json.loads(fetch("https://go.dev/dl/?mode=json").decode())
    for rel in data:
        if rel.get("stable"):
            ver = rel.get("version") or ""
            if ver.startswith("go"):
                return ver[2:]
    die("no stable Go release found")
    raise AssertionError


def _temurin_feature_ver(ver: dict) -> str | None:
    major = ver.get("major")
    if major is None:
        return None
    parts = [int(major), int(ver.get("minor") or 0), int(ver.get("security") or 0)]
    patch = ver.get("patch")
    if patch not in (None, 0):
        parts.append(int(patch))
    return ".".join(str(p) for p in parts)


def latest_jdk_patch(major: str) -> str:
    # Official Adoptium API v3 GA catalog for this feature version.
    lo, hi = int(major), int(major) + 1
    params = (
        "architecture=x64&image_type=jdk&jvm_impl=hotspot&os=linux"
        "&page=0&page_size=20&project=jdk&release_type=ga"
        "&sort_method=DATE&sort_order=DESC&vendor=eclipse"
        f"&version={quote(f'[{lo},{hi})', safe='')}"
    )
    url = f"https://api.adoptium.net/v3/info/release_versions?{params}"
    data = json.loads(fetch(url).decode())
    best: str | None = None
    for ver in data.get("versions") or []:
        got = _temurin_feature_ver(ver)
        if got and (best is None or ver_gt(got, best)):
            best = got
    if not best:
        die(f"no GA Temurin {major} release in Adoptium catalog")
    return best


JDK_LINK = Path("/opt/jdk/current")
JDK_DIR = Path.home() / "jdk"


def java_version(home: Path) -> str:
    java = home / "bin" / "java"
    exe = str(java if java.is_file() else shutil.which("java") or "java")
    out = subprocess.run([exe, "-version"], check=True, text=True, capture_output=True).stderr or ""
    m = re.search(r'version "([^"]+)"', out)
    return m.group(1) if m else "0"


def current_jdk_version() -> str:
    return java_version(JDK_LINK)


def latest_jdk_major() -> str:
    data = json.loads(fetch("https://api.adoptium.net/v3/info/available_releases").decode())
    major = data.get("most_recent_feature_release")
    if not major:
        die(f"unexpected Adoptium available_releases: {data!r}")
    return str(major)


def install_jdk(major: str) -> str:
    # Latest GA Temurin build of this major, checked against the API sha256.
    url = (f"https://api.adoptium.net/v3/assets/latest/{major}/hotspot"
           "?architecture=x64&image_type=jdk&os=linux&vendor=eclipse")
    assets = json.loads(fetch(url).decode())
    if not assets:
        die(f"no Temurin {major} linux x64 JDK asset")
    pkg, name = assets[0]["binary"]["package"], assets[0]["release_name"]
    dest = JDK_DIR / name
    if not (dest / "bin" / "java").is_file():
        log(f"installing Temurin {name}")
        with tempfile.TemporaryDirectory(prefix="arc-jdk-") as td:
            tpath = Path(td) / pkg["name"]
            fetch_to(pkg["link"], tpath, pkg["checksum"])
            JDK_DIR.mkdir(parents=True, exist_ok=True)
            run(["tar", "-C", str(JDK_DIR), "-xzf", str(tpath)])
    if not (dest / "bin" / "java").is_file():
        die(f"JDK install missing {dest}/bin/java")
    run(["mkdir", "-p", str(JDK_LINK.parent)], sudo=True)
    run(["ln", "-sfn", str(dest), str(JDK_LINK)], sudo=True)
    return name


SDKMANAGER = ANDROID_HOME / "cmdline-tools" / "latest" / "bin" / "sdkmanager"


@functools.cache
def sdk_list() -> str | None:
    """sdkmanager --list output, fetched once per run (it takes ~10 s)."""
    if not SDKMANAGER.is_file():
        log("sdkmanager not found")
        return None
    proc = subprocess.run([str(SDKMANAGER), f"--sdk_root={ANDROID_HOME}", "--list"],
                          check=False, text=True, capture_output=True)
    if proc.returncode != 0:
        log("sdkmanager --list failed")
        return None
    return proc.stdout or ""


def latest_ndk(current: str) -> str:
    listing = sdk_list()
    if listing is None:
        log("leaving NDK pin")
        return current
    best = current
    for line in listing.splitlines():
        m = re.search(r"ndk;(\d+\.\d+\.\d+)\s", line)
        if not m:
            continue
        v = m.group(1)
        if "rc" in line.lower() or "alpha" in line.lower() or "beta" in line.lower():
            continue
        if ver_gt(v, best):
            best = v
    return best


def install_ndk(version: str) -> str:
    dest = ANDROID_HOME / "ndk" / version
    clang = dest / "toolchains" / "llvm" / "prebuilt" / "linux-x86_64" / "bin" / "aarch64-linux-android37-clang"
    if clang.is_file():
        return str(dest)
    sm = SDKMANAGER
    if not sm.is_file():
        die("sdkmanager not found; cannot install NDK")
    log(f"installing NDK {version}")
    proc = subprocess.run(
        [str(sm), f"--sdk_root={ANDROID_HOME}", f"ndk;{version}"],
        input="y\n" * 20,
        check=False,
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0 or not clang.is_file():
        die(f"NDK {version} install failed: {(proc.stderr or proc.stdout)[-1000:]}")
    return str(dest)


def latest_compile_minor(major: int, current_minor: int) -> int:
    plats = ANDROID_HOME / "platforms"
    best = current_minor
    if plats.is_dir():
        for p in plats.iterdir():
            m = re.fullmatch(rf"android-{major}(?:\.(\d+))?", p.name)
            if not m:
                continue
            # skip canary folders if any slip through as android-37.2-canary etc.
            if "canary" in p.name.lower() or "beta" in p.name.lower():
                continue
            minor = int(m.group(1) or 0)
            if minor > best:
                best = minor
    # also consult sdkmanager for a newer non-canary package we don't have yet
    for line in (sdk_list() or "").splitlines():
        if "canary" in line.lower() or "beta" in line.lower() or "rc" in line.lower():
            continue
        m = re.search(rf"platforms;android-{major}(?:\.(\d+))?\s", line)
        if not m:
            continue
        minor = int(m.group(1) or 0)
        if minor > best:
            best = minor
    return best


def install_platform(major: int, minor: int) -> None:
    pkg = f"platforms;android-{major}.{minor}" if minor else f"platforms;android-{major}"
    dest = ANDROID_HOME / "platforms" / (f"android-{major}.{minor}" if minor else f"android-{major}")
    if dest.is_dir():
        return
    sm = SDKMANAGER
    if not sm.is_file():
        die("sdkmanager not found; cannot install platform")
    log(f"installing {pkg}")
    proc = subprocess.run(
        [str(sm), f"--sdk_root={ANDROID_HOME}", pkg],
        input="y\n" * 20,
        check=False,
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0 or not dest.is_dir():
        die(f"platform install failed: {(proc.stderr or proc.stdout)[-1000:]}")


def write_pin_env(*, java_home: str, gradle_home: str, goroot: str, ndk_home: str) -> None:
    atomic_write(PIN_ENV, (
        "# generated by tools/update_pins.py, not in git\n"
        f"export JAVA_HOME={java_home}\n"
        f"export GRADLE_HOME={gradle_home}\n"
        f"export GOROOT={goroot}\n"
        f"export ANDROID_NDK_HOME={ndk_home}\n"
    ).encode())


# A change rewrites one pin only in the files that are known to carry it, and
# only as a whole token: "1.3.0" must not touch "brotli v1.3.0" or "21.3.0.1".
Change = tuple[str, str, tuple[Path, ...]]


def token_re(old: str) -> re.Pattern[str]:
    return re.compile(r"(?<![0-9.])(?<!\bv)" + re.escape(old) + r"(?![0-9A-Za-z]|\.[0-9])"
                      if old[:1].isdigit() else
                      r"(?<![0-9A-Za-z_])" + re.escape(old) + r"(?![0-9])")


def plan_replacements(changes: list[Change], texts: dict[Path, str]) -> dict[Path, str]:
    """Return the new text of every file that changes. Dies before anything is
    written if a pin is missing from a file that should carry it, so a drifted
    README or Gradle file is fixed by hand instead of half-updated."""
    out = dict(texts)
    # longer first so a path containing the version is rewritten as a whole
    for old, new, files in sorted(changes, key=lambda c: len(c[0]), reverse=True):
        if old == new:
            continue
        pat = token_re(old)
        for path in files:
            text, n = pat.subn(lambda _m: new, out[path])
            if n == 0:
                die(f"pin {old!r} not found in {path.relative_to(REPO)}; update it by hand")
            out[path] = text
    return {p: t for p, t in out.items() if t != texts[p]}


def apply_replacements(changes: list[Change]) -> None:
    files = sorted({p for _o, _n, fs in changes for p in fs})
    texts = {p: read_text(p) for p in files}
    for path, text in plan_replacements(changes, texts).items():
        atomic_write(path, text.encode("utf-8"))
        log(f"updated {path.relative_to(REPO)}")


def main() -> int:
    log("checking usable pins")
    changes: list[Change] = []
    upgraded: list[str] = []

    cur_agp = current_from(r'id\("com\.android\.application"\) version "([^"]+)"', ROOT_GRADLE)
    cur_kotlin = current_from(r'kotlin-gradle-plugin:([0-9A-Za-z.\-]+)', ROOT_GRADLE)
    cur_bom = current_from(r'compose-bom-beta:([0-9.]+)', APP_GRADLE)
    cur_activity = current_from(r'activity-compose:([0-9.]+)', APP_GRADLE)
    cur_lifecycle = current_from(r'lifecycle-runtime-compose:([0-9.]+)', APP_GRADLE)
    cur_datastore = current_from(r'datastore-preferences:([0-9.]+)', APP_GRADLE)
    cur_coroutines = current_from(r'kotlinx-coroutines-android:([0-9.]+)', APP_GRADLE)
    cur_junit = current_from(r'"junit:junit:([0-9.]+)"', APP_GRADLE)
    cur_json = current_from(r'"org\.json:json:([0-9]+)"', APP_GRADLE)
    cur_gradle = current_from(r"/opt/gradle/gradle-([0-9.]+)", BUILD_SH)
    cur_go = current_from(r"(?m)^go ([0-9.]+)", GO_MOD)
    cur_ndk = current_from(r'ndkVersion = "([0-9.]+)"', APP_GRADLE)
    cur_compile_major = current_from(r"version = release\((\d+)\)", APP_GRADLE)
    cur_compile_minor = current_from(r"minorApiLevel = (\d+)", APP_GRADLE)

    new_agp = latest_google("com.android.tools.build", "gradle", allow_prerelease=True, line=cur_agp)
    new_kotlin = latest_central("org.jetbrains.kotlin", "kotlin-gradle-plugin", allow_prerelease=True, line=cur_kotlin)
    new_bom = latest_google("androidx.compose", "compose-bom-beta", allow_prerelease=True, line=cur_bom)
    new_activity = latest_google("androidx.activity", "activity-compose", allow_prerelease=False, major=cur_activity.split(".")[0])
    new_lifecycle = latest_google("androidx.lifecycle", "lifecycle-runtime-compose", allow_prerelease=False, major=cur_lifecycle.split(".")[0])
    new_datastore = latest_google("androidx.datastore", "datastore-preferences", allow_prerelease=False, major=cur_datastore.split(".")[0])
    new_coroutines = latest_central("org.jetbrains.kotlinx", "kotlinx-coroutines-android", allow_prerelease=False, major=cur_coroutines.split(".")[0])
    new_junit = latest_central("junit", "junit", allow_prerelease=False, major=cur_junit.split(".")[0])
    new_json = latest_central("org.json", "json", allow_prerelease=False)
    new_gradle = latest_gradle()
    new_go = latest_go()
    new_ndk = latest_ndk(cur_ndk)

    major = int(cur_compile_major)
    cur_minor = int(cur_compile_minor)
    new_minor = latest_compile_minor(major, cur_minor)

    app, root = (APP_GRADLE, README), (ROOT_GRADLE, README)
    pins = [
        ("AGP", cur_agp, new_agp, root),
        ("Kotlin", cur_kotlin, new_kotlin, root),
        ("compose-bom-beta", cur_bom, new_bom, app),
        ("activity-compose", cur_activity, new_activity, app),
        ("lifecycle-runtime-compose", cur_lifecycle, new_lifecycle, app),
        ("datastore-preferences", cur_datastore, new_datastore, app),
        ("kotlinx-coroutines-android", cur_coroutines, new_coroutines, app),
        ("JUnit", cur_junit, new_junit, app),
        ("org.json", cur_json, new_json, app),
        ("Gradle", cur_gradle, new_gradle, (BUILD_SH, README)),
        ("Go", cur_go, new_go, (GO_MOD, README)),
        ("NDK", cur_ndk, new_ndk, (APP_GRADLE, BUILD_SH, README)),
    ]
    for name, cur, new, files in pins:
        if new != cur and ver_gt(new, cur):
            log(f"{name}: {cur} -> {new}")
            changes.append((cur, new, files))
            upgraded.append(f"{name} {cur}→{new}")
        elif new != cur:
            log(f"{name}: keeping {cur} (latest usable {new})")
        else:
            log(f"{name}: {cur} (current)")

    if new_minor > cur_minor:
        log(f"compileSdk: {major}.{cur_minor} -> {major}.{new_minor}")
        install_platform(major, new_minor)
        changes.append((f"minorApiLevel = {cur_minor}", f"minorApiLevel = {new_minor}", (APP_GRADLE,)))
        changes.append((f"{major}.{cur_minor}", f"{major}.{new_minor}", (README,)))
        upgraded.append(f"compileSdk {major}.{cur_minor}→{major}.{new_minor}")
    else:
        log(f"compileSdk: {major}.{cur_minor} (current)")

    cur_jdk = current_jdk_version()
    cur_jdk_major = cur_jdk.split(".")[0]
    jdk_major = latest_jdk_major()
    latest_jdk = latest_jdk_patch(jdk_major)
    if int(jdk_major) > int(cur_jdk_major) or ver_gt(latest_jdk, cur_jdk):
        old_dir = JDK_LINK.resolve().name
        new_dir = install_jdk(jdk_major)
        new_jdk = java_version(JDK_LINK)
        log(f"JDK: {cur_jdk} -> {new_jdk}")
        changes += [(old_dir, new_dir, (README,)), (f"| JDK | {cur_jdk}", f"| JDK | {new_jdk}", (README,))]
        if jdk_major != cur_jdk_major:
            changes += [(f"VERSION_{cur_jdk_major}", f"VERSION_{jdk_major}", (APP_GRADLE,)),
                        (f"JVM_{cur_jdk_major}", f"JVM_{jdk_major}", (APP_GRADLE,))]
        upgraded.append(f"JDK {cur_jdk}→{new_jdk}")
        if old_dir != new_dir:
            # build.sh removes it after the next successful release build, so
            # a JDK that cannot build Arc can still be switched back to.
            atomic_write(JDK_PRUNE, (str(JDK_DIR / old_dir) + "\n").encode())
            log(f"old JDK {old_dir} kept until the next successful ~/build.sh")
    else:
        log(f"JDK: {cur_jdk} (current)")

    # install toolchains for upgrades
    gradle_home = f"/opt/gradle/gradle-{new_gradle if (new_gradle != cur_gradle and ver_gt(new_gradle, cur_gradle)) else cur_gradle}"
    if new_gradle != cur_gradle and ver_gt(new_gradle, cur_gradle):
        gradle_home = install_gradle(new_gradle)

    goroot = "/usr/local/go"
    if new_go != cur_go and ver_gt(new_go, cur_go):
        goroot = install_go(new_go)

    ndk_ver = new_ndk if (new_ndk != cur_ndk and ver_gt(new_ndk, cur_ndk)) else cur_ndk
    if ndk_ver != cur_ndk:
        install_ndk(ndk_ver)

    if changes:
        apply_replacements(changes)

    java_home = str(JDK_LINK)
    ndk_home = str(ANDROID_HOME / "ndk" / ndk_ver)
    write_pin_env(java_home=java_home, gradle_home=gradle_home, goroot=goroot, ndk_home=ndk_home)

    if upgraded:
        log("upgraded: " + ", ".join(upgraded))
    else:
        log("all pins already current")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        die("interrupted")
    except subprocess.CalledProcessError as exc:
        err = (exc.stderr or exc.stdout or str(exc))
        die(f"command failed: {' '.join(exc.cmd)}: {err[-1000:]}")
