#!/usr/bin/env bash

set -euo pipefail
export ANDROID_HOME="${ANDROID_HOME:-$HOME/android-sdk}"
W="${ARC_DIR:-$HOME/arc}"
JNI="$W/android/app/src/main/jniLibs/arm64-v8a"
PKGS=(./internal/... ./cmd/... .)
export ARC_PRIVATE="${ARC_PRIVATE:-$HOME/arc-private}"
P="$ARC_PRIVATE"
ASSETS="$W/android/app/build/generated/arc/assets"

if [[ -f "$W/tools/.pin_env" ]]; then
  # shellcheck disable=SC1091
  source "$W/tools/.pin_env"
fi
export JAVA_HOME="${JAVA_HOME:-/opt/jdk/current}"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/30.0.16248370}"
export PATH="${GRADLE_HOME:-/opt/gradle/gradle-9.9.1}/bin:$JAVA_HOME/bin:${GOROOT:-/usr/local/go}/bin:$HOME/go/bin:$PATH"

VN=$(grep -E 'versionName[[:space:]]*=' "$W/android/app/build.gradle.kts" | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
if [[ -z "$VN" ]]; then echo "cannot read versionName" >&2; exit 1; fi

echo "==> [0/6] 私有包: 校验 + 生成 codegen 输入"
# A failed build must leave no APK behind.
rm -f "$P"/out/Arc*.apk
python3 "$W/tools/private.py" check
python3 "$W/tools/private.py" emit
python3 "$W/tools/private.py" test

echo "==> [1/6] 规则库: 拉取上游最新 (临时目录, 用完即删)"
# Rule data lives only for this build: outside the repo, removed on any exit.
RULES=$(mktemp -d "${TMPDIR:-/tmp}/arc-rules.XXXXXX")
trap 'rm -rf -- "$RULES"' EXIT
trap 'exit 1' INT TERM HUP
python3 "$W/tools/fetch_rules.py" "$RULES"

cd "$W/core"
echo "==> [2/6] codegen: 规则库 + 私有规则 -> 节点表 (私有 out/) + 路由表"
go run ./cmd/codegen "$RULES" "$P/out/codegen-input.json" "$P/out/nodes.json"
mkdir -p "$ASSETS"
install -m 600 "$P/out/nodes.json" "$ASSETS/nodes.json"

echo "==> [3/6] 自检: 公开测试 (合成节点表) + 私有测试 (真实节点表, overlay); 路由表均为本次生成"
export ARC_RULES="$RULES"
go vet "${PKGS[@]}"
go test -count=1 "${PKGS[@]}"
ARC_NODES="$P/out/nodes.json" go vet -overlay "$P/out/overlay.json" "${PKGS[@]}"
ARC_NODES="$P/out/nodes.json" go test -count=1 -overlay "$P/out/overlay.json" "${PKGS[@]}"
unset ARC_RULES
rm -rf -- "$RULES"

echo "==> [4/6] 编译 libarc.so (c-shared, arm64; 不带 overlay)"
mkdir -p "$JNI"
CGO_ENABLED=1 GOOS=android GOARCH=arm64 \
  CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android37-clang" \
  CGO_CFLAGS="-Os -ffunction-sections" \
  CGO_LDFLAGS="-Os -ffunction-sections -Wl,--gc-sections -s -Wl,-z,max-page-size=16384" \
  go build -buildmode=c-shared -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o "$JNI/libarc.so" ./mobile
rm -f "$JNI/libarc.h"

cd "$W/android"

echo "==> [5/6] gradle testDebugUnitTest assembleRelease"
gradle testDebugUnitTest assembleRelease --quiet
APK_SRC="app/build/outputs/apk/release/app-release.apk"
echo "==> [6/6] 复制 APK (私有 out/; APK 内含节点表, 不进公开仓库)"
install -m 600 "$APK_SRC" "$P/out/Arc-${VN}.apk"
OUTS=("$P/out/Arc-${VN}.apk")
if [[ -d /workspace ]]; then
  rm -f /workspace/Arc-*.apk
  install -m 600 "$APK_SRC" /workspace/Arc.apk
  OUTS+=(/workspace/Arc.apk)
fi
rm -f "$W"/Arc.apk "$W"/Arc-*.apk
# update_pins.py keeps the replaced JDK until a release build has passed on the new one
PRUNE="$W/tools/.jdk_prune"
if [[ -f "$PRUNE" ]]; then
  old=$(<"$PRUNE")
  if [[ -n "$old" && "$old" != "$(readlink -f "$JAVA_HOME")" && "$old" == "$HOME"/jdk/* ]]; then
    rm -rf -- "$old"
    echo "removed old JDK $old"
  fi
  rm -f "$PRUNE"
fi
ls -lh "${OUTS[@]}"
