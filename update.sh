#!/usr/bin/env bash

set -euo pipefail
trap 'echo "update.sh: failed at line $LINENO: $BASH_COMMAND" >&2' ERR
W="${ARC_DIR:-$HOME/arc}"

echo "==> [1/2] 版本锁定"
"$W/tools/update_pins.py"

echo "==> [2/2] 订阅更新 (私有包里的各个来源)"
"$W/tools/update_subs.py"
