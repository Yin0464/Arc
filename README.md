# Arc

Arc（`com.arc.app`）是 Android 代理客户端：Kotlin / Compose 界面 + Go 内核（`libarc.so`）。内核在 TUN 上用自研用户态协议栈 `ustack` 终结 TCP，出站协议为 Trojan 和 AnyTLS，按内置的「国外 ∪ 中国」路由表分流。当前版本 16.2 / vc162。

本仓库只含通用代码。节点来源（订阅地址、账号、拉取逻辑、提取规则）、订阅、登录态、签名密钥和生成的节点表都在仓库之外的私有包里。规则库数据、路由表和 `libarc.so` 也不入库，每次构建时现拉现生成。

许可证：[MIT](LICENSE)。私有包不在本仓库，也不受这份许可证约束。

## 1. 产品参数

| 项 | 值 |
|---|---|
| applicationId | `com.arc.app` |
| versionName / versionCode | 以 `android/app/build.gradle.kts` 为准 |
| ABI | `arm64-v8a` |
| SDK | minSdk 37 / targetSdk 37 / compileSdk 37.2 |
| 构建变体 | 单一 release；R8 minify + shrinkResources；`localeFilters=["zh"]` |
| 节点分区 | 香港 / 日本 / 台湾 / 新加坡 / 其他（顺序固定） |
| 产物 | `$ARC_PRIVATE/out/Arc-<versionName>.apk` |

## 2. 目录结构

```
arc/
├── README.md  LICENSE
├── build.sh                 # 正式构建（~/build.sh 是指向它的软链接）
├── update.sh                # 更新工具链锁定和订阅（~/update.sh 同上）
├── android/                 # Gradle 工程，无 Wrapper，用本机 Gradle
│   └── app/src/
│       ├── main/java/com/arc/app/   # 界面、AppState、ArcVpnService、磁贴、通知、底层网、JNI 入口 Native.kt
│       └── test/java/com/arc/app/   # JVM 单测：CatalogTest、NodeStoreTest、VpnNotificationTest
├── core/                    # Go 模块 arc/core
│   ├── mobile/              # JNI 桥（bridge.go/bridge.c，android）；host_stub.go（其他平台）
│   ├── cmd/codegen/         # 规则库 + 私有包输入 → 路由表、节点表
│   │   └── testdata/        # rules/：规则库摘录夹具；synthetic/：合成订阅
│   ├── internal/
│   │   ├── engine/          # 编排；tun、ustack、udpnat、sniff
│   │   ├── dns/ dnswire/    # DNS 引擎、报文与明文查询
│   │   ├── router/          # 路由匹配与学习表；dom/ip4/ip6.bin 为构建产物
│   │   ├── outbound/        # anytls、trojan、DoH、自愈、端点缓存
│   │   ├── store/           # 节点目录 Catalog；testdata/nodes.json 为合成节点表
│   │   └── protect/         # 出站 socket 保护
│   └── *_test.go            # 内核整体校验
└── tools/
    ├── private.py           # 私有包加载、校验、生成、泄漏检查
    ├── fetch_rules.py       # 拉取规则库
    ├── update_subs.py       # 订阅更新编排（调用私有包里的来源模块）
    ├── update_pins.py       # 工具链与依赖版本锁定
    ├── common.py            # 日志、重试下载、原子写、订阅覆盖保护
    ├── test_tools.py        # 脚本离线测试
    └── hooks/               # pre-commit、commit-msg、pre-push
```

`.gitignore` 排除 Gradle 与 `build/` 目录、`.cxx/`、`.kotlin/`、IDE 文件、`__pycache__`、`*.log`、APK、`tools/.pin_env`、`tools/.jdk_prune`、构建产物（`core/internal/router/*.bin`、`android/app/src/main/jniLibs/`），并兜底排除 `/subs/`、`*.jks`、`*.keystore`、`keystore.properties`。

## 3. 架构

```
界面 / 磁贴 → AppState → ArcVpnService → JNI（Native ↔ core/mobile）→ Go 内核
```

- **Android 侧**：进程启动时 `AppState` 在 `arc-init` 线程加载 `libarc.so`、节点表和 DataStore 偏好。`ArcVpnService` 建立 TUN（MTU 1420，`172.19.0.1/30`、`fdfe:dcba:9876::1/126`，DNS `172.19.0.2`、`fdfe:dcba:9876::2`，v4/v6 默认路由），把 fd 交给 Go；出站 socket 先 `protect` 再绑定到 `UnderlyingNetworks` 选出的底层网。`NetChangePolicy` 把网络事件分为硬切网和软切网通知内核；核心意外退出时自动重连。
- **Go 内核**：`engine` 读 TUN，TCP 由 `ustack` 终结，UDP 经 `udpnat`；`router` 按路由表和学习表决定直连、局域网或代理；`outbound` 经所选节点用 Trojan 或 AnyTLS 出站。
- **路由**：域名先查路由表（foreign → 代理，cn → 直连），再查学习表；都未命中时经节点向 `https://dns.google/dns-query` 预检，按应答 IP 是否落在 CN 段学成直连或代理。代理域名回 FakeIP（`198.18.0.0/16`、`fdfe:dcba:9876:00ff::/112`），由节点在远端解析。纯 IP 目标：局域网 → LAN，Google 段 → 代理，CN 段或直连学习表 → 直连，其余 → 代理。
- **DNS**：直连域名用国内 DoH（`dns.alidns.com`、`doh.pub`），其主机名由明文引导 DNS（`223.5.5.5`、`119.29.29.29`）解析；节点端点只用所属协议的私有 DoH 解析。不回退到系统 DNS。
- **资源**：不设人为的性能限制或限流，只保留保证正确性的超时和防泄漏、防畸形输入的上限。

运行参数（超时、缓存上限、TCP 参数等）以代码为准。

## 4. 规则库与路由表

`tools/fetch_rules.py OUTDIR` 拉取上游最新数据，不锁定版本、不缓存：

| 文件 | 上游 |
|---|---|
| `accelerated-domains.china.conf` | felixonmars/dnsmasq-china-list |
| `geoip_cn.txt`、`geoip_google.txt` | Loyalsoldier/geoip |
| `operator_china.txt`、`operator_china6.txt` | gaoyifan/china-operator-ip |
| `loyalsoldier_geosite.dat` | Loyalsoldier/v2ray-rules-dat |
| `v2fly_*` | v2fly/domain-list-community `master` 的 tarball，从 `google`、`geolocation-cn`、`geolocation-!cn` 递归解析 includes；`geolocation-!cn` 另写成扁平列表 |

7 个下载并行，失败重试，逐项校验下限以挡住截断或错误页，打印每个输入的 sha256 和 v2fly 提交号；任一失败退出码为 1。

codegen 不联网，只读给定目录，生成：

- `core/internal/router/dom.bin`：域名表（DAT3 格式），foreign 优先于 cn；
- `core/internal/router/ip4.bin`、`ip6.bin`：Google、CN（含 china-operator）IP 段表。

三张表经 `//go:embed` 编进 `libarc.so`。

## 5. 私有包接口

位置为 `$ARC_PRIVATE`，默认 `~/arc-private`，必须在本仓库之外。目录 0700、文件 0600，`private.py check` 校验权限、属主、符号链接、schema 和必填项。

```
$ARC_PRIVATE/
├── bundle.toml            # schema_version、[build] keys_dir、[[providers]]（id、module、proto、require_type、secrets）
├── secrets.toml           # [providers.<id>] 各来源的口令与地址
├── providers/<id>/        # 来源模块 fetch.py：REQUIRED_SECRETS、run(ctx, argv)；tests/ 为其离线测试
├── rules/catalog.toml     # 节点提取规则：类型、名字规则、地区别名、命名模板
├── rules/expected-counts.json  # 可选：私有测试核对的各区节点数
├── state/<id>/            # 来源模块的登录态与设备标识
├── subs/<id>.yaml         # 订阅
├── keys/                  # arc-release.jks、keystore.properties
├── tests/go/              # 需真实节点表的 Go 测试，经 go -overlay 注入
├── leak-denylist.txt      # 泄漏检查的额外禁用词
├── docs/                  # 私有说明
└── out/                   # 生成物：codegen-input.json、overlay.json、nodes.json、APK
```

```bash
python3 ~/arc/tools/private.py check               # 校验
python3 ~/arc/tools/private.py emit                # 写 out/codegen-input.json、out/overlay.json
python3 ~/arc/tools/private.py test                # 运行各来源模块的测试
python3 ~/arc/tools/private.py init                # 新建空包和签名密钥，并启用 git 钩子
python3 ~/arc/tools/private.py fix-modes           # git clone 后把权限收紧到 700/600
python3 ~/arc/tools/private.py set-secret ID KEY   # 从 stdin 读一个值写入 secrets.toml
python3 ~/arc/tools/private.py export-template DIR # 复制可分享部分（不含 secrets、state、subs、keys、out、expected-counts.json、docs/README-*.md）
```

codegen 不认识具体来源，只执行 `out/codegen-input.json` 里的规则；提取逻辑见 `core/cmd/codegen/nodes.go`。节点表为 schema 3 的 JSON，未知字段拒绝。`update_subs.py` 按 `bundle.toml` 顺序调用各来源模块（`update_subs.py ID 参数…` 只跑一个）；写订阅时若旧文件有 `require_type` 类型的代理而新正文没有，则不覆盖并返回 1。

## 6. 工具链

| 项 | 版本 |
|---|---|
| JDK | 27.0.1.0.2（Temurin） |
| Gradle | 9.9.1 |
| AGP | 9.6.0-alpha04 |
| Kotlin | 2.5.0-RC |
| compose-bom-beta | 2026.11.00 |
| activity-compose | 1.13.0 |
| lifecycle-runtime-compose | 2.11.0 |
| DataStore Preferences | 1.3.0 |
| kotlinx-coroutines-android | 1.11.0 |
| JUnit | 4.13.2 |
| org.json | 20260814 |
| Go | 1.27.4 |
| NDK | 30.0.16248370 |
| compileSdk / build-tools | 37.2 / 37.0.0 |

| 项 | 路径 |
|---|---|
| JDK | `/home/box/jdk/jdk-27.0.1.0.2+1`，软链接 `/opt/jdk/current` |
| Gradle | `/opt/gradle/gradle-9.9.1` |
| Go | `/usr/local/go`；`~/go/bin`（goimports、staticcheck、deadcode） |
| Android SDK / NDK | `~/android-sdk`、`~/android-sdk/ndk/30.0.16248370` |

`build.sh` 读取 `tools/.pin_env`（若存在），否则用脚本内的默认路径。Gradle 依赖和 Go 模块按需从网络下载，缓存可以随时清理。

`update_pins.py` 把各项升到当前通道上最新的可用版本并改写 Gradle 文件、`build.sh`、本 README 和 `core/go.mod` 中的锁定；找不到应有的锁定字符串就整体失败、不写任何文件。规则：不改 minSdk；跳过 canary、nightly、snapshot；稳定版 AndroidX 只升稳定版；AGP、Kotlin、compose-bom-beta 留在现有预发布通道；JDK 跟随 Temurin 最新 GA（含大版本，旧 JDK 在下一次构建成功后删除）；compileSdk 只升同一大版本的小版本。

## 7. 构建

```bash
~/build.sh
```

需要联网。`ARC_DIR`（默认 `~/arc`）、`ARC_PRIVATE`（默认 `~/arc-private`）、`ANDROID_HOME`（默认 `~/android-sdk`）可覆盖。任一步失败即中止，开始时先删除 `out/` 里的旧 APK。

0. 私有包：`private.py check`、`emit`、`test`。
1. 规则库：`mktemp -d` 建临时目录，`fetch_rules.py` 拉取上游最新；`trap` 保证任何方式退出都删除该目录。
2. codegen：生成 `out/nodes.json` 和三张路由表，节点表复制到 `android/app/build/generated/arc/assets/`。
3. 自检：`go vet` + `go test -count=1`（`./internal/... ./cmd/... .`）跑两遍，`ARC_RULES` 指向临时规则库；第一遍用合成节点表，第二遍用 `ARC_NODES=out/nodes.json` 和 `-overlay out/overlay.json`。随后删除规则库。
4. `libarc.so`：NDK `aarch64-linux-android37-clang`，c-shared，`-trimpath -buildvcs=false -ldflags="-s -w -buildid="`，不带 overlay。
5. `gradle testDebugUnitTest assembleRelease`；签名读 `$ARC_KEYS`（默认 `$ARC_PRIVATE/keys`）。
6. APK 写到 `out/Arc-<versionName>.apk`；`/workspace` 存在时另复制为 `/workspace/Arc.apk`。

规则库每次取上游最新，所以不同日期构建的 APK 不保证相同；构建日志里的 sha256 和 v2fly 提交号记录了所用数据。输入完全相同时（源码、规则库、私有包、工具链、签名密钥）构建结果逐字节一致。

## 8. 测试

新克隆的仓库不需要私有包、不联网即可运行全部公开测试。路由表不入库，先用夹具生成：

```bash
cd ~/arc/core && go run ./cmd/codegen -fixture
ARC_RULES=$PWD/cmd/codegen/testdata/rules go test ./internal/... ./cmd/... .
```

`ARC_RULES` 必须指向生成当前路由表的规则库目录；未设置时，规则库与路由表的等价性测试跳过。

```bash
# 用真实节点表和私有测试（需先由 build.sh 或 codegen 生成真实路由表与 out/）
cd ~/arc/core && ARC_NODES=$HOME/arc-private/out/nodes.json go test -count=1 -overlay $HOME/arc-private/out/overlay.json ./internal/... ./cmd/... .

# 改了 codegen 或合成订阅后更新合成节点表（审阅 diff 后提交）
cd ~/arc/core && ARC_UPDATE_GOLDEN=1 go test -run Synthetic ./cmd/codegen

# 静态检查（可选）
cd ~/arc/core && go vet ./internal/... ./cmd/... . && staticcheck ./internal/... ./cmd/... .

# Android JVM 单测（不需要 libarc.so 和签名）
cd ~/arc/android && gradle testDebugUnitTest

# 脚本离线测试
python3 ~/arc/tools/test_tools.py
```

## 9. 更新

```bash
~/update.sh    # 依次运行 tools/update_pins.py、tools/update_subs.py，任一步失败即中止
```

两个脚本也可单独运行。规则库不在这里更新。

以下任一项变化时升版并重新构建：版本锁定、路由表（与上一版不同）、订阅中的节点或 DNS 内容、会打进 APK 的代码。版本号以 `android/app/build.gradle.kts` 为准：`versionName` 次版本号到 9 后进位（`x.9` → `(x+1).0`），`versionCode` 每次加 1。

## 10. 泄漏检查与提交

`tools/private.py leakcheck` 用私有包中的全部私有值（及其编码形式）、`leak-denylist.txt` 和通用规则（真实 UUID、私钥、keystore、密钥类文件、带真实端点的节点表、构建产物路径）扫描，命中时只报告位置和规则类别，不打印值。

| 选项 | 范围 |
|---|---|
| `--staged` | 暂存区（pre-commit 钩子） |
| `--msg FILE` | 提交说明（commit-msg 钩子） |
| `--tree` | HEAD 的整棵树 |
| `--history` | HEAD 可达的所有提交 |
| `--pre-push` | 将推送的提交（pre-push 钩子） |
| `--public-only` | 无私有包时只跑通用规则（或设 `ARC_LEAKCHECK_PUBLIC_ONLY=1`） |

钩子通过 `git config core.hooksPath tools/hooks` 启用（`private.py init` 会设置；新克隆需手动执行一次）。

`main` 只有一个 orphan 提交，说明为 `Arc X.Y / vcN`，作者为 `Arc <arc@local>`。本仓库不提交 APK、节点表、订阅或密钥。

```bash
cd ~/arc
git checkout --orphan rel
git add -A
git status --short                          # 确认没有构建产物或私有文件
python3 tools/private.py leakcheck --staged
git -c user.name=Arc -c user.email=arc@local commit -q -m "Arc X.Y / vcN"
git branch -D main && git branch -m main
git push --force origin main                # pre-push 钩子再检查一次
```
