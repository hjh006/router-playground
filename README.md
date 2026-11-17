# 路由器玩法 · Router Playground

<img src="plugin/overlay/shadowsocks/res/icon-shadowsocks.png" width="64" alt="Router Playground icon">

Netgear R7000 / Merlin 380 的 AnyTLS 增强：设备自身 TUN 旁路、UU 游戏加速与视频代理共存、可配置连接参数，以及 Google / YouTube / Telegram HTTPS 状态面板。

当前源码版本：**4.38.3-r7000.5**，包含自动故障切换、UU 动态规则兼容、HTTPS 节点解析和可选域名广告过滤。**GitHub Releases 安装包仍为 4.38.3-r7000.3，完整包为 4.38.3-r7000.3-full.1**，不包含 r4/r5 新增功能；使用这些功能需按第 2 节从当前源码构建。

**Android 1.4.0 与路由端入口 TCP 测速组件：**[版本、源码和校验文件](https://github.com/hjh006/router-playground/releases/tag/android-v1.4.0) · [路由端独立更新包 latency.tar.gz](https://github.com/hjh006/router-playground/releases/download/android-v1.4.0/latency.tar.gz)。该更新包仅用于已安装兼容增强 r5 的 R7000，不能用于首次安装；在软件中心“离线安装”上传 `latency.tar.gz`，只增加四个测速运行文件，不重装插件或改网络配置。它不包含上游完整插件或 AnyTLS 内核。

**首次安装可直接下载完整离线包，一次上传，无需先装原版 4.38.3，也无需编译：**

- [完整离线包 shadowsocks.tar.gz](https://github.com/hjh006/router-playground/releases/download/v4.38.3-r7000.3-full.1/shadowsocks.tar.gz)
- [SHA256SUMS 校验文件](https://github.com/hjh006/router-playground/releases/download/v4.38.3-r7000.3-full.1/SHA256SUMS)
- [完整包版本说明](https://github.com/hjh006/router-playground/releases/tag/v4.38.3-r7000.3-full.1)

完整包适用于下述 R7000 / Koolshare Merlin 380 环境，不是路由器固件，也不是所有路由器通用包。新安装会装好运行依赖、网页和增强组件，保持代理关闭；之后只需填入自己的节点再启用。已有匹配 4.38.3 的设备会转入增强更新流程，保留原有配置；其他插件版本会拒绝覆盖。

这是首个完整包预发布版：首次安装入口已通过沙箱验证，尚未在独立空白 R7000 上完成首装实机验收；其中 AnyTLS 运行增强组件此前已在 R7000 实机使用验证。

已有 4.38.3 的用户也可选[体积更小的旧增量包](https://github.com/hjh006/router-playground/releases/tag/v4.38.3-r7000.3)。GitHub 的 Code → Download ZIP 是源码，不是安装包。第三方内容范围见[来源说明](THIRD_PARTY_NOTICES.md)。

## Android App：自用路由线路

<img src="android/res/drawable-nodpi/ic_launcher_imagegen.png" width="72" alt="自用路由线路 App 图标">

[下载 Android 1.4.0 APK](https://github.com/hjh006/router-playground/releases/download/android-v1.4.0/router-control-1.4.0.apk) · [两端源码与校验文件](https://github.com/hjh006/router-playground/releases/tag/android-v1.4.0) · [构建与使用说明](android/README.md)

用手机连接已经配置好的 R7000，读取并切换已有 AnyTLS 线路。支持国家/地区和国旗分组、双列线路卡片，以及由路由器逐条测量的节点入口 TCP 延迟；当前线路的 HTTPS 健康检测单独显示。App 使用 Android 原生界面，需要 Android 8.0 或更新版本。

`android/` 当前版本为 1.4.0，支持 r5 的直连/代理、设备分流、自动故障切换、广告过滤和连接设置，并内置原插件完整面板。入口 TCP 延迟取 3 次成功建连的中位数，单次最多 5 秒、每条任务预算 25 秒；它只说明入口建连耗时，不能代替线路或出口可用性。无法确认路径未被透明代理截获时显示“路径待确认”，不显示毫秒数。该功能需要同版本入口 TCP 仅测速组件及 `router_tcp / entry / ram_mailbox_v1` 协议；适用范围及手机实测说明见 [Android 文档](android/README.md)。

管理地址、账号和线路来自使用者自己的路由器；公开源码和 APK 不附带账号、节点、MAC、服务商 Hosts 或签名私钥。App 不创建手机 VPN，也不替代路由器插件安装包。切换保留现有 UU、旁路、DNS 和自动更新设置；检测数据代表短期采样，活动游戏流量需在自己的环境验收。

## 阅读顺序

1. [确认设备与准备材料](#1-确认设备与准备材料)
2. [在电脑上构建增强包](#2-在电脑上构建增强包)
3. [在路由器上安装](#3-在路由器上安装)
4. [配置 AnyTLS 节点并启用](#4-配置-anytls-节点并启用)
5. [配置本机 TUN 共存](#5-配置本机-tun-共存)
6. [配置 PS5 / UU 共存](#6-配置-ps5--uu-共存)
7. [看懂检测面板与验收](#7-看懂检测面板与验收)
8. [常见问题与恢复](#8-常见问题与恢复)
9. [用 Android App 切换线路](android/README.md)

普通用户阅读第 1 节后，下载完整包 Releases 的 `shadowsocks.tar.gz`，从第 3 节开始；想自行编译或修改源码的用户再阅读第 2 节。通用包不含节点、订阅或个人设备配置，升级会保留安装者自己的现有配置。

## 1. 确认设备与准备材料

### 路由器要求

| 项目 | 本项目实际验证的环境 |
| --- | --- |
| 路由器 | Netgear R7000 |
| 固件 | 含 Koolshare 软件中心的 Merlin `380.70_0-X7.9.1` |
| 内核 / 架构 | Linux `2.6.36.4` / `armv7l` |
| 首次安装 | 无需预装插件；完整包内含匹配的 4.38.3 运行文件与增强组件 |
| 已有插件 | 支持匹配的 cary-sas Fancyss 4.38.3；其他版本先按上游方法迁移 |
| 共存设备网络 | 主 LAN `br0` 下的 IPv4 设备 |

本项目不是路由器固件，也不是 OpenWrt、原厂 R7000 固件或 Merlin 386/388 的通用插件。没有软件中心的设备，需要先自行准备匹配固件；本文不包含刷机教程。上游列出的其他机型不代表本增强版已逐一实测。

### 需要准备

- 普通安装只需一台能登录路由器管理页、下载并上传安装包的电脑和浏览器，不需要编译工具链。
- 自己的 AnyTLS 地址、端口、密码、SNI 和证书要求；服务商有节点 Hosts 映射时也一并准备。
- 路由器管理权限，使用自己的 LAN 网关地址登录，本文不固定管理 IP。
- 需要 UU 共存时，准备路由器上能正常工作的 UU 后台插件，以及目标设备当前接口的 MAC。

只有自行构建才需要 macOS / Linux 终端（Windows 可用 WSL2）、Python 3.8+、Git、`patch`、curl 和 Go 1.23.12；Node.js 仅用于可选界面测试。编译在电脑上进行，不在路由器上进行。

先备份现有节点配置、访问控制和路由器设置。本文不需要修改电脑自身的 VPN/TUN、全局 IPv6 或全局 DNS。

## 2. 在电脑上构建增强包

命令按顺序执行。每个代码块结束时都会回到本仓库根目录；某步报错时先解决该步，不继续安装。

### 2.1 下载本仓库，确认工具链

```sh
git clone https://github.com/hjh006/router-playground.git
cd router-playground
python3 --version
git --version
patch --version
go version
```

`go version` 应显示 `go1.23.12`。可从 [Go 官方下载页](https://go.dev/dl/)的历史版本取得对应电脑系统的工具链，并放入当前终端的 PATH。本项目固定该版本以适配旧内核，参见 [Go 1.23 Linux 支持说明](https://go.dev/doc/go1.23#linux)。后续使用 `GOTOOLCHAIN=local`，避免自动换用其他版本。

若已通过 GitHub Desktop 克隆仓库，在该仓库目录打开终端，跳过重复的 `git clone`。

### 2.2 取得原版 4.38.3 和 CA bundle

```sh
mkdir -p downloads
curl -fL https://github.com/cary-sas/v2ray_bin/releases/download/v4.38.3/shadowsocks.tar.gz \
  -o downloads/shadowsocks.tar.gz
curl -fL https://curl.se/ca/cacert.pem -o downloads/cacert.pem
```

第一个文件来自[上游 v4.38.3 发布页](https://github.com/cary-sas/v2ray_bin/releases/tag/v4.38.3)的 **Assets → shadowsocks.tar.gz**，不是自动生成的 Source code 压缩包。第二个来自 [curl CA Extract / Mozilla](https://curl.se/docs/caextract.html)，用于 HTTPS 证书校验；保留它的原始文件头与许可说明。

下载失败时，可从上述官方页面手动取得文件，放到相同位置。不要通过关闭 TLS 校验绕过下载错误。原版包必须匹配这个 SHA256，准备脚本会强制检查：

```text
05a30314c8c6d8f33ae9c027b42927e9d17e6e648c75ac7b419282fe5c1c2adf
```

CA bundle 可使用 curl 官方当前版本；`provenance.json` 的 CA 哈希只记录先前验收快照，不要求以后下载的官方 CA 永远与它相同。

### 2.3 编译 AnyTLS 客户端

```sh
mkdir -p build-client
git clone https://github.com/cary-sas/anytls-go-add-nat.git build-client/anytls
git -C build-client/anytls checkout 1a08fcf52fa56c0c1531a76839cd81cd1757dd4c
git -C build-client/anytls apply ../../patches/anytls-r7000.3.patch
cp client/overlay/cmd/client/reuse_test.go build-client/anytls/cmd/client/
cd build-client/anytls
GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 go build \
  -trimpath -buildvcs=true \
  -ldflags='-s -w -X anytls/util.ProgramVersionName=anytls/0.0.13-r7000.3' \
  -o ../anytls-client-linux-armv5-r7000.3 ./cmd/client
cd ../..
```

生成：`build-client/anytls-client-linux-armv5-r7000.3`。它是路由器用的 ARM 二进制，不是在电脑上双击运行的程序。

### 2.4 编译旧固件运行工具

```sh
mkdir -p build-tools
cd runtime-tools
GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 go build \
  -trimpath -ldflags='-s -w' -o ../build-tools/ss-flock-linux-armv5 ./cmd/ss-flock
cd ..
```

再编译采用现代 TLS 的 HTTPS 探测器：

```sh
cd runtime-tools
GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 go build \
  -trimpath -ldflags='-s -w' -o ../build-tools/ss-https-probe-linux-armv5 ./cmd/ss-https-probe
cd ..
```

再编译独立的入口 TCP 探测器：

```sh
cd runtime-tools
GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 go build \
  -trimpath -ldflags='-s -w' -o ../build-tools/ss-tcp-probe-linux-armv5 ./cmd/ss-tcp-probe
cd ..
```

这三个专用工具提供锁、临时文件、权限检查、经过证书验证的 HTTPS 探测及入口 TCP 建连测量，安装时不覆盖系统工具。TCP 工具先只读核验路由器 OUTPUT 路径，再对已解析的入口地址测三次建连；无法确认未被代理截获时返回 `path_unverified`，不提供毫秒值，也不修改规则。

### 2.5 生成增强包

```sh
python3 scripts/prepare.py \
  --base downloads/shadowsocks.tar.gz \
  --anytls-binary build-client/anytls-client-linux-armv5-r7000.3 \
  --flock-binary build-tools/ss-flock-linux-armv5 \
  --https-probe-binary build-tools/ss-https-probe-linux-armv5 \
  --tcp-probe-binary build-tools/ss-tcp-probe-linux-armv5 \
  --ca-bundle downloads/cacert.pem
python3 build/r7000-enhanced/build-enhancement.py
```

最终生成：**`build/r7000-update-generic/shadowsocks.tar.gz`**。

当前增量清单包含 24 个固定文件；独立测速组件清单只包含 TCP 工具、启动脚本、测量脚本和能力声明四个文件。两者的构建器和安装器会核对各自清单。

| 文件 | 用途 |
| --- | --- |
| `downloads/shadowsocks.tar.gz` | 上游原版包，用于尚未安装基线的设备 |
| `build/r7000-update-generic/shadowsocks.tar.gz` | 增强增量包，要求设备已安装 4.38.3 |

两个文件名字相同、用途不同，上传时核对所在目录。准备脚本只在本地展开、应用补丁和复制输入，不联网、不运行输入二进制，也不部署路由器。

默认 `build/` 已存在时会拒绝覆盖。重新准备可选新目录，例如 `--dest build/retry`，然后运行脚本打印出的构建命令；产物会放在该目标目录的 `r7000-update-generic/` 下。无需删除自己的旧产物或配置。

### 2.6 自行构建完整包（可选）

普通下载用户跳过此节。完整包使用第 2.5 节准备好的工作树，并需要四份来源 / 许可材料；这些文件只用于随包附带说明，不涉及设备配置。

```sh
mkdir -p downloads/full-notices
cp LICENSE THIRD_PARTY_NOTICES.md downloads/full-notices/
curl -fL https://github.com/hjh006/router-playground/releases/download/v4.38.3-r7000.3/MPL-2.0.txt \
  -o downloads/full-notices/MPL-2.0.txt
curl -fL https://github.com/hjh006/router-playground/releases/download/v4.38.3-r7000.3/third-party-licenses.tar.gz \
  -o downloads/full-notices/third-party-licenses.tar.gz
python3 build/r7000-enhanced/build-full.py --notices downloads/full-notices
```

生成：`build/r7000-full-generic/shadowsocks.tar.gz`。如果准备工作树使用了其他 `--dest`，按实际目录调整 `build-full.py` 路径。完整包只从校验过的原版包和公开增强代码生成，不从运行中的路由器导出文件、节点或 DBus 配置。

## 3. 在路由器上安装

### 3.1 区分当前状态

| 当前设备状态 | 下载和操作 |
| --- | --- |
| 已有兼容固件和软件中心，尚未装科学上网插件 | 下载上方完整包，一次上传即可；不需要先安装原版 |
| 已安装匹配的 cary-sas 4.38.3 / 增强 r3 | 完整包会使用增强更新器；也可继续用旧增量包 |
| 已有其他版本 / 分支、残留不完整安装或其他固件 | 完整包会拒绝直接覆盖，先备份并按相应上游方法迁移或恢复 |

首次安装不调用原版清理脚本，不启停 UU，不修改共享 DNS 钩子；只安装清单中的文件、建立必要链接和注册软件中心。新安装的代理保持关闭，两组 MAC 与 Hosts 为空，规则 / 订阅自动更新关闭，不创建示例节点。安装器记录可能覆盖的共享文件与设置，并为失败回滚保留私有备份。

完整包在已有 4.38.3 上走原有安全增强更新器，不重新铺装全部基线文件；它保留已有启用状态和配置，自动更新选项仍需按第 4 节核对。

### 3.2 上传安装包

下载后，在安装包所在文件夹运行对应的校验命令，将输出与 `SHA256SUMS` 中 `shadowsocks.tar.gz` 那行比对：

| 电脑系统 | 校验命令 |
| --- | --- |
| macOS | `shasum -a 256 shadowsocks.tar.gz` |
| Linux | `sha256sum shadowsocks.tar.gz` |
| Windows PowerShell | `Get-FileHash .\shadowsocks.tar.gz -Algorithm SHA256` |

哈希一致后再安装；依赖许可证与第三方来源说明附在同一版本的 Releases 资产中。

1. 电脑保持连接该路由器的局域网，登录路由器管理页。
2. 打开 **软件中心 → 离线安装**。
3. 选择从 **完整包 Releases** 下载的 **`shadowsocks.tar.gz`**，点 **上传并安装**。自行构建完整包的用户选择 `build/r7000-full-generic/shadowsocks.tar.gz`。保持文件名，不解压后逐个上传；不要选择 GitHub 自动生成的 Source code 包。
4. 等日志结束：首次安装确认出现 `Full installation completed (proxy disabled)`；已有 4.38.3 的增强更新确认 `Enhancement installed`。记录打印的私有备份目录。
5. 返回科学上网插件并刷新；缓存旧资源时强制刷新或重新登录后再查看。
6. 确认页头出现 **R7000 增强 r3**，能看到新的 HTTPS 面板和“访问控制”中的两组设备策略。

原插件版本数字仍可能显示 **4.38.3**，增强标记在页头。首次安装后代理关闭，需要添加自己的节点；已有 4.38.3 更新会保留原启用状态：之前关闭的不会自动开启，之前运行的会尝试用新入口恢复。设备名单按自己的情况配置。

日志没有成功标记时，先处理具体失败项，不要把“上传完成”当成“安装完成”，也不要连续重复安装。

## 4. 配置 AnyTLS 节点并启用

增强包不附带节点、订阅或默认可用账号。以下入口都在科学上网插件内。

### 4.1 添加节点：三种入口

**方式 A：手动填写，适合首次配置或复杂密码。**

1. 打开 **节点管理 → 添加节点 → 添加Trojan配置** 页签。上游复用了这个表单，名称里有 Trojan 不代表只能添加 Trojan。
2. 在协议下拉框选 **AnyTLS**，填写下表。
3. 点 **添加**。然后在 **账号设置** 选择该节点，点底部 **保存&应用**。

| 界面字段 | 填什么 |
| --- | --- |
| 节点别名 | 自己容易识别的名称，例如“香港-测试” |
| 使用模式 | 日常浏览可先选 gfwlist 模式，再按实际需求调整 |
| 服务器地址、端口 | 服务商的 AnyTLS 主机和端口，地址栏不加 `https://` |
| 密码 | AnyTLS 密码，不是网站登录密码或订阅地址 |
| `tls/xtls域名 (SNI)` | 服务商的 TLS 域名，可能与服务器地址不同 |
| 允许不安全 | 按服务商证书要求填写；正常可信证书保持关闭，不要把开启当作通用修复 |

**方式 B：导入 `anytls://` 节点链接。**

打开 **更新管理 → 通过 … anytls 链接添加服务器**，每行一个，点 **解析并保存为节点**。下面仅是格式示例，必须替换成自己的有效信息：

```text
anytls://REPLACE_WITH_PASSWORD@node.example.com:443?sni=tls.example.com#HK-Example
```

本版 URI 解析读取 `sni=` 和 `insecure=1/true`，不识别 `allowInsecure`、`skip-cert-verify` 等别名。密码含 `@`、`#`、`&` 等字符时建议用方式 A，避免简易解析拆错。导入后仍要核对服务器、密码、SNI 和证书选项。

**方式 C：使用服务商的兼容订阅。**

在 **更新管理 → 节点订阅设置 → 订阅地址管理** 填入返回 URI 节点列表的订阅地址，选择 **禁用订阅计划任务**，需要获取节点时点 **保存并订阅**。只点“仅保存设置”不会立即下载节点。列表可有 Base64 包装，但服务商必须实际提供兼容格式。

**完整 Clash / Mihomo YAML 不能直接导入。** 本版没有整份 YAML 的解析迁移功能，不会自动带入 `dns`、`proxy-groups`、`rules` 和 `hosts`。只有 YAML 时，按 AnyTLS 节点的 `server / port / password / sni` 手填；`skip-cert-verify` 对应证书选项，必要的节点 `hosts` 另按下一节填写。不要把整份 YAML 粘进订阅或链接框。

### 4.2 节点解析与服务商 Hosts

1. 打开 **全局设定 → 节点域名解析DNS服务器**，选在代理尚未启动时也能直连查询的 DNS。按自己的网络选择运营商 DNS、阿里 DNS、DNSpod 等，没有统一强制值。
2. 开发版 r4 的 AnyTLS 可选“自定义”，填写 `IPv4:端口` 或 HTTPS DNS URL；多个上游用逗号分隔，最多 4 个。示例 `192.0.2.53:5353,https://dns.example.test/custom-path` 仅说明格式，不能直接使用。上游从服务商完整配置中取得，不预置服务商目标或账户信息。DoH 使用公共 CA 校验证书，多上游共享查询总超时，失败才尝试下一项。
3. Clash 完整配置的 `proxy-server-nameserver` 若指向 `127.0.0.1` 等本地入口，不能原样作为路由器上游；应核对其实际 `dns.nameserver` 上游。不要只复制节点后继续使用被污染的公共解析器。此设置只负责节点启动解析，代理核心使用解析所得 IP 并保留原 SNI，不覆写设备或全局 DNS，也不改变 Mac TUN。
4. 如果服务商有节点 Hosts，展开 **全局设定 → AnyTLS 高级连接设置 → 服务商 Hosts 映射（节点解析）**，按下面格式逐行填入；没有要求则留空。

```text
node.example.com=connect.example.com
another-node.example.com=192.0.2.10
```

以上都是假地址，不能作为实际节点。每行是“原域名=目标域名或 IPv4”，最多 32 条；重复来源不能指向不同目标，不允许循环，映射链最多 4 跳。

Hosts 只改节点连接目标，**保留原节点 SNI**：手填 SNI 时以手填值为准，没填时使用原节点服务器名。它不等于 Clash DNS 覆写，不替换全局 DNS、规则组或设备自身 TUN。只复制节点而漏掉必需 Hosts，可能出现“手机能用、路由器启动失败”。

### 4.3 高级参数与更新设置

在 **全局设定 → AnyTLS 高级连接设置**可先使用以下起始值。它们是增强版缺省值，已有设置会保留；服务商有明确要求时以其要求为准。

| 参数 | 起始值 | 可选范围 / 说明 |
| --- | --- | --- |
| 最少空闲连接 | 0 | 0–20；0 减少常驻连接 |
| 空闲连接检查间隔 | 30 秒 | 5–300 秒 |
| 空闲连接回收时间 | 30 秒 | 5–600 秒 |
| 握手超时 | 8 秒 | 3–20 秒 |
| ALPN 协商协议 | `h2` | 支持 `h2`、`http/1.1` 及逗号组合；留空自动协商 |
| TLS 指纹 | Chrome | Chrome / 标准 TLS，在本高级设置中修改 |

再打开 **更新管理**，分别保存这两项：

1. 在规则更新区域关闭**规则自动更新**，点该区域的 **保存设置**。
2. 在节点订阅设置中选 **禁用订阅计划任务**，点 **仅保存设置**；需要立刻获取节点时用 **保存并订阅**。
3. 重新打开页面，确认两项都已关闭。

**完整包首次安装会关闭这两项；已有 4.38.3 的增强更新保留原设置，所以仍应重新打开页面核对。**

完整包首次安装会把旧在线更新入口改为离线更新提示；已有安装中的原版“检查并更新”仍可能覆盖增强文件。后续统一通过本项目 Releases 下载匹配的离线包更新。不要为了套用 Clash 教程，顺手改动电脑 TUN、全局 IPv6 或路由器 DNS 劫持。

### 4.4 启用与首次检查

1. 在 **账号设置** 选刚配置的 AnyTLS 节点，确认模式，**先将科学上网开关置为开启，再点保存&应用**，等待启动日志完成。首次只打开开关不会自动提交。
2. 等面板完成首轮 HTTPS 检测，核对当前节点名称。
3. 用一台**未开启自身 VPN、也不在旁路名单**的普通设备试开 Google、YouTube、Telegram。
4. 通过后再配置下面的 TUN、UU 设备。日常可优先测试香港等邻近区域，节点和优先地区由使用者配置；开发版 r4 可另外启用第 7 节的后台故障切换。

## 5. 配置本机 TUN 共存

适用场景：Mac / PC 已运行 Clash Verge、其他 VPN 或 TUN，希望它继续由自身客户端接管。

1. 保持电脑自己的 TUN/VPN 正常运行。
2. 在路由器客户端列表查到电脑**当前连接接口**的 MAC。
3. 打开插件 **访问控制 → 自带 VPN 设备旁路**，每行填一个 MAC。例如这个虚构值：

   ```text
   02:00:00:00:00:01
   ```

4. 点 **保存&应用**。该设备 TCP 和 DNS 保留原路径，交给自身 VPN 处理。
5. 检查电脑客户端仍显示 TUN 已开启，并实际打开需要的网站。路由器的绿色面板不能代替此检查。

**关掉本机 TUN 后想改用路由器代理：**从旁路框移除该 MAC，再点“保存&应用”。仍在名单里时，即使 TUN 已关，设备也不会自动回到路由器代理。

Wi-Fi 与网线通常有不同 MAC；“私有 / 随机 MAC”变化后也要更新。以路由器当前看到的值为准，不要照抄示例。

## 6. 配置 PS5 / UU 共存

目标是同一台 PS5 上：**联网游戏优先走路由器后台 UU，YouTube 等境外视频通过 AnyTLS。** 本功能配合已有 UU 使用，不负责安装、登录或购买 UU 服务。

1. 先在 UU 控制端确认路由器插件在运行、PS5 已识别，选择游戏后能正常加速。后台没有单独网页图标也可以，关键是实际控制状态。
2. PS5 开机并连到路由器主 LAN；在路由器客户端列表或 PS5 网络状态核对**当前有线 / Wi-Fi 接口**的 MAC。
3. 打开 **访问控制 → PS5 / UU 共存设备**，填 MAC，其他 TCP 策略按 DNS 路径选择：UU 接管设备 DNS 时选 **境外 TCP 代理**；由路由器 DNS 产生规则 IP 集合时可选 **规则分流（gfwlist）**。设置后 **保存&应用**。**不要把同一台 PS5 同时放入“自带 VPN 设备旁路”。**
4. 在 PS5 打开 YouTube 实播一段视频，再在 UU 选常玩的游戏，进游戏检查 UU 状态、登录和联机。
5. UU 启动、切游戏或重建规则后，后台按可配置检查间隔核对变化（开发版 r4 默认 5 秒，可设 2–30 秒）；再分别复查视频与游戏，无需反复重启 UU。

两组 MAC 名单各最多 32 个，支持每行一个或逗号分隔，互斥。同一设备只选一种策略。

### 流量怎样走

| 设备 / 流量 | 处理方式 |
| --- | --- |
| TUN 旁路名单中的电脑 | 保留 TCP / DNS 原路径，由本机 VPN/TUN 处理 |
| UU 设备命中已有 UU DNAT / 动态游戏目标的 IPv4 TCP | UU 路径优先，避开路由器代理 |
| UU 设备其余 IPv4 TCP（默认规则分流） | 命中代理规则走 AnyTLS，如 YouTube；其余走原网络，包括未命中规则的 PSN 服务 |
| UU 设备的 UDP | UU 或原网络，不由 AnyTLS 透明代理接管 |
| 未列入两组名单的普通设备 | 按插件主模式及原访问控制处理 |

**开发版 r4 的“其他 TCP 流量策略”可选：规则分流（默认）、境外 TCP 代理（旧版行为）、直连。** 国内/境外规则不能可靠区分 PSN 与视频，PSN 登录或上传失败时优先用规则分流。UU 接管 DNS 后，设备得到的地址可能没有进入本插件的 gfwlist 集合，导致规则分流的视频失效；此时可选境外 TCP 代理，仍先避开 UU 已识别的动态游戏目标。三种策略都保留 UU 动态游戏目标和 UDP 原路径；它不按应用识别视频/游戏，也不保证修复运营商或 UU 自身造成的 NAT 问题。DNS 随所选分流策略生成，同时保留 UU 与用户原有钩子。

名单按 MAC 配置，IP 从主 LAN 邻居表与 DHCP 租约动态发现；源码不固定 PS5 IP、UU 路由表号或服务商地址。后台只在规则/路由摘要变化时核对本插件入口和动态集合；更新采用原子替换，保留原有有效游戏集合，避免刷新期间整机 TCP 退回直连。每分钟任务负责补启监控，不重启 UU，也不更新订阅。

确认 UU 没接管该设备时，视频代理可继续；UU 已接管但无法读取有效目标、设备 IP 或规则时，优先保留游戏路径，该设备视频 TCP 代理可能暂时不可用。先让设备上线，查 UU 控制端与插件日志，不要清空防火墙“修复”。

此实现只验证主 LAN `br0` 的对应 UU 规则格式，不承诺访客网络、所有 UU 版本或 IPv6 同样有效，也不提供 AnyTLS UDP 透明代理。

## 7. 看懂检测面板与验收

面板从**路由器代理**发起 Google、YouTube、Telegram HTTPS 请求，包含连接、TLS 和响应等耗时；不是 ICMP ping，不表示设备自己的 TUN 或 UU 状态。

Google / YouTube 使用轻量连通性地址，Telegram 使用 HTTPS 请求（现代探测器为 GET，旧 curl 兼容路径为 HEAD）；通过不代表视频码率、下载速度或账号登录一定正常。

- **最近 HTTPS 延迟**：本轮通过目标耗时的中位数；单个目标耗时在下方分别显示。
- **中位延迟 / P95 延迟**：最近记录中各轮有效延迟的中位数与第 95 百分位；P95 更容易反映较慢的轮次。
- **延迟波动**：相邻有效轮次延迟差的绝对值平均；越低通常越平稳。
- **完整通过率**：三个目标都通过的轮数除以总轮数；不是单个请求通过率。

| 面板状态 | 含义 |
| --- | --- |
| 等待采样 / 检测中 | 等第一轮完成或刚切换节点 |
| 连接正常 | 最近一轮三个目标全部通过 |
| 连接波动 | 部分失败，或尚未达到连续全失败阈值 |
| 连接检测失败 | 连续全失败达到阈值，或代理监听不可用 |
| 数据过期 | 没有及时刷新，不能把旧绿色结果当作当前可用 |

在 **附加功能 → 健康检测设置**设间隔 30 / 60 / 120 秒、单目标超时 6 / 8 / 10 秒、连续失败判定 1–5 轮；缺省为 **30 秒 / 10 秒 / 3 轮**。频繁检测会增加流量。

最近 20 轮存 RAM，切节点或服务重启后重置。启动时会采样，打开管理页面时持续触发采样；**不是全天候后台监控服务**。检测失败不会自动换节点或重启服务。

分别验收：普通设备三站访问、TUN 设备自身 VPN、PS5 视频实播、UU 控制端和游戏联机。面板“全部通过”不能代替后面三项。

### 后台自动故障切换（开发版 r4）

此功能从源码版本 `4.38.3-r7000.4` 起提供，当前 GitHub Releases 的 r3 安装包不包含它。全新安装默认关闭，需自行添加有效节点后在 **附加功能 → 自动故障切换** 开启并保存。

1. “优先国家/地区”填 `auto` 时采用当前线路的标签；也可填 `HK`、`JP` 等两位代码。地区来自名称/国旗，不按入口服务器 IP 推断；名称不能识别时填“节点地区映射”，如 `1=HK,2=HK,3=JP`，ID 查看页面对照表。
2. 候选节点 ID 留空表示所有已保存 AnyTLS 节点，最多 128 个；也可填逗号分隔的 ID。只测试候选，不修改节点内容；不支持带 KCP 的候选。
3. 每分钟由后台检查，关闭管理页仍运行。当前线路连续达到失败次数后，优先测试同地区候选；同地区全部失败才测试其他地区，并选该组 HTTPS 耗时较低的可用节点。可用要求三个站点至少两个通过；目标 HTTPS 始终验证证书。
4. 开启“故障直连保护”后，在确认当前线路失败时先撤回本插件转发和 DNS，再在隔离 SOCKS 端口分批找备用线路。全候选失败时保留直连并继续恢复检测，不关闭 UU，不重配设备 TUN。直连只恢复原本可直连的网络，受限网站仍需可用代理。
5. 恢复需达到连续成功次数，并遵守切换冷却时间。候选复查失败只淘汰它自己，保留本轮其余健康候选；替补重新完成恢复确认，避免反复扫描整组。单轮预算限制探测负载，大量候选会跨多轮完成；未测试的节点不会被当作失败。预算至少为 `3 × 单站超时 + 8` 秒。候选较多时，缩小候选集合可加快完成一轮扫描。

状态卡区分确认故障、扫描、直连保护、恢复确认、冷却和错误，并显示扫描进度及当前实际节点。TCP 入口延迟不能替代这些 HTTPS 检测，检测通过也不能代替 PS5 登录、视频实播和游戏联机验收。手动关闭路由器代理后，后台不会自动启用；修改参数或手动选线会使旧探测结果失效。

## 8. 常见问题与恢复

| 现象 | 先检查什么 |
| --- | --- |
| `Base archive SHA256 does not match` | 是否下载 v4.38.3 的 Assets 安装包、是否完整；不要修改校验值绕过检查 |
| `Destination already exists` | 给 `--dest` 指定新目录，运行脚本打印的构建命令 |
| 补丁失败 / clone 目录已存在 | 是否在新目录按固定提交准备；不要重复应用补丁 |
| `An installed fancyss 4.38.3 is required` | 很可能误下载了旧增量包；首次安装应选本文顶部的完整包 |
| `Unrecognized plugin` / 存在旧节点或不完整注册 | 安装器不会把残留状态当作全新设备，先保留配置并按上游方法迁移或恢复 |
| 二进制无法运行、缺少 helper 或空间不足 | 看预检日志，核对架构、Go 版本与空间，不跳过预检强行覆盖 |
| 无增强标记 / 新面板 | 确认上传增强包且安装成功，再强制刷新缓存 |
| 手机可用、路由器不通 | 核对节点、SNI、证书选项、必需 Hosts、启动前直接解析；YAML DNS / 规则不自动迁移 |
| YAML / 订阅导入失败 | 确认是 URI 节点订阅；只有 YAML 时按第 4 节手填 |
| TLS 握手 / 证书失败 | 查路由器时间、SNI、服务端证书与服务商要求，不统一开启“允许不安全” |
| 电脑关闭 TUN 后不通 | 是否还在整机旁路名单，移除自己的 MAC 并应用 |
| TUN 电脑仍被路由器代理 | 当前 MAC 是否变化、是否切换有线 / Wi-Fi、是否填对名单 |
| PS5 游戏正常、视频不通 | 是否误填整机旁路，UU 名单是否正确，设备在线和 UU 目标读取是否正常；等一轮核对后看日志 |
| PS5 视频正常、游戏异常 | 查 UU 设备识别、游戏选择与状态，再查共存日志；不要改为全局游戏代理或清空 UU 规则 |
| 面板过期 / 通过率归零 | 是否关闭管理页、刚切节点或重启；等待新采样 |

### 路由器域名广告过滤（开发版 r5）

在 **附加功能 → 域名广告过滤** 打开开关，用“仅保存广告设置”应用。此按钮只热加载本功能的 DNS 规则，不重启代理或 UU。功能随路由器代理运行；全新安装默认关闭。关闭开关或节点故障进入直连保护时，会取消过滤并撤回本功能的 DNS 拦截。

- 只处理普通设备通过主 LAN 发送的 IPv4 UDP/TCP 53 请求。**整机旁路名单和 UU 名单中的设备全部排除**，包括这些设备的 DNS；IPv6 与加密 DNS 不拦截。本机 TUN 与 PS5 的现有路径保持原设置。
- 内置一份保守的小型域名列表；“额外拦截域名”和“放行域名”每行填一个完整 ASCII 域名，自动转小写，最多 256 条、8192 字节。填入的域名也匹配子域名，不支持网址、IP、通配符、Hosts 或 Adblock Plus 语法。放行规则优先；例如放行 `example.com` 也放行其子域名。
- YouTube 视频及其 Google 广告依赖、PSN、UU 等关键域名受到保护，不能添加覆盖它们的拦截规则；也不会封锁整个 `googlevideo.com`。自定义域名可能仍影响其他网站，遇到误拦截时加入放行列表或关闭开关。
- 不下载远程列表，不新增订阅或规则自动更新任务；列表只随手动安装新版或手动编辑而改变。不保存设备的 DNS 查询历史。
- 关闭后，已存在的 DNS 映射可能仍指向本模块，因此会保留**不带过滤的兼容转发**，直到这些连接自然释放后退出；不清空全局连接表。客户端持续复用 DNS socket 时，兼容转发可能持续存在，不能承诺固定时长。卸载同样由私有 RAM keeper 完成排空，避免删文件后旧连接失效。
- 更改 UU 或整机旁路名单时，先整体转为兼容转发，等旧 DNS 映射释放后再应用新排除策略；页面会显示等待状态。只处理本模块自己的 DNS 进程和 TCP DNS worker，不操作游戏、视频、UU 或本机 VPN 的连接。

状态行区分关闭、运行、等待排空与错误，并显示当前有效拦截域名数和排除设备数。关闭时若兼容转发仍在运行，不表示广告过滤仍开启。验证时应分别测试已知广告域名、普通站点、YouTube 实播、UU 启停与本机 TUN；单看“运行”不能替代兼容性验收。它不提供 YouTube 视频内广告过滤能力。

### YouTube 广告与免费客户端方案

本插件负责代理与分流，当前没有 YouTube 视频内广告过滤功能。域名级广告过滤可以拦截独立广告服务器，但 YouTube 广告和正片可能共用域名，封锁会误伤播放；[AdGuard Home 官方限制](https://github.com/AdguardTeam/AdGuardHome#known-limitations)也明确列出这一边界。不要添加整片 `googlevideo.com` 黑名单，也不要把三站连通性检测当作去广告验收。

- **电脑 Chrome**：从[作者指向的官方商店页](https://chromewebstore.google.com/detail/ublock-origin-lite/ddkjiahejlhfcafbddmgiahcphecmpfh)安装 uBlock Origin Lite。在 Chrome 扩展详情中将网页数据访问限于 `https://*.youtube.com/*`，打开 YouTube 后确认扩展弹窗为“优化”过滤模式。过滤规则会随站点变化，不能承诺永久覆盖所有广告。
- **Android 手机**：使用 Firefox，在菜单 → 扩展中添加作者 Raymond Hill 的 [uBlock Origin](https://addons.mozilla.org/en-US/android/addon/ublock-origin/)，保留默认规则，再在 Firefox 内观看 YouTube 网页版。[Mozilla 安装步骤](https://support.mozilla.org/en-US/kb/find-and-install-add-ons-firefox-android)。此方案不处理官方 YouTube App，也不接管手机 VPN。
- **PS5 官方 App**：上述免费浏览器方案不覆盖它。路由器代理、UU 游戏目标优先和设备 TUN 旁路继续按原设置运行；处于 TUN 隧道内的流量也不能由路由器识别其内部视频请求。

### 安装失败和手动恢复

日志会给出本次目录：首次完整安装在 `/jffs/.r7000-full-backups/<本次目录>/`，已有 4.38.3 的增强更新在 `/jffs/.r7000-backups/<本次目录>/`。备份含私有参数，不要上传 GitHub 或公开贴出。

- 预检失败先修日志指出的问题。已触及服务后失败时，安装器会尝试恢复文件和参数，并**保持路由器代理关闭**；不能只看旧文件回来就认定服务恢复。
- 手动恢复前，先用**增强版安全入口**停止代理，再按该备份的 `RESTORE.txt` 执行 `restore-files.sh`。这需要路由器管理 / SSH 操作经验，不确定时保留备份和脱敏日志再排查。
- 恢复旧文件后，不要直接启动旧版服务，其旧入口可能清除 UU 共享规则。不要用卸载 UU、清空防火墙或恢复出厂设置代替插件恢复。

报告问题时附机型、固件、增强版本、使用模式、问题设备属于哪组名单和脱敏错误信息，移除密码、订阅 token、真实 MAC 与私有 Hosts。

## 开发、验证与许可

| 目录 | 内容 |
| --- | --- |
| `plugin/overlay/` | 新增脚本、安装器、界面资源、图标和测试 |
| `patches/` | Fancyss 4.38.3 与 AnyTLS 客户端改动 |
| `client/overlay/` | 新增连接复用测试 |
| `runtime-tools/` | 仅 Go 标准库依赖的 ss-flock、HTTPS 探测器、入口 TCP 探测器与测试 |
| `scripts/prepare.py` | 校验本地输入，恢复可构建的上游工作树 |
| `provenance.json` | 固定上游版本、SHA256、工具链和来源 |

开发者可选验证，在已经准备好的仓库中执行：

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
cd runtime-tools
GOTOOLCHAIN=local go test ./...
cd ../build/r7000-enhanced
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m unittest discover -s shadowsocks/tests -p 'test_*.py'
node tests/ss-health.test.js
```

客户端完整测试在应用补丁后的上游工作树内执行 `go test ./...`；并发验证可用 `go test -race ./cmd/client ./proxy/session`。

完整包首次安装入口经过模拟路由器文件系统与 DBus 的自动化验证，尚未在独立空白 R7000 上完成首次安装实机验收；没有为此清空用户正在使用的路由器。其运行增强组件此前在上述 R7000 上通过 94 项 Python 检查与 JS 界面验证，三站短期检测 16/16 轮完整通过，PS5 视频与 UU 游戏通过用户实测。结果仅对应该窗口与配置，不构成其他网络或长期可用性保证。

原创新增内容用 [MIT License](LICENSE)。第三方文件和补丁上游上下文不因此获得新许可，详见[来源与许可说明](THIRD_PARTY_NOTICES.md)。源码仓库保留补丁；Releases 分发完整离线包及增强增量包，包含各自必需的修改版客户端、插件文件、运行依赖及公共 CA bundle。第三方内容保留其原有权利，发布本身不构成额外授权。

本地维护仓库、下载材料、构建产物和实机资料均在忽略目录中。不要把订阅、密码、真实 MAC、私有 Hosts、实机日志或未脱敏截图加入公开提交。发布包会清除构建电脑的用户名、属主 ID、时间戳和扩展元数据；它不包含本地私有部署包装层。
