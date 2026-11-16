# 路由器玩法 · Router Playground

<img src="plugin/overlay/shadowsocks/res/icon-shadowsocks.png" width="64" alt="Router Playground icon">

Netgear R7000 / Merlin 380 的 AnyTLS 增强：设备自身 TUN 旁路、UU 游戏加速与视频代理共存、可配置连接参数，以及 Google / YouTube / Telegram HTTPS 状态面板。

当前增强版本：**4.38.3-r7000.3**。

**已有 cary-sas Fancyss 4.38.3 的兼容设备，可以直接下载通用离线增强包，无需编译：**

- [下载 shadowsocks.tar.gz](https://github.com/hjh006/router-playground/releases/download/v4.38.3-r7000.3/shadowsocks.tar.gz)
- [下载 SHA256SUMS 校验文件](https://github.com/hjh006/router-playground/releases/download/v4.38.3-r7000.3/SHA256SUMS)
- [版本说明与依赖许可证](https://github.com/hjh006/router-playground/releases/tag/v4.38.3-r7000.3)

**这是 4.38.3 的增量增强包，不是所有路由器都能首次安装的完整包。** 先核对第 1 节环境；尚未安装基线的设备，按第 3 节先装匹配的上游 4.38.3，再装增强包。GitHub 的 Code → Download ZIP 是源码，不能直接上传安装。上游材料的许可范围见[来源说明](THIRD_PARTY_NOTICES.md)。

## 阅读顺序

1. [确认设备与准备材料](#1-确认设备与准备材料)
2. [在电脑上构建增强包](#2-在电脑上构建增强包)
3. [在路由器上安装](#3-在路由器上安装)
4. [配置 AnyTLS 节点并启用](#4-配置-anytls-节点并启用)
5. [配置本机 TUN 共存](#5-配置本机-tun-共存)
6. [配置 PS5 / UU 共存](#6-配置-ps5--uu-共存)
7. [看懂检测面板与验收](#7-看懂检测面板与验收)
8. [常见问题与恢复](#8-常见问题与恢复)

普通用户阅读第 1 节后，下载 Releases 的 `shadowsocks.tar.gz`，从第 3 节开始；想自行编译或修改源码的用户再阅读第 2 节。通用包不含节点、订阅或个人设备配置，升级会保留安装者自己的现有配置。

## 1. 确认设备与准备材料

### 路由器要求

| 项目 | 本项目实际验证的环境 |
| --- | --- |
| 路由器 | Netgear R7000 |
| 固件 | 含 Koolshare 软件中心的 Merlin `380.70_0-X7.9.1` |
| 内核 / 架构 | Linux `2.6.36.4` / `armv7l` |
| 插件基线 | cary-sas 的 Fancyss **4.38.3** |
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

此私有工具提供锁、临时文件和权限检查，安装时不覆盖系统工具。

### 2.5 生成增强包

```sh
python3 scripts/prepare.py \
  --base downloads/shadowsocks.tar.gz \
  --anytls-binary build-client/anytls-client-linux-armv5-r7000.3 \
  --flock-binary build-tools/ss-flock-linux-armv5 \
  --ca-bundle downloads/cacert.pem
python3 build/r7000-enhanced/build-enhancement.py
```

最终生成：**`build/r7000-update-generic/shadowsocks.tar.gz`**。

| 文件 | 用途 |
| --- | --- |
| `downloads/shadowsocks.tar.gz` | 上游原版包，用于尚未安装基线的设备 |
| `build/r7000-update-generic/shadowsocks.tar.gz` | 增强增量包，要求设备已安装 4.38.3 |

两个文件名字相同、用途不同，上传时核对所在目录。准备脚本只在本地展开、应用补丁和复制输入，不联网、不运行输入二进制，也不部署路由器。

默认 `build/` 已存在时会拒绝覆盖。重新准备可选新目录，例如 `--dest build/retry`，然后运行脚本打印出的构建命令；产物会放在该目标目录的 `r7000-update-generic/` 下。无需删除自己的旧产物或配置。

## 3. 在路由器上安装

### 3.1 区分当前状态

- **已经安装 cary-sas 4.38.3**：直接安装增强包，不重复安装原版。
- **兼容固件上还没有插件**：从[上游 v4.38.3 发布页](https://github.com/cary-sas/v2ray_bin/releases/tag/v4.38.3)的 Assets 下载原版 `shadowsocks.tar.gz`，通过软件中心离线安装，确认基线 4.38.3；首次配置前保持代理关闭，再安装本项目的增强包。全新搭建时，完成增强安装后再安装或启用 UU。两个包同名但来源不同，不要传错。
- **已有其他版本、其他分支或其他固件**：本教程不提供原地跨版本迁移，先按相应上游方法备份和迁移，不能直接覆盖增强增量包。

原版旧入口可能影响 UU 的共享规则；已运行 UU 的 4.38.3 用户应直接走增强更新，不要为此反复重装、启停原版。

### 3.2 上传增强包

下载后，在安装包所在文件夹运行对应的校验命令，将输出与 `SHA256SUMS` 中 `shadowsocks.tar.gz` 那行比对：

| 电脑系统 | 校验命令 |
| --- | --- |
| macOS | `shasum -a 256 shadowsocks.tar.gz` |
| Linux | `sha256sum shadowsocks.tar.gz` |
| Windows PowerShell | `Get-FileHash .\shadowsocks.tar.gz -Algorithm SHA256` |

哈希一致后再安装；依赖许可证与第三方来源说明附在同一版本的 Releases 资产中。

1. 电脑保持连接该路由器的局域网，登录路由器管理页。
2. 打开 **软件中心 → 离线安装**。
3. 选择从 **本项目 Releases** 下载的 **`shadowsocks.tar.gz`**，点 **上传并安装**。自行构建的用户选择 `build/r7000-update-generic/shadowsocks.tar.gz`。保持文件名，不解压后逐个上传；不要选择 GitHub 自动生成的 Source code 包。
4. 等日志结束，确认出现 `Enhancement installed`，记录打印的私有备份目录。
5. 返回科学上网插件并刷新；缓存旧资源时强制刷新或重新登录后再查看。
6. 确认页头出现 **R7000 增强 r3**，能看到新的 HTTPS 面板和“访问控制”中的两组设备策略。

原插件版本数字仍可能显示 **4.38.3**，增强标记在页头。安装器保留原来的启用状态：之前关闭的不会自动开启，之前运行的会尝试用新入口恢复。节点和设备名单需继续配置。

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
2. 如果服务商有节点 Hosts，展开 **全局设定 → AnyTLS 高级连接设置 → 服务商 Hosts 映射（节点解析）**，按下面格式逐行填入；没有要求则留空。

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

**通用增强安装器保留已有自动更新设置，不会替每个使用者自动关闭它们。**

原版“检查并更新”可能覆盖增强文件；增强版升级应使用对应增强包。不要为了套用 Clash 教程，顺手改动电脑 TUN、全局 IPv6 或路由器 DNS 劫持。

### 4.4 启用与首次检查

1. 在 **账号设置** 选刚配置的 AnyTLS 节点，确认模式，**先将科学上网开关置为开启，再点保存&应用**，等待启动日志完成。首次只打开开关不会自动提交。
2. 等面板完成首轮 HTTPS 检测，核对当前节点名称。
3. 用一台**未开启自身 VPN、也不在旁路名单**的普通设备试开 Google、YouTube、Telegram。
4. 通过后再配置下面的 TUN、UU 设备。日常可优先测试香港等邻近区域，但本项目不固定节点，也不自动选最快节点。

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
3. 打开 **访问控制 → PS5 / UU 共存设备**，填 MAC 并 **保存&应用**。**不要把同一台 PS5 同时放入“自带 VPN 设备旁路”。**
4. 在 PS5 打开 YouTube 实播一段视频，再在 UU 选常玩的游戏，进游戏检查 UU 状态、登录和联机。
5. UU 启动、切游戏或重建规则后，通常等下一个约 1 分钟的核对周期，再分别复查视频与游戏，无需反复重启 UU。

两组 MAC 名单各最多 32 个，支持每行一个或逗号分隔，互斥。同一设备只选一种策略。

### 流量怎样走

| 设备 / 流量 | 处理方式 |
| --- | --- |
| TUN 旁路名单中的电脑 | 保留 TCP / DNS 原路径，由本机 VPN/TUN 处理 |
| UU 设备命中已有 UU DNAT / 动态游戏目标的 IPv4 TCP | UU 路径优先，避开路由器代理 |
| UU 设备的其他国内 IPv4 TCP | 直连 |
| UU 设备的其他境外 IPv4 TCP | AnyTLS，例如 YouTube 的 TCP 连接 |
| UU 设备的 UDP | UU 或原网络，不由 AnyTLS 透明代理接管 |
| 未列入两组名单的普通设备 | 按插件主模式及原访问控制处理 |

**UU 设备使用“国内直连、其余境外 IPv4 TCP 代理”的单独策略，不完全跟随全局 gfwlist 模式。** DNS 沿用 UU 与路由器现有规则。它不是按应用识别视频 / 游戏，而是依据 UU 规则和动态游戏目标区分。

名单按 MAC 配置，IP 从主 LAN 邻居表与 DHCP 租约动态发现；源码不固定 PS5 IP、UU 路由表号或服务商地址。每分钟只核对本插件入口和动态集合，不重启 UU，也不更新订阅。

确认 UU 没接管该设备时，视频代理可继续；UU 已接管但无法读取有效目标、设备 IP 或规则时，优先保留游戏路径，该设备视频 TCP 代理可能暂时不可用。先让设备上线，查 UU 控制端与插件日志，不要清空防火墙“修复”。

此实现只验证主 LAN `br0` 的对应 UU 规则格式，不承诺访客网络、所有 UU 版本或 IPv6 同样有效，也不提供 AnyTLS UDP 透明代理。

## 7. 看懂检测面板与验收

面板从**路由器代理**发起 Google、YouTube、Telegram HTTPS 请求，包含连接、TLS 和响应等耗时；不是 ICMP ping，不表示设备自己的 TUN 或 UU 状态。

Google / YouTube 使用轻量连通性地址，Telegram 使用 HTTPS 头请求；通过不代表视频码率、下载速度或账号登录一定正常。

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

## 8. 常见问题与恢复

| 现象 | 先检查什么 |
| --- | --- |
| `Base archive SHA256 does not match` | 是否下载 v4.38.3 的 Assets 安装包、是否完整；不要修改校验值绕过检查 |
| `Destination already exists` | 给 `--dest` 指定新目录，运行脚本打印的构建命令 |
| 补丁失败 / clone 目录已存在 | 是否在新目录按固定提交准备；不要重复应用补丁 |
| `An installed fancyss 4.38.3 is required` | 这是增量包，先核对插件来源与基线版本 |
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

### 安装失败和手动恢复

日志会给出本次目录：`/jffs/.r7000-backups/<本次目录>/`。备份含私有参数，不要上传 GitHub 或公开贴出。

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
| `runtime-tools/` | 仅 Go 标准库依赖的 ss-flock、HTTPS 探测器与测试 |
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

本版本曾在上述 R7000 上通过 94 项 Python 检查与 JS 界面验证，三站短期检测 16/16 轮完整通过，PS5 视频与 UU 游戏通过用户实测。结果仅对应该窗口与配置，不构成其他网络或长期可用性保证。

原创新增内容用 [MIT License](LICENSE)。第三方文件和补丁上游上下文不因此获得新许可，详见[来源与许可说明](THIRD_PARTY_NOTICES.md)。源码仓库保留补丁；Releases 分发通用增强增量包，包含必要的修改版客户端、插件文件及公共 CA bundle。第三方内容保留其原有权利，发布本身不构成额外授权。

本地维护仓库、下载材料、构建产物和实机资料均在忽略目录中。不要把订阅、密码、真实 MAC、私有 Hosts、实机日志或未脱敏截图加入公开提交。发布包会清除构建电脑的用户名、属主 ID、时间戳和扩展元数据；它不包含本地私有部署包装层。
