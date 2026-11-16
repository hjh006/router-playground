# 路由器玩法 · Router Playground

<img src="plugin/overlay/shadowsocks/res/icon-shadowsocks.png" width="64" alt="Router Playground icon">

为 Netgear R7000 / Merlin 380 整理的 AnyTLS 日常使用增强：设备自身 TUN 旁路、UU 游戏加速与视频代理共存、可配置的连接参数，以及 Google / YouTube / Telegram HTTPS 状态面板。

当前增强版本：`4.38.3-r7000.3`。目标系统为 Merlin `380.70_0-X7.9.1`、Linux `2.6.36.4`。

## 功能

- 按 MAC 配置设备整机旁路，让设备自身的 VPN/TUN 接管连接。
- 按 MAC 配置 UU 共存设备，保留 UU 的 DNAT、UDP、策略路由和动态游戏目标；其余境外 IPv4 TCP 交给代理。
- 节点 Hosts 映射与独立启动解析，保留 TLS SNI，避免解析依赖尚未启动的代理。
- 可编辑空闲连接数、检查和回收间隔、握手超时、ALPN、TLS 指纹。
- 三站 HTTPS 连通检测，显示请求耗时、中位数、P95、波动和最近通过率。
- 支持 Linux 2.6 旧固件的私有锁、临时文件和权限检查工具；不覆盖系统工具。
- 更新安装器保留备份，并检查文件清单、空间和运行条件。

节点、设备、Hosts 和检测参数通过界面配置，公共源码不包含个人目标。订阅和规则自动更新保持关闭。关闭设备自身 TUN 后，应移除该设备的旁路，才能使用路由器代理。

## 仓库内容与许可范围

这里公开本项目的新增代码、针对固定上游版本的改动补丁和本地重建方法。

| 目录 | 内容 |
| --- | --- |
| `plugin/overlay/` | 新增脚本、安装器、界面资源、图标和测试 |
| `patches/` | Fancyss 4.38.3 与 AnyTLS 客户端改动 |
| `client/overlay/` | 新增连接复用测试 |
| `runtime-tools/` | 独立的 ss-flock、HTTPS 探测器及测试，只有 Go 标准库依赖 |
| `scripts/prepare.py` | 校验本地上游包，准备可构建工作树 |
| `provenance.json` | 固定上游版本、SHA256、工具链和来源 |

原创新增内容使用 [MIT License](LICENSE)。第三方文件和补丁中的上游上下文不因此获得新的许可，具体见 [来源与许可说明](THIRD_PARTY_NOTICES.md)。上游完整源码、预编译 AnyTLS 内核、安装包和 CA bundle 不在本仓库重复分发。使用者自行从上游取得所需材料，并遵守其适用条件。

## 本地重建

准备 Python 3、Git 和 **Go 1.23.12**。Go 使用 `GOTOOLCHAIN=local`；目标为静态 `linux/arm`、`GOARM=5`。不要直接换成要求更高 Linux 内核的工具链。

### 1. 准备 AnyTLS 客户端

从 [客户端上游](https://github.com/cary-sas/anytls-go-add-nat) 取得固定基线，在本地应用补丁：

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

### 2. 编译独立运行工具

```sh
mkdir -p build-tools
cd runtime-tools
GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 go build \
  -trimpath -ldflags='-s -w' -o ../build-tools/ss-flock-linux-armv5 ./cmd/ss-flock
cd ..
```

### 3. 准备插件并打包

自行从 [插件上游](https://github.com/cary-sas/v2ray_bin) 取得原版 **4.38.3** 安装包。所需包的 SHA256 为：

```text
05a30314c8c6d8f33ae9c027b42927e9d17e6e648c75ac7b419282fe5c1c2adf
```

准备从 [curl / Mozilla](https://curl.se/docs/caextract.html) 取得的 CA bundle，然后运行：

```sh
python3 scripts/prepare.py \
  --base /path/to/original/shadowsocks.tar.gz \
  --anytls-binary build-client/anytls-client-linux-armv5-r7000.3 \
  --flock-binary build-tools/ss-flock-linux-armv5 \
  --ca-bundle /path/to/cacert.pem
python3 build/r7000-enhanced/build-enhancement.py
```

生成包：`build/r7000-update-generic/shadowsocks.tar.gz`。它是供**已安装 4.38.3** 的目标路由器使用的增量更新包。软件中心离线安装时保留文件名 `shadowsocks.tar.gz`。先保留自己的配置与备份，安装后核对运行状态。

准备脚本不会联网下载、启动内核或部署到路由器。默认目标 `build/` 已存在时会拒绝覆盖，可用 `--dest` 选择新的目录。

## 验证

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
cd runtime-tools
GOTOOLCHAIN=local go test ./...
cd ../build/r7000-enhanced
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m unittest discover -s shadowsocks/tests -p 'test_*.py'
node tests/ss-health.test.js
```

客户端完整测试在应用补丁后的上游工作树内执行 `go test ./...`；连接和会话的并发验证可用 `go test -race ./cmd/client ./proxy/session`。

本版本曾在上述 R7000 固件上通过 94 项 Python 检查及 JS 界面验证；实机短期验收中三站 16/16 轮完整通过，PS5 视频播放与 UU 游戏加速均通过用户验证。这些结果只对应该验收窗口和配置。面板数值是 HTTPS 请求耗时，包含 TLS 时间，不是 ping 或长期可用性承诺。

## 配置边界

UU 共存策略针对 IPv4 TCP；UDP 保留给 UU 或原网络。设备 DNS 沿用现有路径。服务商教程中的 Clash「DNS 覆写」、本插件的节点 Hosts 与路由器 DNS 劫持含义不同，不应互相替代。工具不会为设备关闭 VPN，也不自动重配全局 IPv6。

请勿提交订阅地址、节点密码、真实 MAC、服务商私有 Hosts、实机日志或未脱敏截图。根目录的本地维护仓库、输出资料和构建目录已加入忽略规则。
