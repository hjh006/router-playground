# 自用路由线路 · Android

连接路由器，查看和切换已保存的 AnyTLS 线路。原生 Android App，不接管手机流量，也不创建 VPN。

[下载 Android 1.1.0 APK 与校验文件](https://github.com/hjh006/router-playground/releases/tag/android-v1.1.0)

## 支持范围

- Android 8.0 及以上。
- 当前兼容目标：Netgear R7000，Merlin 380.70_0-X7.9.1，AnyTLS 增强插件 4.38.3-r7000.3。其他固件及插件接口尚未验证。
- 手机需要能访问路由器管理地址，通常连接家庭 Wi-Fi。HTTP 仅接受局域网 IPv4；HTTPS 使用系统证书校验。

## 使用

1. 安装 APK，填写路由器管理地址并登录。地址、账号和线路由自己配置，安装包不携带这些内容。
2. App 读取路由器已保存的 AnyTLS 线路，按名称归类国家或地区，显示国旗、数量及可折叠分组。正常宽度采用两列，小屏或大字体自动改为单列；分类不能代替实际出口位置检测。
3. 点击分组的“测延迟”，按需测量该组入口，可查看进度或停止。App 不自动后台批测。
4. 点击线路的“切换”并确认，等待配置与新的健康检测；结果未知时先刷新核对，再决定是否重试。

线路新增、编辑及路由策略在原插件页面完成。App 切换现有线路，不调整旁路设备、UU 游戏优先规则、Hosts、DNS 或自动更新开关。

“手机 TCP”测量手机到配置入口的 TCP 建连耗时，不使用节点密码，不代表 AnyTLS 认证、出口速度或完整代理链路。手机当前网络、VPN、透明代理及配置的入口 Hosts 都可能影响结果。

“路由器 HTTPS”是路由器通过当前线路访问检测目标的请求采样，两种指标的起点与协议不同，应分别阅读。App 前台每 30 秒读取状态，并复用固件原有健康检测入口；进入后台后停止定时刷新。

登录会话加密保存在手机本地，备份已禁用；线路配置只保留在内存。路由器在其他设备重新登录后可能使旧会话失效，届时重新登录即可。请勿把管理凭证、私有配置或包含这些信息的截图提交到仓库。

## 本地构建

支持 macOS、Linux，需要 Python 3、JDK 17 或更新版本，以及本地 Android SDK。默认使用 SDK Platform `android-36.1` 和 Build Tools `36.1.0`，不使用 Gradle，不自动下载依赖。

```sh
python3 android/build.py
```

SDK 依次从 `--sdk`、`ANDROID_SDK_ROOT`、`ANDROID_HOME` 读取；未指定时，macOS 查找 `~/Library/Android/sdk`，Linux 查找 `~/Android/Sdk`。JDK 优先使用 `JAVA_HOME`，否则在 macOS 使用 `java_home`，在 Linux 从 `PATH` 查找 `javac`。

```sh
python3 android/build.py --sdk "$ANDROID_SDK_ROOT" \
  --platform android-36.1 --build-tools 36.1.0 \
  --signing-dir "$HOME/.local/share/router-control/signing" \
  --output /tmp/router-control-local.apk
```

默认输出 `android/build/router-control-<版本>.apk` 及 `.apk.sha256`。`android/build/` 是本地忽略的缓存和产物目录。

签名身份由 `--signing-dir` 或 `ROUTER_ANDROID_SIGNING_DIR` 指定，必须位于仓库之外。默认目录为 macOS 的 `~/Library/Application Support/RouterControl/signing`，或 Linux 的 `$XDG_DATA_HOME/router-control/signing`（未设置时使用 `~/.local/share/router-control/signing`）。目录权限为 `0700`，密钥和随机密码文件权限为 `0600`，密码不写入命令行或日志。

请保存同一目录中的 `router-control.p12` 和 `signing-password`：相同签名身份决定后续 APK 能否覆盖升级。自己构建默认会生成新的身份，与公开 Release 的签名不同，不能直接覆盖安装 Release；卸载重装会清除本地登录状态。不要提交或分享签名目录。

## 本地检查

三个 JVM 测试只使用合成配置和本机回环地址，不连接实际路由器或真实节点。测试需另外准备 Maven 坐标 `org.json:json:20240303` 的 JAR；脚本不下载、不复制 JAR，并校验其 SHA-256。

```sh
python3 android/test.py --json-jar /path/to/json-20240303.jar
```

该 JAR 的 SHA-256：

```text
3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed
```

1.1.0 的验收记录包括 125 项本地检查（接口 86、TCP/Hosts 22、国家归类 17），以及实际往返切换后的 23 项状态保留比对；APK 的 v2/v3 签名校验通过。状态比对覆盖 UU 原进程、非插件防火墙规则顺序、旁路优先路径、DNS、Hosts、自动更新、路由模式及节点定义。

这些结果只覆盖当时的验收窗口。此次没有活动中的 UU 游戏流量验收，不能据此保证游戏体验或长期稳定性。横屏和大字体有自适应实现，本次实际截图验收为竖屏。

源码许可见仓库根目录 [LICENSE](../LICENSE)；第三方组件说明见 [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)。
