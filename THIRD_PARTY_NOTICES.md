# 来源与许可说明

本仓库的 MIT 授权限于作者可授权的原创新增内容。补丁中出现的第三方代码、上下文和原有版权归各自权利人；本仓库不为它们授予新许可。

- 插件直接上游：[cary-sas/v2ray_bin](https://github.com/cary-sas/v2ray_bin)，原版包版本 4.38.3。源码仓库保留集成补丁；Releases 增强增量包包含应用修改后的必要插件文件，不包含完整原版安装包。
- 完整离线包另合并该固定原版包中的运行目录（bin、scripts、ss、webs、res），以支持首次安装；它使用本项目的新安装入口，不运行原版批量清理安装器。包内 BUILD.json 记录源包 SHA256 和逐文件校验值。原版通用依赖仍归各自权利人，不因合并而适用本项目 MIT；所附依赖许可证只覆盖其中明确标示的组件，不代替未明确的上游许可。
- 客户端直接上游：[cary-sas/anytls-go-add-nat](https://github.com/cary-sas/anytls-go-add-nat)，基线 `1a08fcf52fa56c0c1531a76839cd81cd1757dd4c`。源码仓库保留客户端补丁；Releases 包含本地编译的修改版 AnyTLS 内核。
- 截至 2026-11-17，这两个直接上游未在已核查的根目录提供明确 LICENSE，GitHub 的 license 元数据为空。上游可被公开访问不等于本仓库有权为其重新授权。
- Fancyss 的较早来源包括 [hq450/fancyss](https://github.com/hq450/fancyss/blob/3.0/LICENSE)，该项目提供 GPL-3.0。此事实不替后续仓库的全部新增内容确定许可。
- 客户端补丁使用 uTLS 和其他依赖；应用补丁后由 Go 的固定 `go.mod` / `go.sum` 获取。依赖自身的 MIT、BSD 等许可继续适用，不能代替主项目的许可。
- CA bundle 来源为 [curl CA Extract](https://curl.se/docs/caextract.html) 从 Mozilla certdata 提取的证书数据，适用 [Mozilla Public License 2.0](https://www.mozilla.org/en-US/MPL/2.0/)。Releases 包含该 CA bundle，保留其原始来源头部，另附 MPL-2.0 全文；源码仓库记录已验收快照的哈希。
- Go 标准库适用 [Go BSD 许可](https://go.dev/LICENSE)。`runtime-tools/` 仅使用标准库；本仓库不分发 Go 工具链。
- 新图标是本项目生成的资源；实际设备截图、账号配置和私有服务商资料不包含在公开仓库中。

Releases 的发布不改变第三方代码的许可状态，也不表示已取得上游额外授权。第三方组件不适用本仓库的 MIT 授权。重建或再次分发时，应保留上游已有版权和许可说明，核对相应材料的适用条件；这里的源码许可不构成对上游安装包或协议实现的重新授权。
