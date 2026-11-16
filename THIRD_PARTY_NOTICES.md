# 来源与许可说明

本仓库的 MIT 授权限于作者可授权的原创新增内容。补丁中出现的第三方代码、上下文和原有版权归各自权利人；本仓库不为它们授予新许可。

- 插件直接上游：[cary-sas/v2ray_bin](https://github.com/cary-sas/v2ray_bin)，原版包版本 4.38.3。公开补丁只记录本次集成修改，完整上游包不随仓库分发。
- 客户端直接上游：[cary-sas/anytls-go-add-nat](https://github.com/cary-sas/anytls-go-add-nat)，基线 `1a08fcf52fa56c0c1531a76839cd81cd1757dd4c`。完整客户端源码和预编译内核不随仓库分发。
- 截至 2026-11-17，这两个直接上游未在已核查的根目录提供明确 LICENSE，GitHub 的 license 元数据为空。上游可被公开访问不等于本仓库有权为其重新授权。
- Fancyss 的较早来源包括 [hq450/fancyss](https://github.com/hq450/fancyss/blob/3.0/LICENSE)，该项目提供 GPL-3.0。此事实不替后续仓库的全部新增内容确定许可。
- 客户端补丁使用 uTLS 和其他依赖；应用补丁后由 Go 的固定 `go.mod` / `go.sum` 获取。依赖自身的 MIT、BSD 等许可继续适用，不能代替主项目的许可。
- CA bundle 来源为 [curl CA Extract](https://curl.se/docs/caextract.html) 从 Mozilla certdata 提取的证书数据，适用 [Mozilla Public License 2.0](https://www.mozilla.org/en-US/MPL/2.0/)。本仓库仅记录来源和已验收快照的哈希，不分发该文件。
- Go 标准库适用 [Go BSD 许可](https://go.dev/LICENSE)。`runtime-tools/` 仅使用标准库；本仓库不分发 Go 工具链。
- 新图标是本项目生成的资源；实际设备截图、账号配置和私有服务商资料不包含在公开仓库中。

重建完整插件时，应保留上游已有版权和许可说明，并自行取得、核对相应上游材料的使用条件。这里的源码许可不构成对完整上游安装包或协议实现的重新授权。
