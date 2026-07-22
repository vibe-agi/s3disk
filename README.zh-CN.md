# s3disk

[English](README.md) | [中文](README.zh-CN.md)

通过 S3 共享一台电脑上的一个或多个 workspace，并在其他电脑上以只读方式挂载。
读取端只需要一个有时效的 handoff 文件，不需要长期 S3 凭据；文件内容在真正读取时
才会按需下载。

```text
发布端电脑 ── 加密快照 ──> S3 兼容对象存储
                              │
读取端电脑 <── 私密 handoff ── 只读、按需加载的挂载点
```

`s3disk` 当前是 pre-1.0 工程预览版。Linux 已有通过的真实文件系统挂载基线；
macOS 已具备同一套门禁，但发布前仍需完成一次成功的 VFS 实挂。集成到产品前请先
查看[平台支持](#平台支持)。

## 能做什么

- 通过 S3 兼容对象存储创建有时效、经过加密的共享。
- 使用不可变 chunk、Merkle manifest 和原子更新的签名引用发布快照。
- 按需读取文件；已经打开的文件固定在打开时的快照上。
- 每个 workspace 独立共享；读取端可用 `mount-set` 在一个进程中管理多个挂载点。
- 挂载始终只读，读取端不能修改发布端的 workspace。

## 安装

从 [GitHub Releases](https://github.com/vibe-agi/s3disk/releases) 下载 Linux 或
macOS 压缩包，或者使用受支持的 Go 工具链从已审阅的源码构建：

```sh
go build -trimpath -o ./s3disk ./cmd/s3disk
./s3disk --help
```

发布端通过 AWS SDK 默认凭据链读取 S3 凭据。命令行不接受 access key 或 secret
key 参数，避免凭据进入 shell 历史。

## 快速开始

下面以一个 S3 兼容的 HTTPS endpoint 和显式信任的 CA 文件为例。密钥、handoff
和状态目录必须是私有目录，并且不能是符号链接。

先在发布端验证 bucket 和 endpoint：

```sh
s3disk s3 doctor \
  --bucket example-bucket \
  --prefix private/s3disk-check \
  --endpoint https://s3.example.com \
  --path-style \
  --tls-ca /secure/provider-ca.pem
```

创建恢复密钥，然后发布 workspace：

```sh
s3disk share recovery-key generate \
  --out /secure/workspace-recovery.json

s3disk share publish \
  --source /srv/workspace \
  --all \
  --bucket example-bucket \
  --prefix private/workspace-a \
  --state-dir /var/lib/s3disk/publisher \
  --recovery-key /secure/workspace-recovery.json \
  --handoff-out /secure/workspace-a.handoff \
  --expires-in 2h \
  --endpoint https://s3.example.com \
  --path-style \
  --tls-ca /secure/provider-ca.pem
```

`share publish` 默认持续监控并发布源目录变化；加 `--once` 可只发布一次后退出。
如果发布进程在到期前中断，应使用输出中的 share ID 执行 `share resume`，不要创建
一个新的 share。

通过私密且经过身份验证的通道，把 `/secure/workspace-a.handoff` 传到读取端一次。
然后在 Linux 或 macOS 读取端挂载到一个已经存在的空目录：

```sh
s3disk mount \
  --handoff /secure/workspace-a.handoff \
  --mountpoint /mnt/workspace-a \
  --state-dir /var/lib/s3disk/reader
```

macOS 需要用户单独安装并启用 macFUSE。当前 go-fuse 适配器使用 macFUSE 的
VFS/内核后端；macFUSE 较新的 FSKit 消息传输暂未适配。

共享多个 workspace 时，每个源目录独立发布。读取端可以为每个 handoff 运行一个
`s3disk mount`，也可以使用有资源上限的 [`mount-set`](docs/MOUNT_SET.md) 管理器。
它不会合并目录；每个 workspace 仍有独立挂载点和信任边界。

## 平台支持

| 平台 | 当前状态 |
| --- | --- |
| Linux | 主要目标。包含原生测试和真实 MinIO/FUSE 挂载测试。 |
| macOS | 发布目标，已有真实 macFUSE VFS 测试门禁，覆盖只读、刷新、旧句柄固定、多挂载和干净卸载；在已启用 macFUSE 的主机上成功运行前，不能宣称正式支持。 |
| Windows | 核心包和原生测试可运行，但尚未实现文件系统挂载。`mount` 会返回 `ErrUnsupportedPlatform`；在 Windows ACL 私密性校验完成前，发布端恢复状态也会 fail-closed。 |
| FreeBSD | FUSE 适配器可以编译，但没有专用的原生生产测试基线。 |

Windows 需要 WinFsp 类文件系统适配器、Windows 路径/reparse point 和 ACL 加固、
驱动安装及生命周期处理，以及真实挂载测试。GitHub 托管的 Windows runner 已经在
运行可移植测试，因此主要缺口是实现，不只是缺少 Windows 机器。

完整状态见[兼容性矩阵](docs/COMPATIBILITY.md)。

## 当前工程边界

- 发布扫描不是正在变化的 workspace 的原子快照。严格时间点一致性需要 APFS/LVM/
  文件系统快照，或在扫描时暂停写入。
- S3 中的不可变对象暂时没有垃圾回收。
- 已公开的规模测试是回归基线，不代表大目录、高变化率、长期挂载的容量承诺。
- 挂载的 inode 身份表有上限；达到上限后需要重挂载或调整分片策略。
- `mount-set` 只管理多个独立读取挂载，不是 union filesystem，也不管理发布端进程。

安全、恢复、一致性和对象存储契约的完整说明见[技术参考](docs/REFERENCE.md)。

## 项目结构

- `cmd/s3disk`：命令行程序。
- 根目录：稳定、与存储实现无关的公开 Go API，以及必须访问包内状态的测试。
- `internal`：按领域划分的实现包，包括 CLI 工作流、安全本地状态、平台文件系统
  操作和并发控制。
- `s3store`：基于 AWS SDK v2 的 S3 适配器。
- `presignedshare`：有时效、无需读取端凭据的读取能力。
- `publisherstate`：受保护的发布端恢复数据封装。
- `mount`：只读文件系统适配器。
- `tests/blackbox`：仅通过公开 API 验证行为的黑盒测试。
- `docs`：运维、协议和深度技术文档。

依赖方向和新增文件的归属规则见[仓库架构说明](docs/ARCHITECTURE.md)。

## 开发

```sh
go test ./...
go test -race ./...
go vet ./...
```

完整检查和 DCO 签署要求见 [`CONTRIBUTING.md`](CONTRIBUTING.md)。

## 许可证与支持边界

项目使用 [Apache License 2.0](LICENSE)。在遵守许可证的前提下，可以商用、修改和
再分发。开源发布不包含 SLA、担保，也不承诺替下游部署、运维或提供支持；集成方
自行负责验证和运行。详见 [`SUPPORT.md`](SUPPORT.md) 和
[`SECURITY.md`](SECURITY.md)。
