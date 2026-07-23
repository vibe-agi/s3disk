# s3disk

[English](README.md) | [中文](README.zh-CN.md)

通过 S3 共享一台电脑上的一个或多个 workspace，并在其他电脑上以只读方式访问。
读取端只需要一个有时效的 handoff 文件，不需要长期 S3 凭据；文件内容在真正读取时
才会按需下载。

```text
发布端电脑 ── 加密快照 ──> S3 兼容对象存储
                              │
读取端电脑 <── 私密 handoff ── 本机 WebDAV 或 FUSE 视图
```

`s3disk` 当前是 pre-1.0 工程预览版。Linux 已有通过的真实 FUSE 挂载基线；macOS
已经通过系统自带 WebDAV 客户端完成真实挂载，不需要 macFUSE 或内核扩展。集成到
产品前请先查看[平台支持](#平台支持)。

## 能做什么

- 通过 S3 兼容对象存储创建有时效、经过加密的共享。
- 使用不可变 chunk、Merkle manifest 和原子更新的签名引用发布快照。
- 按需读取文件；已经打开的文件固定在打开时的快照上。
- 提供跨平台、仅监听本机回环地址的 WebDAV 入口。
- 可选 FUSE 挂载；读取端也可用 `mount-set` 管理多个 FUSE 挂载点。
- 所有适配器只读，读取端不能修改发布端的 workspace。

## 安装

macOS 或 Linux 已安装 [Homebrew](https://brew.sh/) 时，可以直接执行：

```sh
brew install vibe-agi/tap/s3disk
```

也可以从 [GitHub Releases](https://github.com/vibe-agi/s3disk/releases) 下载
Linux 或 macOS 压缩包，或者使用受支持的 Go 工具链从已审阅的源码构建：

```sh
go build -trimpath -o ./s3disk ./cmd/s3disk
./s3disk --help
```

## 配置 S3 凭据

Access Key 和 Secret Key 由 S3 服务商的控制台或管理员提供。`s3disk` 通过 AWS
SDK 默认凭据链读取发布端凭据；它不会创建凭据，也不接受凭据命令行参数。

使用 AWS 时，优先使用 SSO profile 或 EC2/ECS/EKS workload role：

```sh
aws configure sso --profile s3disk
aws sso login --profile s3disk
export AWS_PROFILE=s3disk
```

如果 AWS 或其他 S3 兼容服务商提供的是固定 Access Key 和 Secret Key：

```sh
aws configure --profile s3disk
export AWS_PROFILE=s3disk
```

`aws configure` 会把 profile 写入 `~/.aws` 下的标准 AWS 配置文件；`s3disk` 不会
把可重复使用的凭据复制进自己的状态目录。临时凭据也可以通过
`AWS_ACCESS_KEY_ID`、`AWS_SECRET_ACCESS_KEY` 和 `AWS_SESSION_TOKEN` 提供。
环境变量凭据的优先级高于 profile。项目刻意不提供 `--profile` 参数，请使用
`AWS_PROFILE` 环境变量。

使用 handoff 文件的读取端不需要任何 S3 凭据。

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
默认使用跨平台的本机只读 WebDAV 服务：

```sh
s3disk serve webdav \
  --handoff /secure/workspace-a.handoff \
  --state-dir /var/lib/s3disk/reader
```

命令会输出类似 `http://127.0.0.1:53142/` 的地址。macOS 在 Finder 中选择
“前往 → 连接服务器”，填入该地址即可。每台读取端电脑都在本机运行这个服务；它
刻意不提供公网或远程监听。详见 [WebDAV 访问](docs/WEBDAV.md)。

Linux 可以继续使用原生 FUSE；macOS 用户如果愿意单独安装 macFUSE，也可以使用：

```sh
s3disk mount \
  --handoff /secure/workspace-a.handoff \
  --mountpoint /mnt/workspace-a \
  --state-dir /var/lib/s3disk/reader
```

macOS FUSE 路径使用 macFUSE 的 VFS/内核后端；当前 go-fuse 适配器尚未支持其
FSKit 消息传输。

共享多个 workspace 时，每个源目录独立发布。WebDAV 模式为每个 handoff 使用一个
进程和本机端口；FUSE 模式可以使用有资源上限的
[`mount-set`](docs/MOUNT_SET.md)。这些方式都不会合并目录，每个 workspace 仍有
独立信任和到期边界。

## 平台支持

| 平台 | 当前状态 |
| --- | --- |
| Linux | 支持 WebDAV 服务，也是主要原生 FUSE 目标；原生测试和真实 MinIO/FUSE 挂载测试已通过。 |
| macOS | 系统自带 WebDAV 已真实挂载通过，不依赖第三方软件；macFUSE VFS 是可选路径，发布证据仍待完成。 |
| Windows | WebDAV 服务和核心包可编译并运行原生测试，但 Explorer 集成尚未认证；FUSE 类 `mount` 未实现，发布端恢复状态也仍等待 Windows ACL 工作。 |
| FreeBSD | FUSE 适配器可以编译，但没有专用的原生生产测试基线。 |

Windows 需要 WinFsp 类文件系统适配器、Windows 路径/reparse point 和 ACL 加固、
驱动安装及生命周期处理，以及真实挂载测试。GitHub 托管的 Windows runner 已经在
运行可移植测试，因此主要缺口是实现，不只是缺少 Windows 机器。

完整状态见[兼容性矩阵](docs/COMPATIBILITY.md)。

## 当前工程边界

- 发布扫描不是正在变化的 workspace 的原子快照。严格时间点一致性需要 APFS/LVM/
  文件系统快照，或在扫描时暂停写入；详见[快照与恢复手册](docs/RECOVERY.md)。
- S3 中的不可变对象暂时没有垃圾回收。
- 已公开的规模测试是回归基线，不代表大目录、高变化率、长期挂载的容量承诺。
- WebDAV 不展示符号链接，因为协议没有可移植的 POSIX 符号链接表示；CLI 只允许
  监听本机回环地址。
- macOS 系统 WebDAVFS 对已经读取的文件可能保留约 60 秒缓存；服务端 revision
  会立即切换，但 Finder 中不会立刻可见。原生发布测试会验证无需重挂载即可最终刷新。
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
- `webdav`：跨平台只读 WebDAV 适配器。
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
