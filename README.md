# tls-mitm

## 最新说明

当前版本支持以下四种目标选择模式：

- `-target-ip + -target-port`
  只按目标 `IP:端口` 选择连接，不解析 `SNI`。
- `-target-host + -target-port`
  先用高优先级 `sniff` 句柄观察所有目标端口流量，只在 `ClientHello` 中的 `SNI` 命中目标域名后，才为该四元组创建专用阻断句柄并执行篡改。
- `-target-ip + -target-host + -target-port`
  按 `IP AND SNI AND 端口` 交集匹配。
- `-target-port + -unsafe-any-host`
  显式启用危险模式，按端口匹配所有主机。

当前实现的关键约束：

- `-target-port` 必填。
- 默认情况下，`-target-ip` 与 `-target-host` 至少提供一个，可以同时提供。
- 若未提供 `-target-ip` 和 `-target-host`，则必须显式添加 `-unsafe-any-host` 才允许启动。
- 当前篡改单位是“每条经出站最小 TCP 重组后确认完整的 TLS `Application Data record`”。
- 每条完整 `record` 只生成一个破坏点，破坏点由 `-mutate-offset` 决定。
- 任意覆盖该破坏点的首次发送或重传 TCP 包都会施加同样篡改。
- 当 `record` 数据长度不足以覆盖 `-mutate-offset` 时，会保守跳过该 `record`，不会让主循环退出。
- 无法确认完整 `record` 边界时，保守放行。
- 不做 TLS 解密。
- 当拿不到 `SNI` 时，`host-only` 模式会保守放行，不会猜测命中。

### 最新运行示例

仅按 IP 匹配：

```powershell
.\build\tls-mitm.exe -target-ip 93.184.216.34 -target-port 443 -observe-timeout 5s -mutate-offset 0
```

仅按域名匹配：

```powershell
.\build\tls-mitm.exe -target-host example.com -target-port 443 -observe-timeout 5s -mutate-offset 0
```

按 `IP + 域名` 交集匹配：

```powershell
.\build\tls-mitm.exe -target-ip 93.184.216.34 -target-host example.com -target-port 443 -observe-timeout 5s -mutate-offset 0
```

显式启用危险的“按端口匹配所有主机”模式：

```powershell
.\build\tls-mitm.exe -target-port 443 -unsafe-any-host -observe-timeout 5s -mutate-offset 0
```

### 最新参数说明

- `-target-ip`：按目标服务器 IP 匹配，可选
- `-target-host`：按 TLS `SNI` 域名匹配，可选
- `-target-port`：目标服务器端口，必填
- `-observe-timeout`：篡改后的观察窗口
- `-mutate-offset`：决定命中的 `Application Data record` 在密文区内哪个偏移生成破坏点；若 `record` 太短则保守跳过
- `-log-format`：日志格式，支持文本和 JSON
- `-unsafe-any-host`：显式允许按 `target-port` 匹配所有主机，属于高风险实验开关

下面保留的是前面的构建与运行说明；如果和本节冲突，以“最新说明”为准。

`tls-mitm` 是一个 Windows 专用的 TLS 密文篡改实验工具。

当前实现基于 `github.com/imgk/divert-go` 和 WinDivert，目标是：

- 按 `目标 IP:端口` 捕获出站 TCP/TLS 流量
- 按经出站最小 TCP 重组确认完整的 `Application Data record` 生成破坏点
- 每条完整 `record` 只生成一个破坏点，位置由 `-mutate-offset` 决定，并在首次发送或重传时保持同样篡改
- 若完整 `record` 的数据长度不足以覆盖 `-mutate-offset`，则保守跳过该 `record`
- 重注入修改后的数据包
- 继续观察对端是否出现 `RST`、`FIN`、疑似 `TLS alert` 或超时

## 推荐构建方式

项目当前优先推荐使用 `CGO` 构建：

```powershell
go build -tags "divert_cgo" -o .\build\tls-mitm.exe .\cmd\tls-mitm
```

这样做的效果是：

- 不再依赖外部 `WinDivert.dll`
- 仍然依赖 WinDivert 驱动文件，例如 `WinDivert64.sys`

原因是 `divert_cgo` 会把 `windivert.c` 编进程序，但抓包和重注入最终仍然要通过 WinDivert 驱动完成。

## 其他构建方式

### 默认构建

```powershell
go build -o .\build\tls-mitm.exe .\cmd\tls-mitm
```

这种方式会在运行时动态加载 `WinDivert.dll`，因此除了驱动文件外，还需要保证 `WinDivert.dll` 能被程序找到。

### 内嵌 DLL 构建

```powershell
go build -tags "divert_embedded" -o .\build\tls-mitm.exe .\cmd\tls-mitm
```

这种方式会把 `WinDivert.dll` 以内嵌资源的方式加载，运行时不需要单独放置 DLL 文件，但依然需要 WinDivert 驱动文件。

## 运行前置条件

运行本工具前需要满足：

1. Windows 管理员权限
2. 可用的 WinDivert 驱动文件
3. 如果使用默认构建方式，还需要 `WinDivert.dll`
4. 如果使用 `divert_cgo` 构建，还需要本机具备可用的 CGO/C 编译环境

WinDivert 驱动文件通常来自官方二进制发行包，常见为：

- `WinDivert64.sys`
- `WinDivert32.sys`

建议直接使用官方发布版本，避免从非官方来源复制 DLL 或驱动文件。

## 构建辅助脚本

仓库提供了一个 PowerShell 脚本，默认按 `divert_cgo` 方式构建：

```powershell
.\scripts\build.ps1
```

如果要显式指定其他模式：

```powershell
.\scripts\build.ps1 -Mode default
.\scripts\build.ps1 -Mode divert_cgo
.\scripts\build.ps1 -Mode divert_embedded
```

## MSYS2 Make 构建

如果你是在 Windows 的 `MSYS2` 环境里使用 `mingw32-make` 或 `make`，可以直接使用仓库根目录下的 `Makefile`：

```bash
make build
make test
```

默认行为：

- `make build` 默认按 `divert_cgo` 模式构建
- 输出文件默认是 `build/tls-mitm.exe`
- `divert_cgo` 模式要求 `MSYS2 MinGW64` 环境里可以找到 `gcc`
- `make` 运行时还需要 `go` 在 `PATH` 中，或者通过 `GO=...` 显式指定

可选目标：

```bash
make build-default
make build-cgo
make build-embedded
make clean
make help
```

也可以通过变量覆盖默认值：

```bash
make build MODE=default
make build OUTPUT=dist/tls-mitm.exe
make test GO=/mingw64/bin/go.exe
```

这个 `Makefile` 不依赖 PowerShell，内部直接调用 `go build` 和 `go test`。

## 运行示例

```powershell
.\build\tls-mitm.exe -target-ip 93.184.216.34 -target-port 443 -observe-timeout 5s -mutate-offset 0
```

参数说明：

- `-target-ip`：目标服务器 IP
- `-target-port`：目标服务器端口
- `-observe-timeout`：篡改后观察窗口
- `-mutate-offset`：决定命中的 record 在密文区内哪个偏移生成破坏点；若 record 太短则保守跳过
- `-log-format`：日志格式，支持文本和 JSON

## 当前验证范围

当前仓库已完成：

- `go test ./...`
- 抓包循环、连接状态机、TLS record 识别与密文翻转的单元测试

当前尚未在仓库内自动化完成的部分：

- 真实 WinDivert 联机实验
- 驱动分发与安装自动化
- 完整通用 / 双向 TCP 流重组
- TLS 解密
