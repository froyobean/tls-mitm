# WinDivert TLS 密文篡改实验工具设计说明

## 1. 背景与目标

本阶段要实现一个基于 Go 的 Windows 专用 TLS 密文篡改实验工具，用于验证在不解密 TLS 的前提下，修改 TLS 密文记录中的少量字节后，对端是否会因为完整性校验失败而中止连接。

本阶段目标如下：

- 仅支持 Windows 平台
- 基于 WinDivert 在用户态拦截出站 TCP 数据包
- 按指定目标 `IP:端口` 锁定实验连接
- 识别目标连接中的 TLS `Application Data record`
- 在单个 TCP 连接上，仅对首个完整出站 `Application Data record` 篡改一次
- 将修改后的数据包重新注入网络栈
- 继续观察该连接的后续行为，并输出实验结果分类

本阶段工具的定位不是代理，不是通用 MITM 框架，也不是抓包回放器，而是在线包拦截、在线密文篡改、在线重注入的实验程序。

## 2. 范围界定

### 2.1 本阶段交付范围

本阶段仅实现以下能力：

- Windows 平台命令行工具
- 基于 WinDivert 的出站 TCP 抓包
- 目标 `IP:端口` 的连接过滤
- IPv4/TCP 元数据解析
- 最小 TLS record 边界识别
- 单连接单次密文字节翻转
- 包校验更新与重注入
- 篡改后连接行为观察与结果分类
- 控制台日志与结构化日志输出

### 2.2 非交付范围

本阶段明确不实现以下能力：

- TLS 解密
- TLS 完整状态机
- 证书签发或中间人证书链
- Linux 支持
- 按域名、PID 或进程名选流
- 单连接多次篡改
- TCP 流重组
- 通用代理与转发能力
- 自动安装或分发 WinDivert 驱动

## 3. 核心概念

### 3.1 在线拦截与重注入

本方案不是先保存数据包再回放，而是在连接进行过程中实时拦截当前经过协议栈的出站包，在用户态修改后立刻重新注入回网络栈。

处理链路如下：

```text
网络栈出站包
  -> WinDivert 拦截
  -> Go 程序解析并判断是否命中目标连接
  -> 识别 TLS Application Data record
  -> 修改密文字节
  -> 重算必要校验
  -> WinDivert 重新注入
  -> 数据包继续发往目标服务器
```

### 3.2 完整的 Application Data record

本设计中的“完整的 `Application Data record`”指的是：

- 当前 TCP payload 中存在一条 TLS record
- 该 record 的头部和整个 record 数据都完整落在同一个 TCP payload 中
- 该 record 的类型是 `Application Data`

这里的完整性只针对“当前单个 TCP payload 是否包含一整条 record”，不涉及跨 segment 的 TCP 流重组。

### 3.3 record 起始偏移

record 起始偏移指的是某条 TLS record 在“当前 TCP payload”中的起始位置，而不是在整个 IP 包中的偏移。

例如：

- `payload[0]` 开始就是一条 TLS record，则其起始偏移为 `0`
- 如果 `payload[20]` 才出现下一条完整 record，则其起始偏移为 `20`

该偏移用于计算：

- record 头部位置
- record 数据起始位置
- 要篡改的密文字节在 payload 中的实际索引

## 4. 总体设计

### 4.1 设计原则

本阶段采用“WinDivert 抓包/重注入 + 最小 TCP/TLS 边界识别 + 单连接单次篡改状态管理”的结构。

设计原则如下：

- 抓包与重注入逻辑集中在 WinDivert 交互层
- TCP/IP 解析与 TLS record 识别解耦
- TLS 只做最小 record 边界识别，不做解密与状态机
- 单个 TCP 连接只改一次，以保持实验因果清晰
- 篡改后继续观察连接行为，而不是只记录“已改包”

### 4.2 模块划分

#### `cmd/tls-mitm`

命令行入口模块，职责如下：

- 解析启动参数
- 构造实验配置
- 初始化日志输出
- 启动 WinDivert 抓包循环
- 处理退出信号与优雅停止

第一阶段先支持类似以下运行方式：

```bash
tls-mitm run --target-ip 93.184.216.34 --target-port 443
```

#### `internal/capture`

WinDivert 交互层，职责如下：

- 打开过滤句柄
- 接收命中条件的数据包
- 将原始包与地址元信息交给后续模块
- 在修改后重新注入数据包
- 协调必要的校验更新
- 辅助避免重复处理重注入回流

#### `internal/tcpmeta`

TCP/IP 元数据解析层，职责如下：

- 解析 IPv4 头和 TCP 头
- 提取源/目的 IP 与端口
- 提取 TCP 序号与确认号
- 计算 TCP payload 起始偏移与长度
- 判断是否存在有效 TCP payload

该模块不理解 TLS 语义，只负责把网络层和传输层边界算准。

#### `internal/tlsrecord`

最小 TLS record 识别层，职责如下：

- 在 TCP payload 中识别 TLS record 头
- 判断 record 是否完整落在当前 payload 中
- 判断 record 类型是否为 `Application Data`
- 计算 record 头部偏移、record 总长度与 record 数据区域

该模块不负责：

- TLS 解密
- 握手状态跟踪
- 跨 TCP segment 的 record 拼接

#### `internal/mutate`

篡改策略层，职责如下：

- 根据 record 边界确定可修改的密文区
- 对首个完整出站 `Application Data record` 的密文区翻转 1 个字节
- 输出篡改前后的字节信息

第一阶段仅实现一种策略：

- 对密文区中一个稳定偏移位置翻转 1 个字节

#### `internal/session`

连接状态与观察层，职责如下：

- 以 TCP 四元组标识连接
- 记录连接是否已经被篡改
- 记录篡改时间与篡改细节
- 维护篡改后的观察窗口
- 汇总该连接的实验结果分类

## 5. 数据流设计

第一阶段主链路如下：

```text
WinDivert 捕获出站 TCP 包
  -> tcpmeta 解析源/目的地址、端口、序号和 payload 边界
  -> 判断是否命中目标 IP:端口
  -> session 判断该连接是否已经改过
  -> tlsrecord 在当前 payload 中识别完整 TLS record
  -> 若存在首个完整 Application Data record，则 mutate 修改 1 个密文字节
  -> capture 重新注入已修改数据包
  -> session 继续观察该连接后续是否出现 RST、FIN、疑似 TLS alert 或超时
```

## 6. 包过滤与篡改策略

### 6.1 过滤策略

本阶段仅处理以下数据包：

- 出站方向
- TCP
- 目标 IP 命中配置项
- 目标端口命中配置项

即使 WinDivert 句柄已经做了初筛，程序内部仍需再次确认：

- 当前包确实包含 TCP payload
- 当前连接尚未被篡改
- payload 中存在完整 TLS record
- 该 record 类型为 `Application Data`

### 6.2 篡改时机

本阶段采用保守策略：

- 仅对单个 TCP 连接上的首个完整出站 `Application Data record` 动手
- 如果首次出现的 `Application Data record` 不完整，则跳过，继续等待后续包
- 一旦某次篡改成功，该连接状态变为“已篡改”，后续包只观察不再修改

这样做的原因如下：

- 更容易把对端异常归因到这一次密文破坏
- 避免同一连接被多次篡改后难以解释结果
- 不依赖 TLS 全状态机或 TCP 流重组即可形成最小可用实验

### 6.3 篡改方式

第一阶段仅支持以下方式：

- 在目标 record 的密文区选择一个固定偏移位置
- 将该位置的字节按位翻转一次

该策略要求：

- 不修改 record 头部
- 不改动 TLS 长度字段
- 不改动 IP/TCP 头部业务字段

## 7. 重注入与去重控制

### 7.1 重注入要求

数据包修改后，程序应通过 WinDivert 重新注入回网络栈，使该包继续沿原始方向发往目标服务器。

程序职责如下：

- 修改指定 payload 字节
- 协调必要校验更新
- 调用发送接口完成重注入

### 7.2 避免重复处理重注入回流

本阶段采用双保险：

- 优先利用 WinDivert 地址元信息区分原始捕获包与重注入包
- 对刚处理过的包记录轻量特征，若再次捕获到同一特征，则直接跳过

建议包特征至少包含：

- 四元组
- TCP 序号
- payload 长度
- 篡改位置

目标是避免程序对自己刚注入的包再次篡改，导致实验失真。

## 8. 日志与结果判定

### 8.1 日志事件

第一阶段记录以下四类日志：

- 捕获事件
- TLS 识别事件
- 篡改事件
- 观察结果事件

每次篡改事件至少应包含：

- 连接四元组
- 篡改时间
- record 长度
- 被修改的字节偏移
- 原字节值
- 新字节值
- 重注入结果

### 8.2 日志输出形式

第一阶段建议同时支持：

- 控制台可读日志
- `JSON Lines` 结构化日志

### 8.3 实验结果分类

本阶段将实验结果分为四类：

1. `明确失败`
   篡改后很快出现 `RST`、快速断连或疑似 TLS alert 后终止

2. `疑似失败`
   篡改后通信停滞，随后超时关闭

3. `无明显结论`
   已发生篡改，但在观察窗口内未出现明确异常信号

4. `实验未触发`
   连接上未命中完整 `Application Data record`，或篡改/重注入失败

## 9. 配置设计

本阶段建议保留最小必要配置项：

- `target_ip`
  要观察并篡改的目标 IP

- `target_port`
  要观察并篡改的目标端口，通常为 `443`

- `observe_timeout`
  篡改后连接观察窗口，例如 `5s`

- `log_level`
  日志级别，第一阶段支持 `info` 与 `debug`

- `log_format`
  日志格式，支持 `text` 与 `jsonl`

- `mutate_offset`
  record 密文区内的默认篡改偏移

配置来源优先仅支持命令行参数。

## 10. 测试策略

### 10.1 单元测试

覆盖内容如下：

- IPv4/TCP 头解析
- payload 起始偏移与长度计算
- TLS record 头识别
- `Application Data` 判定
- record 完整性判定
- 单连接只改一次的状态流转
- 篡改字节偏移计算与字节翻转逻辑

### 10.2 离线样本测试

使用人工构造的原始 IP/TCP/TLS 字节样本验证以下行为：

- 非 TLS payload 不误改
- 不完整 TLS record 不误改
- 完整 `Application Data record` 可被正确识别
- 目标 record 的密文字节会被正确翻转

### 10.3 Windows 实机实验

在管理员权限下进行如下验证：

- 启动工具并打开 WinDivert 句柄
- 指定已知目标 `IP:端口`
- 使用真实 HTTPS 连接访问目标
- 验证是否命中、是否只改一次、是否成功重注入、是否能观察到后续连接异常

## 11. 验收标准

第一阶段完成后，应满足以下条件：

- 能在 Windows 上以管理员权限启动
- 能成功打开 WinDivert 句柄
- 能捕获指定目标 `IP:端口` 的出站 TCP 包
- 能正确解析 TCP payload 边界
- 能识别单包内完整的 TLS `Application Data record`
- 能在单个 TCP 连接上只执行一次篡改
- 能成功重注入修改后的数据包
- 能避免重复篡改自己刚注入的包
- 能输出清晰的实验日志与结果分类
- 不会误改非目标连接、非 TLS 流量或不完整 record

## 12. 与旧方案关系

此前已有一份“显式代理与通用转发引擎”设计文档：

- `docs/superpowers/specs/2026-04-15-tls-proxy-core-design.md`

该文档作为归档基线继续保留，不删除、不覆盖。

当前文档是新的实验方向设计，优先级高于旧方案，后续实施计划与代码实现均以本设计为准。

## 13. 实施结论

第一阶段的推荐实施路径为：

- 先搭建命令行入口与 WinDivert 交互骨架
- 再实现 IPv4/TCP 基础解析
- 接着实现最小 TLS record 识别
- 补充单连接单次篡改策略
- 加入重注入去重控制与观察日志
- 最后补齐离线测试与 Windows 实机验证

该方案能够以最小复杂度交付一个真正可运行的 TLS 密文篡改实验器，同时避免过早进入 TLS 解密、TCP 重组或通用代理等高复杂度方向。
