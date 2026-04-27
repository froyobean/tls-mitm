# TLS Application Data 双向篡改方向控制设计说明

## 1. 背景

当前工具已经具备以下能力：

- 基于 `target-ip`、`target-host`、`target-port` 锁定目标连接
- 在 `target-host` 模式下通过 `ClientHello/SNI` 识别目标连接
- 基于出站最小 TCP 重组识别完整 `TLS Application Data record`
- 对每条完整的出站 `Application Data record` 只选择一个目标密文字节破坏一次
- 对任何覆盖该目标字节的首次发送或重传出站包施加相同篡改

现阶段的限制是：

- 篡改方向固定为 `客户端 -> 服务器`
- 无法只对 `服务器 -> 客户端` 的 `Application Data` 做实验
- 无法在同一条目标连接上同时验证出站和入站方向的完整性保护行为

本次设计目标是在不改变目标连接识别逻辑的前提下，引入一个显式的方向配置，让工具支持：

- 仅篡改出站 `Application Data`
- 仅篡改入站 `Application Data`
- 同时篡改出站和入站 `Application Data`

## 2. 目标

本次设计的目标如下：

- 新增命令行参数 `-mutate-direction`
- 支持三种方向值：
  - `out`
  - `in`
  - `both`
- 默认值为 `out`，保持与当前行为兼容
- 复用现有目标连接判定逻辑，不为入站单独发明新的目标识别机制
- 为入站方向新增一套与出站对称但独立的最小重组与破坏点追踪状态
- 在 `both` 模式下保证双向状态互不污染

## 3. 非目标

本次设计明确不包含以下内容：

- 不改写 `target-ip` / `target-host` / `unsafe-any-host` 的目标连接判定语义
- 不引入完整 TCP 状态机
- 不引入完整 TLS 状态机
- 不新增多字节篡改
- 不改变现有出站 record 级破坏策略
- 不让 `target-host` 在入站方向重新解析域名
- 不重做 WinDivert 句柄架构

## 4. 方案选型

### 方案一：只加方向开关，复用现有出站最小重组架构

做法：

- 保留现有出站重组和破坏点机制
- 为入站新增一套对称但独立的状态
- 通过 `-mutate-direction` 控制启用 `out` / `in` / `both`

优点：

- 与当前代码结构最兼容
- 改动范围可控
- 行为边界清楚

缺点：

- `session` 层状态会变大

推荐采用。

### 方案二：抽象为统一的双向重组引擎

做法：

- 把现有出站状态和逻辑抽成一个“方向无关”的统一重组组件
- 出站和入站只作为参数区分

优点：

- 长期结构更整洁

缺点：

- 当前稳定的出站链路需要大范围重构
- 这次需求本身并不要求先做这层抽象

当前阶段不采用。

### 方案三：只给入站补单包内完整 record 篡改

做法：

- 不给入站做最小重组
- 只在单个入站 TCP 包内刚好包含完整 `Application Data record` 时才篡改

优点：

- 实现快

缺点：

- 与当前出站能力不对称
- 会漏掉大量跨包 record
- 不符合现有 record 级、重传一致性的实验目标

不采用。

## 5. 配置设计

### 5.1 新增参数

新增命令行参数：

- `-mutate-direction`

允许值固定为：

- `out`
- `in`
- `both`

默认值：

- `out`

### 5.2 配置语义

#### `out`

- 只启用出站 `Application Data` 的最小重组与 record 级篡改
- 入站仍仅用于：
  - ACK 清理
  - 连接观察结果判定

#### `in`

- 不对出站 `Application Data` 做密文篡改
- 目标连接识别仍然使用现有逻辑完成
- 命中连接后，只对入站 `Application Data` 做最小重组与 record 级篡改

#### `both`

- 出站和入站都启用最小重组与 record 级篡改
- 两个方向各自生成各自的破坏点
- 两个方向各自处理重传一致性和 ACK 清理

## 6. 目标连接识别保持不变

本次设计不改变“命中哪条连接”的判定方式。

目标连接仍然通过以下条件识别：

- `target-ip`
- `target-host`
- `target-port`
- `unsafe-any-host`

其中对于 `target-host`：

- 仍然只通过客户端发出的 `ClientHello/SNI` 识别目标连接
- 入站方向不重新解析域名

也就是说，这次新增的是：

- 命中连接后，允许改哪一个方向

而不是：

- 如何重新定义目标连接

## 7. 状态设计

### 7.1 连接级共享状态

以下状态继续按连接共享：

- TCP 四元组
- 目标命中状态
- 观察窗口
- 观察结果
- `trace_id`

### 7.2 方向级独立状态

以下状态必须按方向拆开维护：

#### 出站方向

- `outboundReassembly`
- `outboundPendingMutationPoints`
- `outboundLastAck`

#### 入站方向

- `inboundReassembly`
- `inboundPendingMutationPoints`
- `inboundLastAck`

原因如下：

- 两个方向的序列号空间不同
- 两个方向的重传行为不同
- 两个方向的完整 record 边界推进不同
- 不能共享同一套 `targetSeq`

## 8. 数据流设计

### 8.1 连接识别阶段

先执行现有目标连接识别：

- 若使用 `target-ip`
  - 按目标 IP + 端口匹配
- 若使用 `target-host`
  - 先观察出站握手，解析 `SNI`
- 若两者都配
  - 按交集匹配

这一阶段不区分最终篡改方向。

### 8.2 出站方向处理

仅当 `mutate-direction` 包含 `out` 时：

1. 对 `客户端 -> 服务器` 的 payload 做最小重组
2. 识别完整 `Application Data record`
3. 为每条完整 record 生成一个出站破坏点
4. 对任何覆盖该破坏点的出站包施加篡改
5. 使用入站 ACK 清理出站待确认破坏点

### 8.3 入站方向处理

仅当 `mutate-direction` 包含 `in` 时：

1. 对 `服务器 -> 客户端` 的 payload 做最小重组
2. 识别完整 `Application Data record`
3. 为每条完整 record 生成一个入站破坏点
4. 对任何覆盖该破坏点的入站包施加篡改
5. 使用出站 ACK 清理入站待确认破坏点

## 9. ACK 清理规则

这是本次设计最重要的边界之一。

规则固定为：

- 处理出站包时：
  - 该包的 payload 只影响出站方向破坏点
  - 该包内的 ACK 只清理入站方向待确认破坏点

- 处理入站包时：
  - 该包的 payload 只影响入站方向破坏点
  - 该包内的 ACK 只清理出站方向待确认破坏点

也就是：

`payload 按本方向处理，ACK 按反方向清理`

如果这条规则做错，最容易出现：

- 出入站状态串线
- 破坏点提前或错误清理
- 重传一致性失效

## 10. both 模式边界

`both` 模式下必须满足以下边界：

1. 出站和入站 `reassembly.State` 完全隔离
2. 出站和入站 `pending mutation points` 完全隔离
3. 同一连接可以同时存在两个方向的破坏点
4. `trace_id` 仍按连接共享
5. 日志建议增加 `direction=out|in` 字段，避免双向命中时难以阅读

## 11. 日志要求

当前连接级 `trace_id` 继续保留。

为避免双向模式下日志可读性退化，关键日志建议增加方向字段：

- `direction=out`
- `direction=in`

建议覆盖以下日志：

- `SNI 命中目标域名`
- `SNI 未命中目标域名`
- `目标连接已命中，但当前包尚未覆盖破坏点`
- `命中完整 application data 破坏点`
- `连接观察结果`

其中：

- 连接级字段继续包含 `trace_id`
- 与 record 破坏相关的日志增加 `direction`

## 12. 测试策略

### 12.1 config 层

需要覆盖：

- 默认 `mutate-direction` 为 `out`
- `out` / `in` / `both` 为合法值
- 其他值返回错误
- 帮助信息包含新参数说明

### 12.2 session 层

需要覆盖：

- 出站重组状态与入站重组状态独立
- 出站 pending mutation points 与入站 pending mutation points 独立
- 入站 ACK 正确清理出站 pending mutation points
- 出站 ACK 正确清理入站 pending mutation points

### 12.3 capture 层

需要覆盖：

- `out` 模式下只改出站 record
- `in` 模式下只改入站 record
- `both` 模式下双向都可独立篡改
- `target-host + in` 模式下仍通过出站 `SNI` 命中连接后再改入站
- `target-host + both` 模式下命中连接后双向都可改

### 12.4 回归测试

需要确认以下能力不退化：

- `target-ip`
- `target-host`
- `unsafe-any-host`
- 出站最小重组
- record 级单点破坏
- 重传一致性
- `trace_id` 日志链路

## 13. 验收标准

完成后应满足：

1. 当 `-mutate-direction out`
   - 行为与当前版本一致
   - 只改出站 `Application Data`

2. 当 `-mutate-direction in`
   - 只改入站 `Application Data`
   - 出站仍可用于目标连接识别与 ACK 清理

3. 当 `-mutate-direction both`
   - 两个方向都可独立重组、生成破坏点并执行篡改
   - 两边状态互不污染

4. ACK 清理方向正确
   - 入站 ACK 只清理出站待确认破坏点
   - 出站 ACK 只清理入站待确认破坏点

5. 目标连接判定逻辑不变
   - 仍然先识别目标连接，再按方向决定是否篡改

6. `host-only` 模式不扩大影响范围
   - 不能因为加入入站篡改而重新影响非目标连接

## 14. 与现有设计文档的关系

本设计建立在以下既有设计之上：

- `docs/superpowers/specs/2026-04-16-windivert-sni-domain-targeting-design.md`
- `docs/superpowers/specs/2026-04-17-windivert-outbound-reassembly-record-mutation-design.md`
- `docs/superpowers/specs/2026-04-18-host-targeting-guardrails-design.md`
- `docs/superpowers/specs/2026-04-18-trace-id-log-correlation-design.md`

其中：

- 目标连接识别逻辑来自 SNI / IP 设计
- 当前 record 级篡改策略来自出站最小重组设计
- 连接级日志链路来自 `trace_id` 设计

本次设计只是在这些既有能力之上，引入“篡改方向控制”和“入站对称状态”。
