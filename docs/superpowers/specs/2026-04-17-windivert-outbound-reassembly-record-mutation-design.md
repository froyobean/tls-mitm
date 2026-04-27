# WinDivert 出站最小重组与 Record 级篡改设计说明

## 1. 背景与目标

当前工具已经支持：

- 基于 `target-ip`、`target-host` 与 `target-port` 锁定目标连接
- 基于 `ClientHello/SNI` 做域名命中
- 对命中连接的首个完整 `TLS Application Data record` 进行一次密文字节篡改

但现有策略仍有两个明显局限：

1. 如果被篡改的发送包随后发生 TCP 重传，而重传包没有再次被篡改，则服务端最终可能收到未损坏的密文，实验结果不稳定。
2. 某些 `Application Data record` 可能完全跨越多个 TCP 包，单包内永远看不到完整 record，导致该 record 无法被识别和篡改。

本阶段目标是在不引入完整 TCP 协议栈和完整 TLS 状态机的前提下，新增“仅针对出站方向”的最小 TCP 重组能力，并把篡改策略升级为：

- 每条经出站最小重组后确认完整的 `TLS Application Data record` 只破坏一次
- 每条 record 只选择一个目标密文字节作为破坏点，位置由 `mutate-offset` 决定
- 任何覆盖该目标字节的首次发送或重传 TCP 包，都施加同样的篡改

这样可以同时满足“record 级归因清晰”和“TCP 重传不漏改”两个目标。

## 2. 范围界定

### 2.1 本阶段交付范围

本阶段只新增以下能力：

- 仅对 `客户端 -> 服务器` 的出站方向做最小 TCP 重组
- 基于连续出站字节流识别完整 TLS record
- 对每条完整 `Application Data record` 仅确定一个破坏点
- 若 `record` 数据长度不足以覆盖 `mutate-offset`，则保守跳过该 `record`
- 将该破坏点映射为绝对 TCP 序列号
- 对任何覆盖该绝对序列号的发送包或重传包施加同样篡改
- 基于入站 ACK 清理已不再可能重传的篡改点

### 2.2 非交付范围

本阶段明确不实现以下能力：

- 完整 TCP 状态机
- 完整乱序重排与窗口管理
- 入站方向 TCP 重组
- 多字节篡改单条 record
- 同一条 `Application Data record` 破坏多个位置
- TLS 解密
- TLS 完整状态机
- DNS 关联
- ECH 支持

## 3. 核心策略

### 3.1 判定单位

篡改的判定单位是：

- 经出站最小 TCP 重组后确认完整的 `TLS Application Data record`

不是：

- 单个 TCP 包
- 整条连接只一次

### 3.2 破坏次数

每条完整的 `Application Data record` 只破坏一次，具体指：

- 只选择一个目标密文字节
- 只对这个字节施加破坏
- 不因为该 record 跨多个包而对多个包分别选不同破坏点

### 3.3 执行单位

虽然判定单位是完整 record，但真正的篡改动作仍然发生在具体的出站 TCP 包上。

判断依据不是“这是不是原来的某个第 N 个包”，而是：

- 当前 TCP 包的 payload 序列范围是否覆盖某个已登记的目标破坏字节

只要覆盖，就在当前包内对应偏移上施加同样篡改。

## 4. 设计原则

本阶段遵循以下原则：

- 只升级“命中连接后如何篡改”的部分，不改变现有 `IP/SNI` 目标连接判定规则
- 只做最小出站重组，不做完整 TCP 实现
- 不按“某个原始包”追踪破坏点，而按“绝对 TCP 序列号”追踪破坏点
- 对无法确认完整 record 边界的流量，保守跳过，不猜测
- 对任何重传，保证同一破坏点得到一致篡改

## 5. 总体架构调整

### 5.1 保持不变的部分

以下逻辑保持不变：

- `target-ip` / `target-host` / `IP + host` 的目标连接判定
- `ClientHello/SNI` 的最小识别
- WinDivert 抓包、重注入与基本错误诊断
- 现有日志框架与基本结果分类模型

### 5.2 需要新增或扩展的部分

#### `internal/session`

新增或扩展每条连接的出站重组状态，包括：

- `nextSeq`：当前连续流期望的下一个序列号
- `segment buffer`：暂存已抓到但暂时不能安全消费的出站 segment
- `record parser state`：当前 TLS record 的解析进度
- `pending mutation points`：已决定破坏、但尚未被 ACK 覆盖的目标点

#### `internal/tcpmeta`

继续负责解析 TCP 元数据，但需要稳定输出以下信息给重组逻辑：

- `seq`
- `ack`
- payload 起始偏移
- payload 长度
- 该包 payload 覆盖的绝对序列号范围

#### `internal/tlsrecord`

从“单包内完整 record 识别”扩展为支持“对连续流缓冲区的最小 TLS record 解析”，职责变为：

- 从当前连续可用的出站字节流起点识别 TLS record 头
- 判断该 record 是否已在重组流中完整到齐
- 若完整，则返回 record 类型、总长度与数据区边界

#### `internal/mutate`

篡改策略从“单连接首次完整 record”升级为“record 级确定性破坏”，职责变为：

- 对每条完整 `Application Data record` 选择一个由 `mutate-offset` 指定的目标密文字节
- 记录该目标字节对应的绝对 TCP 序列号
- 当任何发送包覆盖该序列号时，在包内对应偏移施加同样篡改

## 6. 出站最小 TCP 重组

### 6.1 重组目标

出站最小 TCP 重组只需要回答三个问题：

1. 当前连接的连续可用出站字节流已经到哪里？
2. 从当前连续流位置开始，是否已经拼出一条完整 TLS record？
3. 若该 record 是 `Application Data`，其目标破坏字节的绝对 TCP 序列号是多少？

### 6.2 轻量 Segment 缓冲

轻量 `segment buffer` 的作用不是长期保存整条连接历史，而是服务于以下场景：

- record 跨多个 TCP 包
- 出站包发生轻度乱序
- 需要把“流内字节偏移”映射回“包内实际偏移”

缓冲中只保留当前解析窗口附近、仍可能被消费的 segment，不追求长期完整历史。

### 6.3 推进方式

每个出站 TCP 包到来时，处理顺序如下：

1. 根据四元组找到连接状态
2. 将当前 segment 放入缓冲
3. 按 `nextSeq` 尝试推进连续可用字节流
4. 对连续流起点尝试解析完整 TLS record
5. 若不是 `Application Data`，消费该 record 并继续推进
6. 若是 `Application Data`，按 `record.DataStart + mutate-offset` 生成该条 record 的目标破坏点；若偏移越界则保守跳过

## 7. 破坏点模型

### 7.1 Mutation Point 定义

对每条完整 `Application Data record`，生成一个 `mutation point`，至少包含：

- 连接四元组
- 所属 record 标识
- `targetSeq`：被破坏字节对应的绝对 TCP 序列号
- 原字节值
- 篡改后字节值
- 创建时间

### 7.2 为什么按绝对序列号追踪

不能简单记录“原来的第 2 个包要改”，因为：

- 重传包可能夹在后续 record 的多个发送包之间
- 重传时分段边界可能和原始发送不一致
- 原来在某个包中的目标字节，重传时可能落入另一个更大或更小的新包

因此，正确追踪方式必须是：

- 记住“哪一个绝对序列号字节需要被破坏”
- 之后只要某个包 payload 覆盖该序列号，就施加同样篡改

其中 `targetSeq` 的计算规则是：

- `targetSeq = record.DataStart + mutate-offset` 对应的绝对 TCP 序列号
- 若 `mutate-offset` 超出该条 `record` 的数据区长度，则不生成破坏点

## 8. 重传一致性

### 8.1 一致性要求

对于同一条完整 `Application Data record` 的同一个 `targetSeq`，必须满足：

- 首次发送时篡改结果固定
- 后续任何重传包再次覆盖该 `targetSeq` 时，得到完全相同的篡改结果

这样可以避免：

- 漏改重传导致服务端最终收到未损坏密文
- 多次重传时改出不同结果，导致实验不可解释

### 8.2 处理时机

每个出站 TCP 包到来时，优先执行：

1. 查找该包 payload 是否覆盖任何 `pending mutation point`
2. 若覆盖，则立即在当前包内对应偏移施加同样篡改
3. 然后再继续推进新的 record 解析和后续破坏点生成

也就是说：

- 先按已知破坏点处理当前包
- 再按连续流生成新的破坏点

## 9. 待确认篡改点的保留范围

这里的保留范围不按固定数量或固定时间定义，而按 TCP 语义定义为：

- 当前连接上所有仍未被对端 ACK 覆盖、因此仍可能发生重传的破坏点

### 9.1 清理条件

当满足以下任一条件时，移除该 `mutation point`：

1. 入站 ACK 已覆盖该 `targetSeq`
2. 连接结束
3. 超过安全兜底超时

### 9.2 第一版保护措施

为防止异常连接导致状态泄漏，第一版再增加：

- 每连接 `pending mutation points` 数量上限
- 超时清理

## 10. 数据流设计

升级后的主链路如下：

```text
WinDivert 捕获出站 TCP 包
  -> tcpmeta 解析 seq、ack、payload 边界与覆盖范围
  -> 根据 IP/SNI 规则判断该连接是否为目标连接
  -> 若是目标连接，先检查当前包是否覆盖已登记的 mutation point
  -> 若覆盖，则立即按既定规则篡改对应字节
  -> 将当前 segment 放入出站缓冲并推进 nextSeq
  -> 基于连续流解析完整 TLS record
  -> 若识别出新的完整 Application Data record，则生成新的 mutation point
  -> 重注入当前包
  -> 继续观察入站 ACK、RST、FIN 和其他结束信号
```

## 11. 异常路径与保守策略

第一版对以下情况统一采用“保守跳过，不猜测”：

1. 已见到 TLS record 头，但后续字节迟迟不完整
2. 收到乱序包，但短期内无法接成连续流
3. 无法确认某条 record 是否为完整 `Application Data`
4. 无法稳定计算 `targetSeq`
5. `record` 数据区长度不足以覆盖 `mutate-offset`

在这些情况下：

- 不生成破坏点
- 不误改当前包
- 仅继续缓冲、等待或放行

## 12. 测试策略

### 12.1 重组单元测试

覆盖以下场景：

- 连续 seq 的多包拼接
- 轻度乱序缓冲
- record 跨多个包
- 无法接成连续流时不误推进

### 12.2 TLS Record 级测试

覆盖以下场景：

- 单包内完整 `Application Data record`
- 多包拼成完整 `Application Data record`
- 非 `Application Data` record 正常跳过
- 不完整 record 不误判

### 12.3 Mutation Point 测试

覆盖以下场景：

- 目标破坏字节正确映射为绝对 TCP 序列号
- 包 payload 覆盖 `targetSeq` 时能在正确包内偏移上篡改
- 重传时再次命中相同 `targetSeq`
- 同一条 record 只生成一个破坏点

### 12.4 ACK 清理测试

覆盖以下场景：

- 入站 ACK 覆盖 `targetSeq` 后清理破坏点
- 未覆盖时不提前清理
- 连接结束与超时清理

### 12.5 回归测试

必须确保：

- `target-ip` 模式不退化
- `target-host` 模式不退化
- `IP + host` 交集匹配不退化
- 现有帮助信息和配置校验仍正确

## 13. 验收标准

本阶段完成后，应满足：

1. 单包完整 `Application Data record` 可以稳定生成破坏点并正确篡改
2. 跨多个 TCP 包的完整 `Application Data record` 也可以生成破坏点
3. 每条完整 `Application Data record` 只生成一个破坏点
4. 任何覆盖该破坏点的首次发送或重传包，都施加相同篡改
5. 入站 ACK 能正确清理不再可能重传的破坏点
6. 无法确认完整边界时不误改
7. 现有 `IP/SNI` 目标连接命中逻辑不退化

## 14. 与现有设计文档的关系

此前已有两份相关设计文档：

- `docs/superpowers/specs/2026-04-16-windivert-tls-ciphertext-mutation-design.md`
- `docs/superpowers/specs/2026-04-16-windivert-sni-domain-targeting-design.md`

本文件是在它们基础上的进一步演进，重点升级的是：

- 从“单连接首次完整 record 篡改”升级为“完整 record 级破坏点追踪”
- 从“单包识别”升级为“最小出站重组”
- 从“按包记忆”升级为“按绝对序列号追踪与 ACK 清理”

后续实现计划应以本设计为准。
