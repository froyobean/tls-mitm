# DNS 域名拦截篡改设计说明

## 1. 背景

当前 `tls-mitm` 的域名拦截能力基于 TLS `ClientHello` 中的 `SNI`：

- `-target-host` 只表示 TLS `SNI` 域名
- `host-only` 模式通过出站 `ClientHello/SNI` 命中目标连接
- `SNI` 命中后为该 TCP 四元组创建专用 blocker
- 后续 TLS `Application Data record` 按 `-mutate-direction` 执行密文篡改

这种方案对普通 TLS 连接有效，但有几个自然边界：

- `ClientHello` 被拆包时，第一版 SNI 解析可能拿不到域名
- 客户端不发送 SNI 时无法命中
- 后续 ECH 场景下，明文 SNI 不再可靠
- 某些实验更希望先从 DNS 解析结果锁定目标 IP

本次设计目标是在保留现有 SNI 逻辑的前提下，增加基于明文 DNS 响应的域名命中能力。

## 2. 目标

本阶段实现以下能力：

- 新增 `-host-match sni|dns|both`
- 默认值为 `sni`，保持现有行为不变
- `dns` 模式通过明文 `UDP/53` DNS 响应建立目标域名到 IP 的短期映射
- `both` 模式使用 `SNI OR DNS` 命中语义
- DNS 命中后仍复用现有 per-connection blocker 和 TLS record 篡改链路
- 同一连接最多创建一个动态 blocker
- DNS 和 SNI 同时命中时记录两个来源，但不重复接管连接

## 3. 非目标

本阶段不实现以下内容：

- DNS 请求篡改或 DNS 响应篡改
- `TCP/53` DNS 响应解析
- DoH、DoT、DoQ 解析
- 完整 DNS 缓存系统
- 通配符域名匹配
- 公共后缀或 eTLD+1 规则
- IPv6 TCP 连接接管
- 完整通用双向 TCP 流重组

## 4. 配置语义

### 4.1 新增参数

新增命令行参数：

```text
-host-match <模式>
```

支持三个值：

- `sni`：仅使用现有 TLS `SNI` 命中逻辑
- `dns`：仅使用 DNS 响应解析出的目标 IP 命中逻辑
- `both`：使用 `SNI OR DNS` 命中逻辑

默认值：

```text
sni
```

### 4.2 与现有参数的关系

`-host-match` 只有在配置了 `-target-host` 时才有意义。

约束如下：

- 未提供 `-host-match` 时，行为等价于 `-host-match sni`
- `-host-match dns` 需要 `-target-host`
- `-host-match both` 需要 `-target-host`
- `-target-ip + -target-host + -host-match both` 时，目标连接可以通过 SNI 命中，也可以通过 DNS 命中的 IP 命中，但最终仍需要 `target-port` 匹配
- `-unsafe-any-host` 仍然只表示按端口匹配所有主机，不依赖 DNS 或 SNI

示例：

```powershell
.\build\tls-mitm.exe -target-host www.bing.com -target-port 443 -host-match both
```

## 5. DNS 观察范围

第一版只观察入站明文 DNS 响应：

```text
inbound and udp and ip and udp.SrcPort == 53
```

选择入站响应而不是出站请求的原因：

- 出站请求只能说明客户端想查某个域名，不能说明最终解析到哪些 IP
- 入站响应能提供 `A` 记录与 TTL
- 目标是把域名命中转换成后续 TCP 目标 IP 命中

第一版只解析 IPv4 UDP DNS 响应中的 `A` 记录。解析器可以识别 DNS name compression，避免无法处理常见响应。

## 6. DNS 响应解析

新增一个小型 DNS 响应解析单元，建议包名：

```text
internal/dnsmeta
```

职责：

- 解析 IPv4 UDP 包
- 验证 UDP 源端口为 `53`
- 解析 DNS header
- 只处理 response 包
- 跳过 question section
- 解析 answer section 中的 `A` 记录
- 支持 DNS name compression
- 对域名做标准化：小写、去掉末尾 `.`

返回结构建议：

```go
type Answer struct {
	Name string
	IP   netip.Addr
	TTL  time.Duration
}
```

如果响应中包含 `CNAME` 链，第一版可以先记录 CNAME 关系，再让目标域名通过 CNAME 指向的最终 `A` 记录命中。例如：

```text
www.example.com CNAME example-cdn.net
example-cdn.net A 93.184.216.34
```

当 `target-host == www.example.com` 时，应把 `93.184.216.34` 写入 DNS 命中缓存。

## 7. DNS 命中缓存

新增进程内 DNS 命中缓存，建议包名：

```text
internal/dnscache
```

因为当前工具一次只配置一个 `target-host`，缓存可以围绕目标域名简化设计：

```go
type Cache struct {
	now     func() time.Time
	byIP    map[netip.Addr]Entry
	maxTTL  time.Duration
	fallbackTTL time.Duration
}

type Entry struct {
	Host      string
	IP        netip.Addr
	ExpiresAt time.Time
	TTL       time.Duration
}
```

TTL 策略：

- `effectiveTTL = min(recordTTL, 10m)`
- `recordTTL <= 0` 时使用 `60s`
- 查询时顺手清理过期记录

DNS 命中缓存只用于判断“这个目标 IP 是否来自目标域名的 DNS 响应”。它不影响 DNS 包本身，也不改变系统 DNS 缓存。

## 8. 连接命中语义

### 8.1 `sni`

保持现有行为：

```text
连接命中 = SNI 命中 target-host
```

不打开 DNS observe 句柄，不解析 DNS 响应。

### 8.2 `dns`

使用 DNS 响应命中：

```text
连接命中 = 目标连接 DstIP 命中 DNS 缓存 && DstPort == target-port
```

如果 DNS 缓存中不存在该 IP，保守放行。

### 8.3 `both`

使用 OR 语义：

```text
连接命中 = SNI 命中 target-host || DNS 缓存命中 DstIP
```

这个模式下，SNI 和 DNS 都可以独立触发连接接管。

## 9. DNS 与 SNI 同时命中

同一 TCP 连接最多创建一个动态 blocker。

连接命中来源使用集合语义：

```text
match_sources = {dns, sni}
```

处理规则：

- DNS 先命中时，后续 TCP 连接目标 IP 命中即可创建 blocker，来源记录为 `dns`
- 同一连接随后 SNI 也命中，只把来源补充为 `dns,sni`，不重复创建 blocker
- SNI 先命中时，立即创建 blocker，来源记录为 `sni`
- 后续 DNS 缓存也能解释该 IP 时，只补充来源，不重复创建 blocker
- `trace_id` 仍然是连接级，同一连接保持一个 `trace_id`

如果 DNS 命中目标 IP，但同一连接里的 SNI 是其他域名，`both` 模式仍然按 OR 语义保持命中。此时应记录一条冲突日志：

```text
DNS 命中目标连接但 SNI 不同 target_host=www.example.com observed_host=other.example matched_ip=93.184.216.34
```

如果用户希望冲突时不篡改，应使用后续可扩展的 `sni-and-dns` 策略；本阶段不实现该策略。

## 10. 主循环集成

### 10.1 句柄编排

当 `-target-host` 存在且 `-host-match` 包含 DNS 时，应用入口额外打开 DNS observe 句柄。

建议新增过滤构造函数：

```go
func BuildDNSResponseFilter() string
```

返回：

```text
(inbound and udp and ip and udp.SrcPort == 53)
```

`RunHostMatchLoop` 需要扩展为可以接收 DNS observe handle。为减少对现有调用方的破坏，可以新增内部参数并保留现有导出函数的兼容包装：

```go
func RunHostMatchLoop(..., dnsObserveHandle *Handle, ...)
```

或者新增：

```go
func RunDomainMatchLoop(...)
```

推荐第一版扩展现有 host-match loop，因为 DNS 命中和 SNI 命中最终都服务于同一个“按连接创建 blocker”流程。

### 10.2 事件类型

新增事件类型：

```go
recvKindDNSObserve
```

DNS observe 事件只更新 DNS 缓存，不发送、不阻断、不重注入。

### 10.3 DNS 命中创建 blocker

出站 observe 收到 TCP 包时，按顺序判断：

1. 是否匹配目标端口
2. 是否已有 blocker
3. 是否可以通过 DNS 缓存命中目标 IP
4. 是否可以通过 SNI 命中目标域名
5. 任一命中则创建专用 blocker

DNS 命中时不要求当前包是 TLS `ClientHello`。这让 DNS 命中可以覆盖无 SNI 或 SNI 解析失败的连接。

## 11. 日志设计

新增日志字段：

- `host_match`
- `match_source`
- `match_sources`
- `resolved_ip`
- `dns_ttl`
- `effective_ttl`

建议日志：

```text
DNS 命中目标域名 target_host=www.example.com resolved_ip=93.184.216.34 dns_ttl=300s effective_ttl=300s
DNS 命中目标连接 trace_id=t000001 client_ip=... server_ip=93.184.216.34 target_host=www.example.com match_source=dns
SNI 命中目标域名 trace_id=t000001 target_host=www.example.com matched_host=www.example.com match_sources=dns,sni
DNS 命中目标连接但 SNI 不同 trace_id=t000001 target_host=www.example.com observed_host=other.example matched_ip=93.184.216.34
```

DNS 响应日志本身不一定有连接级 `trace_id`；目标连接日志必须保留 `trace_id`。

## 12. 测试策略

### 12.1 配置测试

覆盖：

- 默认 `HostMatch == "sni"`
- `-host-match sni`
- `-host-match dns`
- `-host-match both`
- 非法值报错
- `-host-match dns` 缺少 `-target-host` 报错
- help 文本包含 `-host-match`

### 12.2 DNS 解析测试

覆盖：

- 解析标准 UDP DNS response 中的 `A` 记录
- 解析压缩 name
- 忽略 query 包
- 忽略非 `A` answer
- CNAME 链指向 `A` 记录时能让目标 host 命中
- 畸形包返回错误，不 panic

### 12.3 DNS 缓存测试

覆盖：

- 写入 IP 后立即命中
- TTL 到期后不命中
- TTL 超过上限时被截断
- TTL 为 0 时使用 fallback

### 12.4 抓包循环测试

覆盖：

- `host-match=sni` 时 DNS 响应不触发 blocker
- `host-match=dns` 时 DNS 响应命中后，目标 IP 的 TCP 连接创建 blocker 并篡改
- `host-match=both` 时 SNI 命中仍保留
- `host-match=both` 时 DNS 先命中、SNI 后命中，只创建一个 blocker
- DNS 命中但 SNI 不同，按 OR 语义仍篡改并记录冲突日志

## 13. 风险与边界

DNS 命中有天然误伤风险：

- CDN 或共享 IP 可能同时服务多个域名
- DNS 响应可能来自系统缓存之外的应用自带解析路径
- DoH/DoT 不会被第一版看到
- 客户端可能直接连接 IP，不产生 DNS 响应

因此默认仍保持 `sni`，只有用户显式选择 `dns` 或 `both` 时才启用 DNS 观察。

## 14. 验收标准

满足以下条件视为完成：

1. 默认不改变现有 SNI 行为
2. `-host-match both` 下，DNS 响应命中后可让后续目标 IP 的 TLS 连接进入篡改链路
3. DNS 与 SNI 同时命中时，同一连接只创建一个 blocker
4. DNS 命中但 SNI 不同时，仍按 OR 语义篡改并输出冲突日志
5. DNS cache TTL 生效，过期 IP 不再命中
6. 所有新增单元测试和现有 `go test ./...` 通过
