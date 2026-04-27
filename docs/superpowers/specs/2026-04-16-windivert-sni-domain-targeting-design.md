# WinDivert 基于域名拦截设计说明

## 1. 背景与目标

当前工具已经支持基于 `target-ip:target-port` 的 TLS 密文篡改实验，但在真实场景里，很多实验需求更适合按域名而不是固定 IP 发起。

本阶段新增目标如下：

- 保留现有基于 `target-ip` 的拦截能力
- 新增 `target-host` 配置项
- 基于 TLS `ClientHello` 中的 `SNI` 实现域名命中
- 仅对命中目标条件的连接执行现有“单连接单次篡改”逻辑
- 不引入 TLS 解密
- 不引入完整 TLS 状态机
- 不引入 TCP 流重组

本阶段新增能力的定位是“目标连接识别层增强”，而不是重写抓包、篡改和观察主链路。

## 2. 范围界定

### 2.1 本阶段交付范围

本阶段仅实现以下能力：

- 同时支持 `target-ip` 和 `target-host`
- 基于 TLS `ClientHello` 的 `SNI` 域名识别
- 按需触发 `SNI` 解析，而不是所有连接强制解析
- 按 `IP`、`SNI`、`端口` 的组合规则命中目标连接
- 复用现有单连接单次篡改、重注入和结果观察逻辑

### 2.2 非交付范围

本阶段明确不实现以下能力：

- DNS 解析结果与连接的自动关联
- ECH 支持
- 通配符域名匹配
- 后缀匹配
- 基于 HTTP Host 的域名识别
- TCP 流重组
- 跨 segment 的 `ClientHello` 拼接
- 多次篡改单连接

## 3. 匹配规则

### 3.1 配置项

配置项扩展为：

- `target-port`：必填
- `target-ip`：可选
- `target-host`：可选

约束如下：

- `target-port` 必填
- `target-ip` 和 `target-host` 至少要提供一个
- `target-host` 在内部会做标准化处理：去掉首尾空白并转成小写

### 3.2 命中规则

最终命中规则固定为以下三种：

1. 只配置 `target-ip`
- 命中条件：`DstIP == target-ip && DstPort == target-port`
- 不解析 `SNI`

2. 只配置 `target-host`
- 命中条件：`SNI == target-host && DstPort == target-port`
- 必须解析 `ClientHello`

3. 同时配置 `target-ip` 和 `target-host`
- 命中条件：`DstIP == target-ip && SNI == target-host && DstPort == target-port`
- 先按 `IP:端口` 初筛，再按 `SNI` 确认

### 3.3 域名比较规则

第一版域名比较采用：

- 大小写不敏感
- 精确匹配
- 不支持通配符
- 不支持后缀匹配

例如：

- `example.com` 只匹配 `example.com`
- 不自动匹配 `www.example.com`

## 4. 总体设计

### 4.1 设计原则

本阶段新增域名能力时遵循以下原则：

- 现有纯 `target-ip` 路径保持不变
- 只有配置了 `target-host` 时才尝试解析 `SNI`
- `SNI` 识别失败时保守放行，不做猜测
- 目标连接一旦命中，后续仍沿用现有成熟的篡改与观察逻辑

### 4.2 模块变更

#### `internal/config`

职责扩展如下：

- 支持 `target-host` 参数
- 校验“`target-ip` 与 `target-host` 至少存在一个”
- 规范化 `target-host`
- 帮助信息中体现新的匹配语义

#### `internal/tlshello`

新增模块，职责如下：

- 在当前 TCP payload 中识别 TLS `ClientHello`
- 从 `ClientHello` 的 `server_name` 扩展中提取 `SNI`
- 仅返回最小必要信息，不维护握手状态机

该模块不负责：

- TLS 解密
- 完整握手解析
- 跨包拼接
- ECH

#### `internal/capture`

职责扩展如下：

- WinDivert 过滤从“锁定目标 IP”放宽为“至少锁定目标端口”
- 内部增加目标连接判定流程
- 若配置了 `target-host`，对尚未完成域名判定的连接尝试解析 `ClientHello/SNI`
- 仅对已命中的连接继续进入现有篡改链路

#### `internal/session`

职责扩展如下：

- 除“是否已篡改”外，增加连接目标判定状态
- 支持以下状态：
  - `未判定`
  - `已命中`
  - `已排除`

这样可以避免同一连接重复解析 `SNI`。

### 4.3 保持不变的模块

以下模块逻辑保持不变：

- `internal/tcpmeta`
- `internal/tlsrecord`
- `internal/mutate`
- 当前结果分类主逻辑

也就是说，本阶段新增的是“目标连接识别层”，不是重写篡改主链路。

## 5. 数据流设计

新增域名能力后的主链路如下：

```text
WinDivert 捕获出站 TCP 包
  -> tcpmeta 解析源/目的地址、端口、序号和 payload 边界
  -> 若配置了 target-ip，则先做 IP:端口 初筛
  -> 若配置了 target-host，且该连接尚未完成域名判定，则尝试解析 ClientHello/SNI
  -> 若命中配置条件，则把该 TCP 四元组标记为目标连接
  -> 后续只对目标连接继续执行现有 Application Data 单次篡改
  -> session 继续观察该连接后续是否出现 RST、FIN、疑似 TLS alert 或超时
```

关键点如下：

- `SNI` 解析是按需触发，不是所有连接都强制做
- 一旦连接被标记为“已命中”，后续不再重复解析握手
- 若连接已被标记为“已排除”，后续直接放行

## 6. SNI 解析边界

第一版 `SNI` 解析只处理以下情况：

- 当前 TCP payload 中存在完整 TLS `Handshake record`
- 该握手消息是完整 `ClientHello`
- `ClientHello` 中包含完整可见的 `server_name` 扩展
- 能够成功提取出主机名

若上述条件不满足，则视为：

- 当前包无法完成域名判定

第一版不做：

- TCP 流重组
- 跨 segment 的 `ClientHello` 拼接
- 多个握手分片的累计缓存

这意味着：

- 如果 `ClientHello` 被拆包，第一版大概率拿不到 `SNI`
- 没拿到 `SNI` 就不视为命中

## 7. 未识别与未命中策略

### 7.1 只配置 `target-ip`

- 完全不涉及 `SNI`
- 按现有逻辑直接处理

### 7.2 只配置 `target-host`

- 若成功提取 `SNI` 且匹配，则命中
- 若成功提取 `SNI` 但不匹配，则标记为 `已排除`
- 若始终无法提取 `SNI`，则连接永远不进入篡改阶段

### 7.3 同时配置 `target-ip` 和 `target-host`

- 若 `IP` 不匹配，则直接排除
- 若 `IP` 匹配但 `SNI` 不匹配，则排除
- 若 `IP` 匹配但始终无法提取 `SNI`，则不进入篡改阶段

整体策略为：

- 宁可漏，不可误改
- 没拿到 `SNI` 就不猜测命中

## 8. 配置与帮助信息变化

帮助信息应调整为：

- `-target-ip <IP>`：按目标 IP 匹配，可选
- `-target-host <域名>`：按 TLS SNI 域名匹配，可选
- `-target-port <端口>`：目标端口，必填

示例应覆盖三种模式：

```text
tls-mitm -target-ip 93.184.216.34 -target-port 443
tls-mitm -target-host example.com -target-port 443
tls-mitm -target-ip 93.184.216.34 -target-host example.com -target-port 443
```

## 9. 测试策略

### 9.1 `config` 单元测试

覆盖以下场景：

- 只配置 `target-ip`
- 只配置 `target-host`
- 同时配置两者
- 两者都为空时报错
- 非法 IP 报错
- 非法端口报错
- `target-host` 标准化行为

### 9.2 `tlshello` 单元测试

覆盖以下场景：

- 正常提取 `SNI`
- 非 `ClientHello` 不命中
- record 不完整不命中
- 缺少 `server_name` 扩展不命中
- `SNI` 为空或格式异常不命中

### 9.3 `capture` 集成测试

覆盖以下场景：

- 只配 `target-ip` 时行为与当前一致
- 只配 `target-host` 时只有 `SNI` 命中连接会进入篡改
- 同时配置 `target-ip` 和 `target-host` 时必须两者同时命中
- 已排除连接不会重复解析
- 已命中连接只会篡改一次

### 9.4 回归测试

必须保证：

- 现有纯 `target-ip` 模式不回退
- 当前 `go test ./...` 的既有能力继续保持通过

## 10. 验收标准

本阶段完成后，应满足：

1. `target-ip` 单独使用时，行为与当前版本一致
2. `target-host` 单独使用时，只有 `SNI` 命中的连接才进入篡改阶段
3. 同时配置 `target-ip` 和 `target-host` 时，必须 `IP AND SNI` 同时命中
4. 未识别 `SNI` 的连接不会被误改
5. 单连接仍然只篡改一次
6. 全量测试通过

## 11. 风险与后续扩展

当前已知风险如下：

- `ClientHello` 跨包时第一版无法识别域名
- ECH 会使域名不可见
- 精确匹配不支持子域名自动覆盖

后续若要扩展，可考虑：

- 增加最小握手分片缓存
- 增加 DNS 关联
- 增加域名匹配策略配置

但这些均不属于本阶段交付范围。
