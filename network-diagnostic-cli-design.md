# 跨平台网络探测 CLI 设计文档

> 状态：最终工程设计基线（已完成全量一致性审计与对抗式反推审计）

## 1. 文档目的

本文定义一个面向日常网络连通性排查的跨平台 CLI 工具。它用于统一替代用户经常手工组合使用的 `ping`、`telnet`、`nc`、`traceroute` 等零散命令，但实现上不得调用这些外部命令；所有探测、分析与诊断都必须由程序自身通过成熟网络库或操作系统原生 API 完成。

本文是工程实施基线，描述产品边界、输入输出契约、核心模型、执行语义、诊断状态机、平台约束、错误与取消语义以及验收要求。后续实现不得改变这些对外语义；如确需调整，必须先显式修改设计基线。

本文沿用讨论中的占位命令名 `abc`。

---

## 2. 产品定位

### 2.1 目标

用户只需要输入目标地址，以及可选 TCP 端口：

```text
abc <address>
abc <address> <port>
```

工具自动完成必要的网络诊断，并输出：

1. 简洁、可理解的诊断结论；
2. 支撑该结论的最少关键证据；
3. 适合 Shell、脚本和 CI 使用的稳定退出状态。

产品面向网络知识有限的普通用户，因此用户侧必须保持极简；诊断复杂度全部收敛在核心内部。

### 2.2 核心原则

- **真实行为优先**：操作系统实际网络行为是最终运行事实，内部推导不得覆盖真实 socket / resolver 结果。
- **事实与解释分离**：先保存客观事实，再由核心形成结论；不能为了给出确定答案而伪造、覆盖或猜测事实。
- **按需诊断**：成功路径尽量短；只有已有证据不足以解释失败时才追加主动诊断。
- **有限诊断**：所有由本产品直接控制的主动探测步骤均必须有明确预算，不无限重试、不递归扩大诊断范围。操作系统正常名称解析属于受 OS 自身语义控制的基础事实获取，不人为套用产品 DNS Attempt 的超时规则。
- **用户侧极简，内部精良**：不把协议、地址族、并发、超时、重试等复杂控制暴露给用户。
- **跨平台语义一致**：macOS、Windows、Linux 的实现可以不同，但对外诊断语义必须一致。
- **只诊断，不修复**：不得修改接口、路由、DNS、防火墙、代理等持久网络配置。

---

## 3. 产品边界

### 3.1 支持平台

正式支持：

- macOS x86_64
- macOS ARM64
- Windows x86_64
- Windows ARM64
- Linux x86_64
- Linux ARM64

每个平台/架构交付一个独立可执行文件。

### 3.2 发布要求

- 每个平台/架构的 release archive 只包含一个可执行文件；
- Linux release 必须是完全自包含的静态 musl ELF，不得包含 `PT_INTERP`、
  `DT_NEEDED`、`RPATH`/`RUNPATH` 或 `GLIBC_*` 版本需求；
- Windows release 必须静态链接 Reach 使用的 C/C++ runtime，不得导入
  `VCRUNTIME*`、`MSVCP*`、`api-ms-win-crt-*` 或第三方应用 DLL；
- macOS release 可以依赖受支持的 `/System/Library` 与 `/usr/lib` 系统组件，
  但不得依赖 Homebrew、MacPorts、第三方 dylib/framework 或相对 runtime 路径；
- 不要求系统安装 `ping`、`traceroute`、`nc`、`telnet` 等命令；
- 不对 macOS / Windows 作不现实的“操作系统层面绝对纯静态链接”承诺，但产品自身不得依赖额外应用运行时才能启动。

上述合同以 archive 内实际 executable 的依赖表、hash、解包后执行和最低支持环境
实测共同裁决；仅有编译参数或 archive 文件数量不构成证明。

### 3.3 明确不做

本产品不是：

- 端口扫描器；
- 网络发现工具；
- 抓包或报文分析器；
- 通用 DNS 调试器；
- 网络修复工具；
- Shell；
- 应用层协议检查器；
- 长期网络监控服务。

端口存在时只检查目标 TCP 端口的连接能力，不根据端口号猜测 HTTP、HTTPS、SSH、数据库等应用协议。

---

## 4. 总体软件边界

系统至少划分为以下职责层次。具体模块、包或 crate 名称可在实现阶段确定，但职责边界不得改变。

### 4.1 CLI 表示层

CLI 只负责：

- 解析位置参数数量；
- 处理终端交互；
- 调用核心；
- 展示核心已经形成的结果；
- 映射稳定退出码；
- 处理可交付给应用的用户取消信号。

CLI 不负责：

- 判断 `address` 类型；
- 验证 IP / hostname；
- 解析或验证端口语义；
- 决定下一项探测；
- 判断网络故障原因；
- 从底层事实自行筛选关键证据。

### 4.2 Core 核心层

Core 是产品语义唯一事实来源，负责：

- 正式输入验证；
- 诊断请求建模；
- 初始网络现场快照；
- 目标解析与目标集合形成；
- 路由分析；
- TCP / ICMP / DNS 诊断状态机；
- Neighbor 证据管理；
- 多目标并发调度；
- 结果模型；
- 关键证据选择；
- 取消传播；
- 最终结论和状态分类。

### 4.3 平台适配层

平台适配层向 Core 提供操作系统事实与网络能力，包括：

- 接口枚举；
- 路由事实；
- 系统名称解析配置；
- 系统正常名称解析；
- Neighbor 状态；
- TCP Connect；
- ICMP Echo 与 TTL/Hop Limit 能力；
- 必要的 DNS transport；
- monotonic clock；
- socket 运行事实；
- 平台能力与权限可用性。

平台适配层不得偷偷改变 Core 的诊断语义。

---

## 5. CLI 契约

### 5.1 命令形式

```text
abc <address> [port]
```

位置参数语义固定，不增加 TCP/UDP 选择参数、地址族选择参数或复杂诊断模式参数。

### 5.2 `address`

`address` 只允许：

- hostname；
- IPv4 literal；
- IPv6 literal；
- 带明确 zone/scope 的 IPv6 literal，例如 `fe80::1%en0`。

不接受：

- URL；
- CIDR；
- IP 范围；
- 主机列表；
- 其他复合目标表达式。

### 5.3 `port`

提供 `port` 时，它始终表示目标 **TCP 端口**。

Core 负责：

- 数值解析；
- `1..=65535` 范围校验。

CLI 不根据端口号猜测协议。

### 5.4 输入解析与分类

Core 的输入处理分成两个阶段，避免无效输入触发无意义的系统采样。

**阶段 A：纯本地词法/语义解析**

在任何网络现场采集之前完成：

1. 严格解析 `port`，并校验 `1..=65535`；
2. 严格尝试 IP literal 解析；
3. 成功则得到 IPv4 或 IPv6 语法对象；
4. 若不是合法 IP literal，再使用 Core 统一的 hostname parser 校验；
5. 失败则直接返回输入错误，不采集网络现场，也不产生任何主动流量。

hostname parser 必须是 Core 的跨平台统一依赖；不得让各 OS resolver 自己决定“这个字符串算不算合法 hostname”。具体语法细节优先由成熟、标准兼容的 parser 提供，并用固定、版本化的接受/拒绝测试语料锁定跨平台行为。parser 或依赖升级不得静默改变既有输入兼容性；任何接受/拒绝集合变化都必须先作为产品输入契约变更审计。

该阶段不执行 DNS、路由查询或任何主动网络操作。

### 5.5 IPv6 scope

IPv6 zone/scope 同时允许：

- 接口名称；
- 接口 index。

scope 的**语法解析**发生在输入解析阶段；scope 到真实 OS interface identity 的**绑定**必须基于本次诊断的接口快照完成。

以下情况必须拒绝：

- 接口不存在；
- scope 已失效；
- 无法唯一映射；
- 实现无法可靠确认其身份。

不得忽略或猜测 scope。

因此 scoped IPv6 在接口快照形成之前只能处于“已解析但未绑定”的中间状态，不能提前冒充已经形成完整正式目标。

## 6. 一次正式诊断的生命周期

一次命令运行就是一次独立、自包含的诊断。执行顺序固定为：

```text
CLI 参数结构解析
  -> Core 纯本地输入解析（address / port / scope syntax）
  -> 输入非法：ExecutionError，结束；不得采集网络现场
  -> 初始被动网络现场
  -> scoped IPv6 绑定到真实 interface identity
  -> hostname：调用系统正常名称解析
     IP literal：直接形成正式目标
  -> 正式目标初始路径分析
  -> 必要时取得当前目标/依赖的定向路径事实
  -> 必要 Neighbor 前置事实
  -> 按请求类型执行主动主检查
  -> 失败时按证据逐层追加有限诊断
  -> 所有必要分支进入终态
  -> Core 形成结论 + 关键证据
  -> CLI 输出与退出
```

不同命令运行之间默认不复用：

- 历史诊断结果；
- 产品自己的路由判断；
- 产品自己的 DNS 结果缓存；
- Neighbor 诊断状态；
- 其他会影响当前结论的历史状态。

每次命令均以本次初始现场与本次主动证据为准。

### 6.1 顶层终止优先级

一次执行最终只能进入以下三类顶层终态之一：

1. **Cancelled/Interrupted**：用户主动取消，退出码 130；
2. **ExecutionError**：某个完成本次请求所必需的步骤无法可靠执行，退出码 2；
3. **Completed Diagnostic**：所有必要分支可靠进入终态，再按检查结果映射退出码 0 或 1。

优先级固定为：

```text
Cancelled > ExecutionError > Completed Diagnostic
```

出现 ExecutionError 时，已经取得的事实可以保留用于内部诊断或错误说明，但不得把未完成的整次请求包装成正常完成的 0/1 诊断结果。

## 7. 初始被动网络现场

### 7.1 总原则

通过纯本地输入解析后，Core 采集诊断开始阶段的操作系统网络现场。

该阶段：

- 只读；
- 不产生主动网络流量；
- 为后续诊断提供时间基线；
- 不因为后续探测结果而回写或重解释初始事实。

初始全局快照只包含：

1. 网络接口；
2. 路由与路径选择相关事实；
3. DNS / 名称解析配置事实。

不无条件采集：

- 完整 ARP/NDP 表；
- 防火墙状态；
- 全部 socket；
- 全系统网络统计；
- 其他与当前目标尚无直接关系的信息。

### 7.2 快照不是伪原子事务

跨接口、路由、resolver 配置的系统采样通常无法在三个操作系统上形成真正原子的一瞬间事务，因此实现不得伪造“所有字段严格同时刻”的保证。

`InitialNetworkSnapshot` 必须至少保存：

- `capture_started_at`；
- `capture_completed_at`；
- 各主要子采样的时间/provenance；
- 每个子能力的 Available / Unavailable 状态。

如果采样窗口内网络状态发生变化，导致接口、路由、resolver 事实互相冲突：

- 保留冲突；
- 标记 snapshot inconsistency / capability limitation；
- 后续实际 socket / resolver 行为仍作为运行事实；
- 不通过猜测把它们修补成一份虚假的“原子快照”。

某个被动现场能力不可用时，不自动导致整次命令失败。只有当缺失事实使当前请求的**主检查或必要目标形成**无法可靠执行时，才升级为 ExecutionError；否则按能力受限继续。

### 7.3 接口事实

必须枚举所有操作系统可见接口，而不是只枚举“默认接口”。

每个接口至少保存：

- OS 接口身份/index；
- 可读名称；
- administrative state；
- operational state；
- loopback 属性；
- 当前全部 IPv4 / IPv6 地址；
- 每个地址的 prefix length；
- 必要的 IPv6 scope/interface 绑定信息。

不存在或无法确定的属性保留 Unknown，不伪造默认值。

默认不采集 MAC、MTU、链路速率、统计计数器等与当前诊断没有直接要求的事实。

### 7.4 路由与路径选择事实

必须保存诊断开始时操作系统当前可见、且可能影响目标路径选择的 IPv4 / IPv6 路由事实。

每条 route 至少能够表达：

- address family；
- destination prefix；
- next-hop 语义，包括 direct/on-link；
- egress interface identity；
- route behavior/type。

如果操作系统提供且确实参与实际路径选择，还应保留：

- metric / priority；
- routing table / domain / compartment；
- preferred source；
- 其他平台特有路径选择事实。

**路由条目与路径选择策略必须分离。** Linux policy rule、Windows compartment/route policy、macOS scoped route 等如果会影响真实选择，应作为独立 `path_selection_facts` / `routing_policy_facts` 保留，不能为了方便硬塞进普通 route object，也不能因为公共模型没有字段就丢掉。

若平台无法公开足以重建某项路径选择的策略事实，Core 的静态路径判断必须降为 Unknown，而不是声称自己能够完全复刻内核选路。

### 7.5 名称解析配置事实

初始现场必须保存可能影响系统名称解析行为的配置事实。

不得把它简单压缩成一个全局 DNS Server 列表。

根据平台实际能力，应保留可能有意义的：

- resolver server / local stub；
- 接口绑定；
- domain/split-DNS scope；
- search domain；
- resolver/source 优先级或配置顺序；
- OS 可公开的非 DNS 名称解析来源或策略事实；
- 其他会影响 resolver 选择的事实。

该配置快照只用于解释系统 resolver 行为，不用于自行替代系统 resolver。平台不能公开的内部 resolver 选择事实必须保持 Unknown。

## 8. Neighbor 事实与并发协调

### 8.1 不做全表快照

完整 Neighbor Cache 不属于初始全局现场。

Neighbor 前置事实的时间语义必须精确限定为：

> 在某个具体目标或依赖分支中，**本产品第一次可控且可能改变该 Neighbor 状态的主动操作之前**读取到的状态。

不得把它描述为“整次命令发生任何网络活动之前的 Neighbor 状态”，因为系统正常 resolver 等 OS 内部操作可能在正式目标形成前已经产生网络流量，而产品无法可靠证明其内部数据路径。

### 8.2 定向当前路径事实

在第一次产品可控的 Neighbor-dependent 主动操作之前，Core 应优先通过平台提供的**定向当前路径查询**确认该操作此刻所依赖的：

- address family；
- egress interface；
- on-link / remote；
- next-hop（如存在）；
- 其他能够可靠取得的当前路径事实。

该定向查询是被动事实读取，不替代初始路由快照。**它本身不得产生任何目标网络流量，也不得通过会实际发包的“试连接/试发送”来伪装成本地路径查询。**若平台没有可证明为纯本地、只读的定向路径查询能力，则该能力标记为 Unavailable，并按 Capability 规则继续，而不是为了取得路径事实提前污染后续 Neighbor/主检查证据。

如果当前定向路径与初始快照推导不一致：

- 两者都保存；
- Neighbor 前置采样以当前可确认的实际依赖为准；
- 不允许让旧快照强行覆盖当前路径事实。

如果当前实际 Neighbor 无法可靠确定，就不得伪造 Neighbor pre-state；该证据标记为 Unavailable/Unknown。

### 8.3 Neighbor identity

Neighbor identity 至少由以下事实共同确定：

- address family；
- OS interface identity；
- Neighbor address。

- on-link 目标：相关 Neighbor 是目标自身；
- 非 on-link 目标：相关 Neighbor 是当前实际 next-hop。

Neighbor 事实不得与 route fact 混为同一对象。

### 8.4 多分支共享 Neighbor

多个并发目标或依赖诊断共享同一个实际 Neighbor 时：

- 该共享 Neighbor 的同一时间边界前置状态只可靠采集一次；
- 采集必须发生在任何相关产品可控主动操作之前；
- 所有相关分支引用同一份不可变前置证据；
- 不为每个分支伪造独立的“探测前 Neighbor 状态”。

协调只保护“首次前置采样”这个事实边界，不因此串行化整个目标诊断。

### 8.5 Neighbor 状态解释

必须严格区分：

- resolving / incomplete；
- usable；
- explicit terminal failure；
- unknown / unavailable。

`INCOMPLETE` 或平台等价状态不得等价为 Neighbor 失败。

如果主动探测后，相关 Neighbor 进入操作系统明确的终止失败状态，可以确认：

> 本机未能建立该路径所必需的本地二层邻居关系。

但不能因此断言 next-hop 设备本身发生故障。

### 8.6 Neighbor 被动收敛观察

如果主动探测后 Neighbor 仍处于解析进行中：

- 不立即判定失败；
- 不自行发送额外 ARP/NDP；
- 进入有界被动观察；
- 最大观察时间 2 秒；
- 使用单调时钟；
- 约 200 ms 观察粒度，或使用平台可靠状态变更通知；
- 一旦进入可用、明确失败或其他足以终止判断的状态，立即结束观察。

2 秒后仍未收敛：

> Neighbor Resolution Indeterminate

不得改写为失败。

## 9. hostname 的正式系统名称解析

### 9.1 第一解析路径

`address` 是 hostname 时，第一个真实解析动作必须使用目标操作系统的**正常名称解析机制**。

不得在此之前：

- 主动探测 DNS Server；
- 自己发送 DNS Query；
- 用初始 DNS 配置构造替代 resolver。

平台适配层应使用 OS 正常地址解析 API 请求 IPv4/IPv6 地址集合，不得由产品自行强制只解析某一个地址族，也不得在 Core 外私自重排结果。具体 API 可以不同，但“让 OS 正常 resolver 产生地址结果”的语义必须一致。

Linux 静态 release 是这一规则的明确平台实现边界：静态 musl 的
`getaddrinfo` 不得冒充宿主 glibc 的任意 NSS。Linux 适配层必须先读取并按顺序
执行宿主 `/etc/nsswitch.conf` 的 `hosts:` 策略，并使用 `/etc/hosts` 与
`/etc/resolv.conf` 完成当前实现能够忠实支持的 `files`/`dns` 路径。执行路径上
出现无法忠实执行的 source、action 或 resolver 选项时，必须以 Required
Capability Unavailable / ExecutionError(2) 结束；不得跳过该 source、猜测目标或
把 failure-only Direct DNS 提升为正式目标。若前置受支持 source 已按 NSS 策略
终止，后续未执行 source 不造成无意义失败。

### 9.2 系统 resolver 的时间语义

系统正常 resolver 是需要被观察的 OS 行为，不属于第 18 章 direct DNS Attempt。

因此：

- 不套用 DNS UDP 2 秒或 DNS TCP 5 秒预算；
- 不为了缩短命令而给系统 resolver 人为改成另一套更短的网络超时；
- resolver 自身的 retry/timeout/cache/search 行为由 OS 正常解析机制决定；
- 用户可通过统一取消语义终止命令。

这不是允许产品无界重试：Core 自己不得在 system resolver 外再增加无界重试循环。

### 9.3 成功结果

系统名称解析成功时，必须保存：

- 原始 resolver 返回的全部 IPv4 / IPv6 地址；
- 原始返回顺序；
- 原始重复项。

随后另外派生一个“有序唯一正式目标序列”：

- 按原始顺序；
- stable dedup；
- 第一次出现决定唯一目标的顺序；
- scoped IPv6 的 scope/interface 属于目标身份的一部分。

原始 resolver 事实不得因去重而被修改。

如果 resolver 调用表面成功但没有形成任何可用 IPv4/IPv6 地址，必须作为“无正式目标的解析结果”进入 hostname 结果分类；**不得因为正式目标集合为空而按数学空集合规则判定为成功。**

### 9.4 多目标诊断

每个有序唯一 IP 都必须形成一个独立正式目标并独立完成诊断。

- 一个目标成功不取消其他目标；
- 一个目标失败不取消其他目标；
- 最多同时活动 4 个独立目标诊断；
- 超过 4 个按有序唯一目标序列排队；
- 每个目标内部诊断步骤仍严格串行；
- 并发完成顺序不得改变最终展示顺序。

调度器不得为全部待处理目标预先创建无限数量活动任务；活动工作集固定有界。若资源耗尽导致无法继续完整处理 resolver 已返回的正式目标，不得静默截断目标集合，必须进入 ExecutionError。

## 10. 正式目标的初始路径分析

每个具体目标 IP 在任何产品可控主动探测之前，Core 必须先基于初始路由/路径选择现场形成诊断开始时的路径分析结果。

至少区分：

- `UsablePath`：可确认存在可用路径；
- `DefinitiveNoPath`：可确认不存在可用路径，或存在明确 local reject/blackhole/unreachable 行为；
- `UnknownPath`：仅凭初始事实无法可靠确定。

路径分析可包含：

- 匹配的路由事实；
- egress interface；
- next-hop；
- source-address 相关事实；
- 路由策略事实；
- 路由冲突或不确定性。

### 10.1 静态分析不能冒充内核最终行为

内部可以形成 source address 候选或预期，但不得仅凭内部推导强制绑定后续 socket。

实际主动网络操作仍使用操作系统正常 source selection。若可观测，必须记录操作系统最终实际使用的 local endpoint。

静态路径推导不能覆盖实际 socket 运行结果。

### 10.2 `DefinitiveNoPath` 必须短路主动主检查

`DefinitiveNoPath` 只能建立在**足以支持该结论且彼此不冲突的路径事实**上。若与该目标相关的 route / policy / interface 事实存在 Snapshot Inconsistency、关键 Capability Unavailable，或无法证明所需策略事实完整，则必须降为 `UnknownPath`，不得为了减少探测而把“不知道”写成“明确无路”。

只有当静态事实足以形成 `DefinitiveNoPath` 时，Core 才允许在不发送主动目标流量的情况下结束该目标主检查：

- 不发 TCP Connect；
- 不发 ICMP Echo；
- 不进入 Neighbor/gateway/path 主动诊断；
- 结果为网络检查未满足，并以本机路径事实作为关键证据。

如果路径只是 Unknown，则不能因为“看起来像没路”而跳过真实主检查；应继续使用操作系统正常 socket/ICMP 行为取得运行事实。

### 10.3 当前定向路径只用于真实依赖绑定

在后续需要 Neighbor 前置事实时，必须按照第 8.2 节重新取得当前定向路径事实。初始路径分析回答“诊断开始时看到什么”，定向查询回答“下一项产品可控操作现在会依赖什么”；两者语义不得混合。

## 11. 带 `port` 的主检查：TCP Connect

### 11.1 首个主动目标探测

用户提供 `port` 时，第一个主动目标探测必须是：

> 对具体目标 IP 与用户指定 TCP 端口执行正常 TCP Connect。

不得先用 ICMP 判断目标是否“可 ping”。

### 11.2 TCP Connect Attempt

每个具体 Connect Attempt：

- 最大 deadline：5 秒；
- 使用单调时钟；
- 从实际发起 connect 开始计时；
- 成功立即结束；
- 操作系统返回明确错误立即结束；
- 只有始终没有明确结果直到 deadline 才是 `TCP Connect Timeout`。

该 5 秒不包含 DNS、路由分析、Neighbor 前置读取等准备阶段。

### 11.3 第一次结果必须永久保留

第一个 Connect Attempt 的结果不得被后续尝试覆盖。

对明确失败，例如：

- Connection Refused；
- 明确无路由类错误；
- 其他已经给出充分确定信息的结果；

不做机械重试。

### 11.4 Timeout 复验

第一次 TCP Connect Timeout 后：

- 立即执行第二个独立 Connect Attempt；
- 不插入人工 sleep；
- 第二次仍为 5 秒 deadline；
- 最多两次；
- 两次结果独立保存。

第二次成功不得把第一次 Timeout 改写成“从未失败”。

如果第一次 Timeout、第二次主检查 Connect 成功，该目标必须标记为 **SatisfiedWithAnomaly / Intermittent**，而不是干净成功。它保留真实连通成功，但进程整体不得因此返回退出码 0。

### 11.5 Connect 成功

一旦某个具体 `IP:port` 的主检查 Connect 成功：

- 该目标 TCP 连通性主检查完成；
- 不再追加 ICMP、gateway、path probe；
- 不根据端口执行应用协议探测；
- 记录必要 socket 运行事实后立即正常关闭连接；
- 不发送应用数据；
- 不人为保持连接；
- 不通过特殊 linger 强制 RST。

成功 Attempt 至少保存：

- Attempt identity；
- address family；
- actual local endpoint；
- actual remote endpoint；
- connect start time；
- duration；
- success result。

### 11.6 Connection Refused

`Connection Refused` 表示本次 Connect 收到了明确拒绝结果，因此提供了很强的双向网络响应证据。

结论边界：

- 不能再描述成普通“网络不通”；
- 不需要额外 ICMP 来验证基本可达性；
- 不能断言一定是目标应用未监听；
- 可能来源于目标主机或中间设备的主动 reject。

### 11.7 No Route / Network Unreachable / Host Unreachable

遇到明确网络错误时，必须与诊断开始时的路由现场交叉验证。

- 一致：可形成更强的本机路径失败结论；
- 不一致：两个事实同时保留；
- 不得让静态路由推导覆盖实际 socket 结果；
- 不得仅凭错误名称宣称目标主机故障。

---

## 12. TCP Timeout 后的目标 ICMP 诊断

只有同一 `IP:port` 连续两次 TCP Connect Timeout 后，才进入目标 ICMP Echo 诊断。

### 12.1 目标 ICMP Attempt 预算

- 最多两个独立 Attempt；
- 每个最大 deadline 2 秒；
- 单调时钟；
- 第一次 Echo Reply 或明确错误立即结束 ICMP 阶段；
- 只有第一次完全 Timeout 才执行第二次；
- 不额外 sleep；
- 两个 Attempt 独立保存。

### 12.2 高层结果类别

Core 至少能够区分：

- Echo Reply；
- Destination Unreachable；
- Time Exceeded；
- Packet Too Big（适用时）；
- Parameter Problem；
- Other ICMP Message；
- Timeout。

同时保留平台/协议提供的必要原始类型信息，不把 IPv4 / IPv6 差异全部抹平。

### 12.3 TCP Timeout + ICMP Echo Reply

如果 TCP 连续 Timeout，但目标 ICMP Echo Reply 成功：

可形成：

> 目标 IP 当前存在相应 IP 层双向响应，但指定 TCP 端口持续未响应。

此时不再为了“证明网关正常”去探测 gateway。

不得进一步猜测防火墙、应用或中间设备的具体根因。

### 12.4 TCP Timeout + ICMP Timeout

如果目标 TCP 两次 Timeout，目标 ICMP 两次也 Timeout：

1. 先重新读取该实际路径依赖的具体 Neighbor 状态；
2. 与首次主动操作前状态对照；
3. 必要时完成 Neighbor 被动收敛观察；
4. 只有 Neighbor 证据仍不足，才考虑下一层主动诊断。

---

## 13. 非 on-link 目标的 first-hop 诊断

仅在以下条件全部成立时，允许检查实际 next-hop：

- 目标不是 on-link；
- TCP Timeout x2；
- 目标 ICMP Timeout x2；
- 实际 next-hop Neighbor 已确认可用；
- 现有证据仍不足。

### 13.1 next-hop ICMP

对实际 next-hop 使用 ICMP Echo：

- 最多两个 Attempt；
- 每个 1 秒 deadline；
- 第一次明确结果立即结束；
- 第一次 Timeout 才执行第二次；
- 不猜 TCP 端口；
- 不使用应用协议。

next-hop Echo Reply 可以增强：

> 本机到第一跳存在直接双向 IP 响应。

next-hop 不响应不能单独证明 next-hop 故障，因为正常转发设备可能不响应或限制针对自身的 ICMP。

---

## 14. TCP 端口场景的路径级诊断

只有当：

- 目标 TCP / ICMP 无响应；
- actual next-hop Neighbor 可用；
- next-hop 本身明确产生 IP 响应；
- 仍缺少足够解释；

才进入路径级诊断。

### 14.1 探测方法

继续针对：

- 同一个目标 IP；
- 同一个用户指定 TCP 端口；

执行带受限 TTL / Hop Limit 的 TCP 尝试。

不改用 UDP，也不默认改成 ICMP Echo。

路径中收到的 ICMP Time Exceeded 等响应只作为路径证据。

### 14.2 TTL/Hop Limit 推进

- 从 1 开始；
- 每次严格 +1；
- 最大 30；
- 30 是硬执行上限，不是必须运行到 30；
- 一旦出现终止条件立即停止。

此前已经知道的 first-hop 信息不能替代 TTL/Hop Limit = 1 的路径尝试。

### 14.3 每 hop Attempt 预算

每个 TTL/Hop Limit：

- 最多两个独立 Attempt；
- 每个 1 秒 deadline；
- 第一次取得明确 hop/终止结果即结束当前 hop；
- 第一次 Timeout 才执行第二次；
- 两次均 Timeout 只表示“该 TTL 下没有取得响应证据”。

不得解释成该 hop 或链路故障。

### 14.4 多 responder

同一个 TTL 的不同 Attempt 可能收到来自不同 responder 地址的 Time Exceeded。

必须保留全部观察结果，只能陈述：

> 在该 TTL 下观察到多个 responder 地址。

不得自动解释为：

- 连续不同 hop；
- ECMP；
- path flap；
- 不同物理设备。

### 14.5 路径终止

必须区分：

**目标终点响应**

- 与当前 Path Attempt 可验证关联的 TCP 成功；
- 或明确的终点级 TCP 结果。

出现后立即停止，记录目标终点响应。

**路径明确终止错误**

- 收到可验证关联、且语义足以表明当前路径无法继续的 ICMP hard error。

出现后立即停止，但只能记录路径终止错误，不能冒充已到达目标。

`Time Exceeded` 表示继续下一 TTL。

路径级探测属于失败后的解释性证据。即使后续某个路径 Attempt 最终取得 TCP endpoint response，也不得反向覆盖此前主检查的 Timeout/Failure；它只能形成“后续路径诊断观察到终点响应”等附加证据。

### 14.6 达到上限

TTL/Hop Limit 达到 30 仍无终点响应或明确路径终止错误时，结果为：

> 达到路径诊断执行上限，但未取得终点证据。

不能解释为：

- 目标不可达；
- 路径在第 30 跳中断；
- 目标实际位于 30 跳之外。

---

## 15. 无 `port` 的地址级诊断

用户未提供 `port` 时，主检查语义是地址级网络响应检查，不猜测任何 TCP 端口。

### 15.1 第一个主动目标探测

完成目标形成、初始路径分析与必要 Neighbor 前置读取后，第一个主动目标探测是：

> ICMP Echo 到具体目标 IP。

### 15.2 目标 ICMP 预算

完全复用目标 ICMP 公共规则：

- 最多两个 Attempt；
- 每个 2 秒；
- 第一次明确结果结束；
- 第一次 Timeout 才执行第二次；
- 两次结果独立保存。

Echo Reply 只证明目标存在相应 IP 层双向响应。

如果第一次主检查 ICMP Timeout、第二次得到 Echo Reply，该目标必须标记为 **SatisfiedWithAnomaly / Intermittent**；后一次成功不覆盖第一次 Timeout，整体退出不得为 0。

两次 Timeout 只表示没有取得目标 ICMP 响应证据，不等价于目标不可达；后续诊断只能决定能否进一步形成明确失败边界，否则最终保持 Indeterminate。

### 15.3 后续失败链

目标 ICMP x2 Timeout 后：

- 检查相关 Neighbor 前后状态；
- 必要时等待 Neighbor 收敛；
- on-link 目标若 Neighbor 已可用但目标仍无 ICMP 响应，到此停止主动扩张并保持必要的不确定性；不存在可继续追踪的远端 gateway/path；
- 非 on-link 目标只有在实际 next-hop Neighbor 已确认可用时，才按既有 first-hop 规则检查实际 next-hop；
- 只有 next-hop 本身取得明确 IP 响应、且现有证据仍不足时，才进入无 port 的 TTL/Hop-Limit 路径诊断；
- next-hop 没有响应不能单独证明其故障，也不能作为继续发送更远路径探测的依据。

不得猜测 TCP 端口。

### 15.4 无 port 路径探测

使用对同一目标 IP 的 ICMP Echo，并逐步增加 TTL / Hop Limit。

推进规则：

- TTL/Hop Limit 从 1 开始；
- 每次 +1；
- 最大 30；
- 每个 TTL 最多两个 Attempt；
- 每个 Attempt 1 秒。

只有与当前 Path Attempt 可靠关联、且确认来自目标的 Echo Reply，才定义为目标终点正响应并停止。

Time Exceeded 只表示中间路径响应并继续。

明确 ICMP 错误可以在语义足够时终止路径诊断，但属于路径/探测错误终止，不得冒充成功到达目标。

达到 30 仍无目标终点证据时，结论仍是：

> 达到路径诊断执行上限，但未取得目标终点证据。

---

## 16. loopback / local route 目标

loopback 或被操作系统判定为本地路径的目标仍按用户请求执行正常主检查：

- 有 port：TCP Connect；
- 无 port：地址级检查。

但不得进入不存在的：

- Neighbor 诊断；
- gateway 诊断；
- 远端路径诊断。

失败只能沿本机相关证据解释。

---

## 17. 系统名称解析失败诊断

### 17.1 原始失败事实优先

系统 resolver 失败后，Core 首先完整保留操作系统返回的原始失败结果及必要上下文。

至少应区分高层语义：

- 确定性名称不存在/无匹配；
- temporary failure；
- timeout；
- server / resolver failure；
- 其他平台可解释失败；
- unknown。

不得把所有名称解析失败统一解释成“DNS Server 不通”。

### 17.2 确定性否定结果

当系统 resolver 明确返回名称不存在/无匹配等确定性否定结果：

- hostname 名称解析阶段立即结束；
- 不主动探测 DNS Server；
- 不自行发替代 DNS Query；
- 因没有形成正式目标 IP，后续目标 TCP / ICMP / 路径诊断不执行。

结论只能是：

> 当前系统正常名称解析路径无法得到该 hostname 的目标地址。

不得扩大成“该名称在所有 DNS 环境中绝对不存在”。

### 17.3 非确定性失败

对于 temporary failure / timeout 等：

1. 先使用初始名称解析配置现场判断该 hostname 是否存在适用的 resolver 配置路径；
2. 此阶段不产生主动 DNS 流量；
3. 若平台只能确定候选 resolver，不能猜测实际使用者；
4. 若能确认不存在任何适用的 resolver/名称解析配置路径，则停止主动 DNS 扩张，以“当前系统缺少可证明适用的解析路径”作为关键证据之一；
5. 若现有平台事实不足以判断是否存在适用路径，则保持 Unknown/Indeterminate，不自行挑一台 DNS Server 猜测；
6. 只有确认存在一个或多个明确适用、且可以进行 DNS 协议级诊断的 resolver dependency，才进入下一阶段。

---

## 18. resolver 网络依赖与主动 DNS 诊断

### 18.1 resolver 路由分析

对已确认或明确候选的 resolver endpoint：

- 先使用初始路由现场判断诊断开始时是否存在可用路径；
- 只有路径存在，或仅凭快照无法确定时，才执行主动 DNS 诊断；
- 不以 ICMP Echo 作为 DNS 服务探测前置条件。

### 18.2 DNS 诊断对象

主动 DNS 诊断只围绕用户原始 hostname。

不得：

- 使用固定公共测试域名替代；
- 默认执行通用 DNS Server 健康检查。

目标是解释当前 hostname 的系统名称解析失败，而不是评价 resolver 的一般递归能力。

这里必须严格区分“用户原始 hostname”与“系统 resolver 实际产生过的 DNS query name”。对于单标签名称、search-domain/suffix、split-DNS 或其他 OS 名称扩展场景，如果平台无法可靠证明 system resolver 当次实际查询了哪个完全限定名称，则 direct DNS 对原始字符串的结果**只能作为补充观察**，不得描述成对 system resolver 原查询的等价复现，也不得据此否定或覆盖 system resolver 的失败事实。若直接查询原始字符串会造成明显错误归因，平台适配层可以将该 direct-DNS 分支标记为 QueryNameSemanticsUnavailable 并停止该分支；固定公共测试域仍然禁止。

### 18.3 A / AAAA

对原始 hostname：

- A 和 AAAA 分别作为独立 Query；
- 两者并发发起；
- 任一 Query 完成不得取消另一个；
- 两者必须分别得到最终结果或 timeout；
- 本机当前是否具备 IPv4 / IPv6 路径，不作为省略 A 或 AAAA 的依据。

这些查询只是失败后的补充诊断，不声称完整复现系统 resolver 原始内部行为。

### 18.4 transport

不得无条件假定 DNS 等于 UDP。

- resolver 依赖具有明确传输语义时，忠实遵循该语义；
- 普通 DNS 且无更具体约束时，第一次使用 UDP；
- TCP 不默认并发发送，只在明确条件下进入。

如果系统 resolver 使用的真实依赖/transport 无法被当前平台以公开、普通用户权限可靠诊断，则必须标记为 capability limitation。不得为了“总得测点什么”而偷偷改查另一台 DNS Server、另一种 transport，或把结果冒充系统 resolver 的真实路径。由于 system resolver 主结果已经取得，这类缺失通常只限制故障定位深度，不升级为 ExecutionError。

### 18.5 UDP Attempt

每个独立 A 或 AAAA Query：

- 最多两个 UDP Attempt；
- 每个最大 deadline 2 秒；
- 单调时钟；
- 第一次获得明确 DNS 响应或明确网络/协议错误立即结束 UDP 阶段；
- 第一次完全 Timeout 才立即执行第二次；
- 不额外等待；
- 第二次结果不得覆盖第一次 Timeout。

### 18.6 连续 UDP Timeout 后的 TCP 对照

同一个 Query 连续两个 UDP Attempt Timeout 后：

- 针对同一个 resolver、hostname、Question 进入 TCP DNS 诊断；
- 该 TCP 分支属于 transport 对照诊断；
- 不得把它描述成 UDP Timeout 按 DNS 协议必然要求的 fallback。

TCP DNS Attempt：

- 最多两个；
- 每个整体最大 deadline 5 秒；
- deadline 覆盖 TCP 建立、DNS 请求发送、等待对应 DNS 响应；
- 明确 DNS 响应或明确 TCP/网络/协议错误立即结束；
- 第一次整体 Timeout 才执行第二次；
- 两次结果独立保存。

### 18.7 UDP 截断响应

普通 DNS UDP Query 收到明确截断结果时：

- 保留“UDP 已响应但结果被截断”的事实；
- UDP 阶段结束；
- 立即进入 TCP DNS 以获取完整响应；
- 不再执行 UDP Timeout 式复验。

该 TCP 分支与“连续 UDP Timeout 后的 transport 对照”必须具有不同 provenance，但执行预算复用相同 TCP DNS Attempt 规则：最多两次、每次整体 5 秒。

### 18.8 DNS 结果粒度

主动 DNS 诊断只需要可靠获得当前网络诊断所需的高层结果，例如：

- 响应成功；
- A/AAAA 地址；
- 必要的别名信息；
- 确定性否定回答；
- server error；
- refused；
- truncation；
- timeout；
- transport / network error。

DNS 报文字段级正确性、未知 RR、压缩、完整消息关联、扩展 RCODE 等底层协议细节交由成熟、标准兼容的 DNS 库负责。

本产品不设计成 DNS 报文分析器，不默认保存完整 DNS 消息结构或原始报文。

### 18.9 直接 DNS 成功不能替代系统 resolver

如果系统 resolver 已失败，而直接 DNS 诊断成功获得 A/AAAA 地址：

- 这些地址仅作为补充证据；
- 不提升为正式目标；
- 不继续对这些地址执行 TCP / ICMP / 路径诊断；
- 不能覆盖系统 resolver 原始失败。

正式 hostname 目标地址只能来自正常系统名称解析路径。

### 18.10 直接 DNS 仍失败时的诊断边界

直接 DNS 也未取得明确响应时：

- 可结合已有路由事实；
- 若实际 DNS 流量依赖具体 Neighbor，可读取主动操作后的 Neighbor 状态并完成必要被动收敛观察；
- 此后停止 DNS 依赖诊断；
- 不继续对 resolver 或其 next-hop 执行完整 ICMP / TTL 路径诊断。

依赖项不得递归套用完整目标诊断流程。

### 18.11 多 resolver 候选

如果系统只能确定多个适用 resolver 候选，无法证明实际系统 resolver：

- 候选身份与“实际系统 resolver”严格分离；
- 需要继续直接 DNS 诊断时，可对全部明确适用候选分别诊断；
- 最多同时活动 4 个 resolver 候选诊断；
- 超过 4 个按系统配置/事实顺序排队；
- 如果 OS 只暴露“候选集合”而没有可证明的语义顺序，调度器必须采用稳定的产品规范化顺序保证确定性，并明确该顺序不是 OS resolver 优先级；
- 每个候选结果独立保存；
- 不得根据后续结果反推系统当时一定选择了某个 resolver。

---

## 19. 目标结果与整体聚合

### 19.1 单目标主检查结果

Core 必须把“主检查是否满足”与“失败原因是否已经定位”分开。

每个正式目标至少能够表达：

- **Satisfied**：主检查在第一次 Attempt 即满足，且不存在需要保留的异常；
- **SatisfiedWithAnomaly / Intermittent**：主检查重试后满足，但此前已经出现 Timeout 等真实异常；
- **NotSatisfied**：主检查明确未满足，例如 Connection Refused、DefinitiveNoPath、TCP 主检查最终未建立连接等；
- **Indeterminate**：当前检查没有取得足够证据形成满足或明确失败边界，例如无 port 场景持续 ICMP 无响应且后续证据仍不足。

**只有 `Satisfied` 才是退出码 0 的候选。** `SatisfiedWithAnomaly` 虽然存在后续成功事实，但为了不覆盖首次异常，进程层仍属于网络检查未完全满足，退出码为 1。

失败后执行的 Neighbor、next-hop、path、direct DNS 等诊断只负责解释和收窄边界，不得反向改写主检查历史。

### 19.2 hostname 多目标聚合

每个正式目标 IP 必须保留自己的完整结果，hostname 层只形成最小组合摘要：

- 所有目标均为干净 `Satisfied`：`All Satisfied`；
- 存在不同目标结果，尤其成功与 NotSatisfied/Indeterminate 并存：`Mixed / 结果不一致`；
- 所有目标都没有形成干净 `Satisfied`：表达为“没有目标完全满足当前检查”，并分别展示 Intermittent / NotSatisfied / Indeterminate，不能互相转换；
- 所有目标最终都能满足，但至少一个存在首次异常：整体为“存在瞬时/间歇异常”，不得冒充 `All Satisfied`。

最终展示顺序始终使用系统 resolver 有序唯一结果顺序，不使用并发完成顺序。

### 19.3 零正式目标绝不按空集合成功

hostname 可能因为以下原因没有形成正式目标：

- definitive negative；
- system resolver 非确定性失败；
- resolver 表面完成但没有可用 IP；
- 解析路径证据不足。

这些情况必须形成 hostname 层 DiagnosticNonSuccess 或 Indeterminate，并返回退出码 1；**不得因为 `formal_targets.is_empty()` 而让 `all(targets satisfied)` 的空集合逻辑错误地产生退出码 0。**

### 19.4 聚合与退出码

只有同时满足以下条件，Completed Diagnostic 才返回 0：

1. 请求已经完整完成；
2. hostname（如有）已经正常形成正式目标；
3. 所有正式目标均为干净 `Satisfied`；
4. 不存在需要保留的主检查 Timeout、失败、Mixed 或 Indeterminate。

除此之外，只要诊断本身可靠完成，就返回 1。

## 20. 核心结果模型

一次执行必须显式区分“诊断完成结果”和“执行未完成终态”。

### 20.1 Completed Diagnostic

只有本次请求按照既有执行规则实际触发的所有必要分支均可靠进入终态，才允许形成 Completed Diagnostic。

完成结果必须包含：

- 整体状态；
- 诊断结论；
- 支撑该结论的关键证据；
- hostname 解析层结果（如适用）；
- 各正式目标独立结果；
- 主检查结果与后续解释性诊断的区分；
- 必要的能力受限信息。

### 20.2 ExecutionError

某个完成当前请求所必需的操作无法可靠执行时进入 ExecutionError，例如：

- 输入语义错误；
- scoped IPv6 无法绑定；
- 主检查所需平台能力不可用；
- 内部资源耗尽导致无法继续处理全部必要目标；
- 内部故障。

ExecutionError 不得被聚合成正常 0/1 结果。已经完成的分支事实可以保留，但只作为部分上下文，不冒充整次诊断已完成。

### 20.3 Cancelled

用户主动取消时进入独立 Cancelled/Interrupted。已经取得的部分事实不包装成正式完成诊断。

### 20.4 允许不确定

证据不足时允许形成明确：

> Indeterminate / Unknown

不得为了产生“单一明确根因”而覆盖或重新解释已有事实。

### 20.5 确定性

Core 结论必须确定性：

> 相同有效输入事实与相同证据集合，应产生相同状态、结论类别和关键证据选择。

关键证据选择也必须遵循稳定规则，而不是由 CLI 或平台实现临时决定：

1. 始终优先包含直接决定主检查结果的事实；
2. 若存在异常复验，必须包含首次异常以及改变后续观察的复验事实；
3. 若失败边界被 Neighbor、next-hop、path 或 resolver 证据进一步收窄，只包含真正改变结论边界的最小证据；
4. 若某个 Capability 缺失阻止了进一步可靠定位，必须把该限制作为关键证据之一；
5. 不影响结论的成功准备步骤、冗余 Attempt 和完整内部过程默认不进入 Key Evidence；
6. 多目标场景先保持各目标独立关键证据，再由 hostname 层只选择解释整体差异所需的最小集合。

系统名称解析成功且已形成正式目标时，该解析事实是后续目标诊断的 Context，
不得作为 PrimaryDecision 抢占真正决定网络检查结果的 Attempt。只有解析失败、
negative/no-usable-address、zero-target 或 Required Capability Unavailable 本身决定
顶层结果时，解析事实才可成为对应角色的关键证据。平台 negative/no-address
事实不得升级成“hostname 在所有环境中不存在”；Direct DNS 的 NXDOMAIN 也只属于
该次协议响应。

OS 返回的事实还必须区分“语义有序”和“仅枚举有序”：resolver 地址返回顺序、明确配置优先级等有协议/OS 语义的顺序必须保留；interface、route、Neighbor 等没有语义保证的枚举顺序不得影响结论或 Key Evidence，必须按身份/优先级事实进行规范化或按集合处理。

不得使用：

- 隐藏健康分数；
- 随机性；
- 不可审计概率猜测；
- 模糊启发式替代明确规则。

## 21. CLI 输出合同

### 21.1 默认输出

默认输出采用：

> 简洁诊断结论 + 理解该结论所必需的最少关键证据

不得默认展开：

- 所有 Attempt；
- 完整路由；
- 全部 Neighbor 状态；
- 每个 path hop；
- 内部执行过程。

成功且没有异常的路径应尤其简洁。

CLI 不自行判断哪些底层事实重要，关键证据由 Core 产生。

默认展示 Attempt 时不得泄漏全局 `AttemptId` 或目标历史 vector 位置。编号只在
同一逻辑操作确有多次 Attempt 时显示，并从 1 局部计数；例如两次 TCP 后的一次
ICMP 显示为 `TCP connect #1`、`TCP connect #2`、`ICMP Echo`。Path Attempt 使用
hop 加该 hop 内的局部 attempt 编号。内部事实模型继续完整保留全局 Attempt identity。

### 21.2 stdout / stderr

**stdout**：

- 只在顶层进入 `Completed Diagnostic` 后输出正式诊断结果；
- 包括退出码 0 的满足结果；
- 也包括退出码 1 的网络检查未完全满足结果；
- 不在多目标尚未完成时把单个目标的部分结果提前写成稳定 stdout 结果，避免后续 ExecutionError/Cancelled 留下一个看起来像完整诊断的半成品。

**stderr**：

- ExecutionError；
- Cancelled/Interrupted 说明；
- 仅 TTY 下的临时过程提示。

### 21.3 TTY 过程提示

仅交互式 TTY 可以显示短暂、可覆盖的过程提示。

要求：

- 输出到 stderr；
- 不属于稳定结果；
- 不承载诊断语义；
- 非 TTY / 重定向场景默认不输出进度。

### 21.4 颜色、符号与终端安全

颜色、图标、Unicode 符号只能作为视觉装饰。

- 不参与结果语义；
- 纯文本必须能完整表达全部状态；
- 非 TTY 默认不得依赖 ANSI 控制序列；
- 用户输入、hostname、interface name、resolver/route 等来自外部或 OS 的文本在进入 CLI 展示前必须进行终端安全转义/编码，不能让其中的控制字符、换行或 ANSI escape 改变终端状态或伪造额外输出；
- Core 中保存的语义值与 CLI 展示转义必须分离，不能为了终端安全修改事实本身。

---

## 22. 退出码与取消语义

### 22.1 完成结果退出码

固定：

| 退出码 | 语义 |
|---:|---|
| `0` | Completed Diagnostic，且本次网络检查全部干净满足 |
| `1` | Completed Diagnostic，但网络检查未完全满足 |
| `2` | ExecutionError：工具自身未能可靠完成本次请求 |
| `130` | 用户主动 Cancelled/Interrupted |

`1` 包含：

- 明确网络失败；
- 多目标结果不一致；
- SatisfiedWithAnomaly / Intermittent；
- Indeterminate；
- hostname 未形成正式目标但诊断过程本身可靠完成。

`2` 包含：

- 输入或执行环境错误；
- 必要权限不足；
- 主检查所需平台能力缺失；
- 资源耗尽导致请求无法完整完成；
- 内部故障。

退出码不进一步承担详细网络故障分类职责。

### 22.2 聚合优先级

顶层优先级固定：

```text
用户主动取消 -> 130
否则，任何必要分支 ExecutionError -> 2
否则，完整诊断且全部干净满足 -> 0
否则，完整诊断 -> 1
```

不得让已经成功的其他目标把某个必要分支的 ExecutionError 掩盖成 0/1。

### 22.3 用户主动取消

用户通过 Ctrl+C 等明确交互主动中断时：

- Core 进入独立 `Cancelled/Interrupted` 状态；
- 不属于 DiagnosticNonSuccess；
- 不属于 ExecutionError；
- 停止启动新探测；
- 对可取消的在途操作发出取消；
- 允许直接结束进程以避免等待不可取消的 OS 阻塞调用；
- 释放能够正常释放的资源；
- 未完成全部必要分支时，不得把已有部分结果包装成正式 Success / Failure。

程序正常捕获并处理的 Ctrl+C / 交互式取消，跨平台统一返回 130。

外部强制杀进程、掉电或操作系统未把终止交给应用处理时，不承诺重映射为 130。

## 23. 权限与平台能力

### 23.1 正常运行权限

产品正常使用不得以：

- root；
- Administrator；
- 自动 UAC；
- 自动 sudo；
- 运行时自行提权；

为前提。

优先使用普通用户可用的成熟 OS 网络能力。

### 23.2 能力按“主检查”与“深度诊断”分级

平台适配层必须显式报告 Capability，而不是让调用失败后由 Core 猜测。

**主检查能力**包括当前请求不可替代的基本动作，例如：

- port 场景的 TCP Connect；
- no-port 场景的 ICMP Echo；
- hostname 场景的系统正常名称解析。

如果主检查能力无法在当前环境中可靠执行：

> ExecutionError，退出码 2

**深度诊断能力**包括失败后的定位增强，例如：

- Neighbor 状态读取；
- next-hop ICMP；
- TCP TTL/Hop-Limit 路径响应关联；
- 某些 resolver 内部配置/transport 的直接诊断。

如果主检查已可靠取得结果，而深度能力不可用：

- 保留主检查结果；
- 明确记录 Capability Unavailable；
- 不伪造证据；
- 不自动提权；
- 不偷偷改用另一种探测协议冒充同一证据；
- 必要时以 Indeterminate 结束故障边界定位；
- 整体仍属于 Completed Diagnostic，通常退出码 1。

### 23.3 TCP 路径诊断特别约束

TCP 端口场景的路径诊断要求“受限 TTL/Hop-Limit 的 TCP 尝试 + 能可靠关联到该 Attempt 的路径响应”。这是一项**可观测性能力**，不是所有 OS 在普通用户权限下都必然提供。

实现必须遵守：

- 能可靠提供时，严格按第 14 章执行；
- 不能可靠提供时，标记 `TcpPathDiagnosisUnavailable`；
- 不允许为了取得中间 hop 而要求管理员/root；
- 不允许静默改成 ICMP traceroute 后仍声称是原 TCP 路径证据；
- 主 TCP Connect 已经完成时，该缺失只降低定位深度，不把主检查改成 ExecutionError。

### 23.4 Capability 必须可测试

每个平台/架构的发布验收必须实测而不是假设以下能力：

- interface / route / resolver configuration snapshot；
- current targeted path lookup；
- Neighbor read；
- TCP Connect；
- ICMP Echo；
- ICMP TTL/Hop-Limit path；
- TCP TTL/Hop-Limit path correlation；
- direct DNS UDP/TCP；
- cancellation。

测试结果决定 Capability 状态；文档不得通过“理论上应该可以”把未验证能力当成 Available。

## 24. 全局时间、并发与资源边界

### 24.1 不设置任意全局 wall-clock timeout

整次命令不设置一个额外的任意总时限。

所有**产品可控主动探测**通过局部上限自然保证有界：

- TCP Connect：5 秒/Attempt，Timeout 最多 2 次；
- 目标 ICMP：2 秒/Attempt，最多 2 次；
- next-hop ICMP：1 秒/Attempt，最多 2 次；
- path probe：每 TTL 1 秒/Attempt，最多 2 次，TTL 最大 30；
- Neighbor convergence：2 秒；
- DNS UDP：2 秒/Attempt，最多 2 次；
- DNS TCP：5 秒/Attempt，最多 2 次；
- 正式目标并发：最多 4；
- resolver 候选并发：最多 4。

系统正常名称解析是明确例外：它使用 OS resolver 自身的正常完成/超时语义，不套用 direct DNS 的 2/5 秒规则，也不由 Core 再叠加无界重试。用户需要提前停止时使用统一取消语义。

产品可控 Attempt 的 deadline 时钟必须是单调的，并且不能因系统 wall-clock 调整而倒退或跳变。对“最大 1/2/5 秒”这类真实 elapsed deadline，平台适配层还必须避免系统 suspend/resume 无声延长 Attempt：优先使用能够覆盖 suspend 的 continuous/boottime 等价时钟；若平台所用单调时钟会在 suspend 时暂停，则恢复后必须把已经跨越真实 deadline 的在途 Attempt 视为到期，而不能重新获得一整段预算。

### 24.2 资源必须有界

任何实现都不得因为并发调度或诊断扩张造成：

- 无界活动 socket；
- 无界活动任务；
- 无界工作队列；
- 无界 hop；
- 无界 retry；
- 递归诊断依赖链。

正式目标和 resolver 候选可以多于并发上限，但调度器必须采用有界活动集，不为每个待处理项预先创建独立活动任务。

resolver 返回的全部正式目标仍必须按既有语义处理；如果由于真实资源耗尽无法完整处理，必须 ExecutionError，不能静默截断、随机抽样或只处理前 N 个后声称诊断完成。

## 25. 依赖与实现原则

### 25.1 Library-first

DNS、IP、ICMP、TCP、接口、路由、Neighbor 等通用能力优先采用成熟、维护可靠、语义匹配的库或操作系统 API。

第一方代码主要负责：

- 诊断状态机；
- 证据模型；
- 统一跨平台语义；
- 目标与依赖关系；
- 结果形成；
- 必要平台胶水。

不得因为“几行代码就能实现”而无必要重复实现成熟协议机制。

对于由产品定义 Attempt、deadline、retry、resolver endpoint 或 transport 的主动操作，所选库/API 必须允许 Core 保持这些语义可观察、可控制。若库会在内部不可见地自动重试、轮换 resolver、改变 transport、追加 fallback 或自行延长超时，且无法关闭或准确暴露这些行为，则该库不满足语义要求，不能作为该主动操作的实现。系统正常 resolver 是明确例外：它本来就是被观察的 OS 行为，其内部 retry/cache/search 语义按第 9 章处理。

依赖版本升级必须重新运行对应的输入契约、Attempt、timeout/retry、DNS transport 与跨平台符合性测试；不得仅凭 API 兼容或单元测试通过就假定产品语义未变化。

### 25.2 OS-native API-first

涉及操作系统真实网络现场和运行行为时，优先从操作系统提供的正式接口取得事实。

不得为了实现统一而调用外部命令并解析文本输出。

明确禁止把以下命令作为核心实现：

- `ping`
- `traceroute` / `tracert`
- `nc`
- `netcat`
- `telnet`
- `route`
- `ip`
- `arp`
- `nslookup`
- `dig`
- 其他外部诊断程序

### 25.3 不重新实现成熟协议细节

只有会改变以下内容的问题才应上升为产品设计语义：

- 用户可观察诊断行为；
- 诊断结论；
- 主动网络流量；
- 超时与重试；
- 可靠性；
- 跨平台语义。

成熟协议库内部的字段级解析、报文合法性等细节不逐项重新设计。

来自网络、DNS/ICMP 响应、操作系统表项与 resolver 的数据一律视为不可信外部输入。协议库返回的 malformed/protocol error、未知值或 OS 异常数据必须进入正常 Fact/Attempt/Error/Capability 模型；不得因为外部数据触发 panic、越过 Core 状态机，或被误报成一个已经验证的正常事实。真正的第一方 invariant violation 才属于内部故障。

---

## 26. Core 必须提供的抽象能力

本节只规定能力，不绑定具体编程语言接口。

### 26.1 输入阶段模型

至少需要区分：

```text
ParsedRequest
  address_syntax
  port
  optional_scope_syntax
```

以及在必要 OS 事实取得后才能形成的：

```text
DiagnosticRequest
  address: BoundAddressInput
  port: Optional<TcpPort>
```

`BoundAddressInput` 只能是：

```text
Ipv4Literal
Ipv6Literal { address, bound_scope_if_required }
Hostname
```

这样可以保证非法 port/hostname 在系统采样前失败，同时又不会假装 scoped IPv6 能在接口快照前完成真实绑定。

### 26.2 初始现场

至少能够表达：

```text
InitialNetworkSnapshot
  capture_started_at
  capture_completed_at
  interfaces: CapabilityValue<...>
  routes_v4: CapabilityValue<...>
  routes_v6: CapabilityValue<...>
  routing_policy_facts: CapabilityValue<...>
  resolver_configuration: CapabilityValue<...>
  inconsistencies
```

每个 CapabilityValue 必须能表达 Available / Unknown / Unavailable 及 provenance。

### 26.3 当前操作路径

需要单独表达：

```text
OperationPathContext
  captured_at
  target_or_dependency
  address_family
  egress_interface
  on_link_or_remote
  next_hop_if_known
  source_related_facts
  relation_to_initial_snapshot
```

它用于绑定下一项产品可控主动操作的实际 Neighbor 依赖，不覆盖 InitialNetworkSnapshot。

### 26.4 正式目标

正式目标必须是具体 IP 身份：

```text
TargetIp
  address_family
  address
  optional_scope/interface identity
  resolver_order/provenance when hostname-derived
```

### 26.5 Attempt

所有主动网络操作必须具有独立 Attempt 身份和结果，不允许后续 Attempt 覆盖前一 Attempt。

Attempt 事实至少具备：

- 所属目标或依赖；
- 操作类型；
- 开始时间；
- deadline（若属于产品可控 probe）；
- 完成结果；
- duration；
- 必要 endpoint；
- provenance。

### 26.6 主检查结果

Core 必须显式表达：

```text
Satisfied
SatisfiedWithAnomaly / Intermittent
NotSatisfied
Indeterminate
```

后续诊断证据只能解释该结果，不能覆盖其历史。

### 26.7 结论与证据

Core 最终结果必须显式区分：

- Fact / Evidence；
- Primary Check Outcome；
- Derived Conclusion；
- Capability Limitation；
- Unknown / Indeterminate；
- ExecutionError；
- Cancelled。

不要设计一个把所有情况压成 `bool` 的核心 API。

## 27. 实施状态机

以下状态机是实现顺序约束，不代表具体代码结构。

### 27.1 顶层状态机

```text
ParseCliStructure
  -> ParseCoreInputLocally
      -> Invalid: ExecutionError(2)
  -> CaptureInitialSnapshot
  -> BindScopedIpv6IfNeeded
      -> CannotBind: ExecutionError(2)

If IP literal:
  -> BuildTarget

If hostname:
  -> SystemResolve
      -> SuccessWithAddresses: BuildOrderedUniqueTargets
      -> SuccessWithoutUsableAddress: HostnameDiagnosticNonSuccess
      -> NegativeWithoutUsableAddress: FinishHostnameFailure
      -> NonDefinitiveFailure: DiagnoseResolverDependency

For each formal target (max concurrency 4):
  -> AnalyzeInitialPath
      -> DefinitiveNoPath: TargetNotSatisfied, no active target traffic
      -> UsablePath/UnknownPath:
          -> CaptureCurrentOperationPathIfNeeded
          -> CaptureRequiredNeighborPreStateIfAvailable
          -> RunPrimaryCheck
          -> If needed, RunBoundedFailureDiagnosis
          -> TargetTerminal

Wait all required branches
  -> if Cancelled: 130
  -> else if any required ExecutionError: 2
  -> else AggregateCompletedDiagnostic
  -> SelectKeyEvidence
  -> 0 or 1
```

### 27.2 有 port 的目标状态机

```text
TCP Connect #1
  -> Success: Satisfied
  -> ConnectionRefused / other sufficient explicit failure: NotSatisfied
  -> Route-related explicit failure: CrossCheckInitialPath -> NotSatisfied or bounded conflict analysis
  -> Timeout: TCP Connect #2
      -> Success: SatisfiedWithAnomaly
      -> Route-related Explicit Failure: CrossCheckInitialPath -> NotSatisfied or bounded conflict analysis
      -> Other Explicit Failure: NotSatisfied
      -> Timeout:
          -> Primary outcome = NotSatisfied
          -> Target ICMP #1/#2
          -> Neighbor post-state / convergence if relevant
          -> optional next-hop ICMP only when non-on-link Neighbor is usable
          -> only if next-hop has explicit IP response: optional TCP TTL path diagnosis if capability available
          -> if next-hop is silent or path capability unavailable: stop active expansion and preserve limitation/uncertainty
          -> Derive failure boundary / Indeterminate cause
```

后续 ICMP/Neighbor/path 证据不得把主 TCP 结果重新改成干净 Satisfied。

### 27.3 无 port 的目标状态机

```text
Target ICMP #1
  -> EchoReply: Satisfied
  -> Explicit ICMP result: Classify; stop if evidence sufficient, otherwise bounded follow-up
  -> Timeout: Target ICMP #2
      -> EchoReply: SatisfiedWithAnomaly
      -> Explicit ICMP result: Classify
      -> Timeout:
          -> Neighbor post-state / convergence if relevant
          -> on-link + Neighbor usable: stop active expansion -> usually Indeterminate
          -> non-on-link: optional next-hop ICMP when Neighbor usable
          -> only if next-hop has explicit IP response: optional ICMP TTL path diagnosis if capability available
          -> derive NotSatisfied only when evidence supports a concrete local/path failure
          -> otherwise Indeterminate
```

### 27.4 hostname resolver 失败状态机

```text
System Resolver Failure
  -> Definitive negative: Completed DiagnosticNonSuccess(1)
  -> Non-definitive:
      -> Analyze applicable resolver configuration
          -> none / unknown: Stop active DNS expansion -> DiagnosticNonSuccess/Indeterminate(1)
          -> explicit DNS-capable candidate(s):
              -> Analyze initial route to candidate
              -> DefinitiveNoPath: record local dependency failure, no DNS packet
              -> Usable/Unknown:
                  -> current targeted path / Neighbor pre-state if applicable
                  -> Direct DNS A + AAAA (parallel per candidate)
                      -> UDP attempt #1
                      -> UDP attempt #2 only on Timeout
                      -> TCP on repeated UDP Timeout
                      -> TCP on explicit UDP truncation
                  -> optional related Neighbor post-state/convergence
                  -> Stop dependency diagnosis
      -> Direct DNS addresses never become formal targets
      -> Completed DiagnosticNonSuccess/Indeterminate(1)
```

不得从 resolver 失败诊断递归进入“完整目标诊断”。

## 28. 关键参数表

| 项目 | 固定语义 |
|---|---|
| 正式目标并发 | 4 |
| resolver 候选并发 | 4 |
| TCP Connect | 5s / Attempt，Timeout 时最多 2 次 |
| 目标 ICMP | 2s / Attempt，最多 2 次 |
| next-hop ICMP | 1s / Attempt，最多 2 次 |
| Neighbor 收敛观察 | 最大 2s，约 200ms 粒度或等价事件通知 |
| Path TTL/Hop Limit | 1 开始，逐一 +1，最大 30 |
| Path 每 hop Attempt | 1s / Attempt，Timeout 时最多 2 次 |
| DNS UDP | 2s / Attempt，Timeout 时最多 2 次 |
| DNS TCP | 整体 5s / Attempt，Timeout 时最多 2 次 |
| 系统正常名称解析 | 使用 OS resolver 自身语义；不套用 direct DNS 2s/5s 预算 |
| 完成退出码 | 0 / 1 / 2 |
| 用户取消 | 130 |

任何实现不得偷偷修改这些产品可控 probe 的预算形成平台差异。

路径级 probe 只有在平台 Capability 可用时执行；Capability 不可用不得通过提权或换协议伪装成同一语义。

## 29. 诊断结论边界

以下表达属于允许结论：

- “目标 TCP 端口可以建立连接。”
- “目标 TCP 端口连续未响应，但目标 IP 可以通过 ICMP 响应。”
- “本机未能建立当前路径所需的本地 Neighbor 关系。”
- “本机到第一跳存在直接 IP 响应。”
- “达到路径诊断上限，但未取得终点证据。”
- “当前系统正常名称解析路径无法解析该 hostname。”
- “系统 resolver 失败，但对适用 resolver 的直接 DNS 诊断取得响应。”
- “证据不足，无法进一步可靠确定故障边界。”

以下表达禁止仅凭现有证据直接得出：

- “服务器挂了”；
- “防火墙拦了”；
- “网关坏了”；
- “第 N 跳故障”；
- “DNS Server 挂了”；
- “网络一定没问题”；
- “域名全球不存在”；
- “Connection Refused 一定是应用没监听”。

---

## 30. 跨平台一致性要求

### 30.1 同一产品语义

六个目标平台必须满足同一套对外行为：

- 输入分类；
- 主检查定义；
- timeout/retry；
- 并发；
- 结果分类；
- 关键证据选择规则；
- stdout/stderr；
- 退出码；
- 取消；
- capability limitation。

### 30.2 平台差异的处理

操作系统 API、权限模型、路由表示、Neighbor 状态名、DNS 配置模型等允许不同。

但：

- 能映射到统一语义时，必须准确映射；
- 无法可靠提供时，必须明确 Unknown / Unavailable；
- 不得用不同的替代操作静默实现另一种产品行为；
- 不得为了跨平台统一而伪造不存在的事实；
- 深度诊断能力缺失不得反向改变已经成立的主检查事实。

### 30.3 支持平台必须通过能力实测门槛

“支持 macOS / Windows / Linux”不能只由代码能够编译来证明。

每个平台/架构发布前必须在普通用户权限下完成 Capability 实测矩阵。特别是：

- no-port 的 ICMP 主检查必须在目标支持环境中有真实普通用户实现，否则该环境只能明确返回主能力不可用；
- TCP TTL/Hop-Limit 路径证据如果无法在普通权限下可靠关联，不得阻塞 TCP 主检查，但必须显式声明该深度能力不可用；
- 不得把需要管理员/root、额外驱动、外部抓包工具才能成立的机制当作默认产品能力。

跨平台一致性的含义是“同一事实与同一 Capability 状态得到同一产品语义”，不是强迫每个内核暴露完全相同的低层观测面。

## 31. 测试与验收

### 31.1 Core 确定性测试

对相同输入事实与证据序列，所有平台无关 Core 测试必须得到相同：

- 最终状态；
- 主检查结果；
- 结论类别；
- 关键证据集合；
- 退出状态类别。

### 31.2 输入与生命周期测试

至少覆盖：

- 非法 port / 非法 address 在网络快照前失败；
- scoped IPv6 语法合法但接口无法绑定；
- snapshot 子能力部分 Unavailable；
- snapshot 采样窗口内出现接口/路由不一致，不伪造成原子一致；
- 与目标相关的 snapshot inconsistency / 关键路径事实缺失不能形成 `DefinitiveNoPath`，必须降为 UnknownPath；
- hostname resolver 成功但零可用地址时绝不返回 0。

### 31.3 主状态机测试

至少覆盖：

- 初始路径 `DefinitiveNoPath`：不得产生主动目标流量；
- 初始路径 Unknown：仍执行真实主检查；
- TCP 第一次成功 -> Satisfied；
- TCP Timeout 后第二次成功 -> SatisfiedWithAnomaly，退出 1；
- TCP Timeout x2 + ICMP Reply；
- TCP Timeout x2 + ICMP Timeout x2；
- Connection Refused；
- No Route 与静态路由一致；
- No Route 与静态路由冲突；
- Neighbor 明确失败；
- Neighbor 长时间 incomplete -> Indeterminate；
- 当前定向路径与初始路径发生变化，Neighbor 绑定到当前依赖；
- 定向路径能力不得通过产生目标网络流量的试连接/试发送实现；
- next-hop 有响应 / 无响应；
- TCP 场景 next-hop 无响应时不继续更远 TTL path；
- path 中间 hop 无响应；
- path 多 responder；
- path 达到 TTL 30；
- path 后续到达终点不得覆盖主检查失败；
- no-port ICMP 第一次成功；
- no-port 第一次 Timeout、第二次 Reply -> SatisfiedWithAnomaly，退出 1；
- no-port ICMP Timeout 后路径诊断；
- no-port on-link 目标不进入远端 path diagnosis；
- no-port non-on-link 的 next-hop 无响应时不继续更远 TTL path；
- hostname 多地址 mixed；
- hostname definitive negative -> 退出 1；
- hostname resolver timeout + direct DNS success，地址不得成为正式 target；
- 单标签/search-domain 场景无法证明 system resolver 实际 query name 时，direct DNS 不得冒充等价复现；
- direct DNS UDP Timeout -> TCP success；
- UDP truncation -> TCP；
- resolver 候选并发；
- direct DNS transport/candidate 无法可靠诊断时 capability limitation；
- TCP path capability unavailable 时不提权、不换协议、不改写主结果；
- 一个必要分支 ExecutionError 时，其他目标成功不得把整体降为 0/1；
- Ctrl+C cancellation。

### 31.4 超时测试

验证所有产品可控 probe deadline 都使用 monotonic clock，且：

- 明确错误立即返回；
- 不人为等待满 timeout；
- Timeout 不包含不属于该 Attempt 的前置阶段；
- 第二次 Attempt 只在对应第一次 Timeout 后触发；
- wall-clock 调整不影响 Attempt deadline；
- suspend/resume 不会无声延长产品定义的最大 elapsed deadline；
- system resolver 不错误套用 direct DNS 的 2s/5s timeout；
- 用户取消可以终止正在等待 OS resolver 的命令进程。

### 31.5 并发与资源测试

验证：

- 正式目标最多 4 个活动诊断；
- resolver 候选最多 4 个；
- 目标内部严格串行；
- 并发完成顺序不影响最终顺序；
- 无语义保证的 OS 枚举顺序变化不影响结论与 Key Evidence；
- resolver/配置等确有语义的顺序不会被规范化过程错误抹掉；
- 共享 Neighbor 的前置事实只在相应时间边界采集一次；
- 一个目标结束不会取消其他目标；
- 大量 resolver 结果不会预创建无界活动任务；
- 资源耗尽不静默截断结果，而进入 ExecutionError。

### 31.6 输出测试

TTY 与非 TTY 均应测试：

- stdout/stderr 分离；
- 纯文本完整语义；
- 非 TTY 无过程动画；
- 无 ANSI 依赖；
- 无效 address、异常 hostname/interface/resolver 文本中的控制字符不会产生终端注入或伪造额外行；
- 成功路径简洁；
- mixed 结果不被压成一个布尔结果；
- SatisfiedWithAnomaly 不返回 0；
- zero-target hostname 不返回 0；
- ExecutionError 不输出伪完整 stdout 诊断；
- 多目标尚未全部进入顶层终态时不提前输出稳定 stdout 部分结果。

### 31.7 跨平台 Capability 与符合性测试

同一抽象网络场景在 macOS、Windows、Linux 上必须通过统一符合性测试，重点验证：

- 结果分类一致；
- timeout/retry 一致；
- capability 缺失语义一致；
- 输出和退出状态一致；
- 不因底层平台差异静默改变诊断产品语义。

此外必须对第 23.4 节列出的每项平台 Capability 建立真实系统集成测试，并记录普通用户权限下的 Available / Unavailable 结果。

## 32. 实施工作包

以下拆分用于工程执行，不代表必须使用对应仓库目录名称。

### WP1：Core 输入与公共模型

交付：

- ParsedRequest / DiagnosticRequest / address / port 模型；
- target identity；
- attempt / evidence / conclusion；
- result / error / cancellation；
- 确定性规则测试。

完成条件：不依赖任何具体 OS 网络调用即可对合成证据运行诊断状态机单元测试。

### WP2：平台被动现场

交付三平台：

- interface snapshot；
- route snapshot + routing policy facts + targeted path lookup；
- resolver configuration snapshot；
- scoped IPv6 interface identity；
- capability reporting + snapshot capture window / inconsistency。

完成条件：同一平台重复采样不会因模型缺失而丢掉影响路径/解析选择的关键事实。

### WP3：主网络操作

交付：

- TCP Connect；
- actual local/remote endpoint；
- ICMP Echo；
- TTL/Hop Limit 控制与平台可观测性 Capability；
- monotonic deadlines；
- cancellation。

完成条件：所有固定 timeout 与 Attempt 预算可由自动化测试验证；无法在普通权限下提供的深度能力必须显式报告，不能依赖提权或协议替换。

### WP4：Neighbor 能力

交付：

- 具体 Neighbor 查询；
- 状态统一映射；
- 共享前置采样协调；
- 2 秒被动收敛观察。

完成条件：不会因为多目标/依赖并发或初始路径变化，在主动流量之后伪造“pre-state”；所有 pre-state 都具有明确时间边界。

### WP5：系统 resolver 与 DNS 失败诊断

交付：

- 系统正常名称解析；
- 原始顺序与 stable dedup；
- resolver 候选分析；
- A / AAAA direct diagnostic；
- UDP/TCP Attempt 规则；
- DNS 诊断边界。

完成条件：direct DNS 结果永远不能被提升为正式 hostname target；无法证明 system resolver 实际 query-name 语义时，不得把对原始字符串的 direct DNS 结果冒充系统解析路径的等价复现。

### WP6：诊断状态机

交付：

- 带 port 流程；
- 无 port 流程；
- hostname resolver failure 流程；
- path diagnosis；
- primary outcome / multi-target aggregation；
- key evidence selection。

完成条件：全部状态机测试矩阵通过。

### WP7：CLI

交付：

- `abc <address> [port]`；
- stdout / stderr；
- TTY progress；
- plain text fallback；
- exit 0/1/2/130；
- Ctrl+C propagation。

完成条件：CLI 不含任何网络诊断业务判断。

### WP8：跨平台符合性与发布

交付：

- 六个平台/架构构建；
- 单一可执行文件；
- 符合性测试；
- 无外部诊断命令依赖验证；
- 普通用户权限运行验证。

完成条件：六个平台通过相同产品语义测试基线。

---

## 33. Definition of Done

项目达到当前设计的可交付状态，至少必须满足：

1. 六个平台/架构均可构建并以单一可执行文件交付；
2. CLI 仅接受既定基础诊断形式，输入语义由 Core 唯一解释；
3. 非法输入不会触发网络现场采集或主动流量；
4. IPv4、IPv6、scoped IPv6、hostname 均按本设计工作；
5. 初始接口/路由/路径策略/resolver 现场能够按 Capability 可靠采集，并明确 capture window，而不是伪原子快照；
6. `DefinitiveNoPath` 会短路主动主检查，UnknownPath 不会阻止真实主检查；
7. TCP、ICMP、Neighbor、路径、DNS 的产品可控 probe 均遵守固定预算；
8. 多地址与多 resolver 活动并发上限均严格为 4，且调度器不会创建无界活动任务；
9. 所有 Attempt 都保留首个事实，不被后续成功覆盖；
10. TCP/ICMP 重试后成功形成 SatisfiedWithAnomaly，整体不得返回 0；
11. 失败后的解释性 probe 永远不能覆盖主检查历史；
12. hostname 未形成正式目标时绝不会因空集合聚合错误返回 0；
13. 成功路径不执行无意义额外探测；
14. 失败路径不会递归扩大为无限诊断；
15. Core 能稳定产生 PrimaryOutcome + Conclusion + Key Evidence；
16. Unknown / Indeterminate / CapabilityUnavailable 都是正式合法状态；
17. stdout/stderr、0/1/2/130 完全符合合同；
18. 用户取消不会包装出不完整正式结果；
19. 任一必要分支 ExecutionError 不会被其他成功分支掩盖；
20. 普通运行不要求 root/Administrator 或自动提权；
21. 深度能力无法在普通权限下提供时，不静默换协议或外部工具；
22. 不调用任何外部网络诊断命令；
23. 外部网络/OS 数据无法通过畸形内容触发 panic 或绕过正常结果模型，CLI 展示不存在终端控制字符注入；
24. 不修改系统持久网络配置；
25. 三大操作系统对同一事实/Capability 状态具有一致对外语义；
26. 第 23.4 节 Capability 均经过真实平台实测，不以理论推测代替；
27. 所有输入、状态机、timeout、并发、资源、输出、取消、Capability 与跨平台符合性测试通过。

## 34. 最终实施约束

任何后续技术选型、代码结构、依赖引入或平台实现都必须满足本文定义的产品语义。

实现可以优化：

- 内部并发调度；
- 系统调用数量；
- 内存布局；
- API 封装；
- 测试基础设施；
- 代码复用。

但不得通过优化改变：

- 用户输入语义；
- 主检查顺序；
- timeout / retry；
- 主动网络流量触发条件；
- 事实边界；
- 诊断结论边界；
- 多目标行为；
- 主检查结果与后续诊断的不可覆盖关系；
- Capability 缺失与降级语义；
- DNS 失败诊断边界；
- 输出/退出/取消合同；
- 跨平台一致性。

本文即当前工程实施基线。
