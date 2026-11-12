# QUIC 后端选型：Quinn 与 tokio-quiche

状态：2026-11-13 更新。生产基线为 `63570f6`。已完成源码、既有裸 QUIC 结果
复核、隔离依赖检查，以及 P1 的 H3 端点和兼容性补丁。G0 尚未通过，详见
[实施结果](tokio-quiche-g0-results.md)。尚未完成 MASQUE 后端或业务性能测量；
生产依赖和实现未变。

后续完整实施方案见 [tokio-quiche 引入计划](tokio-quiche-integration-plan.md)，
包括新增核对的 Retry token、CID 长度、单方向 shutdown 差异，以及模块改造和测试矩阵。

## 建议

**当前生产保留自有 quiche shard；下一步优先验证 tokio-quiche；暂不推进 Quinn
迁移。** 这是针对现有 MASQUE server 的成本与兼容性判断，不是两个库的通用排名。

我们已经使用 Tokio，因此“获得 async/Tokio 支持”不是迁移收益。真正可争取的收益
是减少自维护的 QUIC 收发、定时器和 H3 驱动代码。tokio-quiche 保留 quiche/H3 与
BoringSSL，变更范围较小；但它也有自己的连接、socket、路由和任务架构，仍需调整
应用所有权。现有 shard 并不是一层可以直接删除的 Tokio 包装。

| 决策维度 | 保留现有 quiche shard | tokio-quiche | Quinn + rustls + h3/h3-quinn |
| --- | --- | --- | --- |
| 当下收益 | 延续现有功能与回归证据，避免重写 | 有机会减少 QUIC/H3 driver 的维护 | 高层 async stream API，H3 可走 Rustls |
| 协议栈变化 | 无 | 保留同系列 QUIC/H3/TLS，替换 driver | QUIC、H3 adapter、TLS 接入均需调整 |
| 性能证据 | 可作为生产基线；裸实验不是生产 driver | 只有协议契约实测，尚无业务性能结果 | 裸实验无一致优势，stream 中位吞吐落后 |
| BBR2 / 现有配置 | 已使用 | 底层仍有对应能力，需显式映射配置 | 上游 Bbr 不能视为现有 BBR2 的等价替代 |
| 证书 / reload | 已有 H2/H3 共享身份及测试 | 同类 BoringSSL hook，复用机会较大 | 需实现 Rustls 验证与双 TLS 快照一致发布 |
| 资源 / 迁移 / 分片 | 现有实现与测试继续有效 | 无界控制队列、准入、Retry、CID 路由待解决 | 新驱动也需重做这些约束和配置映射 |
| 总体判断 | **当前生产选择** | **首选有限原型，未达到采用条件** | **保留备选，暂不投入完整迁移** |

若目标只是提高吞吐，先保留当前实现并分析真实 MASQUE 热点。若目标是降低维护成本，
先验证 tokio-quiche 能否实际删掉驱动职责，同时不增加长期 fork 和重复状态机。
只有明确要求 H3 转向 Rustls、后续统一 TLS 技术栈，或发现可重复的真实业务收益时，
才重新提高 Quinn 的优先级；H2、证书工具和测试客户端仍依赖 BoringSSL，单改 H3
不能宣称移除了整个项目的 BoringSSL/C 构建依赖。

如果主要目标是性能，目前没有证据证明它更快。已有的
[裸 QUIC 实验](performance-quic-comparison.md)没有测试 tokio-quiche，且使用了
自写精简 driver，不能把实验中的 quiche 数值当成 tokio-quiche 的结果。

## 为什么现在不选 Quinn

- **没有足以支付迁移成本的性能证据。** 固定 quiche 客户端时，Quinn 服务端可靠
  stream 中位吞吐在四个场景落后约 4%–12%；LAN 双向分别为约 1.85 对 1.96 Gbit/s、
  1.07 对 1.12 Gbit/s。小 DATAGRAM 有得有失，Linux 小包区间明显重叠。
  每组仅三次、采用 CUBIC、关闭 GSO/GRO；这些结果不能外推到生产 BBR2、多连接或
  长 RTT，也不能证明 Quinn 原生 UDP driver 的上限。
- **需同时承担 H3 和 TLS 接入变更。** 候选 `h3` 上游仍标注 experimental；普通
  CONNECT、CONNECT-UDP、CONNECT-IP、DATAGRAM/capsule、FIN、认证、reload 的完整
  语义都要重新验证。Quinn 本身的成熟度不能直接替代这一组合的证据。
  [h3 项目状态](https://github.com/hyperium/h3#status)
- **当前默认 BBR2 缺少已验证的等价映射。** Quinn 文档提供的 `Bbr` 标注实验性，
  不能把旧 `bbr2` 配置静默映射到它；这也是为什么裸实验统一采用 CUBIC。
  [Quinn 拥塞控制](https://docs.rs/quinn/0.11.12/quinn/congestion/index.html)
- **已有一个需要解释的 stream 中断样本。** 正式矩阵出现一次
  `too many gaps in stream buffer`，随后同条件 10 次复测成功。它是继续验证的
  门槛，尚不能认定为 Quinn 缺陷或据此泛化其可靠性。完整上下文在裸实验报告中。

改用 `quinn-proto` 并保留自有 shard，会继续承担 QUIC driver 和 H3 adapter 的
维护，削弱本次迁移希望获得的主要收益，因此也不作为默认备选实施路线。

## 已核对事实

- 初次评估版本是 `tokio-quiche 0.20.1` / quiche 0.30.0；本轮通过 crates.io
  元数据和下载源码核对到 **tokio-quiche 0.23.0**，声明 Rust 1.88，依赖
  quiche 0.30.1。下述关键接口和资源问题也检查了 0.23.0，不仅依据旧版。
  [0.23.0 发布包](https://crates.io/crates/tokio-quiche/0.23.0)
- 提供 `ServerH3Driver`，也允许实现 `ApplicationOverQuic`；listener 接收连接后
  通过独立 Tokio 任务驱动连接。选择自定义 `ApplicationOverQuic` 可以保留更多
  H3 控制权，但也会保留更多自有驱动代码，需重新计算维护收益。
- 它提供 H3 DATAGRAM flow，源码的 extended CONNECT 路径按 quarter stream ID
  关联流，并在发送和接收时处理该前缀。当前项目的 `src/datagram.rs` 也处理此
  前缀；接入时必须明确边界，避免重复编解码。CONNECT-IP、早到报文和 FIN 后报文
  的项目语义还没有通过互通测试。
- `ConnectionHook` 支持自定义 BoringSSL context 和同步 path event 回调。这为
  现有证书 roster、TLS reload 和验证路径后的来源 IP 配额提供了候选接入点，
  **不代表现有行为已经等价**。需要证明连接身份、迁移与配额更新的时序和失败处理。
- **无界队列不止一处。** `quic/router/mod.rs` 的连接映射命令 channel，以及
  `http3/driver/mod.rs` 的 H3 command/event channel 都使用 `unbounded_channel`。
  stream 和 DATAGRAM flow channel 有容量限制。需审计控制事件的生产速率、大小、
  消费停顿及生命周期，证明积压有明确上界，或取得有界实现；仅在应用外面套一个
  有界 channel 不能限制已经进入库内部的积压。这是采用前门槛，不是已经复现的 OOM。
- 上游 `QuicSettings` 的 DATAGRAM 队列默认深度为每方向 65536；本项目默认 2048。
  上游默认 CC 为 CUBIC，默认禁用 active migration，pacing 需显式开启且需要 socket
  支持；本项目默认 BBR2，显式允许迁移并启用 pacing。必须映射设置和测量总内存
  上界，不能直接使用默认值。上游默认 0-RTT 关闭，仍需保持现有明确禁用策略及
  resumption/reload 回归。
  [上游设置源码](https://docs.rs/crate/tokio-quiche/0.23.0/source/src/settings/quic.rs)
- 0.23.0 对先于 CONNECT 到达的 DATAGRAM 提供每连接 2048 条、333 ms 的 pending
  buffer。这个上界是积极信号，但必须计入总预算，并核对本项目认证/目标 setup
  阶段和 FIN 后处理，不能因为有 early-DATAGRAM buffer 就判定语义等价。
- 上游接收器的默认地址验证是开或关：开启时无 token 的 Initial 走 Retry；当前项目
  的 `adaptive` 模式还有基于连接数的阈值。不能假定默认接口支持等价的 adaptive
  语义或静默更改旧配置。`listen_backlog` 也不是全局/每来源的活跃连接配额；源码
  先构造 quiche connection，再检查 accept queue 容量。现有在分配前进行的准入
  不能直接用减小 backlog 替代，需要明确接入点或上游改动。

上述源码位置均相对于 tokio-quiche 发布包。库内部无界队列在 0.20.1 与 0.23.0
均存在；新版并未直接解除这一接入门槛。

## 完整项目依赖检查

本轮把仓库受版本控制的文件复制到临时目录，从现有 lockfile 出发，先加入
`tokio-quiche = "=0.20.1"`，再改为 `tokio-quiche = "=0.23.0"`（默认 features）。
没有修改当前分支的 Cargo 文件，也没有新增后端调用。

| 检查 | 结果 | 能证明的范围 |
| --- | --- | --- |
| 0.20.1：`cargo metadata` 与 `cargo check --workspace --all-targets --locked` | macOS 通过 | 完整 workspace 可解析并通过编译检查 |
| 0.23.0：同上 | macOS 通过 | 最新核对版本也可加入现有 workspace |
| 0.23.0：`cargo +1.88.0 check --workspace --locked` | macOS 通过 | 这份解析后的完整依赖树满足项目 MSRV 的本机检查 |

0.23.0 副本解析为 quiche 0.30.1、boring/boring-sys/tokio-boring 4.22.0、
libc 0.2.189。因此初次最小工程选择 boring 5.5.0 **不是本项目必须升级到
BoringSSL binding 5.x 的证据**，当前完整副本可继续统一在 4.x。

libc 仍须从现有 0.2.191 降至 0.2.189，0.23.0 仍保留 Linux `<0.2.190` 约束；
同时引入 foundations、qlog 等依赖和 features。这些变化需要 Linux GNU/musl、
最终链接及依赖审计验证，尚未验证其生产影响。`cargo check` 不等于链接、网络互通
或完成后端接入；副本中的 server 仍然只有原来的 shard 实现。

## 与当前实现比较

| 方面 | 现有 shard | tokio-quiche 候选 | 接入门槛 |
| --- | --- | --- | --- |
| QUIC / H3 | quiche 0.30，自管连接和事件驱动 | 同系列 quiche，现成 async driver | 实测协议及错误语义，不重复实现框架已有的 framing |
| 所有权 | 每 shard 独占多个连接及其隧道状态 | listener/router 加每连接任务 | 给连接、stream、TUN 路由定义生命周期与取消边界 |
| Linux 网络 | 现有 recvmmsg/sendmmsg、GSO/GRO、CID BPF 与有界跨 shard 转发 | 上游独立 socket 抽象与路由 | 分别验证 fast path、portable fallback、CID 生命周期和迁移，不假设现有 socket 可直接复用 |
| 认证 / reload | BoringSSL 动态 identity、SPKI roster、ticket generation；H2/H3 共享 | BoringSSL context hook | 新旧连接与 resumption、撤销、失败回滚、H2 一致性均需通过测试 |
| DATAGRAM | 有界 QUIC 队列、early-data 预算、native/capsule、FIN 规则 | driver 负责 flow 和 quarter stream ID | 验证默认值、丢弃、公平、Context ID、早到数据及 stream FIN |
| 防护 / 运维 | 自定义 Retry、自适应准入、来源限制、readiness、指标及 drain | 提供部分 hook 与内部指标 | 保留完整语义；无法获取的指标不能当成正常值 |

## 原型及决策门槛

1. **先解决架构硬约束**：给控制/event 队列、握手与来源准入、adaptive Retry、
   路径验证后的配额转移、多 socket CID/BPF 与无 BPF fallback 写出接入方案。
   验证动态证书/roster、ticket、0-RTT 与 H2 一致性；继续完成 Linux 构建、最终
   链接和依赖审计。只有库公开接口或可接受的有限上游改动能够满足这些约束，才
   进入大规模迁移。不能靠未获接受的行为退让换取 demo 成功。
2. **功能原型**：先做单 listener / 单连接的 CONNECT 和 CONNECT-UDP，使用现有
   quiche 测试客户端；再做 CONNECT-IP、capsule、native DATAGRAM、异常头部、
   早到数据、FIN/RESET 和流控。检查有界队列、取消后释放及 overload 丢弃。
3. **维护收益检查**：列出能删除的 QUIC 收发、定时与 H3 driver 职责，和新增的
   adapter、队列、hook、上游补丁及运维负担。目标 UDP/TUN、认证与策略仍归项目
   负责；不把这些代码也算作可删除部分。若需要长期 fork 或重写大部分 H3 driver，
   优先终止替换方案，保留现有 quiche 并做局部边界整理。
4. **公平测量**：同一台 Mac 和同一台 Linux、LAN 双向，采用相同客户端、TLS、CC、
   窗口、offload 配置和网络负载，交替重复。分别对比现有生产 quiche driver、
   tokio-quiche 原型及可选 Quinn 原型；覆盖 64/1200 B、单/多连接、固定速率和饱和、
   p99、两端 CPU、RSS、丢弃/shortfall、CONNECT stream 和 CONNECT-IP。
   比较前设定可接受的回归阈值，保留全部失败样本。
5. **评审再决定**：汇总可删代码量、引入依赖、功能缺口、性能和维护风险。只有达到
   所有既定硬约束、完成 `scripts/check.sh full` 与 Linux/E2E 测试矩阵后，才提出
   实验后端或默认切换方案；不在本评估中修改生产代码或部署。

采用条件是：现有功能和资源约束均有证据、真实 MASQUE 性能达到预先约定的预算，
并且维护职责确实减少。任何一项未满足，都继续保留现有后端；Quinn 不作为自动
fallback，需要独立证明其收益与兼容性。

未执行的验证：tokio-quiche MASQUE 功能原型、网络性能、真实客户端互通、Linux
GNU/musl 构建、最终链接、依赖安全审计、TUN 和生产服务运行。本轮编译检查没有
运行 tokio-quiche 连接，不能代替上述验证。

本轮当前工作区的 `scripts/check.sh quick`、`scripts/check.sh full` 均通过；
完整检查使用 Python 3.11。文档本地链接和空白检查通过。这些检查验证现有生产
workspace，没有覆盖尚未实现的 tokio-quiche 后端。
