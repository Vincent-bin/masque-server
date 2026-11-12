# tokio-quiche G0 实施结果

2026-11-13，生产基线 `63570f6`，实施分支 `feat/tokio-quiche-integration`。
已实现[引入计划](tokio-quiche-integration-plan.md)的 P1 隔离端点、兼容性探针和
两份可重复应用的原型补丁。**G0 尚未通过，P2 生产依赖接入及后续架构重构未开始。**
当前证据支持继续解决上游接口问题，不能支持直接切换后端。

原版 tokio-quiche 0.23.0 在 17 个限定场景中通过 7 个；最新补丁版通过 15 个。
仍失败的两个场景是 Retry token 地址明文，以及 body 消费暂停时 native DATAGRAM
与请求 FIN 的顺序。事件进度通知的问题已有局部修复，但其他队列、G2 准入和完整
G4/G7/G8 仍有未关闭的接口缺口，不能把两个场景修好后就自动宣布 G0 通过。

`Cargo.toml`、`Cargo.lock`、`src/`、`tools/` 未改动。现有 HTTP/2、HTTP/3、
配置和默认后端仍使用原实现；没有发布、配置激活或服务切换。

## 后续原型进展

新增可选 `suppress_body_progress_events`：抑制每次 body 读取的进度事件，
继续维护 stream 的原子字节计数，并保留 FIN 等生命周期事件。默认关闭，原版
调用方语义不变。新的 `event_backlog` 测试在暂停事件消费者时读取 512 个块，
同时校验计数为 32768 字节、恢复消费后能收到 FIN；补丁版 debug 实测队列两次
采样均为 0。Mac debug/release 和 Linux musl release 均为 15/17，见
[Mac debug](../experiments/tokio-quiche-gate/results/2026-11-13/macos-progress-prototype-debug.json)、
[Mac release](../experiments/tokio-quiche-gate/results/2026-11-13/macos-progress-prototype-release.json)、
[Linux release](../experiments/tokio-quiche-gate/results/2026-11-13/linux-progress-prototype-release.json)
和[原版对照](../experiments/tokio-quiche-gate/results/2026-11-13/macos-progress-stock-debug.json)。

这只消除逐 body 读取事件造成的增长：headers、终止事件以及 command/CID 队列
仍未证明有界，G1 仍未通过。Retry 隐私和阻塞 body 的 FIN 场景仍失败，G0 未通过。
以下表格记录此前版本的完整运行结果。

## 已交付的代码

独立 crate 位于 [experiments/tokio-quiche-gate](../experiments/tokio-quiche-gate/README.md)，
有自己的 workspace 和 lockfile。固定 tokio-quiche 0.23.0、quiche 0.30.1、
Boring bindings 4.22.0，禁用 tokio-quiche 默认 features。锁文件选择 libc 0.2.189，
未改变生产使用的 libc 0.2.191。

| 文件 | 已实现内容 |
| --- | --- |
| `src/client.rs` | 独立 quiche/H3 客户端，验证临时服务端证书，观察响应内容、FIN、RESET、连接错误和 native DATAGRAM |
| `src/server.rs` | 标准 listener 和 raw API 两个单连接端点；driver/QUIC owner barrier；预构建 TLS context hook |
| `src/main.rs` | 17 个有截止时间的协议和资源契约探针，每个用例独立进程 |
| `src/identity.rs` | 在临时目录生成合成 localhost 身份，结束后删除 |
| `run.py` | 隔离执行、错误分类、二进制 SHA-256、候选版本和构建 profile、脱敏 JSON 报告 |
| `prepare.py` | 校验原始发布包源文件 SHA-256，在忽略的 `target/` 副本应用补丁；不修改 registry 或生产依赖 |
| `patches/0001-compatibility-prototype.patch` | 16 字节 CID 解析；可选方向独立 shutdown；可选 unknown/FIN 后 DATAGRAM 丢弃；截断 QSID 错误映射 |
| `patches/0002-musl-msghdr.patch` | 修复 datagram-socket 的 musl `msghdr` 初始化编译问题，保留 syscall 中的指针和 buffer 生命周期 |

两份补丁修改 8 个上游源文件。新增 shutdown 和 flow 策略默认
关闭，只有实验显式开启；这些补丁尚未获上游接收，也未作为生产 fork 引入。
原始源码的版本、哈希及 BSD-2-Clause 归属见 [patches](../experiments/tokio-quiche-gate/patches/README.md)。

## 实际运行结果

每个用例只有一个 loopback listener 和一个独立客户端，均在运行二进制的机器上。
Mac 和局域网 Linux 测试机分别执行了这些端点；**这不是跨机器吞吐测试**。
监听地址、账号、临时目录、token 原文和密钥不进入报告。所有用例都产生有效观察，
没有 harness failure；runner 返回 `1` 表示兼容契约未通过。

| 平台及候选 | Profile | 通过 | 报告 |
| --- | --- | --- | --- |
| macOS arm64 原版 | debug | 7/17 | [JSON](../experiments/tokio-quiche-gate/results/2026-11-13/macos-stock.json) |
| macOS arm64 补丁版 | debug | 14/17 | [JSON](../experiments/tokio-quiche-gate/results/2026-11-13/macos-prototype-debug.json) |
| macOS arm64 补丁版 | release | 14/17 | [JSON](../experiments/tokio-quiche-gate/results/2026-11-13/macos-prototype-release.json) |
| Linux x86_64 GNU 原版 | debug | 7/17 | [JSON](../experiments/tokio-quiche-gate/results/2026-11-13/linux-gnu-stock-debug.json) |
| Linux x86_64 musl 补丁版 | release | 14/17 | [JSON](../experiments/tokio-quiche-gate/results/2026-11-13/linux-musl-prototype-release.json) |

下表中的“通过”仅指这一行的限定断言；不等于整项 G 门槛关闭。

| 用例 | 原版 | 补丁版 | 可观察结果 |
| --- | --- | --- | --- |
| `stream_control` | 通过 | 通过 | 请求 FIN 后仍能完整返回响应和 FIN |
| `empty_error` | 通过 | 通过 | 空 404 响应完成；尚未覆盖 credit 耗尽和 64 个 pending error 上限 |
| `cid16` | 未通过 | 通过 | 16 字节 CID 在原版标准 router 上无法完成探针，补丁版能收到请求 |
| `shutdown_read` | 未通过 | 通过 | 关闭上传方向后仍可发送响应 |
| `shutdown_write` | 未通过 | 通过 | 关闭响应方向后仍可接收上传 |
| `unknown_flow` | 未通过 | 通过 | pre-CONNECT DATAGRAM 不在 headers 后重放 |
| `late_datagram` | 未通过 | 通过 | 已交付请求 FIN 后丢弃 native 输入，完整响应及 FIN 仍能发送 |
| `qsid_empty`、`qsid_truncated` | 未通过 | 通过 | 独立 peer 在三秒内观察到 application close `0x33` |
| `qsid_out_of_range` | 通过 | 通过 | 越界 QSID 得到 `H3_DATAGRAM_ERROR` |
| `native_datagram_control` | 通过 | 通过 | 合法 native DATAGRAM 往返，QSID 只编码一次且 Context ID 保留 |
| `event_backlog` | 未通过 | 未通过 | body 消费继续、事件消费暂停，事件数从 256 增至 512 |
| `retry_privacy` | 未通过 | 未通过 | 观察到的 Retry token 含可直接读取的合成来源地址 |
| `blocked_body_fin` | 未通过 | 未通过 | body channel 已满、终止 body 尚可读时，native 输入仍被交付 |
| `raw_cid16` | 通过 | 通过 | raw API 绕过标准 router 后，16 字节 CID 可完成请求和响应 |
| `tls_hook` | 通过 | 通过 | 预构建的自定义 context 确实被使用，客户端完成服务端证书验证 |
| `raw_worker_shutdown` | 通过 | 通过 | peer close 后收到 raw worker 的完成通知 |

### 此前版本的三个失败场景

**事件队列。** `H3Driver::new` 创建无界 command/event channel；每次 body read
发送 `BodyBytesReceived`。探针只发送 32 KiB，共 512 次可控读取，不进行 OOM 压测。
此前版本实测队列随读取次数增长，结合无界 channel 源码确认缺少容量限制；这不是已测得的
进程内存上限。外层及时 drain 可以减少通常积压，无法证明任意调度停顿下的资源上界。

**Retry。** 原版使用 HMAC 认证明文 IP/DCID，没有项目现有的 AEAD 隐私、时间戳
TTL 和 adaptive 决策接口。探针只验证明文地址这一点；其余差异来自源码核对。
每个 acceptor 随机生成自己的 secret，因此存在密钥隔离，不能把“未编码 listener ID”
说成已经证明跨 listener token 可重放。迁移仍需复用项目的 codec、绑定和策略测试。

**body 阻塞与 FIN。** 原型填满 body channel，客户端提交额外 body 和 FIN，
在 QUIC owner 确认 stream 可读后再发送 native DATAGRAM。debug 容量为 1，release
为 16，两者都继续交付 native 输入。当前补丁只检查已消费到的 read 状态，无法
处理 FIN 隐藏在未消费 body 后面的情况。应用仍可能通过有预算的 capsule 解析与
有序 input 状态解决；在完成证明前，不能依赖两个 channel 的 `select!` 顺序放行。

## G1 到 G8 的剩余工作

| 门槛 | 本轮证据 | 进入 P2 前需要的结果 |
| --- | --- | --- |
| G1 资源有界 | 事件增长已复现；command/CID channel 源码无界；body/flow 的条目限制不能替代共享字节预算 | 有界 command/event 接口、可合并计数/终止状态、带预算的 buffer 所有权；暂停消费者与 churn 后状态恢复且内存有界 |
| G2 分配前准入 | 源码顺序为 `accept_conn` 创建 QUIC 后，router 才 `accept_sink.try_reserve`；每次 stateless reply 启动 task | 分配前 admission permit 和有界 reply 发送；同一 guard 贯穿握手和连接销毁；未执行准入洪泛证明 |
| G3 Retry | 明文地址已复现；TTL/adaptive 缺少等价公开接口 | 注入现有 `RetryTokenCodec` 与策略；验证篡改、过期、listener 隔离、NAT 换端口和高负载 |
| G4 CID 与多 router | 标准 router 的 16 字节修复和 raw 16 字节对照均通过 | CID 发布/退休顺序、共享 owner、wrong-router 有界转发、重复 Initial、迁移及 BPF fallback |
| G5 stream 方向 | 两个方向的 shutdown 和空响应基本场景通过 | 极小 credit、真实目标 TCP 半关闭、RESET/STOP、sibling 隔离、pending error 容量/期限及取消回收 |
| G6 DATAGRAM 与 FIN | unknown、普通 FIN、三类 QSID 和合法 native 对照通过；阻塞 body 场景仍失败 | body/FIN 有序解析、共享 early budget、Context ID/MTU/协商与 capsule fallback，以及真实 UDP/IP 转发断言 |
| G7 TLS 与迁移 hook | 服务端 TLS context 交付通过；标准接口有 path hook | 客户端证书、roster、reload/rollback、ticket generation、0-RTT 禁止、迁移来源配额的完整集成 |
| G8 生命周期 | raw worker 完成通知通过 | 标准 router/worker 的故障、panic、进展和完成监督；readiness 与实际进展一致；有界 drain 后 FD/task/路由清理 |

完整 MASQUE 认证、目标转发、TUN、HTTP/2 共享改造尚未进入原型。现有项目测试通过
不为这些新后端能力提供证据；T1–T11 完整矩阵继续作为后续阶段验收。

## 依赖内的资源边界

这是 P1 源码审计和下一步接口设计的清单，数值尚未作为新的生产容量采纳。
应用既有上限仍以[计划第 8 节](tokio-quiche-integration-plan.md#8-资源预算与过载设计)为准。

| 层及生产者到消费者 | 当前条目和持有内容 | 所需满载与释放规则 |
| --- | --- | --- |
| router 到 acceptor 消费任务 | `listen_backlog` 有界，但入队前已创建 QUIC | 在分配前拿连接/来源 permit；关闭或失败释放一次；backlog 满不能先承担完整连接成本 |
| router 到连接 worker | 每连接 2048 个 `Incoming`，含 `Vec`、地址和可能的 GRO 段 | 按 allocation capacity 和拆分 packet 计账；配置容量和共享预算，满载丢包，最终 owner 释放预算 |
| worker 到 router 的 CID 命令 | 无界队列，含 map/unmap/关闭操作 | CID 注册成功才对 peer 发布；关闭/退休不可丢，按连接有限状态合并并监督完成 |
| 应用到 H3 command | 无界，含控制和可自定义 command | 发送端背压或明确容量错误；关闭保留单独通知；禁止 I/O owner await 自己的消费者 |
| H3 到应用 event | 无界，含 headers、每次 body read 计数和生命周期 | 统计合并，headers 数量及字节受 request budget 约束，终止事件每活跃对象保留有限状态 |
| H3 到应用 body | 每 stream debug 1 / release 16；默认单次读取上限 16 KiB，最小分配通常 1 KiB | 除 channel 外计入当前读取 buffer、切片共享 allocation 和 QUIC 窗口；满载触发背压，UDP/IP 另有有界解析进展 |
| 应用到 H3 body | 每 stream debug 1 / release 16，加当前 pending frame；单个应用 frame 可大于读取默认值 | 复用项目 64 KiB chunk 与 retained-buffer permit；必须跟随发送、部分发送和 ACK 保留到最后 owner |
| H3 到每个 flow | 每 flow 2048 个 DATAGRAM，独立于 QUIC 接收队列 | 连接共享条目/字节预算；认证前纳入现有每 tunnel 8 条/64 KiB、每连接 64 KiB；满载丢包 |
| 应用到 H3 native 输出 | 所有 flow 共用 2048 条，再加 QUIC 发送队列和 headroom | 预算跨层传递而非重复加一套，超 MTU/满载有界丢弃 |
| 未知 flow pending | 每连接最多 2048 条、333 ms | 生产语义为未知 QSID 静默丢弃；本原型已提供 opt-in 禁用 |
| stream readiness | 使用无界 channel，但已有每 stream queued flag 合并；通知不持有 channel endpoints | 不能与逐 body event 等同；仍需按活跃及退休 stream 数证明 churn 上界和回收 |
| stateless replies | 每回复 task 持有发送 buffer，缺少共同任务预算 | 用有界发送器/permit，满载丢弃；不得为每个无效 Initial 无限制 spawn |
| QUIC/TLS、定时器及 socket | 由窗口、CID、握手、库内部任务与内核 buffer 共同决定 | 每连接/来源 guard、握手期限、真实进展及完成通知；报告实际 socket buffer，不用低并发 RSS 代替上界 |

只把无界队列换成 `mpsc::channel` 不足以修复 G1：例如 I/O owner 若等待事件
consumer，而 consumer 正等待同一 owner 发完响应，会形成死锁。终止通知、CID
更新和可丢数据需要不同的满载规则，必须随 API 改动一起验证。

## raw API 的可用性与代价

公开 `quic::raw::wrap_quiche_conn` 可以把已有 quiche connection 交给 tokio-quiche
worker。本轮已验证它接受 16 字节 CID、完成 H3 收发，并提供 worker shutdown
通知。这使“保留现有 ingress/admission/Retry，再交出 QUIC 所有权”成为具体备选。

但 0.23.0 的该函数固定 `cid_generator=None`、`connection_hook=None`，没有
handshake timeout 参数，并把 GSO、pacing offload、pktinfo 设为 false。worker
即使没有 hook 也会消费 `path_event_next()`；外层 `ApplicationOverQuic` 不能
假设之后还能取回这些事件。它也没有解决 H3 无界队列和 FIN 顺序。

| 路线 | 继续原型需要改什么 | 维护收益和成本 |
| --- | --- | --- |
| 扩展标准 listener，沿用原计划主路线 | 有界控制、分配前准入/Retry hook、CID owner、path/lifecycle 接口及 FIN 状态 | 有机会删除更多现有 router 职责，但需要覆盖多个上游核心模块；当前原型补丁尚未解决这些问题 |
| 保留 ingress，扩展 raw API | 复用现有 admission/Retry/router；新增 raw options、CID 注册/退休、path hook、offload、握手期限、可配置 ingress budget；H3 仍需改动 | 可以减少 Retry/准入重写，但长期保留自有路由和一部分 socket 逻辑；必须重新核算可删除职责 |
| 自定义 ApplicationOverQuic 并继续自管 H3 | 重新实现应用 H3 driver 及相关预算 | 接近继续维护原核心职责，不能自动视作达到本次降低维护成本的目标 |

建议继续把标准 listener 的有界接口、分配前准入和 FIN 规则作为下一组隔离原型，
先量化补丁规模和上游接受路径，再决定是否采用 raw 备选。不进入共享 TUN/context
大重构，也不把 P1 的临时 patch 直接提升为生产依赖。引入计划第 5 节要求在 G0
review 明确临时补丁的接受范围和维护责任；目前尚无上游接受或长期 fork 承诺。

下一组验收必须包含：暂停 event/command/CID consumer 的恢复；有界 stateless
reply 与分配前拒绝；复用 AEAD/TTL/adaptive Retry；debug/release 的阻塞 body、
空 DATA、无后续网络包时的 FIN 进展；完整 CID/path 和 worker 故障监督。G1–G8
全部有可验证方案之后，才开始 P2 的可选生产依赖和双后端 fixture。

## 构建和检查

| 检查 | 结果及范围 |
| --- | --- |
| 现有项目 `scripts/check.sh quick` / `full` | 通过；Rust 672 项、Python 103 项。full 使用临时 PATH 选择 Python 3.11，没有改变系统 Python |
| 实验 fmt / stock 与补丁版 Clippy `-D warnings` | 通过；独立 crate 不由根 workspace 检查自动覆盖 |
| 补丁版 Rust 1.88 check | 通过 |
| macOS debug/release 最终链接及端点运行 | 通过构建；兼容性断言按上表分别报告 |
| 原版 Linux GNU 最终链接和运行 | 通过构建；7/17 个限定契约通过 |
| 原版 Linux musl | 编译失败：datagram-socket 0.8.1 用 struct literal 初始化带 private padding 的 `libc::msghdr` |
| 补丁版 Linux musl release 最终链接和运行 | 通过构建；14/17 个限定契约通过 |
| 修补 tokio-quiche 上游单元测试 | macOS 150 项通过，使用该发布包的合成证书 fixtures；不是 MASQUE 功能测试 |
| 修补 datagram-socket 上游单元测试 | Linux musl 实际运行 28 项通过，包含 `recvmmsg`、`sendmmsg`、suffix、空 batch 和错误路径；[报告](../experiments/tokio-quiche-gate/results/2026-11-13/linux-musl-socket-tests.json) |
| 实验 lockfile `cargo audit` | 无漏洞 advisory；有 `yaml-rust` 未维护警告 `RUSTSEC-2024-0320`，由 foundations 引入 |
| 实验 `cargo deny ... licenses sources bans` | 未通过现有 license policy：`foldhash 0.2.0` 的 Zlib 不在 allowlist；sources/bans 通过且存在重复版本警告。没有放宽生产策略 |

aarch64 Linux、Linux GNU ASan、实际 TUN/offload、双后端 MASQUE/H2、资源洪泛、
LAN 性能与 soak 尚未执行；当前隔离端点尚不包含对应生产路径。这些检查仍是补丁
进入生产和后续阶段的要求。Linux 测试只使用自建临时目录，结束后已删除；没有
修改机器的接口、路由、防火墙或服务配置。

重现命令和探针范围见[实验 README](../experiments/tokio-quiche-gate/README.md)。
源代码依据为固定发布包的 `quic/{raw,router/mod,router/acceptor,io/worker,
addr_validation_token}.rs`、`http3/driver/{mod,server,streams,datagram}.rs` 和
`settings/config.rs`；公开 API 见 [tokio-quiche 文档](https://docs.rs/tokio-quiche/latest/tokio_quiche/)。
