# 裸 QUIC 性能实验：quiche 与 Quinn

日期：2026-11-12。生产代码基线 `63570f6`（v0.14.23）。本次仅新增实验工具和文档；生产依赖、配置与运行中的服务均未修改。

**本次结果没有支持 Quinn 在所有工作负载下更快。** 固定 quiche 客户端时，Quinn 服务端的可靠 stream 中位吞吐在四个场景中低约 4%–12%；DATAGRAM 结果依赖包大小、客户端和平台。Linux 小包样本波动很大，不能据三次中位数差宣称稳定提升。

正式矩阵计划 192 次，191 次完成、1 次中断。失败是 Mac 上的 Quinn 客户端从 Linux Quinn 服务端下载 stream 时触发 `too many gaps in stream buffer`；同条件追加 10 次均完成。失败没有被成功重试覆盖，也没有混入成功样本的吞吐统计。

## 实验条件与证据

| 项目 | 条件 |
| --- | --- |
| Mac | Apple M4，10 核，16 GiB，arm64，macOS 27.2.1 |
| Linux | Ryzen 9 7940HS CPU 型号，4 vCPU、约 3.3 GiB 的虚拟机，x86_64，Linux 7.0.0-29-generic |
| 构建 | Rust 1.97.1，release + fat LTO；Linux 为 Mac 交叉编译的 musl 二进制 |
| 库 | quiche 0.30.0 / BoringSSL binding 4.22.0；Quinn 0.11.12 / quinn-proto 0.11.19 / Rustls 0.23.46；Tokio 1.54.1 |
| 协议与密码套件 | 裸 QUIC v1，无 H3/MASQUE；AES-128-GCM，临时 ECDSA 证书；客户端校验证书；无 Retry/0-RTT |
| 拥塞/窗口 | CUBIC，初始 10 包，1350 B packet ceiling，16 MiB connection/stream receive window，关闭 PMTUD |
| Runtime/I/O | 每进程单线程 Tokio；普通 UDP syscall，关闭 GSO/GRO；Quinn 使用精简 AsyncUdpSocket，quiche 使用精简自写 driver |
| Socket buffer | 两者请求收/发各 2 MiB；Mac 返回各 2 MiB，Linux 返回各 4 MiB（内核计账口径） |
| DATAGRAM | 64 / 1200 B，256 个在途请求，250 ms 到期，5 秒 offered load；另测 64 B、window=1、目标 100 msg/s 的轻载 RTT |
| Stream | 握手后请求下载 256 MiB，单 bidirectional stream，64 KiB 应用缓冲；验证字节总数和 FIN |
| 顺序与重复 | 四种 client/server 组合，每组三次，交替反转组合顺序；编译与正式测速不并行 |

这是“库 + crypto provider + 此实验 driver”的测量，**没有使用 tokio-quiche**。现有 server 也没有依赖 tokio-quiche；它是 Tokio + 自有 shard loop + quiche。单线程实验不代表生产 Tokio 多线程与多 shard 行为。

源码及完整方法见 [实验 README](../experiments/quic-compare/README.md)。[正式数值记录](../experiments/quic-compare/results/2026-11-12.json)包含全部成功样本、失败标记、每组 min/median/max 和二进制 SHA-256；[独立复测记录](../experiments/quic-compare/results/2026-11-12-stream-followup.json)单独保存。所有记录均不含实际基础设施标识。

## 固定 quiche 客户端：只替换服务端

单位为应用有效载荷 **Mbit/s**；单元格是三次的中位数及 min–max。相对变化为 `Quinn / quiche - 1`，不是统计置信区间。这里所有组均完成 3/3 次。

| 场景 | 工作负载 | quiche 服务端 | Quinn 服务端 | Quinn 相对变化 |
| --- | --- | ---: | ---: | ---: |
| Mac 本机 | DATAGRAM 64 B | 942.0 (926.3–951.7) | 903.2 (889.4–909.1) | -4.1% |
| Mac 本机 | DATAGRAM 1200 B | 1568.9 (1562.7–1582.4) | 1453.1 (1436.1–1463.6) | -7.4% |
| Mac 本机 | Stream 下载 | 2338.8 (2308.2–2353.9) | 2068.6 (1985.8–2096.8) | -11.6% |
| Linux 本机 | DATAGRAM 64 B | 831.7 (796.1–1042.6) | 1048.2 (636.2–1057.5) | +26.0% |
| Linux 本机 | DATAGRAM 1200 B | 2048.0 (2001.3–2077.1) | 2091.6 (2091.4–2112.9) | +2.1% |
| Linux 本机 | Stream 下载 | 2267.2 (2175.8–2506.3) | 2061.2 (1954.0–2207.7) | -9.1% |
| Mac 客户端 / Linux 服务端 | DATAGRAM 64 B | 386.5 (364.3–387.1) | 391.5 (357.1–393.9) | +1.3% |
| Mac 客户端 / Linux 服务端 | DATAGRAM 1200 B | 705.6 (704.4–708.4) | 669.7 (664.6–693.9) | -5.1% |
| Mac 客户端 / Linux 服务端 | Stream 下载 | 1958.4 (1921.4–1992.2) | 1853.5 (1766.3–1856.6) | -5.4% |
| Linux 客户端 / Mac 服务端 | DATAGRAM 64 B | 356.1 (354.0–369.8) | 366.1 (345.9–367.1) | +2.8% |
| Linux 客户端 / Mac 服务端 | DATAGRAM 1200 B | 704.7 (703.9–707.8) | 665.5 (659.0–670.1) | -5.6% |
| Linux 客户端 / Mac 服务端 | Stream 下载 | 1120.1 (1105.2–1179.2) | 1072.5 (1057.4–1131.9) | -4.2% |

Linux 本机 64 B 的两组区间分别为 796–1043 与 636–1058 Mbit/s，明显重叠。观察到的 +26.0% 中位数差不足以确定库的稳定优势。没有设置 CPU affinity、控制宿主机其他负载或锁定 CPU 频率，pacing/调度及 VM 干扰的贡献尚未隔离。

局域网的两个方向也不能合并成一个数字：例如固定 quiche 客户端时，quiche stream 的两个方向分别约 1.96 与 1.12 Gbit/s。没有独立的链路容量基准或包级追踪，不能把方向差直接归因于某个 QUIC 库。

## 全部客户端 / 服务端组合

下表保留客户端效应。64 B 一列是**百万应用回显消息/秒**，不是网卡 UDP pps；一个 QUIC packet 可以承载多个小 DATAGRAM。其余吞吐单位为 Mbit/s。CPU 是完成一次 256 MiB stream 测试的进程 CPU 秒（server / client），包括初始化、握手和关闭；吞吐计时排除握手。

| 场景 | 服务端 | 客户端 | 64 B Mmsg/s | 1200 B Mbit/s | Stream Mbit/s | Stream CPU 秒 S/C | Stream 完成/尝试 |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| Mac 本机 | quiche | quiche | 1.840 | 1568.9 | 2338.8 | 0.919 / 0.731 | 3/3 |
| Mac 本机 | quiche | quinn | 1.799 | 1438.0 | 2389.5 | 0.899 / 0.719 | 3/3 |
| Mac 本机 | quinn | quiche | 1.764 | 1453.1 | 2068.6 | 1.038 / 0.918 | 3/3 |
| Mac 本机 | quinn | quinn | 1.816 | 1440.0 | 2085.0 | 1.030 / 0.927 | 3/3 |
| Linux 本机 | quiche | quiche | 1.624 | 2048.0 | 2267.2 | 0.895 / 0.599 | 3/3 |
| Linux 本机 | quiche | quinn | 1.803 | 1964.7 | 2211.2 | 0.894 / 0.602 | 3/3 |
| Linux 本机 | quinn | quiche | 2.047 | 2091.6 | 2061.2 | 0.984 / 0.722 | 3/3 |
| Linux 本机 | quinn | quinn | 2.025 | 2058.0 | 2069.5 | 0.994 / 0.725 | 3/3 |
| Mac 客户端 / Linux 服务端 | quiche | quiche | 0.755 | 705.6 | 1958.4 | 1.048 / 1.084 | 3/3 |
| Mac 客户端 / Linux 服务端 | quiche | quinn | 0.744 | 657.6 | 1613.1 | 1.134 / 1.287 | 3/3 |
| Mac 客户端 / Linux 服务端 | quinn | quiche | 0.765 | 669.7 | 1853.5 | 1.131 / 1.076 | 3/3 |
| Mac 客户端 / Linux 服务端 | quinn | quinn | 0.705 | 612.7 | 1658.2 | 1.233 / 1.272 | 2/3 |
| Linux 客户端 / Mac 服务端 | quiche | quiche | 0.696 | 704.7 | 1120.1 | 1.910 / 0.926 | 3/3 |
| Linux 客户端 / Mac 服务端 | quiche | quinn | 0.686 | 676.0 | 1177.1 | 1.820 / 0.748 | 3/3 |
| Linux 客户端 / Mac 服务端 | quinn | quiche | 0.715 | 665.5 | 1072.5 | 1.994 / 0.986 | 3/3 |
| Linux 客户端 / Mac 服务端 | quinn | quinn | 0.697 | 626.2 | 1140.5 | 1.876 / 0.835 | 3/3 |

Quinn→Quinn 在 Mac 客户端 / Linux 服务端的 stream 单元格只有 **2 个成功样本**，并有 1 次失败，不应据该单元格的成功中位数宣称可靠性或性能占优。Mac 的 DATAGRAM 在换为 Quinn 客户端后，两种服务端差距明显缩小，也说明不能只比较“quiche 两端”与“Quinn 两端”。

## 延迟、回包缺口与 CPU

固定 quiche 客户端；下表 RTT 单位为 µs，先计算每次测试的 p99，再取三次中位数，不是合并全部样本的 p99。轻载目标为 100 msg/s，所有轻载样本实际为 78.2–90.4 msg/s，受计时与调度影响；未将目标速率当成已实现速率。

| 场景 | 服务端 | 轻载 p99 | 64 B 饱和 p99 | 1200 B 饱和 p99 | 1200 B 回包缺口 |
| --- | --- | ---: | ---: | ---: | ---: |
| Mac 本机 | quiche | 370 | 169 | 1781 | 0.00000% |
| Mac 本机 | quinn | 438 | 174 | 1990 | 0.00000% |
| Linux 本机 | quiche | 652 | 281 | 1386 | 0.00000% |
| Linux 本机 | quinn | 315 | 154 | 1314 | 0.00000% |
| Mac 客户端 / Linux 服务端 | quiche | 1760 | 409 | 3909 | 0.00054% |
| Mac 客户端 / Linux 服务端 | quinn | 1967 | 414 | 4183 | 0.00095% |
| Linux 客户端 / Mac 服务端 | quiche | 1762 | 645 | 3991 | 0.00036% |
| Linux 客户端 / Mac 服务端 | quinn | 1797 | 637 | 4515 | 0.00077% |

正式 DATAGRAM 样本合计发送 331,121,289 条消息，回包缺口 607，无效长度回包 0。本机样本没有回包缺口；LAN 各组缺口均低于 0.002%。缺口包含未回包、超过请求有效期等情况，不等于链路丢包率；RTT 只包含成功回包，不能掩盖缺口。

每次测试的两端 CPU 秒均保存在 JSON。饱和负载下总 CPU 更低也可能只是完成工作更少，需要结合每条回显或每 MiB 的成本判断。未采集 peak RSS、硬件周期、独立 NIC drop、宿主机 steal time 或 syscall profile，因此不对这些指标作结论。

## 失败记录：观察与未验证项

- **范围与观察**：本次正式矩阵第 3 轮，Mac Quinn client / Linux Quinn server，256 MiB stream，16 MiB receive window。客户端约 0.15 秒后以 `too many gaps in stream buffer` 断开；服务端随后报告 peer abort。该次没有吞吐结果。
- **源码证据**：锁定的 quinn-proto 0.11.19 中，`connection/streams/recv.rs` 将 assembler 的 `TooManyChunks` 映射为此 INTERNAL_ERROR。`connection/assembler.rs` 在压缩后 chunk 数仍超过 `MAX_CHUNKS = 1024` 时返回该错误。这解释了报错路径，不证明网络实际存在相同数量的缺口。
- **有限复测**：相同二进制、参数、方向和两端实现，额外 10 次均完成；复测独立存档，未替换正式矩阵中的失败。
- **尚未验证**：未捕获并复放故障数据包，未对比 Quinn 原生 UDP adapter，未缩小 receive window 或加受控 loss/reorder。无法确定是库缺陷、重组上界与工作负载的交互，还是此驱动/环境触发；不能据一次失败泛化为 Quinn 不可靠。
- **后续门槛**：先构建最小可复现实验，验证 native adapter 与窗口/乱序矩阵，再决定是否向上游反馈。不能通过取消资源上界或无界扩大缓冲绕过失败。

## 对架构决策的影响

当前证据支持继续做有边界的可行性验证，而不支持以“Quinn 必然更快”为理由直接替换。若目标是减少自有 driver 维护成本，应把这一收益与真实 MASQUE 能力、资源边界和稳定性分开评估。

现有生产路径使用 BBR2、批量 UDP、可复用 TCP buffer、pacing horizon 与 CID 分片；本实验使用 CUBIC、简单 UDP I/O 和单连接。Quinn 原生 offload、tokio-quiche、H3、证书 roster/reload、TUN 和多连接扩展性均未比较。下一步顺序见[迁移架构与实施草案](quinn-migration-plan.md)，正式实施仍需 review。

## 校验与清理

- 生产 workspace 的 `scripts/check.sh full` 在 Mac 上通过（使用 Python 3.11；默认系统 Python 版本不满足检查要求，已通过隔离 PATH 修正，未改系统安装）。
- 独立实验 crate 的 fmt / Clippy（warnings denied）通过；Mac release 与 Linux musl release 均构建成功；统一 cipher 后 64 个 smoke 组合测试完成。
- 正式矩阵 191/192 完成，失败如上；额外 stream 复测 10/10 完成。测试脚本按失败退出码保留失败结果。
- Linux 临时实验目录已删除，检查时没有残留实验进程；本地临时连接认证材料与测试私钥已移除。未安装远端工具链，未更改服务、路由、防火墙或系统调优。
- 没有运行生产 Linux E2E/TUN、ASan、互联网路径、长 RTT/loss 或多 shard 测试；这些是迁移前的额外门槛，本次裸 QUIC 结果不覆盖它们。
