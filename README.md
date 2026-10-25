# Zeek server 流量日志镜像

被动抓取共享网络命名空间中的流量，对 TCP/UDP 会话输出 **server 视角**的 IP 层累计字节数。没有代理、没有业务监听端口、不修改路由/防火墙、不保存 PCAP。

本仓库只提供 `Dockerfile`，**不提供 `docker-compose.yaml`**。可由其他 Compose 项目构建/引用镜像。

## 快速开始

```sh
docker build -t zeek-monitor:local .

# target-service 是已运行的业务容器名。
# IP 必须改成在它的网络命名空间、抓包接口上实际可见的 server 地址。
docker run -d --name zeek-monitor \
  --network container:target-service \
  --cap-drop ALL --cap-add NET_RAW \
  --read-only --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m \
  --stop-timeout 30 \
  -e CAPTURE_INTERFACE=eth0 \
  -e 'LISTEN_0=tcp 100.64.0.20 443,8000-8100' \
  -e 'LISTEN_1=udp 100.64.0.20 1234' \
  -e TZ=Asia/Shanghai \
  zeek-monitor:local

docker logs -f zeek-monitor
```

镜像固定使用官方 `zeek/zeek:9.0.0`，Python 使用系统标准库。升级时可覆盖 `--build-arg ZEEK_IMAGE=zeek/zeek:<明确版本>`，升级后应重跑全部验收。固定基础镜像已包含 Python 3.13 与 tzdata，构建时校验依赖，无需另外访问 Debian 软件源；首次构建仍需拉取基础镜像。

默认以容器 root 运行；示例剥离全部能力，只加 `NET_RAW`。本项目实测此权限可完成共享网络抓包，不需要 `privileged`、Docker socket 或宿主机目录权限。不同运行环境的 seccomp/AppArmor/rootless 限制仍需单独核对；不要遇到错误就直接开启 privileged。

> 同一个 bridge 网络不等于共享网络命名空间。应使用 Docker 的 `--network container:...`，或外部 Compose 的 `network_mode: service:<service名>`。目标容器被重新创建后，监控容器也应重新创建以加入新的命名空间。

## 配置

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `LISTEN_<数字>` | 无，至少一项 | `tcp\|udp IP 端口列表`，例如 `tcp 100.64.0.20 443,8000-8100` |
| `CAPTURE_INTERFACE` | `eth0` | 单个抓包接口名，例如 `eth0`、`lo`、`tailscale0`、`any` |
| `LOG_FORMAT` | 见下文 | 单行模板 |
| `LOG_FILE` | `/dev/stdout` | 普通文件路径；`-` 也表示 stdout |
| `TZ` | `UTC` | IANA 时区，例如 `Asia/Shanghai` |
| `IGNORE_CHECKSUMS` | `true` | `true/false/1/0`，true 对应 Zeek `-C` |
| `UDP_INACTIVITY_TIMEOUT` | `60` | UDP 流无活动超时，整数秒，1–86400 |
| `SHUTDOWN_TIMEOUT` | `15` | 转发停止信号后等待 Zeek 退出的上限，整数秒，1–86400 |

- `LISTEN_0`、`LISTEN_3`、`LISTEN_100` 均可，编号无需连续。
- TCP/UDP 大小写不敏感；IP 支持精确 IPv4/IPv6，不支持域名、CIDR、通配符、IPv6 zone ID。
- IPv4-mapped IPv6 地址按对应 IPv4 规范化，与 Zeek 的地址表示对齐。
- 端口支持 `443`、`443,8000-8100`；范围两端都包含，合法值为 1–65535。
- 同一 IP/协议的重复、相邻、重叠范围合并；每份 Zeek 会话记录最多输出一次。
- 非法规则、未知格式变量、无规则、时区错误或日志文件不可写时非零退出；不会静默回退为全量日志。
- `LISTEN_*` 只是 **server 身份规则**，不绑定、不占用端口。
- 首版在指定接口抓包后由 Zeek 严格匹配规则，**没有添加按端口裁剪的内核 BPF**，避免遗漏 IP 分片及双向统计所需报文；高吞吐部署需要另做容量测试。
- 默认忽略校验和，以适应容器/虚拟网卡的 checksum offload。代价是也可能接受实际校验和错误的报文；若抓包数据校验和可信，可设为 `false`。不修改宿主机网卡卸载配置。

仅校验环境配置（不抓包、不打开日志文件；不等同于检查抓包权限或 Zeek 编译）：

```sh
docker run --rm \
  -e 'LISTEN_0=tcp 100.64.0.20 443,8000-8100' \
  zeek-monitor:local --check-config
```

## server 与 remote 的判断

两个端点分别按 **IP + 协议 + 端口** 匹配所有规则：

| orig 命中 | resp 命中 | 结果 |
|---|---|---|
| 是 | 否 | orig 是 server，resp 是 remote，输出 |
| 否 | 是 | resp 是 server，orig 是 remote，输出 |
| 是 | 是 | 受监控服务之间的流量，不输出 |
| 否 | 否 | 不涉及受监控服务，不输出 |

remote 不一定是公网地址或连接发起方。对端只有端口号为 `443`、或者只有 IP 属于某个 server，都不代表它命中 server 规则。

例如配置 `tcp 100.64.0.20 443` 和 `tcp 100.64.0.21 443`：

```text
100.64.0.11:61270 ↔ 100.64.0.20:443   输出
100.64.0.21:443   ↔ 100.64.0.20:443   不输出
100.64.0.21:61270 ↔ 100.64.0.20:443   输出
100.64.0.99:443   ↔ 100.64.0.20:443   输出
```

server 主动发起连接时，**其本地端口也必须命中规则**。server 用临时端口访问其他服务，不会仅因 server IP 相同就纳入统计。

## 日志格式

支持 `$name`、`${name}`；`$$` 输出字面量 `$`。不执行 shell、不进行递归变量展开；未知变量、孤立 `$`、换行/控制字符会报错（允许制表符）。模板必须非空。

| 变量 | 含义 |
|---|---|
| `$remote_addr` | 非 server 端 IP，IPv6 不自动加方括号 |
| `$remote_port` | 非 server 端端口 |
| `$time_iso8601` | Python **输出这条日志时**的墙钟时间，秒精度，带时区；不是首包时间 |
| `$protocol` | `TCP` 或 `UDP` |
| `$bytes_sent` | server → remote 的 IP 层累计字节数，即 out_bytes |
| `$bytes_received` | remote → server 的 IP 层累计字节数，即 in_bytes |
| `$session_time` | Zeek `duration`，秒，保留三位小数；缺失时 `0.000` |
| `$server_addr` | 命中规则的 server IP |
| `$server_port` | 命中规则的 server 端口 |

默认格式：

```text
$remote_addr:$remote_port - [$time_iso8601] $protocol in_bytes=$bytes_received out_bytes=$bytes_sent session_time=$session_time server=$server_addr:$server_port
```

自定义示例（shell 中用单引号保护 `$`）：

```sh
-e 'LOG_FORMAT=$remote_addr:$remote_port - [$time_iso8601] $protocol in_bytes=$bytes_received out_bytes=$bytes_sent duration=$session_time server=$server_addr:$server_port'
```

如果要避免 IPv6 地址和端口的歧义，可以使用 `remote=[$remote_addr]:$remote_port server=[$server_addr]:$server_port`（IPv4 也会有括号），或分别输出 IP/端口字段。

**外部 Compose 的 YAML 值**会先由 Compose 插值：写成 `$$remote_addr`、`$$bytes_sent` 等，容器内才会收到 `$remote_addr`、`$bytes_sent`。YAML 单引号本身不能替代 Compose 的转义。配置本镜像后端模板的字面量 `$` 需要最终传入 `$$`；在 Compose YAML 中相应写 `$$$$`。其他环境文件/插值来源应以最终容器环境为准。

## 统计边界与输出时机

- 使用 Zeek `orig_ip_bytes` / `resp_ip_bytes`，包括 IP 头及传输层内容；不是业务载荷、不是链路层线速计费字节，也不是单包大小。
- orig 是 server 时：sent = orig_ip_bytes，received = resp_ip_bytes；resp 是 server 时相反。
- 输出时机由 Zeek 的连接记录生命周期决定：连接关闭后的清理、超时或正常退出时汇总；不是看到 FIN 就保证立即输出。
- UDP 按双向流及无活动超时汇总，不是每个数据报一条日志。长连接/持续 UDP 流可能长时间没有日志；本版本没有周期快照。
- `session_time` 沿用 Zeek duration；正常 TCP 关闭的最终 ACK 等尾部非生产性报文不一定计入 duration，但仍计入相应 IP 字节统计。
- IP 字节统计以 Zeek 实际观测到的报文为准，重传、丢包、采集起止时间及接口选择都会影响结果。不会去重所有网络路径上的重复观测。
- PCAP 回放的 `$time_iso8601` 仍为**回放输出时刻**，不是历史包时间；duration 和字节数来自 PCAP。
- 未建立成功、单向连接也可能产生记录。未观测到对向报文时，对应计数可能为 0，不能据此断言对端没有发送。

只加载 connection 相关脚本，不启动默认 HTTP/DNS/TLS 等应用日志分析。默认本地/远端日志写出关闭，移除 Conn 默认过滤器，但保留 `Conn::log_conn` 回调。没有默认 `conn.log`、`http.log`、`dns.log`、`weird.log`，也没有原始报文落盘。运行诊断走 stderr；`docker logs` 通常同时展示 stdout 和 stderr。

## 文件日志、轮转和停止

文件模式在以上 `docker run` 参数中增加：

```sh
-v "$PWD/logs:/logs" \
-e LOG_FILE=/logs/access.log
```

- 自动创建父目录，文件追加写入，每条刷新用户态缓冲；不做每行 `fsync`，不保证断电持久性。
- 新文件权限上限为 `0640`，进程 umask 为 `027`；默认 root 创建的挂载文件可能需要宿主机相应读取权限。
- 仅支持普通文件、`/dev/stdout` 或 `-`；不支持 FIFO、socket 等特殊输出目标。
- 未配置内置按大小/时间轮转。外部先 rename 文件，再向监控容器发送 `SIGHUP`，进程会重新打开原路径，正在统计的会话不重启。

```sh
mv logs/access.log logs/access.log.1
docker kill --signal HUP zeek-monitor
```

`SIGHUP` 对 stdout 是无操作。文件 reopen/写入失败时非零退出，避免监控悄悄丢日志。

```sh
docker stop --time 30 zeek-monitor
```

启动器将 SIGTERM/SIGINT 转发给 Zeek，持续读取退出期间的最终记录，刷新日志并回收子进程。Docker 的停止期限应大于 `SHUTDOWN_TIMEOUT`；进程强杀、OOM、主机宕机不保证未完成会话能落盘。超过内部退出期限会强杀 Zeek并非零退出。Zeek 进程非零退出同样传播给容器。

输出管道是有界的；日志磁盘/下游持续阻塞会反压抓包过程，可能丢包，不能当作可靠消息队列。没有自动重启策略，交由外部部署设置。

## 网络可见性排查

1. 确认网络命名空间真的共享，并确认抓包接口。
2. 确认配置 IP 是该接口上的可见 IP；Docker 发布端口的 DNAT 可能改变目标 IP/端口。
3. Tailscale 等用户态网络/隧道有额外边界：外层接口上可能只有加密隧道，所配的 `100.64.*` 流量未必出现在 `eth0`。应在能看到明文 IP 流量的接口抓取。
4. 本机服务互访可能走 `lo`；`any` 更方便排查，但在复杂转发/多接口环境可能观测重复流量，不是字节统计去重的保证。
5. 检查 stderr 中是否有接口、权限、校验和或写入错误。`ready: Zeek scripts initialized` 仅表示脚本完成初始化，不是“业务已有流量/统计完整”的证明。
6. 等待连接清理或 UDP 超时；长连接没有中途汇总。

共享服务网络只赋予这个命名空间的可见性，不代表能看到宿主机或其他网络命名空间的所有流量。当前未内建掉包率告警/生产容量监控，生产上线需另行评估。

## 开发与验证

宿主机 Python 需 **3.11+**（用到 `string.Template` 的验证接口与系统时区库）；无需宿主机安装 Zeek。

```sh
# 配置、模板、文件输出单元测试及 fake Zeek 的进程生命周期测试
python3 -m unittest discover -s tests -v

# 构建镜像，再运行全部测试，包含真正的 Zeek 和临时共享网络服务
docker build -t zeek-monitor:test .
ZEEK_TEST_IMAGE=zeek-monitor:test python3 -m unittest discover -s tests -v
```

不指定 `ZEEK_TEST_IMAGE` 时真实 Docker 测试明确 skip，不视为通过。Docker 测试创建随机名称的临时网络/容器，并在 finally 清理，不会操作现有业务容器。测试构造流量仅在新建的隔离测试网络内发送。

测试层次：

- 单元：配置错误、范围合并、时区、全部模板变量、追加和轮转、FIFO 防阻塞。
- fake Zeek 进程：SIGTERM 转发、最终记录排空、退出码传播、超时强杀、坏 JSON 失败；**不证明 Zeek 行为**。
- 合成 PCAP + 真实 Zeek：18 个流，12 条应输出记录；覆盖 TCP/UDP、IPv4/IPv6、server 为 orig/resp、两端命中/都未命中、端口边界/协议不匹配及重复规则；独立按构造的 IP 长度核对字节计数。
- 真实 Docker 共享网络：TCP/UDP 收发、端口排除、UDP 超时、最小抓包能力、只读根文件系统、文件轮转、退出排空和重启追加。
- 直接运行 Zeek 后检查工作目录，确认没有默认日志文件。

单独生成可复现的 PCAP：

```sh
python3 tests/pcap_fixture.py .artifacts/pcap
# 环境变量需与 tests/pcap_fixture.py 的 LISTEN/FORMAT 一致方可逐行比较 expected.log。
docker run --rm --network none --cap-drop ALL \
  -v "$PWD/.artifacts/pcap:/fixtures:ro" \
  -e 'LISTEN_0=tcp 100.64.0.20 443,8000-8100' \
  -e 'LISTEN_1=udp 100.64.0.20 1234' \
  zeek-monitor:local --read-pcap /fixtures/sessions.pcap
```

PCAP 是**合成输入**；共享网络测试是真实本地容器抓包，但两者均不替代用户实际服务器/NAT/Tailscale 拓扑的现场验收。具体本次执行结果见 `docs/runs/`。

## 代码结构

```text
Dockerfile                 官方 Zeek + Python 标准库
src/config.py              环境变量校验、合并范围、生成数据型 Zeek 配置
src/formatter.py           白名单模板、追加文件、SIGHUP reopen
src/entrypoint.py          PID 1、子进程监督、内部 JSON 管道
zeek/monitor.zeek          端点匹配、方向归一化、IP 字节统计输出
tests/                     单元、进程、PCAP 和 Docker 验收
docs/runs/                 实际验证记录
```

## 官方参考

- [Zeek 官方镜像与安装](https://docs.zeek.org/en/v9.0.0/install.html)
- [Conn::Info 字段与 Conn::log_conn](https://docs.zeek.org/en/v9.0.0/scripts/base/protocols/conn/main.zeek.html)
- [Zeek 日志框架](https://docs.zeek.org/en/v9.0.0/frameworks/logging.html)
- [Zeek 参数与 checksum offload](https://docs.zeek.org/en/v9.0.0/tutorial/invoking-zeek.html)
- [Docker Compose 服务网络模式](https://docs.docker.com/reference/compose-file/services/#network_mode)
- [Compose 插值与美元符号转义](https://docs.docker.com/reference/compose-file/interpolation/)
