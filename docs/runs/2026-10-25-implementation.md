# 2026-10-25：Zeek server 流量日志镜像实现及验收

## 实现范围

- `Dockerfile` 使用官方 Zeek 9.0.0；不创建任何 Compose 文件。
- `LISTEN_<数字>`：精确 IP + TCP/UDP + 端口列表/闭区间；范围合并且不展开为数万个端口项。
- Zeek 对两端分别匹配，仅恰好一端为 server 时输出，方向与连接发起方无关。
- Python 标准库解析配置、格式化日志、追加写入、SIGHUP 重新打开文件，以及监督 Zeek 的退出。
- 用户要求的七个格式变量全部支持，并增加 server_addr/server_port。
- 内部 JSON 走有界管道不落盘；默认 Zeek 日志写出关闭，无 PCAP 保存。
- 提供离线 PCAP 回放及无抓包的配置校验入口。

## 环境与镜像

实测平台：macOS 宿主机上的 Docker Desktop Linux/amd64 容器环境。

```text
Docker Engine: 29.6.1
Zeek:          9.0.0
容器 Python:   3.13.5
宿主 Python:   3.14.0
基础镜像:      zeek/zeek:9.0.0
RepoDigest:    sha256:70733f4e540ba1608e37e00c6a93d009f79734262c9ec2ba09d90aa9abc16de5
构建镜像:      zeek-monitor:test
Image ID:      sha256:e2d503c2d260ccf7f63fce3748fa59fe365f776c225aeaa441d0fefa35dad6f6
镜像大小:      536190960 bytes（Docker inspect 的本地镜像大小，并非压缩下载量）
```

基础镜像已经包含 Python 与 tzdata。最终 Dockerfile 仅校验依赖并复制源码，避免无必要的 apt 下载；未更改宿主机 Docker 配置/镜像源。

## 重现命令

```sh
docker build -t zeek-monitor:test .
ZEEK_TEST_IMAGE=zeek-monitor:test python3 -m unittest discover -s tests -v
```

本地执行产物（在 `.gitignore` 中忽略，可由上述命令及 PCAP 生成器重建）：

- `.artifacts/build-final.log`：最终镜像构建日志。
- `.artifacts/tests.log`：全部测试的实际结果。
- `.artifacts/pcap/sessions.pcap`：标准库构造的合成报文。
- `.artifacts/pcap/expected.log`、`actual.log`：预期及实际 Zeek 格式化记录。
- `.artifacts/pcap/manifest.json`：流与预期输出条数。

## 已通过的验收

最终完整执行结果：`Ran 21 tests in 22.156s`，`OK`，无 skip。

### 1. 单元及进程测试：17 项

配置语法/默认值/错误、IPv6 规范化、范围合并、协议隔离、所有模板变量、时区、字面量美元符号、非法模板/记录、文件追加/刷新/轮转、FIFO 不阻塞。

进程测试以 **fake Zeek 可执行文件** 验证正常输出、子进程退出码传播、坏/截断/非对象 JSON 失败、SIGTERM 最终记录排空、忽略停止信号时超时强杀。这一组不作为真实 Zeek 的证据。

### 2. 真实 Zeek 离线测试

标准库生成 **18 个流**，真实 Zeek 9.0.0 回放输出 **恰好 12 条**。关闭 `IGNORE_CHECKSUMS` 后也通过，合成报文具有正确校验和。

覆盖：

- TCP、UDP；IPv4、IPv6；server 分别位于 orig 和 resp。
- 两端均命中、两端均未命中均不输出。
- 对端端口同为 443 但 IP 未命中时正常输出。
- 对端 IP 属于 server 但端口为临时端口时正常输出。
- 8000、8100 边界命中，7999、8101 不命中；UDP 443 不会命中 TCP 443 规则。
- 重复/重叠配置不会重复输出。
- 逐条比对端点、协议、IP 字节数和三位小数 duration。

部分实测记录（分隔字段依次为 remote IP、remote port、协议、received、sent、duration、server IP、server port）：

```text
100.64.0.11|51001|TCP|205|129|0.600|100.64.0.20|443
100.64.0.11|51002|TCP|129|205|0.600|100.64.0.20|443
100.64.0.11|51003|UDP|33|37|0.100|100.64.0.20|1234
100.64.0.11|51004|UDP|37|33|0.100|100.64.0.20|1234
2001:db8::11|51012|TCP|305|189|0.600|2001:db8::20|443
2001:db8::11|51013|TCP|189|305|0.600|2001:db8::20|443
```

测试数据载荷为 orig 5 bytes、resp 9 bytes，计数与独立计算的 **IP 包长度总和**一致，而不是误用了载荷长度。

另外直接执行 Zeek 后保留工作目录检查，确认 **没有任何默认日志文件**。

### 3. 真实共享网络抓包

创建独立的临时 Docker 网络与业务容器；监控容器使用 `--network container:<测试业务容器>`：

- `--cap-drop ALL --cap-add NET_RAW`；没有 privileged、NET_ADMIN 或 Docker socket 挂载。
- 只读根文件系统，只有 `/tmp` tmpfs 和日志目录可写。
- 真实 TCP 18080、UDP 18081 请求/响应；同 IP 的 TCP 18082 被排除。
- UDP 2 秒无活动超时后输出，实际 received=33、sent=37。
- rename 日志 + SIGHUP 后，新记录进入新文件，旧文件保留。
- 在 UDP 超时前停止容器，最终记录正常输出，容器退出码为 0。
- 再启动后追加原文件，不覆盖历史记录。
- 未发现额外业务日志文件。

测试通过 finally 清理自己创建的容器/网络；没有操作现有业务容器。

### 4. 失败路径

真实镜像验证：无 LISTEN 规则、未知格式变量、不存在的抓包接口及不可写的日志路径均非零退出，stdout 不输出伪造业务日志。

## 实现中纠正的实际问题

真实 Zeek 的 `to_json()` 对 interval 会输出文本时间单位，而不是 Python 预期的数值。已在 Zeek 内使用 `interval_to_double()` 明确转换 duration 秒数，并由真实 PCAP 测试验证，未在 Python 端猜测/解析文本单位。

## 尚未验证 / 不承诺的范围

- 用户生产服务的真实 IP、NAT、Tailscale、物理网卡及接口选择。
- Linux 原生部署、arm64、rootless Docker 的现场行为；本次仅 Docker Desktop Linux/amd64。
- IPv6 的真实网络收发：本次 IPv6 证据是合成 PCAP 经真实 Zeek 回放。
- 高吞吐性能、丢包率、资源容量、长期运行与异常断电/OOM 持久性。
- 长连接周期快照：当前不提供；按 Zeek 记录生命周期汇总。
- 完整抓包的保证：未观测到不等于没有发生。
