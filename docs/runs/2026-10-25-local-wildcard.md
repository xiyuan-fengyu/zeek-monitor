# 2026-10-25：通配服务端 IP，限定当前共享网络命名空间

## 修正后的语义

`0.0.0.0` / `::` / `[::]` 不是“忽略端点 IP”。它们分别代表当前网络命名空间的本机 IPv4 / IPv6 地址，协议与端口仍必须匹配。

- 启动时调用 libc `getifaddrs` 枚举接口地址，通过 Python 标准库 ctypes 实现；无需新增软件包或网络能力。
- 在共享 service/container 网络模式下自动获取业务容器的地址；不依赖 DNS/hostname，不把整个私网/局域网范围当成本机。
- Zeek 中以 `Monitor::local_hosts` 保存本机地址快照，并识别 `127.0.0.0/8` 和 `::1` 回环地址。
- 对端局域网 IP 不属于本机时，即使源端口也等于服务端口，仍正常记录。
- 两端均为本机地址且各自协议/端口均命中时跳过。两端都本机但一端端口未命中时仍记录。
- 未配置的外部端点不会因目的端口相同而被当成 server；精确 IP 规则继续按原语义生效。
- 日志保留真实 server IP 与原有方向映射。
- 本机地址发现失败则启动失败，不回退为任意地址。

地址集合为启动快照，IP 变化需重启；业务网络命名空间更换需重新创建监控容器。SIGHUP 仍仅重开日志。

## 变更文件

- `src/local_addresses.py`：只读接口地址发现。
- `src/config.py`：接受 IPv6 方括号写法；通配规则生成本机地址集合。
- `zeek/monitor.zeek`：精确规则或“本机地址 + 通配规则”匹配。
- `tests/test_local_addresses.py`、`tests/test_unit.py`：发现结果、失败路径、格式解析及生成配置。
- `tests/pcap_fixture.py`、`tests/test_docker.py`：本机/远端区分、同端口及内部流量验收。
- `README.md`：使用方式、例子、启动快照及历史 PCAP 边界。

## 实际验证

```sh
docker build -t zeek-monitor:test .
ZEEK_TEST_IMAGE=zeek-monitor:test python3 -m unittest discover -s tests -v
```

最终结果：

```text
Ran 28 tests in 32.695s
OK
```

无 skip。Docker Desktop Linux/amd64、Zeek 9.0.0；本地构建镜像 ID：

```text
sha256:4354be1ffc7fb3181f10bbf4cc767cd344e51227c901f15ea9168372a401dee4
```

- 原有精确 IP 的 18 流 PCAP 回归继续得到预期的 12 条输出。
- 新增通配 PCAP：27 个流，IPv4/IPv6/双栈规则分别输出 10/6/16 条。使用合成本机地址快照，真实 Zeek 执行，并逐条核对端点、方向、字节数及 duration。
- 覆盖远端同源端口、多本机接口 IP、两个回环地址、回环与本机接口互访、两端本机但仅一端端口匹配、外部同端口及地址族隔离。
- 真实 Docker 共享网络：监控容器不接收预先计算的 server IP，仅配置 `tcp 0.0.0.0 18080` / `udp 0.0.0.0 18081`，自动发现本机地址并正常抓包。
- 同一测试 LAN 中，远端客户端分别绑定 TCP 18080 / UDP 18081 再访问服务端同端口，两条会话均输出，server 地址为真实业务容器 IP；不会误作两端 server。
- 保持 `--cap-drop ALL --cap-add NET_RAW`、只读根文件系统；仍通过轮转、停止排空、重启追加、无默认日志及错误退出测试。
- 在宿主 macOS 实际执行只读 `getifaddrs` 测试，确认能够获取精确接口地址及回环地址；容器中的实际发现由上述 live 测试验证。
- 检查测试容器和网络已清理，没有操作业务容器。

本地详细日志：`.artifacts/build-local-wildcard.log`、`.artifacts/tests-local-wildcard.log`。

## 边界

- 不代表用户生产拓扑已验收；IPv6 和回环流量的本次抓包证据主要来自合成 PCAP 的真实 Zeek 回放。
- PCAP 测试提供的本机地址快照不是实际网络枚举；真实枚举另外由 live 测试验证。
- 历史 PCAP 没有原始容器网络配置，使用普通 `--read-pcap` 通配时只能读取当前运行环境地址。历史回放建议配置精确 server IP。
- 不含地址动态订阅、高负载性能、丢包率和长期稳定性验收。
