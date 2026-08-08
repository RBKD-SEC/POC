# Spring / ThinkPHP 调研沉淀报告

> 任务：`docs/research-spring-thinkphp-sediment-brief.md`（编排方批准书 `docs/research-spring-thinkphp-sediment-approval.md`）
> 实施时间：2026-08-08 ｜ 实施者：pi ｜ 未执行任何 git 操作（交编排方统一处理）

## 一、改动清单（三仓库）

### 仓库 1 — `~/DEV/finger`（finger.json，wappalyzer 兼容）

| 项 | 改动 |
|----|------|
| 文件 | `finger.json` |
| 改动 | `apps` 末尾追加 2 个条目，总数 **120 → 122** |
| 验证 | `python3 -c "import json; json.load(open('finger.json'))"` 通过；`jq empty` 通过 |

新增条目：

- **ThinkPHP**：`cats:[18]`（Web 框架，对齐仓库 JeecgBoot/JeeSite/RuoYi 惯例，**未**用任务书初稿的 `[1]`/CMS）
  - `headers.x-powered-by` = `ThinkPHP(?:\s([\d.]+))?\;version:\1`（**版本提取**，含无版本号回退）
  - `html` = `/Library/Think/`、`/thinkphp/library/think/`、`ThinkPHP</a><sup>([\d.]+)</sup>\;version:\1`
  - `implies: ["PHP"]`（与 MetInfo/PbootCMS 一致；OneThink 已 `implies:["ThinkPHP","PHP"]`，本条目使其可被独立验证）
- **Spring Framework**：`cats:[18]`，`implies:["Java"]`（JeecgBoot 已 `implies:["Java",...]`）
  - `html` = `Whitelabel Error Page`、`"status":999`
  - `cookies.jsessionid` = `\;confidence:50`（**关键调和**：见下方「诚实说明 #2」）

### 仓库 2 — `~/DEV/RBKD-templates`（nuclei 模板，补充不重复）

| 项 | 改动 |
|----|------|
| 新增 | `http/technologies/thinkphp-detect.yaml`（**增强版**） |
| 跳过 | `http/technologies/spring-detect.yaml` —— **不建**（见查重结论） |
| 验证 | `nuclei -validate -t http/technologies/thinkphp-detect.yaml` → **All templates validated successfully** |

`thinkphp-detect.yaml` 相比官方 `nuclei-templates/http/technologies/thinkphp-detect.yaml` 的**实质增强**（非复制）：

1. **新增 `/index.php?m=1` 版本泄露页请求**（官方仅请求首页 `{{BaseURL}}` 与随机模块路径 `/?s=...&m=...`）
2. **新增版本 `extractors`**：从页脚 `ThinkPHP</a><sup>([0-9.]+)</sup>` 提取版本号（官方**无任何版本提取能力**）
3. **新增 `ThinkPHP</a><sup>` 特异性 body 标记**
4. 保留官方的 `X-Powered-By: ThinkPHP` 头与 `/Library/Think/`、`/thinkphp/library/think/` body 标记

### 仓库 3 — `~/DEV/POC`（pocsuite3，一键检测利用）

| 项 | 改动 |
|----|------|
| 新增 | `pocsuite3/spring4shell/cve_2022_22965_rce_poc.py` |
| 新增 | `pocsuite3/spring4shell/README.md`（产品目录说明，对齐 n8n/react 风格） |
| 更新 | `README.md` pocsuite3 索引表新增 `spring4shell/` 行 |
| 未改 | `TODO.md`（CVE-2022-22965 不在清单内，已核实，无需标记） |
| 验证 | `python3 -m py_compile` + `ast.parse` 通过；pocsuite3 未安装（见诚实说明 #5） |

POC 采用经 afrog 验证的 **GET 变异技术**（不使用 fscan POST 方案）：
1. `GET ?class.module.classLoader.resources.context.parent.pipeline.first.*` 重配 Tomcat AccessLogValve，向 `webapps/ROOT/{随机8位}.jsp` 写入 webshell（`%{c2}i`/`%{c1}i`/`%{suffix}i` 由请求头 `c2=<%`/`c1=Runtime`/`suffix=%>//` 插值）
2. `GET /{shell}.jsp?pwd=j&cmd=<cmd>` 经 `Runtime.exec` 执行命令并回显
3. `_verify` 匹配 `root:.*?:[0-9]*:[0-9]*:`（/etc/passwd）即证明 RCE
4. **三模式（`_verify`/`_attack`/`_shell`）均在 `finally` 中 `_cleanup()`**：执行 `find / -name {shell}.jsp -delete` 并 GET 复核返回 404（不留痕）

## 二、查重结论（先查重再建）

### finger（120 → 122）
- 实施前复查：`apps` 中无 `ThinkPHP`/`Spring Framework`/`Spring`/`Spring Boot` 作为**独立 app 键**。
- 注意：`OneThink` 的 `implies:["ThinkPHP","PHP"]`、`JeecgBoot` 的 `implies:["Java","Spring Boot","Vue.js"]` 仅是**被联动引用**的名字，这些名字此前无独立指纹条目（即 implies 形同空转）。本次新增的 `ThinkPHP`/`Spring Framework` 独立条目恰好**激活**了这些 implies 关系，无重复。
- 与 wappalyzergo 内置库关系：见诚实说明 #4。

### RBKD-templates
- `http/technologies/` 下原本**无** thinkphp/spring 指纹模板。
- **ThinkPHP**：官方 `nuclei-templates/http/technologies/thinkphp-detect.yaml` 存在但**缺版本提取、缺 `/index.php?m=1` 向量** → 有实质增强空间 → **建增强版**。
- **Spring**：官方覆盖**充分**，无增强空间 → **跳过**。官方覆盖清单：
  - `http/technologies/spring-detect.yaml`（`/error` → `"status":999` + 500）
  - `http/technologies/springboot-whitelabel.yaml`（Whitelabel 错误页）
  - `http/technologies/springboot-actuator.yaml` + `http/misconfiguration/springboot/` 下 12 个端点模板（env/heapdump/beans/mappings/jolokia …）
  - `workflows/springboot-workflow.yaml`
  - 本仓库已有 `workflows/spring-boot.yaml` 聚合上述检测
  - 结论：再建 `spring-detect` 与官方完全重复，违反「补充不重复」原则 → **不建**（批准书决策点 1）
- nuclei 官方 thinkphp 漏洞模板（`thinkphp-501-rce`、`thinkphp-2-rce`、`thinkphp6-arbitrary-write` 等）与本指纹模板**职责不同**（漏洞 vs 指纹），不构成查重冲突。

### POC
- 实施前复查：`grep -rli "spring\|thinkphp\|22965\|spring4shell" ~/DEV/POC/` 仅命中本任务文档（brief/approval）与 `.git` 历史，**无现存 POC 脚本**。
- nuclei 官方虽含 `http/cves/2022/CVE-2022-22965.yaml`，但其走 **OAST 反连**（`interactsh-url`），仅做**存在性判定**、无命令执行回显、无一键利用。POC 仓库定位「nuclei 无法覆盖 / 需一键利用」→ pocsuite3 版（GET 变异 + 命令回显 + 交互 shell + 自动清理）**有独立价值，保留**。

## 三、验证证据

| 仓库 | 验证命令 | 结果 |
|------|----------|------|
| finger | `python3 -c "import json; json.load(open('finger.json'))"` | ✅ 通过，apps=122 |
| finger | `jq empty finger.json` | ✅ parse OK |
| RBKD | `nuclei -validate -t http/technologies/thinkphp-detect.yaml`（nuclei v3.11.0） | ✅ All templates validated successfully |
| RBKD | `python3 -c "import yaml; yaml.safe_load(...)"` | ✅ 结构符合预期（2 paths / 2 matchers / 1 extractor） |
| POC | `python3 -m py_compile cve_2022_22965_rce_poc.py` | ✅ 无语法错误 |
| POC | `python3 -c "import ast; ast.parse(...)"` | ✅ AST OK |
| POC | 清理逻辑核对 | ✅ `_cleanup` ×4（定义+三模式调用）、`finally` ×4（三模式+shell 循环） |
| POC | `pocsuite3 -r ... --verify` 实跑 | ⚠️ **未运行**（本机未安装 pocsuite3，见诚实说明 #5） |

## 四、诚实说明 / 残留风险

1. **cats 取值与任务书初稿不同**：任务书初稿写 `cats:[1]`（CMS），批准书要求「对照现有条目，不硬套 [1]」。仓库现有 Web 框架（JeecgBoot `cats:[18]`、JeeSite/RuoYi）均用 `[18]`（Web frameworks），ThinkPHP/Spring 是框架非 CMS → **采用 `[18]`**，符合批准书「不硬套 [1]」指令。
2. **Spring 的 `jsessionid` cookie 调和**：finger README 铁律 #1 明确「通用 cookie（JSESSIONID …）不要直接当作证据」。批准书要求加 cookie JSESSIONID。核实仓库**实际**做法：通用 cookie 仅作**补充 booster**（如 `苹果CMS:{"maccms_":"\\;confidence:50"}`、`泛微e-cology:{"ecology_JSessionid":""}`）。故按仓库惯例写作 `jsessionid: "\\;confidence:50"`（半强度、不构成独立证据），既满足批准书（cookie 存在）又符合仓库铁律。Spring 主证据仍是 `Whitelabel Error Page` / `"status":999`。
3. **未提供 icon 图标文件**：仓库现有 120 条**全部**带 `icon` 字段，但本次无 ThinkPHP/Spring 的 PNG 图标文件，故**省略 icon**（wappalyzergo 可正常加载，不影响检测）。视觉上与现有条目不完全一致，建议维护者后续补 `ThinkPHP.png`/`Spring Framework.png`。
4. **Spring 与 wappalyzergo 内置库**：finger README 铁律 #5「属内置组件勿重复添加」。wappalyzergo 内置库通常已含 `Spring`。本次新增键名为 `Spring Framework`（非 `Spring`），且补充了 Whitelabel / `"status":999 错误页向量（内置 Spring 未必覆盖）。若编排方认为与内置重复，可剔除该条；ThinkPHP 内置通常**无**，建议保留。
5. **POC 未实跑**：本机未安装 `pocsuite3`（`import pocsuite3` 失败、无 `pocsuite3` 二进制）。仅完成 `py_compile`/`ast.parse` 静态校验与逻辑核对，**未做端到端实测**。请在安装 pocsuite3 的环境对靶机验证：`pocsuite3 -r pocsuite3/spring4shell/cve_2022_22965_rce_poc.py -u http://<vulnerable-target>`。
6. **命令执行限制（Runtime.exec）**：dropped webshell 调 `Runtime.exec(cmd)`，命令按空格分词，**不支持** shell 管道/引号/重定向。清理命令 `find / -name {shell}.jsp -delete` 已刻意保持为空格分词安全的形式（无引号/glob/重定向）。README 已注明。
7. **GET 变异 + 短延迟**：相对原始 afrog，`_exec` 在首次执行失败时 sleep 1s 重试一次，以容忍 AccessLogValve 落盘延迟；payload 本身与 afrog 字节级一致，未改动验证逻辑。

## 五、交付文件

```
~/DEV/finger/finger.json                                                  [改] +2 apps
~/DEV/RBKD-templates/http/technologies/thinkphp-detect.yaml               [新] 增强版
~/DEV/POC/pocsuite3/spring4shell/cve_2022_22965_rce_poc.py                [新] pocsuite3 POC
~/DEV/POC/pocsuite3/spring4shell/README.md                                [新] 产品说明
~/DEV/POC/README.md                                                       [改] 索引表 +1 行
~/DEV/POC/docs/research-spring-thinkphp-sediment-report.md                [新] 本报告
```

未建文件：`~/DEV/RBKD-templates/http/technologies/spring-detect.yaml`（官方已覆盖，跳过）。
未改文件：`~/DEV/POC/TODO.md`（CVE-2022-22965 不在清单）。
