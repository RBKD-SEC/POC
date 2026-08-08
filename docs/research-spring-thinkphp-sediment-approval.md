# 沉淀任务批准书 —— spring/thinkphp 调研沉淀（finger + RBKD-templates + POC）

> 编排方（Hermes）对 pi 实施计划的批复。任务书：`docs/research-spring-thinkphp-sediment-brief.md`（必读，本文件是其补充）。**已获编排方完全批准，直接执行，不要再次请求批准。**

## 计划总体评价

实施计划（finger 2 条目 / RBKD thinkphp-detect 增强 + spring-detect 跳过 / POC spring4shell pocsuite3 脚本）合理，**批准执行**。查重结论与编排方独立核实一致。

## 决策点（已拍板）

### 1. RBKD spring-detect **跳过** — 批准
nuclei 官方已覆盖 spring 全面检测（`spring-detect` /error→"status":999、`springboot-whitelabel`、`springboot-actuator` + 12 个 actuator 端点模板）。再建 spring-detect 与官方重复，违反仓库"补充不重复"原则。**不建**，报告说明理由（官方覆盖清单 + 无实质增强空间）。

### 2. RBKD thinkphp-detect **增强版构建** — 批准
官方 nuclei thinkphp-detect 有 X-Powered-By 头 + body 特征但**无版本提取**。构建增强版：合并头/体标记 + `/index.php?m=1` 版本页 `ThinkPHP</a><sup>([\d.]+)</sup>` **版本 extractor**（官方缺此能力=实质增强）。报告写明"相比官方增强了什么"。

### 3. finger 2 条目 — 批准
- ThinkPHP：X-Powered-By 头 + html（/Library/Think/、/thinkphp/library/think/、版本页）+ implies: [PHP] + **版本提取**（`\\;version:\\1`，符合 MetInfo/PbootCMS 仓库惯例）
- Spring Framework：html（Whitelabel Error Page、"status":999）+ cookie JSESSIONID
- cats 遵循仓库现有分类惯例（对照现有条目，不硬套 [1]）；JSON 合法性 python 校验；apps 总数 120→122

### 4. POC spring4shell pocsuite3 — 批准
- 按 pocsuite3-poc-authoring skill 模板（POCBase 结构、VUL_TYPE/POC_CATEGORY 枚举）
- afrog 已验证 GET mutation 方案（不用 fscan POST）
- **_verify/_attack/_shell 三模式都必须在结束前删除 webshell（清理铁律）**
- `_verify` 匹配 `root:.*?:[0-9]*:[0-9]*:` 正则；证据截断展示
- README 目录表加行；TODO 无该 CVE（已核实）无需改
- 运行验证：pocsuite3 可能未装 → `python3 -c "import ast; ast.parse(...)"` 语法检查 + 报告中如实说明"未运行 pocsuite3 实测"（若未安装）

### 5. 查重纪律 — 已满足
编排方与 pi 双方独立核实：finger 120 apps 无 spring/thinkphp、RBKD 无相关模板、POC 无相关脚本。实施中若发现新重复，按"重复即剔除/跳过"处理并在报告说明。

## 执行指令

- 按计划实施 4 个任务（A finger / B thinkphp 增强 + spring 跳过 / C POC / D 报告）
- 报告：`~/DEV/POC/docs/research-spring-thinkphp-sediment-report.md`（三仓库改动 + 查重结论 + 证据）
- 不做 git 操作。已知未跟踪/已提交文件不得删除。
- 完成后输出：改动摘要、验证证据（finger JSON / RBKD yaml / POC 语法+清理逻辑）、报告路径。
