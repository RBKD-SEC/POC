# 任务书：spring/thinkphp 识别调研结果沉淀（finger + RBKD-templates + POC）

> 本任务书由编排方（Hermes）下达，可直接阅读执行。实施完成后不要执行任何 git 提交/推送操作，由编排方审查后统一处理。
> 涉及仓库（各自独立 git）：`~/DEV/finger`、`~/DEV/RBKD-templates`、`~/DEV/POC`。Pentest-Playbook 的知识沉淀另行处理（见 mv2-rename-brief）。

## 背景

fathom M10 系列（web RCE 检测）实施中发现门控问题，编排方调研了 nuclei-templates + afrog-pocs 的 spring/thinkphp 识别方案。调研结论（已核实，本任务把它沉淀进辅助仓库）：
- **thinkphp 有自身指纹**（X-Powered-By 头 / /Library/Think/ body / 版本页 ThinkPHP</a><sup>x.y.z</sup>），业界不依赖 Apache Server 头
- **spring 识别**：Whitelabel body + /error 端点 `"status":999` 特征；spring4shell 检测用 GET mutation + cat /etc/passwd 回显（afrog 已验证方案，比 fscan POST 可靠）
- 三个仓库定位（用户 2026-08-08 明确）：finger=纯 web 指纹；RBKD-templates=**补充** nuclei 官方（与官方重复即剔除，只留增强/优化/补充）；POC=放 nuclei 无法覆盖的检测/利用（pocsuite3 一键检测利用）

## 必读

1. 各仓库 README（格式说明）：`~/DEV/finger/README.md`（wappalyzer schema）、`~/DEV/RBKD-templates/README.md`、`~/DEV/POC/README.md`
2. 参考模板（本地已有）：
   - `~/nuclei-templates/http/technologies/thinkphp-detect.yaml`（X-Powered-By: ThinkPHP + /Library/Think/ body）
   - `~/nuclei-templates/http/technologies/spring-detect.yaml`（/error → `"status":999` + 500）
   - `~/nuclei-templates/http/technologies/springboot-whitelabel.yaml`
   - `~/nuclei-templates/http/cves/2022/CVE-2022-22965.yaml`（OAST 反连——fathom 不用，但 POC 仓库可参考流程）
   - afrog：`https://raw.githubusercontent.com/zan8in/afrog-pocs/main/CVE/2022/CVE-2022-22965.yaml`（GET mutation + cat /etc/passwd 回显，**已验证方案**）
   - afrog：`https://raw.githubusercontent.com/zan8in/afrog-pocs/main/fingerprinting/thinkphp-detect.yaml`（/index.php?m=1 版本页）

## 任务 A：finger 仓库（finger.json，wappalyzer 兼容）

在 `~/DEV/finger/finger.json` 的 `apps` 增加条目（当前 120 apps，无 Spring/ThinkPHP 指纹）：

```json
"ThinkPHP": {
  "cats": [1],
  "description": "ThinkPHP 国产 PHP 框架",
  "website": "https://www.thinkphp.cn",
  "headers": { "X-Powered-By": "ThinkPHP" },
  "html": ["/Library/Think/", "/thinkphp/library/think/", "ThinkPHP</a><sup>"]
},
"Spring Framework": {
  "cats": [1],
  "description": "Java Spring 框架（Spring MVC/Spring Boot）",
  "website": "https://spring.io",
  "html": ["Whitelabel Error Page", "\"status\":999"],
  "cookies": { "JSESSIONID": "" }
}
```

**要求**：
- 遵守 finger.json 现有 schema（对照 MetInfo/PbootCMS 条目的字段结构）；cats 语义与现有条目一致
- **不要手工大改**：JSON 结构保持（apps 嵌套），只追加条目
- 若有 icon 字段规范，无图标文件就省略（对照现有无 icon 条目）
- 验证：`python3 -c "import json; json.load(open('finger.json'))"` 通过

## 任务 B：RBKD-templates 仓库（补充原则）

`~/DEV/RBKD-templates/http/technologies/` 增加增强模板。**关键：先查重**——nuclei 官方已有 thinkphp-detect/spring-detect，若本地模板与官方完全重复则**不建**（仓库原则：补充/增强，不重复）。核实后：

1. `thinkphp-detect.yaml`（**增强版**，若官方版缺特征则建）：
   - 特征合并：X-Powered-By 头 + /Library/Think/ + /thinkphp/library/think/ + `ThinkPHP</a><sup>` 版本页
   - **版本提取**：`ThinkPHP</a><sup>([\d.]+)</sup>` extractor（官方模板无版本提取——这是增强点）
   - 风格参考 `~/DEV/RBKD-templates/http/technologies/dahua-detect.yaml`（id/info/http/matchers 结构）
2. `spring-detect.yaml`（若官方版缺则建）：
   - GET /error → `"status":999` + status 500（对齐 nuclei spring-detect）
   - 或 Whitelabel body 特征（对齐 springboot-whitelabel）
   - 同样风格

**要求**：
- **先查重再建**：`grep -l "thinkphp" ~/nuclei-templates/http/technologies/` 确认官方模板存在与否；若官方已完全覆盖（含版本提取），如实报告"官方已覆盖，不建"并说明差异
- 增强点必须明确（版本提取 / 多特征合并 / 国内变体），在模板注释或报告里写明"相比官方增强了什么"
- 不复制官方模板原文（增强需有实质差异）

## 任务 C：POC 仓库（pocsuite3，一键检测利用）

**先读 skill**：`pocsuite3-poc-authoring`（Hermes skill，2026-08-08 创建）——pocsuite3 POC 的完整写法（POCBase 结构、VUL_TYPE/POC_CATEGORY 枚举、verify/attack/shell 三模式、pitfalls、查重纪律）。参考实现 `~/DEV/POC/pocsuite3/n8n/cve_2026_21858_rce_poc.py`（已验证的 4 模式完整范例）。

**查重（已由编排方确认）**：finger 无 spring/thinkphp 条目（120 apps）、RBKD-templates 无相关模板、POC 无相关脚本——三仓库均干净。**实施时仍需复查**（用户明确要求防重复）：
```bash
grep -rli "spring\|thinkphp\|22965" ~/DEV/POC/          # 仓库内重复
find ~/nuclei-templates -iname "*spring*" -o -iname "*thinkphp*" 2>/dev/null | head  # nuclei 官方覆盖评估
```
若 nuclei 官方已有可检测模板且无需一键利用 → 如实报告"nuclei 已覆盖，pocsuite3 版不建"（仓库定位：只放 nuclei 无法覆盖/需一键利用的）。

- 路径：`~/DEV/POC/pocsuite3/spring4shell/cve_2022_22965_rce_poc.py`
- 参考已验证方案：afrog CVE-2022-22965（**GET mutation 写 tomcatwar.jsp** + GET 执行 `cat /etc/passwd` 回显 `root:.*` 正则）——不用 fscan POST 方案（已实测 GET 更可靠）
- pocsuite3 标准格式：`class PoC(POCBase)` + `_verify()` 检测 + `_attack()` 利用（按 skill 模板）
- 命令参数：`--url http://target`（verify 模式回显 /etc/passwd 内容即证明）
- **利用后清理**：删除写入的 tomcatwar.jsp（fathom 铁律"不留痕"同样适用 POC 仓库）
- README 更新：`~/DEV/POC/README.md` 目录结构表加 spring4shell 行；`TODO.md` 若该 CVE 在列则标记完成

## 铁律

1. 各仓库独立 git，不做提交（编排方统一处理）
2. **RBKD-templates 查重优先**：与 nuclei 官方完全重复则剔除/不建，只留增强/优化/补充
3. finger.json 用 python 验证 JSON 合法性；不破坏现有 120 条
4. POC 脚本含清理逻辑（不留痕）；pocsuite3 格式对齐仓库现有脚本
5. 诚实报告：各仓库改动清单、查重结论（官方有无覆盖、差异点）、验证证据
6. 报告：`~/DEV/POC/docs/research-spring-thinkphp-sediment-report.md`（三仓库改动汇总）

## 验收

1. finger：JSON 合法、ThinkPHP/Spring 条目存在、特征与调研结论一致
2. RBKD-templates：查重结论明确；建了的模板有实质增强（版本提取等）；没建的有理由
3. POC：pocsuite3 脚本可运行（`pocsuite3 -r ... -u <target> --verify` 或至少 `python3 -c "import ast; ast.parse(open('...').read())"` 语法过）、含清理逻辑
4. 报告含三仓库改动 + 查重结论 + 验证证据
