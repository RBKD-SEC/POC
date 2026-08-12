# POC

> RBKD-SEC 团队漏洞验证/利用 PoC 仓库。
> Nuclei 扫描模板请见 [`RBKD-SEC/templates`](https://github.com/RBKD-SEC/templates)。

## 目录结构

| 格式 | 目录 | 适用场景 | 调用方式 |
|------|------|----------|----------|
| **pocsuite3** | `pocsuite3/` | 集成化批量扫描、报告输出 | `pocsuite3 -r poc.py` |
| **独立脚本** | `standalone/` | 单点利用、交互式 shell、特殊协议 | `python3 poc.py` |

## 快速开始

### pocsuite3 格式

```bash
pip install pocsuite3

# 验证模式
pocsuite3 -r pocsuite3/n8n/cve_2026_21858_rce_poc.py -u http://<target>

# 攻击模式
pocsuite3 -r pocsuite3/n8n/cve_2026_21858_rce_poc.py -u http://<target> --attack
```

### 独立脚本

每个独立脚本目录下均包含 `README.md`，详细说明漏洞原理和使用方法。

```bash
# 示例：1Panel RCE
cd standalone/1panel
python3 CVE-2025-54424.py -u <target>:9999

# 批量扫描
python3 CVE-2025-54424.py -f targets.txt -t 20
```

## PoC 索引

### pocsuite3

| 目录 | CVE | 类型 | 目标 |
|------|-----|------|------|
| `n8n/` | CVE-2026-21858 | LFI → Admin Token → RCE | n8n 工作流平台 |
| `react/` | CVE-2025-55182 | RCE | React Server Components |
| `spring4shell/` | CVE-2022-22965 | RCE (Spring4Shell) | Spring Framework (WAR on Tomcat) |

### standalone

| 目录 | CVE | 类型 | 目标 |
|------|-----|------|------|
| `1panel/` | CVE-2025-54424 | 客户端证书绕过 RCE | 1Panel 管理面板 |
| `copy-fail-CVE-2026-31431/` | CVE-2026-31431 | 内核提权 (copy_fail) | Linux 内核 |
| `dirtyfrag/` | — | 脏页碎片化利用 | Linux 内核 |
| `ruoyi/` | CVE-2023-49371 | SQL 注入 | 若依系统 |

## 待复现漏洞

查看 [`TODO.md`](./TODO.md) 了解当前待复现的漏洞清单。

## 新增 PoC

### 目录规范

#### pocsuite3 格式

- 必须继承 `POCBase` 并调用 `register_poc()`
- 包含完整的 `pocInfo`（name, vulID, author, vulType, references）
- 目录按目标产品分类

```
pocsuite3/
├── {product}/
│   └── {cve-id}_poc.py
```

#### 独立脚本

- 必须包含命令行参数解析（推荐 `argparse`）
- 文件头部注释包含：CVE 编号、作者、依赖安装命令
- 目录按目标产品分类，附 `README.md`

```
standalone/
├── {product}/
│   ├── {cve-id}.py
│   └── README.md
```

### 提交格式

Commit message 建议格式：

```
[add] CVE-2025-XXXXX - 产品名 漏洞类型
[fix] CVE-2025-XXXXX - 修复 XX 问题
```

## Capability catalog & release

本仓库是 repository-orchestration-v2 的 PoC 能力仓。发布门禁：

- 每个 runnable entry（`.py`/`.sh`/`.c` 等）对应一个稳定能力 ID；helper、图片、载荷、Makefile 等作为 component 关联。
- 默认 safety 为 **`manual-only`**：不生成自动执行 command，所有 PoC 只能由人工在授权目标上手动运行。
- 缺授权、来源矛盾或无法安全验证的资产进入 `capabilities/quarantine.json`，不进入公开 release。
- `capabilities/catalog-v1.json` 仅包含 provenance 双人审批为 `accepted` 的资产；当前全部资产 held，catalog 为空。
- 发布候选通过 `scripts/stage_release.py --calver YYYY.MM.DD.N` 生成，包含 catalog、schema、LICENSE、NOTICE、provenance、quarantine 与 rights report。

本地门禁：

```bash
python scripts/validate_poc_gates.py
python scripts/test_poc_gates.py
python scripts/generate_catalog.py --write
python scripts/stage_release.py --calver 2026.08.10.1
cd releases/2026.08.10.1 && shasum -a 256 -c SHA256SUMS
```

动态验证仅允许在隔离 sandbox（无外网、无真实目标、可销毁 fixture）中运行，且必须由人工批准后执行。

## 声明

本仓库所有内容仅供安全研究和教育目的使用。**严禁用于任何非法活动**。因滥用本仓库中提供的信息和代码而造成的一切后果由使用者自行承担。
