#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Common utilities for POC capability repository (Ticket 05)."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CAP_DIR = ROOT / "capabilities"

# runnable entry 扩展名（PoC 脚本 / 源码）
RUNNABLE_EXTS = {".py", ".sh", ".c", ".go", ".js", ".rb", ".pl", ".yaml", ".yml"}


def sha256_digest(text):
    if isinstance(text, str):
        text = text.encode("utf-8")
    return "sha256:" + hashlib.sha256(text).hexdigest()


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, indent=2) + "\n"


def write_canonical(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = canonical_json(obj)
    path.write_text(text, encoding="utf-8")
    sidecar = path.with_suffix(path.suffix + ".sha256")
    sidecar.write_text(sha256_digest(text) + "\n", encoding="utf-8")
    return path


def poc_id(rel_path):
    """Stable capability id from relative path like 'pocsuite3/n8n/cve_2026_21858_rce_poc.py'."""
    p = Path(rel_path)
    return p.with_suffix("").as_posix().replace("/", "-")


def iter_poc_files():
    """遍历 tracked 文件（优先 git ls-files；非 git 环境回退到目录遍历）。"""
    import subprocess
    result = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, text=True, capture_output=True, check=False)
    if result.returncode == 0:
        for rel in result.stdout.splitlines():
            if not rel:
                continue
            path = ROOT / rel
            if path.is_file():
                yield rel, path
        return
    # fallback: 非 git 环境（如临时目录测试）
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT).as_posix()
        if any(part.startswith(".") for part in path.relative_to(ROOT).parts):
            continue
        if rel.startswith("capabilities/") or rel.startswith("scripts/") or rel.startswith("tests/"):
            continue
        yield rel, path


def is_runnable(rel):
    return Path(rel).suffix.lower() in RUNNABLE_EXTS


def load_provenance():
    path = CAP_DIR / "rights" / "provenance.json"
    if not path.is_file():
        return {"assets": []}
    return json.loads(path.read_text(encoding="utf-8"))
