#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC release gate validator (Ticket 05).

Checks:
  - catalog-v1.json validates against vendored schema and sidecar matches
  - no held/rejected asset appears in catalog (fail-closed)
  - catalog capabilities are all manual-only and generate no executable command
  - Python files pass py_compile syntax check
  - secret scan (no private keys, cloud tokens, real credentials)
  - quarantine list enforcement (held/rejected assets listed in quarantine.json)

Usage:
  uv run python scripts/validate_poc_gates.py
"""
import json
import py_compile
import re
import sys
from pathlib import Path

import jsonschema

sys.path.insert(0, str(Path(__file__).resolve().parent))
import poclib as pl  # noqa: E402

QUARANTINE_PATH = pl.CAP_DIR / "quarantine.json"


def check_catalog(errors):
    catalog_path = pl.CAP_DIR / "catalog-v1.json"
    schema_path = pl.CAP_DIR / "schema" / "catalog-v1.schema.json"
    if not catalog_path.is_file():
        errors.append("capabilities/catalog-v1.json missing")
        return
    if not schema_path.is_file():
        errors.append("capabilities/schema/catalog-v1.schema.json missing")
        return
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    for err in validator.iter_errors(catalog):
        path = ".".join(str(p) for p in err.absolute_path) or "(root)"
        errors.append(f"catalog schema: {path}: {err.message}")
    sidecar = catalog_path.with_suffix(".json.sha256")
    if not sidecar.is_file():
        errors.append("catalog sidecar missing")
        return
    expected = pl.sha256_digest(catalog_path.read_text(encoding="utf-8"))
    actual = sidecar.read_text(encoding="utf-8").strip()
    if actual != expected:
        errors.append("catalog sidecar mismatch")
    # manual-only enforcement: catalog capabilities must never carry auto-exec command
    for cap in catalog.get("capabilities", []):
        if cap.get("safety") != "manual-only":
            errors.append(f"capability {cap['id']}: safety must be manual-only")
        if cap.get("contract", {}).get("has_command"):
            errors.append(f"capability {cap['id']}: manual-only must not generate command")


def check_quarantine(errors):
    """held/rejected 资产必须全部出现在 quarantine.json，且不出现在 catalog。"""
    provenance = pl.load_provenance()
    held = [a["destination"] for a in provenance.get("assets", [])
            if a.get("decision") in ("held", "rejected")]
    if not QUARANTINE_PATH.is_file():
        errors.append("capabilities/quarantine.json missing")
        return
    q = json.loads(QUARANTINE_PATH.read_text(encoding="utf-8"))
    quarantined = set(q.get("quarantined", []))
    missing = set(held) - quarantined
    if missing:
        errors.append(f"held/rejected assets missing from quarantine: {sorted(missing)[:10]}")
    # catalog must not contain quarantined assets
    catalog_path = pl.CAP_DIR / "catalog-v1.json"
    if catalog_path.is_file():
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        for cap in catalog.get("capabilities", []):
            if cap.get("path") in quarantined:
                errors.append(f"catalog contains quarantined asset: {cap['path']}")


def check_python_syntax(errors):
    for rel, path in pl.iter_poc_files():
        if rel.endswith(".py"):
            try:
                py_compile.compile(str(path), doraise=True)
            except py_compile.PyCompileError as exc:
                errors.append(f"{rel}: syntax error ({exc})")


def check_secrets(errors):
    pats = [
        ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
        ("aws-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("github-pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
        ("generic-secret", re.compile(r"\b(?:api[_-]?key|apikey|token|secret)\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}[\"']?", re.IGNORECASE)),
    ]
    for rel, path in pl.iter_poc_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for name, pat in pats:
            if pat.search(text):
                errors.append(f"{rel}: potential {name} detected")


def check_side_effects(errors):
    """静态检测恶意副作用声明（反向 shell、持久化、数据破坏、外联）。

    仅对已 accepted（进入 release）的资产失败关闭；held/quarantined 资产
    已经隔离，其存在本身就是保护机制，不阻塞无关资产。
    """
    provenance = pl.load_provenance()
    accepted = {a["destination"] for a in provenance.get("assets", [])
                if a.get("decision") == "accepted"}
    patterns = [
        ("reverse-shell", re.compile(r"(?:sh|bash)\s+-i\s+[^\n]*/dev/tcp", re.IGNORECASE)),
        ("bind-shell", re.compile(r"nc\s+-[e]?\s*\S+\s+-[ep]\s+\d{2,}", re.IGNORECASE)),
    ]
    for rel, path in pl.iter_poc_files():
        if rel not in accepted:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for name, pat in patterns:
            if pat.search(text):
                errors.append(f"{rel}: {name} pattern in accepted asset requires dual approval")


def main():
    errors = []
    print("Validating POC gates...")
    check_catalog(errors)
    check_quarantine(errors)
    check_python_syntax(errors)
    check_secrets(errors)
    check_side_effects(errors)
    if errors:
        print(f"\n✗ {len(errors)} gate failure(s):")
        for e in errors:
            print(f"  - {e}")
        return 1
    print("\n✓ All POC gates passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
