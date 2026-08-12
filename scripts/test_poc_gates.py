#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""POC gate tests (Ticket 05)."""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import poclib as pl  # noqa: E402
import generate_catalog  # noqa: E402
import validate_poc_gates as vpg  # noqa: E402

PASS = 0
FAIL = 0


def case(name, fn):
    global PASS, FAIL
    try:
        fn()
        PASS += 1
        print(f"  ✓ {name}")
    except Exception as exc:
        FAIL += 1
        print(f"  ✗ {name}: {exc}")


def _make_tmp(tmp):
    tmp = Path(tmp)
    rl_save = (pl.ROOT, pl.CAP_DIR)
    pl.ROOT = tmp
    pl.CAP_DIR = tmp / "capabilities"
    (tmp / "pocsuite3" / "n8n").mkdir(parents=True)
    (tmp / "capabilities" / "schema").mkdir(parents=True)
    (tmp / "capabilities" / "rights").mkdir(parents=True)
    return rl_save


def _restore(rl_save):
    pl.ROOT, pl.CAP_DIR = rl_save


def t_held_asset_quarantined_and_excluded():
    with tempfile.TemporaryDirectory() as tmp:
        save = _make_tmp(tmp)
        tmp = Path(tmp)
        (tmp / "pocsuite3" / "n8n" / "cve_test_poc.py").write_text(
            "#!/usr/bin/env python3\nprint('hello')\n", encoding="utf-8")
        prov = {"assets": [
            {"destination": "pocsuite3/n8n/cve_test_poc.py", "decision": "held",
             "provenance_id": "p", "content_digest": "sha256:" + "0" * 64}]}
        (pl.CAP_DIR / "rights" / "provenance.json").write_text(json.dumps(prov), encoding="utf-8")
        json.dump({"$schema": "..."}, (pl.CAP_DIR / "schema" / "catalog-v1.schema.json").open("w"))
        generate_catalog.main(["--write"])
        catalog = json.loads((pl.CAP_DIR / "catalog-v1.json").read_text(encoding="utf-8"))
        assert catalog["capabilities"] == [], "held 资产不得进入 catalog"
        _restore(save)


def t_manual_only_no_command():
    with tempfile.TemporaryDirectory() as tmp:
        save = _make_tmp(tmp)
        tmp = Path(tmp)
        (tmp / "pocsuite3" / "n8n" / "cve_test_poc.py").write_text(
            "#!/usr/bin/env python3\nprint('hello')\n", encoding="utf-8")
        prov = {"assets": [
            {"destination": "pocsuite3/n8n/cve_test_poc.py", "decision": "accepted",
             "provenance_id": "p", "content_digest": "sha256:" + "0" * 64}]}
        (pl.CAP_DIR / "rights" / "provenance.json").write_text(json.dumps(prov), encoding="utf-8")
        json.dump({"$schema": "..."}, (pl.CAP_DIR / "schema" / "catalog-v1.schema.json").open("w"))
        generate_catalog.main(["--write"])
        catalog = json.loads((pl.CAP_DIR / "catalog-v1.json").read_text(encoding="utf-8"))
        assert len(catalog["capabilities"]) == 1
        cap = catalog["capabilities"][0]
        assert cap["safety"] == "manual-only", "POC 默认必须 manual-only"
        assert not cap["contract"].get("has_command"), "manual-only 不得生成 command"
        _restore(save)


def t_quarantine_requires_held_assets():
    with tempfile.TemporaryDirectory() as tmp:
        save = _make_tmp(tmp)
        tmp = Path(tmp)
        (tmp / "pocsuite3" / "n8n" / "cve_test_poc.py").write_text(
            "#!/usr/bin/env python3\nprint('hello')\n", encoding="utf-8")
        prov = {"assets": [
            {"destination": "pocsuite3/n8n/cve_test_poc.py", "decision": "held",
             "provenance_id": "p", "content_digest": "sha256:" + "0" * 64}]}
        (pl.CAP_DIR / "rights" / "provenance.json").write_text(json.dumps(prov), encoding="utf-8")
        json.dump({"$schema": "..."}, (pl.CAP_DIR / "schema" / "catalog-v1.schema.json").open("w"))
        # 空 quarantine → 应报缺失
        (pl.CAP_DIR / "quarantine.json").write_text(json.dumps({"quarantined": []}), encoding="utf-8")
        errors = []
        vpg.check_quarantine(errors)
        assert any("missing from quarantine" in e for e in errors), "held 资产必须在 quarantine"
        _restore(save)


def main():
    cases = [
        ("held asset quarantined and excluded", t_held_asset_quarantined_and_excluded),
        ("manual-only default, no command", t_manual_only_no_command),
        ("quarantine requires held assets", t_quarantine_requires_held_assets),
    ]
    print("POC gate tests")
    for name, fn in cases:
        case(name, fn)
    print()
    print(f"结果：{PASS} 通过，{FAIL} 失败，共 {PASS + FAIL} 项")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
