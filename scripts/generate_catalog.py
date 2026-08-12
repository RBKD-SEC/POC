#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC capability catalog generator (Ticket 05).

Generates capabilities/catalog-v1.json from runnable PoC entries,
including only assets marked accepted in capabilities/rights/provenance.json.
Default safety is `manual-only`; manual-only capabilities never get an
automatically generated executable command.

Usage:
  uv run python scripts/generate_catalog.py --write
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import poclib as pl  # noqa: E402


def guess_kind(rel):
    if rel.startswith("pocsuite3/"):
        return "poc-detect" if "detect" in rel.lower() else "poc-exploit"
    # standalone 目录下的脚本默认按目录名与文件名判断
    lowered = rel.lower()
    if "detect" in lowered or "check" in lowered:
        return "poc-detect"
    return "poc-exploit"


def build_catalog():
    provenance = pl.load_provenance()
    accepted = {a["destination"]: a for a in provenance.get("assets", []) if a.get("decision") == "accepted"}
    capabilities = []
    for rel, path in pl.iter_poc_files():
        if not pl.is_runnable(rel):
            continue
        prov = accepted.get(rel)
        if not prov:
            continue
        capabilities.append({
            "id": pl.poc_id(rel),
            "kind": guess_kind(rel),
            "path": rel,
            "contract": {
                "target_types": ["host-port", "url", "host"],
                "inputs": ["host", "port", "url", "command"],
                "positive_evidence": "documented verify/detect mode output",
                "negative_or_failure": "no match does not prove absence",
                "interface_version": "poc-v1",
            },
            "safety": "manual-only",
            "lifecycle": "active",
            "replacement": None,
            "provenance_id": prov["provenance_id"],
            "content_digest": prov["content_digest"],
            "components": [],
            "requires": [],
            "extensions": {
                "rbkd": {
                    "runnable": True,
                    "script_type": Path(rel).suffix.lower().lstrip("."),
                }
            },
        })
    return {
        "schema_version": 1,
        "repository": "POC",
        "capabilities": capabilities,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    catalog = build_catalog()
    catalog_path = pl.CAP_DIR / "catalog-v1.json"
    if args.write:
        pl.write_canonical(catalog_path, catalog)
        print(f"✓ wrote {catalog_path} ({len(catalog['capabilities'])} capabilities)")
        return 0
    expected = pl.canonical_json(catalog)
    actual = catalog_path.read_text(encoding="utf-8") if catalog_path.is_file() else ""
    if expected != actual:
        print("✗ catalog drift")
        return 1
    print("✓ catalog up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
