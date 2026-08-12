#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Prepare an immutable CalVer release candidate for POC (Ticket 05).

Outputs:
  releases/<calver>/
    catalog-v1.json + .sha256
    schema/catalog-v1.schema.json + SHA256SUMS
    poc/                 (accepted-only runnable assets, preserving relative paths)
    LICENSE, NOTICE
    rights/provenance.json
    quarantine.json
    rights-report.md
    SHA256SUMS

Usage:
  uv run python scripts/stage_release.py --calver 2026.08.10.1
"""
import argparse
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import poclib as pl  # noqa: E402


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_digest_list(release_dir, files):
    lines = []
    for rel in files:
        lines.append(f"{sha256_file(release_dir / rel)}  {rel}")
    (release_dir / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def stage(calver):
    release_dir = pl.ROOT / "releases" / calver
    if release_dir.exists():
        print(f"release {calver} already exists", file=sys.stderr)
        return 1
    release_dir.mkdir(parents=True)

    shutil.copy2(pl.CAP_DIR / "catalog-v1.json", release_dir / "catalog-v1.json")
    shutil.copy2(pl.CAP_DIR / "catalog-v1.json.sha256", release_dir / "catalog-v1.json.sha256")

    schema_dir = release_dir / "schema"
    schema_dir.mkdir()
    shutil.copy2(pl.CAP_DIR / "schema" / "catalog-v1.schema.json", schema_dir / "catalog-v1.schema.json")
    shutil.copy2(pl.CAP_DIR / "schema" / "SHA256SUMS", schema_dir / "SHA256SUMS")

    rights_dir = release_dir / "rights"
    rights_dir.mkdir()
    shutil.copy2(pl.CAP_DIR / "rights" / "provenance.json", rights_dir / "provenance.json")
    shutil.copy2(pl.CAP_DIR / "quarantine.json", release_dir / "quarantine.json")

    provenance = pl.load_provenance()
    accepted = {a["destination"] for a in provenance.get("assets", []) if a.get("decision") == "accepted"}
    poc_dir = release_dir / "poc"
    for rel, path in pl.iter_poc_files():
        if rel in accepted:
            dest = poc_dir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)

    shutil.copy2(pl.ROOT / "LICENSE", release_dir / "LICENSE")
    shutil.copy2(pl.ROOT / "NOTICE", release_dir / "NOTICE")

    report = [
        f"# POC {calver} Rights and Provenance Report",
        "",
        f"Release: `{calver}`",
        f"Prepared: {datetime.now(timezone.utc).isoformat()}",
        "",
        "All PoC assets in this release are currently held and quarantined "
        "pending maintainer/rights-officer provenance and safety review. "
        "The public catalog is therefore empty.",
        "",
        "Default safety is `manual-only`: no automated executable command is generated.",
        "",
        "See `rights/provenance.json` and `quarantine.json` for per-asset status.",
        ""
    ]
    (release_dir / "rights-report.md").write_text("\n".join(report), encoding="utf-8")

    files = ["catalog-v1.json", "schema/catalog-v1.schema.json", "schema/SHA256SUMS",
             "LICENSE", "NOTICE", "rights/provenance.json", "quarantine.json", "rights-report.md"]
    for rel in accepted:
        files.append("poc/" + rel)
    write_digest_list(release_dir, files)
    print(f"✓ staged release candidate at {release_dir}")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--calver", required=True)
    args = parser.parse_args(argv)
    return stage(args.calver)


if __name__ == "__main__":
    sys.exit(main())
