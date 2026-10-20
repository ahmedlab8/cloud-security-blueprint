#!/usr/bin/env python3
"""Render control-mapping.csv into the per-framework markdown matrix (compliance-matrix.md)."""

import csv
from pathlib import Path

HERE = Path(__file__).resolve().parent
rows = list(csv.DictReader((HERE / "control-mapping.csv").open(encoding="utf-8")))

out = [
    "# Compliance control matrix",
    "",
    "_Generated from `control-mapping.csv` by `build_matrix.py`. Edit the CSV, not this file._",
    "",
    "This maps every security control in the repo to **NIST SP 800-53 Rev. 5**, **CIS Benchmarks**",
    "(AWS Foundations v3.0, Azure Foundations v2.x, Kubernetes v1.9, EKS/AKS, Docker, CIS Controls v8),",
    "**SOC 2 Trust Services Criteria (2017, rev. 2022)** and **ISO/IEC 27001:2022 Annex A**.",
    "",
    "> Mappings are engineering guidance meant to support an audit, not an attestation. CIS",
    "> recommendation numbers change between benchmark versions, so check them against the",
    "> version your auditor uses.",
    "",
    "| ID | Control / implementation | Evidence | NIST 800-53 | CIS | SOC 2 | ISO 27001 |",
    "|---|---|---|---|---|---|---|",
]
for r in rows:
    files = "<br>".join(f"`{p.strip()}`" for p in r["evidence"].split(";"))
    out.append(
        f"| {r['id']} | **{r['control']}**<br>{r['implementation']} | {files} | {r['nist_800_53_r5']} | {r['cis']} | {r['soc2_tsc']} | {r['iso_27001_2022']} |"
    )

# Reverse index per framework
for col, title in (("nist_800_53_r5", "NIST 800-53 Rev. 5"), ("soc2_tsc", "SOC 2 TSC"), ("iso_27001_2022", "ISO 27001:2022 Annex A")):
    idx: dict[str, list[str]] = {}
    for r in rows:
        for c in r[col].split(","):
            idx.setdefault(c.strip(), []).append(r["id"])
    out += ["", f"## {title} → repo controls", "", "| Framework control | Repo controls |", "|---|---|"]
    for k in sorted(idx, key=lambda s: [int(p) if p.isdigit() else p for p in s.replace("-", ".").split(".")] if s[0].isdigit() else [s]):
        out.append(f"| {k} | {', '.join(idx[k])} |")

(HERE / "compliance-matrix.md").write_text("\n".join(out) + "\n", encoding="utf-8")
print(f"wrote compliance-matrix.md ({len(rows)} controls)")
