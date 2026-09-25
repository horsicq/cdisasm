#!/usr/bin/env python3
"""Report the exact-evidence buckets in the generated x86 inventory.

This is intentionally independent of the decoder implementation.  It gives
the promotion work a deterministic ledger: every pinned IFORM is listed once,
and any form outside the exact-evidence rollup is visible with its extension
and source-reference metadata.  The optional strict mode is suitable for CI
once all promotion work is complete.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
import sys


EXACT_STATUSES = {"corpus_reachable", "corpus_partial"}
PROMOTION_STATUSES = {
    "catalog_only",
    "source_assignment_only",
    "profile_rejected_probe",
}


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def build_ledger(rows: list[dict[str, str]]) -> dict[str, object]:
    statuses = Counter(row.get("coverage_status", "") for row in rows)
    outside = [
        {
            "iform": row.get("iform", ""),
            "extension": row.get("extension", ""),
            "isa_set": row.get("isa_set", ""),
            "coverage_status": row.get("coverage_status", ""),
            "cdisasm_name": row.get("cdisasm_name", ""),
            "cdisasm_name_id": row.get("cdisasm_name_id", ""),
            "source_name_reference": row.get("source_name_reference", ""),
            "success_cases": row.get("success_cases", ""),
            "missing_cases": row.get("missing_cases", ""),
            "profile_cases": row.get("profile_cases", ""),
        }
        for row in rows
        if row.get("coverage_status", "") not in EXACT_STATUSES
    ]
    return {
        "iform_count": len(rows),
        "exact_evidence_count": sum(statuses[name] for name in EXACT_STATUSES),
        "outside_exact_evidence_count": len(outside),
        "status_counts": dict(sorted(statuses.items())),
        "outside_exact_evidence": outside,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--forms",
        type=Path,
        default=Path(__file__).resolve().parent / "generated" / "x86_forms.tsv",
        help="generated x86 inventory TSV",
    )
    parser.add_argument("--output", type=Path, help="write the JSON ledger")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="fail when any form remains outside exact evidence",
    )
    args = parser.parse_args()
    try:
        ledger = build_ledger(read_rows(args.forms))
    except (OSError, csv.Error) as error:
        print(f"x86 evidence ledger failed: {error}", file=sys.stderr)
        return 2

    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(ledger, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    print(f"x86 IFORMs: {ledger['iform_count']}")
    print(f"exact evidence: {ledger['exact_evidence_count']}")
    print(f"outside exact evidence: {ledger['outside_exact_evidence_count']}")
    for name, count in ledger["status_counts"].items():
        print(f"  {name or '<empty>'}: {count}")
    if args.strict and ledger["outside_exact_evidence_count"] != 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
