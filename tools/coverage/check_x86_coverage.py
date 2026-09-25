#!/usr/bin/env python3
"""Audit the checked-in x86 fallback and coverage inventories.

This check deliberately does not require every XED IFORM to have a corpus
witness.  Catalog-only rows are useful review output, but they are not a
generation failure.  The check instead prevents the more dangerous state in
which the generated fallback, coverage report, and decoder integration claim
different things.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
import sys


_SUCCESSFUL_CORPUS_STATUSES = {"OK", "EXTRA_OK"}


class AuditError(RuntimeError):
    """A checked-in x86 inventory invariant is inconsistent."""


def load_json(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, json.JSONDecodeError) as error:
        raise AuditError(f"cannot read JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise AuditError(f"JSON root is not an object: {path}")
    return value


def read_rows(path: Path) -> list[dict[str, str]]:
    try:
        with path.open("r", encoding="utf-8", newline="") as stream:
            return list(csv.DictReader(stream, delimiter="\t"))
    except OSError as error:
        raise AuditError(f"cannot read TSV {path}: {error}") from error


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AuditError(message)


def _hex_key(value: str) -> str:
    """Normalize a corpus/evidence byte string for exact comparison."""
    return " ".join(value.split()).lower()


def read_corpus_witnesses(path: Path) -> set[tuple[int, str]]:
    """Return successful mode/byte witnesses from the checked-in corpus.

    The x86 corpus deliberately has prose comments before its tabular rows, so
    it cannot be consumed by ``csv.DictReader`` directly.  Keep this parser
    small and strict: malformed data must fail the audit rather than silently
    changing the promotion count.
    """
    witnesses: set[tuple[int, str]] = set()
    try:
        with path.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                fields = line.rstrip("\r\n").split("\t")
                if len(fields) < 9:
                    raise AuditError(
                        f"x86 corpus row {line_number} has fewer than 9 fields"
                    )
                if fields[4] not in _SUCCESSFUL_CORPUS_STATUSES:
                    continue
                # ``@`` and ``-`` are intentional corpus wildcards/placeholders,
                # not formatter evidence.  Do not promote a catalog form from
                # a decode-only row when this audit is measuring exact output.
                if fields[6] in {"@", "-"} or fields[7] in {"@", "-"}:
                    continue
                try:
                    mode = int(fields[2], 0)
                except ValueError as error:
                    raise AuditError(
                        f"x86 corpus row {line_number} has invalid mode"
                    ) from error
                byte_key = _hex_key(fields[8])
                if not byte_key:
                    raise AuditError(
                        f"x86 corpus row {line_number} has no opcode bytes"
                    )
                witnesses.add((mode, byte_key))
    except OSError as error:
        raise AuditError(f"cannot read x86 corpus {path}: {error}") from error
    return witnesses


def catalog_corpus_promotions(
    repo_root: Path,
    rows: list[dict[str, str]],
    ledger_rows: list[dict[str, str]],
) -> tuple[set[str], Counter[str]]:
    """Find catalog-only IFORMs with exact checked-in corpus witnesses.

    ``x86_forms.tsv`` is generated from the pinned XED checkout and therefore
    cannot be regenerated on every developer machine.  The evidence ledger
    already records the exact XED bytes for each catalog-only IFORM; matching
    those bytes against the current corpus keeps the report live as new exact
    witnesses are checked in.  This is a decode/format promotion only: the
    ledger's structural-only legality contract remains unchanged.
    """
    if not ledger_rows:
        return set(), Counter()
    corpus_path = repo_root / "tests" / "data" / "x86_opcodes.tsv"
    corpus_witnesses = read_corpus_witnesses(corpus_path)
    catalog_ids = {
        row["iform"]
        for row in rows
        if row.get("coverage_status") == "catalog_only"
    }
    promoted: set[str] = set()
    extensions: Counter[str] = Counter()
    for evidence in ledger_rows:
        if evidence.get("iform") not in catalog_ids:
            continue
        try:
            mode = int(evidence.get("mode", "0"), 0)
        except ValueError as error:
            raise AuditError(
                f"x86 evidence ledger has invalid mode for {evidence.get('iform', '')}"
            ) from error
        if (mode, _hex_key(evidence.get("bytes", ""))) not in corpus_witnesses:
            continue
        if evidence.get("decoder_contract") != "exact":
            continue
        if evidence.get("formatter_contract") != "exact":
            continue
        iform = evidence["iform"]
        if iform in promoted:
            continue
        promoted.add(iform)
        row = next(row for row in rows if row["iform"] == iform)
        extensions[row.get("extension", "")] += 1
    return promoted, extensions


def audit(repo_root: Path) -> tuple[Counter[str], Counter[str], Counter[str], int, Counter[str]]:
    native_manifest_path = (
        repo_root / "tools" / "isa_codegen" / "generated" / "manifest.json"
    )
    fallback_manifest_path = (
        repo_root
        / "tools"
        / "isa_codegen"
        / "generated"
        / "x86_fallback_manifest.json"
    )
    coverage_manifest_path = (
        repo_root / "tools" / "coverage" / "generated" / "manifest.json"
    )
    forms_path = repo_root / "tools" / "coverage" / "generated" / "x86_forms.tsv"
    ledger_path = (
        repo_root
        / "tools"
        / "coverage"
        / "generated"
        / "x86_catalog_evidence.tsv"
    )
    corpus_path = repo_root / "tests" / "data" / "x86_opcodes.tsv"
    decoder_path = repo_root / "src" / "x86" / "cdisasm_x86.c"
    generated_decoder_path = repo_root / "src" / "x86" / "x86_generated_decoder.c"

    native_manifest = load_json(native_manifest_path)
    fallback_manifest = load_json(fallback_manifest_path)
    coverage_manifest = load_json(coverage_manifest_path)
    rows = read_rows(forms_path)
    require(rows, f"x86 coverage inventory is empty: {forms_path}")
    require(corpus_path.is_file(), f"x86 opcode corpus is missing: {corpus_path}")

    ledger_rows: list[dict[str, str]] = []
    if ledger_path.is_file():
        ledger_rows = read_rows(ledger_path)
        ledger_ids = [row.get("iform", "") for row in ledger_rows]
        require(
            all(ledger_ids),
            f"x86 evidence ledger contains an empty IFORM: {ledger_path}",
        )
        require(
            len(ledger_ids) == len(set(ledger_ids)),
            f"x86 evidence ledger contains duplicate IFORM rows: {ledger_path}",
        )
        inventory_by_iform = {row["iform"]: row for row in rows}
        require(
            all(iform in inventory_by_iform for iform in ledger_ids),
            "x86 evidence ledger contains an IFORM outside the pinned inventory",
        )
        for evidence in ledger_rows:
            iform = evidence["iform"]
            inventory = inventory_by_iform[iform]
            require(
                evidence.get("xed_iform") == iform,
                f"x86 evidence ledger XED identity mismatch for {iform}",
            )
            try:
                length = int(evidence.get("xed_length", "0"))
            except ValueError as error:
                raise AuditError(
                    f"x86 evidence ledger has invalid XED length for {iform}"
                ) from error
            require(
                1 <= length <= 15,
                f"x86 evidence ledger has invalid XED length for {iform}",
            )
            require(
                evidence.get("extension") == inventory.get("extension"),
                f"x86 evidence ledger extension mismatch for {iform}",
            )
            require(
                evidence.get("decoder_contract") in {"exact", "not_checked"},
                f"x86 evidence ledger has invalid decoder state for {iform}",
            )
            require(
                evidence.get("legality_contract") == "structural_only",
                f"x86 evidence ledger overclaims legality for {iform}",
            )

    integration = native_manifest.get("integration_status")
    require(isinstance(integration, dict), "native manifest has no integration_status")
    x86_integration = integration.get("x86")
    require(isinstance(x86_integration, dict), "native manifest has no x86 integration status")
    require(
        integration.get("wired_into_decoder") is True
        and x86_integration.get("wired_into_decoder") is True,
        "native manifest still claims that the x86 fallback is not wired",
    )
    require(
        x86_integration.get("fallback_status") == "unsupported_only",
        "x86 fallback must remain an unsupported-only fallback",
    )
    require(
        x86_integration.get("numeric_only") is True,
        "x86 fallback integration must remain numeric-only",
    )

    fallback_counts = fallback_manifest.get("counts")
    require(isinstance(fallback_counts, dict), "x86 fallback manifest has no counts")
    coverage_counts = coverage_manifest.get("counts", {}).get("x86", {})
    require(isinstance(coverage_counts, dict), "coverage manifest has no x86 counts")

    descriptor_count = int(fallback_counts.get("descriptors", -1))
    iform_count = int(fallback_manifest.get("iform_count", -1))
    require(
        descriptor_count == int(coverage_counts.get("generated_fallback_descriptor_assignments", -2)),
        "fallback descriptor count disagrees with coverage manifest",
    )
    require(
        iform_count == len(rows) == int(coverage_counts.get("upstream_unique_iform_names", -2)),
        "fallback IFORM count disagrees with coverage inventory",
    )
    require(
        int(fallback_counts.get("remaining_emitted_operands_opaque", -1)) == 0,
        "x86 fallback still contains opaque emitted operands",
    )
    require(
        all(row.get("generated_fallback_assignment") == "True" for row in rows),
        "at least one x86 IFORM has no generated fallback assignment",
    )

    try:
        decoder_text = decoder_path.read_text(encoding="utf-8")
    except OSError as error:
        raise AuditError(f"cannot read decoder {decoder_path}: {error}") from error
    require(
        "cdisasm_x86_decode_generated" in decoder_text,
        "x86 decoder does not call the generated fallback",
    )
    require(
        generated_decoder_path.is_file(),
        f"generated x86 decoder is missing: {generated_decoder_path}",
    )

    status_counts = Counter(row.get("coverage_status", "") for row in rows)
    catalog_only_extensions = Counter(
        row.get("extension", "")
        for row in rows
        if row.get("coverage_status") == "catalog_only"
    )
    promoted_ids, promoted_extensions = catalog_corpus_promotions(
        repo_root, rows, ledger_rows
    )
    require(
        len(promoted_ids) <= status_counts.get("catalog_only", 0),
        "corpus overlay promoted a non-catalog or duplicate IFORM",
    )
    effective_status_counts = status_counts.copy()
    effective_status_counts["catalog_only"] -= len(promoted_ids)
    effective_status_counts["corpus_reachable"] += len(promoted_ids)
    require(
        sum(effective_status_counts.values()) == len(rows),
        "effective x86 coverage status counts do not cover the inventory",
    )
    remaining_extensions = catalog_only_extensions - promoted_extensions
    return (
        effective_status_counts,
        remaining_extensions,
        status_counts,
        len(promoted_ids),
        promoted_extensions,
    )


def main() -> int:
    script_path = Path(__file__).resolve()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=script_path.parents[2],
        help="cdisasm source root (defaults to the repository containing this script)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="only report failures",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "require a complete per-IFORM catalog evidence ledger with an "
            "exact decoder contract for every catalog-only form"
        ),
    )
    args = parser.parse_args()

    try:
        (
            statuses,
            catalog_only_extensions,
            generated_statuses,
            promoted_count,
            promoted_extensions,
        ) = audit(args.repo_root.resolve())
        ledger_path = (
            args.repo_root.resolve()
            / "tools"
            / "coverage"
            / "generated"
            / "x86_catalog_evidence.tsv"
        )
        ledger_rows = read_rows(ledger_path) if ledger_path.is_file() else []
        current_rows = read_rows(
            args.repo_root.resolve()
            / "tools"
            / "coverage"
            / "generated"
            / "x86_forms.tsv"
        )
        catalog_ids = {
            row["iform"]
            for row in current_rows
            if row.get("coverage_status") == "catalog_only"
        }
        ledger_ids = {row.get("iform", "") for row in ledger_rows}
        if args.strict:
            if not ledger_path.is_file():
                raise AuditError(f"strict mode requires evidence ledger: {ledger_path}")
            missing = sorted(catalog_ids - ledger_ids)
            if missing:
                raise AuditError(
                    "strict mode evidence ledger is missing catalog-only IFORM(s): "
                    + ", ".join(missing[:8])
                    + (" ..." if len(missing) > 8 else "")
                )
            not_exact = sorted(
                row["iform"]
                for row in ledger_rows
                if row.get("iform") in catalog_ids
                and row.get("decoder_contract") != "exact"
            )
            if not_exact:
                raise AuditError(
                    "strict mode requires exact decoder evidence for catalog-only "
                    "IFORM(s): "
                    + ", ".join(not_exact[:8])
                    + (" ..." if len(not_exact) > 8 else "")
                )
    except AuditError as error:
        print(f"x86 coverage audit failed: {error}", file=sys.stderr)
        return 2

    if not args.quiet:
        print("x86 coverage status:")
        for name, count in sorted(statuses.items()):
            print(f"  {name}: {count}")
        print(
            "catalog-only forms promoted by exact checked-in corpus witnesses: "
            f"{promoted_count}"
        )
        print("catalog-only forms by extension (remaining after corpus overlay):")
        for name, count in catalog_only_extensions.most_common(12):
            print(f"  {name or '<none>'}: {count}")
        if ledger_rows:
            print(f"per-IFORM evidence ledger: {len(ledger_rows)} rows")
            for field in (
                "decoder_contract",
                "operand_contract",
                "legality_contract",
                "formatter_contract",
            ):
                counts = Counter(row.get(field, "") for row in ledger_rows)
                print(f"  {field}: {dict(sorted(counts.items()))}")
        elif args.strict:
            # The strict branch above normally reports this as an error; keep
            # this guard explicit for future callers of audit().
            print("per-IFORM evidence ledger: missing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
