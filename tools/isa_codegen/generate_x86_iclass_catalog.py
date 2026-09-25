#!/usr/bin/env python3
"""Generate the append-only cdisasm x86 ICLASS/name catalog.

The input is the official compact JSON emitted by the pinned Intel XED
``pysrc/xed_to_db.py`` exporter.  This generator deliberately does not emit
decoder matching logic.  It allocates stable numeric mnemonic IDs, emits the
formatter-only spelling data for newly allocated IDs, and records an exact
ICLASS-to-ID map for a later generated decoder.
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
import hashlib
import io
import json
from pathlib import Path
import re
import sys
from typing import Any


GENERATOR_VERSION = 1

NUMERIC_NAME_RE = re.compile(
    r"^#define CDISASM_X86_NAME_([A-Z0-9_]+) UINT16_C\(([0-9]+)\)$",
    re.MULTILINE,
)
ALIASED_NAME_RE = re.compile(
    r"^#define CDISASM_X86_NAME_([A-Z0-9_]+) "
    r"CDISASM_X86_NAME_([A-Z0-9_]+)$",
    re.MULTILINE,
)
VALID_ICLASS_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
METADATA_TOKENS = {"INVALID", "FIRST", "LAST", "COUNT", "ENDING", "NONE"}


class GenerationError(RuntimeError):
    pass


@dataclass(frozen=True)
class CatalogEntry:
    xed_index: int
    iclass: str
    macro_token: str
    name_id: int
    formatter_mnemonic: str
    allocation: str
    record_count: int


@dataclass(frozen=True)
class Allocation:
    iclass: str
    macro_token: str
    name_id: int
    formatter_mnemonic: str


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def normalize_macro_token(iclass: str) -> str:
    """Return a portable C macro suffix for an arbitrary future ICLASS."""
    token = re.sub(r"[^A-Z0-9]+", "_", iclass.upper()).strip("_")
    if not token:
        token = "XED_ICLASS"
    if token[0].isdigit():
        token = "XED_" + token
    return token


def collision_token(
    preferred: str, iclass: str, occupied_tokens: set[str]
) -> str:
    """Resolve a normalized-token collision without depending on source order."""
    base = preferred + "_ICLASS"
    if base not in occupied_tokens:
        return base
    digest = hashlib.sha256(iclass.encode("ascii")).hexdigest().upper()
    for width in range(8, len(digest) + 1, 4):
        candidate = f"{base}_{digest[:width]}"
        if candidate not in occupied_tokens:
            return candidate
    raise GenerationError(f"unable to resolve macro token collision for {iclass!r}")


def c_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def parse_manual_catalog(header_path: Path) -> tuple[dict[str, int], dict[str, str]]:
    text = header_path.read_text(encoding="utf-8")
    numeric = {
        token: int(value)
        for token, value in NUMERIC_NAME_RE.findall(text)
        if token not in METADATA_TOKENS
    }
    aliases = {
        token: target
        for token, target in ALIASED_NAME_RE.findall(text)
        if token not in METADATA_TOKENS
    }
    if numeric.get("NONE") is not None:
        raise GenerationError("NONE must not be treated as a canonical mnemonic")
    if not numeric:
        raise GenerationError(f"no x86 mnemonic IDs found in {header_path}")
    by_id: dict[int, str] = {}
    for token, name_id in numeric.items():
        if name_id == 0:
            raise GenerationError(f"canonical mnemonic {token} has reserved ID zero")
        previous = by_id.setdefault(name_id, token)
        if previous != token:
            raise GenerationError(
                f"duplicate existing mnemonic ID {name_id}: {previous}, {token}"
            )
    expected = set(range(1, max(by_id) + 1))
    if set(by_id) != expected:
        missing = sorted(expected - set(by_id))
        raise GenerationError(f"existing x86 mnemonic ID gap(s): {missing[:8]}")
    for alias, target in aliases.items():
        if alias in numeric:
            raise GenerationError(f"name token is both numeric and alias: {alias}")
        if target not in numeric:
            raise GenerationError(f"alias {alias} targets unknown mnemonic {target}")
    return numeric, aliases


def read_prior_allocations(path: Path) -> dict[str, Allocation]:
    if not path.is_file():
        return {}
    result: dict[str, Allocation] = {}
    with path.open("r", encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream, dialect="excel-tab"):
            if row.get("allocation") != "appended":
                continue
            allocation = Allocation(
                iclass=row["iclass"],
                macro_token=row["macro_token"],
                name_id=int(row["name_id"]),
                formatter_mnemonic=row["formatter_mnemonic"],
            )
            if allocation.iclass in result:
                raise GenerationError(
                    f"duplicate prior ICLASS allocation: {allocation.iclass}"
                )
            result[allocation.iclass] = allocation
    return result


def load_xed_iclasses(
    xed_document: dict[str, Any], expected_iclass_count: int
) -> tuple[list[tuple[str, str, int]], int]:
    records = xed_document.get("Instructions")
    if not isinstance(records, list):
        raise GenerationError("XED JSON has no Instructions array")
    displays: dict[str, set[str]] = {}
    counts: dict[str, int] = {}
    for record in records:
        if not isinstance(record, dict):
            raise GenerationError("XED Instructions contains a non-object record")
        iclass = str(record.get("iclass", ""))
        display = str(record.get("disasm_intel", ""))
        if not VALID_ICLASS_RE.fullmatch(iclass):
            raise GenerationError(f"unsupported XED ICLASS spelling: {iclass!r}")
        if not display or not display.isascii() or any(
            character in "\r\n\t\0" for character in display
        ):
            raise GenerationError(
                f"unsupported formatter spelling {display!r} for {iclass}"
            )
        displays.setdefault(iclass, set()).add(display.lower())
        counts[iclass] = counts.get(iclass, 0) + 1
    if len(displays) != expected_iclass_count:
        raise GenerationError(
            f"expected {expected_iclass_count} unique XED ICLASS values, "
            f"got {len(displays)}"
        )
    result: list[tuple[str, str, int]] = []
    for iclass in sorted(displays):
        spellings = displays[iclass]
        if len(spellings) != 1:
            raise GenerationError(
                f"ICLASS {iclass} has multiple formatter spellings: "
                f"{sorted(spellings)}"
            )
        result.append((iclass, next(iter(spellings)), counts[iclass]))
    return result, len(records)


def allocate_catalog(
    source: list[tuple[str, str, int]],
    manual_ids: dict[str, int],
    manual_aliases: dict[str, str],
    prior: dict[str, Allocation],
) -> tuple[list[CatalogEntry], list[Allocation], list[dict[str, str]]]:
    occupied_tokens = set(manual_ids) | set(manual_aliases) | METADATA_TOKENS
    occupied_ids = set(manual_ids.values())
    allocations: dict[str, Allocation] = {}
    macro_collisions: list[dict[str, str]] = []

    for allocation in sorted(prior.values(), key=lambda item: item.name_id):
        if allocation.macro_token in occupied_tokens:
            raise GenerationError(
                f"prior generated token now collides: {allocation.macro_token}"
            )
        if allocation.name_id in occupied_ids:
            raise GenerationError(
                f"prior generated ID now collides: {allocation.name_id}"
            )
        occupied_tokens.add(allocation.macro_token)
        occupied_ids.add(allocation.name_id)
        allocations[allocation.iclass] = allocation

    all_existing_ids = sorted(occupied_ids)
    if all_existing_ids != list(range(1, max(all_existing_ids) + 1)):
        raise GenerationError("manual and prior generated mnemonic IDs are not contiguous")
    next_id = max(all_existing_ids) + 1
    source_by_iclass = {iclass: (display, count) for iclass, display, count in source}

    for iclass, display, _record_count in source:
        if iclass in manual_ids:
            continue
        if iclass in allocations:
            previous = allocations[iclass]
            allocations[iclass] = Allocation(
                iclass=iclass,
                macro_token=previous.macro_token,
                name_id=previous.name_id,
                formatter_mnemonic=display,
            )
            continue
        preferred = normalize_macro_token(iclass)
        token = preferred
        if token in occupied_tokens:
            token = collision_token(preferred, iclass, occupied_tokens)
            macro_collisions.append(
                {
                    "iclass": iclass,
                    "preferred_token": preferred,
                    "resolved_token": token,
                }
            )
        allocation = Allocation(iclass, token, next_id, display)
        allocations[iclass] = allocation
        occupied_tokens.add(token)
        occupied_ids.add(next_id)
        next_id += 1

    # Retain a prior allocation even if a future XED baseline removes its
    # ICLASS.  That is the append-only ABI rule; current pinned output has none.
    ordered_allocations = sorted(allocations.values(), key=lambda item: item.name_id)
    all_ids = sorted(set(manual_ids.values()) | {item.name_id for item in ordered_allocations})
    if all_ids != list(range(1, max(all_ids) + 1)):
        raise GenerationError("final x86 mnemonic ID namespace is not contiguous")

    entries: list[CatalogEntry] = []
    for xed_index, (iclass, display, record_count) in enumerate(source):
        if iclass in manual_ids:
            token = iclass
            name_id = manual_ids[iclass]
            allocation_kind = "existing"
        else:
            allocated = allocations[iclass]
            token = allocated.macro_token
            name_id = allocated.name_id
            allocation_kind = "appended"
        entries.append(
            CatalogEntry(
                xed_index=xed_index,
                iclass=iclass,
                macro_token=token,
                name_id=name_id,
                formatter_mnemonic=display,
                allocation=allocation_kind,
                record_count=record_count,
            )
        )

    mapped_ids = [entry.name_id for entry in entries]
    if len(mapped_ids) != len(source):
        raise GenerationError("not every XED ICLASS was mapped")
    if len(set(mapped_ids)) != len(mapped_ids):
        duplicates: dict[int, list[str]] = {}
        for entry in entries:
            duplicates.setdefault(entry.name_id, []).append(entry.iclass)
        detail = {
            name_id: iclasses
            for name_id, iclasses in duplicates.items()
            if len(iclasses) > 1
        }
        raise GenerationError(f"XED ICLASS IDs are not unique: {detail}")
    if set(source_by_iclass) != {entry.iclass for entry in entries}:
        raise GenerationError("ICLASS mapping is not exhaustive")
    return entries, ordered_allocations, macro_collisions


def render_id_include(allocations: list[Allocation]) -> str:
    if not allocations:
        raise GenerationError("XED catalog did not allocate any new mnemonic IDs")
    final = allocations[-1]
    lines = [
        "/* Generated by tools/isa_codegen/generate_x86_iclass_catalog.py.",
        " * Exact XED ICLASS tokens are append-only cdisasm mnemonic IDs.",
        " * Do not edit this file by hand. */",
    ]
    for allocation in allocations:
        lines.append(
            f"#define CDISASM_X86_NAME_{allocation.macro_token} "
            f"UINT16_C({allocation.name_id})"
        )
    lines.extend(
        [
            f"#define CDISASM_X86_NAME_LAST "
            f"CDISASM_X86_NAME_{final.macro_token}",
            f"#define CDISASM_X86_NAME_COUNT UINT16_C({final.name_id + 1})",
            "#define CDISASM_X86_NAME_ENDING CDISASM_X86_NAME_COUNT",
            "",
            "/* Backward-compatible architecture-neutral aliases. */",
        ]
    )
    for allocation in allocations:
        lines.append(
            f"#define CDISASM_NAME_{allocation.macro_token} "
            f"CDISASM_X86_NAME_{allocation.macro_token}"
        )
    lines.append("")
    return "\n".join(lines)


def render_formatter_include(allocations: list[Allocation]) -> str:
    lines = [
        "/* Generated by tools/isa_codegen/generate_x86_iclass_catalog.py.",
        " * This formatter-only file is the sole generated C string catalog.",
        " * CDISASM_X86_ICLASS_MNEMONIC(value) is defined by the includer. */",
    ]
    for allocation in allocations:
        lines.append(
            "CDISASM_X86_ICLASS_MNEMONIC("
            + c_string(allocation.formatter_mnemonic)
            + ")"
        )
    lines.append("")
    return "\n".join(lines)


def render_tsv(entries: list[CatalogEntry]) -> str:
    stream = io.StringIO(newline="")
    fieldnames = [
        "xed_index",
        "iclass",
        "macro_token",
        "name_id",
        "formatter_mnemonic",
        "allocation",
        "record_count",
    ]
    writer = csv.DictWriter(
        stream,
        fieldnames=fieldnames,
        dialect="excel-tab",
        lineterminator="\n",
    )
    writer.writeheader()
    for entry in entries:
        writer.writerow(
            {
                "xed_index": entry.xed_index,
                "iclass": entry.iclass,
                "macro_token": entry.macro_token,
                "name_id": entry.name_id,
                "formatter_mnemonic": entry.formatter_mnemonic,
                "allocation": entry.allocation,
                "record_count": entry.record_count,
            }
        )
    return stream.getvalue()


def formatter_collisions(entries: list[CatalogEntry]) -> list[dict[str, Any]]:
    by_spelling: dict[str, list[str]] = {}
    for entry in entries:
        by_spelling.setdefault(entry.formatter_mnemonic, []).append(entry.iclass)
    return [
        {"formatter_mnemonic": spelling, "iclasses": sorted(iclasses)}
        for spelling, iclasses in sorted(by_spelling.items())
        if len(iclasses) > 1
    ]


def render_manifest(
    xed_path: Path,
    xed_version: str,
    xed_records: int,
    entries: list[CatalogEntry],
    allocations: list[Allocation],
    manual_ids: dict[str, int],
    manual_aliases: dict[str, str],
    macro_collisions: list[dict[str, str]],
    artifacts: dict[str, str],
    expected_iclass_count: int,
) -> str:
    normalized_changes = [
        {"iclass": entry.iclass, "macro_token": entry.macro_token}
        for entry in entries
        if normalize_macro_token(entry.iclass) != entry.macro_token
    ]
    existing_upstream = sum(entry.allocation == "existing" for entry in entries)
    appended_upstream = sum(entry.allocation == "appended" for entry in entries)
    upstream_tokens = {entry.iclass for entry in entries}
    manifest = {
        "schema_version": 1,
        "generator_version": GENERATOR_VERSION,
        "source": {
            "name": "Intel XED",
            "version": xed_version,
            "json_export_sha256": sha256_file(xed_path),
            "instruction_records": xed_records,
            "unique_iclasses": len(entries),
            "interface": "official pysrc/xed_to_db.py --compact JSON export",
        },
        "counts": {
            "upstream_iclasses": len(entries),
            "upstream_unique_numeric_ids": len({entry.name_id for entry in entries}),
            "upstream_reused_existing_ids": existing_upstream,
            "upstream_appended_ids": appended_upstream,
            "manual_numeric_ids_before_generation": len(manual_ids),
            "manual_aliases_preserved": len(manual_aliases),
            "manual_non_upstream_numeric_ids_preserved": len(
                set(manual_ids) - upstream_tokens
            ),
            "generated_allocations_retained": len(allocations),
            "final_name_count_including_none": max(
                set(manual_ids.values()) | {item.name_id for item in allocations}
            )
            + 1,
            "macro_token_collisions": len(macro_collisions),
            "formatter_spelling_collisions": len(formatter_collisions(entries)),
        },
        "normalization": {
            "iclass_sort": "ASCII lexicographic",
            "macro_token": "uppercase; non [A-Z0-9] runs become underscore",
            "collision_rule": (
                "append _ICLASS; if occupied append the shortest unique "
                "8+ hex SHA-256 prefix"
            ),
            "formatter_mnemonic": "lowercase disasm_intel from the JSON export",
            "changed_macro_tokens": normalized_changes,
            "macro_token_collisions": macro_collisions,
            "formatter_spelling_collisions": formatter_collisions(entries),
        },
        "invariants": {
            "all_upstream_iclasses_mapped": len(entries) == expected_iclass_count,
            "upstream_mapping_is_one_to_one": len({entry.name_id for entry in entries})
            == len(entries),
            "existing_numeric_ids_preserved": True,
            "existing_aliases_preserved": sorted(manual_aliases),
            "decoder_matching_wired": False,
            "generated_c_strings_outside_formatter_data": False,
        },
        "artifacts": {
            name: {"sha256": sha256_bytes(text.encode("utf-8")), "bytes": len(text.encode("utf-8"))}
            for name, text in sorted(artifacts.items())
        },
    }
    return json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n"


def write_or_check(path: Path, expected: str, check: bool) -> None:
    if check:
        if not path.is_file():
            raise GenerationError(f"generated artifact is missing: {path}")
        actual = path.read_text(encoding="utf-8")
        if actual != expected:
            raise GenerationError(f"generated artifact is stale: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(expected, encoding="utf-8", newline="\n")
    temporary.replace(path)


def main() -> int:
    script_path = Path(__file__).resolve()
    repository = script_path.parent.parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xed-db", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--repo-root", type=Path, default=repository)
    arguments = parser.parse_args()

    repo_root = arguments.repo_root.resolve()
    xed_path = arguments.xed_db.resolve()
    baseline_path = repo_root / "tools" / "coverage" / "baselines.json"
    header_path = repo_root / "include" / "cdisasm" / "cdisasm_x86_ids.h"
    id_include_path = (
        repo_root / "include" / "cdisasm" / "cdisasm_x86_iclass_ids.inc"
    )
    formatter_include_path = repo_root / "src" / "x86" / "x86_iclass_mnemonics.inc"
    generated_dir = repo_root / "tools" / "isa_codegen" / "generated"
    catalog_path = generated_dir / "x86_iclass_catalog.tsv"
    manifest_path = generated_dir / "x86_iclass_catalog.json"

    if not xed_path.is_file():
        raise GenerationError(f"XED JSON export is missing: {xed_path}")
    baselines = read_json(baseline_path)
    baseline = baselines["intel_xed"]
    actual_hash = sha256_file(xed_path)
    if actual_hash != baseline["metadata_export_sha256"]:
        raise GenerationError(
            "XED JSON export hash mismatch: expected "
            f"{baseline['metadata_export_sha256']}, got {actual_hash}"
        )
    xed_document = read_json(xed_path)
    if xed_document.get("Version") != baseline["ref"]:
        raise GenerationError(
            f"XED version mismatch: expected {baseline['ref']}, "
            f"got {xed_document.get('Version')!r}"
        )
    source, record_count = load_xed_iclasses(
        xed_document, int(baseline["metadata_export_unique_iclasses"])
    )
    if record_count != baseline["metadata_export_records"]:
        raise GenerationError(
            f"XED record-count mismatch: expected "
            f"{baseline['metadata_export_records']}, got {record_count}"
        )

    manual_ids, manual_aliases = parse_manual_catalog(header_path)
    prior = read_prior_allocations(catalog_path)
    entries, allocations, macro_collisions = allocate_catalog(
        source, manual_ids, manual_aliases, prior
    )
    id_include = render_id_include(allocations)
    formatter_include = render_formatter_include(allocations)
    catalog = render_tsv(entries)
    artifact_text = {
        "include/cdisasm/cdisasm_x86_iclass_ids.inc": id_include,
        "src/x86/x86_iclass_mnemonics.inc": formatter_include,
        "tools/isa_codegen/generated/x86_iclass_catalog.tsv": catalog,
    }
    manifest = render_manifest(
        xed_path=xed_path,
        xed_version=str(xed_document["Version"]),
        xed_records=record_count,
        entries=entries,
        allocations=allocations,
        manual_ids=manual_ids,
        manual_aliases=manual_aliases,
        macro_collisions=macro_collisions,
        artifacts=artifact_text,
        expected_iclass_count=int(baseline["metadata_export_unique_iclasses"]),
    )

    for path, text in (
        (id_include_path, id_include),
        (formatter_include_path, formatter_include),
        (catalog_path, catalog),
        (manifest_path, manifest),
    ):
        write_or_check(path, text, arguments.check)

    action = "verified" if arguments.check else "generated"
    print(
        f"{action} {len(entries)} XED ICLASS mappings: "
        f"{sum(entry.allocation == 'existing' for entry in entries)} existing, "
        f"{sum(entry.allocation == 'appended' for entry in entries)} appended, "
        f"final CDISASM_X86_NAME_COUNT={max(item.name_id for item in allocations) + 1}"
    )
    print(
        f"macro collisions={len(macro_collisions)}, "
        f"formatter collisions={len(formatter_collisions(entries))}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (GenerationError, KeyError, ValueError) as error:
        print(f"x86 ICLASS catalog generation failed: {error}", file=sys.stderr)
        raise SystemExit(2)
