#!/usr/bin/env python3
"""Generate the append-only ARM mnemonic ID and formatter catalog.

The source is the pinned Arm AARCHMRS Instructions.json recorded in
tools/coverage/baselines.json.  Existing public numeric IDs are read from the
hand-maintained prefix in cdisasm_arm_ids.h and are never reassigned.  Only
previously unseen architectural mnemonics are appended.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class CatalogError(RuntimeError):
    """A deterministic catalog invariant failed."""


@dataclass
class UpstreamMnemonic:
    source_spellings: set[str] = field(default_factory=set)
    instruction_sets: set[str] = field(default_factory=set)
    canonical_records: int = 0
    alias_records: int = 0


@dataclass(frozen=True)
class CatalogEntry:
    mnemonic: str
    name_id: int
    token: str
    origin: str
    upstream_canonical: bool
    upstream_alias: bool
    instruction_sets: tuple[str, ...]
    canonical_records: int
    alias_records: int


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, json.JSONDecodeError) as error:
        raise CatalogError(f"cannot read JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise CatalogError(f"expected a JSON object in {path}")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git_head(root: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.STDOUT,
        ).strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise CatalogError(f"cannot verify Arm checkout {root}: {error}") from error


def verify_git_file(root: Path, relative_path: str) -> None:
    try:
        committed = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", f"HEAD:{relative_path}"],
            text=True,
            stderr=subprocess.STDOUT,
        ).strip()
        working = subprocess.check_output(
            ["git", "-C", str(root), "hash-object", "--", relative_path],
            text=True,
            stderr=subprocess.STDOUT,
        ).strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise CatalogError(
            f"cannot verify pinned Arm file {relative_path}: {error}"
        ) from error
    if committed != working:
        raise CatalogError(
            f"Arm source file differs from pinned HEAD: {relative_path}"
        )


def first_assembly_literal(node: dict[str, Any]) -> str:
    assembly = node.get("assembly") or {}
    for symbol in assembly.get("symbols", []):
        if symbol.get("_type") == "Instruction.Symbols.Literal":
            value = symbol.get("value")
            if not isinstance(value, str) or not value:
                break
            return value
    raise CatalogError(
        f"instruction node {node.get('name', '<unnamed>')!r} has no mnemonic literal"
    )


def extract_upstream_mnemonics(
    document: dict[str, Any],
) -> tuple[dict[str, UpstreamMnemonic], int, int, set[str], set[str]]:
    records: dict[str, UpstreamMnemonic] = {}
    spelling_to_key: dict[str, str] = {}
    canonical_spellings: set[str] = set()
    alias_spellings: set[str] = set()
    canonical_records = 0
    alias_records = 0

    def register(spelling: str, instruction_set: str, is_alias: bool) -> None:
        nonlocal canonical_records, alias_records
        key = spelling.lower()
        previous = spelling_to_key.setdefault(key, spelling)
        if previous != spelling:
            raise CatalogError(
                "case-folding mnemonic collision: "
                f"{previous!r} and {spelling!r}"
            )
        record = records.setdefault(key, UpstreamMnemonic())
        record.source_spellings.add(spelling)
        record.instruction_sets.add(instruction_set)
        if is_alias:
            alias_records += 1
            alias_spellings.add(spelling)
            record.alias_records += 1
        else:
            canonical_records += 1
            canonical_spellings.add(spelling)
            record.canonical_records += 1

    def visit(node: dict[str, Any], instruction_set: str) -> None:
        node_type = node.get("_type")
        children = node.get("children", [])
        if not isinstance(children, list):
            raise CatalogError(f"invalid children array on {node.get('name')!r}")
        if node_type == "Instruction.Instruction":
            register(first_assembly_literal(node), instruction_set, False)
            for child in children:
                if child.get("_type") == "Instruction.InstructionAlias":
                    register(first_assembly_literal(child), instruction_set, True)
        for child in children:
            if child.get("_type") != "Instruction.InstructionAlias":
                visit(child, instruction_set)

    roots = document.get("instructions", [])
    if not isinstance(roots, list):
        raise CatalogError("Instructions.json has no instructions array")
    seen_instruction_sets: set[str] = set()
    for root in roots:
        instruction_set = str(root.get("name", ""))
        if instruction_set not in {"A32", "T32", "A64"}:
            raise CatalogError(f"unexpected Arm instruction set {instruction_set!r}")
        seen_instruction_sets.add(instruction_set)
        visit(root, instruction_set)
    if seen_instruction_sets != {"A32", "T32", "A64"}:
        raise CatalogError(
            f"incomplete instruction-set roots: {sorted(seen_instruction_sets)}"
        )
    return (
        records,
        canonical_records,
        alias_records,
        canonical_spellings,
        alias_spellings,
    )


ID_DEFINE_RE = re.compile(
    r"^#define CDISASM_ARM_NAME_([A-Z0-9_]+) UINT16_C\((\d+)\)$",
    re.MULTILINE,
)
RESERVED_NAME_TOKENS = {
    "NONE",
    "FIRST",
    "LAST",
    "COUNT",
}

# Publicly documented Arm 2026-06 delta.  This remains separate from the
# pinned 2026-03 AARCHMRS inventory and therefore has no mnemonic_pool_id.
MANUAL_EXTENSIONS = (("hinte", "HINTE", "arm_isa_2026_06"),)


def parse_existing_catalog(
    ids_path: Path, formatter_path: Path
) -> list[CatalogEntry]:
    ids_text = ids_path.read_text(encoding="utf-8")
    definitions: list[tuple[str, int]] = []
    for match in ID_DEFINE_RE.finditer(ids_text):
        token = match.group(1)
        if token in RESERVED_NAME_TOKENS:
            continue
        definitions.append((token, int(match.group(2))))
    if not definitions:
        raise CatalogError(f"no existing ARM name IDs found in {ids_path}")
    ids = [name_id for _token, name_id in definitions]
    tokens = [token for token, _name_id in definitions]
    if len(ids) != len(set(ids)):
        raise CatalogError("duplicate existing ARM mnemonic numeric ID")
    if len(tokens) != len(set(tokens)):
        raise CatalogError("duplicate existing ARM mnemonic macro token")
    maximum = max(ids)
    if sorted(ids) != list(range(1, maximum + 1)):
        raise CatalogError("existing ARM mnemonic IDs are not contiguous from 1")

    formatter_text = formatter_path.read_text(encoding="utf-8")
    match = re.search(
        r"static const char \*const arm_mnemonic_names"
        r"\[CDISASM_ARM_NAME_COUNT\]\s*=\s*\{(.*?)\n\};",
        formatter_text,
        re.DOTALL,
    )
    if match is None:
        raise CatalogError(f"cannot locate ARM mnemonic table in {formatter_path}")
    strings: list[str] = []
    for line in match.group(1).splitlines():
        if line.lstrip().startswith("#"):
            continue
        strings.extend(re.findall(r'"([^"\\]*)"', line))
    if len(strings) != maximum:
        raise CatalogError(
            f"legacy formatter has {len(strings)} strings for {maximum} existing IDs"
        )

    by_id = {name_id: token for token, name_id in definitions}
    entries: list[CatalogEntry] = []
    for name_id, mnemonic in enumerate(strings, 1):
        token = by_id.get(name_id)
        if token is None:
            raise CatalogError(f"missing macro token for existing name ID {name_id}")
        entries.append(
            CatalogEntry(
                mnemonic=mnemonic,
                name_id=name_id,
                token=token,
                origin="existing",
                upstream_canonical=False,
                upstream_alias=False,
                instruction_sets=(),
                canonical_records=0,
                alias_records=0,
            )
        )
    if len({entry.mnemonic for entry in entries}) != len(entries):
        raise CatalogError("existing ARM formatter contains duplicate mnemonic strings")
    return entries


def base_macro_token(mnemonic: str) -> str:
    token = re.sub(r"[^A-Z0-9_]+", "_", mnemonic.upper()).strip("_")
    if not token:
        token = "MNEMONIC"
    if token[0].isdigit():
        token = "M_" + token
    return token


def allocate_macro_token(
    mnemonic: str,
    occupied: dict[str, str | None],
) -> tuple[str, dict[str, str | None] | None]:
    base = base_macro_token(mnemonic)
    if base not in occupied:
        occupied[base] = mnemonic
        return base, None
    conflict = {
        "mnemonic": mnemonic,
        "base_token": base,
        "conflicting_mnemonic": occupied[base],
    }
    digest = hashlib.sha256(mnemonic.encode("utf-8")).hexdigest().upper()
    for length in range(8, len(digest) + 1, 4):
        candidate = f"{base}__{digest[:length]}"
        if candidate not in occupied:
            occupied[candidate] = mnemonic
            conflict["resolved_token"] = candidate
            return candidate, conflict
    raise CatalogError(f"cannot resolve macro-token collision for {mnemonic!r}")


def build_catalog(
    existing: list[CatalogEntry], upstream: dict[str, UpstreamMnemonic]
) -> tuple[list[CatalogEntry], list[CatalogEntry], list[dict[str, str | None]]]:
    existing_by_name = {entry.mnemonic: entry for entry in existing}
    occupied: dict[str, str | None] = {
        entry.token: entry.mnemonic for entry in existing
    }
    for token in RESERVED_NAME_TOKENS:
        occupied.setdefault(token, None)

    combined: list[CatalogEntry] = []
    for entry in existing:
        record = upstream.get(entry.mnemonic)
        combined.append(
            CatalogEntry(
                mnemonic=entry.mnemonic,
                name_id=entry.name_id,
                token=entry.token,
                origin=("existing_upstream" if record else "existing_vendor"),
                upstream_canonical=bool(record and record.canonical_records),
                upstream_alias=bool(record and record.alias_records),
                instruction_sets=(
                    tuple(sorted(record.instruction_sets)) if record else ()
                ),
                canonical_records=(record.canonical_records if record else 0),
                alias_records=(record.alias_records if record else 0),
            )
        )

    appended: list[CatalogEntry] = []
    collisions: list[dict[str, str | None]] = []
    next_id = max(entry.name_id for entry in existing) + 1
    for mnemonic in sorted(set(upstream) - set(existing_by_name)):
        token, collision = allocate_macro_token(mnemonic, occupied)
        if collision is not None:
            collisions.append(collision)
        record = upstream[mnemonic]
        entry = CatalogEntry(
            mnemonic=mnemonic,
            name_id=next_id,
            token=token,
            origin="generated_upstream",
            upstream_canonical=record.canonical_records != 0,
            upstream_alias=record.alias_records != 0,
            instruction_sets=tuple(sorted(record.instruction_sets)),
            canonical_records=record.canonical_records,
            alias_records=record.alias_records,
        )
        appended.append(entry)
        combined.append(entry)
        next_id += 1
    if next_id > 65536:
        raise CatalogError("ARM mnemonic catalog no longer fits cdisasm_arm_name_id")
    return combined, appended, collisions


def generated_header(
    appended: list[CatalogEntry],
    manual: list[CatalogEntry],
    catalog_count: int,
    source_sha256: str,
) -> str:
    if not appended:
        raise CatalogError("expected at least one generated ARM mnemonic")
    lines = [
        "#ifndef CDISASM_CDISASM_ARM_MNEMONIC_IDS_GENERATED_H",
        "#define CDISASM_CDISASM_ARM_MNEMONIC_IDS_GENERATED_H",
        "",
        "/*",
        " * Generated by tools/isa_codegen/generate_arm_mnemonic_catalog.py.",
        " * Source: Arm AARCHMRS A-profile FAT 2026-03 Instructions.json",
        f" * Source SHA-256: {source_sha256}",
        " * Stable policy: preserve existing IDs; append unseen mnemonics sorted by name.",
        " * Do not edit this file by hand.",
        " */",
        "",
    ]
    lines.extend(
        f"#define CDISASM_ARM_NAME_{entry.token} UINT16_C({entry.name_id})"
        for entry in appended
    )
    if manual:
        lines.extend(
            [
                "",
                "/* Manual public Arm ISA deltas newer than the pinned AARCHMRS. */",
            ]
        )
        lines.extend(
            f"#define CDISASM_ARM_NAME_{entry.token} UINT16_C({entry.name_id})"
            for entry in manual
        )
    lines.extend(
        [
            "",
            "#define CDISASM_ARM_GENERATED_NAME_FIRST "
            f"CDISASM_ARM_NAME_{appended[0].token}",
            "#define CDISASM_ARM_GENERATED_NAME_LAST "
            f"CDISASM_ARM_NAME_{appended[-1].token}",
            "#define CDISASM_ARM_GENERATED_NAME_COUNT "
            f"UINT16_C({len(appended)})",
            "#define CDISASM_ARM_MANUAL_NAME_FIRST "
            f"CDISASM_ARM_NAME_{manual[0].token}",
            "#define CDISASM_ARM_MANUAL_NAME_LAST "
            f"CDISASM_ARM_NAME_{manual[-1].token}",
            "#define CDISASM_ARM_MANUAL_NAME_COUNT "
            f"UINT16_C({len(manual)})",
            "#define CDISASM_ARM_GENERATED_CATALOG_COUNT "
            f"UINT16_C({catalog_count})",
            "",
            "#endif",
            "",
        ]
    )
    return "\n".join(lines)


def generated_formatter_include(
    appended: list[CatalogEntry],
    manual: list[CatalogEntry],
    source_sha256: str,
) -> str:
    lines = [
        "/* Generated ARM mnemonic strings. Included only by cdisasm_arm_format.c.",
        f" * AARCHMRS 2026-03 Instructions.json SHA-256: {source_sha256}",
        " * Do not edit this file by hand. */",
    ]
    lines.extend(f'    "{entry.mnemonic}",' for entry in appended)
    lines.extend(f'    "{entry.mnemonic}",' for entry in manual)
    lines.append("")
    return "\n".join(lines)


def generated_mnemonic_pool(
    exact_spellings: list[str],
    entries_by_mnemonic: dict[str, CatalogEntry],
) -> str:
    values = [entries_by_mnemonic[spelling.lower()].name_id for spelling in exact_spellings]
    lines = [
        "/*",
        " * Generated decoder-safe mapping from mnemonic_pool_id to public name ID.",
        " * Pool order is the bytewise sort of exact AARCHMRS mnemonic tokens.",
        " * This include intentionally contains no mnemonic strings.",
        " */",
        "#if USE_EXTRA_OPCODES",
        "#ifndef CDISASM_ARM_GEN_MNEMONIC_COUNT",
        f"#define CDISASM_ARM_GEN_MNEMONIC_COUNT UINT16_C({len(values)})",
        f"#elif CDISASM_ARM_GEN_MNEMONIC_COUNT != UINT16_C({len(values)})",
        "#error ARM_generated_mnemonic_pools_disagree",
        "#endif",
        "static const uint16_t cdisasm_arm_gen_mnemonic_name_ids",
        "    [CDISASM_ARM_GEN_MNEMONIC_COUNT] = {",
    ]
    for offset in range(0, len(values), 12):
        group = values[offset : offset + 12]
        lines.append("    " + ", ".join(f"UINT16_C({value})" for value in group) + ",")
    lines.extend(["};", "#endif", ""])
    return "\n".join(lines)


def generated_mapping(
    entries: list[CatalogEntry], pool_ids: dict[str, int]
) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, delimiter="\t", lineterminator="\n")
    writer.writerow(
        [
            "mnemonic",
            "name_id",
            "mnemonic_pool_id",
            "macro_name",
            "catalog_origin",
            "upstream_canonical",
            "upstream_explicit_alias",
            "instruction_sets",
            "canonical_records",
            "alias_records",
        ]
    )
    for entry in entries:
        writer.writerow(
            [
                entry.mnemonic,
                entry.name_id,
                pool_ids.get(entry.mnemonic, ""),
                f"CDISASM_ARM_NAME_{entry.token}",
                entry.origin,
                int(entry.upstream_canonical),
                int(entry.upstream_alias),
                ",".join(entry.instruction_sets),
                entry.canonical_records,
                entry.alias_records,
            ]
        )
    return buffer.getvalue()


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def text_bytes(value: str) -> bytes:
    return value.encode("utf-8")


def write_or_check(path: Path, content: bytes, check: bool) -> None:
    if check:
        try:
            current = path.read_bytes()
        except OSError as error:
            raise CatalogError(f"generated file missing: {path}: {error}") from error
        if current != content:
            raise CatalogError(f"generated file is stale: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(content)
    temporary.replace(path)


def parse_arguments() -> argparse.Namespace:
    script = Path(__file__).resolve()
    default_repo = script.parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arm-root", required=True, type=Path)
    parser.add_argument("--repo-root", type=Path, default=default_repo)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify checked-in outputs instead of updating them",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    repo_root = arguments.repo_root.resolve()
    arm_root = arguments.arm_root.resolve()
    baseline = load_json(repo_root / "tools" / "coverage" / "baselines.json")[
        "arm_aarchmrs"
    ]
    actual_commit = git_head(arm_root)
    expected_commit = str(baseline["commit"])
    if actual_commit != expected_commit:
        raise CatalogError(
            f"Arm checkout mismatch: expected {expected_commit}, got {actual_commit}"
        )
    instructions_path = arm_root / str(baseline["inventory_file"])
    verify_git_file(arm_root, str(baseline["inventory_file"]))
    document = load_json(instructions_path)
    version = (document.get("_meta") or {}).get("version") or {}
    expected_version = {
        "architecture": baseline["architecture_revision"],
        "ref": baseline["data_ref"],
        "build": baseline["build"],
        "schema": baseline["schema"],
        "timestamp": baseline["data_timestamp"],
    }
    actual_version = {key: version.get(key) for key in expected_version}
    if any(
        str(actual_version[key]) != str(expected_version[key])
        for key in expected_version
    ):
        raise CatalogError(
            f"Arm metadata mismatch: expected {expected_version}, got {actual_version}"
        )

    (
        upstream,
        canonical_record_count,
        alias_record_count,
        canonical_spellings,
        alias_spellings,
    ) = extract_upstream_mnemonics(document)
    ids_path = repo_root / "include" / "cdisasm" / "cdisasm_arm_ids.h"
    formatter_path = repo_root / "src" / "arm" / "cdisasm_arm_format.c"
    existing = parse_existing_catalog(ids_path, formatter_path)
    entries, appended, collisions = build_catalog(existing, upstream)
    manual: list[CatalogEntry] = []
    occupied_names = {entry.mnemonic for entry in entries}
    occupied_tokens = {entry.token for entry in entries}
    next_manual_id = max(entry.name_id for entry in entries) + 1
    for mnemonic, token, origin in MANUAL_EXTENSIONS:
        if mnemonic in occupied_names or token in occupied_tokens:
            raise CatalogError(
                f"manual mnemonic extension collides with catalog: {mnemonic}/{token}"
            )
        entry = CatalogEntry(
            mnemonic=mnemonic,
            name_id=next_manual_id,
            token=token,
            origin=origin,
            upstream_canonical=False,
            upstream_alias=False,
            instruction_sets=("A64",),
            canonical_records=0,
            alias_records=0,
        )
        manual.append(entry)
        entries.append(entry)
        occupied_names.add(mnemonic)
        occupied_tokens.add(token)
        next_manual_id += 1
    source_sha256 = sha256_file(instructions_path)
    catalog_count = len(entries) + 1  # ID zero is CDISASM_ARM_NAME_NONE.
    exact_spellings = sorted(
        spelling
        for record in upstream.values()
        for spelling in record.source_spellings
    )
    if len(exact_spellings) != len(upstream):
        raise CatalogError("exact AARCHMRS mnemonic spellings are not one-to-one")
    pool_ids = {
        spelling.lower(): pool_id
        for pool_id, spelling in enumerate(exact_spellings)
    }
    entries_by_mnemonic = {entry.mnemonic: entry for entry in entries}

    header_path = (
        repo_root
        / "include"
        / "cdisasm"
        / "cdisasm_arm_mnemonic_ids_generated.h"
    )
    formatter_include_path = repo_root / "src" / "arm" / "arm_mnemonic_names_generated.inc"
    mnemonic_pool_path = repo_root / "src" / "arm" / "arm_mnemonic_pool_ids_generated.inc"
    mapping_path = (
        repo_root
        / "tools"
        / "isa_codegen"
        / "generated"
        / "arm_mnemonic_ids.tsv"
    )
    manifest_path = (
        repo_root
        / "tools"
        / "isa_codegen"
        / "generated"
        / "arm_mnemonic_catalog_manifest.json"
    )

    header = text_bytes(
        generated_header(appended, manual, catalog_count, source_sha256)
    )
    formatter_include = text_bytes(
        generated_formatter_include(appended, manual, source_sha256)
    )
    mnemonic_pool = text_bytes(
        generated_mnemonic_pool(exact_spellings, entries_by_mnemonic)
    )
    mapping = text_bytes(generated_mapping(entries, pool_ids))
    manifest = {
        "schema_version": 1,
        "upstream": {
            "name": baseline["name"],
            "commit": actual_commit,
            "architecture_revision": baseline["architecture_revision"],
            "data_ref": baseline["data_ref"],
            "build": str(baseline["build"]),
            "schema": str(baseline["schema"]),
            "data_timestamp": baseline["data_timestamp"],
            "instructions_sha256": source_sha256,
        },
        "counts": {
            "canonical_leaf_records": canonical_record_count,
            "explicit_alias_records": alias_record_count,
            "unique_canonical_mnemonics": len(canonical_spellings),
            "unique_explicit_alias_mnemonics": len(alias_spellings),
            "unique_upstream_mnemonics": len(upstream),
            "mnemonic_pool_ids": len(exact_spellings),
            "canonical_alias_unique_overlap": len(
                {value.lower() for value in canonical_spellings}
                & {value.lower() for value in alias_spellings}
            ),
            "preserved_existing_ids": len(existing),
            "preserved_existing_upstream_ids": sum(
                entry.mnemonic in upstream for entry in existing
            ),
            "preserved_existing_vendor_ids": sum(
                entry.mnemonic not in upstream for entry in existing
            ),
            "appended_ids": len(appended),
            "manual_extension_ids": len(manual),
            "catalog_mnemonics": len(entries),
            "catalog_count_including_none": catalog_count,
            "macro_token_collisions": len(collisions),
        },
        "id_policy": {
            "existing": "preserve every numeric ID and formatter spelling",
            "append": "unseen lowercase mnemonics in bytewise lexical order",
            "macro_token": (
                "uppercase identifier normalization; on collision append a stable "
                "double-underscore SHA-256 prefix, starting at eight hex digits"
            ),
        },
        "macro_token_collisions": collisions,
        "manual_extensions": [
            {
                "mnemonic": entry.mnemonic,
                "name_id": entry.name_id,
                "macro_name": f"CDISASM_ARM_NAME_{entry.token}",
                "source": entry.origin,
                "machine_readable_baseline": False,
            }
            for entry in manual
        ],
        "preserved_vendor_mnemonics": sorted(
            entry.mnemonic for entry in existing if entry.mnemonic not in upstream
        ),
        "outputs": {
            str(header_path.relative_to(repo_root)).replace("\\", "/"): {
                "sha256": hashlib.sha256(header).hexdigest(),
                "records": len(appended),
            },
            str(formatter_include_path.relative_to(repo_root)).replace("\\", "/"): {
                "sha256": hashlib.sha256(formatter_include).hexdigest(),
                "records": len(appended) + len(manual),
            },
            str(mnemonic_pool_path.relative_to(repo_root)).replace("\\", "/"): {
                "sha256": hashlib.sha256(mnemonic_pool).hexdigest(),
                "records": len(exact_spellings),
            },
            str(mapping_path.relative_to(repo_root)).replace("\\", "/"): {
                "sha256": hashlib.sha256(mapping).hexdigest(),
                "records": len(entries),
            },
        },
    }

    write_or_check(header_path, header, arguments.check)
    write_or_check(formatter_include_path, formatter_include, arguments.check)
    write_or_check(mnemonic_pool_path, mnemonic_pool, arguments.check)
    write_or_check(mapping_path, mapping, arguments.check)
    write_or_check(manifest_path, json_bytes(manifest), arguments.check)
    action = "verified" if arguments.check else "generated"
    print(
        f"{action} ARM mnemonic catalog: {len(upstream)} upstream unique, "
        f"{len(appended)} upstream appended, {len(manual)} manual appended, "
        f"{len(entries)} total, "
        f"{len(collisions)} token collisions"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except CatalogError as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
