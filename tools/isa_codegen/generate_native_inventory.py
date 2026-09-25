#!/usr/bin/env python3
"""Generate deterministic local ISA tables from pinned XED and AARCHMRS data.

The XED portion is compiled into cdisasm's optional numeric x86 fallback
decoder.  The Arm portion remains an inventory input for the separate Arm tree
generator.  Complex XED pattern nonterminals and Arm condition/operand ASTs are
preserved or diagnosed, not silently approximated.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any


SCHEMA_VERSION = 1
GENERATOR_VERSION = 1
SPACE_ORDER = {"legacy": 0, "vex": 1, "evex": 2, "xop": 3}


class GenerationError(RuntimeError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def digest_value(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def git_head(repository: Path) -> str | None:
    process = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    return process.stdout.strip() if process.returncode == 0 else None


def verify_commit(
    repository: Path, expected: str, label: str, allow_source_drift: bool
) -> str | None:
    actual = git_head(repository)
    if actual != expected and not allow_source_drift:
        raise GenerationError(
            f"{label} commit mismatch: expected {expected}, got "
            f"{actual or 'not a Git checkout'}"
        )
    return actual


def apply_encoding(
    parent_mask: int,
    parent_value: int,
    parent_width: int | None,
    encoding: dict[str, Any] | None,
) -> tuple[int, int, int | None]:
    if not encoding:
        return parent_mask, parent_value, parent_width
    raw_width = encoding.get("width")
    width = int(raw_width) if raw_width is not None else parent_width
    if width is not None and parent_width is not None and width != parent_width:
        parent_mask = 0
        parent_value = 0
    mask, value = parent_mask, parent_value
    for field in encoding.get("values", []):
        bit_range = field.get("range") or {}
        start = int(bit_range.get("start", 0))
        field_width = int(bit_range.get("width", 0))
        bits = str((field.get("value") or {}).get("value", "")).strip("'")
        if len(bits) != field_width or any(bit not in "01x" for bit in bits):
            raise GenerationError(
                f"unsupported Arm bit pattern {bits!r} at {start}:{field_width}"
            )
        field_mask = ((1 << field_width) - 1) << start
        mask &= ~field_mask
        value &= ~field_mask
        for offset, bit in enumerate(reversed(bits)):
            position = start + offset
            if bit != "x":
                mask |= 1 << position
                if bit == "1":
                    value |= 1 << position
    if width is not None:
        width_mask = (1 << width) - 1
        mask &= width_mask
        value &= width_mask
    return mask, value, width


def features_in(value: Any) -> set[str]:
    result: set[str] = set()
    if isinstance(value, dict):
        if value.get("_type") == "AST.Identifier":
            identifier = value.get("value")
            if isinstance(identifier, str) and identifier.startswith("FEAT_"):
                result.add(identifier)
        for child in value.values():
            result.update(features_in(child))
    elif isinstance(value, list):
        for child in value:
            result.update(features_in(child))
    return result


def first_literal(node: dict[str, Any]) -> str:
    for symbol in (node.get("assembly") or {}).get("symbols", []):
        if symbol.get("_type") == "Instruction.Symbols.Literal":
            return str(symbol.get("value", ""))
    return ""


def assembly_template(node: dict[str, Any]) -> str:
    tokens: list[str] = []
    for symbol in (node.get("assembly") or {}).get("symbols", []):
        kind = symbol.get("_type")
        if kind == "Instruction.Symbols.Literal":
            tokens.append(str(symbol.get("value", "")))
        elif kind == "Instruction.Symbols.RuleReference":
            tokens.append(f"<rule:{symbol.get('rule_id', '')}>")
        else:
            tokens.append(f"<unsupported:{kind or 'unknown'}>")
    return "".join(tokens)


def flatten_arm(
    document: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    leaves: list[dict[str, Any]] = []
    aliases: list[dict[str, Any]] = []
    condition_values: dict[str, dict[str, Any]] = {}
    node_type_counts: dict[str, int] = {}
    assembly_symbol_counts: dict[str, int] = {}
    assertion_leaf_count = 0

    def register_feature_condition(conditions: tuple[Any, ...]) -> str:
        expressions = [condition for condition in conditions if features_in(condition)]
        record = {
            "expressions": expressions,
            "features": sorted(features_in(expressions)),
        }
        serialized = canonical_json(record)
        condition_values.setdefault(serialized, record)
        return serialized

    def visit(
        node: dict[str, Any],
        instruction_set: str,
        path: tuple[str, ...],
        parent_mask: int,
        parent_value: int,
        parent_width: int | None,
        conditions: tuple[Any, ...],
    ) -> None:
        nonlocal assertion_leaf_count
        node_type = str(node.get("_type", "unknown"))
        node_type_counts[node_type] = node_type_counts.get(node_type, 0) + 1
        node_name = str(node.get("name", ""))
        node_path = path + (node_name,)
        mask, value, width = apply_encoding(
            parent_mask, parent_value, parent_width, node.get("encoding")
        )
        current_conditions = conditions + (node.get("condition"),)
        for symbol in (node.get("assembly") or {}).get("symbols", []):
            kind = str(symbol.get("_type", "unknown"))
            assembly_symbol_counts[kind] = assembly_symbol_counts.get(kind, 0) + 1

        if node_type == "Instruction.Instruction":
            if width not in (16, 32):
                raise GenerationError(
                    f"unexpected Arm width {width!r} for {'/'.join(node_path)}"
                )
            form_id = "/".join(node_path)
            feature_key = register_feature_condition(current_conditions)
            if node.get("assertions"):
                assertion_leaf_count += 1
            leaf_aliases = [
                child
                for child in node.get("children", [])
                if child.get("_type") == "Instruction.InstructionAlias"
            ]
            leaves.append(
                {
                    "form_id": form_id,
                    "instruction_set": instruction_set,
                    "width": width,
                    "fixed_mask_int": mask,
                    "fixed_value_int": value,
                    "fixed_bits": mask.bit_count(),
                    "internal_name": node_name,
                    "mnemonic": first_literal(node),
                    "assembly_template": assembly_template(node),
                    "feature_condition_key": feature_key,
                    "all_conditions_digest": digest_value(current_conditions),
                    "assertions_digest": digest_value(node.get("assertions")),
                    "operation_id": str(node.get("operation_id", "")),
                    "alias_count": len(leaf_aliases),
                    "source_order": len(leaves),
                }
            )
            for alias in leaf_aliases:
                alias_conditions = current_conditions + (alias.get("condition"),)
                aliases.append(
                    {
                        "form_id": form_id,
                        "internal_name": str(alias.get("name", "")),
                        "mnemonic": first_literal(alias),
                        "assembly_template": assembly_template(alias),
                        "feature_condition_key": register_feature_condition(alias_conditions),
                        "condition_digest": digest_value(alias.get("condition")),
                        "preferred_digest": digest_value(alias.get("preferred")),
                        "operation_id": str(alias.get("operation_id", "")),
                    }
                )

        for child in node.get("children", []):
            if child.get("_type") != "Instruction.InstructionAlias":
                visit(
                    child,
                    instruction_set,
                    node_path,
                    mask,
                    value,
                    width,
                    current_conditions,
                )

    for root in document.get("instructions", []):
        instruction_set = str(root.get("name", ""))
        if instruction_set not in ("A32", "T32", "A64"):
            raise GenerationError(f"unknown Arm instruction set {instruction_set!r}")
        visit(root, instruction_set, (), 0, 0, None, ())

    sorted_conditions = sorted(condition_values.items(), key=lambda item: item[0])
    conditions: list[dict[str, Any]] = []
    condition_ids: dict[str, int] = {}
    for index, (key, record) in enumerate(sorted_conditions):
        condition_ids[key] = index
        conditions.append(
            {
                "feature_condition_id": index,
                "digest": digest_value(record),
                "features": record["features"],
                "expressions": record["expressions"],
            }
        )
    for record in leaves:
        record["feature_condition_id"] = condition_ids[
            record.pop("feature_condition_key")
        ]
    serialized_to_id = {
        key: index for index, (key, _record) in enumerate(sorted_conditions)
    }
    for record in aliases:
        record["feature_condition_id"] = serialized_to_id[
            record.pop("feature_condition_key")
        ]
    unsupported = {
        "node_type_counts": dict(sorted(node_type_counts.items())),
        "assembly_symbol_type_counts": dict(sorted(assembly_symbol_counts.items())),
        "leaves_with_assertions": assertion_leaf_count,
        "condition_ast_compiled": False,
        "assertion_ast_compiled": False,
        "assembly_rules_compiled": False,
        "alias_preference_compiled": False,
    }
    return leaves, aliases, conditions, unsupported


def export_xed_database(xed_root: Path, dgen: Path, output: Path) -> None:
    exporter = xed_root / "pysrc" / "xed_to_db.py"
    if not exporter.is_file():
        raise GenerationError(f"XED exporter missing: {exporter}")
    process = subprocess.run(
        [
            sys.executable,
            str(exporter),
            "--xed-dgen",
            str(dgen),
            "--out",
            str(output),
            "--compact",
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if process.returncode != 0:
        raise GenerationError(
            f"XED metadata export failed ({process.returncode}): "
            + " ".join(process.stdout.split())[-1000:]
        )


def compact_list(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ",".join(str(item) for item in value)
    return str(value)


def prefix_constraint(record: dict[str, Any]) -> str:
    values: list[str] = []
    if record.get("f2_required"):
        values.append("F2")
    if record.get("f3_required"):
        values.append("F3")
    if record.get("osz_66_required"):
        values.append("66")
    if record.get("no_prefixes_allowed"):
        values.append("NP")
    return ",".join(values)


def load_x86_iclass_catalog(
    path: Path, expected_names: set[str]
) -> tuple[dict[str, int], dict[str, Any]]:
    if not path.is_file():
        raise GenerationError(f"x86 ICLASS catalog missing: {path}")
    with path.open("r", encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream, dialect="excel-tab"))
    mapping: dict[str, int] = {}
    used_ids: dict[int, str] = {}
    for row in rows:
        name = row["iclass"]
        name_id = int(row["name_id"], 0)
        if not name or name_id == 0 or name in mapping:
            raise GenerationError(f"invalid/duplicate x86 ICLASS catalog row {row}")
        if name_id in used_ids:
            raise GenerationError(
                f"x86 ICLASS IDs collide: {name} and {used_ids[name_id]} use {name_id}"
            )
        mapping[name] = name_id
        used_ids[name_id] = name
    missing = sorted(expected_names - set(mapping))
    extra = sorted(set(mapping) - expected_names)
    if missing or extra:
        raise GenerationError(
            f"x86 ICLASS catalog mismatch: {len(missing)} missing, {len(extra)} extra; "
            f"missing sample={missing[:5]}, extra sample={extra[:5]}"
        )
    return mapping, {
        "path": str(path),
        "sha256": digest_file(path),
        "rows": len(rows),
        "min_name_id": min(used_ids),
        "max_name_id": max(used_ids),
        "one_to_one": True,
        "exact_name_set": True,
    }


def compact_xed(records: list[dict[str, Any]], iclass_ids: dict[str, int]) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, Any],
]:
    descriptors: list[dict[str, Any]] = []
    unknown_spaces: set[str] = set()
    for source_order, record in enumerate(records):
        space = str(record.get("encoding_space", ""))
        if space not in SPACE_ORDER:
            unknown_spaces.add(space)
        raw_opcode = record.get("opcode_base16")
        try:
            opcode = int(str(raw_opcode), 0)
        except (TypeError, ValueError) as error:
            raise GenerationError(
                f"bad XED opcode {raw_opcode!r} for {record.get('iform')}"
            ) from error
        descriptor = {
            "encoding_space": space,
            "map": int(record["map"]),
            "opcode": opcode,
            "opcode_hex": f"0x{opcode:02x}",
            "iclass": str(record.get("iclass", "")),
            "iclass_id": iclass_ids[str(record.get("iclass", ""))],
            "iform": str(record.get("iform", "")),
            "isa_set": str(record.get("isa_set", "")),
            "extension": str(record.get("extension", "")),
            "category": str(record.get("category", "")),
            "pattern": str(record.get("pattern", "")),
            "pattern_digest": digest_value(record.get("pattern")),
            "attributes": compact_list(sorted(record.get("attributes") or [])),
            "mode": compact_list(record.get("mode_restriction")),
            "easz": compact_list(record.get("easz_list")),
            "eosz": compact_list(record.get("eosz_list")),
            "prefix": prefix_constraint(record),
            "has_modrm": bool(record.get("has_modrm")),
            "mod_required": compact_list(record.get("mod_required")),
            "reg_required": compact_list(record.get("reg_required")),
            "rm_required": "" if record.get("rm_required") is None else record["rm_required"],
            "partial_opcode": bool(record.get("partial_opcode")),
            "rexw": "" if record.get("rexw_prefix") is None else int(bool(record["rexw_prefix"])),
            "rex2": str(record.get("rex2_restriction", "")),
            "evex_pp": "" if record.get("evex_pp") is None else record["evex_pp"],
            "u_bit": record.get("u_bit", ""),
            "vl": "" if record.get("vl") is None else record["vl"],
            "nd": record.get("nd", ""),
            "nf": record.get("nf", ""),
            "undocumented": bool(record.get("undocumented")),
            "cpuid_digest": digest_value(record.get("cpuid_groups") or []),
            "operand_digest": digest_value(record.get("parsed_operands") or []),
            "source_order": source_order,
        }
        descriptor["record_digest"] = digest_value(record)
        descriptors.append(descriptor)

    iforms = sorted({descriptor["iform"] for descriptor in descriptors})
    if len(iforms) > 0xFFFF:
        raise GenerationError(f"{len(iforms)} XED IFORMs do not fit uint16_t")
    iform_ids = {iform: index + 1 for index, iform in enumerate(iforms)}
    iform_iclasses: dict[str, str] = {}
    for descriptor in descriptors:
        old = iform_iclasses.setdefault(descriptor["iform"], descriptor["iclass"])
        if old != descriptor["iclass"]:
            raise GenerationError(
                f"XED IFORM {descriptor['iform']} maps to multiple ICLASS names"
            )
        descriptor["iform_id"] = iform_ids[descriptor["iform"]]
    iform_rows = [
        {
            "iform_id": iform_ids[iform],
            "iform": iform,
            "iclass": iform_iclasses[iform],
            "iclass_id": iclass_ids[iform_iclasses[iform]],
        }
        for iform in iforms
    ]

    descriptors.sort(
        key=lambda item: (
            SPACE_ORDER.get(item["encoding_space"], 99),
            item["encoding_space"],
            item["map"],
            item["opcode"],
            item["iclass"],
            item["iform"],
            item["record_digest"],
            item["source_order"],
        )
    )
    buckets: list[dict[str, Any]] = []
    bucket_start = 0
    while bucket_start < len(descriptors):
        first = descriptors[bucket_start]
        key = (first["encoding_space"], first["map"], first["opcode"])
        bucket_end = bucket_start + 1
        while bucket_end < len(descriptors):
            item = descriptors[bucket_end]
            if (item["encoding_space"], item["map"], item["opcode"]) != key:
                break
            bucket_end += 1
        buckets.append(
            {
                "encoding_space": key[0],
                "map": key[1],
                "opcode": key[2],
                "opcode_hex": f"0x{key[2]:02x}",
                "descriptor_start": bucket_start,
                "descriptor_count": bucket_end - bucket_start,
            }
        )
        bucket_start = bucket_end
    for index, descriptor in enumerate(descriptors):
        descriptor["descriptor_index"] = index
    unsupported = {
        "unknown_encoding_spaces": sorted(unknown_spaces),
        "pattern_language_compiled": False,
        "operand_nonterminals_compiled": False,
        "cpuid_groups_compiled": False,
        "descriptors_with_partial_opcode": sum(
            1 for record in descriptors if record["partial_opcode"]
        ),
        "descriptors_with_modrm": sum(
            1 for record in descriptors if record["has_modrm"]
        ),
    }
    return descriptors, buckets, iform_rows, unsupported


def write_tsv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=fields,
            dialect="excel-tab",
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)


def emit_c_rows(output: list[str], declaration: str, rows: list[str]) -> None:
    output.append(declaration + " = {")
    output.extend(f"    {row}," for row in rows)
    output.extend(["};", ""])


def emit_x86_iform_includes(
    decode_path: Path,
    text_path: Path,
    descriptors: list[dict[str, Any]],
    iform_rows: list[dict[str, Any]],
) -> None:
    descriptor_lists: list[list[int]] = [[] for _ in range(len(iform_rows) + 1)]
    for descriptor in descriptors:
        descriptor_lists[descriptor["iform_id"]].append(descriptor["descriptor_index"])
    flat_indexes: list[int] = []
    spans: list[tuple[int, int]] = []
    for indexes in descriptor_lists:
        spans.append((len(flat_indexes), len(indexes)))
        flat_indexes.extend(indexes)
    if len(flat_indexes) != len(descriptors):
        raise GenerationError("x86 IFORM reverse mapping lost descriptor records")

    decode = [
        "/* Generated numeric-only XED IFORM mapping. Do not edit. */",
        "#ifndef CDISASM_X86_IFORM_DECODE_GENERATED_INC",
        "#define CDISASM_X86_IFORM_DECODE_GENERATED_INC",
        "#include <stdint.h>",
        f"#define CDISASM_X86_GEN_IFORM_ID_COUNT UINT16_C({len(iform_rows)})",
        f"#define CDISASM_X86_GEN_DESCRIPTOR_COUNT UINT32_C({len(descriptors)})",
        "typedef struct cdisasm_x86_gen_iform_span { uint32_t first, count; } cdisasm_x86_gen_iform_span;",
        "",
    ]
    emit_c_rows(
        decode,
        f"static const uint16_t cdisasm_x86_gen_descriptor_to_iform[{len(descriptors)}]",
        [f"UINT16_C({record['iform_id']})" for record in descriptors],
    )
    emit_c_rows(
        decode,
        f"static const uint16_t cdisasm_x86_gen_iform_to_iclass[{len(iform_rows) + 1}]",
        ["UINT16_C(0)"]
        + [f"UINT16_C({row['iclass_id']})" for row in iform_rows],
    )
    emit_c_rows(
        decode,
        f"static const cdisasm_x86_gen_iform_span cdisasm_x86_gen_iform_spans[{len(spans)}]",
        [f"{{UINT32_C({first}), UINT32_C({count})}}" for first, count in spans],
    )
    emit_c_rows(
        decode,
        f"static const uint32_t cdisasm_x86_gen_iform_descriptor_indexes[{len(flat_indexes)}]",
        [f"UINT32_C({index})" for index in flat_indexes],
    )
    decode.extend(["#endif", ""])
    decode_path.parent.mkdir(parents=True, exist_ok=True)
    decode_path.write_text("\n".join(decode), encoding="ascii", newline="\n")

    strings = [""] + sorted({row["iform"] for row in iform_rows})
    offsets: dict[str, int] = {}
    data = bytearray()
    for value in strings:
        offsets[value] = len(data)
        data.extend(value.encode("ascii"))
        data.append(0)
    text = [
        "/* Generated XED IFORM formatter/tooling names. Do not edit. */",
        "#ifndef CDISASM_X86_IFORM_FORMAT_GENERATED_INC",
        "#define CDISASM_X86_IFORM_FORMAT_GENERATED_INC",
        "#include <stdint.h>",
        "typedef struct cdisasm_x86_gen_iform_text { uint32_t iform_offset; uint16_t iclass_id; } cdisasm_x86_gen_iform_text;",
        "",
    ]
    text_rows = ["{UINT32_C(0), UINT16_C(0)}"]
    text_rows.extend(
        f"{{UINT32_C({offsets[row['iform']]}), UINT16_C({row['iclass_id']})}}"
        for row in iform_rows
    )
    emit_c_rows(
        text,
        f"static const cdisasm_x86_gen_iform_text cdisasm_x86_gen_iform_texts[{len(text_rows)}]",
        text_rows,
    )
    text.append(f"static const unsigned char cdisasm_x86_gen_iform_strings[{len(data)}] = {{")
    for start in range(0, len(data), 16):
        text.append(
            "    "
            + ", ".join(f"0x{byte:02x}" for byte in data[start : start + 16])
            + ","
        )
    text.extend(["};", "#endif", ""])
    text_path.parent.mkdir(parents=True, exist_ok=True)
    text_path.write_text("\n".join(text), encoding="ascii", newline="\n")


def file_record(path: Path, base: Path) -> dict[str, Any]:
    try:
        display = path.relative_to(base).as_posix()
    except ValueError:
        display = str(path)
    return {"path": display, "sha256": digest_file(path), "bytes": path.stat().st_size}


def main() -> int:
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xed-root", type=Path, required=True)
    parser.add_argument("--xed-dgen", type=Path)
    parser.add_argument("--xed-db", type=Path)
    parser.add_argument("--arm-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=script_dir / "generated")
    parser.add_argument(
        "--x86-iclass-catalog",
        type=Path,
        default=script_dir / "generated" / "x86_iclass_catalog.tsv",
    )
    parser.add_argument(
        "--x86-decode-include",
        type=Path,
        default=repo_root / "src" / "x86" / "generated" / "cdisasm_x86_iform_decode.inc",
    )
    parser.add_argument(
        "--x86-text-include",
        type=Path,
        default=repo_root / "src" / "x86" / "generated" / "cdisasm_x86_iform_format.inc",
    )
    parser.add_argument("--allow-source-drift", action="store_true")
    arguments = parser.parse_args()

    xed_root = arguments.xed_root.resolve()
    arm_root = arguments.arm_root.resolve()
    output_dir = arguments.output_dir.resolve()
    x86_decode_include = arguments.x86_decode_include.resolve()
    x86_text_include = arguments.x86_text_include.resolve()
    baseline_path = repo_root / "tools" / "coverage" / "baselines.json"
    baselines = load_json(baseline_path)
    xed_baseline = baselines["intel_xed"]
    arm_baseline = baselines["arm_aarchmrs"]
    xed_commit = verify_commit(
        xed_root, xed_baseline["commit"], "Intel XED", arguments.allow_source_drift
    )
    arm_commit = verify_commit(
        arm_root, arm_baseline["commit"], "Arm AARCHMRS", arguments.allow_source_drift
    )

    arm_path = arm_root / arm_baseline["inventory_file"]
    if not arm_path.is_file():
        raise GenerationError(f"Arm inventory missing: {arm_path}")
    arm_document = load_json(arm_path)
    arm_version = (arm_document.get("_meta") or {}).get("version") or {}
    expected = {
        "architecture": arm_baseline["architecture_revision"],
        "ref": arm_baseline["data_ref"],
        "build": arm_baseline["build"],
        "schema": arm_baseline["schema"],
        "timestamp": arm_baseline["data_timestamp"],
    }
    if any(str(arm_version.get(key)) != str(value) for key, value in expected.items()):
        if not arguments.allow_source_drift:
            raise GenerationError(
                f"Arm metadata mismatch: expected {expected}, got {arm_version}"
            )

    temporary: tempfile.TemporaryDirectory[str] | None = None
    if arguments.xed_db is not None:
        xed_db_path = arguments.xed_db.resolve()
    else:
        dgen = (
            arguments.xed_dgen.resolve()
            if arguments.xed_dgen is not None
            else xed_root / "obj" / "dgen"
        )
        if not dgen.is_dir():
            raise GenerationError(
                f"XED dgen missing: {dgen}; pass --xed-dgen or a pre-exported --xed-db"
            )
        temporary = tempfile.TemporaryDirectory(prefix="cdisasm-xed-db-")
        xed_db_path = Path(temporary.name) / "xed_db.json"
        export_xed_database(xed_root, dgen, xed_db_path)
    if not xed_db_path.is_file():
        raise GenerationError(f"XED JSON database missing: {xed_db_path}")
    xed_db_sha256 = digest_file(xed_db_path)
    expected_xed_sha256 = xed_baseline.get("metadata_export_sha256")
    if (
        expected_xed_sha256
        and xed_db_sha256 != expected_xed_sha256
        and not arguments.allow_source_drift
    ):
        raise GenerationError(
            f"XED metadata export hash mismatch: expected {expected_xed_sha256}, "
            f"got {xed_db_sha256}"
        )
    xed_document = load_json(xed_db_path)
    if xed_document.get("Version") != xed_baseline["ref"]:
        if not arguments.allow_source_drift:
            raise GenerationError(
                f"XED database version mismatch: expected {xed_baseline['ref']}, "
                f"got {xed_document.get('Version')!r}"
            )

    arm_leaves, arm_aliases, arm_conditions, arm_unsupported = flatten_arm(
        arm_document
    )
    x86_iclass_ids, x86_iclass_catalog = load_x86_iclass_catalog(
        arguments.x86_iclass_catalog.resolve(),
        {str(record["iclass"]) for record in xed_document["Instructions"]},
    )
    x86_descriptors, x86_buckets, x86_iforms, x86_unsupported = compact_xed(
        xed_document["Instructions"], x86_iclass_ids
    )

    condition_ids = {
        canonical_json(
            {"expressions": condition["expressions"], "features": condition["features"]}
        ): condition["feature_condition_id"]
        for condition in arm_conditions
    }
    # flatten_arm already assigned IDs. This assertion catches accidental table drift.
    if len(condition_ids) != len(arm_conditions):
        raise GenerationError("Arm feature-condition table contains duplicate records")

    arm_leaves.sort(
        key=lambda item: (
            item["instruction_set"],
            item["width"],
            item["fixed_value_int"],
            item["fixed_mask_int"],
            item["form_id"],
        )
    )
    for index, leaf in enumerate(arm_leaves):
        width_digits = leaf["width"] // 4
        leaf["leaf_index"] = index
        leaf["fixed_mask"] = f"0x{leaf.pop('fixed_mask_int'):0{width_digits}x}"
        leaf["fixed_value"] = f"0x{leaf.pop('fixed_value_int'):0{width_digits}x}"
    arm_aliases.sort(key=lambda item: (item["form_id"], item["internal_name"]))

    output_dir.mkdir(parents=True, exist_ok=True)
    arm_leaf_path = output_dir / "arm_leaves.tsv"
    arm_alias_path = output_dir / "arm_aliases.tsv"
    arm_condition_path = output_dir / "arm_feature_conditions.jsonl"
    x86_descriptor_path = output_dir / "x86_descriptors.tsv"
    x86_bucket_path = output_dir / "x86_buckets.tsv"
    x86_iform_path = output_dir / "x86_iforms.tsv"
    write_tsv(
        arm_leaf_path,
        arm_leaves,
        [
            "leaf_index",
            "instruction_set",
            "width",
            "fixed_mask",
            "fixed_value",
            "fixed_bits",
            "internal_name",
            "mnemonic",
            "assembly_template",
            "feature_condition_id",
            "all_conditions_digest",
            "assertions_digest",
            "operation_id",
            "alias_count",
            "form_id",
            "source_order",
        ],
    )
    write_tsv(
        arm_alias_path,
        arm_aliases,
        [
            "form_id",
            "internal_name",
            "mnemonic",
            "assembly_template",
            "feature_condition_id",
            "condition_digest",
            "preferred_digest",
            "operation_id",
        ],
    )
    with arm_condition_path.open("w", encoding="utf-8", newline="\n") as stream:
        for condition in arm_conditions:
            stream.write(canonical_json(condition) + "\n")
    write_tsv(
        x86_descriptor_path,
        x86_descriptors,
        [
            "descriptor_index",
            "iform_id",
            "iclass_id",
            "encoding_space",
            "map",
            "opcode",
            "opcode_hex",
            "iclass",
            "iform",
            "isa_set",
            "extension",
            "category",
            "pattern",
            "pattern_digest",
            "attributes",
            "mode",
            "easz",
            "eosz",
            "prefix",
            "has_modrm",
            "mod_required",
            "reg_required",
            "rm_required",
            "partial_opcode",
            "rexw",
            "rex2",
            "evex_pp",
            "u_bit",
            "vl",
            "nd",
            "nf",
            "undocumented",
            "cpuid_digest",
            "operand_digest",
            "record_digest",
            "source_order",
        ],
    )
    write_tsv(
        x86_bucket_path,
        x86_buckets,
        [
            "encoding_space",
            "map",
            "opcode",
            "opcode_hex",
            "descriptor_start",
            "descriptor_count",
        ],
    )
    write_tsv(
        x86_iform_path,
        x86_iforms,
        ["iform_id", "iform", "iclass", "iclass_id"],
    )
    emit_x86_iform_includes(
        x86_decode_include,
        x86_text_include,
        x86_descriptors,
        x86_iforms,
    )

    artifacts = {}
    for path, rows in (
        (arm_leaf_path, len(arm_leaves)),
        (arm_alias_path, len(arm_aliases)),
        (arm_condition_path, len(arm_conditions)),
        (x86_descriptor_path, len(x86_descriptors)),
        (x86_bucket_path, len(x86_buckets)),
        (x86_iform_path, len(x86_iforms)),
        (x86_decode_include, len(x86_descriptors)),
        (x86_text_include, len(x86_iforms) + 1),
    ):
        artifacts[path.name] = {
            "rows": rows,
            "sha256": digest_file(path),
            "bytes": path.stat().st_size,
        }
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generator_version": GENERATOR_VERSION,
        "generator_sha256": digest_file(Path(__file__).resolve()),
        "baselines_sha256": digest_file(baseline_path),
        "source_revisions": {
            "intel_xed": {**xed_baseline, "observed_commit": xed_commit},
            "arm_aarchmrs": {**arm_baseline, "observed_commit": arm_commit},
        },
        "source_inputs": {
            "arm_instructions": file_record(arm_path, arm_root),
            "xed_export": {
                "version": xed_document.get("Version"),
                "sha256": xed_db_sha256,
                "instruction_records": len(xed_document["Instructions"]),
                "pre_exported_input": arguments.xed_db is not None,
                "official_exporter": "pysrc/xed_to_db.py",
                "official_exporter_sha256": digest_file(
                    xed_root / "pysrc" / "xed_to_db.py"
                ),
            },
            "x86_iclass_catalog": x86_iclass_catalog,
            "source_drift_allowed": arguments.allow_source_drift,
        },
        "counts": {
            "arm_canonical_leaves": len(arm_leaves),
            "arm_aliases": len(arm_aliases),
            "arm_feature_conditions": len(arm_conditions),
            "x86_descriptors": len(x86_descriptors),
            "x86_unique_iforms": len(x86_iforms),
            "x86_iform_id_min": 1,
            "x86_iform_id_max": len(x86_iforms),
            "x86_iform_id_zero_reserved": True,
            "x86_encoding_buckets": len(x86_buckets),
            "x86_by_encoding_space": {
                space: sum(
                    1 for record in x86_descriptors if record["encoding_space"] == space
                )
                for space in sorted({r["encoding_space"] for r in x86_descriptors})
            },
        },
        "unsupported_metadata": {
            "arm": arm_unsupported,
            "x86": x86_unsupported,
        },
        "determinism": {
            "wall_clock_time_embedded": False,
            "sort_keys": [
                "Arm: instruction_set,width,value,mask,form_id",
                "x86: encoding_space,map,opcode,iclass,iform,record_digest,source_order",
            ],
        },
        "integration_status": {
            "wired_into_decoder": True,
            "safe_use": (
                "x86 descriptors are compiled into the numeric fallback after "
                "the hand-written decoder returns unsupported; Arm inventory "
                "remains source data for the Arm tree generator"
            ),
            "x86": {
                "wired_into_decoder": True,
                "fallback_status": "unsupported_only",
                "numeric_only": True,
            },
            "arm": {
                "wired_into_decoder": False,
                "safe_use": "source inventory for the Arm tree generator",
            },
        },
        "artifacts": artifacts,
    }
    manifest_path = output_dir / "manifest.json"
    with manifest_path.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(manifest, stream, ensure_ascii=True, indent=2, sort_keys=True)
        stream.write("\n")
    if temporary is not None:
        temporary.cleanup()
    print(
        f"Arm: {len(arm_leaves)} leaves, {len(arm_aliases)} aliases, "
        f"{len(arm_conditions)} feature-condition records"
    )
    print(
        f"x86: {len(x86_descriptors)} descriptors in {len(x86_buckets)} "
        "encoding-space/map/opcode buckets"
    )
    print(f"wrote {manifest_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GenerationError as error:
        print(f"ISA inventory generation failed: {error}", file=sys.stderr)
        raise SystemExit(2)
