#!/usr/bin/env python3
"""Generate the string-free conservative ARM architectural-alias selector."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import sys
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
sys.path.insert(0, str(SCRIPT_DIR))
import generate_arm_assembly_catalog as assembly  # noqa: E402
import generate_arm_tree as tree  # noqa: E402


NONE = 0xFFFFFFFF
SUPPORTED_FUNCTION_KINDS = {
    "IsFeatureImplemented": 1,
    "UInt": 2,
    "SInt": 3,
    "T32ExpandImm": 4,
    "BitCount": 5,
    "IsZero": 6,
    "IsOnes": 7,
    "InITBlock": 8,
    "BFXPreferred": 9,
    "MoveWidePreferred": 10,
    "SVEMoveMaskPreferred": 11,
    "A32EncodingExists": 12,
    "T32EncodingExists": 13,
    "SysOp": 14,
    "SysLOp": 15,
    "SysOp128": 16,
}

SUPPORTED_SYMBOL_VALUES = {
    "Sys_DC": 1,
    "Sys_TLBI": 2,
    "Sys_IC": 3,
    "Sys_AT": 4,
    "Sys_BRB": 5,
    "Sys_GSB": 6,
    "Sys_GIC": 7,
    "Sys_PLBI": 8,
    "Sysl_GICR": 9,
    "Sys_TLBIP": 10,
}

SYSTEM_OPTION_SPECS = {
    "dc_op_option": ("SysOp", "Sys_DC"),
    "tlbi_op_option": ("SysOp", "Sys_TLBI"),
    "ic_op_option": ("SysOp", "Sys_IC"),
    "at_op_option": ("SysOp", "Sys_AT"),
    "brb_op_option": ("SysOp", "Sys_BRB"),
    "gsb_op_option": ("SysOp", "Sys_GSB"),
    "gic_op_option": ("SysOp", "Sys_GIC"),
    "plbi_op_option": ("SysOp", "Sys_PLBI"),
    "gicr_op_option": ("SysLOp", "Sysl_GICR"),
    "tlbip_op_option": ("SysOp128", "Sys_TLBIP"),
}

FLAG_SETTING_ALIAS_MNEMONICS = {
    "adcs", "adds", "ands", "asrs", "bics", "eors", "lsls", "lsrs",
    "movs", "muls", "mvns", "orrs", "rors", "rsbs", "sbcs", "subs",
}

LEGACY_FEATURE_IDS = {
    "FEAT_AA32BF16": 34,
    "FEAT_BF16": 34,
    "FEAT_AdvSIMD": 5,
    "FEAT_BTI": 21,
    "FEAT_CPA": 28,
    "FEAT_CSSC": 26,
    "FEAT_F64MM": 33,
    "FEAT_FP": 27,
    "FEAT_FP16": 13,
    "FEAT_FP8": 35,
    "FEAT_LOR": 11,
    "FEAT_LRCPC": 12,
    "FEAT_LRCPC2": 12,
    "FEAT_LRCPC3": 20,
    "FEAT_LS64": 25,
    "FEAT_LS64_ACCDATA": 25,
    "FEAT_LS64_V": 25,
    "FEAT_LSE": 10,
    "FEAT_LSE128": 19,
    "FEAT_MOPS": 24,
    "FEAT_MOPS_GO": 24,
    "FEAT_MTE": 23,
    "FEAT_MTE2": 23,
    "FEAT_PAUTH": 22,
    "FEAT_PAUTH_LR": 22,
    "FEAT_SME": 16,
    "FEAT_SME2": 17,
    "FEAT_SME2p1": 30,
    "FEAT_SME2p2": 32,
    "FEAT_SVE": 14,
    "FEAT_SVE2": 15,
    "FEAT_SVE2p1": 29,
    "FEAT_SVE2p2": 31,
}


class AliasGenerationError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def program_reason(
    program: tuple[tuple[int, int, int], ...],
    function_names: list[str],
    symbol_names: list[str],
) -> str:
    for opcode, a, _b in program:
        if opcode == tree.BC_OPCODE["PUSH_SYMBOL"]:
            name = symbol_names[a] if 0 <= a < len(symbol_names) else str(a)
            if name not in SUPPORTED_SYMBOL_VALUES:
                return f"runtime_symbol:{name}"
        if opcode == tree.BC_OPCODE["CALL"]:
            name = function_names[a] if 0 <= a < len(function_names) else str(a)
            if name not in SUPPORTED_FUNCTION_KINDS:
                return f"runtime_function:{name}"
    return ""


def pack_system_operation(op1: int, crn: int, crm: int, op2: int) -> int:
    if not (0 <= op1 < 8 and 0 <= crn < 16
            and 0 <= crm < 16 and 0 <= op2 < 8):
        raise AliasGenerationError("system-operation field is out of range")
    return (op1 << 11) | (crn << 7) | (crm << 3) | op2


def parse_system_rule_reference(option_rule: str, reference: str) -> int:
    parts = reference.lower().split("_")
    if option_rule == "dc_op_option":
        op1, crm, op2 = (int(value, 2) for value in parts[2:5])
        return pack_system_operation(op1, 7, crm, op2)
    if option_rule == "tlbi_op_option":
        op1, crn, crm, op2 = (int(value, 2) for value in parts[2:6])
        return pack_system_operation(op1, crn, crm, op2)
    if option_rule == "ic_op_option":
        op1, crm, op2 = (int(value, 2) for value in parts[2:5])
        return pack_system_operation(op1, 7, crm, op2)
    if option_rule == "at_op_option":
        op1, crm_low, op2 = (int(value, 2) for value in parts[2:5])
        return pack_system_operation(op1, 7, 8 | crm_low, op2)
    if option_rule == "brb_op_option":
        return pack_system_operation(1, 7, 2, int(parts[2], 2))
    if option_rule == "gsb_op_option":
        return pack_system_operation(0, 12, 0, int(parts[2], 2))
    if option_rule == "gic_op_option":
        op1, crm, op2 = (int(value, 2) for value in parts[2:5])
        return pack_system_operation(op1, 12, crm, op2)
    if option_rule in {"plbi_op_option", "tlbip_op_option"}:
        op1, crn, crm, op2 = (int(value, 2) for value in parts[2:6])
        return pack_system_operation(op1, crn, crm, op2)
    if option_rule == "gicr_op_option":
        return pack_system_operation(0, 12, 3, int(parts[2], 2))
    raise AliasGenerationError(f"unknown system option rule {option_rule!r}")


def collect_system_operations(
    document: dict[str, Any],
    pool_ids: dict[str, dict[str, int]],
) -> list[dict[str, Any]]:
    rules = document.get("assembly_rules", {})
    records: dict[int, dict[str, Any]] = {}
    for option_rule, (function_name, symbol_name) in SYSTEM_OPTION_SPECS.items():
        source = rules.get(option_rule)
        if not isinstance(source, dict) or not isinstance(source.get("choices"), list):
            raise AliasGenerationError(f"missing system option rule {option_rule!r}")
        function_kind = SUPPORTED_FUNCTION_KINDS[function_name]
        symbol_value = SUPPORTED_SYMBOL_VALUES[symbol_name]
        for choice in source["choices"]:
            symbols = choice.get("symbols", [])
            if len(symbols) != 1 or symbols[0].get("_type") \
                    != "Instruction.Symbols.RuleReference":
                raise AliasGenerationError(
                    f"unexpected choice in system option rule {option_rule!r}"
                )
            code = parse_system_rule_reference(
                option_rule, str(symbols[0].get("rule_id", ""))
            )
            key = (function_kind << 14) | code
            referenced_rule = rules.get(str(symbols[0].get("rule_id", "")))
            if not isinstance(referenced_rule, dict):
                raise AliasGenerationError(
                    f"missing system operation rule in {option_rule!r}"
                )
            condition = tree.compile_ast(
                referenced_rule.get("condition"), {}, **pool_ids
            )
            if condition is None:
                raise AliasGenerationError(
                    f"empty system operation condition in {option_rule!r}"
                )
            record = {
                "key": key,
                "result": symbol_value,
                "condition": condition,
                "condition_program_id": NONE,
            }
            previous = records.setdefault(key, record)
            if (previous["result"] != symbol_value
                    or previous["condition"] != condition):
                raise AliasGenerationError(
                    f"conflicting system operation key 0x{key:x}"
                )
    return [records[key] for key in sorted(records)]


def program_calls_function(
    program: tuple[tuple[int, int, int], ...],
    function_names: list[str],
    expected: str,
) -> bool:
    return any(
        opcode == tree.BC_OPCODE["CALL"]
        and 0 <= a < len(function_names)
        and function_names[a] == expected
        for opcode, a, _b in program
    )


def capability_id(feature_name: str, feature_index: int) -> int:
    result = LEGACY_FEATURE_IDS.get(feature_name, 36 + feature_index)
    if result >= 512:
        raise AliasGenerationError(
            f"feature {feature_name!r} exceeds the 512-bit capability object"
        )
    return result


def c_u8(value: int) -> str:
    return f"UINT8_C({value})"


def c_u16(value: int) -> str:
    return f"UINT16_C({value})"


def c_u32(value: int) -> str:
    return f"UINT32_C({value})"


def emit_array(lines: list[str], declaration: str, rows: list[str]) -> None:
    lines.append(declaration + " = {")
    lines.extend(f"    {row}," for row in rows)
    lines.extend(["};", ""])


def render_include(
    aliases: list[dict[str, Any]],
    program_records: list[tuple[int, int]],
    bytecode: list[tuple[int, int, int]],
    feature_names: list[str],
    function_names: list[str],
    symbol_names: list[str],
    value_names: list[str],
    system_operations: list[dict[str, Any]],
) -> bytes:
    values = [tree.numeric_value_record(value) for value in value_names]
    lines = [
        "/* Generated string-free ARM architectural-alias selector. Do not edit. */",
        "#ifndef CDISASM_ARM_ALIAS_DECODE_GENERATED_INC",
        "#define CDISASM_ARM_ALIAS_DECODE_GENERATED_INC",
        "#include <stdint.h>",
        "#if USE_EXTRA_OPCODES",
        f"#define CDISASM_ARM_ALIASGEN_ALIAS_COUNT {c_u32(len(aliases))}",
        f"#define CDISASM_ARM_ALIASGEN_PROGRAM_COUNT {c_u32(len(program_records))}",
        f"#define CDISASM_ARM_ALIASGEN_FEATURE_COUNT {c_u32(len(feature_names))}",
        f"#define CDISASM_ARM_ALIASGEN_SYMBOL_COUNT {c_u32(len(symbol_names))}",
        f"#define CDISASM_ARM_ALIASGEN_SYSTEM_OPERATION_COUNT {c_u32(len(system_operations))}",
        "#define CDISASM_ARM_ALIASGEN_NONE UINT32_C(4294967295)",
        "enum cdisasm_arm_aliasgen_opcode { CDISASM_ARM_ALIASGEN_PUSH_BOOL = 1, CDISASM_ARM_ALIASGEN_PUSH_FIELD = 2, CDISASM_ARM_ALIASGEN_PUSH_FEATURE = 3, CDISASM_ARM_ALIASGEN_PUSH_SYMBOL = 4, CDISASM_ARM_ALIASGEN_PUSH_VALUE = 5, CDISASM_ARM_ALIASGEN_PUSH_INTEGER = 6, CDISASM_ARM_ALIASGEN_MAKE_SET = 7, CDISASM_ARM_ALIASGEN_MAKE_SLICE = 8, CDISASM_ARM_ALIASGEN_SQUARE = 9, CDISASM_ARM_ALIASGEN_LOGICAL_NOT = 16, CDISASM_ARM_ALIASGEN_BIT_NOT = 17, CDISASM_ARM_ALIASGEN_AND = 32, CDISASM_ARM_ALIASGEN_OR = 33, CDISASM_ARM_ALIASGEN_EQ = 34, CDISASM_ARM_ALIASGEN_NE = 35, CDISASM_ARM_ALIASGEN_LT = 36, CDISASM_ARM_ALIASGEN_GT = 37, CDISASM_ARM_ALIASGEN_GE = 38, CDISASM_ARM_ALIASGEN_IN = 39, CDISASM_ARM_ALIASGEN_CONCAT = 40, CDISASM_ARM_ALIASGEN_XOR = 41, CDISASM_ARM_ALIASGEN_MOD = 42, CDISASM_ARM_ALIASGEN_ADD = 43, CDISASM_ARM_ALIASGEN_CALL = 48 };",
        "enum cdisasm_arm_aliasgen_function_kind { CDISASM_ARM_ALIASGEN_FUNCTION_UNSUPPORTED = 0, CDISASM_ARM_ALIASGEN_FUNCTION_FEATURE = 1, CDISASM_ARM_ALIASGEN_FUNCTION_UINT = 2, CDISASM_ARM_ALIASGEN_FUNCTION_SINT = 3, CDISASM_ARM_ALIASGEN_FUNCTION_T32_EXPAND_IMM = 4, CDISASM_ARM_ALIASGEN_FUNCTION_BIT_COUNT = 5, CDISASM_ARM_ALIASGEN_FUNCTION_IS_ZERO = 6, CDISASM_ARM_ALIASGEN_FUNCTION_IS_ONES = 7, CDISASM_ARM_ALIASGEN_FUNCTION_IN_IT_BLOCK = 8, CDISASM_ARM_ALIASGEN_FUNCTION_BFX_PREFERRED = 9, CDISASM_ARM_ALIASGEN_FUNCTION_MOVE_WIDE_PREFERRED = 10, CDISASM_ARM_ALIASGEN_FUNCTION_SVE_MOVE_MASK_PREFERRED = 11, CDISASM_ARM_ALIASGEN_FUNCTION_A32_ENCODING_EXISTS = 12, CDISASM_ARM_ALIASGEN_FUNCTION_T32_ENCODING_EXISTS = 13, CDISASM_ARM_ALIASGEN_FUNCTION_SYS_OP = 14, CDISASM_ARM_ALIASGEN_FUNCTION_SYSL_OP = 15, CDISASM_ARM_ALIASGEN_FUNCTION_SYS_OP128 = 16 };",
        "typedef struct cdisasm_arm_aliasgen_span { uint32_t first; uint16_t count, reserved; } cdisasm_arm_aliasgen_span;",
        "typedef struct cdisasm_arm_aliasgen_bc { int32_t a, b; uint8_t opcode, reserved[3]; } cdisasm_arm_aliasgen_bc;",
        "typedef struct cdisasm_arm_aliasgen_value { uint64_t mask, value; uint8_t width, reserved[7]; } cdisasm_arm_aliasgen_value;",
        "typedef struct cdisasm_arm_aliasgen_system_operation { uint32_t key, condition_program_id; uint8_t result, reserved[3]; } cdisasm_arm_aliasgen_system_operation;",
        "#define CDISASM_ARM_ALIASGEN_FLAG_IN_IT_BLOCK UINT8_C(1)",
        "#define CDISASM_ARM_ALIASGEN_FLAG_SETS_FLAGS UINT8_C(2)",
        "typedef struct cdisasm_arm_aliasgen_alias { uint32_t leaf_index, condition_program_id, preferred_program_id; uint16_t canonical_name_id, public_name_id; uint8_t flags, reserved[3]; } cdisasm_arm_aliasgen_alias;",
        "",
    ]
    emit_array(
        lines,
        f"static const cdisasm_arm_aliasgen_span cdisasm_arm_aliasgen_programs[{len(program_records)}]",
        ["{" + c_u32(first) + ", " + c_u16(count) + ", " + c_u16(0) + "}" for first, count in program_records],
    )
    emit_array(
        lines,
        f"static const cdisasm_arm_aliasgen_bc cdisasm_arm_aliasgen_bytecode[{len(bytecode)}]",
        ["{" + f"INT32_C({a}), INT32_C({b}), " + c_u8(opcode) + ", {0, 0, 0}}" for opcode, a, b in bytecode],
    )
    emit_array(
        lines,
        f"static const cdisasm_arm_aliasgen_value cdisasm_arm_aliasgen_values[{len(values)}]",
        ["{" + f"UINT64_C({mask}), UINT64_C({value}), " + c_u8(width) + ", {0, 0, 0, 0, 0, 0, 0}}" for mask, value, width in values],
    )
    emit_array(
        lines,
        f"static const uint16_t cdisasm_arm_aliasgen_feature_capability_ids[{len(feature_names)}]",
        [c_u16(capability_id(name, index)) for index, name in enumerate(feature_names)],
    )
    emit_array(
        lines,
        f"static const uint8_t cdisasm_arm_aliasgen_function_kinds[{len(function_names)}]",
        [c_u8(SUPPORTED_FUNCTION_KINDS.get(name, 0)) for name in function_names],
    )
    emit_array(
        lines,
        f"static const uint8_t cdisasm_arm_aliasgen_symbol_values[{len(symbol_names)}]",
        [c_u8(SUPPORTED_SYMBOL_VALUES.get(name, 0)) for name in symbol_names],
    )
    emit_array(
        lines,
        f"static const cdisasm_arm_aliasgen_system_operation cdisasm_arm_aliasgen_system_operations[{len(system_operations)}]",
        [
            "{" + c_u32(record["key"]) + ", "
                + c_u32(record["condition_program_id"]) + ", "
                + c_u8(record["result"]) + ", {0, 0, 0}}"
            for record in system_operations
        ],
    )
    emit_array(
        lines,
        f"static const cdisasm_arm_aliasgen_alias cdisasm_arm_aliasgen_aliases[{len(aliases)}]",
        [
            "{" + ", ".join([
                c_u32(record["leaf_index"]),
                c_u32(record["condition_program_id"]),
                c_u32(record["preferred_program_id"]),
                c_u16(record["canonical_name_id"]),
                c_u16(record["public_name_id"]),
                c_u8(
                    (1 if record["depends_on_it_block"] else 0)
                    | (2 if record["sets_flags"] else 0)
                ),
            ]) + ", {0, 0, 0}}"
            for record in aliases
        ],
    )
    lines.extend(["#endif", "#endif", ""])
    return "\n".join(lines).encode("ascii")


def write_or_check(path: Path, data: bytes, check: bool) -> None:
    if check:
        if not path.is_file() or path.read_bytes() != data:
            raise AliasGenerationError(f"generated file is stale: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def render_tsv(rows: list[dict[str, Any]], fields: list[str]) -> bytes:
    from io import StringIO

    stream = StringIO(newline="")
    writer = csv.DictWriter(
        stream, fieldnames=fields, dialect="excel-tab", lineterminator="\n"
    )
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arm-root", required=True, type=Path)
    parser.add_argument("--check", action="store_true")
    parser.add_argument(
        "--decode-output", type=Path,
        default=REPO_ROOT / "src/arm/generated/cdisasm_arm_alias_decode.inc",
    )
    parser.add_argument(
        "--status-output", type=Path,
        default=SCRIPT_DIR / "generated/arm_alias_selection.tsv",
    )
    parser.add_argument(
        "--manifest-output", type=Path,
        default=SCRIPT_DIR / "generated/arm_alias_selection_manifest.json",
    )
    arguments = parser.parse_args()

    document, source_path = assembly.load_source(arguments.arm_root.resolve())
    nodes, leaves, tree_aliases, _roots = tree.make_tree(document)
    leaf_sources, alias_sources = assembly.collect_sources(document)
    if len(tree_aliases) != 611 or len(alias_sources) != len(tree_aliases):
        raise AliasGenerationError("pinned alias ordering/count changed")

    inventory = tree.ast_inventory(nodes, tree_aliases)
    pools = {
        "features": sorted(inventory["feature_counts"]),
        "symbols": sorted(inventory["symbol_counts"]),
        "values": sorted(inventory["value_counts"]),
        "functions": sorted(inventory["function_counts"]),
    }
    pools = assembly.extend_ast_pools(
        pools,
        [
            *(source.get("condition") for source in alias_sources),
            *(source.get("preferred") for source in alias_sources),
            *(
                document["assembly_rules"][
                    choice["symbols"][0]["rule_id"]
                ].get("condition")
                for option_rule in SYSTEM_OPTION_SPECS
                for choice in document["assembly_rules"][option_rule]["choices"]
            ),
        ],
    )
    pool_ids = {
        category: {name: index for index, name in enumerate(names)}
        for category, names in pools.items()
    }
    public_ids = assembly.load_public_name_ids(
        SCRIPT_DIR / "generated/arm_mnemonic_ids.tsv"
    )

    records: list[dict[str, Any]] = []
    status_rows: list[dict[str, Any]] = []
    supported_programs: list[tuple[tuple[int, int, int], ...]] = []
    unresolved_reasons: dict[str, int] = {}
    for alias_index, (alias, source) in enumerate(zip(tree_aliases, alias_sources)):
        node = nodes[leaves[alias["leaf_index"]]["node_index"]]
        condition = tree.compile_ast(
            source.get("condition"), node["bindings"], **pool_ids
        )
        preferred = tree.compile_ast(
            source.get("preferred"), node["bindings"], **pool_ids
        )
        if condition is None or preferred is None:
            raise AliasGenerationError(f"alias {alias_index} has an empty predicate")
        condition_reason = program_reason(
            condition, pools["functions"], pools["symbols"]
        )
        preferred_reason = program_reason(
            preferred, pools["functions"], pools["symbols"]
        )
        if not condition_reason:
            supported_programs.append(condition)
        else:
            unresolved_reasons[condition_reason] = (
                unresolved_reasons.get(condition_reason, 0) + 1
            )
        if not preferred_reason:
            supported_programs.append(preferred)
        else:
            unresolved_reasons[preferred_reason] = (
                unresolved_reasons.get(preferred_reason, 0) + 1
            )
        mnemonic = tree.first_literal(source).lower()
        canonical_mnemonic = tree.first_literal(
            leaf_sources[alias["leaf_index"]]
        ).lower()
        record = {
            "alias_index": alias_index,
            "leaf_index": alias["leaf_index"],
            "form_id": alias["leaf_index"] + 1,
            "public_name_id": public_ids[mnemonic],
            "canonical_name_id": public_ids[canonical_mnemonic],
            "mnemonic": mnemonic,
            "source_form_id": alias["source_form_id"],
            "condition": condition,
            "preferred": preferred,
            "condition_reason": condition_reason,
            "preferred_reason": preferred_reason,
            "depends_on_it_block": program_calls_function(
                condition, pools["functions"], "InITBlock"
            ) or program_calls_function(
                preferred, pools["functions"], "InITBlock"
            ),
            "sets_flags": mnemonic in FLAG_SETTING_ALIAS_MNEMONICS,
            "selectable": not condition_reason and not preferred_reason,
        }
        records.append(record)
        status_rows.append({
            "alias_index": alias_index,
            "form_id": record["form_id"],
            "mnemonic": mnemonic,
            "source_form_id": alias["source_form_id"],
            "selectable": int(record["selectable"]),
            "condition_status": condition_reason or "exact",
            "preferred_status": preferred_reason or "exact",
            "depends_on_it_block": int(record["depends_on_it_block"]),
        })

    system_operations = collect_system_operations(document, pool_ids)
    supported_programs.extend(
        record["condition"] for record in system_operations
    )
    program_ids, program_records, bytecode = assembly.finish_programs(
        supported_programs
    )
    for record in records:
        record["condition_program_id"] = (
            NONE if record["condition_reason"]
            else program_ids[record["condition"]]
        )
        record["preferred_program_id"] = (
            NONE if record["preferred_reason"]
            else program_ids[record["preferred"]]
        )
    for record in system_operations:
        record["condition_program_id"] = program_ids[record["condition"]]
    decode = render_include(
        records, program_records, bytecode,
        pools["features"], pools["functions"], pools["symbols"],
        pools["values"], system_operations,
    )
    status = render_tsv(
        status_rows,
        [
            "alias_index", "form_id", "mnemonic", "source_form_id",
            "selectable", "condition_status", "preferred_status",
            "depends_on_it_block",
        ],
    )
    manifest = {
        "schema_version": 1,
        "source": {
            "commit": assembly.PINNED_COMMIT,
            "instructions_sha256": assembly.PINNED_INSTRUCTIONS_SHA256,
            "path": source_path.name,
        },
        "counts": {
            "aliases": len(records),
            "fully_selectable_aliases": sum(r["selectable"] for r in records),
            "unresolved_aliases": sum(not r["selectable"] for r in records),
            "numeric_programs": len(program_records),
            "numeric_bytecode_instructions": len(bytecode),
            "system_operation_encodings": len(system_operations),
            "unresolved_predicates_by_reason": dict(sorted(unresolved_reasons.items())),
        },
        "policy": {
            "selection": "Change name_id only for one uniquely true condition+preferred alias and only when no potentially competing predicate is unresolved.",
            "runtime_context": "All predicate and preferred-form helpers used by the pinned source are evaluated from numeric decode fields and capability bits; InITBlock is supplied explicitly through the T32 decode option.",
            "strings_in_decoder_table": False,
        },
        "outputs": {
            arguments.decode_output.relative_to(REPO_ROOT).as_posix(): {
                "sha256": sha256_bytes(decode)
            },
            arguments.status_output.relative_to(REPO_ROOT).as_posix(): {
                "sha256": sha256_bytes(status)
            },
        },
    }
    manifest_data = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    write_or_check(arguments.decode_output, decode, arguments.check)
    write_or_check(arguments.status_output, status, arguments.check)
    write_or_check(arguments.manifest_output, manifest_data, arguments.check)
    action = "verified" if arguments.check else "generated"
    print(
        f"{action} ARM alias selector: {manifest['counts']['fully_selectable_aliases']} "
        f"selectable, {manifest['counts']['unresolved_aliases']} unresolved"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
