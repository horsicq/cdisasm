#!/usr/bin/env python3
"""Generate exact mixed ARM register/immediate operand descriptors.

The pinned open AARCHMRS catalogue is the authority for canonical operand
order, encoded fields, and relative-branch layouts.  A pinned BSD-licensed
Capstone checkout is used offline to prove the semantic value and access mode
of a conservative set of non-relative immediates.  Capstone is never linked
to cdisasm and no text is emitted into the runtime table.

Relative branches are compiled directly from the public architecture grammar
and the target kinds shared with ``generate_arm_leaf_semantics.py``.  Runtime
lowering independently calculates the signed displacement and accepts it only
when the resolved target equals the target already calculated by the generated
control table.  Unsupported, nonlinear, alias-dependent, or incompletely
described forms remain operands-opaque.
"""

from __future__ import annotations

import argparse
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Iterable


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
sys.path.insert(0, str(SCRIPT_DIR))
import generate_arm_assembly_catalog as arm_assembly  # noqa: E402
import generate_arm_leaf_semantics as leaf_semantics  # noqa: E402
import generate_arm_open_operand_catalog as base  # noqa: E402
import generate_arm_tree as arm_tree  # noqa: E402


SCHEMA_VERSION = 2
ORACLE_FIELDS = [
    "form_id",
    "source_form_id",
    "mnemonic",
    "isa",
    "width",
    "authority",
    "witnesses",
    "operand_semantics",
    "capstone_real_name",
    "capstone_groups",
]

KIND_REGISTER = 1
KIND_IMMEDIATE = 2
KIND_RELATIVE = 3
KIND_DYNAMIC_GPR = 4
KIND_MEMORY = 5
KIND_SCALABLE_REGISTER = 6
KIND_PREDICATE = 7

TRANSFORM_SIGNED = 1
TRANSFORM_SECOND_HIGH = 2

REG_CLASS = {**base.REG_CLASS, "WX": 7, "Z": 8, "P": 9}
REG_SIZE = {**base.REG_SIZE, "WX": 0, "Z": 0, "P": 0}
SPECIAL31 = {**base.SPECIAL31, "W_OR_X_ZR": 6}

PREDICATE_QUALIFIER = {"": 0, "/M": 1, "/Z": 2, "TYPED": 16}
ELEMENT_EXPONENT = {".B": 0, ".H": 1, ".S": 2, ".D": 3}

UINT32_MASK = (1 << 32) - 1
UINT64_MASK = (1 << 64) - 1


class ImmediateCatalogError(RuntimeError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def sign_extend(value: int, width: int) -> int:
    sign = 1 << (width - 1)
    value &= (1 << width) - 1
    return (value ^ sign) - sign


def extract(word: int, start: int, width: int) -> int:
    return (word >> start) & ((1 << width) - 1)


def set_field(node: dict[str, Any], word: int, field: str, desired: int) -> int:
    start, width = node["bindings"][field]
    value = base.choose_field_value(
        desired,
        start,
        width,
        int(node["resolved_mask_int"]),
        int(node["resolved_value_int"]),
    )
    mask = ((1 << width) - 1) << start
    return (word & ~mask) | ((value << start) & mask)


def normalized_operands(
    analyzer: base.GrammarAnalyzer,
    source: dict[str, Any],
    node: dict[str, Any],
) -> list[dict[str, Any]] | None:
    operands = analyzer.flat_operands(source)
    if operands is None:
        return None
    result: list[dict[str, Any]] = []
    for original in operands:
        operand = dict(original)
        if operand["kind"] == "immediate":
            operand["field"] = base.identifier_expression(
                operand.pop("expression", None)
            )
        field = operand.get("field")
        if not field or field not in node["bindings"]:
            return None
        result.append(operand)
    return result


def register_semantic(
    node: dict[str, Any],
    reg_class: str,
    field: str,
    special31: str = "",
    access: int = base.ACCESS["READ"],
) -> dict[str, int]:
    start, width = node["bindings"][field]
    return {
        "kind": KIND_REGISTER,
        "bit_start": start,
        "bit_width": width,
        "second_start": 0,
        "second_width": 0,
        "reg_class": REG_CLASS[reg_class],
        "access": access,
        "size": REG_SIZE[reg_class],
        "special31": SPECIAL31[special31],
        "transform": 0,
        "multiplier": 0,
        "addend": 0,
    }


def immediate_semantic(
    node: dict[str, Any],
    field: str,
    size: int,
    *,
    signed: bool = False,
    multiplier: int = 1,
    addend: int = 0,
    second_field: str | None = None,
) -> dict[str, int]:
    start, width = node["bindings"][field]
    second_start = 0
    second_width = 0
    transform = TRANSFORM_SIGNED if signed else 0
    if second_field is not None:
        second_start, second_width = node["bindings"][second_field]
        transform |= TRANSFORM_SECOND_HIGH
    return {
        "kind": KIND_IMMEDIATE,
        "bit_start": start,
        "bit_width": width,
        "second_start": second_start,
        "second_width": second_width,
        "reg_class": 0,
        "access": base.ACCESS["READ"],
        "size": size,
        "special31": 0,
        "transform": transform,
        "multiplier": multiplier,
        "addend": addend,
    }


def relative_semantic(target_kind: int, size: int) -> dict[str, int]:
    return {
        "kind": KIND_RELATIVE,
        "bit_start": 0,
        "bit_width": 0,
        "second_start": 0,
        "second_width": 0,
        "reg_class": 0,
        "access": base.ACCESS["READ"],
        "size": size,
        "special31": 0,
        "transform": target_kind,
        "multiplier": 0,
        "addend": 0,
    }


def dynamic_gpr_semantic(
    node: dict[str, Any], field: str, selector_field: str
) -> dict[str, int]:
    start, width = node["bindings"][field]
    selector_start, selector_width = node["bindings"][selector_field]
    if selector_width != 1:
        raise ImmediateCatalogError("dynamic GPR selector must be one bit")
    return {
        "kind": KIND_DYNAMIC_GPR,
        "bit_start": start,
        "bit_width": width,
        "second_start": selector_start,
        "second_width": 1,
        "reg_class": REG_CLASS["WX"],
        "access": base.ACCESS["READ"],
        "size": 0,
        "special31": SPECIAL31["W_OR_X_ZR"],
        "transform": 0,
        "multiplier": 0,
        "addend": 0,
    }


def memory_semantic(
    node: dict[str, Any],
    base_field: str,
    displacement_field: str,
    size: int,
    access: int,
) -> dict[str, int]:
    base_start, base_width = node["bindings"][base_field]
    displacement_start, displacement_width = node["bindings"][displacement_field]
    return {
        "kind": KIND_MEMORY,
        "bit_start": base_start,
        "bit_width": base_width,
        "second_start": displacement_start,
        "second_width": displacement_width,
        "reg_class": REG_CLASS["X"],
        "access": access,
        "size": size,
        "special31": SPECIAL31["SP"],
        "transform": 0,
        "multiplier": 1,
        "addend": 0,
    }


def scalable_register_semantic(
    node: dict[str, Any],
    reg_class: str,
    field: str,
    element: tuple[int, int, int],
    qualifier: int,
) -> dict[str, int]:
    start, width = node["bindings"][field]
    element_start, element_width, exponent_addend = element
    return {
        "kind": (
            KIND_SCALABLE_REGISTER if reg_class == "Z" else KIND_PREDICATE
        ),
        "bit_start": start,
        "bit_width": width,
        "second_start": element_start,
        "second_width": element_width,
        "reg_class": REG_CLASS[reg_class],
        "access": base.ACCESS["READ"],
        "size": 0,
        "special31": 0,
        "transform": qualifier,
        "multiplier": 1 if element_width != 0 else 0,
        "addend": exponent_addend,
    }


def scalable_register_semantics(
    candidate: dict[str, Any]
) -> list[dict[str, int]] | None:
    """Recognize a closed SVE grammar made only of Z/P register operands."""
    path = candidate["source_form_id"].lower()
    mnemonic = candidate["mnemonic"].upper()
    template = candidate["assembly_template"]
    prefix = f"{candidate['mnemonic']}<rule:SPACE>"
    if (
        candidate["isa"] != "A64"
        or "/sve/" not in path
        or "/sve_int" not in path
        or mnemonic.startswith(("F", "BF"))
        or not template.startswith(prefix)
    ):
        return None
    parts = template[len(prefix):].split("<rule:COMMA>")
    if not 1 <= len(parts) <= 4:
        return None

    parsed: list[tuple[str, str, str]] = []
    typed_elements: list[tuple[int, int, int]] = []
    for part in parts:
        match = re.fullmatch(r"<rule:([ZP][A-Za-z0-9_]+)>(.*)", part)
        if match is None:
            return None
        rule_name, suffix = match.groups()
        field = re.sub(r"__[0-9]+$", "", rule_name)
        reg_class = rule_name[0]
        if field not in candidate["node"]["bindings"]:
            return None
        _start, width = candidate["node"]["bindings"][field]
        if (reg_class == "Z" and width != 5) or (
            reg_class == "P" and width not in {3, 4}
        ):
            return None

        if suffix in ELEMENT_EXPONENT:
            element = (0, 0, ELEMENT_EXPONENT[suffix])
            qualifier = (
                PREDICATE_QUALIFIER["TYPED"] if reg_class == "P" else 0
            )
            typed_elements.append(element)
        elif re.fullmatch(r"\.<rule:T(?:__[0-9]+)?>", suffix):
            if candidate["node"]["bindings"].get("size", (0, 0))[1] != 2:
                return None
            element_start, element_width = candidate["node"]["bindings"]["size"]
            element = (element_start, element_width, 0)
            qualifier = (
                PREDICATE_QUALIFIER["TYPED"] if reg_class == "P" else 0
            )
            typed_elements.append(element)
        elif reg_class == "P" and suffix in {"", "/M", "/Z"}:
            element = (-1, -1, -1)
            qualifier = PREDICATE_QUALIFIER[suffix]
        else:
            return None
        parsed.append((reg_class, field, suffix))

    if not typed_elements:
        return None
    common_element = typed_elements[0]
    semantics: list[dict[str, int]] = []
    for reg_class, field, suffix in parsed:
        if suffix in ELEMENT_EXPONENT:
            element = (0, 0, ELEMENT_EXPONENT[suffix])
            qualifier = (
                PREDICATE_QUALIFIER["TYPED"] if reg_class == "P" else 0
            )
        elif suffix.startswith(".<rule:T"):
            start, width = candidate["node"]["bindings"]["size"]
            element = (start, width, 0)
            qualifier = (
                PREDICATE_QUALIFIER["TYPED"] if reg_class == "P" else 0
            )
        else:
            element = common_element
            qualifier = PREDICATE_QUALIFIER[suffix]
        semantics.append(
            scalable_register_semantic(
                candidate["node"], reg_class, field, element, qualifier
            )
        )
    return semantics


def branch_operands(
    candidate: dict[str, Any], target_kind: int
) -> list[dict[str, int]]:
    node = candidate["node"]
    path = candidate["source_form_id"].lower()
    isa = candidate["isa"]
    target_size = 4 if isa == "T32" else 8
    operands: list[dict[str, int]] = []

    if target_kind == leaf_semantics.TARGET_T16_CB:
        operands.append(register_semantic(node, "R", "Rn"))
    elif target_kind == leaf_semantics.TARGET_A64_COMPARE19:
        reg_class = "W" if "_32_" in path else "X"
        operands.append(
            register_semantic(node, reg_class, "Rt", f"{reg_class}ZR")
        )
    elif target_kind == leaf_semantics.TARGET_A64_COMPARE9:
        if "/compbranch_regs2/" in path:
            operands.extend(
                [
                    register_semantic(node, "W", "Rt", "WZR"),
                    register_semantic(node, "W", "Rm", "WZR"),
                ]
            )
        elif "/compbranch_regs/" in path:
            reg_class = "W" if "_32_" in path else "X"
            operands.extend(
                [
                    register_semantic(node, reg_class, "Rt", f"{reg_class}ZR"),
                    register_semantic(node, reg_class, "Rm", f"{reg_class}ZR"),
                ]
            )
        elif "/compbranch_imm/" in path:
            reg_class = "W" if "_32_" in path else "X"
            operands.append(
                register_semantic(node, reg_class, "Rt", f"{reg_class}ZR")
            )
            operands.append(
                immediate_semantic(
                    node, "imm6", REG_SIZE[reg_class], signed=False
                )
            )
        else:
            raise ImmediateCatalogError(
                f"unrecognized compare-branch form {candidate['form_id']}"
            )
    elif target_kind == leaf_semantics.TARGET_A64_TEST14:
        operands.append(dynamic_gpr_semantic(node, "Rt", "b5"))
        operands.append(
            immediate_semantic(
                node, "b40", 1, second_field="b5"
            )
        )
    operands.append(relative_semantic(target_kind, target_size))
    if not 1 <= len(operands) <= 4:
        raise ImmediateCatalogError(
            f"branch form {candidate['form_id']} exceeds public operand capacity"
        )
    return operands


def immediate_sizes(candidate: dict[str, Any]) -> list[int] | None:
    """Return exact public sizes for a deliberately closed form subset."""
    path = candidate["source_form_id"].lower()
    mnemonic = candidate["mnemonic"].upper()
    operands = candidate["grammar_operands"]
    immediate_operands = [item for item in operands if item["kind"] == "immediate"]
    if not immediate_operands:
        return None

    if len(operands) == 1 and mnemonic in {
        "SMC", "SVC", "HVC", "BRK", "BKPT", "HLT", "UDF", "DBG",
        "CPS", "SETPAN",
    }:
        return [
            max(1, (candidate["node"]["bindings"][item["field"]][1] + 7) // 8)
            for item in immediate_operands
        ]
    if "/addsub16_" in path:
        return [4 for _ in immediate_operands]
    if "/sat16/" in path or "/sat_bit/" in path:
        return [1 for _ in immediate_operands]
    if "/dpimm/extract/" in path or "/dpimm/bitfield/" in path:
        return [1 for _ in immediate_operands]
    if "/dpimm/minmax_imm/" in path:
        register_sizes = [
            REG_SIZE[item["class"]]
            for item in operands if item["kind"] == "register"
        ]
        return [max(register_sizes) for _ in immediate_operands]
    if "/dpimm/addsub_immtags/" in path:
        return [2, 1] if len(immediate_operands) == 2 else None
    if "/dpreg/rmif/" in path:
        return [1 for _ in immediate_operands]
    if "/simd_dp/float2fix/" in path:
        return [1 for _ in immediate_operands]
    if "/sve_alloca/" in path:
        return [1 for _ in immediate_operands]
    return None


def scalar_fp(candidate: dict[str, Any]) -> bool:
    path = candidate["source_form_id"].lower()
    return "/simd_dp/float2fix/" in path


def memory_data_size(mnemonic: str, register_size: int) -> int:
    name = mnemonic.upper()
    if name in {"LDRAA", "LDRAB"}:
        # The final A/B selects the pointer-authentication key, not a byte
        # transfer.  Both forms load one 64-bit pointer.
        return 8
    if name.endswith("SW"):
        return 4
    if name.endswith("SB") or name.endswith("B"):
        return 1
    if name.endswith("SH") or name.endswith("H"):
        return 2
    return register_size


def a64_scalar_memory_semantics(
    candidate: dict[str, Any]
) -> tuple[list[dict[str, int]], str] | None:
    path = candidate["source_form_id"].lower()
    node = candidate["node"]
    mnemonic = candidate["mnemonic"].upper()
    supported_families = {
        "ldst_unscaled",
        "ldst_immpost",
        "ldst_immpre",
        "ldst_unpriv",
        "ldst_pos",
        "ldapstl_unscaled",
    }
    components = set(path.split("/"))
    if (
        candidate["isa"] != "A64"
        or not components.intersection(supported_families)
        or not mnemonic.startswith(("LD", "ST"))
        or "Rn" not in node["bindings"]
        or "Rt" not in node["bindings"]
        or "Rt2" in node["bindings"]
        or "Rm" in node["bindings"]
    ):
        return None
    immediate_fields = [
        field for field in ("imm9", "imm12") if field in node["bindings"]
    ]
    if len(immediate_fields) != 1:
        return None
    if "_32_" in path:
        reg_class = "W"
    elif "_64_" in path or "_64w_" in path:
        reg_class = "X"
    else:
        # B/H/S/D/Q suffixes in these encoding classes select SIMD/FP state;
        # those need a vector-layout descriptor and are intentionally separate.
        return None
    data_size = memory_data_size(mnemonic, REG_SIZE[reg_class])
    register_access = (
        base.ACCESS["READ"] if mnemonic.startswith("ST")
        else base.ACCESS["WRITE"]
    )
    memory_access = (
        base.ACCESS["WRITE"] if mnemonic.startswith("ST")
        else base.ACCESS["READ"]
    )
    semantics = [
        register_semantic(
            node, reg_class, "Rt", f"{reg_class}ZR", register_access
        ),
        memory_semantic(
            node, "Rn", immediate_fields[0], data_size, memory_access
        ),
    ]
    return semantics, immediate_fields[0]


def collect_candidates(
    document: dict[str, Any], leaf_rows: list[dict[str, str]]
) -> list[dict[str, Any]]:
    nodes, leaves, _aliases, _roots = arm_tree.make_tree(document)
    leaf_sources, _alias_sources = arm_assembly.collect_sources(document)
    analyzer = base.GrammarAnalyzer(document["assembly_rules"])
    if len(leaf_rows) != len(leaves):
        raise ImmediateCatalogError("leaf semantics and architecture tree drift")
    result: list[dict[str, Any]] = []

    for leaf, source, row in zip(leaves, leaf_sources, leaf_rows):
        node = nodes[leaf["node_index"]]
        candidate = {
            "form_id": leaf["form_id"],
            "source_form_id": leaf["source_form_id"],
            "mnemonic": leaf["mnemonic"],
            "assembly_template": leaf["assembly_template"],
            "isa": node["instruction_set_name"],
            "width": int(node["width"]),
            "node": node,
            "source": source,
        }
        target_kind = leaf_semantics.classify(row)[2]
        if target_kind != leaf_semantics.TARGET_NONE:
            candidate["category"] = "relative"
            candidate["target_kind"] = target_kind
            candidate["semantics"] = branch_operands(candidate, target_kind)
            result.append(candidate)
            continue

        memory = a64_scalar_memory_semantics(candidate)
        if memory is not None:
            candidate["category"] = "memory"
            candidate["semantics"], candidate["memory_field"] = memory
            result.append(candidate)
            continue

        scalable = scalable_register_semantics(candidate)
        if scalable is not None:
            candidate["category"] = "scalable"
            candidate["semantics"] = scalable
            result.append(candidate)
            continue

        operands = normalized_operands(analyzer, source, node)
        if operands is None or not any(
            item["kind"] == "immediate" for item in operands
        ):
            continue
        allowed = {"W", "X", "H", "S", "D"} if candidate["isa"] == "A64" else {"R"}
        if any(
            item["kind"] == "register" and item["class"] not in allowed
            for item in operands
        ):
            continue
        candidate["grammar_operands"] = operands
        sizes = immediate_sizes(candidate)
        if sizes is None:
            continue
        size_iter = iter(sizes)
        semantics: list[dict[str, int]] = []
        for item in operands:
            if item["kind"] == "register":
                semantics.append(
                    register_semantic(
                        node, item["class"], item["field"], item["special31"]
                    )
                )
            else:
                semantics.append(
                    immediate_semantic(node, item["field"], next(size_iter))
                )
        candidate["category"] = "immediate"
        candidate["semantics"] = semantics
        result.append(candidate)
    return result


def make_word(candidate: dict[str, Any], assignments: dict[str, int]) -> int:
    node = candidate["node"]
    word = int(node["resolved_value_int"])
    for field, desired in assignments.items():
        word = set_field(node, word, field, desired)
    return word & ((1 << candidate["width"]) - 1)


def register_assignments(candidate: dict[str, Any], seed: int) -> dict[str, int]:
    result: dict[str, int] = {}
    next_value = seed
    for operand in candidate.get("grammar_operands", []):
        if operand["kind"] == "register" and operand["field"] not in result:
            _start, width = candidate["node"]["bindings"][operand["field"]]
            result[operand["field"]] = next_value % min(31, 1 << width)
            next_value += 5
    return result


def possible_binding_bounds(
    candidate: dict[str, Any], field: str
) -> tuple[int, int]:
    """Return encoding bounds, including closed architectural constraints.

    AARCHMRS represents some UNDEFINED constraints in decode pseudocode rather
    than in the fixed mask.  Keeping the small, independently known cases here
    prevents the oracle from treating architecturally invalid endpoint words
    as missing decoder support.
    """
    start, width = candidate["node"]["bindings"][field]
    local_mask = (
        int(candidate["node"]["resolved_mask_int"]) >> start
    ) & ((1 << width) - 1)
    local_value = (
        int(candidate["node"]["resolved_value_int"]) >> start
    ) & ((1 << width) - 1)
    minimum = local_value & local_mask
    maximum = local_value | (~local_mask & ((1 << width) - 1))
    path = candidate["source_form_id"].lower()

    if "/simd_dp/float2fix/" in path and field == "scale":
        sf_start, sf_width = candidate["node"]["bindings"].get("sf", (0, 0))
        if sf_width == 1:
            sf = (int(candidate["node"]["resolved_value_int"]) >> sf_start) & 1
            if sf == 0:
                minimum = max(minimum, 1 << (width - 1))
    if "/dpimm/bitfield/" in path and "_32m_" in path \
        and field in {"immr", "imms"}:
        maximum = min(maximum, (1 << (width - 1)) - 1)
    return minimum, maximum


def immediate_witness_words(candidate: dict[str, Any]) -> list[int]:
    node = candidate["node"]
    operands = candidate["grammar_operands"]
    immediate_fields = list(dict.fromkeys(
        item["field"] for item in operands if item["kind"] == "immediate"
    ))
    base_values = register_assignments(candidate, 1)
    for field in immediate_fields:
        minimum, maximum = possible_binding_bounds(candidate, field)
        base_values[field] = min(maximum, max(minimum, 1))
    assignments: list[dict[str, int]] = [dict(base_values)]

    for seed in (2, 7, 11):
        values = dict(base_values)
        values.update(register_assignments(candidate, seed))
        assignments.append(values)
    for operand in operands:
        if operand["kind"] == "register" and operand["special31"]:
            values = dict(base_values)
            values[operand["field"]] = 31
            assignments.append(values)
    for field in immediate_fields:
        _start, width = node["bindings"][field]
        minimum, maximum = possible_binding_bounds(candidate, field)
        values_to_try = {
            minimum, min(maximum, minimum + 1),
            min(maximum, minimum + 2), min(maximum, minimum + 3),
            maximum, max(minimum, maximum - 1),
            min(maximum, max(minimum, (1 << (width - 1)) - 1)),
            min(maximum, max(minimum, 1 << (width - 1))),
        }
        for value in sorted(values_to_try):
            values = dict(base_values)
            values[field] = value
            assignments.append(values)
    if len(immediate_fields) > 1:
        for offset in (2, 3, 5):
            values = dict(base_values)
            for index, field in enumerate(immediate_fields):
                minimum, maximum = possible_binding_bounds(candidate, field)
                span = maximum - minimum + 1
                values[field] = minimum + (offset + index * 2) % span
            assignments.append(values)
    return list(dict.fromkeys(make_word(candidate, values) for values in assignments))


def branch_witness_words(candidate: dict[str, Any]) -> list[int]:
    node = candidate["node"]
    fields: dict[str, int] = {}
    for semantic in candidate["semantics"]:
        if semantic["kind"] in {KIND_REGISTER, KIND_DYNAMIC_GPR}:
            # Resolve the descriptor back to a binding solely for witnesses.
            for field, (start, width) in node["bindings"].items():
                if start == semantic["bit_start"] and width == semantic["bit_width"]:
                    fields.setdefault(field, 1 + len(fields) * 5)
                    break
        elif semantic["kind"] == KIND_IMMEDIATE:
            for field, (start, width) in node["bindings"].items():
                if start == semantic["bit_start"] and width == semantic["bit_width"]:
                    fields.setdefault(field, 1)
                    break
    words = [make_word(candidate, fields)]
    # The fixed encoding, a small forward target, and a sign-boundary pattern
    # exercise every target-kind implementation without enumerating the ISA.
    words.append(make_word(candidate, {}))
    relative_fields = {
        name: ((1 << width) - 1)
        for name, (_start, width) in node["bindings"].items()
        if name in {"imm24", "imm19", "imm14", "imm11", "imm10", "imm9", "imm8", "imm6", "imm5", "S", "J1", "J2", "i", "H"}
    }
    if relative_fields:
        values = dict(fields)
        values.update(relative_fields)
        words.append(make_word(candidate, values))
    return list(dict.fromkeys(words))


def memory_witness_words(candidate: dict[str, Any]) -> list[int]:
    node = candidate["node"]
    field = candidate["memory_field"]
    _start, width = node["bindings"][field]
    maximum = (1 << width) - 1
    base_values = {"Rt": 1, "Rn": 6, field: 1}
    assignments = [dict(base_values)]
    for rt, rn in ((2, 7), (11, 16), (30, 29), (31, 6), (1, 31)):
        values = dict(base_values)
        values.update({"Rt": rt, "Rn": rn})
        assignments.append(values)
    for value in sorted({
        0, 1, 2, 3, maximum, max(0, maximum - 1),
        (1 << (width - 1)) - 1, 1 << (width - 1),
    }):
        values = dict(base_values)
        values[field] = value
        assignments.append(values)
    return list(dict.fromkeys(make_word(candidate, values) for values in assignments))


def scalable_witness_words(candidate: dict[str, Any]) -> list[int]:
    node = candidate["node"]
    register_fields: list[str] = []
    for semantic in candidate["semantics"]:
        for field, (start, width) in node["bindings"].items():
            if (
                start == semantic["bit_start"]
                and width == semantic["bit_width"]
                and field not in register_fields
            ):
                register_fields.append(field)
                break
    base_values = {
        field: (1 + index * 5) & ((1 << node["bindings"][field][1]) - 1)
        for index, field in enumerate(register_fields)
    }
    assignments = [dict(base_values)]
    for seed in (2, 7, 11):
        values = dict(base_values)
        for index, field in enumerate(register_fields):
            width = node["bindings"][field][1]
            values[field] = (seed + index * 5) & ((1 << width) - 1)
        assignments.append(values)
    for field in register_fields:
        start, width = node["bindings"][field]
        local_mask = (int(node["resolved_mask_int"]) >> start) & ((1 << width) - 1)
        local_value = (int(node["resolved_value_int"]) >> start) & ((1 << width) - 1)
        for value in (
            local_value & local_mask,
            local_value | (~local_mask & ((1 << width) - 1)),
        ):
            values = dict(base_values)
            values[field] = value
            assignments.append(values)
    element_fields = {
        "size"
        for semantic in candidate["semantics"]
        if semantic["second_width"] != 0
    }
    for field in element_fields:
        start, width = node["bindings"][field]
        local_mask = (int(node["resolved_mask_int"]) >> start) & ((1 << width) - 1)
        local_value = (int(node["resolved_value_int"]) >> start) & ((1 << width) - 1)
        for value in range(1 << width):
            if value & local_mask != local_value & local_mask:
                continue
            values = dict(base_values)
            values[field] = value
            assignments.append(values)
    return list(dict.fromkeys(make_word(candidate, values) for values in assignments))


def parse_capstone_immediate(text: str) -> int | None:
    token = text.strip().split()[0].rstrip(",") if text.strip() else ""
    try:
        value = int(token, 0)
    except ValueError:
        return None
    if value > (1 << 63) - 1 and value <= UINT64_MASK:
        value -= 1 << 64
    return value


def expected_register_from_semantic(
    semantic: dict[str, int], word: int
) -> str | None:
    encoded = extract(word, semantic["bit_start"], semantic["bit_width"])
    if semantic["kind"] == KIND_DYNAMIC_GPR:
        is_x = extract(word, semantic["second_start"], 1) != 0
        return ("xzr" if is_x else "wzr") if encoded == 31 else f"{'x' if is_x else 'w'}{encoded}"
    reg_class = next(
        (name for name, value in REG_CLASS.items() if value == semantic["reg_class"]),
        None,
    )
    special = next(
        (name for name, value in SPECIAL31.items() if value == semantic["special31"]),
        "",
    )
    if encoded == (1 << semantic["bit_width"]) - 1 and special:
        return special.lower()
    if reg_class == "R":
        return {13: "sp", 14: "lr", 15: "pc"}.get(encoded, f"r{encoded}")
    return f"{str(reg_class).lower()}{encoded}" if reg_class else None


def raw_immediate(semantic: dict[str, int], word: int) -> int:
    value = extract(word, semantic["bit_start"], semantic["bit_width"])
    width = semantic["bit_width"]
    if semantic["transform"] & TRANSFORM_SECOND_HIGH:
        value |= extract(
            word, semantic["second_start"], semantic["second_width"]
        ) << width
        width += semantic["second_width"]
    if semantic["transform"] & TRANSFORM_SIGNED:
        return sign_extend(value, width)
    return value


def relative_value(candidate: dict[str, Any], word: int) -> tuple[int, int]:
    kind = candidate["target_kind"]
    isa = candidate["isa"]
    if isa == "T32" and candidate["width"] == 32:
        first = (word >> 16) & 0xFFFF
        second = word & 0xFFFF
    else:
        first = word & 0xFFFF
        second = (word >> 16) & 0xFFFF
    base_address = 0
    displacement = 0
    if kind == leaf_semantics.TARGET_A32_BRANCH24:
        displacement = sign_extend((word & 0x00FFFFFF) << 2, 26)
        base_address = 8
    elif kind == leaf_semantics.TARGET_A32_BLX24:
        encoded = ((word & 0x00FFFFFF) << 2) | ((word >> 23) & 2)
        displacement = sign_extend(encoded, 26)
        base_address = 8
    elif kind == leaf_semantics.TARGET_T16_CB:
        displacement = ((first & 0x0200) >> 3) | ((first & 0x00F8) >> 2)
        base_address = 4
    elif kind == leaf_semantics.TARGET_T16_COND8:
        displacement = sign_extend((first & 0x00FF) << 1, 9)
        base_address = 4
    elif kind == leaf_semantics.TARGET_T16_BRANCH11:
        displacement = sign_extend((first & 0x07FF) << 1, 12)
        base_address = 4
    elif kind == leaf_semantics.TARGET_T32_COND:
        encoded = (
            ((first >> 10) & 1) << 20
            | ((second >> 11) & 1) << 19
            | ((second >> 13) & 1) << 18
            | (first & 0x003F) << 12
            | (second & 0x07FF) << 1
        )
        displacement = sign_extend(encoded, 21)
        base_address = 4
    elif kind in {leaf_semantics.TARGET_T32_BRANCH, leaf_semantics.TARGET_T32_BL, leaf_semantics.TARGET_T32_BLX}:
        sign = (first >> 10) & 1
        i1 = (((second >> 13) & 1) ^ sign) ^ 1
        i2 = (((second >> 11) & 1) ^ sign) ^ 1
        low = second & (0x07FE if kind == leaf_semantics.TARGET_T32_BLX else 0x07FF)
        encoded = sign << 24 | i1 << 23 | i2 << 22 | (first & 0x03FF) << 12 | low << 1
        displacement = sign_extend(encoded, 25)
        base_address = 4
    elif kind in {leaf_semantics.TARGET_A64_COND19, leaf_semantics.TARGET_A64_COMPARE19}:
        displacement = sign_extend(((word >> 5) & 0x7FFFF) << 2, 21)
    elif kind == leaf_semantics.TARGET_A64_BRANCH26:
        displacement = sign_extend((word & 0x03FFFFFF) << 2, 28)
    elif kind == leaf_semantics.TARGET_A64_TEST14:
        displacement = sign_extend(((word >> 5) & 0x3FFF) << 2, 16)
    elif kind == leaf_semantics.TARGET_A64_COMPARE9:
        displacement = sign_extend(((word >> 5) & 0x1FF) << 2, 11)
    else:
        raise ImmediateCatalogError(f"unknown target kind {kind}")
    return displacement, (base_address + displacement) & UINT64_MASK


def capstone_observation_matches(
    candidate: dict[str, Any], word: int, observation: dict[str, Any] | None
) -> tuple[list[int], list[int]] | None:
    if observation is None or observation["real_name"] != candidate["mnemonic"].lower():
        return None
    semantics = candidate["semantics"]
    if len(observation["operands"]) != len(semantics):
        return None
    accesses: list[int] = []
    immediate_values: list[int] = []
    for semantic, actual in zip(semantics, observation["operands"]):
        access = base.ACCESS.get(actual["access"])
        if access is None:
            return None
        if semantic["kind"] in {KIND_REGISTER, KIND_DYNAMIC_GPR}:
            if actual["type"] != "REG":
                return None
            expected = expected_register_from_semantic(semantic, word)
            actual_name = actual["value"].split()[0].strip().lower()
            if expected is None or actual_name != expected:
                return None
        elif semantic["kind"] in {KIND_IMMEDIATE, KIND_RELATIVE}:
            if actual["type"] != "IMM":
                return None
            value = parse_capstone_immediate(actual["value"])
            if value is None:
                return None
            if semantic["kind"] == KIND_RELATIVE:
                _displacement, target = relative_value(candidate, word)
                if value & UINT64_MASK != target:
                    return None
            immediate_values.append(value)
        else:
            return None
        accesses.append(access)
    return accesses, immediate_values


def capstone_memory_matches(
    candidate: dict[str, Any], word: int, observation: dict[str, Any] | None
) -> tuple[int, int, int] | None:
    if (
        observation is None
        or observation["real_name"] != candidate["mnemonic"].lower()
        or len(observation["operands"]) != 2
    ):
        return None
    register = candidate["semantics"][0]
    memory = candidate["semantics"][1]
    actual_register, actual_memory = observation["operands"]
    if actual_register["type"] != "REG" or actual_memory["type"] != "MEM":
        return None
    expected_register = expected_register_from_semantic(register, word)
    actual_register_name = actual_register["value"].split()[0].strip().lower()
    encoded_base = extract(word, memory["bit_start"], memory["bit_width"])
    expected_base = "sp" if encoded_base == 31 else f"x{encoded_base}"
    if (
        expected_register is None
        or actual_register_name != expected_register
        or actual_memory.get("base", "") != expected_base
        or actual_memory.get("index", "") != ""
    ):
        return None
    expected_post = "/ldst_immpost/" in candidate["source_form_id"].lower()
    if bool(actual_memory.get("post_indexed")) != expected_post:
        return None
    displacement = parse_capstone_immediate(
        str(actual_memory.get("displacement", ""))
    )
    register_access = base.ACCESS.get(actual_register["access"])
    memory_access = base.ACCESS.get(actual_memory["access"])
    if displacement is None or register_access is None or memory_access is None:
        return None
    return register_access, memory_access, displacement


def capstone_scalable_matches(
    candidate: dict[str, Any], word: int, observation: dict[str, Any] | None
) -> tuple[int, ...] | None:
    if (
        observation is None
        or observation["real_name"] != candidate["mnemonic"].lower()
        or len(observation["operands"]) != len(candidate["semantics"])
    ):
        return None
    accesses: list[int] = []
    for semantic, actual in zip(candidate["semantics"], observation["operands"]):
        encoded = extract(word, semantic["bit_start"], semantic["bit_width"])
        if semantic["kind"] == KIND_SCALABLE_REGISTER:
            expected_type = "REG"
            expected_name = f"z{encoded}"
        elif semantic["kind"] == KIND_PREDICATE:
            expected_type = "PREDICATE"
            expected_name = f"p{encoded}"
        else:
            return None
        access = base.ACCESS.get(actual["access"])
        actual_name = actual["value"].split()[0].strip().lower()
        if (
            actual["type"] != expected_type
            or actual_name != expected_name
            or access is None
        ):
            return None
        accesses.append(access)
    return tuple(accesses)


def possible_field_bounds(candidate: dict[str, Any], semantic: dict[str, int]) -> tuple[int, int]:
    for field, (start, width) in candidate["node"]["bindings"].items():
        if start == semantic["bit_start"] and width == semantic["bit_width"]:
            return possible_binding_bounds(candidate, field)
    raise ImmediateCatalogError(
        f"descriptor has no source field for form {candidate['form_id']}"
    )


def fit_transform(
    candidate: dict[str, Any],
    semantic: dict[str, int],
    samples: list[tuple[int, int]],
    grammar_signed: bool,
) -> tuple[bool, int, int] | None:
    minimum, maximum = possible_field_bounds(candidate, semantic)
    observed_raw = {raw for raw, _value in samples}
    if len(observed_raw) < 3 or minimum not in observed_raw or maximum not in observed_raw:
        return None
    interpretations = [grammar_signed, not grammar_signed]
    for signed in interpretations:
        points = [
            (sign_extend(raw, semantic["bit_width"]) if signed else raw, value)
            for raw, value in samples
        ]
        if signed and maximum >= 1 << (semantic["bit_width"] - 1) and not any(x < 0 for x, _ in points):
            continue
        distinct: dict[int, int] = {}
        consistent = True
        for x, y in points:
            if x in distinct and distinct[x] != y:
                consistent = False
                break
            distinct[x] = y
        if not consistent or len(distinct) < 3:
            continue
        pairs = sorted(distinct.items())
        x0, y0 = pairs[0]
        x1, y1 = next((item for item in pairs[1:] if item[0] != x0), (x0, y0))
        delta = x1 - x0
        if delta == 0 or (y1 - y0) % delta != 0:
            continue
        multiplier = (y1 - y0) // delta
        addend = y0 - multiplier * x0
        if not -65536 <= multiplier <= 65536 or not -(1 << 31) <= addend < (1 << 31):
            continue
        if all(multiplier * x + addend == y for x, y in pairs):
            return signed, multiplier, addend
    return None


def architecture_row(
    candidate: dict[str, Any],
    words: list[int],
    semantics: list[dict[str, int]],
    cdisasm: base.CdisasmFormOracle | None,
) -> dict[str, str] | None:
    """Emit a deliberately whitelisted AARCHMRS-only exact descriptor."""
    if cdisasm is not None and any(
        cdisasm.form(word, candidate["isa"], candidate["width"])
            != candidate["form_id"]
        for word in words
    ):
        return None
    return {
        "form_id": str(candidate["form_id"]),
        "source_form_id": candidate["source_form_id"],
        "mnemonic": candidate["mnemonic"].lower(),
        "isa": candidate["isa"],
        "width": str(candidate["width"]),
        "authority": "aarchmrs",
        "witnesses": ",".join(
            f"0x{word:0{candidate['width'] // 4}x}" for word in words
        ),
        "operand_semantics": canonical_json(semantics),
        "capstone_real_name": "",
        "capstone_groups": "",
    }


def architecture_immediate_semantics(
    candidate: dict[str, Any]
) -> list[dict[str, int]] | None:
    """Return the closed AARCHMRS-only immediate whitelist semantics."""
    path = candidate["source_form_id"].lower()
    mnemonic = candidate["mnemonic"].upper()
    semantics = [dict(item) for item in candidate["semantics"]]

    if mnemonic == "SETPAN" and len(semantics) == 1:
        semantics[0]["access"] = base.ACCESS["READ"]
    elif "/dpimm/bitfield/" in path and "_32m_" in path \
        and mnemonic in {"SBFM", "BFM", "UBFM"}:
        if len(semantics) != 4:
            return None
        semantics[0]["access"] = (
            base.ACCESS["READ_WRITE"]
            if mnemonic == "BFM" else base.ACCESS["WRITE"]
        )
        for semantic in semantics[1:]:
            semantic["access"] = base.ACCESS["READ"]
    else:
        return None
    return semantics


def architecture_immediate_fallback(
    candidate: dict[str, Any],
    words: list[int],
    cdisasm: base.CdisasmFormOracle | None,
) -> dict[str, str] | None:
    """Cover small exact forms whose legal words alias or have two states."""
    semantics = architecture_immediate_semantics(candidate)
    if semantics is None:
        return None
    return architecture_row(candidate, words, semantics, cdisasm)


def architecture_memory_semantics(
    candidate: dict[str, Any]
) -> list[dict[str, int]] | None:
    """Return the closed direct-store fallback for malformed oracle detail."""
    path = candidate["source_form_id"].lower()
    mnemonic = candidate["mnemonic"].upper()
    if "/ldst/ldapstl_unscaled/" not in path \
        or mnemonic not in {"STLUR", "STLURB", "STLURH"} \
        or candidate["memory_field"] != "imm9":
        return None
    semantics = [dict(item) for item in candidate["semantics"]]
    semantics[1]["transform"] = TRANSFORM_SIGNED
    semantics[1]["multiplier"] = 1
    semantics[1]["addend"] = 0
    return semantics


def observe_immediate_candidate(
    candidate: dict[str, Any],
    capstone: base.CapstoneCstoolOracle,
    cdisasm: base.CdisasmFormOracle | None,
) -> dict[str, str] | None:
    words = immediate_witness_words(candidate)
    observations: list[tuple[int, dict[str, Any], list[int], list[int]]] = []
    for word in words:
        if cdisasm is not None and cdisasm.form(word, candidate["isa"], candidate["width"]) != candidate["form_id"]:
            continue
        observation = capstone.decode(word, candidate["isa"], candidate["width"])
        matched = capstone_observation_matches(candidate, word, observation)
        if matched is not None and observation is not None:
            observations.append((word, observation, matched[0], matched[1]))
    if len(observations) < 3:
        return architecture_immediate_fallback(candidate, words, cdisasm)

    access_tuple = tuple(observations[0][2])
    if any(tuple(item[2]) != access_tuple for item in observations[1:]):
        return None
    semantics = [dict(item) for item in candidate["semantics"]]
    immediate_index = 0
    grammar_immediates = [
        item for item in candidate["grammar_operands"] if item["kind"] == "immediate"
    ]
    for index, semantic in enumerate(semantics):
        semantic["access"] = access_tuple[index]
        if semantic["kind"] != KIND_IMMEDIATE:
            continue
        samples = [
            (
                extract(word, semantic["bit_start"], semantic["bit_width"]),
                immediate_values[immediate_index],
            )
            for word, _observation, _accesses, immediate_values in observations
        ]
        fitted = fit_transform(
            candidate,
            semantic,
            samples,
            bool(grammar_immediates[immediate_index]["signed"]),
        )
        if fitted is None:
            return None
        signed, multiplier, addend = fitted
        semantic["transform"] = TRANSFORM_SIGNED if signed else 0
        semantic["multiplier"] = multiplier
        semantic["addend"] = addend
        immediate_index += 1
    first_observation = observations[0][1]
    return {
        "form_id": str(candidate["form_id"]),
        "source_form_id": candidate["source_form_id"],
        "mnemonic": candidate["mnemonic"].lower(),
        "isa": candidate["isa"],
        "width": str(candidate["width"]),
        "authority": "capstone",
        "witnesses": ",".join(
            f"0x{word:0{candidate['width'] // 4}x}" for word, *_rest in observations
        ),
        "operand_semantics": canonical_json(semantics),
        "capstone_real_name": first_observation["real_name"],
        "capstone_groups": ",".join(first_observation["groups"]),
    }


def observe_branch_candidate(
    candidate: dict[str, Any],
    capstone: base.CapstoneCstoolOracle | None,
    cdisasm: base.CdisasmFormOracle | None,
) -> dict[str, str] | None:
    words = branch_witness_words(candidate)
    if cdisasm is not None and any(
        cdisasm.form(word, candidate["isa"], candidate["width"]) != candidate["form_id"]
        for word in words
    ):
        return None
    cross_checked: list[dict[str, Any]] = []
    if capstone is not None:
        for word in words:
            observation = capstone.decode(word, candidate["isa"], candidate["width"])
            if capstone_observation_matches(candidate, word, observation) is not None and observation is not None:
                cross_checked.append(observation)
    authority = "aarchmrs+capstone" if cross_checked else "aarchmrs"
    return {
        "form_id": str(candidate["form_id"]),
        "source_form_id": candidate["source_form_id"],
        "mnemonic": candidate["mnemonic"].lower(),
        "isa": candidate["isa"],
        "width": str(candidate["width"]),
        "authority": authority,
        "witnesses": ",".join(f"0x{word:0{candidate['width'] // 4}x}" for word in words),
        "operand_semantics": canonical_json(candidate["semantics"]),
        "capstone_real_name": cross_checked[0]["real_name"] if cross_checked else "",
        "capstone_groups": ",".join(cross_checked[0]["groups"]) if cross_checked else "",
    }


def observe_memory_candidate(
    candidate: dict[str, Any],
    capstone: base.CapstoneCstoolOracle,
    cdisasm: base.CdisasmFormOracle | None,
) -> dict[str, str] | None:
    words = memory_witness_words(candidate)
    observations: list[tuple[int, dict[str, Any], tuple[int, int, int]]] = []
    for word in words:
        if cdisasm is not None and cdisasm.form(
            word, candidate["isa"], candidate["width"]
        ) != candidate["form_id"]:
            continue
        observation = capstone.decode(word, candidate["isa"], candidate["width"])
        matched = capstone_memory_matches(candidate, word, observation)
        if matched is not None and observation is not None:
            observations.append((word, observation, matched))
    if len(observations) < 3:
        semantics = architecture_memory_semantics(candidate)
        if semantics is None:
            return None
        return architecture_row(candidate, words, semantics, cdisasm)
    register_access = observations[0][2][0]
    memory_access = observations[0][2][1]
    if any(
        item[2][0] != register_access or item[2][1] != memory_access
        for item in observations[1:]
    ):
        return None
    semantics = [dict(item) for item in candidate["semantics"]]
    semantics[0]["access"] = register_access
    semantics[1]["access"] = memory_access
    displacement_descriptor = dict(semantics[1])
    displacement_descriptor["bit_start"] = semantics[1]["second_start"]
    displacement_descriptor["bit_width"] = semantics[1]["second_width"]
    samples = [
        (
            extract(
                word,
                displacement_descriptor["bit_start"],
                displacement_descriptor["bit_width"],
            ),
            matched[2],
        )
        for word, _observation, matched in observations
    ]
    fitted = fit_transform(
        candidate,
        displacement_descriptor,
        samples,
        candidate["memory_field"] == "imm9",
    )
    if fitted is None:
        return None
    signed, multiplier, addend = fitted
    semantics[1]["transform"] = TRANSFORM_SIGNED if signed else 0
    semantics[1]["multiplier"] = multiplier
    semantics[1]["addend"] = addend

    # Both encoded registers must be observed at ordinary values and at their
    # architectural 31 spellings before the descriptor is accepted.
    for semantic in semantics[:2]:
        if semantic["kind"] != KIND_REGISTER and semantic["kind"] != KIND_MEMORY:
            continue
        values = {
            extract(word, semantic["bit_start"], semantic["bit_width"])
            for word, _observation, _matched in observations
        }
        if len(values) < 2 or 31 not in values:
            return None
    first = observations[0][1]
    return {
        "form_id": str(candidate["form_id"]),
        "source_form_id": candidate["source_form_id"],
        "mnemonic": candidate["mnemonic"].lower(),
        "isa": candidate["isa"],
        "width": str(candidate["width"]),
        "authority": "capstone",
        "witnesses": ",".join(
            f"0x{word:0{candidate['width'] // 4}x}" for word, *_rest in observations
        ),
        "operand_semantics": canonical_json(semantics),
        "capstone_real_name": first["real_name"],
        "capstone_groups": ",".join(first["groups"]),
    }


def observe_scalable_candidate(
    candidate: dict[str, Any],
    capstone: base.CapstoneCstoolOracle,
    cdisasm: base.CdisasmFormOracle | None,
) -> dict[str, str] | None:
    words = scalable_witness_words(candidate)
    observations: list[tuple[int, dict[str, Any], tuple[int, ...]]] = []
    for word in words:
        if cdisasm is not None and cdisasm.form(
            word, candidate["isa"], candidate["width"]
        ) != candidate["form_id"]:
            continue
        observation = capstone.decode(word, candidate["isa"], candidate["width"])
        accesses = capstone_scalable_matches(candidate, word, observation)
        if accesses is not None and observation is not None:
            observations.append((word, observation, accesses))
    if len(observations) < 3:
        return None
    access_tuple = observations[0][2]
    if any(item[2] != access_tuple for item in observations[1:]):
        return None

    semantics = [dict(item) for item in candidate["semantics"]]
    for semantic, access in zip(semantics, access_tuple):
        semantic["access"] = access

    # Every encoded register and every dynamic element-size endpoint must have
    # survived canonical-name/type checking before the form is accepted.
    checked_fields: set[tuple[int, int]] = set()
    for semantic in semantics:
        field = (semantic["bit_start"], semantic["bit_width"])
        if field not in checked_fields:
            minimum, maximum = possible_field_bounds(candidate, semantic)
            values = {
                extract(word, field[0], field[1])
                for word, _observation, _accesses in observations
            }
            if minimum not in values or maximum not in values:
                return None
            checked_fields.add(field)
        if semantic["second_width"] != 0:
            element_descriptor = dict(semantic)
            element_descriptor["bit_start"] = semantic["second_start"]
            element_descriptor["bit_width"] = semantic["second_width"]
            element_field = (
                element_descriptor["bit_start"],
                element_descriptor["bit_width"],
            )
            if element_field not in checked_fields:
                minimum, maximum = possible_field_bounds(
                    candidate, element_descriptor
                )
                values = {
                    extract(word, element_field[0], element_field[1])
                    for word, _observation, _accesses in observations
                }
                if minimum not in values or maximum not in values:
                    return None
                checked_fields.add(element_field)
    first = observations[0][1]
    return {
        "form_id": str(candidate["form_id"]),
        "source_form_id": candidate["source_form_id"],
        "mnemonic": candidate["mnemonic"].lower(),
        "isa": candidate["isa"],
        "width": str(candidate["width"]),
        "authority": "aarchmrs+capstone",
        "witnesses": ",".join(
            f"0x{word:0{candidate['width'] // 4}x}"
            for word, *_rest in observations
        ),
        "operand_semantics": canonical_json(semantics),
        "capstone_real_name": first["real_name"],
        "capstone_groups": ",".join(first["groups"]),
    }


def write_tsv(path: Path, rows: Iterable[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=ORACLE_FIELDS, dialect="excel-tab")
        writer.writeheader()
        writer.writerows(rows)


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, dialect="excel-tab")
        if reader.fieldnames != ORACLE_FIELDS:
            raise ImmediateCatalogError(f"stale mixed oracle schema in {path}")
        return list(reader)


def validate_semantic(value: Any, candidate: dict[str, Any]) -> dict[str, int]:
    fields = {
        "kind", "bit_start", "bit_width", "second_start", "second_width",
        "reg_class", "access", "size", "special31", "transform",
        "multiplier", "addend",
    }
    if not isinstance(value, dict) or set(value) != fields or any(
        not isinstance(item, int) for item in value.values()
    ):
        raise ImmediateCatalogError(f"invalid descriptor for form {candidate['form_id']}")
    semantic = dict(value)
    kind = semantic["kind"]
    if kind not in {
        KIND_REGISTER, KIND_IMMEDIATE, KIND_RELATIVE, KIND_DYNAMIC_GPR,
        KIND_MEMORY, KIND_SCALABLE_REGISTER, KIND_PREDICATE,
    }:
        raise ImmediateCatalogError(f"invalid operand kind for form {candidate['form_id']}")
    if semantic["access"] not in base.ACCESS.values() or (
        not 1 <= semantic["size"] <= 8
        and kind not in {
            KIND_DYNAMIC_GPR, KIND_SCALABLE_REGISTER, KIND_PREDICATE,
        }
    ):
        raise ImmediateCatalogError(f"invalid access/size for form {candidate['form_id']}")
    if kind in {
        KIND_REGISTER, KIND_IMMEDIATE, KIND_DYNAMIC_GPR, KIND_MEMORY,
        KIND_SCALABLE_REGISTER, KIND_PREDICATE,
    }:
        if semantic["bit_width"] <= 0 or semantic["bit_start"] + semantic["bit_width"] > candidate["width"]:
            raise ImmediateCatalogError(f"invalid field for form {candidate['form_id']}")
    if kind in {KIND_SCALABLE_REGISTER, KIND_PREDICATE}:
        if (
            semantic["size"] != 0
            or semantic["special31"] != 0
            or semantic["addend"] not in {0, 1, 2, 3}
            or semantic["multiplier"] not in {0, 1}
            or semantic["transform"] not in PREDICATE_QUALIFIER.values()
            or (kind == KIND_SCALABLE_REGISTER
                and semantic["transform"] != 0)
            or (semantic["second_width"] != 0
                and semantic["second_start"] + semantic["second_width"]
                    > candidate["width"])
        ):
            raise ImmediateCatalogError(
                f"invalid scalable descriptor for form {candidate['form_id']}"
            )
    if kind == KIND_RELATIVE and semantic["transform"] != candidate.get("target_kind"):
        raise ImmediateCatalogError(f"relative target-kind drift for form {candidate['form_id']}")
    return semantic


def validate_rows(
    rows: list[dict[str, str]], candidates: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    by_id = {item["form_id"]: item for item in candidates}
    records: list[dict[str, Any]] = []
    previous = 0
    for row in rows:
        form_id = int(row["form_id"])
        candidate = by_id.get(form_id)
        if candidate is None or form_id <= previous:
            raise ImmediateCatalogError("mixed oracle form IDs must be sorted unique candidates")
        previous = form_id
        if (
            row["source_form_id"] != candidate["source_form_id"]
            or row["mnemonic"] != candidate["mnemonic"].lower()
            or row["isa"] != candidate["isa"]
            or int(row["width"]) != candidate["width"]
            or row["authority"] not in {"capstone", "aarchmrs", "aarchmrs+capstone"}
        ):
            raise ImmediateCatalogError(f"mixed oracle identity drift for form {form_id}")
        try:
            raw_semantics = json.loads(row["operand_semantics"])
        except json.JSONDecodeError as error:
            raise ImmediateCatalogError(f"bad semantic JSON for form {form_id}") from error
        if not isinstance(raw_semantics, list) or not 1 <= len(raw_semantics) <= 4:
            raise ImmediateCatalogError(f"bad operand count for form {form_id}")
        semantics = [validate_semantic(value, candidate) for value in raw_semantics]
        if candidate["category"] == "relative":
            expected = candidate["semantics"]
            if semantics != expected or semantics[-1]["kind"] != KIND_RELATIVE:
                raise ImmediateCatalogError(f"relative semantics drift for form {form_id}")
        else:
            expected = candidate["semantics"]
            if len(semantics) != len(expected) or any(
                actual["kind"] != wanted["kind"]
                or actual["bit_start"] != wanted["bit_start"]
                or actual["bit_width"] != wanted["bit_width"]
                or actual["second_start"] != wanted["second_start"]
                or actual["second_width"] != wanted["second_width"]
                or actual["size"] != wanted["size"]
                or actual["reg_class"] != wanted["reg_class"]
                or actual["special31"] != wanted["special31"]
                for actual, wanted in zip(semantics, expected)
            ):
                raise ImmediateCatalogError(f"mixed descriptor shape drift for form {form_id}")
            if row["authority"] == "aarchmrs":
                architecture_expected = (
                    architecture_memory_semantics(candidate)
                    if candidate["category"] == "memory"
                    else architecture_immediate_semantics(candidate)
                    if candidate["category"] == "immediate"
                    else None
                )
                if architecture_expected is None \
                    or semantics != architecture_expected:
                    raise ImmediateCatalogError(
                        f"AARCHMRS-only semantics drift for form {form_id}"
                    )
        for witness in filter(None, row["witnesses"].split(",")):
            word = int(witness, 16)
            node = candidate["node"]
            if word & int(node["resolved_mask_int"]) != int(node["resolved_value_int"]):
                raise ImmediateCatalogError(f"witness violates form {form_id} fixed encoding")
            for operand in candidate.get("grammar_operands", []):
                if operand["kind"] != "immediate":
                    continue
                field = operand["field"]
                start, width = node["bindings"][field]
                value = extract(word, start, width)
                minimum, maximum = possible_binding_bounds(candidate, field)
                if value < minimum or value > maximum:
                    raise ImmediateCatalogError(
                        f"witness violates form {form_id} architectural bounds"
                    )
        records.append({**candidate, "semantics": semantics, "oracle": row})
    return records


def c_u8(value: int) -> str:
    return f"UINT8_C({value})"


def c_i32(value: int) -> str:
    return f"INT32_C({value})" if value >= 0 else f"-INT32_C({-value})"


def c_u16(value: int) -> str:
    return f"UINT16_C({value})"


def emit_include(path: Path, records: list[dict[str, Any]]) -> None:
    operand_rows: list[str] = []
    form_rows: list[str] = []
    first = 0
    for record in records:
        flags = 1 if scalar_fp(record) else 0
        source_path = record["source_form_id"].lower()
        if "/ldst_immpre/" in source_path or (
            "/ldst_pac/" in source_path and "_64w_" in source_path
        ):
            flags |= 2
        if "/ldst_immpost/" in source_path:
            flags |= 4
        if "/ldst_unpriv/" in source_path:
            flags |= 8
        if record["category"] == "scalable":
            flags |= 16
            if any(
                semantic["kind"] == KIND_PREDICATE
                for semantic in record["semantics"]
            ):
                flags |= 32
            # A typed predicate can be ordinary data rather than a governing
            # predicate.  These FFR transfers have no /M or /Z control, so
            # their leaf semantics correctly remain unpredicated.
            if record["form_id"] in {2564, 2617}:
                flags &= ~32
        for semantic in record["semantics"]:
            operand_rows.append(
                "{ %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s }"
                % (
                    c_u8(semantic["kind"]),
                    c_u8(semantic["bit_start"]),
                    c_u8(semantic["bit_width"]),
                    c_u8(semantic["second_start"]),
                    c_u8(semantic["second_width"]),
                    c_u8(semantic["reg_class"]),
                    c_u8(semantic["access"]),
                    c_u8(semantic["size"]),
                    c_u8(semantic["special31"]),
                    c_u8(semantic["transform"]),
                    c_i32(semantic["multiplier"]),
                    c_i32(semantic["addend"]),
                )
            )
        form_rows.append(
            "{ %s, %s, %s, %s }"
            % (
                c_u16(record["form_id"]),
                c_u16(first),
                c_u8(len(record["semantics"])),
                c_u8(flags),
            )
        )
        first += len(record["semantics"])
    lines = [
        "/* Generated numeric ARM mixed operand semantics; do not edit. */",
        "/* Pinned open AARCHMRS plus offline pinned Capstone validation. */",
        f"#define CDISASM_ARM_OPEN_IMMEDIATE_SCHEMA_VERSION UINT32_C({SCHEMA_VERSION})",
        f"#define CDISASM_ARM_OPEN_IMMEDIATE_FORM_COUNT UINT32_C({len(records)})",
        f"#define CDISASM_ARM_OPEN_IMMEDIATE_OPERAND_COUNT UINT32_C({len(operand_rows)})",
        "#define CDISASM_ARM_OPEN_MIXED_FLAG_FLOATING_POINT UINT8_C(1)",
        "#define CDISASM_ARM_OPEN_MIXED_FLAG_PRE_INDEX UINT8_C(2)",
        "#define CDISASM_ARM_OPEN_MIXED_FLAG_POST_INDEX UINT8_C(4)",
        "#define CDISASM_ARM_OPEN_MIXED_FLAG_UNPRIVILEGED UINT8_C(8)",
        "#define CDISASM_ARM_OPEN_MIXED_FLAG_SCALABLE_VECTOR UINT8_C(16)",
        "#define CDISASM_ARM_OPEN_MIXED_FLAG_PREDICATED UINT8_C(32)",
        "",
        "typedef struct cdisasm_arm_open_mixed_operand_desc {",
        "    uint8_t kind, bit_start, bit_width, second_start, second_width;",
        "    uint8_t reg_class, access, size, special31, transform;",
        "    int32_t multiplier, addend;",
        "} cdisasm_arm_open_mixed_operand_desc;",
        "typedef struct cdisasm_arm_open_mixed_form_desc {",
        "    uint16_t form_id, first_operand;",
        "    uint8_t operand_count, flags;",
        "} cdisasm_arm_open_mixed_form_desc;",
        "",
        "static const cdisasm_arm_open_mixed_operand_desc cdisasm_arm_open_mixed_operands[] = {",
        *(f"    {row}," for row in operand_rows),
        "};",
        "",
        "static const cdisasm_arm_open_mixed_form_desc cdisasm_arm_open_mixed_forms[] = {",
        *(f"    {row}," for row in form_rows),
        "};",
        "",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8", newline="\n")


def emit_manifest(
    path: Path,
    arm_source: Path,
    candidates: list[dict[str, Any]],
    records: list[dict[str, Any]],
    oracle_path: Path,
    include_path: Path,
) -> None:
    by_isa: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    by_authority: dict[str, int] = {}
    kind_names = {
        KIND_REGISTER: "register",
        KIND_IMMEDIATE: "immediate",
        KIND_RELATIVE: "relative",
        KIND_DYNAMIC_GPR: "dynamic_gpr",
        KIND_MEMORY: "memory",
        KIND_SCALABLE_REGISTER: "scalable_register",
        KIND_PREDICATE: "predicate",
    }
    for record in records:
        by_isa[record["isa"]] = by_isa.get(record["isa"], 0) + 1
        authority = record["oracle"]["authority"]
        by_authority[authority] = by_authority.get(authority, 0) + 1
        for semantic in record["semantics"]:
            name = kind_names[semantic["kind"]]
            by_kind[name] = by_kind.get(name, 0) + 1
    relative_candidates = sum(item["category"] == "relative" for item in candidates)
    relative_records = sum(item["category"] == "relative" for item in records)
    memory_candidates = sum(item["category"] == "memory" for item in candidates)
    memory_records = sum(item["category"] == "memory" for item in records)
    scalable_candidates = sum(item["category"] == "scalable" for item in candidates)
    scalable_records = sum(item["category"] == "scalable" for item in records)
    immediate_candidates = (
        len(candidates) - relative_candidates - memory_candidates
        - scalable_candidates
    )
    immediate_records = (
        len(records) - relative_records - memory_records - scalable_records
    )
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "source": {
            "arm_commit": base.PINNED_ARM_COMMIT,
            "arm_instructions_sha256": sha256_file(arm_source),
            "capstone_commit": base.PINNED_CAPSTONE_COMMIT,
            "generator_sha256": sha256_file(Path(__file__).resolve()),
        },
        "policy": {
            "scope": "exact canonical mixed scalar immediates, all generated direct relative branches, A64 scalar base-plus-immediate memory forms, and closed all-register SVE integer forms",
            "runtime_dependency": False,
            "strings_in_decoder_table": False,
            "nonrelative_validation": "same canonical form and mnemonic with exact operand type/register/access across legal endpoint witnesses; affine semantic immediate only; direct SETPAN and 32-bit bitfield fields use a closed AARCHMRS-only whitelist",
            "relative_validation": "open architecture target kind; runtime target must equal independently precomputed generated-control branch_target",
            "memory_validation": "Capstone register/memory/access/displacement agreement across endpoint witnesses; STLUR uses its direct AARCHMRS store grammar because the pinned Capstone detail record is malformed",
            "memory_exclusions": "pointer-authentication S:imm9 split offsets and non-scalar/vector-list address forms remain operands-opaque",
            "alias_forms": "not lowered; caller selects aliases before invoking this canonical layer",
            "unlisted_forms": "remain operands-opaque",
        },
        "counts": {
            "structural_candidates": len(candidates),
            "oracle_verified_forms": len(records),
            "oracle_rejected_or_unavailable": len(candidates) - len(records),
            "relative_candidates": relative_candidates,
            "relative_verified_forms": relative_records,
            "nonrelative_immediate_candidates": immediate_candidates,
            "nonrelative_immediate_verified_forms": immediate_records,
            "memory_candidates": memory_candidates,
            "memory_verified_forms": memory_records,
            "scalable_register_candidates": scalable_candidates,
            "scalable_register_verified_forms": scalable_records,
            "lowered_operands": sum(len(item["semantics"]) for item in records),
            "forms_by_isa": dict(sorted(by_isa.items())),
            "operands_by_kind": dict(sorted(by_kind.items())),
            "forms_by_authority": dict(sorted(by_authority.items())),
        },
        "artifacts": {
            str(oracle_path.relative_to(REPO_ROOT)).replace("\\", "/"): {
                "sha256": sha256_file(oracle_path),
                "bytes": oracle_path.stat().st_size,
            },
            str(include_path.relative_to(REPO_ROOT)).replace("\\", "/"): {
                "sha256": sha256_file(include_path),
                "bytes": include_path.stat().st_size,
            },
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(manifest, stream, ensure_ascii=True, indent=2, sort_keys=True)
        stream.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arm-root", type=Path, required=True)
    parser.add_argument("--leaf-tsv", type=Path, default=SCRIPT_DIR / "generated" / "arm_tree_leaves.tsv")
    parser.add_argument("--capstone-root", type=Path)
    parser.add_argument("--capstone-cstool", type=Path)
    parser.add_argument("--cdisasm-dll", type=Path)
    parser.add_argument("--refresh-oracle", action="store_true")
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--oracle", type=Path, default=SCRIPT_DIR / "generated" / "arm_open_immediate_oracle.tsv")
    parser.add_argument("--decode-include", type=Path, default=REPO_ROOT / "src" / "arm" / "generated" / "cdisasm_arm_open_immediates.inc")
    parser.add_argument("--manifest", type=Path, default=SCRIPT_DIR / "generated" / "arm_open_immediate_manifest.json")
    arguments = parser.parse_args()

    arm_root = arguments.arm_root.resolve()
    document = base.load_arm_source(arm_root)
    leaf_rows = leaf_semantics.load_rows(arguments.leaf_tsv)
    candidates = collect_candidates(document, leaf_rows)
    candidates.sort(key=lambda item: item["form_id"])

    if arguments.refresh_oracle:
        if arguments.capstone_root is None:
            raise ImmediateCatalogError("--refresh-oracle requires --capstone-root")
        capstone = base.CapstoneCstoolOracle(
            arguments.capstone_root.resolve(), arguments.capstone_cstool
        )
        cdisasm = base.CdisasmFormOracle(arguments.cdisasm_dll) if arguments.cdisasm_dll else None
        rows: list[dict[str, str]] = []
        with ThreadPoolExecutor(max_workers=max(1, arguments.jobs)) as pool:
            futures = {
                pool.submit(
                    observe_branch_candidate
                    if item["category"] == "relative"
                    else observe_memory_candidate
                    if item["category"] == "memory"
                    else observe_scalable_candidate
                    if item["category"] == "scalable"
                    else observe_immediate_candidate,
                    item,
                    capstone,
                    cdisasm,
                ): item
                for item in candidates
            }
            for future in as_completed(futures):
                row = future.result()
                if row is not None:
                    rows.append(row)
        rows.sort(key=lambda item: int(item["form_id"]))
        write_tsv(arguments.oracle, rows)
    else:
        if not arguments.oracle.is_file():
            raise ImmediateCatalogError(f"missing checked-in oracle {arguments.oracle}; use --refresh-oracle")
        rows = read_tsv(arguments.oracle)

    records = validate_rows(rows, candidates)
    emit_include(arguments.decode_include, records)
    emit_manifest(
        arguments.manifest,
        arm_root / "Instructions.json",
        candidates,
        records,
        arguments.oracle,
        arguments.decode_include,
    )
    relative = sum(item["category"] == "relative" for item in records)
    scalable = sum(item["category"] == "scalable" for item in records)
    print(
        f"Arm open immediate catalogue: {len(records)}/{len(candidates)} verified forms "
        f"({relative} relative, {scalable} scalable), "
        f"{sum(len(item['semantics']) for item in records)} operands"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ImmediateCatalogError, base.OperandCatalogError, leaf_semantics.GenerationError) as error:
        print(f"Arm open immediate generation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
