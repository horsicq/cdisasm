#!/usr/bin/env python3
"""Compile the pinned Intel XED JSON inventory into numeric decoder tables.

This generator deliberately emits no mnemonic, IFORM, ISA-set, pattern, or
operand strings.  Text identities remain in the tooling TSV/formatter tables;
the decoder table is joined by descriptor index to the checked-in numeric
IFORM and ISA-family catalogs.
"""

from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import re
from typing import Any


GENERATOR_VERSION = 8
EXPECTED_DESCRIPTOR_COUNT = 10_994
EXPECTED_IFORM_COUNT = 9_001

SPACE_IDS = {"legacy": 0, "vex": 1, "evex": 2, "xop": 3}
MODE_BITS = {16: 1 << 0, 32: 1 << 1, 64: 1 << 2}
EASZ_BITS = {16: 1 << 0, 32: 1 << 1, 64: 1 << 2}

# The runtime state-field IDs are part of the generated/include contract.
FIELD_IDS = {
    "MODE": 0,
    "EASZ": 1,
    "REP": 2,
    "OSZ": 3,
    "ASZ": 4,
    "LOCK": 5,
    "REXW": 6,
    "REX2": 7,
    "REXR": 8,
    "REXR4": 9,
    "REXB": 10,
    "REXB4": 11,
    "VEX_PREFIX": 12,
    "VL": 13,
    "UBIT": 14,
    "BCRC": 15,
    "ZEROING": 16,
    "MASK": 17,
    "ND": 18,
    "NF": 19,
    "VEXDEST3": 20,
    "VEXDEST210": 21,
    "VEXDEST4": 22,
    "SCC": 23,
    "SRM": 24,
    "NEED_SIB": 25,
}

# These are XED decode-configuration selectors or actions, not raw encoding
# fields.  The ISA-set/runtime flag decides feature aliases (for example
# TZCNT versus BSF); the remaining actions do not constrain input bytes.
IGNORED_ASSIGNMENTS = {
    "CET",
    "CLDEMOTE",
    "ENC_DELETE",
    "IBHF",
    "LZCNT",
    "MODEP5",
    "MODE_SHORT_UD0",
    "MPXMODE",
    "NOREX2",
    "P4",
    "PREFETCHIT",
    "PREFETCHRST",
    "SKIP_OSZ",
    "TZCNT",
    "WBNOINVD",
}

# These assignments are represented by the bucket key or direct masks.
DIRECT_ASSIGNMENTS = {"MAP", "MOD", "RM", "VEXVALID"}

IMMEDIATE_RECIPES = {
    "UIMM8()": 1,
    "SIMM8()": 1,
    "SE_IMM8()": 1,
    "UIMM8_1()": 1,
    "UIMM16()": 2,
    "UIMM32()": 3,
    "UIMMv()": 5,
    "SIMMz()": 6,
    "BRDISP8()": 7,
    "BRDISPz()": 8,
    "BRDISP32()": 9,
    "BRDISP64()": 10,
    "MEMDISPv()": 11,
}

# Every function-like token in the pinned export must be classified.  Most
# affect operand construction only; immediate tokens above affect length.
IGNORED_FUNCTIONS = {
    "AVX512_ROUND()",
    "BRANCH_HINT()",
    "CET_NO_TRACK()",
    "CR_WIDTH()",
    "DF64()",
    "ESIZE_128_BITS()",
    "ESIZE_16_BITS()",
    "ESIZE_32_BITS()",
    "ESIZE_4_BITS()",
    "ESIZE_64_BITS()",
    "ESIZE_8_BITS()",
    "EVEXR4_ONE()",
    "FIX_ROUND_LEN128()",
    "FIX_ROUND_LEN512()",
    "FORCE64()",
    "IGNORE66()",
    "IMMUNE66()",
    "IMMUNE66_LOOP64()",
    "IMMUNE_REXW()",
    "MODRM()",
    "NELEM_EIGHTHMEM()",
    "NELEM_FULL()",
    "NELEM_FULLMEM()",
    "NELEM_HALF()",
    "NELEM_HALFMEM()",
    "NELEM_MEM128()",
    "NELEM_MOVDDUP()",
    "NELEM_ONE()",
    "NELEM_QUARTER()",
    "NELEM_QUARTERMEM()",
    "NELEM_TUPLE1_4X()",
    "NELEM_TUPLE2()",
    "NELEM_TUPLE4()",
    "NELEM_TUPLE8()",
    "ONE()",
    "OVERRIDE_SEG0()",
    "OVERRIDE_SEG1()",
    "REFINING66()",
    "REMOVE_SEGMENT()",
    "SAE()",
    "UISA_VMODRM_XMM()",
    "UISA_VMODRM_YMM()",
    "UISA_VMODRM_ZMM()",
    "VMODRM_XMM()",
    "VMODRM_YMM()",
}

FLAG_HAS_MODRM = 1 << 0
FLAG_EVAPX = 1 << 1
FLAG_EVAPX_SCC = 1 << 2
FLAG_UNDOCUMENTED = 1 << 3
FLAG_DEFAULT_64 = 1 << 4
FLAG_MAP4_SELECTOR = 1 << 5

# Descriptor-level ABI lowering metadata.  These bits never overlap the
# recognition flags above; they live in a separate generated field.
SPECIAL_MASK_OPTIONAL = 1 << 0
SPECIAL_MASK_REQUIRED = 1 << 1
SPECIAL_ROUND = 1 << 2
SPECIAL_SAE = 1 << 3
SPECIAL_BROADCAST = 1 << 4
SPECIAL_EVEX_R4_APX = 1 << 5
SPECIAL_ZEROING_ALLOWED = 1 << 6
SPECIAL_REMOVE_SEGMENT = 1 << 7
SPECIAL_DEFAULT_FLAGS = 1 << 8
SPECIAL_MASK_AS_CONTROL = 1 << 9

STATUS_READS_FLAGS = 1 << 0
STATUS_WRITES_FLAGS = 1 << 1

# XED nonterminals which change EOSZ independently of the raw 66/REX.W
# prefix bits.  The generated runtime applies these policies before indexing
# scalable operand-width recipes.
OPERAND_SIZE_IMMUNE66_LOOP64 = 1 << 0
OPERAND_SIZE_CR_WIDTH = 1 << 1
OPERAND_SIZE_IMMUNE_REXW = 1 << 2
OPERAND_SIZE_IGNORE66 = 1 << 3
OPERAND_SIZE_FORCE64 = 1 << 4
OPERAND_SIZE_IMMUNE66 = 1 << 5

OPERAND_KIND_REGISTER = 1
OPERAND_KIND_MEMORY = 2
OPERAND_KIND_IMMEDIATE = 3
OPERAND_KIND_RELATIVE = 4
OPERAND_KIND_ABSOLUTE_BRANCH = 5
OPERAND_KIND_FAR_POINTER = 6
OPERAND_KIND_LITERAL_IMMEDIATE = 7

OPERAND_SOURCE_NONE = 0
OPERAND_SOURCE_REG = 1
OPERAND_SOURCE_REG_HIGH = 2
OPERAND_SOURCE_RM = 3
OPERAND_SOURCE_RM_HIGH = 4
OPERAND_SOURCE_VVVV = 5
OPERAND_SOURCE_VVVV_HIGH = 6
OPERAND_SOURCE_OPCODE = 7
OPERAND_SOURCE_IMMEDIATE_HIGH = 8
OPERAND_SOURCE_MODRM_MEMORY = 9
OPERAND_SOURCE_ABSOLUTE_MEMORY = 10
OPERAND_SOURCE_FIXED_ZERO = 11
OPERAND_SOURCE_FIXED_REGISTER = 12

REG_CLASS_NONE = 0
REG_CLASS_GPR8 = 1
REG_CLASS_GPR16 = 2
REG_CLASS_GPR32 = 3
REG_CLASS_GPR64 = 4
REG_CLASS_GPRV = 5
REG_CLASS_GPRY = 6
REG_CLASS_GPRZ = 7
REG_CLASS_ADDRESS_GPR = 8
REG_CLASS_MMX = 9
REG_CLASS_XMM = 10
REG_CLASS_YMM = 11
REG_CLASS_ZMM = 12
REG_CLASS_MASK = 13
REG_CLASS_BND = 14
REG_CLASS_TMM = 15
REG_CLASS_X87 = 16
REG_CLASS_SEGMENT = 17
REG_CLASS_CR = 18
REG_CLASS_DR = 19

OPERAND_RECIPE_SIGNED = 1 << 0
OPERAND_RECIPE_ADDRESS_ONLY = 1 << 1
OPERAND_RECIPE_BROADCAST = 1 << 2
OPERAND_RECIPE_NO_RSP = 1 << 3
OPERAND_RECIPE_IMPLICIT = 1 << 4

VSIB_CLASS_NONE = 0
VSIB_CLASS_XMM = 1
VSIB_CLASS_YMM = 2
VSIB_CLASS_ZMM = 3

ACCESS_IDS = {"r": 1, "w": 2, "rw": 3, "rcw": 3, "crw": 3, "cw": 2}

REGISTER_CLASS_IDS = {
    "A_GPR": REG_CLASS_ADDRESS_GPR,
    "BND": REG_CLASS_BND,
    "CR": REG_CLASS_CR,
    "DR": REG_CLASS_DR,
    "GPR8": REG_CLASS_GPR8,
    "GPR16": REG_CLASS_GPR16,
    "GPR32": REG_CLASS_GPR32,
    "GPR64": REG_CLASS_GPR64,
    "GPRv": REG_CLASS_GPRV,
    "GPRy": REG_CLASS_GPRY,
    "GPRz": REG_CLASS_GPRZ,
    "MASK": REG_CLASS_MASK,
    "MMX": REG_CLASS_MMX,
    "SEG": REG_CLASS_SEGMENT,
    "SEG_MOV": REG_CLASS_SEGMENT,
    "TMM": REG_CLASS_TMM,
    "VGPR32": REG_CLASS_GPR32,
    "VGPR64": REG_CLASS_GPR64,
    "VGPRy": REG_CLASS_GPRY,
    "X87": REG_CLASS_X87,
    "XMM": REG_CLASS_XMM,
    "YMM": REG_CLASS_YMM,
    "ZMM": REG_CLASS_ZMM,
}

VSIB_CLASS_IDS = {
    None: VSIB_CLASS_NONE,
    "xmm": VSIB_CLASS_XMM,
    "ymm": VSIB_CLASS_YMM,
    "zmm": VSIB_CLASS_ZMM,
}


class GenerationError(RuntimeError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def digest_value(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def digest_file(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            result.update(block)
    return result.hexdigest()


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream, dialect="excel-tab"))


def read_public_register_ids(path: Path) -> dict[str, int]:
    result: dict[str, int] = {}
    pattern = re.compile(
        r"^#define CDISASM_X86_REG_([A-Z0-9]+) UINT16_C\(([0-9]+)\)$"
    )
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            match = pattern.match(line.rstrip("\n"))
            if match:
                name, value = match.groups()
                result[name] = int(value)
    required = {
        "AL", "AX", "CL", "CS", "DS", "DX", "EAX", "ECX", "EDX",
        "BSR0", "ES", "FS", "GS", "RAX", "RCX", "RDX", "SS", "ST0",
    }
    missing = required - result.keys()
    if missing:
        raise GenerationError(
            f"public register header lacks numeric IDs {sorted(missing)!r}"
        )
    return result


def parse_integer(value: str) -> int:
    if value.startswith("0b"):
        return int(value[2:], 2)
    return int(value, 0)


def implicit_operand_policy(record: dict[str, Any], operand: dict[str, Any]) -> str:
    """Classify XED IMPLICIT operands for the public syntax-oriented ABI.

    XED marks encoded-fixed syntax operands (CL, ST(0), accumulators and the
    literal shift count one and BSR0) as IMPLICIT.  They still belong in
    disassembly text and fit the five-operand ABI.  The x87 memory forms
    canonically omit their implicit ST(0).
    """

    if operand.get("bits") == "XED_REG_ST0":
        has_x87_register_operand = any(
            candidate.get("visibility") == "DEFAULT"
            and candidate.get("lookupfn_name_base") == "X87"
            for candidate in record.get("parsed_operands", [])
        )
        if not has_x87_register_operand:
            return "canonical_x87_memory_hidden"
    return "emit"


def values_mask(values: Any, mapping: dict[int, int]) -> int:
    if values is None:
        return sum(mapping.values())
    result = 0
    for value in values:
        try:
            result |= mapping[int(value)]
        except KeyError as error:
            raise GenerationError(f"unsupported value {value!r} for {mapping}") from error
    return result


def list_mask(values: Any, maximum: int) -> int:
    if values is None or values == []:
        return (1 << maximum) - 1
    result = 0
    for value in values:
        number = int(value)
        if number < 0 or number >= maximum:
            raise GenerationError(f"mask member {number} outside 0..{maximum - 1}")
        result |= 1 << number
    return result


def partial_opcode_mask(pattern_tokens: list[str], opcode: int) -> tuple[int, int]:
    bit_tokens = [token for token in pattern_tokens if re.fullmatch(r"0b[01]+_[01]+", token)]
    if not bit_tokens:
        return 0xFF, opcode
    if len(bit_tokens) != 1:
        raise GenerationError(f"multiple partial-opcode tokens: {bit_tokens}")
    fixed = bit_tokens[0][2:].replace("_", "")
    if len(fixed) != 5:
        raise GenerationError(f"unexpected partial-opcode token {bit_tokens[0]!r}")
    value = int(fixed, 2) << 3
    if opcode != value:
        raise GenerationError(
            f"partial-opcode base mismatch: token={bit_tokens[0]} opcode=0x{opcode:02x}"
        )
    return 0xF8, value


def combine_mask(mask: int, op: str, value: int, domain: int, label: str) -> int:
    if value < 0 or value >= domain:
        raise GenerationError(f"{label} value {value} outside 0..{domain - 1}")
    selected = 1 << value
    result = mask & (selected if op == "=" else ~selected)
    if result == 0:
        raise GenerationError(f"contradictory {label}{op}{value}")
    return result


def width_bytes(widths: Any, *, fallback_bits: int | None = None) -> tuple[int, int, int]:
    """Return ABI byte sizes for effective operand sizes 16/32/64.

    UINT8_MAX is the public run-time-sized sentinel.  XED uses fixed zero for
    tile/state operands and sizes above the ABI's byte range for state areas;
    neither is silently truncated here.
    """

    if widths is None:
        if fallback_bits is None:
            return (0xFF, 0xFF, 0xFF)
        widths = {"fixed": fallback_bits, "scalable": None}
    fixed = widths.get("fixed")
    scalable = widths.get("scalable")

    def convert(bits: Any) -> int:
        if bits is None:
            return 0xFF
        value = int(bits)
        if value <= 0:
            return 0xFF
        size = (value + 7) // 8
        return size if size < 0xFF else 0xFF

    if fixed is not None:
        size = convert(fixed)
        return (size, size, size)
    if not isinstance(scalable, dict):
        raise GenerationError(f"malformed operand width {widths!r}")
    keys = {"eosz16", "eosz32", "eosz64"}
    if set(scalable) != keys:
        raise GenerationError(f"unexpected scalable-width keys {sorted(scalable)!r}")
    return tuple(convert(scalable[key]) for key in ("eosz16", "eosz32", "eosz64"))


def lookup_source_and_class(operand: dict[str, Any]) -> tuple[int, int, int]:
    lookup = str(operand.get("lookupfn_name"))
    base = str(operand.get("lookupfn_name_base"))
    try:
        reg_class = REGISTER_CLASS_IDS[base]
    except KeyError as error:
        raise GenerationError(f"unsupported visible register class {base!r}") from error

    flags = OPERAND_RECIPE_NO_RSP if lookup.endswith("_NORSP") else 0
    if lookup.endswith("_NORSP"):
        lookup = lookup[:-6]
    if lookup == "X87":
        source = OPERAND_SOURCE_RM
    elif lookup in {"SEG", "SEG_MOV"}:
        source = OPERAND_SOURCE_REG
    elif lookup.endswith("_R3"):
        source = OPERAND_SOURCE_REG_HIGH
    elif lookup.endswith("_B3"):
        source = OPERAND_SOURCE_RM_HIGH
    elif lookup.endswith("_N3"):
        source = OPERAND_SOURCE_VVVV_HIGH
    elif lookup.endswith("_R"):
        source = OPERAND_SOURCE_REG
    elif lookup.endswith("_B"):
        source = OPERAND_SOURCE_RM
    elif lookup.endswith("_N"):
        source = OPERAND_SOURCE_VVVV
    elif lookup.endswith("_SB"):
        source = OPERAND_SOURCE_OPCODE
    elif lookup.endswith("_SE"):
        source = OPERAND_SOURCE_IMMEDIATE_HIGH
    else:
        raise GenerationError(f"unsupported visible lookup function {lookup!r}")
    return source, reg_class, flags


def encoded_immediate_actions(record: dict[str, Any]) -> list[tuple[int, str]]:
    result: list[tuple[int, str]] = []
    for token in str(record.get("pattern", "")).split():
        if token in IMMEDIATE_RECIPES:
            result.append((IMMEDIATE_RECIPES[token], token))
    return result


def immediate_operand_index(record: dict[str, Any], name: str) -> int:
    actions = [
        (recipe, token)
        for recipe, token in encoded_immediate_actions(record)
        if recipe != IMMEDIATE_RECIPES["MEMDISPv()"]
    ]
    if name in {"RELBR", "ABSBR", "PTR"}:
        candidates = [index for index, (_, token) in enumerate(actions)
                      if token.startswith("BRDISP")]
    elif name == "IMM1":
        candidates = [index for index, (_, token) in enumerate(actions)
                      if token == "UIMM8_1()"]
    elif name == "IMM0":
        candidates = [index for index, (_, token) in enumerate(actions)
                      if not token.startswith("BRDISP") and token != "UIMM8_1()"]
    else:
        candidates = []
    if len(candidates) != 1:
        raise GenerationError(
            f"cannot bind {name} to encoded immediate in {record['iform']}: {actions!r}"
        )
    return candidates[0]


def status_flag_metadata(record: dict[str, Any]) -> int:
    text = str(record.get("flags") or "")
    iclass = str(record.get("iclass") or "")
    result = 0
    if re.search(r"-[Tt][Ss][Tt]\b", text):
        result |= STATUS_READS_FLAGS
    # APX conditional compare/test encodes the tested condition in SCC; XED's
    # flags string lists the newly assigned flags but not the condition input.
    if iclass.startswith(("CCMP", "CTEST")):
        result |= STATUS_READS_FLAGS
    # XED's -mod/-0/-1/-u actions all assign a status bit.  A single record
    # can contain both tested and assigned flags (ADC/SBB are common cases).
    # SAHF's -ah and architectural-return -pop actions are assignments too.
    if re.search(r"-(?:mod|0|1|u|ah|pop)\b", text, re.IGNORECASE):
        result |= STATUS_WRITES_FLAGS
    return result


def coverage_counts(
    document: dict[str, Any], records: list[dict[str, Any]]
) -> dict[str, int]:
    """Return deterministic proof counters for the operand/control contract."""

    source_records = document.get("Instructions") or []
    visibility = Counter()
    conversions = Counter()
    mask_pseudo = 0
    bcast_pseudo = 0
    implicit_policies = Counter()
    implicit_bsr0 = 0
    for record in source_records:
        for operand in record.get("parsed_operands", []):
            operand_visibility = str(operand.get("visibility") or "")
            visibility[operand_visibility] += 1
            if operand_visibility == "IMPLICIT":
                implicit_policies[implicit_operand_policy(record, operand)] += 1
                if operand.get("bits") == "XED_REG_BSR0":
                    implicit_bsr0 += 1
            if operand_visibility != "DEFAULT":
                continue
            operand_conversions = set(operand.get("cvt") or [])
            conversions.update(operand_conversions)
            if operand.get("lookupfn_name") in {"MASK1", "MASKNOT0"}:
                mask_pseudo += 1
            elif operand.get("name") == "BCAST":
                bcast_pseudo += 1

    emitted_operands = [
        operand for record in records for operand in record["operands"]
    ]
    emitted_default_operands = [
        operand for operand in emitted_operands
        if (operand["flags"] & OPERAND_RECIPE_IMPLICIT) == 0
    ]
    emitted_implicit_operands = [
        operand for operand in emitted_operands
        if (operand["flags"] & OPERAND_RECIPE_IMPLICIT) != 0
    ]
    default_count = visibility["DEFAULT"]
    if default_count != len(emitted_default_operands) + mask_pseudo + bcast_pseudo:
        raise GenerationError(
            "DEFAULT operand accounting does not close: "
            f"{default_count} != {len(emitted_default_operands)} + "
            f"{mask_pseudo} + {bcast_pseudo}"
        )
    if visibility["IMPLICIT"] != sum(implicit_policies.values()):
        raise GenerationError("IMPLICIT operand accounting does not close")
    if implicit_policies["emit"] != len(emitted_implicit_operands):
        raise GenerationError(
            "selected IMPLICIT operand accounting does not close: "
            f"{implicit_policies['emit']} != {len(emitted_implicit_operands)}"
        )

    kind_names = {
        OPERAND_KIND_REGISTER: "register_operand_recipes",
        OPERAND_KIND_MEMORY: "memory_operand_recipes",
        OPERAND_KIND_IMMEDIATE: "immediate_operand_recipes",
        OPERAND_KIND_RELATIVE: "relative_operand_recipes",
        OPERAND_KIND_ABSOLUTE_BRANCH: "absolute_branch_operand_recipes",
        OPERAND_KIND_FAR_POINTER: "far_pointer_operand_recipes",
        OPERAND_KIND_LITERAL_IMMEDIATE: "literal_immediate_operand_recipes",
    }
    group_names = {
        0: "jump_group_descriptors",
        1: "call_group_descriptors",
        2: "return_group_descriptors",
        3: "interrupt_group_descriptors",
        4: "interrupt_return_group_descriptors",
        5: "privileged_group_descriptors",
        6: "relative_branch_group_descriptors",
        7: "conditional_group_descriptors",
    }
    result = {
        "raw_parsed_operands": sum(visibility.values()),
        "raw_default_operands": default_count,
        "raw_suppressed_operands": visibility["SUPPRESSED"],
        "raw_implicit_operands": visibility["IMPLICIT"],
        "raw_econd_operands": visibility["ECOND"],
        "implicit_syntax_operands_lowered": implicit_policies["emit"],
        "implicit_x87_memory_accumulators_canonically_hidden":
            implicit_policies["canonical_x87_memory_hidden"],
        "implicit_bsr0_operands_lowered": implicit_bsr0,
        "remaining_selected_implicit_operands_unlowered": 0,
        "mask_pseudo_operands_lowered_to_instruction": mask_pseudo,
        "bcast_pseudo_operands_lowered_to_memory": bcast_pseudo,
        "remaining_default_operands_unlowered": 0,
        "remaining_emitted_operands_opaque": 0,
        "multireg2_group_operands": conversions["MULTIREG2"],
        "multireg4_group_operands": conversions["MULTIREG4"],
        "rounding_operand_annotations": conversions["ROUNDC"],
        "sae_operand_annotations": conversions["SAESTR"],
        "broadcast_operand_annotations": conversions["BCASTSTR"],
        "zeroing_operand_annotations": conversions["ZEROSTR"],
        "variable_size_operand_recipes": sum(
            0xFF in (operand["size16"], operand["size32"], operand["size64"])
            for operand in emitted_operands
        ),
        "fully_dynamic_memory_operand_recipes": sum(
            operand["kind"] == OPERAND_KIND_MEMORY
            and (operand["size16"], operand["size32"], operand["size64"])
                == (0xFF, 0xFF, 0xFF)
            for operand in emitted_operands
        ),
        "zero_display_operand_descriptors": sum(
            not record["operands"] for record in records
        ),
        "control_metadata_descriptors": sum(
            record["generic_groups"] != 0 for record in records
        ),
        "status_reads_only_descriptors": sum(
            record["status_flags"] == STATUS_READS_FLAGS for record in records
        ),
        "status_writes_only_descriptors": sum(
            record["status_flags"] == STATUS_WRITES_FLAGS for record in records
        ),
        "status_reads_and_writes_descriptors": sum(
            record["status_flags"]
                == (STATUS_READS_FLAGS | STATUS_WRITES_FLAGS)
            for record in records
        ),
        "mask_optional_descriptors": sum(
            bool(record["special_flags"] & SPECIAL_MASK_OPTIONAL)
            for record in records
        ),
        "mask_required_descriptors": sum(
            bool(record["special_flags"] & SPECIAL_MASK_REQUIRED)
            for record in records
        ),
        "rounding_descriptors": sum(
            bool(record["special_flags"] & SPECIAL_ROUND) for record in records
        ),
        "sae_descriptors": sum(
            bool(record["special_flags"] & SPECIAL_SAE) for record in records
        ),
        "broadcast_descriptors": sum(
            bool(record["special_flags"] & SPECIAL_BROADCAST)
            for record in records
        ),
        "zeroing_allowed_descriptors": sum(
            bool(record["special_flags"] & SPECIAL_ZEROING_ALLOWED)
            for record in records
        ),
        "remove_segment_descriptors": sum(
            bool(record["special_flags"] & SPECIAL_REMOVE_SEGMENT)
            for record in records
        ),
        "operand_size_policy_descriptors": sum(
            record["operand_size_policy"] != 0 for record in records
        ),
    }
    for kind, label in kind_names.items():
        result[label] = sum(operand["kind"] == kind for operand in emitted_operands)
    for bit, label in group_names.items():
        result[label] = sum(
            bool(record["generic_groups"] & (1 << bit)) for record in records
        )
    return result


def generic_groups(record: dict[str, Any]) -> int:
    category = str(record.get("category") or "")
    iclass = str(record.get("iclass") or "")
    groups = 0
    if category == "COND_BR":
        groups |= (1 << 0) | (1 << 7)
    elif category == "UNCOND_BR":
        groups |= 1 << 0
    elif category == "CALL":
        groups |= 1 << 1
    elif category == "RET":
        groups |= (1 << 4) if iclass.startswith("IRET") else (1 << 2)
    elif category == "INTERRUPT":
        groups |= 1 << 3
    elif category == "SYSCALL":
        groups |= 1 << 3
    elif category in {"SYSRET", "FRED"}:
        groups |= 1 << 4
    elif category in {"CMOV", "SETCC", "FCMOV"}:
        groups |= 1 << 7
    if (iclass == "INTO"
            or iclass.startswith(("CCMP", "CTEST"))
            or (iclass.startswith("CMP") and iclass.endswith("XADD"))):
        groups |= 1 << 7
    if iclass == "UIRET":
        groups |= 1 << 4
    if any(
        operand.get("visibility") == "DEFAULT"
        and operand.get("name") == "RELBR"
        for operand in record.get("parsed_operands", [])
    ):
        groups |= 1 << 6
    if int(record.get("cpl", 3)) == 0:
        groups |= 1 << 5
    return groups


def tuple_disp8_scale(
    tuple_name: str | None,
    operand_size: int,
    vector_bytes: int,
    element_bytes: int,
) -> int:
    if tuple_name in {None, "NO_SCALE"}:
        return 1
    fixed = {
        "SCALAR": element_bytes,
        "GSCAT": element_bytes,
        "TUPLE1": element_bytes,
        "TUPLE1_BYTE": 1,
        "TUPLE1_WORD": 2,
        "TUPLE2": element_bytes * 2,
        "TUPLE4": element_bytes * 4,
        "TUPLE8": element_bytes * 8,
        "TUPLE1_4X": element_bytes * 4,
        "MEM128": 16,
        "MOVDDUP": 8,
        "GPR_WRITER_LDOP_D": 4,
        "GPR_WRITER_LDOP_Q": 8,
        "GPR_WRITER_STORE": 8,
        "GPR_WRITER_STORE_BYTE": 1,
        "GPR_WRITER_STORE_WORD": 2,
        "GPR_READER": 8,
        "GPR_READER_BYTE": 1,
        "GPR_READER_WORD": 2,
    }
    if tuple_name in fixed:
        scale = fixed[tuple_name]
    elif tuple_name == "FULL":
        scale = vector_bytes
    elif tuple_name == "HALF":
        scale = vector_bytes // 2
    elif tuple_name == "QUARTER":
        scale = vector_bytes // 4
    elif tuple_name in {"FULLMEM", "HALFMEM", "QUARTERMEM", "EIGHTHMEM"}:
        scale = operand_size
    else:
        raise GenerationError(f"unsupported AVX-512 tuple {tuple_name!r}")
    if scale <= 0 or scale >= 0xFF:
        raise GenerationError(
            f"invalid compressed-displacement scale {scale} for {tuple_name!r}"
        )
    return scale


def variable_broadcast_memory_size(
    tuple_name: str | None,
    vector_bytes: int,
    element_bytes: int,
) -> int:
    """Return the non-broadcast memory footprint for XED width-zero rows.

    XED exports EVEX operands which may either be a vector memory source or a
    scalar broadcast source with fixed width zero.  The tuple carries the
    vector-source footprint; BCRC later selects the element-sized source.
    """

    if tuple_name == "FULL":
        size = vector_bytes
    elif tuple_name == "HALF":
        size = vector_bytes // 2
    elif tuple_name == "QUARTER":
        size = vector_bytes // 4
    else:
        raise GenerationError(
            f"unsupported variable broadcast tuple {tuple_name!r}"
        )
    if size <= 0 or size >= 0xFF or size < element_bytes:
        raise GenerationError(
            f"invalid variable broadcast memory size {size} for {tuple_name!r}"
        )
    return size


def compile_operands(
    record: dict[str, Any], public_register_ids: dict[str, int]
) -> tuple[list[dict[str, int]], int, int]:
    recipes: list[dict[str, int]] = []
    special = 0
    vector_bytes = int(record.get("vl") or 0) // 8
    vsib = VSIB_CLASS_IDS.get(record.get("vsib"))
    if vsib is None:
        raise GenerationError(f"unknown VSIB class {record.get('vsib')!r}")

    for operand in record.get("parsed_operands", []):
        visibility = str(operand.get("visibility") or "")
        if visibility not in {"DEFAULT", "IMPLICIT"}:
            continue
        if (visibility == "IMPLICIT"
                and implicit_operand_policy(record, operand) != "emit"):
            continue
        lookup = operand.get("lookupfn_name")
        name = str(operand.get("name"))
        conversions = set(operand.get("cvt") or [])
        unknown_conversions = conversions - {
            "ZEROSTR", "BCASTSTR", "ROUNDC", "SAESTR",
            "MULTIREG2", "MULTIREG4",
        }
        if unknown_conversions:
            raise GenerationError(
                f"unknown operand conversions {sorted(unknown_conversions)!r} "
                f"in {record['iform']}"
            )
        if "ROUNDC" in conversions:
            special |= SPECIAL_ROUND
        if "SAESTR" in conversions:
            special |= SPECIAL_SAE
        if "ZEROSTR" in conversions:
            special |= SPECIAL_ZEROING_ALLOWED
        if lookup in {"MASK1", "MASKNOT0"}:
            requested = (SPECIAL_MASK_REQUIRED if lookup == "MASKNOT0"
                         else SPECIAL_MASK_OPTIONAL)
            if special & (SPECIAL_MASK_OPTIONAL | SPECIAL_MASK_REQUIRED):
                raise GenerationError(f"multiple EVEX mask operands in {record['iform']}")
            special |= requested
            continue
        if name == "BCAST":
            # XED exposes this as formatter metadata, not a programmer-visible
            # operand.  The memory recipe below carries the literal count.
            continue

        try:
            access = ACCESS_IDS[str(operand.get("rw"))]
        except KeyError as error:
            raise GenerationError(
                f"unknown access {operand.get('rw')!r} in {record['iform']}"
            ) from error
        flags = OPERAND_RECIPE_IMPLICIT if visibility == "IMPLICIT" else 0
        sizes = width_bytes(operand.get("op_widths"))
        source = OPERAND_SOURCE_NONE
        reg_class = REG_CLASS_NONE
        immediate_index = 0
        literal = 0
        element_size = 0
        broadcast_count = 0
        disp_scales = (1, 1, 1)

        if operand.get("type") == "nt_lookup_fn":
            if visibility == "IMPLICIT":
                try:
                    reg_class = {
                        "OrAX": REG_CLASS_GPRV,
                        "OeAX": REG_CLASS_GPRV,
                        "ArAX": REG_CLASS_ADDRESS_GPR,
                    }[str(lookup)]
                except KeyError as error:
                    raise GenerationError(
                        f"unsupported implicit lookup {lookup!r} "
                        f"in {record['iform']}"
                    ) from error
                source = OPERAND_SOURCE_FIXED_ZERO
            else:
                source, reg_class, lookup_flags = lookup_source_and_class(operand)
                flags |= lookup_flags
            kind = OPERAND_KIND_REGISTER
            if reg_class == REG_CLASS_SEGMENT:
                sizes = (2, 2, 2)
            elif reg_class == REG_CLASS_BND:
                # MPX bounds hold two 32-bit bounds outside long mode and
                # two 64-bit bounds in long mode.  XED intentionally leaves
                # this lookup width implicit in parsed_operands.
                sizes = (8, 8, 16)
        elif operand.get("type") == "reg" and visibility == "IMPLICIT":
            register_name = str(operand.get("bits") or "")
            if not register_name.startswith("XED_REG_"):
                raise GenerationError(
                    f"malformed implicit register {register_name!r} "
                    f"in {record['iform']}"
                )
            public_name = register_name[len("XED_REG_"):]
            try:
                literal = public_register_ids[public_name]
            except KeyError as error:
                raise GenerationError(
                    f"implicit register {register_name!r} has no public ID "
                    f"in {record['iform']}"
                ) from error
            kind = OPERAND_KIND_REGISTER
            source = OPERAND_SOURCE_FIXED_REGISTER
        elif operand.get("type") == "imm_const" and name in {"MEM0", "AGEN"}:
            kind = OPERAND_KIND_MEMORY
            source = (OPERAND_SOURCE_ABSOLUTE_MEMORY
                      if "MEMDISPv()" in str(record.get("pattern", ""))
                      else OPERAND_SOURCE_MODRM_MEMORY)
            if name == "AGEN":
                flags |= OPERAND_RECIPE_ADDRESS_ONLY
                sizes = (2, 4, 8)
            element_width = operand.get("element_width") or {}
            element_bits = int(element_width.get("fixed") or 0)
            tuple_element_size = (element_bits + 7) // 8 if element_bits > 0 else 0
            if "BCASTSTR" in conversions:
                if not vector_bytes or not tuple_element_size:
                    raise GenerationError(
                        f"broadcast lacks fixed vector/element width in {record['iform']}"
                    )
                if tuple_element_size >= 0xFF:
                    raise GenerationError(
                        f"broadcast element is too large in {record['iform']}"
                    )
                element_size = tuple_element_size
                broadcast_count = vector_bytes // element_size
                if broadcast_count not in {2, 4, 8, 16, 32, 64}:
                    raise GenerationError(
                        f"unsupported broadcast count {broadcast_count} in {record['iform']}"
                    )
                flags |= OPERAND_RECIPE_BROADCAST
                special |= SPECIAL_BROADCAST
                if (operand.get("op_widths") or {}).get("fixed") == 0:
                    memory_size = variable_broadcast_memory_size(
                        record.get("avx512_tuple"),
                        vector_bytes,
                        tuple_element_size,
                    )
                    sizes = (memory_size, memory_size, memory_size)
            tuple_name = record.get("avx512_tuple")
            disp_scales = tuple(
                tuple_disp8_scale(
                    tuple_name, size, vector_bytes, tuple_element_size)
                if size != 0xFF else 1
                for size in sizes
            )
        elif (operand.get("type") == "imm_const"
              and visibility == "IMPLICIT"):
            kind = OPERAND_KIND_LITERAL_IMMEDIATE
            # The public ABI uses size zero for a syntax-visible constant
            # which consumes no encoded immediate bytes (for example the
            # implicit count in ROL r32, 1).
            sizes = (0, 0, 0)
            literal = parse_integer(str(operand.get("bits")))
            if literal != 1:
                raise GenerationError(
                    f"implicit syntax literal {literal} is not representable "
                    f"in {record['iform']}"
                )
        elif operand.get("type") == "imm_const" and name in {
            "IMM0", "IMM1", "RELBR", "ABSBR", "PTR"
        }:
            immediate_index = immediate_operand_index(record, name)
            immediate_actions = [
                (recipe, token)
                for recipe, token in encoded_immediate_actions(record)
                if recipe != IMMEDIATE_RECIPES["MEMDISPv()"]
            ]
            immediate_token = immediate_actions[immediate_index][1]
            if name == "RELBR":
                kind = OPERAND_KIND_RELATIVE
                flags |= OPERAND_RECIPE_SIGNED
            elif name == "ABSBR":
                kind = OPERAND_KIND_ABSOLUTE_BRANCH
            elif name == "PTR":
                kind = OPERAND_KIND_FAR_POINTER
            else:
                kind = OPERAND_KIND_IMMEDIATE
                if immediate_token.startswith("SIMM") \
                        or immediate_token == "SE_IMM8()":
                    flags |= OPERAND_RECIPE_SIGNED
        else:
            raise GenerationError(
                f"unsupported visible operand {operand!r} in {record['iform']}"
            )
        recipes.append({
            "kind": kind,
            "source": source,
            "reg_class": reg_class,
            "access": access,
            "size16": sizes[0],
            "size32": sizes[1],
            "size64": sizes[2],
            "flags": flags,
            "immediate_index": immediate_index,
            "element_size": element_size,
            "broadcast_count": broadcast_count,
            "disp_scale16": disp_scales[0],
            "disp_scale32": disp_scales[1],
            "disp_scale64": disp_scales[2],
            "literal": literal,
        })
    if len(recipes) > 5:
        raise GenerationError(f"more than five ABI operands in {record['iform']}")
    if (special & SPECIAL_ZEROING_ALLOWED) != 0 \
            and (special & (SPECIAL_MASK_OPTIONAL | SPECIAL_MASK_REQUIRED)) == 0:
        raise GenerationError(
            f"zeroing annotation lacks a mask operand in {record['iform']}"
        )
    return recipes, special, vsib


def compile_record(
    record: dict[str, Any], public_register_ids: dict[str, int],
    attributes: str = ""
) -> dict[str, Any]:
    pattern = str(record.get("pattern", ""))
    tokens = pattern.split()
    space = str(record["encoding_space"])
    if space not in SPACE_IDS:
        raise GenerationError(f"unknown encoding space {space!r}")
    opcode = int(str(record["opcode_base16"]), 0)
    opcode_mask, opcode_value = partial_opcode_mask(tokens, opcode)
    if bool(record.get("partial_opcode")) != (opcode_mask != 0xFF):
        raise GenerationError(f"partial-opcode metadata disagrees for {record['iform']}")

    mode_mask = values_mask(record.get("mode_restriction"), MODE_BITS)
    easz_mask = values_mask(record.get("easz_list"), EASZ_BITS)
    mod_mask = list_mask(record.get("mod_required"), 4)
    reg_mask = list_mask(record.get("reg_required"), 8)
    rm_mask = list_mask(
        None if record.get("rm_required") is None else [record["rm_required"]], 8
    )
    predicates: list[tuple[int, int, int]] = []
    immediate: list[int] = []
    flags = 0
    pattern_special_flags = 0
    operand_size_policy = 0
    has_modrm_encoding = bool(record.get("has_modrm")) or any(
        token == "MODRM()"
        or re.match(r"(?:MOD|REG|RM)\[", token)
        or re.match(r"(?:MOD|RM)!?=", token)
        for token in tokens
    )
    if has_modrm_encoding:
        flags |= FLAG_HAS_MODRM
    if record.get("undocumented"):
        flags |= FLAG_UNDOCUMENTED
    if record.get("default_64b"):
        flags |= FLAG_DEFAULT_64
    if space == "legacy" and int(record["map"]) == 4:
        flags |= FLAG_MAP4_SELECTOR

    seen_functions: set[str] = set()
    for token in tokens:
        if re.fullmatch(r"0x[0-9A-Fa-f]+", token):
            continue
        if re.fullmatch(r"0b[01]+_[01]+", token):
            continue
        if token in IMMEDIATE_RECIPES:
            immediate.append(IMMEDIATE_RECIPES[token])
            continue
        if token.endswith("()"):
            seen_functions.add(token)
            if token == "EVAPX()":
                flags |= FLAG_EVAPX
            elif token == "EVAPX_SCC()":
                flags |= FLAG_EVAPX_SCC
            elif token == "EVEXR4_ONE()":
                # In the base AVX-512 decode graph this nonterminal requires
                # REXR4=0.  XED's APX extension adds REXR4=1 when APX is
                # enabled, allowing an existing EVEX instruction to address
                # R16-R31.  Preserve that conditional relation for runtime
                # admission instead of incorrectly freezing either value.
                pattern_special_flags |= SPECIAL_EVEX_R4_APX
            elif token == "SAE()":
                predicates.append((FIELD_IDS["BCRC"], 0, 1))
            elif token == "REMOVE_SEGMENT()":
                pattern_special_flags |= SPECIAL_REMOVE_SEGMENT
            elif token == "IMMUNE66_LOOP64()":
                operand_size_policy |= OPERAND_SIZE_IMMUNE66_LOOP64
            elif token == "CR_WIDTH()":
                operand_size_policy |= OPERAND_SIZE_CR_WIDTH
            elif token == "IMMUNE_REXW()":
                operand_size_policy |= OPERAND_SIZE_IMMUNE_REXW
            elif token in {"IGNORE66()", "REFINING66()"}:
                operand_size_policy |= OPERAND_SIZE_IGNORE66
            elif token == "IMMUNE66()":
                operand_size_policy |= OPERAND_SIZE_IMMUNE66
            elif token == "FORCE64()":
                operand_size_policy |= OPERAND_SIZE_FORCE64
            elif token not in IGNORED_FUNCTIONS:
                raise GenerationError(
                    f"unclassified XED pattern function {token!r} in {record['iform']}"
                )
            continue
        bracket = re.fullmatch(r"(MOD|REG|RM|SRM)\[([^]]+)\]", token)
        if bracket:
            field, value = bracket.groups()
            if field == "MOD":
                # MOD[mm] names the two input bits; MOD!=3 is a separate
                # predicate when a memory form is required.
                expected = 1 << 3 if value == "0b11" else 0x0F
                mod_mask &= expected
                if mod_mask == 0:
                    raise GenerationError(f"contradictory MOD mask in {record['iform']}")
            elif field == "REG":
                if value == "rrr":
                    expected = 0xFF
                elif value == "1-7":
                    expected = 0xFE
                else:
                    expected = 1 << parse_integer(value)
                reg_mask &= expected
                if reg_mask == 0:
                    raise GenerationError(f"contradictory REG mask in {record['iform']}")
            elif field == "RM":
                expected = 0xFF if value == "nnn" else 1 << parse_integer(value)
                rm_mask &= expected
                if rm_mask == 0:
                    raise GenerationError(f"contradictory RM mask in {record['iform']}")
            elif field == "SRM" and value != "rrr":
                predicates.append((FIELD_IDS["SRM"], 0, parse_integer(value)))
            continue
        assignment = re.fullmatch(r"([A-Z0-9_]+)(!?=)(.+)", token)
        if assignment:
            field, op, raw_value = assignment.groups()
            value = parse_integer(raw_value)
            if field in IGNORED_ASSIGNMENTS:
                if (field == "SKIP_OSZ" and value == 1
                        and space == "legacy"):
                    if op != "=":
                        raise GenerationError(
                            f"unexpected {token!r} in {record['iform']}"
                        )
                    operand_size_policy |= OPERAND_SIZE_IGNORE66
                continue
            if field in DIRECT_ASSIGNMENTS:
                if field == "MOD":
                    mod_mask = combine_mask(mod_mask, op, value, 4, field)
                elif field == "RM":
                    rm_mask = combine_mask(rm_mask, op, value, 8, field)
                elif field == "MAP" and value != int(record["map"]):
                    raise GenerationError(f"MAP metadata mismatch in {record['iform']}")
                elif field == "VEXVALID":
                    expected = {"vex": 1, "evex": 2, "xop": 3}.get(space, 0)
                    if op != "=" or value != expected:
                        raise GenerationError(f"VEXVALID mismatch in {record['iform']}")
                continue
            if field not in FIELD_IDS:
                raise GenerationError(
                    f"unclassified XED pattern assignment {field!r} in {record['iform']}"
                )
            predicates.append((FIELD_IDS[field], 0 if op == "=" else 1, value))
            continue
        raise GenerationError(f"unclassified XED pattern token {token!r} in {record['iform']}")

    if len(immediate) > 2:
        raise GenerationError(f"more than two immediate actions in {record['iform']}")
    immediate += [0] * (2 - len(immediate))

    rex2 = str(record.get("rex2_restriction", ""))
    if rex2 == "REQUIRED":
        predicates.append((FIELD_IDS["REX2"], 0, 1))
    elif rex2 == "PROHIBITED":
        predicates.append((FIELD_IDS["REX2"], 0, 0))
    elif rex2:
        raise GenerationError(f"unknown REX2 restriction {rex2!r}")

    # Native APX EVEX records use EVAPX/EVAPX_SCC to reinterpret EVEX fields.
    # U=1 and the low mask relationship are architectural requirements even
    # when the expanded XED pattern leaves them inside the nonterminal.  The
    # native APX maps are not limited to map 4 (CMPCCXADD, for example, is in
    # map 2), so the map restriction belongs in the descriptor predicates,
    # not in the runtime admission rule.
    if flags & (FLAG_EVAPX | FLAG_EVAPX_SCC):
        predicates.append((FIELD_IDS["UBIT"], 0, 1))

    # Canonicalize exact duplicate predicates, retaining contradictions as
    # separate entries for the runtime to reject rather than weakening them.
    predicates = sorted(set(predicates))
    specificity = (
        len(predicates)
        + (4 - mod_mask.bit_count())
        + (8 - reg_mask.bit_count())
        + (8 - rm_mask.bit_count())
        + (3 - mode_mask.bit_count())
        + (3 - easz_mask.bit_count())
        + (1 if flags & FLAG_HAS_MODRM else 0)
    )
    if specificity > 255:
        raise GenerationError("specificity does not fit uint8_t")
    operands, special_flags, vsib_class = compile_operands(
        record, public_register_ids
    )
    special_flags |= pattern_special_flags
    if "DEFAULT_FLAGS" in {
            value.strip() for value in attributes.split(",") if value.strip()
    }:
        special_flags |= SPECIAL_DEFAULT_FLAGS
    if "MASK_AS_CONTROL" in {
            value.strip() for value in attributes.split(",") if value.strip()
    }:
        special_flags |= SPECIAL_MASK_AS_CONTROL
    return {
        "space": SPACE_IDS[space],
        "map": int(record["map"]),
        "opcode_mask": opcode_mask,
        "opcode_value": opcode_value,
        "mode_mask": mode_mask,
        "easz_mask": easz_mask,
        "mod_mask": mod_mask,
        "reg_mask": reg_mask,
        "rm_mask": rm_mask,
        "flags": flags,
        "immediate0": immediate[0],
        "immediate1": immediate[1],
        "predicates": predicates,
        "specificity": specificity,
        "operands": operands,
        "special_flags": special_flags,
        "vsib_class": vsib_class,
        "generic_groups": generic_groups(record),
        "status_flags": status_flag_metadata(record),
        "operand_size_policy": operand_size_policy,
        "source_order": 0,
    }


def load_joined_records(
    xed_db: Path,
    descriptors_path: Path,
    families_path: Path,
    public_register_ids: dict[str, int],
) -> tuple[list[dict[str, Any]], list[dict[str, str]], dict[str, Any]]:
    with xed_db.open("r", encoding="utf-8") as stream:
        document = json.load(stream)
    records = document.get("Instructions") or []
    if len(records) != EXPECTED_DESCRIPTOR_COUNT:
        raise GenerationError(
            f"expected {EXPECTED_DESCRIPTOR_COUNT} XED records, got {len(records)}"
        )
    descriptor_rows = read_tsv(descriptors_path)
    family_rows = read_tsv(families_path)
    if len(descriptor_rows) != len(records) or len(family_rows) != len(records):
        raise GenerationError("descriptor/family catalog length mismatch")
    by_source_order = {int(row["source_order"]): row for row in descriptor_rows}
    if len(by_source_order) != len(records):
        raise GenerationError("source_order is not one-to-one")
    families = {int(row["descriptor_index"]): row for row in family_rows}
    if len(families) != len(records):
        raise GenerationError("descriptor family index is not one-to-one")

    compiled: list[dict[str, Any] | None] = [None] * len(records)
    for source_order, record in enumerate(records):
        row = by_source_order.get(source_order)
        if row is None:
            raise GenerationError(f"missing descriptor source_order {source_order}")
        descriptor_index = int(row["descriptor_index"])
        family = families[descriptor_index]
        validations = {
            "iform": str(record["iform"]),
            "iclass": str(record["iclass"]),
            "encoding_space": str(record["encoding_space"]),
            "map": str(int(record["map"])),
            "opcode": str(int(str(record["opcode_base16"]), 0)),
            "pattern_digest": digest_value(record.get("pattern")),
            "record_digest": digest_value(record),
        }
        for field, expected in validations.items():
            if row[field] != expected:
                raise GenerationError(
                    f"descriptor {descriptor_index} {field} mismatch: "
                    f"{row[field]!r} != {expected!r}"
                )
        if (
            family["iform_id"] != row["iform_id"]
            or family["name_id"] != row["iclass_id"]
            or family["iclass"] != row["iclass"]
            or family["isa_set"] != row["isa_set"]
        ):
            raise GenerationError(f"descriptor family join mismatch at {descriptor_index}")
        item = compile_record(
            record, public_register_ids, str(row.get("attributes") or "")
        )
        item["descriptor_index"] = descriptor_index
        item["source_order"] = source_order
        item["iform_id"] = int(family["iform_id"])
        item["name_id"] = int(family["name_id"])
        item["group_id"] = int(family["group_id"])
        item["decode_bit_id"] = (
            0xFFFF
            if family["decode_bit_id"] == "none"
            else int(family["decode_bit_id"])
        )
        if item["decode_bit_id"] != 0xFFFF and item["decode_bit_id"] >= 512:
            raise GenerationError(
                f"descriptor {descriptor_index} decode bit exceeds public capacity"
            )
        compiled[descriptor_index] = item
    if any(item is None for item in compiled):
        raise GenerationError("compiled descriptor index has holes")
    return [item for item in compiled if item is not None], family_rows, document


def c_rows(declaration: str, rows: list[str]) -> list[str]:
    return [declaration + " = {", *(f"    {row}," for row in rows), "};", ""]


def emit_include(path: Path, records: list[dict[str, Any]]) -> dict[str, int]:
    predicates: list[tuple[int, int, int]] = []
    operand_rows: list[str] = []
    descriptor_rows: list[str] = []
    for record in records:
        first = len(predicates)
        first_operand = len(operand_rows)
        predicates.extend(record["predicates"])
        for operand in record["operands"]:
            operand_rows.append(
                "{" + ", ".join(
                    f"UINT8_C({operand[field]})"
                    for field in (
                        "kind", "source", "reg_class", "access",
                        "size16", "size32", "size64", "flags",
                        "immediate_index", "element_size", "broadcast_count",
                        "disp_scale16", "disp_scale32", "disp_scale64",
                    )
                ) + ", UINT16_C(" + str(operand["literal"]) + ")}"
            )
        descriptor_rows.append(
            "{" + ", ".join(
                [
                    f"UINT32_C({first})",
                    f"UINT32_C({first_operand})",
                    f"UINT16_C({record['source_order']})",
                    f"UINT16_C({record['iform_id']})",
                    f"UINT16_C({record['name_id']})",
                    f"UINT16_C({record['group_id']})",
                    f"UINT16_C({record['decode_bit_id']})",
                    f"UINT16_C({record['generic_groups']})",
                    f"UINT8_C({len(record['predicates'])})",
                    f"UINT8_C({len(record['operands'])})",
                    f"UINT8_C({record['mode_mask']})",
                    f"UINT8_C({record['easz_mask']})",
                    f"UINT8_C({record['mod_mask']})",
                    f"UINT8_C({record['reg_mask']})",
                    f"UINT8_C({record['rm_mask']})",
                    f"UINT8_C({record['flags']})",
                    f"UINT8_C({record['immediate0']})",
                    f"UINT8_C({record['immediate1']})",
                    f"UINT8_C({record['specificity']})",
                    f"UINT16_C({record['special_flags']})",
                    f"UINT8_C({record['vsib_class']})",
                    f"UINT8_C({record['status_flags']})",
                    f"UINT8_C({record['operand_size_policy']})",
                    "UINT8_C(0)",
                ]
            ) + "}"
        )

    # Expand partial opcodes into the lookup spans while keeping one canonical
    # descriptor row per XED record.
    bucket_members: dict[tuple[int, int, int], list[int]] = {}
    for index, record in enumerate(records):
        for opcode in range(256):
            if opcode & record["opcode_mask"] == record["opcode_value"]:
                bucket_members.setdefault(
                    (record["space"], record["map"], opcode), []
                ).append(index)
    bucket_keys = sorted(bucket_members)
    bucket_refs: list[int] = []
    bucket_rows: list[str] = []
    for space, map_id, opcode in bucket_keys:
        members = bucket_members[(space, map_id, opcode)]
        first = len(bucket_refs)
        bucket_refs.extend(members)
        bucket_rows.append(
            "{" + ", ".join(
                [
                    f"UINT32_C({first})",
                    f"UINT16_C({len(members)})",
                    f"UINT8_C({space})",
                    f"UINT8_C({map_id})",
                    f"UINT8_C({opcode})",
                    "UINT8_C(0)",
                ]
            ) + "}"
        )
    if max(len(values) for values in bucket_members.values()) > 0xFFFF:
        raise GenerationError("bucket count does not fit uint16_t")

    lines = [
        "/* Generated numeric-only XED recognition tables. Do not edit. */",
        "#ifndef CDISASM_X86_ISA_DECODE_GENERATED_INC",
        "#define CDISASM_X86_ISA_DECODE_GENERATED_INC",
        "#include <stdint.h>",
        f"#define CDISASM_X86_GEN_RECOGNITION_DESCRIPTOR_COUNT UINT32_C({len(records)})",
        f"#define CDISASM_X86_GEN_RECOGNITION_PREDICATE_COUNT UINT32_C({len(predicates)})",
        f"#define CDISASM_X86_GEN_RECOGNITION_OPERAND_COUNT UINT32_C({len(operand_rows)})",
        f"#define CDISASM_X86_GEN_RECOGNITION_BUCKET_COUNT UINT32_C({len(bucket_keys)})",
        f"#define CDISASM_X86_GEN_RECOGNITION_BUCKET_REF_COUNT UINT32_C({len(bucket_refs)})",
        "#define CDISASM_X86_GEN_DECODE_BIT_NONE UINT16_C(65535)",
        "#define CDISASM_X86_GEN_SPACE_LEGACY UINT8_C(0)",
        "#define CDISASM_X86_GEN_SPACE_VEX UINT8_C(1)",
        "#define CDISASM_X86_GEN_SPACE_EVEX UINT8_C(2)",
        "#define CDISASM_X86_GEN_SPACE_XOP UINT8_C(3)",
        "#define CDISASM_X86_GEN_FLAG_HAS_MODRM UINT8_C(1)",
        "#define CDISASM_X86_GEN_FLAG_EVAPX UINT8_C(2)",
        "#define CDISASM_X86_GEN_FLAG_EVAPX_SCC UINT8_C(4)",
        "#define CDISASM_X86_GEN_FLAG_UNDOCUMENTED UINT8_C(8)",
        "#define CDISASM_X86_GEN_FLAG_DEFAULT_64 UINT8_C(16)",
        "#define CDISASM_X86_GEN_FLAG_MAP4_SELECTOR UINT8_C(32)",
        "#define CDISASM_X86_GEN_SPECIAL_MASK_OPTIONAL UINT8_C(1)",
        "#define CDISASM_X86_GEN_SPECIAL_MASK_REQUIRED UINT8_C(2)",
        "#define CDISASM_X86_GEN_SPECIAL_ROUND UINT8_C(4)",
        "#define CDISASM_X86_GEN_SPECIAL_SAE UINT8_C(8)",
        "#define CDISASM_X86_GEN_SPECIAL_BROADCAST UINT8_C(16)",
        "#define CDISASM_X86_GEN_SPECIAL_EVEX_R4_APX UINT8_C(32)",
        "#define CDISASM_X86_GEN_SPECIAL_ZEROING_ALLOWED UINT8_C(64)",
        "#define CDISASM_X86_GEN_SPECIAL_REMOVE_SEGMENT UINT8_C(128)",
        "#define CDISASM_X86_GEN_SPECIAL_DEFAULT_FLAGS UINT16_C(256)",
        "#define CDISASM_X86_GEN_SPECIAL_MASK_AS_CONTROL UINT16_C(512)",
        "#define CDISASM_X86_GEN_STATUS_READS_FLAGS UINT8_C(1)",
        "#define CDISASM_X86_GEN_STATUS_WRITES_FLAGS UINT8_C(2)",
        "#define CDISASM_X86_GEN_SIZE_IMMUNE66_LOOP64 UINT8_C(1)",
        "#define CDISASM_X86_GEN_SIZE_CR_WIDTH UINT8_C(2)",
        "#define CDISASM_X86_GEN_SIZE_IMMUNE_REXW UINT8_C(4)",
        "#define CDISASM_X86_GEN_SIZE_IGNORE66 UINT8_C(8)",
        "#define CDISASM_X86_GEN_SIZE_FORCE64 UINT8_C(16)",
        "#define CDISASM_X86_GEN_SIZE_IMMUNE66 UINT8_C(32)",
        "#define CDISASM_X86_GEN_OPERAND_REGISTER UINT8_C(1)",
        "#define CDISASM_X86_GEN_OPERAND_MEMORY UINT8_C(2)",
        "#define CDISASM_X86_GEN_OPERAND_IMMEDIATE UINT8_C(3)",
        "#define CDISASM_X86_GEN_OPERAND_RELATIVE UINT8_C(4)",
        "#define CDISASM_X86_GEN_OPERAND_ABSOLUTE_BRANCH UINT8_C(5)",
        "#define CDISASM_X86_GEN_OPERAND_FAR_POINTER UINT8_C(6)",
        "#define CDISASM_X86_GEN_OPERAND_LITERAL_IMMEDIATE UINT8_C(7)",
        "#define CDISASM_X86_GEN_SOURCE_NONE UINT8_C(0)",
        "#define CDISASM_X86_GEN_SOURCE_REG UINT8_C(1)",
        "#define CDISASM_X86_GEN_SOURCE_REG_HIGH UINT8_C(2)",
        "#define CDISASM_X86_GEN_SOURCE_RM UINT8_C(3)",
        "#define CDISASM_X86_GEN_SOURCE_RM_HIGH UINT8_C(4)",
        "#define CDISASM_X86_GEN_SOURCE_VVVV UINT8_C(5)",
        "#define CDISASM_X86_GEN_SOURCE_VVVV_HIGH UINT8_C(6)",
        "#define CDISASM_X86_GEN_SOURCE_OPCODE UINT8_C(7)",
        "#define CDISASM_X86_GEN_SOURCE_IMMEDIATE_HIGH UINT8_C(8)",
        "#define CDISASM_X86_GEN_SOURCE_MODRM_MEMORY UINT8_C(9)",
        "#define CDISASM_X86_GEN_SOURCE_ABSOLUTE_MEMORY UINT8_C(10)",
        "#define CDISASM_X86_GEN_SOURCE_FIXED_ZERO UINT8_C(11)",
        "#define CDISASM_X86_GEN_SOURCE_FIXED_REGISTER UINT8_C(12)",
        "#define CDISASM_X86_GEN_REG_NONE UINT8_C(0)",
        "#define CDISASM_X86_GEN_REG_GPR8 UINT8_C(1)",
        "#define CDISASM_X86_GEN_REG_GPR16 UINT8_C(2)",
        "#define CDISASM_X86_GEN_REG_GPR32 UINT8_C(3)",
        "#define CDISASM_X86_GEN_REG_GPR64 UINT8_C(4)",
        "#define CDISASM_X86_GEN_REG_GPRV UINT8_C(5)",
        "#define CDISASM_X86_GEN_REG_GPRY UINT8_C(6)",
        "#define CDISASM_X86_GEN_REG_GPRZ UINT8_C(7)",
        "#define CDISASM_X86_GEN_REG_ADDRESS_GPR UINT8_C(8)",
        "#define CDISASM_X86_GEN_REG_MMX UINT8_C(9)",
        "#define CDISASM_X86_GEN_REG_XMM UINT8_C(10)",
        "#define CDISASM_X86_GEN_REG_YMM UINT8_C(11)",
        "#define CDISASM_X86_GEN_REG_ZMM UINT8_C(12)",
        "#define CDISASM_X86_GEN_REG_MASK UINT8_C(13)",
        "#define CDISASM_X86_GEN_REG_BND UINT8_C(14)",
        "#define CDISASM_X86_GEN_REG_TMM UINT8_C(15)",
        "#define CDISASM_X86_GEN_REG_X87 UINT8_C(16)",
        "#define CDISASM_X86_GEN_REG_SEGMENT UINT8_C(17)",
        "#define CDISASM_X86_GEN_REG_CR UINT8_C(18)",
        "#define CDISASM_X86_GEN_REG_DR UINT8_C(19)",
        "#define CDISASM_X86_GEN_OPERAND_SIGNED UINT8_C(1)",
        "#define CDISASM_X86_GEN_OPERAND_ADDRESS_ONLY UINT8_C(2)",
        "#define CDISASM_X86_GEN_OPERAND_BROADCAST UINT8_C(4)",
        "#define CDISASM_X86_GEN_OPERAND_NO_RSP UINT8_C(8)",
        "#define CDISASM_X86_GEN_OPERAND_IMPLICIT UINT8_C(16)",
        "#define CDISASM_X86_GEN_VSIB_NONE UINT8_C(0)",
        "#define CDISASM_X86_GEN_VSIB_XMM UINT8_C(1)",
        "#define CDISASM_X86_GEN_VSIB_YMM UINT8_C(2)",
        "#define CDISASM_X86_GEN_VSIB_ZMM UINT8_C(3)",
        "#define CDISASM_X86_GEN_IMM_NONE UINT8_C(0)",
        "#define CDISASM_X86_GEN_IMM_8 UINT8_C(1)",
        "#define CDISASM_X86_GEN_IMM_16 UINT8_C(2)",
        "#define CDISASM_X86_GEN_IMM_32 UINT8_C(3)",
        "#define CDISASM_X86_GEN_IMM_64 UINT8_C(4)",
        "#define CDISASM_X86_GEN_IMM_V UINT8_C(5)",
        "#define CDISASM_X86_GEN_IMM_Z UINT8_C(6)",
        "#define CDISASM_X86_GEN_REL_8 UINT8_C(7)",
        "#define CDISASM_X86_GEN_REL_Z UINT8_C(8)",
        "#define CDISASM_X86_GEN_REL_32 UINT8_C(9)",
        "#define CDISASM_X86_GEN_REL_64 UINT8_C(10)",
        "#define CDISASM_X86_GEN_MEMDISP_V UINT8_C(11)",
        "#define CDISASM_X86_GEN_FIELD_MODE UINT8_C(0)",
        "#define CDISASM_X86_GEN_FIELD_EASZ UINT8_C(1)",
        "#define CDISASM_X86_GEN_FIELD_REP UINT8_C(2)",
        "#define CDISASM_X86_GEN_FIELD_OSZ UINT8_C(3)",
        "#define CDISASM_X86_GEN_FIELD_ASZ UINT8_C(4)",
        "#define CDISASM_X86_GEN_FIELD_LOCK UINT8_C(5)",
        "#define CDISASM_X86_GEN_FIELD_REXW UINT8_C(6)",
        "#define CDISASM_X86_GEN_FIELD_REX2 UINT8_C(7)",
        "#define CDISASM_X86_GEN_FIELD_REXR UINT8_C(8)",
        "#define CDISASM_X86_GEN_FIELD_REXR4 UINT8_C(9)",
        "#define CDISASM_X86_GEN_FIELD_REXB UINT8_C(10)",
        "#define CDISASM_X86_GEN_FIELD_REXB4 UINT8_C(11)",
        "#define CDISASM_X86_GEN_FIELD_VEX_PREFIX UINT8_C(12)",
        "#define CDISASM_X86_GEN_FIELD_VL UINT8_C(13)",
        "#define CDISASM_X86_GEN_FIELD_UBIT UINT8_C(14)",
        "#define CDISASM_X86_GEN_FIELD_BCRC UINT8_C(15)",
        "#define CDISASM_X86_GEN_FIELD_ZEROING UINT8_C(16)",
        "#define CDISASM_X86_GEN_FIELD_MASK UINT8_C(17)",
        "#define CDISASM_X86_GEN_FIELD_ND UINT8_C(18)",
        "#define CDISASM_X86_GEN_FIELD_NF UINT8_C(19)",
        "#define CDISASM_X86_GEN_FIELD_VEXDEST3 UINT8_C(20)",
        "#define CDISASM_X86_GEN_FIELD_VEXDEST210 UINT8_C(21)",
        "#define CDISASM_X86_GEN_FIELD_VEXDEST4 UINT8_C(22)",
        "#define CDISASM_X86_GEN_FIELD_SCC UINT8_C(23)",
        "#define CDISASM_X86_GEN_FIELD_SRM UINT8_C(24)",
        "#define CDISASM_X86_GEN_FIELD_NEED_SIB UINT8_C(25)",
        "typedef struct cdisasm_x86_gen_predicate {",
        "    uint8_t field, not_equal, value, reserved;",
        "} cdisasm_x86_gen_predicate;",
        "typedef struct cdisasm_x86_gen_operand {",
        "    uint8_t kind, source, reg_class, access;",
        "    uint8_t size16, size32, size64, flags;",
        "    uint8_t immediate_index, element_size, broadcast_count;",
        "    uint8_t disp_scale16, disp_scale32, disp_scale64;",
        "    uint16_t literal;",
        "} cdisasm_x86_gen_operand;",
        "typedef struct cdisasm_x86_gen_descriptor {",
        "    uint32_t first_predicate, first_operand;",
        "    uint16_t source_order;",
        "    uint16_t iform_id, name_id, group_id, decode_bit_id;",
        "    uint16_t generic_groups;",
        "    uint8_t predicate_count, operand_count, mode_mask, easz_mask;",
        "    uint8_t mod_mask, reg_mask, rm_mask, flags;",
        "    uint8_t immediate0, immediate1, specificity;",
        "    uint16_t special_flags;",
        "    uint8_t vsib_class, status_flags, operand_size_policy, reserved;",
        "} cdisasm_x86_gen_descriptor;",
        "typedef struct cdisasm_x86_gen_bucket {",
        "    uint32_t first_descriptor;",
        "    uint16_t descriptor_count;",
        "    uint8_t space, map, opcode, reserved;",
        "} cdisasm_x86_gen_bucket;",
        "",
    ]
    lines += c_rows(
        f"static const cdisasm_x86_gen_predicate cdisasm_x86_gen_predicates[{len(predicates)}]",
        [
            f"{{UINT8_C({field}), UINT8_C({not_equal}), UINT8_C({value}), UINT8_C(0)}}"
            for field, not_equal, value in predicates
        ],
    )
    lines += c_rows(
        f"static const cdisasm_x86_gen_operand cdisasm_x86_gen_operands[{len(operand_rows)}]",
        operand_rows,
    )
    lines += c_rows(
        f"static const cdisasm_x86_gen_descriptor cdisasm_x86_gen_descriptors[{len(records)}]",
        descriptor_rows,
    )
    lines += c_rows(
        f"static const cdisasm_x86_gen_bucket cdisasm_x86_gen_buckets[{len(bucket_rows)}]",
        bucket_rows,
    )
    lines += c_rows(
        f"static const uint16_t cdisasm_x86_gen_bucket_descriptor_indexes[{len(bucket_refs)}]",
        [f"UINT16_C({index})" for index in bucket_refs],
    )
    lines.extend(["#endif", ""])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="ascii", newline="\n")
    return {
        "descriptors": len(records),
        "predicates": len(predicates),
        "structured_operands": len(operand_rows),
        "buckets": len(bucket_rows),
        "bucket_descriptor_references": len(bucket_refs),
    }


def main() -> int:
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xed-db", type=Path, required=True)
    parser.add_argument(
        "--descriptors",
        type=Path,
        default=script_dir / "generated" / "x86_descriptors.tsv",
    )
    parser.add_argument(
        "--families",
        type=Path,
        default=script_dir / "generated" / "x86_descriptor_families.tsv",
    )
    parser.add_argument(
        "--register-ids",
        type=Path,
        default=repo_root / "include" / "cdisasm" / "cdisasm_x86_ids.h",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=repo_root / "src" / "x86" / "generated" / "cdisasm_x86_isa_decode.inc",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=script_dir / "generated" / "x86_fallback_manifest.json",
    )
    args = parser.parse_args()

    baseline_path = repo_root / "tools" / "coverage" / "baselines.json"
    with baseline_path.open("r", encoding="utf-8") as stream:
        baseline = json.load(stream)["intel_xed"]
    xed_db = args.xed_db.resolve()
    expected_sha = baseline["metadata_export_sha256"]
    actual_sha = digest_file(xed_db)
    if actual_sha != expected_sha:
        raise GenerationError(
            f"XED JSON hash mismatch: expected {expected_sha}, got {actual_sha}"
        )

    register_ids_path = args.register_ids.resolve()
    public_register_ids = read_public_register_ids(register_ids_path)
    records, family_rows, document = load_joined_records(
        xed_db,
        args.descriptors.resolve(),
        args.families.resolve(),
        public_register_ids,
    )
    if document.get("Version") != baseline["ref"]:
        raise GenerationError(
            f"XED version mismatch: {document.get('Version')!r} != {baseline['ref']!r}"
        )
    if len({int(row["iform_id"]) for row in family_rows}) != EXPECTED_IFORM_COUNT:
        raise GenerationError("authoritative family join does not contain 9,001 IFORM IDs")
    counts = emit_include(args.output.resolve(), records)
    counts.update(coverage_counts(document, records))
    manifest = {
        "generator": "tools/isa_codegen/generate_x86_fallback.py",
        "generator_version": GENERATOR_VERSION,
        "generator_sha256": digest_file(Path(__file__).resolve()),
        "baseline_ref": baseline["ref"],
        "baseline_commit": baseline["commit"],
        "xed_db_sha256": actual_sha,
        "descriptor_tsv_sha256": digest_file(args.descriptors.resolve()),
        "descriptor_families_sha256": digest_file(args.families.resolve()),
        "public_register_ids_sha256": digest_file(register_ids_path),
        "output_sha256": digest_file(args.output.resolve()),
        "numeric_only": True,
        "iform_count": EXPECTED_IFORM_COUNT,
        "counts": counts,
        "pattern_contract": {
            "all_tokens_classified": True,
            "all_default_operands_lowered": True,
            "all_selected_implicit_syntax_operands_lowered": True,
            "emitted_operands_structured": True,
            "operand_nonterminals_opaque": False,
            "feature_aliases_selected_by_isa_set_flags": True,
            "mask_round_sae_broadcast_use_instruction_metadata": True,
            "suppressed_and_econd_operands_are_not_displayed": True,
            "implicit_x87_memory_st0_is_canonically_hidden": True,
            "implicit_bsr0_uses_public_register_id": True,
            "multireg_conversions_preserve_one_group_operand": True,
            "compact_export_has_no_register_relation_assertions": True,
        },
    }
    args.manifest.resolve().write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="ascii",
        newline="\n",
    )
    print(
        f"x86 fallback: {counts['descriptors']} descriptors, "
        f"{counts['predicates']} predicates, {counts['buckets']} buckets"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
