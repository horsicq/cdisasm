#!/usr/bin/env python3
"""Generate string-free semantic metadata for every ARM catalog leaf.

The pinned AARCHMRS tree already provides a stable form ID and a source-tree
path for each canonical encoding.  This generator turns the path and canonical
mnemonic into numeric cdisasm groups.  The generated decoder table contains no
text and does not perform mnemonic string matching at run time.

Only properties that are unambiguous from the encoding class are emitted here.
This includes control flow, family flags, and exact raw-bit-dependent AA32
multiple-transfer addressing. Operand access and register classes are handled
by the separate operand compiler; an opaque generated instruction may therefore
carry exact semantic metadata while its operand array is still intentionally
empty.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = REPO_ROOT / "tools/isa_codegen/generated/arm_tree_leaves.tsv"
DEFAULT_OUTPUT = REPO_ROOT / "src/arm/generated/cdisasm_arm_leaf_semantics.inc"
DEFAULT_MANIFEST = (
    REPO_ROOT / "tools/isa_codegen/generated/arm_leaf_semantics_manifest.json"
)

EXPECTED_FORM_COUNT = 6569

GROUP_JUMP = 1 << 0
GROUP_CALL = 1 << 1
GROUP_RETURN = 1 << 2
GROUP_INTERRUPT = 1 << 3
GROUP_INTERRUPT_RETURN = 1 << 4
GROUP_PRIVILEGED = 1 << 5
GROUP_RELATIVE_BRANCH = 1 << 6
GROUP_CONDITIONAL = 1 << 7

FLAG_LINK = 1 << 4
FLAG_SETS_FLAGS = 1 << 0
FLAG_WRITEBACK = 1 << 1
FLAG_PRE_INDEX = 1 << 2
FLAG_POST_INDEX = 1 << 3
FLAG_BYTE = 1 << 5
FLAG_USER_REGISTERS = 1 << 6
FLAG_UNPRIVILEGED = 1 << 7
FLAG_ADDRESS_INCREMENT = 1 << 10
FLAG_ADDRESS_DECREMENT = 1 << 11
FLAG_SIMD = 1 << 12
FLAG_FLOATING_POINT = 1 << 13
FLAG_ATOMIC = 1 << 18
FLAG_ACQUIRE = 1 << 19
FLAG_RELEASE = 1 << 20
FLAG_EXCLUSIVE = 1 << 21
FLAG_SCALABLE_VECTOR = 1 << 22
FLAG_PREDICATED = 1 << 23
FLAG_SME = 1 << 24
FLAG_STREAMING = 1 << 25
FLAG_MATRIX = 1 << 26
FLAG_MEMORY_TAGGING = 1 << 27
FLAG_POINTER_AUTH = 1 << 28
FLAG_ATOMIC_PAIR = 1 << 29

TARGET_NONE = 0
TARGET_A32_BRANCH24 = 1
TARGET_A32_BLX24 = 2
TARGET_T16_CB = 3
TARGET_T16_COND8 = 4
TARGET_T16_BRANCH11 = 5
TARGET_T32_COND = 6
TARGET_T32_BRANCH = 7
TARGET_T32_BL = 8
TARGET_T32_BLX = 9
TARGET_A64_COND19 = 10
TARGET_A64_BRANCH26 = 11
TARGET_A64_COMPARE19 = 12
TARGET_A64_TEST14 = 13
TARGET_A64_COMPARE9 = 14

DYNAMIC_NONE = 0
DYNAMIC_A64_LSE_ORDER = 1
DYNAMIC_A32_GPR_BLOCK = 2
DYNAMIC_T16_GPR_BLOCK = 3
DYNAMIC_T32_GPR_BLOCK = 4
DYNAMIC_AA32_FP_BLOCK = 5


class GenerationError(RuntimeError):
    pass


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def data_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream, dialect="excel-tab"))
    if len(rows) != EXPECTED_FORM_COUNT:
        raise GenerationError(
            f"expected {EXPECTED_FORM_COUNT} ARM forms, found {len(rows)}"
        )
    for index, row in enumerate(rows):
        if int(row["leaf_index"]) != index or int(row["form_id"]) != index + 1:
            raise GenerationError(f"non-contiguous ARM form IDs at row {index}")
    return rows


def classify(row: dict[str, str]) -> tuple[int, int, int, int]:
    mnemonic = row["mnemonic"].upper()
    path = row["source_form_id"].lower()
    assembly = row["assembly_template"]
    assembly_upper = assembly.upper()
    form_key = path.rsplit("/", 1)[-1]
    groups = 0
    flags = 0
    target = TARGET_NONE
    dynamic = DYNAMIC_NONE

    # Architectural-family metadata is derived entirely at generation time.
    # The emitted decoder table remains numeric and the C runtime never
    # searches instruction or path strings.
    if path.startswith("a64/sve/"):
        flags |= FLAG_SCALABLE_VECTOR
        if ("<rule:Pg" in assembly or "<rule:PNg" in assembly
                or "/m" in assembly or "/z" in assembly
                or mnemonic.startswith("WHILE")):
            flags |= FLAG_PREDICATED
        if mnemonic == "RDSVL":
            flags |= FLAG_STREAMING

    if path.startswith("a64/sme/"):
        flags |= FLAG_SME | FLAG_STREAMING
        if "<RULE:Z" in assembly_upper:
            flags |= FLAG_SCALABLE_VECTOR
        if ("<RULE:PG" in assembly_upper
                or "<RULE:PNG" in assembly_upper
                or "<RULE:PN" in assembly_upper
                or "<RULE:PM" in assembly_upper
                or "/M" in assembly_upper or "/Z" in assembly_upper):
            flags |= FLAG_PREDICATED
        if ("<RULE:ZA" in assembly_upper or "<RULE:ZT" in assembly_upper
                or "ZA." in assembly_upper or "ZA[" in assembly_upper
                or "ZT0" in assembly_upper):
            flags |= FLAG_MATRIX

    # Fixed-width packed Advanced SIMD encodings use an ``asimd`` path
    # component.  ``asisd`` is deliberately excluded because it denotes a
    # scalar operation in the SIMD/FP encoding space.
    if (("/asimd" in path and "/asisd" not in path)
            or ("/advsimd" in path and "/advsimdext/fp" not in path)
            or "/simddp/" in path
            or "/asimld" in path):
        flags |= FLAG_SIMD

    # Floating-point arithmetic/conversion is recognizable without guessing
    # from a CPU generation.  Integer Advanced SIMD operations intentionally
    # retain SIMD alone.
    if (mnemonic.startswith("F") and mnemonic != "FIRSTP"
            or (mnemonic.startswith("BF")
                and mnemonic not in {"BFC", "BFI", "BFM"})
            or mnemonic in {"SCVTF", "UCVTF", "VCVT", "VCVTA",
                            "VCVTB", "VCVTM", "VCVTN", "VCVTP",
                            "VCVTR", "VCVTT"}
            or "/vfp" in path or "/fpdp/" in path
            or "/advsimdext/fp" in path):
        flags |= FLAG_FLOATING_POINT

    if mnemonic in {
        "ADDS", "SUBS", "ANDS", "BICS", "CCMN", "CCMP",
        "EORS", "NANDS", "NORS", "ORNS", "ORRS", "FCCMP",
        "FCCMPE", "FCMP", "FCMPE", "RMIF", "CFINV", "XAFLAG",
        "AXFLAG", "SETF8", "SETF16", "BRKAS", "BRKBS", "BRKNS",
        "BRKPAS", "BRKPBS",
        "PTEST", "PTRUES", "RDFFRS",
    } or mnemonic.startswith("WHILE"):
        flags |= FLAG_SETS_FLAGS

    # Addressing-form metadata is encoded in the canonical form path.
    pre_index = ("_pre" in form_key or "spre_" in form_key
        or "/ldst_immpre/" in path or "/ldstpair_pre/" in path
        or ("/ldst_pac/" in path and "_64w_" in form_key)
        or ("/ldapstl_writeback/" in path and mnemonic.startswith("ST")))
    post_index = ("_post" in form_key or "spost_" in form_key
        or "/ldst_immpost/" in path or "/ldstpair_post/" in path
        or ("/ldapstl_writeback/" in path and mnemonic.startswith("LD")))
    if pre_index:
        flags |= FLAG_WRITEBACK | FLAG_PRE_INDEX
    elif post_index:
        flags |= FLAG_WRITEBACK | FLAG_POST_INDEX
    elif (("/memcms/" in path or "/memset" in path)
            and "!" in assembly):
        flags |= FLAG_WRITEBACK
    if "_unpriv" in path or "/ldst_unpriv/" in path:
        flags |= FLAG_UNPRIVILEGED

    # A32/T32 multiple-transfer addressing is entirely encoded by P/U/W (or,
    # for the T16 form, by its architectural implicit IA/writeback rules).
    # Keep that raw-bit interpretation in the numeric decoder instead of
    # inferring it from a displayed alias such as PUSH or VPOP.
    if path.startswith("a32/brblk/ldstm/"):
        dynamic = DYNAMIC_A32_GPR_BLOCK
    elif path.startswith("t32/n/ldstm16/"):
        dynamic = DYNAMIC_T16_GPR_BLOCK
    elif (path.startswith("t32/w/ldstm/")
            and mnemonic in {"STM", "LDM", "STMDB", "LDMDB"}):
        dynamic = DYNAMIC_T32_GPR_BLOCK
    elif ("/sysldst_mov64/ldstsimdfp/" in path
            or "/sysldst_mov64/simdfp_ldst/" in path) and mnemonic in {
                "VSTMDB", "VSTM", "FSTMDBX", "FSTMIAX",
                "VLDMDB", "VLDM", "FLDMDBX", "FLDMIAX",
            }:
        flags |= FLAG_FLOATING_POINT
        dynamic = DYNAMIC_AA32_FP_BLOCK

    if mnemonic in {
        "LDRB", "LDRSB", "STRB", "LDARB", "STLRB", "LDLARB",
        "STLLRB", "LDAXRB", "LDXRB", "STLXRB", "STXRB",
        "LDAPRB", "LDAPURB", "STLURB", "LDAB", "STLB", "LDAEXB",
        "LDREXB", "STLEXB", "STREXB",
    }:
        flags |= FLAG_BYTE

    if ("/addsub_immtags/" in path or "/ldsttags/" in path
            or mnemonic in {"IRG", "GMI"}):
        flags |= FLAG_MEMORY_TAGGING

    if (mnemonic.startswith(("PAC", "AUT", "XPAC", "RETAA", "RETAB",
                             "BRAA", "BRAB", "BLRAA", "BLRAB",
                             "LDRAA", "LDRAB"))):
        flags |= FLAG_POINTER_AUTH

    a64_atomic_path = any(
        component in path
        for component in (
            "/comswap/", "/comswappr/", "/comswap_unpriv/",
            "/comswappr_unpriv/", "/rcwcomswap/", "/rcwcomswappr/",
            "/memop/", "/memop_128/", "/memop_unpriv/", "/ldstord/",
            "/ldstexclr/", "/ldstexclr_unpriv/", "/ldstexclp/",
            "/ldiappstilp/", "/ldapstl_unscaled/",
            "/ldapstl_writeback/",
        )
    )
    aa32_atomic_path = "/sync/ldst_excl/" in path \
        or "/dstd/ldstex" in path or "/dstd/ldastl/" in path
    if a64_atomic_path or aa32_atomic_path:
        flags |= FLAG_ATOMIC
    if mnemonic == "CLREX":
        flags |= FLAG_ATOMIC | FLAG_EXCLUSIVE
    if ("/ldstexclr/" in path or "/ldstexclr_unpriv/" in path
            or "/ldstexclp/" in path or "EX" in mnemonic
            and aa32_atomic_path):
        flags |= FLAG_EXCLUSIVE
    if "/memop_128/" in path or mnemonic in {"LDIAPP", "STILP"}:
        flags |= FLAG_ATOMIC_PAIR

    # These families encode ordering in the canonical mnemonic itself.  The
    # ordinary LSE memory-operation class needs special care: its acquire bit
    # can be suppressed dynamically when Rt is ZR, while release remains
    # unconditional.  Therefore only its release half is recorded here.
    atomic_stem = mnemonic[:-1] if mnemonic.endswith(("B", "H", "T")) \
        else mnemonic
    if ("/comswap" in path or "/rcwcomswap" in path
            or "/memop_128/" in path):
        if atomic_stem.endswith(("A", "AL")):
            flags |= FLAG_ACQUIRE
        if atomic_stem.endswith(("L", "AL")):
            flags |= FLAG_RELEASE
    elif "/memop/" in path or "/memop_unpriv/" in path:
        if mnemonic not in {"LD64B", "ST64B", "ST64BV", "ST64BV0"}:
            dynamic = DYNAMIC_A64_LSE_ORDER
        if atomic_stem.endswith("L"):
            flags |= FLAG_RELEASE
    elif ("/ldstord/" in path or "/ldiappstilp/" in path
            or "/ldapstl_unscaled/" in path
            or "/ldapstl_writeback/" in path):
        if mnemonic.startswith("LD"):
            flags |= FLAG_ACQUIRE
        elif mnemonic.startswith("ST"):
            flags |= FLAG_RELEASE
    elif "/ldstex" in path or aa32_atomic_path:
        if mnemonic.startswith(("LDAX", "LDA")):
            flags |= FLAG_ACQUIRE
        if mnemonic.startswith(("STLX", "STL")):
            flags |= FLAG_RELEASE

    # Synchronous exception-generating instructions.
    if mnemonic in {"SVC", "BRK", "BKPT", "UDF"}:
        groups |= GROUP_INTERRUPT
    elif mnemonic in {"HVC", "SMC", "HLT", "DCPS1", "DCPS2", "DCPS3"}:
        groups |= GROUP_INTERRUPT | GROUP_PRIVILEGED

    # Exception returns are distinct from ordinary subroutine returns.
    if mnemonic in {
        "ERET", "ERETAA", "ERETAB", "DRPS",
        "RFE", "RFEDA", "RFEDB", "RFEIA", "RFEIB",
    }:
        groups |= GROUP_RETURN | GROUP_INTERRUPT_RETURN | GROUP_PRIVILEGED
    elif mnemonic.startswith("RET"):
        groups |= GROUP_RETURN

    if mnemonic in {"SYS", "SYSL", "MSR", "MRS", "SYSP", "MSRR", "MRRS"}:
        if "/control/" in path:
            groups |= GROUP_PRIVILEGED
    if mnemonic in {"SRS", "SRSDA", "SRSDB", "SRSIA", "SRSIB"}:
        groups |= GROUP_PRIVILEGED

    if path.startswith("A64/control/condbranch/".lower()):
        groups |= GROUP_JUMP | GROUP_CONDITIONAL | GROUP_RELATIVE_BRANCH
        target = TARGET_A64_COND19
    elif "/control/compbranch_regs2/" in path \
            or "/control/compbranch_regs/" in path \
            or "/control/compbranch_imm/" in path:
        groups |= GROUP_JUMP | GROUP_CONDITIONAL | GROUP_RELATIVE_BRANCH
        target = TARGET_A64_COMPARE9
    elif "/control/compbranch/" in path:
        groups |= GROUP_JUMP | GROUP_CONDITIONAL | GROUP_RELATIVE_BRANCH
        target = TARGET_A64_COMPARE19
    elif "/control/testbranch/" in path:
        groups |= GROUP_JUMP | GROUP_CONDITIONAL | GROUP_RELATIVE_BRANCH
        target = TARGET_A64_TEST14
    elif "/control/branch_imm/" in path:
        groups |= GROUP_RELATIVE_BRANCH
        target = TARGET_A64_BRANCH26
        if mnemonic == "BL":
            groups |= GROUP_CALL
            flags |= FLAG_LINK
        else:
            groups |= GROUP_JUMP
    elif "/control/branch_reg/" in path:
        if mnemonic.startswith("BLR"):
            groups |= GROUP_CALL
            flags |= FLAG_LINK
        elif mnemonic.startswith("RET") or mnemonic in {"ERET", "ERETAA", "ERETAB", "DRPS"}:
            pass
        elif mnemonic in {"BR", "BRAA", "BRAB", "BRAAZ", "BRABZ"}:
            groups |= GROUP_JUMP

    if path.startswith("a32/"):
        if "/b_imm/" in path:
            groups |= GROUP_RELATIVE_BRANCH
            if mnemonic == "BL":
                groups |= GROUP_CALL
                flags |= FLAG_LINK
                target = TARGET_A32_BRANCH24
            elif mnemonic == "BLX":
                groups |= GROUP_CALL
                flags |= FLAG_LINK
                target = TARGET_A32_BLX24
            else:
                groups |= GROUP_JUMP
                target = TARGET_A32_BRANCH24
        elif mnemonic in {"BX", "BXJ"}:
            groups |= GROUP_JUMP
        elif mnemonic == "BLX" and "/blx_reg/" in path:
            groups |= GROUP_CALL
            flags |= FLAG_LINK

    if path.startswith("t32/"):
        if mnemonic in {"BX", "BXJ"}:
            groups |= GROUP_JUMP
        elif mnemonic == "BLX" and "/bx16/" in path:
            groups |= GROUP_CALL
            flags |= FLAG_LINK
        elif mnemonic in {"TBB", "TBH"}:
            groups |= GROUP_JUMP
        elif "/cbznz16/" in path:
            groups |= GROUP_JUMP | GROUP_CONDITIONAL | GROUP_RELATIVE_BRANCH
            target = TARGET_T16_CB
        elif "/bcond16/" in path:
            groups |= GROUP_JUMP | GROUP_CONDITIONAL | GROUP_RELATIVE_BRANCH
            target = TARGET_T16_COND8
        elif path == "t32/b16/b_t2":
            groups |= GROUP_JUMP | GROUP_RELATIVE_BRANCH
            target = TARGET_T16_BRANCH11
        elif "/bcrtrl/bcond/" in path:
            groups |= GROUP_JUMP | GROUP_CONDITIONAL | GROUP_RELATIVE_BRANCH
            target = TARGET_T32_COND
        elif "/bcrtrl/b/" in path:
            groups |= GROUP_JUMP | GROUP_RELATIVE_BRANCH
            target = TARGET_T32_BRANCH
        elif "/bcrtrl/bl/" in path:
            groups |= GROUP_CALL | GROUP_RELATIVE_BRANCH
            flags |= FLAG_LINK
            target = TARGET_T32_BL
        elif "/bcrtrl/blx/" in path:
            groups |= GROUP_CALL | GROUP_RELATIVE_BRANCH
            flags |= FLAG_LINK
            target = TARGET_T32_BLX

    return groups, flags, target, dynamic


def emit(rows: list[dict[str, str]]) -> tuple[bytes, dict[str, Any]]:
    records = [classify(row) for row in rows]
    classified = sum(
        1 for groups, flags, target, dynamic in records
        if groups or flags or target or dynamic
    )
    target_count = sum(
        1 for groups, flags, target, dynamic in records
        if target != TARGET_NONE
    )
    dynamic_count = sum(
        1 for groups, flags, target, dynamic in records
        if dynamic != DYNAMIC_NONE
    )
    dynamic_counts = {
        name: sum(1 for _, _, _, dynamic in records if dynamic == kind)
        for name, kind in {
            "a64_lse_order": DYNAMIC_A64_LSE_ORDER,
            "a32_gpr_block": DYNAMIC_A32_GPR_BLOCK,
            "t16_gpr_block": DYNAMIC_T16_GPR_BLOCK,
            "t32_gpr_block": DYNAMIC_T32_GPR_BLOCK,
            "aa32_fp_block": DYNAMIC_AA32_FP_BLOCK,
        }.items()
    }
    group_counts = {
        name: sum(1 for groups, _, _, _ in records if groups & bit)
        for name, bit in {
            "jump": GROUP_JUMP,
            "call": GROUP_CALL,
            "return": GROUP_RETURN,
            "interrupt": GROUP_INTERRUPT,
            "interrupt_return": GROUP_INTERRUPT_RETURN,
            "privileged": GROUP_PRIVILEGED,
            "relative_branch": GROUP_RELATIVE_BRANCH,
            "conditional": GROUP_CONDITIONAL,
        }.items()
    }
    flag_counts = {
        name: sum(1 for _, flags, _, _ in records if flags & bit)
        for name, bit in {
            "sets_flags": FLAG_SETS_FLAGS,
            "writeback": FLAG_WRITEBACK,
            "pre_index": FLAG_PRE_INDEX,
            "post_index": FLAG_POST_INDEX,
            "link": FLAG_LINK,
            "byte": FLAG_BYTE,
            "user_registers": FLAG_USER_REGISTERS,
            "unprivileged": FLAG_UNPRIVILEGED,
            "address_increment": FLAG_ADDRESS_INCREMENT,
            "address_decrement": FLAG_ADDRESS_DECREMENT,
            "simd": FLAG_SIMD,
            "floating_point": FLAG_FLOATING_POINT,
            "atomic": FLAG_ATOMIC,
            "acquire": FLAG_ACQUIRE,
            "release": FLAG_RELEASE,
            "exclusive": FLAG_EXCLUSIVE,
            "scalable_vector": FLAG_SCALABLE_VECTOR,
            "predicated": FLAG_PREDICATED,
            "sme": FLAG_SME,
            "streaming": FLAG_STREAMING,
            "matrix": FLAG_MATRIX,
            "memory_tagging": FLAG_MEMORY_TAGGING,
            "pointer_auth": FLAG_POINTER_AUTH,
            "atomic_pair": FLAG_ATOMIC_PAIR,
        }.items()
    }
    lines = [
        "/* Generated string-free ARM per-leaf semantics. Do not edit. */",
        "#ifndef CDISASM_ARM_LEAF_SEMANTICS_GENERATED_INC",
        "#define CDISASM_ARM_LEAF_SEMANTICS_GENERATED_INC",
        "#include <stdint.h>",
        f"#define CDISASM_ARM_GEN_LEAF_SEMANTICS_COUNT UINT16_C({len(records)})",
        "enum cdisasm_arm_gen_target_kind {",
        "    CDISASM_ARM_GEN_TARGET_NONE = 0,",
        "    CDISASM_ARM_GEN_TARGET_A32_BRANCH24 = 1,",
        "    CDISASM_ARM_GEN_TARGET_A32_BLX24 = 2,",
        "    CDISASM_ARM_GEN_TARGET_T16_CB = 3,",
        "    CDISASM_ARM_GEN_TARGET_T16_COND8 = 4,",
        "    CDISASM_ARM_GEN_TARGET_T16_BRANCH11 = 5,",
        "    CDISASM_ARM_GEN_TARGET_T32_COND = 6,",
        "    CDISASM_ARM_GEN_TARGET_T32_BRANCH = 7,",
        "    CDISASM_ARM_GEN_TARGET_T32_BL = 8,",
        "    CDISASM_ARM_GEN_TARGET_T32_BLX = 9,",
        "    CDISASM_ARM_GEN_TARGET_A64_COND19 = 10,",
        "    CDISASM_ARM_GEN_TARGET_A64_BRANCH26 = 11,",
        "    CDISASM_ARM_GEN_TARGET_A64_COMPARE19 = 12,",
        "    CDISASM_ARM_GEN_TARGET_A64_TEST14 = 13,",
        "    CDISASM_ARM_GEN_TARGET_A64_COMPARE9 = 14",
        "};",
        "enum cdisasm_arm_gen_dynamic_semantics_kind {",
        "    CDISASM_ARM_GEN_DYNAMIC_NONE = 0,",
        "    CDISASM_ARM_GEN_DYNAMIC_A64_LSE_ORDER = 1,",
        "    CDISASM_ARM_GEN_DYNAMIC_A32_GPR_BLOCK = 2,",
        "    CDISASM_ARM_GEN_DYNAMIC_T16_GPR_BLOCK = 3,",
        "    CDISASM_ARM_GEN_DYNAMIC_T32_GPR_BLOCK = 4,",
        "    CDISASM_ARM_GEN_DYNAMIC_AA32_FP_BLOCK = 5",
        "};",
        "typedef struct cdisasm_arm_gen_leaf_semantics {",
        "    uint16_t opcode_groups;",
        "    uint32_t instruction_flags;",
        "    uint8_t target_kind;",
        "    uint8_t dynamic_kind;",
        "} cdisasm_arm_gen_leaf_semantics;",
        f"static const cdisasm_arm_gen_leaf_semantics cdisasm_arm_gen_leaf_semantics_table[{len(records)}] = {{",
    ]
    for groups, flags, target, dynamic in records:
        lines.append(f"    {{{groups}, {flags}, {target}, {dynamic}}},")
    lines.extend(["};", "#endif", ""])
    output = "\n".join(lines).encode("ascii")
    manifest = {
        "schema_version": 1,
        "generator": "tools/isa_codegen/generate_arm_leaf_semantics.py",
        "input": "tools/isa_codegen/generated/arm_tree_leaves.tsv",
        "input_sha256": file_digest(DEFAULT_INPUT),
        "counts": {
            "forms": len(records),
            "classified_forms": classified,
            "relative_target_forms": target_count,
            "dynamic_semantics_forms": dynamic_count,
            "dynamic_semantics": dynamic_counts,
            "groups": group_counts,
            "instruction_flags": flag_counts,
        },
        "policy": {
            "runtime_strings": False,
            "classification": "Only unambiguous source-tree classes and canonical mnemonic semantics are emitted.",
            "opaque_operands": "Leaf semantic metadata remains valid while the separate operand compiler reports operands opaque.",
        },
        "output_sha256": data_digest(output),
    }
    return output, manifest


def update_or_check(path: Path, data: bytes, check: bool) -> None:
    if check:
        if not path.exists() or path.read_bytes() != data:
            raise GenerationError(f"generated artifact is stale: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()

    rows = load_rows(arguments.input)
    output, manifest = emit(rows)
    # Record non-default inputs accurately without embedding host paths.
    manifest["input_sha256"] = file_digest(arguments.input)
    manifest["output_sha256"] = data_digest(output)
    manifest_data = (
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    ).encode("ascii")
    update_or_check(arguments.output, output, arguments.check)
    update_or_check(arguments.manifest, manifest_data, arguments.check)
    action = "verified" if arguments.check else "generated"
    print(
        f"{action} ARM leaf semantics: {manifest['counts']['classified_forms']} "
        f"classified, {manifest['counts']['relative_target_forms']} relative targets"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
