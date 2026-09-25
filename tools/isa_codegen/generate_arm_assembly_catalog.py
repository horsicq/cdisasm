#!/usr/bin/env python3
"""Generate the numeric Arm assembly grammar and conservative format recipes.

The pinned AARCHMRS Instructions.json contains a complete assembly grammar but
does not contain the ASL ``disassemble`` mappings described by the schema.  We
therefore preserve every rule and every encoded-in expression in numeric
tables, and emit executable formatter recipes only when the published data
defines one unambiguous direct projection.  Every other form is listed in the
checked-in opaque manifest with an exact reason.

No string is emitted to the decoder-side includes.  All spelling data lives in
the formatter-only include and tooling TSV/JSON artifacts.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Iterable


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
sys.path.insert(0, str(SCRIPT_DIR))
import generate_arm_tree as tree  # noqa: E402


PINNED_COMMIT = "47b5446cf08ef6a46c86147c7deb0d56caf99d93"
PINNED_INSTRUCTIONS_SHA256 = (
    "0496ca9d55f66fd096c2a7120fafe951763dbd00fa2f006652cbd0547e430602"
)
NONE = 0xFFFFFFFF

RULE_KIND = {
    "Instruction.Rules.Rule": 0,
    "Instruction.Rules.Choice": 1,
    "Instruction.Rules.Token": 2,
}
SYMBOL_KIND = {
    "Instruction.Symbols.Literal": 0,
    "Instruction.Symbols.RuleReference": 1,
}
RECIPE_OPCODE = {
    "MNEMONIC": 1,
    "TEXT": 2,
    "UINT": 3,
    "SINT": 4,
    "COND": 5,
    "COND_SUFFIX": 6,
    "REG31": 7,
    "SELECT": 8,
    "MINUS_IF_ZERO": 9,
    "BRANCH_TARGET": 10,
    "OPTIONAL_REG31": 11,
    "OPTIONAL_GPR_PAIR31": 12,
    "UINT_RSHIFT1": 13,
    "GPR_LIST": 14,
    "THUMB_EXPAND_IMM": 15,
    "A64_LOGICAL_IMM32": 16,
    "A64_LOGICAL_IMM64": 17,
    "VECTOR_D_LIST": 18,
    "A32_FPX_D_LIST": 27,
    "A64_SVE_FP_IMM8": 19,
    "A64_PC_LABEL": 20,
    "A32_VSHLL_FULL_SHIFT": 24,
    "A64_SVE_PATTERN": 26,
    "A32_NEON_SHIFT_ELEMENT_SIZE": 31,
    "A64_SVE_PRFOP": 34,
    "A64_REGOFF_WORX": 35,
    "A64_REGOFF_EXTEND_SHIFT": 36,
    "T32_MODIFIED_REG_SHIFT": 37,
    "A32_LDST_REG_SHIFT": 38,
    "A32_NEON_NARROW_SHIFT": 39,
    "A64_SVE_GPR_SUFFIX": 42,
    "A64_ADDSUB_EXT_REG_PREFIX": 40,
    "A64_ADDSUB_EXT_OPTION": 41,
    "A64_ADDSUB_EXT_REG_NUMBER": 44,
    "A64_PAUTH_LDST_SIMM": 90,
    "A64_SVE_GPR_SIZE_PREFIX": 91,
    "A64_SVE_GPR_SP_SUFFIX": 92,
    "A64_SVE_NARROW_SOURCE_TYPE": 93,
    "A64_SVE_NARROW_DEST_TYPE": 94,
    "A32_NEON_VCVT_DATATYPE": 95,
    "A32_NEON_VCVT_SOURCE_DATATYPE": 96,
    "A32_NEON_VCVT_SHIFT_BITS": 97,
    "A64_SVE_SHIFT_TSZ": 43,
    "A64_SVE_NARROW_SHIFT_TSZ": 45,
    "A64_SVE_FAST_REDUCE_SIZE": 46,
    "A64_SVE_LOGICAL_IMM": 47,
    "A64_SME_QRSHR_SIZE_IMM": 48,
    "A64_SME_QRSHR_GROUP_REG": 49,
    "A64_SME_LUTI_SIZE": 58,
    "A64_SME_LUTI_GROUP_REG": 59,
    "A64_SVE_SRA_TSZ": 100,
    "A64_SVE_SHLL_TSZ": 101,
    "A64_ASIMD_FMOV_IMM8": 120,
    "A64_SME_LUTI_STRIDE8_SECOND": 160,
    "A64_SME_LUTI_STRIDE8_FIRST": 161,
    "T32_DATA_PROC_SHIFT_AMOUNT": 220,
    "T32_SSAT_WIDTH_PLUS1": 221,
    "A32_BF16_INDEXED_LANE": 222,
    "A64_MOVWIDE_ALIAS_IMM": 223,
    "A64_ASIMD_MOVI_BYTE_MASK": 224,
    "A64_ASIMD_EXT_INDEX": 225,
    "A64_FCMLA_INDEX": 226,
    "A64_ASIMD_IMM5_SIZE": 227,
    "A64_ASIMD_MSL_AMOUNT": 228,
    "A32_NEON_VAND_ALIAS_IMM": 230,
    "A64_SVE_DUP_ELEMENT_TSZ": 110,
    "A64_SVE_SAT_NARROW_TSZ": 111,
    "A64_SVE_DUP_ELEMENT_LANE": 112,
    "A32_NEON_VMOV_MODIFIED_TYPE": 113,
    "A32_NEON_SAT_NARROW_TYPE": 114,
    "A64_SME_LUTI_STRIDE8_SIZE": 115,
    "A64_SVE_UNPRED_SHIFT_TSZ": 140,
    "A64_SIMD_SCALAR_SHIFT_SIZE": 141,
    "A64_SIMD_SCALAR_SHIFT_IMMEDIATE": 142,
    "A64_SIMD_FAMAX_ARRANGEMENT": 143,
    "A32_BLOCK_ADDRESS_MODE": 200,
    "T32_LDM_WRITEBACK": 201,
    "T32_OPTIONAL_SHIFT_IMM5": 202,
    "A32_VMOV_ELEMENT_SUFFIX": 203,
    "A32_VMOV_ELEMENT_REG": 204,
    "T32_IT_CONDITION_SUFFIX": 205,
    "T32_IT_CONDITION": 206,
    "A32_LDM_USER_REG_LIST": 207,
    "A64_SVE2P3_QSHRN_TYPE_IMM": 208,
    "A64_SVE2P3_QSHRN_PAIR_REG": 209,
    "A64_INDEXED_VM": 28,
    "A32_DMX_LANE": 29,
    "A64_INDEXED_LANE": 32,
    "A32_NEON_MODIFIED_IMM": 33,
    "A64_TMOP_ZK": 50,
    "A64_TMOP_ZN_PAIR": 51,
    "A64_FP_INDEXED_LANE": 52,
    "A64_SIMD_SHIFT64": 53,
    "A64_BITFIELD_ALIAS_IMM": 54,
    "A32_VDUP_GPR_SIZE": 55,
    "A32_VDUP_GPR_DEST": 56,
    "A32_VMOV_SM_NEXT": 57,
    "A32_VCVT_DDM": 60,
    "A32_VFP_FP_IMM8": 61,
    "A32_VDUP_LANE": 62,
    "A32_VDUP_LANE_SIZE": 63,
    "A32_SPLIT_INDEXED_DM": 65,
    "A32_SPLIT_INDEXED_LANE": 64,
    "T32_SHIFT_ALIAS_IMM": 73,
    "GROUPED_ZREG": 21,
    "A32_T32_PC_LABEL": 22,
    "A64_PN_GROUP": 25,
    "A32_NEON_ALIGNMENT": 23,
    "A32_RT2_PLUS1": 30,
    "A64_PAUTH_LR_PC_LABEL": 66,
    "A32_VFP_MULTI_SIZE": 67,
    "A32_VFP_MULTI_LIST": 68,
    "A64_ASIMD_SHIFT_T": 69,
    "A64_ASIMD_SHIFT_IMMEDIATE": 71,
    "A64_INVCOND": 70,
    "A64_ASIMD_NARROW_ARRANGEMENT": 72,
    "A64_ASIMD_FIXED_FCVT_SIZE": 181,
    "A64_SIMD_FIXED_FCVT_SIZE": 182,
    "A64_PRFM_PIMM12": 183,
    "A64_BTI_TARGETS": 184,
    "A64_SYSTEMREG_NUMERIC": 185,
    "A64_SYSTEMREG_PAIR_SECOND": 186,
    "A64_TESTBRANCH_RT": 187,
    "A64_SVE_ADR_SCALED_SHIFT": 188,
    "A64_SVE_FADDA_SCALAR_V": 189,
    "A64_SME_ZERO_MASK": 190,
    "A64_SHUH_PRIORITY": 196,
    "A64_SME_STATE_ALIAS": 197,
    "A64_PSTATE_MSR": 198,
    "A32_CPS_IFLAGS": 74,
    "A32_VCVT_SDM": 75,
    "A32_VCVT_FBITS": 76,
    "A64_ASIMD_OPTIONAL_LSL": 80,
    "A64_SVE_OPTIONAL_VL": 81,
    "A64_SVE_EXTEND_T": 82,
    "A64_ASIMD_INS_TS": 83,
    "A64_ASIMD_INS_R": 84,
    "A64_ASIMD_INS_LANE": 85,
    "A64_ASIMD_INS_RN": 86,
    "A32_MRS_SPEC_REG": 130,
    "A32_VFP_SPEC_REG": 131,
    "A32_VSHLL_SIGN": 132,
    "A32_VSHLL_IMM6": 133,
    "A32_BARRIER_OPTION": 180,
    "A64_SME_LUTI6_STRIDE4_DEST": 191,
    "A64_SME_LUTI6_TRIPLE_SOURCE": 192,
    "A64_SME_LUTI6_PAIR_SOURCE": 193,
    "A64_SVE_GPR_WIDTH": 240,
    "A64_SVE_GPR_NUMBER": 241,
    "A64_SVE_T_SIZE": 242,
    "A64_SVE_TSZHL_TYPE": 243,
    "A64_SVE_TSZHL_SHIFT": 244,
    "A64_SVE_PTRUE_PATTERN": 245,
    "A64_SVE_DUPQ_TYPE": 246,
    "A64_SVE_DUPQ_LANE": 247,
    "A64_SME_PSEL_TYPE": 248,
    "A64_SME_PSEL_LANE": 249,
    "A64_SME_PSEL_WV": 250,
    "A64_SME_LUTI4_ZD_GROUP": 251,
    "A64_BARRIER_OPTION": 252,
    "A64_RPRFM_OPTION": 253,
    "A64_STSHH_POLICY": 254,
    "A64_ISB_OPTION": 255,
}
RENDER_STATUS = {"OPAQUE": 0, "DIRECT": 1}

# Only these reviewed A64 forms treat <label> as an architectural PC-relative
# address.  The pinned grammar omits its disassemble transform, so keep the
# exact ADR/ADRP/load-literal calculations isolated in the formatter.
A64_PC_LABEL_FORMS = {
    "ADR_only_pcreladdr": 0,
    "ADRP_only_pcreladdr": 1,
    "LDR_32_loadlit": 2,
    "LDR_S_loadlit": 2,
    "LDR_64_loadlit": 2,
    "LDR_D_loadlit": 2,
    "LDRSW_64_loadlit": 2,
    "LDR_Q_loadlit": 2,
    "PRFM_P_loadlit": 2,
}

# FEAT_PAuth_LR's label is always the current instruction address minus
# ZeroExtend(imm16:'00'); unlike ordinary A64 branch labels it is unsigned.
A64_PAUTH_LR_PC_LABEL_FORMS = {
    "AUTIASPPC_only_dp_1src_imm",
    "AUTIBSPPC_only_dp_1src_imm",
    "RETAASPPC_only_miscbranch",
    "RETABSPPC_only_miscbranch",
}

A64_ASIMD_SHIFT_T_FORMS = {
    "SSHR_asimdshf_R", "SSRA_asimdshf_R", "SRSHR_asimdshf_R",
    "SRSRA_asimdshf_R", "SHL_asimdshf_R", "SQSHL_asimdshf_R",
    "USHR_asimdshf_R", "USRA_asimdshf_R", "URSHR_asimdshf_R",
    "URSRA_asimdshf_R", "SRI_asimdshf_R", "SLI_asimdshf_R",
    "SQSHLU_asimdshf_R", "UQSHL_asimdshf_R",
}
A64_ASIMD_SHIFT_RIGHT_FORMS = {
    "SSHR_asimdshf_R", "SSRA_asimdshf_R", "SRSHR_asimdshf_R",
    "SRSRA_asimdshf_R", "USHR_asimdshf_R", "USRA_asimdshf_R",
    "URSHR_asimdshf_R", "URSRA_asimdshf_R", "SRI_asimdshf_R",
}
A32_CPS_IFLAGS_FORMS = {
    "CPSID_A1_AS", "CPSID_A1_ASM", "CPSIE_A1_AS", "CPSIE_A1_ASM",
    "CPSID_T1_AS", "CPSIE_T1_AS",
    "CPSID_T2_AS", "CPSID_T2_ASM", "CPSIE_T2_AS", "CPSIE_T2_ASM",
}

# Narrowing shifts use immh to select both the result/source element sizes.
# Their Q bit selects the lower/upper half of a vector result, not the source
# width. Keep this source-name allowlist separate from same-width shifts.
A64_ASIMD_NARROW_VECTOR_FORMS = {
    "SHRN_asimdshf_N", "RSHRN_asimdshf_N",
    "SQSHRN_asimdshf_N", "SQRSHRN_asimdshf_N",
    "SQSHRUN_asimdshf_N", "SQRSHRUN_asimdshf_N",
    "UQSHRN_asimdshf_N", "UQRSHRN_asimdshf_N",
}
A64_ASIMD_NARROW_SCALAR_FORMS = {
    "SQSHRN_asisdshf_N", "SQRSHRN_asisdshf_N",
    "SQSHRUN_asisdshf_N", "SQRSHRUN_asisdshf_N",
    "UQSHRN_asisdshf_N", "UQRSHRN_asisdshf_N",
}
A64_ASIMD_WIDEN_SHIFT_FORMS = {
    "SSHLL_asimdshf_L", "USHLL_asimdshf_L", "SXTL", "UXTL",
}
A64_FIXED_FCVT_SCALAR_FORMS = {
    "SCVTF_asisdshf_C", "FCVTZS_asisdshf_C",
    "UCVTF_asisdshf_C", "FCVTZU_asisdshf_C",
}
A64_FIXED_FCVT_VECTOR_FORMS = {
    "SCVTF_asimdshf_C", "FCVTZS_asimdshf_C",
    "UCVTF_asimdshf_C", "FCVTZU_asimdshf_C",
}
A64_PRFM_NUMERIC_FORMS = {
    "PRFM_P_loadlit", "PRFUM_P_ldst_unscaled",
    "PRFM_P_ldst_regoff", "PRFM_P_ldst_pos",
}
A64_SYSTEMREG_NUMERIC_FORMS = {
    "MSR_SR_systemmove": "MRS_choice",
    "MRS_RS_systemmove": "MRS_choice__2",
    "MSRR_SR_systemmovepr": "MRS_choice__3",
    "MRRS_RS_systemmovepr": "MRS_choice__3",
}

# PC-relative A32/T32 literal and ADR forms. Mode values are interpreted by
# the formatter; keep this exact-name allowlist separate from A64 rules.
# 0/1: A32 split-imm8/imm12, 2/3: A32 scaled imm8 (2/4 bytes),
# 4: T32 narrow imm8*4, 5/6: T32 scaled imm8 (2/4 bytes),
# 7: T32 imm12, 8/9: T32 wide ADR add/sub, 10/11: A32 ADR add/sub.
A32_T32_PC_LABEL_FORMS = {
    "LDRD_l_A1": 0,
    "LDRH_l_A1": 0,
    "LDRSB_l_A1": 0, "LDRSH_l_A1": 0,
    "LDR_l_A1": 1, "LDRB_l_A1": 1,
    "PLD_l_A1": 1, "PLI_i_A1": 1,
    "VLDR_l_A1_H": 2,
    "VLDR_l_A1_S": 3, "VLDR_l_A1_D": 3, "LDC_l_A1": 3,
    "LDR_l_T1": 4, "ADR_T1": 4,
    "VLDR_l_T1_H": 5,
    "VLDR_l_T1_S": 6, "VLDR_l_T1_D": 6,
    "LDC_l_T1": 6, "LDRD_l_T1": 6,
    "PLD_l_T1": 7, "LDRB_l_T1": 7, "LDRH_l_T1": 7,
    "LDR_l_T2": 7, "LDRSB_l_T1": 7,
    "PLI_i_T3": 7, "LDRSH_l_T1": 7,
    "ADR_T3": 8, "ADR_T2": 9,
    "ADR_A1": 10, "ADR_A2": 11,
}
A32_T32_PC_LABEL_ALIASES = {
    ("A1B", "PLI_i", "PLI"): 1,
    ("T3B", "ADR_a32", "ADR"): 8,
    ("T2B", "LDR_l", "LDR"): 7,
}

A64_SVE_FP_IMM8_FORMS = {
    "fcpy_z_p_i_", "fdup_z_i_", "fmov_z_p_i_", "fmov_z_i_",
}

# Multiple entries for one ``encoded_in`` display are ordered bit fragments,
# but concatenation is not automatically the architectural operand value.
# For example Q-register fields require division by two, logical immediates
# require DecodeBitMasks(), and PC-relative labels require address arithmetic.
# Keep direct concatenation to syntax values whose published encoding is the
# value itself.  Choice rules are handled separately: an exhaustive 2^N
# spelling table is an exact mapping from the concatenated selector bits.
DIRECT_CONCAT_DISPLAYS = {
    "<imm8>", "<imm12>", "<imm16>", "<lsb>",
}
DIRECT_CONCAT_REGISTER_RULE_BASES = {
    "D_Rd", "DN_Rdn", "D_Vd", "M_Rm", "M_Vm", "N_Rn", "N_Vn",
    "Vd_D", "Vm_M", "Vn_N",
}
DIRECT_CONCAT_REGISTER_DISPLAYS = {
    "<Dd>", "<Dn>", "<Dm>",
    "<Sd>", "<Sn>", "<Sm>",
    "<Rd>", "<Rn>", "<Rdn>", "<Vm>",
}
DIRECT_CONCAT_RULE_IDS = {
    "CRm_op2",
    "H_L",
    "H_L_M",
    "H_L__2",
    "imm4H_imm4L__2",
    "imm4_i_imm3_imm8",
    "imm__36",
    "imm__49",
    "imm__53",
    "imm__56",
    "imm__78",
    "imm__88",
    "index__8",
    "index__12",
    "index__13",
    "index__15",
    "index__18",
    "index__23",
    "index__24",
}

# These grammar values are lane indexes assembled from split *raw* encoding
# fields.  Keep the field locations here: a reused rule ID, changed field
# width, or different encoded_in order must become opaque rather than silently
# producing a plausible but wrong operand.  In particular, Zt1/Zt2 and Zk
# register numbers have missing high bits/group offsets and are NOT direct.
REVIEWED_SPLIT_FIELDS = {
    ("index", "<index>"): (("Q", 30, 1), ("S", 12, 1), ("size", 10, 2)),
    ("index__3", "<index>"): (("Q", 30, 1), ("S", 12, 1)),
    ("index__20", "<index>"): (("i3h", 10, 2), ("i3l", 3, 1)),
    ("index__25", "<index>"): (("i2h", 10, 1), ("i2l", 3, 1)),
    ("index__29", "<index>"): (("i3h", 22, 2), ("i3l", 12, 1)),
}

# SME multi-vector memory transfers select one lane within each high register
# group.  T chooses z0-z15 versus z16-z31; Zt chooses a low 3/2-bit index.
# For 2x8 the registers are (base, base+8); for 4x4 they are (base,
# base+4, base+8, base+12).  Raw T:Zt concatenation is *not* the register
# number because the group-position bits are omitted from encoded_in.
GROUPED_ZREG_RULES = {
    "Zt1__3": (8, 0, "<Zt1>"),
    "Zt2__2": (8, 1, "<Zt2>"),
    "Zt1__4": (4, 0, "<Zt1>"),
    "Zt2__3": (4, 1, "<Zt2>"),
    "Zt3": (4, 2, "<Zt3>"),
    "Zt4__2": (4, 3, "<Zt4>"),
}

# These option rules are sparse architectural enumerations.  Their rule
# references carry the exact encoded selector bits before the final spelling
# token (for example ``dc_op_000_0110_001_IVAC``).  Keeping the mapping in the
# generated formatter avoids both a giant hand-written switch and any string
# dependency in the decoder core.
SYSTEM_OPTION_RULE_SHAPES = {
    "dc_op_option": ("dc_op_", (3, 4, 3)),
    "tlbi_op_option": ("tlbi_op_", (3, 4, 4, 3)),
    "ic_op_option": ("ic_op_", (3, 4, 3)),
    "at_op_option": ("at_op_", (3, 1, 3)),
    "brb_op_option": ("brb_op_", (3,)),
    "gsb_op_option": ("gsb_op_", (3,)),
    "gic_op_option": ("gic_op_", (3, 4, 3)),
    "plbi_op_option": ("plbi_op_", (3, 4, 4, 3)),
    "gicr_op_option": ("gicr_op_", (3,)),
    "tlbip_op_option": ("tlbip_op_", (3, 4, 4, 3)),
}


class AssemblyError(RuntimeError):
    pass


class OpaqueRecipe(RuntimeError):
    pass


def system_option_selector(
    rule_id: str,
    choice: dict[str, Any] | None,
    expected_width: int,
) -> int | None:
    """Return one exact sparse system-operation selector, or ``None``."""

    shape = SYSTEM_OPTION_RULE_SHAPES.get(rule_id)
    symbols = (choice or {}).get("symbols", []) or []
    if shape is None or len(symbols) != 1 \
            or symbols[0].get("_type") \
                != "Instruction.Symbols.RuleReference":
        return None
    prefix, widths = shape
    reference = str(symbols[0].get("rule_id", "")).lower()
    if not reference.startswith(prefix):
        return None
    parts = reference[len(prefix):].split("_")
    if len(parts) <= len(widths):
        return None
    fields = parts[:len(widths)]
    if any(len(value) != width or set(value) - {"0", "1"}
           for value, width in zip(fields, widths)):
        return None
    # AT abbreviates CRm=100x as its low selector bit in the option-rule ID.
    if rule_id == "at_op_option":
        fields = [fields[0], "100" + fields[1], fields[2]]
    bits = "".join(fields)
    if len(bits) != expected_width:
        return None
    return int(bits, 2)


def fixed_choice_selector(
    rule_id: str,
    choice: dict[str, Any] | None,
    expected_width: int,
) -> int | None:
    """Recover an exact selector from a fixed-spelling choice reference.

    The public grammar encodes many sparse enum mappings in rule-reference
    names (``size_00_8``, ``shift_11_ROR``, ``T_0_1_4S``).  Binary-only
    underscore components are the selector fragments, in encoded order.  Use
    them only when their combined width exactly matches the bound display;
    otherwise the mapping remains opaque.
    """

    selector = system_option_selector(rule_id, choice, expected_width)
    if selector is not None:
        return selector
    symbols = (choice or {}).get("symbols", []) or []
    if len(symbols) != 1 \
            or symbols[0].get("_type") \
                != "Instruction.Symbols.RuleReference":
        return None
    reference = str(symbols[0].get("rule_id", ""))
    fragments = [
        fragment for fragment in reference.split("_")
        if fragment and not (set(fragment) - {"0", "1"})
    ]
    bits = "".join(fragments)
    if len(bits) != expected_width:
        return None
    return int(bits, 2)


def sve_size_choice_selector(
    rule_id: str,
    choice: dict[str, Any],
    rules: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> int | None:
    """Map a fixed SVE element suffix from the architectural size field.

    Only the raw two-bit ``size`` field at bits 22:23 is eligible.  Other
    grammars with a ``<T>`` display use tsize, concatenated fields, or
    instruction-specific transforms and remain opaque.
    """
    encoded = (source.get("_meta") or {}).get("encoded_in") or {}
    if (not rule_id.startswith("T__")
            or encoded.get("<T>") != [{"_type": "AST.Identifier", "value": "size"}]
            or bindings.get("size") != (22, 2)):
        return None
    symbols = choice.get("symbols", []) or []
    if (len(symbols) != 1
            or symbols[0].get("_type") != "Instruction.Symbols.RuleReference"):
        return None
    branch = rules.get(str(symbols[0].get("rule_id", "")), {})
    branch_symbols = (branch.get("symbols") or {}).get("symbols", []) or []
    if (branch.get("_type") != "Instruction.Rules.Rule"
            or branch.get("condition") != {"_type": "AST.Bool", "value": True}
            or len(branch_symbols) != 1
            or branch_symbols[0].get("_type") != "Instruction.Symbols.Literal"):
        return None
    return {"B": 0, "H": 1, "S": 2, "D": 3}.get(branch_symbols[0].get("value"))


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def git(repository: Path, *arguments: str) -> str:
    process = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    if process.returncode != 0:
        raise AssemblyError(process.stderr.strip() or "git command failed")
    return process.stdout.strip()


def load_source(arm_root: Path) -> tuple[dict[str, Any], Path]:
    if git(arm_root, "rev-parse", "HEAD") != PINNED_COMMIT:
        raise AssemblyError(f"Arm source must be pinned at {PINNED_COMMIT}")
    path = arm_root / "Instructions.json"
    if not path.is_file():
        raise AssemblyError(f"missing {path}")
    if sha256_file(path) != PINNED_INSTRUCTIONS_SHA256:
        raise AssemblyError("pinned Instructions.json digest mismatch")
    if git(arm_root, "hash-object", "Instructions.json") != git(
        arm_root, "rev-parse", "HEAD:Instructions.json"
    ):
        raise AssemblyError("working Instructions.json does not match pinned commit")
    with path.open("r", encoding="utf-8") as stream:
        document = json.load(stream)
    if len(document.get("assembly_rules", {})) != 3191:
        raise AssemblyError("pinned assembly-rule count changed")
    return document, path


def load_public_name_ids(path: Path) -> dict[str, int]:
    result: dict[str, int] = {}
    with path.open("r", encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream, dialect="excel-tab"):
            mnemonic = row["mnemonic"]
            name_id = int(row["name_id"])
            if mnemonic in result and result[mnemonic] != name_id:
                raise AssemblyError(f"duplicate public mnemonic {mnemonic!r}")
            result[mnemonic] = name_id
    return result


def collect_sources(document: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    leaves: list[dict[str, Any]] = []
    aliases: list[dict[str, Any]] = []

    def visit(node: dict[str, Any]) -> None:
        if node.get("_type") == "Instruction.Instruction":
            leaves.append(node)
            aliases.extend(
                child
                for child in node.get("children", [])
                if child.get("_type") == "Instruction.InstructionAlias"
            )
        for child in node.get("children", []):
            if child.get("_type") != "Instruction.InstructionAlias":
                visit(child)

    for root in document.get("instructions", []):
        visit(root)
    return leaves, aliases


# These are source-assembly aliases, not additional byte-level instructions.
# Keep the exact pinned-source indices and parent forms here: a source update
# must invalidate the audit rather than silently inheriting a classification.
NON_INVERTIBLE_SHIFT_ALIASES = {
    60: ("VRSHR", "A32/uncond_as/advsimddp/simd3reg_same/VORR_r_A1_D"),
    61: ("VSHR", "A32/uncond_as/advsimddp/simd3reg_same/VORR_r_A1_D"),
    63: ("VRSHR", "A32/uncond_as/advsimddp/simd3reg_same/VORR_r_A1_Q"),
    64: ("VSHR", "A32/uncond_as/advsimddp/simd3reg_same/VORR_r_A1_Q"),
    144: ("VRSHR", "T32/w/cpaf/simddp/simd_3same/VORR_r_T1_D"),
    145: ("VSHR", "T32/w/cpaf/simddp/simd_3same/VORR_r_T1_D"),
    147: ("VRSHR", "T32/w/cpaf/simddp/simd_3same/VORR_r_T1_Q"),
    148: ("VSHR", "T32/w/cpaf/simddp/simd_3same/VORR_r_T1_Q"),
}
ASSEMBLY_ONLY_VORN_ALIASES = {
    84: "A32/uncond_as/advsimddp/a_simd_12reg/simd1reg_imm/VORR_i_A1_D",
    85: "A32/uncond_as/advsimddp/a_simd_12reg/simd1reg_imm/VORR_i_A1_Q",
    88: "A32/uncond_as/advsimddp/a_simd_12reg/simd1reg_imm/VORR_i_A2_D",
    89: "A32/uncond_as/advsimddp/a_simd_12reg/simd1reg_imm/VORR_i_A2_Q",
    168: "T32/w/cpaf/simddp/t_simd_12reg/simd_1r_imm/VORR_i_T1_D",
    169: "T32/w/cpaf/simddp/t_simd_12reg/simd_1r_imm/VORR_i_T1_Q",
    172: "T32/w/cpaf/simddp/t_simd_12reg/simd_1r_imm/VORR_i_T2_D",
    173: "T32/w/cpaf/simddp/t_simd_12reg/simd_1r_imm/VORR_i_T2_Q",
}


def opaque_audit_class(
    alias_index: int, alias: dict[str, Any], source: dict[str, Any], reason: str
) -> str:
    """Separate missing byte recipes from non-preferred assembly-only aliases."""
    expected = NON_INVERTIBLE_SHIFT_ALIASES.get(alias_index)
    vorn_parent = ASSEMBLY_ONLY_VORN_ALIASES.get(alias_index)
    if expected is None and vorn_parent is None:
        return "unresolved_recipe"
    symbols = (source.get("assembly") or {}).get("symbols") or []
    rule_ids = {
        symbol.get("rule_id") for symbol in symbols
        if symbol.get("_type") == "Instruction.Symbols.RuleReference"
    }
    encoded = (source.get("_meta") or {}).get("encoded_in") or {}
    if (source.get("preferred") != {"_type": "AST.Bool", "value": False}
            or source.get("condition") != {"_type": "AST.Bool", "value": True}):
        raise AssemblyError(f"audited alias preference changed: {alias_index}")
    if expected is not None:
        mnemonic, parent = expected
        register_kind = "Q" if parent.endswith("_Q") else "D"
        if (source.get("name") != mnemonic
                or source.get("operation_id") != f"{mnemonic}_VORR_r"
                or alias.get("source_form_id") != parent
                or reason != "choice_selection_missing:dt_option__8"
                or set(encoded) != {f"<{register_kind}d>", f"<{register_kind}m>"}
                or "dt__3" not in rule_ids
                or "hash" not in rule_ids
                or not symbols
                or symbols[-1] != {"_type": "Instruction.Symbols.Literal", "value": "0"}):
            raise AssemblyError(f"audited shift alias shape changed: {alias_index}")
        # Eight S/U8/16/32/64 datatype spellings and either shift mnemonic
        # map to a parent VORR_r encoding with no datatype or shift field.
        return "non_invertible_assembly_alias"
    if (source.get("name") != "VORN"
            or source.get("operation_id") != "VORN_VORR_i"
            or alias.get("source_form_id") != vorn_parent
            or reason != "encoded_concat_transform_missing:imm__114:<imm>"
            or "<imm>" not in encoded):
        raise AssemblyError(f"audited VORN alias shape changed: {alias_index}")
    # Arm armasm documents VORN immediate as a pseudo-instruction that
    # disassembles as canonical VORR/VBIC with a complemented immediate.
    return "assembly_only_pseudoinstruction"


class TextPool:
    def __init__(self) -> None:
        self.values: set[str] = {""}
        self.ids: dict[str, int] = {}
        self.ordered: list[str] = []

    def add(self, value: str | None) -> None:
        if value is not None:
            self.values.add(str(value))

    def finish(self) -> None:
        self.ordered = [""] + sorted(self.values - {""}, key=lambda value: value.encode("utf-8"))
        self.ids = {value: index for index, value in enumerate(self.ordered)}

    def id(self, value: str | None) -> int:
        if value is None:
            return NONE
        return self.ids[str(value)]


def collect_text(
    rules: dict[str, Any], leaf_sources: list[dict[str, Any]], alias_sources: list[dict[str, Any]]
) -> TextPool:
    pool = TextPool()
    for rule_id, rule in rules.items():
        pool.add(rule_id)
        pool.add(rule.get("display"))
        pool.add(rule.get("default"))
        assemblies: list[dict[str, Any] | None] = []
        if rule.get("_type") == "Instruction.Rules.Rule":
            assemblies.append(rule.get("symbols"))
        elif rule.get("_type") == "Instruction.Rules.Choice":
            assemblies.extend(rule.get("choices", []))
        for assembly in assemblies:
            for symbol in (assembly or {}).get("symbols", []) or []:
                if symbol.get("_type") == "Instruction.Symbols.Literal":
                    pool.add(symbol.get("value", ""))
    for source in [*leaf_sources, *alias_sources]:
        for display in ((source.get("_meta") or {}).get("encoded_in") or {}):
            pool.add(display)
        for symbol in (source.get("assembly") or {}).get("symbols", []) or []:
            if symbol.get("_type") == "Instruction.Symbols.Literal":
                pool.add(symbol.get("value", ""))
    # Formatter recipes deliberately canonicalize the whitespace token.
    pool.add(" ")
    pool.add("i")  # VSHLL_A2/T2's implicit integer datatype.
    pool.finish()
    return pool


def ast_features(value: Any) -> set[str]:
    result: set[str] = set()
    if isinstance(value, dict):
        if value.get("_type") == "AST.Identifier":
            name = str(value.get("value", ""))
            if name.startswith("FEAT_"):
                result.add(name)
        for child in value.values():
            result.update(ast_features(child))
    elif isinstance(value, list):
        for child in value:
            result.update(ast_features(child))
    return result


def has_semantic_branch_target(source_form_id: str) -> bool:
    """Mirror only the exact relative-target classes of the control catalog."""
    path = source_form_id.lower()
    if path.startswith("a64/"):
        return any(fragment in path for fragment in (
            "/control/condbranch/",
            "/control/compbranch_regs2/",
            "/control/compbranch_regs/",
            "/control/compbranch_imm/",
            "/control/compbranch/",
            "/control/testbranch/",
            "/control/branch_imm/",
        ))
    if path.startswith("a32/"):
        return "/b_imm/" in path
    if path.startswith("t32/"):
        return (
            "/cbznz16/" in path
            or "/bcond16/" in path
            or path == "t32/b16/b_t2"
            or "/bcrtrl/bcond/" in path
            or "/bcrtrl/b/" in path
            or "/bcrtrl/bl/" in path
            or "/bcrtrl/blx/" in path
        )
    return False


def extend_ast_pools(
    pool_names: dict[str, list[str]], values: Iterable[Any]
) -> dict[str, list[str]]:
    """Append grammar-only AST names without renumbering tree feature IDs."""
    discovered = {key: set(names) for key, names in pool_names.items()}
    for value in values:
        for node in tree.ast_walk(value):
            kind = node.get("_type")
            if kind == "AST.Identifier":
                name = str(node.get("value", ""))
                if name.startswith("FEAT_"):
                    discovered["features"].add(name)
                else:
                    discovered["symbols"].add(name)
            elif kind == "Values.Value":
                discovered["values"].add(str(node.get("value", "")))
            elif kind == "AST.Function":
                discovered["functions"].add(str(node.get("name", "")))
    result: dict[str, list[str]] = {}
    for category, original in pool_names.items():
        appended = sorted(
            discovered[category] - set(original),
            key=lambda value: value.encode("utf-8"),
        )
        result[category] = [*original, *appended]
    return result


class CatalogBuilder:
    def __init__(
        self,
        rules: dict[str, Any],
        text_pool: TextPool,
        feature_names: list[str],
        symbol_names: list[str],
        value_names: list[str],
        function_names: list[str],
    ) -> None:
        self.rules = rules
        self.text = text_pool
        self.rule_ids = sorted(rules, key=lambda value: value.encode("utf-8"))
        self.rule_indexes = {name: index for index, name in enumerate(self.rule_ids)}
        self.pool_ids = {
            "features": {name: index for index, name in enumerate(feature_names)},
            "symbols": {name: index for index, name in enumerate(symbol_names)},
            "values": {name: index for index, name in enumerate(value_names)},
            "functions": {name: index for index, name in enumerate(function_names)},
        }
        self.assemblies: list[tuple[int, int]] = []
        self.symbols: list[tuple[int, int]] = []
        self.rule_records: list[dict[str, int]] = []
        self.choice_assemblies: list[int] = []
        self.programs_raw: list[tuple[tuple[int, int, int], ...]] = []
        self.form_bindings: list[tuple[int, int, int]] = []
        self.recipe_ops_raw: list[tuple[int, int | tuple[tuple[int, int, int], ...]]] = []
        self.special_registers: list[dict[str, Any]] = []
        self.selections: list[dict[str, Any]] = []
        self.selection_cases: list[tuple[int, int, int]] = []
        self.selection_text_ids: list[int] = []

    def add_assembly(self, assembly: dict[str, Any] | None) -> int:
        if assembly is None:
            return NONE
        first = len(self.symbols)
        for symbol in assembly.get("symbols", []) or []:
            kind = str(symbol.get("_type", ""))
            if kind not in SYMBOL_KIND:
                raise AssemblyError(f"unsupported assembly symbol {kind!r}")
            if kind == "Instruction.Symbols.Literal":
                value = self.text.id(str(symbol.get("value", "")))
            else:
                referenced = str(symbol.get("rule_id", ""))
                if referenced not in self.rule_indexes:
                    raise AssemblyError(f"unknown assembly rule {referenced!r}")
                value = self.rule_indexes[referenced]
            self.symbols.append((SYMBOL_KIND[kind], value))
        assembly_id = len(self.assemblies)
        self.assemblies.append((first, len(self.symbols) - first))
        return assembly_id

    def compile_program(
        self, value: Any, bindings: dict[str, tuple[int, int]]
    ) -> tuple[tuple[int, int, int], ...] | None:
        return tree.compile_ast(value, bindings, **self.pool_ids)

    def add_program(self, raw: tuple[tuple[int, int, int], ...] | None) -> int:
        if raw is None:
            return NONE
        self.programs_raw.append(raw)
        return 0  # Replaced after deterministic de-duplication.

    def build_rules(self) -> list[tuple[tuple[int, int, int], ...] | None]:
        conditions: list[tuple[tuple[int, int, int], ...] | None] = []
        for rule_id in self.rule_ids:
            rule = self.rules[rule_id]
            kind_name = str(rule.get("_type", ""))
            if kind_name not in RULE_KIND:
                raise AssemblyError(f"unsupported rule kind {kind_name!r}")
            first_choice = len(self.choice_assemblies)
            assembly_id = NONE
            if kind_name == "Instruction.Rules.Rule":
                assembly_id = self.add_assembly(rule.get("symbols"))
                condition = self.compile_program(rule.get("condition"), {})
            elif kind_name == "Instruction.Rules.Choice":
                for choice in rule.get("choices", []):
                    self.choice_assemblies.append(self.add_assembly(choice))
                condition = None
            else:
                condition = None
            conditions.append(condition)
            if condition is not None:
                self.programs_raw.append(condition)
            self.rule_records.append(
                {
                    "kind": RULE_KIND[kind_name],
                    "assembly_id": assembly_id,
                    "first_choice": first_choice,
                    "choice_count": len(self.choice_assemblies) - first_choice,
                    "display_text_id": self.text.id(rule.get("display")),
                    "default_text_id": self.text.id(rule.get("default")),
                    "condition_program_id": NONE,
                }
            )
        return conditions

    def add_encoded_bindings(
        self,
        source: dict[str, Any],
        bindings: dict[str, tuple[int, int]],
    ) -> tuple[int, int, dict[str, list[tuple[tuple[int, int, int], ...]]]]:
        encoded = (source.get("_meta") or {}).get("encoded_in") or {}
        first = len(self.form_bindings)
        compiled: dict[str, list[tuple[tuple[int, int, int], ...]]] = {}
        for display in sorted(encoded, key=lambda value: value.encode("utf-8")):
            programs: list[tuple[tuple[int, int, int], ...]] = []
            for expression in encoded[display]:
                raw = self.compile_program(expression, bindings)
                if raw is None:
                    raise AssemblyError(f"empty encoded expression for {display!r}")
                programs.append(raw)
                self.programs_raw.append(raw)
                self.form_bindings.append((self.text.id(display), 0, 0))
            compiled[display] = programs
        return first, len(self.form_bindings) - first, compiled


def normalize_token(rule_id: str, value: str) -> str:
    # AARCHMRS stores two spaces as the permissive SPACE token default.  The
    # architecture's canonical disassembly syntax uses one separator.
    return " " if rule_id == "SPACE" else value


def direct_program_width(
    program: tuple[tuple[int, int, int], ...]
) -> int | None:
    stack: list[int] = []
    for opcode, a, b in program:
        if opcode == tree.BC_OPCODE["PUSH_FIELD"]:
            if a < 0 or b <= 0 or a + b > 32:
                return None
            stack.append(b)
        elif opcode == tree.BC_OPCODE["UNARY_BIT_NOT"]:
            if not stack:
                return None
        elif opcode == tree.BC_OPCODE["BINARY_XOR"]:
            if len(stack) < 2:
                return None
            right = stack.pop()
            left = stack.pop()
            stack.append(max(left, right))
        elif opcode == tree.BC_OPCODE["BINARY_CONCAT"]:
            if len(stack) < 2:
                return None
            right = stack.pop()
            left = stack.pop()
            if left + right > 64:
                return None
            stack.append(left + right)
        else:
            return None
    return stack[0] if len(stack) == 1 else None


def concatenate_encoded_expressions(
    expressions: list[tuple[tuple[int, int, int], ...]],
) -> tuple[tuple[int, int, int], ...]:
    """Join the ordered ``encoded_in`` bit fragments into one value.

    AARCHMRS represents split fields as an ordered list from the most to the
    least significant fragment.  Keep that relationship explicit in the
    generated numeric bytecode instead of assuming physical bit adjacency in
    the instruction word.
    """
    if not expressions:
        raise OpaqueRecipe("missing_value_mapping")
    result = expressions[0]
    for expression in expressions[1:]:
        result = (
            *result,
            *expression,
            (tree.BC_OPCODE["BINARY_CONCAT"], 0, 0),
        )
    if direct_program_width(result) is None:
        raise OpaqueRecipe("encoded_expression_not_direct")
    return result


def vector_d_list_recipe(
    source: dict[str, Any],
    rule_id: str,
    rule: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> int | None:
    """Lower only reviewed A32/T32 D-register-list encoding shapes.

    The generic ``multi_register_list`` grammar is recursive and has no
    disassembly selector.  The forms below instead have a documented fixed
    projection from encoding fields.  Other lists remain opaque.
    """
    symbols = (rule.get("symbols") or {}).get("symbols", []) or []
    if (rule.get("_type") != "Instruction.Rules.Rule"
            or rule.get("display") != "<list>"
            or len(symbols) != 1
            or symbols[0].get("_type")
                != "Instruction.Symbols.RuleReference"
            or symbols[0].get("rule_id") != "multi_register_list"
            or "<list>" in (source.get("_meta") or {}).get("encoded_in", {})):
        return None

    name = str(source.get("name", ""))
    if (name in {"VTBL_A1", "VTBX_A1", "VTBL_T1", "VTBX_T1"}
            and rule_id == "registers__25"
            and bindings.get("Vn") == (16, 4)
            and bindings.get("N") == (7, 1)
            and bindings.get("len") == (8, 2)):
        # Four architectural table-list lengths: len + 1.
        return 16 | (7 << 5) | (1 << 13)

    all_lanes = re.fullmatch(
        r"VLD([1-4])_a_[AT]1_(?:nowb|posti|postr)", name,
    )
    if all_lanes is not None:
        count = int(all_lanes[1])
        if (rule_id == f"registers__{12 + count}"
                and bindings.get("D") == (22, 1)
                and bindings.get("Vd") == (12, 4)
                and bindings.get("T") == (5, 1)
                and bindings.get("size") == (6, 2)):
            # VLD1 uses T as a second-register membership bit.  VLD2-4 use
            # it as the stride (1 or 2) between D registers.
            return (12 | (22 << 5) | (count << 10) | (1 << 15)
                    | ((1 << 27) if count == 1 else
                       ((1 << 14) | (5 << 17))))

    one_lane = re.fullmatch(
        r"V(?:ST|LD)([1-4])_1_[AT]([1-3])_(?:nowb|posti|postr)",
        name,
    )
    if one_lane is not None:
        count = int(one_lane[1])
        size_code = int(one_lane[2]) - 1
        size_fields = [field.get("value", {}).get("value")
                       for field in (source.get("encoding") or {}).get(
                           "values", []) if field.get("name") == "size"]
        if (rule_id == f"registers__{20 + count}"
                and bindings.get("D") == (22, 1)
                and bindings.get("Vd") == (12, 4)
                and bindings.get("size") == (10, 2)
                and bindings.get("index_align") == (4, 4)
                and size_fields == [f"'{size_code:02b}'"]):
            lane_shift = 5 + size_code
            # VLD3/VST3 use the low index_align bit for spacing even for
            # .8; the 2- and 4-register forms use that bit for alignment
            # and permit double spacing only at .16/.32.
            dynamic_stride = count == 3 or (count > 1 and size_code > 0)
            stride_shift = 4 + size_code
            return (12 | (22 << 5) | (count << 10) | (1 << 16)
                    | (lane_shift << 22)
                    | ((1 << 14) | (stride_shift << 17)
                       if dynamic_stride else 0))

    match = re.fullmatch(
        r"V(?:ST|LD)([1-4])_m_[AT]([1-4])_(?:nowb|posti|postr)",
        name,
    )
    if (match is None or rule_id not in {
            "registers__17", "registers__18", "registers__19",
            "registers__20", "registers__21", "registers__22",
            "registers__23", "registers__24",
        } or bindings.get("D") != (22, 1)
            or bindings.get("Vd") != (12, 4)
            or bindings.get("itype") != (8, 4)):
        return None
    # ARMv7-A/R multiple-structure list encodings.  The low itype bit in
    # the three x forms selects stride 1 or 2, not a different count.
    list_shapes = {
        (4, 1): ("000x", 4, True),
        (1, 4): ("0010", 4, False),
        (2, 2): ("0011", 4, False),
        (3, 1): ("010x", 3, True),
        (1, 3): ("0110", 3, False),
        (1, 1): ("0111", 1, False),
        (2, 1): ("100x", 2, True),
        (1, 2): ("1010", 2, False),
    }
    shape = list_shapes.get((int(match[1]), int(match[2])))
    if shape is None:
        return None
    expected_itype, count, dynamic_stride = shape
    itypes = [field.get("value", {}).get("value")
              for field in (source.get("encoding") or {}).get("values", [])
              if field.get("name") == "itype"]
    if itypes != [f"'{expected_itype}'"]:
        return None
    return (12 | (22 << 5) | (count << 10)
            | (((1 << 14) | (8 << 17)) if dynamic_stride else 0))


def fpx_d_list_recipe(
    source: dict[str, Any],
    rule_id: str,
    rule: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> bool:
    """Recognize the eight legacy FLDMX/FSTMX D-register lists only.

    Arm defines d = D:Vd and regs = imm8 DIV 2.  These X encodings have
    imm8<0> fixed to one, and only D0-D15 lists are predictable.
    """
    if (source.get("name") not in {
            "FSTMDBX_A1", "FSTMIAX_A1", "FLDMDBX_A1", "FLDMIAX_A1",
            "FSTMDBX_T1", "FSTMIAX_T1", "FLDMDBX_T1", "FLDMIAX_T1",
        } or rule_id != "registers__12"
            or bindings.get("D") != (22, 1)
            or bindings.get("Vd") != (12, 4)
            or bindings.get("imm8") != (0, 8)
            or "<dreglist>" in (source.get("_meta") or {}).get("encoded_in", {})):
        return False
    symbols = (rule.get("symbols") or {}).get("symbols", []) or []
    if (rule.get("_type") != "Instruction.Rules.Rule"
            or rule.get("display") != "<dreglist>"
            or len(symbols) != 1
            or symbols[0].get("_type")
                != "Instruction.Symbols.RuleReference"
            or symbols[0].get("rule_id") != "multi_register_list"):
        return False
    imm8 = [field.get("value", {}).get("value")
            for field in (source.get("encoding") or {}).get("values", [])
            if field.get("name") == "imm8"]
    return imm8 == ["'xxxxxxx1'"]


def reviewed_vfp_multiple_source(
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> bool:
    """Scope VSTM/VLDM/VPUSH/VPOP suffix and list recipes together."""
    symbols = (source.get("assembly") or {}).get("symbols", []) or []
    references = [symbol.get("rule_id") for symbol in symbols
                  if symbol.get("_type")
                      == "Instruction.Symbols.RuleReference"]
    return (tree.first_literal(source) in {
        "VSTM", "VSTMDB", "VSTMIA", "VLDM", "VLDMDB", "VLDMIA",
        "VPUSH", "VPOP",
    } and references.count("dot_vstm_size_choice") == 1
        and (references.count("registers__10")
             + references.count("registers__11")) == 1
        and bindings.get("Rn") == (16, 4)
        and bindings.get("D") == (22, 1)
        and bindings.get("Vd") == (12, 4)
        and bindings.get("size") == (8, 2)
        and bindings.get("imm8") == (0, 8))


def vector_alignment_recipe(
    source: dict[str, Any],
    rule_id: str,
    rule: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> int | None:
    """Lower only reviewed NEON one-lane/all-lane alignment choices."""
    choices = rule.get("choices", []) or []
    if rule.get("_type") != "Instruction.Rules.Choice" \
            or len(choices) != 2 or any(choice is None for choice in choices):
        return None
    first = choices[0].get("symbols", []) or []
    second = choices[1].get("symbols", []) or []
    if (len(first) != 1 or first[0].get("rule_id") != "no_align"
            or len(second) != 2
            or second[0].get("_type")
                != "Instruction.Symbols.Literal"
            or second[0].get("value") != ":"
            or second[1].get("_type")
                != "Instruction.Symbols.RuleReference"):
        return None
    name = str(source.get("name", ""))
    one_lane = re.fullmatch(
        r"V(?:ST|LD)([1-4])_1_[AT]([1-3])_(?:nowb|posti|postr)",
        name,
    )
    if one_lane is not None:
        count = int(one_lane[1])
        size_code = int(one_lane[2]) - 1
        expected_rule = {
            1: ("colon_align_choice__8", "align__8"),
            2: ("colon_align_choice__9", "align__9"),
            3: ("colon_align_choice__9", "align__9"),
            4: ("colon_align_choice__10", "align__10"),
        }[count]
        if ((rule_id, second[1].get("rule_id")) == expected_rule
                and bindings.get("size") == (10, 2)
                and bindings.get("index_align") == (4, 4)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<align>") == [
                    {"_type": "AST.Identifier", "value": "index_align"},
                    {"_type": "AST.Identifier", "value": "size"},
                ]):
            return count | (size_code << 8)
    all_lanes = re.fullmatch(
        r"VLD([124])_a_[AT]1_(?:nowb|posti|postr)", name,
    )
    if all_lanes is not None:
        count = int(all_lanes[1])
        expected_rule = {
            1: ("colon_align_choice", "align"),
            2: ("colon_align_choice__2", "align__2"),
            4: ("colon_align_choice__3", "align__3"),
        }[count]
        if ((rule_id, second[1].get("rule_id")) == expected_rule
                and bindings.get("size") == (6, 2)
                and bindings.get("a") == (4, 1)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<align>") == [
                    {"_type": "AST.Identifier", "value": "a"},
                    {"_type": "AST.Identifier", "value": "size"},
                ]):
            return count | (1 << 10)
    multiple = re.fullmatch(
        r"V(?:ST|LD)([1-4])_m_[AT]([1-4])_(?:nowb|posti|postr)",
        name,
    )
    if multiple is not None:
        family = int(multiple[1])
        variant = int(multiple[2])
        list_counts = {
            (4, 1): 4, (1, 4): 4, (2, 2): 4,
            (3, 1): 3, (1, 3): 3, (1, 1): 1,
            (2, 1): 2, (1, 2): 2,
        }
        list_count = list_counts.get((family, variant))
        expected_rule = {
            1: ("colon_align_choice__5", "align__5"),
            2: ("colon_align_choice__6", "align__6"),
            3: ("colon_align_choice__7", "align__7"),
            4: ("colon_align_choice__4", "align__4"),
        }[family]
        if (list_count is not None
                and (rule_id, second[1].get("rule_id")) == expected_rule
                and bindings.get("align") == (4, 2)
                and bindings.get("size") == (6, 2)
                and bindings.get("itype") == (8, 4)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<align>") == [
                    {"_type": "AST.Identifier", "value": "align"},
                ]):
            return family | (1 << 11) | (list_count << 12)
    return None


def reviewed_split_field_value(
    rule_id: str,
    display: str,
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
    expressions: list[tuple[tuple[int, int, int], ...]],
) -> tuple[tuple[int, int, int], ...] | None:
    """Return only reviewed raw-field concatenations and the H-lane index.

    A64 LD/ST single-structure B lanes use Q:S:size, S lanes use Q:S,
    whereas H lanes use Q:S:size[1]: size[0] is the fixed zero element-size
    discriminator, not an index bit.  The remaining entries join split
    register numbers or explicitly named high/low index fields.
    """
    shape = REVIEWED_SPLIT_FIELDS.get((rule_id, display))
    half_lane = rule_id == "index__2" and display == "<index>"
    if half_lane:
        shape = (("Q", 30, 1), ("S", 12, 1), ("size", 10, 2))
    if shape is None or len(expressions) != len(shape):
        return None
    raw = (source.get("_meta") or {}).get("encoded_in", {}).get(display)
    if raw != [
        {"_type": "AST.Identifier", "value": name}
        for name, _start, _width in shape
    ]:
        return None
    if any(bindings.get(name) != (start, width)
           for name, start, width in shape):
        return None
    if rule_id in {"index", "index__2", "index__3"}:
        expected_size = {"index": "'xx'", "index__2": "'x0'",
                         "index__3": "'00'"}[rule_id]
        size_fields = [
            field for field in (source.get("encoding") or {}).get("values", [])
            if field.get("_type") == "Instruction.Encodeset.Field"
            and field.get("name") == "size"
        ]
        if (len(size_fields) != 1
                or size_fields[0].get("value", {}).get("value") != expected_size):
            return None
    if half_lane:
        # The source supplies two size bits, but its low bit is fixed zero.
        # Emit a one-bit field read rather than concatenating that zero.
        return concatenate_encoded_expressions([
            *expressions[:2],
            ((tree.BC_OPCODE["PUSH_FIELD"], 11, 1),),
        ])
    return concatenate_encoded_expressions(expressions)


def reviewed_grouped_zreg(
    rule_id: str,
    rule: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> int | None:
    """Pack an exact SME 2x8/4x4 register for recipe opcode 21.

    The value is ``stride | (ordinal << 8)``.  Reject anything that does not
    have the pinned field placement and grammar; the C renderer independently
    checks the stride, ordinal, and z0-z31 bounds.
    """
    entry = GROUPED_ZREG_RULES.get(rule_id)
    if entry is None or rule.get("_type") != "Instruction.Rules.Rule":
        return None
    stride, ordinal, display = entry
    if (rule.get("display") != display
            or not str(source.get("name", "")).endswith(
                "_2x8" if stride == 8 else "_4x4")
            or bindings.get("T") != (4, 1)
            or bindings.get("Zt") != (0, 3 if stride == 8 else 2)
            or bindings.get("N") != (3, 1)
            or (source.get("_meta") or {}).get("encoded_in", {}).get(display)
                != [
                    {"_type": "AST.Identifier", "value": "T"},
                    {"_type": "AST.Identifier", "value": "Zt"},
                ]):
        return None
    symbols = (rule.get("symbols") or {}).get("symbols") or []
    if symbols != [
        {"_type": "Instruction.Symbols.Literal", "value": "Z"},
        {"_type": "Instruction.Symbols.RuleReference", "rule_id": "UInteger"},
    ]:
        return None
    fields = {
        field.get("name"): field
        for field in (source.get("encoding") or {}).get("values", [])
        if field.get("_type") == "Instruction.Encodeset.Field"
    }
    if (fields.get("T", {}).get("value", {}).get("value") != "'x'"
            or fields.get("Zt", {}).get("value", {}).get("value")
                != ("'xxx'" if stride == 8 else "'xx'")
            or fields.get("N", {}).get("value", {}).get("value")
                not in {"'0'", "'1'"}
            or (stride == 4 and fields.get("op2", {}).get("value", {})
                .get("value") != "'0'")):
        return None
    return stride | (ordinal << 8)


def reviewed_pn_group(
    rule_id: str,
    rule: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> bool:
    """Recognize pn8-pn15 in the exact SME 2x8/4x4 tuple encodings."""
    if (rule_id != "PNg"
            or rule.get("_type") != "Instruction.Rules.Rule"
            or rule.get("display") != "<PNg>"
            or bindings.get("PNg") != (10, 3)
            or (source.get("_meta") or {}).get("encoded_in", {}).get("<PNg>")
                != [{"_type": "AST.Identifier", "value": "PNg"}]
            or (rule.get("symbols") or {}).get("symbols") != [
                {"_type": "Instruction.Symbols.Literal", "value": "PN"},
                {"_type": "Instruction.Symbols.RuleReference", "rule_id": "UInteger"},
            ]):
        return False
    source_symbols = (source.get("assembly") or {}).get("symbols") or []
    if not any(symbol.get("_type") == "Instruction.Symbols.RuleReference"
               and symbol.get("rule_id") in {"Zt1__3", "Zt1__4"}
               for symbol in source_symbols):
        return False
    fields = [
        field for field in (source.get("encoding") or {}).get("values", [])
        if field.get("_type") == "Instruction.Encodeset.Field"
        and field.get("name") == "PNg"
    ]
    return len(fields) == 1 and fields[0].get("value", {}).get("value") == "'xxx'"


def reviewed_indexed_operand(
    rule_id: str,
    rule: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> str | None:
    """Recognize two size-dependent indexed-SIMD register projections.

    In A64 H-element forms M is a lane bit and Rm is a four-bit register;
    in S-element forms M is register bit 4.  In A32/T32 Dm[x], 16-bit
    forms take Dm from Vm[2:0] and the index from Vm[3]:M; 32-bit forms
    take Dm from Vm[3:0] and the index from M.
    """
    if rule.get("_type") != "Instruction.Rules.Rule":
        return None
    if rule_id == "Vm__5":
        display = "<m>"
        fields = (("size", 22, 2, "'xx'"), ("M", 20, 1, "'x'"),
                  ("Rm", 16, 4, "'xxxx'"))
        symbols = [
            {"_type": "Instruction.Symbols.RuleReference", "rule_id": "UInteger"}
        ]
        if not any(tag in str(source.get("name", ""))
                   for tag in ("_asisdelem_", "_asimdelem_")):
            return None
        opcode = "A64_INDEXED_VM"
    elif rule_id == "index_option":
        display = "<index>"
        fields = (("size", 22, 2, "'xx'"), ("H", 11, 1, "'x'"),
                  ("L", 21, 1, "'x'"), ("M", 20, 1, "'x'"))
        symbols = [
            {"_type": "Instruction.Symbols.RuleReference", "rule_id": "UInteger"}
        ]
        if not any(tag in str(source.get("name", ""))
                   for tag in ("_asisdelem_", "_asimdelem_")):
            return None
        opcode = "A64_INDEXED_LANE"
    elif rule_id == "index_option__2":
        display = "<index>"
        fields = (("sz", 22, 1, "'x'"), ("L", 21, 1, "'x'"),
                  ("H", 11, 1, "'x'"))
        symbols = [
            {"_type": "Instruction.Symbols.RuleReference", "rule_id": "UInteger"}
        ]
        if not re.fullmatch(
                r"(FMLA|FMLS|FMUL|FMULX)_(asisdelem|asimdelem)_R_SD",
                str(source.get("name", ""))):
            return None
        opcode = "A64_FP_INDEXED_LANE"
    elif rule_id in {"Dmx__2", "Dmx__3", "Dmx__4"}:
        display = "<Dm[x]>"
        fields = (("M", 5, 1, "'x'"), ("Vm", 0, 4, "'xxxx'"),
                  ("size", 20, 2, "'xx'"))
        symbols = [
            {"_type": "Instruction.Symbols.Literal", "value": "D"},
            {"_type": "Instruction.Symbols.RuleReference", "rule_id": "UInteger"},
            {"_type": "Instruction.Symbols.RuleReference", "rule_id": "Ddx_index"},
        ]
        if (rule_id == "Dmx__2"
                and str(source.get("name", "")) not in {
                    "VMLA_s_A1_D", "VMLA_s_A1_Q",
                    "VMLS_s_A1_D", "VMLS_s_A1_Q",
                    "VMLA_s_T1_D", "VMLA_s_T1_Q",
                    "VMLS_s_T1_D", "VMLS_s_T1_Q",
                }):
            return None
        if (rule_id == "Dmx__3"
                and str(source.get("name", "")) not in {
                    "VMLAL_s_A1", "VMLSL_s_A1",
                    "VMLAL_s_T1", "VMLSL_s_T1",
                }):
            return None
        opcode = "A32_DMX_LANE"
    else:
        return None
    if (rule.get("display") != display
            or (rule.get("symbols") or {}).get("symbols") != symbols
            or (source.get("_meta") or {}).get("encoded_in", {}).get(display)
                != [{"_type": "AST.Identifier", "value": name}
                    for name, _start, _width, _value in fields]
            or any(bindings.get(name) != (start, width)
                   for name, start, width, _value in fields)):
        return None
    encoded_fields = {
        field.get("name"): field
        for field in (source.get("encoding") or {}).get("values", [])
        if field.get("_type") == "Instruction.Encodeset.Field"
    }
    if any(encoded_fields.get(name, {}).get("value", {}).get("value") != value
           for name, _start, _width, value in fields):
        return None
    return opcode


def reviewed_a32_split_indexed_operand(
    rule_id: str,
    rule: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> tuple[str, int] | None:
    """Keep by-element Dm and lane projections consistent across split rules."""
    source_name = str(source.get("name", ""))
    bf16 = False
    if (rule_id in {"Dm__5", "index__11"}
            and re.fullmatch(r"VFM[AS]L_s_[AT]1_Q", source_name)):
        mode = 0  # fixed 16-bit elements
    elif (rule_id in {"Dm__5", "index__33"}
          and source_name in {"VFMA_bfs_A1_Q", "VFMA_bfs_T1_Q"}):
        mode = 0
        bf16 = True
    elif (rule_id in {"Dm__6", "index__34"}
          and re.fullmatch(r"VQDML(AL|SL)_[AT]2", source_name)):
        mode = 1
    elif (rule_id in {"Dm__7", "index__35"}
          and re.fullmatch(r"VMUL_s_[AT]1_[DQ]", source_name)):
        mode = 1
    elif (rule_id in {"Dm__8", "index__36"}
          and re.fullmatch(r"VMULL_s_[AT]1", source_name)):
        mode = 1
    else:
        return None
    register_rule = rule_id.startswith("Dm__")
    display = "<Dm>" if register_rule else "<index>"
    expected_fields = ("Vm",) if register_rule else ("M", "Vm")
    expected_symbols = ([
        {"_type": "Instruction.Symbols.Literal", "value": "D"},
        {"_type": "Instruction.Symbols.RuleReference", "rule_id": "UInteger"},
    ] if register_rule else [
        {"_type": "Instruction.Symbols.RuleReference", "rule_id": "UInteger"},
    ])
    if (rule.get("_type") != "Instruction.Rules.Rule"
            or rule.get("display") != display
            or (rule.get("symbols") or {}).get("symbols") != expected_symbols
            or (source.get("_meta") or {}).get("encoded_in", {}).get(display)
                != [{"_type": "AST.Identifier", "value": name}
                    for name in expected_fields]
            or bindings.get("M") != (5, 1)
            or bindings.get("Vm") != (0, 4)
            or (mode == 1 and bindings.get("size") != (20, 2))):
        return None
    fields = {
        field.get("name"): field
        for field in (source.get("encoding") or {}).get("values", [])
        if field.get("_type") == "Instruction.Encodeset.Field"
    }
    if (fields.get("M", {}).get("value", {}).get("value") != "'x'"
            or fields.get("Vm", {}).get("value", {}).get("value") != "'xxxx'"
            or (mode == 1 and fields.get("size", {}).get("value", {})
                .get("value") != "'xx'")):
        return None
    return ("A32_SPLIT_INDEXED_DM" if register_rule
            else "A32_BF16_INDEXED_LANE" if bf16
            else "A32_SPLIT_INDEXED_LANE", mode)


def reviewed_thumb_shift_alias_imm(
    rule_id: str,
    rule: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> int | None:
    """Resolve T32 MOV-register shift aliases' zero-as-32 special case."""
    groups = {
        "imm3_imm2__4": ({"LSL", "LSLB", "LSLS", "LSLSB"}, 0),
        "imm3_imm2__3": ({"LSR", "LSRB", "LSRS", "LSRSB"}, 1),
        "imm3_imm2__5": ({"ASR", "ASRB", "ASRS", "ASRSB"}, 2),
        "imm3_imm2__6": ({"ROR", "RORB", "RORS", "RORSB"}, 3),
    }
    if rule_id not in groups:
        return None
    names, shift_kind = groups[rule_id]
    name = str(source.get("name", ""))
    base_name = name[:-1] if name.endswith("B") else name
    if (name not in names
            or source.get("operation_id") != f"{base_name}_MOV_r"
            or rule.get("_type") != "Instruction.Rules.Rule"
            or rule.get("display") != "<imm>"
            or (rule.get("symbols") or {}).get("symbols") != [
                {"_type": "Instruction.Symbols.RuleReference", "rule_id": "UInteger"}
            ]
            or (source.get("_meta") or {}).get("encoded_in", {}).get("<imm>")
                != [{"_type": "AST.Identifier", "value": "imm3"},
                    {"_type": "AST.Identifier", "value": "imm2"}]
            or bindings.get("imm3") != (12, 3)
            or bindings.get("imm2") != (6, 2)
            or bindings.get("stype") != (4, 2)):
        return None
    return shift_kind


def reviewed_a32_vcvt_sdm(
    rule_id: str,
    rule: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> bool:
    """Recognize VCVT fixed-point Sdm = (Vd << 1) | D only."""
    if (rule_id != "Vd_D__2"
            or rule.get("_type") != "Instruction.Rules.Rule"
            or rule.get("display") != "<Sdm>"
            or str(source.get("name", "")) not in {
                "VCVT_toxv_A1_H", "VCVT_xv_A1_H",
                "VCVT_toxv_A1_S", "VCVT_xv_A1_S",
                "VCVT_toxv_T1_H", "VCVT_xv_T1_H",
                "VCVT_toxv_T1_S", "VCVT_xv_T1_S",
            }
            or (rule.get("symbols") or {}).get("symbols") != [
                {"_type": "Instruction.Symbols.Literal", "value": "S"},
                {"_type": "Instruction.Symbols.RuleReference",
                 "rule_id": "UInteger"},
            ]
            or (source.get("_meta") or {}).get("encoded_in", {}).get(
                "<Sdm>") != [
                    {"_type": "AST.Identifier", "value": "Vd"},
                    {"_type": "AST.Identifier", "value": "D"},
                ]
            or bindings.get("Vd") != (12, 4)
            or bindings.get("D") != (22, 1)):
        return False
    fields = {
        field.get("name"): field
        for field in (source.get("encoding") or {}).get("values", [])
        if field.get("_type") == "Instruction.Encodeset.Field"
    }
    return (fields.get("Vd", {}).get("value", {}).get("value") == "'xxxx'"
            and fields.get("D", {}).get("value", {}).get("value") == "'x'")


def reviewed_a32_vcvt_ddm(
    rule_id: str,
    rule: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> bool:
    """Recognize VCVT fixed-point Ddm = (D << 4) | Vd only."""
    if (rule_id != "D_Vd__2"
            or rule.get("_type") != "Instruction.Rules.Rule"
            or rule.get("display") != "<Ddm>"
            or str(source.get("name", "")) not in {
                "VCVT_toxv_A1_D", "VCVT_xv_A1_D",
                "VCVT_toxv_T1_D", "VCVT_xv_T1_D",
            }
            or (rule.get("symbols") or {}).get("symbols") != [
                {"_type": "Instruction.Symbols.Literal", "value": "D"},
                {"_type": "Instruction.Symbols.RuleReference",
                 "rule_id": "UInteger"},
            ]
            or (source.get("_meta") or {}).get("encoded_in", {}).get("<Ddm>")
                != [{"_type": "AST.Identifier", "value": "D"},
                    {"_type": "AST.Identifier", "value": "Vd"}]
            or bindings.get("D") != (22, 1)
            or bindings.get("Vd") != (12, 4)
            or bindings.get("sf") != (8, 2)):
        return False
    fields = {
        field.get("name"): field
        for field in (source.get("encoding") or {}).get("values", [])
        if field.get("_type") == "Instruction.Encodeset.Field"
    }
    return (fields.get("D", {}).get("value", {}).get("value") == "'x'"
            and fields.get("Vd", {}).get("value", {}).get("value") == "'xxxx'"
            and fields.get("sf", {}).get("value", {}).get("value") == "'11'")


def reviewed_a32_vfp_imm8(
    rule_id: str,
    rule: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> int | None:
    """Recognize VFPExpandImm's exact VMOV scalar FP imm8 placements."""
    if rule_id != "imm__95":
        return None
    match = re.fullmatch(r"VMOV_i_([AT])2_([HSD])",
                         str(source.get("name", "")))
    if match is None:
        return None
    size = {"H": 1, "S": 2, "D": 3}[match.group(2)]
    if (rule.get("_type") != "Instruction.Rules.Rule"
            or rule.get("display") != "<imm>"
            or (rule.get("symbols") or {}).get("symbols") != [
                {"_type": "Instruction.Symbols.RuleReference", "rule_id": "UInteger"}
            ]
            or (source.get("_meta") or {}).get("encoded_in", {}).get("<imm>")
                != [{"_type": "AST.Identifier", "value": name}
                    for name in ("imm4H", "imm4L", "size")]
            or bindings.get("imm4H") != (16, 4)
            or bindings.get("imm4L") != (0, 4)
            or bindings.get("size") != (8, 2)):
        return None
    fields = {
        field.get("name"): field
        for field in (source.get("encoding") or {}).get("values", [])
        if field.get("_type") == "Instruction.Encodeset.Field"
    }
    if (fields.get("imm4H", {}).get("value", {}).get("value") != "'xxxx'"
            or fields.get("imm4L", {}).get("value", {}).get("value") != "'xxxx'"
            or fields.get("size", {}).get("value", {}).get("value")
                != f"'{size:02b}'"):
        return None
    return size


def reviewed_a32_vdup_lane(
    rule_id: str,
    rule: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> bool:
    """Render VDUP's imm4-selected Dm lane without flattening imm4."""
    if (rule_id != "Dmx"
            or rule.get("_type") != "Instruction.Rules.Rule"
            or rule.get("display") != "<Dm[x]>"
            or not re.fullmatch(r"VDUP_s_[AT]1_[DQ]",
                                 str(source.get("name", "")))
            or (rule.get("symbols") or {}).get("symbols") != [
                {"_type": "Instruction.Symbols.Literal", "value": "D"},
                {"_type": "Instruction.Symbols.RuleReference", "rule_id": "UInteger"},
                {"_type": "Instruction.Symbols.RuleReference", "rule_id": "Ddx_index"},
            ]
            or (source.get("_meta") or {}).get("encoded_in", {}).get("<Dm[x]>")
                != [{"_type": "AST.Identifier", "value": "M"},
                    {"_type": "AST.Identifier", "value": "Vm"}]
            or (source.get("_meta") or {}).get("encoded_in", {}).get("<size>")
                != [{"_type": "AST.Identifier", "value": "imm4"}]
            or bindings.get("M") != (5, 1)
            or bindings.get("Vm") != (0, 4)
            or bindings.get("imm4") != (16, 4)):
        return False
    fields = {
        field.get("name"): field
        for field in (source.get("encoding") or {}).get("values", [])
        if field.get("_type") == "Instruction.Encodeset.Field"
    }
    return all(fields.get(name, {}).get("value", {}).get("value") == value
               for name, value in {"M": "'x'", "Vm": "'xxxx'",
                                   "imm4": "'xxxx'"}.items())


def reviewed_a32_vdup_lane_size(
    rule_id: str,
    rule: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> bool:
    if (rule_id != "size__4"
            or rule.get("_type") != "Instruction.Rules.Rule"
            or rule.get("display") != "<size>"
            or not re.fullmatch(r"VDUP_s_[AT]1_[DQ]",
                                 str(source.get("name", "")))
            or (rule.get("symbols") or {}).get("symbols") != [
                {"_type": "Instruction.Symbols.RuleReference", "rule_id": "UInteger"}
            ]
            or (source.get("_meta") or {}).get("encoded_in", {}).get("<size>")
                != [{"_type": "AST.Identifier", "value": "imm4"}]
            or bindings.get("imm4") != (16, 4)):
        return False
    fields = {
        field.get("name"): field
        for field in (source.get("encoding") or {}).get("values", [])
        if field.get("_type") == "Instruction.Encodeset.Field"
    }
    return fields.get("imm4", {}).get("value", {}).get("value") == "'xxxx'"


def reviewed_a32_vcvt_fbits(
    rule_id: str,
    rule: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> bool:
    """VCVT fixed-point fbits = (sx ? 32 : 16) - ((imm4 << 1) | i)."""
    if (rule_id != "fbits__5"
            or rule.get("_type") != "Instruction.Rules.Rule"
            or rule.get("display") != "<fbits>"
            or str(source.get("name", "")) not in {
                "VCVT_toxv_A1_H", "VCVT_xv_A1_H",
                "VCVT_toxv_A1_S", "VCVT_xv_A1_S",
                "VCVT_toxv_A1_D", "VCVT_xv_A1_D",
                "VCVT_toxv_T1_H", "VCVT_xv_T1_H",
                "VCVT_toxv_T1_S", "VCVT_xv_T1_S",
                "VCVT_toxv_T1_D", "VCVT_xv_T1_D",
            }
            or (rule.get("symbols") or {}).get("symbols") != [
                {"_type": "Instruction.Symbols.RuleReference",
                 "rule_id": "UInteger"},
            ]
            or (source.get("_meta") or {}).get("encoded_in", {}).get(
                "<fbits>") is not None
            or any(bindings.get(name) != shape for name, shape in {
                "sx": (7, 1), "i": (5, 1), "imm4": (0, 4)
            }.items())):
        return False
    fields = {
        field.get("name"): field
        for field in (source.get("encoding") or {}).get("values", [])
        if field.get("_type") == "Instruction.Encodeset.Field"
    }
    return all(fields.get(name, {}).get("value", {}).get("value") == value
               for name, value in {
                   "sx": "'x'", "i": "'x'", "imm4": "'xxxx'"
               }.items())


def reviewed_a64_asimd_optional_lsl(
    rule_id: str,
    rule: dict[str, Any],
    rules: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> int | None:
    """Exact AdvSIMD immediate's omitted-zero or explicit LSL suffix."""
    modes = {
        "optional_extend__18": (1, "_L_sl", "amount_option__8",
                                 "'0xx0'", [
                                     "amount_00_0", "amount_01_8",
                                     "amount_10_16", "amount_11_24"]),
        "optional_extend__20": (2, "_L_hl", "amount_option__10",
                                 "'10x0'", ["amount_0_0__2", "amount_1_8"]),
    }
    if rule_id not in modes:
        return None
    mode, suffix, amount_rule, pattern, amounts = modes[rule_id]
    if (rule.get("_type") != "Instruction.Rules.Choice"
            or source.get("name") not in {
                name + suffix for name in (
                    "MOVI_asimdimm", "ORR_asimdimm",
                    "MVNI_asimdimm", "BIC_asimdimm")
            }
            or bindings.get("cmode") != (12, 4)
            or (source.get("_meta") or {}).get("encoded_in", {}).get(
                "<amount>") != [
                    {"_type": "AST.Identifier", "value": "cmode"}
                ]):
        return None
    fields = {
        field.get("name"): field
        for field in (source.get("encoding") or {}).get("values", [])
        if field.get("_type") == "Instruction.Encodeset.Field"
    }
    if source["name"].startswith(("ORR_", "BIC_")):
        mode += 2
        pattern = pattern[:-2] + "1'"
    if fields.get("cmode", {}).get("value", {}).get("value") != pattern:
        return None
    choices = [
        [(symbol.get("_type"), symbol.get("rule_id"),
          symbol.get("value"))
         for symbol in ((choice or {}).get("symbols") or [])]
        for choice in rule.get("choices", []) or []
    ]
    expected = [
        [("Instruction.Symbols.RuleReference", "amount_default", None)],
        [("Instruction.Symbols.RuleReference", "COMMA", None),
         ("Instruction.Symbols.Literal", None, "LSL"),
         ("Instruction.Symbols.RuleReference", "OPT_SPACE", None),
         ("Instruction.Symbols.RuleReference", "hash", None),
         ("Instruction.Symbols.RuleReference", amount_rule, None)],
    ]
    if choices != expected:
        return None
    amount_choices = rules.get(amount_rule, {}).get("choices", []) or []
    actual_amounts = [
        [symbol.get("rule_id") for symbol in
         ((choice or {}).get("symbols") or [])]
        for choice in amount_choices
    ]
    if actual_amounts != [[name] for name in amounts]:
        return None
    if any((rules.get(name, {}).get("symbols") or {}).get("symbols") != [
            {"_type": "Instruction.Symbols.Literal", "value": str(i * 8)}
        ] for i, name in enumerate(amounts)):
        return None
    return mode


def reviewed_a64_sve_optional_vl(
    rule_id: str,
    rule: dict[str, Any],
    rules: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> bool:
    """Exact signed imm9h:imm9l optional MUL VL addressing suffix."""
    if (rule_id != "optional_imm__25"
            or rule.get("_type") != "Instruction.Rules.Choice"
            or source.get("name") not in {
                "ldr_p_bi_", "ldr_z_bi_", "str_p_bi_", "str_z_bi_"
            }
            or bindings.get("imm9h") != (16, 6)
            or bindings.get("imm9l") != (10, 3)
            or (source.get("_meta") or {}).get("encoded_in", {}).get(
                "<imm>") != [
                    {"_type": "AST.Identifier", "value": "imm9h"},
                    {"_type": "AST.Identifier", "value": "imm9l"},
                ]):
        return False
    fields = {
        field.get("name"): field
        for field in (source.get("encoding") or {}).get("values", [])
        if field.get("_type") == "Instruction.Encodeset.Field"
    }
    if (fields.get("imm9h", {}).get("value", {}).get("value") != "'xxxxxx'"
            or fields.get("imm9l", {}).get("value", {}).get("value")
                != "'xxx'"):
        return False
    choices = [
        [(symbol.get("_type"), symbol.get("rule_id"),
          symbol.get("value"))
         for symbol in ((choice or {}).get("symbols") or [])]
        for choice in rule.get("choices", []) or []
    ]
    expected = [
        [("Instruction.Symbols.RuleReference", "default_imm", None)],
        [("Instruction.Symbols.RuleReference", "COMMA", None),
         ("Instruction.Symbols.RuleReference", "hash", None),
         ("Instruction.Symbols.RuleReference", "imm__77", None),
         ("Instruction.Symbols.RuleReference", "COMMA", None),
         ("Instruction.Symbols.Literal", None, "MUL"),
         ("Instruction.Symbols.RuleReference", "OPT_SPACE", None),
         ("Instruction.Symbols.Literal", None, "VL")],
    ]
    inner = rules.get("imm__77", {})
    return (choices == expected
            and inner.get("_type") == "Instruction.Rules.Rule"
            and inner.get("display") == "<imm>"
            and (inner.get("symbols") or {}).get("symbols") == [
                {"_type": "Instruction.Symbols.RuleReference",
                 "rule_id": "SInteger"}
            ])


def reviewed_a64_sve_extend_t(
    rule_id: str,
    rule: dict[str, Any],
    rules: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> int | None:
    """SVE signed/unsigned byte/halfword extension element suffix."""
    if rule_id == "T_xt_SD":
        mode = 1
        leaves = (("T_xt_S__2", "S"), ("T_xt_D__2", "D"))
        stems = ("sxth", "uxth")
    elif rule_id == "T_xt_HSD":
        mode = 2
        leaves = (("T_xt_H", "H"), ("T_xt_S", "S"),
                  ("T_xt_D", "D"))
        stems = ("sxtb", "uxtb")
    else:
        return None
    names = {f"{stem}_z_p_z_{suffix}"
             for stem in stems for suffix in ("m", "z")}
    if (rule.get("_type") != "Instruction.Rules.Choice"
            or rule.get("display") != "<T>"
            or source.get("name") not in names
            or bindings.get("size") != (22, 2)
            or (source.get("_meta") or {}).get("encoded_in", {}).get(
                "<T>") != [
                    {"_type": "AST.Identifier", "value": "size"}
                ]):
        return None
    fields = {
        field.get("name"): field
        for field in (source.get("encoding") or {}).get("values", [])
        if field.get("_type") == "Instruction.Encodeset.Field"
    }
    if fields.get("size", {}).get("value", {}).get("value") != "'xx'":
        return None
    actual = [
        [symbol.get("rule_id") for symbol in
         ((choice or {}).get("symbols") or [])]
        for choice in rule.get("choices", []) or []
    ]
    if actual != [[name] for name, _spelling in leaves]:
        return None
    if any((rules.get(name, {}).get("symbols") or {}).get("symbols") != [
            {"_type": "Instruction.Symbols.Literal", "value": spelling}
        ] for name, spelling in leaves):
        return None
    return mode


def reviewed_a64_asimd_ins_ts(
    rule_id: str,
    rule: dict[str, Any],
    rules: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> bool:
    """INS element type is selected by imm5's least-significant set bit."""
    canonical = source.get("name") in {
        "INS_asimdins_IR_r", "INS_asimdins_IV_v"
    }
    linked_alias = (source.get("name") == "MOV"
                    and source.get("operation_id") in {
                        "MOV_INS_advsimd_gen", "MOV_INS_advsimd_elt"
                    } and source.get("encoding") is None)
    if (rule_id != "Ts_option"
            or rule.get("_type") != "Instruction.Rules.Choice"
            or rule.get("display") != "<Ts>"
            or not (canonical or linked_alias)
            or bindings.get("imm5") != (16, 5)
            or (source.get("_meta") or {}).get("encoded_in", {}).get(
                "<Ts>") != [
                    {"_type": "AST.Identifier", "value": "imm5"}
                ]):
        return False
    fields = {
        field.get("name"): field
        for field in (source.get("encoding") or {}).get("values", [])
        if field.get("_type") == "Instruction.Encodeset.Field"
    }
    if canonical and fields.get("imm5", {}).get("value", {}).get(
            "value") != "'xxxxx'":
        return False
    leaves = (("Ts_xxxx1_B", "B"), ("Ts_xxx10_H", "H"),
              ("Ts_xx100_S", "S"), ("Ts_x1000_D", "D"))
    actual = [
        [symbol.get("rule_id") for symbol in
         ((choice or {}).get("symbols") or [])]
        for choice in rule.get("choices", []) or []
    ]
    return (actual == [[name] for name, _spelling in leaves]
            and all((rules.get(name, {}).get("symbols") or {}).get(
                "symbols") == [
                    {"_type": "Instruction.Symbols.Literal",
                     "value": spelling}
                ] for name, spelling in leaves))


def reviewed_a64_asimd_ins_r(
    rule_id: str,
    rule: dict[str, Any],
    rules: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> bool:
    """INS/MOV integer source prefix is X for D lanes, W otherwise."""
    forms = {
        "R_option__4": ("INS_asimdins_IR_r", "INS_advsimd_gen",
                        ("imm5_R__2", "R_x1000_X__2")),
        "R_option__5": ("MOV", "MOV_INS_advsimd_gen",
                        ("R_xxxx1_W", "R_x1000_X__3")),
    }
    if rule_id not in forms:
        return False
    name, operation_id, leaves = forms[rule_id]
    if (source.get("name") != name
            or source.get("operation_id") != operation_id
            or rule.get("_type") != "Instruction.Rules.Choice"
            or rule.get("display") != "<R>"
            or bindings.get("imm5") != (16, 5)
            or (source.get("_meta") or {}).get("encoded_in", {}).get(
                "<R>") != [
                    {"_type": "AST.Identifier", "value": "imm5"}
                ]):
        return False
    if rule_id == "R_option__4":
        fields = {
            field.get("name"): field
            for field in (source.get("encoding") or {}).get("values", [])
            if field.get("_type") == "Instruction.Encodeset.Field"
        }
        if fields.get("imm5", {}).get("value", {}).get("value") \
                != "'xxxxx'":
            return False
    elif source.get("encoding") is not None:
        return False
    actual = [
        [symbol.get("rule_id") for symbol in
         ((choice or {}).get("symbols") or [])]
        for choice in rule.get("choices", []) or []
    ]
    return (actual == [[leaf] for leaf in leaves]
            and all((rules.get(leaf, {}).get("symbols") or {}).get(
                "symbols") == [
                    {"_type": "Instruction.Symbols.Literal",
                     "value": "W" if i == 0 else "X"}
                ] for i, leaf in enumerate(leaves)))


def reviewed_a64_asimd_ins_lane(
    rule_id: str,
    rule: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> int | None:
    """INS lane indexes use imm5's element marker as a scale."""
    rules = {
        "imm5_index": (0, "<index>", "IR_r", "gen", ("imm5",)),
        "imm5_index__5": (0, "<index1>", "IV_v", "elt", ("imm5",)),
        "imm5_index__6": (1, "<index2>", "IV_v", "elt",
                           ("imm5", "imm4")),
    }
    if rule_id not in rules:
        return None
    mode, display, canonical_suffix, alias_suffix, fields = rules[rule_id]
    canonical = (source.get("name") ==
                 f"INS_asimdins_{canonical_suffix}"
                 and source.get("operation_id") ==
                 f"INS_advsimd_{alias_suffix}")
    linked_alias = (source.get("name") == "MOV"
                    and source.get("operation_id") ==
                    f"MOV_INS_advsimd_{alias_suffix}"
                    and source.get("encoding") is None)
    if (not (canonical or linked_alias)
            or rule.get("_type") != "Instruction.Rules.Rule"
            or rule.get("display") != display
            or (rule.get("symbols") or {}).get("symbols") != [
                {"_type": "Instruction.Symbols.RuleReference",
                 "rule_id": "UInteger"}
            ]
            or bindings.get("imm5") != (16, 5)
            or (mode != 0 and bindings.get("imm4") != (11, 4))
            or (source.get("_meta") or {}).get("encoded_in", {}).get(
                display) != [
                    {"_type": "AST.Identifier", "value": field}
                    for field in fields
                ]):
        return None
    if canonical:
        encoding_fields = {
            field.get("name"): field
            for field in (source.get("encoding") or {}).get("values", [])
            if field.get("_type") == "Instruction.Encodeset.Field"
        }
        if encoding_fields.get("imm5", {}).get("value", {}).get(
                "value") != "'xxxxx'":
            return None
        if mode != 0 and encoding_fields.get("imm4", {}).get(
                "value", {}).get("value") != "'xxxx'":
            return None
    return mode


def reviewed_a64_asimd_ins_rn(
    rule_id: str,
    rule: dict[str, Any],
    rules: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> bool:
    """INS/MOV integer source register 31 spells ZR, not register 31."""
    if (rule_id != "Rn_option__2"
            or rule.get("_type") != "Instruction.Rules.Choice"
            or rule.get("display") != "<n>"
            or bindings.get("Rn") != (5, 5)
            or (source.get("_meta") or {}).get("encoded_in", {}).get(
                "<n>") != [
                    {"_type": "AST.Identifier", "value": "Rn"}
                ]):
        return False
    canonical = (source.get("name") == "INS_asimdins_IR_r"
                 and source.get("operation_id") == "INS_advsimd_gen")
    linked_alias = (source.get("name") == "MOV"
                    and source.get("operation_id") ==
                    "MOV_INS_advsimd_gen"
                    and source.get("encoding") is None)
    if not (canonical or linked_alias):
        return False
    if canonical:
        fields = {
            field.get("name"): field
            for field in (source.get("encoding") or {}).get("values", [])
            if field.get("_type") == "Instruction.Encodeset.Field"
        }
        if fields.get("Rn", {}).get("value", {}).get("value") \
                != "'xxxxx'":
            return False
    actual = [
        [symbol.get("rule_id") for symbol in
         ((choice or {}).get("symbols") or [])]
        for choice in rule.get("choices", []) or []
    ]
    return (actual == [["n_ZR"], ["n"]]
            and (rules.get("n_ZR", {}).get("symbols") or {}).get(
                "symbols") == [
                    {"_type": "Instruction.Symbols.Literal", "value": "ZR"}
                ]
            and (rules.get("n", {}).get("symbols") or {}).get(
                "symbols") == [
                    {"_type": "Instruction.Symbols.RuleReference",
                     "rule_id": "UInteger"}
                ])


def reviewed_a32_mrs_spec_reg(
    rule_id: str,
    rule: dict[str, Any],
    rules: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> int | None:
    """A32/T32 MRS R bit selects APSR/SPSR spelling."""
    shifts = {"MRS_A1_AS": 22, "MRS_T1_AS": 20}
    if (rule_id != "spec_reg_option"
            or rule.get("_type") != "Instruction.Rules.Choice"
            or rule.get("display") != "<spec_reg>"
            or source.get("name") not in shifts
            or source.get("operation_id") != "MRS_a32"
            or bindings.get("R") != (shifts[source["name"]], 1)
            or (source.get("_meta") or {}).get("encoded_in", {}).get(
                "<spec_reg>") != [
                    {"_type": "AST.Identifier", "value": "R"}
                ]):
        return None
    fields = {
        field.get("name"): field
        for field in (source.get("encoding") or {}).get("values", [])
        if field.get("_type") == "Instruction.Encodeset.Field"
    }
    if fields.get("R", {}).get("value", {}).get("value") != "'x'":
        return None
    leaves = (("CPSR", "CPSR"), ("APSR", "APSR"),
              ("spec_reg_1_SPSR", "SPSR"))
    actual = [
        [symbol.get("rule_id") for symbol in
         ((choice or {}).get("symbols") or [])]
        for choice in rule.get("choices", []) or []
    ]
    if (actual != [[name] for name, _text in leaves]
            or any((rules.get(name, {}).get("symbols") or {}).get(
                "symbols") != [
                    {"_type": "Instruction.Symbols.Literal", "value": text}
                ] for name, text in leaves)):
        return None
    return shifts[source["name"]]


def reviewed_a32_vfp_spec_reg(
    rule_id: str,
    rule: dict[str, Any],
    rules: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> int | None:
    """Named VFP system registers, rejecting reserved selectors at runtime."""
    choices = {
        "spec_reg_option__2": (
            0, "VMSR", (("spec_reg_0000_FPSID", "FPSID"),
                        ("spec_reg_0001_FPSCR", "FPSCR"),
                        ("spec_reg_001x_UNPREDICTABLE", "UNPREDICTABLE"),
                        ("spec_reg_1000_FPEXC", "FPEXC"))),
        "spec_reg_option__3": (
            1, "VMRS", (("spec_reg_0000_FPSID", "FPSID"),
                        ("spec_reg_0001_FPSCR", "FPSCR"),
                        ("spec_reg_001x_UNPREDICTABLE__2", "UNPREDICTABLE"),
                        ("spec_reg_0101_MVFR2", "MVFR2"),
                        ("spec_reg_0110_MVFR1", "MVFR1"),
                        ("spec_reg_0111_MVFR0", "MVFR0"),
                        ("spec_reg_1000_FPEXC", "FPEXC"))),
    }
    if rule_id not in choices:
        return None
    mode, stem, leaves = choices[rule_id]
    if (rule.get("_type") != "Instruction.Rules.Choice"
            or rule.get("display") != "<spec_reg>"
            or source.get("name") not in {
                f"{stem}_A1_AS", f"{stem}_T1_AS"
            }
            or source.get("operation_id") != stem
            or bindings.get("reg") != (16, 4)
            or (source.get("_meta") or {}).get("encoded_in", {}).get(
                "<spec_reg>") != [
                    {"_type": "AST.Identifier", "value": "reg"}
                ]):
        return None
    fields = {
        field.get("name"): field
        for field in (source.get("encoding") or {}).get("values", [])
        if field.get("_type") == "Instruction.Encodeset.Field"
    }
    if fields.get("reg", {}).get("value", {}).get("value") != "'xxxx'":
        return None
    actual = [
        [symbol.get("rule_id") for symbol in
         ((choice or {}).get("symbols") or [])]
        for choice in rule.get("choices", []) or []
    ]
    if (actual != [[name] for name, _text in leaves]
            or any((rules.get(name, {}).get("symbols") or {}).get(
                "symbols") != [
                    {"_type": "Instruction.Symbols.Literal", "value": text}
                ] for name, text in leaves)):
        return None
    return mode


def reviewed_a32_vshll_sign(
    rule_id: str,
    rule: dict[str, Any],
    rules: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> int | None:
    """VSHLL A1/T1 signedness follows U, at different bit positions."""
    shifts = {"VSHLL_A1": 24, "VSHLL_T1": 28}
    if (rule_id != "type_option__4"
            or rule.get("_type") != "Instruction.Rules.Choice"
            or rule.get("display") != "<type>"
            or source.get("name") not in shifts
            or source.get("operation_id") != "VSHLL"
            or bindings.get("U") != (shifts[source["name"]], 1)
            or (source.get("_meta") or {}).get("encoded_in", {}).get(
                "<type>") is not None):
        return None
    fields = {
        field.get("name"): field
        for field in (source.get("encoding") or {}).get("values", [])
        if field.get("_type") == "Instruction.Encodeset.Field"
    }
    if fields.get("U", {}).get("value", {}).get("value") != "'x'":
        return None
    leaves = (("s_rule", "S"), ("u_rule", "U"))
    actual = [
        [symbol.get("rule_id") for symbol in
         ((choice or {}).get("symbols") or [])]
        for choice in rule.get("choices", []) or []
    ]
    if (actual != [[name] for name, _text in leaves]
            or any((rules.get(name, {}).get("symbols") or {}).get(
                "symbols") != [
                    {"_type": "Instruction.Symbols.Literal", "value": text}
                ] for name, text in leaves)):
        return None
    return shifts[source["name"]]


def reviewed_a32_vshll_imm6(
    rule_id: str,
    rule: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> int | None:
    """A1/T1 VSHLL: imm6 encodes both element width and shift amount."""
    modes = {"size__5": ("<size>", 0),
             "imm__108": ("<imm>", 1)}
    if rule_id not in modes:
        return None
    display, mode = modes[rule_id]
    if (rule.get("_type") != "Instruction.Rules.Rule"
            or rule.get("display") != display
            or (rule.get("symbols") or {}).get("symbols") != [
                {"_type": "Instruction.Symbols.RuleReference",
                 "rule_id": "UInteger"}
            ]
            or source.get("name") not in {"VSHLL_A1", "VSHLL_T1"}
            or source.get("operation_id") != "VSHLL"
            or bindings.get("imm6") != (16, 6)
            or (source.get("_meta") or {}).get("encoded_in", {}).get(
                display) is not None):
        return None
    fields = {
        field.get("name"): field
        for field in (source.get("encoding") or {}).get("values", [])
        if field.get("_type") == "Instruction.Encodeset.Field"
    }
    if fields.get("imm6", {}).get("value", {}).get("value") != "'xxxxxx'":
        return None
    return mode


def reviewed_a32_barrier_option(
    rule_id: str,
    rule: dict[str, Any],
    rules: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> bool:
    """Exact DSB/DMB option grammar; only architecturally named values emit."""
    forms = {
        "DSB_A1": ("crm_option_choice", "CRm_option__4", "DSB_a32"),
        "DSB_T1": ("crm_option_choice", "CRm_option__4", "DSB_a32"),
        "DMB_A1": ("crm_option_choice__2", "CRm_option__5", "DMB_a32"),
        "DMB_T1": ("crm_option_choice__2", "CRm_option__5", "DMB_a32"),
    }
    selected = forms.get(source.get("name"))
    if selected is None:
        return False
    outer, inner, operation_id = selected
    if (rule_id != outer or source.get("operation_id") != operation_id
            or bindings.get("option") != (0, 4)
            or (source.get("_meta") or {}).get("encoded_in", {}).get(
                "<option>") != [
                    {"_type": "AST.Identifier", "value": "option"}
                ]
            or rule.get("_type") != "Instruction.Rules.Choice"
            or rule.get("display") is not None):
        return False
    choices = rule.get("choices", []) or []
    if (len(choices) != 2 or choices[0] is not None
            or [item.get("rule_id") for item in
                ((choices[1] or {}).get("symbols") or [])] != [inner]):
        return False
    fields = {
        field.get("name"): field
        for field in (source.get("encoding") or {}).get("values", [])
        if field.get("_type") == "Instruction.Encodeset.Field"
    }
    if fields.get("option", {}).get("value", {}).get("value") != "'xxxx'":
        return False
    names = ("SY", "ST", "LD", "ISH", "ISHST", "ISHLD",
             "NSH", "NSHST", "NSHLD", "OSH", "OSHST", "OSHLD")
    selected_rule = rules.get(inner, {})
    actual = [
        [symbol.get("rule_id") for symbol in
         ((choice or {}).get("symbols") or [])]
        for choice in selected_rule.get("choices", []) or []
    ]
    if (selected_rule.get("_type") != "Instruction.Rules.Choice"
            or selected_rule.get("display") != "<option>"
            or actual != [[f"CRm_{name}"] for name in names]):
        return False
    for name in names:
        leaf = rules.get(f"CRm_{name}", {})
        if (leaf.get("condition") != {"_type": "AST.Bool", "value": True}
                or (leaf.get("symbols") or {}).get("symbols") != [
                    {"_type": "Instruction.Symbols.Literal", "value": name}
                ]):
            return False
    return True


def reviewed_a64_sve_gpr_width(
    rule_id: str,
    rule: dict[str, Any],
    rules: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> bool:
    """SVE W/X source-register width follows the two-bit element size."""
    forms = {
        "R__2": {"clasta_r_p_z_", "clastb_r_p_z_"},
        "R__5": {"index_z_ir_"},
        "R__6": {"index_z_ri_"},
        "R__7": {"index_z_rr_"},
        "R__8": {"insr_z_r_"},
        "R__9": {"lasta_r_p_z_", "lastb_r_p_z_"},
    }
    if (source.get("name") not in forms.get(rule_id, set())
            or rule.get("_type") != "Instruction.Rules.Choice"
            or rule.get("display") != "<R>"
            or bindings.get("size") != (22, 2)
            or (source.get("_meta") or {}).get("encoded_in", {}).get(
                "<R>") != [
                    {"_type": "AST.Identifier", "value": "size"}
                ]):
        return False
    fields = {
        field.get("name"): field
        for field in (source.get("encoding") or {}).get("values", [])
        if field.get("_type") == "Instruction.Encodeset.Field"
    }
    if fields.get("size", {}).get("value", {}).get("value") != "'xx'":
        return False
    suffix = rule_id.split("__", 1)[1]
    names = (f"R_W__{suffix}", f"R_X__{suffix}")
    actual = [[symbol.get("rule_id") for symbol in
               ((choice or {}).get("symbols") or [])]
              for choice in rule.get("choices", []) or []]
    if actual != [[name] for name in names]:
        return False
    for name, text in zip(names, ("W", "X")):
        leaf = rules.get(name, {})
        if (leaf.get("condition") != {"_type": "AST.Bool", "value": True}
                or (leaf.get("symbols") or {}).get("symbols") != [
                    {"_type": "Instruction.Symbols.Literal", "value": text}
                ]):
            return False
    return True


def reviewed_a64_sve_gpr_number(
    rule_id: str,
    rule: dict[str, Any],
    rules: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> int | None:
    """Exact SVE GPR number or ZR choice for INDEX/INSR/LAST forms."""
    cases = {
        ("n__5", "index_z_ri_"): ("<n>", "Rn", 5, "n_ZR__2", "nSP_number"),
        ("n__5", "index_z_rr_"): ("<n>", "Rn", 5, "n_ZR__2", "nSP_number"),
        ("m__3", "index_z_ir_"): ("<m>", "Rm", 16, "m_ZR__2", "m_number"),
        ("m__3", "index_z_rr_"): ("<m>", "Rm", 16, "m_ZR__2", "m_number"),
        ("m__3", "insr_z_r_"): ("<m>", "Rm", 5, "m_ZR__2", "m_number"),
        ("d__4", "lasta_r_p_z_"): ("<d>", "Rd", 0, "d_ZR", "d_number"),
        ("d__4", "lastb_r_p_z_"): ("<d>", "Rd", 0, "d_ZR", "d_number"),
        ("dn", "clasta_r_p_z_"): ("<dn>", "Rdn", 0, "dn_ZR", "dn_number"),
        ("dn", "clastb_r_p_z_"): ("<dn>", "Rdn", 0, "dn_ZR", "dn_number"),
    }
    selected = cases.get((rule_id, source.get("name")))
    if selected is None:
        return None
    display, field, shift, zero_rule, number_rule = selected
    if (rule.get("_type") != "Instruction.Rules.Choice"
            or rule.get("display") != display
            or bindings.get(field) != (shift, 5)
            or (source.get("_meta") or {}).get("encoded_in", {}).get(
                display) != [
                    {"_type": "AST.Identifier", "value": field}
                ]):
        return None
    fields = {
        item.get("name"): item
        for item in (source.get("encoding") or {}).get("values", [])
        if item.get("_type") == "Instruction.Encodeset.Field"
    }
    if fields.get(field, {}).get("value", {}).get("value") != "'xxxxx'":
        return None
    actual = [[symbol.get("rule_id") for symbol in
               ((choice or {}).get("symbols") or [])]
              for choice in rule.get("choices", []) or []]
    if actual != [[zero_rule], [number_rule]]:
        return None
    zero = rules.get(zero_rule, {})
    number = rules.get(number_rule, {})
    if (zero.get("condition") != {"_type": "AST.Bool", "value": True}
            or number.get("condition") != {"_type": "AST.Bool", "value": True}
            or (zero.get("symbols") or {}).get("symbols") != [
                {"_type": "Instruction.Symbols.Literal", "value": "ZR"}
            ]
            or (number.get("symbols") or {}).get("symbols") != [
                {"_type": "Instruction.Symbols.RuleReference",
                 "rule_id": "UInteger"}
            ]):
        return None
    return shift


def reviewed_a64_sve_t_size(
    rule_id: str,
    rule: dict[str, Any],
    rules: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> int | None:
    """Verified SVE .s/.d or .h/.s/.d two-bit element selectors."""
    cases = {
        ("T_SD", "revh_z_z_m"): (22, 2, ("T_S", "T_D")),
        ("T_SD", "revh_z_z_z"): (22, 2, ("T_S", "T_D")),
        ("T__38", "flogb_z_p_z_m"):
            (17, 1, ("T_H__27", "T_S__30", "T_D__27")),
        ("T__38", "flogb_z_p_z_z"):
            (13, 1, ("T_H__27", "T_S__30", "T_D__27")),
        ("T__95", "st1h_z_p_br_"):
            (21, 1, ("T_H__73", "T_S__77", "T_D__69")),
        ("T__95", "st1h_z_p_bi_"):
            (21, 1, ("T_H__73", "T_S__77", "T_D__69")),
        ("T__64", "luti4_mz4_ztz_1"):
            (12, 1, ("T_H", "T_S")),
    }
    selected = cases.get((rule_id, source.get("name")))
    if selected is None:
        return None
    shift, minimum, names = selected
    if (rule.get("_type") != "Instruction.Rules.Choice"
            or rule.get("display") != "<T>"
            or bindings.get("size") != (shift, 2)
            or (source.get("_meta") or {}).get("encoded_in", {}).get(
                "<T>") != [
                    {"_type": "AST.Identifier", "value": "size"}
                ]):
        return None
    fields = {
        item.get("name"): item
        for item in (source.get("encoding") or {}).get("values", [])
        if item.get("_type") == "Instruction.Encodeset.Field"
    }
    if fields.get("size", {}).get("value", {}).get("value") != "'xx'":
        return None
    actual = [[symbol.get("rule_id") for symbol in
               ((choice or {}).get("symbols") or [])]
              for choice in rule.get("choices", []) or []]
    if actual != [[name] for name in names]:
        return None
    for name, letter in zip(names, "bhsd"[minimum:]):
        leaf = rules.get(name, {})
        if (leaf.get("condition") != {"_type": "AST.Bool", "value": True}
                or (leaf.get("symbols") or {}).get("symbols") != [
                    {"_type": "Instruction.Symbols.Literal",
                     "value": letter.upper()}
                ]):
            return None
    return shift | (minimum << 8) | ((minimum + len(names) - 1) << 16)


def reviewed_a64_sve_tszhl_type(
    rule_id: str,
    rule: dict[str, Any],
    rules: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> bool:
    """XAR/SRI/SLI element type from the highest set tszh:tszl bit."""
    cases = {
        ("T__103", "xar_z_zzi_"):
            ("T_B__55", "T_H__78", "T_S__83", "T_D__76"),
        ("T__85", "sri_z_zzi_"):
            ("T_B__44", "T_H__64", "T_S__70", "T_D__64"),
        ("T__85", "sli_z_zzi_"):
            ("T_B__44", "T_H__64", "T_S__70", "T_D__64"),
    }
    names = cases.get((rule_id, source.get("name")))
    if (names is None or rule.get("_type") != "Instruction.Rules.Choice"
            or rule.get("display") != "<T>"
            or bindings.get("tszh") != (22, 2)
            or bindings.get("tszl") != (19, 2)
            or (source.get("_meta") or {}).get("encoded_in", {}).get(
                "<T>") != [
                    {"_type": "AST.Identifier", "value": "tszh"},
                    {"_type": "AST.Identifier", "value": "tszl"},
                ]):
        return False
    fields = {
        item.get("name"): item
        for item in (source.get("encoding") or {}).get("values", [])
        if item.get("_type") == "Instruction.Encodeset.Field"
    }
    if any(fields.get(field, {}).get("value", {}).get("value") != "'xx'"
           for field in ("tszh", "tszl")):
        return False
    actual = [[symbol.get("rule_id") for symbol in
               ((choice or {}).get("symbols") or [])]
              for choice in rule.get("choices", []) or []]
    if actual != [[name] for name in names]:
        return False
    for name, letter in zip(names, "BHSD"):
        leaf = rules.get(name, {})
        if (leaf.get("condition") != {"_type": "AST.Bool", "value": True}
                or (leaf.get("symbols") or {}).get("symbols") != [
                    {"_type": "Instruction.Symbols.Literal", "value": letter}
                ]):
            return False
    return True


def reviewed_a64_sve_tszhl_shift(
    rule_id: str,
    rule: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> int | None:
    """SVE XAR/SRI/S​​LI immediate from tszh:tszl:imm3."""
    modes = {
        ("const__2", "xar_z_zzi_"): 0,
        ("const__2", "sri_z_zzi_"): 0,
        ("const__9", "sli_z_zzi_"): 1,
    }
    mode = modes.get((rule_id, source.get("name")))
    if (mode is None or rule.get("_type") != "Instruction.Rules.Rule"
            or rule.get("display") != "<const>"
            or (rule.get("symbols") or {}).get("symbols") != [
                {"_type": "Instruction.Symbols.RuleReference",
                 "rule_id": "UInteger"}
            ]
            or (source.get("_meta") or {}).get("encoded_in", {}).get(
                "<const>") != [
                    {"_type": "AST.Identifier", "value": "tszh"},
                    {"_type": "AST.Identifier", "value": "tszl"},
                    {"_type": "AST.Identifier", "value": "imm3"},
                ]
            or any(bindings.get(field) != shape for field, shape in {
                "tszh": (22, 2), "tszl": (19, 2), "imm3": (16, 3)
            }.items())):
        return None
    fields = {
        item.get("name"): item
        for item in (source.get("encoding") or {}).get("values", [])
        if item.get("_type") == "Instruction.Encodeset.Field"
    }
    if (fields.get("tszh", {}).get("value", {}).get("value") != "'xx'"
            or fields.get("tszl", {}).get("value", {}).get("value") != "'xx'"
            or fields.get("imm3", {}).get("value", {}).get("value")
                != "'xxx'"):
        return None
    return mode


def reviewed_a64_sve_ptrue_pattern(
    rule_id: str,
    rule: dict[str, Any],
    rules: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> bool:
    """PTRUE/PTRUES optional named or numeric five-bit pattern."""
    if (rule_id != "optional_pattern__2"
            or source.get("name") not in {"ptrue_p_s_", "ptrues_p_s_"}
            or rule.get("_type") != "Instruction.Rules.Choice"
            or rule.get("display") is not None
            or bindings.get("pattern") != (5, 5)
            or (source.get("_meta") or {}).get("encoded_in", {}).get(
                "<pattern>") != [
                    {"_type": "AST.Identifier", "value": "pattern"}
                ]):
        return False
    fields = {
        item.get("name"): item
        for item in (source.get("encoding") or {}).get("values", [])
        if item.get("_type") == "Instruction.Encodeset.Field"
    }
    if fields.get("pattern", {}).get("value", {}).get("value") != "'xxxxx'":
        return False
    outer = [[symbol.get("rule_id") for symbol in
              ((choice or {}).get("symbols") or [])]
             for choice in rule.get("choices", []) or []]
    if outer != [["default_pattern"], ["COMMA", "pattern"]]:
        return False
    default = rules.get("default_pattern", {})
    if (default.get("_type") != "Instruction.Rules.Rule"
            or default.get("condition") != {
                "_type": "AST.Bool", "value": True}
            or default.get("symbols") is not None):
        return False
    names = ("POW2", "VL1", "VL2", "VL3", "VL4", "VL5", "VL6",
             "VL7", "VL8", "VL16", "VL32", "VL64", "VL128", "VL256")
    expected = [f"pattern_{name}" for name in names]
    expected += ["pattern_uimm5", "pattern_MUL4", "pattern_MUL3",
                 "pattern_ALL"]
    pattern = rules.get("pattern", {})
    actual = [[symbol.get("rule_id") for symbol in
               ((choice or {}).get("symbols") or [])]
              for choice in pattern.get("choices", []) or []]
    if (pattern.get("_type") != "Instruction.Rules.Choice"
            or pattern.get("display") != "<pattern>"
            or actual != [[name] for name in expected]):
        return False
    for name, spelling in zip(expected, (*names, "", "MUL4", "MUL3", "ALL")):
        leaf = rules.get(name, {})
        symbol = ({"_type": "Instruction.Symbols.RuleReference",
                   "rule_id": "UInteger"} if not spelling else
                  {"_type": "Instruction.Symbols.Literal",
                   "value": spelling})
        if (leaf.get("condition") != {"_type": "AST.Bool", "value": True}
                or (leaf.get("symbols") or {}).get("symbols") != [symbol]):
            return False
    return True


def reviewed_a64_sve_dupq(
    rule_id: str,
    rule: dict[str, Any],
    rules: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> int | None:
    """SVE2.1 DUPQ element type and lane from i1:tsz."""
    if (source.get("name") != "dupq_z_zi_"
            or bindings.get("i1") != (20, 1)
            or bindings.get("tsz") != (16, 4)):
        return None
    fields = {
        item.get("name"): item
        for item in (source.get("encoding") or {}).get("values", [])
        if item.get("_type") == "Instruction.Encodeset.Field"
    }
    if (fields.get("i1", {}).get("value", {}).get("value") != "'x'"
            or fields.get("tsz", {}).get("value", {}).get("value")
                != "'xxxx'"):
        return None
    encoded = (source.get("_meta") or {}).get("encoded_in", {})
    if rule_id == "T__35":
        if (rule.get("_type") != "Instruction.Rules.Choice"
                or rule.get("display") != "<T>"
                or encoded.get("<T>") != [
                    {"_type": "AST.Identifier", "value": "tsz"}
                ]):
            return None
        names = ("T_D", "T_S", "T_H", "T_B")
        actual = [[symbol.get("rule_id") for symbol in
                   ((choice or {}).get("symbols") or [])]
                  for choice in rule.get("choices", []) or []]
        if actual != [[name] for name in names]:
            return None
        for name, letter in zip(names, "DSHB"):
            leaf = rules.get(name, {})
            if (leaf.get("condition") != {"_type": "AST.Bool", "value": True}
                    or (leaf.get("symbols") or {}).get("symbols") != [
                        {"_type": "Instruction.Symbols.Literal",
                         "value": letter}
                    ]):
                return None
        return 0
    if (rule_id == "imm__48"
            and rule.get("_type") == "Instruction.Rules.Rule"
            and rule.get("display") == "<imm>"
            and (rule.get("symbols") or {}).get("symbols") == [
                {"_type": "Instruction.Symbols.RuleReference",
                 "rule_id": "UInteger"}
            ]
            and encoded.get("<imm>") == [
                {"_type": "AST.Identifier", "value": "i1"},
                {"_type": "AST.Identifier", "value": "tsz"},
            ]):
        return 1
    return None


def reviewed_a64_sme_psel(
    rule_id: str,
    rule: dict[str, Any],
    rules: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> int | None:
    """SME PSEL element type and lane from i1:tszh:tszl."""
    if (source.get("name") != "psel_p_ppi_"
            or bindings.get("i1") != (23, 1)
            or bindings.get("tszh") != (22, 1)
            or bindings.get("tszl") != (18, 3)):
        return None
    fields = {
        item.get("name"): item
        for item in (source.get("encoding") or {}).get("values", [])
        if item.get("_type") == "Instruction.Encodeset.Field"
    }
    if any(fields.get(field, {}).get("value", {}).get("value") != pattern
           for field, pattern in (("i1", "'x'"), ("tszh", "'x'"),
                                  ("tszl", "'xxx'"))):
        return None
    encoded = (source.get("_meta") or {}).get("encoded_in", {})
    if rule_id == "T__70":
        if (rule.get("_type") != "Instruction.Rules.Choice"
                or rule.get("display") != "<T>"
                or encoded.get("<T>") != [
                    {"_type": "AST.Identifier", "value": "tszh"},
                    {"_type": "AST.Identifier", "value": "tszl"},
                ]):
            return None
        names = ("T_D__55", "T_S__57", "T_H__53", "T_B__36")
        actual = [[symbol.get("rule_id") for symbol in
                   ((choice or {}).get("symbols") or [])]
                  for choice in rule.get("choices", []) or []]
        if actual != [[name] for name in names]:
            return None
        for name, letter in zip(names, "DSHB"):
            leaf = rules.get(name, {})
            if (leaf.get("condition") != {"_type": "AST.Bool", "value": True}
                    or (leaf.get("symbols") or {}).get("symbols") != [
                        {"_type": "Instruction.Symbols.Literal",
                         "value": letter}
                    ]):
                return None
        return 0
    if (rule_id == "imm__87"
            and rule.get("_type") == "Instruction.Rules.Rule"
            and rule.get("display") == "<imm>"
            and (rule.get("symbols") or {}).get("symbols") == [
                {"_type": "Instruction.Symbols.RuleReference",
                 "rule_id": "UInteger"}
            ]
            and encoded.get("<imm>") == [
                {"_type": "AST.Identifier", "value": "i1"},
                {"_type": "AST.Identifier", "value": "tszh"},
                {"_type": "AST.Identifier", "value": "tszl"},
            ]):
        return 1
    if (rule_id == "Wv__2"
            and rule.get("_type") == "Instruction.Rules.Rule"
            and rule.get("display") == "<Wv>"
            and bindings.get("Rv") == (16, 2)
            and fields.get("Rv", {}).get("value", {}).get("value")
                == "'xx'"
            and (rule.get("symbols") or {}).get("symbols") == [
                {"_type": "Instruction.Symbols.Literal", "value": "W"},
                {"_type": "Instruction.Symbols.RuleReference",
                 "rule_id": "UInteger"},
            ]
            and encoded.get("<Wv>") == [
                {"_type": "AST.Identifier", "value": "Rv"}
            ]):
        return 2
    return None


def reviewed_a64_sme_luti6_register(
    rule_id: str,
    rule: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> tuple[str, int] | None:
    """Two pinned SME2p3 LUTI6 four-destination register encodings."""
    name = source.get("name")
    if name not in {"luti6_mz4_ztmz3_4", "luti6_mz4_zmz2_4"}:
        return None
    fields = {
        item.get("name"): item
        for item in (source.get("encoding") or {}).get("values", [])
        if item.get("_type") == "Instruction.Encodeset.Field"
    }
    required = (
        {"D": (4, 1, "'x'"), "Zd": (0, 2, "'xx'"),
         "Zn": (7, 3, "'xxx'")}
        if name == "luti6_mz4_ztmz3_4" else
        {"D": (4, 1, "'x'"), "Zd": (0, 2, "'xx'"),
         "Zn": (5, 5, "'xxxxx'"), "Zm": (16, 5, "'xxxxx'"),
         "i1": (22, 1, "'x'")}
    )
    if any(bindings.get(field) != (start, width)
           or fields.get(field, {}).get("value", {}).get("value") != bits
           for field, (start, width, bits) in required.items()):
        return None
    destinations = {
        "Zd1__4": ("<Zd1>", 0), "Zd2__3": ("<Zd2>", 1),
        "Zd3": ("<Zd3>", 2), "Zd4__2": ("<Zd4>", 3),
    }
    if rule_id in destinations:
        display, offset = destinations[rule_id]
        encoded_fields = ("D", "Zd")
        result = ("A64_SME_LUTI6_STRIDE4_DEST", offset +
                  (4 if name == "luti6_mz4_zmz2_4" else 0))
    elif name == "luti6_mz4_ztmz3_4" and rule_id in {
            "Zn1__9", "Zn3"}:
        display = "<Zn1>" if rule_id == "Zn1__9" else "<Zn3>"
        encoded_fields = ("Zn",)
        result = ("A64_SME_LUTI6_TRIPLE_SOURCE",
                  0 if rule_id == "Zn1__9" else 1)
    elif name == "luti6_mz4_zmz2_4" and rule_id in {
            "Zn1__7", "Zn2__5", "Zm1__5", "Zm2__3"}:
        display, field, offset = {
            "Zn1__7": ("<Zn1>", "Zn", 0),
            "Zn2__5": ("<Zn2>", "Zn", 1),
            "Zm1__5": ("<Zm1>", "Zm", 2),
            "Zm2__3": ("<Zm2>", "Zm", 3),
        }[rule_id]
        encoded_fields = (field,)
        result = ("A64_SME_LUTI6_PAIR_SOURCE", offset)
    else:
        return None
    if (rule.get("_type") != "Instruction.Rules.Rule"
            or rule.get("display") != display
            or (source.get("_meta") or {}).get("encoded_in", {}).get(
                display) != [
                    {"_type": "AST.Identifier", "value": field}
                    for field in encoded_fields
                ]
            or (rule.get("symbols") or {}).get("symbols") != [
                {"_type": "Instruction.Symbols.Literal", "value": "Z"},
                {"_type": "Instruction.Symbols.RuleReference",
                 "rule_id": "UInteger"},
            ]):
        return None
    return result


def reviewed_a64_sme_luti4_zd_group(
    rule_id: str,
    rule: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> int | None:
    """SME four-register LUTI destination registers."""
    if (source.get("name") == "luti4_mz4_ztmz2_4"
            and rule_id in {"Zn1__4", "Zn2__3"}):
        display = "<Zn1>" if rule_id == "Zn1__4" else "<Zn2>"
        fields = {
            item.get("name"): item
            for item in (source.get("encoding") or {}).get("values", [])
            if item.get("_type") == "Instruction.Encodeset.Field"
        }
        if (bindings.get("Zn") == (6, 4)
                and fields.get("Zn", {}).get("value", {}).get("value")
                    == "'xxxx'"
                and (source.get("_meta") or {}).get("encoded_in", {}).get(
                    display) == [
                        {"_type": "AST.Identifier", "value": "Zn"}
                    ]
                and rule.get("_type") == "Instruction.Rules.Rule"
                and rule.get("display") == display
                and (rule.get("symbols") or {}).get("symbols") == [
                    {"_type": "Instruction.Symbols.Literal", "value": "Z"},
                    {"_type": "Instruction.Symbols.RuleReference",
                     "rule_id": "UInteger"},
                ]):
            return 8 if rule_id == "Zn1__4" else 9
        return None
    cases = {"Zd1__2": ("<Zd1>", 0), "Zd4": ("<Zd4>", 3)}
    selected = cases.get(rule_id)
    if (selected is not None
            and source.get("name") == "luti4_mz4_ztz_1"):
        display, offset = selected
    else:
        grouped = {
            "Zd1__4": ("<Zd1>", 0),
            "Zd2__3": ("<Zd2>", 1),
            "Zd3": ("<Zd3>", 2),
            "Zd4__2": ("<Zd4>", 3),
        }
        selected = grouped.get(rule_id)
        if (selected is None or source.get("name") not in {
                "luti2_mz4_ztz_4", "luti4_mz4_ztz_4",
                "luti4_mz4_ztmz2_4"}):
            return None
        display, offset = selected
        if (bindings.get("D") != (4, 1)
                or bindings.get("Zd") != (0, 2)
                or (source.get("_meta") or {}).get("encoded_in", {}).get(
                    display) != [
                        {"_type": "AST.Identifier", "value": "D"},
                        {"_type": "AST.Identifier", "value": "Zd"},
                    ]):
            return None
        fields = {
            item.get("name"): item
            for item in (source.get("encoding") or {}).get("values", [])
            if item.get("_type") == "Instruction.Encodeset.Field"
        }
        if (fields.get("D", {}).get("value", {}).get("value") != "'x'"
                or fields.get("Zd", {}).get("value", {}).get("value")
                    != "'xx'"):
            return None
        if (rule.get("_type") != "Instruction.Rules.Rule"
                or rule.get("display") != display
                or (rule.get("symbols") or {}).get("symbols") != [
                    {"_type": "Instruction.Symbols.Literal", "value": "Z"},
                    {"_type": "Instruction.Symbols.RuleReference",
                     "rule_id": "UInteger"},
                ]):
            return None
        return 4 + offset
    if (source.get("name") != "luti4_mz4_ztz_1"
            or rule.get("_type") != "Instruction.Rules.Rule"
            or rule.get("display") != display
            or bindings.get("Zd") != (2, 3)
            or (source.get("_meta") or {}).get("encoded_in", {}).get(
                display) != [
                    {"_type": "AST.Identifier", "value": "Zd"}
                ]
            or (rule.get("symbols") or {}).get("symbols") != [
                {"_type": "Instruction.Symbols.Literal", "value": "Z"},
                {"_type": "Instruction.Symbols.RuleReference",
                 "rule_id": "UInteger"},
            ]):
        return None
    fields = {
        item.get("name"): item
        for item in (source.get("encoding") or {}).get("values", [])
        if item.get("_type") == "Instruction.Encodeset.Field"
    }
    if fields.get("Zd", {}).get("value", {}).get("value") != "'xxx'":
        return None
    return offset


def reviewed_a64_barrier_option(
    rule_id: str,
    rule: dict[str, Any],
    rules: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> bool:
    """Unconditional A64 DSB/DMB named barrier domain or numeric CRm."""
    forms = {
        "DSB_BO_barriers": ("prfop_choice", "CRm_option__2", "DSB"),
        "DMB_BO_barriers": ("prfop_choice__2", "CRm_option__3", "DMB"),
    }
    selected = forms.get(source.get("name"))
    if selected is None:
        return False
    outer, inner, operation_id = selected
    encoded = (source.get("_meta") or {}).get("encoded_in", {})
    if (rule_id != outer or source.get("operation_id") != operation_id
            or bindings.get("CRm") != (8, 4)
            or any(encoded.get(display) != [
                {"_type": "AST.Identifier", "value": "CRm"}
            ] for display in ("<option>", "<imm>"))
            or rule.get("_type") != "Instruction.Rules.Choice"
            or rule.get("display") is not None):
        return False
    fields = {
        item.get("name"): item
        for item in (source.get("encoding") or {}).get("values", [])
        if item.get("_type") == "Instruction.Encodeset.Field"
    }
    if fields.get("CRm", {}).get("value", {}).get("value") != "'xxxx'":
        return False
    actual_outer = [[symbol.get("rule_id") for symbol in
                     ((choice or {}).get("symbols") or [])]
                    for choice in rule.get("choices", []) or []]
    if actual_outer != [[inner], ["hash", "option__2"]]:
        return False
    numeric = rules.get("option__2", {})
    if (numeric.get("condition") != {"_type": "AST.Bool", "value": True}
            or (numeric.get("symbols") or {}).get("symbols") != [
                {"_type": "Instruction.Symbols.RuleReference",
                 "rule_id": "UInteger"}
            ]):
        return False
    spellings = ("SY", "ST", "LD", "ISH", "ISHST", "ISHLD",
                 "NSH", "NSHST", "NSHLD", "OSH", "OSHST", "OSHLD")
    ids = ("SY_DSB", "ST", "LD", "ISH_DSB", "ISHST", "ISHLD",
           "NSH_DSB", "NSHST", "NSHLD", "OSH_DSB", "OSHST", "OSHLD")
    if operation_id == "DMB":
        ids = spellings
    selected_rule = rules.get(inner, {})
    actual = [[symbol.get("rule_id") for symbol in
               ((choice or {}).get("symbols") or [])]
              for choice in selected_rule.get("choices", []) or []]
    if (selected_rule.get("_type") != "Instruction.Rules.Choice"
            or selected_rule.get("display") != "<option>"
            or actual != [[f"CRm_{name}"] for name in ids]):
        return False
    for name, spelling in zip(ids, spellings):
        leaf = rules.get(f"CRm_{name}", {})
        if (leaf.get("condition") != {"_type": "AST.Bool", "value": True}
                or (leaf.get("symbols") or {}).get("symbols") != [
                    {"_type": "Instruction.Symbols.Literal",
                     "value": spelling}
                ]):
            return False
    return True


def reviewed_a64_rprfm_option(
    rule_id: str,
    rule: dict[str, Any],
    rules: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> bool:
    """RPRFM six variable hint bits, excluding fixed option/Rt bits."""
    if (rule_id != "prfop_choice__4"
            or source.get("name") != "RPRFM_R_ldst_regoff"
            or source.get("operation_id") != "RPRFM_reg"
            or rule.get("_type") != "Instruction.Rules.Choice"
            or rule.get("display") is not None
            or any(bindings.get(field) != shape for field, shape in {
                "option": (13, 3), "S": (12, 1), "Rt": (0, 5)
            }.items())):
        return False
    encoded = (source.get("_meta") or {}).get("encoded_in", {})
    expected = [
        {"_type": "AST.Identifier", "value": field}
        for field in ("option", "S", "Rt")
    ]
    if any(encoded.get(display) != expected
           for display in ("<rprfop>", "<imm6>")):
        return False
    fields = {
        item.get("name"): item
        for item in (source.get("encoding") or {}).get("values", [])
        if item.get("_type") == "Instruction.Encodeset.Field"
    }
    if any(fields.get(field, {}).get("value", {}).get("value") != value
           for field, value in (("option", "'x1x'"), ("S", "'x'"),
                                ("Rt", "'11xxx'"))):
        return False
    outer = [[symbol.get("rule_id") for symbol in
              ((choice or {}).get("symbols") or [])]
             for choice in rule.get("choices", []) or []]
    if outer != [["RtSoption_rprfop"],
                 ["hash", "RtSoption_imm6"]]:
        return False
    inner = rules.get("RtSoption_rprfop", {})
    ids = ("PLDKEEP", "PLDSTRM", "PSTKEEP", "PSTSTRM")
    inner_choices = [[symbol.get("rule_id") for symbol in
                      ((choice or {}).get("symbols") or [])]
                     for choice in inner.get("choices", []) or []]
    if (inner.get("_type") != "Instruction.Rules.Choice"
            or inner_choices != [[f"RtSoption_{name}"] for name in ids]):
        return False
    for name in ids:
        leaf = rules.get(f"RtSoption_{name}", {})
        if (leaf.get("condition") != {"_type": "AST.Bool", "value": True}
                or (leaf.get("symbols") or {}).get("symbols") != [
                    {"_type": "Instruction.Symbols.Literal", "value": name}
                ]):
            return False
    numeric = rules.get("RtSoption_imm6", {})
    return (numeric.get("condition") == {
                "_type": "AST.Bool", "value": True}
            and (numeric.get("symbols") or {}).get("symbols") == [
                {"_type": "Instruction.Symbols.RuleReference",
                 "rule_id": "UInteger"}
            ])


def reviewed_a64_stshh_policy(
    rule_id: str,
    rule: dict[str, Any],
    rules: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> bool:
    """STSHH KEEP/STRM is the low op2 bit in its exact hint form."""
    if (rule_id != "stshh_policy"
            or source.get("name") != "STSHH_HI_hints"
            or source.get("operation_id") != "STSHH"
            or rule.get("_type") != "Instruction.Rules.Choice"
            or rule.get("display") != "<policy>"
            or bindings.get("op2") != (5, 3)
            or (source.get("_meta") or {}).get("encoded_in", {}).get(
                "<policy>") != [
                    {"_type": "AST.Identifier", "value": "op2"}
                ]):
        return False
    fields = {
        item.get("name"): item
        for item in (source.get("encoding") or {}).get("values", [])
        if item.get("_type") == "Instruction.Encodeset.Field"
    }
    if fields.get("op2", {}).get("value", {}).get("value") != "'00x'":
        return False
    names = ("policy_0_KEEP", "policy_1_STRM")
    actual = [[symbol.get("rule_id") for symbol in
               ((choice or {}).get("symbols") or [])]
              for choice in rule.get("choices", []) or []]
    if actual != [[name] for name in names]:
        return False
    for name, spelling in zip(names, ("KEEP", "STRM")):
        leaf = rules.get(name, {})
        if (leaf.get("condition") != {"_type": "AST.Bool", "value": True}
                or (leaf.get("symbols") or {}).get("symbols") != [
                    {"_type": "Instruction.Symbols.Literal",
                     "value": spelling}
                ]):
            return False
    return True


def reviewed_a64_isb_option(
    rule_id: str,
    rule: dict[str, Any],
    rules: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> bool:
    """ISB option 15 omits the default suffix; others print #imm4."""
    if (rule_id != "optional_barrier"
            or source.get("name") != "ISB_BI_barriers"
            or source.get("operation_id") != "ISB"
            or rule.get("_type") != "Instruction.Rules.Choice"
            or rule.get("display") is not None
            or bindings.get("CRm") != (8, 4)):
        return False
    encoded = (source.get("_meta") or {}).get("encoded_in", {})
    if any(encoded.get(display) != [
        {"_type": "AST.Identifier", "value": "CRm"}
    ] for display in ("<imm>", "<option>")):
        return False
    fields = {
        item.get("name"): item
        for item in (source.get("encoding") or {}).get("values", [])
        if item.get("_type") == "Instruction.Encodeset.Field"
    }
    if fields.get("CRm", {}).get("value", {}).get("value") != "'xxxx'":
        return False
    actual = [[symbol.get("rule_id") for symbol in
               ((choice or {}).get("symbols") or [])]
              for choice in rule.get("choices", []) or []]
    if actual != [["CRm_default"], ["SPACE", "CRm_SY__2"],
                  ["SPACE", "hash", "option"]]:
        return False
    default = rules.get("CRm_default", {})
    sy = rules.get("CRm_SY__2", {})
    numeric = rules.get("option", {})
    return (default.get("condition") == {
                "_type": "AST.Bool", "value": True}
            and default.get("symbols") is None
            and sy.get("condition") == {
                "_type": "AST.Bool", "value": True}
            and (sy.get("symbols") or {}).get("symbols") == [
                {"_type": "Instruction.Symbols.Literal", "value": "SY"}
            ]
            and numeric.get("condition") == {
                "_type": "AST.Bool", "value": True}
            and (numeric.get("symbols") or {}).get("symbols") == [
                {"_type": "Instruction.Symbols.RuleReference",
                 "rule_id": "UInteger"}
            ])


def reviewed_neon_modified_immediate(
    rule_id: str,
    rule: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> int | None:
    """Identify reviewed VMOV/VMVN/VORR/VBIC cmode subfamilies.

    The recipe parameter is one of 1..11; the C formatter validates the
    subfamily-specific cmode/op bits before applying AdvSIMDExpandImm's
    integer-byte placement.  Aliases without their own encoding remain opaque.
    Pinned T3/T4/T5 VMOV metadata lists only i/imm3; exact raw cmode/op/imm4
    bindings are required and checked against the A3/A4/A5 counterparts.
    """
    if (rule_id not in {"imm__113", "imm__114"}
            or rule.get("_type") != "Instruction.Rules.Rule"
            or rule.get("display") != "<imm>"
            or (rule.get("symbols") or {}).get("symbols") != [
                {"_type": "Instruction.Symbols.RuleReference",
                 "rule_id": "UInteger"},
            ]
            or (source.get("_meta") or {}).get("encoded_in", {}).get("<imm>")
                not in ([
                    {"_type": "AST.Identifier", "value": name}
                    for name in (("op", "cmode", "i", "imm3", "imm4")
                                 if rule_id == "imm__113" else
                                 ("cmode", "i", "imm3", "imm4"))
                ], [
                    {"_type": "AST.Identifier", "value": name}
                    for name in ("i", "imm3")
                ] if re.fullmatch(r"VMOV_i_T[345]_[DQ]",
                                  str(source.get("name", ""))) else [])):
        return None
    match = re.fullmatch(r"(VMOV|VMVN|VORR|VBIC)_i_([AT])([12345])_[DQ]",
                         str(source.get("name", "")))
    if match is None:
        return None
    mnemonic, isa_letter, variant_text = match.groups()
    variant = int(variant_text)
    families = {
        ("VMVN", 1): (1, "'0xx0'", "'1'"),
        ("VORR", 1): (2, "'0xx1'", "'0'"),
        ("VBIC", 1): (3, "'0xx1'", "'1'"),
        ("VMVN", 2): (4, "'10x0'", "'1'"),
        ("VORR", 2): (5, "'10x1'", "'0'"),
        ("VBIC", 2): (6, "'10x1'", "'1'"),
        ("VMVN", 3): (7, "'110x'", "'1'"),
        ("VMOV", 1): (8, "'0xx0'", "'0'"),
        ("VMOV", 3): (9, "'10x0'", "'0'"),
        ("VMOV", 4): (11, "'11xx'", "'0'"),
        ("VMOV", 5): (10, "'1110'", "'1'"),
    }
    family = families.get((mnemonic, variant))
    if family is None:
        return None
    family_id, cmode_value, op_value = family
    if (rule_id == "imm__113") != (mnemonic == "VMOV"):
        return None
    shape = (("cmode", 8, 4, cmode_value),
             ("i", 24 if isa_letter == "A" else 28, 1, "'x'"),
             ("imm3", 16, 3, "'xxx'"), ("imm4", 0, 4, "'xxxx'"),
             ("op", 5, 1, op_value))
    if any(bindings.get(name) != (start, width)
           for name, start, width, _value in shape):
        return None
    fields = {
        field.get("name"): field
        for field in (source.get("encoding") or {}).get("values", [])
        if field.get("_type") == "Instruction.Encodeset.Field"
    }
    if any(fields.get(name, {}).get("value", {}).get("value") != value
           for name, _start, _width, value in shape):
        return None
    return family_id | (0 if isa_letter == "A" else 0x100)


def reviewed_tmop_control_reg(
    rule_id: str,
    rule: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> bool:
    """Recognize the exact SME TMOP z20-z23/z28-z31 control register."""
    if (rule_id != "Zk__2"
            or rule.get("_type") != "Instruction.Rules.Rule"
            or rule.get("display") != "<Zk>"
            or not any(tag in str(source.get("operation_id", ""))
                       for tag in ("zzzi", "z8z8zi"))
            or bindings.get("K") != (12, 1)
            or bindings.get("Zk") != (10, 2)
            or (source.get("_meta") or {}).get("encoded_in", {}).get("<Zk>")
                != [{"_type": "AST.Identifier", "value": "K"},
                    {"_type": "AST.Identifier", "value": "Zk"}]
            or (rule.get("symbols") or {}).get("symbols") != [
                {"_type": "Instruction.Symbols.Literal", "value": "Z"},
                {"_type": "Instruction.Symbols.RuleReference", "rule_id": "UInteger"},
            ]):
        return False
    fields = {
        field.get("name"): field
        for field in (source.get("encoding") or {}).get("values", [])
        if field.get("_type") == "Instruction.Encodeset.Field"
    }
    return (fields.get("K", {}).get("value", {}).get("value") == "'x'"
            and fields.get("Zk", {}).get("value", {}).get("value") == "'xx'")


def reviewed_tmop_zn_pair(
    rule_id: str,
    rule: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> int | None:
    """Render the exact TMOP 2x1 Zn pair encoded as a four-bit pair index."""
    if rule_id not in {"Zn1__2", "Zn2__2"}:
        return None
    if (rule.get("_type") != "Instruction.Rules.Rule"
            or rule.get("display") != ("<Zn1>" if rule_id == "Zn1__2" else "<Zn2>")
            or not str(source.get("name", "")).endswith("2x1")
            or not any(tag in str(source.get("operation_id", ""))
                       for tag in ("zzzi", "z8z8zi"))
            or bindings.get("Zn") != (6, 4)
            or (source.get("_meta") or {}).get("encoded_in", {}).get(
                "<Zn1>" if rule_id == "Zn1__2" else "<Zn2>")
                != [{"_type": "AST.Identifier", "value": "Zn"}]
            or (rule.get("symbols") or {}).get("symbols") != [
                {"_type": "Instruction.Symbols.Literal", "value": "Z"},
                {"_type": "Instruction.Symbols.RuleReference", "rule_id": "UInteger"},
            ]):
        return None
    fields = {
        field.get("name"): field
        for field in (source.get("encoding") or {}).get("values", [])
        if field.get("_type") == "Instruction.Encodeset.Field"
    }
    if fields.get("Zn", {}).get("value", {}).get("value") != "'xxxx'":
        return None
    return 0 if rule_id == "Zn1__2" else 1


def reviewed_scalar_simd_shift64(
    rule_id: str,
    rule: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> int | None:
    """Recognize A64 scalar 64-bit AdvSIMD shifts with immh:immb encoding."""
    if rule_id not in {"r_128UIntimmhimmb", "UIntimmhimmb64"}:
        return None
    source_name = str(source.get("name", ""))
    if (rule.get("_type") != "Instruction.Rules.Rule"
            or rule.get("display") != "<shift>"
            or not re.fullmatch(
                r"(SSHR|SSRA|SRSHR|SRSRA|USHR|USRA|URSHR|URSRA|SRI|SHL|SLI)"
                r"_asisdshf_R", source_name)
            or bindings.get("immh") != (19, 4)
            or bindings.get("immb") != (16, 3)
            or (source.get("_meta") or {}).get("encoded_in", {}).get("<shift>")
                != [{"_type": "AST.Identifier", "value": "immh"},
                    {"_type": "AST.Identifier", "value": "immb"}]
            or (rule.get("symbols") or {}).get("symbols") != [
                {"_type": "Instruction.Symbols.RuleReference", "rule_id": "UInteger"}
            ]):
        return None
    fields = {
        field.get("name"): field
        for field in (source.get("encoding") or {}).get("values", [])
        if field.get("_type") == "Instruction.Encodeset.Field"
    }
    if (fields.get("immh", {}).get("value", {}).get("value") != "'1xxx'"
            or fields.get("immb", {}).get("value", {}).get("value") != "'xxx'"):
        return None
    return 0 if rule_id == "r_128UIntimmhimmb" else 1


def reviewed_a64_bitfield_alias_immediate(
    rule_id: str,
    rule: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> int | None:
    """Compute alias lsb/width from immr:imms under exact BFM grammar."""
    if rule_id not in {"lsb", "lsb__3", "width", "width__2"}:
        return None
    name = str(source.get("name", ""))
    canonical = {
        "SBFIZ": "SBFM", "SBFX": "SBFM", "BFXIL": "BFM",
        "BFI": "BFM", "BFC": "BFM", "UBFIZ": "UBFM",
        "UBFX": "UBFM",
    }.get(name)
    if canonical is None or source.get("operation_id") != f"{name}_{canonical}":
        return None
    is_64 = rule_id in {"lsb__3", "width__2"}
    insert = name in {"SBFIZ", "BFI", "BFC", "UBFIZ"}
    if (rule_id.startswith("lsb") and not insert) or (
            rule_id.startswith("width") and name not in {
                "SBFIZ", "SBFX", "BFXIL", "BFI", "BFC", "UBFIZ", "UBFX"}):
        return None
    display = "<lsb>" if rule_id.startswith("lsb") else "<width>"
    expected = ["immr"] if display == "<lsb>" else ["imms", "immr"]
    if (rule.get("_type") != "Instruction.Rules.Rule"
            or rule.get("display") != display
            or (rule.get("symbols") or {}).get("symbols") != [
                {"_type": "Instruction.Symbols.RuleReference", "rule_id": "UInteger"}
            ]
            or (source.get("_meta") or {}).get("encoded_in", {}).get(display)
                != [{"_type": "AST.Identifier", "value": field}
                    for field in expected]
            or bindings.get("immr") != (16, 6)
            or bindings.get("imms") != (10, 6)
            or bindings.get("N") != (22, 1)):
        return None
    # 0: insertion lsb, 1: insertion width, 2: extraction width.
    kind = 0 if display == "<lsb>" else (1 if insert else 2)
    return kind | (8 if is_64 else 0)


def reviewed_a32_vdup_gpr_size(
    rule_id: str,
    rule: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> bool:
    """Map the exact A32/T32 VDUP core-register B/E size selector."""
    if (rule_id != "size__2"
            or rule.get("_type") != "Instruction.Rules.Rule"
            or rule.get("display") != "<size>"
            or not re.fullmatch(r"VDUP_r_[AT]1_[DQ]", str(source.get("name", "")))
            or bindings.get("B") != (22, 1)
            or bindings.get("E") != (5, 1)
            or (source.get("_meta") or {}).get("encoded_in", {}).get("<size>")
                != [{"_type": "AST.Identifier", "value": "B"},
                    {"_type": "AST.Identifier", "value": "E"}]
            or (rule.get("symbols") or {}).get("symbols") != [
                {"_type": "Instruction.Symbols.RuleReference", "rule_id": "UInteger"}
            ]):
        return False
    fields = {
        field.get("name"): field
        for field in (source.get("encoding") or {}).get("values", [])
        if field.get("_type") == "Instruction.Encodeset.Field"
    }
    return (fields.get("B", {}).get("value", {}).get("value") == "'x'"
            and fields.get("E", {}).get("value", {}).get("value") == "'x'")


def reviewed_a32_vdup_gpr_dest(
    rule_id: str,
    rule: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> int | None:
    """Render VDUP Dd/Qd from D:Vd, checking Q-register alignment."""
    if rule_id not in {"Dd__3", "Qd__3"}:
        return None
    q = rule_id == "Qd__3"
    if (rule.get("_type") != "Instruction.Rules.Rule"
            or rule.get("display") != ("<Qd>" if q else "<Dd>")
            or not re.fullmatch(r"VDUP_r_[AT]1_[DQ]", str(source.get("name", "")))
            or bindings.get("Q") != (21, 1)
            or bindings.get("D") != (7, 1)
            or bindings.get("Vd") != (16, 4)
            or (source.get("_meta") or {}).get("encoded_in", {}).get(
                "<Qd>" if q else "<Dd>")
                != [{"_type": "AST.Identifier", "value": field}
                    for field in ("Q", "D", "Vd")]
            or (rule.get("symbols") or {}).get("symbols") != [
                {"_type": "Instruction.Symbols.Literal", "value": "Q" if q else "D"},
                {"_type": "Instruction.Symbols.RuleReference", "rule_id": "UInteger"},
            ]):
        return None
    fields = {
        field.get("name"): field
        for field in (source.get("encoding") or {}).get("values", [])
        if field.get("_type") == "Instruction.Encodeset.Field"
    }
    if (fields.get("Q", {}).get("value", {}).get("value")
            != ("'1'" if q else "'0'")
            or fields.get("D", {}).get("value", {}).get("value") != "'x'"
            or fields.get("Vd", {}).get("value", {}).get("value") != "'xxxx'"):
        return None
    return 1 if q else 0


def reviewed_a32_vmov_sm_next(
    rule_id: str,
    rule: dict[str, Any],
    source: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> bool:
    """Render the consecutive second S register of VMOV core/S pair."""
    if (rule_id != "Sm1"
            or rule.get("_type") != "Instruction.Rules.Rule"
            or rule.get("display") != "<Sm1>"
            or not re.fullmatch(r"VMOV_(ss|toss)_[AT]1", str(source.get("name", "")))
            or bindings.get("Vm") != (0, 4)
            or bindings.get("M") != (5, 1)
            or (source.get("_meta") or {}).get("encoded_in", {}).get("<Sm1>")
                != [{"_type": "AST.Identifier", "value": "Vm"},
                    {"_type": "AST.Identifier", "value": "M"}]
            or (rule.get("symbols") or {}).get("symbols") != [
                {"_type": "Instruction.Symbols.Literal", "value": "S"},
                {"_type": "Instruction.Symbols.RuleReference", "rule_id": "UInteger"},
            ]):
        return False
    fields = {
        field.get("name"): field
        for field in (source.get("encoding") or {}).get("values", [])
        if field.get("_type") == "Instruction.Encodeset.Field"
    }
    return (fields.get("Vm", {}).get("value", {}).get("value") == "'xxxx'"
            and fields.get("M", {}).get("value", {}).get("value") == "'x'")


def reviewed_a64_shuh_priority(
    source: dict[str, Any], rules: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> bool:
    """The PH option is exactly op2[0] in the pinned SHUH hint leaf."""
    if (source.get("name") != "SHUH_HI_hints"
            or source.get("operation_id") != "SHUH"
            or bindings.get("op2") != (5, 3)
            or bindings.get("CRm") != (8, 4)
            or (source.get("_meta") or {}).get("encoded_in", {}).get("PH") != [
                {"_type": "AST.Identifier", "value": "op2"}
            ]):
        return False
    expected = [
        {"_type": "Instruction.Symbols.Literal", "value": "SHUH"},
        {"_type": "Instruction.Symbols.RuleReference", "rule_id": "SPACE"},
        {"_type": "Instruction.Symbols.RuleReference",
         "rule_id": "priority_option"},
    ]
    if (source.get("assembly") or {}).get("symbols") != expected:
        return False
    fields = {
        item.get("name"): item.get("value", {}).get("value")
        for item in (source.get("encoding") or {}).get("values", [])
        if item.get("_type") == "Instruction.Encodeset.Field"
    }
    if (fields.get("op2") != "'01x'"
            or fields.get("CRm") != "'0110'"):
        return False
    choice = rules.get("priority_option", {})
    if (choice.get("_type") != "Instruction.Rules.Choice"
            or choice.get("display") != "PH"
            or [[symbol.get("rule_id") for symbol in
                 (branch or {}).get("symbols", [])]
                for branch in choice.get("choices", [])] != [
                    ["priority_00_ph"], ["priority_01_ph"]
                ]):
        return False
    first = rules.get("priority_00_ph", {})
    second = rules.get("priority_01_ph", {})
    return (first.get("condition") == {"_type": "AST.Bool", "value": True}
            and first.get("symbols") is None
            and second.get("condition") == {
                "_type": "AST.Bool", "value": True}
            and (second.get("symbols") or {}).get("symbols") == [
                {"_type": "Instruction.Symbols.Literal", "value": "PH"}
            ])


def reviewed_a64_sme_state_alias(
    source: dict[str, Any], rules: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> int | None:
    """SMSTART/SMSTOP omit or name a state from CRm[2:1]."""
    name = source.get("name")
    if (name not in {"SMSTART", "SMSTOP"}
            or source.get("operation_id") != f"{name}_MSR_imm"
            or any(bindings.get(field) != shape for field, shape in {
                "op1": (16, 3), "CRm": (8, 4), "op2": (5, 3)
            }.items())
            or (source.get("_meta") or {}).get(
                "encoded_in", {}).get("<option>") != [
                    {"_type": "AST.Identifier", "value": field}
                    for field in ("CRm", "op1", "op2")
                ]):
        return None
    suffix = "__2" if name == "SMSTART" else "__3"
    target = f"optional_targets{suffix}"
    if (source.get("assembly") or {}).get("symbols") != [
        {"_type": "Instruction.Symbols.Literal", "value": name},
        {"_type": "Instruction.Symbols.RuleReference", "rule_id": target},
    ]:
        return None
    outer = rules.get(target, {})
    inner = rules.get(f"pstatefield_option{suffix}", {})
    if (outer.get("_type") != "Instruction.Rules.Choice"
            or inner.get("_type") != "Instruction.Rules.Choice"
            or inner.get("display") != "<option>"):
        return None
    expected_outer = [
        [f"CRm_11_default" + ("" if name == "SMSTART" else "__2")],
        ["SPACE", f"pstatefield_option{suffix}"],
    ]
    expected_inner = [
        ["option_01_SM" + ("" if name == "SMSTART" else "__2")],
        ["option_10_ZA" + ("" if name == "SMSTART" else "__2")],
    ]
    def references(rule: dict[str, Any]) -> list[list[str | None]]:
        return [[symbol.get("rule_id") for symbol in
                 (branch or {}).get("symbols", [])]
                for branch in rule.get("choices", [])]
    if references(outer) != expected_outer or references(inner) != expected_inner:
        return None
    default = rules.get(expected_outer[0][0], {})
    if (default.get("condition") != {"_type": "AST.Bool", "value": True}
            or default.get("symbols") is not None):
        return None
    for branch, spelling in zip(expected_inner, ("SM", "ZA")):
        item = rules.get(branch[0], {})
        if (item.get("condition") != {"_type": "AST.Bool", "value": True}
                or (item.get("symbols") or {}).get("symbols") != [
                    {"_type": "Instruction.Symbols.Literal", "value": spelling}
                ]):
            return None
    return 0 if name == "SMSTART" else 1


def reviewed_a64_pstate_msr(
    source: dict[str, Any], rules: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
) -> bool:
    """The pinned immediate-MSR grammar has the exact PSTATE field set.

    Byte-to-field restrictions come from the matching pinned Registers.json
    A64.MSRimmediate entries and are enforced by arm_pstate_msr_decode_word.
    Keep this recipe source-gated so a changed grammar becomes opaque again.
    """
    if (source.get("name") != "MSR_SI_pstate"
            or source.get("operation_id") != "MSR_imm"
            or any(bindings.get(field) != shape for field, shape in {
                "op1": (16, 3), "CRm": (8, 4), "op2": (5, 3),
                "Rt": (0, 5),
            }.items())):
        return False
    expected_identifiers = [
        {"_type": "AST.Identifier", "value": field}
        for field in ("CRm", "op1", "op2")
    ]
    encoded = (source.get("_meta") or {}).get("encoded_in", {})
    if (encoded.get("<imm>") != expected_identifiers
            or encoded.get("<pstatefield>") != expected_identifiers):
        return False
    expected_assembly = [
        {"_type": "Instruction.Symbols.Literal", "value": "MSR"},
        *({"_type": "Instruction.Symbols.RuleReference", "rule_id": rid}
          for rid in ("SPACE", "pstatefield_option", "COMMA", "hash",
                      "msr_imm")),
    ]
    if (source.get("assembly") or {}).get("symbols") != expected_assembly:
        return False
    fields = {
        item.get("name"): item.get("value", {}).get("value")
        for item in (source.get("encoding") or {}).get("values", [])
        if item.get("_type") == "Instruction.Encodeset.Field"
    }
    if any(fields.get(name) != pattern for name, pattern in {
        "op0": "'110'", "op1": "'xxx'", "CRm": "'xxxx'",
        "op2": "'xxx'", "Rt": "'11111'",
    }.items()):
        return False
    choice = rules.get("pstatefield_option", {})
    identifiers = (
        "UAO", "PAN", "SPSel", "ALLINT", "PM", "SSBS", "DIT",
        "SVCRSM", "SVCRZA", "SVCRSMZA", "TCO", "DAIFSet",
        "DAIFClr",
    )
    if (choice.get("_type") != "Instruction.Rules.Choice"
            or choice.get("display") != "<pstatefield>"
            or [[s.get("rule_id") for s in c.get("symbols", [])]
                for c in choice.get("choices", [])] != [
                    [f"pstatefield_{name}"] for name in identifiers
                ]):
        return False
    features = (
        "FEAT_UAO", "FEAT_PAN", None, "FEAT_NMI", "FEAT_EBEP",
        "FEAT_SSBS", "FEAT_DIT", "FEAT_SME", "FEAT_SME",
        "FEAT_SME", "FEAT_MTE", None, None,
    )
    for name, feature in zip(identifiers, features):
        rule = rules.get(f"pstatefield_{name}", {})
        expected_condition = (
            {"_type": "AST.Bool", "value": True}
            if feature is None else {
                "_type": "AST.Function", "arguments": [
                    {"_type": "AST.Identifier", "value": feature}
                ], "name": "IsFeatureImplemented", "parameters": [],
            }
        )
        if (rule.get("condition") != expected_condition
                or (rule.get("symbols") or {}).get("symbols") != [
                    {"_type": "Instruction.Symbols.Literal", "value": name}
                ]):
            return False
    return True


def compile_recipe(
    source: dict[str, Any],
    rules: dict[str, Any],
    bindings: dict[str, tuple[int, int]],
    encoded: dict[str, list[tuple[tuple[int, int, int], ...]]],
    text: TextPool,
    special_registers: list[dict[str, Any]],
    selections: list[dict[str, Any]],
    selection_cases: list[tuple[int, int]],
    selection_text_ids: list[int],
    has_semantic_branch_target: bool,
) -> list[tuple[int, int | tuple[tuple[int, int, int], ...]]]:
    stack: tuple[str, ...] = ()

    def rule_value(
        rule_id: str,
        rule: dict[str, Any],
        inherited: tuple[tuple[int, int, int], ...] | None,
    ) -> tuple[tuple[int, int, int], ...] | None:
        display = rule.get("display")
        if display is None or display not in encoded:
            return inherited
        expressions = encoded[display]
        if len(expressions) == 1:
            return expressions[0]
        reviewed = reviewed_split_field_value(
            rule_id, str(display), source, bindings, expressions
        )
        if reviewed is not None:
            return reviewed
        if (rule_id == "N_Vn_M_Vm__2"
                and display == "<Dm>"
                and source.get("_type") == "Instruction.InstructionAlias"
                and source.get("name") == "VMOV"
                and source.get("operation_id") == "VMOV_VORR_r"
                and bindings.get("M") == (5, 1)
                and bindings.get("Vm") == (0, 4)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<Dm>") == [
                        {"_type": "AST.Identifier", "value": "M"},
                        {"_type": "AST.Identifier", "value": "Vm"},
                    ]):
            return concatenate_encoded_expressions(expressions)
        if (rule_id == "imm__114"
                and display == "<imm>"
                and source.get("_type") == "Instruction.InstructionAlias"
                and source.get("name") == "VAND"
                and source.get("operation_id") == "VAND_VBIC_i"
                and bindings.get("cmode") == (8, 4)
                and bindings.get("imm3") == (16, 3)
                and bindings.get("imm4") == (0, 4)
                and bindings.get("op") == (5, 1)
                and bindings.get("Q") == (6, 1)
                and bindings.get("i") in {(24, 1), (28, 1)}
                and len([
                    symbol for symbol in (source.get("assembly") or {}).get(
                        "symbols", []) or []
                    if symbol.get("_type")
                        == "Instruction.Symbols.Literal"
                    and symbol.get("value") in {"I16", "I32"}
                ]) == 1
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<imm>") == [
                    {"_type": "AST.Identifier", "value": field}
                    for field in ("cmode", "i", "imm3", "imm4")
                ]):
            return concatenate_encoded_expressions(expressions)
        register_rule_base = rule_id.split("__", 1)[0]
        direct_register = (
            register_rule_base in DIRECT_CONCAT_REGISTER_RULE_BASES
            and display in DIRECT_CONCAT_REGISTER_DISPLAYS
        )
        if (
            rule.get("_type") != "Instruction.Rules.Choice"
            and display not in DIRECT_CONCAT_DISPLAYS
            and rule_id not in DIRECT_CONCAT_RULE_IDS
            and not direct_register
            and not rule_id.startswith(("imm4_imm12", "imm12_imm4"))
        ):
            raise OpaqueRecipe(
                f"encoded_concat_transform_missing:{rule_id}:{display}"
            )
        return concatenate_encoded_expressions(expressions)

    def assembly_ops(
        assembly: dict[str, Any] | None,
        inherited: tuple[tuple[int, int, int], ...] | None,
        call_stack: tuple[str, ...],
        top_level: bool = False,
        semantic_label: bool = False,
    ) -> list[tuple[int, int | tuple[tuple[int, int, int], ...]]]:
        result: list[tuple[int, int | tuple[tuple[int, int, int], ...]]] = []
        mnemonic_pending = top_level
        symbols = (assembly or {}).get("symbols", []) or []
        if top_level and reviewed_a64_shuh_priority(source, rules, bindings):
            return [(RECIPE_OPCODE["MNEMONIC"], text.id("SHUH")),
                    (RECIPE_OPCODE["A64_SHUH_PRIORITY"], 0)]
        if top_level and reviewed_a64_pstate_msr(source, rules, bindings):
            return [(RECIPE_OPCODE["MNEMONIC"], text.id("MSR")),
                    (RECIPE_OPCODE["A64_PSTATE_MSR"], 0)]
        if top_level:
            sme_alias = reviewed_a64_sme_state_alias(
                source, rules, bindings)
            if sme_alias is not None:
                return [(RECIPE_OPCODE["MNEMONIC"], text.id(str(source["name"]))),
                        (RECIPE_OPCODE["A64_SME_STATE_ALIAS"], sme_alias)]
        skip_through = -1
        for symbol_index, symbol in enumerate(symbols):
            if symbol_index <= skip_through:
                continue
            if (symbol.get("rule_id") == "OPT_SPACE"
                    and symbol_index + 1 < len(symbols)
                    and str(symbols[symbol_index + 1].get(
                        "rule_id", "")).startswith(
                            "shift_option_imm3_imm2_choice")
                    and bindings.get("stype") == (4, 2)
                    and bindings.get("imm2") == (6, 2)
                    and bindings.get("imm3") == (12, 3)):
                # The optional separator belongs to the optional shift;
                # the custom shift recipe emits punctuation only if needed.
                continue
            if (str(source.get("name", "")).endswith("_ldst_regoff")
                    and bindings.get("option") == (13, 3)
                    and bindings.get("S") == (12, 1)
                    and [item.get("rule_id") for item in
                         symbols[symbol_index:symbol_index + 3]] == [
                            "COMMA", "extend_option", "S_option"
                        ]):
                # These three adjacent grammar symbols are one encoded
                # register-offset extension.  In the legal option=011/S=0
                # spelling, the entire suffix (including comma) disappears.
                result.append((RECIPE_OPCODE["A64_REGOFF_EXTEND_SHIFT"], 0))
                skip_through = symbol_index + 2
                continue
            kind = symbol.get("_type")
            if kind == "Instruction.Symbols.Literal":
                opcode = RECIPE_OPCODE["MNEMONIC"] if mnemonic_pending else RECIPE_OPCODE["TEXT"]
                result.append((opcode, text.id(str(symbol.get("value", "")))))
                mnemonic_pending = False
            elif kind == "Instruction.Symbols.RuleReference":
                result.extend(rule_ops(
                    str(symbol.get("rule_id", "")),
                    inherited,
                    call_stack,
                    semantic_label,
                ))
            else:
                raise OpaqueRecipe("unsupported_symbol")
        return result

    def rule_ops(
        rule_id: str,
        inherited: tuple[tuple[int, int, int], ...] | None,
        call_stack: tuple[str, ...],
        semantic_label: bool = False,
    ) -> list[tuple[int, int | tuple[tuple[int, int, int], ...]]]:
        if rule_id in call_stack:
            raise OpaqueRecipe("recursive_rule")
        rule = rules[rule_id]
        kind = rule.get("_type")
        if reviewed_a32_barrier_option(
                rule_id, rule, rules, source, bindings):
            return [(RECIPE_OPCODE["A32_BARRIER_OPTION"], 0)]
        if reviewed_a64_sve_gpr_width(
                rule_id, rule, rules, source, bindings):
            return [(RECIPE_OPCODE["A64_SVE_GPR_WIDTH"], 0)]
        sve_gpr_number = reviewed_a64_sve_gpr_number(
            rule_id, rule, rules, source, bindings)
        if sve_gpr_number is not None:
            return [(RECIPE_OPCODE["A64_SVE_GPR_NUMBER"], sve_gpr_number)]
        sve_t_size = reviewed_a64_sve_t_size(
            rule_id, rule, rules, source, bindings)
        if sve_t_size is not None:
            return [(RECIPE_OPCODE["A64_SVE_T_SIZE"], sve_t_size)]
        if reviewed_a64_sve_tszhl_type(
                rule_id, rule, rules, source, bindings):
            return [(RECIPE_OPCODE["A64_SVE_TSZHL_TYPE"], 0)]
        sve_tszhl_shift = reviewed_a64_sve_tszhl_shift(
            rule_id, rule, source, bindings)
        if sve_tszhl_shift is not None:
            return [(RECIPE_OPCODE["A64_SVE_TSZHL_SHIFT"],
                     sve_tszhl_shift)]
        if reviewed_a64_sve_ptrue_pattern(
                rule_id, rule, rules, source, bindings):
            return [(RECIPE_OPCODE["A64_SVE_PTRUE_PATTERN"], 0)]
        sve_dupq = reviewed_a64_sve_dupq(
            rule_id, rule, rules, source, bindings)
        if sve_dupq is not None:
            return [(RECIPE_OPCODE[
                "A64_SVE_DUPQ_TYPE" if sve_dupq == 0
                else "A64_SVE_DUPQ_LANE"], 0)]
        sme_psel = reviewed_a64_sme_psel(
            rule_id, rule, rules, source, bindings)
        if sme_psel is not None:
            return [(RECIPE_OPCODE[
                "A64_SME_PSEL_TYPE" if sme_psel == 0
                else "A64_SME_PSEL_LANE" if sme_psel == 1
                else "A64_SME_PSEL_WV"], 0)]
        luti6_register = reviewed_a64_sme_luti6_register(
            rule_id, rule, source, bindings)
        if luti6_register is not None:
            opcode, value = luti6_register
            return [(RECIPE_OPCODE[opcode], value)]
        luti4_zd_group = reviewed_a64_sme_luti4_zd_group(
            rule_id, rule, source, bindings)
        if luti4_zd_group is not None:
            return [(RECIPE_OPCODE["A64_SME_LUTI4_ZD_GROUP"],
                     luti4_zd_group)]
        if reviewed_a64_barrier_option(
                rule_id, rule, rules, source, bindings):
            return [(RECIPE_OPCODE["A64_BARRIER_OPTION"], 0)]
        if reviewed_a64_rprfm_option(
                rule_id, rule, rules, source, bindings):
            return [(RECIPE_OPCODE["A64_RPRFM_OPTION"], 0)]
        if reviewed_a64_stshh_policy(
                rule_id, rule, rules, source, bindings):
            return [(RECIPE_OPCODE["A64_STSHH_POLICY"], 0)]
        if reviewed_a64_isb_option(
                rule_id, rule, rules, source, bindings):
            return [(RECIPE_OPCODE["A64_ISB_OPTION"], 0)]
        mrs_spec = reviewed_a32_mrs_spec_reg(
            rule_id, rule, rules, source, bindings)
        if mrs_spec is not None:
            return [(RECIPE_OPCODE["A32_MRS_SPEC_REG"], mrs_spec)]
        vfp_spec = reviewed_a32_vfp_spec_reg(
            rule_id, rule, rules, source, bindings)
        if vfp_spec is not None:
            return [(RECIPE_OPCODE["A32_VFP_SPEC_REG"], vfp_spec)]
        vshll_sign = reviewed_a32_vshll_sign(
            rule_id, rule, rules, source, bindings)
        if vshll_sign is not None:
            return [(RECIPE_OPCODE["A32_VSHLL_SIGN"], vshll_sign)]
        vshll_imm6 = reviewed_a32_vshll_imm6(
            rule_id, rule, source, bindings)
        if vshll_imm6 is not None:
            return [(RECIPE_OPCODE["A32_VSHLL_IMM6"], vshll_imm6)]
        optional_lsl = reviewed_a64_asimd_optional_lsl(
            rule_id, rule, rules, source, bindings)
        if optional_lsl is not None:
            return [(RECIPE_OPCODE["A64_ASIMD_OPTIONAL_LSL"], optional_lsl)]
        if reviewed_a64_sve_optional_vl(
                rule_id, rule, rules, source, bindings):
            return [(RECIPE_OPCODE["A64_SVE_OPTIONAL_VL"], 0)]
        extend_t = reviewed_a64_sve_extend_t(
            rule_id, rule, rules, source, bindings)
        if extend_t is not None:
            return [(RECIPE_OPCODE["A64_SVE_EXTEND_T"], extend_t)]
        if reviewed_a64_asimd_ins_ts(
                rule_id, rule, rules, source, bindings):
            return [(RECIPE_OPCODE["A64_ASIMD_INS_TS"], 0)]
        if reviewed_a64_asimd_ins_r(
                rule_id, rule, rules, source, bindings):
            return [(RECIPE_OPCODE["A64_ASIMD_INS_R"], 0)]
        ins_lane = reviewed_a64_asimd_ins_lane(
            rule_id, rule, source, bindings)
        if ins_lane is not None:
            return [(RECIPE_OPCODE["A64_ASIMD_INS_LANE"], ins_lane)]
        # These extract/duplicate lane numbers are encoded in imm5 above
        # its lowest set element-size bit. A raw UInteger of imm5 is not an
        # architectural lane index. Reuse the proven INS lane transform only
        # for the exact pinned source forms and operand bindings.
        if (rule_id in {
                "imm5_index__7": "DUP_asisdone_only",
                "imm5_index": "DUP_asimdins_DV_v",
                "imm5_index__2": "SMOV_asimdins_W_w",
                "imm5_index__3": "UMOV_asimdins_W_w",
            }
                and str(source.get("name", "")) in {
                    "DUP_asisdone_only", "DUP_asimdins_DV_v",
                    "SMOV_asimdins_W_w", "UMOV_asimdins_W_w",
                    "SMOV_asimdins_X_x", "MOV",
                }
                and (source.get("name") != "MOV"
                     or source.get("operation_id")
                     == "MOV_DUP_advsimd_elt")
                and (
                    (rule_id == "imm5_index__7"
                        and source.get("name") in {
                            "DUP_asisdone_only", "MOV"})
                    or (rule_id == "imm5_index"
                        and source.get("name") == "DUP_asimdins_DV_v")
                    or (rule_id == "imm5_index__2"
                        and source.get("name") == "SMOV_asimdins_W_w")
                    or (rule_id == "imm5_index__3"
                        and source.get("name") in {
                            "UMOV_asimdins_W_w", "SMOV_asimdins_X_x"
                        })
                )
                and bindings.get("imm5") == (16, 5)
                and (source.get("_meta") or {}).get("encoded_in", {}).get(
                    "<index>") == [
                        {"_type": "AST.Identifier", "value": "imm5"}
                    ]
                and rule.get("display") == "<index>"
                and (rule.get("symbols") or {}).get("symbols") == [
                    {"_type": "Instruction.Symbols.RuleReference",
                     "rule_id": "UInteger"}
                ]):
            return [(RECIPE_OPCODE["A64_ASIMD_INS_LANE"], 0)]
        if reviewed_a64_asimd_ins_rn(
                rule_id, rule, rules, source, bindings):
            return [(RECIPE_OPCODE["A64_ASIMD_INS_RN"], 0)]
        if (rule_id in {"amode_choice", "amode_choice__2"}
                and str(source.get("name", "")) in {
                    "STM_u_A1_AS", "LDM_u_A1_AS", "LDM_e_A1_AS"
                }
                and bindings.get("P") == (24, 1)
                and bindings.get("U") == (23, 1)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<amode>") == [
                        {"_type": "AST.Identifier", "value": "U"},
                        {"_type": "AST.Identifier", "value": "P"},
                    ]):
            return [(RECIPE_OPCODE["A32_BLOCK_ADDRESS_MODE"], 0)]
        if (rule_id == "bang_choice__4"
                and str(source.get("name", "")) in {
                    "LDM_T1", "T1B"
                }
                and bindings.get("Rn") == (8, 3)
                and bindings.get("register_list") == (0, 8)
                and ((source.get("assembly") or {}).get(
                    "symbols") or [{}])[0].get("value") in {
                        "LDM", "LDMFD"
                    }):
            return [(RECIPE_OPCODE["T32_LDM_WRITEBACK"], 0)]
        thumb_shift_name = str(source.get("name", ""))
        thumb_shift_rule = (
            (thumb_shift_name == "PKHBT_T1"
             and rule_id == "lsl_imm3_imm2_choice")
            or (thumb_shift_name == "PKHTB_T1"
                and rule_id == "asr_imm3_imm2_choice")
            or (thumb_shift_name in {"SSAT_T1_LSL", "USAT_T1_LSL"}
                and rule_id == "lsl_imm3_imm2_choice__2")
        )
        if (thumb_shift_rule
                and bindings.get("imm3") == (12, 3)
                and bindings.get("imm2") == (6, 2)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get(
                        "<amount>" if thumb_shift_name in {
                            "SSAT_T1_LSL", "USAT_T1_LSL"
                        } else "<imm>") == [
                        {"_type": "AST.Identifier", "value": "imm3"},
                        {"_type": "AST.Identifier", "value": "imm2"},
                    ]):
            return [(RECIPE_OPCODE["T32_OPTIONAL_SHIFT_IMM5"],
                     1 if thumb_shift_name == "PKHTB_T1" else 0)]
        vmov_element_name = str(source.get("name", ""))
        vmov_insert = vmov_element_name in {
            "VMOV_rs_A1", "VMOV_rs_T1"
        }
        vmov_extract = vmov_element_name in {
            "VMOV_sr_A1", "VMOV_sr_T1"
        }
        if (((vmov_insert and rule_id == "dot_size_choice")
                or (vmov_extract and rule_id == "dot_dt_choice"))
                and bindings.get("opc1") == (21, 2)
                and bindings.get("opc2") == (5, 2)
                and (not vmov_extract
                     or bindings.get("U") == (23, 1))
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get(
                        "<size>" if vmov_insert else "<dt>") == [
                        {"_type": "AST.Identifier", "value": field}
                        for field in (("opc1", "opc2") if vmov_insert
                                      else ("U", "opc1", "opc2"))
                    ]):
            return [(RECIPE_OPCODE["A32_VMOV_ELEMENT_SUFFIX"],
                     0 if vmov_insert else 1)]
        if (((vmov_insert and rule_id == "Ddx")
                or (vmov_extract and rule_id == "Dnx"))
                and bindings.get("opc1") == (21, 2)
                and bindings.get("opc2") == (5, 2)
                and bindings.get("D" if vmov_insert else "N") == (7, 1)
                and bindings.get("Vd" if vmov_insert else "Vn") == (16, 4)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get(
                        "<Dd[x]>" if vmov_insert else "<Dn[x]>") == [
                        {"_type": "AST.Identifier",
                         "value": "D" if vmov_insert else "N"},
                        {"_type": "AST.Identifier",
                         "value": "Vd" if vmov_insert else "Vn"},
                    ]):
            return [(RECIPE_OPCODE["A32_VMOV_ELEMENT_REG"], 0)]
        if (rule_id == "opt_xyz"
                and source.get("name") == "IT_T1"
                and bindings.get("firstcond") == (4, 4)
                and bindings.get("mask") == (0, 4)
                and rule.get("_type") == "Instruction.Rules.Choice"
                and [((choice or {}).get("symbols") or [{}])[0].get(
                    "rule_id") for choice in rule.get("choices", [])]
                    == ["no_xyz", "x"]):
            return [(RECIPE_OPCODE["T32_IT_CONDITION_SUFFIX"], 0)]
        if (rule_id == "cond__5"
                and source.get("name") == "IT_T1"
                and bindings.get("firstcond") == (4, 4)
                and rule.get("_type") == "Instruction.Rules.Choice"
                and rule.get("display") == "<cond>"
                and len(rule.get("choices", [])) == 16):
            return [(RECIPE_OPCODE["T32_IT_CONDITION"], 0)]
        if (rule_id in {"registers__8", "registers__9"}
                and source.get("name") == (
                    "LDM_u_A1_AS" if rule_id == "registers__8"
                    else "LDM_e_A1_AS")
                and rule.get("_type") == "Instruction.Rules.Rule"
                and rule.get("display") == (
                    "<registers_without_pc>"
                    if rule_id == "registers__8"
                    else "<registers_with_pc>")
                and (rule.get("symbols") or {}).get("symbols") == [
                    {"_type": "Instruction.Symbols.RuleReference",
                     "rule_id": "multi_register_list"}
                ]
                and bindings.get("register_list") == (0, 15)
                and any(
                    field.get("_type") == "Instruction.Encodeset.Bits"
                    and (field.get("range") or {}).get("start") == 15
                    and (field.get("range") or {}).get("width") == 1
                    and (field.get("value") or {}).get("value") == (
                        "'0'" if rule_id == "registers__8" else "'1'")
                    for field in (source.get("encoding") or {}).get(
                        "values", []))
                and "<registers_without_pc>" not in
                    (source.get("_meta") or {}).get("encoded_in", {})
                and "<registers_with_pc>" not in
                    (source.get("_meta") or {}).get("encoded_in", {})):
            return [(RECIPE_OPCODE["A32_LDM_USER_REG_LIST"],
                     0 if rule_id == "registers__8" else 1)]
        unpred_name = str(source.get("name", ""))
        if (rule_id in {"T__16", "const__2", "const__9"}
                and unpred_name in {
                    "asr_z_zi_", "lsl_z_zi_", "lsr_z_zi_"
                }
                and (rule_id == "T__16"
                     or (unpred_name == "lsl_z_zi_")
                        == (rule_id == "const__9"))
                and bindings.get("tszh") == (22, 2)
                and bindings.get("tszl") == (19, 2)
                and bindings.get("imm3") == (16, 3)
                and all((source.get("_meta") or {}).get(
                    "encoded_in", {}).get(token) == [
                        {"_type": "AST.Identifier", "value": field}
                        for field in fields
                    ] for token, fields in (
                        ("<T>", ("tszh", "tszl")),
                        ("<const>", ("tszh", "tszl", "imm3")),
                    ))):
            return [(RECIPE_OPCODE["A64_SVE_UNPRED_SHIFT_TSZ"],
                     0 if rule_id == "T__16" else
                     2 if rule_id == "const__9" else 1)]
        scalar_shift_name = str(source.get("name", ""))
        if (rule_id in {"V_option__5", "immh_shift"}
                and scalar_shift_name in {
                    "SQSHL_asisdshf_R", "SQSHLU_asisdshf_R",
                    "UQSHL_asisdshf_R"
                }
                and bindings.get("immh") == (19, 4)
                and bindings.get("immb") == (16, 3)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get(
                        "<V>" if rule_id == "V_option__5"
                        else "<shift>") == [
                        {"_type": "AST.Identifier", "value": "immh"}
                    ] + ([] if rule_id == "V_option__5" else [
                        {"_type": "AST.Identifier", "value": "immb"}
                    ])):
            return [(RECIPE_OPCODE[
                "A64_SIMD_SCALAR_SHIFT_SIZE"
                if rule_id == "V_option__5" else
                "A64_SIMD_SCALAR_SHIFT_IMMEDIATE"], 0)]
        if (rule_id == "T_option__19"
                and str(source.get("name", "")) in {
                    "FAMAX_asimdsame_only", "FAMIN_asimdsame_only",
                    "FSCALE_asimdsame_only"
                }
                and bindings.get("size") == (22, 2)
                and bindings.get("Q") == (30, 1)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<T>") == [
                        {"_type": "AST.Identifier", "value": "size"},
                        {"_type": "AST.Identifier", "value": "Q"},
                    ]):
            return [(RECIPE_OPCODE["A64_SIMD_FAMAX_ARRANGEMENT"], 0)]
        if (rule_id == "T_BH"
                and str(source.get("name", "")) in {
                    "luti2_mz2_ztz_8", "luti4_mz2_ztz_8",
                    "luti2_mz4_ztz_4"
                }
                and bindings.get("size") == (12, 2)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<T>") == [
                        {"_type": "AST.Identifier", "value": "size"}
                    ]):
            return [(RECIPE_OPCODE["A64_SME_LUTI_STRIDE8_SIZE"], 0)]
        if (kind == "Instruction.Rules.Rule"
                and rule_id in {"Zd1__3", "Zd2__2"}
                and rule.get("display") == (
                    "<Zd1>" if rule_id == "Zd1__3" else "<Zd2>")
                and str(source.get("name", "")) in {
                    "luti2_mz2_ztz_8", "luti4_mz2_ztz_8"
                }
                and (rule.get("symbols") or {}).get("symbols") == [
                    {"_type": "Instruction.Symbols.Literal", "value": "Z"},
                    {"_type": "Instruction.Symbols.RuleReference",
                     "rule_id": "UInteger"},
                ]
                and bindings.get("D") == (4, 1)
                and bindings.get("Zd") == (0, 3)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get(rule.get("display")) == [
                    {"_type": "AST.Identifier", "value": "D"},
                    {"_type": "AST.Identifier", "value": "Zd"},
                ]):
            fields = {field.get("name"): field
                      for field in (source.get("encoding") or {}).get(
                          "values", [])
                      if field.get("_type") == "Instruction.Encodeset.Field"}
            if (fields.get("D", {}).get("value", {}).get("value") != "'x'"
                    or fields.get("Zd", {}).get("value", {}).get("value")
                        != "'xxx'"
                    or not any(
                        field.get("_type") == "Instruction.Encodeset.Bits"
                        and field.get("range") == {
                            "_type": "Range", "start": 3, "width": 1}
                        and field.get("value", {}).get("value") == "'0'"
                        for field in (source.get("encoding") or {}).get(
                            "values", []))):
                raise OpaqueRecipe("luti_stride8_encoding_mismatch")
            # D chooses the z0/z16 bank, Zd selects 0..7 within it, and the
            # second SME2.1 LUTI destination is eight registers after base.
            # Raw D:Zd concatenation would incorrectly render z8 for z16.
            return [(RECIPE_OPCODE[
                "A64_SME_LUTI_STRIDE8_FIRST" if rule_id == "Zd1__3"
                else "A64_SME_LUTI_STRIDE8_SECOND"], 0)]
        if (rule_id == "dt_option__42"
                and str(source.get("name", "")) in {
                    "VMOV_i_A4_D", "VMOV_i_A4_Q",
                    "VMOV_i_T4_D", "VMOV_i_T4_Q"
                }
                and bindings.get("cmode") == (8, 4)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<dt>") == [
                        {"_type": "AST.Identifier", "value": "cmode"}
                    ]):
            return [(RECIPE_OPCODE["A32_NEON_VMOV_MODIFIED_TYPE"], 0)]
        if (((rule_id == "dt_option__38"
                and str(source.get("name", "")) in {
                    "VQRSHRN", "VQSHRN"
                }) or (rule_id == "dt_option__37"
                and str(source.get("name", "")) in {
                    "VQMOVN_A1", "VQMOVN_T1"
                }))
                and bindings.get("op") == (6, 2)
                and bindings.get("size") == (18, 2)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<dt>") == [
                        {"_type": "AST.Identifier", "value": "op"},
                        {"_type": "AST.Identifier", "value": "size"},
                    ]):
            return [(RECIPE_OPCODE["A32_NEON_SAT_NARROW_TYPE"], 0)]
        sve_dup_name = str(source.get("name", ""))
        if (rule_id in {"T__33", "V__8", "imm__47"}
                and sve_dup_name in {
                    "dup_z_zi_", "mov_z_v_", "mov_z_zi_"
                }
                and bindings.get("tsz") == (16, 5)
                and (rule_id != "imm__47"
                     or bindings.get("imm2") == (22, 2))
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get(
                        "<imm>" if rule_id == "imm__47"
                        else "<V>" if rule_id == "V__8"
                        else "<T>") == ([
                        {"_type": "AST.Identifier", "value": "imm2"},
                        {"_type": "AST.Identifier", "value": "tsz"}
                    ] if rule_id == "imm__47" else [
                        {"_type": "AST.Identifier", "value": "tsz"}
                    ])):
            return [(RECIPE_OPCODE[
                "A64_SVE_DUP_ELEMENT_LANE" if rule_id == "imm__47"
                else "A64_SVE_DUP_ELEMENT_TSZ"],
                1 if rule_id == "V__8" else 0)]
        sve_narrow_name = str(source.get("name", ""))
        if (rule_id in {"T__90", "T__91", "Tb__16", "Tb__17"}
                and sve_narrow_name in {
                    "sqxtnb_z_zz_", "sqxtunb_z_zz_", "uqxtnb_z_zz_",
                    "sqxtnt_z_zz_", "sqxtunt_z_zz_", "uqxtnt_z_zz_"
                }
                and ((sve_narrow_name.endswith("b_z_zz_")
                      and rule_id in {"T__90", "Tb__16"})
                     or (sve_narrow_name.endswith("t_z_zz_")
                         and rule_id in {"T__91", "Tb__17"}))
                and bindings.get("tszh") == (22, 1)
                and bindings.get("tszl") == (19, 2)
                and all((source.get("_meta") or {}).get(
                    "encoded_in", {}).get(token) == [
                        {"_type": "AST.Identifier", "value": "tszh"},
                        {"_type": "AST.Identifier", "value": "tszl"},
                    ] for token in ("<T>", "<Tb>"))):
            return [(RECIPE_OPCODE["A64_SVE_SAT_NARROW_TSZ"],
                     0 if rule_id in {"T__90", "T__91"} else 1)]
        sve_shift_name = str(source.get("name", ""))
        sve_sra = sve_shift_name in {
            "ssra_z_zi_", "srsra_z_zi_", "usra_z_zi_", "ursra_z_zi_"
        }
        sve_shll = sve_shift_name in {
            "sshllb_z_zi_", "sshllt_z_zi_",
            "ushllb_z_zi_", "ushllt_z_zi_"
        }
        if ((sve_sra and rule_id in {"T__92", "const__2"})
                or (sve_shll and rule_id in {
                    "T__93", "Tb__18", "const__9"})):
            shift_meta = (source.get("_meta") or {}).get("encoded_in", {})
            expected_tsz = [
                {"_type": "AST.Identifier", "value": "tszh"},
                {"_type": "AST.Identifier", "value": "tszl"},
            ]
            if (bindings.get("tszh") == (22, 2 if sve_sra else 1)
                    and bindings.get("tszl") == (19, 2)
                    and bindings.get("imm3") == (16, 3)
                    and shift_meta.get("<T>") == expected_tsz
                    and shift_meta.get("<const>") == expected_tsz + [
                        {"_type": "AST.Identifier", "value": "imm3"}
                    ]
                    and (not sve_shll
                         or shift_meta.get("<Tb>") == expected_tsz)):
                if sve_sra:
                    return [(RECIPE_OPCODE["A64_SVE_SRA_TSZ"],
                             0 if rule_id == "T__92" else 1)]
                return [(RECIPE_OPCODE["A64_SVE_SHLL_TSZ"],
                         0 if rule_id == "T__93" else
                         1 if rule_id == "Tb__18" else 2)]
        luti_name = str(source.get("name", ""))
        luti_multi2 = luti_name in {
            "luti2_mz2_ztz_1", "luti4_mz2_ztz_1"
        }
        luti_multi4 = luti_name == "luti2_mz4_ztz_1"
        luti_single = luti_name in {
            "luti2_z_ztz_", "luti4_z_ztz_"
        }
        if (rule_id == "T__17"
                and (luti_multi2 or luti_multi4 or luti_single)
                and bindings.get("size") == (12, 2)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<T>") == [
                        {"_type": "AST.Identifier", "value": "size"}
                    ]):
            return [(RECIPE_OPCODE["A64_SME_LUTI_SIZE"], 0)]
        if (((luti_multi2 and rule_id in {"Zd1", "Zd2"})
                or (luti_multi4 and rule_id in {"Zd1__2", "Zd4"}))
                and bindings.get("Zd") == (
                    (1, 4) if luti_multi2 else (2, 3))
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get(
                        "<Zd1>" if rule_id in {"Zd1", "Zd1__2"}
                        else "<" + rule_id + ">") == [
                            {"_type": "AST.Identifier", "value": "Zd"}
                        ]):
            return [(RECIPE_OPCODE["A64_SME_LUTI_GROUP_REG"],
                     0 if luti_multi2 and rule_id == "Zd1"
                     else 1 if luti_multi2
                     else 2 if rule_id == "Zd1__2" else 3)]
        if (rule_id in {"Zn1__6", "Zn4__3"}
                and str(source.get("name", "")) in {
                    "sqrshr_z_mz4_", "sqrshru_z_mz4_",
                    "sqrshrn_z_mz4_", "sqrshrun_z_mz4_",
                    "uqrshr_z_mz4_", "uqrshrn_z_mz4_"
                }
                and bindings.get("Zn") == (7, 3)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get(
                        "<Zn1>" if rule_id == "Zn1__6"
                        else "<Zn4>") == [
                            {"_type": "AST.Identifier", "value": "Zn"}
                        ]):
            return [(RECIPE_OPCODE["A64_SME_QRSHR_GROUP_REG"],
                     0 if rule_id == "Zn1__6" else 1)]
        if (rule_id in {"T__107", "Tb__22", "const__13",
                        "Zn1__4", "Zn2__3"}
                and str(source.get("name", "")) in {
                    "sqshrn_z_mz2_", "sqshrun_z_mz2_", "uqshrn_z_mz2_"
                }
                and bindings.get("tsize") == (19, 2)
                and bindings.get("imm3") == (16, 3)
                and bindings.get("Zn") == (6, 4)
                and bindings.get("Zd") == (0, 5)
                and all((source.get("_meta") or {}).get(
                    "encoded_in", {}).get(token) == [
                        {"_type": "AST.Identifier", "value": field}
                        for field in fields
                    ] for token, fields in (
                        ("<T>", ("tsize",)),
                        ("<Tb>", ("tsize",)),
                        ("<const>", ("tsize", "imm3")),
                        ("<Zn1>", ("Zn",)),
                        ("<Zn2>", ("Zn",)),
                    ))):
            # The two-width narrow forms encode 1..8 for B<-H in
            # tsize=01, and 1..16 for H<-S in tsize=10/11. The four-bit
            # Zn field names an even-numbered pair, not an individual Z.
            if rule_id in {"Zn1__4", "Zn2__3"}:
                return [(RECIPE_OPCODE["A64_SVE2P3_QSHRN_PAIR_REG"],
                         0 if rule_id == "Zn1__4" else 1)]
            return [(RECIPE_OPCODE["A64_SVE2P3_QSHRN_TYPE_IMM"],
                     0 if rule_id == "T__107" else
                     1 if rule_id == "Tb__22" else 2)]
        if (rule_id in {"T__89", "Tb__15", "const__11"}
                and str(source.get("name", "")) in {
                    "sqrshr_z_mz4_", "sqrshru_z_mz4_",
                    "sqrshrn_z_mz4_", "sqrshrun_z_mz4_",
                    "uqrshr_z_mz4_", "uqrshrn_z_mz4_"
                }
                and bindings.get("tsize") == (22, 2)
                and bindings.get("imm5") == (16, 5)
                and all((source.get("_meta") or {}).get(
                    "encoded_in", {}).get(token) == [
                        {"_type": "AST.Identifier", "value": field}
                        for field in fields
                    ] for token, fields in (
                        ("<T>", ("tsize",)),
                        ("<Tb>", ("tsize",)),
                        ("<const>", ("tsize", "imm5")),
                    ))):
            # SME2 QRSHR packs a quarter-width result. The immediate is
            # 8*esize - UInt(tsize:imm5), with esize=8/16 for B/H output.
            return [(RECIPE_OPCODE["A64_SME_QRSHR_SIZE_IMM"],
                     0 if rule_id == "T__89" else
                     1 if rule_id == "Tb__15" else 2)]
        if (rule_id in {"T__12", "T__34", "const"}
                and str(source.get("name", "")) in {
                    "orr_z_zi_", "eor_z_zi_", "and_z_zi_",
                    "orn_z_zi_", "eon_z_zi_", "bic_z_zi_",
                    "dupm_z_i_", "mov_z_m_",
                }
                and (source.get("name") != "mov_z_m_"
                     or source.get("operation_id") == "mov_dupm_z_i")
                and (rule_id != "T__34"
                     or source.get("name") in {
                         "dupm_z_i_", "mov_z_m_"})
                and (rule_id != "T__12"
                     or source.get("name") not in {
                         "dupm_z_i_", "mov_z_m_"})
                and bindings.get("imm13") == (5, 13)
                and all((source.get("_meta") or {}).get(
                    "encoded_in", {}).get(token) == [
                        {"_type": "AST.Identifier", "value": "imm13"}
                    ] for token in ("<T>", "<const>"))):
            # This instruction field packs N:immr:imms, with imms in its
            # low six bits; the shared decoder expects N:imms:immr. The
            # formatter swaps those fields and extracts
            # both the element width and replicated mask from that field.
            return [(RECIPE_OPCODE["A64_SVE_LOGICAL_IMM"],
                     0 if rule_id in {"T__12", "T__34"} else
                     2 if source.get("name") in {
                         "orn_z_zi_", "eon_z_zi_", "bic_z_zi_"
                     } else 1)]
        sve_pred_shift_name = str(source.get("name", ""))
        sve_pred_shift_right = {
            "asr", "asrd", "srshr", "lsr", "urshr"
        }
        sve_pred_shift_left = {"lsl", "sqshl", "sqshlu", "uqshl"}
        sve_pred_shift_family = sve_pred_shift_name.split("_", 1)[0]
        if (rule_id in {"T__14", "const__2", "const__9"}
                and sve_pred_shift_name.endswith("_z_p_zi_")
                and sve_pred_shift_family in
                    sve_pred_shift_right | sve_pred_shift_left
                and bindings.get("tszh") == (22, 2)
                and bindings.get("tszl") == (8, 2)
                and bindings.get("imm3") == (5, 3)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<T>") == [
                        {"_type": "AST.Identifier", "value": "tszh"},
                        {"_type": "AST.Identifier", "value": "tszl"},
                    ]
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<const>") == [
                        {"_type": "AST.Identifier", "value": "tszh"},
                        {"_type": "AST.Identifier", "value": "tszl"},
                        {"_type": "AST.Identifier", "value": "imm3"},
                    ]):
            if rule_id == "T__14":
                return [(RECIPE_OPCODE["A64_SVE_SHIFT_TSZ"], 0)]
            if ((rule_id == "const__2"
                    and sve_pred_shift_family in sve_pred_shift_right)
                    or (rule_id == "const__9"
                        and sve_pred_shift_family in sve_pred_shift_left)):
                return [(RECIPE_OPCODE["A64_SVE_SHIFT_TSZ"],
                         1 if rule_id == "const__2" else 2)]
        narrow_shift_rule_ids = {
            symbol.get("rule_id") for symbol in
            (source.get("assembly") or {}).get("symbols", []) or []
        }
        if (rule_id in {"T__44", "Tb__5", "V__5", "T__45"}
                and str(source.get("name", "")) in {
                    "faddqv_z_p_z_", "fmaxnmqv_z_p_z_",
                    "fminnmqv_z_p_z_", "fmaxqv_z_p_z_",
                    "fminqv_z_p_z_", "faddv_v_p_z_",
                    "fmaxnmv_v_p_z_", "fminnmv_v_p_z_",
                    "fmaxv_v_p_z_", "fminv_v_p_z_"
                }
                and bindings.get("size") == (22, 2)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get(
                        "<T>" if rule_id in {"T__44", "T__45"}
                        else "<Tb>" if rule_id == "Tb__5"
                        else "<V>") == [
                        {"_type": "AST.Identifier", "value": "size"}
                    ]):
            return [(RECIPE_OPCODE["A64_SVE_FAST_REDUCE_SIZE"],
                     0 if rule_id == "T__44" else 1)]
        if (rule_id in {"T__75", "T__76", "Tb__7", "Tb__8",
                        "const__2"}
                and ("T__75" in narrow_shift_rule_ids
                     or "T__76" in narrow_shift_rule_ids)
                and str(source.get("name", "")).endswith("_z_zi_")
                and bindings.get("tszh") == (22, 1)
                and bindings.get("tszl") == (19, 2)
                and bindings.get("imm3") == (16, 3)
                and all((source.get("_meta") or {}).get(
                    "encoded_in", {}).get(token) == [
                        {"_type": "AST.Identifier", "value": field}
                        for field in fields
                    ] for token, fields in (
                        ("<T>", ("tszh", "tszl")),
                        ("<Tb>", ("tszh", "tszl")),
                        ("<const>", ("tszh", "tszl", "imm3")),
                    ))):
            # Source width is 16/32/64 according to the leading set bit
            # of tszh:tszl. Destination width is exactly half the source.
            return [(RECIPE_OPCODE["A64_SVE_NARROW_SHIFT_TSZ"],
                     0 if rule_id in {"T__75", "T__76"}
                     else 1 if rule_id in {"Tb__7", "Tb__8"} else 2)]
        if (rule_id == "OPT_SPACE"
                and source.get("name") in {
                    "CPSID_A1_ASM", "CPSIE_A1_ASM"
                } and [symbol.get("rule_id")
                       for symbol in (source.get("assembly") or {}).get(
                           "symbols", []) or []][-5:] == [
                    "A_I_F", "OPT_SPACE", "COMMA", "hash", "mode__2"
                ]):
            # The source permits whitespace before the comma; choose the
            # canonical no-space spelling for generated disassembly.
            return []
        if (rule_id == "A_I_F"
                and kind == "Instruction.Rules.Rule"
                and rule.get("display") == "<iflags>"
                and source.get("name") in A32_CPS_IFLAGS_FORMS
                and (source.get("_meta") or {}).get("encoded_in", {}).get(
                    "<iflags>") == [
                        {"_type": "AST.Identifier", "value": "A"},
                        {"_type": "AST.Identifier", "value": "I"},
                        {"_type": "AST.Identifier", "value": "F"},
                    ]):
            symbols = (rule.get("symbols") or {}).get("symbols", []) or []
            name = str(source["name"])
            flag_shift = 6 if "_A1_" in name else \
                0 if "_T1_" in name else 5
            if (len(symbols) == 1
                    and symbols[0].get("rule_id") == "UInteger"
                    and bindings.get("A") == (flag_shift + 2, 1)
                    and bindings.get("I") == (flag_shift + 1, 1)
                    and bindings.get("F") == (flag_shift, 1)):
                return [(RECIPE_OPCODE["A32_CPS_IFLAGS"], flag_shift)]
        narrow_vector = source.get("name") in A64_ASIMD_NARROW_VECTOR_FORMS
        narrow_scalar = source.get("name") in A64_ASIMD_NARROW_SCALAR_FORMS
        widen_vector = source.get("name") in A64_ASIMD_WIDEN_SHIFT_FORMS
        narrow_encoded = (source.get("_meta") or {}).get("encoded_in", {})
        narrow_fields = (
            (narrow_vector or narrow_scalar or widen_vector)
            and bindings.get("immh") == (19, 4)
            and bindings.get("immb") == (16, 3)
            and (narrow_scalar or bindings.get("Q") == (30, 1))
        )
        if (narrow_fields and widen_vector
                and rule_id in {"immh_shift__8", "immh_shift__new"}
                and kind == "Instruction.Rules.Rule"
                and rule.get("display") == "<shift>"
                and narrow_encoded.get("<shift>") == [
                    {"_type": "AST.Identifier", "value": "immh"},
                    {"_type": "AST.Identifier", "value": "immb"},
                ]):
            symbols = (rule.get("symbols") or {}).get("symbols", []) or []
            if (len(symbols) == 1
                    and symbols[0].get("rule_id") == "UInteger"):
                return [(RECIPE_OPCODE["A64_ASIMD_SHIFT_IMMEDIATE"], 0)]
        if (source.get("name") in (
                A64_FIXED_FCVT_SCALAR_FORMS | A64_FIXED_FCVT_VECTOR_FORMS)
                and rule_id == (
                    "immh_shift__3" if source.get("name")
                    in A64_FIXED_FCVT_SCALAR_FORMS else "immh_shift__9")
                and kind == "Instruction.Rules.Rule"
                and rule.get("display") == "<fbits>"
                and bindings.get("immh") == (19, 4)
                and bindings.get("immb") == (16, 3)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<fbits>") == [
                    {"_type": "AST.Identifier", "value": "immh"},
                    {"_type": "AST.Identifier", "value": "immb"},
                ]
                and (rule.get("symbols") or {}).get("symbols") == [
                    {"_type": "Instruction.Symbols.RuleReference",
                     "rule_id": "UInteger"}
                ]):
            return [(RECIPE_OPCODE["A64_ASIMD_SHIFT_IMMEDIATE"], 1)]
        if (source.get("name") == "PRFM_P_ldst_pos"
                and rule_id == "pimm__8"
                and kind == "Instruction.Rules.Rule"
                and rule.get("display") == "<pimm>"
                and bindings.get("imm12") == (10, 12)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<pimm>") == [
                    {"_type": "AST.Identifier", "value": "imm12"}
                ]
                and (rule.get("symbols") or {}).get("symbols") == [
                    {"_type": "Instruction.Symbols.RuleReference",
                     "rule_id": "UInteger"}
                ]):
            return [(RECIPE_OPCODE["A64_PRFM_PIMM12"], 0)]
        if (source.get("name") in {
                    "MSRR_SR_systemmovepr", "MRRS_RS_systemmovepr"
                }
                and rule_id == (
                    "XtPlus1" if source.get("name")
                    == "MSRR_SR_systemmovepr" else "XtPlus1__2")
                and kind == "Instruction.Rules.Rule"
                and rule.get("display") == "<Xt+1>"
                and bindings.get("Rt") == (0, 5)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<Xt+1>") == [
                    {"_type": "AST.Identifier", "value": "Rt"}
                ]
                and (rule.get("symbols") or {}).get("symbols") == [
                    {"_type": "Instruction.Symbols.Literal", "value": "X"},
                    {"_type": "Instruction.Symbols.RuleReference",
                     "rule_id": "UInteger"},
                ]):
            return [(RECIPE_OPCODE["A64_SYSTEMREG_PAIR_SECOND"], 0)]
        if (narrow_fields
                and rule_id == ("immh_shift__6" if narrow_vector
                                else "immh_shift__2")
                and kind == "Instruction.Rules.Rule"
                and rule.get("display") == "<shift>"
                and narrow_encoded.get("<shift>") == [
                    {"_type": "AST.Identifier", "value": "immh"},
                    {"_type": "AST.Identifier", "value": "immb"},
                ]):
            symbols = (rule.get("symbols") or {}).get("symbols", []) or []
            if (len(symbols) == 1
                    and symbols[0].get("rule_id") == "UInteger"):
                return [(RECIPE_OPCODE["A64_ASIMD_SHIFT_IMMEDIATE"], 1)]
        if (rule_id in {"immh_shift__4", "immh_shift__5"}
                and kind == "Instruction.Rules.Rule"
                and rule.get("display") == "<shift>"
                and source.get("name") in A64_ASIMD_SHIFT_T_FORMS
                and bindings.get("immh") == (19, 4)
                and bindings.get("immb") == (16, 3)
                and bindings.get("Q") == (30, 1)
                and (source.get("_meta") or {}).get("encoded_in", {}).get(
                    "<shift>") == [
                        {"_type": "AST.Identifier", "value": "immh"},
                        {"_type": "AST.Identifier", "value": "immb"},
                    ]):
            symbols = (rule.get("symbols") or {}).get("symbols", []) or []
            is_right = source.get("name") in A64_ASIMD_SHIFT_RIGHT_FORMS
            if (rule_id == ("immh_shift__4" if is_right
                            else "immh_shift__5")
                    and len(symbols) == 1
                    and symbols[0].get("rule_id") == "UInteger"):
                mode = 1 if is_right else 0
                return [(RECIPE_OPCODE["A64_ASIMD_SHIFT_IMMEDIATE"], mode)]
        if (rule_id == "T_option__15"
                and kind == "Instruction.Rules.Choice"
                and source.get("name") in A64_ASIMD_SHIFT_T_FORMS
                and bindings.get("immh") == (19, 4)
                and bindings.get("Q") == (30, 1)
                and (source.get("_meta") or {}).get("encoded_in", {}).get(
                    "<T>") == [
                        {"_type": "AST.Identifier", "value": "immh"},
                        {"_type": "AST.Identifier", "value": "Q"},
                    ]):
            expected = [
                "T_0001_0_8B", "T_0001_1_16B", "T_001x_0_4H",
                "T_001x_1_8H", "T_01xx_0_2S", "T_01xx_1_4S",
                "T_1xxx_1_2D",
            ]
            alternatives = rule.get("choices", []) or []
            actual = [
                ((alternative or {}).get("symbols", []) or [{}])[0].get(
                    "rule_id") for alternative in alternatives
            ]
            if actual == expected:
                return [(RECIPE_OPCODE["A64_ASIMD_SHIFT_T"], 0)]
        if reviewed_vfp_multiple_source(source, bindings):
            if rule_id == "dot_vstm_size_choice" \
                    and kind == "Instruction.Rules.Choice":
                alternatives = rule.get("choices", []) or []
                suffix = ((alternatives[1] or {}).get("symbols", []) or []) \
                    if len(alternatives) == 2 else []
                sizes = rules.get("vstm_size", {}).get("choices", []) or []
                literals = [
                    ((choice or {}).get("symbols", []) or [{}])[0].get(
                        "value") for choice in sizes
                ]
                if (len(alternatives) == 2
                        and alternatives[0] is None
                        and [symbol.get("rule_id") for symbol in suffix]
                            == ["DOT", "vstm_size"]
                        and literals == ["32", "64"]):
                    return [(RECIPE_OPCODE["A32_VFP_MULTI_SIZE"], 0)]
            if rule_id in {"registers__10", "registers__11"} \
                    and kind == "Instruction.Rules.Rule":
                expected_display = ("<sreglist>" if rule_id == "registers__10"
                                    else "<dreglist>")
                symbols = (rule.get("symbols") or {}).get("symbols", []) or []
                if (rule.get("display") == expected_display
                        and len(symbols) == 1
                        and symbols[0].get("rule_id")
                            == "multi_register_list"):
                    return [(RECIPE_OPCODE["A32_VFP_MULTI_LIST"],
                             0 if rule_id == "registers__10" else 1)]
        if (rule_id in {"size_option__5", "imm__117"}
                and re.fullmatch(
                    r"V(?:QSHRN|QSHRUN|QRSHRN|QRSHRUN|SHRN|RSHRN)_[AT]1",
                    str(source.get("name", "")))
                and bindings.get("imm6") == (16, 6)
                and all((source.get("_meta") or {}).get(
                    "encoded_in", {}).get(name) == [
                        {"_type": "AST.Identifier", "value": "imm6"}
                    ] for name in ("<size>", "<imm>"))):
            # Narrow shifts encode (source element width - shift) in imm6.
            # The three size ranges are 8..15, 16..31, and 32..63.
            return [(RECIPE_OPCODE["A32_NEON_NARROW_SHIFT"],
                     0 if rule_id == "size_option__5" else 1)]
        if ((rule_id == "d_vd_choice"
                and re.fullmatch(r"(VORR|VBIC)_i_[AT][12]_D",
                                 str(source.get("name", ""))))
                or (rule_id == "d_vd_choice__2"
                    and source.get("_type") == "Instruction.Instruction"
                    and re.fullmatch(r"VORR_i_[AT][12]_Q",
                                     str(source.get("name", "")))
                    and (source.get("_meta") or {}).get(
                        "encoded_in", {}).get("<Qd>") == [
                            {"_type": "AST.Identifier", "value": "D"},
                            {"_type": "AST.Identifier", "value": "Vd"},
                        ])):
            # Omit the assembly-only duplicate destination.  Canonical
            # disassembly spells VORR/VBIC Dd, #imm, not Dd, Dd, #imm.
            # The Q VORR forms use a separate duplicate-destination rule.
            source_symbols = (source.get("assembly") or {}).get("symbols") or []
            next_register = "D_Vd__4" if rule_id == "d_vd_choice__2" \
                else "D_Vd"
            for symbol_index, symbol in enumerate(source_symbols[:-1]):
                if (symbol.get("rule_id") == rule_id
                        and source_symbols[symbol_index + 1].get("rule_id")
                            == next_register):
                    return []
        if (rule_id in {"d_vd_choice", "d_vd_choice__2"}
                and source.get("name") == "VAND"
                and source.get("operation_id") == "VAND_VBIC_i"):
            # The non-preferred VAND immediate alias has the same implicit
            # destination as its VBIC parent. LLVM accepts its two-operand
            # spelling, never the redundant destination token.
            return []
        if (kind == "Instruction.Rules.Rule"
                and rule_id in {"imm__115", "imm__116"}
                and rule.get("display") == "<imm>"
                and bindings.get("L") == (7, 1)
                and bindings.get("imm6") == (16, 6)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<size>") == [
                        {"_type": "AST.Identifier", "value": "L"},
                        {"_type": "AST.Identifier", "value": "imm6"},
                    ]
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<imm>") == [
                        {"_type": "AST.Identifier", "value": "imm6"}
                    ]):
            family = str(source.get("name", "")).split("_", 1)[0]
            right_families = {"VSHR", "VSRA", "VRSHR", "VRSRA", "VSRI"}
            left_families = {"VQSHL", "VQSHLU", "VSHL", "VSLI"}
            if rule_id == "imm__115" and family in right_families:
                return [(RECIPE_OPCODE["A32_NEON_SHIFT_ELEMENT_SIZE"], 1)]
            if rule_id == "imm__116" and family in left_families:
                return [(RECIPE_OPCODE["A32_NEON_SHIFT_ELEMENT_SIZE"], 2)]
        vector_alignment = vector_alignment_recipe(
            source, rule_id, rule, bindings)
        if vector_alignment is not None:
            return [(RECIPE_OPCODE["A32_NEON_ALIGNMENT"],
                     vector_alignment)]
        grouped_zreg = reviewed_grouped_zreg(
            rule_id, rule, source, bindings
        )
        if grouped_zreg is not None:
            return [(RECIPE_OPCODE["GROUPED_ZREG"], grouped_zreg)]
        if reviewed_pn_group(rule_id, rule, source, bindings):
            return [
                (RECIPE_OPCODE["TEXT"], text.id("PN")),
                (RECIPE_OPCODE["A64_PN_GROUP"], 0),
            ]
        if reviewed_tmop_control_reg(rule_id, rule, source, bindings):
            return [(RECIPE_OPCODE["A64_TMOP_ZK"], 0)]
        tmop_zn = reviewed_tmop_zn_pair(rule_id, rule, source, bindings)
        if tmop_zn is not None:
            return [(RECIPE_OPCODE["A64_TMOP_ZN_PAIR"], tmop_zn)]
        scalar_shift64 = reviewed_scalar_simd_shift64(
            rule_id, rule, source, bindings)
        if scalar_shift64 is not None:
            return [(RECIPE_OPCODE["A64_SIMD_SHIFT64"], scalar_shift64)]
        bitfield_alias = reviewed_a64_bitfield_alias_immediate(
            rule_id, rule, source, bindings)
        if bitfield_alias is not None:
            return [(RECIPE_OPCODE["A64_BITFIELD_ALIAS_IMM"], bitfield_alias)]
        if reviewed_a32_vdup_gpr_size(rule_id, rule, source, bindings):
            return [(RECIPE_OPCODE["A32_VDUP_GPR_SIZE"], 0)]
        vdup_dest = reviewed_a32_vdup_gpr_dest(
            rule_id, rule, source, bindings)
        if vdup_dest is not None:
            return [(RECIPE_OPCODE["A32_VDUP_GPR_DEST"], vdup_dest)]
        if reviewed_a32_vmov_sm_next(rule_id, rule, source, bindings):
            return [(RECIPE_OPCODE["A32_VMOV_SM_NEXT"], 0)]
        indexed_operand = reviewed_indexed_operand(
            rule_id, rule, source, bindings
        )
        if indexed_operand is not None:
            return [(RECIPE_OPCODE[indexed_operand], 0)]
        split_indexed = reviewed_a32_split_indexed_operand(
            rule_id, rule, source, bindings)
        if split_indexed is not None:
            opcode, mode = split_indexed
            return [(RECIPE_OPCODE[opcode], mode)]
        shift_alias = reviewed_thumb_shift_alias_imm(
            rule_id, rule, source, bindings)
        if shift_alias is not None:
            return [(RECIPE_OPCODE["T32_SHIFT_ALIAS_IMM"], shift_alias)]
        shift_amount_mode = (
            0 if rule_id == "imm3_imm2"
                 and source.get("name") == "CMP_r_T3"
            else 1 if rule_id == "imm3_imm2__10"
                 and source.get("name") in {"SSAT_T1_ASR", "USAT_T1_ASR"}
            else None
        )
        if (kind == "Instruction.Rules.Rule"
                and shift_amount_mode is not None
                and rule.get("display") == "<amount>"
                and (rule.get("symbols") or {}).get("symbols") == [
                    {"_type": "Instruction.Symbols.RuleReference",
                     "rule_id": "UInteger"},
                ]
                and bindings.get("imm3") == (12, 3)
                and bindings.get("imm2") == (6, 2)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<amount>") == [
                    {"_type": "AST.Identifier", "value": "imm3"},
                    {"_type": "AST.Identifier", "value": "imm2"},
                ]
                and (shift_amount_mode != 0
                     or bindings.get("stype") == (4, 2))
                and (shift_amount_mode != 1
                     or bindings.get("sh") == (21, 1))):
            return [(RECIPE_OPCODE["T32_DATA_PROC_SHIFT_AMOUNT"],
                     shift_amount_mode)]
        if (kind == "Instruction.Rules.Rule"
                and rule_id == "imm__93"
                and source.get("name") in {
                    "SSAT_T1_ASR", "SSAT_T1_LSL"
                }
                and rule.get("display") == "<imm>"
                and (rule.get("symbols") or {}).get("symbols") == [
                    {"_type": "Instruction.Symbols.RuleReference",
                     "rule_id": "UInteger"},
                ]
                and bindings.get("sat_imm") == (0, 5)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<imm>") == [
                    {"_type": "AST.Identifier", "value": "sat_imm"},
                ]):
            return [(RECIPE_OPCODE["T32_SSAT_WIDTH_PLUS1"], 0)]
        if reviewed_a32_vcvt_sdm(rule_id, rule, source, bindings):
            return [(RECIPE_OPCODE["A32_VCVT_SDM"], 0)]
        if reviewed_a32_vcvt_ddm(rule_id, rule, source, bindings):
            return [(RECIPE_OPCODE["A32_VCVT_DDM"], 0)]
        vfp_imm8 = reviewed_a32_vfp_imm8(rule_id, rule, source, bindings)
        if vfp_imm8 is not None:
            return [(RECIPE_OPCODE["A32_VFP_FP_IMM8"], vfp_imm8)]
        if reviewed_a32_vdup_lane(rule_id, rule, source, bindings):
            return [(RECIPE_OPCODE["A32_VDUP_LANE"], 0)]
        if reviewed_a32_vdup_lane_size(rule_id, rule, source, bindings):
            return [(RECIPE_OPCODE["A32_VDUP_LANE_SIZE"], 0)]
        if (rule_id == "fbits__6"
                and kind == "Instruction.Rules.Rule"
                and rule.get("display") == "<fbits>"
                and source.get("name") in {
                    "VCVT_xs_A1_D", "VCVT_xs_A1_Q",
                    "VCVT_xs_T1_D", "VCVT_xs_T1_Q",
                }
                and bindings.get("imm6") == (16, 6)
                and bindings.get("op") == (8, 2)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<fbits>") == [
                        {"_type": "AST.Identifier", "value": "imm6"}
                    ]
                and (rule.get("symbols") or {}).get("symbols") == [
                    {"_type": "Instruction.Symbols.RuleReference",
                     "rule_id": "UInteger"}
                ]):
            return [(RECIPE_OPCODE["A32_NEON_VCVT_SHIFT_BITS"], 0)]
        if reviewed_a32_vcvt_fbits(rule_id, rule, source, bindings):
            return [(RECIPE_OPCODE["A32_VCVT_FBITS"], 0)]
        neon_imm = reviewed_neon_modified_immediate(
            rule_id, rule, source, bindings
        )
        if neon_imm is not None:
            return [(RECIPE_OPCODE["A32_NEON_MODIFIED_IMM"], neon_imm)]
        if (kind == "Instruction.Rules.Rule"
                and rule_id == "imm__114"
                and source.get("name") == "VAND"
                and source.get("operation_id") == "VAND_VBIC_i"
                and rule.get("display") == "<imm>"
                and (rule.get("symbols") or {}).get("symbols") == [
                    {"_type": "Instruction.Symbols.RuleReference",
                     "rule_id": "UInteger"},
                ]
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<imm>") == [
                    {"_type": "AST.Identifier", "value": field}
                    for field in ("cmode", "i", "imm3", "imm4")
                ]
                and bindings.get("cmode") == (8, 4)
                and bindings.get("imm3") == (16, 3)
                and bindings.get("imm4") == (0, 4)
                and bindings.get("op") == (5, 1)
                and bindings.get("Q") == (6, 1)
                and bindings.get("i") in {(24, 1), (28, 1)}):
            assembly_symbols = (source.get("assembly") or {}).get(
                "symbols", []) or []
            datatype_rules = [symbol.get("value")
                              for symbol in assembly_symbols
                              if symbol.get("_type")
                                  == "Instruction.Symbols.Literal"
                              and symbol.get("value") in {"I16", "I32"}]
            if len(datatype_rules) == 1:
                thumb = bindings["i"] == (28, 1)
                sixteen_bit = datatype_rules[0] == "I16"
                return [(RECIPE_OPCODE["A32_NEON_VAND_ALIAS_IMM"],
                         (1 if thumb else 0) | (2 if sixteen_bit else 0))]
        if (kind == "Instruction.Rules.Rule"
                and rule_id == "Rt2__2"
                and (source.get("name") == "LDRD_l_A1"
                     or (source.get("name") == "A1B"
                         and source.get("operation_id") == "LDRD_l"))
                and rule.get("display") == "<Rt2>"
                and bindings.get("Rt") == (12, 4)
                and (source.get("_meta") or {}).get("encoded_in", {}).get(
                    "<Rt2>") == [
                    {"_type": "AST.Identifier", "value": "Rt"}
                ]):
            # The second A32 LDRD destination is implicit Rt+1.  The pinned
            # source maps both displays to raw Rt, not to the rendered pair.
            return [
                (RECIPE_OPCODE["TEXT"], text.id("R")),
                (RECIPE_OPCODE["A32_RT2_PLUS1"], 0),
            ]
        if (kind == "Instruction.Rules.Rule"
                and (rule_id == "i_imm3_imm8"
                    or (rule_id == "i_imm3_imm8__2"
                        and source.get("name") in {"ORN_i_T1", "ORNS_i_T1"}
                        and rule.get("display") == "<const>"
                        and bindings.get("i") == (26, 1)
                        and bindings.get("imm3") == (12, 3)
                        and bindings.get("imm8") == (0, 8)
                        and (source.get("_meta") or {}).get(
                            "encoded_in", {}).get("<const>") == [
                            {"_type": "AST.Identifier", "value": field}
                            for field in ("i", "imm3", "imm8")
                        ]))):
            expressions = encoded.get("<const>", [])
            combined = concatenate_encoded_expressions(expressions)
            if direct_program_width(combined) == 12:
                return [(RECIPE_OPCODE["THUMB_EXPAND_IMM"], combined)]
        if (kind == "Instruction.Rules.Rule"
                and rule_id in {
                    "imm__bitmask", "imm__bitmask_w2", "imm__bitmask_x2"
                }
                and rule.get("display") == "<imm>"
                and (rule.get("symbols") or {}).get("symbols") == [
                    {"_type": "Instruction.Symbols.RuleReference",
                     "rule_id": "UInteger"},
                ]
                and ((re.fullmatch(
                         r"(AND|ORR|EOR|ANDS)_(32|64)S?_log_imm",
                         str(source.get("name", ""))) is not None
                      and rule_id == "imm__bitmask")
                     or (source.get("name") == "TST"
                         and source.get("operation_id")
                             == "TST_ANDS_log_imm"
                         and rule_id == "imm__bitmask")
                     or (source.get("name") == "MOV"
                         and source.get("operation_id")
                             == "MOV_ORR_log_imm"
                         and rule_id in {
                             "imm__bitmask_w2", "imm__bitmask_x2"
                         }))
                and bindings.get("imms") == (10, 6)
                and bindings.get("immr") == (16, 6)):
            expressions = encoded.get("<imm>", [])
            is_64_bit = len(expressions) == 3
            fields = ("N", "imms", "immr") if is_64_bit else (
                "imms", "immr")
            if ((source.get("_meta") or {}).get("encoded_in", {}).get(
                    "<imm>") == [
                        {"_type": "AST.Identifier", "value": name}
                        for name in fields
                    ]
                    and (not is_64_bit or bindings.get("N") == (22, 1))):
                combined = concatenate_encoded_expressions(expressions)
                opcode = "A64_LOGICAL_IMM64" if is_64_bit else \
                    "A64_LOGICAL_IMM32"
                expected_width = 13 if is_64_bit else 12
                if direct_program_width(combined) != expected_width:
                    raise OpaqueRecipe("logical_alias_immediate_width")
                return [(RECIPE_OPCODE[opcode], combined)]
        movwide_alias_modes = {
            "hw_imm16": (0, "MOV_MOVN"),
            "hw_imm16__2": (1, "MOV_MOVZ"),
            "hw_imm16__3": (2, "MOV_MOVN"),
            "hw_imm16__4": (3, "MOV_MOVZ"),
        }
        if (kind == "Instruction.Rules.Rule"
                and rule_id in movwide_alias_modes
                and source.get("name") == "MOV"
                and source.get("operation_id")
                    == movwide_alias_modes[rule_id][1]
                and rule.get("display") == "<imm>"
                and (rule.get("symbols") or {}).get("symbols") == [
                    {"_type": "Instruction.Symbols.RuleReference",
                     "rule_id": "UInteger"},
                ]
                and bindings.get("imm16") == (5, 16)
                and bindings.get("hw") == (21, 2)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<imm>") == [
                    {"_type": "AST.Identifier", "value": "imm16"},
                    {"_type": "AST.Identifier", "value": "hw"},
                ]):
            return [(RECIPE_OPCODE["A64_MOVWIDE_ALIAS_IMM"],
                     movwide_alias_modes[rule_id][0])]
        if (kind == "Instruction.Rules.Rule"
                and rule_id == "const__6"
                and source.get("name") in A64_SVE_FP_IMM8_FORMS
                and (source.get("_meta") or {}).get("encoded_in", {}).get(
                    "<const>") == [
                        {"_type": "AST.Identifier", "value": "imm8"}
                    ]):
            expressions = encoded.get("<const>", [])
            if len(expressions) == 1 \
                    and direct_program_width(expressions[0]) == 8:
                # These four source grammars already place an optional '#'
                # before const__6.  Do not render its nested hash twice.
                return [(RECIPE_OPCODE["A64_SVE_FP_IMM8"], expressions[0])]
        if (kind == "Instruction.Rules.Rule"
                and rule_id == "imm__83"
                and source.get("name") in {"pmov_p_zi_d", "pmov_z_pi_d"}
                and source.get("operation_id") in {
                    "pmov_p_zi", "pmov_z_pi"
                }
                and rule.get("display") == "<imm>"
                and (rule.get("symbols") or {}).get("symbols") == [
                    {"_type": "Instruction.Symbols.RuleReference",
                     "rule_id": "UInteger"}
                ]
                and bindings.get("i3h") == (22, 1)
                and bindings.get("i3l") == (17, 2)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<imm>") == [
                    {"_type": "AST.Identifier", "value": "i3h"},
                    {"_type": "AST.Identifier", "value": "i3l"},
                ]):
            combined = concatenate_encoded_expressions(encoded["<imm>"])
            if direct_program_width(combined) == 3:
                return [(RECIPE_OPCODE["UINT"], combined)]
        if (kind == "Instruction.Rules.Rule"
                and rule_id == "a_b_c_d_e_f_g_h__2"
                and rule.get("display") == "<imm>"
                and source.get("name") in {
                    "FMOV_asimdimm_S_s", "FMOV_asimdimm_H_h",
                    "FMOV_asimdimm_D2_d",
                }
                and (rule.get("symbols") or {}).get("symbols") == [
                    {"_type": "Instruction.Symbols.RuleReference",
                     "rule_id": "SInteger"}
                ]
                and (source.get("_meta") or {}).get("encoded_in", {}).get(
                    "<imm>") == [
                    {"_type": "AST.Identifier", "value": field}
                    for field in "abcdefgh"
                ]
                and all(bindings.get(field) == (bit, 1)
                        for field, bit in zip("abcdefgh", (18, 17, 16, 9, 8, 7, 6, 5)))):
            fields = {field.get("name"): field
                      for field in (source.get("encoding") or {}).get(
                          "values", [])
                      if field.get("_type") == "Instruction.Encodeset.Field"}
            expected_op_o2 = {
                "FMOV_asimdimm_S_s": ("'0'", "'0'"),
                "FMOV_asimdimm_H_h": ("'0'", "'1'"),
                "FMOV_asimdimm_D2_d": ("'1'", "'0'"),
            }[source["name"]]
            if (all(fields.get(field, {}).get("value", {}).get("value")
                    == "'x'" for field in "abcdefgh")
                    and fields.get("cmode", {}).get("value", {}).get(
                        "value") == "'1111'"
                    and (fields.get("op", {}).get("value", {}).get("value"),
                         fields.get("o2", {}).get("value", {}).get("value"))
                    == expected_op_o2):
                combined = concatenate_encoded_expressions(encoded["<imm>"])
                if direct_program_width(combined) == 8:
                    return [(RECIPE_OPCODE["A64_ASIMD_FMOV_IMM8"], combined)]
        if (kind == "Instruction.Rules.Rule"
                and rule_id == "a_b_c_d_e_f_g_h__3"
                and rule.get("display") == "<imm>"
                and source.get("name") in {
                    "MOVI_asimdimm_D_ds", "MOVI_asimdimm_D2_d"
                }
                and (rule.get("symbols") or {}).get("symbols") == [
                    {"_type": "Instruction.Symbols.RuleReference",
                     "rule_id": "UInteger"},
                ]
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<imm>") == [
                    {"_type": "AST.Identifier", "value": field}
                    for field in "abcdefgh"
                ]
                and all(bindings.get(field) == (bit, 1)
                        for field, bit in zip(
                            "abcdefgh", (18, 17, 16, 9, 8, 7, 6, 5)))
                and bindings.get("cmode") == (12, 4)
                and bindings.get("op") == (29, 1)):
            fields = {field.get("name"): field
                      for field in (source.get("encoding") or {}).get(
                          "values", [])
                      if field.get("_type") == "Instruction.Encodeset.Field"}
            if (fields.get("cmode", {}).get("value", {}).get("value")
                    == "'1110'"
                    and fields.get("op", {}).get("value", {}).get("value")
                    == "'1'"
                    and all(fields.get(field, {}).get("value", {}).get(
                        "value") == "'x'" for field in "abcdefgh")):
                combined = concatenate_encoded_expressions(encoded["<imm>"])
                if direct_program_width(combined) == 8:
                    return [(RECIPE_OPCODE["A64_ASIMD_MOVI_BYTE_MASK"],
                             combined)]
        if (kind == "Instruction.Rules.Rule"
                and rule_id == "imm_0_63"
                and source.get("name") in {
                    "TBZ_only_testbranch", "TBNZ_only_testbranch"
                }
                and rule.get("display") == "<imm>"
                and bindings.get("b5") == (31, 1)
                and bindings.get("b40") == (19, 5)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<imm>") == [
                    {"_type": "AST.Identifier", "value": "b5"},
                    {"_type": "AST.Identifier", "value": "b40"},
                ]):
            # The high test-bit index is precisely b5:b40, unlike bitmask
            # immediates whose split fields need an architectural transform.
            combined = concatenate_encoded_expressions(encoded["<imm>"])
            if direct_program_width(combined) == 6:
                return [(RECIPE_OPCODE["UINT"], combined)]
        if (kind == "Instruction.Rules.Rule"
                and rule_id == "len_op"
                and source.get("name") == "LUTI2_asimdtbl_L6"
                and rule.get("display") == "<index>"
                and (rule.get("symbols") or {}).get("symbols") == [
                    {"_type": "Instruction.Symbols.RuleReference",
                     "rule_id": "UInteger"},
                ]
                and bindings.get("len") == (13, 2)
                and bindings.get("op") == (12, 1)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<index>") == [
                    {"_type": "AST.Identifier", "value": "len"},
                    {"_type": "AST.Identifier", "value": "op"},
                ]):
            combined = concatenate_encoded_expressions(encoded["<index>"])
            if direct_program_width(combined) == 3:
                return [(RECIPE_OPCODE["UINT"], combined)]
        if (kind == "Instruction.Rules.Rule"
                and rule_id == "imm420"
                and source.get("name") == "EXT_asimdext_only"
                and rule.get("display") == "<index>"
                and (rule.get("symbols") or {}).get("symbols") == [
                    {"_type": "Instruction.Symbols.RuleReference",
                     "rule_id": "UInteger"},
                ]
                and bindings.get("Q") == (30, 1)
                and bindings.get("imm4") == (11, 4)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<index>") == [
                    {"_type": "AST.Identifier", "value": "Q"},
                    {"_type": "AST.Identifier", "value": "imm4"},
                ]):
            return [(RECIPE_OPCODE["A64_ASIMD_EXT_INDEX"], 0)]
        if (kind == "Instruction.Rules.Rule"
                and rule_id == "index_option__3"
                and source.get("name") == "FCMLA_advsimd_elt"
                and rule.get("display") == "<index>"
                and (rule.get("symbols") or {}).get("symbols") == [
                    {"_type": "Instruction.Symbols.RuleReference",
                     "rule_id": "UInteger"},
                ]
                and bindings.get("size") == (22, 2)
                and bindings.get("H") == (11, 1)
                and bindings.get("L") == (21, 1)
                and bindings.get("Q") == (30, 1)
                and (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<index>") == [
                    {"_type": "AST.Identifier", "value": "size"},
                    {"_type": "AST.Identifier", "value": "H"},
                    {"_type": "AST.Identifier", "value": "L"},
                ]):
            return [(RECIPE_OPCODE["A64_FCMLA_INDEX"], 0)]
        if (kind == "Instruction.Rules.Rule"
                and rule_id == "type"
                and source.get("name") in {"VSHLL_A2", "VSHLL_T2"}
                and bindings.get("size") == (18, 2)
                and "<type>" not in ((source.get("_meta") or {}).get(
                    "encoded_in") or {})):
            return [(RECIPE_OPCODE["TEXT"], text.id("i"))]
        if (kind == "Instruction.Rules.Rule"
                and rule_id in {"size__5", "imm__108"}
                and source.get("name") in {"VSHLL_A2", "VSHLL_T2"}
                and bindings.get("size") == (18, 2)
                and rule.get("display") not in ((source.get("_meta") or {}).get(
                    "encoded_in") or {})):
            # A2/T2 encode the full element-width shift as size, rather
            # than carrying an ordinary immediate field.
            return [(RECIPE_OPCODE["A32_VSHLL_FULL_SHIFT"], 0)]
        if (kind == "Instruction.Rules.Rule"
                and rule_id in {"size__6", "size__7"}
                and source.get("name") == "VEXT"
                and bindings.get("imm4") == (8, 4)
                and "<size>" not in ((source.get("_meta") or {}).get(
                    "encoded_in") or {})):
            # The A32/T32 VEXT alias is always the byte-element spelling;
            # its 8 is implicit, not an encoded size selector.
            return [(RECIPE_OPCODE["TEXT"], text.id("8"))]
        if (kind == "Instruction.Rules.Rule"
                and rule.get("display") == "<registers>"
                and "register_list" in bindings):
            list_start, list_width = bindings["register_list"]
            extra_start = 255
            extra_register = 0
            if (list_start == 0 and list_width == 8
                    and bindings.get("M") == (8, 1)):
                extra_start = 8
                extra_register = 14
            elif (list_start == 0 and list_width == 8
                    and bindings.get("P") == (8, 1)):
                extra_start = 8
                extra_register = 15
            elif (list_start == 0 and list_width == 14
                    and (bindings.get("M") == (14, 1)
                         or bindings.get("P") == (15, 1))):
                # T32 wide multiple transfers place the LR/PC membership
                # bits directly above r0-r13, so the raw low 16 bits already
                # are the architectural list mask.
                list_width = 16
            if (0 <= list_start < 32 and 0 < list_width <= 16
                    and list_start + list_width <= 32):
                packed = (list_start & 0xff) \
                    | ((list_width & 0xff) << 8) \
                    | ((extra_start & 0xff) << 16) \
                    | ((extra_register & 0xff) << 24)
                return [(RECIPE_OPCODE["GPR_LIST"], packed)]
        if (kind == "Instruction.Rules.Rule"
                and rule.get("display") in {"<Qd>", "<Qn>", "<Qm>"}):
            display = str(rule.get("display"))
            expressions = encoded.get(display, [])
            symbols = (rule.get("symbols") or {}).get("symbols", []) or []
            if (len(expressions) == 2
                    and len(symbols) == 2
                    and symbols[0].get("_type")
                        == "Instruction.Symbols.Literal"
                    and symbols[0].get("value") == "Q"
                    and symbols[1].get("_type")
                        == "Instruction.Symbols.RuleReference"
                    and symbols[1].get("rule_id") == "UInteger"):
                combined = concatenate_encoded_expressions(expressions)
                if direct_program_width(combined) == 5:
                    return [
                        (RECIPE_OPCODE["TEXT"], text.id("Q")),
                        (RECIPE_OPCODE["UINT_RSHIFT1"], combined),
                    ]
        if fpx_d_list_recipe(source, rule_id, rule, bindings):
            return [(RECIPE_OPCODE["A32_FPX_D_LIST"], 0)]
        vector_list = vector_d_list_recipe(source, rule_id, rule, bindings)
        if vector_list is not None:
            return [(RECIPE_OPCODE["VECTOR_D_LIST"], vector_list)]
        if (kind == "Instruction.Rules.Rule"
                and rule_id == "imm16_offset"
                and rule.get("display") == "<label>"
                and source.get("name") in A64_PAUTH_LR_PC_LABEL_FORMS
                and bindings.get("imm16") == (5, 16)
                and (source.get("_meta") or {}).get("encoded_in", {}).get(
                    "<label>") == [
                        {"_type": "AST.Identifier", "value": "imm16"}
                    ]):
            return [(RECIPE_OPCODE["A64_PAUTH_LR_PC_LABEL"], 0)]
        if (kind == "Instruction.Rules.Rule"
                and rule.get("display") == "<label>"
                and source.get("name") in A64_PC_LABEL_FORMS
                and (source.get("_meta") or {}).get("encoded_in", {}).get(
                    "<label>") == [
                        {"_type": "AST.Identifier", "value": field}
                        for field in (
                            ("immhi", "immlo")
                            if A64_PC_LABEL_FORMS[str(source["name"])] <= 1
                            else ("imm19",)
                        )
                    ]
                and str(source.get("name", "")).startswith(
                    ("ADR", "LDR", "PRFM"))):
            return [(
                RECIPE_OPCODE["A64_PC_LABEL"],
                A64_PC_LABEL_FORMS[str(source["name"])],
            )]
        if (kind == "Instruction.Rules.Rule"
                and rule.get("display") == "<label>"):
            alias_key = (source.get("name"), source.get("operation_id"),
                         tree.first_literal(source))
            mode = A32_T32_PC_LABEL_FORMS.get(
                str(source.get("name", "")),
                A32_T32_PC_LABEL_ALIASES.get(alias_key))
            if mode is not None:
                raw_label = ((source.get("_meta") or {}).get("encoded_in")
                             or {}).get("<label>")
                field_names = (
                    ("imm4H", "imm4L") if mode == 0 else
                    ("i", "imm3", "imm8") if mode in {8, 9} else
                    ("imm12",) if mode in {1, 7, 10, 11} else
                    ("imm8",)
                )
                field_shapes = {
                    "imm4H": (8, 4), "imm4L": (0, 4),
                    "imm8": (0, 8), "imm12": (0, 12),
                    "i": (26, 1), "imm3": (12, 3),
                }
                if (raw_label == [
                        {"_type": "AST.Identifier", "value": field}
                        for field in field_names
                    ] and all(bindings.get(field) == field_shapes[field]
                              for field in field_names)
                        and (mode in {4, 8, 9, 10, 11}
                             or bindings.get("U") == (23, 1))):
                    return [(RECIPE_OPCODE["A32_T32_PC_LABEL"], mode)]
        nested_semantic_label = semantic_label or (
            has_semantic_branch_target and rule.get("display") == "<label>"
        )
        # The resolved target comes from independently generated control-flow
        # metadata. It does not depend on the source's omitted disassemble
        # transform, and therefore does not need the raw label expression.
        if rule.get("display") == "<label>" and not nested_semantic_label:
            raise OpaqueRecipe("label_transform_missing")
        value = inherited if nested_semantic_label else rule_value(
            rule_id, rule, inherited
        )
        nested_stack = call_stack + (rule_id,)
        if kind == "Instruction.Rules.Token":
            default = rule.get("default")
            if default is not None:
                return [(RECIPE_OPCODE["TEXT"], text.id(normalize_token(rule_id, str(default))))]
            if rule_id == "UInteger":
                if nested_semantic_label:
                    return [(RECIPE_OPCODE["BRANCH_TARGET"], 0)]
                if value is None:
                    raise OpaqueRecipe("missing_value_mapping")
                return [(RECIPE_OPCODE["UINT"], value)]
            if rule_id == "SInteger":
                if nested_semantic_label:
                    return [(RECIPE_OPCODE["BRANCH_TARGET"], 0)]
                if value is None:
                    raise OpaqueRecipe("missing_value_mapping")
                return [(RECIPE_OPCODE["SINT"], value)]
            if rule_id == "Real":
                raise OpaqueRecipe("real_transform_missing")
            raise OpaqueRecipe("token_semantics_unknown")
        if kind == "Instruction.Rules.Rule":
            # T32 grammar carries an explicit AL assembly alternative even
            # though canonical disassembly omits the default condition.
            if rule_id.startswith("AL_option"):
                return []
            # System-operation option leaves carry feature predicates.  The
            # decoder-side architectural-alias selector evaluates those exact
            # predicates before choosing the alias; once selected, the
            # formatter may safely render the matching spelling branch.
            system_option_leaf = bool(call_stack) \
                and call_stack[-1] in SYSTEM_OPTION_RULE_SHAPES
            if (rule.get("condition")
                    != {"_type": "AST.Bool", "value": True}
                    and not system_option_leaf):
                raise OpaqueRecipe("conditional_rule_without_runtime_features")
            return assembly_ops(
                rule.get("symbols"), value, nested_stack,
                semantic_label=nested_semantic_label,
            )
        if kind == "Instruction.Rules.Choice":
            if (rule_id == "dot_dt_choice__3"
                    and source.get("_type") == "Instruction.InstructionAlias"
                    and source.get("name") == "VMOV"
                    and source.get("operation_id") == "VMOV_VORR_r"
                    and (source.get("preferred") or {}).get("_type")
                        == "AST.BinaryOp"
                    and (source.get("preferred") or {}).get("op") == "=="
                    and bindings.get("D") == (22, 1)
                    and bindings.get("Vd") == (12, 4)
                    and bindings.get("M") == (5, 1)
                    and bindings.get("Vm") == (0, 4)
                    and bindings.get("N") == (7, 1)
                    and bindings.get("Vn") == (16, 4)
                    and bindings.get("Q") == (6, 1)
                    and set((source.get("_meta") or {}).get(
                        "encoded_in", {})) in (
                            {"<Dd>", "<Dm>"},
                            {"<Qd>", "<Qm>"},
                        )
                    and len(rule.get("choices") or []) == 2
                    and (rule.get("choices") or [])[0] is None
                    and [symbol.get("rule_id") for symbol in
                         ((rule.get("choices") or [])[1] or {}).get(
                             "symbols", [])] == ["DOT", "dt__4"]):
                # VORR register bytes have no element-size/datatype field.
                # VMOV's optional suffix is therefore canonically omitted;
                # its typed spellings assemble to exactly the same word.
                return []
            if (source.get("name") == "zero_za_i_"
                    and rule_id == "OPT_SPACE"
                    and rule.get("display") == " "
                    and rule.get("choices") == [
                        {"_type": "Instruction.Assembly",
                         "description": {"_type": "Description",
                                         "after": None, "before": None},
                         "symbols": [{"_type": "Instruction.Symbols.RuleReference",
                                      "rule_id": "SPACE"}]},
                        None,
                    ]):
                return []
            if (source.get("name") == "zero_za_i_"
                    and rule_id == "mask__2"
                    and rule.get("display") == "<mask>"
                    and bindings.get("imm8") == (0, 8)
                    and (source.get("_meta") or {}).get(
                        "encoded_in", {}).get("<mask>") == [
                        {"_type": "AST.Identifier", "value": "imm8"}
                    ]
                    and [
                        [symbol.get("rule_id") for symbol in
                         (choice.get("symbols") or [])]
                        for choice in (rule.get("choices") or [])
                    ] == [
                        ["ZA__2"], ["ZA"], ["ZAn_H"],
                        ["S_tile_list"], ["D_tile_list"], ["ZAn_B"],
                    ]):
                return [(RECIPE_OPCODE["A64_SME_ZERO_MASK"], 0)]
            if (source.get("name") == "fadda_v_p_z_"
                    and rule_id == "V__4"
                    and rule.get("display") == "<V>"
                    and bindings.get("size") == (22, 2)
                    and (source.get("_meta") or {}).get(
                        "encoded_in", {}).get("<V>") == [
                        {"_type": "AST.Identifier", "value": "size"}
                    ]
                    and [
                        [symbol.get("rule_id") for symbol in
                         (choice.get("symbols") or [])]
                        for choice in (rule.get("choices") or [])
                    ] == [["V_H__4"], ["V_S__4"], ["V_D__4"]]):
                return [(RECIPE_OPCODE["A64_SVE_FADDA_SCALAR_V"], 0)]
            if (source.get("name") == "adr_z_az_sd_same_scaled"
                    and rule_id == "optional_mod_amount"
                    and rule.get("display") is None
                    and bindings.get("msz") == (10, 2)
                    and bindings.get("sz") == (22, 1)
                    and all((source.get("_meta") or {}).get(
                        "encoded_in", {}).get(display) == [
                        {"_type": "AST.Identifier", "value": "msz"}
                    ] for display in ("<mod>", "<amount>"))
                    and [
                        [symbol.get("rule_id") for symbol in
                         (choice.get("symbols") or [])]
                        for choice in (rule.get("choices") or [])
                    ] == [
                        ["mod_absent", "amount__12_absent"],
                        ["COMMA", "mod_LSL", "OPT_SPACE", "amount__12"],
                    ]):
                # The two-bit msz is both the optional-shift selector and
                # its amount. Zero has no modifier; 1..3 spell lsl #msz.
                return [(RECIPE_OPCODE["A64_SVE_ADR_SCALED_SHIFT"], 0)]
            # TBZ/TBNZ use b5 for W/X and Rt[4:0] for the register number.
            # The Rt=31 spelling is ZR, not register 31. Keep this tied to
            # the two exact source leaves and their untransformed field.
            if (source.get("name") in {
                    "TBZ_only_testbranch", "TBNZ_only_testbranch"}
                    and rule_id == "Rt_option"
                    and rule.get("display") == "<t>"
                    and bindings.get("b5") == (31, 1)
                    and bindings.get("Rt") == (0, 5)
                    and (source.get("_meta") or {}).get(
                        "encoded_in", {}).get("<t>") == [
                        {"_type": "AST.Identifier", "value": "Rt"}
                    ]
                    and [
                        [symbol.get("rule_id") for symbol in
                         (choice.get("symbols") or [])]
                        for choice in (rule.get("choices") or [])
                    ] == [["t_ZR"], ["t"]]):
                return [(RECIPE_OPCODE["A64_TESTBRANCH_RT"], 0)]
            # Architectural system-register names depend on optional CPU
            # features; the grammar's S<op0>_<op1>_C<Cn>_C<Cm>_<op2>
            # fallback is lossless for all four exact move forms.
            if (rule_id == A64_SYSTEMREG_NUMERIC_FORMS.get(
                    source.get("name"))
                    and rule.get("display") is None
                    and all(bindings.get(field) == shape for field, shape in {
                        "o0": (19, 1), "op1": (16, 3),
                        "CRn": (12, 4), "CRm": (8, 4),
                        "op2": (5, 3),
                    }.items())
                    and (source.get("_meta") or {}).get(
                        "encoded_in", {}).get("<systemreg>") == [
                        {"_type": "AST.Identifier", "value": field}
                        for field in ("o0", "op1", "CRn", "CRm", "op2")
                    ]):
                alternatives = rule.get("choices") or []
                fallback = (
                    [symbol.get("value", symbol.get("rule_id"))
                     for symbol in (alternatives[1].get("symbols") or [])]
                    if len(alternatives) == 2 else []
                )
                if fallback == [
                    "S", "op0_option" if rule_id == "MRS_choice"
                    else "op0_option__2", "_", "op1", "_", "Cn",
                    "_", "Cm", "_", "op2",
                ]:
                    return [(RECIPE_OPCODE["A64_SYSTEMREG_NUMERIC"], 0)]
            # The unqualified BTI spelling is valid for targets=00 on every
            # BTI CPU; only the optional explicit 'r' spelling requires
            # FEAT_BTIE.  The other three target suffixes are encoded.
            if (source.get("name") == "BTI_HB_hints"
                    and rule_id == "optional_targets"
                    and rule.get("display") is None
                    and bindings.get("op2") == (5, 3)
                    and (source.get("_meta") or {}).get(
                        "encoded_in", {}).get("<targets>") == [
                        {"_type": "AST.Identifier", "value": "op2"}
                    ]):
                actual = [
                    [symbol.get("rule_id") for symbol in
                     (choice.get("symbols") or [])]
                    for choice in (rule.get("choices") or [])
                ]
                if actual == [
                    ["targets_00_omitted_default"],
                    ["SPACE", "targets_option"],
                ]:
                    return [(RECIPE_OPCODE["A64_BTI_TARGETS"], 0)]
            # The named prefetch spelling of some Rt values depends on an
            # optional feature not carried by the formatter ABI.  The pinned
            # grammar also supplies an unconditional numeric #imm5 spelling.
            # Use that lossless spelling for these exact four forms.
            if (source.get("name") in A64_PRFM_NUMERIC_FORMS
                    and rule_id == (
                        "prfop_choice__6" if source.get("name")
                        == "PRFM_P_ldst_pos" else "prfop_choice__3")
                    and rule.get("display") is None
                    and bindings.get("Rt") == (0, 5)
                    and (source.get("_meta") or {}).get(
                        "encoded_in", {}).get("<imm5>") == [
                        {"_type": "AST.Identifier", "value": "Rt"}
                    ]
                    and (source.get("_meta") or {}).get(
                        "encoded_in", {}).get("<prfop>") == [
                        {"_type": "AST.Identifier", "value": "Rt"}
                    ]):
                alternatives = rule.get("choices") or []
                actual = [
                    [symbol.get("rule_id") for symbol in
                     (alternative.get("symbols") or [])]
                    for alternative in alternatives
                ]
                if actual == [
                    ["Rt_prfop__3" if rule_id == "prfop_choice__6"
                     else "Rt_prfop"],
                    ["hash", "Rt_imm5"],
                ]:
                    return assembly_ops(alternatives[1], value, nested_stack)
            # The conditional half-precision branches only express the
            # feature legality of the selected size.  The spelling itself
            # is an unambiguous projection of immh (and Q for vectors).
            fixed_scalar = source.get("name") in A64_FIXED_FCVT_SCALAR_FORMS
            fixed_vector = source.get("name") in A64_FIXED_FCVT_VECTOR_FORMS
            if (fixed_scalar or fixed_vector) and rule_id == (
                    "V_option__6" if fixed_scalar else "T_option__16"):
                fixed_encoded = (source.get("_meta") or {}).get("encoded_in", {})
                token = "<V>" if fixed_scalar else "<T>"
                fields = ["immh"] if fixed_scalar else ["immh", "Q"]
                expected = (
                    ["V_001x_H_cond", "V_01xx_S", "V_1xxx_D__2"]
                    if fixed_scalar else [
                        "T_001x_0_4H_cond", "T_001x_1_8H_cond",
                        "T_01xx_0_2S", "T_01xx_1_4S",
                        "T_1xxx_1_2D",
                    ]
                )
                actual = [
                    ((choice or {}).get("symbols") or [{}])[0].get("rule_id")
                    for choice in (rule.get("choices") or [])
                ]
                fp16_condition = {
                    "_type": "AST.Function",
                    "arguments": [
                        {"_type": "AST.Identifier", "value": "FEAT_FP16"}
                    ],
                    "name": "IsFeatureImplemented",
                    "parameters": [],
                }
                if (rule.get("display") == token
                        and fixed_encoded.get(token) == [
                            {"_type": "AST.Identifier", "value": field}
                            for field in fields
                        ]
                        and bindings.get("immh") == (19, 4)
                        and bindings.get("immb") == (16, 3)
                        and (fixed_scalar or bindings.get("Q") == (30, 1))
                        and actual == expected
                        and all(
                            rules[choice_id].get("condition") == (
                                fp16_condition if choice_id.endswith("_cond")
                                else {"_type": "AST.Bool", "value": True}
                            )
                            for choice_id in expected
                        )):
                    return [(
                        RECIPE_OPCODE[
                            "A64_SIMD_FIXED_FCVT_SIZE" if fixed_scalar
                            else "A64_ASIMD_FIXED_FCVT_SIZE"
                        ], 0,
                    )]
            vcvt_dt1_a = {
                "VCVT_is_A1_D", "VCVT_is_A1_Q",
                "VCVT_is_T1_D", "VCVT_is_T1_Q",
            }
            vcvt_dt1_b = {
                "VCVT_xs_A1_D", "VCVT_xs_A1_Q",
                "VCVT_xs_T1_D", "VCVT_xs_T1_Q",
            }
            if rule_id in {
                    "dt1_option", "dt1_option__2",
                    "dt2_option__2", "dt2_option__3",
            }:
                alternatives = rule.get("choices", []) or []
                actual = [
                    ((choice or {}).get("symbols") or [{}])[0].get(
                        "rule_id") for choice in alternatives
                ]
                encoded_dt1 = (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<dt1>")
                if (rule_id == "dt1_option"
                        and rule.get("display") == "<dt1>"
                        and source.get("name") in vcvt_dt1_a
                        and bindings.get("size") == (18, 2)
                        and bindings.get("op") == (7, 2)
                        and encoded_dt1 == [
                            {"_type": "AST.Identifier", "value": "size"},
                            {"_type": "AST.Identifier", "value": "op"},
                        ]
                        and actual == [
                            "dt1_01_0x_F16", "dt1_01_10_S16",
                            "dt1_01_11_U16", "dt1_10_0x_F32",
                            "dt1_10_10_S32", "dt1_10_11_U32",
                        ]):
                    return [(RECIPE_OPCODE["A32_NEON_VCVT_DATATYPE"], 0)]
                if (rule_id == "dt1_option__2"
                        and rule.get("display") == "<dt1>"
                        and source.get("name") in vcvt_dt1_b
                        and bindings.get("op") == (8, 2)
                        and bindings.get("U") == (
                            28 if "_T1_" in str(source.get("name"))
                            else 24, 1)
                        and encoded_dt1 == [
                            {"_type": "AST.Identifier", "value": "op"},
                            {"_type": "AST.Identifier", "value": "U"},
                        ]
                        and actual == [
                            "dt1_00_x_F16", "dt1_01_0_S16",
                            "dt1_01_1_U16", "dt1_10_x_F32",
                            "dt1_11_0_S32", "dt1_11_1_U32",
                        ]):
                    return [(RECIPE_OPCODE["A32_NEON_VCVT_DATATYPE"],
                             2 if "_T1_" in str(source.get("name")) else 1)]
                encoded_dt2 = (source.get("_meta") or {}).get(
                    "encoded_in", {}).get("<dt2>")
                if (rule_id == "dt2_option__2"
                        and rule.get("display") == "<dt2>"
                        and source.get("name") in vcvt_dt1_a
                        and bindings.get("size") == (18, 2)
                        and bindings.get("op") == (7, 2)
                        and encoded_dt2 == [
                            {"_type": "AST.Identifier", "value": "size"},
                            {"_type": "AST.Identifier", "value": "op"},
                        ]
                        and actual == [
                            "dt2_01_00_S16", "dt2_01_01_U16",
                            "dt2_01_1x_F16", "dt2_10_00_S32",
                            "dt2_10_01_U32", "dt2_10_1x_F32",
                        ]):
                    return [(
                        RECIPE_OPCODE["A32_NEON_VCVT_SOURCE_DATATYPE"], 0
                    )]
                if (rule_id == "dt2_option__3"
                        and rule.get("display") == "<dt2>"
                        and source.get("name") in vcvt_dt1_b
                        and bindings.get("op") == (8, 2)
                        and bindings.get("U") == (
                            28 if "_T1_" in str(source.get("name"))
                            else 24, 1)
                        and encoded_dt2 == [
                            {"_type": "AST.Identifier", "value": "op"},
                            {"_type": "AST.Identifier", "value": "U"},
                        ]
                        and actual == [
                            "dt2_00_0_S16", "dt2_00_1_U16",
                            "dt2_01_x_F16", "dt2_10_0_S32",
                            "dt2_10_1_U32", "dt2_11_x_F32",
                        ]):
                    return [(
                        RECIPE_OPCODE["A32_NEON_VCVT_SOURCE_DATATYPE"],
                        2 if "_T1_" in str(source.get("name")) else 1,
                    )]
            if (rule_id == "T__8"
                    and source.get("name") in {
                        "addhnb_z_zz_", "raddhnb_z_zz_",
                        "subhnb_z_zz_", "rsubhnb_z_zz_",
                    }
                    and rule.get("display") == "<T>"
                    and bindings.get("size") == (22, 2)
                    and (source.get("_meta") or {}).get(
                        "encoded_in", {}).get("<T>") == [
                            {"_type": "AST.Identifier", "value": "size"}
                        ]):
                alternatives = rule.get("choices", []) or []
                actual = [
                    ((choice or {}).get("symbols") or [{}])[0].get(
                        "rule_id") for choice in alternatives
                ]
                if actual == ["T_B__5", "T_H__5", "T_S__8"]:
                    return [(RECIPE_OPCODE["A64_SVE_NARROW_DEST_TYPE"], 0)]
            if (rule_id == "Tb"
                    and source.get("name") in {
                        "addhnb_z_zz_", "raddhnb_z_zz_",
                        "subhnb_z_zz_", "rsubhnb_z_zz_",
                    }
                    and rule.get("display") == "<Tb>"
                    and bindings.get("size") == (22, 2)
                    and (source.get("_meta") or {}).get(
                        "encoded_in", {}).get("<Tb>") == [
                            {"_type": "AST.Identifier", "value": "size"}
                        ]):
                alternatives = rule.get("choices", []) or []
                actual = [
                    ((choice or {}).get("symbols") or [{}])[0].get(
                        "rule_id") for choice in alternatives
                ]
                if actual == ["Tb_H", "Tb_S", "Tb_D"]:
                    return [(RECIPE_OPCODE["A64_SVE_NARROW_SOURCE_TYPE"], 0)]
            if (rule_id == "nSP"
                    and source.get("name") in {
                        "dup_z_r_", "cpy_z_p_r_",
                        "mov_z_r_", "mov_z_p_r_",
                    }
                    and rule.get("display") == "<n|SP>"
                    and bindings.get("Rn") == (5, 5)
                    and (source.get("_meta") or {}).get(
                        "encoded_in", {}).get("<n|SP>") == [
                            {"_type": "AST.Identifier", "value": "Rn"}
                        ]):
                alternatives = rule.get("choices", []) or []
                actual = [
                    ((choice or {}).get("symbols") or [{}])[0].get(
                        "rule_id") for choice in alternatives
                ]
                if actual == ["nSP_SP", "nSP_number"]:
                    return [(RECIPE_OPCODE["A64_SVE_GPR_SP_SUFFIX"], 0)]
            if (rule_id == "R__3"
                    and source.get("name") in {
                        "dup_z_r_", "cpy_z_p_r_",
                        "mov_z_r_", "mov_z_p_r_",
                    }
                    and rule.get("display") == "<R>"
                    and bindings.get("size") == (22, 2)
                    and bindings.get("Rn") == (5, 5)
                    and (source.get("_meta") or {}).get(
                        "encoded_in", {}).get("<R>") == [
                            {"_type": "AST.Identifier", "value": "size"}
                        ]):
                alternatives = rule.get("choices", []) or []
                actual = [
                    ((choice or {}).get("symbols") or [{}])[0].get(
                        "rule_id") for choice in alternatives
                ]
                if actual == ["R_W__3", "R_X__3"]:
                    return [(RECIPE_OPCODE["A64_SVE_GPR_SIZE_PREFIX"], 0)]
            if (rule_id == "Simm9_option"
                    and source.get("name") in {
                        "LDRAA_64_ldst_pac", "LDRAA_64W_ldst_pac",
                        "LDRAB_64_ldst_pac", "LDRAB_64W_ldst_pac",
                    }
                    and bindings.get("S") == (22, 1)
                    and bindings.get("imm9") == (12, 9)
                    and (source.get("_meta") or {}).get(
                        "encoded_in", {}).get("<simm>") == [
                            {"_type": "AST.Identifier", "value": "S"},
                            {"_type": "AST.Identifier", "value": "imm9"},
                        ]):
                alternatives = rule.get("choices", []) or []
                actual = [
                    [symbol.get("rule_id") for symbol in
                     ((choice or {}).get("symbols") or [])]
                    for choice in alternatives
                ]
                if actual == [
                        ["imm9_default"], ["COMMA", "hash", "S_imm9"]
                    ]:
                    return [(RECIPE_OPCODE["A64_PAUTH_LDST_SIMM"], 0)]
            if (rule_id in {"n__5", "m__3"}
                    and str(source.get("name", "")).endswith("_rr_")
                    and bindings.get("Rn") == (5, 5)
                    and bindings.get("Rm") == (16, 5)
                    and ((bindings.get("sf") == (12, 1)
                          and (source.get("_meta") or {}).get(
                              "encoded_in", {}).get("<R>") == [
                                  {"_type": "AST.Identifier", "value": "sf"}
                              ])
                         or (bindings.get("sz") == (22, 1)
                             and (source.get("_meta") or {}).get(
                                 "encoded_in", {}).get("<R>") == [
                                     {"_type": "AST.Identifier", "value": "sz"}
                                 ]))
                    and (source.get("_meta") or {}).get(
                        "encoded_in", {}).get(
                            "<n>" if rule_id == "n__5" else "<m>") == [
                            {"_type": "AST.Identifier",
                             "value": "Rn" if rule_id == "n__5" else "Rm"}
                        ]):
                # The preceding R rule writes W/X; this suffix writes ZR
                # for encoded register 31, otherwise the register number.
                return [(RECIPE_OPCODE["A64_SVE_GPR_SUFFIX"],
                         0 if rule_id == "n__5" else 1)]
            addsub_ext_names = {
                "ADD_64_addsub_ext", "ADDS_64S_addsub_ext",
                "SUB_64_addsub_ext", "SUBS_64S_addsub_ext",
                "CMN", "CMP",
            }
            addsub_ext_32_names = {
                "ADD_32_addsub_ext", "ADDS_32S_addsub_ext",
                "SUB_32_addsub_ext", "SUBS_32S_addsub_ext",
                "CMN", "CMP",
            }
            if (source.get("name") in addsub_ext_names
                    and bindings.get("option") == (13, 3)
                    and bindings.get("imm3") == (10, 3)
                    and bindings.get("Rm") == (16, 5)):
                addsub_encoded = (source.get("_meta") or {}).get(
                    "encoded_in", {})
                if (rule_id == "R_option__2"
                        and rule.get("display") == "<R>"
                        and addsub_encoded.get("<R>") == [
                            {"_type": "AST.Identifier", "value": "option"}
                        ]):
                    alternatives = rule.get("choices", []) or []
                    actual = [
                        ((choice or {}).get("symbols") or [{}])[0].get(
                            "rule_id") for choice in alternatives
                    ]
                    if actual == ["R_00x_W", "R_x11_X"]:
                        return [(
                            RECIPE_OPCODE["A64_ADDSUB_EXT_REG_PREFIX"], 0
                        )]
                if rule_id in {"optional_extend__16",
                               "optional_extend__17"}:
                    alternatives = rule.get("choices", []) or []
                    actual = [
                        [symbol.get("rule_id") for symbol in
                         ((choice or {}).get("symbols") or [])]
                        for choice in alternatives
                    ]
                    extend_rule = ("extend_option__7"
                                   if rule_id == "optional_extend__16"
                                   else "extend_option__8")
                    if (actual == [
                            ["COMMA", extend_rule, "imm3_option__2"],
                            ["extend_default", "amount_default"],
                        ]
                            and addsub_encoded.get("<extend>") == [
                                {"_type": "AST.Identifier",
                                 "value": "option"}
                            ]
                            and addsub_encoded.get("<amount>") == [
                                {"_type": "AST.Identifier",
                                 "value": "imm3"}
                            ]):
                        return [(
                            RECIPE_OPCODE["A64_ADDSUB_EXT_OPTION"], 0
                        )]
                if (rule_id == "Rm_option"
                        and rule.get("display") == "<m>"
                        and addsub_encoded.get("<m>") == [
                            {"_type": "AST.Identifier", "value": "Rm"}
                        ]):
                    alternatives = rule.get("choices", []) or []
                    actual = [
                        ((choice or {}).get("symbols") or [{}])[0].get(
                            "rule_id") for choice in alternatives
                    ]
                    if actual == ["m_ZR", "m"]:
                        return [(
                            RECIPE_OPCODE["A64_ADDSUB_EXT_REG_NUMBER"], 0
                        )]
            if (source.get("name") in addsub_ext_32_names
                    and bindings.get("option") == (13, 3)
                    and bindings.get("imm3") == (10, 3)
                    and bindings.get("Rm") == (16, 5)
                    and rule_id in {"optional_extend__14",
                                    "optional_extend__15"}):
                addsub32_encoded = (source.get("_meta") or {}).get(
                    "encoded_in", {})
                alternatives = rule.get("choices", []) or []
                actual = [
                    [symbol.get("rule_id") for symbol in
                     ((choice or {}).get("symbols") or [])]
                    for choice in alternatives
                ]
                explicit = [
                    "COMMA",
                    "extend_option__5" if rule_id ==
                        "optional_extend__14" else "extend_option__6",
                    "imm3_option__2",
                ]
                default = ["extend_default__2", "amount_default"]
                expected = ([default, explicit] if rule_id ==
                            "optional_extend__14" else [explicit, default])
                if (actual == expected
                        and addsub32_encoded.get("<Wm>") == [
                            {"_type": "AST.Identifier", "value": "Rm"}
                        ]
                        and addsub32_encoded.get("<extend>") == [
                            {"_type": "AST.Identifier", "value": "option"}
                        ]
                        and addsub32_encoded.get("<amount>") == [
                            {"_type": "AST.Identifier", "value": "imm3"}
                        ]):
                    return [(RECIPE_OPCODE["A64_ADDSUB_EXT_OPTION"], 1)]
            narrow_choices = {
                "Tb_option": (0, [
                    "Tb_0001_0_8B", "Tb_0001_1_16B",
                    "Tb_001x_0_4H", "Tb_001x_1_8H",
                    "Tb_01xx_0_2S", "Tb_01xx_1_4S",
                ]),
                "Ta_option": (1, [
                    "Ta_0001_8H", "Ta_001x_4S", "Ta_01xx_2D",
                ]),
                "Vb_option": (2, [
                    "Vb_0001_B", "Vb_001x_H", "Vb_01xx_S",
                ]),
                "Va_option": (3, [
                    "Va_0001_H", "Va_001x_S", "Va_01xx_D",
                ]),
            }
            if widen_vector:
                narrow_choices.update({
                    "Ta_option_new": (1, [
                        "Ta_8H", "Ta_4S", "Ta_2D",
                    ]),
                    "Tb_option_new": (0, [
                        "Tb_8B", "Tb_16B", "Tb_4H", "Tb_8H",
                        "Tb_2S", "Tb_4S",
                    ]),
                })
            if narrow_fields and rule_id in narrow_choices:
                mode, expected = narrow_choices[rule_id]
                is_vector_rule = mode < 2
                token = ("<Tb>", "<Ta>", "<Vb>", "<Va>")[mode]
                fields = ["immh", "Q"] if mode == 0 else ["immh"]
                actual = [
                    ((choice or {}).get("symbols") or [{}])[0].get(
                        "rule_id")
                    for choice in (rule.get("choices") or [])
                ]
                if (is_vector_rule == (narrow_vector or widen_vector)
                        and rule.get("display") == token
                        and narrow_encoded.get(token) == [
                            {"_type": "AST.Identifier", "value": field}
                            for field in fields
                        ]
                        and actual == expected):
                    return [(
                        RECIPE_OPCODE["A64_ASIMD_NARROW_ARRANGEMENT"],
                        mode,
                    )]
            # A32 register-offset load/store carries the shift kind in
            # stype[6:5] and amount in imm5[11:7]. Zero uses the same
            # architectural special cases as A32 data-processing shifts.
            if (rule_id == "shift_option_choice"
                    and bindings.get("stype") == (5, 2)
                    and bindings.get("imm5") == (7, 5)
                    and (source.get("_meta") or {}).get(
                        "encoded_in", {}).get("<shift>") == [
                            {"_type": "AST.Identifier", "value": "stype"}
                        ]):
                return [(RECIPE_OPCODE["A32_LDST_REG_SHIFT"], 0)]
            # Thumb-2 data-processing shifts concatenate imm3:imm2 into a
            # five-bit amount.  Zero means no LSL, LSR/ASR #32, or RRX,
            # depending on stype.  Grammar branch order has no encoding.
            if (rule_id in {
                    "shift_option_imm3_imm2_choice",
                    "shift_option_imm3_imm2_choice__2",
                    "shift_option_imm3_imm2_choice__3",
                    "shift_option_imm3_imm2_choice__4",
                }
                    and bindings.get("stype") == (4, 2)
                    and bindings.get("imm2") == (6, 2)
                    and bindings.get("imm3") == (12, 3)
                    and (source.get("_meta") or {}).get(
                        "encoded_in", {}).get("<shift>") == [
                            {"_type": "AST.Identifier", "value": "stype"}
                        ]
                    and (source.get("_meta") or {}).get(
                        "encoded_in", {}).get("<amount>") == [
                            {"_type": "AST.Identifier", "value": "imm3"},
                            {"_type": "AST.Identifier", "value": "imm2"},
                        ]):
                return [(RECIPE_OPCODE["T32_MODIFIED_REG_SHIFT"], 0)]
            if (rule_id == "cond_option__2"
                    and rule.get("display") == "<invcond>"
                    and source.get("name") in {
                        "CSET", "CINC", "CSETM", "CINV", "CNEG"
                    }
                    and source.get("operation_id") in {
                        "CSET_CSINC", "CINC_CSINC", "CSETM_CSINV",
                        "CINV_CSINV", "CNEG_CSNEG",
                    }
                    and bindings.get("cond") == (12, 4)
                    and (source.get("_meta") or {}).get(
                        "encoded_in", {}).get("<invcond>") == [
                            {"_type": "AST.Identifier", "value": "cond"}
                        ]):
                # Conditional-select aliases invert the encoded condition.
                # Their source grammar names each inverse explicitly, but
                # carries no disassemble selection mapping.
                return [(RECIPE_OPCODE["A64_INVCOND"], 0)]
            # Register-offset load/store encodings select Wm for UXTW/SXTW
            # (option 010/110) and Xm for LSL/SXTX (011/111).  The encoded
            # option low bit is the width selector; the Choice order is not.
            if (rule_id == "WorX_choice"
                    and str(source.get("name", "")).endswith(
                        "_ldst_regoff")
                    and bindings.get("Rm") == (16, 5)
                    and bindings.get("option") == (13, 3)
                    and all((source.get("_meta") or {}).get(
                        "encoded_in", {}).get(name) == [
                            {"_type": "AST.Identifier", "value": "Rm"}
                        ] for name in ("<Wm>", "<Xm>"))):
                return [(RECIPE_OPCODE["A64_REGOFF_WORX"], 0)]
            # SVE prefetch operations use an exact four-bit field. Arm ACLE
            # assigns named spellings to 0..5 and 8..13; the remaining
            # encodings retain their numeric assembly spelling. Do not use
            # the order of the grammar's sparse Choice branches.
            if (rule_id == "prfop"
                    and rule.get("display") == "<prfop>"
                    and bindings.get("prfop") == (0, 4)
                    and (source.get("_meta") or {}).get(
                        "encoded_in", {}).get("<prfop>") == [
                            {"_type": "AST.Identifier", "value": "prfop"}
                        ]):
                return [(RECIPE_OPCODE["A64_SVE_PRFOP"], 0)]
            # AdvSIMD immediate shifts encode the element width in the
            # highest set bit of L:imm6, not in Choice branch order. This
            # rule is admitted only for the exact seven-bit source field.
            if (rule_id == "size_option__4"
                    and rule.get("display") == "<size>"
                    and bindings.get("L") == (7, 1)
                    and bindings.get("imm6") == (16, 6)
                    and (source.get("_meta") or {}).get(
                        "encoded_in", {}).get("<size>") == [
                            {"_type": "AST.Identifier", "value": "L"},
                            {"_type": "AST.Identifier", "value": "imm6"},
                        ]):
                return [(RECIPE_OPCODE["A32_NEON_SHIFT_ELEMENT_SIZE"], 0)]
            # The optional SVE count pattern and multiplier have two direct
            # encoded fields. The architectural defaults are ALL (31) and
            # MUL #1 (imm4=0); named and numeric pattern encodings are
            # selected at render time. The source's two optional grammar
            # branches are not an ordered encoding table.
            if (rule_id == "optional_pattern"
                    and bindings.get("pattern") == (5, 5)
                    and bindings.get("imm4") == (16, 4)
                    and (source.get("_meta") or {}).get(
                        "encoded_in", {}).get("<pattern>")
                        == [{"_type": "AST.Identifier", "value": "pattern"}]
                    and (source.get("_meta") or {}).get(
                        "encoded_in", {}).get("<imm>")
                        == [{"_type": "AST.Identifier", "value": "imm4"}]):
                return [(RECIPE_OPCODE["A64_SVE_PATTERN"], 0)]
            # OPT_SPACE is an assembler-permissive separator: the grammar
            # accepts adjacency, while architectural disassembly emits the
            # canonical single space.  Selecting the visible branch is
            # therefore independent of any encoded value.
            if rule_id == "OPT_SPACE":
                return [(RECIPE_OPCODE["TEXT"], text.id(" "))]
            # AdvSIMD element size is the position of the lowest set bit of
            # imm5, not the ordinal of these sparse grammar alternatives.
            # Keep the source forms and raw operand bindings exact: the same
            # rule identifiers occur in encodings with different legality.
            simd_name = str(source.get("name", ""))
            simd_operation = str(source.get("operation_id", ""))
            simd_encoded = (source.get("_meta") or {}).get("encoded_in", {})
            if (bindings.get("imm5") == (16, 5)
                    and rule_id == "V_option__3"
                    and rule.get("display") == "<V>"
                    and (simd_name, simd_operation) in {
                        ("DUP_asisdone_only", "DUP_advsimd_elt"),
                        ("MOV", "MOV_DUP_advsimd_elt"),
                    }
                    and simd_encoded.get("<V>") == [
                        {"_type": "AST.Identifier", "value": "imm5"}
                    ]):
                return [(RECIPE_OPCODE["A64_ASIMD_IMM5_SIZE"], 1)]
            if (bindings.get("imm5") == (16, 5)
                    and rule_id == "T_option__12"
                    and rule.get("display") == "<T>"
                    and (simd_name, simd_operation) in {
                        ("DUP_asisdone_only", "DUP_advsimd_elt"),
                        ("MOV", "MOV_DUP_advsimd_elt"),
                    }
                    and simd_encoded.get("<T>") == [
                        {"_type": "AST.Identifier", "value": "imm5"}
                    ]):
                return [(RECIPE_OPCODE["A64_ASIMD_IMM5_SIZE"], 1)]
            if (bindings.get("imm5") == (16, 5)
                    and bindings.get("Q") == (30, 1)
                    and rule_id == "T_option__5"
                    and rule.get("display") == "<T>"
                    and simd_name in {"DUP_asimdins_DV_v", "DUP_asimdins_DR_r"}
                    and simd_operation in {"DUP_advsimd_elt", "DUP_advsimd_gen"}
                    and simd_encoded.get("<T>") == [
                        {"_type": "AST.Identifier", "value": "imm5"},
                        {"_type": "AST.Identifier", "value": "Q"},
                    ]):
                return [(RECIPE_OPCODE["A64_ASIMD_IMM5_SIZE"], 0)]
            if (bindings.get("imm5") == (16, 5)
                    and rule_id == "Ts_option"
                    and rule.get("display") == "<Ts>"
                    and simd_name == "DUP_asimdins_DV_v"
                    and simd_operation == "DUP_advsimd_elt"
                    and simd_encoded.get("<Ts>") == [
                        {"_type": "AST.Identifier", "value": "imm5"}
                    ]):
                return [(RECIPE_OPCODE["A64_ASIMD_IMM5_SIZE"], 1)]
            if (bindings.get("imm5") == (16, 5)
                    and rule_id == "R_option__3"
                    and rule.get("display") == "<R>"
                    and simd_name == "DUP_asimdins_DR_r"
                    and simd_operation == "DUP_advsimd_gen"
                    and simd_encoded.get("<R>") == [
                        {"_type": "AST.Identifier", "value": "imm5"}
                    ]):
                return [(RECIPE_OPCODE["A64_ASIMD_INS_R"], 0)]
            if (bindings.get("Rn") == (5, 5)
                    and rule_id == "Rn_option__2"
                    and rule.get("display") == "<n>"
                    and simd_name == "DUP_asimdins_DR_r"
                    and simd_operation == "DUP_advsimd_gen"
                    and simd_encoded.get("<n>") == [
                        {"_type": "AST.Identifier", "value": "Rn"}
                    ]):
                return [(RECIPE_OPCODE["A64_ASIMD_INS_RN"], 0)]
            if (bindings.get("imm5") == (16, 5)
                    and rule_id in {"Ts_option__2", "Ts_option__3"}
                    and rule.get("display") == "<Ts>"
                    and simd_name in {
                        "SMOV_asimdins_W_w", "UMOV_asimdins_W_w",
                        "SMOV_asimdins_X_x",
                    }
                    and simd_operation in {"SMOV_advsimd", "UMOV_advsimd"}
                    and simd_encoded.get("<Ts>") == [
                        {"_type": "AST.Identifier", "value": "imm5"}
                    ]):
                return [(RECIPE_OPCODE["A64_ASIMD_IMM5_SIZE"],
                         2 if rule_id == "Ts_option__2" else 3)]
            if (rule_id == "amount_option__12"
                    and rule.get("display") == "<amount>"
                    and simd_name in {"MOVI_asimdimm_M_sm", "MVNI_asimdimm_M_sm"}
                    and simd_operation in {"MOVI_advsimd", "MVNI_advsimd"}
                    and bindings.get("cmode") == (12, 4)
                    and simd_encoded.get("<amount>") == [
                        {"_type": "AST.Identifier", "value": "cmode"}
                    ]
                    and any(
                        field.get("name") == "cmode"
                        and (field.get("value") or {}).get("value") == "'110x'"
                        for field in (source.get("encoding") or {}).get("values", [])
                    )):
                return [(RECIPE_OPCODE["A64_ASIMD_MSL_AMOUNT"], 0)]
            # A32 condition suffixes are architecturally selected by the
            # encoded four-bit condition field.  The outer cond_choice omits
            # the AL spelling; the inner c__* grammar is also used where the
            # spelling is mandatory.
            if rule_id.startswith("cond_choice"):
                expressions = encoded.get("<c>", [])
                if len(expressions) == 1:
                    return [(RECIPE_OPCODE["COND_SUFFIX"], expressions[0])]
            if rule.get("display") == "<c>" and rule_id.startswith("c__"):
                if value is not None:
                    return [(RECIPE_OPCODE["COND"], value)]
            if rule.get("display") == "+/-" and value is not None:
                return [(RECIPE_OPCODE["MINUS_IF_ZERO"], value)]
            # These A32/T32 AdvSIMD bitwise operations act on a whole D/Q
            # register and do not encode an element datatype.  The grammar
            # optionally permits a .<dt> suffix, but its datatype is not
            # present in encoded_in and cannot be reconstructed from bytes.
            # Canonical disassembly therefore uses the untyped spelling.
            # Keep the exception narrow: typed arithmetic and conversions
            # must not silently lose their suffix.
            if (rule_id == "dot_dt_choice__2"
                    and "<dt>" not in encoded
                    and str(source.get("name", "")).split("_", 1)[0]
                        in {"VAND", "VBIC", "VORR", "VORN", "VEOR",
                            "VBSL", "VBIT", "VBIF", "VSWP", "VMVN"}):
                return []
            choices: list[tuple[tuple[int, int | tuple[tuple[int, int, int], ...]], ...]] = []
            for choice in rule.get("choices", []):
                try:
                    choices.append(tuple(assembly_ops(
                        choice, value, nested_stack,
                        semantic_label=nested_semantic_label,
                    )))
                except OpaqueRecipe as error:
                    raise OpaqueRecipe(
                        f"choice_selection_missing:{rule_id}:{error}"
                    ) from None
            if choices and all(choice == choices[0] for choice in choices):
                return list(choices[0])
            # VLD4 all-lanes assigns both size=10 and size=11 the .32
            # spelling; size=11 is its special mandatory 128-bit-alignment
            # encoding.  The generic fixed-selector parser cannot represent
            # the source's `size_1x_32` wildcard, so emit the exact four-row
            # map only for this reviewed source family.
            if (rule_id == "size_option__2"
                    and re.fullmatch(
                        r"VLD4_a_[AT]1_(?:nowb|posti|postr)",
                        str(source.get("name", "")))
                    and bindings.get("size") == (6, 2)
                    and isinstance(value, tuple)
                    and direct_program_width(value) == 2
                    and len(choices) == 3
                    and [
                        (choice[0][0], text.ordered[int(choice[0][1])])
                        if len(choice) == 1
                            and choice[0][0] == RECIPE_OPCODE["TEXT"]
                        else None for choice in choices
                    ] == [
                        (RECIPE_OPCODE["TEXT"], "8"),
                        (RECIPE_OPCODE["TEXT"], "16"),
                        (RECIPE_OPCODE["TEXT"], "32"),
                    ]):
                first_case = len(selection_cases)
                for selector, choice_index in enumerate((0, 1, 2, 2)):
                    first_text = len(selection_text_ids)
                    selection_text_ids.append(int(choices[choice_index][0][1]))
                    selection_cases.append((selector, first_text, 1))
                selections.append({
                    "program_raw": value,
                    "first_case": first_case,
                    "case_count": 4,
                    "sparse": False,
                })
                return [(RECIPE_OPCODE["SELECT"], len(selections) - 1)]
            # An optional trailing X register is omitted exactly for encoded
            # register 31 and otherwise consists of a separator plus the
            # ordinary X-register spelling.  The nested REG31 record already
            # owns the exact selector expression, so reuse it rather than
            # guessing from a rule name.
            empty_choice = any(not choice for choice in choices)
            optional_register_choice = next((
                choice for choice in choices
                if len(choice) == 2
                and choice[0][0] == RECIPE_OPCODE["TEXT"]
                and choice[1][0] == RECIPE_OPCODE["REG31"]
            ), None)
            if empty_choice and optional_register_choice is not None:
                separator_text_id = int(optional_register_choice[0][1])
                special_index = int(optional_register_choice[1][1])
                if (special_index < len(special_registers)
                        and separator_text_id <= 0xffff
                        and special_index <= 0xffff):
                    special_record = special_registers[special_index]
                    special_spelling = text.ordered[
                        special_record["special_text_id"]
                    ]
                    prefix_spelling = text.ordered[
                        special_record["prefix_text_id"]
                    ]
                    if special_spelling == "XZR" \
                            and prefix_spelling == "X":
                        return [(
                            RECIPE_OPCODE["OPTIONAL_REG31"],
                            (special_index << 16) | separator_text_id,
                        )]
            if rule_id == "SYSP_optional_xt1_xt2" and empty_choice:
                first_register = encoded.get("<Xt1>", [])
                second_register = encoded.get("<Xt2>", [])
                if (len(first_register) == 1
                        and first_register == second_register
                        and direct_program_width(first_register[0]) == 5):
                    return [(
                        RECIPE_OPCODE["OPTIONAL_GPR_PAIR31"],
                        first_register[0],
                    )]
            # When the grammar permits omitting one value-bearing operand,
            # always render its explicit branch.  It is valid for every
            # encoding admitted by that grammar, preserves information, and
            # does not depend on a shortest-spelling preference that the
            # public source intentionally omits.  Pure punctuation/suffix
            # options remain handled by the canonical-omission rule below.
            nonempty_choices = [choice for choice in choices if choice]
            if (empty_choice
                    and len(nonempty_choices) == 1
                    and any(
                        opcode != RECIPE_OPCODE["TEXT"]
                        for opcode, _value in nonempty_choices[0]
                    )):
                return list(nonempty_choices[0])
            # A syntactically optional fixed token carries no information.  A
            # canonical formatter omits it, except for the conventional '#'
            # immediate introducer.  Dynamic alternatives are never folded.
            if rule_id in {"hash", "opt_hash"}:
                return [(RECIPE_OPCODE["TEXT"], text.id("#"))]
            if (
                rule.get("display") is None
                and choices
                and any(not choice for choice in choices)
                and all(
                all(opcode == RECIPE_OPCODE["TEXT"] for opcode, _value in choice)
                for choice in choices
                )
            ):
                return []
            # A64 register-31 choices are fully defined by the architecture:
            # one branch is SP/WSP/XZR/WZR, the other is prefix+UInteger.
            # Recognize that exact grammar shape instead of relying on branch
            # order or an absent Rule.disassemble mapping.
            special: tuple[int, str] | None = None
            normal: tuple[tuple[tuple[int, int, int], ...], str] | None = None
            for choice in choices:
                if len(choice) == 1 and choice[0][0] == RECIPE_OPCODE["TEXT"]:
                    spelling = text.ordered[int(choice[0][1])]
                    if spelling in {"PC", "SP", "WSP", "XZR", "WZR"}:
                        special = (int(choice[0][1]), spelling)
                elif (
                    len(choice) == 2
                    and choice[0][0] == RECIPE_OPCODE["TEXT"]
                    and choice[1][0] == RECIPE_OPCODE["UINT"]
                    and isinstance(choice[1][1], tuple)
                ):
                    prefix = text.ordered[int(choice[0][1])]
                    if prefix in {"R", "W", "X"}:
                        normal = (choice[1][1], prefix)
            if special is not None and normal is not None:
                special_registers.append(
                    {
                        "program_raw": normal[0],
                        "special_text_id": special[0],
                        "prefix_text_id": text.id(normal[1]),
                    }
                )
                return [
                    (RECIPE_OPCODE["REG31"], len(special_registers) - 1)
                ]
            # Exhaustive fixed-spelling enums map the encoded value to the
            # equally ordered Choice branch.  Restrict this to a direct raw
            # expression and an exact power-of-two branch count; partial enums
            # and any branch containing another dynamic value remain opaque.
            width = direct_program_width(value) if value is not None else None
            keyed_choices: list[
                tuple[int, tuple[tuple[int, int | tuple[tuple[int, int, int], ...]], ...]]
            ] = []
            if (
                width is not None
                and all(
                    all(opcode == RECIPE_OPCODE["TEXT"] for opcode, _item in choice)
                    for choice in choices
                )
            ):
                for source_choice, compiled_choice in zip(
                    rule.get("choices", []), choices
                ):
                    selector = sve_size_choice_selector(
                        rule_id, source_choice, rules, source, bindings
                    ) if rule.get("display") == "<T>" and width == 2 else None
                    # Several SVE element-type grammars use the same raw
                    # size[23:22] selector as <T>, but call it <Tb> or give
                    # the <T> choice an instruction-specific rule name.  A
                    # branch is eligible only when its referenced rule is an
                    # unconditional, single-letter element-size literal.
                    # In particular, do not infer an ordering from the
                    # Choice branch list: sparse H/S/D and B/H/S choices
                    # deliberately omit one encoding.
                    if (selector is None and width == 2
                            and rule.get("display") in {"<T>", "<Tb>"}
                            and rule_id.startswith(("Tb__", "T__", "T_fmul_"))
                            and bindings.get("size") == (22, 2)
                            and (source.get("_meta") or {}).get(
                                "encoded_in", {}).get(rule.get("display"))
                                == [{"_type": "AST.Identifier", "value": "size"}]):
                        source_symbols = (source_choice or {}).get(
                            "symbols", []) or []
                        if (len(source_symbols) == 1
                                and source_symbols[0].get("_type")
                                    == "Instruction.Symbols.RuleReference"):
                            branch = rules.get(str(source_symbols[0].get(
                                "rule_id", "")), {})
                            branch_symbols = (branch.get("symbols") or {}).get(
                                "symbols", []) or []
                            if (branch.get("_type")
                                    == "Instruction.Rules.Rule"
                                    and branch.get("condition")
                                        == {"_type": "AST.Bool", "value": True}
                                    and len(branch_symbols) == 1
                                    and branch_symbols[0].get("_type")
                                        == "Instruction.Symbols.Literal"):
                                selector = {"B": 0, "H": 1,
                                            "S": 2, "D": 3}.get(
                                    branch_symbols[0].get("value"))
                    if selector is None:
                        selector = fixed_choice_selector(
                            rule_id, source_choice, width
                        )
                    if selector is None:
                        keyed_choices = []
                        break
                    keyed_choices.append((selector, compiled_choice))
            if (keyed_choices
                    and len(keyed_choices) == len(choices)
                    and len({selector for selector, _choice in keyed_choices})
                        == len(keyed_choices)):
                first_case = len(selection_cases)
                for selector, choice in sorted(keyed_choices):
                    first_text = len(selection_text_ids)
                    selection_text_ids.extend(
                        int(item) for _opcode, item in choice
                    )
                    selection_cases.append(
                        (selector, first_text,
                         len(selection_text_ids) - first_text)
                    )
                selections.append(
                    {
                        "program_raw": value,
                        "first_case": first_case,
                        "case_count": len(keyed_choices),
                        "sparse": True,
                    }
                )
                return [(RECIPE_OPCODE["SELECT"], len(selections) - 1)]
            if (
                width is not None
                and width < 31
                and len(choices) == (1 << width)
                and all(
                    all(opcode == RECIPE_OPCODE["TEXT"] for opcode, _item in choice)
                    for choice in choices
                )
            ):
                first_case = len(selection_cases)
                for selector, choice in enumerate(choices):
                    first_text = len(selection_text_ids)
                    selection_text_ids.extend(int(item) for _opcode, item in choice)
                    selection_cases.append(
                        (selector, first_text,
                         len(selection_text_ids) - first_text)
                    )
                selections.append(
                    {
                        "program_raw": value,
                        "first_case": first_case,
                        "case_count": len(choices),
                        "sparse": False,
                    }
                )
                return [(RECIPE_OPCODE["SELECT"], len(selections) - 1)]
            raise OpaqueRecipe(f"choice_selection_missing:{rule_id}")
        raise OpaqueRecipe("rule_kind_unknown")

    return assembly_ops(source.get("assembly"), None, stack, top_level=True)


def c_u8(value: int) -> str:
    return f"UINT8_C({value})"


def c_u16(value: int) -> str:
    return f"UINT16_C({value})"


def c_u32(value: int) -> str:
    return f"UINT32_C({value})"


def emit_array(lines: list[str], declaration: str, rows: Iterable[str]) -> None:
    lines.append(declaration + " = {")
    lines.extend(f"    {row}," for row in rows)
    lines.extend(["};", ""])


def finish_programs(
    raw_programs: list[tuple[tuple[int, int, int], ...]],
) -> tuple[
    dict[tuple[tuple[int, int, int], ...], int],
    list[tuple[int, int]],
    list[tuple[int, int, int]],
]:
    unique = sorted(set(raw_programs))
    ids = {program: index for index, program in enumerate(unique)}
    bytecode: list[tuple[int, int, int]] = []
    records: list[tuple[int, int]] = []
    for program in unique:
        first = len(bytecode)
        bytecode.extend(program)
        records.append((first, len(program)))
    return ids, records, bytecode


def render_numeric_include(
    builder: CatalogBuilder,
    rule_conditions: list[tuple[tuple[int, int, int], ...] | None],
    forms: list[dict[str, Any]],
    aliases: list[dict[str, Any]],
    requirement_feature_ids: list[int],
    program_ids: dict[tuple[tuple[int, int, int], ...], int],
    program_records: list[tuple[int, int]],
    bytecode: list[tuple[int, int, int]],
) -> str:
    lines = [
        "/* Generated numeric-only ARM assembly grammar. Do not edit. */",
        "/* Contains no runtime strings. */",
        "#ifndef CDISASM_ARM_ASSEMBLY_DECODE_GENERATED_INC",
        "#define CDISASM_ARM_ASSEMBLY_DECODE_GENERATED_INC",
        "#include <stdint.h>",
        "#if USE_EXTRA_OPCODES",
        f"#define CDISASM_ARM_ASMGEN_RULE_COUNT {c_u32(len(builder.rule_records))}",
        f"#define CDISASM_ARM_ASMGEN_ASSEMBLY_COUNT {c_u32(len(builder.assemblies))}",
        f"#define CDISASM_ARM_ASMGEN_SYMBOL_COUNT {c_u32(len(builder.symbols))}",
        f"#define CDISASM_ARM_ASMGEN_FORM_COUNT {c_u32(len(forms))}",
        f"#define CDISASM_ARM_ASMGEN_ALIAS_COUNT {c_u32(len(aliases))}",
        f"#define CDISASM_ARM_ASMGEN_PROGRAM_COUNT {c_u32(len(program_records))}",
        f"#define CDISASM_ARM_ASMGEN_RECIPE_OP_COUNT {c_u32(len(builder.recipe_ops_raw))}",
        "#define CDISASM_ARM_ASMGEN_NONE UINT32_C(4294967295)",
        "enum cdisasm_arm_asmgen_rule_kind { CDISASM_ARM_ASMGEN_RULE = 0, CDISASM_ARM_ASMGEN_CHOICE = 1, CDISASM_ARM_ASMGEN_TOKEN = 2 };",
        "enum cdisasm_arm_asmgen_symbol_kind { CDISASM_ARM_ASMGEN_LITERAL = 0, CDISASM_ARM_ASMGEN_RULE_REFERENCE = 1 };",
        "enum cdisasm_arm_asmgen_recipe_opcode {",
        *(
            f"    CDISASM_ARM_ASMGEN_{name} = {number},"
            for name, number in sorted(
                RECIPE_OPCODE.items(), key=lambda item: item[1]
            )
        ),
        "};",
        "typedef struct cdisasm_arm_asmgen_rule_record { uint32_t assembly_id, first_choice, display_text_id, default_text_id, condition_program_id; uint16_t choice_count; uint8_t kind, reserved; } cdisasm_arm_asmgen_rule_record;",
        "typedef struct cdisasm_arm_asmgen_span { uint32_t first; uint16_t count, reserved; } cdisasm_arm_asmgen_span;",
        "typedef struct cdisasm_arm_asmgen_symbol { uint32_t value; uint8_t kind, reserved[3]; } cdisasm_arm_asmgen_symbol;",
        "typedef struct cdisasm_arm_asmgen_bc { int32_t a, b; uint8_t opcode, reserved[3]; } cdisasm_arm_asmgen_bc;",
        "typedef struct cdisasm_arm_asmgen_recipe_op { uint32_t value; uint8_t opcode, reserved[3]; } cdisasm_arm_asmgen_recipe_op;",
        "typedef struct cdisasm_arm_asmgen_special_register { uint32_t program_id, special_text_id, prefix_text_id; } cdisasm_arm_asmgen_special_register;",
        "typedef struct cdisasm_arm_asmgen_selection { uint32_t program_id, first_case; uint16_t case_count, reserved; } cdisasm_arm_asmgen_selection;",
        "typedef struct cdisasm_arm_asmgen_selection_case { uint32_t selector, first; uint16_t count, reserved; } cdisasm_arm_asmgen_selection_case;",
        "typedef struct cdisasm_arm_asmgen_form { uint32_t assembly_id, first_binding, recipe_first, requirement_first; uint16_t binding_count, recipe_count, requirement_count, public_name_id; uint8_t render_status, minimum_arch_bit; uint16_t reserved; } cdisasm_arm_asmgen_form;",
        "typedef struct cdisasm_arm_asmgen_alias { uint32_t leaf_index, assembly_id, first_binding, recipe_first, condition_program_id, preferred_program_id; uint16_t binding_count, recipe_count, public_name_id; uint8_t render_status; uint8_t reserved; } cdisasm_arm_asmgen_alias;",
        "typedef struct cdisasm_arm_asmgen_binding { uint32_t display_text_id, program_id; } cdisasm_arm_asmgen_binding;",
        "",
    ]
    for record, condition in zip(builder.rule_records, rule_conditions):
        record["condition_program_id"] = NONE if condition is None else program_ids[condition]
    emit_array(
        lines,
        f"static const cdisasm_arm_asmgen_rule_record cdisasm_arm_asmgen_rules[{len(builder.rule_records)}]",
        (
            "{" + ", ".join(
                [
                    c_u32(record["assembly_id"]), c_u32(record["first_choice"]),
                    c_u32(record["display_text_id"]), c_u32(record["default_text_id"]),
                    c_u32(record["condition_program_id"]), c_u16(record["choice_count"]),
                    c_u8(record["kind"]), c_u8(0),
                ]
            ) + "}"
            for record in builder.rule_records
        ),
    )
    emit_array(
        lines,
        f"static const cdisasm_arm_asmgen_selection cdisasm_arm_asmgen_selections[{len(builder.selections)}]",
        (
            "{" + ", ".join([
                c_u32(record["program_id"]), c_u32(record["first_case"]),
                c_u16(record["case_count"]), c_u16(0),
            ]) + "}"
            for record in builder.selections
        ),
    )
    emit_array(
        lines,
        f"static const cdisasm_arm_asmgen_selection_case cdisasm_arm_asmgen_selection_cases[{len(builder.selection_cases)}]",
        (
            "{" + c_u32(selector) + ", " + c_u32(first) + ", "
                + c_u16(count) + ", " + c_u16(0) + "}"
            for selector, first, count in builder.selection_cases
        ),
    )
    emit_array(
        lines,
        f"static const uint32_t cdisasm_arm_asmgen_selection_text_ids[{len(builder.selection_text_ids)}]",
        (c_u32(value) for value in builder.selection_text_ids),
    )
    emit_array(lines, f"static const uint32_t cdisasm_arm_asmgen_choices[{len(builder.choice_assemblies)}]", (c_u32(v) for v in builder.choice_assemblies))
    emit_array(lines, f"static const cdisasm_arm_asmgen_span cdisasm_arm_asmgen_assemblies[{len(builder.assemblies)}]", ("{" + c_u32(a) + ", " + c_u16(b) + ", " + c_u16(0) + "}" for a, b in builder.assemblies))
    emit_array(lines, f"static const cdisasm_arm_asmgen_symbol cdisasm_arm_asmgen_symbols[{len(builder.symbols)}]", ("{" + c_u32(value) + ", " + c_u8(kind) + ", {0, 0, 0}}" for kind, value in builder.symbols))
    emit_array(lines, f"static const cdisasm_arm_asmgen_span cdisasm_arm_asmgen_programs[{len(program_records)}]", ("{" + c_u32(first) + ", " + c_u16(count) + ", " + c_u16(0) + "}" for first, count in program_records))
    emit_array(lines, f"static const cdisasm_arm_asmgen_bc cdisasm_arm_asmgen_bytecode[{len(bytecode)}]", ("{" + f"INT32_C({a}), INT32_C({b}), " + c_u8(opcode) + ", {0, 0, 0}}" for opcode, a, b in bytecode))
    emit_array(lines, f"static const cdisasm_arm_asmgen_binding cdisasm_arm_asmgen_bindings[{len(builder.form_bindings)}]", ("{" + c_u32(display) + ", " + c_u32(program) + "}" for display, program, _unused in builder.form_bindings))
    emit_array(lines, f"static const cdisasm_arm_asmgen_recipe_op cdisasm_arm_asmgen_recipe_ops[{len(builder.recipe_ops_raw)}]", ("{" + c_u32(int(value)) + ", " + c_u8(opcode) + ", {0, 0, 0}}" for opcode, value in builder.recipe_ops_raw))
    emit_array(
        lines,
        f"static const cdisasm_arm_asmgen_special_register cdisasm_arm_asmgen_special_registers[{len(builder.special_registers)}]",
        (
            "{" + ", ".join([
                c_u32(record["program_id"]),
                c_u32(record["special_text_id"]),
                c_u32(record["prefix_text_id"]),
            ]) + "}"
            for record in builder.special_registers
        ),
    )
    emit_array(
        lines,
        f"static const cdisasm_arm_asmgen_form cdisasm_arm_asmgen_forms[{len(forms)}]",
        (
            "{" + ", ".join([
                c_u32(record["assembly_id"]), c_u32(record["first_binding"]), c_u32(record["recipe_first"]), c_u32(record["requirement_first"]),
                c_u16(record["binding_count"]), c_u16(record["recipe_count"]), c_u16(record["requirement_count"]), c_u16(record["public_name_id"]),
                c_u8(record["render_status"]), c_u8(record["minimum_arch_bit"]), c_u16(0),
            ]) + "}"
            for record in forms
        ),
    )
    emit_array(
        lines,
        f"static const cdisasm_arm_asmgen_alias cdisasm_arm_asmgen_aliases[{len(aliases)}]",
        (
            "{" + ", ".join([
                c_u32(record["leaf_index"]), c_u32(record["assembly_id"]), c_u32(record["first_binding"]), c_u32(record["recipe_first"]),
                c_u32(record["condition_program_id"]), c_u32(record["preferred_program_id"]),
                c_u16(record["binding_count"]), c_u16(record["recipe_count"]), c_u16(record["public_name_id"]),
                c_u8(record["render_status"]), c_u8(0),
            ]) + "}"
            for record in aliases
        ),
    )
    emit_array(lines, f"static const uint16_t cdisasm_arm_asmgen_requirement_feature_ids[{len(requirement_feature_ids)}]", (c_u16(value) for value in requirement_feature_ids))
    lines.extend(["#endif", "#endif", ""])
    return "\n".join(lines)


def render_text_include(text: TextPool) -> str:
    offsets: list[int] = []
    data = bytearray()
    for value in text.ordered:
        offsets.append(len(data))
        data.extend(value.encode("utf-8"))
        data.append(0)
    lines = [
        "/* Generated formatter-only ARM assembly spelling pool. Do not edit. */",
        "#ifndef CDISASM_ARM_ASSEMBLY_FORMAT_GENERATED_INC",
        "#define CDISASM_ARM_ASSEMBLY_FORMAT_GENERATED_INC",
        "#include <stdint.h>",
        "#if USE_EXTRA_OPCODES",
    ]
    emit_array(lines, f"static const uint32_t cdisasm_arm_asmgen_text_offsets[{len(offsets)}]", (c_u32(value) for value in offsets))
    emit_array(
        lines,
        f"static const unsigned char cdisasm_arm_asmgen_text_data[{len(data)}]",
        (f"0x{value:02x}" for value in data),
    )
    lines.extend(["#endif", "#endif", ""])
    return "\n".join(lines)


def render_requirements_include(
    forms: list[dict[str, Any]], requirement_feature_ids: list[int]
) -> str:
    lines = [
        "/* Generated conservative per-leaf ARM requirements. Do not edit. */",
        "/* Numeric-only: feature IDs use the generated AARCHMRS namespace. */",
        "#ifndef CDISASM_ARM_LEAF_REQUIREMENTS_GENERATED_INC",
        "#define CDISASM_ARM_LEAF_REQUIREMENTS_GENERATED_INC",
        "#include <stdint.h>",
        "#if USE_EXTRA_OPCODES",
        f"#define CDISASM_ARM_REQGEN_FORM_COUNT {c_u32(len(forms))}",
        "typedef struct cdisasm_arm_reqgen_form { uint32_t first_feature; uint16_t feature_count; uint8_t minimum_arch_bit, reserved; } cdisasm_arm_reqgen_form;",
        "",
    ]
    emit_array(
        lines,
        f"static const cdisasm_arm_reqgen_form cdisasm_arm_reqgen_forms[{len(forms)}]",
        (
            "{" + ", ".join([
                c_u32(record["requirement_first"]),
                c_u16(record["requirement_count"]),
                c_u8(record["minimum_arch_bit"]),
                c_u8(0),
            ]) + "}"
            for record in forms
        ),
    )
    emit_array(
        lines,
        f"static const uint16_t cdisasm_arm_reqgen_feature_ids[{len(requirement_feature_ids)}]",
        (c_u16(value) for value in requirement_feature_ids),
    )
    lines.extend(["#endif", "#endif", ""])
    return "\n".join(lines)


def write_or_check(path: Path, content: str, check: bool) -> None:
    encoded = content.encode("ascii")
    if check:
        if not path.is_file() or path.read_bytes() != encoded:
            raise AssemblyError(f"generated file is stale: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded)


def write_tsv(path: Path, rows: list[dict[str, Any]], fields: list[str], check: bool) -> None:
    from io import StringIO

    stream = StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, dialect="excel-tab", lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    write_or_check(path, stream.getvalue(), check)


def self_test_sve_size_selector() -> None:
    """Check the fixed suffix projection and its exclusion boundaries."""
    rule = {"_type": "Instruction.Rules.Rule",
            "condition": {"_type": "AST.Bool", "value": True}}
    rules = {
        f"T_{spelling}": {
            **rule,
            "symbols": {"symbols": [{"_type": "Instruction.Symbols.Literal",
                                     "value": spelling}]},
        }
        for spelling in "BHSD"
    }
    source = {"_meta": {"encoded_in": {
        "<T>": [{"_type": "AST.Identifier", "value": "size"}]
    }}}
    choices = {
        spelling: {"symbols": [{"_type": "Instruction.Symbols.RuleReference",
                                "rule_id": f"T_{spelling}"}]}
        for spelling in "BHSD"
    }
    for selector, spelling in enumerate("BHSD"):
        choice = choices[spelling]
        if sve_size_choice_selector(
                "T__fixture", choice, rules, source, {"size": (22, 2)}) \
                != selector:
            raise AssemblyError(f"wrong SVE size selector for {spelling}")
        if sve_size_choice_selector(
                "T__fixture", choice, rules, source, {"size": (21, 2)}) \
                is not None:
            raise AssemblyError("nonstandard size field was accepted")
        if sve_size_choice_selector(
                "T__fixture", choice, rules, {"_meta": {"encoded_in": {
                    "<T>": [{"_type": "AST.Identifier", "value": "tsize"}]
                }}}, {"size": (22, 2)}) is not None:
            raise AssemblyError("transformed size field was accepted")
    print("SVE raw-size selector self-test passed: 4 values, 8 exclusions")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arm-root", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--decode-output", type=Path, default=REPO_ROOT / "src/arm/generated/cdisasm_arm_assembly_decode.inc")
    parser.add_argument("--format-output", type=Path, default=REPO_ROOT / "src/arm/generated/cdisasm_arm_assembly_format.inc")
    parser.add_argument("--requirements-decode-output", type=Path, default=REPO_ROOT / "src/arm/generated/cdisasm_arm_leaf_requirements.inc")
    parser.add_argument("--opaque-output", type=Path, default=SCRIPT_DIR / "generated/arm_assembly_opaque.tsv")
    parser.add_argument("--requirements-output", type=Path, default=SCRIPT_DIR / "generated/arm_leaf_requirements.tsv")
    parser.add_argument("--manifest-output", type=Path, default=SCRIPT_DIR / "generated/arm_assembly_manifest.json")
    args = parser.parse_args()

    opcode_ids = list(RECIPE_OPCODE.values())
    if len(opcode_ids) != len(set(opcode_ids)):
        raise AssemblyError("ARM formatter recipe opcode IDs must be unique")
    if any(opcode < 0 or opcode > 255 for opcode in opcode_ids):
        raise AssemblyError("ARM formatter recipe opcode ID exceeds uint8_t")

    if args.self_test:
        self_test_sve_size_selector()
        return 0
    if args.arm_root is None:
        parser.error("--arm-root is required unless --self-test is specified")

    document, source_path = load_source(args.arm_root.resolve())
    rules = document["assembly_rules"]
    nodes, leaves, tree_aliases, _roots = tree.make_tree(document)
    leaf_sources, alias_sources = collect_sources(document)
    if len(leaves) != 6569 or len(tree_aliases) != 611:
        raise AssemblyError("pinned leaf/alias count changed")
    if len(leaf_sources) != len(leaves) or len(alias_sources) != len(tree_aliases):
        raise AssemblyError("source/tree ordering mismatch")
    inventory = tree.ast_inventory(nodes, tree_aliases)
    pool_names = {
        "features": sorted(inventory["feature_counts"]),
        "symbols": sorted(inventory["symbol_counts"]),
        "values": sorted(inventory["value_counts"]),
        "functions": sorted(inventory["function_counts"]),
    }
    tree_feature_names = list(pool_names["features"])
    pool_names = extend_ast_pools(
        pool_names,
        [
            *(rule.get("condition") for rule in document["assembly_rules"].values()),
            *(source.get("condition") for source in alias_sources),
            *(source.get("preferred") for source in alias_sources),
            *(
                expression
                for source in [*leaf_sources, *alias_sources]
                for expressions in ((source.get("_meta") or {}).get("encoded_in") or {}).values()
                for expression in expressions
            ),
        ],
    )
    public_ids = load_public_name_ids(SCRIPT_DIR / "generated/arm_mnemonic_ids.tsv")
    text = collect_text(rules, leaf_sources, alias_sources)
    builder = CatalogBuilder(rules, text, **{f"{key[:-1] if key.endswith('s') else key}_names": value for key, value in pool_names.items()})
    rule_conditions = builder.build_rules()

    form_records: list[dict[str, Any]] = []
    alias_records: list[dict[str, Any]] = []
    opaque_rows: list[dict[str, Any]] = []
    requirement_rows: list[dict[str, Any]] = []
    requirement_feature_ids: list[int] = []
    recipe_program_positions: list[tuple[int, int]] = []

    def add_recipe(
        source: dict[str, Any],
        bindings: dict[str, tuple[int, int]],
        compiled: dict[str, list[tuple[tuple[int, int, int], ...]]],
        has_semantic_branch_target: bool,
    ) -> tuple[int, int, int, str]:
        first = len(builder.recipe_ops_raw)
        before_special_registers = len(builder.special_registers)
        before_selections = len(builder.selections)
        before_selection_cases = len(builder.selection_cases)
        before_selection_text_ids = len(builder.selection_text_ids)
        try:
            ops = compile_recipe(
                source, rules, bindings, compiled, text,
                builder.special_registers,
                builder.selections,
                builder.selection_cases,
                builder.selection_text_ids,
                has_semantic_branch_target,
            )
            for record in builder.special_registers[before_special_registers:]:
                builder.programs_raw.append(record["program_raw"])
            for record in builder.selections[before_selections:]:
                builder.programs_raw.append(record["program_raw"])
            for opcode, value in ops:
                if isinstance(value, tuple):
                    builder.programs_raw.append(value)
                    recipe_program_positions.append((len(builder.recipe_ops_raw), 0))
                    builder.recipe_ops_raw.append((opcode, value))
                else:
                    builder.recipe_ops_raw.append((opcode, value))
            return first, len(ops), RENDER_STATUS["DIRECT"], ""
        except OpaqueRecipe as error:
            del builder.special_registers[before_special_registers:]
            del builder.selections[before_selections:]
            del builder.selection_cases[before_selection_cases:]
            del builder.selection_text_ids[before_selection_text_ids:]
            return first, 0, RENDER_STATUS["OPAQUE"], str(error)

    # Leaf requirements use the exact generated-decode feature namespace.  Any
    # assembly-grammar-only feature is intentionally not a leaf requirement.
    feature_ids = {name: index for index, name in enumerate(tree_feature_names)}
    for leaf_index, (leaf, source) in enumerate(zip(leaves, leaf_sources)):
        node = nodes[leaf["node_index"]]
        binding_first, binding_count, compiled = builder.add_encoded_bindings(source, node["bindings"])
        assembly_id = builder.add_assembly(source.get("assembly"))
        mnemonic = tree.first_literal(source).lower()
        recipe_first, recipe_count, status, reason = add_recipe(
            source, node["bindings"], compiled,
            has_semantic_branch_target(leaf["source_form_id"]),
        )
        if mnemonic not in public_ids:
            raise AssemblyError(f"missing public name ID for {mnemonic!r}")
        required: set[str] = set()
        node_index = leaf["node_index"]
        while node_index != NONE:
            required.update(ast_features(nodes[node_index].get("condition_ast")))
            required.update(ast_features(nodes[node_index].get("assertions_ast")))
            node_index = nodes[node_index]["parent"]
        first_requirement = len(requirement_feature_ids)
        sorted_required = sorted(required, key=lambda value: value.encode("utf-8"))
        requirement_feature_ids.extend(feature_ids[name] for name in sorted_required)
        # Every A64 encoding is at least Armv8-A, and later A64 allocations in
        # this source carry FEAT_* path predicates.  The machine-readable file
        # does not state a minimum architecture for unconditional A32/T32
        # leaves, so UINT8_MAX deliberately keeps those leaves CPU_ANY-only
        # until an authoritative per-leaf version source is joined.
        minimum_arch_bit = 4 if node["instruction_set_name"] == "A64" else 255
        form_records.append(
            {
                "assembly_id": assembly_id,
                "first_binding": binding_first,
                "binding_count": binding_count,
                "recipe_first": recipe_first,
                "recipe_count": recipe_count,
                "render_status": status,
                "public_name_id": public_ids[mnemonic],
                "requirement_first": first_requirement,
                "requirement_count": len(sorted_required),
                "minimum_arch_bit": minimum_arch_bit,
            }
        )
        requirement_rows.append(
            {
                "form_id": leaf_index + 1,
                "instruction_set": node["instruction_set_name"],
                "minimum_architecture": "Armv8-A" if minimum_arch_bit == 4 else "unresolved-strict",
                "required_features_all_atoms": ",".join(sorted_required),
                "source_form_id": leaf["source_form_id"],
            }
        )
        if status == RENDER_STATUS["OPAQUE"]:
            opaque_rows.append(
                {
                    "record_kind": "canonical",
                    "record_index": leaf_index,
                    "form_id": leaf_index + 1,
                    "mnemonic": mnemonic,
                    "source_form_id": leaf["source_form_id"],
                    "reason": reason,
                    "audit_class": "unresolved_recipe",
                }
            )

    for alias_index, (alias, source) in enumerate(zip(tree_aliases, alias_sources)):
        leaf = leaves[alias["leaf_index"]]
        node = nodes[leaf["node_index"]]
        binding_first, binding_count, compiled = builder.add_encoded_bindings(source, node["bindings"])
        assembly_id = builder.add_assembly(source.get("assembly"))
        mnemonic = tree.first_literal(source).lower()
        recipe_first, recipe_count, status, reason = add_recipe(
            source, node["bindings"], compiled,
            has_semantic_branch_target(leaf["source_form_id"]),
        )
        if mnemonic not in public_ids:
            raise AssemblyError(f"missing alias public name ID for {mnemonic!r}")
        condition = builder.compile_program(source.get("condition"), node["bindings"])
        preferred = builder.compile_program(source.get("preferred"), node["bindings"])
        if condition is not None:
            builder.programs_raw.append(condition)
        if preferred is not None:
            builder.programs_raw.append(preferred)
        alias_records.append(
            {
                "leaf_index": alias["leaf_index"],
                "assembly_id": assembly_id,
                "first_binding": binding_first,
                "binding_count": binding_count,
                "recipe_first": recipe_first,
                "recipe_count": recipe_count,
                "render_status": status,
                "public_name_id": public_ids[mnemonic],
                "condition_raw": condition,
                "preferred_raw": preferred,
                "condition_program_id": NONE,
                "preferred_program_id": NONE,
            }
        )
        if status == RENDER_STATUS["OPAQUE"]:
            opaque_rows.append(
                {
                    "record_kind": "alias",
                    "record_index": alias_index,
                    "form_id": alias["form_id"],
                    "mnemonic": mnemonic,
                    "source_form_id": alias["source_form_id"],
                    "reason": reason,
                    "audit_class": opaque_audit_class(
                        alias_index, alias, source, reason
                    ),
                }
            )

    program_ids, program_records, bytecode = finish_programs(builder.programs_raw)
    # Resolve encoded-binding program placeholders in insertion order.
    binding_programs: list[tuple[tuple[int, int, int], ...]] = []
    for source, leaf in zip(leaf_sources, leaves):
        node = nodes[leaf["node_index"]]
        encoded = (source.get("_meta") or {}).get("encoded_in") or {}
        for display in sorted(encoded, key=lambda value: value.encode("utf-8")):
            for expression in encoded[display]:
                raw = builder.compile_program(expression, node["bindings"])
                assert raw is not None
                binding_programs.append(raw)
    for source, alias in zip(alias_sources, tree_aliases):
        leaf = leaves[alias["leaf_index"]]
        node = nodes[leaf["node_index"]]
        encoded = (source.get("_meta") or {}).get("encoded_in") or {}
        for display in sorted(encoded, key=lambda value: value.encode("utf-8")):
            for expression in encoded[display]:
                raw = builder.compile_program(expression, node["bindings"])
                assert raw is not None
                binding_programs.append(raw)
    if len(binding_programs) != len(builder.form_bindings):
        raise AssemblyError("encoded binding program count mismatch")
    builder.form_bindings = [
        (display, program_ids[raw], 0)
        for (display, _placeholder, _unused), raw in zip(builder.form_bindings, binding_programs)
    ]
    builder.recipe_ops_raw = [
        (opcode, program_ids[value] if isinstance(value, tuple) else value)
        for opcode, value in builder.recipe_ops_raw
    ]
    for record in builder.special_registers:
        record["program_id"] = program_ids[record.pop("program_raw")]
    for record in builder.selections:
        record["program_id"] = program_ids[record.pop("program_raw")]
    for record in alias_records:
        condition_raw = record.pop("condition_raw")
        preferred_raw = record.pop("preferred_raw")
        record["condition_program_id"] = (
            NONE if condition_raw is None else program_ids[condition_raw]
        )
        record["preferred_program_id"] = (
            NONE if preferred_raw is None else program_ids[preferred_raw]
        )

    numeric = render_numeric_include(
        builder, rule_conditions, form_records, alias_records,
        requirement_feature_ids, program_ids, program_records, bytecode,
    )
    formatter = render_text_include(text)
    requirements_decode = render_requirements_include(
        form_records, requirement_feature_ids
    )
    write_or_check(args.decode_output, numeric, args.check)
    write_or_check(args.format_output, formatter, args.check)
    write_or_check(
        args.requirements_decode_output, requirements_decode, args.check
    )
    write_tsv(
        args.opaque_output,
        opaque_rows,
        ["record_kind", "record_index", "form_id", "mnemonic", "source_form_id", "reason", "audit_class"],
        args.check,
    )
    write_tsv(
        args.requirements_output,
        requirement_rows,
        ["form_id", "instruction_set", "minimum_architecture", "required_features_all_atoms", "source_form_id"],
        args.check,
    )

    rule_counts = {kind: sum(1 for rule in rules.values() if rule.get("_type") == kind) for kind in RULE_KIND}
    opaque_reason_counts: dict[str, int] = {}
    opaque_audit_class_counts: dict[str, int] = {}
    for row in opaque_rows:
        key = f"{row['record_kind']}:{row['reason']}"
        opaque_reason_counts[key] = opaque_reason_counts.get(key, 0) + 1
        audit_class = row["audit_class"]
        opaque_audit_class_counts[audit_class] = (
            opaque_audit_class_counts.get(audit_class, 0) + 1
        )
    manifest = {
        "schema_version": 2,
        "source": {
            "commit": PINNED_COMMIT,
            "instructions_sha256": PINNED_INSTRUCTIONS_SHA256,
            "path": source_path.name,
        },
        "counts": {
            "assembly_rules": len(rules),
            "rule_kinds": rule_counts,
            "canonical_forms": len(form_records),
            "alias_records": len(alias_records),
            "direct_canonical_recipes": sum(record["render_status"] == RENDER_STATUS["DIRECT"] for record in form_records),
            "direct_alias_recipes": sum(record["render_status"] == RENDER_STATUS["DIRECT"] for record in alias_records),
            "opaque_records": len(opaque_rows),
            "actionable_opaque_records": opaque_audit_class_counts.get(
                "unresolved_recipe", 0
            ),
            "opaque_audit_class_counts": dict(sorted(opaque_audit_class_counts.items())),
            "opaque_reason_counts": dict(sorted(opaque_reason_counts.items())),
            "numeric_programs": len(program_records),
            "numeric_bytecode_instructions": len(bytecode),
            "formatter_text_tokens": len(text.ordered),
        },
        "policy": {
            "direct_recipe": "Deterministic literals/tokens, direct raw-field integer expressions, reviewed ordered split-field concatenations, A32 conditions, register-31 choices, sign markers, and exact fixed-spelling selections are rendered; labels and values requiring an omitted architectural transform remain opaque.",
            "choice": "Choices require an architectural special case, identical branches, syntax-only omission, an exhaustive power-of-two fixed-spelling map, or a verified sparse fixed-spelling map (including SVE size[23:22]); other partial/dynamic choices with null disassemble mappings remain opaque.",
            "minimum_architecture": "A64 requires legacy V8. A32/T32 is UINT8_MAX (named-profile disabled) because the pinned source does not give unconditional leaves a version floor.",
            "feature_requirements": "All FEAT_* atoms on the root-to-leaf path are required; this may underaccept OR/negated predicates but cannot overaccept them.",
            "opaque_audit_class": "unresolved_recipe means a missing byte-to-text recipe; non_invertible_assembly_alias and assembly_only_pseudoinstruction are non-preferred source assembly spellings whose parent bytes retain the canonical/preferred byte-determined output. These 16 aliases remain runtime-opaque and do not count as direct formatter coverage.",
        },
        "outputs": {},
    }
    manifest_text_without_outputs = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if not args.check:
        # First materialize the other files, then capture their exact digests.
        for path in (
            args.decode_output,
            args.format_output,
            args.requirements_decode_output,
            args.opaque_output,
            args.requirements_output,
        ):
            manifest["outputs"][path.relative_to(REPO_ROOT).as_posix()] = {
                "sha256": sha256_file(path),
            }
    else:
        with args.manifest_output.open("r", encoding="utf-8") as stream:
            existing = json.load(stream)
        manifest["outputs"] = existing.get("outputs", {})
        for relative, record in manifest["outputs"].items():
            if sha256_file(REPO_ROOT / relative) != record["sha256"]:
                raise AssemblyError(f"generated output digest mismatch: {relative}")
    manifest_text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    write_or_check(args.manifest_output, manifest_text, args.check)
    action = "verified" if args.check else "generated"
    print(
        f"{action} Arm assembly catalog: {len(rules)} rules, "
        f"{manifest['counts']['direct_canonical_recipes']} direct forms, "
        f"{manifest['counts']['direct_alias_recipes']} direct aliases, "
        f"{len(opaque_rows)} explicit opaque records"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssemblyError, tree.TreeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
