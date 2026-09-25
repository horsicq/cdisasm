#include "cdisasm/cdisasm_x86.h"

#include "x86_decoder.h"
#include "x86_generated_decoder.h"

#include <string.h>

_Static_assert(sizeof(cdisasm_x86_decode_flags)
                   == CDISASM_DECODE_FLAGS_SIZE,
               "x86 decode-flags ABI size changed");

#define X86_CPU_MODES_16 ((uint8_t)CDISASM_X86_MODE_MASK_16)
#define X86_CPU_MODES_16_32 \
    ((uint8_t)(CDISASM_X86_MODE_MASK_16 | CDISASM_X86_MODE_MASK_32))
#define X86_CPU_MODES_16_32_64 \
    ((uint8_t)(CDISASM_X86_MODE_MASK_16 | CDISASM_X86_MODE_MASK_32 \
        | CDISASM_X86_MODE_MASK_64))

static int x86_should_retry_generated_after_invalid(
    const uint8_t *code,
    size_t code_size,
    cdisasm_mode mode)
{
    uint8_t map;
    uint8_t opcode;
    uint8_t modrm;

    if (mode != CDISASM_MODE_64 || code == NULL || code_size < 6u) {
        return 0;
    }

    /*
     * AVX2 VSIB gathers live in the VEX 0F38 map.  The hand decoder
     * deliberately does not claim this family; let the generated descriptor
     * table validate the complete opcode, VEX.W/VL combination and VSIB
     * addressing form.  The structural filter is intentionally narrow so an
     * arbitrary invalid VEX instruction is not promoted to the generated
     * path.
     */
    if (code[0] == UINT8_C(0xc4)) {
        map = code[1] & UINT8_C(0x1f);
        opcode = code[3];
        modrm = code[4];
        if (map == UINT8_C(2)
            && (code[2] & UINT8_C(3)) == UINT8_C(1)
            && opcode >= UINT8_C(0x90) && opcode <= UINT8_C(0x93)
            && (modrm & UINT8_C(0xc0)) != UINT8_C(0xc0)
            && (modrm & UINT8_C(7)) == UINT8_C(4)) {
            return 1;
        }
        return 0;
    }

    if (code[0] != UINT8_C(0x62)
        || (code[1] & UINT8_C(0xc0)) != UINT8_C(0xc0)) {
        return 0;
    }
    map = code[1] & UINT8_C(7);
    opcode = code[4];
    modrm = code[5];

    /* AVX512-FP16 complex/scalar memory forms use raw EVEX.U=0. */
    if (map == UINT8_C(6)
        && (code[2] & UINT8_C(4)) == 0u
        && (modrm & UINT8_C(0xc0)) != UINT8_C(0xc0)
        && (opcode == UINT8_C(0x56) || opcode == UINT8_C(0x57)
            || opcode == UINT8_C(0xd6) || opcode == UINT8_C(0xd7))) {
        return 1;
    }

    /* APX POP2P/PUSH2P are NDD EVEX map-4 forms with W=1. */
    /* APX CFCMOV uses the same map-4 conditional-move opcode window.  The
     * legacy handler intentionally rejects the NDD/NF combinations that are
     * owned by the generated APX descriptor matrix; retry those forms here
     * so APX profiles reach the exact generated form and formatter path. */
    if (code[1] == UINT8_C(0xf4)
        && map == UINT8_C(4)
        && opcode >= UINT8_C(0x40) && opcode <= UINT8_C(0x4f)) {
        return 1;
    }

    return map == UINT8_C(4)
        && (code[2] & UINT8_C(0x80)) != 0u
        && (code[3] & UINT8_C(0x10)) != 0u
        && (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0)
        && (opcode == UINT8_C(0x8f) || opcode == UINT8_C(0xff));
}

/* Indexed by CDISASM_CPU_ORDINAL_OF(cpu_id). Keep append-only with the API. */
static const uint8_t x86_cpu_mode_masks[] = {
    X86_CPU_MODES_16_32_64, /*  0: unrestricted compatibility profile */
    X86_CPU_MODES_16,       /*  1: 8086/8088 */
    X86_CPU_MODES_16,       /*  2: 80186 */
    X86_CPU_MODES_16,       /*  3: 80286 */
    X86_CPU_MODES_16_32,    /*  4: 80386 */
    X86_CPU_MODES_16_32,    /*  5: 80486 */
    X86_CPU_MODES_16_32,    /*  6: late 80486 with CPUID */
    X86_CPU_MODES_16_32,    /*  7: Pentium */
    X86_CPU_MODES_16_32,    /*  8: Pentium Pro */
    X86_CPU_MODES_16_32,    /*  9: Pentium MMX */
    X86_CPU_MODES_16_32,    /* 10: Pentium II */
    X86_CPU_MODES_16_32,    /* 11: AMD K6-2 */
    X86_CPU_MODES_16_32,    /* 12: Pentium III */
    X86_CPU_MODES_16_32,    /* 13: Pentium 4 */
    X86_CPU_MODES_16_32_64, /* 14: Athlon 64 / Opteron */
    X86_CPU_MODES_16_32_64, /* 15: Prescott */
    X86_CPU_MODES_16_32_64, /* 16: Intel VT-x */
    X86_CPU_MODES_16_32_64, /* 17: AMD-V */
    X86_CPU_MODES_16_32_64, /* 18: Core 2 */
    X86_CPU_MODES_16_32_64, /* 19: Penryn */
    X86_CPU_MODES_16_32_64, /* 20: AMD Barcelona */
    X86_CPU_MODES_16_32_64, /* 21: Nehalem */
    X86_CPU_MODES_16_32_64, /* 22: Westmere */
    X86_CPU_MODES_16_32_64, /* 23: Sandy Bridge */
    X86_CPU_MODES_16_32_64, /* 24: AMD Bulldozer */
    X86_CPU_MODES_16_32_64, /* 25: Ivy Bridge */
    X86_CPU_MODES_16_32_64, /* 26: Haswell */
    X86_CPU_MODES_16_32_64, /* 27: Broadwell */
    X86_CPU_MODES_16_32_64, /* 28: Skylake */
    X86_CPU_MODES_16_32_64, /* 29: Goldmont */
    X86_CPU_MODES_16_32_64, /* 30: AMD Zen */
    X86_CPU_MODES_16_32_64, /* 31: Skylake-SP */
    X86_CPU_MODES_16_32_64, /* 32: Ice Lake */
    X86_CPU_MODES_16_32_64, /* 33: Tiger Lake */
    X86_CPU_MODES_16_32_64, /* 34: Alder Lake */
    X86_CPU_MODES_16_32_64, /* 35: AMD Zen 4 */
    X86_CPU_MODES_16_32_64, /* 36: Sapphire Rapids */
    X86_CPU_MODES_16_32_64, /* 37: AVX10 */
    X86_CPU_MODES_16_32_64, /* 38: APX */
    X86_CPU_MODES_16_32_64, /* 39: Celeron G1840 */
    X86_CPU_MODES_16_32_64, /* 40: Celeron G3900 */
    X86_CPU_MODES_16_32_64, /* 41: Celeron N3350 */
    X86_CPU_MODES_16_32_64, /* 42: Celeron N4020 */
    X86_CPU_MODES_16_32_64, /* 43: Celeron G5900 */
    X86_CPU_MODES_16_32_64, /* 44: Pentium Silver N6000 */
    X86_CPU_MODES_16,       /* 45: 8086/8088 plus 8087 */
    X86_CPU_MODES_16,       /* 46: 80186 plus 80187 */
    X86_CPU_MODES_16,       /* 47: 80286 plus 80287 */
    X86_CPU_MODES_16_32,    /* 48: 80386 plus 80387 */
    X86_CPU_MODES_16_32_64, /* 49: Granite Rapids */
    X86_CPU_MODES_16_32_64, /* 50: Arrow Lake */
    X86_CPU_MODES_16_32_64, /* 51: Diamond Rapids */
    X86_CPU_MODES_16_32_64  /* 52: Knights Mill */
};

_Static_assert(
    sizeof(x86_cpu_mode_masks) / sizeof(x86_cpu_mode_masks[0])
        == CDISASM_CPU_ORDINAL_OF(CDISASM_CPU_LAST) + UINT32_C(1),
    "x86 CPU mode metadata must cover every public CPU profile");

#if USE_EXTRA_OPCODES
static const uint64_t x86_known_flag_masks[
    CDISASM_DECODE_FLAGS_BITMAP_COUNT] = {
    CDISASM_X86_DECODE_FLAG_KNOWN_MASK_0,
    CDISASM_X86_DECODE_FLAG_KNOWN_MASK_1,
    CDISASM_X86_DECODE_FLAG_KNOWN_MASK_2,
    CDISASM_X86_DECODE_FLAG_KNOWN_MASK_3,
    CDISASM_X86_DECODE_FLAG_KNOWN_MASK_4,
    CDISASM_X86_DECODE_FLAG_KNOWN_MASK_5,
    CDISASM_X86_DECODE_FLAG_KNOWN_MASK_6,
    CDISASM_X86_DECODE_FLAG_KNOWN_MASK_7
};

#include "generated/cdisasm_x86_cpu_isa_set_masks.inc"

_Static_assert(
    sizeof(x86_cpu_isa_set_flag_masks)
            / sizeof(x86_cpu_isa_set_flag_masks[0])
        == CDISASM_CPU_ORDINAL_OF(CDISASM_CPU_LAST) + UINT32_C(1),
    "generated x86 ISA_SET masks must cover every CPU profile");
#endif

#undef X86_CPU_MODES_16
#undef X86_CPU_MODES_16_32
#undef X86_CPU_MODES_16_32_64

static int valid_mode(cdisasm_mode mode)
{
    return mode == CDISASM_MODE_16
        || mode == CDISASM_MODE_32
        || mode == CDISASM_MODE_64;
}

static cdisasm_x86_mode_mask mode_bit(cdisasm_mode mode)
{
    switch (mode) {
        case CDISASM_MODE_16:
            return CDISASM_X86_MODE_MASK_16;
        case CDISASM_MODE_32:
            return CDISASM_X86_MODE_MASK_32;
        case CDISASM_MODE_64:
            return CDISASM_X86_MODE_MASK_64;
        default:
            return CDISASM_X86_MODE_MASK_NONE;
    }
}

static int valid_cpu(cdisasm_cpu_id cpu_id)
{
    uint32_t ordinal = CDISASM_CPU_ORDINAL_OF(cpu_id);

    return CDISASM_CPU_GROUP_OF(cpu_id) == CDISASM_CPU_GROUP_X86
        && ordinal <= CDISASM_CPU_ORDINAL_OF(CDISASM_CPU_LAST)
        && ordinal < sizeof(x86_cpu_mode_masks)
            / sizeof(x86_cpu_mode_masks[0]);
}

static int cpu_supports_mode(cdisasm_cpu_id cpu_id, cdisasm_mode mode)
{
    uint32_t ordinal = CDISASM_CPU_ORDINAL_OF(cpu_id);
    cdisasm_x86_mode_mask selected_mode = mode_bit(mode);

    return ordinal < sizeof(x86_cpu_mode_masks)
            / sizeof(x86_cpu_mode_masks[0])
        && selected_mode != CDISASM_X86_MODE_MASK_NONE
        && (x86_cpu_mode_masks[ordinal] & selected_mode) != 0;
}

cdisasm_x86_mode_mask CDISASM_CALL cdisasm_x86_cpu_mode_mask(
    cdisasm_x86_cpu_id cpu_id)
{
    if (!valid_cpu(cpu_id)) {
        return CDISASM_X86_MODE_MASK_NONE;
    }
    return x86_cpu_mode_masks[CDISASM_CPU_ORDINAL_OF(cpu_id)];
}

static const cdisasm_x86_family_descriptor x86_family_descriptors[
    CDISASM_X86_FAMILY_LAST + UINT16_C(1)] = {
    [CDISASM_X86_FAMILY_AVX512_EVEX] = {
        CDISASM_X86_FAMILY_AVX512_EVEX,
        CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_EVEX_VECTOR_MASK,
        CDISASM_X86_LEGALITY_RULE_AVX512_EVEX,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_ANY
    },
    [CDISASM_X86_FAMILY_APX_EVEX] = {
        CDISASM_X86_FAMILY_APX_EVEX,
        CDISASM_X86_DECODE_FLAG_APX,
        CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_APX_N3,
        CDISASM_X86_LEGALITY_RULE_APX_F_N3,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_ANY
    },
    [CDISASM_X86_FAMILY_AVX2_GATHER] = {
        CDISASM_X86_FAMILY_AVX2_GATHER,
        CDISASM_X86_DECODE_FLAG_AVX2,
        CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_VSIB_GATHER,
        CDISASM_X86_LEGALITY_RULE_AVX2_VSIB,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_ANY
    },
    [CDISASM_X86_FAMILY_FRED] = {
        CDISASM_X86_FAMILY_FRED,
        CDISASM_X86_DECODE_FLAG_SYSTEM,
        CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_ZERO_OPERANDS,
        CDISASM_X86_LEGALITY_RULE_FRED,
        CDISASM_X86_PRIVILEGE_RING0,
        CDISASM_X86_VENDOR_INTEL
    },
    [CDISASM_X86_FAMILY_TDX] = {
        CDISASM_X86_FAMILY_TDX,
        CDISASM_X86_DECODE_FLAG_SYSTEM,
        CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_ZERO_OPERANDS,
        CDISASM_X86_LEGALITY_RULE_TDX,
        CDISASM_X86_PRIVILEGE_VMX_ROOT,
        CDISASM_X86_VENDOR_INTEL
    },
    [CDISASM_X86_FAMILY_VIA_PADLOCK] = {
        CDISASM_X86_FAMILY_VIA_PADLOCK,
        CDISASM_X86_DECODE_FLAG_SYSTEM,
        CDISASM_X86_MODE_MASK_32 | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_VIA_PADLOCK,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_VIA
    },
    [CDISASM_X86_FAMILY_X87] = {
        CDISASM_X86_FAMILY_X87,
        CDISASM_X86_DECODE_FLAG_FPU,
        CDISASM_X86_MODE_MASK_16 | CDISASM_X86_MODE_MASK_32
            | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_X87_STACK,
        CDISASM_X86_LEGALITY_RULE_X87,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_ANY
    },
    [CDISASM_X86_FAMILY_MOVRS] = {
        CDISASM_X86_FAMILY_MOVRS,
        CDISASM_X86_DECODE_FLAG_MEMORY_HINTS,
        CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_MOVRS,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_ANY
    },
    [CDISASM_X86_FAMILY_INTEL_VMX] = {
        CDISASM_X86_FAMILY_INTEL_VMX,
        CDISASM_X86_DECODE_FLAG_VMX,
        CDISASM_X86_MODE_MASK_32 | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_INTEL_VMX,
        CDISASM_X86_PRIVILEGE_VMX_ROOT,
        CDISASM_X86_VENDOR_INTEL
    },
    [CDISASM_X86_FAMILY_AMD_SVM] = {
        CDISASM_X86_FAMILY_AMD_SVM,
        CDISASM_X86_DECODE_FLAG_SVM,
        CDISASM_X86_MODE_MASK_32 | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_AMD_SVM,
        CDISASM_X86_PRIVILEGE_SVM_HOST,
        CDISASM_X86_VENDOR_AMD
    },
    /* Direct ISA-family projections.  These entries intentionally carry no
     * special operand or privilege rule: the detailed opcode row still uses
     * context.flags for its exact ISA_SET and encoding validation. */
    [CDISASM_X86_FAMILY_MMX] = {
        CDISASM_X86_FAMILY_MMX,
        CDISASM_X86_DECODE_FLAG_MMX,
        CDISASM_X86_MODE_MASK_16 | CDISASM_X86_MODE_MASK_32
            | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_NONE,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_ANY
    },
    [CDISASM_X86_FAMILY_3DNOW] = {
        CDISASM_X86_FAMILY_3DNOW,
        CDISASM_X86_DECODE_FLAG_3DNOW,
        CDISASM_X86_MODE_MASK_32 | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_NONE,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_AMD
    },
    [CDISASM_X86_FAMILY_SSE] = {
        CDISASM_X86_FAMILY_SSE,
        CDISASM_X86_DECODE_FLAG_SSE,
        CDISASM_X86_MODE_MASK_32 | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_NONE,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_ANY
    },
    [CDISASM_X86_FAMILY_SSE2] = {
        CDISASM_X86_FAMILY_SSE2,
        CDISASM_X86_DECODE_FLAG_SSE2,
        CDISASM_X86_MODE_MASK_32 | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_NONE,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_ANY
    },
    [CDISASM_X86_FAMILY_SSE3] = {
        CDISASM_X86_FAMILY_SSE3,
        CDISASM_X86_DECODE_FLAG_SSE3,
        CDISASM_X86_MODE_MASK_32 | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_NONE,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_ANY
    },
    [CDISASM_X86_FAMILY_SSSE3] = {
        CDISASM_X86_FAMILY_SSSE3,
        CDISASM_X86_DECODE_FLAG_SSSE3,
        CDISASM_X86_MODE_MASK_32 | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_NONE,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_ANY
    },
    [CDISASM_X86_FAMILY_SSE4] = {
        CDISASM_X86_FAMILY_SSE4,
        CDISASM_X86_DECODE_FLAG_SSE4,
        CDISASM_X86_MODE_MASK_32 | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_NONE,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_ANY
    },
    [CDISASM_X86_FAMILY_AVX] = {
        CDISASM_X86_FAMILY_AVX,
        CDISASM_X86_DECODE_FLAG_AVX,
        CDISASM_X86_MODE_MASK_32 | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_NONE,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_ANY
    },
    [CDISASM_X86_FAMILY_AVX2] = {
        CDISASM_X86_FAMILY_AVX2,
        CDISASM_X86_DECODE_FLAG_AVX2,
        CDISASM_X86_MODE_MASK_32 | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_NONE,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_ANY
    },
    [CDISASM_X86_FAMILY_F16C] = {
        CDISASM_X86_FAMILY_F16C,
        CDISASM_X86_DECODE_FLAG_F16C,
        CDISASM_X86_MODE_MASK_32 | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_NONE,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_ANY
    },
    [CDISASM_X86_FAMILY_FMA3] = {
        CDISASM_X86_FAMILY_FMA3,
        CDISASM_X86_DECODE_FLAG_FMA3,
        CDISASM_X86_MODE_MASK_32 | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_NONE,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_ANY
    },
    [CDISASM_X86_FAMILY_XOP] = {
        CDISASM_X86_FAMILY_XOP,
        CDISASM_X86_DECODE_FLAG_XOP,
        CDISASM_X86_MODE_MASK_32 | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_NONE,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_AMD
    },
    [CDISASM_X86_FAMILY_FMA4] = {
        CDISASM_X86_FAMILY_FMA4,
        CDISASM_X86_DECODE_FLAG_FMA4,
        CDISASM_X86_MODE_MASK_32 | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_NONE,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_AMD
    },
    [CDISASM_X86_FAMILY_AES] = {
        CDISASM_X86_FAMILY_AES,
        CDISASM_X86_DECODE_FLAG_AES,
        CDISASM_X86_MODE_MASK_32 | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_NONE,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_ANY
    },
    [CDISASM_X86_FAMILY_PCLMUL] = {
        CDISASM_X86_FAMILY_PCLMUL,
        CDISASM_X86_DECODE_FLAG_PCLMUL,
        CDISASM_X86_MODE_MASK_32 | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_NONE,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_ANY
    },
    [CDISASM_X86_FAMILY_SHA] = {
        CDISASM_X86_FAMILY_SHA,
        CDISASM_X86_DECODE_FLAG_SHA,
        CDISASM_X86_MODE_MASK_32 | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_NONE,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_ANY
    },
    [CDISASM_X86_FAMILY_GFNI] = {
        CDISASM_X86_FAMILY_GFNI,
        CDISASM_X86_DECODE_FLAG_GFNI,
        CDISASM_X86_MODE_MASK_32 | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_NONE,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_ANY
    },
    [CDISASM_X86_FAMILY_BITMANIP] = {
        CDISASM_X86_FAMILY_BITMANIP,
        CDISASM_X86_DECODE_FLAG_BITMANIP,
        CDISASM_X86_MODE_MASK_32 | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_NONE,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_ANY
    },
    [CDISASM_X86_FAMILY_AVX10] = {
        CDISASM_X86_FAMILY_AVX10,
        CDISASM_X86_DECODE_FLAG_AVX10,
        CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_NONE,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_ANY
    },
    [CDISASM_X86_FAMILY_AMX] = {
        CDISASM_X86_FAMILY_AMX,
        CDISASM_X86_DECODE_FLAG_AMX,
        CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_NONE,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_INTEL
    }
};

static int x86_instruction_has_group_range(
    const cdisasm_instruction *instruction,
    cdisasm_x86_group_id first,
    cdisasm_x86_group_id last)
{
    uint8_t index;

    if (instruction == NULL
        || instruction->x86_group_count > CDISASM_MAX_X86_GROUPS) {
        return 0;
    }
    for (index = 0; index < instruction->x86_group_count; ++index) {
        const cdisasm_x86_group_id group_id =
            instruction->x86_group_ids[index];
        if (group_id >= first && group_id <= last) {
            return 1;
        }
        if (group_id > last) {
            break;
        }
    }
    return 0;
}

static int x86_instruction_has_avx512_group(
    const cdisasm_instruction *instruction)
{
    return cdisasm_instruction_has_x86_group(
               instruction, CDISASM_X86_GROUP_AVX512F)
        || cdisasm_instruction_has_x86_group(
               instruction, CDISASM_X86_GROUP_AVX512CD)
        || cdisasm_instruction_has_x86_group(
               instruction, CDISASM_X86_GROUP_AVX512ER)
        || cdisasm_instruction_has_x86_group(
               instruction, CDISASM_X86_GROUP_AVX512PF)
        || cdisasm_instruction_has_x86_group(
               instruction, CDISASM_X86_GROUP_AVX512DQ)
        || cdisasm_instruction_has_x86_group(
               instruction, CDISASM_X86_GROUP_AVX512BW)
        || cdisasm_instruction_has_x86_group(
               instruction, CDISASM_X86_GROUP_AVX512VL)
        || cdisasm_instruction_has_x86_group(
               instruction, CDISASM_X86_GROUP_AVX512IFMA)
        || cdisasm_instruction_has_x86_group(
               instruction, CDISASM_X86_GROUP_AVX512VBMI)
        || cdisasm_instruction_has_x86_group(
               instruction, CDISASM_X86_GROUP_AVX512_4VNNIW)
        || cdisasm_instruction_has_x86_group(
               instruction, CDISASM_X86_GROUP_AVX512_4FMAPS)
        || cdisasm_instruction_has_x86_group(
               instruction, CDISASM_X86_GROUP_AVX512VPOPCNTDQ)
        || cdisasm_instruction_has_x86_group(
               instruction, CDISASM_X86_GROUP_AVX512VNNI)
        || cdisasm_instruction_has_x86_group(
               instruction, CDISASM_X86_GROUP_AVX512VBMI2)
        || cdisasm_instruction_has_x86_group(
               instruction, CDISASM_X86_GROUP_AVX512BITALG)
        || cdisasm_instruction_has_x86_group(
               instruction, CDISASM_X86_GROUP_AVX512VP2INTERSECT)
        || cdisasm_instruction_has_x86_group(
               instruction, CDISASM_X86_GROUP_AVX512BF16)
        || cdisasm_instruction_has_x86_group(
               instruction, CDISASM_X86_GROUP_AVX512FP16)
        || x86_instruction_has_group_range(
               instruction, CDISASM_X86_GROUP_AVX512BW_128,
               CDISASM_X86_GROUP_AVX512_VPOPCNTDQ_512);
}

static int x86_instruction_has_apx_group(
    const cdisasm_instruction *instruction)
{
    return cdisasm_instruction_has_x86_group(
               instruction, CDISASM_X86_GROUP_APX_F)
        || cdisasm_instruction_has_x86_group(
               instruction, CDISASM_X86_GROUP_CMPCCXADD)
        || x86_instruction_has_group_range(
               instruction, CDISASM_X86_GROUP_APX_F_ADX,
               CDISASM_X86_GROUP_APX_F_VMX);
}

static int x86_instruction_has_movrs_group(
    const cdisasm_instruction *instruction)
{
    return cdisasm_instruction_has_x86_group(
               instruction, CDISASM_X86_GROUP_MOVRS)
        || cdisasm_instruction_has_x86_group(
               instruction, CDISASM_X86_GROUP_AMX_MOVRS)
        || cdisasm_instruction_has_x86_group(
               instruction, CDISASM_X86_GROUP_APX_F_AMX_MOVRS)
        || cdisasm_instruction_has_x86_group(
               instruction, CDISASM_X86_GROUP_APX_F_MOVRS)
        || x86_instruction_has_group_range(
               instruction, CDISASM_X86_GROUP_AVX10_MOVRS_128,
               CDISASM_X86_GROUP_AVX10_MOVRS_512);
}

cdisasm_x86_family_id CDISASM_CALL cdisasm_x86_instruction_family(
    const cdisasm_instruction *instruction)
{
    if (instruction == NULL) {
        return CDISASM_X86_FAMILY_NONE;
    }
    if (cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_VMX)
        || cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_VTX)) {
        return CDISASM_X86_FAMILY_INTEL_VMX;
    }
    if (cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_SVM)) {
        return CDISASM_X86_FAMILY_AMD_SVM;
    }
    if (cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_FRED)) {
        return CDISASM_X86_FAMILY_FRED;
    }
    if (cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_TDX)) {
        return CDISASM_X86_FAMILY_TDX;
    }
    if (cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_VIA_PADLOCK_AES)
        || cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_VIA_PADLOCK_MONTMUL)
        || cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_VIA_PADLOCK_RNG)
        || cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_VIA_PADLOCK_SHA)) {
        return CDISASM_X86_FAMILY_VIA_PADLOCK;
    }
    if (x86_instruction_has_movrs_group(instruction)) {
        return CDISASM_X86_FAMILY_MOVRS;
    }
    if (cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX2GATHER)) {
        return CDISASM_X86_FAMILY_AVX2_GATHER;
    }
    if (x86_instruction_has_apx_group(instruction)) {
        return CDISASM_X86_FAMILY_APX_EVEX;
    }
    if (x86_instruction_has_avx512_group(instruction)) {
        return CDISASM_X86_FAMILY_AVX512_EVEX;
    }
    if (cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_X87)) {
        return CDISASM_X86_FAMILY_X87;
    }
    return CDISASM_X86_FAMILY_NONE;
}

const cdisasm_x86_family_descriptor *CDISASM_CALL
cdisasm_x86_family_descriptor_get(cdisasm_x86_family_id family_id)
{
    if (family_id < CDISASM_X86_FAMILY_FIRST
        || family_id > CDISASM_X86_FAMILY_LAST) {
        return NULL;
    }
    return &x86_family_descriptors[family_id];
}

static cdisasm_x86_family_mask x86_family_mask_for_id(
    cdisasm_x86_family_id family_id)
{
    if (family_id < CDISASM_X86_FAMILY_FIRST
        || family_id > CDISASM_X86_FAMILY_LAST) {
        return CDISASM_X86_FAMILY_MASK_NONE;
    }
    return UINT64_C(1) << ((uint32_t)family_id - UINT32_C(1));
}

static cdisasm_x86_family_mask x86_family_mask_for_mode(
    cdisasm_x86_mode mode)
{
    const cdisasm_x86_mode_mask selected_mode = mode_bit(mode);
    cdisasm_x86_family_mask family_mask =
        CDISASM_X86_FAMILY_MASK_NONE;
    cdisasm_x86_family_id family_id;

    if (selected_mode == CDISASM_X86_MODE_MASK_NONE) {
        return family_mask;
    }
    for (family_id = CDISASM_X86_FAMILY_FIRST;
         family_id <= CDISASM_X86_FAMILY_LAST;
         ++family_id) {
        const cdisasm_x86_family_descriptor *descriptor =
            cdisasm_x86_family_descriptor_get(family_id);

        if (descriptor != NULL
            && (descriptor->allowed_modes & selected_mode) != 0) {
            family_mask |= x86_family_mask_for_id(family_id);
        }
    }
    return family_mask;
}

int CDISASM_CALL cdisasm_x86_decode_context_add_family(
    cdisasm_x86_decode_context *context,
    cdisasm_x86_family_id family_id)
{
    const cdisasm_x86_family_mask family_mask =
        x86_family_mask_for_id(family_id);

    if (context == NULL || family_mask == CDISASM_X86_FAMILY_MASK_NONE
        || (context->family_mask & family_mask) == 0) {
        return 0;
    }
    context->family_value |= family_mask;
    return 1;
}

int CDISASM_CALL cdisasm_x86_decode_context_remove_family(
    cdisasm_x86_decode_context *context,
    cdisasm_x86_family_id family_id)
{
    const cdisasm_x86_family_mask family_mask =
        x86_family_mask_for_id(family_id);

    if (context == NULL || family_mask == CDISASM_X86_FAMILY_MASK_NONE
        || (context->family_mask & family_mask) == 0) {
        return 0;
    }
    context->family_value &= ~family_mask;
    return 1;
}

cdisasm_x86_family_mask CDISASM_CALL
cdisasm_x86_decode_context_get_available_families(
    const cdisasm_x86_decode_context *context)
{
    return context == NULL
        ? CDISASM_X86_FAMILY_MASK_NONE
        : context->family_mask;
}

cdisasm_x86_family_mask CDISASM_CALL
cdisasm_x86_decode_context_get_set_families(
    const cdisasm_x86_decode_context *context)
{
    return context == NULL
        ? CDISASM_X86_FAMILY_MASK_NONE
        : context->family_value & context->family_mask;
}

static int x86_decode_flags_has_bit_range(
    const cdisasm_x86_decode_flags *flags,
    uint32_t first_bit,
    uint32_t last_bit)
{
    uint32_t bit;

    if (flags == NULL || first_bit > last_bit) {
        return 0;
    }
    for (bit = first_bit;; ++bit) {
        if (cdisasm_decode_flags_test_bit(flags, bit)) {
            return 1;
        }
        if (bit == last_bit) {
            break;
        }
    }
    return 0;
}

cdisasm_x86_family_mask CDISASM_CALL
cdisasm_x86_family_mask_from_flags(
    const cdisasm_x86_decode_flags *flags)
{
    cdisasm_x86_family_mask family_mask =
        CDISASM_X86_FAMILY_MASK_NONE;
    uint64_t bitmap0;

    if (flags == NULL) {
        return family_mask;
    }
    bitmap0 = flags->bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP];

    /* Project the coarse ISA selectors into stable, directly selectable
     * family IDs.  A family bit is an availability summary; exact width,
     * operand, and encoding legality still come from the full flags bitmap. */
    if ((bitmap0 & CDISASM_X86_DECODE_FLAG_MMX) != 0) {
        family_mask |= CDISASM_X86_FAMILY_MASK_MMX;
    }
    if ((bitmap0 & CDISASM_X86_DECODE_FLAG_3DNOW) != 0) {
        family_mask |= CDISASM_X86_FAMILY_MASK_3DNOW;
    }
    if ((bitmap0 & CDISASM_X86_DECODE_FLAG_SSE) != 0) {
        family_mask |= CDISASM_X86_FAMILY_MASK_SSE;
    }
    if ((bitmap0 & CDISASM_X86_DECODE_FLAG_SSE2) != 0) {
        family_mask |= CDISASM_X86_FAMILY_MASK_SSE2;
    }
    if ((bitmap0 & CDISASM_X86_DECODE_FLAG_SSE3) != 0) {
        family_mask |= CDISASM_X86_FAMILY_MASK_SSE3;
    }
    if ((bitmap0 & CDISASM_X86_DECODE_FLAG_SSSE3) != 0) {
        family_mask |= CDISASM_X86_FAMILY_MASK_SSSE3;
    }
    if ((bitmap0 & (CDISASM_X86_DECODE_FLAG_SSE4
                    | CDISASM_X86_DECODE_FLAG_SSE41
                    | CDISASM_X86_DECODE_FLAG_SSE42
                    | CDISASM_X86_DECODE_FLAG_SSE4A)) != 0) {
        family_mask |= CDISASM_X86_FAMILY_MASK_SSE4;
    }
    if ((bitmap0 & CDISASM_X86_DECODE_FLAG_AVX) != 0) {
        family_mask |= CDISASM_X86_FAMILY_MASK_AVX;
    }
    if ((bitmap0 & CDISASM_X86_DECODE_FLAG_AVX2) != 0) {
        family_mask |= CDISASM_X86_FAMILY_MASK_AVX2;
    }
    if ((bitmap0 & CDISASM_X86_DECODE_FLAG_F16C) != 0) {
        family_mask |= CDISASM_X86_FAMILY_MASK_F16C;
    }
    if ((bitmap0 & CDISASM_X86_DECODE_FLAG_FMA3) != 0) {
        family_mask |= CDISASM_X86_FAMILY_MASK_FMA3;
    }
    if ((bitmap0 & CDISASM_X86_DECODE_FLAG_XOP) != 0) {
        family_mask |= CDISASM_X86_FAMILY_MASK_XOP;
    }
    if ((bitmap0 & CDISASM_X86_DECODE_FLAG_FMA4) != 0) {
        family_mask |= CDISASM_X86_FAMILY_MASK_FMA4;
    }
    if ((bitmap0 & (CDISASM_X86_DECODE_FLAG_AES
                    | CDISASM_X86_DECODE_FLAG_VAES)) != 0) {
        family_mask |= CDISASM_X86_FAMILY_MASK_AES;
    }
    if ((bitmap0 & (CDISASM_X86_DECODE_FLAG_PCLMUL
                    | CDISASM_X86_DECODE_FLAG_VPCLMULQDQ)) != 0) {
        family_mask |= CDISASM_X86_FAMILY_MASK_PCLMUL;
    }
    if ((bitmap0 & (CDISASM_X86_DECODE_FLAG_SHA
                    | CDISASM_X86_DECODE_FLAG_SHA512)) != 0) {
        family_mask |= CDISASM_X86_FAMILY_MASK_SHA;
    }
    if ((bitmap0 & CDISASM_X86_DECODE_FLAG_GFNI) != 0) {
        family_mask |= CDISASM_X86_FAMILY_MASK_GFNI;
    }
    if ((bitmap0 & (CDISASM_X86_DECODE_FLAG_BITMANIP
                    | CDISASM_X86_DECODE_FLAG_BMI1
                    | CDISASM_X86_DECODE_FLAG_BMI2)) != 0) {
        family_mask |= CDISASM_X86_FAMILY_MASK_BITMANIP;
    }
    if ((bitmap0 & CDISASM_X86_DECODE_FLAG_AVX10) != 0) {
        family_mask |= CDISASM_X86_FAMILY_MASK_AVX10;
    }
    if ((bitmap0 & (CDISASM_X86_DECODE_FLAG_AMX
                    | CDISASM_X86_DECODE_FLAG_AMX_TILE
                    | CDISASM_X86_DECODE_FLAG_AMX_INT8
                    | CDISASM_X86_DECODE_FLAG_AMX_BF16
                    | CDISASM_X86_DECODE_FLAG_AMX_FP16
                    | CDISASM_X86_DECODE_FLAG_AMX_COMPLEX
                    | CDISASM_X86_DECODE_FLAG_AMX_FP8
                    | CDISASM_X86_DECODE_FLAG_AMX_MOVRS
                    | CDISASM_X86_DECODE_FLAG_AMX_AVX512)) != 0) {
        family_mask |= CDISASM_X86_FAMILY_MASK_AMX;
    }

    if ((bitmap0 & CDISASM_X86_DECODE_FLAG_FPU) != 0) {
        family_mask |= CDISASM_X86_FAMILY_MASK_X87;
    }
    if ((bitmap0 & CDISASM_X86_DECODE_FLAG_AVX512) != 0
        || x86_decode_flags_has_bit_range(
            flags,
            CDISASM_X86_DECODE_BIT_AVX512BW_128,
            CDISASM_X86_DECODE_BIT_AVX512_VPOPCNTDQ_512)) {
        family_mask |= CDISASM_X86_FAMILY_MASK_AVX512_EVEX;
    }
    if ((bitmap0 & CDISASM_X86_DECODE_FLAG_APX) != 0
        || x86_decode_flags_has_bit_range(
            flags,
            CDISASM_X86_DECODE_BIT_APX_F_ADX,
            CDISASM_X86_DECODE_BIT_APX_F_VMX)
        || cdisasm_decode_flags_test_bit(
            flags, CDISASM_X86_DECODE_BIT_CMPCCXADD)) {
        family_mask |= CDISASM_X86_FAMILY_MASK_APX_EVEX;
    }
    if (cdisasm_decode_flags_test_bit(
            flags, CDISASM_X86_DECODE_BIT_AVX2GATHER)) {
        family_mask |= CDISASM_X86_FAMILY_MASK_AVX2_GATHER;
    }
    if ((bitmap0 & CDISASM_X86_DECODE_FLAG_VMX) != 0
        || cdisasm_decode_flags_test_bit(
            flags, CDISASM_X86_DECODE_BIT_VTX)) {
        family_mask |= CDISASM_X86_FAMILY_MASK_INTEL_VMX;
    }
    if ((bitmap0 & CDISASM_X86_DECODE_FLAG_SVM) != 0) {
        family_mask |= CDISASM_X86_FAMILY_MASK_AMD_SVM;
    }
    if (cdisasm_decode_flags_test_bit(flags, CDISASM_X86_DECODE_BIT_FRED)) {
        family_mask |= CDISASM_X86_FAMILY_MASK_FRED;
    }
    if (cdisasm_decode_flags_test_bit(flags, CDISASM_X86_DECODE_BIT_TDX)) {
        family_mask |= CDISASM_X86_FAMILY_MASK_TDX;
    }
    if (x86_decode_flags_has_bit_range(
            flags,
            CDISASM_X86_DECODE_BIT_VIA_PADLOCK_AES,
            CDISASM_X86_DECODE_BIT_VIA_PADLOCK_SHA)) {
        family_mask |= CDISASM_X86_FAMILY_MASK_VIA_PADLOCK;
    }
    if ((bitmap0 & CDISASM_X86_DECODE_FLAG_AMX_MOVRS) != 0
        || cdisasm_decode_flags_test_bit(
            flags, CDISASM_X86_DECODE_BIT_APX_F_AMX_MOVRS)
        || cdisasm_decode_flags_test_bit(
            flags, CDISASM_X86_DECODE_BIT_APX_F_MOVRS)
        || x86_decode_flags_has_bit_range(
            flags,
            CDISASM_X86_DECODE_BIT_AVX10_MOVRS_128,
            CDISASM_X86_DECODE_BIT_AVX10_MOVRS_512)
        || cdisasm_decode_flags_test_bit(
            flags, CDISASM_X86_DECODE_BIT_MOVRS)) {
        family_mask |= CDISASM_X86_FAMILY_MASK_MOVRS;
    }
    return family_mask;
}

static int x86_decode_flags_are_valid(
    const cdisasm_x86_decode_flags *flags)
{
    uint32_t bitmap_index;

    if (flags == NULL) {
        return 1;
    }
    for (bitmap_index = 0;
         bitmap_index < CDISASM_DECODE_FLAGS_BITMAP_COUNT;
         ++bitmap_index) {
#if USE_EXTRA_OPCODES
        const uint64_t known_mask = x86_known_flag_masks[bitmap_index];
#else
        const uint64_t known_mask = UINT64_C(0);
#endif
        if ((flags->bitmap[bitmap_index] & ~known_mask) != 0) {
            return 0;
        }
    }
    return 1;
}

cdisasm_status CDISASM_CALL
cdisasm_x86_cpu_decode_flag_mask(
    cdisasm_x86_cpu_id cpu_id,
    cdisasm_x86_mode mode,
    cdisasm_x86_decode_flags *flags)
{
    if (flags == NULL) {
        return CDISASM_STATUS_INVALID_ARGUMENT;
    }
    memset(flags, 0, sizeof(*flags));
    if (!valid_cpu(cpu_id)
        || !valid_mode(mode)
        || !cpu_supports_mode(cpu_id, mode)) {
        return CDISASM_STATUS_INVALID_ARGUMENT;
    }
#if USE_EXTRA_OPCODES
    {
        const uint32_t ordinal = CDISASM_CPU_ORDINAL_OF(cpu_id);
        const uint32_t mode_index = mode == CDISASM_MODE_16
            ? UINT32_C(0)
            : (mode == CDISASM_MODE_32 ? UINT32_C(1) : UINT32_C(2));
        uint32_t bitmap_index;

        flags->bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP] =
            cdisasm_x86_cpu_decode_flag_mask_core(cpu_id, mode);
        if (cpu_id == CDISASM_CPU_X86) {
            /* The compatibility profile intentionally exposes every exact
             * family which has at least one encoding in the selected mode. */
            flags->bitmap[0] |= CDISASM_X86_DECODE_FLAG_GFNI;
        }
        for (bitmap_index = UINT32_C(1);
             bitmap_index < CDISASM_DECODE_FLAGS_BITMAP_COUNT;
             ++bitmap_index) {
            flags->bitmap[bitmap_index] =
                x86_cpu_isa_set_flag_masks[ordinal][mode_index]
                    [bitmap_index - UINT32_C(1)];
        }
    }
#else
    (void)cpu_id;
    (void)mode;
#endif
    return CDISASM_STATUS_OK;
}

cdisasm_status CDISASM_CALL cdisasm_x86_cpu_decode_context(
    cdisasm_x86_cpu_id cpu_id,
    cdisasm_x86_mode mode,
    cdisasm_x86_decode_context *context)
{
    cdisasm_status status;

    if (context == NULL) {
        return CDISASM_STATUS_INVALID_ARGUMENT;
    }
    memset(context, 0, sizeof(*context));
    status = cdisasm_x86_cpu_decode_flag_mask(
        cpu_id, mode, &context->flags);
    if (status != CDISASM_STATUS_OK) {
        return status;
    }
    context->cpu_id = cpu_id;
    context->mode = mode;
    context->family_mask = cdisasm_x86_family_mask_from_flags(
        &context->flags);
    /* Family descriptors carry their mode legality independently of the
     * coarse decode bitmap. */
    context->family_mask &= x86_family_mask_for_mode(mode);
    context->family_value = context->family_mask
        & CDISASM_X86_FAMILY_MASK_DEFAULT;
    return CDISASM_STATUS_OK;
}

_Static_assert(
    CDISASM_X86_GROUP_ENQCMD == UINT16_C(115),
    "hand-written x86 group boundary changed");

static cdisasm_x86_decode_option x86_group_decode_flag(
    cdisasm_x86_group_id group_id)
{
    switch (group_id) {
        case CDISASM_X86_GROUP_X87:
        case CDISASM_X86_GROUP_FCMOV:
        case CDISASM_X86_GROUP_FCOMI:
            return CDISASM_X86_DECODE_FLAG_FPU;
        case CDISASM_X86_GROUP_MMX:
            return CDISASM_X86_DECODE_FLAG_MMX;
        case CDISASM_X86_GROUP_3DNOW:
        case CDISASM_X86_GROUP_3DNOW_EXT:
            return CDISASM_X86_DECODE_FLAG_3DNOW;
        case CDISASM_X86_GROUP_SSE:
            return CDISASM_X86_DECODE_FLAG_SSE;
        case CDISASM_X86_GROUP_SSE2:
            return CDISASM_X86_DECODE_FLAG_SSE2;
        case CDISASM_X86_GROUP_SSE3:
            return CDISASM_X86_DECODE_FLAG_SSE3;
        case CDISASM_X86_GROUP_SSSE3:
            return CDISASM_X86_DECODE_FLAG_SSSE3;
        case CDISASM_X86_GROUP_SSE41:
            return CDISASM_X86_DECODE_FLAG_SSE41;
        case CDISASM_X86_GROUP_SSE4A:
            return CDISASM_X86_DECODE_FLAG_SSE4A;
        case CDISASM_X86_GROUP_SSE42:
            return CDISASM_X86_DECODE_FLAG_SSE42;
        case CDISASM_X86_GROUP_AVX:
            return CDISASM_X86_DECODE_FLAG_AVX;
        case CDISASM_X86_GROUP_AVX_GFNI:
            return CDISASM_X86_DECODE_FLAG_AVX;
        case CDISASM_X86_GROUP_AVX2:
            return CDISASM_X86_DECODE_FLAG_AVX2;
        case CDISASM_X86_GROUP_AVX_VNNI:
            return CDISASM_X86_DECODE_FLAG_AVX_VNNI;
        case CDISASM_X86_GROUP_AVX_VNNI_INT8:
            return CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT8;
        case CDISASM_X86_GROUP_AVX_VNNI_INT16:
            return CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16;
        case CDISASM_X86_GROUP_F16C:
            return CDISASM_X86_DECODE_FLAG_F16C;
        case CDISASM_X86_GROUP_FMA3:
            return CDISASM_X86_DECODE_FLAG_FMA3;
        case CDISASM_X86_GROUP_XOP:
            return CDISASM_X86_DECODE_FLAG_XOP;
        case CDISASM_X86_GROUP_FMA4:
            return CDISASM_X86_DECODE_FLAG_FMA4;
        case CDISASM_X86_GROUP_AESNI:
            return CDISASM_X86_DECODE_FLAG_AES;
        case CDISASM_X86_GROUP_VAES:
            return CDISASM_X86_DECODE_FLAG_VAES;
        case CDISASM_X86_GROUP_PCLMULQDQ:
            return CDISASM_X86_DECODE_FLAG_PCLMUL;
        case CDISASM_X86_GROUP_VPCLMULQDQ:
            return CDISASM_X86_DECODE_FLAG_VPCLMULQDQ;
        case CDISASM_X86_GROUP_SHA:
            return CDISASM_X86_DECODE_FLAG_SHA;
        case CDISASM_X86_GROUP_SHA512:
            return CDISASM_X86_DECODE_FLAG_SHA512;
        case CDISASM_X86_GROUP_SM3:
            return CDISASM_X86_DECODE_FLAG_SM3;
        case CDISASM_X86_GROUP_SM4:
            return CDISASM_X86_DECODE_FLAG_SM4;
        case CDISASM_X86_GROUP_GFNI:
            return CDISASM_X86_DECODE_FLAG_GFNI;
        case CDISASM_X86_GROUP_LZCNT:
        case CDISASM_X86_GROUP_POPCNT:
        case CDISASM_X86_GROUP_TBM:
        case CDISASM_X86_GROUP_ADX:
            return CDISASM_X86_DECODE_FLAG_BITMANIP;
        case CDISASM_X86_GROUP_BMI1:
            return CDISASM_X86_DECODE_FLAG_BMI1;
        case CDISASM_X86_GROUP_BMI2:
            return CDISASM_X86_DECODE_FLAG_BMI2;
        case CDISASM_X86_GROUP_AVX512F:
        case CDISASM_X86_GROUP_AVX512ER:
        case CDISASM_X86_GROUP_AVX512PF:
        case CDISASM_X86_GROUP_AVX512VL:
        case CDISASM_X86_GROUP_AVX512_4VNNIW:
        case CDISASM_X86_GROUP_AVX512_4FMAPS:
        case CDISASM_X86_GROUP_AVX512VP2INTERSECT:
        case CDISASM_X86_GROUP_AVX512BF16:
        case CDISASM_X86_GROUP_AVX512FP16:
        case CDISASM_X86_GROUP_AVX512F_128:
        case CDISASM_X86_GROUP_AVX512F_128N:
        case CDISASM_X86_GROUP_AVX512F_256:
        case CDISASM_X86_GROUP_AVX512F_512:
        case CDISASM_X86_GROUP_AVX512F_SCALAR:
        case CDISASM_X86_GROUP_AVX512_GFNI_128:
        case CDISASM_X86_GROUP_AVX512_GFNI_256:
        case CDISASM_X86_GROUP_AVX512_GFNI_512:
        case CDISASM_X86_GROUP_AVX512DQ_128:
        case CDISASM_X86_GROUP_AVX512DQ_256:
        case CDISASM_X86_GROUP_AVX512DQ_512:
        case CDISASM_X86_GROUP_AVX512_VP2INTERSECT_128:
        case CDISASM_X86_GROUP_AVX512_VP2INTERSECT_256:
        case CDISASM_X86_GROUP_AVX512_VP2INTERSECT_512:
        case CDISASM_X86_GROUP_AVX512_FP16_128:
        case CDISASM_X86_GROUP_AVX512_FP16_128N:
        case CDISASM_X86_GROUP_AVX512_FP16_256:
        case CDISASM_X86_GROUP_AVX512_FP16_512:
        case CDISASM_X86_GROUP_AVX512_FP16_SCALAR:
        case CDISASM_X86_GROUP_AVX512_MOVZXC_128:
        case CDISASM_X86_GROUP_AVX512_MEDIAX_128:
        case CDISASM_X86_GROUP_AVX512_MEDIAX_256:
        case CDISASM_X86_GROUP_AVX512_MEDIAX_512:
            return CDISASM_X86_DECODE_FLAG_AVX512;
        case CDISASM_X86_GROUP_AVX512CD:
            return CDISASM_X86_DECODE_FLAG_AVX512_CD;
        case CDISASM_X86_GROUP_AVX512DQ:
            return CDISASM_X86_DECODE_FLAG_AVX512_DQ;
        case CDISASM_X86_GROUP_AVX512BW:
            return CDISASM_X86_DECODE_FLAG_AVX512_BW;
        case CDISASM_X86_GROUP_AVX512IFMA:
            return CDISASM_X86_DECODE_FLAG_AVX512_IFMA;
        case CDISASM_X86_GROUP_AVX512VBMI:
            return CDISASM_X86_DECODE_FLAG_AVX512_VBMI;
        case CDISASM_X86_GROUP_AVX512VNNI:
            return CDISASM_X86_DECODE_FLAG_AVX512_VNNI;
        case CDISASM_X86_GROUP_AVX512VBMI2:
            return CDISASM_X86_DECODE_FLAG_AVX512_VBMI2;
        case CDISASM_X86_GROUP_AVX512VPOPCNTDQ:
            return CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ;
        case CDISASM_X86_GROUP_AVX512BITALG:
            return CDISASM_X86_DECODE_FLAG_AVX512_BITALG;
        case CDISASM_X86_GROUP_AVX10_1:
        case CDISASM_X86_GROUP_AVX10_2:
        case CDISASM_X86_GROUP_AVX10_2_BF16_128:
        case CDISASM_X86_GROUP_AVX10_2_BF16_256:
        case CDISASM_X86_GROUP_AVX10_2_BF16_512:
        case CDISASM_X86_GROUP_AVX10_MOVRS_128:
        case CDISASM_X86_GROUP_AVX10_MOVRS_256:
        case CDISASM_X86_GROUP_AVX10_MOVRS_512:
            return CDISASM_X86_DECODE_FLAG_AVX10;
        case CDISASM_X86_GROUP_AMX_TILE:
            return CDISASM_X86_DECODE_FLAG_AMX_TILE;
        case CDISASM_X86_GROUP_AMX_INT8:
            return CDISASM_X86_DECODE_FLAG_AMX_INT8;
        case CDISASM_X86_GROUP_AMX_BF16:
            return CDISASM_X86_DECODE_FLAG_AMX_BF16;
        case CDISASM_X86_GROUP_AMX_FP16:
            return CDISASM_X86_DECODE_FLAG_AMX_FP16;
        case CDISASM_X86_GROUP_AMX_COMPLEX:
            return CDISASM_X86_DECODE_FLAG_AMX_COMPLEX;
        case CDISASM_X86_GROUP_AMX_FP8:
            return CDISASM_X86_DECODE_FLAG_AMX_FP8;
        case CDISASM_X86_GROUP_AMX_MOVRS:
            return CDISASM_X86_DECODE_FLAG_AMX_MOVRS;
        case CDISASM_X86_GROUP_AMX_AVX512:
            return CDISASM_X86_DECODE_FLAG_AMX_AVX512;
        case CDISASM_X86_GROUP_ACE_1:
            return CDISASM_X86_DECODE_FLAG_AMX;
        case CDISASM_X86_GROUP_APX_F_MSR_IMM:
        case CDISASM_X86_GROUP_APX_F_USER_MSR:
        case CDISASM_X86_GROUP_APX_F_CMPCCXADD:
        case CDISASM_X86_GROUP_APX_F:
            return CDISASM_X86_DECODE_FLAG_APX;
        case CDISASM_X86_GROUP_VMX:
        case CDISASM_X86_GROUP_VTX:
            return CDISASM_X86_DECODE_FLAG_VMX;
        case CDISASM_X86_GROUP_SVM:
            return CDISASM_X86_DECODE_FLAG_SVM;
        case CDISASM_X86_GROUP_SMX:
            return CDISASM_X86_DECODE_FLAG_SMX;
        case CDISASM_X86_GROUP_CPUID:
        case CDISASM_X86_GROUP_SEP:
        case CDISASM_X86_GROUP_MONITOR_MWAIT:
        case CDISASM_X86_GROUP_WAITPKG:
        case CDISASM_X86_GROUP_LWP:
        case CDISASM_X86_GROUP_FSGSBASE:
        case CDISASM_X86_GROUP_INVPCID:
        case CDISASM_X86_GROUP_RDPID:
        case CDISASM_X86_GROUP_SERIALIZE:
        case CDISASM_X86_GROUP_MOVDIRI:
        case CDISASM_X86_GROUP_MOVDIR64B:
        case CDISASM_X86_GROUP_WBNOINVD:
        case CDISASM_X86_GROUP_RDTSCP:
        case CDISASM_X86_GROUP_UINTR:
        case CDISASM_X86_GROUP_ENQCMD:
        case CDISASM_X86_GROUP_TDX:
        case CDISASM_X86_GROUP_VIA_PADLOCK_AES:
        case CDISASM_X86_GROUP_VIA_PADLOCK_MONTMUL:
        case CDISASM_X86_GROUP_VIA_PADLOCK_RNG:
        case CDISASM_X86_GROUP_VIA_PADLOCK_SHA:
        case CDISASM_X86_GROUP_USER_MSR:
        case CDISASM_X86_GROUP_MSRLIST:
        case CDISASM_X86_GROUP_MSR_IMM:
        case CDISASM_X86_GROUP_WRMSRNS:
            return CDISASM_X86_DECODE_FLAG_SYSTEM;
        case CDISASM_X86_GROUP_CET_IBT:
        case CDISASM_X86_GROUP_CET_SS:
            return CDISASM_X86_DECODE_FLAG_CET;
        case CDISASM_X86_GROUP_FXSR:
        case CDISASM_X86_GROUP_XSAVE:
        case CDISASM_X86_GROUP_XSAVEOPT:
        case CDISASM_X86_GROUP_XSAVEC:
        case CDISASM_X86_GROUP_XSAVES:
            return CDISASM_X86_DECODE_FLAG_STATE;
        case CDISASM_X86_GROUP_HLE:
        case CDISASM_X86_GROUP_RTM:
        case CDISASM_X86_GROUP_TSX_LDTRK:
            return CDISASM_X86_DECODE_FLAG_TRANSACTIONAL;
        case CDISASM_X86_GROUP_RDRAND:
        case CDISASM_X86_GROUP_RDSEED:
        case CDISASM_X86_GROUP_SGX:
        case CDISASM_X86_GROUP_MPX:
        case CDISASM_X86_GROUP_PKU:
            return CDISASM_X86_DECODE_FLAG_SECURITY;
        case CDISASM_X86_GROUP_PREFETCHW:
        case CDISASM_X86_GROUP_CLFLUSH:
        case CDISASM_X86_GROUP_PAUSE:
        case CDISASM_X86_GROUP_CLFLUSHOPT:
        case CDISASM_X86_GROUP_CLWB:
            return CDISASM_X86_DECODE_FLAG_MEMORY_HINTS;
        default:
            return CDISASM_X86_DECODE_FLAG_BASE;
    }
}

static int x86_name_is_undocumented(cdisasm_x86_name_id name_id)
{
    switch (name_id) {
        case CDISASM_X86_NAME_SALC:
        case CDISASM_X86_NAME_UDB:
        case CDISASM_X86_NAME_UD0:
        case CDISASM_X86_NAME_UD1:
        case CDISASM_X86_NAME_LOADALL286:
        case CDISASM_X86_NAME_LOADALL:
        case CDISASM_X86_NAME_INT1:
        case CDISASM_X86_NAME_FSTPNCE:
        case CDISASM_X86_NAME_FFREEP:
            return 1;
        default:
            return 0;
    }
}

static int x86_name_is_system(cdisasm_x86_name_id name_id)
{
    switch (name_id) {
        case CDISASM_X86_NAME_RDTSC:
        case CDISASM_X86_NAME_RDMSR:
        case CDISASM_X86_NAME_WRMSR:
        case CDISASM_X86_NAME_RDPMC:
        case CDISASM_X86_NAME_SYSCALL:
        case CDISASM_X86_NAME_SYSRET:
        case CDISASM_X86_NAME_INVD:
        case CDISASM_X86_NAME_WBINVD:
        case CDISASM_X86_NAME_WBNOINVD:
        case CDISASM_X86_NAME_INVLPG:
        case CDISASM_X86_NAME_CLTS:
        case CDISASM_X86_NAME_RDPID:
        case CDISASM_X86_NAME_SERIALIZE:
        case CDISASM_X86_NAME_MOVDIRI:
        case CDISASM_X86_NAME_MOVDIR64B:
        case CDISASM_X86_NAME_FXSAVE:
        case CDISASM_X86_NAME_FXSAVE64:
        case CDISASM_X86_NAME_FXRSTOR:
        case CDISASM_X86_NAME_FXRSTOR64:
        case CDISASM_X86_NAME_XSAVE:
        case CDISASM_X86_NAME_XSAVE64:
        case CDISASM_X86_NAME_XRSTOR:
        case CDISASM_X86_NAME_XRSTOR64:
        case CDISASM_X86_NAME_XSAVEOPT:
        case CDISASM_X86_NAME_XSAVEOPT64:
        case CDISASM_X86_NAME_XSAVEC:
        case CDISASM_X86_NAME_XSAVEC64:
        case CDISASM_X86_NAME_XSAVES:
        case CDISASM_X86_NAME_XSAVES64:
        case CDISASM_X86_NAME_XRSTORS:
        case CDISASM_X86_NAME_XRSTORS64:
        case CDISASM_X86_NAME_XGETBV:
        case CDISASM_X86_NAME_XSETBV:
        case CDISASM_X86_NAME_MONITOR:
        case CDISASM_X86_NAME_MWAIT:
        case CDISASM_X86_NAME_RDTSCP:
        case CDISASM_X86_NAME_INVPCID:
        case CDISASM_X86_NAME_RDFSBASE:
        case CDISASM_X86_NAME_RDGSBASE:
        case CDISASM_X86_NAME_WRFSBASE:
        case CDISASM_X86_NAME_WRGSBASE:
        case CDISASM_X86_NAME_RDPKRU:
        case CDISASM_X86_NAME_WRPKRU:
        case CDISASM_X86_NAME_ENCLS:
        case CDISASM_X86_NAME_ENCLU:
        case CDISASM_X86_NAME_ENCLV:
        case CDISASM_X86_NAME_XSUSLDTRK:
        case CDISASM_X86_NAME_XRESLDTRK:
        case CDISASM_X86_NAME_CLUI:
        case CDISASM_X86_NAME_SENDUIPI:
        case CDISASM_X86_NAME_STUI:
        case CDISASM_X86_NAME_TESTUI:
        case CDISASM_X86_NAME_UIRET:
        case CDISASM_X86_NAME_ENQCMD:
        case CDISASM_X86_NAME_ENQCMDS:
        case CDISASM_X86_NAME_URDMSR:
        case CDISASM_X86_NAME_UWRMSR:
        case CDISASM_X86_NAME_RDMSRLIST:
        case CDISASM_X86_NAME_WRMSRLIST:
        case CDISASM_X86_NAME_WRMSRNS:
            return 1;
        default:
            return 0;
    }
}

static int x86_name_is_fpu(cdisasm_x86_name_id name_id)
{
    /* The x87 mnemonic block is intentionally contiguous in the public,
     * append-only name-id table.  FISTTP also carries SSE3 as a CPU
     * prerequisite group, but its selectable opcode family is still x87. */
    return name_id == CDISASM_X86_NAME_WAIT
        || (name_id >= CDISASM_X86_NAME_F2XM1
            && name_id <= CDISASM_X86_NAME_FSTPNCE);
}

static int x86_name_is_memory_hint(cdisasm_x86_name_id name_id)
{
    switch (name_id) {
        case CDISASM_X86_NAME_PAUSE:
        case CDISASM_X86_NAME_PREFETCH:
        case CDISASM_X86_NAME_PREFETCHW:
        case CDISASM_X86_NAME_PREFETCHNTA:
        case CDISASM_X86_NAME_PREFETCHT0:
        case CDISASM_X86_NAME_PREFETCHT1:
        case CDISASM_X86_NAME_PREFETCHT2:
        case CDISASM_X86_NAME_PREFETCHRST2:
        case CDISASM_X86_NAME_PREFETCHWT1:
        case CDISASM_X86_NAME_PREFETCHIT0:
        case CDISASM_X86_NAME_PREFETCHIT1:
        case CDISASM_X86_NAME_CLFLUSH:
        case CDISASM_X86_NAME_CLFLUSHOPT:
        case CDISASM_X86_NAME_CLWB:
            return 1;
        default:
            return 0;
    }
}

static int x86_encoding_is_undocumented_alias(
    const uint8_t *code,
    const cdisasm_instruction *instruction)
{
    uint8_t opcode;
    uint8_t modrm;
    uint8_t extension;

    if ((instruction->opcode_flags
         & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2)) != 0) {
        return 0;
    }

    opcode = code[instruction->encoding.opcode_offset];
    modrm = instruction->encoding.modrm;
    extension = (uint8_t)((modrm >> 3) & UINT8_C(7));

    /* Undocumented aliases whose mnemonic is shared with a documented form. */
    if (opcode == UINT8_C(0x82)) {
        return 1;
    }
    if ((opcode == UINT8_C(0xc0) || opcode == UINT8_C(0xc1)
         || opcode == UINT8_C(0xd0) || opcode == UINT8_C(0xd1)
         || opcode == UINT8_C(0xd2) || opcode == UINT8_C(0xd3))
        && extension == UINT8_C(6)) {
        return 1;
    }
    if ((opcode == UINT8_C(0xf6) || opcode == UINT8_C(0xf7))
        && extension == UINT8_C(1)) {
        return 1;
    }

    /* Early x87 compatibility aliases that spell an otherwise documented
     * mnemonic.  Their register ModRM ranges are intentionally accepted by
     * the decoder but remain opt-in as undocumented encodings. */
    if (opcode == UINT8_C(0xdc)
        && (modrm >= UINT8_C(0xd0) && modrm <= UINT8_C(0xdf))) {
        return 1;
    }
    if (opcode == UINT8_C(0xdd)
        && (modrm >= UINT8_C(0xc8) && modrm <= UINT8_C(0xcf))) {
        return 1;
    }
    if (opcode == UINT8_C(0xde)
        && (modrm >= UINT8_C(0xd0) && modrm <= UINT8_C(0xd7))) {
        return 1;
    }
    if (opcode == UINT8_C(0xdf)
        && (modrm >= UINT8_C(0xc8) && modrm <= UINT8_C(0xdf))) {
        return 1;
    }
    return 0;
}

static cdisasm_x86_decode_option x86_instruction_decode_flags(
    const uint8_t *code,
    const cdisasm_instruction *instruction)
{
    cdisasm_x86_decode_option required = CDISASM_X86_DECODE_FLAG_BASE;
    cdisasm_x86_decode_option qualifiers = CDISASM_X86_DECODE_FLAG_BASE;
    uint8_t index;

    for (index = 0; index < instruction->x86_group_count; ++index) {
        required |= x86_group_decode_flag(instruction->x86_group_ids[index]);
    }
    if ((instruction->opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0
        || x86_name_is_system(instruction->name_id)) {
        required |= CDISASM_X86_DECODE_FLAG_SYSTEM;
    }
    if (x86_name_is_undocumented(instruction->name_id)
        || x86_encoding_is_undocumented_alias(code, instruction)) {
        qualifiers |= CDISASM_X86_DECODE_FLAG_UNDOCUMENTED;
    }
    if (x86_name_is_memory_hint(instruction->name_id)) {
        required |= CDISASM_X86_DECODE_FLAG_MEMORY_HINTS;
    }
    if (x86_name_is_fpu(instruction->name_id)) {
        return CDISASM_X86_DECODE_FLAG_FPU | qualifiers;
    }
    if ((instruction->opcode_flags & CDISASM_PREFIX_EVEX) != 0
        && (instruction->name_id == CDISASM_X86_NAME_VSM4KEY4
            || instruction->name_id == CDISASM_X86_NAME_VSM4RNDS4)) {
        /* Unlike most EVEX spellings, EVEX SM4 has no AVX-512 route.  Keep
         * its SM4 family selection and AVX10.2 encoding authorization
         * independently visible to callers. */
        return CDISASM_X86_DECODE_FLAG_SM4
            | CDISASM_X86_DECODE_FLAG_AVX10;
    }
    if (instruction->name_id == CDISASM_X86_NAME_VGF2P8AFFINEINVQB
        || instruction->name_id == CDISASM_X86_NAME_VGF2P8AFFINEQB
        || instruction->name_id == CDISASM_X86_NAME_VGF2P8MULB) {
        const cdisasm_x86_decode_option encoding_family =
            (instruction->opcode_flags & CDISASM_PREFIX_EVEX) == 0u
            ? CDISASM_X86_DECODE_FLAG_AVX
            : cdisasm_instruction_has_x86_group(
                    instruction, CDISASM_X86_GROUP_AVX10_1)
                ? CDISASM_X86_DECODE_FLAG_AVX10
                : CDISASM_X86_DECODE_FLAG_AVX512;

        /* GFNI is an independent CPUID/runtime prerequisite on every VEX,
         * AVX-512, and AVX10 route.  An exact ISA-set bit below selects the
         * encoded width but must not replace either functional gate. */
        return encoding_family | CDISASM_X86_DECODE_FLAG_GFNI
            | (required & CDISASM_X86_DECODE_FLAG_APX);
    }
    if (instruction->name_id == CDISASM_X86_NAME_VPTERNLOGD
        || instruction->name_id == CDISASM_X86_NAME_VPTERNLOGQ) {
        const cdisasm_x86_decode_option encoding_family =
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX10_1)
                ? CDISASM_X86_DECODE_FLAG_AVX10
                : CDISASM_X86_DECODE_FLAG_AVX512;

        /* AVX10.1 is an alternate EVEX foundation for this AVX512F row.
         * APX remains an independent gate only when B4/U0 is consumed. */
        return encoding_family
            | (required & CDISASM_X86_DECODE_FLAG_APX);
    }
    if (instruction->name_id >= CDISASM_X86_NAME_VPTESTMB
        && instruction->name_id <= CDISASM_X86_NAME_VPTESTNMW) {
        const cdisasm_x86_decode_option encoding_family =
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX10_1)
                ? CDISASM_X86_DECODE_FLAG_AVX10
                : CDISASM_X86_DECODE_FLAG_AVX512;

        return encoding_family
            | (required & CDISASM_X86_DECODE_FLAG_APX);
    }
    if ((instruction->opcode_flags & CDISASM_PREFIX_EVEX) != 0
        && instruction->name_id >= CDISASM_X86_NAME_VPDPBSSD
        && instruction->name_id <= CDISASM_X86_NAME_VPDPBUUDS) {
        /* These six mnemonics also have VEX AVX-VNNI-INT8 spellings.  Their
         * EVEX forms are distinct AVX10.2/FBIT allocations.  Keep that
         * functional selector while independently requiring APX when B4/U0
         * address extensions attach the APX_F group. */
        return CDISASM_X86_DECODE_FLAG_AVX10
            | (required & CDISASM_X86_DECODE_FLAG_APX);
    }
    if (instruction->name_id == CDISASM_X86_NAME_MOVNTI) {
        /* MOVNTI is selected by SSE2 even when APX promotes the legacy row
         * through REX2 map 1.  Keep APX as an independent encoding gate
         * instead of letting the generic most-specific-family rule replace
         * the functional SSE2 selector. */
        return CDISASM_X86_DECODE_FLAG_SSE2
            | (required & CDISASM_X86_DECODE_FLAG_APX);
    }
    if (instruction->name_id == CDISASM_X86_NAME_LDDQU) {
        /* REX2 map 1 is an APX encoding route for the historical SSE3
         * instruction.  Keep the functional SSE3 selector and APX
         * authorization independently visible to callers. */
        return CDISASM_X86_DECODE_FLAG_SSE3
            | (required & CDISASM_X86_DECODE_FLAG_APX);
    }
    if (instruction->name_id == CDISASM_X86_NAME_VMOVNTDQA) {
        if ((instruction->opcode_flags & CDISASM_PREFIX_EVEX) != 0u) {
            return CDISASM_X86_DECODE_FLAG_AVX512
                | (required & CDISASM_X86_DECODE_FLAG_APX);
        }
        return instruction->form_id == UINT16_C(5866)
            ? CDISASM_X86_DECODE_FLAG_AVX2
            : CDISASM_X86_DECODE_FLAG_AVX;
    }
    if (instruction->name_id == CDISASM_X86_NAME_VMOVQ) {
        return (instruction->opcode_flags & CDISASM_PREFIX_EVEX) != 0u
            ? CDISASM_X86_DECODE_FLAG_AVX512
                | (required & CDISASM_X86_DECODE_FLAG_APX)
            : CDISASM_X86_DECODE_FLAG_AVX;
    }
    if (instruction->name_id >= CDISASM_X86_NAME_VMOVRSB
        && instruction->name_id <= CDISASM_X86_NAME_VMOVRSW) {
        return CDISASM_X86_DECODE_FLAG_AVX10
            | (required & CDISASM_X86_DECODE_FLAG_APX);
    }
    if (instruction->name_id == CDISASM_X86_NAME_MOVNTDQ
        || instruction->name_id == CDISASM_X86_NAME_MOVNTPD) {
        return CDISASM_X86_DECODE_FLAG_SSE2
            | (required & CDISASM_X86_DECODE_FLAG_APX);
    }
    if (instruction->name_id == CDISASM_X86_NAME_MOVNTPS) {
        return CDISASM_X86_DECODE_FLAG_SSE
            | (required & CDISASM_X86_DECODE_FLAG_APX);
    }
    if (instruction->name_id == CDISASM_X86_NAME_MOVNTQ) {
        return CDISASM_X86_DECODE_FLAG_MMX
            | (required & CDISASM_X86_DECODE_FLAG_APX);
    }
    if (instruction->name_id == CDISASM_X86_NAME_MOVNTSD
        || instruction->name_id == CDISASM_X86_NAME_MOVNTSS) {
        return CDISASM_X86_DECODE_FLAG_SSE4A
            | (required & CDISASM_X86_DECODE_FLAG_APX);
    }
    if (instruction->name_id == CDISASM_X86_NAME_VMOVNTDQ
        || instruction->name_id == CDISASM_X86_NAME_VMOVNTPD
        || instruction->name_id == CDISASM_X86_NAME_VMOVNTPS) {
        return (instruction->opcode_flags & CDISASM_PREFIX_EVEX) != 0
            ? CDISASM_X86_DECODE_FLAG_AVX512
                | (required & CDISASM_X86_DECODE_FLAG_APX)
            : CDISASM_X86_DECODE_FLAG_AVX;
    }
    if (cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_ACE_1)) {
        /* ACE is selected through the AMX umbrella; optional EVEX.B4
         * admission remains an independent APX requirement. */
        return CDISASM_X86_DECODE_FLAG_AMX
            | (required & CDISASM_X86_DECODE_FLAG_APX);
    }
    if (cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_MSRLIST)
        || cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_MSR_IMM)
        || cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_WRMSRNS)
        || cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_APX_F_MSR_IMM)) {
        /* Each late MSR ISA_SET has an exact bitmap opt-in checked below.
         * That bit is complete for its privileged/system classification;
         * preserve only the independent APX requirement of REX2/APX forms. */
        return CDISASM_X86_DECODE_FLAG_SYSTEM
            | (required & CDISASM_X86_DECODE_FLAG_APX);
    }
    if (cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_VTX)) {
        /* The exact VTX bitmap bit supplies VMX/system authorization.  Keep
         * APX independent when REX2 transports the same virtualization form. */
        return CDISASM_X86_DECODE_FLAG_VMX
            | (required & CDISASM_X86_DECODE_FLAG_APX);
    }
    if (cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_PCONFIG)) {
        /* The exact high PCONFIG bit is checked separately.  Preserve both
         * its CPL0 classification and the independent APX requirement added
         * by a REX2 spelling instead of collapsing to the first umbrella. */
        return CDISASM_X86_DECODE_FLAG_SYSTEM
            | (required & CDISASM_X86_DECODE_FLAG_APX);
    }
    if (cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_PBNDKB)) {
        /* PBNDKB's exact ISA_SET bit is its complete system-family opt-in;
         * REX2 remains an independently selectable APX encoding. */
        return CDISASM_X86_DECODE_FLAG_SYSTEM
            | (required & CDISASM_X86_DECODE_FLAG_APX);
    }
    if (cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_SMAP)) {
        /* The exact SMAP bit is checked independently below.  Its CPL0
         * classification is supplied by that opt-in, while an accepted
         * REX2-map-1 spelling retains a separate APX requirement. */
        return CDISASM_X86_DECODE_FLAG_SYSTEM
            | (required & CDISASM_X86_DECODE_FLAG_APX);
    }
    if (cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_ICACHE_PREFETCH)) {
        /* Likewise, the exact ICACHE_PREFETCH bit supplies the memory-hint
         * umbrella while an accepted REX2 spelling still requires APX. */
        return CDISASM_X86_DECODE_FLAG_MEMORY_HINTS
            | (required & CDISASM_X86_DECODE_FLAG_APX);
    }
    if ((instruction->name_id == CDISASM_X86_NAME_PREFETCHRST2
            && cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_MOVRS))
        || (instruction->name_id == CDISASM_X86_NAME_PREFETCHWT1
            && cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_PREFETCHWT1))) {
        /* The exact extended-ISA bit supplies the memory-hint umbrella.
         * Preserve APX as an independent requirement for REX2 spellings. */
        return CDISASM_X86_DECODE_FLAG_MEMORY_HINTS
            | (required & CDISASM_X86_DECODE_FLAG_APX);
    }
    if (cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AMD_INVLPGB)
        || cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_SNP)) {
        /* Their exact high ISA_SET bits are checked separately.  Preserve
         * the independent APX requirement of an accepted REX2 spelling. */
        return CDISASM_X86_DECODE_FLAG_SYSTEM
            | (required & CDISASM_X86_DECODE_FLAG_APX);
    }
    if ((instruction->name_id >= CDISASM_X86_NAME_VPCOMPRESSB
            && instruction->name_id <= CDISASM_X86_NAME_VPEXPANDQ)
        || instruction->name_id == CDISASM_X86_NAME_VCOMPRESSPD
        || instruction->name_id == CDISASM_X86_NAME_VCOMPRESSPS
        || instruction->name_id == CDISASM_X86_NAME_VEXPANDPD
        || instruction->name_id == CDISASM_X86_NAME_VEXPANDPS) {
        return CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND;
    }
    if (instruction->name_id == CDISASM_X86_NAME_VPOPCNTB
        || instruction->name_id == CDISASM_X86_NAME_VPOPCNTW
        || instruction->name_id == CDISASM_X86_NAME_VPSHUFBITQMB) {
        return CDISASM_X86_DECODE_FLAG_AVX512_BITALG;
    }
    if (instruction->name_id == CDISASM_X86_NAME_VPOPCNTD
        || instruction->name_id == CDISASM_X86_NAME_VPOPCNTQ) {
        return CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ;
    }
    if (instruction->name_id >= CDISASM_X86_NAME_VPCONFLICTD
        && instruction->name_id <= CDISASM_X86_NAME_VPBROADCASTMW2D) {
        return CDISASM_X86_DECODE_FLAG_AVX512_CD;
    }
    if (instruction->name_id == CDISASM_X86_NAME_VPDPBUSD
        || (instruction->name_id >= CDISASM_X86_NAME_VPDPBUSDS
            && instruction->name_id <= CDISASM_X86_NAME_VPDPWSSDS)) {
        if ((instruction->opcode_flags & CDISASM_PREFIX_VEX) != 0) {
            return CDISASM_X86_DECODE_FLAG_AVX_VNNI;
        }
        /* Keep the functional family selector stable when AVX10.1 supplies
         * the EVEX foundation in place of AVX512F/VL/VNNI CPUID bits. */
        return CDISASM_X86_DECODE_FLAG_AVX512_VNNI;
    }
    if (instruction->name_id == CDISASM_X86_NAME_VPERMB
        || (instruction->name_id >= CDISASM_X86_NAME_VPERMI2B
            && instruction->name_id
                <= CDISASM_X86_NAME_VPMULTISHIFTQB)) {
        /* Keep the functional selector stable when AVX10.1 supplies the
         * EVEX foundation instead of AVX512F/VL/VBMI CPUID bits. */
        return CDISASM_X86_DECODE_FLAG_AVX512_VBMI;
    }
    /* Assign an instruction to its most-specific selectable family. CPU
     * prerequisite relationships remain the CPU profile's responsibility;
     * selecting AES, for example, does not also require the SSE2 flag. */
#define RETURN_FAMILY(flag) \
    do { \
        if ((required & (flag)) != 0) { \
            return (flag); \
        } \
    } while (0)
    if (qualifiers != CDISASM_X86_DECODE_FLAG_BASE) {
        return qualifiers;
    }
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_VMX);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_SVM);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_SMX);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_CET);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_STATE);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_TRANSACTIONAL);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_SECURITY);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_MEMORY_HINTS);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_SYSTEM);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_APX);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_AMX_AVX512);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_AMX_MOVRS);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_AMX_FP8);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_AMX_COMPLEX);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_AMX_FP16);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_AMX_BF16);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_AMX_INT8);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_AMX_TILE);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_AMX);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_SM4);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_SM3);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_AVX10);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_VAES);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_AES);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_VPCLMULQDQ);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_PCLMUL);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_SHA512);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_SHA);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_GFNI);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_AVX512_VBMI2);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_AVX512_BITALG);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_AVX512_CD);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_AVX512_IFMA);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_AVX512_VBMI);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_AVX512_VNNI);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_AVX512_DQ);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_AVX512_BW);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_AVX512);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_BMI2);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_BMI1);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_BITMANIP);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_FMA4);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_XOP);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_FMA3);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_F16C);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT8);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_AVX_VNNI);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_AVX2);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_AVX);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_SSE41);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_SSE42);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_SSE4A);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_SSE4);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_SSSE3);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_SSE3);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_SSE2);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_SSE);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_3DNOW);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_MMX);
    RETURN_FAMILY(CDISASM_X86_DECODE_FLAG_FPU);
#undef RETURN_FAMILY
    return CDISASM_X86_DECODE_FLAG_BASE;
}

#if USE_EXTRA_OPCODES
static int x86_decode_flags_admit(
    cdisasm_x86_decode_option required,
    const cdisasm_x86_decode_flags *selected_flags,
    int is_ace_1,
    int is_rao_int,
    int is_apx_rao_int,
    int is_user_msr,
    int is_apx_user_msr,
    int is_msrlist,
    int is_msr_imm,
    int is_apx_msr_imm,
    int is_wrmsrns,
    int is_keylocker,
    int is_keylocker_wide,
    int is_hreset,
    int is_cldemote,
    int is_clzero,
    int is_rdpru,
    int is_mcommit,
    int is_monitorx,
    int is_amd_invlpgb,
    int is_snp,
    int is_pconfig,
    int is_pbndkb,
    int is_icache_prefetch,
    int is_prefetchrst2,
    int is_prefetchwt1,
    int is_ptwrite,
    int is_avx_gfni,
    int is_avx512_gfni_128,
    int is_avx512_gfni_256,
    int is_avx512_gfni_512,
    int is_avx512f_128,
    int is_avx512f_128n,
    int is_avx512f_256,
    int is_avx512f_512,
    int is_avx512f_scalar,
    int is_avx512bw_128,
    int is_avx512bw_256,
    int is_avx512bw_512,
    int is_avx512dq_128,
    int is_avx512dq_256,
    int is_avx512dq_512,
    int is_avx512_vp2intersect_128,
    int is_avx512_vp2intersect_256,
    int is_avx512_vp2intersect_512,
    int is_avx512_fp16_128,
    int is_avx512_fp16_128n,
    int is_avx512_fp16_256,
    int is_avx512_fp16_512,
    int is_avx512_fp16_scalar,
    int is_avx512_movzxc_128,
    int is_avx512_mediax_128,
    int is_avx512_mediax_256,
    int is_avx512_mediax_512,
    int is_avx10_2_bf16_128,
    int is_avx10_2_bf16_256,
    int is_avx10_2_bf16_512,
    int is_avx10_movrs_128,
    int is_avx10_movrs_256,
    int is_avx10_movrs_512,
    int is_vtx,
    int is_smap,
    int is_sse4_isa_set,
    int is_via_padlock_aes,
    int is_via_padlock_montmul,
    int is_via_padlock_rng,
    int is_via_padlock_sha)
{
    cdisasm_x86_decode_option selected = selected_flags == NULL
        ? CDISASM_X86_DECODE_FLAG_BASE
        : selected_flags->bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP];
    const cdisasm_x86_decode_option specific_avx512 =
        CDISASM_X86_DECODE_FLAG_AVX512_VBMI2
        | CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ
        | CDISASM_X86_DECODE_FLAG_AVX512_BITALG
        | CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND
        | CDISASM_X86_DECODE_FLAG_AVX512_IFMA
        | CDISASM_X86_DECODE_FLAG_AVX512_VBMI
        | CDISASM_X86_DECODE_FLAG_AVX512_VNNI
        | CDISASM_X86_DECODE_FLAG_AVX512_DQ
        | CDISASM_X86_DECODE_FLAG_AVX512_BW
        | CDISASM_X86_DECODE_FLAG_AVX512_CD;
    const cdisasm_x86_decode_option specific_amx =
        CDISASM_X86_DECODE_FLAG_AMX_TILE
        | CDISASM_X86_DECODE_FLAG_AMX_INT8
        | CDISASM_X86_DECODE_FLAG_AMX_BF16
        | CDISASM_X86_DECODE_FLAG_AMX_FP16
        | CDISASM_X86_DECODE_FLAG_AMX_COMPLEX
        | CDISASM_X86_DECODE_FLAG_AMX_FP8
        | CDISASM_X86_DECODE_FLAG_AMX_MOVRS
        | CDISASM_X86_DECODE_FLAG_AMX_AVX512;

    if (is_ace_1 && selected_flags != NULL
        && cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_ACE_1)) {
        selected |= CDISASM_X86_DECODE_FLAG_AMX;
    }
    if (is_via_padlock_aes
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_VIA_PADLOCK_AES)) {
        return 0;
    } else if (is_via_padlock_aes) {
        selected |= CDISASM_X86_DECODE_FLAG_SYSTEM;
    }
    if (is_via_padlock_montmul
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_VIA_PADLOCK_MONTMUL)) {
        return 0;
    } else if (is_via_padlock_montmul) {
        selected |= CDISASM_X86_DECODE_FLAG_SYSTEM;
    }
    if (is_via_padlock_rng
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_VIA_PADLOCK_RNG)) {
        return 0;
    } else if (is_via_padlock_rng) {
        selected |= CDISASM_X86_DECODE_FLAG_SYSTEM;
    }
    if (is_via_padlock_sha
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_VIA_PADLOCK_SHA)) {
        return 0;
    } else if (is_via_padlock_sha) {
        selected |= CDISASM_X86_DECODE_FLAG_SYSTEM;
    }
    if (is_rao_int
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_RAO_INT)) {
        return 0;
    }
    if (is_apx_rao_int
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_APX_F_RAO_INT)) {
        return 0;
    }
    if (is_user_msr
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_USER_MSR)) {
        return 0;
    } else if (is_user_msr) {
        selected |= CDISASM_X86_DECODE_FLAG_SYSTEM;
    }
    if (is_apx_user_msr
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_APX_F_USER_MSR)) {
        return 0;
    } else if (is_apx_user_msr) {
        selected |= CDISASM_X86_DECODE_FLAG_APX
            | CDISASM_X86_DECODE_FLAG_SYSTEM;
    }
    if (is_msrlist
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_MSRLIST)) {
        return 0;
    } else if (is_msrlist) {
        selected |= CDISASM_X86_DECODE_FLAG_SYSTEM;
    }
    if (is_msr_imm
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_MSR_IMM)) {
        return 0;
    } else if (is_msr_imm) {
        selected |= CDISASM_X86_DECODE_FLAG_SYSTEM;
    }
    if (is_apx_msr_imm
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_APX_F_MSR_IMM)) {
        return 0;
    } else if (is_apx_msr_imm) {
        selected |= CDISASM_X86_DECODE_FLAG_APX
            | CDISASM_X86_DECODE_FLAG_SYSTEM;
    }
    if (is_wrmsrns
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_WRMSRNS)) {
        return 0;
    } else if (is_wrmsrns) {
        selected |= CDISASM_X86_DECODE_FLAG_SYSTEM;
    }
    if (is_keylocker
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_KEYLOCKER)) {
        return 0;
    } else if (is_keylocker) {
        /* KEYLOCKER is the exact opt-in for both its CPL3 operations and
         * privileged LOADIWKEY; do not require a second SYSTEM opt-in. */
        selected |= CDISASM_X86_DECODE_FLAG_SYSTEM;
    }
    if (is_keylocker_wide
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_KEYLOCKER_WIDE)) {
        return 0;
    }
    if (is_hreset
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_HRESET)) {
        return 0;
    } else if (is_hreset) {
        /* HRESET's exact ISA_SET bit is the complete caller opt-in.  Its CPL0
         * metadata must not impose a second, unrelated SYSTEM-bit gate. */
        selected |= CDISASM_X86_DECODE_FLAG_SYSTEM;
    }
    if (is_cldemote
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_CLDEMOTE)) {
        return 0;
    }
    if (is_clzero
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_CLZERO)) {
        return 0;
    }
    if (is_rdpru
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_RDPRU)) {
        return 0;
    }
    if (is_mcommit
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_MCOMMIT)) {
        return 0;
    }
    if (is_monitorx
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_MONITORX)) {
        return 0;
    }
    if (is_amd_invlpgb
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_AMD_INVLPGB)) {
        return 0;
    } else if (is_amd_invlpgb) {
        selected |= CDISASM_X86_DECODE_FLAG_SYSTEM;
    }
    if (is_snp
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_SNP)) {
        return 0;
    } else if (is_snp) {
        selected |= CDISASM_X86_DECODE_FLAG_SYSTEM;
    }
    if (is_pconfig
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_PCONFIG)) {
        return 0;
    } else if (is_pconfig) {
        /* PCONFIG's exact ISA_SET bit is the complete caller opt-in.  Its CPL0
         * metadata must not impose a second, unrelated SYSTEM-bit gate. */
        selected |= CDISASM_X86_DECODE_FLAG_SYSTEM;
    }
    if (is_pbndkb
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_PBNDKB)) {
        return 0;
    } else if (is_pbndkb) {
        selected |= CDISASM_X86_DECODE_FLAG_SYSTEM;
    }
    if (is_icache_prefetch
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_ICACHE_PREFETCH)) {
        return 0;
    } else if (is_icache_prefetch) {
        selected |= CDISASM_X86_DECODE_FLAG_MEMORY_HINTS;
    }
    if (is_prefetchrst2
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_MOVRS)) {
        return 0;
    } else if (is_prefetchrst2) {
        selected |= CDISASM_X86_DECODE_FLAG_MEMORY_HINTS;
    }
    if (is_prefetchwt1
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_PREFETCHWT1)) {
        return 0;
    } else if (is_prefetchwt1) {
        selected |= CDISASM_X86_DECODE_FLAG_MEMORY_HINTS;
    }
    if (is_ptwrite
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_PTWRITE)) {
        return 0;
    }
    if (is_avx_gfni
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_AVX_GFNI)) {
        return 0;
    }
    if (is_avx512_gfni_128
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_AVX512_GFNI_128)) {
        return 0;
    }
    if (is_avx512_gfni_256
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_AVX512_GFNI_256)) {
        return 0;
    }
    if (is_avx512_gfni_512
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_AVX512_GFNI_512)) {
        return 0;
    }
    if (is_avx512f_128
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_AVX512F_128)) {
        return 0;
    } else if (is_avx512f_128) {
        selected |= CDISASM_X86_DECODE_FLAG_AVX512;
    }
    if (is_avx512f_128n
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_AVX512F_128N)) {
        return 0;
    } else if (is_avx512f_128n) {
        selected |= CDISASM_X86_DECODE_FLAG_AVX512;
    }
    if (is_avx512f_256
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_AVX512F_256)) {
        return 0;
    } else if (is_avx512f_256) {
        selected |= CDISASM_X86_DECODE_FLAG_AVX512;
    }
    if (is_avx512f_512
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_AVX512F_512)) {
        return 0;
    } else if (is_avx512f_512) {
        selected |= CDISASM_X86_DECODE_FLAG_AVX512;
    }
    if (is_avx512f_scalar
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_AVX512F_SCALAR)) {
        return 0;
    } else if (is_avx512f_scalar) {
        selected |= CDISASM_X86_DECODE_FLAG_AVX512;
    }
    if (is_avx512bw_128
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_AVX512BW_128)) {
        return 0;
    } else if (is_avx512bw_128) {
        selected |= CDISASM_X86_DECODE_FLAG_AVX512
            | CDISASM_X86_DECODE_FLAG_AVX512_BW;
    }
    if (is_avx512bw_256
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_AVX512BW_256)) {
        return 0;
    } else if (is_avx512bw_256) {
        selected |= CDISASM_X86_DECODE_FLAG_AVX512
            | CDISASM_X86_DECODE_FLAG_AVX512_BW;
    }
    if (is_avx512bw_512
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_AVX512BW_512)) {
        return 0;
    } else if (is_avx512bw_512) {
        selected |= CDISASM_X86_DECODE_FLAG_AVX512
            | CDISASM_X86_DECODE_FLAG_AVX512_BW;
    }
    if (is_avx512dq_128
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_AVX512DQ_128)) {
        return 0;
    } else if (is_avx512dq_128) {
        selected |= CDISASM_X86_DECODE_FLAG_AVX512
            | CDISASM_X86_DECODE_FLAG_AVX512_DQ;
    }
    if (is_avx512dq_256
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_AVX512DQ_256)) {
        return 0;
    } else if (is_avx512dq_256) {
        selected |= CDISASM_X86_DECODE_FLAG_AVX512
            | CDISASM_X86_DECODE_FLAG_AVX512_DQ;
    }
    if (is_avx512dq_512
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_AVX512DQ_512)) {
        return 0;
    } else if (is_avx512dq_512) {
        selected |= CDISASM_X86_DECODE_FLAG_AVX512
            | CDISASM_X86_DECODE_FLAG_AVX512_DQ;
    }
    if (is_avx512_vp2intersect_128
        && !cdisasm_decode_flags_test_bit(
            selected_flags,
            CDISASM_X86_DECODE_BIT_AVX512_VP2INTERSECT_128)) {
        return 0;
    } else if (is_avx512_vp2intersect_128) {
        selected |= CDISASM_X86_DECODE_FLAG_AVX512;
    }
    if (is_avx512_vp2intersect_256
        && !cdisasm_decode_flags_test_bit(
            selected_flags,
            CDISASM_X86_DECODE_BIT_AVX512_VP2INTERSECT_256)) {
        return 0;
    } else if (is_avx512_vp2intersect_256) {
        selected |= CDISASM_X86_DECODE_FLAG_AVX512;
    }
    if (is_avx512_vp2intersect_512
        && !cdisasm_decode_flags_test_bit(
            selected_flags,
            CDISASM_X86_DECODE_BIT_AVX512_VP2INTERSECT_512)) {
        return 0;
    } else if (is_avx512_vp2intersect_512) {
        selected |= CDISASM_X86_DECODE_FLAG_AVX512;
    }
    if (is_avx512_fp16_128
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_AVX512_FP16_128)) {
        return 0;
    } else if (is_avx512_fp16_128) {
        selected |= CDISASM_X86_DECODE_FLAG_AVX512
            | CDISASM_X86_DECODE_FLAG_AVX10;
    }
    if (is_avx512_fp16_128n
        && !cdisasm_decode_flags_test_bit(
            selected_flags,
            CDISASM_X86_DECODE_BIT_AVX512_FP16_128N)) {
        return 0;
    } else if (is_avx512_fp16_128n) {
        /* The exact ISA-set bit admits either the legacy AVX512-FP16 route
         * or its AVX10.1 promotion. */
        selected |= CDISASM_X86_DECODE_FLAG_AVX512
            | CDISASM_X86_DECODE_FLAG_AVX10;
    }
    if (is_avx512_fp16_256
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_AVX512_FP16_256)) {
        return 0;
    } else if (is_avx512_fp16_256) {
        selected |= CDISASM_X86_DECODE_FLAG_AVX512
            | CDISASM_X86_DECODE_FLAG_AVX10;
    }
    if (is_avx512_fp16_512
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_AVX512_FP16_512)) {
        return 0;
    } else if (is_avx512_fp16_512) {
        selected |= CDISASM_X86_DECODE_FLAG_AVX512
            | CDISASM_X86_DECODE_FLAG_AVX10;
    }
    if (is_avx512_fp16_scalar
        && !cdisasm_decode_flags_test_bit(
            selected_flags,
            CDISASM_X86_DECODE_BIT_AVX512_FP16_SCALAR)) {
        return 0;
    } else if (is_avx512_fp16_scalar) {
        /* The exact ISA-set bit is a complete opt-in for either the legacy
         * AVX512-FP16 route or its AVX10.1 promotion. */
        selected |= CDISASM_X86_DECODE_FLAG_AVX512
            | CDISASM_X86_DECODE_FLAG_AVX10;
    }
    if (is_avx512_movzxc_128
        && !cdisasm_decode_flags_test_bit(
            selected_flags,
            CDISASM_X86_DECODE_BIT_AVX512_MOVZXC_128)) {
        return 0;
    } else if (is_avx512_movzxc_128) {
        selected |= CDISASM_X86_DECODE_FLAG_AVX512
            | CDISASM_X86_DECODE_FLAG_AVX10;
    }
    if (is_avx512_mediax_128
        && !cdisasm_decode_flags_test_bit(
            selected_flags,
            CDISASM_X86_DECODE_BIT_AVX512_MEDIAX_128)) {
        return 0;
    } else if (is_avx512_mediax_128) {
        selected |= CDISASM_X86_DECODE_FLAG_AVX512
            | CDISASM_X86_DECODE_FLAG_AVX10;
    }
    if (is_avx512_mediax_256
        && !cdisasm_decode_flags_test_bit(
            selected_flags,
            CDISASM_X86_DECODE_BIT_AVX512_MEDIAX_256)) {
        return 0;
    } else if (is_avx512_mediax_256) {
        selected |= CDISASM_X86_DECODE_FLAG_AVX512
            | CDISASM_X86_DECODE_FLAG_AVX10;
    }
    if (is_avx512_mediax_512
        && !cdisasm_decode_flags_test_bit(
            selected_flags,
            CDISASM_X86_DECODE_BIT_AVX512_MEDIAX_512)) {
        return 0;
    } else if (is_avx512_mediax_512) {
        selected |= CDISASM_X86_DECODE_FLAG_AVX512
            | CDISASM_X86_DECODE_FLAG_AVX10;
    }
    if (is_avx10_2_bf16_128
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_AVX10_2_BF16_128)) {
        return 0;
    } else if (is_avx10_2_bf16_128) {
        selected |= CDISASM_X86_DECODE_FLAG_AVX10;
    }
    if (is_avx10_2_bf16_256
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_AVX10_2_BF16_256)) {
        return 0;
    } else if (is_avx10_2_bf16_256) {
        selected |= CDISASM_X86_DECODE_FLAG_AVX10;
    }
    if (is_avx10_2_bf16_512
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_AVX10_2_BF16_512)) {
        return 0;
    } else if (is_avx10_2_bf16_512) {
        selected |= CDISASM_X86_DECODE_FLAG_AVX10;
    }
    if (is_avx10_movrs_128
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_AVX10_MOVRS_128)) {
        return 0;
    } else if (is_avx10_movrs_128) {
        selected |= CDISASM_X86_DECODE_FLAG_AVX10;
    }
    if (is_avx10_movrs_256
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_AVX10_MOVRS_256)) {
        return 0;
    } else if (is_avx10_movrs_256) {
        selected |= CDISASM_X86_DECODE_FLAG_AVX10;
    }
    if (is_avx10_movrs_512
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_AVX10_MOVRS_512)) {
        return 0;
    } else if (is_avx10_movrs_512) {
        selected |= CDISASM_X86_DECODE_FLAG_AVX10;
    }
    if (is_vtx
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_VTX)) {
        return 0;
    } else if (is_vtx) {
        /* VTX is the exact pinned ISA_SET selector; it authorizes the VMX
         * functional and privileged-system umbrellas for these forms. */
        selected |= CDISASM_X86_DECODE_FLAG_VMX
            | CDISASM_X86_DECODE_FLAG_SYSTEM;
    }
    if (is_smap
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_SMAP)) {
        return 0;
    } else if (is_smap) {
        selected |= CDISASM_X86_DECODE_FLAG_SYSTEM;
    }
    if (is_sse4_isa_set
        && !cdisasm_decode_flags_test_bit(
            selected_flags, CDISASM_X86_DECODE_BIT_SSE4_ISA_SET)) {
        return 0;
    } else if (is_sse4_isa_set) {
        /* The exact pinned ISA_SET bit is the complete opt-in for this row;
         * its SSE4.1 capability remains a CPU/profile prerequisite in the
         * core decoder. */
        selected |= CDISASM_X86_DECODE_FLAG_SSE41;
    }

#define ADMIT_SPECIFIC_WITH_UMBRELLA(specifics_, umbrella_) \
    do { \
        const cdisasm_x86_decode_option required_specific_ = \
            required & (specifics_); \
        if (required_specific_ != 0) { \
            if ((selected & (required_specific_ | (umbrella_))) == 0) { \
                return 0; \
            } \
            required &= ~(specifics_); \
        } \
    } while (0)

    ADMIT_SPECIFIC_WITH_UMBRELLA(
        specific_avx512, CDISASM_X86_DECODE_FLAG_AVX512);
    ADMIT_SPECIFIC_WITH_UMBRELLA(
        CDISASM_X86_DECODE_FLAG_VAES, CDISASM_X86_DECODE_FLAG_AES);
    ADMIT_SPECIFIC_WITH_UMBRELLA(
        CDISASM_X86_DECODE_FLAG_VPCLMULQDQ,
        CDISASM_X86_DECODE_FLAG_PCLMUL);
    ADMIT_SPECIFIC_WITH_UMBRELLA(
        CDISASM_X86_DECODE_FLAG_SHA512, CDISASM_X86_DECODE_FLAG_SHA);
    ADMIT_SPECIFIC_WITH_UMBRELLA(
        specific_amx, CDISASM_X86_DECODE_FLAG_AMX);
    ADMIT_SPECIFIC_WITH_UMBRELLA(
        CDISASM_X86_DECODE_FLAG_SSE41
            | CDISASM_X86_DECODE_FLAG_SSE42
            | CDISASM_X86_DECODE_FLAG_SSE4A,
        CDISASM_X86_DECODE_FLAG_SSE4);
    ADMIT_SPECIFIC_WITH_UMBRELLA(
        CDISASM_X86_DECODE_FLAG_BMI1
            | CDISASM_X86_DECODE_FLAG_BMI2,
        CDISASM_X86_DECODE_FLAG_BITMANIP);
#undef ADMIT_SPECIFIC_WITH_UMBRELLA
    return (required & ~selected) == 0;
}
#endif

uint32_t CDISASM_CALL cdisasm_x86_decode(
    cdisasm_cpu_id cpu_id,
    cdisasm_mode mode,
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    const cdisasm_x86_decode_flags *flags,
    cdisasm_instruction *instruction)
{
    cdisasm_x86_decode_flags flags_snapshot;
    const cdisasm_x86_decode_flags *selected_flags = flags;
    cdisasm_status status;

    if (instruction == NULL) {
        return 0;
    }
    if (flags != NULL) {
        flags_snapshot = *flags;
        selected_flags = &flags_snapshot;
    }
    memset(instruction, 0, sizeof(*instruction));

    if (!valid_cpu(cpu_id)
        || !valid_mode(mode)
        || !cpu_supports_mode(cpu_id, mode)
        || !x86_decode_flags_are_valid(selected_flags)) {
        instruction->last_error_id = (uint8_t)CDISASM_STATUS_INVALID_ARGUMENT;
        return 0;
    }
    if (code_size == 0) {
        instruction->last_error_id = (uint8_t)CDISASM_STATUS_END_OF_INPUT;
        return 0;
    }
    if (code == NULL) {
        instruction->last_error_id = (uint8_t)CDISASM_STATUS_INVALID_ARGUMENT;
        return 0;
    }

    status = cdisasm_x86_decode_core(
        code,
        code_size,
        address,
        mode,
        cpu_id,
        instruction);
    /* A small set of late EVEX encodings is rejected by the legacy parser
     * before the generated graph can see it.  Limit the retry to those
     * architecturally identified forms; retrying every INVALID byte would
     * let the intentionally structural fallback over-accept reserved forms. */
    if (status == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION
        || (status == CDISASM_STATUS_INVALID_INSTRUCTION
            && x86_should_retry_generated_after_invalid(
                code, code_size, mode))) {
#if USE_EXTRA_OPCODES
        cdisasm_status generated_status;
        cdisasm_status hand_status = status;

        memset(instruction, 0, sizeof(*instruction));
        generated_status = cdisasm_x86_decode_generated(
            code,
            code_size,
            address,
            mode,
            cpu_id,
            selected_flags,
            instruction);
        if (generated_status == CDISASM_STATUS_OK) {
            status = CDISASM_STATUS_OK;
        } else if (hand_status == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION
                   && generated_status != CDISASM_STATUS_INVALID_INSTRUCTION) {
            status = generated_status;
        }
#endif
#if !USE_EXTRA_OPCODES
        /* The same narrowly identified EVEX/VEX forms are owned by the
         * optional generated table.  A no-extra build must classify a valid
         * optional encoding as unsupported, rather than leaking the legacy
         * parser's INVALID result.  This keeps EXTRA_OK corpus witnesses
         * deterministic across both build configurations. */
        if (status == CDISASM_STATUS_INVALID_INSTRUCTION) {
            status = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        }
#endif
    }
    if (status != CDISASM_STATUS_OK) {
        memset(instruction, 0, sizeof(*instruction));
        instruction->last_error_id = (uint8_t)status;
        return 0;
    }
#if USE_EXTRA_OPCODES
    if ((instruction->opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u) {
        (void)cdisasm_x86_attach_generated_identity(
            code, code_size, address, mode, cpu_id, instruction);
    }
    if ((instruction->opcode_flags
            & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u
        && !x86_decode_flags_admit(
            x86_instruction_decode_flags(code, instruction),
            selected_flags,
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_ACE_1),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_RAO_INT),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_APX_F_RAO_INT),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_USER_MSR),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_APX_F_USER_MSR),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_MSRLIST),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_MSR_IMM),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_APX_F_MSR_IMM),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_WRMSRNS),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_KEYLOCKER),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_KEYLOCKER_WIDE),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_HRESET),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_CLDEMOTE),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_CLZERO),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_RDPRU),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_MCOMMIT),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_MONITORX),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AMD_INVLPGB),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_SNP),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_PCONFIG),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_PBNDKB),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_ICACHE_PREFETCH),
            instruction->name_id == CDISASM_X86_NAME_PREFETCHRST2
                && cdisasm_instruction_has_x86_group(
                    instruction, CDISASM_X86_GROUP_MOVRS),
            instruction->name_id == CDISASM_X86_NAME_PREFETCHWT1
                && cdisasm_instruction_has_x86_group(
                    instruction, CDISASM_X86_GROUP_PREFETCHWT1),
            instruction->name_id == CDISASM_X86_NAME_PTWRITE
                && cdisasm_instruction_has_x86_group(
                    instruction, CDISASM_X86_GROUP_PTWRITE),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX_GFNI),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX512_GFNI_128),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX512_GFNI_256),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX512_GFNI_512),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX512F_128),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX512F_128N),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX512F_256),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX512F_512),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX512F_SCALAR),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX512BW_128),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX512BW_256),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX512BW_512),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX512DQ_128),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX512DQ_256),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX512DQ_512),
            cdisasm_instruction_has_x86_group(
                instruction,
                CDISASM_X86_GROUP_AVX512_VP2INTERSECT_128),
            cdisasm_instruction_has_x86_group(
                instruction,
                CDISASM_X86_GROUP_AVX512_VP2INTERSECT_256),
            cdisasm_instruction_has_x86_group(
                instruction,
                CDISASM_X86_GROUP_AVX512_VP2INTERSECT_512),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX512_FP16_128),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX512_FP16_128N),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX512_FP16_256),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX512_FP16_512),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX512_FP16_SCALAR),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX512_MOVZXC_128),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX512_MEDIAX_128),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX512_MEDIAX_256),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX512_MEDIAX_512),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX10_2_BF16_128),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX10_2_BF16_256),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX10_2_BF16_512),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX10_MOVRS_128),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX10_MOVRS_256),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX10_MOVRS_512),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_VTX),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_SMAP),
            instruction->name_id == CDISASM_X86_NAME_MOVNTDQA
                && instruction->form_id == UINT16_C(1690)
                && cdisasm_instruction_has_x86_group(
                    instruction, CDISASM_X86_GROUP_SSE4),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_VIA_PADLOCK_AES),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_VIA_PADLOCK_MONTMUL),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_VIA_PADLOCK_RNG),
            cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_VIA_PADLOCK_SHA))) {
#else
    if (x86_instruction_decode_flags(code, instruction)
        != CDISASM_X86_DECODE_FLAG_BASE) {
#endif
        memset(instruction, 0, sizeof(*instruction));
        instruction->last_error_id =
            (uint8_t)CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        return 0;
    }
#if USE_EXTRA_OPCODES
    if (cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX_NE_CONVERT)) {
        cdisasm_x86_decode_flags cpu_flags;
        const int caller_admits = selected_flags == NULL
            || cdisasm_decode_flags_test_bit(
                selected_flags, CDISASM_X86_DECODE_BIT_AVX_NE_CONVERT);
        const int cpu_admits = cpu_id == CDISASM_CPU_X86
            || (cdisasm_x86_cpu_decode_flag_mask(
                    cpu_id, mode, &cpu_flags) == CDISASM_STATUS_OK
                && cdisasm_decode_flags_test_bit(
                    &cpu_flags, CDISASM_X86_DECODE_BIT_AVX_NE_CONVERT));

        if (!caller_admits || !cpu_admits) {
            memset(instruction, 0, sizeof(*instruction));
            instruction->last_error_id =
                (uint8_t)CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
            return 0;
        }
    }
#endif
    return instruction->opcode_size;
}

uint32_t CDISASM_CALL cdisasm_x86_decode_with_context(
    const cdisasm_x86_decode_context *context,
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    cdisasm_instruction *instruction)
{
    if (context == NULL) {
        if (instruction != NULL) {
            memset(instruction, 0, sizeof(*instruction));
            instruction->last_error_id =
                (uint8_t)CDISASM_STATUS_INVALID_ARGUMENT;
        }
        return 0;
    }
    return cdisasm_x86_decode(
        context->cpu_id,
        context->mode,
        code,
        code_size,
        address,
        &context->flags,
        instruction);
}
