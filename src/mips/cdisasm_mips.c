#include "cdisasm/cdisasm_mips.h"
#include "mips_decoder.h"
#include <string.h>

_Static_assert(sizeof(cdisasm_mips_decode_flags) == CDISASM_DECODE_FLAGS_SIZE, "MIPS decode-flags ABI changed");

typedef struct mips_cpu_profile {
    cdisasm_mips_revision revision;
    cdisasm_mips_mode_mask modes;
    cdisasm_mips_family_mask families;
} mips_cpu_profile;

#define M32 CDISASM_MIPS_MODE_MASK_32
#define M64 (CDISASM_MIPS_MODE_MASK_32 | CDISASM_MIPS_MODE_MASK_64)
#define FPU CDISASM_MIPS_FAMILY_MASK_FPU
#define DSP CDISASM_MIPS_FAMILY_MASK_DSP
#define DSP2 CDISASM_MIPS_FAMILY_MASK_DSPR2
#define MT CDISASM_MIPS_FAMILY_MASK_MT
#define MSA CDISASM_MIPS_FAMILY_MASK_MSA
#define PASE (CDISASM_MIPS_FAMILY_MASK_VZ | CDISASM_MIPS_FAMILY_MASK_EVA | CDISASM_MIPS_FAMILY_MASK_XPA)
#define VZ CDISASM_MIPS_FAMILY_MASK_VZ
#define COP2 CDISASM_MIPS_FAMILY_MASK_COP2
#define COP3 CDISASM_MIPS_FAMILY_MASK_COP3
#define PS CDISASM_MIPS_FAMILY_MASK_PAIRED_SINGLE
#define M3D CDISASM_MIPS_FAMILY_MASK_MIPS3D
#define DSP3 CDISASM_MIPS_FAMILY_MASK_DSPR3

/* Indexed by append-only CPU ordinal. IP core names do not imply optional
 * floating-point/SIMD blocks. SMT on I6400/I6500 is not the legacy MT ASE. */
static const mips_cpu_profile mips_profiles[] = {
    {CDISASM_MIPS_REVISION_NONE, M64, CDISASM_MIPS_FAMILY_MASK_ALL},
    {CDISASM_MIPS_REVISION_I, M32, 0},                       /* R3000 */
    {CDISASM_MIPS_REVISION_III, M64, FPU},                   /* R4000 */
    {CDISASM_MIPS_REVISION_32R1, M32, 0},                    /* 4Kc */
    {CDISASM_MIPS_REVISION_32R2, M32, 0},                    /* 24Kc */
    {CDISASM_MIPS_REVISION_32R2, M32, FPU},                  /* 24Kf */
    {CDISASM_MIPS_REVISION_64R1, M64, 0},                    /* 5Kc */
    {CDISASM_MIPS_REVISION_64R1, M64, FPU},                  /* 5Kf */
    {CDISASM_MIPS_REVISION_32R2, M32, DSP},                  /* 24KEc */
    {CDISASM_MIPS_REVISION_32R2, M32, DSP | MT},             /* 34Kc */
    {CDISASM_MIPS_REVISION_32R2, M32, MT},                   /* 34Kn */
    {CDISASM_MIPS_REVISION_32R2, M32, DSP | DSP2},           /* 74Kc */
    {CDISASM_MIPS_REVISION_32R2, M32, DSP | MT},             /* 1004Kc */
    {CDISASM_MIPS_REVISION_32R5, M32, PASE},                 /* P5600 */
    {CDISASM_MIPS_REVISION_64R6, M64, VZ},                   /* I6400 */
    {CDISASM_MIPS_REVISION_64R6, M64, VZ},                   /* I6500 */
    {CDISASM_MIPS_REVISION_64R6, M64, VZ},                   /* P6600 */
    {CDISASM_MIPS_REVISION_32R5, M32, PASE | FPU},
    {CDISASM_MIPS_REVISION_32R5, M32, PASE | FPU | MSA},
    {CDISASM_MIPS_REVISION_64R6, M64, VZ | FPU},
    {CDISASM_MIPS_REVISION_64R6, M64, VZ | FPU | MSA},
    {CDISASM_MIPS_REVISION_64R6, M64, VZ | FPU},
    {CDISASM_MIPS_REVISION_64R6, M64, VZ | FPU | MSA},
    {CDISASM_MIPS_REVISION_64R6, M64, VZ | FPU},
    {CDISASM_MIPS_REVISION_64R6, M64, VZ | FPU | MSA},
    {CDISASM_MIPS_REVISION_32R1, M32, FPU | CDISASM_MIPS_FAMILY_MASK_ALLEGREX},
    {CDISASM_MIPS_REVISION_III, CDISASM_MIPS_MODE_MASK_64, FPU | CDISASM_MIPS_FAMILY_MASK_R5900 | CDISASM_MIPS_FAMILY_MASK_R5900_VU0 | CDISASM_MIPS_FAMILY_MASK_R5900_VU1},
    {CDISASM_MIPS_REVISION_64R2, M64, COP2 | CDISASM_MIPS_FAMILY_MASK_CNMIPS},
    {CDISASM_MIPS_REVISION_64R2, M64, COP2 | CDISASM_MIPS_FAMILY_MASK_CNMIPS | CDISASM_MIPS_FAMILY_MASK_CNMIPSP},
    {CDISASM_MIPS_REVISION_III, CDISASM_MIPS_MODE_MASK_64, FPU | PS | CDISASM_MIPS_FAMILY_MASK_LOONGSON | CDISASM_MIPS_FAMILY_MASK_LOONGSON2E},
    {CDISASM_MIPS_REVISION_III, CDISASM_MIPS_MODE_MASK_64, FPU | PS | CDISASM_MIPS_FAMILY_MASK_LOONGSON | CDISASM_MIPS_FAMILY_MASK_LOONGSON2F},
    {CDISASM_MIPS_REVISION_64R2, CDISASM_MIPS_MODE_MASK_64, FPU | CDISASM_MIPS_FAMILY_MASK_LOONGSON | CDISASM_MIPS_FAMILY_MASK_LOONGSIMD},
    {CDISASM_MIPS_REVISION_64R2, CDISASM_MIPS_MODE_MASK_64, FPU | MSA | CDISASM_MIPS_FAMILY_MASK_LOONGSON | CDISASM_MIPS_FAMILY_MASK_LOONGSIMD | CDISASM_MIPS_FAMILY_MASK_LOONGASX}
};
_Static_assert(sizeof(mips_profiles) / sizeof(mips_profiles[0]) == CDISASM_CPU_ORDINAL_OF(CDISASM_MIPS_CPU_LAST) + 1u, "MIPS profiles must cover public CPU IDs");

static const cdisasm_mips_revision mips_revisions[] = {
    CDISASM_MIPS_REVISION_I, CDISASM_MIPS_REVISION_II, CDISASM_MIPS_REVISION_III, CDISASM_MIPS_REVISION_IV,
    CDISASM_MIPS_REVISION_32R1, CDISASM_MIPS_REVISION_32R2, CDISASM_MIPS_REVISION_32R5, CDISASM_MIPS_REVISION_32R6,
    CDISASM_MIPS_REVISION_64R1, CDISASM_MIPS_REVISION_64R2, CDISASM_MIPS_REVISION_64R6,
    /* Append only: these array positions are published ISA selector bits. */
    CDISASM_MIPS_REVISION_V, CDISASM_MIPS_REVISION_32R3,
    CDISASM_MIPS_REVISION_64R3, CDISASM_MIPS_REVISION_64R5
};

static const cdisasm_mips_family_descriptor mips_families[] = {
    {CDISASM_MIPS_FAMILY_NONE, 0, 0, 0},
    {CDISASM_MIPS_FAMILY_FPU, 0, M64, CDISASM_MIPS_DECODE_FLAG_FPU},
    {CDISASM_MIPS_FAMILY_DSP, 0, M64, CDISASM_MIPS_DECODE_FLAG_DSP},
    {CDISASM_MIPS_FAMILY_DSPR2, 0, M64, CDISASM_MIPS_DECODE_FLAG_DSP | CDISASM_MIPS_DECODE_FLAG_DSPR2},
    {CDISASM_MIPS_FAMILY_MT, 0, M64, CDISASM_MIPS_DECODE_FLAG_MT},
    {CDISASM_MIPS_FAMILY_MSA, 0, M64, CDISASM_MIPS_DECODE_FLAG_FPU | CDISASM_MIPS_DECODE_FLAG_MSA},
    {CDISASM_MIPS_FAMILY_VZ, 0, M64, CDISASM_MIPS_DECODE_FLAG_VZ},
    {CDISASM_MIPS_FAMILY_EVA, 0, M32, CDISASM_MIPS_DECODE_FLAG_EVA},
    {CDISASM_MIPS_FAMILY_XPA, 0, M32, CDISASM_MIPS_DECODE_FLAG_XPA},
    {CDISASM_MIPS_FAMILY_DSPR3, 0, M64, CDISASM_MIPS_DECODE_FLAG_DSP | CDISASM_MIPS_DECODE_FLAG_DSPR2 | CDISASM_MIPS_DECODE_FLAG_DSPR3},
    {CDISASM_MIPS_FAMILY_MIPS3D, 0, M64, CDISASM_MIPS_DECODE_FLAG_FPU | CDISASM_MIPS_DECODE_FLAG_MIPS3D},
    {CDISASM_MIPS_FAMILY_MDMX, 0, CDISASM_MIPS_MODE_MASK_64, CDISASM_MIPS_DECODE_FLAG_FPU | CDISASM_MIPS_DECODE_FLAG_MDMX},
    {CDISASM_MIPS_FAMILY_SMARTMIPS, 0, M32, CDISASM_MIPS_DECODE_FLAG_SMARTMIPS},
    {CDISASM_MIPS_FAMILY_MCU, 0, M32, CDISASM_MIPS_DECODE_FLAG_MCU},
    {CDISASM_MIPS_FAMILY_CRC, 0, M64, CDISASM_MIPS_DECODE_FLAG_CRC},
    {CDISASM_MIPS_FAMILY_GINV, 0, M64, CDISASM_MIPS_DECODE_FLAG_GINV},
    {CDISASM_MIPS_FAMILY_COP2, 0, M64, CDISASM_MIPS_DECODE_FLAG_COP2},
    {CDISASM_MIPS_FAMILY_COP3, 0, M64, CDISASM_MIPS_DECODE_FLAG_COP3},
    {CDISASM_MIPS_FAMILY_PAIRED_SINGLE, 0, M64, CDISASM_MIPS_DECODE_FLAG_FPU | CDISASM_MIPS_DECODE_FLAG_PAIRED_SINGLE},
    {CDISASM_MIPS_FAMILY_CNMIPS, 0, M64, CDISASM_MIPS_DECODE_FLAG_CNMIPS},
    {CDISASM_MIPS_FAMILY_CNMIPSP, 0, M64, CDISASM_MIPS_DECODE_FLAG_CNMIPS | CDISASM_MIPS_DECODE_FLAG_CNMIPSP},
    {CDISASM_MIPS_FAMILY_LOONGSON, 0, CDISASM_MIPS_MODE_MASK_64, CDISASM_MIPS_DECODE_FLAG_LOONGSON},
    {CDISASM_MIPS_FAMILY_ALLEGREX, 0, M32, CDISASM_MIPS_DECODE_FLAG_ALLEGREX},
    {CDISASM_MIPS_FAMILY_R5900, 0, CDISASM_MIPS_MODE_MASK_64, CDISASM_MIPS_DECODE_FLAG_R5900},
    {CDISASM_MIPS_FAMILY_MXU, 0, M32, CDISASM_MIPS_DECODE_FLAG_MXU},
    {CDISASM_MIPS_FAMILY_MIPS16E2, 0, M64, CDISASM_MIPS_DECODE_FLAG_MIPS16E2},
    {CDISASM_MIPS_FAMILY_LOONGSON2E, 0, CDISASM_MIPS_MODE_MASK_64, CDISASM_MIPS_DECODE_FLAG_LOONGSON | CDISASM_MIPS_DECODE_FLAG_LOONGSON2E},
    {CDISASM_MIPS_FAMILY_LOONGSON2F, 0, CDISASM_MIPS_MODE_MASK_64, CDISASM_MIPS_DECODE_FLAG_LOONGSON | CDISASM_MIPS_DECODE_FLAG_LOONGSON2F},
    {CDISASM_MIPS_FAMILY_LOONGSON_EXT, 0, CDISASM_MIPS_MODE_MASK_64, CDISASM_MIPS_DECODE_FLAG_LOONGSON | CDISASM_MIPS_DECODE_FLAG_LOONGSON_EXT},
    {CDISASM_MIPS_FAMILY_LOONGSON_EXT2, 0, CDISASM_MIPS_MODE_MASK_64, CDISASM_MIPS_DECODE_FLAG_LOONGSON | CDISASM_MIPS_DECODE_FLAG_LOONGSON_EXT | CDISASM_MIPS_DECODE_FLAG_LOONGSON_EXT2},
    {CDISASM_MIPS_FAMILY_LOONGSON_CAM, 0, CDISASM_MIPS_MODE_MASK_64, CDISASM_MIPS_DECODE_FLAG_LOONGSON | CDISASM_MIPS_DECODE_FLAG_LOONGSON_CAM},
    {CDISASM_MIPS_FAMILY_DSP64, 0, CDISASM_MIPS_MODE_MASK_64, CDISASM_MIPS_DECODE_FLAG_DSP | CDISASM_MIPS_DECODE_FLAG_DSP64},
    {CDISASM_MIPS_FAMILY_MXU2, 0, M32, CDISASM_MIPS_DECODE_FLAG_MXU2},
    {CDISASM_MIPS_FAMILY_MXU3, 0, M32, CDISASM_MIPS_DECODE_FLAG_MXU3},
    {CDISASM_MIPS_FAMILY_LOONGSIMD, 0, CDISASM_MIPS_MODE_MASK_64, CDISASM_MIPS_DECODE_FLAG_FPU | CDISASM_MIPS_DECODE_FLAG_LOONGSON | CDISASM_MIPS_DECODE_FLAG_LOONGSIMD},
    {CDISASM_MIPS_FAMILY_R5900_VU0, 0, CDISASM_MIPS_MODE_MASK_64, CDISASM_MIPS_DECODE_FLAG_R5900 | CDISASM_MIPS_DECODE_FLAG_R5900_VU0},
    {CDISASM_MIPS_FAMILY_R5900_VU1, 0, CDISASM_MIPS_MODE_MASK_64, CDISASM_MIPS_DECODE_FLAG_R5900 | CDISASM_MIPS_DECODE_FLAG_R5900_VU1},
    {CDISASM_MIPS_FAMILY_MXU3_1, 0, M32, CDISASM_MIPS_DECODE_FLAG_MXU3 | CDISASM_MIPS_DECODE_FLAG_MXU3_1},
    {CDISASM_MIPS_FAMILY_LOONGASX, 0, CDISASM_MIPS_MODE_MASK_64, CDISASM_MIPS_DECODE_FLAG_FPU | CDISASM_MIPS_DECODE_FLAG_LOONGSON | CDISASM_MIPS_DECODE_FLAG_LOONGASX}
};

static const uint8_t mips_family_flag_bits[] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 61, 31
};
_Static_assert(sizeof(mips_family_flag_bits) == CDISASM_MIPS_FAMILY_LAST + 1u, "MIPS family allocation incomplete");

static uint64_t family_flags(cdisasm_mips_family_mask families)
{
    uint64_t flags = 0;
    unsigned id;
    for (id = 1; id <= CDISASM_MIPS_FAMILY_LAST; ++id)
        if ((families & (UINT64_C(1) << (id - 1u))) != 0) flags |= UINT64_C(1) << mips_family_flag_bits[id];
    return flags;
}

static cdisasm_mips_family_mask flag_families(uint64_t flags)
{
    cdisasm_mips_family_mask families = 0;
    unsigned id;
    for (id = 1; id <= CDISASM_MIPS_FAMILY_LAST; ++id)
        if ((flags & (UINT64_C(1) << mips_family_flag_bits[id])) != 0) families |= UINT64_C(1) << (id - 1u);
    return families;
}

static cdisasm_mips_family_mask family_dependencies(cdisasm_mips_family_mask families)
{
    cdisasm_mips_family_mask prior;
    unsigned id;
    do {
        prior = families;
        for (id = 1; id <= CDISASM_MIPS_FAMILY_LAST; ++id)
            if ((families & (UINT64_C(1) << (id - 1u))) != 0)
                families |= flag_families(mips_families[id].required_flags);
    } while (families != prior);
    return families;
}

cdisasm_mips_family_mask CDISASM_CALL cdisasm_mips_family_mask_from_flags(const cdisasm_mips_decode_flags *flags)
{
    unsigned index;
    if (flags == NULL || (flags->bitmap[0] & ~CDISASM_MIPS_DECODE_FLAG_KNOWN_MASK_0) != 0)
        return CDISASM_MIPS_FAMILY_MASK_NONE;
    for (index = 1; index < CDISASM_DECODE_FLAGS_BITMAP_COUNT; ++index)
        if (flags->bitmap[index] != 0) return CDISASM_MIPS_FAMILY_MASK_NONE;
    return flag_families(flags->bitmap[0]);
}

static const mips_cpu_profile *profile_for(cdisasm_mips_cpu_id cpu_id)
{
    const uint32_t ordinal = CDISASM_CPU_ORDINAL_OF(cpu_id);
    if (CDISASM_CPU_GROUP_OF(cpu_id) != CDISASM_CPU_GROUP_MIPS || ordinal >= sizeof(mips_profiles) / sizeof(mips_profiles[0])) return NULL;
    return &mips_profiles[ordinal];
}

static cdisasm_mips_mode_mask mode_bit(cdisasm_mips_mode mode)
{
    return mode == CDISASM_MIPS_MODE_32 ? M32 : (mode == CDISASM_MIPS_MODE_64 ? CDISASM_MIPS_MODE_MASK_64 : 0);
}

static uint64_t revision_flag(cdisasm_mips_revision revision)
{
    size_t i;
    for (i = 0; i < sizeof(mips_revisions) / sizeof(mips_revisions[0]); ++i) {
        if (mips_revisions[i] == revision) return UINT64_C(1) << (32u + i);
    }
    return 0;
}

static int revision_supports_mode(cdisasm_mips_revision revision, cdisasm_mips_mode mode)
{
    if (!revision_flag(revision) || !mode_bit(mode)) return 0;
    return mode == CDISASM_MIPS_MODE_32 || revision == CDISASM_MIPS_REVISION_III || revision == CDISASM_MIPS_REVISION_IV || revision == CDISASM_MIPS_REVISION_V ||
           revision == CDISASM_MIPS_REVISION_64R1 || revision == CDISASM_MIPS_REVISION_64R2 || revision == CDISASM_MIPS_REVISION_64R3 ||
           revision == CDISASM_MIPS_REVISION_64R5 || revision == CDISASM_MIPS_REVISION_64R6;
}

static cdisasm_mips_revision selected_revision(const mips_cpu_profile *profile, uint64_t flags)
{
    const uint64_t selected = flags & CDISASM_MIPS_DECODE_FLAG_ISA_MASK;
    size_t i;
    if (selected == 0) return profile->revision;
    if ((selected & (selected - 1)) != 0) return CDISASM_MIPS_REVISION_NONE;
    for (i = 0; i < sizeof(mips_revisions) / sizeof(mips_revisions[0]); ++i) {
        if (selected == (UINT64_C(1) << (32u + i))) {
            return profile->revision == CDISASM_MIPS_REVISION_NONE || profile->revision == mips_revisions[i] ? mips_revisions[i] : CDISASM_MIPS_REVISION_NONE;
        }
    }
    return CDISASM_MIPS_REVISION_NONE;
}

static cdisasm_mips_family_mask available_families(const mips_cpu_profile *profile, cdisasm_mips_mode mode)
{
    cdisasm_mips_family_mask result;
    unsigned id;
    if (profile == NULL || (profile->modes & mode_bit(mode)) == 0) return 0;
#if USE_EXTRA_OPCODES
    /* Capability queries describe implemented native decoding slices. Hardware
     * support for a presently unimplemented ASE remains internal metadata. */
    result = profile->families & (FPU | DSP | DSP2 | DSP3 | MT | MSA | M3D | PS | COP2 | COP3 |
        CDISASM_MIPS_FAMILY_MASK_VZ | CDISASM_MIPS_FAMILY_MASK_EVA | CDISASM_MIPS_FAMILY_MASK_XPA |
        CDISASM_MIPS_FAMILY_MASK_CRC | CDISASM_MIPS_FAMILY_MASK_GINV |
        CDISASM_MIPS_FAMILY_MASK_CNMIPS | CDISASM_MIPS_FAMILY_MASK_CNMIPSP |
        CDISASM_MIPS_FAMILY_MASK_SMARTMIPS | CDISASM_MIPS_FAMILY_MASK_MCU | CDISASM_MIPS_FAMILY_MASK_MIPS16E2 |
        CDISASM_MIPS_FAMILY_MASK_ALLEGREX | CDISASM_MIPS_FAMILY_MASK_R5900 | CDISASM_MIPS_FAMILY_MASK_LOONGSON | CDISASM_MIPS_FAMILY_MASK_MXU |
        CDISASM_MIPS_FAMILY_MASK_LOONGSON2E | CDISASM_MIPS_FAMILY_MASK_LOONGSON2F |
        CDISASM_MIPS_FAMILY_MASK_LOONGSON_EXT | CDISASM_MIPS_FAMILY_MASK_LOONGSON_EXT2 | CDISASM_MIPS_FAMILY_MASK_LOONGSON_CAM |
        CDISASM_MIPS_FAMILY_MASK_MXU2 | CDISASM_MIPS_FAMILY_MASK_MXU3 | CDISASM_MIPS_FAMILY_MASK_MXU3_1 |
        CDISASM_MIPS_FAMILY_MASK_LOONGSIMD | CDISASM_MIPS_FAMILY_MASK_LOONGASX | CDISASM_MIPS_FAMILY_MASK_R5900_VU0 | CDISASM_MIPS_FAMILY_MASK_R5900_VU1 |
        (mode == CDISASM_MIPS_MODE_64 ? CDISASM_MIPS_FAMILY_MASK_DSP64 : 0) |
        (mode == CDISASM_MIPS_MODE_64 ? CDISASM_MIPS_FAMILY_MASK_MDMX : 0));
#else
    /* COP1 is part of the handwritten decoder. Optional generated/DSP/MT/MSA
     * coverage is gated separately by USE_EXTRA_OPCODES. */
    result = profile->families & (FPU | PS | COP2 | COP3 | CDISASM_MIPS_FAMILY_MASK_ALLEGREX | CDISASM_MIPS_FAMILY_MASK_R5900);
#endif
    for (id = 1; id <= CDISASM_MIPS_FAMILY_LAST; ++id)
        if ((mips_families[id].allowed_modes & mode_bit(mode)) == 0) result &= ~(UINT64_C(1) << (id - 1u));
    return result;
}

static void apply_cpu_policy(const mips_cpu_profile *profile, cdisasm_mips_decode_flags *effective)
{
    if (profile->revision != CDISASM_MIPS_REVISION_NONE) {
        effective->bitmap[CDISASM_MIPS_INTERNAL_POLICY_WORD] = family_flags(profile->families) &
            (CDISASM_MIPS_DECODE_FLAG_ALLEGREX | CDISASM_MIPS_DECODE_FLAG_R5900);
        /* Retain physical MSA eligibility after a caller disables its active
         * families. Only the named MSA-capable Loongson profile gets this
         * marker; it does not enable MSA/FPU operand lowering. */
        if ((profile->families & (MSA | CDISASM_MIPS_FAMILY_MASK_LOONGSIMD)) ==
            (MSA | CDISASM_MIPS_FAMILY_MASK_LOONGSIMD))
            effective->bitmap[CDISASM_MIPS_INTERNAL_POLICY_WORD] |=
                CDISASM_MIPS_DECODE_FLAG_MSA | CDISASM_MIPS_DECODE_FLAG_LOONGSIMD;
    }
    if (((effective->bitmap[0] | effective->bitmap[CDISASM_MIPS_INTERNAL_POLICY_WORD]) & CDISASM_MIPS_DECODE_FLAG_R5900) != 0)
        effective->bitmap[0] |= CDISASM_MIPS_DECODE_FLAG_FPR32;
}

static cdisasm_mips_family_mask revision_families(const mips_cpu_profile *profile, cdisasm_mips_mode mode, cdisasm_mips_revision revision)
{
    cdisasm_mips_family_mask families = available_families(profile, mode);
    if (profile == NULL) return 0;
    if (revision != CDISASM_MIPS_REVISION_III)
        families &= ~(CDISASM_MIPS_FAMILY_MASK_R5900 | CDISASM_MIPS_FAMILY_MASK_R5900_VU0 | CDISASM_MIPS_FAMILY_MASK_R5900_VU1 |
            CDISASM_MIPS_FAMILY_MASK_LOONGSON2E | CDISASM_MIPS_FAMILY_MASK_LOONGSON2F);
    if (revision != CDISASM_MIPS_REVISION_32R1) families &= ~CDISASM_MIPS_FAMILY_MASK_ALLEGREX;
    if (revision != CDISASM_MIPS_REVISION_64R2 && revision != CDISASM_MIPS_REVISION_64R3 && revision != CDISASM_MIPS_REVISION_64R5)
        families &= ~CDISASM_MIPS_FAMILY_MASK_LOONGSIMD;
    if (revision != CDISASM_MIPS_REVISION_64R2) families &= ~CDISASM_MIPS_FAMILY_MASK_LOONGASX;
    if (mode == CDISASM_MIPS_MODE_64) families &= ~(CDISASM_MIPS_FAMILY_MASK_EVA | CDISASM_MIPS_FAMILY_MASK_XPA);
    switch (revision) {
        case CDISASM_MIPS_REVISION_I: case CDISASM_MIPS_REVISION_II: return families & (FPU | COP2 | COP3);
        case CDISASM_MIPS_REVISION_III: return families & (FPU | COP2 | PS | CDISASM_MIPS_FAMILY_MASK_R5900 |
            CDISASM_MIPS_FAMILY_MASK_LOONGSON | CDISASM_MIPS_FAMILY_MASK_LOONGSON2E | CDISASM_MIPS_FAMILY_MASK_LOONGSON2F |
            CDISASM_MIPS_FAMILY_MASK_R5900_VU0 | CDISASM_MIPS_FAMILY_MASK_R5900_VU1);
        case CDISASM_MIPS_REVISION_IV: return families & (FPU | COP2);
        case CDISASM_MIPS_REVISION_V: return families & (FPU | COP2 | PS);
        case CDISASM_MIPS_REVISION_32R1: return families & (FPU | COP2 | CDISASM_MIPS_FAMILY_MASK_SMARTMIPS | CDISASM_MIPS_FAMILY_MASK_ALLEGREX | CDISASM_MIPS_FAMILY_MASK_MXU | CDISASM_MIPS_FAMILY_MASK_MIPS16E2 |
            CDISASM_MIPS_FAMILY_MASK_MXU2 | CDISASM_MIPS_FAMILY_MASK_MXU3 | CDISASM_MIPS_FAMILY_MASK_MXU3_1);
        case CDISASM_MIPS_REVISION_64R1: return families & (FPU | COP2 | PS | M3D | CDISASM_MIPS_FAMILY_MASK_MDMX | CDISASM_MIPS_FAMILY_MASK_MIPS16E2);
        case CDISASM_MIPS_REVISION_32R2: case CDISASM_MIPS_REVISION_32R3:
        case CDISASM_MIPS_REVISION_64R2: case CDISASM_MIPS_REVISION_64R3:
            return families & ~((revision == CDISASM_MIPS_REVISION_64R2 && (families & CDISASM_MIPS_FAMILY_MASK_LOONGSIMD) != 0 ? 0 : MSA) |
                DSP3 | COP3 | CDISASM_MIPS_FAMILY_MASK_CRC | CDISASM_MIPS_FAMILY_MASK_GINV);
        case CDISASM_MIPS_REVISION_32R5: case CDISASM_MIPS_REVISION_64R5: return families & ~(DSP3 | COP3);
        case CDISASM_MIPS_REVISION_32R6: case CDISASM_MIPS_REVISION_64R6:
            return families & ~(M3D | PS | COP3 | MT | CDISASM_MIPS_FAMILY_MASK_MDMX | CDISASM_MIPS_FAMILY_MASK_SMARTMIPS |
                CDISASM_MIPS_FAMILY_MASK_CNMIPS | CDISASM_MIPS_FAMILY_MASK_CNMIPSP | CDISASM_MIPS_FAMILY_MASK_MXU |
                CDISASM_MIPS_FAMILY_MASK_MCU | CDISASM_MIPS_FAMILY_MASK_DSP64 | CDISASM_MIPS_FAMILY_MASK_MIPS16E2 |
                CDISASM_MIPS_FAMILY_MASK_LOONGSON | CDISASM_MIPS_FAMILY_MASK_LOONGSON2E | CDISASM_MIPS_FAMILY_MASK_LOONGSON2F |
                CDISASM_MIPS_FAMILY_MASK_LOONGSON_EXT | CDISASM_MIPS_FAMILY_MASK_LOONGSON_EXT2 | CDISASM_MIPS_FAMILY_MASK_LOONGSON_CAM |
                CDISASM_MIPS_FAMILY_MASK_MXU2 | CDISASM_MIPS_FAMILY_MASK_MXU3 | CDISASM_MIPS_FAMILY_MASK_MXU3_1 | CDISASM_MIPS_FAMILY_MASK_LOONGSIMD);
        default: return 0;
    }
}

static cdisasm_mips_family_mask default_families(const mips_cpu_profile *profile, cdisasm_mips_family_mask supported, cdisasm_mips_revision revision)
{
    supported &= ~(CDISASM_MIPS_FAMILY_MASK_R5900_VU1 | CDISASM_MIPS_FAMILY_MASK_LOONGASX);
    /* Generic ISA selection must not choose a processor-specific encoding
     * space or an incompatible vector register model implicitly. */
    if (profile->revision == CDISASM_MIPS_REVISION_NONE) {
        if (revision == CDISASM_MIPS_REVISION_64R2 || revision == CDISASM_MIPS_REVISION_64R3) supported &= ~MSA;
        supported &= ~(CDISASM_MIPS_FAMILY_MASK_MDMX | CDISASM_MIPS_FAMILY_MASK_SMARTMIPS |
            CDISASM_MIPS_FAMILY_MASK_CNMIPS | CDISASM_MIPS_FAMILY_MASK_CNMIPSP |
            CDISASM_MIPS_FAMILY_MASK_LOONGSON | CDISASM_MIPS_FAMILY_MASK_ALLEGREX |
            CDISASM_MIPS_FAMILY_MASK_R5900 | CDISASM_MIPS_FAMILY_MASK_MXU |
            CDISASM_MIPS_FAMILY_MASK_LOONGSON2E | CDISASM_MIPS_FAMILY_MASK_LOONGSON2F |
            CDISASM_MIPS_FAMILY_MASK_LOONGSON_EXT | CDISASM_MIPS_FAMILY_MASK_LOONGSON_EXT2 | CDISASM_MIPS_FAMILY_MASK_LOONGSON_CAM |
            CDISASM_MIPS_FAMILY_MASK_DSP64 | CDISASM_MIPS_FAMILY_MASK_MIPS16E2 |
            CDISASM_MIPS_FAMILY_MASK_MXU2 | CDISASM_MIPS_FAMILY_MASK_MXU3 | CDISASM_MIPS_FAMILY_MASK_MXU3_1 |
            CDISASM_MIPS_FAMILY_MASK_LOONGSIMD | CDISASM_MIPS_FAMILY_MASK_R5900_VU0);
    }
    return supported;
}

static int conflicting_features(uint64_t features)
{
    const uint64_t loongson = features & (CDISASM_MIPS_DECODE_FLAG_LOONGSON2E | CDISASM_MIPS_DECODE_FLAG_LOONGSON2F | CDISASM_MIPS_DECODE_FLAG_LOONGSIMD);
    const uint64_t mxu = features & (CDISASM_MIPS_DECODE_FLAG_MXU | CDISASM_MIPS_DECODE_FLAG_MXU2 | CDISASM_MIPS_DECODE_FLAG_MXU3);
    const uint64_t vu = features & (CDISASM_MIPS_DECODE_FLAG_R5900_VU0 | CDISASM_MIPS_DECODE_FLAG_R5900_VU1);
    const unsigned processors = (unsigned)((features & CDISASM_MIPS_DECODE_FLAG_ALLEGREX) != 0) +
        (unsigned)((features & CDISASM_MIPS_DECODE_FLAG_R5900) != 0) +
        (unsigned)((features & (CDISASM_MIPS_DECODE_FLAG_CNMIPS | CDISASM_MIPS_DECODE_FLAG_CNMIPSP)) != 0) +
        (unsigned)((features & CDISASM_MIPS_DECODE_FLAG_LOONGSON) != 0) +
        (unsigned)(mxu != 0);
    if (processors > 1u) return 1;
    if (loongson != 0 && (loongson & (loongson - 1u)) != 0) return 1;
    if (mxu != 0 && (mxu & (mxu - 1u)) != 0) return 1;
    if (vu != 0 && (vu & (vu - 1u)) != 0) return 1;
    if ((features & CDISASM_MIPS_DECODE_FLAG_LOONGASX) != 0 &&
        (features & (CDISASM_MIPS_DECODE_FLAG_LOONGSON2E | CDISASM_MIPS_DECODE_FLAG_LOONGSON2F)) != 0) return 1;
    if ((features & CDISASM_MIPS_DECODE_FLAG_LOONGSON) != 0 && loongson == 0 &&
        (features & (CDISASM_MIPS_DECODE_FLAG_LOONGSON_EXT | CDISASM_MIPS_DECODE_FLAG_LOONGSON_CAM | CDISASM_MIPS_DECODE_FLAG_LOONGASX)) == 0) return 1;
    return (features & (CDISASM_MIPS_DECODE_FLAG_MDMX | CDISASM_MIPS_DECODE_FLAG_FPR32)) ==
               (CDISASM_MIPS_DECODE_FLAG_MDMX | CDISASM_MIPS_DECODE_FLAG_FPR32) ||
           (features & (CDISASM_MIPS_DECODE_FLAG_MDMX | CDISASM_MIPS_DECODE_FLAG_MSA)) ==
               (CDISASM_MIPS_DECODE_FLAG_MDMX | CDISASM_MIPS_DECODE_FLAG_MSA) ||
           ((features & (CDISASM_MIPS_DECODE_FLAG_LOONGSIMD | CDISASM_MIPS_DECODE_FLAG_LOONGASX)) != 0 &&
            (features & CDISASM_MIPS_DECODE_FLAG_FPR32) != 0);
}

cdisasm_mips_mode_mask CDISASM_CALL cdisasm_mips_cpu_mode_mask(cdisasm_mips_cpu_id cpu_id)
{
    const mips_cpu_profile *profile = profile_for(cpu_id);
    return profile == NULL ? 0 : profile->modes;
}

cdisasm_mips_mode_mask CDISASM_CALL cdisasm_mips_decoder_mode_mask(cdisasm_mips_cpu_id cpu_id)
{
    return cdisasm_mips_cpu_mode_mask(cpu_id);
}

cdisasm_mips_revision CDISASM_CALL cdisasm_mips_cpu_revision(cdisasm_mips_cpu_id cpu_id)
{
    const mips_cpu_profile *profile = profile_for(cpu_id);
    return profile == NULL ? CDISASM_MIPS_REVISION_NONE : profile->revision;
}

cdisasm_mips_family_mask CDISASM_CALL cdisasm_mips_cpu_family_mask(cdisasm_mips_cpu_id cpu_id, cdisasm_mips_mode mode)
{
    return available_families(profile_for(cpu_id), mode);
}

const cdisasm_mips_family_descriptor *CDISASM_CALL cdisasm_mips_family_descriptor_get(cdisasm_mips_family_id family_id)
{
    return family_id >= CDISASM_MIPS_FAMILY_FIRST && family_id <= CDISASM_MIPS_FAMILY_LAST ? &mips_families[family_id] : NULL;
}

cdisasm_status CDISASM_CALL cdisasm_mips_cpu_decode_flag_mask(cdisasm_mips_cpu_id cpu_id, cdisasm_mips_mode mode, cdisasm_mips_decode_flags *flags)
{
    const mips_cpu_profile *profile = profile_for(cpu_id);
    if (flags == NULL) return CDISASM_STATUS_INVALID_ARGUMENT;
    cdisasm_decode_flags_reset(flags);
    if (profile == NULL || (profile->modes & mode_bit(mode)) == 0) return CDISASM_STATUS_INVALID_ARGUMENT;
    flags->bitmap[0] = CDISASM_MIPS_DECODE_FLAG_BIG_ENDIAN | CDISASM_MIPS_DECODE_FLAG_EXPLICIT_FAMILIES |
                       family_flags(available_families(profile, mode)) |
                       (profile->revision == CDISASM_MIPS_REVISION_NONE ? CDISASM_MIPS_DECODE_FLAG_ISA_MASK : revision_flag(profile->revision));
    if (profile->revision != CDISASM_MIPS_REVISION_32R6 && profile->revision != CDISASM_MIPS_REVISION_64R6) flags->bitmap[0] |= CDISASM_MIPS_DECODE_FLAG_FPR32;
    return CDISASM_STATUS_OK;
}

cdisasm_status CDISASM_CALL cdisasm_mips_cpu_decode_context(cdisasm_mips_cpu_id cpu_id, cdisasm_mips_mode mode, cdisasm_mips_revision revision, cdisasm_mips_decode_context *context)
{
    const mips_cpu_profile *profile = profile_for(cpu_id);
    if (context == NULL) return CDISASM_STATUS_INVALID_ARGUMENT;
    memset(context, 0, sizeof(*context));
    if (profile == NULL || (profile->modes & mode_bit(mode)) == 0) return CDISASM_STATUS_INVALID_ARGUMENT;
    if (revision == CDISASM_MIPS_REVISION_NONE) revision = profile->revision;
    if (!revision_supports_mode(revision, mode) || (profile->revision != CDISASM_MIPS_REVISION_NONE && revision != profile->revision)) return CDISASM_STATUS_INVALID_ARGUMENT;
    context->cpu_id = cpu_id;
    context->mode = mode;
    context->revision = revision;
    context->family_mask = revision_families(profile, mode, revision);
    context->family_value = default_families(profile, context->family_mask, revision);
    context->flags.bitmap[0] = revision_flag(revision) | CDISASM_MIPS_DECODE_FLAG_EXPLICIT_FAMILIES | family_flags(context->family_mask);
    return CDISASM_STATUS_OK;
}

static cdisasm_mips_family_mask family_bit(cdisasm_mips_family_id family_id)
{
    return family_id >= CDISASM_MIPS_FAMILY_FIRST && family_id <= CDISASM_MIPS_FAMILY_LAST ? UINT64_C(1) << (family_id - 1u) : 0;
}

int CDISASM_CALL cdisasm_mips_decode_context_add_family(cdisasm_mips_decode_context *context, cdisasm_mips_family_id family_id)
{
    cdisasm_mips_family_mask family = family_dependencies(family_bit(family_id));
    cdisasm_mips_family_mask selected;
    uint64_t flags;
    if (context == NULL || family == 0) return 0;
    /* MSA on the older 64R2 revision is the documented 3A4000 vendor slice;
     * the LoongSIMD selector is required by its decoder/replay policy. */
    if (context->revision == CDISASM_MIPS_REVISION_64R2 && (family & MSA) != 0)
        family |= FPU | CDISASM_MIPS_FAMILY_MASK_LOONGSON | CDISASM_MIPS_FAMILY_MASK_LOONGSIMD;
    if ((family & context->family_mask) != family) return 0;
    selected = context->family_value | family;
    flags = family_flags(selected) | (context->flags.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_FPR32);
    if (conflicting_features(flags) ||
        (flags & (CDISASM_MIPS_DECODE_FLAG_MSA | CDISASM_MIPS_DECODE_FLAG_FPR32)) ==
        (CDISASM_MIPS_DECODE_FLAG_MSA | CDISASM_MIPS_DECODE_FLAG_FPR32)) return 0;
    context->family_value = selected;
    return 1;
}

int CDISASM_CALL cdisasm_mips_decode_context_remove_family(cdisasm_mips_decode_context *context, cdisasm_mips_family_id family_id)
{
    cdisasm_mips_family_mask family = family_bit(family_id);
    cdisasm_mips_family_mask selected, prior;
    unsigned id;
    uint64_t flags;
    if (context == NULL || family == 0 || (family & context->family_mask) == 0) return 0;
    selected = context->family_value & ~family;
    do {
        prior = selected;
        for (id = 1; id <= CDISASM_MIPS_FAMILY_LAST; ++id) {
            const cdisasm_mips_family_mask bit = UINT64_C(1) << (id - 1u);
            const cdisasm_mips_family_mask dependencies = flag_families(mips_families[id].required_flags);
            if ((selected & bit) != 0 && (selected & dependencies) != dependencies) selected &= ~bit;
        }
        if (context->revision == CDISASM_MIPS_REVISION_64R2 &&
            (selected & CDISASM_MIPS_FAMILY_MASK_LOONGSIMD) == 0) selected &= ~MSA;
        /* LOONGSON is an umbrella for a selected vendor generation/catalog,
         * not a usable stand-alone processor policy. */
        if ((selected & (CDISASM_MIPS_FAMILY_MASK_LOONGSON2E | CDISASM_MIPS_FAMILY_MASK_LOONGSON2F |
                         CDISASM_MIPS_FAMILY_MASK_LOONGSON_EXT | CDISASM_MIPS_FAMILY_MASK_LOONGSON_CAM |
                         CDISASM_MIPS_FAMILY_MASK_LOONGSIMD | CDISASM_MIPS_FAMILY_MASK_LOONGASX)) == 0) selected &= ~CDISASM_MIPS_FAMILY_MASK_LOONGSON;
    } while (selected != prior);
    flags = family_flags(selected) | (context->flags.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_FPR32);
    if (conflicting_features(flags) ||
        (flags & (CDISASM_MIPS_DECODE_FLAG_MSA | CDISASM_MIPS_DECODE_FLAG_FPR32)) ==
        (CDISASM_MIPS_DECODE_FLAG_MSA | CDISASM_MIPS_DECODE_FLAG_FPR32)) return 0;
    context->family_value = selected;
    return 1;
}

cdisasm_mips_family_mask CDISASM_CALL cdisasm_mips_decode_context_get_available_families(const cdisasm_mips_decode_context *context)
{
    return context == NULL ? 0 : context->family_mask;
}

cdisasm_mips_family_mask CDISASM_CALL cdisasm_mips_decode_context_get_set_families(const cdisasm_mips_decode_context *context)
{
    return context == NULL ? 0 : context->family_value & context->family_mask;
}

static uint32_t fail_result(cdisasm_mips_instruction *instruction, cdisasm_status status)
{
    memset(instruction, 0, sizeof(*instruction));
    instruction->last_error_id = (uint8_t)status;
    return 0;
}

static uint64_t form_required_flags(cdisasm_mips_form_id form)
{
    if (form >= 16384u && form < 19000u) return cdisasm_mips_extra_required_flags(form);
    if (form >= 20000u && form < 25000u) return cdisasm_mips_generated_required_flags(form);
    if (form >= 30000u && form < 34000u) return cdisasm_mips_compact_required_flags(form);
    if (form >= 35000u && form < 40000u) return cdisasm_mips_nano_required_flags(form);
    if (form >= 40000u && form < 45000u) return cdisasm_mips_allegrex_required_flags(form);
    if (form >= 45000u && form < 50000u) return cdisasm_mips_r5900_required_flags(form);
    if (form >= 50000u && form < 55000u) return cdisasm_mips_mxu_required_flags(form);
    if (form >= 55000u && form < 56000u) return cdisasm_mips_mips16e2_required_flags(form);
    if (form >= 56000u && form < 59000u) return cdisasm_mips_mxu_vector_required_flags(form);
    if (form >= 60000u && form < 62000u) return cdisasm_mips_loongasx_required_flags(form);
    if (form >= 59000u && form < 62000u) return cdisasm_mips_loongsimd_required_flags(form);
    if (form >= 62000u) return cdisasm_mips_vu_required_flags(form);
    return 0;
}

static cdisasm_mips_family_mask instruction_families(const cdisasm_mips_instruction *instruction)
{
    const uint64_t minimum = form_required_flags(instruction->form_id);
    cdisasm_mips_family_mask result = flag_families(minimum);
    if ((instruction->instruction_flags & CDISASM_MIPS_INSTRUCTION_FLAG_FLOATING_POINT) != 0 &&
        (minimum & (CDISASM_MIPS_DECODE_FLAG_MXU2 | CDISASM_MIPS_DECODE_FLAG_MXU3 |
                    CDISASM_MIPS_DECODE_FLAG_R5900_VU0 | CDISASM_MIPS_DECODE_FLAG_R5900_VU1)) == 0) result |= FPU;
    if (instruction->instruction_flags & CDISASM_MIPS_INSTRUCTION_FLAG_DSP) result |= DSP;
    if (instruction->instruction_flags & CDISASM_MIPS_INSTRUCTION_FLAG_MT) result |= MT;
    if (instruction->instruction_flags & CDISASM_MIPS_INSTRUCTION_FLAG_MSA) result |= MSA | FPU;
    if ((instruction->instruction_flags & CDISASM_MIPS_INSTRUCTION_FLAG_MSA) != 0 && instruction->revision == CDISASM_MIPS_REVISION_64R2)
        result |= CDISASM_MIPS_FAMILY_MASK_LOONGSON | CDISASM_MIPS_FAMILY_MASK_LOONGSIMD;
    if (instruction->instruction_flags & CDISASM_MIPS_INSTRUCTION_FLAG_DSPR2) result |= DSP2 | DSP;
    if (instruction->instruction_flags & CDISASM_MIPS_INSTRUCTION_FLAG_DSPR3) result |= DSP3 | DSP2 | DSP;
    if (instruction->instruction_flags & CDISASM_MIPS_INSTRUCTION_FLAG_MIPS3D) result |= M3D | FPU;
    if (instruction->instruction_flags & CDISASM_MIPS_INSTRUCTION_FLAG_PAIRED_SINGLE) result |= PS | FPU;
    if (instruction->instruction_flags & CDISASM_MIPS_INSTRUCTION_FLAG_COP2) result |= COP2;
    if (instruction->instruction_flags & CDISASM_MIPS_INSTRUCTION_FLAG_COP3) result |= COP3;
    if (instruction->instruction_flags & CDISASM_MIPS_INSTRUCTION_FLAG_VZ) result |= VZ;
    if (instruction->instruction_flags & CDISASM_MIPS_INSTRUCTION_FLAG_EVA) result |= CDISASM_MIPS_FAMILY_MASK_EVA;
    if (instruction->instruction_flags & CDISASM_MIPS_INSTRUCTION_FLAG_XPA) result |= CDISASM_MIPS_FAMILY_MASK_XPA;
    if (instruction->name_id >= CDISASM_MIPS_NAME_ADDQH_PH && instruction->name_id <= CDISASM_MIPS_NAME_SUBUH_R_QB) result |= DSP2 | DSP;
    return result;
}

uint64_t cdisasm_mips_instruction_required_flags(const cdisasm_mips_instruction *instruction)
{
    return family_flags(instruction_families(instruction)) |
        ((instruction->instruction_flags & CDISASM_MIPS_INSTRUCTION_FLAG_FPR32) ? CDISASM_MIPS_DECODE_FLAG_FPR32 : 0);
}

static cdisasm_mips_family_mask selectable_instruction_families(const cdisasm_mips_instruction *instruction)
{
    cdisasm_mips_family_mask families = instruction_families(instruction);
    /* The 64R2 Loongson selectors make an older revision replay the 3A4000
     * MSA slice. They are processor policy rather than MSA opcode families. */
    if ((instruction->instruction_flags & CDISASM_MIPS_INSTRUCTION_FLAG_MSA) != 0)
        families &= ~(CDISASM_MIPS_FAMILY_MASK_LOONGSON | CDISASM_MIPS_FAMILY_MASK_LOONGSIMD);
    return family_dependencies(families);
}

static cdisasm_mips_family_id most_specific_family(cdisasm_mips_family_mask families)
{
    cdisasm_mips_family_mask direct = families;
    cdisasm_mips_family_id result = CDISASM_MIPS_FAMILY_NONE;
    unsigned id;
    for (id = 1; id <= CDISASM_MIPS_FAMILY_LAST; ++id) {
        const cdisasm_mips_family_mask bit = UINT64_C(1) << (id - 1u);
        if ((families & bit) != 0)
            direct &= ~(flag_families(mips_families[id].required_flags) & ~bit);
    }
    /* MIPS3D can also require the paired-single substrate for this form.
     * Preserve the extension's direct identity when both are present. */
    if ((direct & M3D) != 0) direct &= ~PS;
    for (id = 1; id <= CDISASM_MIPS_FAMILY_LAST; ++id)
        if ((direct & (UINT64_C(1) << (id - 1u))) != 0) result = (cdisasm_mips_family_id)id;
    return result;
}

cdisasm_mips_family_mask CDISASM_CALL cdisasm_mips_instruction_family_mask(const cdisasm_mips_instruction *instruction)
{
    return cdisasm_mips_instruction_validate(instruction)
        ? selectable_instruction_families(instruction) : CDISASM_MIPS_FAMILY_MASK_NONE;
}

cdisasm_mips_family_id CDISASM_CALL cdisasm_mips_instruction_family(const cdisasm_mips_instruction *instruction)
{
    return most_specific_family(cdisasm_mips_instruction_family_mask(instruction));
}

cdisasm_mips_family_mask CDISASM_CALL cdisasm_mips_instruction_family_mask_v2(const cdisasm_mips_instruction_v2 *instruction)
{
    return cdisasm_mips_instruction_validate_v2(instruction)
        ? selectable_instruction_families(&instruction->instruction) : CDISASM_MIPS_FAMILY_MASK_NONE;
}

cdisasm_mips_family_id CDISASM_CALL cdisasm_mips_instruction_family_v2(const cdisasm_mips_instruction_v2 *instruction)
{
    return most_specific_family(cdisasm_mips_instruction_family_mask_v2(instruction));
}

cdisasm_mips_family_mask CDISASM_CALL cdisasm_mips_instruction_family_mask_vu(const cdisasm_mips_vu_instruction *instruction)
{
    if (!cdisasm_mips_vu_instruction_validate(instruction)) return CDISASM_MIPS_FAMILY_MASK_NONE;
    return selectable_instruction_families(&instruction->upper.instruction) |
           selectable_instruction_families(&instruction->lower.instruction);
}

cdisasm_mips_family_id CDISASM_CALL cdisasm_mips_instruction_family_vu(const cdisasm_mips_vu_instruction *instruction)
{
    return most_specific_family(cdisasm_mips_instruction_family_mask_vu(instruction));
}

uint32_t CDISASM_CALL cdisasm_mips_decode(cdisasm_mips_cpu_id cpu_id, cdisasm_mips_mode mode, const uint8_t *code, size_t code_size, uint64_t address,
                                       const cdisasm_mips_decode_flags *flags, cdisasm_mips_instruction *instruction)
{
    cdisasm_mips_decode_flags snapshot = CDISASM_MIPS_DECODE_FLAGS_NONE_INITIALIZER;
    cdisasm_mips_decode_flags effective = CDISASM_MIPS_DECODE_FLAGS_NONE_INITIALIZER;
    const mips_cpu_profile *profile;
    cdisasm_mips_revision revision;
    cdisasm_mips_family_mask supported;
    uint64_t options;
    uint64_t requested;
    uint32_t raw;
    uint32_t i;
    cdisasm_status status;
    if (instruction == NULL) return 0;
    if (flags != NULL) snapshot = *flags;
    memset(instruction, 0, sizeof(*instruction));
    profile = profile_for(cpu_id);
    if (profile == NULL || (profile->modes & mode_bit(mode)) == 0) return fail_result(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
    options = snapshot.bitmap[0];
    if ((options & ~CDISASM_MIPS_DECODE_FLAG_KNOWN_MASK_0) != 0) return fail_result(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
    for (i = 1; i < CDISASM_DECODE_FLAGS_BITMAP_COUNT; ++i) if (snapshot.bitmap[i] != 0) return fail_result(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
    revision = selected_revision(profile, options);
    if (!revision_supports_mode(revision, mode)) return fail_result(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
    if ((options & CDISASM_MIPS_DECODE_FLAG_FPR32) != 0 &&
        (revision == CDISASM_MIPS_REVISION_32R6 || revision == CDISASM_MIPS_REVISION_64R6)) return fail_result(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
    if (conflicting_features(options)) return fail_result(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
    requested = options & CDISASM_MIPS_DECODE_FLAG_FEATURE_MASK;
    {
        cdisasm_mips_family_mask selected = flag_families(requested);
        unsigned family_id;
        for (family_id = 1; family_id <= CDISASM_MIPS_FAMILY_LAST; ++family_id) {
            if ((selected & (UINT64_C(1) << (family_id - 1u))) != 0 &&
                (requested & mips_families[family_id].required_flags) != mips_families[family_id].required_flags)
                return fail_result(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
        }
    }
    if (((requested & CDISASM_MIPS_DECODE_FLAG_DSPR2) != 0 && (requested & CDISASM_MIPS_DECODE_FLAG_DSP) == 0) ||
        ((requested & CDISASM_MIPS_DECODE_FLAG_MSA) != 0 &&
         ((requested & CDISASM_MIPS_DECODE_FLAG_FPU) == 0 || (options & CDISASM_MIPS_DECODE_FLAG_FPR32) != 0))) return fail_result(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
    supported = revision_families(profile, mode, revision);
    effective.bitmap[0] = (requested != 0 || (options & CDISASM_MIPS_DECODE_FLAG_EXPLICIT_FAMILIES) != 0) ? requested & family_flags(supported) : family_flags(default_families(profile, supported, revision));
    effective.bitmap[0] |= options & CDISASM_MIPS_DECODE_FLAG_FPR32;
    apply_cpu_policy(profile, &effective);
    effective.bitmap[CDISASM_MIPS_INTERNAL_POLICY_WORD] |= requested &
        (CDISASM_MIPS_DECODE_FLAG_MXU2 | CDISASM_MIPS_DECODE_FLAG_MXU3 | CDISASM_MIPS_DECODE_FLAG_MXU3_1 | CDISASM_MIPS_DECODE_FLAG_LOONGASX);
    if (conflicting_features(effective.bitmap[0])) return fail_result(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
    if ((effective.bitmap[0] & (CDISASM_MIPS_DECODE_FLAG_MSA | CDISASM_MIPS_DECODE_FLAG_FPR32)) ==
        (CDISASM_MIPS_DECODE_FLAG_MSA | CDISASM_MIPS_DECODE_FLAG_FPR32)) return fail_result(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
    if (code_size == 0) return fail_result(instruction, CDISASM_STATUS_END_OF_INPUT);
    if (code == NULL) return fail_result(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
    if (options & CDISASM_MIPS_DECODE_FLAG_ENCODING_MASK) return fail_result(instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    if (code_size < 4u) return fail_result(instruction, CDISASM_STATUS_TRUNCATED);
    if (options & CDISASM_MIPS_DECODE_FLAG_BIG_ENDIAN) raw = ((uint32_t)code[0] << 24) | ((uint32_t)code[1] << 16) | ((uint32_t)code[2] << 8) | code[3];
    else raw = (uint32_t)code[0] | ((uint32_t)code[1] << 8) | ((uint32_t)code[2] << 16) | ((uint32_t)code[3] << 24);
    status = cdisasm_mips_decode_core(raw, address, mode, revision, &effective, instruction);
    if (status == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        cdisasm_mips_instruction recognized;
        cdisasm_mips_decode_flags all = CDISASM_MIPS_DECODE_FLAGS_INITIALIZER(CDISASM_MIPS_DECODE_FLAG_FEATURE_MASK);
        const uint64_t processor_flags = CDISASM_MIPS_DECODE_FLAG_ALLEGREX | CDISASM_MIPS_DECODE_FLAG_R5900 |
            CDISASM_MIPS_DECODE_FLAG_LOONGSON | CDISASM_MIPS_DECODE_FLAG_LOONGSON2E | CDISASM_MIPS_DECODE_FLAG_LOONGSON2F |
            CDISASM_MIPS_DECODE_FLAG_CNMIPS | CDISASM_MIPS_DECODE_FLAG_CNMIPSP | CDISASM_MIPS_DECODE_FLAG_MXU |
            CDISASM_MIPS_DECODE_FLAG_LOONGSON_EXT | CDISASM_MIPS_DECODE_FLAG_LOONGSON_EXT2 | CDISASM_MIPS_DECODE_FLAG_LOONGSON_CAM |
            CDISASM_MIPS_DECODE_FLAG_SMARTMIPS | CDISASM_MIPS_DECODE_FLAG_MXU2 | CDISASM_MIPS_DECODE_FLAG_MXU3 |
            CDISASM_MIPS_DECODE_FLAG_MXU3_1 | CDISASM_MIPS_DECODE_FLAG_LOONGSIMD | CDISASM_MIPS_DECODE_FLAG_LOONGASX |
            CDISASM_MIPS_DECODE_FLAG_R5900_VU0 | CDISASM_MIPS_DECODE_FLAG_R5900_VU1;
        all.bitmap[0] = (all.bitmap[0] & ~processor_flags) | (effective.bitmap[0] & processor_flags);
        all.bitmap[0] |= effective.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_FPR32;
        all.bitmap[CDISASM_MIPS_INTERNAL_POLICY_WORD] = effective.bitmap[CDISASM_MIPS_INTERNAL_POLICY_WORD];
        memset(&recognized, 0, sizeof(recognized));
        if (cdisasm_mips_decode_core(raw, address, mode, revision, &all, &recognized) == CDISASM_STATUS_OK &&
            (instruction_families(&recognized) & ~profile->families) != 0) status = CDISASM_STATUS_INVALID_INSTRUCTION;
    }
    if (status != CDISASM_STATUS_OK) return fail_result(instruction, status);
    {
        cdisasm_mips_family_mask required = instruction_families(instruction);
        if ((required & ~profile->families) != 0) return fail_result(instruction, CDISASM_STATUS_INVALID_INSTRUCTION);
        if ((required & ~flag_families(effective.bitmap[0] | effective.bitmap[CDISASM_MIPS_INTERNAL_POLICY_WORD])) != 0) return fail_result(instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
    instruction->address = address;
    instruction->raw_instruction = raw;
    instruction->opcode_size = 4;
    instruction->revision = (uint8_t)revision;
    instruction->mode = (uint8_t)mode;
    return 4;
}

uint32_t CDISASM_CALL cdisasm_mips_decode_with_context(const cdisasm_mips_decode_context *context, const uint8_t *code, size_t code_size, uint64_t address,
                                                    cdisasm_mips_instruction *instruction)
{
    cdisasm_mips_decode_context snapshot;
    cdisasm_mips_decode_flags flags;
    uint64_t selected;
    if (instruction == NULL) return 0;
    if (context == NULL) return fail_result(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
    snapshot = *context;
    if (snapshot.reserved != 0 || !revision_flag(snapshot.revision) || (snapshot.family_mask & ~CDISASM_MIPS_FAMILY_MASK_ALL) != 0 ||
        (snapshot.family_value & ~snapshot.family_mask) != 0 ||
        snapshot.family_mask != revision_families(profile_for(snapshot.cpu_id), snapshot.mode, snapshot.revision) ||
        (snapshot.flags.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_ISA_MASK) != revision_flag(snapshot.revision)) return fail_result(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
    flags = snapshot.flags;
    selected = (flags.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_FEATURE_MASK) & family_flags(snapshot.family_value);
    flags.bitmap[0] &= ~CDISASM_MIPS_DECODE_FLAG_FEATURE_MASK;
    flags.bitmap[0] |= selected | CDISASM_MIPS_DECODE_FLAG_EXPLICIT_FAMILIES;
    return cdisasm_mips_decode(snapshot.cpu_id, snapshot.mode, code, code_size, address, &flags, instruction);
}

static uint32_t fail_v2(cdisasm_mips_instruction_v2 *instruction, cdisasm_status status)
{
    memset(instruction, 0, sizeof(*instruction));
    instruction->instruction.last_error_id = (uint8_t)status;
    return 0;
}

static uint64_t encoding_option(cdisasm_mips_encoding encoding)
{
    switch (encoding) {
        case CDISASM_MIPS_ENCODING_STANDARD: return 0;
        case CDISASM_MIPS_ENCODING_MIPS16: return CDISASM_MIPS_DECODE_FLAG_MIPS16;
        case CDISASM_MIPS_ENCODING_MICROMIPS: return CDISASM_MIPS_DECODE_FLAG_MICROMIPS;
        case CDISASM_MIPS_ENCODING_NANOMIPS: return CDISASM_MIPS_DECODE_FLAG_NANOMIPS;
        case CDISASM_MIPS_ENCODING_VU_UPPER: return CDISASM_MIPS_DECODE_FLAG_VU_UPPER;
        case CDISASM_MIPS_ENCODING_VU_LOWER: return CDISASM_MIPS_DECODE_FLAG_VU_LOWER;
        case CDISASM_MIPS_ENCODING_VU_LOWER_LOI: return CDISASM_MIPS_DECODE_FLAG_VU_LOWER_LOI;
        default: return 0;
    }
}

static cdisasm_mips_family_mask encoding_families(const mips_cpu_profile *profile, cdisasm_mips_mode mode,
    cdisasm_mips_revision revision, cdisasm_mips_encoding encoding)
{
    if (encoding >= CDISASM_MIPS_ENCODING_VU_UPPER)
        return available_families(profile, mode) & (CDISASM_MIPS_FAMILY_MASK_R5900 |
            CDISASM_MIPS_FAMILY_MASK_R5900_VU0 | CDISASM_MIPS_FAMILY_MASK_R5900_VU1);
    if (encoding == CDISASM_MIPS_ENCODING_NANOMIPS)
        return available_families(profile, mode) & (FPU | COP2 | DSP | DSP2 | DSP3 | MT |
            CDISASM_MIPS_FAMILY_MASK_EVA | CDISASM_MIPS_FAMILY_MASK_CRC | CDISASM_MIPS_FAMILY_MASK_GINV);
    return revision_families(profile, mode, revision);
}

static cdisasm_status prepare_v2(cdisasm_mips_cpu_id cpu_id, cdisasm_mips_mode mode,
                                const cdisasm_mips_decode_flags *snapshot, cdisasm_mips_encoding encoding,
                                const mips_cpu_profile **profile_out, cdisasm_mips_revision *revision_out,
                                cdisasm_mips_decode_flags *effective)
{
    const mips_cpu_profile *profile = profile_for(cpu_id);
    const uint64_t options = snapshot->bitmap[0];
    const uint64_t requested = options & CDISASM_MIPS_DECODE_FLAG_FEATURE_MASK;
    cdisasm_mips_family_mask supported;
    cdisasm_mips_revision revision;
    unsigned index;
    if (profile == NULL || (profile->modes & mode_bit(mode)) == 0 ||
        (options & ~CDISASM_MIPS_DECODE_FLAG_KNOWN_MASK_0) != 0) return CDISASM_STATUS_INVALID_ARGUMENT;
    for (index = 1; index < CDISASM_DECODE_FLAGS_BITMAP_COUNT; ++index)
        if (snapshot->bitmap[index] != 0) return CDISASM_STATUS_INVALID_ARGUMENT;
    if (conflicting_features(options)) return CDISASM_STATUS_INVALID_ARGUMENT;
    revision = selected_revision(profile, options);
    if (!revision_supports_mode(revision, mode)) return CDISASM_STATUS_INVALID_ARGUMENT;
    if (encoding >= CDISASM_MIPS_ENCODING_VU_UPPER &&
        (mode != CDISASM_MIPS_MODE_64 || revision != CDISASM_MIPS_REVISION_III ||
         (profile->families & CDISASM_MIPS_FAMILY_MASK_R5900) == 0)) return CDISASM_STATUS_INVALID_ARGUMENT;
    if (encoding > CDISASM_MIPS_ENCODING_STANDARD && encoding < CDISASM_MIPS_ENCODING_VU_UPPER &&
        (((profile->revision != CDISASM_MIPS_REVISION_NONE) && (profile->families &
            (CDISASM_MIPS_FAMILY_MASK_ALLEGREX | CDISASM_MIPS_FAMILY_MASK_R5900 | CDISASM_MIPS_FAMILY_MASK_LOONGSON |
             CDISASM_MIPS_FAMILY_MASK_CNMIPS | CDISASM_MIPS_FAMILY_MASK_MXU | CDISASM_MIPS_FAMILY_MASK_MXU2 | CDISASM_MIPS_FAMILY_MASK_MXU3)) != 0) ||
         (requested & (CDISASM_MIPS_DECODE_FLAG_ALLEGREX | CDISASM_MIPS_DECODE_FLAG_R5900 | CDISASM_MIPS_DECODE_FLAG_LOONGSON |
             CDISASM_MIPS_DECODE_FLAG_CNMIPS | CDISASM_MIPS_DECODE_FLAG_MXU | CDISASM_MIPS_DECODE_FLAG_MXU2 | CDISASM_MIPS_DECODE_FLAG_MXU3)) != 0)) return CDISASM_STATUS_INVALID_ARGUMENT;
    if (encoding == CDISASM_MIPS_ENCODING_MIPS16 &&
        (revision == CDISASM_MIPS_REVISION_32R6 || revision == CDISASM_MIPS_REVISION_64R6)) return CDISASM_STATUS_INVALID_ARGUMENT;
    if (encoding == CDISASM_MIPS_ENCODING_NANOMIPS &&
        (mode != CDISASM_MIPS_MODE_32 || revision != CDISASM_MIPS_REVISION_32R6)) return CDISASM_STATUS_INVALID_ARGUMENT;
    if ((options & CDISASM_MIPS_DECODE_FLAG_FPR32) != 0 &&
        (revision == CDISASM_MIPS_REVISION_32R6 || revision == CDISASM_MIPS_REVISION_64R6)) return CDISASM_STATUS_INVALID_ARGUMENT;
    for (index = 1; index <= CDISASM_MIPS_FAMILY_LAST; ++index)
        if ((requested & (UINT64_C(1) << mips_family_flag_bits[index])) != 0 &&
            (requested & mips_families[index].required_flags) != mips_families[index].required_flags)
            return CDISASM_STATUS_INVALID_ARGUMENT;
    supported = encoding_families(profile, mode, revision, encoding);
    memset(effective, 0, sizeof(*effective));
    effective->bitmap[0] = (requested != 0 || (options & CDISASM_MIPS_DECODE_FLAG_EXPLICIT_FAMILIES) != 0)
        ? requested & family_flags(supported) : family_flags(default_families(profile, supported, revision));
    if (encoding >= CDISASM_MIPS_ENCODING_VU_UPPER && requested == 0 &&
        (options & CDISASM_MIPS_DECODE_FLAG_EXPLICIT_FAMILIES) == 0)
        effective->bitmap[0] = family_flags(supported & (CDISASM_MIPS_FAMILY_MASK_R5900 | CDISASM_MIPS_FAMILY_MASK_R5900_VU0));
    effective->bitmap[0] |= options & CDISASM_MIPS_DECODE_FLAG_FPR32;
    apply_cpu_policy(profile, effective);
    effective->bitmap[CDISASM_MIPS_INTERNAL_POLICY_WORD] |= requested &
        (CDISASM_MIPS_DECODE_FLAG_MXU2 | CDISASM_MIPS_DECODE_FLAG_MXU3 | CDISASM_MIPS_DECODE_FLAG_MXU3_1 | CDISASM_MIPS_DECODE_FLAG_LOONGASX);
    if (conflicting_features(effective->bitmap[0])) return CDISASM_STATUS_INVALID_ARGUMENT;
    if ((effective->bitmap[0] & (CDISASM_MIPS_DECODE_FLAG_MSA | CDISASM_MIPS_DECODE_FLAG_FPR32)) ==
        (CDISASM_MIPS_DECODE_FLAG_MSA | CDISASM_MIPS_DECODE_FLAG_FPR32)) return CDISASM_STATUS_INVALID_ARGUMENT;
    *profile_out = profile;
    *revision_out = revision;
    return CDISASM_STATUS_OK;
}

uint32_t CDISASM_CALL cdisasm_mips_decode_v2(cdisasm_mips_cpu_id cpu_id, cdisasm_mips_mode mode,
    const uint8_t *code, size_t code_size, uint64_t address, const cdisasm_mips_decode_flags *flags,
    cdisasm_mips_instruction_v2 *instruction)
{
    cdisasm_mips_decode_flags snapshot = CDISASM_MIPS_DECODE_FLAGS_NONE_INITIALIZER;
    cdisasm_mips_decode_flags effective;
    const mips_cpu_profile *profile;
    cdisasm_mips_revision revision;
    cdisasm_mips_encoding encoding = CDISASM_MIPS_ENCODING_STANDARD;
    cdisasm_status status;
    uint64_t selected, raw = 0;
    uint32_t size, offset;
    uint16_t first;
    if (instruction == NULL) return 0;
    if (flags != NULL) snapshot = *flags;
    memset(instruction, 0, sizeof(*instruction));
    selected = snapshot.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_ENCODING_MASK;
    if (selected != 0 && (selected & (selected - 1u)) != 0) return fail_v2(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
    if (selected == CDISASM_MIPS_DECODE_FLAG_MIPS16) encoding = CDISASM_MIPS_ENCODING_MIPS16;
    else if (selected == CDISASM_MIPS_DECODE_FLAG_MICROMIPS) encoding = CDISASM_MIPS_ENCODING_MICROMIPS;
    else if (selected == CDISASM_MIPS_DECODE_FLAG_NANOMIPS) encoding = CDISASM_MIPS_ENCODING_NANOMIPS;
    else if (selected == CDISASM_MIPS_DECODE_FLAG_VU_UPPER) encoding = CDISASM_MIPS_ENCODING_VU_UPPER;
    else if (selected == CDISASM_MIPS_DECODE_FLAG_VU_LOWER) encoding = CDISASM_MIPS_ENCODING_VU_LOWER;
    else if (selected == CDISASM_MIPS_DECODE_FLAG_VU_LOWER_LOI) encoding = CDISASM_MIPS_ENCODING_VU_LOWER_LOI;
    if (encoding == CDISASM_MIPS_ENCODING_STANDARD) {
        size = cdisasm_mips_decode(cpu_id, mode, code, code_size, address, &snapshot, &instruction->instruction);
        if (size == 0) return 0;
    } else if (encoding >= CDISASM_MIPS_ENCODING_VU_UPPER) {
        uint32_t word;
        status = prepare_v2(cpu_id, mode, &snapshot, encoding, &profile, &revision, &effective);
        if (status != CDISASM_STATUS_OK) return fail_v2(instruction, status);
        if (code_size == 0) return fail_v2(instruction, CDISASM_STATUS_END_OF_INPUT);
        if (code == NULL) return fail_v2(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
        if (code_size < 4u) return fail_v2(instruction, CDISASM_STATUS_TRUNCATED);
        word = (snapshot.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_BIG_ENDIAN) != 0
            ? ((uint32_t)code[0] << 24) | ((uint32_t)code[1] << 16) | ((uint32_t)code[2] << 8) | code[3]
            : (uint32_t)code[0] | ((uint32_t)code[1] << 8) | ((uint32_t)code[2] << 16) | ((uint32_t)code[3] << 24);
        status = cdisasm_mips_decode_vu_word(word, address, encoding,
            (effective.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_R5900_VU1) != 0 ? 1u : 0u,
            mode, revision, &effective, &instruction->instruction);
        if (status != CDISASM_STATUS_OK) return fail_v2(instruction, status);
        if ((instruction_families(&instruction->instruction) & ~profile->families) != 0)
            return fail_v2(instruction, CDISASM_STATUS_INVALID_INSTRUCTION);
        if ((instruction_families(&instruction->instruction) & ~flag_families(effective.bitmap[0])) != 0)
            return fail_v2(instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        size = 4u;
    } else {
        status = prepare_v2(cpu_id, mode, &snapshot, encoding, &profile, &revision, &effective);
        if (status != CDISASM_STATUS_OK) return fail_v2(instruction, status);
        if (code_size == 0) return fail_v2(instruction, CDISASM_STATUS_END_OF_INPUT);
        if (code == NULL) return fail_v2(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
        if (code_size < 2u) return fail_v2(instruction, CDISASM_STATUS_TRUNCATED);
        first = (snapshot.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_BIG_ENDIAN) != 0
            ? (uint16_t)(((uint16_t)code[0] << 8) | code[1]) : (uint16_t)(((uint16_t)code[1] << 8) | code[0]);
        size = encoding == CDISASM_MIPS_ENCODING_NANOMIPS ? cdisasm_mips_nano_size(first)
            : cdisasm_mips_compact_size(encoding, first);
        if (size == 0 || size > 6u || (size & 1u) != 0) return fail_v2(instruction, CDISASM_STATUS_INVALID_INSTRUCTION);
        if (code_size < size) return fail_v2(instruction, CDISASM_STATUS_TRUNCATED);
        for (offset = 0; offset < size; offset += 2u) {
            const uint16_t parcel = (snapshot.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_BIG_ENDIAN) != 0
                ? (uint16_t)(((uint16_t)code[offset] << 8) | code[offset + 1u])
                : (uint16_t)(((uint16_t)code[offset + 1u] << 8) | code[offset]);
            raw = (raw << 16) | parcel;
        }
        if (encoding == CDISASM_MIPS_ENCODING_NANOMIPS)
            status = cdisasm_mips_decode_nano(raw, size, address, mode, revision, &effective, &instruction->instruction);
        else if (encoding == CDISASM_MIPS_ENCODING_MIPS16 && size == 4u && cdisasm_mips_mips16e2_owns((uint32_t)raw))
            status = cdisasm_mips_decode_mips16e2((uint32_t)raw, size, address, mode, revision, &effective, &instruction->instruction);
        else
            status = cdisasm_mips_decode_compact(raw, size, encoding, address, mode, revision, &effective, &instruction->instruction);
        if (status != CDISASM_STATUS_OK) return fail_v2(instruction, status);
        if ((instruction_families(&instruction->instruction) & ~profile->families) != 0)
            return fail_v2(instruction, CDISASM_STATUS_INVALID_INSTRUCTION);
        if ((instruction_families(&instruction->instruction) & ~flag_families(effective.bitmap[0] | effective.bitmap[CDISASM_MIPS_INTERNAL_POLICY_WORD])) != 0)
            return fail_v2(instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        instruction->instruction.address = address;
        instruction->instruction.raw_instruction = (uint32_t)raw;
        instruction->instruction.opcode_size = (uint8_t)size;
        instruction->instruction.mode = (uint8_t)mode;
        instruction->instruction.revision = (uint8_t)revision;
    }
    memcpy(instruction->raw_bytes, code, size);
    instruction->encoding = encoding;
    instruction->structure_version = CDISASM_MIPS_V2_STRUCTURE_VERSION;
    instruction->required_flags = cdisasm_mips_instruction_required_flags(&instruction->instruction) |
        selected | revision_flag(instruction->instruction.revision) |
        (snapshot.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_BIG_ENDIAN);
    return size;
}

cdisasm_status CDISASM_CALL cdisasm_mips_cpu_decode_context_v2(cdisasm_mips_cpu_id cpu_id, cdisasm_mips_mode mode,
    cdisasm_mips_revision revision, cdisasm_mips_encoding encoding, cdisasm_mips_decode_context *context)
{
    const mips_cpu_profile *profile;
    cdisasm_mips_decode_flags effective;
    cdisasm_status status;
    uint64_t encoding_flag = 0;
    if (context == NULL) return CDISASM_STATUS_INVALID_ARGUMENT;
    memset(context, 0, sizeof(*context));
    if (encoding > CDISASM_MIPS_ENCODING_VU_LOWER_LOI) return CDISASM_STATUS_INVALID_ARGUMENT;
    status = cdisasm_mips_cpu_decode_context(cpu_id, mode, revision, context);
    if (status != CDISASM_STATUS_OK) return status;
    if (encoding != CDISASM_MIPS_ENCODING_STANDARD) encoding_flag = encoding_option(encoding);
    context->flags.bitmap[0] = revision_flag(context->revision) | encoding_flag;
    status = prepare_v2(cpu_id, mode, &context->flags, encoding, &profile, &revision, &effective);
    if (status != CDISASM_STATUS_OK) { memset(context, 0, sizeof(*context)); return status; }
    context->family_mask = encoding_families(profile, mode, revision, encoding);
    context->family_value = default_families(profile, context->family_mask, revision);
    if (encoding >= CDISASM_MIPS_ENCODING_VU_UPPER)
        context->family_value = context->family_mask & (CDISASM_MIPS_FAMILY_MASK_R5900 | CDISASM_MIPS_FAMILY_MASK_R5900_VU0);
    context->flags.bitmap[0] |= CDISASM_MIPS_DECODE_FLAG_EXPLICIT_FAMILIES | family_flags(context->family_mask);
    return CDISASM_STATUS_OK;
}

uint32_t CDISASM_CALL cdisasm_mips_decode_with_context_v2(const cdisasm_mips_decode_context *context,
    const uint8_t *code, size_t code_size, uint64_t address, cdisasm_mips_instruction_v2 *instruction)
{
    cdisasm_mips_decode_context snapshot;
    cdisasm_mips_decode_flags flags;
    uint64_t selected;
    cdisasm_mips_encoding encoding = CDISASM_MIPS_ENCODING_STANDARD;
    if (instruction == NULL) return 0;
    if (context == NULL) return fail_v2(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
    snapshot = *context;
    selected = snapshot.flags.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_ENCODING_MASK;
    if (selected != 0 && (selected & (selected - 1u)) != 0) return fail_v2(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
    if (selected == CDISASM_MIPS_DECODE_FLAG_MIPS16) encoding = CDISASM_MIPS_ENCODING_MIPS16;
    else if (selected == CDISASM_MIPS_DECODE_FLAG_MICROMIPS) encoding = CDISASM_MIPS_ENCODING_MICROMIPS;
    else if (selected == CDISASM_MIPS_DECODE_FLAG_NANOMIPS) encoding = CDISASM_MIPS_ENCODING_NANOMIPS;
    else if (selected == CDISASM_MIPS_DECODE_FLAG_VU_UPPER) encoding = CDISASM_MIPS_ENCODING_VU_UPPER;
    else if (selected == CDISASM_MIPS_DECODE_FLAG_VU_LOWER) encoding = CDISASM_MIPS_ENCODING_VU_LOWER;
    else if (selected == CDISASM_MIPS_DECODE_FLAG_VU_LOWER_LOI) encoding = CDISASM_MIPS_ENCODING_VU_LOWER_LOI;
    if (snapshot.reserved != 0 || !revision_flag(snapshot.revision) ||
        (snapshot.family_value & ~snapshot.family_mask) != 0 ||
        snapshot.family_mask != encoding_families(profile_for(snapshot.cpu_id), snapshot.mode, snapshot.revision, encoding) ||
        (snapshot.flags.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_ISA_MASK) != revision_flag(snapshot.revision))
        return fail_v2(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
    flags = snapshot.flags;
    selected = (flags.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_FEATURE_MASK) & family_flags(snapshot.family_value);
    flags.bitmap[0] &= ~CDISASM_MIPS_DECODE_FLAG_FEATURE_MASK;
    flags.bitmap[0] |= selected | CDISASM_MIPS_DECODE_FLAG_EXPLICIT_FAMILIES;
    return cdisasm_mips_decode_v2(snapshot.cpu_id, snapshot.mode, code, code_size, address, &flags, instruction);
}

int cdisasm_mips_instruction_validate_v2(const cdisasm_mips_instruction_v2 *instruction)
{
    cdisasm_mips_instruction_v2 canonical;
    cdisasm_mips_decode_flags flags = CDISASM_MIPS_DECODE_FLAGS_NONE_INITIALIZER;
    if (instruction == NULL || instruction->structure_version != CDISASM_MIPS_V2_STRUCTURE_VERSION ||
        instruction->instruction.opcode_size > sizeof(instruction->raw_bytes) ||
        instruction->encoding > CDISASM_MIPS_ENCODING_VU_LOWER_LOI) return 0;
    flags.bitmap[0] = instruction->required_flags | CDISASM_MIPS_DECODE_FLAG_EXPLICIT_FAMILIES;
    if (cdisasm_mips_decode_v2(CDISASM_MIPS_CPU_ANY, instruction->instruction.mode,
            instruction->raw_bytes, instruction->instruction.opcode_size, instruction->instruction.address,
            &flags, &canonical) == 0) return 0;
    return memcmp(instruction, &canonical, sizeof(canonical)) == 0;
}

static uint32_t fail_vu(cdisasm_mips_vu_instruction *instruction, cdisasm_status status)
{
    memset(instruction, 0, sizeof(*instruction));
    instruction->last_error_id = status;
    return 0;
}

uint32_t CDISASM_CALL cdisasm_mips_decode_vu(cdisasm_mips_vu_unit unit, const uint8_t *code,
    size_t code_size, uint64_t address, const cdisasm_mips_decode_flags *flags, cdisasm_mips_vu_instruction *instruction)
{
    cdisasm_mips_decode_flags snapshot = CDISASM_MIPS_DECODE_FLAGS_NONE_INITIALIZER;
    cdisasm_mips_decode_flags effective;
    const mips_cpu_profile *profile;
    cdisasm_mips_revision revision;
    cdisasm_status status;
    const uint64_t units = CDISASM_MIPS_DECODE_FLAG_R5900_VU0 | CDISASM_MIPS_DECODE_FLAG_R5900_VU1;
    uint64_t selected_unit;
    if (instruction == NULL) return 0;
    if (flags != NULL) snapshot = *flags;
    memset(instruction, 0, sizeof(*instruction));
    if (unit > 1u || (snapshot.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_ENCODING_MASK) != 0 ||
        ((snapshot.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_ISA_MASK) != 0 &&
         (snapshot.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_ISA_MASK) != CDISASM_MIPS_DECODE_FLAG_ISA_III))
        return fail_vu(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
    selected_unit = unit ? CDISASM_MIPS_DECODE_FLAG_R5900_VU1 : CDISASM_MIPS_DECODE_FLAG_R5900_VU0;
    if ((snapshot.bitmap[0] & units) != 0 && (snapshot.bitmap[0] & units) != selected_unit)
        return fail_vu(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
    if ((snapshot.bitmap[0] & (CDISASM_MIPS_DECODE_FLAG_FEATURE_MASK | CDISASM_MIPS_DECODE_FLAG_EXPLICIT_FAMILIES)) == 0)
        snapshot.bitmap[0] |= CDISASM_MIPS_DECODE_FLAG_R5900 | selected_unit;
    snapshot.bitmap[0] |= CDISASM_MIPS_DECODE_FLAG_ISA_III | CDISASM_MIPS_DECODE_FLAG_EXPLICIT_FAMILIES;
    snapshot.bitmap[0] |= CDISASM_MIPS_DECODE_FLAG_VU_UPPER;
    status = prepare_v2(CDISASM_MIPS_CPU_R5900, CDISASM_MIPS_MODE_64, &snapshot,
        CDISASM_MIPS_ENCODING_VU_UPPER, &profile, &revision, &effective);
    if (status != CDISASM_STATUS_OK) return fail_vu(instruction, status);
    if (code_size == 0) return fail_vu(instruction, CDISASM_STATUS_END_OF_INPUT);
    if (code == NULL) return fail_vu(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
    if (code_size < 8u) return fail_vu(instruction, CDISASM_STATUS_TRUNCATED);
    if (cdisasm_mips_decode_v2(CDISASM_MIPS_CPU_R5900, CDISASM_MIPS_MODE_64, code + 4u, 4u,
            address, &snapshot, &instruction->upper) != 4u)
        return fail_vu(instruction, instruction->upper.instruction.last_error_id);
    instruction->control_flags = instruction->upper.instruction.raw_instruction & CDISASM_MIPS_VU_CONTROL_MASK;
    snapshot.bitmap[0] &= ~CDISASM_MIPS_DECODE_FLAG_ENCODING_MASK;
    snapshot.bitmap[0] |= (instruction->control_flags & CDISASM_MIPS_VU_CONTROL_I) != 0
        ? CDISASM_MIPS_DECODE_FLAG_VU_LOWER_LOI : CDISASM_MIPS_DECODE_FLAG_VU_LOWER;
    if (cdisasm_mips_decode_v2(CDISASM_MIPS_CPU_R5900, CDISASM_MIPS_MODE_64, code, 4u,
            address, &snapshot, &instruction->lower) != 4u)
        return fail_vu(instruction, instruction->lower.instruction.last_error_id);
    memcpy(instruction->raw_bytes, code, 8u);
    return 8u;
}

int cdisasm_mips_vu_instruction_validate(const cdisasm_mips_vu_instruction *instruction)
{
    cdisasm_mips_vu_instruction canonical;
    cdisasm_mips_decode_flags flags = CDISASM_MIPS_DECODE_FLAGS_NONE_INITIALIZER;
    uint32_t unit;
    if (instruction == NULL || instruction->last_error_id != CDISASM_STATUS_OK) return 0;
    unit = (instruction->upper.required_flags & CDISASM_MIPS_DECODE_FLAG_R5900_VU1) != 0 ? 1u : 0u;
    flags.bitmap[0] = ((instruction->upper.required_flags | instruction->lower.required_flags) &
        ~CDISASM_MIPS_DECODE_FLAG_ENCODING_MASK) | CDISASM_MIPS_DECODE_FLAG_EXPLICIT_FAMILIES;
    if (cdisasm_mips_decode_vu(unit, instruction->raw_bytes, 8u, instruction->upper.instruction.address, &flags, &canonical) != 8u) return 0;
    return memcmp(instruction, &canonical, sizeof(canonical)) == 0;
}
