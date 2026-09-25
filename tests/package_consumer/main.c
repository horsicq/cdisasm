#include <cdisasm/cdisasm.h>

#if USE_DISASM_FORMAT && (USE_ARCH_X86 || USE_ARCH_ARM)
#  include <cdisasm/cdisasm_format.h>
#endif

#include <stdio.h>
#include <string.h>

#if !defined(USE_ARCH_X86) || !defined(USE_ARCH_ARM) \
    || !defined(USE_DISASM_FORMAT) || !defined(USE_EXTRA_OPCODES)
#  error "installed cdisasm package does not expose feature defines"
#endif
#if USE_ARCH_X86 != CDISASM_PACKAGE_EXPECT_X86
#  error "installed x86 architecture define and exported targets disagree"
#endif
#if USE_ARCH_ARM != CDISASM_PACKAGE_EXPECT_ARM
#  error "installed ARM architecture define and exported targets disagree"
#endif
#if USE_DISASM_FORMAT != CDISASM_PACKAGE_EXPECT_FORMAT
#  error "installed formatter define and exported targets disagree"
#endif
#if USE_EXTRA_OPCODES != CDISASM_PACKAGE_EXPECT_EXTRA
#  error "installed extra-opcode define and package metadata disagree"
#endif
#if CDISASM_PACKAGE_EXPECT_SHARED
#  if defined(CDISASM_STATIC)
#    error "shared cdisasm package unexpectedly defines CDISASM_STATIC"
#  endif
#elif !defined(CDISASM_STATIC)
#  error "static cdisasm package does not define CDISASM_STATIC"
#endif

_Static_assert(sizeof(cdisasm_decode_option) == 8,
               "installed generic decode-option width changed");
_Static_assert(sizeof(cdisasm_decode_flags) == CDISASM_DECODE_FLAGS_SIZE,
               "installed generic decode-flags ABI size changed");
typedef cdisasm_cpu_id (CDISASM_CALL *current_cpu_function)(void);
_Static_assert(
    _Generic(&cdisasm_current_cpu, current_cpu_function: 1, default: 0),
    "installed current-CPU query signature changed");
#if USE_ARCH_X86
_Static_assert(sizeof(cdisasm_x86_decode_option) == 8,
               "installed x86 decode-option width changed");
_Static_assert(sizeof(cdisasm_x86_decode_flags)
                   == sizeof(cdisasm_decode_flags),
               "installed x86 decode-flags ABI size changed");
#endif
#if USE_ARCH_ARM
_Static_assert(sizeof(cdisasm_arm_decode_option) == 8,
               "installed ARM decode-option width changed");
_Static_assert(sizeof(cdisasm_arm_decode_flags)
                   == sizeof(cdisasm_decode_flags),
               "installed ARM decode-flags ABI size changed");
#endif

#if CDISASM_CPU_GROUP_X86 != UINT32_C(0x00010000) \
    || CDISASM_CPU_GROUP_ARM != UINT32_C(0x00020000)
#  error "installed cdisasm package has unexpected CPU group IDs"
#endif

#if USE_ARCH_X86
#  if CDISASM_CPU_APX \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x0026)) \
    || CDISASM_CPU_LATEST \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x0033)) \
    || CDISASM_CPU_CELERON_G1840 \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x0027)) \
    || CDISASM_CPU_CELERON_G3900 \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x0028)) \
    || CDISASM_CPU_CELERON_N3350 \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x0029)) \
    || CDISASM_CPU_CELERON_N4020 \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x002a)) \
    || CDISASM_CPU_CELERON_G5900 \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x002b)) \
    || CDISASM_CPU_PENTIUM_SILVER_N6000 \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x002c)) \
    || CDISASM_CPU_8086_8087 \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x002d)) \
    || CDISASM_CPU_80186_80187 \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x002e)) \
    || CDISASM_CPU_80286_80287 \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x002f)) \
    || CDISASM_CPU_80386_80387 \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x0030)) \
    || CDISASM_CPU_GRANITE_RAPIDS \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x0031)) \
    || CDISASM_CPU_ARROW_LAKE \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x0032)) \
    || CDISASM_CPU_DIAMOND_RAPIDS \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x0033)) \
    || CDISASM_CPU_INTEL_DIAMOND_RAPIDS \
        != CDISASM_CPU_DIAMOND_RAPIDS \
    || CDISASM_CPU_DMR != CDISASM_CPU_DIAMOND_RAPIDS \
    || CDISASM_CPU_LAST \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x0034)) \
    || CDISASM_CPU_KNIGHTS_MILL \
        != (CDISASM_CPU_GROUP_X86 | UINT32_C(0x0034)) \
    || CDISASM_CPU_INTEL_KNIGHTS_MILL != CDISASM_CPU_KNIGHTS_MILL \
    || CDISASM_CPU_KNM != CDISASM_CPU_KNIGHTS_MILL \
    || CDISASM_CPU_HASWELL_CELERON != CDISASM_CPU_CELERON_G1840 \
    || CDISASM_CPU_SKYLAKE_CELERON != CDISASM_CPU_CELERON_G3900 \
    || CDISASM_CPU_APOLLO_LAKE_CELERON != CDISASM_CPU_CELERON_N3350 \
    || CDISASM_CPU_CELERON_J4125 != CDISASM_CPU_CELERON_N4020 \
    || CDISASM_CPU_CELERON_G5905 != CDISASM_CPU_CELERON_G5900 \
    || CDISASM_CPU_CELERON_N5105 != CDISASM_CPU_PENTIUM_SILVER_N6000 \
    || CDISASM_CPU_8088_8087 != CDISASM_CPU_8086_8087 \
    || CDISASM_CPU_286_287 != CDISASM_CPU_80286_80287 \
    || CDISASM_CPU_386_387 != CDISASM_CPU_80386_80387
#    error "installed cdisasm package has unexpected x86 CPU profile IDs"
#  endif
#endif

#if USE_ARCH_ARM
#  if CDISASM_ARM_NAME_VBIC != 75 || CDISASM_ARM_NAME_AT_AS1ELX != 76 \
    || CDISASM_ARM_NAME_WKDMD != 109 \
    || CDISASM_ARM_NAME_LDARB != 110 \
    || CDISASM_ARM_NAME_STLXP != 131 \
    || CDISASM_ARM_NAME_CASB != 132 \
    || CDISASM_ARM_NAME_LDAPR != 216 \
    || CDISASM_ARM_NAME_MLA != 217 \
    || CDISASM_ARM_NAME_SQRDMLAH != 312 \
    || CDISASM_ARM_NAME_ADCS != 313 \
    || CDISASM_ARM_NAME_CNEG != 331 \
    || CDISASM_ARM_NAME_SEL != 341 \
    || CDISASM_ARM_NAME_SUBPT != 347 \
    || CDISASM_ARM_NAME_TBXQ != 356 \
    || CDISASM_ARM_NAME_TBLQ != 357 \
    || CDISASM_ARM_NAME_SUBR != 358 || CDISASM_ARM_NAME_UDIVR != 364 \
    || CDISASM_ARM_NAME_RBIT != 377 \
    || CDISASM_ARM_NAME_ASRR != 378 || CDISASM_ARM_NAME_LSRR != 379 \
    || CDISASM_ARM_NAME_LSLR != 380 \
    || CDISASM_ARM_NAME_ASRD != 381 || CDISASM_ARM_NAME_SQSHLU != 386 \
    || CDISASM_ARM_NAME_CMPEQ != 387 || CDISASM_ARM_NAME_CMPLS != 396 \
    || CDISASM_ARM_NAME_FCMEQ != 397 \
    || CDISASM_ARM_NAME_FCMNE != 398 \
    || CDISASM_ARM_NAME_FCMGE != 399 \
    || CDISASM_ARM_NAME_FCMGT != 400 \
    || CDISASM_ARM_NAME_FCMLE != 401 \
    || CDISASM_ARM_NAME_FCMLT != 402 \
    || CDISASM_ARM_NAME_FCMUO != 403 \
    || CDISASM_ARM_NAME_FACGE != 404 \
    || CDISASM_ARM_NAME_FACGT != 405 \
    || CDISASM_ARM_NAME_FSUBR != 406 \
    || CDISASM_ARM_NAME_FMAXNM != 407 \
    || CDISASM_ARM_NAME_FMINNM != 408 \
    || CDISASM_ARM_NAME_FMAX != 409 \
    || CDISASM_ARM_NAME_FMIN != 410 \
    || CDISASM_ARM_NAME_FABD != 411 \
    || CDISASM_ARM_NAME_FSCALE != 412 \
    || CDISASM_ARM_NAME_FMULX != 413 \
    || CDISASM_ARM_NAME_FDIVR != 414 \
    || CDISASM_ARM_NAME_FADDV != 415 \
    || CDISASM_ARM_NAME_FMAXNMV != 416 \
    || CDISASM_ARM_NAME_FMINNMV != 417 \
    || CDISASM_ARM_NAME_FMAXV != 418 \
    || CDISASM_ARM_NAME_FMINV != 419 \
    || CDISASM_ARM_NAME_FADDA != 420 \
    || CDISASM_ARM_NAME_FRINTN != 421 \
    || CDISASM_ARM_NAME_FRINTP != 422 \
    || CDISASM_ARM_NAME_FRINTM != 423 \
    || CDISASM_ARM_NAME_FRINTZ != 424 \
    || CDISASM_ARM_NAME_FRINTA != 425 \
    || CDISASM_ARM_NAME_FRINTX != 426 \
    || CDISASM_ARM_NAME_FRINTI != 427 \
    || CDISASM_ARM_NAME_FRECPX != 428 \
    || CDISASM_ARM_NAME_FRECPE != 429 \
    || CDISASM_ARM_NAME_FRSQRTE != 430 \
    || CDISASM_ARM_NAME_SCVTF != 431 \
    || CDISASM_ARM_NAME_UCVTF != 432 \
    || CDISASM_ARM_NAME_FCVT != 433 \
    || CDISASM_ARM_NAME_FCVTZS != 434 \
    || CDISASM_ARM_NAME_FCVTZU != 435 \
    || CDISASM_ARM_NAME_BFCVT != 436 \
    || CDISASM_ARM_NAME_BFCVTNT != 437 \
    || CDISASM_ARM_NAME_BFCVTN != 438 \
    || CDISASM_ARM_NAME_BFCVTN >= CDISASM_ARM_NAME_COUNT \
    || CDISASM_ARM_NAME_COUNT != CDISASM_ARM_NAME_LAST + 1
#    error "installed cdisasm package has unexpected ARM name IDs"
#  endif

#  if CDISASM_ARM_REG_D0 != 83 || CDISASM_ARM_REG_D31 != 114 \
    || CDISASM_ARM_REG_Q0 != 115 || CDISASM_ARM_REG_Q15 != 130 \
    || CDISASM_ARM_REG_V0 != 131 || CDISASM_ARM_REG_V31 != 162 \
    || CDISASM_ARM_REG_CPM_IOACC_CTL_EL3 != 163 \
    || CDISASM_ARM_REG_Z0 != 276 || CDISASM_ARM_REG_VG != 374 \
    || CDISASM_ARM_REG_LAST != 374 || CDISASM_ARM_REG_COUNT != 375
#    error "installed cdisasm package has unexpected ARM register IDs"
#  endif

#  if CDISASM_ARM_CPU_CORTEX_A9_NEON \
        != (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0008)) \
    || CDISASM_ARM_CPU_APPLE_A4 \
        != (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0009)) \
    || CDISASM_ARM_CPU_APPLE_M5 \
        != (CDISASM_CPU_GROUP_ARM | UINT32_C(0x001d)) \
    || CDISASM_ARM_CPU_CORTEX_A7_NEON \
        != (CDISASM_CPU_GROUP_ARM | UINT32_C(0x001e)) \
    || CDISASM_ARM_CPU_APPLE_S4 \
        != (CDISASM_CPU_GROUP_ARM | UINT32_C(0x001f)) \
    || CDISASM_ARM_CPU_APPLE_S10 \
        != (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0025)) \
    || CDISASM_ARM_CPU_FUJITSU_A64FX \
        != (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0026)) \
    || CDISASM_ARM_CPU_LAST \
        != (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0026))
#    error "installed cdisasm package has unexpected ARM CPU profile IDs"
#  endif
#endif

static int failures = 0;

#define CHECK(condition) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "%s:%d: check failed: %s\n", \
                __FILE__, __LINE__, #condition); \
            ++failures; \
        } \
    } while (0)

#if USE_ARCH_X86
static uint32_t decode_x86_word0(
    cdisasm_cpu_id cpu_id,
    cdisasm_mode mode,
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    cdisasm_x86_decode_option bitmap0,
    cdisasm_instruction *instruction)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_INITIALIZER(bitmap0);

    return cdisasm_x86_decode(
        cpu_id, mode, code, code_size, address, &flags, instruction);
}

#  define cdisasm_x86_decode decode_x86_word0
#endif

#if USE_ARCH_ARM
static uint32_t decode_arm_word0(
    cdisasm_arm_cpu_id cpu_id,
    cdisasm_arm_mode mode,
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    cdisasm_arm_decode_option bitmap0,
    cdisasm_arm_instruction *instruction)
{
    cdisasm_arm_decode_flags flags =
        CDISASM_ARM_DECODE_FLAGS_INITIALIZER(bitmap0);

    return cdisasm_arm_decode(
        cpu_id, mode, code, code_size, address, &flags, instruction);
}

#  define cdisasm_arm_decode decode_arm_word0
#endif

static void check_current_cpu(void)
{
    const cdisasm_cpu_id cpu_id = cdisasm_current_cpu();

    if (cpu_id == CDISASM_CPU_UNKNOWN) {
        return;
    }

    switch (CDISASM_CPU_GROUP_OF(cpu_id)) {
#if USE_ARCH_X86
        case CDISASM_CPU_GROUP_X86:
            CHECK(cpu_id >= CDISASM_CPU_FIRST);
            CHECK(cpu_id <= CDISASM_CPU_LAST);
            CHECK(cpu_id != CDISASM_CPU_X86);
            CHECK(cdisasm_x86_cpu_mode_mask(cpu_id)
                != CDISASM_X86_MODE_MASK_NONE);
            break;
#endif
#if USE_ARCH_ARM
        case CDISASM_CPU_GROUP_ARM:
            CHECK(cpu_id >= CDISASM_ARM_CPU_FIRST);
            CHECK(cpu_id <= CDISASM_ARM_CPU_LAST);
            CHECK(cpu_id != CDISASM_ARM_CPU_ANY);
            CHECK(cdisasm_arm_cpu_mode_mask(cpu_id)
                != CDISASM_ARM_MODE_MASK_NONE);
            break;
#endif
        default:
            CHECK(0);
            break;
    }
}

#if USE_ARCH_X86
static void check_x86(void)
{
    static const uint8_t nop[] = { UINT8_C(0x90) };
    static const uint8_t addps[] = {
        UINT8_C(0x0f), UINT8_C(0x58), UINT8_C(0xc1)
    };
    static const uint8_t pcmpgtq[] = {
        UINT8_C(0x66), UINT8_C(0x0f), UINT8_C(0x38),
        UINT8_C(0x37), UINT8_C(0xc1)
    };
    static const uint8_t vzeroupper[] = {
        UINT8_C(0xc5), UINT8_C(0xf8), UINT8_C(0x77)
    };
    static const uint8_t optional_vaddps[] = {
        UINT8_C(0xc5), UINT8_C(0xe8), UINT8_C(0x58), UINT8_C(0xcb)
    };
    static const uint8_t optional_vgetexpsd[] = {
        UINT8_C(0x62), UINT8_C(0x52), UINT8_C(0xb5), UINT8_C(0x08),
        UINT8_C(0x43), UINT8_C(0xc2)
    };
#if USE_EXTRA_OPCODES
    static const uint8_t optional_vgetexpph[] = {
        UINT8_C(0x62), UINT8_C(0xf6), UINT8_C(0x7d), UINT8_C(0x48),
        UINT8_C(0x42), UINT8_C(0xca)
    };
    static const uint8_t optional_vgetexpsh[] = {
        UINT8_C(0x62), UINT8_C(0xf6), UINT8_C(0x5d), UINT8_C(0x08),
        UINT8_C(0x43), UINT8_C(0xdd)
    };
    static const uint8_t optional_vgetexpbf16[] = {
        UINT8_C(0x62), UINT8_C(0xf6), UINT8_C(0x7c), UINT8_C(0x48),
        UINT8_C(0x42), UINT8_C(0xf7)
    };
#endif
    static const uint8_t optional_vpsraq[] = {
        UINT8_C(0x62), UINT8_C(0xf1), UINT8_C(0xf5), UINT8_C(0x4a),
        UINT8_C(0x72), UINT8_C(0xe2), UINT8_C(0x13)
    };
    static const uint8_t optional_vpsrldq[] = {
        UINT8_C(0x62), UINT8_C(0xf1), UINT8_C(0x7d), UINT8_C(0x48),
        UINT8_C(0x73), UINT8_C(0xd9), UINT8_C(0x07)
    };
    static const uint8_t optional_vpshrdvq[] = {
        UINT8_C(0x62), UINT8_C(0xf2), UINT8_C(0xed), UINT8_C(0x48),
        UINT8_C(0x73), UINT8_C(0xcb)
    };
    static const uint8_t optional_vpexpandq[] = {
        UINT8_C(0x62), UINT8_C(0xf2), UINT8_C(0xfd), UINT8_C(0x48),
        UINT8_C(0x89), UINT8_C(0xcb)
    };
    static const uint8_t optional_vpopcntq[] = {
        UINT8_C(0x62), UINT8_C(0xf2), UINT8_C(0xfd), UINT8_C(0x48),
        UINT8_C(0x55), UINT8_C(0xcb)
    };
    static const uint8_t optional_vpshufbitqmb[] = {
        UINT8_C(0x62), UINT8_C(0xf2), UINT8_C(0x6d), UINT8_C(0x48),
        UINT8_C(0x8f), UINT8_C(0xcb)
    };
    static const uint8_t optional_vpconflictd[] = {
        UINT8_C(0x62), UINT8_C(0xf2), UINT8_C(0x7d), UINT8_C(0x48),
        UINT8_C(0xc4), UINT8_C(0xcb)
    };
    static const uint8_t optional_vpermi2b[] = {
        UINT8_C(0x62), UINT8_C(0xf2), UINT8_C(0x6d), UINT8_C(0x08),
        UINT8_C(0x75), UINT8_C(0xcb)
    };
    static const uint8_t optional_vpermi2w[] = {
        UINT8_C(0x62), UINT8_C(0xf2), UINT8_C(0xed), UINT8_C(0x08),
        UINT8_C(0x75), UINT8_C(0xcb)
    };
#if USE_EXTRA_OPCODES
    static const uint8_t optional_vpbroadcastmb2q[] = {
        UINT8_C(0x62), UINT8_C(0xf2), UINT8_C(0xfe), UINT8_C(0x48),
        UINT8_C(0x2a), UINT8_C(0xcb)
    };
    static const uint8_t optional_vpdpbusds[] = {
        UINT8_C(0x62), UINT8_C(0xf2), UINT8_C(0x6d), UINT8_C(0x08),
        UINT8_C(0x51), UINT8_C(0xcb)
    };
#endif
    cdisasm_x86_instruction canonical;
    cdisasm_instruction legacy;
    uint32_t optional_size;
    cdisasm_x86_decode_flags available_flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    const cdisasm_x86_decode_flags zero_flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    cdisasm_decode_flags generic_available_flags =
        CDISASM_DECODE_FLAGS_NONE_INITIALIZER;
#if USE_DISASM_FORMAT
    static const char expected[] = "nop";
#  if USE_EXTRA_OPCODES
    static const char expected_addps[] = "addps xmm0, xmm1";
#  endif
    char canonical_text[64];
    char att_text[64];
    char legacy_text[64];
#endif

    CHECK(cdisasm_x86_cpu_mode_mask(CDISASM_CPU_8086)
        == CDISASM_X86_MODE_MASK_16);
    CHECK(cdisasm_x86_cpu_mode_mask(CDISASM_CPU_80386)
        == (CDISASM_X86_MODE_MASK_16 | CDISASM_X86_MODE_MASK_32));
    CHECK(cdisasm_x86_cpu_mode_mask(CDISASM_CPU_ATHLON_64)
        == (CDISASM_X86_MODE_MASK_16 | CDISASM_X86_MODE_MASK_32
            | CDISASM_X86_MODE_MASK_64));
    CHECK(cdisasm_x86_cpu_mode_mask(CDISASM_CPU_GRANITE_RAPIDS)
        == (CDISASM_X86_MODE_MASK_16 | CDISASM_X86_MODE_MASK_32
            | CDISASM_X86_MODE_MASK_64));
    CHECK(cdisasm_x86_cpu_mode_mask(CDISASM_CPU_ARROW_LAKE)
        == (CDISASM_X86_MODE_MASK_16 | CDISASM_X86_MODE_MASK_32
            | CDISASM_X86_MODE_MASK_64));
    CHECK(cdisasm_x86_cpu_mode_mask(CDISASM_CPU_DIAMOND_RAPIDS)
        == (CDISASM_X86_MODE_MASK_16 | CDISASM_X86_MODE_MASK_32
            | CDISASM_X86_MODE_MASK_64));
    CHECK(cdisasm_x86_cpu_mode_mask(CDISASM_CPU_KNIGHTS_MILL)
        == (CDISASM_X86_MODE_MASK_16 | CDISASM_X86_MODE_MASK_32
            | CDISASM_X86_MODE_MASK_64));
    CHECK(cdisasm_x86_cpu_mode_mask(CDISASM_CPU_LAST + UINT32_C(1))
        == CDISASM_X86_MODE_MASK_NONE);
    CHECK(cdisasm_cpu_decode_flag_mask(
              CDISASM_CPU_PENTIUM_III,
              CDISASM_X86_MODE_32,
              &generic_available_flags)
        == CDISASM_STATUS_OK);

    CHECK(cdisasm_x86_cpu_decode_flag_mask(
              CDISASM_CPU_PENTIUM_III,
              CDISASM_X86_MODE_32,
              &available_flags)
        == CDISASM_STATUS_OK);
#if USE_EXTRA_OPCODES
    CHECK((available_flags.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP]
               & CDISASM_X86_DECODE_FLAG_SSE) != 0u);
    CHECK((available_flags.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP]
               & CDISASM_X86_DECODE_FLAG_AVX) == 0u);
    CHECK(cdisasm_x86_cpu_decode_flag_mask(
              CDISASM_CPU_INTEL_VT_X,
              CDISASM_X86_MODE_64,
              &available_flags)
        == CDISASM_STATUS_OK);
    CHECK((available_flags.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP]
            & (CDISASM_X86_DECODE_FLAG_SMX
                | CDISASM_X86_DECODE_FLAG_VMX
                | CDISASM_X86_DECODE_FLAG_SVM))
        == CDISASM_X86_DECODE_FLAG_VMX);
    CHECK(cdisasm_x86_cpu_decode_flag_mask(
              CDISASM_CPU_AMD_V,
              CDISASM_X86_MODE_64,
              &available_flags)
        == CDISASM_STATUS_OK);
    CHECK((available_flags.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP]
            & (CDISASM_X86_DECODE_FLAG_SMX
                | CDISASM_X86_DECODE_FLAG_VMX
                | CDISASM_X86_DECODE_FLAG_SVM))
        == CDISASM_X86_DECODE_FLAG_SVM);
    CHECK(cdisasm_x86_cpu_decode_flag_mask(
              CDISASM_CPU_CORE_2,
              CDISASM_X86_MODE_64,
              &available_flags)
        == CDISASM_STATUS_OK);
    CHECK((available_flags.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP]
            & (CDISASM_X86_DECODE_FLAG_SMX
                | CDISASM_X86_DECODE_FLAG_VMX
                | CDISASM_X86_DECODE_FLAG_SVM))
        == (CDISASM_X86_DECODE_FLAG_SMX
            | CDISASM_X86_DECODE_FLAG_VMX));
    CHECK(cdisasm_x86_cpu_decode_flag_mask(
              CDISASM_CPU_CELERON_N4020,
              CDISASM_X86_MODE_64,
              &available_flags)
        == CDISASM_STATUS_OK);
    CHECK((available_flags.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP]
            & CDISASM_X86_DECODE_FLAG_SSE4)
        != 0u);
    CHECK((available_flags.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP]
            & CDISASM_X86_DECODE_FLAG_AVX)
        == 0u);
#else
    CHECK(memcmp(&available_flags, &zero_flags, sizeof(zero_flags)) == 0);
    CHECK(cdisasm_x86_cpu_decode_flag_mask(
              CDISASM_CPU_CELERON_N4020,
              CDISASM_X86_MODE_64,
              &available_flags)
        == CDISASM_STATUS_OK);
    CHECK(memcmp(&available_flags, &zero_flags, sizeof(zero_flags)) == 0);
#endif
    memset(&available_flags, 0xa5, sizeof(available_flags));
    CHECK(cdisasm_x86_cpu_decode_flag_mask(
              CDISASM_CPU_8086,
              CDISASM_X86_MODE_32,
              &available_flags)
        == CDISASM_STATUS_INVALID_ARGUMENT);
    CHECK(memcmp(&available_flags, &zero_flags, sizeof(zero_flags)) == 0);
    memset(&available_flags, 0xa5, sizeof(available_flags));
    CHECK(cdisasm_x86_cpu_decode_flag_mask(
              CDISASM_CPU_LAST + UINT32_C(1),
              CDISASM_X86_MODE_16,
              &available_flags)
        == CDISASM_STATUS_INVALID_ARGUMENT);
    CHECK(memcmp(&available_flags, &zero_flags, sizeof(zero_flags)) == 0);
    CHECK(cdisasm_x86_cpu_decode_flag_mask(
              CDISASM_CPU_80386, CDISASM_X86_MODE_32, NULL)
        == CDISASM_STATUS_INVALID_ARGUMENT);

    CHECK(cdisasm_x86_decode(
              CDISASM_CPU_80386,
              CDISASM_X86_MODE_32,
              nop,
              sizeof(nop),
              UINT64_C(0x1000),
              CDISASM_X86_DECODE_OPTION_NONE,
              &canonical)
        == sizeof(nop));
    CHECK(canonical.last_error_id == CDISASM_STATUS_OK);
    CHECK(canonical.name_id == CDISASM_X86_NAME_NOP);
#if USE_DISASM_FORMAT
    CHECK(cdisasm_x86_format(
              &canonical,
              CDISASM_FORMAT_SYNTAX_INTEL,
              canonical_text,
              sizeof(canonical_text))
        == sizeof(expected) - 1u);
    CHECK(strcmp(canonical_text, expected) == 0);
    CHECK(cdisasm_x86_format(
              &canonical,
              CDISASM_FORMAT_SYNTAX_ATT,
              att_text,
              sizeof(att_text))
        == sizeof("nop") - 1u);
    CHECK(strcmp(att_text, "nop") == 0);
#endif

    CHECK(cdisasm_x86_decode(
              CDISASM_CPU_80386,
              CDISASM_MODE_32,
              nop,
              sizeof(nop),
              UINT64_C(0x1000),
              CDISASM_X86_DECODE_OPTION_NONE,
              &legacy)
        == sizeof(nop));
    CHECK(legacy.last_error_id == CDISASM_STATUS_OK);
    CHECK(legacy.name_id == CDISASM_NAME_NOP);
    CHECK(CDISASM_NAME_NOP == CDISASM_X86_NAME_NOP);
#if USE_DISASM_FORMAT
    CHECK(cdisasm_format(
              &legacy,
              CDISASM_FORMAT_SYNTAX_INTEL,
              legacy_text,
              sizeof(legacy_text))
        == sizeof(expected) - 1u);
    CHECK(strcmp(legacy_text, expected) == 0);
#endif

    CHECK(cdisasm_x86_decode(
              CDISASM_CPU_PENTIUM_III,
              CDISASM_X86_MODE_32,
              addps,
              sizeof(addps),
              UINT64_C(0x1010),
              CDISASM_X86_DECODE_FLAG_BASE,
              &canonical)
        == 0u);
    CHECK(canonical.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_PENTIUM_III,
        CDISASM_X86_MODE_32,
        addps,
        sizeof(addps),
        UINT64_C(0x1010),
        CDISASM_X86_DECODE_FLAG_SSE,
        &canonical);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(addps));
    CHECK(canonical.last_error_id == CDISASM_STATUS_OK);
    CHECK(canonical.name_id == CDISASM_X86_NAME_ADDPS);
    CHECK(cdisasm_instruction_has_x86_group(
        &canonical, CDISASM_X86_GROUP_SSE));
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_x86_format(
              &canonical,
              CDISASM_FORMAT_UPPERCASE_OPCODE,
              canonical_text,
              sizeof(canonical_text))
        == sizeof(expected_addps) - 1u);
    CHECK(strcmp(canonical_text, "ADDPS xmm0, xmm1") == 0);
    CHECK(cdisasm_x86_format(
              &canonical,
              CDISASM_FORMAT_SYNTAX_ATT,
              att_text,
              sizeof(att_text))
        == sizeof("addps %xmm1, %xmm0") - 1u);
    CHECK(strcmp(att_text, "addps %xmm1, %xmm0") == 0);
#  endif
#else
    CHECK(optional_size == 0u);
    CHECK(canonical.last_error_id == CDISASM_STATUS_INVALID_ARGUMENT);
#endif

    CHECK(cdisasm_x86_decode(
              CDISASM_CPU_CELERON_N4020,
              CDISASM_X86_MODE_64,
              pcmpgtq,
              sizeof(pcmpgtq),
              UINT64_C(0x1020),
              CDISASM_X86_DECODE_FLAG_BASE,
              &canonical)
        == 0u);
    CHECK(canonical.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_CELERON_N4020,
        CDISASM_X86_MODE_64,
        pcmpgtq,
        sizeof(pcmpgtq),
        UINT64_C(0x1020),
        CDISASM_X86_DECODE_FLAG_SSE4,
        &canonical);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(pcmpgtq));
    CHECK(canonical.last_error_id == CDISASM_STATUS_OK);
    CHECK(canonical.name_id == CDISASM_X86_NAME_PCMPGTQ);
#else
    CHECK(optional_size == 0u);
    CHECK(canonical.last_error_id == CDISASM_STATUS_INVALID_ARGUMENT);
#endif
    CHECK(cdisasm_x86_decode(
              CDISASM_CPU_X86,
              CDISASM_X86_MODE_64,
              vzeroupper,
              sizeof(vzeroupper),
              UINT64_C(0x1030),
              CDISASM_X86_DECODE_FLAG_BASE,
              &canonical)
        == 0);
    CHECK(canonical.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    CHECK(cdisasm_x86_decode(
              CDISASM_CPU_CELERON_N4020,
              CDISASM_X86_MODE_64,
              vzeroupper,
              sizeof(vzeroupper),
              UINT64_C(0x1030),
              CDISASM_X86_DECODE_FLAG_AVX,
              &canonical)
        == 0);
#if USE_EXTRA_OPCODES
    CHECK(canonical.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
#else
    CHECK(canonical.last_error_id == CDISASM_STATUS_INVALID_ARGUMENT);
#endif

    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_X86_MODE_64,
        optional_vaddps,
        sizeof(optional_vaddps),
        UINT64_C(0x1040),
        CDISASM_X86_DECODE_FLAG_BASE,
        &canonical);
    CHECK(optional_size == 0u);
    CHECK(canonical.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_X86_MODE_64,
        optional_vaddps,
        sizeof(optional_vaddps),
        UINT64_C(0x1040),
        CDISASM_X86_DECODE_FLAG_AVX,
        &canonical);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(optional_vaddps));
    CHECK(canonical.last_error_id == CDISASM_STATUS_OK);
    CHECK(canonical.name_id == CDISASM_X86_NAME_VADDPS);
    CHECK(canonical.operand_count == 3u);
    CHECK(cdisasm_instruction_has_x86_group(
        &canonical, CDISASM_X86_GROUP_AVX));
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_x86_format(
              &canonical,
              CDISASM_FORMAT_SYNTAX_INTEL,
              canonical_text,
              sizeof(canonical_text))
        == sizeof("vaddps xmm1, xmm2, xmm3") - 1u);
    CHECK(strcmp(canonical_text, "vaddps xmm1, xmm2, xmm3") == 0);
#  endif
#else
    CHECK(optional_size == 0u);
    CHECK(canonical.last_error_id == CDISASM_STATUS_INVALID_ARGUMENT);
#  if USE_DISASM_FORMAT
    memset(&canonical, 0, sizeof(canonical));
    canonical.name_id = CDISASM_X86_NAME_VADDPS;
    canonical_text[0] = 'X';
    CHECK(cdisasm_x86_format(
              &canonical,
              CDISASM_FORMAT_SYNTAX_INTEL,
              canonical_text,
              sizeof(canonical_text))
        == 0u);
    CHECK(canonical_text[0] == '\0');
#  endif
#endif

    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_X86_MODE_64,
        optional_vgetexpsd,
        sizeof(optional_vgetexpsd),
        UINT64_C(0x1050),
        CDISASM_X86_DECODE_FLAG_AVX512,
        &canonical);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(optional_vgetexpsd));
    CHECK(canonical.last_error_id == CDISASM_STATUS_OK);
    CHECK(canonical.name_id == CDISASM_X86_NAME_VGETEXPSD);
    CHECK(canonical.operand_count == 3u);
    CHECK(canonical.opcode[0].reg == CDISASM_X86_REG_XMM8);
    CHECK(canonical.opcode[1].reg == CDISASM_X86_REG_XMM9);
    CHECK(canonical.opcode[2].reg == CDISASM_X86_REG_XMM10);
    CHECK(cdisasm_instruction_has_x86_group(
        &canonical, CDISASM_X86_GROUP_AVX512F));
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_x86_format(
              &canonical,
              CDISASM_FORMAT_SYNTAX_INTEL,
              canonical_text,
              sizeof(canonical_text))
        == sizeof("vgetexpsd xmm8, xmm9, xmm10") - 1u);
    CHECK(strcmp(canonical_text,
        "vgetexpsd xmm8, xmm9, xmm10") == 0);
    CHECK(cdisasm_x86_format(
              &canonical,
              CDISASM_FORMAT_SYNTAX_ATT,
              att_text,
              sizeof(att_text))
        == sizeof("vgetexpsd %xmm10, %xmm9, %xmm8") - 1u);
    CHECK(strcmp(att_text,
        "vgetexpsd %xmm10, %xmm9, %xmm8") == 0);
#  endif
#else
    CHECK(optional_size == 0u);
    CHECK(canonical.last_error_id == CDISASM_STATUS_INVALID_ARGUMENT);
#endif

#if USE_EXTRA_OPCODES
    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_SAPPHIRE_RAPIDS,
        CDISASM_X86_MODE_64,
        optional_vgetexpph,
        sizeof(optional_vgetexpph),
        UINT64_C(0x1058),
        CDISASM_X86_DECODE_FLAG_AVX512,
        &canonical);
    CHECK(optional_size == sizeof(optional_vgetexpph));
    CHECK(canonical.last_error_id == CDISASM_STATUS_OK);
    CHECK(canonical.name_id == CDISASM_X86_NAME_VGETEXPPH);
    CHECK(canonical.operand_count == 2u);
    CHECK(canonical.opcode[0].reg == CDISASM_X86_REG_ZMM1);
    CHECK(canonical.opcode[1].reg == CDISASM_X86_REG_ZMM2);
    CHECK(cdisasm_instruction_has_x86_group(
        &canonical, CDISASM_X86_GROUP_AVX512FP16));
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_x86_format(
              &canonical,
              CDISASM_FORMAT_SYNTAX_INTEL,
              canonical_text,
              sizeof(canonical_text))
        == sizeof("vgetexpph zmm1, zmm2") - 1u);
    CHECK(strcmp(canonical_text, "vgetexpph zmm1, zmm2") == 0);
    CHECK(cdisasm_x86_format(
              &canonical,
              CDISASM_FORMAT_SYNTAX_ATT,
              att_text,
              sizeof(att_text))
        == sizeof("vgetexpph %zmm2, %zmm1") - 1u);
    CHECK(strcmp(att_text, "vgetexpph %zmm2, %zmm1") == 0);
#  endif

    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_SAPPHIRE_RAPIDS,
        CDISASM_X86_MODE_64,
        optional_vgetexpsh,
        sizeof(optional_vgetexpsh),
        UINT64_C(0x105e),
        CDISASM_X86_DECODE_FLAG_AVX512,
        &canonical);
    CHECK(optional_size == sizeof(optional_vgetexpsh));
    CHECK(canonical.last_error_id == CDISASM_STATUS_OK);
    CHECK(canonical.name_id == CDISASM_X86_NAME_VGETEXPSH);
    CHECK(canonical.operand_count == 3u);
    CHECK(canonical.opcode[0].reg == CDISASM_X86_REG_XMM3);
    CHECK(canonical.opcode[1].reg == CDISASM_X86_REG_XMM4);
    CHECK(canonical.opcode[2].reg == CDISASM_X86_REG_XMM5);
    CHECK(cdisasm_instruction_has_x86_group(
        &canonical, CDISASM_X86_GROUP_AVX512FP16));
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_x86_format(
              &canonical,
              CDISASM_FORMAT_SYNTAX_INTEL,
              canonical_text,
              sizeof(canonical_text))
        == sizeof("vgetexpsh xmm3, xmm4, xmm5") - 1u);
    CHECK(strcmp(canonical_text, "vgetexpsh xmm3, xmm4, xmm5") == 0);
    CHECK(cdisasm_x86_format(
              &canonical,
              CDISASM_FORMAT_SYNTAX_ATT,
              att_text,
              sizeof(att_text))
        == sizeof("vgetexpsh %xmm5, %xmm4, %xmm3") - 1u);
    CHECK(strcmp(att_text, "vgetexpsh %xmm5, %xmm4, %xmm3") == 0);
#  endif

    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_DIAMOND_RAPIDS,
        CDISASM_X86_MODE_64,
        optional_vgetexpbf16,
        sizeof(optional_vgetexpbf16),
        UINT64_C(0x1064),
        CDISASM_X86_DECODE_FLAG_AVX10,
        &canonical);
    CHECK(optional_size == sizeof(optional_vgetexpbf16));
    CHECK(canonical.last_error_id == CDISASM_STATUS_OK);
    CHECK(canonical.name_id == CDISASM_X86_NAME_VGETEXPBF16);
    CHECK(canonical.operand_count == 2u);
    CHECK(canonical.opcode[0].reg == CDISASM_X86_REG_ZMM6);
    CHECK(canonical.opcode[1].reg == CDISASM_X86_REG_ZMM7);
    CHECK(cdisasm_instruction_has_x86_group(
        &canonical, CDISASM_X86_GROUP_AVX10_2));
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_x86_format(
              &canonical,
              CDISASM_FORMAT_SYNTAX_INTEL,
              canonical_text,
              sizeof(canonical_text))
        == sizeof("vgetexpbf16 zmm6, zmm7") - 1u);
    CHECK(strcmp(canonical_text, "vgetexpbf16 zmm6, zmm7") == 0);
    CHECK(cdisasm_x86_format(
              &canonical,
              CDISASM_FORMAT_SYNTAX_ATT,
              att_text,
              sizeof(att_text))
        == sizeof("vgetexpbf16 %zmm7, %zmm6") - 1u);
    CHECK(strcmp(att_text, "vgetexpbf16 %zmm7, %zmm6") == 0);
#  endif
#endif

    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_SKYLAKE_SP,
        CDISASM_X86_MODE_64,
        optional_vpsraq,
        sizeof(optional_vpsraq),
        UINT64_C(0x1054),
        CDISASM_X86_DECODE_FLAG_BASE,
        &canonical);
    CHECK(optional_size == 0u);
    CHECK(canonical.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_SKYLAKE_SP,
        CDISASM_X86_MODE_64,
        optional_vpsraq,
        sizeof(optional_vpsraq),
        UINT64_C(0x1054),
        CDISASM_X86_DECODE_FLAG_AVX512,
        &canonical);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(optional_vpsraq));
    CHECK(canonical.last_error_id == CDISASM_STATUS_OK);
    CHECK(canonical.name_id == CDISASM_X86_NAME_VPSRAQ);
    CHECK(canonical.operand_count == 3u);
    CHECK(canonical.opcode[0].reg == CDISASM_X86_REG_ZMM1);
    CHECK(canonical.opcode[1].reg == CDISASM_X86_REG_ZMM2);
    CHECK(canonical.opcode[2].imm == UINT64_C(0x13));
    CHECK(canonical.mask_reg == CDISASM_X86_REG_K2);
    CHECK(canonical.mask_mode == CDISASM_X86_MASK_MERGE);
    CHECK(cdisasm_instruction_has_x86_group(
        &canonical, CDISASM_X86_GROUP_AVX512F));
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_x86_format(
              &canonical,
              CDISASM_FORMAT_SYNTAX_INTEL,
              canonical_text,
              sizeof(canonical_text))
        == sizeof("vpsraq zmm1 {k2}, zmm2, 0x13") - 1u);
    CHECK(strcmp(canonical_text,
        "vpsraq zmm1 {k2}, zmm2, 0x13") == 0);
#  endif
#else
    CHECK(optional_size == 0u);
    CHECK(canonical.last_error_id == CDISASM_STATUS_INVALID_ARGUMENT);
#endif

    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_SKYLAKE_SP,
        CDISASM_X86_MODE_64,
        optional_vpsrldq,
        sizeof(optional_vpsrldq),
        UINT64_C(0x1058),
        CDISASM_X86_DECODE_FLAG_BASE,
        &canonical);
    CHECK(optional_size == 0u);
    CHECK(canonical.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_SKYLAKE_SP,
        CDISASM_X86_MODE_64,
        optional_vpsrldq,
        sizeof(optional_vpsrldq),
        UINT64_C(0x1058),
        CDISASM_X86_DECODE_FLAG_AVX512,
        &canonical);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(optional_vpsrldq));
    CHECK(canonical.last_error_id == CDISASM_STATUS_OK);
    CHECK(canonical.name_id == CDISASM_X86_NAME_VPSRLDQ);
    CHECK(canonical.operand_count == 3u);
    CHECK(canonical.opcode[0].reg == CDISASM_X86_REG_ZMM0);
    CHECK(canonical.opcode[1].reg == CDISASM_X86_REG_ZMM1);
    CHECK(canonical.opcode[2].imm == UINT64_C(7));
    CHECK(canonical.mask_reg == CDISASM_X86_REG_NONE);
    CHECK(cdisasm_instruction_has_x86_group(
        &canonical, CDISASM_X86_GROUP_AVX512BW));
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_x86_format(
              &canonical,
              CDISASM_FORMAT_SYNTAX_INTEL,
              canonical_text,
              sizeof(canonical_text))
        == sizeof("vpsrldq zmm0, zmm1, 0x7") - 1u);
    CHECK(strcmp(canonical_text,
        "vpsrldq zmm0, zmm1, 0x7") == 0);
#  endif
#else
    CHECK(optional_size == 0u);
    CHECK(canonical.last_error_id == CDISASM_STATUS_INVALID_ARGUMENT);
#endif

    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_X86_MODE_64,
        optional_vpshrdvq,
        sizeof(optional_vpshrdvq),
        UINT64_C(0x1060),
        CDISASM_X86_DECODE_FLAG_BASE,
        &canonical);
    CHECK(optional_size == 0u);
    CHECK(canonical.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_X86_MODE_64,
        optional_vpshrdvq,
        sizeof(optional_vpshrdvq),
        UINT64_C(0x1060),
        CDISASM_X86_DECODE_FLAG_AVX512,
        &canonical);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(optional_vpshrdvq));
    CHECK(canonical.last_error_id == CDISASM_STATUS_OK);
    CHECK(canonical.name_id == CDISASM_X86_NAME_VPSHRDVQ);
    CHECK(canonical.operand_count == 3u);
    CHECK(canonical.opcode[0].reg == CDISASM_X86_REG_ZMM1);
    CHECK(canonical.opcode[1].reg == CDISASM_X86_REG_ZMM2);
    CHECK(canonical.opcode[2].reg == CDISASM_X86_REG_ZMM3);
    CHECK(cdisasm_instruction_has_x86_group(
        &canonical, CDISASM_X86_GROUP_AVX512VBMI2));
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_x86_format(
              &canonical,
              CDISASM_FORMAT_SYNTAX_INTEL,
              canonical_text,
              sizeof(canonical_text))
        == sizeof("vpshrdvq zmm1, zmm2, zmm3") - 1u);
    CHECK(strcmp(canonical_text,
        "vpshrdvq zmm1, zmm2, zmm3") == 0);
#  endif
#else
    CHECK(optional_size == 0u);
    CHECK(canonical.last_error_id == CDISASM_STATUS_INVALID_ARGUMENT);
#endif

    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_X86_MODE_64,
        optional_vpexpandq,
        sizeof(optional_vpexpandq),
        UINT64_C(0x1070),
        CDISASM_X86_DECODE_FLAG_BASE,
        &canonical);
    CHECK(optional_size == 0u);
    CHECK(canonical.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_X86_MODE_64,
        optional_vpexpandq,
        sizeof(optional_vpexpandq),
        UINT64_C(0x1070),
        CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND,
        &canonical);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(optional_vpexpandq));
    CHECK(canonical.last_error_id == CDISASM_STATUS_OK);
    CHECK(canonical.name_id == CDISASM_X86_NAME_VPEXPANDQ);
    CHECK(canonical.operand_count == 2u);
    CHECK(canonical.opcode[0].type == CDISASM_OPERAND_REGISTER);
    CHECK(canonical.opcode[0].reg == CDISASM_X86_REG_ZMM1);
    CHECK(canonical.opcode[0].size == 64u);
    CHECK(canonical.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    CHECK(canonical.opcode[1].type == CDISASM_OPERAND_REGISTER);
    CHECK(canonical.opcode[1].reg == CDISASM_X86_REG_ZMM3);
    CHECK(canonical.opcode[1].size == 64u);
    CHECK(canonical.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    CHECK(canonical.mask_reg == CDISASM_X86_REG_NONE);
    CHECK(cdisasm_instruction_has_x86_group(
        &canonical, CDISASM_X86_GROUP_AVX512F));
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_x86_format(
              &canonical,
              CDISASM_FORMAT_SYNTAX_INTEL,
              canonical_text,
              sizeof(canonical_text))
        == sizeof("vpexpandq zmm1, zmm3") - 1u);
    CHECK(strcmp(canonical_text, "vpexpandq zmm1, zmm3") == 0);
#  endif
    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_X86_MODE_64,
        optional_vpexpandq,
        sizeof(optional_vpexpandq),
        UINT64_C(0x1070),
        CDISASM_X86_DECODE_FLAG_AVX512,
        &canonical);
    CHECK(optional_size == sizeof(optional_vpexpandq));
    CHECK(canonical.last_error_id == CDISASM_STATUS_OK);
    CHECK(canonical.name_id == CDISASM_X86_NAME_VPEXPANDQ);
#else
    CHECK(optional_size == 0u);
    CHECK(canonical.last_error_id == CDISASM_STATUS_INVALID_ARGUMENT);
    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_X86_MODE_64,
        optional_vpexpandq,
        sizeof(optional_vpexpandq),
        UINT64_C(0x1070),
        CDISASM_X86_DECODE_FLAG_AVX512,
        &canonical);
    CHECK(optional_size == 0u);
    CHECK(canonical.last_error_id == CDISASM_STATUS_INVALID_ARGUMENT);
#endif

    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_X86_MODE_64,
        optional_vpopcntq,
        sizeof(optional_vpopcntq),
        UINT64_C(0x1078),
        CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ,
        &canonical);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(optional_vpopcntq));
    CHECK(canonical.last_error_id == CDISASM_STATUS_OK);
    CHECK(canonical.name_id == CDISASM_X86_NAME_VPOPCNTQ);
    CHECK(canonical.operand_count == 2u);
    CHECK(canonical.opcode[0].reg == CDISASM_X86_REG_ZMM1);
    CHECK(canonical.opcode[0].size == 64u);
    CHECK(canonical.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    CHECK(canonical.opcode[1].reg == CDISASM_X86_REG_ZMM3);
    CHECK(canonical.opcode[1].size == 64u);
    CHECK(canonical.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    CHECK(cdisasm_instruction_has_x86_group(
        &canonical, CDISASM_X86_GROUP_AVX512F));
    CHECK(cdisasm_instruction_has_x86_group(
        &canonical, CDISASM_X86_GROUP_AVX512VPOPCNTDQ));
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_x86_format(
              &canonical,
              CDISASM_FORMAT_SYNTAX_INTEL,
              canonical_text,
              sizeof(canonical_text))
        == sizeof("vpopcntq zmm1, zmm3") - 1u);
    CHECK(strcmp(canonical_text, "vpopcntq zmm1, zmm3") == 0);
#  endif
    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_X86_MODE_64,
        optional_vpopcntq,
        sizeof(optional_vpopcntq),
        UINT64_C(0x1078),
        CDISASM_X86_DECODE_FLAG_AVX512,
        &canonical);
    CHECK(optional_size == sizeof(optional_vpopcntq));
    CHECK(canonical.last_error_id == CDISASM_STATUS_OK);
    CHECK(canonical.name_id == CDISASM_X86_NAME_VPOPCNTQ);
#else
    CHECK(optional_size == 0u);
    CHECK(canonical.last_error_id == CDISASM_STATUS_INVALID_ARGUMENT);
#endif

    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_X86_MODE_64,
        optional_vpshufbitqmb,
        sizeof(optional_vpshufbitqmb),
        UINT64_C(0x1080),
        CDISASM_X86_DECODE_FLAG_BASE,
        &canonical);
    CHECK(optional_size == 0u);
    CHECK(canonical.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_X86_MODE_64,
        optional_vpshufbitqmb,
        sizeof(optional_vpshufbitqmb),
        UINT64_C(0x1080),
        CDISASM_X86_DECODE_FLAG_AVX512_BITALG,
        &canonical);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(optional_vpshufbitqmb));
    CHECK(canonical.last_error_id == CDISASM_STATUS_OK);
    CHECK(canonical.name_id == CDISASM_X86_NAME_VPSHUFBITQMB);
    CHECK(canonical.operand_count == 3u);
    CHECK(canonical.opcode[0].type == CDISASM_OPERAND_REGISTER);
    CHECK(canonical.opcode[0].reg == CDISASM_X86_REG_K1);
    CHECK(canonical.opcode[0].size == 8u);
    CHECK(canonical.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    CHECK(canonical.opcode[1].type == CDISASM_OPERAND_REGISTER);
    CHECK(canonical.opcode[1].reg == CDISASM_X86_REG_ZMM2);
    CHECK(canonical.opcode[1].size == 64u);
    CHECK(canonical.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    CHECK(canonical.opcode[2].type == CDISASM_OPERAND_REGISTER);
    CHECK(canonical.opcode[2].reg == CDISASM_X86_REG_ZMM3);
    CHECK(canonical.opcode[2].size == 64u);
    CHECK(canonical.opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    CHECK(canonical.mask_reg == CDISASM_X86_REG_NONE);
    CHECK(cdisasm_instruction_has_x86_group(
        &canonical, CDISASM_X86_GROUP_AVX512F));
    CHECK(cdisasm_instruction_has_x86_group(
        &canonical, CDISASM_X86_GROUP_AVX512BITALG));
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_x86_format(
              &canonical,
              CDISASM_FORMAT_SYNTAX_INTEL,
              canonical_text,
              sizeof(canonical_text))
        == sizeof("vpshufbitqmb k1, zmm2, zmm3") - 1u);
    CHECK(strcmp(canonical_text,
        "vpshufbitqmb k1, zmm2, zmm3") == 0);
#  endif
    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_X86_MODE_64,
        optional_vpshufbitqmb,
        sizeof(optional_vpshufbitqmb),
        UINT64_C(0x1080),
        CDISASM_X86_DECODE_FLAG_AVX512,
        &canonical);
    CHECK(optional_size == sizeof(optional_vpshufbitqmb));
    CHECK(canonical.last_error_id == CDISASM_STATUS_OK);
    CHECK(canonical.name_id == CDISASM_X86_NAME_VPSHUFBITQMB);
#else
    CHECK(optional_size == 0u);
    CHECK(canonical.last_error_id == CDISASM_STATUS_INVALID_ARGUMENT);
#endif

    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_X86_MODE_64,
        optional_vpconflictd,
        sizeof(optional_vpconflictd),
        UINT64_C(0x1090),
        CDISASM_X86_DECODE_FLAG_BASE,
        &canonical);
    CHECK(optional_size == 0u);
    CHECK(canonical.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_X86_MODE_64,
        optional_vpconflictd,
        sizeof(optional_vpconflictd),
        UINT64_C(0x1090),
        CDISASM_X86_DECODE_FLAG_AVX512_CD,
        &canonical);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(optional_vpconflictd));
    CHECK(canonical.last_error_id == CDISASM_STATUS_OK);
    CHECK(canonical.name_id == CDISASM_X86_NAME_VPCONFLICTD);
    CHECK(canonical.operand_count == 2u);
    CHECK(canonical.opcode[0].type == CDISASM_OPERAND_REGISTER);
    CHECK(canonical.opcode[0].reg == CDISASM_X86_REG_ZMM1);
    CHECK(canonical.opcode[0].size == 64u);
    CHECK(canonical.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    CHECK(canonical.opcode[1].type == CDISASM_OPERAND_REGISTER);
    CHECK(canonical.opcode[1].reg == CDISASM_X86_REG_ZMM3);
    CHECK(canonical.opcode[1].size == 64u);
    CHECK(canonical.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    CHECK(cdisasm_instruction_has_x86_group(
        &canonical, CDISASM_X86_GROUP_AVX512F));
    CHECK(cdisasm_instruction_has_x86_group(
        &canonical, CDISASM_X86_GROUP_AVX512CD));
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_x86_format(
              &canonical,
              CDISASM_FORMAT_SYNTAX_INTEL,
              canonical_text,
              sizeof(canonical_text))
        == sizeof("vpconflictd zmm1, zmm3") - 1u);
    CHECK(strcmp(canonical_text, "vpconflictd zmm1, zmm3") == 0);
#  endif
    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_X86_MODE_64,
        optional_vpconflictd,
        sizeof(optional_vpconflictd),
        UINT64_C(0x1090),
        CDISASM_X86_DECODE_FLAG_AVX512,
        &canonical);
    CHECK(optional_size == sizeof(optional_vpconflictd));
    CHECK(canonical.last_error_id == CDISASM_STATUS_OK);
    CHECK(canonical.name_id == CDISASM_X86_NAME_VPCONFLICTD);

    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_X86_MODE_64,
        optional_vpbroadcastmb2q,
        sizeof(optional_vpbroadcastmb2q),
        UINT64_C(0x10a0),
        CDISASM_X86_DECODE_FLAG_AVX512_CD,
        &canonical);
    CHECK(optional_size == sizeof(optional_vpbroadcastmb2q));
    CHECK(canonical.last_error_id == CDISASM_STATUS_OK);
    CHECK(canonical.name_id == CDISASM_X86_NAME_VPBROADCASTMB2Q);
    CHECK(canonical.operand_count == 2u);
    CHECK(canonical.opcode[0].type == CDISASM_OPERAND_REGISTER);
    CHECK(canonical.opcode[0].reg == CDISASM_X86_REG_ZMM1);
    CHECK(canonical.opcode[0].size == 64u);
    CHECK(canonical.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    CHECK(canonical.opcode[1].type == CDISASM_OPERAND_REGISTER);
    CHECK(canonical.opcode[1].reg == CDISASM_X86_REG_K3);
    CHECK(canonical.opcode[1].size == 8u);
    CHECK(canonical.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    CHECK(cdisasm_instruction_has_x86_group(
        &canonical, CDISASM_X86_GROUP_AVX512CD));
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_x86_format(
              &canonical,
              CDISASM_FORMAT_SYNTAX_INTEL,
              canonical_text,
              sizeof(canonical_text))
        == sizeof("vpbroadcastmb2q zmm1, k3") - 1u);
    CHECK(strcmp(canonical_text,
        "vpbroadcastmb2q zmm1, k3") == 0);
#  endif

    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_ICE_LAKE,
        CDISASM_X86_MODE_64,
        optional_vpdpbusds,
        sizeof(optional_vpdpbusds),
        UINT64_C(0x10b0),
        CDISASM_X86_DECODE_FLAG_AVX512_VNNI,
        &canonical);
    CHECK(optional_size == sizeof(optional_vpdpbusds));
    CHECK(canonical.last_error_id == CDISASM_STATUS_OK);
    CHECK(canonical.name_id == CDISASM_X86_NAME_VPDPBUSDS);
    CHECK(canonical.operand_count == 3u);
    CHECK(canonical.opcode[0].type == CDISASM_OPERAND_REGISTER);
    CHECK(canonical.opcode[0].reg == CDISASM_X86_REG_XMM1);
    CHECK(canonical.opcode[0].size == 16u);
    CHECK(canonical.opcode[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);
    CHECK(canonical.opcode[1].reg == CDISASM_X86_REG_XMM2);
    CHECK(canonical.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    CHECK(canonical.opcode[2].reg == CDISASM_X86_REG_XMM3);
    CHECK(canonical.opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    CHECK(cdisasm_instruction_has_x86_group(
        &canonical, CDISASM_X86_GROUP_AVX512VNNI));
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_x86_format(
              &canonical,
              CDISASM_FORMAT_SYNTAX_INTEL,
              canonical_text,
              sizeof(canonical_text))
        == sizeof("vpdpbusds xmm1, xmm2, xmm3") - 1u);
    CHECK(strcmp(canonical_text,
        "vpdpbusds xmm1, xmm2, xmm3") == 0);
#  endif
#else
    CHECK(optional_size == 0u);
    CHECK(canonical.last_error_id == CDISASM_STATUS_INVALID_ARGUMENT);
#endif

    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_X86_MODE_64,
        optional_vpermi2b,
        sizeof(optional_vpermi2b),
        UINT64_C(0x10c0),
        CDISASM_X86_DECODE_FLAG_BASE,
        &canonical);
    CHECK(optional_size == 0u);
    CHECK(canonical.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_ICE_LAKE,
        CDISASM_X86_MODE_64,
        optional_vpermi2b,
        sizeof(optional_vpermi2b),
        UINT64_C(0x10c0),
        CDISASM_X86_DECODE_FLAG_AVX512_VBMI,
        &canonical);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(optional_vpermi2b));
    CHECK(canonical.last_error_id == CDISASM_STATUS_OK);
    CHECK(canonical.name_id == CDISASM_X86_NAME_VPERMI2B);
    CHECK(canonical.operand_count == 3u);
    CHECK(canonical.opcode[0].reg == CDISASM_X86_REG_XMM1);
    CHECK(canonical.opcode[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);
    CHECK(canonical.opcode[1].reg == CDISASM_X86_REG_XMM2);
    CHECK(canonical.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    CHECK(canonical.opcode[2].reg == CDISASM_X86_REG_XMM3);
    CHECK(canonical.opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    CHECK(cdisasm_instruction_has_x86_group(
        &canonical, CDISASM_X86_GROUP_AVX512VBMI));
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_x86_format(
              &canonical,
              CDISASM_FORMAT_SYNTAX_INTEL,
              canonical_text,
              sizeof(canonical_text))
        == sizeof("vpermi2b xmm1, xmm2, xmm3") - 1u);
    CHECK(strcmp(canonical_text,
        "vpermi2b xmm1, xmm2, xmm3") == 0);
#  endif
#else
    CHECK(optional_size == 0u);
    CHECK(canonical.last_error_id == CDISASM_STATUS_INVALID_ARGUMENT);
#endif

    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_X86_MODE_64,
        optional_vpermi2w,
        sizeof(optional_vpermi2w),
        UINT64_C(0x10d0),
        CDISASM_X86_DECODE_FLAG_BASE,
        &canonical);
    CHECK(optional_size == 0u);
    CHECK(canonical.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    optional_size = cdisasm_x86_decode(
        CDISASM_CPU_SKYLAKE_SP,
        CDISASM_X86_MODE_64,
        optional_vpermi2w,
        sizeof(optional_vpermi2w),
        UINT64_C(0x10d0),
        CDISASM_X86_DECODE_FLAG_AVX512_BW,
        &canonical);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(optional_vpermi2w));
    CHECK(canonical.last_error_id == CDISASM_STATUS_OK);
    CHECK(canonical.name_id == CDISASM_X86_NAME_VPERMI2W);
    CHECK(canonical.operand_count == 3u);
    CHECK(canonical.opcode[0].reg == CDISASM_X86_REG_XMM1);
    CHECK(canonical.opcode[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);
    CHECK(canonical.opcode[1].reg == CDISASM_X86_REG_XMM2);
    CHECK(canonical.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    CHECK(canonical.opcode[2].reg == CDISASM_X86_REG_XMM3);
    CHECK(canonical.opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    CHECK(cdisasm_instruction_has_x86_group(
        &canonical, CDISASM_X86_GROUP_AVX512BW));
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_x86_format(
              &canonical,
              CDISASM_FORMAT_SYNTAX_INTEL,
              canonical_text,
              sizeof(canonical_text))
        == sizeof("vpermi2w xmm1, xmm2, xmm3") - 1u);
    CHECK(strcmp(canonical_text,
        "vpermi2w xmm1, xmm2, xmm3") == 0);
#  endif
#else
    CHECK(optional_size == 0u);
    CHECK(canonical.last_error_id == CDISASM_STATUS_INVALID_ARGUMENT);
#endif
}
#endif

#if USE_ARCH_ARM
static void check_arm(void)
{
    static const uint8_t add_r0_r1_5[] = {
        UINT8_C(0x05), UINT8_C(0x00), UINT8_C(0x81), UINT8_C(0xe2)
    };
    static const uint8_t ret[] = {
        UINT8_C(0xc0), UINT8_C(0x03), UINT8_C(0x5f), UINT8_C(0xd6)
    };
    static const uint8_t thumb_nop[] = {
        UINT8_C(0x00), UINT8_C(0xbf)
    };
    static const uint8_t a32_neon[] = {
        UINT8_C(0xa0), UINT8_C(0x08), UINT8_C(0x41), UINT8_C(0xf2)
    };
    static const uint8_t a64_neon[] = {
        UINT8_C(0x20), UINT8_C(0x84), UINT8_C(0x22), UINT8_C(0x4e)
    };
    static const uint8_t apple_amx[] = {
        UINT8_C(0x60), UINT8_C(0x12), UINT8_C(0x20), UINT8_C(0x00)
    };
    static const uint8_t apple_mul53[] = {
        UINT8_C(0x01), UINT8_C(0x04), UINT8_C(0x20), UINT8_C(0x00)
    };
    static const uint8_t apple_a7_mrs[] = {
        UINT8_C(0x00), UINT8_C(0xf2), UINT8_C(0x3f), UINT8_C(0xd5)
    };
    static const uint8_t optional_casb[] = {
        UINT8_C(0x41), UINT8_C(0x7c), UINT8_C(0xa0), UINT8_C(0x08)
    };
    static const uint8_t optional_cmpls_immediate[] = {
        UINT8_C(0x77), UINT8_C(0xed), UINT8_C(0xff), UINT8_C(0x24)
    };
    static const uint8_t optional_fcmne_zero[] = {
        UINT8_C(0x67), UINT8_C(0x2d), UINT8_C(0x93), UINT8_C(0x65)
    };
    static const uint8_t optional_facgt_vector[] = {
        UINT8_C(0x30), UINT8_C(0xe0), UINT8_C(0x40), UINT8_C(0x65)
    };
    static const uint8_t optional_fdivr[] = {
        UINT8_C(0xac), UINT8_C(0x8d), UINT8_C(0xcc), UINT8_C(0x65)
    };
    static const uint8_t optional_faddv[] = {
        UINT8_C(0x00), UINT8_C(0x20), UINT8_C(0x40), UINT8_C(0x65)
    };
    static const uint8_t optional_fadda[] = {
        UINT8_C(0xac), UINT8_C(0x2d), UINT8_C(0xd8), UINT8_C(0x65)
    };
    static const uint8_t optional_frintn[] = {
        UINT8_C(0xa7), UINT8_C(0xad), UINT8_C(0x80), UINT8_C(0x65)
    };
    static const uint8_t optional_frecpe[] = {
        UINT8_C(0xa7), UINT8_C(0x31), UINT8_C(0x8e), UINT8_C(0x65)
    };
    static const uint8_t optional_bfcvt[] = {
        UINT8_C(0x29), UINT8_C(0xae), UINT8_C(0x8a), UINT8_C(0x65)
    };
    static const uint8_t optional_bfcvtnt_zero[] = {
        UINT8_C(0x28), UINT8_C(0xa5), UINT8_C(0x82), UINT8_C(0x64)
    };
    static const uint8_t optional_bfcvtn_multi[] = {
        UINT8_C(0x75), UINT8_C(0xe1), UINT8_C(0x60), UINT8_C(0xc1)
    };
    static const uint8_t optional_bfcvt_fp8_multi[] = {
        UINT8_C(0xdf), UINT8_C(0xe3), UINT8_C(0x64), UINT8_C(0xc1)
    };
    static const uint8_t optional_bfcvtn_fp8_multi[] = {
        UINT8_C(0xdf), UINT8_C(0x3b), UINT8_C(0x0a), UINT8_C(0x65)
    };
    static const uint8_t optional_advsimd_frecpe[] = {
        UINT8_C(0xa7), UINT8_C(0xd9), UINT8_C(0xa1), UINT8_C(0x5e)
    };
    static const uint8_t optional_advsimd_frsqrte[] = {
        UINT8_C(0xa7), UINT8_C(0xd9), UINT8_C(0xa1), UINT8_C(0x6e)
    };
    const cdisasm_arm_mode_mask modes32 =
        CDISASM_ARM_MODE_MASK_A32 | CDISASM_ARM_MODE_MASK_T32;
    const cdisasm_arm_mode_mask all_modes =
        modes32 | CDISASM_ARM_MODE_MASK_A64;
    cdisasm_arm_instruction instruction;
    cdisasm_arm_decode_flags available_flags =
        CDISASM_ARM_DECODE_FLAGS_NONE_INITIALIZER;
    const cdisasm_arm_decode_flags zero_flags =
        CDISASM_ARM_DECODE_FLAGS_NONE_INITIALIZER;
    uint32_t optional_size;
#if USE_DISASM_FORMAT
    static const char expected_nop[] = "nop";
    char formatted[64];
#endif

    CHECK(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_CORTEX_A7)
        == modes32);
    CHECK(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_CORTEX_A34)
        == CDISASM_ARM_MODE_MASK_A64);
    CHECK(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_CORTEX_A35)
        == all_modes);
    CHECK(cdisasm_arm_decoder_mode_mask(CDISASM_ARM_CPU_CORTEX_A7)
        == modes32);
    CHECK(cdisasm_arm_decoder_mode_mask(CDISASM_ARM_CPU_CORTEX_A35)
        == all_modes);
    CHECK(cdisasm_arm_cpu_decode_flag_mask(
              CDISASM_ARM_CPU_CORTEX_A7,
              CDISASM_ARM_MODE_A32,
              &available_flags)
        == CDISASM_STATUS_OK);
    CHECK(available_flags.bitmap[CDISASM_ARM_DECODE_FLAGS_OPTION_BITMAP]
        == CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN);
    CHECK(cdisasm_cpu_decode_flag_mask(
              CDISASM_ARM_CPU_CORTEX_A7,
              CDISASM_ARM_MODE_A32,
              &available_flags)
        == CDISASM_STATUS_OK);
    CHECK(available_flags.bitmap[CDISASM_ARM_DECODE_FLAGS_OPTION_BITMAP]
        == CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN);
    memset(&available_flags, 0xa5, sizeof(available_flags));
    CHECK(cdisasm_arm_cpu_decode_flag_mask(
              CDISASM_ARM_CPU_CORTEX_A7,
              CDISASM_ARM_MODE_A64,
              &available_flags)
        == CDISASM_STATUS_INVALID_ARGUMENT);
    CHECK(memcmp(&available_flags, &zero_flags, sizeof(zero_flags)) == 0);
    CHECK(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_APPLE_A4) == modes32);
    CHECK(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_APPLE_A7) == all_modes);
    CHECK(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_APPLE_A11)
        == CDISASM_ARM_MODE_MASK_A64);
    CHECK(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_APPLE_M5)
        == CDISASM_ARM_MODE_MASK_A64);
    CHECK(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_APPLE_S10)
        == CDISASM_ARM_MODE_MASK_A64);
    CHECK(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_FUJITSU_A64FX)
        == CDISASM_ARM_MODE_MASK_A64);

    CHECK(cdisasm_arm_decode(
              CDISASM_ARM_CPU_CORTEX_A7,
              CDISASM_ARM_MODE_A32,
              add_r0_r1_5,
              sizeof(add_r0_r1_5),
              UINT64_C(0x2000),
              CDISASM_ARM_DECODE_OPTION_NONE,
              &instruction)
        == sizeof(add_r0_r1_5));
    CHECK(instruction.last_error_id == CDISASM_STATUS_OK);
    CHECK(instruction.name_id == CDISASM_ARM_NAME_ADD);
    CHECK(instruction.isa_id == CDISASM_ARM_ISA_A32);
    CHECK(instruction.operand_count == 3);
    CHECK(instruction.operand[0].reg == CDISASM_ARM_REG_R0);
    CHECK(instruction.operand[1].reg == CDISASM_ARM_REG_R1);
    CHECK(instruction.operand[2].type == CDISASM_OPERAND_IMMEDIATE);
    CHECK(instruction.operand[2].imm == UINT64_C(5));

    CHECK(cdisasm_arm_decode(
              CDISASM_ARM_CPU_CORTEX_A7,
              CDISASM_ARM_MODE_T32,
              thumb_nop,
              sizeof(thumb_nop),
              UINT64_C(0x2800),
              CDISASM_ARM_DECODE_OPTION_NONE,
              &instruction)
        == sizeof(thumb_nop));
    CHECK(instruction.last_error_id == CDISASM_STATUS_OK);
    CHECK(instruction.name_id == CDISASM_ARM_NAME_NOP);
    CHECK(instruction.isa_id == CDISASM_ARM_ISA_T32);
    CHECK(instruction.raw_instruction == UINT32_C(0xbf00));
#if USE_DISASM_FORMAT
    CHECK(cdisasm_arm_format(
              &instruction, CDISASM_FORMAT_SYNTAX_0, NULL, 0)
        == sizeof(expected_nop) - 1u);
    CHECK(cdisasm_arm_format(
              &instruction,
              CDISASM_FORMAT_UPPERCASE_OPCODE,
              formatted,
              sizeof(formatted))
        == sizeof(expected_nop) - 1u);
    CHECK(strcmp(formatted, "NOP") == 0);
#endif

    CHECK(cdisasm_arm_decode(
              CDISASM_ARM_CPU_CORTEX_A34,
              CDISASM_ARM_MODE_A64,
              ret,
              sizeof(ret),
              UINT64_C(0x3000),
              CDISASM_ARM_DECODE_OPTION_NONE,
              &instruction)
        == sizeof(ret));
    CHECK(instruction.last_error_id == CDISASM_STATUS_OK);
    CHECK(instruction.name_id == CDISASM_ARM_NAME_RET);
    CHECK(instruction.isa_id == CDISASM_ARM_ISA_A64);
    CHECK(instruction.opcode_groups == CDISASM_GROUP_RETURN);
    CHECK(instruction.operand_count == 1);
    CHECK(instruction.operand[0].reg == CDISASM_ARM_REG_X30);

    CHECK(cdisasm_arm_decode(
              CDISASM_ARM_CPU_CORTEX_A9_NEON,
              CDISASM_ARM_MODE_A32,
              a32_neon,
              sizeof(a32_neon),
              UINT64_C(0x4000),
              CDISASM_ARM_DECODE_OPTION_NONE,
              &instruction)
        == sizeof(a32_neon));
    CHECK(instruction.name_id == CDISASM_ARM_NAME_VADD);
    CHECK(instruction.operand[0].reg == CDISASM_ARM_REG_D16);
    CHECK(CDISASM_ARM_VECTOR_ELEMENT_SIZE(&instruction.operand[0]) == 1);
    CHECK(CDISASM_ARM_VECTOR_ELEMENT_COUNT(&instruction.operand[0]) == 8);

    CHECK(cdisasm_arm_decode(
              CDISASM_ARM_CPU_CORTEX_A7,
              CDISASM_ARM_MODE_A32,
              a32_neon,
              sizeof(a32_neon),
              UINT64_C(0x4010),
              CDISASM_ARM_DECODE_OPTION_NONE,
              &instruction)
        == 0);
    CHECK(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
    CHECK(cdisasm_arm_decode(
              CDISASM_ARM_CPU_CORTEX_A7_NEON,
              CDISASM_ARM_MODE_A32,
              a32_neon,
              sizeof(a32_neon),
              UINT64_C(0x4010),
              CDISASM_ARM_DECODE_OPTION_NONE,
              &instruction)
        == sizeof(a32_neon));

    CHECK(cdisasm_arm_decode(
              CDISASM_ARM_CPU_APPLE_M1,
              CDISASM_ARM_MODE_A64,
              a64_neon,
              sizeof(a64_neon),
              UINT64_C(0x5000),
              CDISASM_ARM_DECODE_OPTION_NONE,
              &instruction)
        == sizeof(a64_neon));
    CHECK(instruction.name_id == CDISASM_ARM_NAME_ADD);
    CHECK(instruction.operand[0].reg == CDISASM_ARM_REG_V0);
    CHECK(instruction.operand[0].size == 16);
    CHECK(CDISASM_ARM_VECTOR_ELEMENT_SIZE(&instruction.operand[0]) == 1);
    CHECK(CDISASM_ARM_VECTOR_ELEMENT_COUNT(&instruction.operand[0]) == 16);

    CHECK(cdisasm_arm_decode(
              CDISASM_ARM_CPU_APPLE_M1,
              CDISASM_ARM_MODE_A64,
              apple_amx,
              sizeof(apple_amx),
              UINT64_C(0x5100),
              CDISASM_ARM_DECODE_OPTION_NONE,
              &instruction)
        == sizeof(apple_amx));
    CHECK(instruction.name_id == CDISASM_ARM_NAME_VECFP);
    CHECK(instruction.operand[0].reg == CDISASM_ARM_REG_X0);
    CHECK((instruction.instruction_flags
              & (CDISASM_ARM_INSTRUCTION_FLAG_APPLE_PROPRIETARY
                  | CDISASM_ARM_INSTRUCTION_FLAG_APPLE_AMX))
        == (CDISASM_ARM_INSTRUCTION_FLAG_APPLE_PROPRIETARY
            | CDISASM_ARM_INSTRUCTION_FLAG_APPLE_AMX));

    CHECK(cdisasm_arm_decode(
              CDISASM_ARM_CPU_APPLE_A11,
              CDISASM_ARM_MODE_A64,
              apple_mul53,
              sizeof(apple_mul53),
              UINT64_C(0x5200),
              CDISASM_ARM_DECODE_OPTION_NONE,
              &instruction)
        == sizeof(apple_mul53));
    CHECK(instruction.name_id == CDISASM_ARM_NAME_MUL53HI);
    CHECK(instruction.operand[0].reg == CDISASM_ARM_REG_V1);
    CHECK(instruction.operand[1].reg == CDISASM_ARM_REG_V0);

    CHECK(cdisasm_arm_decode(
              CDISASM_ARM_CPU_APPLE_A7,
              CDISASM_ARM_MODE_A64,
              apple_a7_mrs,
              sizeof(apple_a7_mrs),
              UINT64_C(0x5300),
              CDISASM_ARM_DECODE_OPTION_NONE,
              &instruction)
        == sizeof(apple_a7_mrs));
    CHECK(instruction.name_id == CDISASM_ARM_NAME_MRS);
    CHECK(instruction.operand[1].reg
        == CDISASM_ARM_REG_CPM_IOACC_CTL_EL3);

    optional_size = cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64,
        optional_casb,
        sizeof(optional_casb),
        UINT64_C(0x5400),
        CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(optional_casb));
    CHECK(instruction.last_error_id == CDISASM_STATUS_OK);
    CHECK(instruction.name_id == CDISASM_ARM_NAME_CASB);
    CHECK(instruction.operand_count == 3u);
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_arm_format(
              &instruction,
              CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
              formatted,
              sizeof(formatted))
        == sizeof("casb w0, w1, [x2]") - 1u);
    CHECK(strcmp(formatted, "casb w0, w1, [x2]") == 0);
#  endif
#else
    CHECK(optional_size == 0u);
    CHECK(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#  if USE_DISASM_FORMAT
    memset(&instruction, 0, sizeof(instruction));
    instruction.name_id = CDISASM_ARM_NAME_CASB;
    formatted[0] = 'X';
    CHECK(cdisasm_arm_format(
              &instruction,
              CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
              formatted,
              sizeof(formatted))
        == 0u);
    CHECK(formatted[0] == '\0');
#  endif
#endif

    optional_size = cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64,
        optional_bfcvtnt_zero,
        sizeof(optional_bfcvtnt_zero),
        UINT64_C(0x566c),
        CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(optional_bfcvtnt_zero));
    CHECK(instruction.last_error_id == CDISASM_STATUS_OK);
    CHECK(instruction.name_id == CDISASM_ARM_NAME_BFCVTNT);
    CHECK(instruction.operand_count == 3u);
    CHECK(instruction.operand[0].reg == CDISASM_ARM_REG_Z8);
    CHECK(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction.operand[0]) == 2u);
    CHECK(instruction.operand[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);
    CHECK(instruction.operand[1].reg == CDISASM_ARM_REG_P1);
    CHECK(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction.operand[1]) == 4u);
    CHECK(instruction.operand[1].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO);
    CHECK(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
    CHECK(instruction.operand[2].reg == CDISASM_ARM_REG_Z9);
    CHECK(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction.operand[2]) == 4u);
    CHECK(instruction.operand[2].access == CDISASM_OPERAND_ACCESS_READ);
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_arm_format(
              &instruction,
              CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
              formatted,
              sizeof(formatted))
        == sizeof("bfcvtnt z8.h, p1/z, z9.s") - 1u);
    CHECK(strcmp(formatted, "bfcvtnt z8.h, p1/z, z9.s") == 0);
#  endif
#else
    CHECK(optional_size == 0u);
    CHECK(instruction.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    optional_size = cdisasm_arm_decode(
        CDISASM_ARM_CPU_APPLE_M4,
        CDISASM_ARM_MODE_A64,
        optional_bfcvt,
        sizeof(optional_bfcvt),
        UINT64_C(0x5668),
        CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(optional_bfcvt));
    CHECK(instruction.last_error_id == CDISASM_STATUS_OK);
    CHECK(instruction.name_id == CDISASM_ARM_NAME_BFCVT);
    CHECK(instruction.operand_count == 3u);
    CHECK(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
    CHECK(instruction.operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    CHECK(instruction.operand[0].reg == CDISASM_ARM_REG_Z9);
    CHECK(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction.operand[0]) == 2u);
    CHECK(instruction.operand[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);
    CHECK(instruction.operand[1].type == CDISASM_ARM_OPERAND_PREDICATE);
    CHECK(instruction.operand[1].reg == CDISASM_ARM_REG_P3);
    CHECK(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction.operand[1]) == 4u);
    CHECK(instruction.operand[1].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE);
    CHECK(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
    CHECK(instruction.operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    CHECK(instruction.operand[2].reg == CDISASM_ARM_REG_Z17);
    CHECK(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction.operand[2]) == 4u);
    CHECK(instruction.operand[2].access == CDISASM_OPERAND_ACCESS_READ);
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_arm_format(
              &instruction,
              CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
              formatted,
              sizeof(formatted))
        == sizeof("bfcvt z9.h, p3/m, z17.s") - 1u);
    CHECK(strcmp(formatted, "bfcvt z9.h, p3/m, z17.s") == 0);
#  endif
#else
    CHECK(optional_size == 0u);
    CHECK(instruction.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    optional_size = cdisasm_arm_decode(
        CDISASM_ARM_CPU_APPLE_M4,
        CDISASM_ARM_MODE_A64,
        optional_bfcvtn_multi,
        sizeof(optional_bfcvtn_multi),
        UINT64_C(0x566e),
        CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(optional_bfcvtn_multi));
    CHECK(instruction.last_error_id == CDISASM_STATUS_OK);
    CHECK(instruction.name_id == CDISASM_ARM_NAME_BFCVTN);
    CHECK(instruction.operand_count == 2u);
    CHECK(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
            | CDISASM_ARM_INSTRUCTION_FLAG_SME));
    CHECK(instruction.operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    CHECK(instruction.operand[0].reg == CDISASM_ARM_REG_Z21);
    CHECK(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction.operand[0]) == 2u);
    CHECK(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    CHECK(instruction.operand[1].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);
    CHECK(instruction.operand[1].reg == CDISASM_ARM_REG_Z10);
    CHECK(instruction.operand[1].register_list == UINT16_C(0x0102));
    CHECK(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction.operand[1]) == 4u);
    CHECK(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_arm_format(
              &instruction,
              CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
              formatted,
              sizeof(formatted))
        == sizeof("bfcvtn z21.h, {z10.s, z11.s}") - 1u);
    CHECK(strcmp(formatted, "bfcvtn z21.h, {z10.s, z11.s}") == 0);
#  endif
#else
    CHECK(optional_size == 0u);
    CHECK(instruction.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    optional_size = cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64,
        optional_bfcvt_fp8_multi,
        sizeof(optional_bfcvt_fp8_multi),
        UINT64_C(0x5672),
        CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(optional_bfcvt_fp8_multi));
    CHECK(instruction.last_error_id == CDISASM_STATUS_OK);
    CHECK(instruction.name_id == CDISASM_ARM_NAME_BFCVT);
    CHECK(instruction.operand_count == 2u);
    CHECK(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
            | CDISASM_ARM_INSTRUCTION_FLAG_SME));
    CHECK(instruction.operand[0].reg == CDISASM_ARM_REG_Z31);
    CHECK(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction.operand[0]) == 1u);
    CHECK(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    CHECK(instruction.operand[1].reg == CDISASM_ARM_REG_Z30);
    CHECK(instruction.operand[1].register_list == UINT16_C(0x0102));
    CHECK(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction.operand[1]) == 2u);
    CHECK(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_arm_format(
              &instruction,
              CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
              formatted,
              sizeof(formatted))
        == sizeof("bfcvt z31.b, {z30.h, z31.h}") - 1u);
    CHECK(strcmp(formatted, "bfcvt z31.b, {z30.h, z31.h}") == 0);
#  endif
#else
    CHECK(optional_size == 0u);
    CHECK(instruction.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    optional_size = cdisasm_arm_decode(
        CDISASM_ARM_CPU_APPLE_A18,
        CDISASM_ARM_MODE_A64,
        optional_bfcvt_fp8_multi,
        sizeof(optional_bfcvt_fp8_multi),
        UINT64_C(0x5672),
        CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction);
    CHECK(optional_size == 0u);
#if USE_EXTRA_OPCODES
    CHECK(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
#else
    CHECK(instruction.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    optional_size = cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64,
        optional_bfcvtn_fp8_multi,
        sizeof(optional_bfcvtn_fp8_multi),
        UINT64_C(0x5676),
        CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(optional_bfcvtn_fp8_multi));
    CHECK(instruction.last_error_id == CDISASM_STATUS_OK);
    CHECK(instruction.name_id == CDISASM_ARM_NAME_BFCVTN);
    CHECK(instruction.operand_count == 2u);
    CHECK(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
    CHECK(instruction.operand[0].reg == CDISASM_ARM_REG_Z31);
    CHECK(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction.operand[0]) == 1u);
    CHECK(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    CHECK(instruction.operand[1].reg == CDISASM_ARM_REG_Z30);
    CHECK(instruction.operand[1].register_list == UINT16_C(0x0102));
    CHECK(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction.operand[1]) == 2u);
    CHECK(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_arm_format(
              &instruction,
              CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
              formatted,
              sizeof(formatted))
        == sizeof("bfcvtn z31.b, {z30.h, z31.h}") - 1u);
    CHECK(strcmp(formatted, "bfcvtn z31.b, {z30.h, z31.h}") == 0);
#  endif
#else
    CHECK(optional_size == 0u);
    CHECK(instruction.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    optional_size = cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64,
        optional_cmpls_immediate,
        sizeof(optional_cmpls_immediate),
        UINT64_C(0x5500),
        CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(optional_cmpls_immediate));
    CHECK(instruction.last_error_id == CDISASM_STATUS_OK);
    CHECK(instruction.name_id == CDISASM_ARM_NAME_CMPLS);
    CHECK(instruction.operand_count == 4u);
    CHECK(instruction.operand[0].reg == CDISASM_ARM_REG_P7);
    CHECK(instruction.operand[1].reg == CDISASM_ARM_REG_P3);
    CHECK(instruction.operand[2].reg == CDISASM_ARM_REG_Z11);
    CHECK(instruction.operand[3].type == CDISASM_OPERAND_IMMEDIATE);
    CHECK(instruction.operand[3].imm == UINT64_C(0x7f));
    CHECK((instruction.instruction_flags
              & (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                  | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
                  | CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS))
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS));
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_arm_format(
              &instruction,
              CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
              formatted,
              sizeof(formatted))
        == sizeof("cmpls p7.d, p3/z, z11.d, #0x7f") - 1u);
    CHECK(strcmp(formatted,
        "cmpls p7.d, p3/z, z11.d, #0x7f") == 0);
#  endif
#else
    CHECK(optional_size == 0u);
    CHECK(instruction.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    optional_size = cdisasm_arm_decode(
        CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_A64,
        optional_fcmne_zero,
        sizeof(optional_fcmne_zero),
        UINT64_C(0x5600),
        CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(optional_fcmne_zero));
    CHECK(instruction.last_error_id == CDISASM_STATUS_OK);
    CHECK(instruction.name_id == CDISASM_ARM_NAME_FCMNE);
    CHECK(instruction.operand_count == 4u);
    CHECK(instruction.operand[0].reg == CDISASM_ARM_REG_P7);
    CHECK(instruction.operand[1].reg == CDISASM_ARM_REG_P3);
    CHECK(instruction.operand[2].reg == CDISASM_ARM_REG_Z11);
    CHECK(instruction.operand[3].type == CDISASM_OPERAND_IMMEDIATE);
    CHECK(instruction.operand[3].imm == UINT64_C(0));
    CHECK((instruction.instruction_flags
              & (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                  | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
                  | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT))
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_arm_format(
              &instruction,
              CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
              formatted,
              sizeof(formatted))
        == sizeof("fcmne p7.s, p3/z, z11.s, #0.0") - 1u);
    CHECK(strcmp(formatted,
        "fcmne p7.s, p3/z, z11.s, #0.0") == 0);
#  endif
#else
    CHECK(optional_size == 0u);
    CHECK(instruction.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    optional_size = cdisasm_arm_decode(
        CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_A64,
        optional_facgt_vector,
        sizeof(optional_facgt_vector),
        UINT64_C(0x5610),
        CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(optional_facgt_vector));
    CHECK(instruction.last_error_id == CDISASM_STATUS_OK);
    CHECK(instruction.name_id == CDISASM_ARM_NAME_FACGT);
    CHECK(instruction.operand_count == 4u);
    CHECK(instruction.operand[0].reg == CDISASM_ARM_REG_P0);
    CHECK(instruction.operand[1].reg == CDISASM_ARM_REG_P0);
    CHECK(instruction.operand[2].reg == CDISASM_ARM_REG_Z1);
    CHECK(instruction.operand[3].reg == CDISASM_ARM_REG_Z0);
    CHECK((instruction.instruction_flags
              & (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                  | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
                  | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT))
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_arm_format(
              &instruction,
              CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
              formatted,
              sizeof(formatted))
        == sizeof("facgt p0.h, p0/z, z1.h, z0.h") - 1u);
    CHECK(strcmp(formatted,
        "facgt p0.h, p0/z, z1.h, z0.h") == 0);
#  endif
#else
    CHECK(optional_size == 0u);
    CHECK(instruction.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    optional_size = cdisasm_arm_decode(
        CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_A64,
        optional_fdivr,
        sizeof(optional_fdivr),
        UINT64_C(0x5620),
        CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(optional_fdivr));
    CHECK(instruction.last_error_id == CDISASM_STATUS_OK);
    CHECK(instruction.name_id == CDISASM_ARM_NAME_FDIVR);
    CHECK(instruction.isa_id == CDISASM_ARM_ISA_A64);
    CHECK(instruction.opcode_groups == CDISASM_GROUP_NONE);
    CHECK(instruction.operand_count == 4u);
    CHECK(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
    CHECK(instruction.operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    CHECK(instruction.operand[0].reg == CDISASM_ARM_REG_Z12);
    CHECK(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction.operand[0])
        == 8u);
    CHECK(instruction.operand[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);
    CHECK(instruction.operand[1].type == CDISASM_ARM_OPERAND_PREDICATE);
    CHECK(instruction.operand[1].reg == CDISASM_ARM_REG_P3);
    CHECK(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction.operand[1])
        == 8u);
    CHECK(instruction.operand[1].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE);
    CHECK(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
    CHECK(instruction.operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    CHECK(instruction.operand[2].reg == CDISASM_ARM_REG_Z12);
    CHECK(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction.operand[2])
        == 8u);
    CHECK(instruction.operand[2].access == CDISASM_OPERAND_ACCESS_READ);
    CHECK(instruction.operand[3].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    CHECK(instruction.operand[3].reg == CDISASM_ARM_REG_Z13);
    CHECK(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction.operand[3])
        == 8u);
    CHECK(instruction.operand[3].access == CDISASM_OPERAND_ACCESS_READ);
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_arm_format(
              &instruction,
              CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
              formatted,
              sizeof(formatted))
        == sizeof("fdivr z12.d, p3/m, z12.d, z13.d") - 1u);
    CHECK(strcmp(formatted,
        "fdivr z12.d, p3/m, z12.d, z13.d") == 0);
#  endif
#else
    CHECK(optional_size == 0u);
    CHECK(instruction.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    optional_size = cdisasm_arm_decode(
        CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_A64,
        optional_faddv,
        sizeof(optional_faddv),
        UINT64_C(0x5630),
        CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(optional_faddv));
    CHECK(instruction.last_error_id == CDISASM_STATUS_OK);
    CHECK(instruction.name_id == CDISASM_ARM_NAME_FADDV);
    CHECK(instruction.isa_id == CDISASM_ARM_ISA_A64);
    CHECK(instruction.opcode_groups == CDISASM_GROUP_NONE);
    CHECK(instruction.operand_count == 3u);
    CHECK(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
    CHECK(instruction.operand[0].type == CDISASM_OPERAND_REGISTER);
    CHECK(instruction.operand[0].reg == CDISASM_ARM_REG_H0);
    CHECK(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    CHECK(instruction.operand[1].type == CDISASM_ARM_OPERAND_PREDICATE);
    CHECK(instruction.operand[1].reg == CDISASM_ARM_REG_P0);
    CHECK(instruction.operand[1].flags == 0u);
    CHECK(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
    CHECK(instruction.operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    CHECK(instruction.operand[2].reg == CDISASM_ARM_REG_Z0);
    CHECK(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction.operand[2])
        == 2u);
    CHECK(instruction.operand[2].access == CDISASM_OPERAND_ACCESS_READ);
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_arm_format(
              &instruction,
              CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
              formatted,
              sizeof(formatted))
        == sizeof("faddv h0, p0, z0.h") - 1u);
    CHECK(strcmp(formatted, "faddv h0, p0, z0.h") == 0);
#  endif
#else
    CHECK(optional_size == 0u);
    CHECK(instruction.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    optional_size = cdisasm_arm_decode(
        CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_A64,
        optional_fadda,
        sizeof(optional_fadda),
        UINT64_C(0x5640),
        CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(optional_fadda));
    CHECK(instruction.last_error_id == CDISASM_STATUS_OK);
    CHECK(instruction.name_id == CDISASM_ARM_NAME_FADDA);
    CHECK(instruction.operand_count == 4u);
    CHECK(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
    CHECK(instruction.operand[0].type == CDISASM_OPERAND_REGISTER);
    CHECK(instruction.operand[0].reg == CDISASM_ARM_REG_D12);
    CHECK(instruction.operand[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);
    CHECK(instruction.operand[1].type == CDISASM_ARM_OPERAND_PREDICATE);
    CHECK(instruction.operand[1].reg == CDISASM_ARM_REG_P3);
    CHECK(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
    CHECK(instruction.operand[2].type == CDISASM_OPERAND_REGISTER);
    CHECK(instruction.operand[2].reg == CDISASM_ARM_REG_D12);
    CHECK(instruction.operand[2].access == CDISASM_OPERAND_ACCESS_READ);
    CHECK(instruction.operand[3].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    CHECK(instruction.operand[3].reg == CDISASM_ARM_REG_Z13);
    CHECK(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction.operand[3]) == 8u);
    CHECK(instruction.operand[3].access == CDISASM_OPERAND_ACCESS_READ);
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_arm_format(
              &instruction,
              CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
              formatted,
              sizeof(formatted))
        == sizeof("fadda d12, p3, d12, z13.d") - 1u);
    CHECK(strcmp(formatted,
        "fadda d12, p3, d12, z13.d") == 0);
#  endif
#else
    CHECK(optional_size == 0u);
    CHECK(instruction.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    optional_size = cdisasm_arm_decode(
        CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_A64,
        optional_frintn,
        sizeof(optional_frintn),
        UINT64_C(0x5650),
        CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(optional_frintn));
    CHECK(instruction.last_error_id == CDISASM_STATUS_OK);
    CHECK(instruction.name_id == CDISASM_ARM_NAME_FRINTN);
    CHECK(instruction.operand_count == 3u);
    CHECK(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
    CHECK(instruction.operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    CHECK(instruction.operand[0].reg == CDISASM_ARM_REG_Z7);
    CHECK(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction.operand[0]) == 4u);
    CHECK(instruction.operand[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);
    CHECK(instruction.operand[1].type == CDISASM_ARM_OPERAND_PREDICATE);
    CHECK(instruction.operand[1].reg == CDISASM_ARM_REG_P3);
    CHECK(instruction.operand[1].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE);
    CHECK(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
    CHECK(instruction.operand[2].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    CHECK(instruction.operand[2].reg == CDISASM_ARM_REG_Z13);
    CHECK(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction.operand[2]) == 4u);
    CHECK(instruction.operand[2].access == CDISASM_OPERAND_ACCESS_READ);
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_arm_format(
              &instruction,
              CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
              formatted,
              sizeof(formatted))
        == sizeof("frintn z7.s, p3/m, z13.s") - 1u);
    CHECK(strcmp(formatted, "frintn z7.s, p3/m, z13.s") == 0);
#  endif
#else
    CHECK(optional_size == 0u);
    CHECK(instruction.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    optional_size = cdisasm_arm_decode(
        CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_A64,
        optional_frecpe,
        sizeof(optional_frecpe),
        UINT64_C(0x5660),
        CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(optional_frecpe));
    CHECK(instruction.last_error_id == CDISASM_STATUS_OK);
    CHECK(instruction.name_id == CDISASM_ARM_NAME_FRECPE);
    CHECK(instruction.operand_count == 2u);
    CHECK(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
    CHECK(instruction.operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    CHECK(instruction.operand[0].reg == CDISASM_ARM_REG_Z7);
    CHECK(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction.operand[0]) == 4u);
    CHECK(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    CHECK(instruction.operand[1].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    CHECK(instruction.operand[1].reg == CDISASM_ARM_REG_Z13);
    CHECK(CDISASM_ARM_SCALABLE_ELEMENT_SIZE(&instruction.operand[1]) == 4u);
    CHECK(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_arm_format(
              &instruction,
              CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
              formatted,
              sizeof(formatted))
        == sizeof("frecpe z7.s, z13.s") - 1u);
    CHECK(strcmp(formatted, "frecpe z7.s, z13.s") == 0);
#  endif
#else
    CHECK(optional_size == 0u);
    CHECK(instruction.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    optional_size = cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64,
        optional_advsimd_frecpe,
        sizeof(optional_advsimd_frecpe),
        UINT64_C(0x5670),
        CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(optional_advsimd_frecpe));
    CHECK(instruction.last_error_id == CDISASM_STATUS_OK);
    CHECK(instruction.name_id == CDISASM_ARM_NAME_FRECPE);
    CHECK(instruction.operand_count == 2u);
    CHECK(instruction.instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
    CHECK(instruction.operand[0].type == CDISASM_OPERAND_REGISTER);
    CHECK(instruction.operand[0].reg == CDISASM_ARM_REG_S7);
    CHECK(instruction.operand[0].size == 4u);
    CHECK(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    CHECK(instruction.operand[1].type == CDISASM_OPERAND_REGISTER);
    CHECK(instruction.operand[1].reg == CDISASM_ARM_REG_S13);
    CHECK(instruction.operand[1].size == 4u);
    CHECK(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_arm_format(
              &instruction,
              CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
              formatted,
              sizeof(formatted))
        == sizeof("frecpe s7, s13") - 1u);
    CHECK(strcmp(formatted, "frecpe s7, s13") == 0);
#  endif
#else
    CHECK(optional_size == 0u);
    CHECK(instruction.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    optional_size = cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64,
        optional_advsimd_frsqrte,
        sizeof(optional_advsimd_frsqrte),
        UINT64_C(0x5680),
        CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction);
#if USE_EXTRA_OPCODES
    CHECK(optional_size == sizeof(optional_advsimd_frsqrte));
    CHECK(instruction.last_error_id == CDISASM_STATUS_OK);
    CHECK(instruction.name_id == CDISASM_ARM_NAME_FRSQRTE);
    CHECK(instruction.operand_count == 2u);
    CHECK(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
            | CDISASM_ARM_INSTRUCTION_FLAG_SIMD));
    CHECK(instruction.operand[0].type == CDISASM_OPERAND_REGISTER);
    CHECK(instruction.operand[0].reg == CDISASM_ARM_REG_V7);
    CHECK(instruction.operand[0].size == 16u);
    CHECK(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    CHECK(instruction.operand[1].type == CDISASM_OPERAND_REGISTER);
    CHECK(instruction.operand[1].reg == CDISASM_ARM_REG_V13);
    CHECK(instruction.operand[1].size == 16u);
    CHECK(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
#  if USE_DISASM_FORMAT
    CHECK(cdisasm_arm_format(
              &instruction,
              CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
              formatted,
              sizeof(formatted))
        == sizeof("frsqrte v7.4s, v13.4s") - 1u);
    CHECK(strcmp(formatted, "frsqrte v7.4s, v13.4s") == 0);
#  endif
#else
    CHECK(optional_size == 0u);
    CHECK(instruction.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}
#endif

int main(void)
{
    CHECK(cdisasm_version()
        == ((uint32_t)CDISASM_VERSION_MAJOR << 16
            | (uint32_t)CDISASM_VERSION_MINOR << 8
            | (uint32_t)CDISASM_VERSION_PATCH));
    CHECK(strcmp(cdisasm_version_string(), CDISASM_VERSION_STRING) == 0);
    CHECK(strcmp(cdisasm_status_string(CDISASM_STATUS_OK), "success") == 0);
    check_current_cpu();

#if USE_ARCH_X86
    check_x86();
#endif
#if USE_ARCH_ARM
    check_arm();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d installed-package check(s) failed\n", failures);
        return 1;
    }
    puts("installed cdisasm package smoke test passed");
    return 0;
}
