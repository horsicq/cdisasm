#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm_x86.h"
#include "x86_test_flags.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define EXPECT(condition) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "%s:%d: expectation failed: %s\n", \
                    __FILE__, __LINE__, #condition); \
            ++failures; \
        } \
    } while (0)

static const cdisasm_x86_group_id x86_group_id_manifest[] = {
    CDISASM_X86_GROUP_NONE,
    CDISASM_X86_GROUP_I86,
    CDISASM_X86_GROUP_I186,
    CDISASM_X86_GROUP_I286,
    CDISASM_X86_GROUP_I386,
    CDISASM_X86_GROUP_I486,
    CDISASM_X86_GROUP_X87,
    CDISASM_X86_GROUP_CPUID,
    CDISASM_X86_GROUP_PENTIUM,
    CDISASM_X86_GROUP_P6,
    CDISASM_X86_GROUP_CMOV,
    CDISASM_X86_GROUP_FCMOV,
    CDISASM_X86_GROUP_FCOMI,
    CDISASM_X86_GROUP_MMX,
    CDISASM_X86_GROUP_SEP,
    CDISASM_X86_GROUP_FXSR,
    CDISASM_X86_GROUP_3DNOW,
    CDISASM_X86_GROUP_3DNOW_EXT,
    CDISASM_X86_GROUP_PREFETCHW,
    CDISASM_X86_GROUP_SSE,
    CDISASM_X86_GROUP_SSE2,
    CDISASM_X86_GROUP_CLFLUSH,
    CDISASM_X86_GROUP_PAUSE,
    CDISASM_X86_GROUP_AMD64,
    CDISASM_X86_GROUP_SSE3,
    CDISASM_X86_GROUP_MONITOR_MWAIT,
    CDISASM_X86_GROUP_VMX,
    CDISASM_X86_GROUP_SVM,
    CDISASM_X86_GROUP_SSSE3,
    CDISASM_X86_GROUP_SSE41,
    CDISASM_X86_GROUP_SSE4A,
    CDISASM_X86_GROUP_LZCNT,
    CDISASM_X86_GROUP_POPCNT,
    CDISASM_X86_GROUP_SSE42,
    CDISASM_X86_GROUP_AESNI,
    CDISASM_X86_GROUP_PCLMULQDQ,
    CDISASM_X86_GROUP_XSAVE,
    CDISASM_X86_GROUP_AVX,
    CDISASM_X86_GROUP_XOP,
    CDISASM_X86_GROUP_FMA4,
    CDISASM_X86_GROUP_TBM,
    CDISASM_X86_GROUP_LWP,
    CDISASM_X86_GROUP_XSAVEOPT,
    CDISASM_X86_GROUP_RDRAND,
    CDISASM_X86_GROUP_F16C,
    CDISASM_X86_GROUP_FSGSBASE,
    CDISASM_X86_GROUP_AVX2,
    CDISASM_X86_GROUP_FMA3,
    CDISASM_X86_GROUP_BMI1,
    CDISASM_X86_GROUP_BMI2,
    CDISASM_X86_GROUP_HLE,
    CDISASM_X86_GROUP_RTM,
    CDISASM_X86_GROUP_MOVBE,
    CDISASM_X86_GROUP_INVPCID,
    CDISASM_X86_GROUP_ADX,
    CDISASM_X86_GROUP_RDSEED,
    CDISASM_X86_GROUP_SGX,
    CDISASM_X86_GROUP_MPX,
    CDISASM_X86_GROUP_CLFLUSHOPT,
    CDISASM_X86_GROUP_XSAVEC,
    CDISASM_X86_GROUP_XSAVES,
    CDISASM_X86_GROUP_SHA,
    CDISASM_X86_GROUP_AVX512F,
    CDISASM_X86_GROUP_AVX512CD,
    CDISASM_X86_GROUP_AVX512ER,
    CDISASM_X86_GROUP_AVX512PF,
    CDISASM_X86_GROUP_AVX512DQ,
    CDISASM_X86_GROUP_AVX512BW,
    CDISASM_X86_GROUP_AVX512VL,
    CDISASM_X86_GROUP_AVX512IFMA,
    CDISASM_X86_GROUP_AVX512VBMI,
    CDISASM_X86_GROUP_AVX512_4VNNIW,
    CDISASM_X86_GROUP_AVX512_4FMAPS,
    CDISASM_X86_GROUP_AVX512VPOPCNTDQ,
    CDISASM_X86_GROUP_AVX512VNNI,
    CDISASM_X86_GROUP_AVX512VBMI2,
    CDISASM_X86_GROUP_GFNI,
    CDISASM_X86_GROUP_VAES,
    CDISASM_X86_GROUP_VPCLMULQDQ,
    CDISASM_X86_GROUP_AVX512BITALG,
    CDISASM_X86_GROUP_AVX512VP2INTERSECT,
    CDISASM_X86_GROUP_CET_IBT,
    CDISASM_X86_GROUP_CET_SS,
    CDISASM_X86_GROUP_AVX_VNNI,
    CDISASM_X86_GROUP_AVX512BF16,
    CDISASM_X86_GROUP_AMX_TILE,
    CDISASM_X86_GROUP_AMX_INT8,
    CDISASM_X86_GROUP_AMX_BF16,
    CDISASM_X86_GROUP_AVX512FP16,
    CDISASM_X86_GROUP_AVX10_1,
    CDISASM_X86_GROUP_AVX10_2,
    CDISASM_X86_GROUP_APX_F,
    CDISASM_X86_GROUP_SMX,
    CDISASM_X86_GROUP_AMX_FP16,
    CDISASM_X86_GROUP_WAITPKG,
    CDISASM_X86_GROUP_SHA512,
    CDISASM_X86_GROUP_SM3,
    CDISASM_X86_GROUP_SM4,
    CDISASM_X86_GROUP_AMX_COMPLEX,
    CDISASM_X86_GROUP_AMX_FP8,
    CDISASM_X86_GROUP_AMX_MOVRS,
    CDISASM_X86_GROUP_AMX_AVX512,
    CDISASM_X86_GROUP_CLWB,
    CDISASM_X86_GROUP_RDPID,
    CDISASM_X86_GROUP_SERIALIZE,
    CDISASM_X86_GROUP_MOVDIRI,
    CDISASM_X86_GROUP_MOVDIR64B,
    CDISASM_X86_GROUP_WBNOINVD,
    CDISASM_X86_GROUP_AVX_VNNI_INT8,
    CDISASM_X86_GROUP_AVX_VNNI_INT16,
    CDISASM_X86_GROUP_PKU,
    CDISASM_X86_GROUP_RDTSCP,
    CDISASM_X86_GROUP_CMPXCHG16B,
    CDISASM_X86_GROUP_UINTR,
    CDISASM_X86_GROUP_TSX_LDTRK,
    CDISASM_X86_GROUP_ENQCMD
};

typedef struct group_alias {
    cdisasm_x86_group_id alias_id;
    cdisasm_x86_group_id canonical_id;
} group_alias;

#define GROUP_ALIAS(alias_, canonical_) {(alias_), (canonical_)}

static const group_alias x86_group_alias_manifest[] = {
    GROUP_ALIAS(CDISASM_X86_GROUP_BASE, CDISASM_X86_GROUP_I86),
    GROUP_ALIAS(CDISASM_X86_GROUP_I8086, CDISASM_X86_GROUP_I86),
    GROUP_ALIAS(CDISASM_X86_GROUP_I80186, CDISASM_X86_GROUP_I186),
    GROUP_ALIAS(CDISASM_X86_GROUP_I80286, CDISASM_X86_GROUP_I286),
    GROUP_ALIAS(CDISASM_X86_GROUP_I80386, CDISASM_X86_GROUP_I386),
    GROUP_ALIAS(CDISASM_X86_GROUP_I80486, CDISASM_X86_GROUP_I486),
    GROUP_ALIAS(CDISASM_X86_GROUP_FPU, CDISASM_X86_GROUP_X87),
    GROUP_ALIAS(CDISASM_X86_GROUP_SYSENTER, CDISASM_X86_GROUP_SEP),
    GROUP_ALIAS(CDISASM_X86_GROUP_FXSAVE, CDISASM_X86_GROUP_FXSR),
    GROUP_ALIAS(CDISASM_X86_GROUP_3DNOWEXT, CDISASM_X86_GROUP_3DNOW_EXT),
    GROUP_ALIAS(CDISASM_X86_GROUP_LONG_MODE, CDISASM_X86_GROUP_AMD64),
    GROUP_ALIAS(CDISASM_X86_GROUP_X86_64, CDISASM_X86_GROUP_AMD64),
    GROUP_ALIAS(CDISASM_X86_GROUP_INTEL_VTX, CDISASM_X86_GROUP_VMX),
    GROUP_ALIAS(CDISASM_X86_GROUP_INTEL_VT_X, CDISASM_X86_GROUP_VMX),
    GROUP_ALIAS(CDISASM_X86_GROUP_AMD_V, CDISASM_X86_GROUP_SVM),
    GROUP_ALIAS(CDISASM_X86_GROUP_SSE1, CDISASM_X86_GROUP_SSE),
    GROUP_ALIAS(CDISASM_X86_GROUP_SSE4_1, CDISASM_X86_GROUP_SSE41),
    GROUP_ALIAS(CDISASM_X86_GROUP_SSE4_2, CDISASM_X86_GROUP_SSE42),
    GROUP_ALIAS(CDISASM_X86_GROUP_AES, CDISASM_X86_GROUP_AESNI),
    GROUP_ALIAS(CDISASM_X86_GROUP_AES_NI, CDISASM_X86_GROUP_AESNI),
    GROUP_ALIAS(CDISASM_X86_GROUP_PCLMUL, CDISASM_X86_GROUP_PCLMULQDQ),
    GROUP_ALIAS(CDISASM_X86_GROUP_FMA, CDISASM_X86_GROUP_FMA3),
    GROUP_ALIAS(CDISASM_X86_GROUP_BMI, CDISASM_X86_GROUP_BMI1),
    GROUP_ALIAS(CDISASM_X86_GROUP_TSX_HLE, CDISASM_X86_GROUP_HLE),
    GROUP_ALIAS(CDISASM_X86_GROUP_TSX_RTM, CDISASM_X86_GROUP_RTM),
    GROUP_ALIAS(CDISASM_X86_GROUP_SHA_NI, CDISASM_X86_GROUP_SHA),
    GROUP_ALIAS(CDISASM_X86_GROUP_SHA_512, CDISASM_X86_GROUP_SHA512),
    GROUP_ALIAS(CDISASM_X86_GROUP_SM_3, CDISASM_X86_GROUP_SM3),
    GROUP_ALIAS(CDISASM_X86_GROUP_SM_4, CDISASM_X86_GROUP_SM4),
    GROUP_ALIAS(CDISASM_X86_GROUP_AVX512, CDISASM_X86_GROUP_AVX512F),
    GROUP_ALIAS(CDISASM_X86_GROUP_AMX, CDISASM_X86_GROUP_AMX_TILE),
    GROUP_ALIAS(CDISASM_X86_GROUP_AVX10, CDISASM_X86_GROUP_AVX10_1),
    GROUP_ALIAS(CDISASM_X86_GROUP_APX, CDISASM_X86_GROUP_APX_F)
};

_Static_assert(
    sizeof(x86_group_id_manifest) / sizeof(x86_group_id_manifest[0])
        == CDISASM_X86_GROUP_ENQCMD + 1u,
    "hand-written x86 group manifest is incomplete");

static cdisasm_instruction single_group_instruction(
    cdisasm_x86_group_id group_id)
{
    cdisasm_instruction instruction;

    memset(&instruction, 0, sizeof(instruction));
    instruction.opcode_size = 1;
    instruction.name_id = CDISASM_X86_NAME_NOP;
    instruction.last_error_id = (uint8_t)CDISASM_STATUS_OK;
    instruction.x86_group_count = 1;
    instruction.x86_group_ids[0] = group_id;
    return instruction;
}

static int group_storage_is_zero(const cdisasm_instruction *instruction)
{
    size_t index;

    if (instruction->x86_group_count != 0
        || instruction->x86_group_reserved != 0) {
        return 0;
    }
    for (index = 0; index < CDISASM_MAX_X86_GROUPS; ++index) {
        if (instruction->x86_group_ids[index] != CDISASM_X86_GROUP_NONE) {
            return 0;
        }
    }
    return 1;
}

static int instruction_is_error_only(
    const cdisasm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0
        && group_storage_is_zero(instruction);
}

static void test_group_catalog(void)
{
    size_t index;

    _Static_assert(sizeof(cdisasm_x86_group_id) == 2,
                   "x86 group IDs must remain 16-bit");
    _Static_assert(CDISASM_X86_GROUP_NONE == 0,
                   "the no-group sentinel changed value");
    _Static_assert(CDISASM_X86_GROUP_FIRST == CDISASM_X86_GROUP_I86,
                   "the first x86 group changed");
    _Static_assert(
        CDISASM_X86_GROUP_LAST == CDISASM_X86_GROUP_WRMSRNS,
                   "the last x86 group changed");
    _Static_assert(
        CDISASM_X86_GROUP_COUNT == CDISASM_X86_GROUP_LAST + 1u,
        "the x86 group range is not contiguous");
    _Static_assert(CDISASM_X86_GROUP_ACE_1
                       == CDISASM_X86_GROUP_ENQCMD + 1u,
                   "generated x86 groups must append after manual groups");
    _Static_assert(CDISASM_X86_GROUP_COUNT == 323,
                   "the pinned exact x86 ISA-set group count changed");

    for (index = 0;
         index < sizeof(x86_group_id_manifest)
             / sizeof(x86_group_id_manifest[0]);
         ++index) {
        EXPECT(x86_group_id_manifest[index] == (cdisasm_x86_group_id)index);
        if (index != 0) {
            EXPECT(x86_group_id_manifest[index]
                > x86_group_id_manifest[index - 1u]);
        }
    }

    /* Retired IDs remain stable and occupy their original catalog slots. */
    _Static_assert(CDISASM_X86_GROUP_3DNOW == 16,
                   "3DNow! group changed value");
    _Static_assert(CDISASM_X86_GROUP_3DNOW_EXT == 17,
                   "extended 3DNow! group changed value");
    _Static_assert(CDISASM_X86_GROUP_XOP == 38,
                   "XOP group changed value");
    _Static_assert(CDISASM_X86_GROUP_FMA4 == 39,
                   "FMA4 group changed value");
    _Static_assert(CDISASM_X86_GROUP_TBM == 40,
                   "TBM group changed value");
    _Static_assert(CDISASM_X86_GROUP_LWP == 41,
                   "LWP group changed value");
    _Static_assert(CDISASM_X86_GROUP_MPX == 57,
                   "MPX group changed value");
}

static void test_group_aliases(void)
{
    size_t index;

    for (index = 0;
         index < sizeof(x86_group_alias_manifest)
             / sizeof(x86_group_alias_manifest[0]);
         ++index) {
        EXPECT(x86_group_alias_manifest[index].alias_id
            == x86_group_alias_manifest[index].canonical_id);
        EXPECT(x86_group_alias_manifest[index].canonical_id
            >= CDISASM_X86_GROUP_FIRST);
        EXPECT(x86_group_alias_manifest[index].canonical_id
            <= CDISASM_X86_GROUP_LAST);
    }
}

static void test_every_group_with_helper(void)
{
    size_t group_index;

    for (group_index = 1;
         group_index < CDISASM_X86_GROUP_COUNT;
         ++group_index) {
        cdisasm_x86_group_id group_id =
            (cdisasm_x86_group_id)group_index;
        cdisasm_instruction instruction = single_group_instruction(group_id);
#if USE_DISASM_FORMAT
        cdisasm_instruction before = instruction;
        char text[8];
#endif
        size_t candidate_index;

        EXPECT(instruction.x86_group_count == 1);
        EXPECT(instruction.x86_group_ids[0] == group_id);
        for (candidate_index = 1;
             candidate_index < CDISASM_X86_GROUP_COUNT;
             ++candidate_index) {
            cdisasm_x86_group_id candidate =
                (cdisasm_x86_group_id)candidate_index;
            EXPECT(cdisasm_instruction_has_x86_group(
                       &instruction,
                       candidate)
                == (candidate == group_id));
        }
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction,
            CDISASM_X86_GROUP_NONE));
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction,
            (cdisasm_x86_group_id)CDISASM_X86_GROUP_COUNT));
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction,
            UINT16_MAX));

#if USE_DISASM_FORMAT
        EXPECT(cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_0, NULL, 0) == 3);
        memset(text, 'X', sizeof(text));
        EXPECT(cdisasm_x86_format(
            &instruction,
            CDISASM_FORMAT_SYNTAX_0,
            text,
            sizeof(text)) == 3);
        EXPECT(strcmp(text, "nop") == 0);
        EXPECT(memcmp(&instruction, &before, sizeof(instruction)) == 0);
#endif
    }
}

#if USE_DISASM_FORMAT
static void expect_formatter_rejects(
    const cdisasm_instruction *instruction)
{
    char text[8];

    EXPECT(cdisasm_x86_format(
        instruction, CDISASM_FORMAT_SYNTAX_0, NULL, 0) == 0);
    memset(text, 'X', sizeof(text));
    EXPECT(cdisasm_x86_format(
        instruction,
        CDISASM_FORMAT_SYNTAX_0,
        text,
        sizeof(text)) == 0);
    EXPECT(text[0] == '\0');
    EXPECT(text[1] == 'X');
}
#endif

static void test_sorted_multi_group_metadata(void)
{
    static const cdisasm_x86_group_id maximum_groups[] = {
        CDISASM_X86_GROUP_I86,
        CDISASM_X86_GROUP_X87,
        CDISASM_X86_GROUP_MMX,
        CDISASM_X86_GROUP_3DNOW,
        CDISASM_X86_GROUP_AMD64,
        CDISASM_X86_GROUP_SSE4A,
        CDISASM_X86_GROUP_AVX,
        CDISASM_X86_GROUP_F16C,
        CDISASM_X86_GROUP_RTM,
        CDISASM_X86_GROUP_CLFLUSHOPT,
        CDISASM_X86_GROUP_AVX512PF,
        CDISASM_X86_GROUP_AVX512_4FMAPS,
        CDISASM_X86_GROUP_AVX512BITALG,
        CDISASM_X86_GROUP_AMX_INT8,
        CDISASM_X86_GROUP_SMX
    };
    cdisasm_instruction instruction =
        single_group_instruction(CDISASM_X86_GROUP_I86);
#if USE_DISASM_FORMAT
    char text[8];
#endif
    size_t index;
    size_t candidate_index;

    _Static_assert(
        sizeof(maximum_groups) / sizeof(maximum_groups[0])
            == CDISASM_MAX_X86_GROUPS,
        "maximum-group test does not fill the public group array");

    memset(instruction.x86_group_ids, 0, sizeof(instruction.x86_group_ids));
    instruction.x86_group_count = CDISASM_MAX_X86_GROUPS;
    for (index = 0;
         index < sizeof(maximum_groups) / sizeof(maximum_groups[0]);
         ++index) {
        instruction.x86_group_ids[index] = maximum_groups[index];
        if (index != 0) {
            EXPECT(maximum_groups[index] > maximum_groups[index - 1u]);
        }
    }

#if USE_DISASM_FORMAT
    EXPECT(cdisasm_x86_format(
        &instruction,
        CDISASM_FORMAT_SYNTAX_0,
        text,
        sizeof(text)) == 3);
    EXPECT(strcmp(text, "nop") == 0);
#endif
    for (candidate_index = 1;
         candidate_index < CDISASM_X86_GROUP_COUNT;
         ++candidate_index) {
        cdisasm_x86_group_id candidate =
            (cdisasm_x86_group_id)candidate_index;
        int expected = 0;

        for (index = 0;
             index < sizeof(maximum_groups) / sizeof(maximum_groups[0]);
             ++index) {
            if (maximum_groups[index] == candidate) {
                expected = 1;
                break;
            }
        }
        EXPECT(cdisasm_instruction_has_x86_group(&instruction, candidate)
            == expected);
    }
}

static void test_malformed_group_metadata(void)
{
    cdisasm_instruction valid =
        single_group_instruction(CDISASM_X86_GROUP_I86);
    cdisasm_instruction malformed;

    EXPECT(!cdisasm_instruction_has_x86_group(
        NULL,
        CDISASM_X86_GROUP_I86));
#if USE_DISASM_FORMAT
    EXPECT(cdisasm_x86_format(
        NULL, CDISASM_FORMAT_SYNTAX_0, NULL, 0) == 0);
    EXPECT(cdisasm_x86_format(
        &valid, CDISASM_FORMAT_SYNTAX_0, NULL, 1) == 0);

    malformed = valid;
    malformed.x86_group_count = 0;
    expect_formatter_rejects(&malformed);

    malformed = valid;
    malformed.x86_group_reserved = 1;
    expect_formatter_rejects(&malformed);
#endif

    malformed = valid;
    malformed.x86_group_count = CDISASM_MAX_X86_GROUPS + 1u;
#if USE_DISASM_FORMAT
    expect_formatter_rejects(&malformed);
#endif
    EXPECT(!cdisasm_instruction_has_x86_group(
        &malformed,
        CDISASM_X86_GROUP_I86));

#if USE_DISASM_FORMAT
    malformed = valid;
    malformed.x86_group_ids[0] = CDISASM_X86_GROUP_NONE;
    expect_formatter_rejects(&malformed);

    malformed = valid;
    malformed.x86_group_ids[0] =
        (cdisasm_x86_group_id)CDISASM_X86_GROUP_COUNT;
    expect_formatter_rejects(&malformed);

    malformed = valid;
    malformed.x86_group_ids[0] = UINT16_MAX;
    expect_formatter_rejects(&malformed);

    malformed = valid;
    malformed.x86_group_count = 2;
    malformed.x86_group_ids[0] = CDISASM_X86_GROUP_I386;
    malformed.x86_group_ids[1] = CDISASM_X86_GROUP_I386;
    expect_formatter_rejects(&malformed);

    malformed = valid;
    malformed.x86_group_count = 2;
    malformed.x86_group_ids[0] = CDISASM_X86_GROUP_AVX;
    malformed.x86_group_ids[1] = CDISASM_X86_GROUP_SSE;
    expect_formatter_rejects(&malformed);

    malformed = valid;
    malformed.x86_group_ids[1] = CDISASM_X86_GROUP_I186;
    expect_formatter_rejects(&malformed);
#endif
}

static void expect_decoded_groups(
    const uint8_t *code,
    size_t code_size,
    cdisasm_mode mode,
    const cdisasm_x86_group_id *expected_groups,
    size_t expected_count)
{
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    size_t index;
    size_t candidate_index;

    memset(&instruction, 0xa5, sizeof(instruction));
    decoded_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        mode,
        code,
        code_size,
        UINT64_C(0x1000),
        CDISASM_X86_TEST_ALL_FLAGS,
        &instruction);

    EXPECT(decoded_size == code_size);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.x86_group_reserved == 0);
    EXPECT(instruction.x86_group_count == expected_count);
    for (index = 0; index < expected_count; ++index) {
        EXPECT(instruction.x86_group_ids[index] == expected_groups[index]);
        if (index != 0) {
            EXPECT(instruction.x86_group_ids[index]
                > instruction.x86_group_ids[index - 1u]);
        }
    }
    for (; index < CDISASM_MAX_X86_GROUPS; ++index) {
        EXPECT(instruction.x86_group_ids[index] == CDISASM_X86_GROUP_NONE);
    }
    for (candidate_index = 1;
         candidate_index < CDISASM_X86_GROUP_COUNT;
         ++candidate_index) {
        cdisasm_x86_group_id candidate =
            (cdisasm_x86_group_id)candidate_index;
        int expected = 0;

        for (index = 0; index < expected_count; ++index) {
            if (expected_groups[index] == candidate) {
                expected = 1;
                break;
            }
        }
        EXPECT(cdisasm_instruction_has_x86_group(&instruction, candidate)
            == expected);
    }
#if USE_DISASM_FORMAT
    EXPECT(cdisasm_x86_format(
        &instruction, CDISASM_FORMAT_SYNTAX_0, NULL, 0) != 0);
#endif
}

static void expect_decode_failure(
    cdisasm_mode mode,
    const uint8_t *code,
    size_t code_size,
    cdisasm_status expected_status)
{
    cdisasm_instruction instruction;
#if USE_DISASM_FORMAT
    char text[8];
#endif

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_X86,
               mode,
               code,
               code_size,
               UINT64_C(0x1000),
               CDISASM_X86_TEST_ALL_FLAGS,
               &instruction)
        == 0);
    EXPECT(instruction_is_error_only(&instruction, expected_status));
#if USE_DISASM_FORMAT
    EXPECT(cdisasm_x86_format(
        &instruction,
        CDISASM_FORMAT_SYNTAX_0,
        text,
        sizeof(text)) == 0);
    EXPECT(text[0] == '\0');
#endif
}

static void test_decoder_group_invariants(void)
{
    static const uint8_t nop[] = {0x90};
    static const cdisasm_x86_group_id nop_groups[] = {
        CDISASM_X86_GROUP_I86
    };
    static const uint8_t xadd[] = {0x0f, 0xc1, 0xc0};
    static const cdisasm_x86_group_id xadd_groups[] = {
        CDISASM_X86_GROUP_I386,
        CDISASM_X86_GROUP_I486
    };
    static const uint8_t pause[] = {0xf3, 0x90};
    static const cdisasm_x86_group_id pause_groups[] = {
        CDISASM_X86_GROUP_SSE2,
        CDISASM_X86_GROUP_PAUSE
    };
    static const uint8_t cmove[] = {0x0f, 0x44, 0xc0};
    static const cdisasm_x86_group_id cmove_groups[] = {
        CDISASM_X86_GROUP_I386,
        CDISASM_X86_GROUP_P6,
        CDISASM_X86_GROUP_CMOV
    };
    static const uint8_t truncated[] = {0x0f};
    static const uint8_t retired_3dnow[] = {0x0f, 0x0f, 0xc0, 0xbf};
    static const cdisasm_x86_group_id retired_3dnow_groups[] = {
        CDISASM_X86_GROUP_3DNOW
    };
    static const uint8_t vzeroupper[] = {0xc5, 0xf8, 0x77};
    static const cdisasm_x86_group_id vzeroupper_groups[] = {
        CDISASM_X86_GROUP_AVX
    };
    cdisasm_instruction instruction;

    expect_decoded_groups(
        nop,
        sizeof(nop),
        CDISASM_MODE_16,
        nop_groups,
        sizeof(nop_groups) / sizeof(nop_groups[0]));
    expect_decoded_groups(
        xadd,
        sizeof(xadd),
        CDISASM_MODE_32,
        xadd_groups,
        sizeof(xadd_groups) / sizeof(xadd_groups[0]));
    expect_decoded_groups(
        pause,
        sizeof(pause),
        CDISASM_MODE_64,
        pause_groups,
        sizeof(pause_groups) / sizeof(pause_groups[0]));
    expect_decoded_groups(
        cmove,
        sizeof(cmove),
        CDISASM_MODE_32,
        cmove_groups,
        sizeof(cmove_groups) / sizeof(cmove_groups[0]));
    expect_decoded_groups(
        retired_3dnow,
        sizeof(retired_3dnow),
        CDISASM_MODE_64,
        retired_3dnow_groups,
        sizeof(retired_3dnow_groups) / sizeof(retired_3dnow_groups[0]));
    expect_decoded_groups(
        vzeroupper,
        sizeof(vzeroupper),
        CDISASM_MODE_64,
        vzeroupper_groups,
        sizeof(vzeroupper_groups) / sizeof(vzeroupper_groups[0]));

    expect_decode_failure(
        CDISASM_MODE_64,
        truncated,
        sizeof(truncated),
        CDISASM_STATUS_TRUNCATED);
    expect_decode_failure(
        CDISASM_MODE_64,
        NULL,
        0,
        CDISASM_STATUS_END_OF_INPUT);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_X86,
               (cdisasm_mode)0,
               nop,
               sizeof(nop),
               0,
               CDISASM_X86_TEST_ALL_FLAGS,
               &instruction)
        == 0);
    EXPECT(instruction_is_error_only(
        &instruction,
        CDISASM_STATUS_INVALID_ARGUMENT));
}

int main(void)
{
    test_group_catalog();
    test_group_aliases();
    test_every_group_with_helper();
    test_sorted_multi_group_metadata();
    test_malformed_group_metadata();
    test_decoder_group_invariants();

    if (failures != 0) {
        fprintf(stderr, "%d x86 group test(s) failed\n", failures);
        return 1;
    }
    puts("all x86 group tests passed");
    return 0;
}
