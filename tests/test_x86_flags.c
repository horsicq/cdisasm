#include "cdisasm/cdisasm.h"

#include <stdio.h>
#include <string.h>

_Static_assert(sizeof(cdisasm_decode_option) == 8,
               "generic bitmap-word ABI width changed");
_Static_assert(sizeof(cdisasm_decode_flags) == 64,
               "generic decode flags must remain 64 bytes");
_Static_assert(sizeof(cdisasm_x86_decode_flags)
                   == sizeof(cdisasm_decode_flags),
               "x86 and generic decode flags must have the same size");
_Static_assert(CDISASM_DECODE_FLAGS_BITMAP_COUNT == 8,
               "decode flags must contain eight bitmap words");
_Static_assert(sizeof(cdisasm_x86_decode_option) == 8,
               "x86 bitmap-word ABI width changed");
_Static_assert(sizeof(cdisasm_decode2_option) == 8,
               "legacy x86 decode-option alias width changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_BASE == UINT64_C(0x00000000),
               "x86 base flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_FPU == UINT64_C(0x00000001),
               "x86 FPU flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_MMX == UINT64_C(0x00000002),
               "x86 MMX flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_3DNOW == UINT64_C(0x00000004),
               "x86 3DNow flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_SSE == UINT64_C(0x00000008),
               "x86 SSE flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_SSE2 == UINT64_C(0x00000010),
               "x86 SSE2 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_SSE3 == UINT64_C(0x00000020),
               "x86 SSE3 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_SSSE3 == UINT64_C(0x00000040),
               "x86 SSSE3 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_SSE4 == UINT64_C(0x00000080),
               "x86 SSE4 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX == UINT64_C(0x00000100),
               "x86 AVX flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX2 == UINT64_C(0x00000200),
               "x86 AVX2 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_F16C == UINT64_C(0x00000400),
               "x86 F16C flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_FMA3 == UINT64_C(0x00000800),
               "x86 FMA3 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_XOP == UINT64_C(0x00001000),
               "x86 XOP flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_FMA4 == UINT64_C(0x00002000),
               "x86 FMA4 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AES == UINT64_C(0x00004000),
               "x86 AES flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_PCLMUL == UINT64_C(0x00008000),
               "x86 PCLMUL flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_SHA == UINT64_C(0x00010000),
               "x86 SHA flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_GFNI == UINT64_C(0x00020000),
               "x86 GFNI flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_BITMANIP == UINT64_C(0x00040000),
               "x86 bit-manipulation flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX512 == UINT64_C(0x00080000),
               "x86 AVX-512 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX10 == UINT64_C(0x00100000),
               "x86 AVX10 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AMX == UINT64_C(0x00200000),
               "x86 AMX flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_APX == UINT64_C(0x00400000),
               "x86 APX flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_SMX == UINT64_C(0x00800000),
               "x86 SMX flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_VIRTUALIZATION
                   == CDISASM_X86_DECODE_FLAG_SMX,
               "legacy x86 virtualization alias changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_SYSTEM == UINT64_C(0x01000000),
               "x86 system flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_CET == UINT64_C(0x02000000),
               "x86 CET flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_STATE == UINT64_C(0x04000000),
               "x86 state flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_TRANSACTIONAL == UINT64_C(0x08000000),
               "x86 transactional flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_SECURITY == UINT64_C(0x10000000),
               "x86 security flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_MEMORY_HINTS == UINT64_C(0x20000000),
               "x86 memory-hint flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_UNDOCUMENTED == UINT64_C(0x40000000),
               "x86 undocumented flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_SM3 == UINT64_C(0x080000000),
               "x86 SM3 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_SM4 == UINT64_C(0x100000000),
               "x86 SM4 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX512_VBMI2
                   == UINT64_C(0x200000000),
               "x86 AVX512_VBMI2 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ
                   == UINT64_C(0x400000000),
               "x86 AVX512_VPOPCNTDQ flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX512_BITALG
                   == UINT64_C(0x800000000),
               "x86 AVX512_BITALG flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND
                   == UINT64_C(0x1000000000),
               "x86 compress/expand flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX512_IFMA
                   == UINT64_C(0x2000000000),
               "x86 AVX512_IFMA flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX512_VBMI
                   == UINT64_C(0x4000000000),
               "x86 AVX512_VBMI flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX512_VNNI
                   == UINT64_C(0x8000000000),
               "x86 AVX512_VNNI flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_VAES
                   == UINT64_C(0x10000000000),
               "x86 VAES flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_VPCLMULQDQ
                   == UINT64_C(0x20000000000),
               "x86 VPCLMULQDQ flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_SHA512
                   == UINT64_C(0x40000000000),
               "x86 SHA512 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AMX_TILE
                   == UINT64_C(0x80000000000),
               "x86 AMX_TILE flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AMX_INT8
                   == UINT64_C(0x100000000000),
               "x86 AMX_INT8 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AMX_BF16
                   == UINT64_C(0x200000000000),
               "x86 AMX_BF16 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AMX_FP16
                   == UINT64_C(0x400000000000),
               "x86 AMX_FP16 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AMX_COMPLEX
                   == UINT64_C(0x800000000000),
               "x86 AMX_COMPLEX flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AMX_FP8
                   == UINT64_C(0x1000000000000),
               "x86 AMX_FP8 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AMX_MOVRS
                   == UINT64_C(0x2000000000000),
               "x86 AMX_MOVRS flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AMX_AVX512
                   == UINT64_C(0x4000000000000),
               "x86 AMX_AVX512 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX512_DQ
                   == UINT64_C(0x8000000000000),
               "x86 AVX512_DQ flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX512_BW
                   == UINT64_C(0x10000000000000),
               "x86 AVX512_BW flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_VMX
                   == UINT64_C(0x20000000000000),
               "x86 VMX flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_SVM
                   == UINT64_C(0x40000000000000),
               "x86 SVM flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_INTEL_VIRTUALIZATION
                   == CDISASM_X86_DECODE_FLAG_VMX,
               "Intel virtualization alias changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AMD_VIRTUALIZATION
                   == CDISASM_X86_DECODE_FLAG_SVM,
               "AMD virtualization alias changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_SSE41
                   == UINT64_C(0x80000000000000),
               "x86 SSE41 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_SSE42
                   == UINT64_C(0x100000000000000),
               "x86 SSE42 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_SSE4A
                   == UINT64_C(0x200000000000000),
               "x86 SSE4A flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_BMI1
                   == UINT64_C(0x400000000000000),
               "x86 BMI1 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_BMI2
                   == UINT64_C(0x800000000000000),
               "x86 BMI2 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX512_CD
                   == UINT64_C(0x1000000000000000),
               "x86 AVX512_CD flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX_VNNI
                   == UINT64_C(0x2000000000000000),
               "x86 AVX_VNNI flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT8
                   == UINT64_C(0x4000000000000000),
               "x86 AVX_VNNI_INT8 flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16
                   == UINT64_C(0x8000000000000000),
               "x86 AVX_VNNI_INT16 flag changed");
_Static_assert((UINT64_C(1) << CDISASM_X86_DECODE_BIT_FPU)
                   == CDISASM_X86_DECODE_FLAG_FPU,
               "x86 FPU bit ID and bitmap-0 mask differ");
_Static_assert((UINT64_C(1) << CDISASM_X86_DECODE_BIT_AVX)
                   == CDISASM_X86_DECODE_FLAG_AVX,
               "x86 AVX bit ID and bitmap-0 mask differ");
_Static_assert((UINT64_C(1) << CDISASM_X86_DECODE_BIT_VMX)
                   == CDISASM_X86_DECODE_FLAG_VMX,
               "x86 VMX bit ID and bitmap-0 mask differ");
_Static_assert((UINT64_C(1) << CDISASM_X86_DECODE_BIT_AVX_VNNI_INT16)
                   == CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16,
               "x86 highest legacy bit ID and bitmap-0 mask differ");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX_VNNI_INT16 == UINT32_C(63),
               "legacy x86 flags must end in bitmap word 0");
_Static_assert(CDISASM_X86_DECODE_BIT_COUNT == UINT32_C(271),
               "pinned exact x86 ISA-set flag count changed");
_Static_assert(CDISASM_X86_DECODE_BIT_LAST
                   == CDISASM_X86_DECODE_BIT_SSE4_ISA_SET,
               "pinned exact x86 ISA-set flag endpoint changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_ALL
                   == UINT64_C(0xffffffffffffffff),
               "x86 all-family mask changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_KNOWN_MASK
                   == UINT64_C(0xffffffffffffffff),
               "x86 known-family mask changed");
_Static_assert(CDISASM_X86_DECODE_OPTION_NONE == UINT64_C(0),
               "x86 NONE option must remain base-only zero");
_Static_assert(CDISASM_X86_DECODE_OPTION_ALL
                   == CDISASM_X86_DECODE_FLAG_ALL,
               "x86 ALL option alias changed");
_Static_assert(CDISASM_X86_MODE_MASK_NONE == UINT32_C(0x00),
               "x86 no-mode mask changed");
_Static_assert(CDISASM_X86_MODE_MASK_16 == UINT32_C(0x01),
               "x86 16-bit mode mask changed");
_Static_assert(CDISASM_X86_MODE_MASK_32 == UINT32_C(0x02),
               "x86 32-bit mode mask changed");
_Static_assert(CDISASM_X86_MODE_MASK_64 == UINT32_C(0x04),
               "x86 64-bit mode mask changed");

typedef struct flag_case {
    const char *label;
    cdisasm_cpu_id cpu_id;
    cdisasm_mode mode;
    const uint8_t *bytes;
    size_t size;
    cdisasm_x86_decode_option flag;
    cdisasm_x86_name_id name_id;
} flag_case;

static int failures;

#define EXPECT(condition) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "%s:%d: expectation failed: %s\n", \
                    __FILE__, __LINE__, #condition); \
            ++failures; \
        } \
    } while (0)

static int is_error_only(
    const cdisasm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static void test_flag_set_contract(void)
{
    static const uint8_t nop[] = {UINT8_C(0x90)};
#if USE_EXTRA_OPCODES
    static const uint64_t known_masks[CDISASM_DECODE_FLAGS_BITMAP_COUNT] = {
        CDISASM_X86_DECODE_FLAG_KNOWN_MASK_0,
        CDISASM_X86_DECODE_FLAG_KNOWN_MASK_1,
        CDISASM_X86_DECODE_FLAG_KNOWN_MASK_2,
        CDISASM_X86_DECODE_FLAG_KNOWN_MASK_3,
        CDISASM_X86_DECODE_FLAG_KNOWN_MASK_4,
        CDISASM_X86_DECODE_FLAG_KNOWN_MASK_5,
        CDISASM_X86_DECODE_FLAG_KNOWN_MASK_6,
        CDISASM_X86_DECODE_FLAG_KNOWN_MASK_7
    };
#endif
    cdisasm_x86_decode_flags flags;
    cdisasm_x86_decode_flags before_invalid_bit;
    cdisasm_x86_decode_flags available;
    cdisasm_instruction null_instruction;
    cdisasm_instruction zero_instruction;
    size_t bitmap_index;

    memset(&flags, 0xa5, sizeof(flags));
    cdisasm_decode_flags_reset(&flags);
    for (bitmap_index = 0;
         bitmap_index < CDISASM_DECODE_FLAGS_BITMAP_COUNT;
         ++bitmap_index) {
        EXPECT(flags.bitmap[bitmap_index] == UINT64_C(0));
    }
    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_FPU));
    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_AVX_VNNI_INT16));
    EXPECT(flags.bitmap[0]
        == (CDISASM_X86_DECODE_FLAG_FPU
            | CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16));
    EXPECT(cdisasm_decode_flags_test_bit(
        &flags, CDISASM_X86_DECODE_BIT_FPU));
    EXPECT(cdisasm_decode_flags_set_bit(&flags, UINT32_C(64)));
    EXPECT(flags.bitmap[1] == UINT64_C(1));
    EXPECT(cdisasm_decode_flags_test_bit(&flags, UINT32_C(64)));
    EXPECT(cdisasm_decode_flags_clear_bit(&flags, UINT32_C(64)));
    EXPECT(flags.bitmap[1] == UINT64_C(0));
    EXPECT(!cdisasm_decode_flags_test_bit(&flags, UINT32_C(64)));
    before_invalid_bit = flags;
    EXPECT(!cdisasm_decode_flags_set_bit(
        &flags, CDISASM_DECODE_FLAGS_BIT_CAPACITY));
    EXPECT(!cdisasm_decode_flags_clear_bit(
        &flags, CDISASM_DECODE_FLAGS_BIT_CAPACITY));
    EXPECT(!cdisasm_decode_flags_test_bit(
        &flags, CDISASM_DECODE_FLAGS_BIT_CAPACITY));
    EXPECT(memcmp(&flags, &before_invalid_bit, sizeof(flags)) == 0);
    EXPECT(!cdisasm_decode_flags_set_bit(NULL, UINT32_C(0)));
    EXPECT(!cdisasm_decode_flags_clear_bit(NULL, UINT32_C(0)));
    EXPECT(!cdisasm_decode_flags_test_bit(NULL, UINT32_C(0)));

    memset(&available, 0xa5, sizeof(available));
    EXPECT((cdisasm_x86_cpu_decode_flag_mask)(
               CDISASM_CPU_X86, CDISASM_MODE_64, &available)
        == CDISASM_STATUS_OK);
#if USE_EXTRA_OPCODES
    EXPECT(available.bitmap[0] == known_masks[0]);
    EXPECT(available.bitmap[1]
        == (known_masks[1]
            & ~(UINT64_C(1)
                << (CDISASM_X86_DECODE_BIT_AMD % UINT32_C(64)))));
    EXPECT(available.bitmap[2] == known_masks[2]);
    EXPECT(available.bitmap[3] == known_masks[3]);
    EXPECT(available.bitmap[4] == known_masks[4]);
    EXPECT(available.bitmap[5] == known_masks[5]);
    EXPECT(available.bitmap[6] == known_masks[6]);
    EXPECT(available.bitmap[7] == known_masks[7]);
    EXPECT(cdisasm_decode_flags_test_bit(
        &available, CDISASM_X86_DECODE_BIT_AVX512F_512));
    EXPECT(cdisasm_decode_flags_test_bit(
        &available, CDISASM_X86_DECODE_BIT_SSE4_ISA_SET));
#else
    for (bitmap_index = 0;
         bitmap_index < CDISASM_DECODE_FLAGS_BITMAP_COUNT;
         ++bitmap_index) {
        EXPECT(available.bitmap[bitmap_index] == UINT64_C(0));
    }
#endif
    memset(&available, 0xa5, sizeof(available));
    EXPECT((cdisasm_x86_cpu_decode_flag_mask)(
               CDISASM_CPU_8086, CDISASM_MODE_32, &available)
        == CDISASM_STATUS_INVALID_ARGUMENT);
    for (bitmap_index = 0;
         bitmap_index < CDISASM_DECODE_FLAGS_BITMAP_COUNT;
         ++bitmap_index) {
        EXPECT(available.bitmap[bitmap_index] == UINT64_C(0));
    }
    EXPECT((cdisasm_x86_cpu_decode_flag_mask)(
               CDISASM_CPU_X86, CDISASM_MODE_64, NULL)
        == CDISASM_STATUS_INVALID_ARGUMENT);

    cdisasm_decode_flags_reset(&flags);
    memset(&null_instruction, 0xa5, sizeof(null_instruction));
    memset(&zero_instruction, 0x5a, sizeof(zero_instruction));
    EXPECT((cdisasm_x86_decode)(
               CDISASM_CPU_80386, CDISASM_MODE_32, nop, sizeof(nop),
               UINT64_C(0x1000), NULL, &null_instruction)
        == sizeof(nop));
    EXPECT((cdisasm_x86_decode)(
               CDISASM_CPU_80386, CDISASM_MODE_32, nop, sizeof(nop),
               UINT64_C(0x1000), &flags, &zero_instruction)
        == sizeof(nop));
    EXPECT(memcmp(&null_instruction, &zero_instruction,
                  sizeof(null_instruction)) == 0);

    cdisasm_decode_flags_reset(&flags);
    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_COUNT));
    memset(&zero_instruction, 0xa5, sizeof(zero_instruction));
    EXPECT((cdisasm_x86_decode)(
               CDISASM_CPU_X86, CDISASM_MODE_64, nop, sizeof(nop),
               UINT64_C(0), &flags, &zero_instruction)
        == 0);
    EXPECT(is_error_only(
        &zero_instruction, CDISASM_STATUS_INVALID_ARGUMENT));
}

#if USE_EXTRA_OPCODES
static void test_ace_exact_flag_contract(void)
{
    static const uint8_t tilemovrow[] = {
        UINT8_C(0x62), UINT8_C(0xf2), UINT8_C(0xfd),
        UINT8_C(0x48), UINT8_C(0x4a), UINT8_C(0xc1)
    };
    static const uint8_t tilemovrow_b4[] = {
        UINT8_C(0x62), UINT8_C(0xfa), UINT8_C(0xfd),
        UINT8_C(0x48), UINT8_C(0x4a), UINT8_C(0xc1)
    };
    static const uint8_t amx_avx512_tilemovrow[] = {
        UINT8_C(0x62), UINT8_C(0xf2), UINT8_C(0x7d),
        UINT8_C(0x48), UINT8_C(0x4a), UINT8_C(0xc1)
    };
    cdisasm_x86_decode_flags flags;
    cdisasm_instruction instruction;

    cdisasm_decode_flags_reset(&flags);
    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_ACE_1));
    EXPECT((cdisasm_x86_decode)(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        tilemovrow, sizeof(tilemovrow), UINT64_C(0),
        &flags, &instruction) == sizeof(tilemovrow));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_TILEMOVROW);
    EXPECT(instruction.form_id == UINT16_C(3301));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_ACE_1));

    EXPECT((cdisasm_x86_decode)(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        amx_avx512_tilemovrow, sizeof(amx_avx512_tilemovrow),
        UINT64_C(0), &flags, &instruction) == 0);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));

    EXPECT((cdisasm_x86_decode)(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        tilemovrow_b4, sizeof(tilemovrow_b4), UINT64_C(0),
        &flags, &instruction) == 0);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
    flags.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP] |=
        CDISASM_X86_DECODE_FLAG_APX;
    EXPECT((cdisasm_x86_decode)(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        tilemovrow_b4, sizeof(tilemovrow_b4), UINT64_C(0),
        &flags, &instruction) == sizeof(tilemovrow_b4));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_ACE_1));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F));

    EXPECT((cdisasm_x86_decode)(
        CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
        tilemovrow, sizeof(tilemovrow), UINT64_C(0),
        &flags, &instruction) == 0);
    EXPECT(is_error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));

    cdisasm_decode_flags_reset(&flags);
    flags.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP] =
        CDISASM_X86_DECODE_FLAG_AMX;
    EXPECT((cdisasm_x86_decode)(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        tilemovrow, sizeof(tilemovrow), UINT64_C(0),
        &flags, &instruction) == sizeof(tilemovrow));

    cdisasm_decode_flags_reset(&flags);
    EXPECT((cdisasm_x86_decode)(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        tilemovrow, sizeof(tilemovrow), UINT64_C(0),
        NULL, &instruction) == 0);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
}
#endif

static cdisasm_x86_decode_option query_word0(
    cdisasm_x86_cpu_id cpu_id,
    cdisasm_x86_mode mode)
{
    cdisasm_x86_decode_flags flags;

    memset(&flags, 0xa5, sizeof(flags));
    (void)(cdisasm_x86_cpu_decode_flag_mask)(cpu_id, mode, &flags);
    return flags.bitmap[0];
}

static uint32_t decode_word0(
    cdisasm_x86_cpu_id cpu_id,
    cdisasm_x86_mode mode,
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    cdisasm_x86_decode_option word0,
    cdisasm_instruction *instruction)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_INITIALIZER(word0);

    return (cdisasm_x86_decode)(
        cpu_id, mode, code, code_size, address,
        word0 == CDISASM_X86_DECODE_FLAG_BASE ? NULL : &flags,
        instruction);
}

#define cdisasm_x86_cpu_decode_flag_mask(cpu_id_, mode_) \
    query_word0((cpu_id_), (mode_))
#define cdisasm_x86_decode(                                        \
    cpu_id_, mode_, code_, code_size_, address_, word0_, result_) \
    decode_word0((cpu_id_), (mode_), (code_), (code_size_),        \
                 (address_), (word0_), (result_))

static uint32_t decode_case(
    const flag_case *test_case,
    cdisasm_x86_decode_option flags,
    cdisasm_instruction *instruction)
{
    return cdisasm_x86_decode(
        test_case->cpu_id,
        test_case->mode,
        test_case->bytes,
        test_case->size,
        UINT64_C(0x1000),
        flags,
        instruction);
}

static void test_cpu_queries(void)
{
    static const cdisasm_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    static const cdisasm_x86_mode_mask mode_bits[] = {
        CDISASM_X86_MODE_MASK_16,
        CDISASM_X86_MODE_MASK_32,
        CDISASM_X86_MODE_MASK_64
    };
    const cdisasm_x86_mode_mask all_modes =
        CDISASM_X86_MODE_MASK_16
        | CDISASM_X86_MODE_MASK_32
        | CDISASM_X86_MODE_MASK_64;
    uint32_t ordinal;
    size_t mode_index;

    EXPECT(cdisasm_x86_cpu_mode_mask(CDISASM_CPU_X86) == all_modes);
    EXPECT(cdisasm_x86_cpu_mode_mask(CDISASM_CPU_8086)
        == CDISASM_X86_MODE_MASK_16);
    EXPECT(cdisasm_x86_cpu_mode_mask(CDISASM_CPU_80286)
        == CDISASM_X86_MODE_MASK_16);
    EXPECT(cdisasm_x86_cpu_mode_mask(CDISASM_CPU_80386)
        == (CDISASM_X86_MODE_MASK_16 | CDISASM_X86_MODE_MASK_32));
    EXPECT(cdisasm_x86_cpu_mode_mask(CDISASM_CPU_ATHLON_64)
        == all_modes);
    EXPECT(cdisasm_x86_cpu_mode_mask(CDISASM_CPU_CELERON_N4020)
        == all_modes);
    EXPECT(cdisasm_x86_cpu_mode_mask(CDISASM_CPU_8086_8087)
        == CDISASM_X86_MODE_MASK_16);
    EXPECT(cdisasm_x86_cpu_mode_mask(CDISASM_CPU_80386_80387)
        == (CDISASM_X86_MODE_MASK_16 | CDISASM_X86_MODE_MASK_32));
    EXPECT(cdisasm_x86_cpu_mode_mask(CDISASM_CPU_GRANITE_RAPIDS)
        == all_modes);
    EXPECT(cdisasm_x86_cpu_mode_mask(CDISASM_CPU_ARROW_LAKE)
        == all_modes);
    EXPECT(cdisasm_x86_cpu_mode_mask(CDISASM_CPU_DIAMOND_RAPIDS)
        == all_modes);
    EXPECT(cdisasm_x86_cpu_mode_mask(CDISASM_CPU_KNIGHTS_MILL)
        == all_modes);
    EXPECT(cdisasm_x86_cpu_mode_mask(CDISASM_CPU_LAST + UINT32_C(1))
        == CDISASM_X86_MODE_MASK_NONE);
    EXPECT(cdisasm_x86_cpu_mode_mask(CDISASM_CPU_GROUP_ARM)
        == CDISASM_X86_MODE_MASK_NONE);
    EXPECT(cdisasm_x86_cpu_mode_mask(UINT32_C(0))
        == CDISASM_X86_MODE_MASK_NONE);
    EXPECT(cdisasm_x86_cpu_mode_mask(UINT32_MAX)
        == CDISASM_X86_MODE_MASK_NONE);

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
               CDISASM_CPU_8086, CDISASM_MODE_32)
        == CDISASM_X86_DECODE_FLAG_BASE);
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
               CDISASM_CPU_8086, UINT32_C(0))
        == CDISASM_X86_DECODE_FLAG_BASE);
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
               CDISASM_CPU_8086, UINT32_C(1))
        == CDISASM_X86_DECODE_FLAG_BASE);
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
               CDISASM_CPU_GROUP_ARM, CDISASM_MODE_16)
        == CDISASM_X86_DECODE_FLAG_BASE);
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
               CDISASM_CPU_LAST + UINT32_C(1), CDISASM_MODE_64)
        == CDISASM_X86_DECODE_FLAG_BASE);

    for (ordinal = UINT32_C(0);
         ordinal <= CDISASM_CPU_ORDINAL_OF(CDISASM_CPU_LAST);
         ++ordinal) {
        const cdisasm_cpu_id cpu_id = CDISASM_CPU_GROUP_X86 | ordinal;
        const cdisasm_x86_mode_mask cpu_modes =
            cdisasm_x86_cpu_mode_mask(cpu_id);

        EXPECT(cpu_modes != CDISASM_X86_MODE_MASK_NONE);
        EXPECT((cpu_modes & ~all_modes) == 0);
        for (mode_index = 0;
             mode_index < sizeof(modes) / sizeof(modes[0]);
             ++mode_index) {
            const cdisasm_x86_decode_option flags =
                cdisasm_x86_cpu_decode_flag_mask(
                    cpu_id, modes[mode_index]);

            EXPECT((flags & ~CDISASM_X86_DECODE_FLAG_KNOWN_MASK) == 0);
            if ((cpu_modes & mode_bits[mode_index]) == 0) {
                EXPECT(flags == CDISASM_X86_DECODE_FLAG_BASE);
            }
#if !USE_EXTRA_OPCODES
            EXPECT(flags == CDISASM_X86_DECODE_FLAG_BASE);
#endif
        }
    }

#if USE_EXTRA_OPCODES
    {
        const cdisasm_x86_decode_option unrestricted64 =
            cdisasm_x86_cpu_decode_flag_mask(
                CDISASM_CPU_X86, CDISASM_MODE_64);
        const cdisasm_x86_decode_option unrestricted32 =
            cdisasm_x86_cpu_decode_flag_mask(
                CDISASM_CPU_X86, CDISASM_MODE_32);
        const cdisasm_x86_decode_option cpu8086 =
            cdisasm_x86_cpu_decode_flag_mask(
                CDISASM_CPU_8086, CDISASM_MODE_16);
        const cdisasm_x86_decode_option cpu8087 =
            cdisasm_x86_cpu_decode_flag_mask(
                CDISASM_CPU_8086_8087, CDISASM_MODE_16);
        const cdisasm_x86_decode_option k6 =
            cdisasm_x86_cpu_decode_flag_mask(
                CDISASM_CPU_AMD_K6_2, CDISASM_MODE_32);
        const cdisasm_x86_decode_option bulldozer =
            cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_AMD_BULLDOZER, CDISASM_MODE_64);
        const cdisasm_x86_decode_option zen =
            cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_AMD_ZEN, CDISASM_MODE_64);
        const cdisasm_x86_decode_option westmere =
            cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_WESTMERE, CDISASM_MODE_64);
        const cdisasm_x86_decode_option ivy =
            cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_IVY_BRIDGE, CDISASM_MODE_64);
        const cdisasm_x86_decode_option haswell =
            cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_HASWELL, CDISASM_MODE_64);
        const cdisasm_x86_decode_option celeron =
            cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_CELERON_N4020, CDISASM_MODE_64);
        const cdisasm_x86_decode_option skylake_sp =
            cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64);
        const cdisasm_x86_decode_option ice_lake =
            cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64);
        const cdisasm_x86_decode_option tiger_lake =
            cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_TIGER_LAKE, CDISASM_MODE_64);
        const cdisasm_x86_decode_option alder_lake =
            cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_ALDER_LAKE, CDISASM_MODE_64);
        const cdisasm_x86_decode_option arrow_lake =
            cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_ARROW_LAKE, CDISASM_MODE_64);
        const cdisasm_x86_decode_option sapphire64 =
            cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_MODE_64);
        const cdisasm_x86_decode_option sapphire32 =
            cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_MODE_32);
        const cdisasm_x86_decode_option granite64 =
            cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_GRANITE_RAPIDS, CDISASM_MODE_64);
        const cdisasm_x86_decode_option granite32 =
            cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_GRANITE_RAPIDS, CDISASM_MODE_32);
        const cdisasm_x86_decode_option avx10_64 =
            cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_AVX10, CDISASM_MODE_64);
        const cdisasm_x86_decode_option apx64 =
            cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_APX, CDISASM_MODE_64);
        const cdisasm_x86_decode_option apx32 =
            cdisasm_x86_cpu_decode_flag_mask(
                CDISASM_CPU_APX, CDISASM_MODE_32);

        EXPECT(unrestricted64 == CDISASM_X86_DECODE_FLAG_ALL);
        EXPECT((unrestricted32
                & (CDISASM_X86_DECODE_FLAG_AMX
                    | CDISASM_X86_DECODE_FLAG_APX)) == 0);
        EXPECT((cpu8086 & (CDISASM_X86_DECODE_FLAG_SYSTEM
                          | CDISASM_X86_DECODE_FLAG_UNDOCUMENTED))
            == (CDISASM_X86_DECODE_FLAG_SYSTEM
                | CDISASM_X86_DECODE_FLAG_UNDOCUMENTED));
        EXPECT((cpu8086 & CDISASM_X86_DECODE_FLAG_FPU) == 0);
        EXPECT((cpu8087 & CDISASM_X86_DECODE_FLAG_FPU) != 0);
        EXPECT((k6 & CDISASM_X86_DECODE_FLAG_3DNOW) != 0);
        EXPECT((k6 & CDISASM_X86_DECODE_FLAG_SSE) == 0);
        EXPECT((bulldozer & (CDISASM_X86_DECODE_FLAG_XOP
                            | CDISASM_X86_DECODE_FLAG_FMA4))
            == (CDISASM_X86_DECODE_FLAG_XOP
                | CDISASM_X86_DECODE_FLAG_FMA4));
        EXPECT((bulldozer & CDISASM_X86_DECODE_FLAG_3DNOW) == 0);
        EXPECT((zen & (CDISASM_X86_DECODE_FLAG_XOP
                      | CDISASM_X86_DECODE_FLAG_FMA4)) == 0);
        EXPECT((westmere & (CDISASM_X86_DECODE_FLAG_AES
                            | CDISASM_X86_DECODE_FLAG_PCLMUL))
            == (CDISASM_X86_DECODE_FLAG_AES
                | CDISASM_X86_DECODE_FLAG_PCLMUL));
        EXPECT((westmere & CDISASM_X86_DECODE_FLAG_AVX) == 0);
        EXPECT((westmere & CDISASM_X86_DECODE_FLAG_SECURITY) == 0);
        EXPECT((ivy & CDISASM_X86_DECODE_FLAG_SECURITY) != 0);
        EXPECT((ivy & CDISASM_X86_DECODE_FLAG_TRANSACTIONAL) == 0);
        EXPECT((haswell & (CDISASM_X86_DECODE_FLAG_SECURITY
                          | CDISASM_X86_DECODE_FLAG_TRANSACTIONAL))
            == (CDISASM_X86_DECODE_FLAG_SECURITY
                | CDISASM_X86_DECODE_FLAG_TRANSACTIONAL));
        EXPECT((celeron & (CDISASM_X86_DECODE_FLAG_AVX
                          | CDISASM_X86_DECODE_FLAG_AVX2)) == 0);
        EXPECT((celeron & (CDISASM_X86_DECODE_FLAG_AES
                          | CDISASM_X86_DECODE_FLAG_SHA))
            == (CDISASM_X86_DECODE_FLAG_AES
                | CDISASM_X86_DECODE_FLAG_SHA));
        EXPECT((celeron & CDISASM_X86_DECODE_FLAG_SECURITY) != 0);
        EXPECT((skylake_sp & CDISASM_X86_DECODE_FLAG_AVX512) != 0);
        EXPECT((ice_lake & CDISASM_X86_DECODE_FLAG_TRANSACTIONAL) == 0);
        EXPECT((tiger_lake & CDISASM_X86_DECODE_FLAG_TRANSACTIONAL) == 0);
        EXPECT((alder_lake & CDISASM_X86_DECODE_FLAG_TRANSACTIONAL) == 0);
        EXPECT((alder_lake & CDISASM_X86_DECODE_FLAG_AVX512) == 0);
        EXPECT((arrow_lake & (CDISASM_X86_DECODE_FLAG_SHA
                              | CDISASM_X86_DECODE_FLAG_SM3
                              | CDISASM_X86_DECODE_FLAG_SM4))
            == (CDISASM_X86_DECODE_FLAG_SHA
                | CDISASM_X86_DECODE_FLAG_SM3
                | CDISASM_X86_DECODE_FLAG_SM4));
        EXPECT((arrow_lake & CDISASM_X86_DECODE_FLAG_AVX10) == 0);
        EXPECT((arrow_lake
                & (CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT8
                    | CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16))
            == (CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT8
                | CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16));
        EXPECT((sapphire64 & CDISASM_X86_DECODE_FLAG_AMX) != 0);
        EXPECT((sapphire64 & CDISASM_X86_DECODE_FLAG_TRANSACTIONAL) != 0);
        EXPECT((sapphire32 & CDISASM_X86_DECODE_FLAG_AMX) == 0);
        EXPECT((granite64 & (CDISASM_X86_DECODE_FLAG_AVX10
                            | CDISASM_X86_DECODE_FLAG_AMX))
            == (CDISASM_X86_DECODE_FLAG_AVX10
                | CDISASM_X86_DECODE_FLAG_AMX));
        EXPECT((granite32 & CDISASM_X86_DECODE_FLAG_AVX10) != 0);
        EXPECT((granite32 & CDISASM_X86_DECODE_FLAG_AMX) == 0);
        EXPECT((avx10_64 & CDISASM_X86_DECODE_FLAG_TRANSACTIONAL) == 0);
        EXPECT((apx64 & CDISASM_X86_DECODE_FLAG_TRANSACTIONAL) == 0);
        EXPECT((apx64 & (CDISASM_X86_DECODE_FLAG_AVX10
                        | CDISASM_X86_DECODE_FLAG_APX))
            == (CDISASM_X86_DECODE_FLAG_AVX10
                | CDISASM_X86_DECODE_FLAG_APX));
        EXPECT((apx32 & CDISASM_X86_DECODE_FLAG_APX) == 0);
        EXPECT((apx32 & CDISASM_X86_DECODE_FLAG_AVX10) != 0);
    }
#endif
}

static void test_base_contract(void)
{
    static const uint8_t nop[] = {0x90};
    static const uint8_t fld1[] = {0xd9, 0xe8};
    static const uint8_t x87_truncated[] = {0xd9};
    static const uint8_t x87_reserved[] = {0xd9, 0xd1};
#if USE_EXTRA_OPCODES
    static const uint8_t fisttp[] = {0xdb, 0x08};
    static const uint8_t wait[] = {0x9b};
    static const uint8_t ffreep[] = {0xdf, 0xc1};
    static const uint8_t opcode82[] = {0x82, 0xc0, 0x7f};
    static const uint8_t canonical_add[] = {0x80, 0xc0, 0x7f};
    static const uint8_t near_jcc[] = {0x0f, 0x82, 0, 0, 0, 0};
    static const uint8_t shift_group6[] = {0xd0, 0xf0};
    static const uint8_t test_group1[] = {0xf6, 0xc8, 0x7f};
    static const uint8_t x87_alias[] = {0xdc, 0xd1};
#endif
    static const flag_case base = {
        "base NOP", CDISASM_CPU_X86, CDISASM_MODE_64,
        nop, sizeof(nop), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_X86_NAME_NOP
    };
    static const flag_case fpu = {
        "x87 FLD1", CDISASM_CPU_X86, CDISASM_MODE_64,
        fld1, sizeof(fld1), CDISASM_X86_DECODE_FLAG_FPU,
        CDISASM_X86_NAME_FLD1
    };
    cdisasm_instruction instruction;

    EXPECT(decode_case(&base, 0, &instruction) == sizeof(nop));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_NOP);
#if USE_EXTRA_OPCODES
    EXPECT(decode_case(
               &base, CDISASM_X86_DECODE_FLAG_FPU, &instruction)
        == sizeof(nop));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_NOP);
#endif

    EXPECT(decode_case(&fpu, 0, &instruction) == 0);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_X86, CDISASM_MODE_32,
               x87_truncated, sizeof(x87_truncated), 0,
               CDISASM_X86_DECODE_FLAG_BASE, &instruction)
        == 0);
    EXPECT(is_error_only(&instruction, CDISASM_STATUS_TRUNCATED));
    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_X86, CDISASM_MODE_32,
               x87_reserved, sizeof(x87_reserved), 0,
               CDISASM_X86_DECODE_FLAG_BASE, &instruction)
        == 0);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));

#if USE_EXTRA_OPCODES
    EXPECT(decode_case(
               &fpu, CDISASM_X86_DECODE_FLAG_FPU, &instruction)
        == sizeof(fld1));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_FLD1);
    EXPECT(decode_case(
               &fpu, CDISASM_X86_DECODE_FLAG_SSE, &instruction)
        == 0);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));

    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_PRESCOTT, CDISASM_MODE_32,
               fisttp, sizeof(fisttp), 0,
               CDISASM_X86_DECODE_FLAG_FPU, &instruction)
        == sizeof(fisttp));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_FISTTP);
    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_PRESCOTT, CDISASM_MODE_32,
               fisttp, sizeof(fisttp), 0,
               CDISASM_X86_DECODE_FLAG_SSE3, &instruction)
        == 0);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));

    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_X86, CDISASM_MODE_32,
               wait, sizeof(wait), 0,
               CDISASM_X86_DECODE_FLAG_FPU, &instruction)
        == sizeof(wait));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_WAIT);

    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_8086_8087, CDISASM_MODE_16,
               ffreep, sizeof(ffreep), 0,
               CDISASM_X86_DECODE_FLAG_FPU
                   | CDISASM_X86_DECODE_FLAG_UNDOCUMENTED,
               &instruction)
        == sizeof(ffreep));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_FFREEP);
    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_8086_8087, CDISASM_MODE_16,
               ffreep, sizeof(ffreep), 0,
               CDISASM_X86_DECODE_FLAG_FPU, &instruction)
        == 0);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_8086_8087, CDISASM_MODE_16,
               ffreep, sizeof(ffreep), 0,
               CDISASM_X86_DECODE_FLAG_UNDOCUMENTED, &instruction)
        == 0);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));

    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_80186, CDISASM_MODE_16,
               opcode82, sizeof(opcode82), 0,
               CDISASM_X86_DECODE_FLAG_UNDOCUMENTED, &instruction)
        == sizeof(opcode82));
    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_80186, CDISASM_MODE_16,
               opcode82, sizeof(opcode82), 0,
               CDISASM_X86_DECODE_FLAG_BASE, &instruction)
        == 0);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_8086, CDISASM_MODE_16,
               canonical_add, sizeof(canonical_add), 0,
               CDISASM_X86_DECODE_FLAG_BASE, &instruction)
        == sizeof(canonical_add));
    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_80386, CDISASM_MODE_32,
               near_jcc, sizeof(near_jcc), 0,
               CDISASM_X86_DECODE_FLAG_BASE, &instruction)
        == sizeof(near_jcc));

    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_80186, CDISASM_MODE_16,
               shift_group6, sizeof(shift_group6), 0,
               CDISASM_X86_DECODE_FLAG_UNDOCUMENTED, &instruction)
        == sizeof(shift_group6));
    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_8086, CDISASM_MODE_16,
               test_group1, sizeof(test_group1), 0,
               CDISASM_X86_DECODE_FLAG_UNDOCUMENTED, &instruction)
        == sizeof(test_group1));

    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_8086_8087, CDISASM_MODE_16,
               x87_alias, sizeof(x87_alias), 0,
               CDISASM_X86_DECODE_FLAG_FPU
                   | CDISASM_X86_DECODE_FLAG_UNDOCUMENTED,
               &instruction)
        == sizeof(x87_alias));
    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_8086_8087, CDISASM_MODE_16,
               x87_alias, sizeof(x87_alias), 0,
               CDISASM_X86_DECODE_FLAG_FPU, &instruction)
        == 0);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#else
    EXPECT(decode_case(
               &fpu, CDISASM_X86_DECODE_FLAG_FPU, &instruction)
        == 0);
    EXPECT(is_error_only(&instruction, CDISASM_STATUS_INVALID_ARGUMENT));
#endif

#if USE_EXTRA_OPCODES
    EXPECT(decode_case(
               &base, UINT64_MAX, &instruction)
        == base.size);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(decode_case(
               &base, CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16,
               &instruction)
        == base.size);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
#else
    EXPECT(decode_case(
               &base, UINT64_MAX, &instruction)
        == 0);
    EXPECT(is_error_only(&instruction, CDISASM_STATUS_INVALID_ARGUMENT));
    EXPECT(decode_case(
               &base, CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16,
               &instruction)
        == 0);
    EXPECT(is_error_only(&instruction, CDISASM_STATUS_INVALID_ARGUMENT));
#endif
}

#if USE_EXTRA_OPCODES
static void test_family_selection(void)
{
    static const uint8_t mmx[] = {0x0f, 0x77};
    static const uint8_t dnow[] = {0x0f, 0x0f, 0xc1, 0x9e};
    static const uint8_t sse[] = {0x0f, 0x58, 0xc1};
    static const uint8_t sse2[] = {0x66, 0x0f, 0x58, 0xc1};
    static const uint8_t sse3[] = {0xf2, 0x0f, 0x7c, 0xc1};
    static const uint8_t ssse3[] = {0x66, 0x0f, 0x38, 0x00, 0xc1};
    static const uint8_t sse4[] = {0x66, 0x0f, 0x38, 0x17, 0xc1};
    static const uint8_t avx[] = {0xc5, 0xf8, 0x77};
    static const uint8_t avx2[] = {0xc5, 0xed, 0xfc, 0xcb};
    static const uint8_t f16c[] = {0xc4, 0xe3, 0x7d, 0x1d, 0xc8, 0x00};
    static const uint8_t fma3[] = {0xc4, 0xe2, 0x6d, 0x98, 0xcb};
    static const uint8_t xop[] = {0x8f, 0xe9, 0x60, 0x90, 0xca};
    static const uint8_t fma4[] = {0xc4, 0xe3, 0xe9, 0x68, 0xcc, 0x30};
    static const uint8_t aes[] = {0x66, 0x0f, 0x38, 0xdc, 0xca};
    static const uint8_t pclmul[] = {0x66, 0x0f, 0x3a, 0x44, 0xca, 0x01};
    static const uint8_t sha[] = {0x0f, 0x38, 0xc9, 0xca};
    static const uint8_t bitmanip[] = {0xc4, 0xe2, 0x70, 0xf2, 0xc2};
    static const uint8_t avx512[] = {0x62, 0xf1, 0x6c, 0xc9, 0x58, 0xcb};
    static const uint8_t amx[] = {0xc4, 0xe2, 0x7b, 0x49, 0xd0};
    static const uint8_t apx[] = {0x62, 0xec, 0xf4, 0x10, 0x01, 0xd3};
    static const uint8_t vmx[] = {0x0f, 0x01, 0xc1};
    static const uint8_t system[] = {0x0f, 0xa2};
    static const uint8_t cet[] = {0xf3, 0x0f, 0x1e, 0xfa};
    static const uint8_t transactional[] = {
        0xc7, 0xf8, 0x00, 0x00, 0x00, 0x00
    };
    static const uint8_t xtest_hle[] = {0x0f, 0x01, 0xd6};
    static const uint8_t security[] = {0x0f, 0xc7, 0xf0};
    static const uint8_t hint[] = {0x0f, 0x18, 0x00};
    static const uint8_t undocumented[] = {0xd6};
    static const flag_case cases[] = {
        {"MMX", CDISASM_CPU_X86, CDISASM_MODE_64, mmx, sizeof(mmx),
         CDISASM_X86_DECODE_FLAG_MMX, CDISASM_X86_NAME_EMMS},
        {"3DNow", CDISASM_CPU_X86, CDISASM_MODE_32, dnow, sizeof(dnow),
         CDISASM_X86_DECODE_FLAG_3DNOW, CDISASM_X86_NAME_PFADD},
        {"SSE", CDISASM_CPU_X86, CDISASM_MODE_64, sse, sizeof(sse),
         CDISASM_X86_DECODE_FLAG_SSE, CDISASM_X86_NAME_ADDPS},
        {"SSE2", CDISASM_CPU_X86, CDISASM_MODE_64, sse2, sizeof(sse2),
         CDISASM_X86_DECODE_FLAG_SSE2, CDISASM_X86_NAME_ADDPD},
        {"SSE3", CDISASM_CPU_X86, CDISASM_MODE_64, sse3, sizeof(sse3),
         CDISASM_X86_DECODE_FLAG_SSE3, CDISASM_X86_NAME_HADDPS},
        {"SSSE3", CDISASM_CPU_X86, CDISASM_MODE_64, ssse3, sizeof(ssse3),
         CDISASM_X86_DECODE_FLAG_SSSE3, CDISASM_X86_NAME_PSHUFB},
        {"SSE4", CDISASM_CPU_X86, CDISASM_MODE_64, sse4, sizeof(sse4),
         CDISASM_X86_DECODE_FLAG_SSE4, CDISASM_X86_NAME_PTEST},
        {"AVX", CDISASM_CPU_X86, CDISASM_MODE_64, avx, sizeof(avx),
         CDISASM_X86_DECODE_FLAG_AVX, CDISASM_X86_NAME_VZEROUPPER},
        {"AVX2", CDISASM_CPU_X86, CDISASM_MODE_64, avx2, sizeof(avx2),
         CDISASM_X86_DECODE_FLAG_AVX2, CDISASM_X86_NAME_VPADDB},
        {"F16C", CDISASM_CPU_X86, CDISASM_MODE_64, f16c, sizeof(f16c),
         CDISASM_X86_DECODE_FLAG_F16C, CDISASM_X86_NAME_VCVTPS2PH},
        {"FMA3", CDISASM_CPU_X86, CDISASM_MODE_64, fma3, sizeof(fma3),
         CDISASM_X86_DECODE_FLAG_FMA3, CDISASM_X86_NAME_VFMADD132PS},
        {"XOP", CDISASM_CPU_X86, CDISASM_MODE_32, xop, sizeof(xop),
         CDISASM_X86_DECODE_FLAG_XOP, CDISASM_X86_NAME_VPROTB},
        {"FMA4", CDISASM_CPU_X86, CDISASM_MODE_64, fma4, sizeof(fma4),
         CDISASM_X86_DECODE_FLAG_FMA4, CDISASM_X86_NAME_VFMADDPS},
        {"AES", CDISASM_CPU_X86, CDISASM_MODE_64, aes, sizeof(aes),
         CDISASM_X86_DECODE_FLAG_AES, CDISASM_X86_NAME_AESENC},
        {"PCLMUL", CDISASM_CPU_X86, CDISASM_MODE_64,
         pclmul, sizeof(pclmul), CDISASM_X86_DECODE_FLAG_PCLMUL,
         CDISASM_X86_NAME_PCLMULQDQ},
        {"SHA", CDISASM_CPU_X86, CDISASM_MODE_64, sha, sizeof(sha),
         CDISASM_X86_DECODE_FLAG_SHA, CDISASM_X86_NAME_SHA1MSG1},
        {"bitmanip", CDISASM_CPU_X86, CDISASM_MODE_64,
         bitmanip, sizeof(bitmanip), CDISASM_X86_DECODE_FLAG_BITMANIP,
         CDISASM_X86_NAME_ANDN},
        {"AVX512", CDISASM_CPU_X86, CDISASM_MODE_64,
         avx512, sizeof(avx512), CDISASM_X86_DECODE_FLAG_AVX512,
         CDISASM_X86_NAME_VADDPS},
        {"AVX10", CDISASM_CPU_AVX10, CDISASM_MODE_64,
         avx512, sizeof(avx512), CDISASM_X86_DECODE_FLAG_AVX10,
         CDISASM_X86_NAME_VADDPS},
        {"AMX", CDISASM_CPU_X86, CDISASM_MODE_64, amx, sizeof(amx),
         CDISASM_X86_DECODE_FLAG_AMX, CDISASM_X86_NAME_TILEZERO},
        {"APX", CDISASM_CPU_X86, CDISASM_MODE_64, apx, sizeof(apx),
         CDISASM_X86_DECODE_FLAG_APX, CDISASM_X86_NAME_ADD},
        {"Intel virtualization", CDISASM_CPU_X86, CDISASM_MODE_64,
         vmx, sizeof(vmx), CDISASM_X86_DECODE_FLAG_INTEL_VIRTUALIZATION,
         CDISASM_X86_NAME_VMCALL},
        {"system", CDISASM_CPU_X86, CDISASM_MODE_64,
         system, sizeof(system), CDISASM_X86_DECODE_FLAG_SYSTEM,
         CDISASM_X86_NAME_CPUID},
        {"CET", CDISASM_CPU_X86, CDISASM_MODE_64, cet, sizeof(cet),
         CDISASM_X86_DECODE_FLAG_CET, CDISASM_X86_NAME_ENDBR64},
        {"transactional", CDISASM_CPU_X86, CDISASM_MODE_64,
         transactional, sizeof(transactional),
         CDISASM_X86_DECODE_FLAG_TRANSACTIONAL, CDISASM_X86_NAME_XBEGIN},
        {"transactional XTEST", CDISASM_CPU_SAPPHIRE_RAPIDS,
         CDISASM_MODE_64, xtest_hle, sizeof(xtest_hle),
         CDISASM_X86_DECODE_FLAG_TRANSACTIONAL, CDISASM_X86_NAME_XTEST},
        {"security", CDISASM_CPU_X86, CDISASM_MODE_64,
         security, sizeof(security), CDISASM_X86_DECODE_FLAG_SECURITY,
         CDISASM_X86_NAME_RDRAND},
        {"memory hints", CDISASM_CPU_X86, CDISASM_MODE_64,
         hint, sizeof(hint), CDISASM_X86_DECODE_FLAG_MEMORY_HINTS,
         CDISASM_X86_NAME_PREFETCHNTA},
        {"undocumented", CDISASM_CPU_8086, CDISASM_MODE_16,
         undocumented, sizeof(undocumented),
         CDISASM_X86_DECODE_FLAG_UNDOCUMENTED, CDISASM_X86_NAME_SALC}
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_instruction instruction;
        uint32_t decoded = decode_case(&cases[index], cases[index].flag,
                                       &instruction);

        if (decoded != cases[index].size
            || instruction.name_id != cases[index].name_id) {
            fprintf(stderr,
                    "%s: got size=%u name=%u status=%u, expected size=%u name=%u\n",
                    cases[index].label,
                    (unsigned int)decoded,
                    (unsigned int)instruction.name_id,
                    (unsigned int)instruction.last_error_id,
                    (unsigned int)cases[index].size,
                    (unsigned int)cases[index].name_id);
            ++failures;
        }
        EXPECT(decode_case(&cases[index], 0, &instruction) == 0);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
    }
}

static void test_cpu_gate_is_independent(void)
{
    static const uint8_t aes[] = {0x66, 0x0f, 0x38, 0xdc, 0xca};
    static const uint8_t rdrand[] = {0x0f, 0xc7, 0xf0};
    static const uint8_t rdseed[] = {0x0f, 0xc7, 0xf8};
    static const uint8_t xbegin[] = {
        0xc7, 0xf8, 0x00, 0x00, 0x00, 0x00
    };
    static const flag_case test_cases[] = {
        {"AES before Westmere", CDISASM_CPU_NEHALEM, CDISASM_MODE_64,
         aes, sizeof(aes), CDISASM_X86_DECODE_FLAG_AES,
         CDISASM_X86_NAME_AESENC},
        {"RDRAND before Ivy Bridge", CDISASM_CPU_SANDY_BRIDGE,
         CDISASM_MODE_64, rdrand, sizeof(rdrand),
         CDISASM_X86_DECODE_FLAG_SECURITY, CDISASM_X86_NAME_RDRAND},
        {"RDSEED before Broadwell", CDISASM_CPU_HASWELL,
         CDISASM_MODE_64, rdseed, sizeof(rdseed),
         CDISASM_X86_DECODE_FLAG_SECURITY, CDISASM_X86_NAME_RDSEED},
        {"RTM before Haswell", CDISASM_CPU_IVY_BRIDGE,
         CDISASM_MODE_64, xbegin, sizeof(xbegin),
         CDISASM_X86_DECODE_FLAG_TRANSACTIONAL,
         CDISASM_X86_NAME_XBEGIN},
        {"RTM dropped on Tiger Lake", CDISASM_CPU_TIGER_LAKE,
         CDISASM_MODE_64, xbegin, sizeof(xbegin),
         CDISASM_X86_DECODE_FLAG_TRANSACTIONAL,
         CDISASM_X86_NAME_XBEGIN},
        {"RTM absent on Ice Lake client", CDISASM_CPU_ICE_LAKE,
         CDISASM_MODE_64, xbegin, sizeof(xbegin),
         CDISASM_X86_DECODE_FLAG_TRANSACTIONAL,
         CDISASM_X86_NAME_XBEGIN},
        {"RTM dropped on Alder Lake", CDISASM_CPU_ALDER_LAKE,
         CDISASM_MODE_64, xbegin, sizeof(xbegin),
         CDISASM_X86_DECODE_FLAG_TRANSACTIONAL,
         CDISASM_X86_NAME_XBEGIN}
    };
    cdisasm_instruction instruction;
    size_t index;

    for (index = 0;
         index < sizeof(test_cases) / sizeof(test_cases[0]);
         ++index) {
        EXPECT(decode_case(
                   &test_cases[index], test_cases[index].flag, &instruction)
            == 0);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
    }
}
#endif

int main(void)
{
    test_flag_set_contract();
#if USE_EXTRA_OPCODES
    test_ace_exact_flag_contract();
#endif
    test_cpu_queries();
    test_base_contract();
#if USE_EXTRA_OPCODES
    test_family_selection();
    test_cpu_gate_is_independent();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d x86 decode-flag test(s) failed\n", failures);
        return 1;
    }
    puts("all x86 decode-flag tests passed");
    return 0;
}
