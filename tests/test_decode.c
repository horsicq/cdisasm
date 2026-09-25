#include "cdisasm/cdisasm.h"

#include <stdio.h>
#include <string.h>

#define DISPATCH_SENTINEL_SIZE 256u

_Static_assert(sizeof(cdisasm_decode_option) == 8,
               "generic bitmap-word ABI width changed");
_Static_assert(sizeof(cdisasm_decode_flags) == CDISASM_DECODE_FLAGS_SIZE,
               "generic decode-flags ABI size changed");
_Static_assert(sizeof(cdisasm_decode_flags) == 64,
               "generic decode flags must contain eight 64-bit bitmaps");
_Static_assert(CDISASM_DECODE_FLAGS_BITMAP_COUNT == 8,
               "generic decode bitmap count changed");
_Static_assert(CDISASM_DECODE_OPTION_NONE == UINT64_C(0),
               "generic NONE decode option changed");
#if USE_ARCH_X86
_Static_assert(sizeof(cdisasm_x86_decode_option) == 8,
               "x86 bitmap-word ABI width changed");
_Static_assert(sizeof(cdisasm_x86_decode_flags)
                   == sizeof(cdisasm_decode_flags),
               "generic and x86 decode-flag sizes differ");
#endif
#if USE_ARCH_ARM
_Static_assert(sizeof(cdisasm_arm_decode_option) == 8,
               "ARM bitmap-word ABI width changed");
_Static_assert(sizeof(cdisasm_arm_decode_flags)
                   == sizeof(cdisasm_decode_flags),
               "generic and ARM decode-flag sizes differ");
_Static_assert(CDISASM_ARM_DECODE_OPTION_NONE == UINT64_C(0),
               "ARM NONE decode option changed");
_Static_assert(CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN == UINT64_C(1),
               "ARM big-endian decode option changed");
_Static_assert(CDISASM_ARM_DECODE_OPTION_IN_IT_BLOCK == UINT64_C(2),
               "ARM T32 IT-state decode option changed");
_Static_assert(CDISASM_ARM_DECODE_OPTION_KNOWN_MASK == UINT64_C(3),
               "ARM known decode-option mask changed");
#endif

typedef union dispatch_sentinel {
    uint64_t alignment;
    uint8_t bytes[DISPATCH_SENTINEL_SIZE];
} dispatch_sentinel;

static int failures;

#define EXPECT(condition) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "%s:%d: expectation failed: %s\n", \
                __FILE__, __LINE__, #condition); \
            ++failures; \
        } \
    } while (0)

static void expect_undispatched(uint32_t cpu_id, uint32_t mode)
{
    static const uint8_t code[] = { UINT8_C(0x90) };
    dispatch_sentinel instruction;
    dispatch_sentinel before;

    memset(&instruction, 0xa5, sizeof(instruction));
    memcpy(&before, &instruction, sizeof(before));

    EXPECT(cdisasm_decode(
              cpu_id,
              mode,
              code,
              sizeof(code),
              UINT64_C(0x12345678),
              NULL,
              &instruction)
        == 0);
    EXPECT(memcmp(&instruction, &before, sizeof(instruction)) == 0);
}

static void test_unknown_and_disabled_groups(void)
{
    static const uint8_t code[] = { UINT8_C(0x90) };

    expect_undispatched(UINT32_C(0x00000001), UINT32_C(0));
    expect_undispatched(UINT32_C(0x00030001), UINT32_C(0));
    expect_undispatched(UINT32_MAX, UINT32_C(0));

#if !USE_ARCH_X86
    expect_undispatched(
        CDISASM_CPU_GROUP_X86 | UINT32_C(0x0001), UINT32_C(32));
#endif
#if !USE_ARCH_ARM
    expect_undispatched(
        CDISASM_CPU_GROUP_ARM | UINT32_C(0x0001), UINT32_C(1));
#endif

    EXPECT(cdisasm_decode(
              UINT32_C(0x00030001),
              UINT32_C(0),
              code,
              sizeof(code),
              UINT64_C(0),
              NULL,
              NULL)
        == 0);
}

static void test_checked_dispatch_contract(void)
{
    static const uint8_t code[] = { UINT8_C(0x90) };
    dispatch_sentinel instruction;
    dispatch_sentinel before;

    EXPECT(cdisasm_instruction_size(UINT32_C(0x00030001)) == 0);
    memset(&instruction, 0xa5, sizeof(instruction));
    memcpy(&before, &instruction, sizeof(before));
    EXPECT(cdisasm_decode_checked(
              UINT32_C(0x00030001),
              UINT32_C(0),
              code,
              sizeof(code),
              UINT64_C(0),
              NULL,
              &instruction,
              sizeof(instruction))
        == 0);
    EXPECT(memcmp(&instruction, &before, sizeof(instruction)) == 0);

#if USE_ARCH_X86
    EXPECT(cdisasm_instruction_size(CDISASM_CPU_80386)
        == sizeof(cdisasm_x86_instruction));
    memset(&instruction, 0xa5, sizeof(instruction));
    memcpy(&before, &instruction, sizeof(before));
    EXPECT(cdisasm_decode_checked(
              CDISASM_CPU_80386,
              CDISASM_MODE_32,
              code,
              sizeof(code),
              UINT64_C(0x3000),
              NULL,
              &instruction,
              sizeof(cdisasm_x86_instruction) - 1u)
        == 0);
    EXPECT(memcmp(&instruction, &before, sizeof(instruction)) == 0);
    EXPECT(cdisasm_decode_checked(
              CDISASM_CPU_80386,
              CDISASM_MODE_32,
              code,
              sizeof(code),
              UINT64_C(0x3000),
              NULL,
              &instruction,
              sizeof(cdisasm_x86_instruction))
        == sizeof(code));
    EXPECT(((cdisasm_x86_instruction *)(void *)&instruction)->name_id
        == CDISASM_X86_NAME_NOP);
#  if USE_ARCH_ARM
    memset(&instruction, 0xa5, sizeof(instruction));
    memcpy(&before, &instruction, sizeof(before));
    EXPECT(cdisasm_decode_checked(
              CDISASM_CPU_80386,
              CDISASM_MODE_32,
              code,
              sizeof(code),
              UINT64_C(0),
              NULL,
              &instruction,
              sizeof(cdisasm_arm_instruction))
        == 0);
    EXPECT(memcmp(&instruction, &before, sizeof(instruction)) == 0);
#  endif
#else
    EXPECT(cdisasm_instruction_size(
               CDISASM_CPU_GROUP_X86 | UINT32_C(1))
        == 0);
#endif

#if USE_ARCH_ARM
    static const uint8_t arm_nop[] = {
        UINT8_C(0x00), UINT8_C(0xf0), UINT8_C(0x20), UINT8_C(0xe3)
    };

    EXPECT(cdisasm_instruction_size(CDISASM_ARM_CPU_CORTEX_A7)
        == sizeof(cdisasm_arm_instruction));
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(cdisasm_decode_checked(
              CDISASM_ARM_CPU_CORTEX_A7,
              CDISASM_ARM_MODE_A32,
              arm_nop,
              sizeof(arm_nop),
              UINT64_C(0x7000),
              NULL,
              &instruction,
              sizeof(cdisasm_arm_instruction))
        == sizeof(arm_nop));
    EXPECT(((cdisasm_arm_instruction *)(void *)&instruction)->name_id
        == CDISASM_ARM_NAME_NOP);
    EXPECT(instruction.bytes[sizeof(cdisasm_arm_instruction)]
        == UINT8_C(0xa5));
#else
    EXPECT(cdisasm_instruction_size(
               CDISASM_CPU_GROUP_ARM | UINT32_C(1))
        == 0);
#endif

    EXPECT(cdisasm_decode_checked(
              CDISASM_CPU_GROUP_X86,
              UINT32_C(0),
              code,
              sizeof(code),
              UINT64_C(0),
              NULL,
              NULL,
              0)
        == 0);
}

static int decode_flags_are_zero(const cdisasm_decode_flags *flags)
{
    size_t bitmap_index;

    for (bitmap_index = 0;
         bitmap_index < CDISASM_DECODE_FLAGS_BITMAP_COUNT;
         ++bitmap_index) {
        if (flags->bitmap[bitmap_index] != UINT64_C(0)) {
            return 0;
        }
    }
    return 1;
}

static void test_decode_flag_queries(void)
{
    cdisasm_decode_flags generic_flags;
    cdisasm_decode_flags explicit_flags;

    memset(&generic_flags, 0xa5, sizeof(generic_flags));
    EXPECT(cdisasm_cpu_decode_flag_mask(
               UINT32_C(0x00030001), UINT32_C(0), &generic_flags)
        == CDISASM_STATUS_INVALID_ARGUMENT);
    EXPECT(decode_flags_are_zero(&generic_flags));
    EXPECT(cdisasm_cpu_decode_flag_mask(
               UINT32_C(0x00030001), UINT32_C(0), NULL)
        == CDISASM_STATUS_INVALID_ARGUMENT);

#if USE_ARCH_X86
    memset(&generic_flags, 0xa5, sizeof(generic_flags));
    memset(&explicit_flags, 0x5a, sizeof(explicit_flags));
    EXPECT(cdisasm_cpu_decode_flag_mask(
               CDISASM_CPU_80386, CDISASM_MODE_32, &generic_flags)
        == CDISASM_STATUS_OK);
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
               CDISASM_CPU_80386, CDISASM_MODE_32,
               (cdisasm_x86_decode_flags *)&explicit_flags)
        == CDISASM_STATUS_OK);
    EXPECT(memcmp(&generic_flags, &explicit_flags,
                  sizeof(generic_flags)) == 0);
#endif

#if USE_ARCH_ARM
    memset(&generic_flags, 0xa5, sizeof(generic_flags));
    memset(&explicit_flags, 0x5a, sizeof(explicit_flags));
    EXPECT(cdisasm_cpu_decode_flag_mask(
               CDISASM_ARM_CPU_CORTEX_A7, CDISASM_ARM_MODE_A32,
               &generic_flags)
        == CDISASM_STATUS_OK);
    EXPECT(cdisasm_arm_cpu_decode_flag_mask(
               CDISASM_ARM_CPU_CORTEX_A7, CDISASM_ARM_MODE_A32,
               (cdisasm_arm_decode_flags *)&explicit_flags)
        == CDISASM_STATUS_OK);
    EXPECT(memcmp(&generic_flags, &explicit_flags,
                  sizeof(generic_flags)) == 0);
    EXPECT(generic_flags.bitmap[CDISASM_ARM_DECODE_FLAGS_OPTION_BITMAP]
        == CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN);

    memset(&explicit_flags, 0xa5, sizeof(explicit_flags));
    EXPECT(cdisasm_arm_cpu_decode_flag_mask(
               CDISASM_ARM_CPU_CORTEX_A7, CDISASM_ARM_MODE_A64,
               (cdisasm_arm_decode_flags *)&explicit_flags)
        == CDISASM_STATUS_INVALID_ARGUMENT);
    EXPECT(decode_flags_are_zero(&explicit_flags));
    EXPECT(cdisasm_arm_cpu_decode_flag_mask(
               CDISASM_ARM_CPU_CORTEX_A7, CDISASM_ARM_MODE_A32, NULL)
        == CDISASM_STATUS_INVALID_ARGUMENT);
#endif
}

#if USE_ARCH_X86
static void test_x86_dispatch(void)
{
    static const uint8_t nop[] = { UINT8_C(0x90) };
    static const uint8_t vaddps[] = {
        UINT8_C(0xc5), UINT8_C(0xe8), UINT8_C(0x58), UINT8_C(0xcb)
    };
    static const uint8_t vpconflictd[] = {
        UINT8_C(0x62), UINT8_C(0xf2), UINT8_C(0x7d), UINT8_C(0x48),
        UINT8_C(0xc4), UINT8_C(0xcb)
    };
    static const cdisasm_x86_decode_flags no_flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    static const cdisasm_x86_decode_flags avx_flags =
        CDISASM_X86_DECODE_FLAGS_INITIALIZER(
            CDISASM_X86_DECODE_FLAG_AVX);
    static const cdisasm_x86_decode_flags avx512_cd_flags =
        CDISASM_X86_DECODE_FLAGS_INITIALIZER(
            CDISASM_X86_DECODE_FLAG_AVX512_CD);
    static const cdisasm_x86_decode_flags avx_vnni_int16_flags =
        CDISASM_X86_DECODE_FLAGS_INITIALIZER(
            CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16);
    cdisasm_x86_decode_flags unknown_high_flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    cdisasm_instruction generic_instruction;
    cdisasm_instruction explicit_instruction;
    uint32_t generic_size;
    uint32_t explicit_size;

    memset(&generic_instruction, 0xa5, sizeof(generic_instruction));
    memset(&explicit_instruction, 0x5a, sizeof(explicit_instruction));
    generic_size = cdisasm_decode(
        CDISASM_CPU_80386,
        CDISASM_MODE_32,
        nop,
        sizeof(nop),
        UINT64_C(0x1000),
        NULL,
        &generic_instruction);
    explicit_size = cdisasm_x86_decode(
        CDISASM_CPU_80386,
        CDISASM_MODE_32,
        nop,
        sizeof(nop),
        UINT64_C(0x1000),
        &no_flags,
        &explicit_instruction);

    EXPECT(generic_size == sizeof(nop));
    EXPECT(generic_size == explicit_size);
    EXPECT(memcmp(
              &generic_instruction,
              &explicit_instruction,
              sizeof(generic_instruction))
        == 0);
    EXPECT(generic_instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(generic_instruction.name_id == CDISASM_X86_NAME_NOP);

    memset(&generic_instruction, 0xa5, sizeof(generic_instruction));
    memset(&explicit_instruction, 0x5a, sizeof(explicit_instruction));
    generic_size = cdisasm_decode(
        CDISASM_CPU_X86,
        CDISASM_MODE_64,
        vaddps,
        sizeof(vaddps),
        UINT64_C(0x1050),
        NULL,
        &generic_instruction);
    explicit_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_MODE_64,
        vaddps,
        sizeof(vaddps),
        UINT64_C(0x1050),
        &no_flags,
        &explicit_instruction);
    EXPECT(generic_size == 0);
    EXPECT(generic_size == explicit_size);
    EXPECT(memcmp(
              &generic_instruction,
              &explicit_instruction,
              sizeof(generic_instruction))
        == 0);
    EXPECT(generic_instruction.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    memset(&generic_instruction, 0xa5, sizeof(generic_instruction));
    memset(&explicit_instruction, 0x5a, sizeof(explicit_instruction));
    generic_size = cdisasm_decode(
        CDISASM_CPU_X86,
        CDISASM_MODE_64,
        vaddps,
        sizeof(vaddps),
        UINT64_C(0x1060),
        &avx_flags,
        &generic_instruction);
    explicit_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_MODE_64,
        vaddps,
        sizeof(vaddps),
        UINT64_C(0x1060),
        &avx_flags,
        &explicit_instruction);
    EXPECT(generic_size == explicit_size);
    EXPECT(memcmp(
              &generic_instruction,
              &explicit_instruction,
              sizeof(generic_instruction))
        == 0);
#if USE_EXTRA_OPCODES
    EXPECT(generic_size == sizeof(vaddps));
    EXPECT(generic_instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(generic_instruction.name_id == CDISASM_X86_NAME_VADDPS);
#else
    EXPECT(generic_size == 0);
    EXPECT(generic_instruction.last_error_id
        == CDISASM_STATUS_INVALID_ARGUMENT);
#endif

    /* Exercise the highest assigned runtime-family bit through generic
     * dispatch so a future accidental 32-bit narrowing is caught. */
    memset(&generic_instruction, 0xa5, sizeof(generic_instruction));
    memset(&explicit_instruction, 0x5a, sizeof(explicit_instruction));
    generic_size = cdisasm_decode(
        CDISASM_CPU_X86,
        CDISASM_MODE_64,
        vpconflictd,
        sizeof(vpconflictd),
        UINT64_C(0x1068),
        &avx512_cd_flags,
        &generic_instruction);
    explicit_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_MODE_64,
        vpconflictd,
        sizeof(vpconflictd),
        UINT64_C(0x1068),
        &avx512_cd_flags,
        &explicit_instruction);
    EXPECT(generic_size == explicit_size);
    EXPECT(memcmp(
              &generic_instruction,
              &explicit_instruction,
              sizeof(generic_instruction))
        == 0);
#if USE_EXTRA_OPCODES
    EXPECT(generic_size == sizeof(vpconflictd));
    EXPECT(generic_instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(generic_instruction.name_id == CDISASM_X86_NAME_VPCONFLICTD);
#else
    EXPECT(generic_size == 0);
    EXPECT(generic_instruction.last_error_id
        == CDISASM_STATUS_INVALID_ARGUMENT);
#endif

    memset(&generic_instruction, 0xa5, sizeof(generic_instruction));
    memset(&explicit_instruction, 0x5a, sizeof(explicit_instruction));
    generic_size = cdisasm_decode(
        CDISASM_CPU_X86,
        CDISASM_MODE_64,
        nop,
        sizeof(nop),
        UINT64_C(0x1080),
        &avx_vnni_int16_flags,
        &generic_instruction);
    explicit_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_MODE_64,
        nop,
        sizeof(nop),
        UINT64_C(0x1080),
        &avx_vnni_int16_flags,
        &explicit_instruction);
    EXPECT(generic_size == explicit_size);
    EXPECT(memcmp(
              &generic_instruction,
              &explicit_instruction,
              sizeof(generic_instruction))
        == 0);
#if USE_EXTRA_OPCODES
    EXPECT(generic_size == sizeof(nop));
    EXPECT(generic_instruction.last_error_id == CDISASM_STATUS_OK);
#else
    EXPECT(generic_size == 0);
    EXPECT(generic_instruction.last_error_id
        == CDISASM_STATUS_INVALID_ARGUMENT);
#endif

    memset(&generic_instruction, 0xa5, sizeof(generic_instruction));
    generic_size = cdisasm_decode(
        CDISASM_CPU_X86,
        CDISASM_MODE_64,
        nop,
        sizeof(nop),
        UINT64_C(0x1090),
        &avx_vnni_int16_flags,
        &generic_instruction);
#if USE_EXTRA_OPCODES
    EXPECT(generic_size == sizeof(nop));
    EXPECT(generic_instruction.last_error_id == CDISASM_STATUS_OK);
#else
    EXPECT(generic_size == 0);
    EXPECT(generic_instruction.last_error_id
        == CDISASM_STATUS_INVALID_ARGUMENT);
#endif

    memset(&generic_instruction, 0xa5, sizeof(generic_instruction));
    memset(&explicit_instruction, 0x5a, sizeof(explicit_instruction));
    generic_size = cdisasm_decode(
        CDISASM_CPU_X86,
        CDISASM_MODE_64,
        vaddps,
        sizeof(vaddps),
        UINT64_C(0x1070),
        &avx_vnni_int16_flags,
        &generic_instruction);
    explicit_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_MODE_64,
        vaddps,
        sizeof(vaddps),
        UINT64_C(0x1070),
        &avx_vnni_int16_flags,
        &explicit_instruction);
    EXPECT(generic_size == 0);
    EXPECT(generic_size == explicit_size);
    EXPECT(memcmp(
              &generic_instruction,
              &explicit_instruction,
              sizeof(generic_instruction))
        == 0);
#if USE_EXTRA_OPCODES
    EXPECT(generic_instruction.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
    EXPECT(generic_instruction.last_error_id
        == CDISASM_STATUS_INVALID_ARGUMENT);
#endif

    memset(&generic_instruction, 0xa5, sizeof(generic_instruction));
    memset(&explicit_instruction, 0x5a, sizeof(explicit_instruction));
    generic_size = cdisasm_decode(
        CDISASM_CPU_GROUP_X86 | UINT32_C(0xffff),
        CDISASM_MODE_16,
        nop,
        sizeof(nop),
        UINT64_C(0x1100),
        NULL,
        &generic_instruction);
    explicit_size = cdisasm_x86_decode(
        CDISASM_CPU_GROUP_X86 | UINT32_C(0xffff),
        CDISASM_MODE_16,
        nop,
        sizeof(nop),
        UINT64_C(0x1100),
        &no_flags,
        &explicit_instruction);

    EXPECT(generic_size == 0);
    EXPECT(generic_size == explicit_size);
    EXPECT(memcmp(
              &generic_instruction,
              &explicit_instruction,
              sizeof(generic_instruction))
        == 0);
    EXPECT(generic_instruction.last_error_id
        == CDISASM_STATUS_INVALID_ARGUMENT);

    EXPECT(cdisasm_decode(
              CDISASM_CPU_80386,
              CDISASM_MODE_32,
              nop,
              sizeof(nop),
              UINT64_C(0),
              NULL,
              NULL)
        == 0);

    unknown_high_flags.bitmap[CDISASM_DECODE_FLAGS_BITMAP_COUNT - 1u] =
        UINT64_C(1);
    memset(&generic_instruction, 0xa5, sizeof(generic_instruction));
    memset(&explicit_instruction, 0x5a, sizeof(explicit_instruction));
    generic_size = cdisasm_decode(
        CDISASM_CPU_X86, CDISASM_MODE_64, nop, sizeof(nop), UINT64_C(0),
        &unknown_high_flags, &generic_instruction);
    explicit_size = cdisasm_x86_decode(
        CDISASM_CPU_X86, CDISASM_MODE_64, nop, sizeof(nop), UINT64_C(0),
        &unknown_high_flags, &explicit_instruction);
    EXPECT(generic_size == 0);
    EXPECT(generic_size == explicit_size);
    EXPECT(memcmp(&generic_instruction, &explicit_instruction,
                  sizeof(generic_instruction)) == 0);
    EXPECT(generic_instruction.last_error_id
        == CDISASM_STATUS_INVALID_ARGUMENT);
}
#endif

#if USE_ARCH_ARM
static void test_arm_dispatch(void)
{
    static const uint8_t add_r0_r1_5[] = {
        UINT8_C(0x05), UINT8_C(0x00), UINT8_C(0x81), UINT8_C(0xe2)
    };
    static const cdisasm_arm_decode_flags no_flags =
        CDISASM_ARM_DECODE_FLAGS_NONE_INITIALIZER;
    static const cdisasm_arm_decode_flags invalid_flags[] = {
        CDISASM_ARM_DECODE_FLAGS_INITIALIZER(UINT64_C(0x80000000)),
        CDISASM_ARM_DECODE_FLAGS_INITIALIZER(UINT64_C(0x100000000)),
        CDISASM_ARM_DECODE_FLAGS_INITIALIZER(
            UINT64_C(0x8000000000000000)),
        {{UINT64_C(0), UINT64_C(1)}},
        {{UINT64_C(0), UINT64_C(0), UINT64_C(0), UINT64_C(0),
          UINT64_C(0), UINT64_C(0), UINT64_C(0), UINT64_C(1)}}
    };
    static const cdisasm_arm_decode_flags invalid_big_endian_flags =
        CDISASM_ARM_DECODE_FLAGS_INITIALIZER(
            CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN
                | UINT64_C(0x8000000000000000));
    cdisasm_arm_instruction generic_instruction;
    cdisasm_arm_instruction explicit_instruction;
    uint32_t generic_size;
    uint32_t explicit_size;
    size_t flag_index;

    memset(&generic_instruction, 0xa5, sizeof(generic_instruction));
    memset(&explicit_instruction, 0x5a, sizeof(explicit_instruction));
    generic_size = cdisasm_decode(
        CDISASM_ARM_CPU_CORTEX_A7,
        CDISASM_ARM_MODE_A32,
        add_r0_r1_5,
        sizeof(add_r0_r1_5),
        UINT64_C(0x2000),
        NULL,
        &generic_instruction);
    explicit_size = cdisasm_arm_decode(
        CDISASM_ARM_CPU_CORTEX_A7,
        CDISASM_ARM_MODE_A32,
        add_r0_r1_5,
        sizeof(add_r0_r1_5),
        UINT64_C(0x2000),
        &no_flags,
        &explicit_instruction);

    EXPECT(generic_size == sizeof(add_r0_r1_5));
    EXPECT(generic_size == explicit_size);
    EXPECT(memcmp(
              &generic_instruction,
              &explicit_instruction,
              sizeof(generic_instruction))
        == 0);
    EXPECT(generic_instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(generic_instruction.name_id == CDISASM_ARM_NAME_ADD);
    EXPECT(generic_instruction.isa_id == CDISASM_ARM_ISA_A32);

    memset(&generic_instruction, 0xa5, sizeof(generic_instruction));
    memset(&explicit_instruction, 0x5a, sizeof(explicit_instruction));
    generic_size = cdisasm_decode(
        CDISASM_CPU_GROUP_ARM | UINT32_C(0xffff),
        CDISASM_ARM_MODE_A32,
        add_r0_r1_5,
        sizeof(add_r0_r1_5),
        UINT64_C(0x2100),
        NULL,
        &generic_instruction);
    explicit_size = cdisasm_arm_decode(
        CDISASM_CPU_GROUP_ARM | UINT32_C(0xffff),
        CDISASM_ARM_MODE_A32,
        add_r0_r1_5,
        sizeof(add_r0_r1_5),
        UINT64_C(0x2100),
        &no_flags,
        &explicit_instruction);

    EXPECT(generic_size == 0);
    EXPECT(generic_size == explicit_size);
    EXPECT(memcmp(
              &generic_instruction,
              &explicit_instruction,
              sizeof(generic_instruction))
        == 0);
    EXPECT(generic_instruction.last_error_id
        == CDISASM_STATUS_INVALID_ARGUMENT);

    for (flag_index = 0;
         flag_index < sizeof(invalid_flags) / sizeof(invalid_flags[0]);
         ++flag_index) {
        memset(&generic_instruction, 0xa5, sizeof(generic_instruction));
        memset(&explicit_instruction, 0x5a, sizeof(explicit_instruction));
        generic_size = cdisasm_decode(
            CDISASM_ARM_CPU_CORTEX_A7,
            CDISASM_ARM_MODE_A32,
            add_r0_r1_5,
            sizeof(add_r0_r1_5),
            UINT64_C(0x2208),
            &invalid_flags[flag_index],
            &generic_instruction);
        explicit_size = cdisasm_arm_decode(
            CDISASM_ARM_CPU_CORTEX_A7,
            CDISASM_ARM_MODE_A32,
            add_r0_r1_5,
            sizeof(add_r0_r1_5),
            UINT64_C(0x2208),
            &invalid_flags[flag_index],
            &explicit_instruction);
        EXPECT(generic_size == 0);
        EXPECT(generic_size == explicit_size);
        EXPECT(memcmp(
                  &generic_instruction,
                  &explicit_instruction,
                  sizeof(generic_instruction))
            == 0);
        EXPECT(generic_instruction.last_error_id
            == CDISASM_STATUS_INVALID_ARGUMENT);
    }

    memset(&generic_instruction, 0xa5, sizeof(generic_instruction));
    generic_size = cdisasm_decode(
        CDISASM_ARM_CPU_CORTEX_A7,
        CDISASM_ARM_MODE_A32,
        add_r0_r1_5,
        sizeof(add_r0_r1_5),
        UINT64_C(0x2200),
        &invalid_flags[1],
        &generic_instruction);
    EXPECT(generic_size == 0);
    {
        cdisasm_arm_instruction expected;

        memset(&expected, 0, sizeof(expected));
        expected.last_error_id = (uint8_t)CDISASM_STATUS_INVALID_ARGUMENT;
        EXPECT(memcmp(
                  &generic_instruction,
                  &expected,
                  sizeof(generic_instruction))
            == 0);
    }

    memset(&generic_instruction, 0xa5, sizeof(generic_instruction));
    memset(&explicit_instruction, 0x5a, sizeof(explicit_instruction));
    generic_size = cdisasm_decode_checked(
        CDISASM_ARM_CPU_CORTEX_A7,
        CDISASM_ARM_MODE_A32,
        add_r0_r1_5,
        sizeof(add_r0_r1_5),
        UINT64_C(0x2210),
        &invalid_big_endian_flags,
        &generic_instruction,
        sizeof(generic_instruction));
    explicit_size = cdisasm_arm_decode(
        CDISASM_ARM_CPU_CORTEX_A7,
        CDISASM_ARM_MODE_A32,
        add_r0_r1_5,
        sizeof(add_r0_r1_5),
        UINT64_C(0x2210),
        &invalid_big_endian_flags,
        &explicit_instruction);
    EXPECT(generic_size == 0);
    EXPECT(generic_size == explicit_size);
    EXPECT(memcmp(
              &generic_instruction,
              &explicit_instruction,
              sizeof(generic_instruction))
        == 0);
    {
        cdisasm_arm_instruction expected;

        memset(&expected, 0, sizeof(expected));
        expected.last_error_id = (uint8_t)CDISASM_STATUS_INVALID_ARGUMENT;
        EXPECT(memcmp(
                  &generic_instruction,
                  &expected,
                  sizeof(generic_instruction))
            == 0);
    }

    EXPECT(cdisasm_decode(
              CDISASM_ARM_CPU_CORTEX_A7,
              CDISASM_ARM_MODE_A32,
              add_r0_r1_5,
              sizeof(add_r0_r1_5),
              UINT64_C(0),
              NULL,
              NULL)
        == 0);
}
#endif

int main(void)
{
    test_unknown_and_disabled_groups();
    test_checked_dispatch_contract();
    test_decode_flag_queries();

#if USE_ARCH_X86
    test_x86_dispatch();
#endif
#if USE_ARCH_ARM
    test_arm_dispatch();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d dispatcher test(s) failed\n", failures);
        return 1;
    }
    puts("all dispatcher tests passed");
    return 0;
}
