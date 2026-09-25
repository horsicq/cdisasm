#include <cdisasm/cdisasm.h>

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

#if USE_ARCH_X86 && USE_ARCH_ARM
_Static_assert(
    CDISASM_X86_DECODE_FLAG_FPU == CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN,
    "bit zero is deliberately architecture-scoped by the CPU group");
#endif

#define DISPATCH_SENTINEL_SIZE 256u

typedef union dispatch_sentinel {
    uint64_t alignment;
    uint8_t bytes[DISPATCH_SENTINEL_SIZE];
} dispatch_sentinel;

static int failures;

#define CHECK(condition) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "%s:%d: check failed: %s\n", \
                __FILE__, __LINE__, #condition); \
            ++failures; \
        } \
    } while (0)

static void check_undispatched(uint32_t cpu_id, uint32_t mode)
{
    static const uint8_t code[] = { UINT8_C(0x90) };
    dispatch_sentinel instruction;
    dispatch_sentinel before;

    memset(&instruction, 0xa5, sizeof(instruction));
    memcpy(&before, &instruction, sizeof(before));

    CHECK(cdisasm_decode(
              cpu_id,
              mode,
              code,
              sizeof(code),
              UINT64_C(0x12345678),
              NULL,
              &instruction)
        == 0);
    CHECK(memcmp(&instruction, &before, sizeof(instruction)) == 0);
}

static void check_unknown_and_disabled_groups(void)
{
    static const uint8_t code[] = { UINT8_C(0x90) };
    cdisasm_decode_flags available;
    const cdisasm_decode_flags zero_flags =
        CDISASM_DECODE_FLAGS_NONE_INITIALIZER;

    check_undispatched(UINT32_C(0x00000001), UINT32_C(0));
    check_undispatched(UINT32_C(0x00030001), UINT32_C(0));
    check_undispatched(UINT32_MAX, UINT32_C(0));

    memset(&available, 0xa5, sizeof(available));
    CHECK(cdisasm_cpu_decode_flag_mask(
              UINT32_C(0x00030001), UINT32_C(0), &available)
        == CDISASM_STATUS_INVALID_ARGUMENT);
    CHECK(memcmp(&available, &zero_flags, sizeof(zero_flags)) == 0);
    CHECK(cdisasm_cpu_decode_flag_mask(
              CDISASM_CPU_GROUP_X86 | UINT32_C(1),
              UINT32_C(16),
              NULL)
        == CDISASM_STATUS_INVALID_ARGUMENT);

#if !USE_ARCH_X86
    check_undispatched(
        CDISASM_CPU_GROUP_X86 | UINT32_C(0x0001), UINT32_C(32));
#endif
#if !USE_ARCH_ARM
    check_undispatched(
        CDISASM_CPU_GROUP_ARM | UINT32_C(0x0001), UINT32_C(1));
#endif

    CHECK(cdisasm_decode(
              UINT32_C(0x00030001),
              UINT32_C(0),
              code,
              sizeof(code),
              UINT64_C(0),
              NULL,
              NULL)
        == 0);
}

#if USE_ARCH_X86
static void check_x86_dispatch(void)
{
    static const uint8_t nop[] = { UINT8_C(0x90) };
    static const uint8_t fld1[] = { UINT8_C(0xd9), UINT8_C(0xe8) };
    cdisasm_instruction instruction;
    cdisasm_decode_flags fpu_flags =
        CDISASM_X86_DECODE_FLAGS_INITIALIZER(
            CDISASM_X86_DECODE_FLAG_FPU);
    cdisasm_decode_flags all_flags =
        CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER;
    cdisasm_decode_flags last_word0_flag =
        CDISASM_X86_DECODE_FLAGS_INITIALIZER(
            CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16);
    uint32_t size;

    memset(&instruction, 0xa5, sizeof(instruction));
    CHECK(cdisasm_decode(
              CDISASM_CPU_80386,
              CDISASM_MODE_32,
              nop,
              sizeof(nop),
              UINT64_C(0x1000),
              NULL,
              &instruction)
        == sizeof(nop));
    CHECK(instruction.last_error_id == CDISASM_STATUS_OK);
    CHECK(instruction.opcode_size == sizeof(nop));
    CHECK(instruction.address == UINT64_C(0x1000));
    CHECK(instruction.name_id == CDISASM_X86_NAME_NOP);

    size = cdisasm_decode(
        CDISASM_CPU_80386_80387,
        CDISASM_MODE_32,
        fld1,
        sizeof(fld1),
        UINT64_C(0x1010),
        NULL,
        &instruction);
    CHECK(size == 0u);
    CHECK(instruction.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    size = cdisasm_decode(
        CDISASM_CPU_80386_80387,
        CDISASM_MODE_32,
        fld1,
        sizeof(fld1),
        UINT64_C(0x1010),
        &fpu_flags,
        &instruction);
#if USE_EXTRA_OPCODES
    CHECK(size == sizeof(fld1));
    CHECK(instruction.last_error_id == CDISASM_STATUS_OK);
    CHECK(instruction.name_id == CDISASM_X86_NAME_FLD1);
#else
    CHECK(size == 0u);
    CHECK(instruction.last_error_id == CDISASM_STATUS_INVALID_ARGUMENT);
#endif

    size = cdisasm_decode(
              CDISASM_CPU_80386,
              CDISASM_MODE_32,
              nop,
              sizeof(nop),
              UINT64_C(0),
              &all_flags,
              &instruction);
#if USE_EXTRA_OPCODES
    CHECK(size == sizeof(nop));
    CHECK(instruction.last_error_id == CDISASM_STATUS_OK);
#else
    CHECK(size == 0u);
    CHECK(instruction.last_error_id == CDISASM_STATUS_INVALID_ARGUMENT);
#endif

    memset(&instruction, 0xa5, sizeof(instruction));
    size = cdisasm_decode(
              CDISASM_CPU_80386,
              CDISASM_MODE_32,
              nop,
              sizeof(nop),
              UINT64_C(0),
              &last_word0_flag,
              &instruction);
#if USE_EXTRA_OPCODES
    CHECK(size == sizeof(nop));
    CHECK(instruction.last_error_id == CDISASM_STATUS_OK);
#else
    CHECK(size == 0u);
    CHECK(instruction.last_error_id == CDISASM_STATUS_INVALID_ARGUMENT);
#endif

    memset(&instruction, 0xa5, sizeof(instruction));
    CHECK(cdisasm_decode(
              CDISASM_CPU_GROUP_X86 | UINT32_C(0xffff),
              CDISASM_MODE_16,
              nop,
              sizeof(nop),
              UINT64_C(0),
              NULL,
              &instruction)
        == 0);
    CHECK(instruction.last_error_id == CDISASM_STATUS_INVALID_ARGUMENT);

    CHECK(cdisasm_decode(
              CDISASM_CPU_80386,
              CDISASM_MODE_32,
              nop,
              sizeof(nop),
              UINT64_C(0),
              NULL,
              NULL)
        == 0);
}
#endif

#if USE_ARCH_ARM
static void check_arm_dispatch(void)
{
    static const uint8_t add_r0_r1_5[] = {
        UINT8_C(0x05), UINT8_C(0x00), UINT8_C(0x81), UINT8_C(0xe2)
    };
    static const uint8_t add_r0_r1_5_be[] = {
        UINT8_C(0xe2), UINT8_C(0x81), UINT8_C(0x00), UINT8_C(0x05)
    };
    cdisasm_arm_instruction instruction;
    cdisasm_decode_flags big_endian_flags =
        CDISASM_ARM_DECODE_FLAGS_INITIALIZER(
            CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN);
    cdisasm_decode_flags invalid_flags =
        CDISASM_ARM_DECODE_FLAGS_INITIALIZER(
            UINT64_C(0x8000000000000000));

    memset(&instruction, 0xa5, sizeof(instruction));
    CHECK(cdisasm_decode(
              CDISASM_ARM_CPU_CORTEX_A7,
              CDISASM_ARM_MODE_A32,
              add_r0_r1_5,
              sizeof(add_r0_r1_5),
              UINT64_C(0x2000),
              NULL,
              &instruction)
        == sizeof(add_r0_r1_5));
    CHECK(instruction.last_error_id == CDISASM_STATUS_OK);
    CHECK(instruction.opcode_size == sizeof(add_r0_r1_5));
    CHECK(instruction.address == UINT64_C(0x2000));
    CHECK(instruction.name_id == CDISASM_ARM_NAME_ADD);
    CHECK(instruction.isa_id == CDISASM_ARM_ISA_A32);
    CHECK(instruction.operand_count == 3);
    CHECK(instruction.operand[0].reg == CDISASM_ARM_REG_R0);
    CHECK(instruction.operand[1].reg == CDISASM_ARM_REG_R1);
    CHECK(instruction.operand[2].imm == UINT64_C(5));

    CHECK(cdisasm_decode(
              CDISASM_ARM_CPU_CORTEX_A7,
              CDISASM_ARM_MODE_A32,
              add_r0_r1_5_be,
              sizeof(add_r0_r1_5_be),
              UINT64_C(0x2010),
              &big_endian_flags,
              &instruction)
        == sizeof(add_r0_r1_5_be));
    CHECK(instruction.last_error_id == CDISASM_STATUS_OK);
    CHECK(instruction.address == UINT64_C(0x2010));
    CHECK(instruction.name_id == CDISASM_ARM_NAME_ADD);

    memset(&instruction, 0xa5, sizeof(instruction));
    CHECK(cdisasm_decode(
              CDISASM_CPU_GROUP_ARM | UINT32_C(0xffff),
              CDISASM_ARM_MODE_A32,
              add_r0_r1_5,
              sizeof(add_r0_r1_5),
              UINT64_C(0),
              NULL,
              &instruction)
        == 0);
    CHECK(instruction.last_error_id == CDISASM_STATUS_INVALID_ARGUMENT);

    memset(&instruction, 0xa5, sizeof(instruction));
    CHECK(cdisasm_decode(
              CDISASM_ARM_CPU_CORTEX_A7,
              CDISASM_ARM_MODE_A32,
              add_r0_r1_5,
              sizeof(add_r0_r1_5),
              UINT64_C(0),
              &invalid_flags,
              &instruction)
        == 0);
    {
        cdisasm_arm_instruction expected;

        memset(&expected, 0, sizeof(expected));
        expected.last_error_id = (uint8_t)CDISASM_STATUS_INVALID_ARGUMENT;
        CHECK(memcmp(&instruction, &expected, sizeof(expected)) == 0);
    }

    CHECK(cdisasm_decode(
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
    CHECK(cdisasm_version()
        == ((uint32_t)CDISASM_VERSION_MAJOR << 16
            | (uint32_t)CDISASM_VERSION_MINOR << 8
            | (uint32_t)CDISASM_VERSION_PATCH));
    check_unknown_and_disabled_groups();

#if USE_ARCH_X86
    check_x86_dispatch();
#endif
#if USE_ARCH_ARM
    check_arm_dispatch();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d installed dispatcher check(s) failed\n", failures);
        return 1;
    }
    puts("installed cdisasm dispatcher smoke test passed");
    return 0;
}
