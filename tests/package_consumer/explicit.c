#include <cdisasm/cdisasm.h>

#include <stdio.h>

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
typedef uint32_t (CDISASM_CALL *generic_decode_function)(
    cdisasm_cpu_id,
    uint32_t,
    const uint8_t *,
    size_t,
    uint64_t,
    const cdisasm_decode_flags *,
    void *);
typedef cdisasm_status (CDISASM_CALL *generic_flag_query_function)(
    cdisasm_cpu_id,
    uint32_t,
    cdisasm_decode_flags *);
typedef uint32_t (CDISASM_CALL *generic_decode_checked_function)(
    cdisasm_cpu_id,
    uint32_t,
    const uint8_t *,
    size_t,
    uint64_t,
    const cdisasm_decode_flags *,
    void *,
    size_t);
_Static_assert(
    _Generic(&cdisasm_decode, generic_decode_function: 1, default: 0),
    "installed generic decode signature changed");
_Static_assert(
    _Generic(&cdisasm_cpu_decode_flag_mask,
        generic_flag_query_function: 1, default: 0),
    "installed generic flag-query signature changed");
_Static_assert(
    _Generic(&cdisasm_decode_checked,
        generic_decode_checked_function: 1, default: 0),
    "installed checked generic decode signature changed");
#if USE_ARCH_X86
_Static_assert(sizeof(cdisasm_x86_decode_option) == 8,
               "installed x86 decode-option width changed");
_Static_assert(sizeof(cdisasm_x86_decode_flags)
                   == sizeof(cdisasm_decode_flags),
               "installed x86 decode-flags ABI size changed");
typedef uint32_t (CDISASM_CALL *x86_decode_function)(
    cdisasm_cpu_id,
    cdisasm_mode,
    const uint8_t *,
    size_t,
    uint64_t,
    const cdisasm_x86_decode_flags *,
    cdisasm_instruction *);
typedef cdisasm_status (CDISASM_CALL *x86_flag_query_function)(
    cdisasm_x86_cpu_id,
    cdisasm_x86_mode,
    cdisasm_x86_decode_flags *);
_Static_assert(
    _Generic(&cdisasm_x86_decode, x86_decode_function: 1, default: 0),
    "installed x86 decode signature changed");
_Static_assert(
    _Generic(&cdisasm_x86_cpu_decode_flag_mask,
        x86_flag_query_function: 1, default: 0),
    "installed x86 flag-query signature changed");
#endif
#if USE_ARCH_ARM
_Static_assert(sizeof(cdisasm_arm_decode_option) == 8,
               "installed ARM decode-option width changed");
_Static_assert(sizeof(cdisasm_arm_decode_flags)
                   == sizeof(cdisasm_decode_flags),
               "installed ARM decode-flags ABI size changed");
typedef uint32_t (CDISASM_CALL *arm_decode_function)(
    cdisasm_arm_cpu_id,
    cdisasm_arm_mode,
    const uint8_t *,
    size_t,
    uint64_t,
    const cdisasm_arm_decode_flags *,
    cdisasm_arm_instruction *);
typedef cdisasm_status (CDISASM_CALL *arm_flag_query_function)(
    cdisasm_arm_cpu_id,
    cdisasm_arm_mode,
    cdisasm_arm_decode_flags *);
_Static_assert(
    _Generic(&cdisasm_arm_decode, arm_decode_function: 1, default: 0),
    "installed ARM decode signature changed");
_Static_assert(
    _Generic(&cdisasm_arm_cpu_decode_flag_mask,
        arm_flag_query_function: 1, default: 0),
    "installed ARM flag-query signature changed");
#endif

static int failures;

#define CHECK(condition) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "%s:%d: check failed: %s\n", \
                __FILE__, __LINE__, #condition); \
            ++failures; \
        } \
    } while (0)

#if USE_ARCH_X86
static void check_explicit_x86(void)
{
    static const uint8_t nop[] = { UINT8_C(0x90) };
    cdisasm_x86_instruction instruction;
    cdisasm_x86_decode_flags available =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    cdisasm_decode_flags generic_available =
        CDISASM_DECODE_FLAGS_NONE_INITIALIZER;

    CHECK(cdisasm_x86_cpu_mode_mask(CDISASM_CPU_80386)
        == (CDISASM_X86_MODE_MASK_16 | CDISASM_X86_MODE_MASK_32));
    CHECK(cdisasm_cpu_decode_flag_mask(
              CDISASM_CPU_80386,
              CDISASM_X86_MODE_32,
              &generic_available)
        == CDISASM_STATUS_OK);
#if USE_EXTRA_OPCODES
    CHECK(cdisasm_x86_cpu_decode_flag_mask(
              CDISASM_CPU_PENTIUM_III, CDISASM_X86_MODE_32, &available)
        == CDISASM_STATUS_OK);
    CHECK((available.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP]
            & CDISASM_X86_DECODE_FLAG_SSE)
        != 0u);
#else
    CHECK(cdisasm_x86_cpu_decode_flag_mask(
              CDISASM_CPU_PENTIUM_III, CDISASM_X86_MODE_32, &available)
        == CDISASM_STATUS_OK);
    CHECK(available.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP]
        == 0u);
#endif

    CHECK(cdisasm_x86_decode(
              CDISASM_CPU_80386,
              CDISASM_X86_MODE_32,
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
}
#endif

#if USE_ARCH_ARM
static void check_explicit_arm(void)
{
    static const uint8_t add_r0_r1_5[] = {
        UINT8_C(0x05), UINT8_C(0x00), UINT8_C(0x81), UINT8_C(0xe2)
    };
    cdisasm_arm_instruction instruction;
    cdisasm_arm_decode_flags available =
        CDISASM_ARM_DECODE_FLAGS_NONE_INITIALIZER;
    cdisasm_arm_decode_flags invalid_flags =
        CDISASM_ARM_DECODE_FLAGS_NONE_INITIALIZER;

    CHECK((cdisasm_arm_decoder_mode_mask(CDISASM_ARM_CPU_CORTEX_A7)
              & CDISASM_ARM_MODE_MASK_A32)
        != 0);
    CHECK(cdisasm_arm_cpu_decode_flag_mask(
              CDISASM_ARM_CPU_CORTEX_A7,
              CDISASM_ARM_MODE_A32,
              &available)
        == CDISASM_STATUS_OK);
    CHECK(available.bitmap[CDISASM_ARM_DECODE_FLAGS_OPTION_BITMAP]
        == CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN);
    CHECK(cdisasm_cpu_decode_flag_mask(
              CDISASM_ARM_CPU_CORTEX_A7,
              CDISASM_ARM_MODE_A32,
              &available)
        == CDISASM_STATUS_OK);
    CHECK(available.bitmap[CDISASM_ARM_DECODE_FLAGS_OPTION_BITMAP]
        == CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN);
    CHECK(cdisasm_arm_decode(
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

    invalid_flags.bitmap[0] = UINT64_C(0x100000000);
    CHECK(cdisasm_arm_decode(
              CDISASM_ARM_CPU_CORTEX_A7,
              CDISASM_ARM_MODE_A32,
              add_r0_r1_5,
              sizeof(add_r0_r1_5),
              UINT64_C(0),
              &invalid_flags,
              &instruction)
        == 0u);
    CHECK(instruction.last_error_id == CDISASM_STATUS_INVALID_ARGUMENT);
}
#endif

int main(void)
{
    CHECK(cdisasm_version()
        == ((uint32_t)CDISASM_VERSION_MAJOR << 16
            | (uint32_t)CDISASM_VERSION_MINOR << 8
            | (uint32_t)CDISASM_VERSION_PATCH));

#if USE_ARCH_X86
    check_explicit_x86();
#endif
#if USE_ARCH_ARM
    check_explicit_arm();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d explicit facade check(s) failed\n", failures);
        return 1;
    }
    puts("installed cdisasm explicit facade smoke test passed");
    return 0;
}
