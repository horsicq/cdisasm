#include "cdisasm/cdisasm_common.h"

#if USE_ARCH_X86
#  include "cdisasm/cdisasm_x86.h"
#endif

#if USE_ARCH_ARM
#  include "cdisasm/cdisasm_arm.h"
#endif

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define EXPECT(expression)                                                   \
    do {                                                                     \
        if (!(expression)) {                                                 \
            fprintf(stderr, "%s:%d: expectation failed: %s\n",             \
                    __FILE__, __LINE__, #expression);                        \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(USE_EXTRA_OPCODES == 0 || USE_EXTRA_OPCODES == 1,
               "USE_EXTRA_OPCODES must be a numeric public feature macro");
_Static_assert(sizeof(cdisasm_cpu_id) == 4,
               "cdisasm_cpu_id ABI changed");
_Static_assert(sizeof(cdisasm_decode_option) == 8,
               "generic bitmap-word ABI width changed");
_Static_assert(sizeof(cdisasm_decode_flags) == 64,
               "generic decode flags must remain 64 bytes");
_Static_assert(CDISASM_DECODE_FLAGS_BITMAP_COUNT == 8,
               "generic decode flags must have eight bitmap words");
_Static_assert(CDISASM_CPU_GROUP_X86 == UINT32_C(0x00010000),
               "x86 CPU group ID changed");
_Static_assert(CDISASM_CPU_GROUP_ARM == UINT32_C(0x00020000),
               "ARM CPU group ID changed");

#if USE_ARCH_X86
/* These assertions are deliberately independent of USE_EXTRA_OPCODES.  New
 * IDs may only be appended, so established values and result layout remain
 * identical in an ON or OFF build. */
_Static_assert(CDISASM_MAX_OPERANDS == 5,
               "x86 operand capacity changed");
_Static_assert(CDISASM_MAX_X86_GROUPS == 15,
               "x86 group capacity changed");
_Static_assert(sizeof(cdisasm_opcode) == 32,
               "x86 operand ABI changed");
_Static_assert(sizeof(cdisasm_x86_encoding) == 16,
               "x86 encoding ABI changed");
_Static_assert(sizeof(cdisasm_x86_instruction) == 248,
               "x86 instruction ABI changed");
_Static_assert(offsetof(cdisasm_x86_instruction, name_id) == 28,
               "x86 name ID offset changed");
_Static_assert(offsetof(cdisasm_x86_instruction, opcode) == 32,
               "x86 operand offset changed");
_Static_assert(offsetof(cdisasm_x86_instruction, x86_group_count) == 192,
               "x86 group-count offset changed");
_Static_assert(offsetof(cdisasm_x86_instruction, x86_group_ids) == 194,
               "x86 group-list offset changed");
_Static_assert(offsetof(cdisasm_x86_instruction, mask_reg) == 224,
               "x86 mask offset changed");
_Static_assert(offsetof(cdisasm_x86_instruction, encoding) == 232,
               "x86 encoding offset changed");

_Static_assert(CDISASM_X86_NAME_VADDPS == UINT16_C(610),
               "established x86 mnemonic ID changed");
_Static_assert(CDISASM_X86_NAME_VPSADBW == UINT16_C(669),
               "established x86 mnemonic ID changed");
_Static_assert(CDISASM_X86_NAME_COUNT >= UINT16_C(670),
               "established x86 mnemonic IDs disappeared");
_Static_assert(CDISASM_X86_NAME_COUNT == CDISASM_X86_NAME_LAST + 1,
               "x86 mnemonic IDs are not contiguous");
_Static_assert(CDISASM_X86_REG_ZMM0 == UINT16_C(192),
               "established x86 register ID changed");
_Static_assert(CDISASM_X86_REG_K0 == UINT16_C(224),
               "established x86 register ID changed");
_Static_assert(CDISASM_X86_REG_TMM0 == UINT16_C(236),
               "established x86 register ID changed");
_Static_assert(CDISASM_X86_REG_R16B == UINT16_C(244),
               "established x86 register ID changed");
_Static_assert(CDISASM_X86_REG_R31 == UINT16_C(307),
               "established x86 register ID changed");
_Static_assert(CDISASM_X86_REG_BSR0 == UINT16_C(308),
               "BSR0 register ID changed");
_Static_assert(CDISASM_X86_REG_COUNT >= UINT16_C(309),
               "established x86 register IDs disappeared");
_Static_assert(CDISASM_X86_REG_COUNT == CDISASM_X86_REG_LAST + 1,
               "x86 register IDs are not contiguous");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37),
               "established x86 group ID changed");
_Static_assert(CDISASM_X86_GROUP_AVX2 == UINT16_C(46),
               "established x86 group ID changed");
_Static_assert(CDISASM_X86_GROUP_APX_F == UINT16_C(91),
               "established x86 group ID changed");
_Static_assert(CDISASM_X86_GROUP_COUNT >= UINT16_C(93),
               "established x86 group IDs disappeared");
_Static_assert(CDISASM_X86_GROUP_COUNT == CDISASM_X86_GROUP_LAST + 1,
               "x86 group IDs are not contiguous");
_Static_assert(sizeof(cdisasm_x86_decode_option) == 8,
               "x86 bitmap-word ABI width changed");
_Static_assert(sizeof(cdisasm_x86_decode_flags)
                   == sizeof(cdisasm_decode_flags),
               "x86 decode flags differ from the common ABI size");
_Static_assert(CDISASM_X86_DECODE_FLAG_BASE == UINT64_C(0),
               "x86 base decode flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_FPU == UINT64_C(0x00000001),
               "x86 FPU decode flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_UNDOCUMENTED
                   == UINT64_C(0x40000000),
               "x86 decode-flag tail changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX512_VBMI2
                   == UINT64_C(0x200000000),
               "x86 AVX512_VBMI2 decode flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ
                   == UINT64_C(0x400000000),
               "x86 AVX512_VPOPCNTDQ decode flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX512_BITALG
                   == UINT64_C(0x800000000),
               "x86 AVX512_BITALG decode flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND
                   == UINT64_C(0x1000000000),
               "x86 compress/expand decode flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_BMI2
                   == UINT64_C(0x800000000000000),
               "x86 decode-flag tail changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX512_CD
                   == UINT64_C(0x1000000000000000),
               "x86 AVX512_CD decode flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX_VNNI
                   == UINT64_C(0x2000000000000000),
               "x86 AVX_VNNI decode flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT8
                   == UINT64_C(0x4000000000000000),
               "x86 AVX_VNNI_INT8 decode flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16
                   == UINT64_C(0x8000000000000000),
               "x86 AVX_VNNI_INT16 decode flag changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_ALL
                   == UINT64_C(0xffffffffffffffff),
               "x86 all-family decode mask changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_KNOWN_MASK
                   == UINT64_C(0xffffffffffffffff),
               "x86 known decode mask changed");

static void check_x86_appended_base_instruction(
    const uint8_t *bytes,
    size_t byte_count,
    cdisasm_x86_mode mode,
    cdisasm_x86_name_id expected_name
#if USE_DISASM_FORMAT
    , const char *expected_text
#endif
)
{
    cdisasm_x86_instruction instruction;
    uint32_t decoded_size;

    memset(&instruction, 0xa5, sizeof(instruction));
    decoded_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        mode,
        bytes,
        byte_count,
        UINT64_C(0x1000),
        NULL,
        &instruction);
    EXPECT(decoded_size == byte_count);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == expected_name);
#if USE_DISASM_FORMAT
    {
        char text[64];
        size_t text_size = cdisasm_x86_format(
            &instruction,
            CDISASM_FORMAT_SYNTAX_INTEL,
            text,
            sizeof(text));

        EXPECT(text_size == strlen(expected_text));
        EXPECT(strcmp(text, expected_text) == 0);
    }
#endif
}

static void test_x86_appended_base_contract(void)
{
    static const uint8_t bound[] = {UINT8_C(0x62), UINT8_C(0x00)};
    static const uint8_t lds[] = {UINT8_C(0xc5), UINT8_C(0x00)};
    static const uint8_t les[] = {UINT8_C(0xc4), UINT8_C(0x00)};
    static const uint8_t cmpxchg8b[] = {
        UINT8_C(0x0f), UINT8_C(0xc7), UINT8_C(0x08)
    };
    static const uint8_t cmpxchg16b[] = {
        UINT8_C(0x48), UINT8_C(0x0f), UINT8_C(0xc7), UINT8_C(0x08)
    };

    check_x86_appended_base_instruction(
        bound,
        sizeof(bound),
        CDISASM_MODE_32,
        CDISASM_X86_NAME_BOUND
#if USE_DISASM_FORMAT
        , "bound eax, qword ptr [eax]"
#endif
    );
    check_x86_appended_base_instruction(
        lds,
        sizeof(lds),
        CDISASM_MODE_32,
        CDISASM_X86_NAME_LDS
#if USE_DISASM_FORMAT
        , "lds eax, fword ptr [eax]"
#endif
    );
    check_x86_appended_base_instruction(
        les,
        sizeof(les),
        CDISASM_MODE_32,
        CDISASM_X86_NAME_LES
#if USE_DISASM_FORMAT
        , "les eax, fword ptr [eax]"
#endif
    );
    check_x86_appended_base_instruction(
        cmpxchg8b,
        sizeof(cmpxchg8b),
        CDISASM_MODE_64,
        CDISASM_X86_NAME_CMPXCHG8B
#if USE_DISASM_FORMAT
        , "cmpxchg8b qword ptr [rax]"
#endif
    );
    check_x86_appended_base_instruction(
        cmpxchg16b,
        sizeof(cmpxchg16b),
        CDISASM_MODE_64,
        CDISASM_X86_NAME_CMPXCHG16B
#if USE_DISASM_FORMAT
        , "cmpxchg16b xmmword ptr [rax]"
#endif
    );
}

static void test_x86_optional_contract(void)
{
    static const uint8_t vaddps[] = {
        UINT8_C(0xc5), UINT8_C(0xe8), UINT8_C(0x58), UINT8_C(0xcb)
    };
    static const cdisasm_x86_decode_flags avx_flags =
        CDISASM_X86_DECODE_FLAGS_INITIALIZER(
            CDISASM_X86_DECODE_FLAG_AVX);
    static const cdisasm_x86_decode_flags avx_vnni_int16_flags =
        CDISASM_X86_DECODE_FLAGS_INITIALIZER(
            CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16);
    static const cdisasm_x86_decode_flags all_flags =
        CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER;
    cdisasm_x86_decode_flags high_flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    cdisasm_x86_instruction base_instruction;
    cdisasm_x86_instruction instruction;
    uint32_t decoded_size;

    memset(&base_instruction, 0xa5, sizeof(base_instruction));
    decoded_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_MODE_64,
        vaddps,
        sizeof(vaddps),
        UINT64_C(0x1000),
        NULL,
        &base_instruction);
    {
        cdisasm_x86_instruction expected;

        memset(&expected, 0, sizeof(expected));
        expected.last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        EXPECT(decoded_size == 0);
        EXPECT(memcmp(
            &base_instruction, &expected, sizeof(expected)) == 0);
    }

    memset(&instruction, 0xa5, sizeof(instruction));
    decoded_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_MODE_64,
        vaddps,
        sizeof(vaddps),
        UINT64_C(0x1000),
        &avx_flags,
        &instruction);

#if USE_EXTRA_OPCODES
    EXPECT(decoded_size == sizeof(vaddps));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.opcode_size == sizeof(vaddps));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VADDPS);
    EXPECT(instruction.operand_count == 3);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX));
#  if USE_DISASM_FORMAT
    {
        char text[64];
        size_t text_size = cdisasm_x86_format(
            &instruction,
            CDISASM_FORMAT_SYNTAX_INTEL,
            text,
            sizeof(text));

        EXPECT(text_size == strlen("vaddps xmm1, xmm2, xmm3"));
        EXPECT(strcmp(text, "vaddps xmm1, xmm2, xmm3") == 0);
    }
#  endif
#else
    {
        cdisasm_x86_instruction expected;

        memset(&expected, 0, sizeof(expected));
        expected.last_error_id = CDISASM_STATUS_INVALID_ARGUMENT;
        EXPECT(decoded_size == 0);
        EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
    }
#  if USE_DISASM_FORMAT
    {
        cdisasm_x86_instruction synthetic;
        char text[32] = "not empty";

        EXPECT(cdisasm_x86_format(
            &instruction,
            CDISASM_FORMAT_SYNTAX_INTEL,
            text,
            sizeof(text)) == 0);
        EXPECT(text[0] == '\0');

        memset(&synthetic, 0, sizeof(synthetic));
        synthetic.opcode_size = sizeof(vaddps);
        synthetic.name_id = CDISASM_X86_NAME_VADDPS;
        text[0] = 'x';
        text[1] = '\0';
        EXPECT(cdisasm_x86_format(
            &synthetic,
            CDISASM_FORMAT_SYNTAX_INTEL,
            text,
            sizeof(text)) == 0);
        EXPECT(text[0] == '\0');
    }
#  endif
#endif

    memset(&instruction, 0xa5, sizeof(instruction));
    decoded_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_MODE_64,
        vaddps,
        sizeof(vaddps),
        UINT64_C(0x1000),
        &avx_vnni_int16_flags,
        &instruction);
    {
        cdisasm_x86_instruction expected;

        memset(&expected, 0, sizeof(expected));
#if USE_EXTRA_OPCODES
        expected.last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        expected.last_error_id = CDISASM_STATUS_INVALID_ARGUMENT;
#endif
        EXPECT(decoded_size == 0);
        EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
    }

    memset(&instruction, 0xa5, sizeof(instruction));
    decoded_size = cdisasm_x86_decode(
        CDISASM_CPU_X86,
        CDISASM_MODE_64,
        vaddps,
        sizeof(vaddps),
        UINT64_C(0x1000),
        &all_flags,
        &instruction);
#if USE_EXTRA_OPCODES
    EXPECT(decoded_size == sizeof(vaddps));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VADDPS);
#else
    {
        cdisasm_x86_instruction expected;

        memset(&expected, 0, sizeof(expected));
        expected.last_error_id = CDISASM_STATUS_INVALID_ARGUMENT;
        EXPECT(decoded_size == 0);
        EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
    }
#endif

    high_flags.bitmap[CDISASM_DECODE_FLAGS_BITMAP_COUNT - 1u] =
        UINT64_C(1);
    memset(&instruction, 0xa5, sizeof(instruction));
    decoded_size = cdisasm_x86_decode(
        CDISASM_CPU_X86, CDISASM_MODE_64, vaddps, sizeof(vaddps),
        UINT64_C(0), &high_flags, &instruction);
    EXPECT(decoded_size == 0);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_ARGUMENT);
}
#endif

#if USE_ARCH_ARM
_Static_assert(sizeof(cdisasm_arm_decode_option) == 8,
               "ARM bitmap-word ABI width changed");
_Static_assert(sizeof(cdisasm_arm_decode_flags)
                   == sizeof(cdisasm_decode_flags),
               "ARM decode flags differ from the common ABI size");
_Static_assert(CDISASM_ARM_MAX_OPERANDS == 4,
               "ARM operand capacity changed");
_Static_assert(CDISASM_ARM_OPERAND_FLAG_HAS_ROTATION == UINT8_C(128),
               "ARM packed-rotation flag moved");
_Static_assert(sizeof(cdisasm_arm_operand) == 32,
               "ARM operand ABI changed");
_Static_assert(sizeof(cdisasm_arm_instruction) == 168,
               "ARM instruction ABI changed");
_Static_assert(offsetof(cdisasm_arm_instruction, raw_instruction) == 24,
               "ARM raw-instruction offset changed");
_Static_assert(offsetof(cdisasm_arm_instruction, name_id) == 32,
               "ARM name ID offset changed");
_Static_assert(offsetof(cdisasm_arm_instruction, last_error_id) == 34,
               "ARM status offset changed");
_Static_assert(offsetof(cdisasm_arm_instruction, operand) == 40,
               "ARM operand offset changed");

_Static_assert(CDISASM_ARM_NAME_CASB == UINT16_C(132),
               "established ARM mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_LDAPR == UINT16_C(216),
               "established ARM mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_COUNT >= UINT16_C(217),
               "established ARM mnemonic IDs disappeared");
_Static_assert(CDISASM_ARM_NAME_COUNT == CDISASM_ARM_NAME_LAST + 1,
               "ARM mnemonic IDs are not contiguous");
_Static_assert(CDISASM_ARM_REG_CPM_IOACC_CTL_EL3 == UINT16_C(163),
               "established ARM register ID changed");
_Static_assert(CDISASM_ARM_REG_COUNT >= UINT16_C(164),
               "established ARM register IDs disappeared");
_Static_assert(CDISASM_ARM_REG_COUNT == CDISASM_ARM_REG_LAST + 1,
               "ARM register IDs are not contiguous");
_Static_assert(CDISASM_ARM_OPERAND_REGISTER_PAIR == UINT8_C(5),
               "ARM register-pair operand type changed");

static void test_arm_optional_contract(void)
{
    static const uint8_t casb[] = {
        UINT8_C(0x41), UINT8_C(0x7c), UINT8_C(0xa0), UINT8_C(0x08)
    };
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction zero_instruction;
    cdisasm_arm_decode_flags no_flags =
        CDISASM_ARM_DECODE_FLAGS_NONE_INITIALIZER;
    cdisasm_arm_decode_flags high_flags =
        CDISASM_ARM_DECODE_FLAGS_NONE_INITIALIZER;
    uint32_t decoded_size;
    uint32_t zero_size;

    memset(&instruction, 0xa5, sizeof(instruction));
    decoded_size = cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64,
        casb,
        sizeof(casb),
        UINT64_C(0x2000),
        NULL,
        &instruction);
    memset(&zero_instruction, 0x5a, sizeof(zero_instruction));
    zero_size = cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64,
        casb,
        sizeof(casb),
        UINT64_C(0x2000),
        &no_flags,
        &zero_instruction);
    EXPECT(zero_size == decoded_size);
    EXPECT(memcmp(&zero_instruction, &instruction, sizeof(instruction)) == 0);

#if USE_EXTRA_OPCODES
    EXPECT(decoded_size == sizeof(casb));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.opcode_size == sizeof(casb));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_CASB);
    EXPECT(instruction.operand_count == 3);
    EXPECT((instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC) != 0);
#  if USE_DISASM_FORMAT
    {
        char text[64];
        size_t text_size = cdisasm_arm_format(
            &instruction,
            CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            text,
            sizeof(text));

        EXPECT(text_size == strlen("casb w0, w1, [x2]"));
        EXPECT(strcmp(text, "casb w0, w1, [x2]") == 0);
    }
#  endif
#else
    {
        cdisasm_arm_instruction expected;

        memset(&expected, 0, sizeof(expected));
        expected.last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        EXPECT(decoded_size == 0);
        EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
    }
#  if USE_DISASM_FORMAT
    {
        cdisasm_arm_instruction synthetic;
        char text[32] = "not empty";

        EXPECT(cdisasm_arm_format(
            &instruction,
            CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            text,
            sizeof(text)) == 0);
        EXPECT(text[0] == '\0');

        memset(&synthetic, 0, sizeof(synthetic));
        synthetic.opcode_size = sizeof(casb);
        synthetic.name_id = CDISASM_ARM_NAME_CASB;
        synthetic.condition = CDISASM_ARM_CONDITION_AL;
        synthetic.isa_id = CDISASM_ARM_ISA_A64;
        text[0] = 'x';
        text[1] = '\0';
        EXPECT(cdisasm_arm_format(
            &synthetic,
            CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            text,
            sizeof(text)) == 0);
        EXPECT(text[0] == '\0');
    }
#  endif
#endif

    high_flags.bitmap[1] = UINT64_C(1);
    memset(&instruction, 0xa5, sizeof(instruction));
    decoded_size = cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, casb, sizeof(casb),
        UINT64_C(0), &high_flags, &instruction);
    EXPECT(decoded_size == 0);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_ARGUMENT);
}
#endif

int main(void)
{
#if USE_ARCH_X86
    test_x86_appended_base_contract();
    test_x86_optional_contract();
#endif
#if USE_ARCH_ARM
    test_arm_optional_contract();
#endif

    if (failures != 0) {
        fprintf(stderr,
                "extra-opcode contract failed with %d error(s) "
                "(USE_EXTRA_OPCODES=%d)\n",
                failures,
                USE_EXTRA_OPCODES);
        return 1;
    }
    printf("extra-opcode ABI/policy contract passed "
           "(USE_EXTRA_OPCODES=%d)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
