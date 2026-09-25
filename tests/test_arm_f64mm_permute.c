#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_ZIP1 == UINT16_C(348),
               "F64MM permute IDs must reuse the established catalog");
_Static_assert(CDISASM_ARM_NAME_TRN2 == UINT16_C(353),
               "F64MM permute terminal ID changed");
_Static_assert(CDISASM_ARM_NAME_COUNT == CDISASM_ARM_NAME_LAST + 1u,
               "ARM mnemonic IDs must remain contiguous");

static int failures;

#define EXPECT(condition) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "%s:%d: expectation failed: %s\n", \
                    __FILE__, __LINE__, #condition); \
            ++failures; \
        } \
    } while (0)

static void domain_expect(int condition, uint32_t word, const char *what)
{
    if (!condition) {
        if (failures < 20) {
            fprintf(stderr, "word %08x: %s\n", (unsigned)word, what);
        }
        ++failures;
    }
}

static uint32_t f64mm_permute_word(
    unsigned operation, unsigned zd, unsigned zn, unsigned zm)
{
    return UINT32_C(0x05a00000)
        | ((uint32_t)operation << 10)
        | ((uint32_t)zm << 16)
        | ((uint32_t)zn << 5)
        | (uint32_t)zd;
}

static void word_to_le(uint32_t word, uint8_t bytes[4])
{
    bytes[0] = (uint8_t)word;
    bytes[1] = (uint8_t)(word >> 8);
    bytes[2] = (uint8_t)(word >> 16);
    bytes[3] = (uint8_t)(word >> 24);
}

static void word_to_be(uint32_t word, uint8_t bytes[4])
{
    bytes[0] = (uint8_t)(word >> 24);
    bytes[1] = (uint8_t)(word >> 16);
    bytes[2] = (uint8_t)(word >> 8);
    bytes[3] = (uint8_t)word;
}

static uint32_t decode_word(
    uint32_t word,
    cdisasm_arm_cpu_id cpu_id,
    size_t code_size,
    cdisasm_arm_decode_option options,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(
        cpu_id, CDISASM_ARM_MODE_A64, bytes, code_size,
        UINT64_C(0x6400), options, instruction);
}

static int instruction_is_error_only(
    const cdisasm_arm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

#if USE_EXTRA_OPCODES
static cdisasm_arm_name_id operation_name(unsigned operation)
{
    static const cdisasm_arm_name_id names[8] = {
        CDISASM_ARM_NAME_ZIP1,
        CDISASM_ARM_NAME_ZIP2,
        CDISASM_ARM_NAME_UZP1,
        CDISASM_ARM_NAME_UZP2,
        CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_TRN1,
        CDISASM_ARM_NAME_TRN2
    };

    return names[operation];
}

static void build_expected_instruction(
    uint32_t word,
    unsigned operation,
    unsigned zd,
    unsigned zn,
    unsigned zm,
    cdisasm_arm_instruction *expected)
{
    static const cdisasm_arm_form_id form_ids[8] = {
        UINT16_C(2433), UINT16_C(2436), UINT16_C(2434), UINT16_C(2437),
        0u, 0u, UINT16_C(2435), UINT16_C(2438)
    };

    memset(expected, 0, sizeof(*expected));
    expected->address = UINT64_C(0x6400);
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR;
    expected->name_id = operation_name(operation);
    expected->operand_count = 3u;
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->form_id = form_ids[operation];

    expected->operand[0].type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    expected->operand[0].reg =
        (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zd);
    expected->operand[0].extend_type = (cdisasm_arm_extend_type)16u;
    expected->operand[0].access = CDISASM_OPERAND_ACCESS_WRITE;

    expected->operand[1].type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    expected->operand[1].reg =
        (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zn);
    expected->operand[1].extend_type = (cdisasm_arm_extend_type)16u;
    expected->operand[1].access = CDISASM_OPERAND_ACCESS_READ;

    expected->operand[2].type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    expected->operand[2].reg =
        (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zm);
    expected->operand[2].extend_type = (cdisasm_arm_extend_type)16u;
    expected->operand[2].access = CDISASM_OPERAND_ACCESS_READ;
}
#endif

static void test_exact_allocated_and_reserved_domain(void)
{
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    unsigned operation;

    for (operation = 0u; operation < 8u; ++operation) {
        unsigned zm;

        for (zm = 0u; zm < 32u; ++zm) {
            unsigned zn;

            for (zn = 0u; zn < 32u; ++zn) {
                unsigned zd;

                for (zd = 0u; zd < 32u; ++zd) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = f64mm_permute_word(
                        operation, zd, zn, zm);
                    int valid = operation < 4u || operation >= 6u;
                    uint32_t decoded;

                    memset(&instruction, 0xa5, sizeof(instruction));
                    decoded = decode_word(
                        word, CDISASM_ARM_CPU_ANY, 4u,
                        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                    if (valid) {
                        ++allocated;
#if USE_EXTRA_OPCODES
                        cdisasm_arm_instruction expected;

                        build_expected_instruction(
                            word, operation, zd, zn, zm, &expected);
                        domain_expect(decoded == 4u, word,
                                      "allocated form did not decode");
                        domain_expect(
                            memcmp(&instruction, &expected,
                                   sizeof(expected)) == 0,
                            word, "allocated metadata mismatch");
#else
                        domain_expect(decoded == 0u, word,
                                      "OFF build decoded allocated form");
                        domain_expect(
                            instruction_is_error_only(
                                &instruction,
                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                            word, "OFF-build allocated status mismatch");
#endif
                    } else {
                        ++reserved;
                        domain_expect(decoded == 0u, word,
                                      "reserved control decoded");
                        domain_expect(
                            instruction_is_error_only(
                                &instruction,
                                CDISASM_STATUS_INVALID_INSTRUCTION),
                            word, "reserved control status mismatch");
                    }
                }
            }
        }
    }

    EXPECT(allocated == UINT32_C(196608));
    EXPECT(reserved == UINT32_C(65536));
    EXPECT(allocated + reserved == UINT32_C(262144));
}

static void test_cpu_feature_boundary(void)
{
    uint32_t cpu_value;

    for (cpu_value = CDISASM_ARM_CPU_FIRST;
         cpu_value <= CDISASM_ARM_CPU_LAST;
         ++cpu_value) {
        cdisasm_arm_cpu_id cpu_id = (cdisasm_arm_cpu_id)cpu_value;
        cdisasm_arm_instruction instruction;
        cdisasm_status expected_status;

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            f64mm_permute_word(0u, 0u, 1u, 2u), cpu_id, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        if ((cdisasm_arm_cpu_mode_mask(cpu_id)
                & CDISASM_ARM_MODE_MASK_A64) == 0u) {
            expected_status = CDISASM_STATUS_INVALID_ARGUMENT;
#if USE_EXTRA_OPCODES
        } else {
            expected_status = CDISASM_STATUS_INVALID_INSTRUCTION;
#else
        } else {
            expected_status = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
        }
        EXPECT(instruction_is_error_only(&instruction, expected_status));
    }

    /* SVE and SME are not substitutes for the independent F64MM feature. */
    {
        static const cdisasm_arm_cpu_id independent_profiles[] = {
            CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_ARM_CPU_APPLE_M4
        };
        size_t index;

        for (index = 0u;
             index < sizeof(independent_profiles)
                    / sizeof(independent_profiles[0]);
             ++index) {
            cdisasm_arm_instruction instruction;

            memset(&instruction, 0xa5, sizeof(instruction));
            EXPECT(decode_word(
                f64mm_permute_word(7u, 31u, 0u, 30u),
                independent_profiles[index], 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
#if USE_EXTRA_OPCODES
            EXPECT(instruction_is_error_only(
                &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
#else
            EXPECT(instruction_is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }
}

static void test_endian_dispatch_and_boundaries(void)
{
    const uint32_t word = f64mm_permute_word(7u, 31u, 0u, 17u);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction big;
    cdisasm_arm_instruction generic;
    uint8_t little_bytes[4];
    uint8_t big_bytes[4];
    uint32_t decoded;
    size_t code_size;

    memset(&little, 0xa5, sizeof(little));
    decoded = decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
    EXPECT(instruction_is_error_only(
        &little, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif

    word_to_be(word, big_bytes);
    memset(&big, 0xa5, sizeof(big));
    decoded = cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        big_bytes, sizeof(big_bytes), UINT64_C(0x6400),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &big);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&little, &big, sizeof(little)) == 0);

    word_to_le(word, little_bytes);
    memset(&generic, 0xa5, sizeof(generic));
    decoded = cdisasm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        little_bytes, sizeof(little_bytes), UINT64_C(0x6400),
        CDISASM_ARM_DECODE_OPTION_NONE, &generic);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&little, &generic, sizeof(little)) == 0);

    memset(&generic, 0xa5, sizeof(generic));
    decoded = cdisasm_decode_checked(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        little_bytes, sizeof(little_bytes), UINT64_C(0x6400),
        CDISASM_ARM_DECODE_OPTION_NONE, &generic, sizeof(generic));
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&little, &generic, sizeof(little)) == 0);

    for (code_size = 1u; code_size < 4u; ++code_size) {
        memset(&generic, 0xa5, sizeof(generic));
        EXPECT(decode_word(
            word, CDISASM_ARM_CPU_ANY, code_size,
            CDISASM_ARM_DECODE_OPTION_NONE, &generic) == 0u);
        EXPECT(instruction_is_error_only(
            &generic, CDISASM_STATUS_TRUNCATED));
    }

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, 0u,
        CDISASM_ARM_DECODE_OPTION_NONE, &generic) == 0u);
    EXPECT(instruction_is_error_only(&generic, CDISASM_STATUS_END_OF_INPUT));

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u, UINT64_C(1) << 63,
        &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_ARGUMENT));

    /* The op=4/5 controls are owned reserved encodings in both variants. */
    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        f64mm_permute_word(4u, 0u, 0u, 0u),
        CDISASM_ARM_CPU_ANY, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_INSTRUCTION));

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        f64mm_permute_word(5u, 31u, 31u, 31u),
        CDISASM_ARM_CPU_ANY, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_INSTRUCTION));
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void test_formatting(void)
{
    static const char *const mnemonics[8] = {
        "zip1", "zip2", "uzp1", "uzp2", NULL, NULL, "trn1", "trn2"
    };
    unsigned operation;

    for (operation = 0u; operation < 8u; ++operation) {
        cdisasm_arm_instruction instruction;
        char expected[96];
        char text[96];
        unsigned zd;
        unsigned zn;
        unsigned zm;
        int expected_size;

        if (mnemonics[operation] == NULL) {
            continue;
        }
        zd = (operation * 3u) & 31u;
        zn = (operation * 5u + 1u) & 31u;
        zm = (operation * 7u + 2u) & 31u;
        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            f64mm_permute_word(operation, zd, zn, zm),
            CDISASM_ARM_CPU_ANY, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 4u);
        expected_size = snprintf(
            expected, sizeof(expected), "%s z%u.q, z%u.q, z%u.q",
            mnemonics[operation], zd, zn, zm);
        EXPECT(expected_size > 0);
        EXPECT((size_t)expected_size < sizeof(expected));
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            text, sizeof(text)) == (size_t)expected_size);
        EXPECT(strcmp(text, expected) == 0);
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            NULL, 0u) == (size_t)expected_size);
    }

    {
        cdisasm_arm_instruction instruction;
        char text[64];
        char short_text[5];
        static const char expected[] = "TRN2 z31.q, z0.q, z17.q";

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            f64mm_permute_word(7u, 31u, 0u, 17u),
            CDISASM_ARM_CPU_ANY, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 4u);
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_0
                | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(text, expected) == 0);
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_7,
            short_text, sizeof(short_text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(short_text, "trn2") == 0);

        /* Element size 16 is accepted only for this Q-permute name set. */
        instruction.name_id = CDISASM_ARM_NAME_ADD;
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            text, sizeof(text)) == 0u);
    }
}
#endif

int main(void)
{
    test_exact_allocated_and_reserved_domain();
    test_cpu_feature_boundary();
    test_endian_dispatch_and_boundaries();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatting();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d ARM F64MM permute test(s) failed\n", failures);
        return 1;
    }
    printf("ARM F64MM Q-element permute tests passed "
           "(USE_EXTRA_OPCODES=%d)\n", USE_EXTRA_OPCODES);
    return 0;
}
