#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define TEST_ADDRESS UINT64_C(0x232100)
#define LOGICAL_MASK UINT32_C(0xffe0fc00)
#define XAR_MASK UINT32_C(0xff20fc00)
#define XAR_VALUE UINT32_C(0x04203400)
#define SCALABLE_FLAG CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR

_Static_assert(CDISASM_ARM_NAME_AND == UINT16_C(6),
               "established AND mnemonic ID moved");
_Static_assert(CDISASM_ARM_NAME_BIC == UINT16_C(9),
               "established BIC mnemonic ID moved");
_Static_assert(CDISASM_ARM_NAME_EOR == UINT16_C(21),
               "established EOR mnemonic ID moved");
_Static_assert(CDISASM_ARM_NAME_MOV == UINT16_C(31),
               "established MOV mnemonic ID moved");
_Static_assert(CDISASM_ARM_NAME_ORR == UINT16_C(37),
               "established ORR mnemonic ID moved");
_Static_assert(CDISASM_ARM_NAME_XAR == UINT16_C(2045),
               "established XAR mnemonic ID moved");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(2325),
               "generated ARM form catalog lost logical leaves");

typedef struct logical_form {
    uint32_t value;
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    const char *mnemonic;
} logical_form;

static const logical_form forms[4] = {
    { UINT32_C(0x04203000), UINT16_C(2321),
      CDISASM_ARM_NAME_AND, "and" },
    { UINT32_C(0x04603000), UINT16_C(2322),
      CDISASM_ARM_NAME_ORR, "orr" },
    { UINT32_C(0x04a03000), UINT16_C(2323),
      CDISASM_ARM_NAME_EOR, "eor" },
    { UINT32_C(0x04e03000), UINT16_C(2324),
      CDISASM_ARM_NAME_BIC, "bic" }
};

static int failures;
static uint64_t allocated_count;
static uint64_t canonical_count;
static uint64_t alias_count;
static uint64_t xar_count;
static uint64_t xar_reserved_count;
static uint64_t neighbor_count;

#define EXPECT(condition)                                                   \
    do {                                                                    \
        if (!(condition)) {                                                 \
            if (failures < 24) {                                           \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",       \
                        __FILE__, __LINE__, #condition);                    \
            }                                                               \
            ++failures;                                                     \
        }                                                                   \
    } while (0)

static void domain_expect(int condition, uint32_t word, const char *message)
{
    if (!condition) {
        if (failures < 24) {
            fprintf(stderr, "word %08x: %s\n", (unsigned)word, message);
        }
        ++failures;
    }
}

static uint32_t logical_word(
    unsigned operation, unsigned zd, unsigned zn, unsigned zm)
{
    return forms[operation].value
        | ((uint32_t)zm << 16)
        | ((uint32_t)zn << 5)
        | (uint32_t)zd;
}

static uint32_t xar_word(
    unsigned encoded_immediate, unsigned zd, unsigned zm)
{
    return XAR_VALUE
        | ((uint32_t)(encoded_immediate & 0x60u) << 17)
        | ((uint32_t)(encoded_immediate & 0x1fu) << 16)
        | ((uint32_t)zm << 5)
        | (uint32_t)zd;
}

#if USE_EXTRA_OPCODES
static unsigned xar_element_bits(unsigned encoded_immediate)
{
    return encoded_immediate >= 64u ? 64u
        : encoded_immediate >= 32u ? 32u
        : encoded_immediate >= 16u ? 16u : 8u;
}

static unsigned xar_immediate(unsigned encoded_immediate)
{
    unsigned element_bits = xar_element_bits(encoded_immediate);

    return 2u * element_bits - encoded_immediate;
}
#endif

static void word_to_le(uint32_t word, uint8_t bytes[4])
{
    bytes[0] = (uint8_t)word;
    bytes[1] = (uint8_t)(word >> 8);
    bytes[2] = (uint8_t)(word >> 16);
    bytes[3] = (uint8_t)(word >> 24);
}

static uint32_t decode_word_mode(
    uint32_t word, cdisasm_arm_cpu_id cpu_id, cdisasm_arm_mode mode,
    size_t size, cdisasm_arm_decode_option options,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(
        cpu_id, mode, bytes, size, TEST_ADDRESS, options, instruction);
}

static uint32_t decode_word(
    uint32_t word, cdisasm_arm_cpu_id cpu_id, size_t size,
    cdisasm_arm_decode_option options, cdisasm_arm_instruction *instruction)
{
    return decode_word_mode(
        word, cpu_id, CDISASM_ARM_MODE_A64, size, options, instruction);
}

static int instruction_is_error_only(
    const cdisasm_arm_instruction *instruction, cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

#if USE_EXTRA_OPCODES
static void append_z_operand(
    cdisasm_arm_instruction *instruction, unsigned encoded,
    cdisasm_operand_access access)
{
    cdisasm_arm_operand *operand =
        &instruction->operand[instruction->operand_count++];

    operand->type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    operand->reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + encoded);
    operand->extend_type = (cdisasm_arm_extend_type)8u;
    operand->access = access;
}

static void append_immediate_operand(
    cdisasm_arm_instruction *instruction, uint64_t value)
{
    cdisasm_arm_operand *operand =
        &instruction->operand[instruction->operand_count++];

    operand->type = CDISASM_OPERAND_IMMEDIATE;
    operand->imm = value;
    operand->size = 1u;
    operand->access = CDISASM_OPERAND_ACCESS_READ;
}

static void make_expected(
    unsigned operation, unsigned zd, unsigned zn, unsigned zm,
    cdisasm_arm_instruction *expected)
{
    int alias = operation == 1u && zn == zm;
    uint32_t word = logical_word(operation, zd, zn, zm);

    memset(expected, 0, sizeof(*expected));
    expected->address = TEST_ADDRESS;
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->name_id = alias ? CDISASM_ARM_NAME_MOV
                              : forms[operation].name_id;
    expected->form_id = forms[operation].form_id;
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->instruction_flags = SCALABLE_FLAG;
    append_z_operand(expected, zd, CDISASM_OPERAND_ACCESS_WRITE);
    append_z_operand(expected, zn, CDISASM_OPERAND_ACCESS_READ);
    if (!alias) {
        append_z_operand(expected, zm, CDISASM_OPERAND_ACCESS_READ);
    }
}

static void make_xar_expected(
    unsigned encoded_immediate, unsigned zd, unsigned zm,
    cdisasm_arm_instruction *expected)
{
    uint32_t word = xar_word(encoded_immediate, zd, zm);
    uint8_t element_size = (uint8_t)(
        xar_element_bits(encoded_immediate) / 8u);

    memset(expected, 0, sizeof(*expected));
    expected->address = TEST_ADDRESS;
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->name_id = CDISASM_ARM_NAME_XAR;
    expected->form_id = UINT16_C(2325);
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->instruction_flags = SCALABLE_FLAG;
    append_z_operand(expected, zd, CDISASM_OPERAND_ACCESS_READ_WRITE);
    expected->operand[0].extend_type =
        (cdisasm_arm_extend_type)element_size;
    append_z_operand(expected, zm, CDISASM_OPERAND_ACCESS_READ);
    expected->operand[1].extend_type =
        (cdisasm_arm_extend_type)element_size;
    append_immediate_operand(expected, xar_immediate(encoded_immediate));
}
#endif

static void test_complete_allocation(void)
{
    unsigned operation;

    for (operation = 0u; operation < 4u; ++operation) {
        unsigned zd;

        for (zd = 0u; zd < 32u; ++zd) {
            unsigned zn;

            for (zn = 0u; zn < 32u; ++zn) {
                unsigned zm;

                for (zm = 0u; zm < 32u; ++zm) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = logical_word(
                        operation, zd, zn, zm);

                    domain_expect((word & LOGICAL_MASK)
                            == forms[operation].value,
                        word, "logical payload construction failed");
                    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
                    {
                        cdisasm_arm_instruction expected;

                        domain_expect(decode_word(
                            word, CDISASM_ARM_CPU_ANY, 4u,
                            CDISASM_ARM_DECODE_OPTION_NONE,
                            &instruction) == 4u,
                            word, "allocated logical word did not decode");
                        make_expected(operation, zd, zn, zm, &expected);
                        domain_expect(memcmp(
                            &instruction, &expected, sizeof(expected)) == 0,
                            word, "allocated logical metadata mismatch");
                    }
#else
                    domain_expect(decode_word(
                        word, CDISASM_ARM_CPU_ANY, 4u,
                        CDISASM_ARM_DECODE_OPTION_NONE,
                        &instruction) == 0u,
                        word, "extras-OFF decoded logical word");
                    domain_expect(instruction_is_error_only(
                        &instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                        word, "extras-OFF logical ownership mismatch");
#endif
                    ++allocated_count;
                    if (operation == 1u && zn == zm) {
                        ++alias_count;
                    } else {
                        ++canonical_count;
                    }
                }
            }
        }
    }
    EXPECT(allocated_count == UINT64_C(131072));
    EXPECT(alias_count == UINT64_C(1024));
    EXPECT(canonical_count == UINT64_C(130048));
}

static void test_complete_xar_allocation(void)
{
    unsigned encoded_immediate;

    for (encoded_immediate = 8u; encoded_immediate < 128u;
         ++encoded_immediate) {
        unsigned zd;

        for (zd = 0u; zd < 32u; ++zd) {
            unsigned zm;

            for (zm = 0u; zm < 32u; ++zm) {
                cdisasm_arm_instruction instruction;
                uint32_t word = xar_word(encoded_immediate, zd, zm);

                domain_expect((word & XAR_MASK) == XAR_VALUE,
                    word, "XAR payload construction failed");
                memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
                {
                    cdisasm_arm_instruction expected;

                    domain_expect(decode_word(
                        word, CDISASM_ARM_CPU_ANY, 4u,
                        CDISASM_ARM_DECODE_OPTION_NONE,
                        &instruction) == 4u,
                        word, "allocated XAR word did not decode");
                    make_xar_expected(
                        encoded_immediate, zd, zm, &expected);
                    domain_expect(memcmp(
                        &instruction, &expected, sizeof(expected)) == 0,
                        word, "allocated XAR metadata mismatch");
                }
#else
                domain_expect(decode_word(
                    word, CDISASM_ARM_CPU_ANY, 4u,
                    CDISASM_ARM_DECODE_OPTION_NONE,
                    &instruction) == 0u,
                    word, "extras-OFF decoded XAR word");
                domain_expect(instruction_is_error_only(
                    &instruction,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                    word, "extras-OFF XAR ownership mismatch");
#endif
                ++xar_count;
            }
        }
    }
    EXPECT(xar_count == UINT64_C(122880));
}

static void test_xar_reserved_encodings(void)
{
    static const unsigned edge_registers[4] = { 0u, 1u, 30u, 31u };
    unsigned encoded_immediate;

    for (encoded_immediate = 0u; encoded_immediate < 8u;
         ++encoded_immediate) {
        size_t zd_index;

        for (zd_index = 0u; zd_index < 4u; ++zd_index) {
            size_t zm_index;

            for (zm_index = 0u; zm_index < 4u; ++zm_index) {
                cdisasm_arm_instruction instruction;
                uint32_t word = xar_word(
                    encoded_immediate, edge_registers[zd_index],
                    edge_registers[zm_index]);

                memset(&instruction, 0xa5, sizeof(instruction));
                domain_expect(decode_word(
                    word, CDISASM_ARM_CPU_ANY, 4u,
                    CDISASM_ARM_DECODE_OPTION_NONE,
                    &instruction) == 0u,
                    word, "reserved XAR word decoded");
                domain_expect(instruction_is_error_only(
                    &instruction, CDISASM_STATUS_INVALID_INSTRUCTION),
                    word, "reserved XAR status mismatch");
                ++xar_reserved_count;
            }
        }
    }
    EXPECT(xar_reserved_count == UINT64_C(128));
}

static void test_bounded_neighbors(void)
{
    static const uint32_t sibling_values[8] = {
        UINT32_C(0x04203800), UINT32_C(0x04603800),
        UINT32_C(0x04a03800), UINT32_C(0x04e03800),
        UINT32_C(0x04203c00), UINT32_C(0x04603c00),
        UINT32_C(0x04a03c00), UINT32_C(0x04e03c00)
    };
    static const unsigned edge_registers[4] = { 0u, 1u, 30u, 31u };
    size_t sibling_index;

    for (sibling_index = 0u;
         sibling_index < sizeof(sibling_values) / sizeof(sibling_values[0]);
         ++sibling_index) {
        size_t zd_index;

        for (zd_index = 0u; zd_index < 4u; ++zd_index) {
            size_t zn_index;

            for (zn_index = 0u; zn_index < 4u; ++zn_index) {
                size_t zm_index;

                for (zm_index = 0u; zm_index < 4u; ++zm_index) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = sibling_values[sibling_index]
                        | ((uint32_t)edge_registers[zm_index] << 16)
                        | ((uint32_t)edge_registers[zn_index] << 5)
                        | (uint32_t)edge_registers[zd_index];
                    uint32_t size;

                    memset(&instruction, 0xa5, sizeof(instruction));
                    size = decode_word(
                        word, CDISASM_ARM_CPU_ANY, 4u,
                        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                    if (size == 4u) {
                        domain_expect(instruction.form_id < UINT16_C(2321)
                                || instruction.form_id > UINT16_C(2325),
                            word, "sibling decoded as logical leaf");
                    } else {
                        domain_expect(instruction.last_error_id
                                != CDISASM_STATUS_OK,
                            word, "sibling failure omitted status");
                    }
                    ++neighbor_count;
                }
            }
        }
    }
    EXPECT(neighbor_count == UINT64_C(512));
}

static void expect_profile(
    uint32_t word, cdisasm_arm_cpu_id cpu_id,
    cdisasm_status enabled_status)
{
    cdisasm_arm_instruction instruction;
    cdisasm_status expected;

#if USE_EXTRA_OPCODES
    expected = enabled_status;
#else
    (void)enabled_status;
    expected = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, cpu_id, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction)
        == (expected == CDISASM_STATUS_OK ? 4u : 0u));
    if (expected == CDISASM_STATUS_OK) {
        EXPECT(instruction.form_id == UINT16_C(2324));
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_BIC);
        EXPECT(instruction.operand_count == 3u);
    } else {
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void expect_xar_profile(
    cdisasm_arm_cpu_id cpu_id, cdisasm_status enabled_status)
{
    cdisasm_arm_instruction instruction;
    cdisasm_status expected;
    uint32_t word = xar_word(127u, 31u, 30u);

#if USE_EXTRA_OPCODES
    expected = enabled_status;
#else
    (void)enabled_status;
    expected = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, cpu_id, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction)
        == (expected == CDISASM_STATUS_OK ? 4u : 0u));
    if (expected == CDISASM_STATUS_OK) {
        EXPECT(instruction.form_id == UINT16_C(2325));
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_XAR);
        EXPECT(instruction.operand_count == 3u);
    } else {
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_profiles_transport_and_precedence(void)
{
    uint32_t word = logical_word(3u, 31u, 30u, 29u);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction other;
    uint8_t bytes[4];
    unsigned boundary;

    expect_profile(word, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
    expect_profile(word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_STATUS_OK);
    expect_profile(word, CDISASM_ARM_CPU_APPLE_A18,
        CDISASM_STATUS_OK);
    expect_profile(word, CDISASM_ARM_CPU_APPLE_M4,
        CDISASM_STATUS_OK);
    expect_profile(word, CDISASM_ARM_CPU_CORTEX_A53,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_profile(word, CDISASM_ARM_CPU_APPLE_M1,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    expect_xar_profile(CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
    expect_xar_profile(CDISASM_ARM_CPU_APPLE_A18, CDISASM_STATUS_OK);
    expect_xar_profile(CDISASM_ARM_CPU_APPLE_M4, CDISASM_STATUS_OK);
    expect_xar_profile(CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_xar_profile(CDISASM_ARM_CPU_APPLE_M1,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_xar_profile(CDISASM_ARM_CPU_CORTEX_A53,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    memset(&little, 0xa5, sizeof(little));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little) == 4u);
#else
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little) == 0u);
#endif
    bytes[0] = (uint8_t)(word >> 24);
    bytes[1] = (uint8_t)(word >> 16);
    bytes[2] = (uint8_t)(word >> 8);
    bytes[3] = (uint8_t)word;
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), TEST_ADDRESS,
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), TEST_ADDRESS,
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    word = xar_word(64u, 31u, 30u);
    memset(&little, 0xa5, sizeof(little));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little) == 4u);
#else
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little) == 0u);
#endif
    bytes[0] = (uint8_t)(word >> 24);
    bytes[1] = (uint8_t)(word >> 16);
    bytes[2] = (uint8_t)(word >> 8);
    bytes[3] = (uint8_t)word;
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), TEST_ADDRESS,
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), TEST_ADDRESS,
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    for (boundary = 0u; boundary < 4u; ++boundary) {
        cdisasm_status status = boundary == 0u
            ? CDISASM_STATUS_END_OF_INPUT : CDISASM_STATUS_TRUNCATED;

        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_CORTEX_A53,
            boundary, CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(&other, status));
    }
    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
        UINT64_C(1) << 63, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&other, 0xa5, sizeof(other));
    (void)decode_word_mode(word, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &other);
    EXPECT(other.form_id < UINT16_C(2321)
        || other.form_id > UINT16_C(2325));
    memset(&other, 0xa5, sizeof(other));
    (void)decode_word_mode(word, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_T32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &other);
    EXPECT(other.form_id < UINT16_C(2321)
        || other.form_id > UINT16_C(2325));
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char uppercase_expected[96];
    char text[96];
    size_t opcode_end = strcspn(expected, " ");
    size_t index;

    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == strlen(expected));
    EXPECT(strcmp(text, expected) == 0);
    memcpy(uppercase_expected, expected, strlen(expected) + 1u);
    for (index = 0u; index < opcode_end; ++index) {
        if (uppercase_expected[index] >= 'a'
            && uppercase_expected[index] <= 'z') {
            uppercase_expected[index] = (char)(uppercase_expected[index]
                - 'a' + 'A');
        }
    }
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text)) == strlen(uppercase_expected));
    EXPECT(strcmp(text, uppercase_expected) == 0);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_7, NULL, 0u)
        == strlen(expected));
}

static void reject_forgery(const cdisasm_arm_instruction *instruction)
{
    char text[96];

    memset(text, 0xa5, sizeof(text));
    EXPECT(cdisasm_arm_format(
        instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == 0u);
    EXPECT(text[0] == '\0');
}

static void test_formatter_contract(void)
{
    uint32_t word = logical_word(3u, 31u, 30u, 29u);
    uint32_t alias_word = logical_word(1u, 0u, 31u, 31u);
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction alias;
    cdisasm_arm_instruction xar;
    cdisasm_arm_instruction forged;
    cdisasm_arm_instruction unrelated;
    char text[96];
    unsigned encoded_immediate;

    expect_format(logical_word(0u, 0u, 1u, 2u),
        "and z0.d, z1.d, z2.d");
    expect_format(logical_word(1u, 3u, 4u, 5u),
        "orr z3.d, z4.d, z5.d");
    expect_format(logical_word(2u, 6u, 7u, 8u),
        "eor z6.d, z7.d, z8.d");
    expect_format(word, "bic z31.d, z30.d, z29.d");
    expect_format(alias_word, "mov z0.d, z31.d");
    for (encoded_immediate = 8u; encoded_immediate < 128u;
         ++encoded_immediate) {
        unsigned element_bits = xar_element_bits(encoded_immediate);
        char suffix = element_bits == 64u ? 'd'
            : element_bits == 32u ? 's'
            : element_bits == 16u ? 'h' : 'b';
        char expected[96];

        (void)snprintf(expected, sizeof(expected),
            "xar z7.%c, z7.%c, z13.%c, #0x%x",
            suffix, suffix, suffix,
            xar_immediate(encoded_immediate));
        expect_format(xar_word(encoded_immediate, 7u, 13u), expected);
    }

    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(decode_word(alias_word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &alias) == 4u);
    EXPECT(decode_word(xar_word(95u, 31u, 30u),
        CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &xar) == 4u);

#define REJECT_MUTATION(source, statement)                                  \
    do {                                                                    \
        forged = source;                                                    \
        statement;                                                          \
        reject_forgery(&forged);                                            \
    } while (0)

    REJECT_MUTATION(instruction,
        forged.raw_instruction = UINT32_C(0x04e03400));
    REJECT_MUTATION(instruction, forged.form_id = UINT16_C(2323));
    REJECT_MUTATION(instruction, forged.name_id = CDISASM_ARM_NAME_EOR);
    REJECT_MUTATION(instruction, forged.isa_id = CDISASM_ARM_ISA_A32);
    REJECT_MUTATION(instruction, forged.opcode_size = 2u);
    REJECT_MUTATION(instruction,
        forged.condition = CDISASM_ARM_CONDITION_EQ);
    REJECT_MUTATION(instruction,
        forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
    REJECT_MUTATION(instruction,
        forged.instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED);
    REJECT_MUTATION(instruction, forged.branch_target = UINT64_C(4));
    REJECT_MUTATION(instruction, forged.operand_count = 2u);
    REJECT_MUTATION(instruction,
        forged.operand[0].reg = CDISASM_ARM_REG_Z0);
    REJECT_MUTATION(instruction, forged.operand[0].extend_type = 4u);
    REJECT_MUTATION(instruction,
        forged.operand[0].access = CDISASM_OPERAND_ACCESS_READ);
    REJECT_MUTATION(instruction,
        forged.operand[1].reg = CDISASM_ARM_REG_Z0);
    REJECT_MUTATION(instruction,
        forged.operand[1].access = CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(instruction, forged.operand[2].extend_type = 4u);
    REJECT_MUTATION(instruction,
        forged.operand[2].base_reg = CDISASM_ARM_REG_X0);
    REJECT_MUTATION(instruction,
        forged.operand[3].type = CDISASM_OPERAND_REGISTER);
    REJECT_MUTATION(alias, forged.name_id = CDISASM_ARM_NAME_ORR);
    REJECT_MUTATION(alias, forged.operand_count = 3u);
    REJECT_MUTATION(xar,
        forged.raw_instruction = xar_word(0u, 31u, 30u));
    REJECT_MUTATION(xar, forged.form_id = UINT16_C(2324));
    REJECT_MUTATION(xar, forged.name_id = CDISASM_ARM_NAME_EOR);
    REJECT_MUTATION(xar, forged.isa_id = CDISASM_ARM_ISA_A32);
    REJECT_MUTATION(xar, forged.opcode_size = 2u);
    REJECT_MUTATION(xar,
        forged.condition = CDISASM_ARM_CONDITION_EQ);
    REJECT_MUTATION(xar,
        forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
    REJECT_MUTATION(xar, forged.instruction_flags = 0u);
    REJECT_MUTATION(xar, forged.branch_target = UINT64_C(4));
    REJECT_MUTATION(xar, forged.operand_count = 2u);
    REJECT_MUTATION(xar,
        forged.operand[0].reg = CDISASM_ARM_REG_Z0);
    REJECT_MUTATION(xar, forged.operand[0].extend_type = 4u);
    REJECT_MUTATION(xar,
        forged.operand[0].access = CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(xar,
        forged.operand[1].reg = CDISASM_ARM_REG_Z0);
    REJECT_MUTATION(xar, forged.operand[1].extend_type = 4u);
    REJECT_MUTATION(xar,
        forged.operand[1].access = CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(xar, forged.operand[2].imm = UINT64_C(34));
    REJECT_MUTATION(xar, forged.operand[2].size = 2u);
    REJECT_MUTATION(xar,
        forged.operand[2].type = CDISASM_OPERAND_REGISTER);
    REJECT_MUTATION(xar,
        forged.operand[2].base_reg = CDISASM_ARM_REG_X0);
    REJECT_MUTATION(xar,
        forged.operand[3].type = CDISASM_OPERAND_REGISTER);

#undef REJECT_MUTATION

    memset(&unrelated, 0xa5, sizeof(unrelated));
    EXPECT(decode_word(UINT32_C(0x8a020020), CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &unrelated) == 4u);
    EXPECT(unrelated.name_id == CDISASM_ARM_NAME_AND);
    EXPECT(cdisasm_arm_format(
        &unrelated, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) != 0u);

    memset(&unrelated, 0xa5, sizeof(unrelated));
    EXPECT(decode_word(UINT32_C(0xce8d958b), CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &unrelated) == 4u);
    EXPECT(unrelated.name_id == CDISASM_ARM_NAME_XAR);
    EXPECT(unrelated.form_id == UINT16_C(6301));
    EXPECT(cdisasm_arm_format(
        &unrelated, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) != 0u);
}
#endif

int main(void)
{
    test_complete_allocation();
    test_complete_xar_allocation();
    test_xar_reserved_encodings();
    test_bounded_neighbors();
    test_profiles_transport_and_precedence();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatter_contract();
#endif
    if (failures != 0) {
        fprintf(stderr,
            "ARM SVE unpredicated-logical tests failed: %d\n", failures);
        return 1;
    }
    printf("ARM SVE unpredicated-logical tests passed "
           "(%llu allocated, %llu canonical, %llu MOV aliases, "
           "%llu XAR allocated, %llu XAR reserved, "
           "%llu bounded neighbors; extras=%d, format=%d)\n",
           (unsigned long long)allocated_count,
           (unsigned long long)canonical_count,
           (unsigned long long)alias_count,
           (unsigned long long)xar_count,
           (unsigned long long)xar_reserved_count,
           (unsigned long long)neighbor_count,
           USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
    return 0;
}
