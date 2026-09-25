#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define TEST_ADDRESS UINT64_C(0x1c3000)
#define FAMILY_MASK UINT32_C(0xff20f800)
#define FAMILY_VALUE UINT32_C(0x44201000)
#define SQRDMLAH_VALUE UINT32_C(0x44201000)
#define SQRDMLSH_VALUE UINT32_C(0x44201400)
#define SCALABLE_FLAG CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR

typedef struct indexed_width {
    uint32_t offset;
    uint32_t mask;
    uint8_t element_size;
    uint8_t lane_count;
    uint8_t register_count;
} indexed_width;

static const indexed_width widths[] = {
    { UINT32_C(0x00000000), UINT32_C(0xffa0fc00), 2u, 8u, 8u },
    { UINT32_C(0x00800000), UINT32_C(0xffe0fc00), 4u, 4u, 8u },
    { UINT32_C(0x00c00000), UINT32_C(0xffe0fc00), 8u, 2u, 16u }
};

static int failures;
static uint64_t allocated_count;
static uint64_t form_counts[6];

_Static_assert(CDISASM_ARM_NAME_SQRDMLAH == 312,
    "SQRDMLAH public name ID changed");
_Static_assert(CDISASM_ARM_NAME_SQRDMLSH == 1494,
    "SQRDMLSH public name ID changed");
_Static_assert(CDISASM_ARM_FORM_LAST >= 2735,
    "indexed SQRDMLAH/SQRDMLSH public form IDs are unavailable");

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

static uint32_t indexed_word(
    unsigned operation, unsigned width, unsigned lane, unsigned zm,
    unsigned zn, unsigned zda)
{
    uint32_t word = (operation == 0u
            ? SQRDMLAH_VALUE : SQRDMLSH_VALUE)
        | widths[width].offset | ((uint32_t)zn << 5) | zda;

    if (width == 0u) {
        word |= ((uint32_t)(lane >> 2) << 22)
            | ((uint32_t)(lane & 3u) << 19)
            | ((uint32_t)zm << 16);
    } else if (width == 1u) {
        word |= ((uint32_t)lane << 19) | ((uint32_t)zm << 16);
    } else {
        word |= ((uint32_t)lane << 20) | ((uint32_t)zm << 16);
    }
    return word;
}

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
static cdisasm_arm_operand *append_z_operand(
    cdisasm_arm_instruction *instruction, unsigned encoded,
    uint8_t element_size, cdisasm_operand_access access)
{
    cdisasm_arm_operand *operand =
        &instruction->operand[instruction->operand_count++];

    operand->type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    operand->reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + encoded);
    operand->extend_type = (cdisasm_arm_extend_type)element_size;
    operand->access = access;
    return operand;
}

static void make_expected(
    uint32_t word, unsigned operation, unsigned width,
    cdisasm_arm_instruction *expected)
{
    unsigned indexed_register;
    uint64_t lane;
    cdisasm_arm_operand *indexed;

    if (width == 0u) {
        indexed_register = (word >> 16) & 7u;
        lane = (uint64_t)((((word >> 22) & 1u) << 2)
            | ((word >> 19) & 3u));
    } else if (width == 1u) {
        indexed_register = (word >> 16) & 7u;
        lane = (word >> 19) & 3u;
    } else {
        indexed_register = (word >> 16) & 15u;
        lane = (word >> 20) & 1u;
    }

    memset(expected, 0, sizeof(*expected));
    expected->address = TEST_ADDRESS;
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->name_id = operation == 0u
        ? CDISASM_ARM_NAME_SQRDMLAH : CDISASM_ARM_NAME_SQRDMLSH;
    expected->form_id = (cdisasm_arm_form_id)(UINT16_C(2728)
        + (cdisasm_arm_form_id)(operation * 3u + width));
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->instruction_flags = SCALABLE_FLAG;
    append_z_operand(expected, word & 31u, widths[width].element_size,
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    append_z_operand(expected, (word >> 5) & 31u,
        widths[width].element_size, CDISASM_OPERAND_ACCESS_READ);
    indexed = append_z_operand(expected, indexed_register,
        widths[width].element_size, CDISASM_OPERAND_ACCESS_READ);
    indexed->flags = CDISASM_ARM_OPERAND_FLAG_HAS_LANE;
    indexed->imm = lane;
}
#endif

static void expect_allocated(
    uint32_t word, unsigned operation, unsigned width)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction expected;

        domain_expect(decode_word(
            word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u,
            word, "allocated indexed SQRDML word did not decode");
        make_expected(word, operation, width, &expected);
        domain_expect(memcmp(&instruction, &expected, sizeof(expected)) == 0,
            word, "allocated indexed SQRDML metadata mismatch");
    }
#else
    (void)operation;
    (void)width;
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "extras-OFF decoded indexed SQRDML word");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF indexed SQRDML ownership mismatch");
#endif
}

static void test_complete_leaf_union(void)
{
    unsigned operation;
    unsigned width;
    unsigned lane;
    unsigned zm;
    unsigned zn;
    unsigned zda;

    for (operation = 0u; operation < 2u; ++operation) {
        for (width = 0u; width < 3u; ++width) {
            uint32_t fixed_value = (operation == 0u
                    ? SQRDMLAH_VALUE : SQRDMLSH_VALUE)
                | widths[width].offset;

            for (lane = 0u; lane < widths[width].lane_count; ++lane) {
                for (zm = 0u; zm < widths[width].register_count; ++zm) {
                    for (zn = 0u; zn < 32u; ++zn) {
                        for (zda = 0u; zda < 32u; ++zda) {
                            uint32_t word = indexed_word(
                                operation, width, lane, zm, zn, zda);

                            domain_expect((word & widths[width].mask)
                                == fixed_value, word,
                                "indexed SQRDML construction escaped leaf");
                            domain_expect((word & FAMILY_MASK) == FAMILY_VALUE,
                                word, "indexed SQRDML escaped union");
                            expect_allocated(word, operation, width);
                            ++allocated_count;
                            ++form_counts[operation * 3u + width];
                        }
                    }
                }
            }
        }
    }

    EXPECT(form_counts[0] == UINT64_C(65536));
    EXPECT(form_counts[1] == UINT64_C(32768));
    EXPECT(form_counts[2] == UINT64_C(32768));
    EXPECT(form_counts[3] == UINT64_C(65536));
    EXPECT(form_counts[4] == UINT64_C(32768));
    EXPECT(form_counts[5] == UINT64_C(32768));
    EXPECT(allocated_count == UINT64_C(262144));
}

static void expect_profile(
    uint32_t word, cdisasm_arm_cpu_id cpu_id, cdisasm_status enabled_status,
    uint16_t form_id, cdisasm_arm_name_id name_id)
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
        EXPECT(instruction.form_id == form_id);
        EXPECT(instruction.name_id == name_id);
    } else {
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_profiles_transport_and_status(void)
{
    static const struct profile_case {
        uint32_t word;
        uint16_t form_id;
        cdisasm_arm_name_id name_id;
    } cases[] = {
        { UINT32_C(0x44201020), UINT16_C(2728),
          CDISASM_ARM_NAME_SQRDMLAH },
        { UINT32_C(0x44bf13df), UINT16_C(2729),
          CDISASM_ARM_NAME_SQRDMLAH },
        { UINT32_C(0x44ff13df), UINT16_C(2730),
          CDISASM_ARM_NAME_SQRDMLAH },
        { UINT32_C(0x44201420), UINT16_C(2731),
          CDISASM_ARM_NAME_SQRDMLSH },
        { UINT32_C(0x44bf17df), UINT16_C(2732),
          CDISASM_ARM_NAME_SQRDMLSH },
        { UINT32_C(0x44ff17df), UINT16_C(2733),
          CDISASM_ARM_NAME_SQRDMLSH }
    };
    const uint32_t high = cases[5].word;
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction other;
    uint8_t bytes[4];
    unsigned index;
    unsigned boundary;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_profile(cases[index].word, CDISASM_ARM_CPU_ANY,
            CDISASM_STATUS_OK, cases[index].form_id, cases[index].name_id);
        expect_profile(cases[index].word, CDISASM_ARM_CPU_APPLE_A18,
            CDISASM_STATUS_OK, cases[index].form_id, cases[index].name_id);
        expect_profile(cases[index].word, CDISASM_ARM_CPU_APPLE_M4,
            CDISASM_STATUS_OK, cases[index].form_id, cases[index].name_id);
        expect_profile(cases[index].word, CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_STATUS_INVALID_INSTRUCTION,
            cases[index].form_id, cases[index].name_id);
        expect_profile(cases[index].word, CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_STATUS_INVALID_INSTRUCTION,
            cases[index].form_id, cases[index].name_id);
    }

    memset(&little, 0xa5, sizeof(little));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(high, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little) == 4u);
#else
    EXPECT(decode_word(high, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little) == 0u);
#endif
    bytes[0] = (uint8_t)(high >> 24);
    bytes[1] = (uint8_t)(high >> 16);
    bytes[2] = (uint8_t)(high >> 8);
    bytes[3] = (uint8_t)high;
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

    word_to_le(high, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), TEST_ADDRESS,
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
    EXPECT(cdisasm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), TEST_ADDRESS,
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    for (boundary = 0u; boundary < 4u; ++boundary) {
        cdisasm_status status = boundary == 0u
            ? CDISASM_STATUS_END_OF_INPUT : CDISASM_STATUS_TRUNCATED;

        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(cases[0].word, CDISASM_ARM_CPU_ANY, boundary,
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(&other, status));
    }
    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(cases[0].word, CDISASM_ARM_CPU_ANY, 4u,
        UINT64_C(1) << 63, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));
}

static void test_collision_boundaries(void)
{
    cdisasm_arm_instruction instruction;
    unsigned operation;
    unsigned width;
    unsigned bit;

    for (operation = 0u; operation < 2u; ++operation) {
        for (width = 0u; width < 3u; ++width) {
            uint16_t form_id = (uint16_t)(2728u + operation * 3u + width);
            uint32_t canonical = indexed_word(operation, width,
                0u, 0u, 1u, 0u);

            for (bit = 0u; bit < 32u; ++bit) {
                if ((widths[width].mask & (UINT32_C(1) << bit)) != 0u) {
                    uint32_t neighbor = canonical ^ (UINT32_C(1) << bit);

                    memset(&instruction, 0xa5, sizeof(instruction));
                    (void)decode_word(neighbor, CDISASM_ARM_CPU_ANY, 4u,
                        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                    EXPECT(instruction.form_id != form_id);
                }
            }
        }
    }

    /* Form 2734/2735 is the immediately adjacent indexed USDOT/SUDOT
     * family and must retain its independent I8MM identity. */
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(UINT32_C(0x44a01800), CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(2734));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_USDOT);
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(UINT32_C(0x44a01c00), CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(2735));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_SUDOT);
#else
    EXPECT(decode_word(UINT32_C(0x44a01800), CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif

    /* Baseline Advanced SIMD scalar ADDP form 5808 is outside this SVE
     * family and must retain its independently implemented identity. */
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(UINT32_C(0x5ef1b800), CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(5808));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_ADDP);
#else
    EXPECT(decode_word(UINT32_C(0x5ef1b800), CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif

    memset(&instruction, 0xa5, sizeof(instruction));
    (void)decode_word_mode(indexed_word(0u, 0u, 0u, 0u, 1u, 0u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    EXPECT(instruction.form_id < UINT16_C(2728)
        || instruction.form_id > UINT16_C(2733));
    memset(&instruction, 0xa5, sizeof(instruction));
    (void)decode_word_mode(indexed_word(1u, 2u, 1u, 15u, 30u, 31u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_T32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    EXPECT(instruction.form_id < UINT16_C(2728)
        || instruction.form_id > UINT16_C(2733));
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void reject_forgery(
    const cdisasm_arm_instruction *instruction, const char *mutation)
{
    char text[96];
    size_t length;

    memset(text, 0xa5, sizeof(text));
    length = cdisasm_arm_format(
        instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text));
    if (length != 0u || text[0] != '\0') {
        if (failures < 24) {
            fprintf(stderr, "accepted formatter forgery: %s\n", mutation);
        }
        ++failures;
    }
}

static void test_formatter_contract(void)
{
    static const struct format_case {
        uint32_t word;
        const char *text;
    } cases[] = {
        { UINT32_C(0x44201020), "sqrdmlah z0.h, z1.h, z0.h[0]" },
        { UINT32_C(0x447f13df), "sqrdmlah z31.h, z30.h, z7.h[7]" },
        { UINT32_C(0x44a01020), "sqrdmlah z0.s, z1.s, z0.s[0]" },
        { UINT32_C(0x44bf13df), "sqrdmlah z31.s, z30.s, z7.s[3]" },
        { UINT32_C(0x44e01020), "sqrdmlah z0.d, z1.d, z0.d[0]" },
        { UINT32_C(0x44ff13df), "sqrdmlah z31.d, z30.d, z15.d[1]" },
        { UINT32_C(0x44201420), "sqrdmlsh z0.h, z1.h, z0.h[0]" },
        { UINT32_C(0x447f17df), "sqrdmlsh z31.h, z30.h, z7.h[7]" },
        { UINT32_C(0x44a01420), "sqrdmlsh z0.s, z1.s, z0.s[0]" },
        { UINT32_C(0x44bf17df), "sqrdmlsh z31.s, z30.s, z7.s[3]" },
        { UINT32_C(0x44e01420), "sqrdmlsh z0.d, z1.d, z0.d[0]" },
        { UINT32_C(0x44ff17df), "sqrdmlsh z31.d, z30.d, z15.d[1]" }
    };
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;
    char text[96];
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        EXPECT(decode_word(cases[index].word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            text, sizeof(text)) == strlen(cases[index].text));
        EXPECT(strcmp(text, cases[index].text) == 0);
    }
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text))
        == strlen("SQRDMLSH z31.d, z30.d, z15.d[1]"));
    EXPECT(strcmp(text, "SQRDMLSH z31.d, z30.d, z15.d[1]") == 0);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_7, NULL, 0u)
        == strlen(cases[11].text));

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged, #statement);                                \
    } while (0)

    REJECT_MUTATION(forged.form_id = UINT16_C(2730));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_SQRDMLAH);
    REJECT_MUTATION(forged.raw_instruction ^= UINT32_C(0x00000400));
    REJECT_MUTATION(forged.opcode_size = 2u);
    REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
    REJECT_MUTATION(forged.operand_count = 0u);
    REJECT_MUTATION(forged.instruction_flags = CDISASM_GROUP_NONE);
    REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_CONDITIONAL);
    REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
    REJECT_MUTATION(forged.branch_target = UINT64_C(4));
    REJECT_MUTATION(forged.operand[0].access = CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(forged.operand[0].extend_type = CDISASM_ARM_EXTEND_SXTB);
    REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_Z0);
    REJECT_MUTATION(forged.operand[2].reg = CDISASM_ARM_REG_Z0);
    REJECT_MUTATION(forged.operand[2].imm = 0u);
    REJECT_MUTATION(forged.operand[2].flags = CDISASM_OPERAND_FLAG_NONE);
    REJECT_MUTATION(forged.operand[2].extend_type = CDISASM_ARM_EXTEND_SXTH);
    REJECT_MUTATION(forged.operand[2].access = CDISASM_OPERAND_ACCESS_WRITE);

    forged = instruction;
    memset(forged.operand, 0, sizeof(forged.operand));
    forged.operand_count = 0u;
    forged.instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
        | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
    reject_forgery(&forged, "obsolete generated opaque schema");

#undef REJECT_MUTATION
}
#else
static void test_formatter_contract(void)
{
}
#endif

int main(void)
{
    test_complete_leaf_union();
    test_profiles_transport_and_status();
    test_collision_boundaries();
    test_formatter_contract();

    if (failures != 0) {
        fprintf(stderr, "%d indexed SVE SQRDML test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
