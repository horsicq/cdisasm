#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define TEST_ADDRESS UINT64_C(0x1b3000)
#define DOT_MASK UINT32_C(0xffe0fc00)
#define USDOT_VALUE UINT32_C(0x44a01800)
#define SUDOT_VALUE UINT32_C(0x44a01c00)
#define SCALABLE_FLAG CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR

static int failures;
static uint64_t allocated_count;
static uint64_t named_profile_count;

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

static uint32_t dot_word(
    uint32_t value, unsigned lane, unsigned zm, unsigned zn, unsigned zda)
{
    return value | ((uint32_t)lane << 19)
        | ((uint32_t)zm << 16) | ((uint32_t)zn << 5) | zda;
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
    uint32_t word, cdisasm_arm_instruction *expected)
{
    cdisasm_arm_operand *indexed;

    memset(expected, 0, sizeof(*expected));
    expected->address = TEST_ADDRESS;
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->name_id = (word & UINT32_C(0x00000400)) != 0u
        ? CDISASM_ARM_NAME_SUDOT : CDISASM_ARM_NAME_USDOT;
    expected->form_id = (word & UINT32_C(0x00000400)) != 0u
        ? UINT16_C(2735) : UINT16_C(2734);
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->instruction_flags = SCALABLE_FLAG;
    append_z_operand(expected, word & 31u, 4u,
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    append_z_operand(expected, (word >> 5) & 31u, 1u,
        CDISASM_OPERAND_ACCESS_READ);
    indexed = append_z_operand(expected, (word >> 16) & 7u, 1u,
        CDISASM_OPERAND_ACCESS_READ);
    indexed->flags = CDISASM_ARM_OPERAND_FLAG_HAS_LANE;
    indexed->imm = (word >> 19) & 3u;
}
#endif

static void expect_allocated(uint32_t word)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction expected;

        domain_expect(decode_word(
            word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u,
            word, "allocated indexed dot-product word did not decode");
        make_expected(word, &expected);
        domain_expect(memcmp(&instruction, &expected, sizeof(expected)) == 0,
            word, "allocated indexed dot-product metadata mismatch");
    }
#else
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "extras-OFF decoded indexed dot-product word");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF indexed dot-product ownership mismatch");
#endif
}

static void test_complete_leaf(void)
{
    unsigned lane;
    unsigned zm;
    unsigned zn;
    unsigned zda;

    static const uint32_t values[] = { USDOT_VALUE, SUDOT_VALUE };
    size_t value_index;

    for (value_index = 0u;
         value_index < sizeof(values) / sizeof(values[0]); ++value_index) {
        for (lane = 0u; lane < 4u; ++lane) {
            for (zm = 0u; zm < 8u; ++zm) {
                for (zn = 0u; zn < 32u; ++zn) {
                    for (zda = 0u; zda < 32u; ++zda) {
                        uint32_t word = dot_word(
                            values[value_index], lane, zm, zn, zda);

                        domain_expect((word & DOT_MASK)
                            == values[value_index], word,
                            "indexed dot-product construction escaped leaf");
                        expect_allocated(word);
                        ++allocated_count;
                    }
                }
            }
        }
    }
    EXPECT(allocated_count == UINT64_C(65536));
}

static void expect_status(
    uint32_t word, cdisasm_arm_cpu_id cpu_id, cdisasm_status expected)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, cpu_id, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction)
        == (expected == CDISASM_STATUS_OK ? 4u : 0u));
    if (expected == CDISASM_STATUS_OK) {
        EXPECT(instruction.form_id == ((word & UINT32_C(0x00000400)) != 0u
            ? UINT16_C(2735) : UINT16_C(2734)));
        EXPECT(instruction.name_id == ((word & UINT32_C(0x00000400)) != 0u
            ? CDISASM_ARM_NAME_SUDOT : CDISASM_ARM_NAME_USDOT));
    } else {
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_profiles_transport_and_status(void)
{
    const uint32_t low = dot_word(USDOT_VALUE, 0u, 0u, 1u, 0u);
    const uint32_t high = dot_word(SUDOT_VALUE, 3u, 7u, 30u, 31u);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction other;
    uint8_t bytes[4];
    uint32_t cpu_value;
    unsigned boundary;

#if USE_EXTRA_OPCODES
    expect_status(low, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
    expect_status(high, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
#else
    expect_status(low, CDISASM_ARM_CPU_ANY,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_status(high, CDISASM_ARM_CPU_ANY,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    for (cpu_value = CDISASM_ARM_CPU_FIRST;
         cpu_value <= CDISASM_ARM_CPU_LAST; ++cpu_value) {
        cdisasm_arm_cpu_id cpu_id = (cdisasm_arm_cpu_id)cpu_value;
        cdisasm_status expected;

        if ((cdisasm_arm_cpu_mode_mask(cpu_id)
                & CDISASM_ARM_MODE_MASK_A64) == 0u) {
            expected = CDISASM_STATUS_INVALID_ARGUMENT;
#if USE_EXTRA_OPCODES
        } else {
            /* Every named profile lacks FEAT_I8MM, including profiles that
             * independently provide the SVE or SME half of the gate. */
            expected = CDISASM_STATUS_INVALID_INSTRUCTION;
#else
        } else {
            expected = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
        }
        expect_status(low, cpu_id, expected);
        ++named_profile_count;
    }
    EXPECT(named_profile_count
        == (uint64_t)(CDISASM_ARM_CPU_LAST - CDISASM_ARM_CPU_FIRST + 1u));

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
        EXPECT(decode_word(low, CDISASM_ARM_CPU_ANY, boundary,
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(&other, status));
    }
    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(low, CDISASM_ARM_CPU_ANY, 4u,
        UINT64_C(1) << 63, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));
}

static void test_collision_boundaries(void)
{
    const uint32_t canonical = dot_word(SUDOT_VALUE, 0u, 0u, 1u, 0u);
    cdisasm_arm_instruction instruction;
    unsigned bit;

    /* Every fixed-bit mutation leaves the exact form.  Allocated siblings
     * remain delegated to their generated or structured owners. */
    for (bit = 0u; bit < 32u; ++bit) {
        if ((DOT_MASK & (UINT32_C(1) << bit)) != 0u) {
            uint32_t neighbor = canonical ^ (UINT32_C(1) << bit);

            memset(&instruction, 0xa5, sizeof(instruction));
            (void)decode_word(neighbor, CDISASM_ARM_CPU_ANY, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            EXPECT(instruction.form_id != UINT16_C(2735));
        }
    }

    /* U=0 is the indexed USDOT sibling and remains owned by the same exact
     * structured family without being confused for SUDOT. */
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(canonical ^ UINT32_C(0x00000400),
        CDISASM_ARM_CPU_ANY, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(2734));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_USDOT);
#else
    EXPECT(decode_word(canonical ^ UINT32_C(0x00000400),
        CDISASM_ARM_CPU_ANY, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif

    memset(&instruction, 0xa5, sizeof(instruction));
    (void)decode_word_mode(canonical, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction);
    EXPECT(instruction.form_id != UINT16_C(2735));
    memset(&instruction, 0xa5, sizeof(instruction));
    (void)decode_word_mode(canonical, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_T32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction);
    EXPECT(instruction.form_id != UINT16_C(2735));
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
        { UINT32_C(0x44a01820),
          "usdot z0.s, z1.b, z0.b[0]" },
        { UINT32_C(0x44b31949),
          "usdot z9.s, z10.b, z3.b[2]" },
        { UINT32_C(0x44bf1bdf),
          "usdot z31.s, z30.b, z7.b[3]" },
        { UINT32_C(0x44a01c20),
          "sudot z0.s, z1.b, z0.b[0]" },
        { UINT32_C(0x44b31d49),
          "sudot z9.s, z10.b, z3.b[2]" },
        { UINT32_C(0x44bf1fdf),
          "sudot z31.s, z30.b, z7.b[3]" }
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
        == strlen("SUDOT z31.s, z30.b, z7.b[3]"));
    EXPECT(strcmp(text, "SUDOT z31.s, z30.b, z7.b[3]") == 0);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_7, NULL, 0u)
        == strlen(cases[2].text));

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged, #statement);                                \
    } while (0)

    REJECT_MUTATION(forged.form_id = UINT16_C(2734));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_USDOT);
    REJECT_MUTATION(forged.raw_instruction ^= UINT32_C(0x00080000));
    REJECT_MUTATION(forged.operand_count = 2u);
    REJECT_MUTATION(forged.instruction_flags = CDISASM_GROUP_NONE);
    REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_CONDITIONAL);
    REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
    REJECT_MUTATION(forged.operand[0].access = CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(forged.operand[0].extend_type = CDISASM_ARM_EXTEND_SXTB);
    REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_Z0);
    REJECT_MUTATION(forged.operand[2].reg = CDISASM_ARM_REG_Z0);
    REJECT_MUTATION(forged.operand[2].imm = 0u);
    REJECT_MUTATION(forged.operand[2].flags = CDISASM_OPERAND_FLAG_NONE);
    REJECT_MUTATION(forged.operand[2].extend_type = CDISASM_ARM_EXTEND_SXTH);
    REJECT_MUTATION(forged.operand[2].access = CDISASM_OPERAND_ACCESS_WRITE);

    forged = instruction;
    forged.raw_instruction = UINT32_C(0x44a01820);
    reject_forgery(&forged, "indexed USDOT raw sibling");

#undef REJECT_MUTATION
}
#else
static void test_formatter_contract(void)
{
}
#endif

int main(void)
{
    test_complete_leaf();
    test_profiles_transport_and_status();
    test_collision_boundaries();
    test_formatter_contract();

    if (failures != 0) {
        fprintf(stderr, "%d indexed SVE dot-product test(s) failed\n",
            failures);
        return 1;
    }
    return 0;
}
