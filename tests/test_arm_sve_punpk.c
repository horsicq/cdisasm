#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define TEST_ADDRESS UINT64_C(0x1b6000)
#define PUNPK_PARENT_MASK UINT32_C(0xfffefe10)
#define PUNPK_PARENT_VALUE UINT32_C(0x05304000)
#define PUNPK_LEAF_MASK UINT32_C(0xfffffe10)
#define PUNPKLO_VALUE UINT32_C(0x05304000)
#define PUNPKHI_VALUE UINT32_C(0x05314000)
#define SCALABLE_FLAG CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR

_Static_assert(CDISASM_ARM_NAME_PUNPKHI == UINT16_C(1182),
               "update SVE PUNPKHI exact-family tests");
_Static_assert(CDISASM_ARM_NAME_PUNPKLO == UINT16_C(1183),
               "update SVE PUNPKLO exact-family tests");
_Static_assert(CDISASM_ARM_CPU_LAST - CDISASM_ARM_CPU_FIRST + 1u
                   == UINT32_C(38),
               "update SVE PUNPK named-profile coverage");

static int failures;
static uint64_t parent_count;
static uint64_t profile_count;

#define EXPECT(condition)                                                   \
    do {                                                                    \
        if (!(condition)) {                                                 \
            if (failures < 24) {                                           \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",       \
                    __FILE__, __LINE__, #condition);                        \
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

static uint32_t punpk_word(unsigned high, unsigned pn, unsigned pd)
{
    return PUNPK_PARENT_VALUE | ((uint32_t)high << 16)
        | ((uint32_t)pn << 5) | (uint32_t)pd;
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

static int is_punpk_identity(
    const cdisasm_arm_instruction *instruction)
{
    return instruction->form_id == UINT16_C(2468)
        || instruction->form_id == UINT16_C(2469)
        || instruction->name_id == CDISASM_ARM_NAME_PUNPKLO
        || instruction->name_id == CDISASM_ARM_NAME_PUNPKHI;
}

#if USE_EXTRA_OPCODES
static void append_predicate(
    cdisasm_arm_instruction *instruction, unsigned encoded,
    uint8_t element_size, cdisasm_operand_access access)
{
    cdisasm_arm_operand *operand =
        &instruction->operand[instruction->operand_count++];

    operand->type = CDISASM_ARM_OPERAND_PREDICATE;
    operand->reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + encoded);
    operand->extend_type = (cdisasm_arm_extend_type)element_size;
    operand->flags = CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED;
    operand->access = access;
}

static void make_expected(uint32_t word, cdisasm_arm_instruction *expected)
{
    int high = (word & UINT32_C(0x00010000)) != 0u;

    memset(expected, 0, sizeof(*expected));
    expected->address = TEST_ADDRESS;
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->name_id = high
        ? CDISASM_ARM_NAME_PUNPKHI : CDISASM_ARM_NAME_PUNPKLO;
    expected->form_id = high ? UINT16_C(2469) : UINT16_C(2468);
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->instruction_flags = SCALABLE_FLAG;
    append_predicate(
        expected, word & 15u, 2u, CDISASM_OPERAND_ACCESS_WRITE);
    append_predicate(
        expected, (word >> 5) & 15u, 1u,
        CDISASM_OPERAND_ACCESS_READ);
}
#endif

static void expect_allocated(uint32_t word)
{
    cdisasm_arm_instruction instruction;

    domain_expect((word & PUNPK_PARENT_MASK) == PUNPK_PARENT_VALUE,
        word, "test generator left exact PUNPK parent");
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction expected;

        domain_expect(decode_word(
            word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u,
            word, "allocated PUNPK word did not decode");
        make_expected(word, &expected);
        domain_expect(memcmp(&instruction, &expected, sizeof(expected)) == 0,
            word, "allocated PUNPK metadata mismatch");
#  if USE_DISASM_FORMAT
        {
            char expected_text[48];
            char text[48];
            int length = snprintf(
                expected_text, sizeof(expected_text), "punpk%s p%u.h, p%u.b",
                (word & UINT32_C(0x00010000)) != 0u ? "hi" : "lo",
                (unsigned)(word & 15u),
                (unsigned)((word >> 5) & 15u));

            domain_expect(length > 0
                    && (size_t)length < sizeof(expected_text),
                word, "PUNPK expected-text construction failed");
            domain_expect(cdisasm_arm_format(
                &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
                text, sizeof(text)) == (size_t)length,
                word, "PUNPK formatter length mismatch");
            domain_expect(strcmp(text, expected_text) == 0,
                word, "PUNPK formatter text mismatch");
        }
#  endif
    }
#else
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "extras-OFF decoded allocated PUNPK word");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF PUNPK ownership mismatch");
#endif
    ++parent_count;
}

static void test_complete_parent(void)
{
    unsigned high;
    unsigned pn;
    unsigned pd;

    for (high = 0u; high < 2u; ++high) {
        for (pn = 0u; pn < 16u; ++pn) {
            for (pd = 0u; pd < 16u; ++pd) {
                uint32_t word = punpk_word(high, pn, pd);

                domain_expect((word & PUNPK_LEAF_MASK)
                        == (high ? PUNPKHI_VALUE : PUNPKLO_VALUE),
                    word, "PUNPK word escaped selected exact leaf");
                expect_allocated(word);
            }
        }
    }
    EXPECT(parent_count == UINT64_C(512));
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
        EXPECT(is_punpk_identity(&instruction));
    } else {
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_profiles_transport_and_status(void)
{
    const uint32_t low = punpk_word(0u, 11u, 7u);
    const uint32_t high = punpk_word(1u, 15u, 15u);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction other;
    uint8_t bytes[4];
    uint32_t cpu_value;
    unsigned leaf;
    unsigned boundary;

    for (leaf = 0u; leaf < 2u; ++leaf) {
        uint32_t word = leaf != 0u ? high : low;

#if USE_EXTRA_OPCODES
        expect_status(word, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
#else
        expect_status(word, CDISASM_ARM_CPU_ANY,
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
            } else if (cpu_id == CDISASM_ARM_CPU_FUJITSU_A64FX
                || cpu_id == CDISASM_ARM_CPU_APPLE_A18
                || cpu_id == CDISASM_ARM_CPU_APPLE_M4) {
                expected = CDISASM_STATUS_OK;
            } else {
                expected = CDISASM_STATUS_INVALID_INSTRUCTION;
#else
            } else {
                expected = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
            }
            expect_status(word, cpu_id, expected);
            ++profile_count;
        }
    }
    EXPECT(profile_count == UINT64_C(76));

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

static void test_mode_and_neighbor_isolation(void)
{
    static const uint32_t values[2] = {
        PUNPKLO_VALUE, PUNPKHI_VALUE
    };
    cdisasm_arm_instruction instruction;
    unsigned leaf;
    unsigned bit;

    for (leaf = 0u; leaf < 2u; ++leaf) {
        for (bit = 0u; bit < 32u; ++bit) {
            uint32_t neighbor;

            if ((PUNPK_PARENT_MASK & (UINT32_C(1) << bit)) == 0u) {
                continue;
            }
            neighbor = values[leaf] ^ (UINT32_C(1) << bit);
            memset(&instruction, 0xa5, sizeof(instruction));
            (void)decode_word(neighbor, CDISASM_ARM_CPU_ANY, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            EXPECT(!is_punpk_identity(&instruction));
        }

        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word_mode(
            values[leaf], CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A32,
            4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
        EXPECT(!is_punpk_identity(&instruction));
        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word_mode(
            values[leaf], CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_T32,
            4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
        EXPECT(!is_punpk_identity(&instruction));
    }
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void reject_forgery(
    const cdisasm_arm_instruction *instruction, const char *mutation)
{
    char text[64];
    size_t length;

    memset(text, 0xa5, sizeof(text));
    length = cdisasm_arm_format(
        instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text));
    if (length != 0u || text[0] != '\0') {
        if (failures < 24) {
            fprintf(stderr, "accepted PUNPK formatter forgery: %s\n",
                mutation);
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
        { PUNPKLO_VALUE, "punpklo p0.h, p0.b" },
        { UINT32_C(0x05304167), "punpklo p7.h, p11.b" },
        { PUNPKHI_VALUE, "punpkhi p0.h, p0.b" },
        { UINT32_C(0x053141ef), "punpkhi p15.h, p15.b" }
    };
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;
    char text[64];
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
        text, sizeof(text)) == strlen("PUNPKHI p15.h, p15.b"));
    EXPECT(strcmp(text, "PUNPKHI p15.h, p15.b") == 0);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_7, NULL, 0u)
        == strlen(cases[3].text));

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged, #statement);                                \
    } while (0)

    REJECT_MUTATION(forged.form_id = UINT16_C(2468));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_PUNPKLO);
    REJECT_MUTATION(forged.raw_instruction ^= UINT32_C(0x00010000));
    REJECT_MUTATION(forged.raw_instruction ^= UINT32_C(0x00020000));
    REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
    REJECT_MUTATION(forged.operand_count = 1u);
    REJECT_MUTATION(forged.instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK);
    REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_CONDITIONAL);
    REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
    REJECT_MUTATION(forged.operand[0].type = CDISASM_OPERAND_REGISTER);
    REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_P0);
    REJECT_MUTATION(forged.operand[0].extend_type =
        (cdisasm_arm_extend_type)1u);
    REJECT_MUTATION(forged.operand[0].flags = CDISASM_OPERAND_FLAG_NONE);
    REJECT_MUTATION(forged.operand[0].access =
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_P0);
    REJECT_MUTATION(forged.operand[1].extend_type =
        (cdisasm_arm_extend_type)2u);
    REJECT_MUTATION(forged.operand[1].flags = CDISASM_OPERAND_FLAG_NONE);
    REJECT_MUTATION(forged.operand[1].access =
        CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(forged.operand[1].imm = UINT64_C(1));

#undef REJECT_MUTATION
}
#else
static void test_formatter_contract(void)
{
}
#endif

int main(void)
{
    test_complete_parent();
    test_profiles_transport_and_status();
    test_mode_and_neighbor_isolation();
    test_formatter_contract();

    if (failures != 0) {
        fprintf(stderr, "%d SVE PUNPK test(s) failed\n", failures);
        return 1;
    }
    printf("ARM SVE PUNPK tests passed "
           "(%llu parent words, %llu named-profile probes)\n",
        (unsigned long long)parent_count,
        (unsigned long long)profile_count);
    return 0;
}
