#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define TEST_ADDRESS UINT64_C(0x1b5000)
#define CRYPTO_PARENT_MASK UINT32_C(0xff3ef800)
#define CRYPTO_PARENT_VALUE UINT32_C(0x4522e000)
#define CRYPTO_LEAF_MASK UINT32_C(0xfffffc00)
#define AESE_VALUE UINT32_C(0x4522e000)
#define AESD_VALUE UINT32_C(0x4522e400)
#define SM4E_VALUE UINT32_C(0x4523e000)
#define SCALABLE_FLAG CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR

_Static_assert(CDISASM_ARM_NAME_AESD == UINT16_C(530),
               "update SVE AESD exact-family tests");
_Static_assert(CDISASM_ARM_NAME_AESE == UINT16_C(532),
               "update SVE AESE exact-family tests");
_Static_assert(CDISASM_ARM_NAME_SM4E == UINT16_C(1401),
               "update SVE SM4E exact-family tests");

typedef struct crypto_leaf {
    uint32_t value;
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    uint8_t element_size;
} crypto_leaf;

static const crypto_leaf crypto_leaves[] = {
    { AESE_VALUE, UINT16_C(2905), CDISASM_ARM_NAME_AESE, 1u },
    { AESD_VALUE, UINT16_C(2906), CDISASM_ARM_NAME_AESD, 1u },
    { SM4E_VALUE, UINT16_C(2907), CDISASM_ARM_NAME_SM4E, 4u }
};

static int failures;
static uint64_t allocated_count;
static uint64_t reserved_count;
static uint64_t named_profile_count;

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

static uint32_t crypto_word(
    unsigned size, unsigned algorithm, unsigned operation,
    unsigned zm, unsigned zd)
{
    return CRYPTO_PARENT_VALUE | ((uint32_t)size << 22)
        | ((uint32_t)algorithm << 16)
        | ((uint32_t)operation << 10)
        | ((uint32_t)zm << 5) | zd;
}

static const crypto_leaf *crypto_leaf_for_word(uint32_t word)
{
    size_t index;

    for (index = 0u;
         index < sizeof(crypto_leaves) / sizeof(crypto_leaves[0]);
         ++index) {
        if ((word & CRYPTO_LEAF_MASK) == crypto_leaves[index].value) {
            return &crypto_leaves[index];
        }
    }
    return NULL;
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
static void make_expected(
    uint32_t word, const crypto_leaf *leaf,
    cdisasm_arm_instruction *expected)
{
    unsigned zd = word & 31u;
    unsigned zm = (word >> 5) & 31u;
    size_t operand_index;

    memset(expected, 0, sizeof(*expected));
    expected->address = TEST_ADDRESS;
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->name_id = leaf->name_id;
    expected->form_id = leaf->form_id;
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->instruction_flags = SCALABLE_FLAG;
    expected->operand_count = 3u;
    for (operand_index = 0u; operand_index < 3u; ++operand_index) {
        cdisasm_arm_operand *operand = &expected->operand[operand_index];

        operand->type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
        operand->reg = (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_Z0 + (operand_index < 2u ? zd : zm));
        operand->extend_type =
            (cdisasm_arm_extend_type)leaf->element_size;
        operand->access = operand_index < 2u
            ? CDISASM_OPERAND_ACCESS_READ_WRITE
            : CDISASM_OPERAND_ACCESS_READ;
    }
}
#endif

static void expect_allocated(uint32_t word, const crypto_leaf *leaf)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction expected;

        domain_expect(decode_word(
            word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u,
            word, "allocated crypto binary word did not decode");
        make_expected(word, leaf, &expected);
        domain_expect(memcmp(&instruction, &expected, sizeof(expected)) == 0,
            word, "allocated crypto binary metadata mismatch");
    }
#else
    (void)leaf;
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "extras-OFF decoded crypto binary word");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF crypto binary ownership mismatch");
#endif
}

static void expect_reserved(uint32_t word)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "reserved crypto binary word decoded");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION),
        word, "reserved crypto binary status mismatch");
}

static void test_complete_parent(void)
{
    unsigned size;
    unsigned algorithm;
    unsigned operation;
    unsigned zm;
    unsigned zd;

    for (size = 0u; size < 4u; ++size) {
        for (algorithm = 0u; algorithm < 2u; ++algorithm) {
            for (operation = 0u; operation < 2u; ++operation) {
                for (zm = 0u; zm < 32u; ++zm) {
                    for (zd = 0u; zd < 32u; ++zd) {
                        uint32_t word = crypto_word(
                            size, algorithm, operation, zm, zd);
                        const crypto_leaf *leaf =
                            crypto_leaf_for_word(word);

                        domain_expect(
                            (word & CRYPTO_PARENT_MASK)
                                == CRYPTO_PARENT_VALUE,
                            word,
                            "constructed word escaped crypto binary parent");
                        if (leaf != NULL) {
                            expect_allocated(word, leaf);
                            ++allocated_count;
                        } else {
                            expect_reserved(word);
                            ++reserved_count;
                        }
                    }
                }
            }
        }
    }
    EXPECT(allocated_count == UINT64_C(3072));
    EXPECT(reserved_count == UINT64_C(13312));
}

static void expect_status(
    uint32_t word, cdisasm_arm_cpu_id cpu_id, cdisasm_status expected)
{
    cdisasm_arm_instruction instruction;
    const crypto_leaf *leaf = crypto_leaf_for_word(word);

    EXPECT(leaf != NULL);
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, cpu_id, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction)
        == (expected == CDISASM_STATUS_OK ? 4u : 0u));
    if (expected == CDISASM_STATUS_OK) {
        EXPECT(instruction.form_id == leaf->form_id);
        EXPECT(instruction.name_id == leaf->name_id);
    } else {
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_profiles_transport_and_status(void)
{
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction other;
    const uint32_t high = SM4E_VALUE | UINT32_C(0x3ff);
    uint8_t bytes[4];
    size_t leaf_index;
    uint32_t cpu_value;
    unsigned boundary;

    for (leaf_index = 0u;
         leaf_index < sizeof(crypto_leaves) / sizeof(crypto_leaves[0]);
         ++leaf_index) {
        uint32_t word = crypto_leaves[leaf_index].value
            | UINT32_C(0x3ff);

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
            } else {
                expected = CDISASM_STATUS_INVALID_INSTRUCTION;
#else
            } else {
                expected = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
            }
            expect_status(word, cpu_id, expected);
            ++named_profile_count;
        }
    }
    EXPECT(named_profile_count == UINT64_C(114));

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
        EXPECT(decode_word(AESE_VALUE, CDISASM_ARM_CPU_ANY, boundary,
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(&other, status));
    }
    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(AESE_VALUE, CDISASM_ARM_CPU_ANY, 4u,
        UINT64_C(1) << 63, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));
}

static void test_mode_and_neighbor_isolation(void)
{
    cdisasm_arm_instruction instruction;
    size_t leaf_index;
    unsigned bit;

    for (leaf_index = 0u;
         leaf_index < sizeof(crypto_leaves) / sizeof(crypto_leaves[0]);
         ++leaf_index) {
        for (bit = 10u; bit < 32u; ++bit) {
            uint32_t neighbor;

            if ((CRYPTO_LEAF_MASK & (UINT32_C(1) << bit)) == 0u) {
                continue;
            }
            neighbor = crypto_leaves[leaf_index].value
                ^ (UINT32_C(1) << bit);
            memset(&instruction, 0xa5, sizeof(instruction));
            (void)decode_word(neighbor, CDISASM_ARM_CPU_ANY, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            EXPECT(instruction.form_id != crypto_leaves[leaf_index].form_id);
        }

        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word_mode(
            crypto_leaves[leaf_index].value, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction);
        EXPECT(instruction.form_id != crypto_leaves[leaf_index].form_id);
        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word_mode(
            crypto_leaves[leaf_index].value, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_T32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction);
        EXPECT(instruction.form_id != crypto_leaves[leaf_index].form_id);
    }
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
        { AESE_VALUE, "aese z0.b, z0.b, z0.b" },
        { UINT32_C(0x4522e167), "aese z7.b, z7.b, z11.b" },
        { UINT32_C(0x4522e7ff), "aesd z31.b, z31.b, z31.b" },
        { UINT32_C(0x4523e167), "sm4e z7.s, z7.s, z11.s" },
        { UINT32_C(0x4523e3ff), "sm4e z31.s, z31.s, z31.s" }
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
        text, sizeof(text)) == strlen("SM4E z31.s, z31.s, z31.s"));
    EXPECT(strcmp(text, "SM4E z31.s, z31.s, z31.s") == 0);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_7, NULL, 0u)
        == strlen(cases[4].text));

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged, #statement);                                \
    } while (0)

    REJECT_MUTATION(forged.form_id = UINT16_C(2905));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_AESE);
    REJECT_MUTATION(forged.raw_instruction ^= UINT32_C(0x00010000));
    REJECT_MUTATION(forged.raw_instruction |= UINT32_C(0x00000400));
    REJECT_MUTATION(forged.raw_instruction |= UINT32_C(0x00400000));
    REJECT_MUTATION(forged.operand_count = 2u);
    REJECT_MUTATION(forged.instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK);
    REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_CONDITIONAL);
    REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
    REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_Z0);
    REJECT_MUTATION(forged.operand[0].access =
        CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_Z0);
    REJECT_MUTATION(forged.operand[1].access =
        CDISASM_OPERAND_ACCESS_READ);
    REJECT_MUTATION(forged.operand[2].reg = CDISASM_ARM_REG_Z0);
    REJECT_MUTATION(forged.operand[2].extend_type =
        (cdisasm_arm_extend_type)1u);
    REJECT_MUTATION(forged.operand[2].access =
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    REJECT_MUTATION(forged.operand[2].flags =
        CDISASM_ARM_OPERAND_FLAG_HAS_LANE);

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
        fprintf(stderr, "%d SVE crypto binary test(s) failed\n", failures);
        return 1;
    }
    printf("ARM SVE crypto binary tests passed "
           "(%llu allocated, %llu reserved, %llu profile probes)\n",
        (unsigned long long)allocated_count,
        (unsigned long long)reserved_count,
        (unsigned long long)named_profile_count);
    return 0;
}
