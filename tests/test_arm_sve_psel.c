#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define TEST_ADDRESS UINT64_C(0x17b000)
#define PSEL_MASK UINT32_C(0xff20c210)
#define PSEL_VALUE UINT32_C(0x25204000)
#define SCALABLE_FLAG CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR

_Static_assert(CDISASM_ARM_NAME_PSEL == UINT16_C(1178),
               "update PSEL family tests");

static int failures;
static uint64_t allocated_count;
static uint64_t reserved_count;
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

static uint32_t psel_word(
    unsigned i1, unsigned tsz, unsigned rv,
    unsigned pn, unsigned pm, unsigned pd)
{
    return PSEL_VALUE
        | ((uint32_t)i1 << 23)
        | ((uint32_t)(tsz & 8u) << 19)
        | ((uint32_t)(tsz & 7u) << 18)
        | ((uint32_t)rv << 16)
        | ((uint32_t)pn << 10)
        | ((uint32_t)pm << 5)
        | (uint32_t)pd;
}

static int psel_fields(
    unsigned i1, unsigned tsz, uint8_t *element_size, uint64_t *lane)
{
    unsigned tszl = tsz & 7u;
    unsigned size_log2;

    if (tsz == 0u) {
        return 0;
    }
    size_log2 = (tszl & 1u) != 0u ? 0u
        : (tszl & 2u) != 0u ? 1u
        : (tszl & 4u) != 0u ? 2u : 3u;
    *element_size = (uint8_t)(1u << size_log2);
    *lane = i1;
    if (size_log2 != 3u) {
        *lane = (*lane << (3u - size_log2))
            | (((tsz >> 3) & 1u) << (2u - size_log2))
            | (tszl >> (size_log2 + 1u));
    }
    return 1;
}

#if USE_EXTRA_OPCODES
static void append_predicate(
    cdisasm_arm_instruction *instruction, unsigned reg, uint8_t element_size,
    uint8_t flags, cdisasm_operand_access access)
{
    cdisasm_arm_operand *operand =
        &instruction->operand[instruction->operand_count++];

    operand->type = CDISASM_ARM_OPERAND_PREDICATE;
    operand->reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + reg);
    operand->extend_type = (cdisasm_arm_extend_type)element_size;
    operand->flags = flags;
    operand->access = access;
}

static void make_expected(
    uint32_t word, uint8_t element_size, uint64_t lane,
    cdisasm_arm_instruction *expected)
{
    memset(expected, 0, sizeof(*expected));
    expected->address = TEST_ADDRESS;
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->name_id = CDISASM_ARM_NAME_PSEL;
    expected->form_id = UINT16_C(2565);
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->instruction_flags = SCALABLE_FLAG;
    append_predicate(expected, word & 15u, element_size,
        CDISASM_OPERAND_FLAG_NONE, CDISASM_OPERAND_ACCESS_WRITE);
    append_predicate(expected, (word >> 10) & 15u, element_size,
        CDISASM_OPERAND_FLAG_NONE, CDISASM_OPERAND_ACCESS_READ);
    append_predicate(expected, (word >> 5) & 15u, element_size,
        CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
        CDISASM_OPERAND_ACCESS_READ);
    expected->operand[2].base_reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_W12 + ((word >> 16) & 3u));
    expected->operand[2].imm = lane;
}

#  if USE_DISASM_FORMAT
static char suffix_for_size(uint8_t element_size)
{
    static const char suffixes[9] = {
        '\0', 'b', 'h', '\0', 's', '\0', '\0', '\0', 'd'
    };

    return suffixes[element_size];
}

static void expect_exact_format(
    const cdisasm_arm_instruction *instruction, uint8_t element_size,
    uint64_t lane, uint32_t word)
{
    char expected[96];
    char text[96];
    int length = snprintf(expected, sizeof(expected),
        "psel p%u, p%u, p%u.%c[w%u, %llu]",
        (unsigned)(word & 15u), (unsigned)((word >> 10) & 15u),
        (unsigned)((word >> 5) & 15u), suffix_for_size(element_size),
        (unsigned)(12u + ((word >> 16) & 3u)),
        (unsigned long long)lane);

    domain_expect(length > 0 && (size_t)length < sizeof(expected),
        word, "PSEL expected-text construction failed");
    domain_expect(cdisasm_arm_format(
        instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == (size_t)length,
        word, "PSEL formatter length mismatch");
    domain_expect(strcmp(text, expected) == 0,
        word, "PSEL formatter text mismatch");
}
#  endif
#endif

static void expect_allocated(
    uint32_t word, uint8_t element_size, uint64_t lane)
{
    cdisasm_arm_instruction instruction;

    domain_expect((word & PSEL_MASK) == PSEL_VALUE,
        word, "test generator left exact PSEL leaf");
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction expected;

        domain_expect(decode_word(
            word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u,
            word, "allocated PSEL word did not decode");
        make_expected(word, element_size, lane, &expected);
        domain_expect(memcmp(&instruction, &expected, sizeof(expected)) == 0,
            word, "allocated PSEL metadata mismatch");
#  if USE_DISASM_FORMAT
        expect_exact_format(&instruction, element_size, lane, word);
#  endif
    }
#else
    (void)element_size;
    (void)lane;
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "extras-OFF decoded allocated PSEL word");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF PSEL ownership mismatch");
#endif
    ++allocated_count;
}

static void expect_reserved(uint32_t word)
{
    cdisasm_arm_instruction instruction;

    domain_expect((word & PSEL_MASK) == PSEL_VALUE,
        word, "test generator left exact PSEL leaf");
    memset(&instruction, 0xa5, sizeof(instruction));
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "untyped PSEL residual decoded");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION),
        word, "untyped PSEL residual ownership mismatch");
    ++reserved_count;
}

static void expect_neighbor(uint32_t word)
{
    cdisasm_arm_instruction instruction;
    uint32_t decoded;

    domain_expect((word & PSEL_MASK) != PSEL_VALUE,
        word, "bit-4 neighbor remained in PSEL leaf");
    memset(&instruction, 0xa5, sizeof(instruction));
    decoded = decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    domain_expect(instruction.form_id != UINT16_C(2565)
        && instruction.name_id != CDISASM_ARM_NAME_PSEL,
        word, "neighbor selector was stolen by PSEL");
    if (decoded == 0u) {
        domain_expect(
            instruction_is_error_only(
                &instruction, CDISASM_STATUS_INVALID_INSTRUCTION)
            || instruction_is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
            word, "neighbor failure did not clear instruction metadata");
    }
    ++neighbor_count;
}

static void test_complete_leaf_and_boundary(void)
{
    unsigned i1;
    unsigned tsz;
    unsigned rv;
    unsigned pn;
    unsigned pm;
    unsigned pd;

    for (i1 = 0u; i1 < 2u; ++i1) {
        for (tsz = 0u; tsz < 16u; ++tsz) {
            uint8_t element_size = 0u;
            uint64_t lane = 0u;
            int allocated = psel_fields(
                i1, tsz, &element_size, &lane);

            for (rv = 0u; rv < 4u; ++rv) {
                for (pn = 0u; pn < 16u; ++pn) {
                    for (pm = 0u; pm < 16u; ++pm) {
                        for (pd = 0u; pd < 16u; ++pd) {
                            uint32_t word = psel_word(
                                i1, tsz, rv, pn, pm, pd);

                            if (allocated) {
                                expect_allocated(
                                    word, element_size, lane);
                            } else {
                                expect_reserved(word);
                            }
                            expect_neighbor(word | UINT32_C(0x10));
                        }
                    }
                }
            }
        }
    }
    EXPECT(allocated_count == UINT64_C(491520));
    EXPECT(reserved_count == UINT64_C(32768));
    EXPECT(neighbor_count == UINT64_C(524288));
}

static void expect_profile(
    uint32_t word, cdisasm_arm_cpu_id cpu_id, cdisasm_status enabled_status)
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
    if (expected != CDISASM_STATUS_OK) {
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_feature_alternative(void)
{
    uint32_t word = psel_word(1u, 8u, 3u, 14u, 13u, 15u);

    expect_profile(word, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
    expect_profile(word, CDISASM_ARM_CPU_APPLE_A18, CDISASM_STATUS_OK);
    expect_profile(word, CDISASM_ARM_CPU_APPLE_M4, CDISASM_STATUS_OK);
    expect_profile(word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_profile(word, CDISASM_ARM_CPU_CORTEX_A53,
        CDISASM_STATUS_INVALID_INSTRUCTION);
}

static void test_transport_and_precedence(void)
{
    static const unsigned controls[4][2] = {
        { 1u, 0u }, { 2u, 0u }, { 4u, 0u }, { 8u, 0u }
    };
    unsigned index;

    for (index = 0u; index < 4u; ++index) {
        uint32_t word = psel_word(
            controls[index][1], controls[index][0], index,
            15u - index, 12u - index, index);
        cdisasm_arm_instruction little;
        cdisasm_arm_instruction other;
        uint8_t bytes[4];
        unsigned boundary;

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

        word_to_le(word, bytes);
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
            EXPECT(decode_word(word, CDISASM_ARM_CPU_CORTEX_A53,
                boundary, CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
            EXPECT(instruction_is_error_only(&other, status));
        }
    }

    {
        uint32_t reserved = psel_word(1u, 0u, 3u, 15u, 15u, 15u);
        cdisasm_arm_instruction instruction;
        unsigned boundary;

        for (boundary = 0u; boundary < 4u; ++boundary) {
            cdisasm_status status = boundary == 0u
                ? CDISASM_STATUS_END_OF_INPUT : CDISASM_STATUS_TRUNCATED;

            memset(&instruction, 0xa5, sizeof(instruction));
            EXPECT(decode_word(reserved, CDISASM_ARM_CPU_CORTEX_A53,
                boundary, CDISASM_ARM_DECODE_OPTION_NONE,
                &instruction) == 0u);
            EXPECT(instruction_is_error_only(&instruction, status));
        }
        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(reserved, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
    }

    {
        uint32_t word = psel_word(0u, 1u, 0u, 1u, 2u, 0u);
        cdisasm_arm_instruction instruction;

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
            UINT64_C(1) << 63, &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word_mode(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction);
        EXPECT(instruction.form_id != UINT16_C(2565));
        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word_mode(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_T32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction);
        EXPECT(instruction.form_id != UINT16_C(2565));
    }

    {
        cdisasm_arm_instruction instruction;

        memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(UINT32_C(0x25204010),
            CDISASM_ARM_CPU_ANY, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 4u);
        EXPECT(instruction.form_id == UINT16_C(2566));
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_WHILEGE);
#else
        EXPECT(decode_word(UINT32_C(0x25204010),
            CDISASM_ARM_CPU_ANY, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(
    uint32_t word, const char *expected, const char *expected_upper)
{
    cdisasm_arm_instruction instruction;
    char text[96];

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == strlen(expected));
    EXPECT(strcmp(text, expected) == 0);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text)) == strlen(expected_upper));
    EXPECT(strcmp(text, expected_upper) == 0);
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
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;
    uint32_t word = psel_word(1u, 14u, 3u, 14u, 13u, 15u);

    expect_format(psel_word(0u, 1u, 0u, 1u, 2u, 0u),
        "psel p0, p1, p2.b[w12, 0]",
        "PSEL p0, p1, p2.b[w12, 0]");
    expect_format(psel_word(1u, 15u, 3u, 15u, 15u, 15u),
        "psel p15, p15, p15.b[w15, 15]",
        "PSEL p15, p15, p15.b[w15, 15]");
    expect_format(psel_word(0u, 2u, 1u, 2u, 3u, 4u),
        "psel p4, p2, p3.h[w13, 0]",
        "PSEL p4, p2, p3.h[w13, 0]");
    expect_format(psel_word(1u, 14u, 3u, 14u, 13u, 15u),
        "psel p15, p14, p13.h[w15, 7]",
        "PSEL p15, p14, p13.h[w15, 7]");
    expect_format(psel_word(0u, 4u, 2u, 5u, 6u, 7u),
        "psel p7, p5, p6.s[w14, 0]",
        "PSEL p7, p5, p6.s[w14, 0]");
    expect_format(psel_word(1u, 12u, 2u, 5u, 6u, 7u),
        "psel p7, p5, p6.s[w14, 3]",
        "PSEL p7, p5, p6.s[w14, 3]");
    expect_format(psel_word(0u, 8u, 0u, 0u, 0u, 0u),
        "psel p0, p0, p0.d[w12, 0]",
        "PSEL p0, p0, p0.d[w12, 0]");
    expect_format(psel_word(1u, 8u, 3u, 15u, 15u, 15u),
        "psel p15, p15, p15.d[w15, 1]",
        "PSEL p15, p15, p15.d[w15, 1]");

    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);

#define REJECT_MUTATION(statement)                                         \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged);                                            \
    } while (0)

    REJECT_MUTATION(forged.raw_instruction ^= UINT32_C(0x10));
    REJECT_MUTATION(forged.raw_instruction = psel_word(
        1u, 0u, 3u, 14u, 13u, 15u));
    REJECT_MUTATION(forged.form_id = UINT16_C(2566));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_PTRUE);
    REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
    REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
    REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
    REJECT_MUTATION(forged.instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED);
    REJECT_MUTATION(forged.operand_count = 2u);
    REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_P0);
    REJECT_MUTATION(forged.operand[0].extend_type = 4u);
    REJECT_MUTATION(forged.operand[0].flags =
        CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
    REJECT_MUTATION(forged.operand[0].access =
        CDISASM_OPERAND_ACCESS_READ);
    REJECT_MUTATION(forged.operand[0].base_reg = CDISASM_ARM_REG_W12);
    REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_P0);
    REJECT_MUTATION(forged.operand[1].extend_type = 8u);
    REJECT_MUTATION(forged.operand[1].access =
        CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(forged.operand[2].reg = CDISASM_ARM_REG_P0);
    REJECT_MUTATION(forged.operand[2].extend_type = 4u);
    REJECT_MUTATION(forged.operand[2].flags =
        CDISASM_OPERAND_FLAG_NONE);
    REJECT_MUTATION(forged.operand[2].access =
        CDISASM_OPERAND_ACCESS_WRITE);
    REJECT_MUTATION(forged.operand[2].base_reg = CDISASM_ARM_REG_W12);
    REJECT_MUTATION(forged.operand[2].imm = 6u);
    REJECT_MUTATION(forged.operand[2].index_reg = CDISASM_ARM_REG_W0);
    REJECT_MUTATION(forged.operand[2].register_list = 1u);
    REJECT_MUTATION(forged.operand[2].scale = 1u);
    REJECT_MUTATION(forged.operand[3].type =
        CDISASM_OPERAND_REGISTER);

#undef REJECT_MUTATION
}
#endif

int main(void)
{
    test_complete_leaf_and_boundary();
    test_feature_alternative();
    test_transport_and_precedence();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatter_contract();
#endif
    if (failures != 0) {
        fprintf(stderr, "ARM SVE PSEL tests failed: %d\n", failures);
        return 1;
    }
    printf("ARM SVE PSEL tests passed "
           "(%llu allocated, %llu untyped residuals, %llu neighbors)\n",
           (unsigned long long)allocated_count,
           (unsigned long long)reserved_count,
           (unsigned long long)neighbor_count);
    return 0;
}
