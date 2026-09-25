#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define TEST_ADDRESS UINT64_C(0x179000)
#define FAMILY_FLAGS                                                       \
    (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR                          \
        | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)

_Static_assert(CDISASM_ARM_NAME_BRKA == UINT16_C(614),
               "update predicate-break family tests");
_Static_assert(CDISASM_ARM_NAME_BRKPBS == UINT16_C(623),
               "update predicate-break family tests");

typedef enum break_kind {
    BREAK_KIND_BRKP,
    BREAK_KIND_BRK,
    BREAK_KIND_BRKN
} break_kind;

typedef struct break_descriptor {
    uint32_t mask;
    uint32_t value;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    break_kind kind;
} break_descriptor;

static const break_descriptor descriptors[10] = {
    { UINT32_C(0xfff0c210), UINT32_C(0x2500c000),
      CDISASM_ARM_NAME_BRKPA, UINT16_C(2546), BREAK_KIND_BRKP },
    { UINT32_C(0xfff0c210), UINT32_C(0x2540c000),
      CDISASM_ARM_NAME_BRKPAS, UINT16_C(2547), BREAK_KIND_BRKP },
    { UINT32_C(0xfff0c210), UINT32_C(0x2500c010),
      CDISASM_ARM_NAME_BRKPB, UINT16_C(2548), BREAK_KIND_BRKP },
    { UINT32_C(0xfff0c210), UINT32_C(0x2540c010),
      CDISASM_ARM_NAME_BRKPBS, UINT16_C(2549), BREAK_KIND_BRKP },
    { UINT32_C(0xffffc200), UINT32_C(0x25104000),
      CDISASM_ARM_NAME_BRKA, UINT16_C(2550), BREAK_KIND_BRK },
    { UINT32_C(0xffffc210), UINT32_C(0x25504000),
      CDISASM_ARM_NAME_BRKAS, UINT16_C(2551), BREAK_KIND_BRK },
    { UINT32_C(0xffffc200), UINT32_C(0x25904000),
      CDISASM_ARM_NAME_BRKB, UINT16_C(2552), BREAK_KIND_BRK },
    { UINT32_C(0xffffc210), UINT32_C(0x25d04000),
      CDISASM_ARM_NAME_BRKBS, UINT16_C(2553), BREAK_KIND_BRK },
    { UINT32_C(0xffffc210), UINT32_C(0x25184000),
      CDISASM_ARM_NAME_BRKN, UINT16_C(2554), BREAK_KIND_BRKN },
    { UINT32_C(0xffffc210), UINT32_C(0x25584000),
      CDISASM_ARM_NAME_BRKNS, UINT16_C(2555), BREAK_KIND_BRKN }
};

static int failures;
static uint64_t allocated_count;
static uint64_t reserved_count;

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

static int is_target_identity(const cdisasm_arm_instruction *instruction)
{
    return instruction->form_id >= UINT16_C(2546)
        && instruction->form_id <= UINT16_C(2555);
}

#if USE_EXTRA_OPCODES
static cdisasm_arm_operand *append_predicate(
    cdisasm_arm_instruction *instruction, unsigned reg, uint8_t flags,
    cdisasm_operand_access access)
{
    cdisasm_arm_operand *operand =
        &instruction->operand[instruction->operand_count++];

    operand->type = CDISASM_ARM_OPERAND_PREDICATE;
    operand->reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + reg);
    operand->extend_type = 1u;
    operand->flags = flags;
    operand->access = access;
    return operand;
}

static void make_expected(
    const break_descriptor *descriptor, uint32_t word,
    cdisasm_arm_instruction *expected)
{
    unsigned pd = word & 15u;
    unsigned pn = (word >> 5) & 15u;
    unsigned pg = (word >> 10) & 15u;
    int sets_flags = (word & UINT32_C(0x00400000)) != 0u;
    int merging = descriptor->kind == BREAK_KIND_BRK
        && (word & UINT32_C(0x10)) != 0u;

    memset(expected, 0, sizeof(*expected));
    expected->address = TEST_ADDRESS;
    expected->raw_instruction = word;
    expected->opcode_size = 4u;
    expected->name_id = descriptor->name_id;
    expected->form_id = descriptor->form_id;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->instruction_flags = FAMILY_FLAGS
        | (sets_flags ? CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS : 0u);

    append_predicate(
        expected, pd, CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
        descriptor->kind == BREAK_KIND_BRKN
            ? CDISASM_OPERAND_ACCESS_WRITE
            : merging ? CDISASM_OPERAND_ACCESS_READ_WRITE
                      : CDISASM_OPERAND_ACCESS_WRITE);
    append_predicate(
        expected, pg,
        merging ? CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE
                : CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO,
        CDISASM_OPERAND_ACCESS_READ);
    append_predicate(
        expected, pn, CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
        CDISASM_OPERAND_ACCESS_READ);
    if (descriptor->kind == BREAK_KIND_BRKP) {
        append_predicate(
            expected, (word >> 16) & 15u,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
            CDISASM_OPERAND_ACCESS_READ);
    } else if (descriptor->kind == BREAK_KIND_BRKN) {
        append_predicate(
            expected, pd, CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
            CDISASM_OPERAND_ACCESS_READ);
    }
}
#endif

static void expect_allocated(
    const break_descriptor *descriptor, uint32_t word)
{
    cdisasm_arm_instruction instruction;

    domain_expect((word & descriptor->mask) == descriptor->value,
        word, "test generator left exact predicate-break leaf");
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction expected;

        domain_expect(decode_word(
            word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u,
            word, "allocated predicate-break word did not decode");
        make_expected(descriptor, word, &expected);
        domain_expect(memcmp(&instruction, &expected, sizeof(expected)) == 0,
            word, "allocated predicate-break metadata mismatch");
    }
#else
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "extras-OFF decoded predicate-break word");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF predicate-break ownership mismatch");
#endif
    ++allocated_count;
}

static void expect_reserved(uint32_t word)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "reserved predicate-break word decoded");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION),
        word, "reserved predicate-break ownership mismatch");
    ++reserved_count;
}

static void test_exact_domains(void)
{
    unsigned descriptor_index;

    for (descriptor_index = 0u; descriptor_index < 4u;
         ++descriptor_index) {
        const break_descriptor *descriptor =
            &descriptors[descriptor_index];
        unsigned pm;
        unsigned pg;
        unsigned pn;
        unsigned pd;

        for (pm = 0u; pm < 16u; ++pm) {
            for (pg = 0u; pg < 16u; ++pg) {
                for (pn = 0u; pn < 16u; ++pn) {
                    for (pd = 0u; pd < 16u; ++pd) {
                        expect_allocated(descriptor,
                            descriptor->value | (pm << 16) | (pg << 10)
                                | (pn << 5) | pd);
                    }
                }
            }
        }
    }

    for (descriptor_index = 4u; descriptor_index < 8u;
         ++descriptor_index) {
        const break_descriptor *descriptor =
            &descriptors[descriptor_index];
        unsigned maximum_m = (descriptor_index == 4u
                || descriptor_index == 6u) ? 1u : 0u;
        unsigned m;
        unsigned pg;
        unsigned pn;
        unsigned pd;

        for (m = 0u; m <= maximum_m; ++m) {
            for (pg = 0u; pg < 16u; ++pg) {
                for (pn = 0u; pn < 16u; ++pn) {
                    for (pd = 0u; pd < 16u; ++pd) {
                        expect_allocated(descriptor,
                            descriptor->value | (m << 4) | (pg << 10)
                                | (pn << 5) | pd);
                    }
                }
            }
        }
    }

    for (descriptor_index = 8u; descriptor_index < 10u;
         ++descriptor_index) {
        const break_descriptor *descriptor =
            &descriptors[descriptor_index];
        unsigned pg;
        unsigned pn;
        unsigned pd;

        for (pg = 0u; pg < 16u; ++pg) {
            for (pn = 0u; pn < 16u; ++pn) {
                for (pd = 0u; pd < 16u; ++pd) {
                    expect_allocated(descriptor,
                        descriptor->value | (pg << 10) | (pn << 5) | pd);
                }
            }
        }
    }
    EXPECT(allocated_count == UINT64_C(294912));
}

static void test_parent_residuals(void)
{
    unsigned s;
    unsigned b;
    unsigned pm;
    unsigned pg;
    unsigned pn;
    unsigned pd;
    unsigned ab;

    /* sve_int_brkp reserves the complete op=1 half of its parent. */
    for (s = 0u; s < 2u; ++s) {
        for (b = 0u; b < 2u; ++b) {
            for (pm = 0u; pm < 16u; ++pm) {
                for (pg = 0u; pg < 16u; ++pg) {
                    for (pn = 0u; pn < 16u; ++pn) {
                        for (pd = 0u; pd < 16u; ++pd) {
                            expect_reserved(UINT32_C(0x2580c000)
                                | (s << 22) | (pm << 16) | (pg << 10)
                                | (pn << 5) | (b << 4) | pd);
                        }
                    }
                }
            }
        }
    }

    /* S=1 never allocates the merging control in sve_int_break. */
    for (ab = 0u; ab < 2u; ++ab) {
        for (pg = 0u; pg < 16u; ++pg) {
            for (pn = 0u; pn < 16u; ++pn) {
                for (pd = 0u; pd < 16u; ++pd) {
                    expect_reserved(UINT32_C(0x25504010)
                        | (ab << 23) | (pg << 10) | (pn << 5) | pd);
                }
            }
        }
    }
    EXPECT(reserved_count == UINT64_C(270336));
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

static void test_feature_alternatives(void)
{
    unsigned index;

    for (index = 0u; index < 10u; ++index) {
        uint32_t word = descriptors[index].value
            | UINT32_C(0x00003d4a);

        expect_profile(word, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
        expect_profile(word, CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_STATUS_OK);
        expect_profile(word, CDISASM_ARM_CPU_APPLE_A18,
            CDISASM_STATUS_OK);
        expect_profile(word, CDISASM_ARM_CPU_APPLE_M4,
            CDISASM_STATUS_OK);
        expect_profile(word, CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

static void test_transport_and_boundaries(void)
{
    static const uint32_t words[] = {
        UINT32_C(0x2500fd61), UINT32_C(0x2546f027),
        UINT32_C(0x25106d15), UINT32_C(0x25d07d89),
        UINT32_C(0x25185961), UINT32_C(0x25587dcb)
    };
    static const uint32_t adjacent_words[] = {
        UINT32_C(0x25004000), UINT32_C(0x2550c000),
        UINT32_C(0x2558c000), UINT32_C(0x2518f000)
    };
    unsigned index;

    for (index = 0u; index < sizeof(words) / sizeof(words[0]); ++index) {
        cdisasm_arm_instruction little;
        cdisasm_arm_instruction other;
        uint8_t bytes[4];
        unsigned boundary;

        memset(&little, 0xa5, sizeof(little));
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(words[index], CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &little) == 4u);
#else
        EXPECT(decode_word(words[index], CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &little) == 0u);
#endif
        bytes[0] = (uint8_t)(words[index] >> 24);
        bytes[1] = (uint8_t)(words[index] >> 16);
        bytes[2] = (uint8_t)(words[index] >> 8);
        bytes[3] = (uint8_t)words[index];
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

        word_to_le(words[index], bytes);
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
            EXPECT(decode_word(words[index], CDISASM_ARM_CPU_ANY, boundary,
                CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
            EXPECT(instruction_is_error_only(&other, status));
        }
    }

    for (index = 0u;
         index < sizeof(adjacent_words) / sizeof(adjacent_words[0]);
         ++index) {
        cdisasm_arm_instruction instruction;

        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word(adjacent_words[index], CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
        EXPECT(!is_target_identity(&instruction));
    }

    {
        cdisasm_arm_instruction instruction;

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(words[0], CDISASM_ARM_CPU_ANY, 4u,
            UINT64_C(1) << 63, &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word_mode(words[0], CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction);
        EXPECT(!is_target_identity(&instruction));
        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word_mode(words[0], CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_T32, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction);
        EXPECT(!is_target_identity(&instruction));
    }
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(uint32_t word, const char *expected)
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
        &instruction, CDISASM_FORMAT_SYNTAX_7, NULL, 0u)
        == strlen(expected));
}

static void reject_forgery(cdisasm_arm_instruction *instruction)
{
    char text[96];

    memset(text, 0xa5, sizeof(text));
    EXPECT(cdisasm_arm_format(
        instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == 0u);
    EXPECT(text[0] == '\0');
}

static void test_formatter(void)
{
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;

    expect_format(UINT32_C(0x2500d961),
        "brkpa p1.b, p6/z, p11.b, p0.b");
    expect_format(UINT32_C(0x2540fdef),
        "brkpas p15.b, p15/z, p15.b, p0.b");
    expect_format(UINT32_C(0x2504e072),
        "brkpb p2.b, p8/z, p3.b, p4.b");
    expect_format(UINT32_C(0x2546e4b3),
        "brkpbs p3.b, p9/z, p5.b, p6.b");
    expect_format(UINT32_C(0x251068e4),
        "brka p4.b, p10/z, p7.b");
    expect_format(UINT32_C(0x25106d15),
        "brka p5.b, p11/m, p8.b");
    expect_format(UINT32_C(0x25507126),
        "brkas p6.b, p12/z, p9.b");
    expect_format(UINT32_C(0x25907547),
        "brkb p7.b, p13/z, p10.b");
    expect_format(UINT32_C(0x25907978),
        "brkb p8.b, p14/m, p11.b");
    expect_format(UINT32_C(0x25d07d89),
        "brkbs p9.b, p15/z, p12.b");
    expect_format(UINT32_C(0x251841aa),
        "brkn p10.b, p0/z, p13.b, p10.b");
    expect_format(UINT32_C(0x255845cb),
        "brkns p11.b, p1/z, p14.b, p11.b");

    EXPECT(decode_word(UINT32_C(0x25106d15),
        CDISASM_ARM_CPU_ANY, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    forged = instruction;
    forged.name_id = CDISASM_ARM_NAME_BRKB;
    reject_forgery(&forged);
    forged = instruction;
    forged.form_id = UINT16_C(2551);
    reject_forgery(&forged);
    forged = instruction;
    forged.raw_instruction ^= UINT32_C(0x00800000);
    reject_forgery(&forged);
    forged = instruction;
    forged.instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
    reject_forgery(&forged);
    forged = instruction;
    forged.operand_count = 2u;
    reject_forgery(&forged);
    forged = instruction;
    forged.operand[0].access = CDISASM_OPERAND_ACCESS_WRITE;
    reject_forgery(&forged);
    forged = instruction;
    forged.operand[1].flags = CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO;
    reject_forgery(&forged);
    forged = instruction;
    forged.operand[1].reg = CDISASM_ARM_REG_P10;
    reject_forgery(&forged);
    forged = instruction;
    forged.operand[2].extend_type = 2u;
    reject_forgery(&forged);

    EXPECT(decode_word(UINT32_C(0x2500d961),
        CDISASM_ARM_CPU_ANY, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    forged = instruction;
    forged.operand[3].reg = CDISASM_ARM_REG_P1;
    reject_forgery(&forged);
    forged = instruction;
    forged.operand[3].access = CDISASM_OPERAND_ACCESS_WRITE;
    reject_forgery(&forged);
    forged = instruction;
    forged.operand[3].flags = 0u;
    reject_forgery(&forged);

    EXPECT(decode_word(UINT32_C(0x25507126),
        CDISASM_ARM_CPU_ANY, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    forged = instruction;
    forged.raw_instruction ^= UINT32_C(0x10);
    reject_forgery(&forged);

    EXPECT(decode_word(UINT32_C(0x251841aa),
        CDISASM_ARM_CPU_ANY, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    forged = instruction;
    forged.operand[0].access = CDISASM_OPERAND_ACCESS_READ_WRITE;
    reject_forgery(&forged);
    forged = instruction;
    forged.operand[3].access = CDISASM_OPERAND_ACCESS_READ_WRITE;
    reject_forgery(&forged);
    forged = instruction;
    forged.operand[3].reg = CDISASM_ARM_REG_P11;
    reject_forgery(&forged);
    forged = instruction;
    forged.operand[1].flags = CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE;
    reject_forgery(&forged);
    forged = instruction;
    forged.condition = CDISASM_ARM_CONDITION_EQ;
    reject_forgery(&forged);
    forged = instruction;
    forged.opcode_groups = CDISASM_GROUP_CONDITIONAL;
    reject_forgery(&forged);
}
#endif

int main(void)
{
    test_exact_domains();
    test_parent_residuals();
    test_feature_alternatives();
    test_transport_and_boundaries();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatter();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d ARM SVE predicate-break test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM SVE predicate-break tests passed "
           "(%llu allocated, %llu reserved; USE_EXTRA_OPCODES=%d)\n",
           (unsigned long long)allocated_count,
           (unsigned long long)reserved_count, USE_EXTRA_OPCODES);
    return 0;
}
