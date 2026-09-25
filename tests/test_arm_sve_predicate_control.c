#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define TEST_ADDRESS UINT64_C(0x17a000)
#define SCALABLE_FLAG CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
#define PREDICATED_FLAG CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
#define SETS_FLAGS CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS

_Static_assert(CDISASM_ARM_NAME_PFALSE == UINT16_C(1156),
               "update predicate-control family tests");
_Static_assert(CDISASM_ARM_NAME_PFIRST == UINT16_C(1157),
               "update predicate-control family tests");
_Static_assert(CDISASM_ARM_NAME_PNEXT == UINT16_C(1170),
               "update predicate-control family tests");
_Static_assert(CDISASM_ARM_NAME_PTEST == UINT16_C(1180),
               "update predicate-control family tests");
_Static_assert(CDISASM_ARM_NAME_PTRUES == UINT16_C(1181),
               "update predicate-control family tests");

typedef enum predicate_control_kind {
    CONTROL_PTEST,
    CONTROL_PFIRST,
    CONTROL_PNEXT,
    CONTROL_PTRUE,
    CONTROL_PTRUES,
    CONTROL_PFALSE
} predicate_control_kind;

typedef struct predicate_control_descriptor {
    uint32_t mask;
    uint32_t value;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id form_id;
    predicate_control_kind kind;
} predicate_control_descriptor;

static const predicate_control_descriptor descriptors[6] = {
    { UINT32_C(0xffffc21f), UINT32_C(0x2550c000),
      CDISASM_ARM_NAME_PTEST, UINT16_C(2556), CONTROL_PTEST },
    { UINT32_C(0xfffffe10), UINT32_C(0x2558c000),
      CDISASM_ARM_NAME_PFIRST, UINT16_C(2557), CONTROL_PFIRST },
    { UINT32_C(0xff3ffe10), UINT32_C(0x2519c400),
      CDISASM_ARM_NAME_PNEXT, UINT16_C(2558), CONTROL_PNEXT },
    { UINT32_C(0xff3ffc10), UINT32_C(0x2518e000),
      CDISASM_ARM_NAME_PTRUE, UINT16_C(2559), CONTROL_PTRUE },
    { UINT32_C(0xff3ffc10), UINT32_C(0x2519e000),
      CDISASM_ARM_NAME_PTRUES, UINT16_C(2560), CONTROL_PTRUES },
    { UINT32_C(0xfffffff0), UINT32_C(0x2518e400),
      CDISASM_ARM_NAME_PFALSE, UINT16_C(2561), CONTROL_PFALSE }
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
    return instruction->form_id >= UINT16_C(2556)
        && instruction->form_id <= UINT16_C(2561);
}

#if USE_EXTRA_OPCODES
static void append_predicate(
    cdisasm_arm_instruction *instruction, unsigned reg, uint8_t size,
    uint8_t flags, cdisasm_operand_access access)
{
    cdisasm_arm_operand *operand =
        &instruction->operand[instruction->operand_count++];

    operand->type = CDISASM_ARM_OPERAND_PREDICATE;
    operand->reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + reg);
    operand->extend_type = (cdisasm_arm_extend_type)size;
    operand->flags = flags;
    operand->access = access;
}

static void append_immediate(
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
    const predicate_control_descriptor *descriptor, uint32_t word,
    cdisasm_arm_instruction *expected)
{
    unsigned pd = word & 15u;
    unsigned source = (word >> 5) & 15u;
    uint8_t element_size = (uint8_t)(UINT8_C(1)
        << ((word >> 22) & 3u));

    memset(expected, 0, sizeof(*expected));
    expected->address = TEST_ADDRESS;
    expected->raw_instruction = word;
    expected->opcode_size = 4u;
    expected->name_id = descriptor->name_id;
    expected->form_id = descriptor->form_id;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->instruction_flags = SCALABLE_FLAG;
    if (descriptor->kind == CONTROL_PTEST) {
        expected->instruction_flags |= PREDICATED_FLAG | SETS_FLAGS;
        append_predicate(expected, (word >> 10) & 15u, 1u,
            CDISASM_OPERAND_FLAG_NONE, CDISASM_OPERAND_ACCESS_READ);
        append_predicate(expected, source, 1u,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
            CDISASM_OPERAND_ACCESS_READ);
    } else if (descriptor->kind == CONTROL_PFIRST) {
        expected->instruction_flags |= PREDICATED_FLAG;
        append_predicate(expected, pd, 1u,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_predicate(expected, source, 1u,
            CDISASM_OPERAND_FLAG_NONE, CDISASM_OPERAND_ACCESS_READ);
        append_predicate(expected, pd, 1u,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
            CDISASM_OPERAND_ACCESS_READ);
    } else if (descriptor->kind == CONTROL_PNEXT) {
        append_predicate(expected, pd, element_size,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_predicate(expected, source, element_size,
            CDISASM_OPERAND_FLAG_NONE, CDISASM_OPERAND_ACCESS_READ);
        append_predicate(expected, pd, element_size,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
            CDISASM_OPERAND_ACCESS_READ);
    } else if (descriptor->kind == CONTROL_PTRUE
        || descriptor->kind == CONTROL_PTRUES) {
        if (descriptor->kind == CONTROL_PTRUES) {
            expected->instruction_flags |= SETS_FLAGS;
        }
        append_predicate(expected, pd, element_size,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_immediate(expected, (word >> 5) & UINT32_C(31));
    } else {
        append_predicate(expected, pd, 1u,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
            CDISASM_OPERAND_ACCESS_WRITE);
    }
}
#endif

static void expect_allocated(
    const predicate_control_descriptor *descriptor, uint32_t word)
{
    cdisasm_arm_instruction instruction;

    domain_expect((word & descriptor->mask) == descriptor->value,
        word, "test generator left exact predicate-control leaf");
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction expected;

        domain_expect(decode_word(
            word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u,
            word, "allocated predicate-control word did not decode");
        make_expected(descriptor, word, &expected);
        domain_expect(memcmp(&instruction, &expected, sizeof(expected)) == 0,
            word, "allocated predicate-control metadata mismatch");
    }
#else
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "extras-OFF decoded predicate-control word");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF predicate-control ownership mismatch");
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
        word, "reserved predicate-control word decoded");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION),
        word, "reserved predicate-control ownership mismatch");
    ++reserved_count;
}

static void test_exact_domains(void)
{
    unsigned pg;
    unsigned pn;
    unsigned pd;
    unsigned size;
    unsigned pattern;

    for (pg = 0u; pg < 16u; ++pg) {
        for (pn = 0u; pn < 16u; ++pn) {
            expect_allocated(&descriptors[0],
                descriptors[0].value | (pg << 10) | (pn << 5));
        }
    }
    for (pg = 0u; pg < 16u; ++pg) {
        for (pd = 0u; pd < 16u; ++pd) {
            expect_allocated(&descriptors[1],
                descriptors[1].value | (pg << 5) | pd);
        }
    }
    for (size = 0u; size < 4u; ++size) {
        for (pn = 0u; pn < 16u; ++pn) {
            for (pd = 0u; pd < 16u; ++pd) {
                expect_allocated(&descriptors[2],
                    descriptors[2].value | (size << 22)
                        | (pn << 5) | pd);
            }
        }
    }
    for (size = 0u; size < 4u; ++size) {
        for (pattern = 0u; pattern < 32u; ++pattern) {
            for (pd = 0u; pd < 16u; ++pd) {
                uint32_t payload = (size << 22) | (pattern << 5) | pd;

                expect_allocated(&descriptors[3],
                    descriptors[3].value | payload);
                expect_allocated(&descriptors[4],
                    descriptors[4].value | payload);
            }
        }
    }
    for (pd = 0u; pd < 16u; ++pd) {
        expect_allocated(&descriptors[5], descriptors[5].value | pd);
    }
    EXPECT(allocated_count == UINT64_C(5648));
}

static void test_parent_residuals(void)
{
    unsigned control;
    unsigned opc2;
    unsigned pg;
    unsigned pn;
    unsigned pd;

    for (control = 0u; control < 4u; ++control) {
        for (opc2 = 0u; opc2 < 16u; ++opc2) {
            for (pg = 0u; pg < 16u; ++pg) {
                for (pn = 0u; pn < 16u; ++pn) {
                    uint32_t word = UINT32_C(0x2510c000)
                        | (control << 22) | (pg << 10)
                        | (pn << 5) | opc2;

                    if ((word & descriptors[0].mask)
                            != descriptors[0].value) {
                        expect_reserved(word);
                    }
                }
            }
        }
    }
    for (control = 0u; control < 4u; ++control) {
        if (control == 1u) {
            continue;
        }
        for (pg = 0u; pg < 16u; ++pg) {
            for (pd = 0u; pd < 16u; ++pd) {
                expect_reserved(UINT32_C(0x2518c000)
                    | (control << 22) | (pg << 5) | pd);
            }
        }
    }
    for (control = 1u; control < 4u; ++control) {
        for (pd = 0u; pd < 16u; ++pd) {
            expect_reserved(UINT32_C(0x2518e400)
                | (control << 22) | pd);
        }
    }
    EXPECT(reserved_count == UINT64_C(16944));
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
    static const uint32_t words[6] = {
        UINT32_C(0x2550fdc0), UINT32_C(0x2558c1cf),
        UINT32_C(0x25d9c5cf), UINT32_C(0x25d8e3ef),
        UINT32_C(0x2559e1af), UINT32_C(0x2518e40f)
    };
    unsigned index;

    for (index = 0u; index < 6u; ++index) {
        expect_profile(words[index], CDISASM_ARM_CPU_ANY,
            CDISASM_STATUS_OK);
        expect_profile(words[index], CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_STATUS_OK);
        expect_profile(words[index], CDISASM_ARM_CPU_APPLE_A18,
            CDISASM_STATUS_OK);
        expect_profile(words[index], CDISASM_ARM_CPU_APPLE_M4,
            CDISASM_STATUS_OK);
        expect_profile(words[index], CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

static void test_transport_and_boundaries(void)
{
    static const uint32_t words[6] = {
        UINT32_C(0x2550fdc0), UINT32_C(0x2558c1cf),
        UINT32_C(0x25d9c5cf), UINT32_C(0x2518e1c0),
        UINT32_C(0x2559e1af), UINT32_C(0x2518e40f)
    };
    static const uint32_t adjacent_words[] = {
        UINT32_C(0x25587dcb), UINT32_C(0x2518f000),
        UINT32_C(0x2558f1ef), UINT32_C(0x2519f00f),
        UINT32_C(0x25204000)
    };
    unsigned index;

    for (index = 0u; index < 6u; ++index) {
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

    expect_format(UINT32_C(0x2550c000),
        "ptest p0, p0.b", "PTEST p0, p0.b");
    expect_format(UINT32_C(0x2550fdc0),
        "ptest p15, p14.b", "PTEST p15, p14.b");
    expect_format(UINT32_C(0x2558c000),
        "pfirst p0.b, p0, p0.b", "PFIRST p0.b, p0, p0.b");
    expect_format(UINT32_C(0x2558c1cf),
        "pfirst p15.b, p14, p15.b", "PFIRST p15.b, p14, p15.b");
    expect_format(UINT32_C(0x2519c400),
        "pnext p0.b, p0, p0.b", "PNEXT p0.b, p0, p0.b");
    expect_format(UINT32_C(0x2559c4a5),
        "pnext p5.h, p5, p5.h", "PNEXT p5.h, p5, p5.h");
    expect_format(UINT32_C(0x2599c54a),
        "pnext p10.s, p10, p10.s", "PNEXT p10.s, p10, p10.s");
    expect_format(UINT32_C(0x25d9c5cf),
        "pnext p15.d, p14, p15.d", "PNEXT p15.d, p14, p15.d");
    expect_format(UINT32_C(0x2518e000),
        "ptrue p0.b, pow2", "PTRUE p0.b, pow2");
    expect_format(UINT32_C(0x2558e02f),
        "ptrue p15.h, vl1", "PTRUE p15.h, vl1");
    expect_format(UINT32_C(0x2598e1af),
        "ptrue p15.s, vl256", "PTRUE p15.s, vl256");
    expect_format(UINT32_C(0x2518e1c0),
        "ptrue p0.b, #14", "PTRUE p0.b, #14");
    expect_format(UINT32_C(0x2518e380),
        "ptrue p0.b, #28", "PTRUE p0.b, #28");
    expect_format(UINT32_C(0x2518e3a0),
        "ptrue p0.b, mul4", "PTRUE p0.b, mul4");
    expect_format(UINT32_C(0x2518e3c0),
        "ptrue p0.b, mul3", "PTRUE p0.b, mul3");
    expect_format(UINT32_C(0x25d8e3ef),
        "ptrue p15.d", "PTRUE p15.d");
    expect_format(UINT32_C(0x2519e000),
        "ptrues p0.b, pow2", "PTRUES p0.b, pow2");
    expect_format(UINT32_C(0x2559e1af),
        "ptrues p15.h, vl256", "PTRUES p15.h, vl256");
    expect_format(UINT32_C(0x2599e1c0),
        "ptrues p0.s, #14", "PTRUES p0.s, #14");
    expect_format(UINT32_C(0x25d9e3ef),
        "ptrues p15.d", "PTRUES p15.d");
    expect_format(UINT32_C(0x2518e400),
        "pfalse p0.b", "PFALSE p0.b");
    expect_format(UINT32_C(0x2518e40f),
        "pfalse p15.b", "PFALSE p15.b");

    EXPECT(decode_word(UINT32_C(0x2558c1cf),
        CDISASM_ARM_CPU_ANY, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    forged = instruction;
    forged.name_id = CDISASM_ARM_NAME_PNEXT;
    reject_forgery(&forged);
    forged = instruction;
    forged.form_id = UINT16_C(2558);
    reject_forgery(&forged);
    forged = instruction;
    forged.instruction_flags |= SETS_FLAGS;
    reject_forgery(&forged);
    forged = instruction;
    forged.operand[0].access = CDISASM_OPERAND_ACCESS_READ_WRITE;
    reject_forgery(&forged);
    forged = instruction;
    forged.operand[1].extend_type = 2u;
    reject_forgery(&forged);
    forged = instruction;
    forged.operand[2].access = CDISASM_OPERAND_ACCESS_WRITE;
    reject_forgery(&forged);

    EXPECT(decode_word(UINT32_C(0x2518e1c0),
        CDISASM_ARM_CPU_ANY, 4u, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 4u);
    forged = instruction;
    forged.operand[1].imm = 15u;
    reject_forgery(&forged);
    forged = instruction;
    forged.operand[0].flags = CDISASM_OPERAND_FLAG_NONE;
    reject_forgery(&forged);
    forged = instruction;
    forged.raw_instruction ^= UINT32_C(0x00010000);
    reject_forgery(&forged);
    forged = instruction;
    forged.condition = CDISASM_ARM_CONDITION_EQ;
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
        fprintf(stderr, "%d ARM SVE predicate-control test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM SVE predicate-control tests passed "
           "(%llu allocated, %llu reserved; USE_EXTRA_OPCODES=%d)\n",
           (unsigned long long)allocated_count,
           (unsigned long long)reserved_count, USE_EXTRA_OPCODES);
    return 0;
}
