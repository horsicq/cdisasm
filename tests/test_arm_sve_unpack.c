#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define TEST_ADDRESS UINT64_C(0x245600)
#define UNPACK_PARENT_MASK UINT32_C(0xff3cfc00)
#define UNPACK_PARENT_VALUE UINT32_C(0x05303800)
#define UNPACK_LEAF_MASK UINT32_C(0xff3ffc00)
#define SCALABLE_FLAG CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR

_Static_assert(CDISASM_ARM_NAME_SUNPKHI == UINT16_C(1702),
               "update SVE SUNPKHI exact-family tests");
_Static_assert(CDISASM_ARM_NAME_SUNPKLO == UINT16_C(1703),
               "update SVE SUNPKLO exact-family tests");
_Static_assert(CDISASM_ARM_NAME_UUNPKHI == UINT16_C(1860),
               "update SVE UUNPKHI exact-family tests");
_Static_assert(CDISASM_ARM_NAME_UUNPKLO == UINT16_C(1861),
               "update SVE UUNPKLO exact-family tests");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(2459),
               "AARCHMRS form inventory no longer covers SVE unpack");
_Static_assert(CDISASM_ARM_CPU_LAST - CDISASM_ARM_CPU_FIRST + 1u
                   == UINT32_C(38),
               "update SVE unpack named-profile coverage");

static int failures;
static uint64_t allocated_count;
static uint64_t reserved_count;
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

static uint32_t unpack_word(
    unsigned control, unsigned size_code, unsigned zn, unsigned zd)
{
    return UNPACK_PARENT_VALUE | ((uint32_t)size_code << 22)
        | ((uint32_t)control << 16) | ((uint32_t)zn << 5)
        | (uint32_t)zd;
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
    cdisasm_arm_decode_option options,
    cdisasm_arm_instruction *instruction)
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

static int is_unpack_identity(
    const cdisasm_arm_instruction *instruction)
{
    return (instruction->form_id >= UINT16_C(2456)
            && instruction->form_id <= UINT16_C(2459))
        || instruction->name_id == CDISASM_ARM_NAME_SUNPKLO
        || instruction->name_id == CDISASM_ARM_NAME_SUNPKHI
        || instruction->name_id == CDISASM_ARM_NAME_UUNPKLO
        || instruction->name_id == CDISASM_ARM_NAME_UUNPKHI;
}

#if USE_EXTRA_OPCODES
static const cdisasm_arm_name_id unpack_names[4] = {
    CDISASM_ARM_NAME_SUNPKLO,
    CDISASM_ARM_NAME_SUNPKHI,
    CDISASM_ARM_NAME_UUNPKLO,
    CDISASM_ARM_NAME_UUNPKHI
};

static void append_zreg(
    cdisasm_arm_instruction *instruction, unsigned encoded,
    uint8_t element_size, cdisasm_operand_access access)
{
    cdisasm_arm_operand *operand =
        &instruction->operand[instruction->operand_count++];

    operand->type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    operand->reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + encoded);
    operand->extend_type = (cdisasm_arm_extend_type)element_size;
    operand->access = access;
}

static void make_expected(uint32_t word, cdisasm_arm_instruction *expected)
{
    unsigned control = (word >> 16) & 3u;
    uint8_t destination_size = (uint8_t)(
        UINT8_C(1) << ((word >> 22) & 3u));

    memset(expected, 0, sizeof(*expected));
    expected->address = TEST_ADDRESS;
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->name_id = unpack_names[control];
    expected->form_id = (cdisasm_arm_form_id)(UINT16_C(2456) + control);
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->instruction_flags = SCALABLE_FLAG;
    append_zreg(
        expected, word & 31u, destination_size,
        CDISASM_OPERAND_ACCESS_WRITE);
    append_zreg(
        expected, (word >> 5) & 31u,
        (uint8_t)(destination_size / 2u),
        CDISASM_OPERAND_ACCESS_READ);
}
#endif

static void expect_allocated(uint32_t word)
{
    cdisasm_arm_instruction instruction;

    domain_expect((word & UNPACK_PARENT_MASK) == UNPACK_PARENT_VALUE,
        word, "test generator left exact unpack parent");
    domain_expect(((word >> 22) & 3u) != 0u,
        word, "allocated generator selected reserved size zero");
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction expected;

        domain_expect(decode_word(
            word, CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u,
            word, "allocated unpack word did not decode");
        make_expected(word, &expected);
        domain_expect(memcmp(&instruction, &expected, sizeof(expected)) == 0,
            word, "allocated unpack metadata mismatch");
    }
#else
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "extras-OFF decoded allocated unpack word");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF unpack ownership mismatch");
#endif
    ++allocated_count;
}

static void expect_reserved(uint32_t word)
{
    cdisasm_arm_instruction instruction;

    domain_expect((word & UNPACK_PARENT_MASK) == UNPACK_PARENT_VALUE,
        word, "reserved generator left exact unpack parent");
    domain_expect(((word >> 22) & 3u) == 0u,
        word, "reserved generator selected allocated size");
    memset(&instruction, 0xa5, sizeof(instruction));
    domain_expect(decode_word(
        word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "reserved unpack word decoded");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION),
        word, "reserved unpack word lost malformed ownership");
    ++reserved_count;
}

static void test_complete_parent(void)
{
    unsigned control;
    unsigned size_code;
    unsigned zn;
    unsigned zd;

    for (control = 0u; control < 4u; ++control) {
        for (size_code = 0u; size_code < 4u; ++size_code) {
            for (zn = 0u; zn < 32u; ++zn) {
                for (zd = 0u; zd < 32u; ++zd) {
                    uint32_t word = unpack_word(
                        control, size_code, zn, zd);

                    domain_expect((word & UNPACK_LEAF_MASK)
                            == (UNPACK_PARENT_VALUE
                                | ((uint32_t)control << 16)),
                        word, "unpack word escaped selected exact leaf");
                    if (size_code == 0u) {
                        expect_reserved(word);
                    } else {
                        expect_allocated(word);
                    }
                }
            }
        }
    }
    EXPECT(allocated_count == UINT64_C(12288));
    EXPECT(reserved_count == UINT64_C(4096));
    EXPECT(allocated_count + reserved_count == UINT64_C(16384));
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
        EXPECT(is_unpack_identity(&instruction));
    } else {
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_profiles_transport_and_status(void)
{
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction other;
    uint8_t bytes[4];
    uint32_t cpu_value;
    unsigned control;
    unsigned boundary;

    for (control = 0u; control < 4u; ++control) {
        uint32_t word = unpack_word(control, control % 3u + 1u,
            29u - control, 7u + control);

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
    EXPECT(profile_count == UINT64_C(152));

    {
        uint32_t word = unpack_word(3u, 3u, 31u, 31u);

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
    }

    for (boundary = 0u; boundary < 4u; ++boundary) {
        cdisasm_status status = boundary == 0u
            ? CDISASM_STATUS_END_OF_INPUT : CDISASM_STATUS_TRUNCATED;

        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(
            unpack_word(0u, 1u, 0u, 0u), CDISASM_ARM_CPU_ANY,
            boundary, CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(&other, status));
    }
    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(
        unpack_word(0u, 1u, 0u, 0u), CDISASM_ARM_CPU_ANY, 4u,
        UINT64_C(1) << 63, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));
}

static void test_mode_and_neighbor_isolation(void)
{
    cdisasm_arm_instruction instruction;
    unsigned control;
    unsigned bit;

    for (control = 0u; control < 4u; ++control) {
        uint32_t value = unpack_word(control, 1u, 0u, 0u);

        for (bit = 0u; bit < 32u; ++bit) {
            uint32_t neighbor;

            if ((UNPACK_PARENT_MASK & (UINT32_C(1) << bit)) == 0u) {
                continue;
            }
            neighbor = value ^ (UINT32_C(1) << bit);
            memset(&instruction, 0xa5, sizeof(instruction));
            (void)decode_word(neighbor, CDISASM_ARM_CPU_ANY, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            EXPECT(!is_unpack_identity(&instruction));
        }

        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word_mode(
            value, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A32,
            4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
        EXPECT(!is_unpack_identity(&instruction));
        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word_mode(
            value, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_T32,
            4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
        EXPECT(!is_unpack_identity(&instruction));
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
            fprintf(stderr, "accepted SVE unpack formatter forgery: %s\n",
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
        { UINT32_C(0x05703800), "sunpklo z0.h, z0.b" },
        { UINT32_C(0x05b13967), "sunpkhi z7.s, z11.h" },
        { UINT32_C(0x05723bbf), "uunpklo z31.h, z29.b" },
        { UINT32_C(0x05f33bff), "uunpkhi z31.d, z31.s" }
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
        text, sizeof(text)) == strlen("UUNPKHI z31.d, z31.s"));
    EXPECT(strcmp(text, "UUNPKHI z31.d, z31.s") == 0);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_7, NULL, 0u)
        == strlen(cases[3].text));

#define REJECT_MUTATION(statement)                                          \
    do {                                                                    \
        forged = instruction;                                               \
        statement;                                                          \
        reject_forgery(&forged, #statement);                                \
    } while (0)

    REJECT_MUTATION(forged.form_id = UINT16_C(2456));
    REJECT_MUTATION(forged.name_id = CDISASM_ARM_NAME_UUNPKLO);
    REJECT_MUTATION(forged.raw_instruction ^= UINT32_C(0x00010000));
    REJECT_MUTATION(forged.raw_instruction &= ~UINT32_C(0x00c00000));
    REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
    REJECT_MUTATION(forged.operand_count = 1u);
    REJECT_MUTATION(forged.instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK);
    REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_CONDITIONAL);
    REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
    REJECT_MUTATION(forged.operand[0].type = CDISASM_OPERAND_REGISTER);
    REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_Z30);
    REJECT_MUTATION(forged.operand[0].extend_type =
        (cdisasm_arm_extend_type)4u);
    REJECT_MUTATION(forged.operand[0].access =
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_Z30);
    REJECT_MUTATION(forged.operand[1].extend_type =
        (cdisasm_arm_extend_type)2u);
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
        fprintf(stderr, "%d SVE unpack test(s) failed\n", failures);
        return 1;
    }
    printf("ARM SVE unpack tests passed "
           "(%llu allocated, %llu reserved, %llu named-profile probes)\n",
        (unsigned long long)allocated_count,
        (unsigned long long)reserved_count,
        (unsigned long long)profile_count);
    return 0;
}
