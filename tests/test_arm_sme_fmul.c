#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

typedef struct fmul_descriptor {
    uint32_t mask;
    uint32_t value;
    cdisasm_arm_form_id fmul_form;
    cdisasm_arm_form_id bfmul_form;
    unsigned count;
    int scalar;
} fmul_descriptor;

/* Pinned AARCHMRS mortlach_multi{2,4}_fmul_{mm,sm} leaves.  Size zero is
 * occupied by fixed-H BFMUL; size 1/2/3 selects FMUL H/S/D. */
static const fmul_descriptor descriptors[] = {
    { UINT32_C(0xff21fc21), UINT32_C(0xc120e400),
      UINT16_C(4363), UINT16_C(4364), 2u, 0 },
    { UINT32_C(0xff23fc63), UINT32_C(0xc121e400),
      UINT16_C(4365), UINT16_C(4366), 4u, 0 },
    { UINT32_C(0xff21fc21), UINT32_C(0xc120e800),
      UINT16_C(4367), UINT16_C(4368), 2u, 1 },
    { UINT32_C(0xff21fc63), UINT32_C(0xc121e800),
      UINT16_C(4369), UINT16_C(4370), 4u, 1 }
};

_Static_assert(CDISASM_ARM_NAME_FMUL == UINT16_C(72),
               "established FMUL ID changed");
_Static_assert(CDISASM_ARM_NAME_BFMUL == UINT16_C(594),
               "generated BFMUL ID changed");
_Static_assert(CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST == UINT8_C(8),
               "scalable-list operand ABI changed");

static int failures;

#define EXPECT(condition)                                                   \
    do {                                                                    \
        if (!(condition)) {                                                 \
            if (failures < 24) {                                           \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",      \
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

static uint32_t fmul_word(
    const fmul_descriptor *descriptor, unsigned size,
    unsigned destination_group, unsigned first_source_group,
    unsigned second_source)
{
    uint32_t word = descriptor->value | ((uint32_t)size << 22);

    if (descriptor->count == 2u) {
        word |= (uint32_t)destination_group << 1;
        word |= (uint32_t)first_source_group << 6;
        word |= (uint32_t)second_source << 17;
    } else {
        word |= (uint32_t)destination_group << 2;
        word |= (uint32_t)first_source_group << 7;
        word |= (uint32_t)second_source
            << (descriptor->scalar ? 17u : 18u);
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

static void word_to_be(uint32_t word, uint8_t bytes[4])
{
    bytes[0] = (uint8_t)(word >> 24);
    bytes[1] = (uint8_t)(word >> 16);
    bytes[2] = (uint8_t)(word >> 8);
    bytes[3] = (uint8_t)word;
}

static uint32_t decode_word(
    uint32_t word, cdisasm_arm_cpu_id cpu_id, cdisasm_arm_mode mode,
    size_t code_size, cdisasm_arm_decode_option options,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(
        cpu_id, mode, bytes, code_size, UINT64_C(0x12e000),
        options, instruction);
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
static void expected_list(
    cdisasm_arm_operand *operand, unsigned base, unsigned count,
    uint8_t element_size, cdisasm_operand_access access)
{
    operand->type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST;
    operand->reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + base);
    operand->register_list = (uint16_t)(UINT16_C(0x0100) | count);
    operand->extend_type = (cdisasm_arm_extend_type)element_size;
    operand->access = access;
}

static void expected_instruction(
    uint32_t word, const fmul_descriptor *descriptor,
    cdisasm_arm_instruction *expected)
{
    unsigned size = (word >> 22) & 3u;
    unsigned destination_base = descriptor->count == 2u
        ? word & 30u : word & 28u;
    unsigned first_source_base = descriptor->count == 2u
        ? (word >> 5) & 30u : (word >> 5) & 28u;
    unsigned second_source = descriptor->scalar
        ? (word >> 17) & 15u
        : descriptor->count == 2u
            ? (word >> 16) & 30u : (word >> 16) & 28u;
    uint8_t element_size = size == 0u
        ? 2u : (uint8_t)(UINT32_C(1) << size);

    memset(expected, 0, sizeof(*expected));
    expected->address = UINT64_C(0x12e000);
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->name_id = size == 0u
        ? CDISASM_ARM_NAME_BFMUL : CDISASM_ARM_NAME_FMUL;
    expected->form_id = size == 0u
        ? descriptor->bfmul_form : descriptor->fmul_form;
    expected->operand_count = 3u;
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_SME
        | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
    expected_list(
        &expected->operand[0], destination_base, descriptor->count,
        element_size, CDISASM_OPERAND_ACCESS_WRITE);
    expected_list(
        &expected->operand[1], first_source_base, descriptor->count,
        element_size, CDISASM_OPERAND_ACCESS_READ);
    if (descriptor->scalar) {
        expected->operand[2].type =
            CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
        expected->operand[2].reg = (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_Z0 + second_source);
        expected->operand[2].extend_type =
            (cdisasm_arm_extend_type)element_size;
        expected->operand[2].access = CDISASM_OPERAND_ACCESS_READ;
    } else {
        expected_list(
            &expected->operand[2], second_source, descriptor->count,
            element_size, CDISASM_OPERAND_ACCESS_READ);
    }
}
#endif

static void test_exhaustive_domains(void)
{
    uint32_t fmul_allocated = 0u;
    uint32_t bfmul_allocated = 0u;
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        const fmul_descriptor *descriptor =
            &descriptors[descriptor_index];
        unsigned group_limit = descriptor->count == 2u ? 16u : 8u;
        unsigned second_limit = descriptor->scalar ? 16u : group_limit;
        unsigned size;

        for (size = 0u; size < 4u; ++size) {
            unsigned second_source;

            for (second_source = 0u;
                 second_source < second_limit; ++second_source) {
                unsigned first_source_group;

                for (first_source_group = 0u;
                     first_source_group < group_limit;
                     ++first_source_group) {
                    unsigned destination_group;

                    for (destination_group = 0u;
                         destination_group < group_limit;
                         ++destination_group) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = fmul_word(
                            descriptor, size, destination_group,
                            first_source_group, second_source);
                        uint32_t decoded;

                        domain_expect(
                            (word & descriptor->mask)
                                == descriptor->value,
                            word, "word escaped FMUL/BFMUL envelope");
                        memset(&instruction, 0xa5,
                            sizeof(instruction));
                        decoded = decode_word(
                            word, CDISASM_ARM_CPU_ANY,
                            CDISASM_ARM_MODE_A64, 4u,
                            CDISASM_ARM_DECODE_OPTION_NONE,
                            &instruction);
                        if (size == 0u) {
                            ++bfmul_allocated;
                        } else {
                            ++fmul_allocated;
                        }
#if USE_EXTRA_OPCODES
                        {
                            cdisasm_arm_instruction expected;

                            expected_instruction(
                                word, descriptor, &expected);
                            domain_expect(decoded == 4u, word,
                                "allocated FMUL/BFMUL did not decode");
                            domain_expect(memcmp(
                                &instruction, &expected,
                                sizeof(expected)) == 0,
                                word, "FMUL/BFMUL metadata mismatch");
                        }
#else
                        domain_expect(decoded == 0u, word,
                            "extras-OFF decoded FMUL/BFMUL");
                        domain_expect(instruction_is_error_only(
                            &instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                            word, "extras-OFF ownership mismatch");
#endif
                    }
                }
            }
        }
    }
    EXPECT(fmul_allocated == UINT32_C(29184));
    EXPECT(bfmul_allocated == UINT32_C(9728));
}

static void expect_cpu_status(
    uint32_t word, cdisasm_arm_cpu_id cpu_id,
    cdisasm_status enabled_status)
{
    cdisasm_arm_instruction instruction;
    cdisasm_status expected;
    uint32_t decoded;

#if USE_EXTRA_OPCODES
    expected = enabled_status;
#else
    (void)enabled_status;
    expected = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
    memset(&instruction, 0xa5, sizeof(instruction));
    decoded = decode_word(
        word, cpu_id, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    EXPECT(decoded == (expected == CDISASM_STATUS_OK ? 4u : 0u));
    if (expected == CDISASM_STATUS_OK) {
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    } else {
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_features_and_fixed_neighbors(void)
{
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        const fmul_descriptor *descriptor =
            &descriptors[descriptor_index];
        uint32_t bfmul = fmul_word(descriptor, 0u, 1u, 2u, 3u);
        uint32_t fmul = fmul_word(descriptor, 1u, 1u, 2u, 3u);
        unsigned bit;

        expect_cpu_status(
            bfmul, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
        expect_cpu_status(
            fmul, CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
        /* Current named profiles expose neither SME2.2 nor the generated
         * FEAT_SVE_BFSCALE capability.  M4 does expose baseline SME2, so
         * its BFMUL rejection specifically exercises the BFSCALE gate. */
        expect_cpu_status(bfmul, CDISASM_ARM_CPU_APPLE_M4,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_cpu_status(fmul, CDISASM_ARM_CPU_APPLE_M4,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_cpu_status(bfmul, CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_cpu_status(fmul, CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        for (bit = 0u; bit < 32u; ++bit) {
            cdisasm_arm_instruction instruction;
            uint32_t decoded;

            if ((descriptor->mask
                    & (UINT32_C(1) << bit)) == 0u) {
                continue;
            }
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = decode_word(
                fmul ^ (UINT32_C(1) << bit),
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            EXPECT(decoded != 4u
                || instruction.form_id != descriptor->fmul_form);
        }
    }
}

static void test_named_cpu_profile_boundary(void)
{
    static const uint32_t words[2] = {
        UINT32_C(0xc124e440), /* BFMUL 2x2. */
        UINT32_C(0xc164e440)  /* FMUL 2x2 H. */
    };
    uint32_t cpu_value;

    for (cpu_value = CDISASM_ARM_CPU_FIRST;
         cpu_value <= CDISASM_ARM_CPU_LAST;
         ++cpu_value) {
        cdisasm_arm_cpu_id cpu_id = (cdisasm_arm_cpu_id)cpu_value;
        size_t word_index;

        for (word_index = 0u;
             word_index < sizeof(words) / sizeof(words[0]);
             ++word_index) {
            cdisasm_arm_instruction instruction;
            cdisasm_status expected_status;
            uint32_t decoded;

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
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = decode_word(
                words[word_index], cpu_id, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            EXPECT(decoded == 0u);
            EXPECT(instruction_is_error_only(
                &instruction, expected_status));
        }
    }
}

static void test_transport_and_modes(void)
{
    size_t descriptor_index;

    for (descriptor_index = 0u;
         descriptor_index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++descriptor_index) {
        const fmul_descriptor *descriptor =
            &descriptors[descriptor_index];
        unsigned size;

        for (size = 0u; size < 4u; ++size) {
            cdisasm_arm_instruction little;
            cdisasm_arm_instruction other;
            uint32_t word = fmul_word(
                descriptor, size, 1u, 2u, 3u);
            uint8_t bytes[4];
            unsigned boundary;

            memset(&little, 0xa5, sizeof(little));
#if USE_EXTRA_OPCODES
            EXPECT(decode_word(
                word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                4u, CDISASM_ARM_DECODE_OPTION_NONE, &little) == 4u);
#else
            EXPECT(decode_word(
                word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                4u, CDISASM_ARM_DECODE_OPTION_NONE, &little) == 0u);
#endif

            word_to_be(word, bytes);
            memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
            EXPECT(cdisasm_arm_decode(
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                bytes, sizeof(bytes), UINT64_C(0x12e000),
                CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
            EXPECT(cdisasm_arm_decode(
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                bytes, sizeof(bytes), UINT64_C(0x12e000),
                CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
            EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

            word_to_le(word, bytes);
            memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
            EXPECT(cdisasm_decode(
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                bytes, sizeof(bytes), UINT64_C(0x12e000),
                CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
            EXPECT(cdisasm_decode(
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                bytes, sizeof(bytes), UINT64_C(0x12e000),
                CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
#endif
            EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

            for (boundary = 1u; boundary < 4u; ++boundary) {
                memset(&other, 0xa5, sizeof(other));
                EXPECT(decode_word(
                    word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                    boundary, CDISASM_ARM_DECODE_OPTION_NONE,
                    &other) == 0u);
                EXPECT(instruction_is_error_only(
                    &other, CDISASM_STATUS_TRUNCATED));
            }
        }
    }
    {
        cdisasm_arm_instruction instruction;
        uint32_t word = fmul_word(
            &descriptors[0], 1u, 1u, 2u, 3u);

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            word, CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_ARM_MODE_A32, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            word, CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_ARM_MODE_T32, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
    }
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[192];
    char short_text[8];
    size_t expected_length = strlen(expected);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == expected_length);
    EXPECT(strcmp(text, expected) == 0);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        NULL, 0u) == expected_length);
    memset(short_text, 0xa5, sizeof(short_text));
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        short_text, sizeof(short_text)) == expected_length);
    EXPECT(short_text[sizeof(short_text) - 1u] == '\0');
}

static void test_formatting(void)
{
    static const struct format_vector {
        size_t descriptor_index;
        unsigned size;
        unsigned destination;
        unsigned first_source;
        unsigned second_source;
        const char *text;
    } vectors[] = {
        { 0u, 0u, 0u, 1u, 2u,
          "bfmul {z0.h, z1.h}, {z2.h, z3.h}, {z4.h, z5.h}" },
        { 0u, 1u, 3u, 4u, 5u,
          "fmul {z6.h, z7.h}, {z8.h, z9.h}, {z10.h, z11.h}" },
        { 0u, 2u, 6u, 7u, 0u,
          "fmul {z12.s, z13.s}, {z14.s, z15.s}, {z0.s, z1.s}" },
        { 0u, 3u, 15u, 14u, 13u,
          "fmul {z30.d, z31.d}, {z28.d, z29.d}, {z26.d, z27.d}" },
        { 1u, 0u, 0u, 1u, 2u,
          "bfmul {z0.h, z1.h, z2.h, z3.h}, {z4.h, z5.h, z6.h, z7.h}, {z8.h, z9.h, z10.h, z11.h}" },
        { 1u, 3u, 7u, 6u, 5u,
          "fmul {z28.d, z29.d, z30.d, z31.d}, {z24.d, z25.d, z26.d, z27.d}, {z20.d, z21.d, z22.d, z23.d}" },
        { 2u, 0u, 2u, 3u, 15u,
          "bfmul {z4.h, z5.h}, {z6.h, z7.h}, z15.h" },
        { 2u, 2u, 4u, 5u, 8u,
          "fmul {z8.s, z9.s}, {z10.s, z11.s}, z8.s" },
        { 3u, 0u, 5u, 6u, 15u,
          "bfmul {z20.h, z21.h, z22.h, z23.h}, {z24.h, z25.h, z26.h, z27.h}, z15.h" },
        { 3u, 1u, 7u, 0u, 1u,
          "fmul {z28.h, z29.h, z30.h, z31.h}, {z0.h, z1.h, z2.h, z3.h}, z1.h" },
        { 3u, 2u, 1u, 2u, 3u,
          "fmul {z4.s, z5.s, z6.s, z7.s}, {z8.s, z9.s, z10.s, z11.s}, z3.s" },
        { 3u, 3u, 3u, 4u, 5u,
          "fmul {z12.d, z13.d, z14.d, z15.d}, {z16.d, z17.d, z18.d, z19.d}, z5.d" }
    };
    size_t index;

    for (index = 0u; index < sizeof(vectors) / sizeof(vectors[0]);
         ++index) {
        const struct format_vector *vector = &vectors[index];
        const fmul_descriptor *descriptor =
            &descriptors[vector->descriptor_index];

        expect_format(
            fmul_word(descriptor, vector->size, vector->destination,
                vector->first_source, vector->second_source),
            vector->text);
    }
    {
        cdisasm_arm_instruction instruction;
        char text[192];
        static const char expected[] =
            "FMUL {z30.d, z31.d}, {z28.d, z29.d}, {z26.d, z27.d}";
        uint32_t word = fmul_word(
            &descriptors[0], 3u, 15u, 14u, 13u);

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(
            &instruction,
            CDISASM_FORMAT_SYNTAX_ARM_CANONICAL
                | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(text, expected) == 0);
    }
}
#endif

int main(void)
{
    test_exhaustive_domains();
    test_features_and_fixed_neighbors();
    test_named_cpu_profile_boundary();
    test_transport_and_modes();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatting();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d ARM SME FMUL/BFMUL test(s) failed\n",
            failures);
        return 1;
    }
    printf("ARM SME FMUL/BFMUL tests passed "
           "(USE_EXTRA_OPCODES=%d, FMUL=29184, BFMUL=9728)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
