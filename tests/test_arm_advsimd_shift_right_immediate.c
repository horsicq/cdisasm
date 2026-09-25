#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define SCALAR_SHIFT_MASK UINT32_C(0xffc0fc00)
#define VECTOR_SHIFT_MASK UINT32_C(0xbf80fc00)
#define OPERATION_COUNT 11u

typedef struct shift_operation {
    uint32_t scalar_value;
    uint32_t vector_value;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_form_id scalar_form;
    cdisasm_arm_form_id vector_form;
    cdisasm_operand_access destination_access;
    cdisasm_arm_name_id collision_name;
    cdisasm_arm_form_id collision_form;
    const char *mnemonic;
    const char *uppercase;
    uint8_t left_shift;
} shift_operation;

/* Pinned AARCHMRS SSHR_asisdshf_R, SSHR_asimdshf_R,
 * USHR_asisdshf_R, USHR_asimdshf_R, SSRA_asisdshf_R,
 * SSRA_asimdshf_R, USRA_asisdshf_R, USRA_asimdshf_R,
 * SRSHR_asisdshf_R, SRSHR_asimdshf_R, URSHR_asisdshf_R,
 * URSHR_asimdshf_R, SRSRA_asisdshf_R, SRSRA_asimdshf_R,
 * URSRA_asisdshf_R, URSRA_asimdshf_R, SHL_asisdshf_R,
 * SHL_asimdshf_R, SRI_asisdshf_R, SRI_asimdshf_R,
 * SLI_asisdshf_R, and SLI_asimdshf_R. */
static const shift_operation operations[OPERATION_COUNT] = {
    { UINT32_C(0x5f400400), UINT32_C(0x0f000400),
      CDISASM_ARM_NAME_SSHR, UINT16_C(5853), UINT16_C(6215),
      CDISASM_OPERAND_ACCESS_WRITE, CDISASM_ARM_NAME_MOVI, UINT16_C(6199),
      "sshr", "SSHR", 0u },
    { UINT32_C(0x7f400400), UINT32_C(0x2f000400),
      CDISASM_ARM_NAME_USHR, UINT16_C(5863), UINT16_C(6228),
      CDISASM_OPERAND_ACCESS_WRITE, CDISASM_ARM_NAME_MVNI, UINT16_C(6207),
      "ushr", "USHR", 0u },
    { UINT32_C(0x5f401400), UINT32_C(0x0f001400),
      CDISASM_ARM_NAME_SSRA, UINT16_C(5854), UINT16_C(6216),
      CDISASM_OPERAND_ACCESS_READ_WRITE, CDISASM_ARM_NAME_ORR,
      UINT16_C(6200), "ssra", "SSRA", 0u },
    { UINT32_C(0x7f401400), UINT32_C(0x2f001400),
      CDISASM_ARM_NAME_USRA, UINT16_C(5864), UINT16_C(6229),
      CDISASM_OPERAND_ACCESS_READ_WRITE, CDISASM_ARM_NAME_BIC,
      UINT16_C(6208), "usra", "USRA", 0u },
    { UINT32_C(0x5f402400), UINT32_C(0x0f002400),
      CDISASM_ARM_NAME_SRSHR, UINT16_C(5855), UINT16_C(6217),
      CDISASM_OPERAND_ACCESS_WRITE, CDISASM_ARM_NAME_MOVI, UINT16_C(6199),
      "srshr", "SRSHR", 0u },
    { UINT32_C(0x7f402400), UINT32_C(0x2f002400),
      CDISASM_ARM_NAME_URSHR, UINT16_C(5865), UINT16_C(6230),
      CDISASM_OPERAND_ACCESS_WRITE, CDISASM_ARM_NAME_MVNI, UINT16_C(6207),
      "urshr", "URSHR", 0u },
    { UINT32_C(0x5f403400), UINT32_C(0x0f003400),
      CDISASM_ARM_NAME_SRSRA, UINT16_C(5856), UINT16_C(6218),
      CDISASM_OPERAND_ACCESS_READ_WRITE, CDISASM_ARM_NAME_ORR,
      UINT16_C(6200), "srsra", "SRSRA", 0u },
    { UINT32_C(0x7f403400), UINT32_C(0x2f003400),
      CDISASM_ARM_NAME_URSRA, UINT16_C(5866), UINT16_C(6231),
      CDISASM_OPERAND_ACCESS_READ_WRITE, CDISASM_ARM_NAME_BIC,
      UINT16_C(6208), "ursra", "URSRA", 0u },
    { UINT32_C(0x5f405400), UINT32_C(0x0f005400),
      CDISASM_ARM_NAME_SHL, UINT16_C(5857), UINT16_C(6219),
      CDISASM_OPERAND_ACCESS_WRITE, CDISASM_ARM_NAME_ORR, UINT16_C(6200),
      "shl", "SHL", 1u },
    { UINT32_C(0x7f404400), UINT32_C(0x2f004400),
      CDISASM_ARM_NAME_SRI, UINT16_C(5867), UINT16_C(6232),
      CDISASM_OPERAND_ACCESS_READ_WRITE, CDISASM_ARM_NAME_MVNI,
      UINT16_C(6207), "sri", "SRI", 0u },
    { UINT32_C(0x7f405400), UINT32_C(0x2f005400),
      CDISASM_ARM_NAME_SLI, UINT16_C(5868), UINT16_C(6233),
      CDISASM_OPERAND_ACCESS_READ_WRITE, CDISASM_ARM_NAME_BIC,
      UINT16_C(6208), "sli", "SLI", 1u }
};

_Static_assert(CDISASM_ARM_NAME_SSHR == UINT16_C(1537),
               "SSHR mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_USHR == UINT16_C(1839),
               "USHR mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_SSRA == UINT16_C(1538),
               "SSRA mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_USRA == UINT16_C(1847),
               "USRA mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_SRSHR == UINT16_C(384),
               "SRSHR mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_URSHR == UINT16_C(385),
               "URSHR mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_SRSRA == UINT16_C(1528),
               "SRSRA mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_URSRA == UINT16_C(1828),
               "URSRA mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_SHL == UINT16_C(1382),
               "SHL mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_SRI == UINT16_C(1521),
               "SRI mnemonic ID changed");
_Static_assert(CDISASM_ARM_NAME_SLI == UINT16_C(1393),
               "SLI mnemonic ID changed");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(6233),
               "Advanced SIMD shift-right form IDs unavailable");

static int failures;

#define EXPECT(condition)                                                   \
    do {                                                                    \
        if (!(condition)) {                                                 \
            if (failures < 32) {                                           \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",       \
                        __FILE__, __LINE__, #condition);                    \
            }                                                               \
            ++failures;                                                     \
        }                                                                   \
    } while (0)

static uint32_t make_scalar_word(const shift_operation *operation,
                                 unsigned immh, unsigned immb,
                                 unsigned rn, unsigned rd)
{
    return operation->scalar_value | ((uint32_t)immh << 19)
        | ((uint32_t)immb << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}

static uint32_t make_vector_word(const shift_operation *operation,
                                 unsigned q, unsigned immh, unsigned immb,
                                 unsigned rn, unsigned rd)
{
    return operation->vector_value | ((uint32_t)q << 30)
        | ((uint32_t)immh << 19) | ((uint32_t)immb << 16)
        | ((uint32_t)rn << 5) | (uint32_t)rd;
}

#if USE_EXTRA_OPCODES
static unsigned element_bits_for_immh(unsigned immh)
{
    return (immh & 8u) != 0u ? 64u
        : (immh & 4u) != 0u ? 32u
        : (immh & 2u) != 0u ? 16u : 8u;
}

static unsigned shift_for_encoding(const shift_operation *operation,
                                   unsigned immh, unsigned immb)
{
    unsigned element_bits = element_bits_for_immh(immh);
    unsigned encoded_immediate = (immh << 3) | immb;

    return operation->left_shift != 0u
        ? encoded_immediate - element_bits
        : 2u * element_bits - encoded_immediate;
}
#endif

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

static uint32_t decode_word(uint32_t word, cdisasm_arm_cpu_id cpu,
                            cdisasm_arm_mode mode, size_t code_size,
                            cdisasm_arm_decode_option options,
                            cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(cpu, mode, bytes, code_size,
        UINT64_C(0x17b000), options, instruction);
}

static int error_only(const cdisasm_arm_instruction *instruction,
                      cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

#if USE_EXTRA_OPCODES
static int register_matches(const cdisasm_arm_operand *operand,
                            cdisasm_arm_reg_id base, unsigned encoded,
                            uint8_t total_size, uint8_t element_size,
                            cdisasm_operand_access access)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_OPERAND_REGISTER;
    expected.reg = (cdisasm_arm_reg_id)(base + encoded);
    expected.size = total_size;
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.scale = (uint8_t)(total_size / element_size);
    expected.access = access;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int immediate_matches(const cdisasm_arm_operand *operand,
                             uint64_t value)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_OPERAND_IMMEDIATE;
    expected.imm = value;
    expected.size = 1u;
    expected.access = CDISASM_OPERAND_ACCESS_READ;
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int metadata_matches(const cdisasm_arm_instruction *instruction,
                            const shift_operation *operation,
                            uint32_t word, int scalar, unsigned q,
                            unsigned immh, unsigned immb,
                            unsigned rn, unsigned rd)
{
    unsigned element_bits = scalar ? 64u : element_bits_for_immh(immh);
    uint8_t element_size = (uint8_t)(element_bits / 8u);
    uint8_t total_size = scalar ? 8u : q != 0u ? 16u : 8u;
    cdisasm_arm_reg_id base = scalar
        ? CDISASM_ARM_REG_D0 : CDISASM_ARM_REG_V0;

    return instruction->address == UINT64_C(0x17b000)
        && instruction->opcode_size == 4u
        && instruction->raw_instruction == word
        && instruction->name_id == operation->name_id
        && instruction->form_id == (scalar
            ? operation->scalar_form : operation->vector_form)
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->branch_target == 0u
        && instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->operand_count == 3u
        && register_matches(&instruction->operand[0], base, rd,
            total_size, element_size, operation->destination_access)
        && register_matches(&instruction->operand[1], base, rn,
            total_size, element_size, CDISASM_OPERAND_ACCESS_READ)
        && immediate_matches(&instruction->operand[2],
            (uint64_t)shift_for_encoding(operation, immh, immb));
}

static int collision_metadata_matches(
    const cdisasm_arm_instruction *instruction,
    const shift_operation *operation, uint32_t word,
    unsigned q, unsigned immb, unsigned rn, unsigned rd)
{
    uint8_t total_size = q != 0u ? 16u : 8u;
    unsigned imm8 = (immb << 5) | rn;
    unsigned cmode = (operation->vector_value >> 12) & 15u;
    uint8_t shift_amount = (uint8_t)(4u * (cmode & ~1u));
    cdisasm_arm_operand expected_immediate;
    cdisasm_operand_access destination_access =
        operation->collision_name == CDISASM_ARM_NAME_ORR
            || operation->collision_name == CDISASM_ARM_NAME_BIC
        ? CDISASM_OPERAND_ACCESS_READ_WRITE
        : CDISASM_OPERAND_ACCESS_WRITE;

    memset(&expected_immediate, 0, sizeof(expected_immediate));
    expected_immediate.type = CDISASM_OPERAND_IMMEDIATE;
    expected_immediate.imm = (uint64_t)imm8 << shift_amount;
    expected_immediate.size = 1u;
    expected_immediate.access = CDISASM_OPERAND_ACCESS_READ;
    expected_immediate.shift_type = shift_amount == 0u
        ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL;
    expected_immediate.shift_amount = shift_amount;

    return instruction->address == UINT64_C(0x17b000)
        && instruction->opcode_size == 4u
        && instruction->raw_instruction == word
        && instruction->name_id == operation->collision_name
        && instruction->form_id == operation->collision_form
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->branch_target == 0u
        && instruction->last_error_id == CDISASM_STATUS_OK
        && instruction->operand_count == 2u
        && register_matches(&instruction->operand[0], CDISASM_ARM_REG_V0,
            rd, total_size, 4u, destination_access)
        && memcmp(&instruction->operand[1], &expected_immediate,
            sizeof(expected_immediate)) == 0;
}
#endif

static void test_exhaustive_envelopes(void)
{
    uint32_t scalar_cells[OPERATION_COUNT][8][8] = {{{0u}}};
    uint32_t vector_cells[OPERATION_COUNT][2][16][3] = {{{{0u}}}};
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    uint32_t collisions = 0u;
    unsigned operation_index;

    for (operation_index = 0u; operation_index < OPERATION_COUNT;
         ++operation_index) {
        const shift_operation *operation = &operations[operation_index];
        unsigned immh;

        for (immh = 8u; immh < 16u; ++immh) {
            unsigned immb;

            for (immb = 0u; immb < 8u; ++immb) {
                unsigned rn;

                for (rn = 0u; rn < 32u; ++rn) {
                    unsigned rd;

                    for (rd = 0u; rd < 32u; ++rd) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = make_scalar_word(
                            operation, immh, immb, rn, rd);
                        uint32_t decoded;

                        ++scalar_cells[operation_index][immh - 8u][immb];
                        ++allocated;
                        EXPECT((word & SCALAR_SHIFT_MASK)
                            == operation->scalar_value);
                        memset(&instruction, 0xa5, sizeof(instruction));
                        decoded = decode_word(word, CDISASM_ARM_CPU_ANY,
                            CDISASM_ARM_MODE_A64, 4u,
                            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
                        EXPECT(decoded == 4u);
                        EXPECT(metadata_matches(&instruction, operation,
                            word, 1, 1u, immh, immb, rn, rd));
#else
                        EXPECT(decoded == 0u);
                        EXPECT(error_only(&instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                    }
                }
            }
        }

        for (unsigned q = 0u; q < 2u; ++q) {
            for (immh = 0u; immh < 16u; ++immh) {
                int is_collision = immh == 0u;
                int is_allocated = !is_collision
                    && (q != 0u || (immh & 8u) == 0u);
                unsigned partition = is_collision ? 0u
                    : is_allocated ? 1u : 2u;

                for (unsigned immb = 0u; immb < 8u; ++immb) {
                    for (unsigned rn = 0u; rn < 32u; ++rn) {
                        for (unsigned rd = 0u; rd < 32u; ++rd) {
                            cdisasm_arm_instruction instruction;
                            uint32_t word = make_vector_word(
                                operation, q, immh, immb, rn, rd);
                            uint32_t decoded;

                            ++vector_cells[operation_index][q][immh]
                                [partition];
                            if (is_allocated) {
                                ++allocated;
                            } else if (is_collision) {
                                ++collisions;
                            } else {
                                ++reserved;
                            }
                            EXPECT((word & VECTOR_SHIFT_MASK)
                                == operation->vector_value);
                            memset(&instruction, 0xa5,
                                sizeof(instruction));
                            decoded = decode_word(word,
                                CDISASM_ARM_CPU_ANY,
                                CDISASM_ARM_MODE_A64, 4u,
                                CDISASM_ARM_DECODE_OPTION_NONE,
                                &instruction);
                            if (is_allocated) {
#if USE_EXTRA_OPCODES
                                EXPECT(decoded == 4u);
                                EXPECT(metadata_matches(&instruction,
                                    operation, word, 0, q, immh, immb,
                                    rn, rd));
#else
                                EXPECT(decoded == 0u);
                                EXPECT(error_only(&instruction,
                                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                            } else if (!is_collision) {
                                EXPECT(decoded == 0u);
                                EXPECT(error_only(&instruction,
                                    CDISASM_STATUS_INVALID_INSTRUCTION));
                            } else {
#if USE_EXTRA_OPCODES
                                EXPECT(decoded == 4u);
                                EXPECT(collision_metadata_matches(
                                    &instruction, operation, word, q, immb,
                                    rn, rd));
#else
                                EXPECT(decoded == 0u);
                                EXPECT(error_only(&instruction,
                                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                            }
                        }
                    }
                }
            }
        }
    }

    EXPECT(allocated == UINT32_C(2703360));
    EXPECT(reserved == UINT32_C(720896));
    EXPECT(collisions == UINT32_C(180224));
    for (operation_index = 0u; operation_index < OPERATION_COUNT;
         ++operation_index) {
        for (unsigned immh = 0u; immh < 8u; ++immh) {
            for (unsigned immb = 0u; immb < 8u; ++immb) {
                EXPECT(scalar_cells[operation_index][immh][immb]
                    == UINT32_C(1024));
            }
        }
        for (unsigned q = 0u; q < 2u; ++q) {
            for (unsigned immh = 0u; immh < 16u; ++immh) {
                int is_collision = immh == 0u;
                int is_allocated = !is_collision
                    && (q != 0u || (immh & 8u) == 0u);
                unsigned partition = is_collision ? 0u
                    : is_allocated ? 1u : 2u;

                EXPECT(vector_cells[operation_index][q][immh]
                    [partition] == UINT32_C(8192));
                for (unsigned other = 0u; other < 3u; ++other) {
                    if (other != partition) {
                        EXPECT(vector_cells[operation_index][q][immh]
                            [other] == 0u);
                    }
                }
            }
        }
    }
}

static void expect_cpu_status(uint32_t word, cdisasm_arm_cpu_id cpu,
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
    decoded = decode_word(word, cpu, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    EXPECT(decoded == (expected == CDISASM_STATUS_OK ? 4u : 0u));
    if (expected == CDISASM_STATUS_OK) {
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    } else {
        EXPECT(error_only(&instruction, expected));
    }
}

static void test_profiles_and_collision_boundaries(void)
{
    static const uint32_t adjacent[] = {
        UINT32_C(0x5f407400), /* scalar SQSHL */
        UINT32_C(0x7f407400), /* scalar UQSHL */
        UINT32_C(0x0f007400), /* vector SQSHL */
        UINT32_C(0x2f007400)  /* vector UQSHL */
    };

    for (unsigned operation_index = 0u; operation_index < OPERATION_COUNT;
         ++operation_index) {
        const shift_operation *operation = &operations[operation_index];
        uint32_t words[2] = {
            make_scalar_word(operation, 10u, 7u, 13u, 7u),
            make_vector_word(operation, 1u, 8u, 7u, 13u, 7u)
        };

        for (unsigned sample = 0u; sample < 2u; ++sample) {
            uint32_t mask = sample == 0u
                ? SCALAR_SHIFT_MASK : VECTOR_SHIFT_MASK;
            cdisasm_arm_form_id form = sample == 0u
                ? operation->scalar_form : operation->vector_form;

            expect_cpu_status(words[sample], CDISASM_ARM_CPU_ANY,
                              CDISASM_STATUS_OK);
            expect_cpu_status(words[sample], CDISASM_ARM_CPU_CORTEX_A34,
                              CDISASM_STATUS_OK);
            expect_cpu_status(words[sample], CDISASM_ARM_CPU_CORTEX_A53,
                              CDISASM_STATUS_OK);
            expect_cpu_status(words[sample], CDISASM_ARM_CPU_APPLE_M3,
                              CDISASM_STATUS_OK);
            expect_cpu_status(words[sample], CDISASM_ARM_CPU_FUJITSU_A64FX,
                              CDISASM_STATUS_OK);

            for (unsigned bit = 0u; bit < 32u; ++bit) {
                cdisasm_arm_instruction instruction;

                if ((mask & (UINT32_C(1) << bit)) == 0u) {
                    continue;
                }
                memset(&instruction, 0xa5, sizeof(instruction));
                (void)decode_word(words[sample] ^ (UINT32_C(1) << bit),
                    CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                    CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                EXPECT(instruction.last_error_id != CDISASM_STATUS_OK
                    || instruction.form_id != form);
            }
        }
    }

    for (size_t index = 0u;
         index < sizeof(adjacent) / sizeof(adjacent[0]); ++index) {
        cdisasm_arm_instruction instruction;

        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word(adjacent[index], CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
        EXPECT(instruction.last_error_id != CDISASM_STATUS_OK
            || (instruction.form_id != UINT16_C(5853)
                && instruction.form_id != UINT16_C(5863)
                && instruction.form_id != UINT16_C(5854)
                && instruction.form_id != UINT16_C(5864)
                && instruction.form_id != UINT16_C(6215)
                && instruction.form_id != UINT16_C(6228)
                && instruction.form_id != UINT16_C(6216)
                && instruction.form_id != UINT16_C(6229)
                && instruction.form_id != UINT16_C(5855)
                && instruction.form_id != UINT16_C(5865)
                && instruction.form_id != UINT16_C(6217)
                && instruction.form_id != UINT16_C(6230)
                && instruction.form_id != UINT16_C(5856)
                && instruction.form_id != UINT16_C(5866)
                && instruction.form_id != UINT16_C(6218)
                && instruction.form_id != UINT16_C(6231)
                && instruction.form_id != UINT16_C(5857)
                && instruction.form_id != UINT16_C(6219)
                && instruction.form_id != UINT16_C(5867)
                && instruction.form_id != UINT16_C(6232)
                && instruction.form_id != UINT16_C(5868)
                && instruction.form_id != UINT16_C(6233)));
    }
}

static void check_transport(uint32_t word)
{
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction other;
    uint8_t bytes[4];

    memset(&little, 0xa5, sizeof(little));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        4u, CDISASM_ARM_DECODE_OPTION_NONE, &little) == 4u);
#else
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        4u, CDISASM_ARM_DECODE_OPTION_NONE, &little) == 0u);
#endif

    word_to_be(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x17b000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x17b000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x17b000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
    EXPECT(cdisasm_decode(CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, bytes, sizeof(bytes), UINT64_C(0x17b000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
#endif
    EXPECT(memcmp(&other, &little, sizeof(other)) == 0);

    for (unsigned boundary = 1u; boundary < 4u; ++boundary) {
        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, boundary,
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(error_only(&other, CDISASM_STATUS_TRUNCATED));
    }
}

static void test_transport_and_status_precedence(void)
{
    for (unsigned operation_index = 0u; operation_index < OPERATION_COUNT;
         ++operation_index) {
        const shift_operation *operation = &operations[operation_index];
        uint32_t scalar = make_scalar_word(operation, 8u, 0u, 13u, 7u);
        uint32_t vector = make_vector_word(
            operation, 1u, 8u, 7u, 13u, 7u);
        uint32_t collisions[2] = {
            make_vector_word(operation, 0u, 0u, 0u, 0u, 0u),
            make_vector_word(operation, 1u, 0u, 7u, 31u, 31u)
        };
        uint32_t reserved[2] = {
            make_vector_word(operation, 0u, 8u, 7u, 13u, 7u),
            make_vector_word(operation, 0u, 15u, 7u, 31u, 31u)
        };
        cdisasm_arm_instruction instruction;

        check_transport(scalar);
        check_transport(vector);
        for (unsigned index = 0u; index < 2u; ++index) {
            memset(&instruction, 0xa5, sizeof(instruction));
            EXPECT(decode_word(reserved[index], CDISASM_ARM_CPU_ANY,
                CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
            EXPECT(error_only(&instruction,
                CDISASM_STATUS_INVALID_INSTRUCTION));
        }
        for (unsigned index = 0u; index < 2u; ++index) {
            memset(&instruction, 0xa5, sizeof(instruction));
            uint32_t decoded = decode_word(
                collisions[index], CDISASM_ARM_CPU_ANY,
                CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
            EXPECT(decoded == 4u);
            EXPECT(collision_metadata_matches(&instruction, operation,
                collisions[index], index, index == 0u ? 0u : 7u,
                index == 0u ? 0u : 31u, index == 0u ? 0u : 31u));
#else
            EXPECT(decoded == 0u);
            EXPECT(error_only(&instruction,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(reserved[0], CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 3u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(error_only(&instruction, CDISASM_STATUS_TRUNCATED));

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(vector, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u, UINT64_C(1) << 63,
            &instruction) == 0u);
        EXPECT(error_only(&instruction,
            CDISASM_STATUS_INVALID_ARGUMENT));

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(vector, CDISASM_ARM_CPU_CORTEX_A7,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(error_only(&instruction,
            CDISASM_STATUS_INVALID_ARGUMENT));

        memset(&instruction, 0xa5, sizeof(instruction));
        (void)decode_word(vector, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A32, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
        EXPECT(instruction.last_error_id != CDISASM_STATUS_OK
            || instruction.form_id != operation->vector_form);
    }
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void reject_forgery(const cdisasm_arm_instruction *instruction,
                           const char *mutation)
{
    char text[160];
    size_t length;

    memset(text, 0xa5, sizeof(text));
    length = cdisasm_arm_format(instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, text, sizeof(text));
    if (length != 0u || text[0] != '\0') {
        if (failures < 32) {
            fprintf(stderr, "accepted formatter forgery: %s -> %s\n",
                    mutation, text);
        }
        ++failures;
    }
}

typedef struct format_case {
    uint32_t word;
    const char *text;
} format_case;

static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[160];
    char short_text[8];
    size_t expected_length = strlen(expected);
    size_t length;

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    length = cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, text, sizeof(text));
    if (length != expected_length || strcmp(text, expected) != 0) {
        fprintf(stderr, "format mismatch: expected '%s', got '%s'\n",
                expected, text);
    }
    EXPECT(length == expected_length);
    EXPECT(strcmp(text, expected) == 0);
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, NULL, 0u)
        == expected_length);
    memset(short_text, 0xa5, sizeof(short_text));
    EXPECT(cdisasm_arm_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, short_text,
        sizeof(short_text)) == expected_length);
    EXPECT(short_text[sizeof(short_text) - 1u] == '\0');
}

static void test_formatter_and_schema(void)
{
    static const format_case cases[] = {
        { UINT32_C(0x5f7f0420), "sshr d0, d1, #1" },
        { UINT32_C(0x5f400462), "sshr d2, d3, #64" },
        { UINT32_C(0x7f6f04a4), "ushr d4, d5, #17" },
        { UINT32_C(0x7f4004e6), "ushr d6, d7, #64" },
        { UINT32_C(0x0f0f0420), "sshr v0.8b, v1.8b, #1" },
        { UINT32_C(0x4f080462), "sshr v2.16b, v3.16b, #8" },
        { UINT32_C(0x0f1704a4), "sshr v4.4h, v5.4h, #9" },
        { UINT32_C(0x4f1004e6), "sshr v6.8h, v7.8h, #16" },
        { UINT32_C(0x0f2f0528), "sshr v8.2s, v9.2s, #17" },
        { UINT32_C(0x4f20056a), "sshr v10.4s, v11.4s, #32" },
        { UINT32_C(0x4f5f05ac), "sshr v12.2d, v13.2d, #33" },
        { UINT32_C(0x4f4005ee), "sshr v14.2d, v15.2d, #64" },
        { UINT32_C(0x2f0f0630), "ushr v16.8b, v17.8b, #1" },
        { UINT32_C(0x6f080672), "ushr v18.16b, v19.16b, #8" },
        { UINT32_C(0x2f1706b4), "ushr v20.4h, v21.4h, #9" },
        { UINT32_C(0x6f1006f6), "ushr v22.8h, v23.8h, #16" },
        { UINT32_C(0x2f2f0738), "ushr v24.2s, v25.2s, #17" },
        { UINT32_C(0x6f20077a), "ushr v26.4s, v27.4s, #32" },
        { UINT32_C(0x6f5f07bc), "ushr v28.2d, v29.2d, #33" },
        { UINT32_C(0x6f4007fe), "ushr v30.2d, v31.2d, #64" },
        { UINT32_C(0x5f7f1420), "ssra d0, d1, #1" },
        { UINT32_C(0x5f401462), "ssra d2, d3, #64" },
        { UINT32_C(0x7f6f14a4), "usra d4, d5, #17" },
        { UINT32_C(0x7f4014e6), "usra d6, d7, #64" },
        { UINT32_C(0x0f0f1420), "ssra v0.8b, v1.8b, #1" },
        { UINT32_C(0x4f081462), "ssra v2.16b, v3.16b, #8" },
        { UINT32_C(0x0f1714a4), "ssra v4.4h, v5.4h, #9" },
        { UINT32_C(0x4f1014e6), "ssra v6.8h, v7.8h, #16" },
        { UINT32_C(0x0f2f1528), "ssra v8.2s, v9.2s, #17" },
        { UINT32_C(0x4f20156a), "ssra v10.4s, v11.4s, #32" },
        { UINT32_C(0x4f5f15ac), "ssra v12.2d, v13.2d, #33" },
        { UINT32_C(0x4f4015ee), "ssra v14.2d, v15.2d, #64" },
        { UINT32_C(0x2f0f1630), "usra v16.8b, v17.8b, #1" },
        { UINT32_C(0x6f081672), "usra v18.16b, v19.16b, #8" },
        { UINT32_C(0x2f1716b4), "usra v20.4h, v21.4h, #9" },
        { UINT32_C(0x6f1016f6), "usra v22.8h, v23.8h, #16" },
        { UINT32_C(0x2f2f1738), "usra v24.2s, v25.2s, #17" },
        { UINT32_C(0x6f20177a), "usra v26.4s, v27.4s, #32" },
        { UINT32_C(0x6f5f17bc), "usra v28.2d, v29.2d, #33" },
        { UINT32_C(0x6f4017fe), "usra v30.2d, v31.2d, #64" },
        { UINT32_C(0x5f7f2420), "srshr d0, d1, #1" },
        { UINT32_C(0x5f402462), "srshr d2, d3, #64" },
        { UINT32_C(0x7f6f24a4), "urshr d4, d5, #17" },
        { UINT32_C(0x7f4024e6), "urshr d6, d7, #64" },
        { UINT32_C(0x0f0f2420), "srshr v0.8b, v1.8b, #1" },
        { UINT32_C(0x4f082462), "srshr v2.16b, v3.16b, #8" },
        { UINT32_C(0x0f1724a4), "srshr v4.4h, v5.4h, #9" },
        { UINT32_C(0x4f1024e6), "srshr v6.8h, v7.8h, #16" },
        { UINT32_C(0x0f2f2528), "srshr v8.2s, v9.2s, #17" },
        { UINT32_C(0x4f20256a), "srshr v10.4s, v11.4s, #32" },
        { UINT32_C(0x4f5f25ac), "srshr v12.2d, v13.2d, #33" },
        { UINT32_C(0x4f4025ee), "srshr v14.2d, v15.2d, #64" },
        { UINT32_C(0x2f0f2630), "urshr v16.8b, v17.8b, #1" },
        { UINT32_C(0x6f082672), "urshr v18.16b, v19.16b, #8" },
        { UINT32_C(0x2f1726b4), "urshr v20.4h, v21.4h, #9" },
        { UINT32_C(0x6f1026f6), "urshr v22.8h, v23.8h, #16" },
        { UINT32_C(0x2f2f2738), "urshr v24.2s, v25.2s, #17" },
        { UINT32_C(0x6f20277a), "urshr v26.4s, v27.4s, #32" },
        { UINT32_C(0x6f5f27bc), "urshr v28.2d, v29.2d, #33" },
        { UINT32_C(0x6f4027fe), "urshr v30.2d, v31.2d, #64" },
        { UINT32_C(0x5f7f3420), "srsra d0, d1, #1" },
        { UINT32_C(0x5f403462), "srsra d2, d3, #64" },
        { UINT32_C(0x7f6f34a4), "ursra d4, d5, #17" },
        { UINT32_C(0x7f4034e6), "ursra d6, d7, #64" },
        { UINT32_C(0x0f0f3420), "srsra v0.8b, v1.8b, #1" },
        { UINT32_C(0x4f083462), "srsra v2.16b, v3.16b, #8" },
        { UINT32_C(0x0f1734a4), "srsra v4.4h, v5.4h, #9" },
        { UINT32_C(0x4f1034e6), "srsra v6.8h, v7.8h, #16" },
        { UINT32_C(0x0f2f3528), "srsra v8.2s, v9.2s, #17" },
        { UINT32_C(0x4f20356a), "srsra v10.4s, v11.4s, #32" },
        { UINT32_C(0x4f5f35ac), "srsra v12.2d, v13.2d, #33" },
        { UINT32_C(0x4f4035ee), "srsra v14.2d, v15.2d, #64" },
        { UINT32_C(0x2f0f3630), "ursra v16.8b, v17.8b, #1" },
        { UINT32_C(0x6f083672), "ursra v18.16b, v19.16b, #8" },
        { UINT32_C(0x2f1736b4), "ursra v20.4h, v21.4h, #9" },
        { UINT32_C(0x6f1036f6), "ursra v22.8h, v23.8h, #16" },
        { UINT32_C(0x2f2f3738), "ursra v24.2s, v25.2s, #17" },
        { UINT32_C(0x6f20377a), "ursra v26.4s, v27.4s, #32" },
        { UINT32_C(0x6f5f37bc), "ursra v28.2d, v29.2d, #33" },
        { UINT32_C(0x6f4037fe), "ursra v30.2d, v31.2d, #64" },
        { UINT32_C(0x5f405528), "shl d8, d9, #0" },
        { UINT32_C(0x5f7f556a), "shl d10, d11, #63" },
        { UINT32_C(0x0f0855ac), "shl v12.8b, v13.8b, #0" },
        { UINT32_C(0x4f7f55ee), "shl v14.2d, v15.2d, #63" },
        { UINT32_C(0x7f404630), "sri d16, d17, #64" },
        { UINT32_C(0x7f7f4672), "sri d18, d19, #1" },
        { UINT32_C(0x6f1046b4), "sri v20.8h, v21.8h, #16" },
        { UINT32_C(0x6f7f46f6), "sri v22.2d, v23.2d, #1" },
        { UINT32_C(0x7f405738), "sli d24, d25, #0" },
        { UINT32_C(0x7f7f577a), "sli d26, d27, #63" },
        { UINT32_C(0x6f2057bc), "sli v28.4s, v29.4s, #0" },
        { UINT32_C(0x6f7f57fe), "sli v30.2d, v31.2d, #63" }
    };

    for (size_t index = 0u; index < sizeof(cases) / sizeof(cases[0]);
         ++index) {
        expect_format(cases[index].word, cases[index].text);
    }

    for (unsigned operation_index = 0u; operation_index < OPERATION_COUNT;
         ++operation_index) {
        const shift_operation *operation = &operations[operation_index];
        const shift_operation *other =
            &operations[(operation_index + 1u) % OPERATION_COUNT];
        cdisasm_arm_instruction instruction;
        cdisasm_arm_instruction forged;
        char text[160];
        char uppercase[64];

        (void)snprintf(uppercase, sizeof(uppercase),
            "%s v31.2d, v30.2d, #%u", operation->uppercase,
            shift_for_encoding(operation, 8u, 0u));

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(make_vector_word(
            operation, 1u, 8u, 0u, 30u, 31u),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ARM_CANONICAL
                | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text)) == strlen(uppercase));
        EXPECT(strcmp(text, uppercase) == 0);

#define REJECT_MUTATION(statement)                                          \
        do {                                                                \
            forged = instruction;                                           \
            statement;                                                      \
            reject_forgery(&forged, #statement);                            \
        } while (0)

        REJECT_MUTATION(forged.form_id = operation->scalar_form);
        REJECT_MUTATION(forged.form_id = other->vector_form);
        REJECT_MUTATION(forged.name_id = other->name_id);
        REJECT_MUTATION(forged.raw_instruction = make_vector_word(
            operation, 1u, 0u, 0u, 30u, 31u));
        REJECT_MUTATION(forged.raw_instruction = make_scalar_word(
            operation, 8u, 0u, 30u, 31u));
        REJECT_MUTATION(forged.raw_instruction = UINT32_C(0xd503201f));
        REJECT_MUTATION(forged.opcode_size = 2u);
        REJECT_MUTATION(forged.isa_id = CDISASM_ARM_ISA_A32);
        REJECT_MUTATION(forged.condition = CDISASM_ARM_CONDITION_EQ);
        REJECT_MUTATION(forged.opcode_groups = CDISASM_GROUP_PRIVILEGED);
        REJECT_MUTATION(forged.instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
        REJECT_MUTATION(forged.branch_target = UINT64_C(4));
        REJECT_MUTATION(forged.operand_count = 2u);
        REJECT_MUTATION(forged.operand[0].reg = CDISASM_ARM_REG_V30);
        REJECT_MUTATION(forged.operand[0].size = 8u);
        REJECT_MUTATION(forged.operand[0].extend_type =
            (cdisasm_arm_extend_type)4u);
        REJECT_MUTATION(forged.operand[0].scale = 1u);
        REJECT_MUTATION(forged.operand[0].access =
            operation->destination_access == CDISASM_OPERAND_ACCESS_WRITE
                ? CDISASM_OPERAND_ACCESS_READ_WRITE
                : CDISASM_OPERAND_ACCESS_WRITE);
        REJECT_MUTATION(forged.operand[1].reg = CDISASM_ARM_REG_V29);
        REJECT_MUTATION(forged.operand[1].size = 8u);
        REJECT_MUTATION(forged.operand[1].extend_type =
            (cdisasm_arm_extend_type)4u);
        REJECT_MUTATION(forged.operand[1].scale = 1u);
        REJECT_MUTATION(forged.operand[1].access =
            CDISASM_OPERAND_ACCESS_WRITE);
        REJECT_MUTATION(forged.operand[2].imm = UINT64_C(63));
        REJECT_MUTATION(forged.operand[2].size = 2u);
        REJECT_MUTATION(forged.operand[2].access =
            CDISASM_OPERAND_ACCESS_WRITE);
        REJECT_MUTATION(forged.operand[2].shift_type =
            CDISASM_ARM_SHIFT_LSL);

        memset(&forged, 0, sizeof(forged));
        forged.name_id = CDISASM_ARM_NAME_NOP;
        forged.form_id = operation->vector_form;
        forged.raw_instruction = UINT32_C(0xd503201f);
        forged.opcode_size = 4u;
        forged.isa_id = CDISASM_ARM_ISA_A64;
        forged.condition = CDISASM_ARM_CONDITION_AL;
        reject_forgery(&forged, "form-only claim");
        forged.form_id = CDISASM_ARM_FORM_NONE;
        forged.raw_instruction = make_vector_word(
            operation, 1u, 1u, 0u, 1u, 0u);
        reject_forgery(&forged, "raw-only claim");

        memset(&forged, 0, sizeof(forged));
        forged.name_id = operation->name_id;
        forged.raw_instruction = UINT32_C(0xd503201f);
        forged.opcode_size = 4u;
        forged.isa_id = CDISASM_ARM_ISA_A64;
        forged.condition = CDISASM_ARM_CONDITION_AL;
        reject_forgery(&forged, "name-only claim");

#undef REJECT_MUTATION
    }
}
#else
static void test_formatter_and_schema(void)
{
}
#endif

int main(void)
{
    test_exhaustive_envelopes();
    test_profiles_and_collision_boundaries();
    test_transport_and_status_precedence();
    test_formatter_and_schema();

    if (failures != 0) {
        fprintf(stderr,
                "%d ARM Advanced SIMD shift-immediate test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM Advanced SIMD shift-immediate tests passed "
           "(USE_EXTRA_OPCODES=%d, allocated=2703360, reserved=720896, "
           "collisions=180224)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
