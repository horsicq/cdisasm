#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_PMOV == UINT16_C(1165),
               "SVE PMOV name ID moved");
_Static_assert(CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST >= UINT16_C(2455),
               "AARCHMRS form inventory no longer covers PMOV");

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

static uint32_t pmov_word(
    unsigned direction, unsigned size_code, unsigned lane,
    unsigned predicate, unsigned vector)
{
    static const uint32_t bases[2][4] = {
        { UINT32_C(0x052a3800), UINT32_C(0x052c3800),
          UINT32_C(0x05683800), UINT32_C(0x05a83800) },
        { UINT32_C(0x052b3800), UINT32_C(0x052d3800),
          UINT32_C(0x05693800), UINT32_C(0x05a93800) }
    };
    uint32_t word = bases[direction][size_code];

    if (size_code != 0u) {
        word |= (uint32_t)(lane & 3u) << 17;
        if (size_code == 3u) {
            word |= (uint32_t)(lane & 4u) << 20;
        }
    }
    if (direction == 0u) {
        return word | ((uint32_t)vector << 5) | predicate;
    }
    return word | ((uint32_t)predicate << 5) | vector;
}

static uint32_t decode_word(
    uint32_t word, cdisasm_arm_cpu_id cpu,
    cdisasm_arm_mode mode, cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4] = {
        (uint8_t)word, (uint8_t)(word >> 8),
        (uint8_t)(word >> 16), (uint8_t)(word >> 24)
    };

    return cdisasm_arm_decode(
        cpu, mode, bytes, sizeof(bytes), UINT64_C(0x245000),
        CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static int error_only(
    const cdisasm_arm_instruction *instruction, cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

#if USE_EXTRA_OPCODES
static void check_operand(
    const cdisasm_arm_instruction *instruction,
    unsigned direction, unsigned size_code, unsigned lane,
    unsigned predicate, unsigned vector)
{
    const cdisasm_arm_operand *p = &instruction->operand[direction];
    const cdisasm_arm_operand *z = &instruction->operand[1u - direction];
    uint8_t element_size = (uint8_t)(1u << size_code);

    EXPECT(p->type == CDISASM_ARM_OPERAND_PREDICATE);
    EXPECT(p->reg == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + predicate));
    EXPECT(p->extend_type == (cdisasm_arm_extend_type)element_size);
    EXPECT(p->flags == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
    EXPECT(p->access == (direction == 0u
        ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ));
    EXPECT(z->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    EXPECT(z->reg == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + vector));
    EXPECT(z->access == (direction == 0u
        ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE));
    EXPECT(z->imm == lane);
    EXPECT(z->flags == (lane == 0u
        ? CDISASM_OPERAND_FLAG_NONE : CDISASM_ARM_OPERAND_FLAG_HAS_LANE));
}
#endif

static void test_complete_family(void)
{
    unsigned decoded_forms = 0u;
    unsigned direction;

    for (direction = 0u; direction < 2u; ++direction) {
        unsigned size_code;

        for (size_code = 0u; size_code < 4u; ++size_code) {
            unsigned lane_count = 1u << size_code;
            unsigned lane;

            for (lane = 0u; lane < lane_count; ++lane) {
                unsigned predicate;

                for (predicate = 0u; predicate < 16u; ++predicate) {
                    unsigned vector;

                    for (vector = 0u; vector < 32u; ++vector) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = pmov_word(
                            direction, size_code, lane,
                            predicate, vector);
                        uint32_t decoded;

                        memset(&instruction, 0xa5, sizeof(instruction));
                        decoded = decode_word(
                            word, CDISASM_ARM_CPU_ANY,
                            CDISASM_ARM_MODE_A64, &instruction);
#if USE_EXTRA_OPCODES
                        EXPECT(decoded == 4u);
                        if (decoded == 4u) {
                            EXPECT(instruction.last_error_id
                                == CDISASM_STATUS_OK);
                            EXPECT(instruction.name_id
                                == CDISASM_ARM_NAME_PMOV);
                            EXPECT(instruction.form_id
                                == (cdisasm_arm_form_id)(2448u
                                    + direction * 4u + size_code));
                            EXPECT(instruction.operand_count == 2u);
                            EXPECT(instruction.instruction_flags
                                == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
                            check_operand(&instruction, direction, size_code,
                                lane, predicate, vector);
                        }
#else
                        EXPECT(decoded == 0u);
                        EXPECT(error_only(&instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                        ++decoded_forms;
                    }
                }
            }
        }
    }
    EXPECT(decoded_forms == 15360u);
}

static void test_boundaries_and_format(void)
{
    cdisasm_arm_instruction instruction;
    uint32_t word = pmov_word(0u, 3u, 7u, 3u, 5u);

    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, &instruction) == 4u);
#  if USE_DISASM_FORMAT
    {
        char text[64];
        EXPECT(cdisasm_arm_format(&instruction, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) != 0u);
        EXPECT(strcmp(text, "pmov p3.d, z5[7]") == 0);
    }
#  endif
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_A64FX,
        CDISASM_ARM_MODE_A64, &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION)
        || error_only(&instruction, CDISASM_STATUS_INVALID_ARGUMENT));
#else
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, &instruction) == 0u);
    EXPECT(error_only(&instruction,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

int main(void)
{
    test_complete_family();
    test_boundaries_and_format();

    if (failures != 0) {
        fprintf(stderr, "%d ARM SVE PMOV test(s) failed\n", failures);
        return 1;
    }
    printf("ARM SVE PMOV tests passed (USE_EXTRA_OPCODES=%d)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
