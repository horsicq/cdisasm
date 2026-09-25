#include "cdisasm/cdisasm_x86.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define EXPECT(expression)                                                   \
    do {                                                                     \
        if (!(expression)) {                                                 \
            fprintf(stderr, "%s:%d: expectation failed: %s\n",          \
                __FILE__, __LINE__, #expression);                            \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

typedef struct test_case {
    uint8_t bytes[6];
    cdisasm_x86_form_id form_id;
    cdisasm_x86_group_id width_group;
    uint16_t destination_bytes;
    uint16_t source_bytes;
    cdisasm_x86_broadcast broadcast;
} test_case;

#if !USE_EXTRA_OPCODES
static int is_error_only(
    const cdisasm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}
#endif

int main(void)
{
    static const test_case cases[] = {
        {{0x62,0xf2,0x7e,0x89,0x72,0x00}, 3833, 190, 16, 16, 0},
        {{0x62,0xf2,0x7e,0xa9,0x72,0x00}, 3834, 191, 16, 32, 0},
        {{0x62,0xf2,0x7e,0x89,0x72,0xc1}, 3835, 190, 16, 16, 0},
        {{0x62,0xf2,0x7e,0xa9,0x72,0xc1}, 3836, 191, 16, 32, 0},
        {{0x62,0xf2,0x7e,0xc9,0x72,0x00}, 3841, 192, 32, 64, 0},
        {{0x62,0xf2,0x7e,0xc9,0x72,0xc1}, 3842, 192, 32, 64, 0},
        {{0x62,0xf2,0x7e,0x99,0x72,0x00}, 3833, 190, 16, 4, 4},
        {{0x62,0xf2,0x7e,0xb9,0x72,0x00}, 3834, 191, 16, 4, 8},
        {{0x62,0xf2,0x7e,0xd9,0x72,0x00}, 3841, 192, 32, 4, 16}
    };
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    size_t index;

#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_X86, CDISASM_MODE_64, &flags) == CDISASM_STATUS_OK);
#endif
    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_instruction instruction;
        uint32_t size;

        memset(&instruction, 0xa5, sizeof(instruction));
        size = cdisasm_x86_decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].bytes, sizeof(cases[index].bytes), UINT64_C(0x1000),
            &flags, &instruction);
#if USE_EXTRA_OPCODES
        EXPECT(size == sizeof(cases[index].bytes));
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VCVTNEPS2BF16);
        EXPECT(instruction.form_id == cases[index].form_id);
        EXPECT(instruction.operand_count == 2u);
        EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction.opcode[0].size == cases[index].destination_bytes);
        EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        EXPECT(instruction.opcode[1].size == cases[index].source_bytes);
        EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction.opcode[1].broadcast == cases[index].broadcast);
        EXPECT(instruction.mask_reg == CDISASM_X86_REG_K1);
        EXPECT(instruction.mask_mode == CDISASM_X86_MASK_ZERO);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512F));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512BF16));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, cases[index].width_group));
        EXPECT((instruction.opcode_flags
            & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
                | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
#else
        EXPECT(size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }

    return failures != 0;
}
