#include "cdisasm/cdisasm_x86.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define EXPECT(expression)                                                   \
    do {                                                                     \
        if (!(expression)) {                                                 \
            fprintf(stderr, "%s:%d: expectation failed: %s\n",             \
                __FILE__, __LINE__, #expression);                            \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

/* These are catalog-only forms in the coverage inventory.  Keep this small
 * probe separate from the large VMULPH matrix: its purpose is to prove that
 * the generated fallback reaches a different FP16 iclass, not to duplicate
 * every mask/rounding permutation already covered there. */
_Static_assert(CDISASM_X86_NAME_VADDPH == UINT16_C(1468),
    "VADDPH name ID changed");

static void check_case(
    const uint8_t *code,
    cdisasm_x86_form_id expected_form,
    cdisasm_x86_group_id expected_width_group)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    cdisasm_instruction instruction;
    uint32_t decoded_size;

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_MODE_64, &flags)
        == CDISASM_STATUS_OK);
    memset(&instruction, 0xa5, sizeof(instruction));
    decoded_size = cdisasm_x86_decode(
        CDISASM_CPU_SAPPHIRE_RAPIDS,
        CDISASM_MODE_64,
        code,
        6u,
        UINT64_C(0x1000),
        &flags,
        &instruction);
    EXPECT(decoded_size == 6u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VADDPH);
    EXPECT(instruction.form_id == expected_form);
    EXPECT(instruction.operand_count == 3u);
    EXPECT((instruction.opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u);
    EXPECT((instruction.opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE) == 0u);
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EVEX) != 0u);
    EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction.opcode[0].size == 16u
        || instruction.opcode[0].size == 32u
        || instruction.opcode[0].size == 64u);
    EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction.opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512FP16));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, expected_width_group));
}

int main(void)
{
    static const uint8_t xmm[] = {0x62, 0xf5, 0x74, 0x08, 0x58, 0xc2};
    static const uint8_t ymm[] = {0x62, 0xf5, 0x74, 0x28, 0x58, 0xc2};
    static const uint8_t zmm[] = {0x62, 0xf5, 0x74, 0x48, 0x58, 0xc2};

    check_case(xmm, UINT16_C(3382), CDISASM_X86_GROUP_AVX512_FP16_128);
    check_case(ymm, UINT16_C(3384), CDISASM_X86_GROUP_AVX512_FP16_256);
    check_case(zmm, UINT16_C(3386), CDISASM_X86_GROUP_AVX512_FP16_512);
    if (failures != 0) {
        fprintf(stderr, "x86 catalog FP16 tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("x86 catalog FP16 tests passed");
    return 0;
}
