#include "cdisasm/cdisasm_x86.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;
#define EXPECT(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", \
    __FILE__, __LINE__, #x); ++failures; } } while (0)

typedef struct family_case {
    uint8_t w;
    uint8_t opcode;
    uint8_t dq;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_form_id base_form;
} family_case;

static int is_error_only(
    const cdisasm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_instruction expected;
    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

int main(void)
{
    static const family_case families[] = {
        {0,0x19,0,CDISASM_X86_NAME_VEXTRACTF32X4,4541},
        {1,0x19,1,CDISASM_X86_NAME_VEXTRACTF64X2,4547},
        {0,0x39,0,CDISASM_X86_NAME_VEXTRACTI32X4,4555},
        {1,0x39,1,CDISASM_X86_NAME_VEXTRACTI64X2,4561}
    };
    cdisasm_x86_decode_flags flags = CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    size_t family_index;

#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_X86,
        CDISASM_MODE_64, &flags) == CDISASM_STATUS_OK);
#endif
    for (family_index = 0;
         family_index < sizeof(families) / sizeof(families[0]);
         ++family_index) {
        unsigned int ll;

        for (ll = 1u; ll <= 2u; ++ll) {
            unsigned int memory;

            for (memory = 0u; memory <= 1u; ++memory) {
                uint8_t bytes[] = {0x62,0xf3,
                    (uint8_t)(families[family_index].w ? 0xfdu : 0x7du),
                    (uint8_t)(memory
                        ? (ll == 1u ? 0x29u : 0x49u)
                        : (ll == 1u ? 0xa9u : 0xc9u)),
                    families[family_index].opcode,
                    (uint8_t)(memory ? 0x48u : 0xc8u),0x01,0x03};
                const size_t byte_count = memory ? 8u : 7u;
                const cdisasm_x86_form_id expected_form =
                    (cdisasm_x86_form_id)(families[family_index].base_form
                        + (memory ? 0u : 2u) + (ll - 1u));
                const cdisasm_x86_group_id expected_group =
                    families[family_index].dq
                        ? (ll == 1u ? CDISASM_X86_GROUP_AVX512DQ_256
                                    : CDISASM_X86_GROUP_AVX512DQ_512)
                        : (ll == 1u ? CDISASM_X86_GROUP_AVX512F_256
                                    : CDISASM_X86_GROUP_AVX512F_512);
                const cdisasm_x86_decode_bit_id expected_bit =
                    families[family_index].dq
                        ? (ll == 1u ? CDISASM_X86_DECODE_BIT_AVX512DQ_256
                                    : CDISASM_X86_DECODE_BIT_AVX512DQ_512)
                        : (ll == 1u ? CDISASM_X86_DECODE_BIT_AVX512F_256
                                    : CDISASM_X86_DECODE_BIT_AVX512F_512);
                cdisasm_instruction instruction;
                uint32_t size;

                if (!memory) bytes[6] = 0x03;
                memset(&instruction, 0xa5, sizeof(instruction));
                size = cdisasm_x86_decode(CDISASM_CPU_X86,
                    CDISASM_MODE_64, bytes, byte_count, UINT64_C(0x1000),
                    &flags, &instruction);
#if USE_EXTRA_OPCODES
                EXPECT(size == byte_count);
                EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                EXPECT(instruction.name_id == families[family_index].name_id);
                EXPECT(instruction.form_id == expected_form);
                EXPECT(instruction.operand_count == 3u);
                EXPECT(instruction.opcode[0].type == (memory
                    ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
                EXPECT(instruction.opcode[0].size == 16u);
                EXPECT(instruction.opcode[0].access == (memory
                    ? CDISASM_OPERAND_ACCESS_READ_WRITE
                    : CDISASM_OPERAND_ACCESS_WRITE));
                EXPECT(instruction.opcode[1].size == (16u << ll));
                EXPECT(instruction.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                EXPECT(instruction.opcode[2].imm == 3u);
                EXPECT(instruction.mask_reg == CDISASM_X86_REG_K1);
                EXPECT(instruction.mask_mode == (memory
                    ? CDISASM_X86_MASK_MERGE : CDISASM_X86_MASK_ZERO));
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction, expected_group));
                {
                    cdisasm_x86_decode_flags missing = flags;
                    EXPECT(cdisasm_decode_flags_clear_bit(
                        &missing, expected_bit));
                    memset(&instruction, 0xa5, sizeof(instruction));
                    EXPECT(cdisasm_x86_decode(CDISASM_CPU_X86,
                        CDISASM_MODE_64, bytes, byte_count,
                        UINT64_C(0x1000), &missing, &instruction) == 0u);
                    EXPECT(is_error_only(&instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
                }
#else
                (void)expected_form;
                (void)expected_group;
                (void)expected_bit;
                EXPECT(size == 0u);
                EXPECT(is_error_only(&instruction,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
            }
        }
    }
    {
        static const uint8_t invalid[][7] = {
            {0x62,0xf3,0x7d,0x89,0x19,0xc8,0x03}, /* VL128 */
            {0x62,0xf3,0x7d,0xa9,0x19,0x08,0x03}, /* z on memory */
            {0x62,0xf3,0x7d,0xb9,0x19,0xc8,0x03}, /* reserved EVEX.b */
            {0x62,0xf3,0x6d,0xa9,0x19,0xc8,0x03}  /* reserved vvvv */
        };
        size_t index;

        for (index = 0; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
            cdisasm_instruction instruction;
            memset(&instruction, 0xa5, sizeof(instruction));
            EXPECT(cdisasm_x86_decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                invalid[index], sizeof(invalid[index]), UINT64_C(0x1000),
                &flags, &instruction) == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
        }
    }
    return failures != 0;
}
