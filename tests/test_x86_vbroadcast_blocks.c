#include "cdisasm/cdisasm_x86.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;
#define EXPECT(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", \
    __FILE__, __LINE__, #x); ++failures; } } while (0)

typedef struct broadcast_case {
    uint8_t p1;
    uint8_t p2;
    uint8_t opcode;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_form_id form_id;
    cdisasm_x86_group_id width_group;
    cdisasm_x86_decode_bit_id width_bit;
    uint16_t destination_bytes;
    uint16_t source_bytes;
} broadcast_case;

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
    static const broadcast_case cases[] = {
        {0x7d,0xa9,0x1a,CDISASM_X86_NAME_VBROADCASTF32X4,3548,CDISASM_X86_GROUP_AVX512F_256,CDISASM_X86_DECODE_BIT_AVX512F_256,32,16},
        {0x7d,0xc9,0x1a,CDISASM_X86_NAME_VBROADCASTF32X4,3549,CDISASM_X86_GROUP_AVX512F_512,CDISASM_X86_DECODE_BIT_AVX512F_512,64,16},
        {0x7d,0xc9,0x1b,CDISASM_X86_NAME_VBROADCASTF32X8,3550,CDISASM_X86_GROUP_AVX512DQ_512,CDISASM_X86_DECODE_BIT_AVX512DQ_512,64,32},
        {0xfd,0xa9,0x1a,CDISASM_X86_NAME_VBROADCASTF64X2,3551,CDISASM_X86_GROUP_AVX512DQ_256,CDISASM_X86_DECODE_BIT_AVX512DQ_256,32,16},
        {0xfd,0xc9,0x1a,CDISASM_X86_NAME_VBROADCASTF64X2,3552,CDISASM_X86_GROUP_AVX512DQ_512,CDISASM_X86_DECODE_BIT_AVX512DQ_512,64,16},
        {0xfd,0xc9,0x1b,CDISASM_X86_NAME_VBROADCASTF64X4,3553,CDISASM_X86_GROUP_AVX512F_512,CDISASM_X86_DECODE_BIT_AVX512F_512,64,32},
        {0x7d,0xa9,0x5a,CDISASM_X86_NAME_VBROADCASTI32X4,3561,CDISASM_X86_GROUP_AVX512F_256,CDISASM_X86_DECODE_BIT_AVX512F_256,32,16},
        {0x7d,0xc9,0x5a,CDISASM_X86_NAME_VBROADCASTI32X4,3562,CDISASM_X86_GROUP_AVX512F_512,CDISASM_X86_DECODE_BIT_AVX512F_512,64,16},
        {0x7d,0xc9,0x5b,CDISASM_X86_NAME_VBROADCASTI32X8,3563,CDISASM_X86_GROUP_AVX512DQ_512,CDISASM_X86_DECODE_BIT_AVX512DQ_512,64,32},
        {0xfd,0xa9,0x5a,CDISASM_X86_NAME_VBROADCASTI64X2,3564,CDISASM_X86_GROUP_AVX512DQ_256,CDISASM_X86_DECODE_BIT_AVX512DQ_256,32,16},
        {0xfd,0xc9,0x5a,CDISASM_X86_NAME_VBROADCASTI64X2,3565,CDISASM_X86_GROUP_AVX512DQ_512,CDISASM_X86_DECODE_BIT_AVX512DQ_512,64,16},
        {0xfd,0xc9,0x5b,CDISASM_X86_NAME_VBROADCASTI64X4,3566,CDISASM_X86_GROUP_AVX512F_512,CDISASM_X86_DECODE_BIT_AVX512F_512,64,32}
    };
    cdisasm_x86_decode_flags flags = CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    size_t index;

#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_X86,
        CDISASM_MODE_64, &flags) == CDISASM_STATUS_OK);
#endif
    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        uint8_t bytes[] = {0x62,0xf2,cases[index].p1,cases[index].p2,
            cases[index].opcode,0x40,0x01};
        cdisasm_instruction instruction;
        uint32_t size;

        memset(&instruction, 0xa5, sizeof(instruction));
        size = cdisasm_x86_decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            bytes, sizeof(bytes), UINT64_C(0x1000), &flags, &instruction);
#if USE_EXTRA_OPCODES
        EXPECT(size == sizeof(bytes));
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == cases[index].name_id);
        EXPECT(instruction.form_id == cases[index].form_id);
        EXPECT(instruction.operand_count == 2u);
        EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction.opcode[0].size == cases[index].destination_bytes);
        EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.opcode[1].size == cases[index].source_bytes);
        EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction.encoding.displacement_size == 1u);
        EXPECT(instruction.mask_reg == CDISASM_X86_REG_K1);
        EXPECT(instruction.mask_mode == CDISASM_X86_MASK_ZERO);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512F));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, cases[index].width_group));
        {
            cdisasm_x86_decode_flags missing = flags;
            EXPECT(cdisasm_decode_flags_clear_bit(
                &missing, cases[index].width_bit));
            memset(&instruction, 0xa5, sizeof(instruction));
            EXPECT(cdisasm_x86_decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                bytes, sizeof(bytes), UINT64_C(0x1000), &missing,
                &instruction) == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
        }
#else
        EXPECT(size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
    {
        static const uint8_t invalid[][6] = {
            {0x62,0xf2,0x7d,0xa9,0x1a,0xc0}, /* register source */
            {0x62,0xf2,0x7d,0x89,0x1a,0x00}, /* VL128 */
            {0x62,0xf2,0x7d,0xb9,0x1a,0x00}  /* reserved EVEX.b */
        };
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
