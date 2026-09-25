#include "cdisasm/cdisasm_x86.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;
#define EXPECT(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", \
    __FILE__, __LINE__, #x); ++failures; } } while (0)

typedef struct x2_case {
    uint8_t ll;
    uint8_t opcode;
    uint8_t reg_source;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_form_id form_id;
    cdisasm_x86_group_id group_id;
    cdisasm_x86_decode_bit_id bit_id;
} x2_case;

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
    static const x2_case cases[] = {
        {1,0x19,0,CDISASM_X86_NAME_VBROADCASTF32X2,3544,CDISASM_X86_GROUP_AVX512DQ_256,CDISASM_X86_DECODE_BIT_AVX512DQ_256},
        {1,0x19,1,CDISASM_X86_NAME_VBROADCASTF32X2,3545,CDISASM_X86_GROUP_AVX512DQ_256,CDISASM_X86_DECODE_BIT_AVX512DQ_256},
        {2,0x19,0,CDISASM_X86_NAME_VBROADCASTF32X2,3546,CDISASM_X86_GROUP_AVX512DQ_512,CDISASM_X86_DECODE_BIT_AVX512DQ_512},
        {2,0x19,1,CDISASM_X86_NAME_VBROADCASTF32X2,3547,CDISASM_X86_GROUP_AVX512DQ_512,CDISASM_X86_DECODE_BIT_AVX512DQ_512},
        {0,0x59,0,CDISASM_X86_NAME_VBROADCASTI32X2,3555,CDISASM_X86_GROUP_AVX512DQ_128,CDISASM_X86_DECODE_BIT_AVX512DQ_128},
        {0,0x59,1,CDISASM_X86_NAME_VBROADCASTI32X2,3556,CDISASM_X86_GROUP_AVX512DQ_128,CDISASM_X86_DECODE_BIT_AVX512DQ_128},
        {1,0x59,0,CDISASM_X86_NAME_VBROADCASTI32X2,3557,CDISASM_X86_GROUP_AVX512DQ_256,CDISASM_X86_DECODE_BIT_AVX512DQ_256},
        {1,0x59,1,CDISASM_X86_NAME_VBROADCASTI32X2,3558,CDISASM_X86_GROUP_AVX512DQ_256,CDISASM_X86_DECODE_BIT_AVX512DQ_256},
        {2,0x59,0,CDISASM_X86_NAME_VBROADCASTI32X2,3559,CDISASM_X86_GROUP_AVX512DQ_512,CDISASM_X86_DECODE_BIT_AVX512DQ_512},
        {2,0x59,1,CDISASM_X86_NAME_VBROADCASTI32X2,3560,CDISASM_X86_GROUP_AVX512DQ_512,CDISASM_X86_DECODE_BIT_AVX512DQ_512}
    };
    cdisasm_x86_decode_flags flags = CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    size_t index;

#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_X86,
        CDISASM_MODE_64, &flags) == CDISASM_STATUS_OK);
#endif
    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        uint8_t bytes[] = {0x62,0xf2,0x7d,
            (uint8_t)(0x89u + 0x20u * cases[index].ll),
            cases[index].opcode,
            (uint8_t)(cases[index].reg_source ? 0xc1u : 0x40u),0x01};
        size_t byte_count = cases[index].reg_source ? 6u : 7u;
        cdisasm_instruction instruction;
        uint32_t size;

        memset(&instruction, 0xa5, sizeof(instruction));
        size = cdisasm_x86_decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            bytes, byte_count, UINT64_C(0x1000), &flags, &instruction);
#if USE_EXTRA_OPCODES
        EXPECT(size == byte_count);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == cases[index].name_id);
        EXPECT(instruction.form_id == cases[index].form_id);
        EXPECT(instruction.operand_count == 2u);
        EXPECT(instruction.opcode[0].size == (16u << cases[index].ll));
        EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        EXPECT(instruction.opcode[1].type == (cases[index].reg_source
            ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
        EXPECT(instruction.opcode[1].size == (cases[index].reg_source
            ? 16u : 8u));
        EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction.mask_reg == CDISASM_X86_REG_K1);
        EXPECT(instruction.mask_mode == CDISASM_X86_MASK_ZERO);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512DQ));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, cases[index].group_id));
        {
            cdisasm_x86_decode_flags missing = flags;
            EXPECT(cdisasm_decode_flags_clear_bit(
                &missing, cases[index].bit_id));
            memset(&instruction, 0xa5, sizeof(instruction));
            EXPECT(cdisasm_x86_decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                bytes, byte_count, UINT64_C(0x1000), &missing,
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
            {0x62,0xf2,0x7d,0x89,0x19,0x00}, /* F32X2 VL128 */
            {0x62,0xf2,0x7d,0xb9,0x59,0x00}  /* reserved EVEX.b */
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
