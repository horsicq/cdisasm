#include "cdisasm/cdisasm_x86.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;
#define EXPECT(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", \
    __FILE__, __LINE__, #x); ++failures; } } while (0)

typedef struct extract_case {
    uint8_t p1;
    uint8_t opcode;
    uint8_t memory;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_form_id form_id;
    cdisasm_x86_group_id group_id;
    cdisasm_x86_decode_bit_id bit_id;
} extract_case;

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
    static const extract_case cases[] = {
        {0x7d,0x1b,1,CDISASM_X86_NAME_VEXTRACTF32X8,4545,CDISASM_X86_GROUP_AVX512DQ_512,CDISASM_X86_DECODE_BIT_AVX512DQ_512},
        {0x7d,0x1b,0,CDISASM_X86_NAME_VEXTRACTF32X8,4546,CDISASM_X86_GROUP_AVX512DQ_512,CDISASM_X86_DECODE_BIT_AVX512DQ_512},
        {0xfd,0x1b,1,CDISASM_X86_NAME_VEXTRACTF64X4,4551,CDISASM_X86_GROUP_AVX512F_512,CDISASM_X86_DECODE_BIT_AVX512F_512},
        {0xfd,0x1b,0,CDISASM_X86_NAME_VEXTRACTF64X4,4552,CDISASM_X86_GROUP_AVX512F_512,CDISASM_X86_DECODE_BIT_AVX512F_512},
        {0x7d,0x3b,1,CDISASM_X86_NAME_VEXTRACTI32X8,4559,CDISASM_X86_GROUP_AVX512DQ_512,CDISASM_X86_DECODE_BIT_AVX512DQ_512},
        {0x7d,0x3b,0,CDISASM_X86_NAME_VEXTRACTI32X8,4560,CDISASM_X86_GROUP_AVX512DQ_512,CDISASM_X86_DECODE_BIT_AVX512DQ_512},
        {0xfd,0x3b,1,CDISASM_X86_NAME_VEXTRACTI64X4,4565,CDISASM_X86_GROUP_AVX512F_512,CDISASM_X86_DECODE_BIT_AVX512F_512},
        {0xfd,0x3b,0,CDISASM_X86_NAME_VEXTRACTI64X4,4566,CDISASM_X86_GROUP_AVX512F_512,CDISASM_X86_DECODE_BIT_AVX512F_512}
    };
    cdisasm_x86_decode_flags flags = CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    size_t index;

#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_X86,
        CDISASM_MODE_64, &flags) == CDISASM_STATUS_OK);
#endif
    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        uint8_t bytes[] = {0x62,0xf3,cases[index].p1,
            (uint8_t)(cases[index].memory ? 0x49u : 0xc9u),
            cases[index].opcode,
            (uint8_t)(cases[index].memory ? 0x48u : 0xc8u),0x01,0x03};
        size_t byte_count = cases[index].memory ? 8u : 7u;
        cdisasm_instruction instruction;
        uint32_t size;

        if (!cases[index].memory) bytes[6] = 0x03;
        memset(&instruction, 0xa5, sizeof(instruction));
        size = cdisasm_x86_decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            bytes, byte_count, UINT64_C(0x1000), &flags, &instruction);
#if USE_EXTRA_OPCODES
        EXPECT(size == byte_count);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == cases[index].name_id);
        EXPECT(instruction.form_id == cases[index].form_id);
        EXPECT(instruction.operand_count == 3u);
        EXPECT(instruction.opcode[0].type == (cases[index].memory
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
        EXPECT(instruction.opcode[0].size == 32u);
        EXPECT(instruction.opcode[0].access == (cases[index].memory
            ? CDISASM_OPERAND_ACCESS_READ_WRITE
            : CDISASM_OPERAND_ACCESS_WRITE));
        EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction.opcode[1].size == 64u);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_ZMM1);
        EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_IMMEDIATE);
        EXPECT(instruction.opcode[2].imm == 3u);
        EXPECT(instruction.mask_reg == CDISASM_X86_REG_K1);
        EXPECT(instruction.mask_mode == (cases[index].memory
            ? CDISASM_X86_MASK_MERGE : CDISASM_X86_MASK_ZERO));
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
        static const uint8_t invalid[][7] = {
            {0x62,0xf3,0x7d,0xa9,0x1b,0xc8,0x03}, /* VL256 */
            {0x62,0xf3,0x7d,0xc9,0x1b,0x08,0x03}, /* z on memory */
            {0x62,0xf3,0x7d,0xd9,0x1b,0xc8,0x03}, /* reserved EVEX.b */
            {0x62,0xf3,0x6d,0xc9,0x1b,0xc8,0x03}  /* reserved vvvv */
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
