#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>

static int failures;
#define EXPECT(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", \
    __FILE__, __LINE__, #c); ++failures; } } while (0)

struct test_case {
    uint32_t word;
    cdisasm_arm_name_id name;
    cdisasm_arm_form_id form;
    unsigned count;
    const char *text;
};

static uint32_t decode(uint32_t word, uint32_t options,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];
    if ((options & CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN) != 0u) {
        bytes[0] = (uint8_t)(word >> 24); bytes[1] = (uint8_t)(word >> 16);
        bytes[2] = (uint8_t)(word >> 8); bytes[3] = (uint8_t)word;
    } else {
        bytes[0] = (uint8_t)word; bytes[1] = (uint8_t)(word >> 8);
        bytes[2] = (uint8_t)(word >> 16); bytes[3] = (uint8_t)(word >> 24);
    }
    return cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, 4u, 0u, options, instruction);
}

static void check(const struct test_case *tc)
{
    cdisasm_arm_instruction instruction, big;
#if USE_EXTRA_OPCODES
    unsigned q = (tc->word >> 30) & 1u;
    unsigned vd = tc->word & 31u, vn = (tc->word >> 5) & 31u;
    unsigned vm = (tc->word >> 16) & 31u;
#if USE_DISASM_FORMAT
    char text[160];
#endif
#endif
    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(decode(tc->word, 0u, &instruction) == 4u);
    EXPECT(instruction.name_id == tc->name);
    EXPECT(instruction.form_id == tc->form);
    EXPECT(instruction.instruction_flags == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    EXPECT(instruction.operand_count == 3u);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_V0 + vd);
    EXPECT(instruction.operand[0].size == (q ? 16u : 8u));
    EXPECT(instruction.operand[0].access == (tc->name == CDISASM_ARM_NAME_TBX
        ? CDISASM_OPERAND_ACCESS_READ_WRITE : CDISASM_OPERAND_ACCESS_WRITE));
    EXPECT(instruction.operand[1].type == CDISASM_ARM_OPERAND_VECTOR_REGISTER_LIST);
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_V0 + vn);
    EXPECT(instruction.operand[1].register_list == tc->count);
    EXPECT(instruction.operand[1].size == 16u);
    EXPECT(instruction.operand[1].extend_type == 1u);
    EXPECT(instruction.operand[1].scale == 16u);
    EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.operand[2].reg == CDISASM_ARM_REG_V0 + vm);
    EXPECT(instruction.operand[2].size == (q ? 16u : 8u));
#if USE_DISASM_FORMAT
    EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text)) != 0u);
    EXPECT(strcmp(text, tc->text) == 0);
#endif
    memset(&big, 0xa5, sizeof(big));
    EXPECT(decode(tc->word, CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &big) == 4u);
    EXPECT(memcmp(&instruction, &big, sizeof(instruction)) == 0);
#else
    cdisasm_arm_instruction expected;
    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    EXPECT(decode(tc->word, 0u, &instruction) == 0u);
    EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
    (void)tc; (void)big;
#endif
}

int main(void)
{
    static const struct test_case cases[] = {
        { 0x0e020020u, CDISASM_ARM_NAME_TBL, 5892, 1, "tbl v0.8b, {v1.16b}, v2.8b" },
        { 0x0e0d118bu, CDISASM_ARM_NAME_TBX, 5893, 1, "tbx v11.8b, {v12.16b}, v13.8b" },
        { 0x4e1121eeu, CDISASM_ARM_NAME_TBL, 5894, 2, "tbl v14.16b, {v15.16b, v16.16b}, v17.16b" },
        { 0x4e063083u, CDISASM_ARM_NAME_TBX, 5895, 2, "tbx v3.16b, {v4.16b, v5.16b}, v6.16b" },
        { 0x0e0843a7u, CDISASM_ARM_NAME_TBL, 5896, 3, "tbl v7.8b, {v29.16b, v30.16b, v31.16b}, v8.8b" },
        { 0x0e165272u, CDISASM_ARM_NAME_TBX, 5897, 3, "tbx v18.8b, {v19.16b, v20.16b, v21.16b}, v22.8b" },
        { 0x4e1863b7u, CDISASM_ARM_NAME_TBL, 5898, 4, "tbl v23.16b, {v29.16b, v30.16b, v31.16b, v0.16b}, v24.16b" },
        { 0x4e0a7389u, CDISASM_ARM_NAME_TBX, 5899, 4, "tbx v9.16b, {v28.16b, v29.16b, v30.16b, v31.16b}, v10.16b" }
    };
    size_t i;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) check(&cases[i]);
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction instruction;
        (void)decode(UINT32_C(0x0e020420), 0u, &instruction);
        EXPECT(instruction.form_id < 5892u || instruction.form_id > 5899u);
    }
#endif
    if (failures != 0) return 1;
    puts("A64 Advanced SIMD table lookup tests passed");
    return 0;
}
