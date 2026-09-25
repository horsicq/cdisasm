#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;
#if USE_EXTRA_OPCODES
#define MOVBE_FLAGS CDISASM_X86_DECODE_FLAG_APX
#else
#define MOVBE_FLAGS CDISASM_X86_DECODE_FLAG_BASE
#endif
#define EXPECT(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", \
    __FILE__, __LINE__, #x); ++failures; } } while (0)

int main(void)
{
    static const struct { uint8_t p1, opcode, modrm, bytes; } cases[] = {
        {0x7d,0x61,0xc8,2},{0x7d,0x60,0x01,2},{0x7d,0x61,0x01,2},
        {0x7c,0x61,0xc8,4},{0x7c,0x60,0x01,4},{0x7c,0x61,0x01,4},
        {0xfc,0x61,0xc8,8},{0xfc,0x60,0x01,8},{0xfc,0x61,0x01,8}
    };
    size_t i;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const uint8_t code[6] = {0x62,0xec,cases[i].p1,0x08,
                                  cases[i].opcode,cases[i].modrm};
        cdisasm_x86_decode_flags flags =
            CDISASM_X86_DECODE_FLAGS_INITIALIZER(
                MOVBE_FLAGS);
        cdisasm_instruction insn;
        uint32_t n;
#if USE_EXTRA_OPCODES
        EXPECT(cdisasm_decode_flags_set_bit(
            &flags, CDISASM_X86_DECODE_BIT_APX_F_MOVBE));
#endif
        memset(&insn, 0, sizeof(insn));
        n = cdisasm_test_x86_decode_exact_flags(
            CDISASM_CPU_X86, CDISASM_MODE_64, code, sizeof(code),
            UINT64_C(0x1000), &flags, &insn);
#if USE_EXTRA_OPCODES
        EXPECT(n == sizeof(code));
        EXPECT(insn.last_error_id == CDISASM_STATUS_OK);
        EXPECT(insn.name_id == CDISASM_X86_NAME_MOVBE);
        EXPECT(insn.operand_count == 2u);
        EXPECT(insn.opcode[0].size == cases[i].bytes);
        EXPECT(insn.opcode[1].size == cases[i].bytes);
        EXPECT(insn.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        EXPECT(insn.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(cdisasm_instruction_has_x86_group(
            &insn, CDISASM_X86_GROUP_APX_F));
        EXPECT(cdisasm_instruction_has_x86_group(
            &insn, CDISASM_X86_GROUP_APX_F_MOVBE));
        EXPECT(cdisasm_instruction_has_x86_group(
            &insn, CDISASM_X86_GROUP_MOVBE));
#else
        EXPECT(n == 0u);
        EXPECT(insn.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
    if (failures) return 1;
    printf("x86 APX MOVBE tests passed (%zu width/direction cases)\n",
           sizeof(cases) / sizeof(cases[0]));
    return 0;
}
