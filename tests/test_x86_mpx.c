#include "test_decode_flags_adapter.h"
#include "x86_test_flags.h"

#include "cdisasm/cdisasm.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define EXPECT(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", \
    __FILE__, __LINE__, #x); ++failures; } } while (0)

typedef struct mpx_case {
    uint8_t bytes[5];
    uint8_t size;
    cdisasm_mode mode;
    cdisasm_x86_name_id name;
    uint8_t first_type;
    uint8_t first_size;
    cdisasm_operand_access first_access;
    uint8_t second_type;
    uint8_t second_size;
    cdisasm_operand_access second_access;
    uint8_t address_only;
} mpx_case;

static const mpx_case cases[] = {
    {{0xf3,0x0f,0x1b,0x08},4,CDISASM_MODE_32,CDISASM_X86_NAME_BNDMK,
     CDISASM_OPERAND_REGISTER,8,CDISASM_OPERAND_ACCESS_WRITE,
     CDISASM_OPERAND_MEMORY,1,CDISASM_OPERAND_ACCESS_READ,1},
    {{0xf3,0x0f,0x1a,0x08},4,CDISASM_MODE_32,CDISASM_X86_NAME_BNDCL,
     CDISASM_OPERAND_REGISTER,8,CDISASM_OPERAND_ACCESS_READ,
     CDISASM_OPERAND_MEMORY,1,CDISASM_OPERAND_ACCESS_READ,1},
    {{0xf3,0x0f,0x1a,0xc9},4,CDISASM_MODE_32,CDISASM_X86_NAME_BNDCL,
     CDISASM_OPERAND_REGISTER,8,CDISASM_OPERAND_ACCESS_READ,
     CDISASM_OPERAND_REGISTER,4,CDISASM_OPERAND_ACCESS_READ,0},
    {{0xf3,0x0f,0x1a,0xc9},4,CDISASM_MODE_64,CDISASM_X86_NAME_BNDCL,
     CDISASM_OPERAND_REGISTER,16,CDISASM_OPERAND_ACCESS_READ,
     CDISASM_OPERAND_REGISTER,8,CDISASM_OPERAND_ACCESS_READ,0},
    {{0xf2,0x0f,0x1a,0x08},4,CDISASM_MODE_32,CDISASM_X86_NAME_BNDCU,
     CDISASM_OPERAND_REGISTER,8,CDISASM_OPERAND_ACCESS_READ,
     CDISASM_OPERAND_MEMORY,1,CDISASM_OPERAND_ACCESS_READ,1},
    {{0xf2,0x0f,0x1a,0xc9},4,CDISASM_MODE_32,CDISASM_X86_NAME_BNDCU,
     CDISASM_OPERAND_REGISTER,8,CDISASM_OPERAND_ACCESS_READ,
     CDISASM_OPERAND_REGISTER,4,CDISASM_OPERAND_ACCESS_READ,0},
    {{0xf2,0x0f,0x1a,0xc9},4,CDISASM_MODE_64,CDISASM_X86_NAME_BNDCU,
     CDISASM_OPERAND_REGISTER,16,CDISASM_OPERAND_ACCESS_READ,
     CDISASM_OPERAND_REGISTER,8,CDISASM_OPERAND_ACCESS_READ,0},
    {{0xf2,0x0f,0x1b,0x08},4,CDISASM_MODE_32,CDISASM_X86_NAME_BNDCN,
     CDISASM_OPERAND_REGISTER,8,CDISASM_OPERAND_ACCESS_READ,
     CDISASM_OPERAND_MEMORY,1,CDISASM_OPERAND_ACCESS_READ,1},
    {{0xf2,0x0f,0x1b,0xc9},4,CDISASM_MODE_32,CDISASM_X86_NAME_BNDCN,
     CDISASM_OPERAND_REGISTER,8,CDISASM_OPERAND_ACCESS_READ,
     CDISASM_OPERAND_REGISTER,4,CDISASM_OPERAND_ACCESS_READ,0},
    {{0xf2,0x0f,0x1b,0xc9},4,CDISASM_MODE_64,CDISASM_X86_NAME_BNDCN,
     CDISASM_OPERAND_REGISTER,16,CDISASM_OPERAND_ACCESS_READ,
     CDISASM_OPERAND_REGISTER,8,CDISASM_OPERAND_ACCESS_READ,0},
    {{0x66,0x0f,0x1a,0xca},4,CDISASM_MODE_32,CDISASM_X86_NAME_BNDMOV,
     CDISASM_OPERAND_REGISTER,8,CDISASM_OPERAND_ACCESS_WRITE,
     CDISASM_OPERAND_REGISTER,8,CDISASM_OPERAND_ACCESS_READ,0},
    {{0x66,0x0f,0x1a,0x08},4,CDISASM_MODE_32,CDISASM_X86_NAME_BNDMOV,
     CDISASM_OPERAND_REGISTER,8,CDISASM_OPERAND_ACCESS_WRITE,
     CDISASM_OPERAND_MEMORY,8,CDISASM_OPERAND_ACCESS_READ,0},
    {{0x66,0x0f,0x1a,0x08},4,CDISASM_MODE_64,CDISASM_X86_NAME_BNDMOV,
     CDISASM_OPERAND_REGISTER,16,CDISASM_OPERAND_ACCESS_WRITE,
     CDISASM_OPERAND_MEMORY,16,CDISASM_OPERAND_ACCESS_READ,0},
    {{0x66,0x0f,0x1b,0x08},4,CDISASM_MODE_32,CDISASM_X86_NAME_BNDMOV,
     CDISASM_OPERAND_MEMORY,8,CDISASM_OPERAND_ACCESS_WRITE,
     CDISASM_OPERAND_REGISTER,8,CDISASM_OPERAND_ACCESS_READ,0},
    {{0x66,0x0f,0x1b,0x08},4,CDISASM_MODE_64,CDISASM_X86_NAME_BNDMOV,
     CDISASM_OPERAND_MEMORY,16,CDISASM_OPERAND_ACCESS_WRITE,
     CDISASM_OPERAND_REGISTER,16,CDISASM_OPERAND_ACCESS_READ,0},
    {{0x0f,0x1a,0x0c,0x48},4,CDISASM_MODE_32,CDISASM_X86_NAME_BNDLDX,
     CDISASM_OPERAND_REGISTER,8,CDISASM_OPERAND_ACCESS_WRITE,
     CDISASM_OPERAND_MEMORY,12,CDISASM_OPERAND_ACCESS_READ,0},
    {{0x0f,0x1a,0x0c,0x48},4,CDISASM_MODE_64,CDISASM_X86_NAME_BNDLDX,
     CDISASM_OPERAND_REGISTER,16,CDISASM_OPERAND_ACCESS_WRITE,
     CDISASM_OPERAND_MEMORY,24,CDISASM_OPERAND_ACCESS_READ,0},
    {{0x0f,0x1b,0x0c,0x48},4,CDISASM_MODE_32,CDISASM_X86_NAME_BNDSTX,
     CDISASM_OPERAND_MEMORY,12,CDISASM_OPERAND_ACCESS_WRITE,
     CDISASM_OPERAND_REGISTER,8,CDISASM_OPERAND_ACCESS_READ,0},
    {{0x0f,0x1b,0x0c,0x48},4,CDISASM_MODE_64,CDISASM_X86_NAME_BNDSTX,
     CDISASM_OPERAND_MEMORY,24,CDISASM_OPERAND_ACCESS_WRITE,
     CDISASM_OPERAND_REGISTER,16,CDISASM_OPERAND_ACCESS_READ,0}
};

int main(void)
{
    size_t i;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        cdisasm_instruction insn;
        uint32_t n;
        memset(&insn, 0, sizeof(insn));
        n = cdisasm_test_x86_decode(CDISASM_CPU_X86, cases[i].mode,
            cases[i].bytes, cases[i].size, UINT64_C(0x1000),
            CDISASM_X86_TEST_ALL_FLAGS, &insn);
#if USE_EXTRA_OPCODES
        EXPECT(n == cases[i].size);
        EXPECT(insn.last_error_id == CDISASM_STATUS_OK);
        EXPECT(insn.name_id == cases[i].name);
        EXPECT(insn.operand_count == 2);
        EXPECT(cdisasm_instruction_has_x86_group(
            &insn, CDISASM_X86_GROUP_MPX));
        EXPECT(insn.opcode[0].type == cases[i].first_type);
        EXPECT(insn.opcode[0].size == cases[i].first_size);
        EXPECT(insn.opcode[0].access == cases[i].first_access);
        EXPECT(insn.opcode[1].type == cases[i].second_type);
        EXPECT(insn.opcode[1].size == cases[i].second_size);
        EXPECT(insn.opcode[1].access == cases[i].second_access);
        EXPECT(((insn.opcode[1].flags & CDISASM_OPERAND_FLAG_ADDRESS_ONLY)
                != 0) == cases[i].address_only);
#else
        EXPECT(n == 0);
        EXPECT(insn.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
    if (failures != 0) {
        fprintf(stderr, "%d MPX test(s) failed\n", failures);
        return 1;
    }
    printf("x86 MPX tests passed (%zu exact forms)\n",
        sizeof(cases) / sizeof(cases[0]));
    return 0;
}
