#include "cdisasm/cdisasm_format.h"
#include "cdisasm/cdisasm_x86.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define EXPECT(condition) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "%s:%d: expectation failed: %s\n", \
                    __FILE__, __LINE__, #condition); \
            ++failures; \
        } \
    } while (0)

static int decode_all(
    cdisasm_cpu_id cpu,
    cdisasm_mode mode,
    const uint8_t *bytes,
    size_t size,
    cdisasm_instruction *instruction)
{
    cdisasm_x86_decode_flags flags;

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(cpu, mode, &flags)
           == CDISASM_STATUS_OK);
    return (int)cdisasm_x86_decode(
        cpu, mode, bytes, size, UINT64_C(0x1000), &flags, instruction);
}

static void test_register_compare(void)
{
    static const uint8_t bytes[] = {
        UINT8_C(0x62), UINT8_C(0xf4), UINT8_C(0x7c), UINT8_C(0x06),
        UINT8_C(0x38), UINT8_C(0xc0)
    };
    cdisasm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_all(
        CDISASM_CPU_APX, CDISASM_MODE_64, bytes, sizeof(bytes),
        &instruction) == (int)sizeof(bytes));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_CCMPBE);
    EXPECT(instruction.form_id != CDISASM_X86_FORM_NONE);
    EXPECT(instruction.operand_count == 2u);
    EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction.opcode[0].size == 1u);
    EXPECT(instruction.opcode[1].size == 1u);
    EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.default_flags == (CDISASM_X86_DEFAULT_FLAG_CF
        | CDISASM_X86_DEFAULT_FLAG_ZF
        | CDISASM_X86_DEFAULT_FLAG_SF
        | CDISASM_X86_DEFAULT_FLAG_OF));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F_N3));
#if USE_DISASM_FORMAT
    {
        char text[128];
        EXPECT(cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            text, sizeof(text)) == strlen(
                "ccmpbe {dfv=of,sf,zf,cf} al, al"));
        EXPECT(strcmp(text, "ccmpbe {dfv=of,sf,zf,cf} al, al") == 0);
        EXPECT(cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ATT,
            text, sizeof(text)) == strlen(
                "ccmpbe {dfv=of,sf,zf,cf} %al, %al"));
        EXPECT(strcmp(text, "ccmpbe {dfv=of,sf,zf,cf} %al, %al") == 0);
    }
#endif
}

static void test_memory_test_and_profile_gates(void)
{
    static const uint8_t memory_bytes[] = {
        UINT8_C(0x62), UINT8_C(0xf4), UINT8_C(0x78), UINT8_C(0x06),
        UINT8_C(0x3a), UINT8_C(0x00)
    };
    static const uint8_t mode32_bytes[] = {
        UINT8_C(0x62), UINT8_C(0xf4), UINT8_C(0x7c), UINT8_C(0x06),
        UINT8_C(0x38), UINT8_C(0xc0)
    };
    cdisasm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_all(
        CDISASM_CPU_APX, CDISASM_MODE_64, memory_bytes, sizeof(memory_bytes),
        &instruction) == (int)sizeof(memory_bytes));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_CCMPBE);
    EXPECT(instruction.operand_count == 2u);
    EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.opcode[0].size == 1u);
    EXPECT(instruction.opcode[1].size == 1u);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_all(
        CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_MODE_64,
        memory_bytes, sizeof(memory_bytes), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_all(
        CDISASM_CPU_APX, CDISASM_MODE_32,
        mode32_bytes, sizeof(mode32_bytes), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
}

static void test_stack_pair_forms(void)
{
    static const uint8_t pop2p_bytes[] = {
        UINT8_C(0x62), UINT8_C(0xf4), UINT8_C(0xfc), UINT8_C(0x10),
        UINT8_C(0x8f), UINT8_C(0xc0)
    };
    static const uint8_t push2p_bytes[] = {
        UINT8_C(0x62), UINT8_C(0xf4), UINT8_C(0xfc), UINT8_C(0x10),
        UINT8_C(0xff), UINT8_C(0xf0)
    };
    const uint8_t *samples[] = {pop2p_bytes, push2p_bytes};
    cdisasm_x86_name_id names[] = {
        CDISASM_X86_NAME_POP2P, CDISASM_X86_NAME_PUSH2P
    };
    cdisasm_instruction instruction;
    size_t index;

    for (index = 0; index < 2u; ++index) {
        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_all(
            CDISASM_CPU_APX, CDISASM_MODE_64,
            samples[index], 6u, &instruction) == 6);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == names[index]);
        EXPECT(instruction.form_id != CDISASM_X86_FORM_NONE);
        EXPECT(instruction.operand_count == 2u);
        EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_R16);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_RAX);
        EXPECT(instruction.opcode[0].size == 8u);
        EXPECT(instruction.opcode[1].size == 8u);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F_N3));
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_APX_NDD) != 0u);
#if USE_DISASM_FORMAT
        {
            char text[64];
            const char *intel = index == 0u
                ? "pop2p r16, rax" : "push2p r16, rax";
            const char *att = index == 0u
                ? "pop2p %rax, %r16" : "push2p %rax, %r16";
            EXPECT(cdisasm_x86_format(
                &instruction, CDISASM_FORMAT_SYNTAX_INTEL,
                text, sizeof(text)) == strlen(intel));
            EXPECT(strcmp(text, intel) == 0);
            EXPECT(cdisasm_x86_format(
                &instruction, CDISASM_FORMAT_SYNTAX_ATT,
                text, sizeof(text)) == strlen(att));
            EXPECT(strcmp(text, att) == 0);
        }
#endif
    }
}

int main(void)
{
    test_register_compare();
    test_memory_test_and_profile_gates();
    test_stack_pair_forms();
    if (failures != 0) {
        fprintf(stderr, "%d APX N3 tests failed\n", failures);
        return 1;
    }
    puts("x86 APX N3 tests passed");
    return 0;
}
