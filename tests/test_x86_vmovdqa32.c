#include "cdisasm/cdisasm_x86.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define EXPECT(expression)                                                   \
    do {                                                                      \
        if (!(expression)) {                                                  \
            fprintf(stderr, "%s:%d: expectation failed: %s\n",             \
                __FILE__, __LINE__, #expression);                             \
            ++failures;                                                        \
        }                                                                      \
    } while (0)

typedef struct vmovdqa32_case {
    const char *label;
    const uint8_t *code;
    size_t code_size;
    cdisasm_x86_reg_id destination;
    uint8_t vector_size;
    int memory_source;
    int memory_destination;
    int masked;
} vmovdqa32_case;

static cdisasm_instruction decode(
    const uint8_t *code,
    size_t code_size,
    cdisasm_x86_cpu_id cpu_id,
    uint32_t *decoded_size)
{
    cdisasm_instruction instruction;
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_X86, CDISASM_MODE_64, &flags) == CDISASM_STATUS_OK);

    memset(&instruction, 0xa5, sizeof(instruction));
    *decoded_size = cdisasm_x86_decode(
        cpu_id, CDISASM_MODE_64, code, code_size, UINT64_C(0x1000),
        &flags, &instruction);
    return instruction;
}

static void check_case(const vmovdqa32_case *test_case)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        test_case->code, test_case->code_size, CDISASM_CPU_X86,
        &decoded_size);

    EXPECT(decoded_size == 6u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VMOVDQA32);
    EXPECT((instruction.opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction,
        test_case->vector_size == 16u ? CDISASM_X86_GROUP_AVX512F_128
        : test_case->vector_size == 32u ? CDISASM_X86_GROUP_AVX512F_256
                                        : CDISASM_X86_GROUP_AVX512F_512));
    EXPECT(instruction.operand_count == 2u);
    EXPECT(instruction.encoding.prefix_size == 4u);
    EXPECT(instruction.encoding.opcode_offset == 4u);
    EXPECT(instruction.encoding.opcode_size == 1u);
    EXPECT(instruction.encoding.modrm_offset == 5u);
    EXPECT(instruction.encoding.modrm == UINT8_C(0x08)
        || instruction.encoding.modrm == UINT8_C(0xca));
    EXPECT(instruction.mask_mode == (test_case->masked
        ? CDISASM_X86_MASK_MERGE : CDISASM_X86_MASK_NONE));
    if (test_case->masked) {
        EXPECT(instruction.mask_reg == CDISASM_X86_REG_K1);
    } else {
        EXPECT(instruction.mask_reg == CDISASM_X86_REG_NONE);
    }

    if (test_case->memory_source) {
        EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction.opcode[0].reg == test_case->destination);
        EXPECT(instruction.opcode[0].size == test_case->vector_size);
        EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.opcode[1].size == test_case->vector_size);
        EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_RAX);
    } else if (test_case->memory_destination) {
        EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.opcode[0].size == test_case->vector_size);
        EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_RAX);
        EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction.opcode[1].reg == test_case->destination);
        EXPECT(instruction.opcode[1].size == test_case->vector_size);
    } else {
        EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction.opcode[0].reg == test_case->destination);
        EXPECT(instruction.opcode[0].size == test_case->vector_size);
        EXPECT(instruction.opcode[1].size == test_case->vector_size);
    }

#if USE_DISASM_FORMAT
    {
        char text[96];
        const size_t length = cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            text, sizeof(text));
        EXPECT(length != 0u);
        EXPECT(strstr(text, "vmovdqa32") == text);
        if (test_case->masked) {
            EXPECT(strstr(text, "{k1}") != NULL);
        }
    }
#endif
}

static void test_profile_gate(void)
{
    static const uint8_t code[] =
        { UINT8_C(0x62), UINT8_C(0xf1), UINT8_C(0x7d), UINT8_C(0x48),
          UINT8_C(0x6f), UINT8_C(0x08) };
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        code, sizeof(code), CDISASM_CPU_CELERON_G1840, &decoded_size);

    EXPECT(decoded_size == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION
        || instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
}

int main(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t xmm_load[] =
        { UINT8_C(0x62), UINT8_C(0xf1), UINT8_C(0x7d), UINT8_C(0x08),
          UINT8_C(0x6f), UINT8_C(0x08) };
    static const uint8_t xmm_store[] =
        { UINT8_C(0x62), UINT8_C(0xf1), UINT8_C(0x7d), UINT8_C(0x09),
          UINT8_C(0x7f), UINT8_C(0x08) };
    static const uint8_t xmm_reg[] =
        { UINT8_C(0x62), UINT8_C(0xf1), UINT8_C(0x7d), UINT8_C(0x08),
          UINT8_C(0x6f), UINT8_C(0xca) };
    static const uint8_t ymm_load[] =
        { UINT8_C(0x62), UINT8_C(0xf1), UINT8_C(0x7d), UINT8_C(0x28),
          UINT8_C(0x6f), UINT8_C(0x08) };
    static const uint8_t ymm_store[] =
        { UINT8_C(0x62), UINT8_C(0xf1), UINT8_C(0x7d), UINT8_C(0x29),
          UINT8_C(0x7f), UINT8_C(0x08) };
    static const uint8_t ymm_reg[] =
        { UINT8_C(0x62), UINT8_C(0xf1), UINT8_C(0x7d), UINT8_C(0x28),
          UINT8_C(0x6f), UINT8_C(0xca) };
    static const uint8_t zmm_load[] =
        { UINT8_C(0x62), UINT8_C(0xf1), UINT8_C(0x7d), UINT8_C(0x48),
          UINT8_C(0x6f), UINT8_C(0x08) };
    static const uint8_t zmm_store[] =
        { UINT8_C(0x62), UINT8_C(0xf1), UINT8_C(0x7d), UINT8_C(0x49),
          UINT8_C(0x7f), UINT8_C(0x08) };
    static const uint8_t zmm_reg[] =
        { UINT8_C(0x62), UINT8_C(0xf1), UINT8_C(0x7d), UINT8_C(0x48),
          UINT8_C(0x6f), UINT8_C(0xca) };
    static const vmovdqa32_case cases[] = {
        { "xmm load", xmm_load, sizeof(xmm_load), CDISASM_X86_REG_XMM1,
            16u, 1, 0, 0 },
        { "xmm store", xmm_store, sizeof(xmm_store), CDISASM_X86_REG_XMM1,
            16u, 0, 1, 1 },
        { "xmm register", xmm_reg, sizeof(xmm_reg), CDISASM_X86_REG_XMM1,
            16u, 0, 0, 0 },
        { "ymm load", ymm_load, sizeof(ymm_load), CDISASM_X86_REG_YMM1,
            32u, 1, 0, 0 },
        { "ymm store", ymm_store, sizeof(ymm_store), CDISASM_X86_REG_YMM1,
            32u, 0, 1, 1 },
        { "ymm register", ymm_reg, sizeof(ymm_reg), CDISASM_X86_REG_YMM1,
            32u, 0, 0, 0 },
        { "zmm load", zmm_load, sizeof(zmm_load), CDISASM_X86_REG_ZMM1,
            64u, 1, 0, 0 },
        { "zmm store", zmm_store, sizeof(zmm_store), CDISASM_X86_REG_ZMM1,
            64u, 0, 1, 1 },
        { "zmm register", zmm_reg, sizeof(zmm_reg), CDISASM_X86_REG_ZMM1,
            64u, 0, 0, 0 }
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        check_case(&cases[index]);
    }
    test_profile_gate();
#else
    puts("x86 VMOVDQA32 tests skipped (USE_EXTRA_OPCODES=0)");
#endif
    if (failures != 0) {
        fprintf(stderr, "%d x86 VMOVDQA32 test(s) failed\n", failures);
        return 1;
    }
    puts("x86 VMOVDQA32 tests passed");
    return 0;
}
