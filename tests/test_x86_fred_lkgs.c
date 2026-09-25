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

_Static_assert(CDISASM_X86_NAME_ERETS == UINT16_C(1316),
    "ERETS name ID changed");
_Static_assert(CDISASM_X86_NAME_ERETU == UINT16_C(1317),
    "ERETU name ID changed");
_Static_assert(CDISASM_X86_NAME_LKGS == UINT16_C(1336),
    "LKGS name ID changed");
_Static_assert(CDISASM_X86_GROUP_FRED == UINT16_C(269),
    "FRED group ID changed");
_Static_assert(CDISASM_X86_GROUP_LKGS == UINT16_C(280),
    "LKGS group ID changed");
_Static_assert(CDISASM_X86_DECODE_BIT_FRED == UINT32_C(216),
    "FRED decode bit changed");
_Static_assert(CDISASM_X86_DECODE_BIT_LKGS == UINT32_C(227),
    "LKGS decode bit changed");

static cdisasm_x86_decode_flags one_bit(cdisasm_x86_decode_bit_id bit)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_decode_flags_set_bit(&flags, bit));
    return flags;
}

static cdisasm_instruction decode(
    cdisasm_x86_cpu_id cpu_id,
    const uint8_t *code,
    size_t size,
    const cdisasm_x86_decode_flags *flags,
    uint32_t *decoded_size)
{
    cdisasm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    *decoded_size = cdisasm_x86_decode(
        cpu_id, CDISASM_MODE_64, code, size, UINT64_C(0x1000),
        flags, &instruction);
    return instruction;
}

static void check_lkgs(
    const char *label,
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    uint16_t form_id,
    cdisasm_operand_type operand_type,
    cdisasm_x86_reg_id register_id)
{
    if (decoded_size != 4u
        || instruction->last_error_id != CDISASM_STATUS_OK) {
        fprintf(stderr, "%s: got size/status %u/%u, expected 4/0\n",
            label, (unsigned int)decoded_size,
            (unsigned int)instruction->last_error_id);
    }
    EXPECT(decoded_size == 4u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == CDISASM_X86_NAME_LKGS);
    EXPECT(instruction->form_id == form_id);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_LKGS));
    EXPECT((instruction->opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0u);
    EXPECT((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u);
    EXPECT(instruction->operand_count == 1u);
    EXPECT(instruction->opcode[0].type == operand_type);
    if (operand_type == CDISASM_OPERAND_REGISTER) {
        EXPECT(instruction->opcode[0].reg == register_id);
        EXPECT(instruction->opcode[0].size == 2u);
    } else {
        EXPECT(instruction->opcode[0].size == 2u);
        EXPECT(instruction->opcode[0].base_reg == CDISASM_X86_REG_RAX);
        EXPECT((instruction->opcode[0].flags
            & CDISASM_OPERAND_FLAG_HAS_ADDRESS) == 0u);
    }
    EXPECT(instruction->encoding.prefix_size == 1u);
    EXPECT(instruction->encoding.opcode_offset == 1u);
    EXPECT(instruction->encoding.opcode_size == 2u);
    EXPECT(instruction->encoding.modrm_offset == 3u);
    EXPECT(instruction->encoding.modrm == UINT8_C(0xf0)
        || instruction->encoding.modrm == UINT8_C(0x30));
    EXPECT(instruction->encoding.immediate_count == 0u);
}

static void test_lkgs_operands_and_gate(void)
{
    static const uint8_t reg_code[] = {0xf2, 0x0f, 0x00, 0xf0};
    static const uint8_t mem_code[] = {0xf2, 0x0f, 0x00, 0x30};
    cdisasm_x86_decode_flags flags = one_bit(
        CDISASM_X86_DECODE_BIT_LKGS);
    cdisasm_x86_decode_flags none =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    uint32_t decoded_size;
    cdisasm_instruction instruction;
    cdisasm_x86_decode_flags available;

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_X86, CDISASM_MODE_64, &available)
        == CDISASM_STATUS_OK);
    EXPECT(cdisasm_decode_flags_test_bit(
        &available, CDISASM_X86_DECODE_BIT_LKGS));
    EXPECT(cdisasm_decode_flags_test_bit(
        &available, CDISASM_X86_DECODE_BIT_FRED));
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_X86, CDISASM_MODE_32, &available)
        == CDISASM_STATUS_OK);
    EXPECT(!cdisasm_decode_flags_test_bit(
        &available, CDISASM_X86_DECODE_BIT_LKGS));
    EXPECT(!cdisasm_decode_flags_test_bit(
        &available, CDISASM_X86_DECODE_BIT_FRED));

    instruction = decode(CDISASM_CPU_X86, reg_code, sizeof(reg_code),
        &flags, &decoded_size);
    check_lkgs("LKGS register", &instruction, decoded_size,
        UINT16_C(1589), CDISASM_OPERAND_REGISTER, CDISASM_X86_REG_AX);

    instruction = decode(CDISASM_CPU_X86, mem_code, sizeof(mem_code),
        &flags, &decoded_size);
    check_lkgs("LKGS memory", &instruction, decoded_size,
        UINT16_C(1590), CDISASM_OPERAND_MEMORY, CDISASM_X86_REG_NONE);

    /* The exact family selector is mandatory even when the structural
     * decoder recognizes the bytes. */
    instruction = decode(CDISASM_CPU_X86, reg_code, sizeof(reg_code),
        &none, &decoded_size);
    EXPECT(decoded_size == 0u);
    EXPECT(instruction.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    /* LKGS is long-mode only in the pinned catalog. */
    memset(&instruction, 0xa5, sizeof(instruction));
    decoded_size = cdisasm_x86_decode(
        CDISASM_CPU_X86, CDISASM_MODE_32, reg_code, sizeof(reg_code),
        UINT64_C(0x1000), &flags, &instruction);
    EXPECT(decoded_size == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
}

static void test_fred_state_boundary(void)
{
    static const uint8_t erets[] = {0xf2, 0x0f, 0x01, 0xca};
    static const uint8_t eretu[] = {0xf3, 0x0f, 0x01, 0xca};
    cdisasm_x86_decode_flags flags = one_bit(
        CDISASM_X86_DECODE_BIT_FRED);
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    instruction = decode(CDISASM_CPU_X86, erets, sizeof(erets),
        &flags, &decoded_size);
    EXPECT(decoded_size == sizeof(erets));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_ERETS);
    EXPECT(instruction.form_id == UINT16_C(1147));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_FRED));
    EXPECT(instruction.operand_count == 0u);

#if USE_DISASM_FORMAT
    {
        char text[16];
        EXPECT(cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            text, sizeof(text)) == 5u);
        EXPECT(strcmp(text, "erets") == 0);
    }
#endif
    EXPECT((instruction.opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u);
    EXPECT((instruction.opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE) == 0u);

    instruction = decode(CDISASM_CPU_X86, eretu, sizeof(eretu),
        &flags, &decoded_size);
    EXPECT(decoded_size == sizeof(eretu));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_ERETU);
    EXPECT(instruction.form_id == UINT16_C(1148));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_FRED));
    EXPECT(instruction.operand_count == 0u);

    /* ERETS/ERETU are intentionally owned by the FRED profile and never
     * alias the no-prefix SMAP CLAC/STAC row. */
    instruction = decode(CDISASM_CPU_APX, erets, sizeof(erets),
        &flags, &decoded_size);
    EXPECT(decoded_size == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
}

static void test_apxlegacy_stack_forms(void)
{
    static const uint8_t popp[] = {0xd5, 0x08, 0x58};
    static const uint8_t pushp[] = {0xd5, 0x08, 0x50};
    cdisasm_x86_decode_flags flags = one_bit(
        CDISASM_X86_DECODE_BIT_APX);
    cdisasm_x86_decode_flags none =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    cdisasm_instruction instruction;
    uint32_t decoded_size;

    instruction = decode(CDISASM_CPU_X86, popp, sizeof(popp),
        &flags, &decoded_size);
    EXPECT(decoded_size == 3u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_POPP);
    EXPECT(instruction.form_id == UINT16_C(2295));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F));
    EXPECT(instruction.operand_count == 1u);
    EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_RAX);
    EXPECT(instruction.opcode[0].size == 8u);
    EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
#if USE_DISASM_FORMAT
    {
        char intel[32];
        char att[32];
        EXPECT(cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            intel, sizeof(intel)) == 8u);
        EXPECT(strcmp(intel, "popp rax") == 0);
        EXPECT(cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ATT,
            att, sizeof(att)) == 9u);
        EXPECT(strcmp(att, "popp %rax") == 0);
    }
#endif

    instruction = decode(CDISASM_CPU_X86, pushp, sizeof(pushp),
        &flags, &decoded_size);
    EXPECT(decoded_size == 3u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_PUSHP);
    EXPECT(instruction.form_id == UINT16_C(2475));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F));
    EXPECT(instruction.operand_count == 1u);
    EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_RAX);
    EXPECT(instruction.opcode[0].size == 8u);
    EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
#if USE_DISASM_FORMAT
    {
        char intel[32];
        char att[32];
        EXPECT(cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            intel, sizeof(intel)) == 9u);
        EXPECT(strcmp(intel, "pushp rax") == 0);
        EXPECT(cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ATT,
            att, sizeof(att)) == 10u);
        EXPECT(strcmp(att, "pushp %rax") == 0);
    }
#endif

    instruction = decode(CDISASM_CPU_X86, popp, sizeof(popp),
        &none, &decoded_size);
    EXPECT(decoded_size == 0u);
    EXPECT(instruction.last_error_id
        == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
}

int main(void)
{
#if USE_EXTRA_OPCODES
    test_lkgs_operands_and_gate();
    test_fred_state_boundary();
    test_apxlegacy_stack_forms();
#else
    puts("x86 FRED/LKGS tests skipped (USE_EXTRA_OPCODES=0)");
#endif
    if (failures != 0) {
        fprintf(stderr, "%d x86 FRED/LKGS test(s) failed\n", failures);
        return 1;
    }
    puts("x86 FRED/LKGS tests passed");
    return 0;
}
