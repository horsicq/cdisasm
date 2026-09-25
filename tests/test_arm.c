#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm_arm.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#ifndef CDISASM_ARM_NAME_NOP
#  error "ARM name IDs must be preprocessor definitions"
#endif
#ifndef CDISASM_ARM_REG_X30
#  error "ARM register IDs must be preprocessor definitions"
#endif
#if CDISASM_ARM_NAME_NONE != 0 || CDISASM_ARM_NAME_NOP != 36 \
    || CDISASM_ARM_NAME_TST != 59 || CDISASM_ARM_NAME_STRT != 63 \
    || CDISASM_ARM_NAME_VADD != 64 || CDISASM_ARM_NAME_VBIC != 75 \
    || CDISASM_ARM_NAME_AT_AS1ELX != 76 \
    || CDISASM_ARM_NAME_WKDMD != 109 \
    || CDISASM_ARM_NAME_LDARB != 110 \
    || CDISASM_ARM_NAME_STLXP != 131 \
    || CDISASM_ARM_NAME_CASB != 132 \
    || CDISASM_ARM_NAME_LDAPR != 216 \
    || CDISASM_ARM_NAME_COUNT < 217 \
    || CDISASM_ARM_NAME_COUNT != CDISASM_ARM_NAME_LAST + 1
#  error "append-only ARM name ID catalog changed"
#endif
#if CDISASM_ARM_REG_NONE != 0 || CDISASM_ARM_REG_R0 != 1 \
    || CDISASM_ARM_REG_R15 != 16 || CDISASM_ARM_REG_W0 != 17 \
    || CDISASM_ARM_REG_WZR != 49 || CDISASM_ARM_REG_X0 != 50 \
    || CDISASM_ARM_REG_X30 != 80 || CDISASM_ARM_REG_SP != 81 \
    || CDISASM_ARM_REG_XZR != 82 || CDISASM_ARM_REG_D0 != 83 \
    || CDISASM_ARM_REG_D31 != 114 || CDISASM_ARM_REG_Q0 != 115 \
    || CDISASM_ARM_REG_Q15 != 130 || CDISASM_ARM_REG_V0 != 131 \
    || CDISASM_ARM_REG_V31 != 162 \
    || CDISASM_ARM_REG_CPM_IOACC_CTL_EL3 != 163 \
    || CDISASM_ARM_REG_COUNT < 164 \
    || CDISASM_ARM_REG_COUNT != CDISASM_ARM_REG_LAST + 1
#  error "append-only ARM register ID catalog changed"
#endif

static int failures = 0;

#define EXPECT(condition) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "%s:%d: expectation failed: %s\n", \
                __FILE__, __LINE__, #condition); \
            ++failures; \
        } \
    } while (0)

static void word_bytes(uint32_t word, uint8_t code[4])
{
    code[0] = (uint8_t)word;
    code[1] = (uint8_t)(word >> 8);
    code[2] = (uint8_t)(word >> 16);
    code[3] = (uint8_t)(word >> 24);
}

static void word_bytes_be(uint32_t word, uint8_t code[4])
{
    code[0] = (uint8_t)(word >> 24);
    code[1] = (uint8_t)(word >> 16);
    code[2] = (uint8_t)(word >> 8);
    code[3] = (uint8_t)word;
}

static uint32_t decode_word(
    cdisasm_arm_cpu_id cpu,
    cdisasm_arm_mode mode,
    uint32_t word,
    uint64_t address,
    cdisasm_arm_instruction *instruction)
{
    uint8_t code[4];
    word_bytes(word, code);
    memset(instruction, 0xa5, sizeof(*instruction));
    return cdisasm_arm_decode(
        cpu,
        mode,
        code,
        sizeof(code),
        address,
        CDISASM_ARM_DECODE_OPTION_NONE,
        instruction);
}

static int is_error_only(
    const cdisasm_arm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_arm_instruction expected;
    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static void expect_error(
    cdisasm_arm_cpu_id cpu,
    cdisasm_arm_mode mode,
    uint32_t word,
    cdisasm_status status)
{
    cdisasm_arm_instruction instruction;
    uint32_t decoded_size = decode_word(
        cpu, mode, word, UINT64_C(0x1000), &instruction);
    if (decoded_size != 0 || !is_error_only(&instruction, status)) {
        fprintf(stderr,
            "ARM word 0x%08x: expected %s with error-only output, "
            "got return=%u error=%s name=%u form=%u flags=0x%x\n",
            (unsigned int)word,
            cdisasm_status_string(status),
            (unsigned int)decoded_size,
            cdisasm_status_string(
                (cdisasm_status)instruction.last_error_id),
            (unsigned int)instruction.name_id,
            (unsigned int)instruction.form_id,
            (unsigned int)instruction.instruction_flags);
        ++failures;
    }
}

static void expect_base(
    const cdisasm_arm_instruction *instruction,
    uint64_t address,
    uint32_t raw,
    cdisasm_arm_isa_id isa,
    cdisasm_arm_condition condition,
    cdisasm_arm_name_id name)
{
    EXPECT(instruction->address == address);
    EXPECT(instruction->opcode_size == 4);
    EXPECT(instruction->raw_instruction == raw);
    EXPECT(instruction->isa_id == isa);
    EXPECT(instruction->condition == condition);
    EXPECT(instruction->name_id == name);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
}

static void expect_register(
    const cdisasm_arm_operand *operand,
    cdisasm_arm_reg_id reg,
    uint8_t size,
    cdisasm_operand_access access)
{
    EXPECT(operand->type == CDISASM_OPERAND_REGISTER);
    EXPECT(operand->reg == reg);
    EXPECT(operand->size == size);
    EXPECT(operand->access == access);
}

#if USE_EXTRA_OPCODES
static void expect_register_pair(
    const cdisasm_arm_operand *operand,
    cdisasm_arm_reg_id first_reg,
    cdisasm_arm_reg_id second_reg,
    uint8_t size,
    cdisasm_operand_access access)
{
    EXPECT(operand->type == CDISASM_ARM_OPERAND_REGISTER_PAIR);
    EXPECT(operand->reg == first_reg);
    EXPECT(operand->index_reg == second_reg);
    EXPECT(operand->size == size);
    EXPECT(operand->access == access);
}
#endif

static void expect_immediate(
    const cdisasm_arm_operand *operand,
    uint64_t value,
    uint8_t size)
{
    EXPECT(operand->type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(operand->imm == value);
    EXPECT(operand->size == size);
    EXPECT(operand->access == CDISASM_OPERAND_ACCESS_READ);
}

static void expect_vector_register(
    const cdisasm_arm_operand *operand,
    cdisasm_arm_reg_id reg,
    uint8_t total_size,
    uint8_t element_size,
    uint8_t element_count,
    cdisasm_operand_access access)
{
    EXPECT(operand->type == CDISASM_OPERAND_REGISTER);
    EXPECT(operand->reg == reg);
    EXPECT(operand->size == total_size);
    EXPECT(CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand) == element_size);
    EXPECT(CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand) == element_count);
    EXPECT(operand->access == access);
}

static void test_abi_and_ids(void)
{
    cdisasm_arm_cpu_id apple_cpu_with_side_effect =
        CDISASM_ARM_CPU_APPLE_S4;

    EXPECT(CDISASM_ARM_MAX_INSTRUCTION_SIZE == 4);
    EXPECT(CDISASM_ARM_MAX_OPERANDS == 4);
    EXPECT(CDISASM_ARM_OPERAND_REGISTER_PAIR == 5);
    EXPECT(sizeof(cdisasm_arm_operand) == CDISASM_ARM_OPERAND_SIZE);
    EXPECT(sizeof(cdisasm_arm_operand) == 32);
    EXPECT(offsetof(cdisasm_arm_instruction, address) == 0);
    EXPECT(offsetof(cdisasm_arm_instruction, branch_target) == 8);
    EXPECT(offsetof(cdisasm_arm_instruction, raw_instruction) == 24);
    EXPECT(offsetof(cdisasm_arm_instruction, name_id) == 32);
    EXPECT(offsetof(cdisasm_arm_instruction, operand) == 40);
    EXPECT(sizeof(cdisasm_arm_instruction) == CDISASM_ARM_INSTRUCTION_SIZE);
    EXPECT(sizeof(cdisasm_arm_instruction) == 168);
    EXPECT(CDISASM_ARM_MODE_32 == CDISASM_ARM_MODE_A32);
    EXPECT(CDISASM_ARM_MODE_64 == CDISASM_ARM_MODE_A64);
    EXPECT(CDISASM_ARM_REG_SP_A32 == CDISASM_ARM_REG_R13);
    EXPECT(CDISASM_ARM_REG_LR == CDISASM_ARM_REG_R14);
    EXPECT(CDISASM_ARM_REG_PC == CDISASM_ARM_REG_R15);
    EXPECT(CDISASM_ARM_REG_FP_X == CDISASM_ARM_REG_X29);
    EXPECT(CDISASM_ARM_REG_LR_X == CDISASM_ARM_REG_X30);
    EXPECT(CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL == (UINT32_C(1) << 8));
    EXPECT(CDISASM_ARM_INSTRUCTION_FLAG_UNPREDICTABLE
        == (UINT32_C(1) << 9));
    EXPECT(CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT
        == (UINT32_C(1) << 10));
    EXPECT(CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT
        == (UINT32_C(1) << 11));
    EXPECT(CDISASM_ARM_INSTRUCTION_FLAG_SIMD == (UINT32_C(1) << 12));
    EXPECT(CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
        == (UINT32_C(1) << 13));
    EXPECT(CDISASM_ARM_INSTRUCTION_FLAG_APPLE_PROPRIETARY
        == (UINT32_C(1) << 14));
    EXPECT(CDISASM_ARM_INSTRUCTION_FLAG_APPLE_AMX
        == (UINT32_C(1) << 15));
    EXPECT(CDISASM_ARM_INSTRUCTION_FLAG_APPLE_MUL53
        == (UINT32_C(1) << 16));
    EXPECT(CDISASM_ARM_INSTRUCTION_FLAG_APPLE_SYSTEM
        == (UINT32_C(1) << 17));
    EXPECT(CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
        == (UINT32_C(1) << 18));
    EXPECT(CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
        == (UINT32_C(1) << 19));
    EXPECT(CDISASM_ARM_INSTRUCTION_FLAG_RELEASE
        == (UINT32_C(1) << 20));
    EXPECT(CDISASM_ARM_INSTRUCTION_FLAG_EXCLUSIVE
        == (UINT32_C(1) << 21));
    EXPECT(CDISASM_ARM_CPU_APPLE_A8X == CDISASM_ARM_CPU_APPLE_A8);
    EXPECT(CDISASM_ARM_CPU_APPLE_A12Z == CDISASM_ARM_CPU_APPLE_A12);
    EXPECT(CDISASM_ARM_CPU_APPLE_A19_PRO == CDISASM_ARM_CPU_APPLE_A19);
    EXPECT(CDISASM_ARM_CPU_APPLE_M5_ULTRA == CDISASM_ARM_CPU_APPLE_M5);
    EXPECT(CDISASM_ARM_CPU_ANY
        == (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0000)));
    EXPECT(CDISASM_ARM_CPU_ARM7TDMI
        == (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0001)));
    EXPECT(CDISASM_ARM_CPU_CORTEX_A7_NEON
        == (CDISASM_CPU_GROUP_ARM | UINT32_C(0x001e)));
    EXPECT(CDISASM_ARM_CPU_APPLE_S4
        == (CDISASM_CPU_GROUP_ARM | UINT32_C(0x001f)));
    EXPECT(CDISASM_ARM_CPU_APPLE_S10
        == (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0025)));
    EXPECT(CDISASM_ARM_CPU_FUJITSU_A64FX
        == (CDISASM_CPU_GROUP_ARM | UINT32_C(0x0026)));
    EXPECT(CDISASM_ARM_CPU_A64FX == CDISASM_ARM_CPU_FUJITSU_A64FX);
    EXPECT(CDISASM_ARM_CPU_LAST == CDISASM_ARM_CPU_FUJITSU_A64FX);
    EXPECT(CDISASM_CPU_GROUP_OF(CDISASM_ARM_CPU_APPLE_S10)
        == CDISASM_CPU_GROUP_ARM);
    EXPECT(CDISASM_CPU_ORDINAL_OF(CDISASM_ARM_CPU_APPLE_S10)
        == UINT32_C(0x0025));
    EXPECT(CDISASM_CPU_GROUP_OF(CDISASM_ARM_CPU_FUJITSU_A64FX)
        == CDISASM_CPU_GROUP_ARM);
    EXPECT(CDISASM_CPU_ORDINAL_OF(CDISASM_ARM_CPU_FUJITSU_A64FX)
        == UINT32_C(0x0026));
    EXPECT(CDISASM_ARM_CPU_APPLE_FIRST == CDISASM_ARM_CPU_APPLE_A4);
    EXPECT(CDISASM_ARM_CPU_APPLE_LAST == CDISASM_ARM_CPU_APPLE_S10);
    EXPECT(CDISASM_ARM_CPU_IS_APPLE(CDISASM_ARM_CPU_APPLE_A4));
    EXPECT(CDISASM_ARM_CPU_IS_APPLE(CDISASM_ARM_CPU_APPLE_M5));
    EXPECT(!CDISASM_ARM_CPU_IS_APPLE(CDISASM_ARM_CPU_CORTEX_A7_NEON));
    EXPECT(CDISASM_ARM_CPU_IS_APPLE(CDISASM_ARM_CPU_APPLE_S4));
    EXPECT(CDISASM_ARM_CPU_IS_APPLE(CDISASM_ARM_CPU_APPLE_S10));
    EXPECT(!CDISASM_ARM_CPU_IS_APPLE(CDISASM_ARM_CPU_FUJITSU_A64FX));
    EXPECT(CDISASM_ARM_CPU_IS_APPLE(apple_cpu_with_side_effect++));
    EXPECT(apple_cpu_with_side_effect == CDISASM_ARM_CPU_APPLE_S5);
}

static void test_cpu_mode_matrix(void)
{
    const cdisasm_arm_mode_mask states32 =
        CDISASM_ARM_MODE_MASK_A32 | CDISASM_ARM_MODE_MASK_T32;
    const cdisasm_arm_mode_mask all_states =
        states32 | CDISASM_ARM_MODE_MASK_A64;
    const cdisasm_arm_mode_mask implemented_states = all_states;
    cdisasm_arm_cpu_id cpu_id;

    EXPECT(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_ANY) == all_states);
    EXPECT(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_ARM7TDMI)
        == states32);
    EXPECT(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_CORTEX_A7)
        == states32);
    EXPECT(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_CORTEX_A9)
        == states32);
    EXPECT(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_CORTEX_A32)
        == states32);
    EXPECT(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_CORTEX_A34)
        == CDISASM_ARM_MODE_MASK_A64);
    EXPECT(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_CORTEX_A35)
        == all_states);
    EXPECT(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_CORTEX_A53)
        == all_states);
    EXPECT(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_CORTEX_A9_NEON)
        == states32);
    EXPECT(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_CORTEX_A7_NEON)
        == states32);
    EXPECT(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_APPLE_A4)
        == states32);
    EXPECT(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_APPLE_A7)
        == all_states);
    EXPECT(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_APPLE_A10)
        == all_states);
    EXPECT(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_APPLE_A11)
        == CDISASM_ARM_MODE_MASK_A64);
    EXPECT(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_APPLE_A19)
        == CDISASM_ARM_MODE_MASK_A64);
    EXPECT(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_APPLE_M1)
        == CDISASM_ARM_MODE_MASK_A64);
    EXPECT(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_APPLE_M5)
        == CDISASM_ARM_MODE_MASK_A64);
    EXPECT(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_APPLE_S4)
        == CDISASM_ARM_MODE_MASK_A64);
    EXPECT(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_APPLE_S10)
        == CDISASM_ARM_MODE_MASK_A64);
    EXPECT(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_FUJITSU_A64FX)
        == CDISASM_ARM_MODE_MASK_A64);
    for (cpu_id = CDISASM_ARM_CPU_APPLE_A4;
         cpu_id <= CDISASM_ARM_CPU_APPLE_A6;
         ++cpu_id) {
        EXPECT(cdisasm_arm_cpu_mode_mask(cpu_id) == states32);
    }
    for (cpu_id = CDISASM_ARM_CPU_APPLE_A7;
         cpu_id <= CDISASM_ARM_CPU_APPLE_A10;
         ++cpu_id) {
        EXPECT(cdisasm_arm_cpu_mode_mask(cpu_id) == all_states);
    }
    for (cpu_id = CDISASM_ARM_CPU_APPLE_A11;
         cpu_id <= CDISASM_ARM_CPU_APPLE_M5;
         ++cpu_id) {
        EXPECT(cdisasm_arm_cpu_mode_mask(cpu_id)
            == CDISASM_ARM_MODE_MASK_A64);
    }
    for (cpu_id = CDISASM_ARM_CPU_APPLE_S4;
         cpu_id <= CDISASM_ARM_CPU_APPLE_S10;
         ++cpu_id) {
        EXPECT(cdisasm_arm_cpu_mode_mask(cpu_id)
            == CDISASM_ARM_MODE_MASK_A64);
    }
    EXPECT(cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_LAST + 1)
        == CDISASM_ARM_MODE_MASK_NONE);
    EXPECT(cdisasm_arm_cpu_mode_mask(UINT32_C(0))
        == CDISASM_ARM_MODE_MASK_NONE);
    EXPECT(cdisasm_arm_cpu_mode_mask(UINT32_C(1))
        == CDISASM_ARM_MODE_MASK_NONE);
    EXPECT(cdisasm_arm_cpu_mode_mask(
               CDISASM_CPU_GROUP_X86 | UINT32_C(0x0001))
        == CDISASM_ARM_MODE_MASK_NONE);
    EXPECT(cdisasm_arm_cpu_mode_mask(UINT32_MAX)
        == CDISASM_ARM_MODE_MASK_NONE);

    EXPECT(cdisasm_arm_decoder_mode_mask(CDISASM_ARM_CPU_ANY)
        == implemented_states);
    EXPECT(cdisasm_arm_decoder_mode_mask(CDISASM_ARM_CPU_ARM7TDMI)
        == states32);
    EXPECT(cdisasm_arm_decoder_mode_mask(CDISASM_ARM_CPU_CORTEX_A7)
        == states32);
    EXPECT(cdisasm_arm_decoder_mode_mask(CDISASM_ARM_CPU_CORTEX_A9)
        == states32);
    EXPECT(cdisasm_arm_decoder_mode_mask(CDISASM_ARM_CPU_CORTEX_A32)
        == states32);
    EXPECT(cdisasm_arm_decoder_mode_mask(CDISASM_ARM_CPU_CORTEX_A34)
        == CDISASM_ARM_MODE_MASK_A64);
    EXPECT(cdisasm_arm_decoder_mode_mask(CDISASM_ARM_CPU_CORTEX_A35)
        == implemented_states);
    EXPECT(cdisasm_arm_decoder_mode_mask(CDISASM_ARM_CPU_CORTEX_A53)
        == implemented_states);
    EXPECT(cdisasm_arm_decoder_mode_mask(CDISASM_ARM_CPU_CORTEX_A7_NEON)
        == states32);
    EXPECT(cdisasm_arm_decoder_mode_mask(CDISASM_ARM_CPU_APPLE_A7)
        == implemented_states);
    EXPECT(cdisasm_arm_decoder_mode_mask(CDISASM_ARM_CPU_APPLE_A11)
        == CDISASM_ARM_MODE_MASK_A64);
    EXPECT(cdisasm_arm_decoder_mode_mask(CDISASM_ARM_CPU_APPLE_M5)
        == CDISASM_ARM_MODE_MASK_A64);
    EXPECT(cdisasm_arm_decoder_mode_mask(CDISASM_ARM_CPU_APPLE_S10)
        == CDISASM_ARM_MODE_MASK_A64);
    EXPECT(cdisasm_arm_decoder_mode_mask(CDISASM_ARM_CPU_FUJITSU_A64FX)
        == CDISASM_ARM_MODE_MASK_A64);
    EXPECT(cdisasm_arm_decoder_mode_mask(CDISASM_ARM_CPU_LAST + 1)
        == CDISASM_ARM_MODE_MASK_NONE);
    EXPECT(cdisasm_arm_decoder_mode_mask(UINT32_C(0))
        == CDISASM_ARM_MODE_MASK_NONE);
    EXPECT(cdisasm_arm_decoder_mode_mask(UINT32_C(1))
        == CDISASM_ARM_MODE_MASK_NONE);
    EXPECT(cdisasm_arm_decoder_mode_mask(
               CDISASM_CPU_GROUP_X86 | UINT32_C(0x0001))
        == CDISASM_ARM_MODE_MASK_NONE);
    EXPECT(cdisasm_arm_decoder_mode_mask(UINT32_MAX)
        == CDISASM_ARM_MODE_MASK_NONE);
}

static void test_argument_failures(void)
{
    static const uint8_t nop[4] = { 0x00, 0xf0, 0x20, 0xe3 };
    static const cdisasm_arm_decode_option invalid_options[] = {
        UINT64_C(0x80000000),
        UINT64_C(0x100000000),
        UINT64_C(0x8000000000000000)
    };
    cdisasm_arm_instruction instruction;
    size_t option_index;
    size_t size;

    expect_error(
        CDISASM_ARM_CPU_LAST + 1,
        CDISASM_ARM_MODE_A32,
        UINT32_C(0xe320f000),
        CDISASM_STATUS_INVALID_ARGUMENT);
    expect_error(
        UINT32_C(0),
        CDISASM_ARM_MODE_A32,
        UINT32_C(0xe320f000),
        CDISASM_STATUS_INVALID_ARGUMENT);
    expect_error(
        UINT32_C(1),
        CDISASM_ARM_MODE_A32,
        UINT32_C(0xe320f000),
        CDISASM_STATUS_INVALID_ARGUMENT);
    expect_error(
        CDISASM_CPU_GROUP_X86 | UINT32_C(0x0001),
        CDISASM_ARM_MODE_A32,
        UINT32_C(0xe320f000),
        CDISASM_STATUS_INVALID_ARGUMENT);
    expect_error(
        CDISASM_ARM_CPU_ANY,
        0,
        UINT32_C(0xe320f000),
        CDISASM_STATUS_INVALID_ARGUMENT);
    expect_error(
        CDISASM_ARM_CPU_ANY,
        4,
        UINT32_C(0xe320f000),
        CDISASM_STATUS_INVALID_ARGUMENT);
    expect_error(
        CDISASM_ARM_CPU_CORTEX_A34,
        CDISASM_ARM_MODE_A32,
        UINT32_C(0xe320f000),
        CDISASM_STATUS_INVALID_ARGUMENT);
    expect_error(
        CDISASM_ARM_CPU_CORTEX_A7,
        CDISASM_ARM_MODE_A64,
        UINT32_C(0xd503201f),
        CDISASM_STATUS_INVALID_ARGUMENT);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(cdisasm_arm_decode(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A32,
               nop,
               sizeof(nop),
               0,
               UINT32_C(2),
               &instruction)
        == 0);
    EXPECT(is_error_only(&instruction, CDISASM_STATUS_INVALID_ARGUMENT));

    for (option_index = 0;
         option_index < sizeof(invalid_options) / sizeof(invalid_options[0]);
         ++option_index) {
        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(cdisasm_arm_decode(
                   CDISASM_ARM_CPU_ANY,
                   CDISASM_ARM_MODE_A32,
                   nop,
                   sizeof(nop),
                   0,
                   invalid_options[option_index],
                   &instruction)
            == 0);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
    }

    EXPECT(cdisasm_arm_decode(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A32,
               nop,
               sizeof(nop),
               0,
               CDISASM_ARM_DECODE_OPTION_NONE,
               NULL)
        == 0);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(cdisasm_arm_decode(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A32,
               NULL,
               sizeof(nop),
               0,
               CDISASM_ARM_DECODE_OPTION_NONE,
               &instruction)
        == 0);
    EXPECT(is_error_only(&instruction, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(cdisasm_arm_decode(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A32,
               NULL,
               0,
               0,
               CDISASM_ARM_DECODE_OPTION_NONE,
               &instruction)
        == 0);
    EXPECT(is_error_only(&instruction, CDISASM_STATUS_END_OF_INPUT));

    for (size = 1; size < sizeof(nop); ++size) {
        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(cdisasm_arm_decode(
                   CDISASM_ARM_CPU_ANY,
                   CDISASM_ARM_MODE_A32,
                   nop,
                   size,
                   0,
                   CDISASM_ARM_DECODE_OPTION_NONE,
                   &instruction)
            == 0);
        EXPECT(is_error_only(&instruction, CDISASM_STATUS_TRUNCATED));
    }

    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_arm_decode(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_T32,
               nop,
               sizeof(nop),
               0,
               CDISASM_ARM_DECODE_OPTION_NONE,
               &instruction)
        == sizeof(nop));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_BLX);
    EXPECT(instruction.form_id == UINT16_C(1861));
    EXPECT((instruction.instruction_flags
               & CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK)
        == 0u);
#else
    EXPECT(cdisasm_arm_decode(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_T32,
               nop,
               sizeof(nop),
               0,
               CDISASM_ARM_DECODE_OPTION_NONE,
               &instruction)
        == 0);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_big_endian_input(void)
{
    static const uint8_t t32_le_16[] = { UINT8_C(0x70), UINT8_C(0x47) };
    static const uint8_t t32_be_16[] = { UINT8_C(0x47), UINT8_C(0x70) };
    static const uint8_t t32_le_32[] = {
        UINT8_C(0x00), UINT8_C(0xf0), UINT8_C(0x00), UINT8_C(0xf8)
    };
    static const uint8_t t32_be_32[] = {
        UINT8_C(0xf0), UINT8_C(0x00), UINT8_C(0xf8), UINT8_C(0x00)
    };
    static const struct {
        cdisasm_arm_cpu_id cpu;
        cdisasm_arm_mode mode;
        uint32_t word;
    } word_cases[] = {
        { CDISASM_ARM_CPU_CORTEX_A7, CDISASM_ARM_MODE_A32,
          UINT32_C(0xe2810005) },
        { CDISASM_ARM_CPU_CORTEX_A34, CDISASM_ARM_MODE_A64,
          UINT32_C(0x91001420) }
    };
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction big;
    uint8_t little_bytes[4];
    uint8_t big_bytes[4];
    size_t index;

    for (index = 0; index < sizeof(word_cases) / sizeof(word_cases[0]);
         ++index) {
        word_bytes(word_cases[index].word, little_bytes);
        word_bytes_be(word_cases[index].word, big_bytes);
        EXPECT(cdisasm_arm_decode(
                   word_cases[index].cpu,
                   word_cases[index].mode,
                   little_bytes,
                   sizeof(little_bytes),
                   UINT64_C(0x4000),
                   CDISASM_ARM_DECODE_OPTION_NONE,
                   &little)
            == 4);
        EXPECT(cdisasm_arm_decode(
                   word_cases[index].cpu,
                   word_cases[index].mode,
                   big_bytes,
                   sizeof(big_bytes),
                   UINT64_C(0x4000),
                   CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN,
                   &big)
            == 4);
        EXPECT(memcmp(&little, &big, sizeof(little)) == 0);
    }

    EXPECT(cdisasm_arm_decode(
               CDISASM_ARM_CPU_CORTEX_A7,
               CDISASM_ARM_MODE_T32,
               t32_le_16,
               sizeof(t32_le_16),
               UINT64_C(0x5000),
               CDISASM_ARM_DECODE_OPTION_NONE,
               &little)
        == 2);
    EXPECT(cdisasm_arm_decode(
               CDISASM_ARM_CPU_CORTEX_A7,
               CDISASM_ARM_MODE_T32,
               t32_be_16,
               sizeof(t32_be_16),
               UINT64_C(0x5000),
               CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN,
               &big)
        == 2);
    EXPECT(memcmp(&little, &big, sizeof(little)) == 0);

    EXPECT(cdisasm_arm_decode(
               CDISASM_ARM_CPU_CORTEX_A7,
               CDISASM_ARM_MODE_T32,
               t32_le_32,
               sizeof(t32_le_32),
               UINT64_C(0x6000),
               CDISASM_ARM_DECODE_OPTION_NONE,
               &little)
        == 4);
    EXPECT(cdisasm_arm_decode(
               CDISASM_ARM_CPU_CORTEX_A7,
               CDISASM_ARM_MODE_T32,
               t32_be_32,
               sizeof(t32_be_32),
               UINT64_C(0x6000),
               CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN,
               &big)
        == 4);
    EXPECT(memcmp(&little, &big, sizeof(little)) == 0);

    EXPECT(cdisasm_arm_decode(
               CDISASM_ARM_CPU_CORTEX_A7,
               CDISASM_ARM_MODE_T32,
               t32_be_32,
               3,
               UINT64_C(0),
               CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN,
               &big)
        == 0);
    EXPECT(is_error_only(&big, CDISASM_STATUS_TRUNCATED));
}

static void test_t32_it_context(void)
{
    static const uint8_t adds_r0_r0_0[] = {
        UINT8_C(0x00), UINT8_C(0x1c)
    };
    cdisasm_arm_decode_flags available =
        CDISASM_ARM_DECODE_FLAGS_NONE_INITIALIZER;
    cdisasm_arm_instruction outside;
    cdisasm_arm_instruction inside;

    EXPECT(cdisasm_arm_cpu_decode_flag_mask(
               CDISASM_ARM_CPU_CORTEX_A7,
               CDISASM_ARM_MODE_T32,
               &available)
        == CDISASM_STATUS_OK);
    EXPECT(available.bitmap[CDISASM_ARM_DECODE_FLAGS_OPTION_BITMAP]
        == (CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN
            | CDISASM_ARM_DECODE_OPTION_IN_IT_BLOCK));
    EXPECT(cdisasm_arm_decode(
               CDISASM_ARM_CPU_CORTEX_A7,
               CDISASM_ARM_MODE_T32,
               adds_r0_r0_0,
               sizeof(adds_r0_r0_0),
               UINT64_C(0x7000),
               CDISASM_ARM_DECODE_OPTION_NONE,
               &outside)
        == 2u);
    EXPECT(outside.name_id == CDISASM_ARM_NAME_ADDS);
    EXPECT((outside.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS) != 0u);
    EXPECT(cdisasm_arm_decode(
               CDISASM_ARM_CPU_CORTEX_A7,
               CDISASM_ARM_MODE_T32,
               adds_r0_r0_0,
               sizeof(adds_r0_r0_0),
               UINT64_C(0x7000),
               CDISASM_ARM_DECODE_OPTION_IN_IT_BLOCK,
               &inside)
        == 2u);
#if USE_EXTRA_OPCODES
    EXPECT(inside.name_id == CDISASM_ARM_NAME_ADD);
    EXPECT((inside.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS) == 0u);
#else
    EXPECT(inside.name_id == CDISASM_ARM_NAME_ADDS);
    EXPECT((inside.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS) != 0u);
#endif
    EXPECT(inside.operand_count == outside.operand_count);

    EXPECT(cdisasm_arm_decode(
               CDISASM_ARM_CPU_CORTEX_A7,
               CDISASM_ARM_MODE_A32,
               adds_r0_r0_0,
               sizeof(adds_r0_r0_0),
               UINT64_C(0),
               CDISASM_ARM_DECODE_OPTION_IN_IT_BLOCK,
               &inside)
        == 0u);
    EXPECT(is_error_only(&inside, CDISASM_STATUS_INVALID_ARGUMENT));
}

static void test_a32_capabilities_and_control(void)
{
    cdisasm_arm_instruction instruction;

    EXPECT(decode_word(
               CDISASM_ARM_CPU_CORTEX_A7,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xe320f000),
               UINT64_C(0x1000),
               &instruction)
        == 4);
    expect_base(
        &instruction,
        UINT64_C(0x1000),
        UINT32_C(0xe320f000),
        CDISASM_ARM_ISA_A32,
        CDISASM_ARM_CONDITION_AL,
        CDISASM_ARM_NAME_NOP);
    EXPECT(instruction.operand_count == 0);
    EXPECT(instruction.opcode_groups == CDISASM_GROUP_NONE);

    expect_error(
        CDISASM_ARM_CPU_ARM7TDMI,
        CDISASM_ARM_MODE_A32,
        UINT32_C(0xe320f000),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_ARM7TDMI,
        CDISASM_ARM_MODE_A32,
        UINT32_C(0xe12fff33),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_ARM7TDMI,
        CDISASM_ARM_MODE_A32,
        UINT32_C(0xe1212374),
        CDISASM_STATUS_INVALID_INSTRUCTION);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_CORTEX_A7,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xe12fff33),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_BLX);
    EXPECT(instruction.opcode_groups == CDISASM_GROUP_CALL);
    EXPECT((instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_LINK)
        != 0);
    EXPECT(instruction.operand_count == 1);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_R3,
        4,
        CDISASM_OPERAND_ACCESS_READ);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_CORTEX_A7,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xe1212374),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_BKPT);
    EXPECT(instruction.opcode_groups == CDISASM_GROUP_INTERRUPT);
    EXPECT(instruction.operand_count == 1);
    expect_immediate(&instruction.operand[0], UINT64_C(0x1234), 2);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ARM7TDMI,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xe12fff1e),
               UINT64_C(0x2000),
               &instruction)
        == 4);
    expect_base(
        &instruction,
        UINT64_C(0x2000),
        UINT32_C(0xe12fff1e),
        CDISASM_ARM_ISA_A32,
        CDISASM_ARM_CONDITION_AL,
        CDISASM_ARM_NAME_BX);
    EXPECT(instruction.opcode_groups
        == (CDISASM_GROUP_JUMP | CDISASM_GROUP_RETURN));
    EXPECT(instruction.operand_count == 1);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_LR,
        4,
        CDISASM_OPERAND_ACCESS_READ);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ARM7TDMI,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xea000000),
               UINT64_C(0x3000),
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_B);
    EXPECT(instruction.branch_target == UINT64_C(0x3008));
    EXPECT(instruction.opcode_groups
        == (CDISASM_GROUP_JUMP | CDISASM_GROUP_RELATIVE_BRANCH));
    EXPECT(instruction.operand_count == 1);
    expect_immediate(&instruction.operand[0], UINT64_C(0x3008), 8);
    EXPECT(instruction.operand[0].address == 0);
    EXPECT(instruction.operand[0].flags
        == (CDISASM_OPERAND_FLAG_SIGNED
            | CDISASM_OPERAND_FLAG_PC_RELATIVE
            | CDISASM_OPERAND_FLAG_HAS_ADDRESS));

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xebfffffe),
               UINT64_C(0x4000),
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_BL);
    EXPECT(instruction.branch_target == UINT64_C(0x4000));
    EXPECT(instruction.opcode_groups
        == (CDISASM_GROUP_CALL | CDISASM_GROUP_RELATIVE_BRANCH));
    EXPECT((instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_LINK)
        != 0);
    EXPECT(instruction.operand[0].address == (uint64_t)(int64_t)-8);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0x0a000001),
               UINT64_C(0x5000),
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_B);
    EXPECT(instruction.condition == CDISASM_ARM_CONDITION_EQ);
    EXPECT(instruction.branch_target == UINT64_C(0x500c));
    EXPECT(instruction.opcode_groups
        == (CDISASM_GROUP_JUMP | CDISASM_GROUP_RELATIVE_BRANCH
            | CDISASM_GROUP_CONDITIONAL));

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ARM7TDMI,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xef000123),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_SVC);
    EXPECT(instruction.opcode_groups == CDISASM_GROUP_INTERRUPT);
    EXPECT(instruction.operand_count == 1);
    expect_immediate(&instruction.operand[0], UINT64_C(0x123), 3);

    expect_error(
        CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A32,
        UINT32_C(0xffffffff),
#if USE_EXTRA_OPCODES
        CDISASM_STATUS_INVALID_INSTRUCTION);
#else
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_a32_data_processing(void)
{
    cdisasm_arm_instruction instruction;

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xe2810005),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_ADD);
    EXPECT(instruction.operand_count == 3);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_R0,
        4,
        CDISASM_OPERAND_ACCESS_WRITE);
    expect_register(
        &instruction.operand[1],
        CDISASM_ARM_REG_R1,
        4,
        CDISASM_OPERAND_ACCESS_READ);
    expect_immediate(&instruction.operand[2], 5, 4);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xe0432004),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_SUB);
    EXPECT(instruction.operand_count == 3);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_R2,
        4,
        CDISASM_OPERAND_ACCESS_WRITE);
    expect_register(
        &instruction.operand[1],
        CDISASM_ARM_REG_R3,
        4,
        CDISASM_OPERAND_ACCESS_READ);
    expect_register(
        &instruction.operand[2],
        CDISASM_ARM_REG_R4,
        4,
        CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.operand[2].shift_type == CDISASM_ARM_SHIFT_NONE);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xe3a05012),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_MOV);
    EXPECT(instruction.operand_count == 2);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_R5,
        4,
        CDISASM_OPERAND_ACCESS_WRITE);
    expect_immediate(&instruction.operand[1], UINT64_C(0x12), 4);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xe3560007),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_CMP);
    EXPECT(instruction.operand_count == 2);
    EXPECT((instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS)
        != 0);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_R6,
        4,
        CDISASM_OPERAND_ACCESS_READ);
    expect_immediate(&instruction.operand[1], 7, 4);

    /* MOV/MVN fix Rn to zero; test/compare forms fix Rd to zero. */
    expect_error(
        CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A32,
        UINT32_C(0xe3a10001),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A32,
        UINT32_C(0xe1b6ee49),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A32,
        UINT32_C(0xe1101002),
        CDISASM_STATUS_INVALID_INSTRUCTION);
}

static void test_a32_memory_and_stack(void)
{
    cdisasm_arm_instruction instruction;
    const cdisasm_arm_operand *memory;

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xe591000c),
               UINT64_C(0x1000),
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_LDR);
    EXPECT(instruction.operand_count == 2);
    EXPECT(instruction.instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_R0,
        4,
        CDISASM_OPERAND_ACCESS_WRITE);
    memory = &instruction.operand[1];
    EXPECT(memory->type == CDISASM_OPERAND_MEMORY);
    EXPECT(memory->base_reg == CDISASM_ARM_REG_R1);
    EXPECT(memory->imm == 12);
    EXPECT(memory->size == 4);
    EXPECT(memory->access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(memory->flags == CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xe5232008),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_STR);
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK));
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_R2,
        4,
        CDISASM_OPERAND_ACCESS_READ);
    memory = &instruction.operand[1];
    EXPECT(memory->base_reg == CDISASM_ARM_REG_R3);
    EXPECT(memory->imm == (uint64_t)(int64_t)-8);
    EXPECT(memory->access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(memory->flags
        == (CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
            | CDISASM_OPERAND_FLAG_SIGNED));

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xe59f000c),
               UINT64_C(0x2000),
               &instruction)
        == 4);
    memory = &instruction.operand[1];
    EXPECT(memory->base_reg == CDISASM_ARM_REG_PC);
    EXPECT(memory->address == UINT64_C(0x2014));
    EXPECT(memory->flags
        == (CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
            | CDISASM_OPERAND_FLAG_PC_RELATIVE
            | CDISASM_OPERAND_FLAG_HAS_ADDRESS));

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xe4b10004),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_LDRT);
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_UNPRIVILEGED));
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_R0,
        4,
        CDISASM_OPERAND_ACCESS_WRITE);
    memory = &instruction.operand[1];
    EXPECT(memory->base_reg == CDISASM_ARM_REG_R1);
    EXPECT(memory->imm == 4);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xe4676002),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_STRBT);
    EXPECT((instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_UNPRIVILEGED)
        != 0);
    EXPECT(instruction.operand[1].imm == (uint64_t)(int64_t)-2);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xe92d4030),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_PUSH);
    EXPECT(instruction.operand_count == 1);
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT));
    EXPECT(instruction.operand[0].type
        == CDISASM_ARM_OPERAND_REGISTER_LIST);
    EXPECT(instruction.operand[0].register_list == UINT16_C(0x4030));
    EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_READ);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xe8bd8030),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_POP);
    EXPECT(instruction.operand_count == 1);
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT));
    EXPECT(instruction.operand[0].type
        == CDISASM_ARM_OPERAND_REGISTER_LIST);
    EXPECT(instruction.operand[0].register_list == UINT16_C(0x8030));
    EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.opcode_groups
        == (CDISASM_GROUP_JUMP | CDISASM_GROUP_RETURN));

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xe8bd0000),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_LDM);
    EXPECT(instruction.operand[1].register_list == 0);
    EXPECT((instruction.instruction_flags
            & (CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL
                | CDISASM_ARM_INSTRUCTION_FLAG_UNPREDICTABLE))
        == (CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL
            | CDISASM_ARM_INSTRUCTION_FLAG_UNPREDICTABLE));
}

static void test_a32_block_transfer_metadata(void)
{
    static const struct direction_case {
        uint32_t word;
        cdisasm_arm_name_id expected_name;
        uint32_t expected_flags;
    } direction_cases[] = {
        { UINT32_C(0xe8000002), CDISASM_ARM_NAME_STMDA,
          CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
              | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT },
        { UINT32_C(0xe9000002), CDISASM_ARM_NAME_STM,
          CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
              | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT },
        { UINT32_C(0xe8800002), CDISASM_ARM_NAME_STM,
          CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
              | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT },
        { UINT32_C(0xe9800002), CDISASM_ARM_NAME_STMIB,
          CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
              | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT }
    };
    const uint32_t bad = CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL
        | CDISASM_ARM_INSTRUCTION_FLAG_UNPREDICTABLE;
    size_t index;
    cdisasm_arm_instruction instruction;

    for (index = 0; index < sizeof(direction_cases) / sizeof(direction_cases[0]);
         ++index) {
        EXPECT(decode_word(
                   CDISASM_ARM_CPU_ANY,
                   CDISASM_ARM_MODE_A32,
                   direction_cases[index].word,
                   0,
                   &instruction)
            == 4);
        EXPECT(instruction.name_id == direction_cases[index].expected_name);
        EXPECT(instruction.instruction_flags
            == direction_cases[index].expected_flags);
    }

    /* LDM writeback to a base in its destination list is constrained
     * unpredictable, but retaining the decoded operands aids analysis. */
    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xe8b00001),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_LDM);
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT
            | bad));
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_R0);
    EXPECT(instruction.operand[1].register_list == UINT16_C(1));

    /* The analogous STM has defined behavior when the base is the first
     * transferred register and must not receive a false warning. */
    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xe8a00001),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_STM);
    EXPECT((instruction.instruction_flags & bad) == 0);

    /* R15 cannot be the block-transfer base register. */
    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xe88f0001),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_STM);
    EXPECT((instruction.instruction_flags & bad) == bad);

    /* Base/list overlap is permitted when LDM does not write back. */
    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xe8900001),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_LDM);
    EXPECT((instruction.instruction_flags & bad) == 0);
}

/* A64 tests are kept separate so each fixed word is easy to compare with the
 * Arm architectural encoding diagrams. */
static void test_a64_control(void);
static void test_a64_data(void);
static void test_a64_memory_and_system(void);
static void test_a64_atomic_memory(void);
static void test_a64_extra_atomic_memory(void);
static void test_neon_and_advanced_simd(void);
static void test_t32_dcps(void);
static void test_generated_fallback_boundaries(void);

int main(void)
{
    test_abi_and_ids();
    test_cpu_mode_matrix();
    test_argument_failures();
    test_big_endian_input();
    test_t32_it_context();
    test_a32_capabilities_and_control();
    test_a32_data_processing();
    test_a32_memory_and_stack();
    test_a32_block_transfer_metadata();
    test_a64_control();
    test_a64_data();
    test_a64_memory_and_system();
    test_a64_atomic_memory();
    test_a64_extra_atomic_memory();
    test_neon_and_advanced_simd();
    test_t32_dcps();
    test_generated_fallback_boundaries();

    if (failures != 0) {
        fprintf(stderr, "%d ARM test(s) failed\n", failures);
        return 1;
    }
    puts("all ARM tests passed");
    return 0;
}

static void test_a64_control(void)
{
    cdisasm_arm_instruction instruction;

    EXPECT(decode_word(
               CDISASM_ARM_CPU_CORTEX_A34,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0xd503201f),
               UINT64_C(0x1000),
               &instruction)
        == 4);
    expect_base(
        &instruction,
        UINT64_C(0x1000),
        UINT32_C(0xd503201f),
        CDISASM_ARM_ISA_A64,
        CDISASM_ARM_CONDITION_AL,
        CDISASM_ARM_NAME_NOP);
    EXPECT(instruction.operand_count == 0);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_CORTEX_A53,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0x14000002),
               UINT64_C(0x2000),
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_B);
    EXPECT(instruction.branch_target == UINT64_C(0x2008));
    EXPECT(instruction.opcode_groups
        == (CDISASM_GROUP_JUMP | CDISASM_GROUP_RELATIVE_BRANCH));
    EXPECT(instruction.operand_count == 1);
    expect_immediate(&instruction.operand[0], UINT64_C(0x2008), 8);
    EXPECT(instruction.operand[0].address == 8);
    EXPECT(instruction.operand[0].flags
        == (CDISASM_OPERAND_FLAG_SIGNED
            | CDISASM_OPERAND_FLAG_PC_RELATIVE
            | CDISASM_OPERAND_FLAG_HAS_ADDRESS));

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0x94000001),
               UINT64_C(0x3000),
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_BL);
    EXPECT(instruction.branch_target == UINT64_C(0x3004));
    EXPECT(instruction.opcode_groups
        == (CDISASM_GROUP_CALL | CDISASM_GROUP_RELATIVE_BRANCH));
    EXPECT((instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_LINK)
        != 0);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_CORTEX_A34,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0xd65f03c0),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_RET);
    EXPECT(instruction.opcode_groups == CDISASM_GROUP_RETURN);
    EXPECT(instruction.operand_count == 1);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_X30,
        8,
        CDISASM_OPERAND_ACCESS_READ);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0xd61f0060),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_BR);
    EXPECT(instruction.opcode_groups == CDISASM_GROUP_JUMP);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_X3,
        8,
        CDISASM_OPERAND_ACCESS_READ);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0xd63f0080),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_BLR);
    EXPECT(instruction.opcode_groups == CDISASM_GROUP_CALL);
    EXPECT((instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_LINK)
        != 0);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_X4,
        8,
        CDISASM_OPERAND_ACCESS_READ);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0x54000040),
               UINT64_C(0x4000),
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_B);
    EXPECT(instruction.condition == CDISASM_ARM_CONDITION_EQ);
    EXPECT(instruction.branch_target == UINT64_C(0x4008));
    EXPECT(instruction.opcode_groups
        == (CDISASM_GROUP_JUMP | CDISASM_GROUP_CONDITIONAL
            | CDISASM_GROUP_RELATIVE_BRANCH));

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0xb40002a5),
               UINT64_C(0x5000),
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_CBZ);
    EXPECT(instruction.branch_target == UINT64_C(0x5054));
    EXPECT(instruction.opcode_groups
        == (CDISASM_GROUP_JUMP | CDISASM_GROUP_CONDITIONAL
            | CDISASM_GROUP_RELATIVE_BRANCH));
    EXPECT(instruction.operand_count == 2);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_X5,
        8,
        CDISASM_OPERAND_ACCESS_READ);
    expect_immediate(&instruction.operand[1], UINT64_C(0x5054), 8);
    EXPECT(instruction.operand[1].address == UINT64_C(0x54));

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0x36480267),
               UINT64_C(0x6000),
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_TBZ);
    EXPECT(instruction.branch_target == UINT64_C(0x604c));
    EXPECT(instruction.operand_count == 3);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_W7,
        4,
        CDISASM_OPERAND_ACCESS_READ);
    expect_immediate(&instruction.operand[1], 9, 1);
    expect_immediate(&instruction.operand[2], UINT64_C(0x604c), 8);

    expect_error(
        CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64,
        UINT32_C(0xffffffff),
#if USE_EXTRA_OPCODES
        CDISASM_STATUS_INVALID_INSTRUCTION);
#else
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_a64_data(void)
{
    cdisasm_arm_instruction instruction;

    EXPECT(decode_word(
               CDISASM_ARM_CPU_CORTEX_A35,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0x91001420),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_ADD);
    EXPECT(instruction.operand_count == 3);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_X0,
        8,
        CDISASM_OPERAND_ACCESS_WRITE);
    expect_register(
        &instruction.operand[1],
        CDISASM_ARM_REG_X1,
        8,
        CDISASM_OPERAND_ACCESS_READ);
    expect_immediate(&instruction.operand[2], 5, 8);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0x71001c62),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_SUBS);
    EXPECT(instruction.instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS);
    EXPECT(instruction.operand_count == 3);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_W2,
        4,
        CDISASM_OPERAND_ACCESS_WRITE);
    expect_register(
        &instruction.operand[1],
        CDISASM_ARM_REG_W3,
        4,
        CDISASM_OPERAND_ACCESS_READ);
    expect_immediate(&instruction.operand[2], 7, 4);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0xf100143f),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_CMP);
    EXPECT(instruction.operand_count == 2);
    EXPECT(instruction.instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_X1,
        8,
        CDISASM_OPERAND_ACCESS_READ);
    expect_immediate(&instruction.operand[1], 5, 8);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0xd2824684),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_MOVZ);
    EXPECT(instruction.operand_count == 2);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_X4,
        8,
        CDISASM_OPERAND_ACCESS_WRITE);
    expect_immediate(&instruction.operand[1], UINT64_C(0x1234), 8);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0x72b579a5),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_MOVK);
    EXPECT(instruction.operand_count == 2);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_W5,
        4,
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    expect_immediate(&instruction.operand[1], UINT64_C(0xabcd0000), 4);
    EXPECT(instruction.operand[1].shift_type == CDISASM_ARM_SHIFT_LSL);
    EXPECT(instruction.operand[1].shift_amount == 16);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0x10000186),
               UINT64_C(0x3000),
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_ADR);
    EXPECT(instruction.operand_count == 2);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_X6,
        8,
        CDISASM_OPERAND_ACCESS_WRITE);
    expect_immediate(&instruction.operand[1], UINT64_C(0x3030), 8);
    EXPECT(instruction.operand[1].address == UINT64_C(0x30));
    EXPECT(instruction.operand[1].flags
        == (CDISASM_OPERAND_FLAG_SIGNED
            | CDISASM_OPERAND_FLAG_PC_RELATIVE
            | CDISASM_OPERAND_FLAG_HAS_ADDRESS));

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0x90000007),
               UINT64_C(0x3456),
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_ADRP);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_X7,
        8,
        CDISASM_OPERAND_ACCESS_WRITE);
    expect_immediate(&instruction.operand[1], UINT64_C(0x3000), 8);
    EXPECT(instruction.operand[1].address == 0);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0xaa0103e0),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_MOV);
    EXPECT(instruction.operand_count == 2);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_X0,
        8,
        CDISASM_OPERAND_ACCESS_WRITE);
    expect_register(
        &instruction.operand[1],
        CDISASM_ARM_REG_X1,
        8,
        CDISASM_OPERAND_ACCESS_READ);
}

static void test_a64_memory_and_system(void)
{
    cdisasm_arm_instruction instruction;
    const cdisasm_arm_operand *memory;

    EXPECT(decode_word(
               CDISASM_ARM_CPU_CORTEX_A34,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0xf9400c20),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_LDR);
    EXPECT(instruction.operand_count == 2);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_X0,
        8,
        CDISASM_OPERAND_ACCESS_WRITE);
    memory = &instruction.operand[1];
    EXPECT(memory->type == CDISASM_OPERAND_MEMORY);
    EXPECT(memory->base_reg == CDISASM_ARM_REG_X1);
    EXPECT(memory->imm == 24);
    EXPECT(memory->size == 8);
    EXPECT(memory->access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(memory->flags == CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0xb9000c62),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_STR);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_W2,
        4,
        CDISASM_OPERAND_ACCESS_READ);
    memory = &instruction.operand[1];
    EXPECT(memory->base_reg == CDISASM_ARM_REG_X3);
    EXPECT(memory->imm == 12);
    EXPECT(memory->size == 4);
    EXPECT(memory->access == CDISASM_OPERAND_ACCESS_WRITE);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0xf85f80a4),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_LDUR);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_X4,
        8,
        CDISASM_OPERAND_ACCESS_WRITE);
    memory = &instruction.operand[1];
    EXPECT(memory->base_reg == CDISASM_ARM_REG_X5);
    EXPECT(memory->imm == (uint64_t)(int64_t)-8);
    EXPECT(memory->flags
        == (CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
            | CDISASM_OPERAND_FLAG_SIGNED));

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0x780050e6),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_STURH);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_W6,
        2,
        CDISASM_OPERAND_ACCESS_READ);
    memory = &instruction.operand[1];
    EXPECT(memory->base_reg == CDISASM_ARM_REG_X7);
    EXPECT(memory->imm == 5);
    EXPECT(memory->size == 2);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0xa9bf7bfd),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_STP);
    EXPECT(instruction.operand_count == 3);
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK));
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_X29,
        8,
        CDISASM_OPERAND_ACCESS_READ);
    expect_register(
        &instruction.operand[1],
        CDISASM_ARM_REG_X30,
        8,
        CDISASM_OPERAND_ACCESS_READ);
    memory = &instruction.operand[2];
    EXPECT(memory->base_reg == CDISASM_ARM_REG_SP);
    EXPECT(memory->imm == (uint64_t)(int64_t)-16);
    EXPECT(memory->access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(memory->flags
        == (CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
            | CDISASM_OPERAND_FLAG_SIGNED));

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0xa8c17bfd),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_LDP);
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK));
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_X29,
        8,
        CDISASM_OPERAND_ACCESS_WRITE);
    expect_register(
        &instruction.operand[1],
        CDISASM_ARM_REG_X30,
        8,
        CDISASM_OPERAND_ACCESS_WRITE);
    memory = &instruction.operand[2];
    EXPECT(memory->base_reg == CDISASM_ARM_REG_SP);
    EXPECT(memory->imm == 16);
    EXPECT(memory->access == CDISASM_OPERAND_ACCESS_READ);

    /* Pair loads cannot name the same destination twice. The structural
     * decode is retained and explicitly marked for binary-analysis clients. */
    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0xa9400fe3),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_LDP);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_X3);
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_X3);
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL
            | CDISASM_ARM_INSTRUCTION_FLAG_UNPREDICTABLE));

    /* Duplicate store sources are legal. */
    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0xa9000fe3),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_STP);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_X3);
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_X3);
    EXPECT(instruction.instruction_flags == 0);

    /* Writeback may not overlap either pair-transfer register, for loads or
     * stores. */
    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0xa8c10400),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_LDP);
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL
            | CDISASM_ARM_INSTRUCTION_FLAG_UNPREDICTABLE));

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0xa8810400),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_STP);
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL
            | CDISASM_ARM_INSTRUCTION_FLAG_UNPREDICTABLE));

    /* The same base/target overlap is legal without writeback. */
    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0xa9400400),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_LDP);
    EXPECT(instruction.instruction_flags == 0);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0xd4024681),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_SVC);
    EXPECT(instruction.opcode_groups == CDISASM_GROUP_INTERRUPT);
    expect_immediate(&instruction.operand[0], UINT64_C(0x1234), 2);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0xd40468a2),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_HVC);
    EXPECT(instruction.opcode_groups
        == (CDISASM_GROUP_INTERRUPT | CDISASM_GROUP_PRIVILEGED));
    expect_immediate(&instruction.operand[0], UINT64_C(0x2345), 2);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0xd4068ac3),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_SMC);
    EXPECT(instruction.opcode_groups
        == (CDISASM_GROUP_INTERRUPT | CDISASM_GROUP_PRIVILEGED));
    expect_immediate(&instruction.operand[0], UINT64_C(0x3456), 2);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0xd428ace0),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_BRK);
    EXPECT(instruction.opcode_groups == CDISASM_GROUP_INTERRUPT);
    expect_immediate(&instruction.operand[0], UINT64_C(0x4567), 2);
}

static void test_a64_atomic_memory(void)
{
#define A64_ATOMIC_EXCLUSIVE \
    (CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC \
        | CDISASM_ARM_INSTRUCTION_FLAG_EXCLUSIVE)
#define A64_ATOMIC_ACQUIRE_EXCLUSIVE \
    (A64_ATOMIC_EXCLUSIVE | CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE)
#define A64_ATOMIC_RELEASE_EXCLUSIVE \
    (A64_ATOMIC_EXCLUSIVE | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE)
#define A64_ATOMIC_ACQUIRE \
    (CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC \
        | CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE)
#define A64_ATOMIC_RELEASE \
    (CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC \
        | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE)
    static const struct atomic_case {
        uint32_t word;
        cdisasm_arm_name_id name;
        uint32_t flags;
        cdisasm_arm_reg_id status_reg;
        cdisasm_arm_reg_id first_reg;
        cdisasm_arm_reg_id second_reg;
        cdisasm_arm_reg_id base_reg;
        uint8_t data_size;
        uint8_t load;
    } cases[] = {
        { UINT32_C(0x085f7c20), CDISASM_ARM_NAME_LDXRB,
          A64_ATOMIC_EXCLUSIVE, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_W0, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_X1, 1, 1 },
        { UINT32_C(0x085fffe2), CDISASM_ARM_NAME_LDAXRB,
          A64_ATOMIC_ACQUIRE_EXCLUSIVE, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_W2, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_SP, 1, 1 },
        { UINT32_C(0x485f7c83), CDISASM_ARM_NAME_LDXRH,
          A64_ATOMIC_EXCLUSIVE, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_W3, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_X4, 2, 1 },
        { UINT32_C(0x485ffcc5), CDISASM_ARM_NAME_LDAXRH,
          A64_ATOMIC_ACQUIRE_EXCLUSIVE, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_W5, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_X6, 2, 1 },
        { UINT32_C(0x885f7d07), CDISASM_ARM_NAME_LDXR,
          A64_ATOMIC_EXCLUSIVE, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_W7, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_X8, 4, 1 },
        { UINT32_C(0x885ffd49), CDISASM_ARM_NAME_LDAXR,
          A64_ATOMIC_ACQUIRE_EXCLUSIVE, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_W9, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_X10, 4, 1 },
        { UINT32_C(0xc85f7d8b), CDISASM_ARM_NAME_LDXR,
          A64_ATOMIC_EXCLUSIVE, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_X11, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_X12, 8, 1 },
        { UINT32_C(0xc85fffed), CDISASM_ARM_NAME_LDAXR,
          A64_ATOMIC_ACQUIRE_EXCLUSIVE, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_X13, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_SP, 8, 1 },
        { UINT32_C(0x08007c41), CDISASM_ARM_NAME_STXRB,
          A64_ATOMIC_EXCLUSIVE, CDISASM_ARM_REG_W0,
          CDISASM_ARM_REG_W1, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_X2, 1, 0 },
        { UINT32_C(0x0803ffe4), CDISASM_ARM_NAME_STLXRB,
          A64_ATOMIC_RELEASE_EXCLUSIVE, CDISASM_ARM_REG_W3,
          CDISASM_ARM_REG_W4, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_SP, 1, 0 },
        { UINT32_C(0x48057ce6), CDISASM_ARM_NAME_STXRH,
          A64_ATOMIC_EXCLUSIVE, CDISASM_ARM_REG_W5,
          CDISASM_ARM_REG_W6, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_X7, 2, 0 },
        { UINT32_C(0x4808fd49), CDISASM_ARM_NAME_STLXRH,
          A64_ATOMIC_RELEASE_EXCLUSIVE, CDISASM_ARM_REG_W8,
          CDISASM_ARM_REG_W9, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_X10, 2, 0 },
        { UINT32_C(0x880b7dac), CDISASM_ARM_NAME_STXR,
          A64_ATOMIC_EXCLUSIVE, CDISASM_ARM_REG_W11,
          CDISASM_ARM_REG_W12, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_X13, 4, 0 },
        { UINT32_C(0x880effef), CDISASM_ARM_NAME_STLXR,
          A64_ATOMIC_RELEASE_EXCLUSIVE, CDISASM_ARM_REG_W14,
          CDISASM_ARM_REG_W15, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_SP, 4, 0 },
        { UINT32_C(0xc8107e51), CDISASM_ARM_NAME_STXR,
          A64_ATOMIC_EXCLUSIVE, CDISASM_ARM_REG_W16,
          CDISASM_ARM_REG_X17, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_X18, 8, 0 },
        { UINT32_C(0xc81ffe93), CDISASM_ARM_NAME_STLXR,
          A64_ATOMIC_RELEASE_EXCLUSIVE, CDISASM_ARM_REG_WZR,
          CDISASM_ARM_REG_X19, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_X20, 8, 0 },
        { UINT32_C(0x887f0440), CDISASM_ARM_NAME_LDXP,
          A64_ATOMIC_EXCLUSIVE, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_W0, CDISASM_ARM_REG_W1,
          CDISASM_ARM_REG_X2, 4, 1 },
        { UINT32_C(0x887f93e3), CDISASM_ARM_NAME_LDAXP,
          A64_ATOMIC_ACQUIRE_EXCLUSIVE, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_W3, CDISASM_ARM_REG_W4,
          CDISASM_ARM_REG_SP, 4, 1 },
        { UINT32_C(0xc87f18e5), CDISASM_ARM_NAME_LDXP,
          A64_ATOMIC_EXCLUSIVE, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_X5, CDISASM_ARM_REG_X6,
          CDISASM_ARM_REG_X7, 8, 1 },
        { UINT32_C(0xc87fa548), CDISASM_ARM_NAME_LDAXP,
          A64_ATOMIC_ACQUIRE_EXCLUSIVE, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_X8, CDISASM_ARM_REG_X9,
          CDISASM_ARM_REG_X10, 8, 1 },
        { UINT32_C(0x88200861), CDISASM_ARM_NAME_STXP,
          A64_ATOMIC_EXCLUSIVE, CDISASM_ARM_REG_W0,
          CDISASM_ARM_REG_W1, CDISASM_ARM_REG_W2,
          CDISASM_ARM_REG_X3, 4, 0 },
        { UINT32_C(0x88249be5), CDISASM_ARM_NAME_STLXP,
          A64_ATOMIC_RELEASE_EXCLUSIVE, CDISASM_ARM_REG_W4,
          CDISASM_ARM_REG_W5, CDISASM_ARM_REG_W6,
          CDISASM_ARM_REG_SP, 4, 0 },
        { UINT32_C(0xc8272548), CDISASM_ARM_NAME_STXP,
          A64_ATOMIC_EXCLUSIVE, CDISASM_ARM_REG_W7,
          CDISASM_ARM_REG_X8, CDISASM_ARM_REG_X9,
          CDISASM_ARM_REG_X10, 8, 0 },
        { UINT32_C(0xc83fb1ab), CDISASM_ARM_NAME_STLXP,
          A64_ATOMIC_RELEASE_EXCLUSIVE, CDISASM_ARM_REG_WZR,
          CDISASM_ARM_REG_X11, CDISASM_ARM_REG_X12,
          CDISASM_ARM_REG_X13, 8, 0 },
        { UINT32_C(0x08dffc20), CDISASM_ARM_NAME_LDARB,
          A64_ATOMIC_ACQUIRE, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_W0, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_X1, 1, 1 },
        { UINT32_C(0x48dfffe2), CDISASM_ARM_NAME_LDARH,
          A64_ATOMIC_ACQUIRE, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_W2, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_SP, 2, 1 },
        { UINT32_C(0x88dffc83), CDISASM_ARM_NAME_LDAR,
          A64_ATOMIC_ACQUIRE, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_W3, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_X4, 4, 1 },
        { UINT32_C(0xc8dffcc5), CDISASM_ARM_NAME_LDAR,
          A64_ATOMIC_ACQUIRE, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_X5, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_X6, 8, 1 },
        { UINT32_C(0x089ffd07), CDISASM_ARM_NAME_STLRB,
          A64_ATOMIC_RELEASE, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_W7, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_X8, 1, 0 },
        { UINT32_C(0x489fffe9), CDISASM_ARM_NAME_STLRH,
          A64_ATOMIC_RELEASE, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_W9, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_SP, 2, 0 },
        { UINT32_C(0x889ffd6a), CDISASM_ARM_NAME_STLR,
          A64_ATOMIC_RELEASE, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_W10, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_X11, 4, 0 },
        { UINT32_C(0xc89ffdac), CDISASM_ARM_NAME_STLR,
          A64_ATOMIC_RELEASE, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_X12, CDISASM_ARM_REG_NONE,
          CDISASM_ARM_REG_X13, 8, 0 }
    };
    static const cdisasm_arm_name_id appended_names[] = {
        CDISASM_ARM_NAME_LDARB, CDISASM_ARM_NAME_LDARH,
        CDISASM_ARM_NAME_LDAR, CDISASM_ARM_NAME_LDAXRB,
        CDISASM_ARM_NAME_LDAXRH, CDISASM_ARM_NAME_LDAXR,
        CDISASM_ARM_NAME_LDXRB, CDISASM_ARM_NAME_LDXRH,
        CDISASM_ARM_NAME_LDXR, CDISASM_ARM_NAME_LDXP,
        CDISASM_ARM_NAME_LDAXP, CDISASM_ARM_NAME_STLRB,
        CDISASM_ARM_NAME_STLRH, CDISASM_ARM_NAME_STLR,
        CDISASM_ARM_NAME_STLXRB, CDISASM_ARM_NAME_STLXRH,
        CDISASM_ARM_NAME_STLXR, CDISASM_ARM_NAME_STXRB,
        CDISASM_ARM_NAME_STXRH, CDISASM_ARM_NAME_STXR,
        CDISASM_ARM_NAME_STXP, CDISASM_ARM_NAME_STLXP
    };
    cdisasm_arm_instruction instruction;
    uint8_t truncated[] = { UINT8_C(0x20), UINT8_C(0x7c), UINT8_C(0x5f) };
    size_t index;

    for (index = 0;
         index < sizeof(appended_names) / sizeof(appended_names[0]);
         ++index) {
        EXPECT(appended_names[index]
            == (cdisasm_arm_name_id)(UINT16_C(110) + index));
    }
    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const struct atomic_case *test = &cases[index];
        const cdisasm_arm_operand *memory;
        uint8_t operand_index = 0;

        EXPECT(decode_word(
                   CDISASM_ARM_CPU_CORTEX_A34,
                   CDISASM_ARM_MODE_A64,
                   test->word,
                   UINT64_C(0x8000),
                   &instruction)
            == 4);
        expect_base(
            &instruction,
            UINT64_C(0x8000),
            test->word,
            CDISASM_ARM_ISA_A64,
            CDISASM_ARM_CONDITION_AL,
            test->name);
        EXPECT(instruction.instruction_flags == test->flags);
        EXPECT(instruction.opcode_groups == CDISASM_GROUP_NONE);
        EXPECT(instruction.branch_target == 0u);
        if (test->status_reg != CDISASM_ARM_REG_NONE) {
            expect_register(
                &instruction.operand[operand_index++],
                test->status_reg,
                4,
                CDISASM_OPERAND_ACCESS_WRITE);
        }
        expect_register(
            &instruction.operand[operand_index++],
            test->first_reg,
            test->data_size,
            test->load != 0u ? CDISASM_OPERAND_ACCESS_WRITE
                             : CDISASM_OPERAND_ACCESS_READ);
        if (test->second_reg != CDISASM_ARM_REG_NONE) {
            expect_register(
                &instruction.operand[operand_index++],
                test->second_reg,
                test->data_size,
                test->load != 0u ? CDISASM_OPERAND_ACCESS_WRITE
                                 : CDISASM_OPERAND_ACCESS_READ);
        }
        memory = &instruction.operand[operand_index++];
        EXPECT(memory->type == CDISASM_OPERAND_MEMORY);
        EXPECT(memory->base_reg == test->base_reg);
        EXPECT(memory->size == test->data_size);
        EXPECT(memory->access == (test->load != 0u
                ? CDISASM_OPERAND_ACCESS_READ
                : CDISASM_OPERAND_ACCESS_WRITE));
        EXPECT(memory->flags == CDISASM_OPERAND_FLAG_NONE);
        EXPECT(memory->imm == 0u);
        EXPECT(instruction.operand_count == operand_index);
    }

    /* Architectural reserved fields are rejected, while adjacent extension
     * spaces stay unsupported so they can be added independently. */
    expect_error(
        CDISASM_ARM_CPU_CORTEX_A34,
        CDISASM_ARM_MODE_A64,
        UINT32_C(0x085e7c20),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_CORTEX_A34,
        CDISASM_ARM_MODE_A64,
        UINT32_C(0x08007841),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_CORTEX_A34,
        CDISASM_ARM_MODE_A64,
        UINT32_C(0x487f0440),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_CORTEX_A34,
        CDISASM_ARM_MODE_A64,
        UINT32_C(0x08defc20),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_CORTEX_A34,
        CDISASM_ARM_MODE_A64,
        UINT32_C(0x08df7c20),
#if USE_EXTRA_OPCODES
        CDISASM_STATUS_INVALID_INSTRUCTION);
#else
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    expect_error(
        CDISASM_ARM_CPU_CORTEX_A34,
        CDISASM_ARM_MODE_A64,
        UINT32_C(0x88a07c41),
#if USE_EXTRA_OPCODES
        CDISASM_STATUS_INVALID_INSTRUCTION);
#else
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    expect_error(
        CDISASM_ARM_CPU_CORTEX_A34,
        CDISASM_ARM_MODE_A64,
        UINT32_C(0x08267d48),
#if USE_EXTRA_OPCODES
        CDISASM_STATUS_INVALID_INSTRUCTION);
#else
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    /* Duplicate exclusive-load destinations and a store status register that
     * aliases a source are retained for analysis and marked unpredictable. */
    EXPECT(decode_word(
               CDISASM_ARM_CPU_CORTEX_A34,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0xc87f0020),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_LDXP);
    EXPECT(instruction.instruction_flags
        == (A64_ATOMIC_EXCLUSIVE
            | CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL
            | CDISASM_ARM_INSTRUCTION_FLAG_UNPREDICTABLE));

    EXPECT(decode_word(
               CDISASM_ARM_CPU_CORTEX_A34,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0xc8007c20),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_STXR);
    EXPECT(instruction.instruction_flags
        == (A64_ATOMIC_EXCLUSIVE
            | CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL
            | CDISASM_ARM_INSTRUCTION_FLAG_UNPREDICTABLE));

    {
        static const struct status_overlap_case {
            uint32_t word;
            cdisasm_arm_name_id name;
        } status_overlaps[] = {
            { UINT32_C(0xc8007c02), CDISASM_ARM_NAME_STXR },
            { UINT32_C(0xc82310a3), CDISASM_ARM_NAME_STXP },
            { UINT32_C(0xc8230ca4), CDISASM_ARM_NAME_STXP },
            { UINT32_C(0xc8231464), CDISASM_ARM_NAME_STXP }
        };

        for (index = 0;
             index < sizeof(status_overlaps) / sizeof(status_overlaps[0]);
             ++index) {
            EXPECT(decode_word(
                       CDISASM_ARM_CPU_CORTEX_A34,
                       CDISASM_ARM_MODE_A64,
                       status_overlaps[index].word,
                       0,
                       &instruction)
                == 4);
            EXPECT(instruction.name_id == status_overlaps[index].name);
            EXPECT(instruction.instruction_flags
                == (A64_ATOMIC_EXCLUSIVE
                    | CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL
                    | CDISASM_ARM_INSTRUCTION_FLAG_UNPREDICTABLE));
        }
    }

    /* Transfer/base aliasing is legal because exclusive stores do not write
     * the base register. */
    EXPECT(decode_word(
               CDISASM_ARM_CPU_CORTEX_A34,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0xc8007c42),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.instruction_flags == A64_ATOMIC_EXCLUSIVE);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(cdisasm_arm_decode(
               CDISASM_ARM_CPU_CORTEX_A34,
               CDISASM_ARM_MODE_A64,
               truncated,
               sizeof(truncated),
               0,
               CDISASM_ARM_DECODE_OPTION_NONE,
               &instruction)
        == 0u);
    EXPECT(is_error_only(&instruction, CDISASM_STATUS_TRUNCATED));
#undef A64_ATOMIC_RELEASE
#undef A64_ATOMIC_ACQUIRE
#undef A64_ATOMIC_RELEASE_EXCLUSIVE
#undef A64_ATOMIC_ACQUIRE_EXCLUSIVE
#undef A64_ATOMIC_EXCLUSIVE
}

static void test_a64_extra_atomic_memory(void)
{
#if USE_EXTRA_OPCODES
    cdisasm_arm_instruction instruction;
    static const unsigned rmw_opcodes[] = { 0u, 1u, 2u, 3u, 8u };
    static const cdisasm_arm_name_id lor_names[] = {
        CDISASM_ARM_NAME_LDLARB, CDISASM_ARM_NAME_LDLARH,
        CDISASM_ARM_NAME_LDLAR, CDISASM_ARM_NAME_LDLAR,
        CDISASM_ARM_NAME_STLLRB, CDISASM_ARM_NAME_STLLRH,
        CDISASM_ARM_NAME_STLLR, CDISASM_ARM_NAME_STLLR
    };
    static const uint32_t lor_words[] = {
        UINT32_C(0x08df7c20), UINT32_C(0x48df7c62),
        UINT32_C(0x88df7ca4), UINT32_C(0xc8df7fe6),
        UINT32_C(0x089f7c20), UINT32_C(0x489f7c62),
        UINT32_C(0x889f7ca4), UINT32_C(0xc89f7fe6)
    };
    static const cdisasm_arm_name_id rcpc_names[] = {
        CDISASM_ARM_NAME_LDAPRB, CDISASM_ARM_NAME_LDAPRH,
        CDISASM_ARM_NAME_LDAPR, CDISASM_ARM_NAME_LDAPR
    };
    static const uint32_t rcpc_words[] = {
        UINT32_C(0x38bfc020), UINT32_C(0x78bfc062),
        UINT32_C(0xb8bfc0a4), UINT32_C(0xf8bfc3e6)
    };
    size_t operation_index;
    unsigned ordering;
    unsigned size_code;

    /* Every size and ordering variant of single-register CAS. */
    for (ordering = 0u; ordering < 4u; ++ordering) {
        for (size_code = 0u; size_code < 4u; ++size_code) {
            uint32_t word = UINT32_C(0x08a07c41)
                | (uint32_t)(size_code << 30)
                | (uint32_t)((ordering & 1u) << 22)
                | (uint32_t)((ordering & 2u) << 14);
            uint8_t data_size = (uint8_t)(1u << size_code);
            int is_64 = size_code == 3u;
            uint32_t expected_flags = CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
                | ((ordering & 1u) != 0u
                    ? CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE : 0u)
                | ((ordering & 2u) != 0u
                    ? CDISASM_ARM_INSTRUCTION_FLAG_RELEASE : 0u);

            EXPECT(decode_word(
                       CDISASM_ARM_CPU_ANY,
                       CDISASM_ARM_MODE_A64,
                       word,
                       UINT64_C(0xa000),
                       &instruction)
                == 4u);
            EXPECT(instruction.name_id == (cdisasm_arm_name_id)(
                CDISASM_ARM_NAME_CASB + ordering * 3u
                + (size_code < 2u ? size_code : 2u)));
            EXPECT(instruction.instruction_flags == expected_flags);
            EXPECT(instruction.operand_count == 3u);
            expect_register(
                &instruction.operand[0],
                is_64 ? CDISASM_ARM_REG_X0 : CDISASM_ARM_REG_W0,
                data_size,
                CDISASM_OPERAND_ACCESS_READ_WRITE);
            expect_register(
                &instruction.operand[1],
                is_64 ? CDISASM_ARM_REG_X1 : CDISASM_ARM_REG_W1,
                data_size,
                CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.operand[2].type == CDISASM_OPERAND_MEMORY);
            EXPECT(instruction.operand[2].base_reg == CDISASM_ARM_REG_X2);
            EXPECT(instruction.operand[2].size == data_size);
            EXPECT(instruction.operand[2].access
                == CDISASM_OPERAND_ACCESS_READ_WRITE);
        }
    }

    /* CASP uses compact pair operands so four architectural registers and
     * the memory operand fit the fixed four-operand public ABI. */
    for (ordering = 0u; ordering < 4u; ++ordering) {
        for (size_code = 0u; size_code < 2u; ++size_code) {
            uint32_t word = UINT32_C(0x08207c82)
                | (uint32_t)(size_code << 30)
                | (uint32_t)((ordering & 1u) << 22)
                | (uint32_t)((ordering & 2u) << 14);
            uint8_t data_size = size_code == 0u ? 4u : 8u;
            cdisasm_arm_reg_id first = size_code == 0u
                ? CDISASM_ARM_REG_W0 : CDISASM_ARM_REG_X0;
            cdisasm_arm_reg_id desired = size_code == 0u
                ? CDISASM_ARM_REG_W2 : CDISASM_ARM_REG_X2;

            EXPECT(decode_word(
                       CDISASM_ARM_CPU_ANY,
                       CDISASM_ARM_MODE_A64,
                       word,
                       0,
                       &instruction)
                == 4u);
            EXPECT(instruction.name_id
                == (cdisasm_arm_name_id)(CDISASM_ARM_NAME_CASP + ordering));
            EXPECT(instruction.operand_count == 3u);
            expect_register_pair(
                &instruction.operand[0], first,
                (cdisasm_arm_reg_id)(first + 1u), data_size,
                CDISASM_OPERAND_ACCESS_READ_WRITE);
            expect_register_pair(
                &instruction.operand[1], desired,
                (cdisasm_arm_reg_id)(desired + 1u), data_size,
                CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.operand[2].type == CDISASM_OPERAND_MEMORY);
            EXPECT(instruction.operand[2].base_reg == CDISASM_ARM_REG_X4);
            EXPECT(instruction.operand[2].access
                == CDISASM_OPERAND_ACCESS_READ_WRITE);
        }
    }

    /* Encoded pair 30 wraps architecturally to ZR, not to the intervening
     * public SP enum value. Exercise both pair positions and widths. */
    {
        static const struct casp_edge_case {
            uint32_t word;
            cdisasm_arm_reg_id compare_first;
            cdisasm_arm_reg_id compare_second;
            cdisasm_arm_reg_id desired_first;
            cdisasm_arm_reg_id desired_second;
            uint8_t size;
            cdisasm_arm_reg_id base;
        } edge_cases[] = {
            { UINT32_C(0x083e7c40),
              CDISASM_ARM_REG_W30, CDISASM_ARM_REG_WZR,
              CDISASM_ARM_REG_W0, CDISASM_ARM_REG_W1, 4u,
              CDISASM_ARM_REG_X2 },
            { UINT32_C(0x483e7c40),
              CDISASM_ARM_REG_X30, CDISASM_ARM_REG_XZR,
              CDISASM_ARM_REG_X0, CDISASM_ARM_REG_X1, 8u,
              CDISASM_ARM_REG_X2 },
            { UINT32_C(0x08207c9e),
              CDISASM_ARM_REG_W0, CDISASM_ARM_REG_W1,
              CDISASM_ARM_REG_W30, CDISASM_ARM_REG_WZR, 4u,
              CDISASM_ARM_REG_X4 },
            { UINT32_C(0x48207c9e),
              CDISASM_ARM_REG_X0, CDISASM_ARM_REG_X1,
              CDISASM_ARM_REG_X30, CDISASM_ARM_REG_XZR, 8u,
              CDISASM_ARM_REG_X4 }
        };

        for (operation_index = 0;
             operation_index
                 < sizeof(edge_cases) / sizeof(edge_cases[0]);
             ++operation_index) {
            const struct casp_edge_case *test =
                &edge_cases[operation_index];

            EXPECT(decode_word(
                       CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                       test->word, 0, &instruction)
                == 4u);
            EXPECT(instruction.name_id == CDISASM_ARM_NAME_CASP);
            EXPECT(instruction.instruction_flags
                == CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC);
            EXPECT(instruction.operand_count == 3u);
            expect_register_pair(
                &instruction.operand[0], test->compare_first,
                test->compare_second, test->size,
                CDISASM_OPERAND_ACCESS_READ_WRITE);
            expect_register_pair(
                &instruction.operand[1], test->desired_first,
                test->desired_second, test->size,
                CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.operand[2].type
                == CDISASM_OPERAND_MEMORY);
            EXPECT(instruction.operand[2].base_reg == test->base);
            EXPECT(instruction.operand[2].size == test->size);
        }
    }

    /* Five requested LSE RMW operations, all sizes, and all four ordering
     * combinations are selected by one encoding-driven ID table. */
    for (operation_index = 0;
         operation_index < sizeof(rmw_opcodes) / sizeof(rmw_opcodes[0]);
         ++operation_index) {
        for (ordering = 0u; ordering < 4u; ++ordering) {
            for (size_code = 0u; size_code < 4u; ++size_code) {
                uint32_t word = UINT32_C(0x38200041)
                    | (uint32_t)(rmw_opcodes[operation_index] << 12)
                    | (uint32_t)(size_code << 30)
                    | (uint32_t)((ordering & 1u) << 23)
                    | (uint32_t)((ordering & 2u) << 21);
                uint8_t data_size = (uint8_t)(1u << size_code);
                int is_64 = size_code == 3u;

                EXPECT(decode_word(
                           CDISASM_ARM_CPU_ANY,
                           CDISASM_ARM_MODE_A64,
                           word,
                           0,
                           &instruction)
                    == 4u);
                EXPECT(instruction.name_id == (cdisasm_arm_name_id)(
                    CDISASM_ARM_NAME_LDADDB + operation_index * 12u
                    + ordering * 3u
                    + (size_code < 2u ? size_code : 2u)));
                EXPECT(instruction.operand_count == 3u);
                expect_register(
                    &instruction.operand[0],
                    is_64 ? CDISASM_ARM_REG_X0 : CDISASM_ARM_REG_W0,
                    data_size,
                    CDISASM_OPERAND_ACCESS_READ);
                expect_register(
                    &instruction.operand[1],
                    is_64 ? CDISASM_ARM_REG_X1 : CDISASM_ARM_REG_W1,
                    data_size,
                    CDISASM_OPERAND_ACCESS_WRITE);
                EXPECT(instruction.operand[2].type
                    == CDISASM_OPERAND_MEMORY);
                EXPECT(instruction.operand[2].base_reg
                    == CDISASM_ARM_REG_X2);
                EXPECT(instruction.operand[2].size == data_size);
                EXPECT(instruction.operand[2].access
                    == CDISASM_OPERAND_ACCESS_READ_WRITE);
            }
        }
    }

    /* Arm drops acquire ordering when the LSE result is discarded in ZR;
     * the A/AL mnemonic remains encoded and release remains effective. */
    for (operation_index = 0;
         operation_index < sizeof(rmw_opcodes) / sizeof(rmw_opcodes[0]);
         ++operation_index) {
        static const unsigned acquire_orderings[] = { 1u, 3u };
        size_t acquire_index;

        for (acquire_index = 0;
             acquire_index < sizeof(acquire_orderings)
                 / sizeof(acquire_orderings[0]);
             ++acquire_index) {
            unsigned zr_ordering = acquire_orderings[acquire_index];

            for (size_code = 0u; size_code < 4u; ++size_code) {
                uint32_t word = UINT32_C(0x3820005f)
                    | (uint32_t)(rmw_opcodes[operation_index] << 12)
                    | (uint32_t)(size_code << 30)
                    | (uint32_t)((zr_ordering & 1u) << 23)
                    | (uint32_t)((zr_ordering & 2u) << 21);
                uint8_t data_size = (uint8_t)(1u << size_code);
                int is_64 = size_code == 3u;

                EXPECT(decode_word(
                           CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                           word, 0, &instruction)
                    == 4u);
                EXPECT(instruction.name_id == (cdisasm_arm_name_id)(
                    CDISASM_ARM_NAME_LDADDB + operation_index * 12u
                    + zr_ordering * 3u
                    + (size_code < 2u ? size_code : 2u)));
                EXPECT(instruction.instruction_flags
                    == (CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
                        | (zr_ordering == 3u
                            ? CDISASM_ARM_INSTRUCTION_FLAG_RELEASE : 0u)));
                expect_register(
                    &instruction.operand[0],
                    is_64 ? CDISASM_ARM_REG_X0 : CDISASM_ARM_REG_W0,
                    data_size, CDISASM_OPERAND_ACCESS_READ);
                expect_register(
                    &instruction.operand[1],
                    is_64 ? CDISASM_ARM_REG_XZR : CDISASM_ARM_REG_WZR,
                    data_size, CDISASM_OPERAND_ACCESS_WRITE);
                EXPECT(instruction.operand[2].type
                    == CDISASM_OPERAND_MEMORY);
                EXPECT(instruction.operand[2].access
                    == CDISASM_OPERAND_ACCESS_READ_WRITE);
            }
        }
    }

    for (operation_index = 0;
         operation_index < sizeof(lor_words) / sizeof(lor_words[0]);
         ++operation_index) {
        EXPECT(decode_word(
                   CDISASM_ARM_CPU_ANY,
                   CDISASM_ARM_MODE_A64,
                   lor_words[operation_index],
                   0,
                   &instruction)
            == 4u);
        EXPECT(instruction.name_id == lor_names[operation_index]);
        EXPECT(instruction.operand_count == 2u);
        EXPECT(instruction.operand[1].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.operand[1].access
            == (operation_index < 4u ? CDISASM_OPERAND_ACCESS_READ
                                     : CDISASM_OPERAND_ACCESS_WRITE));
    }
    for (operation_index = 0;
         operation_index < sizeof(rcpc_words) / sizeof(rcpc_words[0]);
         ++operation_index) {
        EXPECT(decode_word(
                   CDISASM_ARM_CPU_ANY,
                   CDISASM_ARM_MODE_A64,
                   rcpc_words[operation_index],
                   0,
                   &instruction)
            == 4u);
        EXPECT(instruction.name_id == rcpc_names[operation_index]);
        EXPECT(instruction.instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
                | CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE));
        EXPECT(instruction.operand[1].access
            == CDISASM_OPERAND_ACCESS_READ);
    }

    /* LLVM product feature profiles establish the optional-family boundary:
     * A10 gains LOR, A11 adds LSE, and A12/M/S products add RCpc. */
    {
        static const struct optional_feature_case {
            uint32_t word;
            cdisasm_arm_name_id name;
        } feature_cases[] = {
            { UINT32_C(0x88a07c41), CDISASM_ARM_NAME_CAS },
            { UINT32_C(0x08207c82), CDISASM_ARM_NAME_CASP },
            { UINT32_C(0xb8200041), CDISASM_ARM_NAME_LDADD },
            { UINT32_C(0x08df7c20), CDISASM_ARM_NAME_LDLARB },
            { UINT32_C(0xb8bfc0a4), CDISASM_ARM_NAME_LDAPR }
        };
        static const cdisasm_arm_cpu_id no_feature_cpus[] = {
            CDISASM_ARM_CPU_APPLE_A7,
            CDISASM_ARM_CPU_APPLE_A8,
            CDISASM_ARM_CPU_APPLE_A9,
            CDISASM_ARM_CPU_APPLE_A8X,
            CDISASM_ARM_CPU_APPLE_A9X,
            CDISASM_ARM_CPU_CORTEX_A34,
            CDISASM_ARM_CPU_CORTEX_A35,
            CDISASM_ARM_CPU_CORTEX_A53
        };
        static const cdisasm_arm_cpu_id all_feature_aliases[] = {
            CDISASM_ARM_CPU_APPLE_A12X,
            CDISASM_ARM_CPU_APPLE_A12Z,
            CDISASM_ARM_CPU_APPLE_A17_PRO,
            CDISASM_ARM_CPU_APPLE_A18_PRO,
            CDISASM_ARM_CPU_APPLE_A19_PRO,
            CDISASM_ARM_CPU_APPLE_M1_PRO,
            CDISASM_ARM_CPU_APPLE_M1_MAX,
            CDISASM_ARM_CPU_APPLE_M1_ULTRA,
            CDISASM_ARM_CPU_APPLE_M2_PRO,
            CDISASM_ARM_CPU_APPLE_M2_MAX,
            CDISASM_ARM_CPU_APPLE_M2_ULTRA,
            CDISASM_ARM_CPU_APPLE_M3_PRO,
            CDISASM_ARM_CPU_APPLE_M3_MAX,
            CDISASM_ARM_CPU_APPLE_M3_ULTRA,
            CDISASM_ARM_CPU_APPLE_M4_PRO,
            CDISASM_ARM_CPU_APPLE_M4_MAX,
            CDISASM_ARM_CPU_APPLE_M4_ULTRA,
            CDISASM_ARM_CPU_APPLE_M5_PRO,
            CDISASM_ARM_CPU_APPLE_M5_MAX,
            CDISASM_ARM_CPU_APPLE_M5_ULTRA
        };
        cdisasm_arm_cpu_id cpu_id;
        size_t cpu_index;
        size_t feature_index;

        for (cpu_id = CDISASM_ARM_CPU_APPLE_A4;
             cpu_id <= CDISASM_ARM_CPU_APPLE_A6;
             ++cpu_id) {
            for (feature_index = 0;
                 feature_index
                     < sizeof(feature_cases) / sizeof(feature_cases[0]);
                 ++feature_index) {
                expect_error(
                    cpu_id, CDISASM_ARM_MODE_A64,
                    feature_cases[feature_index].word,
                    CDISASM_STATUS_INVALID_ARGUMENT);
            }
        }
        for (cpu_index = 0;
             cpu_index < sizeof(no_feature_cpus)
                 / sizeof(no_feature_cpus[0]);
             ++cpu_index) {
            for (feature_index = 0;
                 feature_index
                     < sizeof(feature_cases) / sizeof(feature_cases[0]);
                 ++feature_index) {
                expect_error(
                    no_feature_cpus[cpu_index], CDISASM_ARM_MODE_A64,
                    feature_cases[feature_index].word,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
        }

        /* A10/A10X accept only LOR among these optional families. */
        for (feature_index = 0;
             feature_index < sizeof(feature_cases) / sizeof(feature_cases[0]);
             ++feature_index) {
            cdisasm_status expected_status = feature_index == 3u
                ? CDISASM_STATUS_OK : CDISASM_STATUS_INVALID_INSTRUCTION;

            if (expected_status == CDISASM_STATUS_OK) {
                EXPECT(decode_word(
                           CDISASM_ARM_CPU_APPLE_A10,
                           CDISASM_ARM_MODE_A64,
                           feature_cases[feature_index].word, 0,
                           &instruction)
                    == 4u);
                EXPECT(instruction.name_id
                    == feature_cases[feature_index].name);
                EXPECT(decode_word(
                           CDISASM_ARM_CPU_APPLE_A10X,
                           CDISASM_ARM_MODE_A64,
                           feature_cases[feature_index].word, 0,
                           &instruction)
                    == 4u);
            } else {
                expect_error(
                    CDISASM_ARM_CPU_APPLE_A10,
                    CDISASM_ARM_MODE_A64,
                    feature_cases[feature_index].word,
                    expected_status);
                expect_error(
                    CDISASM_ARM_CPU_APPLE_A10X,
                    CDISASM_ARM_MODE_A64,
                    feature_cases[feature_index].word,
                    expected_status);
            }
        }

        /* A11 adds every LSE encoding here but not RCpc. */
        for (feature_index = 0;
             feature_index < sizeof(feature_cases) / sizeof(feature_cases[0]);
             ++feature_index) {
            if (feature_index < 4u) {
                EXPECT(decode_word(
                           CDISASM_ARM_CPU_APPLE_A11,
                           CDISASM_ARM_MODE_A64,
                           feature_cases[feature_index].word, 0,
                           &instruction)
                    == 4u);
                EXPECT(instruction.name_id
                    == feature_cases[feature_index].name);
            } else {
                expect_error(
                    CDISASM_ARM_CPU_APPLE_A11,
                    CDISASM_ARM_MODE_A64,
                    feature_cases[feature_index].word,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }
        }

        /* A12-A19, M1-M5, S4-S10 and every public product alias carry all
         * three optional capability bits. */
        for (cpu_id = CDISASM_ARM_CPU_APPLE_A12;
             cpu_id <= CDISASM_ARM_CPU_APPLE_M5;
             ++cpu_id) {
            for (feature_index = 0;
                 feature_index
                     < sizeof(feature_cases) / sizeof(feature_cases[0]);
                 ++feature_index) {
                EXPECT(decode_word(
                           cpu_id, CDISASM_ARM_MODE_A64,
                           feature_cases[feature_index].word, 0,
                           &instruction)
                    == 4u);
                EXPECT(instruction.name_id
                    == feature_cases[feature_index].name);
            }
        }
        for (cpu_id = CDISASM_ARM_CPU_APPLE_S4;
             cpu_id <= CDISASM_ARM_CPU_APPLE_S10;
             ++cpu_id) {
            for (feature_index = 0;
                 feature_index
                     < sizeof(feature_cases) / sizeof(feature_cases[0]);
                 ++feature_index) {
                EXPECT(decode_word(
                           cpu_id, CDISASM_ARM_MODE_A64,
                           feature_cases[feature_index].word, 0,
                           &instruction)
                    == 4u);
            }
        }
        for (cpu_index = 0;
             cpu_index < sizeof(all_feature_aliases)
                 / sizeof(all_feature_aliases[0]);
             ++cpu_index) {
            for (feature_index = 0;
                 feature_index
                     < sizeof(feature_cases) / sizeof(feature_cases[0]);
                 ++feature_index) {
                EXPECT(decode_word(
                           all_feature_aliases[cpu_index],
                           CDISASM_ARM_MODE_A64,
                           feature_cases[feature_index].word, 0,
                           &instruction)
                    == 4u);
            }
        }
    }

    /* Reserved pair fields and odd CASP register-pair starts are undefined. */
    expect_error(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        UINT32_C(0x88a07841), CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        UINT32_C(0x08217c82), CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        UINT32_C(0x08207c83), CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        UINT32_C(0x08207882), CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        UINT32_C(0x383fc041), CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        UINT32_C(0x38ffc041), CDISASM_STATUS_INVALID_INSTRUCTION);
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
               UINT32_C(0x38204041), 0, &instruction)
        == 4u);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_LDSMAXB);
    EXPECT(instruction.operand_count == 3u);
#else
    expect_error(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        UINT32_C(0x38204041), CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    /* Big-endian A64 input produces byte-for-byte identical metadata. */
    {
        static const uint32_t parity_words[] = {
            UINT32_C(0xc8e9ffea), UINT32_C(0x486cffee),
            UINT32_C(0xf8e903ea), UINT32_C(0xc8df7fe6),
            UINT32_C(0xf8bfc3e6), UINT32_C(0x083e7c40),
            UINT32_C(0x483e7c40), UINT32_C(0x08207c9e),
            UINT32_C(0x48207c9e), UINT32_C(0x38a0005f),
            UINT32_C(0xf8e0805f)
        };

        for (operation_index = 0;
             operation_index < sizeof(parity_words) / sizeof(parity_words[0]);
             ++operation_index) {
            cdisasm_arm_instruction little;
            cdisasm_arm_instruction big;
            uint8_t bytes[4];

            EXPECT(decode_word(
                       CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                       parity_words[operation_index], UINT64_C(0x1234),
                       &little)
                == 4u);
            word_bytes_be(parity_words[operation_index], bytes);
            memset(&big, 0xa5, sizeof(big));
            EXPECT(cdisasm_arm_decode(
                       CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                       bytes, sizeof(bytes), UINT64_C(0x1234),
                       CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &big)
                == 4u);
            EXPECT(memcmp(&little, &big, sizeof(little)) == 0);
        }
    }
#else
    static const uint32_t disabled_words[] = {
        UINT32_C(0x88a07c41), UINT32_C(0x08207c82),
        UINT32_C(0xb8200041), UINT32_C(0x08df7c20),
        UINT32_C(0xb8bfc0a4), UINT32_C(0x083e7c40),
        UINT32_C(0x48207c9e), UINT32_C(0x38a0005f)
    };
    static const uint32_t malformed_words[] = {
        UINT32_C(0x88a07841), UINT32_C(0x08217c82),
        UINT32_C(0x08207c83), UINT32_C(0x08207882),
        UINT32_C(0x08defc20), UINT32_C(0x383fc041),
        UINT32_C(0x38ffc041)
    };
    size_t index;

    for (index = 0;
         index < sizeof(disabled_words) / sizeof(disabled_words[0]);
         ++index) {
        expect_error(
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64,
            disabled_words[index],
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
    for (index = 0;
         index < sizeof(malformed_words) / sizeof(malformed_words[0]);
         ++index) {
        expect_error(
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64,
            malformed_words[index],
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
#endif
}

static void test_neon_and_advanced_simd(void)
{
    static const struct {
        uint32_t word;
        cdisasm_arm_name_id name;
        uint8_t element_size;
        uint32_t flags;
    } a32_cases[] = {
        { UINT32_C(0xf24108a0), CDISASM_ARM_NAME_VADD, 1,
          CDISASM_ARM_INSTRUCTION_FLAG_SIMD },
        { UINT32_C(0xf35108a0), CDISASM_ARM_NAME_VSUB, 2,
          CDISASM_ARM_INSTRUCTION_FLAG_SIMD },
        { UINT32_C(0xf24101b0), CDISASM_ARM_NAME_VAND, 1,
          CDISASM_ARM_INSTRUCTION_FLAG_SIMD },
        { UINT32_C(0xf25101b0), CDISASM_ARM_NAME_VBIC, 1,
          CDISASM_ARM_INSTRUCTION_FLAG_SIMD },
        { UINT32_C(0xf26101b0), CDISASM_ARM_NAME_VORR, 1,
          CDISASM_ARM_INSTRUCTION_FLAG_SIMD },
        { UINT32_C(0xf34101b0), CDISASM_ARM_NAME_VEOR, 1,
          CDISASM_ARM_INSTRUCTION_FLAG_SIMD },
        { UINT32_C(0xf26009b1), CDISASM_ARM_NAME_VMUL, 4,
          CDISASM_ARM_INSTRUCTION_FLAG_SIMD },
        { UINT32_C(0xf3400db1), CDISASM_ARM_NAME_VMUL, 4,
          CDISASM_ARM_INSTRUCTION_FLAG_SIMD
              | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT }
    };
    static const struct {
        uint32_t word;
        cdisasm_arm_name_id name;
        uint8_t element_size;
        uint32_t flags;
    } a64_cases[] = {
        { UINT32_C(0x4e228420), CDISASM_ARM_NAME_ADD, 1,
          CDISASM_ARM_INSTRUCTION_FLAG_SIMD },
        { UINT32_C(0x6e628420), CDISASM_ARM_NAME_SUB, 2,
          CDISASM_ARM_INSTRUCTION_FLAG_SIMD },
        { UINT32_C(0x4e221c20), CDISASM_ARM_NAME_AND, 1,
          CDISASM_ARM_INSTRUCTION_FLAG_SIMD },
        { UINT32_C(0x4ea21c20), CDISASM_ARM_NAME_ORR, 1,
          CDISASM_ARM_INSTRUCTION_FLAG_SIMD },
        { UINT32_C(0x6e221c20), CDISASM_ARM_NAME_EOR, 1,
          CDISASM_ARM_INSTRUCTION_FLAG_SIMD },
        { UINT32_C(0x4ea29c20), CDISASM_ARM_NAME_MUL, 4,
          CDISASM_ARM_INSTRUCTION_FLAG_SIMD },
        { UINT32_C(0x4e22d420), CDISASM_ARM_NAME_FADD, 4,
          CDISASM_ARM_INSTRUCTION_FLAG_SIMD
              | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT },
        { UINT32_C(0x4ea2d420), CDISASM_ARM_NAME_FSUB, 4,
          CDISASM_ARM_INSTRUCTION_FLAG_SIMD
              | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT },
        { UINT32_C(0x6e22dc20), CDISASM_ARM_NAME_FMUL, 4,
          CDISASM_ARM_INSTRUCTION_FLAG_SIMD
              | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT },
        { UINT32_C(0x6e22fc20), CDISASM_ARM_NAME_FDIV, 4,
          CDISASM_ARM_INSTRUCTION_FLAG_SIMD
              | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT }
    };
    cdisasm_arm_instruction instruction;
    size_t index;
    cdisasm_arm_cpu_id cpu_id;

    for (index = 0; index < sizeof(a32_cases) / sizeof(a32_cases[0]);
         ++index) {
        EXPECT(decode_word(
                   CDISASM_ARM_CPU_CORTEX_A9_NEON,
                   CDISASM_ARM_MODE_A32,
                   a32_cases[index].word,
                   0,
                   &instruction)
            == 4);
        EXPECT(instruction.name_id == a32_cases[index].name);
        EXPECT(instruction.instruction_flags == a32_cases[index].flags);
        EXPECT(CDISASM_ARM_VECTOR_ELEMENT_SIZE(&instruction.operand[0])
            == a32_cases[index].element_size);
    }
    for (index = 0; index < sizeof(a64_cases) / sizeof(a64_cases[0]);
         ++index) {
        EXPECT(decode_word(
                   CDISASM_ARM_CPU_APPLE_A11,
                   CDISASM_ARM_MODE_A64,
                   a64_cases[index].word,
                   0,
                   &instruction)
            == 4);
        EXPECT(instruction.name_id == a64_cases[index].name);
        EXPECT(instruction.instruction_flags == a64_cases[index].flags);
        EXPECT(CDISASM_ARM_VECTOR_ELEMENT_SIZE(&instruction.operand[0])
            == a64_cases[index].element_size);
    }
    for (cpu_id = CDISASM_ARM_CPU_APPLE_A4;
         cpu_id <= CDISASM_ARM_CPU_APPLE_A10;
         ++cpu_id) {
        EXPECT(decode_word(
                   cpu_id,
                   CDISASM_ARM_MODE_A32,
                   UINT32_C(0xf24108a0),
                   0,
                   &instruction)
            == 4);
    }
    for (cpu_id = CDISASM_ARM_CPU_APPLE_A7;
         cpu_id <= CDISASM_ARM_CPU_APPLE_M5;
         ++cpu_id) {
        EXPECT(decode_word(
                   cpu_id,
                   CDISASM_ARM_MODE_A64,
                   UINT32_C(0x4e228420),
                   0,
                   &instruction)
            == 4);
    }
    for (cpu_id = CDISASM_ARM_CPU_APPLE_S4;
         cpu_id <= CDISASM_ARM_CPU_APPLE_S10;
         ++cpu_id) {
        EXPECT(decode_word(
                   cpu_id,
                   CDISASM_ARM_MODE_A64,
                   UINT32_C(0x4e228420),
                   0,
                   &instruction)
            == 4);
    }

    /* A32 Advanced SIMD: VADD.I8 D16, D17, D16. */
    EXPECT(decode_word(
               CDISASM_ARM_CPU_CORTEX_A9_NEON,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xf24108a0),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_VADD);
    EXPECT(instruction.condition == CDISASM_ARM_CONDITION_AL);
    EXPECT(instruction.instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    EXPECT(instruction.operand_count == 3);
    expect_vector_register(
        &instruction.operand[0], CDISASM_ARM_REG_D16, 8, 1, 8,
        CDISASM_OPERAND_ACCESS_WRITE);
    expect_vector_register(
        &instruction.operand[1], CDISASM_ARM_REG_D17, 8, 1, 8,
        CDISASM_OPERAND_ACCESS_READ);
    expect_vector_register(
        &instruction.operand[2], CDISASM_ARM_REG_D16, 8, 1, 8,
        CDISASM_OPERAND_ACCESS_READ);

    /* Cortex-A9 implementations did not universally include NEON. */
    expect_error(
        CDISASM_ARM_CPU_CORTEX_A9,
        CDISASM_ARM_MODE_A32,
        UINT32_C(0xf24108a0),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_CORTEX_A7,
        CDISASM_ARM_MODE_A32,
        UINT32_C(0xf24108a0),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    EXPECT(decode_word(
               CDISASM_ARM_CPU_CORTEX_A7_NEON,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xf24108a0),
               0,
               &instruction)
        == 4);
    expect_error(
        CDISASM_ARM_CPU_ARM7TDMI,
        CDISASM_ARM_MODE_A32,
        UINT32_C(0xf24108a0),
        CDISASM_STATUS_INVALID_INSTRUCTION);

    /* VADD.F32 Q8, Q8, Q9 preserves both total and lane widths. */
    EXPECT(decode_word(
               CDISASM_ARM_CPU_APPLE_A4,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xf2400de2),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_VADD);
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
    expect_vector_register(
        &instruction.operand[0], CDISASM_ARM_REG_Q8, 16, 4, 4,
        CDISASM_OPERAND_ACCESS_WRITE);
    expect_vector_register(
        &instruction.operand[1], CDISASM_ARM_REG_Q8, 16, 4, 4,
        CDISASM_OPERAND_ACCESS_READ);
    expect_vector_register(
        &instruction.operand[2], CDISASM_ARM_REG_Q9, 16, 4, 4,
        CDISASM_OPERAND_ACCESS_READ);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_CORTEX_A7_NEON,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xf24001f2),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_VAND);
    expect_vector_register(
        &instruction.operand[0], CDISASM_ARM_REG_Q8, 16, 1, 16,
        CDISASM_OPERAND_ACCESS_WRITE);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_CORTEX_A7_NEON,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xf26009f2),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_VMUL);
    expect_vector_register(
        &instruction.operand[0], CDISASM_ARM_REG_Q8, 16, 4, 4,
        CDISASM_OPERAND_ACCESS_WRITE);

    /* A64 Advanced SIMD integer, bitwise, and floating-point families. */
    EXPECT(decode_word(
               CDISASM_ARM_CPU_APPLE_A11,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0x4e228420),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_ADD);
    EXPECT(instruction.instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    expect_vector_register(
        &instruction.operand[0], CDISASM_ARM_REG_V0, 16, 1, 16,
        CDISASM_OPERAND_ACCESS_WRITE);
    expect_vector_register(
        &instruction.operand[1], CDISASM_ARM_REG_V1, 16, 1, 16,
        CDISASM_OPERAND_ACCESS_READ);
    expect_vector_register(
        &instruction.operand[2], CDISASM_ARM_REG_V2, 16, 1, 16,
        CDISASM_OPERAND_ACCESS_READ);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_APPLE_M1,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0x4ea29c20),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_MUL);
    expect_vector_register(
        &instruction.operand[0], CDISASM_ARM_REG_V0, 16, 4, 4,
        CDISASM_OPERAND_ACCESS_WRITE);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_APPLE_M5,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0x6e62dc20),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_FMUL);
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
    expect_vector_register(
        &instruction.operand[0], CDISASM_ARM_REG_V0, 16, 8, 2,
        CDISASM_OPERAND_ACCESS_WRITE);

    /* ORR with identical sources is the architectural MOV vector alias. */
    EXPECT(decode_word(
               CDISASM_ARM_CPU_CORTEX_A34,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0x4ea11c20),
               0,
               &instruction)
        == 4);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_MOV);
    EXPECT(instruction.operand_count == 2);
    expect_vector_register(
        &instruction.operand[1], CDISASM_ARM_REG_V1, 16, 1, 16,
        CDISASM_OPERAND_ACCESS_READ);

    /* A one-lane 64-bit form is reserved; Q=1 is required for .2D. */
    expect_error(
        CDISASM_ARM_CPU_CORTEX_A34,
        CDISASM_ARM_MODE_A64,
        UINT32_C(0x0ee28420),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_APPLE_A4,
        CDISASM_ARM_MODE_A64,
        UINT32_C(0x4e228420),
        CDISASM_STATUS_INVALID_ARGUMENT);
}

static void test_t32_dcps(void)
{
    static const struct {
        uint32_t word;
        cdisasm_arm_name_id name_id;
        cdisasm_arm_form_id form_id;
    } cases[] = {
        { UINT32_C(0x8001f78f), CDISASM_ARM_NAME_DCPS1,
          UINT16_C(1853) },
        { UINT32_C(0x8002f78f), CDISASM_ARM_NAME_DCPS2,
          UINT16_C(1854) },
        { UINT32_C(0x8003f78f), CDISASM_ARM_NAME_DCPS3,
          UINT16_C(1855) }
    };
    size_t index;
#if USE_EXTRA_OPCODES
    cdisasm_arm_instruction instruction;
#endif

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(
                   CDISASM_ARM_CPU_ANY,
                   CDISASM_ARM_MODE_T32,
                   cases[index].word,
                   UINT64_C(0x1000),
                   &instruction)
            == 4u);
        expect_base(
            &instruction, UINT64_C(0x1000), cases[index].word,
            CDISASM_ARM_ISA_T32, CDISASM_ARM_CONDITION_AL,
            cases[index].name_id);
        EXPECT(instruction.form_id == cases[index].form_id);
        EXPECT(instruction.opcode_groups
            == (CDISASM_GROUP_INTERRUPT | CDISASM_GROUP_PRIVILEGED));
        EXPECT(instruction.instruction_flags == 0u);
        EXPECT(instruction.operand_count == 0u);
#else
        expect_error(
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_T32,
            cases[index].word,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }

#if USE_EXTRA_OPCODES
    EXPECT(decode_word(
               CDISASM_ARM_CPU_CORTEX_A53,
               CDISASM_ARM_MODE_T32,
               UINT32_C(0x8001f78f),
               UINT64_C(0x1000),
               &instruction)
        == 4u);
    EXPECT(instruction.form_id == UINT16_C(1853));
    expect_error(
        CDISASM_ARM_CPU_CORTEX_A9,
        CDISASM_ARM_MODE_T32,
        UINT32_C(0x8001f78f),
        CDISASM_STATUS_INVALID_INSTRUCTION);
#endif
}

static void test_generated_fallback_boundaries(void)
{
#if USE_EXTRA_OPCODES
    static const struct {
        uint32_t word;
        cdisasm_arm_name_id name_id;
        cdisasm_arm_form_id form_id;
        uint16_t immediate;
    } dcps_cases[] = {
        { UINT32_C(0xd4a00001), CDISASM_ARM_NAME_DCPS1,
          UINT16_C(4453), UINT16_C(0) },
        { UINT32_C(0xd4a24681), CDISASM_ARM_NAME_DCPS1,
          UINT16_C(4453), UINT16_C(0x1234) },
        { UINT32_C(0xd4a00002), CDISASM_ARM_NAME_DCPS2,
          UINT16_C(4454), UINT16_C(0) },
        { UINT32_C(0xd4b7dde2), CDISASM_ARM_NAME_DCPS2,
          UINT16_C(4454), UINT16_C(0xbeef) },
        { UINT32_C(0xd4a00003), CDISASM_ARM_NAME_DCPS3,
          UINT16_C(4455), UINT16_C(0) },
        { UINT32_C(0xd4bfffe3), CDISASM_ARM_NAME_DCPS3,
          UINT16_C(4455), UINT16_C(0xffff) }
    };
    cdisasm_arm_instruction instruction;
    size_t index;

    /* A generated candidate must not override a definitive invalid result from
     * the hand-written architectural classifier. */
    expect_error(
        CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64,
        UINT32_C(0x0a97d3bc),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A32,
        UINT32_C(0xf227c1f5),
        CDISASM_STATUS_INVALID_INSTRUCTION);

    /* DCPS has one exact imm16 operand in bits 20:5.  Lowering it must retain
     * the generated form identity and the generated interrupt/privilege
     * semantics for every architectural selector. */
    for (index = 0u;
         index < sizeof(dcps_cases) / sizeof(dcps_cases[0]);
         ++index) {
        const cdisasm_arm_operand *operand;

        EXPECT(decode_word(
                   CDISASM_ARM_CPU_ANY,
                   CDISASM_ARM_MODE_A64,
                   dcps_cases[index].word,
                   UINT64_C(0x1000),
                   &instruction)
            == 4u);
        expect_base(
            &instruction, UINT64_C(0x1000), dcps_cases[index].word,
            CDISASM_ARM_ISA_A64, CDISASM_ARM_CONDITION_AL,
            dcps_cases[index].name_id);
        EXPECT(instruction.form_id == dcps_cases[index].form_id);
        EXPECT(instruction.opcode_groups
            == (CDISASM_GROUP_INTERRUPT | CDISASM_GROUP_PRIVILEGED));
        EXPECT(instruction.instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK);
        EXPECT(instruction.operand_count == 1u);
        operand = &instruction.operand[0];
        expect_immediate(operand, dcps_cases[index].immediate, 2u);
        EXPECT(operand->flags == CDISASM_OPERAND_FLAG_NONE);
        EXPECT(operand->address == 0u);
        EXPECT(operand->reg == CDISASM_ARM_REG_NONE);
        EXPECT(operand->base_reg == CDISASM_ARM_REG_NONE);
        EXPECT(operand->index_reg == CDISASM_ARM_REG_NONE);
        EXPECT(operand->register_list == 0u);
        EXPECT(operand->extend_type == CDISASM_ARM_EXTEND_NONE);
        EXPECT(operand->scale == 0u);
        EXPECT(operand->shift_type == CDISASM_ARM_SHIFT_NONE);
        EXPECT(operand->shift_amount == 0u);
    }

    /* Cortex-A53 is a named Armv8-A profile and must admit the base DCPS
     * family; an Armv7-only named profile does not admit A64 at all. */
    EXPECT(decode_word(
               CDISASM_ARM_CPU_CORTEX_A53,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0xd4a24681),
               UINT64_C(0x1000),
               &instruction)
        == 4u);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_DCPS1);
    EXPECT(instruction.form_id == UINT16_C(4453));
    expect_error(
        CDISASM_ARM_CPU_CORTEX_A9,
        CDISASM_ARM_MODE_A64,
        UINT32_C(0xd4a24681),
        CDISASM_STATUS_INVALID_ARGUMENT);

    /* Low selector values outside 1..3 are neighboring exception-space
     * encodings, not additional members of the DCPS family. */
    expect_error(
        CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64,
        UINT32_C(0xd4a00000),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64,
        UINT32_C(0xd4a00004),
        CDISASM_STATUS_INVALID_INSTRUCTION);

    /* A generated-only form with exact public operands remains decodable. */
    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A64,
               UINT32_C(0x1fc54577),
               UINT64_C(0x1000),
               &instruction)
        == 4u);
    EXPECT((instruction.instruction_flags
               & CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK)
        != 0u);
    EXPECT((instruction.instruction_flags
               & CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE)
        == 0u);

    /* A32 cond=1111 selects the unconditional encoding space.  It must not
     * leak the obsolete NV predicate into metadata or formatter spelling. */
    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               CDISASM_ARM_MODE_A32,
               UINT32_C(0xfb57610d),
               UINT64_C(0x1000),
               &instruction)
        == 4u);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_BLX);
    EXPECT(instruction.form_id == UINT16_C(407));
    EXPECT(instruction.condition == CDISASM_ARM_CONDITION_AL);
    EXPECT(instruction.opcode_groups
        == (CDISASM_GROUP_CALL | CDISASM_GROUP_RELATIVE_BRANCH));
    EXPECT(instruction.branch_target == UINT64_C(0x15d943e));
#else
    expect_error(
        CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64,
        UINT32_C(0xd4a00001),
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64,
        UINT32_C(0xd4a00002),
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_CORTEX_A53,
        CDISASM_ARM_MODE_A64,
        UINT32_C(0xd4a00003),
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}
