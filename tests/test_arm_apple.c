#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm_arm.h"

#include <stdio.h>
#include <string.h>

#if CDISASM_ARM_NAME_AT_AS1ELX != 76 \
    || CDISASM_ARM_NAME_MUL53HI != 98 \
    || CDISASM_ARM_NAME_MUL53LO != 99 \
    || CDISASM_ARM_NAME_WKDMD != 109 \
    || CDISASM_ARM_NAME_LDARB != 110 \
    || CDISASM_ARM_NAME_STLXP != 131 \
    || CDISASM_ARM_NAME_CASB != 132 \
    || CDISASM_ARM_NAME_LDAPR != 216 \
    || CDISASM_ARM_NAME_COUNT < 217 \
    || CDISASM_ARM_NAME_COUNT != CDISASM_ARM_NAME_LAST + 1
#  error "Apple mnemonic IDs must remain append-only"
#endif

#if CDISASM_ARM_REG_CPM_IOACC_CTL_EL3 != 163 \
    || CDISASM_ARM_REG_COUNT < 164 \
    || CDISASM_ARM_REG_COUNT != CDISASM_ARM_REG_LAST + 1
#  error "Apple register IDs must remain append-only"
#endif

static int failures;

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

static uint32_t decode_word(
    cdisasm_arm_cpu_id cpu_id,
    uint32_t word,
    cdisasm_arm_instruction *instruction)
{
    uint8_t code[4];

    word_bytes(word, code);
    memset(instruction, 0xa5, sizeof(*instruction));
    return cdisasm_arm_decode(
        cpu_id,
        CDISASM_ARM_MODE_A64,
        code,
        sizeof(code),
        UINT64_C(0x1000),
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
    cdisasm_arm_cpu_id cpu_id,
    uint32_t word,
    cdisasm_status status)
{
    cdisasm_arm_instruction instruction;
    uint32_t decoded = decode_word(cpu_id, word, &instruction);

    if (decoded != 0u || !is_error_only(&instruction, status)) {
        fprintf(stderr,
            "cpu=%u word=%08x: decoded=%u expected_status=%u "
            "actual_status=%u name=%u form=%u flags=%08x\n",
            (unsigned)cpu_id, (unsigned)word, (unsigned)decoded,
            (unsigned)status, (unsigned)instruction.last_error_id,
            (unsigned)instruction.name_id, (unsigned)instruction.form_id,
            (unsigned)instruction.instruction_flags);
        ++failures;
    }
}

static void expect_base(
    const cdisasm_arm_instruction *instruction,
    uint32_t word,
    cdisasm_arm_name_id name_id,
    uint32_t flags,
    uint8_t operand_count)
{
    EXPECT(instruction->address == UINT64_C(0x1000));
    EXPECT(instruction->opcode_size == 4u);
    EXPECT(instruction->raw_instruction == word);
    EXPECT(instruction->name_id == name_id);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->operand_count == operand_count);
    EXPECT(instruction->condition == CDISASM_ARM_CONDITION_AL);
    EXPECT(instruction->isa_id == CDISASM_ARM_ISA_A64);
    EXPECT(instruction->instruction_flags == flags);
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

static void test_public_ids(void)
{
    static const cdisasm_arm_name_id appended_names[] = {
        CDISASM_ARM_NAME_AT_AS1ELX,
        CDISASM_ARM_NAME_CLR,
        CDISASM_ARM_NAME_EXTRX,
        CDISASM_ARM_NAME_EXTRY,
        CDISASM_ARM_NAME_FMA16,
        CDISASM_ARM_NAME_FMA32,
        CDISASM_ARM_NAME_FMA64,
        CDISASM_ARM_NAME_FMS16,
        CDISASM_ARM_NAME_FMS32,
        CDISASM_ARM_NAME_FMS64,
        CDISASM_ARM_NAME_GENLUT,
        CDISASM_ARM_NAME_GENTER,
        CDISASM_ARM_NAME_GEXIT,
        CDISASM_ARM_NAME_LDX,
        CDISASM_ARM_NAME_LDY,
        CDISASM_ARM_NAME_LDZ,
        CDISASM_ARM_NAME_LDZI,
        CDISASM_ARM_NAME_MAC16,
        CDISASM_ARM_NAME_MATFP,
        CDISASM_ARM_NAME_MATINT,
        CDISASM_ARM_NAME_MRS,
        CDISASM_ARM_NAME_MSR,
        CDISASM_ARM_NAME_MUL53HI,
        CDISASM_ARM_NAME_MUL53LO,
        CDISASM_ARM_NAME_SDSB,
        CDISASM_ARM_NAME_SET,
        CDISASM_ARM_NAME_STX,
        CDISASM_ARM_NAME_STY,
        CDISASM_ARM_NAME_STZ,
        CDISASM_ARM_NAME_STZI,
        CDISASM_ARM_NAME_VECFP,
        CDISASM_ARM_NAME_VECINT,
        CDISASM_ARM_NAME_WKDMC,
        CDISASM_ARM_NAME_WKDMD
    };
    size_t index;

    for (index = 0;
         index < sizeof(appended_names) / sizeof(appended_names[0]);
         ++index) {
        EXPECT(appended_names[index] == (cdisasm_arm_name_id)(76u + index));
    }
    EXPECT(CDISASM_ARM_NAME_LDAPR == 216u);
    EXPECT(CDISASM_ARM_NAME_LAST >= CDISASM_ARM_NAME_LDAPR);
    EXPECT(CDISASM_ARM_REG_CPM_IOACC_CTL_EL3 == 163u);
    EXPECT(CDISASM_ARM_REG_LAST >= CDISASM_ARM_REG_CPM_IOACC_CTL_EL3);
    EXPECT(CDISASM_ARM_APPLE_SDSB_OSH == 0u);
    EXPECT(CDISASM_ARM_APPLE_SDSB_NSH == 1u);
    EXPECT(CDISASM_ARM_APPLE_SDSB_ISH == 2u);
    EXPECT(CDISASM_ARM_APPLE_SDSB_SY == 3u);
}

static void test_amx_table(void)
{
    static const struct {
        uint32_t word;
        cdisasm_arm_name_id name_id;
        int floating_point;
        int has_register;
    } cases[] = {
        { UINT32_C(0x00201000), CDISASM_ARM_NAME_LDX, 0, 1 },
        { UINT32_C(0x00201020), CDISASM_ARM_NAME_LDY, 0, 1 },
        { UINT32_C(0x00201040), CDISASM_ARM_NAME_STX, 0, 1 },
        { UINT32_C(0x00201060), CDISASM_ARM_NAME_STY, 0, 1 },
        { UINT32_C(0x00201080), CDISASM_ARM_NAME_LDZ, 0, 1 },
        { UINT32_C(0x002010a0), CDISASM_ARM_NAME_STZ, 0, 1 },
        { UINT32_C(0x002010c0), CDISASM_ARM_NAME_LDZI, 0, 1 },
        { UINT32_C(0x002010e0), CDISASM_ARM_NAME_STZI, 0, 1 },
        { UINT32_C(0x00201100), CDISASM_ARM_NAME_EXTRX, 0, 1 },
        { UINT32_C(0x00201120), CDISASM_ARM_NAME_EXTRY, 0, 1 },
        { UINT32_C(0x00201140), CDISASM_ARM_NAME_FMA64, 1, 1 },
        { UINT32_C(0x00201160), CDISASM_ARM_NAME_FMS64, 1, 1 },
        { UINT32_C(0x00201180), CDISASM_ARM_NAME_FMA32, 1, 1 },
        { UINT32_C(0x002011a0), CDISASM_ARM_NAME_FMS32, 1, 1 },
        { UINT32_C(0x002011c0), CDISASM_ARM_NAME_MAC16, 0, 1 },
        { UINT32_C(0x002011e0), CDISASM_ARM_NAME_FMA16, 1, 1 },
        { UINT32_C(0x00201200), CDISASM_ARM_NAME_FMS16, 1, 1 },
        { UINT32_C(0x00201220), CDISASM_ARM_NAME_SET, 0, 0 },
        { UINT32_C(0x00201221), CDISASM_ARM_NAME_CLR, 0, 0 },
        { UINT32_C(0x00201240), CDISASM_ARM_NAME_VECINT, 0, 1 },
        { UINT32_C(0x00201260), CDISASM_ARM_NAME_VECFP, 1, 1 },
        { UINT32_C(0x00201280), CDISASM_ARM_NAME_MATINT, 0, 1 },
        { UINT32_C(0x002012a0), CDISASM_ARM_NAME_MATFP, 1, 1 },
        { UINT32_C(0x002012c0), CDISASM_ARM_NAME_GENLUT, 0, 1 }
    };
    const uint32_t amx_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_APPLE_PROPRIETARY
        | CDISASM_ARM_INSTRUCTION_FLAG_APPLE_AMX;
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_arm_instruction instruction;
        uint32_t expected_flags = amx_flags;

        if (cases[index].floating_point) {
            expected_flags |= CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        }
        EXPECT(decode_word(
                   CDISASM_ARM_CPU_APPLE_M1,
                   cases[index].word,
                   &instruction)
            == 4u);
        expect_base(
            &instruction,
            cases[index].word,
            cases[index].name_id,
            expected_flags,
            (uint8_t)cases[index].has_register);
        EXPECT(instruction.opcode_groups == 0u);
        if (cases[index].has_register) {
            expect_register(
                &instruction.operand[0],
                CDISASM_ARM_REG_X0,
                8u,
                CDISASM_OPERAND_ACCESS_READ);
        }
    }
}

static void test_amx_boundaries_and_cpu_gates(void)
{
    cdisasm_arm_instruction instruction;
    const uint32_t amx_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_APPLE_PROPRIETARY
        | CDISASM_ARM_INSTRUCTION_FLAG_APPLE_AMX;

    EXPECT(decode_word(
               CDISASM_ARM_CPU_APPLE_M4,
               UINT32_C(0x0020101f),
               &instruction)
        == 4u);
    expect_base(
        &instruction,
        UINT32_C(0x0020101f),
        CDISASM_ARM_NAME_LDX,
        amx_flags,
        1u);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_XZR,
        8u,
        CDISASM_OPERAND_ACCESS_READ);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               UINT32_C(0x002012c0),
               &instruction)
        == 4u);
    expect_error(
        CDISASM_ARM_CPU_APPLE_M5,
        UINT32_C(0x00201000),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_APPLE_A19,
        UINT32_C(0x00201000),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_APPLE_S10,
        UINT32_C(0x00201000),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_CORTEX_A53,
        UINT32_C(0x00201000),
        CDISASM_STATUS_INVALID_INSTRUCTION);

    expect_error(
        CDISASM_ARM_CPU_ANY,
        UINT32_C(0x00201222),
#if USE_EXTRA_OPCODES
        CDISASM_STATUS_INVALID_INSTRUCTION);
#else
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    expect_error(
        CDISASM_ARM_CPU_ANY,
        UINT32_C(0x002012e0),
#if USE_EXTRA_OPCODES
        CDISASM_STATUS_INVALID_INSTRUCTION);
#else
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    expect_error(
        CDISASM_ARM_CPU_ANY,
        UINT32_C(0x002013ff),
#if USE_EXTRA_OPCODES
        CDISASM_STATUS_INVALID_INSTRUCTION);
#else
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_mul53(void)
{
    cdisasm_arm_instruction instruction;
    const uint32_t flags =
        CDISASM_ARM_INSTRUCTION_FLAG_APPLE_PROPRIETARY
        | CDISASM_ARM_INSTRUCTION_FLAG_APPLE_MUL53
        | CDISASM_ARM_INSTRUCTION_FLAG_SIMD;

    EXPECT(decode_word(
               CDISASM_ARM_CPU_APPLE_A11,
               UINT32_C(0x00200000),
               &instruction)
        == 4u);
    expect_base(
        &instruction,
        UINT32_C(0x00200000),
        CDISASM_ARM_NAME_MUL53LO,
        flags,
        2u);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_V0,
        16u,
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    expect_register(
        &instruction.operand[1],
        CDISASM_ARM_REG_V0,
        16u,
        CDISASM_OPERAND_ACCESS_READ);
    EXPECT(CDISASM_ARM_VECTOR_ELEMENT_SIZE(&instruction.operand[0]) == 8u);
    EXPECT(CDISASM_ARM_VECTOR_ELEMENT_COUNT(&instruction.operand[0]) == 2u);
    EXPECT(CDISASM_ARM_VECTOR_ELEMENT_SIZE(&instruction.operand[1]) == 8u);
    EXPECT(CDISASM_ARM_VECTOR_ELEMENT_COUNT(&instruction.operand[1]) == 2u);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_APPLE_M5,
               UINT32_C(0x002007ff),
               &instruction)
        == 4u);
    expect_base(
        &instruction,
        UINT32_C(0x002007ff),
        CDISASM_ARM_NAME_MUL53HI,
        flags,
        2u);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_V31,
        16u,
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    expect_register(
        &instruction.operand[1],
        CDISASM_ARM_REG_V31,
        16u,
        CDISASM_OPERAND_ACCESS_READ);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_APPLE_A11,
               UINT32_C(0x00200401),
               &instruction)
        == 4u);
    expect_base(
        &instruction,
        UINT32_C(0x00200401),
        CDISASM_ARM_NAME_MUL53HI,
        flags,
        2u);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_V1,
        16u,
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    expect_register(
        &instruction.operand[1],
        CDISASM_ARM_REG_V0,
        16u,
        CDISASM_OPERAND_ACCESS_READ);

    expect_error(
        CDISASM_ARM_CPU_APPLE_A10,
        UINT32_C(0x00200000),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_APPLE_S10,
        UINT32_C(0x00200000),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_CORTEX_A53,
        UINT32_C(0x00200000),
        CDISASM_STATUS_INVALID_INSTRUCTION);
}

static void test_apple_system(void)
{
    cdisasm_arm_instruction instruction;
    const uint32_t flags =
        CDISASM_ARM_INSTRUCTION_FLAG_APPLE_PROPRIETARY
        | CDISASM_ARM_INSTRUCTION_FLAG_APPLE_SYSTEM;

    EXPECT(decode_word(
               CDISASM_ARM_CPU_APPLE_M1,
               UINT32_C(0x00200822),
               &instruction)
        == 4u);
    expect_base(
        &instruction,
        UINT32_C(0x00200822),
        CDISASM_ARM_NAME_WKDMC,
        flags,
        2u);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_X1,
        8u,
        CDISASM_OPERAND_ACCESS_READ);
    expect_register(
        &instruction.operand[1],
        CDISASM_ARM_REG_X2,
        8u,
        CDISASM_OPERAND_ACCESS_READ_WRITE);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_APPLE_M5,
               UINT32_C(0x00200fff),
               &instruction)
        == 4u);
    expect_base(
        &instruction,
        UINT32_C(0x00200fff),
        CDISASM_ARM_NAME_WKDMD,
        flags,
        2u);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_XZR,
        8u,
        CDISASM_OPERAND_ACCESS_READ);
    expect_register(
        &instruction.operand[1],
        CDISASM_ARM_REG_XZR,
        8u,
        CDISASM_OPERAND_ACCESS_READ_WRITE);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_APPLE_M1,
               UINT32_C(0x00201400),
               &instruction)
        == 4u);
    expect_base(
        &instruction,
        UINT32_C(0x00201400),
        CDISASM_ARM_NAME_GEXIT,
        flags,
        0u);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_APPLE_M1,
               UINT32_C(0x0020145f),
               &instruction)
        == 4u);
    expect_base(
        &instruction,
        UINT32_C(0x0020145f),
        CDISASM_ARM_NAME_AT_AS1ELX,
        flags,
        1u);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_XZR,
        8u,
        CDISASM_OPERAND_ACCESS_READ_WRITE);

    expect_error(
        CDISASM_ARM_CPU_APPLE_A19,
        UINT32_C(0x00201400),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_APPLE_S10,
        UINT32_C(0x00200800),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_CORTEX_A53,
        UINT32_C(0x00201440),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_ANY,
        UINT32_C(0x00201401),
#if USE_EXTRA_OPCODES
        CDISASM_STATUS_INVALID_INSTRUCTION);
#else
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    expect_error(
        CDISASM_ARM_CPU_ANY,
        UINT32_C(0x00201470),
#if USE_EXTRA_OPCODES
        CDISASM_STATUS_INVALID_INSTRUCTION);
#else
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_genter_and_sdsb_immediates(void)
{
    static const struct {
        uint32_t bits;
        uint64_t value;
        uint8_t flags;
    } genter_cases[] = {
        { 0u, UINT64_C(0), 0u },
        { 15u, UINT64_C(15), 0u },
        { 16u, UINT64_MAX - UINT64_C(15), CDISASM_OPERAND_FLAG_SIGNED },
        { 31u, UINT64_MAX, CDISASM_OPERAND_FLAG_SIGNED }
    };
    const uint32_t apple_sys_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_APPLE_PROPRIETARY
        | CDISASM_ARM_INSTRUCTION_FLAG_APPLE_SYSTEM;
    size_t index;

    for (index = 0;
         index < sizeof(genter_cases) / sizeof(genter_cases[0]);
         ++index) {
        cdisasm_arm_instruction instruction;
        uint32_t word = UINT32_C(0x00201420) | genter_cases[index].bits;

        EXPECT(decode_word(
                   CDISASM_ARM_CPU_APPLE_M1, word, &instruction)
            == 4u);
        expect_base(
            &instruction,
            word,
            CDISASM_ARM_NAME_GENTER,
            apple_sys_flags,
            1u);
        EXPECT(instruction.operand[0].type == CDISASM_OPERAND_IMMEDIATE);
        EXPECT(instruction.operand[0].imm == genter_cases[index].value);
        EXPECT(instruction.operand[0].size == 1u);
        EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction.operand[0].flags == genter_cases[index].flags);
    }

    for (index = 0; index < 16u; ++index) {
        cdisasm_arm_instruction instruction;
        uint32_t word = UINT32_C(0x00201460) | (uint32_t)index;
        uint32_t flags = apple_sys_flags;

        if (index > CDISASM_ARM_APPLE_SDSB_SY) {
            flags |= CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL;
        }
        EXPECT(decode_word(
                   CDISASM_ARM_CPU_APPLE_M1, word, &instruction)
            == 4u);
        expect_base(
            &instruction,
            word,
            CDISASM_ARM_NAME_SDSB,
            flags,
            1u);
        EXPECT(instruction.operand[0].type == CDISASM_OPERAND_IMMEDIATE);
        EXPECT(instruction.operand[0].imm == index);
        EXPECT(instruction.operand[0].size == 1u);
        EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_READ);
    }
}

static void test_apple_a7_system_register(void)
{
    cdisasm_arm_instruction instruction;
    const uint32_t flags =
        CDISASM_ARM_INSTRUCTION_FLAG_APPLE_PROPRIETARY
        | CDISASM_ARM_INSTRUCTION_FLAG_APPLE_SYSTEM;

    EXPECT(decode_word(
               CDISASM_ARM_CPU_APPLE_A7,
               UINT32_C(0xd53ff200),
               &instruction)
        == 4u);
    expect_base(
        &instruction,
        UINT32_C(0xd53ff200),
        CDISASM_ARM_NAME_MRS,
        flags,
        2u);
    EXPECT(instruction.opcode_groups == CDISASM_GROUP_PRIVILEGED);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_X0,
        8u,
        CDISASM_OPERAND_ACCESS_WRITE);
    expect_register(
        &instruction.operand[1],
        CDISASM_ARM_REG_CPM_IOACC_CTL_EL3,
        8u,
        CDISASM_OPERAND_ACCESS_READ);

    EXPECT(decode_word(
               CDISASM_ARM_CPU_ANY,
               UINT32_C(0xd51ff21f),
               &instruction)
        == 4u);
    expect_base(
        &instruction,
        UINT32_C(0xd51ff21f),
        CDISASM_ARM_NAME_MSR,
        flags,
        2u);
    EXPECT(instruction.opcode_groups == CDISASM_GROUP_PRIVILEGED);
    expect_register(
        &instruction.operand[0],
        CDISASM_ARM_REG_CPM_IOACC_CTL_EL3,
        8u,
        CDISASM_OPERAND_ACCESS_WRITE);
    expect_register(
        &instruction.operand[1],
        CDISASM_ARM_REG_XZR,
        8u,
        CDISASM_OPERAND_ACCESS_READ);

    expect_error(
        CDISASM_ARM_CPU_APPLE_A8,
        UINT32_C(0xd51ff200),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_APPLE_M1,
        UINT32_C(0xd53ff200),
        CDISASM_STATUS_INVALID_INSTRUCTION);
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(
               CDISASM_ARM_CPU_APPLE_A7,
               UINT32_C(0xd51ff220),
               &instruction)
        == 4u);
    expect_base(
        &instruction,
        UINT32_C(0xd51ff220),
        CDISASM_ARM_NAME_MSR,
        CDISASM_ARM_INSTRUCTION_FLAG_NONE,
        2u);
    EXPECT(instruction.form_id == UINT16_C(4504));
    EXPECT(instruction.opcode_groups == CDISASM_GROUP_PRIVILEGED);
    EXPECT(instruction.operand[0].type
        == CDISASM_ARM_OPERAND_SYSTEM_REGISTER);
    EXPECT(instruction.operand[0].imm == UINT64_C(65425));
    EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    expect_register(
        &instruction.operand[1],
        CDISASM_ARM_REG_X0,
        8u,
        CDISASM_OPERAND_ACCESS_READ);
#else
    expect_error(
        CDISASM_ARM_CPU_APPLE_A7,
        UINT32_C(0xd51ff220),
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static int cpu_accepts_family(
    cdisasm_arm_cpu_id cpu_id,
    unsigned family)
{
    if (cpu_id == CDISASM_ARM_CPU_ANY) {
        return 1;
    }
    switch (family) {
        case 0u:
            return cpu_id == CDISASM_ARM_CPU_APPLE_A7;
        case 1u:
            return (cpu_id >= CDISASM_ARM_CPU_APPLE_A11
                    && cpu_id <= CDISASM_ARM_CPU_APPLE_A19)
                || (cpu_id >= CDISASM_ARM_CPU_APPLE_M1
                    && cpu_id <= CDISASM_ARM_CPU_APPLE_M5);
        case 2u:
            return cpu_id >= CDISASM_ARM_CPU_APPLE_M1
                && cpu_id <= CDISASM_ARM_CPU_APPLE_M4;
        case 3u:
            return cpu_id >= CDISASM_ARM_CPU_APPLE_M1
                && cpu_id <= CDISASM_ARM_CPU_APPLE_M5;
        default:
            return 0;
    }
}

static void test_cpu_capability_matrix(void)
{
    static const struct {
        uint32_t word;
        cdisasm_arm_name_id name_id;
    } families[] = {
        { UINT32_C(0xd53ff200), CDISASM_ARM_NAME_MRS },
        { UINT32_C(0x00200401), CDISASM_ARM_NAME_MUL53HI },
        { UINT32_C(0x00201000), CDISASM_ARM_NAME_LDX },
        { UINT32_C(0x00201400), CDISASM_ARM_NAME_GEXIT }
    };
    cdisasm_arm_cpu_id cpu_id;
    size_t family;

    for (cpu_id = CDISASM_ARM_CPU_ANY;
         cpu_id <= CDISASM_ARM_CPU_LAST;
         ++cpu_id) {
        int has_a64 =
            (cdisasm_arm_cpu_mode_mask(cpu_id)
                & CDISASM_ARM_MODE_MASK_A64) != 0u;

        for (family = 0;
             family < sizeof(families) / sizeof(families[0]);
             ++family) {
            if (cpu_accepts_family(cpu_id, (unsigned)family)) {
                cdisasm_arm_instruction instruction;

                EXPECT(decode_word(
                           cpu_id,
                           families[family].word,
                           &instruction)
                    == 4u);
                EXPECT(instruction.name_id == families[family].name_id);
                EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
            } else {
                expect_error(
                    cpu_id,
                    families[family].word,
                    has_a64
                        ? CDISASM_STATUS_INVALID_INSTRUCTION
                        : CDISASM_STATUS_INVALID_ARGUMENT);
            }
        }
    }
}

static void test_truncation(void)
{
    uint8_t code[4];
    size_t size;

    word_bytes(UINT32_C(0x00201000), code);
    for (size = 0; size < 4u; ++size) {
        cdisasm_arm_instruction instruction;
        cdisasm_status expected = size == 0u
            ? CDISASM_STATUS_END_OF_INPUT
            : CDISASM_STATUS_TRUNCATED;

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(cdisasm_arm_decode(
                   CDISASM_ARM_CPU_APPLE_M1,
                   CDISASM_ARM_MODE_A64,
                   code,
                   size,
                   0,
                   CDISASM_ARM_DECODE_OPTION_NONE,
                   &instruction)
            == 0u);
        EXPECT(is_error_only(&instruction, expected));
    }
}

int main(void)
{
    test_public_ids();
    test_amx_table();
    test_amx_boundaries_and_cpu_gates();
    test_mul53();
    test_apple_system();
    test_genter_and_sdsb_immediates();
    test_apple_a7_system_register();
    test_cpu_capability_matrix();
    test_truncation();

    if (failures != 0) {
        fprintf(stderr, "%d Apple ARM test(s) failed\n", failures);
        return 1;
    }
    puts("Apple ARM opcode tests passed");
    return 0;
}
