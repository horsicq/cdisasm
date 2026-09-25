#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm_arm.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define EXPECT(expression) \
    do { \
        if (!(expression)) { \
            fprintf(stderr, "line %d: EXPECT(%s) failed\n", \
                    __LINE__, #expression); \
            ++failures; \
        } \
    } while (0)

static cdisasm_arm_instruction decode_ok(
    cdisasm_arm_cpu_id cpu_id,
    const uint8_t *bytes,
    size_t byte_count,
    uint64_t address,
    uint32_t expected_size,
    cdisasm_arm_name_id expected_name)
{
    cdisasm_arm_instruction instruction;
    uint32_t size = cdisasm_arm_decode(
        cpu_id,
        CDISASM_ARM_MODE_T32,
        bytes,
        byte_count,
        address,
        CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction);

    EXPECT(size == expected_size);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.opcode_size == expected_size);
    EXPECT(instruction.name_id == expected_name);
    EXPECT(instruction.isa_id == CDISASM_ARM_ISA_T32);
    EXPECT(instruction.address == address);
    return instruction;
}

static void expect_error(
    cdisasm_arm_cpu_id cpu_id,
    const uint8_t *bytes,
    size_t byte_count,
    cdisasm_status expected_status)
{
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction zero = {0};
    uint32_t size = cdisasm_arm_decode(
        cpu_id,
        CDISASM_ARM_MODE_T32,
        bytes,
        byte_count,
        UINT64_C(0x1000),
        CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction);

    zero.last_error_id = (uint8_t)expected_status;
    EXPECT(size == 0);
    EXPECT(memcmp(&instruction, &zero, sizeof(instruction)) == 0);
}

static void test_control_flow(void)
{
    static const uint8_t bx_lr[] = {0x70, 0x47};
    static const uint8_t blx_r3[] = {0x98, 0x47};
    static const uint8_t beq[] = {0x01, 0xd0};
    static const uint8_t branch_back[] = {0xfe, 0xe7};
    static const uint8_t cbz[] = {0x00, 0xb1};
    static const uint8_t bl[] = {0x00, 0xf0, 0x00, 0xf8};
    static const uint8_t thumb2_bl[] = {0x00, 0xf0, 0x00, 0xd0};
    cdisasm_arm_instruction instruction;

    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A7,
        bx_lr,
        sizeof(bx_lr),
        UINT64_C(0x1000),
        2,
        CDISASM_ARM_NAME_BX);
    EXPECT(instruction.operand_count == 1);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_LR);
    EXPECT((instruction.opcode_groups & CDISASM_GROUP_JUMP) != 0);
    EXPECT((instruction.opcode_groups & CDISASM_GROUP_RETURN) != 0);

    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A7,
        blx_r3,
        sizeof(blx_r3),
        UINT64_C(0x1000),
        2,
        CDISASM_ARM_NAME_BLX);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_R3);
    EXPECT((instruction.opcode_groups & CDISASM_GROUP_CALL) != 0);
    EXPECT((instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_LINK) != 0);

    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A7,
        beq,
        sizeof(beq),
        UINT64_C(0x1000),
        2,
        CDISASM_ARM_NAME_B);
    EXPECT(instruction.condition == CDISASM_ARM_CONDITION_EQ);
    EXPECT(instruction.branch_target == UINT64_C(0x1006));
    EXPECT((instruction.opcode_groups & CDISASM_GROUP_CONDITIONAL) != 0);
    EXPECT((int64_t)instruction.operand[0].address == 2);

    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A7,
        branch_back,
        sizeof(branch_back),
        UINT64_C(0x1000),
        2,
        CDISASM_ARM_NAME_B);
    EXPECT(instruction.branch_target == UINT64_C(0x1000));
    EXPECT((int64_t)instruction.operand[0].address == -4);

    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A7,
        cbz,
        sizeof(cbz),
        UINT64_C(0x1000),
        2,
        CDISASM_ARM_NAME_CBZ);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_R0);
    EXPECT(instruction.branch_target == UINT64_C(0x1004));

    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A7,
        bl,
        sizeof(bl),
        UINT64_C(0x1000),
        4,
        CDISASM_ARM_NAME_BL);
    EXPECT(instruction.raw_instruction == UINT32_C(0xf800f000));
    EXPECT(instruction.branch_target == UINT64_C(0x1004));
    EXPECT((instruction.opcode_groups & CDISASM_GROUP_CALL) != 0);

    instruction = decode_ok(
        CDISASM_ARM_CPU_ARM7TDMI,
        bl,
        sizeof(bl),
        UINT64_C(0x1000),
        4,
        CDISASM_ARM_NAME_BL);
    EXPECT(instruction.branch_target == UINT64_C(0x1004));

    expect_error(
        CDISASM_ARM_CPU_ARM7TDMI,
        thumb2_bl,
        sizeof(thumb2_bl),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A7,
        thumb2_bl,
        sizeof(thumb2_bl),
        UINT64_C(0x1000),
        4,
        CDISASM_ARM_NAME_BL);
    EXPECT((instruction.opcode_groups & CDISASM_GROUP_CALL) != 0);
}

static void test_data_processing(void)
{
    static const uint8_t movs[] = {0x2a, 0x21};
    static const uint8_t cmp[] = {0x04, 0x2b};
    static const uint8_t adds_imm[] = {0x02, 0x31};
    static const uint8_t subs_imm[] = {0x03, 0x3a};
    static const uint8_t adds_reg[] = {0x88, 0x18};
    static const uint8_t ands[] = {0x08, 0x40};
    static const uint8_t mov_high[] = {0xc0, 0x46};
    static const uint8_t add_sp[] = {0x01, 0xb0};
    cdisasm_arm_instruction instruction;

    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A7,
        movs,
        sizeof(movs),
        0,
        2,
        CDISASM_ARM_NAME_MOV);
    EXPECT(instruction.operand_count == 2);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_R1);
    EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.operand[1].imm == 0x2a);
    EXPECT((instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS) != 0);

    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A7,
        cmp,
        sizeof(cmp),
        0,
        2,
        CDISASM_ARM_NAME_CMP);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_R3);
    EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.operand[1].imm == 4);

    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A7,
        adds_imm,
        sizeof(adds_imm),
        0,
        2,
        CDISASM_ARM_NAME_ADDS);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_R1);
    EXPECT(instruction.operand[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);

    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A7,
        subs_imm,
        sizeof(subs_imm),
        0,
        2,
        CDISASM_ARM_NAME_SUBS);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_R2);

    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A7,
        adds_reg,
        sizeof(adds_reg),
        0,
        2,
        CDISASM_ARM_NAME_ADDS);
    EXPECT(instruction.operand_count == 3);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_R0);
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_R1);
    EXPECT(instruction.operand[2].reg == CDISASM_ARM_REG_R2);

    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A7,
        ands,
        sizeof(ands),
        0,
        2,
        CDISASM_ARM_NAME_AND);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_R0);
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_R1);

    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A7,
        mov_high,
        sizeof(mov_high),
        0,
        2,
        CDISASM_ARM_NAME_MOV);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_R8);
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_R8);

    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A7,
        add_sp,
        sizeof(add_sp),
        0,
        2,
        CDISASM_ARM_NAME_ADD);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_SP_A32);
    EXPECT(instruction.operand[1].imm == 4);
}

static void test_memory_and_lists(void)
{
    static const uint8_t literal[] = {0x01, 0x48};
    static const uint8_t store[] = {0xd1, 0x60};
    static const uint8_t load_half[] = {0xd1, 0x88};
    static const uint8_t address_pc[] = {0x01, 0xa0};
    static const uint8_t push[] = {0x10, 0xb5};
    static const uint8_t pop[] = {0x10, 0xbd};
    static const uint8_t stm[] = {0x05, 0xc1};
    static const uint8_t ldm_overlap[] = {0x01, 0xc8};
    cdisasm_arm_instruction instruction;

    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A7,
        literal,
        sizeof(literal),
        UINT64_C(0x1000),
        2,
        CDISASM_ARM_NAME_LDR);
    EXPECT(instruction.operand[1].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.operand[1].base_reg == CDISASM_ARM_REG_PC);
    EXPECT(instruction.operand[1].address == UINT64_C(0x1008));

    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A7,
        store,
        sizeof(store),
        0,
        2,
        CDISASM_ARM_NAME_STR);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_R1);
    EXPECT(instruction.operand[1].base_reg == CDISASM_ARM_REG_R2);
    EXPECT(instruction.operand[1].imm == 12);

    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A7,
        load_half,
        sizeof(load_half),
        0,
        2,
        CDISASM_ARM_NAME_LDRH);
    EXPECT(instruction.operand[1].size == 2);
    EXPECT(instruction.operand[1].imm == 6);

    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A7,
        address_pc,
        sizeof(address_pc),
        UINT64_C(0x1000),
        2,
        CDISASM_ARM_NAME_ADR);
    EXPECT(instruction.operand[1].imm == UINT64_C(0x1008));
    EXPECT((instruction.operand[1].flags
            & CDISASM_OPERAND_FLAG_PC_RELATIVE) != 0);

    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A7,
        push,
        sizeof(push),
        0,
        2,
        CDISASM_ARM_NAME_PUSH);
    EXPECT(instruction.operand[0].register_list
        == (UINT16_C(1) << 4 | UINT16_C(1) << 14));
    EXPECT((instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT) != 0);

    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A7,
        pop,
        sizeof(pop),
        0,
        2,
        CDISASM_ARM_NAME_POP);
    EXPECT((instruction.opcode_groups & CDISASM_GROUP_RETURN) != 0);
    EXPECT((instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT) != 0);

    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A7,
        stm,
        sizeof(stm),
        0,
        2,
        CDISASM_ARM_NAME_STM);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_R1);
    EXPECT(instruction.operand[1].register_list == 5);

    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A7,
        ldm_overlap,
        sizeof(ldm_overlap),
        0,
        2,
        CDISASM_ARM_NAME_LDM);
    EXPECT((instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK) == 0);
    EXPECT((instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL) == 0);
    EXPECT((instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_UNPREDICTABLE) == 0);
    EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_READ);
}

static void test_contracts(void)
{
    static const uint8_t nop[] = {0x00, 0xbf};
    static const uint8_t wide_prefix[] = {0x00, 0xf0};
    static const uint8_t unsupported_wide[] = {0x00, 0xe8, 0x00, 0x00};
    cdisasm_arm_instruction instruction;

    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A7,
        nop,
        sizeof(nop),
        0,
        2,
        CDISASM_ARM_NAME_NOP);
    EXPECT(instruction.raw_instruction == UINT32_C(0xbf00));
    EXPECT((cdisasm_arm_decoder_mode_mask(CDISASM_ARM_CPU_CORTEX_A7)
            & CDISASM_ARM_MODE_MASK_T32) != 0);
    EXPECT((cdisasm_arm_decoder_mode_mask(CDISASM_ARM_CPU_CORTEX_A34)
            & CDISASM_ARM_MODE_MASK_T32) == 0);

    expect_error(
        CDISASM_ARM_CPU_ARM7TDMI,
        nop,
        sizeof(nop),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_CORTEX_A34,
        nop,
        sizeof(nop),
        CDISASM_STATUS_INVALID_ARGUMENT);
    expect_error(
        CDISASM_ARM_CPU_CORTEX_A7,
        nop,
        1,
        CDISASM_STATUS_TRUNCATED);
    expect_error(
        CDISASM_ARM_CPU_CORTEX_A7,
        wide_prefix,
        sizeof(wide_prefix),
        CDISASM_STATUS_TRUNCATED);
    expect_error(
        CDISASM_ARM_CPU_CORTEX_A7,
        unsupported_wide,
        sizeof(unsupported_wide),
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
}

static void test_neon(void)
{
    static const struct {
        uint8_t bytes[4];
        cdisasm_arm_name_id name;
        uint8_t element_size;
        uint32_t flags;
    } cases[] = {
        { {0x41, 0xef, 0xa0, 0x08}, CDISASM_ARM_NAME_VADD, 1,
          CDISASM_ARM_INSTRUCTION_FLAG_SIMD },
        { {0x51, 0xff, 0xa0, 0x08}, CDISASM_ARM_NAME_VSUB, 2,
          CDISASM_ARM_INSTRUCTION_FLAG_SIMD },
        { {0x41, 0xef, 0xb0, 0x01}, CDISASM_ARM_NAME_VAND, 1,
          CDISASM_ARM_INSTRUCTION_FLAG_SIMD },
        { {0x51, 0xef, 0xb0, 0x01}, CDISASM_ARM_NAME_VBIC, 1,
          CDISASM_ARM_INSTRUCTION_FLAG_SIMD },
        { {0x61, 0xef, 0xb0, 0x01}, CDISASM_ARM_NAME_VORR, 1,
          CDISASM_ARM_INSTRUCTION_FLAG_SIMD },
        { {0x41, 0xff, 0xb0, 0x01}, CDISASM_ARM_NAME_VEOR, 1,
          CDISASM_ARM_INSTRUCTION_FLAG_SIMD },
        { {0x60, 0xef, 0xb1, 0x09}, CDISASM_ARM_NAME_VMUL, 4,
          CDISASM_ARM_INSTRUCTION_FLAG_SIMD },
        { {0x40, 0xff, 0xb1, 0x0d}, CDISASM_ARM_NAME_VMUL, 4,
          CDISASM_ARM_INSTRUCTION_FLAG_SIMD
              | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT }
    };
    static const uint8_t vadd_i8[] = {0x41, 0xef, 0xa0, 0x08};
    static const uint8_t vadd_f32_q[] = {0x40, 0xef, 0xe2, 0x0d};
    static const uint8_t vand_q[] = {0x40, 0xef, 0xf2, 0x01};
    static const uint8_t vmul_i32_q[] = {0x60, 0xef, 0xf2, 0x09};
    cdisasm_arm_instruction instruction;
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        instruction = decode_ok(
            CDISASM_ARM_CPU_CORTEX_A9_NEON,
            cases[index].bytes,
            sizeof(cases[index].bytes),
            0,
            4,
            cases[index].name);
        EXPECT(instruction.instruction_flags == cases[index].flags);
        EXPECT(CDISASM_ARM_VECTOR_ELEMENT_SIZE(&instruction.operand[0])
            == cases[index].element_size);
    }

    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A9_NEON,
        vadd_i8,
        sizeof(vadd_i8),
        UINT64_C(0x2000),
        4,
        CDISASM_ARM_NAME_VADD);
    EXPECT(instruction.raw_instruction == UINT32_C(0x08a0ef41));
    EXPECT(instruction.instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
    EXPECT(instruction.operand_count == 3);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_D16);
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_D17);
    EXPECT(instruction.operand[2].reg == CDISASM_ARM_REG_D16);
    EXPECT(instruction.operand[0].size == 8);
    EXPECT(CDISASM_ARM_VECTOR_ELEMENT_SIZE(&instruction.operand[0]) == 1);
    EXPECT(CDISASM_ARM_VECTOR_ELEMENT_COUNT(&instruction.operand[0]) == 8);

    expect_error(
        CDISASM_ARM_CPU_CORTEX_A9,
        vadd_i8,
        sizeof(vadd_i8),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(
        CDISASM_ARM_CPU_CORTEX_A7,
        vadd_i8,
        sizeof(vadd_i8),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A7_NEON,
        vadd_i8,
        sizeof(vadd_i8),
        0,
        4,
        CDISASM_ARM_NAME_VADD);

    instruction = decode_ok(
        CDISASM_ARM_CPU_APPLE_A4,
        vadd_f32_q,
        sizeof(vadd_f32_q),
        0,
        4,
        CDISASM_ARM_NAME_VADD);
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_Q8);
    EXPECT(instruction.operand[2].reg == CDISASM_ARM_REG_Q9);
    EXPECT(instruction.operand[0].size == 16);
    EXPECT(CDISASM_ARM_VECTOR_ELEMENT_SIZE(&instruction.operand[0]) == 4);
    EXPECT(CDISASM_ARM_VECTOR_ELEMENT_COUNT(&instruction.operand[0]) == 4);

    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A7_NEON,
        vand_q,
        sizeof(vand_q),
        0,
        4,
        CDISASM_ARM_NAME_VAND);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_Q8);
    EXPECT(CDISASM_ARM_VECTOR_ELEMENT_COUNT(&instruction.operand[0]) == 16);

    instruction = decode_ok(
        CDISASM_ARM_CPU_CORTEX_A7_NEON,
        vmul_i32_q,
        sizeof(vmul_i32_q),
        0,
        4,
        CDISASM_ARM_NAME_VMUL);
    EXPECT(CDISASM_ARM_VECTOR_ELEMENT_SIZE(&instruction.operand[0]) == 4);
    EXPECT(CDISASM_ARM_VECTOR_ELEMENT_COUNT(&instruction.operand[0]) == 4);

    expect_error(
        CDISASM_ARM_CPU_APPLE_A11,
        vadd_i8,
        sizeof(vadd_i8),
        CDISASM_STATUS_INVALID_ARGUMENT);
    expect_error(
        CDISASM_ARM_CPU_APPLE_S10,
        vadd_i8,
        sizeof(vadd_i8),
        CDISASM_STATUS_INVALID_ARGUMENT);
}

int main(void)
{
    test_control_flow();
    test_data_processing();
    test_memory_and_lists();
    test_contracts();
    test_neon();

    if (failures != 0) {
        fprintf(stderr, "%d T32 assertion(s) failed\n", failures);
        return 1;
    }
    puts("cdisasm T32 tests passed");
    return 0;
}
