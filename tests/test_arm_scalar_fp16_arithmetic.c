#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#include <stdio.h>
#include <string.h>

typedef struct fp16_case {
    uint32_t word;
    cdisasm_arm_name_id name;
    uint8_t vd, vn, vm;
    uint8_t accumulate;
} fp16_case;

static const fp16_case cases[] = {
    {0xee011982, CDISASM_ARM_NAME_VMLA, 2, 3, 4, 1},
    {0xee432963, CDISASM_ARM_NAME_VMLS, 5, 6, 7, 1},
    {0xee144985, CDISASM_ARM_NAME_VNMLS, 8, 9, 10, 1},
    {0xee565966, CDISASM_ARM_NAME_VNMLA, 11, 12, 13, 1},
    {0xee277988, CDISASM_ARM_NAME_VMUL, 14, 15, 16, 0},
    {0xee698969, CDISASM_ARM_NAME_VNMUL, 17, 18, 19, 0},
    {0xee3aa98b, CDISASM_ARM_NAME_VADD, 20, 21, 22, 0},
    {0xee7cb96c, CDISASM_ARM_NAME_VSUB, 23, 24, 25, 0},
    {0xee8dd98e, CDISASM_ARM_NAME_VDIV, 26, 27, 28, 0},
    {0xeedfe92f, CDISASM_ARM_NAME_VFNMS, 29, 30, 31, 1},
    {0xeed10961, CDISASM_ARM_NAME_VFNMA, 1, 2, 3, 1},
    {0xeea22983, CDISASM_ARM_NAME_VFMA, 4, 5, 6, 1},
    {0xeee43964, CDISASM_ARM_NAME_VFMS, 7, 8, 9, 1}
};

static const fp16_case t32_select_cases[] = {
    {0xfe011982, CDISASM_ARM_NAME_VSELEQ, 2, 3, 4, 0},
    {0xfe532923, CDISASM_ARM_NAME_VSELVS, 5, 6, 7, 0},
    {0xfe244985, CDISASM_ARM_NAME_VSELGE, 8, 9, 10, 0},
    {0xfe765926, CDISASM_ARM_NAME_VSELGT, 11, 12, 13, 0},
    {0xfe877988, CDISASM_ARM_NAME_VMAXNM, 14, 15, 16, 0},
    {0xfec98969, CDISASM_ARM_NAME_VMINNM, 17, 18, 19, 0}
};

typedef struct fp16_transfer_case {
    uint32_t word;
    uint8_t rt, hn, to_core;
} fp16_transfer_case;

static const fp16_transfer_case transfer_cases[] = {
    {0xee013910, 3, 2, 0},
    {0xee135990, 5, 7, 1}
};

static const fp16_case t32_rounding_cases[] = {
    {0xfebc19e1, CDISASM_ARM_NAME_VCVTA, 2, 0, 3, 0},
    {0xfebd2962, CDISASM_ARM_NAME_VCVTN, 4, 0, 5, 0},
    {0xfebe39e3, CDISASM_ARM_NAME_VCVTP, 6, 0, 7, 0},
    {0xfebf4964, CDISASM_ARM_NAME_VCVTM, 8, 0, 9, 0}
};

static const fp16_case t32_fp16_round_cases[] = {
    {0xfeb81961, CDISASM_ARM_NAME_VRINTA, 2, 0, 3, 0},
    {0xfeb92962, CDISASM_ARM_NAME_VRINTN, 4, 0, 5, 0},
    {0xfeba3963, CDISASM_ARM_NAME_VRINTP, 6, 0, 7, 0},
    {0xfebb4964, CDISASM_ARM_NAME_VRINTM, 8, 0, 9, 0}
};

static const fp16_case t32_fp16_insert_extract_cases[] = {
    {0xfeb01a61, CDISASM_ARM_NAME_VMOVX, 2, 0, 3, 0},
    {0xfeb02ae2, CDISASM_ARM_NAME_VINS, 4, 0, 5, 1}
};

static const fp16_case fp16_to_int_cases[] = {
    {0xeebc1961, CDISASM_ARM_NAME_VCVTR, 2, 0, 3, 0},
    {0xeebd2962, CDISASM_ARM_NAME_VCVTR, 4, 0, 5, 0},
    {0xeebc39e3, CDISASM_ARM_NAME_VCVT, 6, 0, 7, 0},
    {0xeebd49e4, CDISASM_ARM_NAME_VCVT, 8, 0, 9, 0}
};

static const fp16_case int_to_fp16_cases[] = {
    {0xeeb81961, CDISASM_ARM_NAME_VCVT, 2, 0, 3, 0},
    {0xeeb829e2, CDISASM_ARM_NAME_VCVT, 4, 0, 5, 0}
};

typedef struct fp16_fixed_case {
    cdisasm_arm_mode mode;
    uint32_t word;
    uint8_t hd, fbits;
} fp16_fixed_case;

typedef struct fp16_load_store_case {
    uint32_t word;
    cdisasm_arm_name_id name;
    uint8_t hd, rn;
    int64_t displacement;
    cdisasm_operand_access register_access, memory_access;
} fp16_load_store_case;

static const fp16_fixed_case fixed_cases[] = {
    {CDISASM_ARM_MODE_A32, 0xeeba1964, 2, 7},
    {CDISASM_ARM_MODE_A32, 0xeebf2944, 4, 8},
    {CDISASM_ARM_MODE_T32, 0xeebb3965, 6, 5},
    {CDISASM_ARM_MODE_T32, 0xeebe4942, 8, 12}
};

static const fp16_load_store_case t32_load_store_cases[] = {
    {0xed831906, CDISASM_ARM_NAME_VSTR, 2, 3, 12,
        CDISASM_OPERAND_ACCESS_READ, CDISASM_OPERAND_ACCESS_WRITE},
    {0xed15290a, CDISASM_ARM_NAME_VLDR, 4, 5, -20,
        CDISASM_OPERAND_ACCESS_WRITE, CDISASM_OPERAND_ACCESS_READ},
    {0xed9f3900, CDISASM_ARM_NAME_VLDR, 6, 15, 0,
        CDISASM_OPERAND_ACCESS_WRITE, CDISASM_OPERAND_ACCESS_READ}
};

static int failures;
#define EXPECT(x) do { if (!(x)) { ++failures; fprintf(stderr, \
    "%s:%d: %s\n", __FILE__, __LINE__, #x); } } while (0)

static void bytes_for_mode(uint32_t word, cdisasm_arm_mode mode,
                           uint8_t bytes[4])
{
    if (mode == CDISASM_ARM_MODE_A32 || mode == CDISASM_ARM_MODE_A64) {
        bytes[0] = (uint8_t)word;
        bytes[1] = (uint8_t)(word >> 8);
        bytes[2] = (uint8_t)(word >> 16);
        bytes[3] = (uint8_t)(word >> 24);
    } else {
        bytes[0] = (uint8_t)(word >> 16);
        bytes[1] = (uint8_t)(word >> 24);
        bytes[2] = (uint8_t)word;
        bytes[3] = (uint8_t)(word >> 8);
    }
}

#if USE_EXTRA_OPCODES
static int hreg(const cdisasm_arm_operand *operand, unsigned encoded,
                cdisasm_operand_access access)
{
    return operand->type == CDISASM_OPERAND_REGISTER
        && operand->reg == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_H0 + encoded)
        && operand->size == 2u && operand->access == access;
}
#endif

int main(void)
{
    for (unsigned mode_index = 0; mode_index < 2; ++mode_index) {
        cdisasm_arm_mode mode = mode_index == 0
            ? CDISASM_ARM_MODE_A32 : CDISASM_ARM_MODE_T32;
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            cdisasm_arm_instruction instruction;
            uint8_t bytes[4];
            uint32_t decoded;

            bytes_for_mode(cases[i].word, mode, bytes);
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, mode, bytes, 4u,
                UINT64_C(0x190000), CDISASM_ARM_DECODE_OPTION_NONE,
                &instruction);
#if USE_EXTRA_OPCODES
            EXPECT(decoded == 4u);
            EXPECT(instruction.name_id == cases[i].name);
            EXPECT(instruction.condition == CDISASM_ARM_CONDITION_AL);
            EXPECT(instruction.instruction_flags
                == CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
            EXPECT(instruction.operand_count == 3u);
            EXPECT(hreg(&instruction.operand[0], cases[i].vd,
                cases[i].accumulate ? CDISASM_OPERAND_ACCESS_READ_WRITE
                                    : CDISASM_OPERAND_ACCESS_WRITE));
            EXPECT(hreg(&instruction.operand[1], cases[i].vn,
                CDISASM_OPERAND_ACCESS_READ));
            EXPECT(hreg(&instruction.operand[2], cases[i].vm,
                CDISASM_OPERAND_ACCESS_READ));
#else
            cdisasm_arm_instruction expected;
            memset(&expected, 0, sizeof(expected));
            expected.last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
            EXPECT(decoded == 0u);
            EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
#endif
        }
    }
    for (size_t i = 0;
         i < sizeof(t32_load_store_cases)
             / sizeof(t32_load_store_cases[0]); ++i) {
        const fp16_load_store_case *test = &t32_load_store_cases[i];
        cdisasm_arm_instruction instruction;
        const cdisasm_arm_operand *memory;
        uint8_t bytes[4];
        uint32_t decoded;

        bytes_for_mode(test->word, CDISASM_ARM_MODE_T32, bytes);
        memset(&instruction, 0xa5, sizeof(instruction));
        decoded = cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_T32, bytes, 4u, UINT64_C(0x190700),
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
        EXPECT(decoded == 4u);
        EXPECT(instruction.name_id == test->name);
        EXPECT(instruction.instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
        EXPECT(instruction.operand_count == 2u);
        EXPECT(hreg(&instruction.operand[0], test->hd,
            test->register_access));
        memory = &instruction.operand[1];
        EXPECT(memory->type == CDISASM_OPERAND_MEMORY);
        EXPECT(memory->size == 2u);
        EXPECT(memory->base_reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0 + test->rn));
        EXPECT(memory->imm == (uint64_t)test->displacement);
        EXPECT(memory->access == test->memory_access);
        if (test->displacement < 0) {
            EXPECT(memory->flags
                == (CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
                    | CDISASM_OPERAND_FLAG_SIGNED));
        } else if (test->displacement > 0) {
            EXPECT(memory->flags == CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT);
        } else {
            EXPECT(memory->flags == 0u);
        }
#else
        (void)memory;
        cdisasm_arm_instruction expected;
        memset(&expected, 0, sizeof(expected));
        expected.last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        EXPECT(decoded == 0u);
        EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
#endif
    }
    for (size_t i = 0; i < sizeof(fixed_cases) / sizeof(fixed_cases[0]); ++i) {
        cdisasm_arm_instruction instruction;
        uint8_t bytes[4];
        uint32_t decoded;

        bytes_for_mode(fixed_cases[i].word, fixed_cases[i].mode, bytes);
        memset(&instruction, 0xa5, sizeof(instruction));
        decoded = cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, fixed_cases[i].mode,
            bytes, 4u, UINT64_C(0x190600),
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
        EXPECT(decoded == 4u);
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_VCVT);
        EXPECT(instruction.instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
        EXPECT(instruction.operand_count == 3u);
        EXPECT(hreg(&instruction.operand[0], fixed_cases[i].hd,
            CDISASM_OPERAND_ACCESS_WRITE));
        EXPECT(hreg(&instruction.operand[1], fixed_cases[i].hd,
            CDISASM_OPERAND_ACCESS_READ));
        EXPECT(instruction.operand[2].type == CDISASM_OPERAND_IMMEDIATE);
        EXPECT(instruction.operand[2].imm == fixed_cases[i].fbits);
#else
        cdisasm_arm_instruction expected;
        memset(&expected, 0, sizeof(expected));
        expected.last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        EXPECT(decoded == 0u);
        EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
#endif
    }
    {
        cdisasm_arm_instruction instruction;
        uint8_t bytes[4];
        bytes_for_mode(UINT32_C(0xeeba196c), CDISASM_ARM_MODE_A32, bytes);
        EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A32,
            bytes, 4u, 0u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    for (unsigned mode_index = 0; mode_index < 2; ++mode_index) {
        cdisasm_arm_mode mode = mode_index == 0
            ? CDISASM_ARM_MODE_A32 : CDISASM_ARM_MODE_T32;
        for (size_t i = 0;
             i < sizeof(int_to_fp16_cases) / sizeof(int_to_fp16_cases[0]); ++i) {
            cdisasm_arm_instruction instruction;
            uint8_t bytes[4];
            uint32_t decoded;

            bytes_for_mode(int_to_fp16_cases[i].word, mode, bytes);
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, mode, bytes, 4u,
                UINT64_C(0x190500), CDISASM_ARM_DECODE_OPTION_NONE,
                &instruction);
#if USE_EXTRA_OPCODES
            EXPECT(decoded == 4u);
            EXPECT(instruction.name_id == CDISASM_ARM_NAME_VCVT);
            EXPECT(instruction.instruction_flags
                == CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
            EXPECT(instruction.operand_count == 2u);
            EXPECT(hreg(&instruction.operand[0], int_to_fp16_cases[i].vd,
                CDISASM_OPERAND_ACCESS_WRITE));
            EXPECT(instruction.operand[1].reg
                == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0
                    + int_to_fp16_cases[i].vm));
            EXPECT(instruction.operand[1].size == 4u);
            EXPECT(instruction.operand[1].access
                == CDISASM_OPERAND_ACCESS_READ);
#else
            cdisasm_arm_instruction expected;
            memset(&expected, 0, sizeof(expected));
            expected.last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
            EXPECT(decoded == 0u);
            EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
#endif
        }
    }
    for (size_t i = 0;
         i < sizeof(t32_rounding_cases) / sizeof(t32_rounding_cases[0]); ++i) {
        cdisasm_arm_instruction instruction;
        uint8_t bytes[4];
        uint32_t decoded;

        bytes_for_mode(t32_rounding_cases[i].word,
            CDISASM_ARM_MODE_T32, bytes);
        memset(&instruction, 0xa5, sizeof(instruction));
        decoded = cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_T32, bytes, 4u, UINT64_C(0x190300),
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
        EXPECT(decoded == 4u);
        EXPECT(instruction.name_id == t32_rounding_cases[i].name);
        EXPECT(instruction.instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
        EXPECT(instruction.operand_count == 2u);
        EXPECT(instruction.operand[0].reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0
                + t32_rounding_cases[i].vd));
        EXPECT(instruction.operand[0].size == 4u);
        EXPECT(instruction.operand[0].access
            == CDISASM_OPERAND_ACCESS_WRITE);
        EXPECT(hreg(&instruction.operand[1], t32_rounding_cases[i].vm,
            CDISASM_OPERAND_ACCESS_READ));
#else
        cdisasm_arm_instruction expected;
        memset(&expected, 0, sizeof(expected));
        expected.last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        EXPECT(decoded == 0u);
        EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
#endif
    }
    for (size_t i = 0;
         i < sizeof(t32_fp16_round_cases)
             / sizeof(t32_fp16_round_cases[0]); ++i) {
        cdisasm_arm_instruction instruction;
        uint8_t bytes[4];
        uint32_t decoded;

        bytes_for_mode(t32_fp16_round_cases[i].word,
            CDISASM_ARM_MODE_T32, bytes);
        memset(&instruction, 0xa5, sizeof(instruction));
        decoded = cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_T32, bytes, 4u, UINT64_C(0x190380),
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
        EXPECT(decoded == 4u);
        EXPECT(instruction.name_id == t32_fp16_round_cases[i].name);
        EXPECT(instruction.instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
        EXPECT(instruction.operand_count == 2u);
        EXPECT(hreg(&instruction.operand[0], t32_fp16_round_cases[i].vd,
            CDISASM_OPERAND_ACCESS_WRITE));
        EXPECT(hreg(&instruction.operand[1], t32_fp16_round_cases[i].vm,
            CDISASM_OPERAND_ACCESS_READ));
#else
        cdisasm_arm_instruction expected;
        memset(&expected, 0, sizeof(expected));
        expected.last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        EXPECT(decoded == 0u);
        EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
#endif
    }
    for (size_t i = 0;
         i < sizeof(t32_fp16_insert_extract_cases)
             / sizeof(t32_fp16_insert_extract_cases[0]); ++i) {
        const fp16_case *test = &t32_fp16_insert_extract_cases[i];
        cdisasm_arm_instruction instruction;
        uint8_t bytes[4];
        uint32_t decoded;

        bytes_for_mode(test->word, CDISASM_ARM_MODE_T32, bytes);
        memset(&instruction, 0xa5, sizeof(instruction));
        decoded = cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_T32, bytes, 4u, UINT64_C(0x190400),
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
        EXPECT(decoded == 4u);
        EXPECT(instruction.name_id == test->name);
        EXPECT(instruction.instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
        EXPECT(instruction.operand_count == 2u);
        EXPECT(instruction.operand[0].reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0 + test->vd));
        EXPECT(instruction.operand[0].size == 4u);
        EXPECT(instruction.operand[0].access == (test->accumulate
            ? CDISASM_OPERAND_ACCESS_READ_WRITE
            : CDISASM_OPERAND_ACCESS_WRITE));
        EXPECT(instruction.operand[1].reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0 + test->vm));
        EXPECT(instruction.operand[1].size == 4u);
        EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
#else
        cdisasm_arm_instruction expected;
        memset(&expected, 0, sizeof(expected));
        expected.last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        EXPECT(decoded == 0u);
        EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
#endif
    }
    for (unsigned mode_index = 0; mode_index < 2; ++mode_index) {
        cdisasm_arm_mode mode = mode_index == 0
            ? CDISASM_ARM_MODE_A32 : CDISASM_ARM_MODE_T32;
        for (size_t i = 0;
             i < sizeof(fp16_to_int_cases) / sizeof(fp16_to_int_cases[0]); ++i) {
            cdisasm_arm_instruction instruction;
            uint8_t bytes[4];
            uint32_t decoded;

            bytes_for_mode(fp16_to_int_cases[i].word, mode, bytes);
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, mode, bytes, 4u,
                UINT64_C(0x190400), CDISASM_ARM_DECODE_OPTION_NONE,
                &instruction);
#if USE_EXTRA_OPCODES
            EXPECT(decoded == 4u);
            EXPECT(instruction.name_id == fp16_to_int_cases[i].name);
            EXPECT(instruction.instruction_flags
                == CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
            EXPECT(instruction.operand_count == 2u);
            EXPECT(instruction.operand[0].reg
                == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0
                    + fp16_to_int_cases[i].vd));
            EXPECT(instruction.operand[0].size == 4u);
            EXPECT(instruction.operand[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            EXPECT(hreg(&instruction.operand[1], fp16_to_int_cases[i].vm,
                CDISASM_OPERAND_ACCESS_READ));
#else
            cdisasm_arm_instruction expected;
            memset(&expected, 0, sizeof(expected));
            expected.last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
            EXPECT(decoded == 0u);
            EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
#endif
        }
    }
    for (size_t i = 0;
         i < sizeof(t32_select_cases) / sizeof(t32_select_cases[0]); ++i) {
        cdisasm_arm_instruction instruction;
        uint8_t bytes[4];
        uint32_t decoded;

        bytes_for_mode(t32_select_cases[i].word,
            CDISASM_ARM_MODE_T32, bytes);
        memset(&instruction, 0xa5, sizeof(instruction));
        decoded = cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_T32, bytes, 4u, UINT64_C(0x190100),
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
        EXPECT(decoded == 4u);
        EXPECT(instruction.name_id == t32_select_cases[i].name);
        EXPECT(instruction.instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
        EXPECT(instruction.operand_count == 3u);
        EXPECT(hreg(&instruction.operand[0], t32_select_cases[i].vd,
            CDISASM_OPERAND_ACCESS_WRITE));
        EXPECT(hreg(&instruction.operand[1], t32_select_cases[i].vn,
            CDISASM_OPERAND_ACCESS_READ));
        EXPECT(hreg(&instruction.operand[2], t32_select_cases[i].vm,
            CDISASM_OPERAND_ACCESS_READ));
#else
        cdisasm_arm_instruction expected;
        memset(&expected, 0, sizeof(expected));
        expected.last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        EXPECT(decoded == 0u);
        EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
#endif
    }
    for (unsigned mode_index = 0; mode_index < 2; ++mode_index) {
        cdisasm_arm_mode mode = mode_index == 0
            ? CDISASM_ARM_MODE_A32 : CDISASM_ARM_MODE_T32;
        for (size_t i = 0;
             i < sizeof(transfer_cases) / sizeof(transfer_cases[0]); ++i) {
            cdisasm_arm_instruction instruction;
            uint8_t bytes[4];
            uint32_t decoded;

            bytes_for_mode(transfer_cases[i].word, mode, bytes);
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, mode, bytes, 4u,
                UINT64_C(0x190200), CDISASM_ARM_DECODE_OPTION_NONE,
                &instruction);
#if USE_EXTRA_OPCODES
            EXPECT(decoded == 4u);
            EXPECT(instruction.name_id == CDISASM_ARM_NAME_VMOV);
            EXPECT(instruction.instruction_flags
                == CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
            EXPECT(instruction.operand_count == 2u);
            if (transfer_cases[i].to_core) {
                EXPECT(instruction.operand[0].reg
                    == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0
                        + transfer_cases[i].rt));
                EXPECT(instruction.operand[0].size == 4u);
                EXPECT(instruction.operand[0].access
                    == CDISASM_OPERAND_ACCESS_WRITE);
                EXPECT(hreg(&instruction.operand[1], transfer_cases[i].hn,
                    CDISASM_OPERAND_ACCESS_READ));
            } else {
                EXPECT(hreg(&instruction.operand[0], transfer_cases[i].hn,
                    CDISASM_OPERAND_ACCESS_WRITE));
                EXPECT(instruction.operand[1].reg
                    == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0
                        + transfer_cases[i].rt));
                EXPECT(instruction.operand[1].size == 4u);
                EXPECT(instruction.operand[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
            }
#else
            cdisasm_arm_instruction expected;
            memset(&expected, 0, sizeof(expected));
            expected.last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
            EXPECT(decoded == 0u);
            EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
#endif
        }
    }
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction instruction;
        uint8_t bytes[4];
        bytes_for_mode(cases[0].word, CDISASM_ARM_MODE_A32, bytes);
        EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_APPLE_A7, CDISASM_ARM_MODE_A32,
            bytes, 4u, 0u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    {
        cdisasm_arm_instruction instruction;
        uint8_t bytes[4];

        bytes_for_mode(UINT32_C(0x1ee020e8), CDISASM_ARM_MODE_A64, bytes);
        EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            bytes, 4u, UINT64_C(0x190800), CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 4u);
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_FCMP);
        EXPECT(instruction.instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
                | CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS));
        EXPECT(instruction.operand_count == 2u);
        EXPECT(hreg(&instruction.operand[0], 7u,
            CDISASM_OPERAND_ACCESS_READ));
        EXPECT(instruction.operand[1].type == CDISASM_OPERAND_IMMEDIATE);
        EXPECT(instruction.operand[1].imm == 0u);

        bytes_for_mode(UINT32_C(0x1eef1009), CDISASM_ARM_MODE_A64, bytes);
        EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            bytes, 4u, UINT64_C(0x190804), CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction) == 4u);
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_FMOV);
        EXPECT(instruction.instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
        EXPECT(instruction.operand_count == 2u);
        EXPECT(hreg(&instruction.operand[0], 9u,
            CDISASM_OPERAND_ACCESS_WRITE));
        EXPECT(instruction.operand[1].type == CDISASM_OPERAND_IMMEDIATE);
        EXPECT(instruction.operand[1].imm == UINT64_C(0x3e00));

        EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_APPLE_A7,
            CDISASM_ARM_MODE_A64, bytes, 4u, UINT64_C(0x190804),
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    {
        static const fp16_case zero_compare_cases[] = {
            {0x5ef8c841, CDISASM_ARM_NAME_FCMGT, 1, 2, 0, 0},
            {0x5ef8d883, CDISASM_ARM_NAME_FCMEQ, 3, 4, 0, 0},
            {0x5ef8e8c5, CDISASM_ARM_NAME_FCMLT, 5, 6, 0, 0},
            {0x7ef8c907, CDISASM_ARM_NAME_FCMGE, 7, 8, 0, 0},
            {0x7ef8d949, CDISASM_ARM_NAME_FCMLE, 9, 10, 0, 0}
        };
        static const fp16_case pairwise_cases[] = {
            {0x5e30c98b, CDISASM_ARM_NAME_FMAXNMP, 11, 12, 0, 0},
            {0x5e30d9cd, CDISASM_ARM_NAME_FADDP, 13, 14, 0, 0},
            {0x5e30fa0f, CDISASM_ARM_NAME_FMAXP, 15, 16, 0, 0},
            {0x5eb0ca51, CDISASM_ARM_NAME_FMINNMP, 17, 18, 0, 0},
            {0x5eb0fa93, CDISASM_ARM_NAME_FMINP, 19, 20, 0, 0}
        };
        cdisasm_arm_instruction instruction;
        uint8_t bytes[4];

        for (size_t i = 0; i < sizeof(zero_compare_cases)
                / sizeof(zero_compare_cases[0]); ++i) {
            const fp16_case *test = &zero_compare_cases[i];
            bytes_for_mode(test->word, CDISASM_ARM_MODE_A64, bytes);
            EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
                CDISASM_ARM_MODE_A64, bytes, 4u, UINT64_C(0x190900),
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
            EXPECT(instruction.name_id == test->name);
            EXPECT(instruction.instruction_flags
                == CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
            EXPECT(instruction.operand_count == 3u);
            EXPECT(hreg(&instruction.operand[0], test->vd,
                CDISASM_OPERAND_ACCESS_WRITE));
            EXPECT(hreg(&instruction.operand[1], test->vn,
                CDISASM_OPERAND_ACCESS_READ));
            EXPECT(instruction.operand[2].type == CDISASM_OPERAND_IMMEDIATE);
            EXPECT(instruction.operand[2].imm == 0u);
        }
        for (size_t i = 0; i < sizeof(pairwise_cases)
                / sizeof(pairwise_cases[0]); ++i) {
            const fp16_case *test = &pairwise_cases[i];
            bytes_for_mode(test->word, CDISASM_ARM_MODE_A64, bytes);
            EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
                CDISASM_ARM_MODE_A64, bytes, 4u, UINT64_C(0x190940),
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
            EXPECT(instruction.name_id == test->name);
            EXPECT(instruction.instruction_flags
                == CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
            EXPECT(instruction.operand_count == 2u);
            EXPECT(hreg(&instruction.operand[0], test->vd,
                CDISASM_OPERAND_ACCESS_WRITE));
            EXPECT(instruction.operand[1].type == CDISASM_OPERAND_REGISTER);
            EXPECT(instruction.operand[1].reg
                == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + test->vn));
            EXPECT(instruction.operand[1].size == 4u);
            EXPECT(instruction.operand[1].extend_type == 2u);
            EXPECT(instruction.operand[1].scale == 2u);
            EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
        }
        bytes_for_mode(zero_compare_cases[0].word,
            CDISASM_ARM_MODE_A64, bytes);
        EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_APPLE_A7,
            CDISASM_ARM_MODE_A64, bytes, 4u, UINT64_C(0x190980),
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    {
        static const fp16_case scalar_sd_cases[] = {
            {0x5ea0c841, CDISASM_ARM_NAME_FCMGT, 1, 2, 4, 0},
            {0x5ee0d883, CDISASM_ARM_NAME_FCMEQ, 3, 4, 8, 0},
            {0x5ea0e8c5, CDISASM_ARM_NAME_FCMLT, 5, 6, 4, 0},
            {0x7ee0c907, CDISASM_ARM_NAME_FCMGE, 7, 8, 8, 0},
            {0x7ea0d949, CDISASM_ARM_NAME_FCMLE, 9, 10, 4, 0},
            {0x7e30c98b, CDISASM_ARM_NAME_FMAXNMP, 11, 12, 4, 1},
            {0x7e70c9cd, CDISASM_ARM_NAME_FMAXNMP, 13, 14, 8, 1},
            {0x7e30da0f, CDISASM_ARM_NAME_FADDP, 15, 16, 4, 1},
            {0x7e70da51, CDISASM_ARM_NAME_FADDP, 17, 18, 8, 1},
            {0x7e30fa93, CDISASM_ARM_NAME_FMAXP, 19, 20, 4, 1},
            {0x7e70fad5, CDISASM_ARM_NAME_FMAXP, 21, 22, 8, 1},
            {0x7eb0cb17, CDISASM_ARM_NAME_FMINNMP, 23, 24, 4, 1},
            {0x7ef0cb59, CDISASM_ARM_NAME_FMINNMP, 25, 26, 8, 1},
            {0x7eb0fb9b, CDISASM_ARM_NAME_FMINP, 27, 28, 4, 1},
            {0x7ef0fbdd, CDISASM_ARM_NAME_FMINP, 29, 30, 8, 1}
        };
        cdisasm_arm_instruction instruction;
        uint8_t bytes[4];

        for (size_t i = 0; i < sizeof(scalar_sd_cases)
                / sizeof(scalar_sd_cases[0]); ++i) {
            const fp16_case *test = &scalar_sd_cases[i];
            cdisasm_arm_reg_id scalar_base = test->vm == 4u
                ? CDISASM_ARM_REG_S0 : CDISASM_ARM_REG_D0;

            bytes_for_mode(test->word, CDISASM_ARM_MODE_A64, bytes);
            EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
                CDISASM_ARM_MODE_A64, bytes, 4u, UINT64_C(0x190a00),
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
            EXPECT(instruction.name_id == test->name);
            EXPECT(instruction.instruction_flags
                == CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
            EXPECT(instruction.operand_count == (test->accumulate ? 2u : 3u));
            EXPECT(instruction.operand[0].reg
                == (cdisasm_arm_reg_id)(scalar_base + test->vd));
            EXPECT(instruction.operand[0].size == test->vm);
            EXPECT(instruction.operand[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            if (test->accumulate) {
                EXPECT(instruction.operand[1].reg
                    == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + test->vn));
                EXPECT(instruction.operand[1].size == test->vm * 2u);
                EXPECT(instruction.operand[1].extend_type == test->vm);
                EXPECT(instruction.operand[1].scale == 2u);
            } else {
                EXPECT(instruction.operand[1].reg
                    == (cdisasm_arm_reg_id)(scalar_base + test->vn));
                EXPECT(instruction.operand[1].size == test->vm);
                EXPECT(instruction.operand[2].type
                    == CDISASM_OPERAND_IMMEDIATE);
                EXPECT(instruction.operand[2].imm == 0u);
            }
            EXPECT(instruction.operand[1].access
                == CDISASM_OPERAND_ACCESS_READ);
        }
    }
    {
        static const fp16_case vector_half_cases[] = {
            {0x0ef8c841, CDISASM_ARM_NAME_FCMGT, 1, 2, 0, 0},
            {0x4ef8d883, CDISASM_ARM_NAME_FCMEQ, 3, 4, 0, 0},
            {0x0ef8e8c5, CDISASM_ARM_NAME_FCMLT, 5, 6, 0, 0},
            {0x6ef8c907, CDISASM_ARM_NAME_FCMGE, 7, 8, 0, 0},
            {0x2ef8d949, CDISASM_ARM_NAME_FCMLE, 9, 10, 0, 0},
            {0x2e4d058b, CDISASM_ARM_NAME_FMAXNMP, 11, 12, 13, 1},
            {0x6e5015ee, CDISASM_ARM_NAME_FADDP, 14, 15, 16, 1},
            {0x2e533651, CDISASM_ARM_NAME_FMAXP, 17, 18, 19, 1},
            {0x6ed606b4, CDISASM_ARM_NAME_FMINNMP, 20, 21, 22, 1},
            {0x2ed93717, CDISASM_ARM_NAME_FMINP, 23, 24, 25, 1}
        };
        cdisasm_arm_instruction instruction;
        uint8_t bytes[4];

        for (size_t i = 0; i < sizeof(vector_half_cases)
                / sizeof(vector_half_cases[0]); ++i) {
            const fp16_case *test = &vector_half_cases[i];
            uint8_t total_size = (test->word & UINT32_C(0x40000000)) != 0u
                ? 16u : 8u;

            bytes_for_mode(test->word, CDISASM_ARM_MODE_A64, bytes);
            EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
                CDISASM_ARM_MODE_A64, bytes, 4u, UINT64_C(0x190b00),
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
            EXPECT(instruction.name_id == test->name);
            EXPECT(instruction.instruction_flags
                == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
                    | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
            EXPECT(instruction.operand_count == 3u);
            EXPECT(instruction.operand[0].reg
                == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + test->vd));
            EXPECT(instruction.operand[0].size == total_size);
            EXPECT(instruction.operand[0].extend_type == 2u);
            EXPECT(instruction.operand[0].scale == total_size / 2u);
            EXPECT(instruction.operand[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            EXPECT(instruction.operand[1].reg
                == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + test->vn));
            EXPECT(instruction.operand[1].size == total_size);
            EXPECT(instruction.operand[1].extend_type == 2u);
            EXPECT(instruction.operand[1].scale == total_size / 2u);
            EXPECT(instruction.operand[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            if (test->accumulate) {
                EXPECT(instruction.operand[2].reg
                    == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + test->vm));
                EXPECT(instruction.operand[2].size == total_size);
                EXPECT(instruction.operand[2].extend_type == 2u);
                EXPECT(instruction.operand[2].scale == total_size / 2u);
                EXPECT(instruction.operand[2].access
                    == CDISASM_OPERAND_ACCESS_READ);
            } else {
                EXPECT(instruction.operand[2].type
                    == CDISASM_OPERAND_IMMEDIATE);
                EXPECT(instruction.operand[2].imm == 0u);
            }
        }
        bytes_for_mode(vector_half_cases[0].word,
            CDISASM_ARM_MODE_A64, bytes);
        EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_APPLE_A7,
            CDISASM_ARM_MODE_A64, bytes, 4u, UINT64_C(0x190b80),
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    {
        static const fp16_case three_same_half_cases[] = {
            {0x0e430441, CDISASM_ARM_NAME_FMAXNM, 1, 2, 3, 0},
            {0x4e460ca4, CDISASM_ARM_NAME_FMLA, 4, 5, 6, 1},
            {0x0e491507, CDISASM_ARM_NAME_FADD, 7, 8, 9, 0},
            {0x4e4c1d6a, CDISASM_ARM_NAME_FMULX, 10, 11, 12, 0},
            {0x0e4f25cd, CDISASM_ARM_NAME_FCMEQ, 13, 14, 15, 0},
            {0x4e523630, CDISASM_ARM_NAME_FMAX, 16, 17, 18, 0},
            {0x0ed50693, CDISASM_ARM_NAME_FMINNM, 19, 20, 21, 0},
            {0x4ed80ef6, CDISASM_ARM_NAME_FMLS, 22, 23, 24, 1},
            {0x0edb1759, CDISASM_ARM_NAME_FSUB, 25, 26, 27, 0},
            {0x4ede37bc, CDISASM_ARM_NAME_FMIN, 28, 29, 30, 0},
            {0x2e431c41, CDISASM_ARM_NAME_FMUL, 1, 2, 3, 0},
            {0x6e4624a4, CDISASM_ARM_NAME_FCMGE, 4, 5, 6, 0},
            {0x2e492d07, CDISASM_ARM_NAME_FACGE, 7, 8, 9, 0},
            {0x6e4c3d6a, CDISASM_ARM_NAME_FDIV, 10, 11, 12, 0},
            {0x2ecf15cd, CDISASM_ARM_NAME_FABD, 13, 14, 15, 0},
            {0x6ed22630, CDISASM_ARM_NAME_FCMGT, 16, 17, 18, 0},
            {0x2ed52e93, CDISASM_ARM_NAME_FACGT, 19, 20, 21, 0}
        };
        cdisasm_arm_instruction instruction;
        uint8_t bytes[4];

        for (size_t i = 0; i < sizeof(three_same_half_cases)
                / sizeof(three_same_half_cases[0]); ++i) {
            const fp16_case *test = &three_same_half_cases[i];
            uint8_t total_size = (test->word & UINT32_C(0x40000000)) != 0u
                ? 16u : 8u;

            bytes_for_mode(test->word, CDISASM_ARM_MODE_A64, bytes);
            EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
                CDISASM_ARM_MODE_A64, bytes, 4u, UINT64_C(0x190c00),
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
            EXPECT(instruction.name_id == test->name);
            EXPECT(instruction.instruction_flags
                == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
                    | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
            EXPECT(instruction.operand_count == 3u);
            for (unsigned operand_index = 0; operand_index < 3u;
                 ++operand_index) {
                const cdisasm_arm_operand *operand =
                    &instruction.operand[operand_index];
                unsigned encoded = operand_index == 0u ? test->vd
                    : operand_index == 1u ? test->vn : test->vm;

                EXPECT(operand->type == CDISASM_OPERAND_REGISTER);
                EXPECT(operand->reg
                    == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + encoded));
                EXPECT(operand->size == total_size);
                EXPECT(operand->extend_type == 2u);
                EXPECT(operand->scale == total_size / 2u);
                EXPECT(operand->access == (operand_index == 0u
                    ? (test->accumulate
                        ? CDISASM_OPERAND_ACCESS_READ_WRITE
                        : CDISASM_OPERAND_ACCESS_WRITE)
                    : CDISASM_OPERAND_ACCESS_READ));
            }
        }
        bytes_for_mode(three_same_half_cases[0].word,
            CDISASM_ARM_MODE_A64, bytes);
        EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_APPLE_A7,
            CDISASM_ARM_MODE_A64, bytes, 4u, UINT64_C(0x190c80),
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    {
        static const fp16_case unary_half_cases[] = {
            {0x0e799841, CDISASM_ARM_NAME_FRINTM, 1, 2, 0, 0},
            {0x4e79d883, CDISASM_ARM_NAME_SCVTF, 3, 4, 0, 0},
            {0x0ef8f8c5, CDISASM_ARM_NAME_FABS, 5, 6, 0, 0},
            {0x4ef98907, CDISASM_ARM_NAME_FRINTP, 7, 8, 0, 0},
            {0x0ef99949, CDISASM_ARM_NAME_FRINTZ, 9, 10, 0, 0},
            {0x4ef9b98b, CDISASM_ARM_NAME_FCVTZS, 11, 12, 0, 0},
            {0x2e7989cd, CDISASM_ARM_NAME_FRINTA, 13, 14, 0, 0},
            {0x6e799a0f, CDISASM_ARM_NAME_FRINTX, 15, 16, 0, 0},
            {0x2e79da51, CDISASM_ARM_NAME_UCVTF, 17, 18, 0, 0},
            {0x6ef8fa93, CDISASM_ARM_NAME_FNEG, 19, 20, 0, 0},
            {0x2ef99ad5, CDISASM_ARM_NAME_FRINTI, 21, 22, 0, 0},
            {0x6ef9bb17, CDISASM_ARM_NAME_FCVTZU, 23, 24, 0, 0},
            {0x2ef9fb59, CDISASM_ARM_NAME_FSQRT, 25, 26, 0, 0},
            {0x4e798b9b, CDISASM_ARM_NAME_FRINTN, 27, 28, 0, 0}
        };
        cdisasm_arm_instruction instruction;
        uint8_t bytes[4];

        for (size_t i = 0; i < sizeof(unary_half_cases)
                / sizeof(unary_half_cases[0]); ++i) {
            const fp16_case *test = &unary_half_cases[i];
            uint8_t total_size = (test->word & UINT32_C(0x40000000)) != 0u
                ? 16u : 8u;

            bytes_for_mode(test->word, CDISASM_ARM_MODE_A64, bytes);
            EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,
                CDISASM_ARM_MODE_A64, bytes, 4u, UINT64_C(0x190d00),
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
            EXPECT(instruction.name_id == test->name);
            EXPECT(instruction.instruction_flags
                == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
                    | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
            EXPECT(instruction.operand_count == 2u);
            EXPECT(instruction.operand[0].reg
                == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + test->vd));
            EXPECT(instruction.operand[0].size == total_size);
            EXPECT(instruction.operand[0].extend_type == 2u);
            EXPECT(instruction.operand[0].scale == total_size / 2u);
            EXPECT(instruction.operand[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            EXPECT(instruction.operand[1].reg
                == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + test->vn));
            EXPECT(instruction.operand[1].size == total_size);
            EXPECT(instruction.operand[1].extend_type == 2u);
            EXPECT(instruction.operand[1].scale == total_size / 2u);
            EXPECT(instruction.operand[1].access
                == CDISASM_OPERAND_ACCESS_READ);
        }
        bytes_for_mode(unary_half_cases[0].word,
            CDISASM_ARM_MODE_A64, bytes);
        EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_APPLE_A7,
            CDISASM_ARM_MODE_A64, bytes, 4u, UINT64_C(0x190d80),
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
    }
#endif
    if (failures != 0) {
        fprintf(stderr, "%d scalar FP16 arithmetic failure(s)\n", failures);
        return 1;
    }
    puts("ARM scalar FP16 arithmetic tests passed");
    return 0;
}
