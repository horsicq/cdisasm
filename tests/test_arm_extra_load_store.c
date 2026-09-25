#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

static int failures;

#define EXPECT(condition)                                                   \
    do {                                                                    \
        if (!(condition)) {                                                 \
            fprintf(stderr, "%s:%d: expectation failed: %s\n",          \
                    __FILE__, __LINE__, #condition);                        \
            ++failures;                                                     \
        }                                                                   \
    } while (0)

static uint32_t decode(const uint8_t bytes[4], size_t size,
                       cdisasm_arm_instruction *instruction)
{
    return cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A32, bytes, size,
        UINT64_C(0x1000), CDISASM_ARM_DECODE_OPTION_NONE,
        instruction);
}

static uint32_t decode_t32(const uint8_t bytes[4], size_t size,
                           cdisasm_arm_instruction *instruction)
{
    return cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_T32, bytes, size,
        UINT64_C(0x1000), CDISASM_ARM_DECODE_OPTION_NONE,
        instruction);
}

static uint32_t decode_a64(const uint8_t bytes[4],
                           cdisasm_arm_instruction *instruction)
{
    return cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, bytes, 4u,
        UINT64_C(0x1000), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static void test_a64_lsui_exclusive(void)
{
    static const struct lsui_exclusive_case {
        uint8_t bytes[4];
        cdisasm_arm_form_id form;
        cdisasm_arm_name_id name;
        uint32_t flags;
        uint8_t size;
        int load;
#if USE_DISASM_FORMAT
        const char *text;
#endif
    } cases[] = {
        {{0x41,0x7c,0x00,0x89},4811,CDISASM_ARM_NAME_STTXR,
            CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
                | CDISASM_ARM_INSTRUCTION_FLAG_EXCLUSIVE,4,0,
#if USE_DISASM_FORMAT
            "sttxr w0, w1, [x2]"
#endif
        },
        {{0x41,0xfc,0x00,0x89},4812,CDISASM_ARM_NAME_STLTXR,
            CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
                | CDISASM_ARM_INSTRUCTION_FLAG_EXCLUSIVE
                | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE,4,0,
#if USE_DISASM_FORMAT
            "stltxr w0, w1, [x2]"
#endif
        },
        {{0x41,0x7c,0x5f,0x89},4813,CDISASM_ARM_NAME_LDTXR,
            CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
                | CDISASM_ARM_INSTRUCTION_FLAG_EXCLUSIVE,4,1,
#if USE_DISASM_FORMAT
            "ldtxr w1, [x2]"
#endif
        },
        {{0x41,0xfc,0x5f,0x89},4814,CDISASM_ARM_NAME_LDATXR,
            CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
                | CDISASM_ARM_INSTRUCTION_FLAG_EXCLUSIVE
                | CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE,4,1,
#if USE_DISASM_FORMAT
            "ldatxr w1, [x2]"
#endif
        },
        {{0x41,0x7c,0x00,0xc9},4815,CDISASM_ARM_NAME_STTXR,
            CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
                | CDISASM_ARM_INSTRUCTION_FLAG_EXCLUSIVE,8,0,
#if USE_DISASM_FORMAT
            "sttxr w0, x1, [x2]"
#endif
        },
        {{0x41,0xfc,0x00,0xc9},4816,CDISASM_ARM_NAME_STLTXR,
            CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
                | CDISASM_ARM_INSTRUCTION_FLAG_EXCLUSIVE
                | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE,8,0,
#if USE_DISASM_FORMAT
            "stltxr w0, x1, [x2]"
#endif
        },
        {{0x41,0x7c,0x5f,0xc9},4817,CDISASM_ARM_NAME_LDTXR,
            CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
                | CDISASM_ARM_INSTRUCTION_FLAG_EXCLUSIVE,8,1,
#if USE_DISASM_FORMAT
            "ldtxr x1, [x2]"
#endif
        },
        {{0x41,0xfc,0x5f,0xc9},4818,CDISASM_ARM_NAME_LDATXR,
            CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
                | CDISASM_ARM_INSTRUCTION_FLAG_EXCLUSIVE
                | CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE,8,1,
#if USE_DISASM_FORMAT
            "ldatxr x1, [x2]"
#endif
        }
    };
    size_t index;
    cdisasm_arm_instruction instruction;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
#if USE_EXTRA_OPCODES
        const unsigned data_index = cases[index].load ? 0u : 1u;
        const unsigned memory_index = cases[index].load ? 1u : 2u;
        EXPECT(decode_a64(cases[index].bytes, &instruction) == 4u);
        EXPECT(instruction.form_id == cases[index].form);
        EXPECT(instruction.name_id == cases[index].name);
        EXPECT(instruction.instruction_flags == cases[index].flags);
        EXPECT(instruction.operand_count == (cases[index].load ? 2u : 3u));
        EXPECT(instruction.operand[data_index].size == cases[index].size);
        EXPECT(instruction.operand[data_index].access
            == (cases[index].load ? CDISASM_OPERAND_ACCESS_WRITE
                                  : CDISASM_OPERAND_ACCESS_READ));
        EXPECT(instruction.operand[memory_index].type
            == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.operand[memory_index].size == cases[index].size);
        EXPECT(instruction.operand[memory_index].access
            == (cases[index].load ? CDISASM_OPERAND_ACCESS_READ
                                  : CDISASM_OPERAND_ACCESS_WRITE));
#  if USE_DISASM_FORMAT
        {
            char text[48];
            EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
                == strlen(cases[index].text));
            EXPECT(strcmp(text, cases[index].text) == 0);
        }
#  endif
#else
        EXPECT(decode_a64(cases[index].bytes, &instruction) == 0u);
        EXPECT(instruction.last_error_id
            == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_CORTEX_A53,
        CDISASM_ARM_MODE_A64, cases[0].bytes, 4u, UINT64_C(0x1000),
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
#endif
}

static void test_a64_lsui_compare_swap(void)
{
    static const struct lsui_cas_case {
        uint8_t bytes[4];
        cdisasm_arm_form_id form;
        cdisasm_arm_name_id name;
        uint32_t ordering_flags;
        int pair;
#if USE_DISASM_FORMAT
        const char *text;
#endif
    } cases[] = {
        {{0x41,0x7c,0x80,0xc9},4781,CDISASM_ARM_NAME_CAST,0,0,
#if USE_DISASM_FORMAT
            "cast x0, x1, [x2]"
#endif
        },
        {{0x41,0xfc,0x80,0xc9},4782,CDISASM_ARM_NAME_CASLT,
            CDISASM_ARM_INSTRUCTION_FLAG_RELEASE,0,
#if USE_DISASM_FORMAT
            "caslt x0, x1, [x2]"
#endif
        },
        {{0x41,0x7c,0xc0,0xc9},4783,CDISASM_ARM_NAME_CASAT,
            CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE,0,
#if USE_DISASM_FORMAT
            "casat x0, x1, [x2]"
#endif
        },
        {{0x41,0xfc,0xc0,0xc9},4784,CDISASM_ARM_NAME_CASALT,
            CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
                | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE,0,
#if USE_DISASM_FORMAT
            "casalt x0, x1, [x2]"
#endif
        },
        {{0x82,0x7c,0x80,0x49},4777,CDISASM_ARM_NAME_CASPT,0,1,
#if USE_DISASM_FORMAT
            "caspt x0, x1, x2, x3, [x4]"
#endif
        },
        {{0x82,0xfc,0x80,0x49},4778,CDISASM_ARM_NAME_CASPLT,
            CDISASM_ARM_INSTRUCTION_FLAG_RELEASE,1,
#if USE_DISASM_FORMAT
            "casplt x0, x1, x2, x3, [x4]"
#endif
        },
        {{0x82,0x7c,0xc0,0x49},4779,CDISASM_ARM_NAME_CASPAT,
            CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE,1,
#if USE_DISASM_FORMAT
            "caspat x0, x1, x2, x3, [x4]"
#endif
        },
        {{0x82,0xfc,0xc0,0x49},4780,CDISASM_ARM_NAME_CASPALT,
            CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
                | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE,1,
#if USE_DISASM_FORMAT
            "caspalt x0, x1, x2, x3, [x4]"
#endif
        }
    };
    size_t index;
    cdisasm_arm_instruction instruction;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
#if USE_EXTRA_OPCODES
        EXPECT(decode_a64(cases[index].bytes, &instruction) == 4u);
        EXPECT(instruction.form_id == cases[index].form);
        EXPECT(instruction.name_id == cases[index].name);
        EXPECT(instruction.instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
                | cases[index].ordering_flags));
        EXPECT(instruction.operand_count == 3u);
        EXPECT(instruction.operand[0].type == (cases[index].pair
            ? CDISASM_ARM_OPERAND_REGISTER_PAIR : CDISASM_OPERAND_REGISTER));
        EXPECT(instruction.operand[0].size == 8u);
        EXPECT(instruction.operand[0].access
            == CDISASM_OPERAND_ACCESS_READ_WRITE);
        EXPECT(instruction.operand[1].type == (cases[index].pair
            ? CDISASM_ARM_OPERAND_REGISTER_PAIR : CDISASM_OPERAND_REGISTER));
        EXPECT(instruction.operand[1].size == 8u);
        EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction.operand[2].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.operand[2].size == 8u);
        EXPECT(instruction.operand[2].access
            == CDISASM_OPERAND_ACCESS_READ_WRITE);
#  if USE_DISASM_FORMAT
        {
            char text[64];
            EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
                == strlen(cases[index].text));
            EXPECT(strcmp(text, cases[index].text) == 0);
        }
#  endif
#else
        EXPECT(decode_a64(cases[index].bytes, &instruction) == 0u);
        EXPECT(instruction.last_error_id
            == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_CORTEX_A53,
        CDISASM_ARM_MODE_A64, cases[0].bytes, 4u, UINT64_C(0x1000),
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
#endif
}

static void test_a64_lsui_rmw(void)
{
    static const unsigned opcodes[4] = {0u, 1u, 3u, 8u};
#if USE_EXTRA_OPCODES
    static const cdisasm_arm_name_id names[4][4] = {
        {CDISASM_ARM_NAME_LDTADD, CDISASM_ARM_NAME_LDTADDL,
         CDISASM_ARM_NAME_LDTADDA, CDISASM_ARM_NAME_LDTADDAL},
        {CDISASM_ARM_NAME_LDTCLR, CDISASM_ARM_NAME_LDTCLRL,
         CDISASM_ARM_NAME_LDTCLRA, CDISASM_ARM_NAME_LDTCLRAL},
        {CDISASM_ARM_NAME_LDTSET, CDISASM_ARM_NAME_LDTSETL,
         CDISASM_ARM_NAME_LDTSETA, CDISASM_ARM_NAME_LDTSETAL},
        {CDISASM_ARM_NAME_SWPT, CDISASM_ARM_NAME_SWPTL,
         CDISASM_ARM_NAME_SWPTA, CDISASM_ARM_NAME_SWPTAL}
    };
#endif
    unsigned width, form_ordering, operation;
    cdisasm_arm_instruction instruction;

    for (width = 0u; width < 2u; ++width) {
        for (form_ordering = 0u; form_ordering < 4u; ++form_ordering) {
            unsigned release = form_ordering & 1u;
            unsigned acquire = form_ordering >> 1;
            for (operation = 0u; operation < 4u; ++operation) {
                uint32_t word = (width == 0u
                    ? UINT32_C(0x19200000) : UINT32_C(0x59200000))
                    | (acquire << 23) | (release << 22)
                    | (opcodes[operation] << 12)
                    | UINT32_C(0x441);
                uint8_t bytes[4] = {
                    (uint8_t)word, (uint8_t)(word >> 8),
                    (uint8_t)(word >> 16), (uint8_t)(word >> 24)
                };
#if USE_EXTRA_OPCODES
                uint32_t expected_flags = CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
                    | (acquire != 0u
                        ? CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE : 0u)
                    | (release != 0u
                        ? CDISASM_ARM_INSTRUCTION_FLAG_RELEASE : 0u);
                EXPECT(decode_a64(bytes, &instruction) == 4u);
                EXPECT(instruction.form_id == (cdisasm_arm_form_id)(5044u
                    + width * 16u + form_ordering * 4u + operation));
                EXPECT(instruction.name_id
                    == names[operation][form_ordering]);
                EXPECT(instruction.instruction_flags == expected_flags);
                EXPECT(instruction.operand_count == 3u);
                EXPECT(instruction.operand[0].size == (width ? 8u : 4u));
                EXPECT(instruction.operand[0].access
                    == CDISASM_OPERAND_ACCESS_READ);
                EXPECT(instruction.operand[1].size == (width ? 8u : 4u));
                EXPECT(instruction.operand[1].access
                    == CDISASM_OPERAND_ACCESS_WRITE);
                EXPECT(instruction.operand[2].type == CDISASM_OPERAND_MEMORY);
                EXPECT(instruction.operand[2].size == (width ? 8u : 4u));
                EXPECT(instruction.operand[2].access
                    == CDISASM_OPERAND_ACCESS_READ_WRITE);
#  if USE_DISASM_FORMAT
                {
                    char text[48];
                    EXPECT(cdisasm_arm_format(
                        &instruction, 0u, text, sizeof(text)) != 0u);
                }
#  endif
#else
                EXPECT(decode_a64(bytes, &instruction) == 0u);
                EXPECT(instruction.last_error_id
                    == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
            }
        }
    }
#if USE_EXTRA_OPCODES
    {
        static const uint8_t bytes[4] = {0x41,0x04,0x20,0x19};
        EXPECT(cdisasm_arm_decode(CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_ARM_MODE_A64, bytes, 4u, UINT64_C(0x1000),
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
    }
#endif
}

static void test_a64_lsui_pairs(void)
{
    static const struct lsui_case {
        uint8_t bytes[4];
        cdisasm_arm_form_id form;
        cdisasm_arm_name_id name;
        uint32_t flags;
        cdisasm_arm_reg_id first;
        cdisasm_arm_reg_id second;
        uint8_t register_size;
        uint8_t memory_size;
        int64_t displacement;
#if USE_DISASM_FORMAT
        const char *text;
#endif
    } cases[] = {
        {{0x40,0x04,0x01,0xe8},5086,CDISASM_ARM_NAME_STTNP,0,
            CDISASM_ARM_REG_X0,CDISASM_ARM_REG_X1,8,16,16,
#if USE_DISASM_FORMAT
            "sttnp x0, x1, [x2, #0x10]"
#endif
        },
        {{0xb1,0x48,0x7f,0xec},5089,CDISASM_ARM_NAME_LDTNP,
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT,
            CDISASM_ARM_REG_Q17,CDISASM_ARM_REG_Q18,16,32,-32,
#if USE_DISASM_FORMAT
            "ldtnp q17, q18, [x5, #-0x20]"
#endif
        },
        {{0x40,0x04,0x81,0xe8},5102,CDISASM_ARM_NAME_STTP,
            CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK,
            CDISASM_ARM_REG_X0,CDISASM_ARM_REG_X1,8,16,16,
#if USE_DISASM_FORMAT
            "sttp x0, x1, [x2], #0x10"
#endif
        },
        {{0xb1,0x48,0xff,0xed},5137,CDISASM_ARM_NAME_LDTP,
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
                | CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK,
            CDISASM_ARM_REG_Q17,CDISASM_ARM_REG_Q18,16,32,-32,
#if USE_DISASM_FORMAT
            "ldtp q17, q18, [x5, #-0x20]!"
#endif
        }
    };
    size_t index;
    cdisasm_arm_instruction instruction;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
#if USE_EXTRA_OPCODES
        cdisasm_operand_access register_access =
            cases[index].name == CDISASM_ARM_NAME_LDTNP
                || cases[index].name == CDISASM_ARM_NAME_LDTP
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ;
        cdisasm_operand_access memory_access =
            register_access == CDISASM_OPERAND_ACCESS_WRITE
            ? CDISASM_OPERAND_ACCESS_READ
            : CDISASM_OPERAND_ACCESS_WRITE;

        EXPECT(decode_a64(cases[index].bytes, &instruction) == 4u);
        EXPECT(instruction.form_id == cases[index].form);
        EXPECT(instruction.name_id == cases[index].name);
        EXPECT(instruction.instruction_flags == cases[index].flags);
        EXPECT(instruction.operand_count == 3u);
        EXPECT(instruction.operand[0].reg == cases[index].first);
        EXPECT(instruction.operand[1].reg == cases[index].second);
        EXPECT(instruction.operand[0].size == cases[index].register_size);
        EXPECT(instruction.operand[1].size == cases[index].register_size);
        EXPECT(instruction.operand[0].access == register_access);
        EXPECT(instruction.operand[1].access == register_access);
        EXPECT(instruction.operand[2].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.operand[2].size == cases[index].memory_size);
        EXPECT((int64_t)instruction.operand[2].imm
            == cases[index].displacement);
        EXPECT(instruction.operand[2].access == memory_access);
#  if USE_DISASM_FORMAT
        {
            char text[80];
            EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
                == strlen(cases[index].text));
            EXPECT(strcmp(text, cases[index].text) == 0);
        }
#  endif
#else
        EXPECT(decode_a64(cases[index].bytes, &instruction) == 0u);
        EXPECT(instruction.last_error_id
            == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_CORTEX_A53, CDISASM_ARM_MODE_A64,
        cases[0].bytes, 4u, UINT64_C(0x1000),
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
#endif
}

static void test_scalar_register_offset(void)
{
    static const uint8_t bytes[4] = {0xd3, 0x20, 0x11, 0xe1};
    cdisasm_arm_instruction instruction;

#if USE_EXTRA_OPCODES
    EXPECT(decode(bytes, sizeof(bytes), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(13));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_LDRSB);
    EXPECT(instruction.operand_count == 2u);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_R2);
    EXPECT(instruction.operand[0].size == 1u);
    EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.operand[1].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.operand[1].base_reg == CDISASM_ARM_REG_R1);
    EXPECT(instruction.operand[1].index_reg == CDISASM_ARM_REG_R3);
    EXPECT(instruction.operand[1].size == 1u);
    EXPECT(instruction.operand[1].flags == CDISASM_OPERAND_FLAG_SIGNED);
#  if USE_DISASM_FORMAT
    {
        char text[64];
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
            == strlen("ldrsb r2, [r1, -r3]"));
        EXPECT(strcmp(text, "ldrsb r2, [r1, -r3]") == 0);
    }
#  endif
#else
    EXPECT(decode(bytes, sizeof(bytes), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_a32_speculation_barriers(void)
{
    static const uint8_t ssbb[4] = {0x40, 0xf0, 0x7f, 0xf5};
    static const uint8_t pssbb[4] = {0x44, 0xf0, 0x7f, 0xf5};
    cdisasm_arm_instruction instruction;

#if USE_EXTRA_OPCODES
    EXPECT(decode(ssbb, sizeof(ssbb), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(953));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_SSBB);
    EXPECT(instruction.condition == CDISASM_ARM_CONDITION_AL);
    EXPECT(instruction.operand_count == 0u);
    EXPECT(instruction.instruction_flags == 0u);
#  if USE_DISASM_FORMAT
    {
        char text[16];
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
            == strlen("ssbb"));
        EXPECT(strcmp(text, "ssbb") == 0);
    }
#  endif
    EXPECT(decode(pssbb, sizeof(pssbb), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(954));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_PSSBB);
    EXPECT(instruction.condition == CDISASM_ARM_CONDITION_AL);
    EXPECT(instruction.operand_count == 0u);
    EXPECT(instruction.instruction_flags == 0u);
#  if USE_DISASM_FORMAT
    {
        char text[16];
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
            == strlen("pssbb"));
        EXPECT(strcmp(text, "pssbb") == 0);
        instruction.raw_instruction = UINT32_C(0xf57ff040);
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
            == 0u);
    }
#  endif
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_ARM7TDMI, CDISASM_ARM_MODE_A32,
        ssbb, sizeof(ssbb), UINT64_C(0x1000),
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
#else
    EXPECT(decode(ssbb, sizeof(ssbb), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode(pssbb, sizeof(pssbb), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_a32_instruction_prefetch(void)
{
    static const uint8_t register_base[4] = {0x0c, 0xf0, 0xd3, 0xf4};
    static const uint8_t literal[4] = {0x10, 0xf0, 0xdf, 0xf4};
    cdisasm_arm_instruction instruction;

#if USE_EXTRA_OPCODES
    EXPECT(decode(register_base, sizeof(register_base), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(958));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_PLI);
    EXPECT(instruction.condition == CDISASM_ARM_CONDITION_AL);
    EXPECT(instruction.instruction_flags == 0u);
    EXPECT(instruction.operand_count == 1u);
    EXPECT(instruction.operand[0].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.operand[0].base_reg == CDISASM_ARM_REG_R3);
    EXPECT(instruction.operand[0].imm == UINT64_C(12));
    EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_READ);
#  if USE_DISASM_FORMAT
    {
        char text[48];
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
            == strlen("pli [r3, #0xc]"));
        EXPECT(strcmp(text, "pli [r3, #0xc]") == 0);
    }
#  endif
    EXPECT(decode(literal, sizeof(literal), &instruction) == 4u);
    EXPECT(instruction.operand[0].base_reg == CDISASM_ARM_REG_PC);
    EXPECT(instruction.operand[0].address == UINT64_C(0x1018));
    EXPECT((instruction.operand[0].flags
        & (CDISASM_OPERAND_FLAG_PC_RELATIVE
            | CDISASM_OPERAND_FLAG_HAS_ADDRESS))
        == (CDISASM_OPERAND_FLAG_PC_RELATIVE
            | CDISASM_OPERAND_FLAG_HAS_ADDRESS));
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_ARM7TDMI, CDISASM_ARM_MODE_A32,
        register_base, sizeof(register_base), UINT64_C(0x1000),
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
#else
    EXPECT(decode(register_base, sizeof(register_base), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode(literal, sizeof(literal), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_a32_data_prefetch(void)
{
    static const uint8_t register_base[4] = {0x04, 0xf0, 0x51, 0xf5};
    static const uint8_t literal[4] = {0x10, 0xf0, 0xdf, 0xf5};
    cdisasm_arm_instruction instruction;

#if USE_EXTRA_OPCODES
    EXPECT(decode(register_base, sizeof(register_base), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(960));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_PLD);
    EXPECT(instruction.condition == CDISASM_ARM_CONDITION_AL);
    EXPECT(instruction.instruction_flags == 0u);
    EXPECT(instruction.operand_count == 1u);
    EXPECT(instruction.operand[0].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.operand[0].base_reg == CDISASM_ARM_REG_R1);
    EXPECT(instruction.operand[0].imm == (uint64_t)(-(int64_t)4));
    EXPECT((instruction.operand[0].flags
        & (CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
            | CDISASM_OPERAND_FLAG_SIGNED))
        == (CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
            | CDISASM_OPERAND_FLAG_SIGNED));
#  if USE_DISASM_FORMAT
    {
        char text[48];
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
            == strlen("pld [r1, #-0x4]"));
        EXPECT(strcmp(text, "pld [r1, #-0x4]") == 0);
        instruction.form_id = UINT16_C(959);
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
            == 0u);
    }
#  endif
    EXPECT(decode(literal, sizeof(literal), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(959));
    EXPECT(instruction.operand[0].base_reg == CDISASM_ARM_REG_PC);
    EXPECT(instruction.operand[0].address == UINT64_C(0x1018));
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_ARM7TDMI, CDISASM_ARM_MODE_A32,
        register_base, sizeof(register_base), UINT64_C(0x1000),
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
#else
    EXPECT(decode(register_base, sizeof(register_base), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode(literal, sizeof(literal), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_a32_register_prefetch(void)
{
    static const struct prefetch_case {
        uint8_t bytes[4];
        cdisasm_arm_name_id name;
        cdisasm_arm_form_id form;
        cdisasm_arm_shift_type shift;
        uint8_t amount;
        uint8_t negative;
        const char *text;
    } cases[] = {
        {{0x82, 0xf1, 0xd1, 0xf7}, CDISASM_ARM_NAME_PLD, 964,
            CDISASM_ARM_SHIFT_LSL, 3u, 0u,
            "pld [r1, r2, lsl #0x3]"},
        {{0x64, 0xf0, 0xd3, 0xf7}, CDISASM_ARM_NAME_PLD, 965,
            CDISASM_ARM_SHIFT_RRX, 1u, 0u, "pld [r3, r4, rrx]"},
        {{0xc6, 0xf3, 0x55, 0xf6}, CDISASM_ARM_NAME_PLI, 963,
            CDISASM_ARM_SHIFT_ASR, 7u, 1u,
            "pli [r5, -r6, asr #0x7]"},
        {{0x68, 0xf0, 0x57, 0xf6}, CDISASM_ARM_NAME_PLI, 962,
            CDISASM_ARM_SHIFT_RRX, 1u, 1u, "pli [r7, -r8, rrx]"}
    };
    static const uint8_t bad_pc_base[4] = {0x02, 0xf0, 0xdf, 0xf7};
    static const uint8_t bad_pc_index[4] = {0x0f, 0xf0, 0xd1, 0xf7};
    cdisasm_arm_instruction instruction;
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
#if USE_EXTRA_OPCODES
        EXPECT(decode(cases[index].bytes, 4u, &instruction) == 4u);
        EXPECT(instruction.name_id == cases[index].name);
        EXPECT(instruction.form_id == cases[index].form);
        EXPECT(instruction.instruction_flags == 0u);
        EXPECT(instruction.operand_count == 1u);
        EXPECT(instruction.operand[0].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.operand[0].shift_type == cases[index].shift);
        EXPECT(instruction.operand[0].shift_amount == cases[index].amount);
        EXPECT(((instruction.operand[0].flags
            & CDISASM_OPERAND_FLAG_SIGNED) != 0u) == cases[index].negative);
#  if USE_DISASM_FORMAT
        {
            char text[48];
            EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
                == strlen(cases[index].text));
            EXPECT(strcmp(text, cases[index].text) == 0);
        }
#  endif
#else
        EXPECT(decode(cases[index].bytes, 4u, &instruction) == 0u);
        EXPECT(instruction.last_error_id
            == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
    EXPECT(decode(bad_pc_base, sizeof(bad_pc_base), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
    EXPECT(decode(bad_pc_index, sizeof(bad_pc_index), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_ARM7TDMI, CDISASM_ARM_MODE_A32,
        cases[2].bytes, 4u, UINT64_C(0x1000),
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
#endif
}

static void test_a32_write_intent_prefetch(void)
{
    static const uint8_t immediate[4] = {0x08, 0xf0, 0x92, 0xf5};
    static const uint8_t shifted[4] = {0xa4, 0xf2, 0x13, 0xf7};
    static const uint8_t rrx[4] = {0x66, 0xf0, 0x95, 0xf7};
    static const uint8_t bad_pc_base[4] = {0x08, 0xf0, 0x9f, 0xf5};
    cdisasm_arm_instruction instruction;

#if USE_EXTRA_OPCODES
    EXPECT(decode(immediate, sizeof(immediate), &instruction) == 4u);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_PLDW);
    EXPECT(instruction.form_id == UINT16_C(961));
    EXPECT(instruction.instruction_flags == 0u);
    EXPECT(instruction.operand_count == 1u);
    EXPECT(instruction.operand[0].base_reg == CDISASM_ARM_REG_R2);
    EXPECT(instruction.operand[0].imm == UINT64_C(8));
#  if USE_DISASM_FORMAT
    {
        char text[48];
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
            == strlen("pldw [r2, #0x8]"));
        EXPECT(strcmp(text, "pldw [r2, #0x8]") == 0);
    }
#  endif
    EXPECT(decode(shifted, sizeof(shifted), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(966));
    EXPECT(instruction.operand[0].index_reg == CDISASM_ARM_REG_R4);
    EXPECT(instruction.operand[0].shift_type == CDISASM_ARM_SHIFT_LSR);
    EXPECT(instruction.operand[0].shift_amount == 5u);
    EXPECT((instruction.operand[0].flags
        & CDISASM_OPERAND_FLAG_SIGNED) != 0u);
    EXPECT(decode(rrx, sizeof(rrx), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(967));
    EXPECT(instruction.operand[0].shift_type == CDISASM_ARM_SHIFT_RRX);
    EXPECT(instruction.operand[0].shift_amount == 1u);
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_CORTEX_A7, CDISASM_ARM_MODE_A32,
        immediate, sizeof(immediate), UINT64_C(0x1000),
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_APPLE_A4, CDISASM_ARM_MODE_A32,
        immediate, sizeof(immediate), UINT64_C(0x1000),
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
#else
    EXPECT(decode(immediate, sizeof(immediate), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode(shifted, sizeof(shifted), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode(rrx, sizeof(rrx), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    EXPECT(decode(bad_pc_base, sizeof(bad_pc_base), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
}

static void test_t32_narrow_mov_shift_aliases(void)
{
    static const struct shift_case {
        uint8_t bytes[2];
        cdisasm_arm_name_id name;
        cdisasm_arm_form_id form;
        cdisasm_arm_reg_id destination;
        cdisasm_arm_reg_id source;
        const char *text;
    } cases[] = {
        {{0x11, 0x00}, CDISASM_ARM_NAME_MOV, 1104,
            CDISASM_ARM_REG_R1, CDISASM_ARM_REG_R2, "movs r1, r2"},
        {{0x88, 0x40}, CDISASM_ARM_NAME_LSLS, 1112,
            CDISASM_ARM_REG_R0, CDISASM_ARM_REG_R1, "lsls r0, r1"},
        {{0xda, 0x40}, CDISASM_ARM_NAME_LSRS, 1113,
            CDISASM_ARM_REG_R2, CDISASM_ARM_REG_R3, "lsrs r2, r3"},
        {{0x2c, 0x41}, CDISASM_ARM_NAME_ASRS, 1111,
            CDISASM_ARM_REG_R4, CDISASM_ARM_REG_R5, "asrs r4, r5"},
        {{0xfe, 0x41}, CDISASM_ARM_NAME_RORS, 1114,
            CDISASM_ARM_REG_R6, CDISASM_ARM_REG_R7, "rors r6, r7"}
    };
    cdisasm_arm_instruction instruction;
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
#if USE_EXTRA_OPCODES
        EXPECT(decode_t32(cases[index].bytes, 2u, &instruction) == 2u);
        EXPECT(instruction.name_id == cases[index].name);
        EXPECT(instruction.form_id == cases[index].form);
        EXPECT(instruction.instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS);
        EXPECT(instruction.operand_count == 2u);
        EXPECT(instruction.operand[0].reg == cases[index].destination);
        EXPECT(instruction.operand[1].reg == cases[index].source);
        EXPECT(instruction.operand[0].access
            == (index == 0u ? CDISASM_OPERAND_ACCESS_WRITE
                            : CDISASM_OPERAND_ACCESS_READ_WRITE));
        EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
#  if USE_DISASM_FORMAT
        {
            char text[32];
            EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
                == strlen(cases[index].text));
            EXPECT(strcmp(text, cases[index].text) == 0);
        }
#  endif
#else
        EXPECT(decode_t32(cases[index].bytes, 2u, &instruction) == 0u);
        EXPECT(instruction.last_error_id
            == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
}

static void test_a32_movs_register_shift_aliases(void)
{
    static const struct shift_case {
        uint8_t bytes[4];
        cdisasm_arm_name_id name;
        cdisasm_arm_reg_id destination;
        cdisasm_arm_reg_id source;
        cdisasm_arm_reg_id shift_register;
        const char *text;
    } cases[] = {
        {{0x12, 0x13, 0xb0, 0xe1}, CDISASM_ARM_NAME_LSLS,
            CDISASM_ARM_REG_R1, CDISASM_ARM_REG_R2,
            CDISASM_ARM_REG_R3, "lsls r1, r2, r3"},
        {{0x35, 0x46, 0xb0, 0xe1}, CDISASM_ARM_NAME_LSRS,
            CDISASM_ARM_REG_R4, CDISASM_ARM_REG_R5,
            CDISASM_ARM_REG_R6, "lsrs r4, r5, r6"},
        {{0x58, 0x79, 0xb0, 0xe1}, CDISASM_ARM_NAME_ASRS,
            CDISASM_ARM_REG_R7, CDISASM_ARM_REG_R8,
            CDISASM_ARM_REG_R9, "asrs r7, r8, r9"},
        {{0x7b, 0xac, 0xb0, 0xe1}, CDISASM_ARM_NAME_RORS,
            CDISASM_ARM_REG_R10, CDISASM_ARM_REG_R11,
            CDISASM_ARM_REG_R12, "rors r10, r11, r12"}
    };
#if USE_EXTRA_OPCODES
    static const uint8_t bad_pc[4] = {0x1f, 0x13, 0xb0, 0xe1};
#endif
    cdisasm_arm_instruction instruction;
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
#if USE_EXTRA_OPCODES
        EXPECT(decode(cases[index].bytes, 4u, &instruction) == 4u);
        EXPECT(instruction.name_id == cases[index].name);
        EXPECT(instruction.form_id == UINT16_C(210));
        EXPECT(instruction.instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS);
        EXPECT(instruction.operand_count == 3u);
        EXPECT(instruction.operand[0].reg == cases[index].destination);
        EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        EXPECT(instruction.operand[1].reg == cases[index].source);
        EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction.operand[2].reg == cases[index].shift_register);
        EXPECT(instruction.operand[2].access == CDISASM_OPERAND_ACCESS_READ);
#  if USE_DISASM_FORMAT
        {
            char text[32];
            EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
                == strlen(cases[index].text));
            EXPECT(strcmp(text, cases[index].text) == 0);
        }
#  endif
#else
        EXPECT(decode(cases[index].bytes, 4u, &instruction) == 0u);
        EXPECT(instruction.last_error_id
            == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
#if USE_EXTRA_OPCODES
    EXPECT(decode(bad_pc, sizeof(bad_pc), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
#endif
}

static void test_a32_mov_register_shift_aliases(void)
{
    static const struct shift_case {
        uint8_t bytes[4];
        cdisasm_arm_name_id name;
        const char *text;
    } cases[] = {
        {{0x12, 0x13, 0xa0, 0xe1}, CDISASM_ARM_NAME_LSL,
            "lsl r1, r2, r3"},
        {{0x35, 0x46, 0xa0, 0xe1}, CDISASM_ARM_NAME_LSR,
            "lsr r4, r5, r6"},
        {{0x58, 0x79, 0xa0, 0xe1}, CDISASM_ARM_NAME_ASR,
            "asr r7, r8, r9"},
        {{0x7b, 0xac, 0xa0, 0xe1}, CDISASM_ARM_NAME_ROR,
            "ror r10, r11, r12"}
    };
    cdisasm_arm_instruction instruction;
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
#if USE_EXTRA_OPCODES
        EXPECT(decode(cases[index].bytes, 4u, &instruction) == 4u);
        EXPECT(instruction.name_id == cases[index].name);
        EXPECT(instruction.form_id == UINT16_C(211));
        EXPECT(instruction.instruction_flags == 0u);
        EXPECT(instruction.operand_count == 3u);
        EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction.operand[2].access == CDISASM_OPERAND_ACCESS_READ);
#  if USE_DISASM_FORMAT
        {
            char text[32];
            EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
                == strlen(cases[index].text));
            EXPECT(strcmp(text, cases[index].text) == 0);
        }
#  endif
#else
        EXPECT(decode(cases[index].bytes, 4u, &instruction) == 0u);
        EXPECT(instruction.last_error_id
            == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
}

static void test_t32_wide_movs_register_shift_aliases(void)
{
    static const struct shift_case {
        uint8_t bytes[4];
        cdisasm_arm_name_id name;
        cdisasm_arm_reg_id destination;
        cdisasm_arm_reg_id source;
        cdisasm_arm_reg_id shift_register;
        const char *text;
    } cases[] = {
        {{0x12, 0xfa, 0x03, 0xf1}, CDISASM_ARM_NAME_LSLS,
            CDISASM_ARM_REG_R1, CDISASM_ARM_REG_R2,
            CDISASM_ARM_REG_R3, "lsls r1, r2, r3"},
        {{0x35, 0xfa, 0x06, 0xf4}, CDISASM_ARM_NAME_LSRS,
            CDISASM_ARM_REG_R4, CDISASM_ARM_REG_R5,
            CDISASM_ARM_REG_R6, "lsrs r4, r5, r6"},
        {{0x58, 0xfa, 0x09, 0xf7}, CDISASM_ARM_NAME_ASRS,
            CDISASM_ARM_REG_R7, CDISASM_ARM_REG_R8,
            CDISASM_ARM_REG_R9, "asrs r7, r8, r9"},
        {{0x7b, 0xfa, 0x0c, 0xfa}, CDISASM_ARM_NAME_RORS,
            CDISASM_ARM_REG_R10, CDISASM_ARM_REG_R11,
            CDISASM_ARM_REG_R12, "rors r10, r11, r12"}
    };
    static const uint8_t bad_sp[4] = {0x1d, 0xfa, 0x03, 0xf1};
    cdisasm_arm_instruction instruction;
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
#if USE_EXTRA_OPCODES
        EXPECT(decode_t32(cases[index].bytes, 4u, &instruction) == 4u);
        EXPECT(instruction.name_id == cases[index].name);
        EXPECT(instruction.form_id == UINT16_C(2109));
        EXPECT(instruction.instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS);
        EXPECT(instruction.operand_count == 3u);
        EXPECT(instruction.operand[0].reg == cases[index].destination);
        EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        EXPECT(instruction.operand[1].reg == cases[index].source);
        EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction.operand[2].reg == cases[index].shift_register);
        EXPECT(instruction.operand[2].access == CDISASM_OPERAND_ACCESS_READ);
#  if USE_DISASM_FORMAT
        {
            char text[32];
            EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
                == strlen(cases[index].text));
            EXPECT(strcmp(text, cases[index].text) == 0);
        }
#  endif
#else
        EXPECT(decode_t32(cases[index].bytes, 4u, &instruction) == 0u);
        EXPECT(instruction.last_error_id
            == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
#if USE_EXTRA_OPCODES
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_CORTEX_A9, CDISASM_ARM_MODE_T32,
        cases[0].bytes, 4u, UINT64_C(0x1000),
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_ARM7TDMI, CDISASM_ARM_MODE_T32,
        cases[0].bytes, 4u, UINT64_C(0x1000),
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
#endif
    EXPECT(decode_t32(bad_sp, sizeof(bad_sp), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
}

static void test_t32_wide_mov_register_shift_aliases(void)
{
    static const struct shift_case {
        uint8_t bytes[4];
        cdisasm_arm_name_id name;
        cdisasm_arm_reg_id destination;
        cdisasm_arm_reg_id source;
        cdisasm_arm_reg_id shift_register;
        const char *text;
    } cases[] = {
        {{0x02, 0xfa, 0x03, 0xf1}, CDISASM_ARM_NAME_LSL,
            CDISASM_ARM_REG_R1, CDISASM_ARM_REG_R2,
            CDISASM_ARM_REG_R3, "lsl r1, r2, r3"},
        {{0x25, 0xfa, 0x06, 0xf4}, CDISASM_ARM_NAME_LSR,
            CDISASM_ARM_REG_R4, CDISASM_ARM_REG_R5,
            CDISASM_ARM_REG_R6, "lsr r4, r5, r6"},
        {{0x48, 0xfa, 0x09, 0xf7}, CDISASM_ARM_NAME_ASR,
            CDISASM_ARM_REG_R7, CDISASM_ARM_REG_R8,
            CDISASM_ARM_REG_R9, "asr r7, r8, r9"},
        {{0x6b, 0xfa, 0x0c, 0xfa}, CDISASM_ARM_NAME_ROR,
            CDISASM_ARM_REG_R10, CDISASM_ARM_REG_R11,
            CDISASM_ARM_REG_R12, "ror r10, r11, r12"}
    };
    cdisasm_arm_instruction instruction;
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
#if USE_EXTRA_OPCODES
        EXPECT(decode_t32(cases[index].bytes, 4u, &instruction) == 4u);
        EXPECT(instruction.name_id == cases[index].name);
        EXPECT(instruction.form_id == UINT16_C(2110));
        EXPECT(instruction.instruction_flags == 0u);
        EXPECT(instruction.operand_count == 3u);
        EXPECT(instruction.operand[0].reg == cases[index].destination);
        EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        EXPECT(instruction.operand[1].reg == cases[index].source);
        EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction.operand[2].reg == cases[index].shift_register);
        EXPECT(instruction.operand[2].access == CDISASM_OPERAND_ACCESS_READ);
#  if USE_DISASM_FORMAT
        {
            char text[32];
            EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
                == strlen(cases[index].text));
            EXPECT(strcmp(text, cases[index].text) == 0);
        }
#  endif
#else
        EXPECT(decode_t32(cases[index].bytes, 4u, &instruction) == 0u);
        EXPECT(instruction.last_error_id
            == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
}

static void test_pair_and_unprivileged(void)
{
    static const uint8_t pair[4] = {0xd3, 0x24, 0x61, 0xe1};
    static const uint8_t unprivileged[4] = {0xb3, 0x24, 0x71, 0xe0};
    cdisasm_arm_instruction instruction;

#if USE_EXTRA_OPCODES
    EXPECT(decode(pair, sizeof(pair), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(29));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_LDRD);
    EXPECT(instruction.operand_count == 3u);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_R2);
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_R3);
    EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.operand[2].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.operand[2].size == 8u);
    EXPECT(instruction.operand[2].imm == (uint64_t)(int64_t)-67);
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK));

    EXPECT(decode(unprivileged, sizeof(unprivileged), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(46));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_LDRHT);
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_UNPRIVILEGED));
#else
    EXPECT(decode(pair, sizeof(pair), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode(unprivileged, sizeof(unprivileged), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_literal_and_invalid(void)
{
    static const uint8_t literal[4] = {0xf3, 0x24, 0x5f, 0xe1};
    static const uint8_t odd_pair[4] = {0xd3, 0x30, 0x01, 0xe1};
    static const uint8_t overlap[4] = {0xd3, 0x20, 0x22, 0xe1};
    static const uint8_t pc_index[4] = {0xbf, 0x20, 0x11, 0xe1};
    cdisasm_arm_instruction instruction;

#if USE_EXTRA_OPCODES
    EXPECT(decode(literal, sizeof(literal), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(26));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_LDRSH);
    EXPECT(instruction.operand[1].base_reg == CDISASM_ARM_REG_PC);
    EXPECT(instruction.operand[1].address == UINT64_C(0xfc5));
    EXPECT(instruction.operand[1].flags
        == (CDISASM_OPERAND_FLAG_SIGNED
            | CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
            | CDISASM_OPERAND_FLAG_PC_RELATIVE
            | CDISASM_OPERAND_FLAG_HAS_ADDRESS));
#else
    EXPECT(decode(literal, sizeof(literal), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    EXPECT(decode(odd_pair, sizeof(odd_pair), &instruction) == 0u);
    EXPECT(instruction.last_error_id == (USE_EXTRA_OPCODES
        ? CDISASM_STATUS_INVALID_INSTRUCTION
        : CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
    EXPECT(decode(overlap, sizeof(overlap), &instruction) == 0u);
    EXPECT(instruction.last_error_id == (USE_EXTRA_OPCODES
        ? CDISASM_STATUS_INVALID_INSTRUCTION
        : CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
    EXPECT(decode(pc_index, sizeof(pc_index), &instruction) == 0u);
    EXPECT(instruction.last_error_id == (USE_EXTRA_OPCODES
        ? CDISASM_STATUS_INVALID_INSTRUCTION
        : CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
    EXPECT(decode(literal, 3u, &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_TRUNCATED);
}

static void test_t32_wide_forms(void)
{
    static const uint8_t pair[4] = {0x71, 0xe9, 0x04, 0x23};
#if USE_EXTRA_OPCODES
    static const uint8_t indexed[4] = {0x31, 0xf9, 0x13, 0x20};
    static const uint8_t unprivileged[4] = {0x11, 0xf9, 0x04, 0x2e};
    static const uint8_t literal[4] = {0xbf, 0xf8, 0x04, 0x20};
    static const uint8_t word_indexed[4] = {0x51, 0xf8, 0x13, 0x20};
    static const uint8_t byte_unprivileged[4] = {0x01, 0xf8, 0x04, 0x2e};
    static const uint8_t word_literal[4] = {0xdf, 0xf8, 0x04, 0x20};
#endif
    static const uint8_t pair_overlap[4] = {0x71, 0xe9, 0x04, 0x22};
    cdisasm_arm_instruction instruction;

#if USE_EXTRA_OPCODES
    EXPECT(decode_t32(pair, sizeof(pair), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1755));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_LDRD);
    EXPECT(instruction.operand_count == 3u);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_R2);
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_R3);
    EXPECT(instruction.operand[2].size == 8u);
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK));

    EXPECT(decode_t32(indexed, sizeof(indexed), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(2093));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_LDRSH);
    EXPECT(instruction.operand[1].index_reg == CDISASM_ARM_REG_R3);
    EXPECT(instruction.operand[1].shift_type == CDISASM_ARM_SHIFT_LSL);
    EXPECT(instruction.operand[1].shift_amount == 1u);
#  if USE_DISASM_FORMAT
    {
        char text[64];
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
            == strlen("ldrsh r2, [r1, r3, lsl #0x1]"));
        EXPECT(strcmp(text, "ldrsh r2, [r1, r3, lsl #0x1]") == 0);
    }
#  endif

    EXPECT(decode_t32(unprivileged, sizeof(unprivileged), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(2099));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_LDRSBT);
    EXPECT(instruction.instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_UNPRIVILEGED);

    EXPECT(decode_t32(literal, sizeof(literal), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(2089));
    EXPECT(instruction.operand[1].base_reg == CDISASM_ARM_REG_PC);
    EXPECT(instruction.operand[1].address == UINT64_C(0x1008));

    EXPECT(decode_t32(word_indexed, sizeof(word_indexed), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(2052));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_LDR);
    EXPECT(instruction.operand[1].size == 4u);
    EXPECT(instruction.operand[1].index_reg == CDISASM_ARM_REG_R3);

    EXPECT(decode_t32(byte_unprivileged, sizeof(byte_unprivileged),
        &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(2067));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_STRBT);
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_BYTE
            | CDISASM_ARM_INSTRUCTION_FLAG_UNPRIVILEGED));

    EXPECT(decode_t32(word_literal, sizeof(word_literal), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(2090));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_LDR);
    EXPECT(instruction.operand[1].base_reg == CDISASM_ARM_REG_PC);
    EXPECT(instruction.operand[1].address == UINT64_C(0x1008));
#else
    EXPECT(decode_t32(pair, sizeof(pair), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    EXPECT(decode_t32(pair_overlap, sizeof(pair_overlap), &instruction) == 0u);
    EXPECT(instruction.last_error_id == (USE_EXTRA_OPCODES
        ? CDISASM_STATUS_INVALID_INSTRUCTION
        : CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
    EXPECT(decode_t32(pair, 3u, &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_TRUNCATED);
}

static void test_t32_exclusive_and_table(void)
{
    static const uint8_t strex[4] = {0x41, 0xe8, 0x04, 0x23};
    static const uint8_t tbh[4] = {0xd1, 0xe8, 0x13, 0xf0};
    static const uint8_t ldaexd[4] = {0xd1, 0xe8, 0xff, 0x23};
    static const uint8_t bad_status[4] = {0xc1, 0xe8, 0x4d, 0x2f};
    cdisasm_arm_instruction instruction;

#if USE_EXTRA_OPCODES
    EXPECT(decode_t32(strex, sizeof(strex), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1726));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_STREX);
    EXPECT(instruction.operand_count == 3u);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_R3);
    EXPECT(instruction.operand[2].imm == 16u);
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
            | CDISASM_ARM_INSTRUCTION_FLAG_EXCLUSIVE));
#  if USE_DISASM_FORMAT
    {
        char text[64];
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
            == strlen("strex r3, r2, [r1, #0x10]"));
        EXPECT(strcmp(text, "strex r3, r2, [r1, #0x10]") == 0);
    }
#  endif

    EXPECT(decode_t32(tbh, sizeof(tbh), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1729));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_TBH);
    EXPECT(instruction.opcode_groups == CDISASM_GROUP_JUMP);
    EXPECT(instruction.operand[0].shift_amount == 1u);

    EXPECT(decode_t32(ldaexd, sizeof(ldaexd), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1749));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_LDAEXD);
    EXPECT(instruction.operand_count == 3u);
    EXPECT(instruction.operand[2].size == 8u);
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
            | CDISASM_ARM_INSTRUCTION_FLAG_EXCLUSIVE
            | CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE));
#else
    (void)ldaexd;
    EXPECT(decode_t32(strex, sizeof(strex), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(tbh, sizeof(tbh), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    EXPECT(decode_t32(bad_status, sizeof(bad_status), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
}

static void test_t32_prefetch(void)
{
    static const uint8_t pld_register[4] = {0x11, 0xf8, 0x13, 0xf0};
    static const uint8_t pld_negative[4] = {0x11, 0xf8, 0x04, 0xfc};
    static const uint8_t pli_literal[4] = {0x9f, 0xf9, 0x04, 0xf0};
    static const uint8_t bad_pldw_literal[4] = {0xbf, 0xf8, 0x04, 0xf0};
    cdisasm_arm_instruction instruction;

#if USE_EXTRA_OPCODES
    EXPECT(decode_t32(pld_register, sizeof(pld_register), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(2047));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_PLD);
    EXPECT(instruction.operand_count == 1u);
    EXPECT(instruction.operand[0].size == 0u);
    EXPECT(instruction.operand[0].index_reg == CDISASM_ARM_REG_R3);
    EXPECT(instruction.operand[0].shift_amount == 1u);
#  if USE_DISASM_FORMAT
    {
        char text[64];
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
            == strlen("pld [r1, r3, lsl #0x1]"));
        EXPECT(strcmp(text, "pld [r1, r3, lsl #0x1]") == 0);
    }
#  endif

    EXPECT(decode_t32(pld_negative, sizeof(pld_negative), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(2061));
    EXPECT(instruction.operand[0].imm == (uint64_t)(-(int64_t)4));
    EXPECT((instruction.operand[0].flags & CDISASM_OPERAND_FLAG_SIGNED) != 0u);

    EXPECT(decode_t32(pli_literal, sizeof(pli_literal), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(2107));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_PLI);
    EXPECT(instruction.operand[0].base_reg == CDISASM_ARM_REG_PC);
    EXPECT(instruction.operand[0].address == UINT64_C(0x1008));
#else
    (void)pld_negative;
    EXPECT(decode_t32(pld_register, sizeof(pld_register), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(pli_literal, sizeof(pli_literal), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    EXPECT(decode_t32(bad_pldw_literal, sizeof(bad_pldw_literal),
        &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
}

static void test_t32_block_transfer(void)
{
    static const uint8_t srsdb[4] = {0x0d, 0xe8, 0x13, 0xc0};
    static const uint8_t rfedb[4] = {0x11, 0xe8, 0x00, 0xc0};
    static const uint8_t stm[4] = {0x81, 0xe8, 0x03, 0x00};
    static const uint8_t ldm[4] = {0x91, 0xe8, 0x05, 0x00};
    static const uint8_t stmdb[4] = {0x01, 0xe9, 0x03, 0x00};
    static const uint8_t ldmdb[4] = {0x11, 0xe9, 0x05, 0x00};
    static const uint8_t srsia[4] = {0x8d, 0xe9, 0x13, 0xc0};
    static const uint8_t rfeia[4] = {0x91, 0xe9, 0x00, 0xc0};
    static const uint8_t one_register[4] = {0x81, 0xe8, 0x01, 0x00};
    static const uint8_t invalid_srs_mode[4] = {0x0d, 0xe8, 0x10, 0xc0};
    cdisasm_arm_instruction instruction;

#if USE_EXTRA_OPCODES
    EXPECT(decode_t32(srsdb, sizeof(srsdb), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1718));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_SRSDB);
    EXPECT(instruction.opcode_groups == CDISASM_GROUP_PRIVILEGED);
    EXPECT(instruction.operand_count == 2u);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_R13);
    EXPECT(instruction.operand[1].imm == UINT64_C(0x13));
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT));
#  if USE_DISASM_FORMAT
    {
        char text[64];
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
            == strlen("srsdb sp, #0x13"));
        EXPECT(strcmp(text, "srsdb sp, #0x13") == 0);
    }
#  endif

    EXPECT(decode_t32(rfedb, sizeof(rfedb), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1719));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_RFEDB);
    EXPECT(instruction.opcode_groups
        == (CDISASM_GROUP_RETURN | CDISASM_GROUP_INTERRUPT_RETURN
            | CDISASM_GROUP_PRIVILEGED));

    EXPECT(decode_t32(stm, sizeof(stm), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1720));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_STM);
    EXPECT(instruction.operand[1].register_list == UINT16_C(0x0003));
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT));

    EXPECT(decode_t32(ldm, sizeof(ldm), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1721));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_LDM);
    EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_WRITE);

    EXPECT(decode_t32(stmdb, sizeof(stmdb), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1722));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_STMDB);
    EXPECT((instruction.instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT) != 0u);

    EXPECT(decode_t32(ldmdb, sizeof(ldmdb), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1723));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_LDMDB);

    EXPECT(decode_t32(srsia, sizeof(srsia), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1724));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_SRS);
    EXPECT(decode_t32(rfeia, sizeof(rfeia), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1725));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_RFE);
#else
    (void)srsdb;
    (void)ldm;
    (void)stmdb;
    (void)ldmdb;
    (void)srsia;
    (void)rfeia;
    EXPECT(decode_t32(stm, sizeof(stm), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(rfedb, sizeof(rfedb), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    EXPECT(decode_t32(one_register, sizeof(one_register), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
    EXPECT(decode_t32(invalid_srs_mode, sizeof(invalid_srs_mode),
        &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
}

static void test_t32_shifted_logical(void)
{
    static const uint8_t and_rrx[4] = {0x01, 0xea, 0x33, 0x02};
    static const uint8_t tst_shift[4] = {0x11, 0xea, 0x43, 0x0f};
    static const uint8_t movs_shift[4] = {0x5f, 0xea, 0x43, 0x02};
    static const uint8_t orn_rrx[4] = {0x61, 0xea, 0x33, 0x02};
    static const uint8_t mvns_shift[4] = {0x7f, 0xea, 0x43, 0x02};
    static const uint8_t teq_rrx[4] = {0x91, 0xea, 0x33, 0x0f};
    static const uint8_t pkhbt[4] = {0xc1, 0xea, 0x43, 0x12};
    static const uint8_t pkhtb[4] = {0xc1, 0xea, 0xe3, 0x12};
    static const uint8_t add_rrx[4] = {0x01, 0xeb, 0x33, 0x02};
    static const uint8_t add_shift[4] = {0x01, 0xeb, 0x43, 0x12};
    static const uint8_t adds_rrx[4] = {0x11, 0xeb, 0x33, 0x02};
    static const uint8_t adds_shift[4] = {0x11, 0xeb, 0x43, 0x12};
    static const uint8_t add_sp_rrx[4] = {0x0d, 0xeb, 0x33, 0x02};
    static const uint8_t adds_sp_shift[4] = {0x1d, 0xeb, 0x43, 0x12};
    static const uint8_t cmn_rrx[4] = {0x11, 0xeb, 0x33, 0x0f};
    static const uint8_t cmn_shift[4] = {0x11, 0xeb, 0x43, 0x1f};
    static const uint8_t adc_rrx[4] = {0x41, 0xeb, 0x33, 0x02};
    static const uint8_t adcs_shift[4] = {0x51, 0xeb, 0x43, 0x12};
    static const uint8_t sbc_rrx[4] = {0x61, 0xeb, 0x33, 0x02};
    static const uint8_t sbcs_shift[4] = {0x71, 0xeb, 0x43, 0x12};
    static const uint8_t sub_rrx[4] = {0xa1, 0xeb, 0x33, 0x02};
    static const uint8_t subs_shift[4] = {0xb1, 0xeb, 0x43, 0x12};
    static const uint8_t sub_sp_rrx[4] = {0xad, 0xeb, 0x33, 0x02};
    static const uint8_t subs_sp_shift[4] = {0xbd, 0xeb, 0x43, 0x12};
    static const uint8_t cmp_rrx[4] = {0xb1, 0xeb, 0x33, 0x0f};
    static const uint8_t rsb_rrx[4] = {0xc1, 0xeb, 0x33, 0x02};
    static const uint8_t rsbs_shift[4] = {0xd1, 0xeb, 0x43, 0x12};
    static const uint8_t nop_w[4] = {0xaf, 0xf3, 0x00, 0x80};
    static const uint8_t yield_w[4] = {0xaf, 0xf3, 0x01, 0x80};
    static const uint8_t sevl_w[4] = {0xaf, 0xf3, 0x05, 0x80};
    static const uint8_t clrex_w[4] = {0xbf, 0xf3, 0x2f, 0x8f};
    static const uint8_t ssbb_w[4] = {0xbf, 0xf3, 0x40, 0x8f};
    static const uint8_t pssbb_w[4] = {0xbf, 0xf3, 0x44, 0x8f};
    static const uint8_t bad_pc_source[4] = {0x01, 0xea, 0x3f, 0x02};
    cdisasm_arm_instruction instruction;

#if USE_EXTRA_OPCODES
    EXPECT(decode_t32(and_rrx, sizeof(and_rrx), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1757));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_AND);
    EXPECT(instruction.operand_count == 3u);
    EXPECT(instruction.operand[2].shift_type == CDISASM_ARM_SHIFT_RRX);
    EXPECT(instruction.operand[2].shift_amount == 1u);
#  if USE_DISASM_FORMAT
    {
        char text[64];
        EXPECT(cdisasm_arm_format(&instruction, 0u, text, sizeof(text))
            == strlen("and r2, r1, r3, rrx"));
        EXPECT(strcmp(text, "and r2, r1, r3, rrx") == 0);
    }
#  endif

    EXPECT(decode_t32(tst_shift, sizeof(tst_shift), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1762));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_TST);
    EXPECT(instruction.operand_count == 2u);
    EXPECT(instruction.instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS);
    EXPECT(instruction.operand[1].shift_type == CDISASM_ARM_SHIFT_LSL);
    EXPECT(instruction.operand[1].shift_amount == 1u);

    EXPECT(decode_t32(movs_shift, sizeof(movs_shift), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1774));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_MOVS);
    EXPECT(instruction.operand_count == 2u);

    EXPECT(decode_t32(orn_rrx, sizeof(orn_rrx), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1775));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_ORN);
    EXPECT(instruction.operand[2].shift_type == CDISASM_ARM_SHIFT_RRX);
    EXPECT(decode_t32(mvns_shift, sizeof(mvns_shift), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1782));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_MVNS);
    EXPECT(decode_t32(teq_rrx, sizeof(teq_rrx), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1787));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_TEQ);
    EXPECT(instruction.operand_count == 2u);

    EXPECT(decode_t32(pkhbt, sizeof(pkhbt), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1789));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_PKHBT);
    EXPECT(instruction.operand[2].shift_type == CDISASM_ARM_SHIFT_LSL);
    EXPECT(instruction.operand[2].shift_amount == 5u);
    EXPECT(decode_t32(pkhtb, sizeof(pkhtb), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1790));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_PKHTB);
    EXPECT(instruction.operand[2].shift_type == CDISASM_ARM_SHIFT_ASR);
    EXPECT(instruction.operand[2].shift_amount == 7u);
    EXPECT(decode_t32(add_rrx, sizeof(add_rrx), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1791));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_ADD);
    EXPECT(instruction.operand[2].shift_type == CDISASM_ARM_SHIFT_RRX);
    EXPECT(decode_t32(add_shift, sizeof(add_shift), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1792));
    EXPECT(instruction.operand[2].shift_type == CDISASM_ARM_SHIFT_LSL);
    EXPECT(instruction.operand[2].shift_amount == 5u);
    EXPECT(decode_t32(adds_rrx, sizeof(adds_rrx), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1793));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_ADDS);
    EXPECT(instruction.instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS);
    EXPECT(decode_t32(adds_shift, sizeof(adds_shift), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1794));
    EXPECT(instruction.operand[2].shift_amount == 5u);
    EXPECT(decode_t32(add_sp_rrx, sizeof(add_sp_rrx), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1795));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_ADD);
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_R13);
    EXPECT(instruction.operand[2].shift_type == CDISASM_ARM_SHIFT_RRX);
    EXPECT(decode_t32(adds_sp_shift, sizeof(adds_sp_shift), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1798));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_ADDS);
    EXPECT(instruction.instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS);
    EXPECT(decode_t32(cmn_rrx, sizeof(cmn_rrx), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1799));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_CMN);
    EXPECT(instruction.operand_count == 2u);
    EXPECT(instruction.operand[1].shift_type == CDISASM_ARM_SHIFT_RRX);
    EXPECT(decode_t32(cmn_shift, sizeof(cmn_shift), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1800));
    EXPECT(instruction.operand[1].shift_amount == 5u);
    EXPECT(decode_t32(adc_rrx, sizeof(adc_rrx), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1801));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_ADC);
    EXPECT(instruction.operand[2].shift_type == CDISASM_ARM_SHIFT_RRX);
    EXPECT(decode_t32(adcs_shift, sizeof(adcs_shift), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1804));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_ADCS);
    EXPECT(instruction.instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS);
    EXPECT(decode_t32(sbc_rrx, sizeof(sbc_rrx), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1805));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_SBC);
    EXPECT(instruction.operand[2].shift_type == CDISASM_ARM_SHIFT_RRX);
    EXPECT(decode_t32(sbcs_shift, sizeof(sbcs_shift), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1808));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_SBCS);
    EXPECT(instruction.operand[2].shift_amount == 5u);
    EXPECT(decode_t32(sub_rrx, sizeof(sub_rrx), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1809));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_SUB);
    EXPECT(instruction.operand[2].shift_type == CDISASM_ARM_SHIFT_RRX);
    EXPECT(decode_t32(subs_shift, sizeof(subs_shift), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1812));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_SUBS);
    EXPECT(instruction.instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS);
    EXPECT(decode_t32(sub_sp_rrx, sizeof(sub_sp_rrx), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1813));
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_R13);
    EXPECT(decode_t32(subs_sp_shift, sizeof(subs_sp_shift), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1816));
    EXPECT(decode_t32(cmp_rrx, sizeof(cmp_rrx), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1817));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_CMP);
    EXPECT(instruction.operand_count == 2u);
    EXPECT(decode_t32(rsb_rrx, sizeof(rsb_rrx), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1819));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_RSB);
    EXPECT(decode_t32(rsbs_shift, sizeof(rsbs_shift), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1822));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_RSBS);
    EXPECT(decode_t32(nop_w, sizeof(nop_w), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1825));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_NOP);
    EXPECT(instruction.operand_count == 0u);
    EXPECT(decode_t32(yield_w, sizeof(yield_w), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1826));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_YIELD);
    EXPECT(decode_t32(sevl_w, sizeof(sevl_w), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1830));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_SEVL);
    EXPECT(decode_t32(clrex_w, sizeof(clrex_w), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1841));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_CLREX);
    EXPECT(decode_t32(ssbb_w, sizeof(ssbb_w), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1843));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_SSBB);
    EXPECT(instruction.operand_count == 0u);
    EXPECT(decode_t32(pssbb_w, sizeof(pssbb_w), &instruction) == 4u);
    EXPECT(instruction.form_id == UINT16_C(1844));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_PSSBB);
#else
    (void)movs_shift;
    (void)orn_rrx;
    (void)mvns_shift;
    (void)teq_rrx;
    EXPECT(decode_t32(and_rrx, sizeof(and_rrx), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(tst_shift, sizeof(tst_shift), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(pkhbt, sizeof(pkhbt), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(pkhtb, sizeof(pkhtb), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(add_rrx, sizeof(add_rrx), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(add_shift, sizeof(add_shift), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(adds_rrx, sizeof(adds_rrx), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(adds_shift, sizeof(adds_shift), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(add_sp_rrx, sizeof(add_sp_rrx), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(adds_sp_shift, sizeof(adds_sp_shift), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(cmn_rrx, sizeof(cmn_rrx), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(cmn_shift, sizeof(cmn_shift), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(adc_rrx, sizeof(adc_rrx), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(adcs_shift, sizeof(adcs_shift), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(sbc_rrx, sizeof(sbc_rrx), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(sbcs_shift, sizeof(sbcs_shift), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(sub_rrx, sizeof(sub_rrx), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(subs_shift, sizeof(subs_shift), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(sub_sp_rrx, sizeof(sub_sp_rrx), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(subs_sp_shift, sizeof(subs_sp_shift), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(cmp_rrx, sizeof(cmp_rrx), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(rsb_rrx, sizeof(rsb_rrx), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(rsbs_shift, sizeof(rsbs_shift), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(nop_w, sizeof(nop_w), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(yield_w, sizeof(yield_w), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(sevl_w, sizeof(sevl_w), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(clrex_w, sizeof(clrex_w), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(ssbb_w, sizeof(ssbb_w), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    EXPECT(decode_t32(pssbb_w, sizeof(pssbb_w), &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    EXPECT(decode_t32(bad_pc_source, sizeof(bad_pc_source),
        &instruction) == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
}

int main(void)
{
    test_a64_lsui_rmw();
    test_a64_lsui_compare_swap();
    test_a64_lsui_exclusive();
    test_a64_lsui_pairs();
    test_scalar_register_offset();
    test_a32_speculation_barriers();
    test_a32_instruction_prefetch();
    test_a32_data_prefetch();
    test_a32_register_prefetch();
    test_a32_write_intent_prefetch();
    test_t32_narrow_mov_shift_aliases();
    test_a32_movs_register_shift_aliases();
    test_a32_mov_register_shift_aliases();
    test_t32_wide_movs_register_shift_aliases();
    test_t32_wide_mov_register_shift_aliases();
    test_pair_and_unprivileged();
    test_literal_and_invalid();
    test_t32_wide_forms();
    test_t32_exclusive_and_table();
    test_t32_prefetch();
    test_t32_block_transfer();
    test_t32_shifted_logical();
    if (failures != 0) {
        fprintf(stderr, "%d ARM extra load/store test(s) failed\n", failures);
        return 1;
    }
    puts("ARM extra load/store tests passed");
    return 0;
}
