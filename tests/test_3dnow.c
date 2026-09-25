#include "test_decode_flags_adapter.h"


#include "cdisasm/cdisasm_x86.h"
#include "x86_test_flags.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

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

typedef struct selector_case {
    const char *mnemonic;
    uint8_t selector;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_group_id group_id;
} selector_case;

static const selector_case original_selectors[] = {
    {"pi2fd",    0x0d, CDISASM_X86_NAME_PI2FD,    CDISASM_X86_GROUP_3DNOW},
    {"pf2id",    0x1d, CDISASM_X86_NAME_PF2ID,    CDISASM_X86_GROUP_3DNOW},
    {"pfcmpge",  0x90, CDISASM_X86_NAME_PFCMPGE,  CDISASM_X86_GROUP_3DNOW},
    {"pfmin",    0x94, CDISASM_X86_NAME_PFMIN,    CDISASM_X86_GROUP_3DNOW},
    {"pfrcp",    0x96, CDISASM_X86_NAME_PFRCP,    CDISASM_X86_GROUP_3DNOW},
    {"pfrsqrt",  0x97, CDISASM_X86_NAME_PFRSQRT,  CDISASM_X86_GROUP_3DNOW},
    {"pfsub",    0x9a, CDISASM_X86_NAME_PFSUB,    CDISASM_X86_GROUP_3DNOW},
    {"pfadd",    0x9e, CDISASM_X86_NAME_PFADD,    CDISASM_X86_GROUP_3DNOW},
    {"pfcmpgt",  0xa0, CDISASM_X86_NAME_PFCMPGT,  CDISASM_X86_GROUP_3DNOW},
    {"pfmax",    0xa4, CDISASM_X86_NAME_PFMAX,    CDISASM_X86_GROUP_3DNOW},
    {"pfrcpit1", 0xa6, CDISASM_X86_NAME_PFRCPIT1, CDISASM_X86_GROUP_3DNOW},
    {"pfrsqit1", 0xa7, CDISASM_X86_NAME_PFRSQIT1, CDISASM_X86_GROUP_3DNOW},
    {"pfsubr",   0xaa, CDISASM_X86_NAME_PFSUBR,   CDISASM_X86_GROUP_3DNOW},
    {"pfacc",    0xae, CDISASM_X86_NAME_PFACC,    CDISASM_X86_GROUP_3DNOW},
    {"pfcmpeq",  0xb0, CDISASM_X86_NAME_PFCMPEQ,  CDISASM_X86_GROUP_3DNOW},
    {"pfmul",    0xb4, CDISASM_X86_NAME_PFMUL,    CDISASM_X86_GROUP_3DNOW},
    {"pfrcpit2", 0xb6, CDISASM_X86_NAME_PFRCPIT2, CDISASM_X86_GROUP_3DNOW},
    {"pmulhrw",  0xb7, CDISASM_X86_NAME_PMULHRW,  CDISASM_X86_GROUP_3DNOW},
    {"pavgusb",  0xbf, CDISASM_X86_NAME_PAVGUSB,  CDISASM_X86_GROUP_3DNOW}
};

static const selector_case extended_selectors[] = {
    {"pi2fw",   0x0c, CDISASM_X86_NAME_PI2FW,   CDISASM_X86_GROUP_3DNOW_EXT},
    {"pf2iw",   0x1c, CDISASM_X86_NAME_PF2IW,   CDISASM_X86_GROUP_3DNOW_EXT},
    {"pfnacc",  0x8a, CDISASM_X86_NAME_PFNACC,  CDISASM_X86_GROUP_3DNOW_EXT},
    {"pfpnacc", 0x8e, CDISASM_X86_NAME_PFPNACC, CDISASM_X86_GROUP_3DNOW_EXT},
    {"pswapd",  0xbb, CDISASM_X86_NAME_PSWAPD,  CDISASM_X86_GROUP_3DNOW_EXT}
};

static int bytes_are_zero(const void *memory, size_t size)
{
    const unsigned char *bytes = (const unsigned char *)memory;
    size_t index;

    for (index = 0; index < size; ++index) {
        if (bytes[index] != 0) {
            return 0;
        }
    }
    return 1;
}

static int groups_are_exact(
    const cdisasm_instruction *instruction,
    const cdisasm_x86_group_id *expected,
    size_t expected_count)
{
    size_t index;

    if (instruction->x86_group_count != expected_count
        || expected_count > CDISASM_MAX_X86_GROUPS
        || instruction->x86_group_reserved != 0) {
        return 0;
    }
    for (index = 0; index < expected_count; ++index) {
        if (instruction->x86_group_ids[index] != expected[index]) {
            return 0;
        }
        if (index != 0 && expected[index - 1] >= expected[index]) {
            return 0;
        }
    }
    for (; index < CDISASM_MAX_X86_GROUPS; ++index) {
        if (instruction->x86_group_ids[index] != CDISASM_X86_GROUP_NONE) {
            return 0;
        }
    }
    return 1;
}

#if USE_DISASM_FORMAT
static void expect_text(
    const char *label,
    const cdisasm_instruction *instruction,
    const char *expected)
{
    char text[160];
    size_t expected_size = strlen(expected);
    size_t required;

    required = cdisasm_x86_format(
        instruction, CDISASM_FORMAT_SYNTAX_0, NULL, 0);
    if (required != expected_size) {
        fprintf(stderr, "%s: format query returned %zu, expected %zu\n",
                label, required, expected_size);
        ++failures;
    }

    memset(text, 'X', sizeof(text));
    required = cdisasm_x86_format(
        instruction, CDISASM_FORMAT_SYNTAX_0, text, sizeof(text));
    if (required != expected_size || strcmp(text, expected) != 0) {
        fprintf(stderr, "%s: formatted as \"%s\", expected \"%s\"\n",
                label, text, expected);
        ++failures;
    }
}
#else
static void expect_text(
    const char *label,
    const cdisasm_instruction *instruction,
    const char *expected)
{
    (void)label;
    (void)instruction;
    (void)expected;
}
#endif

static uint32_t decode(
    cdisasm_cpu_id cpu_id,
    cdisasm_mode mode,
    const uint8_t *bytes,
    size_t size,
    uint64_t address,
    cdisasm_instruction *instruction)
{
    memset(instruction, 0xa5, sizeof(*instruction));
    return cdisasm_x86_decode(
        cpu_id,
        mode,
        bytes,
        size,
        address,
        CDISASM_X86_TEST_ALL_FLAGS,
        instruction);
}

static void expect_failure(
    const char *label,
    cdisasm_cpu_id cpu_id,
    cdisasm_mode mode,
    const uint8_t *bytes,
    size_t size,
    cdisasm_status expected_status)
{
    cdisasm_instruction instruction;
    cdisasm_instruction expected;
    uint32_t decoded_size = decode(
        cpu_id, mode, bytes, size, UINT64_C(0x1000), &instruction);

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)expected_status;
    if (decoded_size != 0
        || instruction.last_error_id != expected_status
        || memcmp(&instruction, &expected, sizeof(expected)) != 0) {
        fprintf(stderr,
                "%s: decode=%u status=%u, expected error-only status=%u\n",
                label,
                (unsigned int)decoded_size,
                (unsigned int)instruction.last_error_id,
                (unsigned int)expected_status);
        ++failures;
    }
}

static void expect_selector(const selector_case *test)
{
    const uint8_t bytes[] = {0x0f, 0x0f, 0xc1, test->selector};
    const cdisasm_x86_group_id groups[] = {test->group_id};
    cdisasm_instruction instruction;
    char expected_text[64];
    uint32_t decoded_size = decode(
        CDISASM_CPU_X86,
        CDISASM_MODE_32,
        bytes,
        sizeof(bytes),
        UINT64_C(0x2000),
        &instruction);
    int result = snprintf(expected_text, sizeof(expected_text),
                          "%s mm0, mm1", test->mnemonic);
    size_t index;

    if (decoded_size != sizeof(bytes)
        || instruction.last_error_id != CDISASM_STATUS_OK
        || instruction.opcode_size != sizeof(bytes)
        || instruction.address != UINT64_C(0x2000)
        || instruction.branch_target != 0
        || instruction.opcode_groups != CDISASM_GROUP_NONE
        || instruction.opcode_flags != CDISASM_PREFIX_NONE
        || instruction.name_id != test->name_id
        || instruction.operand_count != 2
        || !groups_are_exact(&instruction, groups, 1)) {
        fprintf(stderr,
                "%s: decode=%u status=%u name=%u operands=%u groups=%u\n",
                test->mnemonic,
                (unsigned int)decoded_size,
                (unsigned int)instruction.last_error_id,
                (unsigned int)instruction.name_id,
                (unsigned int)instruction.operand_count,
                (unsigned int)instruction.x86_group_count);
        ++failures;
        return;
    }

    EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_MM0);
    EXPECT(instruction.opcode[0].size == 8);
    EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction.opcode[0].index_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction.opcode[0].segment_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction.opcode[0].scale == 0);
    EXPECT(instruction.opcode[0].flags == CDISASM_OPERAND_FLAG_NONE);
    EXPECT(instruction.opcode[0].access
           != CDISASM_OPERAND_ACCESS_NONE);
    EXPECT(instruction.opcode[0].address == 0);
    EXPECT(instruction.opcode[0].imm == 0);

    EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_MM1);
    EXPECT(instruction.opcode[1].size == 8);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction.opcode[1].index_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction.opcode[1].segment_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction.opcode[1].scale == 0);
    EXPECT(instruction.opcode[1].flags == CDISASM_OPERAND_FLAG_NONE);
    EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.opcode[1].address == 0);
    EXPECT(instruction.opcode[1].imm == 0);
    EXPECT(instruction.encoding.prefix_size == 0);
    EXPECT(instruction.encoding.opcode_offset == 0);
    EXPECT(instruction.encoding.opcode_size == 2);
    EXPECT(instruction.encoding.modrm_offset == 2);
    EXPECT(instruction.encoding.modrm == 0xc1);
    EXPECT(instruction.encoding.sib_offset == 0);
    EXPECT(instruction.encoding.displacement_size == 0);
    EXPECT(instruction.encoding.immediate_count == 0);
    EXPECT(instruction.encoding.selector_offset == 3);

    for (index = instruction.operand_count;
         index < CDISASM_MAX_OPERANDS;
         ++index) {
        EXPECT(bytes_are_zero(
            &instruction.opcode[index], sizeof(instruction.opcode[index])));
    }
    EXPECT(result > 0 && (size_t)result < sizeof(expected_text));
    expect_text(test->mnemonic, &instruction, expected_text);
}

static void test_all_selector_operations(void)
{
    unsigned char selectors_seen[256] = {0};
    size_t index;

    /*
     * Original 3DNow! consists of these nineteen packed-operation selectors,
     * FEMMS, and the PREFETCH hint family tested separately below. AMD counts
     * PREFETCH/PREFETCHW as one operation family in the historical total of 21.
     */
    EXPECT(sizeof(original_selectors) / sizeof(original_selectors[0]) == 19);
    for (index = 0;
         index < sizeof(original_selectors) / sizeof(original_selectors[0]);
         ++index) {
        EXPECT(selectors_seen[original_selectors[index].selector] == 0);
        selectors_seen[original_selectors[index].selector] = 1;
        expect_selector(&original_selectors[index]);
    }

    EXPECT(sizeof(extended_selectors) / sizeof(extended_selectors[0]) == 5);
    for (index = 0;
         index < sizeof(extended_selectors) / sizeof(extended_selectors[0]);
         ++index) {
        EXPECT(selectors_seen[extended_selectors[index].selector] == 0);
        selectors_seen[extended_selectors[index].selector] = 1;
        expect_selector(&extended_selectors[index]);
    }
}

static void test_femms_and_prefetch_classification(void)
{
    static const uint8_t femms[] = {0x0f, 0x0e};
    static const uint8_t prefetch[] = {0x0f, 0x0d, 0x00};
    static const uint8_t prefetchw[] = {0x0f, 0x0d, 0x08};
    static const uint8_t prefetchw_r3[] = {0x0f, 0x0d, 0x18};
    static const cdisasm_x86_group_id femms_groups[] = {
        CDISASM_X86_GROUP_3DNOW
    };
    static const cdisasm_x86_group_id prefetch_groups[] = {
        CDISASM_X86_GROUP_I386,
        CDISASM_X86_GROUP_PREFETCHW
    };
    cdisasm_instruction instruction;

    EXPECT(decode(CDISASM_CPU_X86, CDISASM_MODE_32,
                  femms, sizeof(femms), 0, &instruction) == sizeof(femms));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_FEMMS);
    EXPECT(instruction.operand_count == 0);
    EXPECT(groups_are_exact(&instruction, femms_groups, 1));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_3DNOW));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_3DNOW_EXT));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_PREFETCHW));
    expect_text("FEMMS", &instruction, "femms");

    EXPECT(decode(CDISASM_CPU_X86, CDISASM_MODE_32,
                  prefetch, sizeof(prefetch), 0, &instruction)
           == sizeof(prefetch));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_PREFETCH);
    EXPECT(instruction.operand_count == 1);
    EXPECT(groups_are_exact(&instruction, prefetch_groups, 2));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_3DNOW));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_3DNOW_EXT));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_PREFETCHW));
    EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_EAX);
    EXPECT(instruction.opcode[0].size == 1);
    expect_text("PREFETCH", &instruction, "prefetch byte ptr [eax]");

    EXPECT(decode(CDISASM_CPU_X86, CDISASM_MODE_32,
                  prefetchw, sizeof(prefetchw), 0, &instruction)
           == sizeof(prefetchw));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_PREFETCHW);
    EXPECT(instruction.operand_count == 1);
    EXPECT(groups_are_exact(&instruction, prefetch_groups, 2));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_3DNOW));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_3DNOW_EXT));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_PREFETCHW));
    EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_EAX);
    EXPECT(instruction.opcode[0].size == 1);
    expect_text("PREFETCHW", &instruction, "prefetchw byte ptr [eax]");

    EXPECT(decode(CDISASM_CPU_X86, CDISASM_MODE_32,
                  prefetchw_r3, sizeof(prefetchw_r3), 0, &instruction)
           == sizeof(prefetchw_r3));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_PREFETCHW);
    EXPECT(instruction.operand_count == 1);
    EXPECT(groups_are_exact(&instruction, prefetch_groups, 2));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_PREFETCHW));
    EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_EAX);
    EXPECT(instruction.opcode[0].size == 1);
    expect_text("PREFETCHW /3", &instruction, "prefetchw byte ptr [eax]");

}

static void test_memory_operands(void)
{
    static const uint8_t base_sib_disp[] = {
        0x0f, 0x0f, 0x54, 0x8b, 0xf0, 0xa6
    };
    static const uint8_t extended_disp[] = {
        0x0f, 0x0f, 0x7e, 0x20, 0xbb
    };
    static const uint8_t rip_relative[] = {
        0x0f, 0x0f, 0x15, 0x10, 0x00, 0x00, 0x00, 0xbf
    };
    static const uint8_t prefetchw_sib_disp[] = {
        0x0f, 0x0d, 0x4c, 0x8b, 0xf0
    };
    static const cdisasm_x86_group_id base_groups[] = {
        CDISASM_X86_GROUP_I386,
        CDISASM_X86_GROUP_3DNOW
    };
    static const cdisasm_x86_group_id extended_groups[] = {
        CDISASM_X86_GROUP_I386,
        CDISASM_X86_GROUP_3DNOW_EXT
    };
    static const cdisasm_x86_group_id long_groups[] = {
        CDISASM_X86_GROUP_3DNOW,
        CDISASM_X86_GROUP_AMD64
    };
    static const cdisasm_x86_group_id prefetch_groups[] = {
        CDISASM_X86_GROUP_I386,
        CDISASM_X86_GROUP_PREFETCHW
    };
    cdisasm_instruction instruction;
    const cdisasm_opcode *memory;

    EXPECT(decode(CDISASM_CPU_X86, CDISASM_MODE_32,
                  base_sib_disp, sizeof(base_sib_disp), 0, &instruction)
           == sizeof(base_sib_disp));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_PFRCPIT1);
    EXPECT(instruction.operand_count == 2);
    EXPECT(groups_are_exact(&instruction, base_groups, 2));
    EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_MM2);
    EXPECT(instruction.opcode[0].size == 8);
    memory = &instruction.opcode[1];
    EXPECT(memory->type == CDISASM_OPERAND_MEMORY);
    EXPECT(memory->reg == CDISASM_X86_REG_NONE);
    EXPECT(memory->base_reg == CDISASM_X86_REG_EBX);
    EXPECT(memory->index_reg == CDISASM_X86_REG_ECX);
    EXPECT(memory->segment_reg == CDISASM_X86_REG_NONE);
    EXPECT(memory->size == 8);
    EXPECT(memory->scale == 4);
    EXPECT(memory->imm == UINT64_MAX - UINT64_C(15));
    EXPECT(memory->address == 0);
    EXPECT(memory->flags == CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT);
    EXPECT(instruction.encoding.opcode_size == 2);
    EXPECT(instruction.encoding.modrm_offset == 2);
    EXPECT(instruction.encoding.modrm == 0x54);
    EXPECT(instruction.encoding.sib_offset == 3);
    EXPECT(instruction.encoding.sib == 0x8b);
    EXPECT(instruction.encoding.displacement_offset == 4);
    EXPECT(instruction.encoding.displacement_size == 1);
    EXPECT(instruction.encoding.selector_offset == 5);
    expect_text("base SIB displacement", &instruction,
                "pfrcpit1 mm2, qword ptr [ebx + ecx*4 - 0x10]");

    EXPECT(decode(CDISASM_CPU_X86, CDISASM_MODE_32,
                  extended_disp, sizeof(extended_disp), 0, &instruction)
           == sizeof(extended_disp));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_PSWAPD);
    EXPECT(instruction.operand_count == 2);
    EXPECT(groups_are_exact(&instruction, extended_groups, 2));
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_MM7);
    memory = &instruction.opcode[1];
    EXPECT(memory->type == CDISASM_OPERAND_MEMORY);
    EXPECT(memory->base_reg == CDISASM_X86_REG_ESI);
    EXPECT(memory->index_reg == CDISASM_X86_REG_NONE);
    EXPECT(memory->size == 8);
    EXPECT(memory->scale == 0);
    EXPECT(memory->imm == UINT64_C(0x20));
    EXPECT(memory->flags == CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT);
    EXPECT(instruction.encoding.opcode_size == 2);
    EXPECT(instruction.encoding.modrm_offset == 2);
    EXPECT(instruction.encoding.modrm == 0x7e);
    EXPECT(instruction.encoding.sib_offset == 0);
    EXPECT(instruction.encoding.displacement_offset == 3);
    EXPECT(instruction.encoding.displacement_size == 1);
    EXPECT(instruction.encoding.selector_offset == 4);
    expect_text("extended displacement", &instruction,
                "pswapd mm7, qword ptr [esi + 0x20]");

    EXPECT(decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                  rip_relative, sizeof(rip_relative), UINT64_C(0x1000),
                  &instruction) == sizeof(rip_relative));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_PAVGUSB);
    EXPECT(instruction.operand_count == 2);
    EXPECT(groups_are_exact(&instruction, long_groups, 2));
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_MM2);
    memory = &instruction.opcode[1];
    EXPECT(memory->type == CDISASM_OPERAND_MEMORY);
    EXPECT(memory->base_reg == CDISASM_X86_REG_RIP);
    EXPECT(memory->index_reg == CDISASM_X86_REG_NONE);
    EXPECT(memory->size == 8);
    EXPECT(memory->imm == UINT64_C(0x10));
    EXPECT(memory->address == UINT64_C(0x1018));
    EXPECT(memory->flags
           == (CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
               | CDISASM_OPERAND_FLAG_PC_RELATIVE
               | CDISASM_OPERAND_FLAG_HAS_ADDRESS));
    expect_text("RIP-relative source", &instruction,
                "pavgusb mm2, qword ptr [rip + 0x10]");

    EXPECT(decode(CDISASM_CPU_X86, CDISASM_MODE_32,
                  prefetchw_sib_disp, sizeof(prefetchw_sib_disp), 0,
                  &instruction) == sizeof(prefetchw_sib_disp));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_PREFETCHW);
    EXPECT(instruction.operand_count == 1);
    EXPECT(groups_are_exact(&instruction, prefetch_groups, 2));
    memory = &instruction.opcode[0];
    EXPECT(memory->type == CDISASM_OPERAND_MEMORY);
    EXPECT(memory->base_reg == CDISASM_X86_REG_EBX);
    EXPECT(memory->index_reg == CDISASM_X86_REG_ECX);
    EXPECT(memory->size == 1);
    EXPECT(memory->scale == 4);
    EXPECT(memory->imm == UINT64_MAX - UINT64_C(15));
    EXPECT(memory->flags == CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT);
    EXPECT(instruction.encoding.opcode_size == 2);
    EXPECT(instruction.encoding.modrm_offset == 2);
    EXPECT(instruction.encoding.modrm == 0x4c);
    EXPECT(instruction.encoding.sib_offset == 3);
    EXPECT(instruction.encoding.sib == 0x8b);
    EXPECT(instruction.encoding.displacement_offset == 4);
    EXPECT(instruction.encoding.displacement_size == 1);
    EXPECT(instruction.encoding.selector_offset == 0);
    expect_text("PREFETCHW SIB displacement", &instruction,
                "prefetchw byte ptr [ebx + ecx*4 - 0x10]");
}

static void test_modes(void)
{
    static const uint8_t arithmetic[] = {0x0f, 0x0f, 0xc1, 0xbf};
    static const uint8_t extended[] = {0x0f, 0x0f, 0xc1, 0x1c};
    static const uint8_t prefetchw[] = {0x0f, 0x0d, 0x08};
    static const cdisasm_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    static const cdisasm_x86_reg_id address_bases[] = {
        CDISASM_X86_REG_BX, CDISASM_X86_REG_EAX, CDISASM_X86_REG_RAX
    };
    static const char *const prefetch_text[] = {
        "prefetchw byte ptr [bx + si]",
        "prefetchw byte ptr [eax]",
        "prefetchw byte ptr [rax]"
    };
    cdisasm_instruction instruction;
    size_t index;

    for (index = 0; index < sizeof(modes) / sizeof(modes[0]); ++index) {
        EXPECT(decode(CDISASM_CPU_X86, modes[index], arithmetic,
                      sizeof(arithmetic), 0, &instruction)
               == sizeof(arithmetic));
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_PAVGUSB);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_MM0);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_MM1);
        expect_text("arithmetic mode", &instruction, "pavgusb mm0, mm1");

        EXPECT(decode(CDISASM_CPU_X86, modes[index], extended,
                      sizeof(extended), 0, &instruction)
               == sizeof(extended));
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_PF2IW);
        expect_text("extended mode", &instruction, "pf2iw mm0, mm1");

        EXPECT(decode(CDISASM_CPU_X86, modes[index], prefetchw,
                      sizeof(prefetchw), 0, &instruction)
               == sizeof(prefetchw));
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_PREFETCHW);
        EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.opcode[0].base_reg == address_bases[index]);
        if (modes[index] == CDISASM_MODE_16) {
            EXPECT(instruction.opcode[0].index_reg == CDISASM_X86_REG_SI);
        } else {
            EXPECT(instruction.opcode[0].index_reg == CDISASM_X86_REG_NONE);
        }
        expect_text("PREFETCHW mode", &instruction, prefetch_text[index]);
    }

    EXPECT(decode(CDISASM_CPU_AMD_K6_2, CDISASM_MODE_16,
                  arithmetic, sizeof(arithmetic), 0, &instruction)
           == sizeof(arithmetic));
    EXPECT(decode(CDISASM_CPU_AMD_K6_2, CDISASM_MODE_32,
                  arithmetic, sizeof(arithmetic), 0, &instruction)
           == sizeof(arithmetic));
    EXPECT(decode(CDISASM_CPU_ATHLON_64, CDISASM_MODE_64,
                  arithmetic, sizeof(arithmetic), 0, &instruction)
           == sizeof(arithmetic));
}

typedef struct cpu_case {
    const char *label;
    cdisasm_cpu_id cpu_id;
    unsigned char arithmetic;
    unsigned char extended;
    unsigned char prefetch;
    unsigned char prefetchw;
} cpu_case;

static void expect_cpu_result(
    const cpu_case *test,
    const char *operation,
    const uint8_t *bytes,
    size_t size,
    int should_decode)
{
    cdisasm_instruction instruction;
    uint32_t decoded_size = decode(
        test->cpu_id, CDISASM_MODE_32, bytes, size, 0, &instruction);

    if (should_decode) {
        if (decoded_size != size
            || instruction.last_error_id != CDISASM_STATUS_OK) {
            fprintf(stderr, "%s %s: decode=%u status=%u, expected success\n",
                    test->label,
                    operation,
                    (unsigned int)decoded_size,
                    (unsigned int)instruction.last_error_id);
            ++failures;
        }
    } else if (decoded_size != 0
               || instruction.last_error_id
                    != CDISASM_STATUS_INVALID_INSTRUCTION) {
        fprintf(stderr, "%s %s: decode=%u status=%u, expected invalid for CPU\n",
                test->label,
                operation,
                (unsigned int)decoded_size,
                (unsigned int)instruction.last_error_id);
        ++failures;
    }
}

static void test_cpu_profile_matrix(void)
{
    static const uint8_t arithmetic[] = {0x0f, 0x0f, 0xc1, 0xbf};
    static const uint8_t extended[] = {0x0f, 0x0f, 0xc1, 0x1c};
    static const uint8_t prefetch[] = {0x0f, 0x0d, 0x00};
    static const uint8_t prefetchw[] = {0x0f, 0x0d, 0x08};
    static const cpu_case cases[] = {
        {"generic",        CDISASM_CPU_X86,            1, 1, 1, 1},
        {"AMD K6-2",       CDISASM_CPU_AMD_K6_2,       1, 0, 1, 1},
        {"Athlon 64",      CDISASM_CPU_ATHLON_64,      1, 1, 1, 1},
        {"AMD-V",          CDISASM_CPU_AMD_V,          1, 1, 1, 1},
        {"Barcelona",      CDISASM_CPU_AMD_BARCELONA,  1, 1, 1, 1},
        {"Bulldozer",      CDISASM_CPU_AMD_BULLDOZER,  0, 0, 1, 1},
        {"Zen",            CDISASM_CPU_AMD_ZEN,        0, 0, 1, 1},
        {"Zen 4",          CDISASM_CPU_AMD_ZEN_4,      0, 0, 1, 1},
        {"Pentium MMX",    CDISASM_CPU_PENTIUM_MMX,    0, 0, 0, 0},
        {"Pentium III",    CDISASM_CPU_PENTIUM_III,    0, 0, 0, 0},
        {"Intel VT-x",     CDISASM_CPU_INTEL_VT_X,     0, 0, 0, 0},
        {"Intel Haswell",  CDISASM_CPU_HASWELL,        0, 0, 0, 0},
        {"Intel Broadwell",CDISASM_CPU_BROADWELL,      0, 0, 0, 1},
        {"Intel Goldmont", CDISASM_CPU_GOLDMONT,       0, 0, 0, 1},
        {"Intel APX",      CDISASM_CPU_APX,            0, 0, 0, 1},
        {"Celeron G1840",  CDISASM_CPU_CELERON_G1840,  0, 0, 0, 0},
        {"Celeron G3900",  CDISASM_CPU_CELERON_G3900,  0, 0, 0, 0},
        {"Celeron N3350",  CDISASM_CPU_CELERON_N3350,  0, 0, 0, 1},
        {"Celeron N4020",  CDISASM_CPU_CELERON_N4020,  0, 0, 0, 1},
        {"Celeron G5900",  CDISASM_CPU_CELERON_G5900,  0, 0, 0, 0},
        {"Pentium N6000",  CDISASM_CPU_PENTIUM_SILVER_N6000,
                                                       0, 0, 0, 1}
    };
    static const cpu_case k6_2 = {
        "AMD K6-2 selector sweep", CDISASM_CPU_AMD_K6_2, 1, 0, 1, 1
    };
    static const cpu_case athlon_64 = {
        "Athlon 64 selector sweep", CDISASM_CPU_ATHLON_64, 1, 1, 1, 1
    };
    static const cpu_case bulldozer = {
        "Bulldozer selector sweep", CDISASM_CPU_AMD_BULLDOZER, 0, 0, 1, 1
    };
    static const cpu_case intel = {
        "Intel selector sweep", CDISASM_CPU_HASWELL, 0, 0, 0, 0
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_cpu_result(&cases[index], "3DNow!", arithmetic,
                          sizeof(arithmetic), cases[index].arithmetic);
        expect_cpu_result(&cases[index], "Extended 3DNow!", extended,
                          sizeof(extended), cases[index].extended);
        expect_cpu_result(&cases[index], "PREFETCH", prefetch,
                          sizeof(prefetch), cases[index].prefetch);
        expect_cpu_result(&cases[index], "PREFETCHW", prefetchw,
                          sizeof(prefetchw), cases[index].prefetchw);
    }

    /* Verify that capability lookup is attached to every mnemonic, not only
     * to one representative selector from each family. */
    for (index = 0;
         index < sizeof(original_selectors) / sizeof(original_selectors[0]);
         ++index) {
        const uint8_t bytes[] = {
            0x0f, 0x0f, 0xc1, original_selectors[index].selector
        };

        expect_cpu_result(&k6_2, original_selectors[index].mnemonic,
                          bytes, sizeof(bytes), 1);
        expect_cpu_result(&bulldozer, original_selectors[index].mnemonic,
                          bytes, sizeof(bytes), 0);
        expect_cpu_result(&intel, original_selectors[index].mnemonic,
                          bytes, sizeof(bytes), 0);
    }
    for (index = 0;
         index < sizeof(extended_selectors) / sizeof(extended_selectors[0]);
         ++index) {
        const uint8_t bytes[] = {
            0x0f, 0x0f, 0xc1, extended_selectors[index].selector
        };

        expect_cpu_result(&athlon_64, extended_selectors[index].mnemonic,
                          bytes, sizeof(bytes), 1);
        expect_cpu_result(&k6_2, extended_selectors[index].mnemonic,
                          bytes, sizeof(bytes), 0);
        expect_cpu_result(&bulldozer, extended_selectors[index].mnemonic,
                          bytes, sizeof(bytes), 0);
        expect_cpu_result(&intel, extended_selectors[index].mnemonic,
                          bytes, sizeof(bytes), 0);
    }
    {
        static const uint8_t femms[] = {0x0f, 0x0e};

        expect_cpu_result(&k6_2, "femms", femms, sizeof(femms), 1);
        expect_cpu_result(&athlon_64, "femms", femms, sizeof(femms), 1);
        expect_cpu_result(&bulldozer, "femms", femms, sizeof(femms), 0);
        expect_cpu_result(&intel, "femms", femms, sizeof(femms), 0);
    }
}

static void test_invalid_and_truncated_encodings(void)
{
    static const uint8_t missing_modrm[] = {0x0f, 0x0f};
    static const uint8_t missing_selector[] = {0x0f, 0x0f, 0xc0};
    static const uint8_t missing_sib[] = {0x0f, 0x0f, 0x04};
    static const uint8_t short_displacement[] = {
        0x0f, 0x0f, 0x85, 0x01, 0x02, 0x03
    };
    static const uint8_t memory_without_selector[] = {
        0x0f, 0x0f, 0x04, 0x25, 0x78, 0x56, 0x34, 0x12
    };
    static const uint8_t unknown_zero[] = {0x0f, 0x0f, 0xc0, 0x00};
    static const uint8_t unknown_opcode_byte[] = {0x0f, 0x0f, 0xc0, 0x0e};
    static const uint8_t unknown_high[] = {0x0f, 0x0f, 0xc0, 0xff};
    static const uint8_t prefetch_missing_modrm[] = {0x0f, 0x0d};
    static const uint8_t prefetch_missing_sib[] = {0x0f, 0x0d, 0x04};
    static const uint8_t prefetch_short_displacement[] = {
        0x0f, 0x0d, 0x05, 0x01, 0x02, 0x03
    };
    static const uint8_t prefetch_register[] = {0x0f, 0x0d, 0xc0};
    static const uint8_t prefetchw_register[] = {0x0f, 0x0d, 0xc8};

    expect_failure("3DNow missing ModRM", CDISASM_CPU_X86,
                   CDISASM_MODE_32, missing_modrm, sizeof(missing_modrm),
                   CDISASM_STATUS_TRUNCATED);
    expect_failure("3DNow missing selector", CDISASM_CPU_X86,
                   CDISASM_MODE_32, missing_selector, sizeof(missing_selector),
                   CDISASM_STATUS_TRUNCATED);
    expect_failure("3DNow missing SIB", CDISASM_CPU_X86,
                   CDISASM_MODE_32, missing_sib, sizeof(missing_sib),
                   CDISASM_STATUS_TRUNCATED);
    expect_failure("3DNow short displacement", CDISASM_CPU_X86,
                   CDISASM_MODE_32, short_displacement,
                   sizeof(short_displacement), CDISASM_STATUS_TRUNCATED);
    expect_failure("3DNow memory missing selector", CDISASM_CPU_X86,
                   CDISASM_MODE_32, memory_without_selector,
                   sizeof(memory_without_selector), CDISASM_STATUS_TRUNCATED);

    expect_failure("unknown selector 00", CDISASM_CPU_X86,
                   CDISASM_MODE_32, unknown_zero, sizeof(unknown_zero),
                   CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_failure("opcode byte is not a selector", CDISASM_CPU_X86,
                   CDISASM_MODE_32, unknown_opcode_byte,
                   sizeof(unknown_opcode_byte),
                   CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_failure("unknown selector FF", CDISASM_CPU_X86,
                   CDISASM_MODE_32, unknown_high, sizeof(unknown_high),
                   CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    expect_failure("PREFETCH missing ModRM", CDISASM_CPU_X86,
                   CDISASM_MODE_32, prefetch_missing_modrm,
                   sizeof(prefetch_missing_modrm), CDISASM_STATUS_TRUNCATED);
    expect_failure("PREFETCH missing SIB", CDISASM_CPU_X86,
                   CDISASM_MODE_32, prefetch_missing_sib,
                   sizeof(prefetch_missing_sib), CDISASM_STATUS_TRUNCATED);
    expect_failure("PREFETCH short displacement", CDISASM_CPU_X86,
                   CDISASM_MODE_32, prefetch_short_displacement,
                   sizeof(prefetch_short_displacement),
                   CDISASM_STATUS_TRUNCATED);
    expect_failure("PREFETCH register ModRM", CDISASM_CPU_X86,
                   CDISASM_MODE_32, prefetch_register,
                   sizeof(prefetch_register),
                   CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("PREFETCHW register ModRM", CDISASM_CPU_X86,
                   CDISASM_MODE_32, prefetchw_register,
                   sizeof(prefetchw_register),
                   CDISASM_STATUS_INVALID_INSTRUCTION);
}

int main(void)
{
    test_all_selector_operations();
    test_femms_and_prefetch_classification();
    test_memory_operands();
    test_modes();
    test_cpu_profile_matrix();
    test_invalid_and_truncated_encodings();

    if (failures != 0) {
        fprintf(stderr, "%d 3DNow test(s) failed\n", failures);
        return 1;
    }
    puts("all cdisasm 3DNow tests passed");
    return 0;
}
