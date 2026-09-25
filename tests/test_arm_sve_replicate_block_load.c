#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
# include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>

static int failures;
#define EXPECT(c) do { if (!(c)) { if (failures < 20) fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); ++failures; } } while (0)

static uint32_t decode_word(uint32_t word, cdisasm_arm_cpu_id cpu,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4] = {(uint8_t)word, (uint8_t)(word >> 8),
        (uint8_t)(word >> 16), (uint8_t)(word >> 24)};
    memset(instruction, 0xa5, sizeof(*instruction));
    return cdisasm_arm_decode(cpu, CDISASM_ARM_MODE_A64, bytes, 4,
        UINT64_C(0x18000), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static int error_only(const cdisasm_arm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_arm_instruction expected;
    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

#if USE_EXTRA_OPCODES
static void check_result(const cdisasm_arm_instruction *instruction,
    uint32_t word, unsigned size_log2, unsigned octaword, unsigned immediate)
{
    static const cdisasm_arm_name_id qnames[4] = {
        CDISASM_ARM_NAME_LD1RQB, CDISASM_ARM_NAME_LD1RQH,
        CDISASM_ARM_NAME_LD1RQW, CDISASM_ARM_NAME_LD1RQD};
    static const cdisasm_arm_name_id onames[4] = {
        CDISASM_ARM_NAME_LD1ROB, CDISASM_ARM_NAME_LD1ROH,
        CDISASM_ARM_NAME_LD1ROW, CDISASM_ARM_NAME_LD1ROD};
    unsigned zd = word & 31u, pg = (word >> 10) & 7u;
    unsigned rn = (word >> 5) & 31u, rm_or_imm = (word >> 16) & 31u;
    uint8_t element_size = (uint8_t)(1u << size_log2);
    uint8_t memory_size = octaword ? 32u : 16u;
    int64_t displacement = immediate
        ? ((int64_t)((int32_t)((rm_or_imm & 15u) << 28) >> 28)) * memory_size
        : 0;
    const cdisasm_arm_operand *destination = &instruction->operand[0];
    const cdisasm_arm_operand *predicate = &instruction->operand[1];
    const cdisasm_arm_operand *memory = &instruction->operand[2];

    EXPECT(instruction->name_id == (octaword ? onames[size_log2] : qnames[size_log2]));
    EXPECT(instruction->form_id == (immediate ? 3267u : 3259u) + size_log2 * 2u + octaword);
    EXPECT(instruction->instruction_flags == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT(instruction->operand_count == 3u);
    EXPECT(destination->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);
    EXPECT(destination->reg == CDISASM_ARM_REG_Z0 + zd);
    EXPECT(destination->register_list == UINT16_C(0x0101));
    EXPECT(destination->extend_type == element_size);
    EXPECT(destination->access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(predicate->type == CDISASM_ARM_OPERAND_PREDICATE);
    EXPECT(predicate->reg == CDISASM_ARM_REG_P0 + pg);
    EXPECT(predicate->extend_type == element_size);
    EXPECT(predicate->flags == CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO);
    EXPECT(predicate->access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(memory->type == CDISASM_OPERAND_MEMORY);
    EXPECT(memory->base_reg == (rn == 31u ? CDISASM_ARM_REG_SP : CDISASM_ARM_REG_X0 + rn));
    EXPECT(memory->size == memory_size);
    EXPECT(memory->access == CDISASM_OPERAND_ACCESS_READ);
    if (immediate) {
        EXPECT(memory->index_reg == CDISASM_ARM_REG_NONE);
        EXPECT((int64_t)memory->imm == displacement);
        EXPECT(memory->flags == (displacement ? CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT : 0u));
    } else {
        EXPECT(memory->index_reg == (rm_or_imm == 31u
            ? CDISASM_ARM_REG_XZR : CDISASM_ARM_REG_X0 + rm_or_imm));
        EXPECT(memory->imm == 0u);
        EXPECT(memory->flags == 0u);
        EXPECT(memory->shift_type == (size_log2 ? CDISASM_ARM_SHIFT_LSL : CDISASM_ARM_SHIFT_NONE));
        EXPECT(memory->shift_amount == size_log2);
    }
}
#endif

static void exhaustive(void)
{
    for (unsigned size_log2 = 0; size_log2 < 4; ++size_log2)
        for (unsigned octaword = 0; octaword < 2; ++octaword)
            for (unsigned immediate = 0; immediate < 2; ++immediate) {
                uint32_t base = UINT32_C(0xa4000000) | (size_log2 << 23)
                    | (octaword << 21) | (immediate << 13);
                unsigned offset_count = immediate ? 16u : 32u;
                for (unsigned offset = 0; offset < offset_count; ++offset)
                    for (unsigned pg = 0; pg < 8; ++pg)
                        for (unsigned rn = 0; rn < 32; ++rn)
                            for (unsigned zd = 0; zd < 32; ++zd) {
                                cdisasm_arm_instruction instruction;
                                uint32_t word = base | (offset << 16)
                                    | (pg << 10) | (rn << 5) | zd;
                                uint32_t length = decode_word(word,
                                    CDISASM_ARM_CPU_ANY, &instruction);
                                if (!immediate && offset == 31u) {
                                    EXPECT(length == 0u);
                                    EXPECT(error_only(&instruction,
                                        CDISASM_STATUS_INVALID_INSTRUCTION));
                                    continue;
                                }
#if USE_EXTRA_OPCODES
                                EXPECT(length == 4u);
                                check_result(&instruction, word, size_log2,
                                    octaword, immediate);
#else
                                EXPECT(length == 0u);
                                EXPECT(error_only(&instruction,
                                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                            }
            }
}

static void gates_and_format(void)
{
    cdisasm_arm_instruction instruction;
    EXPECT(decode_word(UINT32_C(0xa4000000), CDISASM_ARM_CPU_CORTEX_A53,
        &instruction) == 0u);
#if USE_EXTRA_OPCODES
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
    EXPECT(decode_word(UINT32_C(0xa4200000), CDISASM_ARM_CPU_CORTEX_A53,
        &instruction) == 0u);
    EXPECT(error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
#else
    EXPECT(error_only(&instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const struct { uint32_t word; const char *text; } vectors[] = {
        {UINT32_C(0xa4010000), "ld1rqb {z0.b}, p0/z, [x0, x1]"},
        {UINT32_C(0xa4240462), "ld1rob {z2.b}, p1/z, [x3, x4]"},
        {UINT32_C(0xa48708c5), "ld1rqh {z5.h}, p2/z, [x6, x7, lsl #0x1]"},
        {UINT32_C(0xa50d118b), "ld1rqw {z11.s}, p4/z, [x12, x13, lsl #0x2]"},
        {UINT32_C(0xa5931a51), "ld1rqd {z17.d}, p6/z, [x18, x19, lsl #0x3]"},
        {UINT32_C(0xa4072317), "ld1rqb {z23.b}, p0/z, [x24, #0x70]"},
        {UINT32_C(0xa4882b9b), "ld1rqh {z27.h}, p2/z, [x28, #-0x80]"},
        {UINT32_C(0xa5af3cc5), "ld1rod {z5.d}, p7/z, [x6, #-0x20]"}};
    for (unsigned index = 0; index < sizeof(vectors) / sizeof(vectors[0]); ++index) {
        char text[96];
        EXPECT(decode_word(vectors[index].word, CDISASM_ARM_CPU_ANY,
            &instruction) == 4u);
        EXPECT(cdisasm_arm_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ARM_CANONICAL, text, sizeof(text))
            == strlen(vectors[index].text));
        EXPECT(strcmp(text, vectors[index].text) == 0);
    }
#endif
}

int main(void)
{
    exhaustive();
    gates_and_format();
    if (failures) fprintf(stderr, "%d SVE replicated block-load failures\n", failures);
    else puts("SVE replicated block-load tests passed");
    return failures ? 1 : 0;
}
