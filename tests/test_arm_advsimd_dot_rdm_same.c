#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>

static int failures;
#define EXPECT(c) do { if (!(c)) { if (failures < 20) fprintf(stderr, \
    "%s:%d: %s\n", __FILE__, __LINE__, #c); ++failures; } } while (0)

static uint32_t dw(uint32_t w, cdisasm_arm_cpu_id cpu,
    cdisasm_arm_instruction *i)
{
    uint8_t b[4] = { (uint8_t)w, (uint8_t)(w >> 8),
        (uint8_t)(w >> 16), (uint8_t)(w >> 24) };
    return cdisasm_arm_decode(cpu, CDISASM_ARM_MODE_A64, b, 4u, 0u, 0u, i);
}

static void check(uint32_t word, cdisasm_arm_name_id name,
    cdisasm_arm_form_id form, uint8_t destination_size,
    uint8_t source_size, uint32_t flags, const char *expected_text)
{
    cdisasm_arm_instruction i;
#if USE_EXTRA_OPCODES
    uint8_t total = (word & UINT32_C(0x40000000)) != 0u ? 16u : 8u;
    char text[96];
#else
    cdisasm_arm_instruction expected;
    (void)name; (void)form; (void)destination_size;
    (void)source_size; (void)flags; (void)expected_text;
#endif
    memset(&i, 0xa5, sizeof(i));
#if USE_EXTRA_OPCODES
    EXPECT(dw(word, CDISASM_ARM_CPU_ANY, &i) == 4u);
    EXPECT(i.name_id == name && i.form_id == form);
    EXPECT(i.instruction_flags == flags);
    EXPECT(i.operand_count == 3u);
    EXPECT(i.operand[0].size == total
        && i.operand[0].extend_type == destination_size
        && i.operand[0].access == CDISASM_OPERAND_ACCESS_READ_WRITE);
    EXPECT(i.operand[1].size == total
        && i.operand[1].extend_type == source_size
        && i.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(i.operand[2].size == total
        && i.operand[2].extend_type == source_size
        && i.operand[2].access == CDISASM_OPERAND_ACCESS_READ);
#if USE_DISASM_FORMAT
    EXPECT(cdisasm_arm_format(&i, 0u, text, sizeof(text)) == strlen(expected_text));
    EXPECT(strcmp(text, expected_text) == 0);
#else
    (void)text; (void)expected_text;
#endif
    memset(&i, 0xa5, sizeof(i));
    EXPECT(dw(word, CDISASM_ARM_CPU_CORTEX_A53, &i) == 0u);
    EXPECT(i.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
#else
    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    EXPECT(dw(word, CDISASM_ARM_CPU_ANY, &i) == 0u);
    EXPECT(memcmp(&i, &expected, sizeof(i)) == 0);
#endif
}

static void check_widen(uint32_t word, cdisasm_arm_name_id name,
    cdisasm_arm_form_id form, uint8_t destination_size,
    uint8_t source_size, const char *expected_text)
{
    cdisasm_arm_instruction i;
#if USE_EXTRA_OPCODES
#if USE_DISASM_FORMAT
    char text[96];
#endif
    memset(&i, 0xa5, sizeof(i));
    EXPECT(dw(word, CDISASM_ARM_CPU_ANY, &i) == 4u);
    EXPECT(i.name_id == name && i.form_id == form);
    EXPECT(i.instruction_flags == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
    EXPECT(i.operand_count == 3u);
    EXPECT(i.operand[0].size == 16u
        && i.operand[0].extend_type == destination_size
        && i.operand[0].access == CDISASM_OPERAND_ACCESS_READ_WRITE);
    EXPECT(i.operand[1].size == 16u
        && i.operand[1].extend_type == source_size
        && i.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(i.operand[2].size == 16u
        && i.operand[2].extend_type == source_size
        && i.operand[2].access == CDISASM_OPERAND_ACCESS_READ);
#if USE_DISASM_FORMAT
    EXPECT(cdisasm_arm_format(&i, 0u, text, sizeof(text)) == strlen(expected_text));
    EXPECT(strcmp(text, expected_text) == 0);
#else
    (void)expected_text;
#endif
    EXPECT(dw(word, CDISASM_ARM_CPU_CORTEX_A53, &i) == 0u);
    EXPECT(i.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
#else
    cdisasm_arm_instruction expected;
    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    memset(&i, 0xa5, sizeof(i));
    EXPECT(dw(word, CDISASM_ARM_CPU_ANY, &i) == 0u);
    EXPECT(memcmp(&i, &expected, sizeof(i)) == 0);
    (void)name; (void)form; (void)destination_size;
    (void)source_size; (void)expected_text;
#endif
}

int main(void)
{
    check(0x0e829420u, CDISASM_ARM_NAME_SDOT, 5975, 4u, 1u,
        CDISASM_ARM_INSTRUCTION_FLAG_SIMD,
        "sdot v0.2s, v1.8b, v2.8b");
    check(0x4e859483u, CDISASM_ARM_NAME_SDOT, 5975, 4u, 1u,
        CDISASM_ARM_INSTRUCTION_FLAG_SIMD,
        "sdot v3.4s, v4.16b, v5.16b");
    check(0x2e8894e6u, CDISASM_ARM_NAME_UDOT, 5984, 4u, 1u,
        CDISASM_ARM_INSTRUCTION_FLAG_SIMD,
        "udot v6.2s, v7.8b, v8.8b");
    check(0x6e8b9549u, CDISASM_ARM_NAME_UDOT, 5984, 4u, 1u,
        CDISASM_ARM_INSTRUCTION_FLAG_SIMD,
        "udot v9.4s, v10.16b, v11.16b");
    check(0x2e4e85acu, CDISASM_ARM_NAME_SQRDMLAH, 5982, 2u, 2u,
        CDISASM_ARM_INSTRUCTION_FLAG_SIMD,
        "sqrdmlah v12.4h, v13.4h, v14.4h");
    check(0x6e51860fu, CDISASM_ARM_NAME_SQRDMLAH, 5982, 2u, 2u,
        CDISASM_ARM_INSTRUCTION_FLAG_SIMD,
        "sqrdmlah v15.8h, v16.8h, v17.8h");
    check(0x2e948e72u, CDISASM_ARM_NAME_SQRDMLSH, 5983, 4u, 4u,
        CDISASM_ARM_INSTRUCTION_FLAG_SIMD,
        "sqrdmlsh v18.2s, v19.2s, v20.2s");
    check(0x6e978ed5u, CDISASM_ARM_NAME_SQRDMLSH, 5983, 4u, 4u,
        CDISASM_ARM_INSTRUCTION_FLAG_SIMD,
        "sqrdmlsh v21.4s, v22.4s, v23.4s");
    check(0x0e02fc20u, CDISASM_ARM_NAME_FDOT, 5977, 4u, 1u,
        CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT,
        "fdot v0.2s, v1.8b, v2.8b");
    check(0x4e05fc83u, CDISASM_ARM_NAME_FDOT, 5977, 4u, 1u,
        CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT,
        "fdot v3.4s, v4.16b, v5.16b");
    check(0x0e48fce6u, CDISASM_ARM_NAME_FDOT, 5979, 2u, 1u,
        CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT,
        "fdot v6.4h, v7.8b, v8.8b");
    check(0x4e4bfd49u, CDISASM_ARM_NAME_FDOT, 5979, 2u, 1u,
        CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT,
        "fdot v9.8h, v10.16b, v11.16b");
    check(0x0e8e9dacu, CDISASM_ARM_NAME_USDOT, 5980, 4u, 1u,
        CDISASM_ARM_INSTRUCTION_FLAG_SIMD,
        "usdot v12.2s, v13.8b, v14.8b");
    check(0x4e919e0fu, CDISASM_ARM_NAME_USDOT, 5980, 4u, 1u,
        CDISASM_ARM_INSTRUCTION_FLAG_SIMD,
        "usdot v15.4s, v16.16b, v17.16b");
    check(0x2e54fe72u, CDISASM_ARM_NAME_BFDOT, 5987, 4u, 2u,
        CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT,
        "bfdot v18.2s, v19.4h, v20.4h");
    check(0x6e57fed5u, CDISASM_ARM_NAME_BFDOT, 5987, 4u, 2u,
        CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT,
        "bfdot v21.4s, v22.8h, v23.8h");
    check_widen(0x2ec2fc20u, CDISASM_ARM_NAME_BFMLAL, 5988, 4u, 2u,
        "bfmlalb v0.4s, v1.8h, v2.8h");
    check_widen(0x6ec5fc83u, CDISASM_ARM_NAME_BFMLAL, 5988, 4u, 2u,
        "bfmlalt v3.4s, v4.8h, v5.8h");
    check_widen(0x0e05c483u, CDISASM_ARM_NAME_FMLALLBB, 5989, 4u, 1u,
        "fmlallbb v3.4s, v4.16b, v5.16b");
    check_widen(0x0e48c4e6u, CDISASM_ARM_NAME_FMLALLBT, 5990, 4u, 1u,
        "fmlallbt v6.4s, v7.16b, v8.16b");
    check_widen(0x0ecbfd49u, CDISASM_ARM_NAME_FMLALB, 5991, 2u, 1u,
        "fmlalb v9.8h, v10.16b, v11.16b");
    check_widen(0x4e0ec5acu, CDISASM_ARM_NAME_FMLALLTB, 5992, 4u, 1u,
        "fmlalltb v12.4s, v13.16b, v14.16b");
    check_widen(0x4e51c60fu, CDISASM_ARM_NAME_FMLALLTT, 5993, 4u, 1u,
        "fmlalltt v15.4s, v16.16b, v17.16b");
    check_widen(0x4ec2fc20u, CDISASM_ARM_NAME_FMLALT, 5997, 2u, 1u,
        "fmlalt v0.8h, v1.16b, v2.16b");
    check_widen(0x6e05ec83u, CDISASM_ARM_NAME_FMMLA, 5998, 2u, 1u,
        "fmmla v3.8h, v4.16b, v5.16b");
    check_widen(0x6e48ece6u, CDISASM_ARM_NAME_BFMMLA, 6000, 4u, 2u,
        "bfmmla v6.4s, v7.8h, v8.8h");
    check_widen(0x6e8bed49u, CDISASM_ARM_NAME_FMMLA, 6001, 4u, 1u,
        "fmmla v9.4s, v10.16b, v11.16b");
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction i;
        EXPECT(dw(UINT32_C(0x0e029420), CDISASM_ARM_CPU_ANY, &i) == 0u);
        EXPECT(i.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
        EXPECT(dw(UINT32_C(0x2ece85ac), CDISASM_ARM_CPU_ANY, &i) == 0u);
        EXPECT(i.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
    }
#endif
    if (failures) return 1;
    puts("A64 Advanced SIMD dot/RDM same-type tests passed");
    return 0;
}
