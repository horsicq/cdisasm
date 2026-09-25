#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
# include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>

typedef struct prefetch_form {
    cdisasm_arm_name_id name;
    cdisasm_arm_form_id form;
    uint8_t size;
} prefetch_form;

#if USE_EXTRA_OPCODES
static const prefetch_form forms[4] = {
    { CDISASM_ARM_NAME_PRFB, 3204u, 1u },
    { CDISASM_ARM_NAME_PRFH, 3205u, 2u },
    { CDISASM_ARM_NAME_PRFW, 3206u, 4u },
    { CDISASM_ARM_NAME_PRFD, 3207u, 8u }
};
#endif
static int failures;
#define E(c) do { if (!(c)) { if (failures < 20) fprintf(stderr, \
    "%d: %s\n", __LINE__, #c); ++failures; } } while (0)

static uint32_t decode_word(uint32_t word, cdisasm_arm_cpu_id cpu,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4] = { (uint8_t)word, (uint8_t)(word >> 8),
        (uint8_t)(word >> 16), (uint8_t)(word >> 24) };
    memset(instruction, 0xa5, sizeof(*instruction));
    return cdisasm_arm_decode(cpu, CDISASM_ARM_MODE_A64, bytes, 4u, 0,
        CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static int error_only(const cdisasm_arm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_arm_instruction expected;
    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static void exhaustive_domains(void)
{
    unsigned f, s, zm, pg, rn, op;
    for (f = 0u; f < 4u; ++f)
    for (s = 0u; s < 2u; ++s)
    for (zm = 0u; zm < 32u; ++zm)
    for (pg = 0u; pg < 8u; ++pg)
    for (rn = 0u; rn < 32u; ++rn)
    for (op = 0u; op < 16u; ++op) {
        cdisasm_arm_instruction i;
        uint32_t word = UINT32_C(0x84200000) | (f << 13) | (s << 22)
            | (zm << 16) | (pg << 10) | (rn << 5) | op;
        uint32_t consumed = decode_word(word, CDISASM_ARM_CPU_ANY, &i);
#if USE_EXTRA_OPCODES
        cdisasm_arm_operand hint = {0}, predicate = {0}, memory = {0};
        E(consumed == 4u); E(i.name_id == forms[f].name);
        E(i.form_id == forms[f].form);
        E(i.instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
        E(i.operand_count == 3u);
        hint.type = CDISASM_OPERAND_IMMEDIATE;
        hint.imm = op; hint.size = 1u;
        hint.access = CDISASM_OPERAND_ACCESS_READ;
        predicate.type = CDISASM_ARM_OPERAND_PREDICATE;
        predicate.reg = CDISASM_ARM_REG_P0 + pg;
        predicate.extend_type = forms[f].size;
        predicate.access = CDISASM_OPERAND_ACCESS_READ;
        memory.type = CDISASM_OPERAND_MEMORY;
        memory.base_reg = rn == 31u ? CDISASM_ARM_REG_SP
                                    : CDISASM_ARM_REG_X0 + rn;
        memory.index_reg = CDISASM_ARM_REG_Z0 + zm;
        memory.size = forms[f].size;
        memory.extend_type = s ? CDISASM_ARM_EXTEND_SXTW
                               : CDISASM_ARM_EXTEND_UXTW;
        memory.scale = (uint8_t)f;
        memory.access = CDISASM_OPERAND_ACCESS_READ;
        E(memcmp(&i.operand[0], &hint, sizeof(hint)) == 0);
        E(memcmp(&i.operand[1], &predicate, sizeof(predicate)) == 0);
        E(memcmp(&i.operand[2], &memory, sizeof(memory)) == 0);
#else
        E(consumed == 0u);
        E(error_only(&i, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

static void gates_and_format(void)
{
    cdisasm_arm_instruction i;
    E(decode_word(UINT32_C(0x84652fe3), CDISASM_ARM_CPU_CORTEX_A53, &i)
        == 0u);
#if USE_EXTRA_OPCODES
    E(error_only(&i, CDISASM_STATUS_INVALID_INSTRUCTION));
    E(decode_word(UINT32_C(0x84652fe3), CDISASM_ARM_CPU_FUJITSU_A64FX,
        &i) == 4u);
#if USE_DISASM_FORMAT
    {
        char text[96];
        E(cdisasm_arm_format(&i, 0u, text, sizeof(text))
            == strlen("prfh pldl2strm, p3, [sp, z5.s, sxtw #0x1]"));
        E(strcmp(text,
            "prfh pldl2strm, p3, [sp, z5.s, sxtw #0x1]") == 0);
        E(decode_word(UINT32_C(0x8469630f), CDISASM_ARM_CPU_ANY, &i) == 4u);
        E(cdisasm_arm_format(&i, 0u, text, sizeof(text))
            == strlen("prfd #0xf, p0, [x24, z9.s, sxtw #0x3]"));
        E(strcmp(text, "prfd #0xf, p0, [x24, z9.s, sxtw #0x3]") == 0);
        i.operand[2].scale = 2u;
        E(cdisasm_arm_format(&i, 0u, text, sizeof(text)) == 0u);
    }
#endif
#else
    E(error_only(&i, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

int main(void)
{
    exhaustive_domains();
    gates_and_format();
    if (failures != 0) {
        fprintf(stderr, "%d SVE gather-prefetch failure(s)\n", failures);
        return 1;
    }
    puts("SVE gather-prefetch tests passed (4 exact leaves)");
    return 0;
}
