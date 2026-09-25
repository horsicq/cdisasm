#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
# include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>

#if USE_EXTRA_OPCODES
static const cdisasm_arm_name_id names[4] = {
    CDISASM_ARM_NAME_PRFB, CDISASM_ARM_NAME_PRFH,
    CDISASM_ARM_NAME_PRFW, CDISASM_ARM_NAME_PRFD
};
#endif
static int failures;
#define E(c) do { if (!(c)) { if (failures < 20) fprintf(stderr, \
    "%d: %s\n", __LINE__, #c); ++failures; } } while (0)

static uint32_t dw(uint32_t w, cdisasm_arm_cpu_id cpu,
    cdisasm_arm_instruction *i)
{
    uint8_t b[4] = { (uint8_t)w, (uint8_t)(w >> 8),
        (uint8_t)(w >> 16), (uint8_t)(w >> 24) };
    memset(i, 0xa5, sizeof(*i));
    return cdisasm_arm_decode(cpu, CDISASM_ARM_MODE_A64, b, 4u, 0,
        CDISASM_ARM_DECODE_OPTION_NONE, i);
}

static int error_only(const cdisasm_arm_instruction *i, cdisasm_status s)
{
    cdisasm_arm_instruction z;
    memset(&z, 0, sizeof(z)); z.last_error_id = (uint8_t)s;
    return memcmp(i, &z, sizeof(z)) == 0;
}

static void domains(void)
{
    unsigned size_log2, imm6, hint, pg, rn;
    for (size_log2 = 0u; size_log2 < 4u; ++size_log2)
    for (imm6 = 0u; imm6 < 64u; ++imm6)
    for (hint = 0u; hint < 16u; ++hint)
    for (pg = 0u; pg < 8u; ++pg)
    for (rn = 0u; rn < 32u; ++rn) {
        uint32_t w = UINT32_C(0x85c00000) | (size_log2 << 13)
            | (imm6 << 16) | (pg << 10) | (rn << 5) | hint;
        cdisasm_arm_instruction i;
#if USE_EXTRA_OPCODES
        int64_t disp = imm6 < 32u ? (int64_t)imm6 : (int64_t)imm6 - 64;
        uint8_t size = (uint8_t)(1u << size_log2);
        cdisasm_arm_operand h = {0}, p = {0}, m = {0};
        E(dw(w, CDISASM_ARM_CPU_ANY, &i) == 4u);
        E(i.name_id == names[size_log2]);
        E(i.form_id == 3216u + size_log2);
        E(i.instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
        E(i.operand_count == 3u);
        h.type = CDISASM_OPERAND_IMMEDIATE; h.imm = hint; h.size = 1u;
        h.access = CDISASM_OPERAND_ACCESS_READ;
        p.type = CDISASM_ARM_OPERAND_PREDICATE;
        p.reg = CDISASM_ARM_REG_P0 + pg; p.extend_type = size;
        p.access = CDISASM_OPERAND_ACCESS_READ;
        m.type = CDISASM_OPERAND_MEMORY;
        m.base_reg = rn == 31u ? CDISASM_ARM_REG_SP : CDISASM_ARM_REG_X0 + rn;
        m.size = size; m.imm = (uint64_t)disp;
        m.access = CDISASM_OPERAND_ACCESS_READ;
        if (disp != 0) {
            m.flags = CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
                | CDISASM_ARM_OPERAND_FLAG_VL_SCALED
                | (disp < 0 ? CDISASM_OPERAND_FLAG_SIGNED : 0u);
        }
        E(memcmp(&i.operand[0], &h, sizeof(h)) == 0);
        E(memcmp(&i.operand[1], &p, sizeof(p)) == 0);
        E(memcmp(&i.operand[2], &m, sizeof(m)) == 0);
#else
        E(dw(w, CDISASM_ARM_CPU_ANY, &i) == 0u);
        E(error_only(&i, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

static void gates_format(void)
{
    cdisasm_arm_instruction i;
    E(dw(UINT32_C(0x85fe2fe3), CDISASM_ARM_CPU_CORTEX_A53, &i) == 0u);
#if USE_EXTRA_OPCODES
    E(error_only(&i, CDISASM_STATUS_INVALID_INSTRUCTION));
    E(dw(UINT32_C(0x85fe2fe3), CDISASM_ARM_CPU_FUJITSU_A64FX, &i) == 4u);
#if USE_DISASM_FORMAT
    {
        char t[96];
        E(cdisasm_arm_format(&i, 0u, t, sizeof(t))
            == strlen("prfh pldl2strm, p3, [sp, #-0x2, mul vl]"));
        E(strcmp(t, "prfh pldl2strm, p3, [sp, #-0x2, mul vl]") == 0);
        E(dw(UINT32_C(0x85c00020), CDISASM_ARM_CPU_ANY, &i) == 4u);
        E(cdisasm_arm_format(&i, 0u, t, sizeof(t))
            == strlen("prfb pldl1keep, p0, [x1]"));
        E(strcmp(t, "prfb pldl1keep, p0, [x1]") == 0);
        i.operand[2].flags = CDISASM_ARM_OPERAND_FLAG_VL_SCALED;
        E(cdisasm_arm_format(&i, 0u, t, sizeof(t)) == 0u);
    }
#endif
#else
    E(error_only(&i, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

int main(void)
{
    domains(); gates_format();
    if (failures) return fprintf(stderr, "%d failures\n", failures), 1;
    puts("SVE immediate-prefetch tests passed (4 exact leaves)");
    return 0;
}
