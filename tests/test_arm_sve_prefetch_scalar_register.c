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
    unsigned sz, xm, pg, rn, hint;
    for (sz = 0u; sz < 4u; ++sz) for (xm = 0u; xm < 32u; ++xm)
    for (pg = 0u; pg < 8u; ++pg) for (rn = 0u; rn < 32u; ++rn)
    for (hint = 0u; hint < 16u; ++hint) {
        uint32_t w = UINT32_C(0x8400c000) | (sz << 23) | (xm << 16)
            | (pg << 10) | (rn << 5) | hint;
        cdisasm_arm_instruction i;
        uint32_t n = dw(w, CDISASM_ARM_CPU_ANY, &i);
#if USE_EXTRA_OPCODES
        if (xm == 31u) {
            E(n == 0u); E(error_only(&i, CDISASM_STATUS_INVALID_INSTRUCTION));
        } else {
            uint8_t size = (uint8_t)(1u << sz);
            cdisasm_arm_operand h = {0}, p = {0}, m = {0};
            E(n == 4u); E(i.name_id == names[sz]);
            E(i.form_id == 3225u + sz);
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
            m.base_reg = rn == 31u ? CDISASM_ARM_REG_SP
                                   : CDISASM_ARM_REG_X0 + rn;
            m.index_reg = CDISASM_ARM_REG_X0 + xm; m.size = size;
            m.shift_type = sz == 0u ? CDISASM_ARM_SHIFT_NONE
                                    : CDISASM_ARM_SHIFT_LSL;
            m.shift_amount = (uint8_t)sz;
            m.access = CDISASM_OPERAND_ACCESS_READ;
            E(memcmp(&i.operand[0], &h, sizeof(h)) == 0);
            E(memcmp(&i.operand[1], &p, sizeof(p)) == 0);
            E(memcmp(&i.operand[2], &m, sizeof(m)) == 0);
        }
#else
        E(n == 0u);
        E(error_only(&i, xm == 31u ? CDISASM_STATUS_INVALID_INSTRUCTION
                                   : CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

static void gates_format(void)
{
    cdisasm_arm_instruction i;
    E(dw(UINT32_C(0x8485cfe3), CDISASM_ARM_CPU_CORTEX_A53, &i) == 0u);
#if USE_EXTRA_OPCODES
    E(error_only(&i, CDISASM_STATUS_INVALID_INSTRUCTION));
    E(dw(UINT32_C(0x8485cfe3), CDISASM_ARM_CPU_FUJITSU_A64FX, &i) == 4u);
#if USE_DISASM_FORMAT
    {
        char t[96];
        E(cdisasm_arm_format(&i, 0u, t, sizeof(t))
            == strlen("prfh pldl2strm, p3, [sp, x5, lsl #0x1]"));
        E(strcmp(t, "prfh pldl2strm, p3, [sp, x5, lsl #0x1]") == 0);
        i.operand[2].shift_amount = 0u;
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
    puts("SVE scalar-register prefetch tests passed (4 exact leaves)");
    return 0;
}
