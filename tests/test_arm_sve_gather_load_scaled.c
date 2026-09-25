#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
# include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>

typedef struct gather_form { uint32_t value; cdisasm_arm_name_id name;
    cdisasm_arm_form_id form; uint8_t memory_size; } gather_form;
#if USE_EXTRA_OPCODES
static const gather_form forms[4] = {
    { UINT32_C(0x84a00000), CDISASM_ARM_NAME_LD1SH, 3208u, 2u },
    { UINT32_C(0x84a02000), CDISASM_ARM_NAME_LDFF1SH, 3210u, 2u },
    { UINT32_C(0x84a06000), CDISASM_ARM_NAME_LDFF1H, 3211u, 2u },
    { UINT32_C(0x85206000), CDISASM_ARM_NAME_LDFF1W, 3213u, 4u }
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
    unsigned f, s, zm, pg, rn, zt;
    for (f = 0u; f < 4u; ++f) for (s = 0u; s < 2u; ++s)
    for (zm = 0u; zm < 32u; ++zm) for (pg = 0u; pg < 8u; ++pg)
    for (rn = 0u; rn < 32u; ++rn) for (zt = 0u; zt < 32u; ++zt) {
        cdisasm_arm_instruction i;
#if USE_EXTRA_OPCODES
        uint32_t w = forms[f].value | (s << 22) | (zm << 16)
            | (pg << 10) | (rn << 5) | zt;
        cdisasm_arm_operand d = {0}, p = {0}, m = {0};
        E(dw(w, CDISASM_ARM_CPU_ANY, &i) == 4u);
        E(i.name_id == forms[f].name); E(i.form_id == forms[f].form);
        E(i.instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
        E(i.operand_count == 3u);
        d.type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST;
        d.reg = CDISASM_ARM_REG_Z0 + zt; d.register_list = UINT16_C(0x0101);
        d.extend_type = 4u; d.access = CDISASM_OPERAND_ACCESS_WRITE;
        p.type = CDISASM_ARM_OPERAND_PREDICATE;
        p.reg = CDISASM_ARM_REG_P0 + pg;
        p.flags = CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO;
        p.extend_type = 4u; p.access = CDISASM_OPERAND_ACCESS_READ;
        m.type = CDISASM_OPERAND_MEMORY;
        m.base_reg = rn == 31u ? CDISASM_ARM_REG_SP : CDISASM_ARM_REG_X0 + rn;
        m.index_reg = CDISASM_ARM_REG_Z0 + zm;
        m.size = forms[f].memory_size;
        m.extend_type = s ? CDISASM_ARM_EXTEND_SXTW : CDISASM_ARM_EXTEND_UXTW;
        m.scale = forms[f].memory_size == 2u ? 1u : 2u;
        m.access = CDISASM_OPERAND_ACCESS_READ;
        E(memcmp(&i.operand[0], &d, sizeof(d)) == 0);
        E(memcmp(&i.operand[1], &p, sizeof(p)) == 0);
        E(memcmp(&i.operand[2], &m, sizeof(m)) == 0);
#else
        uint32_t w = UINT32_C(0x84a00000) | (s << 22) | (zm << 16)
            | (pg << 10) | (rn << 5) | zt;
        E(dw(w, CDISASM_ARM_CPU_ANY, &i) == 0u);
        E(error_only(&i, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

static void gates_format(void)
{
    cdisasm_arm_instruction i;
    E(dw(UINT32_C(0x84e52483), CDISASM_ARM_CPU_CORTEX_A53, &i) == 0u);
#if USE_EXTRA_OPCODES
    E(error_only(&i, CDISASM_STATUS_INVALID_INSTRUCTION));
    E(dw(UINT32_C(0x84e52483), CDISASM_ARM_CPU_FUJITSU_A64FX, &i) == 4u);
#if USE_DISASM_FORMAT
    {
        char t[96];
        E(cdisasm_arm_format(&i, 0u, t, sizeof(t))
            == strlen("ldff1sh {z3.s}, p1/z, [x4, z5.s, sxtw #0x1]"));
        E(strcmp(t,
            "ldff1sh {z3.s}, p1/z, [x4, z5.s, sxtw #0x1]") == 0);
        i.operand[2].scale = 0u;
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
    puts("scaled SVE gather-load tests passed (4 exact leaves)");
    return 0;
}
