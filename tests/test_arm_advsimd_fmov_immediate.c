#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#include <stdio.h>
#include <string.h>

static int failures;
#define EXPECT(c) do { if (!(c)) { if (failures < 16) fprintf(stderr, \
    "%s:%d: %s\n", __FILE__, __LINE__, #c); ++failures; } } while (0)

#if USE_EXTRA_OPCODES
static uint64_t expand(unsigned e, unsigned size)
{
    unsigned total = size * 8u, eb = size == 2u ? 5u : size == 4u ? 8u : 11u;
    unsigned fb = total - eb - 1u, s = (e >> 6) & 1u;
    uint64_t exponent = (uint64_t)(s ^ 1u) << (eb - 1u);
    if (s) exponent |= ((UINT64_C(1) << (eb - 3u)) - 1u) << 2u;
    exponent |= (e >> 4) & 3u;
    return ((uint64_t)(e >> 7) << (total - 1u)) | (exponent << fb)
        | ((uint64_t)(e & 15u) << (fb - 4u));
}
#endif

static uint32_t decode(uint32_t w, cdisasm_arm_cpu_id cpu,
                       cdisasm_arm_instruction *i)
{
    uint8_t b[4] = { (uint8_t)w, (uint8_t)(w >> 8),
        (uint8_t)(w >> 16), (uint8_t)(w >> 24) };
    memset(i, 0xa5, sizeof(*i));
    return cdisasm_arm_decode(cpu, CDISASM_ARM_MODE_A64, b, 4u, 0u,
        CDISASM_ARM_DECODE_OPTION_NONE, i);
}

int main(void)
{
    static const uint32_t bases[3] = { 0x0f00f400, 0x0f00fc00, 0x6f00f400 };
#if USE_EXTRA_OPCODES
    static const uint16_t forms[3] = { 6205, 6206, 6214 };
    static const uint8_t sizes[3] = { 4, 2, 8 };
#endif
    unsigned k, q, imm, rd;
    for (k = 0; k < 3; ++k) for (q = 0; q < 2; ++q)
        for (imm = 0; imm < 256; ++imm) for (rd = 0; rd < 32; rd += 31) {
            cdisasm_arm_instruction i;
            uint32_t w = bases[k] | (q << 30) | ((imm >> 5) << 16)
                | ((imm & 31u) << 5) | rd;
#if USE_EXTRA_OPCODES
            EXPECT(decode(w, CDISASM_ARM_CPU_ANY, &i) == 4u);
            EXPECT(i.name_id == CDISASM_ARM_NAME_FMOV && i.form_id == forms[k]);
            EXPECT(i.instruction_flags == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
                | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
            EXPECT(i.operand_count == 2 && i.operand[0].reg == CDISASM_ARM_REG_V0 + rd);
            EXPECT(i.operand[0].size == ((q || k == 2) ? 16 : 8));
            EXPECT(i.operand[0].extend_type == sizes[k]);
            EXPECT(i.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
            EXPECT(i.operand[1].type == CDISASM_OPERAND_IMMEDIATE);
            EXPECT(i.operand[1].imm == expand(imm, sizes[k]));
#else
            EXPECT(decode(w, CDISASM_ARM_CPU_ANY, &i) == 0u);
#endif
        }
#if USE_EXTRA_OPCODES
    { cdisasm_arm_instruction i;
      EXPECT(decode(UINT32_C(0x4f03fe00), CDISASM_ARM_CPU_CORTEX_A53, &i) == 0u);
      EXPECT(i.last_error_id != CDISASM_STATUS_OK); }
#endif
    return failures ? 1 : 0;
}
