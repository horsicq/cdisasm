#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"

#include <stdio.h>
#include <string.h>

typedef struct operation {
    uint32_t value;
    cdisasm_arm_name_id name;
    cdisasm_arm_form_id form;
    uint8_t conversion;
} operation;

static const operation operations[] = {
    { UINT32_C(0x0f007400), CDISASM_ARM_NAME_SQSHL, UINT16_C(6220), 0u },
    { UINT32_C(0x0f00e400), CDISASM_ARM_NAME_SCVTF, UINT16_C(6226), 1u },
    { UINT32_C(0x0f00fc00), CDISASM_ARM_NAME_FCVTZS, UINT16_C(6227), 1u },
    { UINT32_C(0x2f006400), CDISASM_ARM_NAME_SQSHLU, UINT16_C(6234), 0u },
    { UINT32_C(0x2f007400), CDISASM_ARM_NAME_UQSHL, UINT16_C(6235), 0u },
    { UINT32_C(0x2f00e400), CDISASM_ARM_NAME_UCVTF, UINT16_C(6241), 1u },
    { UINT32_C(0x2f00fc00), CDISASM_ARM_NAME_FCVTZU, UINT16_C(6242), 1u }
};

static int failures;
#define EXPECT(c) do { if (!(c)) { if (failures < 20) fprintf(stderr, \
    "%s:%d: %s\n", __FILE__, __LINE__, #c); ++failures; } } while (0)

static uint32_t decode(uint32_t word, cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4] = { (uint8_t)word, (uint8_t)(word >> 8),
        (uint8_t)(word >> 16), (uint8_t)(word >> 24) };
    memset(instruction, 0xa5, sizeof(*instruction));
    return cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x1000),
        CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

#if USE_EXTRA_OPCODES
static unsigned element_bits(unsigned immh)
{
    return (immh & 8u) ? 64u : (immh & 4u) ? 32u
        : (immh & 2u) ? 16u : 8u;
}
#endif

int main(void)
{
    unsigned op, q, immh, immb, rd, rn;

    for (op = 0u; op < sizeof(operations) / sizeof(operations[0]); ++op)
        for (q = 0u; q < 2u; ++q)
            for (immh = 1u; immh < 16u; ++immh)
                for (immb = 0u; immb < 8u; ++immb)
                    for (rd = 0u; rd < 32u; rd += 31u)
                        for (rn = 0u; rn < 32u; rn += 31u) {
                            cdisasm_arm_instruction i;
                            uint32_t word = operations[op].value
                                | (q << 30) | (immh << 19) | (immb << 16)
                                | (rn << 5) | rd;
#if USE_EXTRA_OPCODES
                            unsigned bits = element_bits(immh);
                            unsigned encoded = (immh << 3) | immb;
                            int legal = q != 0u || bits != 64u;
                            EXPECT(decode(word, &i) == (legal ? 4u : 0u));
                            if (!legal) { EXPECT(i.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION); continue; }
                            EXPECT(i.name_id == operations[op].name);
                            EXPECT(i.form_id == operations[op].form);
                            EXPECT(i.instruction_flags == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
                                | (operations[op].conversion ? CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT : 0u)));
                            EXPECT(i.operand_count == 3u);
                            EXPECT(i.operand[0].reg == CDISASM_ARM_REG_V0 + rd);
                            EXPECT(i.operand[0].size == (q ? 16u : 8u));
                            EXPECT(i.operand[0].extend_type == bits / 8u);
                            EXPECT(i.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
                            EXPECT(i.operand[1].reg == CDISASM_ARM_REG_V0 + rn);
                            EXPECT(i.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
                            EXPECT(i.operand[2].imm == (operations[op].conversion
                                ? 2u * bits - encoded : encoded - bits));
#else
                            EXPECT(decode(word, &i) == 0u);
                            EXPECT(i.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION
                                || i.last_error_id == CDISASM_STATUS_INVALID_INSTRUCTION);
#endif
                        }

    /* immh=0000 belongs to modified-immediate decoding, never these forms. */
    for (op = 0u; op < sizeof(operations) / sizeof(operations[0]); ++op) {
        cdisasm_arm_instruction i;
        (void)decode(operations[op].value, &i);
        EXPECT(i.form_id != operations[op].form);
    }
    if (failures != 0) fprintf(stderr, "%d failures\n", failures);
    return failures == 0 ? 0 : 1;
}
