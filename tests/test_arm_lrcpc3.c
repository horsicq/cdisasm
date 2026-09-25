#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

typedef struct lrcpc3_case {
    uint32_t word;
    cdisasm_arm_name_id name;
    uint16_t form;
    const char *text;
} lrcpc3_case;

static const lrcpc3_case cases[] = {
    { UINT32_C(0x1d000801), CDISASM_ARM_NAME_STLUR, UINT16_C(4907), "stlur b1, [x0]" },
    { UINT32_C(0x1d400801), CDISASM_ARM_NAME_LDAPUR, UINT16_C(4908), "ldapur b1, [x0]" },
    { UINT32_C(0x1d800801), CDISASM_ARM_NAME_STLUR, UINT16_C(4909), "stlur q1, [x0]" },
    { UINT32_C(0x1dc00801), CDISASM_ARM_NAME_LDAPUR, UINT16_C(4910), "ldapur q1, [x0]" },
    { UINT32_C(0x5d000801), CDISASM_ARM_NAME_STLUR, UINT16_C(4911), "stlur h1, [x0]" },
    { UINT32_C(0x5d400801), CDISASM_ARM_NAME_LDAPUR, UINT16_C(4912), "ldapur h1, [x0]" },
    { UINT32_C(0x9d000801), CDISASM_ARM_NAME_STLUR, UINT16_C(4913), "stlur s1, [x0]" },
    { UINT32_C(0x9d400801), CDISASM_ARM_NAME_LDAPUR, UINT16_C(4914), "ldapur s1, [x0]" },
    { UINT32_C(0xdd000801), CDISASM_ARM_NAME_STLUR, UINT16_C(4915), "stlur d1, [x0]" },
    { UINT32_C(0xdd400801), CDISASM_ARM_NAME_LDAPUR, UINT16_C(4916), "ldapur d1, [x0]" }
};

static int error_only(const cdisasm_arm_instruction *instruction,
                      cdisasm_status status)
{
    cdisasm_arm_instruction expected;
    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

int main(void)
{
    size_t i;
    int failures = 0;

    for (i = 0u; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint8_t bytes[4] = {
            (uint8_t)cases[i].word, (uint8_t)(cases[i].word >> 8),
            (uint8_t)(cases[i].word >> 16), (uint8_t)(cases[i].word >> 24)
        };
        cdisasm_arm_instruction instruction;
        uint32_t decoded;

        memset(&instruction, 0xa5, sizeof(instruction));
        decoded = cdisasm_arm_decode(
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            bytes, sizeof(bytes), UINT64_C(0x1000),
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
        if (decoded != 4u || instruction.last_error_id != CDISASM_STATUS_OK
            || instruction.name_id != cases[i].name
            || instruction.form_id != cases[i].form) {
            fprintf(stderr, "case %zu decode failed: size=%u status=%u name=%u form=%u\n",
                    i, (unsigned)decoded, (unsigned)instruction.last_error_id,
                    (unsigned)instruction.name_id, (unsigned)instruction.form_id);
            ++failures;
        }
#if USE_DISASM_FORMAT
        {
            char text[80];
            size_t length = cdisasm_arm_format(
                &instruction, CDISASM_FORMAT_SYNTAX_0, text, sizeof(text));
            if (length != strlen(cases[i].text)
                || strcmp(text, cases[i].text) != 0) {
                fprintf(stderr, "case %zu formatted as '%s', expected '%s' operands=%u flags=%08x reg=%u size=%u memsize=%u\n",
                        i, text, cases[i].text, (unsigned)instruction.operand_count,
                        (unsigned)instruction.instruction_flags,
                        (unsigned)instruction.operand[0].reg,
                        (unsigned)instruction.operand[0].size,
                        (unsigned)instruction.operand[1].size);
                ++failures;
            }
        }
#endif
#else
        (void)decoded;
        if (!error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION)) {
            ++failures;
        }
#endif
    }

    /* RCPC3 is not implied by an early A64 profile. */
    {
        uint8_t bytes[4] = { 0x01, 0x08, 0x00, 0x1d };
        cdisasm_arm_instruction instruction;
        memset(&instruction, 0xa5, sizeof(instruction));
        (void)cdisasm_arm_decode(
            CDISASM_ARM_CPU_CORTEX_A53, CDISASM_ARM_MODE_A64,
            bytes, sizeof(bytes), 0u, CDISASM_ARM_DECODE_OPTION_NONE,
            &instruction);
#if USE_EXTRA_OPCODES
        if (!error_only(&instruction, CDISASM_STATUS_INVALID_INSTRUCTION)) {
            fprintf(stderr, "early A64 CPU unexpectedly admitted RCPC3 status=%u\n",
                    (unsigned)instruction.last_error_id);
            ++failures;
        }
#endif
    }
    return failures != 0;
}
