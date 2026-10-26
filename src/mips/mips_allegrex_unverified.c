#include "mips_decoder.h"
#include <string.h>

/* These are encoding views from a pinned source, not architectural operand
 * domains. No numerical or physical register effects are inferred here. */
#if USE_MIPS_ALLEGREX_UNVERIFIED && USE_EXTRA_OPCODES && USE_MIPS_ALLEGREX
typedef struct allegrex_source_form {
    uint32_t mask, value;
    uint16_t name, form;
    uint8_t destination_size, source_size, destination_vector, source_vector;
} allegrex_source_form;
static const allegrex_source_form source_forms[] = {
#include "generated/mips_allegrex_unverified_forms.inc"
};
#endif

int cdisasm_mips_allegrex_unverified_decode(uint32_t raw, cdisasm_mips_instruction *instruction)
{
#if USE_MIPS_ALLEGREX_UNVERIFIED && USE_EXTRA_OPCODES && USE_MIPS_ALLEGREX
    size_t n;
    if (instruction == NULL) return 0;
    for (n = 0; n < sizeof(source_forms) / sizeof(source_forms[0]); ++n) {
        const allegrex_source_form *form = &source_forms[n];
        unsigned index;
        if ((raw & form->mask) != form->value) continue;
        instruction->raw_instruction = raw;
        instruction->name_id = form->name;
        instruction->form_id = form->form;
        instruction->operand_count = 2;
        memset(instruction->operand, 0, sizeof(instruction->operand));
        for (index = 0; index < 2; ++index) {
            cdisasm_mips_operand *operand = &instruction->operand[index];
            unsigned selector = (raw >> (index ? 8u : 0u)) & 127u;
            unsigned vector = index ? form->source_vector : form->destination_vector;
            operand->type = CDISASM_OPERAND_REGISTER;
            operand->reg = (cdisasm_mips_reg_id)(vector ? CDISASM_MIPS_REG_VFPU_VECTOR(selector) :
                CDISASM_MIPS_REG_VFPU_SCALAR(selector));
            operand->size = index ? form->source_size : form->destination_size;
            operand->access = CDISASM_OPERAND_ACCESS_NONE;
            if (vector) operand->detail.element_size = 4;
        }
        return 1;
    }
#else
    (void)raw;
    (void)instruction;
#endif
    return 0;
}
