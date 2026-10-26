#include "mips_decoder.h"
#include <string.h>

#if USE_EXTRA_OPCODES
typedef struct micro64_fp_form {
    uint32_t mask, value;
    uint16_t name, form;
    uint8_t destination_size, source_size, packed;
} micro64_fp_form;
static const micro64_fp_form forms[] = {
#include "generated/mips_micro64_fp_forms.inc"
};
static int micro64_fp_revision(cdisasm_mips_revision revision, unsigned packed)
{
    switch (revision) {
        case CDISASM_MIPS_REVISION_III: case CDISASM_MIPS_REVISION_IV: return !packed;
        case CDISASM_MIPS_REVISION_V:
        case CDISASM_MIPS_REVISION_32R2: case CDISASM_MIPS_REVISION_32R3: case CDISASM_MIPS_REVISION_32R5:
        case CDISASM_MIPS_REVISION_64R1: case CDISASM_MIPS_REVISION_64R2:
        case CDISASM_MIPS_REVISION_64R3: case CDISASM_MIPS_REVISION_64R5: return 1;
        default: return 0;
    }
}
static void fp_register(cdisasm_mips_instruction *i, unsigned reg, unsigned size, unsigned access)
{
    cdisasm_mips_operand *o = &i->operand[i->operand_count++];
    o->type = CDISASM_OPERAND_REGISTER; o->reg = (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_FPR0 + reg);
    o->size = (uint8_t)size; o->access = (uint8_t)access;
}
#endif

uint64_t cdisasm_mips_micro64_fp_required_flags(cdisasm_mips_form_id form)
{
#if USE_EXTRA_OPCODES
    if (form >= 31140u && form <= 31150u)
        return CDISASM_MIPS_DECODE_FLAG_FPU | (form == 31150u ? CDISASM_MIPS_DECODE_FLAG_PAIRED_SINGLE : 0);
#else
    (void)form;
#endif
    return 0;
}

cdisasm_status cdisasm_mips_micro64_fp(uint32_t raw, uint64_t address, cdisasm_mips_mode mode,
    cdisasm_mips_revision revision, const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *i)
{
#if USE_EXTRA_OPCODES
    size_t n;
    for (n = 0; n < sizeof(forms) / sizeof(forms[0]); ++n) {
        const micro64_fp_form *f = &forms[n];
        uint64_t required;
        unsigned destination = (raw >> 21) & 31u, source = (raw >> 16) & 31u;
        if ((raw & f->mask) != f->value) continue;
        if ((mode != CDISASM_MIPS_MODE_32 && mode != CDISASM_MIPS_MODE_64) || !micro64_fp_revision(revision, f->packed))
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        required = cdisasm_mips_micro64_fp_required_flags(f->form);
        if (!features || (features->bitmap[0] & required) != required) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        /* Long fixed-point and paired-single values require FR=1. Even
         * register numbers do not make these operations defined in FR=0. */
        if (features->bitmap[0] & CDISASM_MIPS_DECODE_FLAG_FPR32) return CDISASM_STATUS_INVALID_INSTRUCTION;
        if (!i) return CDISASM_STATUS_INVALID_ARGUMENT;
        memset(i, 0, sizeof(*i));
        i->address = address; i->raw_instruction = raw; i->opcode_size = 4;
        i->mode = (uint8_t)mode; i->revision = (uint8_t)revision;
        i->name_id = f->name; i->form_id = f->form;
        i->instruction_flags = CDISASM_MIPS_INSTRUCTION_FLAG_FLOATING_POINT;
        if (f->packed) {
            destination = (raw >> 11) & 31u;
            i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_PAIRED_SINGLE;
        } else {
            /* Arithmetic exception enables/NAN handling and preserved status
             * fields are read even for explicitly directed rounding. */
            i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_READS_FCSR | CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_FCSR;
        }
        fp_register(i, destination, f->destination_size, CDISASM_OPERAND_ACCESS_WRITE);
        fp_register(i, source, f->source_size, CDISASM_OPERAND_ACCESS_READ);
        if (f->packed) fp_register(i, (raw >> 21) & 31u, 4u, CDISASM_OPERAND_ACCESS_READ);
        return CDISASM_STATUS_OK;
    }
#else
    (void)raw; (void)address; (void)mode; (void)revision; (void)features; (void)i;
#endif
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}
