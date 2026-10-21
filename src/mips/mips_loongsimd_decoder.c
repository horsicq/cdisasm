#include "mips_decoder.h"
#include <string.h>

/* Later Loongson MIPS processors retain the 64-bit multimedia COP2 bank.
 * No strings/tables are needed to preserve namespace ownership when optional
 * opcodes are excluded. A different ISA's LSX/LASX words are never matched. */
int cdisasm_mips_loongsimd_owns(uint32_t raw)
{
    return (raw & UINT32_C(0xff000000)) == UINT32_C(0x4b000000);
}

#if USE_EXTRA_OPCODES
typedef struct loongsimd_form {
    uint32_t mask, value;
    uint16_t name, form;
    uint8_t kind, size, element, source_element, third_element;
} loongsimd_form;

static const loongsimd_form loongsimd_forms[] = {
#include "generated/mips_loongsimd_forms.inc"
};

static void loongsimd_register(cdisasm_mips_instruction *i, unsigned reg,
                               unsigned size, unsigned element, unsigned access, int hidden)
{
    cdisasm_mips_operand *o = &i->operand[i->operand_count++];
    o->type = CDISASM_OPERAND_REGISTER;
    o->reg = (cdisasm_mips_reg_id)reg;
    o->size = (uint8_t)size;
    o->detail.element_size = (uint8_t)element;
    o->access = (uint8_t)access;
    if (hidden) o->flags = CDISASM_OPERAND_FLAG_IMPLICIT;
}

static int loongsimd_revision(cdisasm_mips_revision revision)
{
    return revision == CDISASM_MIPS_REVISION_64R2 || revision == CDISASM_MIPS_REVISION_64R3 ||
           revision == CDISASM_MIPS_REVISION_64R5;
}
#endif

cdisasm_status cdisasm_mips_decode_loongsimd(uint32_t raw, uint64_t address, cdisasm_mips_mode mode,
                                           cdisasm_mips_revision revision, const cdisasm_mips_decode_flags *features,
                                           cdisasm_mips_instruction *instruction)
{
#if USE_EXTRA_OPCODES
    const uint64_t required = CDISASM_MIPS_DECODE_FLAG_LOONGSIMD |
                              CDISASM_MIPS_DECODE_FLAG_LOONGSON | CDISASM_MIPS_DECODE_FLAG_FPU;
    unsigned fd = (raw >> 6) & 31u, fs = (raw >> 11) & 31u, ft = (raw >> 16) & 31u;
    size_t n;
    int reserved = 0;
    if (!instruction || !features) return CDISASM_STATUS_INVALID_ARGUMENT;
    if (!cdisasm_mips_loongsimd_owns(raw)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    if ((features->bitmap[0] & required) != required) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    if (mode != CDISASM_MIPS_MODE_64 || !loongsimd_revision(revision)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    for (n = 0; n < sizeof(loongsimd_forms)/sizeof(loongsimd_forms[0]); ++n) {
        const loongsimd_form *f = &loongsimd_forms[n];
        cdisasm_mips_instruction candidate;
        /* Unused compare-result/unary-source fields are reserved zero. This
         * also distinguishes known malformed forms from unverified later
         * custom vector opcodes sharing the broad vendor namespace. */
        if ((raw & UINT32_C(0xffe0003f)) != f->value) continue;
        if ((raw & f->mask) != f->value) { reserved = 1; continue; }
        if (features->bitmap[0] & CDISASM_MIPS_DECODE_FLAG_FPR32) return CDISASM_STATUS_INVALID_INSTRUCTION;
        memset(&candidate, 0, sizeof(candidate));
        candidate.address = address;
        candidate.raw_instruction = raw;
        candidate.opcode_size = 4u;
        candidate.mode = (uint8_t)mode;
        candidate.revision = (uint8_t)revision;
        candidate.name_id = f->name;
        candidate.form_id = f->form;
        candidate.instruction_flags = CDISASM_MIPS_INSTRUCTION_FLAG_FLOATING_POINT;
        if (f->kind != 3u)
            loongsimd_register(&candidate, CDISASM_MIPS_REG_FPR0+fd, f->size, f->element, CDISASM_OPERAND_ACCESS_WRITE, 0);
        loongsimd_register(&candidate, CDISASM_MIPS_REG_FPR0+fs, f->size, f->source_element, CDISASM_OPERAND_ACCESS_READ, 0);
        if (f->kind != 2u) {
            unsigned source_size = f->size == 4u && (f->name == CDISASM_MIPS_NAME_SLL ||
                f->name == CDISASM_MIPS_NAME_SRL || f->name == CDISASM_MIPS_NAME_SRA) ? 8u : f->size;
            loongsimd_register(&candidate, CDISASM_MIPS_REG_FPR0+ft, source_size, f->third_element, CDISASM_OPERAND_ACCESS_READ, 0);
        }
        if (f->kind == 3u)
            loongsimd_register(&candidate, CDISASM_MIPS_REG_FCC0, 1u, 0u, CDISASM_OPERAND_ACCESS_WRITE, 1);
        *instruction = candidate;
        return CDISASM_STATUS_OK;
    }
    return reserved ? CDISASM_STATUS_INVALID_INSTRUCTION : CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    (void)raw; (void)address; (void)mode; (void)revision; (void)features; (void)instruction;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
}

uint64_t cdisasm_mips_loongsimd_required_flags(cdisasm_mips_form_id form)
{
#if USE_EXTRA_OPCODES
    if (form >= 59000u && form < 59080u)
        return CDISASM_MIPS_DECODE_FLAG_LOONGSIMD | CDISASM_MIPS_DECODE_FLAG_LOONGSON | CDISASM_MIPS_DECODE_FLAG_FPU;
#else
    (void)form;
#endif
    return 0;
}
