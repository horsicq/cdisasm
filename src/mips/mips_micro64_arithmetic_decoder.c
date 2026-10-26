/* Copyright (c) 2026 hors<horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 * Native microMIPS64 arithmetic lowering from reviewed numeric source facts.
 * No upstream assembler, simulator or manual implementation is included. */
#include "mips_decoder.h"
#include <string.h>

#if USE_EXTRA_OPCODES
typedef struct micro64_arithmetic_form {
    uint32_t mask, value;
    uint16_t name, form;
    uint8_t kind, minimum_release, removed_release6, variant;
} micro64_arithmetic_form;
static const micro64_arithmetic_form micro64_arithmetic_forms[] = {
#include "generated/mips_micro64_arithmetic_forms.inc"
};

static void micro64_reg(cdisasm_mips_instruction *i, unsigned reg, unsigned access)
{
    cdisasm_mips_operand *o = &i->operand[i->operand_count++];
    o->type = CDISASM_OPERAND_REGISTER;
    o->reg = (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0 + reg);
    o->size = 8u;
    o->access = (uint8_t)access;
}
static void micro64_imm(cdisasm_mips_instruction *i, uint64_t value, unsigned size, unsigned flags)
{
    cdisasm_mips_operand *o = &i->operand[i->operand_count++];
    o->type = CDISASM_OPERAND_IMMEDIATE;
    o->imm = value;
    o->size = (uint8_t)size;
    o->access = CDISASM_OPERAND_ACCESS_READ;
    o->flags = (uint8_t)flags;
}
static unsigned micro64_release(cdisasm_mips_revision revision)
{
    switch (revision) {
    /* Abstract ISA selectors follow the existing compact decoder policy;
     * this does not claim a named classic processor implements microMIPS. */
    case CDISASM_MIPS_REVISION_III:
    case CDISASM_MIPS_REVISION_IV:
    case CDISASM_MIPS_REVISION_V:
    case CDISASM_MIPS_REVISION_64R1: return 1u;
    case CDISASM_MIPS_REVISION_64R2: return 2u;
    case CDISASM_MIPS_REVISION_64R3: return 3u;
    case CDISASM_MIPS_REVISION_64R5: return 5u;
    case CDISASM_MIPS_REVISION_64R6: return 6u;
    default: return 0u;
    }
}
#endif

cdisasm_status cdisasm_mips_micro64_arithmetic(uint32_t raw, uint64_t address,
    cdisasm_mips_mode mode, cdisasm_mips_revision revision,
    const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *instruction)
{
#if USE_EXTRA_OPCODES
    size_t n;
    unsigned release = micro64_release(revision);
    /* The compact dispatcher has selected microMIPS before this entry point;
     * effective family flags no longer contain the encoding-selection bit. */
    (void)features;
    for (n = 0u; n < sizeof(micro64_arithmetic_forms)/sizeof(micro64_arithmetic_forms[0]); ++n) {
        const micro64_arithmetic_form *f = &micro64_arithmetic_forms[n];
        const unsigned rt = (raw >> 21) & 31u, rs = (raw >> 16) & 31u;
        const unsigned high = (raw >> 11) & 31u, low = (raw >> 6) & 31u;
        cdisasm_mips_instruction candidate;
        if ((raw & f->mask) != f->value) continue;
        if (mode != CDISASM_MIPS_MODE_64 || !release || release < f->minimum_release ||
            (f->removed_release6 && release == 6u)) return CDISASM_STATUS_INVALID_INSTRUCTION;
        memset(&candidate, 0, sizeof(candidate));
        candidate.raw_instruction = raw;
        candidate.address = address;
        candidate.opcode_size = 4u;
        candidate.mode = (uint8_t)mode;
        candidate.revision = (uint8_t)revision;
        candidate.name_id = f->name;
        candidate.form_id = f->form;
        if (f->kind == 0u) {
            micro64_reg(&candidate, high, CDISASM_OPERAND_ACCESS_WRITE);
            micro64_reg(&candidate, rs, CDISASM_OPERAND_ACCESS_READ);
            micro64_reg(&candidate, rt, CDISASM_OPERAND_ACCESS_READ);
        } else if (f->kind == 1u || f->kind == 2u) {
            unsigned bits = f->kind == 1u ? 10u : 16u;
            unsigned value = f->kind == 1u ? (raw >> 6) & 1023u : raw & 65535u;
            int64_t immediate = (int64_t)(value ^ (1u << (bits - 1u))) - (int64_t)(1u << (bits - 1u));
            micro64_reg(&candidate, rt, CDISASM_OPERAND_ACCESS_WRITE);
            micro64_reg(&candidate, rs, CDISASM_OPERAND_ACCESS_READ);
            micro64_imm(&candidate, (uint64_t)immediate, 2u, CDISASM_MIPS_OPERAND_FLAG_SIGNED);
        } else if (f->kind == 3u) {
            micro64_reg(&candidate, rt, CDISASM_OPERAND_ACCESS_WRITE);
            micro64_reg(&candidate, rs, CDISASM_OPERAND_ACCESS_READ);
        } else if (f->kind == 4u) {
            unsigned pos = low, size, msb = high;
            if (f->variant == 0u) size = high + 1u; /* DEXT */
            else if (f->variant == 1u) size = high + 33u; /* DEXTM */
            else if (f->variant == 2u) { pos += 32u; size = high + 1u; } /* DEXTU */
            else {
                if (f->variant >= 4u) msb += 32u;
                if (f->variant == 5u) pos += 32u;
                if (pos > msb) return CDISASM_STATUS_INVALID_INSTRUCTION;
                size = msb - pos + 1u;
            }
            /* Invalid tuples are a conservative syntax boundary: the manual
             * calls them UNPREDICTABLE, not reserved opcode encodings. */
            if (pos + size > 64u) return CDISASM_STATUS_INVALID_INSTRUCTION;
            micro64_reg(&candidate, rt, f->variant >= 3u ? CDISASM_OPERAND_ACCESS_READ_WRITE : CDISASM_OPERAND_ACCESS_WRITE);
            micro64_reg(&candidate, rs, CDISASM_OPERAND_ACCESS_READ);
            micro64_imm(&candidate, pos, 1u, 0u);
            micro64_imm(&candidate, size, 1u, 0u);
        } else if (f->kind == 5u) {
            micro64_reg(&candidate, rs, CDISASM_OPERAND_ACCESS_READ);
            micro64_reg(&candidate, rt, CDISASM_OPERAND_ACCESS_READ);
            candidate.instruction_flags = CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_HI | CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_LO;
        } else if (f->kind == 6u) {
            micro64_reg(&candidate, rt, CDISASM_OPERAND_ACCESS_WRITE);
            micro64_reg(&candidate, rs, CDISASM_OPERAND_ACCESS_READ);
            micro64_imm(&candidate, high, 1u, 0u);
        } else if (f->kind == 7u) {
            micro64_reg(&candidate, high, CDISASM_OPERAND_ACCESS_WRITE);
            micro64_reg(&candidate, rt, CDISASM_OPERAND_ACCESS_READ);
            micro64_reg(&candidate, rs, CDISASM_OPERAND_ACCESS_READ);
        } else return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        candidate.last_error_id = CDISASM_STATUS_OK;
        *instruction = candidate;
        return CDISASM_STATUS_OK;
    }
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    (void)raw; (void)address; (void)mode; (void)revision; (void)features; (void)instruction;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
}
