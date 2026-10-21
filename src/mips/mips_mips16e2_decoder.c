#include "mips_decoder.h"
#include <string.h>

/* First 16-bit parcel occupies the high half of raw. Ownership is available
 * without optional data so disabled E2 never reinterprets a subdecode as the
 * earlier extended LI/SLL/SRL/LWSP/SWSP instruction. */
int cdisasm_mips_mips16e2_owns(uint32_t raw)
{
    unsigned op = (raw >> 11) & 31u;
    if ((raw >> 27) != 30u) return 0;
    if (op == 0u || op == 13u || op == 18u || op == 26u) return (raw & 224u) != 0u;
    if (op == 6u && ((raw & 3u) == 0u || (raw & 3u) == 2u)) return (raw & 28u) != 0u;
    if (op == 12u && ((raw >> 8) & 7u) == 7u) return 1;
    return 0;
}

#if USE_EXTRA_OPCODES
typedef struct mips16e2_form {
    uint32_t mask, value;
    uint16_t name, form, state;
    uint8_t kind, aux, size, access, mt;
} mips16e2_form;
static const mips16e2_form mips16e2_forms[] = {
#include "generated/mips_mips16e2_forms.inc"
};

static unsigned e2_gpr(unsigned encoded)
{
    return encoded < 2u ? encoded+16u : encoded;
}
static cdisasm_mips_operand *e2_register(cdisasm_mips_instruction *i, unsigned reg, unsigned size, unsigned access, int hidden)
{
    cdisasm_mips_operand *o = &i->operand[i->operand_count++];
    o->type = CDISASM_OPERAND_REGISTER;
    o->reg = (cdisasm_mips_reg_id)reg;
    o->size = (uint8_t)size;
    o->access = (uint8_t)access;
    if (hidden) o->flags = CDISASM_OPERAND_FLAG_IMPLICIT;
    return o;
}
static void e2_immediate(cdisasm_mips_instruction *i, uint64_t value, unsigned size, int is_signed)
{
    cdisasm_mips_operand *o = &i->operand[i->operand_count++];
    o->type = CDISASM_OPERAND_IMMEDIATE;
    o->imm = value;
    o->size = (uint8_t)size;
    o->access = CDISASM_OPERAND_ACCESS_READ;
    if (is_signed) o->flags = CDISASM_OPERAND_FLAG_SIGNED;
}
static void e2_memory(cdisasm_mips_instruction *i, unsigned base, int64_t displacement, unsigned size, unsigned access)
{
    cdisasm_mips_operand *o = &i->operand[i->operand_count++];
    o->type = CDISASM_OPERAND_MEMORY;
    o->base_reg = (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0+base);
    o->imm = (uint64_t)displacement;
    o->size = (uint8_t)size;
    o->access = (uint8_t)access;
    o->flags = CDISASM_OPERAND_FLAG_SIGNED | CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;
    if (!size) o->flags |= CDISASM_OPERAND_FLAG_ADDRESS_ONLY;
}
static int64_t e2_imm9(uint32_t raw)
{
    unsigned value = ((raw >> 21) & 15u) << 5 | (raw & 31u);
    return (int64_t)(value ^ 256u) - 256;
}
static unsigned e2_imm16(uint32_t raw)
{
    return ((raw >> 16) & 31u) << 11 | ((raw >> 21) & 63u) << 5 | (raw & 31u);
}
static cdisasm_status e2_lower(uint32_t raw, const mips16e2_form *f, cdisasm_mips_instruction *i)
{
    unsigned rx = e2_gpr((raw >> 8) & 7u), ry = e2_gpr((raw >> 5) & 7u), rb = e2_gpr((raw >> 16) & 7u);
    unsigned gpr_size = i->mode == CDISASM_MIPS_MODE_64 ? 8u : 4u;
    unsigned immediate = e2_imm16(raw);
    if (f->kind == 1u) {
        e2_register(i, CDISASM_MIPS_REG_GPR0+rx, gpr_size, f->aux == 2u ? 3u : 2u, 0);
        if (!f->aux) e2_register(i, CDISASM_MIPS_REG_GPR28, gpr_size, 1u, 0);
        e2_immediate(i, !f->aux ? (uint64_t)(int64_t)(int16_t)immediate : immediate, 2u, f->aux == 0u);
    } else if (f->kind == 2u) {
        e2_register(i, CDISASM_MIPS_REG_GPR0+rx, gpr_size, f->access == 1u ? 2u : 1u, 0);
        e2_memory(i, 28u, (int16_t)immediate, f->size, f->access);
    } else if (f->kind == 3u) {
        e2_register(i, CDISASM_MIPS_REG_GPR0+rx, gpr_size, f->aux ? 3u : f->access == 1u ? 2u : 1u, 0);
        e2_memory(i, rb, e2_imm9(raw), f->size, f->access);
        if (f->name == CDISASM_MIPS_NAME_LL || f->name == CDISASM_MIPS_NAME_SC)
            i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_ATOMIC;
    } else if (f->kind == 4u) {
        e2_immediate(i, (raw >> 16) & 31u, 1u, 0);
        e2_memory(i, rx, e2_imm9(raw), 0u, 0u);
        if (f->aux) i->opcode_groups |= CDISASM_GROUP_PRIVILEGED;
    } else if (f->kind == 5u) {
        unsigned position = (raw >> 22) & 31u, msb = (raw >> 16) & 31u;
        unsigned size = f->aux ? msb-position+1u : msb+1u;
        if ((f->aux && msb < position) || (!f->aux && position+size > 32u)) return CDISASM_STATUS_INVALID_INSTRUCTION;
        e2_register(i, CDISASM_MIPS_REG_GPR0+ry, gpr_size, f->aux ? 3u : 2u, 0);
        e2_register(i, CDISASM_MIPS_REG_GPR0+(f->aux == 2u ? 0u : rx), gpr_size, 1u, 0);
        e2_immediate(i, position, 1u, 0);
        e2_immediate(i, size, 1u, 0);
    } else if (f->kind == 6u) {
        e2_register(i, CDISASM_MIPS_REG_GPR0+rx, gpr_size, 3u, 0);
        e2_register(i, CDISASM_MIPS_REG_GPR0+(f->aux ? 0u : rb), gpr_size, 1u, 0);
        if (f->name == CDISASM_MIPS_NAME_MOVTN || f->name == CDISASM_MIPS_NAME_MOVTZ)
            e2_register(i, CDISASM_MIPS_REG_GPR24, gpr_size, 1u, 1);
        else e2_register(i, CDISASM_MIPS_REG_GPR0+ry, gpr_size, 1u, 0);
        i->opcode_groups |= CDISASM_GROUP_CONDITIONAL;
    } else if (f->kind == 7u) {
        e2_register(i, CDISASM_MIPS_REG_GPR0+ry, 4u, f->aux ? 1u : 2u, 0);
        e2_register(i, CDISASM_MIPS_REG_CP0(raw & 31u, (raw >> 21) & 7u), 4u, f->aux ? 2u : 1u, 0);
        i->opcode_groups |= CDISASM_GROUP_PRIVILEGED;
    } else if (f->kind == 8u) {
        if (!f->aux) e2_register(i, CDISASM_MIPS_REG_GPR0+ry, 4u, 2u, 0);
        e2_register(i, f->state, 4u, 3u, 1);
        i->opcode_groups |= CDISASM_GROUP_PRIVILEGED;
    } else if (f->kind == 9u) {
        e2_register(i, CDISASM_MIPS_REG_GPR0+ry, gpr_size, 2u, 0);
        e2_immediate(i, (raw >> 16) & 31u, 1u, 0);
    } else if (f->kind == 10u) {
        if (f->name == CDISASM_MIPS_NAME_PAUSE) e2_register(i, CDISASM_MIPS_REG_LLBIT, 1u, 1u, 1);
    } else if (f->kind == 11u) {
        unsigned stype = (raw >> 22) & 31u;
        if (stype) e2_immediate(i, stype, 1u, 0);
        i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_MEMORY_BARRIER;
    } else return CDISASM_STATUS_INTERNAL_ERROR;
    if (f->mt) i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_MT;
    return CDISASM_STATUS_OK;
}
#endif

cdisasm_status cdisasm_mips_decode_mips16e2(uint32_t raw, uint32_t size, uint64_t address,
                                         cdisasm_mips_mode mode, cdisasm_mips_revision revision,
                                         const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *instruction)
{
#if USE_EXTRA_OPCODES
    size_t n;
    if (!features || (features->bitmap[0] & CDISASM_MIPS_DECODE_FLAG_MIPS16E2) == 0u || size != 4u)
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    if (!cdisasm_mips_mips16e2_owns(raw)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    for (n = 0; n < sizeof(mips16e2_forms)/sizeof(mips16e2_forms[0]); ++n) {
        const mips16e2_form *f = &mips16e2_forms[n];
        cdisasm_mips_instruction candidate;
        cdisasm_status status;
        if ((raw & f->mask) != f->value) continue;
        if (f->mt && (features->bitmap[0] & CDISASM_MIPS_DECODE_FLAG_MT) == 0u) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        memset(&candidate, 0, sizeof(candidate));
        candidate.address = address;
        candidate.raw_instruction = raw;
        candidate.opcode_size = 4u;
        candidate.mode = (uint8_t)mode;
        candidate.revision = (uint8_t)revision;
        candidate.name_id = f->name;
        candidate.form_id = f->form;
        status = e2_lower(raw, f, &candidate);
        if (status != CDISASM_STATUS_OK) return status;
        candidate.last_error_id = CDISASM_STATUS_OK;
        *instruction = candidate;
        return CDISASM_STATUS_OK;
    }
    return CDISASM_STATUS_INVALID_INSTRUCTION;
#else
    (void)raw; (void)size; (void)address; (void)mode; (void)revision; (void)features; (void)instruction;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
}

uint64_t cdisasm_mips_mips16e2_required_flags(cdisasm_mips_form_id form)
{
#if USE_EXTRA_OPCODES
    size_t n;
    for (n = 0; n < sizeof(mips16e2_forms)/sizeof(mips16e2_forms[0]); ++n)
        if (mips16e2_forms[n].form == form)
            return CDISASM_MIPS_DECODE_FLAG_MIPS16 | CDISASM_MIPS_DECODE_FLAG_MIPS16E2 |
                   (mips16e2_forms[n].mt ? CDISASM_MIPS_DECODE_FLAG_MT : 0u);
#else
    (void)form;
#endif
    return 0;
}
