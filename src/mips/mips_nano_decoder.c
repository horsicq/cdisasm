#include "mips_decoder.h"

#include <string.h>

/* Native nanoMIPS lowering.  Numeric masks/field permutations derive from
 * MediaTek's pinned LLVM backend (Apache-2.0 WITH LLVM-exception); register,
 * memory and control-flow records are native cdisasm data, never parsed text. */
uint32_t cdisasm_mips_nano_size(uint16_t first)
{
    return (first & UINT16_C(0x1000)) != 0u ? 2u : (first >> 10) == 24u ? 6u : 4u;
}

#if USE_EXTRA_OPCODES
typedef struct nano_bit { uint8_t source, destination; } nano_bit;
typedef struct nano_operand_recipe {
    uint8_t kind, mapping, width, adjustment, detail, access, size, flags;
    uint16_t bit_start;
    uint8_t bit_count, constant, aux;
} nano_operand_recipe;
typedef struct nano_form {
    uint64_t mask, value, required;
    uint32_t flags, groups;
    uint16_t name, form, operand_start;
    uint8_t operand_count, size, special;
} nano_form;
#include "generated/mips_nano_forms.inc"

static uint32_t nano_field(uint64_t raw, const nano_operand_recipe *recipe)
{
    uint32_t value = recipe->constant;
    unsigned n;
    for (n = 0u; n < recipe->bit_count; ++n) {
        const nano_bit *bit = &nano_bits[recipe->bit_start + n];
        value |= (uint32_t)((raw >> bit->source) & UINT64_C(1)) << bit->destination;
    }
    return value;
}
static int64_t nano_signed(uint32_t value, unsigned width)
{
    uint64_t sign = UINT64_C(1) << (width - 1u);
    return (int64_t)(((uint64_t)value ^ sign) - sign);
}
static unsigned nano_gpr(unsigned value, unsigned mapping)
{
    if (mapping == 2u || mapping == 3u) {
        if (value > 7u) return 32u;
        if (mapping == 3u && value == 0u) return 0u;
        return value < 4u ? 16u + value : value;
    }
    if (mapping == 4u || mapping == 5u) {
        value &= ~8u;
        if (mapping == 5u && value == 3u) return 0u;
        return value < 4u ? value + 8u : value;
    }
    if (mapping == 6u) return 0u;
    if (mapping == 7u) return 29u;
    if (mapping == 8u) return 28u;
    if (mapping == 9u) return 31u;
    if (mapping == 10u) return value < 4u ? value + 4u : 32u;
    if (mapping == 11u) return value < 4u ? value + 5u : 32u;
    if (value > 31u || (mapping == 1u && value == 0u)) return 32u;
    return value;
}
static void nano_register(cdisasm_mips_operand *operand, uint16_t reg, uint8_t size, uint8_t access, uint8_t flags)
{
    operand->type = CDISASM_OPERAND_REGISTER;
    operand->reg = reg;
    operand->size = size;
    operand->access = access;
    operand->flags = flags;
}
static void nano_memory(cdisasm_mips_operand *operand, unsigned base, int64_t offset, unsigned size, unsigned access, unsigned flags)
{
    operand->type = CDISASM_OPERAND_MEMORY;
    operand->base_reg = (uint16_t)(CDISASM_MIPS_REG_GPR0 + base);
    operand->imm = (uint64_t)offset;
    operand->size = (uint8_t)size;
    operand->access = (uint8_t)access;
    operand->flags = (uint8_t)(flags | CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT | CDISASM_OPERAND_FLAG_SIGNED);
    if (base == 0u) {
        operand->address = (uint32_t)offset;
        operand->flags |= CDISASM_OPERAND_FLAG_HAS_ADDRESS | CDISASM_OPERAND_FLAG_ABSOLUTE;
    }
}
static int nano_operand(uint64_t raw, const nano_operand_recipe *recipe, cdisasm_mips_instruction *instruction)
{
    cdisasm_mips_operand *operand = &instruction->operand[instruction->operand_count++];
    uint32_t value = nano_field(raw, recipe);
    int64_t immediate = recipe->width ? nano_signed(value, recipe->width) : (int64_t)value;
    unsigned reg, base, mask;
    operand->size = recipe->size;
    operand->access = recipe->access;
    operand->flags = recipe->flags;
    operand->detail.flags = recipe->detail;
    switch (recipe->kind) {
        case 1u:
            if (recipe->mapping >= 12u && recipe->mapping <= 14u) {
                if (value >= 4u) return 0;
                reg = CDISASM_MIPS_REG_ACC0 + value;
            } else if (recipe->mapping == 15u) {
                if (value >= 32u) return 0;
                reg = CDISASM_MIPS_REG_NANO_CP0(value, 0u);
            } else if (recipe->mapping == 16u) {
                if (value >= 1024u) return 0;
                reg = CDISASM_MIPS_REG_NANO_CP0(value >> 5, value & 31u);
            } else if (recipe->mapping == 17u) {
                if (value >= 32u) return 0;
                reg = CDISASM_MIPS_REG_PREVIOUS_GPR(value);
            } else {
                reg = nano_gpr(value, recipe->mapping);
                if (reg >= 32u) return 0;
                reg += CDISASM_MIPS_REG_GPR0;
            }
            nano_register(operand, (uint16_t)reg, recipe->size, recipe->access, recipe->flags);
            operand->detail.flags = recipe->detail;
            return 1;
        case 2u:
            operand->type = CDISASM_OPERAND_IMMEDIATE;
            if (recipe->mapping == 18u) immediate = value == 12u ? 255 : value == 13u ? 65535 : value;
            else if (recipe->mapping == 19u) immediate = value == 0u ? 8 : value;
            else if (recipe->mapping == 20u) {
                unsigned position = instruction->operand_count >= 2u ? (unsigned)instruction->operand[instruction->operand_count - 2u].imm : 0u;
                if (value < position) return 0;
                immediate = value + 1u - position;
            } else if (recipe->mapping == 21u) immediate = -(int64_t)value;
            else if (recipe->mapping == 22u) immediate = value == 127u ? -1 : value;
            if (recipe->adjustment == 12u) immediate *= INT64_C(4096);
            else immediate += recipe->adjustment;
            operand->imm = (uint64_t)immediate;
            return 1;
        case 3u:
            mask = recipe->width ? (UINT32_C(1) << recipe->width) - 1u : 0u;
            base = nano_gpr(value >> recipe->width, recipe->mapping);
            if (base >= 32u) return 0;
            immediate = recipe->aux == 1u ? nano_signed(value & mask, recipe->width) : (value & mask);
            nano_memory(operand, base, immediate, recipe->size, recipe->access, recipe->flags);
            if (recipe->aux == 2u) {
                reg = nano_gpr(value & 31u, recipe->mapping);
                if (reg >= 32u) return 0;
                operand->index_reg = (uint16_t)(CDISASM_MIPS_REG_GPR0 + reg);
                operand->imm = 0u;
                operand->flags &= ~(CDISASM_OPERAND_FLAG_ABSOLUTE | CDISASM_OPERAND_FLAG_HAS_ADDRESS | CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT);
                operand->address = 0u;
                operand->detail.index_shift = recipe->adjustment;
                if (recipe->adjustment) operand->detail.flags |= CDISASM_MIPS_OPERAND_DETAIL_INDEX_SCALED;
            }
            return 1;
        case 4u:
            if (recipe->adjustment) immediate = (int64_t)value * 2;
            operand->type = CDISASM_OPERAND_IMMEDIATE;
            operand->imm = (uint32_t)(instruction->address + instruction->opcode_size + (uint64_t)immediate);
            operand->address = (uint64_t)immediate;
            operand->flags |= CDISASM_OPERAND_FLAG_PC_RELATIVE | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
            instruction->branch_target = operand->imm;
            return 1;
        case 5u: case 7u:
            if (recipe->adjustment) immediate *= INT64_C(4096);
            operand->address = (uint32_t)(instruction->address + instruction->opcode_size + (uint64_t)immediate);
            if (recipe->aux) operand->address &= ~UINT64_C(4095);
            operand->flags |= CDISASM_OPERAND_FLAG_PC_RELATIVE | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
            if (recipe->kind == 5u) {
                operand->type = CDISASM_OPERAND_IMMEDIATE;
                operand->imm = operand->address;
                operand->address = (uint64_t)immediate;
            } else {
                operand->type = CDISASM_OPERAND_MEMORY;
                operand->imm = (uint64_t)immediate;
                operand->flags |= CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT | CDISASM_OPERAND_FLAG_SIGNED;
            }
            return 1;
        case 6u: {
            unsigned start = recipe->mapping ? 30u + ((value >> 4) & 1u) : value >> 5;
            unsigned count = recipe->mapping ? value & 15u : (value >> 1) & 15u;
            unsigned gp = recipe->mapping ? 0u : value & 1u, n;
            uint64_t list = 0u;
            for (n = 0u; n < count; ++n) {
                reg = gp && n + 1u == count ? 28u : start + n;
                if (reg >= 32u) reg -= 16u;
                if (reg >= 32u) return 0;
                list |= UINT64_C(1) << reg;
            }
            nano_register(operand, CDISASM_MIPS_REG_GPR0, 4u, recipe->access, 0u);
            operand->detail.flags = CDISASM_MIPS_OPERAND_DETAIL_REGISTER_LIST;
            operand->imm = list;
            return 1;
        }
        default: return 0;
    }
}

static int nano_finish(const nano_form *form, uint64_t raw, const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *i)
{
    unsigned n;
    if ((i->name_id == CDISASM_MIPS_NAME_ADDIU_32 || i->name_id == CDISASM_MIPS_NAME_SLTU) &&
        i->operand[0].reg == CDISASM_MIPS_REG_GPR0) return 0;
    if (form->special == 1u || form->special == 2u) {
        unsigned rs = ((unsigned)raw >> 4) & 7u, rt = ((unsigned)raw >> 7) & 7u;
        if ((raw & 15u) == 0u || (form->special == 1u ? rs >= rt : rs < rt)) return 0;
    }
    if (form->special == 3u) {
        cdisasm_mips_operand *sp, *memory;
        uint64_t list = i->operand[1].imm;
        unsigned count = 0u, save = i->name_id == CDISASM_MIPS_NAME_SAVE;
        for (n = 0u; n < 32u; ++n) if (list & (UINT64_C(1) << n)) ++count;
        sp = &i->operand[i->operand_count++];
        nano_register(sp, CDISASM_MIPS_REG_GPR29, 4u, CDISASM_OPERAND_ACCESS_READ_WRITE, CDISASM_OPERAND_FLAG_IMPLICIT);
        if (count) {
            memory = &i->operand[i->operand_count++];
            nano_memory(memory, 29u, save ? -(int64_t)(4u * count) : (int64_t)i->operand[0].imm - (int64_t)(4u * count), 4u * count,
                        save ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ, CDISASM_OPERAND_FLAG_IMPLICIT);
        }
        if (i->name_id == CDISASM_MIPS_NAME_RESTORE_JRC) {
            cdisasm_mips_operand *ra = &i->operand[i->operand_count++];
            nano_register(ra, CDISASM_MIPS_REG_GPR31, 4u, CDISASM_OPERAND_ACCESS_READ, CDISASM_OPERAND_FLAG_IMPLICIT);
        }
    }
    if (form->special == 4u) {
        unsigned count = (unsigned)i->operand[2].imm, start = i->operand[0].reg - CDISASM_MIPS_REG_GPR0;
        uint64_t list = 0u;
        for (n = 0u; n < count; ++n) {
            unsigned reg = start + n;
            if (reg >= 32u) reg -= 16u;
            if (reg >= 32u) return 0;
            list |= UINT64_C(1) << reg;
        }
        i->operand[0].reg = CDISASM_MIPS_REG_GPR0;
        i->operand[0].detail.flags |= CDISASM_MIPS_OPERAND_DETAIL_REGISTER_LIST;
        i->operand[0].imm = list;
        i->operand[1].size = (uint8_t)(4u * count);
    }
    if (form->special == 5u) {
        unsigned move_to = i->name_id == CDISASM_MIPS_NAME_MTTR;
        unsigned remote = 1u;
        unsigned u = (unsigned)i->operand[2].imm, sel = (unsigned)i->operand[3].imm, h = (unsigned)i->operand[4].imm;
        cdisasm_mips_operand *o = &i->operand[remote];
        unsigned encoded = ((unsigned)raw >> 16) & 31u;
        o->flags |= CDISASM_MIPS_OPERAND_FLAG_THREAD_REGISTER;
        if (u == 0u) o->reg = CDISASM_MIPS_REG_NANO_CP0(encoded, sel);
        else if (sel == 0u) o->reg = (uint16_t)(CDISASM_MIPS_REG_GPR0 + encoded);
        else if (sel == 1u) {
            if (encoded >= 16u) return 0;
            o->reg = (uint16_t)(CDISASM_MIPS_REG_ACC0 + (encoded >> 2));
            if ((encoded & 3u) == 1u) o->detail.flags |= CDISASM_MIPS_OPERAND_DETAIL_HIGH_HALF;
            else if ((encoded & 3u) == 2u) o->detail.flags |= CDISASM_MIPS_OPERAND_DETAIL_ACC_EXTENSION;
            else if (encoded & 3u) return 0;
            i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_DSP;
            if (!(features->bitmap[0] & CDISASM_MIPS_DECODE_FLAG_DSP)) return -1;
        } else if (sel == 2u || sel == 3u) {
            if (!(features->bitmap[0] & CDISASM_MIPS_DECODE_FLAG_FPU)) return -1;
            o->reg = (uint16_t)((sel == 2u ? CDISASM_MIPS_REG_FPR0 : CDISASM_MIPS_REG_FCR0) + encoded);
            i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_FLOATING_POINT;
        } else if (sel == 4u || sel == 5u) {
            if (!(features->bitmap[0] & CDISASM_MIPS_DECODE_FLAG_COP2)) return -1;
            o->reg = sel == 4u ? CDISASM_MIPS_REG_COP2(encoded, 0u) : (uint16_t)(CDISASM_MIPS_REG_FCR2_FIRST + encoded);
            i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_COP2;
        } else return 0;
        if (h) { o->size = 8u; o->detail.flags |= CDISASM_MIPS_OPERAND_DETAIL_HIGH_HALF; }
        o->access = move_to ? h ? CDISASM_OPERAND_ACCESS_READ_WRITE : CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ;
    }
    if (i->name_id == CDISASM_MIPS_NAME_EXT || i->name_id == CDISASM_MIPS_NAME_INS) {
        if (i->operand[2].imm + i->operand[3].imm > 32u || i->operand[3].imm == 0u) return 0;
    }
    if (i->name_id == CDISASM_MIPS_NAME_JRC && i->operand[0].reg == CDISASM_MIPS_REG_GPR31) i->opcode_groups |= CDISASM_GROUP_RETURN;
    if ((i->name_id == CDISASM_MIPS_NAME_JALRC || i->name_id == CDISASM_MIPS_NAME_JALRC_HB) &&
        i->operand[0].reg == CDISASM_MIPS_REG_GPR0) {
        i->opcode_groups &= ~CDISASM_GROUP_CALL;
        if (i->operand[1].reg == CDISASM_MIPS_REG_GPR31) i->opcode_groups |= CDISASM_GROUP_RETURN;
    }
    return i->operand_count <= CDISASM_MIPS_MAX_OPERANDS;
}

cdisasm_status cdisasm_mips_decode_nano(uint64_t raw, uint32_t size, uint64_t address,
                                      cdisasm_mips_mode mode, cdisasm_mips_revision revision,
                                      const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *instruction)
{
    size_t n;
    unsigned operand;
    int disabled = 0;
    if (mode != CDISASM_MIPS_MODE_32 || features == NULL || instruction == NULL) return CDISASM_STATUS_INVALID_ARGUMENT;
    if (size != 2u && size != 4u && size != 6u) return CDISASM_STATUS_INVALID_ARGUMENT;
    if (cdisasm_mips_nano_size((uint16_t)(raw >> (8u * (size - 2u)))) != size) return CDISASM_STATUS_INVALID_INSTRUCTION;
    for (n = 0u; n < sizeof(nano_forms) / sizeof(nano_forms[0]); ++n) {
        const nano_form *form = &nano_forms[n];
        cdisasm_mips_instruction candidate;
        if (form->size != size || (raw & form->mask) != form->value) continue;
        if ((features->bitmap[0] & form->required) != form->required) { disabled = 1; continue; }
        memset(&candidate, 0, sizeof(candidate));
        candidate.address = address;
        candidate.opcode_size = size;
        candidate.raw_instruction = (uint32_t)raw;
        candidate.mode = (uint8_t)mode;
        candidate.revision = (uint8_t)revision;
        candidate.name_id = form->name;
        candidate.form_id = form->form;
        candidate.instruction_flags = form->flags;
        candidate.opcode_groups = form->groups;
        for (operand = 0u; operand < form->operand_count; ++operand)
            if (!nano_operand(raw, &nano_operands[form->operand_start + operand], &candidate)) break;
        if (operand != form->operand_count) continue;
        {
            int finished = nano_finish(form, raw, features, &candidate);
            if (finished < 0) disabled = 1;
            if (finished <= 0) continue;
        }
        *instruction = candidate;
        return CDISASM_STATUS_OK;
    }
    return disabled ? CDISASM_STATUS_UNSUPPORTED_INSTRUCTION : CDISASM_STATUS_INVALID_INSTRUCTION;
}

uint64_t cdisasm_mips_nano_required_flags(cdisasm_mips_form_id form)
{
    size_t n;
    for (n = 0u; n < sizeof(nano_forms) / sizeof(nano_forms[0]); ++n)
        if (nano_forms[n].form == form) return nano_forms[n].required;
    return 0u;
}
#else
cdisasm_status cdisasm_mips_decode_nano(uint64_t raw, uint32_t size, uint64_t address,
                                      cdisasm_mips_mode mode, cdisasm_mips_revision revision,
                                      const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *instruction)
{
    (void)raw; (void)size; (void)address; (void)mode; (void)revision; (void)features; (void)instruction;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}
uint64_t cdisasm_mips_nano_required_flags(cdisasm_mips_form_id form) { (void)form; return 0u; }
#endif
