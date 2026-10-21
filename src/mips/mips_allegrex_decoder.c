#include "mips_decoder.h"
#include <string.h>

/* Hardware restrictions survive an extras-disabled build: selecting Allegrex
 * must not silently turn its scalar FPU into a generic double-precision FPU.
 * Zero means architecturally unavailable; one leaves ordinary core validation
 * and optional-family selection responsible for the remaining encoding. */
int cdisasm_mips_allegrex_encoding_allowed(uint32_t raw)
{
    unsigned op = raw >> 26, format = (raw >> 21) & 31u, fn = raw & 63u;
    if (op == 17u) {
        if (format == 1u || format == 3u || format == 5u || format == 7u ||
            format == 17u || format == 21u || format == 22u) return 0;
        if (format == 16u && ((fn >= 8u && fn <= 11u) || fn == 33u || fn == 37u || fn == 38u)) return 0;
        if (format == 20u && fn != 32u) return 0;
    }
    if (op == 19u) return 0; /* no COP1X */
    if (op == 16u && format >= 16u && (fn == 1u || fn == 2u || fn == 6u || fn == 8u || fn == 32u)) return 0;
    if (op == 18u && format != 3u && format != 7u && format != 8u) return 0;
    return 1;
}

/* This ownership predicate has no mnemonic strings or generated payload, and
 * survives an extras-disabled build. It prevents VFPU major opcodes from
 * falling through to the unrelated MIPS64 scalar instruction occupying them. */
int cdisasm_mips_allegrex_owns(uint32_t raw)
{
    unsigned op = raw >> 26, fn = raw & 63u, sa = (raw >> 6) & 31u;
    unsigned rd = (raw >> 11) & 31u, rt = (raw >> 16) & 31u, rs = (raw >> 21) & 31u;
    if (op == 24u || op == 25u || op == 27u || op == 50u || op == 52u || op == 53u || op == 54u ||
        op == 55u || op == 58u || op == 60u || op == 61u || op == 62u || op == 63u) return 1;
    if (op == 18u && (rs == 3u || rs == 7u || rs == 8u)) return 1;
    if (op == 0u && sa == 0u && ((rt == 0u && (fn == 22u || fn == 23u)) || fn == 44u || fn == 45u ||
        (rd == 0u && (fn == 28u || fn == 29u || fn == 46u || fn == 47u)))) return 1;
    if (op == 28u && sa == 0u && rd == 0u && rs == 0u && (fn == 36u || fn == 38u || (fn == 0u && rt == 0u))) return 1;
    if (op == 31u && ((fn == 0u || fn == 4u) || (rs == 0u && (fn == 32u || fn == 24u) &&
        (sa == 2u || sa == 3u || sa == 16u || sa == 20u || sa == 24u)))) return 1;
    if (op == 0u && ((fn == 2u && rs == 1u) || (fn == 6u && sa == 1u))) return 1;
    return 0;
}

/* Numeric encoding facts derive from pinned Apache-2.0 Ghidra Allegrex
 * declarations. This decoder does not use SLEIGH, pcode, or text parsing. */
#if USE_EXTRA_OPCODES
typedef struct allegrex_operand_recipe {
    uint8_t kind, shift, bits, size, access, aux;
} allegrex_operand_recipe;
typedef struct allegrex_form {
    uint32_t mask, value;
    uint16_t name, form, effects;
    uint8_t operand_count;
    allegrex_operand_recipe operand[6];
} allegrex_form;
static const allegrex_form allegrex_forms[] = {
#include "generated/mips_allegrex_forms.inc"
};

static int allegrex_enabled(const cdisasm_mips_decode_flags *features)
{
    return features && (features->bitmap[0] & CDISASM_MIPS_DECODE_FLAG_ALLEGREX) != 0;
}
static cdisasm_mips_operand *allegrex_reg(cdisasm_mips_instruction *i, unsigned reg, unsigned size, unsigned access)
{
    cdisasm_mips_operand *o = &i->operand[i->operand_count++];
    o->type = CDISASM_OPERAND_REGISTER;
    o->reg = (cdisasm_mips_reg_id)reg;
    o->size = (uint8_t)size;
    o->access = (uint8_t)access;
    return o;
}
static void allegrex_imm(cdisasm_mips_instruction *i, uint64_t value, unsigned size, unsigned flags)
{
    cdisasm_mips_operand *o = &i->operand[i->operand_count++];
    o->type = CDISASM_OPERAND_IMMEDIATE;
    o->imm = value;
    o->size = (uint8_t)size;
    o->access = CDISASM_OPERAND_ACCESS_READ;
    o->flags = (uint8_t)flags;
}
static int allegrex_lower(uint32_t raw, const allegrex_form *form, cdisasm_mips_instruction *i)
{
    unsigned n;
    for (n = 0; n < form->operand_count; ++n) {
        const allegrex_operand_recipe *r = &form->operand[n];
        uint32_t value = (raw >> r->shift) & ((UINT32_C(1) << r->bits) - 1u);
        cdisasm_mips_operand *o;
        if (r->kind == 1u) {
            unsigned reg;
            if ((r->aux & 8u) != 0u) {
                /* PSP captures include nonaligned matrix origins. Columns
                 * and rows wrap within the physical 4x4 matrix; they are not
                 * reserved register encodings. Preserve every origin bit. */
                if ((r->aux & 2u) != 0u) value ^= 32u;
                reg = CDISASM_MIPS_REG_VFPU_MATRIX(value);
            } else switch (r->aux) {
            case 0: reg = CDISASM_MIPS_REG_VFPU_SCALAR(value); break;
            case 1: reg = CDISASM_MIPS_REG_VFPU_VECTOR(value); break;
            case 2: reg = CDISASM_MIPS_REG_GPR0 + value; break;
            case 3:
                /* Undefined/out-of-range control selectors have no verified
                 * architectural register semantics in the pinned source. */
                if (value > 15u || value == 5u || value == 6u) return 0;
                reg = CDISASM_MIPS_REG_VFPU_CONTROL(value); break;
            case 4: reg = CDISASM_MIPS_REG_VFPU_CONTROL(3u); break;
            case 5:
                value |= (raw & 3u) << 5;
                reg = CDISASM_MIPS_REG_VFPU_SCALAR(value); break;
            case 6:
                value |= (raw & 1u) << 5;
                reg = CDISASM_MIPS_REG_VFPU_VECTOR(value); break;
            default: return 0;
            }
            o = allegrex_reg(i, reg, r->size, r->access);
            if (r->aux == 4u) {
                o->detail.flags = CDISASM_MIPS_OPERAND_DETAIL_HAS_LANE;
                o->detail.lane_index = (uint8_t)value;
                o->detail.element_size = 1u;
            } else if ((r->aux & 8u) != 0u) {
                o->detail.element_size = 4u;
                o->detail.lane_index = (uint8_t)(r->aux >> 4);
            } else if (r->aux == 1u || r->aux == 6u) {
                o->detail.element_size = 4u;
            }
        } else if (r->kind == 2u) {
            uint64_t immediate = value;
            unsigned flags = 0u;
            if (r->aux == 1u) {
                immediate = (uint64_t)(int64_t)(int16_t)value;
                flags = CDISASM_MIPS_OPERAND_FLAG_SIGNED;
            }
            allegrex_imm(i, immediate, r->size, flags);
            if (r->aux == 2u) i->operand[i->operand_count - 1u].detail.element_size = 2u; /* binary16 bit pattern */
        } else if (r->kind == 3u) {
            o = &i->operand[i->operand_count++];
            o->type = CDISASM_OPERAND_MEMORY;
            o->base_reg = (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0 + ((raw >> 21) & 31u));
            o->imm = (uint64_t)(int64_t)(int16_t)(value << 2);
            o->size = r->size;
            o->access = r->access;
            o->flags = CDISASM_MIPS_OPERAND_FLAG_SIGNED | CDISASM_MIPS_OPERAND_FLAG_HAS_DISPLACEMENT;
        } else if (r->kind == 4u) {
            int64_t displacement = (int64_t)(int16_t)value * 4;
            uint64_t target = (uint32_t)(i->address + 4u + displacement);
            allegrex_imm(i, target, 4u, CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS | CDISASM_MIPS_OPERAND_FLAG_PC_RELATIVE);
            i->operand[i->operand_count - 1u].address = (uint64_t)displacement;
            i->branch_target = target;
            i->opcode_groups = CDISASM_GROUP_JUMP | CDISASM_GROUP_RELATIVE_BRANCH | CDISASM_GROUP_CONDITIONAL;
            i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_DELAY_SLOT;
            if (((raw >> 16) & 2u) != 0u) i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_BRANCH_LIKELY;
        } else if (r->kind == 5u) {
            unsigned lane = r->shift;
            unsigned control = (raw >> (lane * 2u)) & 3u;
            if (r->aux) {
                control |= ((raw >> (lane + 8u)) & 1u) << 2;
                if (control == 2u) return -1; /* reserved, unmasked saturation */
            }
            else {
                control |= ((raw >> (lane + 8u)) & 1u) << 2;
                control |= ((raw >> (lane + 12u)) & 1u) << 3;
                control |= ((raw >> (lane + 16u)) & 1u) << 4;
            }
            allegrex_imm(i, control, 1u, 0u);
            o = &i->operand[i->operand_count - 1u];
            o->detail.flags = CDISASM_MIPS_OPERAND_DETAIL_HAS_LANE;
            o->detail.lane_index = (uint8_t)lane;
            o->detail.element_size = 1u;
        } else if (r->kind == 6u) {
            /* The five-bit rotate selector completely specifies which lanes
             * receive sine/cosine and the sign; retain this defined control. */
            allegrex_imm(i, value, 1u, 0u);
        } else return 0;
    }
    return 1;
}

/* Allegrex scalar instructions which precede/reassign standardized SPECIAL
 * forms. Ordinary MIPS-II integer and scalar COP1 decoding remains shared. */
static int allegrex_scalar(uint32_t raw, cdisasm_mips_instruction *i)
{
    unsigned op = raw >> 26, fn = raw & 63u, sa = (raw >> 6) & 31u;
    unsigned rd = (raw >> 11) & 31u, rt = (raw >> 16) & 31u, rs = (raw >> 21) & 31u;
    unsigned id = 0u, form = 41000u;
    if (op == 0u && sa == 0u && rt == 0u && (fn == 22u || fn == 23u)) {
        id = fn == 22u ? CDISASM_MIPS_NAME_CLZ : CDISASM_MIPS_NAME_CLO;
        form += fn;
        allegrex_reg(i, CDISASM_MIPS_REG_GPR0 + rd, 4u, 2u);
        allegrex_reg(i, CDISASM_MIPS_REG_GPR0 + rs, 4u, 1u);
    } else if (op == 0u && sa == 0u && (fn == 44u || fn == 45u || fn == 10u || fn == 11u)) {
        id = fn == 44u ? CDISASM_MIPS_NAME_MAX : fn == 45u ? CDISASM_MIPS_NAME_MIN :
             fn == 10u ? CDISASM_MIPS_NAME_MOVZ : CDISASM_MIPS_NAME_MOVN;
        form += fn;
        allegrex_reg(i, CDISASM_MIPS_REG_GPR0 + rd, 4u, fn < 12u ? 3u : 2u);
        allegrex_reg(i, CDISASM_MIPS_REG_GPR0 + rs, 4u, 1u);
        allegrex_reg(i, CDISASM_MIPS_REG_GPR0 + rt, 4u, 1u);
        if (fn < 12u) i->opcode_groups |= CDISASM_GROUP_CONDITIONAL;
    } else if (op == 0u && sa == 0u && rd == 0u && (fn == 28u || fn == 29u || fn == 46u || fn == 47u)) {
        id = fn == 28u ? CDISASM_MIPS_NAME_MADD : fn == 29u ? CDISASM_MIPS_NAME_MADDU :
             fn == 46u ? CDISASM_MIPS_NAME_MSUB : CDISASM_MIPS_NAME_MSUBU;
        form += fn;
        allegrex_reg(i, CDISASM_MIPS_REG_GPR0 + rs, 4u, 1u);
        allegrex_reg(i, CDISASM_MIPS_REG_GPR0 + rt, 4u, 1u);
        i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_READS_HI | CDISASM_MIPS_INSTRUCTION_FLAG_READS_LO |
                                CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_HI | CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_LO;
    } else if (op == 28u && sa == 0u && rd == 0u && rs == 0u && (fn == 36u || fn == 38u || (fn == 0u && rt == 0u))) {
        id = fn == 36u ? CDISASM_MIPS_NAME_MFIC : fn == 38u ? CDISASM_MIPS_NAME_MTIC : CDISASM_MIPS_NAME_HALT;
        form += 64u + fn;
        if (fn) allegrex_reg(i, CDISASM_MIPS_REG_GPR0 + rt, 4u, fn == 36u ? 2u : 1u);
        i->opcode_groups |= CDISASM_GROUP_PRIVILEGED;
    } else if (op == 31u && rs == 0u && (fn == 32u || fn == 24u) &&
               (sa == 2u || sa == 3u || sa == 16u || sa == 20u || sa == 24u)) {
        id = sa == 2u ? CDISASM_MIPS_NAME_WSBH : sa == 3u ? CDISASM_MIPS_NAME_WSBW :
             sa == 16u ? CDISASM_MIPS_NAME_SEB : sa == 20u ? CDISASM_MIPS_NAME_BITREV : CDISASM_MIPS_NAME_SEH;
        form += 128u + sa + (fn == 24u ? 32u : 0u);
        allegrex_reg(i, CDISASM_MIPS_REG_GPR0 + rd, 4u, 2u);
        allegrex_reg(i, CDISASM_MIPS_REG_GPR0 + rt, 4u, 1u);
    } else if (op == 31u && (fn == 0u || fn == 4u)) {
        unsigned size = fn == 0u ? rd + 1u : rd - sa + 1u;
        if (fn == 0u ? sa + size > 32u : rd < sa) return -1;
        id = fn == 0u ? CDISASM_MIPS_NAME_EXT : CDISASM_MIPS_NAME_INS;
        form += 200u + fn;
        allegrex_reg(i, CDISASM_MIPS_REG_GPR0 + rt, 4u, fn == 0u ? 2u : 3u);
        allegrex_reg(i, CDISASM_MIPS_REG_GPR0 + rs, 4u, 1u);
        allegrex_imm(i, sa, 1u, 0u);
        allegrex_imm(i, size, 1u, 0u);
    } else if (op == 0u && ((fn == 2u && rs == 1u) || (fn == 6u && sa == 1u))) {
        id = fn == 2u ? CDISASM_MIPS_NAME_ROTR : CDISASM_MIPS_NAME_ROTRV;
        form += 220u + fn;
        allegrex_reg(i, CDISASM_MIPS_REG_GPR0 + rd, 4u, 2u);
        allegrex_reg(i, CDISASM_MIPS_REG_GPR0 + rt, 4u, 1u);
        if (fn == 2u) allegrex_imm(i, sa, 1u, 0u);
        else allegrex_reg(i, CDISASM_MIPS_REG_GPR0 + rs, 4u, 1u);
    } else return 0;
    i->name_id = (cdisasm_mips_name_id)id;
    i->form_id = (cdisasm_mips_form_id)form;
    return 1;
}
#endif

cdisasm_status cdisasm_mips_decode_allegrex(uint32_t raw, uint64_t address, cdisasm_mips_mode mode,
                                         cdisasm_mips_revision revision, const cdisasm_mips_decode_flags *features,
                                         cdisasm_mips_instruction *instruction)
{
#if USE_EXTRA_OPCODES
    cdisasm_mips_instruction candidate;
    size_t n;
    int scalar;
    if (!allegrex_enabled(features) || mode != CDISASM_MIPS_MODE_32) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    memset(&candidate, 0, sizeof(candidate));
    candidate.raw_instruction = raw;
    candidate.address = address;
    candidate.opcode_size = 4u;
    candidate.mode = (uint8_t)mode;
    candidate.revision = (uint8_t)revision;
    scalar = allegrex_scalar(raw, &candidate);
    if (scalar < 0) return CDISASM_STATUS_INVALID_INSTRUCTION;
    if (!scalar) {
        for (n = 0u; n < sizeof(allegrex_forms) / sizeof(allegrex_forms[0]); ++n) {
            const allegrex_form *form = &allegrex_forms[n];
            if ((raw & form->mask) != form->value) continue;
            candidate.name_id = form->name;
            candidate.form_id = form->form;
            {
                int lowered = allegrex_lower(raw, form, &candidate);
                if (lowered < 0) return CDISASM_STATUS_INVALID_INSTRUCTION;
                if (!lowered) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
            }
            if ((form->effects & 8u) != 0u) candidate.opcode_groups |= CDISASM_GROUP_CONDITIONAL;
            if ((form->effects & 128u) != 0u) {
                unsigned condition = raw & 15u;
                if (condition == 0u || condition == 4u) {
                    candidate.operand[1].access = candidate.operand[2].access = CDISASM_OPERAND_ACCESS_NONE;
                } else if (condition >= 8u) candidate.operand[2].access = CDISASM_OPERAND_ACCESS_NONE;
            }
            if (form->name == CDISASM_MIPS_NAME_VSYNC || form->name == CDISASM_MIPS_NAME_VFLUSH)
                candidate.instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_MEMORY_BARRIER;
            break;
        }
        if (candidate.name_id == 0u) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    candidate.last_error_id = CDISASM_STATUS_OK;
    *instruction = candidate;
    return CDISASM_STATUS_OK;
#else
    (void)raw; (void)address; (void)mode; (void)revision; (void)features; (void)instruction;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
}

uint64_t cdisasm_mips_allegrex_required_flags(cdisasm_mips_form_id form)
{
#if USE_EXTRA_OPCODES
    if ((form >= 40000u && form < 41000u) || (form >= 41000u && form < 41300u))
        return CDISASM_MIPS_DECODE_FLAG_ALLEGREX;
#else
    (void)form;
#endif
    return 0;
}

#if USE_EXTRA_OPCODES
static void allegrex_effect(cdisasm_mips_register_effect *out, size_t *count, unsigned reg, unsigned access)
{
    size_t n;
    for (n = 0; n < *count; ++n) if (out[n].reg == reg) {
        out[n].access |= (uint8_t)access;
        return;
    }
    if (*count >= 64u) return;
    out[*count].reg = (cdisasm_mips_reg_id)reg;
    out[*count].access = (uint8_t)access;
    out[*count].size = 4u;
    ++*count;
}
/* Expand overlapping vector/matrix views to the 128 physical scalar cells. */
static void allegrex_expand(const cdisasm_mips_operand *o, cdisasm_mips_register_effect *out, size_t *count)
{
    unsigned encoded, m, x, y, cols, rows, row, col, size;
    if (o->reg >= CDISASM_MIPS_REG_VFPU_SCALAR_FIRST && o->reg <= CDISASM_MIPS_REG_VFPU_SCALAR_LAST) {
        allegrex_effect(out, count, o->reg, o->access);
        return;
    }
    if (o->reg >= CDISASM_MIPS_REG_VFPU_VECTOR_FIRST && o->reg <= CDISASM_MIPS_REG_VFPU_VECTOR_LAST) {
        encoded = o->reg - CDISASM_MIPS_REG_VFPU_VECTOR_FIRST;
        size = o->size / 4u;
        m = (encoded >> 2) & 7u;
        x = encoded & 3u;
        y = (encoded & 64u) ? (size == 3u ? 1u : size == 2u ? 2u : 0u) : 0u;
        cols = 1u; rows = size;
    } else if (o->reg >= CDISASM_MIPS_REG_VFPU_MATRIX_FIRST && o->reg <= CDISASM_MIPS_REG_VFPU_MATRIX_LAST) {
        encoded = o->reg - CDISASM_MIPS_REG_VFPU_MATRIX_FIRST;
        size = o->detail.lane_index;
        m = (encoded >> 2) & 7u;
        x = encoded & 3u;
        y = (encoded & 64u) ? (size == 3u ? 1u : 2u) : 0u;
        cols = rows = size;
    } else return;
    for (row = 0u; row < rows; ++row) for (col = 0u; col < cols; ++col) {
        unsigned physical_x = (x + col) & 3u, physical_y = (y + row) & 3u;
        if (encoded & 32u) {
            unsigned temporary = physical_x; physical_x = physical_y; physical_y = temporary;
        }
        allegrex_effect(out, count, CDISASM_MIPS_REG_VFPU_SCALAR((m << 2) | physical_x | (physical_y << 5)), o->access);
    }
}
#endif

size_t cdisasm_mips_allegrex_effects(const cdisasm_mips_instruction *instruction,
                                   cdisasm_mips_register_effect *effects, size_t capacity)
{
#if USE_EXTRA_OPCODES
    cdisasm_mips_register_effect result[64] = {{0}};
    size_t count = 0, n;
    unsigned control = 0;
    if (instruction->form_id >= 41000u && instruction->form_id < 41300u) {
        if (instruction->name_id == CDISASM_MIPS_NAME_MFIC || instruction->name_id == CDISASM_MIPS_NAME_MTIC)
            allegrex_effect(result, &count, CDISASM_MIPS_REG_ALLEGREX_IC, instruction->name_id == CDISASM_MIPS_NAME_MFIC ? 1u : 2u);
        if (effects && capacity >= count) memcpy(effects, result, count * sizeof(*effects));
        return count;
    }
    if (instruction->form_id < 40000u || instruction->form_id >= 41000u) return 0;
    for (n = 0u; n < instruction->operand_count; ++n) allegrex_expand(&instruction->operand[n], result, &count);
    for (n = 0u; n < sizeof(allegrex_forms)/sizeof(allegrex_forms[0]); ++n)
        if (allegrex_forms[n].form == instruction->form_id) { control = allegrex_forms[n].effects; break; }
    if (control & 128u) {
        unsigned condition = instruction->raw_instruction & 15u;
        if (condition == 0u || condition == 4u) control &= ~3u;
        else if (condition >= 8u) control &= ~2u;
    }
    for (n = 0u; n < 3u; ++n) {
        if (control & (1u << (4u + n))) allegrex_effect(result, &count, CDISASM_MIPS_REG_VFPU_CONTROL(n), 2u);
        if (control & (1u << n)) allegrex_effect(result, &count, CDISASM_MIPS_REG_VFPU_CONTROL(n), 3u);
    }
    if (control & 8u) allegrex_effect(result, &count, CDISASM_MIPS_REG_VFPU_CONTROL(3u), 1u);
    if (control & 128u) allegrex_effect(result, &count, CDISASM_MIPS_REG_VFPU_CONTROL(3u), 2u);
    if (control & 256u) for (n = 8u; n < 16u; ++n)
        allegrex_effect(result, &count, CDISASM_MIPS_REG_VFPU_CONTROL(n), (control & 512u) ? 2u : 3u);
    if (effects && capacity >= count) memcpy(effects, result, count * sizeof(*effects));
    return count;
#else
    (void)instruction; (void)effects; (void)capacity;
    return 0;
#endif
}
