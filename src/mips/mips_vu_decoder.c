/* Copyright (c) 2026 hors<horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 * Original typed Sony VU0/VU1 decoder. Manufacturer numeric facts and source
 * provenance are recorded in generated/mips_vu_manifest.json.
 */
#include "mips_vu_internal.h"
#include <string.h>

int cdisasm_mips_vu_macro_owns(uint32_t raw)
{
    unsigned op = raw >> 26;
    return op == 18u || op == 54u || op == 62u;
}

#if USE_EXTRA_OPCODES && (USE_MIPS_R5900_VU0 || USE_MIPS_R5900_VU1)
#include "generated/mips_vu_forms.inc"

const vu_form *cdisasm_mips_vu_form(cdisasm_mips_form_id form)
{
    size_t n;
    if (form >= 63500u && form < 64500u) form = (uint16_t)(form - 1000u);
    for (n = 0; n < sizeof(vu_forms) / sizeof(vu_forms[0]); ++n)
        if (vu_forms[n].form == form) return &vu_forms[n];
    return NULL;
}

uint64_t cdisasm_mips_vu_required_flags(cdisasm_mips_form_id form)
{
    const vu_form *f = cdisasm_mips_vu_form(form);
    uint64_t unit = (form >= 63500u && form < 64500u) || form == 64999u ?
        CDISASM_MIPS_DECODE_FLAG_R5900_VU1 : CDISASM_MIPS_DECODE_FLAG_R5900_VU0;
    uint64_t encoding;
    if (form == 64998u || form == 64999u)
        return CDISASM_MIPS_DECODE_FLAG_R5900 | unit | CDISASM_MIPS_DECODE_FLAG_VU_LOWER_LOI;
    if (!f) return 0;
    encoding = f->kind == 1u ? CDISASM_MIPS_DECODE_FLAG_VU_UPPER :
               f->kind == 2u ? CDISASM_MIPS_DECODE_FLAG_VU_LOWER : 0;
    return CDISASM_MIPS_DECODE_FLAG_R5900 | unit | encoding;
}

static void vu_reg(cdisasm_mips_instruction *i, unsigned reg, unsigned size, unsigned access)
{
    cdisasm_mips_operand *o = &i->operand[i->operand_count++];
    o->type = CDISASM_OPERAND_REGISTER;
    o->reg = (uint16_t)reg;
    o->size = (uint8_t)size;
    o->access = (uint8_t)access;
}

static void vu_vector(cdisasm_mips_instruction *i, unsigned reg, unsigned mask, unsigned access)
{
    vu_reg(i, reg, 16u, access);
    i->operand[i->operand_count - 1u].detail.flags = CDISASM_MIPS_OPERAND_DETAIL_COMPONENT_MASK;
    i->operand[i->operand_count - 1u].detail.element_size = 4u;
    i->operand[i->operand_count - 1u].detail.lane_index = (uint8_t)mask;
}

static void vu_lane(cdisasm_mips_instruction *i, unsigned reg, unsigned lane, unsigned access)
{
    vu_reg(i, reg, 4u, access);
    i->operand[i->operand_count - 1u].detail.flags = CDISASM_MIPS_OPERAND_DETAIL_HAS_LANE;
    i->operand[i->operand_count - 1u].detail.element_size = 4u;
    i->operand[i->operand_count - 1u].detail.lane_index = (uint8_t)lane;
}

static void vu_imm(cdisasm_mips_instruction *i, uint64_t value, unsigned size, int is_signed)
{
    cdisasm_mips_operand *o = &i->operand[i->operand_count++];
    o->type = CDISASM_OPERAND_IMMEDIATE;
    o->imm = value;
    o->size = (uint8_t)size;
    o->access = CDISASM_OPERAND_ACCESS_READ;
    if (is_signed) o->flags = CDISASM_MIPS_OPERAND_FLAG_SIGNED;
}

static int64_t vu_signed(unsigned value, unsigned bits)
{
    return (int64_t)(value ^ (1u << (bits - 1u))) - (int64_t)(1u << (bits - 1u));
}

static unsigned vu_control(unsigned selector)
{
    if (selector < 16u) return CDISASM_MIPS_REG_VU_VI_FIRST + selector;
    switch (selector) {
        case 16: return CDISASM_MIPS_REG_VU_STATUS;
        case 17: return CDISASM_MIPS_REG_VU_MAC;
        case 18: return CDISASM_MIPS_REG_VU_CLIP;
        case 20: return CDISASM_MIPS_REG_VU_R;
        case 21: return CDISASM_MIPS_REG_VU_I;
        case 22: return CDISASM_MIPS_REG_VU_Q;
        case 26: return CDISASM_MIPS_REG_VU_TPC;
        case 27: return CDISASM_MIPS_REG_VU_CMSAR0;
        case 28: return CDISASM_MIPS_REG_VU_FBRST;
        case 29: return CDISASM_MIPS_REG_VU_VPU_STAT;
        case 31: return CDISASM_MIPS_REG_VU_CMSAR1;
        default: return CDISASM_MIPS_REG_NONE;
    }
}

static void vu_target(cdisasm_mips_instruction *i, int64_t displacement, unsigned step)
{
    cdisasm_mips_operand *o;
    i->branch_target = i->address + step + (uint64_t)displacement;
    vu_imm(i, i->branch_target, 8u, 0);
    o = &i->operand[i->operand_count - 1u];
    o->address = (uint64_t)displacement;
    o->flags = CDISASM_MIPS_OPERAND_FLAG_RELATIVE | CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS;
}

static cdisasm_status vu_lower(const vu_form *f, uint32_t raw, uint64_t address,
                              unsigned unit, cdisasm_mips_mode mode, cdisasm_mips_revision revision,
                              const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *out)
{
    cdisasm_mips_instruction i;
    unsigned ft = (raw >> 16) & 31u, fs = (raw >> 11) & 31u, fd = (raw >> 6) & 31u;
    unsigned mask = (raw >> 21) & 15u, fsf = (raw >> 21) & 3u, ftf = (raw >> 23) & 3u;
    unsigned write_acc = f->recipe == VU_ACC_FS_FT || f->recipe == VU_ACC_FS_FT_BC ||
                         f->recipe == VU_ACC_FS_I || f->recipe == VU_ACC_FS_Q;
    unsigned acc_access = (f->properties & VU_PROP_ACC_READ) ?
        CDISASM_OPERAND_ACCESS_READ_WRITE : CDISASM_OPERAND_ACCESS_WRITE;
    cdisasm_mips_operand *o;
    (void)unit;
    memset(&i, 0, sizeof(i));
    i.address = address; i.raw_instruction = raw; i.opcode_size = 4u;
    i.mode = (uint8_t)mode; i.revision = (uint8_t)revision; i.name_id = f->name;
    i.form_id = (uint16_t)(f->form + (unit && f->kind ? 1000u : 0u));
    if (features && (features->bitmap[0] & CDISASM_MIPS_DECODE_FLAG_FPR32))
        i.instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_FPR32;
    if (f->properties & VU_PROP_FLOAT) i.instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_FLOATING_POINT;
    if (f->properties & VU_PROP_BRANCH) {
        i.instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_DELAY_SLOT;
        i.opcode_groups = CDISASM_GROUP_JUMP;
        if (f->recipe != VU_INDIRECT) i.opcode_groups |= CDISASM_GROUP_RELATIVE_BRANCH;
    }
    if (f->properties & VU_PROP_CONDITIONAL) i.opcode_groups |= CDISASM_GROUP_CONDITIONAL;
    if (f->properties & VU_PROP_CALL) i.opcode_groups |= CDISASM_GROUP_CALL;
    if (f->properties & VU_PROP_LIKELY) i.instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_BRANCH_LIKELY;
#define VF(r_, m_, a_) vu_vector(&i, CDISASM_MIPS_REG_VU_VF_FIRST + (r_), (m_), (a_))
#define VI(r_, a_) do { if ((r_) >= 16u) return CDISASM_STATUS_INVALID_INSTRUCTION; vu_reg(&i, CDISASM_MIPS_REG_VU_VI_FIRST + (r_), 2u, (a_)); } while (0)
#define READ CDISASM_OPERAND_ACCESS_READ
#define WRITE CDISASM_OPERAND_ACCESS_WRITE
    switch (f->recipe) {
        case VU_NONE: break;
        case VU_FD_FS_FT: case VU_FD_FS_FT_BC: case VU_FD_FS_I: case VU_FD_FS_Q:
        case VU_ACC_FS_FT: case VU_ACC_FS_FT_BC: case VU_ACC_FS_I: case VU_ACC_FS_Q:
            if (write_acc) vu_vector(&i, CDISASM_MIPS_REG_VU_ACC, mask, acc_access);
            else VF(fd, mask, WRITE);
            VF(fs, mask, READ);
            if (f->recipe == VU_FD_FS_FT_BC || f->recipe == VU_ACC_FS_FT_BC)
                vu_lane(&i, CDISASM_MIPS_REG_VU_VF_FIRST + ft, raw & 3u, READ);
            else if (f->recipe == VU_FD_FS_I || f->recipe == VU_ACC_FS_I) vu_reg(&i, CDISASM_MIPS_REG_VU_I, 4u, READ);
            else if (f->recipe == VU_FD_FS_Q || f->recipe == VU_ACC_FS_Q) vu_reg(&i, CDISASM_MIPS_REG_VU_Q, 4u, READ);
            else VF(ft, mask, READ);
            break;
        case VU_FT_FS:
            VF(ft, mask, WRITE);
            VF(fs, (f->name == CDISASM_MIPS_NAME_MR32 || f->name == CDISASM_MIPS_NAME_VMR32) ?
                ((mask >> 1) | (mask << 3)) & 15u : mask, READ);
            break;
        case VU_CLIP: VF(fs, 14u, READ); vu_lane(&i, CDISASM_MIPS_REG_VU_VF_FIRST + ft, 3u, READ); break;
        case VU_ID_IS_IT: VI(fd, WRITE); VI(fs, READ); VI(ft, READ); break;
        case VU_IT_IS_IMM5: VI(ft, WRITE); VI(fs, READ); vu_imm(&i, (uint64_t)vu_signed(fd, 5u), 1u, 1); break;
        case VU_IT_IS_IMM15: VI(ft, WRITE); VI(fs, READ); vu_imm(&i, (raw & 0x7ffu) | ((raw >> 10) & 0x7800u), 2u, 0); break;
        case VU_FT_IS: VF(ft, mask, WRITE); VI(fs, READ); break;
        case VU_IT_FSF: VI(ft, WRITE); vu_lane(&i, CDISASM_MIPS_REG_VU_VF_FIRST + fs, fsf, READ); break;
        case VU_Q_FSF_FTF: case VU_Q_FTF:
            vu_reg(&i, CDISASM_MIPS_REG_VU_Q, 4u, WRITE);
            if (f->recipe == VU_Q_FSF_FTF) vu_lane(&i, CDISASM_MIPS_REG_VU_VF_FIRST + fs, fsf, READ);
            vu_lane(&i, CDISASM_MIPS_REG_VU_VF_FIRST + ft, ftf, READ); break;
        case VU_FT_R:
            VF(ft, mask, WRITE);
            vu_reg(&i, CDISASM_MIPS_REG_VU_R, 4u,
                f->name == CDISASM_MIPS_NAME_RNEXT || f->name == CDISASM_MIPS_NAME_VRNEXT ? CDISASM_OPERAND_ACCESS_READ_WRITE : READ);
            break;
        case VU_R_FSF:
            vu_reg(&i, CDISASM_MIPS_REG_VU_R, 4u,
                f->name == CDISASM_MIPS_NAME_RXOR || f->name == CDISASM_MIPS_NAME_VRXOR ? CDISASM_OPERAND_ACCESS_READ_WRITE : WRITE);
            vu_lane(&i, CDISASM_MIPS_REG_VU_VF_FIRST + fs, fsf, READ); break;
        case VU_P_FSF: case VU_P_FS:
            vu_reg(&i, CDISASM_MIPS_REG_VU_P, 4u, WRITE);
            if (f->recipe == VU_P_FSF) vu_lane(&i, CDISASM_MIPS_REG_VU_VF_FIRST + fs, fsf, READ);
            else VF(fs, (f->name == CDISASM_MIPS_NAME_EATANXY) ? 12u :
                           (f->name == CDISASM_MIPS_NAME_EATANXZ) ? 10u :
                           (f->name == CDISASM_MIPS_NAME_ESUM) ? 15u : 14u, READ);
            break;
        case VU_FT_P: VF(ft, mask, WRITE); vu_reg(&i, CDISASM_MIPS_REG_VU_P, 4u, READ); break;
        case VU_IT: VI(ft, WRITE); break;
        case VU_IS: VI(fs, READ); break;
        case VU_IT_IS: VI(ft, WRITE); VI(fs, READ); break;
        case VU_VI1_IMM24:
            vu_reg(&i, CDISASM_MIPS_REG_VU_VI_FIRST + 1u, 2u, WRITE);
            vu_imm(&i, raw & 0xffffffu, 4u, 0); break;
        case VU_IMM24: vu_imm(&i, raw & 0xffffffu, 4u, 0); break;
        case VU_IT_IMM12: VI(ft, WRITE); vu_imm(&i, (raw & 0x7ffu) | ((raw >> 10) & 0x800u), 2u, 0); break;
        case VU_IMM12: vu_imm(&i, (raw & 0x7ffu) | ((raw >> 10) & 0x800u), 2u, 0); break;
        case VU_BRANCH:
            if (f->name == CDISASM_MIPS_NAME_BAL) VI(ft, WRITE);
            else if (f->name == CDISASM_MIPS_NAME_IBEQ || f->name == CDISASM_MIPS_NAME_IBNE) { VI(ft, READ); VI(fs, READ); }
            else if (f->name != CDISASM_MIPS_NAME_B) VI(fs, READ);
            vu_target(&i, vu_signed(raw & 0x7ffu, 11u) * 8, 8u); break;
        case VU_INDIRECT:
            if (f->name == CDISASM_MIPS_NAME_JALR) VI(ft, WRITE);
            VI(fs, READ);
            if (fs == 15u && f->name == CDISASM_MIPS_NAME_JR) i.opcode_groups |= CDISASM_GROUP_RETURN;
            break;
        case VU_LOCAL_MEM:
            {
                int integer = f->name == CDISASM_MIPS_NAME_ILW || f->name == CDISASM_MIPS_NAME_ISW ||
                    f->name == CDISASM_MIPS_NAME_ILWR || f->name == CDISASM_MIPS_NAME_ISWR ||
                    f->name == CDISASM_MIPS_NAME_VILWR || f->name == CDISASM_MIPS_NAME_VISWR;
                int store = (f->properties & VU_PROP_STORE) != 0;
                unsigned base = store && !integer ? ft : fs;
                unsigned data = store && !integer ? fs : ft;
                int64_t displacement = (f->kind == 2u && (raw >> 25) < 64u) ? vu_signed(raw & 0x7ffu, 11u) * 16 : 0;
                if (base >= 16u || (integer && data >= 16u)) return CDISASM_STATUS_INVALID_INSTRUCTION;
                if (integer && !store && (!mask || (mask & (mask - 1u)))) return CDISASM_STATUS_INVALID_INSTRUCTION;
                if (integer) VI(data, store ? READ : WRITE); else VF(data, mask, store ? READ : WRITE);
                o = &i.operand[i.operand_count++]; o->type = CDISASM_OPERAND_MEMORY;
                o->index_reg = (uint16_t)(CDISASM_MIPS_REG_VU_VI_FIRST + base);
                o->size = (uint8_t)(integer && !store ? 4u : 16u);
                o->access = (uint8_t)(store ? WRITE : READ);
                o->flags = CDISASM_MIPS_OPERAND_FLAG_SIGNED | CDISASM_MIPS_OPERAND_FLAG_HAS_DISPLACEMENT;
                o->detail.flags = CDISASM_MIPS_OPERAND_DETAIL_INDEX_SCALED;
                o->detail.index_shift = 4u; o->detail.element_size = 4u; o->detail.reserved = (uint16_t)mask;
                if (f->properties & VU_PROP_PRE) displacement -= 16;
                if (integer && !store) {
                    unsigned lane = mask == 8u ? 0u : mask == 4u ? 1u : mask == 2u ? 2u : 3u;
                    displacement += (int64_t)lane * 4;
                }
                o->imm = (uint64_t)displacement;
            }
            break;
        case VU_COP_TRANSFER:
            {
                unsigned selector = fs, reg, size;
                unsigned rs = (raw >> 21) & 31u;
                int to_vu = rs == 5u || rs == 6u, quad = rs == 1u || rs == 5u;
                reg = quad ? CDISASM_MIPS_REG_VU_VF_FIRST + selector : vu_control(selector);
                if (!reg) return CDISASM_STATUS_INVALID_INSTRUCTION;
                size = quad ? 16u : selector < 16u ? 2u : 4u;
                vu_reg(&i, CDISASM_MIPS_REG_GPR0 + ft, quad ? 16u : to_vu ? 4u : 8u, to_vu ? READ : WRITE);
                /* STATUS preserves its low six current flags (Sony p201).
                 * CMSAR1 writes may be ignored while VU1 is running. */
                vu_reg(&i, reg, size, to_vu && (reg == CDISASM_MIPS_REG_VU_STATUS ||
                    reg == CDISASM_MIPS_REG_VU_CMSAR1) ? CDISASM_OPERAND_ACCESS_READ_WRITE : to_vu ? WRITE : READ);
            }
            break;
        case VU_MAIN_MEM:
            {
                int store = (f->properties & VU_PROP_STORE) != 0;
                unsigned base = (raw >> 21) & 31u;
                int64_t displacement = vu_signed(raw & 65535u, 16u);
                VF(ft, 15u, store ? READ : WRITE);
                o = &i.operand[i.operand_count++]; o->type = CDISASM_OPERAND_MEMORY; o->size = 16u;
                o->base_reg = (uint16_t)(CDISASM_MIPS_REG_GPR0 + base); o->imm = (uint64_t)displacement;
                o->flags = CDISASM_MIPS_OPERAND_FLAG_SIGNED | CDISASM_MIPS_OPERAND_FLAG_HAS_DISPLACEMENT;
                o->access = (uint8_t)(store ? WRITE : READ);
                if (!base) { o->address = (uint64_t)displacement & ~UINT64_C(15); o->flags |= CDISASM_MIPS_OPERAND_FLAG_ABSOLUTE | CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS; }
            }
            break;
        case VU_MACRO_BRANCH: vu_target(&i, vu_signed(raw & 65535u, 16u) * 4, 4u); break;
        case VU_CALLMS:
            vu_imm(&i, ((raw >> 6) & 32767u) * 8u, 4u, 0);
            i.operand[0].address = i.operand[0].imm;
            i.operand[0].flags = CDISASM_MIPS_OPERAND_FLAG_ABSOLUTE | CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS;
            break;
        case VU_CALLMSR: vu_reg(&i, CDISASM_MIPS_REG_VU_CMSAR0, 4u, READ); break;
        default: return CDISASM_STATUS_INTERNAL_ERROR;
    }
#undef VF
#undef VI
#undef READ
#undef WRITE
    *out = i;
    return CDISASM_STATUS_OK;
}

cdisasm_status cdisasm_mips_decode_vu_word(uint32_t raw, uint64_t address, cdisasm_mips_encoding encoding,
    uint32_t unit, cdisasm_mips_mode mode, cdisasm_mips_revision revision,
    const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *instruction)
{
    uint64_t active = features ? features->bitmap[0] : 0;
    uint64_t unit_flag = unit ? CDISASM_MIPS_DECODE_FLAG_R5900_VU1 : CDISASM_MIPS_DECODE_FLAG_R5900_VU0;
    unsigned kind;
    size_t n;
    if (unit > 1u || mode != CDISASM_MIPS_MODE_64 || revision != CDISASM_MIPS_REVISION_III)
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    if (!(active & unit_flag) || !(active & CDISASM_MIPS_DECODE_FLAG_R5900)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    if (encoding == CDISASM_MIPS_ENCODING_VU_LOWER_LOI) {
        cdisasm_mips_instruction i;
        memset(&i, 0, sizeof(i));
        i.address = address; i.raw_instruction = raw; i.opcode_size = 4u; i.mode = (uint8_t)mode; i.revision = (uint8_t)revision;
        i.name_id = CDISASM_MIPS_NAME_LOI; i.form_id = (uint16_t)(64998u + unit);
        i.instruction_flags = CDISASM_MIPS_INSTRUCTION_FLAG_FLOATING_POINT;
        if (active & CDISASM_MIPS_DECODE_FLAG_FPR32) i.instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_FPR32;
        vu_reg(&i, CDISASM_MIPS_REG_VU_I, 4u, CDISASM_OPERAND_ACCESS_WRITE);
        i.operand[0].flags = CDISASM_OPERAND_FLAG_IMPLICIT;
        vu_imm(&i, raw, 4u, 0);
        *instruction = i;
        return CDISASM_STATUS_OK;
    }
    kind = encoding == CDISASM_MIPS_ENCODING_VU_UPPER ? 1u : encoding == CDISASM_MIPS_ENCODING_VU_LOWER ? 2u : 0u;
    if (!kind) return CDISASM_STATUS_INVALID_ARGUMENT;
    for (n = 0; n < sizeof(vu_forms) / sizeof(vu_forms[0]); ++n) {
        const vu_form *f = &vu_forms[n];
        if (f->kind != kind || (raw & f->mask) != f->value) continue;
        if (!unit && (f->properties & VU_PROP_UNIT1_ONLY)) return CDISASM_STATUS_INVALID_INSTRUCTION;
        return vu_lower(f, raw, address, unit, mode, revision, features, instruction);
    }
    return CDISASM_STATUS_INVALID_INSTRUCTION;
}

cdisasm_status cdisasm_mips_decode_vu_macro(uint32_t raw, uint64_t address, cdisasm_mips_mode mode,
    cdisasm_mips_revision revision, const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *instruction)
{
    size_t n;
    uint64_t active = features ? features->bitmap[0] : 0;
    if (!(active & CDISASM_MIPS_DECODE_FLAG_R5900_VU0) || !(active & CDISASM_MIPS_DECODE_FLAG_R5900))
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    if (mode != CDISASM_MIPS_MODE_64 || revision != CDISASM_MIPS_REVISION_III) return CDISASM_STATUS_INVALID_INSTRUCTION;
    for (n = 0; n < sizeof(vu_forms) / sizeof(vu_forms[0]); ++n) {
        const vu_form *f = &vu_forms[n];
        if (!f->kind && (raw & f->mask) == f->value) return vu_lower(f, raw, address, 0u, mode, revision, features, instruction);
    }
    return cdisasm_mips_vu_macro_owns(raw) ? CDISASM_STATUS_INVALID_INSTRUCTION : CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}

size_t cdisasm_mips_vu_effects(const cdisasm_mips_instruction *instruction,
                             cdisasm_mips_register_effect *effects, size_t capacity)
{
    const vu_form *f = instruction ? cdisasm_mips_vu_form(instruction->form_id) : NULL;
    size_t count = 0, n;
    if (!f) return 0;
    for (n = 0; n < f->effect_count; ++n) {
        if (count < capacity) {
            memset(&effects[count], 0, sizeof(effects[count]));
            effects[count].reg = f->effect[n].reg;
            effects[count].access = f->effect[n].access;
            effects[count].size = f->effect[n].size;
        }
        ++count;
    }
    if (f->properties & (VU_PROP_PRE | VU_PROP_POST)) {
        const cdisasm_mips_operand *memory = &instruction->operand[instruction->operand_count - 1u];
        if (count < capacity) {
            memset(&effects[count], 0, sizeof(effects[count]));
            effects[count].reg = memory->index_reg;
            effects[count].access = CDISASM_OPERAND_ACCESS_WRITE;
            effects[count].size = 2u;
        }
        ++count;
    }
    if (f->recipe == VU_COP_TRANSFER) {
        unsigned rs = (instruction->raw_instruction >> 21) & 31u;
        unsigned selector = (instruction->raw_instruction >> 11) & 31u;
        /* Interlocked transfers observe microprogram completion. FBRST can
         * reset/break either VU, and CMSAR1 can launch VU1 (Sony pp201-204,
         * 234-235). Keep unknown data/run-state transitions conservative. */
        unsigned access = rs == 6u && (selector == 28u || selector == 31u) ?
            CDISASM_OPERAND_ACCESS_READ_WRITE : (instruction->raw_instruction & 1u) ?
            CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_NONE;
        if (access) {
            if (count < capacity) {
                memset(&effects[count], 0, sizeof(effects[count]));
                effects[count].reg = CDISASM_MIPS_REG_VU_VPU_STAT;
                effects[count].access = (uint8_t)access;
                effects[count].size = 4u;
            }
            ++count;
        }
    }
    if (f->kind == 1u && (instruction->raw_instruction & UINT32_C(0x18000000))) {
        if (count < capacity) {
            memset(&effects[count], 0, sizeof(effects[count]));
            effects[count].reg = CDISASM_MIPS_REG_VU_FBRST;
            effects[count].access = CDISASM_OPERAND_ACCESS_READ;
            effects[count].size = 4u;
        }
        ++count;
    }
    /* E ends the microprogram after its delay slot; D/T halt it. These bits
     * update the observable VPU-STAT operation state (Sony pp63-64/203-204). */
    if (f->kind == 1u && (instruction->raw_instruction & UINT32_C(0x58000000))) {
        if (count < capacity) {
            memset(&effects[count], 0, sizeof(effects[count]));
            effects[count].reg = CDISASM_MIPS_REG_VU_VPU_STAT;
            effects[count].access = CDISASM_OPERAND_ACCESS_READ_WRITE;
            effects[count].size = 4u;
        }
        ++count;
        /* E stores the position after its delay slot; enabled D/T store the
         * stop/restart position. With D/T alone the old TPC may survive when
         * the corresponding FBRST enable is clear (Sony pp54/63-64/362). */
        if (count < capacity) {
            memset(&effects[count], 0, sizeof(effects[count]));
            effects[count].reg = CDISASM_MIPS_REG_VU_TPC;
            effects[count].access = (instruction->raw_instruction & UINT32_C(0x40000000)) ?
                CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ_WRITE;
            effects[count].size = 4u;
        }
        ++count;
    }
    return count;
}

#else
const vu_form *cdisasm_mips_vu_form(cdisasm_mips_form_id form) { (void)form; return NULL; }
uint64_t cdisasm_mips_vu_required_flags(cdisasm_mips_form_id form) { (void)form; return 0; }
size_t cdisasm_mips_vu_effects(const cdisasm_mips_instruction *i, cdisasm_mips_register_effect *e, size_t c)
{ (void)i; (void)e; (void)c; return 0; }
cdisasm_status cdisasm_mips_decode_vu_word(uint32_t r, uint64_t a, cdisasm_mips_encoding e, uint32_t u,
    cdisasm_mips_mode m, cdisasm_mips_revision v, const cdisasm_mips_decode_flags *f, cdisasm_mips_instruction *i)
{ (void)r; (void)a; (void)e; (void)u; (void)m; (void)v; (void)f; (void)i; return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION; }
cdisasm_status cdisasm_mips_decode_vu_macro(uint32_t r, uint64_t a, cdisasm_mips_mode m,
    cdisasm_mips_revision v, const cdisasm_mips_decode_flags *f, cdisasm_mips_instruction *i)
{ (void)r; (void)a; (void)m; (void)v; (void)f; (void)i; return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION; }
#endif
