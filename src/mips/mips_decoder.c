#include "mips_decoder.h"

#include <string.h>

/* Native fixed-width MIPS decoder.  The encoding constants are architectural
 * bit-field values; no external disassembler is linked or called. */

static int mips_modern(cdisasm_mips_revision r) { return (unsigned)r >= 32u; }
static int mips_r2(cdisasm_mips_revision r)
{
    return (unsigned)r == 33u || (unsigned)r == 34u || (unsigned)r == 36u || (unsigned)r == 37u ||
           (unsigned)r == 65u || (unsigned)r == 66u || (unsigned)r == 68u || (unsigned)r == 69u;
}
static int mips_r6(cdisasm_mips_revision r) { return (unsigned)r == 37u || (unsigned)r == 69u; }
static int mips_64(cdisasm_mips_mode mode) { return mode == CDISASM_MIPS_MODE_64; }
static uint8_t mips_gpr_size(cdisasm_mips_mode mode) { return mips_64(mode) ? 8u : 4u; }
static int mips_ii(cdisasm_mips_revision r) { return (unsigned)r >= 2u; }
static int mips_iii(cdisasm_mips_revision r) { return (unsigned)r >= 3u; }
static int mips_iv(cdisasm_mips_revision r) { return (unsigned)r >= 4u; }
static int mips_cop1x_revision(cdisasm_mips_revision r)
{
    return !mips_r6(r) && ((unsigned)r == 4u || (unsigned)r == 5u || (unsigned)r >= 64u || mips_r2(r));
}
static int mips_ps_revision(cdisasm_mips_revision r)
{
    return !mips_r6(r) && ((unsigned)r == 5u || mips_r2(r) || (unsigned)r >= 64u);
}
static int mips_paired(cdisasm_mips_revision r, const cdisasm_mips_decode_flags *f)
{
    return (unsigned)r <= 2u || r == CDISASM_MIPS_REVISION_32R1 ||
           (f != NULL && (f->bitmap[0] & CDISASM_MIPS_DECODE_FLAG_FPR32) != 0u);
}
static int mips_feature(const cdisasm_mips_decode_flags *f, unsigned bit)
{
    return f != NULL && (f->bitmap[bit / 64u] & (UINT64_C(1) << (bit % 64u))) != 0u;
}
static uint64_t mips_address(cdisasm_mips_mode mode, uint64_t address)
{
    return mips_64(mode) ? address : (uint64_t)(uint32_t)address;
}
static int64_t mips_sign(uint32_t value, unsigned bits)
{
    uint32_t sign = UINT32_C(1) << (bits - 1u);
    return (int64_t)(value ^ sign) - (int64_t)sign;
}
static uint64_t mips_relative(cdisasm_mips_mode mode, uint64_t pc, uint32_t value, unsigned bits)
{
    return mips_address(mode, pc + UINT64_C(4) + (uint64_t)(mips_sign(value, bits) * INT64_C(4)));
}
static void mips_reg(cdisasm_mips_instruction *i, uint16_t reg, uint8_t size, cdisasm_operand_access access)
{
    cdisasm_mips_operand *o = &i->operand[i->operand_count++];
    o->type = CDISASM_OPERAND_REGISTER;
    o->reg = reg;
    o->size = size;
    o->access = (uint8_t)access;
}
static void mips_gpr(cdisasm_mips_instruction *i, unsigned reg, uint8_t size, cdisasm_operand_access access)
{
    mips_reg(i, (uint16_t)(CDISASM_MIPS_REG_GPR0 + reg), size, access);
}
static void mips_imm(cdisasm_mips_instruction *i, uint64_t value, uint8_t size, uint8_t flags)
{
    cdisasm_mips_operand *o = &i->operand[i->operand_count++];
    o->type = CDISASM_OPERAND_IMMEDIATE;
    o->imm = value;
    o->size = size;
    o->access = CDISASM_OPERAND_ACCESS_READ;
    o->flags = flags;
}
static void mips_target(cdisasm_mips_instruction *i, uint64_t target, int relative)
{
    cdisasm_mips_operand *o = &i->operand[i->operand_count++];
    o->type = CDISASM_OPERAND_IMMEDIATE;
    o->imm = target;
    o->address = relative ? (i->mode == CDISASM_MIPS_MODE_32
                                ? (uint64_t)mips_sign((uint32_t)target - (uint32_t)(i->address + UINT64_C(4)), 32u)
                                : target - (i->address + UINT64_C(4)))
                          : target;
    o->size = i->mode == CDISASM_MIPS_MODE_64 ? 8u : 4u;
    o->access = CDISASM_OPERAND_ACCESS_READ;
    o->flags = (uint8_t)(CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS |
                         (relative ? CDISASM_MIPS_OPERAND_FLAG_RELATIVE : CDISASM_MIPS_OPERAND_FLAG_ABSOLUTE));
    i->branch_target = target;
}
static void mips_memory(cdisasm_mips_instruction *i, unsigned base, int64_t displacement, uint8_t size, cdisasm_operand_access access)
{
    cdisasm_mips_operand *o = &i->operand[i->operand_count++];
    o->type = CDISASM_OPERAND_MEMORY;
    o->base_reg = (uint16_t)(CDISASM_MIPS_REG_GPR0 + base);
    o->imm = (uint64_t)displacement;
    o->size = size;
    o->access = (uint8_t)access;
    o->flags = CDISASM_MIPS_OPERAND_FLAG_SIGNED | CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;
    if (size == 0u) o->flags |= CDISASM_OPERAND_FLAG_ADDRESS_ONLY;
    if (base == 0u) {
        o->address = mips_address((cdisasm_mips_mode)i->mode, (uint64_t)displacement);
        o->flags |= CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS | CDISASM_MIPS_OPERAND_FLAG_ABSOLUTE;
    }
}
static cdisasm_status mips_name(cdisasm_mips_instruction *i, cdisasm_mips_name_id name)
{
    i->name_id = name;
    return CDISASM_STATUS_OK;
}
static cdisasm_status mips_three(cdisasm_mips_instruction *i, cdisasm_mips_name_id name, unsigned rd, unsigned rs, unsigned rt, uint8_t size)
{
    mips_gpr(i, rd, size, CDISASM_OPERAND_ACCESS_WRITE);
    mips_gpr(i, rs, size, CDISASM_OPERAND_ACCESS_READ);
    mips_gpr(i, rt, size, CDISASM_OPERAND_ACCESS_READ);
    return mips_name(i, name);
}
static cdisasm_status mips_shift(cdisasm_mips_instruction *i, cdisasm_mips_name_id name, unsigned rd, unsigned rt, unsigned sa, uint8_t size)
{
    mips_gpr(i, rd, size, CDISASM_OPERAND_ACCESS_WRITE);
    mips_gpr(i, rt, size, CDISASM_OPERAND_ACCESS_READ);
    mips_imm(i, sa, 1u, 0u);
    return mips_name(i, name);
}
static cdisasm_status mips_branch(cdisasm_mips_instruction *i, cdisasm_mips_name_id name, unsigned rs, unsigned rt, unsigned count,
                                uint32_t displacement, unsigned bits, int link, int likely, int compact)
{
    uint8_t size = mips_gpr_size((cdisasm_mips_mode)i->mode);
    if (count > 0u) mips_gpr(i, rs, size, CDISASM_OPERAND_ACCESS_READ);
    if (count > 1u) mips_gpr(i, rt, size, CDISASM_OPERAND_ACCESS_READ);
    mips_target(i, mips_relative((cdisasm_mips_mode)i->mode, i->address, displacement, bits), 1);
    i->opcode_groups = CDISASM_GROUP_JUMP | CDISASM_GROUP_RELATIVE_BRANCH;
    if (count != 0u) i->opcode_groups |= CDISASM_GROUP_CONDITIONAL;
    if (link) i->opcode_groups |= CDISASM_GROUP_CALL;
    i->instruction_flags |= compact ? CDISASM_MIPS_INSTRUCTION_FLAG_COMPACT_BRANCH : CDISASM_MIPS_INSTRUCTION_FLAG_DELAY_SLOT;
    if (likely) i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_BRANCH_LIKELY;
    return mips_name(i, name);
}

static cdisasm_status mips_special(uint32_t w, cdisasm_mips_mode mode, cdisasm_mips_revision rev,
                                 const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *i)
{
    unsigned rs = (w >> 21) & 31u, rt = (w >> 16) & 31u, rd = (w >> 11) & 31u, sa = (w >> 6) & 31u, fn = w & 63u;
    uint8_t size = mips_gpr_size(mode);
    int r6 = mips_r6(rev);
    cdisasm_mips_name_id name;
    if (w == 0u) return mips_name(i, CDISASM_MIPS_NAME_NOP);
    switch (fn) {
        case 0:
            if (rs != 0u) return CDISASM_STATUS_INVALID_INSTRUCTION;
            if (rt == 0u && rd == 0u && sa == 1u && mips_modern(rev)) return mips_name(i, CDISASM_MIPS_NAME_SSNOP);
            if (rt == 0u && rd == 0u && sa == 3u && mips_r2(rev)) return mips_name(i, CDISASM_MIPS_NAME_EHB);
            if (rt == 0u && rd == 0u && sa == 5u && mips_r2(rev)) return mips_name(i, CDISASM_MIPS_NAME_PAUSE);
            return mips_shift(i, CDISASM_MIPS_NAME_SLL, rd, rt, sa, 4u);
        case 1:
            if (!mips_iv(rev) || r6 || sa != 0u || (rt & 2u) != 0u) return CDISASM_STATUS_INVALID_INSTRUCTION;
            if (!mips_feature(features, CDISASM_MIPS_DECODE_BIT_FPU)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
            mips_gpr(i, rd, size, CDISASM_OPERAND_ACCESS_READ_WRITE);
            mips_gpr(i, rs, size, CDISASM_OPERAND_ACCESS_READ);
            mips_reg(i, (uint16_t)(CDISASM_MIPS_REG_FCC0 + (rt >> 2)), 1u, CDISASM_OPERAND_ACCESS_READ);
            i->opcode_groups = CDISASM_GROUP_CONDITIONAL;
            i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_FLOATING_POINT;
            return mips_name(i, (rt & 1u) ? CDISASM_MIPS_NAME_MOVT : CDISASM_MIPS_NAME_MOVF);
        case 2:
            if (rs == 1u && mips_r2(rev)) return mips_shift(i, CDISASM_MIPS_NAME_ROTR, rd, rt, sa, 4u);
            if (rs != 0u) return CDISASM_STATUS_INVALID_INSTRUCTION;
            return mips_shift(i, CDISASM_MIPS_NAME_SRL, rd, rt, sa, 4u);
        case 3:
            if (rs != 0u) return CDISASM_STATUS_INVALID_INSTRUCTION;
            return mips_shift(i, CDISASM_MIPS_NAME_SRA, rd, rt, sa, 4u);
        case 4: case 6: case 7:
            if (sa != 0u && !(fn == 6u && sa == 1u && mips_r2(rev))) return CDISASM_STATUS_INVALID_INSTRUCTION;
            name = fn == 4u ? CDISASM_MIPS_NAME_SLLV : fn == 7u ? CDISASM_MIPS_NAME_SRAV : sa == 1u ? CDISASM_MIPS_NAME_ROTRV : CDISASM_MIPS_NAME_SRLV;
            return mips_three(i, name, rd, rt, rs, 4u);
        case 8: case 9:
            if (rt != 0u || (fn == 8u && rd != 0u) || (sa != 0u && !(sa == 16u && mips_r2(rev)))) return CDISASM_STATUS_INVALID_INSTRUCTION;
            if (fn == 8u && r6) return CDISASM_STATUS_INVALID_INSTRUCTION;
            if (fn == 9u) mips_gpr(i, rd, size, CDISASM_OPERAND_ACCESS_WRITE);
            mips_gpr(i, rs, size, CDISASM_OPERAND_ACCESS_READ);
            i->opcode_groups = CDISASM_GROUP_JUMP;
            if (fn == 9u && rd != 0u) i->opcode_groups |= CDISASM_GROUP_CALL;
            if (rs == 31u && (fn == 8u || rd == 0u)) i->opcode_groups |= CDISASM_GROUP_RETURN;
            i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_DELAY_SLOT;
            return mips_name(i, fn == 8u ? (sa ? CDISASM_MIPS_NAME_JR_HB : CDISASM_MIPS_NAME_JR) : (sa ? CDISASM_MIPS_NAME_JALR_HB : CDISASM_MIPS_NAME_JALR));
        case 10: case 11:
            if (sa != 0u || !mips_iv(rev) || r6) return CDISASM_STATUS_INVALID_INSTRUCTION;
            mips_three(i, fn == 10u ? CDISASM_MIPS_NAME_MOVZ : CDISASM_MIPS_NAME_MOVN, rd, rs, rt, size);
            i->operand[0].access = CDISASM_OPERAND_ACCESS_READ_WRITE;
            i->opcode_groups = CDISASM_GROUP_CONDITIONAL;
            return CDISASM_STATUS_OK;
        case 12: case 13:
            mips_imm(i, (w >> 6) & UINT32_C(0xfffff), 4u, 0u);
            i->opcode_groups = CDISASM_GROUP_INTERRUPT;
            return mips_name(i, fn == 12u ? CDISASM_MIPS_NAME_SYSCALL : CDISASM_MIPS_NAME_BREAK);
        case 15:
            if (rs != 0u || rt != 0u || rd != 0u || !mips_ii(rev)) return CDISASM_STATUS_INVALID_INSTRUCTION;
            mips_imm(i, sa, 1u, 0u);
            return mips_name(i, CDISASM_MIPS_NAME_SYNC);
        case 16: case 18:
            if (mips_r2(rev) && rs > 0u && rs < 4u && rt == 0u && sa == 0u) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
            if (rs != 0u || rt != 0u || sa != 0u || r6) return CDISASM_STATUS_INVALID_INSTRUCTION;
            mips_gpr(i, rd, size, CDISASM_OPERAND_ACCESS_WRITE);
            /* HI/LO are implicit resources, not additional assembly operands. */
            return mips_name(i, fn == 16u ? CDISASM_MIPS_NAME_MFHI : CDISASM_MIPS_NAME_MFLO);
        case 17: case 19:
            if (mips_r2(rev) && rd > 0u && rd < 4u && rt == 0u && sa == 0u) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
            if (rt != 0u || rd != 0u || sa != 0u || r6) return CDISASM_STATUS_INVALID_INSTRUCTION;
            mips_gpr(i, rs, size, CDISASM_OPERAND_ACCESS_READ);
            return mips_name(i, fn == 17u ? CDISASM_MIPS_NAME_MTHI : CDISASM_MIPS_NAME_MTLO);
        case 20: case 22: case 23:
            if ((sa != 0u && !(fn == 22u && sa == 1u && mips_r2(rev))) || !mips_64(mode) || !mips_iii(rev)) return CDISASM_STATUS_INVALID_INSTRUCTION;
            if (fn == 22u && sa == 1u) return mips_three(i, CDISASM_MIPS_NAME_DROTRV, rd, rt, rs, 8u);
            return mips_three(i, fn == 20u ? CDISASM_MIPS_NAME_DSLLV : fn == 22u ? CDISASM_MIPS_NAME_DSRLV : CDISASM_MIPS_NAME_DSRAV, rd, rt, rs, 8u);
        case 24: case 25: case 26: case 27:
            if (mips_r2(rev) && fn < 26u && rd > 0u && rd < 4u && sa == 0u) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
            if (r6) {
                if (sa != 2u && sa != 3u) return CDISASM_STATUS_INVALID_INSTRUCTION;
                name = fn == 24u ? (sa == 2u ? CDISASM_MIPS_NAME_MUL : CDISASM_MIPS_NAME_MUH)
                     : fn == 25u ? (sa == 2u ? CDISASM_MIPS_NAME_MULU : CDISASM_MIPS_NAME_MUHU)
                     : fn == 26u ? (sa == 2u ? CDISASM_MIPS_NAME_DIV : CDISASM_MIPS_NAME_MOD)
                                 : (sa == 2u ? CDISASM_MIPS_NAME_DIVU : CDISASM_MIPS_NAME_MODU);
                return mips_three(i, name, rd, rs, rt, 4u);
            }
            if (rd != 0u || sa != 0u) return CDISASM_STATUS_INVALID_INSTRUCTION;
            mips_gpr(i, rs, 4u, CDISASM_OPERAND_ACCESS_READ);
            mips_gpr(i, rt, 4u, CDISASM_OPERAND_ACCESS_READ);
            name = fn == 24u ? CDISASM_MIPS_NAME_MULT : fn == 25u ? CDISASM_MIPS_NAME_MULTU : fn == 26u ? CDISASM_MIPS_NAME_DIV : CDISASM_MIPS_NAME_DIVU;
            return mips_name(i, name);
        case 28: case 29: case 30: case 31:
            if (!mips_64(mode) || !mips_iii(rev) || r6 || rd != 0u || sa != 0u) return CDISASM_STATUS_INVALID_INSTRUCTION;
            mips_gpr(i, rs, 8u, CDISASM_OPERAND_ACCESS_READ);
            mips_gpr(i, rt, 8u, CDISASM_OPERAND_ACCESS_READ);
            name = fn == 28u ? CDISASM_MIPS_NAME_DMULT : fn == 29u ? CDISASM_MIPS_NAME_DMULTU : fn == 30u ? CDISASM_MIPS_NAME_DDIV : CDISASM_MIPS_NAME_DDIVU;
            return mips_name(i, name);
        case 32: case 33: case 34: case 35: case 36: case 37: case 38: case 39: case 42: case 43:
            if (sa != 0u) return CDISASM_STATUS_INVALID_INSTRUCTION;
            name = fn == 32u ? CDISASM_MIPS_NAME_ADD : fn == 33u ? CDISASM_MIPS_NAME_ADDU : fn == 34u ? CDISASM_MIPS_NAME_SUB
                 : fn == 35u ? CDISASM_MIPS_NAME_SUBU : fn == 36u ? CDISASM_MIPS_NAME_AND : fn == 37u ? CDISASM_MIPS_NAME_OR
                 : fn == 38u ? CDISASM_MIPS_NAME_XOR : fn == 39u ? CDISASM_MIPS_NAME_NOR : fn == 42u ? CDISASM_MIPS_NAME_SLT : CDISASM_MIPS_NAME_SLTU;
            return mips_three(i, name, rd, rs, rt, fn >= 36u ? size : 4u);
        case 44: case 45: case 46: case 47:
            if (sa != 0u || !mips_64(mode) || !mips_iii(rev)) return CDISASM_STATUS_INVALID_INSTRUCTION;
            name = fn == 44u ? CDISASM_MIPS_NAME_DADD : fn == 45u ? CDISASM_MIPS_NAME_DADDU : fn == 46u ? CDISASM_MIPS_NAME_DSUB : CDISASM_MIPS_NAME_DSUBU;
            return mips_three(i, name, rd, rs, rt, 8u);
        case 48: case 49: case 50: case 51: case 52: case 54:
            if (!mips_ii(rev)) return CDISASM_STATUS_INVALID_INSTRUCTION;
            mips_gpr(i, rs, size, CDISASM_OPERAND_ACCESS_READ);
            mips_gpr(i, rt, size, CDISASM_OPERAND_ACCESS_READ);
            mips_imm(i, (w >> 6) & 1023u, 2u, 0u);
            i->opcode_groups = CDISASM_GROUP_INTERRUPT | CDISASM_GROUP_CONDITIONAL;
            name = fn == 48u ? CDISASM_MIPS_NAME_TGE : fn == 49u ? CDISASM_MIPS_NAME_TGEU : fn == 50u ? CDISASM_MIPS_NAME_TLT
                 : fn == 51u ? CDISASM_MIPS_NAME_TLTU : fn == 52u ? CDISASM_MIPS_NAME_TEQ : CDISASM_MIPS_NAME_TNE;
            return mips_name(i, name);
        case 56: case 58: case 59: case 60: case 62: case 63:
            if ((fn == 58u || fn == 62u) && rs == 1u && mips_r2(rev) && mips_64(mode))
                return mips_shift(i, fn == 58u ? CDISASM_MIPS_NAME_DROTR : CDISASM_MIPS_NAME_DROTR32, rd, rt, sa, 8u);
            if (rs != 0u || !mips_64(mode) || !mips_iii(rev)) return CDISASM_STATUS_INVALID_INSTRUCTION;
            name = fn == 56u ? CDISASM_MIPS_NAME_DSLL : fn == 58u ? CDISASM_MIPS_NAME_DSRL : fn == 59u ? CDISASM_MIPS_NAME_DSRA
                 : fn == 60u ? CDISASM_MIPS_NAME_DSLL32 : fn == 62u ? CDISASM_MIPS_NAME_DSRL32 : CDISASM_MIPS_NAME_DSRA32;
            return mips_shift(i, name, rd, rt, sa, 8u);
        default: return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
}

static cdisasm_status mips_regimm(uint32_t w, cdisasm_mips_mode mode, cdisasm_mips_revision rev, cdisasm_mips_instruction *i)
{
    unsigned rs = (w >> 21) & 31u, rt = (w >> 16) & 31u;
    cdisasm_mips_name_id name;
    if (mips_r6(rev) && rs == 0u && (rt == 16u || rt == 17u)) {
        if (rt == 16u) {
            if ((w & 65535u) != 0u) return CDISASM_STATUS_INVALID_INSTRUCTION;
            return mips_name(i, CDISASM_MIPS_NAME_NAL);
        }
        return mips_branch(i, CDISASM_MIPS_NAME_BAL, 0u, 0u, 0u, w & 65535u, 16u, 1, 0, 0);
    }
    if (rt == 0u || rt == 1u || rt == 2u || rt == 3u || (rt >= 16u && rt <= 19u)) {
        int likely = (rt & 2u) != 0u, link = (rt & 16u) != 0u;
        if ((likely && !mips_ii(rev)) || (mips_r6(rev) && (likely || !link || rs != 0u))) return CDISASM_STATUS_INVALID_INSTRUCTION;
        name = rt == 0u ? CDISASM_MIPS_NAME_BLTZ : rt == 1u ? CDISASM_MIPS_NAME_BGEZ : rt == 2u ? CDISASM_MIPS_NAME_BLTZL
             : rt == 3u ? CDISASM_MIPS_NAME_BGEZL : rt == 16u ? CDISASM_MIPS_NAME_BLTZAL : rt == 17u ? CDISASM_MIPS_NAME_BGEZAL
             : rt == 18u ? CDISASM_MIPS_NAME_BLTZALL : CDISASM_MIPS_NAME_BGEZALL;
        return mips_branch(i, name, rs, 0u, 1u, w & 65535u, 16u, link, likely, 0);
    }
    if (rt == 8u || rt == 9u || rt == 10u || rt == 11u || rt == 12u || rt == 14u) {
        if (!mips_ii(rev) || mips_r6(rev)) return CDISASM_STATUS_INVALID_INSTRUCTION;
        mips_gpr(i, rs, mips_gpr_size(mode), CDISASM_OPERAND_ACCESS_READ);
        mips_imm(i, (uint64_t)mips_sign(w & 65535u, 16u), 2u, CDISASM_MIPS_OPERAND_FLAG_SIGNED);
        i->opcode_groups = CDISASM_GROUP_INTERRUPT | CDISASM_GROUP_CONDITIONAL;
        name = rt == 8u ? CDISASM_MIPS_NAME_TGEI : rt == 9u ? CDISASM_MIPS_NAME_TGEIU : rt == 10u ? CDISASM_MIPS_NAME_TLTI
             : rt == 11u ? CDISASM_MIPS_NAME_TLTIU : rt == 12u ? CDISASM_MIPS_NAME_TEQI : CDISASM_MIPS_NAME_TNEI;
        return mips_name(i, name);
    }
    if (rt == 31u && mips_r2(rev)) {
        mips_memory(i, rs, mips_sign(w & 65535u, 16u), 0u, CDISASM_OPERAND_ACCESS_READ);
        return mips_name(i, CDISASM_MIPS_NAME_SYNCI);
    }
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}

static cdisasm_status mips_cop_branch(cdisasm_mips_instruction *i, unsigned cop, unsigned selector,
                                     uint32_t offset, cdisasm_mips_revision rev);

static cdisasm_status mips_cop0(uint32_t w, cdisasm_mips_mode mode, cdisasm_mips_revision rev, cdisasm_mips_instruction *i)
{
    unsigned rs = (w >> 21) & 31u, rt = (w >> 16) & 31u, rd = (w >> 11) & 31u, sel = w & 7u;
    cdisasm_mips_name_id name;
    i->opcode_groups = CDISASM_GROUP_PRIVILEGED;
#if USE_EXTRA_OPCODES
    /* R6 virtual-processor control uses distinct encodings from the removed
     * MT ASE DVPE/EVPE operations and requires no MT-family selection. */
    if (mips_r6(rev) && (w & UINT32_C(0xffe0ffdf)) == UINT32_C(0x41600004)) {
        mips_gpr(i, rt, 4u, CDISASM_OPERAND_ACCESS_WRITE);
        return mips_name(i, (w & 32u) ? CDISASM_MIPS_NAME_DVP : CDISASM_MIPS_NAME_EVP);
    }
#endif
    if (rs == 8u) {
        if (mips_modern(rev) && !mips_r6(rev)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        if (mips_iv(rev)) return CDISASM_STATUS_INVALID_INSTRUCTION;
        return mips_cop_branch(i, 0u, rt, w & 65535u, rev);
    }
    if (rs == 2u || rs == 6u) {
        if (mips_modern(rev) || (w & 2047u) != 0u) return CDISASM_STATUS_INVALID_INSTRUCTION;
        mips_gpr(i, rt, 4u, rs == 2u ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ);
        mips_reg(i, (uint16_t)CDISASM_MIPS_REG_CP0_CONTROL(rd), 4u,
                 rs == 2u ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE);
        return mips_name(i, rs == 2u ? CDISASM_MIPS_NAME_CFC0 : CDISASM_MIPS_NAME_CTC0);
    }
    if (rs == 0u || rs == 1u || rs == 4u || rs == 5u) {
        int to_cop = (rs & 4u) != 0u, wide = (rs & 1u) != 0u;
        if ((w & 2040u) != 0u || (!mips_modern(rev) && sel != 0u) || (wide && (!mips_64(mode) || !mips_iii(rev))))
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        /* MFC0 sign-extends its word into the whole destination GPR;
         * MTC0 consumes only a word. MD00087 rev6.06, printedp356. */
        mips_gpr(i, rt, to_cop ? (wide ? 8u : 4u) : mips_gpr_size(mode),
                 to_cop ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE);
        mips_reg(i, (uint16_t)CDISASM_MIPS_REG_CP0(rd, sel), wide ? 8u : 4u,
                 to_cop ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ);
        name = rs == 0u ? CDISASM_MIPS_NAME_MFC0 : rs == 1u ? CDISASM_MIPS_NAME_DMFC0 : rs == 4u ? CDISASM_MIPS_NAME_MTC0 : CDISASM_MIPS_NAME_DMTC0;
        return mips_name(i, name);
    }
    /* WAIT's CO field is one bit. The following nineteen bits are an
     * implementation code, including the low four bits of rs, rather than
     * reserved zeroes (MD00086 rev3.00 p282; rev6.06 p442). */
    if ((w & UINT32_C(0xfe00003f)) == UINT32_C(0x42000020)) {
        unsigned code = (w >> 6) & UINT32_C(0x7ffff);
        if (!mips_modern(rev)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        if (code != 0u) mips_imm(i, code, 4u, 0u);
        return mips_name(i, CDISASM_MIPS_NAME_WAIT);
    }
    if (rs == 16u && (w & UINT32_C(0x001fffc0)) == 0u) {
        switch (w & 63u) {
            case 1: return mips_name(i, CDISASM_MIPS_NAME_TLBR);
            case 2: return mips_name(i, CDISASM_MIPS_NAME_TLBWI);
            case 6: return mips_name(i, CDISASM_MIPS_NAME_TLBWR);
            case 8: return mips_name(i, CDISASM_MIPS_NAME_TLBP);
            case 16:
                if (mips_iii(rev)) return CDISASM_STATUS_INVALID_INSTRUCTION;
                i->opcode_groups |= CDISASM_GROUP_INTERRUPT_RETURN;
                return mips_name(i, CDISASM_MIPS_NAME_RFE);
            case 24:
                if (!mips_iii(rev)) return CDISASM_STATUS_INVALID_INSTRUCTION;
                i->opcode_groups |= CDISASM_GROUP_INTERRUPT_RETURN;
                return mips_name(i, CDISASM_MIPS_NAME_ERET);
            case 31:
                if (!mips_modern(rev)) return CDISASM_STATUS_INVALID_INSTRUCTION;
                i->opcode_groups |= CDISASM_GROUP_INTERRUPT_RETURN;
                return mips_name(i, CDISASM_MIPS_NAME_DERET);
            default: return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        }
    }
    if (rs == 11u && rd == 12u && (w & UINT32_C(0x7df)) == 0u && mips_r2(rev)) {
        mips_gpr(i, rt, 4u, CDISASM_OPERAND_ACCESS_WRITE);
        return mips_name(i, (w & 32u) ? CDISASM_MIPS_NAME_EI : CDISASM_MIPS_NAME_DI);
    }
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}

static cdisasm_status mips_special2(uint32_t w, cdisasm_mips_mode mode, cdisasm_mips_revision rev, cdisasm_mips_instruction *i)
{
    unsigned rs = (w >> 21) & 31u, rt = (w >> 16) & 31u, rd = (w >> 11) & 31u, sa = (w >> 6) & 31u, fn = w & 63u;
    cdisasm_mips_name_id name;
    if (!mips_modern(rev)) return CDISASM_STATUS_INVALID_INSTRUCTION;
    if (mips_r2(rev) && (fn == 0u || fn == 1u || fn == 4u || fn == 5u) && rd > 0u && rd < 4u && sa == 0u)
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    if (mips_r6(rev)) return CDISASM_STATUS_INVALID_INSTRUCTION;
    if (fn == 2u) {
        if (sa != 0u) return CDISASM_STATUS_INVALID_INSTRUCTION;
        return mips_three(i, CDISASM_MIPS_NAME_MUL, rd, rs, rt, 4u);
    }
    if (fn == 0u || fn == 1u || fn == 4u || fn == 5u) {
        if (rd != 0u || sa != 0u) return CDISASM_STATUS_INVALID_INSTRUCTION;
        mips_gpr(i, rs, 4u, CDISASM_OPERAND_ACCESS_READ);
        mips_gpr(i, rt, 4u, CDISASM_OPERAND_ACCESS_READ);
        name = fn == 0u ? CDISASM_MIPS_NAME_MADD : fn == 1u ? CDISASM_MIPS_NAME_MADDU : fn == 4u ? CDISASM_MIPS_NAME_MSUB : CDISASM_MIPS_NAME_MSUBU;
        return mips_name(i, name);
    }
    if (fn == 32u || fn == 33u || fn == 36u || fn == 37u) {
        if (sa != 0u || rt != rd || ((fn & 4u) && !mips_64(mode))) return CDISASM_STATUS_INVALID_INSTRUCTION;
        mips_gpr(i, rd, (fn & 4u) ? 8u : 4u, CDISASM_OPERAND_ACCESS_WRITE);
        mips_gpr(i, rs, (fn & 4u) ? 8u : 4u, CDISASM_OPERAND_ACCESS_READ);
        name = fn == 32u ? CDISASM_MIPS_NAME_CLZ : fn == 33u ? CDISASM_MIPS_NAME_CLO : fn == 36u ? CDISASM_MIPS_NAME_DCLZ : CDISASM_MIPS_NAME_DCLO;
        return mips_name(i, name);
    }
    if (fn == 63u) {
        mips_imm(i, (w >> 6) & UINT32_C(0xfffff), 4u, 0u);
        i->opcode_groups = CDISASM_GROUP_INTERRUPT;
        return mips_name(i, CDISASM_MIPS_NAME_SDBBP);
    }
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}

static cdisasm_status mips_special3(uint32_t w, cdisasm_mips_mode mode, cdisasm_mips_revision rev, cdisasm_mips_instruction *i)
{
    unsigned rs = (w >> 21) & 31u, rt = (w >> 16) & 31u, rd = (w >> 11) & 31u, sa = (w >> 6) & 31u, fn = w & 63u;
    cdisasm_mips_name_id name;
    if (!mips_r2(rev)) return CDISASM_STATUS_INVALID_INSTRUCTION;
    if (fn == 0u || fn == 4u) {
        unsigned width = fn == 0u ? rd + 1u : rd >= sa ? rd - sa + 1u : 0u;
        if (width == 0u || sa + width > 32u) return CDISASM_STATUS_INVALID_INSTRUCTION;
        mips_gpr(i, rt, 4u, fn == 0u ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ_WRITE);
        mips_gpr(i, rs, 4u, CDISASM_OPERAND_ACCESS_READ);
        mips_imm(i, sa, 1u, 0u);
        mips_imm(i, width, 1u, 0u);
        return mips_name(i, fn == 0u ? CDISASM_MIPS_NAME_EXT : CDISASM_MIPS_NAME_INS);
    }
    if (fn == 32u && rs == 0u && (sa == 2u || sa == 16u || sa == 24u)) {
        mips_gpr(i, rd, 4u, CDISASM_OPERAND_ACCESS_WRITE);
        mips_gpr(i, rt, 4u, CDISASM_OPERAND_ACCESS_READ);
        return mips_name(i, sa == 2u ? CDISASM_MIPS_NAME_WSBH : sa == 16u ? CDISASM_MIPS_NAME_SEB : CDISASM_MIPS_NAME_SEH);
    }
    if (fn == 36u && rs == 0u && mips_64(mode) && (sa == 2u || sa == 5u)) {
        mips_gpr(i, rd, 8u, CDISASM_OPERAND_ACCESS_WRITE);
        mips_gpr(i, rt, 8u, CDISASM_OPERAND_ACCESS_READ);
        return mips_name(i, sa == 2u ? CDISASM_MIPS_NAME_DSBH : CDISASM_MIPS_NAME_DSHD);
    }
    if (fn == 59u) {
        /* R6 adds a three-bit selector for PerfCtr's eight control/counter
         * views. Other register numbers retain their selector-zero encoding
         * (MD00087 rev6.05 pp389-391). */
        if (rs != 0u || sa > 7u || (sa != 0u && (!mips_r6(rev) || rd != 4u)))
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        mips_gpr(i, rt, mips_gpr_size(mode), CDISASM_OPERAND_ACCESS_WRITE);
        mips_imm(i, rd, 1u, 0u);
        if (sa != 0u) mips_imm(i, sa, 1u, 0u);
        return mips_name(i, CDISASM_MIPS_NAME_RDHWR);
    }
    if (mips_64(mode) && (fn == 1u || fn == 2u || fn == 3u || fn == 5u || fn == 6u || fn == 7u)) {
        unsigned position = sa + ((fn == 2u || fn == 6u) ? 32u : 0u);
        unsigned top = rd + ((fn == 1u || fn == 5u || fn == 6u) ? 32u : 0u);
        if (fn == 2u) top = rd;
        unsigned width = fn <= 3u ? top + 1u : top >= position ? top - position + 1u : 0u;
        if (width == 0u || position + width > 64u) return CDISASM_STATUS_INVALID_INSTRUCTION;
        mips_gpr(i, rt, 8u, fn <= 3u ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ_WRITE);
        mips_gpr(i, rs, 8u, CDISASM_OPERAND_ACCESS_READ);
        mips_imm(i, position, 1u, 0u);
        mips_imm(i, width, 1u, 0u);
        name = fn == 1u ? CDISASM_MIPS_NAME_DEXTM : fn == 2u ? CDISASM_MIPS_NAME_DEXTU : fn == 3u ? CDISASM_MIPS_NAME_DEXT
             : fn == 5u ? CDISASM_MIPS_NAME_DINSM : fn == 6u ? CDISASM_MIPS_NAME_DINSU : CDISASM_MIPS_NAME_DINS;
        return mips_name(i, name);
    }
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}

static void mips_fpr(cdisasm_mips_instruction *i, unsigned reg, uint8_t size, cdisasm_operand_access access)
{
    mips_reg(i, (uint16_t)(CDISASM_MIPS_REG_FPR0 + reg), size, access);
}

static cdisasm_status mips_fp_three(cdisasm_mips_instruction *i, cdisasm_mips_name_id name, unsigned fd, unsigned fs, unsigned ft,
                                   uint8_t size, cdisasm_operand_access destination_access)
{
    mips_fpr(i, fd, size, destination_access);
    mips_fpr(i, fs, size, CDISASM_OPERAND_ACCESS_READ);
    mips_fpr(i, ft, size, CDISASM_OPERAND_ACCESS_READ);
    return mips_name(i, name);
}
static void mips_fcc(cdisasm_mips_instruction *i, unsigned cc, unsigned count, cdisasm_operand_access access)
{
    cdisasm_mips_operand *o;
    mips_reg(i, (uint16_t)(CDISASM_MIPS_REG_FCC0 + cc), 1u, access);
    o = &i->operand[i->operand_count - 1u];
    if (count > 1u) {
        o->detail.flags = CDISASM_MIPS_OPERAND_DETAIL_REGISTER_LIST;
        o->imm = (UINT64_C(1) << count) - UINT64_C(1);
    }
}

#define MIPS_FPCOND_NAMES(prefix_, suffix_) \
    prefix_##F##suffix_, prefix_##UN##suffix_, prefix_##EQ##suffix_, prefix_##UEQ##suffix_, \
    prefix_##OLT##suffix_, prefix_##ULT##suffix_, prefix_##OLE##suffix_, prefix_##ULE##suffix_, \
    prefix_##SF##suffix_, prefix_##NGLE##suffix_, prefix_##SEQ##suffix_, prefix_##NGL##suffix_, \
    prefix_##LT##suffix_, prefix_##NGE##suffix_, prefix_##LE##suffix_, prefix_##NGT##suffix_

static cdisasm_status mips_cop1_extended(uint32_t w, cdisasm_mips_mode mode, cdisasm_mips_revision rev,
                                       const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *i)
{
    unsigned fmt = (w >> 21) & 31u, ft = (w >> 16) & 31u, fs = (w >> 11) & 31u, fd = (w >> 6) & 31u, fn = w & 63u;
    int paired = mips_paired(rev, features), r6 = mips_r6(rev), ps = fmt == 22u;
    uint8_t size = fmt == 16u ? 4u : 8u;
    cdisasm_mips_name_id name = CDISASM_MIPS_NAME_NONE;
#if USE_EXTRA_OPCODES
    if (!r6 && (fmt == 9u || fmt == 10u)) {
        unsigned count = fmt == 9u ? 2u : 4u, cc = ft >> 2;
        if ((ft & 2u) || (cc & (count - 1u)) || !mips_ps_revision(rev) || paired) return CDISASM_STATUS_INVALID_INSTRUCTION;
        if (!mips_feature(features, CDISASM_MIPS_DECODE_BIT_MIPS3D)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_MIPS3D | CDISASM_MIPS_INSTRUCTION_FLAG_DELAY_SLOT;
        i->opcode_groups = CDISASM_GROUP_JUMP | CDISASM_GROUP_CONDITIONAL | CDISASM_GROUP_RELATIVE_BRANCH;
        mips_fcc(i, cc, count, CDISASM_OPERAND_ACCESS_READ);
        mips_target(i, mips_relative(mode, i->address, w & 65535u, 16u), 1);
        return mips_name(i, count == 2u ? ((ft & 1u) ? CDISASM_MIPS_NAME_BC1ANY2T : CDISASM_MIPS_NAME_BC1ANY2F)
                                      : ((ft & 1u) ? CDISASM_MIPS_NAME_BC1ANY4T : CDISASM_MIPS_NAME_BC1ANY4F));
    }
#endif
    if (r6 && (fmt == 9u || fmt == 13u)) {
        mips_fpr(i, ft, 8u, CDISASM_OPERAND_ACCESS_READ);
        mips_target(i, mips_relative(mode, i->address, w & 65535u, 16u), 1);
        i->opcode_groups = CDISASM_GROUP_JUMP | CDISASM_GROUP_CONDITIONAL | CDISASM_GROUP_RELATIVE_BRANCH;
        i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_DELAY_SLOT;
        return mips_name(i, fmt == 9u ? CDISASM_MIPS_NAME_BC1EQZ : CDISASM_MIPS_NAME_BC1NEZ);
    }
    if (r6 && (fmt == 20u || fmt == 21u) && fn < 32u) {
#define MIPS_R6CMP_NAMES(suffix_) \
    CDISASM_MIPS_NAME_CMP_AF##suffix_, CDISASM_MIPS_NAME_CMP_UN##suffix_, CDISASM_MIPS_NAME_CMP_EQ##suffix_, CDISASM_MIPS_NAME_CMP_UEQ##suffix_, \
    CDISASM_MIPS_NAME_CMP_LT##suffix_, CDISASM_MIPS_NAME_CMP_ULT##suffix_, CDISASM_MIPS_NAME_CMP_LE##suffix_, CDISASM_MIPS_NAME_CMP_ULE##suffix_, \
    CDISASM_MIPS_NAME_CMP_SAF##suffix_, CDISASM_MIPS_NAME_CMP_SUN##suffix_, CDISASM_MIPS_NAME_CMP_SEQ##suffix_, CDISASM_MIPS_NAME_CMP_SUEQ##suffix_, \
    CDISASM_MIPS_NAME_CMP_SLT##suffix_, CDISASM_MIPS_NAME_CMP_SULT##suffix_, CDISASM_MIPS_NAME_CMP_SLE##suffix_, CDISASM_MIPS_NAME_CMP_SULE##suffix_
        static const cdisasm_mips_name_id cmp[2][16] = {{MIPS_R6CMP_NAMES(_S)}, {MIPS_R6CMP_NAMES(_D)}};
#undef MIPS_R6CMP_NAMES
        if (fn >= 16u) {
            /* MD00087 rev6.06 table3.9: bit4 negates a predicate, but
             * only OR/UNE/NE and their signalling forms are allocated.
             * Always-true and reversed-order conditions remain reserved. */
            static const cdisasm_mips_name_id negated[2][6] = {
                {CDISASM_MIPS_NAME_CMP_OR_S, CDISASM_MIPS_NAME_CMP_UNE_S, CDISASM_MIPS_NAME_CMP_NE_S,
                 CDISASM_MIPS_NAME_CMP_SOR_S, CDISASM_MIPS_NAME_CMP_SUNE_S, CDISASM_MIPS_NAME_CMP_SNE_S},
                {CDISASM_MIPS_NAME_CMP_OR_D, CDISASM_MIPS_NAME_CMP_UNE_D, CDISASM_MIPS_NAME_CMP_NE_D,
                 CDISASM_MIPS_NAME_CMP_SOR_D, CDISASM_MIPS_NAME_CMP_SUNE_D, CDISASM_MIPS_NAME_CMP_SNE_D}};
            const unsigned predicate = fn & 7u;
            if (predicate < 1u || predicate > 3u) return CDISASM_STATUS_INVALID_INSTRUCTION;
            return mips_fp_three(i, negated[fmt == 21u][predicate - 1u + ((fn & 8u) ? 3u : 0u)],
                                 fd, fs, ft, fmt == 20u ? 4u : 8u, CDISASM_OPERAND_ACCESS_WRITE);
        }
        return mips_fp_three(i, cmp[fmt == 21u][fn], fd, fs, ft, fmt == 20u ? 4u : 8u, CDISASM_OPERAND_ACCESS_WRITE);
    }
    if (fmt != 16u && fmt != 17u && fmt != 22u && !(fmt == 20u && fn == 38u)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    if (ps || (!r6 && fn == 38u && (fmt == 16u || fmt == 20u))) {
        if (!mips_ps_revision(rev) || paired) return CDISASM_STATUS_INVALID_INSTRUCTION;
        if (!mips_feature(features, CDISASM_MIPS_DECODE_BIT_PAIRED_SINGLE)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_PAIRED_SINGLE;
    }
    if (fmt == 17u && paired && (fs & 1u)) return CDISASM_STATUS_INVALID_INSTRUCTION;
    if (r6 && (fmt == 16u || fmt == 17u)) {
        int unary = fn == 26u || fn == 27u;
        switch (fn) {
            case 16: name = fmt == 16u ? CDISASM_MIPS_NAME_SEL_S : CDISASM_MIPS_NAME_SEL_D; break;
            case 20: name = fmt == 16u ? CDISASM_MIPS_NAME_SELEQZ_S : CDISASM_MIPS_NAME_SELEQZ_D; break;
            case 23: name = fmt == 16u ? CDISASM_MIPS_NAME_SELNEZ_S : CDISASM_MIPS_NAME_SELNEZ_D; break;
            case 24: name = fmt == 16u ? CDISASM_MIPS_NAME_MADDF_S : CDISASM_MIPS_NAME_MADDF_D; break;
            case 25: name = fmt == 16u ? CDISASM_MIPS_NAME_MSUBF_S : CDISASM_MIPS_NAME_MSUBF_D; break;
            case 26: name = fmt == 16u ? CDISASM_MIPS_NAME_RINT_S : CDISASM_MIPS_NAME_RINT_D; break;
            case 27: name = fmt == 16u ? CDISASM_MIPS_NAME_CLASS_S : CDISASM_MIPS_NAME_CLASS_D; break;
            case 28: name = fmt == 16u ? CDISASM_MIPS_NAME_MIN_S : CDISASM_MIPS_NAME_MIN_D; break;
            case 29: name = fmt == 16u ? CDISASM_MIPS_NAME_MINA_S : CDISASM_MIPS_NAME_MINA_D; break;
            case 30: name = fmt == 16u ? CDISASM_MIPS_NAME_MAX_S : CDISASM_MIPS_NAME_MAX_D; break;
            case 31: name = fmt == 16u ? CDISASM_MIPS_NAME_MAXA_S : CDISASM_MIPS_NAME_MAXA_D; break;
            default: break;
        }
        if (name != CDISASM_MIPS_NAME_NONE) {
            if (unary && ft != 0u) return CDISASM_STATUS_INVALID_INSTRUCTION;
            mips_fpr(i, fd, size, fn == 16u || fn == 24u || fn == 25u ? CDISASM_OPERAND_ACCESS_READ_WRITE : CDISASM_OPERAND_ACCESS_WRITE);
            mips_fpr(i, fs, size, CDISASM_OPERAND_ACCESS_READ);
            if (!unary) mips_fpr(i, ft, size, CDISASM_OPERAND_ACCESS_READ);
            return mips_name(i, name);
        }
    }
    if (!r6 && (fn == 17u || fn == 18u || fn == 19u) && fmt != 20u) {
        if (!mips_iv(rev) || (fn == 17u && (ft & 2u)) || (fmt == 17u && paired && (fd & 1u))) return CDISASM_STATUS_INVALID_INSTRUCTION;
        mips_fpr(i, fd, size, CDISASM_OPERAND_ACCESS_READ_WRITE);
        mips_fpr(i, fs, size, CDISASM_OPERAND_ACCESS_READ);
        i->opcode_groups |= CDISASM_GROUP_CONDITIONAL;
        if (fn == 17u) {
            unsigned cc = ft >> 2;
            if (ps && (cc & 1u)) return CDISASM_STATUS_INVALID_INSTRUCTION;
            mips_fcc(i, cc, ps ? 2u : 1u, CDISASM_OPERAND_ACCESS_READ);
            name = ps ? ((ft & 1u) ? CDISASM_MIPS_NAME_MOVT_PS : CDISASM_MIPS_NAME_MOVF_PS)
                 : fmt == 16u ? ((ft & 1u) ? CDISASM_MIPS_NAME_MOVT_S : CDISASM_MIPS_NAME_MOVF_S)
                              : ((ft & 1u) ? CDISASM_MIPS_NAME_MOVT_D : CDISASM_MIPS_NAME_MOVF_D);
        } else {
            mips_gpr(i, ft, mips_gpr_size(mode), CDISASM_OPERAND_ACCESS_READ);
            name = ps ? (fn == 18u ? CDISASM_MIPS_NAME_MOVZ_PS : CDISASM_MIPS_NAME_MOVN_PS)
                 : fmt == 16u ? (fn == 18u ? CDISASM_MIPS_NAME_MOVZ_S : CDISASM_MIPS_NAME_MOVN_S)
                              : (fn == 18u ? CDISASM_MIPS_NAME_MOVZ_D : CDISASM_MIPS_NAME_MOVN_D);
        }
        return mips_name(i, name);
    }
    if ((fmt == 16u || fmt == 17u) && (fn == 21u || fn == 22u)) {
        if (!mips_cop1x_revision(rev) && !r6) return CDISASM_STATUS_INVALID_INSTRUCTION;
        if (ft != 0u || (fmt == 17u && paired && (fd & 1u))) return CDISASM_STATUS_INVALID_INSTRUCTION;
        mips_fpr(i, fd, size, CDISASM_OPERAND_ACCESS_WRITE);
        mips_fpr(i, fs, size, CDISASM_OPERAND_ACCESS_READ);
        name = fmt == 16u ? (fn == 21u ? CDISASM_MIPS_NAME_RECIP_S : CDISASM_MIPS_NAME_RSQRT_S)
                          : (fn == 21u ? CDISASM_MIPS_NAME_RECIP_D : CDISASM_MIPS_NAME_RSQRT_D);
        return mips_name(i, name);
    }
    if (ps) {
        int unary = fn == 5u || fn == 6u || fn == 7u || fn == 32u || fn == 40u;
        switch (fn) {
            case 0: name = CDISASM_MIPS_NAME_ADD_PS; break;
            case 1: name = CDISASM_MIPS_NAME_SUB_PS; break;
            case 2: name = CDISASM_MIPS_NAME_MUL_PS; break;
            case 5: name = CDISASM_MIPS_NAME_ABS_PS; break;
            case 6: name = CDISASM_MIPS_NAME_MOV_PS; break;
            case 7: name = CDISASM_MIPS_NAME_NEG_PS; break;
            case 32: name = CDISASM_MIPS_NAME_CVT_S_PU; break;
            case 40: name = CDISASM_MIPS_NAME_CVT_S_PL; break;
            case 44: name = CDISASM_MIPS_NAME_PLL_PS; break;
            case 45: name = CDISASM_MIPS_NAME_PLU_PS; break;
            case 46: name = CDISASM_MIPS_NAME_PUL_PS; break;
            case 47: name = CDISASM_MIPS_NAME_PUU_PS; break;
            default: break;
        }
        if (name != CDISASM_MIPS_NAME_NONE) {
            if (unary && ft != 0u) return CDISASM_STATUS_INVALID_INSTRUCTION;
            mips_fpr(i, fd, fn == 32u || fn == 40u ? 4u : 8u, CDISASM_OPERAND_ACCESS_WRITE);
            mips_fpr(i, fs, 8u, CDISASM_OPERAND_ACCESS_READ);
            if (!unary) mips_fpr(i, ft, 8u, CDISASM_OPERAND_ACCESS_READ);
            return mips_name(i, name);
        }
    }
    if (!r6 && fmt == 16u && fn == 38u) {
        if (!mips_ps_revision(rev) || paired) return CDISASM_STATUS_INVALID_INSTRUCTION;
        mips_fpr(i, fd, 8u, CDISASM_OPERAND_ACCESS_WRITE);
        mips_fpr(i, fs, 4u, CDISASM_OPERAND_ACCESS_READ);
        mips_fpr(i, ft, 4u, CDISASM_OPERAND_ACCESS_READ);
        return mips_name(i, CDISASM_MIPS_NAME_CVT_PS_S);
    }
    if (!r6 && fn >= 48u && (ps || (fd & 1u))) {
        static const cdisasm_mips_name_id normal_ps[16] = {MIPS_FPCOND_NAMES(CDISASM_MIPS_NAME_C_, _PS)};
#if USE_EXTRA_OPCODES
        static const cdisasm_mips_name_id absolute[3][16] = {
            {MIPS_FPCOND_NAMES(CDISASM_MIPS_NAME_CABS_, _S)}, {MIPS_FPCOND_NAMES(CDISASM_MIPS_NAME_CABS_, _D)}, {MIPS_FPCOND_NAMES(CDISASM_MIPS_NAME_CABS_, _PS)}};
#endif
        unsigned cc = fd >> 2;
        if ((fd & 2u) || (ps && (cc & 1u)) || (fmt == 17u && paired && (ft & 1u))) return CDISASM_STATUS_INVALID_INSTRUCTION;
        if (fd & 1u) {
#if USE_EXTRA_OPCODES
            if (!mips_feature(features, CDISASM_MIPS_DECODE_BIT_MIPS3D)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
            if (paired || !mips_ps_revision(rev)) return CDISASM_STATUS_INVALID_INSTRUCTION;
            i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_MIPS3D;
            name = absolute[ps ? 2 : fmt == 17u][fn & 15u];
#else
            return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
        } else name = normal_ps[fn & 15u];
        mips_fcc(i, cc, ps ? 2u : 1u, CDISASM_OPERAND_ACCESS_WRITE);
        mips_fpr(i, fs, size, CDISASM_OPERAND_ACCESS_READ);
        mips_fpr(i, ft, size, CDISASM_OPERAND_ACCESS_READ);
        return mips_name(i, name);
    }
#if USE_EXTRA_OPCODES
    if (!r6 && mips_ps_revision(rev) && ((fn >= 28u && fn <= 31u) || (ps && (fn == 24u || fn == 26u || fn == 36u)) || (fmt == 20u && fn == 38u))) {
        int unary = fn == 29u || fn == 30u || fn == 36u || fn == 38u;
        if (!mips_feature(features, CDISASM_MIPS_DECODE_BIT_MIPS3D)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        if (paired || (unary && ft != 0u)) return CDISASM_STATUS_INVALID_INSTRUCTION;
        i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_MIPS3D;
        if (ps && fn == 24u) name = CDISASM_MIPS_NAME_ADDR_PS;
        else if (ps && fn == 26u) name = CDISASM_MIPS_NAME_MULR_PS;
        else if (fn == 36u) name = CDISASM_MIPS_NAME_CVT_PW_PS;
        else if (fn == 38u) name = CDISASM_MIPS_NAME_CVT_PS_PW;
        else if (fmt == 16u) name = fn == 28u ? CDISASM_MIPS_NAME_RECIP2_S : fn == 29u ? CDISASM_MIPS_NAME_RECIP1_S : fn == 30u ? CDISASM_MIPS_NAME_RSQRT1_S : CDISASM_MIPS_NAME_RSQRT2_S;
        else if (fmt == 17u) name = fn == 28u ? CDISASM_MIPS_NAME_RECIP2_D : fn == 29u ? CDISASM_MIPS_NAME_RECIP1_D : fn == 30u ? CDISASM_MIPS_NAME_RSQRT1_D : CDISASM_MIPS_NAME_RSQRT2_D;
        else name = fn == 28u ? CDISASM_MIPS_NAME_RECIP2_PS : fn == 29u ? CDISASM_MIPS_NAME_RECIP1_PS : fn == 30u ? CDISASM_MIPS_NAME_RSQRT1_PS : CDISASM_MIPS_NAME_RSQRT2_PS;
        mips_fpr(i, fd, size, CDISASM_OPERAND_ACCESS_WRITE);
        mips_fpr(i, fs, size, CDISASM_OPERAND_ACCESS_READ);
        if (!unary) mips_fpr(i, ft, size, CDISASM_OPERAND_ACCESS_READ);
        return mips_name(i, name);
    }
#endif
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}

static cdisasm_status mips_cop1x(uint32_t w, cdisasm_mips_mode mode, cdisasm_mips_revision rev,
                               const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *i)
{
    unsigned fr = (w >> 21) & 31u, ft = (w >> 16) & 31u, fs = (w >> 11) & 31u, fd = (w >> 6) & 31u, fn = w & 63u;
    int paired = mips_paired(rev, features);
    cdisasm_mips_name_id name;
    i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_FLOATING_POINT;
    if (!mips_cop1x_revision(rev)) return CDISASM_STATUS_INVALID_INSTRUCTION;
    if (!mips_feature(features, CDISASM_MIPS_DECODE_BIT_FPU)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    if (fn == 0u || fn == 1u || fn == 5u || fn == 8u || fn == 9u || fn == 13u || fn == 15u) {
        cdisasm_mips_operand *o;
        int store = fn == 8u || fn == 9u || fn == 13u;
        uint8_t size = fn == 0u || fn == 8u ? 4u : fn == 15u ? 0u : 8u;
        unsigned freg = store ? fs : fd;
        if ((store ? fd != 0u : fs != 0u) && fn != 15u) return CDISASM_STATUS_INVALID_INSTRUCTION;
        if ((fn == 5u || fn == 13u) && (!mips_ps_revision(rev) || paired)) return CDISASM_STATUS_INVALID_INSTRUCTION;
        if (size == 8u && paired && (freg & 1u)) return CDISASM_STATUS_INVALID_INSTRUCTION;
        if (fn == 15u) {
            if (fd != 0u) return CDISASM_STATUS_INVALID_INSTRUCTION;
            mips_imm(i, fs, 1u, 0u);
        } else mips_fpr(i, freg, size, store ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE);
        o = &i->operand[i->operand_count++];
        o->type = CDISASM_OPERAND_MEMORY;
        o->base_reg = (uint16_t)(CDISASM_MIPS_REG_GPR0 + fr);
        o->index_reg = (uint16_t)(CDISASM_MIPS_REG_GPR0 + ft);
        o->size = size;
        o->access = store ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ;
        if (size == 0u) o->flags |= CDISASM_OPERAND_FLAG_ADDRESS_ONLY;
        name = fn == 0u ? CDISASM_MIPS_NAME_LWXC1 : fn == 1u ? CDISASM_MIPS_NAME_LDXC1 : fn == 5u ? CDISASM_MIPS_NAME_LUXC1
             : fn == 8u ? CDISASM_MIPS_NAME_SWXC1 : fn == 9u ? CDISASM_MIPS_NAME_SDXC1 : fn == 13u ? CDISASM_MIPS_NAME_SUXC1 : CDISASM_MIPS_NAME_PREFX;
        return mips_name(i, name);
    }
    if (fn == 30u) {
        if (!mips_ps_revision(rev) || paired) return CDISASM_STATUS_INVALID_INSTRUCTION;
        if (!mips_feature(features, CDISASM_MIPS_DECODE_BIT_PAIRED_SINGLE)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_PAIRED_SINGLE;
        mips_fp_three(i, CDISASM_MIPS_NAME_ALNV_PS, fd, fs, ft, 8u, CDISASM_OPERAND_ACCESS_WRITE);
        mips_gpr(i, fr, mips_gpr_size(mode), CDISASM_OPERAND_ACCESS_READ);
        return CDISASM_STATUS_OK;
    }
    if (fn >= 32u && ((fn & 7u) == 0u || (fn & 7u) == 1u || (fn & 7u) == 6u)) {
        unsigned kind = (fn >> 3) - 4u, fmt = fn & 7u;
        uint8_t size = fmt == 0u ? 4u : 8u;
        static const cdisasm_mips_name_id names[4][3] = {
            {CDISASM_MIPS_NAME_MADD_S, CDISASM_MIPS_NAME_MADD_D, CDISASM_MIPS_NAME_MADD_PS},
            {CDISASM_MIPS_NAME_MSUB_S, CDISASM_MIPS_NAME_MSUB_D, CDISASM_MIPS_NAME_MSUB_PS},
            {CDISASM_MIPS_NAME_NMADD_S, CDISASM_MIPS_NAME_NMADD_D, CDISASM_MIPS_NAME_NMADD_PS},
            {CDISASM_MIPS_NAME_NMSUB_S, CDISASM_MIPS_NAME_NMSUB_D, CDISASM_MIPS_NAME_NMSUB_PS}};
        if (fmt == 6u && (!mips_ps_revision(rev) || paired)) return CDISASM_STATUS_INVALID_INSTRUCTION;
        if (fmt == 6u) {
            if (!mips_feature(features, CDISASM_MIPS_DECODE_BIT_PAIRED_SINGLE)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
            i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_PAIRED_SINGLE;
        }
        if (fmt == 1u && paired && ((fd | fr | fs | ft) & 1u)) return CDISASM_STATUS_INVALID_INSTRUCTION;
        mips_fpr(i, fd, size, CDISASM_OPERAND_ACCESS_WRITE);
        mips_fpr(i, fr, size, CDISASM_OPERAND_ACCESS_READ);
        mips_fpr(i, fs, size, CDISASM_OPERAND_ACCESS_READ);
        mips_fpr(i, ft, size, CDISASM_OPERAND_ACCESS_READ);
        return mips_name(i, names[kind][fmt == 6u ? 2u : fmt]);
    }
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}

/* COP1 arithmetic has fixed numeric FPR operands.  Conditions are independent
 * FCC registers; branch targets and memory addresses share the integer model. */
static cdisasm_status mips_cop1(uint32_t w, cdisasm_mips_mode mode, cdisasm_mips_revision rev,
                              const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *i)
{
    unsigned fmt = (w >> 21) & 31u, ft = (w >> 16) & 31u, fs = (w >> 11) & 31u, fd = (w >> 6) & 31u, fn = w & 63u;
    uint8_t size;
    int unary = 0;
    int paired = (unsigned)rev <= 2u || rev == CDISASM_MIPS_REVISION_32R1 || mips_feature(features, 12u);
    cdisasm_mips_name_id name;
    i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_FLOATING_POINT;
    if (!mips_feature(features, 1u)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    {
        cdisasm_status extended = mips_cop1_extended(w, mode, rev, features, i);
        if (extended != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION || fmt == 22u || (fn == 38u && (fmt == 16u || fmt == 20u)) ||
            (!mips_r6(rev) && fn >= 48u && (fd & 1u)) || (!mips_r6(rev) && fn >= 28u && fn <= 31u)) return extended;
    }
    if (fmt == 3u || fmt == 7u) {
        if (!mips_r2(rev) || (paired && (fs & 1u)) || (w & 2047u) != 0u) return CDISASM_STATUS_INVALID_INSTRUCTION;
        mips_gpr(i, ft, fmt == 3u ? mips_gpr_size(mode) : 4u,
                 fmt == 3u ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ);
        mips_reg(i, (uint16_t)(CDISASM_MIPS_REG_FPR0 + fs), 8u,
                 fmt == 3u ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_READ_WRITE);
        i->operand[1].detail.flags |= CDISASM_MIPS_OPERAND_DETAIL_HIGH_HALF;
        return mips_name(i, fmt == 3u ? CDISASM_MIPS_NAME_MFHC1 : CDISASM_MIPS_NAME_MTHC1);
    }
    if (fmt == 0u || fmt == 1u || fmt == 2u || fmt == 4u || fmt == 5u || fmt == 6u) {
        int to_cop = (fmt & 4u) != 0u, control = (fmt & 2u) != 0u, wide = (fmt & 1u) != 0u;
        if ((w & 2047u) != 0u || (wide && (!mips_iii(rev) || !mips_64(mode) || (paired && (fs & 1u))))) return CDISASM_STATUS_INVALID_INSTRUCTION;
        /* Word reads sign-extend into the complete destination GPR. Word
         * writes still consume only the low32 input bits. */
        mips_gpr(i, ft, wide ? 8u : to_cop ? 4u : mips_gpr_size(mode),
                 to_cop ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE);
        mips_reg(i, (uint16_t)((control ? CDISASM_MIPS_REG_FCR0 : CDISASM_MIPS_REG_FPR0) + fs), wide ? 8u : 4u,
                 to_cop ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ);
        name = fmt == 0u ? CDISASM_MIPS_NAME_MFC1 : fmt == 1u ? CDISASM_MIPS_NAME_DMFC1 : fmt == 2u ? CDISASM_MIPS_NAME_CFC1
             : fmt == 4u ? CDISASM_MIPS_NAME_MTC1 : fmt == 5u ? CDISASM_MIPS_NAME_DMTC1 : CDISASM_MIPS_NAME_CTC1;
        return mips_name(i, name);
    }
    if (fmt == 8u) {
        unsigned cc = ft >> 2;
        int likely = (ft & 2u) != 0u;
        if ((!mips_iv(rev) && cc != 0u) || (likely && !mips_ii(rev)) || mips_r6(rev)) return CDISASM_STATUS_INVALID_INSTRUCTION;
        mips_reg(i, (uint16_t)(CDISASM_MIPS_REG_FCC0 + cc), 1u, CDISASM_OPERAND_ACCESS_READ);
        mips_target(i, mips_relative(mode, i->address, w & 65535u, 16u), 1);
        i->opcode_groups = CDISASM_GROUP_JUMP | CDISASM_GROUP_CONDITIONAL | CDISASM_GROUP_RELATIVE_BRANCH;
        i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_DELAY_SLOT | (likely ? CDISASM_MIPS_INSTRUCTION_FLAG_BRANCH_LIKELY : 0u);
        return mips_name(i, (ft & 1u) ? (likely ? CDISASM_MIPS_NAME_BC1TL : CDISASM_MIPS_NAME_BC1T)
                                                    : (likely ? CDISASM_MIPS_NAME_BC1FL : CDISASM_MIPS_NAME_BC1F));
    }
    if (fmt != 16u && fmt != 17u && fmt != 20u && fmt != 21u) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    if ((fmt == 21u && (!mips_iii(rev) || paired)) || (fmt == 17u && paired && (fs & 1u)))
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    size = fmt == 17u || fmt == 21u ? 8u : 4u;
    if (fn >= 48u && (fmt == 16u || fmt == 17u)) {
        static const cdisasm_mips_name_id single[16] = {
            CDISASM_MIPS_NAME_C_F_S, CDISASM_MIPS_NAME_C_UN_S, CDISASM_MIPS_NAME_C_EQ_S, CDISASM_MIPS_NAME_C_UEQ_S,
            CDISASM_MIPS_NAME_C_OLT_S, CDISASM_MIPS_NAME_C_ULT_S, CDISASM_MIPS_NAME_C_OLE_S, CDISASM_MIPS_NAME_C_ULE_S,
            CDISASM_MIPS_NAME_C_SF_S, CDISASM_MIPS_NAME_C_NGLE_S, CDISASM_MIPS_NAME_C_SEQ_S, CDISASM_MIPS_NAME_C_NGL_S,
            CDISASM_MIPS_NAME_C_LT_S, CDISASM_MIPS_NAME_C_NGE_S, CDISASM_MIPS_NAME_C_LE_S, CDISASM_MIPS_NAME_C_NGT_S};
        static const cdisasm_mips_name_id dbl[16] = {
            CDISASM_MIPS_NAME_C_F_D, CDISASM_MIPS_NAME_C_UN_D, CDISASM_MIPS_NAME_C_EQ_D, CDISASM_MIPS_NAME_C_UEQ_D,
            CDISASM_MIPS_NAME_C_OLT_D, CDISASM_MIPS_NAME_C_ULT_D, CDISASM_MIPS_NAME_C_OLE_D, CDISASM_MIPS_NAME_C_ULE_D,
            CDISASM_MIPS_NAME_C_SF_D, CDISASM_MIPS_NAME_C_NGLE_D, CDISASM_MIPS_NAME_C_SEQ_D, CDISASM_MIPS_NAME_C_NGL_D,
            CDISASM_MIPS_NAME_C_LT_D, CDISASM_MIPS_NAME_C_NGE_D, CDISASM_MIPS_NAME_C_LE_D, CDISASM_MIPS_NAME_C_NGT_D};
        unsigned cc = fd >> 2;
        if ((fd & 3u) != 0u || (!mips_iv(rev) && cc != 0u) || mips_r6(rev) || (fmt == 17u && paired && (ft & 1u)))
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        mips_reg(i, (uint16_t)(CDISASM_MIPS_REG_FCC0 + cc), 1u, CDISASM_OPERAND_ACCESS_WRITE);
        mips_reg(i, (uint16_t)(CDISASM_MIPS_REG_FPR0 + fs), size, CDISASM_OPERAND_ACCESS_READ);
        mips_reg(i, (uint16_t)(CDISASM_MIPS_REG_FPR0 + ft), size, CDISASM_OPERAND_ACCESS_READ);
        return mips_name(i, fmt == 16u ? single[fn & 15u] : dbl[fn & 15u]);
    }
    if (fmt == 16u || fmt == 17u) {
        int d = fmt == 17u;
        uint8_t output_size = size;
        switch (fn) {
            case 0: name = d ? CDISASM_MIPS_NAME_ADD_D : CDISASM_MIPS_NAME_ADD_S; break;
            case 1: name = d ? CDISASM_MIPS_NAME_SUB_D : CDISASM_MIPS_NAME_SUB_S; break;
            case 2: name = d ? CDISASM_MIPS_NAME_MUL_D : CDISASM_MIPS_NAME_MUL_S; break;
            case 3: name = d ? CDISASM_MIPS_NAME_DIV_D : CDISASM_MIPS_NAME_DIV_S; break;
            case 4: if (!mips_ii(rev)) return CDISASM_STATUS_INVALID_INSTRUCTION; name = d ? CDISASM_MIPS_NAME_SQRT_D : CDISASM_MIPS_NAME_SQRT_S; unary = 1; break;
            case 5: name = d ? CDISASM_MIPS_NAME_ABS_D : CDISASM_MIPS_NAME_ABS_S; unary = 1; break;
            case 6: name = d ? CDISASM_MIPS_NAME_MOV_D : CDISASM_MIPS_NAME_MOV_S; unary = 1; break;
            case 7: name = d ? CDISASM_MIPS_NAME_NEG_D : CDISASM_MIPS_NAME_NEG_S; unary = 1; break;
            case 8: case 9: case 10: case 11:
                if (!mips_iii(rev) || paired) return CDISASM_STATUS_INVALID_INSTRUCTION;
                name = fn == 8u ? (d ? CDISASM_MIPS_NAME_ROUND_L_D : CDISASM_MIPS_NAME_ROUND_L_S)
                     : fn == 9u ? (d ? CDISASM_MIPS_NAME_TRUNC_L_D : CDISASM_MIPS_NAME_TRUNC_L_S)
                     : fn == 10u ? (d ? CDISASM_MIPS_NAME_CEIL_L_D : CDISASM_MIPS_NAME_CEIL_L_S)
                                  : (d ? CDISASM_MIPS_NAME_FLOOR_L_D : CDISASM_MIPS_NAME_FLOOR_L_S);
                unary = 1; output_size = 8u; break;
            case 12: case 13: case 14: case 15:
                if (!mips_ii(rev)) return CDISASM_STATUS_INVALID_INSTRUCTION;
                name = fn == 12u ? (d ? CDISASM_MIPS_NAME_ROUND_W_D : CDISASM_MIPS_NAME_ROUND_W_S)
                     : fn == 13u ? (d ? CDISASM_MIPS_NAME_TRUNC_W_D : CDISASM_MIPS_NAME_TRUNC_W_S)
                     : fn == 14u ? (d ? CDISASM_MIPS_NAME_CEIL_W_D : CDISASM_MIPS_NAME_CEIL_W_S)
                                  : (d ? CDISASM_MIPS_NAME_FLOOR_W_D : CDISASM_MIPS_NAME_FLOOR_W_S);
                unary = 1; output_size = 4u; break;
            case 32: if (!d) return CDISASM_STATUS_INVALID_INSTRUCTION; name = CDISASM_MIPS_NAME_CVT_S_D; unary = 1; break;
            case 33: if (d) return CDISASM_STATUS_INVALID_INSTRUCTION; name = CDISASM_MIPS_NAME_CVT_D_S; unary = 1; break;
            case 36: name = d ? CDISASM_MIPS_NAME_CVT_W_D : CDISASM_MIPS_NAME_CVT_W_S; unary = 1; break;
            case 37: if (!mips_iii(rev) || paired) return CDISASM_STATUS_INVALID_INSTRUCTION; name = d ? CDISASM_MIPS_NAME_CVT_L_D : CDISASM_MIPS_NAME_CVT_L_S; unary = 1; break;
            default: return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        if (fn == 32u || fn == 36u) output_size = 4u;
        if (fn == 33u || fn == 37u) output_size = 8u;
        if ((unary && ft != 0u) || (!unary && d && paired && (ft & 1u)) ||
            (paired && (fd & 1u) && output_size == 8u)) return CDISASM_STATUS_INVALID_INSTRUCTION;
        mips_reg(i, (uint16_t)(CDISASM_MIPS_REG_FPR0 + fd), output_size,
                 CDISASM_OPERAND_ACCESS_WRITE);
        mips_reg(i, (uint16_t)(CDISASM_MIPS_REG_FPR0 + fs), size, CDISASM_OPERAND_ACCESS_READ);
        if (!unary) mips_reg(i, (uint16_t)(CDISASM_MIPS_REG_FPR0 + ft), size, CDISASM_OPERAND_ACCESS_READ);
        return mips_name(i, name);
    }
    /* Release 6 uses the W/L-format slots for new three-FPR comparisons.
     * They are outside this bounded FPU slice, rather than invalid CVT words. */
    if (mips_r6(rev) && (fmt == 20u || fmt == 21u) && fn < 32u) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    if (ft != 0u || (fn != 32u && fn != 33u) || (paired && fn == 33u && (fd & 1u))) return CDISASM_STATUS_INVALID_INSTRUCTION;
    name = fn == 32u ? (fmt == 20u ? CDISASM_MIPS_NAME_CVT_S_W : CDISASM_MIPS_NAME_CVT_S_L)
                     : (fmt == 20u ? CDISASM_MIPS_NAME_CVT_D_W : CDISASM_MIPS_NAME_CVT_D_L);
    mips_reg(i, (uint16_t)(CDISASM_MIPS_REG_FPR0 + fd), fn == 32u ? 4u : 8u, CDISASM_OPERAND_ACCESS_WRITE);
    mips_reg(i, (uint16_t)(CDISASM_MIPS_REG_FPR0 + fs), size, CDISASM_OPERAND_ACCESS_READ);
    return mips_name(i, name);
}

/* COP2 supplies an architected register-transfer and memory protocol, while
 * the meaning of operations with CO=1 is supplied by the coprocessor vendor.
 * Keep the full modern Impl selector typed as a bank selector; it is not an
 * immediate arithmetic operand or a decoded implementation-defined opcode. */
static void mips_cop_register(cdisasm_mips_instruction *i, unsigned cop, unsigned reg, uint16_t selector,
                              int control, int implementation_selector, uint8_t size, cdisasm_operand_access access)
{
    uint16_t bank = cop == 2u ? (control ? CDISASM_MIPS_REG_FCR2_FIRST : CDISASM_MIPS_REG_COP2_FIRST)
                             : (control ? CDISASM_MIPS_REG_FCR3_FIRST : CDISASM_MIPS_REG_COP3_FIRST);
    mips_reg(i, implementation_selector ? bank : cop == 2u && !control ? (uint16_t)CDISASM_MIPS_REG_COP2(reg, 0u)
                                                                                     : (uint16_t)(bank + reg), size, access);
    if (implementation_selector) {
        cdisasm_mips_operand *o = &i->operand[i->operand_count - 1u];
        o->imm = selector;
        o->detail.flags |= CDISASM_MIPS_OPERAND_DETAIL_REGISTER_SELECTOR;
    }
}

static cdisasm_status mips_cop_branch(cdisasm_mips_instruction *i, unsigned cop, unsigned selector,
                                     uint32_t offset, cdisasm_mips_revision rev)
{
    static const cdisasm_mips_name_id branch_names[3][4] = {
        {CDISASM_MIPS_NAME_BC0F, CDISASM_MIPS_NAME_BC0T, CDISASM_MIPS_NAME_BC0FL, CDISASM_MIPS_NAME_BC0TL},
        {CDISASM_MIPS_NAME_BC2F, CDISASM_MIPS_NAME_BC2T, CDISASM_MIPS_NAME_BC2FL, CDISASM_MIPS_NAME_BC2TL},
        {CDISASM_MIPS_NAME_BC3F, CDISASM_MIPS_NAME_BC3T, CDISASM_MIPS_NAME_BC3FL, CDISASM_MIPS_NAME_BC3TL}};
    unsigned cc = selector >> 2, likely = (selector & 2u) != 0u;
    uint16_t reg = cop == 0u ? CDISASM_MIPS_REG_COP0CC0 : cop == 2u ? (uint16_t)(CDISASM_MIPS_REG_COP2CC0 + cc)
                                                                 : CDISASM_MIPS_REG_COP3CC0;
    if (mips_r6(rev) || (likely && !mips_ii(rev)) || (cc != 0u && (cop != 2u || !mips_iv(rev))))
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    mips_reg(i, reg, 1u, CDISASM_OPERAND_ACCESS_READ);
    if (cop != 2u) i->operand[0].flags |= CDISASM_OPERAND_FLAG_IMPLICIT;
    mips_target(i, mips_relative((cdisasm_mips_mode)i->mode, i->address, offset, 16u), 1);
    i->opcode_groups |= CDISASM_GROUP_JUMP | CDISASM_GROUP_CONDITIONAL | CDISASM_GROUP_RELATIVE_BRANCH;
    i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_DELAY_SLOT;
    if (likely) i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_BRANCH_LIKELY;
    return mips_name(i, branch_names[cop == 0u ? 0u : cop == 2u ? 1u : 2u][selector & 3u]);
}

static cdisasm_status mips_cop_other(uint32_t w, cdisasm_mips_mode mode, cdisasm_mips_revision rev,
                                    const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *i, unsigned cop)
{
    unsigned rs = (w >> 21) & 31u, rt = (w >> 16) & 31u, rd = (w >> 11) & 31u;
    int modern = mips_modern(rev), to_cop = (rs & 4u) != 0u;
    unsigned feature = cop == 2u ? CDISASM_MIPS_DECODE_BIT_COP2 : CDISASM_MIPS_DECODE_BIT_COP3;
    cdisasm_mips_name_id name;
    if (cop == 3u && (unsigned)rev > 2u) return CDISASM_STATUS_INVALID_INSTRUCTION;
    i->instruction_flags |= cop == 2u ? CDISASM_MIPS_INSTRUCTION_FLAG_COP2 : CDISASM_MIPS_INSTRUCTION_FLAG_COP3;
    if (!mips_feature(features, feature)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    if (cop == 2u && mips_r6(rev) && (rs == 10u || rs == 11u || rs == 14u || rs == 15u)) {
        int store = (rs & 1u) != 0u;
        uint8_t size = rs >= 14u ? 8u : 4u;
        mips_cop_register(i, 2u, rt, 0u, 0, 0, size, store ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE);
        mips_memory(i, rd, mips_sign(w & 2047u, 11u), size, store ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ);
        i->form_id = (cdisasm_mips_form_id)(CDISASM_MIPS_FORM_R6_BASE +
            (rs == 10u ? CDISASM_MIPS_NAME_LWC2 : rs == 11u ? CDISASM_MIPS_NAME_SWC2 : rs == 14u ? CDISASM_MIPS_NAME_LDC2 : CDISASM_MIPS_NAME_SDC2));
        return mips_name(i, rs == 10u ? CDISASM_MIPS_NAME_LWC2 : rs == 11u ? CDISASM_MIPS_NAME_SWC2 : rs == 14u ? CDISASM_MIPS_NAME_LDC2 : CDISASM_MIPS_NAME_SDC2);
    }
    if (cop == 2u && mips_r6(rev) && (rs == 9u || rs == 13u)) {
        mips_cop_register(i, 2u, rt, 0u, 0, 0, 8u, CDISASM_OPERAND_ACCESS_READ);
        mips_target(i, mips_relative(mode, i->address, w & 65535u, 16u), 1);
        i->opcode_groups = CDISASM_GROUP_JUMP | CDISASM_GROUP_CONDITIONAL | CDISASM_GROUP_RELATIVE_BRANCH;
        i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_DELAY_SLOT;
        return mips_name(i, rs == 9u ? CDISASM_MIPS_NAME_BC2EQZ : CDISASM_MIPS_NAME_BC2NEZ);
    }
    if (rs == 8u) return mips_cop_branch(i, cop, rt, w & 65535u, rev);
    if (rs < 8u) {
        int control = rs == 2u || rs == 6u;
        int high = rs == 3u || rs == 7u;
        int wide = rs == 1u || rs == 5u;
        uint8_t size = wide || high ? 8u : 4u;
        if ((!modern && (w & 2047u) != 0u) || (high && (cop != 2u || !mips_r2(rev))) ||
            (wide && (cop != 2u || !mips_iii(rev) || !mips_64(mode)))) return CDISASM_STATUS_INVALID_INSTRUCTION;
        /* Word transfers from COP2 sign-extend across the whole GPR;
         * opposite-direction inputs consume only their transferred word. */
        mips_gpr(i, rt, !to_cop ? mips_gpr_size(mode) : wide ? 8u : 4u,
                 to_cop ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE);
        mips_cop_register(i, cop, rd, (uint16_t)w, control, modern, size,
                          to_cop ? high ? CDISASM_OPERAND_ACCESS_READ_WRITE : CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ);
        if (high) i->operand[1].detail.flags |= CDISASM_MIPS_OPERAND_DETAIL_HIGH_HALF;
        if (cop == 2u) {
            static const cdisasm_mips_name_id transfers[8] = {CDISASM_MIPS_NAME_MFC2, CDISASM_MIPS_NAME_DMFC2, CDISASM_MIPS_NAME_CFC2,
                CDISASM_MIPS_NAME_MFHC2, CDISASM_MIPS_NAME_MTC2, CDISASM_MIPS_NAME_DMTC2, CDISASM_MIPS_NAME_CTC2, CDISASM_MIPS_NAME_MTHC2};
            name = transfers[rs];
        } else {
            name = rs == 0u ? CDISASM_MIPS_NAME_MFC3 : rs == 2u ? CDISASM_MIPS_NAME_CFC3 : rs == 4u ? CDISASM_MIPS_NAME_MTC3 : CDISASM_MIPS_NAME_CTC3;
        }
        return mips_name(i, name);
    }
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}

static cdisasm_status mips_cop_memory(uint32_t w, cdisasm_mips_revision rev, const cdisasm_mips_decode_flags *features,
                                     cdisasm_mips_instruction *i, unsigned cop)
{
    unsigned op = w >> 26, rt = (w >> 16) & 31u, base = (w >> 21) & 31u;
    int store = (op & 8u) != 0u, wide = (op & 4u) != 0u;
    cdisasm_mips_name_id name;
    if ((cop == 3u && (unsigned)rev > 2u) || (wide && !mips_ii(rev)) || mips_r6(rev)) return CDISASM_STATUS_INVALID_INSTRUCTION;
    i->instruction_flags |= cop == 2u ? CDISASM_MIPS_INSTRUCTION_FLAG_COP2 : CDISASM_MIPS_INSTRUCTION_FLAG_COP3;
    if (!mips_feature(features, cop == 2u ? CDISASM_MIPS_DECODE_BIT_COP2 : CDISASM_MIPS_DECODE_BIT_COP3))
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    mips_cop_register(i, cop, rt, 0u, 0, 0, wide ? 8u : 4u,
                      store ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE);
    mips_memory(i, base, mips_sign(w & 65535u, 16u), wide ? 8u : 4u,
                store ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ);
    if (cop == 2u) name = wide ? (store ? CDISASM_MIPS_NAME_SDC2 : CDISASM_MIPS_NAME_LDC2)
                              : (store ? CDISASM_MIPS_NAME_SWC2 : CDISASM_MIPS_NAME_LWC2);
    else name = wide ? (store ? CDISASM_MIPS_NAME_SDC3 : CDISASM_MIPS_NAME_LDC3)
                     : (store ? CDISASM_MIPS_NAME_SWC3 : CDISASM_MIPS_NAME_LWC3);
    return mips_name(i, name);
}

static cdisasm_status mips_main(uint32_t w, uint64_t address, cdisasm_mips_mode mode, cdisasm_mips_revision rev,
                              const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *i)
{
    unsigned op = w >> 26, rs = (w >> 21) & 31u, rt = (w >> 16) & 31u;
    uint8_t size = mips_gpr_size(mode), memory_size = 0u;
    int store = 0, floating = 0, conditional_store = 0, partial_load = 0;
    cdisasm_mips_name_id name = CDISASM_MIPS_NAME_NONE;
    if (op == 0u) return mips_special(w, mode, rev, features, i);
    if (op == 1u) return mips_regimm(w, mode, rev, i);
    if (op == 16u) return mips_cop0(w, mode, rev, i);
    if (op == 17u) return mips_cop1(w, mode, rev, features, i);
    if (op == 18u) return mips_cop_other(w, mode, rev, features, i, 2u);
    if (op == 19u) return (unsigned)rev <= 3u ? mips_cop_other(w, mode, rev, features, i, 3u) : mips_cop1x(w, mode, rev, features, i);
    if (op == 50u || op == 54u || op == 58u || op == 62u) return mips_cop_memory(w, rev, features, i, 2u);
    if ((unsigned)rev <= 2u && (op == 51u || op == 55u || op == 59u || op == 63u)) return mips_cop_memory(w, rev, features, i, 3u);
    if (op == 28u) return mips_special2(w, mode, rev, i);
    if (op == 31u) return mips_special3(w, mode, rev, i);
#if USE_EXTRA_OPCODES
    if (op == 29u && mips_modern(rev) && !mips_r6(rev)) {
        uint64_t target = ((address + UINT64_C(4)) & ~UINT64_C(0x0fffffff)) | ((uint64_t)(w & UINT32_C(0x03ffffff)) << 2);
        mips_target(i, mips_address(mode, target), 0);
        i->opcode_groups = CDISASM_GROUP_JUMP | CDISASM_GROUP_CALL;
        i->instruction_flags = CDISASM_MIPS_INSTRUCTION_FLAG_DELAY_SLOT | CDISASM_MIPS_INSTRUCTION_FLAG_LINK |
                               CDISASM_MIPS_INSTRUCTION_FLAG_ISA_EXCHANGE;
        return mips_name(i, CDISASM_MIPS_NAME_JALX);
    }
#endif
    if (op == 2u || op == 3u) {
        uint64_t target = ((address + UINT64_C(4)) & ~UINT64_C(0x0fffffff)) | ((uint64_t)(w & UINT32_C(0x03ffffff)) << 2);
        mips_target(i, mips_address(mode, target), 0);
        i->opcode_groups = CDISASM_GROUP_JUMP | (op == 3u ? CDISASM_GROUP_CALL : 0u);
        i->instruction_flags = CDISASM_MIPS_INSTRUCTION_FLAG_DELAY_SLOT;
        return mips_name(i, op == 2u ? CDISASM_MIPS_NAME_J : CDISASM_MIPS_NAME_JAL);
    }
    if (op >= 4u && op <= 7u) {
        if (op >= 6u && rt != 0u) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        name = op == 4u ? CDISASM_MIPS_NAME_BEQ : op == 5u ? CDISASM_MIPS_NAME_BNE : op == 6u ? CDISASM_MIPS_NAME_BLEZ : CDISASM_MIPS_NAME_BGTZ;
        return mips_branch(i, name, rs, rt, op < 6u ? 2u : 1u, w & 65535u, 16u, 0, 0, 0);
    }
    if (op >= 8u && op <= 15u) {
        if (op == 8u && mips_r6(rev)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        if (op == 15u) {
            if (rs != 0u) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
            mips_gpr(i, rt, 4u, CDISASM_OPERAND_ACCESS_WRITE);
        } else {
            mips_gpr(i, rt, op == 9u || op == 8u ? 4u : size, CDISASM_OPERAND_ACCESS_WRITE);
            mips_gpr(i, rs, op == 9u || op == 8u ? 4u : size, CDISASM_OPERAND_ACCESS_READ);
        }
        mips_imm(i, op >= 12u ? w & 65535u : (uint64_t)mips_sign(w & 65535u, 16u), 2u, op >= 12u ? 0u : CDISASM_MIPS_OPERAND_FLAG_SIGNED);
        name = op == 8u ? CDISASM_MIPS_NAME_ADDI : op == 9u ? CDISASM_MIPS_NAME_ADDIU : op == 10u ? CDISASM_MIPS_NAME_SLTI
             : op == 11u ? CDISASM_MIPS_NAME_SLTIU : op == 12u ? CDISASM_MIPS_NAME_ANDI : op == 13u ? CDISASM_MIPS_NAME_ORI
             : op == 14u ? CDISASM_MIPS_NAME_XORI : CDISASM_MIPS_NAME_LUI;
        return mips_name(i, name);
    }
    if (op >= 20u && op <= 23u) {
        if (mips_r6(rev)) return op < 22u ? CDISASM_STATUS_INVALID_INSTRUCTION : CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        if (!mips_ii(rev) || (op >= 22u && rt != 0u)) return CDISASM_STATUS_INVALID_INSTRUCTION;
        name = op == 20u ? CDISASM_MIPS_NAME_BEQL : op == 21u ? CDISASM_MIPS_NAME_BNEL : op == 22u ? CDISASM_MIPS_NAME_BLEZL : CDISASM_MIPS_NAME_BGTZL;
        return mips_branch(i, name, rs, rt, op < 22u ? 2u : 1u, w & 65535u, 16u, 0, 1, 0);
    }
    if (op == 24u || op == 25u) {
        if (op == 24u && mips_r6(rev)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        if (!mips_64(mode) || !mips_iii(rev)) return CDISASM_STATUS_INVALID_INSTRUCTION;
        mips_gpr(i, rt, 8u, CDISASM_OPERAND_ACCESS_WRITE);
        mips_gpr(i, rs, 8u, CDISASM_OPERAND_ACCESS_READ);
        mips_imm(i, (uint64_t)mips_sign(w & 65535u, 16u), 2u, CDISASM_MIPS_OPERAND_FLAG_SIGNED);
        return mips_name(i, op == 24u ? CDISASM_MIPS_NAME_DADDI : CDISASM_MIPS_NAME_DADDIU);
    }
    switch (op) {
        case 26: name = CDISASM_MIPS_NAME_LDL; memory_size = 8u; partial_load = 1; break;
        case 27: name = CDISASM_MIPS_NAME_LDR; memory_size = 8u; partial_load = 1; break;
        case 32: name = CDISASM_MIPS_NAME_LB; memory_size = 1u; break;
        case 33: name = CDISASM_MIPS_NAME_LH; memory_size = 2u; break;
        case 34: name = CDISASM_MIPS_NAME_LWL; memory_size = 4u; partial_load = 1; break;
        case 35: name = CDISASM_MIPS_NAME_LW; memory_size = 4u; break;
        case 36: name = CDISASM_MIPS_NAME_LBU; memory_size = 1u; break;
        case 37: name = CDISASM_MIPS_NAME_LHU; memory_size = 2u; break;
        case 38: name = CDISASM_MIPS_NAME_LWR; memory_size = 4u; partial_load = 1; break;
        case 39: name = CDISASM_MIPS_NAME_LWU; memory_size = 4u; if (!mips_64(mode)) return CDISASM_STATUS_INVALID_INSTRUCTION; break;
        case 40: name = CDISASM_MIPS_NAME_SB; memory_size = 1u; store = 1; break;
        case 41: name = CDISASM_MIPS_NAME_SH; memory_size = 2u; store = 1; break;
        case 42: name = CDISASM_MIPS_NAME_SWL; memory_size = 4u; store = 1; break;
        case 43: name = CDISASM_MIPS_NAME_SW; memory_size = 4u; store = 1; break;
        case 44: name = CDISASM_MIPS_NAME_SDL; memory_size = 8u; store = 1; break;
        case 45: name = CDISASM_MIPS_NAME_SDR; memory_size = 8u; store = 1; break;
        case 46: name = CDISASM_MIPS_NAME_SWR; memory_size = 4u; store = 1; break;
        case 47:
            if (!mips_iii(rev) || mips_r6(rev)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
            mips_imm(i, rt, 1u, 0u);
            mips_memory(i, rs, mips_sign(w & 65535u, 16u), 0u, CDISASM_OPERAND_ACCESS_READ);
            i->opcode_groups = CDISASM_GROUP_PRIVILEGED;
            return mips_name(i, CDISASM_MIPS_NAME_CACHE);
        case 48: name = CDISASM_MIPS_NAME_LL; memory_size = 4u; if (!mips_ii(rev)) return CDISASM_STATUS_INVALID_INSTRUCTION; break;
        case 49: name = CDISASM_MIPS_NAME_LWC1; memory_size = 4u; floating = 1; break;
        case 51:
            if (!mips_iv(rev) || mips_r6(rev)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
            mips_imm(i, rt, 1u, 0u);
            mips_memory(i, rs, mips_sign(w & 65535u, 16u), 0u, CDISASM_OPERAND_ACCESS_READ);
            return mips_name(i, CDISASM_MIPS_NAME_PREF);
        case 52: name = CDISASM_MIPS_NAME_LLD; memory_size = 8u; break;
        case 53: name = CDISASM_MIPS_NAME_LDC1; memory_size = 8u; floating = 1; if (!mips_ii(rev)) return CDISASM_STATUS_INVALID_INSTRUCTION; break;
        case 55: name = CDISASM_MIPS_NAME_LD; memory_size = 8u; break;
        case 56: name = CDISASM_MIPS_NAME_SC; memory_size = 4u; store = 1; conditional_store = 1; if (!mips_ii(rev)) return CDISASM_STATUS_INVALID_INSTRUCTION; break;
        case 57: name = CDISASM_MIPS_NAME_SWC1; memory_size = 4u; store = 1; floating = 1; break;
        case 60: name = CDISASM_MIPS_NAME_SCD; memory_size = 8u; store = 1; conditional_store = 1; break;
        case 61: name = CDISASM_MIPS_NAME_SDC1; memory_size = 8u; store = 1; floating = 1; if (!mips_ii(rev)) return CDISASM_STATUS_INVALID_INSTRUCTION; break;
        case 63: name = CDISASM_MIPS_NAME_SD; memory_size = 8u; store = 1; break;
        default: return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if (mips_r6(rev) && (partial_load || op == 42u || op == 44u || op == 45u || op == 46u || op == 48u || op == 52u || op == 56u || op == 60u))
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    if (memory_size == 8u && !floating && (!mips_64(mode) || !mips_iii(rev))) return CDISASM_STATUS_INVALID_INSTRUCTION;
    if (floating) {
        i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_FLOATING_POINT;
        if (!mips_feature(features, 1u)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        if (memory_size == 8u && ((unsigned)rev <= 2u || rev == CDISASM_MIPS_REVISION_32R1 || mips_feature(features, 12u)) && (rt & 1u))
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        mips_reg(i, (uint16_t)(CDISASM_MIPS_REG_FPR0 + rt), memory_size, store ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE);
    } else {
        mips_gpr(i, rt, size, conditional_store || partial_load ? CDISASM_OPERAND_ACCESS_READ_WRITE
                                                              : store ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE);
    }
    mips_memory(i, rs, mips_sign(w & 65535u, 16u), memory_size, store ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ);
    return mips_name(i, name);
}

static void mips_implicit_semantics(cdisasm_mips_instruction *i, int r6)
{
    unsigned n;
    int nonzero_accumulator = 0;
    for (n = 0u; n < i->operand_count; ++n) {
        if (i->operand[n].type == CDISASM_OPERAND_REGISTER && i->operand[n].reg > CDISASM_MIPS_REG_ACC0 &&
            i->operand[n].reg <= CDISASM_MIPS_REG_ACC3) nonzero_accumulator = 1;
    }
    switch (i->name_id) {
        case CDISASM_MIPS_NAME_MFHI: i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_READS_HI; break;
        case CDISASM_MIPS_NAME_MFLO: i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_READS_LO; break;
        case CDISASM_MIPS_NAME_MTHI: i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_HI; break;
        case CDISASM_MIPS_NAME_MTLO: i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_LO; break;
        case CDISASM_MIPS_NAME_MULT: case CDISASM_MIPS_NAME_MULTU: case CDISASM_MIPS_NAME_DMULT: case CDISASM_MIPS_NAME_DMULTU:
        case CDISASM_MIPS_NAME_DIV: case CDISASM_MIPS_NAME_DIVU: case CDISASM_MIPS_NAME_DDIV: case CDISASM_MIPS_NAME_DDIVU:
        case CDISASM_MIPS_NAME_MUL:
            if (!r6) i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_HI | CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_LO;
            break;
        case CDISASM_MIPS_NAME_MADD: case CDISASM_MIPS_NAME_MADDU: case CDISASM_MIPS_NAME_MSUB: case CDISASM_MIPS_NAME_MSUBU:
            i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_READS_HI | CDISASM_MIPS_INSTRUCTION_FLAG_READS_LO |
                                    CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_HI | CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_LO;
            break;
        case CDISASM_MIPS_NAME_JAL: case CDISASM_MIPS_NAME_BAL: case CDISASM_MIPS_NAME_BALC: case CDISASM_MIPS_NAME_JIALC:
        case CDISASM_MIPS_NAME_BLTZAL: case CDISASM_MIPS_NAME_BGEZAL: case CDISASM_MIPS_NAME_BLTZALL: case CDISASM_MIPS_NAME_BGEZALL:
        case CDISASM_MIPS_NAME_BEQZALC: case CDISASM_MIPS_NAME_BNEZALC: case CDISASM_MIPS_NAME_BLEZALC: case CDISASM_MIPS_NAME_BGEZALC:
        case CDISASM_MIPS_NAME_BGTZALC: case CDISASM_MIPS_NAME_BLTZALC: case CDISASM_MIPS_NAME_NAL:
            i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_LINK;
            break;
        case CDISASM_MIPS_NAME_RDDSP: i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_READS_DSPCONTROL; break;
        case CDISASM_MIPS_NAME_WRDSP: i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_DSPCONTROL; break;
        case CDISASM_MIPS_NAME_LL: case CDISASM_MIPS_NAME_LLD: case CDISASM_MIPS_NAME_SC: case CDISASM_MIPS_NAME_SCD:
            i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_ATOMIC;
            break;
        case CDISASM_MIPS_NAME_SYNC: case CDISASM_MIPS_NAME_EHB: case CDISASM_MIPS_NAME_SYNCI:
            i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_BARRIER;
            break;
        case CDISASM_MIPS_NAME_ADDQ_PH: case CDISASM_MIPS_NAME_SUBQ_PH:
        case CDISASM_MIPS_NAME_ADDQ_S_PH: case CDISASM_MIPS_NAME_SUBQ_S_PH:
        case CDISASM_MIPS_NAME_ADDU_QB: case CDISASM_MIPS_NAME_SUBU_QB:
        case CDISASM_MIPS_NAME_ADDU_S_QB: case CDISASM_MIPS_NAME_SUBU_S_QB:
            /* The overflow bits are sticky: preserving the other control bits
             * requires the old DSPControl value as well as a write.  Halving
             * DSPR2 arithmetic does not update these overflow flags. */
            i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_READS_DSPCONTROL | CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_DSPCONTROL;
            break;
        default: break;
    }
    if ((i->instruction_flags & CDISASM_MIPS_INSTRUCTION_FLAG_DSP) && (nonzero_accumulator || r6))
        i->instruction_flags &= ~(CDISASM_MIPS_INSTRUCTION_FLAG_READS_HI | CDISASM_MIPS_INSTRUCTION_FLAG_READS_LO |
                                  CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_HI | CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_LO);
}

static void mips_fp_semantics(cdisasm_mips_instruction *i, int r6)
{
    uint32_t w = i->raw_instruction;
    unsigned op = w >> 26, fmt = (w >> 21) & 31u, fs = (w >> 11) & 31u, fn = w & 63u;
    if (!(i->instruction_flags & CDISASM_MIPS_INSTRUCTION_FLAG_FLOATING_POINT)) return;
    if (op == 17u && (fmt == 2u || fmt == 6u)) {
        if (fs == 25u || fs == 26u || fs == 28u || fs == 31u)
            i->instruction_flags |= fmt == 2u ? CDISASM_MIPS_INSTRUCTION_FLAG_READS_FCSR : CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_FCSR;
        /* FCCR/FEXR/FENR replace only selected FCSR fields. Their writes
         * retain the other fields of this aggregate physical resource. */
        if (fmt == 6u && (fs == 25u || fs == 26u || fs == 28u))
            i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_READS_FCSR;
        return;
    }
    if (op == 17u && fmt >= 16u) {
        /* Pure moves, conditionally selected bit patterns, classifications,
         * paired packing and unpacking do not perform FP arithmetic. */
        if ((fmt == 16u || fmt == 17u || fmt == 22u) &&
            (fn == 6u || (!r6 && (fn == 17u || fn == 18u || fn == 19u)) ||
             (r6 && (fn == 5u || fn == 7u || fn == 16u || fn == 20u || fn == 23u || fn == 27u)))) return;
        if ((fmt == 16u && fn == 38u) || (fmt == 22u && (fn == 32u || fn == 40u || (fn >= 44u && fn <= 47u)))) return;
        i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_READS_FCSR | CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_FCSR;
    } else if (op == 19u && fn >= 32u) {
        i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_READS_FCSR | CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_FCSR;
    }
}

static void mips_prepare(cdisasm_mips_instruction *i, uint32_t raw, uint64_t address,
                         cdisasm_mips_mode mode, cdisasm_mips_revision revision)
{
    memset(i, 0, sizeof(*i));
    i->address = address;
    i->opcode_size = 4u;
    i->raw_instruction = raw;
    i->mode = (uint8_t)mode;
    i->revision = (uint8_t)revision;
}

cdisasm_status cdisasm_mips_decode_core(uint32_t raw, uint64_t address, cdisasm_mips_mode mode, cdisasm_mips_revision revision,
                                      const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *instruction)
{
    cdisasm_status status;
    if (instruction == NULL) return CDISASM_STATUS_INTERNAL_ERROR;
    mips_prepare(instruction, raw, address, mode, revision);
    if ((mips_feature(features, CDISASM_MIPS_DECODE_BIT_ALLEGREX) ||
         (features != NULL && (features->bitmap[CDISASM_MIPS_INTERNAL_POLICY_WORD] & CDISASM_MIPS_DECODE_FLAG_ALLEGREX) != 0)) &&
        !cdisasm_mips_allegrex_encoding_allowed(raw))
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    /* Release 6 reassigns several primary/SPECIAL encoding slots.  Only exact
     * recognized new forms take priority; other bytes retain core validation. */
    /* Octeon assigns COP2 load/store slots to integer bit branches.  An
     * explicitly selected vendor ISA owns those encodings before the common
     * coprocessor protocol; the generated matcher still requires exact forms. */
    status = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    if (features != NULL && ((features->bitmap[0] | features->bitmap[CDISASM_MIPS_INTERNAL_POLICY_WORD]) &
        CDISASM_MIPS_DECODE_FLAG_XLP) != 0 && cdisasm_mips_xlp_owns(raw)) {
        status = cdisasm_mips_decode_xlp(raw, address, mode, revision, features, instruction);
        goto decoded_vendor;
    }
    if (features != NULL && ((features->bitmap[0] | features->bitmap[CDISASM_MIPS_INTERNAL_POLICY_WORD]) &
        CDISASM_MIPS_DECODE_FLAG_XLR) != 0 && cdisasm_mips_xlr_owns(raw)) {
        status = cdisasm_mips_decode_xlr(raw, address, mode, revision, features, instruction);
        goto decoded_vendor;
    }
    if (features != NULL && ((features->bitmap[0] | features->bitmap[CDISASM_MIPS_INTERNAL_POLICY_WORD]) &
        (CDISASM_MIPS_DECODE_FLAG_MXU2 | CDISASM_MIPS_DECODE_FLAG_MXU3)) != 0) {
        status = cdisasm_mips_decode_mxu_vector(raw, address, mode, revision, features, instruction);
        if (status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION || cdisasm_mips_mxu_vector_owns(raw, features))
            goto decoded_vendor;
    }
    if (features != NULL && ((features->bitmap[0] | features->bitmap[CDISASM_MIPS_INTERNAL_POLICY_WORD]) &
        CDISASM_MIPS_DECODE_FLAG_LOONGASX) != 0) {
        status = cdisasm_mips_decode_loongasx(raw, address, mode, revision, features, instruction);
        if (status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION || cdisasm_mips_loongasx_owns(raw, features))
            goto decoded_vendor;
    }
    if (mips_feature(features, CDISASM_MIPS_DECODE_BIT_LOONGSIMD)) {
        status = cdisasm_mips_decode_loongsimd(raw, address, mode, revision, features, instruction);
        if (status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION || cdisasm_mips_loongsimd_owns(raw))
            goto decoded_vendor;
    }
    if (features != NULL && ((features->bitmap[0] | features->bitmap[CDISASM_MIPS_INTERNAL_POLICY_WORD]) & CDISASM_MIPS_DECODE_FLAG_R5900) != 0 &&
        cdisasm_mips_vu_macro_owns(raw)) {
        status = cdisasm_mips_decode_vu_macro(raw, address, mode, revision, features, instruction);
        goto decoded_vendor;
    }
    if (mips_feature(features, CDISASM_MIPS_DECODE_BIT_ALLEGREX))
        status = cdisasm_mips_decode_allegrex(raw, address, mode, revision, features, instruction);
    if (status == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION &&
        (mips_feature(features, CDISASM_MIPS_DECODE_BIT_ALLEGREX) ||
         (features != NULL && (features->bitmap[CDISASM_MIPS_INTERNAL_POLICY_WORD] & CDISASM_MIPS_DECODE_FLAG_ALLEGREX) != 0)) &&
        cdisasm_mips_allegrex_owns(raw)) return status;
    if (status == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION &&
        (mips_feature(features, CDISASM_MIPS_DECODE_BIT_R5900) ||
         (features != NULL && (features->bitmap[CDISASM_MIPS_INTERNAL_POLICY_WORD] & CDISASM_MIPS_DECODE_FLAG_R5900) != 0)))
        status = cdisasm_mips_decode_r5900(raw, address, mode, revision, features, instruction);
    if (status == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION &&
        (mips_feature(features, CDISASM_MIPS_DECODE_BIT_R5900) ||
         (features != NULL && (features->bitmap[CDISASM_MIPS_INTERNAL_POLICY_WORD] & CDISASM_MIPS_DECODE_FLAG_R5900) != 0)) &&
        cdisasm_mips_r5900_owns(raw)) return status;
    if (status == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION && mips_feature(features, CDISASM_MIPS_DECODE_BIT_MXU))
        status = cdisasm_mips_decode_mxu(raw, address, mode, revision, features, instruction);
    if (status == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION)
    status = mips_feature(features, CDISASM_MIPS_DECODE_BIT_LOONGSON) || mips_feature(features, CDISASM_MIPS_DECODE_BIT_CNMIPS) || mips_feature(features, CDISASM_MIPS_DECODE_BIT_CNMIPSP) ||
             mips_feature(features, CDISASM_MIPS_DECODE_BIT_SMARTMIPS)
                 ? cdisasm_mips_decode_generated(raw, address, mode, revision, features, instruction)
                 : CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    if (status == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION && mips_r6(revision))
        status = cdisasm_mips_decode_extra(raw, address, mode, revision, features, instruction);
    if (status == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        mips_prepare(instruction, raw, address, mode, revision);
        status = mips_main(raw, address, mode, revision, features, instruction);
    }
    if (status == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        /* A rejected family cannot leak its operands into another candidate. */
        mips_prepare(instruction, raw, address, mode, revision);
        status = cdisasm_mips_decode_extra(raw, address, mode, revision, features, instruction);
    }
    if (status == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION || status == CDISASM_STATUS_INVALID_INSTRUCTION) {
        cdisasm_mips_instruction candidate;
        cdisasm_status generated;
        mips_prepare(&candidate, raw, address, mode, revision);
        generated = cdisasm_mips_decode_generated(raw, address, mode, revision, features, &candidate);
        /* The exact generated forms can occupy a field which an older native
         * family reserves.  A failed generated probe cannot weaken that
         * family's invalid-encoding result or expose partial operands. */
        if (generated == CDISASM_STATUS_OK) {
            *instruction = candidate;
            status = generated;
        }
    }
decoded_vendor:
    if (status == CDISASM_STATUS_OK) {
        /* Canonical native forms use the append-only original name ID.  The
         * Release 6 namespace distinguishes reassigned multiply/divide,
         * leading-count and LL/SC encodings from their pre-R6 spellings.
         * Generated DSP rows have independently assigned append-only IDs. */
        if (instruction->form_id == 0u) instruction->form_id = instruction->name_id;
        if (instruction->form_id < 40000u &&
            (instruction->name_id == CDISASM_MIPS_NAME_NOP || instruction->name_id == CDISASM_MIPS_NAME_SSNOP ||
             instruction->name_id == CDISASM_MIPS_NAME_EHB || instruction->name_id == CDISASM_MIPS_NAME_PAUSE))
            instruction->form_id = CDISASM_MIPS_NAME_SLL;
        if (mips_r6(revision) && (instruction->name_id == CDISASM_MIPS_NAME_MUL || instruction->name_id == CDISASM_MIPS_NAME_DIV ||
                                instruction->name_id == CDISASM_MIPS_NAME_DIVU || instruction->name_id == CDISASM_MIPS_NAME_CLZ ||
                                instruction->name_id == CDISASM_MIPS_NAME_CLO || instruction->name_id == CDISASM_MIPS_NAME_DCLZ ||
                                instruction->name_id == CDISASM_MIPS_NAME_DCLO || instruction->name_id == CDISASM_MIPS_NAME_LL ||
                                instruction->name_id == CDISASM_MIPS_NAME_LLD || instruction->name_id == CDISASM_MIPS_NAME_SC ||
                                instruction->name_id == CDISASM_MIPS_NAME_SCD || instruction->name_id == CDISASM_MIPS_NAME_SDBBP ||
                                instruction->name_id == CDISASM_MIPS_NAME_DDIV || instruction->name_id == CDISASM_MIPS_NAME_DDIVU))
            instruction->form_id = (cdisasm_mips_form_id)(UINT16_C(4096) + instruction->name_id);
        if ((unsigned)revision <= 2u || revision == CDISASM_MIPS_REVISION_32R1 || mips_feature(features, 12u))
            instruction->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_FPR32;
        if (instruction->form_id < 40000u) {
            mips_implicit_semantics(instruction, mips_r6(revision));
            mips_fp_semantics(instruction, mips_r6(revision));
        }
        instruction->last_error_id = (uint8_t)CDISASM_STATUS_OK;
    }
    return status;
}
