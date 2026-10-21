#include "mips_decoder.h"

#if USE_EXTRA_OPCODES

/* Encoding facts verified against LLVM 21.1.8 Mips{DSP,MT,32r6,64r6}
 * Instr{Info,Formats}.td, commit 2078da43e25a4623cab2d0d60decddf709aaea28.
 * The LLVM inventory derives from Apache-2.0 WITH LLVM-exception source.
 * Historical DSP64 rows retain architectural numeric facts, independently
 * cross-checked against GNU assembler tests; operand recipes are authored
 * locally. See the generator manifest for the separate source provenance. */

typedef struct mips_extension_operand {
    uint8_t kind, lsb, width, size, access, aux;
    uint8_t lane_kind, lane_lsb, lane_width, element_size;
} mips_extension_operand;
typedef struct mips_extension_form {
    uint32_t mask, value;
    cdisasm_mips_name_id name;
    cdisasm_mips_form_id form;
    uint32_t effects;
    uint8_t feature_bit, wide, delay, store, count, special;
    mips_extension_operand operand[4];
} mips_extension_form;
#include "generated/mips_dsp_forms.inc"

uint64_t cdisasm_mips_extra_required_flags(cdisasm_mips_form_id form)
{
    size_t n;
    if (form >= 18000u && form < 19000u) {
        for (n=0; n<sizeof(mips_extension_forms)/sizeof(mips_extension_forms[0]); ++n) {
            const mips_extension_form *f=&mips_extension_forms[n];
            if (f->form==form)
                return CDISASM_MIPS_DECODE_FLAG_DSP | CDISASM_MIPS_DECODE_FLAG_DSP64 |
                    (f->special==4u ? CDISASM_MIPS_DECODE_FLAG_DSPR2 : 0);
        }
    }
    return 0;
}

static int extra_feature(const cdisasm_mips_decode_flags *f, unsigned bit)
{
    return f != NULL && (f->bitmap[0] & (UINT64_C(1) << bit)) != 0u;
}
static int extra_r6(cdisasm_mips_revision r) { return r == CDISASM_MIPS_REVISION_32R6 || r == CDISASM_MIPS_REVISION_64R6; }
static int extra_r2(cdisasm_mips_revision r) { return r == CDISASM_MIPS_REVISION_32R2 || r == CDISASM_MIPS_REVISION_32R3 || r == CDISASM_MIPS_REVISION_32R5 || r == CDISASM_MIPS_REVISION_64R2 || r == CDISASM_MIPS_REVISION_64R3 || r == CDISASM_MIPS_REVISION_64R5; }
static int64_t extra_sign(uint32_t value, unsigned bits)
{
    uint32_t sign = UINT32_C(1) << (bits - 1u);
    return (int64_t)(value ^ sign) - (int64_t)sign;
}
static uint64_t extra_address(cdisasm_mips_mode mode, uint64_t value) { return mode == CDISASM_MIPS_MODE_64 ? value : (uint64_t)(uint32_t)value; }
static void extra_reg(cdisasm_mips_instruction *i, unsigned reg, uint8_t size, cdisasm_operand_access access)
{
    cdisasm_mips_operand *o = &i->operand[i->operand_count++];
    o->type = CDISASM_OPERAND_REGISTER;
    o->reg = (uint16_t)(CDISASM_MIPS_REG_GPR0 + reg);
    o->size = size;
    o->access = access;
}
static void extra_imm(cdisasm_mips_instruction *i, uint64_t value, uint8_t size, uint8_t flags)
{
    cdisasm_mips_operand *o = &i->operand[i->operand_count++];
    o->type = CDISASM_OPERAND_IMMEDIATE;
    o->imm = value;
    o->size = size;
    o->flags = flags;
    o->access = CDISASM_OPERAND_ACCESS_READ;
}
static cdisasm_status extra_name(cdisasm_mips_instruction *i, cdisasm_mips_name_id name)
{
    i->name_id = name;
    return CDISASM_STATUS_OK;
}
static cdisasm_status extra_three(cdisasm_mips_instruction *i, cdisasm_mips_name_id name, unsigned rd, unsigned rs, unsigned rt, uint8_t size)
{
    extra_reg(i, rd, size, CDISASM_OPERAND_ACCESS_WRITE);
    extra_reg(i, rs, size, CDISASM_OPERAND_ACCESS_READ);
    extra_reg(i, rt, size, CDISASM_OPERAND_ACCESS_READ);
    return extra_name(i, name);
}
static cdisasm_status extra_branch(cdisasm_mips_instruction *i, cdisasm_mips_name_id name, unsigned rs, unsigned rt, unsigned count,
                                  uint32_t offset, unsigned bits, int link)
{
    cdisasm_mips_operand *o;
    int64_t displacement = extra_sign(offset, bits) * INT64_C(4);
    uint8_t size = i->mode == CDISASM_MIPS_MODE_64 ? 8u : 4u;
    if (count > 0u) extra_reg(i, rs, size, CDISASM_OPERAND_ACCESS_READ);
    if (count > 1u) extra_reg(i, rt, size, CDISASM_OPERAND_ACCESS_READ);
    o = &i->operand[i->operand_count++];
    o->type = CDISASM_OPERAND_IMMEDIATE;
    o->imm = extra_address((cdisasm_mips_mode)i->mode, i->address + UINT64_C(4) + (uint64_t)displacement);
    o->address = (uint64_t)displacement;
    o->size = size;
    o->flags = CDISASM_MIPS_OPERAND_FLAG_RELATIVE | CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS;
    o->access = CDISASM_OPERAND_ACCESS_READ;
    i->branch_target = o->imm;
    i->opcode_groups = CDISASM_GROUP_JUMP | CDISASM_GROUP_RELATIVE_BRANCH | (count ? CDISASM_GROUP_CONDITIONAL : 0u) | (link ? CDISASM_GROUP_CALL : 0u);
    i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_COMPACT_BRANCH;
    return extra_name(i, name);
}
static uint32_t extra_field(uint32_t w, unsigned lsb, unsigned width)
{
    return width == 0u ? 0u : (w >> lsb) & ((UINT32_C(1) << width) - 1u);
}
static cdisasm_status extra_generated(uint32_t w, cdisasm_mips_revision rev,
                                      const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *i)
{
    size_t n;
    unsigned a;
    cdisasm_mips_mode mode = (cdisasm_mips_mode)i->mode;
    for (n = 0u; n < sizeof(mips_extension_forms) / sizeof(mips_extension_forms[0]); ++n) {
        const mips_extension_form *f = &mips_extension_forms[n];
        int msa = f->feature_bit == CDISASM_MIPS_DECODE_BIT_MSA;
        if ((w & f->mask) != f->value) continue;
        if (msa) {
            const uint64_t physical_msa = CDISASM_MIPS_DECODE_FLAG_MSA | CDISASM_MIPS_DECODE_FLAG_LOONGSIMD;
            const int loongson_msa = extra_feature(features, CDISASM_MIPS_DECODE_BIT_LOONGSIMD) ||
                (features != NULL && (features->bitmap[CDISASM_MIPS_INTERNAL_POLICY_WORD] & physical_msa) == physical_msa);
            /* 3A4000 implements the documented MIPS MSA module alongside its
             * MIPS64r2 base ISA. This physical extension does not upgrade all
             * scalar instructions to a later standard ISA revision. Private
             * physical eligibility preserves disabled-family status; active
             * MSA and FPU are still required below for successful lowering. */
            if (rev != CDISASM_MIPS_REVISION_32R5 && rev != CDISASM_MIPS_REVISION_64R5 && !extra_r6(rev) &&
                !(rev == CDISASM_MIPS_REVISION_64R2 && loongson_msa))
                return CDISASM_STATUS_INVALID_INSTRUCTION;
            if (extra_feature(features, CDISASM_MIPS_DECODE_BIT_FPR32)) return CDISASM_STATUS_INVALID_INSTRUCTION;
            if (!extra_feature(features, CDISASM_MIPS_DECODE_BIT_MSA) || !extra_feature(features, CDISASM_MIPS_DECODE_BIT_FPU))
                return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        } else {
            /* DSP Module3 retains Rev1/2 arithmetic and accumulator forms
             * at Release6. Its branch is compact BPOSGE32C; the historical
             * 64-bit forms remain pre-Release6 only. See MD00375r3.02,
             * sections3.10/3.11 and6.1. */
            if (extra_r6(rev)) {
                if (f->feature_bit==CDISASM_MIPS_DECODE_BIT_DSP64) continue;
                if (f->name==CDISASM_MIPS_NAME_BPOSGE32) return CDISASM_STATUS_INVALID_INSTRUCTION;
                if (!extra_feature(features,CDISASM_MIPS_DECODE_BIT_DSPR3) ||
                    !extra_feature(features,CDISASM_MIPS_DECODE_BIT_DSPR2)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
            } else if (!extra_r2(rev) || f->feature_bit==CDISASM_MIPS_DECODE_BIT_DSPR3)
                return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
            if (!extra_feature(features, CDISASM_MIPS_DECODE_BIT_DSP) || !extra_feature(features, f->feature_bit))
                return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
            if (f->special==4u && !extra_feature(features, CDISASM_MIPS_DECODE_BIT_DSPR2))
                return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        if (f->wide && mode != CDISASM_MIPS_MODE_64) return CDISASM_STATUS_INVALID_INSTRUCTION;
        if (f->special == 1u) {
            unsigned mask = f->name == CDISASM_MIPS_NAME_RDDSP ? (w >> 16) & 1023u : (w >> 11) & 1023u;
            if (mask > 63u) return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        i->instruction_flags |= f->effects | (msa ? CDISASM_MIPS_INSTRUCTION_FLAG_MSA : CDISASM_MIPS_INSTRUCTION_FLAG_DSP);
        if (f->feature_bit == CDISASM_MIPS_DECODE_BIT_DSPR2 || f->special==4u) i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_DSPR2;
        if (!msa && extra_r6(rev)) i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_DSPR2|CDISASM_MIPS_INSTRUCTION_FLAG_DSPR3;
        i->form_id = f->form;
        i->name_id = f->name;
        for (a = 0u; a < f->count; ++a) {
            const mips_extension_operand *d = &f->operand[a];
            cdisasm_mips_operand *o = &i->operand[i->operand_count++];
            uint32_t value = extra_field(w, d->lsb, d->width);
            o->size = d->size;
            o->access = d->access;
            if (d->kind <= 4u) {
                static const uint16_t banks[4] = {CDISASM_MIPS_REG_GPR0, CDISASM_MIPS_REG_ACC0,
                                                  CDISASM_MIPS_REG_MSA0, CDISASM_MIPS_REG_MSACTRL0};
                o->type = CDISASM_OPERAND_REGISTER;
                if (d->kind == 4u && value > 7u) return CDISASM_STATUS_INVALID_INSTRUCTION;
                o->reg = (uint16_t)(banks[d->kind - 1u] + value);
                if (d->kind == 2u) {
                    o->detail.flags = d->aux;
                    if (f->special == 2u) { o->detail.flags |= CDISASM_MIPS_OPERAND_DETAIL_HIGH_HALF; o->size = 4u; }
                    if (f->special == 3u) o->size = 4u;
                }
                /* Preserve the stable operand shape of the original MSA
                 * arithmetic slice; element metadata is needed for lanes. */
                if (d->lane_kind) {
                    uint32_t lane = extra_field(w, d->lane_lsb, d->lane_width);
                    o->detail.flags |= CDISASM_MIPS_OPERAND_DETAIL_HAS_LANE;
                    o->detail.element_size = d->element_size;
                    if (d->lane_kind == 2u) {
                        o->detail.flags |= CDISASM_MIPS_OPERAND_DETAIL_LANE_REGISTER;
                        o->index_reg = (uint16_t)(CDISASM_MIPS_REG_GPR0 + lane);
                    } else o->detail.lane_index = (uint8_t)lane;
                }
            } else if (d->kind == 5u || d->kind == 6u) {
                o->type = CDISASM_OPERAND_IMMEDIATE;
                o->imm = d->kind == 6u ? (uint64_t)extra_sign(value, d->width) : (uint64_t)(value + d->aux);
                if (d->kind == 6u) o->flags = CDISASM_MIPS_OPERAND_FLAG_SIGNED;
            } else if (d->kind == 7u || d->kind == 8u) {
                int64_t displacement = d->kind == 7u ? extra_sign(value, d->width) * (INT64_C(1) << d->aux) : 0;
                unsigned base = d->kind == 7u ? (w >> 11) & 31u : value;
                o->type = CDISASM_OPERAND_MEMORY;
                o->base_reg = (uint16_t)(CDISASM_MIPS_REG_GPR0 + base);
                o->imm = (uint64_t)displacement;
                o->access = f->store ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ;
                if (d->kind == 7u) o->flags = CDISASM_MIPS_OPERAND_FLAG_SIGNED | CDISASM_MIPS_OPERAND_FLAG_HAS_DISPLACEMENT;
                else o->index_reg = (uint16_t)(CDISASM_MIPS_REG_GPR0 + extra_field(w, d->lane_lsb, d->lane_width));
                if (base == 0u && (d->kind == 7u || o->index_reg == CDISASM_MIPS_REG_GPR0)) {
                    o->address = extra_address(mode, (uint64_t)displacement);
                    o->flags |= CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS | CDISASM_MIPS_OPERAND_FLAG_ABSOLUTE;
                }
            } else if (d->kind == 9u) {
                int64_t displacement = extra_sign(value, d->width) * INT64_C(4);
                o->type = CDISASM_OPERAND_IMMEDIATE;
                o->size = mode == CDISASM_MIPS_MODE_64 ? 8u : 4u;
                o->imm = extra_address(mode, i->address + UINT64_C(4) + (uint64_t)displacement);
                o->address = (uint64_t)displacement;
                o->flags = CDISASM_MIPS_OPERAND_FLAG_RELATIVE | CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS;
                i->branch_target = o->imm;
                i->opcode_groups |= CDISASM_GROUP_JUMP | CDISASM_GROUP_CONDITIONAL | CDISASM_GROUP_RELATIVE_BRANCH;
                if (f->delay) i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_DELAY_SLOT;
                else i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_COMPACT_BRANCH;
            }
        }
        return CDISASM_STATUS_OK;
    }
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}
static cdisasm_status extra_mt(uint32_t w, cdisasm_mips_revision rev, const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *i)
{
    unsigned op = w >> 26, rs = (w >> 21) & 31u, rt = (w >> 16) & 31u, rd = (w >> 11) & 31u, sa = (w >> 6) & 31u, fn = w & 63u;
    cdisasm_mips_name_id name;
    if (!extra_r2(rev)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    if (op == 31u && (fn == 8u || fn == 9u)) {
        if (sa != 0u || (fn == 9u && rt != 0u)) return CDISASM_STATUS_INVALID_INSTRUCTION;
        if (!extra_feature(features, 4u)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_MT;
        extra_reg(i, rd, 4u, CDISASM_OPERAND_ACCESS_WRITE);
        if (fn == 8u) i->operand[0].flags |= CDISASM_MIPS_OPERAND_FLAG_THREAD_REGISTER;
        extra_reg(i, rs, 4u, CDISASM_OPERAND_ACCESS_READ);
        if (fn == 8u) extra_reg(i, rt, 4u, CDISASM_OPERAND_ACCESS_READ);
        return extra_name(i, fn == 8u ? CDISASM_MIPS_NAME_FORK : CDISASM_MIPS_NAME_YIELD);
    }
    if (op != 16u) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    if (rs == 11u && (w & UINT32_C(0xffff)) == UINT32_C(0x0bc1)) name = CDISASM_MIPS_NAME_DMT;
    else if (rs == 11u && (w & UINT32_C(0xffff)) == UINT32_C(0x0be1)) name = CDISASM_MIPS_NAME_EMT;
    else if (rs == 11u && (w & UINT32_C(0xffff)) == UINT32_C(0x0001)) name = CDISASM_MIPS_NAME_DVPE;
    else if (rs == 11u && (w & UINT32_C(0xffff)) == UINT32_C(0x0021)) name = CDISASM_MIPS_NAME_EVPE;
    else if (rs == 8u || rs == 12u) {
        unsigned u = (w >> 5) & 1u, sel = w & 7u, remote = rs == 8u ? rt : rd;
        unsigned high = (w >> 4) & 1u;
        cdisasm_mips_operand *remote_operand;
        if ((w & 8u) != 0u) return CDISASM_STATUS_INVALID_INSTRUCTION;
        if ((w & UINT32_C(0x7c0)) != 0u)
            return u && (sel == 4u || sel == 5u) ? CDISASM_STATUS_UNSUPPORTED_INSTRUCTION : CDISASM_STATUS_INVALID_INSTRUCTION;
        if (u && (sel > 5u || (sel == 1u && remote != 16u && ((remote & 3u) == 3u || remote > 14u))))
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        if (!extra_feature(features, 4u)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_MT;
        i->opcode_groups |= CDISASM_GROUP_PRIVILEGED;
        /* MFTR uses rd as the local destination and rt as the remote register
         * selector; MTTR's assembly order reverses those encoding fields. */
        extra_reg(i, rs == 8u ? rd : rt, 4u, rs == 8u ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ);
        extra_reg(i, remote, 4u, rs == 8u ? CDISASM_OPERAND_ACCESS_READ : u && sel == 2u ? CDISASM_OPERAND_ACCESS_READ_WRITE : CDISASM_OPERAND_ACCESS_WRITE);
        remote_operand = &i->operand[1];
        remote_operand->flags |= CDISASM_MIPS_OPERAND_FLAG_THREAD_REGISTER;
        if (!u) remote_operand->reg = CDISASM_MIPS_REG_CP0(remote, sel);
        else if (sel == 1u) {
            if (remote == 16u) {
                remote_operand->reg = CDISASM_MIPS_REG_DSPCONTROL;
                i->instruction_flags |= rs == 8u ? CDISASM_MIPS_INSTRUCTION_FLAG_READS_DSPCONTROL : CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_DSPCONTROL;
            } else {
                remote_operand->reg = (uint16_t)(CDISASM_MIPS_REG_ACC0 + remote / 4u);
                if ((remote & 3u) == 1u) remote_operand->detail.flags |= CDISASM_MIPS_OPERAND_DETAIL_HIGH_HALF;
                if ((remote & 3u) == 2u) remote_operand->detail.flags |= CDISASM_MIPS_OPERAND_DETAIL_ACC_EXTENSION;
            }
        } else if (sel == 2u) {
            remote_operand->reg = (uint16_t)(CDISASM_MIPS_REG_FPR0 + remote);
            if (high) remote_operand->detail.flags |= CDISASM_MIPS_OPERAND_DETAIL_HIGH_HALF;
            i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_FLOATING_POINT;
        } else if (sel == 3u) {
            remote_operand->reg = (uint16_t)(CDISASM_MIPS_REG_FCR0 + remote);
            i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_FLOATING_POINT;
            i->instruction_flags |= rs == 8u ? CDISASM_MIPS_INSTRUCTION_FLAG_READS_FCSR : CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_FCSR;
        } else if (sel == 4u) {
            remote_operand->reg = CDISASM_MIPS_REG_COP2(remote, 0u);
            if (high) remote_operand->detail.flags |= CDISASM_MIPS_OPERAND_DETAIL_HIGH_HALF;
        } else if (sel == 5u) remote_operand->reg = (uint16_t)(CDISASM_MIPS_REG_FCR2_FIRST + remote);
        extra_imm(i, (w >> 5) & 1u, 1u, 0u);
        extra_imm(i, w & 7u, 1u, 0u);
        extra_imm(i, (w >> 4) & 1u, 1u, 0u);
        return extra_name(i, rs == 8u ? CDISASM_MIPS_NAME_MFTR : CDISASM_MIPS_NAME_MTTR);
    } else return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    if (!extra_feature(features, 4u)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_MT;
    i->opcode_groups |= CDISASM_GROUP_PRIVILEGED;
    extra_reg(i, rt, 4u, CDISASM_OPERAND_ACCESS_WRITE);
    return extra_name(i, name);
}
static cdisasm_status extra_pcrel(uint32_t w, cdisasm_mips_mode mode, cdisasm_mips_instruction *i)
{
    unsigned rs=(w>>21)&31u, selector=(w>>19)&3u;
    int64_t displacement;
    uint64_t target;
    int memory=0;
    uint8_t width=4u;
    cdisasm_mips_name_id name;
    cdisasm_mips_operand *o;
    if(selector<3u) {
        displacement=extra_sign(w&UINT32_C(0x7ffff),19u)*INT64_C(4);
        name=selector==0u ? CDISASM_MIPS_NAME_ADDIUPC : selector==1u ? CDISASM_MIPS_NAME_LWPC : CDISASM_MIPS_NAME_LWUPC;
        memory=selector!=0u;
        if(selector==2u && mode!=CDISASM_MIPS_MODE_64) return CDISASM_STATUS_INVALID_INSTRUCTION;
        target=extra_address(mode,i->address+(uint64_t)displacement);
    } else if(((w>>18)&7u)==6u) {
        if(mode!=CDISASM_MIPS_MODE_64) return CDISASM_STATUS_INVALID_INSTRUCTION;
        displacement=extra_sign(w&UINT32_C(0x3ffff),18u)*INT64_C(8);
        target=(i->address&~UINT64_C(7))+(uint64_t)displacement;
        name=CDISASM_MIPS_NAME_LDPC; memory=1; width=8u;
    } else if(((w>>16)&31u)>=30u) {
        displacement=extra_sign(w&65535u,16u)*INT64_C(65536);
        name=((w>>16)&31u)==30u ? CDISASM_MIPS_NAME_AUIPC : CDISASM_MIPS_NAME_ALUIPC;
        target=extra_address(mode,i->address+(uint64_t)displacement);
        if(name==CDISASM_MIPS_NAME_ALUIPC) target &= ~UINT64_C(65535);
    } else return CDISASM_STATUS_INVALID_INSTRUCTION;
    extra_reg(i,rs,mode==CDISASM_MIPS_MODE_64 ? 8u : 4u,CDISASM_OPERAND_ACCESS_WRITE);
    o=&i->operand[i->operand_count++];
    o->type=memory ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_IMMEDIATE;
    o->size=memory ? width : mode==CDISASM_MIPS_MODE_64 ? 8u : 4u;
    o->access=CDISASM_OPERAND_ACCESS_READ;
    if(memory) {
        o->imm=(uint64_t)displacement; o->address=target;
        o->flags=CDISASM_MIPS_OPERAND_FLAG_PC_RELATIVE|CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS|
                 CDISASM_MIPS_OPERAND_FLAG_HAS_DISPLACEMENT|CDISASM_MIPS_OPERAND_FLAG_SIGNED;
    } else {
        o->imm=target; o->address=(uint64_t)displacement;
        o->flags=CDISASM_MIPS_OPERAND_FLAG_PC_RELATIVE|CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS;
    }
    return extra_name(i,name);
}
static cdisasm_status extra_release6(uint32_t w, cdisasm_mips_mode mode, cdisasm_mips_revision rev, cdisasm_mips_instruction *i)
{
    unsigned op = w >> 26, rs = (w >> 21) & 31u, rt = (w >> 16) & 31u, rd = (w >> 11) & 31u, sa = (w >> 6) & 31u, fn = w & 63u;
    uint8_t size = mode == CDISASM_MIPS_MODE_64 ? 8u : 4u;
    cdisasm_mips_name_id name;
    if (!extra_r6(rev)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    if(op==59u) return extra_pcrel(w,mode,i);
    if(op==31u && ((fn==32u && (sa>>2)==2u) || (fn==36u && (sa>>3)==1u))) {
        int wide=fn==36u;
        if(wide && mode!=CDISASM_MIPS_MODE_64) return CDISASM_STATUS_INVALID_INSTRUCTION;
        extra_three(i,wide ? CDISASM_MIPS_NAME_DALIGN : CDISASM_MIPS_NAME_ALIGN,rd,rs,rt,wide ? 8u : 4u);
        extra_imm(i,sa&(wide ? 7u : 3u),1u,0u);
        return CDISASM_STATUS_OK;
    }
    if(op==1u && (rt==6u || rt==30u)) {
        if(mode!=CDISASM_MIPS_MODE_64) return CDISASM_STATUS_INVALID_INSTRUCTION;
        extra_reg(i,rs,8u,CDISASM_OPERAND_ACCESS_READ_WRITE);
        extra_imm(i,w&65535u,2u,0u);
        return extra_name(i,rt==6u ? CDISASM_MIPS_NAME_DAHI : CDISASM_MIPS_NAME_DATI);
    }
    if(op==1u && rs==0u && rt==23u) {
        extra_imm(i,w&65535u,2u,0u); i->opcode_groups=CDISASM_GROUP_INTERRUPT;
        return extra_name(i,CDISASM_MIPS_NAME_SIGRIE);
    }
    if(op==31u && (fn==37u || fn==53u)) {
        cdisasm_mips_operand *o;
        if(w&64u) return CDISASM_STATUS_INVALID_INSTRUCTION;
        extra_imm(i,rt,1u,0u);
        o=&i->operand[i->operand_count++]; o->type=CDISASM_OPERAND_MEMORY;
        o->base_reg=(uint16_t)(CDISASM_MIPS_REG_GPR0+rs); o->imm=(uint64_t)extra_sign((w>>7)&511u,9u);
        o->flags=CDISASM_MIPS_OPERAND_FLAG_HAS_DISPLACEMENT|CDISASM_MIPS_OPERAND_FLAG_SIGNED|CDISASM_OPERAND_FLAG_ADDRESS_ONLY;
        o->access=CDISASM_OPERAND_ACCESS_READ;
        if(rs==0u) {o->address=extra_address(mode,o->imm);o->flags|=CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS|CDISASM_MIPS_OPERAND_FLAG_ABSOLUTE;}
        if(fn==37u) i->opcode_groups=CDISASM_GROUP_PRIVILEGED;
        return extra_name(i,fn==37u ? CDISASM_MIPS_NAME_CACHE : CDISASM_MIPS_NAME_PREF);
    }
    if ((op == 15u && rs != 0u) || op == 29u) {
        if (op == 29u && mode != CDISASM_MIPS_MODE_64) return CDISASM_STATUS_INVALID_INSTRUCTION;
        extra_reg(i, rt, op == 29u ? 8u : 4u, CDISASM_OPERAND_ACCESS_WRITE);
        extra_reg(i, rs, op == 29u ? 8u : 4u, CDISASM_OPERAND_ACCESS_READ);
        extra_imm(i, (uint64_t)extra_sign(w & 65535u, 16u), 2u, CDISASM_MIPS_OPERAND_FLAG_SIGNED);
        return extra_name(i, op == 29u ? CDISASM_MIPS_NAME_DAUI : CDISASM_MIPS_NAME_AUI);
    }
    if (op == 0u && (fn == 53u || fn == 55u)) {
        if (sa != 0u) return CDISASM_STATUS_INVALID_INSTRUCTION;
        return extra_three(i, fn == 53u ? CDISASM_MIPS_NAME_SELEQZ : CDISASM_MIPS_NAME_SELNEZ, rd, rs, rt, size);
    }
    if (op == 0u && (fn == 5u || fn == 21u)) {
        if (sa > 3u || (fn == 21u && mode != CDISASM_MIPS_MODE_64)) return CDISASM_STATUS_INVALID_INSTRUCTION;
        extra_three(i, fn == 5u ? CDISASM_MIPS_NAME_LSA : CDISASM_MIPS_NAME_DLSA, rd, rs, rt, fn == 5u ? 4u : 8u);
        extra_imm(i, sa + 1u, 1u, 0u);
        return CDISASM_STATUS_OK;
    }
    if (op == 0u && fn >= 28u && fn <= 31u) {
        if (mode != CDISASM_MIPS_MODE_64 || (sa != 2u && sa != 3u)) return CDISASM_STATUS_INVALID_INSTRUCTION;
        name = fn == 28u ? (sa == 2u ? CDISASM_MIPS_NAME_DMUL : CDISASM_MIPS_NAME_DMUH)
             : fn == 29u ? (sa == 2u ? CDISASM_MIPS_NAME_DMULU : CDISASM_MIPS_NAME_DMUHU)
             : fn == 30u ? (sa == 2u ? CDISASM_MIPS_NAME_DDIV : CDISASM_MIPS_NAME_DMOD)
                          : (sa == 2u ? CDISASM_MIPS_NAME_DDIVU : CDISASM_MIPS_NAME_DMODU);
        return extra_three(i, name, rd, rs, rt, 8u);
    }
    if (op == 31u && (fn == 32u || fn == 36u) && rs == 0u && sa == 0u) {
        if (fn == 36u && mode != CDISASM_MIPS_MODE_64) return CDISASM_STATUS_INVALID_INSTRUCTION;
        extra_reg(i, rd, fn == 36u ? 8u : 4u, CDISASM_OPERAND_ACCESS_WRITE);
        extra_reg(i, rt, fn == 36u ? 8u : 4u, CDISASM_OPERAND_ACCESS_READ);
        return extra_name(i, fn == 32u ? CDISASM_MIPS_NAME_BITSWAP : CDISASM_MIPS_NAME_DBITSWAP);
    }
    if (op == 50u || op == 58u) return extra_branch(i, op == 50u ? CDISASM_MIPS_NAME_BC : CDISASM_MIPS_NAME_BALC, 0u, 0u, 0u, w & UINT32_C(0x3ffffff), 26u, op == 58u);
    if (op == 54u || op == 62u) {
        if (rs != 0u) return extra_branch(i, op == 54u ? CDISASM_MIPS_NAME_BEQZC : CDISASM_MIPS_NAME_BNEZC, rs, 0u, 1u, w & UINT32_C(0x1fffff), 21u, 0);
        extra_reg(i, rt, size, CDISASM_OPERAND_ACCESS_READ);
        extra_imm(i, (uint64_t)extra_sign(w & 65535u, 16u), 2u, CDISASM_MIPS_OPERAND_FLAG_SIGNED);
        i->opcode_groups = CDISASM_GROUP_JUMP | (op == 62u ? CDISASM_GROUP_CALL : 0u) | (op == 54u && rt == 31u ? CDISASM_GROUP_RETURN : 0u);
        i->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_COMPACT_BRANCH;
        return extra_name(i, op == 54u ? CDISASM_MIPS_NAME_JIC : CDISASM_MIPS_NAME_JIALC);
    }
    if (op == 8u || op == 24u) {
        if (rs == 0u && rt != 0u) return extra_branch(i, op == 8u ? CDISASM_MIPS_NAME_BEQZALC : CDISASM_MIPS_NAME_BNEZALC, rt, 0u, 1u, w & 65535u, 16u, 1);
        name = rs < rt ? (op == 8u ? CDISASM_MIPS_NAME_BEQC : CDISASM_MIPS_NAME_BNEC) : (op == 8u ? CDISASM_MIPS_NAME_BOVC : CDISASM_MIPS_NAME_BNVC);
        return extra_branch(i, name, rs, rt, 2u, w & 65535u, 16u, 0);
    }
    if ((op == 6u || op == 7u) && rt != 0u) {
        if (rs == 0u || rs == rt) {
            name = op == 6u ? (rs == 0u ? CDISASM_MIPS_NAME_BLEZALC : CDISASM_MIPS_NAME_BGEZALC)
                           : (rs == 0u ? CDISASM_MIPS_NAME_BGTZALC : CDISASM_MIPS_NAME_BLTZALC);
            return extra_branch(i, name, rt, 0u, 1u, w & 65535u, 16u, 1);
        }
        return extra_branch(i, op == 6u ? CDISASM_MIPS_NAME_BGEUC : CDISASM_MIPS_NAME_BLTUC, rs, rt, 2u, w & 65535u, 16u, 0);
    }
    if (op == 22u || op == 23u) {
        if (rt == 0u) return CDISASM_STATUS_INVALID_INSTRUCTION;
        if (rs == 0u || rs == rt) {
            name = op == 22u ? (rs == 0u ? CDISASM_MIPS_NAME_BLEZC : CDISASM_MIPS_NAME_BGEZC)
                            : (rs == 0u ? CDISASM_MIPS_NAME_BGTZC : CDISASM_MIPS_NAME_BLTZC);
            return extra_branch(i, name, rt, 0u, 1u, w & 65535u, 16u, 0);
        }
        return extra_branch(i, op == 22u ? CDISASM_MIPS_NAME_BGEC : CDISASM_MIPS_NAME_BLTC, rs, rt, 2u, w & 65535u, 16u, 0);
    }
    if (op == 31u && (fn == 54u || fn == 55u || fn == 38u || fn == 39u)) {
        cdisasm_mips_operand *o;
        int wide = fn == 55u || fn == 39u, store = fn == 38u || fn == 39u;
        if ((w & 64u) != 0u || (wide && mode != CDISASM_MIPS_MODE_64)) return CDISASM_STATUS_INVALID_INSTRUCTION;
        extra_reg(i, rt, size, store ? CDISASM_OPERAND_ACCESS_READ_WRITE : CDISASM_OPERAND_ACCESS_WRITE);
        o = &i->operand[i->operand_count++];
        o->type = CDISASM_OPERAND_MEMORY;
        o->base_reg = (uint16_t)(CDISASM_MIPS_REG_GPR0 + rs);
        o->imm = (uint64_t)extra_sign((w >> 7) & 511u, 9u);
        o->size = wide ? 8u : 4u;
        o->flags = CDISASM_MIPS_OPERAND_FLAG_SIGNED | CDISASM_MIPS_OPERAND_FLAG_HAS_DISPLACEMENT;
        o->access = store ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ;
        return extra_name(i, wide ? (store ? CDISASM_MIPS_NAME_SCD : CDISASM_MIPS_NAME_LLD) : (store ? CDISASM_MIPS_NAME_SC : CDISASM_MIPS_NAME_LL));
    }
    if (op == 0u && fn >= 16u && fn <= 19u && rt == 0u && sa == 1u) {
        int wide = fn >= 18u;
        if (wide && mode != CDISASM_MIPS_MODE_64) return CDISASM_STATUS_INVALID_INSTRUCTION;
        extra_reg(i, rd, wide ? 8u : 4u, CDISASM_OPERAND_ACCESS_WRITE);
        extra_reg(i, rs, wide ? 8u : 4u, CDISASM_OPERAND_ACCESS_READ);
        name = fn == 16u ? CDISASM_MIPS_NAME_CLZ : fn == 17u ? CDISASM_MIPS_NAME_CLO : fn == 18u ? CDISASM_MIPS_NAME_DCLZ : CDISASM_MIPS_NAME_DCLO;
        return extra_name(i, name);
    }
    if (op == 0u && fn == 14u) {
        extra_imm(i, (w >> 6) & UINT32_C(0xfffff), 4u, 0u);
        i->opcode_groups = CDISASM_GROUP_INTERRUPT;
        return extra_name(i, CDISASM_MIPS_NAME_SDBBP);
    }
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}

cdisasm_status cdisasm_mips_decode_extra(uint32_t raw, uint64_t address, cdisasm_mips_mode mode, cdisasm_mips_revision revision,
                                       const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *instruction)
{
    cdisasm_status status;
    (void)address;
    if (extra_r6(revision) && extra_feature(features,CDISASM_MIPS_DECODE_BIT_DSPR3)) {
        status = extra_generated(raw, revision, features, instruction);
        if (status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) return status;
    }
    status = extra_release6(raw, mode, revision, instruction);
    if (status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) return status;
    status = extra_generated(raw, revision, features, instruction);
    if (status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) return status;
    status = extra_mt(raw, revision, features, instruction);
    if (status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) return status;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}

#else
uint64_t cdisasm_mips_extra_required_flags(cdisasm_mips_form_id form)
{
    (void)form;
    return 0;
}

cdisasm_status cdisasm_mips_decode_extra(uint32_t raw, uint64_t address, cdisasm_mips_mode mode, cdisasm_mips_revision revision,
                                       const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *instruction)
{
    (void)raw; (void)address; (void)mode; (void)revision; (void)features; (void)instruction;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}
#endif
