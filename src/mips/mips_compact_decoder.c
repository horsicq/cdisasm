/* Copyright (c) 2026 hors<horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 * Native typed lowering; numerical encoding/operand facts are generated from
 * pinned LLVM21.1.8, Apache-2.0 WITH LLVM-exception. See generated manifest.
 */
#include "mips_decoder.h"
#include <string.h>

uint32_t cdisasm_mips_compact_size(cdisasm_mips_encoding encoding, uint16_t first)
{
    if ((unsigned)encoding == 1u) return (first>>11)==30u || (first>>11)==3u ? 4u : 2u;
    if ((unsigned)encoding == 2u) {
        unsigned prefix=(first>>10)&7u;
        return prefix>=1u && prefix<=3u ? 2u : 4u;
    }
    return 0u;
}

#if USE_EXTRA_OPCODES
typedef struct compact_piece { uint8_t lsb, width, destination; } compact_piece;
typedef struct compact_field { uint8_t width; compact_piece piece[5]; } compact_field;
/* kind, encoded field, secondary field, bytes, access, transformation, scale */
typedef struct compact_operand { uint16_t kind, field, secondary, size, access, aux, scale; } compact_operand;
typedef struct compact_form {
    uint32_t mask, value;
    uint64_t required;
    uint32_t effects, groups;
    uint16_t name, form, revisions;
    uint8_t encoding, size, fr, count, special;
    compact_operand operand[6];
} compact_form;
typedef struct compact_effect { uint16_t form,reg;uint8_t access,size; } compact_effect;
#include "generated/mips_compact_forms.inc"

/* MD00594r6.05 supplement absent from the pinned LLVM/GNU inventories. */
typedef struct micro_paired_form {
    uint32_t mask, value;
    uint16_t name, form;
    uint8_t data_size, store, eva;
} micro_paired_form;
static const micro_paired_form micro_paired_forms[] = {
#include "generated/mips_micro_paired_forms.inc"
};

typedef struct micro_supplement_form {
    uint32_t mask, value;
    uint16_t name, form;
    uint8_t kind, store;
} micro_supplement_form;
static const micro_supplement_form micro_supplement_forms[] = {
#include "generated/mips_micro_supplement_forms.inc"
};

static cdisasm_status micro_paired_decode(uint32_t raw, const micro_paired_form *f,
    uint64_t address, cdisasm_mips_mode mode, cdisasm_mips_revision revision,
    uint64_t active, cdisasm_mips_instruction *i)
{
    const unsigned rt = (raw >> 21) & 31u, base = (raw >> 16) & 31u, rd = (raw >> 4) & 31u;
    const uint8_t gpr_size = mode == CDISASM_MIPS_MODE_64 ? 8u : 4u;
    if ((f->data_size == 8u && mode != CDISASM_MIPS_MODE_64) ||
        (f->eva && mode != CDISASM_MIPS_MODE_32)) return CDISASM_STATUS_INVALID_INSTRUCTION;
    if (f->eva && (active & CDISASM_MIPS_DECODE_FLAG_EVA) == 0)
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    memset(i, 0, sizeof(*i));
    i->address = address; i->raw_instruction = raw; i->opcode_size = 4;
    i->mode = (uint8_t)mode; i->revision = (uint8_t)revision;
    i->name_id = f->name; i->form_id = f->form; i->operand_count = 3;
    i->instruction_flags = CDISASM_MIPS_INSTRUCTION_FLAG_ATOMIC |
        (f->eva ? CDISASM_MIPS_INSTRUCTION_FLAG_EVA : 0);
    i->operand[0].type = CDISASM_OPERAND_REGISTER;
    i->operand[0].reg = (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0 + rt);
    i->operand[0].size = gpr_size;
    i->operand[0].access = f->store ? CDISASM_OPERAND_ACCESS_READ_WRITE : CDISASM_OPERAND_ACCESS_WRITE;
    i->operand[1].type = CDISASM_OPERAND_REGISTER;
    i->operand[1].reg = (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0 + rd);
    i->operand[1].size = f->store ? f->data_size : gpr_size;
    i->operand[1].access = f->store ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE;
    i->operand[2].type = CDISASM_OPERAND_MEMORY;
    i->operand[2].base_reg = (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0 + base);
    i->operand[2].size = (uint8_t)(2u * f->data_size);
    i->operand[2].access = f->store ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ;
    return CDISASM_STATUS_OK;
}

static uint32_t compact_value(uint32_t raw, uint16_t field)
{
    const compact_field *f = &compact_fields[field];
    unsigned n;
    uint32_t value = 0;
    for (n=0;n<5u;++n) {
        const compact_piece *p = &f->piece[n];
        if (p->width) value |= ((raw >> p->lsb) & ((UINT32_C(1)<<p->width)-1u)) << p->destination;
    }
    return value;
}
static int64_t compact_signed(uint32_t value, unsigned width)
{
    uint32_t sign;
    if (!width) return 0;
    sign = UINT32_C(1) << (width-1u);
    return (int64_t)(value ^ sign) - sign;
}
static uint64_t compact_address(cdisasm_mips_mode mode, uint64_t value)
{
    return mode == CDISASM_MIPS_MODE_64 ? value : (uint64_t)(uint32_t)value;
}
static int compact_revision(cdisasm_mips_revision revision)
{
    static const uint8_t revisions[15] = {1u,2u,3u,4u,5u,32u,33u,34u,36u,37u,64u,65u,66u,68u,69u};
    unsigned n;
    for(n=0;n<15u;++n) if(revision == revisions[n]) return (int)n;
    return -1;
}
static unsigned compact_gpr(unsigned value, unsigned map)
{
    static const uint8_t registers[5][8] = {
        {16u,17u,2u,3u,4u,5u,6u,7u},
        {0u,17u,2u,3u,4u,5u,6u,7u},
        {0u,17u,2u,3u,16u,18u,19u,20u},
        {5u,5u,6u,4u,4u,4u,4u,4u},
        {6u,7u,7u,21u,22u,5u,6u,7u}
    };
    return registers[map][value & 7u];
}
uint64_t cdisasm_mips_compact_required_flags(cdisasm_mips_form_id form)
{
    size_t n;
    if(form>=33820u && form<=33831u)return CDISASM_MIPS_DECODE_FLAG_FPU;
    uint64_t cop_required=cdisasm_mips_micro64_cop_required_flags(form);
    if(cop_required)return cop_required;
    cop_required=cdisasm_mips_micro64_fp_required_flags(form);
    if(cop_required)return cop_required;
    for(n=0;n<sizeof(micro_paired_forms)/sizeof(micro_paired_forms[0]);++n)
        if(micro_paired_forms[n].form==form)
            return micro_paired_forms[n].eva ? CDISASM_MIPS_DECODE_FLAG_EVA : 0;
    for(n=0;n<sizeof(compact_forms)/sizeof(compact_forms[0]);++n)
        if(compact_forms[n].form==form) return compact_forms[n].required;
    return 0u;
}

/* Several Release6 branch classes intentionally share their bit pattern.
 * Register relations select a canonical operation, before operand lowering. */
static int compact_branch_class(const compact_form *f, uint32_t raw)
{
    unsigned rt=(raw>>21)&31u,rs=(raw>>16)&31u;
    cdisasm_mips_name_id name=CDISASM_MIPS_NAME_NONE;
    switch(f->special) {
        case 0u: return 1;
        case 1u: name=rs>=rt ? CDISASM_MIPS_NAME_BOVC : rs ? CDISASM_MIPS_NAME_BEQC : CDISASM_MIPS_NAME_BEQZALC; break;
        case 2u: name=rs>=rt ? CDISASM_MIPS_NAME_BNVC : rs ? CDISASM_MIPS_NAME_BNEC : CDISASM_MIPS_NAME_BNEZALC; break;
        case 3u: if(!rt)return 0; name=!rs ? CDISASM_MIPS_NAME_BGTZC : rs==rt ? CDISASM_MIPS_NAME_BLTZC : CDISASM_MIPS_NAME_BLTC; break;
        case 4u: if(!rt)return 0; name=!rs ? CDISASM_MIPS_NAME_BLEZC : rs==rt ? CDISASM_MIPS_NAME_BGEZC : CDISASM_MIPS_NAME_BGEC; break;
        case 5u: if(!rt)return 0; name=!rs ? CDISASM_MIPS_NAME_BLEZALC : rs==rt ? CDISASM_MIPS_NAME_BGEZALC : CDISASM_MIPS_NAME_BGEUC; break;
        case 6u: if(!rt)return 0; name=!rs ? CDISASM_MIPS_NAME_BGTZALC : rs==rt ? CDISASM_MIPS_NAME_BLTZALC : CDISASM_MIPS_NAME_BLTUC; break;
        case 7u: return rt!=0u; /* The zero register field selects JIC/JIALC. */
        case 8u: return rs!=0u; /* AUI with zero source is canonical LUI. */
        default: return 0;
    }
    return f->name==name;
}

static cdisasm_status compact_lower(uint32_t raw,const compact_form *f,cdisasm_mips_instruction *i)
{
    unsigned n;
    cdisasm_mips_mode mode=(cdisasm_mips_mode)i->mode;
    /* MD00594 rev6.05 pp179-183: every scalar R6 comparison may update
     * FCSR Cause/Flags and preserves its other fields. Imported compiler
     * records describe only the explicit FPR operands. */
    if(f->encoding==2u && (i->revision==37u || i->revision==69u) &&
       ((raw&UINT32_C(0xfc00003f))==UINT32_C(0x54000005) ||
        (raw&UINT32_C(0xfc00003f))==UINT32_C(0x54000015)))
        i->instruction_flags|=CDISASM_MIPS_INSTRUCTION_FLAG_READS_FCSR|CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_FCSR;
    if(f->name==CDISASM_MIPS_NAME_LWU && mode!=CDISASM_MIPS_MODE_64)
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    for(n=0;n<f->count;++n) {
        const compact_operand *d=&f->operand[n];
        cdisasm_mips_operand *o=&i->operand[i->operand_count++];
        uint32_t value=compact_value(raw,d->field);
        unsigned width=compact_fields[d->field].width;
        o->size=(uint8_t)d->size;
        o->access=(uint8_t)d->access;
        if(d->kind==1u || (d->kind>=3u && d->kind<=9u)) {
            o->type=CDISASM_OPERAND_REGISTER;
            if(d->kind==1u) o->reg=d->aux==32u ? CDISASM_MIPS_REG_PC : (uint16_t)(CDISASM_MIPS_REG_GPR0+d->aux);
            else if(d->kind==3u) o->reg=(uint16_t)(CDISASM_MIPS_REG_GPR0+value);
            else if(d->kind==4u) o->reg=(uint16_t)(CDISASM_MIPS_REG_GPR0+compact_gpr(value,d->aux));
            else if(d->kind==5u) {
                if((d->aux&1u) && (value&1u)) return CDISASM_STATUS_INVALID_INSTRUCTION;
                o->reg=(uint16_t)(CDISASM_MIPS_REG_FPR0+value);
                if(d->aux&2u)o->detail.flags=CDISASM_MIPS_OPERAND_DETAIL_HIGH_HALF;
            } else if(d->kind==6u) o->reg=(uint16_t)(CDISASM_MIPS_REG_FCC0+value);
            else if(d->kind==7u) {
                if(value>3u) return CDISASM_STATUS_INVALID_INSTRUCTION;
                o->reg=(uint16_t)(CDISASM_MIPS_REG_ACC0+value);
                o->detail.flags=(uint8_t)d->aux;
            } else if(d->kind==8u) {
                if(d->aux==0u) o->reg=CDISASM_MIPS_REG_CP0(value,compact_value(raw,d->secondary));
                else if(d->aux==1u) o->reg=(uint16_t)(CDISASM_MIPS_REG_FCR0+value);
                else if(d->aux==2u) {
                    o->reg=CDISASM_MIPS_REG_COP2(value & 31u,0u);
                    if(width>5u) { o->imm=value;o->detail.flags=CDISASM_MIPS_OPERAND_DETAIL_REGISTER_SELECTOR; }
                }
            } else if(d->kind==9u) {
                unsigned count;
                uint32_t registers=0u;
                if(d->aux) {
                    count=value+1u;
                    registers=UINT32_C(1)<<31;
                } else {
                    count=value&15u;
                    if(!value || count>9u) return CDISASM_STATUS_INVALID_INSTRUCTION;
                    if(value&16u) registers=UINT32_C(1)<<31;
                }
                if(count>9u) return CDISASM_STATUS_INVALID_INSTRUCTION;
                for(;count>0u;--count) registers|=UINT32_C(1)<<(count==9u ? 30u : 15u+count);
                o->imm=registers;
                o->detail.flags=CDISASM_MIPS_OPERAND_DETAIL_REGISTER_LIST;
            }
        } else if(d->kind==10u || d->kind==11u) {
            uint64_t target;
            int64_t displacement=compact_signed(value,width)*(INT64_C(1)<<d->scale);
            if(d->kind==11u) {
                uint64_t region=(UINT64_C(1)<<(width+d->scale))-1u;
                target=((i->address+i->opcode_size)&~region)|((uint64_t)value<<d->scale);
                o->flags=CDISASM_MIPS_OPERAND_FLAG_ABSOLUTE|CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS;
            } else {
                target=i->address+i->opcode_size+(uint64_t)displacement;
                o->address=(uint64_t)displacement;
                o->flags=CDISASM_MIPS_OPERAND_FLAG_RELATIVE|CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS;
                i->opcode_groups|=CDISASM_GROUP_RELATIVE_BRANCH;
            }
            o->type=CDISASM_OPERAND_IMMEDIATE;
            o->imm=compact_address(mode,target);
            i->branch_target=o->imm;
        } else if(d->kind==12u) {
            int64_t displacement=(width<=8u ? (int64_t)value*4 : compact_signed(value,width));
            o->type=CDISASM_OPERAND_MEMORY;
            o->imm=(uint64_t)displacement;
            o->address=compact_address(mode,(i->address&~UINT64_C(3))+(uint64_t)displacement);
            o->size=4u;
            o->flags=CDISASM_MIPS_OPERAND_FLAG_SIGNED|CDISASM_MIPS_OPERAND_FLAG_PC_RELATIVE|CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS|CDISASM_MIPS_OPERAND_FLAG_HAS_DISPLACEMENT;
        } else if(d->kind==16u) {
            o->type=CDISASM_OPERAND_MEMORY;
            o->base_reg=(uint16_t)(CDISASM_MIPS_REG_GPR0+value);
            o->index_reg=(uint16_t)(CDISASM_MIPS_REG_GPR0+compact_value(raw,d->secondary));
            if(d->scale) {o->detail.flags=CDISASM_MIPS_OPERAND_DETAIL_INDEX_SCALED;o->detail.index_shift=(uint8_t)d->scale;}
            if(!d->size)o->flags=CDISASM_OPERAND_FLAG_ADDRESS_ONLY;
        } else if(d->kind==15u) {
            unsigned base=compact_value(raw,d->secondary);
            int sign=1;
            int64_t displacement;
            if(d->aux==1u) { base=compact_gpr(base,0u);sign=f->encoding==1u && width>=16u; }
            else if(d->aux==2u) { base=29u;sign=f->encoding==1u || ((f->name==CDISASM_MIPS_NAME_LWM16 || f->name==CDISASM_MIPS_NAME_SWM16) && i->revision!=37u && i->revision!=69u); }
            else if(d->aux==3u) base=28u;
            displacement=(sign ? compact_signed(value,width) : (int64_t)value)*(INT64_C(1)<<d->scale);
            if(f->name==CDISASM_MIPS_NAME_LBU16 && value==15u && i->revision!=37u && i->revision!=69u) displacement=-1;
            o->type=CDISASM_OPERAND_MEMORY;
            o->base_reg=(uint16_t)(CDISASM_MIPS_REG_GPR0+base);
            o->imm=(uint64_t)displacement;
            o->flags=CDISASM_MIPS_OPERAND_FLAG_HAS_DISPLACEMENT|(sign || displacement<0 ? CDISASM_MIPS_OPERAND_FLAG_SIGNED : 0u);
            if(!d->size)o->flags|=CDISASM_OPERAND_FLAG_ADDRESS_ONLY;
            if(!base) { o->address=compact_address(mode,(uint64_t)displacement);o->flags|=CDISASM_MIPS_OPERAND_FLAG_ABSOLUTE|CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS; }
        } else {
            int64_t immediate=d->kind==14u ? compact_signed(value,width) : (int64_t)value;
            if(d->kind==2u) immediate=d->aux;
            else if(d->aux==1u) immediate=value==127u ? -1 : (int64_t)value;
            else if(d->aux==2u) immediate=!value ? 1 : value==7u ? -1 : (int64_t)value*4;
            else if(d->aux==3u) immediate=(!value ? 256 : value==1u ? 257 : value==510u ? -258 : value==511u ? -257 : compact_signed(value,9u))*4;
            else if(d->aux==4u) {
                static const uint16_t masks[16]={128u,1u,2u,3u,4u,7u,8u,15u,16u,31u,32u,63u,64u,255u,32768u,65535u};
                immediate=masks[value&15u];
            } else if(d->aux==5u) immediate=value ? value : 8;
            else if(d->aux==6u) immediate=(int64_t)value+1;
            else if(d->aux==7u) {
                if(n<1u || value<i->operand[n-1u].imm) return CDISASM_STATUS_INVALID_INSTRUCTION;
                immediate=(int64_t)value-(int64_t)i->operand[n-1u].imm+1;
            }
            immediate*=INT64_C(1)<<d->scale;
            o->type=CDISASM_OPERAND_IMMEDIATE;
            o->imm=(uint64_t)immediate;
            if(d->kind==14u)o->flags=CDISASM_MIPS_OPERAND_FLAG_SIGNED;
            if(f->name==CDISASM_MIPS_NAME_ADDIUPC || (f->encoding==1u && f->name==CDISASM_MIPS_NAME_ADDIU && n>0u && i->operand[n-1u].reg==CDISASM_MIPS_REG_PC)) {
                o->address=(uint64_t)immediate;
                o->imm=compact_address(mode,(i->address&~UINT64_C(3))+(uint64_t)immediate);
                o->flags=CDISASM_MIPS_OPERAND_FLAG_PC_RELATIVE|CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS;
            }
        }
    }
    if(i->operand_count==2u &&
       (f->name==CDISASM_MIPS_NAME_MFC2 || f->name==CDISASM_MIPS_NAME_MTC2 ||
        f->name==CDISASM_MIPS_NAME_MFHC2 || f->name==CDISASM_MIPS_NAME_MTHC2 ||
        f->name==CDISASM_MIPS_NAME_CFC2 || f->name==CDISASM_MIPS_NAME_CTC2)) {
        cdisasm_mips_operand *cop=&i->operand[1];
        const int control=f->name==CDISASM_MIPS_NAME_CFC2 || f->name==CDISASM_MIPS_NAME_CTC2;
        const int high=f->name==CDISASM_MIPS_NAME_MFHC2 || f->name==CDISASM_MIPS_NAME_MTHC2;
        cop->reg=control ? CDISASM_MIPS_REG_FCR2_FIRST : CDISASM_MIPS_REG_COP2_FIRST;
        cop->imm=(raw>>16)&31u;
        cop->size=high ? 8u : 4u;
        cop->detail.flags=CDISASM_MIPS_OPERAND_DETAIL_REGISTER_SELECTOR|
            (high ? CDISASM_MIPS_OPERAND_DETAIL_HIGH_HALF : 0u);
        if(f->name==CDISASM_MIPS_NAME_MTHC2)cop->access=CDISASM_OPERAND_ACCESS_READ_WRITE;
    }
    if(mode==CDISASM_MIPS_MODE_64 && i->operand_count &&
       (f->name==CDISASM_MIPS_NAME_MFC0 || f->name==CDISASM_MIPS_NAME_MFC1 ||
        f->name==CDISASM_MIPS_NAME_CFC1 || f->name==CDISASM_MIPS_NAME_MFHC1 ||
        f->name==CDISASM_MIPS_NAME_MFC2 || f->name==CDISASM_MIPS_NAME_CFC2 || f->name==CDISASM_MIPS_NAME_MFHC2))
        i->operand[0].size=8u;
    if(f->name==CDISASM_MIPS_NAME_INS && i->operand_count>=4u && i->operand[2].imm+i->operand[3].imm>32u) return CDISASM_STATUS_INVALID_INSTRUCTION;
    if(f->name==CDISASM_MIPS_NAME_EXT && i->operand_count>=4u && i->operand[2].imm+i->operand[3].imm>32u) return CDISASM_STATUS_INVALID_INSTRUCTION;
    if((f->name==CDISASM_MIPS_NAME_LWP || f->name==CDISASM_MIPS_NAME_SWP) && i->operand[0].reg==CDISASM_MIPS_REG_GPR31) return CDISASM_STATUS_INVALID_INSTRUCTION;
    if((f->name==CDISASM_MIPS_NAME_JALR || f->name==CDISASM_MIPS_NAME_JALR_HB ||
        f->name==CDISASM_MIPS_NAME_JALRC || f->name==CDISASM_MIPS_NAME_JALRC_HB || f->name==CDISASM_MIPS_NAME_JALRS) &&
        i->operand_count>=2u && i->operand[0].reg==CDISASM_MIPS_REG_GPR0) {
        i->instruction_flags&=~CDISASM_MIPS_INSTRUCTION_FLAG_LINK;
        i->opcode_groups&=~CDISASM_GROUP_CALL;
        if(i->operand[1].reg==CDISASM_MIPS_REG_GPR31)i->opcode_groups|=CDISASM_GROUP_RETURN;
    }
    return CDISASM_STATUS_OK;
}

/* Numeric allocation: MD00594 rev6.05 pp179-182, table5.23. The lower
 * sixteen conditions already have generated forms. Only six of the sixteen
 * negated conditions are allocated; the other ten remain reserved. */
static cdisasm_status micro_negated_compare(uint32_t raw,uint64_t address,
    cdisasm_mips_mode mode,cdisasm_mips_revision revision,uint64_t active,cdisasm_mips_instruction *i)
{
    static const cdisasm_mips_name_id names[6][2]={
        {CDISASM_MIPS_NAME_CMP_OR_S,CDISASM_MIPS_NAME_CMP_OR_D},
        {CDISASM_MIPS_NAME_CMP_UNE_S,CDISASM_MIPS_NAME_CMP_UNE_D},
        {CDISASM_MIPS_NAME_CMP_NE_S,CDISASM_MIPS_NAME_CMP_NE_D},
        {CDISASM_MIPS_NAME_CMP_SOR_S,CDISASM_MIPS_NAME_CMP_SOR_D},
        {CDISASM_MIPS_NAME_CMP_SUNE_S,CDISASM_MIPS_NAME_CMP_SUNE_D},
        {CDISASM_MIPS_NAME_CMP_SNE_S,CDISASM_MIPS_NAME_CMP_SNE_D}};
    const unsigned condition=(raw>>6)&31u,predicate=condition&7u;
    const unsigned format=(raw&16u)!=0u;
    const unsigned index=predicate-1u+((condition&8u) ? 3u : 0u);
    unsigned n;
    if(predicate<1u || predicate>3u)return CDISASM_STATUS_INVALID_INSTRUCTION;
    if(!(active&CDISASM_MIPS_DECODE_FLAG_FPU))return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    memset(i,0,sizeof(*i));
    i->address=address;i->raw_instruction=raw;i->opcode_size=4u;
    i->mode=(uint8_t)mode;i->revision=(uint8_t)revision;
    i->name_id=names[index][format];i->form_id=(uint16_t)(33820u+2u*index+format);
    i->operand_count=3u;
    i->instruction_flags=CDISASM_MIPS_INSTRUCTION_FLAG_FLOATING_POINT|
        CDISASM_MIPS_INSTRUCTION_FLAG_READS_FCSR|CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_FCSR;
    for(n=0;n<3u;++n) {
        cdisasm_mips_operand *o=&i->operand[n];
        const unsigned field=n==0u ? 11u : n==1u ? 16u : 21u;
        o->type=CDISASM_OPERAND_REGISTER;
        o->reg=(uint16_t)(CDISASM_MIPS_REG_FPR0+((raw>>field)&31u));
        o->size=format ? 8u : 4u;
        o->access=n==0u ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ;
    }
    return CDISASM_STATUS_OK;
}

static void m16_register(cdisasm_mips_instruction *i,unsigned reg,unsigned size,unsigned access)
{
    cdisasm_mips_operand *o=&i->operand[i->operand_count++];
    o->type=CDISASM_OPERAND_REGISTER;o->reg=(uint16_t)(CDISASM_MIPS_REG_GPR0+reg);
    o->size=(uint8_t)size;o->access=(uint8_t)access;
}
static void m16_immediate(cdisasm_mips_instruction *i,int64_t value,int sign)
{
    cdisasm_mips_operand *o=&i->operand[i->operand_count++];
    o->type=CDISASM_OPERAND_IMMEDIATE;o->imm=(uint64_t)value;o->size=4u;o->access=CDISASM_OPERAND_ACCESS_READ;
    if(sign)o->flags=CDISASM_MIPS_OPERAND_FLAG_SIGNED;
}
static void m16_memory(cdisasm_mips_instruction *i,unsigned base,int64_t displacement,unsigned size,int store,int pcrel)
{
    cdisasm_mips_operand *o=&i->operand[i->operand_count++];
    o->type=CDISASM_OPERAND_MEMORY;o->size=(uint8_t)size;
    o->access=store ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ;
    o->imm=(uint64_t)displacement;o->flags=CDISASM_MIPS_OPERAND_FLAG_SIGNED|CDISASM_MIPS_OPERAND_FLAG_HAS_DISPLACEMENT;
    if(pcrel) {
        o->flags|=CDISASM_MIPS_OPERAND_FLAG_PC_RELATIVE|CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS;
        o->address=compact_address((cdisasm_mips_mode)i->mode,(i->address&~UINT64_C(3))+(uint64_t)displacement);
    } else o->base_reg=(uint16_t)(CDISASM_MIPS_REG_GPR0+base);
}

/* MD00594 pp90-93/111-113; GNU's distinct short-delay JALRS.HB slot.
 * Runtime address alignment, restartability and hazard clearing are not
 * properties that can be established from an instruction word. */
static cdisasm_status micro_supplement_decode(uint32_t raw,const micro_supplement_form *f,
    uint64_t address,cdisasm_mips_mode mode,cdisasm_mips_revision revision,cdisasm_mips_instruction *i)
{
    unsigned reg=(raw>>21)&31u,base=(raw>>16)&31u,count=2u;
    uint32_t list=0;
    if(f->kind==2u) {
        if(revision==37u || revision==69u)return CDISASM_STATUS_INVALID_INSTRUCTION;
    } else {
        if(mode!=CDISASM_MIPS_MODE_64 || !((revision>=3u && revision<=5u) || revision>=64u))
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        if(f->kind==1u) {
            unsigned saved=reg&15u,n;
            if(!reg || saved>9u)return CDISASM_STATUS_INVALID_INSTRUCTION;
            count=saved+((reg&16u)!=0u);
            for(n=0;n<saved;++n)list|=UINT32_C(1)<<(n==8u ? 30u : 16u+n);
            if(reg&16u)list|=UINT32_C(1)<<31;
        } else if(reg==31u) {
            /* No in-range adjacent GPR exists for this undefined operand. */
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
    }
    memset(i,0,sizeof(*i));
    i->address=address;i->raw_instruction=raw;i->opcode_size=4;
    i->mode=(uint8_t)mode;i->revision=(uint8_t)revision;i->name_id=f->name;i->form_id=f->form;
    if(f->kind==2u) {
        const unsigned width=mode==CDISASM_MIPS_MODE_64 ? 8u : 4u;
        m16_register(i,reg,width,CDISASM_OPERAND_ACCESS_WRITE);
        m16_register(i,base,width,CDISASM_OPERAND_ACCESS_READ);
        i->instruction_flags=CDISASM_MIPS_INSTRUCTION_FLAG_DELAY_SLOT;
        i->opcode_groups=CDISASM_GROUP_JUMP;
        if(reg) {
            i->instruction_flags|=CDISASM_MIPS_INSTRUCTION_FLAG_LINK;
            i->opcode_groups|=CDISASM_GROUP_CALL;
        } else if(base==31u)i->opcode_groups|=CDISASM_GROUP_RETURN;
    } else {
        m16_register(i,reg,8u,f->store ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE);
        if(f->kind==1u) {
            i->operand[0].reg=CDISASM_MIPS_REG_NONE;
            i->operand[0].imm=list;
            i->operand[0].detail.flags=CDISASM_MIPS_OPERAND_DETAIL_REGISTER_LIST;
        }
        m16_memory(i,base,compact_signed(raw&4095u,12u),count*8u,f->store,0);
        if(!base) {
            i->operand[1].address=(uint64_t)compact_signed(raw&4095u,12u);
            i->operand[1].flags|=CDISASM_MIPS_OPERAND_FLAG_ABSOLUTE|CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS;
        }
    }
    return CDISASM_STATUS_OK;
}
static void m16_branch(cdisasm_mips_instruction *i,int64_t displacement,int conditional)
{
    cdisasm_mips_operand *o;
    m16_immediate(i,displacement,0);o=&i->operand[i->operand_count-1u];
    o->imm=compact_address((cdisasm_mips_mode)i->mode,i->address+i->opcode_size+(uint64_t)displacement);
    o->address=(uint64_t)displacement;o->flags=CDISASM_MIPS_OPERAND_FLAG_RELATIVE|CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS;
    i->branch_target=o->imm;i->opcode_groups=CDISASM_GROUP_JUMP|CDISASM_GROUP_RELATIVE_BRANCH|(conditional ? CDISASM_GROUP_CONDITIONAL : 0u);
    i->instruction_flags|=CDISASM_MIPS_INSTRUCTION_FLAG_COMPACT_BRANCH;
}
static int m16_wide(const cdisasm_mips_instruction *i)
{
    return i->mode==CDISASM_MIPS_MODE_64 && ((i->revision>=3u && i->revision<=5u)||i->revision>=64u);
}

size_t cdisasm_mips_compact_effects(const cdisasm_mips_instruction *instruction,cdisasm_mips_register_effect *effects,size_t capacity)
{
    size_t count=0u,n;
    cdisasm_mips_reg_id extra_reg=CDISASM_MIPS_REG_NONE;
    cdisasm_operand_access extra_access=CDISASM_OPERAND_ACCESS_NONE;
    if(!instruction)return 0u;
    if(instruction->form_id==31089u || instruction->form_id==31090u) {
        if(effects && capacity) {
            memset(effects,0,sizeof(*effects));effects[0].reg=CDISASM_MIPS_REG_PC;
            effects[0].size=8;effects[0].access=CDISASM_OPERAND_ACCESS_READ;
        }
        return 1u;
    }
    for(n=0;n<sizeof(micro_paired_forms)/sizeof(micro_paired_forms[0]);++n) {
        const micro_paired_form *f=&micro_paired_forms[n];
        if(f->form!=instruction->form_id)continue;
        if(effects && capacity) {
            memset(&effects[0],0,sizeof(effects[0]));
            effects[0].reg=CDISASM_MIPS_REG_CP0(17,0);
            /* Optional LLAddr has unknown extent; stores preserve address
             * bits while clearing the aliased LLbit in bit0. */
            effects[0].access=f->store ? CDISASM_OPERAND_ACCESS_READ_WRITE : CDISASM_OPERAND_ACCESS_WRITE;
        }
        return 1u;
    }
    for(n=0;n<sizeof(compact_effects)/sizeof(compact_effects[0]);++n) {
        const compact_effect *source=&compact_effects[n];
        if(source->form!=instruction->form_id)continue;
        if(count<capacity) {
            memset(&effects[count],0,sizeof(effects[count]));effects[count].reg=source->reg;
            effects[count].access=source->access;effects[count].size=source->size;
        }
        ++count;
    }
    if(instruction->form_id>=32000u && instruction->form_id<34000u) {
        switch(instruction->name_id) {
            case CDISASM_MIPS_NAME_CMP:case CDISASM_MIPS_NAME_CMPI:case CDISASM_MIPS_NAME_SLT:
            case CDISASM_MIPS_NAME_SLTI:case CDISASM_MIPS_NAME_SLTU:case CDISASM_MIPS_NAME_SLTIU:
                extra_reg=CDISASM_MIPS_REG_GPR24;extra_access=CDISASM_OPERAND_ACCESS_WRITE;break;
            case CDISASM_MIPS_NAME_BTEQZ:case CDISASM_MIPS_NAME_BTNEZ:
                extra_reg=CDISASM_MIPS_REG_GPR24;extra_access=CDISASM_OPERAND_ACCESS_READ;break;
            case CDISASM_MIPS_NAME_SAVE:case CDISASM_MIPS_NAME_RESTORE:
                extra_reg=CDISASM_MIPS_REG_GPR29;extra_access=CDISASM_OPERAND_ACCESS_READ_WRITE;break;
            default:break;
        }
    }
    if(extra_reg!=CDISASM_MIPS_REG_NONE) {
        if(count<capacity) {
            memset(&effects[count],0,sizeof(effects[count]));effects[count].reg=extra_reg;effects[count].access=extra_access;
            effects[count].size=instruction->mode==CDISASM_MIPS_MODE_64 ? 8u : 4u;
        }
        ++count;
    }
    if((instruction->name_id==CDISASM_MIPS_NAME_LWP || instruction->name_id==CDISASM_MIPS_NAME_SWP ||
        instruction->name_id==CDISASM_MIPS_NAME_LDP || instruction->name_id==CDISASM_MIPS_NAME_SDP) && instruction->operand_count) {
        if(count<capacity) {
            memset(&effects[count],0,sizeof(effects[count]));effects[count].reg=(uint16_t)(instruction->operand[0].reg+1u);
            effects[count].access=instruction->operand[0].access;
            effects[count].size=(instruction->name_id==CDISASM_MIPS_NAME_LDP || instruction->name_id==CDISASM_MIPS_NAME_SDP) ? 8u : 4u;
        }
        ++count;
    }
    return count;
}
static cdisasm_status m16_save(uint32_t raw,int extended,cdisasm_mips_instruction *i)
{
    static const uint8_t arguments[15]={0u,0u,0u,0u,1u,1u,1u,1u,2u,2u,2u,0u,3u,3u,4u};
    static const uint8_t statics[15]={0u,1u,2u,3u,0u,1u,2u,3u,0u,1u,2u,4u,0u,1u,0u};
    unsigned selector=extended ? (raw>>16)&15u : 0u;
    unsigned xs=extended ? (raw>>24)&7u : 0u;
    unsigned frame=raw&15u,n;
    int save=(raw&128u)!=0u;
    uint32_t argmask=0u,staticmask=0u;
    cdisasm_mips_operand *o;
    if(selector==15u)return CDISASM_STATUS_INVALID_INSTRUCTION;
    frame=extended ? ((((raw>>20)&15u)<<4)|frame)*8u : (frame ? frame : 16u)*8u;
    for(n=0;n<arguments[selector];++n)argmask|=UINT32_C(1)<<(4u+n);
    for(n=0;n<statics[selector];++n)staticmask|=UINT32_C(1)<<(7u-n);
    for(n=0;n<xs;++n)staticmask|=UINT32_C(1)<<(n==6u ? 30u : 18u+n);
    if(raw&64u)staticmask|=UINT32_C(1)<<31;
    if(raw&32u)staticmask|=UINT32_C(1)<<16;
    if(raw&16u)staticmask|=UINT32_C(1)<<17;
    i->name_id=save ? CDISASM_MIPS_NAME_SAVE : CDISASM_MIPS_NAME_RESTORE;
    i->form_id=(uint16_t)(33900u+(extended ? 2u : 0u)+(save ? 0u : 1u));
    o=&i->operand[i->operand_count++];o->type=CDISASM_OPERAND_REGISTER;o->size=4u;
    o->detail.flags=CDISASM_MIPS_OPERAND_DETAIL_REGISTER_LIST;o->imm=argmask;o->access=save ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_NONE;
    m16_immediate(i,frame,0);
    o=&i->operand[i->operand_count++];o->type=CDISASM_OPERAND_REGISTER;o->size=4u;
    o->detail.flags=CDISASM_MIPS_OPERAND_DETAIL_REGISTER_LIST;o->imm=staticmask;
    o->access=save ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE;
    return CDISASM_STATUS_OK;
}

/* Architectural MIPS16 supplements include real unextended memory and 64-bit
 * forms omitted by LLVM's printer-oriented MIPS16 backend. Field facts were
 * cross-checked with MIPS MD00076 r2.50 and the independent QEMU v10.1.0
 * translator. This implementation shares no vendor decoder code. */
static cdisasm_status compact_mips16(uint32_t raw,uint32_t size,cdisasm_mips_instruction *i)
{
    uint32_t h=raw&65535u,first=size==4u ? raw>>16 : h;
    int extended=size==4u && (first>>11)==30u;
    unsigned op=h>>11,rx=compact_gpr((h>>8)&7u,0u),ry=compact_gpr((h>>5)&7u,0u);
    unsigned width=i->mode==CDISASM_MIPS_MODE_64 ? 8u : 4u;
    int64_t imm=extended ? compact_signed(((raw>>16)&31u)<<11|((raw>>21)&63u)<<5|(h&31u),16u) : 0;
    cdisasm_mips_name_id name=CDISASM_MIPS_NAME_NONE;
    if(i->revision==37u || i->revision==69u)return CDISASM_STATUS_INVALID_INSTRUCTION;
    /* The legacy extended formats explicitly encode zero in these fields.
     * MIPS16e2 reuses some selectors and is dispatched before this decoder. */
    if(extended) {
        if(op==6u && ((h&28u)!=0u || (first&63u)!=0u)) return CDISASM_STATUS_INVALID_INSTRUCTION;
        if(op==2u && (h&UINT32_C(0x7e0))!=0u) return CDISASM_STATUS_INVALID_INSTRUCTION;
        if((op<=1u || op==4u || op==5u || (op>=9u && op<=11u) || op==13u || op==14u ||
            op==18u || op==22u || op==26u || (op==12u && ((h>>8)&7u)<=3u) ||
            (op==31u && (((h>>8)&7u)==2u || ((h>>8)&7u)==3u))) && (h&224u)!=0u)
            return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
    if(size==2u && h==UINT32_C(0x6500)) {i->name_id=CDISASM_MIPS_NAME_NOP;i->form_id=32389u;return CDISASM_STATUS_OK;}
    if(size==4u && !extended) {
        uint32_t target;
        if((first>>11)!=3u)return CDISASM_STATUS_INVALID_INSTRUCTION;
        target=(((first&31u)<<21)|(((first>>5)&31u)<<16)|h)<<2;
        name=(first&1024u) ? CDISASM_MIPS_NAME_JALX : CDISASM_MIPS_NAME_JAL;
        m16_immediate(i,(int64_t)((i->address+4u)&~UINT64_C(0xfffffff))|target,0);
        i->operand[0].flags=CDISASM_MIPS_OPERAND_FLAG_ABSOLUTE|CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS;
        i->branch_target=i->operand[0].imm;i->opcode_groups=CDISASM_GROUP_JUMP|CDISASM_GROUP_CALL;
        i->instruction_flags|=CDISASM_MIPS_INSTRUCTION_FLAG_LINK|CDISASM_MIPS_INSTRUCTION_FLAG_DELAY_SLOT;
        i->name_id=name;i->form_id=(uint16_t)(32900u+((first>>10)&1u));return CDISASM_STATUS_OK;
    }
    {
        unsigned selector=op==29u ? h&31u : (op==12u || op==31u) ? (h>>8)&7u : (op==6u || op==28u) ? h&3u : op==8u ? (h>>4)&1u : 0u;
        i->form_id=(uint16_t)((extended ? 33500u+op*8u : 32000u+op*32u)+selector);
    }
    if(op<=1u) {
        m16_register(i,rx,width,CDISASM_OPERAND_ACCESS_WRITE);
        if(op==0u)m16_register(i,29u,width,CDISASM_OPERAND_ACCESS_READ);
        else { cdisasm_mips_operand *o=&i->operand[i->operand_count++];o->type=CDISASM_OPERAND_REGISTER;o->reg=CDISASM_MIPS_REG_PC;o->size=(uint8_t)width;o->access=CDISASM_OPERAND_ACCESS_READ; }
        m16_immediate(i,extended ? imm : (int64_t)(h&255u)*4,extended);
        name=CDISASM_MIPS_NAME_ADDIU;
    } else if(op==2u || op==4u || op==5u) {
        if(op!=2u)m16_register(i,rx,width,CDISASM_OPERAND_ACCESS_READ);
        m16_branch(i,(extended ? imm : compact_signed(h&(op==2u ? 2047u : 255u),op==2u ? 11u : 8u))*2,op!=2u);
        name=op==2u ? CDISASM_MIPS_NAME_B : op==4u ? CDISASM_MIPS_NAME_BEQZ : CDISASM_MIPS_NAME_BNEZ;
    } else if(op==6u) {
        unsigned fn=h&3u,shift=extended ? (raw>>22)&31u : (h>>2)&7u;
        if(!extended && !shift)shift=8u;
        if(fn==1u && !m16_wide(i))return CDISASM_STATUS_INVALID_INSTRUCTION;
        m16_register(i,rx,fn==1u ? 8u : 4u,CDISASM_OPERAND_ACCESS_WRITE);
        m16_register(i,ry,fn==1u ? 8u : 4u,CDISASM_OPERAND_ACCESS_READ);
        m16_immediate(i,shift,0);
        name=fn==0u ? CDISASM_MIPS_NAME_SLL : fn==1u ? CDISASM_MIPS_NAME_DSLL : fn==2u ? CDISASM_MIPS_NAME_SRL : CDISASM_MIPS_NAME_SRA;
    } else if(op==8u || op==9u) {
        int wide=op==8u && (h&16u);
        if(wide && !m16_wide(i))return CDISASM_STATUS_INVALID_INSTRUCTION;
        if(op==8u) {
            int64_t value=extended ? compact_signed((h&15u)|((raw>>20)&127u)<<4|((raw>>16)&15u)<<11,15u) : compact_signed(h&15u,4u);
            m16_register(i,ry,wide ? 8u : 4u,CDISASM_OPERAND_ACCESS_WRITE);m16_register(i,rx,wide ? 8u : 4u,CDISASM_OPERAND_ACCESS_READ);m16_immediate(i,value,1);
        } else { m16_register(i,rx,4u,CDISASM_OPERAND_ACCESS_READ_WRITE);m16_immediate(i,extended ? imm : compact_signed(h&255u,8u),1); }
        name=wide ? CDISASM_MIPS_NAME_DADDIU : CDISASM_MIPS_NAME_ADDIU;
    } else if(op==10u || op==11u || op==13u || op==14u) {
        m16_register(i,rx,width,op==13u ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ);
        m16_immediate(i,extended ? ((op==13u || op==14u) ? (int64_t)(uint16_t)imm : imm) : (int64_t)(h&255u),extended && op!=13u && op!=14u);
        name=op==10u ? CDISASM_MIPS_NAME_SLTI : op==11u ? CDISASM_MIPS_NAME_SLTIU : op==13u ? CDISASM_MIPS_NAME_LI : CDISASM_MIPS_NAME_CMPI;
    } else if(op==12u) {
        unsigned fn=(h>>8)&7u;
        if(fn<=1u) { m16_branch(i,(extended ? imm : compact_signed(h&255u,8u))*2,1);name=fn ? CDISASM_MIPS_NAME_BTNEZ : CDISASM_MIPS_NAME_BTEQZ; }
        else if(fn==2u) { m16_register(i,31u,width,CDISASM_OPERAND_ACCESS_READ);m16_memory(i,29u,extended ? imm : (int64_t)(h&255u)*4,4u,1,0);name=CDISASM_MIPS_NAME_SW; }
        else if(fn==3u) { m16_register(i,29u,width,CDISASM_OPERAND_ACCESS_READ_WRITE);m16_immediate(i,extended ? imm : compact_signed(h&255u,8u)*8,1);name=CDISASM_MIPS_NAME_ADDIU; }
        else if(fn==4u)return m16_save(raw,extended,i);
        else if(!extended && fn==5u) { m16_register(i,(((h>>3)&3u)<<3)|((h>>5)&7u),width,CDISASM_OPERAND_ACCESS_WRITE);m16_register(i,compact_gpr(h&7u,0u),width,CDISASM_OPERAND_ACCESS_READ);name=CDISASM_MIPS_NAME_MOVE; }
        else if(!extended && fn==7u) { m16_register(i,ry,width,CDISASM_OPERAND_ACCESS_WRITE);m16_register(i,h&31u,width,CDISASM_OPERAND_ACCESS_READ);name=CDISASM_MIPS_NAME_MOVE; }
        else return CDISASM_STATUS_INVALID_INSTRUCTION;
    } else if(op==7u || op==15u || (op>=16u && op<=27u)) {
        static const cdisasm_mips_name_id names[12]={CDISASM_MIPS_NAME_LB,CDISASM_MIPS_NAME_LH,CDISASM_MIPS_NAME_LW,CDISASM_MIPS_NAME_LW,CDISASM_MIPS_NAME_LBU,CDISASM_MIPS_NAME_LHU,CDISASM_MIPS_NAME_LW,CDISASM_MIPS_NAME_LWU,CDISASM_MIPS_NAME_SB,CDISASM_MIPS_NAME_SH,CDISASM_MIPS_NAME_SW,CDISASM_MIPS_NAME_SW};
        unsigned data_size=1u,reg=ry,base=rx,scale=0u;
        int store=op==15u || op>=24u,pcrel=op==22u;
        if(op==7u || op==15u) { if(!m16_wide(i))return CDISASM_STATUS_INVALID_INSTRUCTION;data_size=8u;scale=3u;name=op==7u ? CDISASM_MIPS_NAME_LD : CDISASM_MIPS_NAME_SD; }
        else { name=names[op-16u];if(op==17u || op==21u || op==25u){data_size=2u;scale=1u;}else if(op==18u || op==19u || op==22u || op==23u || op==26u || op==27u){data_size=4u;scale=2u;} }
        if(op==23u && !m16_wide(i))return CDISASM_STATUS_INVALID_INSTRUCTION;
        if(op==18u || op==22u || op==26u) {reg=rx;base=29u;}
        m16_register(i,reg,width,store ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE);
        m16_memory(i,base,extended ? imm : (int64_t)(h&((op==18u || op==22u || op==26u) ? 255u : 31u))*(INT64_C(1)<<scale),data_size,store,pcrel);
    } else if(op==28u && !extended) {
        unsigned fn=h&3u,reg=compact_gpr((h>>2)&7u,0u);
        int wide=fn==0u || fn==2u;
        if(wide && !m16_wide(i))return CDISASM_STATUS_INVALID_INSTRUCTION;
        m16_register(i,reg,wide ? 8u : 4u,CDISASM_OPERAND_ACCESS_WRITE);m16_register(i,rx,wide ? 8u : 4u,CDISASM_OPERAND_ACCESS_READ);m16_register(i,ry,wide ? 8u : 4u,CDISASM_OPERAND_ACCESS_READ);
        name=fn==0u ? CDISASM_MIPS_NAME_DADDU : fn==1u ? CDISASM_MIPS_NAME_ADDU : fn==2u ? CDISASM_MIPS_NAME_DSUBU : CDISASM_MIPS_NAME_SUBU;
    } else if(op==29u && !extended) {
        unsigned fn=h&31u;
        if(fn==0u) {
            int no_delay=(h&128u)!=0u,link=(h&64u)!=0u;
            unsigned reg=(h&32u) ? 31u : rx;
            if((h&32u)!=0u && (link || (h&UINT32_C(0x700))!=0u)) return CDISASM_STATUS_INVALID_INSTRUCTION;
            m16_register(i,reg,width,CDISASM_OPERAND_ACCESS_READ);
            i->opcode_groups=CDISASM_GROUP_JUMP|(link ? CDISASM_GROUP_CALL : reg==31u ? CDISASM_GROUP_RETURN : 0u);
            i->instruction_flags|=no_delay ? CDISASM_MIPS_INSTRUCTION_FLAG_COMPACT_BRANCH : CDISASM_MIPS_INSTRUCTION_FLAG_DELAY_SLOT;
            if(link)i->instruction_flags|=CDISASM_MIPS_INSTRUCTION_FLAG_LINK;
            name=link ? (no_delay ? CDISASM_MIPS_NAME_JALRC : CDISASM_MIPS_NAME_JALR) : (no_delay ? CDISASM_MIPS_NAME_JRC : CDISASM_MIPS_NAME_JR);
        } else if(fn==1u || fn==5u) { name=fn==1u ? CDISASM_MIPS_NAME_SDBBP : CDISASM_MIPS_NAME_BREAK;m16_immediate(i,(h>>5)&63u,0);i->opcode_groups=CDISASM_GROUP_INTERRUPT; }
        else if(fn==2u || fn==3u || fn==10u) { m16_register(i,rx,width,CDISASM_OPERAND_ACCESS_READ);m16_register(i,ry,width,CDISASM_OPERAND_ACCESS_READ);name=fn==2u ? CDISASM_MIPS_NAME_SLT : fn==3u ? CDISASM_MIPS_NAME_SLTU : CDISASM_MIPS_NAME_CMP; }
        else if(fn==4u || fn==6u || fn==7u || fn==20u || fn==22u || fn==23u) {
            int wide=fn>=20u;
            if(wide && !m16_wide(i))return CDISASM_STATUS_INVALID_INSTRUCTION;
            m16_register(i,ry,wide ? 8u : 4u,CDISASM_OPERAND_ACCESS_READ_WRITE);m16_register(i,rx,wide ? 8u : 4u,CDISASM_OPERAND_ACCESS_READ);
            name=fn==4u ? CDISASM_MIPS_NAME_SLLV : fn==6u ? CDISASM_MIPS_NAME_SRLV : fn==7u ? CDISASM_MIPS_NAME_SRAV : fn==20u ? CDISASM_MIPS_NAME_DSLLV : fn==22u ? CDISASM_MIPS_NAME_DSRLV : CDISASM_MIPS_NAME_DSRAV;
        } else if(fn==8u || fn==19u) {
            if(!m16_wide(i))return CDISASM_STATUS_INVALID_INSTRUCTION;
            m16_register(i,ry,8u,CDISASM_OPERAND_ACCESS_READ_WRITE);m16_immediate(i,((h>>8)&7u) ? (h>>8)&7u : 8u,0);name=fn==8u ? CDISASM_MIPS_NAME_DSRL : CDISASM_MIPS_NAME_DSRA;
        } else if(fn>=11u && fn<=15u) {
            int modify=fn>=12u && fn<=14u;
            m16_register(i,rx,width,modify ? CDISASM_OPERAND_ACCESS_READ_WRITE : CDISASM_OPERAND_ACCESS_WRITE);m16_register(i,ry,width,CDISASM_OPERAND_ACCESS_READ);
            name=fn==11u ? CDISASM_MIPS_NAME_NEG : fn==12u ? CDISASM_MIPS_NAME_AND : fn==13u ? CDISASM_MIPS_NAME_OR : fn==14u ? CDISASM_MIPS_NAME_XOR : CDISASM_MIPS_NAME_NOT;
        } else if(fn==16u || fn==18u) {
            if(h&224u)return CDISASM_STATUS_INVALID_INSTRUCTION;
            m16_register(i,rx,width,CDISASM_OPERAND_ACCESS_WRITE);name=fn==16u ? CDISASM_MIPS_NAME_MFHI : CDISASM_MIPS_NAME_MFLO;
            i->instruction_flags|=fn==16u ? CDISASM_MIPS_INSTRUCTION_FLAG_READS_HI : CDISASM_MIPS_INSTRUCTION_FLAG_READS_LO;
        } else if(fn==17u) {
            unsigned conversion=(h>>5)&7u;
            static const cdisasm_mips_name_id conversions[8]={CDISASM_MIPS_NAME_ZEB,CDISASM_MIPS_NAME_ZEH,CDISASM_MIPS_NAME_ZEW,0u,CDISASM_MIPS_NAME_SEB,CDISASM_MIPS_NAME_SEH,CDISASM_MIPS_NAME_SEW,0u};
            if(!conversions[conversion] || ((conversion&3u)==2u && !m16_wide(i)))return CDISASM_STATUS_INVALID_INSTRUCTION;
            m16_register(i,rx,width,CDISASM_OPERAND_ACCESS_READ_WRITE);name=conversions[conversion];
        } else if(fn>=24u) {
            int wide=fn>=28u;
            static const cdisasm_mips_name_id multiply[8]={CDISASM_MIPS_NAME_MULT,CDISASM_MIPS_NAME_MULTU,CDISASM_MIPS_NAME_DIV,CDISASM_MIPS_NAME_DIVU,CDISASM_MIPS_NAME_DMULT,CDISASM_MIPS_NAME_DMULTU,CDISASM_MIPS_NAME_DDIV,CDISASM_MIPS_NAME_DDIVU};
            if(wide && !m16_wide(i))return CDISASM_STATUS_INVALID_INSTRUCTION;
            m16_register(i,rx,wide ? 8u : 4u,CDISASM_OPERAND_ACCESS_READ);m16_register(i,ry,wide ? 8u : 4u,CDISASM_OPERAND_ACCESS_READ);name=multiply[fn-24u];
            i->instruction_flags|=CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_HI|CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_LO;
        } else return CDISASM_STATUS_INVALID_INSTRUCTION;
    } else if(op==31u) {
        unsigned fn=(h>>8)&7u;
        int64_t offset=extended ? imm : (int64_t)(h&31u);
        if(!m16_wide(i))return CDISASM_STATUS_INVALID_INSTRUCTION;
        if(fn<=2u || fn==4u) {
            unsigned reg=fn==2u ? 31u : ry;
            m16_register(i,reg,8u,(fn==1u || fn==2u) ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE);
            if(!extended)offset=(int64_t)(h&(fn==2u ? 255u : 31u))*8;
            m16_memory(i,29u,offset,8u,fn==1u || fn==2u,fn==4u);name=fn==1u || fn==2u ? CDISASM_MIPS_NAME_SD : CDISASM_MIPS_NAME_LD;
        } else {
            unsigned dest=fn==3u ? 29u : ry;
            unsigned base=fn==3u || fn==7u ? 29u : ry;
            m16_register(i,dest,8u,dest==base && fn!=6u ? CDISASM_OPERAND_ACCESS_READ_WRITE : CDISASM_OPERAND_ACCESS_WRITE);
            if(dest!=base)m16_register(i,base,8u,CDISASM_OPERAND_ACCESS_READ);
            if(fn==6u) { cdisasm_mips_operand *o=&i->operand[i->operand_count++];o->type=CDISASM_OPERAND_REGISTER;o->reg=CDISASM_MIPS_REG_PC;o->size=8u;o->access=CDISASM_OPERAND_ACCESS_READ; }
            if(!extended)offset=fn==3u ? compact_signed(h&255u,8u)*8 : fn==5u ? compact_signed(h&31u,5u) : offset*4;
            m16_immediate(i,offset,1);name=CDISASM_MIPS_NAME_DADDIU;
        }
    } else return CDISASM_STATUS_INVALID_INSTRUCTION;
    i->name_id=name;
    return CDISASM_STATUS_OK;
}

cdisasm_status cdisasm_mips_decode_compact(uint64_t raw, uint32_t size, cdisasm_mips_encoding encoding, uint64_t address,
                                         cdisasm_mips_mode mode, cdisasm_mips_revision revision,
                                         const cdisasm_mips_decode_flags *features,cdisasm_mips_instruction *instruction)
{
    size_t n;
    int revision_index=compact_revision(revision), matched=0,disabled=0;
    uint64_t active=features ? features->bitmap[0] : 0u;
    int fr32=revision==1u || revision==2u || revision==32u || (active&CDISASM_MIPS_DECODE_FLAG_FPR32)!=0u;
    if(!instruction || revision_index<0 || (size!=2u && size!=4u)) return CDISASM_STATUS_INVALID_ARGUMENT;
    if((unsigned)encoding==1u) {
        memset(instruction,0,sizeof(*instruction));
        instruction->address=address;instruction->opcode_size=(uint8_t)size;instruction->raw_instruction=(uint32_t)raw;
        instruction->mode=(uint8_t)mode;instruction->revision=(uint8_t)revision;
        instruction->instruction_flags=fr32 ? CDISASM_MIPS_INSTRUCTION_FLAG_FPR32 : 0u;
        return compact_mips16((uint32_t)raw,size,instruction);
    }
    if((unsigned)encoding==2u && size==4u && (revision==37u || revision==69u)) {
        if(((uint32_t)raw&UINT32_C(0xfc00003f))==UINT32_C(0x54000005) ||
           ((uint32_t)raw&UINT32_C(0xfc00003f))==UINT32_C(0x54000015)) {
            if(((raw>>6)&31u)>=16u)
                return micro_negated_compare((uint32_t)raw,address,mode,revision,active,instruction);
        }
        for(n=0;n<sizeof(micro_paired_forms)/sizeof(micro_paired_forms[0]);++n) {
            const micro_paired_form *f=&micro_paired_forms[n];
            if(((uint32_t)raw&f->mask)==f->value)
                return micro_paired_decode((uint32_t)raw,f,address,mode,revision,active,instruction);
        }
    }
    if((unsigned)encoding==2u && size==4u) {
        for(n=0;n<sizeof(micro_supplement_forms)/sizeof(micro_supplement_forms[0]);++n) {
            const micro_supplement_form *f=&micro_supplement_forms[n];
            if(((uint32_t)raw&f->mask)==f->value)
                return micro_supplement_decode((uint32_t)raw,f,address,mode,revision,instruction);
        }
    }
    for(n=0;n<sizeof(compact_forms)/sizeof(compact_forms[0]);++n) {
        const compact_form *f=&compact_forms[n];
        cdisasm_mips_instruction candidate;
        cdisasm_status status;
        if(f->encoding!=(unsigned)encoding || f->size!=size || ((uint32_t)raw&f->mask)!=f->value)continue;
        matched=1;
        if(!(f->revisions&(1u<<revision_index)) || (f->fr==1u && !fr32) || (f->fr==2u && fr32))continue;
        if(!compact_branch_class(f,(uint32_t)raw))continue;
        if((f->required&active)!=f->required) { disabled=1;continue; }
#if !USE_EXTRA_OPCODES
        if(f->required&~CDISASM_MIPS_DECODE_FLAG_FPU) { disabled=1;continue; }
#endif
        memset(&candidate,0,sizeof(candidate));
        candidate.address=address;
        candidate.opcode_size=(uint8_t)size;
        candidate.raw_instruction=(uint32_t)raw;
        candidate.mode=(uint8_t)mode;
        candidate.revision=(uint8_t)revision;
        candidate.name_id=f->name;
        candidate.form_id=f->form;
        candidate.opcode_groups=f->groups;
        candidate.instruction_flags=f->effects|(fr32 ? CDISASM_MIPS_INSTRUCTION_FLAG_FPR32 : 0u);
        status=compact_lower((uint32_t)raw,f,&candidate);
        if(status!=CDISASM_STATUS_OK)continue;
        *instruction=candidate;
        return CDISASM_STATUS_OK;
    }
    if((unsigned)encoding==2u && size==4u) {
        {
            cdisasm_status status=cdisasm_mips_micro64_r6((uint32_t)raw,address,mode,revision,features,instruction);
            if(status!=CDISASM_STATUS_UNSUPPORTED_INSTRUCTION)return status;
            status=cdisasm_mips_micro64_arithmetic((uint32_t)raw,address,mode,revision,features,instruction);
            if(status!=CDISASM_STATUS_UNSUPPORTED_INSTRUCTION)return status;
            status=cdisasm_mips_micro64_cop((uint32_t)raw,address,mode,revision,features,instruction);
            if(status!=CDISASM_STATUS_UNSUPPORTED_INSTRUCTION)return status;
            status=cdisasm_mips_micro64_fp((uint32_t)raw,address,mode,revision,features,instruction);
            if(status!=CDISASM_STATUS_UNSUPPORTED_INSTRUCTION)return status;
            status=cdisasm_mips_micro64_memory((uint32_t)raw,address,mode,revision,features,instruction);
            if(status!=CDISASM_STATUS_UNSUPPORTED_INSTRUCTION)return status;
        }
    }
    return disabled || !matched ? CDISASM_STATUS_UNSUPPORTED_INSTRUCTION : CDISASM_STATUS_INVALID_INSTRUCTION;
}

#else
size_t cdisasm_mips_compact_effects(const cdisasm_mips_instruction *instruction,cdisasm_mips_register_effect *effects,size_t capacity)
{
    (void)instruction;(void)effects;(void)capacity;return 0u;
}
uint64_t cdisasm_mips_compact_required_flags(cdisasm_mips_form_id form)
{
    (void)form;return 0u;
}
cdisasm_status cdisasm_mips_decode_compact(uint64_t raw,uint32_t size,cdisasm_mips_encoding encoding,uint64_t address,
                                         cdisasm_mips_mode mode,cdisasm_mips_revision revision,
                                         const cdisasm_mips_decode_flags *features,cdisasm_mips_instruction *instruction)
{
    (void)raw;(void)size;(void)encoding;(void)address;(void)mode;(void)revision;(void)features;(void)instruction;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}
#endif
