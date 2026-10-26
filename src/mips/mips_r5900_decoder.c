/* Copyright (c) 2026 hors<horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 * Original typed decoder. Numeric instruction facts: Sony EE Core Instruction
 * Set Manual6.0; pinned source identity is in the generated manifest.
 */
#include "mips_decoder.h"
#include <string.h>

static uint64_t r5900_base_required(cdisasm_mips_form_id form)
{
    if(form<49980u || form>49990u)return 0u;
    return CDISASM_MIPS_DECODE_FLAG_R5900|(form>=49985u ? CDISASM_MIPS_DECODE_FLAG_FPU : 0u);
}
int cdisasm_mips_r5900_owns(uint32_t raw)
{
    unsigned op=raw>>26,rs=(raw>>21)&31u,rt=(raw>>16)&31u,fn=raw&63u;
    if(op==28u || op==30u || op==31u || op==51u)return 1;
    if(op==0u && (fn==40u || fn==41u || fn==10u || fn==11u || ((fn==24u || fn==25u)&&((raw>>11)&31u))))return 1;
    if(op==1u && (rt==24u || rt==25u))return 1;
    if(op==16u && ((raw&UINT32_C(0xffe0fffc))==UINT32_C(0x4000c800) || (raw&UINT32_C(0xffe0fffc))==UINT32_C(0x4080c800) || raw==UINT32_C(0x42000038) || raw==UINT32_C(0x42000039)))return 1;
    return op==17u && rs==16u && (fn==4u || fn==22u || (fn>=24u&&fn<=31u) || fn==36u || fn==40u || fn==41u || fn==48u || fn==50u || fn==52u || fn==54u);
}
static void r5900_base_reg(cdisasm_mips_instruction *i,unsigned bank,unsigned reg,unsigned size,unsigned access)
{
    cdisasm_mips_operand *o=&i->operand[i->operand_count++];
    o->type=CDISASM_OPERAND_REGISTER;o->reg=(uint16_t)(bank+reg);o->size=(uint8_t)size;o->access=(uint8_t)access;
}
static cdisasm_status r5900_base(uint32_t raw,uint64_t address,cdisasm_mips_mode mode,cdisasm_mips_revision revision,
                               uint64_t active,cdisasm_mips_instruction *instruction)
{
    unsigned op=raw>>26,rs=(raw>>21)&31u,rt=(raw>>16)&31u,rd=(raw>>11)&31u,fd=(raw>>6)&31u,fn=raw&63u;
    cdisasm_mips_instruction i;
    cdisasm_mips_operand *o;
    memset(&i,0,sizeof(i));i.address=address;i.raw_instruction=raw;i.opcode_size=4u;i.mode=(uint8_t)mode;i.revision=(uint8_t)revision;
    i.instruction_flags=CDISASM_MIPS_INSTRUCTION_FLAG_FPR32;
    if(op==0u && (fn==10u || fn==11u)) {
        if(fd)return CDISASM_STATUS_INVALID_INSTRUCTION;
        i.name_id=fn==11u ? CDISASM_MIPS_NAME_MOVN : CDISASM_MIPS_NAME_MOVZ;i.form_id=(uint16_t)(fn==11u ? 49980u : 49981u);
        r5900_base_reg(&i,CDISASM_MIPS_REG_GPR0,rd,8u,CDISASM_OPERAND_ACCESS_READ_WRITE);
        r5900_base_reg(&i,CDISASM_MIPS_REG_GPR0,rs,8u,CDISASM_OPERAND_ACCESS_READ);
        r5900_base_reg(&i,CDISASM_MIPS_REG_GPR0,rt,8u,CDISASM_OPERAND_ACCESS_READ);
    } else if(op==51u) {
        int64_t displacement=(int64_t)((raw&65535u)^32768u)-32768;
        i.name_id=CDISASM_MIPS_NAME_PREF;i.form_id=49982u;
        o=&i.operand[i.operand_count++];o->type=CDISASM_OPERAND_IMMEDIATE;o->imm=rt;o->size=1u;o->access=CDISASM_OPERAND_ACCESS_READ;
        o=&i.operand[i.operand_count++];o->type=CDISASM_OPERAND_MEMORY;o->base_reg=(uint16_t)(CDISASM_MIPS_REG_GPR0+rs);o->imm=(uint64_t)displacement;
        o->access=CDISASM_OPERAND_ACCESS_READ;o->flags=CDISASM_MIPS_OPERAND_FLAG_SIGNED|CDISASM_MIPS_OPERAND_FLAG_HAS_DISPLACEMENT|CDISASM_OPERAND_FLAG_ADDRESS_ONLY;
        if(!rs){o->address=(uint64_t)displacement;o->flags|=CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS|CDISASM_MIPS_OPERAND_FLAG_ABSOLUTE;}
    } else if(raw==UINT32_C(0x42000038) || raw==UINT32_C(0x42000039)) {
        i.name_id=fn==56u ? CDISASM_MIPS_NAME_EI : CDISASM_MIPS_NAME_DI;i.form_id=(uint16_t)(fn==56u ? 49983u : 49984u);i.opcode_groups=CDISASM_GROUP_PRIVILEGED;
    } else if(op==17u && rs==16u && (fn==4u || fn==36u || fn==48u || fn==50u || fn==52u || fn==54u)) {
        if(!(active&CDISASM_MIPS_DECODE_FLAG_FPU))return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        if((fn==4u&&rd) || (fn>=48u&&fd) || (fn==36u&&rt))return CDISASM_STATUS_INVALID_INSTRUCTION;
        i.instruction_flags|=CDISASM_MIPS_INSTRUCTION_FLAG_FLOATING_POINT|CDISASM_MIPS_INSTRUCTION_FLAG_READS_FCSR|CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_FCSR;
        if(fn==4u) {
            i.name_id=CDISASM_MIPS_NAME_SQRT_S;i.form_id=49985u;
            r5900_base_reg(&i,CDISASM_MIPS_REG_FPR0,fd,4u,CDISASM_OPERAND_ACCESS_WRITE);r5900_base_reg(&i,CDISASM_MIPS_REG_FPR0,rt,4u,CDISASM_OPERAND_ACCESS_READ);
        } else if(fn==36u) {
            i.name_id=CDISASM_MIPS_NAME_TRUNC_W_S;i.form_id=49990u;
            r5900_base_reg(&i,CDISASM_MIPS_REG_FPR0,fd,4u,CDISASM_OPERAND_ACCESS_WRITE);r5900_base_reg(&i,CDISASM_MIPS_REG_FPR0,rd,4u,CDISASM_OPERAND_ACCESS_READ);
        } else {
            i.name_id=fn==48u ? CDISASM_MIPS_NAME_C_F_S : fn==50u ? CDISASM_MIPS_NAME_C_EQ_S : fn==52u ? CDISASM_MIPS_NAME_C_LT_S : CDISASM_MIPS_NAME_C_LE_S;
            i.form_id=(uint16_t)(49986u+(fn-48u)/2u);
            r5900_base_reg(&i,CDISASM_MIPS_REG_FPR0,rd,4u,CDISASM_OPERAND_ACCESS_READ);r5900_base_reg(&i,CDISASM_MIPS_REG_FPR0,rt,4u,CDISASM_OPERAND_ACCESS_READ);
        }
    } else return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    *instruction=i;return CDISASM_STATUS_OK;
}

#if USE_EXTRA_OPCODES && USE_MIPS_R5900
typedef struct r5900_resource {uint16_t reg;uint8_t access,size;} r5900_resource;
typedef struct r5900_form {
    uint32_t mask,value;
    uint16_t name,form;
    uint8_t recipe,size,floating,effect_count;
    r5900_resource effect[4];
} r5900_form;
#include "generated/mips_r5900_forms.inc"

static const r5900_form *r5900_find(cdisasm_mips_form_id form)
{
    size_t n;
    for(n=0;n<sizeof(r5900_forms)/sizeof(r5900_forms[0]);++n)if(r5900_forms[n].form==form)return &r5900_forms[n];
    return NULL;
}
uint64_t cdisasm_mips_r5900_required_flags(cdisasm_mips_form_id form)
{
    const r5900_form *f=r5900_find(form);
    return f ? CDISASM_MIPS_DECODE_FLAG_R5900|(f->floating ? CDISASM_MIPS_DECODE_FLAG_FPU : 0u) : r5900_base_required(form);
}
size_t cdisasm_mips_r5900_effects(const cdisasm_mips_instruction *instruction,cdisasm_mips_register_effect *effects,size_t capacity)
{
    const r5900_form *f=instruction ? r5900_find(instruction->form_id) : NULL;
    size_t n;
    if(!f) {
        if(instruction && instruction->form_id>=49986u && instruction->form_id<=49989u) {
            if(capacity){memset(effects,0,sizeof(*effects));effects[0].reg=CDISASM_MIPS_REG_FCC0;effects[0].access=CDISASM_OPERAND_ACCESS_WRITE;effects[0].size=1u;}
            return 1u;
        }
        return 0u;
    }
    for(n=0;n<f->effect_count && n<capacity;++n) {
        memset(&effects[n],0,sizeof(effects[n]));effects[n].reg=f->effect[n].reg;
        effects[n].access=f->effect[n].access;effects[n].size=f->effect[n].size;
    }
    if(f->recipe==R5900_PERF_GET || f->recipe==R5900_PERF_SET) {
        if(capacity) {
            memset(effects,0,sizeof(*effects));effects[0].reg=CDISASM_MIPS_REG_CP0(25u,instruction->raw_instruction&3u);
            effects[0].size=4u;effects[0].access=f->recipe==R5900_PERF_GET ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE;
        }
        return 1u;
    }
    return f->effect_count;
}
static void r5900_register(cdisasm_mips_instruction *i,unsigned bank,unsigned reg,unsigned size,unsigned access)
{
    cdisasm_mips_operand *o=&i->operand[i->operand_count++];
    o->type=CDISASM_OPERAND_REGISTER;o->reg=(uint16_t)(bank+reg);o->size=(uint8_t)size;o->access=(uint8_t)access;
}
static void r5900_immediate(cdisasm_mips_instruction *i,uint32_t value,unsigned size)
{
    cdisasm_mips_operand *o=&i->operand[i->operand_count++];
    o->type=CDISASM_OPERAND_IMMEDIATE;o->imm=value;o->size=(uint8_t)size;o->access=CDISASM_OPERAND_ACCESS_READ;
}

static cdisasm_status r5900_decode_extra(uint32_t raw,uint64_t address,cdisasm_mips_mode mode,cdisasm_mips_revision revision,
                                       const cdisasm_mips_decode_flags *features,cdisasm_mips_instruction *instruction)
{
    size_t n;
    unsigned rs=(raw>>21)&31u,rt=(raw>>16)&31u,rd=(raw>>11)&31u,sa=(raw>>6)&31u,op=raw>>26;
    uint64_t active=features ? features->bitmap[0] : 0u;
    if(!(active&CDISASM_MIPS_DECODE_FLAG_R5900))return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    if(mode!=CDISASM_MIPS_MODE_64 || revision!=CDISASM_MIPS_REVISION_III)return CDISASM_STATUS_INVALID_INSTRUCTION;
    for(n=0;n<sizeof(r5900_forms)/sizeof(r5900_forms[0]);++n) {
        const r5900_form *f=&r5900_forms[n];
        cdisasm_mips_instruction candidate;
        if((raw&f->mask)!=f->value)continue;
        if(f->floating && !(active&CDISASM_MIPS_DECODE_FLAG_FPU))return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        memset(&candidate,0,sizeof(candidate));candidate.address=address;candidate.raw_instruction=raw;candidate.opcode_size=4u;
        candidate.mode=(uint8_t)mode;candidate.revision=(uint8_t)revision;candidate.name_id=f->name;candidate.form_id=f->form;
        candidate.instruction_flags=CDISASM_MIPS_INSTRUCTION_FLAG_FPR32;
        if(f->floating) {
            candidate.instruction_flags|=CDISASM_MIPS_INSTRUCTION_FLAG_FLOATING_POINT;
            if(f->name!=CDISASM_MIPS_NAME_MAX_S && f->name!=CDISASM_MIPS_NAME_MIN_S)
                candidate.instruction_flags|=CDISASM_MIPS_INSTRUCTION_FLAG_READS_FCSR|CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_FCSR;
        }
#define REG(reg_,size_,access_) r5900_register(&candidate,CDISASM_MIPS_REG_GPR0,(reg_),(size_),(access_))
#define FPR(reg_,access_) r5900_register(&candidate,CDISASM_MIPS_REG_FPR0,(reg_),4u,(access_))
        switch(f->recipe) {
            case R5900_RD_RS_RT:
                REG(rd,f->size,CDISASM_OPERAND_ACCESS_WRITE);
                REG(rs,f->name==CDISASM_MIPS_NAME_PCPYLD ? 8u : f->size,CDISASM_OPERAND_ACCESS_READ);
                REG(rt,f->name==CDISASM_MIPS_NAME_PCPYLD ? 8u : f->size,CDISASM_OPERAND_ACCESS_READ);break;
            case R5900_RD_RT_RS:
                REG(rd,f->size,CDISASM_OPERAND_ACCESS_WRITE);REG(rt,f->size,CDISASM_OPERAND_ACCESS_READ);REG(rs,f->size,CDISASM_OPERAND_ACCESS_READ);break;
            case R5900_RD_RT:
                REG(rd,f->size,CDISASM_OPERAND_ACCESS_WRITE);REG(rt,f->size,CDISASM_OPERAND_ACCESS_READ);break;
            case R5900_RD_RS:
                REG(rd,f->size,CDISASM_OPERAND_ACCESS_WRITE);REG(rs,f->size,CDISASM_OPERAND_ACCESS_READ);break;
            case R5900_RD:REG(rd,f->size,CDISASM_OPERAND_ACCESS_WRITE);break;
            case R5900_RS:REG(rs,f->size,CDISASM_OPERAND_ACCESS_READ);break;
            case R5900_RS_RT:
                REG(rs,f->size,CDISASM_OPERAND_ACCESS_READ);REG(rt,f->name==CDISASM_MIPS_NAME_PDIVBW ? 2u : f->size,CDISASM_OPERAND_ACCESS_READ);break;
            case R5900_RD_RT_SA:
                REG(rd,16u,CDISASM_OPERAND_ACCESS_WRITE);REG(rt,16u,CDISASM_OPERAND_ACCESS_READ);r5900_immediate(&candidate,sa,1u);break;
            case R5900_SCALAR_MUL:
                if(rd)REG(rd,8u,CDISASM_OPERAND_ACCESS_WRITE);
                /* Sony's NotWordValue check observes bits63:32 as well as
                 * the low arithmetic word (EE pp138-145/154-157). */
                REG(rs,8u,CDISASM_OPERAND_ACCESS_READ);REG(rt,8u,CDISASM_OPERAND_ACCESS_READ);break;
            case R5900_SCALAR_DIV:
                REG(rs,8u,CDISASM_OPERAND_ACCESS_READ);REG(rt,8u,CDISASM_OPERAND_ACCESS_READ);break;
            case R5900_RS_IMM:
                REG(rs,8u,CDISASM_OPERAND_ACCESS_READ);r5900_immediate(&candidate,raw&65535u,2u);break;
            case R5900_QUAD_MEM:
                {
                    cdisasm_mips_operand *o;
                    int store=f->name==CDISASM_MIPS_NAME_SQ;
                    int64_t displacement=(int64_t)((raw&65535u)^32768u)-32768;
                    REG(rt,16u,store ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE);
                    o=&candidate.operand[candidate.operand_count++];o->type=CDISASM_OPERAND_MEMORY;o->size=16u;
                    o->base_reg=(uint16_t)(CDISASM_MIPS_REG_GPR0+rs);o->imm=(uint64_t)displacement;
                    o->flags=CDISASM_MIPS_OPERAND_FLAG_SIGNED|CDISASM_MIPS_OPERAND_FLAG_HAS_DISPLACEMENT;
                    o->access=store ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ;
                    if(!rs) {o->address=(uint64_t)displacement&~UINT64_C(15);o->flags|=CDISASM_MIPS_OPERAND_FLAG_ABSOLUTE|CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS;}
                }
                break;
            case R5900_FD_FS_FT:FPR(sa,CDISASM_OPERAND_ACCESS_WRITE);FPR(rd,CDISASM_OPERAND_ACCESS_READ);FPR(rt,CDISASM_OPERAND_ACCESS_READ);break;
            case R5900_FS_FT:case R5900_FS_FT_COMPARE:FPR(rd,CDISASM_OPERAND_ACCESS_READ);FPR(rt,CDISASM_OPERAND_ACCESS_READ);break;
            case R5900_FD_FT:FPR(sa,CDISASM_OPERAND_ACCESS_WRITE);FPR(rt,CDISASM_OPERAND_ACCESS_READ);break;
            case R5900_PERF_GET:case R5900_PERF_SET:
                REG(rt,8u,f->recipe==R5900_PERF_GET ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ);
                r5900_immediate(&candidate,(raw>>1)&1u,1u);candidate.opcode_groups=CDISASM_GROUP_PRIVILEGED;break;
            case R5900_NONE:candidate.opcode_groups=CDISASM_GROUP_PRIVILEGED;break;
            default:return CDISASM_STATUS_INTERNAL_ERROR;
        }
#undef REG
#undef FPR
        *instruction=candidate;
        return CDISASM_STATUS_OK;
    }
    /* Occupied R5900 opcode spaces must never fall through into a later ISA's
     * unrelated SPECIAL2/SPECIAL3/FP operations. Common legal III forms are
     * deliberately left to the ordinary typed scalar decoder. */
    if(op==28u)return CDISASM_STATUS_INVALID_INSTRUCTION;
    if(op==17u && rs==16u && cdisasm_mips_r5900_owns(raw))return CDISASM_STATUS_INVALID_INSTRUCTION;
    if(op==16u && cdisasm_mips_r5900_owns(raw))return CDISASM_STATUS_INVALID_INSTRUCTION;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}
#else
uint64_t cdisasm_mips_r5900_required_flags(cdisasm_mips_form_id form){return r5900_base_required(form);}
size_t cdisasm_mips_r5900_effects(const cdisasm_mips_instruction *instruction,cdisasm_mips_register_effect *effects,size_t capacity)
{
    if(instruction && instruction->form_id>=49986u && instruction->form_id<=49989u) {
        if(capacity){memset(effects,0,sizeof(*effects));effects[0].reg=CDISASM_MIPS_REG_FCC0;effects[0].access=CDISASM_OPERAND_ACCESS_WRITE;effects[0].size=1u;}return 1u;
    }
    return 0u;
}
static cdisasm_status r5900_decode_extra(uint32_t raw,uint64_t address,cdisasm_mips_mode mode,cdisasm_mips_revision revision,
                                       const cdisasm_mips_decode_flags *features,cdisasm_mips_instruction *instruction)
{(void)raw;(void)address;(void)mode;(void)revision;(void)features;(void)instruction;return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;}
#endif

cdisasm_status cdisasm_mips_decode_r5900(uint32_t raw,uint64_t address,cdisasm_mips_mode mode,cdisasm_mips_revision revision,
                                       const cdisasm_mips_decode_flags *features,cdisasm_mips_instruction *instruction)
{
    uint64_t active=features ? features->bitmap[0] : 0u;
    uint64_t physical=features ? features->bitmap[7] : 0u;
    unsigned op=raw>>26,rs=(raw>>21)&31u,rt=(raw>>16)&31u,fn=raw&63u;
    cdisasm_status status;
    /* Bitmap7 is private wrapper state, never accepted from callers. A named
     * processor keeps its physical instruction restrictions when optional
     * extension decoding is disabled in bitmap0. */
    if(!((active|physical)&CDISASM_MIPS_DECODE_FLAG_R5900))return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    if(mode!=CDISASM_MIPS_MODE_64 || revision!=CDISASM_MIPS_REVISION_III)return CDISASM_STATUS_INVALID_INSTRUCTION;
    if(op==48u || op==52u || op==56u || op==60u || op==19u)return CDISASM_STATUS_INVALID_INSTRUCTION;
    status=r5900_base(raw,address,mode,revision,active,instruction);
    if(status!=CDISASM_STATUS_UNSUPPORTED_INSTRUCTION || cdisasm_mips_r5900_owns(raw)) {
        if(status!=CDISASM_STATUS_UNSUPPORTED_INSTRUCTION)return status;
        return r5900_decode_extra(raw,address,mode,revision,features,instruction);
    }
    if(op==17u) {
        if(rs==16u)return fn==0u || fn==1u || fn==2u || fn==3u || fn==5u || fn==6u || fn==7u ? CDISASM_STATUS_UNSUPPORTED_INSTRUCTION : CDISASM_STATUS_INVALID_INSTRUCTION;
        if(rs==20u)return fn==32u ? CDISASM_STATUS_UNSUPPORTED_INSTRUCTION : CDISASM_STATUS_INVALID_INSTRUCTION;
        if(rs==0u || rs==2u || rs==4u || rs==6u || (rs==8u && rt<4u))return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
    return r5900_decode_extra(raw,address,mode,revision,features,instruction);
}
