/* Copyright (c) 2026 hors<horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 * Original lowering of source-defined nanoMIPS CP1 numeric allocations.
 * Encoding/syntax provenance and unresolved source disagreements are retained
 * in nano_fpu_instruction_facts.json. No upstream execution code is copied.
 */
#include "mips_decoder.h"
#include <string.h>

#if USE_EXTRA_OPCODES
typedef struct nano_fpu_form {
    uint32_t mask,value,flags;
    uint16_t name,form;
    uint8_t kind,destination_size,source_size,destination_access,store,high,scale;
} nano_fpu_form;
static const nano_fpu_form nano_fpu_forms[]={
#include "generated/mips_nano_fpu_forms.inc"
};

static void nano_fp_reg(cdisasm_mips_instruction *i,unsigned bank,unsigned reg,unsigned size,unsigned access)
{
    cdisasm_mips_operand *o=&i->operand[i->operand_count++];
    o->type=CDISASM_OPERAND_REGISTER;o->reg=(cdisasm_mips_reg_id)(bank+reg);
    o->size=(uint8_t)size;o->access=(uint8_t)access;
}

static void nano_fp_memory(cdisasm_mips_instruction *i,unsigned base,unsigned index,int64_t displacement,
    unsigned size,unsigned access,unsigned scale)
{
    cdisasm_mips_operand *o=&i->operand[i->operand_count++];
    o->type=CDISASM_OPERAND_MEMORY;o->base_reg=(cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0+base);
    o->size=(uint8_t)size;o->access=(uint8_t)access;
    if(index<32u) {
        o->index_reg=(cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0+index);
        if(scale) {o->detail.flags=CDISASM_MIPS_OPERAND_DETAIL_INDEX_SCALED;o->detail.index_shift=(uint8_t)scale;}
    } else {
        o->imm=(uint64_t)displacement;o->flags=CDISASM_MIPS_OPERAND_FLAG_SIGNED|CDISASM_MIPS_OPERAND_FLAG_HAS_DISPLACEMENT;
        if(!base) {o->address=i->mode==CDISASM_MIPS_MODE_64 ? (uint64_t)displacement:(uint32_t)displacement;o->flags|=CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS|CDISASM_MIPS_OPERAND_FLAG_ABSOLUTE;}
    }
}
#endif

uint64_t cdisasm_mips_nano_fpu_required_flags(cdisasm_mips_form_id form)
{
#if USE_EXTRA_OPCODES
    if(form>=36000u && form<36144u)return CDISASM_MIPS_DECODE_FLAG_FPU;
#else
    (void)form;
#endif
    return 0;
}

int cdisasm_mips_nano_fpu_owns(uint32_t raw)
{
#if USE_EXTRA_OPCODES
    size_t n;
    if(raw>>26==40u || (raw&UINT32_C(0xfc10f006))==UINT32_C(0x80103000))return 1;
    for(n=0;n<sizeof(nano_fpu_forms)/sizeof(nano_fpu_forms[0]);++n)
        if((raw&nano_fpu_forms[n].mask)==nano_fpu_forms[n].value)return 1;
#else
    (void)raw;
#endif
    return 0;
}

cdisasm_status cdisasm_mips_nano_fpu(uint32_t raw,uint64_t address,cdisasm_mips_mode mode,
    cdisasm_mips_revision revision,const cdisasm_mips_decode_flags *features,cdisasm_mips_instruction *i)
{
#if USE_EXTRA_OPCODES
    size_t n;
    unsigned ft=(raw>>21)&31u,fs=(raw>>16)&31u,fd=(raw>>11)&31u;
    for(n=0;n<sizeof(nano_fpu_forms)/sizeof(nano_fpu_forms[0]);++n) {
        const nano_fpu_form *f=&nano_fpu_forms[n];
        if((raw&f->mask)!=f->value)continue;
        if(f->kind==8u) {
            if(mode!=CDISASM_MIPS_MODE_64 || revision!=CDISASM_MIPS_REVISION_64R6)return CDISASM_STATUS_INVALID_INSTRUCTION;
        } else if(!((mode==CDISASM_MIPS_MODE_32 && revision==CDISASM_MIPS_REVISION_32R6) ||
                    (mode==CDISASM_MIPS_MODE_64 && revision==CDISASM_MIPS_REVISION_64R6)))return CDISASM_STATUS_INVALID_INSTRUCTION;
        if(!features || !(features->bitmap[0]&CDISASM_MIPS_DECODE_FLAG_FPU))return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        if(features->bitmap[0]&CDISASM_MIPS_DECODE_FLAG_FPR32)return CDISASM_STATUS_INVALID_INSTRUCTION;
        if(!i)return CDISASM_STATUS_INVALID_ARGUMENT;
        memset(i,0,sizeof(*i));i->address=address;i->opcode_size=4;i->raw_instruction=raw;
        i->mode=(uint8_t)mode;i->revision=(uint8_t)revision;i->name_id=f->name;i->form_id=f->form;
        i->instruction_flags=CDISASM_MIPS_INSTRUCTION_FLAG_FLOATING_POINT|f->flags;
        if(f->kind==0u) {
            nano_fp_reg(i,CDISASM_MIPS_REG_FPR0,fd,f->destination_size,f->destination_access);
            nano_fp_reg(i,CDISASM_MIPS_REG_FPR0,fs,f->source_size,CDISASM_OPERAND_ACCESS_READ);
            nano_fp_reg(i,CDISASM_MIPS_REG_FPR0,ft,f->source_size,CDISASM_OPERAND_ACCESS_READ);
        } else if(f->kind==1u) {
            nano_fp_reg(i,CDISASM_MIPS_REG_FPR0,ft,f->destination_size,f->destination_access);
            nano_fp_reg(i,CDISASM_MIPS_REG_FPR0,fs,f->source_size,CDISASM_OPERAND_ACCESS_READ);
        } else if(f->kind==9u) {
            /* The primary assembler proves these explicit fields only.
             * Its FP_S view is 32 bits. Stack/memory/preservation effects
             * remain unknown and are reported by the limitations API. */
            cdisasm_mips_operand *frame=&i->operand[i->operand_count++],*list;
            unsigned count=((raw>>16)&15u)+1u;
            frame->type=CDISASM_OPERAND_IMMEDIATE;frame->size=4u;frame->imm=((raw>>3)&511u)<<3;
            nano_fp_reg(i,CDISASM_MIPS_REG_FPR0,0u,4u,f->destination_access);
            list=&i->operand[1];list->detail.flags=CDISASM_MIPS_OPERAND_DETAIL_REGISTER_LIST;
            list->imm=(UINT64_C(1)<<count)-1u;
        } else if(f->kind==8u) {
            nano_fp_reg(i,CDISASM_MIPS_REG_GPR0,ft,8u,f->store ? CDISASM_OPERAND_ACCESS_READ:CDISASM_OPERAND_ACCESS_WRITE);
            nano_fp_reg(i,CDISASM_MIPS_REG_FPR0,fs,8u,f->store ? CDISASM_OPERAND_ACCESS_WRITE:CDISASM_OPERAND_ACCESS_READ);
        } else if(f->kind==2u || f->kind==3u) {
            nano_fp_reg(i,CDISASM_MIPS_REG_GPR0,ft,!f->store && mode==CDISASM_MIPS_MODE_64 ? 8u:4u,f->store ? CDISASM_OPERAND_ACCESS_READ:CDISASM_OPERAND_ACCESS_WRITE);
            nano_fp_reg(i,f->kind==3u ? CDISASM_MIPS_REG_FCR0:CDISASM_MIPS_REG_FPR0,fs,
                f->high ? 8u:4u,f->store ? (f->high ? CDISASM_OPERAND_ACCESS_READ_WRITE:CDISASM_OPERAND_ACCESS_WRITE):CDISASM_OPERAND_ACCESS_READ);
            if(f->high)i->operand[1].detail.flags=CDISASM_MIPS_OPERAND_DETAIL_HIGH_HALF;
            if(f->kind==3u && (fs==25u || fs==26u || fs==28u || fs==31u)) {
                i->instruction_flags|=f->store ? CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_FCSR:CDISASM_MIPS_INSTRUCTION_FLAG_READS_FCSR;
                if(f->store && fs!=31u)i->instruction_flags|=CDISASM_MIPS_INSTRUCTION_FLAG_READS_FCSR;
            }
        } else {
            unsigned target=f->kind==7u ? fd:ft,base=f->kind==4u ? 28u:f->kind==7u ? ft:fs;
            unsigned index=f->kind==7u ? fs:32u;
            int64_t displacement=f->kind==4u ? (int64_t)(raw&UINT32_C(0x3fffc)):
                f->kind==5u ? (int64_t)(raw&UINT32_C(0xfff)):
                f->kind==6u ? (int64_t)(raw&255u)-(int64_t)((raw>>7)&256u):0;
            nano_fp_reg(i,CDISASM_MIPS_REG_FPR0,target,f->destination_size,f->store ? CDISASM_OPERAND_ACCESS_READ:CDISASM_OPERAND_ACCESS_WRITE);
            nano_fp_memory(i,base,index,displacement,f->destination_size,f->store ? CDISASM_OPERAND_ACCESS_WRITE:CDISASM_OPERAND_ACCESS_READ,f->scale);
        }
        return CDISASM_STATUS_OK;
    }
    /* The broader author-disassembler pool permits noncanonical fields that
     * the primary assembler does not allocate. Do not guess their contracts. */
    if((raw&UINT32_C(0xfc10f006))==UINT32_C(0x80103000))return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    /* Ownership fences prevent fallback; they do not turn every unallocated
     * CP1 word into a recognized-but-unimplemented instruction. */
    if(raw>>26==40u)return CDISASM_STATUS_INVALID_INSTRUCTION;
#else
    (void)raw;(void)address;(void)mode;(void)revision;(void)features;(void)i;
#endif
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}
