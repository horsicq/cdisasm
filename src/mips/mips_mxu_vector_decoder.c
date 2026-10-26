/* Copyright (c) 2026 hors<horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 * Original allocation-free numeric lowering for Ingenic MXU vector ISAs.
 * Architectural source identities and finite coverage are in the generated
 * manifest. No compiler, disassembler, or emulator implementation is linked.
 */
#include "mips_decoder.h"
#include <string.h>

typedef struct mxuv_owner {uint32_t mask,value;uint8_t generation;} mxuv_owner;
#include "generated/mips_mxu_vector_ownership.inc"

int cdisasm_mips_mxu_vector_owns(uint32_t raw,const cdisasm_mips_decode_flags *features)
{
    uint64_t enabled=features!=NULL ? (features->bitmap[0]|features->bitmap[CDISASM_MIPS_INTERNAL_POLICY_WORD]) : 0;
    unsigned generation=(enabled&CDISASM_MIPS_DECODE_FLAG_MXU3)!=0u ? 3u : (enabled&CDISASM_MIPS_DECODE_FLAG_MXU2)!=0u ? 2u : 0u;
    size_t n;
    if(!generation)return 0;
    if(raw>>26==18u)return 1;
    for(n=0;n<sizeof(mxuv_owners)/sizeof(mxuv_owners[0]);++n)
        if(mxuv_owners[n].generation==generation && (raw&mxuv_owners[n].mask)==mxuv_owners[n].value)return 1;
    return 0;
}

#if USE_EXTRA_OPCODES && (USE_MIPS_MXU2 || USE_MIPS_MXU3)
typedef struct mxuv_operand {
    uint8_t shift,width,destination_shift,shift2,width2,destination_shift2,shift3,width3,destination_shift3;
    uint8_t kind,access,size,element,scale,lane_kind,lane_shift,lane_width,lane_modulo,lane_constant;
    uint8_t base,index,displacement_scale,displacement_signed,implicit,post_update,bare;
    uint32_t allowed_values;
    uint8_t displacement_shift,displacement_width,displacement_destination_shift;
    uint8_t displacement_shift2,displacement_width2,displacement_destination_shift2;
    uint8_t displacement_shift3,displacement_width3,displacement_destination_shift3;
} mxuv_operand;
typedef struct mxuv_form {
    uint32_t mask,value;
    uint64_t required;
    cdisasm_mips_name_id name;
    cdisasm_mips_form_id form;
    uint8_t generation,operand_count,flags,control_access;
    mxuv_operand operand[6];
} mxuv_form;
#include "generated/mips_mxu_vector_forms.inc"
#include "generated/mips_mxu_vector_limitations.inc"

static unsigned mxuv_bits(uint32_t raw,unsigned shift,unsigned width)
{
    return width ? (unsigned)((raw>>shift)&((UINT32_C(1)<<width)-1u)) : 0u;
}
static unsigned mxuv_extract(uint32_t raw,const mxuv_operand *op)
{
    return (mxuv_bits(raw,op->shift,op->width)<<op->destination_shift)|
           (mxuv_bits(raw,op->shift2,op->width2)<<op->destination_shift2)|
           (mxuv_bits(raw,op->shift3,op->width3)<<op->destination_shift3);
}
static int64_t mxuv_signed(unsigned value,unsigned width)
{
    return width ? (int64_t)(value^(UINT32_C(1)<<(width-1u)))-(INT64_C(1)<<(width-1u)) : 0;
}
static const mxuv_form *mxuv_find(cdisasm_mips_form_id form)
{
    size_t n;
    for(n=0;n<sizeof(mxuv_forms)/sizeof(mxuv_forms[0]);++n)if(mxuv_forms[n].form==form)return &mxuv_forms[n];
    return NULL;
}
static int mxuv_lower(const mxuv_form *form,uint32_t raw,uint64_t active,cdisasm_mips_instruction *result)
{
    unsigned n;
    int paired=(active&CDISASM_MIPS_DECODE_FLAG_FPR32)!=0u || result->revision==CDISASM_MIPS_REVISION_32R1;
    for(n=0;n<form->operand_count;++n) {
        const mxuv_operand *spec=&form->operand[n];
        cdisasm_mips_operand *op=&result->operand[result->operand_count++];
        unsigned value=mxuv_extract(raw,spec);
        if(spec->allowed_values && (value>=32u || !(spec->allowed_values&(UINT32_C(1)<<value))))return 0;
        op->size=spec->size;op->access=spec->access;
        if(spec->implicit)op->flags|=CDISASM_OPERAND_FLAG_IMPLICIT;
        if(spec->kind<=6u || spec->kind==11u) {
            unsigned bank=0u;
            switch(spec->kind) {
                case 1u:bank=form->generation==2u ? CDISASM_MIPS_REG_MXU2_VR_FIRST : CDISASM_MIPS_REG_MXU3_VR_FIRST;break;
                case 2u:bank=CDISASM_MIPS_REG_GPR0;break;
                case 3u:
                    bank=CDISASM_MIPS_REG_FPR0;
                    if(paired && spec->size==8u && (value&1u))return 0;
                    if(paired)result->instruction_flags|=CDISASM_MIPS_INSTRUCTION_FLAG_FPR32;
                    break;
                case 4u:bank=form->generation==2u ? CDISASM_MIPS_REG_MXU2_CTRL_FIRST : CDISASM_MIPS_REG_MXU3_CTRL_FIRST;break;
                case 5u:bank=CDISASM_MIPS_REG_MXU3_VSR_FIRST;break;
                case 6u:bank=CDISASM_MIPS_REG_MXU3_VWR_FIRST;break;
                case 11u:bank=CDISASM_MIPS_REG_MXU3_MCS_FIRST;break;
                default:return 0;
            }
            op->type=CDISASM_OPERAND_REGISTER;op->reg=(cdisasm_mips_reg_id)(bank+value);
            op->detail.element_size=spec->element;
            if(spec->lane_kind) {
                unsigned lane=mxuv_bits(raw,spec->lane_shift,spec->lane_width);
                op->detail.flags|=CDISASM_MIPS_OPERAND_DETAIL_HAS_LANE;
                if(spec->lane_kind==2u) {
                    op->detail.flags|=CDISASM_MIPS_OPERAND_DETAIL_LANE_REGISTER;
                    op->index_reg=(cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0+lane);
                } else {
                    /* The assembly operand is the encoded selector. MXU2
                     * masks it to MLEN/esize during execution, but reducing
                     * it here would discard architecturally encoded bits. */
                    op->detail.lane_index=(uint8_t)(spec->lane_kind==3u ? spec->lane_constant : lane);
                }
            }
        } else if(spec->kind==10u) {
            unsigned base=mxuv_bits(raw,spec->base,5u);
            op->type=CDISASM_OPERAND_MEMORY;
            if(spec->bare)op->detail.flags|=CDISASM_MIPS_OPERAND_DETAIL_BARE_BASE;
            op->base_reg=(cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0+base);
            if(spec->index!=255u)op->index_reg=(cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0+mxuv_bits(raw,spec->index,5u));
            else {
                unsigned displacement=(mxuv_bits(raw,spec->displacement_shift,spec->displacement_width)<<spec->displacement_destination_shift)|
                    (mxuv_bits(raw,spec->displacement_shift2,spec->displacement_width2)<<spec->displacement_destination_shift2)|
                    (mxuv_bits(raw,spec->displacement_shift3,spec->displacement_width3)<<spec->displacement_destination_shift3);
                unsigned width=spec->displacement_width+spec->displacement_width2+spec->displacement_width3;
                op->imm=(uint64_t)((spec->displacement_signed ? mxuv_signed(displacement,width) : (int64_t)displacement)*(INT64_C(1)<<spec->displacement_scale));
                op->flags|=CDISASM_MIPS_OPERAND_FLAG_HAS_DISPLACEMENT;
                if(spec->displacement_signed)op->flags|=CDISASM_MIPS_OPERAND_FLAG_SIGNED;
                if(!base) {op->address=(uint32_t)op->imm;op->flags|=CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS|CDISASM_MIPS_OPERAND_FLAG_ABSOLUTE;}
            }
        } else {
            unsigned width=spec->width+spec->width2+spec->width3;
            int64_t immediate=(spec->kind==8u || spec->kind==9u) ? mxuv_signed(value,width) : (int64_t)value;
            immediate*=INT64_C(1)<<spec->scale;
            op->type=CDISASM_OPERAND_IMMEDIATE;op->imm=(uint64_t)immediate;
            if(spec->kind==8u || spec->kind==9u)op->flags|=CDISASM_MIPS_OPERAND_FLAG_SIGNED;
            if(spec->kind==9u) {
                op->address=(uint64_t)immediate;
                op->imm=(uint32_t)(result->address+4u+(uint64_t)immediate);
                op->flags|=CDISASM_MIPS_OPERAND_FLAG_RELATIVE|CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS;
                result->branch_target=op->imm;
            }
        }
    }
    if(form->flags&1u)result->instruction_flags|=CDISASM_MIPS_INSTRUCTION_FLAG_FLOATING_POINT;
    if(form->flags&2u) {
        result->instruction_flags|=CDISASM_MIPS_INSTRUCTION_FLAG_DELAY_SLOT;
        result->opcode_groups=CDISASM_GROUP_JUMP|CDISASM_GROUP_CONDITIONAL|CDISASM_GROUP_RELATIVE_BRANCH;
    }
    return 1;
}
#endif

uint64_t cdisasm_mips_mxu_vector_required_flags(cdisasm_mips_form_id form)
{
#if USE_EXTRA_OPCODES && (USE_MIPS_MXU2 || USE_MIPS_MXU3)
    const mxuv_form *row=mxuv_find(form);return row!=NULL ? row->required : UINT64_C(0);
#else
    (void)form;return 0;
#endif
}

uint32_t cdisasm_mips_mxu_vector_effect_limitations(const cdisasm_mips_instruction *instruction)
{
#if USE_EXTRA_OPCODES && (USE_MIPS_MXU2 || USE_MIPS_MXU3)
    const mxuv_form *row=instruction ? mxuv_find(instruction->form_id) : NULL;
    uint32_t result;
    unsigned n;
    if(!row || row->generation!=3u || row->form<57000u || row->form>=57496u)return 0;
    result=mxuv_recorded_limitations[row->form-57000u];
    /* This is an evidence-gap query, not a guessed physical dependency.
     * Public callers validate the complete canonical instruction first. */
    for(n=0;n<instruction->operand_count && n<CDISASM_MIPS_MAX_OPERANDS;++n) {
        const cdisasm_mips_operand *op=&instruction->operand[n];
        if(op->type!=CDISASM_OPERAND_REGISTER)continue;
        if((op->reg>=CDISASM_MIPS_REG_MXU3_VSR_FIRST && op->reg<=CDISASM_MIPS_REG_MXU3_VSR_FIRST+3u) ||
           (op->reg>=CDISASM_MIPS_REG_MXU3_VWR_FIRST+16u && op->reg<=CDISASM_MIPS_REG_MXU3_VWR_LAST))result|=CDISASM_MIPS_EFFECT_LIMITATION_REGISTER_ALIASES;
    }
    return result;
#else
    (void)instruction;return 0;
#endif
}

size_t cdisasm_mips_mxu_vector_effects(const cdisasm_mips_instruction *instruction,cdisasm_mips_register_effect *effects,size_t capacity)
{
#if USE_EXTRA_OPCODES && (USE_MIPS_MXU2 || USE_MIPS_MXU3)
    const mxuv_form *row=instruction!=NULL ? mxuv_find(instruction->form_id) : NULL;
    size_t count=0;unsigned n,alias_access=0;
    if(row==NULL)return 0;
    if(row->control_access) {
        if(effects!=NULL && count<capacity) {
            memset(&effects[count],0,sizeof(*effects));effects[count].size=4u;effects[count].access=row->control_access;
            effects[count].reg=(cdisasm_mips_reg_id)((row->generation==2u ? CDISASM_MIPS_REG_MXU2_CTRL_FIRST : CDISASM_MIPS_REG_MXU3_CTRL_FIRST)+31u);
        }
        ++count;
    }
    for(n=0;n<instruction->operand_count;++n)if(row->operand[n].post_update) {
        /* The pinned basic LU/SU compiler contracts load/store through the
         * old address and then advance the 32-bit base by element size. The
         * generic memory effect supplies its read; retain the write here. */
        if(effects!=NULL && count<capacity) {
            memset(&effects[count],0,sizeof(*effects));effects[count].size=4u;
            effects[count].access=CDISASM_OPERAND_ACCESS_READ_WRITE;
            effects[count].reg=instruction->operand[n].base_reg;
        }
        ++count;
    }
    if(row->generation==3u)for(n=0;n<instruction->operand_count;++n) {
        const cdisasm_mips_operand *op=&instruction->operand[n];
        /* The manufacturer compiler returns bound VW0..15 through
         * VR31[word0..15]. Keep the encoded resource in the generic effects
         * and add a conservative whole-parent footprint here. Partial writes
         * preserve the other words. Encoded VW16..31 remain unresolved. */
        if(op->type==CDISASM_OPERAND_REGISTER &&
           op->reg>=CDISASM_MIPS_REG_MXU3_VWR_FIRST &&
           op->reg<CDISASM_MIPS_REG_MXU3_VWR_FIRST+16u) {
            alias_access|=(op->access&CDISASM_OPERAND_ACCESS_WRITE) ? CDISASM_OPERAND_ACCESS_READ_WRITE:op->access;
        }
    }
    if(alias_access) {
        if(effects!=NULL && count<capacity) {
            memset(&effects[count],0,sizeof(*effects));effects[count].size=64u;effects[count].access=(cdisasm_operand_access)alias_access;
            effects[count].reg=(cdisasm_mips_reg_id)(CDISASM_MIPS_REG_MXU3_VR_FIRST+31u);
        }
        ++count;
    }
    return count;
#else
    (void)instruction;(void)effects;(void)capacity;return 0;
#endif
}

cdisasm_status cdisasm_mips_decode_mxu_vector(uint32_t raw,uint64_t address,cdisasm_mips_mode mode,
    cdisasm_mips_revision revision,const cdisasm_mips_decode_flags *features,cdisasm_mips_instruction *instruction)
{
#if USE_EXTRA_OPCODES && (USE_MIPS_MXU2 || USE_MIPS_MXU3)
    uint64_t active=features!=NULL ? features->bitmap[0] : 0;
    unsigned generation=(active&CDISASM_MIPS_DECODE_FLAG_MXU3)!=0u ? 3u : (active&CDISASM_MIPS_DECODE_FLAG_MXU2)!=0u ? 2u : 0u;
    int disabled=0;size_t n;
    if(instruction==NULL)return CDISASM_STATUS_INTERNAL_ERROR;
    if(!generation || mode!=CDISASM_MIPS_MODE_32 ||
       (revision!=CDISASM_MIPS_REVISION_32R1 && revision!=CDISASM_MIPS_REVISION_32R2 &&
        revision!=CDISASM_MIPS_REVISION_32R3 && revision!=CDISASM_MIPS_REVISION_32R5))return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    for(n=0;n<sizeof(mxuv_forms)/sizeof(mxuv_forms[0]);++n) {
        const mxuv_form *row=&mxuv_forms[n];cdisasm_mips_instruction result;
        if(row->generation!=generation || (raw&row->mask)!=row->value)continue;
        if((active&row->required)!=row->required || ((row->flags&4u) && (active&CDISASM_MIPS_DECODE_FLAG_MXU3_1))) {disabled=1;continue;}
        memset(&result,0,sizeof(result));result.address=address;result.raw_instruction=raw;result.opcode_size=4u;
        result.mode=(uint8_t)mode;result.revision=(uint8_t)revision;result.name_id=row->name;result.form_id=row->form;
        if(!mxuv_lower(row,raw,active,&result))return CDISASM_STATUS_INVALID_INSTRUCTION;
        *instruction=result;return CDISASM_STATUS_OK;
    }
    if(!disabled && cdisasm_mips_mxu_vector_owns(raw,features))return CDISASM_STATUS_INVALID_INSTRUCTION;
#else
    (void)raw;(void)address;(void)mode;(void)revision;(void)features;(void)instruction;
#endif
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}
