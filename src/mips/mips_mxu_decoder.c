/* Copyright (c) 2026 hors<horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 * Original numeric decoder for Ingenic's original 32-bit-XR MXU architecture.
 * Operand semantics: Ingenic XBurst ISA Programming Manual, June 2, 2017.
 * The checked-in inventory records the exact manual and independent numeric
 * reference identities. No upstream decoder or emulator is linked or copied.
 */
#include "mips_decoder.h"
#include <string.h>

#if USE_EXTRA_OPCODES && USE_MIPS_MXU
typedef struct mips_mxu_operand_spec {
    uint8_t kind, shift, width, access, scale, element_size;
    uint16_t minimum, maximum;
} mips_mxu_operand_spec;
typedef struct mips_mxu_memory_spec {
    uint8_t size, access, base, index, stride, displacement;
} mips_mxu_memory_spec;
typedef struct mips_mxu_form {
    uint32_t mask, value;
    cdisasm_mips_name_id name;
    cdisasm_mips_form_id form;
    uint8_t operand_count, control_access, hilo_writes, conditional;
    mips_mxu_operand_spec operand[6];
    mips_mxu_memory_spec memory;
} mips_mxu_form;
#include "generated/mips_mxu_inventory.inc"

static const mips_mxu_form *mxu_form(cdisasm_mips_form_id id)
{
    size_t index;
    for (index=0;index<sizeof(mips_mxu_forms)/sizeof(mips_mxu_forms[0]);++index)
        if(mips_mxu_forms[index].form==id)return &mips_mxu_forms[index];
    return NULL;
}

static unsigned mxu_field(uint32_t raw,unsigned shift,unsigned width)
{
    return (unsigned)((raw>>shift)&((UINT32_C(1)<<width)-1u));
}

static int mxu_lower(const mips_mxu_form *form,uint32_t raw,cdisasm_mips_instruction *result)
{
    unsigned index;
    for(index=0;index<form->operand_count;++index) {
        const mips_mxu_operand_spec *spec=&form->operand[index];
        cdisasm_mips_operand *operand=&result->operand[result->operand_count++];
        unsigned value=mxu_field(raw,spec->shift,spec->width);
        if(value<spec->minimum || value>spec->maximum)return 0;
        operand->access=spec->access;
        if(spec->kind<=2u) {
            operand->type=CDISASM_OPERAND_REGISTER;
            operand->reg=(cdisasm_mips_reg_id)((spec->kind==1u ? CDISASM_MIPS_REG_MXU_XR0 : CDISASM_MIPS_REG_GPR0)+value);
            operand->size=4u;
            operand->detail.element_size=spec->element_size;
        } else {
            operand->type=CDISASM_OPERAND_IMMEDIATE;
            operand->size=(uint8_t)((spec->width+spec->scale+7u)/8u);
            if(spec->kind==4u) {
                int64_t signed_value=(int64_t)(value^(1u<<(spec->width-1u)))-(INT64_C(1)<<(spec->width-1u));
                operand->imm=(uint64_t)(signed_value*(INT64_C(1)<<spec->scale));
                operand->flags=CDISASM_MIPS_OPERAND_FLAG_SIGNED;
            } else operand->imm=value;
        }
    }
    /* Only the selected lane is replaced by small loads with an insertion
     * pattern; all remaining XR bits retain their previous value. */
    if(form->memory.size && form->memory.access==CDISASM_OPERAND_ACCESS_READ &&
       form->name!=CDISASM_MIPS_NAME_LXB && form->name!=CDISASM_MIPS_NAME_LXBU &&
       form->name!=CDISASM_MIPS_NAME_LXH && form->name!=CDISASM_MIPS_NAME_LXHU &&
       form->name!=CDISASM_MIPS_NAME_LXW && form->memory.size<4u) {
        unsigned pattern=mxu_field(raw,form->memory.size==1u ? 18u : 19u,form->memory.size==1u ? 3u : 2u);
        if(pattern<(form->memory.size==1u ? 4u : 2u))result->operand[0].access=CDISASM_OPERAND_ACCESS_READ_WRITE;
    }
    if(form->memory.size) {
        const mips_mxu_memory_spec *memory=&form->memory;
        cdisasm_mips_operand *operand=&result->operand[result->operand_count++];
        unsigned base=mxu_field(raw,memory->base,5u);
        operand->type=CDISASM_OPERAND_MEMORY;
        operand->size=memory->size;
        operand->access=memory->access;
        operand->flags=CDISASM_OPERAND_FLAG_IMPLICIT;
        operand->base_reg=(cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0+base);
        if(memory->index!=255u) {
            operand->index_reg=(cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0+mxu_field(raw,memory->index,5u));
            operand->detail.flags=CDISASM_MIPS_OPERAND_DETAIL_INDEX_SCALED;
            operand->detail.index_shift=(uint8_t)mxu_field(raw,memory->stride,2u);
        } else {
            operand->imm=result->operand[memory->displacement].imm;
            operand->flags|=CDISASM_MIPS_OPERAND_FLAG_SIGNED|CDISASM_MIPS_OPERAND_FLAG_HAS_DISPLACEMENT;
            if(!base) {
                operand->address=(uint32_t)operand->imm;
                operand->flags|=CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS|CDISASM_MIPS_OPERAND_FLAG_ABSOLUTE;
            }
        }
    }
    if(form->hilo_writes)result->instruction_flags|=CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_HI|CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_LO;
    if(form->conditional)result->opcode_groups=CDISASM_GROUP_CONDITIONAL;
    return 1;
}
#endif

uint64_t cdisasm_mips_mxu_required_flags(cdisasm_mips_form_id form)
{
#if USE_EXTRA_OPCODES && USE_MIPS_MXU
    return mxu_form(form)!=NULL ? CDISASM_MIPS_DECODE_FLAG_MXU : UINT64_C(0);
#else
    (void)form;
    return 0;
#endif
}

size_t cdisasm_mips_mxu_effects(const cdisasm_mips_instruction *instruction,cdisasm_mips_register_effect *effects,size_t capacity)
{
#if USE_EXTRA_OPCODES && USE_MIPS_MXU
    const mips_mxu_form *form=instruction!=NULL ? mxu_form(instruction->form_id) : NULL;
    unsigned access;
    if(form==NULL)return 0;
    access=form->control_access;
    /* D32ADD only replaces the carry field of a nonzero destination. Its
     * whole-register read-write recipe preserves the other carry and the
     * rounding/enable fields; neither carry changes for two XR0 results. */
    if(form->name==CDISASM_MIPS_NAME_D32ADD &&
       ((instruction->raw_instruction>>6)&15u)==0u && ((instruction->raw_instruction>>18)&15u)==0u)access=0u;
    if(!access)return 0;
    if(effects!=NULL && capacity>0u) {
        memset(effects,0,sizeof(*effects));
        effects->reg=CDISASM_MIPS_REG_MXU_CR;
        effects->access=(cdisasm_operand_access)access;
        effects->size=4u;
    }
    return 1;
#else
    (void)instruction;(void)effects;(void)capacity;
    return 0;
#endif
}

cdisasm_status cdisasm_mips_decode_mxu(uint32_t raw,uint64_t address,cdisasm_mips_mode mode,
    cdisasm_mips_revision revision,const cdisasm_mips_decode_flags *features,cdisasm_mips_instruction *instruction)
{
#if USE_EXTRA_OPCODES && USE_MIPS_MXU
    size_t index;
    int invalid=0;
    if(instruction==NULL)return CDISASM_STATUS_INTERNAL_ERROR;
    if(mode!=CDISASM_MIPS_MODE_32 || (revision!=CDISASM_MIPS_REVISION_32R1 && revision!=CDISASM_MIPS_REVISION_32R2 &&
       revision!=CDISASM_MIPS_REVISION_32R3 && revision!=CDISASM_MIPS_REVISION_32R5) ||
       features==NULL || (features->bitmap[0]&CDISASM_MIPS_DECODE_FLAG_MXU)==0u)return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    for(index=0;index<sizeof(mips_mxu_forms)/sizeof(mips_mxu_forms[0]);++index) {
        const mips_mxu_form *form=&mips_mxu_forms[index];
        cdisasm_mips_instruction result;
        if((raw&form->mask)!=form->value)continue;
        memset(&result,0,sizeof(result));
        result.address=address;result.raw_instruction=raw;result.opcode_size=4u;
        result.mode=(uint8_t)mode;result.revision=(uint8_t)revision;
        result.name_id=form->name;result.form_id=form->form;
        if(!mxu_lower(form,raw,&result)){invalid=1;continue;}
        *instruction=result;
        return CDISASM_STATUS_OK;
    }
    if(invalid)return CDISASM_STATUS_INVALID_INSTRUCTION;
#else
    (void)raw;(void)address;(void)mode;(void)revision;(void)features;(void)instruction;
#endif
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}
