/* Copyright (c) 2026 hors<horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 * Authored lowering from primary numeric operand/resource facts.
 */
#include "mips_decoder.h"
#include <string.h>

typedef struct octeon_form {
    uint32_t mask, value;
    uint16_t name, form;
    uint8_t generation, kind, memory_size, source, lane;
} octeon_form;
/* Allocation ownership survives disabled builds, so selected processors do
 * not reinterpret their slots through unrelated or older instruction forms. */
static const octeon_form octeon_forms[] = {
#include "generated/mips_octeon_forms.inc"
};

static const octeon_form *octeon_find(uint32_t raw, unsigned generation)
{
    size_t n;
    if (generation != 2u && generation != 3u) return NULL;
    for (n=0;n<sizeof(octeon_forms)/sizeof(octeon_forms[0]);++n)
        if (octeon_forms[n].generation<=generation && (raw&octeon_forms[n].mask)==octeon_forms[n].value)
            return &octeon_forms[n];
    return NULL;
}
int cdisasm_mips_octeon_owns(uint32_t raw, unsigned generation)
{
    return octeon_find(raw,generation)!=NULL;
}
unsigned cdisasm_mips_octeon_form_generation(cdisasm_mips_form_id form)
{
    return form>=38000u && form<=38028u ? 2u : form>=38029u && form<=38036u ? 3u : 0u;
}

#if USE_EXTRA_OPCODES && USE_MIPS_CNMIPS2
static void octeon_reg(cdisasm_mips_instruction *i,unsigned reg,unsigned access)
{
    cdisasm_mips_operand *o=&i->operand[i->operand_count++];
    o->type=CDISASM_OPERAND_REGISTER;o->reg=(cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0+reg);
    o->size=8u;o->access=(uint8_t)access;
}
static void octeon_memory(cdisasm_mips_instruction *i,unsigned base,unsigned index,unsigned size,unsigned access)
{
    cdisasm_mips_operand *o=&i->operand[i->operand_count++];
    o->type=CDISASM_OPERAND_MEMORY;o->base_reg=(cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0+base);
    if(index<32u)o->index_reg=(cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0+index);
    o->size=(uint8_t)size;o->access=(uint8_t)access;
    if(!size)o->flags=CDISASM_OPERAND_FLAG_ADDRESS_ONLY;
}
#endif

cdisasm_status cdisasm_mips_octeon_decode(uint32_t raw,cdisasm_mips_mode mode,
    cdisasm_mips_revision revision,unsigned generation,cdisasm_mips_instruction *instruction)
{
    const octeon_form *f=octeon_find(raw,generation);
    if(instruction==NULL || (generation!=2u && generation!=3u))return CDISASM_STATUS_INVALID_ARGUMENT;
    if(f==NULL)return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    if(mode!=CDISASM_MIPS_MODE_64 ||
        (generation==3u ? revision!=CDISASM_MIPS_REVISION_64R5 :
          (revision!=CDISASM_MIPS_REVISION_64R2 && revision!=CDISASM_MIPS_REVISION_64R5)))
        return CDISASM_STATUS_INVALID_INSTRUCTION;
#if USE_EXTRA_OPCODES && USE_MIPS_CNMIPS2
    {
        cdisasm_mips_instruction candidate;
        const unsigned rs=(raw>>21)&31u,rt=(raw>>16)&31u,rd=(raw>>11)&31u;
        if(f->generation==3u && !USE_MIPS_CNMIPS3)return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        memset(&candidate,0,sizeof(candidate));candidate.address=instruction->address;
        candidate.raw_instruction=raw;candidate.opcode_size=4u;candidate.mode=(uint8_t)mode;candidate.revision=(uint8_t)revision;
        candidate.name_id=f->name;candidate.form_id=f->form;
        if(f->kind==0u) {
            octeon_reg(&candidate,rs,CDISASM_OPERAND_ACCESS_READ);
            octeon_reg(&candidate,rt,CDISASM_OPERAND_ACCESS_READ);
            candidate.instruction_flags=CDISASM_MIPS_INSTRUCTION_FLAG_READS_HI|CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_HI|
                CDISASM_MIPS_INSTRUCTION_FLAG_READS_LO|CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_LO;
        } else if(f->kind==1u) {
            octeon_reg(&candidate,rd,CDISASM_OPERAND_ACCESS_WRITE);
            octeon_memory(&candidate,rs,rt,f->memory_size,CDISASM_OPERAND_ACCESS_READ);
        } else if(f->kind==2u) {
            octeon_reg(&candidate,rd,CDISASM_OPERAND_ACCESS_WRITE);
            octeon_memory(&candidate,rs,32u,f->memory_size,CDISASM_OPERAND_ACCESS_READ_WRITE);
            if(f->source)octeon_reg(&candidate,rt,CDISASM_OPERAND_ACCESS_READ);
            candidate.instruction_flags=CDISASM_MIPS_INSTRUCTION_FLAG_ATOMIC;
        } else if(f->kind==3u) {
            /* Syntax identifies a base, while the actual cache block starts at
             * an aligned address. Do not invent a precise memory interval. */
            octeon_memory(&candidate,rs,32u,0u,CDISASM_OPERAND_ACCESS_WRITE);
        } else {
            if(f->kind>=6u)octeon_reg(&candidate,rd,CDISASM_OPERAND_ACCESS_WRITE);
            octeon_reg(&candidate,rs,CDISASM_OPERAND_ACCESS_READ);
            octeon_reg(&candidate,rt,CDISASM_OPERAND_ACCESS_READ);
        }
        *instruction=candidate;
        return CDISASM_STATUS_OK;
    }
#else
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
}

cdisasm_mips_effect_limitations cdisasm_mips_octeon_effect_limitations(cdisasm_mips_form_id form)
{
    return form==38027u || form==38028u ? CDISASM_MIPS_EFFECT_LIMITATION_IMPLICIT_EFFECTS : 0;
}

size_t cdisasm_mips_octeon_effects(const cdisasm_mips_instruction *instruction,
    cdisasm_mips_register_effect *output,size_t capacity)
{
    cdisasm_mips_register_effect effects[32]={{0}};
    size_t count,n;
    unsigned form,lane;
    static const cdisasm_mips_reg_id mpl[6]={CDISASM_MIPS_REG_OCTEON_MPL0,CDISASM_MIPS_REG_OCTEON_MPL1,CDISASM_MIPS_REG_OCTEON_MPL2,
        CDISASM_MIPS_REG_OCTEON_MPL3,CDISASM_MIPS_REG_OCTEON_MPL4,CDISASM_MIPS_REG_OCTEON_MPL5};
    static const cdisasm_mips_reg_id p[6]={CDISASM_MIPS_REG_OCTEON_P0,CDISASM_MIPS_REG_OCTEON_P1,CDISASM_MIPS_REG_OCTEON_P2,
        CDISASM_MIPS_REG_OCTEON_P3,CDISASM_MIPS_REG_OCTEON_P4,CDISASM_MIPS_REG_OCTEON_P5};
    if(instruction==NULL || (capacity && output==NULL) || !cdisasm_mips_octeon_form_generation(instruction->form_id))return 0;
    count=cdisasm_mips_v3_effects_numeric(instruction,effects,32u);
    form=instruction->form_id;
#define WRITE_RESOURCE(reg_) do { effects[count].reg=(reg_);effects[count].access=CDISASM_OPERAND_ACCESS_WRITE;effects[count].size=8u;++count; } while(0)
    if(form>=38029u && form<=38031u) {
        lane=form-38029u;WRITE_RESOURCE(mpl[lane]);WRITE_RESOURCE(mpl[lane+3u]);
        if(lane==0u)WRITE_RESOURCE(mpl[1]);
        for(n=0;n<6u;++n)WRITE_RESOURCE(p[n]);
    } else if(form>=38032u && form<=38034u) {
        lane=form-38032u;WRITE_RESOURCE(p[lane]);WRITE_RESOURCE(p[lane+3u]);
        if(lane==0u)WRITE_RESOURCE(p[1]);
    } else if(form==38035u) {
        for(n=0;n<6u;++n){
            effects[count].reg=mpl[n];effects[count].access=CDISASM_OPERAND_ACCESS_READ;effects[count].size=8u;++count;
            effects[count].reg=p[n];effects[count].access=CDISASM_OPERAND_ACCESS_READ_WRITE;effects[count].size=8u;++count;
        }
    } else if(form==38036u) {
        effects[count].reg=mpl[0];effects[count].access=CDISASM_OPERAND_ACCESS_READ_WRITE;effects[count].size=8u;++count;
        WRITE_RESOURCE(mpl[1]);
        for(n=0;n<6u;++n)WRITE_RESOURCE(p[n]);
    }
#undef WRITE_RESOURCE
    if(capacity>count)capacity=count;
    if(capacity)memcpy(output,effects,capacity*sizeof(*output));
    return count;
}
