/* Original microMIPS64 lowering from pinned manufacturer/GNU numeric facts. */
#include "mips_decoder.h"
#include <string.h>

#if USE_EXTRA_OPCODES
typedef struct micro64_memory_form {
    uint32_t mask,value;
    uint16_t name,form;
    uint8_t bits,store,partial,atomic,generation,pc_shift,memory_size;
} micro64_memory_form;
static const micro64_memory_form forms[]={
#include "generated/mips_micro64_memory_forms.inc"
};
#endif

cdisasm_status cdisasm_mips_micro64_memory(uint32_t raw,uint64_t address,cdisasm_mips_mode mode,
    cdisasm_mips_revision revision,const cdisasm_mips_decode_flags *features,cdisasm_mips_instruction *instruction)
{
#if USE_EXTRA_OPCODES
    size_t n;int matched=0,r6=revision==37u || revision==69u;
    (void)features;
    for(n=0;n<sizeof(forms)/sizeof(forms[0]);++n) {
        const micro64_memory_form *f=&forms[n];
        unsigned rt=(raw>>21)&31u,base=(raw>>16)&31u;
        uint32_t sign=UINT32_C(1)<<(f->bits-1u),offset=raw&((sign<<1)-1u);
        int64_t displacement=(int64_t)(offset^sign)-(int64_t)sign;
        cdisasm_mips_operand *reg,*memory;
        if((raw&f->mask)!=f->value)continue;
        matched=1;
        if(mode!=CDISASM_MIPS_MODE_64 || !((revision>=3u && revision<=5u) || revision>=64u))
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        if((f->generation==1u && r6) || (f->generation==2u && !r6))continue;
        memset(instruction,0,sizeof(*instruction));
        instruction->address=address;instruction->raw_instruction=raw;instruction->opcode_size=4;
        instruction->mode=(uint8_t)mode;instruction->revision=(uint8_t)revision;
        instruction->name_id=f->name;instruction->form_id=f->form;instruction->operand_count=2;
        if(f->atomic)instruction->instruction_flags=CDISASM_MIPS_INSTRUCTION_FLAG_ATOMIC;
        reg=&instruction->operand[0];reg->type=CDISASM_OPERAND_REGISTER;
        reg->reg=(uint16_t)(CDISASM_MIPS_REG_GPR0+rt);reg->size=8;
        reg->access=f->partial || (f->atomic && f->store) ? CDISASM_OPERAND_ACCESS_READ_WRITE :
            f->store ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE;
        memory=&instruction->operand[1];memory->type=CDISASM_OPERAND_MEMORY;memory->size=f->memory_size;
        memory->base_reg=(uint16_t)(CDISASM_MIPS_REG_GPR0+base);memory->imm=(uint64_t)displacement;
        memory->access=f->store ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ;
        memory->flags=CDISASM_MIPS_OPERAND_FLAG_SIGNED|CDISASM_MIPS_OPERAND_FLAG_HAS_DISPLACEMENT;
        if(f->pc_shift) {
            displacement*=INT64_C(1)<<f->pc_shift;
            memory->base_reg=CDISASM_MIPS_REG_NONE;memory->imm=(uint64_t)displacement;
            memory->address=(f->pc_shift==3u ? address&~UINT64_C(7) : address)+(uint64_t)displacement;
            memory->flags|=CDISASM_MIPS_OPERAND_FLAG_PC_RELATIVE|CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS;
        } else if(!base) {
            memory->address=(uint64_t)displacement;
            memory->flags|=CDISASM_MIPS_OPERAND_FLAG_ABSOLUTE|CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS;
        }
        return CDISASM_STATUS_OK;
    }
    return matched ? CDISASM_STATUS_INVALID_INSTRUCTION : CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    (void)raw;(void)address;(void)mode;(void)revision;(void)features;(void)instruction;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
}
