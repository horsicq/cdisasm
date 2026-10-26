/* Copyright (c) 2026 hors<horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 * microMIPS64 Release6 numeric forms reviewed against MD00594r6.05.
 * No manufacturer implementation code or arithmetic simulator is included. */
#include "mips_decoder.h"
#include <string.h>

#if USE_EXTRA_OPCODES
typedef struct micro64_r6_form {
    uint32_t mask, value;
    uint16_t name, form;
    uint8_t kind;
} micro64_r6_form;
static const micro64_r6_form micro64_r6_forms[] = {
#include "generated/mips_micro64_r6_forms.inc"
};
static void micro64_r6_reg(cdisasm_mips_instruction *i, unsigned reg, unsigned access)
{
    cdisasm_mips_operand *o=&i->operand[i->operand_count++];
    o->type=CDISASM_OPERAND_REGISTER;
    o->reg=(cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0+reg);
    o->size=8u;
    o->access=(uint8_t)access;
}
static void micro64_r6_imm(cdisasm_mips_instruction *i, uint64_t value, unsigned size, unsigned flags)
{
    cdisasm_mips_operand *o=&i->operand[i->operand_count++];
    o->type=CDISASM_OPERAND_IMMEDIATE;
    o->imm=value;
    o->size=(uint8_t)size;
    o->access=CDISASM_OPERAND_ACCESS_READ;
    o->flags=(uint8_t)flags;
}
#endif

cdisasm_status cdisasm_mips_micro64_r6(uint32_t raw, uint64_t address,
    cdisasm_mips_mode mode, cdisasm_mips_revision revision,
    const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *instruction)
{
#if USE_EXTRA_OPCODES
    size_t n;
    (void)features;
    /* R6-only allocations can overlap removed pre-R6 instructions. Let the
     * legacy decoder retain ownership outside the precise R6 profile. */
    if (mode!=CDISASM_MIPS_MODE_64 || revision!=CDISASM_MIPS_REVISION_64R6)
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    for(n=0u;n<sizeof(micro64_r6_forms)/sizeof(micro64_r6_forms[0]);++n) {
        const micro64_r6_form *f=&micro64_r6_forms[n];
        unsigned rt=(raw>>21)&31u, rs=(raw>>16)&31u, rd=(raw>>11)&31u;
        cdisasm_mips_instruction candidate;
        if((raw&f->mask)!=f->value) continue;
        if(f->kind==3u && !rs) return CDISASM_STATUS_INVALID_INSTRUCTION;
        memset(&candidate,0,sizeof(candidate));
        candidate.raw_instruction=raw;
        candidate.address=address;
        candidate.opcode_size=4u;
        candidate.mode=(uint8_t)mode;
        candidate.revision=(uint8_t)revision;
        candidate.name_id=f->name;
        candidate.form_id=f->form;
        if(f->kind<=2u) {
            micro64_r6_reg(&candidate,rd,CDISASM_OPERAND_ACCESS_WRITE);
            micro64_r6_reg(&candidate,rs,CDISASM_OPERAND_ACCESS_READ);
            micro64_r6_reg(&candidate,rt,CDISASM_OPERAND_ACCESS_READ);
            if(f->kind==1u) micro64_r6_imm(&candidate,(raw>>8)&7u,1u,0u);
            else if(f->kind==2u) micro64_r6_imm(&candidate,((raw>>9)&3u)+1u,1u,0u);
        } else if(f->kind==3u) {
            int64_t immediate=(int64_t)((raw&65535u)^32768u)-32768;
            micro64_r6_reg(&candidate,rt,CDISASM_OPERAND_ACCESS_WRITE);
            micro64_r6_reg(&candidate,rs,CDISASM_OPERAND_ACCESS_READ);
            micro64_r6_imm(&candidate,(uint64_t)immediate,2u,CDISASM_MIPS_OPERAND_FLAG_SIGNED);
        } else if(f->kind==4u) {
            /* DAHI/DATI have one physical read-modify-write GPR. The two
             * repeated registers in one Format line are not two resources. */
            int64_t immediate=(int64_t)((raw&65535u)^32768u)-32768;
            micro64_r6_reg(&candidate,rs,CDISASM_OPERAND_ACCESS_READ_WRITE);
            micro64_r6_imm(&candidate,(uint64_t)immediate,2u,CDISASM_MIPS_OPERAND_FLAG_SIGNED);
        } else if(f->kind==5u) {
            micro64_r6_reg(&candidate,rs,CDISASM_OPERAND_ACCESS_WRITE);
            micro64_r6_reg(&candidate,rt,CDISASM_OPERAND_ACCESS_READ);
        } else return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        candidate.last_error_id=CDISASM_STATUS_OK;
        *instruction=candidate;
        return CDISASM_STATUS_OK;
    }
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    (void)raw;(void)address;(void)mode;(void)revision;(void)features;(void)instruction;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
}
