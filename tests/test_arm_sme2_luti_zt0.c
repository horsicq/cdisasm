#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>

static uint32_t decode_word(uint32_t word, cdisasm_arm_cpu_id cpu,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4] = {(uint8_t)word, (uint8_t)(word >> 8),
        (uint8_t)(word >> 16), (uint8_t)(word >> 24)};
    return cdisasm_arm_decode(cpu, 3, bytes, sizeof(bytes), 0, 0, instruction);
}

int main(void)
{
    cdisasm_arm_instruction instruction;
#if USE_EXTRA_OPCODES
    struct family { uint32_t value; unsigned form, count, luti4, lane_shift, lane_bits; };
    static const struct family families[] = {
        {UINT32_C(0xc08c4000),3920,2,0,15,3}, {UINT32_C(0xc08a4000),3921,2,1,15,2},
        {UINT32_C(0xc08c8000),3922,4,0,16,2}, {UINT32_C(0xc08a8000),3923,4,1,16,1},
        {UINT32_C(0xc0cc0000),3924,1,0,14,4}, {UINT32_C(0xc0ca0000),3925,1,1,14,3}
    };
    unsigned f, size_code, zd, zn, lane;
    for (f = 0; f < sizeof(families) / sizeof(families[0]); ++f) {
        const struct family *x = &families[f];
        unsigned zd_step = x->count;
        for (size_code = 0; size_code < 2; ++size_code) {
            unsigned size = 1u << size_code;
            unsigned lane_count = 1u << x->lane_bits;
            for (zd = 0; zd < 32; zd += zd_step) for (zn = 0; zn < 32; ++zn)
                for (lane = 0; lane < lane_count; ++lane) {
                    uint32_t word = x->value | (size_code << 12) | zd
                        | (zn << 5) | (lane << x->lane_shift);
                    const cdisasm_arm_operand *d, *t, *s;
                    if (decode_word(word, CDISASM_ARM_CPU_ANY, &instruction) != 4
                        || instruction.name_id != (x->luti4 ? CDISASM_ARM_NAME_LUTI4 : CDISASM_ARM_NAME_LUTI2)
                        || instruction.form_id != x->form || instruction.instruction_flags != UINT32_C(0x05400000)
                        || instruction.operand_count != 3) return 1;
                    d=&instruction.operand[0];t=&instruction.operand[1];s=&instruction.operand[2];
                    if ((x->count == 1 ? d->type != CDISASM_ARM_OPERAND_SCALABLE_REGISTER
                                       : d->type != CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST)
                        || d->reg != CDISASM_ARM_REG_Z0 + zd || d->extend_type != size
                        || d->access != CDISASM_OPERAND_ACCESS_WRITE
                        || (x->count != 1 && d->register_list != (UINT16_C(0x0100) | x->count))
                        || t->type != CDISASM_ARM_OPERAND_TILE || t->reg != CDISASM_ARM_REG_ZT0
                        || t->access != CDISASM_OPERAND_ACCESS_READ
                        || s->type != CDISASM_ARM_OPERAND_SCALABLE_REGISTER
                        || s->reg != CDISASM_ARM_REG_Z0 + zn || s->extend_type != size
                        || s->flags != CDISASM_ARM_OPERAND_FLAG_HAS_LANE || s->imm != lane
                        || s->access != CDISASM_OPERAND_ACCESS_READ) return 1;
                }
        }
    }
    if (decode_word(UINT32_C(0xc08c6000), CDISASM_ARM_CPU_ANY, &instruction) != 0
        || instruction.last_error_id != CDISASM_STATUS_INVALID_INSTRUCTION) return 1;
    if (decode_word(UINT32_C(0xc08c4040), CDISASM_ARM_CPU_CORTEX_A53, &instruction) != 0
        || instruction.last_error_id != CDISASM_STATUS_INVALID_INSTRUCTION) return 1;
    {
        struct ext {uint32_t value;unsigned form,count,stride,luti4,lane_shift,lane_bits,size_mode,source_list;};
        static const struct ext xs[]={
          {0xc08b0000,3927,4,1,1,0,0,0,1},{0xc09c4000,3933,2,8,0,15,3,2,0},
          {0xc09a4000,3934,2,8,1,15,2,2,0},{0xc09c8000,3935,4,4,0,16,2,2,0},
          {0xc09a9000,3936,4,4,1,16,1,0,0},{0xc09b0000,3937,4,4,1,0,0,0,1}};
        unsigned x,sc,di,si,li;
        for(x=0;x<6;x++)for(sc=0;sc<(xs[x].size_mode==2?2:1);sc++)
          for(di=0;di<(xs[x].stride==1?8:xs[x].count==2?16:8);di++)
          for(si=0;si<32;si+=xs[x].source_list?2:1)
          for(li=0;li<(xs[x].source_list?1:(1u<<xs[x].lane_bits));li++){
            unsigned low_count=xs[x].count==2?8:4;
            unsigned zd=xs[x].stride==1?di*4:(di>=low_count?16:0)+(di%low_count);
            uint32_t w=xs[x].value|(sc<<12)|zd|(xs[x].source_list?((si/2)<<6):(si<<5))|(li<<xs[x].lane_shift);
            const cdisasm_arm_operand*d,*s;
            if(decode_word(w,CDISASM_ARM_CPU_ANY,&instruction)!=4||instruction.form_id!=xs[x].form||instruction.name_id!=(xs[x].luti4?CDISASM_ARM_NAME_LUTI4:CDISASM_ARM_NAME_LUTI2)||instruction.instruction_flags!=UINT32_C(0x05400000)||instruction.operand_count!=3)return 1;
            d=&instruction.operand[0];s=&instruction.operand[2];
            if(d->type!=CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST||d->reg!=CDISASM_ARM_REG_Z0+zd||d->register_list!=((uint16_t)xs[x].stride<<8|xs[x].count)||d->extend_type!=(1u<<((w>>12)&3))||d->access!=CDISASM_OPERAND_ACCESS_WRITE)return 1;
            if(xs[x].source_list){if(s->type!=CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST||s->reg!=CDISASM_ARM_REG_Z0+si||s->register_list!=UINT16_C(0x0102)||s->extend_type!=1||s->access!=CDISASM_OPERAND_ACCESS_READ)return 1;}
            else if(s->type!=CDISASM_ARM_OPERAND_SCALABLE_REGISTER||s->reg!=CDISASM_ARM_REG_Z0+si||s->flags!=CDISASM_ARM_OPERAND_FLAG_HAS_LANE||s->imm!=li||s->extend_type!=(1u<<((w>>12)&3)))return 1;
          }
        if(decode_word(UINT32_C(0xc09c6000),CDISASM_ARM_CPU_ANY,&instruction)!=0||instruction.last_error_id!=CDISASM_STATUS_INVALID_INSTRUCTION)return 1;
        if(decode_word(UINT32_C(0xc09a8000),CDISASM_ARM_CPU_ANY,&instruction)!=0||instruction.last_error_id!=CDISASM_STATUS_INVALID_INSTRUCTION)return 1;
        if(decode_word(UINT32_C(0xc08b1040),CDISASM_ARM_CPU_ANY,&instruction)!=0||instruction.last_error_id!=CDISASM_STATUS_INVALID_INSTRUCTION)return 1;
        if(decode_word(UINT32_C(0xc09f9040),CDISASM_ARM_CPU_CORTEX_A53,&instruction)!=0||instruction.last_error_id!=CDISASM_STATUS_INVALID_INSTRUCTION)return 1;
    }
#if USE_DISASM_FORMAT
    {
        char text[128];
        if (decode_word(UINT32_C(0xc08dd126), CDISASM_ARM_CPU_ANY, &instruction) != 4
            || !cdisasm_arm_format(&instruction, 0, text, sizeof(text))
            || strcmp(text, "luti2 {z6.h, z7.h}, zt0, z9[3]") != 0) return 1;
        if (decode_word(UINT32_C(0xc08a9040), CDISASM_ARM_CPU_ANY, &instruction) != 4
            || !cdisasm_arm_format(&instruction, 0, text, sizeof(text))
            || strcmp(text, "luti4 {z0.h, z1.h, z2.h, z3.h}, zt0, z2[0]") != 0) return 1;
        instruction.form_id = 3919;
        if (cdisasm_arm_format(&instruction, 0, text, sizeof(text)) != 0) return 1;
        if (decode_word(UINT32_C(0xc09fc140), CDISASM_ARM_CPU_ANY, &instruction) != 4
            || !cdisasm_arm_format(&instruction, 0, text, sizeof(text))
            || strcmp(text, "luti2 {z0.b, z8.b}, zt0, z10[7]") != 0) return 1;
        if (decode_word(UINT32_C(0xc09b0110), CDISASM_ARM_CPU_ANY, &instruction) != 4
            || !cdisasm_arm_format(&instruction, 0, text, sizeof(text))
            || strcmp(text, "luti4 {z16.b, z20.b, z24.b, z28.b}, zt0, {z8, z9}") != 0) return 1;
    }
#endif
#else
    if (decode_word(UINT32_C(0xc08c4040), CDISASM_ARM_CPU_ANY, &instruction) != 0
        || instruction.last_error_id != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) return 1;
#endif
    puts("ARM SME ZT0 LUTI tests passed (12 exact leaves)");
    return 0;
}
