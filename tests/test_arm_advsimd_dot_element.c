#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#include <stdio.h>
#include <string.h>
static int f;
#define E(c)do{if(!(c)){if(f<16)fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#c);++f;}}while(0)
static uint32_t d(uint32_t w,cdisasm_arm_cpu_id c,cdisasm_arm_instruction*i){uint8_t b[4]={(uint8_t)w,(uint8_t)(w>>8),(uint8_t)(w>>16),(uint8_t)(w>>24)};memset(i,0xa5,sizeof(*i));return cdisasm_arm_decode(c,CDISASM_ARM_MODE_A64,b,4,0,CDISASM_ARM_DECODE_OPTION_NONE,i);}
int main(void){static const uint32_t b[4]={0x0f00e000,0x2f00e000,0x0f00f000,0x0f80f000};
#if USE_EXTRA_OPCODES
static const uint16_t forms[4]={6252,6274,6257,6266};static const cdisasm_arm_name_id names[4]={CDISASM_ARM_NAME_SDOT,CDISASM_ARM_NAME_UDOT,CDISASM_ARM_NAME_SUDOT,CDISASM_ARM_NAME_USDOT};
#endif
unsigned o,q,l,rm,rd;for(o=0;o<4;o++)for(q=0;q<2;q++)for(l=0;l<4;l++)for(rm=0;rm<32;rm+=31)for(rd=0;rd<32;rd+=31){uint32_t w=b[o]|(q<<30)|((l&1)<<21)|((rm>>4)<<20)|((rm&15)<<16)|((l>>1)<<11)|(17u<<5)|rd;cdisasm_arm_instruction i;
#if USE_EXTRA_OPCODES
E(d(w,CDISASM_ARM_CPU_ANY,&i)==4);E(i.form_id==forms[o]&&i.name_id==names[o]);E(i.instruction_flags==CDISASM_ARM_INSTRUCTION_FLAG_SIMD&&i.operand_count==3);E(i.operand[0].reg==CDISASM_ARM_REG_V0+rd&&i.operand[0].access==CDISASM_OPERAND_ACCESS_READ_WRITE);E(i.operand[1].reg==CDISASM_ARM_REG_V17&&i.operand[1].access==CDISASM_OPERAND_ACCESS_READ);E(i.operand[2].reg==CDISASM_ARM_REG_V0+rm&&i.operand[2].imm==l&&i.operand[2].flags==CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
#else
E(d(w,CDISASM_ARM_CPU_ANY,&i)==0);
#endif
}
#if USE_EXTRA_OPCODES
{cdisasm_arm_instruction i;E(d(UINT32_C(0x4fa2e820),CDISASM_ARM_CPU_CORTEX_A53,&i)==0);}
#endif
return f?1:0;}
