#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#include <stdio.h>
#include <string.h>
static int failures;
#define E(c) do{if(!(c)){if(failures<16)fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#c);++failures;}}while(0)
static uint32_t dec(uint32_t w,cdisasm_arm_instruction*i){uint8_t b[4]={(uint8_t)w,(uint8_t)(w>>8),(uint8_t)(w>>16),(uint8_t)(w>>24)};memset(i,0xa5,sizeof(*i));return cdisasm_arm_decode(CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,b,4,0,CDISASM_ARM_DECODE_OPTION_NONE,i);}
int main(void){static const uint32_t base[5]={0x0f008000,0x0f00c000,0x0f00d000,0x2f00d000,0x2f00f000};
#if USE_EXTRA_OPCODES
static const uint16_t form[5]={6247,6250,6251,6273,6275};static const cdisasm_arm_name_id name[5]={CDISASM_ARM_NAME_MUL,CDISASM_ARM_NAME_SQDMULH,CDISASM_ARM_NAME_SQRDMULH,CDISASM_ARM_NAME_SQRDMLAH,CDISASM_ARM_NAME_SQRDMLSH};
#endif
unsigned o,q,s,l,rd,rn;
for(o=0;o<5;o++)for(q=0;q<2;q++)for(s=1;s<=2;s++)for(l=0;l<(s==1?8u:4u);l++)for(rd=0;rd<32;rd+=31)for(rn=0;rn<32;rn+=31){unsigned rm=s==1?15u:31u;uint32_t w=base[o]|(q<<30)|(s<<22)|(rn<<5)|rd;if(s==1)w|=(rm<<16)|((l>>2)<<11)|(((l>>1)&1)<<21)|((l&1)<<20);else w|=(rm<<16)|((l>>1)<<11)|((l&1)<<21);cdisasm_arm_instruction i;
#if USE_EXTRA_OPCODES
E(dec(w,&i)==4);E(i.form_id==form[o]&&i.name_id==name[o]);E(i.instruction_flags==CDISASM_ARM_INSTRUCTION_FLAG_SIMD);E(i.operand_count==3);E(i.operand[0].reg==CDISASM_ARM_REG_V0+rd&&i.operand[0].access==(o>=3?CDISASM_OPERAND_ACCESS_READ_WRITE:CDISASM_OPERAND_ACCESS_WRITE));E(i.operand[1].reg==CDISASM_ARM_REG_V0+rn&&i.operand[1].access==CDISASM_OPERAND_ACCESS_READ);E(i.operand[2].reg==CDISASM_ARM_REG_V0+rm&&i.operand[2].imm==l&&i.operand[2].flags==CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
#else
E(dec(w,&i)==0);
#endif
}return failures?1:0;}
