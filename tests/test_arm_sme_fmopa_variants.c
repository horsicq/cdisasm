#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>
typedef struct D{uint32_t w;uint16_t form;uint8_t dst,src,tile;}D;
static const D ds[]={{0x81a32040,3789,4,2,0},{0x80a56881,3791,4,1,1},{0x80a7b0c8,3794,2,1,0},{0x8189f909,3795,2,2,1},{0x80cb4547,3811,8,8,7}};
static int f;
#define E(c)do{if(!(c)){if(f<20)fprintf(stderr,"%d: %s\n",__LINE__,#c);f++;}}while(0)
static uint32_t dec(uint32_t w,cdisasm_arm_cpu_id cpu,cdisasm_arm_instruction*i){uint8_t b[4]={(uint8_t)w,(uint8_t)(w>>8),(uint8_t)(w>>16),(uint8_t)(w>>24)};return cdisasm_arm_decode(cpu,3,b,4,0,0,i);}
int main(void){unsigned n;for(n=0;n<sizeof(ds)/sizeof(ds[0]);n++){cdisasm_arm_instruction i;
#if USE_EXTRA_OPCODES
 E(dec(ds[n].w,CDISASM_ARM_CPU_ANY,&i)==4);E(i.name_id==CDISASM_ARM_NAME_FMOPA);E(i.form_id==ds[n].form);E(i.instruction_flags==UINT32_C(0x05c02000));E(i.operand_count==4);E(i.operand[0].type==CDISASM_ARM_OPERAND_TILE);E(i.operand[0].extend_type==ds[n].dst);E(i.operand[1].type==CDISASM_ARM_OPERAND_PREDICATE_PAIR);E(i.operand[1].extend_type==ds[n].dst);E(i.operand[2].extend_type==ds[n].src);E(i.operand[3].extend_type==ds[n].src);E(dec(ds[n].w,CDISASM_ARM_CPU_CORTEX_A53,&i)==0);E(i.last_error_id==CDISASM_STATUS_INVALID_INSTRUCTION);
#else
 E(dec(ds[n].w,CDISASM_ARM_CPU_ANY,&i)==0);E(i.last_error_id==CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
{cdisasm_arm_instruction i;char t[96];E(dec(ds[0].w,CDISASM_ARM_CPU_ANY,&i)==4);E(cdisasm_arm_format(&i,0,t,sizeof(t))!=0);E(strcmp(t,"fmopa za0.s, p0/m, p1/m, z2.h, z3.h")==0);E(dec(ds[4].w,CDISASM_ARM_CPU_ANY,&i)==4);E(cdisasm_arm_format(&i,0,t,sizeof(t))!=0);E(strcmp(t,"fmopa za7.d, p1/m, p2/m, z10.d, z11.d")==0);i.form_id=3789;E(cdisasm_arm_format(&i,0,t,sizeof(t))==0);}
#endif
if(f)return fprintf(stderr,"%d FMOPA failures\n",f),1;puts("ARM SME FMOPA variant tests passed (5 exact leaves)");return 0;}
