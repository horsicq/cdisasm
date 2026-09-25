#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#include <stdio.h>
#include <string.h>
static int f;
#define E(c)do{if(!(c)){fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#c);++f;}}while(0)
static uint32_t d(uint32_t w,cdisasm_arm_cpu_id c,cdisasm_arm_instruction*i){uint8_t b[4]={(uint8_t)w,(uint8_t)(w>>8),(uint8_t)(w>>16),(uint8_t)(w>>24)};memset(i,0xa5,sizeof(*i));return cdisasm_arm_decode(c,CDISASM_ARM_MODE_A64,b,4,0,CDISASM_ARM_DECODE_OPTION_NONE,i);}
int main(void){static const uint32_t words[8]={0x4f321820,0x0f2f5083,0x4f1790c5,0x4fbf1928,0x0f8c516a,0x4fde99cd,0x6f329820,0x6fbf9883};
#if USE_EXTRA_OPCODES
static const uint16_t forms[8]={6254,6255,6256,6261,6262,6263,6276,6278};static const cdisasm_arm_name_id names[8]={CDISASM_ARM_NAME_FMLA,CDISASM_ARM_NAME_FMLS,CDISASM_ARM_NAME_FMUL,CDISASM_ARM_NAME_FMLA,CDISASM_ARM_NAME_FMLS,CDISASM_ARM_NAME_FMUL,CDISASM_ARM_NAME_FMULX,CDISASM_ARM_NAME_FMULX};
#endif
unsigned x;for(x=0;x<8;x++){cdisasm_arm_instruction i;
#if USE_EXTRA_OPCODES
E(d(words[x],CDISASM_ARM_CPU_ANY,&i)==4);E(i.form_id==forms[x]&&i.name_id==names[x]);E(i.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SIMD|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));E(i.operand_count==3);E(i.operand[0].access==((x%3==2||x>=6)?CDISASM_OPERAND_ACCESS_WRITE:CDISASM_OPERAND_ACCESS_READ_WRITE));E(i.operand[1].access==CDISASM_OPERAND_ACCESS_READ&&i.operand[2].access==CDISASM_OPERAND_ACCESS_READ);E(i.operand[2].flags==CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
#else
E(d(words[x],CDISASM_ARM_CPU_ANY,&i)==0);
#endif
}
#if USE_EXTRA_OPCODES
{cdisasm_arm_instruction i;E(d(0x0f321820,CDISASM_ARM_CPU_CORTEX_A53,&i)==0);E(d(0x0fde99cd,CDISASM_ARM_CPU_ANY,&i)==0);E(i.last_error_id==CDISASM_STATUS_INVALID_INSTRUCTION);}
#endif
return f?1:0;}
