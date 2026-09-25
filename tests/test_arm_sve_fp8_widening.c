#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>
static int failures;
#define EXPECT(c) do{if(!(c)){fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#c);++failures;}}while(0)
static uint32_t decode(uint32_t w,cdisasm_arm_cpu_id cpu,cdisasm_arm_instruction*i){uint8_t b[4]={(uint8_t)w,(uint8_t)(w>>8),(uint8_t)(w>>16),(uint8_t)(w>>24)};memset(i,0xa5,sizeof(*i));return cdisasm_arm_decode(cpu,CDISASM_ARM_MODE_A64,b,4,0,CDISASM_ARM_DECODE_OPTION_NONE,i);}
int main(void){static const uint32_t words[14]={0x64228820,0x64259883,0x6428a8e6,0x642bb949,0x64ae89ac,0x64b19a0f,0x6422e020,0x6465e083,0x64a2e020,0x64e2e020,0x6422e420,0x6462e420,0x64a2e420,0x64e2e420};
#if USE_EXTRA_OPCODES
static const uint16_t forms[14]={3036,3037,3038,3039,3040,3041,3046,3047,3048,3049,3050,3051,3052,3053};static const cdisasm_arm_name_id names[14]={CDISASM_ARM_NAME_FMLALLBB,CDISASM_ARM_NAME_FMLALLBT,CDISASM_ARM_NAME_FMLALLTB,CDISASM_ARM_NAME_FMLALLTT,CDISASM_ARM_NAME_FMLALB,CDISASM_ARM_NAME_FMLALT,CDISASM_ARM_NAME_FMMLA,CDISASM_ARM_NAME_FMMLA,CDISASM_ARM_NAME_FMMLA,CDISASM_ARM_NAME_BFMMLA,CDISASM_ARM_NAME_FMMLA,CDISASM_ARM_NAME_BFMMLA,CDISASM_ARM_NAME_FMMLA,CDISASM_ARM_NAME_FMMLA};static const unsigned ds[14]={4,4,4,4,2,2,4,2,2,2,4,4,4,8};static const unsigned ss[14]={1,1,1,1,1,1,1,1,2,2,2,2,4,8};
#if USE_DISASM_FORMAT
static const char*texts[14]={"fmlallbb z0.s, z1.b, z2.b","fmlallbt z3.s, z4.b, z5.b","fmlalltb z6.s, z7.b, z8.b","fmlalltt z9.s, z10.b, z11.b","fmlalb z12.h, z13.b, z14.b","fmlalt z15.h, z16.b, z17.b","fmmla z0.s, z1.b, z2.b","fmmla z3.h, z4.b, z5.b","fmmla z0.h, z1.h, z2.h","bfmmla z0.h, z1.h, z2.h","fmmla z0.s, z1.h, z2.h","bfmmla z0.s, z1.h, z2.h","fmmla z0.s, z1.s, z2.s","fmmla z0.d, z1.d, z2.d"};
#endif
#endif
unsigned x;for(x=0;x<14;x++){cdisasm_arm_instruction i;
#if USE_EXTRA_OPCODES
EXPECT(decode(words[x],CDISASM_ARM_CPU_ANY,&i)==4);EXPECT(i.form_id==forms[x]&&i.name_id==names[x]);EXPECT(i.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));EXPECT(i.operand_count==3);EXPECT(i.operand[0].extend_type==ds[x]&&i.operand[0].access==CDISASM_OPERAND_ACCESS_READ_WRITE);EXPECT(i.operand[1].extend_type==ss[x]&&i.operand[2].extend_type==ss[x]);
#if USE_DISASM_FORMAT
{char text[96];size_t n=cdisasm_arm_format(&i,CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,text,sizeof(text));EXPECT(n==strlen(texts[x]));EXPECT(strcmp(text,texts[x])==0);}
#endif
#else
EXPECT(decode(words[x],CDISASM_ARM_CPU_ANY,&i)==0);
#endif
}
#if USE_EXTRA_OPCODES
{cdisasm_arm_instruction i;EXPECT(decode(words[0],CDISASM_ARM_CPU_CORTEX_A53,&i)==0);}
#endif
return failures?1:0;}
