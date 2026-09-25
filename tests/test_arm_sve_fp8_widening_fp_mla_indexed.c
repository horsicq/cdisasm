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
int main(void){static const uint32_t words[6]={UINT32_C(0x642a5c20),UINT32_C(0x64ad5c83),UINT32_C(0x642acc20),UINT32_C(0x646dcc83),UINT32_C(0x64aacce6),UINT32_C(0x64edcd49)};
#if USE_EXTRA_OPCODES
static const uint16_t forms[6]={3022,3023,3042,3043,3044,3045};static const cdisasm_arm_name_id names[6]={CDISASM_ARM_NAME_FMLALB,CDISASM_ARM_NAME_FMLALT,CDISASM_ARM_NAME_FMLALLBB,CDISASM_ARM_NAME_FMLALLBT,CDISASM_ARM_NAME_FMLALLTB,CDISASM_ARM_NAME_FMLALLTT};
#if USE_DISASM_FORMAT
static const char*texts[6]={"fmlalb z0.h, z1.b, z2.b[7]","fmlalt z3.h, z4.b, z5.b[7]","fmlallbb z0.s, z1.b, z2.b[7]","fmlallbt z3.s, z4.b, z5.b[7]","fmlalltb z6.s, z7.b, z2.b[7]","fmlalltt z9.s, z10.b, z5.b[7]"};
#endif
#endif
unsigned x;for(x=0;x<6;x++){cdisasm_arm_instruction i;
#if USE_EXTRA_OPCODES
EXPECT(decode(words[x],CDISASM_ARM_CPU_ANY,&i)==4);EXPECT(i.form_id==forms[x]&&i.name_id==names[x]);EXPECT(i.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));EXPECT(i.operand_count==3);EXPECT(i.operand[0].extend_type==(x<2?2:4)&&i.operand[0].access==CDISASM_OPERAND_ACCESS_READ_WRITE);EXPECT(i.operand[1].extend_type==1&&i.operand[1].access==CDISASM_OPERAND_ACCESS_READ);EXPECT(i.operand[2].extend_type==1&&i.operand[2].imm==7&&i.operand[2].flags==CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
#if USE_DISASM_FORMAT
{char text[96];size_t n=cdisasm_arm_format(&i,CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,text,sizeof(text));if(strcmp(text,texts[x])!=0)fprintf(stderr,"expected '%s', got '%s'\n",texts[x],text);EXPECT(n==strlen(texts[x]));EXPECT(strcmp(text,texts[x])==0);}
#endif
#else
EXPECT(decode(words[x],CDISASM_ARM_CPU_ANY,&i)==0);
#endif
}
#if USE_EXTRA_OPCODES
{cdisasm_arm_instruction i;EXPECT(decode(words[0],CDISASM_ARM_CPU_CORTEX_A53,&i)==0);}
#endif
return failures?1:0;}
