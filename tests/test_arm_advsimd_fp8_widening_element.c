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
int main(void){static const uint32_t words[6]={0x0fff0a20,0x2f3f8a21,0x2f7f8a22,0x4fff0a23,0x6f3f8a24,0x6f7f8a25};
#if USE_EXTRA_OPCODES
static const uint16_t forms[6]={6281,6282,6283,6284,6285,6286};static const cdisasm_arm_name_id names[6]={CDISASM_ARM_NAME_FMLALB,CDISASM_ARM_NAME_FMLALLBB,CDISASM_ARM_NAME_FMLALLBT,CDISASM_ARM_NAME_FMLALT,CDISASM_ARM_NAME_FMLALLTB,CDISASM_ARM_NAME_FMLALLTT};
#if USE_DISASM_FORMAT
static const char*texts[6]={"fmlalb v0.8h, v17.16b, v7.b[15]","fmlallbb v1.4s, v17.16b, v7.b[15]","fmlallbt v2.4s, v17.16b, v7.b[15]","fmlalt v3.8h, v17.16b, v7.b[15]","fmlalltb v4.4s, v17.16b, v7.b[15]","fmlalltt v5.4s, v17.16b, v7.b[15]"};
#endif
#endif
unsigned x;for(x=0;x<6;x++){cdisasm_arm_instruction i;
#if USE_EXTRA_OPCODES
EXPECT(decode(words[x],CDISASM_ARM_CPU_ANY,&i)==4);EXPECT(i.form_id==forms[x]&&i.name_id==names[x]);EXPECT(i.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SIMD|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));EXPECT(i.operand_count==3);EXPECT(i.operand[0].size==16&&CDISASM_ARM_VECTOR_ELEMENT_SIZE(&i.operand[0])==((x==0||x==3)?2:4)&&i.operand[0].access==CDISASM_OPERAND_ACCESS_READ_WRITE);EXPECT(i.operand[1].reg==CDISASM_ARM_REG_V17&&CDISASM_ARM_VECTOR_ELEMENT_SIZE(&i.operand[1])==1);EXPECT(i.operand[2].reg==CDISASM_ARM_REG_V7&&i.operand[2].imm==15&&i.operand[2].flags==CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
#if USE_DISASM_FORMAT
{char text[96];EXPECT(cdisasm_arm_format(&i,CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,text,sizeof(text))==strlen(texts[x]));EXPECT(strcmp(text,texts[x])==0);}
#endif
#else
EXPECT(decode(words[x],CDISASM_ARM_CPU_ANY,&i)==0);
#endif
}
#if USE_EXTRA_OPCODES
{cdisasm_arm_instruction i;EXPECT(decode(words[0],CDISASM_ARM_CPU_CORTEX_A53,&i)==0);}
#endif
return failures?1:0;}
