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
int main(void){static const uint32_t words[8]={0x64aa4820,0x64ea4820,0x64aa6820,0x64ea6820,0x64aa4c20,0x64ea4c20,0x64aa6c20,0x64ea6c20};
#if USE_EXTRA_OPCODES
static const uint16_t forms[8]={3014,3015,3016,3017,3018,3019,3020,3021};static const cdisasm_arm_name_id names[8]={CDISASM_ARM_NAME_FMLALB,CDISASM_ARM_NAME_BFMLALB,CDISASM_ARM_NAME_FMLSLB,CDISASM_ARM_NAME_BFMLSLB,CDISASM_ARM_NAME_FMLALT,CDISASM_ARM_NAME_BFMLALT,CDISASM_ARM_NAME_FMLSLT,CDISASM_ARM_NAME_BFMLSLT};
#if USE_DISASM_FORMAT
static const char*texts[8]={"fmlalb z0.s, z1.h, z2.h[3]","bfmlalb z0.s, z1.h, z2.h[3]","fmlslb z0.s, z1.h, z2.h[3]","bfmlslb z0.s, z1.h, z2.h[3]","fmlalt z0.s, z1.h, z2.h[3]","bfmlalt z0.s, z1.h, z2.h[3]","fmlslt z0.s, z1.h, z2.h[3]","bfmlslt z0.s, z1.h, z2.h[3]"};
#endif
#endif
unsigned x;for(x=0;x<8;x++){cdisasm_arm_instruction i;
#if USE_EXTRA_OPCODES
EXPECT(decode(words[x],CDISASM_ARM_CPU_ANY,&i)==4);EXPECT(i.form_id==forms[x]&&i.name_id==names[x]);EXPECT(i.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));EXPECT(i.operand_count==3);EXPECT(i.operand[0].reg==CDISASM_ARM_REG_Z0&&i.operand[0].extend_type==4&&i.operand[0].access==CDISASM_OPERAND_ACCESS_READ_WRITE);EXPECT(i.operand[1].reg==CDISASM_ARM_REG_Z1&&i.operand[1].extend_type==2&&i.operand[1].access==CDISASM_OPERAND_ACCESS_READ);EXPECT(i.operand[2].reg==CDISASM_ARM_REG_Z2&&i.operand[2].extend_type==2&&i.operand[2].imm==3&&i.operand[2].flags==CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
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
