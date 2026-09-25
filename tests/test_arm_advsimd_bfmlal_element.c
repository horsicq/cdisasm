#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>
static int failures;
#define EXPECT(c) do { if(!(c)){fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#c);++failures;} } while(0)
static uint32_t decode(uint32_t w,cdisasm_arm_cpu_id cpu,cdisasm_arm_instruction*i){uint8_t b[4]={(uint8_t)w,(uint8_t)(w>>8),(uint8_t)(w>>16),(uint8_t)(w>>24)};memset(i,0xa5,sizeof(*i));return cdisasm_arm_decode(cpu,CDISASM_ARM_MODE_A64,b,4,0,CDISASM_ARM_DECODE_OPTION_NONE,i);}
int main(void){static const uint32_t words[3]={UINT32_C(0x0ff2f020),UINT32_C(0x4ff2f020),UINT32_C(0x0ffffbdf)};unsigned x;
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static const char*texts[3]={"bfmlalb v0.4s, v1.8h, v2.h[3]","bfmlalt v0.4s, v1.8h, v2.h[3]","bfmlalb v31.4s, v30.8h, v15.h[7]"};
#endif
for(x=0;x<3;x++){cdisasm_arm_instruction i;
#if USE_EXTRA_OPCODES
EXPECT(decode(words[x],CDISASM_ARM_CPU_ANY,&i)==4);EXPECT(i.form_id==6267&&i.name_id==CDISASM_ARM_NAME_BFMLAL);EXPECT(i.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SIMD|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));EXPECT(i.operand_count==3);EXPECT(i.operand[0].size==16&&CDISASM_ARM_VECTOR_ELEMENT_SIZE(&i.operand[0])==4&&i.operand[0].access==CDISASM_OPERAND_ACCESS_READ_WRITE);EXPECT(i.operand[1].size==16&&CDISASM_ARM_VECTOR_ELEMENT_SIZE(&i.operand[1])==2&&i.operand[1].access==CDISASM_OPERAND_ACCESS_READ);EXPECT(i.operand[2].reg<=CDISASM_ARM_REG_V15&&i.operand[2].imm==(x<2?3:7)&&i.operand[2].flags==CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
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
