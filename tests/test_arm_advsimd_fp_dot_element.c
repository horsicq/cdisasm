#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>
static int failures;
#define EXPECT(c) do { if (!(c)) { fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#c); ++failures; } } while (0)
static uint32_t decode(uint32_t word,cdisasm_arm_cpu_id cpu,cdisasm_arm_instruction *instruction){uint8_t bytes[4]={(uint8_t)word,(uint8_t)(word>>8),(uint8_t)(word>>16),(uint8_t)(word>>24)};memset(instruction,0xa5,sizeof(*instruction));return cdisasm_arm_decode(cpu,CDISASM_ARM_MODE_A64,bytes,4,0,CDISASM_ARM_DECODE_OPTION_NONE,instruction);}
int main(void){
    static const uint32_t words[4]={UINT32_C(0x4f220020),UINT32_C(0x0f750083),UINT32_C(0x4f6890e6),UINT32_C(0x4f4bf949)};
#if USE_EXTRA_OPCODES
    static const uint16_t forms[4]={6253,6258,6259,6260};
    static const cdisasm_arm_name_id names[4]={CDISASM_ARM_NAME_FDOT,CDISASM_ARM_NAME_FDOT,CDISASM_ARM_NAME_FDOT,CDISASM_ARM_NAME_BFDOT};
    static const uint8_t dst_elements[4]={4,2,4,4},src_elements[4]={1,1,2,2},lanes[4]={1,3,1,2};
#if USE_DISASM_FORMAT
    static const char *texts[4]={"fdot v0.4s, v1.16b, v2.4b[1]","fdot v3.4h, v4.8b, v5.2b[3]","fdot v6.4s, v7.8h, v8.2h[1]","bfdot v9.4s, v10.8h, v11.2h[2]"};
#endif
#endif
    unsigned x;for(x=0;x<4;x++){cdisasm_arm_instruction i;
#if USE_EXTRA_OPCODES
        EXPECT(decode(words[x],CDISASM_ARM_CPU_ANY,&i)==4);EXPECT(i.form_id==forms[x]&&i.name_id==names[x]);
        EXPECT(i.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SIMD|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));EXPECT(i.operand_count==3);
        EXPECT(CDISASM_ARM_VECTOR_ELEMENT_SIZE(&i.operand[0])==dst_elements[x]&&i.operand[0].access==CDISASM_OPERAND_ACCESS_READ_WRITE);
        EXPECT(CDISASM_ARM_VECTOR_ELEMENT_SIZE(&i.operand[1])==src_elements[x]&&i.operand[1].access==CDISASM_OPERAND_ACCESS_READ);
        EXPECT(CDISASM_ARM_VECTOR_ELEMENT_SIZE(&i.operand[2])==src_elements[x]&&i.operand[2].imm==lanes[x]&&i.operand[2].flags==CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
#if USE_DISASM_FORMAT
        {char text[96];EXPECT(cdisasm_arm_format(&i,CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,text,sizeof(text))==strlen(texts[x]));EXPECT(strcmp(text,texts[x])==0);}
#endif
#else
        EXPECT(decode(words[x],CDISASM_ARM_CPU_ANY,&i)==0);
#endif
    }
#if USE_EXTRA_OPCODES
    {cdisasm_arm_instruction i;for(x=0;x<4;x++)EXPECT(decode(words[x],CDISASM_ARM_CPU_CORTEX_A53,&i)==0);}
#endif
    return failures?1:0;
}
