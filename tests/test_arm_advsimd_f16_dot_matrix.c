#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
# include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>
typedef struct F{uint32_t v;cdisasm_arm_name_id n;cdisasm_arm_form_id f;uint8_t ds,ss,q;}F;
#define CDISASM_ARM_OPERAND_VECTOR_REGISTER CDISASM_OPERAND_REGISTER
static const F fs[3]={{0x0e80fc00u,CDISASM_ARM_NAME_FDOT,5981u,4u,2u,2u},{0x4ec0ec00u,CDISASM_ARM_NAME_FMMLA,5996u,2u,2u,1u},{0x4e40ec00u,CDISASM_ARM_NAME_FMMLA,5999u,4u,2u,1u}};
static int fails;
#define E(x) do{if(!(x)){if(fails<24)fprintf(stderr,"%d: %s\n",__LINE__,#x);fails++;}}while(0)
static uint32_t D(uint32_t w,cdisasm_arm_cpu_id c,cdisasm_arm_instruction*i){uint8_t b[4]={(uint8_t)w,(uint8_t)(w>>8),(uint8_t)(w>>16),(uint8_t)(w>>24)};memset(i,0xa5,sizeof(*i));return cdisasm_arm_decode(c,CDISASM_ARM_MODE_A64,b,4,0,CDISASM_ARM_DECODE_OPTION_NONE,i);}
static int Z(const cdisasm_arm_instruction*i,cdisasm_status s){cdisasm_arm_instruction z;memset(&z,0,sizeof(z));z.last_error_id=(uint8_t)s;return !memcmp(i,&z,sizeof(z));}
static void domain(void){unsigned f,q,d,n,m;for(f=0;f<3;f++)for(q=0;q<2;q++){if(fs[f].q==1&&q==0)continue;for(d=0;d<32;d++)for(n=0;n<32;n++)for(m=0;m<32;m++){uint32_t w=fs[f].v|(q<<30)|(m<<16)|(n<<5)|d;cdisasm_arm_instruction i;
#if USE_EXTRA_OPCODES
unsigned ts=q?16:8;E(D(w,CDISASM_ARM_CPU_ANY,&i)==4);E(i.name_id==fs[f].n&&i.form_id==fs[f].f);E(i.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SIMD|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)&&i.operand_count==3);E(i.operand[0].type==CDISASM_ARM_OPERAND_VECTOR_REGISTER&&i.operand[0].reg==CDISASM_ARM_REG_V0+d&&i.operand[0].size==ts&&i.operand[0].extend_type==fs[f].ds&&i.operand[0].access==CDISASM_OPERAND_ACCESS_READ_WRITE);E(i.operand[1].reg==CDISASM_ARM_REG_V0+n&&i.operand[1].size==ts&&i.operand[1].extend_type==fs[f].ss&&i.operand[1].access==CDISASM_OPERAND_ACCESS_READ);E(i.operand[2].reg==CDISASM_ARM_REG_V0+m&&i.operand[2].size==ts&&i.operand[2].extend_type==fs[f].ss&&i.operand[2].access==CDISASM_OPERAND_ACCESS_READ);
#else
E(D(w,CDISASM_ARM_CPU_ANY,&i)==0&&Z(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}}}
static void edges(void){cdisasm_arm_instruction i;unsigned f;for(f=0;f<3;f++){
#if USE_EXTRA_OPCODES
E(D(fs[f].v,CDISASM_ARM_CPU_CORTEX_A53,&i)==0&&Z(&i,CDISASM_STATUS_INVALID_INSTRUCTION));E(D(fs[f].v,CDISASM_ARM_CPU_ANY,&i)==4);
#else
E(D(fs[f].v,CDISASM_ARM_CPU_ANY,&i)==0&&Z(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
E(D(0x4e80fc00u,CDISASM_ARM_CPU_ANY,&i)==4);{char s[96];E(cdisasm_arm_format(&i,0,s,sizeof(s))==strlen("fdot v0.4s, v0.8h, v0.8h"));E(!strcmp(s,"fdot v0.4s, v0.8h, v0.8h"));i.operand[0].access=CDISASM_OPERAND_ACCESS_WRITE;E(cdisasm_arm_format(&i,0,s,sizeof(s))==0);}
#endif
}
int main(void){domain();edges();if(fails)return fprintf(stderr,"%d failures\n",fails),1;puts("Advanced SIMD FP16 dot/matrix tests passed (3 exact leaves)");return 0;}
