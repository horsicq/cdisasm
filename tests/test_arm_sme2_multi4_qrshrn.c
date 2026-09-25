#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
# include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>
typedef struct F{uint32_t v;cdisasm_arm_name_id n;cdisasm_arm_form_id f;}F;
#define CDISASM_ARM_OPERAND_IMMEDIATE CDISASM_OPERAND_IMMEDIATE
static const F fs[3]={{0xc120dc00u,CDISASM_ARM_NAME_SQRSHRN,4308u},{0xc120dc40u,CDISASM_ARM_NAME_SQRSHRUN,4309u},{0xc120dc20u,CDISASM_ARM_NAME_UQRSHRN,4311u}};
static int fails;
#define E(x) do{if(!(x)){if(fails<24)fprintf(stderr,"%d: %s\n",__LINE__,#x);fails++;}}while(0)
static uint32_t D(uint32_t w,cdisasm_arm_cpu_id c,cdisasm_arm_instruction*i){uint8_t b[4]={(uint8_t)w,(uint8_t)(w>>8),(uint8_t)(w>>16),(uint8_t)(w>>24)};memset(i,0xa5,sizeof(*i));return cdisasm_arm_decode(c,CDISASM_ARM_MODE_A64,b,4,0,CDISASM_ARM_DECODE_OPTION_NONE,i);}
static int Z(const cdisasm_arm_instruction*i,cdisasm_status s){cdisasm_arm_instruction z;memset(&z,0,sizeof(z));z.last_error_id=(uint8_t)s;return !memcmp(i,&z,sizeof(z));}
static void domain(void){unsigned f,t,im,g,d;for(f=0;f<3;f++)for(t=1;t<4;t++)for(im=0;im<32;im++)for(g=0;g<8;g++)for(d=0;d<32;d++){uint32_t w=fs[f].v|(t<<22)|(im<<16)|(g<<7)|d;cdisasm_arm_instruction i;
#if USE_EXTRA_OPCODES
unsigned sb=t==1?32:64,en=(t<<5)|im;E(D(w,CDISASM_ARM_CPU_ANY,&i)==4);E(i.name_id==fs[f].n&&i.form_id==fs[f].f);E(i.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SME|CDISASM_ARM_INSTRUCTION_FLAG_MATRIX|CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR));E(i.operand_count==3);E(i.operand[0].type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER&&i.operand[0].reg==CDISASM_ARM_REG_Z0+d&&i.operand[0].extend_type==sb/32&&i.operand[0].access==CDISASM_OPERAND_ACCESS_WRITE);E(i.operand[1].type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&i.operand[1].reg==CDISASM_ARM_REG_Z0+g*4&&i.operand[1].register_list==0x0104&&i.operand[1].extend_type==sb/8&&i.operand[1].access==CDISASM_OPERAND_ACCESS_READ);E(i.operand[2].type==CDISASM_ARM_OPERAND_IMMEDIATE&&i.operand[2].imm==2*sb-en&&i.operand[2].size==1&&i.operand[2].access==CDISASM_OPERAND_ACCESS_READ);
#else
E(D(w,CDISASM_ARM_CPU_ANY,&i)==0&&Z(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}}
static void edges(void){cdisasm_arm_instruction i;unsigned f;for(f=0;f<3;f++){uint32_t bad=fs[f].v|0x001f0000u;E(D(bad,CDISASM_ARM_CPU_ANY,&i)==0);
#if USE_EXTRA_OPCODES
E(Z(&i,CDISASM_STATUS_INVALID_INSTRUCTION));E(D(fs[f].v|0x00400000u,CDISASM_ARM_CPU_APPLE_M4,&i)==4);E(D(fs[f].v|0x00400000u,CDISASM_ARM_CPU_CORTEX_A53,&i)==0&&Z(&i,CDISASM_STATUS_INVALID_INSTRUCTION));
#else
E(Z(&i,CDISASM_STATUS_INVALID_INSTRUCTION));
#endif
}
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
E(D(0xc160dc00u,CDISASM_ARM_CPU_ANY,&i)==4);{char s[96];E(cdisasm_arm_format(&i,0,s,sizeof(s))==strlen("sqrshrn z0.b, {z0.s, z1.s, z2.s, z3.s}, #0x20"));E(!strcmp(s,"sqrshrn z0.b, {z0.s, z1.s, z2.s, z3.s}, #0x20"));i.operand[1].register_list=0x0102;E(cdisasm_arm_format(&i,0,s,sizeof(s))==0);}
#endif
}
int main(void){domain();edges();if(fails)return fprintf(stderr,"%d failures\n",fails),1;puts("SME2 four-vector saturating rounding-narrow tests passed (3 exact leaves)");return 0;}
