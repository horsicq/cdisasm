#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
# include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>
typedef struct d{uint32_t rv,iv;cdisasm_arm_name_id name;cdisasm_arm_form_id rf,ifm;uint8_t size;}d;
static const d forms[]={{0xe4006000,0xe410e000,CDISASM_ARM_NAME_STNT1B,3485,3533,1},{0xe4806000,0xe490e000,CDISASM_ARM_NAME_STNT1H,3486,3534,2},{0xe5006000,0xe510e000,CDISASM_ARM_NAME_STNT1W,3487,3535,4},{0xe5806000,0xe590e000,CDISASM_ARM_NAME_STNT1D,3488,3536,8}};
typedef struct g{uint32_t value;cdisasm_arm_name_id name;cdisasm_arm_form_id form;uint8_t es,ms;}g;
static const g gather_forms[]={{0xe4402000,CDISASM_ARM_NAME_STNT1B,3481,4,1},{0xe4c02000,CDISASM_ARM_NAME_STNT1H,3482,4,2},{0xe5402000,CDISASM_ARM_NAME_STNT1W,3483,4,4},{0xe4002000,CDISASM_ARM_NAME_STNT1B,3477,8,1},{0xe4802000,CDISASM_ARM_NAME_STNT1H,3478,8,2},{0xe5002000,CDISASM_ARM_NAME_STNT1W,3479,8,4},{0xe5802000,CDISASM_ARM_NAME_STNT1D,3480,8,8}};
static int failures;
#define E(c) do{if(!(c)){if(failures<20)fprintf(stderr,"%d: %s\n",__LINE__,#c);failures++;}}while(0)
static uint32_t dw(uint32_t w,cdisasm_arm_cpu_id c,cdisasm_arm_instruction*i){uint8_t b[4]={(uint8_t)w,(uint8_t)(w>>8),(uint8_t)(w>>16),(uint8_t)(w>>24)};memset(i,0xa5,sizeof(*i));return cdisasm_arm_decode(c,CDISASM_ARM_MODE_A64,b,4,0,CDISASM_ARM_DECODE_OPTION_NONE,i);}
static int eo(const cdisasm_arm_instruction*i,cdisasm_status s){cdisasm_arm_instruction z;memset(&z,0,sizeof(z));z.last_error_id=(uint8_t)s;return memcmp(i,&z,sizeof(z))==0;}
#if USE_EXTRA_OPCODES
static void common(const d*x,const cdisasm_arm_instruction*i,unsigned p,unsigned r,unsigned z,cdisasm_arm_form_id form){E(i->name_id==x->name);E(i->form_id==form);E(i->instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));E(i->operand_count==3);E(i->operand[0].type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);E(i->operand[0].reg==CDISASM_ARM_REG_Z0+z);E(i->operand[0].register_list==0x101);E(i->operand[0].extend_type==x->size);E(i->operand[0].access==CDISASM_OPERAND_ACCESS_READ);E(i->operand[1].reg==CDISASM_ARM_REG_P0+p);E(i->operand[1].extend_type==x->size);E(i->operand[1].flags==0);E(i->operand[1].access==CDISASM_OPERAND_ACCESS_READ);E(i->operand[2].base_reg==(r==31?CDISASM_ARM_REG_SP:CDISASM_ARM_REG_X0+r));E(i->operand[2].size==x->size);E(i->operand[2].access==CDISASM_OPERAND_ACCESS_WRITE);}
#endif
static void domains(void){for(unsigned q=0;q<4;q++)for(unsigned im=0;im<2;im++)for(unsigned m=0;m<(im?16u:32u);m++)for(unsigned p=0;p<8;p++)for(unsigned r=0;r<32;r++)for(unsigned z=0;z<32;z++){const d*x=&forms[q];cdisasm_arm_instruction i;uint32_t w=(im?x->iv:x->rv)|(m<<16)|(p<<10)|(r<<5)|z,n=dw(w,CDISASM_ARM_CPU_ANY,&i);if(!im&&m==31){E(n==0);E(eo(&i,CDISASM_STATUS_INVALID_INSTRUCTION));continue;}
#if USE_EXTRA_OPCODES
 int64_t disp=im*(m<8?(int64_t)m:(int64_t)m-16);E(n==4);common(x,&i,p,r,z,im?x->ifm:x->rf);E(i.operand[2].index_reg==(im?CDISASM_ARM_REG_NONE:CDISASM_ARM_REG_X0+m));E((int64_t)i.operand[2].imm==disp);E(i.operand[2].flags==(disp==0?0:(CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT|CDISASM_ARM_OPERAND_FLAG_VL_SCALED|(disp<0?CDISASM_OPERAND_FLAG_SIGNED:0))));E(i.operand[2].shift_amount==(im||x->size==1?0:x->size==2?1:x->size==4?2:3));
#else
 E(n==0);E(eo(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}}
static void gather_domains(void){for(unsigned q=0;q<7;q++)for(unsigned m=0;m<32;m++)for(unsigned p=0;p<8;p++)for(unsigned r=0;r<32;r++)for(unsigned z=0;z<32;z++){const g*x=&gather_forms[q];cdisasm_arm_instruction i;uint32_t w=x->value|(m<<16)|(p<<10)|(r<<5)|z,n=dw(w,CDISASM_ARM_CPU_ANY,&i);
#if USE_EXTRA_OPCODES
 E(n==4);E(i.name_id==x->name);E(i.form_id==x->form);E(i.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));E(i.operand_count==3);E(i.operand[0].type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);E(i.operand[0].reg==CDISASM_ARM_REG_Z0+z);E(i.operand[0].register_list==0x101);E(i.operand[0].extend_type==x->es);E(i.operand[0].access==CDISASM_OPERAND_ACCESS_READ);E(i.operand[1].type==CDISASM_ARM_OPERAND_PREDICATE);E(i.operand[1].reg==CDISASM_ARM_REG_P0+p);E(i.operand[1].extend_type==x->es);E(i.operand[1].flags==0);E(i.operand[1].access==CDISASM_OPERAND_ACCESS_READ);E(i.operand[2].type==CDISASM_OPERAND_MEMORY);E(i.operand[2].base_reg==CDISASM_ARM_REG_Z0+r);E(i.operand[2].index_reg==(m==31?CDISASM_ARM_REG_NONE:CDISASM_ARM_REG_X0+m));E(i.operand[2].size==x->ms);E(i.operand[2].access==CDISASM_OPERAND_ACCESS_WRITE);E(i.operand[2].flags==0);E(i.operand[2].shift_type==CDISASM_ARM_SHIFT_NONE);E(i.operand[2].extend_type==CDISASM_ARM_EXTEND_NONE);
#else
 E(n==0);E(eo(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}}
static void gates_format(void){cdisasm_arm_instruction i;E(dw(0xe4026020,CDISASM_ARM_CPU_CORTEX_A53,&i)==0);
#if USE_EXTRA_OPCODES
 E(eo(&i,CDISASM_STATUS_INVALID_INSTRUCTION));E(dw(0xe4026020,CDISASM_ARM_CPU_FUJITSU_A64FX,&i)==4);E(dw(0xe4026020,CDISASM_ARM_CPU_APPLE_M4,&i)==4);
#else
 E(eo(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
 E(dw(0xe45f2020,CDISASM_ARM_CPU_CORTEX_A53,&i)==0);
#if USE_EXTRA_OPCODES
 E(eo(&i,CDISASM_STATUS_INVALID_INSTRUCTION));E(dw(0xe45f2020,CDISASM_ARM_CPU_ANY,&i)==4);
#else
 E(eo(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
 {static const struct{uint32_t w;const char*t;}v[]={{0xe4026020,"stnt1b {z0.b}, p0, [x1, x2]"},{0xe58a6fe9,"stnt1d {z9.d}, p3, [sp, x10, lsl #0x3]"},{0xe497f5cd,"stnt1h {z13.h}, p5, [x14, #0x7, mul vl]"}};for(unsigned k=0;k<3;k++){char t[96];E(dw(v[k].w,CDISASM_ARM_CPU_ANY,&i)==4);E(cdisasm_arm_format(&i,0,t,sizeof(t))==strlen(v[k].t));E(strcmp(t,v[k].t)==0);}char t[96];E(dw(0xe497f5cd,CDISASM_ARM_CPU_ANY,&i)==4);i.form_id=3533;E(cdisasm_arm_format(&i,0,t,sizeof(t))==0);}
 {static const struct{uint32_t w;const char*t;}v[]={{0xe45f2020,"stnt1b {z0.s}, p0, [z1.s]"},{0xe4c42462,"stnt1h {z2.s}, p1, [z3.s, x4]"},{0xe5923a30,"stnt1d {z16.d}, p6, [z17.d, x18]"}};for(unsigned k=0;k<3;k++){char t[96];E(dw(v[k].w,CDISASM_ARM_CPU_ANY,&i)==4);E(cdisasm_arm_format(&i,0,t,sizeof(t))==strlen(v[k].t));E(strcmp(t,v[k].t)==0);}char t[96];E(dw(v[1].w,CDISASM_ARM_CPU_ANY,&i)==4);i.operand[2].index_reg=CDISASM_ARM_REG_Z4;E(cdisasm_arm_format(&i,0,t,sizeof(t))==0);}
#endif
}
int main(void){domains();gather_domains();gates_format();if(failures)return fprintf(stderr,"%d failures\n",failures),1;puts("SVE/SME non-temporal store tests passed (15 exact leaves)");return 0;}
