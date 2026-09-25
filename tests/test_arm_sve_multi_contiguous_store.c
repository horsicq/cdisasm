#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
# include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>
typedef struct d{uint32_t value;cdisasm_arm_name_id name;cdisasm_arm_form_id rf,imf;uint8_t size,count;}d;
static const d f[]={{0xe4206000,CDISASM_ARM_NAME_ST2B,3489,3537,1,2},{0xe4406000,CDISASM_ARM_NAME_ST3B,3490,3538,1,3},{0xe4606000,CDISASM_ARM_NAME_ST4B,3491,3539,1,4},{0xe4a06000,CDISASM_ARM_NAME_ST2H,3492,3540,2,2},{0xe4c06000,CDISASM_ARM_NAME_ST3H,3493,3541,2,3},{0xe4e06000,CDISASM_ARM_NAME_ST4H,3494,3542,2,4},{0xe5206000,CDISASM_ARM_NAME_ST2W,3495,3543,4,2},{0xe5406000,CDISASM_ARM_NAME_ST3W,3496,3544,4,3},{0xe5606000,CDISASM_ARM_NAME_ST4W,3497,3545,4,4},{0xe5a06000,CDISASM_ARM_NAME_ST2D,3498,3546,8,2},{0xe5c06000,CDISASM_ARM_NAME_ST3D,3499,3547,8,3},{0xe5e06000,CDISASM_ARM_NAME_ST4D,3500,3548,8,4}};
static int failures;
#define E(c) do{if(!(c)){if(failures<20)fprintf(stderr,"%d: %s\n",__LINE__,#c);failures++;}}while(0)
static uint32_t dw(uint32_t w,cdisasm_arm_cpu_id c,cdisasm_arm_instruction*i){uint8_t b[4]={(uint8_t)w,(uint8_t)(w>>8),(uint8_t)(w>>16),(uint8_t)(w>>24)};memset(i,0xa5,sizeof(*i));return cdisasm_arm_decode(c,CDISASM_ARM_MODE_A64,b,4,0,CDISASM_ARM_DECODE_OPTION_NONE,i);}
static int eo(const cdisasm_arm_instruction*i,cdisasm_status s){cdisasm_arm_instruction z;memset(&z,0,sizeof(z));z.last_error_id=(uint8_t)s;return memcmp(i,&z,sizeof(z))==0;}
#if USE_EXTRA_OPCODES
static void common(const d*x,const cdisasm_arm_instruction*i,unsigned p,unsigned r,unsigned z,unsigned im){E(i->name_id==x->name);E(i->form_id==(im?x->imf:x->rf));E(i->instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));E(i->operand_count==3);E(i->operand[0].type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);E(i->operand[0].reg==CDISASM_ARM_REG_Z0+z);E(i->operand[0].register_list==(0x100u|x->count));E(i->operand[0].extend_type==x->size);E(i->operand[0].access==CDISASM_OPERAND_ACCESS_READ);E(i->operand[1].reg==CDISASM_ARM_REG_P0+p);E(i->operand[1].extend_type==x->size);E(i->operand[1].flags==0);E(i->operand[2].base_reg==(r==31?CDISASM_ARM_REG_SP:CDISASM_ARM_REG_X0+r));E(i->operand[2].size==x->size);E(i->operand[2].access==CDISASM_OPERAND_ACCESS_WRITE);}
#endif
static void domains(void){for(unsigned q=0;q<12;q++)for(unsigned im=0;im<2;im++)for(unsigned m=0;m<(im?16u:32u);m++)for(unsigned p=0;p<8;p++)for(unsigned r=0;r<32;r++)for(unsigned z=0;z<32;z++){const d*x=&f[q];cdisasm_arm_instruction i;uint32_t w=x->value|(im?0x108000u:0u)|(m<<16)|(p<<10)|(r<<5)|z;uint32_t n=dw(w,CDISASM_ARM_CPU_ANY,&i);if(!im&&m==31){E(n==0);E(eo(&i,CDISASM_STATUS_INVALID_INSTRUCTION));continue;}
#if USE_EXTRA_OPCODES
 int64_t disp=im*(m<8?(int64_t)m:(int64_t)m-16)*(int64_t)x->count;E(n==4);common(x,&i,p,r,z,im);E(i.operand[2].index_reg==(im?CDISASM_ARM_REG_NONE:CDISASM_ARM_REG_X0+m));E((int64_t)i.operand[2].imm==disp);E(i.operand[2].flags==(disp==0?0:(CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT|CDISASM_ARM_OPERAND_FLAG_VL_SCALED|(disp<0?CDISASM_OPERAND_FLAG_SIGNED:0))));E(i.operand[2].shift_amount==(im||x->size==1?0:x->size==2?1:x->size==4?2:3));
#else
 E(n==0);E(eo(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}}
static void profiles_format(void){cdisasm_arm_instruction i;E(dw(UINT32_C(0xe4226020),CDISASM_ARM_CPU_CORTEX_A53,&i)==0);
#if USE_EXTRA_OPCODES
 E(eo(&i,CDISASM_STATUS_INVALID_INSTRUCTION));E(dw(UINT32_C(0xe4226020),CDISASM_ARM_CPU_FUJITSU_A64FX,&i)==4);E(dw(UINT32_C(0xe4226020),CDISASM_ARM_CPU_APPLE_M4,&i)==4);
#else
 E(eo(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
 {char t[128];E(dw(UINT32_C(0xe422603f),CDISASM_ARM_CPU_ANY,&i)==4);E(cdisasm_arm_format(&i,0,t,sizeof(t))!=0);E(strcmp(t,"st2b {z31.b, z0.b}, p0, [x1, x2]")==0);E(dw(UINT32_C(0xe5f7ffee),CDISASM_ARM_CPU_ANY,&i)==4);E(cdisasm_arm_format(&i,0,t,sizeof(t))!=0);E(strcmp(t,"st4d {z14.d, z15.d, z16.d, z17.d}, p7, [sp, #0x1c, mul vl]")==0);i.form_id=3491;E(cdisasm_arm_format(&i,0,t,sizeof(t))==0);}
#endif
}
int main(void){domains();profiles_format();if(failures)return fprintf(stderr,"%d failures\n",failures),1;puts("SVE/SME ST2/ST3/ST4 contiguous-store tests passed (24 exact leaves)");return 0;}
