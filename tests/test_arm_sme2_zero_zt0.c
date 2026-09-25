#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>
static uint32_t d(cdisasm_arm_cpu_id c,cdisasm_arm_instruction*i){uint8_t b[4]={1,0,0x48,0xc0};return cdisasm_arm_decode(c,3,b,4,0,0,i);}
#if USE_EXTRA_OPCODES
static uint32_t dw(uint32_t w,cdisasm_arm_cpu_id c,cdisasm_arm_instruction*i){uint8_t b[4]={(uint8_t)w,(uint8_t)(w>>8),(uint8_t)(w>>16),(uint8_t)(w>>24)};return cdisasm_arm_decode(c,3,b,4,0,0,i);}
#endif
int main(void){cdisasm_arm_instruction i;
#if USE_EXTRA_OPCODES
{unsigned m;for(m=0;m<256;m++){uint32_t w=UINT32_C(0xc0080000)|m;if(dw(w,CDISASM_ARM_CPU_ANY,&i)!=4||i.name_id!=CDISASM_ARM_NAME_ZERO||i.form_id!=3907||i.instruction_flags!=UINT32_C(0x05000000)||i.operand_count!=1||i.operand[0].type!=CDISASM_OPERAND_IMMEDIATE||i.operand[0].imm!=m||i.operand[0].size!=1||i.operand[0].access!=CDISASM_OPERAND_ACCESS_READ)return 1;}if(dw(UINT32_C(0xc00800ff),CDISASM_ARM_CPU_CORTEX_A53,&i)!=0||i.last_error_id!=CDISASM_STATUS_INVALID_INSTRUCTION)return 1;
#if USE_DISASM_FORMAT
{struct F{uint32_t w;const char*s;}f[]={{0xc0080000,"zero {}"},{0xc0080001,"zero {za0.d}"},{0xc0080003,"zero {za0.d, za1.d}"},{0xc0080011,"zero {za0.s}"},{0xc0080033,"zero {za0.s, za1.s}"},{0xc0080055,"zero {za0.h}"},{0xc00800aa,"zero {za1.h}"},{0xc00800ff,"zero {za}"}};unsigned n;char t[96];for(n=0;n<sizeof(f)/sizeof(f[0]);n++){if(dw(f[n].w,CDISASM_ARM_CPU_ANY,&i)!=4||!cdisasm_arm_format(&i,0,t,sizeof(t))||strcmp(t,f[n].s))return 1;}i.form_id=3906;if(cdisasm_arm_format(&i,0,t,sizeof(t)))return 1;}
#endif
}
if(d(CDISASM_ARM_CPU_ANY,&i)!=4||i.name_id!=CDISASM_ARM_NAME_ZERO||i.form_id!=3916||i.operand_count!=1||i.operand[0].type!=CDISASM_ARM_OPERAND_TILE||i.operand[0].reg!=CDISASM_ARM_REG_ZT0||i.operand[0].access!=CDISASM_OPERAND_ACCESS_WRITE)return 1;if(d(CDISASM_ARM_CPU_CORTEX_A53,&i)!=0||i.last_error_id!=CDISASM_STATUS_INVALID_INSTRUCTION)return 1;
#if USE_DISASM_FORMAT
{char t[32];if(d(CDISASM_ARM_CPU_ANY,&i)!=4||!cdisasm_arm_format(&i,0,t,sizeof(t))||strcmp(t,"zero {zt0}"))return 1;i.form_id=3917;if(cdisasm_arm_format(&i,0,t,sizeof(t)))return 1;}
#endif
#else
if(d(CDISASM_ARM_CPU_ANY,&i)!=0||i.last_error_id!=CDISASM_STATUS_UNSUPPORTED_INSTRUCTION)return 1;
#endif
#if USE_EXTRA_OPCODES
{unsigned q,s,o;for(q=0;q<2;q++)for(s=0;s<4;s++)for(o=0;o<8;o++){uint32_t w=(q?UINT32_C(0xc00e0000):UINT32_C(0xc00c0000))|(s<<13)|o;if(dw(w,CDISASM_ARM_CPU_ANY,&i)!=4||i.form_id!=(q?3909:3908)||i.instruction_flags!=UINT32_C(0x05400000)||i.operand[0].reg!=CDISASM_ARM_REG_ZA||i.operand[0].base_reg!=CDISASM_ARM_REG_W8+s||i.operand[0].imm!=o||i.operand[0].register_list!=(q?4:2))return 1;}
#if USE_DISASM_FORMAT
{char t[64];if(dw(UINT32_C(0xc00e2007),CDISASM_ARM_CPU_ANY,&i)!=4||!cdisasm_arm_format(&i,0,t,sizeof(t))||strcmp(t,"zero za.d[w9, 7, vgx4]"))return 1;i.form_id=3908;if(cdisasm_arm_format(&i,0,t,sizeof(t)))return 1;}
#endif
}
{struct R{uint32_t v;unsigned form,range,vgx,max;}rs[]={{0xc00c8000,3910,2,0,8},{0xc00d0000,3911,2,2,4},{0xc00d8000,3912,2,4,4},{0xc00e8000,3913,4,0,4},{0xc00f0000,3914,4,2,2},{0xc00f8000,3915,4,4,2}};unsigned a,s,e;for(a=0;a<6;a++)for(s=0;s<4;s++)for(e=0;e<rs[a].max;e++){uint32_t w=rs[a].v|(s<<13)|e;if(dw(w,CDISASM_ARM_CPU_ANY,&i)!=4||i.form_id!=rs[a].form||i.operand[0].imm!=e*rs[a].range||i.operand[0].register_list!=((rs[a].vgx<<8)|rs[a].range))return 1;}
#if USE_DISASM_FORMAT
{char t[64];if(dw(UINT32_C(0xc00ce007),CDISASM_ARM_CPU_ANY,&i)!=4||!cdisasm_arm_format(&i,0,t,sizeof(t))||strcmp(t,"zero za.d[w11, 14:15]"))return 1;if(dw(UINT32_C(0xc00f2001),CDISASM_ARM_CPU_ANY,&i)!=4||!cdisasm_arm_format(&i,0,t,sizeof(t))||strcmp(t,"zero za.d[w9, 4:7, vgx2]"))return 1;i.form_id=3915;if(cdisasm_arm_format(&i,0,t,sizeof(t)))return 1;}
#endif
}
#endif
puts("ARM SME ZERO tests passed (10 exact leaves)");return 0;}
