#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
# include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>
typedef struct d{uint32_t reg_value,imm_value;cdisasm_arm_name_id name;cdisasm_arm_form_id reg_form,imm_form;uint8_t size;}d;
static const d forms[]={{UINT32_C(0xa400c000),UINT32_C(0xa400e000),CDISASM_ARM_NAME_LDNT1B,3346u,3362u,1u},{UINT32_C(0xa480c000),UINT32_C(0xa480e000),CDISASM_ARM_NAME_LDNT1H,3347u,3363u,2u},{UINT32_C(0xa500c000),UINT32_C(0xa500e000),CDISASM_ARM_NAME_LDNT1W,3348u,3364u,4u},{UINT32_C(0xa580c000),UINT32_C(0xa580e000),CDISASM_ARM_NAME_LDNT1D,3349u,3365u,8u}};
typedef struct g{uint32_t value;cdisasm_arm_name_id name;cdisasm_arm_form_id form;uint8_t es,ms;}g;
static const g gather_forms[]={{UINT32_C(0x8500a000),CDISASM_ARM_NAME_LDNT1W,3222u,4u,4u},{UINT32_C(0x8400a000),CDISASM_ARM_NAME_LDNT1B,3223u,4u,1u},{UINT32_C(0x8480a000),CDISASM_ARM_NAME_LDNT1H,3224u,4u,2u},{UINT32_C(0xc580c000),CDISASM_ARM_NAME_LDNT1D,3412u,8u,8u},{UINT32_C(0xc400c000),CDISASM_ARM_NAME_LDNT1B,3413u,8u,1u},{UINT32_C(0xc480c000),CDISASM_ARM_NAME_LDNT1H,3414u,8u,2u},{UINT32_C(0xc500c000),CDISASM_ARM_NAME_LDNT1W,3415u,8u,4u}};
static int failures;
#define EXPECT(c) do{if(!(c)){if(failures<20)fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#c);++failures;}}while(0)
static uint32_t dw(uint32_t w,cdisasm_arm_cpu_id cpu,cdisasm_arm_instruction*i){uint8_t b[4]={(uint8_t)w,(uint8_t)(w>>8),(uint8_t)(w>>16),(uint8_t)(w>>24)};memset(i,0xa5,sizeof(*i));return cdisasm_arm_decode(cpu,CDISASM_ARM_MODE_A64,b,4,UINT64_C(0x1a000),CDISASM_ARM_DECODE_OPTION_NONE,i);}
static int error_only(const cdisasm_arm_instruction*i,cdisasm_status s){cdisasm_arm_instruction z;memset(&z,0,sizeof(z));z.last_error_id=(uint8_t)s;return memcmp(i,&z,sizeof(z))==0;}
#if USE_EXTRA_OPCODES
static void common(const d*x,const cdisasm_arm_instruction*i,unsigned pg,unsigned rn,unsigned zt,cdisasm_arm_form_id form){EXPECT(i->name_id==x->name);EXPECT(i->form_id==form);EXPECT(i->instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));EXPECT(i->operand_count==3);EXPECT(i->operand[0].type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);EXPECT(i->operand[0].reg==CDISASM_ARM_REG_Z0+zt);EXPECT(i->operand[0].register_list==UINT16_C(0x0101));EXPECT(i->operand[0].extend_type==x->size);EXPECT(i->operand[0].access==CDISASM_OPERAND_ACCESS_WRITE);EXPECT(i->operand[1].type==CDISASM_ARM_OPERAND_PREDICATE);EXPECT(i->operand[1].reg==CDISASM_ARM_REG_P0+pg);EXPECT(i->operand[1].extend_type==x->size);EXPECT(i->operand[1].flags==CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO);EXPECT(i->operand[1].access==CDISASM_OPERAND_ACCESS_READ);EXPECT(i->operand[2].type==CDISASM_OPERAND_MEMORY);EXPECT(i->operand[2].base_reg==(rn==31?CDISASM_ARM_REG_SP:CDISASM_ARM_REG_X0+rn));EXPECT(i->operand[2].size==x->size);EXPECT(i->operand[2].access==CDISASM_OPERAND_ACCESS_READ);}
#endif
static void exhaustive_register(void){for(unsigned f=0;f<4;f++)for(unsigned xm=0;xm<32;xm++)for(unsigned pg=0;pg<8;pg++)for(unsigned rn=0;rn<32;rn++)for(unsigned zt=0;zt<32;zt++){const d*x=&forms[f];cdisasm_arm_instruction i;uint32_t w=x->reg_value|(xm<<16)|(pg<<10)|(rn<<5)|zt;uint32_t n=dw(w,CDISASM_ARM_CPU_ANY,&i);if(xm==31){EXPECT(n==0);EXPECT(error_only(&i,CDISASM_STATUS_INVALID_INSTRUCTION));continue;}
#if USE_EXTRA_OPCODES
 EXPECT(n==4);common(x,&i,pg,rn,zt,x->reg_form);EXPECT(i.operand[2].index_reg==CDISASM_ARM_REG_X0+xm);EXPECT(i.operand[2].shift_type==(x->size==1?CDISASM_ARM_SHIFT_NONE:CDISASM_ARM_SHIFT_LSL));EXPECT(i.operand[2].shift_amount==(x->size==1?0:x->size==2?1:x->size==4?2:3));
#else
 EXPECT(n==0);EXPECT(error_only(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}}
static void exhaustive_immediate(void){for(unsigned f=0;f<4;f++)for(unsigned imm=0;imm<16;imm++)for(unsigned pg=0;pg<8;pg++)for(unsigned rn=0;rn<32;rn++)for(unsigned zt=0;zt<32;zt++){const d*x=&forms[f];cdisasm_arm_instruction i;int64_t disp=imm<8?(int64_t)imm:(int64_t)imm-16;uint32_t w=x->imm_value|(imm<<16)|(pg<<10)|(rn<<5)|zt;uint32_t n=dw(w,CDISASM_ARM_CPU_ANY,&i);
#if USE_EXTRA_OPCODES
 EXPECT(n==4);common(x,&i,pg,rn,zt,x->imm_form);EXPECT(i.operand[2].index_reg==CDISASM_ARM_REG_NONE);EXPECT((int64_t)i.operand[2].imm==disp);EXPECT(i.operand[2].flags==(disp==0?0:(CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT|CDISASM_ARM_OPERAND_FLAG_VL_SCALED|(disp<0?CDISASM_OPERAND_FLAG_SIGNED:0))));
#else
 (void)disp;EXPECT(n==0);EXPECT(error_only(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}}
static void exhaustive_gather(void){for(unsigned f=0;f<7;f++)for(unsigned xm=0;xm<32;xm++)for(unsigned pg=0;pg<8;pg++)for(unsigned zn=0;zn<32;zn++)for(unsigned zt=0;zt<32;zt++){const g*x=&gather_forms[f];cdisasm_arm_instruction i;uint32_t w=x->value|(xm<<16)|(pg<<10)|(zn<<5)|zt;uint32_t n=dw(w,CDISASM_ARM_CPU_ANY,&i);
#if USE_EXTRA_OPCODES
 EXPECT(n==4);EXPECT(i.name_id==x->name);EXPECT(i.form_id==x->form);EXPECT(i.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));EXPECT(i.operand_count==3);EXPECT(i.operand[0].type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);EXPECT(i.operand[0].reg==CDISASM_ARM_REG_Z0+zt);EXPECT(i.operand[0].register_list==UINT16_C(0x0101));EXPECT(i.operand[0].extend_type==x->es);EXPECT(i.operand[0].access==CDISASM_OPERAND_ACCESS_WRITE);EXPECT(i.operand[1].type==CDISASM_ARM_OPERAND_PREDICATE);EXPECT(i.operand[1].reg==CDISASM_ARM_REG_P0+pg);EXPECT(i.operand[1].extend_type==x->es);EXPECT(i.operand[1].flags==CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO);EXPECT(i.operand[1].access==CDISASM_OPERAND_ACCESS_READ);EXPECT(i.operand[2].type==CDISASM_OPERAND_MEMORY);EXPECT(i.operand[2].base_reg==CDISASM_ARM_REG_Z0+zn);EXPECT(i.operand[2].index_reg==(xm==31?CDISASM_ARM_REG_NONE:CDISASM_ARM_REG_X0+xm));EXPECT(i.operand[2].size==x->ms);EXPECT(i.operand[2].access==CDISASM_OPERAND_ACCESS_READ);EXPECT(i.operand[2].flags==0);EXPECT(i.operand[2].shift_type==CDISASM_ARM_SHIFT_NONE);EXPECT(i.operand[2].extend_type==CDISASM_ARM_EXTEND_NONE);
#else
 EXPECT(n==0);EXPECT(error_only(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}}
static void gates_format(void){cdisasm_arm_instruction i;EXPECT(dw(UINT32_C(0xa400c020),CDISASM_ARM_CPU_CORTEX_A53,&i)==0);
#if USE_EXTRA_OPCODES
 EXPECT(error_only(&i,CDISASM_STATUS_INVALID_INSTRUCTION));EXPECT(dw(UINT32_C(0xa400c020),CDISASM_ARM_CPU_FUJITSU_A64FX,&i)==4);EXPECT(dw(UINT32_C(0xa400c020),CDISASM_ARM_CPU_APPLE_M4,&i)==4);
#else
 EXPECT(error_only(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
 EXPECT(dw(UINT32_C(0x841fa020),CDISASM_ARM_CPU_CORTEX_A53,&i)==0);
#if USE_EXTRA_OPCODES
 EXPECT(error_only(&i,CDISASM_STATUS_INVALID_INSTRUCTION));EXPECT(dw(UINT32_C(0x841fa020),CDISASM_ARM_CPU_ANY,&i)==4);
#else
 EXPECT(error_only(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
 static const struct{uint32_t w;const char*t;}v[]={{UINT32_C(0xa402c020),"ldnt1b {z0.b}, p0/z, [x1, x2]"},{UINT32_C(0xa58acfE9),"ldnt1d {z9.d}, p3/z, [sp, x10, lsl #0x3]"},{UINT32_C(0xa487f5cd),"ldnt1h {z13.h}, p5/z, [x14, #0x7, mul vl]"}};for(unsigned k=0;k<3;k++){char t[96];EXPECT(dw(v[k].w,CDISASM_ARM_CPU_ANY,&i)==4);EXPECT(cdisasm_arm_format(&i,0,t,sizeof(t))==strlen(v[k].t));EXPECT(strcmp(t,v[k].t)==0);}{char t[96];cdisasm_arm_instruction bad;EXPECT(dw(UINT32_C(0xa487f5cd),CDISASM_ARM_CPU_ANY,&i)==4);bad=i;bad.form_id=3362u;EXPECT(cdisasm_arm_format(&bad,0,t,sizeof(t))==0);bad=i;bad.operand[2].flags=0;EXPECT(cdisasm_arm_format(&bad,0,t,sizeof(t))==0);}
 {static const struct{uint32_t w;const char*t;}g[]={{UINT32_C(0x841fa020),"ldnt1b {z0.s}, p0/z, [z1.s]"},{UINT32_C(0x8484a462),"ldnt1h {z2.s}, p1/z, [z3.s, x4]"},{UINT32_C(0xc58cd16a),"ldnt1d {z10.d}, p4/z, [z11.d, x12]"}};for(unsigned k=0;k<3;k++){char t[96];EXPECT(dw(g[k].w,CDISASM_ARM_CPU_ANY,&i)==4);EXPECT(cdisasm_arm_format(&i,0,t,sizeof(t))==strlen(g[k].t));EXPECT(strcmp(t,g[k].t)==0);} {char t[96];cdisasm_arm_instruction bad;EXPECT(dw(g[1].w,CDISASM_ARM_CPU_ANY,&i)==4);bad=i;bad.form_id=3414u;EXPECT(cdisasm_arm_format(&bad,0,t,sizeof(t))==0);bad=i;bad.operand[2].index_reg=CDISASM_ARM_REG_Z4;EXPECT(cdisasm_arm_format(&bad,0,t,sizeof(t))==0);}}
#endif
}
int main(void){exhaustive_register();exhaustive_immediate();exhaustive_gather();gates_format();if(failures)fprintf(stderr,"%d non-temporal load failures\n",failures);else puts("SVE/SME non-temporal load tests passed (15 exact leaves)");return failures?1:0;}
