#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
# include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>
static int failures;
#define EXPECT(c) do{if(!(c)){if(failures<20)fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#c);++failures;}}while(0)
static uint32_t dw(uint32_t w,cdisasm_arm_cpu_id cpu,cdisasm_arm_instruction*i){uint8_t b[4]={(uint8_t)w,(uint8_t)(w>>8),(uint8_t)(w>>16),(uint8_t)(w>>24)};memset(i,0xa5,sizeof(*i));return cdisasm_arm_decode(cpu,CDISASM_ARM_MODE_A64,b,4,UINT64_C(0x18000),CDISASM_ARM_DECODE_OPTION_NONE,i);}
static int error_only(const cdisasm_arm_instruction*i,cdisasm_status s){cdisasm_arm_instruction z;memset(&z,0,sizeof(z));z.last_error_id=(uint8_t)s;return memcmp(i,&z,sizeof(z))==0;}
static void exhaustive(void){
#if USE_EXTRA_OPCODES
 static const cdisasm_arm_name_id names[4][4]={{CDISASM_ARM_NAME_LD1RB,CDISASM_ARM_NAME_LD1RB,CDISASM_ARM_NAME_LD1RB,CDISASM_ARM_NAME_LD1RB},{CDISASM_ARM_NAME_LD1RSW,CDISASM_ARM_NAME_LD1RH,CDISASM_ARM_NAME_LD1RH,CDISASM_ARM_NAME_LD1RH},{CDISASM_ARM_NAME_LD1RSH,CDISASM_ARM_NAME_LD1RSH,CDISASM_ARM_NAME_LD1RW,CDISASM_ARM_NAME_LD1RW},{CDISASM_ARM_NAME_LD1RSB,CDISASM_ARM_NAME_LD1RSB,CDISASM_ARM_NAME_LD1RSB,CDISASM_ARM_NAME_LD1RD}};
 static const uint8_t ms[4][4]={{1,1,1,1},{4,2,2,2},{2,2,4,4},{1,1,1,8}},ds[4][4]={{1,2,4,8},{8,2,4,8},{8,4,4,8},{8,4,2,8}};
#endif
 static const uint32_t bases[4]={UINT32_C(0x84408000),UINT32_C(0x84c08000),UINT32_C(0x85408000),UINT32_C(0x85c08000)};
 for(unsigned op=0;op<4;op++)for(unsigned a=0;a<4;a++)for(unsigned imm=0;imm<64;imm++)for(unsigned pg=0;pg<8;pg++)for(unsigned rn=0;rn<32;rn++)for(unsigned zd=0;zd<32;zd++){cdisasm_arm_instruction i;uint32_t w=bases[op]|(a<<13)|(imm<<16)|(pg<<10)|(rn<<5)|zd;uint32_t n=dw(w,CDISASM_ARM_CPU_ANY,&i);
#if USE_EXTRA_OPCODES
 EXPECT(n==4);EXPECT(i.name_id==names[op][a]);EXPECT(i.form_id==3243u+op*4u+a);EXPECT(i.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));EXPECT(i.operand_count==3);EXPECT(i.operand[0].type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);EXPECT(i.operand[0].reg==CDISASM_ARM_REG_Z0+zd);EXPECT(i.operand[0].register_list==UINT16_C(0x0101));EXPECT(i.operand[0].extend_type==ds[op][a]);EXPECT(i.operand[1].reg==CDISASM_ARM_REG_P0+pg);EXPECT(i.operand[1].flags==CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO);EXPECT(i.operand[2].base_reg==(rn==31?CDISASM_ARM_REG_SP:CDISASM_ARM_REG_X0+rn));EXPECT(i.operand[2].size==ms[op][a]);EXPECT(i.operand[2].imm==(uint64_t)imm*ms[op][a]);
#else
 EXPECT(n==0);EXPECT(error_only(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
 }}
static void gates_and_format(void){cdisasm_arm_instruction i;EXPECT(dw(UINT32_C(0x84408000),CDISASM_ARM_CPU_CORTEX_A53,&i)==0);
#if USE_EXTRA_OPCODES
 EXPECT(error_only(&i,CDISASM_STATUS_INVALID_INSTRUCTION));
#else
 EXPECT(error_only(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
 static const struct{uint32_t w;const char*t;}v[]={{UINT32_C(0x84408000),"ld1rb {z0.b}, p0/z, [x0]"},{UINT32_C(0x8443a441),"ld1rb {z1.h}, p1/z, [x2, #3]"},{UINT32_C(0x84c3c883),"ld1rh {z3.s}, p2/z, [x4, #6]"},{UINT32_C(0x8543ecc5),"ld1rw {z5.d}, p3/z, [x6, #12]"},{UINT32_C(0x85cf9107),"ld1rsb {z7.d}, p4/z, [x8, #15]"},{UINT32_C(0x8547b549),"ld1rsh {z9.s}, p5/z, [x10, #14]"},{UINT32_C(0x84c7998b),"ld1rsw {z11.d}, p6/z, [x12, #28]"}};for(unsigned k=0;k<sizeof(v)/sizeof(v[0]);k++){char t[96];EXPECT(dw(v[k].w,CDISASM_ARM_CPU_ANY,&i)==4);EXPECT(cdisasm_arm_format(&i,CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,t,sizeof(t))==strlen(v[k].t));EXPECT(strcmp(t,v[k].t)==0);}
#endif
}
int main(void){exhaustive();gates_and_format();if(failures)fprintf(stderr,"%d SVE replicate-load failures\n",failures);else puts("SVE replicated scalar-load tests passed");return failures?1:0;}
