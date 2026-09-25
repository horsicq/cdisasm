#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
# include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>
#if USE_EXTRA_OPCODES
static const cdisasm_arm_name_id ns[4]={CDISASM_ARM_NAME_PRFB,CDISASM_ARM_NAME_PRFH,CDISASM_ARM_NAME_PRFW,CDISASM_ARM_NAME_PRFD};
#endif
static int fail;
#define E(x)do{if(!(x)){if(fail<20)fprintf(stderr,"%d: %s\n",__LINE__,#x);fail++;}}while(0)
static uint32_t D(uint32_t w,cdisasm_arm_cpu_id c,cdisasm_arm_instruction*i){uint8_t b[4]={(uint8_t)w,(uint8_t)(w>>8),(uint8_t)(w>>16),(uint8_t)(w>>24)};memset(i,0xa5,sizeof(*i));return cdisasm_arm_decode(c,CDISASM_ARM_MODE_A64,b,4,0,CDISASM_ARM_DECODE_OPTION_NONE,i);}
static int Z(const cdisasm_arm_instruction*i,cdisasm_status s){cdisasm_arm_instruction z;memset(&z,0,sizeof(z));z.last_error_id=(uint8_t)s;return !memcmp(i,&z,sizeof(z));}
static void domain(void){unsigned f,s,zm,pg,rn,op;for(f=0;f<4;f++)for(s=0;s<2;s++)for(zm=0;zm<32;zm++)for(pg=0;pg<8;pg++)for(rn=0;rn<32;rn++)for(op=0;op<16;op++){cdisasm_arm_instruction i;uint32_t w=0xc4200000u|(f<<13)|(s<<22)|(zm<<16)|(pg<<10)|(rn<<5)|op;
#if USE_EXTRA_OPCODES
cdisasm_arm_operand h={0},p={0},m={0};E(D(w,CDISASM_ARM_CPU_ANY,&i)==4);E(i.name_id==ns[f]&&i.form_id==3395u+f);E(i.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)&&i.operand_count==3);h.type=CDISASM_OPERAND_IMMEDIATE;h.imm=op;h.size=1;h.access=CDISASM_OPERAND_ACCESS_READ;p.type=CDISASM_ARM_OPERAND_PREDICATE;p.reg=CDISASM_ARM_REG_P0+pg;p.extend_type=1u<<f;p.access=CDISASM_OPERAND_ACCESS_READ;m.type=CDISASM_OPERAND_MEMORY;m.base_reg=rn==31?CDISASM_ARM_REG_SP:CDISASM_ARM_REG_X0+rn;m.index_reg=CDISASM_ARM_REG_Z0+zm;m.size=1u<<f;m.extend_type=s?CDISASM_ARM_EXTEND_SXTW:CDISASM_ARM_EXTEND_UXTW;m.scale=f;m.access=CDISASM_OPERAND_ACCESS_READ;E(!memcmp(&i.operand[0],&h,sizeof(h)));E(!memcmp(&i.operand[1],&p,sizeof(p)));E(!memcmp(&i.operand[2],&m,sizeof(m)));
#else
E(D(w,CDISASM_ARM_CPU_ANY,&i)==0&&Z(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}}
static void gates(void){cdisasm_arm_instruction i;E(D(0xc47d678fu,CDISASM_ARM_CPU_CORTEX_A53,&i)==0);
#if USE_EXTRA_OPCODES
E(Z(&i,CDISASM_STATUS_INVALID_INSTRUCTION));E(D(0xc47d678fu,CDISASM_ARM_CPU_FUJITSU_A64FX,&i)==4);
#if USE_DISASM_FORMAT
{char t[96];E(cdisasm_arm_format(&i,0,t,sizeof(t))==strlen("prfd #0xf, p1, [x28, z29.d, sxtw #0x3]"));E(!strcmp(t,"prfd #0xf, p1, [x28, z29.d, sxtw #0x3]"));i.operand[2].scale=2;E(cdisasm_arm_format(&i,0,t,sizeof(t))==0);}
#endif
#else
E(Z(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}
int main(void){domain();gates();if(fail)return fprintf(stderr,"%d failures\n",fail),1;puts("SVE 64-bit x32 gather-prefetch tests passed (4 exact leaves)");return 0;}
