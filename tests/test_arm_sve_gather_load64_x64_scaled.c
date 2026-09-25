#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
# include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>
typedef struct F{uint32_t v;cdisasm_arm_name_id n;cdisasm_arm_form_id f;uint8_t s,h;}F;
#if USE_EXTRA_OPCODES
static const F fs[10]={{0xc4e08000u,CDISASM_ARM_NAME_LD1SH,3453u,2u,1u},{0xc5608000u,CDISASM_ARM_NAME_LD1SW,3454u,4u,2u},{0xc5e0c000u,CDISASM_ARM_NAME_LD1D,3455u,8u,3u},{0xc4e0c000u,CDISASM_ARM_NAME_LD1H,3456u,2u,1u},{0xc560c000u,CDISASM_ARM_NAME_LD1W,3457u,4u,2u},{0xc4e0a000u,CDISASM_ARM_NAME_LDFF1SH,3458u,2u,1u},{0xc560a000u,CDISASM_ARM_NAME_LDFF1SW,3459u,4u,2u},{0xc5e0e000u,CDISASM_ARM_NAME_LDFF1D,3460u,8u,3u},{0xc4e0e000u,CDISASM_ARM_NAME_LDFF1H,3461u,2u,1u},{0xc560e000u,CDISASM_ARM_NAME_LDFF1W,3462u,4u,2u}};
#endif
static int fails;
#define E(x) do{if(!(x)){if(fails<20)fprintf(stderr,"%d: %s\n",__LINE__,#x);fails++;}}while(0)
static uint32_t D(uint32_t w,cdisasm_arm_cpu_id c,cdisasm_arm_instruction*i){uint8_t b[4]={(uint8_t)w,(uint8_t)(w>>8),(uint8_t)(w>>16),(uint8_t)(w>>24)};memset(i,0xa5,sizeof(*i));return cdisasm_arm_decode(c,CDISASM_ARM_MODE_A64,b,4,0,CDISASM_ARM_DECODE_OPTION_NONE,i);}
static int Z(const cdisasm_arm_instruction*i,cdisasm_status s){cdisasm_arm_instruction z;memset(&z,0,sizeof(z));z.last_error_id=(uint8_t)s;return !memcmp(i,&z,sizeof(z));}
static void domain(void){unsigned f,zm,pg,rn,zt;for(f=0;f<10;f++)for(zm=0;zm<32;zm++)for(pg=0;pg<8;pg++)for(rn=0;rn<32;rn++)for(zt=0;zt<32;zt++){cdisasm_arm_instruction i;
#if USE_EXTRA_OPCODES
uint32_t w=fs[f].v|(zm<<16)|(pg<<10)|(rn<<5)|zt;cdisasm_arm_operand d={0},p={0},m={0};E(D(w,CDISASM_ARM_CPU_ANY,&i)==4);E(i.name_id==fs[f].n&&i.form_id==fs[f].f);E(i.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)&&i.operand_count==3);d.type=CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST;d.reg=CDISASM_ARM_REG_Z0+zt;d.register_list=0x0101;d.extend_type=8;d.access=CDISASM_OPERAND_ACCESS_WRITE;p.type=CDISASM_ARM_OPERAND_PREDICATE;p.reg=CDISASM_ARM_REG_P0+pg;p.flags=CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO;p.extend_type=8;p.access=CDISASM_OPERAND_ACCESS_READ;m.type=CDISASM_OPERAND_MEMORY;m.base_reg=rn==31?CDISASM_ARM_REG_SP:CDISASM_ARM_REG_X0+rn;m.index_reg=CDISASM_ARM_REG_Z0+zm;m.size=fs[f].s;m.shift_type=CDISASM_ARM_SHIFT_LSL;m.shift_amount=fs[f].h;m.access=CDISASM_OPERAND_ACCESS_READ;E(!memcmp(&i.operand[0],&d,sizeof(d)));E(!memcmp(&i.operand[1],&p,sizeof(p)));E(!memcmp(&i.operand[2],&m,sizeof(m)));
#else
uint32_t w=0xc4e08000u|(zm<<16)|(pg<<10)|(rn<<5)|zt;E(D(w,CDISASM_ARM_CPU_ANY,&i)==0&&Z(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}}
static void gates(void){cdisasm_arm_instruction i;E(D(0xc57de79bu,CDISASM_ARM_CPU_CORTEX_A53,&i)==0);
#if USE_EXTRA_OPCODES
E(Z(&i,CDISASM_STATUS_INVALID_INSTRUCTION));E(D(0xc57de79bu,CDISASM_ARM_CPU_FUJITSU_A64FX,&i)==4);
#if USE_DISASM_FORMAT
{char t[96];E(cdisasm_arm_format(&i,0,t,sizeof(t))==strlen("ldff1w {z27.d}, p1/z, [x28, z29.d, lsl #0x2]"));E(!strcmp(t,"ldff1w {z27.d}, p1/z, [x28, z29.d, lsl #0x2]"));i.operand[2].shift_amount=1;E(cdisasm_arm_format(&i,0,t,sizeof(t))==0);}
#endif
#else
E(Z(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}
int main(void){domain();gates();if(fails)return fprintf(stderr,"%d failures\n",fails),1;puts("SVE 64-bit x64-scaled gather-load tests passed (10 exact leaves)");return 0;}
