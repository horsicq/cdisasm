#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
# include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>
typedef struct F{uint32_t value;cdisasm_arm_name_id name;cdisasm_arm_form_id form;uint8_t size,scale;}F;
#if USE_EXTRA_OPCODES
static const F fs[7]={{0xc4a00000u,CDISASM_ARM_NAME_LD1SH,3399u,2u,1u},{0xc5200000u,CDISASM_ARM_NAME_LD1SW,3400u,4u,2u},{0xc4a02000u,CDISASM_ARM_NAME_LDFF1SH,3404u,2u,1u},{0xc5202000u,CDISASM_ARM_NAME_LDFF1SW,3405u,4u,2u},{0xc5a06000u,CDISASM_ARM_NAME_LDFF1D,3406u,8u,3u},{0xc4a06000u,CDISASM_ARM_NAME_LDFF1H,3407u,2u,1u},{0xc5206000u,CDISASM_ARM_NAME_LDFF1W,3408u,4u,2u}};
#endif
static int failures;
#define E(c) do{if(!(c)){if(failures<20)fprintf(stderr,"%d: %s\n",__LINE__,#c);++failures;}}while(0)
static uint32_t dw(uint32_t w,cdisasm_arm_cpu_id cpu,cdisasm_arm_instruction*i){uint8_t b[4]={(uint8_t)w,(uint8_t)(w>>8),(uint8_t)(w>>16),(uint8_t)(w>>24)};memset(i,0xa5,sizeof(*i));return cdisasm_arm_decode(cpu,CDISASM_ARM_MODE_A64,b,4u,0,CDISASM_ARM_DECODE_OPTION_NONE,i);}
static int eo(const cdisasm_arm_instruction*i,cdisasm_status s){cdisasm_arm_instruction z;memset(&z,0,sizeof(z));z.last_error_id=(uint8_t)s;return memcmp(i,&z,sizeof(z))==0;}
static void domains(void){unsigned f,s,zm,pg,rn,zt;for(f=0;f<7;f++)for(s=0;s<2;s++)for(zm=0;zm<32;zm++)for(pg=0;pg<8;pg++)for(rn=0;rn<32;rn++)for(zt=0;zt<32;zt++){cdisasm_arm_instruction i;
#if USE_EXTRA_OPCODES
uint32_t w=fs[f].value|(s<<22)|(zm<<16)|(pg<<10)|(rn<<5)|zt;cdisasm_arm_operand d={0},p={0},m={0};E(dw(w,CDISASM_ARM_CPU_ANY,&i)==4u);E(i.name_id==fs[f].name);E(i.form_id==fs[f].form);E(i.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));E(i.operand_count==3u);d.type=CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST;d.reg=CDISASM_ARM_REG_Z0+zt;d.register_list=UINT16_C(0x0101);d.extend_type=8u;d.access=CDISASM_OPERAND_ACCESS_WRITE;p.type=CDISASM_ARM_OPERAND_PREDICATE;p.reg=CDISASM_ARM_REG_P0+pg;p.flags=CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO;p.extend_type=8u;p.access=CDISASM_OPERAND_ACCESS_READ;m.type=CDISASM_OPERAND_MEMORY;m.base_reg=rn==31u?CDISASM_ARM_REG_SP:CDISASM_ARM_REG_X0+rn;m.index_reg=CDISASM_ARM_REG_Z0+zm;m.size=fs[f].size;m.extend_type=s?CDISASM_ARM_EXTEND_SXTW:CDISASM_ARM_EXTEND_UXTW;m.scale=fs[f].scale;m.access=CDISASM_OPERAND_ACCESS_READ;E(memcmp(&i.operand[0],&d,sizeof(d))==0);E(memcmp(&i.operand[1],&p,sizeof(p))==0);E(memcmp(&i.operand[2],&m,sizeof(m))==0);
#else
uint32_t w=UINT32_C(0xc4a00000)|(s<<22)|(zm<<16)|(pg<<10)|(rn<<5)|zt;E(dw(w,CDISASM_ARM_CPU_ANY,&i)==0u);E(eo(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}}
static void gates_format(void){cdisasm_arm_instruction i;E(dw(UINT32_C(0xc5347a72),CDISASM_ARM_CPU_CORTEX_A53,&i)==0u);
#if USE_EXTRA_OPCODES
E(eo(&i,CDISASM_STATUS_INVALID_INSTRUCTION));E(dw(UINT32_C(0xc5347a72),CDISASM_ARM_CPU_FUJITSU_A64FX,&i)==4u);
#if USE_DISASM_FORMAT
{char t[96];E(cdisasm_arm_format(&i,0,t,sizeof(t))==strlen("ldff1w {z18.d}, p6/z, [x19, z20.d, uxtw #0x2]"));E(strcmp(t,"ldff1w {z18.d}, p6/z, [x19, z20.d, uxtw #0x2]")==0);i.operand[2].scale=1u;E(cdisasm_arm_format(&i,0,t,sizeof(t))==0u);}
#endif
#else
E(eo(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}
int main(void){domains();gates_format();if(failures)return fprintf(stderr,"%d failures\n",failures),1;puts("SVE 64-bit x32-scaled gather-load tests passed (7 exact leaves)");return 0;}
