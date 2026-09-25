#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
# include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>
typedef struct F{uint32_t v;cdisasm_arm_name_id n;cdisasm_arm_form_id f;uint8_t s;}F;
#if USE_EXTRA_OPCODES
static const F fs[10]={{0xc4208000u,CDISASM_ARM_NAME_LD1SB,3421u,1u},{0xc4a08000u,CDISASM_ARM_NAME_LD1SH,3422u,2u},{0xc5208000u,CDISASM_ARM_NAME_LD1SW,3423u,4u},{0xc420a000u,CDISASM_ARM_NAME_LDFF1SB,3428u,1u},{0xc4a0a000u,CDISASM_ARM_NAME_LDFF1SH,3429u,2u},{0xc520a000u,CDISASM_ARM_NAME_LDFF1SW,3430u,4u},{0xc5a0e000u,CDISASM_ARM_NAME_LDFF1D,3431u,8u},{0xc420e000u,CDISASM_ARM_NAME_LDFF1B,3432u,1u},{0xc4a0e000u,CDISASM_ARM_NAME_LDFF1H,3433u,2u},{0xc520e000u,CDISASM_ARM_NAME_LDFF1W,3434u,4u}};
#endif
static int failures;
#define E(c) do{if(!(c)){if(failures<20)fprintf(stderr,"%d: %s\n",__LINE__,#c);++failures;}}while(0)
static uint32_t dw(uint32_t w,cdisasm_arm_cpu_id cpu,cdisasm_arm_instruction*i){uint8_t b[4]={(uint8_t)w,(uint8_t)(w>>8),(uint8_t)(w>>16),(uint8_t)(w>>24)};memset(i,0xa5,sizeof(*i));return cdisasm_arm_decode(cpu,CDISASM_ARM_MODE_A64,b,4u,0,CDISASM_ARM_DECODE_OPTION_NONE,i);}
static int eo(const cdisasm_arm_instruction*i,cdisasm_status s){cdisasm_arm_instruction z;memset(&z,0,sizeof(z));z.last_error_id=(uint8_t)s;return memcmp(i,&z,sizeof(z))==0;}
static void domains(void){unsigned f,imm,pg,zn,zt;for(f=0;f<10;f++)for(imm=0;imm<32;imm++)for(pg=0;pg<8;pg++)for(zn=0;zn<32;zn++)for(zt=0;zt<32;zt++){cdisasm_arm_instruction i;
#if USE_EXTRA_OPCODES
uint32_t w=fs[f].v|(imm<<16)|(pg<<10)|(zn<<5)|zt;uint64_t disp=imm*fs[f].s;cdisasm_arm_operand d={0},p={0},m={0};E(dw(w,CDISASM_ARM_CPU_ANY,&i)==4u);E(i.name_id==fs[f].n);E(i.form_id==fs[f].f);E(i.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));E(i.operand_count==3u);d.type=CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST;d.reg=CDISASM_ARM_REG_Z0+zt;d.register_list=UINT16_C(0x0101);d.extend_type=8u;d.access=CDISASM_OPERAND_ACCESS_WRITE;p.type=CDISASM_ARM_OPERAND_PREDICATE;p.reg=CDISASM_ARM_REG_P0+pg;p.flags=CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO;p.extend_type=8u;p.access=CDISASM_OPERAND_ACCESS_READ;m.type=CDISASM_OPERAND_MEMORY;m.base_reg=CDISASM_ARM_REG_Z0+zn;m.size=fs[f].s;m.imm=disp;m.access=CDISASM_OPERAND_ACCESS_READ;if(disp)m.flags=CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;E(memcmp(&i.operand[0],&d,sizeof(d))==0);E(memcmp(&i.operand[1],&p,sizeof(p))==0);E(memcmp(&i.operand[2],&m,sizeof(m))==0);
#else
uint32_t w=UINT32_C(0xc4208000)|(imm<<16)|(pg<<10)|(zn<<5)|zt;E(dw(w,CDISASM_ARM_CPU_ANY,&i)==0u);E(eo(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}}
static void gates_format(void){cdisasm_arm_instruction i;E(dw(UINT32_C(0xc53fe672),CDISASM_ARM_CPU_CORTEX_A53,&i)==0u);
#if USE_EXTRA_OPCODES
E(eo(&i,CDISASM_STATUS_INVALID_INSTRUCTION));E(dw(UINT32_C(0xc53fe672),CDISASM_ARM_CPU_FUJITSU_A64FX,&i)==4u);
#if USE_DISASM_FORMAT
{char t[96];E(cdisasm_arm_format(&i,0,t,sizeof(t))==strlen("ldff1w {z18.d}, p1/z, [z19.d, #0x7c]"));E(strcmp(t,"ldff1w {z18.d}, p1/z, [z19.d, #0x7c]")==0);i.operand[2].imm=123u;E(cdisasm_arm_format(&i,0,t,sizeof(t))==0u);}
#endif
#else
E(eo(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}
int main(void){domains();gates_format();if(failures)return fprintf(stderr,"%d failures\n",failures),1;puts("SVE 64-bit vector-immediate gather-load tests passed (10 exact leaves)");return 0;}
