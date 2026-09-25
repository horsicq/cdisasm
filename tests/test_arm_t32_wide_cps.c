#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>
static int failures;
#define E(c) do{if(!(c)){if(failures<20)fprintf(stderr,"%d: %s\n",__LINE__,#c);failures++;}}while(0)
static uint32_t dec(uint32_t w,cdisasm_arm_cpu_id cpu,cdisasm_arm_instruction*i){uint8_t b[4]={(uint8_t)(w>>16),(uint8_t)(w>>24),(uint8_t)w,(uint8_t)(w>>8)};return cdisasm_arm_decode(cpu,CDISASM_ARM_MODE_T32,b,4,0,0,i);}
int main(void){unsigned ctl,lo;for(ctl=0;ctl<4;ctl++)for(lo=0;lo<256;lo++){uint32_t w=UINT32_C(0xf3af8400)|(ctl<<8)|lo;cdisasm_arm_instruction i;int cm=ctl&1;
#if USE_EXTRA_OPCODES
 if(!cm&&(lo&31)){E(dec(w,CDISASM_ARM_CPU_ANY,&i)==0);E(i.last_error_id==CDISASM_STATUS_INVALID_INSTRUCTION);continue;}
 E(dec(w,CDISASM_ARM_CPU_ANY,&i)==4);E(i.name_id==((ctl&2)?CDISASM_ARM_NAME_CPSID:CDISASM_ARM_NAME_CPSIE));E(i.form_id==((ctl&2)?(cm?1838u:1837u):(cm?1840u:1839u)));E(i.opcode_groups==CDISASM_GROUP_PRIVILEGED);E(i.operand_count==(cm?2u:1u));E(i.operand[0].imm==((lo>>5)&7));if(cm)E(i.operand[1].imm==(lo&31));
#else
 E(dec(w,CDISASM_ARM_CPU_ANY,&i)==0);E(i.last_error_id==(uint8_t)(!cm&&(lo&31)?CDISASM_STATUS_INVALID_INSTRUCTION:CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
{cdisasm_arm_instruction i;char t[64];E(dec(UINT32_C(0xf3af86e0),CDISASM_ARM_CPU_ANY,&i)==4);E(cdisasm_arm_format(&i,0,t,sizeof(t))!=0);E(strcmp(t,"cpsid aif")==0);E(dec(UINT32_C(0xf3af8753),CDISASM_ARM_CPU_ANY,&i)==4);E(cdisasm_arm_format(&i,0,t,sizeof(t))!=0);E(strcmp(t,"cpsid i, #0x13")==0);i.form_id=1837;E(cdisasm_arm_format(&i,0,t,sizeof(t))==0);}
#endif
if(failures)return fprintf(stderr,"%d T32 CPS failures\n",failures),1;puts("ARM T32 wide CPS tests passed (4 exact leaves; exhaustive controls)");return 0;}
