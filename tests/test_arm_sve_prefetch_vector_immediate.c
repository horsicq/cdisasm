#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
# include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>

#if USE_EXTRA_OPCODES
static const cdisasm_arm_name_id names[4] = {
    CDISASM_ARM_NAME_PRFB, CDISASM_ARM_NAME_PRFH,
    CDISASM_ARM_NAME_PRFW, CDISASM_ARM_NAME_PRFD
};
#endif
static int failures;
#define E(c) do { if (!(c)) { if (failures < 20) fprintf(stderr, \
    "%d: %s\n", __LINE__, #c); ++failures; } } while (0)
static uint32_t dw(uint32_t w, cdisasm_arm_cpu_id cpu,
    cdisasm_arm_instruction *i)
{ uint8_t b[4]={(uint8_t)w,(uint8_t)(w>>8),(uint8_t)(w>>16),(uint8_t)(w>>24)};
  memset(i,0xa5,sizeof(*i));return cdisasm_arm_decode(cpu,CDISASM_ARM_MODE_A64,
    b,4u,0,CDISASM_ARM_DECODE_OPTION_NONE,i); }
static int eo(const cdisasm_arm_instruction*i,cdisasm_status s)
{ cdisasm_arm_instruction z;memset(&z,0,sizeof(z));z.last_error_id=(uint8_t)s;
  return memcmp(i,&z,sizeof(z))==0; }

static void domains(void)
{
    unsigned sz,imm,pg,zn,hint;
    for(sz=0;sz<4;sz++)for(imm=0;imm<32;imm++)for(pg=0;pg<8;pg++)
    for(zn=0;zn<32;zn++)for(hint=0;hint<16;hint++) {
        uint32_t w=UINT32_C(0x8400e000)|(sz<<23)|(imm<<16)|(pg<<10)
            |(zn<<5)|hint;cdisasm_arm_instruction i;uint32_t n=dw(w,CDISASM_ARM_CPU_ANY,&i);
#if USE_EXTRA_OPCODES
        uint8_t size=(uint8_t)(1u<<sz);uint64_t disp=imm*size;
        cdisasm_arm_operand h={0},p={0},m={0};E(n==4);E(i.name_id==names[sz]);
        E(i.form_id==3229u+sz);E(i.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));E(i.operand_count==3);
        h.type=CDISASM_OPERAND_IMMEDIATE;h.imm=hint;h.size=1;h.access=CDISASM_OPERAND_ACCESS_READ;
        p.type=CDISASM_ARM_OPERAND_PREDICATE;p.reg=CDISASM_ARM_REG_P0+pg;p.extend_type=size;p.access=CDISASM_OPERAND_ACCESS_READ;
        m.type=CDISASM_OPERAND_MEMORY;m.base_reg=CDISASM_ARM_REG_Z0+zn;m.size=size;m.imm=disp;m.access=CDISASM_OPERAND_ACCESS_READ;if(disp)m.flags=CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;
        E(memcmp(&i.operand[0],&h,sizeof(h))==0);E(memcmp(&i.operand[1],&p,sizeof(p))==0);E(memcmp(&i.operand[2],&m,sizeof(m))==0);
#else
        E(n==0);E(eo(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

static void gates_format(void)
{
    cdisasm_arm_instruction i;E(dw(UINT32_C(0x849feca3),CDISASM_ARM_CPU_CORTEX_A53,&i)==0);
#if USE_EXTRA_OPCODES
    E(eo(&i,CDISASM_STATUS_INVALID_INSTRUCTION));E(dw(UINT32_C(0x849feca3),CDISASM_ARM_CPU_FUJITSU_A64FX,&i)==4);
#if USE_DISASM_FORMAT
    {char t[96];E(cdisasm_arm_format(&i,0,t,sizeof(t))==strlen("prfh pldl2strm, p3, [z5.s, #0x3e]"));E(strcmp(t,"prfh pldl2strm, p3, [z5.s, #0x3e]")==0);i.operand[2].imm=61;E(cdisasm_arm_format(&i,0,t,sizeof(t))==0);}
#endif
#else
    E(eo(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}
int main(void){domains();gates_format();if(failures)return fprintf(stderr,"%d failures\n",failures),1;puts("SVE vector-immediate prefetch tests passed (4 exact leaves)");return 0;}
