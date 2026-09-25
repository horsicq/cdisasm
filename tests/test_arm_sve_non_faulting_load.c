#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
# include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>

typedef struct desc { uint32_t value; cdisasm_arm_name_id name;
    cdisasm_arm_form_id form; uint8_t destination_size, memory_size; } desc;
static const desc forms[] = {
    {UINT32_C(0xa410a000),CDISASM_ARM_NAME_LDNF1B,3330u,1u,1u},
    {UINT32_C(0xa430a000),CDISASM_ARM_NAME_LDNF1B,3331u,2u,1u},
    {UINT32_C(0xa450a000),CDISASM_ARM_NAME_LDNF1B,3332u,4u,1u},
    {UINT32_C(0xa470a000),CDISASM_ARM_NAME_LDNF1B,3333u,8u,1u},
    {UINT32_C(0xa490a000),CDISASM_ARM_NAME_LDNF1SW,3334u,8u,4u},
    {UINT32_C(0xa4b0a000),CDISASM_ARM_NAME_LDNF1H,3335u,2u,2u},
    {UINT32_C(0xa4d0a000),CDISASM_ARM_NAME_LDNF1H,3336u,4u,2u},
    {UINT32_C(0xa4f0a000),CDISASM_ARM_NAME_LDNF1H,3337u,8u,2u},
    {UINT32_C(0xa510a000),CDISASM_ARM_NAME_LDNF1SH,3338u,8u,2u},
    {UINT32_C(0xa530a000),CDISASM_ARM_NAME_LDNF1SH,3339u,4u,2u},
    {UINT32_C(0xa550a000),CDISASM_ARM_NAME_LDNF1W,3340u,4u,4u},
    {UINT32_C(0xa570a000),CDISASM_ARM_NAME_LDNF1W,3341u,8u,4u},
    {UINT32_C(0xa590a000),CDISASM_ARM_NAME_LDNF1SB,3342u,8u,1u},
    {UINT32_C(0xa5b0a000),CDISASM_ARM_NAME_LDNF1SB,3343u,4u,1u},
    {UINT32_C(0xa5d0a000),CDISASM_ARM_NAME_LDNF1SB,3344u,2u,1u},
    {UINT32_C(0xa5f0a000),CDISASM_ARM_NAME_LDNF1D,3345u,8u,8u}
};
static int failures;
#define EXPECT(c) do{if(!(c)){if(failures<20)fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#c);++failures;}}while(0)
static uint32_t dw(uint32_t w,cdisasm_arm_cpu_id cpu,cdisasm_arm_instruction*i){uint8_t b[4]={(uint8_t)w,(uint8_t)(w>>8),(uint8_t)(w>>16),(uint8_t)(w>>24)};memset(i,0xa5,sizeof(*i));return cdisasm_arm_decode(cpu,CDISASM_ARM_MODE_A64,b,4,UINT64_C(0x19000),CDISASM_ARM_DECODE_OPTION_NONE,i);}
static int error_only(const cdisasm_arm_instruction*i,cdisasm_status s){cdisasm_arm_instruction z;memset(&z,0,sizeof(z));z.last_error_id=(uint8_t)s;return memcmp(i,&z,sizeof(z))==0;}
static void exhaustive(void){for(unsigned f=0;f<sizeof(forms)/sizeof(forms[0]);f++)for(unsigned imm=0;imm<16;imm++)for(unsigned pg=0;pg<8;pg++)for(unsigned rn=0;rn<32;rn++)for(unsigned zt=0;zt<32;zt++){const desc*d=&forms[f];cdisasm_arm_instruction i;int64_t disp=imm<8?(int64_t)imm:(int64_t)imm-16;uint32_t w=d->value|(imm<<16)|(pg<<10)|(rn<<5)|zt;uint32_t n=dw(w,CDISASM_ARM_CPU_ANY,&i);
#if USE_EXTRA_OPCODES
 EXPECT(n==4);EXPECT(i.name_id==d->name);EXPECT(i.form_id==d->form);EXPECT(i.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));EXPECT(i.operand_count==3);EXPECT(i.operand[0].type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);EXPECT(i.operand[0].reg==CDISASM_ARM_REG_Z0+zt);EXPECT(i.operand[0].register_list==UINT16_C(0x0101));EXPECT(i.operand[0].extend_type==d->destination_size);EXPECT(i.operand[0].access==CDISASM_OPERAND_ACCESS_WRITE);EXPECT(i.operand[1].type==CDISASM_ARM_OPERAND_PREDICATE);EXPECT(i.operand[1].reg==CDISASM_ARM_REG_P0+pg);EXPECT(i.operand[1].extend_type==d->destination_size);EXPECT(i.operand[1].flags==CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO);EXPECT(i.operand[1].access==CDISASM_OPERAND_ACCESS_READ);EXPECT(i.operand[2].type==CDISASM_OPERAND_MEMORY);EXPECT(i.operand[2].base_reg==(rn==31?CDISASM_ARM_REG_SP:CDISASM_ARM_REG_X0+rn));EXPECT((int64_t)i.operand[2].imm==disp);EXPECT(i.operand[2].size==d->memory_size);EXPECT(i.operand[2].flags==(disp==0?0:(CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT|CDISASM_ARM_OPERAND_FLAG_VL_SCALED|(disp<0?CDISASM_OPERAND_FLAG_SIGNED:0))));EXPECT(i.operand[2].access==CDISASM_OPERAND_ACCESS_READ);
#else
 (void)disp;EXPECT(n==0);EXPECT(error_only(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
 }}
static void gates_format(void){cdisasm_arm_instruction i;EXPECT(dw(UINT32_C(0xa410a000),CDISASM_ARM_CPU_CORTEX_A53,&i)==0);
#if USE_EXTRA_OPCODES
 EXPECT(error_only(&i,CDISASM_STATUS_INVALID_INSTRUCTION));EXPECT(dw(UINT32_C(0xa410a000),CDISASM_ARM_CPU_APPLE_M4,&i)==0);EXPECT(error_only(&i,CDISASM_STATUS_INVALID_INSTRUCTION));EXPECT(dw(UINT32_C(0xa410a000),CDISASM_ARM_CPU_FUJITSU_A64FX,&i)==4);
#else
 EXPECT(error_only(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
 static const struct{uint32_t w;const char*t;}v[]={{UINT32_C(0xa410a000),"ldnf1b {z0.b}, p0/z, [x0]"},{UINT32_C(0xa497a862),"ldnf1sw {z2.d}, p2/z, [x3, #0x7, mul vl]"},{UINT32_C(0xa5f1bd8b),"ldnf1d {z11.d}, p7/z, [x12, #0x1, mul vl]"}};for(unsigned k=0;k<sizeof(v)/sizeof(v[0]);k++){char t[96];EXPECT(dw(v[k].w,CDISASM_ARM_CPU_ANY,&i)==4);EXPECT(cdisasm_arm_format(&i,0,t,sizeof(t))==strlen(v[k].t));EXPECT(strcmp(t,v[k].t)==0);}
 {char t[96];cdisasm_arm_instruction bad;EXPECT(dw(UINT32_C(0xa497a862),CDISASM_ARM_CPU_ANY,&i)==4);bad=i;bad.form_id=3333u;EXPECT(cdisasm_arm_format(&bad,0,t,sizeof(t))==0);bad=i;bad.name_id=CDISASM_ARM_NAME_LD1SW;EXPECT(cdisasm_arm_format(&bad,0,t,sizeof(t))==0);bad=i;bad.operand[2].flags=0u;EXPECT(cdisasm_arm_format(&bad,0,t,sizeof(t))==0);}
#endif
}
int main(void){exhaustive();gates_format();if(failures)fprintf(stderr,"%d non-faulting load failures\n",failures);else puts("SVE non-faulting contiguous-load tests passed (16 exact leaves)");return failures?1:0;}
