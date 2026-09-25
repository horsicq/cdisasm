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
    {UINT32_C(0xa4006000),CDISASM_ARM_NAME_LDFF1B,3293u,1u,1u},
    {UINT32_C(0xa4206000),CDISASM_ARM_NAME_LDFF1B,3294u,2u,1u},
    {UINT32_C(0xa4406000),CDISASM_ARM_NAME_LDFF1B,3295u,4u,1u},
    {UINT32_C(0xa4606000),CDISASM_ARM_NAME_LDFF1B,3296u,8u,1u},
    {UINT32_C(0xa4806000),CDISASM_ARM_NAME_LDFF1SW,3297u,8u,4u},
    {UINT32_C(0xa4a06000),CDISASM_ARM_NAME_LDFF1H,3298u,2u,2u},
    {UINT32_C(0xa4c06000),CDISASM_ARM_NAME_LDFF1H,3299u,4u,2u},
    {UINT32_C(0xa4e06000),CDISASM_ARM_NAME_LDFF1H,3300u,8u,2u},
    {UINT32_C(0xa5006000),CDISASM_ARM_NAME_LDFF1SH,3301u,8u,2u},
    {UINT32_C(0xa5206000),CDISASM_ARM_NAME_LDFF1SH,3302u,4u,2u},
    {UINT32_C(0xa5406000),CDISASM_ARM_NAME_LDFF1W,3303u,4u,4u},
    {UINT32_C(0xa5606000),CDISASM_ARM_NAME_LDFF1W,3304u,8u,4u},
    {UINT32_C(0xa5806000),CDISASM_ARM_NAME_LDFF1SB,3305u,8u,1u},
    {UINT32_C(0xa5a06000),CDISASM_ARM_NAME_LDFF1SB,3306u,4u,1u},
    {UINT32_C(0xa5c06000),CDISASM_ARM_NAME_LDFF1SB,3307u,2u,1u},
    {UINT32_C(0xa5e06000),CDISASM_ARM_NAME_LDFF1D,3308u,8u,8u}
};
static int failures;
#define EXPECT(c) do{if(!(c)){if(failures<20)fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#c);++failures;}}while(0)
static uint32_t dw(uint32_t w,cdisasm_arm_cpu_id cpu,cdisasm_arm_instruction*i){uint8_t b[4]={(uint8_t)w,(uint8_t)(w>>8),(uint8_t)(w>>16),(uint8_t)(w>>24)};memset(i,0xa5,sizeof(*i));return cdisasm_arm_decode(cpu,CDISASM_ARM_MODE_A64,b,4,UINT64_C(0x18000),CDISASM_ARM_DECODE_OPTION_NONE,i);}
static int error_only(const cdisasm_arm_instruction*i,cdisasm_status s){cdisasm_arm_instruction z;memset(&z,0,sizeof(z));z.last_error_id=(uint8_t)s;return memcmp(i,&z,sizeof(z))==0;}
static void exhaustive(void){for(unsigned f=0;f<sizeof(forms)/sizeof(forms[0]);f++)for(unsigned xm=0;xm<32;xm++)for(unsigned pg=0;pg<8;pg++)for(unsigned rn=0;rn<32;rn++)for(unsigned zt=0;zt<32;zt++){const desc*d=&forms[f];cdisasm_arm_instruction i;uint32_t w=d->value|(xm<<16)|(pg<<10)|(rn<<5)|zt;uint32_t n=dw(w,CDISASM_ARM_CPU_ANY,&i);
#if USE_EXTRA_OPCODES
 EXPECT(n==4);EXPECT(i.name_id==d->name);EXPECT(i.form_id==d->form);EXPECT(i.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));EXPECT(i.operand_count==3);EXPECT(i.operand[0].type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);EXPECT(i.operand[0].reg==CDISASM_ARM_REG_Z0+zt);EXPECT(i.operand[0].register_list==UINT16_C(0x0101));EXPECT(i.operand[0].extend_type==d->destination_size);EXPECT(i.operand[0].access==CDISASM_OPERAND_ACCESS_WRITE);EXPECT(i.operand[1].type==CDISASM_ARM_OPERAND_PREDICATE);EXPECT(i.operand[1].reg==CDISASM_ARM_REG_P0+pg);EXPECT(i.operand[1].extend_type==d->destination_size);EXPECT(i.operand[1].flags==CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO);EXPECT(i.operand[1].access==CDISASM_OPERAND_ACCESS_READ);EXPECT(i.operand[2].type==CDISASM_OPERAND_MEMORY);EXPECT(i.operand[2].base_reg==(rn==31?CDISASM_ARM_REG_SP:CDISASM_ARM_REG_X0+rn));EXPECT(i.operand[2].index_reg==(xm==31?CDISASM_ARM_REG_NONE:CDISASM_ARM_REG_X0+xm));EXPECT(i.operand[2].size==d->memory_size);EXPECT(i.operand[2].shift_type==(xm==31||d->memory_size==1?CDISASM_ARM_SHIFT_NONE:CDISASM_ARM_SHIFT_LSL));EXPECT(i.operand[2].shift_amount==(xm==31||d->memory_size==1?0:d->memory_size==2?1:d->memory_size==4?2:3));EXPECT(i.operand[2].access==CDISASM_OPERAND_ACCESS_READ);
#else
 EXPECT(n==0);EXPECT(error_only(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
 }}
static void gates_format(void){cdisasm_arm_instruction i;EXPECT(dw(UINT32_C(0xa4006000),CDISASM_ARM_CPU_CORTEX_A53,&i)==0);
#if USE_EXTRA_OPCODES
 EXPECT(error_only(&i,CDISASM_STATUS_INVALID_INSTRUCTION));EXPECT(dw(UINT32_C(0xa4006000),CDISASM_ARM_CPU_APPLE_M4,&i)==0);EXPECT(error_only(&i,CDISASM_STATUS_INVALID_INSTRUCTION));EXPECT(dw(UINT32_C(0xa4006000),CDISASM_ARM_CPU_FUJITSU_A64FX,&i)==4);
#else
 EXPECT(error_only(&i,CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
 static const struct{uint32_t w;const char*t;}v[]={{UINT32_C(0xa41f6000),"ldff1b {z0.b}, p0/z, [x0]"},{UINT32_C(0xa48468a4),"ldff1sw {z4.d}, p2/z, [x5, x4, lsl #0x2]"},{UINT32_C(0xa5f47ff3),"ldff1d {z19.d}, p7/z, [sp, x20, lsl #0x3]"}};for(unsigned k=0;k<sizeof(v)/sizeof(v[0]);k++){char t[96];EXPECT(dw(v[k].w,CDISASM_ARM_CPU_ANY,&i)==4);EXPECT(cdisasm_arm_format(&i,0,t,sizeof(t))==strlen(v[k].t));EXPECT(strcmp(t,v[k].t)==0);}
 {char t[96];cdisasm_arm_instruction bad;EXPECT(dw(UINT32_C(0xa48468a4),CDISASM_ARM_CPU_ANY,&i)==4);bad=i;bad.form_id=3296u;EXPECT(cdisasm_arm_format(&bad,0,t,sizeof(t))==0);bad=i;bad.name_id=CDISASM_ARM_NAME_LD1SW;EXPECT(cdisasm_arm_format(&bad,0,t,sizeof(t))==0);bad=i;bad.operand[2].shift_amount=1u;EXPECT(cdisasm_arm_format(&bad,0,t,sizeof(t))==0);bad=i;bad.operand[2].index_reg=CDISASM_ARM_REG_NONE;EXPECT(cdisasm_arm_format(&bad,0,t,sizeof(t))==0);}
#endif
}
int main(void){exhaustive();gates_format();if(failures)fprintf(stderr,"%d first-fault load failures\n",failures);else puts("SVE first-fault contiguous-load tests passed (16 exact leaves)");return failures?1:0;}
