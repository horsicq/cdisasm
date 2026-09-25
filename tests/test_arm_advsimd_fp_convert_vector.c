#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>

static int failures;
#define EXPECT(c) do { if (!(c)) { if (failures < 24) fprintf(stderr, \
    "%s:%d: expectation failed: %s\n", __FILE__, __LINE__, #c); ++failures; } } while (0)

static uint32_t decode(uint32_t w, cdisasm_arm_instruction *i)
{
    uint8_t b[4] = {(uint8_t)w,(uint8_t)(w>>8),(uint8_t)(w>>16),(uint8_t)(w>>24)};
    return cdisasm_arm_decode(CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        b, 4u, UINT64_C(0x1000), CDISASM_ARM_DECODE_OPTION_NONE, i);
}

static void test_domain(void)
{
    static const struct op { uint32_t base; cdisasm_arm_name_id name; uint16_t form; } ops[] = {
        {0x0e218800,CDISASM_ARM_NAME_FRINTN,6019},{0x0e219800,CDISASM_ARM_NAME_FRINTM,6020},
        {0x0e21d800,CDISASM_ARM_NAME_SCVTF,6024},{0x0ea18800,CDISASM_ARM_NAME_FRINTP,6031},
        {0x0ea19800,CDISASM_ARM_NAME_FRINTZ,6032},{0x0ea1b800,CDISASM_ARM_NAME_FCVTZS,6034},
        {0x2e218800,CDISASM_ARM_NAME_FRINTA,6051},{0x2e219800,CDISASM_ARM_NAME_FRINTX,6052},
        {0x2e21d800,CDISASM_ARM_NAME_UCVTF,6056},{0x2ea19800,CDISASM_ARM_NAME_FRINTI,6066},
        {0x2ea1b800,CDISASM_ARM_NAME_FCVTZU,6068}
    };
    unsigned o,a,rn,rd;
    for(o=0;o<sizeof(ops)/sizeof(ops[0]);++o) for(a=0;a<3;++a)
      for(rn=0;rn<32;++rn) for(rd=0;rd<32;++rd) {
        uint32_t ab=a==0?0:a==1?0x40000000u:0x40400000u;
        cdisasm_arm_instruction i; memset(&i,0xa5,sizeof(i));
#if USE_EXTRA_OPCODES
        EXPECT(decode(ops[o].base|ab|(rn<<5)|rd,&i)==4u);
        EXPECT(i.name_id==ops[o].name && i.form_id==ops[o].form);
        EXPECT(i.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SIMD|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
        EXPECT(i.operand_count==2u && i.operand[0].access==CDISASM_OPERAND_ACCESS_WRITE
            && i.operand[1].access==CDISASM_OPERAND_ACCESS_READ);
        EXPECT(i.operand[0].size==(a?16u:8u) && i.operand[0].extend_type==(a==2?8u:4u));
#else
        EXPECT(decode(ops[o].base|ab|(rn<<5)|rd,&i)==0u);
        EXPECT(i.last_error_id==CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
      }
}

static void test_fcvtl_and_format(void)
{
    unsigned sz,q,rn,rd;
    for(sz=0;sz<2;++sz) for(q=0;q<2;++q) for(rn=0;rn<32;++rn) for(rd=0;rd<32;++rd) {
        cdisasm_arm_instruction i; memset(&i,0xa5,sizeof(i));
#if USE_EXTRA_OPCODES
        EXPECT(decode(0x0e217800u|(sz<<22)|(q<<30)|(rn<<5)|rd,&i)==4u);
        EXPECT(i.name_id==CDISASM_ARM_NAME_FCVTL && i.form_id==6018);
        EXPECT(i.operand[0].size==16u && i.operand[0].extend_type==(sz?8u:4u));
        EXPECT(i.operand[1].size==(q?16u:8u) && i.operand[1].extend_type==(sz?4u:2u));
#else
        EXPECT(decode(0x0e217800u|(sz<<22)|(q<<30)|(rn<<5)|rd,&i)==0u);
#endif
    }
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    {
        cdisasm_arm_instruction i, forged; char text[64];
        EXPECT(decode(0x4e617862u,&i)==4u);
        EXPECT(cdisasm_arm_format(&i,0u,text,sizeof(text))==strlen("fcvtl2 v2.2d, v3.4s"));
        EXPECT(strcmp(text,"fcvtl2 v2.2d, v3.4s")==0);
        forged=i; forged.form_id=6019;
        EXPECT(cdisasm_arm_format(&forged,0u,text,sizeof(text))==0u);
    }
#endif
}

static void test_fp8_fcvtl(void)
{
    static const struct op { uint32_t base; cdisasm_arm_name_id name; uint16_t form; } ops[4] = {
        {0x2e217800,CDISASM_ARM_NAME_F1CVTL,6060},{0x2e617800,CDISASM_ARM_NAME_F2CVTL,6062},
        {0x2ea17800,CDISASM_ARM_NAME_BF1CVTL,6072},{0x2ee17800,CDISASM_ARM_NAME_BF2CVTL,6073}};
    unsigned o,q,rn,rd;
    for(o=0;o<4;++o) for(q=0;q<2;++q) for(rn=0;rn<32;++rn) for(rd=0;rd<32;++rd) {
        cdisasm_arm_instruction i; memset(&i,0xa5,sizeof(i));
#if USE_EXTRA_OPCODES
        EXPECT(decode(ops[o].base|(q<<30)|(rn<<5)|rd,&i)==4u);
        EXPECT(i.name_id==ops[o].name&&i.form_id==ops[o].form);
        EXPECT(i.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SIMD|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
        EXPECT(i.operand_count==2u&&i.operand[0].size==16u&&i.operand[0].extend_type==2u);
        EXPECT(i.operand[1].size==(q?16u:8u)&&i.operand[1].extend_type==1u);
#else
        EXPECT(decode(ops[o].base|(q<<30)|(rn<<5)|rd,&i)==0u);
#endif
    }
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    { cdisasm_arm_instruction i; char text[64]; EXPECT(decode(0x6e217820u,&i)==4u);
      EXPECT(cdisasm_arm_format(&i,0u,text,sizeof(text))==strlen("f1cvtl2 v0.8h, v1.16b"));
      EXPECT(strcmp(text,"f1cvtl2 v0.8h, v1.16b")==0); }
#endif
}

int main(void) { test_domain(); test_fcvtl_and_format(); test_fp8_fcvtl(); return failures!=0; }
