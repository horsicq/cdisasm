#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>
static int failures;
#define EXPECT(c) do { if(!(c)){if(failures<24)fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#c);++failures;} } while(0)
static uint32_t decode(uint32_t w,cdisasm_arm_cpu_id cpu,cdisasm_arm_instruction*i){uint8_t b[4]={(uint8_t)w,(uint8_t)(w>>8),(uint8_t)(w>>16),(uint8_t)(w>>24)};return cdisasm_arm_decode(cpu,CDISASM_ARM_MODE_A64,b,4,0x1000,CDISASM_ARM_DECODE_OPTION_NONE,i);}
static void test_by_element(void){static const uint32_t b[4]={0x0f800000,0x0f804000,0x2f808000,0x2f80c000};static const cdisasm_arm_name_id n[4]={CDISASM_ARM_NAME_FMLAL,CDISASM_ARM_NAME_FMLSL,CDISASM_ARM_NAME_FMLAL2,CDISASM_ARM_NAME_FMLSL2};static const uint16_t f[4]={6264,6265,6279,6280};unsigned o,q,l,rm,rn,rd;
#if !USE_EXTRA_OPCODES
 (void)n;(void)f;
#endif
 for(o=0;o<4;++o)for(q=0;q<2;++q)for(l=0;l<8;++l)for(rm=0;rm<16;++rm)for(rn=0;rn<32;++rn)for(rd=0;rd<32;++rd){uint32_t w=b[o]|(q<<30)|(rm<<16)|((l&1)<<20)|((l&2)<<20)|((l&4)<<9)|(rn<<5)|rd;cdisasm_arm_instruction i;memset(&i,0xa5,sizeof(i));
#if USE_EXTRA_OPCODES
 EXPECT(decode(w,CDISASM_ARM_CPU_ANY,&i)==4);EXPECT(i.name_id==n[o]&&i.form_id==f[o]);EXPECT(i.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SIMD|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));EXPECT(i.operand_count==3&&i.operand[0].access==CDISASM_OPERAND_ACCESS_READ_WRITE);EXPECT(i.operand[0].size==(q?16:8)&&i.operand[0].extend_type==4);EXPECT(i.operand[1].size==(q?8:4)&&i.operand[1].extend_type==2);EXPECT(i.operand[2].reg==CDISASM_ARM_REG_V0+rm&&i.operand[2].extend_type==2&&i.operand[2].imm==l&&i.operand[2].flags==CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
#else
 EXPECT(decode(w,CDISASM_ARM_CPU_ANY,&i)==0&&i.last_error_id==CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
 }
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
 {cdisasm_arm_instruction i;char s[80];EXPECT(decode(0x6fbec9ac,CDISASM_ARM_CPU_ANY,&i)==4);EXPECT(cdisasm_arm_format(&i,0,s,sizeof(s))==strlen("fmlsl2 v12.4s, v13.4h, v14.h[7]"));EXPECT(strcmp(s,"fmlsl2 v12.4s, v13.4h, v14.h[7]")==0);}
#endif
}
int main(void){static const uint32_t bases[4]={0x0e20ec00,0x0ea0ec00,0x2e20cc00,0x2ea0cc00};static const cdisasm_arm_name_id names[4]={CDISASM_ARM_NAME_FMLAL,CDISASM_ARM_NAME_FMLSL,CDISASM_ARM_NAME_FMLAL2,CDISASM_ARM_NAME_FMLSL2};static const uint16_t forms[4]={6146,6155,6187,6197};unsigned o,q,rm,rn,rd;
#if !USE_EXTRA_OPCODES
 (void)names;(void)forms;
#endif
 for(o=0;o<4;++o)for(q=0;q<2;++q)for(rm=0;rm<32;++rm)for(rn=0;rn<32;++rn)for(rd=0;rd<32;++rd){uint32_t w=bases[o]|(q<<30)|(rm<<16)|(rn<<5)|rd;cdisasm_arm_instruction i;memset(&i,0xa5,sizeof(i));
#if USE_EXTRA_OPCODES
 EXPECT(decode(w,CDISASM_ARM_CPU_ANY,&i)==4);EXPECT(i.name_id==names[o]&&i.form_id==forms[o]);EXPECT(i.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SIMD|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));EXPECT(i.operand_count==3&&i.operand[0].access==CDISASM_OPERAND_ACCESS_READ_WRITE&&i.operand[1].access==CDISASM_OPERAND_ACCESS_READ&&i.operand[2].access==CDISASM_OPERAND_ACCESS_READ);EXPECT(i.operand[0].size==(q?16:8)&&i.operand[0].extend_type==4);EXPECT(i.operand[1].size==(q?8:4)&&i.operand[1].extend_type==2&&i.operand[2].size==(q?8:4)&&i.operand[2].extend_type==2);
#else
 EXPECT(decode(w,CDISASM_ARM_CPU_ANY,&i)==0&&i.last_error_id==CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
 }
#if USE_EXTRA_OPCODES
 {cdisasm_arm_instruction i;EXPECT(decode(0x0e22ec20,CDISASM_ARM_CPU_CORTEX_A53,&i)==0);}
#if USE_DISASM_FORMAT
 {cdisasm_arm_instruction i,f;char s[64];EXPECT(decode(0x4e22ec20,CDISASM_ARM_CPU_ANY,&i)==4);EXPECT(cdisasm_arm_format(&i,0,s,sizeof(s))==strlen("fmlal v0.4s, v1.4h, v2.4h"));EXPECT(strcmp(s,"fmlal v0.4s, v1.4h, v2.4h")==0);f=i;f.operand[1].size=16;EXPECT(cdisasm_arm_format(&f,0,s,sizeof(s))==0);}
#endif
#endif
 test_by_element();return failures!=0;}
