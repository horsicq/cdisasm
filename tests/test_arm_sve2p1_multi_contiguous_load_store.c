#include "test_decode_flags_adapter.h"
#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
# include "cdisasm/cdisasm_format.h"
#endif
#include <stdio.h>
#include <string.h>
static int failures;
#define EXPECT(c) do { if (!(c)) { if (failures < 20) fprintf(stderr, "%d: %s\n", __LINE__, #c); ++failures; } } while (0)
static uint32_t decode(uint32_t w, cdisasm_arm_cpu_id cpu, cdisasm_arm_instruction *i) {
    uint8_t b[4]={(uint8_t)w,(uint8_t)(w>>8),(uint8_t)(w>>16),(uint8_t)(w>>24)};
    return cdisasm_arm_decode(cpu,CDISASM_ARM_MODE_A64,b,4,0,CDISASM_ARM_DECODE_OPTION_NONE,i);
}
static void domains(void) {
#if USE_EXTRA_OPCODES
    static const cdisasm_arm_name_id ln[4]={CDISASM_ARM_NAME_LD1B,CDISASM_ARM_NAME_LD1H,CDISASM_ARM_NAME_LD1W,CDISASM_ARM_NAME_LD1D};
    static const cdisasm_arm_name_id sn[4]={CDISASM_ARM_NAME_ST1B,CDISASM_ARM_NAME_ST1H,CDISASM_ARM_NAME_ST1W,CDISASM_ARM_NAME_ST1D};
    static const cdisasm_arm_name_id nn[4]={CDISASM_ARM_NAME_STNT1B,CDISASM_ARM_NAME_STNT1H,CDISASM_ARM_NAME_STNT1W,CDISASM_ARM_NAME_STNT1D};
    static const cdisasm_arm_name_id lnn[4]={CDISASM_ARM_NAME_LDNT1B,CDISASM_ARM_NAME_LDNT1H,CDISASM_ARM_NAME_LDNT1W,CDISASM_ARM_NAME_LDNT1D};
#endif
    unsigned im,st,nt,q,sz,p,pn,r,z;
    for(im=0;im<2;im++)for(st=0;st<2;st++)for(nt=0;nt<2;nt++)for(q=0;q<2;q++)for(sz=0;sz<4;sz++)
      for(p=0;p<(im?16u:32u);p++)for(pn=0;pn<8;pn++)for(r=0;r<32;r++)for(z=nt;z<32;z+=q?4u:2u){
        uint32_t w=UINT32_C(0xa0000000)|(im<<22)|(st<<21)|(q<<15)|(sz<<13)|(p<<16)|(pn<<10)|(r<<5)|z;
        cdisasm_arm_instruction i;
#if USE_EXTRA_OPCODES
        unsigned count=q?4u:2u, base=im?(st?3597u:3581u):(st?3565u:3549u);
        int64_t d=im*(p<8?(int64_t)p:(int64_t)p-16)*(int64_t)count;
        EXPECT(decode(w,CDISASM_ARM_CPU_ANY,&i)==4); EXPECT(i.name_id==(nt?(st?nn[sz]:lnn[sz]):(st?sn[sz]:ln[sz])));
        EXPECT(i.form_id==base+(q?8u:0u)+sz*2u+nt); EXPECT(i.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
        EXPECT(i.operand_count==3); EXPECT(i.operand[0].register_list==(0x100u|count)); EXPECT(i.operand[0].reg==CDISASM_ARM_REG_Z0+z-nt); EXPECT(i.operand[0].extend_type==(1u<<sz));
        EXPECT(i.operand[1].reg==CDISASM_ARM_REG_PN8+pn); EXPECT(i.operand[1].flags==(st?0u:CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO));
        EXPECT(i.operand[2].base_reg==(r==31?CDISASM_ARM_REG_SP:CDISASM_ARM_REG_X0+r)); EXPECT((int64_t)i.operand[2].imm==d); EXPECT(i.operand[2].size==(1u<<sz));
        if(!im){EXPECT(i.operand[2].index_reg==(p==31?CDISASM_ARM_REG_XZR:CDISASM_ARM_REG_X0+p)); EXPECT(i.operand[2].shift_amount==sz);}
#else
        EXPECT(decode(w,CDISASM_ARM_CPU_ANY,&i)==0); EXPECT(i.last_error_id==CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
      }
}
static void profiles_format(void) {
#if USE_EXTRA_OPCODES
    cdisasm_arm_instruction i; EXPECT(decode(UINT32_C(0xa0030040),CDISASM_ARM_CPU_ANY,&i)==4);
    EXPECT(decode(UINT32_C(0xa0030040),CDISASM_ARM_CPU_FUJITSU_A64FX,&i)==0); EXPECT(decode(UINT32_C(0xa0030040),CDISASM_ARM_CPU_APPLE_M4,&i)==4);
    EXPECT(decode(UINT32_C(0xa0030041),CDISASM_ARM_CPU_FUJITSU_A64FX,&i)==0); EXPECT(decode(UINT32_C(0xa0030041),CDISASM_ARM_CPU_APPLE_M4,&i)==4);
    EXPECT(decode(UINT32_C(0xa04724c5),CDISASM_ARM_CPU_FUJITSU_A64FX,&i)==0); EXPECT(decode(UINT32_C(0xa04724c5),CDISASM_ARM_CPU_APPLE_M4,&i)==4);
#if USE_DISASM_FORMAT
    { char t[128]; EXPECT(decode(UINT32_C(0xa0030040),CDISASM_ARM_CPU_ANY,&i)==4); EXPECT(cdisasm_arm_format(&i,0,t,sizeof(t))!=0); EXPECT(strcmp(t,"ld1b {z0.b, z1.b}, pn8/z, [x2, x3]")==0);
      EXPECT(decode(UINT32_C(0xa0030041),CDISASM_ARM_CPU_ANY,&i)==4); EXPECT(cdisasm_arm_format(&i,0,t,sizeof(t))!=0); EXPECT(strcmp(t,"ldnt1b {z0.b, z1.b}, pn8/z, [x2, x3]")==0);
      EXPECT(decode(UINT32_C(0xa04724c5),CDISASM_ARM_CPU_ANY,&i)==4); EXPECT(cdisasm_arm_format(&i,0,t,sizeof(t))!=0); EXPECT(strcmp(t,"ldnt1h {z4.h, z5.h}, pn9/z, [x6, #0xe, mul vl]")==0);
      EXPECT(decode(UINT32_C(0xa047fffc),CDISASM_ARM_CPU_ANY,&i)==4); EXPECT(cdisasm_arm_format(&i,0,t,sizeof(t))!=0); EXPECT(strcmp(t,"ld1d {z28.d, z29.d, z30.d, z31.d}, pn15/z, [sp, #0x1c, mul vl]")==0);
      EXPECT(decode(UINT32_C(0xa0230041),CDISASM_ARM_CPU_ANY,&i)==4); EXPECT(cdisasm_arm_format(&i,0,t,sizeof(t))!=0); EXPECT(strcmp(t,"stnt1b {z0.b, z1.b}, pn8, [x2, x3]")==0);
      EXPECT(decode(UINT32_C(0xa061e041),CDISASM_ARM_CPU_ANY,&i)==4); EXPECT(cdisasm_arm_format(&i,0,t,sizeof(t))!=0); EXPECT(strcmp(t,"stnt1d {z0.d, z1.d, z2.d, z3.d}, pn8, [x2, #0x4, mul vl]")==0);
      i.form_id=3549u; EXPECT(cdisasm_arm_format(&i,0,t,sizeof(t))==0); }
#endif
#endif
}
static void q_domains(void) {
    static const struct qcase { uint32_t word; cdisasm_arm_form_id form;
        cdisasm_arm_name_id name; unsigned count; int store; int immediate;
    } cases[] = {
        {0xa4a38040u,3311,CDISASM_ARM_NAME_LD2Q,2,0,0},
        {0xa5238040u,3312,CDISASM_ARM_NAME_LD3Q,3,0,0},
        {0xa5a38040u,3313,CDISASM_ARM_NAME_LD4Q,4,0,0},
        {0xa491e040u,3378,CDISASM_ARM_NAME_LD2Q,2,0,1},
        {0xa511e040u,3379,CDISASM_ARM_NAME_LD3Q,3,0,1},
        {0xa591e040u,3380,CDISASM_ARM_NAME_LD4Q,4,0,1},
        {0xe4410040u,3463,CDISASM_ARM_NAME_ST2Q,2,1,1},
        {0xe4810040u,3464,CDISASM_ARM_NAME_ST3Q,3,1,1},
        {0xe4c10040u,3465,CDISASM_ARM_NAME_ST4Q,4,1,1},
        {0xe4630040u,3466,CDISASM_ARM_NAME_ST2Q,2,1,0},
        {0xe4a30040u,3467,CDISASM_ARM_NAME_ST3Q,3,1,0},
        {0xe4e30040u,3468,CDISASM_ARM_NAME_ST4Q,4,1,0}
    };
    size_t n; cdisasm_arm_instruction i;
    for(n=0;n<sizeof(cases)/sizeof(cases[0]);++n){
#if USE_EXTRA_OPCODES
        const struct qcase *c=&cases[n];
        EXPECT(decode(c->word,CDISASM_ARM_CPU_ANY,&i)==4);
        EXPECT(i.form_id==c->form); EXPECT(i.name_id==c->name);
        EXPECT(i.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
        EXPECT(i.operand_count==3); EXPECT(i.operand[0].type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);
        EXPECT(i.operand[0].reg==CDISASM_ARM_REG_Z0); EXPECT(i.operand[0].register_list==(0x100u|c->count));
        EXPECT(i.operand[0].extend_type==16u); EXPECT(i.operand[0].access==(c->store?CDISASM_OPERAND_ACCESS_READ:CDISASM_OPERAND_ACCESS_WRITE));
        EXPECT(i.operand[1].reg==CDISASM_ARM_REG_P0); EXPECT(i.operand[1].extend_type==16u);
        EXPECT(i.operand[1].flags==(c->store?0u:CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO));
        EXPECT(i.operand[2].base_reg==CDISASM_ARM_REG_X2); EXPECT(i.operand[2].size==16u);
        EXPECT((int64_t)i.operand[2].imm==(c->immediate?(int64_t)c->count:0));
        EXPECT(i.operand[2].index_reg==(c->immediate?CDISASM_ARM_REG_NONE:CDISASM_ARM_REG_X3));
        EXPECT(i.operand[2].access==(c->store?CDISASM_OPERAND_ACCESS_WRITE:CDISASM_OPERAND_ACCESS_READ));
#if USE_DISASM_FORMAT
        {char t[128];EXPECT(cdisasm_arm_format(&i,0,t,sizeof(t))!=0);}
#endif
#else
        EXPECT(decode(cases[n].word,CDISASM_ARM_CPU_ANY,&i)==0);
        EXPECT(i.last_error_id==CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
#if USE_EXTRA_OPCODES
    EXPECT(decode(cases[0].word,CDISASM_ARM_CPU_APPLE_M4,&i)==4);
    EXPECT(decode(cases[0].word,CDISASM_ARM_CPU_FUJITSU_A64FX,&i)==0);
#endif
}
static void strided_domains(void) {
#if USE_EXTRA_OPCODES
    static const cdisasm_arm_name_id lnn[4]={CDISASM_ARM_NAME_LDNT1B,CDISASM_ARM_NAME_LDNT1H,CDISASM_ARM_NAME_LDNT1W,CDISASM_ARM_NAME_LDNT1D};
#endif
    unsigned im,st,nt,q,sz,p,pn,r,z;
    for(im=0;im<2;im++)for(st=0;st<2;st++)for(nt=0;nt<2;nt++)for(q=0;q<2;q++)for(sz=0;sz<4;sz++)
      for(p=0;p<(im?16u:32u);p++)for(pn=0;pn<8;pn++)for(r=0;r<32;r++)for(z=0;z<(q?4u:8u);z++){
        uint32_t w=UINT32_C(0xa1000000)|(im<<22)|(st<<21)|(q<<15)|(sz<<13)|(p<<16)|(pn<<10)|(r<<5)|z|(nt<<3);
        cdisasm_arm_instruction i;
#if USE_EXTRA_OPCODES
        unsigned count=q?4u:2u, base=im?(st?3661u:3645u):(st?3629u:3613u);
        EXPECT(decode(w,CDISASM_ARM_CPU_ANY,&i)==4); EXPECT(i.form_id==base+(q?8u:0u)+sz*2u+nt);
        if(!st&&nt)EXPECT(i.name_id==lnn[sz]);
        EXPECT(i.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED|CDISASM_ARM_INSTRUCTION_FLAG_SME));
        EXPECT(i.operand[0].reg==CDISASM_ARM_REG_Z0+z); EXPECT(i.operand[0].register_list==(((q?4u:8u)<<8)|count));
        EXPECT(i.operand[1].reg==CDISASM_ARM_REG_PN8+pn); EXPECT(i.operand[2].size==(1u<<sz));
#else
        EXPECT(decode(w,CDISASM_ARM_CPU_ANY,&i)==0); EXPECT(i.last_error_id==CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
      }
#if USE_EXTRA_OPCODES
    { cdisasm_arm_instruction i; EXPECT(decode(UINT32_C(0xa1030040),CDISASM_ARM_CPU_APPLE_M4,&i)==4); EXPECT(decode(UINT32_C(0xa1030040),CDISASM_ARM_CPU_FUJITSU_A64FX,&i)==0);
      EXPECT(decode(UINT32_C(0xa1030048),CDISASM_ARM_CPU_APPLE_M4,&i)==4); EXPECT(decode(UINT32_C(0xa1030048),CDISASM_ARM_CPU_FUJITSU_A64FX,&i)==0);
      EXPECT(decode(UINT32_C(0xa14724c9),CDISASM_ARM_CPU_APPLE_M4,&i)==4); EXPECT(decode(UINT32_C(0xa14724c9),CDISASM_ARM_CPU_FUJITSU_A64FX,&i)==0);
#if USE_DISASM_FORMAT
      { char t[128]; EXPECT(decode(UINT32_C(0xa1030040),CDISASM_ARM_CPU_ANY,&i)==4); EXPECT(cdisasm_arm_format(&i,0,t,sizeof(t))!=0); EXPECT(strcmp(t,"ld1b {z0.b, z8.b}, pn8/z, [x2, x3]")==0);
        EXPECT(decode(UINT32_C(0xa1030048),CDISASM_ARM_CPU_ANY,&i)==4); EXPECT(cdisasm_arm_format(&i,0,t,sizeof(t))!=0); EXPECT(strcmp(t,"ldnt1b {z0.b, z8.b}, pn8/z, [x2, x3]")==0);
        EXPECT(decode(UINT32_C(0xa14724c9),CDISASM_ARM_CPU_ANY,&i)==4); EXPECT(cdisasm_arm_format(&i,0,t,sizeof(t))!=0); EXPECT(strcmp(t,"ldnt1h {z1.h, z9.h}, pn9/z, [x6, #0xe, mul vl]")==0);
        EXPECT(decode(UINT32_C(0xa1232048),CDISASM_ARM_CPU_ANY,&i)==4); EXPECT(cdisasm_arm_format(&i,0,t,sizeof(t))!=0); EXPECT(strcmp(t,"stnt1h {z0.h, z8.h}, pn8, [x2, x3, lsl #0x1]")==0);
        i.form_id=3615u; EXPECT(cdisasm_arm_format(&i,0,t,sizeof(t))==0); }
#endif
    }
#endif
}
int main(void){domains();profiles_format();q_domains();strided_domains();if(failures)return fprintf(stderr,"%d failures\n",failures),1;puts("ARM multi-vector transfer tests passed (140 exact leaves)");return 0;}
