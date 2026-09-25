#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"
#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

static int failures;
#define EXPECT(c) do { if (!(c)) { if (failures < 24) fprintf(stderr, \
    "%s:%d: expectation failed: %s\n", __FILE__, __LINE__, #c); \
    ++failures; } } while (0)

static uint32_t decode_word(uint32_t word, cdisasm_arm_cpu_id cpu,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4] = { (uint8_t)word, (uint8_t)(word >> 8),
        (uint8_t)(word >> 16), (uint8_t)(word >> 24) };
    return cdisasm_arm_decode(cpu, CDISASM_ARM_MODE_A64, bytes, 4u,
        UINT64_C(0x1e202000), CDISASM_ARM_DECODE_OPTION_NONE, instruction);
}

static void test_complete_domain(void)
{
    static const uint32_t bases[3] = {
        UINT32_C(0x1e202000), UINT32_C(0x1e602000), UINT32_C(0x1ee02000)
    };
#if USE_EXTRA_OPCODES
    static const cdisasm_arm_reg_id first_regs[3] = {
        CDISASM_ARM_REG_S0, CDISASM_ARM_REG_D0, CDISASM_ARM_REG_H0
    };
    static const uint8_t sizes[3] = { 4u, 8u, 2u };
    static const cdisasm_arm_form_id forms[3][4] = {
        { 6507, 6508, 6509, 6510 },
        { 6511, 6512, 6513, 6514 },
        { 6515, 6516, 6517, 6518 }
    };
#endif
    unsigned precision, signaling, zero, rn, rm;

    for (precision = 0u; precision < 3u; ++precision) {
        for (signaling = 0u; signaling <= 1u; ++signaling) {
            for (zero = 0u; zero <= 1u; ++zero) {
                for (rn = 0u; rn < 32u; ++rn) {
                    unsigned rm_limit = zero != 0u ? 1u : 32u;
                    for (rm = 0u; rm < rm_limit; ++rm) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = bases[precision]
                            | ((uint32_t)rm << 16) | ((uint32_t)rn << 5)
                            | (signaling != 0u ? UINT32_C(0x10) : 0u)
                            | (zero != 0u ? UINT32_C(0x08) : 0u);
                        memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
                        EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
                            &instruction) == 4u);
                        EXPECT(instruction.name_id == (signaling != 0u
                            ? CDISASM_ARM_NAME_FCMPE : CDISASM_ARM_NAME_FCMP));
                        EXPECT(instruction.form_id
                            == forms[precision][signaling * 2u + zero]);
                        EXPECT(instruction.instruction_flags
                            == (CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
                                | CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS));
                        EXPECT(instruction.operand_count == 2u);
                        EXPECT(instruction.operand[0].type
                            == CDISASM_OPERAND_REGISTER);
                        EXPECT(instruction.operand[0].reg
                            == (cdisasm_arm_reg_id)(first_regs[precision] + rn));
                        EXPECT(instruction.operand[0].size == sizes[precision]);
                        EXPECT(instruction.operand[0].access
                            == CDISASM_OPERAND_ACCESS_READ);
                        if (zero != 0u) {
                            EXPECT(instruction.operand[1].type
                                == CDISASM_OPERAND_IMMEDIATE);
                            EXPECT(instruction.operand[1].imm == 0u);
                        } else {
                            EXPECT(instruction.operand[1].type
                                == CDISASM_OPERAND_REGISTER);
                            EXPECT(instruction.operand[1].reg
                                == (cdisasm_arm_reg_id)(first_regs[precision]
                                    + rm));
                            EXPECT(instruction.operand[1].size
                                == sizes[precision]);
                            EXPECT(instruction.operand[1].access
                                == CDISASM_OPERAND_ACCESS_READ);
                        }
#else
                        {
                            cdisasm_arm_instruction expected;
                            memset(&expected, 0, sizeof(expected));
                            expected.last_error_id =
                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
                            EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY,
                                &instruction) == 0u);
                            EXPECT(memcmp(&instruction, &expected,
                                sizeof(expected)) == 0);
                        }
#endif
                    }
                }
            }
        }
    }
}

static void test_legality_and_profile(void)
{
    cdisasm_arm_instruction instruction, expected;
    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = CDISASM_STATUS_INVALID_INSTRUCTION;
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(UINT32_C(0x1ea22010), CDISASM_ARM_CPU_ANY,
        &instruction) == 0u);
    EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
#if !USE_EXTRA_OPCODES
    expected.last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(UINT32_C(0x1ee22010), CDISASM_ARM_CPU_CORTEX_A53,
        &instruction) == 0u);
    EXPECT(memcmp(&instruction, &expected, sizeof(expected)) == 0);
}

#if USE_EXTRA_OPCODES
static uint64_t expand_fmov_imm(unsigned encoded, unsigned size)
{
    unsigned total=8u*size,eb=size==4u?8u:11u,fb=total-eb-1u,s=(encoded>>6)&1u;uint64_t e=(uint64_t)(s^1u)<<(eb-1u);if(s)e|=((UINT64_C(1)<<(eb-3u))-1u)<<2u;e|=(encoded>>4)&3u;return ((uint64_t)((encoded>>7)&1u)<<(total-1u))|(e<<fb)|((uint64_t)(encoded&15u)<<(fb-4u));
}
#endif

static void test_fmov_immediate_domain(void)
{
    unsigned p,imm,rd;for(p=0;p<2;p++)for(imm=0;imm<256;imm++)for(rd=0;rd<32;rd++){cdisasm_arm_instruction i;uint32_t w=(p?UINT32_C(0x1e601000):UINT32_C(0x1e201000))|(imm<<13)|rd;memset(&i,0xa5,sizeof(i));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(w,CDISASM_ARM_CPU_ANY,&i)==4u);EXPECT(i.name_id==CDISASM_ARM_NAME_FMOV);EXPECT(i.form_id==(p?6520:6519));EXPECT(i.instruction_flags==CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);EXPECT(i.operand_count==2);EXPECT(i.operand[0].type==CDISASM_OPERAND_REGISTER);EXPECT(i.operand[0].reg==(cdisasm_arm_reg_id)((p?CDISASM_ARM_REG_D0:CDISASM_ARM_REG_S0)+rd));EXPECT(i.operand[0].size==(p?8:4));EXPECT(i.operand[0].access==CDISASM_OPERAND_ACCESS_WRITE);EXPECT(i.operand[1].type==CDISASM_OPERAND_IMMEDIATE);EXPECT(i.operand[1].imm==expand_fmov_imm(imm,p?8:4));EXPECT(i.operand[1].size==1);EXPECT(i.operand[1].access==CDISASM_OPERAND_ACCESS_READ);
#else
    EXPECT(decode_word(w,CDISASM_ARM_CPU_ANY,&i)==0u);EXPECT(i.last_error_id==CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    {cdisasm_arm_instruction i;char text[80];EXPECT(decode_word(UINT32_C(0x1e2e101f),CDISASM_ARM_CPU_ANY,&i)==4u);EXPECT(cdisasm_arm_format(&i,0,text,sizeof(text))!=0u);i.form_id=6520;EXPECT(cdisasm_arm_format(&i,0,text,sizeof(text))==0u);}
#endif
}

static void test_fmov_lane64_domain(void)
{
    unsigned direction,rd,rn;for(direction=0;direction<2;direction++)for(rd=0;rd<32;rd++)for(rn=0;rn<32;rn++){cdisasm_arm_instruction i;uint32_t w=(direction?UINT32_C(0x9eaf0000):UINT32_C(0x9eae0000))|(rn<<5)|rd;memset(&i,0xa5,sizeof(i));
#if USE_EXTRA_OPCODES
    const cdisasm_arm_operand*x,*v;EXPECT(decode_word(w,CDISASM_ARM_CPU_ANY,&i)==4u);EXPECT(i.name_id==CDISASM_ARM_NAME_FMOV);EXPECT(i.form_id==(direction?6396:6395));EXPECT(i.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SIMD|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));EXPECT(i.operand_count==2);x=&i.operand[direction?1:0];v=&i.operand[direction?0:1];EXPECT(x->type==CDISASM_OPERAND_REGISTER);EXPECT(x->reg==(cdisasm_arm_reg_id)(((direction?rn:rd)==31)?CDISASM_ARM_REG_XZR:CDISASM_ARM_REG_X0+(direction?rn:rd)));EXPECT(x->size==8);EXPECT(x->access==(direction?CDISASM_OPERAND_ACCESS_READ:CDISASM_OPERAND_ACCESS_WRITE));EXPECT(v->type==CDISASM_OPERAND_REGISTER);EXPECT(v->reg==(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+(direction?rd:rn)));EXPECT(v->size==16);EXPECT(v->extend_type==8);EXPECT(v->scale==2);EXPECT(v->flags==CDISASM_ARM_OPERAND_FLAG_HAS_LANE);EXPECT(v->imm==1);EXPECT(v->access==(direction?CDISASM_OPERAND_ACCESS_WRITE:CDISASM_OPERAND_ACCESS_READ));
#else
    EXPECT(decode_word(w,CDISASM_ARM_CPU_ANY,&i)==0u);EXPECT(i.last_error_id==CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    {cdisasm_arm_instruction i;char text[80];EXPECT(decode_word(UINT32_C(0x9eae03ff),CDISASM_ARM_CPU_ANY,&i)==4u);EXPECT(cdisasm_arm_format(&i,0,text,sizeof(text))!=0u);EXPECT(strcmp(text,"fmov xzr, v31.d[1]")==0);i.form_id=6396;EXPECT(cdisasm_arm_format(&i,0,text,sizeof(text))==0u);EXPECT(decode_word(UINT32_C(0x9eaf03ff),CDISASM_ARM_CPU_ANY,&i)==4u);EXPECT(cdisasm_arm_format(&i,0,text,sizeof(text))!=0u);EXPECT(strcmp(text,"fmov v31.d[1], xzr")==0);}
#endif
}

int main(void)
{
    test_complete_domain();
    test_legality_and_profile();
    test_fmov_immediate_domain();
    test_fmov_lane64_domain();
    if (failures != 0) return 1;
    puts("A64 scalar floating-point compare tests passed");
    return 0;
}
