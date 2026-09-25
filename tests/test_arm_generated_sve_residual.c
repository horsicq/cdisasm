#include "arm_generated_formatter.h"

#include <stdio.h>
#include <string.h>

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct sve_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    const char *expected;
} sve_case;

/* Independently assembled and disassembled with LLVM SVE2. */
static const sve_case cases[] = {
    { UINT32_C(0x04224420), 2345u, CDISASM_ARM_NAME_INDEX,
      "index z0.b, w1, #2" },
    { UINT32_C(0x04624420), 2345u, CDISASM_ARM_NAME_INDEX,
      "index z0.h, w1, #2" },
    { UINT32_C(0x04a24420), 2345u, CDISASM_ARM_NAME_INDEX,
      "index z0.s, w1, #2" },
    { UINT32_C(0x04e24420), 2345u, CDISASM_ARM_NAME_INDEX,
      "index z0.d, x1, #2" },
    { UINT32_C(0x05a43841), 2447u, CDISASM_ARM_NAME_INSR,
      "insr z1.s, w2" },
    { UINT32_C(0x05e43841), 2447u, CDISASM_ARM_NAME_INSR,
      "insr z1.d, x2" },
    { UINT32_C(0x0520a020), 2496u, CDISASM_ARM_NAME_LASTA,
      "lasta w0, p0, z1.b" },
    { UINT32_C(0x05e0a020), 2496u, CDISASM_ARM_NAME_LASTA,
      "lasta x0, p0, z1.d" },
    { UINT32_C(0x05b0a020), 2499u, CDISASM_ARM_NAME_CLASTA,
      "clasta w0, p0, w0, z1.s" },
    { UINT32_C(0x05f0a020), 2499u, CDISASM_ARM_NAME_CLASTA,
      "clasta x0, p0, x0, z1.d" },
    { UINT32_C(0x05a58020), 2484u, CDISASM_ARM_NAME_REVH,
      "revh z0.s, p0/m, z1.s" },
    { UINT32_C(0x651aa020), 3142u, CDISASM_ARM_NAME_FLOGB,
      "flogb z0.h, p0/m, z1.h" },
    { UINT32_C(0x651ca020), 3142u, CDISASM_ARM_NAME_FLOGB,
      "flogb z0.s, p0/m, z1.s" },
    { UINT32_C(0x651ea020), 3142u, CDISASM_ARM_NAME_FLOGB,
      "flogb z0.d, p0/m, z1.d" },
    { UINT32_C(0xe4a14000), 3471u, CDISASM_ARM_NAME_ST1H,
      "st1h { z0.h }, p0, [x0, x1, lsl #1]" },
    { UINT32_C(0xe4c1e000), 3528u, CDISASM_ARM_NAME_ST1H,
      "st1h { z0.s }, p0, [x0, #1, mul vl]" },
    { UINT32_C(0x042f3420), 2325u, CDISASM_ARM_NAME_XAR,
      "xar z0.b, z0.b, z1.b, #1" },
    { UINT32_C(0x043f3420), 2325u, CDISASM_ARM_NAME_XAR,
      "xar z0.h, z0.h, z1.h, #1" },
    { UINT32_C(0x047f3420), 2325u, CDISASM_ARM_NAME_XAR,
      "xar z0.s, z0.s, z1.s, #1" },
    { UINT32_C(0x04ff3420), 2325u, CDISASM_ARM_NAME_XAR,
      "xar z0.d, z0.d, z1.d, #1" },
    { UINT32_C(0x450ff020), 2846u, CDISASM_ARM_NAME_SRI,
      "sri z0.b, z1.b, #1" },
    { UINT32_C(0x451ff020), 2846u, CDISASM_ARM_NAME_SRI,
      "sri z0.h, z1.h, #1" },
    { UINT32_C(0x455ff020), 2846u, CDISASM_ARM_NAME_SRI,
      "sri z0.s, z1.s, #1" },
    { UINT32_C(0x45dff020), 2846u, CDISASM_ARM_NAME_SRI,
      "sri z0.d, z1.d, #1" },
    { UINT32_C(0x4508f020), 2846u, CDISASM_ARM_NAME_SRI,
      "sri z0.b, z1.b, #8" },
    { UINT32_C(0x4509f420), 2847u, CDISASM_ARM_NAME_SLI,
      "sli z0.b, z1.b, #1" },
    { UINT32_C(0x4508f420), 2847u, CDISASM_ARM_NAME_SLI,
      "sli z0.b, z1.b, #0" },
    { UINT32_C(0x450ff420), 2847u, CDISASM_ARM_NAME_SLI,
      "sli z0.b, z1.b, #7" },
    { UINT32_C(0x2518e3e0), 2559u, CDISASM_ARM_NAME_PTRUE,
      "ptrue p0.b" },
    { UINT32_C(0x2518e020), 2559u, CDISASM_ARM_NAME_PTRUE,
      "ptrue p0.b, vl1" },
    { UINT32_C(0x2518e000), 2559u, CDISASM_ARM_NAME_PTRUE,
      "ptrue p0.b, pow2" },
    { UINT32_C(0x2518e1c0), 2559u, CDISASM_ARM_NAME_PTRUE,
      "ptrue p0.b, #14" },
    { UINT32_C(0x2518e3a0), 2559u, CDISASM_ARM_NAME_PTRUE,
      "ptrue p0.b, mul4" },
    { UINT32_C(0x2518e3c0), 2559u, CDISASM_ARM_NAME_PTRUE,
      "ptrue p0.b, mul3" },
    { UINT32_C(0x2519e3e0), 2560u, CDISASM_ARM_NAME_PTRUES,
      "ptrues p0.b" },
    { UINT32_C(0x05212420), 2440u, CDISASM_ARM_NAME_DUPQ,
      "dupq z0.b, z1.b[0]" },
    { UINT32_C(0x05222420), 2440u, CDISASM_ARM_NAME_DUPQ,
      "dupq z0.h, z1.h[0]" },
    { UINT32_C(0x05242420), 2440u, CDISASM_ARM_NAME_DUPQ,
      "dupq z0.s, z1.s[0]" },
    { UINT32_C(0x05282420), 2440u, CDISASM_ARM_NAME_DUPQ,
      "dupq z0.d, z1.d[0]" },
    { UINT32_C(0x053f2420), 2440u, CDISASM_ARM_NAME_DUPQ,
      "dupq z0.b, z1.b[15]" },
    { UINT32_C(0x053e2420), 2440u, CDISASM_ARM_NAME_DUPQ,
      "dupq z0.h, z1.h[7]" },
    { UINT32_C(0x053c2420), 2440u, CDISASM_ARM_NAME_DUPQ,
      "dupq z0.s, z1.s[3]" },
    { UINT32_C(0x05382420), 2440u, CDISASM_ARM_NAME_DUPQ,
      "dupq z0.d, z1.d[1]" },
    { UINT32_C(0x25244440), 2565u, CDISASM_ARM_NAME_PSEL,
      "psel p0, p1, p2.b[w12, 0]" },
    { UINT32_C(0x25284440), 2565u, CDISASM_ARM_NAME_PSEL,
      "psel p0, p1, p2.h[w12, 0]" },
    { UINT32_C(0x25304440), 2565u, CDISASM_ARM_NAME_PSEL,
      "psel p0, p1, p2.s[w12, 0]" },
    { UINT32_C(0x25604440), 2565u, CDISASM_ARM_NAME_PSEL,
      "psel p0, p1, p2.d[w12, 0]" },
    { UINT32_C(0x25fc4440), 2565u, CDISASM_ARM_NAME_PSEL,
      "psel p0, p1, p2.b[w12, 15]" },
    { UINT32_C(0x25f84440), 2565u, CDISASM_ARM_NAME_PSEL,
      "psel p0, p1, p2.h[w12, 7]" },
    { UINT32_C(0x25f04440), 2565u, CDISASM_ARM_NAME_PSEL,
      "psel p0, p1, p2.s[w12, 3]" },
    { UINT32_C(0x25e04440), 2565u, CDISASM_ARM_NAME_PSEL,
      "psel p0, p1, p2.d[w12, 1]" },
    { UINT32_C(0xc08a9020), 3923u, CDISASM_ARM_NAME_LUTI4,
      "luti4 { z0.h-z3.h }, zt0, z1[0]" },
    { UINT32_C(0xc08aa020), 3923u, CDISASM_ARM_NAME_LUTI4,
      "luti4 { z0.s-z3.s }, zt0, z1[0]" },
    { UINT32_C(0xc08a9024), 3923u, CDISASM_ARM_NAME_LUTI4,
      "luti4 { z4.h-z7.h }, zt0, z1[0]" },
    { UINT32_C(0xc08aa03c), 3923u, CDISASM_ARM_NAME_LUTI4,
      "luti4 { z28.s-z31.s }, zt0, z1[0]" },
    { UINT32_C(0xd5033f9f), 4493u, CDISASM_ARM_NAME_DSB,
      "dsb sy" },
    { UINT32_C(0xd5033a9f), 4493u, CDISASM_ARM_NAME_DSB,
      "dsb ishst" },
    { UINT32_C(0xd503389f), 4493u, CDISASM_ARM_NAME_DSB,
      "dsb #8" },
    { UINT32_C(0xd5033fbf), 4494u, CDISASM_ARM_NAME_DMB,
      "dmb sy" },
    { UINT32_C(0xd50331bf), 4494u, CDISASM_ARM_NAME_DMB,
      "dmb oshld" },
    { UINT32_C(0xd50330bf), 4494u, CDISASM_ARM_NAME_DMB,
      "dmb #0" },
    { UINT32_C(0xf8a04838), 5545u, CDISASM_ARM_NAME_RPRFM,
      "rprfm pldkeep, x0, [x1]" },
    { UINT32_C(0xf8a0483c), 5545u, CDISASM_ARM_NAME_RPRFM,
      "rprfm pldstrm, x0, [x1]" },
    { UINT32_C(0xf8a04839), 5545u, CDISASM_ARM_NAME_RPRFM,
      "rprfm pstkeep, x0, [x1]" },
    { UINT32_C(0xf8a0483d), 5545u, CDISASM_ARM_NAME_RPRFM,
      "rprfm pststrm, x0, [x1]" },
    { UINT32_C(0xf8a0783f), 5545u, CDISASM_ARM_NAME_RPRFM,
      "rprfm #31, x0, [x1]" },
    { UINT32_C(0x05a5a020), 2485u, CDISASM_ARM_NAME_REVH,
      "revh z0.s, p0/z, z1.s" },
    { UINT32_C(0x05e5a020), 2485u, CDISASM_ARM_NAME_REVH,
      "revh z0.d, p0/z, z1.d" },
    { UINT32_C(0x641ea020), 2979u, CDISASM_ARM_NAME_FLOGB,
      "flogb z0.h, p0/z, z1.h" },
    { UINT32_C(0x641ec020), 2979u, CDISASM_ARM_NAME_FLOGB,
      "flogb z0.s, p0/z, z1.s" },
    { UINT32_C(0x641ee020), 2979u, CDISASM_ARM_NAME_FLOGB,
      "flogb z0.d, p0/z, z1.d" },
    { UINT32_C(0xd501961f), 4488u, CDISASM_ARM_NAME_STSHH,
      "stshh keep" },
    { UINT32_C(0xd501963f), 4488u, CDISASM_ARM_NAME_STSHH,
      "stshh strm" },
    { UINT32_C(0xd5033fdf), 4495u, CDISASM_ARM_NAME_ISB,
      "isb" },
    { UINT32_C(0xd50330df), 4495u, CDISASM_ARM_NAME_ISB,
      "isb #0" },
    { UINT32_C(0xd5033edf), 4495u, CDISASM_ARM_NAME_ISB,
      "isb #14" },
    { UINT32_C(0xc08c8020), 3935u, CDISASM_ARM_NAME_LUTI2,
      "luti2 { z0.b, z1.b, z2.b, z3.b }, zt0, z1[0]" },
    { UINT32_C(0xc08c8030), 3935u, CDISASM_ARM_NAME_LUTI2,
      "luti2 { z16.b, z17.b, z18.b, z19.b }, zt0, z1[0]" },
    { UINT32_C(0xc08c9020), 3935u, CDISASM_ARM_NAME_LUTI2,
      "luti2 { z0.h, z1.h, z2.h, z3.h }, zt0, z1[0]" },
    { UINT32_C(0xc08a9020), 3936u, CDISASM_ARM_NAME_LUTI4,
      "luti4 { z0.h, z1.h, z2.h, z3.h }, zt0, z1[0]" },
    { UINT32_C(0xc08a9030), 3936u, CDISASM_ARM_NAME_LUTI4,
      "luti4 { z16.h, z17.h, z18.h, z19.h }, zt0, z1[0]" },
    { UINT32_C(0xc08b0000), 3937u, CDISASM_ARM_NAME_LUTI4,
      "luti4 { z0.b, z1.b, z2.b, z3.b }, zt0, { z0-z1 }" },
    { UINT32_C(0xc08b0010), 3937u, CDISASM_ARM_NAME_LUTI4,
      "luti4 { z16.b, z17.b, z18.b, z19.b }, zt0, { z0-z1 }" },
    { UINT32_C(0xc08b0040), 3937u, CDISASM_ARM_NAME_LUTI4,
      "luti4 { z0.b, z1.b, z2.b, z3.b }, zt0, { z2-z3 }" },
    { UINT32_C(0xc08b03c0), 3937u, CDISASM_ARM_NAME_LUTI4,
      "luti4 { z0.b, z1.b, z2.b, z3.b }, zt0, { z30-z31 }" },
    { UINT32_C(0xc08c8021), 3935u, CDISASM_ARM_NAME_LUTI2, NULL },
    { UINT32_C(0xc08a9021), 3936u, CDISASM_ARM_NAME_LUTI4, NULL },
    { UINT32_C(0xc08b0001), 3937u, CDISASM_ARM_NAME_LUTI4, NULL },
    { UINT32_C(0xc08ca020), 3935u, CDISASM_ARM_NAME_LUTI2, NULL },
    { UINT32_C(0xc09a0000), 3938u, CDISASM_ARM_NAME_LUTI6,
      "luti6 { z0.b, z4.b, z8.b, z12.b }, zt0, { z0-z2 }" },
    { UINT32_C(0xc09a0013), 3938u, CDISASM_ARM_NAME_LUTI6,
      "luti6 { z19.b, z23.b, z27.b, z31.b }, zt0, { z0-z2 }" },
    { UINT32_C(0xc09a0380), 3938u, CDISASM_ARM_NAME_LUTI6,
      "luti6 { z0.b, z4.b, z8.b, z12.b }, zt0, { z7-z9 }" },
    { UINT32_C(0xc120fc00), 4372u, CDISASM_ARM_NAME_LUTI6,
      "luti6 { z0.h, z4.h, z8.h, z12.h }, { z0.h, z1.h }, { z0-z1 }[0]" },
    { UINT32_C(0xc120fc13), 4372u, CDISASM_ARM_NAME_LUTI6,
      "luti6 { z19.h, z23.h, z27.h, z31.h }, { z0.h, z1.h }, { z0-z1 }[0]" },
    { UINT32_C(0xc120ffc0), 4372u, CDISASM_ARM_NAME_LUTI6,
      "luti6 { z0.h, z4.h, z8.h, z12.h }, { z30.h, z31.h }, { z0-z1 }[0]" },
    { UINT32_C(0xc120ffe0), 4372u, CDISASM_ARM_NAME_LUTI6,
      "luti6 { z0.h, z4.h, z8.h, z12.h }, { z31.h, z0.h }, { z0-z1 }[0]" },
    { UINT32_C(0xc13ffc00), 4372u, CDISASM_ARM_NAME_LUTI6,
      "luti6 { z0.h, z4.h, z8.h, z12.h }, { z0.h, z1.h }, { z31-z0 }[0]" },
    { UINT32_C(0xc160fc00), 4372u, CDISASM_ARM_NAME_LUTI6,
      "luti6 { z0.h, z4.h, z8.h, z12.h }, { z0.h, z1.h }, { z0-z1 }[1]" },
    { UINT32_C(0xc09a0004), 3938u, CDISASM_ARM_NAME_LUTI6, NULL },
    { UINT32_C(0xc120fc04), 4372u, CDISASM_ARM_NAME_LUTI6, NULL },
    { UINT32_C(0xc120fc00), 3938u, CDISASM_ARM_NAME_LUTI6, NULL },
    { UINT32_C(0xc09a0000), 4372u, CDISASM_ARM_NAME_LUTI6, NULL },
};

int main(void)
{
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const sve_case *entry = &cases[index];
        cdisasm_arm_instruction instruction = {0};
        char buffer[128] = {0};
        size_t length;

        instruction.raw_instruction = entry->word;
        instruction.opcode_size = 4u;
        instruction.isa_id = CDISASM_ARM_ISA_A64;
        instruction.form_id = entry->form_id;
        instruction.name_id = entry->name_id;
        instruction.instruction_flags =
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
        length = cdisasm_arm_format_generated(
            &instruction, 0u, buffer, sizeof(buffer));
        if (entry->expected == NULL ? length != 0u
            : length == 0u || strcmp(buffer, entry->expected) != 0) {
            fprintf(stderr, "SVE residual case %zu: got '%s', expected '%s'\n",
                    index, buffer,
                    entry->expected != NULL ? entry->expected : "<rejected>");
            return 1;
        }
    }
    puts("ARM generated SVE residual tests passed");
    return 0;
}
