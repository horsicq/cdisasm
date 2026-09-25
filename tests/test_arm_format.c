#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm_format.h"

#include <stdio.h>
#include <string.h>

typedef struct arm_format_case {
    const char *label;
    cdisasm_arm_cpu_id cpu_id;
    cdisasm_arm_mode mode;
    uint64_t address;
    uint8_t bytes[4];
    uint8_t byte_count;
    const char *expected;
} arm_format_case;

static int failures;

#define EXPECT(condition) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "%s:%d: expectation failed: %s\n", \
                __FILE__, __LINE__, #condition); \
            ++failures; \
        } \
    } while (0)

static int decode_case(
    const arm_format_case *test,
    cdisasm_arm_instruction *instruction)
{
    uint32_t decoded = cdisasm_arm_decode(
        test->cpu_id,
        test->mode,
        test->bytes,
        test->byte_count,
        test->address,
        CDISASM_ARM_DECODE_OPTION_NONE,
        instruction);

    if (decoded != test->byte_count
        || instruction->last_error_id != CDISASM_STATUS_OK) {
        fprintf(
            stderr,
            "%s: decode failed: return=%u status=%u\n",
            test->label,
            (unsigned)decoded,
            (unsigned)instruction->last_error_id);
        ++failures;
        return 0;
    }
    return 1;
}

static void expect_case(const arm_format_case *test)
{
    cdisasm_arm_instruction instruction;
    char text[256];
    size_t expected_size = strlen(test->expected);
    size_t required;
    size_t written;

    if (!decode_case(test, &instruction)) {
        return;
    }

    required = cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_0, NULL, 0);
    written = cdisasm_arm_format(
        &instruction,
        CDISASM_FORMAT_SYNTAX_0,
        text,
        sizeof(text));
    if (required != expected_size
        || written != expected_size
        || strcmp(text, test->expected) != 0) {
        fprintf(
            stderr,
            "%s: expected `%s` (%u), got `%s` (query=%u write=%u)\n",
            test->label,
            test->expected,
            (unsigned)expected_size,
            text,
            (unsigned)required,
            (unsigned)written);
        ++failures;
    }
}

static void test_a32_and_t32(void)
{
    static const arm_format_case cases[] = {
        {
            "A32 immediate",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A32,
            UINT64_C(0),
            { UINT8_C(0x05), UINT8_C(0x00), UINT8_C(0x81), UINT8_C(0xe2) },
            4,
            "add r0, r1, #0x5"
        },
        {
            "A32 shifted register",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A32,
            UINT64_C(0),
            { UINT8_C(0x82), UINT8_C(0x01), UINT8_C(0x81), UINT8_C(0xe0) },
            4,
            "add r0, r1, r2, lsl #0x3"
        },
        {
            "A32 conditional branch",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A32,
            UINT64_C(0x5000),
            { UINT8_C(0x01), UINT8_C(0x00), UINT8_C(0x00), UINT8_C(0x0a) },
            4,
            "beq 0x500c"
        },
#if USE_EXTRA_OPCODES
        {
            "A32 unconditional-space BLX",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A32,
            UINT64_C(0x1000),
            { UINT8_C(0x0d), UINT8_C(0x61), UINT8_C(0x57), UINT8_C(0xfb) },
            4,
            "blx 0x15d943e"
        },
        {
            "T32 VMSR FPSCR",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_T32,
            UINT64_C(0),
            { UINT8_C(0xe1), UINT8_C(0xee), UINT8_C(0x10), UINT8_C(0x1a) },
            4,
            "vmsr fpscr, r1"
        },
        {
            "T32 VMRS FPSCR",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_T32,
            UINT64_C(0),
            { UINT8_C(0xf1), UINT8_C(0xee), UINT8_C(0x10), UINT8_C(0x2a) },
            4,
            "vmrs r2, fpscr"
        },
#endif
        {
            "A32 pre-index writeback",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A32,
            UINT64_C(0),
            { UINT8_C(0x08), UINT8_C(0x20), UINT8_C(0x23), UINT8_C(0xe5) },
            4,
            "str r2, [r3, #-0x8]!"
        },
        {
            "A32 byte register width",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A32,
            UINT64_C(0),
            { UINT8_C(0x02), UINT8_C(0x00), UINT8_C(0xd1), UINT8_C(0xe5) },
            4,
            "ldrb r0, [r1, #0x2]"
        },
        {
            "A32 register list",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A32,
            UINT64_C(0),
            { UINT8_C(0x30), UINT8_C(0x40), UINT8_C(0x2d), UINT8_C(0xe9) },
            4,
            "push {r4, r5, lr}"
        },
        {
            "T32 immediate",
            CDISASM_ARM_CPU_CORTEX_A7,
            CDISASM_ARM_MODE_T32,
            UINT64_C(0),
            { UINT8_C(0x2a), UINT8_C(0x21), UINT8_C(0), UINT8_C(0) },
            2,
            "movs r1, #0x2a"
        },
        {
            "T32 conditional branch",
            CDISASM_ARM_CPU_CORTEX_A7,
            CDISASM_ARM_MODE_T32,
            UINT64_C(0x1000),
            { UINT8_C(0x01), UINT8_C(0xd0), UINT8_C(0), UINT8_C(0) },
            2,
            "beq 0x1006"
        },
        {
            "T32 register list",
            CDISASM_ARM_CPU_CORTEX_A7,
            CDISASM_ARM_MODE_T32,
            UINT64_C(0),
            { UINT8_C(0x10), UINT8_C(0xb5), UINT8_C(0), UINT8_C(0) },
            2,
            "push {r4, lr}"
        },
        {
            "T32 halfword register width",
            CDISASM_ARM_CPU_CORTEX_A7,
            CDISASM_ARM_MODE_T32,
            UINT64_C(0),
            { UINT8_C(0xd1), UINT8_C(0x88), UINT8_C(0), UINT8_C(0) },
            2,
            "ldrh r1, [r2, #0x6]"
        },
#if USE_EXTRA_OPCODES
        {
            "T32 DCPS1",
            CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_ARM_MODE_T32,
            UINT64_C(0),
            { UINT8_C(0x8f), UINT8_C(0xf7), UINT8_C(0x01), UINT8_C(0x80) },
            4,
            "dcps1"
        },
        {
            "T32 DCPS2",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_T32,
            UINT64_C(0),
            { UINT8_C(0x8f), UINT8_C(0xf7), UINT8_C(0x02), UINT8_C(0x80) },
            4,
            "dcps2"
        },
        {
            "T32 DCPS3",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_T32,
            UINT64_C(0),
            { UINT8_C(0x8f), UINT8_C(0xf7), UINT8_C(0x03), UINT8_C(0x80) },
            4,
            "dcps3"
        }
#endif
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_case(&cases[index]);
    }
}

static void test_a64(void)
{
    static const arm_format_case cases[] = {
        {
            "A64 return",
            CDISASM_ARM_CPU_CORTEX_A34,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0xc0), UINT8_C(0x03), UINT8_C(0x5f), UINT8_C(0xd6) },
            4,
            "ret x30"
        },
        {
            "A64 conditional branch",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0x4000),
            { UINT8_C(0x40), UINT8_C(0x00), UINT8_C(0x00), UINT8_C(0x54) },
            4,
            "b.eq 0x4008"
        },
#if USE_EXTRA_OPCODES
        {
            "A64 generated BC conditional branch",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0x4000),
            { UINT8_C(0x12), UINT8_C(0x40), UINT8_C(0x00), UINT8_C(0x54) },
            4,
            "bc.cs 0x4800"
        },
        {
            "A64 DCPS1 default immediate",
            CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0x01), UINT8_C(0x00), UINT8_C(0xa0), UINT8_C(0xd4) },
            4,
            "dcps1"
        },
        {
            "A64 DCPS1 nonzero immediate",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0x81), UINT8_C(0x46), UINT8_C(0xa2), UINT8_C(0xd4) },
            4,
            "dcps1 #4660"
        },
        {
            "A64 DCPS2 nonzero immediate",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0xe2), UINT8_C(0xdd), UINT8_C(0xb7), UINT8_C(0xd4) },
            4,
            "dcps2 #48879"
        },
        {
            "A64 DCPS3 nonzero immediate",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0xe3), UINT8_C(0xff), UINT8_C(0xbf), UINT8_C(0xd4) },
            4,
            "dcps3 #65535"
        },
        {
            "A64 MTE STG post-index",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0x20), UINT8_C(0x14), UINT8_C(0x20), UINT8_C(0xd9) },
            4,
            "stg x0, [x1], #0x10"
        },
        {
            "A64 MTE STG pre-index",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0x62), UINT8_C(0xfc), UINT8_C(0x3f), UINT8_C(0xd9) },
            4,
            "stg x2, [x3, #-0x10]!"
        },
        {
            "A64 MTE STZG post-index",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0xa4), UINT8_C(0x24), UINT8_C(0x60), UINT8_C(0xd9) },
            4,
            "stzg x4, [x5], #0x20"
        },
        {
            "A64 MTE STZG pre-index",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0xe6), UINT8_C(0xec), UINT8_C(0x7f), UINT8_C(0xd9) },
            4,
            "stzg x6, [x7, #-0x20]!"
        },
        {
            "A64 MTE ST2G post-index",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0x20), UINT8_C(0x24), UINT8_C(0xa0), UINT8_C(0xd9) },
            4, "st2g x0, [x1], #0x20"
        },
        {
            "A64 MTE ST2G offset",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0xa4), UINT8_C(0x48), UINT8_C(0xa0), UINT8_C(0xd9) },
            4, "st2g x4, [x5, #0x40]"
        },
        {
            "A64 MTE STZ2G pre-index",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0x28), UINT8_C(0xcd), UINT8_C(0xff), UINT8_C(0xd9) },
            4, "stz2g x8, [x9, #-0x40]!"
        },
        {
            "A64 MTE2 STGM",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0xac), UINT8_C(0x01), UINT8_C(0xa0), UINT8_C(0xd9) },
            4, "stgm x12, [x13]"
        },
        {
            "A64 MTE2 STZGM",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0xee), UINT8_C(0x01), UINT8_C(0x20), UINT8_C(0xd9) },
            4, "stzgm x14, [x15]"
        },
        {
            "A64 RCpc3 STLR writeback",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0x20), UINT8_C(0x08), UINT8_C(0x80), UINT8_C(0x99) },
            4, "stlr w0, [x1, #-0x4]!"
        },
        {
            "A64 RCpc3 LDAPR writeback",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0xe6), UINT8_C(0x08), UINT8_C(0xc0), UINT8_C(0xd9) },
            4, "ldapr x6, [x7], #0x8"
        },
        {
            "A64 RCpc3 STILP writeback",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0x40), UINT8_C(0x08), UINT8_C(0x01), UINT8_C(0xd9) },
            4, "stilp x0, x1, [x2, #-0x10]!"
        },
        {
            "A64 RCpc3 LDIAPP writeback",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0x40), UINT8_C(0x08), UINT8_C(0x41), UINT8_C(0xd9) },
            4, "ldiapp x0, x1, [x2], #0x10"
        },
        {
            "A64 LDR W literal",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0x1000),
            { UINT8_C(0x20), UINT8_C(0x00), UINT8_C(0x00), UINT8_C(0x18) },
            4, "ldr w0, 0x1004"
        },
        {
            "A64 LDR Q literal",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0x1000),
            { UINT8_C(0x84), UINT8_C(0x00), UINT8_C(0x00), UINT8_C(0x9c) },
            4, "ldr q4, 0x1010"
        },
        {
            "A64 LDRSW literal",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0x1000),
            { UINT8_C(0x85), UINT8_C(0xff), UINT8_C(0xff), UINT8_C(0x98) },
            4, "ldrsw x5, 0xff0"
        },
        {
            "A64 PRFM literal named",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0x1000),
            { UINT8_C(0xa0), UINT8_C(0x00), UINT8_C(0x00), UINT8_C(0xd8) },
            4, "prfm pldl1keep, 0x1014"
        },
        {
            "A64 PRFM literal store-streaming",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0x1000),
            { UINT8_C(0xf5), UINT8_C(0xff), UINT8_C(0xff), UINT8_C(0xd8) },
            4, "prfm pstl3strm, 0xffc"
        },
        {
            "A64 PRFM literal numeric",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0x1000),
            { UINT8_C(0x3f), UINT8_C(0x00), UINT8_C(0x00), UINT8_C(0xd8) },
            4, "prfm #0x1f, 0x1004"
        },
        {
            "A64 SVE2.2 COMPACT B",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0xc5), UINT8_C(0x90), UINT8_C(0x21), UINT8_C(0x05) },
            4, "compact z5.b, p4, z6.b"
        },
        {
            "A64 SVE2.2 COMPACT H",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0x07), UINT8_C(0x95), UINT8_C(0x61), UINT8_C(0x05) },
            4, "compact z7.h, p5, z8.h"
        },
        {
            "A64 SVE COMPACT S",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0x20), UINT8_C(0x80), UINT8_C(0xa1), UINT8_C(0x05) },
            4, "compact z0.s, p0, z1.s"
        },
        {
            "A64 SVE COMPACT D",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0x82), UINT8_C(0x8c), UINT8_C(0xe1), UINT8_C(0x05) },
            4, "compact z2.d, p3, z4.d"
        },
        {
            "A64 SVE2.1 REVD Q merge",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0x61), UINT8_C(0x88), UINT8_C(0x2e), UINT8_C(0x05) },
            4, "revd z1.q, p2/m, z3.q"
        },
        {
            "A64 SVE2.2 REVD Q zero",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0xc4), UINT8_C(0xb4), UINT8_C(0x2e), UINT8_C(0x05) },
            4, "revd z4.q, p5/z, z6.q"
        },
        {
            "A64 SVE2 FLOGB S merge",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0x20), UINT8_C(0xa0), UINT8_C(0x1c), UINT8_C(0x65) },
            4, "flogb z0.s, p0/m, z1.s"
        },
        {
            "A64 SVE2 FLOGB D merge",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0x82), UINT8_C(0xac), UINT8_C(0x1e), UINT8_C(0x65) },
            4, "flogb z2.d, p3/m, z4.d"
        },
        {
            "A64 SVE2.2 FLOGB S zero",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0xc5), UINT8_C(0xd0), UINT8_C(0x1e), UINT8_C(0x64) },
            4, "flogb z5.s, p4/z, z6.s"
        },
        {
            "A64 SVE2.2 FLOGB D zero",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0x07), UINT8_C(0xf5), UINT8_C(0x1e), UINT8_C(0x64) },
            4, "flogb z7.d, p5/z, z8.d"
        },
        {
            "A64 SVE FTMAD S",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0x40), UINT8_C(0x80), UINT8_C(0x93), UINT8_C(0x65) },
            4, "ftmad z0.s, z0.s, z2.s, #0x3"
        },
        {
            "A64 SVE FTMAD D",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0xc4), UINT8_C(0x80), UINT8_C(0xd7), UINT8_C(0x65) },
            4, "ftmad z4.d, z4.d, z6.d, #0x7"
        },
        {
            "A64 SVE2.1 FCLAMP H",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0x20), UINT8_C(0x24), UINT8_C(0x62), UINT8_C(0x64) },
            4, "fclamp z0.h, z1.h, z2.h"
        },
        {
            "A64 SVE2.1 FCLAMP S",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0x83), UINT8_C(0x24), UINT8_C(0xa5), UINT8_C(0x64) },
            4, "fclamp z3.s, z4.s, z5.s"
        },
        {
            "A64 SVE2.1 FCLAMP D",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0xe6), UINT8_C(0x24), UINT8_C(0xe8), UINT8_C(0x64) },
            4, "fclamp z6.d, z7.d, z8.d"
        },
        {
            "A64 SVE BFCLAMP H",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0x49), UINT8_C(0x25), UINT8_C(0x2b), UINT8_C(0x64) },
            4, "bfclamp z9.h, z10.h, z11.h"
        },
        {
            "A64 SVE2.1 FDOT indexed H",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0x20), UINT8_C(0x40), UINT8_C(0x3a), UINT8_C(0x64) },
            4, "fdot z0.s, z1.h, z2.h[3]"
        },
        {
            "A64 SVE BFDOT indexed H",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0x83), UINT8_C(0x40), UINT8_C(0x75), UINT8_C(0x64) },
            4, "bfdot z3.s, z4.h, z5.h[2]"
        },
        {
            "A64 SVE2.1 FDOT H",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0x20), UINT8_C(0x80), UINT8_C(0x22), UINT8_C(0x64) },
            4, "fdot z0.s, z1.h, z2.h"
        },
        {
            "A64 SVE BFDOT H",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0x83), UINT8_C(0x80), UINT8_C(0x65), UINT8_C(0x64) },
            4, "bfdot z3.s, z4.h, z5.h"
        },
        {
            "A64 SVE FP8DOT2 indexed",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0x20), UINT8_C(0x4c), UINT8_C(0x32), UINT8_C(0x64) },
            4, "fdot z0.h, z1.b, z2.b[5]"
        },
        {
            "A64 SVE FP8DOT4 indexed",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0x83), UINT8_C(0x44), UINT8_C(0x75), UINT8_C(0x64) },
            4, "fdot z3.s, z4.b, z5.b[2]"
        },
        {
            "A64 SVE FP8DOT2 vector",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0xe6), UINT8_C(0x84), UINT8_C(0x28), UINT8_C(0x64) },
            4, "fdot z6.h, z7.b, z8.b"
        },
        {
            "A64 SVE FP8DOT4 vector",
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, UINT64_C(0),
            { UINT8_C(0x49), UINT8_C(0x85), UINT8_C(0x6b), UINT8_C(0x64) },
            4, "fdot z9.s, z10.b, z11.b"
        },
#endif
        {
            "A64 always-condition branch",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0x4000),
            { UINT8_C(0x0e), UINT8_C(0x00), UINT8_C(0x00), UINT8_C(0x54) },
            4,
            "b.al 0x4000"
        },
        {
            "A64 never-condition branch",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0x4000),
            { UINT8_C(0x0f), UINT8_C(0x00), UINT8_C(0x00), UINT8_C(0x54) },
            4,
            "b.nv 0x4000"
        },
        {
            "A64 pre-index writeback",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0xfd), UINT8_C(0x7b), UINT8_C(0xbf), UINT8_C(0xa9) },
            4,
            "stp x29, x30, [sp, #-0x10]!"
        },
        {
            "A64 post-index writeback",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0xfd), UINT8_C(0x7b), UINT8_C(0xc1), UINT8_C(0xa8) },
            4,
            "ldp x29, x30, [sp], #0x10"
        },
        {
            "A64 byte register width",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0xe6), UINT8_C(0x50), UINT8_C(0x00), UINT8_C(0x38) },
            4,
            "sturb w6, [x7, #0x5]"
        },
        {
            "A64 halfword register width",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0xe6), UINT8_C(0x50), UINT8_C(0x00), UINT8_C(0x78) },
            4,
            "sturh w6, [x7, #0x5]"
        },
        {
            "A64 shifted add immediate",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0x20), UINT8_C(0x14), UINT8_C(0x40), UINT8_C(0x91) },
            4,
            "add x0, x1, #0x5, lsl #0xc"
        },
        {
            "A64 shifted sub immediate",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0x83), UINT8_C(0x1c), UINT8_C(0x40), UINT8_C(0xd1) },
            4,
            "sub x3, x4, #0x7, lsl #0xc"
        },
        {
            "A64 shifted immediate",
            CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0xa5), UINT8_C(0x79), UINT8_C(0xb5), UINT8_C(0x72) },
            4,
            "movk w5, #0xabcd, lsl #0x10"
        },
        {
            "A64 exclusive byte load",
            CDISASM_ARM_CPU_CORTEX_A34,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0x20), UINT8_C(0x7c), UINT8_C(0x5f), UINT8_C(0x08) },
            4,
            "ldxrb w0, [x1]"
        },
        {
            "A64 acquire-exclusive byte load",
            CDISASM_ARM_CPU_CORTEX_A34,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0xe2), UINT8_C(0xff), UINT8_C(0x5f), UINT8_C(0x08) },
            4,
            "ldaxrb w2, [sp]"
        },
        {
            "A64 exclusive halfword load",
            CDISASM_ARM_CPU_CORTEX_A34,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0x83), UINT8_C(0x7c), UINT8_C(0x5f), UINT8_C(0x48) },
            4,
            "ldxrh w3, [x4]"
        },
        {
            "A64 acquire-exclusive halfword load",
            CDISASM_ARM_CPU_CORTEX_A34,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0xc5), UINT8_C(0xfc), UINT8_C(0x5f), UINT8_C(0x48) },
            4,
            "ldaxrh w5, [x6]"
        },
        {
            "A64 exclusive register load",
            CDISASM_ARM_CPU_CORTEX_A34,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0x8b), UINT8_C(0x7d), UINT8_C(0x5f), UINT8_C(0xc8) },
            4,
            "ldxr x11, [x12]"
        },
        {
            "A64 acquire-exclusive register load",
            CDISASM_ARM_CPU_CORTEX_A34,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0x49), UINT8_C(0xfd), UINT8_C(0x5f), UINT8_C(0x88) },
            4,
            "ldaxr w9, [x10]"
        },
        {
            "A64 exclusive byte store",
            CDISASM_ARM_CPU_CORTEX_A34,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0x41), UINT8_C(0x7c), UINT8_C(0x00), UINT8_C(0x08) },
            4,
            "stxrb w0, w1, [x2]"
        },
        {
            "A64 release-exclusive byte store",
            CDISASM_ARM_CPU_CORTEX_A34,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0xe4), UINT8_C(0xff), UINT8_C(0x03), UINT8_C(0x08) },
            4,
            "stlxrb w3, w4, [sp]"
        },
        {
            "A64 exclusive halfword store",
            CDISASM_ARM_CPU_CORTEX_A34,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0xe6), UINT8_C(0x7c), UINT8_C(0x05), UINT8_C(0x48) },
            4,
            "stxrh w5, w6, [x7]"
        },
        {
            "A64 release-exclusive halfword store",
            CDISASM_ARM_CPU_CORTEX_A34,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0x49), UINT8_C(0xfd), UINT8_C(0x08), UINT8_C(0x48) },
            4,
            "stlxrh w8, w9, [x10]"
        },
        {
            "A64 exclusive register store",
            CDISASM_ARM_CPU_CORTEX_A34,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0x51), UINT8_C(0x7e), UINT8_C(0x10), UINT8_C(0xc8) },
            4,
            "stxr w16, x17, [x18]"
        },
        {
            "A64 release-exclusive register store",
            CDISASM_ARM_CPU_CORTEX_A34,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0x93), UINT8_C(0xfe), UINT8_C(0x1f), UINT8_C(0xc8) },
            4,
            "stlxr wzr, x19, [x20]"
        },
        {
            "A64 exclusive pair load",
            CDISASM_ARM_CPU_CORTEX_A34,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0x40), UINT8_C(0x04), UINT8_C(0x7f), UINT8_C(0x88) },
            4,
            "ldxp w0, w1, [x2]"
        },
        {
            "A64 acquire-exclusive pair load",
            CDISASM_ARM_CPU_CORTEX_A34,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0x48), UINT8_C(0xa5), UINT8_C(0x7f), UINT8_C(0xc8) },
            4,
            "ldaxp x8, x9, [x10]"
        },
        {
            "A64 exclusive pair store",
            CDISASM_ARM_CPU_CORTEX_A34,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0x61), UINT8_C(0x08), UINT8_C(0x20), UINT8_C(0x88) },
            4,
            "stxp w0, w1, w2, [x3]"
        },
        {
            "A64 release-exclusive pair store",
            CDISASM_ARM_CPU_CORTEX_A34,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0xab), UINT8_C(0xb1), UINT8_C(0x3f), UINT8_C(0xc8) },
            4,
            "stlxp wzr, x11, x12, [x13]"
        },
        {
            "A64 acquire byte load",
            CDISASM_ARM_CPU_CORTEX_A34,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0x20), UINT8_C(0xfc), UINT8_C(0xdf), UINT8_C(0x08) },
            4,
            "ldarb w0, [x1]"
        },
        {
            "A64 acquire halfword load",
            CDISASM_ARM_CPU_CORTEX_A34,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0xe2), UINT8_C(0xff), UINT8_C(0xdf), UINT8_C(0x48) },
            4,
            "ldarh w2, [sp]"
        },
        {
            "A64 acquire register load",
            CDISASM_ARM_CPU_CORTEX_A34,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0xc5), UINT8_C(0xfc), UINT8_C(0xdf), UINT8_C(0xc8) },
            4,
            "ldar x5, [x6]"
        },
        {
            "A64 release byte store",
            CDISASM_ARM_CPU_CORTEX_A34,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0x07), UINT8_C(0xfd), UINT8_C(0x9f), UINT8_C(0x08) },
            4,
            "stlrb w7, [x8]"
        },
        {
            "A64 release halfword store",
            CDISASM_ARM_CPU_CORTEX_A34,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0xe9), UINT8_C(0xff), UINT8_C(0x9f), UINT8_C(0x48) },
            4,
            "stlrh w9, [sp]"
        },
        {
            "A64 release register store",
            CDISASM_ARM_CPU_CORTEX_A34,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0xac), UINT8_C(0xfd), UINT8_C(0x9f), UINT8_C(0xc8) },
            4,
            "stlr x12, [x13]"
        }
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_case(&cases[index]);
    }
}

static void test_vectors_and_apple(void)
{
    static const arm_format_case cases[] = {
        {
            "A32 NEON lanes",
            CDISASM_ARM_CPU_CORTEX_A9_NEON,
            CDISASM_ARM_MODE_A32,
            UINT64_C(0),
            { UINT8_C(0xa0), UINT8_C(0x08), UINT8_C(0x41), UINT8_C(0xf2) },
            4,
            "vadd.i8 d16, d17, d16"
        },
        {
            "A64 vector arrangement",
            CDISASM_ARM_CPU_APPLE_A11,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0x20), UINT8_C(0x84), UINT8_C(0x22), UINT8_C(0x4e) },
            4,
            "add v0.16b, v1.16b, v2.16b"
        },
        {
            "A64 floating vector arrangement",
            CDISASM_ARM_CPU_APPLE_M5,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0x20), UINT8_C(0xdc), UINT8_C(0x62), UINT8_C(0x6e) },
            4,
            "fmul v0.2d, v1.2d, v2.2d"
        },
        {
            "Apple AMX",
            CDISASM_ARM_CPU_APPLE_M1,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0x60), UINT8_C(0x12), UINT8_C(0x20), UINT8_C(0x00) },
            4,
            "vecfp x0"
        },
        {
            "Apple MUL53",
            CDISASM_ARM_CPU_APPLE_A11,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0x01), UINT8_C(0x04), UINT8_C(0x20), UINT8_C(0x00) },
            4,
            "mul53hi.2d v1, v0"
        },
        {
            "Apple barrier option",
            CDISASM_ARM_CPU_APPLE_M5,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0x63), UINT8_C(0x14), UINT8_C(0x20), UINT8_C(0x00) },
            4,
            "sdsb sy"
        },
        {
            "Apple system register",
            CDISASM_ARM_CPU_APPLE_A7,
            CDISASM_ARM_MODE_A64,
            UINT64_C(0),
            { UINT8_C(0x00), UINT8_C(0xf2), UINT8_C(0x3f), UINT8_C(0xd5) },
            4,
            "mrs x0, cpm_ioacc_ctl_el3"
        }
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_case(&cases[index]);
    }
}

static void test_format_flags(void)
{
    static const arm_format_case conditional = {
        "format flags conditional",
        CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64,
        UINT64_C(0),
        { UINT8_C(0x40), UINT8_C(0x00), UINT8_C(0x00), UINT8_C(0x54) },
        4,
        "b.eq 0x8"
    };
    static const arm_format_case neon = {
        "format flags NEON",
        CDISASM_ARM_CPU_CORTEX_A9_NEON,
        CDISASM_ARM_MODE_A32,
        UINT64_C(0),
        { UINT8_C(0xa0), UINT8_C(0x08), UINT8_C(0x41), UINT8_C(0xf2) },
        4,
        "vadd.i8 d16, d17, d16"
    };
    cdisasm_arm_instruction instruction;
    char text[128];
    uint32_t syntax;

    EXPECT(CDISASM_FORMAT_SYNTAX_MASK == UINT32_C(0x07));
    EXPECT(CDISASM_FORMAT_UPPERCASE_OPCODE == UINT32_C(0x08));
    EXPECT(CDISASM_FORMAT_KNOWN_FLAGS_MASK == UINT32_C(0x0f));

    if (!decode_case(&conditional, &instruction)) {
        return;
    }
    for (syntax = CDISASM_FORMAT_SYNTAX_0;
         syntax <= CDISASM_FORMAT_SYNTAX_7;
         ++syntax) {
        EXPECT(cdisasm_arm_format(
                   &instruction, syntax, text, sizeof(text))
            == strlen(conditional.expected));
        EXPECT(strcmp(text, conditional.expected) == 0);
    }
    EXPECT(cdisasm_arm_format(
               &instruction,
               CDISASM_FORMAT_SYNTAX_4
                   | CDISASM_FORMAT_UPPERCASE_OPCODE,
               text,
               sizeof(text))
        == strlen("B.EQ 0x8"));
    EXPECT(strcmp(text, "B.EQ 0x8") == 0);

    if (!decode_case(&neon, &instruction)) {
        return;
    }
    EXPECT(cdisasm_arm_format(
               &instruction,
               CDISASM_FORMAT_UPPERCASE_OPCODE,
               text,
               sizeof(text))
        == strlen("VADD.I8 d16, d17, d16"));
    EXPECT(strcmp(text, "VADD.I8 d16, d17, d16") == 0);

    memcpy(text, "invalid", sizeof("invalid"));
    EXPECT(cdisasm_arm_format(
               &instruction, UINT32_C(0x10), text, sizeof(text))
        == 0);
    EXPECT(text[0] == '\0');
}

static void test_buffer_contract_and_invalid_metadata(void)
{
    static const arm_format_case add = {
        "buffer contract",
        CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A32,
        UINT64_C(0),
        { UINT8_C(0x05), UINT8_C(0x00), UINT8_C(0x81), UINT8_C(0xe2) },
        4,
        "add r0, r1, #0x5"
    };
    static const arm_format_case atomic = {
        "atomic metadata validation",
        CDISASM_ARM_CPU_CORTEX_A34,
        CDISASM_ARM_MODE_A64,
        UINT64_C(0),
        { UINT8_C(0x20), UINT8_C(0xfc), UINT8_C(0xdf), UINT8_C(0x08) },
        4,
        "ldarb w0, [x1]"
    };
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction atomic_instruction;
    cdisasm_arm_instruction invalid;
    char truncated[5];
    char one[1] = { 'x' };
    char untouched = 'q';
    char error_buffer[8] = "invalid";
    size_t expected_size = strlen(add.expected);

    if (!decode_case(&add, &instruction)) {
        return;
    }

    EXPECT(cdisasm_arm_format(
               &instruction,
               CDISASM_FORMAT_SYNTAX_0,
               truncated,
               sizeof(truncated))
        == expected_size);
    EXPECT(strcmp(truncated, "add ") == 0);
    EXPECT(cdisasm_arm_format(
               &instruction, CDISASM_FORMAT_SYNTAX_0, one, sizeof(one))
        == expected_size);
    EXPECT(one[0] == '\0');
    EXPECT(cdisasm_arm_format(
               &instruction, CDISASM_FORMAT_SYNTAX_0, &untouched, 0)
        == expected_size);
    EXPECT(untouched == 'q');
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_0, NULL, 1) == 0);

    EXPECT(cdisasm_arm_format(
               NULL,
               CDISASM_FORMAT_SYNTAX_0,
               error_buffer,
               sizeof(error_buffer))
        == 0);
    EXPECT(error_buffer[0] == '\0');

    invalid = instruction;
    invalid.last_error_id = (uint8_t)CDISASM_STATUS_INVALID_ARGUMENT;
    memcpy(error_buffer, "invalid", sizeof("invalid"));
    EXPECT(cdisasm_arm_format(
               &invalid,
               CDISASM_FORMAT_SYNTAX_0,
               error_buffer,
               sizeof(error_buffer))
        == 0);
    EXPECT(error_buffer[0] == '\0');

    invalid = instruction;
    invalid.name_id = CDISASM_ARM_NAME_COUNT;
    EXPECT(cdisasm_arm_format(
               &invalid,
               CDISASM_FORMAT_SYNTAX_0,
               error_buffer,
               sizeof(error_buffer))
        == 0);

    invalid = instruction;
    invalid.operand_count = CDISASM_ARM_MAX_OPERANDS + 1u;
    EXPECT(cdisasm_arm_format(
               &invalid,
               CDISASM_FORMAT_SYNTAX_0,
               error_buffer,
               sizeof(error_buffer))
        == 0);

    invalid = instruction;
    invalid.condition = UINT8_C(16);
    EXPECT(cdisasm_arm_format(
               &invalid,
               CDISASM_FORMAT_SYNTAX_0,
               error_buffer,
               sizeof(error_buffer))
        == 0);

    invalid = instruction;
    invalid.operand[0].reg = CDISASM_ARM_REG_COUNT;
    EXPECT(cdisasm_arm_format(
               &invalid,
               CDISASM_FORMAT_SYNTAX_0,
               error_buffer,
               sizeof(error_buffer))
        == 0);

    invalid = instruction;
    invalid.operand[0].access = CDISASM_OPERAND_ACCESS_NONE;
    EXPECT(cdisasm_arm_format(
               &invalid,
               CDISASM_FORMAT_SYNTAX_0,
               error_buffer,
               sizeof(error_buffer))
        == 0);

    if (!decode_case(&atomic, &atomic_instruction)) {
        return;
    }
    invalid = atomic_instruction;
    invalid.instruction_flags &= ~CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC;
    EXPECT(cdisasm_arm_format(
               &invalid,
               CDISASM_FORMAT_SYNTAX_0,
               error_buffer,
               sizeof(error_buffer))
        == 0);

    invalid = atomic_instruction;
    invalid.operand[1].access = CDISASM_OPERAND_ACCESS_WRITE;
    EXPECT(cdisasm_arm_format(
               &invalid,
               CDISASM_FORMAT_SYNTAX_0,
               error_buffer,
               sizeof(error_buffer))
        == 0);
}

static void test_a64_extra_atomic(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        { "CASAL X", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xea, 0xff, 0xe9, 0xc8 }, 4,
          "casal x9, x10, [sp]" },
        { "CASPAL X pairs", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xee, 0xff, 0x6c, 0x48 }, 4,
          "caspal x12, x13, x14, x15, [sp]" },
        { "LDADDAL X", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xea, 0x03, 0xe9, 0xf8 }, 4,
          "ldaddal x9, x10, [sp]" },
        { "LDCLRAH", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xa4, 0x10, 0xa3, 0x78 }, 4,
          "ldclrah w3, w4, [x5]" },
        { "LDEORLB", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x07, 0x21, 0x66, 0x38 }, 4,
          "ldeorlb w6, w7, [x8]" },
        { "LDSETAB", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xa4, 0x30, 0xa3, 0x38 }, 4,
          "ldsetab w3, w4, [x5]" },
        { "SWPALB", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xea, 0x83, 0xe9, 0x38 }, 4,
          "swpalb w9, w10, [sp]" },
        { "LDLAR X", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xe6, 0x7f, 0xdf, 0xc8 }, 4,
          "ldlar x6, [sp]" },
        { "STLLR X", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xe6, 0x7f, 0x9f, 0xc8 }, 4,
          "stllr x6, [sp]" },
        { "LDAPR X", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xe6, 0xc3, 0xbf, 0xf8 }, 4,
          "ldapr x6, [sp]" },
        { "CASP compare W30/WZR", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0x40, 0x7c, 0x3e, 0x08 }, 4,
          "casp w30, wzr, w0, w1, [x2]" },
        { "CASP compare X30/XZR", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0x40, 0x7c, 0x3e, 0x48 }, 4,
          "casp x30, xzr, x0, x1, [x2]" },
        { "CASP desired W30/WZR", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0x9e, 0x7c, 0x20, 0x08 }, 4,
          "casp w0, w1, w30, wzr, [x4]" },
        { "CASP desired X30/XZR", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0x9e, 0x7c, 0x20, 0x48 }, 4,
          "casp x0, x1, x30, xzr, [x4]" },
        { "LDADDAB discarded result", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0x5f, 0x00, 0xa0, 0x38 }, 4,
          "ldaddab w0, wzr, [x2]" },
        { "LDCLRALH discarded result", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0x5f, 0x10, 0xe0, 0x78 }, 4,
          "ldclralh w0, wzr, [x2]" },
        { "LDEORA discarded result", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0x5f, 0x20, 0xa0, 0xb8 }, 4,
          "ldeora w0, wzr, [x2]" },
        { "LDSETAL discarded result", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0x5f, 0x30, 0xe0, 0xf8 }, 4,
          "ldsetal x0, xzr, [x2]" },
        { "SWPA discarded result", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0x5f, 0x80, 0xa0, 0xf8 }, 4,
          "swpa x0, xzr, [x2]" }
    };
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction invalid;
    char text[128];
    size_t index;
    size_t operand_index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_case(&cases[index]);
    }
    EXPECT(decode_case(&cases[1], &instruction));
    EXPECT(cdisasm_arm_format(
               &instruction,
               CDISASM_FORMAT_SYNTAX_0 | CDISASM_FORMAT_UPPERCASE_OPCODE,
               text,
               sizeof(text))
        == strlen("CASPAL x12, x13, x14, x15, [sp]"));
    EXPECT(strcmp(text, "CASPAL x12, x13, x14, x15, [sp]") == 0);
    instruction.operand[0].access = CDISASM_OPERAND_ACCESS_READ;
    EXPECT(cdisasm_arm_format(
               &instruction,
               CDISASM_FORMAT_SYNTAX_0,
               text,
               sizeof(text))
        == 0u);
    EXPECT(text[0] == '\0');

    if (decode_case(&cases[10], &instruction)) {
        invalid = instruction;
        invalid.operand[0].index_reg = CDISASM_ARM_REG_WSP;
        EXPECT(cdisasm_arm_format(
                   &invalid, CDISASM_FORMAT_SYNTAX_0,
                   text, sizeof(text))
            == 0u);
        EXPECT(text[0] == '\0');
    }
    if (decode_case(&cases[13], &instruction)) {
        invalid = instruction;
        invalid.operand[1].index_reg = CDISASM_ARM_REG_SP;
        EXPECT(cdisasm_arm_format(
                   &invalid, CDISASM_FORMAT_SYNTAX_0,
                   text, sizeof(text))
            == 0u);
        EXPECT(text[0] == '\0');
    }

    /* Every optional atomic family has a fixed public operand schema. */
    if (decode_case(&cases[0], &instruction)) {
        invalid = instruction;
        invalid.operand_count = 1u;
        invalid.operand[0] = invalid.operand[2];
        memset(&invalid.operand[1], 0,
               sizeof(invalid.operand[1]) * 3u);
        EXPECT(cdisasm_arm_format(
                   &invalid, CDISASM_FORMAT_SYNTAX_0,
                   text, sizeof(text))
            == 0u);

        invalid = instruction;
        invalid.operand[0].reg = CDISASM_ARM_REG_SP;
        EXPECT(cdisasm_arm_format(
                   &invalid, CDISASM_FORMAT_SYNTAX_0,
                   text, sizeof(text))
            == 0u);

        invalid = instruction;
        invalid.operand[2].size = 4u;
        EXPECT(cdisasm_arm_format(
                   &invalid, CDISASM_FORMAT_SYNTAX_0,
                   text, sizeof(text))
            == 0u);
    }
    if (decode_case(&cases[2], &instruction)) {
        invalid = instruction;
        invalid.operand_count = 1u;
        invalid.operand[0] = invalid.operand[2];
        memset(&invalid.operand[1], 0,
               sizeof(invalid.operand[1]) * 3u);
        EXPECT(cdisasm_arm_format(
                   &invalid, CDISASM_FORMAT_SYNTAX_0,
                   text, sizeof(text))
            == 0u);

        invalid = instruction;
        invalid.operand[0].access = CDISASM_OPERAND_ACCESS_WRITE;
        EXPECT(cdisasm_arm_format(
                   &invalid, CDISASM_FORMAT_SYNTAX_0,
                   text, sizeof(text))
            == 0u);

        invalid = instruction;
        invalid.operand[2].index_reg = CDISASM_ARM_REG_X0;
        EXPECT(cdisasm_arm_format(
                   &invalid, CDISASM_FORMAT_SYNTAX_0,
                   text, sizeof(text))
            == 0u);
    }
    if (decode_case(&cases[7], &instruction)) {
        invalid = instruction;
        invalid.operand_count = 1u;
        invalid.operand[0] = invalid.operand[1];
        memset(&invalid.operand[1], 0,
               sizeof(invalid.operand[1]) * 3u);
        EXPECT(cdisasm_arm_format(
                   &invalid, CDISASM_FORMAT_SYNTAX_0,
                   text, sizeof(text))
            == 0u);

        invalid = instruction;
        invalid.operand[1].size = 4u;
        EXPECT(cdisasm_arm_format(
                   &invalid, CDISASM_FORMAT_SYNTAX_0,
                   text, sizeof(text))
            == 0u);
    }
    if (decode_case(&cases[9], &instruction)) {
        invalid = instruction;
        invalid.operand_count = 1u;
        invalid.operand[0] = invalid.operand[1];
        memset(&invalid.operand[1], 0,
               sizeof(invalid.operand[1]) * 3u);
        EXPECT(cdisasm_arm_format(
                   &invalid, CDISASM_FORMAT_SYNTAX_0,
                   text, sizeof(text))
            == 0u);

        invalid = instruction;
        invalid.operand[0].reg = CDISASM_ARM_REG_SP;
        EXPECT(cdisasm_arm_format(
                   &invalid, CDISASM_FORMAT_SYNTAX_0,
                   text, sizeof(text))
            == 0u);
    }

    /* Atomic register operands have fixed, undecorated encodings. Reject
     * forged shift/extend metadata for every optional schema, including both
     * CAS/CASP roles and the LOR load/store forms. */
    {
        static const size_t decorated_case_indices[] = {
            0u, 1u, 2u, 7u, 8u, 9u
        };

        for (index = 0;
             index < sizeof(decorated_case_indices)
                 / sizeof(decorated_case_indices[0]);
             ++index) {
            EXPECT(decode_case(
                &cases[decorated_case_indices[index]], &instruction));

            invalid = instruction;
            invalid.instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_BYTE;
            EXPECT(cdisasm_arm_format(
                       &invalid, CDISASM_FORMAT_SYNTAX_0,
                       text, sizeof(text))
                == 0u);
            EXPECT(text[0] == '\0');

            invalid = instruction;
            invalid.instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
                | CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX;
            EXPECT(cdisasm_arm_format(
                       &invalid, CDISASM_FORMAT_SYNTAX_0,
                       text, sizeof(text))
                == 0u);
            EXPECT(text[0] == '\0');

            for (operand_index = 0u;
                 operand_index < instruction.operand_count;
                 ++operand_index) {
                if (instruction.operand[operand_index].type
                        != CDISASM_OPERAND_REGISTER
                    && instruction.operand[operand_index].type
                        != CDISASM_ARM_OPERAND_REGISTER_PAIR) {
                    continue;
                }

                invalid = instruction;
                invalid.operand[operand_index].shift_type
                    = CDISASM_ARM_SHIFT_LSL;
                invalid.operand[operand_index].shift_amount = 1u;
                EXPECT(cdisasm_arm_format(
                           &invalid, CDISASM_FORMAT_SYNTAX_0,
                           text, sizeof(text))
                    == 0u);
                EXPECT(text[0] == '\0');

                invalid = instruction;
                invalid.operand[operand_index].extend_type
                    = CDISASM_ARM_EXTEND_UXTW;
                invalid.operand[operand_index].scale = 1u;
                EXPECT(cdisasm_arm_format(
                           &invalid, CDISASM_FORMAT_SYNTAX_0,
                           text, sizeof(text))
                    == 0u);
                EXPECT(text[0] == '\0');
            }
        }
    }
#else
    cdisasm_arm_instruction instruction;
    char text[32] = "untouched";

    memset(&instruction, 0, sizeof(instruction));
    instruction.opcode_size = 4u;
    instruction.name_id = CDISASM_ARM_NAME_CAS;
    instruction.condition = CDISASM_ARM_CONDITION_AL;
    instruction.isa_id = CDISASM_ARM_ISA_A64;
    instruction.instruction_flags = CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC;
    EXPECT(cdisasm_arm_format(
               &instruction,
               CDISASM_FORMAT_SYNTAX_0,
               text,
               sizeof(text))
        == 0u);
    EXPECT(text[0] == '\0');
#endif
}

static void test_generated_opaque_formatting(void)
{
#if USE_EXTRA_OPCODES
    cdisasm_arm_instruction instruction;
    char text[64];

    /* Exact catalog text remains available even when structured operands are
     * intentionally opaque to callers. */
    memset(&instruction, 0, sizeof(instruction));
    instruction.opcode_size = 4u;
    instruction.raw_instruction = UINT32_C(0xd4a24681);
    instruction.name_id = CDISASM_ARM_NAME_DCPS1;
    instruction.condition = CDISASM_ARM_CONDITION_AL;
    instruction.isa_id = CDISASM_ARM_ISA_A64;
    instruction.form_id = UINT16_C(4453);
    instruction.instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
        | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
    EXPECT(cdisasm_arm_format(
               &instruction, CDISASM_FORMAT_SYNTAX_0, NULL, 0)
        == strlen("dcps1 #4660"));
    EXPECT(cdisasm_arm_format(
               &instruction, CDISASM_FORMAT_SYNTAX_0, text, sizeof(text))
        == strlen("dcps1 #4660"));
    EXPECT(strcmp(text, "dcps1 #4660") == 0);

    /* The reviewed PSTATE selector now has an exact numeric recipe. */
    memset(&instruction, 0, sizeof(instruction));
    instruction.opcode_size = 4u;
    instruction.raw_instruction = UINT32_C(0xd50341df);
    instruction.name_id = CDISASM_ARM_NAME_MSR;
    instruction.condition = CDISASM_ARM_CONDITION_AL;
    instruction.isa_id = CDISASM_ARM_ISA_A64;
    instruction.form_id = UINT16_C(4498);
    instruction.instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
        | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
    EXPECT(cdisasm_arm_format(
               &instruction, CDISASM_FORMAT_SYNTAX_0, NULL, 0)
        == strlen("msr daifset, #1"));
    strcpy(text, "not empty");
    EXPECT(cdisasm_arm_format(
               &instruction, CDISASM_FORMAT_SYNTAX_0, text, sizeof(text))
        == strlen("msr daifset, #1"));
    EXPECT(strcmp(text, "msr daifset, #1") == 0);

    /* An unallocated PSTATE selector still has no exact recipe. */
    instruction.raw_instruction = UINT32_C(0xd501441f);
    strcpy(text, "not empty");
    EXPECT(cdisasm_arm_format(
               &instruction, CDISASM_FORMAT_SYNTAX_0, text, sizeof(text))
        == 0u);
    EXPECT(text[0] == '\0');

    /* D128 system-register pairs must start at an even X register. */
    instruction.raw_instruction = UINT32_C(0xd5581003);
    instruction.name_id = CDISASM_ARM_NAME_MSRR;
    instruction.form_id = UINT16_C(4507);
    EXPECT(cdisasm_arm_format(
               &instruction, CDISASM_FORMAT_SYNTAX_0, text, sizeof(text))
        == 0u);
#endif
}

static void test_advsimd_aes(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        { "A64 AESE", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x20, 0x48, 0x28, 0x4e }, 4, "aese v0.16b, v1.16b" },
        { "A64 AESD", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x62, 0x58, 0x28, 0x4e }, 4, "aesd v2.16b, v3.16b" },
        { "A64 AESMC", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xa4, 0x68, 0x28, 0x4e }, 4, "aesmc v4.16b, v5.16b" },
        { "A64 AESIMC", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xfe, 0x7b, 0x28, 0x4e }, 4, "aesimc v30.16b, v31.16b" }
    };
    static const cdisasm_arm_form_id forms[] = { 5727, 5728, 5729, 5730 };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_arm_instruction instruction;

        expect_case(&cases[index]);
        if (decode_case(&cases[index], &instruction)) {
            EXPECT(instruction.form_id == forms[index]);
            EXPECT(instruction.instruction_flags
                == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
            EXPECT(instruction.operand_count == 2u);
            EXPECT(instruction.operand[0].access
                == (index < 2u ? CDISASM_OPERAND_ACCESS_READ_WRITE
                               : CDISASM_OPERAND_ACCESS_WRITE));
            EXPECT(instruction.operand[1].access
                == CDISASM_OPERAND_ACCESS_READ);
        }
    }
#endif
}

static void test_advsimd_integer_reductions(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        { "A64 SMAXV", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x20, 0xa8, 0x30, 0x4e }, 4, "smaxv b0, v1.16b" },
        { "A64 SMINV", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x62, 0xa8, 0x71, 0x4e }, 4, "sminv h2, v3.8h" },
        { "A64 UMAXV", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xa4, 0xa8, 0xb0, 0x6e }, 4, "umaxv s4, v5.4s" },
        { "A64 UMINV", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xfe, 0xab, 0x31, 0x2e }, 4, "uminv b30, v31.8b" }
    };
    static const cdisasm_arm_form_id forms[] = { 6075, 6076, 6083, 6084 };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_arm_instruction instruction;

        expect_case(&cases[index]);
        if (decode_case(&cases[index], &instruction)) {
            EXPECT(instruction.form_id == forms[index]);
            EXPECT(instruction.instruction_flags
                == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
            EXPECT(instruction.operand_count == 2u);
            EXPECT(instruction.operand[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            EXPECT(instruction.operand[1].access
                == CDISASM_OPERAND_ACCESS_READ);
        }
    }
#endif
}

static void test_advsimd_integer_unary_scalar(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        { "A64 SUQADD scalar", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x20, 0x38, 0x20, 0x5e }, 4, "suqadd b0, b1" },
        { "A64 SQABS scalar", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x62, 0x78, 0x60, 0x5e }, 4, "sqabs h2, h3" },
        { "A64 CMGT scalar zero", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xa4, 0x88, 0xe0, 0x5e }, 4, "cmgt d4, d5, #0x0" },
        { "A64 CMEQ scalar zero", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xe6, 0x98, 0xe0, 0x5e }, 4, "cmeq d6, d7, #0x0" },
        { "A64 ABS scalar", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x28, 0xb9, 0xe0, 0x5e }, 4, "abs d8, d9" },
        { "A64 USQADD scalar", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x6a, 0x39, 0xa0, 0x7e }, 4, "usqadd s10, s11" },
        { "A64 SQNEG scalar", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xac, 0x79, 0xe0, 0x7e }, 4, "sqneg d12, d13" },
        { "A64 CMGE scalar zero", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xee, 0x89, 0xe0, 0x7e }, 4, "cmge d14, d15, #0x0" },
        { "A64 NEG scalar", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xfe, 0xbb, 0xe0, 0x7e }, 4, "neg d30, d31" }
    };
    static const cdisasm_arm_form_id forms[] = {
        5773, 5774, 5775, 5776, 5778, 5791, 5792, 5793, 5795
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_arm_instruction instruction;

        expect_case(&cases[index]);
        if (decode_case(&cases[index], &instruction)) {
            EXPECT(instruction.form_id == forms[index]);
            EXPECT(instruction.instruction_flags
                == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
            EXPECT(instruction.operand[0].access
                == (index == 0u || index == 5u
                    ? CDISASM_OPERAND_ACCESS_READ_WRITE
                    : CDISASM_OPERAND_ACCESS_WRITE));
            EXPECT(instruction.operand[1].access
                == CDISASM_OPERAND_ACCESS_READ);
        }
    }
#endif
}

static void test_advsimd_unsigned_estimates(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        { "A64 URECPE", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x20, 0xc8, 0xa1, 0x0e }, 4, "urecpe v0.2s, v1.2s" },
        { "A64 URSQRTE", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xfe, 0xcb, 0xa1, 0x6e }, 4, "ursqrte v30.4s, v31.4s" }
    };
    static const cdisasm_arm_form_id forms[] = { 6035, 6069 };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_arm_instruction instruction;

        expect_case(&cases[index]);
        if (decode_case(&cases[index], &instruction)) {
            EXPECT(instruction.form_id == forms[index]);
            EXPECT(instruction.instruction_flags
                == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
            EXPECT(instruction.operand_count == 2u);
            EXPECT(instruction.operand[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            EXPECT(instruction.operand[1].access
                == CDISASM_OPERAND_ACCESS_READ);
        }
    }
#endif
}

static void test_advsimd_frecpx_scalar(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        { "A64 FRECPX H", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x20, 0xf8, 0xf9, 0x5e }, 4, "frecpx h0, h1" },
        { "A64 FRECPX S", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x62, 0xf8, 0xa1, 0x5e }, 4, "frecpx s2, s3" },
        { "A64 FRECPX D", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xfe, 0xfb, 0xe1, 0x5e }, 4, "frecpx d30, d31" }
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_arm_instruction instruction;

        expect_case(&cases[index]);
        if (decode_case(&cases[index], &instruction)) {
            EXPECT(instruction.form_id == (index == 0u ? 5761u : 5790u));
            EXPECT(instruction.instruction_flags
                == CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT);
            EXPECT(instruction.operand_count == 2u);
            EXPECT(instruction.operand[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            EXPECT(instruction.operand[1].access
                == CDISASM_OPERAND_ACCESS_READ);
        }
    }
#endif
}

static void test_fprcvt_fcvtns_scalar(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        { "A64 FPRCVT FCVTNS S,D", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0x20, 0x00, 0x6a, 0x1e }, 4, "fcvtns s0, d1" },
        { "A64 FPRCVT FCVTNS S,H", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0x62, 0x00, 0xea, 0x1e }, 4, "fcvtns s2, h3" },
        { "A64 FPRCVT FCVTNS D,H", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0xa4, 0x00, 0xea, 0x9e }, 4, "fcvtns d4, h5" },
        { "A64 FPRCVT FCVTNS D,S", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0xfe, 0x03, 0x2a, 0x9e }, 4, "fcvtns d30, s31" }
    };
    static const cdisasm_arm_form_id forms[] = { 6411, 6423, 6435, 6447 };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_arm_instruction instruction;

        expect_case(&cases[index]);
        if (decode_case(&cases[index], &instruction)) {
            EXPECT(instruction.form_id == forms[index]);
            EXPECT(instruction.instruction_flags
                == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
                    | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
            EXPECT(instruction.operand_count == 2u);
            EXPECT(instruction.operand[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            EXPECT(instruction.operand[1].access
                == CDISASM_OPERAND_ACCESS_READ);
        }
    }
#endif
}

static void test_fprcvt_remaining_scalar(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        { "A64 FPRCVT FCVTAS", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
          0, { 0x20, 0x00, 0x7a, 0x1e }, 4, "fcvtas s0, d1" },
        { "A64 FPRCVT FCVTPS", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
          0, { 0x62, 0x00, 0xf2, 0x1e }, 4, "fcvtps s2, h3" },
        { "A64 FPRCVT FCVTMS", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
          0, { 0xa4, 0x00, 0xf4, 0x9e }, 4, "fcvtms d4, h5" },
        { "A64 FPRCVT FCVTZS", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
          0, { 0xfe, 0x03, 0x36, 0x9e }, 4, "fcvtzs d30, s31" },
        { "A64 FPRCVT SCVTF", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
          0, { 0x01, 0x00, 0x7c, 0x1e }, 4, "scvtf d1, s0" },
        { "A64 FPRCVT FCVTNU", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
          0, { 0x62, 0x00, 0xeb, 0x1e }, 4, "fcvtnu s2, h3" },
        { "A64 FPRCVT FCVTAU", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
          0, { 0xa4, 0x00, 0xfb, 0x9e }, 4, "fcvtau d4, h5" },
        { "A64 FPRCVT FCVTPU", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
          0, { 0xfe, 0x03, 0x33, 0x9e }, 4, "fcvtpu d30, s31" },
        { "A64 FPRCVT FCVTMU", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
          0, { 0x20, 0x00, 0x75, 0x1e }, 4, "fcvtmu s0, d1" },
        { "A64 FPRCVT FCVTZU", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
          0, { 0x62, 0x00, 0xf7, 0x1e }, 4, "fcvtzu s2, h3" },
        { "A64 FPRCVT UCVTF", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
          0, { 0x85, 0x00, 0xfd, 0x9e }, 4, "ucvtf h5, d4" }
    };
    static const cdisasm_arm_form_id forms[] = {
        6412, 6425, 6438, 6451, 6416, 6429,
        6442, 6455, 6420, 6433, 6446
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_arm_instruction instruction;

        expect_case(&cases[index]);
        if (decode_case(&cases[index], &instruction)) {
            EXPECT(instruction.form_id == forms[index]);
            EXPECT(instruction.instruction_flags
                == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
                    | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
            EXPECT(instruction.operand_count == 2u);
            EXPECT(instruction.operand[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            EXPECT(instruction.operand[1].access
                == CDISASM_OPERAND_ACCESS_READ);
        }
    }
#endif
}

static void test_advsimd_fcvtn_narrow(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        { "A64 FP8 FCVTN S to B", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0x20, 0xf4, 0x02, 0x0e }, 4,
          "fcvtn v0.8b, v1.4s, v2.4s" },
        { "A64 FP8 FCVTN2 S to B", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0x83, 0xf4, 0x05, 0x4e }, 4,
          "fcvtn2 v3.16b, v4.4s, v5.4s" },
        { "A64 FP8 FCVTN H to B", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0xe6, 0xf4, 0x48, 0x0e }, 4,
          "fcvtn v6.8b, v7.4h, v8.4h" },
        { "A64 FP8 FCVTN H to B Q", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0x49, 0xf5, 0x4b, 0x4e }, 4,
          "fcvtn v9.16b, v10.8h, v11.8h" },
        { "A64 FCVTN S to H", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0xac, 0x69, 0x21, 0x0e }, 4,
          "fcvtn v12.4h, v13.4s" },
        { "A64 FCVTN2 S to H", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0xee, 0x69, 0x21, 0x4e }, 4,
          "fcvtn2 v14.8h, v15.4s" },
        { "A64 FCVTN D to S", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0x30, 0x6a, 0x61, 0x0e }, 4,
          "fcvtn v16.2s, v17.2d" },
        { "A64 FCVTN2 D to S", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0x72, 0x6a, 0x61, 0x4e }, 4,
          "fcvtn2 v18.4s, v19.2d" },
        { "A64 BFCVTN", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0xb4, 0x6a, 0xa1, 0x0e }, 4,
          "bfcvtn v20.4h, v21.4s" },
        { "A64 BFCVTN2", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0xf6, 0x6a, 0xa1, 0x4e }, 4,
          "bfcvtn2 v22.8h, v23.4s" }
    };
    static const cdisasm_arm_form_id forms[] = {
        5976, 5976, 5978, 5978, 6017, 6017, 6017, 6017, 6037, 6037
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_arm_instruction instruction;

        expect_case(&cases[index]);
        if (decode_case(&cases[index], &instruction)) {
            EXPECT(instruction.form_id == forms[index]);
            EXPECT(instruction.instruction_flags
                == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
                    | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
            EXPECT(instruction.operand_count
                == (index < 4u ? 3u : 2u));
            EXPECT(instruction.operand[0].access
                == ((index == 1u || index == 5u
                        || index == 7u || index == 9u)
                    ? CDISASM_OPERAND_ACCESS_READ_WRITE
                    : CDISASM_OPERAND_ACCESS_WRITE));
        }
    }
#endif
}

static void test_advsimd_scalar_cvt_fixed(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        { "A64 Advanced SIMD SCVTF S", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0x20, 0xd8, 0x21, 0x5e }, 4, "scvtf s0, s1" },
        { "A64 Advanced SIMD SCVTF D", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0x62, 0xd8, 0x61, 0x5e }, 4, "scvtf d2, d3" },
        { "A64 Advanced SIMD FCVTZS S", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0xa4, 0xb8, 0xa1, 0x5e }, 4, "fcvtzs s4, s5" },
        { "A64 Advanced SIMD FCVTZS D", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0xe6, 0xb8, 0xe1, 0x5e }, 4, "fcvtzs d6, d7" },
        { "A64 Advanced SIMD UCVTF S", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0x28, 0xd9, 0x21, 0x7e }, 4, "ucvtf s8, s9" },
        { "A64 Advanced SIMD UCVTF D", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0x6a, 0xd9, 0x61, 0x7e }, 4, "ucvtf d10, d11" },
        { "A64 Advanced SIMD FCVTZU S", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0xac, 0xb9, 0xa1, 0x7e }, 4, "fcvtzu s12, s13" },
        { "A64 Advanced SIMD FCVTZU D", CDISASM_ARM_CPU_ANY,
          CDISASM_ARM_MODE_A64, 0,
          { 0xfe, 0xbb, 0xe1, 0x7e }, 4, "fcvtzu d30, d31" }
    };
    static const cdisasm_arm_form_id forms[] = {
        5783, 5783, 5788, 5788, 5802, 5802, 5806, 5806
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_arm_instruction instruction;

        expect_case(&cases[index]);
        if (decode_case(&cases[index], &instruction)) {
            EXPECT(instruction.form_id == forms[index]);
            EXPECT(instruction.instruction_flags
                == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
                    | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
            EXPECT(instruction.operand_count == 2u);
            EXPECT(instruction.operand[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            EXPECT(instruction.operand[1].access
                == CDISASM_OPERAND_ACCESS_READ);
        }
    }
#endif
}

static void test_advsimd_fp_reductions(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        { "A64 FMAXNMV 4H", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x20, 0xc8, 0x30, 0x0e }, 4, "fmaxnmv h0, v1.4h" },
        { "A64 FMAXNMV 8H", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x62, 0xc8, 0x30, 0x4e }, 4, "fmaxnmv h2, v3.8h" },
        { "A64 FMAXV 4H", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xa4, 0xf8, 0x30, 0x0e }, 4, "fmaxv h4, v5.4h" },
        { "A64 FMAXV 8H", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xe6, 0xf8, 0x30, 0x4e }, 4, "fmaxv h6, v7.8h" },
        { "A64 FMINNMV 4H", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x28, 0xc9, 0xb0, 0x0e }, 4, "fminnmv h8, v9.4h" },
        { "A64 FMINNMV 8H", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x6a, 0xc9, 0xb0, 0x4e }, 4, "fminnmv h10, v11.8h" },
        { "A64 FMINV 4H", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xac, 0xf9, 0xb0, 0x0e }, 4, "fminv h12, v13.4h" },
        { "A64 FMINV 8H", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xfe, 0xfb, 0xb0, 0x4e }, 4, "fminv h30, v31.8h" },
        { "A64 FMAXNMV 4S", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x20, 0xc8, 0x30, 0x6e }, 4, "fmaxnmv s0, v1.4s" },
        { "A64 FMAXV 4S", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x62, 0xf8, 0x30, 0x6e }, 4, "fmaxv s2, v3.4s" },
        { "A64 FMINNMV 4S", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xa4, 0xc8, 0xb0, 0x6e }, 4, "fminnmv s4, v5.4s" },
        { "A64 FMINV 4S", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xfe, 0xfb, 0xb0, 0x6e }, 4, "fminv s30, v31.4s" }
    };
    static const cdisasm_arm_form_id forms[] = {
        6078, 6078, 6079, 6079, 6080, 6080,
        6081, 6081, 6085, 6086, 6087, 6088
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_arm_instruction instruction;

        expect_case(&cases[index]);
        if (decode_case(&cases[index], &instruction)) {
            EXPECT(instruction.form_id == forms[index]);
            EXPECT(instruction.instruction_flags
                == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
                    | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
            EXPECT(instruction.operand_count == 2u);
            EXPECT(instruction.operand[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            EXPECT(instruction.operand[1].access
                == CDISASM_OPERAND_ACCESS_READ);
        }
    }
#endif
}

static void test_advsimd_faminmax_fscale(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        { "A64 FAMAX 4H", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x20, 0x1c, 0xc2, 0x0e }, 4, "famax v0.4h, v1.4h, v2.4h" },
        { "A64 FAMAX 8H", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x83, 0x1c, 0xc5, 0x4e }, 4, "famax v3.8h, v4.8h, v5.8h" },
        { "A64 FAMIN 4H", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xe6, 0x1c, 0xc8, 0x2e }, 4, "famin v6.4h, v7.4h, v8.4h" },
        { "A64 FAMIN 8H", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x49, 0x1d, 0xcb, 0x6e }, 4, "famin v9.8h, v10.8h, v11.8h" },
        { "A64 FSCALE 4H", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xac, 0x3d, 0xce, 0x2e }, 4, "fscale v12.4h, v13.4h, v14.4h" },
        { "A64 FSCALE 8H", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x0f, 0x3e, 0xd1, 0x6e }, 4, "fscale v15.8h, v16.8h, v17.8h" },
        { "A64 FAMAX 2S", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x72, 0xde, 0xb4, 0x0e }, 4, "famax v18.2s, v19.2s, v20.2s" },
        { "A64 FAMAX 4S", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xd5, 0xde, 0xb7, 0x4e }, 4, "famax v21.4s, v22.4s, v23.4s" },
        { "A64 FAMAX 2D", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x38, 0xdf, 0xfa, 0x4e }, 4, "famax v24.2d, v25.2d, v26.2d" },
        { "A64 FAMIN 2S", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x20, 0xdc, 0xa2, 0x2e }, 4, "famin v0.2s, v1.2s, v2.2s" },
        { "A64 FAMIN 4S", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x83, 0xdc, 0xa5, 0x6e }, 4, "famin v3.4s, v4.4s, v5.4s" },
        { "A64 FAMIN 2D", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xe6, 0xdc, 0xe8, 0x6e }, 4, "famin v6.2d, v7.2d, v8.2d" },
        { "A64 FSCALE 2S", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x49, 0xfd, 0xab, 0x2e }, 4, "fscale v9.2s, v10.2s, v11.2s" },
        { "A64 FSCALE 4S", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xac, 0xfd, 0xae, 0x6e }, 4, "fscale v12.4s, v13.4s, v14.4s" },
        { "A64 FSCALE 2D", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x0f, 0xfe, 0xf1, 0x6e }, 4, "fscale v15.2d, v16.2d, v17.2d" }
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_arm_instruction instruction;

        expect_case(&cases[index]);
        if (decode_case(&cases[index], &instruction)) {
            EXPECT(instruction.instruction_flags
                == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
                    | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
            EXPECT(instruction.operand_count == 3u);
            EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
            EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.operand[2].access == CDISASM_OPERAND_ACCESS_READ);
        }
    }
#endif
}

static void test_sve_gather_load_32(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        { "A64 SVE LD1W gather UXTW", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x20, 0x40, 0x02, 0x85 }, 4, "ld1w {z0.s}, p0/z, [x1, z2.s, uxtw]" },
        { "A64 SVE LD1B gather SXTW", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x83, 0x44, 0x45, 0x84 }, 4, "ld1b {z3.s}, p1/z, [x4, z5.s, sxtw]" },
        { "A64 SVE LD1H gather UXTW", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xe6, 0x48, 0x88, 0x84 }, 4, "ld1h {z6.s}, p2/z, [x7, z8.s, uxtw]" },
        { "A64 SVE LD1H gather scaled", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x49, 0x4d, 0xab, 0x84 }, 4, "ld1h {z9.s}, p3/z, [x10, z11.s, uxtw #0x1]" },
        { "A64 SVE LD1W gather scaled", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0xac, 0x51, 0x6e, 0x85 }, 4, "ld1w {z12.s}, p4/z, [x13, z14.s, sxtw #0x2]" },
        { "A64 SVE LD1W vector base", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x0f, 0xd6, 0x3f, 0x85 }, 4, "ld1w {z15.s}, p5/z, [z16.s, #0x7c]" },
        { "A64 SVE LD1B vector base", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x51, 0xda, 0x3f, 0x84 }, 4, "ld1b {z17.s}, p6/z, [z18.s, #0x1f]" },
        { "A64 SVE LD1H vector base", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0,
          { 0x93, 0xde, 0xbf, 0x84 }, 4, "ld1h {z19.s}, p7/z, [z20.s, #0x3e]" }
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_arm_instruction instruction;
        expect_case(&cases[index]);
        if (decode_case(&cases[index], &instruction)) {
            EXPECT(instruction.instruction_flags
                == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                    | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
            EXPECT(instruction.operand_count == 3u);
            EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
            EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.operand[2].access == CDISASM_OPERAND_ACCESS_READ);
        }
    }
#endif
}

static void test_sve_gather_load_64(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        { "SVE LD1D D UXTW", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0, { 0x20,0x40,0x82,0xc5 },4,"ld1d {z0.d}, p0/z, [x1, z2.d, uxtw]" },
        { "SVE LD1B D SXTW", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0, { 0x83,0x44,0x45,0xc4 },4,"ld1b {z3.d}, p1/z, [x4, z5.d, sxtw]" },
        { "SVE LD1H D UXTW", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0, { 0xe6,0x48,0x88,0xc4 },4,"ld1h {z6.d}, p2/z, [x7, z8.d, uxtw]" },
        { "SVE LD1W D SXTW", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0, { 0x49,0x4d,0x4b,0xc5 },4,"ld1w {z9.d}, p3/z, [x10, z11.d, sxtw]" },
        { "SVE LD1D D scaled", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0, { 0xac,0x51,0xae,0xc5 },4,"ld1d {z12.d}, p4/z, [x13, z14.d, uxtw #0x3]" },
        { "SVE LD1H D scaled", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0, { 0x0f,0x56,0xf1,0xc4 },4,"ld1h {z15.d}, p5/z, [x16, z17.d, sxtw #0x1]" },
        { "SVE LD1W D scaled", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0, { 0x72,0x5a,0x34,0xc5 },4,"ld1w {z18.d}, p6/z, [x19, z20.d, uxtw #0x2]" },
        { "SVE LD1D D vector base", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0, { 0xd5,0xde,0xbf,0xc5 },4,"ld1d {z21.d}, p7/z, [z22.d, #0xf8]" },
        { "SVE LD1B D vector base", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0, { 0x17,0xc3,0x3f,0xc4 },4,"ld1b {z23.d}, p0/z, [z24.d, #0x1f]" },
        { "SVE LD1H D vector base", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0, { 0x59,0xc7,0xbf,0xc4 },4,"ld1h {z25.d}, p1/z, [z26.d, #0x3e]" },
        { "SVE LD1W D vector base", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0, { 0x9b,0xcb,0x3f,0xc5 },4,"ld1w {z27.d}, p2/z, [z28.d, #0x7c]" },
        { "SVE LD1D D index", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0, { 0xdd,0xcf,0xdf,0xc5 },4,"ld1d {z29.d}, p3/z, [x30, z31.d]" },
        { "SVE LD1B D index", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0, { 0xe0,0xd3,0x41,0xc4 },4,"ld1b {z0.d}, p4/z, [sp, z1.d]" },
        { "SVE LD1H D index", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0, { 0x62,0xd4,0xc4,0xc4 },4,"ld1h {z2.d}, p5/z, [x3, z4.d]" },
        { "SVE LD1W D index", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0, { 0xc5,0xd8,0x47,0xc5 },4,"ld1w {z5.d}, p6/z, [x6, z7.d]" },
        { "SVE LD1D D LSL", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0, { 0x28,0xdd,0xea,0xc5 },4,"ld1d {z8.d}, p7/z, [x9, z10.d, lsl #0x3]" },
        { "SVE LD1H D LSL", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0, { 0x8b,0xc1,0xed,0xc4 },4,"ld1h {z11.d}, p0/z, [x12, z13.d, lsl #0x1]" },
        { "SVE LD1W D LSL", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0, { 0xee,0xc5,0x70,0xc5 },4,"ld1w {z14.d}, p1/z, [x15, z16.d, lsl #0x2]" }
        ,{ "SVE2.1 LD1Q vector base", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0, { 0x20,0xa0,0x1f,0xc4 },4,"ld1q {z0.q}, p0/z, [z1.d]" }
        ,{ "SVE2.1 LD1Q scalar index", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0, { 0x82,0xac,0x05,0xc4 },4,"ld1q {z2.q}, p3/z, [z4.d, x5]" }
        ,{ "SVE2.1 LD1Q XZR omitted", CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0, { 0xdf,0xbf,0x1f,0xc4 },4,"ld1q {z31.q}, p7/z, [z30.d]" }
    };
    size_t index;
    for (index=0u; index<sizeof(cases)/sizeof(cases[0]); ++index) {
        cdisasm_arm_instruction instruction;
        expect_case(&cases[index]);
        if (decode_case(&cases[index], &instruction)) {
            EXPECT(instruction.instruction_flags
                == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                    | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
            EXPECT(instruction.operand_count == 3u);
            EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
            EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.operand[2].access == CDISASM_OPERAND_ACCESS_READ);
        }
    }
#endif
}

static void test_sve_scatter_store(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        { "SVE ST1B D UXTW",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x20,0x80,0x02,0xe4},4,"st1b {z0.d}, p0, [x1, z2.d, uxtw]" },
        { "SVE ST1H S SXTW",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x0f,0xd6,0xd1,0xe4},4,"st1h {z15.s}, p5, [x16, z17.s, sxtw]" },
        { "SVE ST1D D scaled",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x9b,0x87,0xbd,0xe5},4,"st1d {z27.d}, p1, [x28, z29.d, uxtw #0x3]" },
        { "SVE ST1W D index",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x6a,0xb9,0x0c,0xe5},4,"st1w {z10.d}, p6, [x11, z12.d]" },
        { "SVE ST1H D LSL",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x30,0xa2,0xb2,0xe4},4,"st1h {z16.d}, p0, [x17, z18.d, lsl #0x1]" },
        { "SVE ST1W S vector base",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xc5,0xa4,0x7f,0xe5},4,"st1w {z5.s}, p1, [z6.s, #0x7c]" }
        ,{ "SVE2.1 ST1Q vector base",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x20,0x20,0x3f,0xe4},4,"st1q {z0.q}, p0, [z1.d]" }
        ,{ "SVE2.1 ST1Q scalar index",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x82,0x2c,0x25,0xe4},4,"st1q {z2.q}, p3, [z4.d, x5]" }
        ,{ "SVE2.1 ST1Q XZR omitted",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xdf,0x3f,0x3f,0xe4},4,"st1q {z31.q}, p7, [z30.d]" }
    };
    size_t index;
    for(index=0u;index<sizeof(cases)/sizeof(cases[0]);++index){
        cdisasm_arm_instruction instruction; expect_case(&cases[index]);
        if(decode_case(&cases[index],&instruction)){
            EXPECT(instruction.instruction_flags
                ==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                    |CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
            EXPECT(instruction.operand_count==3u);
            EXPECT(instruction.operand[0].access==CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.operand[1].access==CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.operand[2].access==CDISASM_OPERAND_ACCESS_WRITE);
        }
    }
#endif
}

static void test_sme_movt(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        {"SME2 MOVT extract zero",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xe0,0x03,0x4c,0xc0},4,"movt x0, zt0[0]"},
        {"SME2 MOVT extract max",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xfe,0x73,0x4c,0xc0},4,"movt x30, zt0[56]"},
        {"SME2 MOVT insert zero",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xe1,0x03,0x4e,0xc0},4,"movt zt0[0], x1"},
        {"SME2 MOVT insert offset",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xe2,0x13,0x4e,0xc0},4,"movt zt0[8], x2"},
        {"SME LUTv2 MOVT vector zero",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xe2,0x03,0x4f,0xc0},4,"movt zt0, z2"},
        {"SME LUTv2 MOVT vector offset",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xe3,0x13,0x4f,0xc0},4,"movt zt0[1, mul vl], z3"},
        {"SME LUTv2 MOVT vector max",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xff,0x33,0x4f,0xc0},4,"movt zt0[3, mul vl], z31"}
    };
    size_t index;
    for(index=0u;index<sizeof(cases)/sizeof(cases[0]);++index){
        cdisasm_arm_instruction instruction; expect_case(&cases[index]);
        if(decode_case(&cases[index],&instruction)){
            uint32_t expected=CDISASM_ARM_INSTRUCTION_FLAG_SME
                |CDISASM_ARM_INSTRUCTION_FLAG_MATRIX;
            if(index>=4u) expected|=CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR;
            EXPECT(instruction.instruction_flags==expected);
            EXPECT(instruction.operand_count==2u);
        }
    }
#endif
}

static void test_sme2_indexed_multi2_s(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        {"SME2 FMLA indexed multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x00,0x00,0x50,0xc1},4,"fmla za.s[w8, 0, vgx2], {z0.s, z1.s}, z0.s[0]"},
        {"SME2 FMLS indexed multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xd7,0x6f,0x5f,0xc1},4,"fmls za.s[w11, 7, vgx2], {z30.s, z31.s}, z15.s[3]"},
        {"SME2 SDOT H indexed multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x00,0x10,0x50,0xc1},4,"sdot za.s[w8, 0, vgx2], {z0.h, z1.h}, z0.h[0]"},
        {"SME2 FDOT H indexed multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x49,0x34,0x53,0xc1},4,"fdot za.s[w9, 1, vgx2], {z2.h, z3.h}, z3.h[1]"},
        {"SME2 UDOT H indexed multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x92,0x54,0x54,0xc1},4,"udot za.s[w10, 2, vgx2], {z4.h, z5.h}, z4.h[1]"},
        {"SME2 BFDOT indexed multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xdb,0x74,0x55,0xc1},4,"bfdot za.s[w11, 3, vgx2], {z6.h, z7.h}, z5.h[1]"},
        {"SME2 SDOT B indexed multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x24,0x1d,0x56,0xc1},4,"sdot za.s[w8, 4, vgx2], {z8.b, z9.b}, z6.b[3]"},
        {"SME2 UDOT B indexed multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x75,0x3d,0x57,0xc1},4,"udot za.s[w9, 5, vgx2], {z10.b, z11.b}, z7.b[3]"},
        {"SME F8F32 FDOT indexed multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xbe,0x4d,0x58,0xc1},4,"fdot za.s[w10, 6, vgx2], {z12.b, z13.b}, z8.b[3]"}
    };
    size_t index;
    for(index=0u;index<sizeof(cases)/sizeof(cases[0]);++index){
        cdisasm_arm_instruction instruction; expect_case(&cases[index]);
        if(decode_case(&cases[index],&instruction)){
            uint32_t expected=CDISASM_ARM_INSTRUCTION_FLAG_SME
                |CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
                |CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR;
            if(index<2u||index==3u||index==5u||index==8u)
                expected|=CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
            EXPECT(instruction.instruction_flags==expected);
            EXPECT(instruction.operand_count==3u);
            EXPECT(instruction.operand[0].access==CDISASM_OPERAND_ACCESS_READ_WRITE);
            EXPECT(instruction.operand[1].access==CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.operand[2].access==CDISASM_OPERAND_ACCESS_READ);
        }
    }
#endif
}

static void test_sme2_indexed_multi4_s(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        {"SME2 FMLA indexed multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x00,0x80,0x50,0xc1},4,"fmla za.s[w8, 0, vgx4], {z0.s, z1.s, z2.s, z3.s}, z0.s[0]"},
        {"SME2 FMLS indexed multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x97,0xef,0x5f,0xc1},4,"fmls za.s[w11, 7, vgx4], {z28.s, z29.s, z30.s, z31.s}, z15.s[3]"},
        {"SME2 SDOT H indexed multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x00,0x90,0x50,0xc1},4,"sdot za.s[w8, 0, vgx4], {z0.h, z1.h, z2.h, z3.h}, z0.h[0]"},
        {"SME2 FDOT H indexed multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x89,0xb4,0x53,0xc1},4,"fdot za.s[w9, 1, vgx4], {z4.h, z5.h, z6.h, z7.h}, z3.h[1]"},
        {"SME2 UDOT H indexed multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x12,0xd5,0x54,0xc1},4,"udot za.s[w10, 2, vgx4], {z8.h, z9.h, z10.h, z11.h}, z4.h[1]"},
        {"SME2 BFDOT indexed multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x9b,0xf5,0x55,0xc1},4,"bfdot za.s[w11, 3, vgx4], {z12.h, z13.h, z14.h, z15.h}, z5.h[1]"},
        {"SME2 SDOT B indexed multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x24,0x9e,0x56,0xc1},4,"sdot za.s[w8, 4, vgx4], {z16.b, z17.b, z18.b, z19.b}, z6.b[3]"},
        {"SME2 UDOT B indexed multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xb5,0xbe,0x57,0xc1},4,"udot za.s[w9, 5, vgx4], {z20.b, z21.b, z22.b, z23.b}, z7.b[3]"},
        {"SME F8F32 FDOT indexed multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x0e,0xcf,0x58,0xc1},4,"fdot za.s[w10, 6, vgx4], {z24.b, z25.b, z26.b, z27.b}, z8.b[3]"}
    };
    size_t index;
    for(index=0u;index<sizeof(cases)/sizeof(cases[0]);++index){
        cdisasm_arm_instruction instruction; expect_case(&cases[index]);
        if(decode_case(&cases[index],&instruction)){
            uint32_t expected=CDISASM_ARM_INSTRUCTION_FLAG_SME
                |CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
                |CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR;
            if(index<2u||index==3u||index==5u||index==8u)
                expected|=CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
            EXPECT(instruction.instruction_flags==expected);
            EXPECT(instruction.operand_count==3u);
            EXPECT(instruction.operand[0].access==CDISASM_OPERAND_ACCESS_READ_WRITE);
            EXPECT(instruction.operand[1].access==CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.operand[2].access==CDISASM_OPERAND_ACCESS_READ);
        }
    }
#endif
}

static void test_sme_indexed_fp8_fdot_h(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        {"SME F8F16 FDOT indexed multi2 low",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x20,0x00,0xd0,0xc1},4,"fdot za.h[w8, 0, vgx2], {z0.b, z1.b}, z0.b[0]"},
        {"SME F8F16 FDOT indexed multi2 high",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xef,0x6f,0xdf,0xc1},4,"fdot za.h[w11, 7, vgx2], {z30.b, z31.b}, z15.b[7]"},
        {"SME F8F16 FDOT indexed multi4 low",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x40,0x90,0x10,0xc1},4,"fdot za.h[w8, 0, vgx4], {z0.b, z1.b, z2.b, z3.b}, z0.b[0]"},
        {"SME F8F16 FDOT indexed multi4 high",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xcf,0xff,0x1f,0xc1},4,"fdot za.h[w11, 7, vgx4], {z28.b, z29.b, z30.b, z31.b}, z15.b[7]"}
    };
    size_t index;
    for(index=0u;index<sizeof(cases)/sizeof(cases[0]);++index){
        cdisasm_arm_instruction instruction; expect_case(&cases[index]);
        if(decode_case(&cases[index],&instruction)){
            EXPECT(instruction.instruction_flags
                ==(CDISASM_ARM_INSTRUCTION_FLAG_SME
                    |CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
                    |CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                    |CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
            EXPECT(instruction.operand_count==3u);
            EXPECT(instruction.operand[0].access==CDISASM_OPERAND_ACCESS_READ_WRITE);
            EXPECT(instruction.operand[1].access==CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.operand[2].access==CDISASM_OPERAND_ACCESS_READ);
        }
    }
#endif
}

static void test_sme2_multi2_long_mla_single(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        {"SME2 SMLAL multi2 single",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x00,0x08,0x60,0xc1},4,"smlal za.s[w8, 0:1, vgx2], {z0.h, z1.h}, z0.h"},
        {"SME2 SMLSL multi2 single",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x49,0x28,0x63,0xc1},4,"smlsl za.s[w9, 2:3, vgx2], {z2.h, z3.h}, z3.h"},
        {"SME2 UMLAL multi2 single",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x92,0x48,0x64,0xc1},4,"umlal za.s[w10, 4:5, vgx2], {z4.h, z5.h}, z4.h"},
        {"SME2 UMLSL multi2 single",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xdb,0x6b,0x6f,0xc1},4,"umlsl za.s[w11, 6:7, vgx2], {z30.h, z31.h}, z15.h"}
    };
    size_t index;
    for(index=0u;index<sizeof(cases)/sizeof(cases[0]);++index){
        cdisasm_arm_instruction instruction; expect_case(&cases[index]);
        if(decode_case(&cases[index],&instruction)){
            EXPECT(instruction.instruction_flags
                ==(CDISASM_ARM_INSTRUCTION_FLAG_SME
                    |CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
                    |CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR));
            EXPECT(instruction.operand_count==3u);
            EXPECT(instruction.operand[0].access==CDISASM_OPERAND_ACCESS_READ_WRITE);
            EXPECT(instruction.operand[1].access==CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.operand[2].access==CDISASM_OPERAND_ACCESS_READ);
        }
    }
#endif
}

static void test_sme2_single_long_mla(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        {"SME2 SMLAL single",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x00,0x0c,0x60,0xc1},4,"smlal za.s[w8, 0:1], z0.h, z0.h"},
        {"SME2 SMLSL single",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x49,0x2c,0x63,0xc1},4,"smlsl za.s[w9, 2:3], z2.h, z3.h"},
        {"SME2 UMLAL single",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x92,0x4c,0x64,0xc1},4,"umlal za.s[w10, 4:5], z4.h, z4.h"},
        {"SME2 UMLSL single",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xfb,0x6f,0x6f,0xc1},4,"umlsl za.s[w11, 6:7], z31.h, z15.h"}
    };
    size_t index;
    for(index=0u;index<sizeof(cases)/sizeof(cases[0]);++index){
        cdisasm_arm_instruction instruction; expect_case(&cases[index]);
        if(decode_case(&cases[index],&instruction)){
            EXPECT(instruction.instruction_flags
                ==(CDISASM_ARM_INSTRUCTION_FLAG_SME
                    |CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
                    |CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR));
            EXPECT(instruction.operand_count==3u);
            EXPECT(instruction.operand[0].access==CDISASM_OPERAND_ACCESS_READ_WRITE);
            EXPECT(instruction.operand[1].access==CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.operand[2].access==CDISASM_OPERAND_ACCESS_READ);
        }
    }
#endif
}

static void test_sme_multi2_fdot_single(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        {"SME2 FDOT H multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x00,0x10,0x20,0xc1},4,"fdot za.s[w8, 0, vgx2], {z0.h, z1.h}, z0.h"},
        {"SME2 BFDOT H multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x51,0x30,0x23,0xc1},4,"bfdot za.s[w9, 1, vgx2], {z2.h, z3.h}, z3.h"},
        {"SME F8F16 FDOT B multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x8a,0x50,0x24,0xc1},4,"fdot za.h[w10, 2, vgx2], {z4.b, z5.b}, z4.b"},
        {"SME F8F32 FDOT B multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xdf,0x73,0x2f,0xc1},4,"fdot za.s[w11, 7, vgx2], {z30.b, z31.b}, z15.b"},
        {"SME2 FDOT H multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x00,0x10,0x30,0xc1},4,"fdot za.s[w8, 0, vgx4], {z0.h, z1.h, z2.h, z3.h}, z0.h"},
        {"SME2 BFDOT H multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x91,0x30,0x33,0xc1},4,"bfdot za.s[w9, 1, vgx4], {z4.h, z5.h, z6.h, z7.h}, z3.h"},
        {"SME F8F16 FDOT B multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x0a,0x51,0x34,0xc1},4,"fdot za.h[w10, 2, vgx4], {z8.b, z9.b, z10.b, z11.b}, z4.b"},
        {"SME F8F32 FDOT B multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x9f,0x73,0x3f,0xc1},4,"fdot za.s[w11, 7, vgx4], {z28.b, z29.b, z30.b, z31.b}, z15.b"},
        {"SME2 FDOT H two lists",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x00,0x10,0xa0,0xc1},4,"fdot za.s[w8, 0, vgx2], {z0.h, z1.h}, {z0.h, z1.h}"},
        {"SME2 BFDOT H two lists",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x51,0x30,0xa4,0xc1},4,"bfdot za.s[w9, 1, vgx2], {z2.h, z3.h}, {z4.h, z5.h}"},
        {"SME F8F16 FDOT B two lists",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xe2,0x50,0xa8,0xc1},4,"fdot za.h[w10, 2, vgx2], {z6.b, z7.b}, {z8.b, z9.b}"},
        {"SME F8F32 FDOT B two lists",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xf7,0x73,0xae,0xc1},4,"fdot za.s[w11, 7, vgx2], {z30.b, z31.b}, {z14.b, z15.b}"},
        {"SME2 FDOT H four lists",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x00,0x10,0xa1,0xc1},4,"fdot za.s[w8, 0, vgx4], {z0.h, z1.h, z2.h, z3.h}, {z0.h, z1.h, z2.h, z3.h}"},
        {"SME2 BFDOT H four lists",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x91,0x30,0xa9,0xc1},4,"bfdot za.s[w9, 1, vgx4], {z4.h, z5.h, z6.h, z7.h}, {z8.h, z9.h, z10.h, z11.h}"},
        {"SME F8F16 FDOT B four lists",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xa2,0x51,0xb1,0xc1},4,"fdot za.h[w10, 2, vgx4], {z12.b, z13.b, z14.b, z15.b}, {z16.b, z17.b, z18.b, z19.b}"},
        {"SME F8F32 FDOT B four lists",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xb7,0x73,0xb9,0xc1},4,"fdot za.s[w11, 7, vgx4], {z28.b, z29.b, z30.b, z31.b}, {z24.b, z25.b, z26.b, z27.b}"}
    };
    size_t index;
    for(index=0u;index<sizeof(cases)/sizeof(cases[0]);++index){
        cdisasm_arm_instruction instruction; expect_case(&cases[index]);
        if(decode_case(&cases[index],&instruction)){
            EXPECT(instruction.instruction_flags
                ==(CDISASM_ARM_INSTRUCTION_FLAG_SME
                    |CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
                    |CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                    |CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
            EXPECT(instruction.operand_count==3u);
            EXPECT(instruction.operand[0].access==CDISASM_OPERAND_ACCESS_READ_WRITE);
            EXPECT(instruction.operand[1].access==CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.operand[2].access==CDISASM_OPERAND_ACCESS_READ);
        }
    }
#endif
}

static void test_sme_multi2_integer_dot_single(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        {"SME2 SDOT B multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x00,0x14,0x20,0xc1},4,"sdot za.s[w8, 0, vgx2], {z0.b, z1.b}, z0.b"},
        {"SME I16I64 SDOT H multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x41,0x34,0x63,0xc1},4,"sdot za.d[w9, 1, vgx2], {z2.h, z3.h}, z3.h"},
        {"SME2 UDOT B multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x92,0x54,0x24,0xc1},4,"udot za.s[w10, 2, vgx2], {z4.b, z5.b}, z4.b"},
        {"SME I16I64 UDOT H multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xd7,0x77,0x6f,0xc1},4,"udot za.d[w11, 7, vgx2], {z30.h, z31.h}, z15.h"},
        {"SME2 USDOT multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xcb,0x14,0x25,0xc1},4,"usdot za.s[w8, 3, vgx2], {z6.b, z7.b}, z5.b"},
        {"SME2 SUDOT multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x1c,0x35,0x26,0xc1},4,"sudot za.s[w9, 4, vgx2], {z8.b, z9.b}, z6.b"},
        {"SME2 SDOT H to S multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x4d,0x55,0x67,0xc1},4,"sdot za.s[w10, 5, vgx2], {z10.h, z11.h}, z7.h"},
        {"SME2 UDOT H to S multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x9e,0x75,0x68,0xc1},4,"udot za.s[w11, 6, vgx2], {z12.h, z13.h}, z8.h"},
        {"SME2 SDOT B multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x00,0x14,0x30,0xc1},4,"sdot za.s[w8, 0, vgx4], {z0.b, z1.b, z2.b, z3.b}, z0.b"},
        {"SME I16I64 SDOT H multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x81,0x34,0x73,0xc1},4,"sdot za.d[w9, 1, vgx4], {z4.h, z5.h, z6.h, z7.h}, z3.h"},
        {"SME2 UDOT B multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x12,0x55,0x34,0xc1},4,"udot za.s[w10, 2, vgx4], {z8.b, z9.b, z10.b, z11.b}, z4.b"},
        {"SME I16I64 UDOT H multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x97,0x77,0x7f,0xc1},4,"udot za.d[w11, 7, vgx4], {z28.h, z29.h, z30.h, z31.h}, z15.h"},
        {"SME2 USDOT multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x8b,0x15,0x35,0xc1},4,"usdot za.s[w8, 3, vgx4], {z12.b, z13.b, z14.b, z15.b}, z5.b"},
        {"SME2 SUDOT multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x1c,0x36,0x36,0xc1},4,"sudot za.s[w9, 4, vgx4], {z16.b, z17.b, z18.b, z19.b}, z6.b"},
        {"SME2 SDOT H to S multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x8d,0x56,0x77,0xc1},4,"sdot za.s[w10, 5, vgx4], {z20.h, z21.h, z22.h, z23.h}, z7.h"},
        {"SME2 UDOT H to S multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x1e,0x77,0x78,0xc1},4,"udot za.s[w11, 6, vgx4], {z24.h, z25.h, z26.h, z27.h}, z8.h"}
    };
    size_t index;
    for(index=0u;index<sizeof(cases)/sizeof(cases[0]);++index){
        cdisasm_arm_instruction instruction; expect_case(&cases[index]);
        if(decode_case(&cases[index],&instruction)){
            EXPECT(instruction.instruction_flags
                ==(CDISASM_ARM_INSTRUCTION_FLAG_SME
                    |CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
                    |CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR));
            EXPECT(instruction.operand_count==3u);
            EXPECT(instruction.operand[0].access==CDISASM_OPERAND_ACCESS_READ_WRITE);
            EXPECT(instruction.operand[1].access==CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.operand[2].access==CDISASM_OPERAND_ACCESS_READ);
        }
    }
#endif
}

static void test_sme_multi2_arith_single(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        {"SME FMLA S multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x00,0x18,0x20,0xc1},4,"fmla za.s[w8, 0, vgx2], {z0.s, z1.s}, z0.s"},
        {"SME FMLA D multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x41,0x38,0x63,0xc1},4,"fmla za.d[w9, 1, vgx2], {z2.d, z3.d}, z3.d"},
        {"SME FMLS S multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x8a,0x58,0x24,0xc1},4,"fmls za.s[w10, 2, vgx2], {z4.s, z5.s}, z4.s"},
        {"SME FMLS D multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xcf,0x7b,0x6f,0xc1},4,"fmls za.d[w11, 7, vgx2], {z30.d, z31.d}, z15.d"},
        {"SME ADD S multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xd3,0x18,0x25,0xc1},4,"add za.s[w8, 3, vgx2], {z6.s, z7.s}, z5.s"},
        {"SME ADD D multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x14,0x39,0x66,0xc1},4,"add za.d[w9, 4, vgx2], {z8.d, z9.d}, z6.d"},
        {"SME SUB S multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x5d,0x59,0x27,0xc1},4,"sub za.s[w10, 5, vgx2], {z10.s, z11.s}, z7.s"},
        {"SME SUB D multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x9e,0x79,0x68,0xc1},4,"sub za.d[w11, 6, vgx2], {z12.d, z13.d}, z8.d"},
        {"SME F16F16 FMLA multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x00,0x1c,0x20,0xc1},4,"fmla za.h[w8, 0, vgx2], {z0.h, z1.h}, z0.h"},
        {"SME B16B16 BFMLA multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x41,0x3c,0x63,0xc1},4,"bfmla za.h[w9, 1, vgx2], {z2.h, z3.h}, z3.h"},
        {"SME F16F16 FMLS multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x8a,0x5c,0x24,0xc1},4,"fmls za.h[w10, 2, vgx2], {z4.h, z5.h}, z4.h"},
        {"SME B16B16 BFMLS multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xcf,0x7f,0x6f,0xc1},4,"bfmls za.h[w11, 7, vgx2], {z30.h, z31.h}, z15.h"},
        {"SME FMLA S multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x00,0x18,0x30,0xc1},4,"fmla za.s[w8, 0, vgx4], {z0.s, z1.s, z2.s, z3.s}, z0.s"},
        {"SME FMLA D multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x81,0x38,0x73,0xc1},4,"fmla za.d[w9, 1, vgx4], {z4.d, z5.d, z6.d, z7.d}, z3.d"},
        {"SME FMLS S multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x0a,0x59,0x34,0xc1},4,"fmls za.s[w10, 2, vgx4], {z8.s, z9.s, z10.s, z11.s}, z4.s"},
        {"SME FMLS D multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x8f,0x7b,0x7f,0xc1},4,"fmls za.d[w11, 7, vgx4], {z28.d, z29.d, z30.d, z31.d}, z15.d"},
        {"SME ADD S multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x93,0x19,0x35,0xc1},4,"add za.s[w8, 3, vgx4], {z12.s, z13.s, z14.s, z15.s}, z5.s"},
        {"SME ADD D multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x14,0x3a,0x76,0xc1},4,"add za.d[w9, 4, vgx4], {z16.d, z17.d, z18.d, z19.d}, z6.d"},
        {"SME SUB S multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x9d,0x5a,0x37,0xc1},4,"sub za.s[w10, 5, vgx4], {z20.s, z21.s, z22.s, z23.s}, z7.s"},
        {"SME SUB D multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x1e,0x7b,0x78,0xc1},4,"sub za.d[w11, 6, vgx4], {z24.d, z25.d, z26.d, z27.d}, z8.d"},
        {"SME F16F16 FMLA multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x00,0x1c,0x30,0xc1},4,"fmla za.h[w8, 0, vgx4], {z0.h, z1.h, z2.h, z3.h}, z0.h"},
        {"SME B16B16 BFMLA multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x81,0x3c,0x73,0xc1},4,"bfmla za.h[w9, 1, vgx4], {z4.h, z5.h, z6.h, z7.h}, z3.h"},
        {"SME F16F16 FMLS multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x0a,0x5d,0x34,0xc1},4,"fmls za.h[w10, 2, vgx4], {z8.h, z9.h, z10.h, z11.h}, z4.h"},
        {"SME B16B16 BFMLS multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x8f,0x7f,0x7f,0xc1},4,"bfmls za.h[w11, 7, vgx4], {z28.h, z29.h, z30.h, z31.h}, z15.h"}
    };
    size_t index;
    for(index=0u;index<sizeof(cases)/sizeof(cases[0]);++index){
        cdisasm_arm_instruction instruction; expect_case(&cases[index]);
        if(decode_case(&cases[index],&instruction)){
            uint32_t expected=CDISASM_ARM_INSTRUCTION_FLAG_SME
                |CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
                |CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR;
            if(index<4u||(index>=8u&&index<16u)||index>=20u)
                expected|=CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
            EXPECT(instruction.instruction_flags==expected);
            EXPECT(instruction.operand_count==3u);
            EXPECT(instruction.operand[0].access==CDISASM_OPERAND_ACCESS_READ_WRITE);
            EXPECT(instruction.operand[1].access==CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.operand[2].access==CDISASM_OPERAND_ACCESS_READ);
        }
    }
#endif
}

static void test_sme2_multi4_long_mla_single(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        {"SME2 SMLAL multi4 single",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x00,0x08,0x70,0xc1},4,"smlal za.s[w8, 0:1, vgx4], {z0.h, z1.h, z2.h, z3.h}, z0.h"},
        {"SME2 SMLSL multi4 single",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x89,0x28,0x73,0xc1},4,"smlsl za.s[w9, 2:3, vgx4], {z4.h, z5.h, z6.h, z7.h}, z3.h"},
        {"SME2 UMLAL multi4 single",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x12,0x49,0x74,0xc1},4,"umlal za.s[w10, 4:5, vgx4], {z8.h, z9.h, z10.h, z11.h}, z4.h"},
        {"SME2 UMLSL multi4 single",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x9b,0x6b,0x7f,0xc1},4,"umlsl za.s[w11, 6:7, vgx4], {z28.h, z29.h, z30.h, z31.h}, z15.h"}
    };
    size_t index;
    for(index=0u;index<sizeof(cases)/sizeof(cases[0]);++index){
        cdisasm_arm_instruction instruction; expect_case(&cases[index]);
        if(decode_case(&cases[index],&instruction)){
            EXPECT(instruction.instruction_flags
                ==(CDISASM_ARM_INSTRUCTION_FLAG_SME
                    |CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
                    |CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR));
            EXPECT(instruction.operand_count==3u);
            EXPECT(instruction.operand[0].access==CDISASM_OPERAND_ACCESS_READ_WRITE);
            EXPECT(instruction.operand[1].access==CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.operand[2].access==CDISASM_OPERAND_ACCESS_READ);
        }
    }
#endif
}

static void test_sme_multi_fscale(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        {"SME FP8 FSCALE H multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x80,0xa1,0x60,0xc1},4,"fscale {z0.h, z1.h}, {z0.h, z1.h}, z0.h"},
        {"SME FP8 FSCALE S multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x82,0xa1,0xa4,0xc1},4,"fscale {z2.s, z3.s}, {z2.s, z3.s}, z4.s"},
        {"SME FP8 FSCALE D multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x9e,0xa1,0xef,0xc1},4,"fscale {z30.d, z31.d}, {z30.d, z31.d}, z15.d"},
        {"SME BFSCALE H multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x84,0xa1,0x23,0xc1},4,"bfscale {z4.h, z5.h}, {z4.h, z5.h}, z3.h"},
        {"SME FP8 FSCALE H multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x80,0xa9,0x60,0xc1},4,"fscale {z0.h, z1.h, z2.h, z3.h}, {z0.h, z1.h, z2.h, z3.h}, z0.h"},
        {"SME FP8 FSCALE S multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x84,0xa9,0xa8,0xc1},4,"fscale {z4.s, z5.s, z6.s, z7.s}, {z4.s, z5.s, z6.s, z7.s}, z8.s"},
        {"SME FP8 FSCALE D multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x9c,0xa9,0xef,0xc1},4,"fscale {z28.d, z29.d, z30.d, z31.d}, {z28.d, z29.d, z30.d, z31.d}, z15.d"},
        {"SME BFSCALE H multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x88,0xa9,0x23,0xc1},4,"bfscale {z8.h, z9.h, z10.h, z11.h}, {z8.h, z9.h, z10.h, z11.h}, z3.h"}
    };
    size_t index;
    for(index=0u;index<sizeof(cases)/sizeof(cases[0]);++index){
        cdisasm_arm_instruction instruction;expect_case(&cases[index]);
        if(decode_case(&cases[index],&instruction)){
            EXPECT(instruction.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SME|CDISASM_ARM_INSTRUCTION_FLAG_MATRIX|CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
            EXPECT(instruction.operand_count==3u);
            EXPECT(instruction.operand[0].access==CDISASM_OPERAND_ACCESS_WRITE);
            EXPECT(instruction.operand[1].access==CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.operand[2].access==CDISASM_OPERAND_ACCESS_READ);
        }
    }
#endif
}

static void test_sme_multi_matrix_special(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        {"SME FAMAX 2x2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x40,0xb1,0x62,0xc1},4,"famax {z0.h, z1.h}, {z0.h, z1.h}, {z2.h, z3.h}"},
        {"SME FAMIN 2x2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x45,0xb1,0xa6,0xc1},4,"famin {z4.s, z5.s}, {z4.s, z5.s}, {z6.s, z7.s}"},
        {"SME FSCALE 2x2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x88,0xb1,0xea,0xc1},4,"fscale {z8.d, z9.d}, {z8.d, z9.d}, {z10.d, z11.d}"},
        {"SME BFSCALE 2x2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x8c,0xb1,0x2e,0xc1},4,"bfscale {z12.h, z13.h}, {z12.h, z13.h}, {z14.h, z15.h}"},
        {"SME FAMAX 4x4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x40,0xb9,0x64,0xc1},4,"famax {z0.h, z1.h, z2.h, z3.h}, {z0.h, z1.h, z2.h, z3.h}, {z4.h, z5.h, z6.h, z7.h}"},
        {"SME FAMIN 4x4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x49,0xb9,0xac,0xc1},4,"famin {z8.s, z9.s, z10.s, z11.s}, {z8.s, z9.s, z10.s, z11.s}, {z12.s, z13.s, z14.s, z15.s}"},
        {"SME FSCALE 4x4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x90,0xb9,0xf4,0xc1},4,"fscale {z16.d, z17.d, z18.d, z19.d}, {z16.d, z17.d, z18.d, z19.d}, {z20.d, z21.d, z22.d, z23.d}"},
        {"SME BFSCALE 4x4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x98,0xb9,0x3c,0xc1},4,"bfscale {z24.h, z25.h, z26.h, z27.h}, {z24.h, z25.h, z26.h, z27.h}, {z28.h, z29.h, z30.h, z31.h}"}
    };
    size_t index;
    for(index=0u;index<sizeof(cases)/sizeof(cases[0]);++index){
        cdisasm_arm_instruction instruction;expect_case(&cases[index]);
        if(decode_case(&cases[index],&instruction)){
            EXPECT(instruction.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SME|CDISASM_ARM_INSTRUCTION_FLAG_MATRIX|CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
            EXPECT(instruction.operand_count==3u);
            EXPECT(instruction.operand[0].access==CDISASM_OPERAND_ACCESS_WRITE);
            EXPECT(instruction.operand[1].access==CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.operand[2].access==CDISASM_OPERAND_ACCESS_READ);
        }
    }
#endif
}

static void test_sme_multi_fclamp(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        {"SME FCLAMP H multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x40,0xc0,0x63,0xc1},4,"fclamp {z0.h, z1.h}, z2.h, z3.h"},
        {"SME FCLAMP S multi2",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xc4,0xc0,0xa7,0xc1},4,"fclamp {z4.s, z5.s}, z6.s, z7.s"},
        {"SME FCLAMP D multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x88,0xc9,0xed,0xc1},4,"fclamp {z8.d, z9.d, z10.d, z11.d}, z12.d, z13.d"},
        {"SME BFCLAMP H multi4",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x90,0xca,0x35,0xc1},4,"bfclamp {z16.h, z17.h, z18.h, z19.h}, z20.h, z21.h"}
    };
    size_t index;
    for(index=0u;index<sizeof(cases)/sizeof(cases[0]);++index){
        cdisasm_arm_instruction instruction;expect_case(&cases[index]);
        if(decode_case(&cases[index],&instruction)){
            EXPECT(instruction.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SME|CDISASM_ARM_INSTRUCTION_FLAG_MATRIX|CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
            EXPECT(instruction.operand_count==3u);
            EXPECT(instruction.operand[0].access==CDISASM_OPERAND_ACCESS_WRITE);
            EXPECT(instruction.operand[1].access==CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.operand[2].access==CDISASM_OPERAND_ACCESS_READ);
        }
    }
#endif
}

static void test_sve_predicated_bfscale(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        {"SVE BFSCALE low",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x20,0x80,0x09,0x65},4,"bfscale z0.h, p0/m, z0.h, z1.h"},
        {"SVE BFSCALE high",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xfc,0x9f,0x09,0x65},4,"bfscale z28.h, p7/m, z28.h, z31.h"}
    };
    size_t index;
    for(index=0u;index<sizeof(cases)/sizeof(cases[0]);++index){
        cdisasm_arm_instruction instruction;expect_case(&cases[index]);
        if(decode_case(&cases[index],&instruction)){
            EXPECT(instruction.form_id==3092u);
            EXPECT(instruction.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT|CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR));
            EXPECT(instruction.operand_count==4u);
            EXPECT(instruction.operand[0].access==CDISASM_OPERAND_ACCESS_READ_WRITE);
            EXPECT(instruction.operand[1].access==CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.operand[2].access==CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.operand[3].access==CDISASM_OPERAND_ACCESS_READ);
        }
    }
#endif
}

static void test_a64_fp_pair_memory(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        {"A64 FP pair S post",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x40,0x04,0x81,0x2c},4,"stp s0, s1, [x2], #0x8"},
        {"A64 FP pair D off",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xe3,0x13,0x7f,0x6d},4,"ldp d3, d4, [sp, #-0x10]"},
        {"A64 FP pair Q pre high",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xb0,0x7c,0x81,0xad},4,"stp q16, q31, [x5, #0x20]!"},
        {"A64 FP pair S pre",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x06,0x9d,0xc1,0x2d},4,"ldp s6, s7, [x8, #0xc]!"},
        {"A64 FP pair D off negative",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x69,0x29,0x3e,0x6d},4,"stp d9, d10, [x11, #-0x20]"},
        {"A64 FP pair Q post",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xec,0x37,0xc2,0xac},4,"ldp q12, q13, [sp], #0x40"}
    };
    size_t index;
    for(index=0u;index<sizeof(cases)/sizeof(cases[0]);++index){
        cdisasm_arm_instruction instruction;expect_case(&cases[index]);
        if(decode_case(&cases[index],&instruction)){
            EXPECT((instruction.instruction_flags&CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)!=0u);
            EXPECT(instruction.operand_count==3u);
            EXPECT(instruction.operand[2].type==CDISASM_OPERAND_MEMORY);
        }
    }
#endif
}

static void test_a64_fp_unscaled_memory(void)
{
#if USE_EXTRA_OPCODES
    static const arm_format_case cases[] = {
        {"A64 STUR B",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x20,0xf0,0x1f,0x3c},4,"stur b0, [x1, #-0x1]"},
        {"A64 LDUR H",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xc5,0x20,0x40,0x7c},4,"ldur h5, [x6, #0x2]"},
        {"A64 STUR S",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x07,0xc1,0x1f,0xbc},4,"stur s7, [x8, #-0x4]"},
        {"A64 LDUR D",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xcd,0x81,0x41,0xfc},4,"ldur d13, [x14, #0x18]"},
        {"A64 LDUR Q high",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x3f,0x02,0xc3,0x3c},4,"ldur q31, [x17, #0x30]"},
        {"A64 STR B post",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x20,0xf4,0x1f,0x3c},4,"str b0, [x1], #-0x1"},
        {"A64 LDR Q post",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x9f,0x04,0xc3,0x3c},4,"ldr q31, [x4], #0x30"},
        {"A64 STR H post",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xc5,0xe4,0x1f,0x7c},4,"str h5, [x6], #-0x2"},
        {"A64 LDR S pre",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xfc,0x0f,0x41,0xbc},4,"ldr s28, [sp, #0x10]!"},
        {"A64 STR D pre",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xdd,0x8f,0x1e,0xfc},4,"str d29, [x30, #-0x18]!"},
        {"A64 LDR B pre",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xf2,0xff,0x47,0x3c},4,"ldr b18, [sp, #0x7f]!"},
        {"A64 STR B unsigned",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x20,0xfc,0x3f,0x3d},4,"str b0, [x1, #0xfff]"},
        {"A64 LDR Q unsigned",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x9f,0x0c,0xc0,0x3d},4,"ldr q31, [x4, #0x30]"},
        {"A64 STR H unsigned",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xc5,0xfc,0x3f,0x7d},4,"str h5, [x6, #0x1ffe]"},
        {"A64 LDR S unsigned",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x6a,0x0d,0x40,0xbd},4,"ldr s10, [x11, #0xc]"},
        {"A64 STR D unsigned",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xec,0xff,0x3f,0xfd},4,"str d12, [sp, #0x7ff8]"},
        {"A64 STR B register UXTW",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x20,0x48,0x22,0x3c},4,"str b0, [x1, w2, uxtw]"},
        {"A64 LDR B register LSL",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x49,0x79,0x6b,0x3c},4,"ldr b9, [x10, x11, lsl #0x0]"},
        {"A64 STR Q register high",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x90,0x79,0xad,0x3c},4,"str q16, [x12, x13, lsl #0x4]"},
        {"A64 LDR Q register UXTW",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xff,0x5b,0xee,0x3c},4,"ldr q31, [sp, w14, uxtw #0x4]"},
        {"A64 STR H register SXTW",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x0f,0xda,0x31,0x7c},4,"str h15, [x16, w17, sxtw #0x1]"},
        {"A64 LDR D register SXTX",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xdd,0xfb,0x60,0xfc},4,"ldr d29, [x30, x0, sxtx #0x3]"}
        ,{"A64 STRB register",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x20,0x48,0x22,0x38},4,"strb w0, [x1, w2, uxtw]"}
        ,{"A64 LDRSB X register",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xac,0x49,0xae,0x38},4,"ldrsb x12, [x13, w14, uxtw]"}
        ,{"A64 LDRSH W register",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x41,0x78,0xe3,0x78},4,"ldrsh w1, [x2, x3, lsl #0x1]"}
        ,{"A64 LDRSW register",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x6a,0xd9,0xac,0xb8},4,"ldrsw x10, [x11, w12, sxtw #0x2]"}
        ,{"A64 PRFM register",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x40,0xfa,0xb3,0xf8},4,"prfm pldl1keep, [x18, x19, sxtx #0x3]"}
        ,{"A64 PRFM unsigned",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x63,0xd4,0x80,0xf9},4,"prfm pldl2strm, [x3, #0x1a8]"}
        ,{"A64 ADD extended W",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x20,0x00,0x22,0x0b},4,"add w0, w1, w2, uxtb"}
        ,{"A64 ADDS extended W",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x83,0x24,0x25,0x2b},4,"adds w3, w4, w5, uxth #0x1"}
        ,{"A64 SUB extended W",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xe6,0x48,0x28,0x4b},4,"sub w6, w7, w8, uxtw #0x2"}
        ,{"A64 SUBS extended W",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x49,0x8d,0x2b,0x6b},4,"subs w9, w10, w11, sxtb #0x3"}
        ,{"A64 ADD extended X SP",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xec,0xb3,0x2d,0x8b},4,"add x12, sp, w13, sxth #0x4"}
        ,{"A64 ADDS extended X",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xee,0xc1,0x30,0xab},4,"adds x14, x15, w16, sxtw"}
        ,{"A64 SUB extended X SP",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x3f,0x66,0x32,0xcb},4,"sub sp, x17, x18, lsl #0x1"}
        ,{"A64 SUBS extended X",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x93,0xea,0x35,0xeb},4,"subs x19, x20, x21, sxtx #0x2"}
        ,{"A64 ADDPT",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xe3,0x2f,0x04,0x9a},4,"addpt x3, sp, x4, lsl #0x3"}
        ,{"A64 SUBPT",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x07,0x3d,0x09,0xda},4,"subpt x7, x8, x9, lsl #0x7"}
        ,{"A64 SQDMLAL scalar",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x20,0x90,0x62,0x5e},4,"sqdmlal s0, h1, h2"}
        ,{"A64 SQDMLSL scalar",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x83,0xb0,0xa5,0x5e},4,"sqdmlsl d3, s4, s5"}
        ,{"A64 SQDMULL scalar",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xe6,0xd0,0x68,0x5e},4,"sqdmull s6, h7, h8"}
        ,{"A64 SQSHL scalar",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x20,0x74,0x0f,0x5f},4,"sqshl b0, b1, #0x7"}
        ,{"A64 SCVTF scalar fixed",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x28,0xe5,0x20,0x5f},4,"scvtf s8, s9, #0x20"}
        ,{"A64 FCVTZS scalar fixed",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xee,0xfd,0x40,0x5f},4,"fcvtzs d14, d15, #0x40"}
        ,{"A64 SQSHLU scalar",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xa4,0x64,0x3f,0x7f},4,"sqshlu s4, s5, #0x1f"}
        ,{"A64 UQSHL scalar",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xe6,0x74,0x7f,0x7f},4,"uqshl d6, d7, #0x3f"}
        ,{"A64 UCVTF scalar fixed",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xac,0xe5,0x2f,0x7f},4,"ucvtf s12, s13, #0x11"}
        ,{"A64 FCVTZU scalar fixed",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x30,0xfe,0x3f,0x7f},4,"fcvtzu s16, s17, #0x1"}
        ,{"A64 SQRDMLAH scalar",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x20,0x84,0x42,0x7e},4,"sqrdmlah h0, h1, h2"}
        ,{"A64 SQRDMLSH scalar",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x83,0x8c,0x85,0x7e},4,"sqrdmlsh s3, s4, s5"}
        ,{"A64 SQDMLAL scalar element",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x20,0x30,0x42,0x5f},4,"sqdmlal s0, h1, v2.h[0]"}
        ,{"A64 SQDMLSL scalar element",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xe6,0x78,0x7f,0x5f},4,"sqdmlsl s6, h7, v15.h[7]"}
        ,{"A64 SQDMULL scalar element",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x28,0xb1,0xbf,0x5f},4,"sqdmull d8, s9, v31.s[1]"}
        ,{"A64 SQDMULH scalar element",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x6a,0xc9,0x5c,0x5f},4,"sqdmulh h10, h11, v12.h[5]"}
        ,{"A64 SQRDMULH scalar element",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xcd,0xd9,0x94,0x5f},4,"sqrdmulh s13, s14, v20.s[2]"}
        ,{"A64 FMLA H scalar element",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x20,0x18,0x32,0x5f},4,"fmla h0, h1, v2.h[7]"}
        ,{"A64 FMLS H scalar element",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x83,0x50,0x0f,0x5f},4,"fmls h3, h4, v15.h[0]"}
        ,{"A64 FMUL H scalar element",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xc5,0x90,0x37,0x5f},4,"fmul h5, h6, v7.h[3]"}
        ,{"A64 FMLA S scalar element",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x8b,0x19,0xbf,0x5f},4,"fmla s11, s12, v31.s[3]"}
        ,{"A64 FMLS D scalar element",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xcd,0x59,0xcf,0x5f},4,"fmls d13, d14, v15.d[1]"}
        ,{"A64 FMUL S scalar element",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x30,0x9a,0x92,0x5f},4,"fmul s16, s17, v18.s[2]"}
        ,{"A64 SQRDMLAH scalar element",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0xf6,0xda,0x47,0x7f},4,"sqrdmlah h22, h23, v7.h[4]"}
        ,{"A64 SQRDMLSH scalar element",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x38,0xfb,0xba,0x7f},4,"sqrdmlsh s24, s25, v26.s[3]"}
        ,{"A64 FMULX H scalar element",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x28,0x99,0x2a,0x7f},4,"fmulx h8, h9, v10.h[6]"}
        ,{"A64 FMULX D scalar element",CDISASM_ARM_CPU_ANY,CDISASM_ARM_MODE_A64,0,{0x93,0x92,0xd5,0x7f},4,"fmulx d19, d20, v21.d[0]"}
    };
    size_t index;
    for(index=0u;index<sizeof(cases)/sizeof(cases[0]);++index){
        cdisasm_arm_instruction instruction;expect_case(&cases[index]);
        if(decode_case(&cases[index],&instruction)){
            if(instruction.form_id>=5877u&&instruction.form_id<=5891u)EXPECT(instruction.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SIMD|((instruction.form_id>=5882u&&instruction.form_id<=5887u)||(instruction.form_id>=5890u&&instruction.form_id<=5891u)?CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT:0u)));
            else if(index<22u)EXPECT((instruction.instruction_flags&CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)!=0u);
            else if(instruction.name_id==CDISASM_ARM_NAME_ADDS||instruction.name_id==CDISASM_ARM_NAME_SUBS)EXPECT(instruction.instruction_flags==CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS);
            else if(instruction.name_id==CDISASM_ARM_NAME_SQDMLAL||instruction.name_id==CDISASM_ARM_NAME_SQDMLSL||instruction.name_id==CDISASM_ARM_NAME_SQDMULL)EXPECT(instruction.instruction_flags==CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
            else if(instruction.name_id==CDISASM_ARM_NAME_SCVTF||instruction.name_id==CDISASM_ARM_NAME_UCVTF||instruction.name_id==CDISASM_ARM_NAME_FCVTZS||instruction.name_id==CDISASM_ARM_NAME_FCVTZU)EXPECT(instruction.instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SIMD|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT));
            else if(instruction.name_id==CDISASM_ARM_NAME_SQSHL||instruction.name_id==CDISASM_ARM_NAME_SQSHLU||instruction.name_id==CDISASM_ARM_NAME_UQSHL)EXPECT(instruction.instruction_flags==CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
            else if(instruction.name_id==CDISASM_ARM_NAME_SQRDMLAH||instruction.name_id==CDISASM_ARM_NAME_SQRDMLSH)EXPECT(instruction.instruction_flags==CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
            else EXPECT(instruction.instruction_flags==0u);
            EXPECT(instruction.operand_count==(index<28u?2u:3u));
            if(index<28u)EXPECT(instruction.operand[1].type==CDISASM_OPERAND_MEMORY);
        }
    }
#endif
}

int main(void)
{
    test_a32_and_t32();
    test_a64();
    test_vectors_and_apple();
    test_format_flags();
    test_buffer_contract_and_invalid_metadata();
    test_a64_extra_atomic();
    test_generated_opaque_formatting();
    test_advsimd_aes();
    test_advsimd_integer_reductions();
    test_advsimd_integer_unary_scalar();
    test_advsimd_unsigned_estimates();
    test_advsimd_frecpx_scalar();
    test_fprcvt_fcvtns_scalar();
    test_fprcvt_remaining_scalar();
    test_advsimd_fcvtn_narrow();
    test_advsimd_scalar_cvt_fixed();
    test_advsimd_fp_reductions();
    test_advsimd_faminmax_fscale();
    test_sve_gather_load_32();
    test_sve_gather_load_64();
    test_sve_scatter_store();
    test_sme_movt();
    test_sme2_indexed_multi2_s();
    test_sme2_indexed_multi4_s();
    test_sme_indexed_fp8_fdot_h();
    test_sme2_multi2_long_mla_single();
    test_sme2_single_long_mla();
    test_sme_multi2_fdot_single();
    test_sme_multi2_integer_dot_single();
    test_sme_multi2_arith_single();
    test_sme2_multi4_long_mla_single();
    test_sme_multi_fscale();
    test_sme_multi_matrix_special();
    test_sme_multi_fclamp();
    test_sve_predicated_bfscale();
    test_a64_fp_pair_memory();
    test_a64_fp_unscaled_memory();

    if (failures != 0) {
        fprintf(stderr, "%d ARM formatter test(s) failed\n", failures);
        return 1;
    }
    puts("all ARM formatter tests passed");
    return 0;
}
