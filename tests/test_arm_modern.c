#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_LDAPR == 216,
               "established ARM name IDs moved");
_Static_assert(CDISASM_ARM_NAME_MLA == 217,
               "modern ARM name IDs must remain append-only");
_Static_assert(CDISASM_ARM_NAME_SQRDMLAH == 312,
               "established modern ARM name IDs moved");
_Static_assert(CDISASM_ARM_NAME_ADCS == 313,
               "scalar-register ARM name IDs must remain append-only");
_Static_assert(CDISASM_ARM_NAME_CNEG == 331,
               "scalar-register ARM terminal ID changed");
_Static_assert(CDISASM_ARM_NAME_SEL == 341,
               "SVE predicate-logical ARM terminal ID changed");
_Static_assert(CDISASM_ARM_NAME_SUBPT == 347,
               "SVE arithmetic ARM terminal ID changed");
_Static_assert(CDISASM_ARM_NAME_UDIVR == 364,
               "SVE predicated arithmetic terminal ID changed");
_Static_assert(CDISASM_ARM_NAME_COUNT == CDISASM_ARM_NAME_LAST + 1,
               "ARM name catalog must remain contiguous");
_Static_assert(CDISASM_ARM_REG_CPM_IOACC_CTL_EL3 == 163,
               "established ARM register IDs moved");
_Static_assert(CDISASM_ARM_REG_Z0 == 276,
               "scalable ARM register IDs moved");
_Static_assert(CDISASM_ARM_REG_VG == 374,
               "modern ARM register terminal ID changed");
_Static_assert(CDISASM_ARM_REG_COUNT == CDISASM_ARM_REG_LAST + 1,
               "ARM register catalog must remain contiguous");
_Static_assert(sizeof(cdisasm_arm_instruction)
                   == CDISASM_ARM_INSTRUCTION_SIZE,
               "modern metadata changed the public ARM ABI");

typedef struct modern_case {
    const char *label;
    cdisasm_arm_mode mode;
    uint8_t bytes[4];
    uint8_t byte_count;
    cdisasm_arm_name_id name_id;
    const char *text;
} modern_case;

static const modern_case modern_cases[] = {
    { "a32-mla", CDISASM_ARM_MODE_A32,
      { 0x91, 0x32, 0x20, 0xe0 }, 4, CDISASM_ARM_NAME_MLA,
      "mla r0, r1, r2, r3" },
    { "a32-vmla-f64", CDISASM_ARM_MODE_A32,
      { 0x02, 0x0b, 0x01, 0xee }, 4, CDISASM_ARM_NAME_VMLA,
      "vmla.f64 d0, d1, d2" },
    { "a32-vmla-i16", CDISASM_ARM_MODE_A32,
      { 0x44, 0x09, 0x12, 0xf2 }, 4, CDISASM_ARM_NAME_VMLA,
      "vmla.i16 q0, q1, q2" },
    { "a32-dmb", CDISASM_ARM_MODE_A32,
      { 0x5f, 0xf0, 0x7f, 0xf5 }, 4, CDISASM_ARM_NAME_DMB,
      "dmb sy" },
    { "t32-it", CDISASM_ARM_MODE_T32,
      { 0x08, 0xbf, 0x00, 0x00 }, 2, CDISASM_ARM_NAME_IT,
      "it eq" },
    { "t32-movw", CDISASM_ARM_MODE_T32,
      { 0x44, 0xf2, 0x67, 0x53 }, 4, CDISASM_ARM_NAME_MOVW,
      "movw r3, #0x4567" },
    { "t32-sdiv", CDISASM_ARM_MODE_T32,
      { 0x95, 0xfb, 0xf6, 0xf4 }, 4, CDISASM_ARM_NAME_SDIV,
      "sdiv r4, r5, r6" },
    { "t32-vdiv-f32", CDISASM_ARM_MODE_T32,
      { 0x80, 0xee, 0x81, 0x0a }, 4, CDISASM_ARM_NAME_VDIV,
      "vdiv.f32 s0, s1, s2" },
    { "a64-add-shifted", CDISASM_ARM_MODE_A64,
      { 0x20, 0x0c, 0x02, 0x8b }, 4, CDISASM_ARM_NAME_ADD,
      "add x0, x1, x2, lsl #0x3" },
    { "a64-neg-alias", CDISASM_ARM_MODE_A64,
      { 0xe0, 0x0f, 0x81, 0xcb }, 4, CDISASM_ARM_NAME_NEG,
      "neg x0, x1, asr #0x3" },
    { "a64-negs-alias", CDISASM_ARM_MODE_A64,
      { 0xe2, 0x13, 0x43, 0x6b }, 4, CDISASM_ARM_NAME_NEGS,
      "negs w2, w3, lsr #0x4" },
    { "a64-adc", CDISASM_ARM_MODE_A64,
      { 0x20, 0x00, 0x02, 0x9a }, 4, CDISASM_ARM_NAME_ADC,
      "adc x0, x1, x2" },
    { "a64-adcs", CDISASM_ARM_MODE_A64,
      { 0x83, 0x00, 0x05, 0x3a }, 4, CDISASM_ARM_NAME_ADCS,
      "adcs w3, w4, w5" },
    { "a64-sbc", CDISASM_ARM_MODE_A64,
      { 0xe6, 0x00, 0x08, 0xda }, 4, CDISASM_ARM_NAME_SBC,
      "sbc x6, x7, x8" },
    { "a64-sbcs", CDISASM_ARM_MODE_A64,
      { 0x49, 0x01, 0x0b, 0x7a }, 4, CDISASM_ARM_NAME_SBCS,
      "sbcs w9, w10, w11" },
    { "a64-ngc-alias", CDISASM_ARM_MODE_A64,
      { 0xe4, 0x03, 0x05, 0xda }, 4, CDISASM_ARM_NAME_NGC,
      "ngc x4, x5" },
    { "a64-ngcs-alias", CDISASM_ARM_MODE_A64,
      { 0xe6, 0x03, 0x07, 0x7a }, 4, CDISASM_ARM_NAME_NGCS,
      "ngcs w6, w7" },
    { "a64-csel", CDISASM_ARM_MODE_A64,
      { 0x20, 0x00, 0x82, 0x9a }, 4, CDISASM_ARM_NAME_CSEL,
      "csel x0, x1, x2, eq" },
    { "a64-csinc", CDISASM_ARM_MODE_A64,
      { 0x83, 0x14, 0x85, 0x1a }, 4, CDISASM_ARM_NAME_CSINC,
      "csinc w3, w4, w5, ne" },
    { "a64-csinv", CDISASM_ARM_MODE_A64,
      { 0xe6, 0x40, 0x88, 0xda }, 4, CDISASM_ARM_NAME_CSINV,
      "csinv x6, x7, x8, mi" },
    { "a64-csneg", CDISASM_ARM_MODE_A64,
      { 0x49, 0x55, 0x8b, 0x5a }, 4, CDISASM_ARM_NAME_CSNEG,
      "csneg w9, w10, w11, pl" },
    { "a64-cinc-alias", CDISASM_ARM_MODE_A64,
      { 0x28, 0x15, 0x89, 0x9a }, 4, CDISASM_ARM_NAME_CINC,
      "cinc x8, x9, eq" },
    { "a64-cset-alias", CDISASM_ARM_MODE_A64,
      { 0xea, 0x07, 0x9f, 0x1a }, 4, CDISASM_ARM_NAME_CSET,
      "cset w10, ne" },
    { "a64-cinv-alias", CDISASM_ARM_MODE_A64,
      { 0x8b, 0x51, 0x8c, 0xda }, 4, CDISASM_ARM_NAME_CINV,
      "cinv x11, x12, mi" },
    { "a64-csetm-alias", CDISASM_ARM_MODE_A64,
      { 0xed, 0x43, 0x9f, 0x5a }, 4, CDISASM_ARM_NAME_CSETM,
      "csetm w13, pl" },
    { "a64-cneg-alias", CDISASM_ARM_MODE_A64,
      { 0xee, 0x75, 0x8f, 0xda }, 4, CDISASM_ARM_NAME_CNEG,
      "cneg x14, x15, vs" },
    { "a64-sdiv", CDISASM_ARM_MODE_A64,
      { 0xee, 0x0d, 0xd0, 0x9a }, 4, CDISASM_ARM_NAME_SDIV,
      "sdiv x14, x15, x16" },
    { "a64-udiv", CDISASM_ARM_MODE_A64,
      { 0x51, 0x0a, 0xd3, 0x1a }, 4, CDISASM_ARM_NAME_UDIV,
      "udiv w17, w18, w19" },
    { "a64-lsl-variable", CDISASM_ARM_MODE_A64,
      { 0xb4, 0x22, 0xd6, 0x9a }, 4, CDISASM_ARM_NAME_LSL,
      "lsl x20, x21, x22" },
    { "a64-lsr-variable", CDISASM_ARM_MODE_A64,
      { 0x17, 0x27, 0xd9, 0x1a }, 4, CDISASM_ARM_NAME_LSR,
      "lsr w23, w24, w25" },
    { "a64-asr-variable", CDISASM_ARM_MODE_A64,
      { 0x7a, 0x2b, 0xdc, 0x9a }, 4, CDISASM_ARM_NAME_ASR,
      "asr x26, x27, x28" },
    { "a64-ror-variable", CDISASM_ARM_MODE_A64,
      { 0xdd, 0x2f, 0xc0, 0x1a }, 4, CDISASM_ARM_NAME_ROR,
      "ror w29, w30, w0" },
    { "a64-madd", CDISASM_ARM_MODE_A64,
      { 0x20, 0x0c, 0x02, 0x9b }, 4, CDISASM_ARM_NAME_MADD,
      "madd x0, x1, x2, x3" },
    { "a64-msub", CDISASM_ARM_MODE_A64,
      { 0xa4, 0x9c, 0x06, 0x1b }, 4, CDISASM_ARM_NAME_MSUB,
      "msub w4, w5, w6, w7" },
    { "a64-mul-alias", CDISASM_ARM_MODE_A64,
      { 0x28, 0x7d, 0x0a, 0x9b }, 4, CDISASM_ARM_NAME_MUL,
      "mul x8, x9, x10" },
    { "a64-mneg-alias", CDISASM_ARM_MODE_A64,
      { 0x8b, 0xfd, 0x0d, 0x1b }, 4, CDISASM_ARM_NAME_MNEG,
      "mneg w11, w12, w13" },
    { "sve-add", CDISASM_ARM_MODE_A64,
      { 0x61, 0x08, 0x80, 0x04 }, 4, CDISASM_ARM_NAME_ADD,
      "add z1.s, p2/m, z1.s, z3.s" },
    { "sve-load", CDISASM_ARM_MODE_A64,
      { 0x61, 0xa8, 0x40, 0xa5 }, 4, CDISASM_ARM_NAME_LD1W,
      "ld1w {z1.s}, p2/z, [x3]" },
    { "sve2-eor3", CDISASM_ARM_MODE_A64,
      { 0xe4, 0x38, 0x26, 0x04 }, 4, CDISASM_ARM_NAME_EOR3,
      "eor3 z4.d, z4.d, z6.d, z7.d" },
    { "sve2-sqrdmlah", CDISASM_ARM_MODE_A64,
      { 0x20, 0x70, 0x82, 0x44 }, 4, CDISASM_ARM_NAME_SQRDMLAH,
      "sqrdmlah z0.s, z1.s, z2.s" },
    { "sme-state", CDISASM_ARM_MODE_A64,
      { 0x7f, 0x43, 0x03, 0xd5 }, 4, CDISASM_ARM_NAME_SMSTART,
      "smstart sm" },
    { "sme-fmopa", CDISASM_ARM_MODE_A64,
      { 0x01, 0x20, 0x81, 0x80 }, 4, CDISASM_ARM_NAME_FMOPA,
      "fmopa za1.s, p0/m, p1/m, z0.s, z1.s" },
    { "sme-za-load", CDISASM_ARM_MODE_A64,
      { 0x00, 0x00, 0x00, 0xe1 }, 4, CDISASM_ARM_NAME_LDR,
      "ldr za[w12, 0], [x0]" },
    { "sme2-zt-load", CDISASM_ARM_MODE_A64,
      { 0x40, 0x80, 0x1f, 0xe1 }, 4, CDISASM_ARM_NAME_LDR,
      "ldr zt0, [x2]" },
    { "sme2-luti", CDISASM_ARM_MODE_A64,
      { 0x00, 0x10, 0xcc, 0xc0 }, 4, CDISASM_ARM_NAME_LUTI2,
      "luti2 z0.h, zt0, z0[0]" },
    { "lse128", CDISASM_ARM_MODE_A64,
      { 0x80, 0x80, 0x22, 0x19 }, 4, CDISASM_ARM_NAME_SWPP,
      "swpp x0, x2, [x4]" },
    { "rcpc3-load", CDISASM_ARM_MODE_A64,
      { 0x40, 0x18, 0x41, 0xd9 }, 4, CDISASM_ARM_NAME_LDIAPP,
      "ldiapp x0, x1, [x2]" },
    { "rcpc3-store", CDISASM_ARM_MODE_A64,
      { 0x40, 0x18, 0x01, 0xd9 }, 4, CDISASM_ARM_NAME_STILP,
      "stilp x0, x1, [x2]" },
    { "bti", CDISASM_ARM_MODE_A64,
      { 0x5f, 0x24, 0x03, 0xd5 }, 4, CDISASM_ARM_NAME_BTI,
      "bti c" },
    { "pointer-auth", CDISASM_ARM_MODE_A64,
      { 0x20, 0x00, 0xc1, 0xda }, 4, CDISASM_ARM_NAME_PACIA,
      "pacia x0, x1" },
    { "mte", CDISASM_ARM_MODE_A64,
      { 0x41, 0x08, 0x20, 0xd9 }, 4, CDISASM_ARM_NAME_STG,
      "stg x1, [x2]" },
    { "mops", CDISASM_ARM_MODE_A64,
      { 0x40, 0x04, 0x01, 0x19 }, 4, CDISASM_ARM_NAME_CPYFP,
      "cpyfp [x0]!, [x1]!, x2!" },
    { "ls64", CDISASM_ARM_MODE_A64,
      { 0x00, 0xd1, 0x3f, 0xf8 }, 4, CDISASM_ARM_NAME_LD64B,
      "ld64b x0, [x8]" },
    { "cssc", CDISASM_ARM_MODE_A64,
      { 0x41, 0x20, 0xc0, 0xda }, 4, CDISASM_ARM_NAME_ABS,
      "abs x1, x2" },
    { "fp16", CDISASM_ARM_MODE_A64,
      { 0x20, 0xc0, 0xe0, 0x1e }, 4, CDISASM_ARM_NAME_FABS,
      "fabs h0, h1" },
    { "paciasp", CDISASM_ARM_MODE_A64,
      { 0x3f, 0x23, 0x03, 0xd5 }, 4, CDISASM_ARM_NAME_PACIASP,
      "paciasp" },
    { "dgh", CDISASM_ARM_MODE_A64,
      { 0xdf, 0x20, 0x03, 0xd5 }, 4, CDISASM_ARM_NAME_DGH,
      "dgh" },
    { "xpaclri", CDISASM_ARM_MODE_A64,
      { 0xff, 0x20, 0x03, 0xd5 }, 4, CDISASM_ARM_NAME_XPACLRI,
      "xpaclri" },
    { "psb", CDISASM_ARM_MODE_A64,
      { 0x3f, 0x22, 0x03, 0xd5 }, 4, CDISASM_ARM_NAME_PSB,
      "psb csync" },
    { "gcsb", CDISASM_ARM_MODE_A64,
      { 0x7f, 0x22, 0x03, 0xd5 }, 4, CDISASM_ARM_NAME_GCSB,
      "gcsb dsync" },
    { "pacm", CDISASM_ARM_MODE_A64,
      { 0xff, 0x24, 0x03, 0xd5 }, 4, CDISASM_ARM_NAME_PACM,
      "pacm" },
    { "chkfeat", CDISASM_ARM_MODE_A64,
      { 0x1f, 0x25, 0x03, 0xd5 }, 4, CDISASM_ARM_NAME_CHKFEAT,
      "chkfeat x16" },
    { "a64-and-immediate", CDISASM_ARM_MODE_A64,
      { 0x20, 0x9c, 0x08, 0x92 }, 4, CDISASM_ARM_NAME_AND,
      "and x0, x1, #0xff00ff00ff00ff00" },
    { "a64-orr-immediate-sp", CDISASM_ARM_MODE_A64,
      { 0x5f, 0x1c, 0x40, 0xb2 }, 4, CDISASM_ARM_NAME_ORR,
      "orr sp, x2, #0xff" },
    { "a64-eor-immediate-w", CDISASM_ARM_MODE_A64,
      { 0x83, 0x9c, 0x00, 0x52 }, 4, CDISASM_ARM_NAME_EOR,
      "eor w3, w4, #0xff00ff" },
    { "a64-ands-immediate", CDISASM_ARM_MODE_A64,
      { 0xc5, 0xcc, 0x04, 0xf2 }, 4, CDISASM_ARM_NAME_ANDS,
      "ands x5, x6, #0xf0f0f0f0f0f0f0f0" },
    { "a64-tst-immediate-w", CDISASM_ARM_MODE_A64,
      { 0xff, 0x04, 0x01, 0x72 }, 4, CDISASM_ARM_NAME_TST,
      "tst w7, #0x80000001" },
    { "a64-mov-bitmask", CDISASM_ARM_MODE_A64,
      { 0xe8, 0x9f, 0x00, 0xb2 }, 4, CDISASM_ARM_NAME_MOV,
      "mov x8, #0xff00ff00ff00ff" },
    { "a64-mov-bitmask-negative", CDISASM_ARM_MODE_A64,
      { 0xe9, 0x9f, 0x08, 0xb2 }, 4, CDISASM_ARM_NAME_MOV,
      "mov x9, #-0xff00ff00ff0100" },
    { "a64-orr-movz-preferred", CDISASM_ARM_MODE_A64,
      { 0xea, 0x03, 0x40, 0xb2 }, 4, CDISASM_ARM_NAME_ORR,
      "orr x10, xzr, #0x1" },
    { "a64-mov-bitmask-sp", CDISASM_ARM_MODE_A64,
      { 0xff, 0x9f, 0x00, 0xb2 }, 4, CDISASM_ARM_NAME_MOV,
      "mov sp, #0xff00ff00ff00ff" },
    { "a64-mov-bitmask-wsp", CDISASM_ARM_MODE_A64,
      { 0xff, 0x9f, 0x00, 0x32 }, 4, CDISASM_ARM_NAME_MOV,
      "mov wsp, #0xff00ff" }
};

static int failures;

#define EXPECT(condition) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "%s:%d: expectation failed: %s\n", \
                    __FILE__, __LINE__, #condition); \
            ++failures; \
        } \
    } while (0)

static uint32_t decode_case(
    const modern_case *test_case,
    cdisasm_arm_cpu_id cpu_id,
    cdisasm_arm_decode_option flags,
    cdisasm_arm_instruction *instruction)
{
    return cdisasm_arm_decode(
        cpu_id, test_case->mode, test_case->bytes, test_case->byte_count,
        UINT64_C(0x1000), flags, instruction);
}

static int is_error_only(
    const cdisasm_arm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static void expect_word_error(
    uint32_t word,
    cdisasm_status expected_status)
{
    uint8_t bytes[4] = {
        (uint8_t)word, (uint8_t)(word >> 8),
        (uint8_t)(word >> 16), (uint8_t)(word >> 24)
    };
    cdisasm_arm_instruction instruction;
    uint32_t decoded;

    memset(&instruction, 0xa5, sizeof(instruction));
    decoded = cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x1000),
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    if (decoded != 0u || !is_error_only(&instruction, expected_status)) {
        fprintf(stderr,
            "word %08x: decoded=%u expected_status=%u actual_status=%u "
            "name=%u form=%u flags=%08x\n",
            (unsigned)word, (unsigned)decoded, (unsigned)expected_status,
            (unsigned)instruction.last_error_id,
            (unsigned)instruction.name_id, (unsigned)instruction.form_id,
            (unsigned)instruction.instruction_flags);
        ++failures;
    }
}

static uint64_t expected_low_mask(unsigned count)
{
    return count == 64u
        ? UINT64_MAX
        : (UINT64_C(1) << count) - UINT64_C(1);
}

static int expected_logical_immediate(
    unsigned sf,
    unsigned n,
    unsigned immr,
    unsigned imms,
    uint64_t *value)
{
    unsigned combined;
    int length;
    unsigned element_size;
    unsigned levels;
    unsigned set_bits;
    unsigned rotation;
    uint64_t element;
    uint64_t result = UINT64_C(0);
    unsigned offset;

    if (sf == 0u && n != 0u) {
        return 0;
    }
    combined = (n << 6) | ((~imms) & 63u);
    for (length = 6; length >= 1; --length) {
        if ((combined & (1u << (unsigned)length)) != 0u) {
            break;
        }
    }
    if (length < 1) {
        return 0;
    }
    element_size = 1u << (unsigned)length;
    levels = element_size - 1u;
    set_bits = imms & levels;
    if (set_bits == levels) {
        return 0;
    }
    rotation = immr & levels;
    element = expected_low_mask(set_bits + 1u);
    if (rotation != 0u) {
        element = ((element >> rotation)
            | (element << (element_size - rotation)))
            & expected_low_mask(element_size);
    }
    for (offset = 0u; offset < (sf != 0u ? 64u : 32u);
         offset += element_size) {
        result |= element << offset;
    }
    *value = result;
    return 1;
}

#if USE_EXTRA_OPCODES
static int expected_move_wide_preferred(uint64_t value, unsigned width)
{
    uint64_t width_mask = expected_low_mask(width);
    unsigned shift;

    value &= width_mask;
    for (shift = 0u; shift < width; shift += 16u) {
        uint64_t chunk = UINT64_C(0xffff) << shift;
        uint64_t outside = width_mask ^ chunk;

        if ((value & outside) == 0u
            || (value | chunk) == width_mask) {
            return 1;
        }
    }
    return 0;
}
#endif

static int expect_logical_space(
    int condition,
    uint32_t word,
    const char *detail)
{
    if (!condition) {
        fprintf(stderr,
                "%s:%d: logical-immediate 0x%08x failed: %s\n",
                __FILE__, __LINE__, (unsigned)word, detail);
        ++failures;
        return 0;
    }
    return 1;
}

static void test_logical_immediate_encoding_space(void)
{
    static const unsigned register_fields[2] = { 0u, 31u };
#if USE_EXTRA_OPCODES
    static const cdisasm_arm_name_id names[4] = {
        CDISASM_ARM_NAME_AND, CDISASM_ARM_NAME_ORR,
        CDISASM_ARM_NAME_EOR, CDISASM_ARM_NAME_ANDS
    };
    size_t move_aliases = 0u;
    size_t test_aliases = 0u;
#endif
    size_t valid_fields = 0u;
    unsigned sf;
    unsigned n;
    unsigned immr;
    unsigned imms;

    for (sf = 0u; sf < 2u; ++sf) {
        for (n = 0u; n < 2u; ++n) {
            for (immr = 0u; immr < 64u; ++immr) {
                for (imms = 0u; imms < 64u; ++imms) {
                    uint64_t expected_immediate = UINT64_C(0);
                    int valid = expected_logical_immediate(
                        sf, n, immr, imms, &expected_immediate);
                    unsigned opcode;

                    if (!valid) {
                        uint32_t word = UINT32_C(0x12000020)
                            | (sf << 31) | (n << 22)
                            | (immr << 16) | (imms << 10);
                        uint8_t bytes[4] = {
                            (uint8_t)word, (uint8_t)(word >> 8),
                            (uint8_t)(word >> 16), (uint8_t)(word >> 24)
                        };
                        cdisasm_arm_instruction instruction;

                        memset(&instruction, 0xa5, sizeof(instruction));
                        if (!expect_logical_space(
                                cdisasm_arm_decode(
                                    CDISASM_ARM_CPU_ANY,
                                    CDISASM_ARM_MODE_A64,
                                    bytes, sizeof(bytes), UINT64_C(0x1000),
                                    CDISASM_ARM_DECODE_OPTION_NONE,
                                    &instruction) == 0u
                                && is_error_only(
                                    &instruction,
                                    CDISASM_STATUS_INVALID_INSTRUCTION),
                                word, "reserved encoding status")) {
                            return;
                        }
                        continue;
                    }
                    ++valid_fields;

                    for (opcode = 0u; opcode < 4u; ++opcode) {
                        unsigned rn_index;

                        for (rn_index = 0u; rn_index < 2u; ++rn_index) {
                            unsigned rd_index;

                            for (rd_index = 0u; rd_index < 2u; ++rd_index) {
                                unsigned rn = register_fields[rn_index];
                                unsigned rd = register_fields[rd_index];
                                uint32_t word = UINT32_C(0x12000000)
                                    | (sf << 31) | (opcode << 29)
                                    | (n << 22) | (immr << 16)
                                    | (imms << 10) | (rn << 5) | rd;
                                uint8_t bytes[4] = {
                                    (uint8_t)word, (uint8_t)(word >> 8),
                                    (uint8_t)(word >> 16),
                                    (uint8_t)(word >> 24)
                                };
                                cdisasm_arm_instruction instruction;
                                uint32_t decoded;

                                memset(
                                    &instruction, 0xa5,
                                    sizeof(instruction));
                                decoded = cdisasm_arm_decode(
                                    CDISASM_ARM_CPU_ANY,
                                    CDISASM_ARM_MODE_A64,
                                    bytes, sizeof(bytes), UINT64_C(0x1000),
                                    CDISASM_ARM_DECODE_OPTION_NONE,
                                    &instruction);
#if USE_EXTRA_OPCODES
                                {
                                    int test_alias = opcode == 3u
                                        && rd == 31u;
                                    int move_alias = opcode == 1u
                                        && rn == 31u
                                        && !expected_move_wide_preferred(
                                            expected_immediate,
                                            sf != 0u ? 64u : 32u);
                                    cdisasm_arm_name_id expected_name =
                                        test_alias ? CDISASM_ARM_NAME_TST
                                        : (move_alias
                                            ? CDISASM_ARM_NAME_MOV
                                            : names[opcode]);
                                    unsigned expected_count =
                                        test_alias || move_alias ? 2u : 3u;
                                    const cdisasm_arm_operand *immediate =
                                        &instruction.operand[
                                            expected_count - 1u];
                                    uint64_t stored_immediate =
                                        expected_immediate;
                                    int signed_immediate = move_alias
                                        && (expected_immediate
                                            & (UINT64_C(1)
                                                << (sf != 0u
                                                    ? 63u : 31u))) != 0u;

                                    if (move_alias) {
                                        ++move_aliases;
                                    }
                                    if (test_alias) {
                                        ++test_aliases;
                                    }
                                    if (signed_immediate && sf == 0u) {
                                        stored_immediate |=
                                            UINT64_C(0xffffffff00000000);
                                    }
                                    if (!expect_logical_space(
                                            decoded == 4u
                                            && instruction.last_error_id
                                                == CDISASM_STATUS_OK
                                            && instruction.name_id
                                                == expected_name
                                            && instruction.operand_count
                                                == expected_count
                                            && instruction.instruction_flags
                                                == (opcode == 3u
                                                    ? CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS
                                                    : 0u)
                                            && instruction.opcode_groups == 0u
                                            && immediate->type
                                                == CDISASM_OPERAND_IMMEDIATE
                                            && immediate->imm
                                                == stored_immediate
                                            && immediate->size
                                                == (sf != 0u ? 8u : 4u)
                                            && immediate->access
                                                == CDISASM_OPERAND_ACCESS_READ
                                            && immediate->flags
                                                == (signed_immediate
                                                    ? CDISASM_OPERAND_FLAG_SIGNED
                                                    : 0u),
                                            word,
                                            "decoded identity/immediate")) {
                                        return;
                                    }
                                    if (!test_alias
                                        && !expect_logical_space(
                                            instruction.operand[0].reg
                                                == (rd == 31u
                                                    ? (opcode == 3u
                                                        ? (sf != 0u
                                                            ? CDISASM_ARM_REG_XZR
                                                            : CDISASM_ARM_REG_WZR)
                                                        : (sf != 0u
                                                            ? CDISASM_ARM_REG_SP
                                                            : CDISASM_ARM_REG_WSP))
                                                    : (cdisasm_arm_reg_id)(
                                                        (sf != 0u
                                                            ? CDISASM_ARM_REG_X0
                                                            : CDISASM_ARM_REG_W0)
                                                        + rd))
                                            && instruction.operand[0].access
                                                == CDISASM_OPERAND_ACCESS_WRITE,
                                            word, "Rd SP/ZR semantics")) {
                                        return;
                                    }
                                    if (!move_alias) {
                                        unsigned source_index =
                                            test_alias ? 0u : 1u;

                                        if (!expect_logical_space(
                                                instruction.operand[
                                                    source_index].reg
                                                    == (rn == 31u
                                                        ? (sf != 0u
                                                            ? CDISASM_ARM_REG_XZR
                                                            : CDISASM_ARM_REG_WZR)
                                                        : (cdisasm_arm_reg_id)(
                                                            (sf != 0u
                                                                ? CDISASM_ARM_REG_X0
                                                                : CDISASM_ARM_REG_W0)
                                                            + rn))
                                                && instruction.operand[
                                                    source_index].access
                                                    == CDISASM_OPERAND_ACCESS_READ,
                                                word, "Rn ZR semantics")) {
                                            return;
                                        }
                                    }
                                }
#else
                                if (!expect_logical_space(
                                        decoded == 0u
                                        && is_error_only(
                                            &instruction,
                                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                                        word, "OFF-build ownership")) {
                                    return;
                                }
#endif
                            }
                        }
                    }
                }
            }
        }
    }
    EXPECT(valid_fields == 11328u);
#if USE_EXTRA_OPCODES
    EXPECT(move_aliases == 18312u);
    EXPECT(test_aliases == 22656u);
#endif
}

static void test_gate_and_format(void)
{
    size_t index;

    for (index = 0u;
         index < sizeof(modern_cases) / sizeof(modern_cases[0]);
         ++index) {
        const modern_case *test_case = &modern_cases[index];
        cdisasm_arm_instruction instruction;
        uint32_t decoded;

        memset(&instruction, 0xa5, sizeof(instruction));
        decoded = decode_case(
            test_case, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
        char text[160];

        EXPECT(decoded == test_case->byte_count);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == test_case->name_id);
        EXPECT(instruction.address == UINT64_C(0x1000));
#if USE_DISASM_FORMAT
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_0,
            text, sizeof(text)) == strlen(test_case->text));
        EXPECT(strcmp(text, test_case->text) == 0);
#else
        (void)text;
#endif
#else
        (void)decoded;
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

static void test_endian_and_cpu_gates(void)
{
    static const modern_case big_endian_add = {
        "sve-add-be", CDISASM_ARM_MODE_A64,
        { 0x04, 0x80, 0x08, 0x61 }, 4, CDISASM_ARM_NAME_ADD,
        "add z1.s, p2/m, z1.s, z3.s"
    };
    cdisasm_arm_instruction instruction;
    uint32_t decoded = decode_case(
        &big_endian_add, CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &instruction);

#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
#if USE_EXTRA_OPCODES
    EXPECT(instruction.raw_instruction == UINT32_C(0x04800861));
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_ADD);
    EXPECT(decode_case(
        &modern_cases[36], CDISASM_ARM_CPU_CORTEX_A53,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
    EXPECT(decode_case(
        &modern_cases[7], CDISASM_ARM_CPU_CORTEX_A53,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(decode_case(
        &modern_cases[49], CDISASM_ARM_CPU_APPLE_A12,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(decode_case(
        &modern_cases[49], CDISASM_ARM_CPU_APPLE_M1,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(decode_case(
        &modern_cases[54], CDISASM_ARM_CPU_APPLE_A11,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
#else
    EXPECT(is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif

    {
        static const modern_case big_endian_logical = {
            "a64-and-immediate-be", CDISASM_ARM_MODE_A64,
            { 0x92, 0x08, 0x9c, 0x20 }, 4, CDISASM_ARM_NAME_AND,
            "and x0, x1, #0xff00ff00ff00ff00"
        };
        const size_t logical_first =
            sizeof(modern_cases) / sizeof(modern_cases[0]) - 10u;

        decoded = decode_case(
            &big_endian_logical, CDISASM_ARM_CPU_CORTEX_A34,
            CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &instruction);
#if USE_EXTRA_OPCODES
        EXPECT(decoded == 4u);
        EXPECT(instruction.raw_instruction == UINT32_C(0x92089c20));
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_AND);
        EXPECT(decode_case(
            &modern_cases[logical_first], CDISASM_ARM_CPU_CORTEX_A34,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(decode_case(
            &modern_cases[logical_first], CDISASM_ARM_CPU_CORTEX_A7,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
#else
        (void)logical_first;
        EXPECT(decoded == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

#if USE_EXTRA_OPCODES
static void expect_profile_success(
    cdisasm_arm_cpu_id cpu_id,
    const modern_case *test_case)
{
    cdisasm_arm_instruction instruction;

    EXPECT(decode_case(
        test_case, cpu_id, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == test_case->byte_count);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == test_case->name_id);
}
#endif

static void expect_profile_error(
    cdisasm_arm_cpu_id cpu_id,
    const modern_case *test_case,
    cdisasm_status status)
{
    cdisasm_arm_instruction instruction;

    EXPECT(decode_case(
        test_case, cpu_id, CDISASM_ARM_DECODE_OPTION_NONE,
        &instruction) == 0u);
    EXPECT(is_error_only(&instruction, status));
}

static void test_named_profiles(void)
{
#if USE_EXTRA_OPCODES
    static const cdisasm_arm_cpu_id sme_profiles[] = {
        CDISASM_ARM_CPU_APPLE_A18,
        CDISASM_ARM_CPU_APPLE_M4
    };
    static const cdisasm_arm_cpu_id no_sme_profiles[] = {
        CDISASM_ARM_CPU_APPLE_A17,
        CDISASM_ARM_CPU_APPLE_A19,
        CDISASM_ARM_CPU_APPLE_M3,
        CDISASM_ARM_CPU_APPLE_M5
    };
    cdisasm_arm_cpu_id cpu_id;
    size_t index;

    for (index = 0u;
         index < sizeof(sme_profiles) / sizeof(sme_profiles[0]);
         ++index) {
        expect_profile_success(sme_profiles[index], &modern_cases[40]);
        expect_profile_success(sme_profiles[index], &modern_cases[41]);
        expect_profile_success(sme_profiles[index], &modern_cases[44]);
    }
    for (index = 0u;
         index < sizeof(no_sme_profiles) / sizeof(no_sme_profiles[0]);
         ++index) {
        expect_profile_error(
            no_sme_profiles[index], &modern_cases[40],
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_profile_error(
            no_sme_profiles[index], &modern_cases[44],
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    for (cpu_id = CDISASM_ARM_CPU_APPLE_S4;
         cpu_id <= CDISASM_ARM_CPU_APPLE_S10;
         ++cpu_id) {
        expect_profile_success(cpu_id, &modern_cases[54]);
        expect_profile_success(cpu_id, &modern_cases[55]);
    }
    expect_profile_error(
        CDISASM_ARM_CPU_APPLE_A10, &modern_cases[54],
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_profile_error(
        CDISASM_ARM_CPU_APPLE_A10, &modern_cases[55],
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_profile_error(
        CDISASM_ARM_CPU_APPLE_A11, &modern_cases[55],
        CDISASM_STATUS_INVALID_INSTRUCTION);
#else
    expect_profile_error(
        CDISASM_ARM_CPU_APPLE_A18, &modern_cases[40],
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_profile_error(
        CDISASM_ARM_CPU_APPLE_M4, &modern_cases[44],
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_profile_error(
        CDISASM_ARM_CPU_APPLE_S4, &modern_cases[54],
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_profile_error(
        CDISASM_ARM_CPU_APPLE_S10, &modern_cases[55],
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

#if USE_EXTRA_OPCODES
static void test_metadata(void)
{
    cdisasm_arm_instruction instruction;
    const cdisasm_arm_operand *operand;
    const size_t logical_first =
        sizeof(modern_cases) / sizeof(modern_cases[0]) - 10u;

    EXPECT(decode_case(
        &modern_cases[10], CDISASM_ARM_CPU_CORTEX_A34,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_NEGS);
    EXPECT(instruction.operand_count == 2u);
    EXPECT(instruction.instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_W2);
    EXPECT(instruction.operand[0].access
        == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_W3);
    EXPECT(instruction.operand[1].shift_type == CDISASM_ARM_SHIFT_LSR);
    EXPECT(instruction.operand[1].shift_amount == 4u);

    EXPECT(decode_case(
        &modern_cases[12], CDISASM_ARM_CPU_CORTEX_A34,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_ADCS);
    EXPECT(instruction.operand_count == 3u);
    EXPECT(instruction.instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS);

    EXPECT(decode_case(
        &modern_cases[22], CDISASM_ARM_CPU_CORTEX_A34,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_CSET);
    EXPECT(instruction.operand_count == 2u);
    EXPECT(instruction.condition == CDISASM_ARM_CONDITION_AL);
    EXPECT(instruction.opcode_groups == 0u);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_W10);
    EXPECT(instruction.operand[1].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction.operand[1].imm == CDISASM_ARM_CONDITION_NE);

    {
        static const uint8_t csinc_al[] = { 0x20, 0xe4, 0x81, 0x9a };

        EXPECT(cdisasm_arm_decode(
            CDISASM_ARM_CPU_CORTEX_A34, CDISASM_ARM_MODE_A64,
            csinc_al, sizeof(csinc_al), UINT64_C(0x1000),
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_CSINC);
        EXPECT(instruction.operand_count == 4u);
        EXPECT(instruction.operand[3].imm == CDISASM_ARM_CONDITION_AL);
    }

    EXPECT(decode_case(
        &modern_cases[32], CDISASM_ARM_CPU_CORTEX_A34,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_MADD);
    EXPECT(instruction.operand_count == 4u);
    EXPECT(instruction.operand[0].access
        == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.operand[1].access
        == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.operand[2].access
        == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.operand[3].access
        == CDISASM_OPERAND_ACCESS_READ);

    EXPECT(decode_case(
        &modern_cases[logical_first + 1u], CDISASM_ARM_CPU_CORTEX_A34,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_ORR);
    EXPECT(instruction.operand_count == 3u);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_SP);
    EXPECT(instruction.operand[0].access
        == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_X2);
    EXPECT(instruction.operand[2].imm == UINT64_C(0xff));

    EXPECT(decode_case(
        &modern_cases[logical_first + 4u], CDISASM_ARM_CPU_CORTEX_A34,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_TST);
    EXPECT(instruction.operand_count == 2u);
    EXPECT(instruction.instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_W7);
    EXPECT(instruction.operand[0].access
        == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.operand[1].imm == UINT64_C(0x80000001));

    EXPECT(decode_case(
        &modern_cases[logical_first + 6u], CDISASM_ARM_CPU_CORTEX_A34,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_MOV);
    EXPECT(instruction.operand_count == 2u);
    EXPECT(instruction.operand[1].imm
        == UINT64_C(0xff00ff00ff00ff00));
    EXPECT(instruction.operand[1].flags
        == CDISASM_OPERAND_FLAG_SIGNED);

    EXPECT(decode_case(
        &modern_cases[logical_first + 7u], CDISASM_ARM_CPU_CORTEX_A34,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_ORR);
    EXPECT(instruction.operand_count == 3u);
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_XZR);

    EXPECT(decode_case(
        &modern_cases[logical_first + 9u], CDISASM_ARM_CPU_CORTEX_A34,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_MOV);
    EXPECT(instruction.operand_count == 2u);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_WSP);
    EXPECT(instruction.operand[0].access
        == CDISASM_OPERAND_ACCESS_WRITE);

    {
        static const uint8_t cneg_zero[] = { 0xe0, 0x17, 0x9f, 0xda };

        EXPECT(cdisasm_arm_decode(
            CDISASM_ARM_CPU_CORTEX_A34, CDISASM_ARM_MODE_A64,
            cneg_zero, sizeof(cneg_zero), UINT64_C(0x1000),
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_CNEG);
        EXPECT(instruction.operand_count == 3u);
        EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_XZR);
        EXPECT(instruction.operand[2].imm == CDISASM_ARM_CONDITION_EQ);
    }

    EXPECT(decode_case(
        &modern_cases[36], CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(instruction.operand_count == 4u);
    EXPECT(instruction.instruction_flags
        == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
    EXPECT(instruction.operand[0].type
        == CDISASM_ARM_OPERAND_SCALABLE_REGISTER);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_Z1);
    EXPECT(instruction.operand[0].access
        == CDISASM_OPERAND_ACCESS_READ_WRITE);
    EXPECT(instruction.operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE);
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_P2);
    EXPECT(instruction.operand[1].flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE);

    EXPECT(decode_case(
        &modern_cases[41], CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(instruction.operand_count == 4u);
    EXPECT((instruction.instruction_flags
        & (CDISASM_ARM_INSTRUCTION_FLAG_SME
            | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
            | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED))
        == (CDISASM_ARM_INSTRUCTION_FLAG_SME
            | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
            | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED));
    EXPECT(instruction.operand[0].type == CDISASM_ARM_OPERAND_TILE);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_ZAS1);
    EXPECT(instruction.operand[1].type
        == CDISASM_ARM_OPERAND_PREDICATE_PAIR);
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_P0);
    EXPECT(instruction.operand[1].index_reg == CDISASM_ARM_REG_P1);

    EXPECT(decode_case(
        &modern_cases[45], CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT((instruction.instruction_flags
        & CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC_PAIR) != 0u);
    EXPECT(instruction.operand[0].type
        == CDISASM_ARM_OPERAND_REGISTER_PAIR_BASE);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_X0);
    EXPECT(instruction.operand[0].index_reg == CDISASM_ARM_REG_X1);
    EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.operand[1].reg == CDISASM_ARM_REG_X2);
    EXPECT(instruction.operand[1].index_reg == CDISASM_ARM_REG_X3);
    EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.operand[2].size == 16u);

    EXPECT(decode_case(
        &modern_cases[46], CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT((instruction.instruction_flags
        & (CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX)) == 0u);
    EXPECT(instruction.operand[2].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.operand[2].size == 16u);
    EXPECT(instruction.operand[2].flags == CDISASM_OPERAND_FLAG_NONE);

    EXPECT(decode_case(
        &modern_cases[51], CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(instruction.operand[0].base_reg == CDISASM_ARM_REG_X0);
    EXPECT(instruction.operand[1].base_reg == CDISASM_ARM_REG_X1);
    EXPECT(instruction.operand[2].reg == CDISASM_ARM_REG_X2);
    EXPECT(instruction.operand[0].flags
        == CDISASM_ARM_OPERAND_FLAG_WRITEBACK);
    EXPECT(instruction.operand[1].flags
        == CDISASM_ARM_OPERAND_FLAG_WRITEBACK);
    EXPECT(instruction.operand[2].flags
        == CDISASM_ARM_OPERAND_FLAG_WRITEBACK);

    EXPECT(decode_case(
        &modern_cases[52], CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(instruction.operand[0].type
        == CDISASM_ARM_OPERAND_REGISTER_BLOCK);
    EXPECT(instruction.operand[0].reg == CDISASM_ARM_REG_X0);
    EXPECT(instruction.operand[0].register_list == 8u);
    EXPECT(instruction.operand[0].size == 64u);

    {
        static const uint8_t negative_rdsvl[] = { 0xe1, 0x5f, 0xbf, 0x04 };

        EXPECT(cdisasm_arm_decode(
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            negative_rdsvl, sizeof(negative_rdsvl), UINT64_C(0x1000),
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        operand = &instruction.operand[1];
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_RDSVL);
        EXPECT(operand->imm == UINT64_MAX);
        EXPECT((operand->flags & CDISASM_OPERAND_FLAG_SIGNED) != 0u);
    }

    {
        static const cdisasm_arm_name_id lse128_names[3][4] = {
            { CDISASM_ARM_NAME_LDCLRP, CDISASM_ARM_NAME_LDCLRPA,
              CDISASM_ARM_NAME_LDCLRPL, CDISASM_ARM_NAME_LDCLRPAL },
            { CDISASM_ARM_NAME_LDSETP, CDISASM_ARM_NAME_LDSETPA,
              CDISASM_ARM_NAME_LDSETPL, CDISASM_ARM_NAME_LDSETPAL },
            { CDISASM_ARM_NAME_SWPP, CDISASM_ARM_NAME_SWPPA,
              CDISASM_ARM_NAME_SWPPL, CDISASM_ARM_NAME_SWPPAL }
        };
        static const unsigned operations[] = { 1u, 3u, 8u };
        unsigned operation_index;
        unsigned ordering;

        for (operation_index = 0u; operation_index < 3u;
             ++operation_index) {
            for (ordering = 0u; ordering < 4u; ++ordering) {
                uint32_t word = UINT32_C(0x19220080)
                    | (operations[operation_index] << 12)
                    | ((ordering & 1u) << 23)
                    | (((ordering >> 1) & 1u) << 22);
                uint8_t bytes[4] = {
                    (uint8_t)word, (uint8_t)(word >> 8),
                    (uint8_t)(word >> 16), (uint8_t)(word >> 24)
                };

                EXPECT(cdisasm_arm_decode(
                    CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                    bytes, sizeof(bytes), UINT64_C(0x1000),
                    CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
                EXPECT(instruction.name_id
                    == lse128_names[operation_index][ordering]);
                EXPECT(instruction.operand[0].access
                    == CDISASM_OPERAND_ACCESS_READ);
                EXPECT(instruction.operand[1].access
                    == CDISASM_OPERAND_ACCESS_WRITE);
                EXPECT(instruction.operand[2].size == 16u);
            }
        }
    }
}
#endif

static void test_reserved_truncated_and_lse2(void)
{
    static const uint8_t ldp[] = { 0x40, 0x04, 0x40, 0xa9 };
    static const uint8_t truncated[] = { 0x61, 0x08, 0x80 };
    cdisasm_arm_instruction instruction;

    expect_word_error(
        UINT32_C(0x19222080), CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_word_error(
        UINT32_C(0xf83fd101), CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_word_error(
        UINT32_C(0x19411840), CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_word_error(
        UINT32_C(0x59411840), CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_word_error(
        UINT32_C(0x8bc20c20), CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_word_error(
        UINT32_C(0x0b028020), CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_word_error(
        UINT32_C(0x12400020), CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_word_error(
        UINT32_C(0x1200fc20), CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_word_error(
        UINT32_C(0x1ac00020),
#if USE_EXTRA_OPCODES
        CDISASM_STATUS_INVALID_INSTRUCTION);
#else
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    /* Bit 23 selects the SVE2 SBC family; do not misclassify it as ADCL. */
#if USE_EXTRA_OPCODES
    {
        static const uint32_t sbclb_words[] = {
            UINT32_C(0x4583d041), UINT32_C(0x45c3d041)
        };
        size_t index;

        for (index = 0u;
             index < sizeof(sbclb_words) / sizeof(sbclb_words[0]);
             ++index) {
            uint32_t word = sbclb_words[index];
            uint8_t bytes[4] = {
                (uint8_t)word, (uint8_t)(word >> 8),
                (uint8_t)(word >> 16), (uint8_t)(word >> 24)
            };

            memset(&instruction, 0xa5, sizeof(instruction));
            EXPECT(cdisasm_arm_decode(
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                bytes, sizeof(bytes), UINT64_C(0x1000),
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
            EXPECT(instruction.name_id == CDISASM_ARM_NAME_SBCLB);
            EXPECT(instruction.form_id == UINT16_C(2837));
            EXPECT(instruction.operand_count == 3u);
            EXPECT(instruction.instruction_flags
                == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                    | CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK));
        }
    }
#else
    expect_word_error(
        UINT32_C(0x4583d041), CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_word_error(
        UINT32_C(0x45c3d041), CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        truncated, sizeof(truncated), UINT64_C(0x1000),
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
    EXPECT(is_error_only(&instruction, CDISASM_STATUS_TRUNCATED));

    /* FEAT_LSE2 strengthens existing pair-transfer semantics. It does not
     * allocate replacement LDP/STP mnemonics and is never extra-gated. */
    EXPECT(cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        ldp, sizeof(ldp), UINT64_C(0x1000),
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_LDP);
}

int main(void)
{
    test_logical_immediate_encoding_space();
    test_gate_and_format();
    test_endian_and_cpu_gates();
    test_named_profiles();
#if USE_EXTRA_OPCODES
    test_metadata();
#endif
    test_reserved_truncated_and_lse2();

    if (failures != 0) {
        fprintf(stderr, "%d ARM modern test(s) failed\n", failures);
        return 1;
    }
    printf("ARM modern tests passed (USE_EXTRA_OPCODES=%d)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
