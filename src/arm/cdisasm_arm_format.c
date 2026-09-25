#include "cdisasm/cdisasm_format.h"
#include "arm_generated_decoder.h"
#include "arm_generated_formatter.h"
#include "arm_pstate_msr_format.h"

#if USE_DISASM_FORMAT && USE_ARCH_ARM

#include <stdint.h>

typedef struct arm_text_writer {
    char *buffer;
    size_t buffer_size;
    size_t length;
} arm_text_writer;

static const char *const arm_mnemonic_names[CDISASM_ARM_NAME_COUNT] = {
    NULL, "adc", "add", "adds", "adr", "adrp", "and", "ands",
    "b", "bic", "bkpt", "bl", "blr", "blx", "br", "brk",
    "bx", "cbnz", "cbz", "cmn", "cmp", "eor", "hvc", "ldm",
    "ldp", "ldr", "ldrb", "ldrh", "ldur", "ldurb", "ldurh", "mov",
    "movk", "movn", "movz", "mvn", "nop", "orr", "pop", "push",
    "ret", "rsb", "rsc", "sbc", "smc", "stm", "stp", "str",
    "strb", "strh", "stur", "sturb", "sturh", "sub", "subs", "svc",
    "tbnz", "tbz", "teq", "tst", "ldrbt", "ldrt", "strbt", "strt",
    "vadd", "vsub", "vand", "vorr", "veor", "vmul", "fadd", "fsub",
    "fmul", "fdiv", "mul", "vbic", "at_as1elx", "clr", "extrx",
    "extry", "fma16", "fma32", "fma64", "fms16", "fms32", "fms64",
    "genlut", "genter", "gexit", "ldx", "ldy", "ldz", "ldzi", "mac16",
    "matfp", "matint", "mrs", "msr", "mul53hi", "mul53lo", "sdsb",
    "set", "stx", "sty", "stz", "stzi", "vecfp", "vecint", "wkdmc",
    "wkdmd", "ldarb", "ldarh", "ldar", "ldaxrb", "ldaxrh", "ldaxr",
    "ldxrb", "ldxrh", "ldxr", "ldxp", "ldaxp", "stlrb", "stlrh",
    "stlr", "stlxrb", "stlxrh", "stlxr", "stxrb", "stxrh", "stxr",
    "stxp", "stlxp",
#if USE_EXTRA_OPCODES
    "casb", "cash", "cas", "casab", "casah", "casa",
    "caslb", "caslh", "casl", "casalb", "casalh", "casal", "casp",
    "caspa", "caspl", "caspal", "ldaddb", "ldaddh", "ldadd", "ldaddab",
    "ldaddah", "ldadda", "ldaddlb", "ldaddlh", "ldaddl", "ldaddalb",
    "ldaddalh", "ldaddal", "ldclrb", "ldclrh", "ldclr", "ldclrab",
    "ldclrah", "ldclra", "ldclrlb", "ldclrlh", "ldclrl", "ldclralb",
    "ldclralh", "ldclral", "ldeorb", "ldeorh", "ldeor", "ldeorab",
    "ldeorah", "ldeora", "ldeorlb", "ldeorlh", "ldeorl", "ldeoralb",
    "ldeoralh", "ldeoral", "ldsetb", "ldseth", "ldset", "ldsetab",
    "ldsetah", "ldseta", "ldsetlb", "ldsetlh", "ldsetl", "ldsetalb",
    "ldsetalh", "ldsetal", "swpb", "swph", "swp", "swpab", "swpah",
    "swpa", "swplb", "swplh", "swpl", "swpalb", "swpalh", "swpal",
    "ldlarb", "ldlarh", "ldlar", "stllrb", "stllrh", "stllr",
    "ldaprb", "ldaprh", "ldapr",
    "mla", "movw", "movt", "clz", "rev", "ldrsb", "ldrsh",
    "dmb", "dsb", "isb", "it", "sdiv", "udiv", "vmla", "vmls",
    "fabs", "fneg", "fsqrt", "fcmp", "fcsel", "fmla", "fmls",
    "smax", "smin", "umax", "umin", "ptrue", "whilelo", "cntb",
    "cnth", "cntw", "cntd", "ld1b", "ld1h", "ld1w", "ld1d",
    "st1b", "st1h", "st1w", "st1d", "adclb", "adclt", "eor3",
    "rax1", "smstart", "smstop", "rdsvl", "fmopa", "smopa", "umopa",
    "luti2", "ldclrp", "ldclrpa", "ldclrpl", "ldclrpal", "ldsetp",
    "ldsetpa", "ldsetpl", "ldsetpal", "swpp", "swppa", "swppl",
    "swppal", "ldiapp", "stilp", "bti", "pacia", "autia", "xpaci",
    "paciasp", "irg", "gmi", "addg", "subg", "stg", "stzg", "ldg",
    "cpyfp", "cpyfm", "cpyfe", "setp", "setm", "sete", "ld64b",
    "st64b", "st64bv", "st64bv0", "abs", "cnt", "ctz", "lsl", "lsr",
    "asr", "mls", "vdiv", "sqrdmlah", "adcs", "sbcs", "csel", "csinc",
    "csinv", "csneg", "madd", "msub", "mneg", "ror", "neg", "negs",
    "ngc", "ngcs", "cinc", "cset", "cinv", "csetm", "cneg", "bics",
    "eors", "nand", "nands", "nor", "nors", "orn", "orns", "orrs",
    "sel", "sqadd", "uqadd", "sqsub", "uqsub", "addpt", "subpt",
    "zip1", "zip2", "uzp1", "uzp2", "trn1", "trn2",
    "tbl", "tbx", "tbxq", "tblq", "subr", "sabd", "uabd",
    "smulh", "umulh", "sdivr", "udivr", "cls", "cnot", "not",
    "sxtb", "sxth", "sxtw", "uxtb", "uxth", "uxtw", "revb",
    "revh", "revw", "rbit", "asrr", "lsrr", "lslr", "asrd",
    "sqshl", "uqshl", "srshr", "urshr", "sqshlu",
    "cmpeq", "cmpne", "cmpge", "cmpgt", "cmphs", "cmphi",
    "cmplt", "cmple", "cmplo", "cmpls", "fcmeq", "fcmne",
    "fcmge", "fcmgt", "fcmle", "fcmlt", "fcmuo", "facge", "facgt",
    "fsubr", "fmaxnm", "fminnm", "fmax", "fmin", "fabd", "fscale",
    "fmulx", "fdivr", "faddv", "fmaxnmv", "fminnmv", "fmaxv",
    "fminv", "fadda", "frintn", "frintp", "frintm", "frintz",
    "frinta", "frintx", "frinti", "frecpx", "frecpe", "frsqrte",
    "scvtf", "ucvtf", "fcvt", "fcvtzs", "fcvtzu", "bfcvt", "bfcvtnt",
    "bfcvtn", "sbfm", "bfm", "ubfm", "extr", "ccmp", "ccmn",
    "crc32b", "crc32h", "crc32w", "crc32x", "crc32cb", "crc32ch",
    "crc32cw", "crc32cx", "eret", "yield", "wfe", "wfi", "sev",
    "sevl", "hint", "sys", "sysl", "clrex",
    "ldsmaxb", "ldsmaxh", "ldsmax", "ldsmaxab", "ldsmaxah", "ldsmaxa",
    "ldsmaxlb", "ldsmaxlh", "ldsmaxl", "ldsmaxalb", "ldsmaxalh",
    "ldsmaxal", "ldsminb", "ldsminh", "ldsmin", "ldsminab",
    "ldsminah", "ldsmina", "ldsminlb", "ldsminlh", "ldsminl",
    "ldsminalb", "ldsminalh", "ldsminal", "ldumaxb", "ldumaxh",
    "ldumax", "ldumaxab", "ldumaxah", "ldumaxa", "ldumaxlb",
    "ldumaxlh", "ldumaxl", "ldumaxalb", "ldumaxalh", "ldumaxal",
    "lduminb", "lduminh", "ldumin", "lduminab", "lduminah",
    "ldumina", "lduminlb", "lduminlh", "lduminl", "lduminalb",
    "lduminalh", "lduminal", "insr", "dupq", "famax", "famin",
#include "arm_mnemonic_names_generated.inc"
#endif
};

static const char *const arm_register_names[CDISASM_ARM_REG_COUNT] = {
    NULL,
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
    "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc",
    "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7",
    "w8", "w9", "w10", "w11", "w12", "w13", "w14", "w15",
    "w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23",
    "w24", "w25", "w26", "w27", "w28", "w29", "w30", "wsp", "wzr",
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
    "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
    "x24", "x25", "x26", "x27", "x28", "x29", "x30", "sp", "xzr",
    "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7",
    "d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15",
    "d16", "d17", "d18", "d19", "d20", "d21", "d22", "d23",
    "d24", "d25", "d26", "d27", "d28", "d29", "d30", "d31",
    "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7",
    "q8", "q9", "q10", "q11", "q12", "q13", "q14", "q15",
    "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
    "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
    "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
    "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31",
    "cpm_ioacc_ctl_el3"
#if USE_EXTRA_OPCODES
    , "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7",
    "b8", "b9", "b10", "b11", "b12", "b13", "b14", "b15",
    "b16", "b17", "b18", "b19", "b20", "b21", "b22", "b23",
    "b24", "b25", "b26", "b27", "b28", "b29", "b30", "b31",
    "h0", "h1", "h2", "h3", "h4", "h5", "h6", "h7",
    "h8", "h9", "h10", "h11", "h12", "h13", "h14", "h15",
    "h16", "h17", "h18", "h19", "h20", "h21", "h22", "h23",
    "h24", "h25", "h26", "h27", "h28", "h29", "h30", "h31",
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
    "s8", "s9", "s10", "s11", "s12", "s13", "s14", "s15",
    "s16", "s17", "s18", "s19", "s20", "s21", "s22", "s23",
    "s24", "s25", "s26", "s27", "s28", "s29", "s30", "s31",
    "q16", "q17", "q18", "q19", "q20", "q21", "q22", "q23",
    "q24", "q25", "q26", "q27", "q28", "q29", "q30", "q31",
    "z0", "z1", "z2", "z3", "z4", "z5", "z6", "z7",
    "z8", "z9", "z10", "z11", "z12", "z13", "z14", "z15",
    "z16", "z17", "z18", "z19", "z20", "z21", "z22", "z23",
    "z24", "z25", "z26", "z27", "z28", "z29", "z30", "z31",
    "p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7",
    "p8", "p9", "p10", "p11", "p12", "p13", "p14", "p15",
    "pn0", "pn1", "pn2", "pn3", "pn4", "pn5", "pn6", "pn7",
    "pn8", "pn9", "pn10", "pn11", "pn12", "pn13", "pn14", "pn15",
    "ffr", "za", "za0.b", "za0.h", "za1.h", "za0.s", "za1.s",
    "za2.s", "za3.s", "za0.d", "za1.d", "za2.d", "za3.d", "za4.d",
    "za5.d", "za6.d", "za7.d", "za0.q", "za1.q", "za2.q", "za3.q",
    "za4.q", "za5.q", "za6.q", "za7.q", "za8.q", "za9.q", "za10.q",
    "za11.q", "za12.q", "za13.q", "za14.q", "za15.q", "zt0", "vg"
#endif
};

static const char *const arm_condition_names[] = {
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"
};

static const char *const arm_shift_names[] = {
    NULL, "lsl", "lsr", "asr", "ror", "rrx", "msl"
};

static const char *const arm_extend_names[] = {
    NULL, "uxtb", "uxth", "uxtw", "uxtx",
    "sxtb", "sxth", "sxtw", "sxtx"
};

_Static_assert(
    sizeof(arm_mnemonic_names) / sizeof(arm_mnemonic_names[0])
        == CDISASM_ARM_NAME_COUNT,
    "ARM mnemonic table is incomplete");
_Static_assert(
    sizeof(arm_register_names) / sizeof(arm_register_names[0])
        == CDISASM_ARM_REG_COUNT,
    "ARM register table is incomplete");
_Static_assert(
    sizeof(arm_condition_names) / sizeof(arm_condition_names[0])
        == CDISASM_ARM_CONDITION_NV + 1u,
    "ARM condition table is incomplete");
_Static_assert(
    sizeof(arm_shift_names) / sizeof(arm_shift_names[0])
        == CDISASM_ARM_SHIFT_MSL + 1u,
    "ARM shift table is incomplete");
_Static_assert(
    sizeof(arm_extend_names) / sizeof(arm_extend_names[0])
        == CDISASM_ARM_EXTEND_SXTX + 1u,
    "ARM extension table is incomplete");

static void arm_writer_putc(arm_text_writer *writer, char value)
{
    if (writer->buffer != NULL
        && writer->buffer_size != 0
        && writer->length < writer->buffer_size - 1u) {
        writer->buffer[writer->length] = value;
    }
    ++writer->length;
}

static void arm_writer_puts(arm_text_writer *writer, const char *text)
{
    while (*text != '\0') {
        arm_writer_putc(writer, *text++);
    }
}

static char arm_ascii_upper(char value)
{
    if (value >= 'a' && value <= 'z') {
        return (char)(value - 'a' + 'A');
    }
    return value;
}

static void arm_writer_putc_mnemonic(
    arm_text_writer *writer,
    char value,
    int uppercase)
{
    arm_writer_putc(writer, uppercase ? arm_ascii_upper(value) : value);
}

static void arm_writer_puts_mnemonic(
    arm_text_writer *writer,
    const char *text,
    int uppercase)
{
    while (*text != '\0') {
        arm_writer_putc_mnemonic(writer, *text++, uppercase);
    }
}

static void arm_writer_finish(arm_text_writer *writer)
{
    if (writer->buffer != NULL && writer->buffer_size != 0) {
        size_t ending = writer->length < writer->buffer_size
            ? writer->length
            : writer->buffer_size - 1u;

        writer->buffer[ending] = '\0';
    }
}

static void arm_writer_hex(arm_text_writer *writer, uint64_t value)
{
    static const char digits[] = "0123456789abcdef";
    char reversed[16];
    size_t count = 0;

    arm_writer_puts(writer, "0x");
    do {
        reversed[count++] = digits[value & UINT64_C(0xf)];
        value >>= 4;
    } while (value != 0);
    while (count != 0) {
        arm_writer_putc(writer, reversed[--count]);
    }
}

static void arm_writer_decimal(arm_text_writer *writer, uint64_t value)
{
    char reversed[20];
    size_t count = 0;

    do {
        reversed[count++] = (char)('0' + value % UINT64_C(10));
        value /= UINT64_C(10);
    } while (value != 0);
    while (count != 0) {
        arm_writer_putc(writer, reversed[--count]);
    }
}

static int arm_value_is_negative(uint64_t value)
{
    return (value & (UINT64_C(1) << 63)) != 0;
}

static void arm_writer_signed_hex(arm_text_writer *writer, uint64_t value)
{
    if (arm_value_is_negative(value)) {
        arm_writer_putc(writer, '-');
        value = UINT64_C(0) - value;
    }
    arm_writer_hex(writer, value);
}

static int arm_bytes_are_zero(const void *data, size_t size)
{
    const uint8_t *bytes = (const uint8_t *)data;
    size_t index;

    for (index = 0; index < size; ++index) {
        if (bytes[index] != 0) {
            return 0;
        }
    }
    return 1;
}

static int arm_valid_register_id(cdisasm_arm_reg_id reg)
{
    return reg < CDISASM_ARM_REG_COUNT
        && arm_register_names[reg] != NULL;
}

static int arm_is_a32_register(cdisasm_arm_reg_id reg)
{
    return reg >= CDISASM_ARM_REG_R0 && reg <= CDISASM_ARM_REG_R15;
}

static int arm_is_w_register(cdisasm_arm_reg_id reg)
{
    return reg >= CDISASM_ARM_REG_W0 && reg <= CDISASM_ARM_REG_WZR;
}

static int arm_is_x_register(cdisasm_arm_reg_id reg)
{
    return reg >= CDISASM_ARM_REG_X0 && reg <= CDISASM_ARM_REG_XZR;
}

static int arm_is_vector_register(cdisasm_arm_reg_id reg)
{
    return (reg >= CDISASM_ARM_REG_D0 && reg <= CDISASM_ARM_REG_D31)
        || (reg >= CDISASM_ARM_REG_Q0 && reg <= CDISASM_ARM_REG_Q15)
        || (reg >= CDISASM_ARM_REG_V0 && reg <= CDISASM_ARM_REG_V31);
}

static int arm_is_scalar_fp_register(cdisasm_arm_reg_id reg)
{
    return (reg >= CDISASM_ARM_REG_H0 && reg <= CDISASM_ARM_REG_H31)
        || (reg >= CDISASM_ARM_REG_S0 && reg <= CDISASM_ARM_REG_S31)
        || (reg >= CDISASM_ARM_REG_D0 && reg <= CDISASM_ARM_REG_D31);
}

static int arm_is_sve_integer_reduction_name(cdisasm_arm_name_id name_id)
{
    return name_id == CDISASM_ARM_NAME_SADDV
        || name_id == CDISASM_ARM_NAME_UADDV
        || name_id == CDISASM_ARM_NAME_SMAXV
        || name_id == CDISASM_ARM_NAME_SMINV
        || name_id == CDISASM_ARM_NAME_UMAXV
        || name_id == CDISASM_ARM_NAME_UMINV
        || name_id == CDISASM_ARM_NAME_ORV
        || name_id == CDISASM_ARM_NAME_EORV
        || name_id == CDISASM_ARM_NAME_ANDV;
}

static int arm_is_sve_quadword_reduction_name(cdisasm_arm_name_id name_id)
{
    return name_id == CDISASM_ARM_NAME_ADDQV
        || name_id == CDISASM_ARM_NAME_SMAXQV
        || name_id == CDISASM_ARM_NAME_SMINQV
        || name_id == CDISASM_ARM_NAME_UMAXQV
        || name_id == CDISASM_ARM_NAME_UMINQV
        || name_id == CDISASM_ARM_NAME_ORQV
        || name_id == CDISASM_ARM_NAME_EORQV
        || name_id == CDISASM_ARM_NAME_ANDQV;
}

static int arm_valid_access(cdisasm_operand_access access)
{
    return access >= CDISASM_OPERAND_ACCESS_READ
        && access <= CDISASM_OPERAND_ACCESS_READ_WRITE;
}

static int arm_valid_data_size(uint8_t size)
{
    return size == 1u || size == 2u || size == 4u || size == 8u
        || size == 16u || size == 64u;
}

static int arm_valid_shift(
    cdisasm_arm_shift_type shift_type,
    uint8_t shift_amount)
{
    if (shift_type == CDISASM_ARM_SHIFT_NONE) {
        return shift_amount == 0u;
    }
    if (shift_type == CDISASM_ARM_SHIFT_RRX) {
        return shift_amount == 1u;
    }
    return shift_type >= CDISASM_ARM_SHIFT_LSL
        && shift_type <= CDISASM_ARM_SHIFT_MSL
        && shift_amount <= 63u;
}

static int arm_valid_scalar_register_size(
    cdisasm_arm_reg_id reg,
    uint8_t size)
{
    if (arm_is_a32_register(reg)) {
        return size == 1u || size == 2u || size == 4u;
    }
    if (arm_is_w_register(reg)) {
        return size == 1u || size == 2u || size == 4u;
    }
    if (arm_is_x_register(reg)
        || reg == CDISASM_ARM_REG_CPM_IOACC_CTL_EL3) {
        return size == 8u;
    }
    if (reg >= CDISASM_ARM_REG_B0 && reg <= CDISASM_ARM_REG_B31) {
        return size == 1u;
    }
    if (reg >= CDISASM_ARM_REG_H0 && reg <= CDISASM_ARM_REG_H31) {
        return size == 2u;
    }
    if (reg >= CDISASM_ARM_REG_S0 && reg <= CDISASM_ARM_REG_S31) {
        return size == 4u;
    }
    if (reg >= CDISASM_ARM_REG_D0 && reg <= CDISASM_ARM_REG_D31) {
        return size == 8u;
    }
    return 0;
}

static int arm_is_scalar_advsimd_d_layout(
    const cdisasm_arm_instruction *instruction)
{
    return (instruction->form_id == UINT16_C(5831)
            && instruction->name_id == CDISASM_ARM_NAME_CMTST)
        || (instruction->form_id == UINT16_C(5777)
            && instruction->name_id == CDISASM_ARM_NAME_CMLT)
        || (instruction->form_id == UINT16_C(5794)
            && instruction->name_id == CDISASM_ARM_NAME_CMLE)
        || (instruction->form_id == UINT16_C(5826)
            && instruction->name_id == CDISASM_ARM_NAME_SSHL)
        || (instruction->form_id == UINT16_C(5841)
            && instruction->name_id == CDISASM_ARM_NAME_USHL)
        || (instruction->form_id == UINT16_C(5853)
            && instruction->name_id == CDISASM_ARM_NAME_SSHR)
        || (instruction->form_id == UINT16_C(5863)
            && instruction->name_id == CDISASM_ARM_NAME_USHR)
        || (instruction->form_id == UINT16_C(5854)
            && instruction->name_id == CDISASM_ARM_NAME_SSRA)
        || (instruction->form_id == UINT16_C(5864)
            && instruction->name_id == CDISASM_ARM_NAME_USRA)
        || (instruction->form_id == UINT16_C(5855)
            && instruction->name_id == CDISASM_ARM_NAME_SRSHR)
        || (instruction->form_id == UINT16_C(5865)
            && instruction->name_id == CDISASM_ARM_NAME_URSHR)
        || (instruction->form_id == UINT16_C(5856)
            && instruction->name_id == CDISASM_ARM_NAME_SRSRA)
        || (instruction->form_id == UINT16_C(5866)
            && instruction->name_id == CDISASM_ARM_NAME_URSRA)
        || (instruction->form_id == UINT16_C(5857)
            && instruction->name_id == CDISASM_ARM_NAME_SHL)
        || (instruction->form_id == UINT16_C(5867)
            && instruction->name_id == CDISASM_ARM_NAME_SRI)
        || (instruction->form_id == UINT16_C(5868)
            && instruction->name_id == CDISASM_ARM_NAME_SLI)
        || (instruction->form_id == UINT16_C(6212)
            && instruction->name_id == CDISASM_ARM_NAME_MOVI);
}

static int arm_is_advsimd_sha_name(cdisasm_arm_name_id name_id)
{
    return name_id == CDISASM_ARM_NAME_SHA1C
        || name_id == CDISASM_ARM_NAME_SHA1P
        || name_id == CDISASM_ARM_NAME_SHA1M
        || name_id == CDISASM_ARM_NAME_SHA1SU0
        || name_id == CDISASM_ARM_NAME_SHA1H
        || name_id == CDISASM_ARM_NAME_SHA1SU1
        || name_id == CDISASM_ARM_NAME_SHA256H
        || name_id == CDISASM_ARM_NAME_SHA256H2
        || name_id == CDISASM_ARM_NAME_SHA256SU0
        || name_id == CDISASM_ARM_NAME_SHA256SU1;
}

static int arm_is_a64_advsimd_sha_q_operand(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return 0;
    }
    if (instruction->form_id >= UINT16_C(5731)
        && instruction->form_id <= UINT16_C(5733)) {
        return operand == &instruction->operand[0];
    }
    if (instruction->form_id >= UINT16_C(5735)
        && instruction->form_id <= UINT16_C(5736)) {
        return operand == &instruction->operand[0]
            || operand == &instruction->operand[1];
    }
    if (instruction->form_id >= UINT16_C(6291)
        && instruction->form_id <= UINT16_C(6292)) {
        return operand == &instruction->operand[0]
            || operand == &instruction->operand[1];
    }
    return 0;
}

static int arm_is_a64_advsimd_sha_scalar_operand(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return 0;
    }
    if (instruction->form_id >= UINT16_C(5731)
        && instruction->form_id <= UINT16_C(5733)) {
        return operand == &instruction->operand[1];
    }
    return instruction->form_id == UINT16_C(5738)
        && (operand == &instruction->operand[0]
            || operand == &instruction->operand[1]);
}

static int arm_is_a64_fprcvt_scalar(
    const cdisasm_arm_instruction *instruction)
{
    cdisasm_arm_name_id name = instruction->name_id;

    return instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id >= UINT16_C(6411)
        && instruction->form_id <= UINT16_C(6458)
        && (name == CDISASM_ARM_NAME_FCVTNS
            || name == CDISASM_ARM_NAME_FCVTAS
            || name == CDISASM_ARM_NAME_FCVTPS
            || name == CDISASM_ARM_NAME_FCVTMS
            || name == CDISASM_ARM_NAME_FCVTZS
            || name == CDISASM_ARM_NAME_SCVTF
            || name == CDISASM_ARM_NAME_FCVTNU
            || name == CDISASM_ARM_NAME_FCVTAU
            || name == CDISASM_ARM_NAME_FCVTPU
            || name == CDISASM_ARM_NAME_FCVTMU
            || name == CDISASM_ARM_NAME_FCVTZU
            || name == CDISASM_ARM_NAME_UCVTF);
}

static int arm_valid_vector_layout(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    uint8_t element_size = CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand);
    uint8_t element_count = CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand);

    if ((instruction->isa_id == CDISASM_ARM_ISA_A64
            && (instruction->form_id == UINT16_C(5780)
                || instruction->form_id == UINT16_C(5783)
                || instruction->form_id == UINT16_C(5788)
                || instruction->form_id == UINT16_C(5802)
                || instruction->form_id == UINT16_C(5806)
                || instruction->form_id == UINT16_C(5819)
                || instruction->form_id == UINT16_C(5820)
                || instruction->form_id == UINT16_C(5821)
                || instruction->form_id == UINT16_C(5858)
                || instruction->form_id == UINT16_C(5859)
                || instruction->form_id == UINT16_C(5860)
                || instruction->form_id == UINT16_C(5861)
                || instruction->form_id == UINT16_C(5862)
                || instruction->form_id == UINT16_C(5869)
                || instruction->form_id == UINT16_C(5870)
                || instruction->form_id == UINT16_C(5871)
                || instruction->form_id == UINT16_C(5872)
                || instruction->form_id == UINT16_C(5873)
                || instruction->form_id == UINT16_C(5874)
                || instruction->form_id == UINT16_C(5875)
                || instruction->form_id == UINT16_C(5876)
                || instruction->form_id == UINT16_C(5771)
                || instruction->form_id == UINT16_C(5772)))
        || arm_is_a64_fprcvt_scalar(instruction)) {
        cdisasm_arm_reg_id base = element_size == 1u
            ? CDISASM_ARM_REG_B0 : element_size == 2u
                ? CDISASM_ARM_REG_H0 : element_size == 4u
                    ? CDISASM_ARM_REG_S0 : CDISASM_ARM_REG_D0;

        return (element_size == 1u || element_size == 2u || element_size == 4u
                || element_size == 8u)
            && operand->reg >= base
            && operand->reg <= (cdisasm_arm_reg_id)(base + 31u)
            && operand->size == element_size && element_count == 1u;
    }

    if (arm_is_a64_advsimd_sha_scalar_operand(instruction, operand)) {
        return operand->reg >= CDISASM_ARM_REG_S0
            && operand->reg <= CDISASM_ARM_REG_S31
            && operand->size == 4u
            && element_size == 0u && element_count == 0u;
    }

    if (instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->form_id == UINT16_C(5773)
            || instruction->form_id == UINT16_C(5774)
            || instruction->form_id == UINT16_C(5775)
            || instruction->form_id == UINT16_C(5776)
            || instruction->form_id == UINT16_C(5778)
            || instruction->form_id == UINT16_C(5791)
            || instruction->form_id == UINT16_C(5792)
            || instruction->form_id == UINT16_C(5793)
            || instruction->form_id == UINT16_C(5795))) {
        cdisasm_arm_reg_id scalar_base = element_size == 1u
            ? CDISASM_ARM_REG_B0 : element_size == 2u
                ? CDISASM_ARM_REG_H0 : element_size == 4u
                    ? CDISASM_ARM_REG_S0 : CDISASM_ARM_REG_D0;

        return (operand == &instruction->operand[0]
                || operand == &instruction->operand[1])
            && operand->reg >= scalar_base
            && operand->reg <= (cdisasm_arm_reg_id)(scalar_base + 31u)
            && operand->size == element_size && element_count == 1u;
    }

    if (instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id >= UINT16_C(5877)
        && instruction->form_id <= UINT16_C(5891)
        && (operand == &instruction->operand[0]
            || operand == &instruction->operand[1])) {
        cdisasm_arm_reg_id scalar_base = element_size == 2u
            ? CDISASM_ARM_REG_H0 : element_size == 4u
                ? CDISASM_ARM_REG_S0 : CDISASM_ARM_REG_D0;
        return (element_size == 2u || element_size == 4u
                || element_size == 8u)
            && operand->reg >= scalar_base
            && operand->reg <= (cdisasm_arm_reg_id)(scalar_base + 31u)
            && operand->size == element_size && element_count == 1u;
    }

    if (instruction->isa_id == CDISASM_ARM_ISA_A64
        && ((instruction->form_id == UINT16_C(6077)
                && instruction->name_id == CDISASM_ARM_NAME_ADDV)
            || (instruction->form_id == UINT16_C(6075)
                && instruction->name_id == CDISASM_ARM_NAME_SMAXV)
            || (instruction->form_id == UINT16_C(6076)
                && instruction->name_id == CDISASM_ARM_NAME_SMINV)
            || (instruction->form_id == UINT16_C(6083)
                && instruction->name_id == CDISASM_ARM_NAME_UMAXV)
            || (instruction->form_id == UINT16_C(6084)
                && instruction->name_id == CDISASM_ARM_NAME_UMINV))) {
        cdisasm_arm_reg_id scalar_base = element_size == 1u
            ? CDISASM_ARM_REG_B0 : element_size == 2u
                ? CDISASM_ARM_REG_H0 : CDISASM_ARM_REG_S0;

        if (element_size != 1u && element_size != 2u
            && element_size != 4u) {
            return 0;
        }
        if (operand == &instruction->operand[0]) {
            return operand->reg >= scalar_base
                && operand->reg <= (cdisasm_arm_reg_id)(scalar_base + 31u)
                && operand->size == element_size
                && element_count == 1u;
        }
        return operand == &instruction->operand[1]
            && operand->reg >= CDISASM_ARM_REG_V0
            && operand->reg <= CDISASM_ARM_REG_V31
            && (operand->size == 8u || operand->size == 16u)
            && element_count == operand->size / element_size;
    }
    if (instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id >= UINT16_C(6078)
        && instruction->form_id <= UINT16_C(6088)
        && instruction->form_id != UINT16_C(6082)
        && instruction->form_id != UINT16_C(6083)
        && instruction->form_id != UINT16_C(6084)) {
        uint8_t expected_element_size = instruction->form_id <= UINT16_C(6081)
            ? 2u : 4u;
        cdisasm_arm_reg_id scalar_base = expected_element_size == 2u
            ? CDISASM_ARM_REG_H0 : CDISASM_ARM_REG_S0;

        if (element_size != expected_element_size) {
            return 0;
        }
        if (operand == &instruction->operand[0]) {
            return operand->reg >= scalar_base
                && operand->reg <= (cdisasm_arm_reg_id)(scalar_base + 31u)
                && operand->size == element_size && element_count == 1u;
        }
        return operand == &instruction->operand[1]
            && operand->reg >= CDISASM_ARM_REG_V0
            && operand->reg <= CDISASM_ARM_REG_V31
            && (operand->size == 8u || operand->size == 16u)
            && element_count == operand->size / element_size;
    }
    if (instruction->isa_id == CDISASM_ARM_ISA_A64
        && ((instruction->form_id == UINT16_C(6074)
                && instruction->name_id == CDISASM_ARM_NAME_SADDLV)
            || (instruction->form_id == UINT16_C(6082)
                && instruction->name_id == CDISASM_ARM_NAME_UADDLV))) {
        if (operand == &instruction->operand[0]) {
            cdisasm_arm_reg_id scalar_base = element_size == 2u
                ? CDISASM_ARM_REG_H0 : element_size == 4u
                    ? CDISASM_ARM_REG_S0 : CDISASM_ARM_REG_D0;

            return (element_size == 2u || element_size == 4u
                    || element_size == 8u)
                && operand->reg >= scalar_base
                && operand->reg <= (cdisasm_arm_reg_id)(scalar_base + 31u)
                && operand->size == element_size
                && element_count == 1u;
        }
        return operand == &instruction->operand[1]
            && operand->reg >= CDISASM_ARM_REG_V0
            && operand->reg <= CDISASM_ARM_REG_V31
            && (element_size == 1u || element_size == 2u
                || element_size == 4u)
            && (operand->size == 8u || operand->size == 16u)
            && element_count == operand->size / element_size;
    }

    if (instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->form_id == UINT16_C(6146)
            || instruction->form_id == UINT16_C(6155)
            || instruction->form_id == UINT16_C(6187)
            || instruction->form_id == UINT16_C(6197)
            || instruction->form_id == UINT16_C(6264)
            || instruction->form_id == UINT16_C(6265)
            || instruction->form_id == UINT16_C(6279)
            || instruction->form_id == UINT16_C(6280))) {
        int by_element = instruction->form_id >= UINT16_C(6264);
        if (operand == &instruction->operand[0]) {
            return operand->reg >= CDISASM_ARM_REG_V0
                && operand->reg <= CDISASM_ARM_REG_V31
                && (operand->size == 8u || operand->size == 16u)
                && element_size == 4u
                && element_count == operand->size / element_size;
        }
        if (operand == &instruction->operand[1]
            || (!by_element && operand == &instruction->operand[2])) {
            return operand->reg >= CDISASM_ARM_REG_V0
                && operand->reg <= CDISASM_ARM_REG_V31
                && (operand->size == 4u || operand->size == 8u)
                && element_size == 2u
                && element_count == operand->size / element_size;
        }
        return by_element && operand == &instruction->operand[2]
            && operand->reg >= CDISASM_ARM_REG_V0
            && operand->reg <= CDISASM_ARM_REG_V15
            && operand->size == 16u && element_size == 2u
            && element_count == 8u;
    }

    if (!arm_is_vector_register(operand->reg)
        || (element_size != 1u && element_size != 2u
            && element_size != 4u && element_size != 8u
            && !(element_size == 16u
                && ((instruction->name_id == CDISASM_ARM_NAME_PMULL
                        && instruction->form_id == UINT16_C(6103))
                    || arm_is_a64_advsimd_sha_q_operand(
                        instruction, operand))))
        || element_count == 0u
        || (uint16_t)element_size * element_count != operand->size) {
        return 0;
    }
    if (instruction->isa_id == CDISASM_ARM_ISA_A64) {
        if (instruction->form_id == UINT16_C(5808)
            && instruction->name_id == CDISASM_ARM_NAME_ADDP) {
            if (operand == &instruction->operand[0]) {
                return operand->reg >= CDISASM_ARM_REG_D0
                    && operand->reg <= CDISASM_ARM_REG_D31
                    && operand->size == 8u
                    && element_size == 8u && element_count == 1u;
            }
            return operand == &instruction->operand[1]
                && operand->reg >= CDISASM_ARM_REG_V0
                && operand->reg <= CDISASM_ARM_REG_V31
                && operand->size == 16u
                && element_size == 8u && element_count == 2u;
        }
        if (arm_is_scalar_advsimd_d_layout(instruction)) {
            return operand->reg >= CDISASM_ARM_REG_D0
                && operand->reg <= CDISASM_ARM_REG_D31
                && operand->size == 8u
                && element_size == 8u && element_count == 1u;
        }
        return operand->reg >= CDISASM_ARM_REG_V0
            && operand->reg <= CDISASM_ARM_REG_V31
            && (operand->size == 8u || operand->size == 16u);
    }
    if (operand->reg >= CDISASM_ARM_REG_D0
        && operand->reg <= CDISASM_ARM_REG_D31) {
        return operand->size == 8u;
    }
    return operand->reg >= CDISASM_ARM_REG_Q0
        && operand->reg <= CDISASM_ARM_REG_Q15
        && operand->size == 16u;
}

static int arm_valid_register_operand(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    int is_simd = (instruction->instruction_flags
        & CDISASM_ARM_INSTRUCTION_FLAG_SIMD) != 0;
    int is_advsimd_element_lane = is_simd
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && ((instruction->form_id >= UINT16_C(4615)
                && instruction->form_id <= UINT16_C(4724)
                && instruction->name_id >= CDISASM_ARM_NAME_LD1
                && instruction->name_id <= CDISASM_ARM_NAME_ST4)
            || instruction->form_id == UINT16_C(5900)
            || instruction->form_id == UINT16_C(5901)
            || instruction->form_id == UINT16_C(5902)
            || instruction->form_id == UINT16_C(5903)
            || instruction->form_id == UINT16_C(6243)
            || instruction->form_id == UINT16_C(6244)
            || instruction->form_id == UINT16_C(6245)
            || instruction->form_id == UINT16_C(6246)
            || instruction->form_id == UINT16_C(6247)
            || instruction->form_id == UINT16_C(6248)
            || instruction->form_id == UINT16_C(6249)
            || instruction->form_id == UINT16_C(6250)
            || instruction->form_id == UINT16_C(6251)
            || instruction->form_id == UINT16_C(6252)
            || instruction->form_id == UINT16_C(6253)
            || instruction->form_id == UINT16_C(6257)
            || instruction->form_id == UINT16_C(6258)
            || instruction->form_id == UINT16_C(6259)
            || instruction->form_id == UINT16_C(6260)
            || instruction->form_id == UINT16_C(6266)
            || instruction->form_id == UINT16_C(6267)
            || instruction->form_id == UINT16_C(6274)
            || (instruction->form_id >= UINT16_C(6254)
                && instruction->form_id <= UINT16_C(6256))
            || (instruction->form_id >= UINT16_C(6261)
                && instruction->form_id <= UINT16_C(6263))
            || instruction->form_id == UINT16_C(6276)
            || instruction->form_id == UINT16_C(6278)
            || instruction->form_id == UINT16_C(6264)
            || instruction->form_id == UINT16_C(6265)
            || instruction->form_id == UINT16_C(6268)
            || instruction->form_id == UINT16_C(6269)
            || instruction->form_id == UINT16_C(6270)
            || instruction->form_id == UINT16_C(6271)
            || instruction->form_id == UINT16_C(6272)
            || instruction->form_id == UINT16_C(6273)
            || instruction->form_id == UINT16_C(6275)
            || instruction->form_id == UINT16_C(6277)
            || instruction->form_id == UINT16_C(6279)
            || instruction->form_id == UINT16_C(6280)
            || (instruction->form_id >= UINT16_C(6281)
                && instruction->form_id <= UINT16_C(6286))
            || (instruction->form_id >= UINT16_C(6287)
                && instruction->form_id <= UINT16_C(6290)))
        && operand == &instruction->operand[2]
        && operand->flags == CDISASM_ARM_OPERAND_FLAG_HAS_LANE;

    if (!is_advsimd_element_lane && is_simd
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && ((instruction->form_id == UINT16_C(6395)
                && operand == &instruction->operand[1])
            || (instruction->form_id == UINT16_C(6396)
                && operand == &instruction->operand[0]))
        && operand->flags == CDISASM_ARM_OPERAND_FLAG_HAS_LANE) {
        is_advsimd_element_lane = 1;
    }

    if (!arm_valid_register_id(operand->reg)
        || operand->base_reg != CDISASM_ARM_REG_NONE
        || operand->index_reg != CDISASM_ARM_REG_NONE
        || operand->register_list != 0u
        || operand->address != 0u
        || (!is_advsimd_element_lane && operand->imm != 0u)
        || (!is_advsimd_element_lane
            && operand->flags != CDISASM_OPERAND_FLAG_NONE
            && !(operand->flags == CDISASM_ARM_OPERAND_FLAG_WRITEBACK
                && instruction->name_id >= CDISASM_ARM_NAME_CPYFP
                && instruction->name_id <= CDISASM_ARM_NAME_SETE))
        || !arm_valid_shift(operand->shift_type, operand->shift_amount)
        || operand->shift_type == CDISASM_ARM_SHIFT_MSL) {
        return 0;
    }
    if (instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id == UINT16_C(4922)
        && instruction->name_id == CDISASM_ARM_NAME_LDR
        && operand == &instruction->operand[0]
        && ((operand->reg >= CDISASM_ARM_REG_Q0
                && operand->reg <= CDISASM_ARM_REG_Q15)
            || (operand->reg >= CDISASM_ARM_REG_Q16
                && operand->reg <= CDISASM_ARM_REG_Q31))
        && operand->size == 16u
        && operand->access == CDISASM_OPERAND_ACCESS_WRITE) {
        return 1;
    }
    if (instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->form_id == UINT16_C(5100)
            || instruction->form_id == UINT16_C(5101)
            || instruction->form_id == UINT16_C(5116)
            || instruction->form_id == UINT16_C(5117)
            || instruction->form_id == UINT16_C(5132)
            || instruction->form_id == UINT16_C(5133))
        && ((operand->reg >= CDISASM_ARM_REG_Q0
                && operand->reg <= CDISASM_ARM_REG_Q15)
            || (operand->reg >= CDISASM_ARM_REG_Q16
                && operand->reg <= CDISASM_ARM_REG_Q31))
        && operand->size == 16u
        && operand->access == (instruction->name_id == CDISASM_ARM_NAME_LDP
            ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ)) {
        return 1;
    }
    if (instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->form_id == UINT16_C(5084)
            || instruction->form_id == UINT16_C(5085)
            || instruction->form_id == UINT16_C(5088)
            || instruction->form_id == UINT16_C(5089)
            || (instruction->form_id >= UINT16_C(5104)
                && instruction->form_id <= UINT16_C(5105))
            || (instruction->form_id >= UINT16_C(5120)
                && instruction->form_id <= UINT16_C(5121))
            || (instruction->form_id >= UINT16_C(5136)
                && instruction->form_id <= UINT16_C(5137)))
        && ((operand->reg >= CDISASM_ARM_REG_Q0
                && operand->reg <= CDISASM_ARM_REG_Q15)
            || (operand->reg >= CDISASM_ARM_REG_Q16
                && operand->reg <= CDISASM_ARM_REG_Q31))
        && operand->size == 16u
        && operand->access == (instruction->name_id == CDISASM_ARM_NAME_LDNP
                || instruction->name_id == CDISASM_ARM_NAME_LDTNP
                || instruction->name_id == CDISASM_ARM_NAME_LDTP
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ)) {
        return 1;
    }
    if (instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->form_id == UINT16_C(5144)
            || instruction->form_id == UINT16_C(5145)
            || instruction->form_id == UINT16_C(5168)
            || instruction->form_id == UINT16_C(5169)
            || instruction->form_id == UINT16_C(5204)
            || instruction->form_id == UINT16_C(5205)
            || instruction->form_id == UINT16_C(5529)
            || instruction->form_id == UINT16_C(5530)
            || instruction->form_id == UINT16_C(5558)
            || instruction->form_id == UINT16_C(5559))
        && ((operand->reg >= CDISASM_ARM_REG_Q0
                && operand->reg <= CDISASM_ARM_REG_Q15)
            || (operand->reg >= CDISASM_ARM_REG_Q16
                && operand->reg <= CDISASM_ARM_REG_Q31))
        && operand->size == 16u
        && operand->access == (instruction->name_id == CDISASM_ARM_NAME_LDUR
                || instruction->name_id == CDISASM_ARM_NAME_LDR
            ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ)) {
        return 1;
    }
    if (instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->form_id == UINT16_C(6395)
            || instruction->form_id == UINT16_C(6396))) {
        return operand->shift_type == CDISASM_ARM_SHIFT_NONE
            && (is_advsimd_element_lane
                ? operand->reg >= CDISASM_ARM_REG_V0
                    && operand->reg <= CDISASM_ARM_REG_V31
                    && operand->size == 16u && operand->extend_type == 8u
                    && operand->scale == 2u && operand->imm == 1u
                : ((operand->reg >= CDISASM_ARM_REG_X0
                        && operand->reg <= CDISASM_ARM_REG_X30)
                    || operand->reg == CDISASM_ARM_REG_XZR)
                    && operand->size == 8u
                && operand->extend_type == CDISASM_ARM_EXTEND_NONE
                && operand->scale == 0u);
    }
    if (instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id >= UINT16_C(4907)
        && instruction->form_id <= UINT16_C(4916)
        && operand == &instruction->operand[0]) {
        if (operand->size == 16u) {
            return operand->reg >= CDISASM_ARM_REG_V0
                && operand->reg <= CDISASM_ARM_REG_V31
                && operand->extend_type == 1u
                && operand->scale == 16u;
        }
        {
            cdisasm_arm_reg_id base = operand->size == 1u
                ? CDISASM_ARM_REG_B0 : operand->size == 2u
                    ? CDISASM_ARM_REG_H0 : operand->size == 4u
                        ? CDISASM_ARM_REG_S0 : CDISASM_ARM_REG_D0;
            return (operand->size == 1u || operand->size == 2u
                    || operand->size == 4u || operand->size == 8u)
                && operand->reg >= base
                && operand->reg <= (cdisasm_arm_reg_id)(base + 31u)
                && operand->extend_type == operand->size
                && operand->scale == 1u;
        }
    }
    if (is_simd) {
        return operand->shift_type == CDISASM_ARM_SHIFT_NONE
            && arm_valid_vector_layout(instruction, operand)
            && (!is_advsimd_element_lane
                || operand->imm
                    < CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand));
    }
    if (arm_is_sve_quadword_reduction_name(instruction->name_id)
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR) != 0u
        && operand == &instruction->operand[0]
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->reg >= CDISASM_ARM_REG_V0
        && operand->reg <= CDISASM_ARM_REG_V31
        && arm_valid_vector_layout(instruction, operand)) {
        return 1;
    }
    if (instruction->name_id == CDISASM_ARM_NAME_MOV
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR) != 0u
        && operand->extend_type == CDISASM_ARM_EXTEND_NONE
        && operand->scale == 0u
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && (arm_valid_scalar_register_size(operand->reg, operand->size)
            || (operand->reg >= CDISASM_ARM_REG_V0
                && operand->reg <= CDISASM_ARM_REG_V31
                && operand->size == 16u))) {
        return 1;
    }
    if ((arm_is_vector_register(operand->reg)
            && !(((instruction->instruction_flags
                        & CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT) != 0u)
                    && arm_is_scalar_fp_register(operand->reg))
            && !(arm_is_sve_quadword_reduction_name(instruction->name_id)
                && (instruction->instruction_flags
                    & CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR) != 0u
                && operand == &instruction->operand[0]
                && operand->reg >= CDISASM_ARM_REG_V0
                && operand->reg <= CDISASM_ARM_REG_V31
                && arm_valid_vector_layout(instruction, operand))
            && !(arm_is_sve_integer_reduction_name(instruction->name_id)
                && (instruction->instruction_flags
                    & CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR) != 0u
                && operand->reg >= CDISASM_ARM_REG_D0
                && operand->reg <= CDISASM_ARM_REG_D31)
            && !(instruction->name_id == CDISASM_ARM_NAME_INSR
                && (instruction->instruction_flags
                    & CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR) != 0u
                && operand == &instruction->operand[1]
                && operand->reg >= CDISASM_ARM_REG_D0
                && operand->reg <= CDISASM_ARM_REG_D31))
        || operand->extend_type > CDISASM_ARM_EXTEND_SXTX
        || (operand->shift_type != CDISASM_ARM_SHIFT_NONE
            && operand->extend_type != CDISASM_ARM_EXTEND_NONE)
        || (operand->extend_type == CDISASM_ARM_EXTEND_NONE
            && operand->scale != 0u)
        || (operand->extend_type != CDISASM_ARM_EXTEND_NONE
            && operand->scale > 4u)
        ) {
        return 0;
    }
    return arm_valid_scalar_register_size(operand->reg, operand->size);
}

static int arm_valid_immediate_operand(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    const uint8_t allowed_flags = CDISASM_OPERAND_FLAG_SIGNED
        | CDISASM_OPERAND_FLAG_PC_RELATIVE
        | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
    int is_pc_relative =
        (operand->flags & CDISASM_OPERAND_FLAG_PC_RELATIVE) != 0;
    int is_advsimd_msl = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->form_id == UINT16_C(6203)
            || instruction->form_id == UINT16_C(6211))
        && (instruction->name_id == CDISASM_ARM_NAME_MOVI
            || instruction->name_id == CDISASM_ARM_NAME_MVNI)
        && operand == &instruction->operand[1];

    if (operand->reg != CDISASM_ARM_REG_NONE
        || operand->base_reg != CDISASM_ARM_REG_NONE
        || operand->index_reg != CDISASM_ARM_REG_NONE
        || operand->register_list != 0u
        || operand->size == 0u || operand->size > 8u
        || (operand->flags & (uint8_t)~allowed_flags) != 0
        || operand->extend_type != CDISASM_ARM_EXTEND_NONE
        || operand->scale != 0u
        || !arm_valid_shift(operand->shift_type, operand->shift_amount)
        || operand->shift_type == CDISASM_ARM_SHIFT_RRX
        || (operand->shift_type == CDISASM_ARM_SHIFT_MSL
            && !is_advsimd_msl)) {
        return 0;
    }
    if (is_pc_relative
        != ((operand->flags & CDISASM_OPERAND_FLAG_HAS_ADDRESS) != 0)) {
        return 0;
    }
    if (!is_pc_relative && operand->address != 0u) {
        return 0;
    }
    return !is_pc_relative
        || operand->shift_type == CDISASM_ARM_SHIFT_NONE;
}

static int arm_valid_memory_register(
    cdisasm_arm_isa_id isa_id,
    cdisasm_arm_reg_id reg,
    int is_index)
{
    if (isa_id != CDISASM_ARM_ISA_A64) {
        return arm_is_a32_register(reg);
    }
    if (is_index && arm_is_w_register(reg)) {
        return reg != CDISASM_ARM_REG_WSP;
    }
    return reg >= CDISASM_ARM_REG_X0 && reg <= CDISASM_ARM_REG_SP;
}

static int arm_valid_memory_operand(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    const uint8_t allowed_flags = CDISASM_OPERAND_FLAG_SIGNED
        | CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
        | CDISASM_OPERAND_FLAG_PC_RELATIVE
        | CDISASM_OPERAND_FLAG_HAS_ADDRESS
        | CDISASM_ARM_OPERAND_FLAG_WRITEBACK
        | CDISASM_ARM_OPERAND_FLAG_VL_SCALED;
    int has_index = operand->index_reg != CDISASM_ARM_REG_NONE;
    int has_displacement =
        (operand->flags & CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT) != 0;
    int is_pc_relative =
        (operand->flags & CDISASM_OPERAND_FLAG_PC_RELATIVE) != 0;
    int is_vl_scaled =
        (operand->flags & CDISASM_ARM_OPERAND_FLAG_VL_SCALED) != 0;
    int is_sve_multi_contiguous = instruction->isa_id == CDISASM_ARM_ISA_A64
        && ((instruction->form_id >= UINT16_C(3366)
                && instruction->form_id <= UINT16_C(3377))
            || (instruction->form_id >= UINT16_C(3311)
                && instruction->form_id <= UINT16_C(3313))
            || (instruction->form_id >= UINT16_C(3378)
                && instruction->form_id <= UINT16_C(3380))
            || (instruction->form_id >= UINT16_C(3463)
                && instruction->form_id <= UINT16_C(3468))
            || (instruction->form_id >= UINT16_C(3537)
                && instruction->form_id <= UINT16_C(3548))
            || (instruction->form_id >= UINT16_C(3549)
                && instruction->form_id <= UINT16_C(3676)));
    int is_sve_contiguous = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (is_sve_multi_contiguous
            || (instruction->form_id >= UINT16_C(3314)
                && instruction->form_id <= UINT16_C(3345))
            || (instruction->form_id >= UINT16_C(3362)
                && instruction->form_id <= UINT16_C(3365))
            || instruction->form_id == UINT16_C(3527)
            || instruction->form_id == UINT16_C(3528)
            || instruction->form_id == UINT16_C(3530)
            || instruction->form_id == UINT16_C(3532)
            || instruction->form_id == UINT16_C(3275)
            || instruction->form_id == UINT16_C(3276)
            || instruction->form_id == UINT16_C(3529)
            || instruction->form_id == UINT16_C(3531)
            || (instruction->form_id >= UINT16_C(3533)
                && instruction->form_id <= UINT16_C(3536))
            || (instruction->form_id >= UINT16_C(3489)
                && instruction->form_id <= UINT16_C(3500))
            || is_sve_multi_contiguous);
    int is_sve_prefetch_immediate = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id >= UINT16_C(3216)
        && instruction->form_id <= UINT16_C(3219);
    int is_sve_gather = instruction->isa_id == CDISASM_ARM_ISA_A64
        && ((instruction->form_id >= UINT16_C(2338)
                && instruction->form_id <= UINT16_C(2340))
            || (instruction->form_id >= UINT16_C(3194)
                && instruction->form_id <= UINT16_C(3207))
            || (instruction->form_id >= UINT16_C(3208)
                && instruction->form_id <= UINT16_C(3213))
            || (instruction->form_id >= UINT16_C(3222)
                && instruction->form_id <= UINT16_C(3224))
            || (instruction->form_id >= UINT16_C(3229)
                && instruction->form_id <= UINT16_C(3232))
            || (instruction->form_id >= UINT16_C(3233)
                && instruction->form_id <= UINT16_C(3242))
            || (instruction->form_id >= UINT16_C(3381)
                && instruction->form_id <= UINT16_C(3394))
            || (instruction->form_id >= UINT16_C(3395)
                && instruction->form_id <= UINT16_C(3398))
            || (instruction->form_id >= UINT16_C(3399)
                && instruction->form_id <= UINT16_C(3408))
            || (instruction->form_id >= UINT16_C(3416)
                && instruction->form_id <= UINT16_C(3419))
            || (instruction->form_id >= UINT16_C(3412)
                && instruction->form_id <= UINT16_C(3415))
            || instruction->form_id == UINT16_C(3420)
            || instruction->form_id == UINT16_C(3484)
            || (instruction->form_id >= UINT16_C(3477)
                && instruction->form_id <= UINT16_C(3483))
            || (instruction->form_id >= UINT16_C(3421)
                && instruction->form_id <= UINT16_C(3434))
            || (instruction->form_id >= UINT16_C(3435)
                && instruction->form_id <= UINT16_C(3448))
            || (instruction->form_id >= UINT16_C(3449)
                && instruction->form_id <= UINT16_C(3452))
            || (instruction->form_id >= UINT16_C(3453)
                && instruction->form_id <= UINT16_C(3462))
            || (instruction->form_id >= UINT16_C(3501)
                && instruction->form_id <= UINT16_C(3526)));

    if (operand->reg != CDISASM_ARM_REG_NONE
        || operand->register_list != 0u
        || (!arm_valid_data_size(operand->size)
            && !(instruction->isa_id == CDISASM_ARM_ISA_A64
                && instruction->form_id >= UINT16_C(3259)
                && instruction->form_id <= UINT16_C(3274)
                && (instruction->form_id & UINT16_C(1)) == 0u
                && operand->size == 32u)
            && !(instruction->isa_id == CDISASM_ARM_ISA_A64
                && (instruction->form_id == UINT16_C(5084)
                    || instruction->form_id == UINT16_C(5085)
                    || instruction->form_id == UINT16_C(5088)
                    || instruction->form_id == UINT16_C(5089)
                    || (instruction->form_id >= UINT16_C(5104)
                        && instruction->form_id <= UINT16_C(5105))
                    || (instruction->form_id >= UINT16_C(5120)
                        && instruction->form_id <= UINT16_C(5121))
                    || (instruction->form_id >= UINT16_C(5136)
                        && instruction->form_id <= UINT16_C(5137)))
                && operand->size == 32u)
            && !(instruction->isa_id == CDISASM_ARM_ISA_A64
                && instruction->form_id >= UINT16_C(4573)
                && instruction->form_id <= UINT16_C(4614)
                && (operand->size == 24u || operand->size == 32u
                    || operand->size == 48u))
            && !(instruction->isa_id == CDISASM_ARM_ISA_A64
                && instruction->form_id >= UINT16_C(4615)
                && instruction->form_id <= UINT16_C(4724)
                && instruction->name_id >= CDISASM_ARM_NAME_LD1
                && instruction->name_id <= CDISASM_ARM_NAME_ST4
                && (operand->size == 3u || operand->size == 6u
                    || operand->size == 12u || operand->size == 24u))
            && !(instruction->isa_id == CDISASM_ARM_ISA_A64
                && instruction->form_id >= UINT16_C(4795)
                && instruction->form_id <= UINT16_C(4801)
                && (instruction->name_id == CDISASM_ARM_NAME_ST2G
                    || instruction->name_id == CDISASM_ARM_NAME_STZ2G)
                && operand->size == 32u)
            && !(operand->size == 0u
                && ((instruction->instruction_flags
                        & CDISASM_ARM_INSTRUCTION_FLAG_SME) != 0u
                    || instruction->form_id == UINT16_C(3214)
                    || instruction->form_id == UINT16_C(3215)
                    || instruction->form_id == UINT16_C(3469)
                    || instruction->form_id == UINT16_C(3476)
                    || instruction->name_id == CDISASM_ARM_NAME_PLD
                    || instruction->name_id == CDISASM_ARM_NAME_PLDW
                    || instruction->name_id == CDISASM_ARM_NAME_PLI)))
        || (operand->flags & (uint8_t)~allowed_flags) != 0
        || (!(is_sve_gather
                && operand->base_reg >= CDISASM_ARM_REG_Z0
                && operand->base_reg <= CDISASM_ARM_REG_Z31)
            && !arm_valid_memory_register(
                instruction->isa_id, operand->base_reg, 0))
        || (has_index
            && !(is_sve_gather
                && operand->index_reg >= CDISASM_ARM_REG_Z0
                && operand->index_reg <= CDISASM_ARM_REG_Z31)
            && !arm_valid_memory_register(
                instruction->isa_id, operand->index_reg, 1))
        || (has_index && has_displacement)
        || (!has_index && (operand->shift_type != CDISASM_ARM_SHIFT_NONE
            || operand->extend_type != CDISASM_ARM_EXTEND_NONE
            || operand->scale != 0u))
        || !arm_valid_shift(operand->shift_type, operand->shift_amount)
        || operand->shift_type == CDISASM_ARM_SHIFT_MSL
        || operand->extend_type > CDISASM_ARM_EXTEND_SXTX
        || (operand->shift_type != CDISASM_ARM_SHIFT_NONE
            && operand->extend_type != CDISASM_ARM_EXTEND_NONE)
        || (operand->extend_type == CDISASM_ARM_EXTEND_NONE
            && operand->scale != 0u)
        || (operand->extend_type != CDISASM_ARM_EXTEND_NONE
            && operand->scale > 4u)) {
        return 0;
    }
    if (!has_displacement && operand->imm != 0u) {
        return 0;
    }
    if ((operand->flags & CDISASM_OPERAND_FLAG_SIGNED) != 0
        && !has_displacement
        && !(has_index && instruction->isa_id != CDISASM_ARM_ISA_A64)) {
        return 0;
    }
    if (is_vl_scaled
        && (instruction->isa_id != CDISASM_ARM_ISA_A64
            || (instruction->form_id != UINT16_C(3214)
                && instruction->form_id != UINT16_C(3215)
                && instruction->form_id != UINT16_C(3469)
                && instruction->form_id != UINT16_C(3476)
                && instruction->form_id != UINT16_C(4381)
                && instruction->form_id != UINT16_C(4382)
                && !is_sve_prefetch_immediate
                && !is_sve_contiguous)
            || (!is_sve_contiguous && !is_sve_prefetch_immediate
                && instruction->name_id != CDISASM_ARM_NAME_LDR
                && instruction->name_id != CDISASM_ARM_NAME_STR)
            || operand->flags
                != (uint8_t)(CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
                    | CDISASM_ARM_OPERAND_FLAG_VL_SCALED
                    | ((int64_t)operand->imm < 0
                        ? CDISASM_OPERAND_FLAG_SIGNED : 0u))
            || (!is_sve_contiguous && !is_sve_prefetch_immediate
                && operand->size != 0u)
            || operand->imm == 0u
            || (is_sve_contiguous
                ? (is_sve_multi_contiguous
                    ? (int64_t)operand->imm < INT64_C(-32)
                        || (int64_t)operand->imm > INT64_C(28)
                    : (int64_t)operand->imm < INT64_C(-8)
                        || (int64_t)operand->imm > INT64_C(7))
                : is_sve_prefetch_immediate
                ? (int64_t)operand->imm < INT64_C(-32)
                    || (int64_t)operand->imm > INT64_C(31)
                : (instruction->form_id == UINT16_C(4381)
                    || instruction->form_id == UINT16_C(4382))
                ? operand->imm > UINT64_C(15)
                : (int64_t)operand->imm < INT64_C(-256)
                    || (int64_t)operand->imm > INT64_C(255))
            || has_index
            || (instruction->instruction_flags
                & CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR) == 0u
            || ((instruction->form_id == UINT16_C(4381)
                    || instruction->form_id == UINT16_C(4382))
                && (instruction->instruction_flags
                    & (CDISASM_ARM_INSTRUCTION_FLAG_SME
                        | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX))
                    != (CDISASM_ARM_INSTRUCTION_FLAG_SME
                        | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX)))) {
        return 0;
    }
    if (is_pc_relative
        != ((operand->flags & CDISASM_OPERAND_FLAG_HAS_ADDRESS) != 0)) {
        return 0;
    }
    if (!is_pc_relative && operand->address != 0u) {
        return 0;
    }
    return 1;
}

static int arm_valid_register_list_operand(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    if (instruction->isa_id == CDISASM_ARM_ISA_A64
        || operand->address != 0u
        || operand->imm != 0u
        || operand->reg != CDISASM_ARM_REG_NONE
        || operand->base_reg != CDISASM_ARM_REG_NONE
        || operand->index_reg != CDISASM_ARM_REG_NONE
        || operand->size != 4u
        || operand->flags != CDISASM_OPERAND_FLAG_NONE
        || operand->shift_type != CDISASM_ARM_SHIFT_NONE
        || operand->shift_amount != 0u
        || operand->extend_type != CDISASM_ARM_EXTEND_NONE
        || operand->scale != 0u) {
        return 0;
    }
    return operand->register_list != 0u
        || (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL) != 0;
}

static int arm_valid_register_pair_operand(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    int w_pair = operand->reg >= CDISASM_ARM_REG_W0
        && operand->reg <= CDISASM_ARM_REG_W30;
    int x_pair = operand->reg >= CDISASM_ARM_REG_X0
        && operand->reg <= CDISASM_ARM_REG_X30;
    cdisasm_arm_reg_id expected_second = CDISASM_ARM_REG_NONE;

    if (w_pair) {
        expected_second = operand->reg == CDISASM_ARM_REG_W30
            ? CDISASM_ARM_REG_WZR
            : (cdisasm_arm_reg_id)(operand->reg + 1u);
    } else if (x_pair) {
        expected_second = operand->reg == CDISASM_ARM_REG_X30
            ? CDISASM_ARM_REG_XZR
            : (cdisasm_arm_reg_id)(operand->reg + 1u);
    }

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || (!w_pair && !x_pair)
        || operand->index_reg != expected_second
        || ((operand->reg - (w_pair ? CDISASM_ARM_REG_W0
                                   : CDISASM_ARM_REG_X0)) & 1u) != 0u
        || operand->base_reg != CDISASM_ARM_REG_NONE
        || operand->register_list != 0u
        || operand->address != 0u
        || operand->imm != 0u
        || operand->flags != CDISASM_OPERAND_FLAG_NONE
        || operand->shift_type != CDISASM_ARM_SHIFT_NONE
        || operand->shift_amount != 0u
        || operand->extend_type != CDISASM_ARM_EXTEND_NONE
        || operand->scale != 0u) {
        return 0;
    }
    return operand->size == (w_pair ? 4u : 8u);
}

static int arm_name_accepts_quadword_scalable_elements(
    cdisasm_arm_name_id name_id)
{
    return name_id == CDISASM_ARM_NAME_MOV
        || name_id == CDISASM_ARM_NAME_MOVAZ
        || name_id == CDISASM_ARM_NAME_AESD
        || name_id == CDISASM_ARM_NAME_AESDIMC
        || name_id == CDISASM_ARM_NAME_AESE
        || name_id == CDISASM_ARM_NAME_AESEMC
        || name_id == CDISASM_ARM_NAME_PMULL
        || name_id == CDISASM_ARM_NAME_PMLAL
        || name_id == CDISASM_ARM_NAME_LD1Q
        || name_id == CDISASM_ARM_NAME_LD2Q
        || name_id == CDISASM_ARM_NAME_LD3Q
        || name_id == CDISASM_ARM_NAME_LD4Q
        || name_id == CDISASM_ARM_NAME_ST1Q
        || name_id == CDISASM_ARM_NAME_ST2Q
        || name_id == CDISASM_ARM_NAME_ST3Q
        || name_id == CDISASM_ARM_NAME_ST4Q
        || name_id == CDISASM_ARM_NAME_LD1W
        || name_id == CDISASM_ARM_NAME_LD1D
        || name_id == CDISASM_ARM_NAME_ST1W
        || name_id == CDISASM_ARM_NAME_ST1D
        || name_id == CDISASM_ARM_NAME_REVD
        || name_id == CDISASM_ARM_NAME_ZIP
        || name_id == CDISASM_ARM_NAME_UZP
        || (name_id >= CDISASM_ARM_NAME_ZIP1
            && name_id <= CDISASM_ARM_NAME_TRN2);
}

static int arm_valid_scalable_operand(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    uint8_t element_size = CDISASM_ARM_SCALABLE_ELEMENT_SIZE(operand);
    int lane = (operand->flags & CDISASM_ARM_OPERAND_FLAG_HAS_LANE) != 0u;

    return instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR) != 0u
        && operand->reg >= CDISASM_ARM_REG_Z0
        && operand->reg <= CDISASM_ARM_REG_Z31
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u
        && operand->address == 0u
        && operand->size == 0u
        && ((element_size == 0u
                && (instruction->name_id == CDISASM_ARM_NAME_MOVPRFX
                    || instruction->form_id == UINT16_C(3215)
                    || instruction->form_id == UINT16_C(3476)
                    || (instruction->form_id >= UINT16_C(3772)
                        && instruction->form_id <= UINT16_C(3784)
                        && operand == &instruction->operand[3])))
            || element_size == 1u || element_size == 2u
            || element_size == 4u || element_size == 8u
            || (element_size == 16u
                && arm_name_accepts_quadword_scalable_elements(
                    instruction->name_id)))
        && operand->scale == 0u
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u
        && (operand->flags == CDISASM_OPERAND_FLAG_NONE
            || operand->flags == CDISASM_ARM_OPERAND_FLAG_HAS_LANE
            || (operand->flags == CDISASM_ARM_OPERAND_FLAG_HAS_ROTATION
                && instruction->form_id == UINT16_C(2920)
                && instruction->name_id == CDISASM_ARM_NAME_FCMLA
                && operand == &instruction->operand[3]
                && operand->imm <= UINT64_C(270)
                && operand->imm % UINT64_C(90) == 0u))
        && (!lane
            || (instruction->name_id != CDISASM_ARM_NAME_DUPQ
                && instruction->name_id != CDISASM_ARM_NAME_MOV)
            || operand->imm
                < (instruction->name_id == CDISASM_ARM_NAME_DUPQ
                    ? UINT64_C(16) : UINT64_C(64)) / element_size)
        && (lane || operand->imm == 0u
            || operand->flags == CDISASM_ARM_OPERAND_FLAG_HAS_ROTATION);
}

static int arm_sve_psel_fields(
    uint32_t word, uint8_t *element_size, uint64_t *lane)
{
    unsigned tszl;
    unsigned size_log2;

    if ((word & UINT32_C(0xff20c210)) != UINT32_C(0x25204000)
        || (word & UINT32_C(0x005c0000)) == 0u) {
        return 0;
    }
    tszl = (word >> 18) & 7u;
    size_log2 = (tszl & 1u) != 0u ? 0u
        : (tszl & 2u) != 0u ? 1u
        : (tszl & 4u) != 0u ? 2u : 3u;
    *element_size = (uint8_t)(1u << size_log2);
    *lane = (word >> 23) & 1u;
    if (size_log2 != 3u) {
        *lane = (*lane << (3u - size_log2))
            | (((word >> 22) & 1u) << (2u - size_log2))
            | (tszl >> (size_log2 + 1u));
    }
    return 1;
}

static int arm_valid_predicate_operand(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    uint8_t element_size = CDISASM_ARM_SCALABLE_ELEMENT_SIZE(operand);
    uint8_t qualifier = operand->flags;
    int classic_counter = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id == UINT16_C(2600)
        && instruction->name_id == CDISASM_ARM_NAME_CNTP
        && operand->reg >= CDISASM_ARM_REG_PN0
        && operand->reg <= CDISASM_ARM_REG_PN15;
    int restricted_counter = instruction->isa_id == CDISASM_ARM_ISA_A64
        && ((instruction->form_id >= UINT16_C(2566)
                && instruction->form_id <= UINT16_C(2573))
            || (instruction->form_id >= UINT16_C(2582)
                && instruction->form_id <= UINT16_C(2584))
            || (instruction->form_id >= UINT16_C(3549)
                && instruction->form_id <= UINT16_C(3676)
                && ((instruction->form_id & UINT16_C(1)) != 0u
                    || (instruction->name_id >= CDISASM_ARM_NAME_STNT1B
                        && instruction->name_id <= CDISASM_ARM_NAME_STNT1W)
                    || instruction->name_id == CDISASM_ARM_NAME_LDNT1B
                    || instruction->name_id == CDISASM_ARM_NAME_LDNT1H
                    || instruction->name_id == CDISASM_ARM_NAME_LDNT1W
                    || instruction->name_id == CDISASM_ARM_NAME_LDNT1D))
            || instruction->form_id == UINT16_C(4215)
            || instruction->form_id == UINT16_C(4216))
        && operand->reg >= CDISASM_ARM_REG_PN8
        && operand->reg <= CDISASM_ARM_REG_PN15;
    int predicate_counter = classic_counter || restricted_counter;
    int multi_transfer_counter = instruction->form_id >= UINT16_C(3549)
        && instruction->form_id <= UINT16_C(3676)
        && ((instruction->form_id & UINT16_C(1)) != 0u
            || (instruction->name_id >= CDISASM_ARM_NAME_STNT1B
                && instruction->name_id <= CDISASM_ARM_NAME_STNT1W)
            || instruction->name_id == CDISASM_ARM_NAME_LDNT1B
            || instruction->name_id == CDISASM_ARM_NAME_LDNT1H
            || instruction->name_id == CDISASM_ARM_NAME_LDNT1W
            || instruction->name_id == CDISASM_ARM_NAME_LDNT1D);
    int extract_source = restricted_counter
        && instruction->name_id == CDISASM_ARM_NAME_PEXT
        && (instruction->form_id == UINT16_C(2582)
            || instruction->form_id == UINT16_C(2583))
        && operand->access == CDISASM_OPERAND_ACCESS_READ
        && qualifier == CDISASM_ARM_OPERAND_FLAG_HAS_LANE;
    int indexed_psel = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id == UINT16_C(2565)
        && instruction->name_id == CDISASM_ARM_NAME_PSEL
        && instruction->operand_count == 3u
        && operand == &instruction->operand[2];

    return instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR) != 0u
        && ((operand->reg >= CDISASM_ARM_REG_P0
                && operand->reg <= CDISASM_ARM_REG_P15)
            || predicate_counter)
        && (indexed_psel
            ? operand->base_reg >= CDISASM_ARM_REG_W12
                && operand->base_reg <= CDISASM_ARM_REG_W15
            : operand->base_reg == CDISASM_ARM_REG_NONE)
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u
        && operand->address == 0u
        && (indexed_psel
            ? operand->imm <= UINT64_C(15)
            : extract_source
            ? operand->imm < (instruction->form_id == UINT16_C(2582)
                    ? UINT64_C(4) : UINT64_C(2))
            : operand->imm == 0u)
        && operand->size == 0u
        && ((extract_source && element_size == 0u)
            || element_size == 1u || element_size == 2u
            || element_size == 4u || element_size == 8u
            || (element_size == 16u
                && arm_name_accepts_quadword_scalable_elements(
                    instruction->name_id)))
        && operand->scale == 0u
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u
        && (indexed_psel
            ? qualifier == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED
            : predicate_counter
            ? (multi_transfer_counter
                ? qualifier == 0u
                    || qualifier == CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO
                : qualifier == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED)
                || (extract_source
                    && qualifier == CDISASM_ARM_OPERAND_FLAG_HAS_LANE)
            : qualifier == 0u
            || qualifier == CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE
            || qualifier == CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO
            || qualifier == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
}

static int arm_valid_scalable_list_operand(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    unsigned count = CDISASM_ARM_SCALABLE_LIST_COUNT(operand);
    unsigned stride = CDISASM_ARM_SCALABLE_LIST_STRIDE(operand);

    return instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR) != 0u
        && operand->reg >= CDISASM_ARM_REG_Z0
        && operand->reg <= CDISASM_ARM_REG_Z31
        && count >= 1u && count <= 4u && stride >= 1u && stride <= 8u
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->address == 0u && operand->imm == 0u
        && operand->size == 0u && operand->flags == 0u
        && (operand->extend_type == 1u || operand->extend_type == 2u
            || operand->extend_type == 4u || operand->extend_type == 8u
            || (operand->extend_type == 16u
                && arm_name_accepts_quadword_scalable_elements(
                    instruction->name_id)))
        && operand->scale == 0u
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u;
}

static int arm_valid_vector_list_operand(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    unsigned count = operand->register_list;
    unsigned element_size = operand->extend_type;
    int a32_structure = (instruction->isa_id == CDISASM_ARM_ISA_A32
        || instruction->isa_id == CDISASM_ARM_ISA_T32)
        && ((instruction->name_id >= CDISASM_ARM_NAME_VLD1
                && instruction->name_id <= CDISASM_ARM_NAME_VLD4)
            || (instruction->name_id >= CDISASM_ARM_NAME_VST1
                && instruction->name_id <= CDISASM_ARM_NAME_VST4));
    int a32_vfp_multiple = (instruction->isa_id == CDISASM_ARM_ISA_A32
        || instruction->isa_id == CDISASM_ARM_ISA_T32)
        && (instruction->name_id == CDISASM_ARM_NAME_VLDM
            || instruction->name_id == CDISASM_ARM_NAME_VLDMDB
            || instruction->name_id == CDISASM_ARM_NAME_VSTM
            || instruction->name_id == CDISASM_ARM_NAME_VSTMDB);
    int fixed_structure = instruction->form_id >= UINT16_C(4573)
        && instruction->form_id <= UINT16_C(4614);
    int lane_structure = instruction->form_id >= UINT16_C(4615)
        && instruction->form_id <= UINT16_C(4724)
        && instruction->name_id >= CDISASM_ARM_NAME_LD1
        && instruction->name_id <= CDISASM_ARM_NAME_ST4;

    if (a32_structure) {
        int lane = (operand->flags
            & CDISASM_ARM_OPERAND_FLAG_HAS_LANE) != 0u;
        return (instruction->instruction_flags
                & CDISASM_ARM_INSTRUCTION_FLAG_SIMD) != 0u
            && operand->reg >= CDISASM_ARM_REG_D0
            && operand->reg <= CDISASM_ARM_REG_D31
            && count >= 1u && count <= 4u
            && (element_size == 1u || element_size == 2u
                || element_size == 4u || element_size == 8u)
            && operand->base_reg == CDISASM_ARM_REG_NONE
            && operand->index_reg == CDISASM_ARM_REG_NONE
            && operand->address == 0u
            && (lane ? operand->imm < 8u / element_size
                     : operand->imm == 0u)
            && operand->size == 8u
            && operand->flags == (lane
                ? CDISASM_ARM_OPERAND_FLAG_HAS_LANE : 0u)
            && operand->scale == 8u / element_size
            && operand->shift_type == CDISASM_ARM_SHIFT_NONE
            && operand->shift_amount == 0u;
    }

    if (a32_vfp_multiple) {
        int is_double = operand->reg >= CDISASM_ARM_REG_D0
            && operand->reg <= CDISASM_ARM_REG_D31;
        int is_single = operand->reg >= CDISASM_ARM_REG_S0
            && operand->reg <= CDISASM_ARM_REG_S31;
        return (instruction->instruction_flags
                & CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT) != 0u
            && (is_double || is_single)
            && count >= 1u && count <= 32u
            && operand->base_reg == CDISASM_ARM_REG_NONE
            && operand->index_reg == CDISASM_ARM_REG_NONE
            && operand->address == 0u && operand->imm == 0u
            && operand->size == (is_double ? 8u : 4u)
            && operand->flags == CDISASM_OPERAND_FLAG_NONE
            && operand->shift_type == CDISASM_ARM_SHIFT_NONE
            && operand->shift_amount == 0u
            && operand->extend_type == (is_double ? 8u : 4u)
            && operand->scale == 1u
            && ((unsigned)(operand->reg
                    - (is_double ? CDISASM_ARM_REG_D0
                                  : CDISASM_ARM_REG_S0)) + count <= 32u);
    }

    return instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_SIMD) != 0u
        && operand->reg >= CDISASM_ARM_REG_V0
        && operand->reg <= CDISASM_ARM_REG_V31
        && count >= 1u && count <= 4u
        && (element_size == 1u || element_size == 2u
            || element_size == 4u || element_size == 8u)
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->address == 0u
        && (lane_structure
            ? operand->imm < 16u / element_size : operand->imm == 0u)
        && (operand->size == 16u
            || (fixed_structure && operand->size == 8u))
        && operand->flags == (lane_structure
            ? CDISASM_ARM_OPERAND_FLAG_HAS_LANE : 0u)
        && operand->scale == operand->size / element_size
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u;
}

static int arm_is_predicated_mova_form(cdisasm_arm_form_id form_id);

static int arm_is_sme2_multi_mova_form(cdisasm_arm_form_id form_id);

static int arm_is_sme2p1_movaz_form(cdisasm_arm_form_id form_id);

static int arm_valid_tile_operand(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    int movt = instruction->name_id == CDISASM_ARM_NAME_MOVT
        && instruction->form_id >= UINT16_C(3917)
        && instruction->form_id <= UINT16_C(3919);
    int zero_range = instruction->name_id == CDISASM_ARM_NAME_ZERO
        && instruction->form_id >= UINT16_C(3910)
        && instruction->form_id <= UINT16_C(3915);
    int indexed_long = instruction->form_id == UINT16_C(3954)
        || instruction->form_id == UINT16_C(3950)
        || instruction->form_id == UINT16_C(3951)
        || instruction->form_id == UINT16_C(3952)
        || instruction->form_id == UINT16_C(3953)
        || (instruction->form_id >= UINT16_C(3955)
            && instruction->form_id <= UINT16_C(3958))
        || (instruction->form_id >= UINT16_C(4077)
            && instruction->form_id <= UINT16_C(4080))
        || (instruction->form_id >= UINT16_C(4073)
            && instruction->form_id <= UINT16_C(4076))
        || instruction->form_id == UINT16_C(4116);
    int indexed_long4 = (instruction->form_id >= UINT16_C(4000)
            && instruction->form_id <= UINT16_C(4003))
        || (instruction->form_id >= UINT16_C(4048)
            && instruction->form_id <= UINT16_C(4051))
        || (instruction->form_id >= UINT16_C(4186)
            && instruction->form_id <= UINT16_C(4189))
        || (instruction->form_id >= UINT16_C(4146)
            && instruction->form_id <= UINT16_C(4149))
        || (instruction->form_id >= UINT16_C(4069)
            && instruction->form_id <= UINT16_C(4072))
        || (instruction->form_id >= UINT16_C(4112)
            && instruction->form_id <= UINT16_C(4115))
        || (instruction->form_id >= UINT16_C(3989)
            && instruction->form_id <= UINT16_C(3992));
    indexed_long4 = indexed_long4
        || (instruction->form_id >= UINT16_C(4037)
            && instruction->form_id <= UINT16_C(4040))
        || ((instruction->form_id >= UINT16_C(4064)
            && instruction->form_id <= UINT16_C(4068))
            && instruction->form_id != UINT16_C(4066))
        || ((instruction->form_id >= UINT16_C(4107)
            && instruction->form_id <= UINT16_C(4111))
            && instruction->form_id != UINT16_C(4109))
        || (instruction->form_id >= UINT16_C(4141)
            && instruction->form_id <= UINT16_C(4144))
        || (instruction->form_id >= UINT16_C(4181)
            && instruction->form_id <= UINT16_C(4184));
    int indexed_d2 = (instruction->form_id >= UINT16_C(3996)
            && instruction->form_id <= UINT16_C(3999))
        || instruction->form_id == UINT16_C(4042)
        || instruction->form_id == UINT16_C(4043)
        || instruction->form_id == UINT16_C(4044)
        || instruction->form_id == UINT16_C(4045)
        || instruction->form_id == UINT16_C(4046)
        || instruction->form_id == UINT16_C(4047);
    int indexed_vdot_s = instruction->form_id == UINT16_C(3972)
        || instruction->form_id == UINT16_C(3980)
        || instruction->form_id == UINT16_C(3978)
        || instruction->form_id == UINT16_C(3983)
        || instruction->form_id == UINT16_C(4020)
        || instruction->form_id == UINT16_C(4028)
        || instruction->form_id == UINT16_C(4026)
        || instruction->form_id == UINT16_C(4032);
    int indexed_multi2_s = instruction->form_id == UINT16_C(3969)
        || (instruction->form_id >= UINT16_C(3973)
            && instruction->form_id <= UINT16_C(3977))
        || instruction->form_id == UINT16_C(3979)
        || instruction->form_id == UINT16_C(3981)
        || instruction->form_id == UINT16_C(3982);
    indexed_multi2_s = indexed_multi2_s
        || instruction->form_id == UINT16_C(4018)
        || instruction->form_id == UINT16_C(4019)
        || (instruction->form_id >= UINT16_C(4022)
            && instruction->form_id <= UINT16_C(4025))
        || instruction->form_id == UINT16_C(4027)
        || instruction->form_id == UINT16_C(4030)
        || instruction->form_id == UINT16_C(4031);
    int indexed_fp16 = (instruction->form_id >= UINT16_C(3965)
            && instruction->form_id <= UINT16_C(3968))
        || (instruction->form_id >= UINT16_C(4013)
            && instruction->form_id <= UINT16_C(4016))
        || (instruction->form_id >= UINT16_C(4154)
            && instruction->form_id <= UINT16_C(4157))
        || (instruction->form_id >= UINT16_C(4194)
            && instruction->form_id <= UINT16_C(4197))
        || instruction->form_id == UINT16_C(4004)
        || instruction->form_id == UINT16_C(4017)
        || instruction->form_id == UINT16_C(3993)
        || instruction->form_id == UINT16_C(4041)
        || instruction->form_id == UINT16_C(4066)
        || instruction->form_id == UINT16_C(4109)
        || instruction->form_id == UINT16_C(4145)
        || instruction->form_id == UINT16_C(4185);
    int multi_dot = (instruction->form_id >= UINT16_C(4158)
            && instruction->form_id <= UINT16_C(4162))
        || (instruction->form_id >= UINT16_C(4198)
            && instruction->form_id <= UINT16_C(4202))
        || (instruction->form_id >= UINT16_C(4085)
            && instruction->form_id <= UINT16_C(4090))
        || (instruction->form_id >= UINT16_C(4121)
            && instruction->form_id <= UINT16_C(4126));
    int multi2_fdot_single = (instruction->form_id >= UINT16_C(4081)
            && instruction->form_id <= UINT16_C(4084))
        || (instruction->form_id >= UINT16_C(4117)
            && instruction->form_id <= UINT16_C(4120))
        || (instruction->form_id >= UINT16_C(4150)
            && instruction->form_id <= UINT16_C(4153))
        || (instruction->form_id >= UINT16_C(4190)
            && instruction->form_id <= UINT16_C(4193));
    int multi2_arith_single = (instruction->form_id >= UINT16_C(4091)
            && instruction->form_id <= UINT16_C(4098))
        || (instruction->form_id >= UINT16_C(4127)
            && instruction->form_id <= UINT16_C(4134));
    int multi_fp_mla = instruction->form_id == UINT16_C(4163)
        || instruction->form_id == UINT16_C(4164)
        || instruction->form_id == UINT16_C(4203)
        || instruction->form_id == UINT16_C(4204);
    int multi_int_add_sub = instruction->form_id == UINT16_C(4165)
        || instruction->form_id == UINT16_C(4166)
        || instruction->form_id == UINT16_C(4205)
        || instruction->form_id == UINT16_C(4206);
    int multi_arith_single = instruction->form_id >= UINT16_C(4167)
        && instruction->form_id <= UINT16_C(4174);
    multi_arith_single = multi_arith_single
        || (instruction->form_id >= UINT16_C(4207)
            && instruction->form_id <= UINT16_C(4214));
    int sme_fvdot = instruction->form_id >= UINT16_C(6500)
        && instruction->form_id <= UINT16_C(6504);
    int multi_za_move = instruction->isa_id == CDISASM_ARM_ISA_A64
        && ((instruction->name_id == CDISASM_ARM_NAME_MOV
                && arm_is_sme2_multi_mova_form(instruction->form_id))
            || (instruction->name_id == CDISASM_ARM_NAME_ZERO
                && (instruction->form_id == UINT16_C(3908)
                    || instruction->form_id == UINT16_C(3909)))
            || (instruction->name_id == CDISASM_ARM_NAME_MOVAZ
                && arm_is_sme2p1_movaz_form(instruction->form_id)))
        && (operand->register_list == 2u
            || operand->register_list == 4u);
    int selector = operand->base_reg != CDISASM_ARM_REG_NONE;
    int selected_slice = selector && operand->reg >= CDISASM_ARM_REG_ZAB0
        && operand->reg <= CDISASM_ARM_REG_ZAQ15;
    uint8_t expected_element_size = 0u;
    uint64_t maximum_offset = 0u;

    if (zero_range || indexed_long) {
        unsigned range = operand->register_list & 255u;
        unsigned vgx = indexed_long ? 0u : operand->register_list >> 8;
        return operand->reg == CDISASM_ARM_REG_ZA
            && operand->base_reg >= CDISASM_ARM_REG_W8
            && operand->base_reg <= CDISASM_ARM_REG_W11
            && operand->index_reg == CDISASM_ARM_REG_NONE
            && (indexed_long ? range == 2u : (range == 2u || range == 4u))
            && (vgx == 0u || vgx == 2u || vgx == 4u)
            && operand->imm + range <= 16u
            && operand->imm % range == 0u && operand->size == 0u
            && operand->flags == 0u
            && operand->extend_type == (indexed_long
                ? ((instruction->form_id == UINT16_C(3954)
                    || instruction->form_id == UINT16_C(4116)) ? 2u : 4u) : 8u)
            && operand->scale == 0u && operand->shift_type == CDISASM_ARM_SHIFT_NONE
            && operand->shift_amount == 0u
            && operand->access == (indexed_long
                ? CDISASM_OPERAND_ACCESS_READ_WRITE
                : CDISASM_OPERAND_ACCESS_WRITE);
    }
    if (indexed_fp16) {
        return operand->reg == CDISASM_ARM_REG_ZA
            && operand->base_reg >= CDISASM_ARM_REG_W8
            && operand->base_reg <= CDISASM_ARM_REG_W11
            && operand->index_reg == CDISASM_ARM_REG_NONE
            && (operand->register_list == 2u
                || operand->register_list == 4u) && operand->imm < 8u
            && operand->size == 0u && operand->flags == 0u
            && operand->extend_type == 2u && operand->scale == 0u
            && operand->shift_type == CDISASM_ARM_SHIFT_NONE
            && operand->shift_amount == 0u
            && operand->access == CDISASM_OPERAND_ACCESS_READ_WRITE;
    }
    if (multi_dot || sme_fvdot || multi2_fdot_single || multi2_arith_single
        || multi_fp_mla || multi_int_add_sub
        || multi_arith_single) {
        return operand->reg == CDISASM_ARM_REG_ZA
            && operand->base_reg >= CDISASM_ARM_REG_W8
            && operand->base_reg <= CDISASM_ARM_REG_W11
            && operand->index_reg == CDISASM_ARM_REG_NONE
            && (operand->register_list == 2u
                || operand->register_list == 4u) && operand->imm < 8u
            && operand->size == 0u && operand->flags == 0u
            && (operand->extend_type == 4u || operand->extend_type == 8u
                || ((multi2_fdot_single || multi2_arith_single)
                    && operand->extend_type == 2u)
                || (sme_fvdot && instruction->form_id == UINT16_C(6504)
                    && operand->extend_type == 2u)
                || (instruction->form_id >= UINT16_C(4171)
                    && operand->extend_type == 2u))
            && operand->scale == 0u
            && operand->shift_type == CDISASM_ARM_SHIFT_NONE
            && operand->shift_amount == 0u
            && operand->access == CDISASM_OPERAND_ACCESS_READ_WRITE;
    }
    if (indexed_long4) {
        return operand->reg == CDISASM_ARM_REG_ZA
            && operand->base_reg >= CDISASM_ARM_REG_W8
            && operand->base_reg <= CDISASM_ARM_REG_W11
            && operand->index_reg == CDISASM_ARM_REG_NONE
            && (operand->register_list == 2u
                || operand->register_list == 4u) && operand->imm <= 6u
            && (operand->imm & 1u) == 0u
            && operand->size == 0u && operand->flags == 0u
            && operand->extend_type == 4u && operand->scale == 0u
            && operand->shift_type == CDISASM_ARM_SHIFT_NONE
            && operand->shift_amount == 0u
            && operand->access == CDISASM_OPERAND_ACCESS_READ_WRITE;
    }
    if (indexed_d2) {
        return operand->reg == CDISASM_ARM_REG_ZA
            && operand->base_reg >= CDISASM_ARM_REG_W8
            && operand->base_reg <= CDISASM_ARM_REG_W11
            && operand->index_reg == CDISASM_ARM_REG_NONE
            && (operand->register_list == 2u
                || operand->register_list == 4u) && operand->imm < 8u
            && operand->size == 0u && operand->flags == 0u
            && operand->extend_type == 8u && operand->scale == 0u
            && operand->shift_type == CDISASM_ARM_SHIFT_NONE
            && operand->shift_amount == 0u
            && operand->access == CDISASM_OPERAND_ACCESS_READ_WRITE;
    }
    if (indexed_vdot_s || indexed_multi2_s) {
        return operand->reg == CDISASM_ARM_REG_ZA
            && operand->base_reg >= CDISASM_ARM_REG_W8
            && operand->base_reg <= CDISASM_ARM_REG_W11
            && operand->index_reg == CDISASM_ARM_REG_NONE
            && (operand->register_list == 2u
                || operand->register_list == 4u) && operand->imm < 8u
            && operand->size == 0u && operand->flags == 0u
            && operand->extend_type == 4u && operand->scale == 0u
            && operand->shift_type == CDISASM_ARM_SHIFT_NONE
            && operand->shift_amount == 0u
            && operand->access == CDISASM_OPERAND_ACCESS_READ_WRITE;
    }

    if (movt) {
        int vector = instruction->form_id == UINT16_C(3919);
        return instruction->isa_id == CDISASM_ARM_ISA_A64
            && operand->reg == CDISASM_ARM_REG_ZT0
            && operand->base_reg == CDISASM_ARM_REG_NONE
            && operand->index_reg == CDISASM_ARM_REG_NONE
            && operand->register_list == 0u && operand->address == 0u
            && operand->size == 0u && operand->extend_type == 0u
            && operand->scale == 0u
            && operand->shift_type == CDISASM_ARM_SHIFT_NONE
            && operand->shift_amount == 0u
            && (vector ? operand->imm <= UINT64_C(3)
                    && operand->flags == CDISASM_ARM_OPERAND_FLAG_VL_SCALED
                : operand->imm <= UINT64_C(56)
                    && (operand->imm & UINT64_C(7)) == 0u
                    && operand->flags == CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
    }
    if (multi_za_move) {
        int whole_array = operand->reg == CDISASM_ARM_REG_ZA
            && operand->base_reg >= CDISASM_ARM_REG_W8
            && operand->base_reg <= CDISASM_ARM_REG_W11;
        int selected_group = operand->reg >= CDISASM_ARM_REG_ZAB0
            && operand->reg <= CDISASM_ARM_REG_ZAD7
            && operand->base_reg >= CDISASM_ARM_REG_W12
            && operand->base_reg <= CDISASM_ARM_REG_W15;

        return (whole_array || selected_group)
            && operand->index_reg == CDISASM_ARM_REG_NONE
            && operand->address == 0u && operand->size == 0u
            && (whole_array
                ? operand->extend_type == 8u
                    && operand->flags == CDISASM_OPERAND_FLAG_NONE
                    && operand->imm <= UINT64_C(7)
                : (operand->extend_type == 1u
                        || operand->extend_type == 2u
                        || operand->extend_type == 4u
                        || operand->extend_type == 8u)
                    && (operand->flags == CDISASM_OPERAND_FLAG_NONE
                        || operand->flags
                            == CDISASM_ARM_OPERAND_FLAG_TILE_VERTICAL)
                    && operand->imm <= UINT64_C(15))
            && operand->scale == 0u
            && operand->shift_type == CDISASM_ARM_SHIFT_NONE
            && operand->shift_amount == 0u;
    }

    if (selected_slice) {
        if (operand->reg == CDISASM_ARM_REG_ZAB0) {
            expected_element_size = 1u;
            maximum_offset = UINT64_C(15);
        } else if (operand->reg >= CDISASM_ARM_REG_ZAH0
            && operand->reg <= CDISASM_ARM_REG_ZAH1) {
            expected_element_size = 2u;
            maximum_offset = UINT64_C(7);
        } else if (operand->reg >= CDISASM_ARM_REG_ZAS0
            && operand->reg <= CDISASM_ARM_REG_ZAS3) {
            expected_element_size = 4u;
            maximum_offset = UINT64_C(3);
        } else if (operand->reg >= CDISASM_ARM_REG_ZAD0
            && operand->reg <= CDISASM_ARM_REG_ZAD7) {
            expected_element_size = 8u;
            maximum_offset = UINT64_C(1);
        } else {
            expected_element_size = 16u;
            maximum_offset = 0u;
        }
    }

    return instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_MATRIX) != 0u
        && operand->reg >= CDISASM_ARM_REG_ZA
        && operand->reg <= CDISASM_ARM_REG_ZT0
        && (!selector || (operand->base_reg >= CDISASM_ARM_REG_W12
            && operand->base_reg <= CDISASM_ARM_REG_W15))
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u && operand->address == 0u
        && operand->size == 0u
        && ((!selected_slice && operand->flags == 0u)
            || (selected_slice
                && (operand->flags == 0u
                    || operand->flags
                        == CDISASM_ARM_OPERAND_FLAG_TILE_VERTICAL)))
        && (operand->extend_type == 0u || operand->extend_type == 1u
            || operand->extend_type == 2u || operand->extend_type == 4u
            || operand->extend_type == 8u
            || (selected_slice && operand->extend_type == 16u))
        && operand->scale == 0u
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u
        && (selector || operand->imm == 0u)
        && (!selector || operand->reg != CDISASM_ARM_REG_ZA
            || operand->imm <= UINT64_C(15))
        && (!selected_slice
            || (operand->extend_type == expected_element_size
                && operand->imm <= maximum_offset));
}

static int arm_valid_pair_base_operand(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    cdisasm_arm_reg_id expected_second =
        operand->reg == CDISASM_ARM_REG_X30
            ? CDISASM_ARM_REG_XZR
            : (cdisasm_arm_reg_id)(operand->reg + 1u);

    return instruction->isa_id == CDISASM_ARM_ISA_A64
        && operand->reg >= CDISASM_ARM_REG_X0
        && operand->reg <= CDISASM_ARM_REG_X30
        && operand->index_reg == expected_second
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u
        && operand->address == 0u && operand->imm == 0u
        && operand->size == 16u && operand->flags == 0u
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u
        && operand->extend_type == 0u && operand->scale == 0u;
}

static int arm_valid_predicate_pair_operand(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    int while_pair = operand->flags
            == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED
        && instruction->form_id >= UINT16_C(2574)
        && instruction->form_id <= UINT16_C(2581)
        && (instruction->raw_instruction & UINT32_C(0xff20f010))
            == UINT32_C(0x25205010);
    int extract_pair = operand->flags
            == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED
        && instruction->form_id == UINT16_C(2583)
        && instruction->name_id == CDISASM_ARM_NAME_PEXT
        && (instruction->raw_instruction & UINT32_C(0xff3ffe10))
            == UINT32_C(0x25207410);
    int typed_pair = while_pair || extract_pair;

    return instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR) != 0u
        && (typed_pair
            ? (operand->reg >= CDISASM_ARM_REG_P0
                && operand->reg
                    <= (extract_pair ? CDISASM_ARM_REG_P15
                                     : CDISASM_ARM_REG_P14)
                && (!while_pair
                    || ((unsigned)(operand->reg - CDISASM_ARM_REG_P0)
                        & 1u) == 0u)
                && operand->index_reg == (extract_pair
                    ? (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0
                        + (((unsigned)(operand->reg - CDISASM_ARM_REG_P0)
                            + 1u) & 15u))
                    : (cdisasm_arm_reg_id)(operand->reg + 1u))
                && operand->access == CDISASM_OPERAND_ACCESS_WRITE)
            : ((instruction->instruction_flags
                    & CDISASM_ARM_INSTRUCTION_FLAG_SME) != 0u
                && operand->reg >= CDISASM_ARM_REG_P0
                && operand->reg <= CDISASM_ARM_REG_P7
                && operand->index_reg >= CDISASM_ARM_REG_P0
                && operand->index_reg <= CDISASM_ARM_REG_P7
                && operand->flags
                    == CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE
                && operand->access == CDISASM_OPERAND_ACCESS_READ))
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u
        && operand->address == 0u && operand->imm == 0u
        && operand->size == 0u
        && (operand->extend_type == 1u || operand->extend_type == 2u
            || operand->extend_type == 4u || operand->extend_type == 8u)
        && operand->scale == 0u
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u;
}

static int arm_valid_register_block_operand(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    unsigned count = operand->register_list;

    return instruction->isa_id == CDISASM_ARM_ISA_A64
        && operand->reg >= CDISASM_ARM_REG_X0
        && operand->reg <= CDISASM_ARM_REG_X30
        && count == 8u
        && ((unsigned)(operand->reg - CDISASM_ARM_REG_X0) & 1u) == 0u
        && operand->reg <= CDISASM_ARM_REG_X22
        && (unsigned)(operand->reg - CDISASM_ARM_REG_X0) + count <= 31u
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->address == 0u && operand->imm == 0u
        && operand->size == count * 8u && operand->flags == 0u
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u
        && operand->extend_type == 0u && operand->scale == 0u;
}

static int arm_valid_system_operand(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    uint64_t maximum;
    int valid_name;

    if (operand->type == CDISASM_ARM_OPERAND_SYSTEM_REGISTER) {
        if (instruction->name_id == CDISASM_ARM_NAME_VMRS
            || instruction->name_id == CDISASM_ARM_NAME_VMSR) {
            maximum = UINT64_C(0);
            valid_name = instruction->isa_id == CDISASM_ARM_ISA_A32
                || instruction->isa_id == CDISASM_ARM_ISA_T32;
        } else if ((instruction->isa_id == CDISASM_ARM_ISA_A32
                || instruction->isa_id == CDISASM_ARM_ISA_T32)
            && (instruction->name_id == CDISASM_ARM_NAME_MRS
                || instruction->name_id == CDISASM_ARM_NAME_MSR)) {
            maximum = UINT64_C(0x1f);
            valid_name = instruction->name_id == CDISASM_ARM_NAME_MRS
                ? (operand->imm & UINT64_C(0x0f)) == 0u
                : (operand->imm & UINT64_C(0x0f)) != 0u;
        } else {
            maximum = UINT64_C(0xffff);
            valid_name = instruction->isa_id == CDISASM_ARM_ISA_A64
                && (instruction->name_id == CDISASM_ARM_NAME_MRS
                    || instruction->name_id == CDISASM_ARM_NAME_MSR);
        }
    } else {
        maximum = UINT64_C(0x3fff);
        valid_name = instruction->name_id == CDISASM_ARM_NAME_SYS
            || instruction->name_id == CDISASM_ARM_NAME_SYSL;
    }
    return valid_name
        && operand->imm <= maximum
        && operand->reg == CDISASM_ARM_REG_NONE
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u && operand->address == 0u
        && operand->size == 0u && operand->flags == 0u
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u
        && operand->extend_type == CDISASM_ARM_EXTEND_NONE
        && operand->scale == 0u;
}

static int arm_valid_pstate_field_operand(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    return instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id == UINT16_C(4498)
        && instruction->name_id == CDISASM_ARM_NAME_MSR
        && operand == &instruction->operand[0]
        && arm_pstate_msr_field_name((uint8_t)operand->imm) != NULL
        && operand->imm <= CDISASM_ARM_PSTATE_FIELD_DAIFCLR
        && operand->reg == CDISASM_ARM_REG_NONE
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u
        && operand->address == 0u
        && operand->size == 0u
        && operand->flags == 0u
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u
        && operand->extend_type == CDISASM_ARM_EXTEND_NONE
        && operand->scale == 0u
        && operand->access == CDISASM_OPERAND_ACCESS_WRITE;
}

static int arm_valid_operand(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    if (!arm_valid_access(operand->access)) {
        return 0;
    }
    switch (operand->type) {
        case CDISASM_OPERAND_REGISTER:
            return arm_valid_register_operand(instruction, operand);
        case CDISASM_OPERAND_IMMEDIATE:
            return arm_valid_immediate_operand(instruction, operand);
        case CDISASM_OPERAND_MEMORY:
            return arm_valid_memory_operand(instruction, operand);
        case CDISASM_ARM_OPERAND_REGISTER_LIST:
            return arm_valid_register_list_operand(instruction, operand);
        case CDISASM_ARM_OPERAND_REGISTER_PAIR:
            return arm_valid_register_pair_operand(instruction, operand);
        case CDISASM_ARM_OPERAND_SCALABLE_REGISTER:
            return arm_valid_scalable_operand(instruction, operand);
        case CDISASM_ARM_OPERAND_PREDICATE:
            return arm_valid_predicate_operand(instruction, operand);
        case CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST:
            return arm_valid_scalable_list_operand(instruction, operand);
        case CDISASM_ARM_OPERAND_TILE:
            return arm_valid_tile_operand(instruction, operand);
        case CDISASM_ARM_OPERAND_REGISTER_PAIR_BASE:
            return arm_valid_pair_base_operand(instruction, operand);
        case CDISASM_ARM_OPERAND_PREDICATE_PAIR:
            return arm_valid_predicate_pair_operand(instruction, operand);
        case CDISASM_ARM_OPERAND_REGISTER_BLOCK:
            return arm_valid_register_block_operand(instruction, operand);
        case CDISASM_ARM_OPERAND_SYSTEM_REGISTER:
        case CDISASM_ARM_OPERAND_SYSTEM_OPERATION:
            return arm_valid_system_operand(instruction, operand);
        case CDISASM_ARM_OPERAND_PSTATE_FIELD:
            return arm_valid_pstate_field_operand(instruction, operand);
        case CDISASM_ARM_OPERAND_VECTOR_REGISTER_LIST:
            return arm_valid_vector_list_operand(instruction, operand);
        default:
            return 0;
    }
}

static int arm_is_multiple_transfer_name(cdisasm_arm_name_id name_id)
{
    switch (name_id) {
        case CDISASM_ARM_NAME_LDM:
        case CDISASM_ARM_NAME_LDMDA:
        case CDISASM_ARM_NAME_LDMDB:
        case CDISASM_ARM_NAME_LDMEA:
        case CDISASM_ARM_NAME_LDMED:
        case CDISASM_ARM_NAME_LDMFA:
        case CDISASM_ARM_NAME_LDMFD:
        case CDISASM_ARM_NAME_LDMIB:
        case CDISASM_ARM_NAME_STM:
        case CDISASM_ARM_NAME_STMDA:
        case CDISASM_ARM_NAME_STMDB:
        case CDISASM_ARM_NAME_STMEA:
        case CDISASM_ARM_NAME_STMED:
        case CDISASM_ARM_NAME_STMFA:
        case CDISASM_ARM_NAME_STMFD:
        case CDISASM_ARM_NAME_STMIB:
        case CDISASM_ARM_NAME_PUSH:
        case CDISASM_ARM_NAME_POP:
        case CDISASM_ARM_NAME_VLDM:
        case CDISASM_ARM_NAME_VLDMDB:
        case CDISASM_ARM_NAME_VLDMIA:
        case CDISASM_ARM_NAME_VSTM:
        case CDISASM_ARM_NAME_VSTMDB:
        case CDISASM_ARM_NAME_VSTMIA:
        case CDISASM_ARM_NAME_FLDMDBX:
        case CDISASM_ARM_NAME_FLDMIAX:
        case CDISASM_ARM_NAME_FSTMDBX:
        case CDISASM_ARM_NAME_FSTMIAX:
        case CDISASM_ARM_NAME_VPUSH:
        case CDISASM_ARM_NAME_VPOP:
        case CDISASM_ARM_NAME_RFE:
        case CDISASM_ARM_NAME_RFEDA:
        case CDISASM_ARM_NAME_RFEDB:
        case CDISASM_ARM_NAME_RFEEA:
        case CDISASM_ARM_NAME_RFEED:
        case CDISASM_ARM_NAME_RFEFA:
        case CDISASM_ARM_NAME_RFEFD:
        case CDISASM_ARM_NAME_RFEIB:
        case CDISASM_ARM_NAME_SRS:
        case CDISASM_ARM_NAME_SRSDA:
        case CDISASM_ARM_NAME_SRSDB:
        case CDISASM_ARM_NAME_SRSIB:
            return 1;
        default:
            return 0;
    }
}

static int arm_lse_rmw_first_name(
    cdisasm_arm_name_id name_id,
    cdisasm_arm_name_id *first_name)
{
    unsigned family;

    if (name_id >= CDISASM_ARM_NAME_LDADDB
        && name_id <= CDISASM_ARM_NAME_SWPAL) {
        family = (unsigned)(name_id - CDISASM_ARM_NAME_LDADDB) / 12u;
        *first_name = (cdisasm_arm_name_id)(
            CDISASM_ARM_NAME_LDADDB + family * 12u);
        return 1;
    }
    if (name_id >= CDISASM_ARM_NAME_LDSMAXB
        && name_id <= CDISASM_ARM_NAME_LDUMINAL) {
        family = (unsigned)(name_id - CDISASM_ARM_NAME_LDSMAXB) / 12u;
        *first_name = (cdisasm_arm_name_id)(
            CDISASM_ARM_NAME_LDSMAXB + family * 12u);
        return 1;
    }
    return 0;
}

static int arm_is_generated_ldapur(
    const cdisasm_arm_instruction *instruction)
{
    return (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u
        && instruction->name_id >= CDISASM_ARM_NAME_LDAPUR
        && instruction->name_id <= CDISASM_ARM_NAME_LDAPURSW;
}

static int arm_is_generated_stlur(
    const cdisasm_arm_instruction *instruction)
{
    return (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u
        && instruction->name_id >= CDISASM_ARM_NAME_STLUR
        && instruction->name_id <= CDISASM_ARM_NAME_STLURH;
}

static int arm_is_lrcpc3_simd_unscaled(
    const cdisasm_arm_instruction *instruction)
{
    return instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id >= UINT16_C(4907)
        && instruction->form_id <= UINT16_C(4916);
}

static int arm_is_t32_atomic_name(cdisasm_arm_name_id name_id)
{
    return (name_id >= CDISASM_ARM_NAME_LDA
            && name_id <= CDISASM_ARM_NAME_LDAH)
        || (name_id >= CDISASM_ARM_NAME_LDREX
            && name_id <= CDISASM_ARM_NAME_LDREXH)
        || name_id == CDISASM_ARM_NAME_STL
        || (name_id >= CDISASM_ARM_NAME_STLB
            && name_id <= CDISASM_ARM_NAME_STLH)
        || (name_id >= CDISASM_ARM_NAME_STREX
            && name_id <= CDISASM_ARM_NAME_STREXH);
}

static int arm_is_t32_atomic_load(cdisasm_arm_name_id name_id)
{
    return (name_id >= CDISASM_ARM_NAME_LDA
            && name_id <= CDISASM_ARM_NAME_LDAH)
        || (name_id >= CDISASM_ARM_NAME_LDREX
            && name_id <= CDISASM_ARM_NAME_LDREXH);
}

static int arm_lsui_cas_ordering(
    cdisasm_arm_name_id name_id, unsigned *ordering, int *pair)
{
    switch (name_id) {
        case CDISASM_ARM_NAME_CAST: *ordering = 0u; *pair = 0; return 1;
        case CDISASM_ARM_NAME_CASAT: *ordering = 1u; *pair = 0; return 1;
        case CDISASM_ARM_NAME_CASLT: *ordering = 2u; *pair = 0; return 1;
        case CDISASM_ARM_NAME_CASALT: *ordering = 3u; *pair = 0; return 1;
        case CDISASM_ARM_NAME_CASPT: *ordering = 0u; *pair = 1; return 1;
        case CDISASM_ARM_NAME_CASPAT: *ordering = 1u; *pair = 1; return 1;
        case CDISASM_ARM_NAME_CASPLT: *ordering = 2u; *pair = 1; return 1;
        case CDISASM_ARM_NAME_CASPALT: *ordering = 3u; *pair = 1; return 1;
        default: return 0;
    }
}

static int arm_lsui_rmw_ordering(
    cdisasm_arm_name_id name_id, unsigned *ordering)
{
    switch (name_id) {
        case CDISASM_ARM_NAME_LDTADD:
        case CDISASM_ARM_NAME_LDTCLR:
        case CDISASM_ARM_NAME_LDTSET:
        case CDISASM_ARM_NAME_SWPT: *ordering = 0u; return 1;
        case CDISASM_ARM_NAME_LDTADDA:
        case CDISASM_ARM_NAME_LDTCLRA:
        case CDISASM_ARM_NAME_LDTSETA:
        case CDISASM_ARM_NAME_SWPTA: *ordering = 1u; return 1;
        case CDISASM_ARM_NAME_LDTADDL:
        case CDISASM_ARM_NAME_LDTCLRL:
        case CDISASM_ARM_NAME_LDTSETL:
        case CDISASM_ARM_NAME_SWPTL: *ordering = 2u; return 1;
        case CDISASM_ARM_NAME_LDTADDAL:
        case CDISASM_ARM_NAME_LDTCLRAL:
        case CDISASM_ARM_NAME_LDTSETAL:
        case CDISASM_ARM_NAME_SWPTAL: *ordering = 3u; return 1;
        default: return 0;
    }
}

static uint32_t arm_expected_atomic_flags(
    const cdisasm_arm_instruction *instruction)
{
    const uint32_t atomic = CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC;
    const uint32_t exclusive = CDISASM_ARM_INSTRUCTION_FLAG_EXCLUSIVE;
    cdisasm_arm_name_id name_id = instruction->name_id;
    cdisasm_arm_name_id first_name;
    unsigned ordering;
    int lsui_pair;

    if (instruction->form_id >= UINT16_C(4725)
        && instruction->form_id <= UINT16_C(4732)) {
        unsigned rcw_order = instruction->form_id - UINT16_C(4725);

        return atomic
            | ((rcw_order & 1u) != 0u
                ? CDISASM_ARM_INSTRUCTION_FLAG_RELEASE : 0u)
            | ((rcw_order & 2u) != 0u
                ? CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE : 0u);
    }

    if (arm_is_lrcpc3_simd_unscaled(instruction)) {
        return atomic
            | (((instruction->form_id - UINT16_C(4907)) & 1u) != 0u
                ? CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
                : CDISASM_ARM_INSTRUCTION_FLAG_RELEASE);
    }

    if (arm_lsui_rmw_ordering(name_id, &ordering)) {
        int result_is_zero_register = instruction->operand_count > 1u
            && instruction->operand[1].type == CDISASM_OPERAND_REGISTER
            && (instruction->operand[1].reg == CDISASM_ARM_REG_WZR
                || instruction->operand[1].reg == CDISASM_ARM_REG_XZR);
        return atomic
            | ((ordering & 1u) != 0u && !result_is_zero_register
                ? CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE : 0u)
            | ((ordering & 2u) != 0u
                ? CDISASM_ARM_INSTRUCTION_FLAG_RELEASE : 0u);
    }

    if (arm_lsui_cas_ordering(name_id, &ordering, &lsui_pair)) {
        (void)lsui_pair;
        return atomic
            | ((ordering & 1u) != 0u
                ? CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE : 0u)
            | ((ordering & 2u) != 0u
                ? CDISASM_ARM_INSTRUCTION_FLAG_RELEASE : 0u);
    }

    if (arm_is_generated_ldapur(instruction)) {
        return atomic | CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE;
    }
    if (arm_is_generated_stlur(instruction)) {
        return atomic | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE;
    }

    if (name_id >= CDISASM_ARM_NAME_CASB
        && name_id <= CDISASM_ARM_NAME_CASAL) {
        ordering = (unsigned)(name_id - CDISASM_ARM_NAME_CASB) / 3u;
        return atomic
            | ((ordering & 1u) != 0u
                ? CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE : 0u)
            | ((ordering & 2u) != 0u
                ? CDISASM_ARM_INSTRUCTION_FLAG_RELEASE : 0u);
    }
    if (name_id >= CDISASM_ARM_NAME_CASP
        && name_id <= CDISASM_ARM_NAME_CASPAL) {
        ordering = (unsigned)(name_id - CDISASM_ARM_NAME_CASP);
        return atomic
            | ((ordering & 1u) != 0u
                ? CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE : 0u)
            | ((ordering & 2u) != 0u
                ? CDISASM_ARM_INSTRUCTION_FLAG_RELEASE : 0u);
    }
    if (arm_lse_rmw_first_name(name_id, &first_name)) {
        int result_is_zero_register = instruction->operand_count > 1u
            && instruction->operand[1].type == CDISASM_OPERAND_REGISTER
            && (instruction->operand[1].reg == CDISASM_ARM_REG_WZR
                || instruction->operand[1].reg == CDISASM_ARM_REG_XZR);

        ordering = (unsigned)(name_id - first_name) / 3u;
        return atomic
            | ((ordering & 1u) != 0u && !result_is_zero_register
                ? CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE : 0u)
            | ((ordering & 2u) != 0u
                ? CDISASM_ARM_INSTRUCTION_FLAG_RELEASE : 0u);
    }
    if (name_id >= CDISASM_ARM_NAME_LDCLRP
        && name_id <= CDISASM_ARM_NAME_SWPPAL) {
        ordering = (unsigned)(name_id - CDISASM_ARM_NAME_LDCLRP) % 4u;
        return atomic | CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC_PAIR
            | ((ordering & 1u) != 0u
                ? CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE : 0u)
            | ((ordering & 2u) != 0u
                ? CDISASM_ARM_INSTRUCTION_FLAG_RELEASE : 0u);
    }

    switch (name_id) {
        case CDISASM_ARM_NAME_LDREX:
        case CDISASM_ARM_NAME_LDREXB:
        case CDISASM_ARM_NAME_LDREXD:
        case CDISASM_ARM_NAME_LDREXH:
        case CDISASM_ARM_NAME_STREX:
        case CDISASM_ARM_NAME_STREXB:
        case CDISASM_ARM_NAME_STREXD:
        case CDISASM_ARM_NAME_STREXH:
            return atomic | exclusive;
        case CDISASM_ARM_NAME_LDA:
        case CDISASM_ARM_NAME_LDAB:
        case CDISASM_ARM_NAME_LDAH:
            return atomic | CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE;
        case CDISASM_ARM_NAME_LDAEX:
        case CDISASM_ARM_NAME_LDAEXB:
        case CDISASM_ARM_NAME_LDAEXD:
        case CDISASM_ARM_NAME_LDAEXH:
            return atomic | exclusive
                | CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE;
        case CDISASM_ARM_NAME_STL:
        case CDISASM_ARM_NAME_STLB:
        case CDISASM_ARM_NAME_STLH:
            return atomic | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE;
        case CDISASM_ARM_NAME_STLEX:
        case CDISASM_ARM_NAME_STLEXB:
        case CDISASM_ARM_NAME_STLEXD:
        case CDISASM_ARM_NAME_STLEXH:
            return atomic | exclusive
                | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE;
        case CDISASM_ARM_NAME_LDARB:
        case CDISASM_ARM_NAME_LDARH:
        case CDISASM_ARM_NAME_LDAR:
            return atomic | CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE;
        case CDISASM_ARM_NAME_STLRB:
        case CDISASM_ARM_NAME_STLRH:
        case CDISASM_ARM_NAME_STLR:
            return atomic | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE;
        case CDISASM_ARM_NAME_LDAXRB:
        case CDISASM_ARM_NAME_LDAXRH:
        case CDISASM_ARM_NAME_LDAXR:
        case CDISASM_ARM_NAME_LDAXP:
            return atomic | exclusive
                | CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE;
        case CDISASM_ARM_NAME_STLXRB:
        case CDISASM_ARM_NAME_STLXRH:
        case CDISASM_ARM_NAME_STLXR:
        case CDISASM_ARM_NAME_STLXP:
            return atomic | exclusive
                | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE;
        case CDISASM_ARM_NAME_LDXRB:
        case CDISASM_ARM_NAME_LDXRH:
        case CDISASM_ARM_NAME_LDXR:
        case CDISASM_ARM_NAME_LDXP:
        case CDISASM_ARM_NAME_LDTXR:
        case CDISASM_ARM_NAME_STTXR:
        case CDISASM_ARM_NAME_STXRB:
        case CDISASM_ARM_NAME_STXRH:
        case CDISASM_ARM_NAME_STXR:
        case CDISASM_ARM_NAME_STXP:
            return atomic | exclusive;
        case CDISASM_ARM_NAME_LDATXR:
            return atomic | exclusive
                | CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE;
        case CDISASM_ARM_NAME_STLTXR:
            return atomic | exclusive
                | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE;
        case CDISASM_ARM_NAME_LDLARB:
        case CDISASM_ARM_NAME_LDLARH:
        case CDISASM_ARM_NAME_LDLAR:
        case CDISASM_ARM_NAME_LDAPRB:
        case CDISASM_ARM_NAME_LDAPRH:
        case CDISASM_ARM_NAME_LDAPR:
            return atomic | CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE;
        case CDISASM_ARM_NAME_STLLRB:
        case CDISASM_ARM_NAME_STLLRH:
        case CDISASM_ARM_NAME_STLLR:
            return atomic | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE;
        case CDISASM_ARM_NAME_LDIAPP:
            return atomic | CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC_PAIR
                | CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE;
        case CDISASM_ARM_NAME_STILP:
            return atomic | CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC_PAIR
                | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE;
        default:
            return CDISASM_ARM_INSTRUCTION_FLAG_NONE;
    }
}

static cdisasm_operand_access arm_expected_atomic_memory_access(
    cdisasm_arm_name_id name_id)
{
    unsigned lsui_ordering;
    int lsui_pair;

    if (arm_lsui_rmw_ordering(name_id, &lsui_ordering)) {
        return CDISASM_OPERAND_ACCESS_READ_WRITE;
    }

    if ((name_id >= CDISASM_ARM_NAME_RCWCAS
            && name_id <= CDISASM_ARM_NAME_RCWCASL)
        || (name_id >= CDISASM_ARM_NAME_RCWSCAS
            && name_id <= CDISASM_ARM_NAME_RCWSCASL)) {
        return CDISASM_OPERAND_ACCESS_READ_WRITE;
    }

    if (arm_lsui_cas_ordering(name_id, &lsui_ordering, &lsui_pair)) {
        (void)lsui_ordering;
        (void)lsui_pair;
        return CDISASM_OPERAND_ACCESS_READ_WRITE;
    }
    if ((name_id >= CDISASM_ARM_NAME_CASB
            && name_id <= CDISASM_ARM_NAME_CASPAL)
        || arm_lse_rmw_first_name(name_id, &name_id)
        || (name_id >= CDISASM_ARM_NAME_LDCLRP
            && name_id <= CDISASM_ARM_NAME_SWPPAL)) {
        return CDISASM_OPERAND_ACCESS_READ_WRITE;
    }
    switch (name_id) {
        case CDISASM_ARM_NAME_LDA:
        case CDISASM_ARM_NAME_LDAB:
        case CDISASM_ARM_NAME_LDAEX:
        case CDISASM_ARM_NAME_LDAEXB:
        case CDISASM_ARM_NAME_LDAEXD:
        case CDISASM_ARM_NAME_LDAEXH:
        case CDISASM_ARM_NAME_LDAH:
        case CDISASM_ARM_NAME_LDREX:
        case CDISASM_ARM_NAME_LDREXB:
        case CDISASM_ARM_NAME_LDREXD:
        case CDISASM_ARM_NAME_LDREXH:
        case CDISASM_ARM_NAME_LDARB:
        case CDISASM_ARM_NAME_LDARH:
        case CDISASM_ARM_NAME_LDAR:
        case CDISASM_ARM_NAME_LDAXRB:
        case CDISASM_ARM_NAME_LDAXRH:
        case CDISASM_ARM_NAME_LDAXR:
        case CDISASM_ARM_NAME_LDXRB:
        case CDISASM_ARM_NAME_LDXRH:
        case CDISASM_ARM_NAME_LDXR:
        case CDISASM_ARM_NAME_LDTXR:
        case CDISASM_ARM_NAME_LDATXR:
        case CDISASM_ARM_NAME_LDXP:
        case CDISASM_ARM_NAME_LDAXP:
        case CDISASM_ARM_NAME_LDLARB:
        case CDISASM_ARM_NAME_LDLARH:
        case CDISASM_ARM_NAME_LDLAR:
        case CDISASM_ARM_NAME_LDAPRB:
        case CDISASM_ARM_NAME_LDAPRH:
        case CDISASM_ARM_NAME_LDAPR:
        case CDISASM_ARM_NAME_LDAPUR:
        case CDISASM_ARM_NAME_LDAPURB:
        case CDISASM_ARM_NAME_LDAPURH:
        case CDISASM_ARM_NAME_LDAPURSB:
        case CDISASM_ARM_NAME_LDAPURSH:
        case CDISASM_ARM_NAME_LDAPURSW:
        case CDISASM_ARM_NAME_LDIAPP:
            return CDISASM_OPERAND_ACCESS_READ;
        case CDISASM_ARM_NAME_STILP:
            return CDISASM_OPERAND_ACCESS_WRITE;
        default:
            return CDISASM_OPERAND_ACCESS_WRITE;
    }
}

static int arm_atomic_register_matches_size(
    const cdisasm_arm_operand *operand,
    uint8_t size,
    cdisasm_operand_access access)
{
    int valid_register = size == 8u
        ? ((operand->reg >= CDISASM_ARM_REG_X0
                && operand->reg <= CDISASM_ARM_REG_X30)
            || operand->reg == CDISASM_ARM_REG_XZR)
        : ((operand->reg >= CDISASM_ARM_REG_W0
                && operand->reg <= CDISASM_ARM_REG_W30)
            || operand->reg == CDISASM_ARM_REG_WZR);

    return operand->type == CDISASM_OPERAND_REGISTER
        && operand->size == size
        && operand->access == access
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u
        && operand->extend_type == CDISASM_ARM_EXTEND_NONE
        && operand->scale == 0u
        && valid_register;
}

static int arm_atomic_pair_matches_size(
    const cdisasm_arm_operand *operand,
    uint8_t size,
    cdisasm_operand_access access)
{
    return operand->type == CDISASM_ARM_OPERAND_REGISTER_PAIR
        && operand->size == size
        && operand->access == access;
}

static int arm_atomic_memory_matches_size(
    const cdisasm_arm_operand *operand,
    uint8_t size,
    cdisasm_operand_access access)
{
    return operand->type == CDISASM_OPERAND_MEMORY
        && operand->size == size
        && operand->access == access
        && operand->base_reg >= CDISASM_ARM_REG_X0
        && operand->base_reg <= CDISASM_ARM_REG_SP
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->imm == 0u
        && operand->flags == CDISASM_OPERAND_FLAG_NONE;
}

static int arm_atomic_name_matches_size(
    cdisasm_arm_name_id name_id,
    cdisasm_arm_name_id first_name,
    uint8_t size)
{
    unsigned width = (unsigned)(name_id - first_name) % 3u;

    return (width == 0u && size == 1u)
        || (width == 1u && size == 2u)
        || (width == 2u && (size == 4u || size == 8u));
}

static int arm_valid_extra_atomic_schema(
    const cdisasm_arm_instruction *instruction)
{
    cdisasm_arm_name_id name_id = instruction->name_id;
    cdisasm_arm_name_id lse_first_name;
    const cdisasm_arm_operand *first = &instruction->operand[0];
    const cdisasm_arm_operand *second = &instruction->operand[1];
    const cdisasm_arm_operand *memory = &instruction->operand[2];
    uint8_t size = first->size;
    int is_lrcpc3_simd = arm_is_lrcpc3_simd_unscaled(instruction);
    int is_generated_ldapur = arm_is_generated_ldapur(instruction);
    int is_generated_stlur = arm_is_generated_stlur(instruction);
    int is_t32_atomic = instruction->isa_id == CDISASM_ARM_ISA_T32
        && arm_is_t32_atomic_name(name_id);
    unsigned lsui_ordering;
    int lsui_pair;
    int is_lsui_cas = arm_lsui_cas_ordering(
        name_id, &lsui_ordering, &lsui_pair);
    int is_lsui_rmw = arm_lsui_rmw_ordering(name_id, &lsui_ordering);
    int is_extra_atomic = (name_id >= CDISASM_ARM_NAME_CASB
            && name_id <= CDISASM_ARM_NAME_CASPAL)
        || (name_id >= CDISASM_ARM_NAME_LDADDB
            && name_id <= CDISASM_ARM_NAME_LDAPR)
        || (name_id >= CDISASM_ARM_NAME_LDSMAXB
            && name_id <= CDISASM_ARM_NAME_LDUMINAL)
        || (name_id >= CDISASM_ARM_NAME_LDCLRP
            && name_id <= CDISASM_ARM_NAME_STILP)
        || name_id == CDISASM_ARM_NAME_STTXR
        || name_id == CDISASM_ARM_NAME_STLTXR
        || name_id == CDISASM_ARM_NAME_LDTXR
        || name_id == CDISASM_ARM_NAME_LDATXR
        || is_lsui_cas
        || is_lsui_rmw
        || is_generated_ldapur
        || is_generated_stlur
        || is_lrcpc3_simd
        || (instruction->form_id >= UINT16_C(4725)
            && instruction->form_id <= UINT16_C(4732))
        || is_t32_atomic;

    if (!is_extra_atomic) {
        return 1;
    }
    if (is_lrcpc3_simd) {
        static const uint8_t sizes[5] = { 1u, 16u, 2u, 4u, 8u };
        static const cdisasm_arm_reg_id register_bases[5] = {
            CDISASM_ARM_REG_B0, CDISASM_ARM_REG_V0, CDISASM_ARM_REG_H0,
            CDISASM_ARM_REG_S0, CDISASM_ARM_REG_D0
        };
        static const uint32_t store_values[5] = {
            UINT32_C(0x1d000800), UINT32_C(0x1d800800),
            UINT32_C(0x5d000800), UINT32_C(0x9d000800),
            UINT32_C(0xdd000800)
        };
        unsigned pair = (unsigned)(instruction->form_id - UINT16_C(4907)) / 2u;
        int load = ((instruction->form_id - UINT16_C(4907)) & 1u) != 0u;
        uint8_t expected_size = sizes[pair];
        int64_t displacement = (int64_t)((instruction->raw_instruction >> 12)
            & UINT32_C(0x1ff));
        uint8_t memory_flags;

        if ((displacement & INT64_C(0x100)) != 0) {
            displacement -= INT64_C(0x200);
        }
        memory_flags = displacement == 0 ? CDISASM_OPERAND_FLAG_NONE
            : (uint8_t)(CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
                | (displacement < 0 ? CDISASM_OPERAND_FLAG_SIGNED : 0u));
        return pair < 5u
            && instruction->name_id == (load
                ? CDISASM_ARM_NAME_LDAPUR : CDISASM_ARM_NAME_STLUR)
            && (instruction->raw_instruction & UINT32_C(0xffe00c00))
                == (store_values[pair]
                    | (load ? UINT32_C(0x00400000) : UINT32_C(0)))
            && instruction->instruction_flags
                == (arm_expected_atomic_flags(instruction)
                    | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
                    | CDISASM_ARM_INSTRUCTION_FLAG_SIMD)
            && instruction->operand_count == 2u
            && first->type == CDISASM_OPERAND_REGISTER
            && first->reg == (cdisasm_arm_reg_id)(register_bases[pair]
                + (instruction->raw_instruction & 31u))
            && first->size == expected_size
            && first->access == (load ? CDISASM_OPERAND_ACCESS_WRITE
                                      : CDISASM_OPERAND_ACCESS_READ)
            && second->type == CDISASM_OPERAND_MEMORY
            && second->base_reg == ((instruction->raw_instruction >> 5 & 31u)
                    == 31u
                ? CDISASM_ARM_REG_SP
                : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0
                    + ((instruction->raw_instruction >> 5) & 31u)))
            && second->index_reg == CDISASM_ARM_REG_NONE
            && second->size == expected_size
            && second->access == (load ? CDISASM_OPERAND_ACCESS_READ
                                       : CDISASM_OPERAND_ACCESS_WRITE)
            && (int64_t)second->imm == displacement
            && second->flags == memory_flags;
    }
    if (is_t32_atomic) {
        uint32_t flags = arm_expected_atomic_flags(instruction);
        int load = arm_is_t32_atomic_load(name_id);
        int exclusive = (flags & CDISASM_ARM_INSTRUCTION_FLAG_EXCLUSIVE) != 0u;
        int pair = name_id == CDISASM_ARM_NAME_LDREXD
            || name_id == CDISASM_ARM_NAME_LDAEXD
            || name_id == CDISASM_ARM_NAME_STREXD
            || name_id == CDISASM_ARM_NAME_STLEXD;
        unsigned data_index = !load && exclusive ? 1u : 0u;
        unsigned memory_index = data_index + (pair ? 2u : 1u);
        uint8_t data_size = name_id == CDISASM_ARM_NAME_LDREXB
                || name_id == CDISASM_ARM_NAME_LDAEXB
                || name_id == CDISASM_ARM_NAME_STREXB
                || name_id == CDISASM_ARM_NAME_STLEXB
                || name_id == CDISASM_ARM_NAME_LDAB
                || name_id == CDISASM_ARM_NAME_STLB
            ? 1u : name_id == CDISASM_ARM_NAME_LDREXH
                || name_id == CDISASM_ARM_NAME_LDAEXH
                || name_id == CDISASM_ARM_NAME_STREXH
                || name_id == CDISASM_ARM_NAME_STLEXH
                || name_id == CDISASM_ARM_NAME_LDAH
                || name_id == CDISASM_ARM_NAME_STLH ? 2u : 4u;
        const cdisasm_arm_operand *data = &instruction->operand[data_index];
        const cdisasm_arm_operand *atomic_memory =
            &instruction->operand[memory_index];
        unsigned operand_index;

        if (instruction->instruction_flags != flags
            || instruction->operand_count != memory_index + 1u) {
            return 0;
        }
        if (!load && exclusive) {
            if (first->type != CDISASM_OPERAND_REGISTER
                || first->reg < CDISASM_ARM_REG_R0
                || first->reg > CDISASM_ARM_REG_R12
                || first->size != 4u
                || first->access != CDISASM_OPERAND_ACCESS_WRITE) {
                return 0;
            }
        }
        for (operand_index = data_index;
             operand_index < memory_index; ++operand_index) {
            data = &instruction->operand[operand_index];
            if (data->type != CDISASM_OPERAND_REGISTER
                || data->reg < CDISASM_ARM_REG_R0
                || data->reg > CDISASM_ARM_REG_LR
                || data->size != (pair ? 4u : data_size)
                || data->access != (load ? CDISASM_OPERAND_ACCESS_WRITE
                                        : CDISASM_OPERAND_ACCESS_READ)) {
                return 0;
            }
        }
        return atomic_memory->type == CDISASM_OPERAND_MEMORY
            && atomic_memory->base_reg >= CDISASM_ARM_REG_R0
            && atomic_memory->base_reg <= CDISASM_ARM_REG_LR
            && atomic_memory->index_reg == CDISASM_ARM_REG_NONE
            && atomic_memory->size == (pair ? 8u : data_size)
            && atomic_memory->access == (load ? CDISASM_OPERAND_ACCESS_READ
                                             : CDISASM_OPERAND_ACCESS_WRITE)
            && (atomic_memory->imm == 0u
                || ((name_id == CDISASM_ARM_NAME_LDREX
                        || name_id == CDISASM_ARM_NAME_STREX)
                    && atomic_memory->imm <= 1020u
                    && (atomic_memory->imm & 3u) == 0u));
    }
    if (is_generated_ldapur) {
        uint32_t expected_flags = arm_expected_atomic_flags(instruction)
            | CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        uint8_t memory_size;

        if (name_id == CDISASM_ARM_NAME_LDAPURB) {
            expected_flags |= CDISASM_ARM_INSTRUCTION_FLAG_BYTE;
            memory_size = 1u;
        } else if (name_id == CDISASM_ARM_NAME_LDAPURSB) {
            memory_size = 1u;
        } else if (name_id == CDISASM_ARM_NAME_LDAPURH
            || name_id == CDISASM_ARM_NAME_LDAPURSH) {
            memory_size = 2u;
        } else if (name_id == CDISASM_ARM_NAME_LDAPURSW) {
            memory_size = 4u;
        } else {
            memory_size = size;
        }
        return instruction->instruction_flags == expected_flags
            && instruction->operand_count == 2u
            && (size == 4u || size == 8u)
            && arm_atomic_register_matches_size(
                first, size, CDISASM_OPERAND_ACCESS_WRITE)
            && second->type == CDISASM_OPERAND_MEMORY
            && second->size == memory_size
            && second->access == CDISASM_OPERAND_ACCESS_READ
            && second->base_reg >= CDISASM_ARM_REG_X0
            && second->base_reg <= CDISASM_ARM_REG_SP
            && second->index_reg == CDISASM_ARM_REG_NONE;
    }
    if (is_generated_stlur) {
        uint32_t expected_flags = arm_expected_atomic_flags(instruction)
            | CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        uint8_t memory_size;

        if (name_id == CDISASM_ARM_NAME_STLURB) {
            expected_flags |= CDISASM_ARM_INSTRUCTION_FLAG_BYTE;
            memory_size = 1u;
        } else if (name_id == CDISASM_ARM_NAME_STLURH) {
            memory_size = 2u;
        } else {
            memory_size = size;
        }
        return instruction->instruction_flags == expected_flags
            && instruction->operand_count == 2u
            && (size == 4u || size == 8u)
            && arm_atomic_register_matches_size(
                first, size, CDISASM_OPERAND_ACCESS_READ)
            && second->type == CDISASM_OPERAND_MEMORY
            && second->size == memory_size
            && second->access == CDISASM_OPERAND_ACCESS_WRITE
            && second->base_reg >= CDISASM_ARM_REG_X0
            && second->base_reg <= CDISASM_ARM_REG_SP
            && second->index_reg == CDISASM_ARM_REG_NONE;
    }
    if (instruction->isa_id == CDISASM_ARM_ISA_A64
        && ((instruction->form_id >= UINT16_C(4867)
                && instruction->form_id <= UINT16_C(4872))
            || (instruction->form_id >= UINT16_C(4874)
                && instruction->form_id <= UINT16_C(4875))
            || (instruction->form_id >= UINT16_C(4878)
                && instruction->form_id <= UINT16_C(4881)))) {
        int single = instruction->form_id >= UINT16_C(4878);
        int load = instruction->name_id == CDISASM_ARM_NAME_LDIAPP
            || instruction->name_id == CDISASM_ARM_NAME_LDAPR;
        int writeback = instruction->form_id == UINT16_C(4867)
            || instruction->form_id == UINT16_C(4869)
            || instruction->form_id == UINT16_C(4871)
            || instruction->form_id == UINT16_C(4874) || single;
        const cdisasm_arm_operand *atomic_memory = single ? second : memory;
        uint32_t expected_flags = arm_expected_atomic_flags(instruction)
            | (single ? 0u : CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC_PAIR)
            | (writeback
                ? CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
                    | (load ? CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
                            : CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX)
                : 0u);
        int64_t expected_displacement = writeback
            ? (load ? 1 : -1) * (single ? 1 : 2) * size : 0;

        return instruction->instruction_flags == expected_flags
            && instruction->operand_count == (single ? 2u : 3u)
            && (size == 4u || size == 8u)
            && arm_atomic_register_matches_size(
                first, size, load ? CDISASM_OPERAND_ACCESS_WRITE
                                  : CDISASM_OPERAND_ACCESS_READ)
            && (single || arm_atomic_register_matches_size(
                second, size, load ? CDISASM_OPERAND_ACCESS_WRITE
                                   : CDISASM_OPERAND_ACCESS_READ))
            && atomic_memory->type == CDISASM_OPERAND_MEMORY
            && atomic_memory->size == (uint8_t)((single ? 1u : 2u) * size)
            && atomic_memory->access == (load
                ? CDISASM_OPERAND_ACCESS_READ
                : CDISASM_OPERAND_ACCESS_WRITE)
            && atomic_memory->base_reg >= CDISASM_ARM_REG_X0
            && atomic_memory->base_reg <= CDISASM_ARM_REG_SP
            && atomic_memory->index_reg == CDISASM_ARM_REG_NONE
            && (int64_t)atomic_memory->imm == expected_displacement
            && atomic_memory->flags == (uint8_t)(writeback
                ? CDISASM_ARM_OPERAND_FLAG_WRITEBACK
                    | CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
                    | (expected_displacement < 0
                        ? CDISASM_OPERAND_FLAG_SIGNED : 0u)
                : CDISASM_OPERAND_FLAG_NONE);
    }
    if (instruction->instruction_flags
        != arm_expected_atomic_flags(instruction)) {
        if (!(instruction->form_id >= UINT16_C(4725)
                && instruction->form_id <= UINT16_C(4732)
            && instruction->instruction_flags
                == (arm_expected_atomic_flags(instruction)
                    | CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK))) {
            return 0;
        }
    }

    if (instruction->form_id >= UINT16_C(4725)
        && instruction->form_id <= UINT16_C(4732)) {
        static const cdisasm_arm_name_id rcw_names[8] = {
            CDISASM_ARM_NAME_RCWCAS, CDISASM_ARM_NAME_RCWCASL,
            CDISASM_ARM_NAME_RCWCASA, CDISASM_ARM_NAME_RCWCASAL,
            CDISASM_ARM_NAME_RCWSCAS, CDISASM_ARM_NAME_RCWSCASL,
            CDISASM_ARM_NAME_RCWSCASA, CDISASM_ARM_NAME_RCWSCASAL
        };
        unsigned rcw_index = instruction->form_id - UINT16_C(4725);
        uint32_t rcw_word = instruction->raw_instruction;

        return instruction->isa_id == CDISASM_ARM_ISA_A64
            && instruction->name_id == rcw_names[rcw_index]
            && (rcw_word & UINT32_C(0xffe0fc00))
                == (UINT32_C(0x19200800)
                    | ((rcw_index >> 2) << 30)
                    | ((rcw_index & 3u) << 22))
            && instruction->operand_count == 3u
            && arm_atomic_register_matches_size(
                first, 8u, CDISASM_OPERAND_ACCESS_READ_WRITE)
            && arm_atomic_register_matches_size(
                second, 8u, CDISASM_OPERAND_ACCESS_READ)
            && arm_atomic_memory_matches_size(
                memory, 8u, CDISASM_OPERAND_ACCESS_READ_WRITE)
            && first->reg == (((rcw_word >> 16) & 31u) == 31u
                ? CDISASM_ARM_REG_XZR
                : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0
                    + ((rcw_word >> 16) & 31u)))
            && second->reg == ((rcw_word & 31u) == 31u
                ? CDISASM_ARM_REG_XZR
                : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0
                    + (rcw_word & 31u)))
            && memory->base_reg == (((rcw_word >> 5) & 31u) == 31u
                ? CDISASM_ARM_REG_SP
                : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0
                    + ((rcw_word >> 5) & 31u)));
    }

    if (name_id >= CDISASM_ARM_NAME_CASB
        && name_id <= CDISASM_ARM_NAME_CASAL) {
        return instruction->operand_count == 3u
            && arm_atomic_name_matches_size(
                name_id, CDISASM_ARM_NAME_CASB, size)
            && arm_atomic_register_matches_size(
                first, size, CDISASM_OPERAND_ACCESS_READ_WRITE)
            && arm_atomic_register_matches_size(
                second, size, CDISASM_OPERAND_ACCESS_READ)
            && arm_atomic_memory_matches_size(
                memory, size, CDISASM_OPERAND_ACCESS_READ_WRITE);
    }
    if (name_id >= CDISASM_ARM_NAME_CASP
        && name_id <= CDISASM_ARM_NAME_CASPAL) {
        return instruction->operand_count == 3u
            && (size == 4u || size == 8u)
            && arm_atomic_pair_matches_size(
                first, size, CDISASM_OPERAND_ACCESS_READ_WRITE)
            && arm_atomic_pair_matches_size(
                second, size, CDISASM_OPERAND_ACCESS_READ)
            && arm_atomic_memory_matches_size(
                memory, size, CDISASM_OPERAND_ACCESS_READ_WRITE);
    }
    if (arm_lse_rmw_first_name(name_id, &lse_first_name)) {
        return instruction->operand_count == 3u
            && arm_atomic_name_matches_size(
                name_id, lse_first_name, size)
            && arm_atomic_register_matches_size(
                first, size, CDISASM_OPERAND_ACCESS_READ)
            && arm_atomic_register_matches_size(
                second, size, CDISASM_OPERAND_ACCESS_WRITE)
            && arm_atomic_memory_matches_size(
                memory, size, CDISASM_OPERAND_ACCESS_READ_WRITE);
    }
    if (name_id >= CDISASM_ARM_NAME_LDCLRP
        && name_id <= CDISASM_ARM_NAME_SWPPAL) {
        return instruction->operand_count == 3u
            && first->type == CDISASM_ARM_OPERAND_REGISTER_PAIR_BASE
            && first->size == 16u
            && first->access == CDISASM_OPERAND_ACCESS_READ
            && second->type == CDISASM_ARM_OPERAND_REGISTER_PAIR_BASE
            && second->size == 16u
            && second->access == CDISASM_OPERAND_ACCESS_WRITE
            && arm_atomic_memory_matches_size(
                memory, 16u, CDISASM_OPERAND_ACCESS_READ_WRITE);
    }
    if (name_id == CDISASM_ARM_NAME_LDIAPP
        || name_id == CDISASM_ARM_NAME_STILP) {
        cdisasm_operand_access register_access =
            name_id == CDISASM_ARM_NAME_LDIAPP
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ;
        cdisasm_operand_access memory_access =
            name_id == CDISASM_ARM_NAME_LDIAPP
                ? CDISASM_OPERAND_ACCESS_READ
                : CDISASM_OPERAND_ACCESS_WRITE;

        return instruction->operand_count == 3u
            && arm_atomic_register_matches_size(
                first, size, register_access)
            && arm_atomic_register_matches_size(
                second, size, register_access)
            && memory->type == CDISASM_OPERAND_MEMORY
            && memory->size == (uint8_t)(2u * size)
            && memory->access == memory_access
            && memory->base_reg >= CDISASM_ARM_REG_X0
            && memory->base_reg <= CDISASM_ARM_REG_SP
            && memory->index_reg == CDISASM_ARM_REG_NONE
            && memory->flags == CDISASM_OPERAND_FLAG_NONE
            && memory->imm == 0u;
    }
    if (name_id >= CDISASM_ARM_NAME_LDLARB
        && name_id <= CDISASM_ARM_NAME_STLLR) {
        int is_load = name_id <= CDISASM_ARM_NAME_LDLAR;
        cdisasm_arm_name_id first_name = is_load
            ? CDISASM_ARM_NAME_LDLARB : CDISASM_ARM_NAME_STLLRB;

        return instruction->operand_count == 2u
            && arm_atomic_name_matches_size(name_id, first_name, size)
            && arm_atomic_register_matches_size(
                first, size, is_load ? CDISASM_OPERAND_ACCESS_WRITE
                                     : CDISASM_OPERAND_ACCESS_READ)
            && arm_atomic_memory_matches_size(
                second, size, is_load ? CDISASM_OPERAND_ACCESS_READ
                                      : CDISASM_OPERAND_ACCESS_WRITE);
    }
    if (name_id >= CDISASM_ARM_NAME_LDAPRB
        && name_id <= CDISASM_ARM_NAME_LDAPR) {
        return instruction->operand_count == 2u
            && arm_atomic_name_matches_size(
                name_id, CDISASM_ARM_NAME_LDAPRB, size)
            && arm_atomic_register_matches_size(
                first, size, CDISASM_OPERAND_ACCESS_WRITE)
            && arm_atomic_memory_matches_size(
                second, size, CDISASM_OPERAND_ACCESS_READ);
    }
    if (name_id == CDISASM_ARM_NAME_LDTXR
        || name_id == CDISASM_ARM_NAME_LDATXR) {
        return instruction->operand_count == 2u
            && (size == 4u || size == 8u)
            && arm_atomic_register_matches_size(
                first, size, CDISASM_OPERAND_ACCESS_WRITE)
            && arm_atomic_memory_matches_size(
                second, size, CDISASM_OPERAND_ACCESS_READ);
    }
    if (name_id == CDISASM_ARM_NAME_STTXR
        || name_id == CDISASM_ARM_NAME_STLTXR) {
        return instruction->operand_count == 3u
            && (second->size == 4u || second->size == 8u)
            && arm_atomic_register_matches_size(
                first, 4u, CDISASM_OPERAND_ACCESS_WRITE)
            && arm_atomic_register_matches_size(
                second, second->size, CDISASM_OPERAND_ACCESS_READ)
            && arm_atomic_memory_matches_size(
                memory, second->size, CDISASM_OPERAND_ACCESS_WRITE);
    }
    if (is_lsui_cas) {
        (void)lsui_ordering;
        return instruction->operand_count == 3u
            && first->size == 8u
            && (lsui_pair
                ? arm_atomic_pair_matches_size(first, 8u,
                    CDISASM_OPERAND_ACCESS_READ_WRITE)
                    && arm_atomic_pair_matches_size(second, 8u,
                        CDISASM_OPERAND_ACCESS_READ)
                : arm_atomic_register_matches_size(first, 8u,
                    CDISASM_OPERAND_ACCESS_READ_WRITE)
                    && arm_atomic_register_matches_size(second, 8u,
                        CDISASM_OPERAND_ACCESS_READ))
            && arm_atomic_memory_matches_size(
                memory, 8u, CDISASM_OPERAND_ACCESS_READ_WRITE);
    }
    if (is_lsui_rmw) {
        return instruction->operand_count == 3u
            && (size == 4u || size == 8u)
            && arm_atomic_register_matches_size(
                first, size, CDISASM_OPERAND_ACCESS_READ)
            && arm_atomic_register_matches_size(
                second, size, CDISASM_OPERAND_ACCESS_WRITE)
            && arm_atomic_memory_matches_size(
                memory, size, CDISASM_OPERAND_ACCESS_READ_WRITE);
    }
    return 0;
}

static int arm_valid_a64_udf_schema(
    const cdisasm_arm_instruction *instruction)
{
    int raw_is_udf = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->raw_instruction & UINT32_C(0xffff0000)) == 0u;
    int form_is_udf = instruction->form_id == UINT16_C(4387);
    int name_is_udf = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->name_id == CDISASM_ARM_NAME_UDF;
    const cdisasm_arm_operand *immediate;

    if (!raw_is_udf && !form_is_udf && !name_is_udf) {
        return 1;
    }
    if (!raw_is_udf || !form_is_udf || !name_is_udf
        || instruction->opcode_groups != CDISASM_GROUP_INTERRUPT
        || instruction->instruction_flags != 0u
        || instruction->operand_count != 1u) {
        return 0;
    }
    immediate = &instruction->operand[0];
    return immediate->type == CDISASM_OPERAND_IMMEDIATE
        && immediate->imm
            == (instruction->raw_instruction & UINT32_C(0xffff))
        && immediate->size == 2u
        && immediate->flags == CDISASM_OPERAND_FLAG_NONE
        && immediate->shift_type == CDISASM_ARM_SHIFT_NONE
        && immediate->shift_amount == 0u
        && immediate->access == CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_wfxt_schema(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t fixed = instruction->raw_instruction & UINT32_C(0xffffffe0);
    int raw_is_wfxt = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (fixed == UINT32_C(0xd5031000)
            || fixed == UINT32_C(0xd5031020));
    int form_is_wfxt = instruction->form_id == UINT16_C(4457)
        || instruction->form_id == UINT16_C(4458);
    int name_is_wfxt = instruction->name_id == CDISASM_ARM_NAME_WFET
        || instruction->name_id == CDISASM_ARM_NAME_WFIT;
    cdisasm_arm_name_id expected_name;
    cdisasm_arm_form_id expected_form;
    cdisasm_arm_reg_id expected_register;
    const cdisasm_arm_operand *timeout;

    if (!raw_is_wfxt && !form_is_wfxt && !name_is_wfxt) {
        return 1;
    }
    if (!raw_is_wfxt || !form_is_wfxt || !name_is_wfxt) {
        return 0;
    }
    expected_name = fixed == UINT32_C(0xd5031020)
        ? CDISASM_ARM_NAME_WFIT : CDISASM_ARM_NAME_WFET;
    expected_form = fixed == UINT32_C(0xd5031020)
        ? UINT16_C(4458) : UINT16_C(4457);
    expected_register = (instruction->raw_instruction & UINT32_C(31)) == 31u
        ? CDISASM_ARM_REG_XZR
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0
            + (instruction->raw_instruction & UINT32_C(31)));
    if (instruction->name_id != expected_name
        || instruction->form_id != expected_form
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->instruction_flags
            != CDISASM_ARM_INSTRUCTION_FLAG_NONE
        || instruction->operand_count != 1u) {
        return 0;
    }
    timeout = &instruction->operand[0];
    return timeout->type == CDISASM_OPERAND_REGISTER
        && timeout->reg == expected_register
        && timeout->size == 8u
        && timeout->flags == CDISASM_OPERAND_FLAG_NONE
        && timeout->shift_type == CDISASM_ARM_SHIFT_NONE
        && timeout->shift_amount == 0u
        && timeout->extend_type == CDISASM_ARM_EXTEND_NONE
        && timeout->scale == 0u
        && timeout->access == CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sb_schema(const cdisasm_arm_instruction *instruction)
{
    int raw = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->raw_instruction == UINT32_C(0xd50330ff);
    int form = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id == UINT16_C(4496);
    if (!raw && !form) {
        return 1;
    }
    return raw && form && instruction->name_id == CDISASM_ARM_NAME_SB
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags == CDISASM_ARM_INSTRUCTION_FLAG_NONE
        && instruction->operand_count == 0u;
}

static int arm_valid_dsb_nxs_schema(const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned option = (word >> 10) & 3u;
    int raw = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (word & UINT32_C(0xfffff3ff)) == UINT32_C(0xd503323f);
    int form = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id == UINT16_C(4497);
    const cdisasm_arm_operand *operand = &instruction->operand[0];
    if (!raw && !form) {
        return 1;
    }
    return raw && form && instruction->name_id == CDISASM_ARM_NAME_DSB
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags == CDISASM_ARM_INSTRUCTION_FLAG_NONE
        && instruction->operand_count == 1u
        && operand->type == CDISASM_OPERAND_IMMEDIATE
        && operand->imm == option && operand->size == 1u
        && operand->access == CDISASM_OPERAND_ACCESS_READ;
}

typedef struct arm_sve_element_count_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_reg_id destination_reg;
    uint8_t element_size;
    cdisasm_operand_access destination_access;
    int vector_destination;
} arm_sve_element_count_identity;

static int arm_sve_element_count_identity_for_word(
    uint32_t word, arm_sve_element_count_identity *identity)
{
    static const uint32_t values[18] = {
        UINT32_C(0x0470c000), UINT32_C(0x0470c400),
        UINT32_C(0x04b0c000), UINT32_C(0x04b0c400),
        UINT32_C(0x04f0c000), UINT32_C(0x04f0c400),
        UINT32_C(0x0420e000), UINT32_C(0x0460e000),
        UINT32_C(0x04a0e000), UINT32_C(0x04e0e000),
        UINT32_C(0x0430e000), UINT32_C(0x0430e400),
        UINT32_C(0x0470e000), UINT32_C(0x0470e400),
        UINT32_C(0x04b0e000), UINT32_C(0x04b0e400),
        UINT32_C(0x04f0e000), UINT32_C(0x04f0e400)
    };
    static const cdisasm_arm_name_id names[18] = {
        CDISASM_ARM_NAME_INCH, CDISASM_ARM_NAME_DECH,
        CDISASM_ARM_NAME_INCW, CDISASM_ARM_NAME_DECW,
        CDISASM_ARM_NAME_INCD, CDISASM_ARM_NAME_DECD,
        CDISASM_ARM_NAME_CNTB, CDISASM_ARM_NAME_CNTH,
        CDISASM_ARM_NAME_CNTW, CDISASM_ARM_NAME_CNTD,
        CDISASM_ARM_NAME_INCB, CDISASM_ARM_NAME_DECB,
        CDISASM_ARM_NAME_INCH, CDISASM_ARM_NAME_DECH,
        CDISASM_ARM_NAME_INCW, CDISASM_ARM_NAME_DECW,
        CDISASM_ARM_NAME_INCD, CDISASM_ARM_NAME_DECD
    };
    static const uint8_t vector_sizes[6] = { 2u, 2u, 4u, 4u, 8u, 8u };
    uint32_t fixed = word & UINT32_C(0xfff0fc00);
    unsigned encoded_register = word & 31u;
    unsigned index;

    for (index = 0u; index < 18u; ++index) {
        if (fixed == values[index]) {
            identity->form_id = (cdisasm_arm_form_id)(UINT16_C(2374)
                + index);
            identity->name_id = names[index];
            identity->vector_destination = index < 6u;
            identity->element_size = index < 6u
                ? vector_sizes[index] : 0u;
            identity->destination_access = index < 6u || index >= 10u
                ? CDISASM_OPERAND_ACCESS_READ_WRITE
                : CDISASM_OPERAND_ACCESS_WRITE;
            identity->destination_reg = index < 6u
                ? (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0
                    + encoded_register)
                : encoded_register == 31u
                    ? CDISASM_ARM_REG_XZR
                    : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0
                        + encoded_register);
            return 1;
        }
    }
    return 0;
}

static int arm_is_sve_element_count_form(
    const cdisasm_arm_instruction *instruction)
{
    return instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id >= UINT16_C(2374)
        && instruction->form_id <= UINT16_C(2391);
}

static int arm_valid_sve_element_count_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_sve_element_count_identity identity;
    const cdisasm_arm_operand *destination;
    const cdisasm_arm_operand *pattern;
    const cdisasm_arm_operand *multiplier;
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_element_count_identity_for_word(
            instruction->raw_instruction, &identity);
    int form_is_family = arm_is_sve_element_count_form(instruction);

    if (!raw_is_family && !form_is_family) {
        return 1;
    }
    if (!raw_is_family || !form_is_family
        || instruction->form_id != identity.form_id
        || instruction->name_id != identity.name_id
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->instruction_flags
            != CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        || instruction->operand_count != 3u) {
        return 0;
    }
    destination = &instruction->operand[0];
    pattern = &instruction->operand[1];
    multiplier = &instruction->operand[2];
    if (destination->type != (identity.vector_destination
            ? CDISASM_ARM_OPERAND_SCALABLE_REGISTER
            : CDISASM_OPERAND_REGISTER)
        || destination->reg != identity.destination_reg
        || destination->base_reg != CDISASM_ARM_REG_NONE
        || destination->index_reg != CDISASM_ARM_REG_NONE
        || destination->register_list != 0u
        || destination->address != 0u || destination->imm != 0u
        || destination->size != (identity.vector_destination ? 0u : 8u)
        || destination->flags != CDISASM_OPERAND_FLAG_NONE
        || destination->shift_type != CDISASM_ARM_SHIFT_NONE
        || destination->shift_amount != 0u
        || destination->extend_type != (identity.vector_destination
            ? identity.element_size : CDISASM_ARM_EXTEND_NONE)
        || destination->scale != 0u
        || destination->access != identity.destination_access) {
        return 0;
    }
    return pattern->type == CDISASM_OPERAND_IMMEDIATE
        && pattern->reg == CDISASM_ARM_REG_NONE
        && pattern->base_reg == CDISASM_ARM_REG_NONE
        && pattern->index_reg == CDISASM_ARM_REG_NONE
        && pattern->register_list == 0u && pattern->address == 0u
        && pattern->imm
            == ((instruction->raw_instruction >> 5) & UINT32_C(31))
        && pattern->size == 1u
        && pattern->flags == CDISASM_OPERAND_FLAG_NONE
        && pattern->shift_type == CDISASM_ARM_SHIFT_NONE
        && pattern->shift_amount == 0u
        && pattern->extend_type == CDISASM_ARM_EXTEND_NONE
        && pattern->scale == 0u
        && pattern->access == CDISASM_OPERAND_ACCESS_READ
        && multiplier->type == CDISASM_OPERAND_IMMEDIATE
        && multiplier->reg == CDISASM_ARM_REG_NONE
        && multiplier->base_reg == CDISASM_ARM_REG_NONE
        && multiplier->index_reg == CDISASM_ARM_REG_NONE
        && multiplier->register_list == 0u && multiplier->address == 0u
        && multiplier->imm
            == ((instruction->raw_instruction >> 16) & UINT32_C(15)) + 1u
        && multiplier->size == 1u
        && multiplier->flags == CDISASM_OPERAND_FLAG_NONE
        && multiplier->shift_type == CDISASM_ARM_SHIFT_NONE
        && multiplier->shift_amount == 0u
        && multiplier->extend_type == CDISASM_ARM_EXTEND_NONE
        && multiplier->scale == 0u
        && multiplier->access == CDISASM_OPERAND_ACCESS_READ;
}

enum arm_sve_count_destination_kind {
    ARM_SVE_COUNT_VECTOR = 0,
    ARM_SVE_COUNT_X,
    ARM_SVE_COUNT_W,
    ARM_SVE_COUNT_X_W
};

typedef struct arm_sve_saturating_count_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    uint8_t destination_kind;
    uint8_t element_size;
} arm_sve_saturating_count_identity;

static int arm_sve_saturating_count_identity_for_word(
    uint32_t word, arm_sve_saturating_count_identity *identity)
{
    static const cdisasm_arm_form_id scalar_forms[4][2][4] = {
        {
            { UINT16_C(2392), UINT16_C(2393), UINT16_C(2394), UINT16_C(2395) },
            { UINT16_C(2396), UINT16_C(2416), UINT16_C(2397), UINT16_C(2417) }
        },
        {
            { UINT16_C(2398), UINT16_C(2399), UINT16_C(2400), UINT16_C(2401) },
            { UINT16_C(2402), UINT16_C(2418), UINT16_C(2403), UINT16_C(2419) }
        },
        {
            { UINT16_C(2404), UINT16_C(2405), UINT16_C(2406), UINT16_C(2407) },
            { UINT16_C(2408), UINT16_C(2420), UINT16_C(2409), UINT16_C(2421) }
        },
        {
            { UINT16_C(2410), UINT16_C(2411), UINT16_C(2412), UINT16_C(2413) },
            { UINT16_C(2414), UINT16_C(2422), UINT16_C(2415), UINT16_C(2423) }
        }
    };
    static const cdisasm_arm_name_id names[4][4] = {
        {
            CDISASM_ARM_NAME_SQINCB, CDISASM_ARM_NAME_UQINCB,
            CDISASM_ARM_NAME_SQDECB, CDISASM_ARM_NAME_UQDECB
        },
        {
            CDISASM_ARM_NAME_SQINCH, CDISASM_ARM_NAME_UQINCH,
            CDISASM_ARM_NAME_SQDECH, CDISASM_ARM_NAME_UQDECH
        },
        {
            CDISASM_ARM_NAME_SQINCW, CDISASM_ARM_NAME_UQINCW,
            CDISASM_ARM_NAME_SQDECW, CDISASM_ARM_NAME_UQDECW
        },
        {
            CDISASM_ARM_NAME_SQINCD, CDISASM_ARM_NAME_UQINCD,
            CDISASM_ARM_NAME_SQDECD, CDISASM_ARM_NAME_UQDECD
        }
    };
    unsigned size = (word >> 22) & 3u;
    unsigned operation = (word >> 10) & 3u;
    int scalar_x = (word & UINT32_C(0x00100000)) != 0u;

    if ((word & UINT32_C(0xff30f000)) == UINT32_C(0x0420c000)
        && size != 0u) {
        unsigned local = ((operation & 1u) << 1) | (operation >> 1);

        identity->form_id = (cdisasm_arm_form_id)(
            UINT16_C(2362) + (size - 1u) * 4u + local);
        identity->name_id = names[size][operation];
        identity->destination_kind = ARM_SVE_COUNT_VECTOR;
        identity->element_size = (uint8_t)(UINT8_C(1) << size);
        return 1;
    }
    if ((word & UINT32_C(0xff20f000)) != UINT32_C(0x0420f000)) {
        return 0;
    }
    identity->form_id = scalar_forms[size][scalar_x][operation];
    identity->name_id = names[size][operation];
    identity->destination_kind = scalar_x ? ARM_SVE_COUNT_X
        : (operation & 1u) != 0u ? ARM_SVE_COUNT_W
        : ARM_SVE_COUNT_X_W;
    identity->element_size = 0u;
    return 1;
}

static int arm_is_sve_saturating_count_form(
    const cdisasm_arm_instruction *instruction)
{
    return instruction->isa_id == CDISASM_ARM_ISA_A64
        && ((instruction->form_id >= UINT16_C(2362)
                && instruction->form_id <= UINT16_C(2373))
            || (instruction->form_id >= UINT16_C(2392)
                && instruction->form_id <= UINT16_C(2423)));
}

static int arm_exact_register_operand(
    const cdisasm_arm_operand *operand, cdisasm_arm_reg_id reg,
    uint8_t size, cdisasm_operand_access access)
{
    return operand->type == CDISASM_OPERAND_REGISTER
        && operand->reg == reg && operand->size == size
        && operand->extend_type == CDISASM_ARM_EXTEND_NONE
        && operand->flags == CDISASM_OPERAND_FLAG_NONE
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u
        && operand->scale == 0u
        && operand->access == access;
}

typedef struct arm_pauth_branch_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    uint8_t link;
    uint8_t explicit_modifier;
} arm_pauth_branch_identity;

static int arm_pauth_branch_identity_for_word(
    uint32_t word, arm_pauth_branch_identity *identity)
{
    int link;
    int explicit_modifier;
    int key_b;

    if ((word & UINT32_C(0xfedff800)) != UINT32_C(0xd61f0800)) {
        return 0;
    }
    explicit_modifier = (word & UINT32_C(0x01000000)) != 0u;
    if (!explicit_modifier
        && (word & UINT32_C(31)) != UINT32_C(31)) {
        return 0;
    }
    link = (word & UINT32_C(0x00200000)) != 0u;
    key_b = (word & UINT32_C(0x00000400)) != 0u;
    identity->link = (uint8_t)link;
    identity->explicit_modifier = (uint8_t)explicit_modifier;
    if (link) {
        identity->form_id = explicit_modifier
            ? (key_b ? UINT16_C(4528) : UINT16_C(4527))
            : (key_b ? UINT16_C(4514) : UINT16_C(4513));
        identity->name_id = explicit_modifier
            ? (key_b ? CDISASM_ARM_NAME_BLRAB : CDISASM_ARM_NAME_BLRAA)
            : (key_b ? CDISASM_ARM_NAME_BLRABZ
                     : CDISASM_ARM_NAME_BLRAAZ);
    } else {
        identity->form_id = explicit_modifier
            ? (key_b ? UINT16_C(4526) : UINT16_C(4525))
            : (key_b ? UINT16_C(4511) : UINT16_C(4510));
        identity->name_id = explicit_modifier
            ? (key_b ? CDISASM_ARM_NAME_BRAB : CDISASM_ARM_NAME_BRAA)
            : (key_b ? CDISASM_ARM_NAME_BRABZ
                     : CDISASM_ARM_NAME_BRAAZ);
    }
    return 1;
}

static int arm_is_pauth_branch_form(cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(4510) || form_id == UINT16_C(4511)
        || form_id == UINT16_C(4513) || form_id == UINT16_C(4514)
        || form_id == UINT16_C(4525) || form_id == UINT16_C(4526)
        || form_id == UINT16_C(4527) || form_id == UINT16_C(4528);
}

static int arm_is_pauth_branch_name(cdisasm_arm_name_id name_id)
{
    return name_id == CDISASM_ARM_NAME_BRAAZ
        || name_id == CDISASM_ARM_NAME_BRABZ
        || name_id == CDISASM_ARM_NAME_BLRAAZ
        || name_id == CDISASM_ARM_NAME_BLRABZ
        || name_id == CDISASM_ARM_NAME_BRAA
        || name_id == CDISASM_ARM_NAME_BRAB
        || name_id == CDISASM_ARM_NAME_BLRAA
        || name_id == CDISASM_ARM_NAME_BLRAB;
}

static int arm_valid_pauth_branch_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_pauth_branch_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE, 0u, 0u
    };
    uint32_t word = instruction->raw_instruction;
    int raw_is_envelope = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (word & UINT32_C(0xfedff800)) == UINT32_C(0xd61f0800);
    int raw_is_family = raw_is_envelope
        && arm_pauth_branch_identity_for_word(word, &identity);
    int form_is_family = arm_is_pauth_branch_form(instruction->form_id);
    int name_is_family = arm_is_pauth_branch_name(instruction->name_id);
    cdisasm_arm_reg_id target = ((word >> 5) & 31u) == 31u
        ? CDISASM_ARM_REG_XZR
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0
            + ((word >> 5) & 31u));
    cdisasm_arm_reg_id modifier = (word & 31u) == 31u
        ? CDISASM_ARM_REG_SP
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + (word & 31u));

    /* Raw, form, and mnemonic ownership are deliberately independent.  This
     * rejects cross-ISA, form-only, name-only, and generated-opaque forgeries
     * instead of allowing them to fall through the generic formatter. */
    if (!raw_is_envelope && !form_is_family && !name_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups
            == (identity.link ? CDISASM_GROUP_CALL : CDISASM_GROUP_JUMP)
        && instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_POINTER_AUTH
                | (identity.link
                    ? CDISASM_ARM_INSTRUCTION_FLAG_LINK : 0u))
        && instruction->branch_target == 0u
        && instruction->operand_count
            == (identity.explicit_modifier ? 2u : 1u)
        && arm_exact_register_operand(
            &instruction->operand[0], target, 8u,
            CDISASM_OPERAND_ACCESS_READ)
        && (!identity.explicit_modifier
            || arm_exact_register_operand(
                &instruction->operand[1], modifier, 8u,
                CDISASM_OPERAND_ACCESS_READ));
}

static int arm_exact_vector_operand(
    const cdisasm_arm_operand *operand, cdisasm_arm_reg_id reg,
    uint8_t total_size, uint8_t element_size,
    cdisasm_operand_access access)
{
    return operand->type == CDISASM_OPERAND_REGISTER
        && operand->reg == reg && operand->size == total_size
        && operand->extend_type == (cdisasm_arm_extend_type)element_size
        && operand->scale == (uint8_t)(total_size / element_size)
        && operand->flags == CDISASM_OPERAND_FLAG_NONE
        && operand->access == access;
}

static int arm_exact_vector_lane_operand(
    const cdisasm_arm_operand *operand, cdisasm_arm_reg_id reg,
    uint8_t element_size, uint64_t lane, cdisasm_operand_access access)
{
    return operand->type == CDISASM_OPERAND_REGISTER
        && operand->reg == reg && operand->size == 16u
        && operand->extend_type == (cdisasm_arm_extend_type)element_size
        && operand->scale == (uint8_t)(16u / element_size)
        && operand->flags == CDISASM_ARM_OPERAND_FLAG_HAS_LANE
        && operand->imm == lane && operand->access == access;
}

static int arm_exact_scalable_operand(
    const cdisasm_arm_operand *operand, cdisasm_arm_reg_id reg,
    uint8_t element_size, cdisasm_operand_access access)
{
    return operand->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER
        && operand->reg == reg && operand->size == 0u
        && operand->extend_type == element_size
        && operand->flags == CDISASM_OPERAND_FLAG_NONE
        && operand->access == access;
}

static int arm_exact_scalable_lane_operand(
    const cdisasm_arm_operand *operand, cdisasm_arm_reg_id reg,
    uint8_t element_size, uint64_t lane, cdisasm_operand_access access)
{
    return operand->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER
        && operand->reg == reg && operand->size == 0u
        && operand->extend_type == element_size
        && operand->flags == CDISASM_ARM_OPERAND_FLAG_HAS_LANE
        && operand->imm == lane && operand->access == access;
}

static int arm_exact_predicate_operand(
    const cdisasm_arm_operand *operand, cdisasm_arm_reg_id reg,
    uint8_t element_size, uint8_t flags, cdisasm_operand_access access)
{
    return operand->type == CDISASM_ARM_OPERAND_PREDICATE
        && operand->reg == reg && operand->size == 0u
        && operand->extend_type == element_size
        && operand->flags == flags && operand->access == access;
}

static int arm_exact_predicate_lane_operand(
    const cdisasm_arm_operand *operand, cdisasm_arm_reg_id reg,
    uint8_t element_size, uint64_t lane, cdisasm_operand_access access)
{
    return operand->type == CDISASM_ARM_OPERAND_PREDICATE
        && operand->reg == reg && operand->size == 0u
        && operand->extend_type == element_size
        && operand->flags == CDISASM_ARM_OPERAND_FLAG_HAS_LANE
        && operand->imm == lane && operand->access == access;
}

static int arm_exact_u8_immediate_operand(
    const cdisasm_arm_operand *operand, uint64_t value)
{
    return operand->type == CDISASM_OPERAND_IMMEDIATE
        && operand->imm == value && operand->size == 1u
        && operand->flags == CDISASM_OPERAND_FLAG_NONE
        && operand->access == CDISASM_OPERAND_ACCESS_READ;
}

static int arm_exact_u16_immediate_operand(
    const cdisasm_arm_operand *operand, uint64_t value)
{
    return operand->type == CDISASM_OPERAND_IMMEDIATE
        && operand->imm == value && operand->size == 2u
        && operand->flags == CDISASM_OPERAND_FLAG_NONE
        && operand->access == CDISASM_OPERAND_ACCESS_READ;
}

static int arm_exact_predicate_pair_operand(
    const cdisasm_arm_operand *operand, cdisasm_arm_reg_id first,
    cdisasm_arm_reg_id second, uint8_t element_size,
    cdisasm_operand_access access)
{
    return operand->type == CDISASM_ARM_OPERAND_PREDICATE_PAIR
        && operand->reg == first && operand->index_reg == second
        && operand->size == 0u && operand->extend_type == element_size
        && operand->flags == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED
        && operand->access == access;
}

typedef struct arm_sve_while_single_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
} arm_sve_while_single_identity;

static int arm_sve_while_single_identity_for_word(
    uint32_t word, arm_sve_while_single_identity *identity)
{
    static const uint32_t values[8] = {
        UINT32_C(0x25200000), UINT32_C(0x25200800),
        UINT32_C(0x25200010), UINT32_C(0x25200810),
        UINT32_C(0x25200400), UINT32_C(0x25200c00),
        UINT32_C(0x25200410), UINT32_C(0x25200c10)
    };
    static const cdisasm_arm_name_id names[8] = {
        CDISASM_ARM_NAME_WHILEGE, CDISASM_ARM_NAME_WHILEHS,
        CDISASM_ARM_NAME_WHILEGT, CDISASM_ARM_NAME_WHILEHI,
        CDISASM_ARM_NAME_WHILELT, CDISASM_ARM_NAME_WHILELO,
        CDISASM_ARM_NAME_WHILELE, CDISASM_ARM_NAME_WHILELS
    };
    uint32_t fixed = word & UINT32_C(0xff20ec10);
    unsigned index;

    for (index = 0u; index < 8u; ++index) {
        if (fixed == values[index]) {
            identity->form_id = (cdisasm_arm_form_id)(UINT16_C(2585)
                + index);
            identity->name_id = names[index];
            return 1;
        }
    }
    return 0;
}

static int arm_is_sve_while_comparison_name(cdisasm_arm_name_id name_id)
{
    return name_id == CDISASM_ARM_NAME_WHILEGE
        || name_id == CDISASM_ARM_NAME_WHILEHS
        || name_id == CDISASM_ARM_NAME_WHILEGT
        || name_id == CDISASM_ARM_NAME_WHILEHI
        || name_id == CDISASM_ARM_NAME_WHILELT
        || name_id == CDISASM_ARM_NAME_WHILELO
        || name_id == CDISASM_ARM_NAME_WHILELE
        || name_id == CDISASM_ARM_NAME_WHILELS;
}

typedef enum arm_sve_predicate_break_kind {
    ARM_SVE_PREDICATE_BREAK_NONE = 0,
    ARM_SVE_PREDICATE_BREAK_BRKP,
    ARM_SVE_PREDICATE_BREAK_BRK,
    ARM_SVE_PREDICATE_BREAK_BRKN
} arm_sve_predicate_break_kind;

typedef struct arm_sve_predicate_break_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    arm_sve_predicate_break_kind kind;
} arm_sve_predicate_break_identity;

static int arm_sve_predicate_break_identity_for_word(
    uint32_t word, arm_sve_predicate_break_identity *identity)
{
    static const struct arm_sve_predicate_break_encoding {
        uint32_t mask;
        uint32_t value;
        cdisasm_arm_name_id name_id;
        arm_sve_predicate_break_kind kind;
    } encodings[10] = {
        { UINT32_C(0xfff0c210), UINT32_C(0x2500c000),
          CDISASM_ARM_NAME_BRKPA, ARM_SVE_PREDICATE_BREAK_BRKP },
        { UINT32_C(0xfff0c210), UINT32_C(0x2540c000),
          CDISASM_ARM_NAME_BRKPAS, ARM_SVE_PREDICATE_BREAK_BRKP },
        { UINT32_C(0xfff0c210), UINT32_C(0x2500c010),
          CDISASM_ARM_NAME_BRKPB, ARM_SVE_PREDICATE_BREAK_BRKP },
        { UINT32_C(0xfff0c210), UINT32_C(0x2540c010),
          CDISASM_ARM_NAME_BRKPBS, ARM_SVE_PREDICATE_BREAK_BRKP },
        { UINT32_C(0xffffc200), UINT32_C(0x25104000),
          CDISASM_ARM_NAME_BRKA, ARM_SVE_PREDICATE_BREAK_BRK },
        { UINT32_C(0xffffc210), UINT32_C(0x25504000),
          CDISASM_ARM_NAME_BRKAS, ARM_SVE_PREDICATE_BREAK_BRK },
        { UINT32_C(0xffffc200), UINT32_C(0x25904000),
          CDISASM_ARM_NAME_BRKB, ARM_SVE_PREDICATE_BREAK_BRK },
        { UINT32_C(0xffffc210), UINT32_C(0x25d04000),
          CDISASM_ARM_NAME_BRKBS, ARM_SVE_PREDICATE_BREAK_BRK },
        { UINT32_C(0xffffc210), UINT32_C(0x25184000),
          CDISASM_ARM_NAME_BRKN, ARM_SVE_PREDICATE_BREAK_BRKN },
        { UINT32_C(0xffffc210), UINT32_C(0x25584000),
          CDISASM_ARM_NAME_BRKNS, ARM_SVE_PREDICATE_BREAK_BRKN }
    };
    unsigned index;

    for (index = 0u; index < 10u; ++index) {
        if ((word & encodings[index].mask) == encodings[index].value) {
            identity->form_id = (cdisasm_arm_form_id)(UINT16_C(2546)
                + index);
            identity->name_id = encodings[index].name_id;
            identity->kind = encodings[index].kind;
            return 1;
        }
    }
    return 0;
}

static int arm_is_sve_predicate_break_name(cdisasm_arm_name_id name_id)
{
    return name_id >= CDISASM_ARM_NAME_BRKA
        && name_id <= CDISASM_ARM_NAME_BRKPBS;
}

typedef enum arm_sve_predicate_control_kind {
    ARM_SVE_PREDICATE_CONTROL_NONE = 0,
    ARM_SVE_PREDICATE_CONTROL_PTEST,
    ARM_SVE_PREDICATE_CONTROL_PFIRST,
    ARM_SVE_PREDICATE_CONTROL_PNEXT,
    ARM_SVE_PREDICATE_CONTROL_PTRUE,
    ARM_SVE_PREDICATE_CONTROL_PTRUES,
    ARM_SVE_PREDICATE_CONTROL_PFALSE
} arm_sve_predicate_control_kind;

typedef struct arm_sve_predicate_control_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    arm_sve_predicate_control_kind kind;
} arm_sve_predicate_control_identity;

static int arm_sve_predicate_control_identity_for_word(
    uint32_t word, arm_sve_predicate_control_identity *identity)
{
    static const struct arm_sve_predicate_control_encoding {
        uint32_t mask;
        uint32_t value;
        cdisasm_arm_name_id name_id;
    } encodings[6] = {
        { UINT32_C(0xffffc21f), UINT32_C(0x2550c000),
          CDISASM_ARM_NAME_PTEST },
        { UINT32_C(0xfffffe10), UINT32_C(0x2558c000),
          CDISASM_ARM_NAME_PFIRST },
        { UINT32_C(0xff3ffe10), UINT32_C(0x2519c400),
          CDISASM_ARM_NAME_PNEXT },
        { UINT32_C(0xff3ffc10), UINT32_C(0x2518e000),
          CDISASM_ARM_NAME_PTRUE },
        { UINT32_C(0xff3ffc10), UINT32_C(0x2519e000),
          CDISASM_ARM_NAME_PTRUES },
        { UINT32_C(0xfffffff0), UINT32_C(0x2518e400),
          CDISASM_ARM_NAME_PFALSE }
    };
    unsigned index;

    for (index = 0u; index < 6u; ++index) {
        if ((word & encodings[index].mask) == encodings[index].value) {
            identity->form_id = (cdisasm_arm_form_id)(UINT16_C(2556)
                + index);
            identity->name_id = encodings[index].name_id;
            identity->kind = (arm_sve_predicate_control_kind)(
                ARM_SVE_PREDICATE_CONTROL_PTEST + index);
            return 1;
        }
    }
    return 0;
}

static int arm_is_exclusive_sve_predicate_control_name(
    cdisasm_arm_name_id name_id)
{
    return name_id == CDISASM_ARM_NAME_PTEST
        || name_id == CDISASM_ARM_NAME_PFIRST
        || name_id == CDISASM_ARM_NAME_PNEXT
        || name_id == CDISASM_ARM_NAME_PTRUES
        || name_id == CDISASM_ARM_NAME_PFALSE;
}

static int arm_valid_sve_psel_schema(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint8_t element_size = 0u;
    uint64_t lane = 0u;
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_psel_fields(word, &element_size, &lane);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id == UINT16_C(2565);
    int name_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->name_id == CDISASM_ARM_NAME_PSEL;
    const cdisasm_arm_operand *indexed;

    if (!raw_is_family && !form_is_family && !name_is_family) {
        return 1;
    }
    if (!raw_is_family || !form_is_family || !name_is_family
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->instruction_flags
            != CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        || instruction->operand_count != 3u
        || !arm_exact_predicate_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_P0 + (word & 15u)), element_size,
            CDISASM_OPERAND_FLAG_NONE,
            CDISASM_OPERAND_ACCESS_WRITE)
        || !arm_exact_predicate_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_P0 + ((word >> 10) & 15u)),
            element_size, CDISASM_OPERAND_FLAG_NONE,
            CDISASM_OPERAND_ACCESS_READ)
        || !arm_exact_predicate_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_P0 + ((word >> 5) & 15u)),
            element_size, CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
            CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    indexed = &instruction->operand[2];
    return indexed->base_reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_W12 + ((word >> 16) & 3u))
        && indexed->imm == lane;
}

static int arm_valid_sve_punpk_schema(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (word & UINT32_C(0xfffefe10)) == UINT32_C(0x05304000);
    int form_is_family = instruction->form_id == UINT16_C(2468)
        || instruction->form_id == UINT16_C(2469);
    int name_is_family = instruction->name_id == CDISASM_ARM_NAME_PUNPKLO
        || instruction->name_id == CDISASM_ARM_NAME_PUNPKHI;
    cdisasm_arm_form_id expected_form =
        (word & UINT32_C(0x00010000)) != 0u
            ? UINT16_C(2469) : UINT16_C(2468);
    cdisasm_arm_name_id expected_name =
        (word & UINT32_C(0x00010000)) != 0u
            ? CDISASM_ARM_NAME_PUNPKHI : CDISASM_ARM_NAME_PUNPKLO;

    if (!raw_is_family && !form_is_family && !name_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->form_id == expected_form
        && instruction->name_id == expected_name
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        && instruction->operand_count == 2u
        && arm_exact_predicate_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_P0 + (word & 15u)), 2u,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
            CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_predicate_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_P0 + ((word >> 5) & 15u)), 1u,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
            CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sve_unpack_schema(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id names[4] = {
        CDISASM_ARM_NAME_SUNPKLO,
        CDISASM_ARM_NAME_SUNPKHI,
        CDISASM_ARM_NAME_UUNPKLO,
        CDISASM_ARM_NAME_UUNPKHI
    };
    uint32_t word = instruction->raw_instruction;
    unsigned control = (word >> 16) & 3u;
    unsigned size_code = (word >> 22) & 3u;
    uint8_t destination_size = (uint8_t)(UINT8_C(1) << size_code);
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (word & UINT32_C(0xff3cfc00)) == UINT32_C(0x05303800)
        && size_code != 0u;
    int form_is_family = instruction->form_id >= UINT16_C(2456)
        && instruction->form_id <= UINT16_C(2459);
    int name_is_family = instruction->name_id == CDISASM_ARM_NAME_SUNPKLO
        || instruction->name_id == CDISASM_ARM_NAME_SUNPKHI
        || instruction->name_id == CDISASM_ARM_NAME_UUNPKLO
        || instruction->name_id == CDISASM_ARM_NAME_UUNPKHI;

    if (!raw_is_family && !form_is_family && !name_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->form_id == (cdisasm_arm_form_id)(
            UINT16_C(2456) + control)
        && instruction->name_id == names[control]
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        && instruction->operand_count == 2u
        && arm_exact_scalable_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + (word & 31u)), destination_size,
            CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_scalable_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)),
            (uint8_t)(destination_size / 2u),
            CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sve_shift_insert_schema(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned encoded_immediate = (((word >> 22) & 3u) << 5)
        | ((word >> 16) & 31u);
    unsigned element_bits = encoded_immediate >= 64u ? 64u
        : encoded_immediate >= 32u ? 32u
        : encoded_immediate >= 16u ? 16u : 8u;
    int left = (word & UINT32_C(0x00000400)) != 0u;
    unsigned immediate = encoded_immediate >= 8u
        ? (left
            ? encoded_immediate - element_bits
            : 2u * element_bits - encoded_immediate)
        : 0u;
    uint8_t element_size = (uint8_t)(element_bits / 8u);
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (word & UINT32_C(0xff20f800)) == UINT32_C(0x4500f000)
        && encoded_immediate >= 8u;
    int form_is_family = instruction->form_id >= UINT16_C(2846)
        && instruction->form_id <= UINT16_C(2847);
    int name_is_family = (instruction->instruction_flags
            & (CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE
                | CDISASM_ARM_INSTRUCTION_FLAG_SIMD)) == 0u
        && (instruction->name_id == CDISASM_ARM_NAME_SRI
            || instruction->name_id == CDISASM_ARM_NAME_SLI);
    cdisasm_arm_form_id expected_form = (cdisasm_arm_form_id)(
        UINT16_C(2846) + (left ? 1u : 0u));
    cdisasm_arm_name_id expected_name = left
        ? CDISASM_ARM_NAME_SLI : CDISASM_ARM_NAME_SRI;

    if (!raw_is_family && !form_is_family && !name_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->form_id == expected_form
        && instruction->name_id == expected_name
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        && instruction->operand_count == 3u
        && arm_exact_scalable_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + (word & 31u)), element_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_scalable_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)), element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_u8_immediate_operand(
            &instruction->operand[2], (uint64_t)immediate);
}

static int arm_sve_bitperm_identity_for_word(
    uint32_t word, cdisasm_arm_form_id *form_id,
    cdisasm_arm_name_id *name_id)
{
    switch (word & UINT32_C(0xff20fc00)) {
        case UINT32_C(0x4500b000):
            *form_id = UINT16_C(2829);
            *name_id = CDISASM_ARM_NAME_BEXT;
            return 1;
        case UINT32_C(0x4500b400):
            *form_id = UINT16_C(2830);
            *name_id = CDISASM_ARM_NAME_BDEP;
            return 1;
        case UINT32_C(0x4500b800):
            *form_id = UINT16_C(2831);
            *name_id = CDISASM_ARM_NAME_BGRP;
            return 1;
        default:
            return 0;
    }
}

static int arm_valid_sve_bitperm_schema(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    cdisasm_arm_form_id expected_form = CDISASM_ARM_FORM_NONE;
    cdisasm_arm_name_id expected_name = CDISASM_ARM_NAME_NONE;
    uint8_t element_size = (uint8_t)(UINT8_C(1)
        << ((word >> 22) & 3u));
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_bitperm_identity_for_word(
            word, &expected_form, &expected_name);
    int form_is_family = instruction->form_id >= UINT16_C(2829)
        && instruction->form_id <= UINT16_C(2831);
    int name_is_family = (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE) == 0u
        && (instruction->name_id == CDISASM_ARM_NAME_BEXT
            || instruction->name_id == CDISASM_ARM_NAME_BDEP
            || instruction->name_id == CDISASM_ARM_NAME_BGRP);

    if (!raw_is_family && !form_is_family && !name_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->form_id == expected_form
        && instruction->name_id == expected_name
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        && instruction->operand_count == 3u
        && arm_exact_scalable_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + (word & 31u)), element_size,
            CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_scalable_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)),
            element_size, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_scalable_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 16) & 31u)),
            element_size, CDISASM_OPERAND_ACCESS_READ);
}

typedef enum arm_advsimd_sha_layout {
    ARM_ADVSIMD_SHA_LAYOUT_NONE = 0,
    ARM_ADVSIMD_SHA_LAYOUT_A32_QQQ,
    ARM_ADVSIMD_SHA_LAYOUT_A32_QQ,
    ARM_ADVSIMD_SHA_LAYOUT_A64_QSV,
    ARM_ADVSIMD_SHA_LAYOUT_A64_VVV,
    ARM_ADVSIMD_SHA_LAYOUT_A64_QQV,
    ARM_ADVSIMD_SHA_LAYOUT_A64_SS,
    ARM_ADVSIMD_SHA_LAYOUT_A64_VV
} arm_advsimd_sha_layout;

typedef struct arm_advsimd_sha_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    arm_advsimd_sha_layout layout;
    unsigned rd;
    unsigned rn;
    unsigned rm;
} arm_advsimd_sha_identity;

static uint32_t arm_advsimd_sha_canonical_word(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;

    return instruction->isa_id == CDISASM_ARM_ISA_T32
        ? (word << 16) | (word >> 16) : word;
}

static int arm_advsimd_sha_raw_is_envelope(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = arm_advsimd_sha_canonical_word(instruction);
    static const uint32_t a32_sha3_values[7] = {
        UINT32_C(0xf2000c00), UINT32_C(0xf2100c00),
        UINT32_C(0xf2200c00), UINT32_C(0xf2300c00),
        UINT32_C(0xf3000c00), UINT32_C(0xf3100c00),
        UINT32_C(0xf3200c00)
    };
    static const uint32_t t32_sha3_values[7] = {
        UINT32_C(0xef000c00), UINT32_C(0xef100c00),
        UINT32_C(0xef200c00), UINT32_C(0xef300c00),
        UINT32_C(0xff000c00), UINT32_C(0xff100c00),
        UINT32_C(0xff200c00)
    };
    static const uint32_t a32_sha2_values[3] = {
        UINT32_C(0xf3b102c0), UINT32_C(0xf3b20380),
        UINT32_C(0xf3b203c0)
    };
    static const uint32_t t32_sha2_values[3] = {
        UINT32_C(0xffb102c0), UINT32_C(0xffb20380),
        UINT32_C(0xffb203c0)
    };
    const uint32_t *sha3_values;
    const uint32_t *sha2_values;
    size_t index;

    if (instruction->isa_id == CDISASM_ARM_ISA_A64) {
        switch (word & UINT32_C(0xffe0fc00)) {
            case UINT32_C(0x5e000000):
            case UINT32_C(0x5e001000):
            case UINT32_C(0x5e002000):
            case UINT32_C(0x5e003000):
            case UINT32_C(0x5e004000):
            case UINT32_C(0x5e005000):
            case UINT32_C(0x5e006000):
                return 1;
            default:
                break;
        }
        return (word & UINT32_C(0xfffffc00)) == UINT32_C(0x5e280800)
            || (word & UINT32_C(0xfffffc00)) == UINT32_C(0x5e281800)
            || (word & UINT32_C(0xfffffc00)) == UINT32_C(0x5e282800);
    }
    if (instruction->isa_id != CDISASM_ARM_ISA_A32
        && instruction->isa_id != CDISASM_ARM_ISA_T32) {
        return 0;
    }
    sha3_values = instruction->isa_id == CDISASM_ARM_ISA_A32
        ? a32_sha3_values : t32_sha3_values;
    sha2_values = instruction->isa_id == CDISASM_ARM_ISA_A32
        ? a32_sha2_values : t32_sha2_values;
    for (index = 0u; index < 7u; ++index) {
        if ((word & UINT32_C(0xffb00f10)) == sha3_values[index]) {
            return 1;
        }
    }
    for (index = 0u; index < 3u; ++index) {
        if ((word & UINT32_C(0xffb30fd0)) == sha2_values[index]) {
            return 1;
        }
    }
    return 0;
}

static int arm_advsimd_sha_identity_for_instruction(
    const cdisasm_arm_instruction *instruction,
    arm_advsimd_sha_identity *identity)
{
    static const cdisasm_arm_name_id names[10] = {
        CDISASM_ARM_NAME_SHA1C, CDISASM_ARM_NAME_SHA1P,
        CDISASM_ARM_NAME_SHA1M, CDISASM_ARM_NAME_SHA1SU0,
        CDISASM_ARM_NAME_SHA256H, CDISASM_ARM_NAME_SHA256H2,
        CDISASM_ARM_NAME_SHA256SU1, CDISASM_ARM_NAME_SHA1H,
        CDISASM_ARM_NAME_SHA1SU1, CDISASM_ARM_NAME_SHA256SU0
    };
    static const uint32_t a32_sha3_values[7] = {
        UINT32_C(0xf2000c00), UINT32_C(0xf2100c00),
        UINT32_C(0xf2200c00), UINT32_C(0xf2300c00),
        UINT32_C(0xf3000c00), UINT32_C(0xf3100c00),
        UINT32_C(0xf3200c00)
    };
    static const uint32_t t32_sha3_values[7] = {
        UINT32_C(0xef000c00), UINT32_C(0xef100c00),
        UINT32_C(0xef200c00), UINT32_C(0xef300c00),
        UINT32_C(0xff000c00), UINT32_C(0xff100c00),
        UINT32_C(0xff200c00)
    };
    static const uint32_t a32_sha2_values[3] = {
        UINT32_C(0xf3b102c0), UINT32_C(0xf3b20380),
        UINT32_C(0xf3b203c0)
    };
    static const uint32_t t32_sha2_values[3] = {
        UINT32_C(0xffb102c0), UINT32_C(0xffb20380),
        UINT32_C(0xffb203c0)
    };
    static const cdisasm_arm_form_id a32_forms[10] = {
        UINT16_C(676), UINT16_C(687), UINT16_C(716), UINT16_C(728),
        UINT16_C(743), UINT16_C(748), UINT16_C(768), UINT16_C(819),
        UINT16_C(831), UINT16_C(832)
    };
    static const cdisasm_arm_form_id t32_forms[10] = {
        UINT16_C(1203), UINT16_C(1214), UINT16_C(1243), UINT16_C(1255),
        UINT16_C(1270), UINT16_C(1275), UINT16_C(1295), UINT16_C(1346),
        UINT16_C(1358), UINT16_C(1359)
    };
    static const cdisasm_arm_form_id a64_forms[10] = {
        UINT16_C(5731), UINT16_C(5732), UINT16_C(5733), UINT16_C(5734),
        UINT16_C(5735), UINT16_C(5736), UINT16_C(5737), UINT16_C(5738),
        UINT16_C(5739), UINT16_C(5740)
    };
    uint32_t word = arm_advsimd_sha_canonical_word(instruction);
    size_t operation;

    identity->layout = ARM_ADVSIMD_SHA_LAYOUT_NONE;
    if (instruction->isa_id == CDISASM_ARM_ISA_A64) {
        for (operation = 0u; operation < 7u; ++operation) {
            if ((word & UINT32_C(0xffe0fc00))
                    == UINT32_C(0x5e000000)
                        + ((uint32_t)operation << 12)) {
                identity->form_id = a64_forms[operation];
                identity->name_id = names[operation];
                identity->layout = operation <= 2u
                    ? ARM_ADVSIMD_SHA_LAYOUT_A64_QSV
                    : operation == 3u || operation == 6u
                        ? ARM_ADVSIMD_SHA_LAYOUT_A64_VVV
                        : ARM_ADVSIMD_SHA_LAYOUT_A64_QQV;
                identity->rd = word & 31u;
                identity->rn = (word >> 5) & 31u;
                identity->rm = (word >> 16) & 31u;
                return 1;
            }
        }
        for (operation = 0u; operation < 3u; ++operation) {
            static const uint32_t values[3] = {
                UINT32_C(0x5e280800), UINT32_C(0x5e281800),
                UINT32_C(0x5e282800)
            };

            if ((word & UINT32_C(0xfffffc00)) != values[operation]) {
                continue;
            }
            identity->form_id = a64_forms[operation + 7u];
            identity->name_id = names[operation + 7u];
            identity->layout = operation == 0u
                ? ARM_ADVSIMD_SHA_LAYOUT_A64_SS
                : ARM_ADVSIMD_SHA_LAYOUT_A64_VV;
            identity->rd = word & 31u;
            identity->rn = (word >> 5) & 31u;
            identity->rm = 0u;
            return 1;
        }
        return 0;
    }
    if (instruction->isa_id == CDISASM_ARM_ISA_A32
        || instruction->isa_id == CDISASM_ARM_ISA_T32) {
        const uint32_t *sha3_values =
            instruction->isa_id == CDISASM_ARM_ISA_A32
                ? a32_sha3_values : t32_sha3_values;
        const uint32_t *sha2_values =
            instruction->isa_id == CDISASM_ARM_ISA_A32
                ? a32_sha2_values : t32_sha2_values;
        const cdisasm_arm_form_id *forms =
            instruction->isa_id == CDISASM_ARM_ISA_A32
                ? a32_forms : t32_forms;
        unsigned encoded_rd = ((word >> 18) & 16u)
            | ((word >> 12) & 15u);
        unsigned encoded_rn = ((word >> 3) & 16u)
            | ((word >> 16) & 15u);
        unsigned encoded_rm = ((word >> 1) & 16u) | (word & 15u);

        for (operation = 0u; operation < 7u; ++operation) {
            if ((word & UINT32_C(0xffb00f10)) != sha3_values[operation]) {
                continue;
            }
            if ((word & UINT32_C(0x40)) == 0u
                || ((encoded_rd | encoded_rn | encoded_rm) & 1u) != 0u) {
                return 0;
            }
            identity->form_id = forms[operation];
            identity->name_id = names[operation];
            identity->layout = ARM_ADVSIMD_SHA_LAYOUT_A32_QQQ;
            identity->rd = encoded_rd / 2u;
            identity->rn = encoded_rn / 2u;
            identity->rm = encoded_rm / 2u;
            return 1;
        }
        for (operation = 0u; operation < 3u; ++operation) {
            if ((word & UINT32_C(0xffb30fd0)) != sha2_values[operation]) {
                continue;
            }
            if (((word >> 18) & 3u) != 2u
                || ((encoded_rd | encoded_rm) & 1u) != 0u) {
                return 0;
            }
            identity->form_id = forms[operation + 7u];
            identity->name_id = names[operation + 7u];
            identity->layout = ARM_ADVSIMD_SHA_LAYOUT_A32_QQ;
            identity->rd = encoded_rd / 2u;
            identity->rn = 0u;
            identity->rm = encoded_rm / 2u;
            return 1;
        }
    }
    return 0;
}

static int arm_valid_advsimd_sha_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_advsimd_sha_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE,
        ARM_ADVSIMD_SHA_LAYOUT_NONE, 0u, 0u, 0u
    };
    int raw_is_envelope = arm_advsimd_sha_raw_is_envelope(instruction);
    int raw_is_family = arm_advsimd_sha_identity_for_instruction(
        instruction, &identity);
    int form_is_family = (instruction->form_id >= UINT16_C(5731)
            && instruction->form_id <= UINT16_C(5740))
        || instruction->form_id == UINT16_C(676)
        || instruction->form_id == UINT16_C(687)
        || instruction->form_id == UINT16_C(716)
        || instruction->form_id == UINT16_C(728)
        || instruction->form_id == UINT16_C(743)
        || instruction->form_id == UINT16_C(748)
        || instruction->form_id == UINT16_C(768)
        || instruction->form_id == UINT16_C(819)
        || instruction->form_id == UINT16_C(831)
        || instruction->form_id == UINT16_C(832)
        || instruction->form_id == UINT16_C(1203)
        || instruction->form_id == UINT16_C(1214)
        || instruction->form_id == UINT16_C(1243)
        || instruction->form_id == UINT16_C(1255)
        || instruction->form_id == UINT16_C(1270)
        || instruction->form_id == UINT16_C(1275)
        || instruction->form_id == UINT16_C(1295)
        || instruction->form_id == UINT16_C(1346)
        || instruction->form_id == UINT16_C(1358)
        || instruction->form_id == UINT16_C(1359);
    int name_is_family = (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE) == 0u
        && arm_is_advsimd_sha_name(instruction->name_id);
    cdisasm_operand_access destination_access =
        identity.name_id == CDISASM_ARM_NAME_SHA1H
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ_WRITE;
    cdisasm_arm_reg_id rd;
    cdisasm_arm_reg_id rn;
    cdisasm_arm_reg_id rm;

    if (!raw_is_envelope && !form_is_family && !name_is_family) {
        return 1;
    }
    if (!raw_is_family || !form_is_family || !name_is_family
        || instruction->form_id != identity.form_id
        || instruction->name_id != identity.name_id
        || instruction->opcode_size != 4u
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->instruction_flags
            != CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        || instruction->branch_target != 0u) {
        return 0;
    }
    if (identity.layout == ARM_ADVSIMD_SHA_LAYOUT_A32_QQQ
        || identity.layout == ARM_ADVSIMD_SHA_LAYOUT_A32_QQ) {
        rd = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Q0 + identity.rd);
        rn = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Q0 + identity.rn);
        rm = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Q0 + identity.rm);
        return instruction->operand_count
                == (identity.layout == ARM_ADVSIMD_SHA_LAYOUT_A32_QQQ
                    ? 3u : 2u)
            && arm_exact_vector_operand(
                &instruction->operand[0], rd, 16u, 4u,
                destination_access)
            && (identity.layout == ARM_ADVSIMD_SHA_LAYOUT_A32_QQQ
                ? arm_exact_vector_operand(
                    &instruction->operand[1], rn, 16u, 4u,
                    CDISASM_OPERAND_ACCESS_READ)
                    && arm_exact_vector_operand(
                        &instruction->operand[2], rm, 16u, 4u,
                        CDISASM_OPERAND_ACCESS_READ)
                : arm_exact_vector_operand(
                    &instruction->operand[1], rm, 16u, 4u,
                    CDISASM_OPERAND_ACCESS_READ));
    }
    rd = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + identity.rd);
    rn = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + identity.rn);
    rm = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + identity.rm);
    if (identity.layout == ARM_ADVSIMD_SHA_LAYOUT_A64_QSV) {
        return instruction->operand_count == 3u
            && arm_exact_vector_operand(
                &instruction->operand[0], rd, 16u, 16u,
                destination_access)
            && arm_exact_register_operand(
                &instruction->operand[1], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_S0 + identity.rn), 4u,
                CDISASM_OPERAND_ACCESS_READ)
            && arm_exact_vector_operand(
                &instruction->operand[2], rm, 16u, 4u,
                CDISASM_OPERAND_ACCESS_READ);
    }
    if (identity.layout == ARM_ADVSIMD_SHA_LAYOUT_A64_QQV) {
        return instruction->operand_count == 3u
            && arm_exact_vector_operand(
                &instruction->operand[0], rd, 16u, 16u,
                destination_access)
            && arm_exact_vector_operand(
                &instruction->operand[1], rn, 16u, 16u,
                CDISASM_OPERAND_ACCESS_READ)
            && arm_exact_vector_operand(
                &instruction->operand[2], rm, 16u, 4u,
                CDISASM_OPERAND_ACCESS_READ);
    }
    if (identity.layout == ARM_ADVSIMD_SHA_LAYOUT_A64_VVV) {
        return instruction->operand_count == 3u
            && arm_exact_vector_operand(
                &instruction->operand[0], rd, 16u, 4u,
                destination_access)
            && arm_exact_vector_operand(
                &instruction->operand[1], rn, 16u, 4u,
                CDISASM_OPERAND_ACCESS_READ)
            && arm_exact_vector_operand(
                &instruction->operand[2], rm, 16u, 4u,
                CDISASM_OPERAND_ACCESS_READ);
    }
    if (identity.layout == ARM_ADVSIMD_SHA_LAYOUT_A64_SS) {
        return instruction->operand_count == 2u
            && arm_exact_register_operand(
                &instruction->operand[0], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_S0 + identity.rd), 4u,
                destination_access)
            && arm_exact_register_operand(
                &instruction->operand[1], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_S0 + identity.rn), 4u,
                CDISASM_OPERAND_ACCESS_READ);
    }
    return identity.layout == ARM_ADVSIMD_SHA_LAYOUT_A64_VV
        && instruction->operand_count == 2u
        && arm_exact_vector_operand(
            &instruction->operand[0], rd, 16u, 4u,
            destination_access)
        && arm_exact_vector_operand(
            &instruction->operand[1], rn, 16u, 4u,
            CDISASM_OPERAND_ACCESS_READ);
}

typedef enum arm_fixed_crypto_layout {
    ARM_FIXED_CRYPTO_LAYOUT_NONE = 0,
    ARM_FIXED_CRYPTO_LAYOUT_TT,
    ARM_FIXED_CRYPTO_LAYOUT_QQV2D,
    ARM_FIXED_CRYPTO_LAYOUT_VVV2D,
    ARM_FIXED_CRYPTO_LAYOUT_VVV2D_WRITE,
    ARM_FIXED_CRYPTO_LAYOUT_VVV4S,
    ARM_FIXED_CRYPTO_LAYOUT_VVV4S_WRITE,
    ARM_FIXED_CRYPTO_LAYOUT_VVVV4S,
    ARM_FIXED_CRYPTO_LAYOUT_VVVV16B,
    ARM_FIXED_CRYPTO_LAYOUT_VVV2D_IMM6,
    ARM_FIXED_CRYPTO_LAYOUT_VV2D,
    ARM_FIXED_CRYPTO_LAYOUT_VV4S
} arm_fixed_crypto_layout;

typedef struct arm_fixed_crypto_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    arm_fixed_crypto_layout layout;
    unsigned rd;
    unsigned rn;
    unsigned rm;
    unsigned ra;
    unsigned lane;
} arm_fixed_crypto_identity;

static int arm_fixed_crypto_identity_for_word(
    uint32_t word, arm_fixed_crypto_identity *identity)
{
    static const cdisasm_arm_name_id tt_names[4] = {
        CDISASM_ARM_NAME_SM3TT1A, CDISASM_ARM_NAME_SM3TT1B,
        CDISASM_ARM_NAME_SM3TT2A, CDISASM_ARM_NAME_SM3TT2B
    };
    static const uint32_t three_values[7] = {
        UINT32_C(0xce608000), UINT32_C(0xce608400),
        UINT32_C(0xce608800), UINT32_C(0xce608c00),
        UINT32_C(0xce60c000),
        UINT32_C(0xce60c400), UINT32_C(0xce60c800)
    };
    static const cdisasm_arm_form_id three_forms[7] = {
        UINT16_C(6291), UINT16_C(6292), UINT16_C(6293),
        UINT16_C(6294), UINT16_C(6295), UINT16_C(6296),
        UINT16_C(6297)
    };
    static const cdisasm_arm_name_id three_names[7] = {
        CDISASM_ARM_NAME_SHA512H, CDISASM_ARM_NAME_SHA512H2,
        CDISASM_ARM_NAME_SHA512SU1, CDISASM_ARM_NAME_RAX1,
        CDISASM_ARM_NAME_SM3PARTW1,
        CDISASM_ARM_NAME_SM3PARTW2, CDISASM_ARM_NAME_SM4EKEY
    };
    static const arm_fixed_crypto_layout three_layouts[7] = {
        ARM_FIXED_CRYPTO_LAYOUT_QQV2D,
        ARM_FIXED_CRYPTO_LAYOUT_QQV2D,
        ARM_FIXED_CRYPTO_LAYOUT_VVV2D,
        ARM_FIXED_CRYPTO_LAYOUT_VVV2D_WRITE,
        ARM_FIXED_CRYPTO_LAYOUT_VVV4S,
        ARM_FIXED_CRYPTO_LAYOUT_VVV4S,
        ARM_FIXED_CRYPTO_LAYOUT_VVV4S_WRITE
    };
    size_t operation;

    for (operation = 0u; operation < 4u; ++operation) {
        if ((word & UINT32_C(0xffe0cc00))
                != UINT32_C(0xce408000)
                    + ((uint32_t)operation << 10)) {
            continue;
        }
        identity->form_id = (cdisasm_arm_form_id)(UINT16_C(6287)
            + operation);
        identity->name_id = tt_names[operation];
        identity->layout = ARM_FIXED_CRYPTO_LAYOUT_TT;
        identity->rd = word & 31u;
        identity->rn = (word >> 5) & 31u;
        identity->rm = (word >> 16) & 31u;
        identity->ra = 0u;
        identity->lane = (word >> 12) & 3u;
        return 1;
    }
    for (operation = 0u; operation < 7u; ++operation) {
        if ((word & UINT32_C(0xffe0fc00)) != three_values[operation]) {
            continue;
        }
        identity->form_id = three_forms[operation];
        identity->name_id = three_names[operation];
        identity->layout = three_layouts[operation];
        identity->rd = word & 31u;
        identity->rn = (word >> 5) & 31u;
        identity->rm = (word >> 16) & 31u;
        identity->ra = 0u;
        identity->lane = 0u;
        return 1;
    }
    if ((word & UINT32_C(0xffe08000)) == UINT32_C(0xce000000)
        || (word & UINT32_C(0xffe08000)) == UINT32_C(0xce200000)
        || (word & UINT32_C(0xffe08000)) == UINT32_C(0xce400000)) {
        uint32_t fixed = word & UINT32_C(0xffe08000);

        identity->form_id = fixed == UINT32_C(0xce000000)
            ? UINT16_C(6298)
            : fixed == UINT32_C(0xce200000)
                ? UINT16_C(6299) : UINT16_C(6300);
        identity->name_id = fixed == UINT32_C(0xce000000)
            ? CDISASM_ARM_NAME_EOR3
            : fixed == UINT32_C(0xce200000)
                ? CDISASM_ARM_NAME_BCAX : CDISASM_ARM_NAME_SM3SS1;
        identity->layout = fixed == UINT32_C(0xce400000)
            ? ARM_FIXED_CRYPTO_LAYOUT_VVVV4S
            : ARM_FIXED_CRYPTO_LAYOUT_VVVV16B;
        identity->rd = word & 31u;
        identity->rn = (word >> 5) & 31u;
        identity->rm = (word >> 16) & 31u;
        identity->ra = (word >> 10) & 31u;
        identity->lane = 0u;
        return 1;
    }
    if ((word & UINT32_C(0xffe00000)) == UINT32_C(0xce800000)) {
        identity->form_id = UINT16_C(6301);
        identity->name_id = CDISASM_ARM_NAME_XAR;
        identity->layout = ARM_FIXED_CRYPTO_LAYOUT_VVV2D_IMM6;
        identity->rd = word & 31u;
        identity->rn = (word >> 5) & 31u;
        identity->rm = (word >> 16) & 31u;
        identity->ra = 0u;
        identity->lane = (word >> 10) & 63u;
        return 1;
    }
    if ((word & UINT32_C(0xfffffc00)) == UINT32_C(0xcec08000)) {
        identity->form_id = UINT16_C(6302);
        identity->name_id = CDISASM_ARM_NAME_SHA512SU0;
        identity->layout = ARM_FIXED_CRYPTO_LAYOUT_VV2D;
        identity->rd = word & 31u;
        identity->rn = (word >> 5) & 31u;
        identity->rm = 0u;
        identity->ra = 0u;
        identity->lane = 0u;
        return 1;
    }
    if ((word & UINT32_C(0xfffffc00)) == UINT32_C(0xcec08400)) {
        identity->form_id = UINT16_C(6303);
        identity->name_id = CDISASM_ARM_NAME_SM4E;
        identity->layout = ARM_FIXED_CRYPTO_LAYOUT_VV4S;
        identity->rd = word & 31u;
        identity->rn = (word >> 5) & 31u;
        identity->rm = 0u;
        identity->ra = 0u;
        identity->lane = 0u;
        return 1;
    }
    return 0;
}

static int arm_is_fixed_crypto_form(cdisasm_arm_form_id form_id)
{
    return form_id >= UINT16_C(6287) && form_id <= UINT16_C(6303);
}

static int arm_is_fixed_crypto_unique_name(cdisasm_arm_name_id name_id)
{
    return name_id == CDISASM_ARM_NAME_SM3TT1A
        || name_id == CDISASM_ARM_NAME_SM3TT1B
        || name_id == CDISASM_ARM_NAME_SM3TT2A
        || name_id == CDISASM_ARM_NAME_SM3TT2B
        || name_id == CDISASM_ARM_NAME_SHA512H
        || name_id == CDISASM_ARM_NAME_SHA512H2
        || name_id == CDISASM_ARM_NAME_SHA512SU0
        || name_id == CDISASM_ARM_NAME_SHA512SU1
        || name_id == CDISASM_ARM_NAME_SM3PARTW1
        || name_id == CDISASM_ARM_NAME_SM3PARTW2
        || name_id == CDISASM_ARM_NAME_SM3SS1;
}

static int arm_is_fixed_crypto_shared_name(cdisasm_arm_name_id name_id)
{
    return name_id == CDISASM_ARM_NAME_EOR3
        || name_id == CDISASM_ARM_NAME_BCAX
        || name_id == CDISASM_ARM_NAME_XAR
        || name_id == CDISASM_ARM_NAME_RAX1
        || name_id == CDISASM_ARM_NAME_SM4E
        || name_id == CDISASM_ARM_NAME_SM4EKEY;
}

static int arm_sve_xar_identity_for_word(
    uint32_t word, uint8_t *element_size, uint8_t *immediate)
{
    unsigned encoded_immediate;
    unsigned element_bits;

    if ((word & UINT32_C(0xff20fc00)) != UINT32_C(0x04203400)) {
        return 0;
    }
    encoded_immediate = (((word >> 22) & 3u) << 5)
        | ((word >> 16) & 31u);
    if (encoded_immediate < 8u) {
        return 0;
    }
    element_bits = encoded_immediate >= 64u ? 64u
        : encoded_immediate >= 32u ? 32u
        : encoded_immediate >= 16u ? 16u : 8u;
    *element_size = (uint8_t)(element_bits / 8u);
    *immediate = (uint8_t)(2u * element_bits - encoded_immediate);
    return 1;
}

static int arm_is_exact_sve_xar(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint8_t element_size;
    uint8_t immediate;

    return instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_xar_identity_for_word(
            word, &element_size, &immediate)
        && instruction->form_id == UINT16_C(2325)
        && instruction->name_id == CDISASM_ARM_NAME_XAR
        && instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        && instruction->branch_target == 0u
        && instruction->operand_count == 3u
        && arm_exact_scalable_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + (word & 31u)), element_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_scalable_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)), element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_u8_immediate_operand(
            &instruction->operand[2], immediate)
        && cdisasm_arm_generated_form_matches(instruction);
}

static int arm_valid_sve_xar_schema(
    const cdisasm_arm_instruction *instruction)
{
    uint8_t element_size;
    uint8_t immediate;
    int raw_is_envelope = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->raw_instruction & UINT32_C(0xff20fc00))
            == UINT32_C(0x04203400);
    int raw_is_family = raw_is_envelope
        && arm_sve_xar_identity_for_word(
            instruction->raw_instruction, &element_size, &immediate);
    int form_is_family = instruction->form_id == UINT16_C(2325);
    int name_is_family = instruction->name_id == CDISASM_ARM_NAME_XAR
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_SIMD) == 0u;

    if (!raw_is_envelope && !form_is_family && !name_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && arm_is_exact_sve_xar(instruction);
}

static int arm_is_exact_sve_sibling_of_fixed_crypto(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    cdisasm_arm_reg_id zd = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (word & 31u));
    cdisasm_arm_reg_id zn = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u));
    cdisasm_arm_reg_id zm = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + ((word >> 16) & 31u));

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || instruction->opcode_size != 4u
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->branch_target != 0u) {
        return 0;
    }
    switch (instruction->name_id) {
        case CDISASM_ARM_NAME_EOR3:
            return instruction->form_id == UINT16_C(2326)
                && (word & UINT32_C(0xffe0fc00))
                    == UINT32_C(0x04203800)
                && instruction->instruction_flags
                    == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                && instruction->operand_count == 4u
                && arm_exact_scalable_operand(
                    &instruction->operand[0], zd, 8u,
                    CDISASM_OPERAND_ACCESS_WRITE)
                && arm_exact_scalable_operand(
                    &instruction->operand[1], zd, 8u,
                    CDISASM_OPERAND_ACCESS_READ)
                && arm_exact_scalable_operand(
                    &instruction->operand[2], zm, 8u,
                    CDISASM_OPERAND_ACCESS_READ)
                && arm_exact_scalable_operand(
                    &instruction->operand[3], zn, 8u,
                    CDISASM_OPERAND_ACCESS_READ);
        case CDISASM_ARM_NAME_BCAX:
            return instruction->form_id == UINT16_C(2327)
                && (word & UINT32_C(0xffe0fc00))
                    == UINT32_C(0x04603800)
                && instruction->instruction_flags
                    == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                        | CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK)
                && instruction->operand_count == 4u
                && arm_exact_scalable_operand(
                    &instruction->operand[0], zd, 8u,
                    CDISASM_OPERAND_ACCESS_READ_WRITE)
                && arm_exact_scalable_operand(
                    &instruction->operand[1], zd, 8u,
                    CDISASM_OPERAND_ACCESS_READ_WRITE)
                && arm_exact_scalable_operand(
                    &instruction->operand[2], zm, 8u,
                    CDISASM_OPERAND_ACCESS_READ)
                && arm_exact_scalable_operand(
                    &instruction->operand[3], zn, 8u,
                    CDISASM_OPERAND_ACCESS_READ);
        case CDISASM_ARM_NAME_SM4E:
            return instruction->form_id == UINT16_C(2907)
                && (word & UINT32_C(0xfffffc00))
                    == UINT32_C(0x4523e000)
                && instruction->instruction_flags
                    == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                && instruction->operand_count == 3u
                && arm_exact_scalable_operand(
                    &instruction->operand[0], zd, 4u,
                    CDISASM_OPERAND_ACCESS_READ_WRITE)
                && arm_exact_scalable_operand(
                    &instruction->operand[1], zd, 4u,
                    CDISASM_OPERAND_ACCESS_READ_WRITE)
                && arm_exact_scalable_operand(
                    &instruction->operand[2], zn, 4u,
                    CDISASM_OPERAND_ACCESS_READ);
        case CDISASM_ARM_NAME_SM4EKEY:
            return instruction->form_id == UINT16_C(2916)
                && (word & UINT32_C(0xffe0fc00))
                    == UINT32_C(0x4520f000)
                && instruction->instruction_flags
                    == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                        | CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK)
                && instruction->operand_count == 3u
                && arm_exact_scalable_operand(
                    &instruction->operand[0], zd, 4u,
                    CDISASM_OPERAND_ACCESS_WRITE)
                && arm_exact_scalable_operand(
                    &instruction->operand[1], zn, 4u,
                    CDISASM_OPERAND_ACCESS_READ)
                && arm_exact_scalable_operand(
                    &instruction->operand[2], zm, 4u,
                    CDISASM_OPERAND_ACCESS_READ);
        case CDISASM_ARM_NAME_RAX1:
            return instruction->form_id == UINT16_C(2917)
                && (word & UINT32_C(0xffe0fc00))
                    == UINT32_C(0x4520f400)
                && instruction->instruction_flags
                    == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                && instruction->operand_count == 3u
                && arm_exact_scalable_operand(
                    &instruction->operand[0], zd, 8u,
                    CDISASM_OPERAND_ACCESS_WRITE)
                && arm_exact_scalable_operand(
                    &instruction->operand[1], zn, 8u,
                    CDISASM_OPERAND_ACCESS_READ)
                && arm_exact_scalable_operand(
                    &instruction->operand[2], zm, 8u,
                    CDISASM_OPERAND_ACCESS_READ);
        case CDISASM_ARM_NAME_XAR:
            return arm_is_exact_sve_xar(instruction);
        default:
            return 0;
    }
}

static int arm_exact_fixed_crypto_vector(
    const cdisasm_arm_operand *operand, cdisasm_arm_reg_id reg,
    uint8_t element_size, cdisasm_operand_access access)
{
    return arm_exact_vector_operand(
            operand, reg, 16u, element_size, access)
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u
        && operand->address == 0u && operand->imm == 0u
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u;
}

static int arm_exact_fixed_crypto_lane(
    const cdisasm_arm_operand *operand, cdisasm_arm_reg_id reg,
    uint64_t lane)
{
    return arm_exact_vector_lane_operand(
            operand, reg, 4u, lane, CDISASM_OPERAND_ACCESS_READ)
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u && operand->address == 0u
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u;
}

static int arm_exact_fixed_crypto_immediate(
    const cdisasm_arm_operand *operand, uint64_t value)
{
    return arm_exact_u8_immediate_operand(operand, value)
        && operand->reg == CDISASM_ARM_REG_NONE
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u && operand->address == 0u
        && operand->flags == CDISASM_OPERAND_FLAG_NONE
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u
        && operand->extend_type == CDISASM_ARM_EXTEND_NONE
        && operand->scale == 0u;
}

static int arm_valid_fixed_crypto_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_fixed_crypto_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE,
        ARM_FIXED_CRYPTO_LAYOUT_NONE, 0u, 0u, 0u, 0u, 0u
    };
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_fixed_crypto_identity_for_word(
            instruction->raw_instruction, &identity);
    int form_is_family = arm_is_fixed_crypto_form(instruction->form_id);
    int name_is_family = ((instruction->instruction_flags
                & CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE) == 0u
            && arm_is_fixed_crypto_unique_name(instruction->name_id))
        || (arm_is_fixed_crypto_shared_name(instruction->name_id)
            && !arm_is_exact_sve_sibling_of_fixed_crypto(instruction));
    cdisasm_arm_reg_id rd;
    cdisasm_arm_reg_id rn;
    cdisasm_arm_reg_id rm;
    cdisasm_arm_reg_id ra;
    cdisasm_operand_access destination_access;

    /* Shared mnemonics are union-owned.  Only a complete, exact SVE sibling
     * schema is delegated; every other structured use remains fail-closed as
     * a fixed-width family claim. */
    if (!raw_is_family && !form_is_family && !name_is_family) {
        return 1;
    }
    if (!raw_is_family || !form_is_family
        || instruction->form_id != identity.form_id
        || instruction->name_id != identity.name_id
        || instruction->opcode_size != 4u
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->instruction_flags
            != CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        || instruction->branch_target != 0u) {
        return 0;
    }
    rd = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + identity.rd);
    rn = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + identity.rn);
    rm = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + identity.rm);
    ra = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + identity.ra);
    destination_access =
        identity.layout == ARM_FIXED_CRYPTO_LAYOUT_VVV2D_WRITE
            || identity.layout == ARM_FIXED_CRYPTO_LAYOUT_VVV4S_WRITE
            || identity.layout == ARM_FIXED_CRYPTO_LAYOUT_VVVV4S
            || identity.layout == ARM_FIXED_CRYPTO_LAYOUT_VVVV16B
            || identity.layout == ARM_FIXED_CRYPTO_LAYOUT_VVV2D_IMM6
        ? CDISASM_OPERAND_ACCESS_WRITE
        : CDISASM_OPERAND_ACCESS_READ_WRITE;
    if (identity.layout == ARM_FIXED_CRYPTO_LAYOUT_TT) {
        return instruction->operand_count == 3u
            && arm_exact_fixed_crypto_vector(
                &instruction->operand[0], rd, 4u, destination_access)
            && arm_exact_fixed_crypto_vector(
                &instruction->operand[1], rn, 4u,
                CDISASM_OPERAND_ACCESS_READ)
            && arm_exact_fixed_crypto_lane(
                &instruction->operand[2], rm, identity.lane);
    }
    if (identity.layout == ARM_FIXED_CRYPTO_LAYOUT_QQV2D) {
        return instruction->operand_count == 3u
            && arm_exact_fixed_crypto_vector(
                &instruction->operand[0], rd, 16u, destination_access)
            && arm_exact_fixed_crypto_vector(
                &instruction->operand[1], rn, 16u,
                CDISASM_OPERAND_ACCESS_READ)
            && arm_exact_fixed_crypto_vector(
                &instruction->operand[2], rm, 8u,
                CDISASM_OPERAND_ACCESS_READ);
    }
    if (identity.layout == ARM_FIXED_CRYPTO_LAYOUT_VVVV4S
        || identity.layout == ARM_FIXED_CRYPTO_LAYOUT_VVVV16B) {
        uint8_t element_size =
            identity.layout == ARM_FIXED_CRYPTO_LAYOUT_VVVV16B ? 1u : 4u;

        return instruction->operand_count == 4u
            && arm_exact_fixed_crypto_vector(
                &instruction->operand[0], rd, element_size,
                destination_access)
            && arm_exact_fixed_crypto_vector(
                &instruction->operand[1], rn, element_size,
                CDISASM_OPERAND_ACCESS_READ)
            && arm_exact_fixed_crypto_vector(
                &instruction->operand[2], rm, element_size,
                CDISASM_OPERAND_ACCESS_READ)
            && arm_exact_fixed_crypto_vector(
                &instruction->operand[3], ra, element_size,
                CDISASM_OPERAND_ACCESS_READ);
    }
    if (identity.layout == ARM_FIXED_CRYPTO_LAYOUT_VVV2D_IMM6) {
        return instruction->operand_count == 4u
            && arm_exact_fixed_crypto_vector(
                &instruction->operand[0], rd, 8u, destination_access)
            && arm_exact_fixed_crypto_vector(
                &instruction->operand[1], rn, 8u,
                CDISASM_OPERAND_ACCESS_READ)
            && arm_exact_fixed_crypto_vector(
                &instruction->operand[2], rm, 8u,
                CDISASM_OPERAND_ACCESS_READ)
            && arm_exact_fixed_crypto_immediate(
                &instruction->operand[3], identity.lane);
    }
    if (identity.layout == ARM_FIXED_CRYPTO_LAYOUT_VV2D
        || identity.layout == ARM_FIXED_CRYPTO_LAYOUT_VV4S) {
        uint8_t element_size =
            identity.layout == ARM_FIXED_CRYPTO_LAYOUT_VV2D ? 8u : 4u;

        return instruction->operand_count == 2u
            && arm_exact_fixed_crypto_vector(
                &instruction->operand[0], rd, element_size,
                destination_access)
            && arm_exact_fixed_crypto_vector(
                &instruction->operand[1], rn, element_size,
                CDISASM_OPERAND_ACCESS_READ);
    }
    {
        uint8_t element_size =
            identity.layout == ARM_FIXED_CRYPTO_LAYOUT_VVV2D
                || identity.layout == ARM_FIXED_CRYPTO_LAYOUT_VVV2D_WRITE
            ? 8u : 4u;

        return identity.layout == ARM_FIXED_CRYPTO_LAYOUT_VVV2D
                || identity.layout == ARM_FIXED_CRYPTO_LAYOUT_VVV2D_WRITE
                || identity.layout == ARM_FIXED_CRYPTO_LAYOUT_VVV4S
                || identity.layout == ARM_FIXED_CRYPTO_LAYOUT_VVV4S_WRITE
            ? instruction->operand_count == 3u
                && arm_exact_fixed_crypto_vector(
                    &instruction->operand[0], rd, element_size,
                    destination_access)
                && arm_exact_fixed_crypto_vector(
                    &instruction->operand[1], rn, element_size,
                    CDISASM_OPERAND_ACCESS_READ)
                && arm_exact_fixed_crypto_vector(
                    &instruction->operand[2], rm, element_size,
                    CDISASM_OPERAND_ACCESS_READ)
            : 0;
    }
}

static int arm_exact_advsimd_ext_vector_operand(
    const cdisasm_arm_operand *operand, cdisasm_arm_reg_id reg,
    uint8_t total_size, cdisasm_operand_access access)
{
    return arm_exact_vector_operand(
            operand, reg, total_size, 1u, access)
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u
        && operand->address == 0u
        && operand->imm == 0u
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u;
}

static int arm_exact_advsimd_ext_immediate_operand(
    const cdisasm_arm_operand *operand, uint64_t value)
{
    return arm_exact_u8_immediate_operand(operand, value)
        && operand->reg == CDISASM_ARM_REG_NONE
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u
        && operand->address == 0u
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u
        && operand->extend_type == CDISASM_ARM_EXTEND_NONE
        && operand->scale == 0u;
}

static int arm_valid_advsimd_ext_schema(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned q = (word >> 30) & 1u;
    unsigned imm4 = (word >> 11) & 15u;
    uint8_t total_size = q != 0u ? 16u : 8u;
    int raw_is_envelope = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (word & UINT32_C(0xbfe08400)) == UINT32_C(0x2e000000);
    int raw_is_family = raw_is_envelope && (q != 0u || imm4 < 8u);
    int form_is_family = instruction->form_id == UINT16_C(5910);
    int name_is_family = instruction->name_id == CDISASM_ARM_NAME_EXT
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR) == 0u;

    /* EXT is also an SVE/SVE2 mnemonic.  Fixed-width raw/form claims remain
     * fail-closed, while a scalable-vector object is left to its own schema. */
    if (!raw_is_envelope && !form_is_family && !name_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->opcode_size == 4u
        && instruction->name_id == CDISASM_ARM_NAME_EXT
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->branch_target == 0u
        && instruction->operand_count == 4u
        && arm_exact_advsimd_ext_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + (word & 31u)), total_size,
            CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_advsimd_ext_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)), total_size,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_advsimd_ext_vector_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 16) & 31u)), total_size,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_advsimd_ext_immediate_operand(
            &instruction->operand[3], imm4);
}

static int arm_advsimd_bitwise_select_identity_for_word(
    uint32_t word, cdisasm_arm_form_id *form_id,
    cdisasm_arm_name_id *name_id)
{
    switch (word & UINT32_C(0xbfe0fc00)) {
        case UINT32_C(0x2e601c00):
            *form_id = UINT16_C(6188);
            *name_id = CDISASM_ARM_NAME_BSL;
            return 1;
        case UINT32_C(0x2ea01c00):
            *form_id = UINT16_C(6196);
            *name_id = CDISASM_ARM_NAME_BIT;
            return 1;
        case UINT32_C(0x2ee01c00):
            *form_id = UINT16_C(6198);
            *name_id = CDISASM_ARM_NAME_BIF;
            return 1;
        default:
            return 0;
    }
}

static int arm_is_exact_generated_sve_bsl(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    cdisasm_arm_reg_id zd = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (word & 31u));

    return instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->opcode_size == 4u
        && (word & UINT32_C(0xffe0fc00)) == UINT32_C(0x04203c00)
        && instruction->form_id == UINT16_C(2328)
        && instruction->name_id == CDISASM_ARM_NAME_BSL
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
                | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR)
        && instruction->branch_target == 0u
        && instruction->operand_count == 4u
        && arm_exact_scalable_operand(
            &instruction->operand[0], zd, 8u,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_scalable_operand(
            &instruction->operand[1], zd, 8u,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_scalable_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 16) & 31u)), 8u,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_scalable_operand(
            &instruction->operand[3], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)), 8u,
            CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_advsimd_bitwise_select_schema(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    cdisasm_arm_form_id expected_form = CDISASM_ARM_FORM_NONE;
    cdisasm_arm_name_id expected_name = CDISASM_ARM_NAME_NONE;
    uint8_t total_size = (word & UINT32_C(0x40000000)) != 0u
        ? 16u : 8u;
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_advsimd_bitwise_select_identity_for_word(
            word, &expected_form, &expected_name);
    int raw_is_sve_bsl = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (word & UINT32_C(0xffe0fc00)) == UINT32_C(0x04203c00);
    int form_is_family = instruction->form_id == UINT16_C(6188)
        || instruction->form_id == UINT16_C(6196)
        || instruction->form_id == UINT16_C(6198);
    int form_is_sve_bsl = instruction->form_id == UINT16_C(2328);
    int name_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE) == 0u
        && (instruction->name_id == CDISASM_ARM_NAME_BSL
            || instruction->name_id == CDISASM_ARM_NAME_BIT
            || instruction->name_id == CDISASM_ARM_NAME_BIF);

    /* BSL is shared with a generated SVE2/SME leaf.  Own that leaf by its
     * exact raw/form envelope before applying the fixed-width AdvSIMD
     * mnemonic schema, retaining mutation protection for both families. */
    if (raw_is_sve_bsl || form_is_sve_bsl) {
        return arm_is_exact_generated_sve_bsl(instruction);
    }
    if (!raw_is_family && !form_is_family && !name_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->form_id == expected_form
        && instruction->name_id == expected_name
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->operand_count == 3u
        && arm_exact_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + (word & 31u)), total_size, 1u,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)),
            total_size, 1u, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_vector_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 16) & 31u)),
            total_size, 1u, CDISASM_OPERAND_ACCESS_READ);
}

static int arm_advsimd_high_narrow_identity_for_word(
    uint32_t word, cdisasm_arm_form_id *form_id,
    cdisasm_arm_name_id *name_id)
{
    switch (word & UINT32_C(0xbf20fc00)) {
        case UINT32_C(0x0e204000):
            *form_id = UINT16_C(6093);
            *name_id = CDISASM_ARM_NAME_ADDHN;
            return 1;
        case UINT32_C(0x0e206000):
            *form_id = UINT16_C(6095);
            *name_id = CDISASM_ARM_NAME_SUBHN;
            return 1;
        case UINT32_C(0x2e204000):
            *form_id = UINT16_C(6108);
            *name_id = CDISASM_ARM_NAME_RADDHN;
            return 1;
        case UINT32_C(0x2e206000):
            *form_id = UINT16_C(6110);
            *name_id = CDISASM_ARM_NAME_RSUBHN;
            return 1;
        default:
            return 0;
    }
}

typedef struct arm_advsimd_widening_add_sub_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    uint8_t wide_first;
} arm_advsimd_widening_add_sub_identity;

static int arm_advsimd_widening_add_sub_identity_for_word(
    uint32_t word, arm_advsimd_widening_add_sub_identity *identity)
{
    switch (word & UINT32_C(0xbf20fc00)) {
        case UINT32_C(0x0e200000):
            identity->form_id = UINT16_C(6089);
            identity->name_id = CDISASM_ARM_NAME_SADDL;
            identity->wide_first = 0u;
            return 1;
        case UINT32_C(0x0e201000):
            identity->form_id = UINT16_C(6090);
            identity->name_id = CDISASM_ARM_NAME_SADDW;
            identity->wide_first = 1u;
            return 1;
        case UINT32_C(0x0e202000):
            identity->form_id = UINT16_C(6091);
            identity->name_id = CDISASM_ARM_NAME_SSUBL;
            identity->wide_first = 0u;
            return 1;
        case UINT32_C(0x0e203000):
            identity->form_id = UINT16_C(6092);
            identity->name_id = CDISASM_ARM_NAME_SSUBW;
            identity->wide_first = 1u;
            return 1;
        case UINT32_C(0x2e200000):
            identity->form_id = UINT16_C(6104);
            identity->name_id = CDISASM_ARM_NAME_UADDL;
            identity->wide_first = 0u;
            return 1;
        case UINT32_C(0x2e201000):
            identity->form_id = UINT16_C(6105);
            identity->name_id = CDISASM_ARM_NAME_UADDW;
            identity->wide_first = 1u;
            return 1;
        case UINT32_C(0x2e202000):
            identity->form_id = UINT16_C(6106);
            identity->name_id = CDISASM_ARM_NAME_USUBL;
            identity->wide_first = 0u;
            return 1;
        case UINT32_C(0x2e203000):
            identity->form_id = UINT16_C(6107);
            identity->name_id = CDISASM_ARM_NAME_USUBW;
            identity->wide_first = 1u;
            return 1;
        default:
            return 0;
    }
}

static int arm_is_advsimd_widening_add_sub_form(
    cdisasm_arm_form_id form_id)
{
    return (form_id >= UINT16_C(6089) && form_id <= UINT16_C(6092))
        || (form_id >= UINT16_C(6104) && form_id <= UINT16_C(6107));
}

static int arm_is_advsimd_widening_add_sub_name(
    cdisasm_arm_name_id name_id)
{
    return name_id == CDISASM_ARM_NAME_SADDL
        || name_id == CDISASM_ARM_NAME_SADDW
        || name_id == CDISASM_ARM_NAME_SSUBL
        || name_id == CDISASM_ARM_NAME_SSUBW
        || name_id == CDISASM_ARM_NAME_UADDL
        || name_id == CDISASM_ARM_NAME_UADDW
        || name_id == CDISASM_ARM_NAME_USUBL
        || name_id == CDISASM_ARM_NAME_USUBW;
}

static int arm_valid_advsimd_widening_add_sub_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_advsimd_widening_add_sub_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE, 0u
    };
    uint32_t word = instruction->raw_instruction;
    unsigned size_code = (word >> 22) & 3u;
    int high = (word & UINT32_C(0x40000000)) != 0u;
    uint8_t source_element_size = (uint8_t)(UINT8_C(1) << size_code);
    uint8_t result_element_size =
        (uint8_t)(source_element_size * 2u);
    uint8_t narrow_total_size = high ? 16u : 8u;
    int raw_is_envelope = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_advsimd_widening_add_sub_identity_for_word(word, &identity);
    int raw_is_family = raw_is_envelope && size_code <= 2u;
    int form_is_family =
        arm_is_advsimd_widening_add_sub_form(instruction->form_id);
    int name_is_family =
        arm_is_advsimd_widening_add_sub_name(instruction->name_id);

    /* Raw, form, and mnemonic ownership are independent so cross-ISA,
     * form-only, name-only, opaque, and reserved-size forgeries cannot fall
     * through to the generic vector formatter. */
    if (!raw_is_envelope && !form_is_family && !name_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->operand_count == 3u
        && arm_exact_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + (word & 31u)),
            16u, result_element_size, CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)),
            identity.wide_first ? 16u : narrow_total_size,
            identity.wide_first
                ? result_element_size : source_element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_vector_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 16) & 31u)),
            narrow_total_size, source_element_size,
            CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_advsimd_absolute_difference_long_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    uint8_t accumulate;
} arm_advsimd_absolute_difference_long_identity;

static int arm_advsimd_absolute_difference_long_identity_for_word(
    uint32_t word,
    arm_advsimd_absolute_difference_long_identity *identity)
{
    switch (word & UINT32_C(0xbf20fc00)) {
        case UINT32_C(0x0e205000):
            identity->form_id = UINT16_C(6094);
            identity->name_id = CDISASM_ARM_NAME_SABAL;
            identity->accumulate = 1u;
            return 1;
        case UINT32_C(0x0e207000):
            identity->form_id = UINT16_C(6096);
            identity->name_id = CDISASM_ARM_NAME_SABDL;
            identity->accumulate = 0u;
            return 1;
        case UINT32_C(0x2e205000):
            identity->form_id = UINT16_C(6109);
            identity->name_id = CDISASM_ARM_NAME_UABAL;
            identity->accumulate = 1u;
            return 1;
        case UINT32_C(0x2e207000):
            identity->form_id = UINT16_C(6111);
            identity->name_id = CDISASM_ARM_NAME_UABDL;
            identity->accumulate = 0u;
            return 1;
        default:
            return 0;
    }
}

static int arm_is_advsimd_absolute_difference_long_form(
    cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(6094) || form_id == UINT16_C(6096)
        || form_id == UINT16_C(6109) || form_id == UINT16_C(6111);
}

static int arm_is_advsimd_absolute_difference_long_name(
    cdisasm_arm_name_id name_id)
{
    return name_id == CDISASM_ARM_NAME_SABAL
        || name_id == CDISASM_ARM_NAME_SABDL
        || name_id == CDISASM_ARM_NAME_UABAL
        || name_id == CDISASM_ARM_NAME_UABDL;
}

static int arm_is_exact_generated_sve_abal(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed;
    cdisasm_arm_form_id expected_form;
    cdisasm_arm_name_id expected_name;
    unsigned size_code = (word >> 22) & 3u;
    uint8_t source_element_size = (uint8_t)(UINT8_C(1) << size_code);
    uint8_t result_element_size = (uint8_t)(source_element_size * 2u);

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || instruction->opcode_size != 4u || size_code > 2u) {
        return 0;
    }
    fixed = word & UINT32_C(0xff20fc00);
    if (fixed == UINT32_C(0x4400d400)) {
        expected_form = UINT16_C(2709);
        expected_name = CDISASM_ARM_NAME_SABAL;
    } else if (fixed == UINT32_C(0x4400dc00)) {
        expected_form = UINT16_C(2710);
        expected_name = CDISASM_ARM_NAME_UABAL;
    } else {
        return 0;
    }
    return instruction->form_id == expected_form
        && instruction->name_id == expected_name
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
                | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR)
        && instruction->branch_target == 0u
        && instruction->operand_count == 3u
        && arm_exact_scalable_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + (word & 31u)), result_element_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_scalable_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)),
            source_element_size, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_scalable_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 16) & 31u)),
            source_element_size, CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_advsimd_absolute_difference_long_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_advsimd_absolute_difference_long_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE, 0u
    };
    uint32_t word = instruction->raw_instruction;
    unsigned size_code = (word >> 22) & 3u;
    int high = (word & UINT32_C(0x40000000)) != 0u;
    uint8_t source_element_size = (uint8_t)(UINT8_C(1) << size_code);
    uint8_t result_element_size =
        (uint8_t)(source_element_size * 2u);
    uint8_t narrow_total_size = high ? 16u : 8u;
    int raw_is_envelope = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_advsimd_absolute_difference_long_identity_for_word(
            word, &identity);
    int raw_is_family = raw_is_envelope && size_code <= 2u;
    int raw_is_sve_abal = instruction->isa_id == CDISASM_ARM_ISA_A64
        && ((word & UINT32_C(0xff20fc00)) == UINT32_C(0x4400d400)
            || (word & UINT32_C(0xff20fc00)) == UINT32_C(0x4400dc00));
    int form_is_sve_abal = instruction->form_id == UINT16_C(2709)
        || instruction->form_id == UINT16_C(2710);
    int form_is_family = arm_is_advsimd_absolute_difference_long_form(
        instruction->form_id);
    int name_is_family = arm_is_advsimd_absolute_difference_long_name(
        instruction->name_id);

    /* SABAL and UABAL are also names of generated SVE2p3/SME2p3 forms.
     * Own those leaves by raw and form independently, validating their full
     * future structured schema without adding decoder lowering for them. */
    if (raw_is_sve_abal || form_is_sve_abal) {
        return arm_is_exact_generated_sve_abal(instruction);
    }
    /* Raw, form, and mnemonic ownership are independent so cross-ISA,
     * form-only, name-only, opaque, and reserved-size forgeries cannot fall
     * through to the generic vector formatter. */
    if (!raw_is_envelope && !form_is_family && !name_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->operand_count == 3u
        && arm_exact_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + (word & 31u)),
            16u, result_element_size,
            identity.accumulate != 0u
                ? CDISASM_OPERAND_ACCESS_READ_WRITE
                : CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)),
            narrow_total_size, source_element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_vector_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 16) & 31u)),
            narrow_total_size, source_element_size,
            CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_advsimd_widening_multiply_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    uint8_t accumulate;
    uint8_t minimum_size_code;
} arm_advsimd_widening_multiply_identity;

static int arm_advsimd_widening_multiply_identity_for_word(
    uint32_t word,
    arm_advsimd_widening_multiply_identity *identity)
{
    switch (word & UINT32_C(0xbf20fc00)) {
        case UINT32_C(0x0e208000):
            identity->form_id = UINT16_C(6097);
            identity->name_id = CDISASM_ARM_NAME_SMLAL;
            identity->accumulate = 1u;
            identity->minimum_size_code = 0u;
            return 1;
        case UINT32_C(0x0e209000):
            identity->form_id = UINT16_C(6098);
            identity->name_id = CDISASM_ARM_NAME_SQDMLAL;
            identity->accumulate = 1u;
            identity->minimum_size_code = 1u;
            return 1;
        case UINT32_C(0x0e20a000):
            identity->form_id = UINT16_C(6099);
            identity->name_id = CDISASM_ARM_NAME_SMLSL;
            identity->accumulate = 1u;
            identity->minimum_size_code = 0u;
            return 1;
        case UINT32_C(0x0e20b000):
            identity->form_id = UINT16_C(6100);
            identity->name_id = CDISASM_ARM_NAME_SQDMLSL;
            identity->accumulate = 1u;
            identity->minimum_size_code = 1u;
            return 1;
        case UINT32_C(0x0e20c000):
            identity->form_id = UINT16_C(6101);
            identity->name_id = CDISASM_ARM_NAME_SMULL;
            identity->accumulate = 0u;
            identity->minimum_size_code = 0u;
            return 1;
        case UINT32_C(0x0e20d000):
            identity->form_id = UINT16_C(6102);
            identity->name_id = CDISASM_ARM_NAME_SQDMULL;
            identity->accumulate = 0u;
            identity->minimum_size_code = 1u;
            return 1;
        case UINT32_C(0x2e208000):
            identity->form_id = UINT16_C(6112);
            identity->name_id = CDISASM_ARM_NAME_UMLAL;
            identity->accumulate = 1u;
            identity->minimum_size_code = 0u;
            return 1;
        case UINT32_C(0x2e20a000):
            identity->form_id = UINT16_C(6113);
            identity->name_id = CDISASM_ARM_NAME_UMLSL;
            identity->accumulate = 1u;
            identity->minimum_size_code = 0u;
            return 1;
        case UINT32_C(0x2e20c000):
            identity->form_id = UINT16_C(6114);
            identity->name_id = CDISASM_ARM_NAME_UMULL;
            identity->accumulate = 0u;
            identity->minimum_size_code = 0u;
            return 1;
        default:
            return 0;
    }
}

static int arm_is_advsimd_widening_multiply_form(
    cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(6097) || form_id == UINT16_C(6098)
        || form_id == UINT16_C(6099) || form_id == UINT16_C(6100)
        || form_id == UINT16_C(6101) || form_id == UINT16_C(6102)
        || form_id == UINT16_C(6112) || form_id == UINT16_C(6113)
        || form_id == UINT16_C(6114);
}

static int arm_valid_advsimd_scalar_saturating_widening_multiply_schema(
    const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction,op=w&UINT32_C(0xff20fc00);unsigned sc=(w>>22)&3,rm=(w>>16)&31,rn=(w>>5)&31,rd=w&31,index=op==UINT32_C(0x5e209000)?0u:op==UINT32_C(0x5e20b000)?1u:2u;int envelope=op==UINT32_C(0x5e209000)||op==UINT32_C(0x5e20b000)||op==UINT32_C(0x5e20d000),raw=i->isa_id==CDISASM_ARM_ISA_A64&&envelope&&(sc==1||sc==2),form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=5819&&i->form_id<=5821;uint8_t ss=(uint8_t)(1u<<sc),ds=(uint8_t)(ss*2u);static const cdisasm_arm_name_id names[3]={CDISASM_ARM_NAME_SQDMLAL,CDISASM_ARM_NAME_SQDMLSL,CDISASM_ARM_NAME_SQDMULL};static const cdisasm_arm_reg_id bases[3]={CDISASM_ARM_REG_H0,CDISASM_ARM_REG_S0,CDISASM_ARM_REG_D0};const cdisasm_arm_operand*d=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];if(!envelope&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==names[index]&&i->form_id==5819+index&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==CDISASM_ARM_INSTRUCTION_FLAG_SIMD&&i->operand_count==3&&d->type==CDISASM_OPERAND_REGISTER&&d->reg==bases[sc]+rd&&d->size==ds&&d->extend_type==ds&&d->scale==1&&d->access==(index<2?CDISASM_OPERAND_ACCESS_READ_WRITE:CDISASM_OPERAND_ACCESS_WRITE)&&n->type==CDISASM_OPERAND_REGISTER&&n->reg==bases[sc-1]+rn&&n->size==ss&&n->extend_type==ss&&n->scale==1&&n->access==CDISASM_OPERAND_ACCESS_READ&&m->type==CDISASM_OPERAND_REGISTER&&m->reg==bases[sc-1]+rm&&m->size==ss&&m->extend_type==ss&&m->scale==1&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_advsimd_scalar_immediate_shift_convert_schema(
    const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction,op=w&UINT32_C(0xff80fc00);unsigned enc=(w>>16)&127u,bits=enc>=64?64:enc>=32?32:enc>=16?16:8,rd=w&31,rn=(w>>5)&31,index;int cvt=op==UINT32_C(0x5f00e400)||op==UINT32_C(0x5f00fc00)||op==UINT32_C(0x7f00e400)||op==UINT32_C(0x7f00fc00);static const uint32_t ops[7]={UINT32_C(0x5f007400),UINT32_C(0x5f00e400),UINT32_C(0x5f00fc00),UINT32_C(0x7f006400),UINT32_C(0x7f007400),UINT32_C(0x7f00e400),UINT32_C(0x7f00fc00)};static const cdisasm_arm_name_id names[7]={CDISASM_ARM_NAME_SQSHL,CDISASM_ARM_NAME_SCVTF,CDISASM_ARM_NAME_FCVTZS,CDISASM_ARM_NAME_SQSHLU,CDISASM_ARM_NAME_UQSHL,CDISASM_ARM_NAME_UCVTF,CDISASM_ARM_NAME_FCVTZU};static const uint16_t forms[7]={5858,5861,5862,5869,5870,5875,5876};static const cdisasm_arm_reg_id bases[4]={CDISASM_ARM_REG_B0,CDISASM_ARM_REG_H0,CDISASM_ARM_REG_S0,CDISASM_ARM_REG_D0};uint8_t es=(uint8_t)(bits/8);uint64_t imm=cvt?2u*bits-enc:enc-bits;const cdisasm_arm_operand*d=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];int form=0;
    for(index=0;index<7;++index)if(i->form_id==forms[index])form=1;
    for(index=0;index<7&&ops[index]!=op;++index){}
    if(index==7&&!form)return 1;
    if(index==7||enc<8||(cvt&&enc<32)||i->form_id!=forms[index])return 0;
    return i->isa_id==CDISASM_ARM_ISA_A64&&i->name_id==names[index]&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SIMD|(cvt?CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT:0))&&i->operand_count==3&&d->type==CDISASM_OPERAND_REGISTER&&d->reg==bases[bits==8?0:bits==16?1:bits==32?2:3]+rd&&d->size==es&&d->extend_type==es&&d->scale==1&&d->access==CDISASM_OPERAND_ACCESS_WRITE&&n->type==CDISASM_OPERAND_REGISTER&&n->reg==bases[bits==8?0:bits==16?1:bits==32?2:3]+rn&&n->size==es&&n->extend_type==es&&n->scale==1&&n->access==CDISASM_OPERAND_ACCESS_READ&&m->type==CDISASM_OPERAND_IMMEDIATE&&m->imm==imm&&m->size==1&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_advsimd_scalar_sqrdml_accumulate_schema(
    const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;unsigned sc=(w>>22)&3u,rd=w&31u,rn=(w>>5)&31u,rm=(w>>16)&31u;int sub=(w&UINT32_C(0x800))!=0u,envelope=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0xff20f400))==UINT32_C(0x7e008400),form=i->isa_id==CDISASM_ARM_ISA_A64&&(i->form_id==5771||i->form_id==5772);uint8_t es=(uint8_t)(1u<<sc);cdisasm_arm_reg_id base=sc==1?CDISASM_ARM_REG_H0:CDISASM_ARM_REG_S0;const cdisasm_arm_operand*d=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];
    if(!envelope&&!form)return 1;if(!envelope||!form||(sc!=1&&sc!=2))return 0;
    return i->form_id==(sub?5772:5771)&&i->name_id==(sub?CDISASM_ARM_NAME_SQRDMLSH:CDISASM_ARM_NAME_SQRDMLAH)&&i->opcode_size==4&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==CDISASM_ARM_INSTRUCTION_FLAG_SIMD&&i->branch_target==0&&i->operand_count==3&&d->type==CDISASM_OPERAND_REGISTER&&d->reg==base+rd&&d->size==es&&d->extend_type==es&&d->scale==1&&d->access==CDISASM_OPERAND_ACCESS_READ_WRITE&&n->type==CDISASM_OPERAND_REGISTER&&n->reg==base+rn&&n->size==es&&n->extend_type==es&&n->scale==1&&n->access==CDISASM_OPERAND_ACCESS_READ&&m->type==CDISASM_OPERAND_REGISTER&&m->reg==base+rm&&m->size==es&&m->extend_type==es&&m->scale==1&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_scalar_by_element_identity(uint32_t w,uint16_t*f,cdisasm_arm_name_id*n)
{
    static const uint32_t m[15]={0xff00f400,0xff00f400,0xff00f400,0xff00f400,0xff00f400,0xffc0f400,0xffc0f400,0xffc0f400,0xff80f400,0xff80f400,0xff80f400,0xff00f400,0xff00f400,0xffc0f400,0xff80f400};static const uint32_t v[15]={0x5f003000,0x5f007000,0x5f00b000,0x5f00c000,0x5f00d000,0x5f001000,0x5f005000,0x5f009000,0x5f801000,0x5f805000,0x5f809000,0x7f00d000,0x7f00f000,0x7f009000,0x7f809000};static const cdisasm_arm_name_id names[15]={CDISASM_ARM_NAME_SQDMLAL,CDISASM_ARM_NAME_SQDMLSL,CDISASM_ARM_NAME_SQDMULL,CDISASM_ARM_NAME_SQDMULH,CDISASM_ARM_NAME_SQRDMULH,CDISASM_ARM_NAME_FMLA,CDISASM_ARM_NAME_FMLS,CDISASM_ARM_NAME_FMUL,CDISASM_ARM_NAME_FMLA,CDISASM_ARM_NAME_FMLS,CDISASM_ARM_NAME_FMUL,CDISASM_ARM_NAME_SQRDMLAH,CDISASM_ARM_NAME_SQRDMLSH,CDISASM_ARM_NAME_FMULX,CDISASM_ARM_NAME_FMULX};unsigned x;for(x=0;x<15;x++)if((w&m[x])==v[x]){*f=(uint16_t)(5877+x);*n=names[x];return (int)x;}return -1;
}

static int arm_valid_advsimd_scalar_by_element_schema(const cdisasm_arm_instruction*i)
{
    uint16_t form=0;cdisasm_arm_name_id name=CDISASM_ARM_NAME_NONE;uint32_t w=i->raw_instruction;int op=arm_scalar_by_element_identity(w,&form,&name),form_claim=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=5877&&i->form_id<=5891;unsigned sc=(w>>22)&3u,precision=(w>>22)&1u,rd=w&31u,rn=(w>>5)&31u,rm,lane;int fh=(op>=5&&op<=7)||op==13,fs=(op>=8&&op<=10)||op==14;uint8_t ss=fh?2u:fs?(uint8_t)(4u<<precision):(uint8_t)(1u<<sc),ds=op<=2?ss*2u:ss;cdisasm_arm_reg_id sb=ss==2?CDISASM_ARM_REG_H0:ss==4?CDISASM_ARM_REG_S0:CDISASM_ARM_REG_D0,db=ds==2?CDISASM_ARM_REG_H0:ds==4?CDISASM_ARM_REG_S0:CDISASM_ARM_REG_D0;cdisasm_operand_access da=(op==0||op==1||op==5||op==6||op==8||op==9||op==11||op==12)?CDISASM_OPERAND_ACCESS_READ_WRITE:CDISASM_OPERAND_ACCESS_WRITE;const cdisasm_arm_operand*d=&i->operand[0],*s=&i->operand[1],*e=&i->operand[2];
    if(op<0&&!form_claim)return 1;if(op<0||!form_claim||(!fh&&!fs&&(sc!=1&&sc!=2))||(fs&&precision==1&&(w&0x00200000)))return 0;if(ss==2){rm=(w>>16)&15;lane=((w>>11)&1)*4+((w>>21)&1)*2+((w>>20)&1);}else if(ss==4){rm=(w>>16)&31;lane=((w>>11)&1)*2+((w>>21)&1);}else{rm=(w>>16)&31;lane=(w>>11)&1;}
    return i->form_id==form&&i->name_id==name&&i->opcode_size==4&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SIMD|((fh||fs)?CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT:0))&&i->branch_target==0&&i->operand_count==3&&d->type==CDISASM_OPERAND_REGISTER&&d->reg==db+rd&&d->size==ds&&d->extend_type==ds&&d->scale==1&&d->access==da&&s->type==CDISASM_OPERAND_REGISTER&&s->reg==sb+rn&&s->size==ss&&s->extend_type==ss&&s->scale==1&&s->access==CDISASM_OPERAND_ACCESS_READ&&arm_exact_vector_lane_operand(e,(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rm),ss,lane,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_advsimd_table_lookup_schema(
    const cdisasm_arm_instruction *i)
{
    uint32_t w = i->raw_instruction;
    int envelope = i->isa_id == CDISASM_ARM_ISA_A64
        && (w & UINT32_C(0xbfe08c00)) == UINT32_C(0x0e000000);
    int form_claim = i->isa_id == CDISASM_ARM_ISA_A64
        && i->form_id >= UINT16_C(5892) && i->form_id <= UINT16_C(5899);
    unsigned control = (w >> 12) & 7u;
    unsigned vd = w & 31u, vn = (w >> 5) & 31u, vm = (w >> 16) & 31u;
    unsigned count = (control >> 1) + 1u;
    uint8_t vector_size = (w & UINT32_C(0x40000000)) != 0u ? 16u : 8u;
    int extending = (control & 1u) != 0;
    const cdisasm_arm_operand *d = &i->operand[0];
    const cdisasm_arm_operand *t = &i->operand[1];
    const cdisasm_arm_operand *m = &i->operand[2];

    if (!envelope && !form_claim) return 1;
    if (!envelope || !form_claim) return 0;
    return i->form_id == UINT16_C(5892) + control
        && i->name_id == (extending ? CDISASM_ARM_NAME_TBX
                                   : CDISASM_ARM_NAME_TBL)
        && i->opcode_size == 4u
        && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && i->branch_target == 0u && i->operand_count == 3u
        && d->type == CDISASM_OPERAND_REGISTER
        && d->reg == CDISASM_ARM_REG_V0 + vd
        && d->size == vector_size && d->extend_type == 1u
        && d->scale == vector_size
        && d->access == (extending ? CDISASM_OPERAND_ACCESS_READ_WRITE
                                   : CDISASM_OPERAND_ACCESS_WRITE)
        && t->type == CDISASM_ARM_OPERAND_VECTOR_REGISTER_LIST
        && t->reg == CDISASM_ARM_REG_V0 + vn
        && t->register_list == count && t->size == 16u
        && t->extend_type == 1u && t->scale == 16u
        && t->access == CDISASM_OPERAND_ACCESS_READ
        && m->type == CDISASM_OPERAND_REGISTER
        && m->reg == CDISASM_ARM_REG_V0 + vm
        && m->size == vector_size && m->extend_type == 1u
        && m->scale == vector_size
        && m->access == CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_advsimd_dot_rdm_three_same_schema(
    const cdisasm_arm_instruction *i)
{
    static const uint32_t values[4] = {
        UINT32_C(0x0e009400), UINT32_C(0x2e008400),
        UINT32_C(0x2e008c00), UINT32_C(0x2e009400)
    };
    static const uint16_t forms[4] = { 5975, 5982, 5983, 5984 };
    static const cdisasm_arm_name_id names[4] = {
        CDISASM_ARM_NAME_SDOT, CDISASM_ARM_NAME_SQRDMLAH,
        CDISASM_ARM_NAME_SQRDMLSH, CDISASM_ARM_NAME_UDOT
    };
    uint32_t w = i->raw_instruction;
    uint32_t operation = w & UINT32_C(0xbf20fc00);
    unsigned index, size = (w >> 22) & 3u;
    int form_claim = i->isa_id == CDISASM_ARM_ISA_A64
        && (i->form_id == 5975 || (i->form_id >= 5982 && i->form_id <= 5984));
    uint8_t total_size = (w & UINT32_C(0x40000000)) != 0u ? 16u : 8u;
    uint8_t source_size;
    unsigned rd = w & 31u, rn = (w >> 5) & 31u, rm = (w >> 16) & 31u;

    for (index = 0u; index < 4u && operation != values[index]; ++index) {}
    if (index == 4u && !form_claim) return 1;
    if (index == 4u || !form_claim
        || ((index == 0u || index == 3u) ? size != 2u
                                         : (size != 1u && size != 2u))) return 0;
    source_size = (index == 0u || index == 3u)
        ? 1u : (uint8_t)(1u << size);
    return i->form_id == forms[index] && i->name_id == names[index]
        && i->opcode_size == 4u && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && i->branch_target == 0u && i->operand_count == 3u
        && arm_exact_vector_operand(&i->operand[0],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rd), total_size,
            (index == 0u || index == 3u) ? 4u : source_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_vector_operand(&i->operand[1],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rn), total_size,
            source_size, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_vector_operand(&i->operand[2],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rm), total_size,
            source_size, CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_advsimd_extended_dot_three_same_schema(
    const cdisasm_arm_instruction *i)
{
    static const uint32_t values[5] = {
        UINT32_C(0x0e00fc00), UINT32_C(0x0e40fc00),
        UINT32_C(0x0e809c00), UINT32_C(0x2e40fc00),
        UINT32_C(0x0e80fc00)
    };
    static const uint16_t forms[5] = { 5977, 5979, 5980, 5987, 5981 };
    static const cdisasm_arm_name_id names[5] = {
        CDISASM_ARM_NAME_FDOT, CDISASM_ARM_NAME_FDOT,
        CDISASM_ARM_NAME_USDOT, CDISASM_ARM_NAME_BFDOT,
        CDISASM_ARM_NAME_FDOT
    };
    uint32_t w = i->raw_instruction;
    uint32_t operation = w & UINT32_C(0xbfe0fc00);
    unsigned index, rd = w & 31u, rn = (w >> 5) & 31u;
    unsigned rm = (w >> 16) & 31u;
    int form_claim = i->isa_id == CDISASM_ARM_ISA_A64
        && (i->form_id == 5977 || i->form_id == 5979
            || i->form_id == 5980 || i->form_id == 5987
            || i->form_id == 5981);
    uint8_t total_size = (w & UINT32_C(0x40000000)) != 0u ? 16u : 8u;
    uint8_t destination_size, source_size;

    for (index = 0u; index < 5u && operation != values[index]; ++index) {}
    if (index == 5u && !form_claim) return 1;
    if (index == 5u || !form_claim) return 0;
    destination_size = index == 1u ? 2u : 4u;
    source_size = index == 3u || index == 4u ? 2u : 1u;
    return i->form_id == forms[index] && i->name_id == names[index]
        && i->opcode_size == 4u && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | (index == 2u ? 0u : CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT))
        && i->branch_target == 0u && i->operand_count == 3u
        && arm_exact_vector_operand(&i->operand[0],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rd), total_size,
            destination_size, CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_vector_operand(&i->operand[1],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rn), total_size,
            source_size, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_vector_operand(&i->operand[2],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rm), total_size,
            source_size, CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_advsimd_widening_fp_three_same_schema(
    const cdisasm_arm_instruction *i)
{
    static const uint32_t masks[6] = {
        UINT32_C(0xbfe0fc00), UINT32_C(0xffe0fc00), UINT32_C(0xffe0fc00),
        UINT32_C(0xffe0fc00), UINT32_C(0xffe0fc00), UINT32_C(0xffe0fc00)
    };
    static const uint32_t values[6] = {
        UINT32_C(0x2ec0fc00), UINT32_C(0x0e00c400), UINT32_C(0x0e40c400),
        UINT32_C(0x0ec0fc00), UINT32_C(0x4e00c400), UINT32_C(0x4e40c400)
    };
    static const cdisasm_arm_name_id names[6] = {
        CDISASM_ARM_NAME_BFMLAL, CDISASM_ARM_NAME_FMLALLBB,
        CDISASM_ARM_NAME_FMLALLBT, CDISASM_ARM_NAME_FMLALB,
        CDISASM_ARM_NAME_FMLALLTB, CDISASM_ARM_NAME_FMLALLTT
    };
    uint32_t w = i->raw_instruction;
    unsigned index, rd = w & 31u, rn = (w >> 5) & 31u;
    unsigned rm = (w >> 16) & 31u;
    int form_claim = i->isa_id == CDISASM_ARM_ISA_A64
        && i->form_id >= 5988 && i->form_id <= 5993;
    for (index = 0u; index < 6u
            && (w & masks[index]) != values[index]; ++index) {}
    if (index == 6u && !form_claim) return 1;
    if (index == 6u || !form_claim) return 0;
    return i->form_id == 5988u + index && i->name_id == names[index]
        && i->opcode_size == 4u && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)
        && i->branch_target == 0u && i->operand_count == 3u
        && arm_exact_vector_operand(&i->operand[0],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rd), 16u,
            index == 3u ? 2u : 4u, CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_vector_operand(&i->operand[1],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rn), 16u,
            index == 0u ? 2u : 1u, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_vector_operand(&i->operand[2],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rm), 16u,
            index == 0u ? 2u : 1u, CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_advsimd_i8mm_mmla_schema(
    const cdisasm_arm_instruction *i)
{
    static const uint32_t values[3] = {
        UINT32_C(0x4e80a400), UINT32_C(0x4e80ac00), UINT32_C(0x6e80a400)
    };
    static const uint16_t forms[3] = { 5994, 5995, 6002 };
    static const cdisasm_arm_name_id names[3] = {
        CDISASM_ARM_NAME_SMMLA, CDISASM_ARM_NAME_USMMLA,
        CDISASM_ARM_NAME_UMMLA
    };
    uint32_t w = i->raw_instruction;
    uint32_t operation = w & UINT32_C(0xffe0fc00);
    unsigned index, rd = w & 31u, rn = (w >> 5) & 31u;
    unsigned rm = (w >> 16) & 31u;
    int form_claim = i->isa_id == CDISASM_ARM_ISA_A64
        && (i->form_id == 5994 || i->form_id == 5995 || i->form_id == 6002);
    for (index = 0u; index < 3u && operation != values[index]; ++index) {}
    if (index == 3u && !form_claim) return 1;
    if (index == 3u || !form_claim) return 0;
    return i->form_id == forms[index] && i->name_id == names[index]
        && i->opcode_size == 4u && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && i->branch_target == 0u && i->operand_count == 3u
        && arm_exact_vector_operand(&i->operand[0],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rd), 16u, 4u,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_vector_operand(&i->operand[1],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rn), 16u, 1u,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_vector_operand(&i->operand[2],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rm), 16u, 1u,
            CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_advsimd_matrix_fp_three_same_schema(
    const cdisasm_arm_instruction *i)
{
    static const uint32_t values[6] = {
        UINT32_C(0x4ec0fc00), UINT32_C(0x6e00ec00),
        UINT32_C(0x6e40ec00), UINT32_C(0x6e80ec00),
        UINT32_C(0x4ec0ec00), UINT32_C(0x4e40ec00)
    };
    static const uint16_t forms[6] = { 5997, 5998, 6000, 6001, 5996, 5999 };
    static const cdisasm_arm_name_id names[6] = {
        CDISASM_ARM_NAME_FMLALT, CDISASM_ARM_NAME_FMMLA,
        CDISASM_ARM_NAME_BFMMLA, CDISASM_ARM_NAME_FMMLA,
        CDISASM_ARM_NAME_FMMLA, CDISASM_ARM_NAME_FMMLA
    };
    uint32_t w = i->raw_instruction;
    uint32_t operation = w & UINT32_C(0xffe0fc00);
    unsigned index, rd = w & 31u, rn = (w >> 5) & 31u;
    unsigned rm = (w >> 16) & 31u;
    int form_claim = i->isa_id == CDISASM_ARM_ISA_A64
        && (i->form_id == 5997 || i->form_id == 5998
            || i->form_id == 6000 || i->form_id == 6001
            || i->form_id == 5996 || i->form_id == 5999);
    uint8_t destination_size, source_size;
    for (index = 0u; index < 6u && operation != values[index]; ++index) {}
    if (index == 6u && !form_claim) return 1;
    if (index == 6u || !form_claim) return 0;
    destination_size = index < 2u || index == 4u ? 2u : 4u;
    source_size = index == 2u || index >= 4u ? 2u : 1u;
    return i->form_id == forms[index] && i->name_id == names[index]
        && i->opcode_size == 4u && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)
        && i->branch_target == 0u && i->operand_count == 3u
        && arm_exact_vector_operand(&i->operand[0],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rd), 16u,
            destination_size, CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_vector_operand(&i->operand[1],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rn), 16u,
            source_size, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_vector_operand(&i->operand[2],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rm), 16u,
            source_size, CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_advsimd_fp_convert_vector_schema(
    const cdisasm_arm_instruction *i)
{
    static const uint32_t values[12] = {
        UINT32_C(0x0e217800), UINT32_C(0x0e218800),
        UINT32_C(0x0e219800), UINT32_C(0x0e21d800),
        UINT32_C(0x0ea18800), UINT32_C(0x0ea19800),
        UINT32_C(0x0ea1b800), UINT32_C(0x2e218800),
        UINT32_C(0x2e219800), UINT32_C(0x2e21d800),
        UINT32_C(0x2ea19800), UINT32_C(0x2ea1b800)
    };
    static const uint16_t forms[12] = {
        6018, 6019, 6020, 6024, 6031, 6032,
        6034, 6051, 6052, 6056, 6066, 6068
    };
    static const cdisasm_arm_name_id names[12] = {
        CDISASM_ARM_NAME_FCVTL, CDISASM_ARM_NAME_FRINTN,
        CDISASM_ARM_NAME_FRINTM, CDISASM_ARM_NAME_SCVTF,
        CDISASM_ARM_NAME_FRINTP, CDISASM_ARM_NAME_FRINTZ,
        CDISASM_ARM_NAME_FCVTZS, CDISASM_ARM_NAME_FRINTA,
        CDISASM_ARM_NAME_FRINTX, CDISASM_ARM_NAME_UCVTF,
        CDISASM_ARM_NAME_FRINTI, CDISASM_ARM_NAME_FCVTZU
    };
    uint32_t w = i->raw_instruction;
    uint32_t operation = w & UINT32_C(0xbfbffc00);
    unsigned index, rd = w & 31u, rn = (w >> 5) & 31u;
    int form_claim = i->isa_id == CDISASM_ARM_ISA_A64
        && i->form_id >= UINT16_C(6018) && i->form_id <= UINT16_C(6068);
    int owned_form = 0;
    uint8_t total_size = (w & UINT32_C(0x40000000)) != 0u ? 16u : 8u;
    uint8_t element_size = (w & UINT32_C(0x00400000)) != 0u ? 8u : 4u;

    for (index = 0u; index < 12u; ++index) {
        if (i->form_id == forms[index]) owned_form = 1;
        if (operation == values[index]) break;
    }
    form_claim = form_claim && owned_form;
    if (index == 12u && !form_claim) return 1;
    if (index == 12u || !form_claim) return 0;
    if (i->form_id != forms[index] || i->name_id != names[index]
        || i->opcode_size != 4u || i->condition != CDISASM_ARM_CONDITION_AL
        || i->opcode_groups != CDISASM_GROUP_NONE
        || i->instruction_flags != (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)
        || i->branch_target != 0u || i->operand_count != 2u) return 0;
    if (index == 0u) {
        uint8_t source_element_size = element_size == 8u ? 4u : 2u;
        return arm_exact_vector_operand(&i->operand[0],
                (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rd), 16u,
                (uint8_t)(source_element_size * 2u),
                CDISASM_OPERAND_ACCESS_WRITE)
            && arm_exact_vector_operand(&i->operand[1],
                (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rn), total_size,
                source_element_size,
                CDISASM_OPERAND_ACCESS_READ);
    }
    return arm_exact_vector_operand(&i->operand[0],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rd), total_size,
            element_size, CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_vector_operand(&i->operand[1],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rn), total_size,
            element_size, CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_advsimd_fp8_fcvtl_vector_schema(
    const cdisasm_arm_instruction *i)
{
    static const uint16_t forms[4] = {6060,6062,6072,6073};
    static const cdisasm_arm_name_id names[4] = {
        CDISASM_ARM_NAME_F1CVTL,CDISASM_ARM_NAME_F2CVTL,
        CDISASM_ARM_NAME_BF1CVTL,CDISASM_ARM_NAME_BF2CVTL};
    uint32_t w=i->raw_instruction, op=w&UINT32_C(0xbffffc00);
    unsigned index=(w>>22)&3u,rd=w&31u,rn=(w>>5)&31u;
    int raw=i->isa_id==CDISASM_ARM_ISA_A64
        && (op==UINT32_C(0x2e217800)||op==UINT32_C(0x2e617800)
            ||op==UINT32_C(0x2ea17800)||op==UINT32_C(0x2ee17800));
    int form=i->form_id==6060||i->form_id==6062||i->form_id==6072||i->form_id==6073;
    uint8_t source_size=(w&UINT32_C(0x40000000))?16u:8u;
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->form_id==forms[index]&&i->name_id==names[index]
        &&i->opcode_size==4u&&i->condition==CDISASM_ARM_CONDITION_AL
        &&i->opcode_groups==CDISASM_GROUP_NONE
        &&i->instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SIMD|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)
        &&i->branch_target==0u&&i->operand_count==2u
        &&arm_exact_vector_operand(&i->operand[0],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rd),16u,2u,CDISASM_OPERAND_ACCESS_WRITE)
        &&arm_exact_vector_operand(&i->operand[1],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rn),source_size,1u,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_advsimd_fhm_three_same_schema(
    const cdisasm_arm_instruction *i)
{
    uint32_t w = i->raw_instruction;
    uint32_t operation = w & UINT32_C(0xbfe0fc00);
    unsigned rd = w & 31u, rn = (w >> 5) & 31u, rm = (w >> 16) & 31u;
    int subtract = operation == UINT32_C(0x0ea0ec00)
        || operation == UINT32_C(0x2ea0cc00);
    int upper = operation == UINT32_C(0x2e20cc00)
        || operation == UINT32_C(0x2ea0cc00);
    int raw = i->isa_id == CDISASM_ARM_ISA_A64
        && (operation == UINT32_C(0x0e20ec00)
            || operation == UINT32_C(0x0ea0ec00)
            || operation == UINT32_C(0x2e20cc00)
            || operation == UINT32_C(0x2ea0cc00));
    int form = i->form_id == UINT16_C(6146)
        || i->form_id == UINT16_C(6155)
        || i->form_id == UINT16_C(6187)
        || i->form_id == UINT16_C(6197);
    uint8_t total_size = (w & UINT32_C(0x40000000)) != 0u ? 16u : 8u;
    if (!raw && !form) return 1;
    if (!raw || !form) return 0;
    return i->form_id == (upper
            ? (subtract ? UINT16_C(6197) : UINT16_C(6187))
            : (subtract ? UINT16_C(6155) : UINT16_C(6146)))
        && i->name_id == (upper
            ? (subtract ? CDISASM_ARM_NAME_FMLSL2 : CDISASM_ARM_NAME_FMLAL2)
            : (subtract ? CDISASM_ARM_NAME_FMLSL : CDISASM_ARM_NAME_FMLAL))
        && i->opcode_size == 4u && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)
        && i->branch_target == 0u && i->operand_count == 3u
        && arm_exact_vector_operand(&i->operand[0],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rd), total_size, 4u,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_vector_operand(&i->operand[1],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rn),
            (uint8_t)(total_size / 2u), 2u, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_vector_operand(&i->operand[2],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + rm),
            (uint8_t)(total_size / 2u), 2u, CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_advsimd_fhm_by_element_schema(
    const cdisasm_arm_instruction *i)
{
    static const uint32_t values[4] = {
        UINT32_C(0x0f800000), UINT32_C(0x0f804000),
        UINT32_C(0x2f808000), UINT32_C(0x2f80c000)};
    static const uint16_t forms[4] = {6264,6265,6279,6280};
    static const cdisasm_arm_name_id names[4] = {
        CDISASM_ARM_NAME_FMLAL,CDISASM_ARM_NAME_FMLSL,
        CDISASM_ARM_NAME_FMLAL2,CDISASM_ARM_NAME_FMLSL2};
    uint32_t w=i->raw_instruction,op=w&UINT32_C(0xbfc0f400);
    unsigned index,rd=w&31u,rn=(w>>5)&31u,rm=(w>>16)&15u;
    uint64_t lane=(uint64_t)(((w>>11)&1u)<<2)
        |(uint64_t)(((w>>21)&1u)<<1)|(uint64_t)((w>>20)&1u);
    uint8_t ds=(w&UINT32_C(0x40000000))?16u:8u;
    int form=i->form_id==6264||i->form_id==6265||i->form_id==6279||i->form_id==6280;
    for(index=0;index<4u&&op!=values[index];++index){}
    if(index==4u&&!form)return 1;if(index==4u||!form)return 0;
    return i->form_id==forms[index]&&i->name_id==names[index]
        &&i->opcode_size==4u&&i->condition==CDISASM_ARM_CONDITION_AL
        &&i->opcode_groups==CDISASM_GROUP_NONE
        &&i->instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SIMD|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)
        &&i->branch_target==0u&&i->operand_count==3u
        &&arm_exact_vector_operand(&i->operand[0],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rd),ds,4u,CDISASM_OPERAND_ACCESS_READ_WRITE)
        &&arm_exact_vector_operand(&i->operand[1],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rn),(uint8_t)(ds/2u),2u,CDISASM_OPERAND_ACCESS_READ)
        &&arm_exact_vector_lane_operand(&i->operand[2],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rm),2u,lane,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_is_advsimd_widening_multiply_element_form(
    cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(6243) || form_id == UINT16_C(6244)
        || form_id == UINT16_C(6245) || form_id == UINT16_C(6246)
        || form_id == UINT16_C(6248) || form_id == UINT16_C(6249)
        || form_id == UINT16_C(6269) || form_id == UINT16_C(6271)
        || form_id == UINT16_C(6272);
}

static int arm_advsimd_widening_multiply_element_identity_for_word(
    uint32_t word,
    arm_advsimd_widening_multiply_identity *identity)
{
    switch (word & UINT32_C(0xbf00f400)) {
        case UINT32_C(0x0f002000):
            identity->form_id = UINT16_C(6243);
            identity->name_id = CDISASM_ARM_NAME_SMLAL;
            identity->accumulate = 1u;
            identity->minimum_size_code = 1u;
            return 1;
        case UINT32_C(0x0f003000):
            identity->form_id = UINT16_C(6244);
            identity->name_id = CDISASM_ARM_NAME_SQDMLAL;
            identity->accumulate = 1u;
            identity->minimum_size_code = 1u;
            return 1;
        case UINT32_C(0x0f006000):
            identity->form_id = UINT16_C(6245);
            identity->name_id = CDISASM_ARM_NAME_SMLSL;
            identity->accumulate = 1u;
            identity->minimum_size_code = 1u;
            return 1;
        case UINT32_C(0x0f007000):
            identity->form_id = UINT16_C(6246);
            identity->name_id = CDISASM_ARM_NAME_SQDMLSL;
            identity->accumulate = 1u;
            identity->minimum_size_code = 1u;
            return 1;
        case UINT32_C(0x0f00a000):
            identity->form_id = UINT16_C(6248);
            identity->name_id = CDISASM_ARM_NAME_SMULL;
            identity->accumulate = 0u;
            identity->minimum_size_code = 1u;
            return 1;
        case UINT32_C(0x0f00b000):
            identity->form_id = UINT16_C(6249);
            identity->name_id = CDISASM_ARM_NAME_SQDMULL;
            identity->accumulate = 0u;
            identity->minimum_size_code = 1u;
            return 1;
        case UINT32_C(0x2f002000):
            identity->form_id = UINT16_C(6269);
            identity->name_id = CDISASM_ARM_NAME_UMLAL;
            identity->accumulate = 1u;
            identity->minimum_size_code = 1u;
            return 1;
        case UINT32_C(0x2f006000):
            identity->form_id = UINT16_C(6271);
            identity->name_id = CDISASM_ARM_NAME_UMLSL;
            identity->accumulate = 1u;
            identity->minimum_size_code = 1u;
            return 1;
        case UINT32_C(0x2f00a000):
            identity->form_id = UINT16_C(6272);
            identity->name_id = CDISASM_ARM_NAME_UMULL;
            identity->accumulate = 0u;
            identity->minimum_size_code = 1u;
            return 1;
        default:
            return 0;
    }
}

static int arm_is_advsimd_widening_multiply_name(
    cdisasm_arm_name_id name_id)
{
    return name_id == CDISASM_ARM_NAME_SMLAL
        || name_id == CDISASM_ARM_NAME_SMLALS
        || name_id == CDISASM_ARM_NAME_SMLSL
        || name_id == CDISASM_ARM_NAME_SMULL
        || name_id == CDISASM_ARM_NAME_SQDMLAL
        || name_id == CDISASM_ARM_NAME_SQDMLSL
        || name_id == CDISASM_ARM_NAME_SQDMULL
        || name_id == CDISASM_ARM_NAME_UMLAL
        || name_id == CDISASM_ARM_NAME_UMLALS
        || name_id == CDISASM_ARM_NAME_UMLSL
        || name_id == CDISASM_ARM_NAME_UMULL
        || name_id == CDISASM_ARM_NAME_UMULLS
        || name_id == CDISASM_ARM_NAME_SMULLS;
}

static int arm_is_legacy_widening_multiply_form(
    cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(56) || form_id == UINT16_C(58)
        || form_id == UINT16_C(60) || form_id == UINT16_C(62)
        || form_id == UINT16_C(2206) || form_id == UINT16_C(2207)
        || form_id == UINT16_C(2208) || form_id == UINT16_C(2217);
}

static int arm_raw_claims_legacy_widening_multiply(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t fixed;

    if (instruction->isa_id == CDISASM_ARM_ISA_A32
        && instruction->opcode_size == 4u) {
        fixed = instruction->raw_instruction & UINT32_C(0x0ff000f0);
        return fixed == UINT32_C(0x00800090)
            || fixed == UINT32_C(0x00900090)
            || fixed == UINT32_C(0x00a00090)
            || fixed == UINT32_C(0x00b00090)
            || fixed == UINT32_C(0x00c00090)
            || fixed == UINT32_C(0x00d00090)
            || fixed == UINT32_C(0x00e00090)
            || fixed == UINT32_C(0x00f00090);
    }
    if (instruction->isa_id == CDISASM_ARM_ISA_T32
        && instruction->opcode_size == 4u) {
        uint32_t normalized =
            (instruction->raw_instruction << 16)
            | (instruction->raw_instruction >> 16);

        fixed = normalized & UINT32_C(0xfff000f0);
        return fixed == UINT32_C(0xfb800000)
            || fixed == UINT32_C(0xfba00000)
            || fixed == UINT32_C(0xfbc00000)
            || fixed == UINT32_C(0xfbe00000);
    }
    return 0;
}

static int arm_valid_legacy_widening_multiply_schema(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t normalized = word;
    uint32_t fixed;
    cdisasm_arm_form_id expected_form = CDISASM_ARM_FORM_NONE;
    cdisasm_arm_name_id expected_name = CDISASM_ARM_NAME_NONE;
    unsigned rdlo;
    unsigned rdhi;
    unsigned rn;
    unsigned rm;
    cdisasm_operand_access destination_access;
    cdisasm_arm_condition expected_condition;
    uint32_t expected_groups;
    uint32_t expected_flags;

    if (instruction->isa_id == CDISASM_ARM_ISA_A32
        && instruction->opcode_size == 4u) {
        expected_condition = (cdisasm_arm_condition)(word >> 28);
        if (expected_condition >= CDISASM_ARM_CONDITION_NV) {
            return 0;
        }
        expected_groups = expected_condition < CDISASM_ARM_CONDITION_AL
            ? CDISASM_GROUP_CONDITIONAL : CDISASM_GROUP_NONE;
        expected_flags = (word & UINT32_C(0x00100000)) != 0u
            ? CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS : 0u;
        fixed = word & UINT32_C(0x0ff000f0);
        rdlo = (word >> 12) & 15u;
        rdhi = (word >> 16) & 15u;
        rn = word & 15u;
        rm = (word >> 8) & 15u;
        switch (fixed) {
            case UINT32_C(0x00800090):
                expected_form = UINT16_C(56);
                expected_name = CDISASM_ARM_NAME_UMULL;
                break;
            case UINT32_C(0x00900090):
                expected_form = UINT16_C(56);
                expected_name = CDISASM_ARM_NAME_UMULLS;
                break;
            case UINT32_C(0x00a00090):
                expected_form = UINT16_C(58);
                expected_name = CDISASM_ARM_NAME_UMLAL;
                break;
            case UINT32_C(0x00b00090):
                expected_form = UINT16_C(58);
                expected_name = CDISASM_ARM_NAME_UMLALS;
                break;
            case UINT32_C(0x00c00090):
                expected_form = UINT16_C(60);
                expected_name = CDISASM_ARM_NAME_SMULL;
                break;
            case UINT32_C(0x00d00090):
                expected_form = UINT16_C(60);
                expected_name = CDISASM_ARM_NAME_SMULLS;
                break;
            case UINT32_C(0x00e00090):
                expected_form = UINT16_C(62);
                expected_name = CDISASM_ARM_NAME_SMLAL;
                break;
            case UINT32_C(0x00f00090):
                expected_form = UINT16_C(62);
                expected_name = CDISASM_ARM_NAME_SMLALS;
                break;
            default:
                return 0;
        }
    } else if (instruction->isa_id == CDISASM_ARM_ISA_T32
        && instruction->opcode_size == 4u) {
        expected_condition = CDISASM_ARM_CONDITION_AL;
        expected_groups = CDISASM_GROUP_NONE;
        expected_flags = 0u;
        normalized = (word << 16) | (word >> 16);
        fixed = normalized & UINT32_C(0xfff000f0);
        rdlo = (normalized >> 12) & 15u;
        rdhi = (normalized >> 8) & 15u;
        rn = (normalized >> 16) & 15u;
        rm = normalized & 15u;
        switch (fixed) {
            case UINT32_C(0xfb800000):
                expected_form = UINT16_C(2206);
                expected_name = CDISASM_ARM_NAME_SMULL;
                break;
            case UINT32_C(0xfba00000):
                expected_form = UINT16_C(2207);
                expected_name = CDISASM_ARM_NAME_UMULL;
                break;
            case UINT32_C(0xfbc00000):
                expected_form = UINT16_C(2208);
                expected_name = CDISASM_ARM_NAME_SMLAL;
                break;
            case UINT32_C(0xfbe00000):
                expected_form = UINT16_C(2217);
                expected_name = CDISASM_ARM_NAME_UMLAL;
                break;
            default:
                return 0;
        }
    } else {
        return 0;
    }
    destination_access = expected_name == CDISASM_ARM_NAME_SMLAL
            || expected_name == CDISASM_ARM_NAME_SMLALS
            || expected_name == CDISASM_ARM_NAME_UMLAL
            || expected_name == CDISASM_ARM_NAME_UMLALS
        ? CDISASM_OPERAND_ACCESS_READ_WRITE
        : CDISASM_OPERAND_ACCESS_WRITE;
    return instruction->form_id == expected_form
        && instruction->name_id == expected_name
        && instruction->condition == expected_condition
        && instruction->opcode_groups == expected_groups
        && instruction->instruction_flags == expected_flags
        && instruction->branch_target == 0u
        && instruction->operand_count == 4u
        && arm_exact_register_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_R0 + rdlo), 4u, destination_access)
        && arm_exact_register_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_R0 + rdhi), 4u, destination_access)
        && arm_exact_register_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_R0 + rn), 4u,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_register_operand(
            &instruction->operand[3], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_R0 + rm), 4u,
            CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_advsimd_widening_multiply_element_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_advsimd_widening_multiply_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE, 0u, 0u
    };
    uint32_t word = instruction->raw_instruction;
    unsigned size_code = (word >> 22) & 3u;
    unsigned indexed_register;
    uint64_t lane;
    uint8_t source_element_size;
    uint8_t result_element_size;
    uint8_t source_vector_size;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || !arm_advsimd_widening_multiply_element_identity_for_word(
            word, &identity)
        || (size_code != 1u && size_code != 2u)) {
        return 0;
    }
    source_element_size = size_code == 1u ? 2u : 4u;
    result_element_size = (uint8_t)(source_element_size * 2u);
    source_vector_size =
        (word & UINT32_C(0x40000000)) != 0u ? 16u : 8u;
    if (size_code == 1u) {
        indexed_register = (word >> 16) & 15u;
        lane = (uint64_t)(((word >> 11) & 1u) << 2)
            | (uint64_t)(((word >> 21) & 1u) << 1)
            | (uint64_t)((word >> 20) & 1u);
    } else {
        indexed_register = (word >> 16) & 31u;
        lane = (uint64_t)(((word >> 11) & 1u) << 1)
            | (uint64_t)((word >> 21) & 1u);
    }

    return instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->branch_target == 0u
        && instruction->operand_count == 3u
        && cdisasm_arm_generated_form_matches(instruction)
        && arm_exact_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + (word & 31u)),
            16u, result_element_size,
            identity.accumulate != 0u
                ? CDISASM_OPERAND_ACCESS_READ_WRITE
                : CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)),
            source_vector_size, source_element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_vector_lane_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + indexed_register),
            source_element_size, lane, CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_advsimd_widening_multiply_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_advsimd_widening_multiply_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE, 0u, 0u
    };
    uint32_t word = instruction->raw_instruction;
    unsigned size_code = (word >> 22) & 3u;
    int high = (word & UINT32_C(0x40000000)) != 0u;
    uint8_t source_element_size = (uint8_t)(UINT8_C(1) << size_code);
    uint8_t result_element_size =
        (uint8_t)(source_element_size * 2u);
    uint8_t narrow_total_size = high ? 16u : 8u;
    int raw_is_envelope = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_advsimd_widening_multiply_identity_for_word(word, &identity);
    int raw_is_family = raw_is_envelope && size_code <= 2u
        && size_code >= identity.minimum_size_code;
    int form_is_family = arm_is_advsimd_widening_multiply_form(
        instruction->form_id);
    int name_is_family = arm_is_advsimd_widening_multiply_name(
        instruction->name_id);
    int raw_is_legacy_family =
        arm_raw_claims_legacy_widening_multiply(instruction);
    int form_is_legacy_family = arm_is_legacy_widening_multiply_form(
        instruction->form_id);
    arm_advsimd_widening_multiply_identity element_identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE, 0u, 0u
    };
    int raw_is_element_envelope = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_advsimd_widening_multiply_element_identity_for_word(
            word, &element_identity);
    int form_is_element_family =
        arm_is_advsimd_widening_multiply_element_form(
            instruction->form_id);
    int sme2_indexed_long = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (((instruction->raw_instruction & UINT32_C(0xfff01000))
                == UINT32_C(0xc1c01000))
            || ((instruction->raw_instruction & UINT32_C(0xfff01010))
                == UINT32_C(0xc1c00000))
            || ((instruction->raw_instruction & UINT32_C(0xfff09020))
                == UINT32_C(0xc1901000))
            || ((instruction->raw_instruction & UINT32_C(0xfff09060))
                == UINT32_C(0xc1909000))
            || ((instruction->raw_instruction & UINT32_C(0xffe39c64))
                == UINT32_C(0xc1e10800))
            || ((instruction->raw_instruction & UINT32_C(0xffe19c24))
                == UINT32_C(0xc1e00800))
            || instruction->form_id == UINT16_C(3950)
            || instruction->form_id == UINT16_C(3951)
            || instruction->form_id == UINT16_C(3952)
            || instruction->form_id == UINT16_C(3953)
            || instruction->form_id == UINT16_C(3954)
            || (instruction->form_id >= UINT16_C(3989)
                && instruction->form_id <= UINT16_C(3992))
            || (instruction->form_id >= UINT16_C(4037)
                && instruction->form_id <= UINT16_C(4040))
            || (instruction->form_id >= UINT16_C(3955)
                && instruction->form_id <= UINT16_C(3958))
            || (instruction->form_id >= UINT16_C(4048)
                && instruction->form_id <= UINT16_C(4051))
            || (instruction->form_id >= UINT16_C(4000)
                && instruction->form_id <= UINT16_C(4003))
            || (instruction->form_id >= UINT16_C(4186)
                && instruction->form_id <= UINT16_C(4189))
            || (instruction->form_id >= UINT16_C(4146)
                && instruction->form_id <= UINT16_C(4149))
            || (instruction->form_id >= UINT16_C(4069)
                && instruction->form_id <= UINT16_C(4072))
            || (instruction->form_id >= UINT16_C(4077)
                && instruction->form_id <= UINT16_C(4080))
            || (instruction->form_id >= UINT16_C(4112)
                && instruction->form_id <= UINT16_C(4115)));

    int generated_opaque_other = name_is_family && !form_is_family
        && instruction->form_id != CDISASM_ARM_FORM_NONE
        && (instruction->instruction_flags
            & (CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
                | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE))
            == (CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
                | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE)
        && cdisasm_arm_generated_form_matches(instruction);
    int name_claims_fixed_vector_family = name_is_family
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && !generated_opaque_other;
    int scalar_exact_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (((word & UINT32_C(0xff20fc00)) == UINT32_C(0x5e209000))
            || ((word & UINT32_C(0xff20fc00)) == UINT32_C(0x5e20b000))
            || ((word & UINT32_C(0xff20fc00)) == UINT32_C(0x5e20d000))
            || (instruction->form_id >= UINT16_C(5819)
                && instruction->form_id <= UINT16_C(5821)));

    /* The dedicated scalar validator above owns this disjoint encoding/form
     * namespace, including cross-form and malformed-size rejection. */
    if (scalar_exact_family) {
        return 1;
    }

    if (sme2_indexed_long) {
        return 1;
    }

    if (raw_is_element_envelope || form_is_element_family) {
        return arm_valid_advsimd_widening_multiply_element_schema(
            instruction);
    }

    if (raw_is_legacy_family || form_is_legacy_family) {
        return arm_valid_legacy_widening_multiply_schema(instruction);
    }

    /* These public names are also genuine A32/T32 long multiplies, A64
     * scalar operations, by-element forms, aliases, and SME operations. Raw
     * and form ownership remain unconditional. All other A64 same-name
     * claims are owned unless both generated-opaque flags hand an exact
     * generated form/raw/ISA identity to the generated formatter, which
     * then verifies its alias or public name and recipe. */
    if (!raw_is_envelope && !form_is_family
        && !name_claims_fixed_vector_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->branch_target == 0u
        && instruction->operand_count == 3u
        && arm_exact_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + (word & 31u)),
            16u, result_element_size,
            identity.accumulate != 0u
                ? CDISASM_OPERAND_ACCESS_READ_WRITE
                : CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)),
            narrow_total_size, source_element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_vector_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 16) & 31u)),
            narrow_total_size, source_element_size,
            CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_advsimd_saturating_mulh_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
} arm_advsimd_saturating_mulh_identity;

static int arm_advsimd_saturating_mulh_identity_for_word(
    uint32_t word, arm_advsimd_saturating_mulh_identity *identity)
{
    switch (word & UINT32_C(0xbf20fc00)) {
        case UINT32_C(0x0e20b400):
            identity->form_id = UINT16_C(6136);
            identity->name_id = CDISASM_ARM_NAME_SQDMULH;
            return 1;
        case UINT32_C(0x2e20b400):
            identity->form_id = UINT16_C(6178);
            identity->name_id = CDISASM_ARM_NAME_SQRDMULH;
            return 1;
        default:
            return 0;
    }
}

static int arm_is_advsimd_saturating_mulh_form(
    cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(6136) || form_id == UINT16_C(6178);
}

static int arm_is_advsimd_saturating_mulh_name(
    cdisasm_arm_name_id name_id)
{
    return name_id == CDISASM_ARM_NAME_SQDMULH
        || name_id == CDISASM_ARM_NAME_SQRDMULH;
}

static int arm_is_generated_saturating_mulh_sibling(
    const cdisasm_arm_instruction *instruction)
{
    int name_matches;

    switch (instruction->form_id) {
        case UINT16_C(2358):
        case UINT16_C(2778):
        case UINT16_C(2779):
        case UINT16_C(2780):
        case UINT16_C(4234):
        case UINT16_C(4252):
        case UINT16_C(4271):
        case UINT16_C(4290):
        case UINT16_C(5832):
        case UINT16_C(5880):
        case UINT16_C(6250):
            name_matches =
                instruction->name_id == CDISASM_ARM_NAME_SQDMULH;
            break;
        case UINT16_C(2359):
        case UINT16_C(2781):
        case UINT16_C(2782):
        case UINT16_C(2783):
        case UINT16_C(5847):
        case UINT16_C(5881):
        case UINT16_C(6251):
            name_matches =
                instruction->name_id == CDISASM_ARM_NAME_SQRDMULH;
            break;
        default:
            return 0;
    }
    if (name_matches && (instruction->form_id == UINT16_C(4234)
            || instruction->form_id == UINT16_C(4252)
            || instruction->form_id == UINT16_C(4271)
            || instruction->form_id == UINT16_C(4290))) {
        return instruction->isa_id == CDISASM_ARM_ISA_A64
            && instruction->instruction_flags == UINT32_C(0x05400000);
    }
    if (name_matches && (instruction->form_id == UINT16_C(6250)
            || instruction->form_id == UINT16_C(6251))) {
        return instruction->isa_id == CDISASM_ARM_ISA_A64
            && instruction->instruction_flags
                == CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
    }
    return name_matches
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u
        && cdisasm_arm_generated_form_matches(instruction);
}

static int arm_valid_advsimd_saturating_mulh_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_advsimd_saturating_mulh_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE
    };
    uint32_t word = instruction->raw_instruction;
    unsigned size_code = (word >> 22) & 3u;
    uint8_t element_size = (uint8_t)(UINT8_C(1) << size_code);
    uint8_t vector_size = (word & UINT32_C(0x40000000)) != 0u
        ? 16u : 8u;
    int raw_is_envelope = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_advsimd_saturating_mulh_identity_for_word(word, &identity);
    int raw_is_family = raw_is_envelope
        && (size_code == 1u || size_code == 2u);
    int form_is_family = arm_is_advsimd_saturating_mulh_form(
        instruction->form_id);
    int name_is_family = arm_is_advsimd_saturating_mulh_name(
        instruction->name_id);
    int generated_sibling = name_is_family && !form_is_family
        && arm_is_generated_saturating_mulh_sibling(instruction);
    int name_claims_fixed_family = name_is_family && !generated_sibling;

    if (!raw_is_envelope && !form_is_family
        && !name_claims_fixed_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->branch_target == 0u
        && instruction->operand_count == 3u
        && arm_exact_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + (word & 31u)),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_vector_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 16) & 31u)),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
}

static int arm_is_advsimd_pmull_form(
    const cdisasm_arm_instruction *instruction)
{
    return instruction->form_id == UINT16_C(6103);
}

static int arm_is_generated_pmull_sibling(
    const cdisasm_arm_instruction *instruction)
{
    return instruction->form_id == UINT16_C(2918)
        && instruction->name_id == CDISASM_ARM_NAME_PMULL
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u
        && cdisasm_arm_generated_form_matches(instruction);
}

static int arm_valid_advsimd_pmull_schema(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned size_code = (word >> 22) & 3u;
    int high = (word & UINT32_C(0x40000000)) != 0u;
    uint8_t source_element_size = size_code == 0u ? 1u : 8u;
    uint8_t result_element_size =
        (uint8_t)(source_element_size * 2u);
    uint8_t source_total_size = high ? 16u : 8u;
    int raw_is_envelope = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (word & UINT32_C(0xbf20fc00)) == UINT32_C(0x0e20e000);
    int raw_is_family = raw_is_envelope
        && (size_code == 0u || size_code == 3u);
    int form_is_family = arm_is_advsimd_pmull_form(instruction);
    int name_is_family = instruction->name_id == CDISASM_ARM_NAME_PMULL;
    int generated_sibling = name_is_family && !form_is_family
        && arm_is_generated_pmull_sibling(instruction);
    int name_claims_fixed_family = name_is_family && !generated_sibling;

    if (instruction->form_id == UINT16_C(2918)
        && instruction->name_id == CDISASM_ARM_NAME_PMULL
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        && cdisasm_arm_generated_form_matches(instruction)) {
        return 1;
    }

    if (!raw_is_envelope && !form_is_family
        && !name_claims_fixed_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->branch_target == 0u
        && instruction->operand_count == 3u
        && arm_exact_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + (word & 31u)),
            16u, result_element_size, CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)),
            source_total_size, source_element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_vector_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 16) & 31u)),
            source_total_size, source_element_size,
            CDISASM_OPERAND_ACCESS_READ);
}

static int arm_is_advsimd_pmul_form(
    const cdisasm_arm_instruction *instruction)
{
    return instruction->form_id == UINT16_C(6175);
}

static int arm_is_generated_pmul_sibling(
    const cdisasm_arm_instruction *instruction)
{
    return instruction->form_id == UINT16_C(2355)
        && instruction->name_id == CDISASM_ARM_NAME_PMUL
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u
        && cdisasm_arm_generated_form_matches(instruction);
}

static int arm_valid_advsimd_pmul_schema(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned size_code = (word >> 22) & 3u;
    uint8_t vector_size = (word & UINT32_C(0x40000000)) != 0u
        ? 16u : 8u;
    int raw_is_envelope = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (word & UINT32_C(0xbf20fc00)) == UINT32_C(0x2e209c00);
    int raw_is_family = raw_is_envelope && size_code == 0u;
    int form_is_family = arm_is_advsimd_pmul_form(instruction);
    int name_is_family = instruction->name_id == CDISASM_ARM_NAME_PMUL;
    int generated_sibling = name_is_family && !form_is_family
        && arm_is_generated_pmul_sibling(instruction);
    int name_claims_fixed_family = name_is_family && !generated_sibling;

    if (!raw_is_envelope && !form_is_family
        && !name_claims_fixed_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->branch_target == 0u
        && instruction->operand_count == 3u
        && arm_exact_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + (word & 31u)),
            vector_size, 1u, CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)),
            vector_size, 1u, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_vector_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 16) & 31u)),
            vector_size, 1u, CDISASM_OPERAND_ACCESS_READ);
}

static int arm_is_advsimd_high_narrow_form(
    const cdisasm_arm_instruction *instruction)
{
    return instruction->form_id == UINT16_C(6093)
        || instruction->form_id == UINT16_C(6095)
        || instruction->form_id == UINT16_C(6108)
        || instruction->form_id == UINT16_C(6110);
}

static int arm_valid_advsimd_high_narrow_schema(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    cdisasm_arm_form_id expected_form = CDISASM_ARM_FORM_NONE;
    cdisasm_arm_name_id expected_name = CDISASM_ARM_NAME_NONE;
    unsigned size_code = (word >> 22) & 3u;
    int high = (word & UINT32_C(0x40000000)) != 0u;
    uint8_t result_element_size = (uint8_t)(UINT8_C(1) << size_code);
    uint8_t source_element_size = (uint8_t)(result_element_size * 2u);
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && size_code <= 2u
        && arm_advsimd_high_narrow_identity_for_word(
            word, &expected_form, &expected_name);
    int form_is_family = arm_is_advsimd_high_narrow_form(instruction);
    int name_is_family = instruction->name_id == CDISASM_ARM_NAME_ADDHN
        || instruction->name_id == CDISASM_ARM_NAME_SUBHN
        || instruction->name_id == CDISASM_ARM_NAME_RADDHN
        || instruction->name_id == CDISASM_ARM_NAME_RSUBHN;

    if (!raw_is_family && !form_is_family && !name_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->form_id == expected_form
        && instruction->name_id == expected_name
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->operand_count == 3u
        && arm_exact_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + (word & 31u)),
            high ? 16u : 8u, result_element_size,
            high ? CDISASM_OPERAND_ACCESS_READ_WRITE
                 : CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)),
            16u, source_element_size, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_vector_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 16) & 31u)),
            16u, source_element_size, CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_sve_integer_immediate_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    uint8_t signed_immediate;
    uint8_t shiftable;
} arm_sve_integer_immediate_identity;

static int arm_sve_integer_immediate_identity_for_word(
    uint32_t word, arm_sve_integer_immediate_identity *identity)
{
    static const struct arm_sve_integer_immediate_encoding {
        uint32_t mask;
        uint32_t value;
        cdisasm_arm_form_id form_id;
        cdisasm_arm_name_id name_id;
        uint8_t signed_immediate;
        uint8_t shiftable;
    } encodings[12] = {
        { UINT32_C(0xff3fc000), UINT32_C(0x2520c000), UINT16_C(2619),
          CDISASM_ARM_NAME_ADD, 0u, 1u },
        { UINT32_C(0xff3fc000), UINT32_C(0x2521c000), UINT16_C(2620),
          CDISASM_ARM_NAME_SUB, 0u, 1u },
        { UINT32_C(0xff3fc000), UINT32_C(0x2523c000), UINT16_C(2621),
          CDISASM_ARM_NAME_SUBR, 0u, 1u },
        { UINT32_C(0xff3fc000), UINT32_C(0x2524c000), UINT16_C(2622),
          CDISASM_ARM_NAME_SQADD, 0u, 1u },
        { UINT32_C(0xff3fc000), UINT32_C(0x2526c000), UINT16_C(2623),
          CDISASM_ARM_NAME_SQSUB, 0u, 1u },
        { UINT32_C(0xff3fc000), UINT32_C(0x2525c000), UINT16_C(2624),
          CDISASM_ARM_NAME_UQADD, 0u, 1u },
        { UINT32_C(0xff3fc000), UINT32_C(0x2527c000), UINT16_C(2625),
          CDISASM_ARM_NAME_UQSUB, 0u, 1u },
        { UINT32_C(0xff3fe000), UINT32_C(0x2528c000), UINT16_C(2626),
          CDISASM_ARM_NAME_SMAX, 1u, 0u },
        { UINT32_C(0xff3fe000), UINT32_C(0x252ac000), UINT16_C(2627),
          CDISASM_ARM_NAME_SMIN, 1u, 0u },
        { UINT32_C(0xff3fe000), UINT32_C(0x2529c000), UINT16_C(2628),
          CDISASM_ARM_NAME_UMAX, 0u, 0u },
        { UINT32_C(0xff3fe000), UINT32_C(0x252bc000), UINT16_C(2629),
          CDISASM_ARM_NAME_UMIN, 0u, 0u },
        { UINT32_C(0xff3fe000), UINT32_C(0x2530c000), UINT16_C(2630),
          CDISASM_ARM_NAME_MUL, 1u, 0u }
    };
    unsigned index;

    for (index = 0u; index < 12u; ++index) {
        if ((word & encodings[index].mask) == encodings[index].value) {
            if (encodings[index].shiftable != 0u
                && ((word >> 22) & 3u) == 0u
                && (word & UINT32_C(0x00002000)) != 0u) {
                return 0;
            }
            identity->form_id = encodings[index].form_id;
            identity->name_id = encodings[index].name_id;
            identity->signed_immediate =
                encodings[index].signed_immediate;
            identity->shiftable = encodings[index].shiftable;
            return 1;
        }
    }
    return 0;
}

static int arm_valid_sve_unpredicated_logical_schema(
    const cdisasm_arm_instruction *instruction)
{
    static const uint32_t values[4] = {
        UINT32_C(0x04203000), UINT32_C(0x04603000),
        UINT32_C(0x04a03000), UINT32_C(0x04e03000)
    };
    static const cdisasm_arm_name_id names[4] = {
        CDISASM_ARM_NAME_AND, CDISASM_ARM_NAME_ORR,
        CDISASM_ARM_NAME_EOR, CDISASM_ARM_NAME_BIC
    };
    uint32_t word = instruction->raw_instruction;
    uint32_t fixed = word & UINT32_C(0xffe0fc00);
    unsigned operation;
    unsigned zd = word & 31u;
    unsigned zn = (word >> 5) & 31u;
    unsigned zm = (word >> 16) & 31u;
    int alias;
    int raw_is_family = 0;
    int form_is_family = instruction->form_id >= UINT16_C(2321)
        && instruction->form_id <= UINT16_C(2324);

    for (operation = 0u; operation < 4u; ++operation) {
        if (fixed == values[operation]) {
            raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64;
            break;
        }
    }
    if (!raw_is_family && !form_is_family) {
        return 1;
    }
    alias = operation == 1u && zn == zm;
    if (!raw_is_family || !form_is_family
        || instruction->form_id
            != (cdisasm_arm_form_id)(UINT16_C(2321) + operation)
        || instruction->name_id
            != (alias ? CDISASM_ARM_NAME_MOV : names[operation])
        || instruction->opcode_size != 4u
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->instruction_flags
            != CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        || instruction->branch_target != 0u
        || instruction->operand_count != (alias ? 2u : 3u)
        || !arm_exact_scalable_operand(
            &instruction->operand[0],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zd), 8u,
            CDISASM_OPERAND_ACCESS_WRITE)
        || !arm_exact_scalable_operand(
            &instruction->operand[1],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zn), 8u,
            CDISASM_OPERAND_ACCESS_READ)
        || (!alias && !arm_exact_scalable_operand(
            &instruction->operand[2],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zm), 8u,
            CDISASM_OPERAND_ACCESS_READ))) {
        return 0;
    }
    return cdisasm_arm_generated_form_matches(instruction);
}

static int arm_valid_sve_integer_immediate_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_sve_integer_immediate_identity identity;
    uint32_t word = instruction->raw_instruction;
    unsigned encoded_immediate = (word >> 5) & 255u;
    unsigned encoded_register = word & 31u;
    uint8_t element_size = (uint8_t)(UINT8_C(1)
        << ((word >> 22) & 3u));
    int shifted;
    int64_t immediate_value;
    uint8_t immediate_flags;
    cdisasm_arm_shift_type shift_type;
    uint8_t shift_amount;
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_integer_immediate_identity_for_word(word, &identity);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id >= UINT16_C(2619)
        && instruction->form_id <= UINT16_C(2630);
    const cdisasm_arm_operand *immediate;

    if (!raw_is_family && !form_is_family) {
        return 1;
    }
    if (!raw_is_family || !form_is_family
        || instruction->form_id != identity.form_id
        || instruction->name_id != identity.name_id
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->instruction_flags
            != CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        || instruction->operand_count != 3u
        || !arm_exact_scalable_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + encoded_register), element_size,
            CDISASM_OPERAND_ACCESS_WRITE)
        || !arm_exact_scalable_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + encoded_register), element_size,
            CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    shifted = identity.shiftable != 0u
        && (word & UINT32_C(0x00002000)) != 0u;
    immediate_value = identity.signed_immediate != 0u
        ? (encoded_immediate >= 128u
            ? (int64_t)encoded_immediate - INT64_C(256)
            : (int64_t)encoded_immediate)
        : (int64_t)((uint64_t)encoded_immediate
            << (shifted ? 8u : 0u));
    immediate_flags = identity.signed_immediate != 0u
            && immediate_value < 0
        ? CDISASM_OPERAND_FLAG_SIGNED
        : CDISASM_OPERAND_FLAG_NONE;
    shift_type = shifted && encoded_immediate == 0u
        ? CDISASM_ARM_SHIFT_LSL : CDISASM_ARM_SHIFT_NONE;
    shift_amount = shift_type == CDISASM_ARM_SHIFT_LSL ? 8u : 0u;
    immediate = &instruction->operand[2];
    return immediate->type == CDISASM_OPERAND_IMMEDIATE
        && immediate->reg == CDISASM_ARM_REG_NONE
        && immediate->base_reg == CDISASM_ARM_REG_NONE
        && immediate->index_reg == CDISASM_ARM_REG_NONE
        && immediate->register_list == 0u
        && immediate->address == 0u
        && immediate->imm == (uint64_t)immediate_value
        && immediate->size == 1u
        && immediate->flags == immediate_flags
        && immediate->shift_type == shift_type
        && immediate->shift_amount == shift_amount
        && immediate->extend_type == CDISASM_ARM_EXTEND_NONE
        && immediate->scale == 0u
        && immediate->access == CDISASM_OPERAND_ACCESS_READ;
}

typedef struct arm_sve_dup_immediate_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    uint8_t floating_point;
} arm_sve_dup_immediate_identity;

static int64_t arm_sve_dup_integer_value(
    unsigned encoded, unsigned shifted)
{
    uint64_t sign = UINT64_C(1) << 7u;
    int64_t value = (int64_t)(((uint64_t)encoded ^ sign) - sign);

    return value * (shifted != 0u ? INT64_C(256) : INT64_C(1));
}

static uint64_t arm_sve_vfp_expand_imm(
    unsigned encoded, uint8_t element_size)
{
    unsigned total_bits = 8u * element_size;
    unsigned exponent_bits = element_size == 2u ? 5u
        : element_size == 4u ? 8u : 11u;
    unsigned fraction_bits = total_bits - exponent_bits - 1u;
    unsigned exponent_selector = (encoded >> 6) & 1u;
    uint64_t exponent = (uint64_t)(exponent_selector ^ 1u)
        << (exponent_bits - 1u);

    if (exponent_selector != 0u) {
        exponent |= ((UINT64_C(1) << (exponent_bits - 3u))
                - UINT64_C(1))
            << 2u;
    }
    exponent |= (encoded >> 4) & 3u;
    return ((uint64_t)((encoded >> 7) & 1u) << (total_bits - 1u))
        | (exponent << fraction_bits)
        | ((uint64_t)(encoded & 15u) << (fraction_bits - 4u));
}

static int arm_sve_dup_immediate_identity_for_word(
    uint32_t word, arm_sve_dup_immediate_identity *identity)
{
    unsigned size_code = (word >> 22) & 3u;

    if ((word & UINT32_C(0xff3fc000)) == UINT32_C(0x2538c000)) {
        if (size_code == 0u
            && (word & UINT32_C(0x00002000)) != 0u) {
            return 0;
        }
        identity->form_id = UINT16_C(2631);
        identity->name_id = CDISASM_ARM_NAME_MOV;
        identity->floating_point = 0u;
        return 1;
    }
    if ((word & UINT32_C(0xff3fe000)) == UINT32_C(0x2539c000)) {
        if (size_code == 0u) {
            return 0;
        }
        identity->form_id = UINT16_C(2632);
        identity->name_id = CDISASM_ARM_NAME_FMOV;
        identity->floating_point = 1u;
        return 1;
    }
    return 0;
}

static int arm_valid_sve_dup_immediate_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_sve_dup_immediate_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE, 0u
    };
    uint32_t word = instruction->raw_instruction;
    unsigned encoded = (word >> 5) & 255u;
    unsigned shifted = (word & UINT32_C(0x00002000)) != 0u;
    uint8_t element_size = (uint8_t)(UINT8_C(1)
        << ((word >> 22) & 3u));
    uint32_t expected_flags;
    uint64_t immediate_value;
    uint8_t immediate_flags;
    cdisasm_arm_shift_type shift_type;
    uint8_t shift_amount;
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_dup_immediate_identity_for_word(word, &identity);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->form_id == UINT16_C(2631)
            || instruction->form_id == UINT16_C(2632));
    const cdisasm_arm_operand *immediate;

    if (!raw_is_family && !form_is_family) {
        return 1;
    }
    expected_flags = CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        | (identity.floating_point != 0u
            ? CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT : 0u);
    immediate_value = identity.floating_point != 0u
        ? arm_sve_vfp_expand_imm(encoded, element_size)
        : (uint64_t)arm_sve_dup_integer_value(encoded, shifted);
    immediate_flags = identity.floating_point == 0u
            && arm_sve_dup_integer_value(encoded, shifted) < 0
        ? CDISASM_OPERAND_FLAG_SIGNED : CDISASM_OPERAND_FLAG_NONE;
    shift_type = identity.floating_point == 0u
            && shifted != 0u && encoded == 0u
        ? CDISASM_ARM_SHIFT_LSL : CDISASM_ARM_SHIFT_NONE;
    shift_amount = shift_type == CDISASM_ARM_SHIFT_LSL ? 8u : 0u;
    if (!raw_is_family || !form_is_family
        || instruction->form_id != identity.form_id
        || instruction->name_id != identity.name_id
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->instruction_flags != expected_flags
        || instruction->operand_count != 2u
        || !arm_exact_scalable_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + (word & 31u)), element_size,
            CDISASM_OPERAND_ACCESS_WRITE)) {
        return 0;
    }
    immediate = &instruction->operand[1];
    return immediate->type == CDISASM_OPERAND_IMMEDIATE
        && immediate->reg == CDISASM_ARM_REG_NONE
        && immediate->base_reg == CDISASM_ARM_REG_NONE
        && immediate->index_reg == CDISASM_ARM_REG_NONE
        && immediate->register_list == 0u
        && immediate->address == 0u
        && immediate->imm == immediate_value
        && immediate->size == 1u
        && immediate->flags == immediate_flags
        && immediate->shift_type == shift_type
        && immediate->shift_amount == shift_amount
        && immediate->extend_type == CDISASM_ARM_EXTEND_NONE
        && immediate->scale == 0u
        && immediate->access == CDISASM_OPERAND_ACCESS_READ;
}

typedef struct arm_sve_dot_product_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    uint8_t destination_size;
    uint8_t source_size;
} arm_sve_dot_product_identity;

static int arm_sve_dot_product_identity_for_word(
    uint32_t word, arm_sve_dot_product_identity *identity)
{
    unsigned size_code = (word >> 22) & 3u;

    if ((word & UINT32_C(0xffa0fc00)) == UINT32_C(0x44800000)) {
        identity->form_id = UINT16_C(2633);
        identity->name_id = CDISASM_ARM_NAME_SDOT;
    } else if ((word & UINT32_C(0xffe0fc00))
        == UINT32_C(0x44400000)) {
        identity->form_id = UINT16_C(2634);
        identity->name_id = CDISASM_ARM_NAME_SDOT;
    } else if ((word & UINT32_C(0xffa0fc00))
        == UINT32_C(0x44800400)) {
        identity->form_id = UINT16_C(2635);
        identity->name_id = CDISASM_ARM_NAME_UDOT;
    } else if ((word & UINT32_C(0xffe0fc00))
        == UINT32_C(0x44400400)) {
        identity->form_id = UINT16_C(2636);
        identity->name_id = CDISASM_ARM_NAME_UDOT;
    } else {
        return 0;
    }
    identity->destination_size = (uint8_t)(UINT8_C(1) << size_code);
    identity->source_size = size_code == 1u
        ? 1u : (uint8_t)(identity->destination_size / 4u);
    return 1;
}

static int arm_valid_sve_dot_product_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_sve_dot_product_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE, 0u, 0u
    };
    uint32_t word = instruction->raw_instruction;
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_dot_product_identity_for_word(word, &identity);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id >= UINT16_C(2633)
        && instruction->form_id <= UINT16_C(2636);

    if (!raw_is_family && !form_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family
        && instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        && instruction->operand_count == 3u
        && arm_exact_scalable_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + (word & 31u)),
            identity.destination_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_scalable_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)),
            identity.source_size, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_scalable_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 16) & 31u)),
            identity.source_size, CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sve_usdot_schema(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (word & UINT32_C(0xffe0fc00)) == UINT32_C(0x44807800);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id == UINT16_C(2656);

    if (!raw_is_family && !form_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family
        && instruction->name_id == CDISASM_ARM_NAME_USDOT
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        && instruction->operand_count == 3u
        && arm_exact_scalable_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + (word & 31u)), 4u,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_scalable_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)), 1u,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_scalable_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_Z0 + ((word >> 16) & 31u)), 1u,
            CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sve_dot_indexed_schema(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (word & UINT32_C(0xffe0f800)) == UINT32_C(0x44a01800);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->form_id == UINT16_C(2734)
            || instruction->form_id == UINT16_C(2735));
    cdisasm_arm_form_id expected_form =
        (word & UINT32_C(0x00000400)) != 0u
            ? UINT16_C(2735) : UINT16_C(2734);
    cdisasm_arm_name_id expected_name =
        (word & UINT32_C(0x00000400)) != 0u
            ? CDISASM_ARM_NAME_SUDOT : CDISASM_ARM_NAME_USDOT;

    if (!raw_is_family && !form_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family
        && instruction->form_id == expected_form
        && instruction->name_id == expected_name
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        && instruction->operand_count == 3u
        && arm_exact_scalable_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + (word & 31u)), 4u,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_scalable_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)), 1u,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_scalable_lane_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 16) & 7u)), 1u,
            (word >> 19) & 3u, CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sve_mla_indexed_schema(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    int sme_indexed_fp16 = (instruction->form_id >= UINT16_C(3965)
            && instruction->form_id <= UINT16_C(3968))
        || (instruction->form_id >= UINT16_C(4013)
            && instruction->form_id <= UINT16_C(4016))
        || (instruction->form_id >= UINT16_C(4154)
            && instruction->form_id <= UINT16_C(4157))
        || (instruction->form_id >= UINT16_C(4194)
            && instruction->form_id <= UINT16_C(4197))
        || instruction->form_id == UINT16_C(3969)
        || (instruction->form_id >= UINT16_C(3973)
            && instruction->form_id <= UINT16_C(3977))
        || instruction->form_id == UINT16_C(3979)
        || instruction->form_id == UINT16_C(3981)
        || instruction->form_id == UINT16_C(3982);
    sme_indexed_fp16 = sme_indexed_fp16
        || instruction->form_id == UINT16_C(4018)
        || instruction->form_id == UINT16_C(4019)
        || (instruction->form_id >= UINT16_C(4022)
            && instruction->form_id <= UINT16_C(4025))
        || instruction->form_id == UINT16_C(4027)
        || instruction->form_id == UINT16_C(4030)
        || instruction->form_id == UINT16_C(4031);
    sme_indexed_fp16 = sme_indexed_fp16
        || instruction->form_id == UINT16_C(4004)
        || instruction->form_id == UINT16_C(4017)
        || instruction->form_id == UINT16_C(3993)
        || instruction->form_id == UINT16_C(4041);
    sme_indexed_fp16 = sme_indexed_fp16
        || (instruction->form_id >= UINT16_C(4091)
            && instruction->form_id <= UINT16_C(4098))
        || (instruction->form_id >= UINT16_C(4127)
            && instruction->form_id <= UINT16_C(4134));
    int bf16_raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (word & UINT32_C(0xffa0f800)) == UINT32_C(0x64200800);
    int bf16_form_is_family = instruction->form_id == UINT16_C(2995)
        || instruction->form_id == UINT16_C(2999);
    unsigned wide_size = (word >> 23) & 1u;
    unsigned high_size_or_lane = (word >> 22) & 1u;
    unsigned width_index;
    unsigned indexed_register;
    uint64_t lane;
    uint8_t element_size;
    int subtract = (word & UINT32_C(0x00000400)) != 0u;
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (word & UINT32_C(0xff20f800)) == UINT32_C(0x44200800);
    int form_is_family = instruction->form_id >= UINT16_C(2722)
        && instruction->form_id <= UINT16_C(2727);
    cdisasm_arm_form_id expected_form;
    cdisasm_arm_name_id expected_name = subtract
        ? CDISASM_ARM_NAME_MLS : CDISASM_ARM_NAME_MLA;

    if (sme_indexed_fp16) {
        return 1;
    }

    if (bf16_raw_is_family || bf16_form_is_family
        || instruction->name_id == CDISASM_ARM_NAME_BFMLA
        || instruction->name_id == CDISASM_ARM_NAME_BFMLS) {
        cdisasm_arm_form_id bf16_expected_form = subtract
            ? UINT16_C(2999) : UINT16_C(2995);
        cdisasm_arm_name_id bf16_expected_name = subtract
            ? CDISASM_ARM_NAME_BFMLS : CDISASM_ARM_NAME_BFMLA;
        uint64_t bf16_lane = ((word >> 19) & 3u)
            | (((word >> 22) & 1u) << 2);

        return bf16_raw_is_family && bf16_form_is_family
            && instruction->form_id == bf16_expected_form
            && instruction->name_id == bf16_expected_name
            && instruction->opcode_size == 4u
            && instruction->condition == CDISASM_ARM_CONDITION_AL
            && instruction->opcode_groups == CDISASM_GROUP_NONE
            && instruction->instruction_flags
                == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                    | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)
            && instruction->branch_target == 0u
            && instruction->operand_count == 3u
            && cdisasm_arm_generated_form_matches(instruction)
            && arm_exact_scalable_operand(
                &instruction->operand[0], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_Z0 + (word & 31u)), 2u,
                CDISASM_OPERAND_ACCESS_READ_WRITE)
            && arm_exact_scalable_operand(
                &instruction->operand[1], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)), 2u,
                CDISASM_OPERAND_ACCESS_READ)
            && arm_exact_scalable_lane_operand(
                &instruction->operand[2], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_Z0 + ((word >> 16) & 7u)), 2u,
                bf16_lane, CDISASM_OPERAND_ACCESS_READ);
    }

    if (!raw_is_family && !form_is_family) {
        return 1;
    }
    if (wide_size == 0u) {
        width_index = 0u;
        element_size = 2u;
        indexed_register = (word >> 16) & 7u;
        lane = (uint64_t)((high_size_or_lane << 2)
            | ((word >> 19) & 3u));
    } else if (high_size_or_lane == 0u) {
        width_index = 1u;
        element_size = 4u;
        indexed_register = (word >> 16) & 7u;
        lane = (uint64_t)((word >> 19) & 3u);
    } else {
        width_index = 2u;
        element_size = 8u;
        indexed_register = (word >> 16) & 15u;
        lane = (uint64_t)((word >> 20) & 1u);
    }
    expected_form = (cdisasm_arm_form_id)(UINT16_C(2722)
        + (subtract ? UINT16_C(3) : UINT16_C(0))
        + (cdisasm_arm_form_id)width_index);

    return raw_is_family && form_is_family
        && instruction->form_id == expected_form
        && instruction->name_id == expected_name
        && instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        && instruction->branch_target == 0u
        && instruction->operand_count == 3u
        && cdisasm_arm_generated_form_matches(instruction)
        && arm_exact_scalable_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + (word & 31u)), element_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_scalable_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)), element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_scalable_lane_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + indexed_register), element_size,
            lane, CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sve_sqrdml_indexed_schema(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned wide_size = (word >> 23) & 1u;
    unsigned high_size_or_lane = (word >> 22) & 1u;
    unsigned width_index;
    unsigned indexed_register;
    uint64_t lane;
    uint8_t element_size;
    int subtract = (word & UINT32_C(0x00000400)) != 0u;
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (word & UINT32_C(0xff20f800)) == UINT32_C(0x44201000);
    int form_is_family = instruction->form_id >= UINT16_C(2728)
        && instruction->form_id <= UINT16_C(2733);
    cdisasm_arm_form_id expected_form;
    cdisasm_arm_name_id expected_name = subtract
        ? CDISASM_ARM_NAME_SQRDMLSH : CDISASM_ARM_NAME_SQRDMLAH;

    if (!raw_is_family && !form_is_family) {
        return 1;
    }
    if (wide_size == 0u) {
        width_index = 0u;
        element_size = 2u;
        indexed_register = (word >> 16) & 7u;
        lane = (uint64_t)((high_size_or_lane << 2)
            | ((word >> 19) & 3u));
    } else if (high_size_or_lane == 0u) {
        width_index = 1u;
        element_size = 4u;
        indexed_register = (word >> 16) & 7u;
        lane = (uint64_t)((word >> 19) & 3u);
    } else {
        width_index = 2u;
        element_size = 8u;
        indexed_register = (word >> 16) & 15u;
        lane = (uint64_t)((word >> 20) & 1u);
    }
    expected_form = (cdisasm_arm_form_id)(UINT16_C(2728)
        + (subtract ? UINT16_C(3) : UINT16_C(0))
        + (cdisasm_arm_form_id)width_index);

    return raw_is_family && form_is_family
        && instruction->form_id == expected_form
        && instruction->name_id == expected_name
        && instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        && instruction->branch_target == 0u
        && instruction->operand_count == 3u
        && cdisasm_arm_generated_form_matches(instruction)
        && arm_exact_scalable_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + (word & 31u)), element_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_scalable_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)), element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_scalable_lane_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + indexed_register), element_size,
            lane, CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sve_aes_unary_schema(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (word & UINT32_C(0xfffffbe0)) == UINT32_C(0x4520e000);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->form_id == UINT16_C(2903)
            || instruction->form_id == UINT16_C(2904));
    cdisasm_arm_form_id expected_form =
        (word & UINT32_C(0x00000400)) != 0u
            ? UINT16_C(2904) : UINT16_C(2903);
    cdisasm_arm_name_id expected_name =
        (word & UINT32_C(0x00000400)) != 0u
            ? CDISASM_ARM_NAME_AESIMC : CDISASM_ARM_NAME_AESMC;
    cdisasm_arm_reg_id zd = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (word & 31u));

    if (!raw_is_family && !form_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family
        && instruction->form_id == expected_form
        && instruction->name_id == expected_name
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        && instruction->operand_count == 2u
        && arm_exact_scalable_operand(
            &instruction->operand[0], zd, 1u,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_scalable_operand(
            &instruction->operand[1], zd, 1u,
            CDISASM_OPERAND_ACCESS_READ_WRITE);
}

static int arm_valid_sve_crypto_binary_schema(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    int raw_is_parent = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (word & UINT32_C(0xff3ef800)) == UINT32_C(0x4522e000);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->form_id == UINT16_C(2905)
            || instruction->form_id == UINT16_C(2906)
            || instruction->form_id == UINT16_C(2907));
    cdisasm_arm_form_id expected_form;
    cdisasm_arm_name_id expected_name;
    uint8_t element_size;
    cdisasm_arm_reg_id zd;
    cdisasm_arm_reg_id zm;

    if (!raw_is_parent && !form_is_family) {
        return 1;
    }
    if (!raw_is_parent) {
        return 0;
    }
    if ((word & UINT32_C(0xfffffc00)) == UINT32_C(0x4522e000)) {
        expected_form = UINT16_C(2905);
        expected_name = CDISASM_ARM_NAME_AESE;
        element_size = 1u;
    } else if ((word & UINT32_C(0xfffffc00))
            == UINT32_C(0x4522e400)) {
        expected_form = UINT16_C(2906);
        expected_name = CDISASM_ARM_NAME_AESD;
        element_size = 1u;
    } else if ((word & UINT32_C(0xfffffc00))
            == UINT32_C(0x4523e000)) {
        expected_form = UINT16_C(2907);
        expected_name = CDISASM_ARM_NAME_SM4E;
        element_size = 4u;
    } else {
        return 0;
    }
    zd = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + (word & 31u));
    zm = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u));
    return form_is_family
        && instruction->form_id == expected_form
        && instruction->name_id == expected_name
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        && instruction->operand_count == 3u
        && arm_exact_scalable_operand(
            &instruction->operand[0], zd, element_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_scalable_operand(
            &instruction->operand[1], zd, element_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_scalable_operand(
            &instruction->operand[2], zm, element_size,
            CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_sve_predicated_shift_sat_round_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
} arm_sve_predicated_shift_sat_round_identity;

static int arm_sve_predicated_shift_sat_round_identity_for_word(
    uint32_t word,
    arm_sve_predicated_shift_sat_round_identity *identity)
{
    static const cdisasm_arm_form_id forms[16] = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_FORM_NONE,
        UINT16_C(2657), UINT16_C(2663),
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_FORM_NONE,
        UINT16_C(2658), UINT16_C(2664),
        UINT16_C(2659), UINT16_C(2665),
        UINT16_C(2660), UINT16_C(2666),
        UINT16_C(2661), UINT16_C(2667),
        UINT16_C(2662), UINT16_C(2668)
    };
    static const cdisasm_arm_name_id names[16] = {
        CDISASM_ARM_NAME_NONE, CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_SRSHL, CDISASM_ARM_NAME_URSHL,
        CDISASM_ARM_NAME_NONE, CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_SRSHLR, CDISASM_ARM_NAME_URSHLR,
        CDISASM_ARM_NAME_SQSHL, CDISASM_ARM_NAME_UQSHL,
        CDISASM_ARM_NAME_SQRSHL, CDISASM_ARM_NAME_UQRSHL,
        CDISASM_ARM_NAME_SQSHLR, CDISASM_ARM_NAME_UQSHLR,
        CDISASM_ARM_NAME_SQRSHLR, CDISASM_ARM_NAME_UQRSHLR
    };
    unsigned operation;

    if ((word & UINT32_C(0xff30e000)) != UINT32_C(0x44008000)) {
        return 0;
    }
    operation = (word >> 16) & 15u;
    if (forms[operation] == CDISASM_ARM_FORM_NONE) {
        return 0;
    }
    identity->form_id = forms[operation];
    identity->name_id = names[operation];
    return 1;
}

static int arm_valid_sve_predicated_shift_sat_round_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_sve_predicated_shift_sat_round_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE
    };
    uint32_t word = instruction->raw_instruction;
    uint8_t element_size = (uint8_t)(UINT8_C(1)
        << ((word >> 22) & 3u));
    cdisasm_arm_reg_id zdn = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (word & 31u));
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_predicated_shift_sat_round_identity_for_word(
            word, &identity);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id >= UINT16_C(2657)
        && instruction->form_id <= UINT16_C(2668);

    if (!raw_is_family && !form_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family
        && instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        && instruction->operand_count == 4u
        && arm_exact_scalable_operand(
            &instruction->operand[0], zdn, element_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_predicate_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_P0 + ((word >> 10) & 7u)),
            element_size, CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_scalable_operand(
            &instruction->operand[2], zdn, element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_scalable_operand(
            &instruction->operand[3], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)),
            element_size, CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_sve_predicated_sat_unary_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    uint8_t zeroing;
} arm_sve_predicated_sat_unary_identity;

static int arm_sve_predicated_sat_unary_identity_for_word(
    uint32_t word, arm_sve_predicated_sat_unary_identity *identity)
{
    static const cdisasm_arm_name_id names[2][2] = {
        { CDISASM_ARM_NAME_URECPE, CDISASM_ARM_NAME_URSQRTE },
        { CDISASM_ARM_NAME_SQABS, CDISASM_ARM_NAME_SQNEG }
    };
    unsigned saturating;
    unsigned operation;
    unsigned zeroing;

    if ((word & UINT32_C(0xff34e000)) != UINT32_C(0x4400a000)) {
        return 0;
    }
    saturating = (word >> 19) & 1u;
    if (saturating == 0u && ((word >> 22) & 3u) != 2u) {
        return 0;
    }
    operation = (word >> 16) & 1u;
    zeroing = (word >> 17) & 1u;
    identity->form_id = (cdisasm_arm_form_id)(
        UINT16_C(2669) + saturating * 4u + operation * 2u + zeroing);
    identity->name_id = names[saturating][operation];
    identity->zeroing = (uint8_t)zeroing;
    return 1;
}

static int arm_valid_sve_predicated_sat_unary_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_sve_predicated_sat_unary_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE, 0u
    };
    uint32_t word = instruction->raw_instruction;
    uint8_t element_size = (uint8_t)(UINT8_C(1)
        << ((word >> 22) & 3u));
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_predicated_sat_unary_identity_for_word(word, &identity);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id >= UINT16_C(2669)
        && instruction->form_id <= UINT16_C(2676);

    if (!raw_is_family && !form_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family
        && instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        && instruction->operand_count == 3u
        && arm_exact_scalable_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + (word & 31u)), element_size,
            identity.zeroing != 0u ? CDISASM_OPERAND_ACCESS_WRITE
                                   : CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_predicate_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_P0 + ((word >> 10) & 7u)),
            element_size,
            identity.zeroing != 0u
                ? CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO
                : CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_scalable_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)),
            element_size, CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_sve_predicated_accumulate_long_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
} arm_sve_predicated_accumulate_long_identity;

static int arm_sve_predicated_accumulate_long_identity_for_word(
    uint32_t word,
    arm_sve_predicated_accumulate_long_identity *identity)
{
    unsigned operation;

    if ((word & UINT32_C(0xff3ee000)) != UINT32_C(0x4404a000)
        || ((word >> 22) & 3u) == 0u) {
        return 0;
    }
    operation = (word >> 16) & 1u;
    identity->form_id = (cdisasm_arm_form_id)(UINT16_C(2677) + operation);
    identity->name_id = operation != 0u
        ? CDISASM_ARM_NAME_UADALP : CDISASM_ARM_NAME_SADALP;
    return 1;
}

static int arm_valid_sve_predicated_accumulate_long_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_sve_predicated_accumulate_long_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE
    };
    uint32_t word = instruction->raw_instruction;
    uint8_t destination_size = (uint8_t)(UINT8_C(1)
        << ((word >> 22) & 3u));
    uint8_t source_size = (uint8_t)(destination_size / 2u);
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_predicated_accumulate_long_identity_for_word(
            word, &identity);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id >= UINT16_C(2677)
        && instruction->form_id <= UINT16_C(2678);

    if (!raw_is_family && !form_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family
        && instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        && instruction->operand_count == 3u
        && arm_exact_scalable_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + (word & 31u)), destination_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_predicate_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_P0 + ((word >> 10) & 7u)),
            destination_size, CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_scalable_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)), source_size,
            CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_sve_predicated_halving_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
} arm_sve_predicated_halving_identity;

static int arm_sve_predicated_halving_identity_for_word(
    uint32_t word, arm_sve_predicated_halving_identity *identity)
{
    static const cdisasm_arm_name_id names[8] = {
        CDISASM_ARM_NAME_SHADD,
        CDISASM_ARM_NAME_UHADD,
        CDISASM_ARM_NAME_SHSUB,
        CDISASM_ARM_NAME_UHSUB,
        CDISASM_ARM_NAME_SRHADD,
        CDISASM_ARM_NAME_URHADD,
        CDISASM_ARM_NAME_SHSUBR,
        CDISASM_ARM_NAME_UHSUBR
    };
    unsigned operation;

    if ((word & UINT32_C(0xff38e000)) != UINT32_C(0x44108000)) {
        return 0;
    }
    operation = (word >> 16) & 7u;
    identity->form_id = (cdisasm_arm_form_id)(
        UINT16_C(2679) + (operation >> 1) + (operation & 1u) * 4u);
    identity->name_id = names[operation];
    return 1;
}

static int arm_valid_sve_predicated_halving_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_sve_predicated_halving_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE
    };
    uint32_t word = instruction->raw_instruction;
    uint8_t element_size = (uint8_t)(UINT8_C(1)
        << ((word >> 22) & 3u));
    cdisasm_arm_reg_id zdn = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (word & 31u));
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_predicated_halving_identity_for_word(word, &identity);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id >= UINT16_C(2679)
        && instruction->form_id <= UINT16_C(2686);

    if (!raw_is_family && !form_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family
        && instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        && instruction->operand_count == 4u
        && arm_exact_scalable_operand(
            &instruction->operand[0], zdn, element_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_predicate_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_P0 + ((word >> 10) & 7u)),
            element_size, CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_scalable_operand(
            &instruction->operand[2], zdn, element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_scalable_operand(
            &instruction->operand[3], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)), element_size,
            CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_sve_predicated_pairwise_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
} arm_sve_predicated_pairwise_identity;

static int arm_sve_predicated_pairwise_identity_for_word(
    uint32_t word, arm_sve_predicated_pairwise_identity *identity)
{
    static const cdisasm_arm_form_id forms[8] = {
        UINT16_C(2687), UINT16_C(2688), CDISASM_ARM_FORM_NONE,
        CDISASM_ARM_FORM_NONE, UINT16_C(2689), UINT16_C(2691),
        UINT16_C(2690), UINT16_C(2692)
    };
    static const cdisasm_arm_name_id names[8] = {
        CDISASM_ARM_NAME_SUBP,
        CDISASM_ARM_NAME_ADDP,
        CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_NONE,
        CDISASM_ARM_NAME_SMAXP,
        CDISASM_ARM_NAME_UMAXP,
        CDISASM_ARM_NAME_SMINP,
        CDISASM_ARM_NAME_UMINP
    };
    unsigned operation;

    if ((word & UINT32_C(0xff38e000)) != UINT32_C(0x4410a000)) {
        return 0;
    }
    operation = (word >> 16) & 7u;
    if (forms[operation] == CDISASM_ARM_FORM_NONE) {
        return 0;
    }
    identity->form_id = forms[operation];
    identity->name_id = names[operation];
    return 1;
}

static int arm_valid_sve_predicated_pairwise_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_sve_predicated_pairwise_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE
    };
    uint32_t word = instruction->raw_instruction;
    uint8_t element_size = (uint8_t)(UINT8_C(1)
        << ((word >> 22) & 3u));
    cdisasm_arm_reg_id zdn = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (word & 31u));
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_predicated_pairwise_identity_for_word(word, &identity);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id >= UINT16_C(2687)
        && instruction->form_id <= UINT16_C(2692);

    if (!raw_is_family && !form_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family
        && instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        && instruction->operand_count == 4u
        && arm_exact_scalable_operand(
            &instruction->operand[0], zdn, element_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_predicate_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_P0 + ((word >> 10) & 7u)),
            element_size, CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_scalable_operand(
            &instruction->operand[2], zdn, element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_scalable_operand(
            &instruction->operand[3], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)), element_size,
            CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_advsimd_compare_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
} arm_advsimd_compare_identity;

static int arm_advsimd_compare_identity_for_word(
    uint32_t word, arm_advsimd_compare_identity *identity)
{
    switch (word & UINT32_C(0xbf20fc00)) {
        case UINT32_C(0x0e203400):
            identity->form_id = UINT16_C(6120);
            identity->name_id = CDISASM_ARM_NAME_CMGT;
            return 1;
        case UINT32_C(0x0e203c00):
            identity->form_id = UINT16_C(6121);
            identity->name_id = CDISASM_ARM_NAME_CMGE;
            return 1;
        case UINT32_C(0x2e203400):
            identity->form_id = UINT16_C(6162);
            identity->name_id = CDISASM_ARM_NAME_CMHI;
            return 1;
        case UINT32_C(0x2e203c00):
            identity->form_id = UINT16_C(6163);
            identity->name_id = CDISASM_ARM_NAME_CMHS;
            return 1;
        case UINT32_C(0x2e208c00):
            identity->form_id = UINT16_C(6173);
            identity->name_id = CDISASM_ARM_NAME_CMEQ;
            return 1;
        default:
            return 0;
    }
}

static int arm_is_advsimd_compare_form(cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(6120) || form_id == UINT16_C(6121)
        || form_id == UINT16_C(6162) || form_id == UINT16_C(6163)
        || form_id == UINT16_C(6173);
}

static int arm_is_advsimd_compare_name(cdisasm_arm_name_id name_id)
{
    return name_id == CDISASM_ARM_NAME_CMGT
        || name_id == CDISASM_ARM_NAME_CMGE
        || name_id == CDISASM_ARM_NAME_CMHI
        || name_id == CDISASM_ARM_NAME_CMHS
        || name_id == CDISASM_ARM_NAME_CMEQ;
}

static int arm_valid_advsimd_compare_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_advsimd_compare_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE
    };
    uint32_t word = instruction->raw_instruction;
    unsigned q = (word >> 30) & 1u;
    unsigned size_code = (word >> 22) & 3u;
    uint8_t element_size = (uint8_t)(UINT8_C(1) << size_code);
    uint8_t vector_size = q != 0u ? 16u : 8u;
    int raw_is_envelope = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_advsimd_compare_identity_for_word(word, &identity);
    int raw_is_family = raw_is_envelope
        && (size_code <= 2u || q != 0u);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_is_advsimd_compare_form(instruction->form_id);
    int name_is_family = arm_is_advsimd_compare_name(instruction->name_id);
    int name_claims_fixed_family = name_is_family;
    int exact_scalar_zero_sibling = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->form_id == UINT16_C(5775)
            || instruction->form_id == UINT16_C(5776)
            || instruction->form_id == UINT16_C(5793)
            || (word & UINT32_C(0xfffffc00)) == UINT32_C(0x5ee08800)
            || (word & UINT32_C(0xfffffc00)) == UINT32_C(0x5ee09800)
            || (word & UINT32_C(0xfffffc00)) == UINT32_C(0x7ee08800));

    /* Scalar-register and compare-with-zero CMGT/CMEQ/CMGE siblings remain
     * catalog-only.  CMLT/CMLE are claimed by their separate exact schema
     * below.  Reject fabricated same-name public instructions until the
     * remaining siblings gain exact schemas of their own. */
    if (exact_scalar_zero_sibling) {
        return 1;
    }
    if (!raw_is_envelope && !form_is_family
        && !name_claims_fixed_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->branch_target == 0u
        && instruction->operand_count == 3u
        && arm_exact_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + (word & 31u)),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_vector_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 16) & 31u)),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_advsimd_compare_zero_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    uint8_t scalar;
} arm_advsimd_compare_zero_identity;

static int arm_advsimd_compare_zero_identity_for_word(
    uint32_t word, arm_advsimd_compare_zero_identity *identity)
{
    if ((word & UINT32_C(0xfffffc00)) == UINT32_C(0x5ee0a800)) {
        identity->form_id = UINT16_C(5777);
        identity->name_id = CDISASM_ARM_NAME_CMLT;
        identity->scalar = 1u;
        return 1;
    }
    if ((word & UINT32_C(0xfffffc00)) == UINT32_C(0x7ee09800)) {
        identity->form_id = UINT16_C(5794);
        identity->name_id = CDISASM_ARM_NAME_CMLE;
        identity->scalar = 1u;
        return 1;
    }
    switch (word & UINT32_C(0xbf3ffc00)) {
        case UINT32_C(0x0e20a800):
            identity->form_id = UINT16_C(6013);
            identity->name_id = CDISASM_ARM_NAME_CMLT;
            identity->scalar = 0u;
            return 1;
        case UINT32_C(0x2e209800):
            identity->form_id = UINT16_C(6045);
            identity->name_id = CDISASM_ARM_NAME_CMLE;
            identity->scalar = 0u;
            return 1;
        default:
            return 0;
    }
}

static int arm_is_advsimd_compare_zero_form(cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(5777) || form_id == UINT16_C(5794)
        || form_id == UINT16_C(6013) || form_id == UINT16_C(6045);
}

static int arm_is_advsimd_compare_zero_name(cdisasm_arm_name_id name_id)
{
    return name_id == CDISASM_ARM_NAME_CMLT
        || name_id == CDISASM_ARM_NAME_CMLE;
}

static int arm_valid_advsimd_compare_zero_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_advsimd_compare_zero_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE, 0u
    };
    uint32_t word = instruction->raw_instruction;
    unsigned q = (word >> 30) & 1u;
    unsigned size_code = (word >> 22) & 3u;
    uint8_t element_size;
    uint8_t total_size;
    cdisasm_arm_reg_id register_base;
    int raw_is_envelope = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_advsimd_compare_zero_identity_for_word(word, &identity);
    int raw_is_family = raw_is_envelope
        && (identity.scalar != 0u || size_code <= 2u || q != 0u);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_is_advsimd_compare_zero_form(instruction->form_id);
    int name_is_family = arm_is_advsimd_compare_zero_name(
        instruction->name_id);

    if (!raw_is_envelope && !form_is_family && !name_is_family) {
        return 1;
    }
    if (!raw_is_family || !form_is_family || !name_is_family
        || instruction->form_id != identity.form_id
        || instruction->name_id != identity.name_id) {
        return 0;
    }
    element_size = identity.scalar != 0u
        ? 8u : (uint8_t)(UINT8_C(1) << size_code);
    total_size = identity.scalar != 0u ? 8u : q != 0u ? 16u : 8u;
    register_base = identity.scalar != 0u
        ? CDISASM_ARM_REG_D0 : CDISASM_ARM_REG_V0;
    return instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->branch_target == 0u
        && instruction->operand_count == 3u
        && arm_exact_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                register_base + (word & 31u)),
            total_size, element_size, CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                register_base + ((word >> 5) & 31u)),
            total_size, element_size, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_u8_immediate_operand(&instruction->operand[2], 0u);
}

typedef struct arm_advsimd_cmtst_identity {
    cdisasm_arm_form_id form_id;
    uint8_t scalar;
} arm_advsimd_cmtst_identity;

static int arm_advsimd_cmtst_identity_for_word(
    uint32_t word, arm_advsimd_cmtst_identity *identity)
{
    if ((word & UINT32_C(0xffe0fc00)) == UINT32_C(0x5ee08c00)) {
        identity->form_id = UINT16_C(5831);
        identity->scalar = 1u;
        return 1;
    }
    if ((word & UINT32_C(0xbf20fc00)) == UINT32_C(0x0e208c00)) {
        identity->form_id = UINT16_C(6131);
        identity->scalar = 0u;
        return 1;
    }
    return 0;
}

static int arm_is_advsimd_cmtst_form(cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(5831) || form_id == UINT16_C(6131);
}

static int arm_valid_advsimd_cmtst_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_advsimd_cmtst_identity identity = {
        CDISASM_ARM_FORM_NONE, 0u
    };
    uint32_t word = instruction->raw_instruction;
    unsigned q = (word >> 30) & 1u;
    unsigned size_code = (word >> 22) & 3u;
    uint8_t element_size;
    uint8_t total_size;
    cdisasm_arm_reg_id register_base;
    int raw_is_envelope = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_advsimd_cmtst_identity_for_word(word, &identity);
    int raw_is_family = raw_is_envelope
        && (identity.scalar != 0u || size_code <= 2u || q != 0u);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_is_advsimd_cmtst_form(instruction->form_id);
    int name_is_family = instruction->name_id == CDISASM_ARM_NAME_CMTST;

    /* CMTST has exactly one scalar and one fixed-vector public form.  Raw,
     * form, and mnemonic claims must therefore agree on one exact schema. */
    if (!raw_is_envelope && !form_is_family && !name_is_family) {
        return 1;
    }
    if (!raw_is_family || !form_is_family || !name_is_family
        || instruction->form_id != identity.form_id) {
        return 0;
    }
    element_size = identity.scalar != 0u
        ? 8u : (uint8_t)(UINT8_C(1) << size_code);
    total_size = identity.scalar != 0u ? 8u : q != 0u ? 16u : 8u;
    register_base = identity.scalar != 0u
        ? CDISASM_ARM_REG_D0 : CDISASM_ARM_REG_V0;
    return instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->branch_target == 0u
        && instruction->operand_count == 3u
        && arm_exact_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                register_base + (word & 31u)),
            total_size, element_size, CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                register_base + ((word >> 5) & 31u)),
            total_size, element_size, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_vector_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                register_base + ((word >> 16) & 31u)),
            total_size, element_size, CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_advsimd_variable_shift_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    uint8_t scalar;
} arm_advsimd_variable_shift_identity;

static int arm_advsimd_variable_shift_identity_for_word(
    uint32_t word, arm_advsimd_variable_shift_identity *identity)
{
    if ((word & UINT32_C(0xffe0fc00)) == UINT32_C(0x5ee04400)) {
        identity->form_id = UINT16_C(5826);
        identity->name_id = CDISASM_ARM_NAME_SSHL;
        identity->scalar = 1u;
        return 1;
    }
    if ((word & UINT32_C(0xffe0fc00)) == UINT32_C(0x7ee04400)) {
        identity->form_id = UINT16_C(5841);
        identity->name_id = CDISASM_ARM_NAME_USHL;
        identity->scalar = 1u;
        return 1;
    }
    switch (word & UINT32_C(0xbf20fc00)) {
        case UINT32_C(0x0e204400):
            identity->form_id = UINT16_C(6122);
            identity->name_id = CDISASM_ARM_NAME_SSHL;
            identity->scalar = 0u;
            return 1;
        case UINT32_C(0x2e204400):
            identity->form_id = UINT16_C(6164);
            identity->name_id = CDISASM_ARM_NAME_USHL;
            identity->scalar = 0u;
            return 1;
        default:
            return 0;
    }
}

static int arm_is_advsimd_variable_shift_form(
    cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(5826) || form_id == UINT16_C(5841)
        || form_id == UINT16_C(6122) || form_id == UINT16_C(6164);
}

static int arm_is_advsimd_variable_shift_name(
    cdisasm_arm_name_id name_id)
{
    return name_id == CDISASM_ARM_NAME_SSHL
        || name_id == CDISASM_ARM_NAME_USHL;
}

static int arm_valid_advsimd_variable_shift_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_advsimd_variable_shift_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE, 0u
    };
    uint32_t word = instruction->raw_instruction;
    unsigned q = (word >> 30) & 1u;
    unsigned size_code = (word >> 22) & 3u;
    uint8_t element_size;
    uint8_t total_size;
    cdisasm_arm_reg_id register_base;
    int raw_is_envelope = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_advsimd_variable_shift_identity_for_word(word, &identity);
    int raw_is_family = raw_is_envelope
        && (identity.scalar != 0u || size_code <= 2u || q != 0u);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_is_advsimd_variable_shift_form(instruction->form_id);
    int name_is_family = arm_is_advsimd_variable_shift_name(
        instruction->name_id);

    /* SSHL/USHL each have one scalar and one fixed-vector public form.
     * Require every raw, form, and mnemonic claim to select the same exact
     * schema and reject the reserved Q=0,size=11 vector controls. */
    if (!raw_is_envelope && !form_is_family && !name_is_family) {
        return 1;
    }
    if (!raw_is_family || !form_is_family || !name_is_family
        || instruction->form_id != identity.form_id
        || instruction->name_id != identity.name_id) {
        return 0;
    }
    element_size = identity.scalar != 0u
        ? 8u : (uint8_t)(UINT8_C(1) << size_code);
    total_size = identity.scalar != 0u ? 8u : q != 0u ? 16u : 8u;
    register_base = identity.scalar != 0u
        ? CDISASM_ARM_REG_D0 : CDISASM_ARM_REG_V0;
    return instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->branch_target == 0u
        && instruction->operand_count == 3u
        && arm_exact_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                register_base + (word & 31u)),
            total_size, element_size, CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                register_base + ((word >> 5) & 31u)),
            total_size, element_size, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_vector_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                register_base + ((word >> 16) & 31u)),
            total_size, element_size, CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_advsimd_shift_right_immediate_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    uint8_t scalar;
    uint8_t left_shift;
    cdisasm_operand_access destination_access;
} arm_advsimd_shift_right_immediate_identity;

static int arm_advsimd_shift_right_immediate_identity_for_word(
    uint32_t word, arm_advsimd_shift_right_immediate_identity *identity)
{
    identity->left_shift = 0u;
    switch (word & UINT32_C(0xffc0fc00)) {
        case UINT32_C(0x5f400400):
            identity->form_id = UINT16_C(5853);
            identity->name_id = CDISASM_ARM_NAME_SSHR;
            identity->scalar = 1u;
            identity->destination_access = CDISASM_OPERAND_ACCESS_WRITE;
            return 1;
        case UINT32_C(0x7f400400):
            identity->form_id = UINT16_C(5863);
            identity->name_id = CDISASM_ARM_NAME_USHR;
            identity->scalar = 1u;
            identity->destination_access = CDISASM_OPERAND_ACCESS_WRITE;
            return 1;
        case UINT32_C(0x5f401400):
            identity->form_id = UINT16_C(5854);
            identity->name_id = CDISASM_ARM_NAME_SSRA;
            identity->scalar = 1u;
            identity->destination_access =
                CDISASM_OPERAND_ACCESS_READ_WRITE;
            return 1;
        case UINT32_C(0x7f401400):
            identity->form_id = UINT16_C(5864);
            identity->name_id = CDISASM_ARM_NAME_USRA;
            identity->scalar = 1u;
            identity->destination_access =
                CDISASM_OPERAND_ACCESS_READ_WRITE;
            return 1;
        case UINT32_C(0x5f402400):
            identity->form_id = UINT16_C(5855);
            identity->name_id = CDISASM_ARM_NAME_SRSHR;
            identity->scalar = 1u;
            identity->destination_access = CDISASM_OPERAND_ACCESS_WRITE;
            return 1;
        case UINT32_C(0x7f402400):
            identity->form_id = UINT16_C(5865);
            identity->name_id = CDISASM_ARM_NAME_URSHR;
            identity->scalar = 1u;
            identity->destination_access = CDISASM_OPERAND_ACCESS_WRITE;
            return 1;
        case UINT32_C(0x5f403400):
            identity->form_id = UINT16_C(5856);
            identity->name_id = CDISASM_ARM_NAME_SRSRA;
            identity->scalar = 1u;
            identity->destination_access =
                CDISASM_OPERAND_ACCESS_READ_WRITE;
            return 1;
        case UINT32_C(0x7f403400):
            identity->form_id = UINT16_C(5866);
            identity->name_id = CDISASM_ARM_NAME_URSRA;
            identity->scalar = 1u;
            identity->destination_access =
                CDISASM_OPERAND_ACCESS_READ_WRITE;
            return 1;
        case UINT32_C(0x5f405400):
            identity->form_id = UINT16_C(5857);
            identity->name_id = CDISASM_ARM_NAME_SHL;
            identity->scalar = 1u;
            identity->left_shift = 1u;
            identity->destination_access = CDISASM_OPERAND_ACCESS_WRITE;
            return 1;
        case UINT32_C(0x7f404400):
            identity->form_id = UINT16_C(5867);
            identity->name_id = CDISASM_ARM_NAME_SRI;
            identity->scalar = 1u;
            identity->destination_access =
                CDISASM_OPERAND_ACCESS_READ_WRITE;
            return 1;
        case UINT32_C(0x7f405400):
            identity->form_id = UINT16_C(5868);
            identity->name_id = CDISASM_ARM_NAME_SLI;
            identity->scalar = 1u;
            identity->left_shift = 1u;
            identity->destination_access =
                CDISASM_OPERAND_ACCESS_READ_WRITE;
            return 1;
        default:
            break;
    }
    switch (word & UINT32_C(0xbf80fc00)) {
        case UINT32_C(0x0f000400):
            identity->form_id = UINT16_C(6215);
            identity->name_id = CDISASM_ARM_NAME_SSHR;
            identity->scalar = 0u;
            identity->destination_access = CDISASM_OPERAND_ACCESS_WRITE;
            return 1;
        case UINT32_C(0x2f000400):
            identity->form_id = UINT16_C(6228);
            identity->name_id = CDISASM_ARM_NAME_USHR;
            identity->scalar = 0u;
            identity->destination_access = CDISASM_OPERAND_ACCESS_WRITE;
            return 1;
        case UINT32_C(0x0f001400):
            identity->form_id = UINT16_C(6216);
            identity->name_id = CDISASM_ARM_NAME_SSRA;
            identity->scalar = 0u;
            identity->destination_access =
                CDISASM_OPERAND_ACCESS_READ_WRITE;
            return 1;
        case UINT32_C(0x2f001400):
            identity->form_id = UINT16_C(6229);
            identity->name_id = CDISASM_ARM_NAME_USRA;
            identity->scalar = 0u;
            identity->destination_access =
                CDISASM_OPERAND_ACCESS_READ_WRITE;
            return 1;
        case UINT32_C(0x0f002400):
            identity->form_id = UINT16_C(6217);
            identity->name_id = CDISASM_ARM_NAME_SRSHR;
            identity->scalar = 0u;
            identity->destination_access = CDISASM_OPERAND_ACCESS_WRITE;
            return 1;
        case UINT32_C(0x2f002400):
            identity->form_id = UINT16_C(6230);
            identity->name_id = CDISASM_ARM_NAME_URSHR;
            identity->scalar = 0u;
            identity->destination_access = CDISASM_OPERAND_ACCESS_WRITE;
            return 1;
        case UINT32_C(0x0f003400):
            identity->form_id = UINT16_C(6218);
            identity->name_id = CDISASM_ARM_NAME_SRSRA;
            identity->scalar = 0u;
            identity->destination_access =
                CDISASM_OPERAND_ACCESS_READ_WRITE;
            return 1;
        case UINT32_C(0x2f003400):
            identity->form_id = UINT16_C(6231);
            identity->name_id = CDISASM_ARM_NAME_URSRA;
            identity->scalar = 0u;
            identity->destination_access =
                CDISASM_OPERAND_ACCESS_READ_WRITE;
            return 1;
        case UINT32_C(0x0f005400):
            identity->form_id = UINT16_C(6219);
            identity->name_id = CDISASM_ARM_NAME_SHL;
            identity->scalar = 0u;
            identity->left_shift = 1u;
            identity->destination_access = CDISASM_OPERAND_ACCESS_WRITE;
            return 1;
        case UINT32_C(0x2f004400):
            identity->form_id = UINT16_C(6232);
            identity->name_id = CDISASM_ARM_NAME_SRI;
            identity->scalar = 0u;
            identity->destination_access =
                CDISASM_OPERAND_ACCESS_READ_WRITE;
            return 1;
        case UINT32_C(0x2f005400):
            identity->form_id = UINT16_C(6233);
            identity->name_id = CDISASM_ARM_NAME_SLI;
            identity->scalar = 0u;
            identity->left_shift = 1u;
            identity->destination_access =
                CDISASM_OPERAND_ACCESS_READ_WRITE;
            return 1;
        default:
            return 0;
    }
}

static int arm_is_advsimd_shift_right_immediate_form(
    cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(5853) || form_id == UINT16_C(5863)
        || form_id == UINT16_C(5854) || form_id == UINT16_C(5864)
        || form_id == UINT16_C(5855) || form_id == UINT16_C(5865)
        || form_id == UINT16_C(5856) || form_id == UINT16_C(5866)
        || form_id == UINT16_C(6215) || form_id == UINT16_C(6228)
        || form_id == UINT16_C(6216) || form_id == UINT16_C(6229)
        || form_id == UINT16_C(6217) || form_id == UINT16_C(6230)
        || form_id == UINT16_C(6218) || form_id == UINT16_C(6231)
        || form_id == UINT16_C(5857) || form_id == UINT16_C(6219)
        || form_id == UINT16_C(5867) || form_id == UINT16_C(6232)
        || form_id == UINT16_C(5868) || form_id == UINT16_C(6233);
}

static int arm_valid_advsimd_shift_right_immediate_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_advsimd_shift_right_immediate_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE, 0u, 0u,
        CDISASM_OPERAND_ACCESS_NONE
    };
    uint32_t word = instruction->raw_instruction;
    unsigned q = (word >> 30) & 1u;
    unsigned immh = (word >> 19) & 15u;
    unsigned encoded_immediate = (immh << 3) | ((word >> 16) & 7u);
    unsigned element_bits;
    unsigned immediate;
    uint8_t element_size;
    uint8_t total_size;
    cdisasm_arm_reg_id register_base;
    int raw_is_envelope = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_advsimd_shift_right_immediate_identity_for_word(
            word, &identity)
        && (identity.scalar != 0u || immh != 0u);
    int raw_is_family = raw_is_envelope
        && (identity.scalar != 0u
            || (immh != 0u && (q != 0u || (immh & 8u) == 0u)));
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_is_advsimd_shift_right_immediate_form(instruction->form_id);
    int name_is_family = (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR) == 0u
        && (instruction->name_id == CDISASM_ARM_NAME_SSHR
            || instruction->name_id == CDISASM_ARM_NAME_USHR
            || instruction->name_id == CDISASM_ARM_NAME_SSRA
            || instruction->name_id == CDISASM_ARM_NAME_USRA
            || instruction->name_id == CDISASM_ARM_NAME_SRSHR
            || instruction->name_id == CDISASM_ARM_NAME_URSHR
            || instruction->name_id == CDISASM_ARM_NAME_SRSRA
            || instruction->name_id == CDISASM_ARM_NAME_URSRA
            || instruction->name_id == CDISASM_ARM_NAME_SHL
            || instruction->name_id == CDISASM_ARM_NAME_SRI
            || instruction->name_id == CDISASM_ARM_NAME_SLI);

    /* Bind the pinned scalar and fixed-vector SSHR/USHR, SSRA/USRA,
     * SRSHR/URSHR, SRSRA/URSRA, SHL, SRI, and SLI raw/form/name/access
     * identities.  Reserved immh controls and fabricated same-name objects
     * fail closed; scalable SVE/SVE2 siblings own their name space separately. */
    if (!raw_is_envelope && !form_is_family && !name_is_family) {
        return 1;
    }
    if (!raw_is_family || !form_is_family || !name_is_family
        || instruction->form_id != identity.form_id
        || instruction->name_id != identity.name_id) {
        return 0;
    }
    element_bits = identity.scalar != 0u || (immh & 8u) != 0u ? 64u
        : (immh & 4u) != 0u ? 32u
        : (immh & 2u) != 0u ? 16u : 8u;
    immediate = identity.left_shift != 0u
        ? encoded_immediate - element_bits
        : 2u * element_bits - encoded_immediate;
    element_size = (uint8_t)(element_bits / 8u);
    total_size = identity.scalar != 0u ? 8u : q != 0u ? 16u : 8u;
    register_base = identity.scalar != 0u
        ? CDISASM_ARM_REG_D0 : CDISASM_ARM_REG_V0;
    return instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->branch_target == 0u
        && instruction->operand_count == 3u
        && arm_exact_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                register_base + (word & 31u)),
            total_size, element_size, identity.destination_access)
        && arm_exact_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                register_base + ((word >> 5) & 31u)),
            total_size, element_size, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_u8_immediate_operand(
            &instruction->operand[2], (uint64_t)immediate)
        && instruction->operand[2].shift_type == CDISASM_ARM_SHIFT_NONE
        && instruction->operand[2].shift_amount == 0u;
}

typedef struct arm_advsimd_shift_narrow_widen_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id base_name_id;
    uint8_t widening;
} arm_advsimd_shift_narrow_widen_identity;

static int arm_advsimd_shift_narrow_widen_identity_for_word(
    uint32_t word, arm_advsimd_shift_narrow_widen_identity *identity)
{
    switch (word & UINT32_C(0xbf80fc00)) {
        case UINT32_C(0x0f008400):
            identity->form_id = UINT16_C(6221);
            identity->base_name_id = CDISASM_ARM_NAME_SHRN;
            identity->widening = 0u;
            return 1;
        case UINT32_C(0x0f008c00):
            identity->form_id = UINT16_C(6222);
            identity->base_name_id = CDISASM_ARM_NAME_RSHRN;
            identity->widening = 0u;
            return 1;
        case UINT32_C(0x0f00a400):
            identity->form_id = UINT16_C(6225);
            identity->base_name_id = CDISASM_ARM_NAME_SSHLL;
            identity->widening = 1u;
            return 1;
        case UINT32_C(0x2f00a400):
            identity->form_id = UINT16_C(6240);
            identity->base_name_id = CDISASM_ARM_NAME_USHLL;
            identity->widening = 1u;
            return 1;
        default:
            return 0;
    }
}

static int arm_is_advsimd_shift_narrow_widen_form(
    cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(6221) || form_id == UINT16_C(6222)
        || form_id == UINT16_C(6225) || form_id == UINT16_C(6240);
}

static int arm_exact_advsimd_shift_narrow_widen_vector_operand(
    const cdisasm_arm_operand *operand, cdisasm_arm_reg_id reg,
    uint8_t total_size, uint8_t element_size,
    cdisasm_operand_access access)
{
    return arm_exact_vector_operand(
            operand, reg, total_size, element_size, access)
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u
        && operand->address == 0u
        && operand->imm == 0u
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u;
}

static int arm_exact_advsimd_shift_narrow_widen_immediate_operand(
    const cdisasm_arm_operand *operand, uint64_t value)
{
    return arm_exact_u8_immediate_operand(operand, value)
        && operand->reg == CDISASM_ARM_REG_NONE
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u
        && operand->address == 0u
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u
        && operand->extend_type == CDISASM_ARM_EXTEND_NONE
        && operand->scale == 0u;
}

static int arm_valid_advsimd_shift_narrow_widen_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_advsimd_shift_narrow_widen_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE, 0u
    };
    uint32_t word = instruction->raw_instruction;
    unsigned q = (word >> 30) & 1u;
    unsigned immh = (word >> 19) & 15u;
    unsigned encoded_immediate = (immh << 3) | ((word >> 16) & 7u);
    unsigned narrow_bits = (immh & 4u) != 0u ? 32u
        : (immh & 2u) != 0u ? 16u : 8u;
    unsigned immediate;
    uint8_t narrow_size = (uint8_t)(narrow_bits / 8u);
    uint8_t wide_size = (uint8_t)(narrow_size * 2u);
    cdisasm_arm_name_id expected_name;
    int has_identity = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_advsimd_shift_narrow_widen_identity_for_word(word, &identity);
    int modified_immediate_collision = immh == 0u
        && identity.base_name_id != CDISASM_ARM_NAME_RSHRN;
    int raw_is_envelope = has_identity && !modified_immediate_collision;
    int raw_is_family = raw_is_envelope && immh >= 1u && immh <= 7u;
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_is_advsimd_shift_narrow_widen_form(instruction->form_id);
    int name_is_family = instruction->name_id == CDISASM_ARM_NAME_SHRN
        || instruction->name_id == CDISASM_ARM_NAME_RSHRN
        || instruction->name_id == CDISASM_ARM_NAME_SSHLL
        || instruction->name_id == CDISASM_ARM_NAME_USHLL
        || instruction->name_id == CDISASM_ARM_NAME_SXTL
        || instruction->name_id == CDISASM_ARM_NAME_UXTL;

    if (!raw_is_envelope && !form_is_family && !name_is_family) {
        return 1;
    }
    if (!raw_is_family || !form_is_family || !name_is_family) {
        return 0;
    }
    immediate = identity.widening != 0u
        ? encoded_immediate - narrow_bits
        : 2u * narrow_bits - encoded_immediate;
    expected_name = identity.base_name_id;
    if (identity.widening != 0u && immediate == 0u) {
        expected_name = identity.base_name_id == CDISASM_ARM_NAME_SSHLL
            ? CDISASM_ARM_NAME_SXTL : CDISASM_ARM_NAME_UXTL;
    }
    if (instruction->form_id != identity.form_id
        || instruction->name_id != expected_name
        || instruction->opcode_size != 4u
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->instruction_flags
            != CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        || instruction->branch_target != 0u
        || instruction->operand_count
            != (identity.widening != 0u && immediate == 0u ? 2u : 3u)) {
        return 0;
    }
    if (identity.widening != 0u) {
        if (!arm_exact_advsimd_shift_narrow_widen_vector_operand(
                &instruction->operand[0], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_V0 + (word & 31u)),
                16u, wide_size, CDISASM_OPERAND_ACCESS_WRITE)
            || !arm_exact_advsimd_shift_narrow_widen_vector_operand(
                &instruction->operand[1], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)),
                q != 0u ? 16u : 8u, narrow_size,
                CDISASM_OPERAND_ACCESS_READ)) {
            return 0;
        }
    } else if (!arm_exact_advsimd_shift_narrow_widen_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + (word & 31u)),
            q != 0u ? 16u : 8u, narrow_size,
            q != 0u ? CDISASM_OPERAND_ACCESS_READ_WRITE
                     : CDISASM_OPERAND_ACCESS_WRITE)
        || !arm_exact_advsimd_shift_narrow_widen_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)),
            16u, wide_size, CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    return (identity.widening != 0u && immediate == 0u)
        || arm_exact_advsimd_shift_narrow_widen_immediate_operand(
            &instruction->operand[2], (uint64_t)immediate);
}

typedef struct arm_advsimd_sat_shift_convert_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    uint8_t conversion;
} arm_advsimd_sat_shift_convert_identity;

static int arm_advsimd_sat_shift_convert_identity_for_word(
    uint32_t word, arm_advsimd_sat_shift_convert_identity *identity)
{
    static const struct {
        uint32_t operation;
        cdisasm_arm_form_id form_id;
        cdisasm_arm_name_id name_id;
        uint8_t conversion;
    } operations[] = {
        { UINT32_C(0x0f007400), UINT16_C(6220), CDISASM_ARM_NAME_SQSHL, 0u },
        { UINT32_C(0x0f00e400), UINT16_C(6226), CDISASM_ARM_NAME_SCVTF, 1u },
        { UINT32_C(0x0f00fc00), UINT16_C(6227), CDISASM_ARM_NAME_FCVTZS, 1u },
        { UINT32_C(0x2f006400), UINT16_C(6234), CDISASM_ARM_NAME_SQSHLU, 0u },
        { UINT32_C(0x2f007400), UINT16_C(6235), CDISASM_ARM_NAME_UQSHL, 0u },
        { UINT32_C(0x2f00e400), UINT16_C(6241), CDISASM_ARM_NAME_UCVTF, 1u },
        { UINT32_C(0x2f00fc00), UINT16_C(6242), CDISASM_ARM_NAME_FCVTZU, 1u }
    };
    uint32_t operation = word & UINT32_C(0xbf80fc00);
    unsigned index;

    for (index = 0u; index < sizeof(operations) / sizeof(operations[0]); ++index) {
        if (operation == operations[index].operation) {
            identity->form_id = operations[index].form_id;
            identity->name_id = operations[index].name_id;
            identity->conversion = operations[index].conversion;
            return 1;
        }
    }
    return 0;
}

static int arm_valid_advsimd_sat_shift_convert_immediate_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_advsimd_sat_shift_convert_identity identity;
    uint32_t word = instruction->raw_instruction;
    unsigned q = (word >> 30) & 1u;
    unsigned immh = (word >> 19) & 15u;
    unsigned encoded = (immh << 3) | ((word >> 16) & 7u);
    unsigned element_bits = (immh & 8u) != 0u ? 64u
        : (immh & 4u) != 0u ? 32u : (immh & 2u) != 0u ? 16u : 8u;
    uint8_t element_size = (uint8_t)(element_bits / 8u);
    uint8_t total_size = q != 0u ? 16u : 8u;
    int has_identity = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_advsimd_sat_shift_convert_identity_for_word(word, &identity);
    int raw_is_envelope = has_identity && immh != 0u;
    int raw_is_family = raw_is_envelope
        && (q != 0u || (immh & 8u) == 0u);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->form_id == UINT16_C(6220)
            || instruction->form_id == UINT16_C(6226)
            || instruction->form_id == UINT16_C(6227)
            || instruction->form_id == UINT16_C(6234)
            || instruction->form_id == UINT16_C(6235)
            || instruction->form_id == UINT16_C(6241)
            || instruction->form_id == UINT16_C(6242));
    uint64_t immediate;
    uint64_t flags;

    if (!raw_is_envelope && !form_is_family) return 1;
    if (!raw_is_family || !form_is_family
        || instruction->form_id != identity.form_id
        || instruction->name_id != identity.name_id) return 0;
    immediate = identity.conversion != 0u
        ? 2u * element_bits - encoded : encoded - element_bits;
    flags = CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        | (identity.conversion != 0u
            ? CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT : 0u);
    return instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags == flags
        && instruction->branch_target == 0u
        && instruction->operand_count == 3u
        && arm_exact_vector_operand(
            &instruction->operand[0],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + (word & 31u)),
            total_size, element_size, CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_vector_operand(
            &instruction->operand[1],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)),
            total_size, element_size, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_u8_immediate_operand(&instruction->operand[2], immediate)
        && instruction->operand[2].shift_type == CDISASM_ARM_SHIFT_NONE
        && instruction->operand[2].shift_amount == 0u;
}

typedef struct arm_advsimd_modified_immediate_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    uint8_t element_size;
    uint8_t scalar;
    cdisasm_arm_shift_type shift_type;
    uint8_t shift_amount;
    cdisasm_operand_access destination_access;
} arm_advsimd_modified_immediate_identity;

static int arm_advsimd_modified_immediate_identity_for_word(
    uint32_t word, arm_advsimd_modified_immediate_identity *identity)
{
    unsigned cmode = (word >> 12) & 15u;

    if ((word & UINT32_C(0xbff89c00)) == UINT32_C(0x0f001400)
        || (word & UINT32_C(0xbff89c00)) == UINT32_C(0x2f001400)) {
        identity->form_id = (word & UINT32_C(0x20000000)) == 0u
            ? UINT16_C(6200) : UINT16_C(6208);
        identity->name_id = (word & UINT32_C(0x20000000)) == 0u
            ? CDISASM_ARM_NAME_ORR : CDISASM_ARM_NAME_BIC;
        identity->element_size = 4u;
        identity->scalar = 0u;
        identity->shift_amount = (uint8_t)(4u * (cmode - 1u));
        identity->shift_type = identity->shift_amount == 0u
            ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL;
        identity->destination_access =
            CDISASM_OPERAND_ACCESS_READ_WRITE;
        return 1;
    }
    if ((word & UINT32_C(0xbff8dc00)) == UINT32_C(0x0f009400)
        || (word & UINT32_C(0xbff8dc00)) == UINT32_C(0x2f009400)) {
        identity->form_id = (word & UINT32_C(0x20000000)) == 0u
            ? UINT16_C(6202) : UINT16_C(6210);
        identity->name_id = (word & UINT32_C(0x20000000)) == 0u
            ? CDISASM_ARM_NAME_ORR : CDISASM_ARM_NAME_BIC;
        identity->element_size = 2u;
        identity->scalar = 0u;
        identity->shift_amount = (cmode & 2u) != 0u ? 8u : 0u;
        identity->shift_type = identity->shift_amount == 0u
            ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL;
        identity->destination_access =
            CDISASM_OPERAND_ACCESS_READ_WRITE;
        return 1;
    }
    if ((word & UINT32_C(0xbff89c00)) == UINT32_C(0x0f000400)
        || (word & UINT32_C(0xbff89c00)) == UINT32_C(0x2f000400)) {
        identity->form_id = (word & UINT32_C(0x20000000)) == 0u
            ? UINT16_C(6199) : UINT16_C(6207);
        identity->name_id = (word & UINT32_C(0x20000000)) == 0u
            ? CDISASM_ARM_NAME_MOVI : CDISASM_ARM_NAME_MVNI;
        identity->element_size = 4u;
        identity->scalar = 0u;
        identity->shift_amount = (uint8_t)(4u * cmode);
        identity->shift_type = identity->shift_amount == 0u
            ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL;
        identity->destination_access = CDISASM_OPERAND_ACCESS_WRITE;
        return 1;
    }
    if ((word & UINT32_C(0xbff8dc00)) == UINT32_C(0x0f008400)
        || (word & UINT32_C(0xbff8dc00)) == UINT32_C(0x2f008400)) {
        identity->form_id = (word & UINT32_C(0x20000000)) == 0u
            ? UINT16_C(6201) : UINT16_C(6209);
        identity->name_id = (word & UINT32_C(0x20000000)) == 0u
            ? CDISASM_ARM_NAME_MOVI : CDISASM_ARM_NAME_MVNI;
        identity->element_size = 2u;
        identity->scalar = 0u;
        identity->shift_amount = (cmode & 2u) != 0u ? 8u : 0u;
        identity->shift_type = identity->shift_amount == 0u
            ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL;
        identity->destination_access = CDISASM_OPERAND_ACCESS_WRITE;
        return 1;
    }
    if ((word & UINT32_C(0xbff8ec00)) == UINT32_C(0x0f00c400)
        || (word & UINT32_C(0xbff8ec00)) == UINT32_C(0x2f00c400)) {
        identity->form_id = (word & UINT32_C(0x20000000)) == 0u
            ? UINT16_C(6203) : UINT16_C(6211);
        identity->name_id = (word & UINT32_C(0x20000000)) == 0u
            ? CDISASM_ARM_NAME_MOVI : CDISASM_ARM_NAME_MVNI;
        identity->element_size = 4u;
        identity->scalar = 0u;
        identity->shift_type = CDISASM_ARM_SHIFT_MSL;
        identity->shift_amount = (cmode & 1u) != 0u ? 16u : 8u;
        identity->destination_access = CDISASM_OPERAND_ACCESS_WRITE;
        return 1;
    }
    if ((word & UINT32_C(0xbff8fc00)) == UINT32_C(0x0f00e400)) {
        identity->form_id = UINT16_C(6204);
        identity->name_id = CDISASM_ARM_NAME_MOVI;
        identity->element_size = 1u;
        identity->scalar = 0u;
        identity->shift_type = CDISASM_ARM_SHIFT_NONE;
        identity->shift_amount = 0u;
        identity->destination_access = CDISASM_OPERAND_ACCESS_WRITE;
        return 1;
    }
    if ((word & UINT32_C(0xbff8fc00)) == UINT32_C(0x0f00f400)
        || (word & UINT32_C(0xbff8fc00)) == UINT32_C(0x0f00fc00)
        || (word & UINT32_C(0xfff8fc00)) == UINT32_C(0x6f00f400)) {
        int half = (word & UINT32_C(0xbff8fc00))
            == UINT32_C(0x0f00fc00);
        int double_vector = (word & UINT32_C(0xfff8fc00))
            == UINT32_C(0x6f00f400);

        identity->form_id = half ? UINT16_C(6206)
            : double_vector ? UINT16_C(6214) : UINT16_C(6205);
        identity->name_id = CDISASM_ARM_NAME_FMOV;
        identity->element_size = half ? 2u : double_vector ? 8u : 4u;
        identity->scalar = 0u;
        identity->shift_type = CDISASM_ARM_SHIFT_NONE;
        identity->shift_amount = 0u;
        identity->destination_access = CDISASM_OPERAND_ACCESS_WRITE;
        return 1;
    }
    if ((word & UINT32_C(0xfff8fc00)) == UINT32_C(0x2f00e400)
        || (word & UINT32_C(0xfff8fc00)) == UINT32_C(0x6f00e400)) {
        identity->form_id = (word & UINT32_C(0x40000000)) == 0u
            ? UINT16_C(6212) : UINT16_C(6213);
        identity->name_id = CDISASM_ARM_NAME_MOVI;
        identity->element_size = 8u;
        identity->scalar = (word & UINT32_C(0x40000000)) == 0u;
        identity->shift_type = CDISASM_ARM_SHIFT_NONE;
        identity->shift_amount = 0u;
        identity->destination_access = CDISASM_OPERAND_ACCESS_WRITE;
        return 1;
    }
    return 0;
}

static int arm_is_advsimd_modified_immediate_form(
    cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(6199) || form_id == UINT16_C(6200)
        || form_id == UINT16_C(6201) || form_id == UINT16_C(6202)
        || form_id == UINT16_C(6203) || form_id == UINT16_C(6204)
        || form_id == UINT16_C(6205) || form_id == UINT16_C(6206)
        || form_id == UINT16_C(6207) || form_id == UINT16_C(6208)
        || form_id == UINT16_C(6209) || form_id == UINT16_C(6210)
        || form_id == UINT16_C(6211) || form_id == UINT16_C(6212)
        || form_id == UINT16_C(6213) || form_id == UINT16_C(6214);
}

static uint64_t arm_advsimd_modified_immediate_value(
    uint32_t word,
    const arm_advsimd_modified_immediate_identity *identity)
{
    unsigned encoded = (((word >> 16) & 7u) << 5)
        | ((word >> 5) & 31u);

    if (identity->name_id == CDISASM_ARM_NAME_FMOV)
        return arm_sve_vfp_expand_imm(encoded, identity->element_size);

    if (identity->element_size == 8u) {
        uint64_t value = UINT64_C(0);

        for (unsigned bit = 0u; bit < 8u; ++bit) {
            if ((encoded & (1u << bit)) != 0u) {
                value |= UINT64_C(0xff) << (8u * bit);
            }
        }
        return value;
    }
    if (identity->shift_type == CDISASM_ARM_SHIFT_MSL) {
        return ((uint64_t)encoded << identity->shift_amount)
            | ((UINT64_C(1) << identity->shift_amount) - UINT64_C(1));
    }
    return (uint64_t)encoded << identity->shift_amount;
}

static int arm_valid_advsimd_modified_immediate_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_advsimd_modified_immediate_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE, 0u, 0u,
        CDISASM_ARM_SHIFT_NONE, 0u, CDISASM_OPERAND_ACCESS_NONE
    };
    uint32_t word = instruction->raw_instruction;
    unsigned q = (word >> 30) & 1u;
    uint8_t total_size;
    cdisasm_arm_reg_id register_base;
    const cdisasm_arm_operand *immediate;
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_advsimd_modified_immediate_identity_for_word(word, &identity);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_is_advsimd_modified_immediate_form(instruction->form_id);
    int unique_name_is_family = instruction->name_id == CDISASM_ARM_NAME_MOVI
        || instruction->name_id == CDISASM_ARM_NAME_MVNI;

    /* Bind the exact MOVI/MVNI/ORR/BIC modified-immediate raw bits, form,
     * mnemonic, access, expanded semantic immediate, and encoded LSL/MSL
     * modifier.  ORR/BIC have unrelated same-name forms, so their name alone
     * intentionally does not claim this schema. */
    if (!raw_is_family && !form_is_family && !unique_name_is_family) {
        return 1;
    }
    if (!raw_is_family || !form_is_family
        || instruction->form_id != identity.form_id
        || instruction->name_id != identity.name_id) {
        return 0;
    }
    total_size = identity.scalar != 0u ? 8u : q != 0u ? 16u : 8u;
    register_base = identity.scalar != 0u
        ? CDISASM_ARM_REG_D0 : CDISASM_ARM_REG_V0;
    immediate = &instruction->operand[1];
    return instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
                | (identity.name_id == CDISASM_ARM_NAME_FMOV
                    ? CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT : 0u))
        && instruction->branch_target == 0u
        && instruction->operand_count == 2u
        && arm_exact_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                register_base + (word & 31u)),
            total_size, identity.element_size,
            identity.destination_access)
        && immediate->type == CDISASM_OPERAND_IMMEDIATE
        && immediate->imm
            == arm_advsimd_modified_immediate_value(word, &identity)
        && immediate->size == 1u
        && immediate->access == CDISASM_OPERAND_ACCESS_READ
        && immediate->reg == CDISASM_ARM_REG_NONE
        && immediate->base_reg == CDISASM_ARM_REG_NONE
        && immediate->index_reg == CDISASM_ARM_REG_NONE
        && immediate->register_list == 0u
        && immediate->address == 0u
        && immediate->flags == CDISASM_OPERAND_FLAG_NONE
        && immediate->shift_type == identity.shift_type
        && immediate->shift_amount == identity.shift_amount
        && immediate->extend_type == CDISASM_ARM_EXTEND_NONE
        && immediate->scale == 0u;
}

typedef struct arm_advsimd_absolute_difference_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
} arm_advsimd_absolute_difference_identity;

static int arm_advsimd_absolute_difference_identity_for_word(
    uint32_t word, arm_advsimd_absolute_difference_identity *identity)
{
    switch (word & UINT32_C(0xbf20fc00)) {
        case UINT32_C(0x0e207400):
            identity->form_id = UINT16_C(6128);
            identity->name_id = CDISASM_ARM_NAME_SABD;
            return 1;
        case UINT32_C(0x2e207400):
            identity->form_id = UINT16_C(6170);
            identity->name_id = CDISASM_ARM_NAME_UABD;
            return 1;
        default:
            return 0;
    }
}

static int arm_is_advsimd_absolute_difference_form(
    cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(6128) || form_id == UINT16_C(6170);
}

static int arm_is_advsimd_absolute_difference_name(
    cdisasm_arm_name_id name_id)
{
    return name_id == CDISASM_ARM_NAME_SABD
        || name_id == CDISASM_ARM_NAME_UABD;
}

static int arm_is_exact_sve_absolute_difference(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t operation = word & UINT32_C(0xff3fe000);
    cdisasm_arm_form_id expected_form;
    cdisasm_arm_name_id expected_name;
    uint8_t element_size = (uint8_t)(UINT8_C(1)
        << ((word >> 22) & 3u));
    unsigned zd = word & 31u;

    if (operation == UINT32_C(0x040c0000)) {
        expected_form = UINT16_C(2228);
        expected_name = CDISASM_ARM_NAME_SABD;
    } else if (operation == UINT32_C(0x040d0000)) {
        expected_form = UINT16_C(2231);
        expected_name = CDISASM_ARM_NAME_UABD;
    } else {
        return 0;
    }
    return instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->opcode_size == 4u
        && instruction->form_id == expected_form
        && instruction->name_id == expected_name
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        && instruction->branch_target == 0u
        && instruction->operand_count == 4u
        && arm_exact_scalable_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + zd), element_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_predicate_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_P0 + ((word >> 10) & 7u)), element_size,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_scalable_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + zd), element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_scalable_operand(
            &instruction->operand[3], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)), element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && cdisasm_arm_generated_form_matches(instruction);
}

static int arm_valid_advsimd_absolute_difference_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_advsimd_absolute_difference_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE
    };
    uint32_t word = instruction->raw_instruction;
    unsigned size_code = (word >> 22) & 3u;
    uint8_t element_size = (uint8_t)(UINT8_C(1) << size_code);
    uint8_t vector_size = (word & UINT32_C(0x40000000)) != 0u
        ? 16u : 8u;
    int raw_is_envelope = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_advsimd_absolute_difference_identity_for_word(
            word, &identity);
    int raw_is_family = raw_is_envelope && size_code <= 2u;
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_is_advsimd_absolute_difference_form(instruction->form_id);
    int name_is_family = arm_is_advsimd_absolute_difference_name(
        instruction->name_id);
    int raw_is_sve = instruction->isa_id == CDISASM_ARM_ISA_A64
        && ((word & UINT32_C(0xff3fe000)) == UINT32_C(0x040c0000)
            || (word & UINT32_C(0xff3fe000)) == UINT32_C(0x040d0000));
    int form_is_sve = instruction->form_id == UINT16_C(2228)
        || instruction->form_id == UINT16_C(2231);

    /* SABD/UABD are also names of predicated SVE forms.  Own those raw and
     * form claims independently and admit only their exact lowered schema;
     * all other same-name claims remain owned by the fixed-vector family. */
    if (raw_is_sve || form_is_sve) {
        return arm_is_exact_sve_absolute_difference(instruction);
    }
    if (!raw_is_envelope && !form_is_family && !name_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->branch_target == 0u
        && instruction->operand_count == 3u
        && arm_exact_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + (word & 31u)),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_vector_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 16) & 31u)),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_advsimd_absolute_difference_accumulate_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
} arm_advsimd_absolute_difference_accumulate_identity;

static int arm_advsimd_absolute_difference_accumulate_identity_for_word(
    uint32_t word,
    arm_advsimd_absolute_difference_accumulate_identity *identity)
{
    switch (word & UINT32_C(0xbf20fc00)) {
        case UINT32_C(0x0e207c00):
            identity->form_id = UINT16_C(6129);
            identity->name_id = CDISASM_ARM_NAME_SABA;
            return 1;
        case UINT32_C(0x2e207c00):
            identity->form_id = UINT16_C(6171);
            identity->name_id = CDISASM_ARM_NAME_UABA;
            return 1;
        default:
            return 0;
    }
}

static int arm_is_advsimd_absolute_difference_accumulate_form(
    cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(6129) || form_id == UINT16_C(6171);
}

static int arm_is_advsimd_absolute_difference_accumulate_name(
    cdisasm_arm_name_id name_id)
{
    return name_id == CDISASM_ARM_NAME_SABA
        || name_id == CDISASM_ARM_NAME_UABA;
}

static int arm_is_advsimd_absolute_difference_accumulate_sibling(
    const cdisasm_arm_instruction *instruction)
{
    int form_and_name_match =
        (instruction->form_id == UINT16_C(2848)
            && instruction->name_id == CDISASM_ARM_NAME_SABA)
        || (instruction->form_id == UINT16_C(2849)
            && instruction->name_id == CDISASM_ARM_NAME_UABA);

    return instruction->isa_id == CDISASM_ARM_ISA_A64
        && form_and_name_match
        && instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
                | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR)
        && cdisasm_arm_generated_form_matches(instruction);
}

static int arm_valid_advsimd_absolute_difference_accumulate_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_advsimd_absolute_difference_accumulate_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE
    };
    uint32_t word = instruction->raw_instruction;
    unsigned size_code = (word >> 22) & 3u;
    uint8_t element_size = (uint8_t)(UINT8_C(1) << size_code);
    uint8_t vector_size = (word & UINT32_C(0x40000000)) != 0u
        ? 16u : 8u;
    int raw_is_envelope = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_advsimd_absolute_difference_accumulate_identity_for_word(
            word, &identity);
    int raw_is_family = raw_is_envelope && size_code <= 2u;
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_is_advsimd_absolute_difference_accumulate_form(
            instruction->form_id);
    int name_is_family =
        arm_is_advsimd_absolute_difference_accumulate_name(
            instruction->name_id);
    int sibling = name_is_family && !form_is_family
        && arm_is_advsimd_absolute_difference_accumulate_sibling(
            instruction);
    int name_claims_fixed_family = name_is_family && !sibling;

    /* SABA/UABA also name generated SVE2/SME forms.  Admit those only
     * through their exact generated identities; all other same-name claims
     * remain owned by this fixed-vector schema and fail closed. */
    if (!raw_is_envelope && !form_is_family
        && !name_claims_fixed_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->branch_target == 0u
        && instruction->operand_count == 3u
        && arm_exact_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + (word & 31u)),
            vector_size, element_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_vector_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 16) & 31u)),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_advsimd_multiply_accumulate_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
} arm_advsimd_multiply_accumulate_identity;

static int arm_advsimd_multiply_accumulate_identity_for_word(
    uint32_t word, arm_advsimd_multiply_accumulate_identity *identity)
{
    switch (word & UINT32_C(0xbf20fc00)) {
        case UINT32_C(0x0e209400):
            identity->form_id = UINT16_C(6132);
            identity->name_id = CDISASM_ARM_NAME_MLA;
            return 1;
        case UINT32_C(0x2e209400):
            identity->form_id = UINT16_C(6174);
            identity->name_id = CDISASM_ARM_NAME_MLS;
            return 1;
        default:
            return 0;
    }
}

static int arm_is_advsimd_multiply_accumulate_form(
    cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(6132) || form_id == UINT16_C(6174);
}

static int arm_is_advsimd_multiply_accumulate_name(
    cdisasm_arm_name_id name_id)
{
    return name_id == CDISASM_ARM_NAME_MLA
        || name_id == CDISASM_ARM_NAME_MLS;
}

static int arm_is_advsimd_multiply_accumulate_sibling_form(
    cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(51) || form_id == UINT16_C(52)
        || form_id == UINT16_C(54)
        || form_id == UINT16_C(2175) || form_id == UINT16_C(2176)
        || form_id == UINT16_C(2177)
        || form_id == UINT16_C(2309) || form_id == UINT16_C(2310)
        || (form_id >= UINT16_C(2722) && form_id <= UINT16_C(2727))
        || form_id == UINT16_C(6268) || form_id == UINT16_C(6270);
}

static int arm_is_advsimd_multiply_accumulate_sibling_raw(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;

    if (instruction->isa_id == CDISASM_ARM_ISA_A32) {
        return (word & UINT32_C(0x0ff000f0)) == UINT32_C(0x00200090)
            || (word & UINT32_C(0x0ff000f0)) == UINT32_C(0x00300090)
            || (word & UINT32_C(0x0ff000f0)) == UINT32_C(0x00600090);
    }
    if (instruction->isa_id == CDISASM_ARM_ISA_T32
        && instruction->opcode_size == 4u) {
        word = (word << 16) | (word >> 16);
        return (word & UINT32_C(0xfff000f0)) == UINT32_C(0xfb000000)
            || (word & UINT32_C(0xfff000f0)) == UINT32_C(0xfb000010);
    }
    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return 0;
    }
    return (word & UINT32_C(0xff20e000)) == UINT32_C(0x04004000)
        || (word & UINT32_C(0xff20e000)) == UINT32_C(0x04006000)
        || (word & UINT32_C(0xffa0fc00)) == UINT32_C(0x44200800)
        || (word & UINT32_C(0xffe0fc00)) == UINT32_C(0x44a00800)
        || (word & UINT32_C(0xffe0fc00)) == UINT32_C(0x44e00800)
        || (word & UINT32_C(0xffa0fc00)) == UINT32_C(0x44200c00)
        || (word & UINT32_C(0xffe0fc00)) == UINT32_C(0x44a00c00)
        || (word & UINT32_C(0xffe0fc00)) == UINT32_C(0x44e00c00)
        || (word & UINT32_C(0xbf00f400)) == UINT32_C(0x2f000000)
        || (word & UINT32_C(0xbf00f400)) == UINT32_C(0x2f004000);
}

static int arm_advsimd_multiply_accumulate_element_identity_for_word(
    uint32_t word, arm_advsimd_multiply_accumulate_identity *identity)
{
    switch (word & UINT32_C(0xbf00f400)) {
        case UINT32_C(0x2f000000):
            identity->form_id = UINT16_C(6268);
            identity->name_id = CDISASM_ARM_NAME_MLA;
            return 1;
        case UINT32_C(0x2f004000):
            identity->form_id = UINT16_C(6270);
            identity->name_id = CDISASM_ARM_NAME_MLS;
            return 1;
        default:
            return 0;
    }
}

static int arm_valid_advsimd_multiply_accumulate_element_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_advsimd_multiply_accumulate_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE
    };
    uint32_t word = instruction->raw_instruction;
    unsigned size_code = (word >> 22) & 3u;
    unsigned indexed_register;
    uint64_t lane;
    uint8_t element_size;
    uint8_t vector_size;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || !arm_advsimd_multiply_accumulate_element_identity_for_word(
            word, &identity)
        || (size_code != 1u && size_code != 2u)) {
        return 0;
    }
    element_size = size_code == 1u ? 2u : 4u;
    vector_size = (word & UINT32_C(0x40000000)) != 0u ? 16u : 8u;
    if (size_code == 1u) {
        indexed_register = (word >> 16) & 15u;
        lane = (uint64_t)(((word >> 11) & 1u) << 2)
            | (uint64_t)(((word >> 21) & 1u) << 1)
            | (uint64_t)((word >> 20) & 1u);
    } else {
        indexed_register = (word >> 16) & 31u;
        lane = (uint64_t)(((word >> 11) & 1u) << 1)
            | (uint64_t)((word >> 21) & 1u);
    }

    return instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->branch_target == 0u
        && instruction->operand_count == 3u
        && cdisasm_arm_generated_form_matches(instruction)
        && arm_exact_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + (word & 31u)),
            vector_size, element_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_vector_lane_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + indexed_register),
            element_size, lane, CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_advsimd_multiply_element_schema(
    const cdisasm_arm_instruction *i)
{
    static const uint32_t ops[3] = { 0x0f008000, 0x0f00c000, 0x0f00d000 };
    static const uint16_t forms[3] = { 6247, 6250, 6251 };
    static const cdisasm_arm_name_id names[3] = { CDISASM_ARM_NAME_MUL,
        CDISASM_ARM_NAME_SQDMULH, CDISASM_ARM_NAME_SQRDMULH };
    uint32_t w=i->raw_instruction,op=w&UINT32_C(0xbf00f400);unsigned sc=(w>>22)&3u,index,rm,lane,rd=w&31u,rn=(w>>5)&31u;
    int form_claim=i->isa_id==CDISASM_ARM_ISA_A64&&(i->form_id==6247||i->form_id==6250||i->form_id==6251);
    uint8_t es=(uint8_t)(1u<<sc),vs=(w&UINT32_C(0x40000000))?16u:8u;
    for(index=0;index<3&&ops[index]!=op;++index){}
    if(index==3&&!form_claim)return 1;
    if(index==3||!form_claim||(sc!=1&&sc!=2))return 0;
    if(sc==1){rm=(w>>16)&15u;lane=((w>>11)&1u)*4u+((w>>21)&1u)*2u+((w>>20)&1u);}
    else{rm=(w>>16)&31u;lane=((w>>11)&1u)*2u+((w>>21)&1u);}
    return i->form_id==forms[index]&&i->name_id==names[index]
        &&i->opcode_size==4&&i->condition==CDISASM_ARM_CONDITION_AL
        &&i->opcode_groups==CDISASM_GROUP_NONE
        &&i->instruction_flags==CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        &&i->branch_target==0&&i->operand_count==3
        &&arm_exact_vector_operand(&i->operand[0],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rd),vs,es,CDISASM_OPERAND_ACCESS_WRITE)
        &&arm_exact_vector_operand(&i->operand[1],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rn),vs,es,CDISASM_OPERAND_ACCESS_READ)
        &&arm_exact_vector_lane_operand(&i->operand[2],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rm),es,lane,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_advsimd_dot_element_schema(const cdisasm_arm_instruction*i)
{
    static const uint32_t masks[4]={0xbf00f400,0xbf00f400,0xbfc0f400,0xbfc0f400};
    static const uint32_t vals[4]={0x0f00e000,0x2f00e000,0x0f00f000,0x0f80f000};
    static const uint16_t forms[4]={6252,6274,6257,6266};
    static const cdisasm_arm_name_id names[4]={CDISASM_ARM_NAME_SDOT,CDISASM_ARM_NAME_UDOT,CDISASM_ARM_NAME_SUDOT,CDISASM_ARM_NAME_USDOT};
    uint32_t w=i->raw_instruction;unsigned x,rd=w&31u,rn=(w>>5)&31u,rm=((w>>20)&1u)*16u+((w>>16)&15u),lane=((w>>11)&1u)*2u+((w>>21)&1u);uint8_t vs=(w&0x40000000)?16u:8u;int fc=i->form_id==6252||i->form_id==6274||i->form_id==6257||i->form_id==6266;
    for(x=0;x<4u&&((w&masks[x])!=vals[x]);++x){}
    if(x==4u&&!fc)return 1;if(x==4u||!fc)return 0;
    return i->form_id==forms[x]&&i->name_id==names[x]&&i->opcode_size==4
        &&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE
        &&i->instruction_flags==CDISASM_ARM_INSTRUCTION_FLAG_SIMD&&i->branch_target==0&&i->operand_count==3
        &&arm_exact_vector_operand(&i->operand[0],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rd),vs,4u,CDISASM_OPERAND_ACCESS_READ_WRITE)
        &&arm_exact_vector_operand(&i->operand[1],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rn),vs,1u,CDISASM_OPERAND_ACCESS_READ)
        &&arm_exact_vector_lane_operand(&i->operand[2],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rm),1u,lane,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_advsimd_fp_dot_element_schema(const cdisasm_arm_instruction*i)
{
    static const uint32_t vals[4]={0x0f000000,0x0f400000,0x0f409000,0x0f40f000};
    static const uint16_t forms[4]={6253,6258,6259,6260};
    static const cdisasm_arm_name_id names[4]={CDISASM_ARM_NAME_FDOT,CDISASM_ARM_NAME_FDOT,CDISASM_ARM_NAME_FDOT,CDISASM_ARM_NAME_BFDOT};
    uint32_t w=i->raw_instruction;unsigned x,rd=w&31u,rn=(w>>5)&31u,rm,lane;uint8_t de,se,vs=(w&UINT32_C(0x40000000))?16u:8u;int fc=i->form_id==6253||i->form_id==6258||i->form_id==6259||i->form_id==6260;
    for(x=0;x<4u&&((w&UINT32_C(0xbfc0f400))!=vals[x]);++x){}
    if(x==4u&&!fc)return 1;if(x==4u||!fc)return 0;
    de=x==1u?2u:4u;se=x<2u?1u:2u;
    if(x==1u){rm=(w>>16)&15u;lane=((w>>11)&1u)*4u+((w>>21)&1u)*2u+((w>>20)&1u);}
    else{rm=((w>>20)&1u)*16u+((w>>16)&15u);lane=((w>>11)&1u)*2u+((w>>21)&1u);}
    return i->form_id==forms[x]&&i->name_id==names[x]&&i->opcode_size==4
        &&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE
        &&i->instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SIMD|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)
        &&i->branch_target==0&&i->operand_count==3
        &&arm_exact_vector_operand(&i->operand[0],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rd),vs,de,CDISASM_OPERAND_ACCESS_READ_WRITE)
        &&arm_exact_vector_operand(&i->operand[1],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rn),vs,se,CDISASM_OPERAND_ACCESS_READ)
        &&arm_exact_vector_lane_operand(&i->operand[2],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rm),se,lane,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_advsimd_bfmlal_element_schema(const cdisasm_arm_instruction*i)
{
    uint32_t w=i->raw_instruction;
    int raw=(w&UINT32_C(0xbfc0f400))==UINT32_C(0x0fc0f000);
    int form_claim=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id==UINT16_C(6267);
    unsigned rd=w&31u,rn=(w>>5)&31u,rm=(w>>16)&15u;
    uint64_t lane=(uint64_t)(((w>>11)&1u)<<2)
        |(uint64_t)(((w>>21)&1u)<<1)|(uint64_t)((w>>20)&1u);
    if(!raw&&!form_claim)return 1;if(!raw||!form_claim)return 0;
    return i->name_id==CDISASM_ARM_NAME_BFMLAL&&i->opcode_size==4
        &&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE
        &&i->instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SIMD|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)
        &&i->branch_target==0&&i->operand_count==3
        &&arm_exact_vector_operand(&i->operand[0],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rd),16u,4u,CDISASM_OPERAND_ACCESS_READ_WRITE)
        &&arm_exact_vector_operand(&i->operand[1],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rn),16u,2u,CDISASM_OPERAND_ACCESS_READ)
        &&arm_exact_vector_lane_operand(&i->operand[2],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rm),2u,lane,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_advsimd_fp8_widening_element_schema(const cdisasm_arm_instruction*i)
{
    static const uint32_t vals[6]={0x0fc00000,0x2f008000,0x2f408000,0x4fc00000,0x6f008000,0x6f408000};
    static const uint16_t forms[6]={6281,6282,6283,6284,6285,6286};
    static const cdisasm_arm_name_id names[6]={CDISASM_ARM_NAME_FMLALB,CDISASM_ARM_NAME_FMLALLBB,CDISASM_ARM_NAME_FMLALLBT,CDISASM_ARM_NAME_FMLALT,CDISASM_ARM_NAME_FMLALLTB,CDISASM_ARM_NAME_FMLALLTT};
    uint32_t w=i->raw_instruction;unsigned x,rd=w&31u,rn=(w>>5)&31u,rm=(w>>16)&7u;uint8_t de;uint64_t lane=(uint64_t)(((w>>11)&1u)<<3)|(uint64_t)(((w>>21)&1u)<<2)|(uint64_t)(((w>>20)&1u)<<1)|(uint64_t)((w>>19)&1u);int fc=i->form_id>=6281&&i->form_id<=6286;
    for(x=0;x<6u&&((w&UINT32_C(0xffc0f400))!=vals[x]);++x){}
    if(x==6u&&!fc)return 1;if(x==6u||!fc)return 0;de=(x==0u||x==3u)?2u:4u;
    return i->form_id==forms[x]&&i->name_id==names[x]&&i->opcode_size==4
        &&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE
        &&i->instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SIMD|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)
        &&i->branch_target==0&&i->operand_count==3
        &&arm_exact_vector_operand(&i->operand[0],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rd),16u,de,CDISASM_OPERAND_ACCESS_READ_WRITE)
        &&arm_exact_vector_operand(&i->operand[1],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rn),16u,1u,CDISASM_OPERAND_ACCESS_READ)
        &&arm_exact_vector_lane_operand(&i->operand[2],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rm),1u,lane,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_advsimd_fp_multiply_element_schema(const cdisasm_arm_instruction*i)
{
    static const uint32_t masks[8]={0xbfc0f400,0xbfc0f400,0xbfc0f400,0xbf80f400,0xbf80f400,0xbf80f400,0xbfc0f400,0xbf80f400};static const uint32_t vals[8]={0x0f001000,0x0f005000,0x0f009000,0x0f801000,0x0f805000,0x0f809000,0x2f009000,0x2f809000};static const uint16_t forms[8]={6254,6255,6256,6261,6262,6263,6276,6278};static const cdisasm_arm_name_id names[8]={CDISASM_ARM_NAME_FMLA,CDISASM_ARM_NAME_FMLS,CDISASM_ARM_NAME_FMUL,CDISASM_ARM_NAME_FMLA,CDISASM_ARM_NAME_FMLS,CDISASM_ARM_NAME_FMUL,CDISASM_ARM_NAME_FMULX,CDISASM_ARM_NAME_FMULX};
    uint32_t w=i->raw_instruction;unsigned x,rd=w&31u,rn=(w>>5)&31u,rm,lane;uint8_t es,vs=(w&0x40000000)?16u:8u;int fc=(i->form_id>=6254&&i->form_id<=6256)||(i->form_id>=6261&&i->form_id<=6263)||i->form_id==6276||i->form_id==6278,half;
    for(x=0;x<8u&&((w&masks[x])!=vals[x]);++x){}if(x==8u&&!fc)return 1;if(x==8u||!fc)return 0;half=x<3u||x==6u;es=half?2u:((w&0x00400000)?8u:4u);if(!half&&es==8u&&((w&0x40000000)==0||(w&0x00200000)!=0))return 0;
    if(half){rm=(w>>16)&15u;lane=((w>>11)&1u)*4u+((w>>21)&1u)*2u+((w>>20)&1u);}else{rm=(w>>16)&31u;lane=es==4u?((w>>11)&1u)*2u+((w>>21)&1u):((w>>11)&1u);}
    return i->form_id==forms[x]&&i->name_id==names[x]&&i->opcode_size==4&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SIMD|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)&&i->branch_target==0&&i->operand_count==3
        &&arm_exact_vector_operand(&i->operand[0],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rd),vs,es,(x%3u==2u||x>=6u)?CDISASM_OPERAND_ACCESS_WRITE:CDISASM_OPERAND_ACCESS_READ_WRITE)
        &&arm_exact_vector_operand(&i->operand[1],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rn),vs,es,CDISASM_OPERAND_ACCESS_READ)
        &&arm_exact_vector_lane_operand(&i->operand[2],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rm),es,lane,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_advsimd_rdm_element_schema(const cdisasm_arm_instruction*i)
{
    uint32_t w=i->raw_instruction,op=w&UINT32_C(0xbf00f400);unsigned sc=(w>>22)&3u,rd=w&31u,rn=(w>>5)&31u,rm,lane;uint8_t es=(uint8_t)(1u<<sc),vs=(w&0x40000000)?16u:8u;int raw=op==UINT32_C(0x2f00d000)||op==UINT32_C(0x2f00f000),fc=i->form_id==6273||i->form_id==6275;
    if(!raw&&!fc)return 1;if(!raw||!fc||(sc!=1u&&sc!=2u))return 0;
    if(sc==1u){rm=(w>>16)&15u;lane=((w>>11)&1u)*4u+((w>>21)&1u)*2u+((w>>20)&1u);}else{rm=(w>>16)&31u;lane=((w>>11)&1u)*2u+((w>>21)&1u);}
    return i->form_id==(op==UINT32_C(0x2f00d000)?6273:6275)&&i->name_id==(op==UINT32_C(0x2f00d000)?CDISASM_ARM_NAME_SQRDMLAH:CDISASM_ARM_NAME_SQRDMLSH)&&i->opcode_size==4&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==CDISASM_ARM_INSTRUCTION_FLAG_SIMD&&i->branch_target==0&&i->operand_count==3
        &&arm_exact_vector_operand(&i->operand[0],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rd),vs,es,CDISASM_OPERAND_ACCESS_READ_WRITE)&&arm_exact_vector_operand(&i->operand[1],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rn),vs,es,CDISASM_OPERAND_ACCESS_READ)&&arm_exact_vector_lane_operand(&i->operand[2],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rm),es,lane,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_is_exact_advsimd_multiply_accumulate_sibling(
    const cdisasm_arm_instruction *instruction)
{
    cdisasm_arm_name_id expected_name;
    uint32_t expected_flags;

    switch (instruction->form_id) {
        case UINT16_C(51):
            expected_name = CDISASM_ARM_NAME_MLAS;
            expected_flags = CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
            break;
        case UINT16_C(52):
            expected_name = CDISASM_ARM_NAME_MLA;
            expected_flags = 0u;
            break;
        case UINT16_C(54):
        case UINT16_C(2176):
            expected_name = CDISASM_ARM_NAME_MLS;
            expected_flags =
                CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK;
            break;
        case UINT16_C(2175):
            expected_name = CDISASM_ARM_NAME_MLA;
            expected_flags =
                CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK;
            break;
        case UINT16_C(2177):
            expected_name = CDISASM_ARM_NAME_MUL;
            expected_flags = 0u;
            break;
        case UINT16_C(2309):
            expected_name = CDISASM_ARM_NAME_MLA;
            expected_flags =
                CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
                | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED;
            break;
        case UINT16_C(2310):
            expected_name = CDISASM_ARM_NAME_MLS;
            expected_flags =
                CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
                | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED;
            break;
        case UINT16_C(2722):
        case UINT16_C(2723):
        case UINT16_C(2724):
        case UINT16_C(2725):
        case UINT16_C(2726):
        case UINT16_C(2727):
            return arm_valid_sve_mla_indexed_schema(instruction);
        case UINT16_C(6268):
        case UINT16_C(6270):
            return arm_valid_advsimd_multiply_accumulate_element_schema(
                instruction);
        default:
            return 0;
    }
    return instruction->name_id == expected_name
        && instruction->instruction_flags == expected_flags
        && cdisasm_arm_generated_form_matches(instruction);
}

static int arm_valid_advsimd_multiply_accumulate_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_advsimd_multiply_accumulate_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE
    };
    uint32_t word = instruction->raw_instruction;
    unsigned size_code = (word >> 22) & 3u;
    uint8_t element_size = (uint8_t)(UINT8_C(1) << size_code);
    uint8_t vector_size = (word & UINT32_C(0x40000000)) != 0u
        ? 16u : 8u;
    int raw_is_envelope = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_advsimd_multiply_accumulate_identity_for_word(
            word, &identity);
    int raw_is_family = raw_is_envelope && size_code <= 2u;
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_is_advsimd_multiply_accumulate_form(instruction->form_id);
    int name_is_family = arm_is_advsimd_multiply_accumulate_name(
        instruction->name_id);
    int sibling_claim =
        arm_is_advsimd_multiply_accumulate_sibling_form(
            instruction->form_id)
        || arm_is_advsimd_multiply_accumulate_sibling_raw(instruction);

    /* MLA/MLS also name scalar A32/T32 (including the legacy MLA+S flag
     * representation), predicated and indexed SVE, and Advanced SIMD
     * by-element forms.  Own their raw and form claims, but admit them only
     * through the pinned generated identity and flag shape. */
    if (sibling_claim) {
        return arm_is_exact_advsimd_multiply_accumulate_sibling(
            instruction);
    }
    if (!raw_is_envelope && !form_is_family && !name_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->branch_target == 0u
        && instruction->operand_count == 3u
        && arm_exact_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + (word & 31u)),
            vector_size, element_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_vector_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 16) & 31u)),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_advsimd_minmax_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
} arm_advsimd_minmax_identity;

static int arm_advsimd_minmax_identity_for_word(
    uint32_t word, arm_advsimd_minmax_identity *identity)
{
    switch (word & UINT32_C(0xbf20fc00)) {
        case UINT32_C(0x0e206400):
            identity->form_id = UINT16_C(6126);
            identity->name_id = CDISASM_ARM_NAME_SMAX;
            return 1;
        case UINT32_C(0x0e206c00):
            identity->form_id = UINT16_C(6127);
            identity->name_id = CDISASM_ARM_NAME_SMIN;
            return 1;
        case UINT32_C(0x2e206400):
            identity->form_id = UINT16_C(6168);
            identity->name_id = CDISASM_ARM_NAME_UMAX;
            return 1;
        case UINT32_C(0x2e206c00):
            identity->form_id = UINT16_C(6169);
            identity->name_id = CDISASM_ARM_NAME_UMIN;
            return 1;
        default:
            return 0;
    }
}

static int arm_is_advsimd_minmax_form(cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(6126) || form_id == UINT16_C(6127)
        || form_id == UINT16_C(6168) || form_id == UINT16_C(6169);
}

static int arm_is_advsimd_minmax_name(cdisasm_arm_name_id name_id)
{
    return name_id == CDISASM_ARM_NAME_SMAX
        || name_id == CDISASM_ARM_NAME_SMIN
        || name_id == CDISASM_ARM_NAME_UMAX
        || name_id == CDISASM_ARM_NAME_UMIN;
}

static int arm_is_advsimd_minmax_sibling(
    const cdisasm_arm_instruction *instruction)
{
    static const struct arm_advsimd_minmax_sibling {
        cdisasm_arm_form_id form_id;
        cdisasm_arm_name_id name_id;
    } siblings[] = {
        /* Predicated SVE and SVE immediate forms. */
        { UINT16_C(2226), CDISASM_ARM_NAME_SMAX },
        { UINT16_C(2227), CDISASM_ARM_NAME_SMIN },
        { UINT16_C(2229), CDISASM_ARM_NAME_UMAX },
        { UINT16_C(2230), CDISASM_ARM_NAME_UMIN },
        { UINT16_C(2626), CDISASM_ARM_NAME_SMAX },
        { UINT16_C(2627), CDISASM_ARM_NAME_SMIN },
        { UINT16_C(2628), CDISASM_ARM_NAME_UMAX },
        { UINT16_C(2629), CDISASM_ARM_NAME_UMIN },
        /* SME2 2x1, 4x1, 2x2, and 4x4 multi-vector forms. */
        { UINT16_C(4217), CDISASM_ARM_NAME_SMAX },
        { UINT16_C(4218), CDISASM_ARM_NAME_SMIN },
        { UINT16_C(4219), CDISASM_ARM_NAME_UMAX },
        { UINT16_C(4220), CDISASM_ARM_NAME_UMIN },
        { UINT16_C(4235), CDISASM_ARM_NAME_SMAX },
        { UINT16_C(4236), CDISASM_ARM_NAME_SMIN },
        { UINT16_C(4237), CDISASM_ARM_NAME_UMAX },
        { UINT16_C(4238), CDISASM_ARM_NAME_UMIN },
        { UINT16_C(4253), CDISASM_ARM_NAME_SMAX },
        { UINT16_C(4254), CDISASM_ARM_NAME_SMIN },
        { UINT16_C(4255), CDISASM_ARM_NAME_UMAX },
        { UINT16_C(4256), CDISASM_ARM_NAME_UMIN },
        { UINT16_C(4272), CDISASM_ARM_NAME_SMAX },
        { UINT16_C(4273), CDISASM_ARM_NAME_SMIN },
        { UINT16_C(4274), CDISASM_ARM_NAME_UMAX },
        { UINT16_C(4275), CDISASM_ARM_NAME_UMIN },
        /* CSSC immediate and two-register scalar forms. */
        { UINT16_C(4404), CDISASM_ARM_NAME_SMAX },
        { UINT16_C(4405), CDISASM_ARM_NAME_UMAX },
        { UINT16_C(4406), CDISASM_ARM_NAME_SMIN },
        { UINT16_C(4407), CDISASM_ARM_NAME_UMIN },
        { UINT16_C(4408), CDISASM_ARM_NAME_SMAX },
        { UINT16_C(4409), CDISASM_ARM_NAME_UMAX },
        { UINT16_C(4410), CDISASM_ARM_NAME_SMIN },
        { UINT16_C(4411), CDISASM_ARM_NAME_UMIN },
        { UINT16_C(5588), CDISASM_ARM_NAME_SMAX },
        { UINT16_C(5589), CDISASM_ARM_NAME_UMAX },
        { UINT16_C(5590), CDISASM_ARM_NAME_SMIN },
        { UINT16_C(5591), CDISASM_ARM_NAME_UMIN },
        { UINT16_C(5604), CDISASM_ARM_NAME_SMAX },
        { UINT16_C(5605), CDISASM_ARM_NAME_UMAX },
        { UINT16_C(5606), CDISASM_ARM_NAME_SMIN },
        { UINT16_C(5607), CDISASM_ARM_NAME_UMIN }
    };
    size_t index;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return 0;
    }
    for (index = 0u; index < sizeof(siblings) / sizeof(siblings[0]);
         ++index) {
        if (instruction->form_id == siblings[index].form_id
            && instruction->name_id == siblings[index].name_id) {
            uint32_t required_flags =
                CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK;

            if (instruction->form_id == UINT16_C(2226)
                || instruction->form_id == UINT16_C(2227)
                || instruction->form_id == UINT16_C(2229)
                || instruction->form_id == UINT16_C(2230)) {
                required_flags =
                    CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                    | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED;
            } else if (instruction->form_id >= UINT16_C(2626)
                && instruction->form_id <= UINT16_C(2629)) {
                required_flags =
                    CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR;
            } else if (instruction->form_id >= UINT16_C(4217)
                && instruction->form_id <= UINT16_C(4275)) {
                if (instruction->form_id <= UINT16_C(4220)
                    || (instruction->form_id >= UINT16_C(4235)
                        && instruction->form_id <= UINT16_C(4238))
                    || (instruction->form_id >= UINT16_C(4253)
                        && instruction->form_id <= UINT16_C(4256))
                    || (instruction->form_id >= UINT16_C(4272)
                        && instruction->form_id <= UINT16_C(4275))) {
                    return instruction->instruction_flags
                        == UINT32_C(0x05400000);
                }
                required_flags =
                    CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
            }
            return instruction->instruction_flags == required_flags
                && cdisasm_arm_generated_form_matches(instruction);
        }
    }
    return 0;
}

static int arm_valid_advsimd_minmax_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_advsimd_minmax_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE
    };
    uint32_t word = instruction->raw_instruction;
    unsigned size_code = (word >> 22) & 3u;
    uint8_t element_size = (uint8_t)(UINT8_C(1) << size_code);
    uint8_t vector_size = (word & UINT32_C(0x40000000)) != 0u
        ? 16u : 8u;
    int raw_is_envelope = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_advsimd_minmax_identity_for_word(word, &identity);
    int raw_is_family = raw_is_envelope && size_code <= 2u;
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_is_advsimd_minmax_form(instruction->form_id);
    int name_is_family = arm_is_advsimd_minmax_name(instruction->name_id);
    int sibling = name_is_family && !form_is_family
        && arm_is_advsimd_minmax_sibling(instruction);
    int name_claims_fixed_family = name_is_family && !sibling;

    /* These names also belong to exact SVE, SME2, and scalar CSSC forms.
     * Admit only their pinned form/raw/name identities; every other same-name
     * claim remains owned by this fixed-vector schema and fails closed. */
    if (!raw_is_envelope && !form_is_family
        && !name_claims_fixed_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->branch_target == 0u
        && instruction->operand_count == 3u
        && arm_exact_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + (word & 31u)),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_vector_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 16) & 31u)),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_advsimd_pairwise_minmax_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
} arm_advsimd_pairwise_minmax_identity;

static int arm_advsimd_pairwise_minmax_identity_for_word(
    uint32_t word, arm_advsimd_pairwise_minmax_identity *identity)
{
    switch (word & UINT32_C(0xbf20fc00)) {
        case UINT32_C(0x0e20a400):
            identity->form_id = UINT16_C(6134);
            identity->name_id = CDISASM_ARM_NAME_SMAXP;
            return 1;
        case UINT32_C(0x0e20ac00):
            identity->form_id = UINT16_C(6135);
            identity->name_id = CDISASM_ARM_NAME_SMINP;
            return 1;
        case UINT32_C(0x2e20a400):
            identity->form_id = UINT16_C(6176);
            identity->name_id = CDISASM_ARM_NAME_UMAXP;
            return 1;
        case UINT32_C(0x2e20ac00):
            identity->form_id = UINT16_C(6177);
            identity->name_id = CDISASM_ARM_NAME_UMINP;
            return 1;
        default:
            return 0;
    }
}

static int arm_is_advsimd_pairwise_minmax_form(
    cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(6134) || form_id == UINT16_C(6135)
        || form_id == UINT16_C(6176) || form_id == UINT16_C(6177);
}

static int arm_is_advsimd_pairwise_minmax_name(
    cdisasm_arm_name_id name_id)
{
    return name_id == CDISASM_ARM_NAME_SMAXP
        || name_id == CDISASM_ARM_NAME_SMINP
        || name_id == CDISASM_ARM_NAME_UMAXP
        || name_id == CDISASM_ARM_NAME_UMINP;
}

static int arm_is_sve_pairwise_minmax_sibling(
    const cdisasm_arm_instruction *instruction)
{
    arm_sve_predicated_pairwise_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE
    };

    return arm_is_advsimd_pairwise_minmax_name(instruction->name_id)
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_predicated_pairwise_identity_for_word(
            instruction->raw_instruction, &identity)
        && instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id;
}

static int arm_valid_advsimd_pairwise_minmax_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_advsimd_pairwise_minmax_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE
    };
    uint32_t word = instruction->raw_instruction;
    unsigned size_code = (word >> 22) & 3u;
    uint8_t element_size = (uint8_t)(UINT8_C(1) << size_code);
    uint8_t vector_size = (word & UINT32_C(0x40000000)) != 0u
        ? 16u : 8u;
    int raw_is_envelope = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_advsimd_pairwise_minmax_identity_for_word(word, &identity);
    int raw_is_family = raw_is_envelope && size_code <= 2u;
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_is_advsimd_pairwise_minmax_form(instruction->form_id);
    int name_is_family =
        arm_is_advsimd_pairwise_minmax_name(instruction->name_id);
    int sve_sibling = name_is_family && !form_is_family
        && arm_is_sve_pairwise_minmax_sibling(instruction);
    int name_claims_fixed_family = name_is_family && !sve_sibling;

    if (!raw_is_envelope && !form_is_family
        && !name_claims_fixed_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->branch_target == 0u
        && instruction->operand_count == 3u
        && arm_exact_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + (word & 31u)),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_vector_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 16) & 31u)),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_advsimd_addp_identity {
    cdisasm_arm_form_id form_id;
    uint8_t scalar;
} arm_advsimd_addp_identity;

static int arm_advsimd_addp_identity_for_word(
    uint32_t word, arm_advsimd_addp_identity *identity)
{
    if ((word & UINT32_C(0xfffffc00)) == UINT32_C(0x5ef1b800)) {
        identity->form_id = UINT16_C(5808);
        identity->scalar = 1u;
        return 1;
    }
    if ((word & UINT32_C(0xbf20fc00)) == UINT32_C(0x0e20bc00)) {
        identity->form_id = UINT16_C(6137);
        identity->scalar = 0u;
        return 1;
    }
    return 0;
}

static int arm_is_advsimd_addp_form(cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(5808) || form_id == UINT16_C(6137);
}

static int arm_is_sve_addp_sibling(
    const cdisasm_arm_instruction *instruction)
{
    arm_sve_predicated_pairwise_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE
    };

    return instruction->name_id == CDISASM_ARM_NAME_ADDP
        && instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_predicated_pairwise_identity_for_word(
            instruction->raw_instruction, &identity)
        && identity.form_id == UINT16_C(2688)
        && instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id;
}

static int arm_valid_advsimd_addp_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_advsimd_addp_identity identity = {
        CDISASM_ARM_FORM_NONE, 0u
    };
    uint32_t word = instruction->raw_instruction;
    unsigned q = (word >> 30) & 1u;
    unsigned size_code = (word >> 22) & 3u;
    uint8_t element_size;
    uint8_t vector_size;
    int raw_is_envelope = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_advsimd_addp_identity_for_word(word, &identity);
    int raw_is_family = raw_is_envelope
        && (identity.scalar != 0u || size_code <= 2u || q != 0u);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_is_advsimd_addp_form(instruction->form_id);
    int name_is_family = instruction->name_id == CDISASM_ARM_NAME_ADDP;
    int sve_sibling = name_is_family && !form_is_family
        && arm_is_sve_addp_sibling(instruction);
    int name_claims_fixed_family = name_is_family && !sve_sibling;

    /* ADDP also has one exact destructive SVE sibling.  Admit that sibling
     * to its own schema, but fail closed for every unmatched scalar/vector
     * ADDP raw, form, or mnemonic claim. */
    if (!raw_is_envelope && !form_is_family
        && !name_claims_fixed_family) {
        return 1;
    }
    if (!raw_is_family || !form_is_family || !name_is_family
        || instruction->form_id != identity.form_id) {
        return 0;
    }
    if (instruction->opcode_size != 4u
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->instruction_flags
            != CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        || instruction->branch_target != 0u) {
        return 0;
    }
    if (identity.scalar != 0u) {
        return instruction->operand_count == 2u
            && arm_exact_vector_operand(
                &instruction->operand[0], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_D0 + (word & 31u)),
                8u, 8u, CDISASM_OPERAND_ACCESS_WRITE)
            && arm_exact_vector_operand(
                &instruction->operand[1], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)),
                16u, 8u, CDISASM_OPERAND_ACCESS_READ);
    }
    element_size = (uint8_t)(UINT8_C(1) << size_code);
    vector_size = q != 0u ? 16u : 8u;
    return instruction->operand_count == 3u
        && arm_exact_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + (word & 31u)),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_vector_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 16) & 31u)),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_advsimd_addv_schema(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned q = (word >> 30) & 1u;
    unsigned size_code = (word >> 22) & 3u;
    uint8_t element_size = (uint8_t)(UINT8_C(1) << size_code);
    uint8_t vector_size = q != 0u ? 16u : 8u;
    cdisasm_arm_reg_id scalar_base = size_code == 0u
        ? CDISASM_ARM_REG_B0 : size_code == 1u
            ? CDISASM_ARM_REG_H0 : CDISASM_ARM_REG_S0;
    int raw_is_envelope = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (word & UINT32_C(0xbf3ffc00)) == UINT32_C(0x0e31b800);
    int raw_is_family = raw_is_envelope
        && (size_code <= 1u || (q != 0u && size_code == 2u));
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id == UINT16_C(6077);
    int name_is_family = instruction->name_id == CDISASM_ARM_NAME_ADDV;

    if (!raw_is_envelope && !form_is_family && !name_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->branch_target == 0u
        && instruction->operand_count == 2u
        && arm_exact_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                scalar_base + (word & 31u)),
            element_size, element_size, CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_advsimd_addlv_schema(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t operation = word & UINT32_C(0xbf3ffc00);
    unsigned q = (word >> 30) & 1u;
    unsigned size_code = (word >> 22) & 3u;
    uint8_t source_element_size = (uint8_t)(UINT8_C(1) << size_code);
    uint8_t result_element_size =
        (uint8_t)(source_element_size * 2u);
    uint8_t vector_size = q != 0u ? 16u : 8u;
    cdisasm_arm_reg_id result_base = result_element_size == 2u
        ? CDISASM_ARM_REG_H0 : result_element_size == 4u
            ? CDISASM_ARM_REG_S0 : CDISASM_ARM_REG_D0;
    int unsigned_operation = operation == UINT32_C(0x2e303800);
    int raw_is_envelope = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (operation == UINT32_C(0x0e303800) || unsigned_operation);
    int raw_is_family = raw_is_envelope
        && (size_code <= 1u || (q != 0u && size_code == 2u));
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->form_id == UINT16_C(6074)
            || instruction->form_id == UINT16_C(6082));
    int name_is_family = instruction->name_id == CDISASM_ARM_NAME_SADDLV
        || instruction->name_id == CDISASM_ARM_NAME_UADDLV;
    cdisasm_arm_form_id expected_form = unsigned_operation
        ? UINT16_C(6082) : UINT16_C(6074);
    cdisasm_arm_name_id expected_name = unsigned_operation
        ? CDISASM_ARM_NAME_UADDLV : CDISASM_ARM_NAME_SADDLV;

    if (!raw_is_envelope && !form_is_family && !name_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->form_id == expected_form
        && instruction->name_id == expected_name
        && instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->branch_target == 0u
        && instruction->operand_count == 2u
        && arm_exact_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                result_base + (word & 31u)),
            result_element_size, result_element_size,
            CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)),
            vector_size, source_element_size,
            CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_advsimd_minmaxv_schema(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id names[2][2] = {
        { CDISASM_ARM_NAME_SMAXV, CDISASM_ARM_NAME_SMINV },
        { CDISASM_ARM_NAME_UMAXV, CDISASM_ARM_NAME_UMINV }
    };
    static const cdisasm_arm_form_id forms[2][2] = {
        { UINT16_C(6075), UINT16_C(6076) },
        { UINT16_C(6083), UINT16_C(6084) }
    };
    uint32_t word = instruction->raw_instruction;
    unsigned is_unsigned = (word >> 29) & 1u;
    unsigned is_minimum = (word >> 16) & 1u;
    unsigned q = (word >> 30) & 1u;
    unsigned size_code = (word >> 22) & 3u;
    uint8_t element_size = (uint8_t)(UINT8_C(1) << size_code);
    uint8_t vector_size = q != 0u ? 16u : 8u;
    cdisasm_arm_reg_id scalar_base = size_code == 0u
        ? CDISASM_ARM_REG_B0 : size_code == 1u
            ? CDISASM_ARM_REG_H0 : CDISASM_ARM_REG_S0;
    uint32_t operation = word & UINT32_C(0xbf3ffc00);
    int raw_is_envelope = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (operation == UINT32_C(0x0e30a800)
            || operation == UINT32_C(0x0e31a800)
            || operation == UINT32_C(0x2e30a800)
            || operation == UINT32_C(0x2e31a800));
    int raw_is_family = raw_is_envelope
        && (size_code <= 1u || (q != 0u && size_code == 2u));
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->form_id == UINT16_C(6075)
            || instruction->form_id == UINT16_C(6076)
            || instruction->form_id == UINT16_C(6083)
            || instruction->form_id == UINT16_C(6084));
    int name_is_family = instruction->name_id == names[is_unsigned][is_minimum];

    /* These mnemonics also have SVE reduction forms.  Raw allocation and
     * native fixed-width form identity own this schema; mnemonic identity
     * alone must not reject the independently validated scalable sibling. */
    if (!raw_is_envelope && !form_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->form_id == forms[is_unsigned][is_minimum]
        && instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->branch_target == 0u
        && instruction->operand_count == 2u
        && arm_exact_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                scalar_base + (word & 31u)), element_size, element_size,
            CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_advsimd_integer_unary_scalar_schema(
    const cdisasm_arm_instruction *instruction)
{
    static const struct identity {
        uint32_t mask, value;
        cdisasm_arm_form_id form_id;
        cdisasm_arm_name_id name_id;
        uint8_t compare_zero, destructive;
    } identities[] = {
        { UINT32_C(0xff3ffc00), UINT32_C(0x5e203800), 5773, CDISASM_ARM_NAME_SUQADD, 0, 1 },
        { UINT32_C(0xff3ffc00), UINT32_C(0x5e207800), 5774, CDISASM_ARM_NAME_SQABS, 0, 0 },
        { UINT32_C(0xfffffc00), UINT32_C(0x5ee08800), 5775, CDISASM_ARM_NAME_CMGT, 1, 0 },
        { UINT32_C(0xfffffc00), UINT32_C(0x5ee09800), 5776, CDISASM_ARM_NAME_CMEQ, 1, 0 },
        { UINT32_C(0xfffffc00), UINT32_C(0x5ee0b800), 5778, CDISASM_ARM_NAME_ABS, 0, 0 },
        { UINT32_C(0xff3ffc00), UINT32_C(0x7e203800), 5791, CDISASM_ARM_NAME_USQADD, 0, 1 },
        { UINT32_C(0xff3ffc00), UINT32_C(0x7e207800), 5792, CDISASM_ARM_NAME_SQNEG, 0, 0 },
        { UINT32_C(0xfffffc00), UINT32_C(0x7ee08800), 5793, CDISASM_ARM_NAME_CMGE, 1, 0 },
        { UINT32_C(0xfffffc00), UINT32_C(0x7ee0b800), 5795, CDISASM_ARM_NAME_NEG, 0, 0 }
    };
    uint32_t word = instruction->raw_instruction;
    unsigned index;
    unsigned size_code = (word >> 22) & 3u;
    uint8_t element_size = (uint8_t)(UINT8_C(1) << size_code);
    cdisasm_arm_reg_id scalar_base = size_code == 0u
        ? CDISASM_ARM_REG_B0 : size_code == 1u
            ? CDISASM_ARM_REG_H0 : size_code == 2u
                ? CDISASM_ARM_REG_S0 : CDISASM_ARM_REG_D0;
    int form_is_family = 0;

    for (index = 0u; index < sizeof(identities) / sizeof(identities[0]); ++index) {
        if (instruction->form_id == identities[index].form_id) {
            form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64;
            break;
        }
    }
    if (index == sizeof(identities) / sizeof(identities[0])) {
        for (index = 0u; index < sizeof(identities) / sizeof(identities[0]); ++index) {
            if ((word & identities[index].mask) == identities[index].value
                && instruction->isa_id == CDISASM_ARM_ISA_A64) break;
        }
    }
    if (index == sizeof(identities) / sizeof(identities[0])) return 1;
    return form_is_family
        && (word & identities[index].mask) == identities[index].value
        && instruction->name_id == identities[index].name_id
        && instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->branch_target == 0u
        && instruction->operand_count == (identities[index].compare_zero ? 3u : 2u)
        && arm_exact_vector_operand(&instruction->operand[0],
            (cdisasm_arm_reg_id)(scalar_base + (word & 31u)),
            element_size, element_size,
            identities[index].destructive ? CDISASM_OPERAND_ACCESS_READ_WRITE
                                           : CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_vector_operand(&instruction->operand[1],
            (cdisasm_arm_reg_id)(scalar_base + ((word >> 5) & 31u)),
            element_size, element_size, CDISASM_OPERAND_ACCESS_READ)
        && (!identities[index].compare_zero
            || arm_exact_u8_immediate_operand(&instruction->operand[2], 0u));
}

typedef struct arm_advsimd_pairwise_add_long_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    cdisasm_operand_access destination_access;
} arm_advsimd_pairwise_add_long_identity;

static int arm_advsimd_pairwise_add_long_identity_for_word(
    uint32_t word, arm_advsimd_pairwise_add_long_identity *identity)
{
    switch (word & UINT32_C(0xbf3ffc00)) {
        case UINT32_C(0x0e202800):
            identity->form_id = UINT16_C(6005);
            identity->name_id = CDISASM_ARM_NAME_SADDLP;
            identity->destination_access = CDISASM_OPERAND_ACCESS_WRITE;
            return 1;
        case UINT32_C(0x0e206800):
            identity->form_id = UINT16_C(6009);
            identity->name_id = CDISASM_ARM_NAME_SADALP;
            identity->destination_access =
                CDISASM_OPERAND_ACCESS_READ_WRITE;
            return 1;
        case UINT32_C(0x2e202800):
            identity->form_id = UINT16_C(6039);
            identity->name_id = CDISASM_ARM_NAME_UADDLP;
            identity->destination_access = CDISASM_OPERAND_ACCESS_WRITE;
            return 1;
        case UINT32_C(0x2e206800):
            identity->form_id = UINT16_C(6042);
            identity->name_id = CDISASM_ARM_NAME_UADALP;
            identity->destination_access =
                CDISASM_OPERAND_ACCESS_READ_WRITE;
            return 1;
        default:
            return 0;
    }
}

static int arm_valid_advsimd_pairwise_add_long_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_advsimd_pairwise_add_long_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE,
        CDISASM_OPERAND_ACCESS_NONE
    };
    uint32_t word = instruction->raw_instruction;
    unsigned q = (word >> 30) & 1u;
    unsigned size_code = (word >> 22) & 3u;
    uint8_t source_element_size = (uint8_t)(UINT8_C(1) << size_code);
    uint8_t result_element_size =
        (uint8_t)(source_element_size * 2u);
    uint8_t vector_size = q != 0u ? 16u : 8u;
    int raw_is_envelope = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_advsimd_pairwise_add_long_identity_for_word(
            word, &identity);
    int raw_is_family = raw_is_envelope && size_code <= 2u;
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->form_id == UINT16_C(6005)
            || instruction->form_id == UINT16_C(6009)
            || instruction->form_id == UINT16_C(6039)
            || instruction->form_id == UINT16_C(6042));
    int name_is_family = instruction->name_id == CDISASM_ARM_NAME_SADDLP
        || instruction->name_id == CDISASM_ARM_NAME_SADALP
        || instruction->name_id == CDISASM_ARM_NAME_UADDLP
        || instruction->name_id == CDISASM_ARM_NAME_UADALP;
    int sve_sibling = instruction->isa_id == CDISASM_ARM_ISA_A64
        && ((instruction->form_id == UINT16_C(2677)
                && instruction->name_id == CDISASM_ARM_NAME_SADALP)
            || (instruction->form_id == UINT16_C(2678)
                && instruction->name_id == CDISASM_ARM_NAME_UADALP));
    int name_claims_fixed_family = name_is_family && !sve_sibling;

    if (!raw_is_envelope && !form_is_family
        && !name_claims_fixed_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        && instruction->branch_target == 0u
        && instruction->operand_count == 2u
        && arm_exact_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + (word & 31u)),
            vector_size, result_element_size,
            identity.destination_access)
        && arm_exact_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)),
            vector_size, source_element_size,
            CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_advsimd_narrow_widen_move_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    uint8_t widening;
} arm_advsimd_narrow_widen_move_identity;

static int arm_advsimd_narrow_widen_move_identity_for_word(
    uint32_t word, arm_advsimd_narrow_widen_move_identity *identity)
{
    switch (word & UINT32_C(0xbf3ffc00)) {
        case UINT32_C(0x0e212800):
            identity->form_id = UINT16_C(6015);
            identity->name_id = CDISASM_ARM_NAME_XTN;
            identity->widening = 0u;
            return 1;
        case UINT32_C(0x2e213800):
            identity->form_id = UINT16_C(6048);
            identity->name_id = CDISASM_ARM_NAME_SHLL;
            identity->widening = 1u;
            return 1;
        default:
            return 0;
    }
}

static int arm_is_advsimd_narrow_widen_move_form(
    cdisasm_arm_form_id form_id)
{
    return form_id == UINT16_C(6015) || form_id == UINT16_C(6048);
}

static int arm_valid_advsimd_narrow_widen_move_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_advsimd_narrow_widen_move_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE, 0u
    };
    uint32_t word = instruction->raw_instruction;
    unsigned size_code = (word >> 22) & 3u;
    int high = (word & UINT32_C(0x40000000)) != 0u;
    uint8_t narrow_element_size =
        (uint8_t)(UINT8_C(1) << size_code);
    uint8_t wide_element_size =
        (uint8_t)(narrow_element_size * 2u);
    int raw_is_envelope = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_advsimd_narrow_widen_move_identity_for_word(word, &identity);
    int raw_is_family = raw_is_envelope && size_code <= 2u;
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_is_advsimd_narrow_widen_move_form(instruction->form_id);
    int name_is_family = instruction->name_id == CDISASM_ARM_NAME_XTN
        || instruction->name_id == CDISASM_ARM_NAME_SHLL;

    /* XTN and SHLL have no same-name A64 sibling forms in the pinned
     * catalog.  Keep raw, form, and mnemonic ownership independent so a
     * forged or generated-opaque claim cannot reach generic formatting. */
    if (!raw_is_envelope && !form_is_family && !name_is_family) {
        return 1;
    }
    if (!raw_is_family || !form_is_family || !name_is_family
        || instruction->form_id != identity.form_id
        || instruction->name_id != identity.name_id
        || instruction->opcode_size != 4u
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->instruction_flags
            != CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        || instruction->branch_target != 0u) {
        return 0;
    }
    if (identity.widening == 0u) {
        return instruction->operand_count == 2u
            && arm_exact_vector_operand(
                &instruction->operand[0], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_V0 + (word & 31u)),
                high ? 16u : 8u, narrow_element_size,
                high ? CDISASM_OPERAND_ACCESS_READ_WRITE
                     : CDISASM_OPERAND_ACCESS_WRITE)
            && arm_exact_vector_operand(
                &instruction->operand[1], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)),
                16u, wide_element_size, CDISASM_OPERAND_ACCESS_READ);
    }
    return instruction->operand_count == 3u
        && arm_exact_vector_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + (word & 31u)),
            16u, wide_element_size, CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_vector_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_V0 + ((word >> 5) & 31u)),
            high ? 16u : 8u, narrow_element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_u8_immediate_operand(
            &instruction->operand[2],
            (uint64_t)narrow_element_size * UINT64_C(8))
        && instruction->operand[2].shift_type == CDISASM_ARM_SHIFT_NONE
        && instruction->operand[2].shift_amount == 0u;
}

typedef struct arm_sve_predicated_saturating_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
} arm_sve_predicated_saturating_identity;

static int arm_sve_predicated_saturating_identity_for_word(
    uint32_t word, arm_sve_predicated_saturating_identity *identity)
{
    static const cdisasm_arm_form_id forms[8] = {
        UINT16_C(2693), UINT16_C(2698), UINT16_C(2694), UINT16_C(2699),
        UINT16_C(2695), UINT16_C(2696), UINT16_C(2697), UINT16_C(2700)
    };
    static const cdisasm_arm_name_id names[8] = {
        CDISASM_ARM_NAME_SQADD,
        CDISASM_ARM_NAME_UQADD,
        CDISASM_ARM_NAME_SQSUB,
        CDISASM_ARM_NAME_UQSUB,
        CDISASM_ARM_NAME_SUQADD,
        CDISASM_ARM_NAME_USQADD,
        CDISASM_ARM_NAME_SQSUBR,
        CDISASM_ARM_NAME_UQSUBR
    };
    unsigned operation;

    if ((word & UINT32_C(0xff38e000)) != UINT32_C(0x44188000)) {
        return 0;
    }
    operation = (word >> 16) & 7u;
    identity->form_id = forms[operation];
    identity->name_id = names[operation];
    return 1;
}

static int arm_valid_sve_predicated_saturating_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_sve_predicated_saturating_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE
    };
    uint32_t word = instruction->raw_instruction;
    uint8_t element_size = (uint8_t)(UINT8_C(1)
        << ((word >> 22) & 3u));
    cdisasm_arm_reg_id zdn = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + (word & 31u));
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_predicated_saturating_identity_for_word(word, &identity);
    int form_is_family = instruction->form_id >= UINT16_C(2693)
        && instruction->form_id <= UINT16_C(2700);

    if (!raw_is_family && !form_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family
        && instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        && instruction->operand_count == 4u
        && arm_exact_scalable_operand(
            &instruction->operand[0], zdn, element_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_predicate_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_P0 + ((word >> 10) & 7u)),
            element_size, CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_scalable_operand(
            &instruction->operand[2], zdn, element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_scalable_operand(
            &instruction->operand[3], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)), element_size,
            CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_sve_clamp_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
} arm_sve_clamp_identity;

static int arm_sve_clamp_identity_for_word(
    uint32_t word, arm_sve_clamp_identity *identity)
{
    if ((word & UINT32_C(0xff20f800)) != UINT32_C(0x4400c000)) {
        return 0;
    }
    if ((word & UINT32_C(0x00000400)) != 0u) {
        identity->form_id = UINT16_C(2702);
        identity->name_id = CDISASM_ARM_NAME_UCLAMP;
    } else {
        identity->form_id = UINT16_C(2701);
        identity->name_id = CDISASM_ARM_NAME_SCLAMP;
    }
    return 1;
}

static int arm_valid_sve_clamp_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_sve_clamp_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE
    };
    uint32_t word = instruction->raw_instruction;
    uint8_t element_size = (uint8_t)(UINT8_C(1)
        << ((word >> 22) & 3u));
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_clamp_identity_for_word(word, &identity);
    int form_is_family = instruction->form_id >= UINT16_C(2701)
        && instruction->form_id <= UINT16_C(2702);
    int name_is_family = (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE) == 0u
        && (instruction->name_id == CDISASM_ARM_NAME_SCLAMP
            || instruction->name_id == CDISASM_ARM_NAME_UCLAMP);

    if (!raw_is_family && !form_is_family && !name_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        && instruction->operand_count == 3u
        && arm_exact_scalable_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + (word & 31u)), element_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_scalable_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)), element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_scalable_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 16) & 31u)), element_size,
            CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_sve_pointer_muladd_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    uint8_t add_then_multiply;
} arm_sve_pointer_muladd_identity;

static int arm_sve_pointer_muladd_identity_for_word(
    uint32_t word, arm_sve_pointer_muladd_identity *identity)
{
    if ((word & UINT32_C(0xff20f400)) != UINT32_C(0x4400d000)
        || ((word >> 22) & 3u) != 3u) {
        return 0;
    }
    identity->add_then_multiply =
        (word & UINT32_C(0x00000800)) != 0u;
    identity->form_id = identity->add_then_multiply != 0u
        ? UINT16_C(2708) : UINT16_C(2707);
    identity->name_id = identity->add_then_multiply != 0u
        ? CDISASM_ARM_NAME_MADPT : CDISASM_ARM_NAME_MLAPT;
    return 1;
}

static int arm_valid_sve_pointer_muladd_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_sve_pointer_muladd_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE, 0u
    };
    uint32_t word = instruction->raw_instruction;
    cdisasm_arm_reg_id low = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u));
    cdisasm_arm_reg_id high = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + ((word >> 16) & 31u));
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_pointer_muladd_identity_for_word(word, &identity);
    int form_is_family = instruction->form_id >= UINT16_C(2707)
        && instruction->form_id <= UINT16_C(2708);
    int name_is_family = instruction->name_id == CDISASM_ARM_NAME_MLAPT
        || instruction->name_id == CDISASM_ARM_NAME_MADPT;

    if (!raw_is_family && !form_is_family && !name_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        && instruction->operand_count == 3u
        && arm_exact_scalable_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + (word & 31u)), 8u,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_scalable_operand(
            &instruction->operand[1],
            identity.add_then_multiply != 0u ? high : low, 8u,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_scalable_operand(
            &instruction->operand[2],
            identity.add_then_multiply != 0u ? low : high, 8u,
            CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_sve_quad_permute_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
} arm_sve_quad_permute_identity;

static int arm_sve_quad_permute_identity_for_word(
    uint32_t word, arm_sve_quad_permute_identity *identity)
{
    uint32_t fixed = word & UINT32_C(0xff20fc00);

    if (fixed == UINT32_C(0x4400e000)) {
        identity->form_id = UINT16_C(2711);
        identity->name_id = CDISASM_ARM_NAME_ZIPQ1;
        return 1;
    }
    if (fixed == UINT32_C(0x4400e400)) {
        identity->form_id = UINT16_C(2714);
        identity->name_id = CDISASM_ARM_NAME_ZIPQ2;
        return 1;
    }
    if (fixed == UINT32_C(0x4400e800)) {
        identity->form_id = UINT16_C(2712);
        identity->name_id = CDISASM_ARM_NAME_UZPQ1;
        return 1;
    }
    if (fixed == UINT32_C(0x4400ec00)) {
        identity->form_id = UINT16_C(2715);
        identity->name_id = CDISASM_ARM_NAME_UZPQ2;
        return 1;
    }
    return 0;
}

static int arm_valid_sve_quad_permute_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_sve_quad_permute_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE
    };
    uint32_t word = instruction->raw_instruction;
    uint8_t element_size = (uint8_t)(UINT8_C(1)
        << ((word >> 22) & 3u));
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_quad_permute_identity_for_word(word, &identity);
    int form_is_family = instruction->form_id == UINT16_C(2711)
        || instruction->form_id == UINT16_C(2712)
        || instruction->form_id == UINT16_C(2714)
        || instruction->form_id == UINT16_C(2715);
    int name_is_family = instruction->name_id == CDISASM_ARM_NAME_ZIPQ1
        || instruction->name_id == CDISASM_ARM_NAME_UZPQ1
        || instruction->name_id == CDISASM_ARM_NAME_ZIPQ2
        || instruction->name_id == CDISASM_ARM_NAME_UZPQ2;

    if (!raw_is_family && !form_is_family && !name_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        && instruction->operand_count == 3u
        && arm_exact_scalable_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + (word & 31u)), element_size,
            CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_scalable_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)), element_size,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_scalable_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 16) & 31u)), element_size,
            CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_sve_complex_muladd_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    uint8_t destination_size;
    uint8_t source_size;
    uint8_t has_rotation;
} arm_sve_complex_muladd_identity;

static int arm_sve_complex_muladd_identity_for_word(
    uint32_t word, arm_sve_complex_muladd_identity *identity)
{
    static const struct arm_sve_widening_identity {
        uint32_t fixed_value;
        cdisasm_arm_form_id form_id;
        cdisasm_arm_name_id name_id;
    } widening_identities[14] = {
        { UINT32_C(0x44004000), UINT16_C(2642),
          CDISASM_ARM_NAME_SMLALB },
        { UINT32_C(0x44005000), UINT16_C(2643),
          CDISASM_ARM_NAME_SMLSLB },
        { UINT32_C(0x44004400), UINT16_C(2644),
          CDISASM_ARM_NAME_SMLALT },
        { UINT32_C(0x44005400), UINT16_C(2645),
          CDISASM_ARM_NAME_SMLSLT },
        { UINT32_C(0x44004800), UINT16_C(2646),
          CDISASM_ARM_NAME_UMLALB },
        { UINT32_C(0x44005800), UINT16_C(2647),
          CDISASM_ARM_NAME_UMLSLB },
        { UINT32_C(0x44004c00), UINT16_C(2648),
          CDISASM_ARM_NAME_UMLALT },
        { UINT32_C(0x44005c00), UINT16_C(2649),
          CDISASM_ARM_NAME_UMLSLT },
        { UINT32_C(0x44006000), UINT16_C(2650),
          CDISASM_ARM_NAME_SQDMLALB },
        { UINT32_C(0x44006800), UINT16_C(2651),
          CDISASM_ARM_NAME_SQDMLSLB },
        { UINT32_C(0x44006400), UINT16_C(2652),
          CDISASM_ARM_NAME_SQDMLALT },
        { UINT32_C(0x44006c00), UINT16_C(2653),
          CDISASM_ARM_NAME_SQDMLSLT },
        { UINT32_C(0x44007000), UINT16_C(2654),
          CDISASM_ARM_NAME_SQRDMLAH },
        { UINT32_C(0x44007400), UINT16_C(2655),
          CDISASM_ARM_NAME_SQRDMLSH }
    };
    unsigned size_code = (word >> 22) & 3u;

    identity->destination_size = (uint8_t)(UINT8_C(1) << size_code);
    identity->source_size = identity->destination_size;
    identity->has_rotation = 0u;
    if ((word & UINT32_C(0xff20fc00)) == UINT32_C(0x44000800)
        && size_code != 0u) {
        identity->form_id = UINT16_C(2637);
        identity->name_id = CDISASM_ARM_NAME_SQDMLALBT;
        identity->source_size = (uint8_t)(identity->destination_size / 2u);
    } else if ((word & UINT32_C(0xff20fc00))
            == UINT32_C(0x44000c00)
        && size_code != 0u) {
        identity->form_id = UINT16_C(2638);
        identity->name_id = CDISASM_ARM_NAME_SQDMLSLBT;
        identity->source_size = (uint8_t)(identity->destination_size / 2u);
    } else if ((word & UINT32_C(0xff20f000))
            == UINT32_C(0x44001000)
        && size_code >= 2u) {
        identity->form_id = UINT16_C(2639);
        identity->name_id = CDISASM_ARM_NAME_CDOT;
        identity->source_size = (uint8_t)(identity->destination_size / 4u);
        identity->has_rotation = 1u;
    } else if ((word & UINT32_C(0xff20f000))
        == UINT32_C(0x44002000)) {
        identity->form_id = UINT16_C(2640);
        identity->name_id = CDISASM_ARM_NAME_CMLA;
        identity->has_rotation = 1u;
    } else if ((word & UINT32_C(0xff20f000))
        == UINT32_C(0x44003000)) {
        identity->form_id = UINT16_C(2641);
        identity->name_id = CDISASM_ARM_NAME_SQRDCMLAH;
        identity->has_rotation = 1u;
    } else {
        size_t index;

        for (index = 0u;
             index < sizeof(widening_identities)
                 / sizeof(widening_identities[0]);
             ++index) {
            if ((word & UINT32_C(0xff20fc00))
                == widening_identities[index].fixed_value) {
                break;
            }
        }
        if (index == sizeof(widening_identities)
                / sizeof(widening_identities[0])
            || (index < 12u && size_code == 0u)) {
            return 0;
        }
        identity->form_id = widening_identities[index].form_id;
        identity->name_id = widening_identities[index].name_id;
        if (index < 12u) {
            identity->source_size =
                (uint8_t)(identity->destination_size / 2u);
        }
    }
    return 1;
}

static int arm_valid_sve_complex_muladd_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_sve_complex_muladd_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE, 0u, 0u, 0u
    };
    uint32_t word = instruction->raw_instruction;
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_complex_muladd_identity_for_word(word, &identity);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id >= UINT16_C(2637)
        && instruction->form_id <= UINT16_C(2655);

    if (!raw_is_family && !form_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family
        && instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        && instruction->operand_count == (identity.has_rotation ? 4u : 3u)
        && arm_exact_scalable_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + (word & 31u)),
            identity.destination_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_scalable_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 5) & 31u)),
            identity.source_size, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_scalable_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_Z0 + ((word >> 16) & 31u)),
            identity.source_size, CDISASM_OPERAND_ACCESS_READ)
        && (!identity.has_rotation
            || arm_exact_u16_immediate_operand(
                &instruction->operand[3], ((word >> 10) & 3u) * 90u));
}

static int arm_valid_sve_fcmla_predicated_schema(
    const cdisasm_arm_instruction *i)
{
    uint32_t w = i->raw_instruction;
    unsigned size_code = (w >> 22) & 3u;
    uint8_t size = (uint8_t)(1u << size_code);
    int raw = i->isa_id == CDISASM_ARM_ISA_A64 && size_code != 0u
        && (w & UINT32_C(0xff208000)) == UINT32_C(0x64000000);
    int claimed = i->isa_id == CDISASM_ARM_ISA_A64
        && i->form_id == UINT16_C(2920);

    if (!raw && !claimed) return 1;
    if (!raw || !claimed) return 0;
    return i->name_id == CDISASM_ARM_NAME_FCMLA
        && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
                | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)
        && i->operand_count == 4u
        && arm_exact_scalable_operand(&i->operand[0],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + (w & 31u)), size,
            CDISASM_OPERAND_ACCESS_READ_WRITE)
        && arm_exact_predicate_operand(&i->operand[1],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + ((w >> 10) & 7u)),
            size, CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_scalable_operand(&i->operand[2],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + ((w >> 5) & 31u)),
            size, CDISASM_OPERAND_ACCESS_READ)
        && i->operand[3].type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER
        && i->operand[3].reg == CDISASM_ARM_REG_Z0 + ((w >> 16) & 31u)
        && i->operand[3].base_reg == CDISASM_ARM_REG_NONE
        && i->operand[3].index_reg == CDISASM_ARM_REG_NONE
        && i->operand[3].register_list == 0u && i->operand[3].address == 0u
        && i->operand[3].imm == ((w >> 13) & 3u) * 90u
        && i->operand[3].size == 0u
        && i->operand[3].flags == CDISASM_ARM_OPERAND_FLAG_HAS_ROTATION
        && i->operand[3].shift_type == CDISASM_ARM_SHIFT_NONE
        && i->operand[3].shift_amount == 0u
        && i->operand[3].extend_type == size && i->operand[3].scale == 0u
        && i->operand[3].access == CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sve_predicate_control_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_sve_predicate_control_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE,
        ARM_SVE_PREDICATE_CONTROL_NONE
    };
    uint32_t word = instruction->raw_instruction;
    unsigned pd = word & 15u;
    unsigned source = (word >> 5) & 15u;
    uint8_t element_size = (uint8_t)(UINT8_C(1)
        << ((word >> 22) & 3u));
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_predicate_control_identity_for_word(word, &identity);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id >= UINT16_C(2556)
        && instruction->form_id <= UINT16_C(2561);
    int name_is_exclusive = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_is_exclusive_sve_predicate_control_name(
            instruction->name_id);
    uint32_t expected_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR;

    if (!raw_is_family && !form_is_family && !name_is_exclusive) {
        return 1;
    }
    if (!raw_is_family || !form_is_family
        || instruction->form_id != identity.form_id
        || instruction->name_id != identity.name_id
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->opcode_groups != CDISASM_GROUP_NONE) {
        return 0;
    }
    if (identity.kind == ARM_SVE_PREDICATE_CONTROL_PTEST) {
        expected_flags |= CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
    } else if (identity.kind == ARM_SVE_PREDICATE_CONTROL_PFIRST) {
        expected_flags |= CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED;
    } else if (identity.kind == ARM_SVE_PREDICATE_CONTROL_PTRUES) {
        expected_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
    }
    if (instruction->instruction_flags != expected_flags) {
        return 0;
    }
    if (identity.kind == ARM_SVE_PREDICATE_CONTROL_PTEST) {
        return instruction->operand_count == 2u
            && arm_exact_predicate_operand(
                &instruction->operand[0], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_P0 + ((word >> 10) & 15u)), 1u,
                CDISASM_OPERAND_FLAG_NONE,
                CDISASM_OPERAND_ACCESS_READ)
            && arm_exact_predicate_operand(
                &instruction->operand[1], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_P0 + source), 1u,
                CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
                CDISASM_OPERAND_ACCESS_READ);
    }
    if (identity.kind == ARM_SVE_PREDICATE_CONTROL_PFIRST
        || identity.kind == ARM_SVE_PREDICATE_CONTROL_PNEXT) {
        uint8_t size = identity.kind == ARM_SVE_PREDICATE_CONTROL_PFIRST
            ? 1u : element_size;

        return instruction->operand_count == 3u
            && arm_exact_predicate_operand(
                &instruction->operand[0], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_P0 + pd), size,
                CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
                CDISASM_OPERAND_ACCESS_WRITE)
            && arm_exact_predicate_operand(
                &instruction->operand[1], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_P0 + source), size,
                CDISASM_OPERAND_FLAG_NONE,
                CDISASM_OPERAND_ACCESS_READ)
            && arm_exact_predicate_operand(
                &instruction->operand[2], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_P0 + pd), size,
                CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
                CDISASM_OPERAND_ACCESS_READ);
    }
    if (identity.kind == ARM_SVE_PREDICATE_CONTROL_PTRUE
        || identity.kind == ARM_SVE_PREDICATE_CONTROL_PTRUES) {
        return instruction->operand_count == 2u
            && arm_exact_predicate_operand(
                &instruction->operand[0], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_P0 + pd), element_size,
                CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
                CDISASM_OPERAND_ACCESS_WRITE)
            && arm_exact_u8_immediate_operand(
                &instruction->operand[1], (word >> 5) & UINT32_C(31));
    }
    return instruction->operand_count == 1u
        && arm_exact_predicate_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_P0 + pd), 1u,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
            CDISASM_OPERAND_ACCESS_WRITE);
}

static int arm_valid_sve_predicate_break_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_sve_predicate_break_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE,
        ARM_SVE_PREDICATE_BREAK_NONE
    };
    uint32_t word = instruction->raw_instruction;
    unsigned pd = word & 15u;
    unsigned pn = (word >> 5) & 15u;
    unsigned pg = (word >> 10) & 15u;
    cdisasm_arm_reg_id expected_pd = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_P0 + pd);
    int sets_flags = (word & UINT32_C(0x00400000)) != 0u;
    int merging;
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_predicate_break_identity_for_word(word, &identity);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id >= UINT16_C(2546)
        && instruction->form_id <= UINT16_C(2555);
    int name_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_is_sve_predicate_break_name(instruction->name_id);
    uint32_t expected_flags = CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
        | (sets_flags ? CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS : 0u);

    merging = raw_is_family
        && identity.kind == ARM_SVE_PREDICATE_BREAK_BRK
        && (word & UINT32_C(0x10)) != 0u;
    if (!raw_is_family && !form_is_family && !name_is_family) {
        return 1;
    }
    if (!raw_is_family || !form_is_family || !name_is_family
        || instruction->form_id != identity.form_id
        || instruction->name_id != identity.name_id
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->instruction_flags != expected_flags) {
        return 0;
    }
    if (identity.kind == ARM_SVE_PREDICATE_BREAK_BRKP) {
        return instruction->operand_count == 4u
            && arm_exact_predicate_operand(
                &instruction->operand[0], expected_pd, 1u,
                CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
                CDISASM_OPERAND_ACCESS_WRITE)
            && arm_exact_predicate_operand(
                &instruction->operand[1], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_P0 + pg), 1u,
                CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO,
                CDISASM_OPERAND_ACCESS_READ)
            && arm_exact_predicate_operand(
                &instruction->operand[2], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_P0 + pn), 1u,
                CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
                CDISASM_OPERAND_ACCESS_READ)
            && arm_exact_predicate_operand(
                &instruction->operand[3], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_P0 + ((word >> 16) & 15u)), 1u,
                CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
                CDISASM_OPERAND_ACCESS_READ);
    }
    if (identity.kind == ARM_SVE_PREDICATE_BREAK_BRKN) {
        return instruction->operand_count == 4u
            && arm_exact_predicate_operand(
                &instruction->operand[0], expected_pd, 1u,
                CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
                CDISASM_OPERAND_ACCESS_WRITE)
            && arm_exact_predicate_operand(
                &instruction->operand[1], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_P0 + pg), 1u,
                CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO,
                CDISASM_OPERAND_ACCESS_READ)
            && arm_exact_predicate_operand(
                &instruction->operand[2], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_P0 + pn), 1u,
                CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
                CDISASM_OPERAND_ACCESS_READ)
            && arm_exact_predicate_operand(
                &instruction->operand[3], expected_pd, 1u,
                CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
                CDISASM_OPERAND_ACCESS_READ);
    }
    return identity.kind == ARM_SVE_PREDICATE_BREAK_BRK
        && instruction->operand_count == 3u
        && arm_exact_predicate_operand(
            &instruction->operand[0], expected_pd, 1u,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
            merging ? CDISASM_OPERAND_ACCESS_READ_WRITE
                    : CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_predicate_operand(
            &instruction->operand[1], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_P0 + pg), 1u,
            merging ? CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE
                    : CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_predicate_operand(
            &instruction->operand[2], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_P0 + pn), 1u,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
            CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_sve_while_counter_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
} arm_sve_while_counter_identity;

static int arm_sve_while_counter_identity_for_word(
    uint32_t word, arm_sve_while_counter_identity *identity)
{
    static const uint32_t values[8] = {
        UINT32_C(0x25204010), UINT32_C(0x25204810),
        UINT32_C(0x25204018), UINT32_C(0x25204818),
        UINT32_C(0x25204410), UINT32_C(0x25204c10),
        UINT32_C(0x25204418), UINT32_C(0x25204c18)
    };
    static const cdisasm_arm_name_id names[8] = {
        CDISASM_ARM_NAME_WHILEGE, CDISASM_ARM_NAME_WHILEHS,
        CDISASM_ARM_NAME_WHILEGT, CDISASM_ARM_NAME_WHILEHI,
        CDISASM_ARM_NAME_WHILELT, CDISASM_ARM_NAME_WHILELO,
        CDISASM_ARM_NAME_WHILELE, CDISASM_ARM_NAME_WHILELS
    };
    uint32_t fixed = word & UINT32_C(0xff20dc18);
    unsigned index;

    for (index = 0u; index < 8u; ++index) {
        if (fixed == values[index]) {
            identity->form_id = (cdisasm_arm_form_id)(UINT16_C(2566)
                + index);
            identity->name_id = names[index];
            return 1;
        }
    }
    return 0;
}

static int arm_valid_sve_while_counter_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_sve_while_counter_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE
    };
    uint32_t word = instruction->raw_instruction;
    uint8_t element_size = (uint8_t)(UINT8_C(1)
        << ((word >> 22) & 3u));
    unsigned rn = (word >> 5) & 31u;
    unsigned rm = (word >> 16) & 31u;
    cdisasm_arm_reg_id expected_rn = rn == 31u
        ? CDISASM_ARM_REG_XZR
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + rn);
    cdisasm_arm_reg_id expected_rm = rm == 31u
        ? CDISASM_ARM_REG_XZR
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + rm);
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_while_counter_identity_for_word(word, &identity);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id >= UINT16_C(2566)
        && instruction->form_id <= UINT16_C(2573);
    int form_is_sibling = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id >= UINT16_C(2574)
        && instruction->form_id <= UINT16_C(2592);
    int name_is_shared = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_is_sve_while_comparison_name(instruction->name_id);

    if (!raw_is_family && form_is_sibling) {
        return 1;
    }
    if (!raw_is_family && !form_is_family && !name_is_shared) {
        return 1;
    }
    if (!raw_is_family || !form_is_family || !name_is_shared) {
        return 0;
    }
    return instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
                | CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS)
        && instruction->operand_count == 4u
        && arm_exact_predicate_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_PN8 + (word & 7u)), element_size,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
            CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_register_operand(
            &instruction->operand[1], expected_rn, 8u,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_register_operand(
            &instruction->operand[2], expected_rm, 8u,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_u8_immediate_operand(
            &instruction->operand[3],
            (word & UINT32_C(0x00002000)) != 0u ? 4u : 2u);
}

static int arm_valid_sve_while_single_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_sve_while_single_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE
    };
    uint32_t word = instruction->raw_instruction;
    uint8_t element_size = (uint8_t)(UINT8_C(1)
        << ((word >> 22) & 3u));
    int wide = (word & UINT32_C(0x00001000)) != 0u;
    unsigned rn = (word >> 5) & 31u;
    unsigned rm = (word >> 16) & 31u;
    cdisasm_arm_reg_id expected_rn = wide
        ? (rn == 31u ? CDISASM_ARM_REG_XZR
                     : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + rn))
        : (rn == 31u ? CDISASM_ARM_REG_WZR
                     : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_W0 + rn));
    cdisasm_arm_reg_id expected_rm = wide
        ? (rm == 31u ? CDISASM_ARM_REG_XZR
                     : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + rm))
        : (rm == 31u ? CDISASM_ARM_REG_WZR
                     : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_W0 + rm));
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_while_single_identity_for_word(word, &identity);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id >= UINT16_C(2585)
        && instruction->form_id <= UINT16_C(2592);
    int form_is_sibling = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id >= UINT16_C(2566)
        && instruction->form_id <= UINT16_C(2581);
    int name_is_shared = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_is_sve_while_comparison_name(instruction->name_id);

    if (!raw_is_family && form_is_sibling) {
        return 1;
    }
    if (!raw_is_family && !form_is_family && !name_is_shared) {
        return 1;
    }
    if (!raw_is_family || !form_is_family || !name_is_shared) {
        return 0;
    }
    return instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
                | CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS)
        && instruction->operand_count == 3u
        && arm_exact_predicate_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_P0 + (word & 15u)), element_size,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
            CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_register_operand(
            &instruction->operand[1], expected_rn, wide ? 8u : 4u,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_register_operand(
            &instruction->operand[2], expected_rm, wide ? 8u : 4u,
            CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_sve_while_pair_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
} arm_sve_while_pair_identity;

static int arm_sve_while_pair_identity_for_word(
    uint32_t word, arm_sve_while_pair_identity *identity)
{
    static const uint32_t values[8] = {
        UINT32_C(0x25205010), UINT32_C(0x25205810),
        UINT32_C(0x25205011), UINT32_C(0x25205811),
        UINT32_C(0x25205410), UINT32_C(0x25205c10),
        UINT32_C(0x25205411), UINT32_C(0x25205c11)
    };
    static const cdisasm_arm_name_id names[8] = {
        CDISASM_ARM_NAME_WHILEGE, CDISASM_ARM_NAME_WHILEHS,
        CDISASM_ARM_NAME_WHILEGT, CDISASM_ARM_NAME_WHILEHI,
        CDISASM_ARM_NAME_WHILELT, CDISASM_ARM_NAME_WHILELO,
        CDISASM_ARM_NAME_WHILELE, CDISASM_ARM_NAME_WHILELS
    };
    uint32_t fixed = word & UINT32_C(0xff20fc11);
    unsigned index;

    for (index = 0u; index < 8u; ++index) {
        if (fixed == values[index]) {
            identity->form_id = (cdisasm_arm_form_id)(UINT16_C(2574)
                + index);
            identity->name_id = names[index];
            return 1;
        }
    }
    return 0;
}

static int arm_valid_sve_while_pair_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_sve_while_pair_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE
    };
    uint32_t word = instruction->raw_instruction;
    uint8_t element_size = (uint8_t)(UINT8_C(1)
        << ((word >> 22) & 3u));
    unsigned pd = (word >> 1) & 7u;
    unsigned rn = (word >> 5) & 31u;
    unsigned rm = (word >> 16) & 31u;
    cdisasm_arm_reg_id expected_first = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_P0 + pd * 2u);
    cdisasm_arm_reg_id expected_rn = rn == 31u
        ? CDISASM_ARM_REG_XZR
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + rn);
    cdisasm_arm_reg_id expected_rm = rm == 31u
        ? CDISASM_ARM_REG_XZR
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + rm);
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_while_pair_identity_for_word(word, &identity);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id >= UINT16_C(2574)
        && instruction->form_id <= UINT16_C(2581);
    int form_is_sibling = instruction->isa_id == CDISASM_ARM_ISA_A64
        && ((instruction->form_id >= UINT16_C(2566)
                && instruction->form_id <= UINT16_C(2573))
            || (instruction->form_id >= UINT16_C(2585)
                && instruction->form_id <= UINT16_C(2592)));
    int name_is_shared = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_is_sve_while_comparison_name(instruction->name_id);

    if (!raw_is_family && form_is_sibling) {
        return 1;
    }
    if (!raw_is_family && !form_is_family && !name_is_shared) {
        return 1;
    }
    if (!raw_is_family || !form_is_family || !name_is_shared) {
        return 0;
    }
    return instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
                | CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS)
        && instruction->operand_count == 3u
        && arm_exact_predicate_pair_operand(
            &instruction->operand[0], expected_first,
            (cdisasm_arm_reg_id)(expected_first + 1u), element_size,
            CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_register_operand(
            &instruction->operand[1], expected_rn, 8u,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_register_operand(
            &instruction->operand[2], expected_rm, 8u,
            CDISASM_OPERAND_ACCESS_READ);
}

typedef enum arm_sve_counter_mask_kind {
    ARM_SVE_COUNTER_MASK_NONE = 0,
    ARM_SVE_COUNTER_MASK_PEXT_ONE,
    ARM_SVE_COUNTER_MASK_PEXT_PAIR,
    ARM_SVE_COUNTER_MASK_PTRUE
} arm_sve_counter_mask_kind;

typedef struct arm_sve_counter_mask_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    arm_sve_counter_mask_kind kind;
} arm_sve_counter_mask_identity;

static int arm_sve_counter_mask_identity_for_word(
    uint32_t word, arm_sve_counter_mask_identity *identity)
{
    if ((word & UINT32_C(0xff3ffc10)) == UINT32_C(0x25207010)) {
        identity->form_id = UINT16_C(2582);
        identity->name_id = CDISASM_ARM_NAME_PEXT;
        identity->kind = ARM_SVE_COUNTER_MASK_PEXT_ONE;
        return 1;
    }
    if ((word & UINT32_C(0xff3ffe10)) == UINT32_C(0x25207410)) {
        identity->form_id = UINT16_C(2583);
        identity->name_id = CDISASM_ARM_NAME_PEXT;
        identity->kind = ARM_SVE_COUNTER_MASK_PEXT_PAIR;
        return 1;
    }
    if ((word & UINT32_C(0xff3ffff8)) == UINT32_C(0x25207810)) {
        identity->form_id = UINT16_C(2584);
        identity->name_id = CDISASM_ARM_NAME_PTRUE;
        identity->kind = ARM_SVE_COUNTER_MASK_PTRUE;
        return 1;
    }
    return 0;
}

static int arm_valid_sve_counter_mask_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_sve_counter_mask_identity identity = {
        CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE,
        ARM_SVE_COUNTER_MASK_NONE
    };
    uint32_t word = instruction->raw_instruction;
    uint8_t element_size = (uint8_t)(UINT8_C(1)
        << ((word >> 22) & 3u));
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_counter_mask_identity_for_word(word, &identity);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id >= UINT16_C(2582)
        && instruction->form_id <= UINT16_C(2584);
    int name_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->name_id == CDISASM_ARM_NAME_PEXT
            || instruction->name_id == CDISASM_ARM_NAME_PTRUE);
    int ordinary_ptrue = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id == UINT16_C(2559)
        && instruction->name_id == CDISASM_ARM_NAME_PTRUE
        && (word & UINT32_C(0xff3ffc10)) == UINT32_C(0x2518e000);

    if (!raw_is_family && ordinary_ptrue) {
        return 1;
    }
    if (!raw_is_family && !form_is_family && !name_is_family) {
        return 1;
    }
    if (!raw_is_family || !form_is_family || !name_is_family
        || instruction->form_id != identity.form_id
        || instruction->name_id != identity.name_id
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->instruction_flags
            != CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR) {
        return 0;
    }
    if (identity.kind == ARM_SVE_COUNTER_MASK_PTRUE) {
        return instruction->operand_count == 1u
            && arm_exact_predicate_operand(
                &instruction->operand[0], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_PN8 + (word & 7u)), element_size,
                CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
                CDISASM_OPERAND_ACCESS_WRITE);
    }
    if (identity.kind == ARM_SVE_COUNTER_MASK_PEXT_ONE) {
        return instruction->operand_count == 2u
            && arm_exact_predicate_operand(
                &instruction->operand[0], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_P0 + (word & 15u)), element_size,
                CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
                CDISASM_OPERAND_ACCESS_WRITE)
            && arm_exact_predicate_lane_operand(
                &instruction->operand[1], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_PN8 + ((word >> 5) & 7u)),
                0u, (word >> 8) & 3u,
                CDISASM_OPERAND_ACCESS_READ);
    }
    if (identity.kind == ARM_SVE_COUNTER_MASK_PEXT_PAIR) {
        unsigned first = word & 15u;

        return instruction->operand_count == 2u
            && arm_exact_predicate_pair_operand(
                &instruction->operand[0], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_P0 + first),
                (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0
                    + ((first + 1u) & 15u)), element_size,
                CDISASM_OPERAND_ACCESS_WRITE)
            && arm_exact_predicate_lane_operand(
                &instruction->operand[1], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_PN8 + ((word >> 5) & 7u)),
                0u, (word >> 8) & 1u,
                CDISASM_OPERAND_ACCESS_READ);
    }
    return 0;
}

typedef struct arm_sve_cterm_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
} arm_sve_cterm_identity;

static int arm_sve_cterm_identity_for_word(
    uint32_t word, arm_sve_cterm_identity *identity)
{
    uint32_t fixed = word & UINT32_C(0xffa0fc1f);

    if (fixed == UINT32_C(0x25a02000)) {
        identity->form_id = UINT16_C(2593);
        identity->name_id = CDISASM_ARM_NAME_CTERMEQ;
        return 1;
    }
    if (fixed == UINT32_C(0x25a02010)) {
        identity->form_id = UINT16_C(2594);
        identity->name_id = CDISASM_ARM_NAME_CTERMNE;
        return 1;
    }
    return 0;
}

static int arm_valid_sve_cterm_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_sve_cterm_identity identity;
    uint32_t word = instruction->raw_instruction;
    int wide = (word & UINT32_C(0x00400000)) != 0u;
    unsigned rn = (word >> 5) & 31u;
    unsigned rm = (word >> 16) & 31u;
    cdisasm_arm_reg_id expected_rn = wide
        ? (rn == 31u ? CDISASM_ARM_REG_XZR
                     : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + rn))
        : (rn == 31u ? CDISASM_ARM_REG_WZR
                     : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_W0 + rn));
    cdisasm_arm_reg_id expected_rm = wide
        ? (rm == 31u ? CDISASM_ARM_REG_XZR
                     : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + rm))
        : (rm == 31u ? CDISASM_ARM_REG_WZR
                     : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_W0 + rm));
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_cterm_identity_for_word(word, &identity);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->form_id == UINT16_C(2593)
            || instruction->form_id == UINT16_C(2594));
    int name_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->name_id == CDISASM_ARM_NAME_CTERMEQ
            || instruction->name_id == CDISASM_ARM_NAME_CTERMNE);

    if (!raw_is_family && !form_is_family && !name_is_family) {
        return 1;
    }
    if (!raw_is_family || !form_is_family || !name_is_family) {
        return 0;
    }
    return instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS)
        && instruction->operand_count == 2u
        && arm_exact_register_operand(
            &instruction->operand[0], expected_rn, wide ? 8u : 4u,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_register_operand(
            &instruction->operand[1], expected_rm, wide ? 8u : 4u,
            CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_sve_whilewr_rw_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
} arm_sve_whilewr_rw_identity;

static int arm_sve_whilewr_rw_identity_for_word(
    uint32_t word, arm_sve_whilewr_rw_identity *identity)
{
    uint32_t fixed = word & UINT32_C(0xff20fc10);

    if (fixed == UINT32_C(0x25203000)) {
        identity->form_id = UINT16_C(2595);
        identity->name_id = CDISASM_ARM_NAME_WHILEWR;
        return 1;
    }
    if (fixed == UINT32_C(0x25203010)) {
        identity->form_id = UINT16_C(2596);
        identity->name_id = CDISASM_ARM_NAME_WHILERW;
        return 1;
    }
    return 0;
}

static int arm_valid_sve_whilewr_rw_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_sve_whilewr_rw_identity identity;
    uint32_t word = instruction->raw_instruction;
    uint8_t element_size = (uint8_t)(UINT8_C(1) << ((word >> 22) & 3u));
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_whilewr_rw_identity_for_word(word, &identity);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->form_id == UINT16_C(2595)
            || instruction->form_id == UINT16_C(2596));
    int name_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (instruction->name_id == CDISASM_ARM_NAME_WHILEWR
            || instruction->name_id == CDISASM_ARM_NAME_WHILERW);

    if (!raw_is_family && !form_is_family && !name_is_family) {
        return 1;
    }
    if (!raw_is_family || !form_is_family || !name_is_family) {
        return 0;
    }
    return instruction->form_id == identity.form_id
        && instruction->name_id == identity.name_id
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
                | CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS)
        && instruction->operand_count == 3u
        && arm_exact_predicate_operand(
            &instruction->operand[0], (cdisasm_arm_reg_id)(
                CDISASM_ARM_REG_P0 + (word & 15u)), element_size,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
            CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_register_operand(
            &instruction->operand[1], ((word >> 5) & 31u) == 31u
                ? CDISASM_ARM_REG_XZR
                : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0
                    + ((word >> 5) & 31u)),
            8u, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_register_operand(
            &instruction->operand[2], ((word >> 16) & 31u) == 31u
                ? CDISASM_ARM_REG_XZR
                : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0
                    + ((word >> 16) & 31u)),
            8u, CDISASM_OPERAND_ACCESS_READ);
}

static int arm_exact_immediate_operand(
    const cdisasm_arm_operand *operand, uint64_t value)
{
    return operand->type == CDISASM_OPERAND_IMMEDIATE
        && operand->imm == value && operand->size == 1u
        && operand->flags == CDISASM_OPERAND_FLAG_NONE
        && operand->access == CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sve_saturating_count_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_sve_saturating_count_identity identity;
    unsigned encoded = instruction->raw_instruction & 31u;
    unsigned pattern_index;
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_saturating_count_identity_for_word(
            instruction->raw_instruction, &identity);
    int form_is_family = arm_is_sve_saturating_count_form(instruction);

    if (!raw_is_family && !form_is_family) {
        return 1;
    }
    if (!raw_is_family || !form_is_family
        || instruction->form_id != identity.form_id
        || instruction->name_id != identity.name_id
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->instruction_flags
            != CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        || instruction->operand_count
            != (identity.destination_kind == ARM_SVE_COUNT_X_W ? 4u : 3u)) {
        return 0;
    }
    if (identity.destination_kind == ARM_SVE_COUNT_VECTOR) {
        if (!arm_exact_scalable_operand(
                &instruction->operand[0],
                (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + encoded),
                identity.element_size,
                CDISASM_OPERAND_ACCESS_READ_WRITE)) {
            return 0;
        }
    } else if (identity.destination_kind == ARM_SVE_COUNT_W) {
        if (!arm_exact_register_operand(
                &instruction->operand[0], encoded == 31u
                    ? CDISASM_ARM_REG_WZR
                    : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_W0 + encoded),
                4u, CDISASM_OPERAND_ACCESS_READ_WRITE)) {
            return 0;
        }
    } else if (!arm_exact_register_operand(
            &instruction->operand[0], encoded == 31u
                ? CDISASM_ARM_REG_XZR
                : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + encoded),
            8u, identity.destination_kind == ARM_SVE_COUNT_X_W
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ_WRITE)) {
        return 0;
    }
    pattern_index = identity.destination_kind == ARM_SVE_COUNT_X_W ? 2u : 1u;
    if (identity.destination_kind == ARM_SVE_COUNT_X_W
        && !arm_exact_register_operand(
            &instruction->operand[1], encoded == 31u
                ? CDISASM_ARM_REG_WZR
                : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_W0 + encoded),
            4u, CDISASM_OPERAND_ACCESS_READ)) {
        return 0;
    }
    return arm_exact_immediate_operand(
            &instruction->operand[pattern_index],
            (instruction->raw_instruction >> 5) & UINT32_C(31))
        && arm_exact_immediate_operand(
            &instruction->operand[pattern_index + 1u],
            ((instruction->raw_instruction >> 16) & UINT32_C(15)) + 1u);
}

enum arm_sve_predicate_count_kind {
    ARM_SVE_PCOUNT_CNTP = 0,
    ARM_SVE_PCOUNT_FIRST_LAST,
    ARM_SVE_PCOUNT_CNTP_COUNTER,
    ARM_SVE_PCOUNT_VECTOR,
    ARM_SVE_PCOUNT_X,
    ARM_SVE_PCOUNT_W,
    ARM_SVE_PCOUNT_X_W
};

typedef struct arm_sve_predicate_count_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    uint8_t kind;
} arm_sve_predicate_count_identity;

static int arm_sve_predicate_count_identity_for_word(
    uint32_t word, arm_sve_predicate_count_identity *identity)
{
    static const uint32_t values[16] = {
        UINT32_C(0x25288000), UINT32_C(0x252a8000),
        UINT32_C(0x25298000), UINT32_C(0x252b8000),
        UINT32_C(0x252c8000), UINT32_C(0x252d8000),
        UINT32_C(0x25288800), UINT32_C(0x25298800),
        UINT32_C(0x252a8800), UINT32_C(0x252b8800),
        UINT32_C(0x25288c00), UINT32_C(0x252a8c00),
        UINT32_C(0x25298c00), UINT32_C(0x252b8c00),
        UINT32_C(0x252c8800), UINT32_C(0x252d8800)
    };
    static const cdisasm_arm_name_id names[16] = {
        CDISASM_ARM_NAME_SQINCP, CDISASM_ARM_NAME_SQDECP,
        CDISASM_ARM_NAME_UQINCP, CDISASM_ARM_NAME_UQDECP,
        CDISASM_ARM_NAME_INCP, CDISASM_ARM_NAME_DECP,
        CDISASM_ARM_NAME_SQINCP, CDISASM_ARM_NAME_UQINCP,
        CDISASM_ARM_NAME_SQDECP, CDISASM_ARM_NAME_UQDECP,
        CDISASM_ARM_NAME_SQINCP, CDISASM_ARM_NAME_SQDECP,
        CDISASM_ARM_NAME_UQINCP, CDISASM_ARM_NAME_UQDECP,
        CDISASM_ARM_NAME_INCP, CDISASM_ARM_NAME_DECP
    };
    static const uint8_t kinds[16] = {
        ARM_SVE_PCOUNT_VECTOR, ARM_SVE_PCOUNT_VECTOR,
        ARM_SVE_PCOUNT_VECTOR, ARM_SVE_PCOUNT_VECTOR,
        ARM_SVE_PCOUNT_VECTOR, ARM_SVE_PCOUNT_VECTOR,
        ARM_SVE_PCOUNT_X_W, ARM_SVE_PCOUNT_W,
        ARM_SVE_PCOUNT_X_W, ARM_SVE_PCOUNT_W,
        ARM_SVE_PCOUNT_X, ARM_SVE_PCOUNT_X,
        ARM_SVE_PCOUNT_X, ARM_SVE_PCOUNT_X,
        ARM_SVE_PCOUNT_X, ARM_SVE_PCOUNT_X
    };
    uint32_t fixed;
    unsigned index;

    if ((word & UINT32_C(0xff3fc200)) == UINT32_C(0x25208000)) {
        identity->form_id = UINT16_C(2597);
        identity->name_id = CDISASM_ARM_NAME_CNTP;
        identity->kind = ARM_SVE_PCOUNT_CNTP;
        return 1;
    }
    if ((word & UINT32_C(0xff3fc200)) == UINT32_C(0x25218000)
        || (word & UINT32_C(0xff3fc200)) == UINT32_C(0x25228000)) {
        int last = (word & UINT32_C(0x00010000)) == 0u;

        identity->form_id = last ? UINT16_C(2599) : UINT16_C(2598);
        identity->name_id = last
            ? CDISASM_ARM_NAME_LASTP : CDISASM_ARM_NAME_FIRSTP;
        identity->kind = ARM_SVE_PCOUNT_FIRST_LAST;
        return 1;
    }
    if ((word & UINT32_C(0xff3ffa00)) == UINT32_C(0x25208200)) {
        identity->form_id = UINT16_C(2600);
        identity->name_id = CDISASM_ARM_NAME_CNTP;
        identity->kind = ARM_SVE_PCOUNT_CNTP_COUNTER;
        return 1;
    }
    fixed = word & UINT32_C(0xff3ffe00);
    for (index = 0u; index < 16u; ++index) {
        if (fixed == values[index]) {
            if (kinds[index] == ARM_SVE_PCOUNT_VECTOR
                && ((word >> 22) & 3u) == 0u) {
                return 0;
            }
            identity->form_id = (cdisasm_arm_form_id)(UINT16_C(2601)
                + index);
            identity->name_id = names[index];
            identity->kind = kinds[index];
            return 1;
        }
    }
    return 0;
}

static int arm_is_sve_predicate_count_form(
    const cdisasm_arm_instruction *instruction)
{
    return instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id >= UINT16_C(2597)
        && instruction->form_id <= UINT16_C(2616);
}

static int arm_valid_sve_predicate_count_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_sve_predicate_count_identity identity;
    unsigned encoded = instruction->raw_instruction & 31u;
    unsigned predicate = (instruction->raw_instruction >> 5) & 15u;
    uint8_t element_size = (uint8_t)(UINT8_C(1)
        << ((instruction->raw_instruction >> 22) & 3u));
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sve_predicate_count_identity_for_word(
            instruction->raw_instruction, &identity);
    int form_is_family = arm_is_sve_predicate_count_form(instruction);
    uint32_t expected_flags;

    if (!raw_is_family && !form_is_family) {
        return 1;
    }
    if (!raw_is_family || !form_is_family) {
        return 0;
    }
    expected_flags = CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        | (identity.kind == ARM_SVE_PCOUNT_CNTP
                || identity.kind == ARM_SVE_PCOUNT_FIRST_LAST
            ? CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED : 0u);
    if (instruction->form_id != identity.form_id
        || instruction->name_id != identity.name_id
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->instruction_flags != expected_flags) {
        return 0;
    }
    if (identity.kind == ARM_SVE_PCOUNT_CNTP
        || identity.kind == ARM_SVE_PCOUNT_FIRST_LAST) {
        return instruction->operand_count == 3u
            && arm_exact_register_operand(
                &instruction->operand[0], encoded == 31u
                    ? CDISASM_ARM_REG_XZR
                    : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + encoded),
                8u, CDISASM_OPERAND_ACCESS_WRITE)
            && arm_exact_predicate_operand(
                &instruction->operand[1], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_P0
                    + ((instruction->raw_instruction >> 10) & 15u)),
                element_size, CDISASM_OPERAND_FLAG_NONE,
                CDISASM_OPERAND_ACCESS_READ)
            && arm_exact_predicate_operand(
                &instruction->operand[2], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_P0 + predicate), element_size,
                CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
                CDISASM_OPERAND_ACCESS_READ);
    }
    if (identity.kind == ARM_SVE_PCOUNT_CNTP_COUNTER) {
        return instruction->operand_count == 3u
            && arm_exact_register_operand(
                &instruction->operand[0], encoded == 31u
                    ? CDISASM_ARM_REG_XZR
                    : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + encoded),
                8u, CDISASM_OPERAND_ACCESS_WRITE)
            && arm_exact_predicate_operand(
                &instruction->operand[1], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_PN0 + predicate), element_size,
                CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
                CDISASM_OPERAND_ACCESS_READ)
            && arm_exact_immediate_operand(
                &instruction->operand[2],
                (instruction->raw_instruction
                    & UINT32_C(0x00000400)) != 0u ? 4u : 2u);
    }
    if (identity.kind == ARM_SVE_PCOUNT_VECTOR) {
        if (instruction->operand_count != 2u
            || !arm_exact_scalable_operand(
                &instruction->operand[0], (cdisasm_arm_reg_id)(
                    CDISASM_ARM_REG_Z0 + encoded), element_size,
                CDISASM_OPERAND_ACCESS_READ_WRITE)) {
            return 0;
        }
    } else if (identity.kind == ARM_SVE_PCOUNT_W) {
        if (instruction->operand_count != 2u
            || !arm_exact_register_operand(
                &instruction->operand[0], encoded == 31u
                    ? CDISASM_ARM_REG_WZR
                    : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_W0 + encoded),
                4u, CDISASM_OPERAND_ACCESS_READ_WRITE)) {
            return 0;
        }
    } else if (identity.kind == ARM_SVE_PCOUNT_X_W) {
        if (instruction->operand_count != 3u
            || !arm_exact_register_operand(
                &instruction->operand[0], encoded == 31u
                    ? CDISASM_ARM_REG_XZR
                    : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + encoded),
                8u, CDISASM_OPERAND_ACCESS_WRITE)
            || !arm_exact_register_operand(
                &instruction->operand[2], encoded == 31u
                    ? CDISASM_ARM_REG_WZR
                    : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_W0 + encoded),
                4u, CDISASM_OPERAND_ACCESS_READ)) {
            return 0;
        }
    } else if (instruction->operand_count != 2u
        || !arm_exact_register_operand(
            &instruction->operand[0], encoded == 31u
                ? CDISASM_ARM_REG_XZR
                : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + encoded),
            8u, CDISASM_OPERAND_ACCESS_READ_WRITE)) {
        return 0;
    }
    return arm_exact_predicate_operand(
        &instruction->operand[1], (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_P0 + predicate), element_size,
        CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED,
        CDISASM_OPERAND_ACCESS_READ);
}

static int arm_is_predicated_mova_form(cdisasm_arm_form_id form_id)
{
    return (form_id >= UINT16_C(3862) && form_id <= UINT16_C(3866))
        || (form_id >= UINT16_C(3877) && form_id <= UINT16_C(3881));
}

static int arm_is_sme2_multi_mova_form(cdisasm_arm_form_id form_id)
{
    return (form_id >= UINT16_C(3867) && form_id <= UINT16_C(3876))
        || (form_id >= UINT16_C(3882) && form_id <= UINT16_C(3891));
}

static int arm_is_sme2p1_movaz_form(cdisasm_arm_form_id form_id)
{
    return form_id >= UINT16_C(3892) && form_id <= UINT16_C(3906);
}

static int arm_predicated_mova_identity(
    uint32_t word,
    int *extract,
    unsigned *element_log2,
    cdisasm_arm_form_id *form_id)
{
    unsigned size;
    unsigned quadword;

    if ((word & UINT32_C(0xff3e0010)) == UINT32_C(0xc0000000)) {
        *extract = 0;
    } else if ((word & UINT32_C(0xff3e0200))
        == UINT32_C(0xc0020000)) {
        *extract = 1;
    } else {
        return 0;
    }
    size = (word >> 22) & 3u;
    quadword = (word >> 16) & 1u;
    if (quadword != 0u && size != 3u) {
        return 0;
    }
    *element_log2 = quadword != 0u ? 4u : size;
    *form_id = (cdisasm_arm_form_id)(
        (*extract != 0 ? UINT16_C(3877) : UINT16_C(3862))
            + *element_log2);
    return 1;
}

static int arm_valid_predicated_mova_schema(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_reg_id tile_bases[5] = {
        CDISASM_ARM_REG_ZAB0, CDISASM_ARM_REG_ZAH0,
        CDISASM_ARM_REG_ZAS0, CDISASM_ARM_REG_ZAD0,
        CDISASM_ARM_REG_ZAQ0
    };
    const cdisasm_arm_operand *destination;
    const cdisasm_arm_operand *predicate;
    const cdisasm_arm_operand *source;
    const cdisasm_arm_operand *tile;
    const cdisasm_arm_operand *zreg;
    cdisasm_arm_form_id expected_form = CDISASM_ARM_FORM_NONE;
    cdisasm_arm_reg_id expected_tile;
    unsigned element_log2 = 0u;
    unsigned offset_bits;
    unsigned encoded_slice;
    unsigned tile_number;
    unsigned slice_offset;
    unsigned zencoded;
    uint8_t element_size;
    uint8_t tile_flags;
    int extract = 0;
    int raw_is_mova;
    int form_is_mova = arm_is_predicated_mova_form(instruction->form_id);
    int operand_is_mova_slice = 0;
    size_t index;

    raw_is_mova = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_predicated_mova_identity(
            instruction->raw_instruction, &extract, &element_log2,
            &expected_form);
    for (index = 0u; index < instruction->operand_count; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];

        if (operand->type == CDISASM_ARM_OPERAND_TILE
            && operand->reg >= CDISASM_ARM_REG_ZAB0
            && operand->reg <= CDISASM_ARM_REG_ZAQ15
            && operand->base_reg >= CDISASM_ARM_REG_W12
            && operand->base_reg <= CDISASM_ARM_REG_W15
            && operand->register_list == 0u) {
            operand_is_mova_slice = instruction->name_id
                == CDISASM_ARM_NAME_MOV;
        }
    }
    if (!raw_is_mova && !form_is_mova && !operand_is_mova_slice) {
        return 1;
    }
    if (!raw_is_mova || !form_is_mova
        || instruction->name_id != CDISASM_ARM_NAME_MOV
        || instruction->form_id != expected_form
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->instruction_flags
            != (CDISASM_ARM_INSTRUCTION_FLAG_SME
                | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
                | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        || instruction->operand_count != 3u) {
        return 0;
    }

    element_size = (uint8_t)(1u << element_log2);
    offset_bits = 4u - element_log2;
    encoded_slice = extract != 0
        ? (instruction->raw_instruction >> 5) & 15u
        : instruction->raw_instruction & 15u;
    tile_number = encoded_slice >> offset_bits;
    slice_offset = offset_bits == 0u ? 0u
        : encoded_slice & ((1u << offset_bits) - 1u);
    zencoded = extract != 0
        ? instruction->raw_instruction & 31u
        : (instruction->raw_instruction >> 5) & 31u;
    expected_tile = (cdisasm_arm_reg_id)(
        tile_bases[element_log2] + tile_number);
    tile_flags = (instruction->raw_instruction & UINT32_C(0x00008000))
            != 0u
        ? CDISASM_ARM_OPERAND_FLAG_TILE_VERTICAL
        : CDISASM_OPERAND_FLAG_NONE;
    destination = &instruction->operand[0];
    predicate = &instruction->operand[1];
    source = &instruction->operand[2];
    tile = extract != 0 ? source : destination;
    zreg = extract != 0 ? destination : source;

    return tile->type == CDISASM_ARM_OPERAND_TILE
        && tile->reg == expected_tile
        && tile->base_reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_W12
                + ((instruction->raw_instruction >> 13) & 3u))
        && tile->index_reg == CDISASM_ARM_REG_NONE
        && tile->register_list == 0u && tile->address == 0u
        && tile->imm == slice_offset && tile->size == 0u
        && tile->flags == tile_flags
        && tile->shift_type == CDISASM_ARM_SHIFT_NONE
        && tile->shift_amount == 0u
        && tile->extend_type == element_size && tile->scale == 0u
        && tile->access == (extract != 0
            ? CDISASM_OPERAND_ACCESS_READ
            : CDISASM_OPERAND_ACCESS_READ_WRITE)
        && predicate->type == CDISASM_ARM_OPERAND_PREDICATE
        && predicate->reg == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0
            + ((instruction->raw_instruction >> 10) & 7u))
        && predicate->base_reg == CDISASM_ARM_REG_NONE
        && predicate->index_reg == CDISASM_ARM_REG_NONE
        && predicate->register_list == 0u && predicate->address == 0u
        && predicate->imm == 0u && predicate->size == 0u
        && predicate->flags
            == CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE
        && predicate->shift_type == CDISASM_ARM_SHIFT_NONE
        && predicate->shift_amount == 0u
        && predicate->extend_type == element_size
        && predicate->scale == 0u
        && predicate->access == CDISASM_OPERAND_ACCESS_READ
        && zreg->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER
        && zreg->reg == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zencoded)
        && zreg->base_reg == CDISASM_ARM_REG_NONE
        && zreg->index_reg == CDISASM_ARM_REG_NONE
        && zreg->register_list == 0u && zreg->address == 0u
        && zreg->imm == 0u && zreg->size == 0u
        && zreg->flags == CDISASM_OPERAND_FLAG_NONE
        && zreg->shift_type == CDISASM_ARM_SHIFT_NONE
        && zreg->shift_amount == 0u
        && zreg->extend_type == element_size && zreg->scale == 0u
        && zreg->access == (extract != 0
            ? CDISASM_OPERAND_ACCESS_READ_WRITE
            : CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_sme2_multi_mova_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_reg_id tile_reg;
    cdisasm_arm_reg_id tile_base_reg;
    cdisasm_arm_reg_id list_reg;
    uint8_t element_size;
    uint8_t tile_flags;
    uint8_t count;
    uint8_t extract;
    uint8_t tile_offset;
} arm_sme2_multi_mova_identity;

static int arm_sme2_multi_mova_identity_for_word(
    uint32_t word,
    arm_sme2_multi_mova_identity *identity)
{
    static const cdisasm_arm_reg_id tile_bases[4] = {
        CDISASM_ARM_REG_ZAB0, CDISASM_ARM_REG_ZAH0,
        CDISASM_ARM_REG_ZAS0, CDISASM_ARM_REG_ZAD0
    };
    unsigned size = (word >> 22) & 3u;
    unsigned count;
    unsigned encoded_list;
    unsigned encoded_slice;
    unsigned count_log2;
    unsigned group_offset_bits;
    int whole_array = 0;
    int extract = 0;

    if ((word & UINT32_C(0xff3f1c38)) == UINT32_C(0xc0040000)) {
        identity->form_id = (cdisasm_arm_form_id)(UINT16_C(3867) + size);
        count = 2u;
    } else if ((word & UINT32_C(0xff3f1c78))
            == UINT32_C(0xc0040400)) {
        if (size != 3u && (word & UINT32_C(4)) != 0u) {
            return 0;
        }
        identity->form_id = (cdisasm_arm_form_id)(UINT16_C(3871) + size);
        count = 4u;
    } else if ((word & UINT32_C(0xffff9c38))
            == UINT32_C(0xc0040800)) {
        identity->form_id = UINT16_C(3875);
        count = 2u;
        whole_array = 1;
    } else if ((word & UINT32_C(0xffff9c78))
            == UINT32_C(0xc0040c00)) {
        identity->form_id = UINT16_C(3876);
        count = 4u;
        whole_array = 1;
    } else if ((word & UINT32_C(0xff3f1f01))
            == UINT32_C(0xc0060000)) {
        identity->form_id = (cdisasm_arm_form_id)(UINT16_C(3882) + size);
        count = 2u;
        extract = 1;
    } else if ((word & UINT32_C(0xff3f1f03))
            == UINT32_C(0xc0060400)) {
        if (size != 3u && (word & UINT32_C(0x80)) != 0u) {
            return 0;
        }
        identity->form_id = (cdisasm_arm_form_id)(UINT16_C(3886) + size);
        count = 4u;
        extract = 1;
    } else if ((word & UINT32_C(0xffff9f01))
            == UINT32_C(0xc0060800)) {
        identity->form_id = UINT16_C(3890);
        count = 2u;
        whole_array = 1;
        extract = 1;
    } else if ((word & UINT32_C(0xffff9f03))
            == UINT32_C(0xc0060c00)) {
        identity->form_id = UINT16_C(3891);
        count = 4u;
        whole_array = 1;
        extract = 1;
    } else {
        return 0;
    }

    encoded_list = extract
        ? (count == 4u ? (word >> 2) & 7u : (word >> 1) & 15u)
        : (count == 4u ? (word >> 7) & 7u : (word >> 6) & 15u);
    encoded_slice = extract ? (word >> 5) & 7u : word & 7u;
    identity->list_reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + encoded_list * count);
    identity->element_size = whole_array
        ? 8u : (uint8_t)(UINT32_C(1) << size);
    identity->count = (uint8_t)count;
    identity->extract = (uint8_t)extract;
    if (whole_array) {
        identity->tile_reg = CDISASM_ARM_REG_ZA;
        identity->tile_base_reg = (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_W8 + ((word >> 13) & 3u));
        identity->tile_offset = (uint8_t)encoded_slice;
        identity->tile_flags = CDISASM_OPERAND_FLAG_NONE;
        return 1;
    }

    count_log2 = count == 4u ? 2u : 1u;
    group_offset_bits = 4u > size + count_log2
        ? 4u - size - count_log2 : 0u;
    identity->tile_reg = (cdisasm_arm_reg_id)(
        tile_bases[size] + (encoded_slice >> group_offset_bits));
    identity->tile_base_reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_W12 + ((word >> 13) & 3u));
    identity->tile_offset = group_offset_bits == 0u ? 0u
        : (uint8_t)((encoded_slice
            & ((1u << group_offset_bits) - 1u)) * count);
    identity->tile_flags = (word & UINT32_C(0x00008000)) != 0u
        ? CDISASM_ARM_OPERAND_FLAG_TILE_VERTICAL
        : CDISASM_OPERAND_FLAG_NONE;
    return 1;
}

static int arm_valid_sme2_multi_mova_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_sme2_multi_mova_identity identity;
    const cdisasm_arm_operand *tile;
    const cdisasm_arm_operand *list;
    int raw_is_mova = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sme2_multi_mova_identity_for_word(
            instruction->raw_instruction, &identity);
    int form_is_mova = arm_is_sme2_multi_mova_form(instruction->form_id);
    int operand_is_mova = 0;
    size_t index;

    for (index = 0u; index < instruction->operand_count; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];

        if (operand->type == CDISASM_ARM_OPERAND_TILE
            && (operand->register_list == 2u
                || operand->register_list == 4u)) {
            operand_is_mova = instruction->name_id == CDISASM_ARM_NAME_MOV;
        }
    }
    if (!raw_is_mova && !form_is_mova && !operand_is_mova) {
        return 1;
    }
    if (!raw_is_mova || !form_is_mova
        || instruction->name_id != CDISASM_ARM_NAME_MOV
        || instruction->form_id != identity.form_id
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->instruction_flags
            != (CDISASM_ARM_INSTRUCTION_FLAG_SME
                | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
                | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR)
        || instruction->operand_count != 2u) {
        return 0;
    }
    tile = &instruction->operand[identity.extract != 0u ? 1u : 0u];
    list = &instruction->operand[identity.extract != 0u ? 0u : 1u];
    return tile->type == CDISASM_ARM_OPERAND_TILE
        && tile->reg == identity.tile_reg
        && tile->base_reg == identity.tile_base_reg
        && tile->index_reg == CDISASM_ARM_REG_NONE
        && tile->register_list == identity.count
        && tile->address == 0u && tile->imm == identity.tile_offset
        && tile->size == 0u && tile->flags == identity.tile_flags
        && tile->shift_type == CDISASM_ARM_SHIFT_NONE
        && tile->shift_amount == 0u
        && tile->extend_type == identity.element_size
        && tile->scale == 0u
        && tile->access == (identity.extract != 0u
            ? CDISASM_OPERAND_ACCESS_READ
            : CDISASM_OPERAND_ACCESS_WRITE)
        && list->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
        && list->reg == identity.list_reg
        && list->base_reg == CDISASM_ARM_REG_NONE
        && list->index_reg == CDISASM_ARM_REG_NONE
        && list->register_list
            == (uint16_t)(UINT16_C(0x0100) | identity.count)
        && list->address == 0u && list->imm == 0u && list->size == 0u
        && list->flags == CDISASM_OPERAND_FLAG_NONE
        && list->shift_type == CDISASM_ARM_SHIFT_NONE
        && list->shift_amount == 0u
        && list->extend_type == identity.element_size
        && list->scale == 0u
        && list->access == (identity.extract != 0u
            ? CDISASM_OPERAND_ACCESS_WRITE
            : CDISASM_OPERAND_ACCESS_READ);
}

typedef struct arm_sme2p1_movaz_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_reg_id tile_reg;
    cdisasm_arm_reg_id tile_base_reg;
    cdisasm_arm_reg_id destination_reg;
    uint8_t element_size;
    uint8_t tile_flags;
    uint8_t count;
    uint8_t tile_offset;
} arm_sme2p1_movaz_identity;

static int arm_sme2p1_movaz_identity_for_word(
    uint32_t word,
    arm_sme2p1_movaz_identity *identity)
{
    static const cdisasm_arm_reg_id tile_bases[5] = {
        CDISASM_ARM_REG_ZAB0, CDISASM_ARM_REG_ZAH0,
        CDISASM_ARM_REG_ZAS0, CDISASM_ARM_REG_ZAD0,
        CDISASM_ARM_REG_ZAQ0
    };
    unsigned size = (word >> 22) & 3u;
    unsigned element_log2 = size;
    unsigned encoded_destination;
    unsigned encoded_slice;
    unsigned count_log2;
    unsigned group_offset_bits;
    unsigned count;
    int whole_array = 0;

    if ((word & UINT32_C(0xff3e1e00)) == UINT32_C(0xc0020200)) {
        if ((word & UINT32_C(0x00010000)) != 0u) {
            if (size != 3u) {
                return 0;
            }
            element_log2 = 4u;
        }
        identity->form_id = (cdisasm_arm_form_id)(
            UINT16_C(3892) + element_log2);
        count = 1u;
        encoded_destination = word & 31u;
        encoded_slice = (word >> 5) & 15u;
    } else if ((word & UINT32_C(0xff3f1f01))
            == UINT32_C(0xc0060200)) {
        identity->form_id = (cdisasm_arm_form_id)(
            UINT16_C(3897) + size);
        count = 2u;
        encoded_destination = (word >> 1) & 15u;
        encoded_slice = (word >> 5) & 7u;
    } else if ((word & UINT32_C(0xff3f1f03))
            == UINT32_C(0xc0060600)) {
        if (size != 3u && (word & UINT32_C(0x80)) != 0u) {
            return 0;
        }
        identity->form_id = (cdisasm_arm_form_id)(
            UINT16_C(3901) + size);
        count = 4u;
        encoded_destination = (word >> 2) & 7u;
        encoded_slice = (word >> 5) & 7u;
    } else if ((word & UINT32_C(0xffff9f01))
            == UINT32_C(0xc0060a00)) {
        identity->form_id = UINT16_C(3905);
        count = 2u;
        encoded_destination = (word >> 1) & 15u;
        encoded_slice = (word >> 5) & 7u;
        element_log2 = 3u;
        whole_array = 1;
    } else if ((word & UINT32_C(0xffff9f03))
            == UINT32_C(0xc0060e00)) {
        identity->form_id = UINT16_C(3906);
        count = 4u;
        encoded_destination = (word >> 2) & 7u;
        encoded_slice = (word >> 5) & 7u;
        element_log2 = 3u;
        whole_array = 1;
    } else {
        return 0;
    }

    identity->destination_reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_Z0 + encoded_destination * count);
    identity->element_size = (uint8_t)(UINT32_C(1) << element_log2);
    identity->count = (uint8_t)count;
    if (whole_array) {
        identity->tile_reg = CDISASM_ARM_REG_ZA;
        identity->tile_base_reg = (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_W8 + ((word >> 13) & 3u));
        identity->tile_offset = (uint8_t)encoded_slice;
        identity->tile_flags = CDISASM_OPERAND_FLAG_NONE;
        return 1;
    }

    count_log2 = count == 4u ? 2u : count == 2u ? 1u : 0u;
    group_offset_bits = 4u > element_log2 + count_log2
        ? 4u - element_log2 - count_log2 : 0u;
    identity->tile_reg = (cdisasm_arm_reg_id)(
        tile_bases[element_log2]
            + (encoded_slice >> group_offset_bits));
    identity->tile_base_reg = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_W12 + ((word >> 13) & 3u));
    identity->tile_offset = group_offset_bits == 0u ? 0u
        : (uint8_t)((encoded_slice
            & ((1u << group_offset_bits) - 1u)) * count);
    identity->tile_flags = (word & UINT32_C(0x00008000)) != 0u
        ? CDISASM_ARM_OPERAND_FLAG_TILE_VERTICAL
        : CDISASM_OPERAND_FLAG_NONE;
    return 1;
}

static int arm_valid_sme2p1_movaz_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_sme2p1_movaz_identity identity;
    const cdisasm_arm_operand *destination;
    const cdisasm_arm_operand *tile;
    int raw_is_movaz = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_sme2p1_movaz_identity_for_word(
            instruction->raw_instruction, &identity);
    int form_is_movaz = arm_is_sme2p1_movaz_form(instruction->form_id);
    int operand_is_movaz = instruction->name_id == CDISASM_ARM_NAME_MOVAZ;

    if (!raw_is_movaz && !form_is_movaz && !operand_is_movaz) {
        return 1;
    }
    if (!raw_is_movaz || !form_is_movaz || !operand_is_movaz
        || instruction->form_id != identity.form_id
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->instruction_flags
            != (CDISASM_ARM_INSTRUCTION_FLAG_SME
                | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
                | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR)
        || instruction->operand_count != 2u) {
        return 0;
    }

    destination = &instruction->operand[0];
    tile = &instruction->operand[1];
    return destination->type == (identity.count == 1u
            ? CDISASM_ARM_OPERAND_SCALABLE_REGISTER
            : CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST)
        && destination->reg == identity.destination_reg
        && destination->base_reg == CDISASM_ARM_REG_NONE
        && destination->index_reg == CDISASM_ARM_REG_NONE
        && destination->register_list == (identity.count == 1u ? 0u
            : (uint16_t)(UINT16_C(0x0100) | identity.count))
        && destination->address == 0u && destination->imm == 0u
        && destination->size == 0u
        && destination->flags == CDISASM_OPERAND_FLAG_NONE
        && destination->shift_type == CDISASM_ARM_SHIFT_NONE
        && destination->shift_amount == 0u
        && destination->extend_type == identity.element_size
        && destination->scale == 0u
        && destination->access == CDISASM_OPERAND_ACCESS_WRITE
        && tile->type == CDISASM_ARM_OPERAND_TILE
        && tile->reg == identity.tile_reg
        && tile->base_reg == identity.tile_base_reg
        && tile->index_reg == CDISASM_ARM_REG_NONE
        && tile->register_list == (identity.count == 1u
            ? 0u : identity.count)
        && tile->address == 0u && tile->imm == identity.tile_offset
        && tile->size == 0u && tile->flags == identity.tile_flags
        && tile->shift_type == CDISASM_ARM_SHIFT_NONE
        && tile->shift_amount == 0u
        && tile->extend_type == identity.element_size
        && tile->scale == 0u
        && tile->access == CDISASM_OPERAND_ACCESS_READ;
}

static int arm_za_contiguous_identity(
    uint32_t word,
    unsigned *element_log2,
    int *load,
    cdisasm_arm_name_id *name_id,
    cdisasm_arm_form_id *form_id)
{
    static const uint32_t values[10] = {
        UINT32_C(0xe0000000), UINT32_C(0xe0200000),
        UINT32_C(0xe0400000), UINT32_C(0xe0600000),
        UINT32_C(0xe0800000), UINT32_C(0xe0a00000),
        UINT32_C(0xe0c00000), UINT32_C(0xe0e00000),
        UINT32_C(0xe1c00000), UINT32_C(0xe1e00000)
    };
    static const cdisasm_arm_name_id names[10] = {
        CDISASM_ARM_NAME_LD1B, CDISASM_ARM_NAME_ST1B,
        CDISASM_ARM_NAME_LD1H, CDISASM_ARM_NAME_ST1H,
        CDISASM_ARM_NAME_LD1W, CDISASM_ARM_NAME_ST1W,
        CDISASM_ARM_NAME_LD1D, CDISASM_ARM_NAME_ST1D,
        CDISASM_ARM_NAME_LD1Q, CDISASM_ARM_NAME_ST1Q
    };
    static const cdisasm_arm_form_id forms[10] = {
        UINT16_C(4373), UINT16_C(4377),
        UINT16_C(4374), UINT16_C(4378),
        UINT16_C(4375), UINT16_C(4379),
        UINT16_C(4376), UINT16_C(4380),
        UINT16_C(4385), UINT16_C(4386)
    };
    uint32_t fixed = word & UINT32_C(0xffe00010);
    unsigned index;

    for (index = 0u; index < 10u; ++index) {
        if (fixed == values[index]) {
            *element_log2 = index / 2u;
            *load = (index & 1u) == 0u;
            *name_id = names[index];
            *form_id = forms[index];
            return 1;
        }
    }
    return 0;
}

static int arm_valid_za_contiguous_schema(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_reg_id tile_bases[5] = {
        CDISASM_ARM_REG_ZAB0, CDISASM_ARM_REG_ZAH0,
        CDISASM_ARM_REG_ZAS0, CDISASM_ARM_REG_ZAD0,
        CDISASM_ARM_REG_ZAQ0
    };
    const cdisasm_arm_operand *tile;
    const cdisasm_arm_operand *predicate;
    const cdisasm_arm_operand *memory;
    cdisasm_arm_name_id expected_name = CDISASM_ARM_NAME_NONE;
    cdisasm_arm_form_id expected_form = CDISASM_ARM_FORM_NONE;
    cdisasm_arm_reg_id expected_tile;
    cdisasm_arm_reg_id expected_base;
    cdisasm_arm_reg_id expected_index;
    unsigned element_log2 = 0u;
    unsigned offset_bits;
    unsigned tile_number;
    unsigned slice_offset;
    unsigned rm;
    uint8_t element_size;
    uint8_t expected_tile_flags;
    int raw_is_transfer;
    int form_is_transfer;
    int operand_is_slice;
    int load = 0;

    raw_is_transfer = instruction->isa_id == CDISASM_ARM_ISA_A64
        && arm_za_contiguous_identity(
            instruction->raw_instruction, &element_log2, &load,
            &expected_name, &expected_form);
    form_is_transfer = (instruction->form_id >= UINT16_C(4373)
            && instruction->form_id <= UINT16_C(4380))
        || instruction->form_id == UINT16_C(4385)
        || instruction->form_id == UINT16_C(4386);
    operand_is_slice = instruction->operand_count != 0u
        && !arm_is_predicated_mova_form(instruction->form_id)
        && !arm_is_sme2_multi_mova_form(instruction->form_id)
        && instruction->operand[0].type == CDISASM_ARM_OPERAND_TILE
        && instruction->operand[0].reg >= CDISASM_ARM_REG_ZAB0
        && instruction->operand[0].reg <= CDISASM_ARM_REG_ZAQ15
        && instruction->operand[0].base_reg >= CDISASM_ARM_REG_W12
        && instruction->operand[0].base_reg <= CDISASM_ARM_REG_W15;
    if (!raw_is_transfer && !form_is_transfer && !operand_is_slice) {
        return 1;
    }
    if (!raw_is_transfer || !form_is_transfer || !operand_is_slice) {
        return 0;
    }

    element_size = (uint8_t)(1u << element_log2);
    offset_bits = 4u - element_log2;
    tile_number = (instruction->raw_instruction & UINT32_C(15))
        >> offset_bits;
    slice_offset = offset_bits == 0u ? 0u
        : (instruction->raw_instruction & UINT32_C(15))
            & ((1u << offset_bits) - 1u);
    rm = (instruction->raw_instruction >> 16) & 31u;
    expected_tile = (cdisasm_arm_reg_id)(
        tile_bases[element_log2] + tile_number);
    expected_base = ((instruction->raw_instruction >> 5) & 31u) == 31u
        ? CDISASM_ARM_REG_SP
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0
            + ((instruction->raw_instruction >> 5) & 31u));
    expected_index = rm == 31u ? CDISASM_ARM_REG_NONE
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + rm);
    expected_tile_flags =
        (instruction->raw_instruction & UINT32_C(0x00008000)) != 0u
            ? CDISASM_ARM_OPERAND_FLAG_TILE_VERTICAL
            : CDISASM_OPERAND_FLAG_NONE;

    if (instruction->name_id != expected_name
        || instruction->form_id != expected_form
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->instruction_flags
            != (CDISASM_ARM_INSTRUCTION_FLAG_SME
                | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
                | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        || instruction->operand_count != 3u) {
        return 0;
    }
    tile = &instruction->operand[0];
    predicate = &instruction->operand[1];
    memory = &instruction->operand[2];
    return tile->type == CDISASM_ARM_OPERAND_TILE
        && tile->reg == expected_tile
        && tile->base_reg == (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_W12
            + ((instruction->raw_instruction >> 13) & 3u))
        && tile->index_reg == CDISASM_ARM_REG_NONE
        && tile->register_list == 0u && tile->address == 0u
        && tile->imm == slice_offset && tile->size == 0u
        && tile->flags == expected_tile_flags
        && tile->shift_type == CDISASM_ARM_SHIFT_NONE
        && tile->shift_amount == 0u
        && tile->extend_type == element_size && tile->scale == 0u
        && tile->access == (load ? CDISASM_OPERAND_ACCESS_WRITE
                                 : CDISASM_OPERAND_ACCESS_READ)
        && predicate->type == CDISASM_ARM_OPERAND_PREDICATE
        && predicate->reg == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0
            + ((instruction->raw_instruction >> 10) & 7u))
        && predicate->base_reg == CDISASM_ARM_REG_NONE
        && predicate->index_reg == CDISASM_ARM_REG_NONE
        && predicate->register_list == 0u && predicate->address == 0u
        && predicate->imm == 0u && predicate->size == 0u
        && predicate->flags == (load
            ? CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO
            : CDISASM_OPERAND_FLAG_NONE)
        && predicate->shift_type == CDISASM_ARM_SHIFT_NONE
        && predicate->shift_amount == 0u
        && predicate->extend_type == element_size
        && predicate->scale == 0u
        && predicate->access == CDISASM_OPERAND_ACCESS_READ
        && memory->type == CDISASM_OPERAND_MEMORY
        && memory->reg == CDISASM_ARM_REG_NONE
        && memory->base_reg == expected_base
        && memory->index_reg == expected_index
        && memory->register_list == 0u && memory->address == 0u
        && memory->imm == 0u && memory->size == 0u
        && memory->flags == CDISASM_OPERAND_FLAG_NONE
        && memory->shift_type == (rm == 31u || element_log2 == 0u
            ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL)
        && memory->shift_amount == (rm == 31u ? 0u : element_log2)
        && memory->extend_type == CDISASM_ARM_EXTEND_NONE
        && memory->scale == 0u
        && memory->access == (load ? CDISASM_OPERAND_ACCESS_READ
                                   : CDISASM_OPERAND_ACCESS_WRITE);
}

static int arm_valid_za_transfer_schema(
    const cdisasm_arm_instruction *instruction)
{
    const cdisasm_arm_operand *tile;
    const cdisasm_arm_operand *memory;
    cdisasm_operand_access tile_access;
    cdisasm_operand_access memory_access;
    cdisasm_arm_reg_id expected_base;
    cdisasm_arm_reg_id expected_selector;
    uint8_t expected_memory_flags;
    uint64_t expected_offset;
    uint32_t fixed;
    int raw_is_load;
    int raw_is_store;
    int form_is_transfer;
    int operand_is_za_array;
    int is_load;

    fixed = instruction->raw_instruction & UINT32_C(0xffff9c10);
    raw_is_load = instruction->isa_id == CDISASM_ARM_ISA_A64
        && fixed == UINT32_C(0xe1000000);
    raw_is_store = instruction->isa_id == CDISASM_ARM_ISA_A64
        && fixed == UINT32_C(0xe1200000);
    form_is_transfer = instruction->form_id == UINT16_C(4381)
        || instruction->form_id == UINT16_C(4382);
    operand_is_za_array = instruction->operand_count != 0u
        && instruction->operand[0].type == CDISASM_ARM_OPERAND_TILE
        && instruction->operand[0].reg == CDISASM_ARM_REG_ZA
        && (instruction->name_id == CDISASM_ARM_NAME_LDR
            || instruction->name_id == CDISASM_ARM_NAME_STR);
    if (!raw_is_load && !raw_is_store
        && !form_is_transfer && !operand_is_za_array) {
        return 1;
    }
    if ((!raw_is_load && !raw_is_store) || !form_is_transfer
        || !operand_is_za_array) {
        return 0;
    }
    is_load = raw_is_load;
    tile_access = is_load ? CDISASM_OPERAND_ACCESS_WRITE
                          : CDISASM_OPERAND_ACCESS_READ;
    memory_access = is_load ? CDISASM_OPERAND_ACCESS_READ
                            : CDISASM_OPERAND_ACCESS_WRITE;
    expected_selector = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_W12
        + ((instruction->raw_instruction >> 13) & UINT32_C(3)));
    expected_base = ((instruction->raw_instruction >> 5) & UINT32_C(31))
            == UINT32_C(31)
        ? CDISASM_ARM_REG_SP
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0
            + ((instruction->raw_instruction >> 5) & UINT32_C(31)));
    expected_offset = instruction->raw_instruction & UINT32_C(15);
    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || instruction->form_id
            != (is_load ? UINT16_C(4381) : UINT16_C(4382))
        || instruction->name_id
            != (is_load ? CDISASM_ARM_NAME_LDR : CDISASM_ARM_NAME_STR)
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->instruction_flags
            != (CDISASM_ARM_INSTRUCTION_FLAG_SME
                | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
                | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR)
        || instruction->operand_count != 2u) {
        return 0;
    }
    tile = &instruction->operand[0];
    memory = &instruction->operand[1];
    expected_memory_flags = expected_offset == 0u
        ? CDISASM_OPERAND_FLAG_NONE
        : (uint8_t)(CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
            | CDISASM_ARM_OPERAND_FLAG_VL_SCALED);
    return tile->type == CDISASM_ARM_OPERAND_TILE
        && tile->reg == CDISASM_ARM_REG_ZA
        && tile->base_reg == expected_selector
        && tile->imm == expected_offset
        && tile->extend_type == CDISASM_ARM_EXTEND_NONE
        && tile->access == tile_access
        && memory->type == CDISASM_OPERAND_MEMORY
        && memory->base_reg == expected_base
        && memory->index_reg == CDISASM_ARM_REG_NONE
        && memory->imm == expected_offset
        && memory->size == 0u
        && memory->flags == expected_memory_flags
        && memory->access == memory_access;
}

static int arm_is_crc32_name(cdisasm_arm_name_id name_id)
{
    return name_id >= CDISASM_ARM_NAME_CRC32B
        && name_id <= CDISASM_ARM_NAME_CRC32CX;
}

static int arm_is_crc32_form(cdisasm_arm_form_id form_id)
{
    return (form_id >= UINT16_C(98) && form_id <= UINT16_C(103))
        || (form_id >= UINT16_C(2169) && form_id <= UINT16_C(2174))
        || (form_id >= UINT16_C(5582) && form_id <= UINT16_C(5587))
        || form_id == UINT16_C(5602) || form_id == UINT16_C(5603);
}

static int arm_exact_crc32_register(
    const cdisasm_arm_operand *operand,
    cdisasm_arm_reg_id reg,
    uint8_t size,
    cdisasm_operand_access access)
{
    return operand->type == CDISASM_OPERAND_REGISTER
        && operand->reg == reg
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u
        && operand->address == 0u
        && operand->imm == 0u
        && operand->size == size
        && operand->flags == CDISASM_OPERAND_FLAG_NONE
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u
        && operand->extend_type == CDISASM_ARM_EXTEND_NONE
        && operand->scale == 0u
        && operand->access == access;
}

static cdisasm_arm_reg_id arm_crc32_a64_reg(unsigned encoded, int is_64)
{
    if (encoded == 31u) {
        return is_64 ? CDISASM_ARM_REG_XZR : CDISASM_ARM_REG_WZR;
    }
    return (cdisasm_arm_reg_id)(
        (is_64 ? CDISASM_ARM_REG_X0 : CDISASM_ARM_REG_W0) + encoded);
}

static int arm_valid_crc32_schema(
    const cdisasm_arm_instruction *instruction)
{
    static const uint32_t a32_values[6] = {
        UINT32_C(0x01000040), UINT32_C(0x01200040),
        UINT32_C(0x01400040), UINT32_C(0x01000240),
        UINT32_C(0x01200240), UINT32_C(0x01400240)
    };
    static const uint32_t t32_values[6] = {
        UINT32_C(0xfac0f080), UINT32_C(0xfac0f090),
        UINT32_C(0xfac0f0a0), UINT32_C(0xfad0f080),
        UINT32_C(0xfad0f090), UINT32_C(0xfad0f0a0)
    };
    static const cdisasm_arm_name_id names[8] = {
        CDISASM_ARM_NAME_CRC32B, CDISASM_ARM_NAME_CRC32H,
        CDISASM_ARM_NAME_CRC32W, CDISASM_ARM_NAME_CRC32X,
        CDISASM_ARM_NAME_CRC32CB, CDISASM_ARM_NAME_CRC32CH,
        CDISASM_ARM_NAME_CRC32CW, CDISASM_ARM_NAME_CRC32CX
    };
    uint32_t word = instruction->raw_instruction;
    cdisasm_arm_form_id expected_form = CDISASM_ARM_FORM_NONE;
    cdisasm_arm_name_id expected_name = CDISASM_ARM_NAME_NONE;
    cdisasm_arm_reg_id expected_rd;
    cdisasm_arm_reg_id expected_rn;
    cdisasm_arm_reg_id expected_rm;
    cdisasm_arm_condition expected_condition = CDISASM_ARM_CONDITION_AL;
    uint32_t expected_groups = CDISASM_GROUP_NONE;
    uint8_t source_size = 0u;
    unsigned rd;
    unsigned rn;
    unsigned rm;
    size_t operation;
    int raw_is_family = 0;

    if (instruction->isa_id == CDISASM_ARM_ISA_T32) {
        word = (word << 16) | (word >> 16);
    }
    if (instruction->isa_id == CDISASM_ARM_ISA_A32) {
        for (operation = 0u; operation < 6u; ++operation) {
            if ((word & UINT32_C(0x0ff00ff0)) == a32_values[operation]) {
                break;
            }
        }
        raw_is_family = operation < 6u
            && (word >> 28) != CDISASM_ARM_CONDITION_NV;
        if (raw_is_family) {
            rd = (word >> 12) & 15u;
            rn = (word >> 16) & 15u;
            rm = word & 15u;
            expected_form = (cdisasm_arm_form_id)(UINT16_C(98) + operation);
            expected_name = names[operation < 3u ? operation
                                                  : operation + 1u];
            expected_rd = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0 + rd);
            expected_rn = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0 + rn);
            expected_rm = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0 + rm);
            source_size = (uint8_t)(UINT32_C(1) << (operation % 3u));
            expected_condition = (cdisasm_arm_condition)(word >> 28);
            if (expected_condition <= CDISASM_ARM_CONDITION_LE) {
                expected_groups = CDISASM_GROUP_CONDITIONAL;
            }
        }
    } else if (instruction->isa_id == CDISASM_ARM_ISA_T32) {
        for (operation = 0u; operation < 6u; ++operation) {
            if ((word & UINT32_C(0xfff0f0f0)) == t32_values[operation]) {
                break;
            }
        }
        raw_is_family = operation < 6u;
        if (raw_is_family) {
            rd = (word >> 8) & 15u;
            rn = (word >> 16) & 15u;
            rm = word & 15u;
            expected_form = (cdisasm_arm_form_id)(
                UINT16_C(2169) + operation);
            expected_name = names[operation < 3u ? operation
                                                  : operation + 1u];
            expected_rd = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0 + rd);
            expected_rn = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0 + rn);
            expected_rm = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0 + rm);
            source_size = (uint8_t)(UINT32_C(1) << (operation % 3u));
        }
    } else if (instruction->isa_id == CDISASM_ARM_ISA_A64
               && (word & UINT32_C(0x7fe0e000))
                    == UINT32_C(0x1ac04000)) {
        unsigned size_code = (word >> 10) & 3u;
        unsigned castagnoli = (word >> 12) & 1u;
        unsigned sf = word >> 31;

        raw_is_family = 1;
        if (sf == (size_code == 3u ? 1u : 0u)) {
            operation = castagnoli * 4u + size_code;
            rd = word & 31u;
            rn = (word >> 5) & 31u;
            rm = (word >> 16) & 31u;
            expected_name = names[operation];
            expected_form = size_code < 3u
                ? (cdisasm_arm_form_id)(UINT16_C(5582)
                    + castagnoli * 3u + size_code)
                : (cdisasm_arm_form_id)(UINT16_C(5602) + castagnoli);
            expected_rd = arm_crc32_a64_reg(rd, 0);
            expected_rn = arm_crc32_a64_reg(rn, 0);
            expected_rm = arm_crc32_a64_reg(rm, size_code == 3u);
            source_size = (uint8_t)(UINT32_C(1) << size_code);
        }
    }

    if (!raw_is_family && !arm_is_crc32_name(instruction->name_id)
        && !arm_is_crc32_form(instruction->form_id)) {
        return 1;
    }
    if (!raw_is_family || expected_form == CDISASM_ARM_FORM_NONE
        || rd == (instruction->isa_id == CDISASM_ARM_ISA_A64 ? 32u : 15u)
        || rn == (instruction->isa_id == CDISASM_ARM_ISA_A64 ? 32u : 15u)
        || rm == (instruction->isa_id == CDISASM_ARM_ISA_A64 ? 32u : 15u)
        || instruction->name_id != expected_name
        || instruction->form_id != expected_form
        || instruction->opcode_size != 4u
        || instruction->condition != expected_condition
        || instruction->opcode_groups != expected_groups
        || instruction->instruction_flags != 0u
        || instruction->branch_target != 0u
        || instruction->operand_count != 3u) {
        return 0;
    }
    return arm_exact_crc32_register(
            &instruction->operand[0], expected_rd, 4u,
            CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_crc32_register(
            &instruction->operand[1], expected_rn, 4u,
            CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_crc32_register(
            &instruction->operand[2], expected_rm, source_size,
            CDISASM_OPERAND_ACCESS_READ)
        && cdisasm_arm_generated_form_matches(instruction);
}

typedef struct arm_architectural_hint_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    cdisasm_arm_condition condition;
    uint32_t groups;
    uint8_t has_immediate;
    uint8_t immediate;
} arm_architectural_hint_identity;

static int arm_architectural_hint_identity_for_instruction(
    const cdisasm_arm_instruction *instruction,
    arm_architectural_hint_identity *identity)
{
    static const cdisasm_arm_name_id names[5] = {
        CDISASM_ARM_NAME_ESB,
        CDISASM_ARM_NAME_TSB,
        CDISASM_ARM_NAME_CSDB,
        CDISASM_ARM_NAME_CLRBHB,
        CDISASM_ARM_NAME_DBG
    };
    uint32_t word = instruction->raw_instruction;
    unsigned operation;

    identity->condition = CDISASM_ARM_CONDITION_AL;
    identity->groups = CDISASM_GROUP_NONE;
    identity->has_immediate = 0u;
    identity->immediate = 0u;
    if (instruction->isa_id == CDISASM_ARM_ISA_A32) {
        static const uint32_t values[4] = {
            UINT32_C(0x0320f010), UINT32_C(0x0320f012),
            UINT32_C(0x0320f014), UINT32_C(0x0320f016)
        };
        uint32_t fixed = word & UINT32_C(0x0fffffff);
        cdisasm_arm_condition condition =
            (cdisasm_arm_condition)(word >> 28);

        if (condition == CDISASM_ARM_CONDITION_NV) {
            return 0;
        }
        for (operation = 0u; operation < 4u; ++operation) {
            if (fixed == values[operation]) {
                break;
            }
        }
        if (operation == 4u
            && (word & UINT32_C(0x0ffffff0))
                != UINT32_C(0x0320f0f0)) {
            return 0;
        }
        identity->form_id = (cdisasm_arm_form_id)(
            UINT16_C(247) + operation);
        identity->name_id = names[operation];
        identity->condition = condition;
        identity->groups = condition <= CDISASM_ARM_CONDITION_LE
            ? CDISASM_GROUP_CONDITIONAL : CDISASM_GROUP_NONE;
        identity->has_immediate = operation == 4u;
        identity->immediate = (uint8_t)(word & 15u);
        return 1;
    }
    if (instruction->isa_id == CDISASM_ARM_ISA_T32) {
        static const uint32_t values[4] = {
            UINT32_C(0xf3af8010), UINT32_C(0xf3af8012),
            UINT32_C(0xf3af8014), UINT32_C(0xf3af8016)
        };
        uint32_t canonical = (word << 16) | (word >> 16);

        for (operation = 0u; operation < 4u; ++operation) {
            if (canonical == values[operation]) {
                break;
            }
        }
        if (operation == 4u
            && (canonical & UINT32_C(0xfffffff0))
                != UINT32_C(0xf3af80f0)) {
            return 0;
        }
        identity->form_id = (cdisasm_arm_form_id)(
            UINT16_C(1831) + operation);
        identity->name_id = names[operation];
        identity->has_immediate = operation == 4u;
        identity->immediate = (uint8_t)(canonical & 15u);
        return 1;
    }
    if (instruction->isa_id == CDISASM_ARM_ISA_A64) {
        static const uint32_t values[4] = {
            UINT32_C(0xd503221f), UINT32_C(0xd503225f),
            UINT32_C(0xd503229f), UINT32_C(0xd50322df)
        };
        static const cdisasm_arm_form_id forms[4] = {
            UINT16_C(4471), UINT16_C(4473),
            UINT16_C(4475), UINT16_C(4476)
        };

        for (operation = 0u; operation < 4u; ++operation) {
            if (word == values[operation]) {
                identity->form_id = forms[operation];
                identity->name_id = names[operation];
                return 1;
            }
        }
    }
    return 0;
}

static int arm_is_architectural_hint_form(cdisasm_arm_form_id form_id)
{
    return (form_id >= UINT16_C(247) && form_id <= UINT16_C(251))
        || (form_id >= UINT16_C(1831) && form_id <= UINT16_C(1835))
        || form_id == UINT16_C(4471) || form_id == UINT16_C(4473)
        || form_id == UINT16_C(4475) || form_id == UINT16_C(4476);
}

static int arm_is_architectural_hint_name(cdisasm_arm_name_id name_id)
{
    return name_id == CDISASM_ARM_NAME_ESB
        || name_id == CDISASM_ARM_NAME_TSB
        || name_id == CDISASM_ARM_NAME_CSDB
        || name_id == CDISASM_ARM_NAME_CLRBHB
        || name_id == CDISASM_ARM_NAME_DBG;
}

static int arm_is_architectural_tsb_form(
    const cdisasm_arm_instruction *instruction)
{
    return instruction->name_id == CDISASM_ARM_NAME_TSB
        && (instruction->form_id == UINT16_C(248)
            || instruction->form_id == UINT16_C(1832)
            || instruction->form_id == UINT16_C(4473));
}

static const char *arm_architectural_fixed_hint_suffix(
    const cdisasm_arm_instruction *instruction)
{
    if (instruction->name_id == CDISASM_ARM_NAME_PSB
        && instruction->form_id == UINT16_C(4472)) {
        return " csync";
    }
    if (instruction->name_id == CDISASM_ARM_NAME_GCSB
        && instruction->form_id == UINT16_C(4474)) {
        return " dsync";
    }
    return NULL;
}

static int arm_valid_architectural_hint_schema(
    const cdisasm_arm_instruction *instruction)
{
    arm_architectural_hint_identity identity;
    int raw_is_family = arm_architectural_hint_identity_for_instruction(
        instruction, &identity);
    int form_is_family = arm_is_architectural_hint_form(
        instruction->form_id);
    int name_is_family = arm_is_architectural_hint_name(
        instruction->name_id);

    if (!raw_is_family && !form_is_family && !name_is_family) {
        return 1;
    }
    if (!raw_is_family || !form_is_family || !name_is_family
        || instruction->form_id != identity.form_id
        || instruction->name_id != identity.name_id
        || instruction->opcode_size != 4u
        || instruction->condition != identity.condition
        || instruction->opcode_groups != identity.groups
        || instruction->instruction_flags != 0u
        || instruction->branch_target != 0u
        || instruction->operand_count
            != (identity.has_immediate != 0u ? 1u : 0u)
        || (identity.has_immediate != 0u
            && !arm_exact_u8_immediate_operand(
                &instruction->operand[0], identity.immediate))) {
        return 0;
    }
    return cdisasm_arm_generated_form_matches(instruction);
}

static int arm_valid_a32_speculation_barrier_schema(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A32
        && (word == UINT32_C(0xf57ff040)
            || word == UINT32_C(0xf57ff044));
    int form_is_family = instruction->form_id == UINT16_C(953)
        || instruction->form_id == UINT16_C(954);
    int name_is_family = instruction->name_id == CDISASM_ARM_NAME_SSBB
        || instruction->name_id == CDISASM_ARM_NAME_PSSBB;
    int pssbb = word == UINT32_C(0xf57ff044);

    if (!raw_is_family && !form_is_family && !name_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family && name_is_family
        && instruction->form_id
            == (pssbb ? UINT16_C(954) : UINT16_C(953))
        && instruction->name_id
            == (pssbb ? CDISASM_ARM_NAME_PSSBB : CDISASM_ARM_NAME_SSBB)
        && instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags == 0u
        && instruction->branch_target == 0u
        && instruction->operand_count == 0u
        && cdisasm_arm_generated_form_matches(instruction);
}

static int arm_valid_a32_prefetch_immediate_schema(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned add = (word >> 23) & 1u;
    unsigned rn = (word >> 16) & 15u;
    uint64_t offset = word & UINT32_C(0x0fff);
    uint64_t expected_imm = add != 0u
        ? offset : (uint64_t)(-(int64_t)offset);
    uint32_t expected_flags = offset != 0u
        ? CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT : 0u;
    int pli = (word & UINT32_C(0xff70f000)) == UINT32_C(0xf450f000);
    int pld = (word & UINT32_C(0xff70f000)) == UINT32_C(0xf550f000);
    int pldw = (word & UINT32_C(0xff70f000)) == UINT32_C(0xf510f000)
        && rn != 15u;
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A32
        && (pli || pld || pldw);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A32
        && instruction->form_id >= UINT16_C(958)
        && instruction->form_id <= UINT16_C(961);
    cdisasm_arm_form_id expected_form = pli ? UINT16_C(958)
        : pldw ? UINT16_C(961)
        : rn == 15u ? UINT16_C(959) : UINT16_C(960);
    cdisasm_arm_name_id expected_name = pli
        ? CDISASM_ARM_NAME_PLI
        : pldw ? CDISASM_ARM_NAME_PLDW : CDISASM_ARM_NAME_PLD;
    const cdisasm_arm_operand *memory = &instruction->operand[0];

    if (!raw_is_family && !form_is_family) {
        return 1;
    }
    if (add == 0u && offset != 0u) {
        expected_flags |= CDISASM_OPERAND_FLAG_SIGNED;
    }
    if (rn == 15u) {
        expected_flags |= CDISASM_OPERAND_FLAG_PC_RELATIVE
            | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
    }
    return raw_is_family && form_is_family
        && instruction->form_id == expected_form
        && instruction->name_id == expected_name
        && instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags == 0u
        && instruction->branch_target == 0u
        && instruction->operand_count == 1u
        && memory->type == CDISASM_OPERAND_MEMORY
        && memory->base_reg == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0 + rn)
        && memory->index_reg == CDISASM_ARM_REG_NONE
        && memory->reg == CDISASM_ARM_REG_NONE
        && memory->register_list == 0u
        && memory->imm == expected_imm
        && memory->flags == expected_flags
        && memory->address == (rn == 15u
            ? (add != 0u ? instruction->address + UINT64_C(8) + offset
                         : instruction->address + UINT64_C(8) - offset)
            : 0u)
        && memory->size == 0u
        && memory->access == CDISASM_OPERAND_ACCESS_READ
        && memory->shift_type == CDISASM_ARM_SHIFT_NONE
        && memory->shift_amount == 0u
        && memory->extend_type == CDISASM_ARM_EXTEND_NONE
        && memory->scale == 0u
        && cdisasm_arm_generated_form_matches(instruction);
}

static int arm_valid_a32_prefetch_register_schema(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned add = (word >> 23) & 1u;
    unsigned rn = (word >> 16) & 15u;
    unsigned rm = word & 15u;
    unsigned shift = (word >> 5) & 3u;
    unsigned amount = (word >> 7) & 31u;
    int pldw = (word & UINT32_C(0xff70f010))
        == UINT32_C(0xf710f000);
    int pli = !pldw && (word & UINT32_C(0x01000000)) == 0u;
    int rrx = shift == 3u && amount == 0u;
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A32
        && ((word & UINT32_C(0xfe70f010)) == UINT32_C(0xf650f000)
            || pldw)
        && rn != 15u && rm != 15u;
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A32
        && instruction->form_id >= UINT16_C(962)
        && instruction->form_id <= UINT16_C(967);
    cdisasm_arm_form_id expected_form = pldw
        ? (rrx ? UINT16_C(967) : UINT16_C(966)) : pli
        ? (rrx ? UINT16_C(962) : UINT16_C(963))
        : (rrx ? UINT16_C(965) : UINT16_C(964));
    cdisasm_arm_name_id expected_name = pldw ? CDISASM_ARM_NAME_PLDW
        : pli ? CDISASM_ARM_NAME_PLI : CDISASM_ARM_NAME_PLD;
    const cdisasm_arm_operand *memory = &instruction->operand[0];
    cdisasm_arm_shift_type expected_shift = rrx
        ? CDISASM_ARM_SHIFT_RRX
        : (shift == 0u && amount == 0u) ? CDISASM_ARM_SHIFT_NONE
        : (cdisasm_arm_shift_type)(CDISASM_ARM_SHIFT_LSL + shift);
    uint8_t expected_amount = rrx ? 1u
        : (uint8_t)(amount == 0u && shift != 0u ? 32u : amount);

    if (!raw_is_family && !form_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family
        && instruction->form_id == expected_form
        && instruction->name_id == expected_name
        && instruction->opcode_size == 4u
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags == 0u
        && instruction->branch_target == 0u
        && instruction->operand_count == 1u
        && memory->type == CDISASM_OPERAND_MEMORY
        && memory->reg == CDISASM_ARM_REG_NONE
        && memory->base_reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0 + rn)
        && memory->index_reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0 + rm)
        && memory->register_list == 0u
        && memory->address == 0u && memory->imm == 0u
        && memory->size == 0u
        && memory->access == CDISASM_OPERAND_ACCESS_READ
        && memory->flags
            == (add == 0u ? CDISASM_OPERAND_FLAG_SIGNED : 0u)
        && memory->shift_type == expected_shift
        && memory->shift_amount == expected_amount
        && memory->extend_type == CDISASM_ARM_EXTEND_NONE
        && memory->scale == 0u
        && cdisasm_arm_generated_form_matches(instruction);
}

static int arm_valid_t32_narrow_mov_shift_schema(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t encoding = word & UINT32_C(0xffc0);
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_T32
        && instruction->opcode_size == 2u
        && (encoding == UINT32_C(0x0000)
            || encoding == UINT32_C(0x4080)
            || encoding == UINT32_C(0x40c0)
            || encoding == UINT32_C(0x4100)
            || encoding == UINT32_C(0x41c0));
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_T32
        && (instruction->form_id == UINT16_C(1104)
            || (instruction->form_id >= UINT16_C(1111)
                && instruction->form_id <= UINT16_C(1114)));
    cdisasm_arm_form_id expected_form;
    cdisasm_arm_name_id expected_name;
    cdisasm_operand_access destination_access;
    cdisasm_arm_reg_id destination = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_R0 + (word & UINT32_C(7)));
    cdisasm_arm_reg_id source = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_R0 + ((word >> 3) & UINT32_C(7)));

    if (!raw_is_family && !form_is_family) {
        return 1;
    }
    if (encoding == UINT32_C(0x0000)) {
        expected_form = UINT16_C(1104);
        expected_name = CDISASM_ARM_NAME_MOV;
        destination_access = CDISASM_OPERAND_ACCESS_WRITE;
    } else if (encoding == UINT32_C(0x4080)) {
        expected_form = UINT16_C(1112);
        expected_name = CDISASM_ARM_NAME_LSLS;
        destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
    } else if (encoding == UINT32_C(0x40c0)) {
        expected_form = UINT16_C(1113);
        expected_name = CDISASM_ARM_NAME_LSRS;
        destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
    } else if (encoding == UINT32_C(0x4100)) {
        expected_form = UINT16_C(1111);
        expected_name = CDISASM_ARM_NAME_ASRS;
        destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
    } else {
        expected_form = UINT16_C(1114);
        expected_name = CDISASM_ARM_NAME_RORS;
        destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
    }
    return raw_is_family && form_is_family
        && instruction->form_id == expected_form
        && instruction->name_id == expected_name
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS
        && instruction->branch_target == 0u
        && instruction->operand_count == 2u
        && arm_exact_register_operand(&instruction->operand[0],
            destination, 4u, destination_access)
        && arm_exact_register_operand(&instruction->operand[1],
            source, 4u, CDISASM_OPERAND_ACCESS_READ)
        && cdisasm_arm_generated_form_matches(instruction);
}

static int arm_valid_a32_mov_register_shift_schema(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    unsigned shift = (word >> 5) & 3u;
    unsigned set_flags = (word >> 20) & 1u;
    static const cdisasm_arm_name_id names[2][4] = {
        {CDISASM_ARM_NAME_LSL, CDISASM_ARM_NAME_LSR,
            CDISASM_ARM_NAME_ASR, CDISASM_ARM_NAME_ROR},
        {CDISASM_ARM_NAME_LSLS, CDISASM_ARM_NAME_LSRS,
            CDISASM_ARM_NAME_ASRS, CDISASM_ARM_NAME_RORS}
    };
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_A32
        && (word & UINT32_C(0x0fef0090)) == UINT32_C(0x01a00010);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_A32
        && (instruction->form_id == UINT16_C(210)
            || instruction->form_id == UINT16_C(211));
    cdisasm_arm_condition condition =
        (cdisasm_arm_condition)(word >> 28);
    uint32_t groups = condition == CDISASM_ARM_CONDITION_AL
        ? CDISASM_GROUP_NONE : CDISASM_GROUP_CONDITIONAL;
    cdisasm_arm_reg_id rd = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_R0 + ((word >> 12) & UINT32_C(15)));
    cdisasm_arm_reg_id rm = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_R0 + (word & UINT32_C(15)));
    cdisasm_arm_reg_id rs = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_R0 + ((word >> 8) & UINT32_C(15)));

    if (!raw_is_family && !form_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family
        && condition != CDISASM_ARM_CONDITION_NV
        && rd != CDISASM_ARM_REG_PC
        && rm != CDISASM_ARM_REG_PC
        && rs != CDISASM_ARM_REG_PC
        && instruction->form_id
            == (set_flags != 0u ? UINT16_C(210) : UINT16_C(211))
        && instruction->name_id == names[set_flags][shift]
        && instruction->opcode_size == 4u
        && instruction->condition == condition
        && instruction->opcode_groups == groups
        && instruction->instruction_flags == (set_flags != 0u
            ? CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS : 0u)
        && instruction->branch_target == 0u
        && instruction->operand_count == 3u
        && arm_exact_register_operand(&instruction->operand[0],
            rd, 4u, CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_register_operand(&instruction->operand[1],
            rm, 4u, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_register_operand(&instruction->operand[2],
            rs, 4u, CDISASM_OPERAND_ACCESS_READ)
        && cdisasm_arm_generated_form_matches(instruction);
}

static int arm_valid_t32_wide_mov_register_shift_schema(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = instruction->raw_instruction;
    uint16_t first = (uint16_t)word;
    uint16_t second = (uint16_t)(word >> 16);
    unsigned operation = (first >> 5) & 3u;
    unsigned set_flags = (first >> 4) & 1u;
    static const cdisasm_arm_name_id names[2][4] = {
        {CDISASM_ARM_NAME_LSL, CDISASM_ARM_NAME_LSR,
            CDISASM_ARM_NAME_ASR, CDISASM_ARM_NAME_ROR},
        {CDISASM_ARM_NAME_LSLS, CDISASM_ARM_NAME_LSRS,
            CDISASM_ARM_NAME_ASRS, CDISASM_ARM_NAME_RORS}
    };
    int raw_is_family = instruction->isa_id == CDISASM_ARM_ISA_T32
        && instruction->opcode_size == 4u
        && (first & UINT16_C(0xff80)) == UINT16_C(0xfa00)
        && (second & UINT16_C(0xf0f0)) == UINT16_C(0xf000);
    int form_is_family = instruction->isa_id == CDISASM_ARM_ISA_T32
        && (instruction->form_id == UINT16_C(2109)
            || instruction->form_id == UINT16_C(2110));
    cdisasm_arm_reg_id rd = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_R0 + ((second >> 8) & 15u));
    cdisasm_arm_reg_id rm = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_R0 + (first & 15u));
    cdisasm_arm_reg_id rs = (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_R0 + (second & 15u));

    if (!raw_is_family && !form_is_family) {
        return 1;
    }
    return raw_is_family && form_is_family
        && rd != CDISASM_ARM_REG_SP && rd != CDISASM_ARM_REG_PC
        && rm != CDISASM_ARM_REG_SP && rm != CDISASM_ARM_REG_PC
        && rs != CDISASM_ARM_REG_SP && rs != CDISASM_ARM_REG_PC
        && instruction->form_id
            == (set_flags != 0u ? UINT16_C(2109) : UINT16_C(2110))
        && instruction->name_id == names[set_flags][operation]
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_NONE
        && instruction->instruction_flags == (set_flags != 0u
            ? CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS : 0u)
        && instruction->branch_target == 0u
        && instruction->operand_count == 3u
        && arm_exact_register_operand(&instruction->operand[0],
            rd, 4u, CDISASM_OPERAND_ACCESS_WRITE)
        && arm_exact_register_operand(&instruction->operand[1],
            rm, 4u, CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_register_operand(&instruction->operand[2],
            rs, 4u, CDISASM_OPERAND_ACCESS_READ)
        && cdisasm_arm_generated_form_matches(instruction);
}

static int arm_valid_sve_contiguous_load_schema(
    const cdisasm_arm_instruction *instruction)
{
    typedef struct arm_sve_load_identity {
        uint32_t value;
        cdisasm_arm_name_id name;
        cdisasm_arm_form_id form;
        uint8_t destination_size;
        uint8_t memory_size;
    } arm_sve_load_identity;
    static const arm_sve_load_identity identities[] = {
        { UINT32_C(0xa400a000), CDISASM_ARM_NAME_LD1B, 3314u, 1u, 1u },
        { UINT32_C(0xa420a000), CDISASM_ARM_NAME_LD1B, 3315u, 2u, 1u },
        { UINT32_C(0xa440a000), CDISASM_ARM_NAME_LD1B, 3316u, 4u, 1u },
        { UINT32_C(0xa460a000), CDISASM_ARM_NAME_LD1B, 3317u, 8u, 1u },
        { UINT32_C(0xa480a000), CDISASM_ARM_NAME_LD1SW, 3318u, 8u, 4u },
        { UINT32_C(0xa4a0a000), CDISASM_ARM_NAME_LD1H, 3319u, 2u, 2u },
        { UINT32_C(0xa4c0a000), CDISASM_ARM_NAME_LD1H, 3320u, 4u, 2u },
        { UINT32_C(0xa4e0a000), CDISASM_ARM_NAME_LD1H, 3321u, 8u, 2u },
        { UINT32_C(0xa500a000), CDISASM_ARM_NAME_LD1SH, 3322u, 8u, 2u },
        { UINT32_C(0xa520a000), CDISASM_ARM_NAME_LD1SH, 3323u, 4u, 2u },
        { UINT32_C(0xa540a000), CDISASM_ARM_NAME_LD1W, 3324u, 4u, 4u },
        { UINT32_C(0xa560a000), CDISASM_ARM_NAME_LD1W, 3325u, 8u, 4u },
        { UINT32_C(0xa580a000), CDISASM_ARM_NAME_LD1SB, 3326u, 8u, 1u },
        { UINT32_C(0xa5a0a000), CDISASM_ARM_NAME_LD1SB, 3327u, 4u, 1u },
        { UINT32_C(0xa5c0a000), CDISASM_ARM_NAME_LD1SB, 3328u, 2u, 1u },
        { UINT32_C(0xa5e0a000), CDISASM_ARM_NAME_LD1D, 3329u, 8u, 8u },
        { UINT32_C(0xa410a000), CDISASM_ARM_NAME_LDNF1B, 3330u, 1u, 1u },
        { UINT32_C(0xa430a000), CDISASM_ARM_NAME_LDNF1B, 3331u, 2u, 1u },
        { UINT32_C(0xa450a000), CDISASM_ARM_NAME_LDNF1B, 3332u, 4u, 1u },
        { UINT32_C(0xa470a000), CDISASM_ARM_NAME_LDNF1B, 3333u, 8u, 1u },
        { UINT32_C(0xa490a000), CDISASM_ARM_NAME_LDNF1SW, 3334u, 8u, 4u },
        { UINT32_C(0xa4b0a000), CDISASM_ARM_NAME_LDNF1H, 3335u, 2u, 2u },
        { UINT32_C(0xa4d0a000), CDISASM_ARM_NAME_LDNF1H, 3336u, 4u, 2u },
        { UINT32_C(0xa4f0a000), CDISASM_ARM_NAME_LDNF1H, 3337u, 8u, 2u },
        { UINT32_C(0xa510a000), CDISASM_ARM_NAME_LDNF1SH, 3338u, 8u, 2u },
        { UINT32_C(0xa530a000), CDISASM_ARM_NAME_LDNF1SH, 3339u, 4u, 2u },
        { UINT32_C(0xa550a000), CDISASM_ARM_NAME_LDNF1W, 3340u, 4u, 4u },
        { UINT32_C(0xa570a000), CDISASM_ARM_NAME_LDNF1W, 3341u, 8u, 4u },
        { UINT32_C(0xa590a000), CDISASM_ARM_NAME_LDNF1SB, 3342u, 8u, 1u },
        { UINT32_C(0xa5b0a000), CDISASM_ARM_NAME_LDNF1SB, 3343u, 4u, 1u },
        { UINT32_C(0xa5d0a000), CDISASM_ARM_NAME_LDNF1SB, 3344u, 2u, 1u },
        { UINT32_C(0xa5f0a000), CDISASM_ARM_NAME_LDNF1D, 3345u, 8u, 8u },
        { UINT32_C(0xa400e000), CDISASM_ARM_NAME_LDNT1B, 3362u, 1u, 1u },
        { UINT32_C(0xa480e000), CDISASM_ARM_NAME_LDNT1H, 3363u, 2u, 2u },
        { UINT32_C(0xa500e000), CDISASM_ARM_NAME_LDNT1W, 3364u, 4u, 4u },
        { UINT32_C(0xa580e000), CDISASM_ARM_NAME_LDNT1D, 3365u, 8u, 8u }
    };
    const arm_sve_load_identity *identity = NULL;
    const cdisasm_arm_operand *list;
    const cdisasm_arm_operand *memory;
    uint32_t word = instruction->raw_instruction;
    uint32_t operation = word & UINT32_C(0xfff0e000);
    int form_is_family = 0;
    int64_t displacement;
    uint8_t memory_flags;
    size_t index;

    for (index = 0u; index < sizeof(identities) / sizeof(identities[0]); ++index) {
        if (identities[index].value == operation
            && instruction->isa_id == CDISASM_ARM_ISA_A64) {
            identity = &identities[index];
        }
        if (identities[index].form == instruction->form_id
            && instruction->isa_id == CDISASM_ARM_ISA_A64) {
            form_is_family = 1;
        }
    }
    if (identity == NULL && !form_is_family) return 1;
    if (identity == NULL || !form_is_family) return 0;
    displacement = (int64_t)((word >> 16) & 15u);
    if (displacement >= 8) displacement -= 16;
    memory_flags = displacement == 0
        ? CDISASM_OPERAND_FLAG_NONE
        : (uint8_t)(CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
            | CDISASM_ARM_OPERAND_FLAG_VL_SCALED
            | (displacement < 0 ? CDISASM_OPERAND_FLAG_SIGNED : 0u));
    if (instruction->name_id != identity->name
        || instruction->form_id != identity->form
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->instruction_flags
            != (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        || instruction->operand_count != 3u) {
        return 0;
    }
    list = &instruction->operand[0];
    memory = &instruction->operand[2];
    return list->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
        && list->reg == CDISASM_ARM_REG_Z0 + (word & 31u)
        && list->base_reg == CDISASM_ARM_REG_NONE
        && list->index_reg == CDISASM_ARM_REG_NONE
        && list->register_list == UINT16_C(0x0101)
        && list->address == 0u && list->imm == 0u && list->size == 0u
        && list->flags == CDISASM_OPERAND_FLAG_NONE
        && list->shift_type == CDISASM_ARM_SHIFT_NONE
        && list->shift_amount == 0u
        && list->extend_type == identity->destination_size
        && list->scale == 0u
        && list->access == CDISASM_OPERAND_ACCESS_WRITE
        && arm_exact_predicate_operand(&instruction->operand[1],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + ((word >> 10) & 7u)),
            identity->destination_size,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO,
            CDISASM_OPERAND_ACCESS_READ)
        && memory->type == CDISASM_OPERAND_MEMORY
        && memory->reg == CDISASM_ARM_REG_NONE
        && memory->base_reg == (((word >> 5) & 31u) == 31u
            ? CDISASM_ARM_REG_SP
            : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0
                + ((word >> 5) & 31u)))
        && memory->index_reg == CDISASM_ARM_REG_NONE
        && memory->register_list == 0u && memory->address == 0u
        && (int64_t)memory->imm == displacement
        && memory->size == identity->memory_size
        && memory->flags == memory_flags
        && memory->shift_type == CDISASM_ARM_SHIFT_NONE
        && memory->shift_amount == 0u
        && memory->extend_type == CDISASM_ARM_EXTEND_NONE
        && memory->scale == 0u
        && memory->access == CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sve_multi_contiguous_load_schema(
    const cdisasm_arm_instruction *instruction)
{
    typedef struct identity { uint32_t value; cdisasm_arm_name_id name;
        cdisasm_arm_form_id reg_form, imm_form; uint8_t size, count; } identity;
    static const identity ids[] = {
        {0xa420c000,CDISASM_ARM_NAME_LD2B,3350,3366,1,2},{0xa440c000,CDISASM_ARM_NAME_LD3B,3351,3367,1,3},{0xa460c000,CDISASM_ARM_NAME_LD4B,3352,3368,1,4},
        {0xa4a0c000,CDISASM_ARM_NAME_LD2H,3353,3369,2,2},{0xa4c0c000,CDISASM_ARM_NAME_LD3H,3354,3370,2,3},{0xa4e0c000,CDISASM_ARM_NAME_LD4H,3355,3371,2,4},
        {0xa520c000,CDISASM_ARM_NAME_LD2W,3356,3372,4,2},{0xa540c000,CDISASM_ARM_NAME_LD3W,3357,3373,4,3},{0xa560c000,CDISASM_ARM_NAME_LD4W,3358,3374,4,4},
        {0xa5a0c000,CDISASM_ARM_NAME_LD2D,3359,3375,8,2},{0xa5c0c000,CDISASM_ARM_NAME_LD3D,3360,3376,8,3},{0xa5e0c000,CDISASM_ARM_NAME_LD4D,3361,3377,8,4}
    };
    uint32_t word=instruction->raw_instruction;
    int immediate=(word&UINT32_C(0x2000))!=0;
    uint32_t operation=(word&(immediate?UINT32_C(0xfff0e000):UINT32_C(0xffe0e000)))&~UINT32_C(0x2000);
    const identity *id=NULL;int form_family=0;size_t n;int64_t displacement=0;
    const cdisasm_arm_operand *list,*memory;uint8_t memory_flags;
    for(n=0;n<sizeof(ids)/sizeof(ids[0]);++n){if(ids[n].value==operation&&instruction->isa_id==CDISASM_ARM_ISA_A64)id=&ids[n];if((instruction->form_id==ids[n].reg_form||instruction->form_id==ids[n].imm_form)&&instruction->isa_id==CDISASM_ARM_ISA_A64)form_family=1;}
    if(id==NULL&&!form_family)return 1;if(id==NULL||!form_family)return 0;
    if(immediate){displacement=(int64_t)((word>>16)&15u);if(displacement>=8)displacement-=16;displacement*=id->count;}
    memory_flags=displacement==0?0u:(uint8_t)(CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT|CDISASM_ARM_OPERAND_FLAG_VL_SCALED|(displacement<0?CDISASM_OPERAND_FLAG_SIGNED:0u));
    if(instruction->name_id!=id->name||instruction->form_id!=(immediate?id->imm_form:id->reg_form)||instruction->condition!=CDISASM_ARM_CONDITION_AL||instruction->opcode_groups!=CDISASM_GROUP_NONE||instruction->instruction_flags!=(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)||instruction->operand_count!=3u)return 0;
    list=&instruction->operand[0];memory=&instruction->operand[2];
    return list->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&list->reg==CDISASM_ARM_REG_Z0+(word&31u)&&list->base_reg==CDISASM_ARM_REG_NONE&&list->index_reg==CDISASM_ARM_REG_NONE&&list->register_list==(uint16_t)(UINT16_C(0x0100)|id->count)&&list->address==0&&list->imm==0&&list->size==0&&list->flags==0&&list->shift_type==CDISASM_ARM_SHIFT_NONE&&list->shift_amount==0&&list->extend_type==id->size&&list->scale==0&&list->access==CDISASM_OPERAND_ACCESS_WRITE
        &&arm_exact_predicate_operand(&instruction->operand[1],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0+((word>>10)&7u)),id->size,CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO,CDISASM_OPERAND_ACCESS_READ)
        &&memory->type==CDISASM_OPERAND_MEMORY&&memory->reg==CDISASM_ARM_REG_NONE&&memory->base_reg==(((word>>5)&31u)==31u?CDISASM_ARM_REG_SP:(cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0+((word>>5)&31u)))&&memory->index_reg==(immediate?CDISASM_ARM_REG_NONE:(cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0+((word>>16)&31u)))&&memory->register_list==0&&memory->address==0&&(int64_t)memory->imm==displacement&&memory->size==id->size&&memory->flags==memory_flags&&memory->shift_type==(!immediate&&id->size!=1?CDISASM_ARM_SHIFT_LSL:CDISASM_ARM_SHIFT_NONE)&&memory->shift_amount==(immediate||id->size==1?0:id->size==2?1:id->size==4?2:3)&&memory->extend_type==CDISASM_ARM_EXTEND_NONE&&memory->scale==0&&memory->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sve_multi_contiguous_store_schema(
    const cdisasm_arm_instruction *instruction)
{
    typedef struct identity { uint32_t value; cdisasm_arm_name_id name;
        cdisasm_arm_form_id reg_form, imm_form; uint8_t size, count; } identity;
    static const identity ids[] = {
        {0xe4206000,CDISASM_ARM_NAME_ST2B,3489,3537,1,2},{0xe4406000,CDISASM_ARM_NAME_ST3B,3490,3538,1,3},{0xe4606000,CDISASM_ARM_NAME_ST4B,3491,3539,1,4},
        {0xe4a06000,CDISASM_ARM_NAME_ST2H,3492,3540,2,2},{0xe4c06000,CDISASM_ARM_NAME_ST3H,3493,3541,2,3},{0xe4e06000,CDISASM_ARM_NAME_ST4H,3494,3542,2,4},
        {0xe5206000,CDISASM_ARM_NAME_ST2W,3495,3543,4,2},{0xe5406000,CDISASM_ARM_NAME_ST3W,3496,3544,4,3},{0xe5606000,CDISASM_ARM_NAME_ST4W,3497,3545,4,4},
        {0xe5a06000,CDISASM_ARM_NAME_ST2D,3498,3546,8,2},{0xe5c06000,CDISASM_ARM_NAME_ST3D,3499,3547,8,3},{0xe5e06000,CDISASM_ARM_NAME_ST4D,3500,3548,8,4}
    };
    uint32_t word=instruction->raw_instruction;
    int immediate=(word&UINT32_C(0x8000))!=0;
    uint32_t operation=word&(immediate?UINT32_C(0xfff0e000):UINT32_C(0xffe0e000));
    const identity *id=NULL;int form_family=0;size_t n;int64_t displacement=0;
    const cdisasm_arm_operand *list,*memory;uint8_t memory_flags;
    for(n=0;n<sizeof(ids)/sizeof(ids[0]);++n){if((immediate?(ids[n].value|UINT32_C(0x00108000)):ids[n].value)==operation&&instruction->isa_id==CDISASM_ARM_ISA_A64)id=&ids[n];if((instruction->form_id==ids[n].reg_form||instruction->form_id==ids[n].imm_form)&&instruction->isa_id==CDISASM_ARM_ISA_A64)form_family=1;}
    if(id==NULL&&!form_family)return 1;if(id==NULL||!form_family)return 0;
    if(immediate){displacement=(int64_t)((word>>16)&15u);if(displacement>=8)displacement-=16;displacement*=id->count;}
    memory_flags=displacement==0?0u:(uint8_t)(CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT|CDISASM_ARM_OPERAND_FLAG_VL_SCALED|(displacement<0?CDISASM_OPERAND_FLAG_SIGNED:0u));
    if(instruction->name_id!=id->name||instruction->form_id!=(immediate?id->imm_form:id->reg_form)||instruction->condition!=CDISASM_ARM_CONDITION_AL||instruction->opcode_groups!=CDISASM_GROUP_NONE||instruction->instruction_flags!=(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)||instruction->operand_count!=3u)return 0;
    list=&instruction->operand[0];memory=&instruction->operand[2];
    return list->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&list->reg==CDISASM_ARM_REG_Z0+(word&31u)&&list->base_reg==CDISASM_ARM_REG_NONE&&list->index_reg==CDISASM_ARM_REG_NONE&&list->register_list==(uint16_t)(UINT16_C(0x0100)|id->count)&&list->address==0&&list->imm==0&&list->size==0&&list->flags==0&&list->shift_type==CDISASM_ARM_SHIFT_NONE&&list->shift_amount==0&&list->extend_type==id->size&&list->scale==0&&list->access==CDISASM_OPERAND_ACCESS_READ
        &&arm_exact_predicate_operand(&instruction->operand[1],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0+((word>>10)&7u)),id->size,CDISASM_OPERAND_FLAG_NONE,CDISASM_OPERAND_ACCESS_READ)
        &&memory->type==CDISASM_OPERAND_MEMORY&&memory->reg==CDISASM_ARM_REG_NONE&&memory->base_reg==(((word>>5)&31u)==31u?CDISASM_ARM_REG_SP:(cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0+((word>>5)&31u)))&&memory->index_reg==(immediate?CDISASM_ARM_REG_NONE:(cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0+((word>>16)&31u)))&&memory->register_list==0&&memory->address==0&&(int64_t)memory->imm==displacement&&memory->size==id->size&&memory->flags==memory_flags&&memory->shift_type==(!immediate&&id->size!=1?CDISASM_ARM_SHIFT_LSL:CDISASM_ARM_SHIFT_NONE)&&memory->shift_amount==(immediate||id->size==1?0:id->size==2?1:id->size==4?2:3)&&memory->extend_type==CDISASM_ARM_EXTEND_NONE&&memory->scale==0&&memory->access==CDISASM_OPERAND_ACCESS_WRITE;
}

static int arm_valid_sve_contiguous_store_schema(
    const cdisasm_arm_instruction *instruction)
{
    typedef struct arm_sve_store_identity { uint32_t value;
        cdisasm_arm_name_id name; cdisasm_arm_form_id form;
        uint8_t source_size, memory_size; } arm_sve_store_identity;
    static const arm_sve_store_identity identities[] = {
        { UINT32_C(0xe400e000), CDISASM_ARM_NAME_ST1B, 3527u, 1u, 1u },
        { UINT32_C(0xe420e000), CDISASM_ARM_NAME_ST1B, 3527u, 2u, 1u },
        { UINT32_C(0xe440e000), CDISASM_ARM_NAME_ST1B, 3527u, 4u, 1u },
        { UINT32_C(0xe460e000), CDISASM_ARM_NAME_ST1B, 3527u, 8u, 1u },
        { UINT32_C(0xe4a0e000), CDISASM_ARM_NAME_ST1H, 3528u, 2u, 2u },
        { UINT32_C(0xe4c0e000), CDISASM_ARM_NAME_ST1H, 3528u, 4u, 2u },
        { UINT32_C(0xe4e0e000), CDISASM_ARM_NAME_ST1H, 3528u, 8u, 2u },
        { UINT32_C(0xe540e000), CDISASM_ARM_NAME_ST1W, 3530u, 4u, 4u },
        { UINT32_C(0xe560e000), CDISASM_ARM_NAME_ST1W, 3530u, 8u, 4u },
        { UINT32_C(0xe5e0e000), CDISASM_ARM_NAME_ST1D, 3532u, 8u, 8u },
        { UINT32_C(0xe410e000), CDISASM_ARM_NAME_STNT1B, 3533u, 1u, 1u },
        { UINT32_C(0xe490e000), CDISASM_ARM_NAME_STNT1H, 3534u, 2u, 2u },
        { UINT32_C(0xe510e000), CDISASM_ARM_NAME_STNT1W, 3535u, 4u, 4u },
        { UINT32_C(0xe590e000), CDISASM_ARM_NAME_STNT1D, 3536u, 8u, 8u }
    };
    const arm_sve_store_identity *identity = NULL;
    const cdisasm_arm_operand *list, *memory;
    uint32_t word = instruction->raw_instruction;
    uint32_t operation = word & UINT32_C(0xfff0e000);
    int form_is_family = 0;
    int64_t displacement;
    uint8_t memory_flags;
    size_t index;

    for (index = 0u; index < sizeof(identities) / sizeof(identities[0]); ++index) {
        if (identities[index].value == operation
            && instruction->isa_id == CDISASM_ARM_ISA_A64)
            identity = &identities[index];
        if (identities[index].form == instruction->form_id
            && instruction->isa_id == CDISASM_ARM_ISA_A64)
            form_is_family = 1;
    }
    if (identity == NULL && !form_is_family) return 1;
    if (identity == NULL || !form_is_family) return 0;
    displacement = (int64_t)((word >> 16) & 15u);
    if (displacement >= 8) displacement -= 16;
    memory_flags = displacement == 0 ? CDISASM_OPERAND_FLAG_NONE
        : (uint8_t)(CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
            | CDISASM_ARM_OPERAND_FLAG_VL_SCALED
            | (displacement < 0 ? CDISASM_OPERAND_FLAG_SIGNED : 0u));
    if (instruction->name_id != identity->name
        || instruction->form_id != identity->form
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->instruction_flags
            != (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        || instruction->operand_count != 3u) return 0;
    list = &instruction->operand[0];
    memory = &instruction->operand[2];
    return list->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
        && list->reg == CDISASM_ARM_REG_Z0 + (word & 31u)
        && list->base_reg == CDISASM_ARM_REG_NONE
        && list->index_reg == CDISASM_ARM_REG_NONE
        && list->register_list == UINT16_C(0x0101)
        && list->address == 0u && list->imm == 0u && list->size == 0u
        && list->flags == CDISASM_OPERAND_FLAG_NONE
        && list->shift_type == CDISASM_ARM_SHIFT_NONE
        && list->shift_amount == 0u
        && list->extend_type == identity->source_size && list->scale == 0u
        && list->access == CDISASM_OPERAND_ACCESS_READ
        && arm_exact_predicate_operand(&instruction->operand[1],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + ((word >> 10) & 7u)),
            identity->source_size, CDISASM_OPERAND_FLAG_NONE,
            CDISASM_OPERAND_ACCESS_READ)
        && memory->type == CDISASM_OPERAND_MEMORY
        && memory->reg == CDISASM_ARM_REG_NONE
        && memory->base_reg == (((word >> 5) & 31u) == 31u
            ? CDISASM_ARM_REG_SP
            : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0
                + ((word >> 5) & 31u)))
        && memory->index_reg == CDISASM_ARM_REG_NONE
        && memory->register_list == 0u && memory->address == 0u
        && (int64_t)memory->imm == displacement
        && memory->size == identity->memory_size
        && memory->flags == memory_flags
        && memory->shift_type == CDISASM_ARM_SHIFT_NONE
        && memory->shift_amount == 0u
        && memory->extend_type == CDISASM_ARM_EXTEND_NONE
        && memory->scale == 0u
        && memory->access == CDISASM_OPERAND_ACCESS_WRITE;
}

static int arm_valid_sve_contiguous_load_register_schema(
    const cdisasm_arm_instruction *instruction)
{
    typedef struct arm_sve_load_register_identity { uint32_t value;
        cdisasm_arm_name_id name; cdisasm_arm_form_id form;
        uint8_t destination_size, memory_size, first_fault; } arm_sve_load_register_identity;
    static const arm_sve_load_register_identity identities[] = {
        { UINT32_C(0xa4004000), CDISASM_ARM_NAME_LD1B, 3277u, 1u, 1u, 0u },
        { UINT32_C(0xa4204000), CDISASM_ARM_NAME_LD1B, 3278u, 2u, 1u, 0u },
        { UINT32_C(0xa4404000), CDISASM_ARM_NAME_LD1B, 3279u, 4u, 1u, 0u },
        { UINT32_C(0xa4604000), CDISASM_ARM_NAME_LD1B, 3280u, 8u, 1u, 0u },
        { UINT32_C(0xa4804000), CDISASM_ARM_NAME_LD1SW, 3281u, 8u, 4u, 0u },
        { UINT32_C(0xa4a04000), CDISASM_ARM_NAME_LD1H, 3282u, 2u, 2u, 0u },
        { UINT32_C(0xa4c04000), CDISASM_ARM_NAME_LD1H, 3283u, 4u, 2u, 0u },
        { UINT32_C(0xa4e04000), CDISASM_ARM_NAME_LD1H, 3284u, 8u, 2u, 0u },
        { UINT32_C(0xa5004000), CDISASM_ARM_NAME_LD1SH, 3285u, 8u, 2u, 0u },
        { UINT32_C(0xa5204000), CDISASM_ARM_NAME_LD1SH, 3286u, 4u, 2u, 0u },
        { UINT32_C(0xa5404000), CDISASM_ARM_NAME_LD1W, 3287u, 4u, 4u, 0u },
        { UINT32_C(0xa5604000), CDISASM_ARM_NAME_LD1W, 3288u, 8u, 4u, 0u },
        { UINT32_C(0xa5804000), CDISASM_ARM_NAME_LD1SB, 3289u, 8u, 1u, 0u },
        { UINT32_C(0xa5a04000), CDISASM_ARM_NAME_LD1SB, 3290u, 4u, 1u, 0u },
        { UINT32_C(0xa5c04000), CDISASM_ARM_NAME_LD1SB, 3291u, 2u, 1u, 0u },
        { UINT32_C(0xa5e04000), CDISASM_ARM_NAME_LD1D, 3292u, 8u, 8u, 0u },
        { UINT32_C(0xa4006000), CDISASM_ARM_NAME_LDFF1B, 3293u, 1u, 1u, 1u },
        { UINT32_C(0xa4206000), CDISASM_ARM_NAME_LDFF1B, 3294u, 2u, 1u, 1u },
        { UINT32_C(0xa4406000), CDISASM_ARM_NAME_LDFF1B, 3295u, 4u, 1u, 1u },
        { UINT32_C(0xa4606000), CDISASM_ARM_NAME_LDFF1B, 3296u, 8u, 1u, 1u },
        { UINT32_C(0xa4806000), CDISASM_ARM_NAME_LDFF1SW, 3297u, 8u, 4u, 1u },
        { UINT32_C(0xa4a06000), CDISASM_ARM_NAME_LDFF1H, 3298u, 2u, 2u, 1u },
        { UINT32_C(0xa4c06000), CDISASM_ARM_NAME_LDFF1H, 3299u, 4u, 2u, 1u },
        { UINT32_C(0xa4e06000), CDISASM_ARM_NAME_LDFF1H, 3300u, 8u, 2u, 1u },
        { UINT32_C(0xa5006000), CDISASM_ARM_NAME_LDFF1SH, 3301u, 8u, 2u, 1u },
        { UINT32_C(0xa5206000), CDISASM_ARM_NAME_LDFF1SH, 3302u, 4u, 2u, 1u },
        { UINT32_C(0xa5406000), CDISASM_ARM_NAME_LDFF1W, 3303u, 4u, 4u, 1u },
        { UINT32_C(0xa5606000), CDISASM_ARM_NAME_LDFF1W, 3304u, 8u, 4u, 1u },
        { UINT32_C(0xa5806000), CDISASM_ARM_NAME_LDFF1SB, 3305u, 8u, 1u, 1u },
        { UINT32_C(0xa5a06000), CDISASM_ARM_NAME_LDFF1SB, 3306u, 4u, 1u, 1u },
        { UINT32_C(0xa5c06000), CDISASM_ARM_NAME_LDFF1SB, 3307u, 2u, 1u, 1u },
        { UINT32_C(0xa5e06000), CDISASM_ARM_NAME_LDFF1D, 3308u, 8u, 8u, 1u },
        { UINT32_C(0xa400c000), CDISASM_ARM_NAME_LDNT1B, 3346u, 1u, 1u, 0u },
        { UINT32_C(0xa480c000), CDISASM_ARM_NAME_LDNT1H, 3347u, 2u, 2u, 0u },
        { UINT32_C(0xa500c000), CDISASM_ARM_NAME_LDNT1W, 3348u, 4u, 4u, 0u },
        { UINT32_C(0xa580c000), CDISASM_ARM_NAME_LDNT1D, 3349u, 8u, 8u, 0u }
    };
    const arm_sve_load_register_identity *identity = NULL;
    const cdisasm_arm_operand *list, *memory;
    uint32_t word = instruction->raw_instruction;
    uint32_t operation = word & UINT32_C(0xffe0e000);
    int form_is_family = 0;
    uint8_t shift;
    size_t index;

    for (index = 0u; index < sizeof(identities) / sizeof(identities[0]); ++index) {
        if (identities[index].value == operation
            && instruction->isa_id == CDISASM_ARM_ISA_A64)
            identity = &identities[index];
        if (identities[index].form == instruction->form_id
            && instruction->isa_id == CDISASM_ARM_ISA_A64)
            form_is_family = 1;
    }
    if (identity == NULL && !form_is_family) return 1;
    if (identity == NULL || !form_is_family) return 0;
    if (!identity->first_fault && ((word >> 16) & 31u) == 31u) return 0;
    shift = identity->first_fault && ((word >> 16) & 31u) == 31u ? 0u
        : identity->memory_size == 1u ? 0u
        : identity->memory_size == 2u ? 1u
        : identity->memory_size == 4u ? 2u : 3u;
    if (instruction->name_id != identity->name
        || instruction->form_id != identity->form
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->instruction_flags
            != (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        || instruction->operand_count != 3u) return 0;
    list = &instruction->operand[0]; memory = &instruction->operand[2];
    return list->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
        && list->reg == CDISASM_ARM_REG_Z0 + (word & 31u)
        && list->base_reg == CDISASM_ARM_REG_NONE
        && list->index_reg == CDISASM_ARM_REG_NONE
        && list->register_list == UINT16_C(0x0101)
        && list->address == 0u && list->imm == 0u && list->size == 0u
        && list->flags == CDISASM_OPERAND_FLAG_NONE
        && list->shift_type == CDISASM_ARM_SHIFT_NONE
        && list->shift_amount == 0u
        && list->extend_type == identity->destination_size
        && list->scale == 0u && list->access == CDISASM_OPERAND_ACCESS_WRITE
        && arm_exact_predicate_operand(&instruction->operand[1],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + ((word >> 10) & 7u)),
            identity->destination_size,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO,
            CDISASM_OPERAND_ACCESS_READ)
        && memory->type == CDISASM_OPERAND_MEMORY
        && memory->reg == CDISASM_ARM_REG_NONE
        && memory->base_reg == (((word >> 5) & 31u) == 31u
            ? CDISASM_ARM_REG_SP : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0
                + ((word >> 5) & 31u)))
        && memory->index_reg == (identity->first_fault
                && ((word >> 16) & 31u) == 31u
            ? CDISASM_ARM_REG_NONE : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0
                + ((word >> 16) & 31u)))
        && memory->register_list == 0u && memory->address == 0u
        && memory->imm == 0u && memory->size == identity->memory_size
        && memory->flags == CDISASM_OPERAND_FLAG_NONE
        && memory->shift_type == (shift == 0u
            ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL)
        && memory->shift_amount == shift
        && memory->extend_type == CDISASM_ARM_EXTEND_NONE
        && memory->scale == 0u
        && memory->access == CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sve_contiguous_store_register_schema(
    const cdisasm_arm_instruction *instruction)
{
    typedef struct identity { uint32_t value; cdisasm_arm_name_id name;
        cdisasm_arm_form_id form; uint8_t source_size, memory_size; } identity;
    static const identity identities[] = {
        { UINT32_C(0xe4004000), CDISASM_ARM_NAME_ST1B, 3470u, 1u, 1u },
        { UINT32_C(0xe4204000), CDISASM_ARM_NAME_ST1B, 3470u, 2u, 1u },
        { UINT32_C(0xe4404000), CDISASM_ARM_NAME_ST1B, 3470u, 4u, 1u },
        { UINT32_C(0xe4604000), CDISASM_ARM_NAME_ST1B, 3470u, 8u, 1u },
        { UINT32_C(0xe4a04000), CDISASM_ARM_NAME_ST1H, 3471u, 2u, 2u },
        { UINT32_C(0xe4c04000), CDISASM_ARM_NAME_ST1H, 3471u, 4u, 2u },
        { UINT32_C(0xe4e04000), CDISASM_ARM_NAME_ST1H, 3471u, 8u, 2u },
        { UINT32_C(0xe5404000), CDISASM_ARM_NAME_ST1W, 3473u, 4u, 4u },
        { UINT32_C(0xe5604000), CDISASM_ARM_NAME_ST1W, 3473u, 8u, 4u },
        { UINT32_C(0xe5e04000), CDISASM_ARM_NAME_ST1D, 3475u, 8u, 8u },
        { UINT32_C(0xe4006000), CDISASM_ARM_NAME_STNT1B, 3485u, 1u, 1u },
        { UINT32_C(0xe4806000), CDISASM_ARM_NAME_STNT1H, 3486u, 2u, 2u },
        { UINT32_C(0xe5006000), CDISASM_ARM_NAME_STNT1W, 3487u, 4u, 4u },
        { UINT32_C(0xe5806000), CDISASM_ARM_NAME_STNT1D, 3488u, 8u, 8u }
    };
    const identity *expected = NULL;
    const cdisasm_arm_operand *list, *memory;
    uint32_t word = instruction->raw_instruction;
    uint32_t operation = word & UINT32_C(0xffe0e000);
    int form_is_family = 0;
    uint8_t shift;
    size_t index;

    for (index = 0u; index < sizeof(identities) / sizeof(identities[0]); ++index) {
        if (identities[index].value == operation
            && instruction->isa_id == CDISASM_ARM_ISA_A64)
            expected = &identities[index];
        if (identities[index].form == instruction->form_id
            && instruction->isa_id == CDISASM_ARM_ISA_A64)
            form_is_family = 1;
    }
    if (expected == NULL && !form_is_family) return 1;
    if (expected == NULL || !form_is_family) return 0;
    if (((word >> 16) & 31u) == 31u) return 0;
    shift = expected->memory_size == 1u ? 0u
        : expected->memory_size == 2u ? 1u
        : expected->memory_size == 4u ? 2u : 3u;
    if (instruction->name_id != expected->name
        || instruction->form_id != expected->form
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->instruction_flags
            != (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        || instruction->operand_count != 3u) return 0;
    list = &instruction->operand[0]; memory = &instruction->operand[2];
    return list->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
        && list->reg == CDISASM_ARM_REG_Z0 + (word & 31u)
        && list->base_reg == CDISASM_ARM_REG_NONE
        && list->index_reg == CDISASM_ARM_REG_NONE
        && list->register_list == UINT16_C(0x0101)
        && list->address == 0u && list->imm == 0u && list->size == 0u
        && list->flags == CDISASM_OPERAND_FLAG_NONE
        && list->shift_type == CDISASM_ARM_SHIFT_NONE
        && list->shift_amount == 0u
        && list->extend_type == expected->source_size
        && list->scale == 0u && list->access == CDISASM_OPERAND_ACCESS_READ
        && arm_exact_predicate_operand(&instruction->operand[1],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + ((word >> 10) & 7u)),
            expected->source_size, CDISASM_OPERAND_FLAG_NONE,
            CDISASM_OPERAND_ACCESS_READ)
        && memory->type == CDISASM_OPERAND_MEMORY
        && memory->reg == CDISASM_ARM_REG_NONE
        && memory->base_reg == (((word >> 5) & 31u) == 31u
            ? CDISASM_ARM_REG_SP : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0
                + ((word >> 5) & 31u)))
        && memory->index_reg == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0
            + ((word >> 16) & 31u))
        && memory->register_list == 0u && memory->address == 0u
        && memory->imm == 0u && memory->size == expected->memory_size
        && memory->flags == CDISASM_OPERAND_FLAG_NONE
        && memory->shift_type == (shift == 0u
            ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL)
        && memory->shift_amount == shift
        && memory->extend_type == CDISASM_ARM_EXTEND_NONE
        && memory->scale == 0u
        && memory->access == CDISASM_OPERAND_ACCESS_WRITE;
}

static int arm_valid_sve2p1_q_load_store_schema(
    const cdisasm_arm_instruction *instruction)
{
    typedef struct identity { uint32_t value, mask; cdisasm_arm_name_id name;
        cdisasm_arm_form_id form; uint8_t memory_size, load, immediate; } identity;
    static const identity identities[] = {
        { UINT32_C(0xa5102000), UINT32_C(0xfff0e000), CDISASM_ARM_NAME_LD1W, 3275u, 4u, 1u, 1u },
        { UINT32_C(0xa5902000), UINT32_C(0xfff0e000), CDISASM_ARM_NAME_LD1D, 3276u, 8u, 1u, 1u },
        { UINT32_C(0xa5008000), UINT32_C(0xffe0e000), CDISASM_ARM_NAME_LD1W, 3309u, 4u, 1u, 0u },
        { UINT32_C(0xa5808000), UINT32_C(0xffe0e000), CDISASM_ARM_NAME_LD1D, 3310u, 8u, 1u, 0u },
        { UINT32_C(0xe500e000), UINT32_C(0xfff0e000), CDISASM_ARM_NAME_ST1W, 3529u, 4u, 0u, 1u },
        { UINT32_C(0xe5c0e000), UINT32_C(0xfff0e000), CDISASM_ARM_NAME_ST1D, 3531u, 8u, 0u, 1u },
        { UINT32_C(0xe5004000), UINT32_C(0xffe0e000), CDISASM_ARM_NAME_ST1W, 3472u, 4u, 0u, 0u },
        { UINT32_C(0xe5c04000), UINT32_C(0xffe0e000), CDISASM_ARM_NAME_ST1D, 3474u, 8u, 0u, 0u }
    };
    const identity *expected = NULL;
    const cdisasm_arm_operand *list, *memory;
    uint32_t word = instruction->raw_instruction;
    int form_is_family = 0;
    int64_t displacement = 0;
    uint8_t memory_flags = 0u;
    size_t index;

    for (index = 0; index < sizeof(identities) / sizeof(identities[0]); ++index) {
        if ((word & identities[index].mask) == identities[index].value
            && instruction->isa_id == CDISASM_ARM_ISA_A64)
            expected = &identities[index];
        if (instruction->form_id == identities[index].form
            && instruction->isa_id == CDISASM_ARM_ISA_A64)
            form_is_family = 1;
    }
    if (expected == NULL && !form_is_family) return 1;
    if (expected == NULL || !form_is_family) return 0;
    if (expected->immediate) {
        displacement = (int64_t)((word >> 16) & 15u);
        if (displacement >= 8) displacement -= 16;
        if (displacement != 0) memory_flags = (uint8_t)(
            CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
            | CDISASM_ARM_OPERAND_FLAG_VL_SCALED
            | (displacement < 0 ? CDISASM_OPERAND_FLAG_SIGNED : 0u));
    }
    if (instruction->name_id != expected->name
        || instruction->form_id != expected->form
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->instruction_flags
            != (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        || instruction->operand_count != 3u) return 0;
    list = &instruction->operand[0]; memory = &instruction->operand[2];
    return list->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
        && list->reg == CDISASM_ARM_REG_Z0 + (word & 31u)
        && list->base_reg == CDISASM_ARM_REG_NONE
        && list->index_reg == CDISASM_ARM_REG_NONE
        && list->register_list == UINT16_C(0x0101)
        && list->address == 0u && list->imm == 0u && list->size == 0u
        && list->flags == CDISASM_OPERAND_FLAG_NONE
        && list->shift_type == CDISASM_ARM_SHIFT_NONE
        && list->shift_amount == 0u && list->extend_type == 16u
        && list->scale == 0u
        && list->access == (expected->load ? CDISASM_OPERAND_ACCESS_WRITE
                                           : CDISASM_OPERAND_ACCESS_READ)
        && arm_exact_predicate_operand(&instruction->operand[1],
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + ((word >> 10) & 7u)),
            16u, expected->load ? CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO : 0u,
            CDISASM_OPERAND_ACCESS_READ)
        && memory->type == CDISASM_OPERAND_MEMORY
        && memory->reg == CDISASM_ARM_REG_NONE
        && memory->base_reg == (((word >> 5) & 31u) == 31u
            ? CDISASM_ARM_REG_SP : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0
                + ((word >> 5) & 31u)))
        && memory->index_reg == (expected->immediate
            ? CDISASM_ARM_REG_NONE
            : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0
                + ((word >> 16) & 31u)))
        && memory->register_list == 0u && memory->address == 0u
        && (int64_t)memory->imm == displacement
        && memory->size == expected->memory_size
        && memory->flags == memory_flags
        && memory->shift_type == (expected->immediate
            ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL)
        && memory->shift_amount == (expected->immediate
            ? 0u : expected->memory_size == 4u ? 2u : 3u)
        && memory->extend_type == CDISASM_ARM_EXTEND_NONE
        && memory->scale == 0u
        && memory->access == (expected->load ? CDISASM_OPERAND_ACCESS_READ
                                             : CDISASM_OPERAND_ACCESS_WRITE);
}

static int arm_valid_sve2p1_multi_q_schema(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id load_names[3] = {
        CDISASM_ARM_NAME_LD2Q, CDISASM_ARM_NAME_LD3Q,
        CDISASM_ARM_NAME_LD4Q };
    static const cdisasm_arm_name_id store_names[3] = {
        CDISASM_ARM_NAME_ST2Q, CDISASM_ARM_NAME_ST3Q,
        CDISASM_ARM_NAME_ST4Q };
    uint32_t word = instruction->raw_instruction;
    uint32_t register_value = word & UINT32_C(0xffe0e000);
    uint32_t immediate_value = word & UINT32_C(0xfff0e000);
    int raw_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (register_value == UINT32_C(0xa4a08000)
            || register_value == UINT32_C(0xa5208000)
            || register_value == UINT32_C(0xa5a08000)
            || immediate_value == UINT32_C(0xa490e000)
            || immediate_value == UINT32_C(0xa510e000)
            || immediate_value == UINT32_C(0xa590e000)
            || immediate_value == UINT32_C(0xe4400000)
            || immediate_value == UINT32_C(0xe4800000)
            || immediate_value == UINT32_C(0xe4c00000)
            || register_value == UINT32_C(0xe4600000)
            || register_value == UINT32_C(0xe4a00000)
            || register_value == UINT32_C(0xe4e00000));
    int form_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && ((instruction->form_id >= 3311u && instruction->form_id <= 3313u)
            || (instruction->form_id >= 3378u && instruction->form_id <= 3380u)
            || (instruction->form_id >= 3463u && instruction->form_id <= 3468u));
    int store, immediate;
    unsigned count, index, form_base;
    int64_t displacement;
    const cdisasm_arm_operand *list, *predicate, *memory;
    uint8_t memory_flags;

    if (!raw_family && !form_family) return 1;
    if (!raw_family || !form_family) return 0;
    store = (word & UINT32_C(0x40000000)) != 0u;
    immediate = store ? (word & UINT32_C(0x00200000)) == 0u
        : (word & UINT32_C(0x00006000)) == UINT32_C(0x00006000);
    count = ((word >> (store ? 22u : 23u)) & 3u) + 1u;
    if (count < 2u || count > 4u) return 0;
    index = count - 2u;
    form_base = store ? (immediate ? 3463u : 3466u)
                      : (immediate ? 3378u : 3311u);
    displacement = immediate
        ? (int64_t)((int32_t)(((word >> 16) & 15u) << 28) >> 28)
            * (int64_t)count : 0;
    memory_flags = displacement == 0 ? 0u
        : (uint8_t)(CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
            | CDISASM_ARM_OPERAND_FLAG_VL_SCALED
            | (displacement < 0 ? CDISASM_OPERAND_FLAG_SIGNED : 0u));
    if (instruction->form_id != form_base + index
        || instruction->name_id != (store ? store_names[index]
                                          : load_names[index])
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->instruction_flags
            != (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        || instruction->operand_count != 3u) return 0;
    list=&instruction->operand[0]; predicate=&instruction->operand[1];
    memory=&instruction->operand[2];
    return list->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
        && list->reg == CDISASM_ARM_REG_Z0 + (word & 31u)
        && list->register_list == (uint16_t)(UINT16_C(0x100) | count)
        && list->extend_type == 16u
        && list->access == (store ? CDISASM_OPERAND_ACCESS_READ
                                  : CDISASM_OPERAND_ACCESS_WRITE)
        && predicate->type == CDISASM_ARM_OPERAND_PREDICATE
        && predicate->reg == CDISASM_ARM_REG_P0 + ((word >> 10) & 7u)
        && predicate->extend_type == 16u
        && predicate->flags == (store ? 0u
            : CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO)
        && predicate->access == CDISASM_OPERAND_ACCESS_READ
        && memory->type == CDISASM_OPERAND_MEMORY
        && memory->base_reg == (((word >> 5) & 31u) == 31u
            ? CDISASM_ARM_REG_SP
            : CDISASM_ARM_REG_X0 + ((word >> 5) & 31u))
        && memory->index_reg == (immediate ? CDISASM_ARM_REG_NONE
            : CDISASM_ARM_REG_X0 + ((word >> 16) & 31u))
        && (int64_t)memory->imm == displacement && memory->size == 16u
        && memory->flags == memory_flags
        && memory->shift_type == (immediate ? CDISASM_ARM_SHIFT_NONE
                                            : CDISASM_ARM_SHIFT_LSL)
        && memory->shift_amount == (immediate ? 0u : 4u)
        && memory->access == (store ? CDISASM_OPERAND_ACCESS_WRITE
                                    : CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sve2p1_multi_contiguous_schema(
    const cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id load_names[4] = {
        CDISASM_ARM_NAME_LD1B, CDISASM_ARM_NAME_LD1H,
        CDISASM_ARM_NAME_LD1W, CDISASM_ARM_NAME_LD1D };
    static const cdisasm_arm_name_id store_names[4] = {
        CDISASM_ARM_NAME_ST1B, CDISASM_ARM_NAME_ST1H,
        CDISASM_ARM_NAME_ST1W, CDISASM_ARM_NAME_ST1D };
    static const cdisasm_arm_name_id non_temporal_store_names[4] = {
        CDISASM_ARM_NAME_STNT1B, CDISASM_ARM_NAME_STNT1H,
        CDISASM_ARM_NAME_STNT1W, CDISASM_ARM_NAME_STNT1D };
    static const cdisasm_arm_name_id non_temporal_load_names[4] = {
        CDISASM_ARM_NAME_LDNT1B, CDISASM_ARM_NAME_LDNT1H,
        CDISASM_ARM_NAME_LDNT1W, CDISASM_ARM_NAME_LDNT1D };
    uint32_t word = instruction->raw_instruction;
    unsigned size_log2 = (word >> 13) & 3u;
    unsigned count = (word & UINT32_C(0x8000)) != 0u ? 4u : 2u;
    int store = (word & UINT32_C(0x200000)) != 0u;
    int immediate = (word & UINT32_C(0x400000)) != 0u;
    int strided = (word & UINT32_C(0x01000000)) != 0u;
    int non_temporal =
        (word & (strided ? UINT32_C(0x8) : UINT32_C(0x1))) != 0u;
    uint32_t value = UINT32_C(0xa0000000) | ((uint32_t)strided << 24)
        | ((uint32_t)immediate << 22)
        | ((uint32_t)store << 21) | (count == 4u ? UINT32_C(0x8000) : 0u)
        | ((uint32_t)size_log2 << 13)
        | (non_temporal ? (strided ? UINT32_C(0x8) : UINT32_C(0x1)) : 0u);
    uint32_t mask = immediate
        ? (count == 4u ? (strided ? UINT32_C(0xfff0e00c) : UINT32_C(0xfff0e003))
                       : (strided ? UINT32_C(0xfff0e008) : UINT32_C(0xfff0e001)))
        : (count == 4u ? (strided ? UINT32_C(0xffe0e00c) : UINT32_C(0xffe0e003))
                       : (strided ? UINT32_C(0xffe0e008) : UINT32_C(0xffe0e001)));
    int raw_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && (word & mask) == value;
    int form_family = instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id >= UINT16_C(3549)
        && instruction->form_id <= UINT16_C(3676);
    unsigned base = strided
        ? (immediate ? (store ? 3661u : 3645u) : (store ? 3629u : 3613u))
        : (immediate ? (store ? 3597u : 3581u) : (store ? 3565u : 3549u));
    uint8_t size = (uint8_t)(1u << size_log2);
    int64_t displacement = immediate
        ? ((int64_t)((word >> 16) & 15u) >= 8
            ? (int64_t)((word >> 16) & 15u) - 16
            : (int64_t)((word >> 16) & 15u)) * (int64_t)count : 0;
    const cdisasm_arm_operand *list, *predicate, *memory;
    uint8_t memory_flags = displacement == 0 ? 0u
        : (uint8_t)(CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
            | CDISASM_ARM_OPERAND_FLAG_VL_SCALED
            | (displacement < 0 ? CDISASM_OPERAND_FLAG_SIGNED : 0u));
    if (!raw_family && !form_family) return 1;
    if (!raw_family || !form_family) return 0;
    if (count == 4u) base += 8u;
    if (instruction->form_id != base + size_log2 * 2u
            + (non_temporal ? 1u : 0u)
        || instruction->name_id != (non_temporal
            ? (store ? non_temporal_store_names[size_log2]
                     : non_temporal_load_names[size_log2])
            : (store ? store_names[size_log2] : load_names[size_log2]))
        || instruction->condition != CDISASM_ARM_CONDITION_AL
        || instruction->opcode_groups != CDISASM_GROUP_NONE
        || instruction->instruction_flags != (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
            | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
            | (strided ? CDISASM_ARM_INSTRUCTION_FLAG_SME : 0u))
        || instruction->operand_count != 3u) return 0;
    list=&instruction->operand[0]; predicate=&instruction->operand[1]; memory=&instruction->operand[2];
    return list->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
        && list->reg == CDISASM_ARM_REG_Z0 + (strided
            ? word & (count == 4u ? 3u : 7u)
            : non_temporal ? ((word & 31u) + 31u) & 31u : word & 31u)
        && list->register_list == (uint16_t)(((strided
            ? (count == 4u ? 4u : 8u) : 1u) << 8) | count)
        && list->extend_type == size && list->access == (store ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE)
        && predicate->type == CDISASM_ARM_OPERAND_PREDICATE
        && predicate->reg == CDISASM_ARM_REG_PN8 + ((word >> 10) & 7u)
        && predicate->extend_type == size && predicate->flags == (store ? 0u : CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO)
        && predicate->access == CDISASM_OPERAND_ACCESS_READ
        && memory->type == CDISASM_OPERAND_MEMORY
        && memory->base_reg == (((word >> 5) & 31u) == 31u ? CDISASM_ARM_REG_SP : CDISASM_ARM_REG_X0 + ((word >> 5) & 31u))
        && memory->index_reg == (immediate ? CDISASM_ARM_REG_NONE : CDISASM_ARM_REG_X0 + ((word >> 16) & 31u))
        && (int64_t)memory->imm == displacement && memory->size == size
        && memory->flags == memory_flags
        && memory->shift_type == (!immediate && size_log2 ? CDISASM_ARM_SHIFT_LSL : CDISASM_ARM_SHIFT_NONE)
        && memory->shift_amount == (immediate ? 0u : size_log2)
        && memory->access == (store ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_t32_wide_cps_schema(
    const cdisasm_arm_instruction *instruction)
{
    uint32_t word = (instruction->raw_instruction << 16)
        | (instruction->raw_instruction >> 16);
    int raw_family = instruction->isa_id == CDISASM_ARM_ISA_T32
        && (word & UINT32_C(0xfffffc00)) == UINT32_C(0xf3af8400);
    int form_family = instruction->isa_id == CDISASM_ARM_ISA_T32
        && instruction->form_id >= UINT16_C(1837)
        && instruction->form_id <= UINT16_C(1840);
    unsigned control = (word >> 8) & 3u;
    int disable = (control & 2u) != 0u;
    int change_mode = (control & 1u) != 0u;
    cdisasm_arm_form_id form = (cdisasm_arm_form_id)(disable
        ? (change_mode ? 1838u : 1837u)
        : (change_mode ? 1840u : 1839u));
    if (!raw_family && !form_family) return 1;
    if (!raw_family || !form_family || (!change_mode && (word & 31u) != 0u)) return 0;
    return instruction->name_id == (disable ? CDISASM_ARM_NAME_CPSID : CDISASM_ARM_NAME_CPSIE)
        && instruction->form_id == form
        && instruction->condition == CDISASM_ARM_CONDITION_AL
        && instruction->opcode_groups == CDISASM_GROUP_PRIVILEGED
        && instruction->instruction_flags == 0u
        && instruction->operand_count == (change_mode ? 2u : 1u)
        && arm_exact_immediate_operand(&instruction->operand[0], (word >> 5) & 7u)
        && (!change_mode || arm_exact_immediate_operand(&instruction->operand[1], word & 31u));
}

static int arm_valid_sme_fmopa_schema(const cdisasm_arm_instruction *instruction)
{
    typedef struct I{uint32_t mask,value;uint16_t form;uint8_t dst,src;}I;
    static const I ids[]={{0xffe0001c,0x80800000,3785,4,4},{0xffe0001c,0x81a00000,3789,4,2},{0xffe0001c,0x80a00000,3791,4,1},{0xffe0001e,0x80a00008,3794,2,1},{0xffe0001e,0x81800008,3795,2,2},{0xffe00018,0x80c00000,3811,8,8}};
    const I *id=NULL;int form=0;size_t n;uint32_t w=instruction->raw_instruction;
    for(n=0;n<sizeof(ids)/sizeof(ids[0]);n++){if((w&ids[n].mask)==ids[n].value&&instruction->isa_id==CDISASM_ARM_ISA_A64)id=&ids[n];if(instruction->form_id==ids[n].form&&instruction->isa_id==CDISASM_ARM_ISA_A64)form=1;}
    if(id==NULL&&!form)return 1;if(id==NULL||!form)return 0;
    {const cdisasm_arm_operand *t=&instruction->operand[0],*p=&instruction->operand[1];unsigned tm=id->dst==2?1:id->dst==8?7:3;cdisasm_arm_reg_id tb=id->dst==2?CDISASM_ARM_REG_ZAH0:id->dst==8?CDISASM_ARM_REG_ZAD0:CDISASM_ARM_REG_ZAS0;
    return instruction->name_id==CDISASM_ARM_NAME_FMOPA&&instruction->form_id==id->form&&instruction->condition==CDISASM_ARM_CONDITION_AL&&instruction->opcode_groups==CDISASM_GROUP_NONE&&instruction->instruction_flags==UINT32_C(0x05c02000)&&instruction->operand_count==4
      &&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==tb+(w&tm)&&t->extend_type==id->dst&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE
      &&p->type==CDISASM_ARM_OPERAND_PREDICATE_PAIR&&p->reg==CDISASM_ARM_REG_P0+((w>>10)&7)&&p->index_reg==CDISASM_ARM_REG_P0+((w>>13)&7)&&p->extend_type==id->dst&&p->flags==CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE&&p->access==CDISASM_OPERAND_ACCESS_READ
      &&arm_exact_scalable_operand(&instruction->operand[2],CDISASM_ARM_REG_Z0+((w>>5)&31),id->src,CDISASM_OPERAND_ACCESS_READ)
      &&arm_exact_scalable_operand(&instruction->operand[3],CDISASM_ARM_REG_Z0+((w>>16)&31),id->src,CDISASM_OPERAND_ACCESS_READ);}
}

static int arm_valid_sme2_zero_zt0_schema(const cdisasm_arm_instruction *i)
{
    int raw=i->isa_id==CDISASM_ARM_ISA_A64&&i->raw_instruction==UINT32_C(0xc0480001);
    int form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id==UINT16_C(3916);
    const cdisasm_arm_operand *o=&i->operand[0];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==CDISASM_ARM_NAME_ZERO&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SME|CDISASM_ARM_INSTRUCTION_FLAG_MATRIX)&&i->operand_count==1&&o->type==CDISASM_ARM_OPERAND_TILE&&o->reg==CDISASM_ARM_REG_ZT0&&o->base_reg==CDISASM_ARM_REG_NONE&&o->index_reg==CDISASM_ARM_REG_NONE&&o->imm==0&&o->size==0&&o->flags==0&&o->extend_type==0&&o->access==CDISASM_OPERAND_ACCESS_WRITE;
}

static int arm_valid_sme_zero_mask_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;
    int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0xffffff00))==UINT32_C(0xc0080000);
    int form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id==UINT16_C(3907);
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==CDISASM_ARM_NAME_ZERO&&i->condition==CDISASM_ARM_CONDITION_AL
      &&i->opcode_groups==CDISASM_GROUP_NONE
      &&i->instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SME|CDISASM_ARM_INSTRUCTION_FLAG_MATRIX)
      &&i->operand_count==1&&arm_exact_immediate_operand(&i->operand[0],w&255u);
}

static int arm_valid_sme2_luti_zt0_schema(const cdisasm_arm_instruction *i)
{
    typedef struct L{uint32_t m,v;uint16_t f;uint8_t count,l4,shift,bits;}L;
    static const L ids[]={
      {0xfffc4c01,0xc08c4000,3920,2,0,15,3},{0xfffe4c01,0xc08a4000,3921,2,1,15,2},
      {0xfffccc03,0xc08c8000,3922,4,0,16,2},{0xfffecc03,0xc08a8000,3923,4,1,16,1},
      {0xfffc0c00,0xc0cc0000,3924,1,0,14,4},{0xfffe0c00,0xc0ca0000,3925,1,1,14,3}};
    const L*x=NULL;int form=0;size_t n;uint32_t w=i->raw_instruction;
    for(n=0;n<6;n++){if(i->isa_id==CDISASM_ARM_ISA_A64&&(w&ids[n].m)==ids[n].v)x=&ids[n];if(i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id==ids[n].f)form=1;}
    if(x==NULL&&!form)return 1;if(x==NULL||!form||((w>>12)&3)>1)return 0;
    {unsigned size=1u<<((w>>12)&3),zd=x->count==2?w&30u:x->count==4?w&28u:w&31u,lane=(w>>x->shift)&((1u<<x->bits)-1u);const cdisasm_arm_operand*d=&i->operand[0],*t=&i->operand[1],*s=&i->operand[2];
    return i->name_id==(x->l4?CDISASM_ARM_NAME_LUTI4:CDISASM_ARM_NAME_LUTI2)&&i->form_id==x->f
      &&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05400000)&&i->operand_count==3
      &&(x->count==1?arm_exact_scalable_operand(d,CDISASM_ARM_REG_Z0+zd,(uint8_t)size,CDISASM_OPERAND_ACCESS_WRITE)
        :(d->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&d->reg==CDISASM_ARM_REG_Z0+zd&&d->register_list==(UINT16_C(0x0100)|x->count)&&d->extend_type==size&&d->access==CDISASM_OPERAND_ACCESS_WRITE))
      &&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZT0&&t->base_reg==CDISASM_ARM_REG_NONE&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==0&&t->imm==0&&t->size==0&&t->flags==0&&t->extend_type==0&&t->access==CDISASM_OPERAND_ACCESS_READ
      &&arm_exact_scalable_lane_operand(s,CDISASM_ARM_REG_Z0+((w>>5)&31),(uint8_t)size,lane,CDISASM_OPERAND_ACCESS_READ);}
}

static int arm_valid_sme_luti_extended_schema(const cdisasm_arm_instruction *i)
{
    typedef struct L{uint32_t m,v;uint16_t f;uint8_t count,stride,l4,shift,bits,mode;}L;
    static const L ids[]={
      {0xffffcc23,0xc08b0000,3927,4,1,1,0,0,1},
      {0xfffc4c08,0xc09c4000,3933,2,8,0,15,3,0},{0xfffe4c08,0xc09a4000,3934,2,8,1,15,2,0},
      {0xfffccc0c,0xc09c8000,3935,4,4,0,16,2,0},{0xfffecc0c,0xc09a8000,3936,4,4,1,16,1,2},
      {0xffffcc2c,0xc09b0000,3937,4,4,1,0,0,1}};
    const L*x=NULL;int form=0;size_t n;uint32_t w=i->raw_instruction;unsigned sc=(w>>12)&3;
    for(n=0;n<6;n++){if(i->isa_id==CDISASM_ARM_ISA_A64&&(w&ids[n].m)==ids[n].v)x=&ids[n];if(i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id==ids[n].f)form=1;}
    if(x==NULL&&!form)return 1;if(x==NULL||!form||(x->mode==1?sc!=0:x->mode==2?sc!=1:sc>1))return 0;
    {unsigned size=1u<<sc,zd=x->stride==1?w&28u:(((w>>4)&1)<<4)|(w&(x->count==2?7u:3u));const cdisasm_arm_operand*d=&i->operand[0],*t=&i->operand[1],*s=&i->operand[2];
    if(!(i->name_id==(x->l4?CDISASM_ARM_NAME_LUTI4:CDISASM_ARM_NAME_LUTI2)&&i->form_id==x->f&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05400000)&&i->operand_count==3
      &&d->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&d->reg==CDISASM_ARM_REG_Z0+zd&&d->register_list==((uint16_t)x->stride<<8|x->count)&&d->extend_type==size&&d->access==CDISASM_OPERAND_ACCESS_WRITE
      &&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZT0&&t->base_reg==CDISASM_ARM_REG_NONE&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==0&&t->imm==0&&t->size==0&&t->flags==0&&t->extend_type==0&&t->access==CDISASM_OPERAND_ACCESS_READ))return 0;
    if(x->mode==1)return s->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&s->reg==CDISASM_ARM_REG_Z0+(((w>>6)&15)*2)&&s->register_list==UINT16_C(0x0102)&&s->extend_type==1&&s->access==CDISASM_OPERAND_ACCESS_READ;
    return arm_exact_scalable_lane_operand(s,CDISASM_ARM_REG_Z0+((w>>5)&31),(uint8_t)size,(w>>x->shift)&((1u<<x->bits)-1u),CDISASM_OPERAND_ACCESS_READ);}
}

static int arm_valid_sme_fp8_indexed_long_mla_single_schema(const cdisasm_arm_instruction*i)
{
    uint32_t w=i->raw_instruction;int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0xfff01010))==UINT32_C(0xc1c00000);int form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id==3954;const cdisasm_arm_operand*t=&i->operand[0];uint64_t lane=(((w>>15)&1u)<<3)|(((w>>10)&3u)<<1)|((w>>3)&1u);
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==CDISASM_ARM_NAME_FMLAL&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05402000)&&i->operand_count==3&&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3u)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==2&&t->imm==(w&7u)*2u&&t->size==0&&t->flags==0&&t->extend_type==2&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE&&arm_exact_scalable_operand(&i->operand[1],CDISASM_ARM_REG_Z0+((w>>5)&31u),1,CDISASM_OPERAND_ACCESS_READ)&&arm_exact_scalable_lane_operand(&i->operand[2],CDISASM_ARM_REG_Z0+((w>>16)&15u),1,lane,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sme2_indexed_fp_long_mla_single_schema(const cdisasm_arm_instruction*i)
{
    uint32_t w=i->raw_instruction,op=(w>>3)&3u;int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0xfff01018))==(UINT32_C(0xc1801000)|(op<<3));int form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=3950&&i->form_id<=3953;uint16_t fid=op==0?3951:op==1?3953:op==2?3950:3952;cdisasm_arm_name_id name=op==0?CDISASM_ARM_NAME_FMLAL:op==1?CDISASM_ARM_NAME_FMLSL:op==2?CDISASM_ARM_NAME_BFMLAL:CDISASM_ARM_NAME_BFMLSL;const cdisasm_arm_operand*t=&i->operand[0];uint64_t lane=((w>>13)&4u)|((w>>10)&3u);
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->form_id==fid&&i->name_id==name&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05402000)&&i->operand_count==3&&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3u)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==2&&t->imm==(w&7u)*2u&&t->size==0&&t->flags==0&&t->extend_type==4&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE&&arm_exact_scalable_operand(&i->operand[1],CDISASM_ARM_REG_Z0+((w>>5)&31u),2,CDISASM_OPERAND_ACCESS_READ)&&arm_exact_scalable_lane_operand(&i->operand[2],CDISASM_ARM_REG_Z0+((w>>16)&15u),2,lane,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sme2_indexed_fp_long_mla2_schema(const cdisasm_arm_instruction*i)
{
    static const cdisasm_arm_name_id names[4]={CDISASM_ARM_NAME_FMLAL,CDISASM_ARM_NAME_FMLSL,CDISASM_ARM_NAME_BFMLAL,CDISASM_ARM_NAME_BFMLSL};static const uint16_t forms[4]={3990,3992,3989,3991};uint32_t w=i->raw_instruction;unsigned op=(w>>3)&3u,lane=((w>>9)&6u)|((w>>2)&1u),zn=((w>>6)&15u)*2u;int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0xfff09038))==(UINT32_C(0xc1901000)|(op<<3));int form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=3989&&i->form_id<=3992;const cdisasm_arm_operand*t=&i->operand[0],*l=&i->operand[1];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==names[op]&&i->form_id==forms[op]&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05402000)&&i->operand_count==3&&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3u)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==2&&t->imm==(w&3u)*2u&&t->size==0&&t->flags==0&&t->extend_type==4&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE&&l->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&l->reg==CDISASM_ARM_REG_Z0+zn&&l->register_list==UINT16_C(0x0102)&&l->extend_type==2&&l->access==CDISASM_OPERAND_ACCESS_READ&&arm_exact_scalable_lane_operand(&i->operand[2],CDISASM_ARM_REG_Z0+((w>>16)&15u),2,lane,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sme2_indexed_fp_long_mla4_schema(const cdisasm_arm_instruction*i)
{
    static const cdisasm_arm_name_id names[4]={CDISASM_ARM_NAME_FMLAL,CDISASM_ARM_NAME_FMLSL,CDISASM_ARM_NAME_BFMLAL,CDISASM_ARM_NAME_BFMLSL};static const uint16_t forms[4]={4038,4040,4037,4039};uint32_t w=i->raw_instruction;unsigned op=(w>>3)&3u,lane=((w>>9)&6u)|((w>>2)&1u),zn=((w>>7)&7u)*4u;int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0xfff09078))==(UINT32_C(0xc1909000)|(op<<3));int form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=4037&&i->form_id<=4040;const cdisasm_arm_operand*t=&i->operand[0],*l=&i->operand[1];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==names[op]&&i->form_id==forms[op]&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05402000)&&i->operand_count==3&&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3u)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==4&&t->imm==(w&3u)*2u&&t->size==0&&t->flags==0&&t->extend_type==4&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE&&l->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&l->reg==CDISASM_ARM_REG_Z0+zn&&l->register_list==UINT16_C(0x0104)&&l->extend_type==2&&l->access==CDISASM_OPERAND_ACCESS_READ&&arm_exact_scalable_lane_operand(&i->operand[2],CDISASM_ARM_REG_Z0+((w>>16)&15u),2,lane,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sme_fp8_indexed_long_mla_multi_schema(const cdisasm_arm_instruction*i)
{
    uint32_t w=i->raw_instruction;unsigned count=(w&UINT32_C(0x8000))?4u:2u,lane=(((w>>12)&1u)<<3)|(((w>>10)&3u)<<1)|((w>>3)&1u),zn=count==4?((w>>7)&7u)*4u:((w>>6)&15u)*2u;uint32_t mask=count==4?UINT32_C(0xfff09070):UINT32_C(0xfff09030),value=count==4?UINT32_C(0xc1909020):UINT32_C(0xc1901030);int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&mask)==value;int form=i->isa_id==CDISASM_ARM_ISA_A64&&(i->form_id==3993||i->form_id==4041);const cdisasm_arm_operand*t=&i->operand[0],*l=&i->operand[1];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==CDISASM_ARM_NAME_FMLAL&&i->form_id==(count==4?4041:3993)&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05402000)&&i->operand_count==3&&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3u)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==count&&t->imm==(w&3u)*2u&&t->size==0&&t->flags==0&&t->extend_type==2&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE&&l->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&l->reg==CDISASM_ARM_REG_Z0+zn&&l->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&l->extend_type==1&&l->access==CDISASM_OPERAND_ACCESS_READ&&arm_exact_scalable_lane_operand(&i->operand[2],CDISASM_ARM_REG_Z0+((w>>16)&15u),1,lane,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sme2_indexed_long_mla_schema(const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id names[4]={CDISASM_ARM_NAME_SMLAL,CDISASM_ARM_NAME_SMLSL,CDISASM_ARM_NAME_UMLAL,CDISASM_ARM_NAME_UMLSL};
    uint32_t w=i->raw_instruction;unsigned op=(w>>3)&3,lane=((w>>13)&4)|((w>>10)&3);int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0xfff01018))==(UINT32_C(0xc1c01000)|(op<<3));int form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=3955&&i->form_id<=3958;const cdisasm_arm_operand*t=&i->operand[0];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==names[op]&&i->form_id==3955+op&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05400000)&&i->operand_count==3
      &&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==2&&t->imm==(w&7)*2&&t->size==0&&t->flags==0&&t->extend_type==4&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE
      &&arm_exact_scalable_operand(&i->operand[1],CDISASM_ARM_REG_Z0+((w>>5)&31),2,CDISASM_OPERAND_ACCESS_READ)
      &&arm_exact_scalable_lane_operand(&i->operand[2],CDISASM_ARM_REG_Z0+((w>>16)&15),2,lane,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sme2_indexed_long_mla4_schema(const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id names[4]={CDISASM_ARM_NAME_SMLAL,CDISASM_ARM_NAME_SMLSL,CDISASM_ARM_NAME_UMLAL,CDISASM_ARM_NAME_UMLSL};
    uint32_t w=i->raw_instruction;unsigned op=(w>>3)&3,lane=((w>>9)&6)|((w>>2)&1),count=(w&UINT32_C(0x8000))?4:2,zn=count==4?((w>>7)&7)*4:((w>>6)&15)*2;uint32_t mask=count==4?UINT32_C(0xfff09078):UINT32_C(0xfff09038),value=count==4?UINT32_C(0xc1d09000):UINT32_C(0xc1d01000);int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&mask)==(value|(op<<3));int form=i->isa_id==CDISASM_ARM_ISA_A64&&((i->form_id>=4000&&i->form_id<=4003)||(i->form_id>=4048&&i->form_id<=4051));const cdisasm_arm_operand*t=&i->operand[0],*l=&i->operand[1];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==names[op]&&i->form_id==(count==4?4048:4000)+op&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05400000)&&i->operand_count==3
      &&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==count&&t->imm==(w&3)*2&&t->size==0&&t->flags==0&&t->extend_type==4&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE
      &&l->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&l->reg==CDISASM_ARM_REG_Z0+zn&&l->register_list==(uint16_t)(0x0100|count)&&l->extend_type==2&&l->access==CDISASM_OPERAND_ACCESS_READ
      &&arm_exact_scalable_lane_operand(&i->operand[2],CDISASM_ARM_REG_Z0+((w>>16)&15),2,lane,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sme2_multi_long_mla_schema(const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id names[4]={CDISASM_ARM_NAME_SMLAL,CDISASM_ARM_NAME_SMLSL,CDISASM_ARM_NAME_UMLAL,CDISASM_ARM_NAME_UMLSL};
    uint32_t w=i->raw_instruction;unsigned op=(w>>3)&3,count=(w&UINT32_C(0x10000))?4:2,zn=count==4?((w>>7)&7)*4:((w>>6)&15)*2,zm=(w>>16)&(count==4?28:30);uint32_t mask=count==4?UINT32_C(0xffe39c7c):UINT32_C(0xffe19c3c),value=count==4?UINT32_C(0xc1e10800):UINT32_C(0xc1e00800);int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&mask)==(value|(op<<3));int form=i->isa_id==CDISASM_ARM_ISA_A64&&((i->form_id>=4146&&i->form_id<=4149)||(i->form_id>=4186&&i->form_id<=4189));const cdisasm_arm_operand*t=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==names[op]&&i->form_id==(count==4?4186:4146)+op&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05400000)&&i->operand_count==3
      &&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==count&&t->imm==(w&3)*2&&t->size==0&&t->flags==0&&t->extend_type==4&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE
      &&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&n->reg==CDISASM_ARM_REG_Z0+zn&&n->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&n->extend_type==2&&n->access==CDISASM_OPERAND_ACCESS_READ
      &&m->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&m->reg==CDISASM_ARM_REG_Z0+zm&&m->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&m->extend_type==2&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sme_fp_long_mla_multi_schema(const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id names[4]={CDISASM_ARM_NAME_FMLAL,CDISASM_ARM_NAME_FMLSL,CDISASM_ARM_NAME_BFMLAL,CDISASM_ARM_NAME_BFMLSL};static const uint16_t forms2[4]={4142,4144,4141,4143},forms4[4]={4182,4184,4181,4183};
    uint32_t w=i->raw_instruction;unsigned op=(w>>3)&3u,count=(w&UINT32_C(0x10000))?4u:2u;int fp8=(w&UINT32_C(0x20))!=0;uint32_t mask=count==4?UINT32_C(0xffe39c7c):UINT32_C(0xffe19c3c),value=(count==4?UINT32_C(0xc1a10800):UINT32_C(0xc1a00800))|(fp8?UINT32_C(0x20):(op<<3));uint16_t expected=fp8?(count==4?4185:4145):(count==4?forms4[op]:forms2[op]);int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&mask)==value;int form=i->isa_id==CDISASM_ARM_ISA_A64&&((i->form_id>=4141&&i->form_id<=4145)||(i->form_id>=4181&&i->form_id<=4185));const cdisasm_arm_operand*t=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];unsigned size=fp8?1u:2u,zn=count==4?((w>>7)&7u)*4u:((w>>6)&15u)*2u,zm=(w>>16)&(count==4?28u:30u);
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==(fp8?CDISASM_ARM_NAME_FMLAL:names[op])&&i->form_id==expected&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05402000)&&i->operand_count==3&&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3u)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==count&&t->imm==(w&3u)*2u&&t->size==0&&t->flags==0&&t->extend_type==(fp8?2u:4u)&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE&&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&n->reg==CDISASM_ARM_REG_Z0+zn&&n->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&n->extend_type==size&&n->access==CDISASM_OPERAND_ACCESS_READ&&m->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&m->reg==CDISASM_ARM_REG_Z0+zm&&m->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&m->extend_type==size&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sme2_fp_long_mla_schema(const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id names[4]={CDISASM_ARM_NAME_FMLAL,CDISASM_ARM_NAME_FMLSL,CDISASM_ARM_NAME_BFMLAL,CDISASM_ARM_NAME_BFMLSL};
    static const uint16_t forms2[4]={4065,4068,4064,4067},forms1[4]={4074,4076,4073,4075},forms4[4]={4108,4111,4107,4110};
    uint32_t w=i->raw_instruction;unsigned op=(w>>3)&3u;int single=(w&UINT32_C(0xfff09c18))==(UINT32_C(0xc1200c00)|(op<<3));unsigned count=single?1u:((w&UINT32_C(0x00100000))?4u:2u);uint32_t mask=count==4?UINT32_C(0xfff09c1c):count==2?UINT32_C(0xfff09c1c):UINT32_C(0xfff09c18),value=count==4?UINT32_C(0xc1300800):count==2?UINT32_C(0xc1200800):UINT32_C(0xc1200c00);int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&mask)==(value|(op<<3));int form=i->isa_id==CDISASM_ARM_ISA_A64&&(((i->form_id>=4064&&i->form_id<=4068)&&i->form_id!=4066)||(i->form_id>=4073&&i->form_id<=4076)||((i->form_id>=4107&&i->form_id<=4111)&&i->form_id!=4109));const cdisasm_arm_operand*t=&i->operand[0];uint16_t expected=count==4?forms4[op]:count==2?forms2[op]:forms1[op];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    if(!(i->name_id==names[op]&&i->form_id==expected&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05402000)&&i->operand_count==3&&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3u)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==(single?2u:count)&&t->imm==((w&(single?7u:3u))*2u)&&t->size==0&&t->flags==0&&t->extend_type==4&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE))return 0;
    if(single)return arm_exact_scalable_operand(&i->operand[1],CDISASM_ARM_REG_Z0+((w>>5)&31u),2,CDISASM_OPERAND_ACCESS_READ)&&arm_exact_scalable_operand(&i->operand[2],CDISASM_ARM_REG_Z0+((w>>16)&15u),2,CDISASM_OPERAND_ACCESS_READ);
    {unsigned zn=count==4?(w>>5)&28u:(w>>5)&30u;const cdisasm_arm_operand*n=&i->operand[1];return n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&n->reg==CDISASM_ARM_REG_Z0+zn&&n->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&n->extend_type==2&&n->access==CDISASM_OPERAND_ACCESS_READ&&arm_exact_scalable_operand(&i->operand[2],CDISASM_ARM_REG_Z0+((w>>16)&15u),2,CDISASM_OPERAND_ACCESS_READ);}
}

static int arm_valid_sme_fp8_long_mla_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;int single=(w&UINT32_C(0xfff09c18))==UINT32_C(0xc1300c00);unsigned count=single?1u:((w&UINT32_C(0x00100000))?4u:2u);uint32_t mask=single?UINT32_C(0xfff09c18):UINT32_C(0xfff09c1c),value=single?UINT32_C(0xc1300c00):count==4?UINT32_C(0xc1300804):UINT32_C(0xc1200804);uint16_t expected=single?4116:count==4?4109:4066;int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&mask)==value;int form=i->isa_id==CDISASM_ARM_ISA_A64&&(i->form_id==4066||i->form_id==4109||i->form_id==4116);const cdisasm_arm_operand*t=&i->operand[0];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    if(!(i->name_id==CDISASM_ARM_NAME_FMLAL&&i->form_id==expected&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05402000)&&i->operand_count==3&&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3u)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==(single?2u:count)&&t->imm==((w&(single?7u:3u))*2u)&&t->size==0&&t->flags==0&&t->extend_type==2&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE))return 0;
    if(single)return arm_exact_scalable_operand(&i->operand[1],CDISASM_ARM_REG_Z0+((w>>5)&31u),1,CDISASM_OPERAND_ACCESS_READ)&&arm_exact_scalable_operand(&i->operand[2],CDISASM_ARM_REG_Z0+((w>>16)&15u),1,CDISASM_OPERAND_ACCESS_READ);
    {unsigned zn=count==4?(w>>5)&28u:(w>>5)&30u;const cdisasm_arm_operand*n=&i->operand[1];return n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&n->reg==CDISASM_ARM_REG_Z0+zn&&n->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&n->extend_type==1&&n->access==CDISASM_OPERAND_ACCESS_READ&&arm_exact_scalable_operand(&i->operand[2],CDISASM_ARM_REG_Z0+((w>>16)&15u),1,CDISASM_OPERAND_ACCESS_READ);}
}

static int arm_valid_sme_multi_fp16_mla_schema(const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id names[4]={CDISASM_ARM_NAME_FMLA,CDISASM_ARM_NAME_BFMLA,CDISASM_ARM_NAME_FMLS,CDISASM_ARM_NAME_BFMLS};
    uint32_t w=i->raw_instruction;unsigned bf=(w>>22)&1,sub=(w>>4)&1,op=(sub<<1)|bf,count=(w&UINT32_C(0x10000))?4:2,zn=count==4?((w>>7)&7)*4:((w>>6)&15)*2,zm=(w>>16)&(count==4?28:30);uint32_t mask=count==4?UINT32_C(0xffe39c78):UINT32_C(0xffe19c38),value=(bf?(count==4?UINT32_C(0xc1e11008):UINT32_C(0xc1e01008)):(count==4?UINT32_C(0xc1a11008):UINT32_C(0xc1a01008)))|(sub<<4);int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&mask)==value;int form=i->isa_id==CDISASM_ARM_ISA_A64&&((i->form_id>=4154&&i->form_id<=4157)||(i->form_id>=4194&&i->form_id<=4197));const cdisasm_arm_operand*t=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==names[op]&&i->form_id==(count==4?4194:4154)+op&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05402000)&&i->operand_count==3
      &&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==count&&t->imm==(w&7)&&t->size==0&&t->flags==0&&t->extend_type==2&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE
      &&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&n->reg==CDISASM_ARM_REG_Z0+zn&&n->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&n->extend_type==2&&n->access==CDISASM_OPERAND_ACCESS_READ
      &&m->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&m->reg==CDISASM_ARM_REG_Z0+zm&&m->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&m->extend_type==2&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sme2_multi_dot_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;unsigned wide=(w>>22)&1,special=(w>>3)&1,u=(w>>4)&1,count=(w&UINT32_C(0x10000))?4:2,ss=wide?2:1,ds=special?4:(wide?8:4),zn=count==4?((w>>7)&7)*4:((w>>6)&15)*2,zm=(w>>16)&(count==4?28:30);uint16_t expected=count==4?(special?(wide?4201+u:4200):4198+u):(special?(wide?4161+u:4160):4158+u);cdisasm_arm_name_id name=special&&!wide?CDISASM_ARM_NAME_USDOT:(u?CDISASM_ARM_NAME_UDOT:CDISASM_ARM_NAME_SDOT);uint32_t mask=count==4?(special?UINT32_C(0xffe39c78):UINT32_C(0xffa39c78)):(special?UINT32_C(0xffe19c38):UINT32_C(0xffa19c38)),value=count==4?(special?(wide?(UINT32_C(0xc1e11408)|(u<<4)):UINT32_C(0xc1a11408)):(UINT32_C(0xc1a11400)|(u<<4))):(special?(wide?(UINT32_C(0xc1e01408)|(u<<4)):UINT32_C(0xc1a01408)):(UINT32_C(0xc1a01400)|(u<<4)));int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&mask)==value&&!(special&&!wide&&u);int form=i->isa_id==CDISASM_ARM_ISA_A64&&((i->form_id>=4158&&i->form_id<=4162)||(i->form_id>=4198&&i->form_id<=4202));const cdisasm_arm_operand*t=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==name&&i->form_id==expected&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05400000)&&i->operand_count==3
      &&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==count&&t->imm==(w&7)&&t->size==0&&t->flags==0&&t->extend_type==ds&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE
      &&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&n->reg==CDISASM_ARM_REG_Z0+zn&&n->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&n->extend_type==ss&&n->access==CDISASM_OPERAND_ACCESS_READ
      &&m->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&m->reg==CDISASM_ARM_REG_Z0+zm&&m->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&m->extend_type==ss&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sme2_multi_fp_mla_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;unsigned wide=(w>>22)&1,sub=(w>>3)&1,count=(w&UINT32_C(0x10000))?4:2,size=wide?8:4,zn=count==4?((w>>7)&7)*4:((w>>6)&15)*2,zm=(w>>16)&(count==4?28:30);uint32_t mask=count==4?UINT32_C(0xffa39c78):UINT32_C(0xffa19c38),value=(count==4?UINT32_C(0xc1a11800):UINT32_C(0xc1a01800))|(sub<<3);uint16_t expected=(count==4?4203:4163)+sub;int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&mask)==value;int form=i->isa_id==CDISASM_ARM_ISA_A64&&(i->form_id==4163||i->form_id==4164||i->form_id==4203||i->form_id==4204);const cdisasm_arm_operand*t=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==(sub?CDISASM_ARM_NAME_FMLS:CDISASM_ARM_NAME_FMLA)&&i->form_id==expected&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05402000)&&i->operand_count==3
      &&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==count&&t->imm==(w&7)&&t->size==0&&t->flags==0&&t->extend_type==size&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE
      &&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&n->reg==CDISASM_ARM_REG_Z0+zn&&n->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&n->extend_type==size&&n->access==CDISASM_OPERAND_ACCESS_READ
      &&m->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&m->reg==CDISASM_ARM_REG_Z0+zm&&m->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&m->extend_type==size&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sme2_multi_int_add_sub_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;unsigned wide=(w>>22)&1,sub=(w>>3)&1,count=(w&UINT32_C(0x10000))?4:2,size=wide?8:4,zn=count==4?((w>>7)&7)*4:((w>>6)&15)*2,zm=(w>>16)&(count==4?28:30);uint32_t mask=count==4?UINT32_C(0xffa39c78):UINT32_C(0xffa19c38),value=(count==4?UINT32_C(0xc1a11810):UINT32_C(0xc1a01810))|(sub<<3);uint16_t expected=(count==4?4205:4165)+sub;int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&mask)==value;int form=i->isa_id==CDISASM_ARM_ISA_A64&&(i->form_id==4165||i->form_id==4166||i->form_id==4205||i->form_id==4206);const cdisasm_arm_operand*t=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==(sub?CDISASM_ARM_NAME_SUB:CDISASM_ARM_NAME_ADD)&&i->form_id==expected&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05400000)&&i->operand_count==3
      &&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==count&&t->imm==(w&7)&&t->size==0&&t->flags==0&&t->extend_type==size&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE
      &&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&n->reg==CDISASM_ARM_REG_Z0+zn&&n->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&n->extend_type==size&&n->access==CDISASM_OPERAND_ACCESS_READ
      &&m->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&m->reg==CDISASM_ARM_REG_Z0+zm&&m->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&m->extend_type==size&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sme2_multi_arith_single_schema(const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id names[4]={CDISASM_ARM_NAME_FADD,CDISASM_ARM_NAME_FSUB,CDISASM_ARM_NAME_ADD,CDISASM_ARM_NAME_SUB};
    uint32_t w=i->raw_instruction;unsigned wide=(w>>22)&1,op=(w>>3)&3,count=(w&UINT32_C(0x10000))?4:2,size=wide?8:4,zn=count==4?((w>>7)&7)*4:((w>>6)&15)*2;uint32_t mask=count==4?UINT32_C(0xffbf9c78):UINT32_C(0xffbf9c38),value=(count==4?UINT32_C(0xc1a11c00):UINT32_C(0xc1a01c00))|(op<<3);int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&mask)==value;int form=i->isa_id==CDISASM_ARM_ISA_A64&&((i->form_id>=4167&&i->form_id<=4170)||(i->form_id>=4207&&i->form_id<=4210));const cdisasm_arm_operand*t=&i->operand[0],*n=&i->operand[1];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==names[op]&&i->form_id==(count==4?4207:4167)+op&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==(uint32_t)(UINT32_C(0x05400000)|(op<2?CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT:0))&&i->operand_count==2
      &&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==count&&t->imm==(w&7)&&t->size==0&&t->flags==0&&t->extend_type==size&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE
      &&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&n->reg==CDISASM_ARM_REG_Z0+zn&&n->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&n->extend_type==size&&n->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sme_multi_fp16_arith_single_schema(const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id names[4]={CDISASM_ARM_NAME_FADD,CDISASM_ARM_NAME_BFADD,CDISASM_ARM_NAME_FSUB,CDISASM_ARM_NAME_BFSUB};
    uint32_t w=i->raw_instruction;unsigned bf=(w>>22)&1,sub=(w>>3)&1,op=(sub<<1)|bf,count=(w&UINT32_C(0x10000))?4:2,zn=count==4?((w>>7)&7)*4:((w>>6)&15)*2;uint32_t mask=count==4?UINT32_C(0xffff9c78):UINT32_C(0xffff9c38),value=(bf?(count==4?UINT32_C(0xc1e51c00):UINT32_C(0xc1e41c00)):(count==4?UINT32_C(0xc1a51c00):UINT32_C(0xc1a41c00)))|(sub<<3);int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&mask)==value;int form=i->isa_id==CDISASM_ARM_ISA_A64&&((i->form_id>=4171&&i->form_id<=4174)||(i->form_id>=4211&&i->form_id<=4214));const cdisasm_arm_operand*t=&i->operand[0],*n=&i->operand[1];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==names[op]&&i->form_id==(count==4?4211:4171)+op&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05402000)&&i->operand_count==2
      &&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==count&&t->imm==(w&7)&&t->size==0&&t->flags==0&&t->extend_type==2&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE
      &&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&n->reg==CDISASM_ARM_REG_Z0+zn&&n->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&n->extend_type==2&&n->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sme2_multi_sel_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;unsigned count=(w&UINT32_C(0x10000))?4:2,size=1u<<((w>>22)&3),zd=w&(count==4?28:30),zn=(w>>5)&(count==4?28:30),zm=(w>>16)&(count==4?28:30);uint32_t mask=count==4?UINT32_C(0xff23e063):UINT32_C(0xff21e021),value=count==4?UINT32_C(0xc1218000):UINT32_C(0xc1208000);int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&mask)==value;int form=i->isa_id==CDISASM_ARM_ISA_A64&&(i->form_id==4215||i->form_id==4216);const cdisasm_arm_operand*d=&i->operand[0],*p=&i->operand[1],*n=&i->operand[2],*m=&i->operand[3];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==CDISASM_ARM_NAME_SEL&&i->form_id==(count==4?4216:4215)&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05c00000)&&i->operand_count==4
      &&d->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&d->reg==CDISASM_ARM_REG_Z0+zd&&d->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&d->extend_type==size&&d->access==CDISASM_OPERAND_ACCESS_WRITE
      &&p->type==CDISASM_ARM_OPERAND_PREDICATE&&p->reg==CDISASM_ARM_REG_PN8+((w>>10)&7)&&p->extend_type==size&&p->flags==CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED&&p->access==CDISASM_OPERAND_ACCESS_READ
      &&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&n->reg==CDISASM_ARM_REG_Z0+zn&&n->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&n->extend_type==size&&n->access==CDISASM_OPERAND_ACCESS_READ
      &&m->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&m->reg==CDISASM_ARM_REG_Z0+zm&&m->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&m->extend_type==size&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sme2_multi_int_minmax_schema(const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id names[4]={CDISASM_ARM_NAME_SMAX,CDISASM_ARM_NAME_UMAX,CDISASM_ARM_NAME_SMIN,CDISASM_ARM_NAME_UMIN};static const uint16_t forms[4]={4217,4219,4218,4220};
    uint32_t w=i->raw_instruction;unsigned op=(((w>>5)&1)<<1)|(w&1),size=1u<<((w>>22)&3),zdn=w&30,zm=(w>>16)&15;uint32_t value=UINT32_C(0xc120a000)|((op>>1)<<5)|(op&1);int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0xff30ffe1))==value;int form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=4217&&i->form_id<=4220;const cdisasm_arm_operand*d=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==names[op]&&i->form_id==forms[op]&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05400000)&&i->operand_count==3
      &&d->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&d->reg==CDISASM_ARM_REG_Z0+zdn&&d->register_list==UINT16_C(0x0102)&&d->extend_type==size&&d->access==CDISASM_OPERAND_ACCESS_WRITE
      &&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&n->reg==CDISASM_ARM_REG_Z0+zdn&&n->register_list==UINT16_C(0x0102)&&n->extend_type==size&&n->access==CDISASM_OPERAND_ACCESS_READ
      &&m->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER&&m->reg==CDISASM_ARM_REG_Z0+zm&&m->extend_type==size&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sme2_multi_fp_minmax_schema(const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id fn[4]={CDISASM_ARM_NAME_FMAX,CDISASM_ARM_NAME_FMIN,CDISASM_ARM_NAME_FMAXNM,CDISASM_ARM_NAME_FMINNM};static const cdisasm_arm_name_id bn[4]={CDISASM_ARM_NAME_BFMAX,CDISASM_ARM_NAME_BFMIN,CDISASM_ARM_NAME_BFMAXNM,CDISASM_ARM_NAME_BFMINNM};static const uint16_t ff[4]={4221,4223,4225,4227},bf[4]={4222,4224,4226,4228};
    uint32_t w=i->raw_instruction;unsigned sc=(w>>22)&3,op=(((w>>5)&1)<<1)|(w&1),size=sc?1u<<sc:2,zdn=w&30,zm=(w>>16)&15;int b=sc==0;uint32_t value=UINT32_C(0xc120a100)|((op>>1)<<5)|(op&1);int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0xff30ffe1))==value;int form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=4221&&i->form_id<=4228;const cdisasm_arm_operand*d=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==(b?bn[op]:fn[op])&&i->form_id==(b?bf[op]:ff[op])&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05402000)&&i->operand_count==3
      &&d->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&d->reg==CDISASM_ARM_REG_Z0+zdn&&d->register_list==UINT16_C(0x0102)&&d->extend_type==size&&d->access==CDISASM_OPERAND_ACCESS_WRITE
      &&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&n->reg==CDISASM_ARM_REG_Z0+zdn&&n->register_list==UINT16_C(0x0102)&&n->extend_type==size&&n->access==CDISASM_OPERAND_ACCESS_READ
      &&m->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER&&m->reg==CDISASM_ARM_REG_Z0+zm&&m->extend_type==size&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sme2_multi_int_misc_schema(const cdisasm_arm_instruction *i)
{
    static const uint32_t values[4]={UINT32_C(0xc120a220),UINT32_C(0xc120a221),UINT32_C(0xc120a300),UINT32_C(0xc120a400)};static const cdisasm_arm_name_id names[4]={CDISASM_ARM_NAME_SRSHL,CDISASM_ARM_NAME_URSHL,CDISASM_ARM_NAME_ADD,CDISASM_ARM_NAME_SQDMULH};
    uint32_t w=i->raw_instruction;unsigned k,size=1u<<((w>>22)&3),zdn=w&30,zm=(w>>16)&15;int raw=0;for(k=0;k<4;k++)if((w&UINT32_C(0xff30ffe1))==values[k]){raw=1;break;}int form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=4231&&i->form_id<=4234;const cdisasm_arm_operand*d=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];raw=raw&&i->isa_id==CDISASM_ARM_ISA_A64;
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==names[k]&&i->form_id==4231+k&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05400000)&&i->operand_count==3
      &&d->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&d->reg==CDISASM_ARM_REG_Z0+zdn&&d->register_list==UINT16_C(0x0102)&&d->extend_type==size&&d->access==CDISASM_OPERAND_ACCESS_WRITE
      &&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&n->reg==CDISASM_ARM_REG_Z0+zdn&&n->register_list==UINT16_C(0x0102)&&n->extend_type==size&&n->access==CDISASM_OPERAND_ACCESS_READ
      &&m->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER&&m->reg==CDISASM_ARM_REG_Z0+zm&&m->extend_type==size&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sme2_multi4_int_minmax_schema(const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id names[4]={CDISASM_ARM_NAME_SMAX,CDISASM_ARM_NAME_UMAX,CDISASM_ARM_NAME_SMIN,CDISASM_ARM_NAME_UMIN};static const uint16_t forms[4]={4235,4237,4236,4238};
    uint32_t w=i->raw_instruction;unsigned op=(((w>>5)&1)<<1)|(w&1),size=1u<<((w>>22)&3),zdn=w&28,zm=(w>>16)&15;uint32_t value=UINT32_C(0xc120a800)|((op>>1)<<5)|(op&1);int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0xff30ffe3))==value;int form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=4235&&i->form_id<=4238;const cdisasm_arm_operand*d=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==names[op]&&i->form_id==forms[op]&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05400000)&&i->operand_count==3
      &&d->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&d->reg==CDISASM_ARM_REG_Z0+zdn&&d->register_list==UINT16_C(0x0104)&&d->extend_type==size&&d->access==CDISASM_OPERAND_ACCESS_WRITE
      &&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&n->reg==CDISASM_ARM_REG_Z0+zdn&&n->register_list==UINT16_C(0x0104)&&n->extend_type==size&&n->access==CDISASM_OPERAND_ACCESS_READ
      &&m->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER&&m->reg==CDISASM_ARM_REG_Z0+zm&&m->extend_type==size&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sme2_multi4_fp_minmax_schema(const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id fn[4]={CDISASM_ARM_NAME_FMAX,CDISASM_ARM_NAME_FMIN,CDISASM_ARM_NAME_FMAXNM,CDISASM_ARM_NAME_FMINNM};static const cdisasm_arm_name_id bn[4]={CDISASM_ARM_NAME_BFMAX,CDISASM_ARM_NAME_BFMIN,CDISASM_ARM_NAME_BFMAXNM,CDISASM_ARM_NAME_BFMINNM};static const uint16_t ff[4]={4239,4241,4243,4245},bf[4]={4240,4242,4244,4246};
    uint32_t w=i->raw_instruction;unsigned sc=(w>>22)&3,op=(((w>>5)&1)<<1)|(w&1),size=sc?1u<<sc:2,zdn=w&28,zm=(w>>16)&15;int b=sc==0;uint32_t value=UINT32_C(0xc120a900)|((op>>1)<<5)|(op&1);int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0xff30ffe3))==value;int form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=4239&&i->form_id<=4246;const cdisasm_arm_operand*d=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==(b?bn[op]:fn[op])&&i->form_id==(b?bf[op]:ff[op])&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05402000)&&i->operand_count==3
      &&d->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&d->reg==CDISASM_ARM_REG_Z0+zdn&&d->register_list==UINT16_C(0x0104)&&d->extend_type==size&&d->access==CDISASM_OPERAND_ACCESS_WRITE
      &&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&n->reg==CDISASM_ARM_REG_Z0+zdn&&n->register_list==UINT16_C(0x0104)&&n->extend_type==size&&n->access==CDISASM_OPERAND_ACCESS_READ
      &&m->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER&&m->reg==CDISASM_ARM_REG_Z0+zm&&m->extend_type==size&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sme_multi_fscale_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;unsigned sc=(w>>22)&3,count=(w&UINT32_C(0x800))?4:2,size=sc?1u<<sc:2,zdn=w&(count==4?28:30),zm=(w>>16)&15;int b=sc==0;uint32_t mask=count==4?UINT32_C(0xff30ffe3):UINT32_C(0xff30ffe1),value=count==4?UINT32_C(0xc120a980):UINT32_C(0xc120a180);int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&mask)==value,form=i->isa_id==CDISASM_ARM_ISA_A64&&(i->form_id==4229||i->form_id==4230||i->form_id==4247||i->form_id==4248);const cdisasm_arm_operand*d=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==(b?CDISASM_ARM_NAME_BFSCALE:CDISASM_ARM_NAME_FSCALE)&&i->form_id==(count==4?(b?4248:4247):(b?4230:4229))&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05402000)&&i->operand_count==3
      &&d->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&d->reg==CDISASM_ARM_REG_Z0+zdn&&d->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&d->extend_type==size&&d->access==CDISASM_OPERAND_ACCESS_WRITE
      &&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&n->reg==CDISASM_ARM_REG_Z0+zdn&&n->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&n->extend_type==size&&n->access==CDISASM_OPERAND_ACCESS_READ
      &&m->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER&&m->reg==CDISASM_ARM_REG_Z0+zm&&m->extend_type==size&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sme2_multi4_int_misc_schema(const cdisasm_arm_instruction *i)
{
    static const uint32_t values[4]={UINT32_C(0xc120aa20),UINT32_C(0xc120aa21),UINT32_C(0xc120ab00),UINT32_C(0xc120ac00)};static const cdisasm_arm_name_id names[4]={CDISASM_ARM_NAME_SRSHL,CDISASM_ARM_NAME_URSHL,CDISASM_ARM_NAME_ADD,CDISASM_ARM_NAME_SQDMULH};
    uint32_t w=i->raw_instruction;unsigned k,size=1u<<((w>>22)&3),zdn=w&28,zm=(w>>16)&15;int raw=0;for(k=0;k<4;k++)if((w&UINT32_C(0xff30ffe3))==values[k]){raw=1;break;}int form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=4249&&i->form_id<=4252;const cdisasm_arm_operand*d=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];raw=raw&&i->isa_id==CDISASM_ARM_ISA_A64;
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==names[k]&&i->form_id==4249+k&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05400000)&&i->operand_count==3
      &&d->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&d->reg==CDISASM_ARM_REG_Z0+zdn&&d->register_list==UINT16_C(0x0104)&&d->extend_type==size&&d->access==CDISASM_OPERAND_ACCESS_WRITE
      &&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&n->reg==CDISASM_ARM_REG_Z0+zdn&&n->register_list==UINT16_C(0x0104)&&n->extend_type==size&&n->access==CDISASM_OPERAND_ACCESS_READ
      &&m->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER&&m->reg==CDISASM_ARM_REG_Z0+zm&&m->extend_type==size&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sme2_multi2x2_int_minmax_schema(const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id names[4]={CDISASM_ARM_NAME_SMAX,CDISASM_ARM_NAME_UMAX,CDISASM_ARM_NAME_SMIN,CDISASM_ARM_NAME_UMIN};static const uint16_t forms[4]={4253,4255,4254,4256};
    uint32_t w=i->raw_instruction;unsigned op=(((w>>5)&1)<<1)|(w&1),size=1u<<((w>>22)&3),zdn=w&30,zm=(w>>16)&30;uint32_t value=UINT32_C(0xc120b000)|((op>>1)<<5)|(op&1);int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0xff21ffe1))==value;int form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=4253&&i->form_id<=4256;const cdisasm_arm_operand*d=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==names[op]&&i->form_id==forms[op]&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05400000)&&i->operand_count==3
      &&d->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&d->reg==CDISASM_ARM_REG_Z0+zdn&&d->register_list==UINT16_C(0x0102)&&d->extend_type==size&&d->access==CDISASM_OPERAND_ACCESS_WRITE
      &&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&n->reg==CDISASM_ARM_REG_Z0+zdn&&n->register_list==UINT16_C(0x0102)&&n->extend_type==size&&n->access==CDISASM_OPERAND_ACCESS_READ
      &&m->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&m->reg==CDISASM_ARM_REG_Z0+zm&&m->register_list==UINT16_C(0x0102)&&m->extend_type==size&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sme2_multi2x2_fp_minmax_schema(const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id fn[4]={CDISASM_ARM_NAME_FMAX,CDISASM_ARM_NAME_FMIN,CDISASM_ARM_NAME_FMAXNM,CDISASM_ARM_NAME_FMINNM};static const cdisasm_arm_name_id bn[4]={CDISASM_ARM_NAME_BFMAX,CDISASM_ARM_NAME_BFMIN,CDISASM_ARM_NAME_BFMAXNM,CDISASM_ARM_NAME_BFMINNM};static const uint16_t ff[4]={4257,4259,4261,4263},bf[4]={4258,4260,4262,4264};
    uint32_t w=i->raw_instruction;unsigned sc=(w>>22)&3,op=(((w>>5)&1)<<1)|(w&1),size=sc?1u<<sc:2,zdn=w&30,zm=(w>>16)&30;int b=sc==0;uint32_t value=UINT32_C(0xc120b100)|((op>>1)<<5)|(op&1);int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0xff21ffe1))==value;int form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=4257&&i->form_id<=4264;const cdisasm_arm_operand*d=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==(b?bn[op]:fn[op])&&i->form_id==(b?bf[op]:ff[op])&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05402000)&&i->operand_count==3
      &&d->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&d->reg==CDISASM_ARM_REG_Z0+zdn&&d->register_list==UINT16_C(0x0102)&&d->extend_type==size&&d->access==CDISASM_OPERAND_ACCESS_WRITE
      &&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&n->reg==CDISASM_ARM_REG_Z0+zdn&&n->register_list==UINT16_C(0x0102)&&n->extend_type==size&&n->access==CDISASM_OPERAND_ACCESS_READ
      &&m->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&m->reg==CDISASM_ARM_REG_Z0+zm&&m->register_list==UINT16_C(0x0102)&&m->extend_type==size&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sme2_multi2x2_int_misc_schema(const cdisasm_arm_instruction *i)
{
    static const uint32_t values[3]={UINT32_C(0xc120b220),UINT32_C(0xc120b221),UINT32_C(0xc120b400)};static const cdisasm_arm_name_id names[3]={CDISASM_ARM_NAME_SRSHL,CDISASM_ARM_NAME_URSHL,CDISASM_ARM_NAME_SQDMULH};static const uint16_t forms[3]={4269,4270,4271};
    uint32_t w=i->raw_instruction;unsigned k,size=1u<<((w>>22)&3),zdn=w&30,zm=(w>>16)&30;int raw=0;for(k=0;k<3;k++)if((w&UINT32_C(0xff21ffe1))==values[k]){raw=1;break;}int form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=4269&&i->form_id<=4271;const cdisasm_arm_operand*d=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];raw=raw&&i->isa_id==CDISASM_ARM_ISA_A64;
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==names[k]&&i->form_id==forms[k]&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05400000)&&i->operand_count==3
      &&d->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&d->reg==CDISASM_ARM_REG_Z0+zdn&&d->register_list==UINT16_C(0x0102)&&d->extend_type==size&&d->access==CDISASM_OPERAND_ACCESS_WRITE
      &&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&n->reg==CDISASM_ARM_REG_Z0+zdn&&n->register_list==UINT16_C(0x0102)&&n->extend_type==size&&n->access==CDISASM_OPERAND_ACCESS_READ
      &&m->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&m->reg==CDISASM_ARM_REG_Z0+zm&&m->register_list==UINT16_C(0x0102)&&m->extend_type==size&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sme2_multi4x4_int_minmax_schema(const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id names[4]={CDISASM_ARM_NAME_SMAX,CDISASM_ARM_NAME_UMAX,CDISASM_ARM_NAME_SMIN,CDISASM_ARM_NAME_UMIN};static const uint16_t forms[4]={4272,4274,4273,4275};
    uint32_t w=i->raw_instruction;unsigned op=(((w>>5)&1)<<1)|(w&1),size=1u<<((w>>22)&3),zdn=w&28,zm=(w>>16)&28;uint32_t value=UINT32_C(0xc120b800)|((op>>1)<<5)|(op&1);int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0xff23ffe3))==value;int form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=4272&&i->form_id<=4275;const cdisasm_arm_operand*d=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==names[op]&&i->form_id==forms[op]&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05400000)&&i->operand_count==3
      &&d->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&d->reg==CDISASM_ARM_REG_Z0+zdn&&d->register_list==UINT16_C(0x0104)&&d->extend_type==size&&d->access==CDISASM_OPERAND_ACCESS_WRITE
      &&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&n->reg==CDISASM_ARM_REG_Z0+zdn&&n->register_list==UINT16_C(0x0104)&&n->extend_type==size&&n->access==CDISASM_OPERAND_ACCESS_READ
      &&m->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&m->reg==CDISASM_ARM_REG_Z0+zm&&m->register_list==UINT16_C(0x0104)&&m->extend_type==size&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sme2_multi4x4_fp_minmax_schema(const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id fn[4]={CDISASM_ARM_NAME_FMAX,CDISASM_ARM_NAME_FMIN,CDISASM_ARM_NAME_FMAXNM,CDISASM_ARM_NAME_FMINNM};static const cdisasm_arm_name_id bn[4]={CDISASM_ARM_NAME_BFMAX,CDISASM_ARM_NAME_BFMIN,CDISASM_ARM_NAME_BFMAXNM,CDISASM_ARM_NAME_BFMINNM};static const uint16_t ff[4]={4276,4278,4280,4282},bf[4]={4277,4279,4281,4283};
    uint32_t w=i->raw_instruction;unsigned sc=(w>>22)&3,op=(((w>>5)&1)<<1)|(w&1),size=sc?1u<<sc:2,zdn=w&28,zm=(w>>16)&28;int b=sc==0;uint32_t value=UINT32_C(0xc120b900)|((op>>1)<<5)|(op&1);int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0xff23ffe3))==value;int form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=4276&&i->form_id<=4283;const cdisasm_arm_operand*d=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==(b?bn[op]:fn[op])&&i->form_id==(b?bf[op]:ff[op])&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05402000)&&i->operand_count==3
      &&d->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&d->reg==CDISASM_ARM_REG_Z0+zdn&&d->register_list==UINT16_C(0x0104)&&d->extend_type==size&&d->access==CDISASM_OPERAND_ACCESS_WRITE
      &&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&n->reg==CDISASM_ARM_REG_Z0+zdn&&n->register_list==UINT16_C(0x0104)&&n->extend_type==size&&n->access==CDISASM_OPERAND_ACCESS_READ
      &&m->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&m->reg==CDISASM_ARM_REG_Z0+zm&&m->register_list==UINT16_C(0x0104)&&m->extend_type==size&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sme_multi_matrix_special_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;unsigned count=(w&UINT32_C(0x800))?4:2,sc=(w>>22)&3,size=sc?1u<<sc:2,zdn=w&(count==4?28:30),zm=(w>>16)&(count==4?28:30);uint32_t opcode=w&(count==4?UINT32_C(0x0000ffe3):UINT32_C(0x0000ffe1)),amax=count==4?UINT32_C(0xb940):UINT32_C(0xb140),amin=amax|1,scale=count==4?UINT32_C(0xb980):UINT32_C(0xb180);int is_scale=opcode==scale,is_min=opcode==amin,b=is_scale&&sc==0,raw=i->isa_id==CDISASM_ARM_ISA_A64&&(opcode==amax||opcode==amin||opcode==scale)&&!(!is_scale&&sc==0),form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=4265&&i->form_id<=4287&&(i->form_id<=4268||i->form_id>=4284);uint16_t expected=count==4?(is_scale?(b?4287:4286):(is_min?4285:4284)):(is_scale?(b?4268:4267):(is_min?4266:4265));cdisasm_arm_name_id name=is_scale?(b?CDISASM_ARM_NAME_BFSCALE:CDISASM_ARM_NAME_FSCALE):(is_min?CDISASM_ARM_NAME_FAMIN:CDISASM_ARM_NAME_FAMAX);const cdisasm_arm_operand*d=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==name&&i->form_id==expected&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05402000)&&i->operand_count==3
      &&d->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&d->reg==CDISASM_ARM_REG_Z0+zdn&&d->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&d->extend_type==size&&d->access==CDISASM_OPERAND_ACCESS_WRITE
      &&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&n->reg==CDISASM_ARM_REG_Z0+zdn&&n->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&n->extend_type==size&&n->access==CDISASM_OPERAND_ACCESS_READ
      &&m->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&m->reg==CDISASM_ARM_REG_Z0+zm&&m->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&m->extend_type==size&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sme2_multi4x4_int_misc_schema(const cdisasm_arm_instruction *i)
{
    static const uint32_t values[3]={UINT32_C(0xc120ba20),UINT32_C(0xc120ba21),UINT32_C(0xc120bc00)};static const cdisasm_arm_name_id names[3]={CDISASM_ARM_NAME_SRSHL,CDISASM_ARM_NAME_URSHL,CDISASM_ARM_NAME_SQDMULH};static const uint16_t forms[3]={4288,4289,4290};
    uint32_t w=i->raw_instruction;unsigned k,size=1u<<((w>>22)&3),zdn=w&28,zm=(w>>16)&28;int raw=0;for(k=0;k<3;k++)if((w&UINT32_C(0xff23ffe3))==values[k]){raw=1;break;}int form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=4288&&i->form_id<=4290;const cdisasm_arm_operand*d=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];raw=raw&&i->isa_id==CDISASM_ARM_ISA_A64;if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==names[k]&&i->form_id==forms[k]&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05400000)&&i->operand_count==3&&d->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&d->reg==CDISASM_ARM_REG_Z0+zdn&&d->register_list==UINT16_C(0x0104)&&d->extend_type==size&&d->access==CDISASM_OPERAND_ACCESS_WRITE&&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&n->reg==CDISASM_ARM_REG_Z0+zdn&&n->register_list==UINT16_C(0x0104)&&n->extend_type==size&&n->access==CDISASM_OPERAND_ACCESS_READ&&m->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&m->reg==CDISASM_ARM_REG_Z0+zm&&m->register_list==UINT16_C(0x0104)&&m->extend_type==size&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sme2_multi_fclamp_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;unsigned count=(w&UINT32_C(0x800))?4:2,sc=(w>>22)&3,size=sc?1u<<sc:2,zd=w&(count==4?28:30),zn=(w>>5)&31,zm=(w>>16)&31;uint32_t mask=count==4?UINT32_C(0xff20fc03):UINT32_C(0xff20fc01),value=count==4?UINT32_C(0xc120c800):UINT32_C(0xc120c000);int b=sc==0,raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&mask)==value,form=i->isa_id==CDISASM_ARM_ISA_A64&&(i->form_id==4291||i->form_id==4292||i->form_id==4295||i->form_id==4296);uint16_t expected=(uint16_t)((count==4?4295:4291)+b);const cdisasm_arm_operand*d=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==(b?CDISASM_ARM_NAME_BFCLAMP:CDISASM_ARM_NAME_FCLAMP)&&i->form_id==expected&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05402000)&&i->operand_count==3&&d->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&d->reg==CDISASM_ARM_REG_Z0+zd&&d->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&d->extend_type==size&&d->access==CDISASM_OPERAND_ACCESS_WRITE&&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER&&n->reg==CDISASM_ARM_REG_Z0+zn&&n->extend_type==size&&n->access==CDISASM_OPERAND_ACCESS_READ&&m->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER&&m->reg==CDISASM_ARM_REG_Z0+zm&&m->extend_type==size&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sve_predicated_bfscale_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;unsigned zd=w&31,pg=(w>>10)&7,zn=(w>>5)&31;int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0xffffe000))==UINT32_C(0x65098000),form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id==3092;if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==CDISASM_ARM_NAME_BFSCALE&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x00c02000)&&i->operand_count==4&&arm_exact_scalable_operand(&i->operand[0],CDISASM_ARM_REG_Z0+zd,2,CDISASM_OPERAND_ACCESS_READ_WRITE)&&arm_exact_predicate_operand(&i->operand[1],CDISASM_ARM_REG_P0+pg,2,CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE,CDISASM_OPERAND_ACCESS_READ)&&arm_exact_scalable_operand(&i->operand[2],CDISASM_ARM_REG_Z0+zd,2,CDISASM_OPERAND_ACCESS_READ)&&arm_exact_scalable_operand(&i->operand[3],CDISASM_ARM_REG_Z0+zn,2,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_a64_fp_pair_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;unsigned sc=w>>30,am=(w>>23)&3,load=(w>>22)&1,rt=w&31,rn=(w>>5)&31,rt2=(w>>10)&31,mi=am==1?0:am==2?1:2;static const uint16_t forms[3][3][2]={{{5092,5093},{5108,5109},{5124,5125}},{{5096,5097},{5112,5113},{5128,5129}},{{5100,5101},{5116,5117},{5132,5133}}};uint16_t fid=i->form_id;int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0x3e000000))==UINT32_C(0x2c000000)&&sc<3&&am!=0,form=i->isa_id==CDISASM_ARM_ISA_A64&&(fid==5092||fid==5093||fid==5096||fid==5097||fid==5100||fid==5101||fid==5108||fid==5109||fid==5112||fid==5113||fid==5116||fid==5117||fid==5124||fid==5125||fid==5128||fid==5129||fid==5132||fid==5133);uint8_t size=(uint8_t)(4u<<sc);int64_t disp=(int64_t)((w>>15)&127);uint32_t flags=CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT|(am==1?(CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX|CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK):am==3?(CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX|CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK):0);const cdisasm_arm_operand*a=&i->operand[0],*b=&i->operand[1],*m=&i->operand[2];cdisasm_arm_reg_id rb=(cdisasm_arm_reg_id)(size==4?CDISASM_ARM_REG_S0:size==8?CDISASM_ARM_REG_D0:rt<16?CDISASM_ARM_REG_Q0:CDISASM_ARM_REG_Q16-16),rb2=(cdisasm_arm_reg_id)(size==4?CDISASM_ARM_REG_S0:size==8?CDISASM_ARM_REG_D0:rt2<16?CDISASM_ARM_REG_Q0:CDISASM_ARM_REG_Q16-16);if((disp&64)!=0)disp-=128;disp*=size;if(!raw&&!form)return 1;if(!raw||!form)return 0;if(load&&rt==rt2)flags|=CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL|CDISASM_ARM_INSTRUCTION_FLAG_UNPREDICTABLE;
    return i->name_id==(load?CDISASM_ARM_NAME_LDP:CDISASM_ARM_NAME_STP)&&i->form_id==forms[sc][mi][load]&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==flags&&i->operand_count==3&&a->type==CDISASM_OPERAND_REGISTER&&a->reg==rb+rt&&a->size==size&&a->access==(load?CDISASM_OPERAND_ACCESS_WRITE:CDISASM_OPERAND_ACCESS_READ)&&b->type==CDISASM_OPERAND_REGISTER&&b->reg==rb2+rt2&&b->size==size&&b->access==(load?CDISASM_OPERAND_ACCESS_WRITE:CDISASM_OPERAND_ACCESS_READ)&&m->type==CDISASM_OPERAND_MEMORY&&m->base_reg==(rn==31?CDISASM_ARM_REG_SP:CDISASM_ARM_REG_X0+rn)&&m->size==size&&m->imm==(uint64_t)disp&&m->access==(load?CDISASM_OPERAND_ACCESS_READ:CDISASM_OPERAND_ACCESS_WRITE)&&m->flags==(disp==0?0:CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT|(disp<0?CDISASM_OPERAND_FLAG_SIGNED:0));
}

static int arm_valid_a64_lsui_pair_schema(
    const cdisasm_arm_instruction *i)
{
    static const uint16_t integer_forms[4][2] = {
        {5086, 5087}, {5102, 5103}, {5118, 5119}, {5134, 5135}
    };
    static const uint16_t vector_forms[4][2] = {
        {5088, 5089}, {5104, 5105}, {5120, 5121}, {5136, 5137}
    };
    uint32_t w = i->raw_instruction;
    unsigned address_mode = (w >> 23) & 3u;
    unsigned load = (w >> 22) & 1u;
    unsigned rt = w & 31u;
    unsigned rn = (w >> 5) & 31u;
    unsigned rt2 = (w >> 10) & 31u;
    unsigned mode_index = address_mode == 0u ? 0u
        : address_mode == 1u ? 1u
        : address_mode == 2u ? 2u : 3u;
    int vector = (w & UINT32_C(0x04000000)) != 0;
    int raw = i->isa_id == CDISASM_ARM_ISA_A64
        && (w & UINT32_C(0xfa000000)) == UINT32_C(0xe8000000);
    int form = i->isa_id == CDISASM_ARM_ISA_A64
        && ((i->form_id >= UINT16_C(5086)
                && i->form_id <= UINT16_C(5089))
            || (i->form_id >= UINT16_C(5102)
                && i->form_id <= UINT16_C(5105))
            || (i->form_id >= UINT16_C(5118)
                && i->form_id <= UINT16_C(5121))
            || (i->form_id >= UINT16_C(5134)
                && i->form_id <= UINT16_C(5137)));
    uint16_t expected = vector ? vector_forms[mode_index][load]
                               : integer_forms[mode_index][load];
    uint8_t size = vector ? 16u : 8u;
    int64_t displacement = (int64_t)((w >> 15) & 127u);
    uint32_t flags = vector
        ? CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT : 0u;
    cdisasm_arm_reg_id base = vector
        ? (cdisasm_arm_reg_id)(rt < 16u ? CDISASM_ARM_REG_Q0
                                        : CDISASM_ARM_REG_Q16 - 16u)
        : CDISASM_ARM_REG_X0;
    cdisasm_arm_reg_id base2 = vector
        ? (cdisasm_arm_reg_id)(rt2 < 16u ? CDISASM_ARM_REG_Q0
                                         : CDISASM_ARM_REG_Q16 - 16u)
        : CDISASM_ARM_REG_X0;
    const cdisasm_arm_operand *a = &i->operand[0];
    const cdisasm_arm_operand *b = &i->operand[1];
    const cdisasm_arm_operand *m = &i->operand[2];

    if ((displacement & 64) != 0) displacement -= 128;
    displacement *= size;
    if (address_mode == 1u) {
        flags |= CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
    } else if (address_mode == 3u) {
        flags |= CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
    }
    if ((load && rt == rt2)
        || (address_mode != 0u && address_mode != 2u
            && rn != 31u && (rn == rt || rn == rt2))) {
        flags |= CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL
            | CDISASM_ARM_INSTRUCTION_FLAG_UNPREDICTABLE;
    }
    if (!raw && !form) return 1;
    if (!raw || !form) return 0;
    return i->name_id == (address_mode == 0u
            ? (load ? CDISASM_ARM_NAME_LDTNP : CDISASM_ARM_NAME_STTNP)
            : (load ? CDISASM_ARM_NAME_LDTP : CDISASM_ARM_NAME_STTP))
        && i->form_id == expected
        && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags == flags
        && i->operand_count == 3u
        && a->type == CDISASM_OPERAND_REGISTER
        && a->reg == base + rt && a->size == size
        && a->access == (load ? CDISASM_OPERAND_ACCESS_WRITE
                              : CDISASM_OPERAND_ACCESS_READ)
        && b->type == CDISASM_OPERAND_REGISTER
        && b->reg == base2 + rt2 && b->size == size
        && b->access == (load ? CDISASM_OPERAND_ACCESS_WRITE
                              : CDISASM_OPERAND_ACCESS_READ)
        && m->type == CDISASM_OPERAND_MEMORY
        && m->base_reg == (rn == 31u ? CDISASM_ARM_REG_SP
                                     : CDISASM_ARM_REG_X0 + rn)
        && m->size == 2u * size && m->imm == (uint64_t)displacement
        && m->access == (load ? CDISASM_OPERAND_ACCESS_READ
                              : CDISASM_OPERAND_ACCESS_WRITE)
        && m->flags == (displacement == 0 ? 0u
            : CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
                | (displacement < 0 ? CDISASM_OPERAND_FLAG_SIGNED : 0u));
}

static int arm_valid_a64_fp_signed_memory_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;unsigned sc=w>>30,q=(w>>23)&1,load=(w>>22)&1,mode=(w>>10)&3,rt=w&31,rn=(w>>5)&31,type=sc==0?q:sc+1,mi=mode==0?0:mode==1?1:2;static const uint8_t sizes[5]={1,16,2,4,8};static const cdisasm_arm_reg_id bases[5]={CDISASM_ARM_REG_B0,CDISASM_ARM_REG_Q0,CDISASM_ARM_REG_H0,CDISASM_ARM_REG_S0,CDISASM_ARM_REG_D0};static const uint16_t forms[5][3][2]={{{5142,5143},{5166,5167},{5202,5203}},{{5144,5145},{5168,5169},{5204,5205}},{{5150,5151},{5174,5175},{5210,5211}},{{5155,5156},{5179,5180},{5215,5216}},{{5160,5161},{5183,5184},{5219,5220}}};uint16_t fid=i->form_id;int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0x3f200000))==UINT32_C(0x3c000000)&&!(q&&sc!=0)&&mode!=2,form=i->isa_id==CDISASM_ARM_ISA_A64&&(fid==5142||fid==5143||fid==5144||fid==5145||fid==5150||fid==5151||fid==5155||fid==5156||fid==5160||fid==5161||fid==5166||fid==5167||fid==5168||fid==5169||fid==5174||fid==5175||fid==5179||fid==5180||fid==5183||fid==5184||fid==5202||fid==5203||fid==5204||fid==5205||fid==5210||fid==5211||fid==5215||fid==5216||fid==5219||fid==5220);int64_t disp=(int64_t)((w>>12)&511);uint32_t flags=CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT|(mode==1?(CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX|CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK):mode==3?(CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX|CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK):0);const cdisasm_arm_operand*r=&i->operand[0],*m=&i->operand[1];cdisasm_arm_reg_id base=(cdisasm_arm_reg_id)(type==1&&rt>=16?CDISASM_ARM_REG_Q16-16:bases[type]);cdisasm_arm_name_id name=mode==0?(load?CDISASM_ARM_NAME_LDUR:CDISASM_ARM_NAME_STUR):(load?CDISASM_ARM_NAME_LDR:CDISASM_ARM_NAME_STR);if((disp&256)!=0)disp-=512;if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==name&&i->form_id==forms[type][mi][load]&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==flags&&i->operand_count==2&&r->type==CDISASM_OPERAND_REGISTER&&r->reg==base+rt&&r->size==sizes[type]&&r->access==(load?CDISASM_OPERAND_ACCESS_WRITE:CDISASM_OPERAND_ACCESS_READ)&&m->type==CDISASM_OPERAND_MEMORY&&m->base_reg==(rn==31?CDISASM_ARM_REG_SP:CDISASM_ARM_REG_X0+rn)&&m->size==sizes[type]&&m->imm==(uint64_t)disp&&m->access==(load?CDISASM_OPERAND_ACCESS_READ:CDISASM_OPERAND_ACCESS_WRITE)&&m->flags==(disp==0?0:CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT|(disp<0?CDISASM_OPERAND_FLAG_SIGNED:0));
}

static int arm_valid_a64_fp_unsigned_memory_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;unsigned sc=w>>30,q=(w>>23)&1,load=(w>>22)&1,rt=w&31,rn=(w>>5)&31,type=sc==0?q:sc+1;static const uint8_t sizes[5]={1,16,2,4,8};static const cdisasm_arm_reg_id bases[5]={CDISASM_ARM_REG_B0,CDISASM_ARM_REG_Q0,CDISASM_ARM_REG_H0,CDISASM_ARM_REG_S0,CDISASM_ARM_REG_D0};static const uint16_t forms[5][2]={{5556,5557},{5558,5559},{5564,5565},{5569,5570},{5574,5575}};uint16_t fid=i->form_id;int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0x3f000000))==UINT32_C(0x3d000000)&&!(q&&sc!=0),form=i->isa_id==CDISASM_ARM_ISA_A64&&(fid==5556||fid==5557||fid==5558||fid==5559||fid==5564||fid==5565||fid==5569||fid==5570||fid==5574||fid==5575);uint64_t disp=((w>>10)&UINT32_C(0xfff))*sizes[type];const cdisasm_arm_operand*r=&i->operand[0],*m=&i->operand[1];cdisasm_arm_reg_id base=(cdisasm_arm_reg_id)(type==1&&rt>=16?CDISASM_ARM_REG_Q16-16:bases[type]);if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==(load?CDISASM_ARM_NAME_LDR:CDISASM_ARM_NAME_STR)&&i->form_id==forms[type][load]&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT&&i->operand_count==2&&r->type==CDISASM_OPERAND_REGISTER&&r->reg==base+rt&&r->size==sizes[type]&&r->access==(load?CDISASM_OPERAND_ACCESS_WRITE:CDISASM_OPERAND_ACCESS_READ)&&m->type==CDISASM_OPERAND_MEMORY&&m->base_reg==(rn==31?CDISASM_ARM_REG_SP:CDISASM_ARM_REG_X0+rn)&&m->size==sizes[type]&&m->imm==disp&&m->access==(load?CDISASM_OPERAND_ACCESS_READ:CDISASM_OPERAND_ACCESS_WRITE)&&m->flags==(disp==0?0:CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT);
}

static int arm_valid_a64_fp_register_memory_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;unsigned sc=w>>30,q=(w>>23)&1,load=(w>>22)&1,s=(w>>12)&1,option=(w>>13)&7,rm=(w>>16)&31,rt=w&31,rn=(w>>5)&31,type=sc==0?q:sc+1;static const uint8_t sizes[5]={1,16,2,4,8},shifts[5]={0,4,1,2,3};static const cdisasm_arm_reg_id bases[5]={CDISASM_ARM_REG_B0,CDISASM_ARM_REG_Q0,CDISASM_ARM_REG_H0,CDISASM_ARM_REG_S0,CDISASM_ARM_REG_D0};static const uint16_t forms[5][2]={{5525,5527},{5529,5530},{5535,5536},{5540,5541},{5546,5547}};uint16_t fid=i->form_id,expected=(uint16_t)(type==0&&option==3?(load?5528:5526):forms[type][load]);int legal=(option==2||option==3||option==6||option==7)&&!(q&&sc!=0),raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0x3f200c00))==UINT32_C(0x3c200800)&&legal,form=i->isa_id==CDISASM_ARM_ISA_A64&&(fid==5525||fid==5526||fid==5527||fid==5528||fid==5529||fid==5530||fid==5535||fid==5536||fid==5540||fid==5541||fid==5546||fid==5547);const cdisasm_arm_operand*r=&i->operand[0],*m=&i->operand[1];cdisasm_arm_reg_id base=(cdisasm_arm_reg_id)(type==1&&rt>=16?CDISASM_ARM_REG_Q16-16:bases[type]),index=(cdisasm_arm_reg_id)(((option&1)!=0?CDISASM_ARM_REG_X0:CDISASM_ARM_REG_W0)+rm);cdisasm_arm_extend_type ext=(cdisasm_arm_extend_type)(option==2?CDISASM_ARM_EXTEND_UXTW:option==6?CDISASM_ARM_EXTEND_SXTW:option==7?CDISASM_ARM_EXTEND_SXTX:CDISASM_ARM_EXTEND_NONE);if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==(load?CDISASM_ARM_NAME_LDR:CDISASM_ARM_NAME_STR)&&i->form_id==expected&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT&&i->operand_count==2&&r->type==CDISASM_OPERAND_REGISTER&&r->reg==base+rt&&r->size==sizes[type]&&r->access==(load?CDISASM_OPERAND_ACCESS_WRITE:CDISASM_OPERAND_ACCESS_READ)&&m->type==CDISASM_OPERAND_MEMORY&&m->base_reg==(rn==31?CDISASM_ARM_REG_SP:CDISASM_ARM_REG_X0+rn)&&m->index_reg==index&&m->size==sizes[type]&&m->access==(load?CDISASM_OPERAND_ACCESS_READ:CDISASM_OPERAND_ACCESS_WRITE)&&m->shift_type==(option==3&&s?CDISASM_ARM_SHIFT_LSL:CDISASM_ARM_SHIFT_NONE)&&m->shift_amount==(option==3&&s?shifts[type]:0)&&m->extend_type==ext&&m->scale==(option!=3&&s?shifts[type]:0)&&m->imm==0&&m->flags==0;
}

static int arm_valid_a64_register_memory_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;unsigned size=w>>30,opc=(w>>22)&3,s=(w>>12)&1,option=(w>>13)&7,rm=(w>>16)&31,rt=w&31,rn=(w>>5)&31,reg64=0,ms=1u<<size;uint16_t expected=0;cdisasm_arm_name_id name=CDISASM_ARM_NAME_NONE;int legal=option==2||option==3||option==6||option==7;if(size==0){if(opc==0){name=CDISASM_ARM_NAME_STRB;expected=option==3?5518:5517;}else if(opc==1){name=CDISASM_ARM_NAME_LDRB;expected=option==3?5520:5519;}else{name=CDISASM_ARM_NAME_LDRSB;reg64=opc==2;expected=opc==2?(option==3?5522:5521):(option==3?5524:5523);}}else if(size==1){if(opc==0){name=CDISASM_ARM_NAME_STRH;expected=5531;}else if(opc==1){name=CDISASM_ARM_NAME_LDRH;expected=5532;}else{name=CDISASM_ARM_NAME_LDRSH;reg64=opc==2;expected=opc==2?5533:5534;}}else if(size==2){if(opc==0){name=CDISASM_ARM_NAME_STR;expected=5537;}else if(opc==1){name=CDISASM_ARM_NAME_LDR;expected=5538;}else if(opc==2){name=CDISASM_ARM_NAME_LDRSW;reg64=1;expected=5539;}else legal=0;}else{if(opc==0){name=CDISASM_ARM_NAME_STR;reg64=1;expected=5542;}else if(opc==1){name=CDISASM_ARM_NAME_LDR;reg64=1;expected=5543;}else if(opc==2){name=CDISASM_ARM_NAME_PRFM;expected=5544;ms=1;}else legal=0;}int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0x3f200c00))==UINT32_C(0x38200800)&&legal,form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=5517&&i->form_id<=5544&&(i->form_id<=5524||(i->form_id>=5531&&i->form_id<=5534)||(i->form_id>=5537&&i->form_id<=5539)||i->form_id>=5542);const cdisasm_arm_operand*r=&i->operand[0],*m=&i->operand[1];cdisasm_arm_reg_id index=(cdisasm_arm_reg_id)(((option&1)?CDISASM_ARM_REG_X0:CDISASM_ARM_REG_W0)+rm);cdisasm_arm_extend_type ext=(cdisasm_arm_extend_type)(option==2?CDISASM_ARM_EXTEND_UXTW:option==6?CDISASM_ARM_EXTEND_SXTW:option==7?CDISASM_ARM_EXTEND_SXTX:CDISASM_ARM_EXTEND_NONE);if(!raw&&!form)return 1;if(!raw||!form)return 0;
    if(i->name_id!=name||i->form_id!=expected||i->condition!=CDISASM_ARM_CONDITION_AL||i->opcode_groups!=CDISASM_GROUP_NONE||i->instruction_flags!=0||i->operand_count!=2)return 0;if(name==CDISASM_ARM_NAME_PRFM){if(r->type!=CDISASM_OPERAND_IMMEDIATE||r->imm!=rt||r->size!=1)return 0;}else if(r->type!=CDISASM_OPERAND_REGISTER||r->reg!=((reg64?CDISASM_ARM_REG_X0:CDISASM_ARM_REG_W0)+rt)||r->size!=(reg64?8:4)||r->access!=(opc==0?CDISASM_OPERAND_ACCESS_READ:CDISASM_OPERAND_ACCESS_WRITE))return 0;
    return m->type==CDISASM_OPERAND_MEMORY&&m->base_reg==(rn==31?CDISASM_ARM_REG_SP:CDISASM_ARM_REG_X0+rn)&&m->index_reg==index&&m->size==ms&&m->access==(opc==0?CDISASM_OPERAND_ACCESS_WRITE:CDISASM_OPERAND_ACCESS_READ)&&m->shift_type==(option==3&&s?CDISASM_ARM_SHIFT_LSL:CDISASM_ARM_SHIFT_NONE)&&m->shift_amount==(option==3&&s?size:0)&&m->extend_type==ext&&m->scale==(option!=3&&s?size:0)&&m->imm==0&&m->flags==0;
}

static int arm_valid_a64_prfm_unsigned_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;unsigned rt=w&31,rn=(w>>5)&31;uint64_t disp=((w>>10)&UINT32_C(0xfff))*8u;int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0xffc00000))==UINT32_C(0xf9800000),form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id==5573;const cdisasm_arm_operand*p=&i->operand[0],*m=&i->operand[1];if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==CDISASM_ARM_NAME_PRFM&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==0&&i->operand_count==2&&p->type==CDISASM_OPERAND_IMMEDIATE&&p->imm==rt&&p->size==1&&m->type==CDISASM_OPERAND_MEMORY&&m->base_reg==(rn==31?CDISASM_ARM_REG_SP:CDISASM_ARM_REG_X0+rn)&&m->size==1&&m->imm==disp&&m->access==CDISASM_OPERAND_ACCESS_READ&&m->flags==(disp?CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT:0);
}

static int arm_valid_a64_add_sub_extended_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;unsigned sf=w>>31,sub=(w>>30)&1,set=(w>>29)&1,rm=(w>>16)&31,option=(w>>13)&7,amount=(w>>10)&7,rn=(w>>5)&31,rd=w&31;uint16_t expected=(uint16_t)(5678+sf*4+sub*2+set);int alias=set&&rd==31,raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0x1f200000))==UINT32_C(0x0b200000)&&amount<=4,form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=5678&&i->form_id<=5685;uint8_t size=sf?8:4;const cdisasm_arm_operand*d=&i->operand[0],*n=&i->operand[alias?0:1],*m=&i->operand[alias?1:2];cdisasm_arm_name_id name=alias?(sub?CDISASM_ARM_NAME_CMP:CDISASM_ARM_NAME_CMN):(sub?(set?CDISASM_ARM_NAME_SUBS:CDISASM_ARM_NAME_SUB):(set?CDISASM_ARM_NAME_ADDS:CDISASM_ARM_NAME_ADD));cdisasm_arm_reg_id mr=(cdisasm_arm_reg_id)(((sf&&(option==3||option==7))?CDISASM_ARM_REG_X0:CDISASM_ARM_REG_W0)+rm);if(!raw&&!form)return 1;if(!raw||!form)return 0;
    if(i->name_id!=name||i->form_id!=expected||i->condition!=CDISASM_ARM_CONDITION_AL||i->opcode_groups!=CDISASM_GROUP_NONE||i->instruction_flags!=(set?CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS:0)||i->operand_count!=(alias?2:3))return 0;if(!alias&&(d->type!=CDISASM_OPERAND_REGISTER||d->reg!=(rd==31&&!set?(sf?CDISASM_ARM_REG_SP:CDISASM_ARM_REG_WSP):(sf?CDISASM_ARM_REG_X0:CDISASM_ARM_REG_W0)+rd)||d->size!=size||d->access!=CDISASM_OPERAND_ACCESS_WRITE))return 0;
    return n->type==CDISASM_OPERAND_REGISTER&&n->reg==(rn==31?(sf?CDISASM_ARM_REG_SP:CDISASM_ARM_REG_WSP):(sf?CDISASM_ARM_REG_X0:CDISASM_ARM_REG_W0)+rn)&&n->size==size&&n->access==CDISASM_OPERAND_ACCESS_READ&&m->type==CDISASM_OPERAND_REGISTER&&m->reg==mr&&m->size==(sf&&(option==3||option==7)?8:4)&&m->access==CDISASM_OPERAND_ACCESS_READ&&m->shift_type==(sf&&option==3?CDISASM_ARM_SHIFT_LSL:CDISASM_ARM_SHIFT_NONE)&&m->shift_amount==(sf&&option==3?amount:0)&&m->extend_type==(sf&&option==3?CDISASM_ARM_EXTEND_NONE:CDISASM_ARM_EXTEND_UXTB+option)&&m->scale==(sf&&option==3?0:amount);
}

static int arm_valid_a64_add_sub_pointer_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;unsigned sub=(w>>30)&1,rm=(w>>16)&31,amount=(w>>10)&7,rn=(w>>5)&31,rd=w&31;int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0xbfe0e000))==UINT32_C(0x9a002000),form=i->isa_id==CDISASM_ARM_ISA_A64&&(i->form_id==5694||i->form_id==5695);const cdisasm_arm_operand*d=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==(sub?CDISASM_ARM_NAME_SUBPT:CDISASM_ARM_NAME_ADDPT)&&i->form_id==(sub?5695:5694)&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==0&&i->operand_count==3&&d->type==CDISASM_OPERAND_REGISTER&&d->reg==(rd==31?CDISASM_ARM_REG_SP:CDISASM_ARM_REG_X0+rd)&&d->size==8&&d->access==CDISASM_OPERAND_ACCESS_WRITE&&n->type==CDISASM_OPERAND_REGISTER&&n->reg==(rn==31?CDISASM_ARM_REG_SP:CDISASM_ARM_REG_X0+rn)&&n->size==8&&n->access==CDISASM_OPERAND_ACCESS_READ&&m->type==CDISASM_OPERAND_REGISTER&&m->reg==CDISASM_ARM_REG_X0+rm&&m->size==8&&m->access==CDISASM_OPERAND_ACCESS_READ&&m->shift_type==(amount?CDISASM_ARM_SHIFT_LSL:CDISASM_ARM_SHIFT_NONE)&&m->shift_amount==amount&&m->extend_type==CDISASM_ARM_EXTEND_NONE&&m->scale==0;
}

static int arm_valid_sme2_multi_clamp_int_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;unsigned count=(w&UINT32_C(0x800))?4:2,u=w&1,size=1u<<((w>>22)&3),zd=w&(count==4?28:30),zn=(w>>5)&31,zm=(w>>16)&31;uint32_t mask=count==4?UINT32_C(0xff20fc03):UINT32_C(0xff20fc01),value=(count==4?UINT32_C(0xc120cc00):UINT32_C(0xc120c400))|u;int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&mask)==value;int form=i->isa_id==CDISASM_ARM_ISA_A64&&(i->form_id==4293||i->form_id==4294||i->form_id==4297||i->form_id==4298);const cdisasm_arm_operand*d=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==(u?CDISASM_ARM_NAME_UCLAMP:CDISASM_ARM_NAME_SCLAMP)&&i->form_id==(count==4?4297:4293)+u&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05400000)&&i->operand_count==3&&d->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&d->reg==CDISASM_ARM_REG_Z0+zd&&d->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&d->extend_type==size&&d->access==CDISASM_OPERAND_ACCESS_WRITE&&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER&&n->reg==CDISASM_ARM_REG_Z0+zn&&n->extend_type==size&&n->access==CDISASM_OPERAND_ACCESS_READ&&m->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER&&m->reg==CDISASM_ARM_REG_Z0+zm&&m->extend_type==size&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sme2_multi_zip_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;unsigned q=(w&UINT32_C(0x400))!=0,u=w&1,size=q?16:1u<<((w>>22)&3),zd=w&30,zn=(w>>5)&31,zm=(w>>16)&31;uint32_t mask=q?UINT32_C(0xffe0fc01):UINT32_C(0xff20fc01),value=(q?UINT32_C(0xc120d400):UINT32_C(0xc120d000))|u;int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&mask)==value;int form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=4299&&i->form_id<=4302;const cdisasm_arm_operand*d=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==(u?CDISASM_ARM_NAME_UZP:CDISASM_ARM_NAME_ZIP)&&i->form_id==(q?4301:4299)+u&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05400000)&&i->operand_count==3&&d->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&d->reg==CDISASM_ARM_REG_Z0+zd&&d->register_list==UINT16_C(0x0102)&&d->extend_type==size&&d->access==CDISASM_OPERAND_ACCESS_WRITE&&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER&&n->reg==CDISASM_ARM_REG_Z0+zn&&n->extend_type==size&&n->access==CDISASM_OPERAND_ACCESS_READ&&m->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER&&m->reg==CDISASM_ARM_REG_Z0+zm&&m->extend_type==size&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sme2_multi4_qrshrn_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction,opcode=w&UINT32_C(0x60);unsigned tsize=(w>>22)&3u,encoded=(tsize<<5)|((w>>16)&31u),source_bits=tsize==1u?32u:64u,zn=((w>>7)&7u)*4u;uint16_t expected=opcode==UINT32_C(0x40)?4309u:opcode==UINT32_C(0x20)?4311u:4308u;cdisasm_arm_name_id name=opcode==UINT32_C(0x40)?CDISASM_ARM_NAME_SQRSHRUN:opcode==UINT32_C(0x20)?CDISASM_ARM_NAME_UQRSHRN:CDISASM_ARM_NAME_SQRSHRN;int raw=i->isa_id==CDISASM_ARM_ISA_A64&&tsize!=0u&&((w&UINT32_C(0xff20fc60))==UINT32_C(0xc120dc00)||(w&UINT32_C(0xff20fc60))==UINT32_C(0xc120dc40)||(w&UINT32_C(0xff20fc60))==UINT32_C(0xc120dc20));int form=i->isa_id==CDISASM_ARM_ISA_A64&&(i->form_id==4308u||i->form_id==4309u||i->form_id==4311u);const cdisasm_arm_operand*d=&i->operand[0],*n=&i->operand[1];if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==name&&i->form_id==expected&&i->opcode_size==4u&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05400000)&&i->branch_target==0u&&i->operand_count==3u&&arm_exact_scalable_operand(d,(cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0+(w&31u)),(uint8_t)(source_bits/32u),CDISASM_OPERAND_ACCESS_WRITE)&&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&n->reg==CDISASM_ARM_REG_Z0+zn&&n->register_list==UINT16_C(0x0104)&&n->extend_type==source_bits/8u&&n->access==CDISASM_OPERAND_ACCESS_READ&&arm_exact_immediate_operand(&i->operand[2],2u*source_bits-encoded);
}

static int arm_valid_sme2_indexed_d2_schema(const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id names[4]={CDISASM_ARM_NAME_FMLA,CDISASM_ARM_NAME_SDOT,CDISASM_ARM_NAME_FMLS,CDISASM_ARM_NAME_UDOT};
    static const uint16_t forms4[4]={4042,4043,4045,4046};uint32_t w=i->raw_instruction;unsigned op=(w>>3)&3,size=(op&1)?2:8,lane=(w>>10)&1,count=(w&UINT32_C(0x8000))?4:2,zn=count==4?((w>>7)&7)*4:((w>>6)&15)*2;uint32_t mask=count==4?UINT32_C(0xfff09878):UINT32_C(0xfff09838),value=count==4?UINT32_C(0xc1d08000):UINT32_C(0xc1d00000);int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&mask)==(value|(op<<3));int form=i->isa_id==CDISASM_ARM_ISA_A64&&((i->form_id>=3996&&i->form_id<=3999)||i->form_id==4042||i->form_id==4043||i->form_id==4045||i->form_id==4046);const cdisasm_arm_operand*t=&i->operand[0],*l=&i->operand[1];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==names[op]&&i->form_id==(count==4?forms4[op]:3996+op)&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==(uint32_t)(UINT32_C(0x05400000)|((op&1)?0:CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT))&&i->operand_count==3
      &&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==count&&t->imm==(w&7)&&t->size==0&&t->flags==0&&t->extend_type==8&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE
      &&l->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&l->reg==CDISASM_ARM_REG_Z0+zn&&l->register_list==(uint16_t)(0x0100|count)&&l->extend_type==size&&l->access==CDISASM_OPERAND_ACCESS_READ
      &&arm_exact_scalable_lane_operand(&i->operand[2],CDISASM_ARM_REG_Z0+((w>>16)&15),(uint8_t)size,lane,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sme2_indexed_vdot_d4_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;int u=(w&UINT32_C(0x10))!=0;unsigned lane=(w>>10)&1,zn=((w>>7)&7)*4;uint32_t value=u?UINT32_C(0xc1d08818):UINT32_C(0xc1d08808);int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0xfff09878))==value;int form=i->isa_id==CDISASM_ARM_ISA_A64&&(i->form_id==4044||i->form_id==4047);const cdisasm_arm_operand*t=&i->operand[0],*l=&i->operand[1];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==(u?CDISASM_ARM_NAME_UVDOT:CDISASM_ARM_NAME_SVDOT)&&i->form_id==(u?4047:4044)&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05400000)&&i->operand_count==3
      &&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==4&&t->imm==(w&7)&&t->size==0&&t->flags==0&&t->extend_type==8&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE
      &&l->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&l->reg==CDISASM_ARM_REG_Z0+zn&&l->register_list==UINT16_C(0x0104)&&l->extend_type==2&&l->access==CDISASM_OPERAND_ACCESS_READ
      &&arm_exact_scalable_lane_operand(&i->operand[2],CDISASM_ARM_REG_Z0+((w>>16)&15),2,lane,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sme2_indexed_vdot_s_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;int u=(w&UINT32_C(0x10))!=0;unsigned count=(w&UINT32_C(0x8000))?4:2,size=count==4?1:2,lane=(w>>10)&3,zn=count==4?((w>>7)&7)*4:((w>>6)&15)*2;uint32_t mask=count==4?UINT32_C(0xfff09078):UINT32_C(0xfff09038),value=count==4?UINT32_C(0xc1508020):UINT32_C(0xc1500020);uint16_t expected=count==4?(u?4028:4020):(u?3980:3972);int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&mask)==(value|(u?UINT32_C(0x10):0));int form=i->isa_id==CDISASM_ARM_ISA_A64&&(i->form_id==3972||i->form_id==3980||i->form_id==4020||i->form_id==4028);const cdisasm_arm_operand*t=&i->operand[0],*l=&i->operand[1];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==(u?CDISASM_ARM_NAME_UVDOT:CDISASM_ARM_NAME_SVDOT)&&i->form_id==expected&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05400000)&&i->operand_count==3
      &&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==count&&t->imm==(w&7)&&t->size==0&&t->flags==0&&t->extend_type==4&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE
      &&l->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&l->reg==CDISASM_ARM_REG_Z0+zn&&l->register_list==(uint16_t)(0x0100|count)&&l->extend_type==size&&l->access==CDISASM_OPERAND_ACCESS_READ
      &&arm_exact_scalable_lane_operand(&i->operand[2],CDISASM_ARM_REG_Z0+((w>>16)&15),(uint8_t)size,lane,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sme2_indexed_mixed_dot_s_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;int s=(w&UINT32_C(0x10))!=0;unsigned count=(w&UINT32_C(0x8000))?4:2,lane=(w>>10)&3,zn=count==4?((w>>7)&7)*4:((w>>6)&15)*2;uint32_t mask=count==4?UINT32_C(0xfff09078):UINT32_C(0xfff09038),value=count==4?UINT32_C(0xc1509028):UINT32_C(0xc1501028);uint16_t expected=count==4?(s?4032:4026):(s?3983:3978);int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&mask)==(value|(s?UINT32_C(0x10):0));int form=i->isa_id==CDISASM_ARM_ISA_A64&&(i->form_id==3978||i->form_id==3983||i->form_id==4026||i->form_id==4032);const cdisasm_arm_operand*t=&i->operand[0],*l=&i->operand[1];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==(s?CDISASM_ARM_NAME_SUDOT:CDISASM_ARM_NAME_USDOT)&&i->form_id==expected&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05400000)&&i->operand_count==3
      &&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==count&&t->imm==(w&7)&&t->size==0&&t->flags==0&&t->extend_type==4&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE
      &&l->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&l->reg==CDISASM_ARM_REG_Z0+zn&&l->register_list==(uint16_t)(0x0100|count)&&l->extend_type==1&&l->access==CDISASM_OPERAND_ACCESS_READ
      &&arm_exact_scalable_lane_operand(&i->operand[2],CDISASM_ARM_REG_Z0+((w>>16)&15),1,lane,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sme2_indexed_multi2_s_schema(const cdisasm_arm_instruction *i)
{
    static const uint16_t opcodes[9]={0x0000,0x0010,0x0038,0x1000,0x1008,0x1010,0x1018,0x1020,0x1030};
    static const uint16_t forms[9]={3969,3979,3973,3974,3975,3981,3976,3977,3982};
    static const cdisasm_arm_name_id names[9]={CDISASM_ARM_NAME_FMLA,CDISASM_ARM_NAME_FMLS,CDISASM_ARM_NAME_FDOT,CDISASM_ARM_NAME_SDOT,CDISASM_ARM_NAME_FDOT,CDISASM_ARM_NAME_UDOT,CDISASM_ARM_NAME_BFDOT,CDISASM_ARM_NAME_SDOT,CDISASM_ARM_NAME_UDOT};
    uint32_t w=i->raw_instruction;unsigned k,size,lane,zn=((w>>6)&15)*2;int raw=0,form=0;
    for(k=0;k<9;k++){if((w&UINT32_C(0xfff09038))==(UINT32_C(0xc1500000)|opcodes[k]))raw=i->isa_id==CDISASM_ARM_ISA_A64;if(i->form_id==forms[k])form=i->isa_id==CDISASM_ARM_ISA_A64;if(raw||form)break;}
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    size=(k<2)?4:((k==2||k>=7)?1:2);lane=(w>>10)&(size==2?1:3);
    return i->name_id==names[k]&&i->form_id==forms[k]&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE
      &&i->instruction_flags==(uint32_t)(UINT32_C(0x05400000)|((k<3||k==4||k==6)?CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT:0))&&i->operand_count==3
      &&i->operand[0].type==CDISASM_ARM_OPERAND_TILE&&i->operand[0].reg==CDISASM_ARM_REG_ZA&&i->operand[0].base_reg==CDISASM_ARM_REG_W8+((w>>13)&3)&&i->operand[0].index_reg==CDISASM_ARM_REG_NONE&&i->operand[0].register_list==2&&i->operand[0].imm==(w&7)&&i->operand[0].size==0&&i->operand[0].flags==0&&i->operand[0].extend_type==4&&i->operand[0].access==CDISASM_OPERAND_ACCESS_READ_WRITE
      &&i->operand[1].type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&i->operand[1].reg==CDISASM_ARM_REG_Z0+zn&&i->operand[1].register_list==UINT16_C(0x0102)&&i->operand[1].extend_type==size&&i->operand[1].access==CDISASM_OPERAND_ACCESS_READ
      &&arm_exact_scalable_lane_operand(&i->operand[2],CDISASM_ARM_REG_Z0+((w>>16)&15),(uint8_t)size,lane,CDISASM_OPERAND_ACCESS_READ);
}

/* FEAT_SME_TMOP has an untyped indexed control Z register.  Keep its exact
 * four-operand contract separate from the ordinary typed indexed Z forms. */
static int arm_valid_sme_tmop_schema(const cdisasm_arm_instruction *i)
{
    typedef struct arm_tmop_format_info {
        uint32_t value;
        cdisasm_arm_name_id name;
        uint8_t tile_size;
        uint8_t source_size;
    } arm_tmop_format_info;
    static const arm_tmop_format_info forms[] = {
        { UINT32_C(0x80400000), CDISASM_ARM_NAME_FTMOPA, 4u, 4u },
        { UINT32_C(0x80600000), CDISASM_ARM_NAME_FTMOPA, 4u, 1u },
        { UINT32_C(0x81400000), CDISASM_ARM_NAME_BFTMOPA, 4u, 2u },
        { UINT32_C(0x81600000), CDISASM_ARM_NAME_FTMOPA, 4u, 2u },
        { UINT32_C(0x80408000), CDISASM_ARM_NAME_STMOPA, 4u, 1u },
        { UINT32_C(0x80608000), CDISASM_ARM_NAME_SUTMOPA, 4u, 1u },
        { UINT32_C(0x81408000), CDISASM_ARM_NAME_USTMOPA, 4u, 1u },
        { UINT32_C(0x81608000), CDISASM_ARM_NAME_UTMOPA, 4u, 1u },
        { UINT32_C(0x80600008), CDISASM_ARM_NAME_FTMOPA, 2u, 1u },
        { UINT32_C(0x81400008), CDISASM_ARM_NAME_FTMOPA, 2u, 2u },
        { UINT32_C(0x81600008), CDISASM_ARM_NAME_BFTMOPA, 2u, 2u },
        { UINT32_C(0x80408008), CDISASM_ARM_NAME_STMOPA, 4u, 2u },
        { UINT32_C(0x81408008), CDISASM_ARM_NAME_UTMOPA, 4u, 2u }
    };
    const arm_tmop_format_info *info;
    const cdisasm_arm_operand *tile;
    const cdisasm_arm_operand *list;
    const cdisasm_arm_operand *source;
    const cdisasm_arm_operand *control;
    uint32_t word;
    uint32_t mask;

    if (i->form_id < UINT16_C(3772) || i->form_id > UINT16_C(3784)) {
        return 1;
    }
    info = &forms[i->form_id - UINT16_C(3772)];
    word = i->raw_instruction;
    mask = info->tile_size == 2u
        ? UINT32_C(0xffe0e00e) : UINT32_C(0xffe0e00c);
    if (i->isa_id != CDISASM_ARM_ISA_A64
        || (word & mask) != info->value
        || i->name_id != info->name || i->operand_count != 4u
        || (i->instruction_flags
            & (CDISASM_ARM_INSTRUCTION_FLAG_SME
                | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
                | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR))
            != (CDISASM_ARM_INSTRUCTION_FLAG_SME
                | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
                | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR)) {
        return 0;
    }
    tile = &i->operand[0];
    list = &i->operand[1];
    source = &i->operand[2];
    control = &i->operand[3];
    return tile->type == CDISASM_ARM_OPERAND_TILE
        && tile->reg == (cdisasm_arm_reg_id)(
            (info->tile_size == 2u
                ? CDISASM_ARM_REG_ZAH0 : CDISASM_ARM_REG_ZAS0)
            + (word & (info->tile_size == 2u ? 1u : 3u)))
        && tile->extend_type == info->tile_size
        && tile->access == CDISASM_OPERAND_ACCESS_READ_WRITE
        && list->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
        && list->reg == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0
            + (((word >> 6) & 15u) * 2u))
        && list->register_list == UINT16_C(0x0102)
        && list->extend_type == info->source_size
        && list->access == CDISASM_OPERAND_ACCESS_READ
        && source->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER
        && source->reg == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0
            + ((word >> 16) & 31u))
        && source->extend_type == info->source_size
        && source->access == CDISASM_OPERAND_ACCESS_READ
        && control->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER
        && control->reg == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0
            + 20u + (((word >> 12) & 1u) * 8u)
            + ((word >> 10) & 3u))
        && control->extend_type == 0u
        && control->flags == CDISASM_ARM_OPERAND_FLAG_HAS_LANE
        && control->imm == ((word >> 4) & 3u)
        && control->access == CDISASM_OPERAND_ACCESS_READ;
}

/* FEAT_SME2 FVDOT/BFVDOT and FP8 FVDOT indexed forms.  These encodings share
 * the older indexed multi-vector envelope but use distinct mnemonics; keep a
 * separate schema so formatter validation cannot accidentally accept them as
 * FDOT/UDOT. */
static int arm_valid_sme_fvdot_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w = i->raw_instruction;
    unsigned count;
    uint16_t form;
    cdisasm_arm_name_id name;
    unsigned source_size;
    unsigned tile_size;
    unsigned lane_mask;
    uint32_t mask;
    uint32_t value;
    const cdisasm_arm_operand *tile;
    const cdisasm_arm_operand *list;
    const cdisasm_arm_operand *indexed;

    if (i->form_id == UINT16_C(6500)
            || i->form_id == UINT16_C(6501)) {
        count = 2u;
        form = (uint16_t)i->form_id;
        name = i->form_id == UINT16_C(6501)
            ? CDISASM_ARM_NAME_BFVDOT : CDISASM_ARM_NAME_FVDOT;
        source_size = 2u;
        tile_size = 4u;
        lane_mask = 1u;
        mask = UINT32_C(0xfff09038);
        value = i->form_id == UINT16_C(6501)
            ? UINT32_C(0xc1500018) : UINT32_C(0xc1500008);
    } else if (i->form_id == UINT16_C(6502)
            || i->form_id == UINT16_C(6503)) {
        count = 4u;
        form = (uint16_t)i->form_id;
        name = i->form_id == UINT16_C(6503)
            ? CDISASM_ARM_NAME_FVDOTT : CDISASM_ARM_NAME_FVDOTB;
        source_size = 1u;
        tile_size = 4u;
        lane_mask = 3u;
        mask = UINT32_C(0xfff09830);
        value = i->form_id == UINT16_C(6503)
            ? UINT32_C(0xc1d00810) : UINT32_C(0xc1d00800);
    } else if (i->form_id == UINT16_C(6504)) {
        count = 2u;
        form = 6504u;
        name = CDISASM_ARM_NAME_FVDOT;
        source_size = 1u;
        tile_size = 2u;
        lane_mask = 3u;
        mask = UINT32_C(0xfff09030);
        value = UINT32_C(0xc1d01020);
    } else {
        return 1;
    }
    if (i->isa_id != CDISASM_ARM_ISA_A64
        || (w & mask) != value) {
        return 0;
    }
    tile = &i->operand[0];
    list = &i->operand[1];
    indexed = &i->operand[2];
    return i->name_id == name && i->form_id == form
        && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags == UINT32_C(0x05402000)
        && i->operand_count == 3u
        && tile->type == CDISASM_ARM_OPERAND_TILE
        && tile->reg == CDISASM_ARM_REG_ZA
        && tile->base_reg == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_W8
            + ((w >> 13) & 3u))
        && tile->register_list == count && tile->imm == (w & 7u)
        && tile->size == 0u && tile->flags == 0u
        && tile->extend_type == tile_size
        && tile->access == CDISASM_OPERAND_ACCESS_READ_WRITE
        && list->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
        && list->reg == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0
            + (count == 4u ? ((w >> 7) & 7u) * 4u
                           : ((w >> 6) & 15u) * 2u))
        && list->register_list == UINT16_C(0x0102)
        && list->extend_type == source_size
        && list->access == CDISASM_OPERAND_ACCESS_READ
        && indexed->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER
        && indexed->reg == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0
            + ((w >> 16) & 15u))
        && indexed->extend_type == source_size
        && indexed->flags == CDISASM_ARM_OPERAND_FLAG_HAS_LANE
        && indexed->imm == ((w >> 10) & lane_mask)
        && indexed->access == CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sme2_indexed_multi4_s_schema(const cdisasm_arm_instruction *i)
{
    static const uint16_t opcodes[9]={0x0000,0x0010,0x0008,0x1000,0x1008,0x1010,0x1018,0x1020,0x1030};
    static const uint16_t forms[9]={4018,4027,4019,4022,4023,4030,4024,4025,4031};
    static const cdisasm_arm_name_id names[9]={CDISASM_ARM_NAME_FMLA,CDISASM_ARM_NAME_FMLS,CDISASM_ARM_NAME_FDOT,CDISASM_ARM_NAME_SDOT,CDISASM_ARM_NAME_FDOT,CDISASM_ARM_NAME_UDOT,CDISASM_ARM_NAME_BFDOT,CDISASM_ARM_NAME_SDOT,CDISASM_ARM_NAME_UDOT};
    uint32_t w=i->raw_instruction;unsigned k,size,lane,zn=((w>>7)&7)*4;int raw=0,form=0;
    for(k=0;k<9;k++){if((w&UINT32_C(0xfff09078))==(UINT32_C(0xc1508000)|opcodes[k]))raw=i->isa_id==CDISASM_ARM_ISA_A64;if(i->form_id==forms[k])form=i->isa_id==CDISASM_ARM_ISA_A64;if(raw||form)break;}
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    size=(k<2)?4:((k==2||k>=7)?1:2);lane=(w>>10)&(size==2?1:3);
    return i->name_id==names[k]&&i->form_id==forms[k]&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE
      &&i->instruction_flags==(uint32_t)(UINT32_C(0x05400000)|((k<3||k==4||k==6)?CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT:0))&&i->operand_count==3
      &&i->operand[0].type==CDISASM_ARM_OPERAND_TILE&&i->operand[0].reg==CDISASM_ARM_REG_ZA&&i->operand[0].base_reg==CDISASM_ARM_REG_W8+((w>>13)&3)&&i->operand[0].index_reg==CDISASM_ARM_REG_NONE&&i->operand[0].register_list==4&&i->operand[0].imm==(w&7)&&i->operand[0].size==0&&i->operand[0].flags==0&&i->operand[0].extend_type==4&&i->operand[0].access==CDISASM_OPERAND_ACCESS_READ_WRITE
      &&i->operand[1].type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&i->operand[1].reg==CDISASM_ARM_REG_Z0+zn&&i->operand[1].register_list==UINT16_C(0x0104)&&i->operand[1].extend_type==size&&i->operand[1].access==CDISASM_OPERAND_ACCESS_READ
      &&arm_exact_scalable_lane_operand(&i->operand[2],CDISASM_ARM_REG_Z0+((w>>16)&15),(uint8_t)size,lane,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sme_indexed_fp8_fdot_h_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;unsigned count=(w&UINT32_C(0x8000))?4:2,zn=count==4?((w>>7)&7)*4:((w>>6)&15)*2,lane=((w>>9)&6)|((w>>3)&1);uint32_t mask=count==4?UINT32_C(0xfff09070):UINT32_C(0xfff09030),value=count==4?UINT32_C(0xc1109040):UINT32_C(0xc1d00020);uint16_t expected=count==4?4017:4004;int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&mask)==value,form=i->isa_id==CDISASM_ARM_ISA_A64&&(i->form_id==4004||i->form_id==4017);const cdisasm_arm_operand*t=&i->operand[0],*l=&i->operand[1];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==CDISASM_ARM_NAME_FDOT&&i->form_id==expected&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05402000)&&i->operand_count==3
      &&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==count&&t->imm==(w&7)&&t->size==0&&t->flags==0&&t->extend_type==2&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE
      &&l->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&l->reg==CDISASM_ARM_REG_Z0+zn&&l->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&l->extend_type==1&&l->access==CDISASM_OPERAND_ACCESS_READ
      &&arm_exact_scalable_lane_operand(&i->operand[2],CDISASM_ARM_REG_Z0+((w>>16)&15),1,lane,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sme2_multi2_long_mla_single_schema(const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id names[4]={CDISASM_ARM_NAME_SMLAL,CDISASM_ARM_NAME_SMLSL,CDISASM_ARM_NAME_UMLAL,CDISASM_ARM_NAME_UMLSL};
    uint32_t w=i->raw_instruction;unsigned op=(w>>3)&3,zn=(w>>5)&30;int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0xfff09c1c))==(UINT32_C(0xc1600800)|(op<<3)),form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=4069&&i->form_id<=4072;const cdisasm_arm_operand*t=&i->operand[0],*l=&i->operand[1];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==names[op]&&i->form_id==4069+op&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05400000)&&i->operand_count==3
      &&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==2&&t->imm==(w&3)*2&&t->size==0&&t->flags==0&&t->extend_type==4&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE
      &&l->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&l->reg==CDISASM_ARM_REG_Z0+zn&&l->register_list==UINT16_C(0x0102)&&l->extend_type==2&&l->access==CDISASM_OPERAND_ACCESS_READ
      &&arm_exact_scalable_operand(&i->operand[2],CDISASM_ARM_REG_Z0+((w>>16)&15),2,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sme2_multi4_long_mla_single_schema(const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id names[4]={CDISASM_ARM_NAME_SMLAL,CDISASM_ARM_NAME_SMLSL,CDISASM_ARM_NAME_UMLAL,CDISASM_ARM_NAME_UMLSL};
    uint32_t w=i->raw_instruction;unsigned op=(w>>3)&3,zn=(w>>5)&28;int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0xfff09c1c))==(UINT32_C(0xc1700800)|(op<<3)),form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=4112&&i->form_id<=4115;const cdisasm_arm_operand*t=&i->operand[0],*l=&i->operand[1];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==names[op]&&i->form_id==4112+op&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05400000)&&i->operand_count==3
      &&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==4&&t->imm==(w&3)*2&&t->size==0&&t->flags==0&&t->extend_type==4&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE
      &&l->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&l->reg==CDISASM_ARM_REG_Z0+zn&&l->register_list==UINT16_C(0x0104)&&l->extend_type==2&&l->access==CDISASM_OPERAND_ACCESS_READ
      &&arm_exact_scalable_operand(&i->operand[2],CDISASM_ARM_REG_Z0+((w>>16)&15),2,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sme2_single_long_mla_schema(const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id names[4]={CDISASM_ARM_NAME_SMLAL,CDISASM_ARM_NAME_SMLSL,CDISASM_ARM_NAME_UMLAL,CDISASM_ARM_NAME_UMLSL};
    uint32_t w=i->raw_instruction;unsigned op=(w>>3)&3;int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0xfff09c18))==(UINT32_C(0xc1600c00)|(op<<3)),form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=4077&&i->form_id<=4080;const cdisasm_arm_operand*t=&i->operand[0];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==names[op]&&i->form_id==4077+op&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05400000)&&i->operand_count==3
      &&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==2&&t->imm==(w&3)*2&&t->size==0&&t->flags==0&&t->extend_type==4&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE
      &&arm_exact_scalable_operand(&i->operand[1],CDISASM_ARM_REG_Z0+((w>>5)&31),2,CDISASM_OPERAND_ACCESS_READ)
      &&arm_exact_scalable_operand(&i->operand[2],CDISASM_ARM_REG_Z0+((w>>16)&15),2,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sme_multi2_fdot_single_schema(const cdisasm_arm_instruction *i)
{
    static const uint16_t forms2[4]={4081,4083,4082,4084},forms4[4]={4117,4119,4118,4120};uint32_t w=i->raw_instruction;unsigned op=(w>>3)&3,count=(w&UINT32_C(0x00100000))?4:2,ss=(op==1||op==3)?1:2,ds=op==1?2:4,zn=count==4?((w>>7)&7)*4:(w>>5)&30;int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0xffe09c18))==(UINT32_C(0xc1201000)|(op<<3)),form=i->isa_id==CDISASM_ARM_ISA_A64&&((i->form_id>=4081&&i->form_id<=4084)||(i->form_id>=4117&&i->form_id<=4120));const cdisasm_arm_operand*t=&i->operand[0],*l=&i->operand[1];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==(op==2?CDISASM_ARM_NAME_BFDOT:CDISASM_ARM_NAME_FDOT)&&i->form_id==(count==4?forms4[op]:forms2[op])&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05402000)&&i->operand_count==3
      &&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==count&&t->imm==(w&7)&&t->size==0&&t->flags==0&&t->extend_type==ds&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE
      &&l->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&l->reg==CDISASM_ARM_REG_Z0+zn&&l->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&l->extend_type==ss&&l->access==CDISASM_OPERAND_ACCESS_READ
      &&arm_exact_scalable_operand(&i->operand[2],CDISASM_ARM_REG_Z0+((w>>16)&15),(uint8_t)ss,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sme_multi_fdot_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;unsigned op=(w>>4)&3,count=(w&UINT32_C(0x10000))?4:2,ss=op>=2?1:2,ds=op==2?2:4,zn=count==4?((w>>7)&7)*4:((w>>6)&15)*2,zm=(w>>16)&(count==4?28:30);uint32_t mask=count==4?UINT32_C(0xffe39c78):UINT32_C(0xffe19c38),value=(count==4?UINT32_C(0xc1a11000):UINT32_C(0xc1a01000))|(op<<4);int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&mask)==value,form=i->isa_id==CDISASM_ARM_ISA_A64&&((i->form_id>=4150&&i->form_id<=4153)||(i->form_id>=4190&&i->form_id<=4193));const cdisasm_arm_operand*t=&i->operand[0],*n=&i->operand[1],*m=&i->operand[2];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==(op==1?CDISASM_ARM_NAME_BFDOT:CDISASM_ARM_NAME_FDOT)&&i->form_id==(count==4?4190:4150)+op&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05402000)&&i->operand_count==3
      &&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==count&&t->imm==(w&7)&&t->size==0&&t->flags==0&&t->extend_type==ds&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE
      &&n->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&n->reg==CDISASM_ARM_REG_Z0+zn&&n->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&n->extend_type==ss&&n->access==CDISASM_OPERAND_ACCESS_READ
      &&m->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&m->reg==CDISASM_ARM_REG_Z0+zm&&m->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&m->extend_type==ss&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sme_multi2_integer_dot_single_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction,key=w&UINT32_C(0x00400018);unsigned count=(w&UINT32_C(0x00100000))?4:2,wide=(w>>22)&1,ss=1,ds=4,zn=count==4?((w>>7)&7)*4:(w>>5)&30;uint16_t expected=0;cdisasm_arm_name_id name=CDISASM_ARM_NAME_NONE;int raw=0,form=i->isa_id==CDISASM_ARM_ISA_A64&&((i->form_id>=4085&&i->form_id<=4090)||(i->form_id>=4121&&i->form_id<=4126));const cdisasm_arm_operand*t=&i->operand[0],*l=&i->operand[1];
    if((key&0x18)==0){name=CDISASM_ARM_NAME_SDOT;expected=4085;ss=wide?2:1;ds=wide?8:4;raw=(w&UINT32_C(0xffa09c18))==UINT32_C(0xc1201400);}else if((key&0x18)==0x10){name=CDISASM_ARM_NAME_UDOT;expected=4086;ss=wide?2:1;ds=wide?8:4;raw=(w&UINT32_C(0xffa09c18))==UINT32_C(0xc1201410);}else if(key==8){name=CDISASM_ARM_NAME_USDOT;expected=4087;raw=(w&UINT32_C(0xffe09c18))==UINT32_C(0xc1201408);}else if(key==0x18){name=CDISASM_ARM_NAME_SUDOT;expected=4088;raw=(w&UINT32_C(0xffe09c18))==UINT32_C(0xc1201418);}else if(key==0x400008){name=CDISASM_ARM_NAME_SDOT;expected=4089;ss=2;raw=(w&UINT32_C(0xffe09c18))==UINT32_C(0xc1601408);}else if(key==0x400018){name=CDISASM_ARM_NAME_UDOT;expected=4090;ss=2;raw=(w&UINT32_C(0xffe09c18))==UINT32_C(0xc1601418);}raw=raw&&i->isa_id==CDISASM_ARM_ISA_A64;if(count==4)expected+=36;
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==name&&i->form_id==expected&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05400000)&&i->operand_count==3
      &&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==count&&t->imm==(w&7)&&t->size==0&&t->flags==0&&t->extend_type==ds&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE
      &&l->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&l->reg==CDISASM_ARM_REG_Z0+zn&&l->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&l->extend_type==ss&&l->access==CDISASM_OPERAND_ACCESS_READ
      &&arm_exact_scalable_operand(&i->operand[2],CDISASM_ARM_REG_Z0+((w>>16)&15),(uint8_t)ss,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sme_multi2_arith_single_schema(const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id base_names[4]={CDISASM_ARM_NAME_FMLA,CDISASM_ARM_NAME_FMLS,CDISASM_ARM_NAME_ADD,CDISASM_ARM_NAME_SUB};uint32_t w=i->raw_instruction;int half=(w&UINT32_C(0x1c00))==UINT32_C(0x1c00),bf=half&&((w>>22)&1);unsigned count=(w&UINT32_C(0x00100000))?4:2,op=(w>>3)&(half?1:3),size=half?2:((w>>22)&1?8:4),zn=count==4?((w>>7)&7)*4:(w>>5)&30;uint16_t expected; cdisasm_arm_name_id name;int raw,form=i->isa_id==CDISASM_ARM_ISA_A64&&((i->form_id>=4091&&i->form_id<=4098)||(i->form_id>=4127&&i->form_id<=4134));const cdisasm_arm_operand*t=&i->operand[0],*l=&i->operand[1];
    if(half){name=bf?(op?CDISASM_ARM_NAME_BFMLS:CDISASM_ARM_NAME_BFMLA):(op?CDISASM_ARM_NAME_FMLS:CDISASM_ARM_NAME_FMLA);expected=op?(bf?4098:4097):(bf?4096:4095);raw=(w&UINT32_C(0xffe09c18))==((bf?UINT32_C(0xc1601c00):UINT32_C(0xc1201c00))|(op<<3));}else{name=base_names[op];expected=4091+op;raw=(w&UINT32_C(0xffa09c18))==(UINT32_C(0xc1201800)|(op<<3));}raw=raw&&i->isa_id==CDISASM_ARM_ISA_A64;if(count==4)expected+=36;
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==name&&i->form_id==expected&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==(uint32_t)(UINT32_C(0x05400000)|((half||op<2)?CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT:0))&&i->operand_count==3
      &&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==count&&t->imm==(w&7)&&t->size==0&&t->flags==0&&t->extend_type==size&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE
      &&l->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&l->reg==CDISASM_ARM_REG_Z0+zn&&l->register_list==(uint16_t)(UINT16_C(0x0100)|count)&&l->extend_type==size&&l->access==CDISASM_OPERAND_ACCESS_READ
      &&arm_exact_scalable_operand(&i->operand[2],CDISASM_ARM_REG_Z0+((w>>16)&15),(uint8_t)size,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sme_indexed_fp16_mla_schema(const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id names[4]={CDISASM_ARM_NAME_FMLA,CDISASM_ARM_NAME_FMLS,CDISASM_ARM_NAME_BFMLA,CDISASM_ARM_NAME_BFMLS};
    static const uint16_t forms2[4]={3965,3967,3966,3968},forms4[4]={4013,4015,4014,4016};uint32_t w=i->raw_instruction;unsigned op=(w>>4)&3,lane=((w>>9)&6)|((w>>3)&1),count=(w&UINT32_C(0x8000))?4:2,zn=count==4?((w>>7)&7)*4:((w>>6)&15)*2;uint32_t mask=count==4?UINT32_C(0xfff09070):UINT32_C(0xfff09030),value=count==4?UINT32_C(0xc1109000):UINT32_C(0xc1101000);int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&mask)==(value|(op<<4));int form=i->isa_id==CDISASM_ARM_ISA_A64&&((i->form_id>=3965&&i->form_id<=3968)||(i->form_id>=4013&&i->form_id<=4016));const cdisasm_arm_operand*t=&i->operand[0],*l=&i->operand[1];
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==names[op]&&i->form_id==(count==4?forms4[op]:forms2[op])&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05402000)&&i->operand_count==3
      &&t->type==CDISASM_ARM_OPERAND_TILE&&t->reg==CDISASM_ARM_REG_ZA&&t->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3)&&t->index_reg==CDISASM_ARM_REG_NONE&&t->register_list==count&&t->imm==(w&7)&&t->size==0&&t->flags==0&&t->extend_type==2&&t->access==CDISASM_OPERAND_ACCESS_READ_WRITE
      &&l->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&l->reg==CDISASM_ARM_REG_Z0+zn&&l->register_list==(uint16_t)(0x0100|count)&&l->extend_type==2&&l->access==CDISASM_OPERAND_ACCESS_READ
      &&arm_exact_scalable_lane_operand(&i->operand[2],CDISASM_ARM_REG_Z0+((w>>16)&15),2,lane,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sme2p1_zero_multi_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;int four=(w&UINT32_C(0x20000))!=0;
    uint32_t value=four?UINT32_C(0xc00e0000):UINT32_C(0xc00c0000);
    int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0xffff9ff8))==value;
    int form=i->isa_id==CDISASM_ARM_ISA_A64&&(i->form_id==3908||i->form_id==3909);
    const cdisasm_arm_operand *o=&i->operand[0];unsigned count=four?4u:2u;
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==CDISASM_ARM_NAME_ZERO&&i->form_id==(four?3909:3908)
      &&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE
      &&i->instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SME|CDISASM_ARM_INSTRUCTION_FLAG_MATRIX|CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR)&&i->operand_count==1
      &&o->type==CDISASM_ARM_OPERAND_TILE&&o->reg==CDISASM_ARM_REG_ZA
      &&o->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3)&&o->index_reg==CDISASM_ARM_REG_NONE
      &&o->register_list==count&&o->imm==(w&7)&&o->size==0&&o->flags==0
      &&o->extend_type==8&&o->access==CDISASM_OPERAND_ACCESS_WRITE;
}

static int arm_valid_sme2p1_zero_range_schema(const cdisasm_arm_instruction *i)
{
    typedef struct Z{uint32_t m,v;uint16_t f;uint8_t r,g;}Z;
    static const Z z[]={{0xffff9ff8,0xc00c8000,3910,2,0},{0xffff9ffc,0xc00d0000,3911,2,2},{0xffff9ffc,0xc00d8000,3912,2,4},{0xffff9ffc,0xc00e8000,3913,4,0},{0xffff9ffe,0xc00f0000,3914,4,2},{0xffff9ffe,0xc00f8000,3915,4,4}};
    const Z*x=NULL;int form=0;size_t n;uint32_t w=i->raw_instruction;
    for(n=0;n<6;n++){if(i->isa_id==CDISASM_ARM_ISA_A64&&(w&z[n].m)==z[n].v)x=&z[n];if(i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id==z[n].f)form=1;}
    if(x==NULL&&!form)return 1;if(x==NULL||!form)return 0;
    {const cdisasm_arm_operand*o=&i->operand[0];uint64_t start=(w&(x->r==4?3u:7u))*x->r;
    return i->name_id==CDISASM_ARM_NAME_ZERO&&i->form_id==x->f&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==UINT32_C(0x05400000)&&i->operand_count==1&&o->type==CDISASM_ARM_OPERAND_TILE&&o->reg==CDISASM_ARM_REG_ZA&&o->base_reg==CDISASM_ARM_REG_W8+((w>>13)&3)&&o->index_reg==CDISASM_ARM_REG_NONE&&o->register_list==((uint16_t)x->g<<8|x->r)&&o->imm==start&&o->size==0&&o->flags==0&&o->extend_type==8&&o->access==CDISASM_OPERAND_ACCESS_WRITE;}
}

static int arm_valid_sve_widening_fp_mla_indexed_schema(const cdisasm_arm_instruction*i)
{
    static const uint16_t forms[8]={3014,3015,3016,3017,3018,3019,3020,3021};
    static const cdisasm_arm_name_id names[8]={CDISASM_ARM_NAME_FMLALB,CDISASM_ARM_NAME_BFMLALB,CDISASM_ARM_NAME_FMLSLB,CDISASM_ARM_NAME_BFMLSLB,CDISASM_ARM_NAME_FMLALT,CDISASM_ARM_NAME_BFMLALT,CDISASM_ARM_NAME_FMLSLT,CDISASM_ARM_NAME_BFMLSLT};
    uint32_t w=i->raw_instruction;int raw=(w&UINT32_C(0xffa0d000))==UINT32_C(0x64a04000);int fc=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=3014&&i->form_id<=3021;unsigned bf=(w>>22)&1u,sub=(w>>13)&1u,top=(w>>10)&1u,index=(top<<2)|(sub<<1)|bf,zd=w&31u,zn=(w>>5)&31u,zm=(w>>16)&7u;uint64_t lane=(((w>>19)&1u)<<1)|((w>>11)&1u);
    if(!raw&&!fc)return 1;if(!raw||!fc)return 0;
    return i->form_id==forms[index]&&i->name_id==names[index]&&i->opcode_size==4
        &&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE
        &&i->instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)
        &&i->branch_target==0&&i->operand_count==3
        &&arm_exact_scalable_operand(&i->operand[0],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0+zd),4u,CDISASM_OPERAND_ACCESS_READ_WRITE)
        &&arm_exact_scalable_operand(&i->operand[1],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0+zn),2u,CDISASM_OPERAND_ACCESS_READ)
        &&arm_exact_scalable_lane_operand(&i->operand[2],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0+zm),2u,lane,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sve_fp8_widening_fp_mla_indexed_schema(const cdisasm_arm_instruction*i)
{
    uint32_t w=i->raw_instruction;int raw=(w&UINT32_C(0xff60f000))==UINT32_C(0x64205000);int fc=i->isa_id==CDISASM_ARM_ISA_A64&&(i->form_id==3022||i->form_id==3023);unsigned top=(w>>23)&1u,zd=w&31u,zn=(w>>5)&31u,zm=(w>>16)&7u;uint64_t lane=(((w>>19)&1u)<<2)|(((w>>11)&1u)<<1)|((w>>10)&1u);
    if(!raw&&!fc)return 1;if(!raw||!fc)return 0;
    return i->form_id==(top?3023:3022)&&i->name_id==(top?CDISASM_ARM_NAME_FMLALT:CDISASM_ARM_NAME_FMLALB)&&i->opcode_size==4
        &&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE
        &&i->instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)
        &&i->branch_target==0&&i->operand_count==3
        &&arm_exact_scalable_operand(&i->operand[0],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0+zd),2u,CDISASM_OPERAND_ACCESS_READ_WRITE)
        &&arm_exact_scalable_operand(&i->operand[1],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0+zn),1u,CDISASM_OPERAND_ACCESS_READ)
        &&arm_exact_scalable_lane_operand(&i->operand[2],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0+zm),1u,lane,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sve_fp8_widening_schema(const cdisasm_arm_instruction*i)
{
    static const cdisasm_arm_name_id names[6]={CDISASM_ARM_NAME_FMLALLBB,CDISASM_ARM_NAME_FMLALLBT,CDISASM_ARM_NAME_FMLALLTB,CDISASM_ARM_NAME_FMLALLTT,CDISASM_ARM_NAME_FMLALB,CDISASM_ARM_NAME_FMLALT};uint32_t w=i->raw_instruction;int ll=(w&UINT32_C(0xffe0cc00))==UINT32_C(0x64208800),l=(w&UINT32_C(0xffe0ec00))==UINT32_C(0x64a08800);int fc=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=3036&&i->form_id<=3041;unsigned index=ll?((w>>12)&3u):(4u+((w>>12)&1u)),zd=w&31u,zn=(w>>5)&31u,zm=(w>>16)&31u;
    if(!ll&&!l&&!fc)return 1;if((!ll&&!l)||!fc)return 0;
    return i->form_id==3036+index&&i->name_id==names[index]&&i->opcode_size==4&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)&&i->branch_target==0&&i->operand_count==3&&arm_exact_scalable_operand(&i->operand[0],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0+zd),ll?4u:2u,CDISASM_OPERAND_ACCESS_READ_WRITE)&&arm_exact_scalable_operand(&i->operand[1],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0+zn),1u,CDISASM_OPERAND_ACCESS_READ)&&arm_exact_scalable_operand(&i->operand[2],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0+zm),1u,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sve_fp8_widening_long_long_indexed_schema(const cdisasm_arm_instruction*i)
{
    static const cdisasm_arm_name_id names[4]={CDISASM_ARM_NAME_FMLALLBB,CDISASM_ARM_NAME_FMLALLBT,CDISASM_ARM_NAME_FMLALLTB,CDISASM_ARM_NAME_FMLALLTT};uint32_t w=i->raw_instruction;int raw=(w&UINT32_C(0xff20f000))==UINT32_C(0x6420c000);int fc=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=3042&&i->form_id<=3045;unsigned variant=(w>>22)&3u,zd=w&31u,zn=(w>>5)&31u,zm=(w>>16)&7u;uint64_t lane=(((w>>19)&1u)<<2)|(((w>>11)&1u)<<1)|((w>>10)&1u);
    if(!raw&&!fc)return 1;if(!raw||!fc)return 0;
    return i->form_id==3042+variant&&i->name_id==names[variant]&&i->opcode_size==4&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)&&i->branch_target==0&&i->operand_count==3&&arm_exact_scalable_operand(&i->operand[0],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0+zd),4u,CDISASM_OPERAND_ACCESS_READ_WRITE)&&arm_exact_scalable_operand(&i->operand[1],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0+zn),1u,CDISASM_OPERAND_ACCESS_READ)&&arm_exact_scalable_lane_operand(&i->operand[2],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0+zm),1u,lane,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sve_fp8_fmmla_schema(const cdisasm_arm_instruction*i)
{
    uint32_t w=i->raw_instruction;int raw=(w&UINT32_C(0xffa0fc00))==UINT32_C(0x6420e000);int fc=i->isa_id==CDISASM_ARM_ISA_A64&&(i->form_id==3046||i->form_id==3047);unsigned half=(w>>22)&1u,zd=w&31u,zn=(w>>5)&31u,zm=(w>>16)&31u;
    if(!raw&&!fc)return 1;if(!raw||!fc)return 0;
    return i->form_id==3046+half&&i->name_id==CDISASM_ARM_NAME_FMMLA&&i->opcode_size==4&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)&&i->branch_target==0&&i->operand_count==3&&arm_exact_scalable_operand(&i->operand[0],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0+zd),half?2u:4u,CDISASM_OPERAND_ACCESS_READ_WRITE)&&arm_exact_scalable_operand(&i->operand[1],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0+zn),1u,CDISASM_OPERAND_ACCESS_READ)&&arm_exact_scalable_operand(&i->operand[2],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0+zm),1u,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sve_fmmla_schema(const cdisasm_arm_instruction*i)
{
    uint32_t w=i->raw_instruction;int narrow=(w&UINT32_C(0xffa0fc00))==UINT32_C(0x64a0e000),regular=(w&UINT32_C(0xff20fc00))==UINT32_C(0x6420e400);int fc=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=3048&&i->form_id<=3053;unsigned v=narrow?((w>>22)&1u):((w>>22)&3u),form=narrow?3048u+v:3050u+v,zd=w&31u,zn=(w>>5)&31u,zm=(w>>16)&31u,ds=narrow?2u:(v==3?8u:4u),ss=narrow?2u:(v<2?2u:ds);cdisasm_arm_name_id name=((narrow&&v)||(!narrow&&v==1))?CDISASM_ARM_NAME_BFMMLA:CDISASM_ARM_NAME_FMMLA;
    if(!narrow&&!regular&&!fc)return 1;if((!narrow&&!regular)||!fc)return 0;
    return i->form_id==form&&i->name_id==name&&i->opcode_size==4&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)&&i->branch_target==0&&i->operand_count==3&&arm_exact_scalable_operand(&i->operand[0],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0+zd),ds,CDISASM_OPERAND_ACCESS_READ_WRITE)&&arm_exact_scalable_operand(&i->operand[1],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0+zn),ss,CDISASM_OPERAND_ACCESS_READ)&&arm_exact_scalable_operand(&i->operand[2],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0+zm),ss,CDISASM_OPERAND_ACCESS_READ);
}

static int arm_valid_sve_widening_fp_mla_schema(const cdisasm_arm_instruction*i)
{
    static const uint16_t forms[8]={3028,3029,3030,3031,3032,3033,3034,3035};
    static const cdisasm_arm_name_id names[8]={CDISASM_ARM_NAME_FMLALB,CDISASM_ARM_NAME_BFMLALB,CDISASM_ARM_NAME_FMLSLB,CDISASM_ARM_NAME_BFMLSLB,CDISASM_ARM_NAME_FMLALT,CDISASM_ARM_NAME_BFMLALT,CDISASM_ARM_NAME_FMLSLT,CDISASM_ARM_NAME_BFMLSLT};
    uint32_t w=i->raw_instruction;int raw=(w&UINT32_C(0xffa0d800))==UINT32_C(0x64a08000);int fc=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=3028&&i->form_id<=3035;unsigned bf=(w>>22)&1u,sub=(w>>13)&1u,top=(w>>10)&1u,index=(top<<2)|(sub<<1)|bf,zd=w&31u,zn=(w>>5)&31u,zm=(w>>16)&31u;
    if(!raw&&!fc)return 1;if(!raw||!fc)return 0;
    return i->form_id==forms[index]&&i->name_id==names[index]&&i->opcode_size==4
        &&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE
        &&i->instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)
        &&i->branch_target==0&&i->operand_count==3
        &&arm_exact_scalable_operand(&i->operand[0],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0+zd),4u,CDISASM_OPERAND_ACCESS_READ_WRITE)
        &&arm_exact_scalable_operand(&i->operand[1],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0+zn),2u,CDISASM_OPERAND_ACCESS_READ)
        &&arm_exact_scalable_operand(&i->operand[2],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0+zm),2u,CDISASM_OPERAND_ACCESS_READ);
}

static uint64_t arm_expand_fmov_immediate(unsigned encoded, uint8_t size)
{
    unsigned total_bits=8u*size,exponent_bits=size==4u?8u:11u,fraction_bits=total_bits-exponent_bits-1u,selector=(encoded>>6)&1u;uint64_t exponent=(uint64_t)(selector^1u)<<(exponent_bits-1u);
    if(selector)exponent|=((UINT64_C(1)<<(exponent_bits-3u))-1u)<<2u;
    exponent|=(encoded>>4)&3u;
    return ((uint64_t)((encoded>>7)&1u)<<(total_bits-1u))|(exponent<<fraction_bits)|((uint64_t)(encoded&15u)<<(fraction_bits-4u));
}

static int arm_valid_a64_fmov_immediate_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;unsigned type=(w>>22)&3u;int raw=i->isa_id==CDISASM_ARM_ISA_A64&&type<2u&&(w&UINT32_C(0xff201fe0))==UINT32_C(0x1e201000);int form=i->isa_id==CDISASM_ARM_ISA_A64&&(i->form_id==6519||i->form_id==6520);uint8_t size=type==0u?4u:8u;cdisasm_arm_reg_id reg=(cdisasm_arm_reg_id)((type==0u?CDISASM_ARM_REG_S0:CDISASM_ARM_REG_D0)+(w&31u));
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==CDISASM_ARM_NAME_FMOV&&i->form_id==(type==0u?6519:6520)&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT&&i->operand_count==2&&arm_exact_register_operand(&i->operand[0],reg,size,CDISASM_OPERAND_ACCESS_WRITE)&&arm_exact_immediate_operand(&i->operand[1],arm_expand_fmov_immediate((w>>13)&255u,size));
}

static int arm_valid_a64_fmov_lane64_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction;int to_vector=(w&UINT32_C(0x10000))!=0;int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(w&UINT32_C(0xfffefc00))==UINT32_C(0x9eae0000);int form=i->isa_id==CDISASM_ARM_ISA_A64&&(i->form_id==6395||i->form_id==6396);unsigned rd=w&31u,rn=(w>>5)&31u;cdisasm_arm_reg_id xd=rd==31u?CDISASM_ARM_REG_XZR:(cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0+rd),xn=rn==31u?CDISASM_ARM_REG_XZR:(cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0+rn);
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==CDISASM_ARM_NAME_FMOV&&i->form_id==(to_vector?6396:6395)&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SIMD|CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)&&i->operand_count==2&&(to_vector?(arm_exact_vector_lane_operand(&i->operand[0],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rd),8u,1u,CDISASM_OPERAND_ACCESS_WRITE)&&arm_exact_register_operand(&i->operand[1],xn,8u,CDISASM_OPERAND_ACCESS_READ)):(arm_exact_register_operand(&i->operand[0],xd,8u,CDISASM_OPERAND_ACCESS_WRITE)&&arm_exact_vector_lane_operand(&i->operand[1],(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rn),8u,1u,CDISASM_OPERAND_ACCESS_READ)));
}

static int arm_valid_advsimd_sat_round_narrow_schema(const cdisasm_arm_instruction *i)
{
    uint32_t w=i->raw_instruction,so=w&UINT32_C(0xff80fc00),vo=w&UINT32_C(0xbf80fc00),op;unsigned immh=(w>>19)&15u,encoded=(immh<<3)|((w>>16)&7u),bits=(immh&4u)?32u:(immh&2u)?16u:8u,rd=w&31u,rn=(w>>5)&31u,q=(w>>30)&1u;uint8_t ns=(uint8_t)(bits/8u),ws=(uint8_t)(ns*2u);int scalar=so==UINT32_C(0x5f009400)||so==UINT32_C(0x7f008400)||so==UINT32_C(0x7f009400)||so==UINT32_C(0x5f009c00)||so==UINT32_C(0x7f008c00)||so==UINT32_C(0x7f009c00);cdisasm_arm_form_id form;cdisasm_arm_name_id name;const cdisasm_arm_operand*d=&i->operand[0],*n=&i->operand[1];cdisasm_arm_reg_id dr,nr;
    op=scalar?so:vo;if(scalar)form=op==UINT32_C(0x5f009400)?5859:op==UINT32_C(0x7f008400)?5871:op==UINT32_C(0x7f009400)?5873:op==UINT32_C(0x5f009c00)?5860:op==UINT32_C(0x7f008c00)?5872:op==UINT32_C(0x7f009c00)?5874:0;else form=op==UINT32_C(0x0f009400)?6223:op==UINT32_C(0x2f008400)?6236:op==UINT32_C(0x2f009400)?6238:op==UINT32_C(0x0f009c00)?6224:op==UINT32_C(0x2f008c00)?6237:op==UINT32_C(0x2f009c00)?6239:0;
    if(immh==0u)form=0;if(form==0&&i->form_id!=5859&&i->form_id!=5871&&i->form_id!=5873&&i->form_id!=5860&&i->form_id!=5872&&i->form_id!=5874&&i->form_id!=6223&&i->form_id!=6236&&i->form_id!=6238&&i->form_id!=6224&&i->form_id!=6237&&i->form_id!=6239)return 1;if(form==0||immh>7u)return 0;
    name=op==UINT32_C(0x7f008400)||op==UINT32_C(0x2f008400)?CDISASM_ARM_NAME_SQSHRUN:op==UINT32_C(0x7f009400)||op==UINT32_C(0x2f009400)?CDISASM_ARM_NAME_UQSHRN:op==UINT32_C(0x5f009400)||op==UINT32_C(0x0f009400)?CDISASM_ARM_NAME_SQSHRN:op==UINT32_C(0x7f008c00)||op==UINT32_C(0x2f008c00)?CDISASM_ARM_NAME_SQRSHRUN:op==UINT32_C(0x7f009c00)||op==UINT32_C(0x2f009c00)?CDISASM_ARM_NAME_UQRSHRN:CDISASM_ARM_NAME_SQRSHRN;
    if(i->isa_id!=CDISASM_ARM_ISA_A64||i->name_id!=name||i->form_id!=form||i->opcode_size!=4u||i->condition!=CDISASM_ARM_CONDITION_AL||i->opcode_groups!=CDISASM_GROUP_NONE||i->instruction_flags!=CDISASM_ARM_INSTRUCTION_FLAG_SIMD||i->branch_target!=0u||i->operand_count!=3u)return 0;
    if(scalar){dr=(cdisasm_arm_reg_id)((ns==1u?CDISASM_ARM_REG_B0:ns==2u?CDISASM_ARM_REG_H0:CDISASM_ARM_REG_S0)+rd);nr=(cdisasm_arm_reg_id)((ws==2u?CDISASM_ARM_REG_H0:ws==4u?CDISASM_ARM_REG_S0:CDISASM_ARM_REG_D0)+rn);if(d->type!=CDISASM_OPERAND_REGISTER||d->reg!=dr||d->size!=ns||d->extend_type!=ns||d->scale!=1u||d->access!=CDISASM_OPERAND_ACCESS_WRITE||n->type!=CDISASM_OPERAND_REGISTER||n->reg!=nr||n->size!=ws||n->extend_type!=ws||n->scale!=1u||n->access!=CDISASM_OPERAND_ACCESS_READ)return 0;}else if(!arm_exact_advsimd_shift_narrow_widen_vector_operand(d,(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rd),q?16u:8u,ns,q?CDISASM_OPERAND_ACCESS_READ_WRITE:CDISASM_OPERAND_ACCESS_WRITE)||!arm_exact_advsimd_shift_narrow_widen_vector_operand(n,(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rn),16u,ws,CDISASM_OPERAND_ACCESS_READ))return 0;
    return arm_exact_advsimd_shift_narrow_widen_immediate_operand(&i->operand[2],2u*bits-encoded);
}

static int arm_valid_sve2_gather_non_temporal_load_schema(
    const cdisasm_arm_instruction *i)
{
    static const uint32_t values[7] = {
        UINT32_C(0x8500a000), UINT32_C(0x8400a000),
        UINT32_C(0x8480a000), UINT32_C(0xc580c000),
        UINT32_C(0xc400c000), UINT32_C(0xc480c000),
        UINT32_C(0xc500c000)
    };
    static const cdisasm_arm_name_id names[7] = {
        CDISASM_ARM_NAME_LDNT1W, CDISASM_ARM_NAME_LDNT1B,
        CDISASM_ARM_NAME_LDNT1H, CDISASM_ARM_NAME_LDNT1D,
        CDISASM_ARM_NAME_LDNT1B, CDISASM_ARM_NAME_LDNT1H,
        CDISASM_ARM_NAME_LDNT1W
    };
    static const cdisasm_arm_form_id forms[7] = {
        3222u, 3223u, 3224u, 3412u, 3413u, 3414u, 3415u
    };
    static const uint8_t element_sizes[7] = { 4u, 4u, 4u, 8u, 8u, 8u, 8u };
    static const uint8_t memory_sizes[7] = { 4u, 1u, 2u, 8u, 1u, 2u, 4u };
    uint32_t value = i->raw_instruction & UINT32_C(0xffe0e000);
    unsigned index, zt = i->raw_instruction & 31u;
    unsigned zn = (i->raw_instruction >> 5) & 31u;
    unsigned pg = (i->raw_instruction >> 10) & 7u;
    unsigned xm = (i->raw_instruction >> 16) & 31u;
    int raw = 0, claimed = 0;
    const cdisasm_arm_operand *d = &i->operand[0];
    const cdisasm_arm_operand *p = &i->operand[1];
    const cdisasm_arm_operand *m = &i->operand[2];

    for (index = 0u; index < 7u; ++index) {
        raw |= value == values[index];
        claimed |= i->form_id == forms[index];
        if (value == values[index]) break;
    }
    if (!raw && !claimed) return 1;
    if (!raw || !claimed || index == 7u) return 0;
    return i->isa_id == CDISASM_ARM_ISA_A64
        && i->name_id == names[index] && i->form_id == forms[index]
        && i->opcode_size == 4u && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        && i->branch_target == 0u && i->operand_count == 3u
        && d->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
        && d->reg == CDISASM_ARM_REG_Z0 + zt
        && d->register_list == UINT16_C(0x0101)
        && d->size == 0u && d->extend_type == element_sizes[index]
        && d->flags == 0u && d->access == CDISASM_OPERAND_ACCESS_WRITE
        && arm_exact_predicate_operand(p,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg),
            element_sizes[index], CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO,
            CDISASM_OPERAND_ACCESS_READ)
        && m->type == CDISASM_OPERAND_MEMORY
        && m->base_reg == CDISASM_ARM_REG_Z0 + zn
        && m->index_reg == (xm == 31u ? CDISASM_ARM_REG_NONE
            : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + xm))
        && m->size == memory_sizes[index] && m->imm == 0u
        && m->shift_type == CDISASM_ARM_SHIFT_NONE && m->shift_amount == 0u
        && m->extend_type == CDISASM_ARM_EXTEND_NONE && m->scale == 0u
        && m->flags == 0u && m->access == CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sve_address_generation_schema(
    const cdisasm_arm_instruction *i)
{
    uint32_t w = i->raw_instruction;
    uint32_t operation = w & UINT32_C(0xffe0f000);
    int extended = operation == UINT32_C(0x0420a000)
        || operation == UINT32_C(0x0460a000);
    int raw = i->isa_id == CDISASM_ARM_ISA_A64
        && (extended || (w & UINT32_C(0xffa0f000)) == UINT32_C(0x04a0a000));
    int claimed = i->isa_id == CDISASM_ARM_ISA_A64
        && i->form_id >= UINT16_C(2338) && i->form_id <= UINT16_C(2340);
    uint16_t form = operation == UINT32_C(0x0420a000) ? UINT16_C(2338)
        : operation == UINT32_C(0x0460a000) ? UINT16_C(2339)
        : UINT16_C(2340);
    uint8_t element_size = extended || (w & UINT32_C(0x00400000)) != 0u
        ? 8u : 4u;
    unsigned amount = (w >> 10) & 3u;
    const cdisasm_arm_operand *d = &i->operand[0];
    const cdisasm_arm_operand *a = &i->operand[1];

    if (!raw && !claimed) return 1;
    if (!raw || !claimed) return 0;
    return i->name_id == CDISASM_ARM_NAME_ADR && i->form_id == form
        && i->opcode_size == 4u && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        && i->branch_target == 0u && i->operand_count == 2u
        && arm_exact_scalable_operand(d,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + (w & 31u)),
            element_size, CDISASM_OPERAND_ACCESS_WRITE)
        && a->type == CDISASM_OPERAND_MEMORY && a->address == 0u
        && a->imm == 0u && a->reg == CDISASM_ARM_REG_NONE
        && a->base_reg == CDISASM_ARM_REG_Z0 + ((w >> 5) & 31u)
        && a->index_reg == CDISASM_ARM_REG_Z0 + ((w >> 16) & 31u)
        && a->register_list == 0u && a->size == element_size
        && a->access == CDISASM_OPERAND_ACCESS_READ && a->flags == 0u
        && (extended
            ? a->shift_type == CDISASM_ARM_SHIFT_NONE
                && a->shift_amount == 0u
                && a->extend_type == (form == UINT16_C(2338)
                    ? CDISASM_ARM_EXTEND_SXTW : CDISASM_ARM_EXTEND_UXTW)
                && a->scale == amount
            : a->extend_type == CDISASM_ARM_EXTEND_NONE && a->scale == 0u
                && a->shift_type == (amount == 0u
                    ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL)
                && a->shift_amount == amount);
}

static int arm_valid_sve_gather32_unscaled_remaining_schema(
    const cdisasm_arm_instruction *i)
{
    static const uint32_t values[7] = { UINT32_C(0x84000000),
        UINT32_C(0x84800000), UINT32_C(0x84002000),
        UINT32_C(0x84802000), UINT32_C(0x85006000),
        UINT32_C(0x84006000), UINT32_C(0x84806000) };
    static const cdisasm_arm_name_id names[7] = { CDISASM_ARM_NAME_LD1SB,
        CDISASM_ARM_NAME_LD1SH, CDISASM_ARM_NAME_LDFF1SB,
        CDISASM_ARM_NAME_LDFF1SH, CDISASM_ARM_NAME_LDFF1W,
        CDISASM_ARM_NAME_LDFF1B, CDISASM_ARM_NAME_LDFF1H };
    static const uint16_t forms[7] = { 3194u, 3195u, 3199u, 3200u,
        3201u, 3202u, 3203u };
    static const uint8_t sizes[7] = { 1u, 2u, 1u, 2u, 4u, 1u, 2u };
    uint32_t value = i->raw_instruction & UINT32_C(0xffa0e000);
    unsigned n, zt = i->raw_instruction & 31u;
    unsigned rn = (i->raw_instruction >> 5) & 31u;
    unsigned pg = (i->raw_instruction >> 10) & 7u;
    unsigned zm = (i->raw_instruction >> 16) & 31u;
    int raw = 0, claimed = 0;
    const cdisasm_arm_operand *d = &i->operand[0];
    const cdisasm_arm_operand *p = &i->operand[1];
    const cdisasm_arm_operand *m = &i->operand[2];

    for (n = 0u; n < 7u; ++n) {
        raw |= value == values[n]; claimed |= i->form_id == forms[n];
        if (value == values[n]) break;
    }
    if (!raw && !claimed) return 1;
    if (!raw || !claimed || n == 7u) return 0;
    return i->isa_id == CDISASM_ARM_ISA_A64 && i->name_id == names[n]
        && i->form_id == forms[n] && i->opcode_size == 4u
        && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        && i->operand_count == 3u
        && d->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
        && d->reg == CDISASM_ARM_REG_Z0 + zt
        && d->register_list == UINT16_C(0x0101) && d->size == 0u
        && d->extend_type == 4u && d->flags == 0u
        && d->access == CDISASM_OPERAND_ACCESS_WRITE
        && arm_exact_predicate_operand(p,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg), 4u,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO,
            CDISASM_OPERAND_ACCESS_READ)
        && m->type == CDISASM_OPERAND_MEMORY && m->reg == CDISASM_ARM_REG_NONE
        && m->base_reg == (rn == 31u ? CDISASM_ARM_REG_SP
            : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + rn))
        && m->index_reg == CDISASM_ARM_REG_Z0 + zm
        && m->register_list == 0u && m->address == 0u && m->imm == 0u
        && m->size == sizes[n] && m->flags == 0u
        && m->shift_type == CDISASM_ARM_SHIFT_NONE && m->shift_amount == 0u
        && m->extend_type == ((i->raw_instruction & UINT32_C(0x00400000))
            ? CDISASM_ARM_EXTEND_SXTW : CDISASM_ARM_EXTEND_UXTW)
        && m->scale == 0u && m->access == CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sve_gather32_prefetch_schema(
    const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id names[4] = {
        CDISASM_ARM_NAME_PRFB, CDISASM_ARM_NAME_PRFH,
        CDISASM_ARM_NAME_PRFW, CDISASM_ARM_NAME_PRFD
    };
    uint32_t w = i->raw_instruction;
    uint32_t value = w & UINT32_C(0xffa0e010);
    unsigned size_log2 = (w >> 13) & 3u;
    unsigned rn = (w >> 5) & 31u;
    unsigned pg = (w >> 10) & 7u;
    unsigned zm = (w >> 16) & 31u;
    uint8_t size = (uint8_t)(1u << size_log2);
    int raw = i->isa_id == CDISASM_ARM_ISA_A64
        && value == (UINT32_C(0x84200000) | (size_log2 << 13));
    int claimed = i->isa_id == CDISASM_ARM_ISA_A64
        && i->form_id >= UINT16_C(3204)
        && i->form_id <= UINT16_C(3207);
    const cdisasm_arm_operand *p = &i->operand[0];
    const cdisasm_arm_operand *g = &i->operand[1];
    const cdisasm_arm_operand *m = &i->operand[2];

    if (!raw && !claimed) return 1;
    if (!raw || !claimed) return 0;
    return i->name_id == names[size_log2]
        && i->form_id == UINT16_C(3204) + size_log2
        && i->opcode_size == 4u && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        && i->branch_target == 0u && i->operand_count == 3u
        && p->type == CDISASM_OPERAND_IMMEDIATE && p->imm == (w & 15u)
        && p->size == 1u && p->access == CDISASM_OPERAND_ACCESS_READ
        && p->reg == CDISASM_ARM_REG_NONE
        && p->base_reg == CDISASM_ARM_REG_NONE
        && p->index_reg == CDISASM_ARM_REG_NONE && p->flags == 0u
        && arm_exact_predicate_operand(g,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg), size, 0u,
            CDISASM_OPERAND_ACCESS_READ)
        && m->type == CDISASM_OPERAND_MEMORY && m->reg == CDISASM_ARM_REG_NONE
        && m->base_reg == (rn == 31u ? CDISASM_ARM_REG_SP
            : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + rn))
        && m->index_reg == CDISASM_ARM_REG_Z0 + zm
        && m->register_list == 0u && m->address == 0u && m->imm == 0u
        && m->size == size && m->flags == 0u
        && m->shift_type == CDISASM_ARM_SHIFT_NONE && m->shift_amount == 0u
        && m->extend_type == ((w & UINT32_C(0x00400000))
            ? CDISASM_ARM_EXTEND_SXTW : CDISASM_ARM_EXTEND_UXTW)
        && m->scale == size_log2 && m->access == CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sve_gather64_x32_prefetch_schema(
    const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id names[4] = {
        CDISASM_ARM_NAME_PRFB, CDISASM_ARM_NAME_PRFH,
        CDISASM_ARM_NAME_PRFW, CDISASM_ARM_NAME_PRFD
    };
    uint32_t w = i->raw_instruction;
    unsigned size_log2 = (w >> 13) & 3u, rn = (w >> 5) & 31u;
    unsigned pg = (w >> 10) & 7u, zm = (w >> 16) & 31u;
    uint8_t size = (uint8_t)(1u << size_log2);
    int raw = i->isa_id == CDISASM_ARM_ISA_A64
        && (w & UINT32_C(0xffa0e010))
            == (UINT32_C(0xc4200000) | (size_log2 << 13));
    int claimed = i->isa_id == CDISASM_ARM_ISA_A64
        && i->form_id >= UINT16_C(3395)
        && i->form_id <= UINT16_C(3398);
    const cdisasm_arm_operand *h = &i->operand[0];
    const cdisasm_arm_operand *p = &i->operand[1];
    const cdisasm_arm_operand *m = &i->operand[2];
    if (!raw && !claimed) return 1;
    if (!raw || !claimed) return 0;
    return i->name_id == names[size_log2]
        && i->form_id == UINT16_C(3395) + size_log2
        && i->opcode_size == 4u && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        && i->branch_target == 0u && i->operand_count == 3u
        && h->type == CDISASM_OPERAND_IMMEDIATE && h->imm == (w & 15u)
        && h->size == 1u && h->access == CDISASM_OPERAND_ACCESS_READ
        && h->reg == CDISASM_ARM_REG_NONE && h->base_reg == CDISASM_ARM_REG_NONE
        && h->index_reg == CDISASM_ARM_REG_NONE && h->flags == 0u
        && arm_exact_predicate_operand(p,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg), size, 0u,
            CDISASM_OPERAND_ACCESS_READ)
        && m->type == CDISASM_OPERAND_MEMORY && m->reg == CDISASM_ARM_REG_NONE
        && m->base_reg == (rn == 31u ? CDISASM_ARM_REG_SP
            : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + rn))
        && m->index_reg == CDISASM_ARM_REG_Z0 + zm
        && m->register_list == 0u && m->address == 0u && m->imm == 0u
        && m->size == size && m->flags == 0u
        && m->shift_type == CDISASM_ARM_SHIFT_NONE && m->shift_amount == 0u
        && m->extend_type == ((w & UINT32_C(0x00400000))
            ? CDISASM_ARM_EXTEND_SXTW : CDISASM_ARM_EXTEND_UXTW)
        && m->scale == size_log2 && m->access == CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sve_gather64_prefetch_schema(
    const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id names[4] = {
        CDISASM_ARM_NAME_PRFB, CDISASM_ARM_NAME_PRFH,
        CDISASM_ARM_NAME_PRFW, CDISASM_ARM_NAME_PRFD
    };
    uint32_t w = i->raw_instruction;
    unsigned size_log2 = (w >> 13) & 3u, rn = (w >> 5) & 31u;
    unsigned pg = (w >> 10) & 7u, zm = (w >> 16) & 31u;
    uint8_t size = (uint8_t)(1u << size_log2);
    int raw = i->isa_id == CDISASM_ARM_ISA_A64
        && (w & UINT32_C(0xffe0e010))
            == (UINT32_C(0xc4608000) | (size_log2 << 13));
    int claimed = i->isa_id == CDISASM_ARM_ISA_A64
        && i->form_id >= UINT16_C(3449)
        && i->form_id <= UINT16_C(3452);
    const cdisasm_arm_operand *h = &i->operand[0];
    const cdisasm_arm_operand *p = &i->operand[1];
    const cdisasm_arm_operand *m = &i->operand[2];

    if (!raw && !claimed) return 1;
    if (!raw || !claimed) return 0;
    return i->name_id == names[size_log2]
        && i->form_id == UINT16_C(3449) + size_log2
        && i->opcode_size == 4u && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        && i->branch_target == 0u && i->operand_count == 3u
        && h->type == CDISASM_OPERAND_IMMEDIATE && h->imm == (w & 15u)
        && h->size == 1u && h->access == CDISASM_OPERAND_ACCESS_READ
        && h->reg == CDISASM_ARM_REG_NONE
        && h->base_reg == CDISASM_ARM_REG_NONE
        && h->index_reg == CDISASM_ARM_REG_NONE && h->flags == 0u
        && arm_exact_predicate_operand(p,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg), size, 0u,
            CDISASM_OPERAND_ACCESS_READ)
        && m->type == CDISASM_OPERAND_MEMORY && m->reg == CDISASM_ARM_REG_NONE
        && m->base_reg == (rn == 31u ? CDISASM_ARM_REG_SP
            : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + rn))
        && m->index_reg == CDISASM_ARM_REG_Z0 + zm
        && m->register_list == 0u && m->address == 0u && m->imm == 0u
        && m->size == size && m->flags == 0u
        && m->shift_type == (size_log2 == 0u
            ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL)
        && m->shift_amount == size_log2
        && m->extend_type == CDISASM_ARM_EXTEND_NONE && m->scale == 0u
        && m->access == CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sve_gather32_scaled_remaining_schema(
    const cdisasm_arm_instruction *i)
{
    static const uint32_t values[4] = { UINT32_C(0x84a00000),
        UINT32_C(0x84a02000), UINT32_C(0x84a06000),
        UINT32_C(0x85206000) };
    static const cdisasm_arm_name_id names[4] = { CDISASM_ARM_NAME_LD1SH,
        CDISASM_ARM_NAME_LDFF1SH, CDISASM_ARM_NAME_LDFF1H,
        CDISASM_ARM_NAME_LDFF1W };
    static const cdisasm_arm_form_id forms[4] = {
        3208u, 3210u, 3211u, 3213u
    };
    static const uint8_t sizes[4] = { 2u, 2u, 2u, 4u };
    uint32_t w = i->raw_instruction;
    uint32_t value = w & UINT32_C(0xffa0e000);
    unsigned n, zt = w & 31u, rn = (w >> 5) & 31u;
    unsigned pg = (w >> 10) & 7u, zm = (w >> 16) & 31u;
    int raw = 0, claimed = 0;
    const cdisasm_arm_operand *d = &i->operand[0];
    const cdisasm_arm_operand *p = &i->operand[1];
    const cdisasm_arm_operand *m = &i->operand[2];

    for (n = 0u; n < 4u; ++n) {
        raw |= value == values[n];
        claimed |= i->form_id == forms[n];
        if (value == values[n]) break;
    }
    if (!raw && !claimed) return 1;
    if (!raw || !claimed || n == 4u) return 0;
    return i->isa_id == CDISASM_ARM_ISA_A64 && i->name_id == names[n]
        && i->form_id == forms[n] && i->opcode_size == 4u
        && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        && i->branch_target == 0u && i->operand_count == 3u
        && d->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
        && d->reg == CDISASM_ARM_REG_Z0 + zt
        && d->register_list == UINT16_C(0x0101) && d->size == 0u
        && d->extend_type == 4u && d->flags == 0u
        && d->access == CDISASM_OPERAND_ACCESS_WRITE
        && arm_exact_predicate_operand(p,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg), 4u,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO,
            CDISASM_OPERAND_ACCESS_READ)
        && m->type == CDISASM_OPERAND_MEMORY && m->reg == CDISASM_ARM_REG_NONE
        && m->base_reg == (rn == 31u ? CDISASM_ARM_REG_SP
            : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + rn))
        && m->index_reg == CDISASM_ARM_REG_Z0 + zm
        && m->register_list == 0u && m->address == 0u && m->imm == 0u
        && m->size == sizes[n] && m->flags == 0u
        && m->shift_type == CDISASM_ARM_SHIFT_NONE && m->shift_amount == 0u
        && m->extend_type == ((w & UINT32_C(0x00400000))
            ? CDISASM_ARM_EXTEND_SXTW : CDISASM_ARM_EXTEND_UXTW)
        && m->scale == (sizes[n] == 2u ? 1u : 2u)
        && m->access == CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sve_prefetch_immediate_schema(
    const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id names[4] = {
        CDISASM_ARM_NAME_PRFB, CDISASM_ARM_NAME_PRFH,
        CDISASM_ARM_NAME_PRFW, CDISASM_ARM_NAME_PRFD
    };
    uint32_t w = i->raw_instruction;
    unsigned size_log2 = (w >> 13) & 3u;
    unsigned rn = (w >> 5) & 31u, pg = (w >> 10) & 7u;
    uint8_t size = (uint8_t)(1u << size_log2);
    int64_t displacement = (int64_t)(int32_t)(w << 10) >> 26;
    int raw = i->isa_id == CDISASM_ARM_ISA_A64
        && (w & UINT32_C(0xffc0e010))
            == (UINT32_C(0x85c00000) | (size_log2 << 13));
    int claimed = i->isa_id == CDISASM_ARM_ISA_A64
        && i->form_id >= UINT16_C(3216)
        && i->form_id <= UINT16_C(3219);
    const cdisasm_arm_operand *h = &i->operand[0];
    const cdisasm_arm_operand *p = &i->operand[1];
    const cdisasm_arm_operand *m = &i->operand[2];

    if (!raw && !claimed) return 1;
    if (!raw || !claimed) return 0;
    return i->name_id == names[size_log2]
        && i->form_id == UINT16_C(3216) + size_log2
        && i->opcode_size == 4u && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        && i->branch_target == 0u && i->operand_count == 3u
        && h->type == CDISASM_OPERAND_IMMEDIATE && h->imm == (w & 15u)
        && h->size == 1u && h->access == CDISASM_OPERAND_ACCESS_READ
        && h->reg == CDISASM_ARM_REG_NONE
        && h->base_reg == CDISASM_ARM_REG_NONE
        && h->index_reg == CDISASM_ARM_REG_NONE && h->flags == 0u
        && arm_exact_predicate_operand(p,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg), size, 0u,
            CDISASM_OPERAND_ACCESS_READ)
        && m->type == CDISASM_OPERAND_MEMORY && m->reg == CDISASM_ARM_REG_NONE
        && m->base_reg == (rn == 31u ? CDISASM_ARM_REG_SP
            : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + rn))
        && m->index_reg == CDISASM_ARM_REG_NONE && m->register_list == 0u
        && m->address == 0u && (int64_t)m->imm == displacement
        && m->size == size && m->access == CDISASM_OPERAND_ACCESS_READ
        && m->shift_type == CDISASM_ARM_SHIFT_NONE && m->shift_amount == 0u
        && m->extend_type == CDISASM_ARM_EXTEND_NONE && m->scale == 0u
        && m->flags == (displacement == 0 ? 0u
            : CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
                | CDISASM_ARM_OPERAND_FLAG_VL_SCALED
                | (displacement < 0 ? CDISASM_OPERAND_FLAG_SIGNED : 0u));
}

static int arm_valid_sve_prefetch_scalar_register_schema(
    const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id names[4] = {
        CDISASM_ARM_NAME_PRFB, CDISASM_ARM_NAME_PRFH,
        CDISASM_ARM_NAME_PRFW, CDISASM_ARM_NAME_PRFD
    };
    uint32_t w = i->raw_instruction;
    unsigned size_log2 = (w >> 23) & 3u;
    unsigned rn = (w >> 5) & 31u, pg = (w >> 10) & 7u;
    unsigned xm = (w >> 16) & 31u;
    uint8_t size = (uint8_t)(1u << size_log2);
    int raw = i->isa_id == CDISASM_ARM_ISA_A64 && xm != 31u
        && (w & UINT32_C(0xffe0e010))
            == (UINT32_C(0x8400c000) | (size_log2 << 23));
    int claimed = i->isa_id == CDISASM_ARM_ISA_A64
        && i->form_id >= UINT16_C(3225)
        && i->form_id <= UINT16_C(3228);
    const cdisasm_arm_operand *h = &i->operand[0];
    const cdisasm_arm_operand *p = &i->operand[1];
    const cdisasm_arm_operand *m = &i->operand[2];

    if (!raw && !claimed) return 1;
    if (!raw || !claimed) return 0;
    return i->name_id == names[size_log2]
        && i->form_id == UINT16_C(3225) + size_log2
        && i->opcode_size == 4u && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        && i->branch_target == 0u && i->operand_count == 3u
        && h->type == CDISASM_OPERAND_IMMEDIATE && h->imm == (w & 15u)
        && h->size == 1u && h->access == CDISASM_OPERAND_ACCESS_READ
        && h->reg == CDISASM_ARM_REG_NONE
        && h->base_reg == CDISASM_ARM_REG_NONE
        && h->index_reg == CDISASM_ARM_REG_NONE && h->flags == 0u
        && arm_exact_predicate_operand(p,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg), size, 0u,
            CDISASM_OPERAND_ACCESS_READ)
        && m->type == CDISASM_OPERAND_MEMORY && m->reg == CDISASM_ARM_REG_NONE
        && m->base_reg == (rn == 31u ? CDISASM_ARM_REG_SP
            : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + rn))
        && m->index_reg == CDISASM_ARM_REG_X0 + xm
        && m->register_list == 0u && m->address == 0u && m->imm == 0u
        && m->size == size && m->flags == 0u
        && m->extend_type == CDISASM_ARM_EXTEND_NONE && m->scale == 0u
        && m->shift_type == (size_log2 == 0u
            ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL)
        && m->shift_amount == size_log2
        && m->access == CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sve_prefetch_vector_immediate_schema(
    const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id names[4] = {
        CDISASM_ARM_NAME_PRFB, CDISASM_ARM_NAME_PRFH,
        CDISASM_ARM_NAME_PRFW, CDISASM_ARM_NAME_PRFD
    };
    uint32_t w = i->raw_instruction;
    unsigned size_log2 = (w >> 23) & 3u;
    unsigned zn = (w >> 5) & 31u, pg = (w >> 10) & 7u;
    uint8_t size = (uint8_t)(1u << size_log2);
    uint64_t displacement = ((w >> 16) & 31u) * size;
    int raw = i->isa_id == CDISASM_ARM_ISA_A64
        && (w & UINT32_C(0xffe0e010))
            == (UINT32_C(0x8400e000) | (size_log2 << 23));
    int claimed = i->isa_id == CDISASM_ARM_ISA_A64
        && i->form_id >= UINT16_C(3229)
        && i->form_id <= UINT16_C(3232);
    const cdisasm_arm_operand *h = &i->operand[0];
    const cdisasm_arm_operand *p = &i->operand[1];
    const cdisasm_arm_operand *m = &i->operand[2];

    if (!raw && !claimed) return 1;
    if (!raw || !claimed) return 0;
    return i->name_id == names[size_log2]
        && i->form_id == UINT16_C(3229) + size_log2
        && i->opcode_size == 4u && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        && i->branch_target == 0u && i->operand_count == 3u
        && h->type == CDISASM_OPERAND_IMMEDIATE && h->imm == (w & 15u)
        && h->size == 1u && h->access == CDISASM_OPERAND_ACCESS_READ
        && h->reg == CDISASM_ARM_REG_NONE
        && h->base_reg == CDISASM_ARM_REG_NONE
        && h->index_reg == CDISASM_ARM_REG_NONE && h->flags == 0u
        && arm_exact_predicate_operand(p,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg), size, 0u,
            CDISASM_OPERAND_ACCESS_READ)
        && m->type == CDISASM_OPERAND_MEMORY && m->reg == CDISASM_ARM_REG_NONE
        && m->base_reg == CDISASM_ARM_REG_Z0 + zn
        && m->index_reg == CDISASM_ARM_REG_NONE && m->register_list == 0u
        && m->address == 0u && m->imm == displacement && m->size == size
        && m->flags == (displacement == 0u ? 0u
            : CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT)
        && m->shift_type == CDISASM_ARM_SHIFT_NONE && m->shift_amount == 0u
        && m->extend_type == CDISASM_ARM_EXTEND_NONE && m->scale == 0u
        && m->access == CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sve_prefetch64_vector_immediate_schema(
    const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id names[4] = {
        CDISASM_ARM_NAME_PRFB, CDISASM_ARM_NAME_PRFH,
        CDISASM_ARM_NAME_PRFW, CDISASM_ARM_NAME_PRFD
    };
    uint32_t w = i->raw_instruction;
    unsigned size_log2 = (w >> 23) & 3u;
    unsigned zn = (w >> 5) & 31u, pg = (w >> 10) & 7u;
    uint8_t size = (uint8_t)(1u << size_log2);
    uint64_t displacement = ((w >> 16) & 31u) * size;
    int raw = i->isa_id == CDISASM_ARM_ISA_A64
        && (w & UINT32_C(0xffe0e010))
            == (UINT32_C(0xc400e000) | (size_log2 << 23));
    int claimed = i->isa_id == CDISASM_ARM_ISA_A64
        && i->form_id >= UINT16_C(3416)
        && i->form_id <= UINT16_C(3419);
    const cdisasm_arm_operand *h = &i->operand[0];
    const cdisasm_arm_operand *p = &i->operand[1];
    const cdisasm_arm_operand *m = &i->operand[2];
    if (!raw && !claimed) return 1;
    if (!raw || !claimed) return 0;
    return i->name_id == names[size_log2]
        && i->form_id == UINT16_C(3416) + size_log2
        && i->opcode_size == 4u && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        && i->branch_target == 0u && i->operand_count == 3u
        && h->type == CDISASM_OPERAND_IMMEDIATE && h->imm == (w & 15u)
        && h->size == 1u && h->access == CDISASM_OPERAND_ACCESS_READ
        && h->reg == CDISASM_ARM_REG_NONE && h->base_reg == CDISASM_ARM_REG_NONE
        && h->index_reg == CDISASM_ARM_REG_NONE && h->flags == 0u
        && arm_exact_predicate_operand(p,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg), size, 0u,
            CDISASM_OPERAND_ACCESS_READ)
        && m->type == CDISASM_OPERAND_MEMORY && m->reg == CDISASM_ARM_REG_NONE
        && m->base_reg == CDISASM_ARM_REG_Z0 + zn
        && m->index_reg == CDISASM_ARM_REG_NONE && m->register_list == 0u
        && m->address == 0u && m->imm == displacement && m->size == size
        && m->flags == (displacement == 0u ? 0u
            : CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT)
        && m->shift_type == CDISASM_ARM_SHIFT_NONE && m->shift_amount == 0u
        && m->extend_type == CDISASM_ARM_EXTEND_NONE && m->scale == 0u
        && m->access == CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sve_gather32_vector_immediate_remaining_schema(
    const cdisasm_arm_instruction *i)
{
    static const uint32_t values[7] = { UINT32_C(0x84208000),
        UINT32_C(0x84a08000), UINT32_C(0x8420a000),
        UINT32_C(0x84a0a000), UINT32_C(0x8520e000),
        UINT32_C(0x8420e000), UINT32_C(0x84a0e000) };
    static const cdisasm_arm_name_id names[7] = { CDISASM_ARM_NAME_LD1SB,
        CDISASM_ARM_NAME_LD1SH, CDISASM_ARM_NAME_LDFF1SB,
        CDISASM_ARM_NAME_LDFF1SH, CDISASM_ARM_NAME_LDFF1W,
        CDISASM_ARM_NAME_LDFF1B, CDISASM_ARM_NAME_LDFF1H };
    static const cdisasm_arm_form_id forms[7] = {
        3233u, 3234u, 3238u, 3239u, 3240u, 3241u, 3242u
    };
    static const uint8_t sizes[7] = { 1u, 2u, 1u, 2u, 4u, 1u, 2u };
    uint32_t w = i->raw_instruction, value = w & UINT32_C(0xffe0e000);
    unsigned n, zt = w & 31u, zn = (w >> 5) & 31u;
    unsigned pg = (w >> 10) & 7u, imm = (w >> 16) & 31u;
    int raw = 0, claimed = 0;
    const cdisasm_arm_operand *d = &i->operand[0];
    const cdisasm_arm_operand *p = &i->operand[1];
    const cdisasm_arm_operand *m = &i->operand[2];

    for (n = 0u; n < 7u; ++n) {
        raw |= value == values[n]; claimed |= i->form_id == forms[n];
        if (value == values[n]) break;
    }
    if (!raw && !claimed) return 1;
    if (!raw || !claimed || n == 7u) return 0;
    return i->isa_id == CDISASM_ARM_ISA_A64 && i->name_id == names[n]
        && i->form_id == forms[n] && i->opcode_size == 4u
        && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        && i->branch_target == 0u && i->operand_count == 3u
        && d->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
        && d->reg == CDISASM_ARM_REG_Z0 + zt
        && d->register_list == UINT16_C(0x0101) && d->size == 0u
        && d->extend_type == 4u && d->flags == 0u
        && d->access == CDISASM_OPERAND_ACCESS_WRITE
        && arm_exact_predicate_operand(p,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg), 4u,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO,
            CDISASM_OPERAND_ACCESS_READ)
        && m->type == CDISASM_OPERAND_MEMORY && m->reg == CDISASM_ARM_REG_NONE
        && m->base_reg == CDISASM_ARM_REG_Z0 + zn
        && m->index_reg == CDISASM_ARM_REG_NONE && m->register_list == 0u
        && m->address == 0u && m->imm == (uint64_t)imm * sizes[n]
        && m->size == sizes[n]
        && m->flags == (imm == 0u ? 0u
            : CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT)
        && m->shift_type == CDISASM_ARM_SHIFT_NONE && m->shift_amount == 0u
        && m->extend_type == CDISASM_ARM_EXTEND_NONE && m->scale == 0u
        && m->access == CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sve_gather64_x32_unscaled_remaining_schema(
    const cdisasm_arm_instruction *i)
{
    static const uint32_t values[10] = {
        UINT32_C(0xc4000000), UINT32_C(0xc4800000),
        UINT32_C(0xc5000000), UINT32_C(0xc4002000),
        UINT32_C(0xc4802000), UINT32_C(0xc5002000),
        UINT32_C(0xc5806000), UINT32_C(0xc4006000),
        UINT32_C(0xc4806000), UINT32_C(0xc5006000)
    };
    static const cdisasm_arm_name_id names[10] = {
        CDISASM_ARM_NAME_LD1SB, CDISASM_ARM_NAME_LD1SH,
        CDISASM_ARM_NAME_LD1SW, CDISASM_ARM_NAME_LDFF1SB,
        CDISASM_ARM_NAME_LDFF1SH, CDISASM_ARM_NAME_LDFF1SW,
        CDISASM_ARM_NAME_LDFF1D, CDISASM_ARM_NAME_LDFF1B,
        CDISASM_ARM_NAME_LDFF1H, CDISASM_ARM_NAME_LDFF1W
    };
    static const cdisasm_arm_form_id forms[10] = {
        3381u, 3382u, 3383u, 3388u, 3389u,
        3390u, 3391u, 3392u, 3393u, 3394u
    };
    static const uint8_t sizes[10] = {
        1u, 2u, 4u, 1u, 2u, 4u, 8u, 1u, 2u, 4u
    };
    uint32_t w = i->raw_instruction, value = w & UINT32_C(0xffa0e000);
    unsigned n, zt = w & 31u, rn = (w >> 5) & 31u;
    unsigned pg = (w >> 10) & 7u, zm = (w >> 16) & 31u;
    int raw = 0, claimed = 0;
    const cdisasm_arm_operand *d = &i->operand[0];
    const cdisasm_arm_operand *p = &i->operand[1];
    const cdisasm_arm_operand *m = &i->operand[2];

    for (n = 0u; n < 10u; ++n) {
        raw |= value == values[n]; claimed |= i->form_id == forms[n];
        if (value == values[n]) break;
    }
    if (!raw && !claimed) return 1;
    if (!raw || !claimed || n == 10u) return 0;
    return i->isa_id == CDISASM_ARM_ISA_A64 && i->name_id == names[n]
        && i->form_id == forms[n] && i->opcode_size == 4u
        && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        && i->branch_target == 0u && i->operand_count == 3u
        && d->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
        && d->reg == CDISASM_ARM_REG_Z0 + zt
        && d->register_list == UINT16_C(0x0101) && d->size == 0u
        && d->extend_type == 8u && d->flags == 0u
        && d->access == CDISASM_OPERAND_ACCESS_WRITE
        && arm_exact_predicate_operand(p,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg), 8u,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO,
            CDISASM_OPERAND_ACCESS_READ)
        && m->type == CDISASM_OPERAND_MEMORY && m->reg == CDISASM_ARM_REG_NONE
        && m->base_reg == (rn == 31u ? CDISASM_ARM_REG_SP
            : CDISASM_ARM_REG_X0 + rn)
        && m->index_reg == CDISASM_ARM_REG_Z0 + zm
        && m->register_list == 0u && m->address == 0u && m->imm == 0u
        && m->size == sizes[n] && m->flags == 0u
        && m->shift_type == CDISASM_ARM_SHIFT_NONE && m->shift_amount == 0u
        && m->extend_type == ((w & UINT32_C(0x00400000)) != 0u
            ? CDISASM_ARM_EXTEND_SXTW : CDISASM_ARM_EXTEND_UXTW)
        && m->scale == 0u && m->access == CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sve_gather64_x32_scaled_remaining_schema(
    const cdisasm_arm_instruction *i)
{
    static const uint32_t values[7] = { UINT32_C(0xc4a00000),
        UINT32_C(0xc5200000), UINT32_C(0xc4a02000),
        UINT32_C(0xc5202000), UINT32_C(0xc5a06000),
        UINT32_C(0xc4a06000), UINT32_C(0xc5206000) };
    static const cdisasm_arm_name_id names[7] = { CDISASM_ARM_NAME_LD1SH,
        CDISASM_ARM_NAME_LD1SW, CDISASM_ARM_NAME_LDFF1SH,
        CDISASM_ARM_NAME_LDFF1SW, CDISASM_ARM_NAME_LDFF1D,
        CDISASM_ARM_NAME_LDFF1H, CDISASM_ARM_NAME_LDFF1W };
    static const cdisasm_arm_form_id forms[7] = {
        3399u, 3400u, 3404u, 3405u, 3406u, 3407u, 3408u
    };
    static const uint8_t sizes[7] = { 2u, 4u, 2u, 4u, 8u, 2u, 4u };
    static const uint8_t scales[7] = { 1u, 2u, 1u, 2u, 3u, 1u, 2u };
    uint32_t w = i->raw_instruction, value = w & UINT32_C(0xffa0e000);
    unsigned n, zt = w & 31u, rn = (w >> 5) & 31u;
    unsigned pg = (w >> 10) & 7u, zm = (w >> 16) & 31u;
    int raw = 0, claimed = 0;
    const cdisasm_arm_operand *d = &i->operand[0];
    const cdisasm_arm_operand *p = &i->operand[1];
    const cdisasm_arm_operand *m = &i->operand[2];

    for (n = 0u; n < 7u; ++n) {
        raw |= value == values[n]; claimed |= i->form_id == forms[n];
        if (value == values[n]) break;
    }
    if (!raw && !claimed) return 1;
    if (!raw || !claimed || n == 7u) return 0;
    return i->isa_id == CDISASM_ARM_ISA_A64 && i->name_id == names[n]
        && i->form_id == forms[n] && i->opcode_size == 4u
        && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        && i->branch_target == 0u && i->operand_count == 3u
        && d->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
        && d->reg == CDISASM_ARM_REG_Z0 + zt
        && d->register_list == UINT16_C(0x0101) && d->size == 0u
        && d->extend_type == 8u && d->flags == 0u
        && d->access == CDISASM_OPERAND_ACCESS_WRITE
        && arm_exact_predicate_operand(p,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg), 8u,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO,
            CDISASM_OPERAND_ACCESS_READ)
        && m->type == CDISASM_OPERAND_MEMORY && m->reg == CDISASM_ARM_REG_NONE
        && m->base_reg == (rn == 31u ? CDISASM_ARM_REG_SP
            : CDISASM_ARM_REG_X0 + rn)
        && m->index_reg == CDISASM_ARM_REG_Z0 + zm
        && m->register_list == 0u && m->address == 0u && m->imm == 0u
        && m->size == sizes[n] && m->flags == 0u
        && m->shift_type == CDISASM_ARM_SHIFT_NONE && m->shift_amount == 0u
        && m->extend_type == ((w & UINT32_C(0x00400000)) != 0u
            ? CDISASM_ARM_EXTEND_SXTW : CDISASM_ARM_EXTEND_UXTW)
        && m->scale == scales[n] && m->access == CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sve_gather64_x64_unscaled_remaining_schema(
    const cdisasm_arm_instruction *i)
{
    static const uint32_t values[10] = {
        UINT32_C(0xc4408000), UINT32_C(0xc4c08000),
        UINT32_C(0xc5408000), UINT32_C(0xc440a000),
        UINT32_C(0xc4c0a000), UINT32_C(0xc540a000),
        UINT32_C(0xc5c0e000), UINT32_C(0xc440e000),
        UINT32_C(0xc4c0e000), UINT32_C(0xc540e000)
    };
    static const cdisasm_arm_name_id names[10] = {
        CDISASM_ARM_NAME_LD1SB, CDISASM_ARM_NAME_LD1SH,
        CDISASM_ARM_NAME_LD1SW, CDISASM_ARM_NAME_LDFF1SB,
        CDISASM_ARM_NAME_LDFF1SH, CDISASM_ARM_NAME_LDFF1SW,
        CDISASM_ARM_NAME_LDFF1D, CDISASM_ARM_NAME_LDFF1B,
        CDISASM_ARM_NAME_LDFF1H, CDISASM_ARM_NAME_LDFF1W
    };
    static const cdisasm_arm_form_id forms[10] = {
        3435u, 3436u, 3437u, 3442u, 3443u,
        3444u, 3445u, 3446u, 3447u, 3448u
    };
    static const uint8_t sizes[10] = {
        1u, 2u, 4u, 1u, 2u, 4u, 8u, 1u, 2u, 4u
    };
    uint32_t w = i->raw_instruction, value = w & UINT32_C(0xffe0e000);
    unsigned n, zt = w & 31u, rn = (w >> 5) & 31u;
    unsigned pg = (w >> 10) & 7u, zm = (w >> 16) & 31u;
    int raw = 0, claimed = 0;
    const cdisasm_arm_operand *d = &i->operand[0];
    const cdisasm_arm_operand *p = &i->operand[1];
    const cdisasm_arm_operand *m = &i->operand[2];

    for (n = 0u; n < 10u; ++n) {
        raw |= value == values[n]; claimed |= i->form_id == forms[n];
        if (value == values[n]) break;
    }
    if (!raw && !claimed) return 1;
    if (!raw || !claimed || n == 10u) return 0;
    return i->isa_id == CDISASM_ARM_ISA_A64 && i->name_id == names[n]
        && i->form_id == forms[n] && i->opcode_size == 4u
        && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        && i->branch_target == 0u && i->operand_count == 3u
        && d->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
        && d->reg == CDISASM_ARM_REG_Z0 + zt
        && d->register_list == UINT16_C(0x0101) && d->size == 0u
        && d->extend_type == 8u && d->flags == 0u
        && d->access == CDISASM_OPERAND_ACCESS_WRITE
        && arm_exact_predicate_operand(p,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg), 8u,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO,
            CDISASM_OPERAND_ACCESS_READ)
        && m->type == CDISASM_OPERAND_MEMORY && m->reg == CDISASM_ARM_REG_NONE
        && m->base_reg == (rn == 31u ? CDISASM_ARM_REG_SP
            : CDISASM_ARM_REG_X0 + rn)
        && m->index_reg == CDISASM_ARM_REG_Z0 + zm
        && m->register_list == 0u && m->address == 0u && m->imm == 0u
        && m->size == sizes[n] && m->flags == 0u
        && m->shift_type == CDISASM_ARM_SHIFT_NONE && m->shift_amount == 0u
        && m->extend_type == CDISASM_ARM_EXTEND_NONE && m->scale == 0u
        && m->access == CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sve_gather64_x64_scaled_schema(
    const cdisasm_arm_instruction *i)
{
    static const uint32_t values[10] = {
        UINT32_C(0xc4e08000), UINT32_C(0xc5608000),
        UINT32_C(0xc5e0c000), UINT32_C(0xc4e0c000),
        UINT32_C(0xc560c000), UINT32_C(0xc4e0a000),
        UINT32_C(0xc560a000), UINT32_C(0xc5e0e000),
        UINT32_C(0xc4e0e000), UINT32_C(0xc560e000)
    };
    static const cdisasm_arm_name_id names[10] = {
        CDISASM_ARM_NAME_LD1SH, CDISASM_ARM_NAME_LD1SW,
        CDISASM_ARM_NAME_LD1D, CDISASM_ARM_NAME_LD1H,
        CDISASM_ARM_NAME_LD1W, CDISASM_ARM_NAME_LDFF1SH,
        CDISASM_ARM_NAME_LDFF1SW, CDISASM_ARM_NAME_LDFF1D,
        CDISASM_ARM_NAME_LDFF1H, CDISASM_ARM_NAME_LDFF1W
    };
    static const cdisasm_arm_form_id forms[10] = {
        3453u, 3454u, 3455u, 3456u, 3457u,
        3458u, 3459u, 3460u, 3461u, 3462u
    };
    static const uint8_t sizes[10] = {
        2u, 4u, 8u, 2u, 4u, 2u, 4u, 8u, 2u, 4u
    };
    static const uint8_t shifts[10] = {
        1u, 2u, 3u, 1u, 2u, 1u, 2u, 3u, 1u, 2u
    };
    uint32_t w = i->raw_instruction, value = w & UINT32_C(0xffe0e000);
    unsigned n, zt = w & 31u, rn = (w >> 5) & 31u;
    unsigned pg = (w >> 10) & 7u, zm = (w >> 16) & 31u;
    int raw = 0, claimed = 0;
    const cdisasm_arm_operand *d = &i->operand[0];
    const cdisasm_arm_operand *p = &i->operand[1];
    const cdisasm_arm_operand *m = &i->operand[2];

    for (n = 0u; n < 10u; ++n) {
        raw |= value == values[n]; claimed |= i->form_id == forms[n];
        if (value == values[n]) break;
    }
    if (!raw && !claimed) return 1;
    if (!raw || !claimed || n == 10u) return 0;
    return i->isa_id == CDISASM_ARM_ISA_A64 && i->name_id == names[n]
        && i->form_id == forms[n] && i->opcode_size == 4u
        && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        && i->branch_target == 0u && i->operand_count == 3u
        && d->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
        && d->reg == CDISASM_ARM_REG_Z0 + zt
        && d->register_list == UINT16_C(0x0101) && d->size == 0u
        && d->extend_type == 8u && d->flags == 0u
        && d->access == CDISASM_OPERAND_ACCESS_WRITE
        && arm_exact_predicate_operand(p,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg), 8u,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO,
            CDISASM_OPERAND_ACCESS_READ)
        && m->type == CDISASM_OPERAND_MEMORY && m->reg == CDISASM_ARM_REG_NONE
        && m->base_reg == (rn == 31u ? CDISASM_ARM_REG_SP
            : CDISASM_ARM_REG_X0 + rn)
        && m->index_reg == CDISASM_ARM_REG_Z0 + zm
        && m->register_list == 0u && m->address == 0u && m->imm == 0u
        && m->size == sizes[n] && m->flags == 0u
        && m->shift_type == CDISASM_ARM_SHIFT_LSL
        && m->shift_amount == shifts[n]
        && m->extend_type == CDISASM_ARM_EXTEND_NONE && m->scale == 0u
        && m->access == CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sve_gather64_vector_immediate_remaining_schema(
    const cdisasm_arm_instruction *i)
{
    static const uint32_t values[10] = { UINT32_C(0xc4208000),
        UINT32_C(0xc4a08000), UINT32_C(0xc5208000),
        UINT32_C(0xc420a000), UINT32_C(0xc4a0a000),
        UINT32_C(0xc520a000), UINT32_C(0xc5a0e000),
        UINT32_C(0xc420e000), UINT32_C(0xc4a0e000),
        UINT32_C(0xc520e000) };
    static const cdisasm_arm_name_id names[10] = {
        CDISASM_ARM_NAME_LD1SB, CDISASM_ARM_NAME_LD1SH,
        CDISASM_ARM_NAME_LD1SW, CDISASM_ARM_NAME_LDFF1SB,
        CDISASM_ARM_NAME_LDFF1SH, CDISASM_ARM_NAME_LDFF1SW,
        CDISASM_ARM_NAME_LDFF1D, CDISASM_ARM_NAME_LDFF1B,
        CDISASM_ARM_NAME_LDFF1H, CDISASM_ARM_NAME_LDFF1W };
    static const cdisasm_arm_form_id forms[10] = { 3421u, 3422u, 3423u,
        3428u, 3429u, 3430u, 3431u, 3432u, 3433u, 3434u };
    static const uint8_t sizes[10] = {
        1u, 2u, 4u, 1u, 2u, 4u, 8u, 1u, 2u, 4u };
    uint32_t w = i->raw_instruction, value = w & UINT32_C(0xffe0e000);
    unsigned n, zt = w & 31u, zn = (w >> 5) & 31u;
    unsigned pg = (w >> 10) & 7u, imm = (w >> 16) & 31u;
    int raw = 0, claimed = 0;
    const cdisasm_arm_operand *d = &i->operand[0];
    const cdisasm_arm_operand *p = &i->operand[1];
    const cdisasm_arm_operand *m = &i->operand[2];
    for (n = 0u; n < 10u; ++n) {
        raw |= value == values[n]; claimed |= i->form_id == forms[n];
        if (value == values[n]) break;
    }
    if (!raw && !claimed) return 1;
    if (!raw || !claimed || n == 10u) return 0;
    return i->isa_id == CDISASM_ARM_ISA_A64 && i->name_id == names[n]
        && i->form_id == forms[n] && i->opcode_size == 4u
        && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        && i->branch_target == 0u && i->operand_count == 3u
        && d->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
        && d->reg == CDISASM_ARM_REG_Z0 + zt
        && d->register_list == UINT16_C(0x0101) && d->size == 0u
        && d->extend_type == 8u && d->flags == 0u
        && d->access == CDISASM_OPERAND_ACCESS_WRITE
        && arm_exact_predicate_operand(p,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg), 8u,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO,
            CDISASM_OPERAND_ACCESS_READ)
        && m->type == CDISASM_OPERAND_MEMORY && m->reg == CDISASM_ARM_REG_NONE
        && m->base_reg == CDISASM_ARM_REG_Z0 + zn
        && m->index_reg == CDISASM_ARM_REG_NONE && m->register_list == 0u
        && m->address == 0u && m->imm == (uint64_t)imm * sizes[n]
        && m->size == sizes[n]
        && m->flags == (imm == 0u ? 0u
            : CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT)
        && m->shift_type == CDISASM_ARM_SHIFT_NONE && m->shift_amount == 0u
        && m->extend_type == CDISASM_ARM_EXTEND_NONE && m->scale == 0u
        && m->access == CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sve2_scatter_non_temporal_store_schema(
    const cdisasm_arm_instruction *i)
{
    static const uint32_t values[7] = {
        UINT32_C(0xe4402000), UINT32_C(0xe4c02000),
        UINT32_C(0xe5402000), UINT32_C(0xe4002000),
        UINT32_C(0xe4802000), UINT32_C(0xe5002000),
        UINT32_C(0xe5802000)
    };
    static const cdisasm_arm_name_id names[7] = {
        CDISASM_ARM_NAME_STNT1B, CDISASM_ARM_NAME_STNT1H,
        CDISASM_ARM_NAME_STNT1W, CDISASM_ARM_NAME_STNT1B,
        CDISASM_ARM_NAME_STNT1H, CDISASM_ARM_NAME_STNT1W,
        CDISASM_ARM_NAME_STNT1D
    };
    static const cdisasm_arm_form_id forms[7] = {
        3481u, 3482u, 3483u, 3477u, 3478u, 3479u, 3480u
    };
    static const uint8_t element_sizes[7] = { 4u, 4u, 4u, 8u, 8u, 8u, 8u };
    static const uint8_t memory_sizes[7] = { 1u, 2u, 4u, 1u, 2u, 4u, 8u };
    uint32_t value = i->raw_instruction & UINT32_C(0xffe0e000);
    unsigned index, zt = i->raw_instruction & 31u;
    unsigned zn = (i->raw_instruction >> 5) & 31u;
    unsigned pg = (i->raw_instruction >> 10) & 7u;
    unsigned xm = (i->raw_instruction >> 16) & 31u;
    int raw = 0, claimed = 0;
    const cdisasm_arm_operand *d = &i->operand[0];
    const cdisasm_arm_operand *p = &i->operand[1];
    const cdisasm_arm_operand *m = &i->operand[2];

    for (index = 0u; index < 7u; ++index) {
        raw |= value == values[index];
        claimed |= i->form_id == forms[index];
        if (value == values[index]) break;
    }
    if (!raw && !claimed) return 1;
    if (!raw || !claimed || index == 7u) return 0;
    return i->isa_id == CDISASM_ARM_ISA_A64
        && i->name_id == names[index] && i->form_id == forms[index]
        && i->opcode_size == 4u && i->condition == CDISASM_ARM_CONDITION_AL
        && i->opcode_groups == CDISASM_GROUP_NONE
        && i->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)
        && i->branch_target == 0u && i->operand_count == 3u
        && d->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
        && d->reg == CDISASM_ARM_REG_Z0 + zt
        && d->register_list == UINT16_C(0x0101)
        && d->size == 0u && d->extend_type == element_sizes[index]
        && d->flags == 0u && d->access == CDISASM_OPERAND_ACCESS_READ
        && arm_exact_predicate_operand(p,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg),
            element_sizes[index], 0u, CDISASM_OPERAND_ACCESS_READ)
        && m->type == CDISASM_OPERAND_MEMORY
        && m->base_reg == CDISASM_ARM_REG_Z0 + zn
        && m->index_reg == (xm == 31u ? CDISASM_ARM_REG_NONE
            : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + xm))
        && m->size == memory_sizes[index] && m->imm == 0u
        && m->shift_type == CDISASM_ARM_SHIFT_NONE && m->shift_amount == 0u
        && m->extend_type == CDISASM_ARM_EXTEND_NONE && m->scale == 0u
        && m->flags == 0u && m->access == CDISASM_OPERAND_ACCESS_WRITE;
}

static int arm_valid_sve_replicate_load_immediate_schema(const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id names[4][4]={{CDISASM_ARM_NAME_LD1RB,CDISASM_ARM_NAME_LD1RB,CDISASM_ARM_NAME_LD1RB,CDISASM_ARM_NAME_LD1RB},{CDISASM_ARM_NAME_LD1RSW,CDISASM_ARM_NAME_LD1RH,CDISASM_ARM_NAME_LD1RH,CDISASM_ARM_NAME_LD1RH},{CDISASM_ARM_NAME_LD1RSH,CDISASM_ARM_NAME_LD1RSH,CDISASM_ARM_NAME_LD1RW,CDISASM_ARM_NAME_LD1RW},{CDISASM_ARM_NAME_LD1RSB,CDISASM_ARM_NAME_LD1RSB,CDISASM_ARM_NAME_LD1RSB,CDISASM_ARM_NAME_LD1RD}};static const uint8_t ms[4][4]={{1,1,1,1},{4,2,2,2},{2,2,4,4},{1,1,1,8}},dsizes[4][4]={{1,2,4,8},{8,2,4,8},{8,4,4,8},{8,4,2,8}};
    uint32_t w=i->raw_instruction;int raw=i->isa_id==CDISASM_ARM_ISA_A64&&((w&UINT32_C(0xffc08000))==UINT32_C(0x84408000)||(w&UINT32_C(0xffc08000))==UINT32_C(0x84c08000)||(w&UINT32_C(0xffc08000))==UINT32_C(0x85408000)||(w&UINT32_C(0xffc08000))==UINT32_C(0x85c08000));int form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=3243&&i->form_id<=3258;unsigned op=(w>>23)&3u,a=(w>>13)&3u,zd=w&31u,pg=(w>>10)&7u,rn=(w>>5)&31u;uint8_t ds=dsizes[op][a],mem=ms[op][a];const cdisasm_arm_operand*d=&i->operand[0],*p=&i->operand[1],*m=&i->operand[2];cdisasm_arm_reg_id base=rn==31u?CDISASM_ARM_REG_SP:(cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0+rn);uint64_t disp=((w>>16)&63u)*mem;
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    return i->name_id==names[op][a]&&i->form_id==(3243u+op*4u+a)&&i->opcode_size==4u&&i->condition==CDISASM_ARM_CONDITION_AL&&i->opcode_groups==CDISASM_GROUP_NONE&&i->instruction_flags==(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)&&i->operand_count==3u&&d->type==CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST&&d->reg==CDISASM_ARM_REG_Z0+zd&&d->register_list==UINT16_C(0x0101)&&d->extend_type==ds&&d->access==CDISASM_OPERAND_ACCESS_WRITE&&p->type==CDISASM_ARM_OPERAND_PREDICATE&&p->reg==CDISASM_ARM_REG_P0+pg&&p->extend_type==ds&&p->flags==CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO&&p->access==CDISASM_OPERAND_ACCESS_READ&&m->type==CDISASM_OPERAND_MEMORY&&m->base_reg==base&&m->size==mem&&m->imm==disp&&m->flags==(disp?CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT:0)&&m->access==CDISASM_OPERAND_ACCESS_READ;
}

static int arm_valid_sve_replicate_block_load_schema(const cdisasm_arm_instruction *i)
{
    static const cdisasm_arm_name_id qn[4]={CDISASM_ARM_NAME_LD1RQB,CDISASM_ARM_NAME_LD1RQH,CDISASM_ARM_NAME_LD1RQW,CDISASM_ARM_NAME_LD1RQD},on[4]={CDISASM_ARM_NAME_LD1ROB,CDISASM_ARM_NAME_LD1ROH,CDISASM_ARM_NAME_LD1ROW,CDISASM_ARM_NAME_LD1ROD};uint32_t w=i->raw_instruction,mask=(w&UINT32_C(0x2000))?UINT32_C(0xfff0e000):UINT32_C(0xffe0e000),value=w&mask;int raw=i->isa_id==CDISASM_ARM_ISA_A64&&(value==UINT32_C(0xa4000000)||value==UINT32_C(0xa4200000)||value==UINT32_C(0xa4800000)||value==UINT32_C(0xa4a00000)||value==UINT32_C(0xa5000000)||value==UINT32_C(0xa5200000)||value==UINT32_C(0xa5800000)||value==UINT32_C(0xa5a00000)||value==UINT32_C(0xa4002000)||value==UINT32_C(0xa4202000)||value==UINT32_C(0xa4802000)||value==UINT32_C(0xa4a02000)||value==UINT32_C(0xa5002000)||value==UINT32_C(0xa5202000)||value==UINT32_C(0xa5802000)||value==UINT32_C(0xa5a02000));int form=i->isa_id==CDISASM_ARM_ISA_A64&&i->form_id>=3259&&i->form_id<=3274;unsigned sz=(w>>23)&3u,zd=w&31u,pg=(w>>10)&7u,rn=(w>>5)&31u;int o=(w&UINT32_C(0x200000))!=0,imm=(w&UINT32_C(0x2000))!=0;uint8_t es=(uint8_t)(1u<<sz),ms=o?32u:16u;const cdisasm_arm_operand*d=&i->operand[0],*p=&i->operand[1],*m=&i->operand[2];cdisasm_arm_reg_id base=rn==31u?CDISASM_ARM_REG_SP:(cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0+rn);int64_t disp=imm?((int64_t)((int32_t)(((w>>16)&15u)<<28)>>28))*ms:0;
    if(!raw&&!form)return 1;if(!raw||!form)return 0;
    if(i->name_id!=(o?on[sz]:qn[sz])||i->form_id!=(imm?3267u:3259u)+sz*2u+o||i->opcode_size!=4u||i->condition!=CDISASM_ARM_CONDITION_AL||i->opcode_groups!=CDISASM_GROUP_NONE||i->instruction_flags!=(CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR|CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED)||i->operand_count!=3u)return 0;
    if(d->type!=CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST||d->reg!=CDISASM_ARM_REG_Z0+zd||d->register_list!=UINT16_C(0x0101)||d->extend_type!=es||d->access!=CDISASM_OPERAND_ACCESS_WRITE||p->type!=CDISASM_ARM_OPERAND_PREDICATE||p->reg!=CDISASM_ARM_REG_P0+pg||p->extend_type!=es||p->flags!=CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO||p->access!=CDISASM_OPERAND_ACCESS_READ||m->type!=CDISASM_OPERAND_MEMORY||m->base_reg!=base||m->size!=ms||m->access!=CDISASM_OPERAND_ACCESS_READ)return 0;
    return imm?(m->index_reg==CDISASM_ARM_REG_NONE&&(int64_t)m->imm==disp&&m->flags==(disp?CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT:0)):(m->index_reg==(cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0+((w>>16)&31u))&&m->imm==0u&&m->flags==0u&&m->shift_type==(sz?CDISASM_ARM_SHIFT_LSL:CDISASM_ARM_SHIFT_NONE)&&m->shift_amount==sz);
}

static int arm_valid_instruction(const cdisasm_arm_instruction *instruction)
{
    const uint32_t known_groups = CDISASM_GROUP_JUMP | CDISASM_GROUP_CALL
        | CDISASM_GROUP_RETURN | CDISASM_GROUP_INTERRUPT
        | CDISASM_GROUP_INTERRUPT_RETURN | CDISASM_GROUP_PRIVILEGED
        | CDISASM_GROUP_RELATIVE_BRANCH | CDISASM_GROUP_CONDITIONAL;
    const uint32_t known_flags = CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS
        | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
        | CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
        | CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
        | CDISASM_ARM_INSTRUCTION_FLAG_LINK
        | CDISASM_ARM_INSTRUCTION_FLAG_BYTE
        | CDISASM_ARM_INSTRUCTION_FLAG_USER_REGISTERS
        | CDISASM_ARM_INSTRUCTION_FLAG_UNPRIVILEGED
        | CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL
        | CDISASM_ARM_INSTRUCTION_FLAG_UNPREDICTABLE
        | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT
        | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT
        | CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
        | CDISASM_ARM_INSTRUCTION_FLAG_APPLE_PROPRIETARY
        | CDISASM_ARM_INSTRUCTION_FLAG_APPLE_AMX
        | CDISASM_ARM_INSTRUCTION_FLAG_APPLE_MUL53
        | CDISASM_ARM_INSTRUCTION_FLAG_APPLE_SYSTEM
        | CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
        | CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
        | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE
        | CDISASM_ARM_INSTRUCTION_FLAG_EXCLUSIVE
        | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
        | CDISASM_ARM_INSTRUCTION_FLAG_SME
        | CDISASM_ARM_INSTRUCTION_FLAG_STREAMING
        | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
        | CDISASM_ARM_INSTRUCTION_FLAG_MEMORY_TAGGING
        | CDISASM_ARM_INSTRUCTION_FLAG_POINTER_AUTH
        | CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC_PAIR
        | CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
        | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
    size_t index;
    size_t relative_target_count = 0;
    size_t atomic_memory_count = 0;
    size_t register_pair_count = 0;
    cdisasm_operand_access atomic_memory_access =
        CDISASM_OPERAND_ACCESS_NONE;
    uint32_t expected_atomic_flags;
    unsigned lsui_cas_ordering = 0u;
    int lsui_cas_pair = 0;
    const uint32_t atomic_flags_mask =
        CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
        | CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
        | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE
        | CDISASM_ARM_INSTRUCTION_FLAG_EXCLUSIVE
        | CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC_PAIR;

    if (instruction == NULL
        || instruction->last_error_id != CDISASM_STATUS_OK
        || instruction->name_id == CDISASM_ARM_NAME_NONE
        || instruction->name_id >= CDISASM_ARM_NAME_COUNT
        || arm_mnemonic_names[instruction->name_id] == NULL
        || instruction->operand_count > CDISASM_ARM_MAX_OPERANDS
        || instruction->condition > CDISASM_ARM_CONDITION_NV
        || (instruction->opcode_groups & ~known_groups) != 0u
        || (instruction->instruction_flags & ~known_flags) != 0u) {
        return 0;
    }
    if (instruction->form_id == UINT16_C(4498)
        && instruction->name_id == CDISASM_ARM_NAME_MSR
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE) == 0u) {
        uint8_t field;
        uint8_t immediate;

        if (instruction->isa_id != CDISASM_ARM_ISA_A64
            || instruction->opcode_size != 4u
            || !arm_pstate_msr_decode_word(
                instruction->raw_instruction, &field, &immediate)
            || instruction->operand_count != 2u
            || instruction->operand[0].type
                != CDISASM_ARM_OPERAND_PSTATE_FIELD
            || instruction->operand[0].imm != field
            || instruction->operand[1].type != CDISASM_OPERAND_IMMEDIATE
            || instruction->operand[1].imm != immediate) {
            return 0;
        }
    }
    /* The FVDOT/BFVDOT indexed forms use encodings which overlap older SME
     * envelope validators.  Validate their complete structured shape once,
     * before those legacy schemas inspect the same raw word. */
    if (instruction->form_id >= UINT16_C(6500)
            && instruction->form_id <= UINT16_C(6504)) {
        if (!arm_valid_sme_fvdot_schema(instruction)
                || instruction->opcode_size != 4u
                || instruction->branch_target != 0u) {
            return 0;
        }
        for (index = 0u; index < instruction->operand_count; ++index) {
            if (!arm_valid_operand(instruction, &instruction->operand[index])) {
                return 0;
            }
        }
        return 1;
    }
    if (!arm_valid_a64_fmov_immediate_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_a64_fmov_lane64_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_sat_round_narrow_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve2_gather_non_temporal_load_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_address_generation_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_gather32_unscaled_remaining_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_gather32_prefetch_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_gather64_x32_prefetch_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_gather64_prefetch_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_gather32_scaled_remaining_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_prefetch_immediate_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_prefetch_scalar_register_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_prefetch_vector_immediate_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_prefetch64_vector_immediate_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_gather32_vector_immediate_remaining_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_gather64_x32_unscaled_remaining_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_gather64_x32_scaled_remaining_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_gather64_x64_unscaled_remaining_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_gather64_x64_scaled_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_gather64_vector_immediate_remaining_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve2_scatter_non_temporal_store_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_replicate_load_immediate_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_replicate_block_load_schema(instruction)) {
        return 0;
    }
    if ((instruction->isa_id == CDISASM_ARM_ISA_A64
            && (instruction->raw_instruction & UINT32_C(0xff20f400))
                == UINT32_C(0x7e008400))
        || instruction->form_id == UINT16_C(5771)
        || instruction->form_id == UINT16_C(5772)) {
        return arm_valid_advsimd_scalar_sqrdml_accumulate_schema(instruction);
    }
    if ((instruction->isa_id == CDISASM_ARM_ISA_A64
            && arm_scalar_by_element_identity(instruction->raw_instruction,
                &(uint16_t){0}, &(cdisasm_arm_name_id){0}) >= 0)
        || (instruction->form_id >= UINT16_C(5877)
            && instruction->form_id <= UINT16_C(5891))) {
        return arm_valid_advsimd_scalar_by_element_schema(instruction);
    }
    expected_atomic_flags = arm_expected_atomic_flags(instruction);
    if ((instruction->instruction_flags & atomic_flags_mask)
            != expected_atomic_flags
        || (expected_atomic_flags != 0u
            && ((instruction->isa_id != CDISASM_ARM_ISA_A64
                    && !(instruction->isa_id == CDISASM_ARM_ISA_T32
                        && arm_is_t32_atomic_name(instruction->name_id)))
                || instruction->opcode_groups != CDISASM_GROUP_NONE))) {
        return 0;
    }
    if ((instruction->isa_id == CDISASM_ARM_ISA_A32
            || instruction->isa_id == CDISASM_ARM_ISA_A64)
        ? instruction->opcode_size != 4u
        : instruction->isa_id != CDISASM_ARM_ISA_T32
            || (instruction->opcode_size != 2u
                && instruction->opcode_size != 4u)) {
        return 0;
    }
    if (instruction->isa_id == CDISASM_ARM_ISA_T32
        && instruction->opcode_size == 2u
        && (instruction->raw_instruction & UINT32_C(0xffff0000)) != 0u) {
        return 0;
    }
    if ((instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX) != 0u
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX) != 0u) {
        return 0;
    }
    if ((instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED) != 0u
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR) == 0u) {
        return 0;
    }
    if ((instruction->instruction_flags
            & (CDISASM_ARM_INSTRUCTION_FLAG_STREAMING
                | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX)) != 0u
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_SME) == 0u) {
        return 0;
    }
    if ((instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC_PAIR) != 0u
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC) == 0u) {
        return 0;
    }
    if ((instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT) != 0u
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT) != 0u) {
        return 0;
    }
    if ((instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_UNPREDICTABLE) != 0u
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL) == 0u) {
        return 0;
    }
    if ((instruction->instruction_flags
            & (CDISASM_ARM_INSTRUCTION_FLAG_APPLE_AMX
                | CDISASM_ARM_INSTRUCTION_FLAG_APPLE_MUL53
                | CDISASM_ARM_INSTRUCTION_FLAG_APPLE_SYSTEM)) != 0u
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_APPLE_PROPRIETARY) == 0u) {
        return 0;
    }
    if ((instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_APPLE_MUL53) != 0u
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_SIMD) == 0u) {
        return 0;
    }
    if ((instruction->instruction_flags
            & (CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
                | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE
                | CDISASM_ARM_INSTRUCTION_FLAG_EXCLUSIVE)) != 0u
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC) == 0u) {
        return 0;
    }
    if ((instruction->instruction_flags
            & (CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT
                | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT
                | CDISASM_ARM_INSTRUCTION_FLAG_USER_REGISTERS)) != 0u
        && !arm_is_multiple_transfer_name(instruction->name_id)) {
        return 0;
    }
    if (instruction->condition != CDISASM_ARM_CONDITION_AL
        && (instruction->opcode_groups & CDISASM_GROUP_CONDITIONAL) == 0u
        && !((instruction->instruction_flags
                & CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u
            && instruction->isa_id == CDISASM_ARM_ISA_A32
            && instruction->form_id != CDISASM_ARM_FORM_NONE
            && instruction->form_id
                <= CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST)) {
        return 0;
    }
    if (instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->condition != CDISASM_ARM_CONDITION_AL
        && instruction->name_id != CDISASM_ARM_NAME_B
        && instruction->name_id != CDISASM_ARM_NAME_BC) {
        return 0;
    }
    for (index = 0; index < instruction->operand_count; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];

        if (!arm_valid_operand(instruction, operand)) {
            return 0;
        }
        if (operand->type == CDISASM_OPERAND_IMMEDIATE
            && (operand->flags & CDISASM_OPERAND_FLAG_PC_RELATIVE) != 0u
            && operand->imm == instruction->branch_target) {
            ++relative_target_count;
        }
        if (operand->type == CDISASM_OPERAND_MEMORY
            && expected_atomic_flags != 0u) {
            ++atomic_memory_count;
            atomic_memory_access = operand->access;
        }
        if (operand->type == CDISASM_ARM_OPERAND_REGISTER_PAIR) {
            ++register_pair_count;
        }
    }
    for (; index < CDISASM_ARM_MAX_OPERANDS; ++index) {
        if (!arm_bytes_are_zero(
                &instruction->operand[index],
                sizeof(instruction->operand[index]))) {
            return 0;
        }
    }
    if ((instruction->opcode_groups & CDISASM_GROUP_RELATIVE_BRANCH) != 0u) {
        int generated_opaque = (instruction->instruction_flags
            & (CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
                | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE))
            == (CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
                | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE);

        if ((!generated_opaque && relative_target_count != 1u)
            || (generated_opaque && relative_target_count > 1u)) {
            return 0;
        }
    } else if (instruction->branch_target != 0u) {
        return 0;
    }
    if ((instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_SIMD) != 0u
        && instruction->operand_count == 0u) {
        return 0;
    }
    if (expected_atomic_flags != 0u
        && (atomic_memory_count != 1u
            || atomic_memory_access != arm_expected_atomic_memory_access(
                instruction->name_id))) {
        return 0;
    }
    (void)arm_lsui_cas_ordering(instruction->name_id,
        &lsui_cas_ordering, &lsui_cas_pair);
    if (((instruction->name_id >= CDISASM_ARM_NAME_CASP
                && instruction->name_id <= CDISASM_ARM_NAME_CASPAL)
            || lsui_cas_pair)
        ? register_pair_count != 2u : register_pair_count != 0u) {
        return 0;
    }
    if (!arm_valid_extra_atomic_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_a64_udf_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_architectural_hint_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_a32_speculation_barrier_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_a32_prefetch_immediate_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_a32_prefetch_register_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_t32_narrow_mov_shift_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_a32_mov_register_shift_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_t32_wide_mov_register_shift_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_contiguous_load_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_multi_contiguous_load_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_multi_contiguous_store_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_contiguous_store_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_contiguous_load_register_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_contiguous_store_register_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve2p1_q_load_store_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve2p1_multi_q_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve2p1_multi_contiguous_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_t32_wide_cps_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme_fmopa_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme_zero_mask_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_luti_zt0_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme_luti_extended_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_indexed_long_mla_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_indexed_fp_long_mla_single_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme_fp8_indexed_long_mla_single_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_indexed_fp_long_mla2_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_indexed_fp_long_mla4_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme_fp8_indexed_long_mla_multi_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_indexed_long_mla4_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_fp_long_mla_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme_fp8_long_mla_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_multi_long_mla_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme_fp_long_mla_multi_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme_multi_fp16_mla_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_multi_dot_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_multi_fp_mla_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_multi_int_add_sub_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_multi_arith_single_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme_multi_fp16_arith_single_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_multi_sel_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_multi_int_minmax_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_multi_fp_minmax_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_multi_int_misc_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_multi4_int_minmax_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_multi4_fp_minmax_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme_multi_fscale_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_multi4_int_misc_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_multi2x2_int_minmax_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_multi2x2_fp_minmax_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_multi2x2_int_misc_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_multi4x4_int_minmax_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_multi4x4_fp_minmax_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme_multi_matrix_special_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_multi_fclamp_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_predicated_bfscale_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_a64_lsui_pair_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_a64_fp_pair_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_a64_fp_signed_memory_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_a64_fp_unsigned_memory_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_a64_fp_register_memory_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_a64_register_memory_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_a64_prfm_unsigned_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_a64_add_sub_extended_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_a64_add_sub_pointer_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_multi4x4_int_misc_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_multi_clamp_int_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_multi_zip_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_multi4_qrshrn_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_indexed_d2_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_indexed_vdot_d4_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_indexed_vdot_s_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_indexed_mixed_dot_s_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_indexed_multi2_s_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme_tmop_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme_fvdot_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_indexed_multi4_s_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme_indexed_fp8_fdot_h_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_multi2_long_mla_single_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_multi4_long_mla_single_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_single_long_mla_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme_multi2_fdot_single_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme_multi_fdot_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme_multi2_integer_dot_single_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme_multi2_arith_single_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme_indexed_fp16_mla_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_zero_zt0_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2p1_zero_multi_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2p1_zero_range_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_crc32_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_wfxt_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sb_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_dsb_nxs_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_pauth_branch_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_element_count_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_widening_fp_mla_indexed_schema(instruction)) return 0;
    if (!arm_valid_sve_fp8_widening_fp_mla_indexed_schema(instruction)) return 0;
    if (!arm_valid_sve_fp8_widening_schema(instruction)) return 0;
    if (!arm_valid_sve_fp8_widening_long_long_indexed_schema(instruction)) return 0;
    if (!arm_valid_sve_fp8_fmmla_schema(instruction)) return 0;
    if (!arm_valid_sve_fmmla_schema(instruction)) return 0;
    if (!arm_valid_sve_widening_fp_mla_schema(instruction)) return 0;
    if (!arm_valid_sve_saturating_count_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_psel_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_punpk_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_unpack_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_shift_insert_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_xar_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_bitperm_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_fixed_crypto_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_sha_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_ext_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_bitwise_select_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_widening_add_sub_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_absolute_difference_long_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_scalar_saturating_widening_multiply_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_scalar_immediate_shift_convert_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_table_lookup_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_dot_rdm_three_same_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_extended_dot_three_same_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_widening_fp_three_same_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_i8mm_mmla_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_matrix_fp_three_same_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_fp_convert_vector_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_fp8_fcvtl_vector_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_fhm_three_same_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_fhm_by_element_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_widening_multiply_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_pmull_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_pmul_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_saturating_mulh_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_high_narrow_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_unpredicated_logical_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_integer_immediate_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_dup_immediate_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_dot_product_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_usdot_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_dot_indexed_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_mla_indexed_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_sqrdml_indexed_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_aes_unary_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_crypto_binary_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_predicated_shift_sat_round_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_predicated_sat_unary_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_predicated_accumulate_long_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_predicated_halving_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_predicated_pairwise_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_compare_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_compare_zero_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_cmtst_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_variable_shift_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_modified_immediate_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_shift_right_immediate_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_shift_narrow_widen_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_sat_shift_convert_immediate_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_absolute_difference_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_absolute_difference_accumulate_schema(
            instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_multiply_accumulate_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_multiply_element_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_dot_element_schema(instruction)) return 0;
    if (!arm_valid_advsimd_fp_dot_element_schema(instruction)) return 0;
    if (!arm_valid_advsimd_bfmlal_element_schema(instruction)) return 0;
    if (!arm_valid_advsimd_fp8_widening_element_schema(instruction)) return 0;
    if (!arm_valid_advsimd_fp_multiply_element_schema(instruction)) return 0;
    if (!arm_valid_advsimd_rdm_element_schema(instruction)) return 0;
    if (!arm_valid_advsimd_minmax_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_pairwise_minmax_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_addp_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_addv_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_minmaxv_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_integer_unary_scalar_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_addlv_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_pairwise_add_long_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_advsimd_narrow_widen_move_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_predicated_saturating_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_clamp_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_pointer_muladd_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_quad_permute_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_complex_muladd_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_fcmla_predicated_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_predicate_control_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_predicate_break_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_while_counter_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_while_single_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_while_pair_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_counter_mask_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_cterm_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_whilewr_rw_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sve_predicate_count_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_predicated_mova_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2_multi_mova_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_sme2p1_movaz_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_za_contiguous_schema(instruction)) {
        return 0;
    }
    if (!arm_valid_za_transfer_schema(instruction)) {
        return 0;
    }
    return 1;
}

static int arm_name_accepts_flag_suffix(cdisasm_arm_name_id name_id)
{
    switch (name_id) {
        case CDISASM_ARM_NAME_ADC:
        case CDISASM_ARM_NAME_ADD:
        case CDISASM_ARM_NAME_AND:
        case CDISASM_ARM_NAME_BIC:
        case CDISASM_ARM_NAME_EOR:
        case CDISASM_ARM_NAME_MOV:
        case CDISASM_ARM_NAME_MUL:
        case CDISASM_ARM_NAME_MVN:
        case CDISASM_ARM_NAME_ORR:
        case CDISASM_ARM_NAME_RSB:
        case CDISASM_ARM_NAME_RSC:
        case CDISASM_ARM_NAME_SBC:
        case CDISASM_ARM_NAME_SUB:
            return 1;
        default:
            return 0;
    }
}

static int arm_a32_vector_name_has_datatype(cdisasm_arm_name_id name_id)
{
    return name_id == CDISASM_ARM_NAME_VADD
        || name_id == CDISASM_ARM_NAME_VSUB
        || name_id == CDISASM_ARM_NAME_VMUL
        || name_id == CDISASM_ARM_NAME_VMLA
        || name_id == CDISASM_ARM_NAME_VMLS;
}

static int arm_a32_scalar_fp_name_has_datatype(cdisasm_arm_name_id name_id)
{
    return name_id == CDISASM_ARM_NAME_VADD
        || name_id == CDISASM_ARM_NAME_VSUB
        || name_id == CDISASM_ARM_NAME_VMUL
        || name_id == CDISASM_ARM_NAME_VDIV
        || name_id == CDISASM_ARM_NAME_VMLA
        || name_id == CDISASM_ARM_NAME_VMLS;
}

static char arm_vector_element_letter(uint8_t element_size)
{
    switch (element_size) {
        case 1u:
            return 'b';
        case 2u:
            return 'h';
        case 4u:
            return 's';
        case 8u:
            return 'd';
        case 16u:
            return 'q';
        default:
            return '\0';
    }
}

static void arm_format_it_suffix(
    arm_text_writer *writer,
    const cdisasm_arm_instruction *instruction,
    int uppercase)
{
    unsigned mask;
    unsigned condition_bit;
    unsigned least_significant = 0u;
    unsigned following;
    unsigned index;

    if (instruction->name_id != CDISASM_ARM_NAME_IT
        || instruction->operand_count != 2u
        || instruction->operand[0].type != CDISASM_OPERAND_IMMEDIATE
        || instruction->operand[1].type != CDISASM_OPERAND_IMMEDIATE) {
        return;
    }
    mask = (unsigned)instruction->operand[1].imm & 15u;
    condition_bit = (unsigned)instruction->operand[0].imm & 1u;
    while (least_significant < 4u
        && (mask & (1u << least_significant)) == 0u) {
        ++least_significant;
    }
    if (least_significant >= 4u) {
        return;
    }
    following = 3u - least_significant;
    for (index = 0u; index < following; ++index) {
        unsigned encoded_bit = (mask >> (3u - index)) & 1u;

        arm_writer_putc_mnemonic(
            writer, encoded_bit == condition_bit ? 't' : 'e', uppercase);
    }
}

static void arm_format_mnemonic(
    arm_text_writer *writer,
    const cdisasm_arm_instruction *instruction,
    uint32_t format_flags)
{
    uint32_t instruction_flags = instruction->instruction_flags;
    int uppercase =
        (format_flags & CDISASM_FORMAT_UPPERCASE_OPCODE) != 0u;

    arm_writer_puts_mnemonic(
        writer, arm_mnemonic_names[instruction->name_id], uppercase);
    /* A32/T32 AdvSIMD structure transfers carry the element width on the
     * mnemonic (vld1.8/vst4.32), while their fixed operand records retain
     * only D-register lists and memory metadata. */
    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        && instruction->operand_count != 0u
        && instruction->operand[0].type
            == CDISASM_ARM_OPERAND_VECTOR_REGISTER_LIST
        && ((instruction->name_id >= CDISASM_ARM_NAME_VLD1
                && instruction->name_id <= CDISASM_ARM_NAME_VLD4)
            || (instruction->name_id >= CDISASM_ARM_NAME_VST1
                && instruction->name_id <= CDISASM_ARM_NAME_VST4))) {
        arm_writer_putc_mnemonic(writer, '.', uppercase);
        arm_writer_decimal(writer,
            (uint64_t)instruction->operand[0].extend_type * UINT64_C(8));
    }
    if ((instruction->form_id == UINT16_C(5988)
            || instruction->form_id == UINT16_C(6267))
        && instruction->name_id == CDISASM_ARM_NAME_BFMLAL) {
        arm_writer_putc_mnemonic(writer,
            (instruction->raw_instruction & UINT32_C(0x40000000)) != 0u
                ? 't' : 'b', uppercase);
    }
    if ((arm_is_advsimd_high_narrow_form(instruction)
            || arm_is_advsimd_narrow_widen_move_form(
                instruction->form_id)
            || arm_is_advsimd_shift_narrow_widen_form(
                instruction->form_id)
            || instruction->form_id == UINT16_C(6224)
            || instruction->form_id == UINT16_C(6223)
            || instruction->form_id == UINT16_C(6236)
            || instruction->form_id == UINT16_C(6238)
            || instruction->form_id == UINT16_C(6237)
            || instruction->form_id == UINT16_C(6239)
            || arm_is_advsimd_widening_add_sub_form(
                instruction->form_id)
            || arm_is_advsimd_absolute_difference_long_form(
                instruction->form_id)
            || arm_is_advsimd_widening_multiply_form(
                instruction->form_id)
            || arm_is_advsimd_widening_multiply_element_form(
                instruction->form_id)
            || arm_is_advsimd_pmull_form(instruction))
        && (instruction->raw_instruction & UINT32_C(0x40000000)) != 0u) {
        arm_writer_putc_mnemonic(writer, '2', uppercase);
    }
    if ((instruction->form_id == UINT16_C(6017)
            || instruction->form_id == UINT16_C(6018)
            || instruction->form_id == UINT16_C(6060)
            || instruction->form_id == UINT16_C(6062)
            || instruction->form_id == UINT16_C(6072)
            || instruction->form_id == UINT16_C(6073)
            || instruction->form_id == UINT16_C(6037)
            || instruction->form_id == UINT16_C(5976))
        && (instruction->raw_instruction & UINT32_C(0x40000000)) != 0u) {
        arm_writer_putc_mnemonic(writer, '2', uppercase);
    }
    arm_format_it_suffix(writer, instruction, uppercase);
    if ((instruction_flags & CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS) != 0u
        && arm_name_accepts_flag_suffix(instruction->name_id)) {
        arm_writer_putc_mnemonic(writer, 's', uppercase);
    }
    if ((instruction->name_id == CDISASM_ARM_NAME_LDM
            || instruction->name_id == CDISASM_ARM_NAME_STM)
        && (instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT) != 0u
        && (instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX) != 0u) {
        arm_writer_puts_mnemonic(writer, "ib", uppercase);
    } else if ((instruction->name_id == CDISASM_ARM_NAME_LDM
            || instruction->name_id == CDISASM_ARM_NAME_STM)
        && (instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT) != 0u) {
        arm_writer_puts_mnemonic(writer,
            (instruction_flags & CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX)
                    != 0u
                ? "db" : "da",
            uppercase);
    }
    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        && (instruction_flags & CDISASM_ARM_INSTRUCTION_FLAG_SIMD) != 0u
        && arm_is_advsimd_sha_name(instruction->name_id)) {
        arm_writer_puts(writer, ".32");
    } else if (instruction->isa_id != CDISASM_ARM_ISA_A64
        && (instruction_flags & CDISASM_ARM_INSTRUCTION_FLAG_SIMD) != 0u
        && arm_a32_vector_name_has_datatype(instruction->name_id)) {
        uint8_t element_size =
            CDISASM_ARM_VECTOR_ELEMENT_SIZE(&instruction->operand[0]);

        arm_writer_putc(writer, '.');
        arm_writer_putc_mnemonic(writer,
            (instruction_flags
                & CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT) != 0u
                ? 'f' : 'i',
            uppercase);
        arm_writer_decimal(writer, (uint64_t)element_size * UINT64_C(8));
    } else if (instruction->isa_id != CDISASM_ARM_ISA_A64
        && (instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT) != 0u
        && (instruction_flags & CDISASM_ARM_INSTRUCTION_FLAG_SIMD) == 0u
        && arm_a32_scalar_fp_name_has_datatype(instruction->name_id)) {
        arm_writer_puts(writer, ".f");
        arm_writer_decimal(
            writer, (uint64_t)instruction->operand[0].size * UINT64_C(8));
    } else if ((instruction_flags
        & CDISASM_ARM_INSTRUCTION_FLAG_APPLE_MUL53) != 0u) {
        const cdisasm_arm_operand *operand = &instruction->operand[0];

        arm_writer_putc(writer, '.');
        arm_writer_decimal(
            writer, CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand));
        arm_writer_putc_mnemonic(writer,
            arm_vector_element_letter(
                CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand)),
            uppercase);
    }
    if (instruction->condition != CDISASM_ARM_CONDITION_AL
        || (instruction->isa_id == CDISASM_ARM_ISA_A64
            && instruction->name_id == CDISASM_ARM_NAME_B
            && (instruction->opcode_groups & CDISASM_GROUP_CONDITIONAL)
                != 0u)) {
        if (instruction->isa_id == CDISASM_ARM_ISA_A64) {
            arm_writer_putc(writer, '.');
        }
        arm_writer_puts_mnemonic(
            writer,
            arm_condition_names[instruction->condition],
            uppercase);
    }
}

static void arm_format_modifier(
    arm_text_writer *writer,
    const cdisasm_arm_operand *operand)
{
    if (operand->shift_type != CDISASM_ARM_SHIFT_NONE) {
        arm_writer_puts(writer, ", ");
        arm_writer_puts(writer, arm_shift_names[operand->shift_type]);
        if (operand->shift_type != CDISASM_ARM_SHIFT_RRX) {
            arm_writer_puts(writer, " #");
            arm_writer_hex(writer, operand->shift_amount);
        }
    } else if (operand->extend_type != CDISASM_ARM_EXTEND_NONE) {
        arm_writer_puts(writer, ", ");
        arm_writer_puts(writer, arm_extend_names[operand->extend_type]);
        if (operand->scale != 0u) {
            arm_writer_puts(writer, " #");
            arm_writer_hex(writer, operand->scale);
        }
    }
}

static void arm_format_vector_arrangement(
    arm_text_writer *writer,
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    if (instruction->name_id == CDISASM_ARM_NAME_MOVT
        && instruction->form_id == UINT16_C(3919)) {
        return;
    }
    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || ((instruction->instruction_flags
                & CDISASM_ARM_INSTRUCTION_FLAG_SIMD) == 0u
            && !(arm_is_sve_quadword_reduction_name(instruction->name_id)
                && operand == &instruction->operand[0]))
        || (instruction->form_id == UINT16_C(5808)
            && instruction->name_id == CDISASM_ARM_NAME_ADDP
            && operand == &instruction->operand[0])
        || (instruction->form_id == UINT16_C(6077)
            && instruction->name_id == CDISASM_ARM_NAME_ADDV
            && operand == &instruction->operand[0])
        || (((instruction->form_id == UINT16_C(6075)
                    && instruction->name_id == CDISASM_ARM_NAME_SMAXV)
                || (instruction->form_id == UINT16_C(6076)
                    && instruction->name_id == CDISASM_ARM_NAME_SMINV)
                || (instruction->form_id == UINT16_C(6083)
                    && instruction->name_id == CDISASM_ARM_NAME_UMAXV)
                || (instruction->form_id == UINT16_C(6084)
                    && instruction->name_id == CDISASM_ARM_NAME_UMINV))
            && operand == &instruction->operand[0])
        || ((instruction->form_id >= UINT16_C(6078)
                && instruction->form_id <= UINT16_C(6081))
            && operand == &instruction->operand[0])
        || ((instruction->form_id >= UINT16_C(6085)
                && instruction->form_id <= UINT16_C(6088))
            && operand == &instruction->operand[0])
        || ((instruction->form_id == UINT16_C(5773)
                || instruction->form_id == UINT16_C(5774)
                || instruction->form_id == UINT16_C(5775)
                || instruction->form_id == UINT16_C(5776)
                || instruction->form_id == UINT16_C(5778)
                || instruction->form_id == UINT16_C(5791)
                || instruction->form_id == UINT16_C(5792)
                || instruction->form_id == UINT16_C(5793)
                || instruction->form_id == UINT16_C(5795))
            && (operand == &instruction->operand[0]
                || operand == &instruction->operand[1]))
        || (((instruction->form_id == UINT16_C(6074)
                    && instruction->name_id == CDISASM_ARM_NAME_SADDLV)
                || (instruction->form_id == UINT16_C(6082)
                    && instruction->name_id == CDISASM_ARM_NAME_UADDLV))
            && operand == &instruction->operand[0])
        || arm_is_scalar_advsimd_d_layout(instruction)
        || instruction->form_id == UINT16_C(5780)
        || instruction->form_id == UINT16_C(5783)
        || instruction->form_id == UINT16_C(5788)
        || instruction->form_id == UINT16_C(5802)
        || instruction->form_id == UINT16_C(5806)
        || instruction->form_id == UINT16_C(5819)
        || instruction->form_id == UINT16_C(5820)
        || instruction->form_id == UINT16_C(5821)
        || instruction->form_id == UINT16_C(5858)
        || instruction->form_id == UINT16_C(5861)
        || instruction->form_id == UINT16_C(5862)
        || instruction->form_id == UINT16_C(5869)
        || instruction->form_id == UINT16_C(5870)
        || instruction->form_id == UINT16_C(5875)
        || instruction->form_id == UINT16_C(5876)
        || instruction->form_id == UINT16_C(5771)
        || instruction->form_id == UINT16_C(5772)
        || ((instruction->form_id >= UINT16_C(5877)
                && instruction->form_id <= UINT16_C(5891))
            && (operand == &instruction->operand[0]
                || operand == &instruction->operand[1]))
        || arm_is_a64_fprcvt_scalar(instruction)
        || arm_is_a64_advsimd_sha_q_operand(instruction, operand)
        || arm_is_a64_advsimd_sha_scalar_operand(instruction, operand)
        || (arm_is_lrcpc3_simd_unscaled(instruction)
            && operand == &instruction->operand[0])
        || (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_APPLE_MUL53) != 0u) {
        return;
    }
    arm_writer_putc(writer, '.');
    if ((operand->flags & CDISASM_ARM_OPERAND_FLAG_HAS_LANE) != 0u) {
        if (instruction->form_id == UINT16_C(6252)
            || instruction->form_id == UINT16_C(6253)
            || instruction->form_id == UINT16_C(6257)
            || instruction->form_id == UINT16_C(6266)
            || instruction->form_id == UINT16_C(6274)) {
            arm_writer_putc(writer, '4');
        } else if (instruction->form_id == UINT16_C(6258)
            || instruction->form_id == UINT16_C(6259)
            || instruction->form_id == UINT16_C(6260)) {
            arm_writer_putc(writer, '2');
        }
        arm_writer_putc(writer,
            arm_vector_element_letter(
                CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand)));
        return;
    }
    arm_writer_decimal(
        writer, CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand));
    arm_writer_putc(writer,
        arm_vector_element_letter(
            CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand)));
}

static void arm_format_register(
    arm_text_writer *writer,
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand,
    size_t operand_index)
{
    if (arm_is_lrcpc3_simd_unscaled(instruction)
        && operand_index == 0u
        && operand->size == 16u) {
        arm_writer_putc(writer, 'q');
        arm_writer_decimal(
            writer, (uint64_t)(operand->reg - CDISASM_ARM_REG_V0));
    } else if (arm_is_a64_advsimd_sha_q_operand(instruction, operand)) {
        arm_writer_putc(writer, 'q');
        arm_writer_decimal(
            writer, (uint64_t)(operand->reg - CDISASM_ARM_REG_V0));
    } else if (instruction->name_id == CDISASM_ARM_NAME_MOV
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR) != 0u
        && operand->reg >= CDISASM_ARM_REG_V0
        && operand->reg <= CDISASM_ARM_REG_V31
        && operand->size == 16u) {
        arm_writer_putc(writer, 'q');
        arm_writer_decimal(
            writer, (uint64_t)(operand->reg - CDISASM_ARM_REG_V0));
    } else {
        arm_writer_puts(writer, arm_register_names[operand->reg]);
    }
    if (!(instruction->form_id == UINT16_C(4922)
            && instruction->name_id == CDISASM_ARM_NAME_LDR
            && operand_index == 0u)
        && instruction->form_id != UINT16_C(5860)
        && instruction->form_id != UINT16_C(5859)
        && instruction->form_id != UINT16_C(5871)
        && instruction->form_id != UINT16_C(5873)
        && instruction->form_id != UINT16_C(5872)
        && instruction->form_id != UINT16_C(5874)
        && !(((instruction->name_id == CDISASM_ARM_NAME_LUTI2
                && (instruction->form_id == UINT16_C(5902)
                    || instruction->form_id == UINT16_C(5903)))
            || (instruction->name_id == CDISASM_ARM_NAME_LUTI4
                && (instruction->form_id == UINT16_C(5900)
                    || instruction->form_id == UINT16_C(5901))))
            && operand_index == 2u)) {
        arm_format_vector_arrangement(writer, instruction, operand);
    }
    if ((operand->flags & CDISASM_ARM_OPERAND_FLAG_HAS_LANE) != 0u) {
        arm_writer_putc(writer, '[');
        arm_writer_decimal(writer, operand->imm);
        arm_writer_putc(writer, ']');
    }
    if (operand_index == 0u
        && (instruction->name_id == CDISASM_ARM_NAME_LDM
            || instruction->name_id == CDISASM_ARM_NAME_STM)
        && (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK) != 0u) {
        arm_writer_putc(writer, '!');
    }
    if ((instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_SIMD) == 0u
        && !(arm_is_sve_quadword_reduction_name(instruction->name_id)
            && operand == &instruction->operand[0])) {
        arm_format_modifier(writer, operand);
    }
    if ((operand->flags & CDISASM_ARM_OPERAND_FLAG_WRITEBACK) != 0u) {
        arm_writer_putc(writer, '!');
    }
}

static int arm_immediate_shift_is_displayed(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    return operand->shift_type != CDISASM_ARM_SHIFT_NONE
        && instruction->isa_id == CDISASM_ARM_ISA_A64;
}

static uint64_t arm_immediate_display_value(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    if (arm_immediate_shift_is_displayed(instruction, operand)
        && (operand->shift_type == CDISASM_ARM_SHIFT_LSL
            || operand->shift_type == CDISASM_ARM_SHIFT_MSL)) {
        return operand->imm >> operand->shift_amount;
    }
    return operand->imm;
}

#if USE_EXTRA_OPCODES
static void arm_format_sve_fp_modified_immediate(
    arm_text_writer *writer, uint32_t word)
{
    unsigned encoded = (word >> 5) & 255u;
    unsigned fraction_numerator = 16u + (encoded & 15u);
    int exponent = ((encoded >> 6) & 1u) != 0u ? -3 : 1;
    uint64_t scaled;
    uint64_t fraction;
    uint64_t divisor;
    unsigned digit;

    exponent += (int)((encoded >> 4) & 3u);
    scaled = (uint64_t)fraction_numerator * UINT64_C(100000000);
    if (exponent >= 0) {
        scaled = (scaled << (unsigned)exponent) / UINT64_C(16);
    } else {
        scaled /= UINT64_C(16) << (unsigned)(-exponent);
    }
    arm_writer_putc(writer, '#');
    if ((encoded & 128u) != 0u) {
        arm_writer_putc(writer, '-');
    }
    arm_writer_decimal(writer, scaled / UINT64_C(100000000));
    arm_writer_putc(writer, '.');
    fraction = scaled % UINT64_C(100000000);
    divisor = UINT64_C(10000000);
    for (digit = 0u; digit < 8u; ++digit) {
        arm_writer_putc(writer, (char)('0' + fraction / divisor));
        fraction %= divisor;
        divisor /= UINT64_C(10);
    }
}

static int arm_is_a64_dcps_form(
    const cdisasm_arm_instruction *instruction)
{
    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return 0;
    }
    switch (instruction->form_id) {
        case UINT16_C(4453):
            return instruction->name_id == CDISASM_ARM_NAME_DCPS1;
        case UINT16_C(4454):
            return instruction->name_id == CDISASM_ARM_NAME_DCPS2;
        case UINT16_C(4455):
            return instruction->name_id == CDISASM_ARM_NAME_DCPS3;
        default:
            return 0;
    }
}
#endif

static void arm_format_immediate(
    arm_text_writer *writer,
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand,
    size_t operand_index)
{
    uint64_t value = arm_immediate_display_value(instruction, operand);

#if USE_EXTRA_OPCODES
    if ((instruction->form_id == UINT16_C(5860)
            || instruction->form_id == UINT16_C(5859)
            || instruction->form_id == UINT16_C(5871)
            || instruction->form_id == UINT16_C(5873)
            || instruction->form_id == UINT16_C(5872)
            || instruction->form_id == UINT16_C(5874)
            || instruction->form_id == UINT16_C(6223)
            || instruction->form_id == UINT16_C(6236)
            || instruction->form_id == UINT16_C(6238)
            || instruction->form_id == UINT16_C(6224)
            || instruction->form_id == UINT16_C(6237)
            || instruction->form_id == UINT16_C(6239))
        && operand_index == 2u) {
        arm_writer_putc(writer, '#');
        arm_writer_decimal(writer, value);
        return;
    }
    if ((instruction->form_id == UINT16_C(2866)
            || instruction->form_id == UINT16_C(2867)
            || instruction->form_id == UINT16_C(2868)
            || instruction->form_id == UINT16_C(2869)
            || instruction->form_id == UINT16_C(2870)
            || instruction->form_id == UINT16_C(2871)
            || instruction->form_id == UINT16_C(2872)
            || instruction->form_id == UINT16_C(2873)
            || instruction->form_id == UINT16_C(2874))
        && operand_index == 2u) {
        arm_writer_putc(writer, '#');
        arm_writer_decimal(writer, value);
        return;
    }
    if (instruction->form_id == UINT16_C(3098)
        && instruction->name_id == CDISASM_ARM_NAME_FTMAD
        && operand_index == 3u) {
        arm_writer_putc(writer, '#');
        arm_writer_hex(writer, value);
        return;
    }
    if (((instruction->form_id >= UINT16_C(3204)
                && instruction->form_id <= UINT16_C(3207))
            || (instruction->form_id >= UINT16_C(3395)
                && instruction->form_id <= UINT16_C(3398))
            || (instruction->form_id >= UINT16_C(3416)
                && instruction->form_id <= UINT16_C(3419))
            || (instruction->form_id >= UINT16_C(3449)
                && instruction->form_id <= UINT16_C(3452))
            || (instruction->form_id >= UINT16_C(3216)
                && instruction->form_id <= UINT16_C(3219))
            || (instruction->form_id >= UINT16_C(3225)
                && instruction->form_id <= UINT16_C(3228))
            || (instruction->form_id >= UINT16_C(3229)
                && instruction->form_id <= UINT16_C(3232))
            || instruction->form_id == UINT16_C(4923)
            || instruction->form_id == UINT16_C(5544)
            || instruction->form_id == UINT16_C(5573))
        && (instruction->name_id == CDISASM_ARM_NAME_PRFM
            || (instruction->name_id >= CDISASM_ARM_NAME_PRFB
                && instruction->name_id <= CDISASM_ARM_NAME_PRFW))
        && operand_index == 0u && value < 32u) {
        static const char *const prfop_names[32] = {
            "pldl1keep", "pldl1strm", "pldl2keep", "pldl2strm",
            "pldl3keep", "pldl3strm", NULL, NULL,
            "plil1keep", "plil1strm", "plil2keep", "plil2strm",
            "plil3keep", "plil3strm", NULL, NULL,
            "pstl1keep", "pstl1strm", "pstl2keep", "pstl2strm",
            "pstl3keep", "pstl3strm", NULL, NULL,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
        };

        if (prfop_names[value] != NULL) {
            arm_writer_puts(writer, prfop_names[value]);
            return;
        }
    }
    if (instruction->form_id == UINT16_C(3907)
        && instruction->name_id == CDISASM_ARM_NAME_ZERO
        && operand_index == 0u) {
        unsigned mask = (unsigned)operand->imm;
        unsigned unit_mask;
        unsigned count;
        unsigned stride;
        unsigned n;
        char suffix;

        arm_writer_putc(writer, '{');
        if (mask == 255u) {
            arm_writer_puts(writer, "za");
        } else {
            if (mask == ((mask & 3u) * 85u)) {
                unit_mask = mask & 3u; count = 2u; stride = 1u; suffix = 'h';
            } else if ((mask & 15u) == (mask >> 4)) {
                unit_mask = mask & 15u; count = 4u; stride = 1u; suffix = 's';
            } else {
                unit_mask = mask; count = 8u; stride = 1u; suffix = 'd';
            }
            for (n = 0u; n < count; ++n) {
                if ((unit_mask & (1u << (n * stride))) != 0u) {
                    if (unit_mask & ((1u << (n * stride)) - 1u)) arm_writer_puts(writer, ", ");
                    arm_writer_puts(writer, "za"); arm_writer_decimal(writer, n);
                    arm_writer_putc(writer, '.'); arm_writer_putc(writer, suffix);
                }
            }
        }
        arm_writer_putc(writer, '}');
        return;
    }
    if (instruction->form_id >= UINT16_C(3098)
        && instruction->form_id <= UINT16_C(3105)
        && operand_index == 3u) {
        arm_writer_puts(writer,
            (instruction->raw_instruction & UINT32_C(0x20)) != 0u
                ? "#1.0" : "#0.5");
        return;
    }
    if (instruction->form_id == UINT16_C(5910)
        && instruction->name_id == CDISASM_ARM_NAME_EXT
        && operand_index == 3u) {
        arm_writer_putc(writer, '#');
        arm_writer_decimal(writer, value);
        return;
    }
    if (((instruction->form_id == UINT16_C(6048)
                && instruction->name_id == CDISASM_ARM_NAME_SHLL)
            || (arm_is_advsimd_shift_right_immediate_form(
                    instruction->form_id)
                && (instruction->name_id == CDISASM_ARM_NAME_SSHR
                    || instruction->name_id == CDISASM_ARM_NAME_USHR
                    || instruction->name_id == CDISASM_ARM_NAME_SSRA
                    || instruction->name_id == CDISASM_ARM_NAME_USRA
                    || instruction->name_id == CDISASM_ARM_NAME_SRSHR
                    || instruction->name_id == CDISASM_ARM_NAME_URSHR
                    || instruction->name_id == CDISASM_ARM_NAME_SRSRA
                    || instruction->name_id == CDISASM_ARM_NAME_URSRA
                    || instruction->name_id == CDISASM_ARM_NAME_SHL
                    || instruction->name_id == CDISASM_ARM_NAME_SRI
                    || instruction->name_id == CDISASM_ARM_NAME_SLI))
            || (arm_is_advsimd_shift_narrow_widen_form(
                    instruction->form_id)
                && (instruction->name_id == CDISASM_ARM_NAME_SHRN
                    || instruction->name_id == CDISASM_ARM_NAME_RSHRN
                    || instruction->name_id == CDISASM_ARM_NAME_SSHLL
                    || instruction->name_id == CDISASM_ARM_NAME_USHLL)))
        && operand_index == 2u) {
        arm_writer_putc(writer, '#');
        arm_writer_decimal(writer, value);
        return;
    }
    if (instruction->form_id >= UINT16_C(2639)
        && instruction->form_id <= UINT16_C(2641)
        && operand_index == 3u) {
        arm_writer_putc(writer, '#');
        arm_writer_decimal(writer, value);
        return;
    }
    if ((instruction->form_id == UINT16_C(3002)
            || instruction->form_id == UINT16_C(3003))
        && instruction->name_id == CDISASM_ARM_NAME_FCMLA
        && operand_index == 3u) {
        arm_writer_putc(writer, '#');
        arm_writer_decimal(writer, value);
        return;
    }
    if ((instruction->form_id == UINT16_C(5985)
            || instruction->form_id == UINT16_C(5986)
            || instruction->form_id == UINT16_C(6277))
        && (instruction->name_id == CDISASM_ARM_NAME_FCMLA
            || instruction->name_id == CDISASM_ARM_NAME_FCADD)
        && operand_index == 3u) {
        arm_writer_putc(writer, '#');
        arm_writer_decimal(writer, value);
        return;
    }
    if (instruction->form_id == UINT16_C(2632)
        && instruction->name_id == CDISASM_ARM_NAME_FMOV
        && operand_index == 1u) {
        arm_format_sve_fp_modified_immediate(
            writer, instruction->raw_instruction);
        return;
    }
    if ((instruction->form_id == UINT16_C(2559)
            || instruction->form_id == UINT16_C(2560))
        && operand_index == 1u && value < 32u) {
        static const char *const pattern_names[32] = {
            "pow2", "vl1", "vl2", "vl3", "vl4", "vl5", "vl6", "vl7",
            "vl8", "vl16", "vl32", "vl64", "vl128", "vl256",
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL,
            "mul4", "mul3", "all"
        };

        if (pattern_names[value] != NULL) {
            arm_writer_puts(writer, pattern_names[value]);
        } else {
            arm_writer_putc(writer, '#');
            arm_writer_decimal(writer, value);
        }
        return;
    }
    if (arm_is_sve_element_count_form(instruction)
        || arm_is_sve_saturating_count_form(instruction)) {
        static const char *const pattern_names[32] = {
            "pow2", "vl1", "vl2", "vl3", "vl4", "vl5", "vl6", "vl7",
            "vl8", "vl16", "vl32", "vl64", "vl128", "vl256",
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL,
            "mul4", "mul3", "all"
        };
        size_t pattern_index = arm_is_sve_saturating_count_form(instruction)
                && instruction->operand_count == 4u ? 2u : 1u;

        if (operand_index == pattern_index && value < 32u) {
            if (pattern_names[value] != NULL) {
                arm_writer_puts(writer, pattern_names[value]);
            } else {
                arm_writer_putc(writer, '#');
                arm_writer_decimal(writer, value);
            }
            return;
        }
        if (operand_index == pattern_index + 1u) {
            arm_writer_puts(writer, "mul #");
            arm_writer_decimal(writer, value);
            return;
        }
    }
    if (instruction->form_id == UINT16_C(2600)
        && instruction->name_id == CDISASM_ARM_NAME_CNTP
        && operand_index == 2u) {
        arm_writer_puts(writer, "vlx");
        arm_writer_decimal(writer, value);
        return;
    }
    if (instruction->form_id >= UINT16_C(2566)
        && instruction->form_id <= UINT16_C(2573)
        && arm_is_sve_while_comparison_name(instruction->name_id)
        && operand_index == 3u) {
        arm_writer_puts(writer, "vlx");
        arm_writer_decimal(writer, value);
        return;
    }
    if (arm_is_a64_dcps_form(instruction) && operand_index == 0u) {
        arm_writer_putc(writer, '#');
        arm_writer_decimal(writer, value);
        return;
    }
    if ((instruction->name_id == CDISASM_ARM_NAME_CMLT
            || instruction->name_id == CDISASM_ARM_NAME_CMLE)
        && operand_index == 2u && value == 0u) {
        arm_writer_puts(writer, "#0");
        return;
    }
    if ((instruction->name_id == CDISASM_ARM_NAME_FCMEQ
            || instruction->name_id == CDISASM_ARM_NAME_FCMNE
            || instruction->name_id == CDISASM_ARM_NAME_FCMGE
            || instruction->name_id == CDISASM_ARM_NAME_FCMGT
            || instruction->name_id == CDISASM_ARM_NAME_FCMLE
            || instruction->name_id == CDISASM_ARM_NAME_FCMLT)
        && operand_index == 3u && value == 0u) {
        arm_writer_puts(writer, "#0.0");
        return;
    }
    if (instruction->name_id == CDISASM_ARM_NAME_IT
        && operand_index == 0u && value < CDISASM_ARM_CONDITION_AL) {
        arm_writer_puts(writer, arm_condition_names[value]);
        return;
    }
    if (((instruction->name_id == CDISASM_ARM_NAME_FCSEL
                || instruction->name_id == CDISASM_ARM_NAME_CSEL
                || instruction->name_id == CDISASM_ARM_NAME_CSINC
                || instruction->name_id == CDISASM_ARM_NAME_CSINV
                || instruction->name_id == CDISASM_ARM_NAME_CSNEG)
            && operand_index == 3u
            && value <= CDISASM_ARM_CONDITION_NV)
        || ((instruction->name_id == CDISASM_ARM_NAME_CINC
                || instruction->name_id == CDISASM_ARM_NAME_CINV
                || instruction->name_id == CDISASM_ARM_NAME_CNEG)
            && operand_index == 2u
            && value <= CDISASM_ARM_CONDITION_NV)
        || ((instruction->name_id == CDISASM_ARM_NAME_CSET
                || instruction->name_id == CDISASM_ARM_NAME_CSETM)
            && operand_index == 1u
            && value <= CDISASM_ARM_CONDITION_NV)
        || ((instruction->name_id == CDISASM_ARM_NAME_CCMP
                || instruction->name_id == CDISASM_ARM_NAME_CCMN)
            && operand_index == 3u
            && value <= CDISASM_ARM_CONDITION_NV)) {
        arm_writer_puts(writer, arm_condition_names[value]);
        return;
    }
    if (instruction->name_id == CDISASM_ARM_NAME_DSB
        && instruction->form_id == UINT16_C(4497)
        && operand_index == 0u && value < 4u) {
        static const char *const nxs_options[4] = {
            "oshnxs", "nshnxs", "ishnxs", "synxs"
        };
        arm_writer_puts(writer, nxs_options[value]);
        return;
    }
    if ((instruction->name_id == CDISASM_ARM_NAME_DMB
            || instruction->name_id == CDISASM_ARM_NAME_DSB
            || instruction->name_id == CDISASM_ARM_NAME_ISB)
        && operand_index == 0u && value < 16u) {
        static const char *const barrier_options[16] = {
            NULL, "oshld", "oshst", "osh",
            NULL, "nshld", "nshst", "nsh",
            NULL, "ishld", "ishst", "ish",
            NULL, "ld", "st", "sy"
        };

        if (barrier_options[value] != NULL) {
            arm_writer_puts(writer, barrier_options[value]);
            return;
        }
    }
    if (instruction->name_id == CDISASM_ARM_NAME_BTI
        && operand_index == 0u && value >= 1u && value <= 3u) {
        static const char *const bti_options[] = { NULL, "c", "j", "jc" };

        arm_writer_puts(writer, bti_options[value]);
        return;
    }
    if ((instruction->name_id == CDISASM_ARM_NAME_SMSTART
            || instruction->name_id == CDISASM_ARM_NAME_SMSTOP)
        && operand_index == 0u) {
        if (value == CDISASM_ARM_SME_STATE_SM) {
            arm_writer_puts(writer, "sm");
            return;
        }
        if (value == CDISASM_ARM_SME_STATE_ZA) {
            arm_writer_puts(writer, "za");
            return;
        }
    }
#endif

    if (instruction->name_id == CDISASM_ARM_NAME_SDSB
        && operand_index == 0u && value <= CDISASM_ARM_APPLE_SDSB_SY) {
        static const char *const options[] = { "osh", "nsh", "ish", "sy" };

        arm_writer_puts(writer, options[value]);
        return;
    }
    if ((operand->flags & CDISASM_OPERAND_FLAG_PC_RELATIVE) != 0u) {
        arm_writer_hex(writer, value);
    } else {
        arm_writer_putc(writer, '#');
        if ((operand->flags & CDISASM_OPERAND_FLAG_SIGNED) != 0u) {
            arm_writer_signed_hex(writer, value);
        } else {
            arm_writer_hex(writer, value);
        }
    }
    if (arm_immediate_shift_is_displayed(instruction, operand)) {
        arm_format_modifier(writer, operand);
    }
}

static void arm_format_memory_offset(
    arm_text_writer *writer,
    const cdisasm_arm_operand *operand,
    int force_zero)
{
    if (operand->index_reg != CDISASM_ARM_REG_NONE) {
        if ((operand->flags & CDISASM_OPERAND_FLAG_SIGNED) != 0u) {
            arm_writer_putc(writer, '-');
        }
        arm_writer_puts(writer, arm_register_names[operand->index_reg]);
        arm_format_modifier(writer, operand);
        return;
    }
    if ((operand->flags & CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT) == 0u
        && !force_zero) {
        return;
    }
    arm_writer_putc(writer, '#');
    arm_writer_signed_hex(writer, operand->imm);
    if ((operand->flags & CDISASM_ARM_OPERAND_FLAG_VL_SCALED) != 0u) {
        arm_writer_puts(writer, ", mul vl");
    }
}

static void arm_format_memory(
    arm_text_writer *writer,
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    int post_index = (instruction->instruction_flags
        & CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX) != 0u;
    int has_offset = operand->index_reg != CDISASM_ARM_REG_NONE
        || (operand->flags & CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT) != 0u;
    int sve_s_arrangement = (instruction->form_id >= UINT16_C(3194)
            && instruction->form_id <= UINT16_C(3242))
        || (instruction->form_id >= UINT16_C(3505)
            && instruction->form_id <= UINT16_C(3507))
        || (instruction->form_id >= UINT16_C(3511)
            && instruction->form_id <= UINT16_C(3512))
        || (instruction->form_id >= UINT16_C(3524)
            && instruction->form_id <= UINT16_C(3526))
        || (instruction->form_id >= UINT16_C(3481)
            && instruction->form_id <= UINT16_C(3483))
        || (instruction->form_id == UINT16_C(2340) && operand->size == 4u);

    arm_writer_putc(writer, '[');
    arm_writer_puts(writer, arm_register_names[operand->base_reg]);
    if (operand->base_reg >= CDISASM_ARM_REG_Z0
        && operand->base_reg <= CDISASM_ARM_REG_Z31) {
        arm_writer_puts(writer,
            sve_s_arrangement ? ".s" : ".d");
    }
    if (!post_index && has_offset) {
        arm_writer_puts(writer, ", ");
        if (instruction->form_id >= UINT16_C(3243)
            && instruction->form_id <= UINT16_C(3258)
            && operand->index_reg == CDISASM_ARM_REG_NONE) {
            arm_writer_putc(writer, '#');
            arm_writer_decimal(writer, operand->imm);
        } else if (operand->index_reg >= CDISASM_ARM_REG_Z0
            && operand->index_reg <= CDISASM_ARM_REG_Z31) {
            arm_writer_puts(writer, arm_register_names[operand->index_reg]);
            arm_writer_puts(writer,
                sve_s_arrangement ? ".s" : ".d");
            arm_format_modifier(writer, operand);
        } else {
            arm_format_memory_offset(writer, operand, 0);
        }
    }
    arm_writer_putc(writer, ']');
    if (post_index) {
        arm_writer_puts(writer, ", ");
        arm_format_memory_offset(writer, operand, 1);
    } else if ((instruction->instruction_flags
        & (CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK))
        == (CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK)) {
        arm_writer_putc(writer, '!');
    } else if ((operand->flags
        & CDISASM_ARM_OPERAND_FLAG_WRITEBACK) != 0u) {
        arm_writer_putc(writer, '!');
    }
}

static void arm_format_register_list(
    arm_text_writer *writer,
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    unsigned reg;
    int emitted = 0;

    arm_writer_putc(writer, '{');
    for (reg = 0; reg < 16u; ++reg) {
        if ((operand->register_list & (UINT16_C(1) << reg)) == 0u) {
            continue;
        }
        if (emitted) {
            arm_writer_puts(writer, ", ");
        }
        arm_writer_puts(writer,
            arm_register_names[CDISASM_ARM_REG_R0 + reg]);
        emitted = 1;
    }
    arm_writer_putc(writer, '}');
    if ((instruction->instruction_flags
        & CDISASM_ARM_INSTRUCTION_FLAG_USER_REGISTERS) != 0u) {
        arm_writer_puts(writer, " ^");
    }
}

static void arm_format_register_pair(
    arm_text_writer *writer,
    const cdisasm_arm_operand *operand)
{
    arm_writer_puts(writer, arm_register_names[operand->reg]);
    arm_writer_puts(writer, ", ");
    arm_writer_puts(writer, arm_register_names[operand->index_reg]);
}

#if USE_EXTRA_OPCODES
static void arm_format_scalable_suffix(
    arm_text_writer *writer,
    uint8_t element_size)
{
    arm_writer_putc(writer, '.');
    arm_writer_putc(writer, arm_vector_element_letter(element_size));
}

static void arm_format_scalable_register(
    arm_text_writer *writer,
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    arm_writer_puts(writer, arm_register_names[operand->reg]);
    if ((operand->flags & CDISASM_ARM_OPERAND_FLAG_HAS_LANE) != 0u) {
        if (instruction->name_id == CDISASM_ARM_NAME_DUPQ
            || instruction->name_id == CDISASM_ARM_NAME_MOV
            || (instruction->form_id >= UINT16_C(2908)
                && instruction->form_id <= UINT16_C(2915)
                && (instruction->name_id == CDISASM_ARM_NAME_AESD
                    || instruction->name_id == CDISASM_ARM_NAME_AESDIMC
                    || instruction->name_id == CDISASM_ARM_NAME_AESE
                    || instruction->name_id == CDISASM_ARM_NAME_AESEMC))
            || (instruction->form_id >= UINT16_C(2722)
                && instruction->form_id <= UINT16_C(2727)
                && (instruction->name_id == CDISASM_ARM_NAME_MLA
                    || instruction->name_id == CDISASM_ARM_NAME_MLS))
            || (instruction->form_id >= UINT16_C(2728)
                && instruction->form_id <= UINT16_C(2733)
                && (instruction->name_id == CDISASM_ARM_NAME_SQRDMLAH
                    || instruction->name_id
                        == CDISASM_ARM_NAME_SQRDMLSH))
            || (instruction->form_id == UINT16_C(2734)
                && instruction->name_id == CDISASM_ARM_NAME_USDOT)
            || (instruction->form_id == UINT16_C(2735)
                && instruction->name_id == CDISASM_ARM_NAME_SUDOT)
            || ((instruction->form_id == UINT16_C(3010)
                    && instruction->name_id == CDISASM_ARM_NAME_FDOT)
                || (instruction->form_id == UINT16_C(3011)
                    && instruction->name_id == CDISASM_ARM_NAME_BFDOT))
            || ((instruction->form_id == UINT16_C(3012)
                    || instruction->form_id == UINT16_C(3013))
                && instruction->name_id == CDISASM_ARM_NAME_FDOT)
            || (instruction->form_id >= UINT16_C(3014)
                && instruction->form_id <= UINT16_C(3021))
            || instruction->form_id == UINT16_C(3022)
            || instruction->form_id == UINT16_C(3023)
            || (instruction->form_id >= UINT16_C(3036)
                && instruction->form_id <= UINT16_C(3041))
            || (instruction->form_id >= UINT16_C(3042)
                && instruction->form_id <= UINT16_C(3045))
            || instruction->form_id == UINT16_C(3046)
            || instruction->form_id == UINT16_C(3047)
            || (instruction->form_id >= UINT16_C(3048)
                && instruction->form_id <= UINT16_C(3053))
            || ((instruction->form_id == UINT16_C(2995)
                    && instruction->name_id == CDISASM_ARM_NAME_BFMLA)
                || (instruction->form_id == UINT16_C(2999)
                    && instruction->name_id == CDISASM_ARM_NAME_BFMLS))
            || ((instruction->form_id == UINT16_C(3002)
                    || instruction->form_id == UINT16_C(3003))
                && instruction->name_id == CDISASM_ARM_NAME_FCMLA)
            || instruction->form_id == UINT16_C(3954)
            || (instruction->form_id >= UINT16_C(3955)
                && instruction->form_id <= UINT16_C(3958))
            || instruction->form_id == UINT16_C(3950)
            || instruction->form_id == UINT16_C(3951)
            || instruction->form_id == UINT16_C(3952)
            || instruction->form_id == UINT16_C(3953)
            || (instruction->form_id >= UINT16_C(3989)
                && instruction->form_id <= UINT16_C(3992))
            || (instruction->form_id >= UINT16_C(4037)
                && instruction->form_id <= UINT16_C(4040))
            || instruction->form_id == UINT16_C(3993)
            || instruction->form_id == UINT16_C(4041)
            || (instruction->form_id >= UINT16_C(4064)
                && instruction->form_id <= UINT16_C(4068))
            || (instruction->form_id >= UINT16_C(4073)
                && instruction->form_id <= UINT16_C(4076))
            || (instruction->form_id >= UINT16_C(4107)
                && instruction->form_id <= UINT16_C(4111))
            || instruction->form_id == UINT16_C(4116)
            || (instruction->form_id >= UINT16_C(3965)
                && instruction->form_id <= UINT16_C(3968))
            || (instruction->form_id >= UINT16_C(4013)
                && instruction->form_id <= UINT16_C(4016))
            || (instruction->form_id >= UINT16_C(4000)
                && instruction->form_id <= UINT16_C(4003))
            || (instruction->form_id >= UINT16_C(3996)
                && instruction->form_id <= UINT16_C(3999))
            || instruction->form_id == UINT16_C(4042)
            || instruction->form_id == UINT16_C(4043)
            || instruction->form_id == UINT16_C(4044)
            || instruction->form_id == UINT16_C(4045)
            || instruction->form_id == UINT16_C(4046)
            || instruction->form_id == UINT16_C(4047)
            || instruction->form_id == UINT16_C(3972)
            || instruction->form_id == UINT16_C(3980)
            || instruction->form_id == UINT16_C(4020)
            || instruction->form_id == UINT16_C(4028)
            || instruction->form_id == UINT16_C(3978)
            || instruction->form_id == UINT16_C(3983)
            || instruction->form_id == UINT16_C(4026)
            || instruction->form_id == UINT16_C(4032)
            || instruction->form_id == UINT16_C(3969)
            || (instruction->form_id >= UINT16_C(3973)
                && instruction->form_id <= UINT16_C(3977))
            || instruction->form_id == UINT16_C(3979)
            || instruction->form_id == UINT16_C(3981)
            || instruction->form_id == UINT16_C(3982)
            || instruction->form_id == UINT16_C(4018)
            || instruction->form_id == UINT16_C(4019)
            || (instruction->form_id >= UINT16_C(4022)
                && instruction->form_id <= UINT16_C(4025))
            || instruction->form_id == UINT16_C(4027)
            || instruction->form_id == UINT16_C(4030)
            || instruction->form_id == UINT16_C(4031)
            || instruction->form_id == UINT16_C(4004)
            || instruction->form_id == UINT16_C(4017)
            || (instruction->form_id >= UINT16_C(6500)
                && instruction->form_id <= UINT16_C(6504))
            || (instruction->form_id >= UINT16_C(4048)
                && instruction->form_id <= UINT16_C(4051))) {
            arm_format_scalable_suffix(
                writer, CDISASM_ARM_SCALABLE_ELEMENT_SIZE(operand));
        }
        arm_writer_putc(writer, '[');
        arm_writer_decimal(writer, operand->imm);
        arm_writer_putc(writer, ']');
    } else if (CDISASM_ARM_SCALABLE_ELEMENT_SIZE(operand) != 0u
        && !(instruction->name_id == CDISASM_ARM_NAME_PMOV
            && instruction->form_id >= UINT16_C(2448)
            && instruction->form_id <= UINT16_C(2455))
        && !(instruction->name_id == CDISASM_ARM_NAME_MOVT
            && instruction->form_id == UINT16_C(3919))) {
        arm_format_scalable_suffix(
            writer, CDISASM_ARM_SCALABLE_ELEMENT_SIZE(operand));
    }
}

static void arm_format_predicate(
    arm_text_writer *writer,
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    arm_writer_puts(writer, arm_register_names[operand->reg]);
    if (instruction->form_id == UINT16_C(2565)
        && instruction->name_id == CDISASM_ARM_NAME_PSEL
        && instruction->operand_count == 3u
        && operand == &instruction->operand[2]) {
        arm_format_scalable_suffix(
            writer, CDISASM_ARM_SCALABLE_ELEMENT_SIZE(operand));
        arm_writer_putc(writer, '[');
        arm_writer_puts(writer, arm_register_names[operand->base_reg]);
        arm_writer_puts(writer, ", ");
        arm_writer_decimal(writer, operand->imm);
        arm_writer_putc(writer, ']');
    } else if (operand->flags == CDISASM_ARM_OPERAND_FLAG_HAS_LANE) {
        arm_writer_putc(writer, '[');
        arm_writer_decimal(writer, operand->imm);
        arm_writer_putc(writer, ']');
    } else if (operand->flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE) {
        arm_writer_puts(writer, "/m");
    } else if (operand->flags == CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO) {
        arm_writer_puts(writer, "/z");
    } else if (operand->flags
        == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED
        && instruction->form_id != UINT16_C(4215)
        && instruction->form_id != UINT16_C(4216)) {
        arm_format_scalable_suffix(
            writer, CDISASM_ARM_SCALABLE_ELEMENT_SIZE(operand));
    } else if (instruction->name_id == CDISASM_ARM_NAME_PTRUE
        || instruction->name_id == CDISASM_ARM_NAME_WHILELO) {
        arm_format_scalable_suffix(
            writer, CDISASM_ARM_SCALABLE_ELEMENT_SIZE(operand));
    }
}

static void arm_format_scalable_list(
    arm_text_writer *writer,
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand,
    size_t operand_index)
{
    unsigned first = (unsigned)(operand->reg - CDISASM_ARM_REG_Z0);
    unsigned count = CDISASM_ARM_SCALABLE_LIST_COUNT(operand);
    unsigned stride = CDISASM_ARM_SCALABLE_LIST_STRIDE(operand);
    unsigned index;

    arm_writer_putc(writer, '{');
    for (index = 0u; index < count; ++index) {
        cdisasm_arm_reg_id reg = (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_Z0 + ((first + index * stride) & 31u));

        if (index != 0u) {
            arm_writer_puts(writer, ", ");
        }
        arm_writer_puts(writer, arm_register_names[reg]);
        if (!((instruction->form_id == UINT16_C(3927)
                    || instruction->form_id == UINT16_C(3937))
                && operand_index == 2u)) {
            arm_format_scalable_suffix(
                writer, CDISASM_ARM_SCALABLE_ELEMENT_SIZE(operand));
        }
    }
    arm_writer_putc(writer, '}');
}

static void arm_format_vector_list(
    arm_text_writer *writer,
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand,
    size_t operand_index)
{
    int a32_registers = operand->reg >= CDISASM_ARM_REG_D0
        && operand->reg <= CDISASM_ARM_REG_D31;
    unsigned first = (unsigned)(operand->reg
        - (a32_registers ? CDISASM_ARM_REG_D0 : CDISASM_ARM_REG_V0));
    cdisasm_arm_reg_id register_base = a32_registers
        ? CDISASM_ARM_REG_D0 : CDISASM_ARM_REG_V0;
    unsigned index;

    arm_writer_putc(writer, '{');
    for (index = 0u; index < operand->register_list; ++index) {
        cdisasm_arm_operand member = *operand;

        if (index != 0u) {
            arm_writer_puts(writer, ", ");
        }
        member.type = CDISASM_OPERAND_REGISTER;
        member.reg = (cdisasm_arm_reg_id)(
            register_base + ((first + index) & 31u));
        member.register_list = 0u;
        if ((operand->flags & CDISASM_ARM_OPERAND_FLAG_HAS_LANE) != 0u) {
            arm_writer_puts(writer, arm_register_names[member.reg]);
            if (a32_registers) {
                arm_writer_putc(writer, '[');
                arm_writer_decimal(writer, operand->imm);
                arm_writer_putc(writer, ']');
            } else {
                arm_format_vector_arrangement(writer, instruction, &member);
            }
        } else {
            arm_format_register(writer, instruction, &member, operand_index);
        }
    }
    arm_writer_putc(writer, '}');
    if (!a32_registers
        && (operand->flags & CDISASM_ARM_OPERAND_FLAG_HAS_LANE) != 0u) {
        arm_writer_putc(writer, '[');
        arm_writer_decimal(writer, operand->imm);
        arm_writer_putc(writer, ']');
    }
}

static void arm_format_tile(
    arm_text_writer *writer,
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    int multi_mova = arm_is_sme2_multi_mova_form(instruction->form_id)
        || instruction->form_id == UINT16_C(3908)
        || instruction->form_id == UINT16_C(3909);
    int movaz = arm_is_sme2p1_movaz_form(instruction->form_id);

    if (instruction->form_id >= UINT16_C(6500)
            && instruction->form_id <= UINT16_C(6504)) {
        arm_writer_puts(writer,
            instruction->form_id == UINT16_C(6504) ? "za.h[" : "za.s[");
        arm_writer_puts(writer, arm_register_names[operand->base_reg]);
        arm_writer_puts(writer, ", ");
        arm_writer_decimal(writer, operand->imm);
        arm_writer_puts(writer, operand->register_list == 4u
            ? ", vgx4]" : ", vgx2]");
        return;
    }

    if (instruction->name_id == CDISASM_ARM_NAME_MOVT
        && instruction->form_id >= UINT16_C(3917)
        && instruction->form_id <= UINT16_C(3919)) {
        arm_writer_puts(writer, "zt0");
        if (instruction->form_id != UINT16_C(3919) || operand->imm != 0u) {
            arm_writer_putc(writer, '[');
            arm_writer_decimal(writer, operand->imm);
            if (instruction->form_id == UINT16_C(3919)) {
                arm_writer_puts(writer, ", mul vl");
            }
            arm_writer_putc(writer, ']');
        }
        return;
    }
    if (instruction->name_id == CDISASM_ARM_NAME_ZERO
        && instruction->form_id >= UINT16_C(3910)
        && instruction->form_id <= UINT16_C(3915)) {
        unsigned range = operand->register_list & 255u;
        unsigned vgx = operand->register_list >> 8;
        arm_writer_puts(writer, "za.d[");
        arm_writer_puts(writer, arm_register_names[operand->base_reg]);
        arm_writer_puts(writer, ", "); arm_writer_decimal(writer, operand->imm);
        arm_writer_putc(writer, ':'); arm_writer_decimal(writer, operand->imm + range - 1u);
        if (vgx != 0u) { arm_writer_puts(writer, ", vgx"); arm_writer_decimal(writer, vgx); }
        arm_writer_putc(writer, ']'); return;
    }

    if (instruction->form_id == UINT16_C(3954)) {
        arm_writer_puts(writer, "za.h[");
        arm_writer_puts(writer, arm_register_names[operand->base_reg]);
        arm_writer_puts(writer, ", "); arm_writer_decimal(writer, operand->imm);
        arm_writer_putc(writer, ':'); arm_writer_decimal(writer, operand->imm + 1u);
        arm_writer_putc(writer, ']'); return;
    }

    if (instruction->form_id == UINT16_C(3950)
        || instruction->form_id == UINT16_C(3951)
        || instruction->form_id == UINT16_C(3952)
        || instruction->form_id == UINT16_C(3953)
        || (instruction->form_id >= UINT16_C(3955)
            && instruction->form_id <= UINT16_C(3958))
        || (instruction->form_id >= UINT16_C(4077)
            && instruction->form_id <= UINT16_C(4080))) {
        arm_writer_puts(writer, "za.s[");
        arm_writer_puts(writer, arm_register_names[operand->base_reg]);
        arm_writer_puts(writer, ", "); arm_writer_decimal(writer, operand->imm);
        arm_writer_putc(writer, ':'); arm_writer_decimal(writer, operand->imm + 1u);
        arm_writer_putc(writer, ']'); return;
    }

    if ((instruction->form_id >= UINT16_C(3989)
            && instruction->form_id <= UINT16_C(3992))
        || (instruction->form_id >= UINT16_C(4037)
            && instruction->form_id <= UINT16_C(4040))
        || (instruction->form_id >= UINT16_C(4000)
            && instruction->form_id <= UINT16_C(4003))
        || (instruction->form_id >= UINT16_C(4048)
            && instruction->form_id <= UINT16_C(4051))
        || (instruction->form_id >= UINT16_C(4186)
            && instruction->form_id <= UINT16_C(4189))
        || (instruction->form_id >= UINT16_C(4146)
            && instruction->form_id <= UINT16_C(4149))
        || (instruction->form_id >= UINT16_C(4069)
            && instruction->form_id <= UINT16_C(4072))
        || (instruction->form_id >= UINT16_C(4112)
            && instruction->form_id <= UINT16_C(4115))) {
        arm_writer_puts(writer, "za.s[");
        arm_writer_puts(writer, arm_register_names[operand->base_reg]);
        arm_writer_puts(writer, ", "); arm_writer_decimal(writer, operand->imm);
        arm_writer_putc(writer, ':'); arm_writer_decimal(writer, operand->imm + 1u);
        arm_writer_puts(writer, operand->register_list == 4u
            ? ", vgx4]" : ", vgx2]"); return;
    }

    if ((instruction->form_id >= UINT16_C(3996)
            && instruction->form_id <= UINT16_C(3999))
        || instruction->form_id == UINT16_C(4042)
        || instruction->form_id == UINT16_C(4043)
        || instruction->form_id == UINT16_C(4044)
        || instruction->form_id == UINT16_C(4045)
        || instruction->form_id == UINT16_C(4046)
        || instruction->form_id == UINT16_C(4047)) {
        arm_writer_puts(writer, "za.d[");
        arm_writer_puts(writer, arm_register_names[operand->base_reg]);
        arm_writer_puts(writer, ", "); arm_writer_decimal(writer, operand->imm);
        arm_writer_puts(writer, operand->register_list == 4u
            ? ", vgx4]" : ", vgx2]"); return;
    }

    if (instruction->form_id == UINT16_C(3972)
        || instruction->form_id == UINT16_C(3980)
        || instruction->form_id == UINT16_C(4020)
        || instruction->form_id == UINT16_C(4028)
        || instruction->form_id == UINT16_C(3978)
        || instruction->form_id == UINT16_C(3983)
        || instruction->form_id == UINT16_C(4026)
        || instruction->form_id == UINT16_C(4032)) {
        arm_writer_puts(writer, "za.s[");
        arm_writer_puts(writer, arm_register_names[operand->base_reg]);
        arm_writer_puts(writer, ", "); arm_writer_decimal(writer, operand->imm);
        arm_writer_puts(writer, operand->register_list == 4u
            ? ", vgx4]" : ", vgx2]"); return;
    }

    if (instruction->form_id == UINT16_C(3969)
        || (instruction->form_id >= UINT16_C(3973)
            && instruction->form_id <= UINT16_C(3977))
        || instruction->form_id == UINT16_C(3979)
        || instruction->form_id == UINT16_C(3981)
        || instruction->form_id == UINT16_C(3982)) {
        arm_writer_puts(writer, "za.s[");
        arm_writer_puts(writer, arm_register_names[operand->base_reg]);
        arm_writer_puts(writer, ", "); arm_writer_decimal(writer, operand->imm);
        arm_writer_puts(writer, ", vgx2]"); return;
    }

    if (instruction->form_id == UINT16_C(4018)
        || instruction->form_id == UINT16_C(4019)
        || (instruction->form_id >= UINT16_C(4022)
            && instruction->form_id <= UINT16_C(4025))
        || instruction->form_id == UINT16_C(4027)
        || instruction->form_id == UINT16_C(4030)
        || instruction->form_id == UINT16_C(4031)) {
        arm_writer_puts(writer, "za.s[");
        arm_writer_puts(writer, arm_register_names[operand->base_reg]);
        arm_writer_puts(writer, ", "); arm_writer_decimal(writer, operand->imm);
        arm_writer_puts(writer, ", vgx4]"); return;
    }

    if ((instruction->form_id >= UINT16_C(4141)
            && instruction->form_id <= UINT16_C(4145))
        || (instruction->form_id >= UINT16_C(4181)
            && instruction->form_id <= UINT16_C(4185))) {
        arm_writer_puts(writer, operand->extend_type == 2u ? "za.h[" : "za.s[");
        arm_writer_puts(writer, arm_register_names[operand->base_reg]);
        arm_writer_puts(writer, ", "); arm_writer_decimal(writer, operand->imm);
        arm_writer_putc(writer, ':'); arm_writer_decimal(writer, operand->imm + 1u);
        arm_writer_puts(writer, operand->register_list == 4u
            ? ", vgx4]" : ", vgx2]"); return;
    }

    if (((instruction->form_id >= UINT16_C(4064)
            && instruction->form_id <= UINT16_C(4068))
            && instruction->form_id != UINT16_C(4066))
        || (instruction->form_id >= UINT16_C(4073)
            && instruction->form_id <= UINT16_C(4076))
        || ((instruction->form_id >= UINT16_C(4107)
            && instruction->form_id <= UINT16_C(4111))
            && instruction->form_id != UINT16_C(4109))) {
        arm_writer_puts(writer, "za.s[");
        arm_writer_puts(writer, arm_register_names[operand->base_reg]);
        arm_writer_puts(writer, ", "); arm_writer_decimal(writer, operand->imm);
        arm_writer_putc(writer, ':'); arm_writer_decimal(writer, operand->imm + 1u);
        if (instruction->form_id < UINT16_C(4073)
            || instruction->form_id > UINT16_C(4076)) {
            arm_writer_puts(writer, operand->register_list == 4u
                ? ", vgx4" : ", vgx2");
        }
        arm_writer_putc(writer, ']'); return;
    }

    if (instruction->form_id == UINT16_C(4066)
        || instruction->form_id == UINT16_C(4109)
        || instruction->form_id == UINT16_C(4116)) {
        arm_writer_puts(writer, "za.h[");
        arm_writer_puts(writer, arm_register_names[operand->base_reg]);
        arm_writer_puts(writer, ", "); arm_writer_decimal(writer, operand->imm);
        arm_writer_putc(writer, ':'); arm_writer_decimal(writer, operand->imm + 1u);
        if (instruction->form_id != UINT16_C(4116)) {
            arm_writer_puts(writer, operand->register_list == 4u
                ? ", vgx4" : ", vgx2");
        }
        arm_writer_putc(writer, ']'); return;
    }

    if ((instruction->form_id >= UINT16_C(4158)
            && instruction->form_id <= UINT16_C(4162))
        || (instruction->form_id >= UINT16_C(4198)
            && instruction->form_id <= UINT16_C(4202))
        || instruction->form_id == UINT16_C(4163)
        || instruction->form_id == UINT16_C(4164)
        || instruction->form_id == UINT16_C(4203)
        || instruction->form_id == UINT16_C(4204)
        || instruction->form_id == UINT16_C(4165)
        || instruction->form_id == UINT16_C(4166)
        || instruction->form_id == UINT16_C(4205)
        || instruction->form_id == UINT16_C(4206)
        || (instruction->form_id >= UINT16_C(4167)
            && instruction->form_id <= UINT16_C(4174))
        || (instruction->form_id >= UINT16_C(4207)
            && instruction->form_id <= UINT16_C(4214))
        || (instruction->form_id >= UINT16_C(4081)
            && instruction->form_id <= UINT16_C(4084))
        || (instruction->form_id >= UINT16_C(4117)
            && instruction->form_id <= UINT16_C(4120))
        || (instruction->form_id >= UINT16_C(4150)
            && instruction->form_id <= UINT16_C(4153))
        || (instruction->form_id >= UINT16_C(4190)
            && instruction->form_id <= UINT16_C(4193))
        || (instruction->form_id >= UINT16_C(4085)
            && instruction->form_id <= UINT16_C(4090))
        || (instruction->form_id >= UINT16_C(4121)
            && instruction->form_id <= UINT16_C(4126))
        || (instruction->form_id >= UINT16_C(4091)
            && instruction->form_id <= UINT16_C(4098))
        || (instruction->form_id >= UINT16_C(4127)
            && instruction->form_id <= UINT16_C(4134))) {
        arm_writer_puts(writer, operand->extend_type == 8u ? "za.d["
            : operand->extend_type == 2u ? "za.h[" : "za.s[");
        arm_writer_puts(writer, arm_register_names[operand->base_reg]);
        arm_writer_puts(writer, ", "); arm_writer_decimal(writer, operand->imm);
        arm_writer_puts(writer, operand->register_list == 4u
            ? ", vgx4]" : ", vgx2]"); return;
    }

    if (instruction->form_id == UINT16_C(3993)
        || instruction->form_id == UINT16_C(4041)) {
        arm_writer_puts(writer, "za.h[");
        arm_writer_puts(writer, arm_register_names[operand->base_reg]);
        arm_writer_puts(writer, ", "); arm_writer_decimal(writer, operand->imm);
        arm_writer_putc(writer, ':'); arm_writer_decimal(writer, operand->imm + 1u);
        arm_writer_puts(writer, operand->register_list == 4u
            ? ", vgx4]" : ", vgx2]"); return;
    }

    if ((instruction->form_id >= UINT16_C(3965)
            && instruction->form_id <= UINT16_C(3968))
        || (instruction->form_id >= UINT16_C(4013)
            && instruction->form_id <= UINT16_C(4016))
        || (instruction->form_id >= UINT16_C(4154)
            && instruction->form_id <= UINT16_C(4157))
        || (instruction->form_id >= UINT16_C(4194)
            && instruction->form_id <= UINT16_C(4197))
        || instruction->form_id == UINT16_C(4004)
        || instruction->form_id == UINT16_C(4017)
        || instruction->form_id == UINT16_C(3993)
        || instruction->form_id == UINT16_C(4041)) {
        arm_writer_puts(writer, "za.h[");
        arm_writer_puts(writer, arm_register_names[operand->base_reg]);
        arm_writer_puts(writer, ", "); arm_writer_decimal(writer, operand->imm);
        arm_writer_puts(writer, operand->register_list == 4u
            ? ", vgx4]" : ", vgx2]"); return;
    }

    if (instruction->name_id == CDISASM_ARM_NAME_ZERO
        && operand->reg == CDISASM_ARM_REG_ZT0) {
        arm_writer_puts(writer, "{zt0}");
        return;
    }

    if ((multi_mova || movaz)
        && operand->reg == CDISASM_ARM_REG_ZA
        && operand->base_reg >= CDISASM_ARM_REG_W8
        && operand->base_reg <= CDISASM_ARM_REG_W11
        && (operand->register_list == 2u
            || operand->register_list == 4u)) {
        arm_writer_puts(writer, "za.d[");
        arm_writer_puts(writer, arm_register_names[operand->base_reg]);
        arm_writer_puts(writer, ", ");
        arm_writer_decimal(writer, operand->imm);
        arm_writer_puts(writer, ", vgx");
        arm_writer_decimal(writer, operand->register_list);
        arm_writer_putc(writer, ']');
        return;
    }
    if (operand->base_reg != CDISASM_ARM_REG_NONE
        && operand->reg >= CDISASM_ARM_REG_ZAB0
        && operand->reg <= CDISASM_ARM_REG_ZAQ15) {
        cdisasm_arm_reg_id first;

        if (operand->reg == CDISASM_ARM_REG_ZAB0) {
            first = CDISASM_ARM_REG_ZAB0;
        } else if (operand->reg <= CDISASM_ARM_REG_ZAH1) {
            first = CDISASM_ARM_REG_ZAH0;
        } else if (operand->reg <= CDISASM_ARM_REG_ZAS3) {
            first = CDISASM_ARM_REG_ZAS0;
        } else if (operand->reg <= CDISASM_ARM_REG_ZAD7) {
            first = CDISASM_ARM_REG_ZAD0;
        } else {
            first = CDISASM_ARM_REG_ZAQ0;
        }
        int brace = !arm_is_predicated_mova_form(instruction->form_id)
            && !multi_mova && !movaz;

        if (brace) {
            arm_writer_putc(writer, '{');
        }
        arm_writer_puts(writer, "za");
        arm_writer_decimal(writer, (uint64_t)(operand->reg - first));
        arm_writer_putc(writer,
            (operand->flags & CDISASM_ARM_OPERAND_FLAG_TILE_VERTICAL) != 0u
                ? 'v' : 'h');
        arm_format_scalable_suffix(
            writer, CDISASM_ARM_SCALABLE_ELEMENT_SIZE(operand));
        arm_writer_putc(writer, '[');
        arm_writer_puts(writer, arm_register_names[operand->base_reg]);
        arm_writer_puts(writer, ", ");
        arm_writer_decimal(writer, operand->imm);
        if (multi_mova || (movaz && operand->register_list > 1u)) {
            arm_writer_putc(writer, ':');
            arm_writer_decimal(
                writer, operand->imm + operand->register_list - 1u);
        }
        arm_writer_putc(writer, ']');
        if (brace) {
            arm_writer_putc(writer, '}');
        }
        return;
    }
    arm_writer_puts(writer, arm_register_names[operand->reg]);
    if (operand->base_reg != CDISASM_ARM_REG_NONE) {
        arm_writer_putc(writer, '[');
        arm_writer_puts(writer, arm_register_names[operand->base_reg]);
        arm_writer_puts(writer, ", ");
        arm_writer_decimal(writer, operand->imm);
        arm_writer_putc(writer, ']');
    }
}

static void arm_format_pair_base(
    arm_text_writer *writer,
    const cdisasm_arm_operand *operand)
{
    arm_writer_puts(writer, arm_register_names[operand->reg]);
}

static void arm_format_predicate_pair(
    arm_text_writer *writer,
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    if (((instruction->form_id >= UINT16_C(2574)
             && instruction->form_id <= UINT16_C(2581))
            || (instruction->form_id == UINT16_C(2583)
                && instruction->name_id == CDISASM_ARM_NAME_PEXT))
        && operand->flags == CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED) {
        arm_writer_putc(writer, '{');
        arm_writer_puts(writer, arm_register_names[operand->reg]);
        arm_format_scalable_suffix(
            writer, CDISASM_ARM_SCALABLE_ELEMENT_SIZE(operand));
        arm_writer_puts(writer, ", ");
        arm_writer_puts(writer, arm_register_names[operand->index_reg]);
        arm_format_scalable_suffix(
            writer, CDISASM_ARM_SCALABLE_ELEMENT_SIZE(operand));
        arm_writer_putc(writer, '}');
        return;
    }
    arm_writer_puts(writer, arm_register_names[operand->reg]);
    arm_writer_puts(writer, "/m, ");
    arm_writer_puts(writer, arm_register_names[operand->index_reg]);
    arm_writer_puts(writer, "/m");
}

static void arm_format_register_block(
    arm_text_writer *writer,
    const cdisasm_arm_operand *operand)
{
    arm_writer_puts(writer, arm_register_names[operand->reg]);
}

static void arm_format_system_register(
    arm_text_writer *writer,
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand)
{
    uint64_t encoding = operand->imm;

    if (encoding == 0u
        && (instruction->name_id == CDISASM_ARM_NAME_VMRS
            || instruction->name_id == CDISASM_ARM_NAME_VMSR)) {
        arm_writer_puts(writer, "fpscr");
        return;
    }
    if ((instruction->isa_id == CDISASM_ARM_ISA_A32
            || instruction->isa_id == CDISASM_ARM_ISA_T32)
        && (instruction->name_id == CDISASM_ARM_NAME_MRS
            || instruction->name_id == CDISASM_ARM_NAME_MSR)) {
        static const char field_names[4] = { 'c', 'x', 's', 'f' };
        unsigned bit;

        arm_writer_puts(writer,
            (encoding & UINT64_C(0x10)) != 0u ? "spsr" : "cpsr");
        if (instruction->name_id == CDISASM_ARM_NAME_MSR) {
            arm_writer_putc(writer, '_');
            for (bit = 4u; bit != 0u; --bit) {
                if ((encoding & (UINT64_C(1) << (bit - 1u))) != 0u) {
                    arm_writer_putc(writer, field_names[bit - 1u]);
                }
            }
        }
        return;
    }

    arm_writer_putc(writer, 's');
    arm_writer_decimal(writer, (encoding >> 14) & UINT64_C(3));
    arm_writer_putc(writer, '_');
    arm_writer_decimal(writer, (encoding >> 11) & UINT64_C(7));
    arm_writer_puts(writer, "_c");
    arm_writer_decimal(writer, (encoding >> 7) & UINT64_C(15));
    arm_writer_puts(writer, "_c");
    arm_writer_decimal(writer, (encoding >> 3) & UINT64_C(15));
    arm_writer_putc(writer, '_');
    arm_writer_decimal(writer, encoding & UINT64_C(7));
}

static void arm_format_system_operation(
    arm_text_writer *writer,
    const cdisasm_arm_operand *operand)
{
    uint64_t encoding = operand->imm;

    arm_writer_putc(writer, '#');
    arm_writer_decimal(writer, (encoding >> 11) & UINT64_C(7));
    arm_writer_puts(writer, ", c");
    arm_writer_decimal(writer, (encoding >> 7) & UINT64_C(15));
    arm_writer_puts(writer, ", c");
    arm_writer_decimal(writer, (encoding >> 3) & UINT64_C(15));
    arm_writer_puts(writer, ", #");
    arm_writer_decimal(writer, encoding & UINT64_C(7));
}
#endif

static void arm_format_operand(
    arm_text_writer *writer,
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand,
    size_t operand_index)
{
    switch (operand->type) {
        case CDISASM_OPERAND_REGISTER:
            arm_format_register(
                writer, instruction, operand, operand_index);
            break;
        case CDISASM_OPERAND_IMMEDIATE:
            arm_format_immediate(
                writer, instruction, operand, operand_index);
            break;
        case CDISASM_OPERAND_MEMORY:
            arm_format_memory(writer, instruction, operand);
            break;
        case CDISASM_ARM_OPERAND_REGISTER_LIST:
            arm_format_register_list(writer, instruction, operand);
            break;
        case CDISASM_ARM_OPERAND_REGISTER_PAIR:
            arm_format_register_pair(writer, operand);
            break;
#if USE_EXTRA_OPCODES
        case CDISASM_ARM_OPERAND_SCALABLE_REGISTER:
            arm_format_scalable_register(writer, instruction, operand);
            break;
        case CDISASM_ARM_OPERAND_PREDICATE:
            arm_format_predicate(writer, instruction, operand);
            break;
        case CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST:
            arm_format_scalable_list(
                writer, instruction, operand, operand_index);
            break;
        case CDISASM_ARM_OPERAND_TILE:
            arm_format_tile(writer, instruction, operand);
            break;
        case CDISASM_ARM_OPERAND_REGISTER_PAIR_BASE:
            arm_format_pair_base(writer, operand);
            break;
        case CDISASM_ARM_OPERAND_PREDICATE_PAIR:
            arm_format_predicate_pair(writer, instruction, operand);
            break;
        case CDISASM_ARM_OPERAND_REGISTER_BLOCK:
            arm_format_register_block(writer, operand);
            break;
        case CDISASM_ARM_OPERAND_SYSTEM_REGISTER:
            arm_format_system_register(writer, instruction, operand);
            break;
        case CDISASM_ARM_OPERAND_SYSTEM_OPERATION:
            arm_format_system_operation(writer, operand);
            break;
        case CDISASM_ARM_OPERAND_PSTATE_FIELD:
            arm_writer_puts(
                writer, arm_pstate_msr_field_name((uint8_t)operand->imm));
            break;
        case CDISASM_ARM_OPERAND_VECTOR_REGISTER_LIST:
            arm_format_vector_list(
                writer, instruction, operand, operand_index);
            break;
#endif
        default:
            break;
    }
}

size_t CDISASM_CALL cdisasm_arm_format(
    const cdisasm_arm_instruction *instruction,
    uint32_t flags,
    char *buffer,
    size_t buffer_size)
{
    arm_text_writer writer;
    size_t index;
    size_t display_operand_count;

    if (buffer != NULL && buffer_size != 0u) {
        buffer[0] = '\0';
    }
    if ((buffer == NULL && buffer_size != 0u)
        || (flags & ~CDISASM_FORMAT_KNOWN_FLAGS_MASK) != 0u
        || !arm_valid_instruction(instruction)) {
        return 0;
    }

    writer.buffer = buffer;
    writer.buffer_size = buffer_size;
    writer.length = 0;

    if ((instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE) != 0u) {
#if USE_EXTRA_OPCODES
        size_t generated_length = cdisasm_arm_format_generated(
            instruction, flags, buffer, buffer_size);

        if (generated_length != 0u) {
            return generated_length;
        }
#endif
        /* Opaque operands have no exact structured representation.  If the
         * generated recipe cannot render all of them, emitting only the
         * mnemonic would falsely report a successful disassembly. */
        if (buffer != NULL && buffer_size != 0u) {
            buffer[0] = '\0';
        }
        return 0u;
    }

    arm_format_mnemonic(&writer, instruction, flags);
    if (arm_is_architectural_tsb_form(instruction)) {
        arm_writer_puts(&writer, " csync");
    } else {
        const char *fixed_hint_suffix =
            arm_architectural_fixed_hint_suffix(instruction);

        if (fixed_hint_suffix != NULL) {
            arm_writer_puts(&writer, fixed_hint_suffix);
        }
    }
    display_operand_count = instruction->operand_count;
#if USE_EXTRA_OPCODES
    if (instruction->name_id == CDISASM_ARM_NAME_IT
        && display_operand_count == 2u) {
        display_operand_count = 1u;
    } else if (arm_is_a64_dcps_form(instruction)
        && display_operand_count == 1u
        && instruction->operand[0].type == CDISASM_OPERAND_IMMEDIATE
        && instruction->operand[0].imm == 0u) {
        display_operand_count = 0u;
    } else if ((instruction->form_id == UINT16_C(2559)
            || instruction->form_id == UINT16_C(2560))
        && instruction->operand[1].imm == UINT64_C(31)) {
        display_operand_count = 1u;
    } else if (arm_is_sve_element_count_form(instruction)
        && instruction->operand[2].imm == 1u) {
        display_operand_count = instruction->operand[1].imm == 31u
            ? 1u : 2u;
    } else if (arm_is_sve_saturating_count_form(instruction)) {
        size_t pattern_index = instruction->operand_count == 4u ? 2u : 1u;

        if (instruction->operand[pattern_index + 1u].imm == 1u) {
            display_operand_count = instruction->operand[pattern_index].imm
                    == 31u
                ? pattern_index : pattern_index + 1u;
        }
    }
#endif
    if (display_operand_count != 0u) {
        arm_writer_putc(&writer, ' ');
    }
    for (index = 0; index < display_operand_count; ++index) {
        if (index != 0u) {
            arm_writer_puts(&writer, ", ");
        }
#if USE_EXTRA_OPCODES
        /* LDC/STC keep the coprocessor p#/c# selectors packed into the
         * first numeric ABI operand.  Render that operand as the canonical
         * architectural pair instead of exposing the implementation's
         * compact selector value (for example, 0x5e). */
        if (index == 0u
            && (instruction->name_id == CDISASM_ARM_NAME_LDC
                || instruction->name_id == CDISASM_ARM_NAME_STC)
            && ((instruction->form_id >= UINT16_C(520)
                    && instruction->form_id <= UINT16_C(528))
                || (instruction->form_id >= UINT16_C(1505)
                    && instruction->form_id <= UINT16_C(1513)))
            && instruction->operand[0].type == CDISASM_OPERAND_IMMEDIATE) {
            uint64_t selector = instruction->operand[0].imm;

            arm_writer_putc(&writer, 'p');
            arm_writer_decimal(&writer, selector & UINT64_C(15));
            arm_writer_puts(&writer, ", c");
            arm_writer_decimal(&writer, selector >> 4);
            continue;
        }
        if (index + 1u == display_operand_count
            && instruction->isa_id == CDISASM_ARM_ISA_A32
            && instruction->form_id >= UINT16_C(188)
            && instruction->form_id <= UINT16_C(215)
            && instruction->form_id != UINT16_C(210)
            && instruction->form_id != UINT16_C(211)) {
            static const char *const shift_names[4] = {
                "lsl ", "lsr ", "asr ", "ror "
            };

            arm_writer_puts(&writer,
                shift_names[(instruction->raw_instruction >> 5) & 3u]);
        }
        if (index == 0u
            && instruction->name_id == CDISASM_ARM_NAME_SETEND) {
            arm_writer_puts(&writer,
                instruction->operand[0].imm != 0u ? "be" : "le");
            continue;
        }
        if (index == 0u
            && (instruction->name_id == CDISASM_ARM_NAME_CPSID
                || instruction->name_id == CDISASM_ARM_NAME_CPSIE)) {
            uint64_t mask = instruction->operand[0].imm;

            if (mask == 0u) {
                arm_writer_puts(&writer, "none");
            } else {
                if ((mask & 4u) != 0u) {
                    arm_writer_putc(&writer, 'a');
                }
                if ((mask & 2u) != 0u) {
                    arm_writer_putc(&writer, 'i');
                }
                if ((mask & 1u) != 0u) {
                    arm_writer_putc(&writer, 'f');
                }
            }
            continue;
        }
        if (instruction->form_id == UINT16_C(6395)
            || instruction->form_id == UINT16_C(6396)) {
            const cdisasm_arm_operand *op = &instruction->operand[index];
            if ((op->flags & CDISASM_ARM_OPERAND_FLAG_HAS_LANE) != 0u) {
                arm_writer_putc(&writer, 'v');
                arm_writer_decimal(&writer,
                    (uint64_t)(op->reg - CDISASM_ARM_REG_V0));
                arm_writer_puts(&writer, ".d[1]");
            } else {
                arm_writer_puts(&writer, arm_register_names[op->reg]);
            }
            continue;
        }
#endif
        arm_format_operand(
            &writer,
            instruction,
            &instruction->operand[index],
            index);
#if USE_EXTRA_OPCODES
        if (index == 3u && instruction->form_id == UINT16_C(2920)
            && instruction->name_id == CDISASM_ARM_NAME_FCMLA) {
            arm_writer_puts(&writer, ", #");
            arm_writer_decimal(&writer, instruction->operand[3].imm);
        }
        if (index == 0u
            && instruction->form_id == UINT16_C(2325)
            && instruction->name_id == CDISASM_ARM_NAME_XAR) {
            /* The ABI collapses tied Zdn into one read/write operand, while
             * the architectural spelling repeats it as destination/source. */
            arm_writer_puts(&writer, ", ");
            arm_format_operand(
                &writer, instruction, &instruction->operand[0], 0u);
        }
#endif
    }
    arm_writer_finish(&writer);
    return writer.length;
}

#endif
