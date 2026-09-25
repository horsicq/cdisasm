#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_SCVTF == UINT16_C(431),
               "established SCVTF ID moved");
_Static_assert(CDISASM_ARM_NAME_UCVTF == UINT16_C(432),
               "established UCVTF ID moved");
_Static_assert(CDISASM_ARM_NAME_FCVT == UINT16_C(433),
               "FCVT must be appended to the ARM name catalog");
_Static_assert(CDISASM_ARM_NAME_FCVTZS == UINT16_C(434),
               "FCVTZS must follow FCVT");
_Static_assert(CDISASM_ARM_NAME_FCVTZU == UINT16_C(435),
               "FCVTZU must follow FCVTZS");
_Static_assert(CDISASM_ARM_NAME_BFCVT == UINT16_C(436),
               "BFCVT must follow the baseline conversion names");
_Static_assert(CDISASM_ARM_NAME_BFCVTNT == UINT16_C(437),
               "BFCVTNT must follow BFCVT");
_Static_assert(CDISASM_ARM_NAME_COUNT == CDISASM_ARM_NAME_LAST + 1u,
               "ARM mnemonic IDs must remain contiguous");

typedef struct fcvt_form {
    uint8_t selector;
    uint8_t destination_size;
    uint8_t source_size;
    cdisasm_arm_form_id form_id;
} fcvt_form;

static const fcvt_form allocated_forms[6] = {
    { 0u, 2u, 4u, UINT16_C(3115) },
    { 1u, 4u, 2u, UINT16_C(3116) },
    { 4u, 2u, 8u, UINT16_C(3118) },
    { 5u, 8u, 2u, UINT16_C(3119) },
    { 6u, 4u, 8u, UINT16_C(3120) },
    { 7u, 8u, 4u, UINT16_C(3121) }
};

typedef struct fp_to_int_form {
    uint8_t class_index;
    uint8_t selector;
    cdisasm_arm_name_id name_id;
    uint8_t destination_size;
    uint8_t source_size;
    cdisasm_arm_form_id form_id;
} fp_to_int_form;

static const fp_to_int_form allocated_fp_to_int_forms[14] = {
    { 0u, 2u, CDISASM_ARM_NAME_FCVTZS, 2u, 2u, UINT16_C(3147) },
    { 0u, 3u, CDISASM_ARM_NAME_FCVTZU, 2u, 2u, UINT16_C(3154) },
    { 0u, 4u, CDISASM_ARM_NAME_FCVTZS, 4u, 2u, UINT16_C(3148) },
    { 0u, 5u, CDISASM_ARM_NAME_FCVTZU, 4u, 2u, UINT16_C(3155) },
    { 0u, 6u, CDISASM_ARM_NAME_FCVTZS, 8u, 2u, UINT16_C(3149) },
    { 0u, 7u, CDISASM_ARM_NAME_FCVTZU, 8u, 2u, UINT16_C(3156) },
    { 1u, 0u, CDISASM_ARM_NAME_FCVTZS, 4u, 4u, UINT16_C(3143) },
    { 1u, 1u, CDISASM_ARM_NAME_FCVTZU, 4u, 4u, UINT16_C(3150) },
    { 2u, 0u, CDISASM_ARM_NAME_FCVTZS, 4u, 8u, UINT16_C(3144) },
    { 2u, 1u, CDISASM_ARM_NAME_FCVTZU, 4u, 8u, UINT16_C(3151) },
    { 2u, 4u, CDISASM_ARM_NAME_FCVTZS, 8u, 4u, UINT16_C(3145) },
    { 2u, 5u, CDISASM_ARM_NAME_FCVTZU, 8u, 4u, UINT16_C(3152) },
    { 2u, 6u, CDISASM_ARM_NAME_FCVTZS, 8u, 8u, UINT16_C(3146) },
    { 2u, 7u, CDISASM_ARM_NAME_FCVTZU, 8u, 8u, UINT16_C(3153) }
};

static int failures;

#define EXPECT(condition)                                                   \
    do {                                                                    \
        if (!(condition)) {                                                 \
            if (failures < 24) {                                           \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",      \
                        __FILE__, __LINE__, #condition);                    \
            }                                                               \
            ++failures;                                                     \
        }                                                                   \
    } while (0)

static void domain_expect(int condition, uint32_t word, const char *message)
{
    if (!condition) {
        if (failures < 24) {
            fprintf(stderr, "word %08x: %s\n", (unsigned)word, message);
        }
        ++failures;
    }
}

static uint32_t fcvt_word(
    unsigned selector, unsigned pg, unsigned zn, unsigned zd)
{
    return UINT32_C(0x6588a000)
        | ((uint32_t)(selector & 4u) << 20)
        | ((uint32_t)(selector & 3u) << 16)
        | ((uint32_t)pg << 10)
        | ((uint32_t)zn << 5)
        | (uint32_t)zd;
}

static uint32_t zeroing_fcvt_word(
    unsigned pg, unsigned zn, unsigned zd)
{
    return UINT32_C(0x649a8000)
        | ((uint32_t)pg << 10)
        | ((uint32_t)zn << 5)
        | (uint32_t)zd;
}

static int selector_is_allocated(unsigned selector)
{
    return selector < 2u || selector >= 4u;
}

static int word_is_allocated_fcvt(uint32_t word)
{
    return (word & UINT32_C(0xfffee000)) == UINT32_C(0x6588a000)
        || (word & UINT32_C(0xfffee000)) == UINT32_C(0x65c8a000)
        || (word & UINT32_C(0xfffee000)) == UINT32_C(0x65caa000);
}

#if USE_EXTRA_OPCODES
static const fcvt_form *form_for_selector(unsigned selector)
{
    size_t index;

    for (index = 0u;
         index < sizeof(allocated_forms) / sizeof(allocated_forms[0]);
         ++index) {
        if (allocated_forms[index].selector == selector) {
            return &allocated_forms[index];
        }
    }
    return NULL;
}
#endif

static uint32_t fp_to_int_word(
    unsigned class_index, unsigned selector, unsigned pg, unsigned zn,
    unsigned zd)
{
    static const uint32_t bases[3] = {
        UINT32_C(0x6558a000), UINT32_C(0x659ca000),
        UINT32_C(0x65d8a000)
    };

    return bases[class_index]
        | ((uint32_t)selector << 16)
        | ((uint32_t)pg << 10)
        | ((uint32_t)zn << 5)
        | (uint32_t)zd;
}

static int fp_to_int_selector_is_allocated(
    unsigned class_index, unsigned selector)
{
    if (class_index == 0u) {
        return selector >= 2u;
    }
    if (class_index == 1u) {
        return selector < 2u;
    }
    return selector < 2u || selector >= 4u;
}

#if USE_EXTRA_OPCODES
static const fp_to_int_form *fp_to_int_form_for_selector(
    unsigned class_index, unsigned selector)
{
    size_t index;

    for (index = 0u;
         index < sizeof(allocated_fp_to_int_forms)
            / sizeof(allocated_fp_to_int_forms[0]);
         ++index) {
        if (allocated_fp_to_int_forms[index].class_index == class_index
            && allocated_fp_to_int_forms[index].selector == selector) {
            return &allocated_fp_to_int_forms[index];
        }
    }
    return NULL;
}
#endif

static int word_is_allocated_fp_to_int(uint32_t word)
{
    unsigned selector = (word >> 16) & 7u;

    if ((word & UINT32_C(0xfff8e000)) == UINT32_C(0x6558a000)) {
        return selector >= 2u;
    }
    if ((word & UINT32_C(0xfffee000)) == UINT32_C(0x659ca000)) {
        return 1;
    }
    return (word & UINT32_C(0xfff8e000)) == UINT32_C(0x65d8a000)
        && (selector < 2u || selector >= 4u);
}

static void word_to_le(uint32_t word, uint8_t bytes[4])
{
    bytes[0] = (uint8_t)word;
    bytes[1] = (uint8_t)(word >> 8);
    bytes[2] = (uint8_t)(word >> 16);
    bytes[3] = (uint8_t)(word >> 24);
}

static void word_to_be(uint32_t word, uint8_t bytes[4])
{
    bytes[0] = (uint8_t)(word >> 24);
    bytes[1] = (uint8_t)(word >> 16);
    bytes[2] = (uint8_t)(word >> 8);
    bytes[3] = (uint8_t)word;
}

static uint32_t decode_word(
    uint32_t word, cdisasm_arm_cpu_id cpu_id, cdisasm_arm_mode mode,
    size_t code_size, cdisasm_arm_decode_option options,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(cpu_id, mode, bytes, code_size,
        UINT64_C(0x126000), options, instruction);
}

static int instruction_is_error_only(
    const cdisasm_arm_instruction *instruction, cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

#if USE_EXTRA_OPCODES
static void build_expected_instruction(
    uint32_t word, cdisasm_arm_name_id name_id,
    uint8_t destination_size, uint8_t source_size,
    cdisasm_arm_form_id form_id, unsigned pg,
    unsigned zn, unsigned zd, cdisasm_arm_instruction *expected)
{
    memset(expected, 0, sizeof(*expected));
    expected->address = UINT64_C(0x126000);
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
        | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
    expected->name_id = name_id;
    expected->operand_count = 3u;
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->form_id = form_id;

    expected->operand[0].type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    expected->operand[0].reg =
        (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zd);
    expected->operand[0].extend_type =
        (cdisasm_arm_extend_type)destination_size;
    expected->operand[0].access = CDISASM_OPERAND_ACCESS_READ_WRITE;

    expected->operand[1].type = CDISASM_ARM_OPERAND_PREDICATE;
    expected->operand[1].reg =
        (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg);
    expected->operand[1].flags =
        CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE;
    expected->operand[1].extend_type =
        (cdisasm_arm_extend_type)source_size;
    expected->operand[1].access = CDISASM_OPERAND_ACCESS_READ;

    expected->operand[2].type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    expected->operand[2].reg =
        (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zn);
    expected->operand[2].extend_type =
        (cdisasm_arm_extend_type)source_size;
    expected->operand[2].access = CDISASM_OPERAND_ACCESS_READ;
}

static void build_expected_zeroing_fcvt(
    uint32_t word, unsigned pg, unsigned zn, unsigned zd,
    cdisasm_arm_instruction *expected)
{
    build_expected_instruction(
        word, CDISASM_ARM_NAME_FCVT, 2u, 4u, UINT16_C(2952),
        pg, zn, zd, expected);
    expected->operand[0].access = CDISASM_OPERAND_ACCESS_WRITE;
    expected->operand[1].flags =
        CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO;
}
#endif

static void test_exhaustive_exact_envelope(void)
{
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    uint32_t bf16_allocated = 0u;
    unsigned selector;

    for (selector = 0u; selector < 8u; ++selector) {
        unsigned pg;

        for (pg = 0u; pg < 8u; ++pg) {
            unsigned zn;

            for (zn = 0u; zn < 32u; ++zn) {
                unsigned zd;

                for (zd = 0u; zd < 32u; ++zd) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = fcvt_word(selector, pg, zn, zd);
                    uint32_t decoded;

                    domain_expect(
                        (word & UINT32_C(0xffbce000))
                            == UINT32_C(0x6588a000),
                        word, "word escaped exact FCVT envelope");
                    memset(&instruction, 0xa5, sizeof(instruction));
                    decoded = decode_word(
                        word, CDISASM_ARM_CPU_ANY,
                        CDISASM_ARM_MODE_A64, 4u,
                        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                    if (selector == 2u) {
                        ++bf16_allocated;
#if USE_EXTRA_OPCODES
                        {
                            cdisasm_arm_instruction expected;

                            build_expected_instruction(
                                word, CDISASM_ARM_NAME_BFCVT,
                                2u, 4u, UINT16_C(3117),
                                pg, zn, zd, &expected);
                            domain_expect(decoded == 4u, word,
                                "allocated BFCVT did not decode");
                            domain_expect(memcmp(
                                &instruction, &expected,
                                sizeof(expected)) == 0,
                                word, "BFCVT metadata mismatch");
                        }
#else
                        domain_expect(decoded == 0u, word,
                            "extras-OFF build decoded BFCVT");
                        domain_expect(instruction_is_error_only(
                            &instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                            word, "extras-OFF BFCVT status mismatch");
#endif
                        continue;
                    }
                    if (!selector_is_allocated(selector)) {
                        ++reserved;
                        domain_expect(decoded == 0u, word,
                            "reserved selector decoded");
                        domain_expect(instruction_is_error_only(
                            &instruction,
                            CDISASM_STATUS_INVALID_INSTRUCTION),
                            word, "reserved selector status mismatch");
                        continue;
                    }
                    ++allocated;
#if USE_EXTRA_OPCODES
                    {
                        const fcvt_form *form = form_for_selector(selector);
                        cdisasm_arm_instruction expected;

                        domain_expect(form != NULL, word,
                            "allocated selector lacks metadata");
                        if (form == NULL) {
                            continue;
                        }
                        build_expected_instruction(
                            word, CDISASM_ARM_NAME_FCVT,
                            form->destination_size, form->source_size,
                            form->form_id, pg, zn, zd, &expected);
                        domain_expect(decoded == 4u, word,
                            "allocated FCVT did not decode");
                        domain_expect(memcmp(
                            &instruction, &expected,
                            sizeof(expected)) == 0,
                            word, "FCVT metadata mismatch");
                    }
#else
                    domain_expect(decoded == 0u, word,
                        "extras-OFF build decoded FCVT");
                    domain_expect(instruction_is_error_only(
                        &instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                        word, "extras-OFF ownership status mismatch");
#endif
                }
            }
        }
    }

    EXPECT(allocated == UINT32_C(49152));
    EXPECT(reserved == UINT32_C(8192));
    EXPECT(bf16_allocated == UINT32_C(8192));
    EXPECT(allocated + reserved + bf16_allocated == UINT32_C(65536));
}

static void test_exhaustive_zeroing_fcvt(void)
{
    uint32_t allocated = 0u;
    unsigned pg;

    for (pg = 0u; pg < 8u; ++pg) {
        unsigned zn;

        for (zn = 0u; zn < 32u; ++zn) {
            unsigned zd;

            for (zd = 0u; zd < 32u; ++zd) {
                cdisasm_arm_instruction instruction;
                uint32_t word = zeroing_fcvt_word(pg, zn, zd);
                uint32_t decoded;

                domain_expect(
                    (word & UINT32_C(0xffffe000))
                        == UINT32_C(0x649a8000),
                    word, "word escaped exact zeroing FCVT envelope");
                memset(&instruction, 0xa5, sizeof(instruction));
                decoded = decode_word(
                    word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                    4u, CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
                {
                    cdisasm_arm_instruction expected;

                    build_expected_zeroing_fcvt(
                        word, pg, zn, zd, &expected);
                    domain_expect(decoded == 4u, word,
                        "allocated zeroing FCVT did not decode");
                    domain_expect(memcmp(
                        &instruction, &expected, sizeof(expected)) == 0,
                        word, "zeroing FCVT metadata mismatch");
                }
#else
                domain_expect(decoded == 0u, word,
                    "extras-OFF build decoded zeroing FCVT");
                domain_expect(instruction_is_error_only(
                    &instruction,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                    word, "extras-OFF zeroing FCVT status mismatch");
#endif
                ++allocated;
            }
        }
    }

    EXPECT(allocated == UINT32_C(8192));
}

static void test_exhaustive_fp_to_int_envelopes(void)
{
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    unsigned class_index;

    for (class_index = 0u; class_index < 3u; ++class_index) {
        unsigned selector_count = class_index == 1u ? 2u : 8u;
        unsigned selector;

        for (selector = 0u; selector < selector_count; ++selector) {
            unsigned pg;

            for (pg = 0u; pg < 8u; ++pg) {
                unsigned zn;

                for (zn = 0u; zn < 32u; ++zn) {
                    unsigned zd;

                    for (zd = 0u; zd < 32u; ++zd) {
                        cdisasm_arm_instruction instruction;
                        uint32_t word = fp_to_int_word(
                            class_index, selector, pg, zn, zd);
                        uint32_t mask = class_index == 1u
                            ? UINT32_C(0xfffee000)
                            : UINT32_C(0xfff8e000);
                        uint32_t value = class_index == 0u
                            ? UINT32_C(0x6558a000)
                            : class_index == 1u
                                ? UINT32_C(0x659ca000)
                                : UINT32_C(0x65d8a000);
                        uint32_t decoded;

                        domain_expect((word & mask) == value, word,
                            "word escaped FP-to-integer envelope");
                        memset(&instruction, 0xa5, sizeof(instruction));
                        decoded = decode_word(
                            word, CDISASM_ARM_CPU_ANY,
                            CDISASM_ARM_MODE_A64, 4u,
                            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                        if (!fp_to_int_selector_is_allocated(
                                class_index, selector)) {
                            ++reserved;
                            domain_expect(decoded == 0u, word,
                                "reserved FP-to-integer selector decoded");
                            domain_expect(instruction_is_error_only(
                                &instruction,
                                CDISASM_STATUS_INVALID_INSTRUCTION),
                                word, "reserved FP-to-integer status mismatch");
                            continue;
                        }
                        ++allocated;
#if USE_EXTRA_OPCODES
                        {
                            const fp_to_int_form *form =
                                fp_to_int_form_for_selector(
                                    class_index, selector);
                            cdisasm_arm_instruction expected;

                            domain_expect(form != NULL, word,
                                "allocated FP-to-integer selector lacks metadata");
                            if (form == NULL) {
                                continue;
                            }
                            build_expected_instruction(
                                word, form->name_id,
                                form->destination_size, form->source_size,
                                form->form_id, pg, zn, zd, &expected);
                            domain_expect(decoded == 4u, word,
                                "allocated FP-to-integer did not decode");
                            domain_expect(memcmp(
                                &instruction, &expected,
                                sizeof(expected)) == 0,
                                word, "FP-to-integer metadata mismatch");
                        }
#else
                        domain_expect(decoded == 0u, word,
                            "extras-OFF build decoded FP-to-integer");
                        domain_expect(instruction_is_error_only(
                            &instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                            word, "extras-OFF FP-to-integer status mismatch");
#endif
                    }
                }
            }
        }
    }

    EXPECT(allocated == UINT32_C(114688));
    EXPECT(reserved == UINT32_C(32768));
    EXPECT(allocated + reserved == UINT32_C(147456));
}

static void expect_cpu_status(
    uint32_t word, cdisasm_arm_name_id name_id,
    cdisasm_arm_cpu_id cpu_id, cdisasm_status enabled_status)
{
    cdisasm_arm_instruction instruction;
    cdisasm_status expected_status;
    uint32_t decoded;

#if USE_EXTRA_OPCODES
    expected_status = enabled_status;
#else
    expected_status = enabled_status == CDISASM_STATUS_INVALID_ARGUMENT
        ? CDISASM_STATUS_INVALID_ARGUMENT
        : CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
    memset(&instruction, 0xa5, sizeof(instruction));
    decoded = decode_word(
        word, cpu_id, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
    EXPECT(decoded == (expected_status == CDISASM_STATUS_OK ? 4u : 0u));
    if (expected_status == CDISASM_STATUS_OK) {
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == name_id);
    } else {
        EXPECT(instruction_is_error_only(&instruction, expected_status));
    }
}

static void test_capability_routes(void)
{
    size_t index;

    for (index = 0u;
         index < sizeof(allocated_forms) / sizeof(allocated_forms[0]);
         ++index) {
        uint32_t word = fcvt_word(
            allocated_forms[index].selector, 3u, 13u, 7u);

        expect_cpu_status(
            word, CDISASM_ARM_NAME_FCVT,
            CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);
        expect_cpu_status(
            word, CDISASM_ARM_NAME_FCVT,
            CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_STATUS_OK);
        /* Apple A18/M4 exercise the independent SME-only route. */
        expect_cpu_status(
            word, CDISASM_ARM_NAME_FCVT,
            CDISASM_ARM_CPU_APPLE_A18, CDISASM_STATUS_OK);
        expect_cpu_status(
            word, CDISASM_ARM_NAME_FCVT,
            CDISASM_ARM_CPU_APPLE_M4, CDISASM_STATUS_OK);
        expect_cpu_status(
            word, CDISASM_ARM_NAME_FCVT,
            CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_cpu_status(
            word, CDISASM_ARM_NAME_FCVT,
            CDISASM_ARM_CPU_APPLE_M3,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    for (index = 0u;
         index < sizeof(allocated_fp_to_int_forms)
            / sizeof(allocated_fp_to_int_forms[0]);
         ++index) {
        const fp_to_int_form *form = &allocated_fp_to_int_forms[index];
        uint32_t word = fp_to_int_word(
            form->class_index, form->selector, 3u, 13u, 7u);

        expect_cpu_status(
            word, form->name_id, CDISASM_ARM_CPU_ANY,
            CDISASM_STATUS_OK);
        expect_cpu_status(
            word, form->name_id, CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_STATUS_OK);
        expect_cpu_status(
            word, form->name_id, CDISASM_ARM_CPU_APPLE_A18,
            CDISASM_STATUS_OK);
        expect_cpu_status(
            word, form->name_id, CDISASM_ARM_CPU_APPLE_M4,
            CDISASM_STATUS_OK);
        expect_cpu_status(
            word, form->name_id, CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_cpu_status(
            word, form->name_id, CDISASM_ARM_CPU_APPLE_M3,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

static void test_named_cpu_profile_boundary(void)
{
    const uint32_t word = fcvt_word(6u, 3u, 13u, 7u);
    uint32_t cpu_value;

    for (cpu_value = CDISASM_ARM_CPU_FIRST;
         cpu_value <= CDISASM_ARM_CPU_LAST;
         ++cpu_value) {
        cdisasm_arm_cpu_id cpu_id = (cdisasm_arm_cpu_id)cpu_value;
        cdisasm_arm_instruction instruction;
        cdisasm_status expected_status;
        uint32_t decoded;

        if ((cdisasm_arm_cpu_mode_mask(cpu_id)
                & CDISASM_ARM_MODE_MASK_A64) == 0u) {
            expected_status = CDISASM_STATUS_INVALID_ARGUMENT;
#if USE_EXTRA_OPCODES
        } else if (cpu_id == CDISASM_ARM_CPU_APPLE_A18
            || cpu_id == CDISASM_ARM_CPU_APPLE_M4
            || cpu_id == CDISASM_ARM_CPU_FUJITSU_A64FX) {
            expected_status = CDISASM_STATUS_OK;
        } else {
            expected_status = CDISASM_STATUS_INVALID_INSTRUCTION;
#else
        } else {
            expected_status = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
        }

        memset(&instruction, 0xa5, sizeof(instruction));
        decoded = decode_word(
            word, cpu_id, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
        EXPECT(decoded == (expected_status == CDISASM_STATUS_OK ? 4u : 0u));
        if (expected_status == CDISASM_STATUS_OK) {
            EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
            EXPECT(instruction.name_id == CDISASM_ARM_NAME_FCVT);
        } else {
            EXPECT(instruction_is_error_only(
                &instruction, expected_status));
        }
    }
}

static void test_zeroing_fcvt_feature_and_profile_gates(void)
{
    const uint32_t word = zeroing_fcvt_word(3u, 13u, 7u);
    uint32_t cpu_value;

    expect_cpu_status(
        word, CDISASM_ARM_NAME_FCVT,
        CDISASM_ARM_CPU_ANY, CDISASM_STATUS_OK);

    for (cpu_value = CDISASM_ARM_CPU_FIRST;
         cpu_value <= CDISASM_ARM_CPU_LAST;
         ++cpu_value) {
        cdisasm_arm_cpu_id cpu_id = (cdisasm_arm_cpu_id)cpu_value;
        cdisasm_status expected_status =
            (cdisasm_arm_cpu_mode_mask(cpu_id)
                & CDISASM_ARM_MODE_MASK_A64) != 0u
                ? CDISASM_STATUS_INVALID_INSTRUCTION
                : CDISASM_STATUS_INVALID_ARGUMENT;

        expect_cpu_status(
            word, CDISASM_ARM_NAME_FCVT, cpu_id, expected_status);
    }
}

static void test_zeroing_fcvt_neighbors_and_boundaries(void)
{
    const uint32_t fixed_mask = UINT32_C(0xffffe000);
    const uint32_t word = zeroing_fcvt_word(3u, 13u, 7u);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction other;
    uint8_t bytes[4];
    uint32_t decoded;
    unsigned bit;
    size_t code_size;

    for (bit = 0u; bit < 32u; ++bit) {
        uint32_t neighbor;

        if ((fixed_mask & (UINT32_C(1) << bit)) == 0u) {
            continue;
        }
        neighbor = word ^ (UINT32_C(1) << bit);
        memset(&other, 0xa5, sizeof(other));
        decoded = decode_word(
            neighbor, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &other);
        EXPECT(decoded != 4u || other.form_id != UINT16_C(2952));
    }

    memset(&little, 0xa5, sizeof(little));
    decoded = decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif

    word_to_be(word, bytes);
    memset(&other, 0xa5, sizeof(other));
    decoded = cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x126000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
    decoded = cdisasm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x126000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    memset(&other, 0xa5, sizeof(other));
    decoded = cdisasm_decode_checked(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x126000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    for (code_size = 1u; code_size < 4u; ++code_size) {
        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(
            word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, code_size,
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(
            &other, CDISASM_STATUS_TRUNCATED));
    }

    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0u,
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_END_OF_INPUT));

    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        UINT64_C(1) << 63, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_IN_IT_BLOCK, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));
}

static void test_fixed_bit_neighbors(void)
{
    const uint32_t fixed_mask = UINT32_C(0xfffee000);
    size_t index;

    for (index = 0u;
         index < sizeof(allocated_forms) / sizeof(allocated_forms[0]);
         ++index) {
        uint32_t canonical = fcvt_word(
            allocated_forms[index].selector, 3u, 13u, 7u);
        unsigned bit;

        for (bit = 0u; bit < 32u; ++bit) {
            cdisasm_arm_instruction instruction;
            uint32_t decoded;

            if ((fixed_mask & (UINT32_C(1) << bit)) == 0u) {
                continue;
            }
            if (word_is_allocated_fcvt(
                    canonical ^ (UINT32_C(1) << bit))) {
                continue;
            }
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = decode_word(
                canonical ^ (UINT32_C(1) << bit),
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            EXPECT(decoded != 4u
                || instruction.name_id != CDISASM_ARM_NAME_FCVT);
        }
    }
}

static void test_fp_to_int_fixed_bit_neighbors(void)
{
    size_t index;

    for (index = 0u;
         index < sizeof(allocated_fp_to_int_forms)
            / sizeof(allocated_fp_to_int_forms[0]);
         ++index) {
        const fp_to_int_form *form = &allocated_fp_to_int_forms[index];
        uint32_t fixed_mask = form->class_index == 1u
            ? UINT32_C(0xfffee000) : UINT32_C(0xfff8e000);
        uint32_t canonical = fp_to_int_word(
            form->class_index, form->selector, 3u, 13u, 7u);
        unsigned bit;

        for (bit = 0u; bit < 32u; ++bit) {
            cdisasm_arm_instruction instruction;
            uint32_t decoded;
            int same_class;

            if ((fixed_mask & (UINT32_C(1) << bit)) == 0u) {
                continue;
            }
            if (word_is_allocated_fp_to_int(
                    canonical ^ (UINT32_C(1) << bit))) {
                continue;
            }
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = decode_word(
                canonical ^ (UINT32_C(1) << bit),
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            same_class = decoded == 4u
                && (instruction.name_id == CDISASM_ARM_NAME_FCVTZS
                    || instruction.name_id == CDISASM_ARM_NAME_FCVTZU)
                && (instruction.operand[1].flags
                    & CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE) != 0u;
            EXPECT(!same_class);
        }
    }
}

static void test_endian_dispatch_modes_and_boundaries(void)
{
    const uint32_t word = fcvt_word(7u, 7u, 31u, 31u);
    const uint32_t reserved = fcvt_word(3u, 7u, 31u, 31u);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction other;
    uint8_t bytes[4];
    size_t code_size;
    uint32_t decoded;

    memset(&little, 0xa5, sizeof(little));
    decoded = decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif

    word_to_be(word, bytes);
    memset(&other, 0xa5, sizeof(other));
    decoded = cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x126000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    word_to_le(word, bytes);
    memset(&other, 0xa5, sizeof(other));
    decoded = cdisasm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x126000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    memset(&other, 0xa5, sizeof(other));
    decoded = cdisasm_decode_checked(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        bytes, sizeof(bytes), UINT64_C(0x126000),
        CDISASM_ARM_DECODE_OPTION_NONE, &other, sizeof(other));
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

    for (code_size = 1u; code_size < 4u; ++code_size) {
        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(
            word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, code_size,
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(&other, CDISASM_STATUS_TRUNCATED));
        memset(&other, 0xa5, sizeof(other));
        EXPECT(decode_word(
            reserved, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, code_size,
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
        EXPECT(instruction_is_error_only(&other, CDISASM_STATUS_TRUNCATED));
    }

    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0u,
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
    EXPECT(instruction_is_error_only(&other, CDISASM_STATUS_END_OF_INPUT));

    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_A32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_FUJITSU_A64FX,
        CDISASM_ARM_MODE_T32, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&other, 0xa5, sizeof(other));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        UINT64_C(1) << 63, &other) == 0u);
    EXPECT(instruction_is_error_only(
        &other, CDISASM_STATUS_INVALID_ARGUMENT));
}

static void test_fp_to_int_endian_and_boundaries(void)
{
    static const uint32_t words[2] = {
        UINT32_C(0x655aa020), UINT32_C(0x65dfbfff)
    };
    size_t index;

    for (index = 0u; index < sizeof(words) / sizeof(words[0]); ++index) {
        cdisasm_arm_instruction little;
        cdisasm_arm_instruction other;
        uint8_t bytes[4];
        size_t code_size;
        uint32_t decoded;

        memset(&little, 0xa5, sizeof(little));
        decoded = decode_word(
            words[index], CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &little);
#if USE_EXTRA_OPCODES
        EXPECT(decoded == 4u);
#else
        EXPECT(decoded == 0u);
#endif

        word_to_be(words[index], bytes);
        memset(&other, 0xa5, sizeof(other));
        decoded = cdisasm_arm_decode(
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            bytes, sizeof(bytes), UINT64_C(0x126000),
            CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other);
#if USE_EXTRA_OPCODES
        EXPECT(decoded == 4u);
#else
        EXPECT(decoded == 0u);
#endif
        EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

        for (code_size = 1u; code_size < 4u; ++code_size) {
            memset(&other, 0xa5, sizeof(other));
            EXPECT(decode_word(
                words[index], CDISASM_ARM_CPU_ANY,
                CDISASM_ARM_MODE_A64, code_size,
                CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
            EXPECT(instruction_is_error_only(
                &other, CDISASM_STATUS_TRUNCATED));
        }
    }

    {
        cdisasm_arm_instruction instruction;
        uint32_t reserved_h = fp_to_int_word(0u, 0u, 3u, 13u, 7u);
        uint32_t reserved_sd = fp_to_int_word(2u, 2u, 3u, 13u, 7u);

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            reserved_h, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            reserved_sd, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            words[0], CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_ARM_MODE_A32, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            words[1], CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            UINT64_C(1) << 63, &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
    }
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[96];
    char short_text[5];
    size_t expected_length = strlen(expected);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == expected_length);
    EXPECT(strcmp(text, expected) == 0);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_7,
        NULL, 0u) == expected_length);
    memset(short_text, 0xa5, sizeof(short_text));
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_0,
        short_text, sizeof(short_text)) == expected_length);
    EXPECT(short_text[sizeof(short_text) - 1u] == '\0');
}

static void test_formatter(void)
{
    static const char *const expected[6] = {
        "fcvt z7.h, p3/m, z13.s",
        "fcvt z7.s, p3/m, z13.h",
        "fcvt z7.h, p3/m, z13.d",
        "fcvt z7.d, p3/m, z13.h",
        "fcvt z7.s, p3/m, z13.d",
        "fcvt z7.d, p3/m, z13.s"
    };
    size_t index;

    for (index = 0u;
         index < sizeof(allocated_forms) / sizeof(allocated_forms[0]);
         ++index) {
        expect_format(
            fcvt_word(allocated_forms[index].selector, 3u, 13u, 7u),
            expected[index]);
    }

    expect_format(
        zeroing_fcvt_word(3u, 13u, 7u),
        "fcvt z7.h, p3/z, z13.s");

    {
        static const char *const fp_to_int_expected[14] = {
            "fcvtzs z7.h, p3/m, z13.h",
            "fcvtzu z7.h, p3/m, z13.h",
            "fcvtzs z7.s, p3/m, z13.h",
            "fcvtzu z7.s, p3/m, z13.h",
            "fcvtzs z7.d, p3/m, z13.h",
            "fcvtzu z7.d, p3/m, z13.h",
            "fcvtzs z7.s, p3/m, z13.s",
            "fcvtzu z7.s, p3/m, z13.s",
            "fcvtzs z7.s, p3/m, z13.d",
            "fcvtzu z7.s, p3/m, z13.d",
            "fcvtzs z7.d, p3/m, z13.s",
            "fcvtzu z7.d, p3/m, z13.s",
            "fcvtzs z7.d, p3/m, z13.d",
            "fcvtzu z7.d, p3/m, z13.d"
        };

        for (index = 0u;
             index < sizeof(allocated_fp_to_int_forms)
                / sizeof(allocated_fp_to_int_forms[0]);
             ++index) {
            const fp_to_int_form *form = &allocated_fp_to_int_forms[index];

            expect_format(fp_to_int_word(
                form->class_index, form->selector, 3u, 13u, 7u),
                fp_to_int_expected[index]);
        }
    }

    {
        cdisasm_arm_instruction instruction;
        char text[96];
        static const char expected_upper[] =
            "FCVT z31.d, p7/m, z31.s";

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            fcvt_word(7u, 7u, 31u, 31u),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(
            &instruction,
            CDISASM_FORMAT_SYNTAX_0 | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text)) == sizeof(expected_upper) - 1u);
        EXPECT(strcmp(text, expected_upper) == 0);
    }
}
#endif

int main(void)
{
    test_exhaustive_exact_envelope();
    test_exhaustive_zeroing_fcvt();
    test_exhaustive_fp_to_int_envelopes();
    test_capability_routes();
    test_named_cpu_profile_boundary();
    test_zeroing_fcvt_feature_and_profile_gates();
    test_zeroing_fcvt_neighbors_and_boundaries();
    test_fixed_bit_neighbors();
    test_fp_to_int_fixed_bit_neighbors();
    test_endian_dispatch_modes_and_boundaries();
    test_fp_to_int_endian_and_boundaries();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatter();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d ARM SVE FCVT test(s) failed\n", failures);
        return 1;
    }
    printf("ARM SVE FCVT tests passed "
           "(USE_EXTRA_OPCODES=%d, forms=21, owned=212992, "
           "allocated=172032, reserved=40960)\n", USE_EXTRA_OPCODES);
    return 0;
}
