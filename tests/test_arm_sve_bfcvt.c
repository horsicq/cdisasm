#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_FCVTZU == UINT16_C(435),
               "established ARM conversion IDs moved");
_Static_assert(CDISASM_ARM_NAME_BFCVT == UINT16_C(436),
               "BFCVT must be appended to the ARM name catalog");
_Static_assert(CDISASM_ARM_NAME_BFCVTNT == UINT16_C(437),
               "BFCVTNT must follow BFCVT");
_Static_assert(CDISASM_ARM_NAME_BFCVTN == UINT16_C(438),
               "BFCVTN must follow BFCVTNT");
_Static_assert(CDISASM_ARM_NAME_BFCVTN < CDISASM_ARM_NAME_COUNT,
               "BFCVTN must remain in the ARM name catalog");
_Static_assert(CDISASM_ARM_NAME_COUNT == CDISASM_ARM_NAME_LAST + 1u,
               "ARM mnemonic IDs must remain contiguous");

static int failures;

#define EXPECT(condition)                                                   \
    do {                                                                    \
        if (!(condition)) {                                                 \
            if (failures < 24) {                                           \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",       \
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

static uint32_t conversion_word(
    unsigned selector, unsigned pg, unsigned zn, unsigned zd)
{
    return UINT32_C(0x6588a000)
        | ((uint32_t)(selector & 3u) << 16)
        | ((uint32_t)(pg & 7u) << 10)
        | ((uint32_t)(zn & 31u) << 5)
        | (uint32_t)(zd & 31u);
}

static uint32_t bfcvt_word(unsigned pg, unsigned zn, unsigned zd)
{
    return conversion_word(2u, pg, zn, zd);
}

static uint32_t predicated_bf16_word(
    uint32_t base, unsigned pg, unsigned zn, unsigned zd)
{
    return base | ((uint32_t)(pg & 7u) << 10)
        | ((uint32_t)(zn & 31u) << 5)
        | (uint32_t)(zd & 31u);
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
    return cdisasm_arm_decode(
        cpu_id, mode, bytes, code_size, UINT64_C(0x127000),
        options, instruction);
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
    cdisasm_operand_access destination_access,
    uint8_t predicate_flag, cdisasm_arm_form_id form_id,
    unsigned pg, unsigned zn, unsigned zd,
    cdisasm_arm_instruction *expected)
{
    memset(expected, 0, sizeof(*expected));
    expected->address = UINT64_C(0x127000);
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
    expected->operand[0].access = destination_access;

    expected->operand[1].type = CDISASM_ARM_OPERAND_PREDICATE;
    expected->operand[1].reg =
        (cdisasm_arm_reg_id)(CDISASM_ARM_REG_P0 + pg);
    expected->operand[1].extend_type =
        (cdisasm_arm_extend_type)source_size;
    expected->operand[1].flags = predicate_flag;
    expected->operand[1].access = CDISASM_OPERAND_ACCESS_READ;

    expected->operand[2].type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    expected->operand[2].reg =
        (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zn);
    expected->operand[2].extend_type =
        (cdisasm_arm_extend_type)source_size;
    expected->operand[2].access = CDISASM_OPERAND_ACCESS_READ;
}
#endif

static void test_exhaustive_allocated_and_control_domain(void)
{
    uint32_t baseline_allocated = 0u;
    uint32_t bf16_allocated = 0u;
    uint32_t reserved = 0u;
    unsigned selector;

    /* This exhausts every variable field in the exact 0x6588a000 class:
     * two baseline FCVT rows, the BFCVT row, and the reserved control. */
    for (selector = 0u; selector < 4u; ++selector) {
        unsigned pg;

        for (pg = 0u; pg < 8u; ++pg) {
            unsigned zn;

            for (zn = 0u; zn < 32u; ++zn) {
                unsigned zd;

                for (zd = 0u; zd < 32u; ++zd) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = conversion_word(selector, pg, zn, zd);
                    uint32_t decoded;

                    domain_expect(
                        (word & UINT32_C(0xfffce000))
                            == UINT32_C(0x6588a000),
                        word, "word escaped the four-row control envelope");
                    memset(&instruction, 0xa5, sizeof(instruction));
                    decoded = decode_word(
                        word, CDISASM_ARM_CPU_ANY,
                        CDISASM_ARM_MODE_A64, 4u,
                        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
                    if (selector == 3u) {
                        ++reserved;
                        domain_expect(decoded == 0u, word,
                            "reserved selector decoded");
                        domain_expect(instruction_is_error_only(
                            &instruction,
                            CDISASM_STATUS_INVALID_INSTRUCTION),
                            word, "reserved selector status mismatch");
                        continue;
                    }
                    if (selector == 2u) {
                        ++bf16_allocated;
                    } else {
                        ++baseline_allocated;
                    }
#if USE_EXTRA_OPCODES
                    {
                        cdisasm_arm_instruction expected;
                        cdisasm_arm_name_id name_id = selector == 2u
                            ? CDISASM_ARM_NAME_BFCVT
                            : CDISASM_ARM_NAME_FCVT;
                        uint8_t destination_size = selector == 1u
                            ? 4u : 2u;
                        uint8_t source_size = selector == 1u
                            ? 2u : 4u;
                        cdisasm_arm_form_id form_id =
                            (cdisasm_arm_form_id)(UINT16_C(3115) + selector);

                        build_expected_instruction(
                            word, name_id, destination_size, source_size,
                            CDISASM_OPERAND_ACCESS_READ_WRITE,
                            CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE,
                            form_id, pg, zn, zd, &expected);
                        domain_expect(decoded == 4u, word,
                            "allocated conversion did not decode");
                        domain_expect(memcmp(
                            &instruction, &expected,
                            sizeof(expected)) == 0,
                            word, "allocated conversion metadata mismatch");
                    }
#else
                    domain_expect(decoded == 0u, word,
                        "extras-OFF build decoded allocated conversion");
                    domain_expect(instruction_is_error_only(
                        &instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                        word, "extras-OFF ownership status mismatch");
#endif
                }
            }
        }
    }

    EXPECT(baseline_allocated == UINT32_C(16384));
    EXPECT(bf16_allocated == UINT32_C(8192));
    EXPECT(reserved == UINT32_C(8192));
    EXPECT(baseline_allocated + bf16_allocated + reserved
        == UINT32_C(32768));
}

static void test_exhaustive_added_bf16_classes(void)
{
    static const struct bf16_form {
        uint32_t base;
        cdisasm_arm_name_id name_id;
        cdisasm_operand_access destination_access;
        uint8_t predicate_flag;
        cdisasm_arm_form_id form_id;
    } forms[] = {
        { UINT32_C(0x648aa000), CDISASM_ARM_NAME_BFCVTNT,
          CDISASM_OPERAND_ACCESS_READ_WRITE,
          CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE, UINT16_C(2931) },
        { UINT32_C(0x649ac000), CDISASM_ARM_NAME_BFCVT,
          CDISASM_OPERAND_ACCESS_WRITE,
          CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO, UINT16_C(2954) },
        { UINT32_C(0x6482a000), CDISASM_ARM_NAME_BFCVTNT,
          CDISASM_OPERAND_ACCESS_READ_WRITE,
          CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO, UINT16_C(2925) }
    };
    static const uint32_t reserved_bases[] = {
        UINT32_C(0x648ba000),
        UINT32_C(0x6483a000)
    };
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    size_t form_index;

    /* Each exact class has only Pg, Zn, and Zd as variable fields:
     * 8 * 32 * 32 = 8192 encodings per form. */
    for (form_index = 0u;
         form_index < sizeof(forms) / sizeof(forms[0]);
         ++form_index) {
        unsigned pg;

        for (pg = 0u; pg < 8u; ++pg) {
            unsigned zn;

            for (zn = 0u; zn < 32u; ++zn) {
                unsigned zd;

                for (zd = 0u; zd < 32u; ++zd) {
                    const struct bf16_form *form = &forms[form_index];
                    cdisasm_arm_instruction instruction;
                    uint32_t word = predicated_bf16_word(
                        form->base, pg, zn, zd);
                    uint32_t decoded;

                    ++allocated;
                    domain_expect(
                        (word & UINT32_C(0xffffe000)) == form->base,
                        word, "word escaped its exact BF16 class");
                    memset(&instruction, 0xa5, sizeof(instruction));
                    decoded = decode_word(
                        word, CDISASM_ARM_CPU_ANY,
                        CDISASM_ARM_MODE_A64, 4u,
                        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
                    {
                        cdisasm_arm_instruction expected;

                        build_expected_instruction(
                            word, form->name_id, 2u, 4u,
                            form->destination_access,
                            form->predicate_flag,
                            form->form_id, pg, zn, zd, &expected);
                        domain_expect(decoded == 4u, word,
                            "allocated BF16 conversion did not decode");
                        domain_expect(memcmp(
                            &instruction, &expected,
                            sizeof(expected)) == 0,
                            word, "BF16 conversion metadata mismatch");
                    }
#else
                    domain_expect(decoded == 0u, word,
                        "extras-OFF build decoded a BF16 conversion");
                    domain_expect(instruction_is_error_only(
                        &instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
                        word, "extras-OFF BF16 ownership mismatch");
#endif
                }
            }
        }
    }

    /* opc=1011 is unallocated beside BFCVTNT for both /m and /z. */
    for (form_index = 0u;
         form_index < sizeof(reserved_bases) / sizeof(reserved_bases[0]);
         ++form_index) {
        unsigned pg;

        for (pg = 0u; pg < 8u; ++pg) {
            unsigned zn;

            for (zn = 0u; zn < 32u; ++zn) {
                unsigned zd;

                for (zd = 0u; zd < 32u; ++zd) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = predicated_bf16_word(
                        reserved_bases[form_index], pg, zn, zd);

                    ++reserved;
                    memset(&instruction, 0xa5, sizeof(instruction));
                    domain_expect(decode_word(
                        word, CDISASM_ARM_CPU_ANY,
                        CDISASM_ARM_MODE_A64, 4u,
                        CDISASM_ARM_DECODE_OPTION_NONE,
                        &instruction) == 0u,
                        word, "reserved BF16 neighbor decoded");
                    domain_expect(instruction_is_error_only(
                        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION),
                        word, "reserved BF16 neighbor status mismatch");
                }
            }
        }
    }

    EXPECT(allocated == UINT32_C(24576));
    EXPECT(reserved == UINT32_C(16384));
    EXPECT(allocated + reserved == UINT32_C(40960));
    EXPECT((forms[0].base & UINT32_C(0xffffe000)) != forms[1].base);
    EXPECT((forms[0].base & UINT32_C(0xffffe000)) != forms[2].base);
    EXPECT((forms[1].base & UINT32_C(0xffffe000)) != forms[2].base);
}

static void test_feature_and_profile_gates(void)
{
    uint32_t cpu_value;

    for (cpu_value = CDISASM_ARM_CPU_FIRST;
         cpu_value <= CDISASM_ARM_CPU_LAST;
         ++cpu_value) {
        cdisasm_arm_cpu_id cpu_id = (cdisasm_arm_cpu_id)cpu_value;
        cdisasm_arm_instruction instruction;
        cdisasm_status expected_status;
        uint32_t decoded;

        memset(&instruction, 0xa5, sizeof(instruction));
        decoded = decode_word(
            bfcvt_word(3u, 17u, 9u), cpu_id,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
        if ((cdisasm_arm_cpu_mode_mask(cpu_id)
                & CDISASM_ARM_MODE_MASK_A64) == 0u) {
            expected_status = CDISASM_STATUS_INVALID_ARGUMENT;
#if USE_EXTRA_OPCODES
        } else if (cpu_id == CDISASM_ARM_CPU_APPLE_A18
            || cpu_id == CDISASM_ARM_CPU_APPLE_M4) {
            expected_status = CDISASM_STATUS_OK;
        } else {
            expected_status = CDISASM_STATUS_INVALID_INSTRUCTION;
#else
        } else {
            expected_status = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
        }
        if (expected_status == CDISASM_STATUS_OK) {
            EXPECT(decoded == 4u);
            EXPECT(instruction.name_id == CDISASM_ARM_NAME_BFCVT);
        } else {
            EXPECT(decoded == 0u);
            EXPECT(instruction_is_error_only(
                &instruction, expected_status));
        }
    }

    {
        cdisasm_arm_instruction instruction;
        uint32_t decoded;

        memset(&instruction, 0xa5, sizeof(instruction));
        decoded = decode_word(
            bfcvt_word(0u, 1u, 0u), CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
        EXPECT(decoded == 4u);
#else
        EXPECT(decoded == 0u);
#endif
#if USE_EXTRA_OPCODES
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_BFCVT);
#else
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif

        /* A64FX supplies SVE but not the independent FEAT_BF16 gate. */
        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            bfcvt_word(7u, 31u, 31u),
            CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
#if USE_EXTRA_OPCODES
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
#else
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif

        /* M3 has neither route. The M4 profile records SME and BF16 as
         * independent capabilities and therefore satisfies both gates. */
        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            bfcvt_word(1u, 2u, 3u), CDISASM_ARM_CPU_APPLE_M3,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
#if USE_EXTRA_OPCODES
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
#else
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif

        memset(&instruction, 0xa5, sizeof(instruction));
        decoded = decode_word(
            bfcvt_word(1u, 2u, 3u), CDISASM_ARM_CPU_APPLE_M4,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
        EXPECT(decoded == 4u);
#else
        EXPECT(decoded == 0u);
#endif

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            bfcvt_word(0u, 0u, 0u),
            CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_ARM_MODE_A32, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_INVALID_ARGUMENT));
    }
}

static void test_added_feature_and_profile_gates(void)
{
    static const struct gate_form {
        uint32_t word;
        cdisasm_arm_name_id name_id;
        int zeroing;
    } forms[] = {
        { UINT32_C(0x648aac82), CDISASM_ARM_NAME_BFCVTNT, 0 },
        { UINT32_C(0x649ad8e5), CDISASM_ARM_NAME_BFCVT, 1 },
        { UINT32_C(0x6482a528), CDISASM_ARM_NAME_BFCVTNT, 1 }
    };
    size_t form_index;

    for (form_index = 0u;
         form_index < sizeof(forms) / sizeof(forms[0]);
         ++form_index) {
        const struct gate_form *form = &forms[form_index];
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
            } else if (!form->zeroing
                && (cpu_id == CDISASM_ARM_CPU_APPLE_A18
                    || cpu_id == CDISASM_ARM_CPU_APPLE_M4)) {
                expected_status = CDISASM_STATUS_OK;
            } else {
                /* No named profile currently asserts SVE2.2 or SME2.2. */
                expected_status = CDISASM_STATUS_INVALID_INSTRUCTION;
#else
            } else {
                expected_status = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
            }
            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = decode_word(
                form->word, cpu_id, CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            if (expected_status == CDISASM_STATUS_OK) {
                EXPECT(decoded == 4u);
                EXPECT(instruction.name_id == form->name_id);
            } else {
                EXPECT(decoded == 0u);
                EXPECT(instruction_is_error_only(
                    &instruction, expected_status));
            }
        }

        {
            cdisasm_arm_instruction instruction;
            uint32_t decoded;

            memset(&instruction, 0xa5, sizeof(instruction));
            decoded = decode_word(
                form->word, CDISASM_ARM_CPU_ANY,
                CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
            EXPECT(decoded == 4u);
            EXPECT(instruction.name_id == form->name_id);
#else
            EXPECT(decoded == 0u);
            EXPECT(instruction_is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }

    /* SME2 is not SME2.2: A18 and M4 must reject the two zeroing forms. */
    {
        static const cdisasm_arm_cpu_id sme2_profiles[] = {
            CDISASM_ARM_CPU_APPLE_A18,
            CDISASM_ARM_CPU_APPLE_M4
        };
        size_t cpu_index;

        for (cpu_index = 0u;
             cpu_index < sizeof(sme2_profiles) / sizeof(sme2_profiles[0]);
             ++cpu_index) {
            cdisasm_arm_instruction instruction;

            memset(&instruction, 0xa5, sizeof(instruction));
            EXPECT(decode_word(
                UINT32_C(0x649ad8e5), sme2_profiles[cpu_index],
                CDISASM_ARM_MODE_A64, 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
#if USE_EXTRA_OPCODES
            EXPECT(instruction_is_error_only(
                &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
#else
            EXPECT(instruction_is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }
}

static void test_dispatch_endian_and_errors(void)
{
    const uint32_t word = UINT32_C(0x6482bfff);
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction big;
    cdisasm_arm_instruction generic;
    uint8_t little_bytes[4];
    uint8_t big_bytes[4];
    uint32_t decoded;
    size_t code_size;

    memset(&little, 0xa5, sizeof(little));
    decoded = decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &little);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif

    word_to_be(word, big_bytes);
    memset(&big, 0xa5, sizeof(big));
    decoded = cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        big_bytes, sizeof(big_bytes), UINT64_C(0x127000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &big);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&little, &big, sizeof(little)) == 0);

    word_to_le(word, little_bytes);
    memset(&generic, 0xa5, sizeof(generic));
    decoded = cdisasm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        little_bytes, sizeof(little_bytes), UINT64_C(0x127000),
        CDISASM_ARM_DECODE_OPTION_NONE, &generic);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&little, &generic, sizeof(little)) == 0);

    memset(&generic, 0xa5, sizeof(generic));
    decoded = cdisasm_decode_checked(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        little_bytes, sizeof(little_bytes), UINT64_C(0x127000),
        CDISASM_ARM_DECODE_OPTION_NONE, &generic, sizeof(generic));
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    EXPECT(memcmp(&little, &generic, sizeof(little)) == 0);

    for (code_size = 1u; code_size < 4u; ++code_size) {
        memset(&generic, 0xa5, sizeof(generic));
        EXPECT(decode_word(
            word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            code_size, CDISASM_ARM_DECODE_OPTION_NONE,
            &generic) == 0u);
        EXPECT(instruction_is_error_only(
            &generic, CDISASM_STATUS_TRUNCATED));
    }

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 0u,
        CDISASM_ARM_DECODE_OPTION_NONE, &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_END_OF_INPUT));

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64, 4u,
        UINT64_C(1) << 63, &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        conversion_word(3u, 7u, 31u, 31u), CDISASM_ARM_CPU_ANY,
        CDISASM_ARM_MODE_A64, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_INSTRUCTION));
}

static void test_neighbors_and_non_a64_nonownership(void)
{
    static const uint32_t reserved_a64_words[] = {
        UINT32_C(0x658ba020),
        UINT32_C(0x648ba020),
        UINT32_C(0x6483a020)
    };
    static const uint32_t owned_a64_words[] = {
        UINT32_C(0x658aa020),
        UINT32_C(0x648aa020),
        UINT32_C(0x649ac020),
        UINT32_C(0x6482a020)
    };
    static const cdisasm_arm_mode non_a64_modes[] = {
        CDISASM_ARM_MODE_A32,
        CDISASM_ARM_MODE_T32
    };
    size_t index;

    for (index = 0u;
         index < sizeof(reserved_a64_words) / sizeof(reserved_a64_words[0]);
         ++index) {
        cdisasm_arm_instruction instruction;

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            reserved_a64_words[index], CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
        EXPECT(instruction.name_id != CDISASM_ARM_NAME_BFCVT);
        EXPECT(instruction.name_id != CDISASM_ARM_NAME_BFCVTNT);
    }

    for (index = 0u;
         index < sizeof(non_a64_modes) / sizeof(non_a64_modes[0]);
         ++index) {
        size_t word_index;

        for (word_index = 0u;
             word_index < sizeof(owned_a64_words)
                 / sizeof(owned_a64_words[0]);
             ++word_index) {
            cdisasm_arm_instruction instruction;

            memset(&instruction, 0xa5, sizeof(instruction));
            (void)decode_word(
                owned_a64_words[word_index], CDISASM_ARM_CPU_ANY,
                non_a64_modes[index], 4u,
                CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
            EXPECT(instruction.name_id != CDISASM_ARM_NAME_BFCVT);
            EXPECT(instruction.name_id != CDISASM_ARM_NAME_BFCVTNT);
            EXPECT(instruction.isa_id != CDISASM_ARM_ISA_A64);
        }
    }
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void test_formatting(void)
{
    static const struct {
        uint32_t word;
        const char *text;
    } vectors[] = {
        { UINT32_C(0x658aa000), "bfcvt z0.h, p0/m, z0.s" },
        { UINT32_C(0x658abfff), "bfcvt z31.h, p7/m, z31.s" },
        { UINT32_C(0x658aae29), "bfcvt z9.h, p3/m, z17.s" },
        { UINT32_C(0x648aac82), "bfcvtnt z2.h, p3/m, z4.s" },
        { UINT32_C(0x649ad8e5), "bfcvt z5.h, p6/z, z7.s" },
        { UINT32_C(0x6482a528), "bfcvtnt z8.h, p1/z, z9.s" },
        { UINT32_C(0x648abfff), "bfcvtnt z31.h, p7/m, z31.s" },
        { UINT32_C(0x649adfff), "bfcvt z31.h, p7/z, z31.s" },
        { UINT32_C(0x6482bfff), "bfcvtnt z31.h, p7/z, z31.s" }
    };
    size_t index;

    for (index = 0u; index < sizeof(vectors) / sizeof(vectors[0]);
         ++index) {
        cdisasm_arm_instruction instruction;
        char text[80];
        size_t expected_length = strlen(vectors[index].text);

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            vectors[index].word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            text, sizeof(text)) == expected_length);
        EXPECT(strcmp(text, vectors[index].text) == 0);
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            NULL, 0u) == expected_length);
    }

    {
        cdisasm_arm_instruction instruction;
        char text[80];
        char short_text[5];
        static const char expected[] = "BFCVTNT z31.h, p7/z, z31.s";

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            UINT32_C(0x6482bfff), CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
        EXPECT(cdisasm_arm_format(
            &instruction,
            CDISASM_FORMAT_SYNTAX_0 | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(text, expected) == 0);
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_7,
            short_text, sizeof(short_text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(short_text, "bfcv") == 0);
    }
}
#endif

int main(void)
{
    test_exhaustive_allocated_and_control_domain();
    test_exhaustive_added_bf16_classes();
    test_feature_and_profile_gates();
    test_added_feature_and_profile_gates();
    test_dispatch_endian_and_errors();
    test_neighbors_and_non_a64_nonownership();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatting();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d ARM SVE BFCVT test(s) failed\n", failures);
        return 1;
    }
    printf("ARM SVE BFCVT/BFCVTNT tests passed "
           "(73728 control words; USE_EXTRA_OPCODES=%d)\n",
           USE_EXTRA_OPCODES);
    return 0;
}
