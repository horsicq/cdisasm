#include "cdisasm/cdisasm_x86.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define EXPECT(expression)                                                   \
    do {                                                                     \
        if (!(expression)) {                                                 \
            if (failures < 48) {                                             \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",          \
                    __FILE__, __LINE__, #expression);                        \
            }                                                                \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(CDISASM_X86_NAME_LDDQU == UINT16_C(437),
    "LDDQU name ID changed");
_Static_assert(CDISASM_X86_NAME_VLDDQU == UINT16_C(1195),
    "VLDDQU name ID changed");
_Static_assert(CDISASM_X86_GROUP_SSE3 == UINT16_C(24)
        && CDISASM_X86_DECODE_BIT_SSE3 == UINT32_C(5),
    "SSE3 family identity changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
    "AVX family identity changed");
_Static_assert(CDISASM_X86_GROUP_APX_F == UINT16_C(91)
        && CDISASM_X86_DECODE_BIT_APX == UINT32_C(22),
    "APX family identity changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update LDDQU profile sweeps");

static int is_error_only(
    const cdisasm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static cdisasm_instruction decode(
    cdisasm_x86_cpu_id cpu_id,
    cdisasm_x86_mode mode,
    const uint8_t *code,
    size_t size,
    const cdisasm_x86_decode_flags *flags,
    uint32_t *decoded_size)
{
    cdisasm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    *decoded_size = cdisasm_x86_decode(
        cpu_id, mode, code, size, UINT64_C(0x1000), flags, &instruction);
    return instruction;
}

static void expect_error(
    const char *label,
    cdisasm_x86_cpu_id cpu_id,
    cdisasm_x86_mode mode,
    const uint8_t *code,
    size_t size,
    const cdisasm_x86_decode_flags *flags,
    cdisasm_status status)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        cpu_id, mode, code, size, flags, &decoded_size);

    if (decoded_size != 0u || !is_error_only(&instruction, status)) {
        fprintf(stderr, "%s: got size/status %u/%u, expected 0/%u\n",
            label, (unsigned int)decoded_size,
            (unsigned int)instruction.last_error_id,
            (unsigned int)status);
    }
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(&instruction, status));
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_decode_flags one_bit(cdisasm_x86_decode_bit_id bit_id)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_decode_flags_set_bit(&flags, bit_id));
    return flags;
}

static cdisasm_x86_decode_flags two_bits(
    cdisasm_x86_decode_bit_id first,
    cdisasm_x86_decode_bit_id second)
{
    cdisasm_x86_decode_flags flags = one_bit(first);

    EXPECT(cdisasm_decode_flags_set_bit(&flags, second));
    return flags;
}

static cdisasm_x86_reg_id vector_id(unsigned int index, unsigned int bits)
{
    return (cdisasm_x86_reg_id)((bits == 128u
        ? CDISASM_X86_REG_XMM0 : CDISASM_X86_REG_YMM0) + index);
}

static cdisasm_x86_reg_id address_reg(unsigned int index)
{
    return index < 16u
        ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_RAX + index)
        : (cdisasm_x86_reg_id)(CDISASM_X86_REG_R16 + index - 16u);
}

static void check_load(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    size_t minimum_size,
    cdisasm_x86_name_id name_id,
    cdisasm_x86_form_id form_id,
    unsigned int vector_bits,
    cdisasm_x86_reg_id destination,
    cdisasm_x86_reg_id base,
    cdisasm_x86_reg_id index,
    unsigned int scale,
    cdisasm_x86_group_id family_group,
    int expect_apx)
{
    EXPECT(decoded_size >= minimum_size);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == name_id);
    EXPECT(instruction->form_id == form_id);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
            | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT(cdisasm_instruction_has_x86_group(instruction, family_group));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_APX_F) == expect_apx);
    EXPECT(instruction->operand_count == 2u);
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].reg == destination);
    EXPECT(instruction->opcode[0].size == vector_bits / 8u);
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction->opcode[1].base_reg == base);
    EXPECT(instruction->opcode[1].index_reg == index);
    EXPECT(instruction->opcode[1].scale == scale);
    EXPECT(instruction->opcode[1].size == vector_bits / 8u);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[1].broadcast == CDISASM_X86_BROADCAST_NONE);
    EXPECT(instruction->encoding.immediate_count == 0u);
    EXPECT(instruction->mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction->mask_mode == CDISASM_X86_MASK_NONE);
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
}
#endif

static void test_three_forms_in_all_modes(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    static const uint8_t legacy[] = {0xf2, 0x0f, 0xf0, 0x00};
    static const uint8_t vex128[] = {0xc5, 0xfb, 0xf0, 0x00};
    static const uint8_t vex256[] = {0xc5, 0xff, 0xf0, 0x00};
    static const struct form_case {
        const uint8_t *code;
        size_t size;
        cdisasm_x86_name_id name_id;
        cdisasm_x86_form_id form_id;
        cdisasm_x86_group_id group_id;
        cdisasm_x86_decode_bit_id decode_bit;
        unsigned int bits;
        uint8_t prefix_size;
        uint8_t opcode_size;
    } forms[] = {
        {legacy, sizeof(legacy), CDISASM_X86_NAME_LDDQU, 1574,
         CDISASM_X86_GROUP_SSE3, CDISASM_X86_DECODE_BIT_SSE3,
         128u, 1u, 2u},
        {vex128, sizeof(vex128), CDISASM_X86_NAME_VLDDQU, 5583,
         CDISASM_X86_GROUP_AVX, CDISASM_X86_DECODE_BIT_AVX,
         128u, 2u, 1u},
        {vex256, sizeof(vex256), CDISASM_X86_NAME_VLDDQU, 5584,
         CDISASM_X86_GROUP_AVX, CDISASM_X86_DECODE_BIT_AVX,
         256u, 2u, 1u}
    };
    size_t form_index;

    for (form_index = 0u;
         form_index < sizeof(forms) / sizeof(forms[0]);
         ++form_index) {
        size_t mode_index;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = one_bit(forms[form_index].decode_bit);
#endif

        for (mode_index = 0u; mode_index < 3u; ++mode_index) {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, modes[mode_index], forms[form_index].code,
                forms[form_index].size,
#if USE_EXTRA_OPCODES
                &flags,
#else
                NULL,
#endif
                &decoded_size);

#if USE_EXTRA_OPCODES
            check_load(&instruction, decoded_size, forms[form_index].size,
                forms[form_index].name_id, forms[form_index].form_id,
                forms[form_index].bits,
                vector_id(0u, forms[form_index].bits),
                mode_index == 0u ? CDISASM_X86_REG_BX
                    : mode_index == 1u ? CDISASM_X86_REG_EAX
                                       : CDISASM_X86_REG_RAX,
                mode_index == 0u ? CDISASM_X86_REG_SI
                                 : CDISASM_X86_REG_NONE,
                mode_index == 0u ? 1u : 0u, forms[form_index].group_id, 0);
            EXPECT(decoded_size == forms[form_index].size);
            EXPECT(instruction.encoding.prefix_size
                == forms[form_index].prefix_size);
            EXPECT(instruction.encoding.opcode_size
                == forms[form_index].opcode_size);
#else
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }
}

static void test_legacy_prefixes_and_modrm(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    static const struct prefix_case {
        uint8_t code[8];
        uint8_t size;
        int valid;
    } prefix_cases[] = {
        {{0xf2, 0x0f, 0xf0, 0x00}, 4u, 1},
        {{0x66, 0xf2, 0x0f, 0xf0, 0x00}, 5u, 1},
        {{0xf2, 0x66, 0x0f, 0xf0, 0x00}, 5u, 1},
        {{0xf3, 0xf2, 0x0f, 0xf0, 0x00}, 5u, 1},
        {{0x66, 0xf3, 0xf2, 0x0f, 0xf0, 0x00}, 6u, 1},
        {{0xf2, 0xf3, 0x0f, 0xf0, 0x00}, 5u, 0},
        {{0x0f, 0xf0, 0x00}, 3u, 0},
        {{0x66, 0x0f, 0xf0, 0x00}, 4u, 0},
        {{0xf3, 0x0f, 0xf0, 0x00}, 4u, 0},
        {{0xf0, 0xf2, 0x0f, 0xf0, 0x00}, 5u, 0},
        {{0xf2, 0x0f, 0xf0, 0xc0}, 4u, 0}
    };
    size_t mode_index;
    size_t case_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        unsigned int modrm;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags sse3 =
            one_bit(CDISASM_X86_DECODE_BIT_SSE3);
#endif

        for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
            uint8_t code[15] = {
                0xf2, 0x0f, 0xf0, (uint8_t)modrm,
                0x24, 0x10, 0x20, 0x30, 0x40, 0x50
            };
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, modes[mode_index], code, sizeof(code),
#if USE_EXTRA_OPCODES
                &sse3,
#else
                NULL,
#endif
                &decoded_size);

            if ((modrm & UINT8_C(0xc0)) == UINT8_C(0xc0)) {
                EXPECT(decoded_size == 0u);
                EXPECT(is_error_only(
                    &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
                continue;
            }
#if USE_EXTRA_OPCODES
            EXPECT(decoded_size >= 4u && decoded_size <= sizeof(code));
            EXPECT(instruction.name_id == CDISASM_X86_NAME_LDDQU);
            EXPECT(instruction.form_id == UINT16_C(1574));
            EXPECT(instruction.opcode[0].reg
                == vector_id((modrm >> 3u) & 7u, 128u));
            EXPECT(instruction.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
            EXPECT(instruction.opcode[1].size == 16u);
            EXPECT(instruction.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
#else
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }

    for (case_index = 0u;
         case_index < sizeof(prefix_cases) / sizeof(prefix_cases[0]);
         ++case_index) {
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags sse3 =
            one_bit(CDISASM_X86_DECODE_BIT_SSE3);
#endif
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            prefix_cases[case_index].code, prefix_cases[case_index].size,
#if USE_EXTRA_OPCODES
            &sse3,
#else
            NULL,
#endif
            &decoded_size);

        if (!prefix_cases[case_index].valid) {
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
        } else {
#if USE_EXTRA_OPCODES
            EXPECT(decoded_size == prefix_cases[case_index].size);
            EXPECT(instruction.name_id == CDISASM_X86_NAME_LDDQU);
            EXPECT(instruction.form_id == UINT16_C(1574));
#else
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }

    {
        unsigned int payload;

        for (payload = 0u; payload < 16u; ++payload) {
            uint8_t code[] = {
                0xf2, (uint8_t)(UINT8_C(0x40) + payload),
                0x0f, 0xf0, 0x5c, 0x58, 0x7f
            };
            uint32_t decoded_size;
#if USE_EXTRA_OPCODES
            cdisasm_x86_decode_flags sse3 =
                one_bit(CDISASM_X86_DECODE_BIT_SSE3);
#endif
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64, code, sizeof(code),
#if USE_EXTRA_OPCODES
                &sse3,
#else
                NULL,
#endif
                &decoded_size);

#if USE_EXTRA_OPCODES
            check_load(&instruction, decoded_size, sizeof(code),
                CDISASM_X86_NAME_LDDQU, 1574, 128u,
                vector_id(3u + ((payload & 4u) != 0u ? 8u : 0u), 128u),
                address_reg((payload & 1u) != 0u ? 8u : 0u),
                address_reg(3u + ((payload & 2u) != 0u ? 8u : 0u)),
                2u, CDISASM_X86_GROUP_SSE3, 0);
            EXPECT(decoded_size == sizeof(code));
#else
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }

#if USE_EXTRA_OPCODES
    {
        static const uint8_t early_rex[] = {
            0x44, 0xf2, 0x0f, 0xf0, 0x08
        };
        cdisasm_x86_decode_flags sse3 =
            one_bit(CDISASM_X86_DECODE_BIT_SSE3);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64, early_rex,
            sizeof(early_rex), &sse3, &decoded_size);

        EXPECT(decoded_size == sizeof(early_rex));
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM1);
    }
#endif
}

static void test_rex2_space(void)
{
    static const struct rex2_prefix_case {
        uint8_t code[8];
        uint8_t size;
        int valid;
    } prefix_cases[] = {
        {{0x66, 0xf2, 0xd5, 0x80, 0xf0, 0x08}, 6u, 1},
        {{0xf2, 0x66, 0xd5, 0x80, 0xf0, 0x08}, 6u, 1},
        {{0xf3, 0xf2, 0xd5, 0x80, 0xf0, 0x08}, 6u, 1},
        {{0xf2, 0xf3, 0xd5, 0x80, 0xf0, 0x08}, 6u, 0}
    };
    unsigned int payload;
    size_t case_index;

    for (payload = 0x80u; payload <= UINT8_MAX; ++payload) {
        uint8_t code[] = {
            0xf2, 0xd5, (uint8_t)payload, 0xf0, 0x5c, 0x58, 0x7f
        };
        uint32_t decoded_size;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = two_bits(
            CDISASM_X86_DECODE_BIT_SSE3, CDISASM_X86_DECODE_BIT_APX);
#endif
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64, code, sizeof(code),
#if USE_EXTRA_OPCODES
            &flags,
#else
            NULL,
#endif
            &decoded_size);

#if USE_EXTRA_OPCODES
        check_load(&instruction, decoded_size, sizeof(code),
            CDISASM_X86_NAME_LDDQU, 1574, 128u,
            vector_id(3u + ((payload & 4u) != 0u ? 8u : 0u), 128u),
            address_reg(((payload & 1u) != 0u ? 8u : 0u)
                + ((payload & 0x10u) != 0u ? 16u : 0u)),
            address_reg(3u + ((payload & 2u) != 0u ? 8u : 0u)
                + ((payload & 0x20u) != 0u ? 16u : 0u)),
            2u, CDISASM_X86_GROUP_SSE3, 1);
        EXPECT(decoded_size == sizeof(code));
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REX2) != 0u);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AMD64));
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }

    for (case_index = 0u;
         case_index < sizeof(prefix_cases) / sizeof(prefix_cases[0]);
         ++case_index) {
        uint32_t decoded_size;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = two_bits(
            CDISASM_X86_DECODE_BIT_SSE3, CDISASM_X86_DECODE_BIT_APX);
#endif
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            prefix_cases[case_index].code, prefix_cases[case_index].size,
#if USE_EXTRA_OPCODES
            &flags,
#else
            NULL,
#endif
            &decoded_size);

        if (!prefix_cases[case_index].valid) {
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
        } else {
#if USE_EXTRA_OPCODES
            EXPECT(decoded_size == prefix_cases[case_index].size);
            EXPECT(instruction.form_id == UINT16_C(1574));
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_APX_F));
#else
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }

    {
        static const uint8_t no_apx_profile[] = {
            0xf2, 0xd5, 0x80, 0xf0, 0x08
        };
        static const uint8_t lock[] = {
            0xf0, 0xf2, 0xd5, 0x80, 0xf0, 0x08
        };
        expect_error("REX2 profile gate", CDISASM_CPU_SKYLAKE_SP,
            CDISASM_MODE_64, no_apx_profile, sizeof(no_apx_profile), NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("REX2 lock", CDISASM_CPU_X86, CDISASM_MODE_64,
            lock, sizeof(lock), NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    {
        static const uint8_t code[] = {0xf2, 0xd5, 0xf8, 0xf0, 0x08};
        static const cdisasm_x86_cpu_id apx_profiles[] = {
            CDISASM_CPU_APX, CDISASM_CPU_DIAMOND_RAPIDS
        };
        size_t index;

        for (index = 0u;
             index < sizeof(apx_profiles) / sizeof(apx_profiles[0]);
             ++index) {
            uint32_t decoded_size;
#if USE_EXTRA_OPCODES
            cdisasm_x86_decode_flags available;
#endif
#if USE_EXTRA_OPCODES
            EXPECT(cdisasm_x86_cpu_decode_flag_mask(
                apx_profiles[index], CDISASM_MODE_64, &available)
                == CDISASM_STATUS_OK);
#endif
            cdisasm_instruction instruction = decode(
                apx_profiles[index], CDISASM_MODE_64,
                code, sizeof(code),
#if USE_EXTRA_OPCODES
                &available,
#else
                NULL,
#endif
                &decoded_size);

#if USE_EXTRA_OPCODES
            EXPECT(decoded_size == sizeof(code));
            EXPECT(instruction.form_id == UINT16_C(1574));
            EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM1);
            EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_R16);
#else
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }
}

static void test_vex_controls_and_modrm(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        unsigned int control;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags avx =
            one_bit(CDISASM_X86_DECODE_BIT_AVX);
#endif

        for (control = 0u; control <= UINT8_MAX; ++control) {
            unsigned int modrm;

            for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                uint8_t code[15] = {
                    0xc4, 0xe1, (uint8_t)control, 0xf0, (uint8_t)modrm,
                    0x24, 0x10, 0x20, 0x30, 0x40
                };
                const int valid_control =
                    (control & UINT8_C(0x7b)) == UINT8_C(0x7b);
                const int memory =
                    (modrm & UINT8_C(0xc0)) != UINT8_C(0xc0);
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86, modes[mode_index], code, sizeof(code),
#if USE_EXTRA_OPCODES
                    &avx,
#else
                    NULL,
#endif
                    &decoded_size);

                if (!valid_control || !memory) {
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(
                        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
                    continue;
                }
#if USE_EXTRA_OPCODES
                EXPECT(decoded_size >= 5u && decoded_size <= sizeof(code));
                EXPECT(instruction.name_id == CDISASM_X86_NAME_VLDDQU);
                EXPECT(instruction.form_id == ((control & 4u) != 0u
                    ? UINT16_C(5584) : UINT16_C(5583)));
                EXPECT(instruction.opcode[0].reg == vector_id(
                    (modrm >> 3u) & 7u,
                    (control & 4u) != 0u ? 256u : 128u));
                EXPECT(instruction.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_WRITE);
                EXPECT(instruction.opcode[1].type
                    == CDISASM_OPERAND_MEMORY);
                EXPECT(instruction.opcode[1].size
                    == ((control & 4u) != 0u ? 32u : 16u));
                EXPECT(instruction.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX));
                EXPECT(!cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX2));
#else
                EXPECT(decoded_size == 0u);
                EXPECT(is_error_only(
                    &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
            }
        }
    }

    {
        unsigned int extension;

        for (extension = 0u; extension < 8u; ++extension) {
            uint8_t code[] = {
                0xc4, (uint8_t)(UINT8_C(1) | (extension << 5)),
                0xfb, 0xf0, 0x5c, 0x58, 0x7f
            };
            uint32_t decoded_size;
#if USE_EXTRA_OPCODES
            cdisasm_x86_decode_flags avx =
                one_bit(CDISASM_X86_DECODE_BIT_AVX);
#endif
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64, code, sizeof(code),
#if USE_EXTRA_OPCODES
                &avx,
#else
                NULL,
#endif
                &decoded_size);

#if USE_EXTRA_OPCODES
            check_load(&instruction, decoded_size, sizeof(code),
                CDISASM_X86_NAME_VLDDQU, 5583, 128u,
                vector_id(3u + ((extension & 4u) == 0u ? 8u : 0u), 128u),
                address_reg((extension & 1u) == 0u ? 8u : 0u),
                address_reg(3u + ((extension & 2u) == 0u ? 8u : 0u)),
                2u, CDISASM_X86_GROUP_AVX, 0);
            EXPECT(decoded_size == sizeof(code));
#else
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }
}

static void test_profiles_runtime_and_unallocated_encodings(void)
{
    static const uint8_t legacy[] = {0xf2, 0x0f, 0xf0, 0x00};
    static const uint8_t vex[] = {0xc5, 0xff, 0xf0, 0x00};
    static const uint8_t evex[] = {0x62, 0xf1, 0x7f, 0x28, 0xf0, 0x00};
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    static const cdisasm_x86_mode_mask mode_bits[] = {
        CDISASM_X86_MODE_MASK_16, CDISASM_X86_MODE_MASK_32,
        CDISASM_X86_MODE_MASK_64
    };

    expect_error("unowned EVEX map-1/F0", CDISASM_CPU_X86,
        CDISASM_MODE_64, evex, sizeof(evex), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

#if USE_EXTRA_OPCODES
    {
        cdisasm_x86_decode_flags sse3 =
            one_bit(CDISASM_X86_DECODE_BIT_SSE3);
        cdisasm_x86_decode_flags avx =
            one_bit(CDISASM_X86_DECODE_BIT_AVX);
        cdisasm_x86_decode_flags avx2 =
            one_bit(CDISASM_X86_DECODE_BIT_AVX2);
        static const uint8_t rex2[] = {0xf2, 0xd5, 0x80, 0xf0, 0x08};
        cdisasm_x86_decode_flags apx =
            one_bit(CDISASM_X86_DECODE_BIT_APX);
        cdisasm_x86_decode_flags sse3_apx = two_bits(
            CDISASM_X86_DECODE_BIT_SSE3, CDISASM_X86_DECODE_BIT_APX);
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        expect_error("legacy needs SSE3 runtime bit", CDISASM_CPU_X86,
            CDISASM_MODE_64, legacy, sizeof(legacy), &avx,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("VEX256 remains AVX", CDISASM_CPU_X86,
            CDISASM_MODE_64, vex, sizeof(vex), &avx2,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("REX2 needs SSE3", CDISASM_CPU_X86,
            CDISASM_MODE_64, rex2, sizeof(rex2), &apx,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("REX2 needs APX", CDISASM_CPU_X86,
            CDISASM_MODE_64, rex2, sizeof(rex2), &sse3,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            rex2, sizeof(rex2), &sse3_apx, &decoded_size);
        EXPECT(decoded_size == sizeof(rex2));
        EXPECT(instruction.form_id == UINT16_C(1574));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            vex, sizeof(vex), &avx, &decoded_size);
        EXPECT(decoded_size == sizeof(vex));
        EXPECT(instruction.form_id == UINT16_C(5584));
    }

    {
        uint32_t cpu_value;

        for (cpu_value = (uint32_t)CDISASM_CPU_FIRST;
             cpu_value <= (uint32_t)CDISASM_CPU_LAST;
             ++cpu_value) {
            cdisasm_x86_cpu_id cpu_id = (cdisasm_x86_cpu_id)cpu_value;
            size_t mode_index;

            for (mode_index = 0u; mode_index < 3u; ++mode_index) {
                cdisasm_x86_decode_flags available;
                const cdisasm_x86_mode mode = modes[mode_index];
                const cdisasm_x86_mode_mask available_modes =
                    cdisasm_x86_cpu_mode_mask(cpu_id);
                const uint8_t *codes[] = {legacy, vex};
                const size_t sizes[] = {sizeof(legacy), sizeof(vex)};
                const cdisasm_x86_decode_bit_id bits[] = {
                    CDISASM_X86_DECODE_BIT_SSE3,
                    CDISASM_X86_DECODE_BIT_AVX
                };
                size_t family;

                if ((available_modes & mode_bits[mode_index]) == 0u) {
                    continue;
                }
                EXPECT(cdisasm_x86_cpu_decode_flag_mask(
                    cpu_id, mode, &available) == CDISASM_STATUS_OK);
                for (family = 0u; family < 2u; ++family) {
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        cpu_id, mode, codes[family], sizes[family],
                        &available, &decoded_size);
                    const int has_family = cdisasm_decode_flags_test_bit(
                        &available, bits[family]);

                    if (has_family) {
                        EXPECT(decoded_size == sizes[family]);
                        EXPECT(instruction.form_id == (family == 0u
                            ? UINT16_C(1574) : UINT16_C(5584)));
                    } else {
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_INVALID_INSTRUCTION));
                    }
                }
            }
        }
    }
#else
    (void)legacy;
    (void)vex;
    (void)modes;
    (void)mode_bits;
#endif
}

static void test_truncation_and_formatting(void)
{
    static const uint8_t legacy_modrm[] = {0xf2, 0x0f, 0xf0};
    static const uint8_t legacy_sib[] = {0x66, 0xf2, 0x0f, 0xf0, 0x04};
    static const uint8_t legacy_bad_prefix_sib[] = {
        0xf2, 0xf3, 0x0f, 0xf0, 0x04
    };
    static const uint8_t vex_modrm[] = {0xc5, 0xfb, 0xf0};
    static const uint8_t vex_bad_control_sib[] = {
        0xc4, 0xe1, 0xeb, 0xf0, 0x04
    };
    static const uint8_t rex2_sib[] = {0xf2, 0xd5, 0xf8, 0xf0, 0x04};
    static const struct trunc_case {
        const uint8_t *code;
        size_t size;
    } cases[] = {
        {legacy_modrm, sizeof(legacy_modrm)},
        {legacy_sib, sizeof(legacy_sib)},
        {legacy_bad_prefix_sib, sizeof(legacy_bad_prefix_sib)},
        {vex_modrm, sizeof(vex_modrm)},
        {vex_bad_control_sib, sizeof(vex_bad_control_sib)},
        {rex2_sib, sizeof(rex2_sib)}
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_error("owned truncation", CDISASM_CPU_X86,
            CDISASM_MODE_64, cases[index].code, cases[index].size, NULL,
            CDISASM_STATUS_TRUNCATED);
    }

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    {
        static const uint8_t legacy[] = {
            0x66, 0xf2, 0x44, 0x0f, 0xf0, 0x54, 0x58, 0x20
        };
        static const uint8_t vex[] = {
            0xc4, 0x61, 0xff, 0xf0, 0x64, 0x58, 0xc0
        };
        static const uint8_t rex2[] = {
            0xf2, 0xd5, 0xf8, 0xf0, 0x0c, 0x58
        };
        cdisasm_x86_decode_flags sse3 =
            one_bit(CDISASM_X86_DECODE_BIT_SSE3);
        cdisasm_x86_decode_flags avx =
            one_bit(CDISASM_X86_DECODE_BIT_AVX);
        cdisasm_x86_decode_flags sse3_apx = two_bits(
            CDISASM_X86_DECODE_BIT_SSE3, CDISASM_X86_DECODE_BIT_APX);
        uint32_t decoded_size;
        cdisasm_instruction instruction;
        char output[128];

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            legacy, sizeof(legacy), &sse3, &decoded_size);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output))
            == strlen("lddqu xmm10, xmmword ptr [rax + rbx*2 + 0x20]"));
        EXPECT(strcmp(output,
            "lddqu xmm10, xmmword ptr [rax + rbx*2 + 0x20]") == 0);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            vex, sizeof(vex), &avx, &decoded_size);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output))
            == strlen("vlddqu -0x40(%rax,%rbx,2), %ymm12"));
        EXPECT(strcmp(output, "vlddqu -0x40(%rax,%rbx,2), %ymm12") == 0);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            rex2, sizeof(rex2), &sse3_apx, &decoded_size);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output))
            == strlen("lddqu xmm1, xmmword ptr [r16 + r19*2]"));
        EXPECT(strcmp(output,
            "lddqu xmm1, xmmword ptr [r16 + r19*2]") == 0);
    }
#endif
}

int main(void)
{
    test_three_forms_in_all_modes();
    test_legacy_prefixes_and_modrm();
    test_rex2_space();
    test_vex_controls_and_modrm();
    test_profiles_runtime_and_unallocated_encodings();
    test_truncation_and_formatting();

    if (failures != 0) {
        fprintf(stderr, "%d LDDQU/VLDDQU test(s) failed\n", failures);
        return 1;
    }
    puts("x86 LDDQU/VLDDQU tests passed (3 forms; exhaustive prefixes/ModRM/VEX/REX2)");
    return 0;
}
