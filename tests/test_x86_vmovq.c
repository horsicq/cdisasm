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
            if (failures < 64) {                                             \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",        \
                    __FILE__, __LINE__, #expression);                        \
            }                                                                \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(CDISASM_X86_NAME_VMOVQ == UINT16_C(1783),
    "VMOVQ name ID changed");
_Static_assert(CDISASM_X86_NAME_VMOVD == UINT16_C(1768)
        && CDISASM_X86_NAME_MOVQ == UINT16_C(1348),
    "VMOVD/MOVQ collision IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
    "AVX family identity changed");
_Static_assert(CDISASM_X86_GROUP_AVX512F_128N == UINT16_C(181)
        && CDISASM_X86_DECODE_BIT_AVX512F_128N == UINT32_C(129),
    "AVX512F_128N identity changed");
_Static_assert(CDISASM_X86_GROUP_AVX512_MOVZXC_128 == UINT16_C(221)
        && CDISASM_X86_DECODE_BIT_AVX512_MOVZXC_128 == UINT32_C(169),
    "AVX512_MOVZXC_128 identity changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update VMOVQ profile sweeps");

typedef struct vmovq_row {
    uint8_t opcode;
    uint8_t prefix;
} vmovq_row;

static const vmovq_row rows[] = {
    {0x6e, 1}, {0x7e, 1}, {0x7e, 2}, {0xd6, 1}
};

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

static cdisasm_x86_decode_flags all_flags(cdisasm_x86_mode mode)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_X86, mode, &flags) == CDISASM_STATUS_OK);
    return flags;
}

static cdisasm_x86_reg_id xmm(unsigned int index)
{
    return (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0 + index);
}

static cdisasm_x86_reg_id gpr64(unsigned int index)
{
    return index < 16u
        ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_RAX + index)
        : (cdisasm_x86_reg_id)(CDISASM_X86_REG_R16 + index - 16u);
}

static void check_vmovq(
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_form_id form_id,
    int evex,
    int apx)
{
    cdisasm_operand_type destination_type = CDISASM_OPERAND_REGISTER;
    cdisasm_operand_type source_type = CDISASM_OPERAND_REGISTER;
    unsigned int destination_size = 16u;
    unsigned int source_size = 16u;

    if (form_id == UINT16_C(5884) || form_id == UINT16_C(5885)) {
        destination_size = 8u;
    } else if (form_id == UINT16_C(5886)
        || form_id == UINT16_C(5887)
        || form_id == UINT16_C(5888)) {
        destination_type = CDISASM_OPERAND_MEMORY;
        destination_size = 8u;
    } else if (form_id == UINT16_C(5889)
        || form_id == UINT16_C(5894)) {
        source_size = 8u;
    } else if (form_id == UINT16_C(5890)
        || form_id == UINT16_C(5891)
        || form_id == UINT16_C(5895)) {
        source_type = CDISASM_OPERAND_MEMORY;
        source_size = 8u;
    }

    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == CDISASM_X86_NAME_VMOVQ);
    EXPECT(instruction->form_id == form_id);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
            | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT((instruction->opcode_flags
        & (evex ? CDISASM_PREFIX_EVEX : CDISASM_PREFIX_VEX)) != 0u);
    EXPECT((instruction->opcode_flags
        & (evex ? CDISASM_PREFIX_VEX : CDISASM_PREFIX_EVEX)) == 0u);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX512F_128N) == evex);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_APX_F) == apx);
    EXPECT(instruction->operand_count == 2u);
    EXPECT(instruction->opcode[0].type == destination_type);
    EXPECT(instruction->opcode[0].size == destination_size);
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction->opcode[1].type == source_type);
    EXPECT(instruction->opcode[1].size == source_size);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->encoding.opcode_size == 1u);
    EXPECT(instruction->encoding.immediate_count == 0u);
    EXPECT(instruction->mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction->mask_mode == CDISASM_X86_MASK_NONE);
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
}
#endif

static cdisasm_x86_form_id vex_form(
    uint8_t opcode,
    uint8_t prefix,
    uint8_t modrm)
{
    const int reg = (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);

    if (opcode == UINT8_C(0x6e)) {
        return reg ? UINT16_C(5889) : UINT16_C(5890);
    }
    if (opcode == UINT8_C(0x7e) && prefix == UINT8_C(1)) {
        return reg ? UINT16_C(5884) : UINT16_C(5886);
    }
    if (opcode == UINT8_C(0x7e)) {
        return reg ? UINT16_C(5892) : UINT16_C(5891);
    }
    return reg ? UINT16_C(5893) : UINT16_C(5887);
}

static cdisasm_x86_form_id evex_form(
    uint8_t opcode,
    uint8_t prefix,
    uint8_t modrm)
{
    const int reg = (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);

    if (opcode == UINT8_C(0x6e)) {
        return reg ? UINT16_C(5894) : UINT16_C(5895);
    }
    if (opcode == UINT8_C(0x7e) && prefix == UINT8_C(1)) {
        return reg ? UINT16_C(5885) : UINT16_C(5888);
    }
    if (opcode == UINT8_C(0x7e)) {
        return reg ? UINT16_C(5896) : UINT16_C(5895);
    }
    return reg ? UINT16_C(5896) : UINT16_C(5888);
}

static void test_thirteen_forms(void)
{
    static const struct {
        uint8_t code[8];
        uint8_t size;
        cdisasm_x86_form_id form;
    } cases[] = {
        {{0xc4,0xe1,0xf9,0x7e,0xc1},5,5884},
        {{0x62,0xf1,0xfd,0x08,0x7e,0xc1},6,5885},
        {{0xc4,0xe1,0xf9,0x7e,0x40,0x08},6,5886},
        {{0xc5,0xf9,0xd6,0x40,0x08},5,5887},
        {{0x62,0xf1,0xfd,0x08,0x7e,0x40,0x01},7,5888},
        {{0xc4,0xe1,0xf9,0x6e,0xc1},5,5889},
        {{0xc4,0xe1,0xf9,0x6e,0x40,0x08},6,5890},
        {{0xc5,0xfa,0x7e,0x40,0x08},5,5891},
        {{0xc5,0xfa,0x7e,0xc1},4,5892},
        {{0xc5,0xf9,0xd6,0xc1},4,5893},
        {{0x62,0xf1,0xfd,0x08,0x6e,0xc1},6,5894},
        {{0x62,0xf1,0xfd,0x08,0x6e,0x40,0x01},7,5895},
        {{0x62,0xf1,0xfe,0x08,0x7e,0xc1},6,5896}
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        uint32_t decoded_size;
#if USE_EXTRA_OPCODES
        const int evex = cases[index].code[0] == UINT8_C(0x62);
        cdisasm_x86_decode_flags flags = evex
            ? one_bit(CDISASM_X86_DECODE_BIT_AVX512F_128N)
            : one_bit(CDISASM_X86_DECODE_BIT_AVX);
#endif
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size,
#if USE_EXTRA_OPCODES
            &flags,
#else
            NULL,
#endif
            &decoded_size);

#if USE_EXTRA_OPCODES
        if (decoded_size == 0u) {
            fprintf(stderr, "form sample %u failed with status %u\n",
                (unsigned int)cases[index].form,
                (unsigned int)instruction.last_error_id);
        }
        check_vmovq(&instruction, decoded_size, cases[index].form, evex, 0);
        EXPECT(decoded_size == cases[index].size);
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

static void test_complete_allocated_domain(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint32_t per_form[13] = {0};
    uint32_t vex_total = 0u;
    uint32_t evex_total = 0u;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const int long_mode = modes[mode_index] == CDISASM_MODE_64;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif
        size_t row_index;

        for (row_index = 0u; row_index < 4u; ++row_index) {
            const uint8_t opcode = rows[row_index].opcode;
            const uint8_t prefix = rows[row_index].prefix;
            const int mode64_only = prefix == UINT8_C(1)
                && (opcode == UINT8_C(0x6e)
                    || opcode == UINT8_C(0x7e));
            unsigned int raw_r;

            if (!mode64_only) {
                for (raw_r = long_mode ? 0u : 1u;
                     raw_r <= 1u;
                     ++raw_r) {
                    unsigned int modrm;

                    for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                        uint8_t code[12] = {
                            0xc5,
                            (uint8_t)((raw_r << 7) | 0x78u | prefix),
                            opcode, (uint8_t)modrm,
                            0x24,0x10,0x20,0x30,0x40
                        };
                        const cdisasm_x86_form_id form = vex_form(
                            opcode, prefix, (uint8_t)modrm);
                        uint32_t decoded_size;
                        cdisasm_instruction instruction = decode(
                            CDISASM_CPU_X86, modes[mode_index], code,
                            sizeof(code),
#if USE_EXTRA_OPCODES
                            &flags,
#else
                            NULL,
#endif
                            &decoded_size);

#if USE_EXTRA_OPCODES
                        check_vmovq(&instruction, decoded_size, form, 0, 0);
#else
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                        ++per_form[form - UINT16_C(5884)];
                        ++vex_total;
                    }
                }
            }

            {
                unsigned int extension;

                for (extension = long_mode ? 0u : 6u;
                     extension <= 7u;
                     ++extension) {
                    unsigned int w;

                    for (w = 0u; w <= 1u; ++w) {
                        unsigned int modrm;

                        if (mode64_only && (!long_mode || w == 0u)) {
                            continue;
                        }
                        for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                            uint8_t code[12] = {
                                0xc4,
                                (uint8_t)((extension << 5) | 1u),
                                (uint8_t)((w << 7) | 0x78u | prefix),
                                opcode, (uint8_t)modrm,
                                0x24,0x10,0x20,0x30,0x40
                            };
                            const cdisasm_x86_form_id form = vex_form(
                                opcode, prefix, (uint8_t)modrm);
                            uint32_t decoded_size;
                            cdisasm_instruction instruction = decode(
                                CDISASM_CPU_X86, modes[mode_index], code,
                                sizeof(code),
#if USE_EXTRA_OPCODES
                                &flags,
#else
                                NULL,
#endif
                                &decoded_size);

#if USE_EXTRA_OPCODES
                            check_vmovq(
                                &instruction, decoded_size, form, 0, 0);
#else
                            EXPECT(decoded_size == 0u);
                            EXPECT(is_error_only(&instruction,
                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                            ++per_form[form - UINT16_C(5884)];
                            ++vex_total;
                        }
                    }
                }
            }

            if (mode64_only && !long_mode) {
                continue;
            }
            {
                unsigned int p0_index;
                const unsigned int p0_count = long_mode ? 32u : 4u;

                for (p0_index = 0u; p0_index < p0_count; ++p0_index) {
                    const uint8_t p0 = long_mode
                        ? (uint8_t)((p0_index << 3) | 1u)
                        : (uint8_t)(0xc1u | (p0_index << 4));
                    unsigned int u;

                    for (u = long_mode ? 0u : 1u; u <= 1u; ++u) {
                        unsigned int modrm;

                        for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                            const int is_register =
                                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                            uint8_t code[12] = {
                                0x62, p0,
                                (uint8_t)(0xf8u | (u ? 4u : 0u) | prefix),
                                0x08, opcode, (uint8_t)modrm,
                                0x24,0x10,0x20,0x30,0x40
                            };
                            cdisasm_x86_form_id form;
                            uint32_t decoded_size;
                            cdisasm_instruction instruction;

                            if (!u && is_register) {
                                continue;
                            }
                            form = evex_form(opcode, prefix, (uint8_t)modrm);
                            instruction = decode(
                                CDISASM_CPU_X86, modes[mode_index], code,
                                sizeof(code),
#if USE_EXTRA_OPCODES
                                &flags,
#else
                                NULL,
#endif
                                &decoded_size);
#if USE_EXTRA_OPCODES
                            check_vmovq(&instruction, decoded_size, form, 1,
                                (p0 & UINT8_C(8)) != 0 || !u);
#else
                            EXPECT(decoded_size == 0u);
                            EXPECT(is_error_only(&instruction,
                                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                            ++per_form[form - UINT16_C(5884)];
                            ++evex_total;
                        }
                    }
                }
            }
        }
    }

    EXPECT(vex_total == UINT32_C(18432));
    EXPECT(evex_total == UINT32_C(61440));
    EXPECT(per_form[0] == UINT32_C(512));
    EXPECT(per_form[1] == UINT32_C(2048));
    EXPECT(per_form[2] == UINT32_C(1536));
    EXPECT(per_form[3] == UINT32_C(5376));
    EXPECT(per_form[4] == UINT32_C(26112));
    EXPECT(per_form[5] == UINT32_C(512));
    EXPECT(per_form[6] == UINT32_C(1536));
    EXPECT(per_form[7] == UINT32_C(5376));
    EXPECT(per_form[8] == UINT32_C(1792));
    EXPECT(per_form[9] == UINT32_C(1792));
    EXPECT(per_form[10] == UINT32_C(2048));
    EXPECT(per_form[11] == UINT32_C(26112));
    EXPECT(per_form[12] == UINT32_C(5120));
}

static int vex_selector_kind(
    cdisasm_x86_mode mode,
    uint8_t opcode,
    uint8_t control)
{
    const uint8_t prefix = control & UINT8_C(3);
    const int w = (control & UINT8_C(0x80)) != 0;

    if ((control & UINT8_C(0x7c)) != UINT8_C(0x78)) {
        return 0;
    }
    if (opcode == UINT8_C(0x6e) && prefix == UINT8_C(1)) {
        return mode == CDISASM_MODE_64 && w ? 1 : 2;
    }
    if (opcode == UINT8_C(0x7e) && prefix == UINT8_C(1)) {
        return mode == CDISASM_MODE_64 && w ? 1 : 2;
    }
    if (opcode == UINT8_C(0x7e) && prefix == UINT8_C(2)) {
        return 1;
    }
    if (opcode == UINT8_C(0xd6) && prefix == UINT8_C(1)) {
        return 1;
    }
    return 0;
}

static void test_complete_vex_selector_space(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    static const uint8_t opcodes[] = {0x6e, 0x7e, 0xd6};
    uint32_t allocated = 0u;
    uint32_t collisions = 0u;
    uint32_t reserved = 0u;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const int long_mode = modes[mode_index] == CDISASM_MODE_64;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif
        size_t opcode_index;

        for (opcode_index = 0u; opcode_index < 3u; ++opcode_index) {
            unsigned int control;

            for (control = long_mode ? 0u : 0xc0u;
                 control <= UINT8_MAX;
                 ++control) {
                unsigned int modrm;

                for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                    uint8_t code[12] = {
                        0xc5, (uint8_t)control, opcodes[opcode_index],
                        (uint8_t)modrm,0x24,0x10,0x20,0x30,0x40
                    };
                    const int kind = vex_selector_kind(
                        modes[mode_index], opcodes[opcode_index],
                        (uint8_t)(control & UINT8_C(0x7f)));
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_X86, modes[mode_index], code,
                        sizeof(code),
#if USE_EXTRA_OPCODES
                        &flags,
#else
                        NULL,
#endif
                        &decoded_size);

                    if (kind == 1) {
#if USE_EXTRA_OPCODES
                        check_vmovq(&instruction, decoded_size,
                            vex_form(opcodes[opcode_index],
                                (uint8_t)control & 3u, (uint8_t)modrm),
                            0, 0);
#else
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                        ++allocated;
                    } else if (kind == 2) {
#if USE_EXTRA_OPCODES
                        EXPECT(decoded_size != 0u);
                        EXPECT(instruction.name_id == CDISASM_X86_NAME_VMOVD);
                        EXPECT(instruction.name_id != CDISASM_X86_NAME_VMOVQ);
#else
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                        ++collisions;
                    } else {
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_INVALID_INSTRUCTION));
                        ++reserved;
                    }
                }
            }

            {
                unsigned int extension;

                for (extension = long_mode ? 0u : 6u;
                     extension <= 7u;
                     ++extension) {
                    for (control = 0u; control <= UINT8_MAX; ++control) {
                        unsigned int modrm;

                        for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                            uint8_t code[12] = {
                                0xc4,
                                (uint8_t)((extension << 5) | 1u),
                                (uint8_t)control, opcodes[opcode_index],
                                (uint8_t)modrm,0x24,0x10,0x20,0x30,0x40
                            };
                            const int kind = vex_selector_kind(
                                modes[mode_index], opcodes[opcode_index],
                                (uint8_t)control);
                            uint32_t decoded_size;
                            cdisasm_instruction instruction = decode(
                                CDISASM_CPU_X86, modes[mode_index], code,
                                sizeof(code),
#if USE_EXTRA_OPCODES
                                &flags,
#else
                                NULL,
#endif
                                &decoded_size);

                            if (kind == 1) {
#if USE_EXTRA_OPCODES
                                check_vmovq(&instruction, decoded_size,
                                    vex_form(opcodes[opcode_index],
                                        (uint8_t)control & 3u,
                                        (uint8_t)modrm), 0, 0);
#else
                                EXPECT(decoded_size == 0u);
                                EXPECT(is_error_only(&instruction,
                                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                                ++allocated;
                            } else if (kind == 2) {
#if USE_EXTRA_OPCODES
                                EXPECT(decoded_size != 0u);
                                EXPECT(instruction.name_id
                                    == CDISASM_X86_NAME_VMOVD);
                                EXPECT(instruction.name_id
                                    != CDISASM_X86_NAME_VMOVQ);
#else
                                EXPECT(decoded_size == 0u);
                                EXPECT(is_error_only(&instruction,
                                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                                ++collisions;
                            } else {
                                EXPECT(decoded_size == 0u);
                                EXPECT(is_error_only(&instruction,
                                    CDISASM_STATUS_INVALID_INSTRUCTION));
                                ++reserved;
                            }
                        }
                    }
                }
            }
        }
    }

    EXPECT(allocated == UINT32_C(18432));
    EXPECT(collisions == UINT32_C(10240));
    EXPECT(reserved == UINT32_C(2625536));
}

static void test_evex_p0_u_w_modrm_space(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint32_t allocated = 0u;
    uint32_t collisions = 0u;
    uint32_t reserved = 0u;
    uint32_t w1_allocated = 0u;
    uint32_t w1_collisions = 0u;
    uint32_t w1_reserved = 0u;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const int long_mode = modes[mode_index] == CDISASM_MODE_64;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif
        size_t row_index;

        for (row_index = 0u; row_index < 4u; ++row_index) {
            unsigned int p0_index;
            const unsigned int p0_count = long_mode ? 32u : 4u;

            for (p0_index = 0u; p0_index < p0_count; ++p0_index) {
                const uint8_t p0 = long_mode
                    ? (uint8_t)((p0_index << 3) | 1u)
                    : (uint8_t)(0xc1u | (p0_index << 4));
                unsigned int w;

                for (w = 0u; w <= 1u; ++w) {
                    unsigned int u;

                    for (u = 0u; u <= 1u; ++u) {
                        unsigned int modrm;

                        for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                            const int reg =
                                (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
                            const int invalid_u = !u && (!long_mode || reg);
                            const int vmovd = !invalid_u
                                && (w == 0u
                                    || (!long_mode
                                        && rows[row_index].prefix == 1u
                                        && (rows[row_index].opcode == 0x6e
                                            || rows[row_index].opcode
                                                == 0x7e)));
                            uint8_t code[12] = {
                                0x62,p0,
                                (uint8_t)((w << 7) | 0x78u
                                    | (u << 2) | rows[row_index].prefix),
                                0x08,rows[row_index].opcode,(uint8_t)modrm,
                                0x24,0x10,0x20,0x30,0x40
                            };
                            uint32_t decoded_size;
                            cdisasm_instruction instruction = decode(
                                CDISASM_CPU_X86, modes[mode_index], code,
                                sizeof(code),
#if USE_EXTRA_OPCODES
                                &flags,
#else
                                NULL,
#endif
                                &decoded_size);

                            if (invalid_u) {
                                EXPECT(decoded_size == 0u);
                                EXPECT(is_error_only(&instruction,
                                    CDISASM_STATUS_INVALID_INSTRUCTION));
                                ++reserved;
                                if (w == 1u) {
                                    ++w1_reserved;
                                }
                            } else if (vmovd) {
#if USE_EXTRA_OPCODES
                                EXPECT(decoded_size != 0u);
                                EXPECT(instruction.name_id
                                    == CDISASM_X86_NAME_VMOVD);
#else
                                EXPECT(decoded_size == 0u);
                                EXPECT(is_error_only(&instruction,
                                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                                ++collisions;
                                if (w == 1u) {
                                    ++w1_collisions;
                                }
                            } else {
#if USE_EXTRA_OPCODES
                                check_vmovq(&instruction, decoded_size,
                                    evex_form(rows[row_index].opcode,
                                        rows[row_index].prefix,
                                        (uint8_t)modrm), 1,
                                    (p0 & UINT8_C(8)) != 0 || !u);
#else
                                EXPECT(decoded_size == 0u);
                                EXPECT(is_error_only(&instruction,
                                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                                ++allocated;
                                if (w == 1u) {
                                    ++w1_allocated;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    EXPECT(allocated == UINT32_C(61440));
    EXPECT(collisions == UINT32_C(69632));
    EXPECT(reserved == UINT32_C(32768));
    EXPECT(w1_allocated == UINT32_C(61440));
    EXPECT(w1_collisions == UINT32_C(4096));
    EXPECT(w1_reserved == UINT32_C(16384));
}

static void test_evex_p1_p2_spaces(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint32_t p1_allocated = 0u;
    uint32_t p1_collisions = 0u;
    uint32_t p1_reserved = 0u;
    uint32_t p2_allocated = 0u;
    uint32_t p2_collisions = 0u;
    uint32_t p2_reserved = 0u;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const int long_mode = modes[mode_index] == CDISASM_MODE_64;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif
        size_t row_index;

        for (row_index = 0u; row_index < 4u; ++row_index) {
            unsigned int value;

            for (value = 0u; value <= UINT8_MAX; ++value) {
                unsigned int representative;

                for (representative = 0u; representative < 2u;
                     ++representative) {
                    const uint8_t modrm = representative != 0u
                        ? UINT8_C(0xc1) : UINT8_C(0x01);
                    const uint8_t effective_prefix =
                        (uint8_t)value & UINT8_C(0x03);
                    const unsigned int u = (value >> 2) & 1u;
                    const unsigned int w = value >> 7;
                    const int selector =
                        (value & UINT8_C(0x78)) == UINT8_C(0x78)
                        && ((rows[row_index].opcode == UINT8_C(0x6e)
                                && effective_prefix == UINT8_C(1))
                            || (rows[row_index].opcode == UINT8_C(0x7e)
                                && (effective_prefix == UINT8_C(1)
                                    || effective_prefix == UINT8_C(2)))
                            || (rows[row_index].opcode == UINT8_C(0xd6)
                                && effective_prefix == UINT8_C(1)));
                    const int invalid_u = !u
                        && (!long_mode || representative != 0u);
                    const int vmovd = selector && !invalid_u
                        && (w == 0u
                            || (!long_mode
                                && effective_prefix == UINT8_C(1)
                                && (rows[row_index].opcode == 0x6e
                                    || rows[row_index].opcode == 0x7e)));
                    const int vmovq = selector && !invalid_u && !vmovd;
                    uint8_t code[12] = {
                        0x62,0xf1,(uint8_t)value,0x08,
                        rows[row_index].opcode,modrm,
                        0x24,0x10,0x20,0x30,0x40
                    };
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_X86, modes[mode_index], code,
                        sizeof(code),
#if USE_EXTRA_OPCODES
                        &flags,
#else
                        NULL,
#endif
                        &decoded_size);

                    if (vmovq) {
#if USE_EXTRA_OPCODES
                        check_vmovq(&instruction, decoded_size,
                            evex_form(rows[row_index].opcode,
                                effective_prefix, modrm), 1, !u);
#else
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                        ++p1_allocated;
                    } else if (vmovd) {
#if USE_EXTRA_OPCODES
                        EXPECT(decoded_size != 0u);
                        EXPECT(instruction.name_id == CDISASM_X86_NAME_VMOVD);
#else
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                        ++p1_collisions;
                    } else {
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_INVALID_INSTRUCTION));
                        ++p1_reserved;
                    }
                }
            }

            for (value = 0u; value <= UINT8_MAX; ++value) {
                unsigned int representative;

                for (representative = 0u; representative < 2u;
                     ++representative) {
                    const uint8_t modrm = representative != 0u
                        ? UINT8_C(0xc1) : UINT8_C(0x01);
                    const int p66_nonlong_collision = !long_mode
                        && rows[row_index].prefix == 1u
                        && (rows[row_index].opcode == 0x6e
                            || rows[row_index].opcode == 0x7e);
                    uint8_t code[12] = {
                        0x62,0xf1,
                        (uint8_t)(0xfcu | rows[row_index].prefix),
                        (uint8_t)value,rows[row_index].opcode,modrm,
                        0x24,0x10,0x20,0x30,0x40
                    };
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_X86, modes[mode_index], code,
                        sizeof(code),
#if USE_EXTRA_OPCODES
                        &flags,
#else
                        NULL,
#endif
                        &decoded_size);

                    if (value == UINT8_C(0x08)
                        && p66_nonlong_collision) {
#if USE_EXTRA_OPCODES
                        EXPECT(decoded_size != 0u);
                        EXPECT(instruction.name_id == CDISASM_X86_NAME_VMOVD);
#else
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                        ++p2_collisions;
                    } else if (value == UINT8_C(0x08)) {
#if USE_EXTRA_OPCODES
                        check_vmovq(&instruction, decoded_size,
                            evex_form(rows[row_index].opcode,
                                rows[row_index].prefix, modrm), 1, 0);
#else
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                        ++p2_allocated;
                    } else {
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_INVALID_INSTRUCTION));
                        ++p2_reserved;
                    }
                }
            }
        }
    }

    EXPECT(p1_allocated == UINT32_C(30));
    EXPECT(p1_collisions == UINT32_C(54));
    EXPECT(p1_reserved == UINT32_C(6060));
    EXPECT(p2_allocated == UINT32_C(16));
    EXPECT(p2_collisions == UINT32_C(8));
    EXPECT(p2_reserved == UINT32_C(6120));
}

static void test_extensions_profiles_runtime_and_collisions(void)
{
    static const uint8_t vmovd_vex[] = {0xc4,0xe1,0x79,0x6e,0xc1};
    static const uint8_t vmovd_evex[] = {0x62,0xf1,0x7d,0x08,0x6e,0xc1};

#if USE_EXTRA_OPCODES
    static const uint8_t vmovd_evex_nonlong[] = {
        0x62,0xf1,0xfd,0x08,0x6e,0xc1
    };
    static const uint8_t vmovd_evex_movzxc_7e[] = {
        0x62,0xf1,0x7e,0x08,0x7e,0xc1
    };
    static const uint8_t vmovd_evex_movzxc_d6[] = {
        0x62,0xf1,0x7d,0x08,0xd6,0xc1
    };
    static const uint8_t vex[] = {0xc4,0xe1,0xf9,0x6e,0xc1};
    static const uint8_t evex[] = {0x62,0xf1,0xfd,0x08,0x6e,0xc1};
    static const uint8_t b4[] = {0x62,0xf9,0xfd,0x08,0x6e,0xc1};
    static const uint8_t x4[] = {
        0x62,0xf1,0xf9,0x08,0x6e,0x44,0xa4,0x01
    };
    static const uint8_t vector_ext[] = {
        0x62,0x01,0xfe,0x08,0x7e,0xc1
    };
    static const uint8_t nonlong[] = {
        0x62,0xc1,0xfe,0x08,0x7e,0xc1
    };
    static const uint8_t legacy[] = {0x66,0x48,0x0f,0x6e,0xc1};
    static const uint8_t rex2[] = {0x66,0xd5,0x88,0x6e,0xc1};
    static const uint8_t map2[] = {0xc4,0xe2,0x79,0x6e,0xc1};
    cdisasm_x86_decode_flags avx = one_bit(CDISASM_X86_DECODE_BIT_AVX);
    cdisasm_x86_decode_flags avx512n =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512F_128N);
    cdisasm_x86_decode_flags apx = two_bits(
        CDISASM_X86_DECODE_BIT_AVX512F_128N,
        CDISASM_X86_DECODE_BIT_APX);
    cdisasm_x86_decode_flags only_avx512 =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512);
    cdisasm_x86_decode_flags movzxc =
        one_bit(CDISASM_X86_DECODE_BIT_AVX512_MOVZXC_128);
    cdisasm_x86_decode_flags available;
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        b4, sizeof(b4), &apx, &decoded_size);
    check_vmovq(&instruction, decoded_size, 5894, 1, 1);
    EXPECT(instruction.opcode[1].reg == gpr64(17u));

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        x4, sizeof(x4), &apx, &decoded_size);
    check_vmovq(&instruction, decoded_size, 5895, 1, 1);
    EXPECT(instruction.opcode[1].index_reg == gpr64(20u));
    EXPECT(instruction.opcode[1].imm == UINT64_C(8));

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        vector_ext, sizeof(vector_ext), &avx512n, &decoded_size);
    check_vmovq(&instruction, decoded_size, 5896, 1, 0);
    EXPECT(instruction.opcode[0].reg == xmm(24u));
    EXPECT(instruction.opcode[1].reg == xmm(25u));

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_16,
        nonlong, sizeof(nonlong), &avx512n, &decoded_size);
    check_vmovq(&instruction, decoded_size, 5896, 1, 0);
    EXPECT(instruction.opcode[0].reg == xmm(0u));
    EXPECT(instruction.opcode[1].reg == xmm(1u));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_32,
        nonlong, sizeof(nonlong), &avx512n, &decoded_size);
    check_vmovq(&instruction, decoded_size, 5896, 1, 0);

    expect_error("AVX runtime", CDISASM_CPU_X86, CDISASM_MODE_64,
        vex, sizeof(vex), &avx512n, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AVX512F_128N exact runtime", CDISASM_CPU_X86,
        CDISASM_MODE_64, evex, sizeof(evex), &only_avx512,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("APX runtime", CDISASM_CPU_X86, CDISASM_MODE_64,
        b4, sizeof(b4), &avx512n, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("Nehalem profile", CDISASM_CPU_NEHALEM,
        CDISASM_MODE_64, vex, sizeof(vex), &avx,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("Skylake client EVEX profile", CDISASM_CPU_SKYLAKE,
        CDISASM_MODE_64, evex, sizeof(evex), &avx512n,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("Skylake-SP APX profile", CDISASM_CPU_SKYLAKE_SP,
        CDISASM_MODE_64, b4, sizeof(b4), &apx,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_NEHALEM, CDISASM_MODE_64, &available)
        == CDISASM_STATUS_OK);
    expect_error("Nehalem VEX VMOVD collision profile",
        CDISASM_CPU_NEHALEM, CDISASM_MODE_64,
        vmovd_vex, sizeof(vmovd_vex), &available,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_SKYLAKE, CDISASM_MODE_64, &available)
        == CDISASM_STATUS_OK);
    expect_error("Skylake EVEX p66 VMOVD collision profile",
        CDISASM_CPU_SKYLAKE, CDISASM_MODE_64,
        vmovd_evex, sizeof(vmovd_evex), &available,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_SKYLAKE, CDISASM_MODE_32, &available)
        == CDISASM_STATUS_OK);
    expect_error("Skylake non-long EVEX p66 VMOVD collision profile",
        CDISASM_CPU_SKYLAKE, CDISASM_MODE_32,
        vmovd_evex_nonlong, sizeof(vmovd_evex_nonlong), &available,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64, &available)
        == CDISASM_STATUS_OK);
    expect_error("Skylake-SP EVEX F3/7E MOVZXC collision profile",
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        vmovd_evex_movzxc_7e, sizeof(vmovd_evex_movzxc_7e), &available,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("Skylake-SP EVEX 66/D6 MOVZXC collision profile",
        CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
        vmovd_evex_movzxc_d6, sizeof(vmovd_evex_movzxc_d6), &available,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    expect_error("p66 VMOVD exact runtime gate", CDISASM_CPU_X86,
        CDISASM_MODE_64, vmovd_evex, sizeof(vmovd_evex), &movzxc,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("MOVZXC exact runtime gate", CDISASM_CPU_X86,
        CDISASM_MODE_64, vmovd_evex_movzxc_7e,
        sizeof(vmovd_evex_movzxc_7e), &avx512n,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64, &available)
        == CDISASM_STATUS_OK);
    instruction = decode(CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64,
        evex, sizeof(evex), &available, &decoded_size);
    check_vmovq(&instruction, decoded_size, 5894, 1, 0);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        vmovd_vex, sizeof(vmovd_vex), &available, &decoded_size);
    EXPECT(decoded_size == sizeof(vmovd_vex));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VMOVD);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        vmovd_evex, sizeof(vmovd_evex), &available, &decoded_size);
    EXPECT(decoded_size == sizeof(vmovd_evex));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VMOVD);

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_AVX10, CDISASM_MODE_64, &available)
        == CDISASM_STATUS_OK);
    instruction = decode(CDISASM_CPU_AVX10, CDISASM_MODE_64,
        vmovd_evex_movzxc_7e, sizeof(vmovd_evex_movzxc_7e),
        &available, &decoded_size);
    EXPECT(decoded_size == sizeof(vmovd_evex_movzxc_7e));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VMOVD);
    EXPECT(instruction.form_id == UINT16_C(5839));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512_MOVZXC_128));
    instruction = decode(CDISASM_CPU_AVX10, CDISASM_MODE_64,
        vmovd_evex_movzxc_d6, sizeof(vmovd_evex_movzxc_d6),
        &available, &decoded_size);
    EXPECT(decoded_size == sizeof(vmovd_evex_movzxc_d6));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VMOVD);
    EXPECT(instruction.form_id == UINT16_C(5839));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512_MOVZXC_128));

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        legacy, sizeof(legacy), &available, &decoded_size);
    EXPECT(decoded_size == sizeof(legacy));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_MOVQ);
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_VEX) == 0u);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2, sizeof(rex2), &available, &decoded_size);
    EXPECT(decoded_size == sizeof(rex2));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_MOVQ);
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REX2) != 0u);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        map2, sizeof(map2), &available, &decoded_size);
    EXPECT(decoded_size == 0u
        || instruction.name_id != CDISASM_X86_NAME_VMOVQ);
#else
    expect_error("VEX VMOVD collision extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, vmovd_vex, sizeof(vmovd_vex), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("EVEX VMOVD collision extras off", CDISASM_CPU_X86,
        CDISASM_MODE_64, vmovd_evex, sizeof(vmovd_evex), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_invalid_and_truncated(void)
{
    static const uint8_t invalid[][7] = {
        {0xc5,0xea,0x7e,0xc1,0,0,0},
        {0xc5,0xfe,0x7e,0xc1,0,0,0},
        {0xc5,0xfb,0x7e,0xc1,0,0,0},
        {0xc5,0xfd,0xd6,0xc1,0,0,0},
        {0x62,0xf1,0xed,0x08,0x6e,0xc1,0},
        {0x62,0xf1,0xfd,0x28,0x6e,0xc1,0},
        {0x62,0xf1,0xfd,0x18,0x6e,0xc1,0},
        {0x62,0xf1,0xfd,0x09,0x6e,0xc1,0},
        {0x62,0xf1,0xf9,0x08,0x6e,0xc1,0},
        {0x62,0xf1,0xfc,0x08,0x6e,0xc1,0},
        {0x62,0xf1,0xfe,0x08,0xd6,0xc1,0}
    };
    static const uint8_t vex_short[] = {0xc4,0xe1,0xf9,0x6e};
    static const uint8_t evex_short[] = {0x62,0xf1,0xfd,0x08,0x6e};
    static const uint8_t bad_vex_sib[] = {0xc4,0xe1,0xed,0x6e,0x04};
    static const uint8_t bad_evex_sib[] = {0x62,0xf1,0xed,0x08,0x6e,0x04};
    size_t index;

    for (index = 0u; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
        expect_error("reserved VMOVQ selector", CDISASM_CPU_X86,
            CDISASM_MODE_64, invalid[index], sizeof(invalid[index]), NULL,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    expect_error("VEX missing ModRM", CDISASM_CPU_X86, CDISASM_MODE_64,
        vex_short, sizeof(vex_short), NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("EVEX missing ModRM", CDISASM_CPU_X86, CDISASM_MODE_64,
        evex_short, sizeof(evex_short), NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("bad VEX control missing SIB", CDISASM_CPU_X86,
        CDISASM_MODE_64, bad_vex_sib, sizeof(bad_vex_sib), NULL,
        CDISASM_STATUS_TRUNCATED);
    expect_error("bad EVEX control missing SIB", CDISASM_CPU_X86,
        CDISASM_MODE_64, bad_evex_sib, sizeof(bad_evex_sib), NULL,
        CDISASM_STATUS_TRUNCATED);
}

static void test_formatting(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const uint8_t vex[] = {0xc4,0x41,0xf9,0x6e,0xdc};
    static const uint8_t evex[] = {
        0x62,0x79,0xfe,0x08,0x7e,0x64,0x98,0xff
    };
    cdisasm_x86_decode_flags avx = one_bit(CDISASM_X86_DECODE_BIT_AVX);
    cdisasm_x86_decode_flags both = two_bits(
        CDISASM_X86_DECODE_BIT_AVX512F_128N,
        CDISASM_X86_DECODE_BIT_APX);
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    char output[128];

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        vex, sizeof(vex), &avx, &decoded_size);
    check_vmovq(&instruction, decoded_size, 5889, 0, 0);
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
        output, sizeof(output)) == strlen("vmovq xmm11, r12"));
    EXPECT(strcmp(output, "vmovq xmm11, r12") == 0);

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        evex, sizeof(evex), &both, &decoded_size);
    check_vmovq(&instruction, decoded_size, 5895, 1, 1);
    EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
        output, sizeof(output)) == strlen("vmovq -0x8(%r16,%rbx,4), %xmm12"));
    EXPECT(strcmp(output, "vmovq -0x8(%r16,%rbx,4), %xmm12") == 0);
#endif
}

int main(void)
{
#define RUN_TEST(function)                                                   \
    do {                                                                     \
        int before = failures;                                               \
        function();                                                          \
        if (failures != before) {                                            \
            fprintf(stderr, #function ": %d new failure(s)\n",             \
                failures - before);                                          \
        }                                                                    \
    } while (0)

    RUN_TEST(test_thirteen_forms);
    RUN_TEST(test_complete_allocated_domain);
    RUN_TEST(test_complete_vex_selector_space);
    RUN_TEST(test_evex_p0_u_w_modrm_space);
    RUN_TEST(test_evex_p1_p2_spaces);
    RUN_TEST(test_extensions_profiles_runtime_and_collisions);
    RUN_TEST(test_invalid_and_truncated);
    RUN_TEST(test_formatting);

#undef RUN_TEST

    if (failures != 0) {
        fprintf(stderr, "%d VMOVQ test(s) failed\n", failures);
        return 1;
    }
    puts("x86 VMOVQ tests passed (13 forms; 79,872 allocated; "
         "VEX reserved=2,625,536; EVEX factored controls exhaustive)");
    return 0;
}
