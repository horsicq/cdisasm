#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_X86_NAME_VGETEXPPH == UINT16_C(1126)
        && CDISASM_X86_NAME_VGETEXPSH == UINT16_C(1127)
        && CDISASM_X86_NAME_VGETEXPBF16 == UINT16_C(1128)
        && CDISASM_X86_NAME_VGETEXPBF16 < CDISASM_X86_NAME_COUNT
        && CDISASM_X86_NAME_COUNT == CDISASM_X86_NAME_LAST + UINT16_C(1),
    "16-bit VGETEXP append-only name IDs changed");
_Static_assert(CDISASM_NAME_VGETEXPPH == CDISASM_X86_NAME_VGETEXPPH
        && CDISASM_NAME_VGETEXPSH == CDISASM_X86_NAME_VGETEXPSH
        && CDISASM_NAME_VGETEXPBF16 == CDISASM_X86_NAME_VGETEXPBF16,
    "16-bit VGETEXP compatibility aliases changed");

enum getexp16_kind {
    GETEXP16_PH,
    GETEXP16_SH,
    GETEXP16_BF16,
    GETEXP16_KIND_COUNT
};

static int failures;

#if USE_EXTRA_OPCODES
#  define ACTIVE_FLAGS CDISASM_X86_DECODE_FLAG_ALL
#else
#  define ACTIVE_FLAGS CDISASM_X86_DECODE_FLAG_BASE
#endif

#define EXPECT(expression)                                                   \
    do {                                                                     \
        if (!(expression)) {                                                 \
            fprintf(stderr, "%s:%d: expectation failed: %s\n",           \
                __FILE__, __LINE__, #expression);                            \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

static cdisasm_instruction decode_mode(
    cdisasm_cpu_id cpu,
    cdisasm_mode mode,
    const uint8_t *code,
    size_t size,
    cdisasm_x86_decode_option flags,
    uint32_t *decoded_size)
{
    cdisasm_instruction instruction;

    memset(&instruction, UINT8_C(0xa5), sizeof(instruction));
    *decoded_size = cdisasm_x86_decode(
        cpu, mode, code, size, UINT64_C(0x2000), flags, &instruction);
    return instruction;
}

static cdisasm_instruction decode(
    cdisasm_cpu_id cpu,
    const uint8_t *code,
    size_t size,
    cdisasm_x86_decode_option flags,
    uint32_t *decoded_size)
{
    return decode_mode(cpu, CDISASM_MODE_64,
        code, size, flags, decoded_size);
}

static int is_error_only(
    const cdisasm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static void expect_status_mode(
    const char *label,
    cdisasm_cpu_id cpu,
    cdisasm_mode mode,
    const uint8_t *code,
    size_t size,
    cdisasm_x86_decode_option flags,
    cdisasm_status status)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode_mode(
        cpu, mode, code, size, flags, &decoded_size);

    if (decoded_size != 0u || !is_error_only(&instruction, status)) {
        fprintf(stderr,
            "%s: expected status=%u, actual=%u, decoded=%u\n",
            label, (unsigned int)status,
            (unsigned int)instruction.last_error_id,
            (unsigned int)decoded_size);
    }
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(&instruction, status));
}

static void expect_status(
    const char *label,
    cdisasm_cpu_id cpu,
    const uint8_t *code,
    size_t size,
    cdisasm_x86_decode_option flags,
    cdisasm_status status)
{
    expect_status_mode(label, cpu, CDISASM_MODE_64,
        code, size, flags, status);
}

static uint8_t kind_opcode(enum getexp16_kind kind)
{
    return kind == GETEXP16_SH ? UINT8_C(0x43) : UINT8_C(0x42);
}

static uint8_t kind_prefix(enum getexp16_kind kind)
{
    return kind == GETEXP16_BF16
        ? UINT8_C(0) : UINT8_C(1);
}

static unsigned int kind_source(enum getexp16_kind kind)
{
    return kind == GETEXP16_SH ? 7u : 0u;
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_name_id kind_name(enum getexp16_kind kind)
{
    if (kind == GETEXP16_PH) {
        return CDISASM_X86_NAME_VGETEXPPH;
    }
    if (kind == GETEXP16_SH) {
        return CDISASM_X86_NAME_VGETEXPSH;
    }
    return CDISASM_X86_NAME_VGETEXPBF16;
}
#endif

/* Build EVEX MAP6 opcode 42/43 with a register r/m operand. */
static void make_register_encoding(
    enum getexp16_kind kind,
    unsigned int w,
    unsigned int source,
    unsigned int destination,
    unsigned int rm,
    unsigned int ll,
    unsigned int mask,
    unsigned int zero,
    unsigned int evex_b,
    uint8_t code[15])
{
    uint8_t p0 = UINT8_C(0xf6);
    uint8_t p1 = (uint8_t)((w << 7)
        | (((~source) & 15u) << 3) | UINT8_C(0x04)
        | kind_prefix(kind));
    uint8_t p2 = (uint8_t)((ll << 5) | (mask & 7u));

    memset(code, 0, 15u);
    if ((destination & 8u) != 0u) {
        p0 &= (uint8_t)~UINT8_C(0x80);
    }
    if ((destination & 16u) != 0u) {
        p0 &= (uint8_t)~UINT8_C(0x10);
    }
    if ((rm & 8u) != 0u) {
        p0 &= (uint8_t)~UINT8_C(0x20);
    }
    if ((rm & 16u) != 0u) {
        p0 &= (uint8_t)~UINT8_C(0x40);
    }
    if ((source & 16u) == 0u) {
        p2 |= UINT8_C(0x08);
    }
    if (zero != 0u) {
        p2 |= UINT8_C(0x80);
    }
    if (evex_b != 0u) {
        p2 |= UINT8_C(0x10);
    }
    code[0] = UINT8_C(0x62);
    code[1] = p0;
    code[2] = p1;
    code[3] = p2;
    code[4] = kind_opcode(kind);
    code[5] = (uint8_t)(UINT8_C(0xc0)
        | ((destination & 7u) << 3) | (rm & 7u));
}

/* Raw ModRM allocation sweep; a zero SIB byte selects [rax+rax]. */
static void make_raw_encoding(
    enum getexp16_kind kind,
    unsigned int w,
    unsigned int ll,
    unsigned int evex_b,
    uint8_t modrm,
    uint8_t code[15])
{
    const unsigned int source = kind_source(kind);
    uint8_t p1 = (uint8_t)((w << 7)
        | (((~source) & 15u) << 3) | UINT8_C(0x04)
        | kind_prefix(kind));
    uint8_t p2 = (uint8_t)(ll << 5);

    memset(code, 0, 15u);
    if ((source & 16u) == 0u) {
        p2 |= UINT8_C(0x08);
    }
    if (evex_b != 0u) {
        p2 |= UINT8_C(0x10);
    }
    code[0] = UINT8_C(0x62);
    code[1] = UINT8_C(0xf6);
    code[2] = p1;
    code[3] = p2;
    code[4] = kind_opcode(kind);
    code[5] = modrm;
}

#if USE_EXTRA_OPCODES
static unsigned int expected_size(uint8_t modrm)
{
    const unsigned int mod = modrm >> 6;
    const unsigned int rm = modrm & 7u;
    unsigned int size = 6u;

    if (mod == 3u) {
        return size;
    }
    if (rm == 4u) {
        ++size;
    }
    if (mod == 1u) {
        ++size;
    } else if (mod == 2u || (mod == 0u && rm == 5u)) {
        size += 4u;
    }
    return size;
}
#endif

static int structurally_valid(
    enum getexp16_kind kind,
    unsigned int w,
    unsigned int ll,
    unsigned int evex_b,
    uint8_t modrm)
{
    const int is_register = (modrm >> 6) == 3u;

    if (w != 0u) {
        return 0;
    }
    if (evex_b == 0u) {
        return ll != 3u;
    }
    if (kind == GETEXP16_PH) {
        return is_register || ll != 3u;
    }
    if (kind == GETEXP16_SH) {
        return is_register;
    }
    return !is_register && ll != 3u;
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_reg_id vector_reg(unsigned int index, unsigned int bytes)
{
    if (bytes == 16u) {
        return (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0 + index);
    }
    if (bytes == 32u) {
        return (cdisasm_x86_reg_id)(CDISASM_X86_REG_YMM0 + index);
    }
    return (cdisasm_x86_reg_id)(CDISASM_X86_REG_ZMM0 + index);
}

static void verify_allocated(
    const cdisasm_instruction *instruction,
    enum getexp16_kind kind,
    unsigned int ll,
    unsigned int evex_b,
    uint8_t modrm)
{
    const int scalar = kind == GETEXP16_SH;
    const int is_register = (modrm >> 6) == 3u;
    const unsigned int vector_bytes = scalar ? 16u
        : evex_b != 0u && is_register ? 64u : 16u << ll;
    const unsigned int source_operand = scalar ? 2u : 1u;
    const cdisasm_opcode *source = &instruction->opcode[source_operand];

    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == kind_name(kind));
    EXPECT((instruction->opcode_flags & CDISASM_PREFIX_EVEX) != 0u);
    EXPECT(instruction->operand_count == (scalar ? 3u : 2u));
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].reg
        == vector_reg((modrm >> 3) & 7u, vector_bytes));
    EXPECT(instruction->opcode[0].size == vector_bytes);
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    if (scalar) {
        EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction->opcode[1].reg == CDISASM_X86_REG_XMM7);
        EXPECT(instruction->opcode[1].size == 16u);
        EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    }
    EXPECT(source->type == (is_register
        ? CDISASM_OPERAND_REGISTER : CDISASM_OPERAND_MEMORY));
    EXPECT(source->access == CDISASM_OPERAND_ACCESS_READ);
    if (is_register) {
        EXPECT(source->reg == vector_reg(modrm & 7u, vector_bytes));
        EXPECT(source->size == vector_bytes);
        EXPECT(source->broadcast == CDISASM_X86_BROADCAST_NONE);
    } else {
        const unsigned int memory_bytes = scalar || evex_b != 0u
            ? 2u : vector_bytes;
        EXPECT(source->size == memory_bytes);
        EXPECT(source->broadcast == (evex_b != 0u
            ? (cdisasm_x86_broadcast)(vector_bytes / 2u)
            : CDISASM_X86_BROADCAST_NONE));
    }
    EXPECT(instruction->sae
        == (is_register && evex_b != 0u
            ? CDISASM_X86_SAE_ENABLED : CDISASM_X86_SAE_NONE));
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    if (kind == GETEXP16_BF16) {
        EXPECT(cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX10_2));
    } else {
        EXPECT(cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX512F));
        EXPECT(cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX512FP16));
        EXPECT(cdisasm_instruction_has_x86_group(
                instruction, CDISASM_X86_GROUP_AVX512VL)
            == (!scalar && vector_bytes < 64u));
    }
}
#endif

static void test_complete_allocation_lattice(void)
{
    unsigned int allocated = 0u;
    unsigned int rejected = 0u;
    unsigned int kind_value;

    for (kind_value = 0u; kind_value != GETEXP16_KIND_COUNT;
         ++kind_value) {
        const enum getexp16_kind kind = (enum getexp16_kind)kind_value;
        unsigned int w;

        for (w = 0u; w != 2u; ++w) {
            unsigned int ll;

            for (ll = 0u; ll != 4u; ++ll) {
                unsigned int evex_b;

                for (evex_b = 0u; evex_b != 2u; ++evex_b) {
                    unsigned int raw_modrm;

                    for (raw_modrm = 0u; raw_modrm != 256u; ++raw_modrm) {
                        const int valid = structurally_valid(
                            kind, w, ll, evex_b, (uint8_t)raw_modrm);
                        uint8_t code[15];
                        uint32_t decoded_size;
                        cdisasm_instruction instruction;

                        make_raw_encoding(kind, w, ll, evex_b,
                            (uint8_t)raw_modrm, code);
                        instruction = decode(CDISASM_CPU_X86, code,
                            sizeof(code), ACTIVE_FLAGS, &decoded_size);
                        if (!valid) {
                            ++rejected;
                            EXPECT(decoded_size == 0u);
                            EXPECT(is_error_only(&instruction,
                                CDISASM_STATUS_INVALID_INSTRUCTION));
                            continue;
                        }
                        ++allocated;
#if USE_EXTRA_OPCODES
                        EXPECT(decoded_size
                            == expected_size((uint8_t)raw_modrm));
                        verify_allocated(&instruction,
                            kind, ll, evex_b, (uint8_t)raw_modrm);
#else
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                    }
                }
            }
        }
    }
    EXPECT(allocated == 3968u);
    EXPECT(rejected == 8320u);
}

static void test_vvvv_masks_and_register_extensions(void)
{
    unsigned int source;

    for (source = 0u; source != 32u; ++source) {
        uint8_t code[15];
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        make_register_encoding(GETEXP16_PH, 0u, source,
            1u, 2u, 2u, 0u, 0u, 0u, code);
        instruction = decode(CDISASM_CPU_X86, code, 6u,
            ACTIVE_FLAGS, &decoded_size);
        if (source != 0u) {
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(&instruction,
                CDISASM_STATUS_INVALID_INSTRUCTION));
        } else {
#if USE_EXTRA_OPCODES
            EXPECT(decoded_size == 6u);
            EXPECT(instruction.name_id == CDISASM_X86_NAME_VGETEXPPH);
#else
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(&instruction,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }

        make_register_encoding(GETEXP16_BF16, 0u, source,
            1u, 2u, 2u, 0u, 0u, 0u, code);
        instruction = decode(CDISASM_CPU_X86, code, 6u,
            ACTIVE_FLAGS, &decoded_size);
        if (source != 0u) {
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(&instruction,
                CDISASM_STATUS_INVALID_INSTRUCTION));
        } else {
#if USE_EXTRA_OPCODES
            EXPECT(decoded_size == 6u);
            EXPECT(instruction.name_id == CDISASM_X86_NAME_VGETEXPBF16);
#else
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(&instruction,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }

        make_register_encoding(GETEXP16_SH, 0u, source,
            1u, 2u, 0u, 0u, 0u, 0u, code);
        instruction = decode(CDISASM_CPU_X86, code, 6u,
            ACTIVE_FLAGS, &decoded_size);
#if USE_EXTRA_OPCODES
        EXPECT(decoded_size == 6u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VGETEXPSH);
        EXPECT(instruction.opcode[1].reg
            == (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0 + source));
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(&instruction,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }

    {
        unsigned int mask;

        for (mask = 0u; mask != 8u; ++mask) {
            unsigned int zero;

            for (zero = 0u; zero != 2u; ++zero) {
                uint8_t code[15];
                uint32_t decoded_size;
                cdisasm_instruction instruction;

                make_register_encoding(GETEXP16_PH, 0u, 0u,
                    1u, 2u, 2u, mask, zero, 0u, code);
                instruction = decode(CDISASM_CPU_X86, code, 6u,
                    ACTIVE_FLAGS, &decoded_size);
                if (zero != 0u && mask == 0u) {
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(&instruction,
                        CDISASM_STATUS_INVALID_INSTRUCTION));
                    continue;
                }
#if USE_EXTRA_OPCODES
                EXPECT(decoded_size == 6u);
                EXPECT(instruction.mask_reg == (mask != 0u
                    ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + mask)
                    : CDISASM_X86_REG_NONE));
                EXPECT(instruction.mask_mode == (mask == 0u
                    ? CDISASM_X86_MASK_NONE
                    : zero != 0u ? CDISASM_X86_MASK_ZERO
                                 : CDISASM_X86_MASK_MERGE));
                EXPECT(instruction.opcode[0].access
                    == (mask != 0u && zero == 0u
                        ? CDISASM_OPERAND_ACCESS_READ_WRITE
                        : CDISASM_OPERAND_ACCESS_WRITE));
#else
                EXPECT(decoded_size == 0u);
                EXPECT(is_error_only(&instruction,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
            }
        }
    }

#if USE_EXTRA_OPCODES
    {
        unsigned int destination;

        for (destination = 0u; destination != 32u; ++destination) {
            unsigned int rm;

            for (rm = 0u; rm != 32u; ++rm) {
                uint8_t code[15];
                uint32_t decoded_size;
                cdisasm_instruction instruction;

                make_register_encoding(GETEXP16_SH, 0u, 17u,
                    destination, rm, 0u, 0u, 0u, 0u, code);
                instruction = decode(CDISASM_CPU_X86, code, 6u,
                    CDISASM_X86_DECODE_FLAG_ALL, &decoded_size);
                EXPECT(decoded_size == 6u);
                EXPECT(instruction.opcode[0].reg
                    == (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0
                        + destination));
                EXPECT(instruction.opcode[1].reg
                    == CDISASM_X86_REG_XMM17);
                EXPECT(instruction.opcode[2].reg
                    == (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0 + rm));
            }
        }
    }
#endif
}

typedef struct oracle_case {
    const uint8_t *code;
    size_t size;
    cdisasm_x86_name_id name_id;
    uint8_t operand_count;
    uint8_t destination_size;
    uint8_t source_size;
    cdisasm_x86_broadcast broadcast;
    cdisasm_x86_sae sae;
} oracle_case;

static void test_xed_oracle_vectors(void)
{
    static const uint8_t ph_xmm[] =
        {0x62, 0xf6, 0x7d, 0x08, 0x42, 0xca};
    static const uint8_t ph_ymm[] =
        {0x62, 0xf6, 0x7d, 0x28, 0x42, 0xca};
    static const uint8_t ph_zmm[] =
        {0x62, 0xf6, 0x7d, 0x48, 0x42, 0xca};
    static const uint8_t sh[] =
        {0x62, 0xf6, 0x5d, 0x08, 0x43, 0xdd};
    static const uint8_t bf16[] =
        {0x62, 0xf6, 0x7c, 0x48, 0x42, 0xf7};
    static const uint8_t ph_memory[] =
        {0x62, 0xf6, 0x7d, 0x4b, 0x42, 0x48, 0x01};
    static const uint8_t ph_broadcast[] =
        {0x62, 0xf6, 0x7d, 0x5b, 0x42, 0x48, 0x01};
    static const uint8_t sh_memory[] =
        {0x62, 0xf6, 0x5d, 0x89, 0x43, 0x5a, 0x01};
    static const uint8_t bf16_memory[] =
        {0x62, 0xf6, 0x7c, 0x2d, 0x42, 0x5b, 0x01};
    static const uint8_t bf16_broadcast[] =
        {0x62, 0xf6, 0x7c, 0x3d, 0x42, 0x5b, 0x01};
    static const uint8_t ph_sae[] =
        {0x62, 0xf6, 0x7d, 0x18, 0x42, 0xca};
    static const uint8_t sh_sae[] =
        {0x62, 0xf6, 0x5d, 0x18, 0x43, 0xdd};
    static const oracle_case cases[] = {
        {ph_xmm, sizeof(ph_xmm), CDISASM_X86_NAME_VGETEXPPH,
            2u, 16u, 16u, 0u, 0u},
        {ph_ymm, sizeof(ph_ymm), CDISASM_X86_NAME_VGETEXPPH,
            2u, 32u, 32u, 0u, 0u},
        {ph_zmm, sizeof(ph_zmm), CDISASM_X86_NAME_VGETEXPPH,
            2u, 64u, 64u, 0u, 0u},
        {sh, sizeof(sh), CDISASM_X86_NAME_VGETEXPSH,
            3u, 16u, 16u, 0u, 0u},
        {bf16, sizeof(bf16), CDISASM_X86_NAME_VGETEXPBF16,
            2u, 64u, 64u, 0u, 0u},
        {ph_memory, sizeof(ph_memory), CDISASM_X86_NAME_VGETEXPPH,
            2u, 64u, 64u, 0u, 0u},
        {ph_broadcast, sizeof(ph_broadcast), CDISASM_X86_NAME_VGETEXPPH,
            2u, 64u, 2u, 32u, 0u},
        {sh_memory, sizeof(sh_memory), CDISASM_X86_NAME_VGETEXPSH,
            3u, 16u, 2u, 0u, 0u},
        {bf16_memory, sizeof(bf16_memory), CDISASM_X86_NAME_VGETEXPBF16,
            2u, 32u, 32u, 0u, 0u},
        {bf16_broadcast, sizeof(bf16_broadcast),
            CDISASM_X86_NAME_VGETEXPBF16,
            2u, 32u, 2u, 16u, 0u},
        {ph_sae, sizeof(ph_sae), CDISASM_X86_NAME_VGETEXPPH,
            2u, 64u, 64u, 0u, 1u},
        {sh_sae, sizeof(sh_sae), CDISASM_X86_NAME_VGETEXPSH,
            3u, 16u, 16u, 0u, 1u}
    };
    size_t index;

    for (index = 0u; index != sizeof(cases) / sizeof(cases[0]); ++index) {
        const oracle_case *test = &cases[index];
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, test->code, test->size,
            ACTIVE_FLAGS, &decoded_size);

#if USE_EXTRA_OPCODES
        const cdisasm_opcode *source =
            &instruction.opcode[test->operand_count - 1u];

        EXPECT(decoded_size == test->size);
        EXPECT(instruction.name_id == test->name_id);
        EXPECT(instruction.operand_count == test->operand_count);
        EXPECT(instruction.opcode[0].size == test->destination_size);
        EXPECT(source->size == test->source_size);
        EXPECT(source->broadcast == test->broadcast);
        EXPECT(instruction.sae == test->sae);
        EXPECT(instruction.rounding == CDISASM_X86_ROUNDING_NONE);
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(&instruction,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

static void test_modes_and_cpu_gates(void)
{
    uint8_t ph_zmm[15];
    uint8_t ph_xmm[15];
    uint8_t sh[15];
    uint8_t bf16[15];
    static const cdisasm_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t index;

    make_register_encoding(GETEXP16_PH, 0u, 0u,
        1u, 2u, 2u, 0u, 0u, 0u, ph_zmm);
    make_register_encoding(GETEXP16_PH, 0u, 0u,
        1u, 2u, 0u, 0u, 0u, 0u, ph_xmm);
    make_register_encoding(GETEXP16_SH, 0u, 2u,
        1u, 3u, 0u, 0u, 0u, 0u, sh);
    make_register_encoding(GETEXP16_BF16, 0u, 0u,
        1u, 2u, 2u, 0u, 0u, 0u, bf16);

    for (index = 0u; index != sizeof(modes) / sizeof(modes[0]); ++index) {
#if USE_EXTRA_OPCODES
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_mode(
            CDISASM_CPU_X86, modes[index], sh, 6u,
            CDISASM_X86_DECODE_FLAG_ALL, &decoded_size);

        EXPECT(decoded_size == 6u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VGETEXPSH);
#else
        expect_status_mode("16-bit VGETEXP OFF mode ownership",
            CDISASM_CPU_X86, modes[index], sh, 6u,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }

#if USE_EXTRA_OPCODES
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        instruction = decode(CDISASM_CPU_SAPPHIRE_RAPIDS,
            ph_zmm, 6u, CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
        EXPECT(decoded_size == 6u);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512F));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512FP16));
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512VL));

        instruction = decode(CDISASM_CPU_SAPPHIRE_RAPIDS,
            ph_xmm, 6u, CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
        EXPECT(decoded_size == 6u);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512VL));

        instruction = decode(CDISASM_CPU_GRANITE_RAPIDS,
            sh, 6u, CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
        EXPECT(decoded_size == 6u);
        instruction = decode(CDISASM_CPU_DIAMOND_RAPIDS,
            sh, 6u, CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
        EXPECT(decoded_size == 6u);

        expect_status("pre-FP16 profile", CDISASM_CPU_ICE_LAKE,
            ph_zmm, 6u, CDISASM_X86_DECODE_FLAG_AVX512,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_status("FP16 runtime base gate",
            CDISASM_CPU_SAPPHIRE_RAPIDS, ph_zmm, 6u,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_status("FP16 AVX10 selector on legacy profile",
            CDISASM_CPU_SAPPHIRE_RAPIDS, ph_zmm, 6u,
            CDISASM_X86_DECODE_FLAG_AVX10,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

        instruction = decode(CDISASM_CPU_AVX10,
            ph_xmm, 6u, CDISASM_X86_DECODE_FLAG_AVX10, &decoded_size);
        EXPECT(decoded_size == 6u);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX10_1));
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512F));
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512VL));
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512FP16));
        instruction = decode(CDISASM_CPU_APX,
            sh, 6u, CDISASM_X86_DECODE_FLAG_AVX10, &decoded_size);
        EXPECT(decoded_size == 6u);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX10_1));
        expect_status("FP16 legacy selector on AVX10 profile",
            CDISASM_CPU_AVX10, ph_zmm, 6u,
            CDISASM_X86_DECODE_FLAG_AVX512,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

        instruction = decode(CDISASM_CPU_DIAMOND_RAPIDS,
            bf16, 6u, CDISASM_X86_DECODE_FLAG_AVX10, &decoded_size);
        EXPECT(decoded_size == 6u);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX10_2));
        instruction = decode(CDISASM_CPU_AVX10,
            bf16, 6u, CDISASM_X86_DECODE_FLAG_AVX10, &decoded_size);
        EXPECT(decoded_size == 6u);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX10_2));
        expect_status("AVX10.1 profile lacks BF16 GETEXP",
            CDISASM_CPU_GRANITE_RAPIDS, bf16, 6u,
            CDISASM_X86_DECODE_FLAG_AVX10,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_status("pre-AVX10.2 profile lacks BF16 GETEXP",
            CDISASM_CPU_SAPPHIRE_RAPIDS, bf16, 6u,
            CDISASM_X86_DECODE_FLAG_AVX10,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_status("BF16 legacy AVX512 selector",
            CDISASM_CPU_DIAMOND_RAPIDS, bf16, 6u,
            CDISASM_X86_DECODE_FLAG_AVX512,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

        EXPECT((cdisasm_x86_cpu_decode_flag_mask(
                    CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_MODE_64)
                & CDISASM_X86_DECODE_FLAG_AVX512) != 0u);
        EXPECT((cdisasm_x86_cpu_decode_flag_mask(
                    CDISASM_CPU_GRANITE_RAPIDS, CDISASM_MODE_64)
                & CDISASM_X86_DECODE_FLAG_AVX10) != 0u);
        EXPECT((cdisasm_x86_cpu_decode_flag_mask(
                    CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64)
                & CDISASM_X86_DECODE_FLAG_AVX10) != 0u);
    }
#endif
}

typedef struct apx_x4_case {
    const uint8_t *code;
    size_t size;
    cdisasm_x86_name_id name_id;
    uint8_t source_operand;
    cdisasm_x86_reg_id base;
} apx_x4_case;

static void test_apx_x4_memory(void)
{
    static const uint8_t ph_x4[] =
        {0x62, 0xf6, 0x79, 0x48, 0x42, 0x0c, 0x08};
    static const uint8_t sh_x4[] =
        {0x62, 0xf6, 0x59, 0x08, 0x43, 0x0c, 0x08};
    static const uint8_t bf16_x4[] =
        {0x62, 0xf6, 0x78, 0x48, 0x42, 0x0c, 0x08};
    static const uint8_t ph_b4_x4[] =
        {0x62, 0xfe, 0x79, 0x48, 0x42, 0x0c, 0x08};
    static const uint8_t ph_u0_register[] =
        {0x62, 0xf6, 0x79, 0x48, 0x42, 0xca};
    static const uint8_t ph_u0_w1[] =
        {0x62, 0xf6, 0xf9, 0x48, 0x42, 0x0c, 0x08};
    static const uint8_t ph_u0_wrong_prefix[] =
        {0x62, 0xf6, 0x7a, 0x48, 0x42, 0x0c, 0x08};
    static const uint8_t map6_u0_opcode_neighbor[] =
        {0x62, 0xf6, 0x79, 0x48, 0x44, 0x0c, 0x08};
    static const apx_x4_case cases[] = {
        {ph_x4, sizeof(ph_x4), CDISASM_X86_NAME_VGETEXPPH,
            1u, CDISASM_X86_REG_RAX},
        {sh_x4, sizeof(sh_x4), CDISASM_X86_NAME_VGETEXPSH,
            2u, CDISASM_X86_REG_RAX},
        {bf16_x4, sizeof(bf16_x4), CDISASM_X86_NAME_VGETEXPBF16,
            1u, CDISASM_X86_REG_RAX},
        {ph_b4_x4, sizeof(ph_b4_x4), CDISASM_X86_NAME_VGETEXPPH,
            1u, CDISASM_X86_REG_R16}
    };
    size_t index;

    for (index = 0u; index != sizeof(cases) / sizeof(cases[0]); ++index) {
        const apx_x4_case *test = &cases[index];
#if USE_EXTRA_OPCODES
        const cdisasm_x86_decode_option apx_flags =
            CDISASM_X86_DECODE_FLAG_AVX10 | CDISASM_X86_DECODE_FLAG_APX;
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_APX, test->code, test->size,
            apx_flags, &decoded_size);
        const cdisasm_opcode *source =
            &instruction.opcode[test->source_operand];

        EXPECT(decoded_size == test->size);
        EXPECT(instruction.name_id == test->name_id);
        EXPECT(source->type == CDISASM_OPERAND_MEMORY);
        EXPECT(source->base_reg == test->base);
        EXPECT(source->index_reg == CDISASM_X86_REG_R17);
        EXPECT(source->scale == 1u);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, test->name_id == CDISASM_X86_NAME_VGETEXPBF16
                ? CDISASM_X86_GROUP_AVX10_2
                : CDISASM_X86_GROUP_AVX10_1));
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512F));

        expect_status("MAP6 X4 runtime APX gate",
            CDISASM_CPU_APX, test->code, test->size,
            CDISASM_X86_DECODE_FLAG_AVX10,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_status("MAP6 X4 CPU APX gate",
            CDISASM_CPU_AVX10, test->code, test->size,
            apx_flags, CDISASM_STATUS_INVALID_INSTRUCTION);
#else
        expect_status("extra-opcodes OFF MAP6 X4 ownership",
            CDISASM_CPU_X86, test->code, test->size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        expect_status_mode("MAP6 X4 non-long-mode reserved",
            CDISASM_CPU_APX, CDISASM_MODE_32,
            test->code, test->size, ACTIVE_FLAGS,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    expect_status("MAP6 U0 register reserved",
        CDISASM_CPU_APX, ph_u0_register, sizeof(ph_u0_register),
        ACTIVE_FLAGS, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("MAP6 U0 W=1 reserved",
        CDISASM_CPU_APX, ph_u0_w1, sizeof(ph_u0_w1),
        ACTIVE_FLAGS, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("MAP6 U0 prefix neighbor reserved",
        CDISASM_CPU_APX, ph_u0_wrong_prefix,
        sizeof(ph_u0_wrong_prefix), ACTIVE_FLAGS,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("MAP6 U0 opcode neighbor reserved",
        CDISASM_CPU_APX, map6_u0_opcode_neighbor,
        sizeof(map6_u0_opcode_neighbor), ACTIVE_FLAGS,
        CDISASM_STATUS_INVALID_INSTRUCTION);
}

static void test_reserved_neighbors_and_truncation(void)
{
    static const uint8_t wrong_map5[] =
        {0x62, 0xf5, 0x7d, 0x48, 0x42, 0xca};
    static const uint8_t wrong_map7[] =
        {0x62, 0xf7, 0x7d, 0x48, 0x42, 0xca};
    static const uint8_t ph_wrong_prefix[] =
        {0x62, 0xf6, 0x7e, 0x48, 0x42, 0xca};
    static const uint8_t sh_wrong_prefix[] =
        {0x62, 0xf6, 0x6c, 0x08, 0x43, 0xcb};
    static const uint8_t neighbor_opcode[] =
        {0x62, 0xf6, 0x7d, 0x48, 0x44, 0xca};
    static const uint8_t bad_u[] =
        {0x62, 0xf6, 0x79, 0x48, 0x42, 0xca};
    static const uint8_t ph_w1[] =
        {0x62, 0xf6, 0xfd, 0x48, 0x42, 0xca};
    static const uint8_t bf16_register_b[] =
        {0x62, 0xf6, 0x7c, 0x58, 0x42, 0xca};
    static const uint8_t sh_memory_b[] =
        {0x62, 0xf6, 0x6d, 0x18, 0x43, 0x08};
    static const uint8_t ph_memory_ll3[] =
        {0x62, 0xf6, 0x7d, 0x68, 0x42, 0x08};
    static const uint8_t zero_without_mask[] =
        {0x62, 0xf6, 0x7d, 0xc8, 0x42, 0xca};
    static const uint8_t legacy_prefix[] =
        {0x66, 0x62, 0xf6, 0x7d, 0x48, 0x42, 0xca};
    static const uint8_t truncated_prefix[] =
        {0x62, 0xf6, 0x7d};
    static const uint8_t truncated_modrm[] =
        {0x62, 0xf6, 0x7d, 0x48, 0x42};
    static const uint8_t truncated_sib[] =
        {0x62, 0xf6, 0x7d, 0x48, 0x42, 0x04};
    static const uint8_t truncated_displacement[] =
        {0x62, 0xf6, 0x7c, 0x28, 0x42, 0x85, 0x00};

    expect_status("MAP5 neighbor", CDISASM_CPU_X86,
        wrong_map5, sizeof(wrong_map5), ACTIVE_FLAGS,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_status("reserved MAP7", CDISASM_CPU_X86,
        wrong_map7, sizeof(wrong_map7), ACTIVE_FLAGS,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("PH wrong mandatory prefix", CDISASM_CPU_X86,
        ph_wrong_prefix, sizeof(ph_wrong_prefix), ACTIVE_FLAGS,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_status("SH wrong mandatory prefix", CDISASM_CPU_X86,
        sh_wrong_prefix, sizeof(sh_wrong_prefix), ACTIVE_FLAGS,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_status("MAP6 opcode neighbor", CDISASM_CPU_X86,
        neighbor_opcode, sizeof(neighbor_opcode), ACTIVE_FLAGS,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_status("reserved EVEX.U", CDISASM_CPU_X86,
        bad_u, sizeof(bad_u), ACTIVE_FLAGS,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("reserved PH W=1", CDISASM_CPU_X86,
        ph_w1, sizeof(ph_w1), ACTIVE_FLAGS,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("BF16 register EVEX.b", CDISASM_CPU_X86,
        bf16_register_b, sizeof(bf16_register_b), ACTIVE_FLAGS,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("SH memory EVEX.b", CDISASM_CPU_X86,
        sh_memory_b, sizeof(sh_memory_b), ACTIVE_FLAGS,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("PH broadcast LL3", CDISASM_CPU_X86,
        ph_memory_ll3, sizeof(ph_memory_ll3), ACTIVE_FLAGS,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("zero without mask", CDISASM_CPU_X86,
        zero_without_mask, sizeof(zero_without_mask), ACTIVE_FLAGS,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("legacy prefix before MAP6 EVEX", CDISASM_CPU_X86,
        legacy_prefix, sizeof(legacy_prefix), ACTIVE_FLAGS,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("truncated MAP6 EVEX prefix", CDISASM_CPU_X86,
        truncated_prefix, sizeof(truncated_prefix), ACTIVE_FLAGS,
        CDISASM_STATUS_TRUNCATED);
    expect_status("truncated MAP6 ModRM", CDISASM_CPU_X86,
        truncated_modrm, sizeof(truncated_modrm), ACTIVE_FLAGS,
        CDISASM_STATUS_TRUNCATED);
    expect_status("truncated MAP6 SIB", CDISASM_CPU_X86,
        truncated_sib, sizeof(truncated_sib), ACTIVE_FLAGS,
        CDISASM_STATUS_TRUNCATED);
    expect_status("truncated MAP6 displacement", CDISASM_CPU_X86,
        truncated_displacement, sizeof(truncated_displacement), ACTIVE_FLAGS,
        CDISASM_STATUS_TRUNCATED);
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(
    const uint8_t *code,
    size_t size,
    uint32_t flags,
    const char *expected)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        CDISASM_CPU_X86, code, size,
        CDISASM_X86_DECODE_FLAG_ALL, &decoded_size);
    char text[160];
    size_t length;

    EXPECT(decoded_size == size);
    length = cdisasm_x86_format(&instruction, flags, text, sizeof(text));
    if (strcmp(text, expected) != 0) {
        fprintf(stderr, "format mismatch: expected '%s', actual '%s'\n",
            expected, text);
    }
    EXPECT(length == strlen(expected));
    EXPECT(strcmp(text, expected) == 0);
}

static void test_formatting(void)
{
    static const uint8_t ph[] =
        {0x62, 0xf6, 0x7d, 0x48, 0x42, 0xca};
    static const uint8_t sh[] =
        {0x62, 0xf6, 0x5d, 0x08, 0x43, 0xdd};
    static const uint8_t bf16[] =
        {0x62, 0xf6, 0x7c, 0x48, 0x42, 0xf7};
    static const uint8_t ph_memory[] =
        {0x62, 0xf6, 0x7d, 0x4b, 0x42, 0x48, 0x01};
    static const uint8_t ph_broadcast[] =
        {0x62, 0xf6, 0x7d, 0x5b, 0x42, 0x48, 0x01};
    static const uint8_t sh_memory[] =
        {0x62, 0xf6, 0x5d, 0x89, 0x43, 0x5a, 0x01};
    static const uint8_t bf16_memory[] =
        {0x62, 0xf6, 0x7c, 0x2d, 0x42, 0x5b, 0x01};
    static const uint8_t bf16_broadcast[] =
        {0x62, 0xf6, 0x7c, 0x3d, 0x42, 0x5b, 0x01};
    static const uint8_t ph_sae[] =
        {0x62, 0xf6, 0x7d, 0x18, 0x42, 0xca};
    static const uint8_t sh_sae[] =
        {0x62, 0xf6, 0x5d, 0x18, 0x43, 0xdd};

    expect_format(ph, sizeof(ph), CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vgetexpph zmm1, zmm2");
    expect_format(ph, sizeof(ph), CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vgetexpph %zmm2, %zmm1");
    expect_format(sh, sizeof(sh), CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vgetexpsh xmm3, xmm4, xmm5");
    expect_format(sh, sizeof(sh), CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vgetexpsh %xmm5, %xmm4, %xmm3");
    expect_format(bf16, sizeof(bf16), CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vgetexpbf16 zmm6, zmm7");
    expect_format(bf16, sizeof(bf16), CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vgetexpbf16 %zmm7, %zmm6");
    expect_format(ph_memory, sizeof(ph_memory),
        CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vgetexpph zmm1 {k3}, zmmword ptr [rax + 0x40]");
    expect_format(ph_memory, sizeof(ph_memory),
        CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vgetexpph 0x40(%rax), %zmm1{%k3}");
    expect_format(ph_broadcast, sizeof(ph_broadcast),
        CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vgetexpph zmm1 {k3}, word ptr [rax + 0x2]{1to32}");
    expect_format(ph_broadcast, sizeof(ph_broadcast),
        CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vgetexpph 0x2(%rax){1to32}, %zmm1{%k3}");
    expect_format(sh_memory, sizeof(sh_memory),
        CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vgetexpsh xmm3 {k1}{z}, xmm4, word ptr [rdx + 0x2]");
    expect_format(sh_memory, sizeof(sh_memory),
        CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vgetexpsh 0x2(%rdx), %xmm4, %xmm3{%k1}{z}");
    expect_format(bf16_memory, sizeof(bf16_memory),
        CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vgetexpbf16 ymm3 {k5}, ymmword ptr [rbx + 0x20]");
    expect_format(bf16_memory, sizeof(bf16_memory),
        CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vgetexpbf16 0x20(%rbx), %ymm3{%k5}");
    expect_format(bf16_broadcast, sizeof(bf16_broadcast),
        CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vgetexpbf16 ymm3 {k5}, word ptr [rbx + 0x2]{1to16}");
    expect_format(bf16_broadcast, sizeof(bf16_broadcast),
        CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vgetexpbf16 0x2(%rbx){1to16}, %ymm3{%k5}");
    expect_format(ph_sae, sizeof(ph_sae),
        CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vgetexpph zmm1, zmm2, {sae}");
    expect_format(ph_sae, sizeof(ph_sae),
        CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vgetexpph {sae}, %zmm2, %zmm1");
    expect_format(sh_sae, sizeof(sh_sae),
        CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vgetexpsh xmm3, xmm4, xmm5, {sae}");
    expect_format(sh_sae, sizeof(sh_sae),
        CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vgetexpsh {sae}, %xmm5, %xmm4, %xmm3");
    expect_format(bf16, sizeof(bf16),
        CDISASM_FORMAT_SYNTAX_X86_INTEL | CDISASM_FORMAT_UPPERCASE_OPCODE,
        "VGETEXPBF16 zmm6, zmm7");
}
#endif

int main(void)
{
    test_complete_allocation_lattice();
    test_vvvv_masks_and_register_extensions();
    test_xed_oracle_vectors();
    test_modes_and_cpu_gates();
    test_apx_x4_memory();
    test_reserved_neighbors_and_truncation();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatting();
#endif

    if (failures != 0) {
        fprintf(stderr,
            "x86 16-bit VGETEXP tests failed: %d (extra=%d format=%d)\n",
            failures, USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
        return 1;
    }
    printf("x86 16-bit VGETEXP tests passed "
        "(12288 lattice cells, extra=%d format=%d)\n",
        USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
    return 0;
}
