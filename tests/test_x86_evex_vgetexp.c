#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_X86_NAME_VGETEXPPS == UINT16_C(1122)
        && CDISASM_X86_NAME_VGETEXPPD == UINT16_C(1123)
        && CDISASM_X86_NAME_VGETEXPSS == UINT16_C(1124)
        && CDISASM_X86_NAME_VGETEXPSD == UINT16_C(1125)
        && CDISASM_X86_NAME_VGETEXPBF16 < CDISASM_X86_NAME_COUNT
        && CDISASM_X86_NAME_COUNT == CDISASM_X86_NAME_LAST + UINT16_C(1),
    "VGETEXP append-only name IDs changed");
_Static_assert(CDISASM_NAME_VGETEXPPS == CDISASM_X86_NAME_VGETEXPPS
        && CDISASM_NAME_VGETEXPPD == CDISASM_X86_NAME_VGETEXPPD
        && CDISASM_NAME_VGETEXPSS == CDISASM_X86_NAME_VGETEXPSS
        && CDISASM_NAME_VGETEXPSD == CDISASM_X86_NAME_VGETEXPSD,
    "VGETEXP compatibility aliases changed");

static int failures;

#if USE_EXTRA_OPCODES
#  define ACTIVE_FLAGS CDISASM_X86_DECODE_FLAG_AVX512
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
        cpu, mode, code, size, UINT64_C(0x1000), flags, &instruction);
    return instruction;
}

static cdisasm_instruction decode(
    cdisasm_cpu_id cpu,
    const uint8_t *code,
    size_t size,
    cdisasm_x86_decode_option flags,
    uint32_t *decoded_size)
{
    return decode_mode(cpu, CDISASM_MODE_64, code, size, flags, decoded_size);
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

/* Build EVEX.66.0F38 42/43 with a register r/m operand. */
static void make_register_encoding(
    uint8_t opcode,
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
    uint8_t p0 = UINT8_C(0xf2);
    uint8_t p1 = (uint8_t)((w << 7)
        | (((~source) & 15u) << 3) | UINT8_C(0x05));
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
    code[4] = opcode;
    code[5] = (uint8_t)(UINT8_C(0xc0)
        | ((destination & 7u) << 3) | (rm & 7u));
}

/* Raw ModRM allocation sweep; the zeroed SIB selects [rax+rax]. */
static void make_raw_encoding(
    uint8_t opcode,
    unsigned int w,
    unsigned int source,
    unsigned int ll,
    unsigned int evex_b,
    uint8_t modrm,
    uint8_t code[15])
{
    uint8_t p1 = (uint8_t)((w << 7)
        | (((~source) & 15u) << 3) | UINT8_C(0x05));
    uint8_t p2 = (uint8_t)(ll << 5);

    memset(code, 0, 15u);
    if ((source & 16u) == 0u) {
        p2 |= UINT8_C(0x08);
    }
    if (evex_b != 0u) {
        p2 |= UINT8_C(0x10);
    }
    code[0] = UINT8_C(0x62);
    code[1] = UINT8_C(0xf2);
    code[2] = p1;
    code[3] = p2;
    code[4] = opcode;
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

static cdisasm_x86_name_id expected_name(uint8_t opcode, unsigned int w)
{
    if (opcode == UINT8_C(0x42)) {
        return w != 0u
            ? CDISASM_X86_NAME_VGETEXPPD : CDISASM_X86_NAME_VGETEXPPS;
    }
    return w != 0u
        ? CDISASM_X86_NAME_VGETEXPSD : CDISASM_X86_NAME_VGETEXPSS;
}
#endif

static int structurally_valid(
    uint8_t opcode,
    unsigned int ll,
    unsigned int evex_b,
    uint8_t modrm)
{
    const int is_register = (modrm >> 6) == 3u;

    if (evex_b == 0u) {
        return ll != 3u;
    }
    if (is_register) {
        return 1;
    }
    return opcode == UINT8_C(0x42) && ll != 3u;
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
    uint8_t opcode,
    unsigned int w,
    unsigned int ll,
    unsigned int evex_b,
    uint8_t modrm)
{
    const int scalar = opcode == UINT8_C(0x43);
    const int is_register = (modrm >> 6) == 3u;
    const unsigned int vector_bytes = scalar ? 16u
        : evex_b != 0u && is_register ? 64u : 16u << ll;
    const unsigned int element_bytes = w != 0u ? 8u : 4u;
    const unsigned int source_operand = scalar ? 2u : 1u;
    const cdisasm_opcode *source = &instruction->opcode[source_operand];

    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == expected_name(opcode, w));
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
            ? element_bytes : vector_bytes;
        EXPECT(source->size == memory_bytes);
        EXPECT(source->broadcast == (evex_b != 0u
            ? (cdisasm_x86_broadcast)(vector_bytes / element_bytes)
            : CDISASM_X86_BROADCAST_NONE));
    }
    EXPECT(instruction->sae == (is_register && evex_b != 0u
        ? CDISASM_X86_SAE_ENABLED : CDISASM_X86_SAE_NONE));
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX512F));
    EXPECT(cdisasm_instruction_has_x86_group(
            instruction, CDISASM_X86_GROUP_AVX512VL)
        == (!scalar && vector_bytes < 64u));
}
#endif

static void test_complete_allocation_lattice(void)
{
    unsigned int allocated = 0u;
    unsigned int rejected = 0u;
    unsigned int opcode_index;

    for (opcode_index = 0u; opcode_index != 2u; ++opcode_index) {
        const uint8_t opcode = (uint8_t)(UINT8_C(0x42) + opcode_index);
        unsigned int w;

        for (w = 0u; w != 2u; ++w) {
            unsigned int ll;

            for (ll = 0u; ll != 4u; ++ll) {
                unsigned int evex_b;

                for (evex_b = 0u; evex_b != 2u; ++evex_b) {
                    unsigned int raw_modrm;

                    for (raw_modrm = 0u; raw_modrm != 256u; ++raw_modrm) {
                        const int valid = structurally_valid(
                            opcode, ll, evex_b, (uint8_t)raw_modrm);
                        const unsigned int source = opcode == UINT8_C(0x42)
                            ? 0u : 7u;
                        uint8_t code[15];
                        uint32_t decoded_size;
                        cdisasm_instruction instruction;

                        make_raw_encoding(opcode, w, source, ll, evex_b,
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
                        verify_allocated(&instruction, opcode, w, ll, evex_b,
                            (uint8_t)raw_modrm);
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
    EXPECT(allocated == 5248u);
    EXPECT(rejected == 2944u);
}

static void test_vvvv_and_register_extensions(void)
{
    unsigned int source;

    for (source = 0u; source != 32u; ++source) {
        uint8_t code[15];
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        make_register_encoding(UINT8_C(0x42), 0u, source,
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
            EXPECT(instruction.name_id == CDISASM_X86_NAME_VGETEXPPS);
#else
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(&instruction,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }

        make_register_encoding(UINT8_C(0x43), 1u, source,
            1u, 2u, 0u, 0u, 0u, 0u, code);
        instruction = decode(CDISASM_CPU_X86, code, 6u,
            ACTIVE_FLAGS, &decoded_size);
#if USE_EXTRA_OPCODES
        EXPECT(decoded_size == 6u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VGETEXPSD);
        EXPECT(instruction.opcode[1].reg
            == (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0 + source));
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(&instruction,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
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

                make_register_encoding(UINT8_C(0x43), 0u, 17u,
                    destination, rm, 0u, 0u, 0u, 0u, code);
                instruction = decode(CDISASM_CPU_X86, code, 6u,
                    CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
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
    static const uint8_t ps[] =
        {0x62, 0xf2, 0x7d, 0x48, 0x42, 0xca};
    static const uint8_t pd[] =
        {0x62, 0xf2, 0xfd, 0x48, 0x42, 0xdc};
    static const uint8_t ss[] =
        {0x62, 0xf2, 0x4d, 0x08, 0x43, 0xef};
    static const uint8_t sd[] =
        {0x62, 0x52, 0xb5, 0x08, 0x43, 0xc2};
    static const uint8_t ps_memory[] =
        {0x62, 0xf2, 0x7d, 0xca, 0x42, 0x48, 0x01};
    static const uint8_t ps_broadcast[] =
        {0x62, 0xf2, 0x7d, 0x5a, 0x42, 0x08};
    static const uint8_t pd_memory[] =
        {0x62, 0xf2, 0xfd, 0xac, 0x42, 0x5b, 0x01};
    static const uint8_t pd_broadcast[] =
        {0x62, 0xf2, 0xfd, 0x1e, 0x42, 0x29};
    static const uint8_t ss_memory[] =
        {0x62, 0xf2, 0x3d, 0x89, 0x43, 0x7a, 0x01};
    static const uint8_t sd_memory[] =
        {0x62, 0x72, 0xad, 0x0b, 0x43, 0x4e, 0x01};
    static const uint8_t ps_sae[] =
        {0x62, 0x52, 0x7d, 0x9d, 0x42, 0xdc};
    static const uint8_t ss_sae[] =
        {0x62, 0x52, 0x8d, 0x9f, 0x43, 0xef};
    static const uint8_t address_prefixed[] =
        {0x67, 0x62, 0xf2, 0x7d, 0x48, 0x42, 0xca};
    static const uint8_t segment_prefixed[] =
        {0x64, 0x62, 0xf2, 0x7d, 0x48, 0x42, 0x00};
    static const oracle_case cases[] = {
        {ps, sizeof(ps), CDISASM_X86_NAME_VGETEXPPS, 2u, 64u, 64u, 0u, 0u},
        {pd, sizeof(pd), CDISASM_X86_NAME_VGETEXPPD, 2u, 64u, 64u, 0u, 0u},
        {ss, sizeof(ss), CDISASM_X86_NAME_VGETEXPSS, 3u, 16u, 16u, 0u, 0u},
        {sd, sizeof(sd), CDISASM_X86_NAME_VGETEXPSD, 3u, 16u, 16u, 0u, 0u},
        {ps_memory, sizeof(ps_memory), CDISASM_X86_NAME_VGETEXPPS,
            2u, 64u, 64u, 0u, 0u},
        {ps_broadcast, sizeof(ps_broadcast), CDISASM_X86_NAME_VGETEXPPS,
            2u, 64u, 4u, 16u, 0u},
        {pd_memory, sizeof(pd_memory), CDISASM_X86_NAME_VGETEXPPD,
            2u, 32u, 32u, 0u, 0u},
        {pd_broadcast, sizeof(pd_broadcast), CDISASM_X86_NAME_VGETEXPPD,
            2u, 16u, 8u, 2u, 0u},
        {ss_memory, sizeof(ss_memory), CDISASM_X86_NAME_VGETEXPSS,
            3u, 16u, 4u, 0u, 0u},
        {sd_memory, sizeof(sd_memory), CDISASM_X86_NAME_VGETEXPSD,
            3u, 16u, 8u, 0u, 0u},
        {ps_sae, sizeof(ps_sae), CDISASM_X86_NAME_VGETEXPPS,
            2u, 64u, 64u, 0u, 1u},
        {ss_sae, sizeof(ss_sae), CDISASM_X86_NAME_VGETEXPSD,
            3u, 16u, 16u, 0u, 1u},
        {address_prefixed, sizeof(address_prefixed),
            CDISASM_X86_NAME_VGETEXPPS, 2u, 64u, 64u, 0u, 0u},
        {segment_prefixed, sizeof(segment_prefixed),
            CDISASM_X86_NAME_VGETEXPPS, 2u, 64u, 64u, 0u, 0u}
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

#if USE_EXTRA_OPCODES
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, address_prefixed, sizeof(address_prefixed),
            CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);

        EXPECT(decoded_size == sizeof(address_prefixed));
        EXPECT(instruction.encoding.prefix_size == 5u);
        EXPECT(instruction.encoding.opcode_offset == 5u);
        EXPECT(instruction.encoding.modrm_offset == 6u);

        instruction = decode(
            CDISASM_CPU_X86, segment_prefixed, sizeof(segment_prefixed),
            CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
        EXPECT(decoded_size == sizeof(segment_prefixed));
        EXPECT(instruction.encoding.prefix_size == 5u);
        EXPECT(instruction.encoding.opcode_offset == 5u);
        EXPECT(instruction.encoding.modrm_offset == 6u);
        EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.opcode[1].segment_reg == CDISASM_X86_REG_FS);
        EXPECT((instruction.opcode[1].flags
                & CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT) != 0u);
    }
#endif
}

static void test_masks_modes_and_gates(void)
{
    unsigned int mask;

    for (mask = 0u; mask != 8u; ++mask) {
        unsigned int zero;

        for (zero = 0u; zero != 2u; ++zero) {
            uint8_t code[15];
            uint32_t decoded_size;
            cdisasm_instruction instruction;

            make_register_encoding(UINT8_C(0x42), 0u, 0u,
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

    {
        static const cdisasm_mode modes[] = {
            CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
        };
        uint8_t code[15];
        size_t index;

        make_register_encoding(UINT8_C(0x43), 0u, 2u,
            1u, 3u, 0u, 0u, 0u, 0u, code);
        for (index = 0u; index != sizeof(modes) / sizeof(modes[0]); ++index) {
#if USE_EXTRA_OPCODES
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode_mode(
                CDISASM_CPU_X86, modes[index], code, 6u,
                CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);

            EXPECT(decoded_size == 6u);
            EXPECT(instruction.name_id == CDISASM_X86_NAME_VGETEXPSS);
#else
            expect_status_mode("VGETEXP OFF mode ownership",
                CDISASM_CPU_X86, modes[index], code, 6u,
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }

#if USE_EXTRA_OPCODES
    {
        uint8_t packed_512[15];
        uint8_t packed_128[15];
        uint8_t scalar[15];
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        make_register_encoding(UINT8_C(0x42), 0u, 0u,
            1u, 2u, 2u, 0u, 0u, 0u, packed_512);
        make_register_encoding(UINT8_C(0x42), 0u, 0u,
            1u, 2u, 0u, 0u, 0u, 0u, packed_128);
        make_register_encoding(UINT8_C(0x43), 0u, 2u,
            1u, 3u, 0u, 0u, 0u, 0u, scalar);

        instruction = decode(CDISASM_CPU_SKYLAKE_SP, packed_512, 6u,
            CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
        EXPECT(decoded_size == 6u);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512F));
        instruction = decode(CDISASM_CPU_SKYLAKE_SP, packed_128, 6u,
            CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
        EXPECT(decoded_size == 6u);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512VL));

        expect_status("pre-AVX512 profile", CDISASM_CPU_SKYLAKE,
            packed_512, 6u, CDISASM_X86_DECODE_FLAG_AVX512,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_status("runtime base gate", CDISASM_CPU_SKYLAKE_SP,
            packed_512, 6u, CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_status("runtime AVX10 selector on legacy profile",
            CDISASM_CPU_SKYLAKE_SP, packed_512, 6u,
            CDISASM_X86_DECODE_FLAG_AVX10,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

        instruction = decode(CDISASM_CPU_AVX10, packed_512, 6u,
            CDISASM_X86_DECODE_FLAG_AVX10, &decoded_size);
        EXPECT(decoded_size == 6u);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX10_1));
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512F));
        instruction = decode(CDISASM_CPU_AVX10, packed_128, 6u,
            CDISASM_X86_DECODE_FLAG_AVX10, &decoded_size);
        EXPECT(decoded_size == 6u);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX10_1));
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512VL));
        instruction = decode(CDISASM_CPU_AVX10, scalar, 6u,
            CDISASM_X86_DECODE_FLAG_AVX10, &decoded_size);
        EXPECT(decoded_size == 6u);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX10_1));
        expect_status("legacy selector on AVX10 profile", CDISASM_CPU_AVX10,
            packed_512, 6u, CDISASM_X86_DECODE_FLAG_AVX512,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

        instruction = decode(CDISASM_CPU_KNIGHTS_MILL, packed_512, 6u,
            CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
        EXPECT(decoded_size == 6u);
        instruction = decode(CDISASM_CPU_KNIGHTS_MILL, scalar, 6u,
            CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
        EXPECT(decoded_size == 6u);
        expect_status("KNM lacks AVX512VL", CDISASM_CPU_KNIGHTS_MILL,
            packed_128, 6u, CDISASM_X86_DECODE_FLAG_AVX512,
            CDISASM_STATUS_INVALID_INSTRUCTION);

        EXPECT((cdisasm_x86_cpu_decode_flag_mask(
                    CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64)
                & CDISASM_X86_DECODE_FLAG_AVX512) != 0u);
        EXPECT((cdisasm_x86_cpu_decode_flag_mask(
                    CDISASM_CPU_SKYLAKE, CDISASM_MODE_64)
                & CDISASM_X86_DECODE_FLAG_AVX512) == 0u);
        EXPECT((cdisasm_x86_cpu_decode_flag_mask(
                    CDISASM_CPU_AVX10, CDISASM_MODE_64)
                & CDISASM_X86_DECODE_FLAG_AVX10) != 0u);
    }
#endif
}

static void test_reserved_and_truncated(void)
{
    static const uint8_t bad_map[] =
        {0x62, 0xf1, 0x7d, 0x48, 0x42, 0xca};
    static const uint8_t bad_prefix[] =
        {0x62, 0xf2, 0x7c, 0x48, 0x42, 0xca};
    static const uint8_t bad_u[] =
        {0x62, 0xf2, 0x79, 0x48, 0x42, 0xca};
    static const uint8_t scalar_b_memory[] =
        {0x62, 0xf2, 0x6d, 0x18, 0x43, 0x08};
    static const uint8_t packed_ll3_memory[] =
        {0x62, 0xf2, 0x7d, 0x68, 0x42, 0x08};
    static const uint8_t scalar_ll3[] =
        {0x62, 0xf2, 0x6d, 0x68, 0x43, 0xca};
    static const uint8_t zero_without_mask[] =
        {0x62, 0xf2, 0x7d, 0xc8, 0x42, 0xca};
    static const uint8_t legacy_prefix[] =
        {0x66, 0x62, 0xf2, 0x7d, 0x48, 0x42, 0xca};
    static const uint8_t truncated_prefix[] =
        {0x62, 0xf2, 0x7d};
    static const uint8_t truncated_modrm[] =
        {0x62, 0xf2, 0x7d, 0x48, 0x42};
    static const uint8_t truncated_displacement[] =
        {0x62, 0xf2, 0x7d, 0x48, 0x42, 0x85, 0x00};

    expect_status("wrong map", CDISASM_CPU_X86,
        bad_map, sizeof(bad_map), ACTIVE_FLAGS,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_status("wrong mandatory prefix", CDISASM_CPU_X86,
        bad_prefix, sizeof(bad_prefix), ACTIVE_FLAGS,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_status("reserved EVEX.U", CDISASM_CPU_X86,
        bad_u, sizeof(bad_u), ACTIVE_FLAGS,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("scalar memory EVEX.b", CDISASM_CPU_X86,
        scalar_b_memory, sizeof(scalar_b_memory), ACTIVE_FLAGS,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("packed memory LL3", CDISASM_CPU_X86,
        packed_ll3_memory, sizeof(packed_ll3_memory), ACTIVE_FLAGS,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("scalar LL3 without SAE", CDISASM_CPU_X86,
        scalar_ll3, sizeof(scalar_ll3), ACTIVE_FLAGS,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("zero without mask", CDISASM_CPU_X86,
        zero_without_mask, sizeof(zero_without_mask), ACTIVE_FLAGS,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("legacy prefix before EVEX", CDISASM_CPU_X86,
        legacy_prefix, sizeof(legacy_prefix), ACTIVE_FLAGS,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("truncated EVEX prefix", CDISASM_CPU_X86,
        truncated_prefix, sizeof(truncated_prefix), ACTIVE_FLAGS,
        CDISASM_STATUS_TRUNCATED);
    expect_status("truncated ModRM", CDISASM_CPU_X86,
        truncated_modrm, sizeof(truncated_modrm), ACTIVE_FLAGS,
        CDISASM_STATUS_TRUNCATED);
    expect_status("truncated displacement", CDISASM_CPU_X86,
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
        CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
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
    static const uint8_t ps[] =
        {0x62, 0xf2, 0x7d, 0x48, 0x42, 0xca};
    static const uint8_t sd[] =
        {0x62, 0x52, 0xb5, 0x08, 0x43, 0xc2};
    static const uint8_t ps_memory[] =
        {0x62, 0xf2, 0x7d, 0xca, 0x42, 0x48, 0x01};
    static const uint8_t ps_broadcast[] =
        {0x62, 0xf2, 0x7d, 0x5a, 0x42, 0x08};
    static const uint8_t pd_memory[] =
        {0x62, 0xf2, 0xfd, 0xac, 0x42, 0x5b, 0x01};
    static const uint8_t pd_broadcast[] =
        {0x62, 0xf2, 0xfd, 0x1e, 0x42, 0x29};
    static const uint8_t ss_memory[] =
        {0x62, 0xf2, 0x3d, 0x89, 0x43, 0x7a, 0x01};
    static const uint8_t sd_memory[] =
        {0x62, 0x72, 0xad, 0x0b, 0x43, 0x4e, 0x01};
    static const uint8_t ps_sae[] =
        {0x62, 0x52, 0x7d, 0x9d, 0x42, 0xdc};
    static const uint8_t ss_sae[] =
        {0x62, 0x52, 0x8d, 0x9f, 0x43, 0xef};

    expect_format(ps, sizeof(ps), CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vgetexpps zmm1, zmm2");
    expect_format(ps, sizeof(ps), CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vgetexpps %zmm2, %zmm1");
    expect_format(sd, sizeof(sd), CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vgetexpsd xmm8, xmm9, xmm10");
    expect_format(sd, sizeof(sd), CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vgetexpsd %xmm10, %xmm9, %xmm8");
    expect_format(ps_memory, sizeof(ps_memory),
        CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vgetexpps zmm1 {k2}{z}, zmmword ptr [rax + 0x40]");
    expect_format(ps_memory, sizeof(ps_memory),
        CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vgetexppsz 0x40(%rax), %zmm1{%k2}{z}");
    expect_format(ps_broadcast, sizeof(ps_broadcast),
        CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vgetexpps zmm1 {k2}, dword ptr [rax]{1to16}");
    expect_format(ps_broadcast, sizeof(ps_broadcast),
        CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vgetexppsl (%rax){1to16}, %zmm1{%k2}");
    expect_format(pd_memory, sizeof(pd_memory),
        CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vgetexppd ymm3 {k4}{z}, ymmword ptr [rbx + 0x20]");
    expect_format(pd_memory, sizeof(pd_memory),
        CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vgetexppdy 0x20(%rbx), %ymm3{%k4}{z}");
    expect_format(pd_broadcast, sizeof(pd_broadcast),
        CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vgetexppd xmm5 {k6}, qword ptr [rcx]{1to2}");
    expect_format(pd_broadcast, sizeof(pd_broadcast),
        CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vgetexppdq (%rcx){1to2}, %xmm5{%k6}");
    expect_format(ss_memory, sizeof(ss_memory),
        CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vgetexpss xmm7 {k1}{z}, xmm8, dword ptr [rdx + 0x4]");
    expect_format(ss_memory, sizeof(ss_memory),
        CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vgetexpssl 0x4(%rdx), %xmm8, %xmm7{%k1}{z}");
    expect_format(sd_memory, sizeof(sd_memory),
        CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vgetexpsd xmm9 {k3}, xmm10, qword ptr [rsi + 0x8]");
    expect_format(sd_memory, sizeof(sd_memory),
        CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vgetexpsdq 0x8(%rsi), %xmm10, %xmm9{%k3}");
    expect_format(ps_sae, sizeof(ps_sae),
        CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vgetexpps zmm11 {k5}{z}, zmm12, {sae}");
    expect_format(ps_sae, sizeof(ps_sae),
        CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vgetexpps {sae}, %zmm12, %zmm11{%k5}{z}");
    expect_format(ss_sae, sizeof(ss_sae),
        CDISASM_FORMAT_SYNTAX_X86_INTEL,
        "vgetexpsd xmm13 {k7}{z}, xmm14, xmm15, {sae}");
    expect_format(ss_sae, sizeof(ss_sae),
        CDISASM_FORMAT_SYNTAX_X86_ATT,
        "vgetexpsd {sae}, %xmm15, %xmm14, %xmm13{%k7}{z}");
    expect_format(ps, sizeof(ps),
        CDISASM_FORMAT_SYNTAX_X86_INTEL | CDISASM_FORMAT_UPPERCASE_OPCODE,
        "VGETEXPPS zmm1, zmm2");
}
#endif

int main(void)
{
    test_complete_allocation_lattice();
    test_vvvv_and_register_extensions();
    test_xed_oracle_vectors();
    test_masks_modes_and_gates();
    test_reserved_and_truncated();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatting();
#endif

    if (failures != 0) {
        fprintf(stderr,
            "x86 VGETEXP tests failed: %d (extra=%d format=%d)\n",
            failures, USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
        return 1;
    }
    printf("x86 VGETEXP tests passed (extra=%d format=%d)\n",
        USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
    return 0;
}
