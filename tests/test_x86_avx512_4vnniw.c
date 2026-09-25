#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct instruction_case {
    uint8_t opcode;
    cdisasm_x86_name_id name_id;
    const char *mnemonic;
} instruction_case;

static const instruction_case instruction_cases[] = {
    {UINT8_C(0x52), CDISASM_X86_NAME_VP4DPWSSD, "vp4dpwssd"},
    {UINT8_C(0x53), CDISASM_X86_NAME_VP4DPWSSDS, "vp4dpwssds"}
};

_Static_assert(CDISASM_X86_NAME_VP4DPWSSD == UINT16_C(1116)
        && CDISASM_X86_NAME_VP4DPWSSDS == UINT16_C(1117)
        && CDISASM_X86_NAME_VGETEXPBF16 < CDISASM_X86_NAME_COUNT
        && CDISASM_X86_NAME_COUNT == CDISASM_X86_NAME_LAST + UINT16_C(1),
    "AVX512_4VNNIW append-only name IDs changed");
_Static_assert(CDISASM_X86_GROUP_AVX512_4VNNIW == UINT16_C(71),
    "AVX512_4VNNIW group ID changed");
_Static_assert(CDISASM_X86_DECODE_FLAG_AVX512 == UINT64_C(0x00080000),
    "AVX512_4VNNIW must retain the historical AVX512 selector");
_Static_assert(CDISASM_CPU_KNIGHTS_MILL
        == (CDISASM_CPU_GROUP_X86 | UINT32_C(0x0034))
        && CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL
        && CDISASM_CPU_LATEST == CDISASM_CPU_DIAMOND_RAPIDS,
    "Knights Mill CPU profile IDs changed");

static int failures;

#define EXPECT(expression)                                                   \
    do {                                                                     \
        if (!(expression)) {                                                 \
            fprintf(stderr, "%s:%d: expectation failed: %s\n",             \
                __FILE__, __LINE__, #expression);                            \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

static void make_encoding(
    uint8_t opcode,
    unsigned int source,
    unsigned int destination,
    unsigned int ll,
    unsigned int w,
    unsigned int mask,
    unsigned int zero,
    unsigned int evex_b,
    uint8_t modrm_rm,
    uint8_t code[15])
{
    uint8_t p0 = UINT8_C(0x62);
    uint8_t p1 = (uint8_t)((((~source) & 15u) << 3)
        | UINT8_C(0x07));
    uint8_t p2 = (uint8_t)((ll << 5) | (mask & 7u));

    memset(code, 0, 15u);
    if ((destination & 8u) == 0u) {
        p0 |= UINT8_C(0x80);
    }
    if ((destination & 16u) == 0u) {
        p0 |= UINT8_C(0x10);
    }
    if (w != 0u) {
        p1 |= UINT8_C(0x80);
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
    code[5] = (uint8_t)((destination & 7u) << 3 | modrm_rm);
}

static cdisasm_instruction decode(
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

static int is_error_only(
    const cdisasm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static void expect_status(
    const char *label,
    cdisasm_cpu_id cpu,
    cdisasm_mode mode,
    const uint8_t *code,
    size_t size,
    cdisasm_x86_decode_option flags,
    cdisasm_status status)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        cpu, mode, code, size, flags, &decoded_size);

    if (decoded_size != 0u || !is_error_only(&instruction, status)) {
        fprintf(stderr, "%s: expected status=%u, actual=%u, decoded=%u\n",
            label, (unsigned int)status,
            (unsigned int)instruction.last_error_id,
            (unsigned int)decoded_size);
    }
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(&instruction, status));
}

#if USE_EXTRA_OPCODES
static unsigned int expected_memory_size(uint8_t modrm)
{
    const unsigned int mod = modrm >> 6;
    const unsigned int rm = modrm & 7u;
    unsigned int size = 6u;

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

static void test_exhaustive_modrm_and_w(void)
{
    unsigned int allocated = 0u;
    unsigned int reserved_register = 0u;
    unsigned int reserved_w = 0u;
    size_t case_index;

    for (case_index = 0u;
         case_index < sizeof(instruction_cases) / sizeof(instruction_cases[0]);
         ++case_index) {
        unsigned int raw_modrm;

        for (raw_modrm = 0u; raw_modrm != 256u; ++raw_modrm) {
            const unsigned int mod = raw_modrm >> 6;
            uint8_t code[15];

            make_encoding(instruction_cases[case_index].opcode,
                4u, (raw_modrm >> 3) & 7u, 2u, 0u, 0u, 0u, 0u,
                (uint8_t)raw_modrm, code);
            /* Preserve the complete raw ModRM byte for this ownership sweep. */
            code[5] = (uint8_t)raw_modrm;
            if (mod != 3u) {
                ++allocated;
#if USE_EXTRA_OPCODES
                {
                    uint32_t decoded_size;
                    cdisasm_instruction instruction = decode(
                        CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64,
                        code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
                        &decoded_size);

                    EXPECT(decoded_size == expected_memory_size(
                        (uint8_t)raw_modrm));
                    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                    EXPECT(instruction.name_id
                        == instruction_cases[case_index].name_id);
                    EXPECT(instruction.operand_count == 3u);
                    EXPECT(instruction.opcode[0].type
                        == CDISASM_OPERAND_REGISTER);
                    EXPECT(instruction.opcode[0].reg
                        == (cdisasm_x86_reg_id)(CDISASM_X86_REG_ZMM0
                            + ((raw_modrm >> 3) & 7u)));
                    EXPECT(instruction.opcode[0].size == 64u);
                    EXPECT(instruction.opcode[0].access
                        == CDISASM_OPERAND_ACCESS_READ_WRITE);
                    EXPECT(instruction.opcode[1].reg
                        == CDISASM_X86_REG_ZMM4);
                    EXPECT(instruction.opcode[1].size == 64u);
                    EXPECT(instruction.opcode[1].access
                        == CDISASM_OPERAND_ACCESS_READ);
                    EXPECT(instruction.opcode[2].type
                        == CDISASM_OPERAND_MEMORY);
                    EXPECT(instruction.opcode[2].size == 16u);
                    EXPECT(instruction.opcode[2].access
                        == CDISASM_OPERAND_ACCESS_READ);
                    EXPECT(instruction.opcode[2].broadcast
                        == CDISASM_X86_BROADCAST_NONE);
                    EXPECT(cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_AVX));
                    EXPECT(cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_AVX512F));
                    EXPECT(cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_AVX512_4VNNIW));
                }
#else
                expect_status("extra-opcodes OFF owned 4VNNIW memory form",
                    CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64,
                    code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
            } else {
                ++reserved_register;
                expect_status("4VNNIW register form is reserved",
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_INVALID_INSTRUCTION);
            }

            make_encoding(instruction_cases[case_index].opcode,
                4u, (raw_modrm >> 3) & 7u, 2u, 1u, 0u, 0u, 0u,
                (uint8_t)raw_modrm, code);
            code[5] = (uint8_t)raw_modrm;
            ++reserved_w;
            expect_status("4VNNIW W1 is reserved",
                CDISASM_CPU_X86, CDISASM_MODE_64,
                code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
    EXPECT(allocated == 384u);
    EXPECT(reserved_register == 128u);
    EXPECT(reserved_w == 512u);
}

static void test_source_destination_and_tuple(void)
{
    unsigned int source;
    unsigned int destination;

    for (source = 0u; source != 32u; ++source) {
        uint8_t code[15];
#if USE_EXTRA_OPCODES
        uint32_t decoded_size;
        cdisasm_instruction instruction;
#endif

        make_encoding(UINT8_C(0x52), source, 1u, 2u, 0u,
            0u, 0u, 0u, UINT8_C(0x00), code);
#if USE_EXTRA_OPCODES
        instruction = decode(CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64,
            code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
            &decoded_size);
        EXPECT(decoded_size == 6u);
        EXPECT(instruction.opcode[1].reg
            == (cdisasm_x86_reg_id)(CDISASM_X86_REG_ZMM0 + source));
#else
        expect_status("extra-opcodes OFF source-alias sweep",
            CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64,
            code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }

    for (destination = 0u; destination != 32u; ++destination) {
        uint8_t code[15];
#if USE_EXTRA_OPCODES
        uint32_t decoded_size;
        cdisasm_instruction instruction;
#endif

        make_encoding(UINT8_C(0x53), 4u, destination, 2u, 0u,
            0u, 0u, 0u, UINT8_C(0x00), code);
#if USE_EXTRA_OPCODES
        instruction = decode(CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64,
            code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
            &decoded_size);
        EXPECT(decoded_size == 6u);
        EXPECT(instruction.opcode[0].reg
            == (cdisasm_x86_reg_id)(CDISASM_X86_REG_ZMM0 + destination));
#else
        expect_status("extra-opcodes OFF destination sweep",
            CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64,
            code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }

#if USE_EXTRA_OPCODES
    {
        uint8_t code[15];
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        make_encoding(UINT8_C(0x52), 4u, 1u, 2u, 0u,
            0u, 0u, 0u, UINT8_C(0x40), code);
        code[6] = UINT8_C(0x01);
        instruction = decode(CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64,
            code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
            &decoded_size);
        EXPECT(decoded_size == 7u);
        EXPECT(instruction.opcode[2].imm == UINT64_C(0x10));
        EXPECT(instruction.encoding.displacement_size == 1u);

        code[6] = UINT8_C(0xff);
        instruction = decode(CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64,
            code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
            &decoded_size);
        EXPECT(decoded_size == 7u);
        EXPECT(instruction.opcode[2].imm == UINT64_MAX - UINT64_C(0x0f));
    }
#endif

    {
        static const uint8_t unowned_prefixes[] = {
            UINT8_C(0x00), UINT8_C(0x02)
        };
        uint8_t code[15];
        size_t prefix_index;

        for (prefix_index = 0u; prefix_index != 2u; ++prefix_index) {
            make_encoding(UINT8_C(0x52), 4u, 1u, 2u, 0u,
                0u, 0u, 0u, UINT8_C(0x00), code);
            code[2] = (uint8_t)((code[2] & UINT8_C(0xfc))
                | unowned_prefixes[prefix_index]);
            expect_status("unallocated pp neighbor remains unowned",
                CDISASM_CPU_X86, CDISASM_MODE_64, code, 15u,
#if USE_EXTRA_OPCODES
                CDISASM_X86_DECODE_FLAG_ALL,
#else
                CDISASM_X86_DECODE_FLAG_BASE,
#endif
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        }
    }
}

static void test_masks_reserved_neighbors_and_truncation(void)
{
    uint8_t code[16];
    unsigned int mask;
    unsigned int ll;
    size_t size;

    for (mask = 0u; mask != 8u; ++mask) {
        make_encoding(UINT8_C(0x52), 4u, 1u, 2u, 0u,
            mask, 0u, 0u, UINT8_C(0x00), code);
#if USE_EXTRA_OPCODES
        {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64,
                code, 15u, CDISASM_X86_DECODE_FLAG_AVX512,
                &decoded_size);

            EXPECT(decoded_size == 6u);
            EXPECT(instruction.mask_mode == (mask == 0u
                ? CDISASM_X86_MASK_NONE : CDISASM_X86_MASK_MERGE));
            EXPECT(instruction.mask_reg == (mask == 0u
                ? CDISASM_X86_REG_NONE
                : (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + mask)));
        }
#else
        expect_status("extra-opcodes OFF mask sweep",
            CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64,
            code, 15u, CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        if (mask != 0u) {
            make_encoding(UINT8_C(0x53), 4u, 1u, 2u, 0u,
                mask, 1u, 0u, UINT8_C(0x00), code);
#if USE_EXTRA_OPCODES
            {
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64,
                    code, 15u, CDISASM_X86_DECODE_FLAG_AVX512,
                    &decoded_size);
                EXPECT(decoded_size == 6u);
                EXPECT(instruction.mask_mode == CDISASM_X86_MASK_ZERO);
            }
#else
            expect_status("extra-opcodes OFF zero-mask sweep",
                CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64,
                code, 15u, CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }

    make_encoding(UINT8_C(0x52), 4u, 1u, 2u, 0u,
        0u, 1u, 0u, UINT8_C(0x00), code);
    expect_status("zeroing without a mask is reserved",
        CDISASM_CPU_X86, CDISASM_MODE_64, code, 15u,
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_INVALID_INSTRUCTION);

    for (ll = 0u; ll != 4u; ++ll) {
        if (ll == 2u) {
            continue;
        }
        make_encoding(UINT8_C(0x52), 4u, 1u, ll, 0u,
            0u, 0u, 0u, UINT8_C(0x00), code);
        expect_status("only EVEX.512 is allocated",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, 15u,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    make_encoding(UINT8_C(0x52), 4u, 1u, 2u, 0u,
        0u, 0u, 1u, UINT8_C(0x00), code);
    expect_status("EVEX.b is reserved",
        CDISASM_CPU_X86, CDISASM_MODE_64, code, 15u,
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_INVALID_INSTRUCTION);

    make_encoding(UINT8_C(0x52), 4u, 1u, 2u, 0u,
        0u, 0u, 0u, UINT8_C(0x00), code);
    code[2] &= (uint8_t)~UINT8_C(0x04);
    expect_status("EVEX.U0 is reserved",
        CDISASM_CPU_X86, CDISASM_MODE_64, code, 15u,
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_INVALID_INSTRUCTION);

    make_encoding(UINT8_C(0x52), 4u, 1u, 2u, 0u,
        0u, 0u, 0u, UINT8_C(0x00), code);
    code[1] |= UINT8_C(0x08);
    expect_status("APX B4 does not extend 4VNNIW",
        CDISASM_CPU_X86, CDISASM_MODE_64, code, 15u,
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_INVALID_INSTRUCTION);

    /* The P66 neighbor is the existing AVX512_VNNI VPDPWSSD row. */
    make_encoding(UINT8_C(0x52), 4u, 1u, 2u, 0u,
        0u, 0u, 0u, UINT8_C(0x00), code);
    code[2] = (uint8_t)((code[2] & UINT8_C(0xfc)) | UINT8_C(0x01));
#if USE_EXTRA_OPCODES
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64, code, 15u,
            CDISASM_X86_DECODE_FLAG_ALL, &decoded_size);
        EXPECT(decoded_size == 6u);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPDPWSSD);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512VNNI));
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_AVX512_4VNNIW));
    }
#endif

    make_encoding(UINT8_C(0x54), 4u, 1u, 2u, 0u,
        0u, 0u, 0u, UINT8_C(0x00), code);
    expect_status("opcode neighbor remains unowned",
        CDISASM_CPU_X86, CDISASM_MODE_64, code, 15u,
#if USE_EXTRA_OPCODES
        CDISASM_X86_DECODE_FLAG_ALL,
#else
        CDISASM_X86_DECODE_FLAG_BASE,
#endif
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    make_encoding(UINT8_C(0x52), 4u, 1u, 2u, 0u,
        0u, 0u, 0u, UINT8_C(0x00), code);
    code[1] = (uint8_t)((code[1] & UINT8_C(0xf8)) | UINT8_C(0x03));
    expect_status("map neighbor remains unowned",
        CDISASM_CPU_X86, CDISASM_MODE_64, code, 15u,
#if USE_EXTRA_OPCODES
        CDISASM_X86_DECODE_FLAG_ALL,
#else
        CDISASM_X86_DECODE_FLAG_BASE,
#endif
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    make_encoding(UINT8_C(0x52), 4u, 1u, 2u, 0u,
        0u, 0u, 0u, UINT8_C(0x00), code + 1);
    code[0] = UINT8_C(0x66);
    expect_status("legacy prefix before EVEX is reserved",
        CDISASM_CPU_X86, CDISASM_MODE_64, code, 7u,
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_status("legacy-prefixed EVEX ownership precedes missing ModRM",
        CDISASM_CPU_X86, CDISASM_MODE_64, code, 6u,
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_INVALID_INSTRUCTION);

    make_encoding(UINT8_C(0x52), 4u, 1u, 2u, 0u,
        0u, 0u, 0u, UINT8_C(0x00), code);
    expect_status("empty 4VNNIW input",
        CDISASM_CPU_X86, CDISASM_MODE_64, code, 0u,
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_END_OF_INPUT);
    for (size = 1u; size != 6u; ++size) {
        expect_status("truncated 4VNNIW prefix/opcode/ModRM",
            CDISASM_CPU_X86, CDISASM_MODE_64, code, size,
            CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    }
    make_encoding(UINT8_C(0x53), 4u, 1u, 2u, 0u,
        0u, 0u, 0u, UINT8_C(0x40), code);
    expect_status("truncated 4VNNIW disp8",
        CDISASM_CPU_X86, CDISASM_MODE_64, code, 6u,
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    make_encoding(UINT8_C(0x53), 4u, 1u, 2u, 1u,
        0u, 0u, 0u, UINT8_C(0x40), code);
    expect_status("W1 truncated disp8 takes precedence",
        CDISASM_CPU_X86, CDISASM_MODE_64, code, 6u,
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    make_encoding(UINT8_C(0x52), 4u, 1u, 2u, 0u,
        0u, 1u, 0u, UINT8_C(0x40), code);
    expect_status("zero-without-mask truncated disp8 takes precedence",
        CDISASM_CPU_X86, CDISASM_MODE_64, code, 6u,
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    make_encoding(UINT8_C(0x52), 4u, 1u, 1u, 0u,
        0u, 0u, 0u, UINT8_C(0x40), code);
    expect_status("LL256 truncated disp8 takes precedence",
        CDISASM_CPU_X86, CDISASM_MODE_64, code, 6u,
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    make_encoding(UINT8_C(0x52), 4u, 1u, 2u, 0u,
        0u, 0u, 0u, UINT8_C(0x04), code);
    expect_status("truncated 4VNNIW SIB",
        CDISASM_CPU_X86, CDISASM_MODE_64, code, 6u,
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    make_encoding(UINT8_C(0x52), 4u, 1u, 2u, 1u,
        0u, 0u, 0u, UINT8_C(0x04), code);
    expect_status("W1 truncated SIB takes precedence",
        CDISASM_CPU_X86, CDISASM_MODE_64, code, 6u,
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    make_encoding(UINT8_C(0x52), 4u, 1u, 2u, 0u,
        0u, 1u, 0u, UINT8_C(0x04), code);
    expect_status("zero-without-mask truncated SIB takes precedence",
        CDISASM_CPU_X86, CDISASM_MODE_64, code, 6u,
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
    make_encoding(UINT8_C(0x52), 4u, 1u, 2u, 0u,
        0u, 0u, 1u, UINT8_C(0x04), code);
    expect_status("EVEX.b truncated SIB takes precedence",
        CDISASM_CPU_X86, CDISASM_MODE_64, code, 6u,
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
}

static void test_cpu_and_runtime_gates(void)
{
    uint8_t code[15];
    cdisasm_cpu_id cpu;

    make_encoding(UINT8_C(0x52), 4u, 1u, 2u, 0u,
        0u, 0u, 0u, UINT8_C(0x00), code);
#if USE_EXTRA_OPCODES
    {
        const cdisasm_x86_decode_option knm_flags =
            cdisasm_x86_cpu_decode_flag_mask(
                CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64);

        EXPECT((knm_flags & CDISASM_X86_DECODE_FLAG_AVX512) != 0u);
        EXPECT((knm_flags & CDISASM_X86_DECODE_FLAG_AVX512_CD) != 0u);
        EXPECT((knm_flags
            & CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ) != 0u);
        EXPECT((knm_flags & CDISASM_X86_DECODE_FLAG_AVX512_DQ) == 0u);
        EXPECT((knm_flags & CDISASM_X86_DECODE_FLAG_AVX512_BW) == 0u);
        EXPECT((knm_flags & CDISASM_X86_DECODE_FLAG_AVX512_VNNI) == 0u);
    }
    for (cpu = CDISASM_CPU_FIRST; cpu <= CDISASM_CPU_LAST; ++cpu) {
        const cdisasm_x86_mode_mask modes = cdisasm_x86_cpu_mode_mask(cpu);
        const cdisasm_mode mode = (modes & CDISASM_X86_MODE_MASK_64) != 0u
            ? CDISASM_MODE_64
            : ((modes & CDISASM_X86_MODE_MASK_32) != 0u
                ? CDISASM_MODE_32 : CDISASM_MODE_16);
        const int supported = cpu == CDISASM_CPU_X86
            || cpu == CDISASM_CPU_KNIGHTS_MILL;

        if (supported) {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                cpu, mode, code, sizeof(code),
                CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
            EXPECT(decoded_size == 6u);
            EXPECT(instruction.name_id == CDISASM_X86_NAME_VP4DPWSSD);
        } else {
            expect_status("CPU lacks independent AVX512_4VNNIW feature",
                cpu, mode, code, sizeof(code),
                CDISASM_X86_DECODE_FLAG_AVX512,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }

    {
        static const cdisasm_cpu_id rejected_modern[] = {
            CDISASM_CPU_SKYLAKE_SP,
            CDISASM_CPU_SAPPHIRE_RAPIDS,
            CDISASM_CPU_GRANITE_RAPIDS,
            CDISASM_CPU_DIAMOND_RAPIDS,
            CDISASM_CPU_AVX10,
            CDISASM_CPU_APX
        };
        size_t index;

        for (index = 0u;
             index < sizeof(rejected_modern) / sizeof(rejected_modern[0]);
             ++index) {
            expect_status("mainstream AVX-512 profile is not KNM",
                rejected_modern[index], CDISASM_MODE_64,
                code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
    expect_status("BASE selector does not admit 4VNNIW",
        CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64,
        code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_status("AVX512_VNNI selector does not admit 4VNNIW",
        CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64,
        code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512_VNNI,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    {
        static const cdisasm_mode modes[] = {
            CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
        };
        size_t index;

        for (index = 0u; index != 3u; ++index) {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_KNIGHTS_MILL, modes[index],
                code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
                &decoded_size);
            EXPECT(decoded_size == 6u);
            EXPECT(instruction.name_id == CDISASM_X86_NAME_VP4DPWSSD);
        }
    }
#else
    (void)cpu;
    expect_status("extra-opcodes OFF rejects AVX512 selector",
        CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64,
        code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_STATUS_INVALID_ARGUMENT);
#endif
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void test_formatting(void)
{
    uint8_t code[15];
    char text[160];
    uint32_t decoded_size;
    cdisasm_instruction instruction;
    size_t length;

    make_encoding(UINT8_C(0x52), 5u, 1u, 2u, 0u,
        0u, 0u, 0u, UINT8_C(0x00), code);
    instruction = decode(CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64,
        code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
        &decoded_size);
    EXPECT(decoded_size == 6u);
    length = cdisasm_x86_format(&instruction,
        CDISASM_FORMAT_SYNTAX_INTEL, text, sizeof(text));
    EXPECT(length == strlen("vp4dpwssd zmm1, zmm5+3, xmmword ptr [rax]"));
    EXPECT(strcmp(text,
        "vp4dpwssd zmm1, zmm5+3, xmmword ptr [rax]") == 0);
    length = cdisasm_x86_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ATT, text, sizeof(text));
    EXPECT(length == strlen("vp4dpwssdx (%rax), %zmm5+3, %zmm1"));
    EXPECT(strcmp(text, "vp4dpwssdx (%rax), %zmm5+3, %zmm1") == 0);

    make_encoding(UINT8_C(0x53), 31u, 31u, 2u, 0u,
        1u, 1u, 0u, UINT8_C(0x00), code);
    instruction = decode(CDISASM_CPU_KNIGHTS_MILL, CDISASM_MODE_64,
        code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
        &decoded_size);
    EXPECT(decoded_size == 6u);
    cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
        text, sizeof(text));
    EXPECT(strcmp(text,
        "vp4dpwssds zmm31 {k1}{z}, zmm31+3, xmmword ptr [rax]") == 0);
    cdisasm_x86_format(&instruction,
        CDISASM_FORMAT_SYNTAX_ATT | CDISASM_FORMAT_UPPERCASE_OPCODE,
        text, sizeof(text));
    EXPECT(strcmp(text,
        "VP4DPWSSDSX (%rax), %zmm31+3, %zmm31{%k1}{z}") == 0);
}
#endif

int main(void)
{
    test_exhaustive_modrm_and_w();
    test_source_destination_and_tuple();
    test_masks_reserved_neighbors_and_truncation();
    test_cpu_and_runtime_gates();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatting();
#endif
    if (failures != 0) {
        fprintf(stderr, "%d AVX512_4VNNIW test(s) failed\n", failures);
        return 1;
    }
    puts("AVX512_4VNNIW tests passed");
    return 0;
}
