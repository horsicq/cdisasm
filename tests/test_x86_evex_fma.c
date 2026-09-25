#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct evex_fma_case {
    uint8_t opcode;
    uint8_t w;
    cdisasm_x86_name_id name_id;
    const char *mnemonic;
} evex_fma_case;

#define FMA_PAIR(opcode_, stem_, text_)                                      \
    { (opcode_), 0, CDISASM_X86_NAME_##stem_##PS, text_ "ps" },             \
    { (opcode_), 1, CDISASM_X86_NAME_##stem_##PD, text_ "pd" }

static const evex_fma_case cases[] = {
    FMA_PAIR(0x96, VFMADDSUB132, "vfmaddsub132"),
    FMA_PAIR(0x97, VFMSUBADD132, "vfmsubadd132"),
    FMA_PAIR(0x98, VFMADD132, "vfmadd132"),
    FMA_PAIR(0x9a, VFMSUB132, "vfmsub132"),
    FMA_PAIR(0x9c, VFNMADD132, "vfnmadd132"),
    FMA_PAIR(0x9e, VFNMSUB132, "vfnmsub132"),
    FMA_PAIR(0xa6, VFMADDSUB213, "vfmaddsub213"),
    FMA_PAIR(0xa7, VFMSUBADD213, "vfmsubadd213"),
    FMA_PAIR(0xa8, VFMADD213, "vfmadd213"),
    FMA_PAIR(0xaa, VFMSUB213, "vfmsub213"),
    FMA_PAIR(0xac, VFNMADD213, "vfnmadd213"),
    FMA_PAIR(0xae, VFNMSUB213, "vfnmsub213"),
    FMA_PAIR(0xb6, VFMADDSUB231, "vfmaddsub231"),
    FMA_PAIR(0xb7, VFMSUBADD231, "vfmsubadd231"),
    FMA_PAIR(0xb8, VFMADD231, "vfmadd231"),
    FMA_PAIR(0xba, VFMSUB231, "vfmsub231"),
    FMA_PAIR(0xbc, VFNMADD231, "vfnmadd231"),
    FMA_PAIR(0xbe, VFNMSUB231, "vfnmsub231")
};

#undef FMA_PAIR

#define SCALAR_FMA_PAIR(opcode_, stem_, text_)                               \
    { (opcode_), 0, CDISASM_X86_NAME_##stem_##SS, text_ "ss" },             \
    { (opcode_), 1, CDISASM_X86_NAME_##stem_##SD, text_ "sd" }

static const evex_fma_case scalar_cases[] = {
    SCALAR_FMA_PAIR(0x99, VFMADD132, "vfmadd132"),
    SCALAR_FMA_PAIR(0x9b, VFMSUB132, "vfmsub132"),
    SCALAR_FMA_PAIR(0x9d, VFNMADD132, "vfnmadd132"),
    SCALAR_FMA_PAIR(0x9f, VFNMSUB132, "vfnmsub132"),
    SCALAR_FMA_PAIR(0xa9, VFMADD213, "vfmadd213"),
    SCALAR_FMA_PAIR(0xab, VFMSUB213, "vfmsub213"),
    SCALAR_FMA_PAIR(0xad, VFNMADD213, "vfnmadd213"),
    SCALAR_FMA_PAIR(0xaf, VFNMSUB213, "vfnmsub213"),
    SCALAR_FMA_PAIR(0xb9, VFMADD231, "vfmadd231"),
    SCALAR_FMA_PAIR(0xbb, VFMSUB231, "vfmsub231"),
    SCALAR_FMA_PAIR(0xbd, VFNMADD231, "vfnmadd231"),
    SCALAR_FMA_PAIR(0xbf, VFNMSUB231, "vfnmsub231")
};

#undef SCALAR_FMA_PAIR

static int failures;

#define EXPECT(expression)                                                   \
    do {                                                                     \
        if (!(expression)) {                                                 \
            fprintf(stderr, "%s:%d: expectation failed: %s\n",             \
                __FILE__, __LINE__, #expression);                            \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

static cdisasm_instruction decode(
    cdisasm_cpu_id cpu,
    cdisasm_mode mode,
    const uint8_t *bytes,
    size_t size,
    cdisasm_x86_decode_option flags,
    uint32_t *decoded_size)
{
    cdisasm_instruction instruction;

    memset(&instruction, UINT8_C(0xa5), sizeof(instruction));
    *decoded_size = cdisasm_x86_decode(
        cpu, mode, bytes, size, UINT64_C(0x1000), flags, &instruction);
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

static void expect_error(
    cdisasm_cpu_id cpu,
    cdisasm_mode mode,
    const uint8_t *bytes,
    size_t size,
    cdisasm_x86_decode_option flags,
    cdisasm_status status)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction =
        decode(cpu, mode, bytes, size, flags, &decoded_size);

    if (decoded_size != 0 || !is_error_only(&instruction, status)) {
        fprintf(stderr,
            "unexpected result: cpu=0x%08x flags=0x%016llx opcode=%02x "
            "expected=%u actual=%u decoded=%u\n",
            (unsigned int)cpu, (unsigned long long)flags,
            size > 4 ? (unsigned int)bytes[4] : 0u,
            (unsigned int)status, (unsigned int)instruction.last_error_id,
            (unsigned int)decoded_size);
    }
    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(&instruction, status));
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_reg_id vector_register(unsigned int index, unsigned int bits)
{
    if (bits == 128) {
        return (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0 + index);
    }
    if (bits == 256) {
        return (cdisasm_x86_reg_id)(CDISASM_X86_REG_YMM0 + index);
    }
    return (cdisasm_x86_reg_id)(CDISASM_X86_REG_ZMM0 + index);
}

#if USE_DISASM_FORMAT
static void expect_format(
    const cdisasm_instruction *instruction,
    uint32_t syntax,
    const char *expected)
{
    char buffer[160];
    size_t length =
        cdisasm_x86_format(instruction, syntax, buffer, sizeof(buffer));

    if (strcmp(buffer, expected) != 0) {
        fprintf(stderr, "format mismatch: expected='%s' actual='%s'\n",
            expected, buffer);
    }
    EXPECT(length == strlen(expected));
    EXPECT(strcmp(buffer, expected) == 0);
}
#endif
#endif

static void test_complete_matrix(void)
{
    size_t index;

    EXPECT(sizeof(cases) / sizeof(cases[0]) == 36u);
    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        unsigned int length;
        const evex_fma_case *test = &cases[index];

        for (length = 0; length != 3; ++length) {
            const unsigned int vector_bits = 128u << length;
            uint8_t code[] = {
                0x62, 0xf2, (uint8_t)(test->w != 0 ? 0xed : 0x6d),
                (uint8_t)(0x08u | (length << 5)), test->opcode, 0xcb
            };

#if USE_EXTRA_OPCODES
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                code, sizeof(code),
                CDISASM_X86_DECODE_FLAG_AVX512,
                &decoded_size);

            EXPECT(decoded_size == sizeof(code));
            EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
            EXPECT(instruction.name_id == test->name_id);
            EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EVEX) != 0);
            EXPECT(instruction.operand_count == 3);
            EXPECT(instruction.opcode[0].reg
                == vector_register(1, vector_bits));
            EXPECT(instruction.opcode[1].reg
                == vector_register(2, vector_bits));
            EXPECT(instruction.opcode[2].reg
                == vector_register(3, vector_bits));
            EXPECT(instruction.opcode[0].size == vector_bits / 8u);
            EXPECT(instruction.opcode[1].size == vector_bits / 8u);
            EXPECT(instruction.opcode[2].size == vector_bits / 8u);
            EXPECT(instruction.opcode[0].access
                == CDISASM_OPERAND_ACCESS_READ_WRITE);
            EXPECT(instruction.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.opcode[2].access
                == CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.mask_reg == CDISASM_X86_REG_NONE);
            EXPECT(instruction.mask_mode == CDISASM_X86_MASK_NONE);
            EXPECT(instruction.rounding == CDISASM_X86_ROUNDING_NONE);
            EXPECT(instruction.sae == CDISASM_X86_SAE_NONE);
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_FMA3));
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_AVX512F));
            EXPECT(cdisasm_instruction_has_x86_group(
                       &instruction, CDISASM_X86_GROUP_AVX512VL)
                == (vector_bits < 512u));
            EXPECT(instruction.encoding.prefix_size == 4);
            EXPECT(instruction.encoding.opcode_offset == 4);
            EXPECT(instruction.encoding.opcode_size == 1);
            EXPECT(instruction.encoding.modrm_offset == 5);
            EXPECT(instruction.encoding.modrm == UINT8_C(0xcb));

#if USE_DISASM_FORMAT
            {
                const char *register_name = length == 0 ? "xmm"
                    : length == 1 ? "ymm" : "zmm";
                char intel[128];
                char att[128];

                snprintf(intel, sizeof(intel), "%s %s1, %s2, %s3",
                    test->mnemonic, register_name, register_name,
                    register_name);
                snprintf(att, sizeof(att), "%s %%%s3, %%%s2, %%%s1",
                    test->mnemonic, register_name, register_name,
                    register_name);
                expect_format(&instruction,
                    CDISASM_FORMAT_SYNTAX_X86_INTEL, intel);
                expect_format(&instruction,
                    CDISASM_FORMAT_SYNTAX_X86_ATT, att);
            }
#endif
#else
            (void)vector_bits;
            expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
                code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }

        {
            uint8_t truncated[] = {
                0x62, 0xf2, (uint8_t)(test->w != 0 ? 0xed : 0x6d),
                0x48, test->opcode
            };

            expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
                truncated, sizeof(truncated),
                CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
        }

        {
            uint8_t broadcast[] = {
                0x62, 0xf2, (uint8_t)(test->w != 0 ? 0xed : 0x6d),
                0x59, test->opcode, 0x08
            };
            uint8_t rounding[] = {
                0x62, 0xf2, (uint8_t)(test->w != 0 ? 0xed : 0x6d),
                0x58, test->opcode, 0xcb
            };

#if USE_EXTRA_OPCODES
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                broadcast, sizeof(broadcast),
                CDISASM_X86_DECODE_FLAG_AVX512,
                &decoded_size);

            EXPECT(decoded_size == sizeof(broadcast));
            EXPECT(instruction.name_id == test->name_id);
            EXPECT(instruction.mask_reg == CDISASM_X86_REG_K1);
            EXPECT(instruction.mask_mode == CDISASM_X86_MASK_MERGE);
            EXPECT(instruction.opcode[0].access
                == CDISASM_OPERAND_ACCESS_READ_WRITE);
            EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_MEMORY);
            EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RAX);
            EXPECT(instruction.opcode[2].size == (test->w != 0 ? 8u : 4u));
            EXPECT(instruction.opcode[2].broadcast
                == (test->w != 0 ? CDISASM_X86_BROADCAST_1_TO_8
                                 : CDISASM_X86_BROADCAST_1_TO_16));

            instruction = decode(
                CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                rounding, sizeof(rounding),
                CDISASM_X86_DECODE_FLAG_AVX512,
                &decoded_size);
            EXPECT(decoded_size == sizeof(rounding));
            EXPECT(instruction.name_id == test->name_id);
            EXPECT(instruction.opcode[0].access
                == CDISASM_OPERAND_ACCESS_READ_WRITE);
            EXPECT(instruction.rounding == CDISASM_X86_ROUNDING_RU);
            EXPECT(instruction.sae == CDISASM_X86_SAE_ENABLED);
#else
            expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
                broadcast, sizeof(broadcast),
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
                rounding, sizeof(rounding),
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }
}

static void test_complete_scalar_matrix(void)
{
    size_t index;

    EXPECT(sizeof(scalar_cases) / sizeof(scalar_cases[0]) == 24u);
    for (index = 0;
         index < sizeof(scalar_cases) / sizeof(scalar_cases[0]);
         ++index) {
        const evex_fma_case *test = &scalar_cases[index];
        unsigned int ll;

        /* EVEX.LIG accepts LL=0..2 without changing scalar XMM operands. */
        for (ll = 0; ll != 3; ++ll) {
            uint8_t code[] = {
                0x62, 0xf2, (uint8_t)(test->w != 0 ? 0xed : 0x6d),
                (uint8_t)(0x08u | (ll << 5)), test->opcode, 0xcb
            };

#if USE_EXTRA_OPCODES
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                code, sizeof(code), CDISASM_X86_DECODE_FLAG_AVX512,
                &decoded_size);

            EXPECT(decoded_size == sizeof(code));
            EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
            EXPECT(instruction.name_id == test->name_id);
            EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EVEX) != 0);
            EXPECT(instruction.operand_count == 3);
            EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM1);
            EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM2);
            EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM3);
            EXPECT(instruction.opcode[0].size == 16);
            EXPECT(instruction.opcode[1].size == 16);
            EXPECT(instruction.opcode[2].size == 16);
            EXPECT(instruction.opcode[0].access
                == CDISASM_OPERAND_ACCESS_READ_WRITE);
            EXPECT(instruction.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.opcode[2].access
                == CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.mask_reg == CDISASM_X86_REG_NONE);
            EXPECT(instruction.rounding == CDISASM_X86_ROUNDING_NONE);
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_FMA3));
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_AVX512F));
            EXPECT(!cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_AVX512VL));
            EXPECT(instruction.encoding.prefix_size == 4);
            EXPECT(instruction.encoding.opcode_offset == 4);
            EXPECT(instruction.encoding.modrm_offset == 5);

#if USE_DISASM_FORMAT
            {
                char intel[112];
                char att[112];

                snprintf(intel, sizeof(intel), "%s xmm1, xmm2, xmm3",
                    test->mnemonic);
                snprintf(att, sizeof(att), "%s %%xmm3, %%xmm2, %%xmm1",
                    test->mnemonic);
                expect_format(&instruction,
                    CDISASM_FORMAT_SYNTAX_X86_INTEL, intel);
                expect_format(&instruction,
                    CDISASM_FORMAT_SYNTAX_X86_ATT, att);
            }
#endif
#else
            expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
                code, sizeof(code), CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }

        {
            uint8_t bad_ll[] = {
                0x62, 0xf2, (uint8_t)(test->w != 0 ? 0xed : 0x6d),
                0x68, test->opcode, 0xcb
            };
            uint8_t truncated[] = {
                0x62, 0xf2, (uint8_t)(test->w != 0 ? 0xed : 0x6d),
                0x08, test->opcode
            };

            expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
                bad_ll, sizeof(bad_ll), CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
                truncated, sizeof(truncated),
                CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
        }

        {
            uint8_t memory[] = {
                0x62, 0xf2, (uint8_t)(test->w != 0 ? 0xed : 0x6d),
                0x09, test->opcode, 0x4b, 0x02
            };
            uint8_t bad_b_memory[] = {
                0x62, 0xf2, (uint8_t)(test->w != 0 ? 0xed : 0x6d),
                0x19, test->opcode, 0x0b
            };
            uint8_t masked_zero[] = {
                0x62, 0xf2, (uint8_t)(test->w != 0 ? 0xed : 0x6d),
                0x89, test->opcode, 0xcb
            };

            expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
                bad_b_memory, sizeof(bad_b_memory),
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_INVALID_INSTRUCTION);

#if USE_EXTRA_OPCODES
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                memory, sizeof(memory), CDISASM_X86_DECODE_FLAG_AVX512,
                &decoded_size);

            EXPECT(decoded_size == sizeof(memory));
            EXPECT(instruction.name_id == test->name_id);
            EXPECT(instruction.mask_reg == CDISASM_X86_REG_K1);
            EXPECT(instruction.mask_mode == CDISASM_X86_MASK_MERGE);
            EXPECT(instruction.opcode[0].access
                == CDISASM_OPERAND_ACCESS_READ_WRITE);
            EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_MEMORY);
            EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RBX);
            EXPECT(instruction.opcode[2].size == (test->w != 0 ? 8u : 4u));
            EXPECT(instruction.opcode[2].imm
                == (test->w != 0 ? UINT64_C(16) : UINT64_C(8)));
            EXPECT(instruction.opcode[2].broadcast
                == CDISASM_X86_BROADCAST_NONE);
            EXPECT(instruction.encoding.displacement_offset == 6);
            EXPECT(instruction.encoding.displacement_size == 1);

            instruction = decode(
                CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                masked_zero, sizeof(masked_zero),
                CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);
            EXPECT(decoded_size == sizeof(masked_zero));
            EXPECT(instruction.name_id == test->name_id);
            EXPECT(instruction.mask_reg == CDISASM_X86_REG_K1);
            EXPECT(instruction.mask_mode == CDISASM_X86_MASK_ZERO);
            EXPECT(instruction.opcode[0].access
                == CDISASM_OPERAND_ACCESS_READ_WRITE);
#else
            expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
                memory, sizeof(memory), CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
                masked_zero, sizeof(masked_zero),
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }

        /* EVEX.b with a register source makes all four LL values rounding. */
        for (ll = 0; ll != 4; ++ll) {
            uint8_t rounding[] = {
                0x62, 0xf2, (uint8_t)(test->w != 0 ? 0xed : 0x6d),
                (uint8_t)(0x18u | (ll << 5)), test->opcode, 0xcb
            };

#if USE_EXTRA_OPCODES
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
                rounding, sizeof(rounding),
                CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size);

            EXPECT(decoded_size == sizeof(rounding));
            EXPECT(instruction.name_id == test->name_id);
            EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM1);
            EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM2);
            EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM3);
            EXPECT(instruction.opcode[0].access
                == CDISASM_OPERAND_ACCESS_READ_WRITE);
            EXPECT(instruction.rounding
                == (cdisasm_x86_rounding_mode)(ll + 1u));
            EXPECT(instruction.sae == CDISASM_X86_SAE_ENABLED);
#else
            expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
                rounding, sizeof(rounding),
                CDISASM_X86_DECODE_FLAG_BASE,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }
}

static void test_policy_and_reserved_forms(void)
{
    static const uint8_t fma[] = {0x62, 0xf2, 0x6d, 0x48, 0x98, 0xcb};
    static const uint8_t scalar_fma[] = {
        0x62, 0xf2, 0x6d, 0x08, 0x99, 0xcb
    };
    static const uint8_t bad_ll[] = {0x62, 0xf2, 0x6d, 0x68, 0x98, 0xcb};
    static const uint8_t zero_without_mask[] = {
        0x62, 0xf2, 0x6d, 0xc8, 0x98, 0xcb
    };
    static const uint8_t locked[] = {
        0xf0, 0x62, 0xf2, 0x6d, 0x48, 0x98, 0xcb
    };

    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        bad_ll, sizeof(bad_ll), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        zero_without_mask, sizeof(zero_without_mask),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        locked, sizeof(locked), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_INVALID_INSTRUCTION);
#if USE_EXTRA_OPCODES
    {
        const cdisasm_x86_decode_option avx512_fma =
            CDISASM_X86_DECODE_FLAG_AVX512;
        const cdisasm_x86_decode_option avx10_fma =
            CDISASM_X86_DECODE_FLAG_AVX10;
        static const cdisasm_cpu_id avx512_cpus[] = {
            CDISASM_CPU_SKYLAKE_SP,
            CDISASM_CPU_AMD_ZEN_4,
            CDISASM_CPU_GRANITE_RAPIDS
        };
        size_t index;

        for (index = 0;
             index < sizeof(avx512_cpus) / sizeof(avx512_cpus[0]);
             ++index) {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                avx512_cpus[index], CDISASM_MODE_64,
                fma, sizeof(fma), avx512_fma, &decoded_size);

            EXPECT(decoded_size == sizeof(fma));
            EXPECT(instruction.name_id == CDISASM_X86_NAME_VFMADD132PS);

            instruction = decode(
                avx512_cpus[index], CDISASM_MODE_64,
                scalar_fma, sizeof(scalar_fma), avx512_fma,
                &decoded_size);
            EXPECT(decoded_size == sizeof(scalar_fma));
            EXPECT(instruction.name_id == CDISASM_X86_NAME_VFMADD132SS);
            EXPECT(!cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_AVX512VL));
        }

        expect_error(CDISASM_CPU_SKYLAKE, CDISASM_MODE_64,
            fma, sizeof(fma), avx512_fma,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error(CDISASM_CPU_ALDER_LAKE, CDISASM_MODE_64,
            fma, sizeof(fma), avx512_fma,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error(CDISASM_CPU_ALDER_LAKE, CDISASM_MODE_64,
            scalar_fma, sizeof(scalar_fma), avx512_fma,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
            fma, sizeof(fma), CDISASM_X86_DECODE_FLAG_FMA3,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

        {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_AVX10, CDISASM_MODE_64,
                fma, sizeof(fma), avx10_fma, &decoded_size);

            EXPECT(decoded_size == sizeof(fma));
            EXPECT(instruction.name_id == CDISASM_X86_NAME_VFMADD132PS);
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_FMA3));
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_AVX10_1));
            EXPECT(!cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_AVX512F));
            EXPECT(!cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_AVX512VL));

            instruction = decode(
                CDISASM_CPU_AVX10, CDISASM_MODE_64,
                scalar_fma, sizeof(scalar_fma), avx10_fma,
                &decoded_size);
            EXPECT(decoded_size == sizeof(scalar_fma));
            EXPECT(instruction.name_id == CDISASM_X86_NAME_VFMADD132SS);
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_FMA3));
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_AVX10_1));
            EXPECT(!cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_AVX512F));
            EXPECT(!cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_AVX512VL));
        }

        expect_error(CDISASM_CPU_AVX10, CDISASM_MODE_64,
            fma, sizeof(fma), CDISASM_X86_DECODE_FLAG_FMA3,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error(CDISASM_CPU_AVX10, CDISASM_MODE_64,
            scalar_fma, sizeof(scalar_fma), CDISASM_X86_DECODE_FLAG_FMA3,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

        EXPECT((cdisasm_x86_cpu_decode_flag_mask(
                    CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64)
                & avx512_fma) == avx512_fma);
        EXPECT((cdisasm_x86_cpu_decode_flag_mask(
                    CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64)
                & CDISASM_X86_DECODE_FLAG_FMA3)
            == CDISASM_X86_DECODE_FLAG_FMA3);
        EXPECT((cdisasm_x86_cpu_decode_flag_mask(
                    CDISASM_CPU_AVX10, CDISASM_MODE_64)
                & avx10_fma) == avx10_fma);
        EXPECT((cdisasm_x86_cpu_decode_flag_mask(
                    CDISASM_CPU_AVX10, CDISASM_MODE_64)
                & CDISASM_X86_DECODE_FLAG_FMA3)
            == CDISASM_X86_DECODE_FLAG_FMA3);
    }
#else
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        fma, sizeof(fma), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, CDISASM_MODE_64,
        scalar_fma, sizeof(scalar_fma), CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

int main(void)
{
    test_complete_matrix();
    test_complete_scalar_matrix();
    test_policy_and_reserved_forms();

    if (failures != 0) {
        fprintf(stderr,
            "x86 EVEX FMA tests failed: %d (extra=%d, format=%d)\n",
            failures, USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
        return 1;
    }
    printf("x86 EVEX FMA tests passed (extra=%d, format=%d)\n",
        USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
    return 0;
}
