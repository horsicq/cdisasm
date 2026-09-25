#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_X86_NAME_VFRCZPS == UINT16_C(843),
               "XOP map-9 expansion start changed");
_Static_assert(CDISASM_X86_NAME_VPHSUBDQ == UINT16_C(861),
               "XOP map-9 expansion end changed");
_Static_assert(CDISASM_X86_NAME_COUNT >= UINT16_C(862),
               "XOP map-9 public catalog is incomplete");

static int failures;

#if USE_EXTRA_OPCODES
#define XOP_STRUCTURAL_FLAGS CDISASM_X86_DECODE_FLAG_XOP
#else
#define XOP_STRUCTURAL_FLAGS CDISASM_X86_DECODE_FLAG_BASE
#endif

#define EXPECT(expression)                                                     \
    do {                                                                       \
        if (!(expression)) {                                                   \
            fprintf(stderr, "%s:%d: expectation failed: %s\n",              \
                    __FILE__, __LINE__, #expression);                          \
            ++failures;                                                        \
        }                                                                      \
    } while (0)

typedef enum xop_shape {
    XOP_PACKED = 0,
    XOP_SCALAR32 = 1,
    XOP_SCALAR64 = 2,
    XOP_VECTOR128 = 3
} xop_shape;

typedef struct xop_case {
    uint8_t opcode;
    uint8_t shape;
    cdisasm_x86_name_id name_id;
    const char *mnemonic;
} xop_case;

static const xop_case xop_cases[] = {
    {0x80, XOP_PACKED, CDISASM_X86_NAME_VFRCZPS, "vfrczps"},
    {0x81, XOP_PACKED, CDISASM_X86_NAME_VFRCZPD, "vfrczpd"},
    {0x82, XOP_SCALAR32, CDISASM_X86_NAME_VFRCZSS, "vfrczss"},
    {0x83, XOP_SCALAR64, CDISASM_X86_NAME_VFRCZSD, "vfrczsd"},
    {0xc1, XOP_VECTOR128, CDISASM_X86_NAME_VPHADDBW, "vphaddbw"},
    {0xc2, XOP_VECTOR128, CDISASM_X86_NAME_VPHADDBD, "vphaddbd"},
    {0xc3, XOP_VECTOR128, CDISASM_X86_NAME_VPHADDBQ, "vphaddbq"},
    {0xc6, XOP_VECTOR128, CDISASM_X86_NAME_VPHADDWD, "vphaddwd"},
    {0xc7, XOP_VECTOR128, CDISASM_X86_NAME_VPHADDWQ, "vphaddwq"},
    {0xcb, XOP_VECTOR128, CDISASM_X86_NAME_VPHADDDQ, "vphadddq"},
    {0xd1, XOP_VECTOR128, CDISASM_X86_NAME_VPHADDUBW, "vphaddubw"},
    {0xd2, XOP_VECTOR128, CDISASM_X86_NAME_VPHADDUBD, "vphaddubd"},
    {0xd3, XOP_VECTOR128, CDISASM_X86_NAME_VPHADDUBQ, "vphaddubq"},
    {0xd6, XOP_VECTOR128, CDISASM_X86_NAME_VPHADDUWD, "vphadduwd"},
    {0xd7, XOP_VECTOR128, CDISASM_X86_NAME_VPHADDUWQ, "vphadduwq"},
    {0xdb, XOP_VECTOR128, CDISASM_X86_NAME_VPHADDUDQ, "vphaddudq"},
    {0xe1, XOP_VECTOR128, CDISASM_X86_NAME_VPHSUBBW, "vphsubbw"},
    {0xe2, XOP_VECTOR128, CDISASM_X86_NAME_VPHSUBWD, "vphsubwd"},
    {0xe3, XOP_VECTOR128, CDISASM_X86_NAME_VPHSUBDQ, "vphsubdq"}
};

static cdisasm_instruction decode_mode(
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

static void expect_error_mode(
    cdisasm_cpu_id cpu,
    cdisasm_mode mode,
    const uint8_t *bytes,
    size_t size,
    cdisasm_x86_decode_option flags,
    cdisasm_status status)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode_mode(
        cpu, mode, bytes, size, flags, &decoded_size);

    if (decoded_size != 0 || !is_error_only(&instruction, status)) {
        fprintf(stderr,
                "unexpected XOP status: cpu=0x%08x mode=%u opcode=%02x "
                "expected=%u actual=%u decoded=%u\n",
                (unsigned int)cpu,
                (unsigned int)mode,
                size > 3 ? (unsigned int)bytes[3] : 0u,
                (unsigned int)status,
                (unsigned int)instruction.last_error_id,
                (unsigned int)decoded_size);
    }
    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(&instruction, status));
}

static void expect_error(
    const uint8_t *bytes,
    size_t size,
    cdisasm_status status)
{
    expect_error_mode(
        CDISASM_CPU_X86, CDISASM_MODE_64, bytes, size,
        XOP_STRUCTURAL_FLAGS, status);
}

#if USE_EXTRA_OPCODES
static cdisasm_instruction decode_bulldozer(
    cdisasm_mode mode,
    const uint8_t *bytes,
    size_t size,
    uint32_t *decoded_size)
{
    return decode_mode(
        CDISASM_CPU_AMD_BULLDOZER, mode, bytes, size,
        CDISASM_X86_DECODE_FLAG_XOP, decoded_size);
}

static void expect_register_pair(
    const cdisasm_instruction *instruction,
    cdisasm_x86_reg_id destination,
    cdisasm_x86_reg_id source,
    unsigned int size)
{
    EXPECT(instruction->operand_count == 2);
    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].reg == destination);
    EXPECT(instruction->opcode[0].size == size);
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[1].reg == source);
    EXPECT(instruction->opcode[1].size == size);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
}

#if USE_DISASM_FORMAT
static void expect_format(
    const cdisasm_instruction *instruction,
    const char *mnemonic,
    const char *register_name)
{
    char expected[96];
    char text[96];
    size_t length;

    (void)snprintf(
        expected, sizeof(expected), "%s %s1, %s2",
        mnemonic, register_name, register_name);
    length = cdisasm_x86_format(
        instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
        text, sizeof(text));
    EXPECT(length == strlen(expected));
    EXPECT(strcmp(text, expected) == 0);

    (void)snprintf(
        expected, sizeof(expected), "%s %%%s2, %%%s1",
        mnemonic, register_name, register_name);
    length = cdisasm_x86_format(
        instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
        text, sizeof(text));
    EXPECT(length == strlen(expected));
    EXPECT(strcmp(text, expected) == 0);
}
#endif
#endif

#if USE_EXTRA_OPCODES
static unsigned int memory_size_for_shape(uint8_t shape, unsigned int l)
{
    switch (shape) {
        case XOP_PACKED:
            return l != 0 ? 32u : 16u;
        case XOP_SCALAR32:
            return 4u;
        case XOP_SCALAR64:
            return 8u;
        default:
            return 16u;
    }
}
#endif

static void test_complete_map9_matrix(void)
{
    size_t case_index;

    EXPECT(sizeof(xop_cases) / sizeof(xop_cases[0]) == 19u);
    for (case_index = 0;
         case_index < sizeof(xop_cases) / sizeof(xop_cases[0]);
         ++case_index) {
        const xop_case *test = &xop_cases[case_index];
        unsigned int l;

        for (l = 0; l != 2; ++l) {
            uint8_t code[5] = {
                0x8f, 0xe9, (uint8_t)(0x78u | (l << 2)),
                test->opcode, 0xca
            };
            uint8_t memory[5] = {
                0x8f, 0xe9, (uint8_t)(0x78u | (l << 2)),
                test->opcode, 0x08
            };
            const int l_is_valid = test->shape == XOP_PACKED || l == 0;

            if (!l_is_valid) {
                expect_error(
                    code, sizeof(code), CDISASM_STATUS_INVALID_INSTRUCTION);
                expect_error(
                    memory, sizeof(memory),
                    CDISASM_STATUS_INVALID_INSTRUCTION);
                continue;
            }

#if USE_EXTRA_OPCODES
            {
                const cdisasm_x86_reg_id register_base = l != 0
                    ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
                const unsigned int register_size = l != 0 ? 32u : 16u;
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode_bulldozer(
                    CDISASM_MODE_64, code, sizeof(code), &decoded_size);

                EXPECT(decoded_size == sizeof(code));
                EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
                EXPECT(instruction.name_id == test->name_id);
                EXPECT((instruction.opcode_flags & CDISASM_PREFIX_XOP) != 0);
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_AVX));
                EXPECT(cdisasm_instruction_has_x86_group(
                    &instruction, CDISASM_X86_GROUP_XOP));
                expect_register_pair(
                    &instruction, register_base + 1u,
                    register_base + 2u, register_size);
                EXPECT(instruction.encoding.prefix_size == 3);
                EXPECT(instruction.encoding.opcode_offset == 3);
                EXPECT(instruction.encoding.opcode_size == 1);
                EXPECT(instruction.encoding.modrm_offset == 4);
                EXPECT(instruction.encoding.modrm == 0xca);
                EXPECT(instruction.encoding.immediate_count == 0);

#if USE_DISASM_FORMAT
                expect_format(
                    &instruction, test->mnemonic,
                    l != 0 ? "ymm" : "xmm");
#endif

                instruction = decode_bulldozer(
                    CDISASM_MODE_64, memory, sizeof(memory), &decoded_size);
                EXPECT(decoded_size == sizeof(memory));
                EXPECT(instruction.name_id == test->name_id);
                EXPECT(instruction.operand_count == 2);
                EXPECT(instruction.opcode[0].type
                       == CDISASM_OPERAND_REGISTER);
                EXPECT(instruction.opcode[0].reg == register_base + 1u);
                EXPECT(instruction.opcode[0].size == register_size);
                EXPECT(instruction.opcode[1].type
                       == CDISASM_OPERAND_MEMORY);
                EXPECT(instruction.opcode[1].base_reg
                       == CDISASM_X86_REG_RAX);
                EXPECT(instruction.opcode[1].size
                       == memory_size_for_shape(test->shape, l));
                EXPECT(instruction.opcode[1].access
                       == CDISASM_OPERAND_ACCESS_READ);
            }
#else
            expect_error(
                code, sizeof(code),
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            expect_error(
                memory, sizeof(memory),
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }
}

static void test_structural_ownership_and_reservations(void)
{
    size_t case_index;

    for (case_index = 0;
         case_index < sizeof(xop_cases) / sizeof(xop_cases[0]);
         ++case_index) {
        const uint8_t opcode = xop_cases[case_index].opcode;
        const uint8_t truncated[] = {0x8f, 0xe9, 0x78, opcode};
        const uint8_t wrong_w[] = {0x8f, 0xe9, 0xf8, opcode, 0xca};
        const uint8_t wrong_vvvv[] = {0x8f, 0xe9, 0x70, opcode, 0xca};
        const uint8_t wrong_pp[] = {0x8f, 0xe9, 0x79, opcode, 0xca};
        const uint8_t wrong_map[] = {0x8f, 0xea, 0x78, opcode, 0xca};
        const uint8_t reserved_map[] = {0x8f, 0xeb, 0x78, opcode, 0xca};

        expect_error(
            truncated, sizeof(truncated), CDISASM_STATUS_TRUNCATED);
        expect_error(wrong_w, sizeof(wrong_w),
                     CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error(wrong_vvvv, sizeof(wrong_vvvv),
                     CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error(wrong_pp, sizeof(wrong_pp),
                     CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error(wrong_map, sizeof(wrong_map),
                     CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error(reserved_map, sizeof(reserved_map),
                     CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

static void test_cpu_group_and_flag_gates(void)
{
    static const uint8_t code[] = {0x8f, 0xe9, 0x78, 0x80, 0xca};

#if USE_EXTRA_OPCODES
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    expect_error_mode(
        CDISASM_CPU_HASWELL, CDISASM_MODE_64, code, sizeof(code),
        CDISASM_X86_DECODE_FLAG_XOP,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error_mode(
        CDISASM_CPU_AMD_ZEN, CDISASM_MODE_64, code, sizeof(code),
        CDISASM_X86_DECODE_FLAG_XOP,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error_mode(
        CDISASM_CPU_AMD_ZEN_4, CDISASM_MODE_64, code, sizeof(code),
        CDISASM_X86_DECODE_FLAG_XOP,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error_mode(
        CDISASM_CPU_AMD_BULLDOZER, CDISASM_MODE_64, code, sizeof(code),
        CDISASM_X86_DECODE_FLAG_BASE,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error_mode(
        CDISASM_CPU_AMD_BULLDOZER, CDISASM_MODE_64, code, sizeof(code),
        CDISASM_X86_DECODE_FLAG_AVX,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    EXPECT((cdisasm_x86_cpu_decode_flag_mask(
                CDISASM_CPU_AMD_BULLDOZER, CDISASM_MODE_64)
            & (CDISASM_X86_DECODE_FLAG_AVX
               | CDISASM_X86_DECODE_FLAG_XOP))
           == (CDISASM_X86_DECODE_FLAG_AVX
               | CDISASM_X86_DECODE_FLAG_XOP));
    EXPECT((cdisasm_x86_cpu_decode_flag_mask(
                CDISASM_CPU_HASWELL, CDISASM_MODE_64)
            & CDISASM_X86_DECODE_FLAG_XOP) == 0);
    EXPECT((cdisasm_x86_cpu_decode_flag_mask(
                CDISASM_CPU_AMD_ZEN, CDISASM_MODE_64)
            & CDISASM_X86_DECODE_FLAG_XOP) == 0);

    instruction = decode_mode(
        CDISASM_CPU_X86, CDISASM_MODE_64, code, sizeof(code),
        CDISASM_X86_DECODE_FLAG_XOP, &decoded_size);
    EXPECT(decoded_size == sizeof(code));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VFRCZPS);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_XOP));
#else
    expect_error(
        code, sizeof(code), CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_non64_b_is_ignored(void)
{
    static const uint8_t register32[] = {0x8f, 0xc9, 0x78, 0x80, 0xca};
    static const uint8_t memory32[] = {0x8f, 0xc9, 0x78, 0xc1, 0x08};
    static const uint8_t raw_r_zero[] = {0x8f, 0x69, 0x78, 0x80, 0xca};
    static const uint8_t raw_x_zero[] = {0x8f, 0xa9, 0x78, 0x80, 0xca};

    expect_error_mode(
        CDISASM_CPU_X86, CDISASM_MODE_32,
        raw_r_zero, sizeof(raw_r_zero), XOP_STRUCTURAL_FLAGS,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error_mode(
        CDISASM_CPU_X86, CDISASM_MODE_32,
        raw_x_zero, sizeof(raw_x_zero), XOP_STRUCTURAL_FLAGS,
        CDISASM_STATUS_INVALID_INSTRUCTION);

#if USE_EXTRA_OPCODES
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_bulldozer(
            CDISASM_MODE_32,
            register32, sizeof(register32), &decoded_size);

        EXPECT(decoded_size == sizeof(register32));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VFRCZPS);
        expect_register_pair(
            &instruction, CDISASM_X86_REG_XMM1,
            CDISASM_X86_REG_XMM2, 16u);

        instruction = decode_bulldozer(
            CDISASM_MODE_32, memory32, sizeof(memory32), &decoded_size);
        EXPECT(decoded_size == sizeof(memory32));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPHADDBW);
        EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_EAX);

        instruction = decode_bulldozer(
            CDISASM_MODE_16,
            register32, sizeof(register32), &decoded_size);
        EXPECT(decoded_size == sizeof(register32));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VFRCZPS);
        expect_register_pair(
            &instruction, CDISASM_X86_REG_XMM1,
            CDISASM_X86_REG_XMM2, 16u);

        instruction = decode_bulldozer(
            CDISASM_MODE_64,
            register32, sizeof(register32), &decoded_size);
        EXPECT(decoded_size == sizeof(register32));
        expect_register_pair(
            &instruction, CDISASM_X86_REG_XMM1,
            CDISASM_X86_REG_XMM10, 16u);

        instruction = decode_bulldozer(
            CDISASM_MODE_64, memory32, sizeof(memory32), &decoded_size);
        EXPECT(decoded_size == sizeof(memory32));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPHADDBW);
        EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_R8);
    }
#else
    expect_error_mode(
        CDISASM_CPU_X86, CDISASM_MODE_32,
        register32, sizeof(register32), XOP_STRUCTURAL_FLAGS,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error_mode(
        CDISASM_CPU_X86, CDISASM_MODE_32,
        memory32, sizeof(memory32), XOP_STRUCTURAL_FLAGS,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error_mode(
        CDISASM_CPU_X86, CDISASM_MODE_16,
        register32, sizeof(register32), XOP_STRUCTURAL_FLAGS,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error_mode(
        CDISASM_CPU_X86, CDISASM_MODE_64,
        memory32, sizeof(memory32), XOP_STRUCTURAL_FLAGS,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

#undef XOP_STRUCTURAL_FLAGS

int main(void)
{
    test_complete_map9_matrix();
    test_structural_ownership_and_reservations();
    test_cpu_group_and_flag_gates();
    test_non64_b_is_ignored();

    if (failures != 0) {
        fprintf(stderr,
                "x86 XOP map-9 tests failed: %d (extra=%d, format=%d)\n",
                failures, USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
        return 1;
    }
    printf("x86 XOP map-9 tests passed (extra=%d, format=%d)\n",
           USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
    return 0;
}
