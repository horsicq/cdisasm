#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_X86_NAME_CLFLUSH == UINT16_C(917),
               "modern system name range start changed");
_Static_assert(CDISASM_X86_NAME_WBNOINVD == UINT16_C(924),
               "modern system name range end changed");
_Static_assert(CDISASM_X86_NAME_COUNT >= UINT16_C(925),
               "modern system name range is incomplete");
_Static_assert(CDISASM_X86_GROUP_CLFLUSH == UINT16_C(21),
               "CLFLUSH group ID changed");
_Static_assert(CDISASM_X86_GROUP_CLFLUSHOPT == UINT16_C(58),
               "CLFLUSHOPT group ID changed");

static int failures;

#if USE_EXTRA_OPCODES
#define SYSTEM_STRUCTURAL_FLAGS CDISASM_X86_DECODE_FLAG_ALL
#else
#define SYSTEM_STRUCTURAL_FLAGS CDISASM_X86_DECODE_FLAG_BASE
#endif

#define EXPECT(expression)                                                     \
    do {                                                                       \
        if (!(expression)) {                                                   \
            fprintf(stderr, "%s:%d: expectation failed: %s\n",              \
                    __FILE__, __LINE__, #expression);                          \
            ++failures;                                                        \
        }                                                                      \
    } while (0)

typedef struct modern_system_case {
    const char *label;
    uint8_t bytes[8];
    uint8_t size;
    cdisasm_cpu_id cpu;
    cdisasm_mode mode;
    cdisasm_x86_decode_option flag;
    cdisasm_x86_name_id name_id;
    uint8_t operand_count;
    uint8_t prefix_size;
    uint8_t opcode_size;
    uint8_t modrm_offset;
    cdisasm_x86_group_id group_id;
    uint8_t privileged;
} modern_system_case;

static const modern_system_case positive_cases[] = {
    {"CLFLUSH", {0x0f, 0xae, 0x38}, 3,
     CDISASM_CPU_PENTIUM_4, CDISASM_MODE_32,
     CDISASM_X86_DECODE_FLAG_MEMORY_HINTS, CDISASM_X86_NAME_CLFLUSH,
     1, 0, 2, 2, CDISASM_X86_GROUP_CLFLUSH, 0},
    {"CLFLUSHOPT", {0x66, 0x0f, 0xae, 0x38}, 4,
     CDISASM_CPU_SKYLAKE, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_MEMORY_HINTS, CDISASM_X86_NAME_CLFLUSHOPT,
     1, 1, 2, 3, CDISASM_X86_GROUP_CLFLUSHOPT, 0},
    {"CLWB", {0x66, 0x0f, 0xae, 0x30}, 4,
     CDISASM_CPU_SKYLAKE_SP, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_MEMORY_HINTS, CDISASM_X86_NAME_CLWB,
     1, 1, 2, 3, 0, 0},
    {"RDPID", {0xf3, 0x0f, 0xc7, 0xf8}, 4,
     CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_SYSTEM, CDISASM_X86_NAME_RDPID,
     1, 1, 2, 3, 0, 0},
    {"SERIALIZE", {0x0f, 0x01, 0xe8}, 3,
     CDISASM_CPU_ALDER_LAKE, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_SYSTEM, CDISASM_X86_NAME_SERIALIZE,
     0, 0, 2, 2, 0, 0},
    {"TDCALL", {0x66, 0x0f, 0x01, 0xcc}, 4,
     CDISASM_CPU_X86, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_SYSTEM, CDISASM_X86_NAME_TDCALL,
     0, 1, 2, 3, CDISASM_X86_GROUP_TDX, 1},
    {"SEAMRET", {0x66, 0x0f, 0x01, 0xcd}, 4,
     CDISASM_CPU_X86, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_SYSTEM, CDISASM_X86_NAME_SEAMRET,
     0, 1, 2, 3, CDISASM_X86_GROUP_TDX, 1},
    {"SEAMOPS", {0x66, 0x0f, 0x01, 0xce}, 4,
     CDISASM_CPU_X86, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_SYSTEM, CDISASM_X86_NAME_SEAMOPS,
     0, 1, 2, 3, CDISASM_X86_GROUP_TDX, 1},
    {"SEAMCALL", {0x66, 0x0f, 0x01, 0xcf}, 4,
     CDISASM_CPU_X86, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_SYSTEM, CDISASM_X86_NAME_SEAMCALL,
     0, 1, 2, 3, CDISASM_X86_GROUP_TDX, 1},
    {"MOVDIRI", {0x0f, 0x38, 0xf9, 0x08}, 4,
     CDISASM_CPU_TIGER_LAKE, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_SYSTEM, CDISASM_X86_NAME_MOVDIRI,
     2, 0, 3, 3, 0, 0},
    {"MOVDIR64B", {0x66, 0x0f, 0x38, 0xf8, 0x08}, 5,
     CDISASM_CPU_TIGER_LAKE, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_SYSTEM, CDISASM_X86_NAME_MOVDIR64B,
     3, 1, 3, 4, 0, 0},
    {"WBNOINVD", {0xf3, 0x0f, 0x09}, 3,
     CDISASM_CPU_TIGER_LAKE, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_SYSTEM, CDISASM_X86_NAME_WBNOINVD,
     0, 1, 2, 0, 0, 1},
    {"XSAVEOPT", {0x0f, 0xae, 0x30}, 3,
     CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_STATE, CDISASM_X86_NAME_XSAVEOPT,
     1, 0, 2, 2, CDISASM_X86_GROUP_XSAVEOPT, 0},
    {"ENQCMD", {0xf2, 0x0f, 0x38, 0xf8, 0x08}, 5,
     CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_SYSTEM, CDISASM_X86_NAME_ENQCMD,
     2, 1, 3, 4, CDISASM_X86_GROUP_ENQCMD, 0},
    {"ENQCMDS", {0xf3, 0x0f, 0x38, 0xf8, 0x08}, 5,
     CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_SYSTEM, CDISASM_X86_NAME_ENQCMDS,
     2, 1, 3, 4, CDISASM_X86_GROUP_ENQCMD, 1},
    {"SENDUIPI", {0xf3, 0x0f, 0xc7, 0xf0}, 4,
     CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_SYSTEM, CDISASM_X86_NAME_SENDUIPI,
     1, 1, 2, 3, CDISASM_X86_GROUP_UINTR, 0},
    {"UIRET", {0xf3, 0x0f, 0x01, 0xec}, 4,
     CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_SYSTEM, CDISASM_X86_NAME_UIRET,
     0, 1, 2, 3, CDISASM_X86_GROUP_UINTR, 0},
    {"TESTUI", {0xf3, 0x0f, 0x01, 0xed}, 4,
     CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_SYSTEM, CDISASM_X86_NAME_TESTUI,
     0, 1, 2, 3, CDISASM_X86_GROUP_UINTR, 0},
    {"STUI", {0xf3, 0x0f, 0x01, 0xef}, 4,
     CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_MODE_64,
     CDISASM_X86_DECODE_FLAG_SYSTEM, CDISASM_X86_NAME_STUI,
     0, 1, 2, 3, CDISASM_X86_GROUP_UINTR, 0}
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

    memset(&instruction, 0xa5, sizeof(instruction));
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
    const char *label,
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
                "%s: expected status %u, got status %u and size %u\n",
                label, (unsigned int)status,
                (unsigned int)instruction.last_error_id,
                (unsigned int)decoded_size);
    }
    EXPECT(decoded_size == 0);
    EXPECT(is_error_only(&instruction, status));
}

#if USE_EXTRA_OPCODES
static cdisasm_instruction expect_success(
    const modern_system_case *test)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode_mode(
        test->cpu, test->mode, test->bytes, test->size,
        test->flag, &decoded_size);

    if (decoded_size != test->size
        || instruction.last_error_id != CDISASM_STATUS_OK
        || instruction.name_id != test->name_id) {
        fprintf(stderr,
                "%s: expected name %u and size %u, got name %u, "
                "status %u and size %u\n",
                test->label, (unsigned int)test->name_id,
                (unsigned int)test->size, (unsigned int)instruction.name_id,
                (unsigned int)instruction.last_error_id,
                (unsigned int)decoded_size);
    }
    EXPECT(decoded_size == test->size);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == test->name_id);
    EXPECT(instruction.operand_count == test->operand_count);
    EXPECT(instruction.opcode_size == test->size);
    EXPECT(instruction.encoding.prefix_size == test->prefix_size);
    EXPECT(instruction.encoding.opcode_offset == test->prefix_size);
    EXPECT(instruction.encoding.opcode_size == test->opcode_size);
    EXPECT(instruction.encoding.modrm_offset == test->modrm_offset);
    EXPECT(((instruction.opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0)
           == test->privileged);
    if (test->group_id != 0) {
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, test->group_id));
    }
    return instruction;
}

static void check_positive_operands(
    const modern_system_case *test,
    const cdisasm_instruction *instruction)
{
    if (test->name_id == CDISASM_X86_NAME_CLFLUSH
        || test->name_id == CDISASM_X86_NAME_CLFLUSHOPT
        || test->name_id == CDISASM_X86_NAME_CLWB) {
        const cdisasm_x86_reg_id expected_base =
            test->mode == CDISASM_MODE_32
                ? CDISASM_X86_REG_EAX : CDISASM_X86_REG_RAX;

        EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction->opcode[0].size == 1u);
        EXPECT(instruction->opcode[0].base_reg == expected_base);
        EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT((instruction->opcode[0].flags
                & CDISASM_OPERAND_FLAG_ADDRESS_ONLY) != 0);
        return;
    }
    if (test->name_id == CDISASM_X86_NAME_RDPID) {
        EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction->opcode[0].reg == CDISASM_X86_REG_RAX);
        EXPECT(instruction->opcode[0].size == 8u);
        EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        return;
    }
    if (test->name_id == CDISASM_X86_NAME_MOVDIRI) {
        EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction->opcode[0].base_reg == CDISASM_X86_REG_RAX);
        EXPECT(instruction->opcode[0].size == 4u);
        EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction->opcode[1].reg == CDISASM_X86_REG_ECX);
        EXPECT(instruction->opcode[1].size == 4u);
        EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
        return;
    }
    if (test->name_id == CDISASM_X86_NAME_MOVDIR64B) {
        EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction->opcode[0].reg == CDISASM_X86_REG_RCX);
        EXPECT(instruction->opcode[0].size == 8u);
        EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction->opcode[1].base_reg == CDISASM_X86_REG_RAX);
        EXPECT(instruction->opcode[1].size == 64u);
        EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction->opcode[2].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction->opcode[2].base_reg == CDISASM_X86_REG_RCX);
        EXPECT(instruction->opcode[2].size == 64u);
        EXPECT(instruction->opcode[2].access == CDISASM_OPERAND_ACCESS_WRITE);
        EXPECT((instruction->opcode[2].flags
                & CDISASM_OPERAND_FLAG_IMPLICIT) != 0);
        return;
    }
    if (test->name_id == CDISASM_X86_NAME_XSAVEOPT) {
        EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction->opcode[0].base_reg == CDISASM_X86_REG_RAX);
        EXPECT(instruction->opcode[0].size
            == CDISASM_X86_OPERAND_SIZE_VARIABLE);
        EXPECT(instruction->opcode[0].access
            == CDISASM_OPERAND_ACCESS_READ_WRITE);
        return;
    }
    if (test->name_id == CDISASM_X86_NAME_ENQCMD
        || test->name_id == CDISASM_X86_NAME_ENQCMDS) {
        EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction->opcode[0].reg == CDISASM_X86_REG_RCX);
        EXPECT(instruction->opcode[0].size == 8u);
        EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction->opcode[1].base_reg == CDISASM_X86_REG_RAX);
        EXPECT(instruction->opcode[1].size == 64u);
        EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
        return;
    }
    if (test->name_id == CDISASM_X86_NAME_SENDUIPI) {
        EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction->opcode[0].reg == CDISASM_X86_REG_RAX);
        EXPECT(instruction->opcode[0].size == 8u);
        EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
    }
}
#endif

static void test_catalog_operands_and_build_ownership(void)
{
    size_t index;

    EXPECT(sizeof(positive_cases) / sizeof(positive_cases[0]) == 19u);
    for (index = 0;
         index < sizeof(positive_cases) / sizeof(positive_cases[0]);
         ++index) {
#if USE_EXTRA_OPCODES
        cdisasm_instruction instruction = expect_success(&positive_cases[index]);

        check_positive_operands(&positive_cases[index], &instruction);
        expect_error_mode(
            positive_cases[index].label,
            positive_cases[index].cpu,
            positive_cases[index].mode,
            positive_cases[index].bytes,
            positive_cases[index].size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
        expect_error_mode(
            positive_cases[index].label,
            CDISASM_CPU_X86,
            positive_cases[index].mode,
            positive_cases[index].bytes,
            positive_cases[index].size,
            CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
}

static void test_modes_and_widths(void)
{
    static const uint8_t clflush[] = {0x0f, 0xae, 0x38};
    static const uint8_t rdpid[] = {0xf3, 0x0f, 0xc7, 0xf9};
    static const uint8_t serialize[] = {0x0f, 0x01, 0xe8};
    static const cdisasm_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t index;

    for (index = 0; index < sizeof(modes) / sizeof(modes[0]); ++index) {
#if USE_EXTRA_OPCODES
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_mode(
            CDISASM_CPU_X86, modes[index], clflush, sizeof(clflush),
            CDISASM_X86_DECODE_FLAG_MEMORY_HINTS, &decoded_size);

        EXPECT(decoded_size == sizeof(clflush));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_CLFLUSH);
        EXPECT(instruction.opcode[0].base_reg
               == (modes[index] == CDISASM_MODE_16
                       ? CDISASM_X86_REG_BX
                       : (modes[index] == CDISASM_MODE_32
                              ? CDISASM_X86_REG_EAX
                              : CDISASM_X86_REG_RAX)));
        EXPECT(instruction.opcode[0].index_reg
               == (modes[index] == CDISASM_MODE_16
                       ? CDISASM_X86_REG_SI : CDISASM_X86_REG_NONE));

        instruction = decode_mode(
            CDISASM_CPU_X86, modes[index], rdpid, sizeof(rdpid),
            CDISASM_X86_DECODE_FLAG_SYSTEM, &decoded_size);
        EXPECT(decoded_size == sizeof(rdpid));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_RDPID);
        EXPECT(instruction.opcode[0].reg
               == (modes[index] == CDISASM_MODE_64
                       ? CDISASM_X86_REG_RCX : CDISASM_X86_REG_ECX));
        EXPECT(instruction.opcode[0].size
               == (modes[index] == CDISASM_MODE_64 ? 8u : 4u));

        instruction = decode_mode(
            CDISASM_CPU_X86, modes[index], serialize, sizeof(serialize),
            CDISASM_X86_DECODE_FLAG_SYSTEM, &decoded_size);
        EXPECT(decoded_size == sizeof(serialize));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_SERIALIZE);
#else
        expect_error_mode(
            "CLFLUSH mode ownership", CDISASM_CPU_X86, modes[index],
            clflush, sizeof(clflush), CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error_mode(
            "RDPID mode ownership", CDISASM_CPU_X86, modes[index],
            rdpid, sizeof(rdpid), CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error_mode(
            "SERIALIZE mode ownership", CDISASM_CPU_X86, modes[index],
            serialize, sizeof(serialize), CDISASM_X86_DECODE_FLAG_BASE,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }

#if USE_EXTRA_OPCODES
    {
        static const uint8_t rdpid_66_rex_b[] = {
            0x66, 0xf3, 0x41, 0x0f, 0xc7, 0xf8
        };
        static const uint8_t movdiri64[] = {
            0x48, 0x0f, 0x38, 0xf9, 0x08
        };
        static const uint8_t movdir64b32[] = {
            0x66, 0x0f, 0x38, 0xf8, 0x08
        };
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_mode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            rdpid_66_rex_b, sizeof(rdpid_66_rex_b),
            CDISASM_X86_DECODE_FLAG_SYSTEM, &decoded_size);

        EXPECT(decoded_size == sizeof(rdpid_66_rex_b));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_RDPID);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_R8);
        EXPECT(instruction.opcode[0].size == 8u);

        instruction = decode_mode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            movdiri64, sizeof(movdiri64),
            CDISASM_X86_DECODE_FLAG_SYSTEM, &decoded_size);
        EXPECT(decoded_size == sizeof(movdiri64));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_MOVDIRI);
        EXPECT(instruction.opcode[0].size == 8u);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_RCX);

        instruction = decode_mode(
            CDISASM_CPU_X86, CDISASM_MODE_32,
            movdir64b32, sizeof(movdir64b32),
            CDISASM_X86_DECODE_FLAG_SYSTEM, &decoded_size);
        EXPECT(decoded_size == sizeof(movdir64b32));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_MOVDIR64B);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_ECX);
        EXPECT(instruction.opcode[0].size == 4u);
        EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_EAX);
        EXPECT(instruction.opcode[1].size == 64u);
        EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_ECX);
        EXPECT(instruction.opcode[2].segment_reg == CDISASM_X86_REG_ES);
        EXPECT(instruction.opcode[2].access == CDISASM_OPERAND_ACCESS_WRITE);
        EXPECT((instruction.opcode[2].flags
                & CDISASM_OPERAND_FLAG_IMPLICIT) != 0);
    }
#endif
}

static void test_cpu_and_runtime_gates(void)
{
#if USE_EXTRA_OPCODES
    static const struct gate_case {
        const char *label;
        uint8_t bytes[5];
        uint8_t size;
        cdisasm_mode mode;
        cdisasm_cpu_id supporting_cpu;
        cdisasm_cpu_id rejecting_cpu;
        cdisasm_x86_decode_option flag;
        cdisasm_x86_decode_option wrong_flag;
        cdisasm_x86_name_id name_id;
    } cases[] = {
        {"CLFLUSH gate", {0x0f, 0xae, 0x38}, 3, CDISASM_MODE_32,
         CDISASM_CPU_PENTIUM_4, CDISASM_CPU_80486,
         CDISASM_X86_DECODE_FLAG_MEMORY_HINTS,
         CDISASM_X86_DECODE_FLAG_SYSTEM, CDISASM_X86_NAME_CLFLUSH},
        {"CLFLUSHOPT gate", {0x66, 0x0f, 0xae, 0x38}, 4, CDISASM_MODE_64,
         CDISASM_CPU_SKYLAKE, CDISASM_CPU_BROADWELL,
         CDISASM_X86_DECODE_FLAG_MEMORY_HINTS,
         CDISASM_X86_DECODE_FLAG_SYSTEM, CDISASM_X86_NAME_CLFLUSHOPT},
        {"CLWB gate", {0x66, 0x0f, 0xae, 0x30}, 4, CDISASM_MODE_64,
         CDISASM_CPU_SKYLAKE_SP, CDISASM_CPU_SKYLAKE,
         CDISASM_X86_DECODE_FLAG_MEMORY_HINTS,
         CDISASM_X86_DECODE_FLAG_SYSTEM, CDISASM_X86_NAME_CLWB},
        {"RDPID gate", {0xf3, 0x0f, 0xc7, 0xf8}, 4, CDISASM_MODE_64,
         CDISASM_CPU_ICE_LAKE, CDISASM_CPU_SKYLAKE,
         CDISASM_X86_DECODE_FLAG_SYSTEM,
         CDISASM_X86_DECODE_FLAG_MEMORY_HINTS, CDISASM_X86_NAME_RDPID},
        {"SERIALIZE gate", {0x0f, 0x01, 0xe8}, 3, CDISASM_MODE_64,
         CDISASM_CPU_ALDER_LAKE, CDISASM_CPU_TIGER_LAKE,
         CDISASM_X86_DECODE_FLAG_SYSTEM,
         CDISASM_X86_DECODE_FLAG_MEMORY_HINTS, CDISASM_X86_NAME_SERIALIZE},
        {"MOVDIRI gate", {0x0f, 0x38, 0xf9, 0x08}, 4, CDISASM_MODE_64,
         CDISASM_CPU_TIGER_LAKE, CDISASM_CPU_ICE_LAKE,
         CDISASM_X86_DECODE_FLAG_SYSTEM,
         CDISASM_X86_DECODE_FLAG_MEMORY_HINTS, CDISASM_X86_NAME_MOVDIRI},
        {"MOVDIR64B gate", {0x66, 0x0f, 0x38, 0xf8, 0x08}, 5,
         CDISASM_MODE_64,
         CDISASM_CPU_TIGER_LAKE, CDISASM_CPU_ICE_LAKE,
         CDISASM_X86_DECODE_FLAG_SYSTEM,
         CDISASM_X86_DECODE_FLAG_MEMORY_HINTS, CDISASM_X86_NAME_MOVDIR64B},
        {"WBNOINVD gate", {0xf3, 0x0f, 0x09}, 3, CDISASM_MODE_64,
         CDISASM_CPU_TIGER_LAKE, CDISASM_CPU_ICE_LAKE,
         CDISASM_X86_DECODE_FLAG_SYSTEM,
         CDISASM_X86_DECODE_FLAG_MEMORY_HINTS, CDISASM_X86_NAME_WBNOINVD}
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_mode(
            cases[index].supporting_cpu, cases[index].mode,
            cases[index].bytes, cases[index].size,
            cases[index].flag, &decoded_size);

        EXPECT(decoded_size == cases[index].size);
        EXPECT(instruction.name_id == cases[index].name_id);
        EXPECT((cdisasm_x86_cpu_decode_flag_mask(
                    cases[index].supporting_cpu, cases[index].mode)
                & cases[index].flag) != 0);
        expect_error_mode(
            cases[index].label, cases[index].supporting_cpu,
            cases[index].mode, cases[index].bytes, cases[index].size,
            cases[index].wrong_flag,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

        if (cases[index].name_id != CDISASM_X86_NAME_WBNOINVD) {
            expect_error_mode(
                cases[index].label, cases[index].rejecting_cpu,
                cases[index].mode, cases[index].bytes, cases[index].size,
                cases[index].flag, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }

    {
        static const uint8_t wbnoinvd[] = {0xf3, 0x0f, 0x09};
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_mode(
            CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
            wbnoinvd, sizeof(wbnoinvd),
            CDISASM_X86_DECODE_FLAG_SYSTEM, &decoded_size);

        EXPECT(decoded_size == sizeof(wbnoinvd));
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_WBINVD);
        EXPECT((instruction.opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0);
    }
#endif
}

static void test_collisions_invalid_and_truncated(void)
{
    static const struct error_case {
        const char *label;
        uint8_t bytes[8];
        uint8_t size;
        cdisasm_status status;
    } cases[] = {
        {"CLFLUSHOPT register collision", {0x66, 0x0f, 0xae, 0xf8}, 4,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"operand-size SERIALIZE", {0x66, 0x0f, 0x01, 0xe8}, 4,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"prefixed MOVDIRI", {0x66, 0x0f, 0x38, 0xf9, 0x08}, 5,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"register MOVDIRI", {0x0f, 0x38, 0xf9, 0xc8}, 4,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"register MOVDIR64B", {0x66, 0x0f, 0x38, 0xf8, 0xc8}, 5,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"unprefixed 0F38 F8", {0x0f, 0x38, 0xf8, 0x08}, 4,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"RDPID memory", {0xf3, 0x0f, 0xc7, 0x38}, 4,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"locked CLFLUSH", {0xf0, 0x0f, 0xae, 0x38}, 4,
         CDISASM_STATUS_INVALID_INSTRUCTION},
        {"truncated 0F AE", {0x0f, 0xae}, 2,
         CDISASM_STATUS_TRUNCATED},
        {"truncated CLWB", {0x66, 0x0f, 0xae}, 3,
         CDISASM_STATUS_TRUNCATED},
        {"truncated CLFLUSH displacement", {0x0f, 0xae, 0x78}, 3,
         CDISASM_STATUS_TRUNCATED},
        {"truncated RDPID", {0xf3, 0x0f, 0xc7}, 3,
         CDISASM_STATUS_TRUNCATED},
        {"truncated Group 7", {0x0f, 0x01}, 2,
         CDISASM_STATUS_TRUNCATED},
        {"truncated MOVDIRI", {0x0f, 0x38, 0xf9}, 3,
         CDISASM_STATUS_TRUNCATED},
        {"truncated MOVDIR64B", {0x66, 0x0f, 0x38, 0xf8}, 4,
         CDISASM_STATUS_TRUNCATED},
        {"truncated MOVDIRI displacement",
         {0x0f, 0x38, 0xf9, 0x88, 0x01, 0x02, 0x03}, 7,
         CDISASM_STATUS_TRUNCATED}
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_error_mode(
            cases[index].label, CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].bytes, cases[index].size,
            SYSTEM_STRUCTURAL_FLAGS, cases[index].status);
    }

#if USE_EXTRA_OPCODES
    {
        static const uint8_t tpause[] = {0x66, 0x0f, 0xae, 0xf0};
        static const uint8_t setssbsy[] = {0xf3, 0x0f, 0x01, 0xe8};
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_mode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            tpause, sizeof(tpause),
            CDISASM_X86_DECODE_FLAG_SYSTEM, &decoded_size);

        EXPECT(decoded_size == sizeof(tpause));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_TPAUSE);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_WAITPKG));

        instruction = decode_mode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            setssbsy, sizeof(setssbsy),
            CDISASM_X86_DECODE_FLAG_CET, &decoded_size);
        EXPECT(decoded_size == sizeof(setssbsy));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_SETSSBSY);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_CET_SS));
    }
#endif
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(
    const cdisasm_instruction *instruction,
    uint32_t syntax,
    const char *expected)
{
    char text[128];
    size_t length = cdisasm_x86_format(
        instruction, syntax, text, sizeof(text));

    if (strcmp(text, expected) != 0) {
        fprintf(stderr, "expected format '%s', got '%s'\n", expected, text);
    }
    EXPECT(length == strlen(expected));
    EXPECT(strcmp(text, expected) == 0);
}

static void test_formatting(void)
{
    static const struct format_case {
        uint8_t bytes[8];
        uint8_t size;
        cdisasm_x86_decode_option flag;
        cdisasm_x86_name_id name_id;
        const char *intel;
        const char *att;
    } cases[] = {
        {{0x41, 0x0f, 0xae, 0x79, 0x10}, 5,
         CDISASM_X86_DECODE_FLAG_MEMORY_HINTS, CDISASM_X86_NAME_CLFLUSH,
         "clflush [r9 + 0x10]", "clflush 0x10(%r9)"},
        {{0x66, 0x41, 0x0f, 0xae, 0x79, 0x10}, 6,
         CDISASM_X86_DECODE_FLAG_MEMORY_HINTS, CDISASM_X86_NAME_CLFLUSHOPT,
         "clflushopt [r9 + 0x10]", "clflushopt 0x10(%r9)"},
        {{0x66, 0x41, 0x0f, 0xae, 0x71, 0x10}, 6,
         CDISASM_X86_DECODE_FLAG_MEMORY_HINTS, CDISASM_X86_NAME_CLWB,
         "clwb [r9 + 0x10]", "clwb 0x10(%r9)"},
        {{0xf3, 0x41, 0x0f, 0xc7, 0xf8}, 5,
         CDISASM_X86_DECODE_FLAG_SYSTEM, CDISASM_X86_NAME_RDPID,
         "rdpid r8", "rdpid %r8"},
        {{0x0f, 0x01, 0xe8}, 3,
         CDISASM_X86_DECODE_FLAG_SYSTEM, CDISASM_X86_NAME_SERIALIZE,
         "serialize", "serialize"},
        {{0x45, 0x0f, 0x38, 0xf9, 0x51, 0x10}, 6,
         CDISASM_X86_DECODE_FLAG_SYSTEM, CDISASM_X86_NAME_MOVDIRI,
         "movdiri dword ptr [r9 + 0x10], r10d",
         "movdiri %r10d, 0x10(%r9)"},
        {{0x66, 0x45, 0x0f, 0x38, 0xf8, 0x51, 0x10}, 7,
         CDISASM_X86_DECODE_FLAG_SYSTEM, CDISASM_X86_NAME_MOVDIR64B,
         "movdir64b r10, zmmword ptr [r9 + 0x10], zmmword ptr [r10]",
         "movdir64b (%r10), 0x10(%r9), %r10"},
        {{0xf3, 0x0f, 0x09}, 3,
         CDISASM_X86_DECODE_FLAG_SYSTEM, CDISASM_X86_NAME_WBNOINVD,
         "wbnoinvd", "wbnoinvd"},
        {{0x0f, 0xae, 0x30}, 3,
         CDISASM_X86_DECODE_FLAG_STATE, CDISASM_X86_NAME_XSAVEOPT,
         "xsaveopt [rax]", "xsaveopt (%rax)"},
        {{0xf2, 0x0f, 0x38, 0xf8, 0x08}, 5,
         CDISASM_X86_DECODE_FLAG_SYSTEM, CDISASM_X86_NAME_ENQCMD,
         "enqcmd rcx, zmmword ptr [rax]", "enqcmd (%rax), %rcx"},
        {{0xf3, 0x0f, 0x38, 0xf8, 0x08}, 5,
         CDISASM_X86_DECODE_FLAG_SYSTEM, CDISASM_X86_NAME_ENQCMDS,
         "enqcmds rcx, zmmword ptr [rax]", "enqcmds (%rax), %rcx"},
        {{0xf3, 0x0f, 0xc7, 0xf0}, 4,
         CDISASM_X86_DECODE_FLAG_SYSTEM, CDISASM_X86_NAME_SENDUIPI,
         "senduipi rax", "senduipi %rax"}
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_mode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].bytes, cases[index].size,
            cases[index].flag, &decoded_size);

        EXPECT(decoded_size == cases[index].size);
        EXPECT(instruction.name_id == cases[index].name_id);
        expect_format(
            &instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
            cases[index].intel);
        expect_format(
            &instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
            cases[index].att);
    }
}
#endif

int main(void)
{
    test_catalog_operands_and_build_ownership();
    test_modes_and_widths();
    test_cpu_and_runtime_gates();
    test_collisions_invalid_and_truncated();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatting();
#endif

    if (failures != 0) {
        fprintf(stderr,
                "%d modern x86 system test(s) failed "
                "(extra=%d, format=%d)\n",
                failures, USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
        return 1;
    }
    printf("modern x86 system tests passed (extra=%d, format=%d)\n",
           USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
    return 0;
}
