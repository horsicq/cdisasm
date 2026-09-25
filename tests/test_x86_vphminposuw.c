#include "cdisasm/cdisasm_x86.h"
#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define EXPECT(expression) do { if (!(expression)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expression); \
    ++failures; } } while (0)

_Static_assert(CDISASM_X86_NAME_VPHMINPOSUW == UINT16_C(1855),
    "VPHMINPOSUW name ID changed");
_Static_assert(CDISASM_X86_GROUP_AVX == UINT16_C(37)
        && CDISASM_X86_DECODE_BIT_AVX == UINT32_C(8),
    "VPHMINPOSUW AVX IDs changed");

static int is_error_only(const cdisasm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static cdisasm_instruction decode(cdisasm_cpu_id cpu, cdisasm_mode mode,
    const uint8_t *code, size_t size,
    const cdisasm_x86_decode_flags *flags, uint32_t *decoded_size)
{
    cdisasm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    *decoded_size = cdisasm_x86_decode(cpu, mode, code, size,
        UINT64_C(0x1000), flags, &instruction);
    return instruction;
}

static void expect_error(const char *label, cdisasm_mode mode,
    const uint8_t *code, size_t size,
    const cdisasm_x86_decode_flags *flags, cdisasm_status status)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(CDISASM_CPU_X86, mode,
        code, size, flags, &decoded_size);

    if (decoded_size != 0u || !is_error_only(&instruction, status)) {
        fprintf(stderr, "%s: got size/status %u/%u, expected 0/%u\n",
            label, (unsigned int)decoded_size,
            (unsigned int)instruction.last_error_id, (unsigned int)status);
    }
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(&instruction, status));
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_decode_flags all_flags(cdisasm_mode mode)
{
    cdisasm_x86_decode_flags flags;

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_X86, mode, &flags) == CDISASM_STATUS_OK);
    return flags;
}

static cdisasm_x86_decode_flags selected_flags(int avx, int avx2)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    if (avx) {
        EXPECT(cdisasm_decode_flags_set_bit(
            &flags, CDISASM_X86_DECODE_BIT_AVX));
    }
    if (avx2) {
        EXPECT(cdisasm_decode_flags_set_bit(
            &flags, CDISASM_X86_DECODE_BIT_AVX2));
    }
    return flags;
}

static void check_instruction(const cdisasm_instruction *instruction,
    uint32_t decoded_size, cdisasm_mode mode, int register_form)
{
    size_t index;

    EXPECT(decoded_size >= 5u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == CDISASM_X86_NAME_VPHMINPOSUW);
    EXPECT(instruction->form_id == (register_form
        ? UINT16_C(7041) : UINT16_C(7040)));
    EXPECT(instruction->operand_count == 2u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE
            | CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_PREFIX_VEX | CDISASM_PREFIX_XOP
            | CDISASM_PREFIX_EVEX | CDISASM_PREFIX_REX2))
        == CDISASM_PREFIX_VEX);
    EXPECT(instruction->encoding.prefix_size >= 3u);
    EXPECT(instruction->encoding.opcode_size == 1u);
    EXPECT(instruction->encoding.modrm_offset
        == instruction->encoding.opcode_offset + 1u);
    EXPECT(instruction->encoding.immediate_count == 0u);
    EXPECT(instruction->encoding.selector_offset == 0u);
    for (index = 0u; index < 2u; ++index) {
        const cdisasm_opcode *operand = &instruction->opcode[index];
        const int memory = !register_form && index == 1u;

        EXPECT(operand->type == (memory
            ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
        EXPECT(operand->size == 16u);
        EXPECT(operand->access == (index == 0u
            ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ));
        EXPECT(operand->broadcast == CDISASM_X86_BROADCAST_NONE);
        if (!memory) {
            EXPECT(operand->reg >= CDISASM_X86_REG_XMM0);
            EXPECT(operand->reg <= CDISASM_X86_REG_XMM15);
            EXPECT(operand->flags == 0u);
            if (mode != CDISASM_MODE_64) {
                EXPECT(operand->reg <= CDISASM_X86_REG_XMM7);
            }
        } else {
            EXPECT((operand->flags
                & (CDISASM_OPERAND_FLAG_IMPLICIT
                    | CDISASM_OPERAND_FLAG_ADDRESS_ONLY)) == 0u);
        }
    }
    EXPECT(instruction->mask_reg == CDISASM_X86_REG_NONE);
    EXPECT(instruction->mask_mode == CDISASM_X86_MASK_NONE);
    EXPECT(instruction->rounding == CDISASM_X86_ROUNDING_NONE);
    EXPECT(instruction->sae == CDISASM_X86_SAE_NONE);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT(instruction->branch_target == 0u);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX));
    EXPECT(!cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_AVX2));
}
#endif

static void test_complete_c4_partition(void)
{
    static const cdisasm_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
    static const uint64_t expected_forms[2] = {4608u, 1536u};
    uint64_t form_counts[2] = {0u, 0u};
    uint64_t allocated = 0u;
    uint64_t reserved = 0u;
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        const int long_mode = modes[mode_index] == CDISASM_MODE_64;
        const unsigned int p0_count = long_mode ? 8u : 2u;
        unsigned int p0_index;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
#endif

        for (p0_index = 0u; p0_index < p0_count; ++p0_index) {
            const uint8_t p0 = long_mode
                ? (uint8_t)((p0_index << 5) | 2u)
                : (uint8_t)(0xc2u | (p0_index << 5));
            unsigned int p1;

            for (p1 = 0u; p1 <= UINT8_MAX; ++p1) {
                const int valid = (p1 & UINT8_C(0x7f))
                    == UINT8_C(0x79);
                unsigned int modrm;

                for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                    const uint8_t code[15] = {
                        0xc4,p0,(uint8_t)p1,0x41,(uint8_t)modrm,
                        0x24,0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,0x90};
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

                    if (valid) {
                        const int register_form =
                            (modrm & UINT8_C(0xc0)) == UINT8_C(0xc0);
#if USE_EXTRA_OPCODES
                        check_instruction(&instruction, decoded_size,
                            modes[mode_index], register_form);
#else
                        EXPECT(decoded_size == 0u);
                        EXPECT(is_error_only(&instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                        ++form_counts[register_form ? 1u : 0u];
                        ++allocated;
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
    EXPECT(allocated == UINT64_C(6144));
    EXPECT(reserved == UINT64_C(780288));
    EXPECT(form_counts[0] == expected_forms[0]);
    EXPECT(form_counts[1] == expected_forms[1]);
}

static void test_forms_gates_aliases(void)
{
    static const uint8_t memory[] = {0xc4,0xe2,0x79,0x41,0x00};
    static const uint8_t reg[] = {0xc4,0xe2,0xf9,0x41,0xc2};
    static const uint8_t high[] = {0xc4,0x42,0x79,0x41,0xcb};
    static const uint8_t nonlong[] = {0xc4,0xc2,0x79,0x41,0xc2};
    static const uint8_t address[] = {0x67,0xc4,0xe2,0x79,0x41,0x00};
    size_t index;
#if USE_EXTRA_OPCODES
    static const cdisasm_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
#endif

#if USE_EXTRA_OPCODES
    for (index = 0u; index < 3u; ++index) {
        cdisasm_x86_decode_flags flags = all_flags(modes[index]);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            modes[index], reg, sizeof(reg), &flags, &decoded_size);

        check_instruction(&instruction, decoded_size, modes[index], 1);
    }
    {
        const cdisasm_x86_decode_flags none = selected_flags(0, 0);
        const cdisasm_x86_decode_flags avx = selected_flags(1, 0);
        const cdisasm_x86_decode_flags avx2 = selected_flags(0, 1);
        cdisasm_x86_decode_flags profile;
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        expect_error("VPHMINPOSUW needs AVX", CDISASM_MODE_64,
            reg, sizeof(reg), &none, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("AVX2 alone does not admit VPHMINPOSUW",
            CDISASM_MODE_64, reg, sizeof(reg), &avx2,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            reg, sizeof(reg), &avx, &decoded_size);
        EXPECT(decoded_size == sizeof(reg));
        EXPECT(cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_SANDY_BRIDGE,
            CDISASM_MODE_64, &profile) == CDISASM_STATUS_OK);
        instruction = decode(CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64,
            reg, sizeof(reg), &profile, &decoded_size);
        EXPECT(decoded_size == sizeof(reg));
        EXPECT(instruction.form_id == UINT16_C(7041));
    }
    {
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            CDISASM_MODE_64, memory, sizeof(memory), &flags, &decoded_size);

        check_instruction(&instruction, decoded_size, CDISASM_MODE_64, 0);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            high, sizeof(high), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(high));
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM9);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM11);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            address, sizeof(address), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(address));
        EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_EAX);
    }
    {
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_32);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            CDISASM_MODE_32, nonlong, sizeof(nonlong), &flags,
            &decoded_size);

        EXPECT(decoded_size == sizeof(nonlong));
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM2);
    }
#else
    const uint8_t *cases[] = {memory,reg,high,nonlong,address};
    const size_t sizes[] = {
        sizeof(memory),sizeof(reg),sizeof(high),sizeof(nonlong),sizeof(address)};

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_error("VPHMINPOSUW extras off", CDISASM_MODE_64,
            cases[index], sizes[index], NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    }
#endif
}

static void test_controls_and_precedence(void)
{
    static const uint8_t valid[] = {0xc4,0xe2,0x79,0x41,0xc2};
    size_t size;

    for (size = 1u; size < sizeof(valid); ++size) {
        expect_error("truncated C4 VPHMINPOSUW", CDISASM_MODE_64,
            valid, size, NULL, CDISASM_STATUS_TRUNCATED);
    }
    expect_error("wrong pp", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0x78,0x41,0xc2}, 5u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("L=1", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0x7d,0x41,0xc2}, 5u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("reserved vvvv", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0x71,0x41,0xc2}, 5u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("wrong map", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe1,0x79,0x41,0xc2}, 5u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("C5", CDISASM_MODE_64,
        (const uint8_t[]){0xc5,0xf9,0x41,0xc2}, 4u,
        NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("wrong pp missing SIB", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0x78,0x41,0x04}, 5u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("L=1 missing disp8", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0x7d,0x41,0x45}, 5u,
        NULL, CDISASM_STATUS_TRUNCATED);
    expect_error("vvvv missing disp32", CDISASM_MODE_64,
        (const uint8_t[]){0xc4,0xe2,0x71,0x41,0x05,0x11,0x22,0x33}, 8u,
        NULL, CDISASM_STATUS_TRUNCATED);
    {
        static const uint8_t encountered[5] = {0x66,0xf2,0xf3,0xf0,0x48};
        size_t index;

        for (index = 0u; index < sizeof(encountered); ++index) {
            const uint8_t missing_sib[6] = {
                encountered[index],0xc4,0xe2,0x79,0x41,0x04};
            const uint8_t complete[7] = {
                encountered[index],0xc4,0xe2,0x79,0x41,0x04,0x24};

            expect_error("encountered prefix missing SIB",
                CDISASM_MODE_64, missing_sib, sizeof(missing_sib),
                NULL, CDISASM_STATUS_TRUNCATED);
            expect_error("encountered prefix complete",
                CDISASM_MODE_64, complete, sizeof(complete),
                NULL, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }

    {
        const uint8_t legacy[] = {0x66,0x0f,0x38,0x41,0xc2};
        uint32_t decoded_size;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
#endif
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            CDISASM_MODE_64, legacy, sizeof(legacy),
#if USE_EXTRA_OPCODES
            &flags,
#else
            NULL,
#endif
            &decoded_size);
#if USE_EXTRA_OPCODES
        EXPECT(decoded_size == sizeof(legacy));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_PHMINPOSUW);
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(&instruction,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
    {
        static const struct c5_sibling {
            uint8_t code[4];
            cdisasm_x86_name_id name;
        } siblings[] = {
            {{0xc5,0xfd,0x41,0xc2}, CDISASM_X86_NAME_KANDB},
            {{0xc5,0xfc,0x41,0xc2}, CDISASM_X86_NAME_KANDW}};
        size_t index;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
#endif

        for (index = 0u; index < sizeof(siblings) / sizeof(siblings[0]);
             ++index) {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
                CDISASM_MODE_64, siblings[index].code,
                sizeof(siblings[index].code),
#if USE_EXTRA_OPCODES
                &flags,
#else
                NULL,
#endif
                &decoded_size);
#if USE_EXTRA_OPCODES
            EXPECT(decoded_size == sizeof(siblings[index].code));
            EXPECT(instruction.name_id == siblings[index].name);
#else
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(&instruction,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }
    {
        const uint8_t evex[] = {0x62,0xf2,0x7e,0x08,0x41,0xc2};
        uint32_t decoded_size;
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
#endif
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            CDISASM_MODE_64, evex, sizeof(evex),
#if USE_EXTRA_OPCODES
            &flags,
#else
            NULL,
#endif
            &decoded_size);
#if USE_EXTRA_OPCODES
        EXPECT(decoded_size == sizeof(evex));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VPMOVSSDB);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EVEX) != 0u);
#else
        EXPECT(decoded_size == 0u);
        EXPECT(is_error_only(&instruction,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format_rejected(const cdisasm_instruction *instruction)
{
    char output[192] = {'x'};

    EXPECT(cdisasm_x86_format(instruction, CDISASM_FORMAT_SYNTAX_INTEL,
        output, sizeof(output)) == 0u);
    EXPECT(output[0] == '\0');
    output[0] = 'x';
    EXPECT(cdisasm_x86_format(instruction, CDISASM_FORMAT_SYNTAX_ATT,
        output, sizeof(output)) == 0u);
    EXPECT(output[0] == '\0');
}

static void test_formatting_and_schema(void)
{
    static const struct format_case {
        uint8_t code[5];
        const char *intel;
        const char *att;
    } cases[] = {
        {{0xc4,0xe2,0x79,0x41,0xc2},
            "vphminposuw xmm0, xmm2", "vphminposuw %xmm2, %xmm0"},
        {{0xc4,0xe2,0xf9,0x41,0x00},
            "vphminposuw xmm0, xmmword ptr [rax]",
            "vphminposuw (%rax), %xmm0"},
        {{0xc4,0x42,0x79,0x41,0xcb},
            "vphminposuw xmm9, xmm11", "vphminposuw %xmm11, %xmm9"}};
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        char output[192];
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            CDISASM_MODE_64, cases[index].code, sizeof(cases[index].code),
            &flags, &decoded_size);
        cdisasm_instruction forged;

        EXPECT(decoded_size == sizeof(cases[index].code));
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) == strlen(cases[index].intel));
        EXPECT(strcmp(output, cases[index].intel) == 0);
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output)) == strlen(cases[index].att));
        EXPECT(strcmp(output, cases[index].att) == 0);

        forged = instruction;
        forged.name_id = CDISASM_X86_NAME_VPHADDD;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.form_id = (cdisasm_x86_form_id)(instruction.form_id ^ 1u);
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode_flags |=
            CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.operand_count = 1u;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.x86_group_ids[forged.x86_group_count++] =
            CDISASM_X86_GROUP_AVX2;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.mask_mode = CDISASM_X86_MASK_MERGE;
        forged.mask_reg = CDISASM_X86_REG_K1;
        expect_format_rejected(&forged);
        forged = instruction;
        ++forged.opcode[0].reg;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.opcode[1].access = CDISASM_OPERAND_ACCESS_WRITE;
        expect_format_rejected(&forged);
        forged = instruction;
        forged.encoding.modrm ^= UINT8_C(8);
        expect_format_rejected(&forged);
        forged = instruction;
        forged.encoding.immediate_count = 1u;
        expect_format_rejected(&forged);
    }
}
#else
static void test_formatting_and_schema(void)
{
}
#endif

int main(void)
{
    test_complete_c4_partition();
    test_forms_gates_aliases();
    test_controls_and_precedence();
    test_formatting_and_schema();

    if (failures != 0) {
        fprintf(stderr, "%d VPHMINPOSUW test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
