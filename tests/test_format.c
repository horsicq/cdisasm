#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm_format.h"
#include "x86_test_flags.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define EXPECT(condition) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "%s:%d: expectation failed: %s\n", \
                    __FILE__, __LINE__, #condition); \
            ++failures; \
        } \
    } while (0)

static void expect_formatted_instruction_with_flags(
    const char *name,
    const cdisasm_instruction *instruction,
    uint32_t flags,
    const char *expected)
{
    char exact[256];
    char roomy[256];
    size_t expected_size = strlen(expected);
    size_t required;

    required = cdisasm_x86_format(instruction, flags, NULL, 0);
    if (required != expected_size) {
        fprintf(stderr, "%s: query returned %zu, expected %zu\n",
                name, required, expected_size);
        ++failures;
    }

    EXPECT(expected_size + 1u <= sizeof(exact));
    memset(exact, 'X', sizeof(exact));
    required = cdisasm_x86_format(
        instruction,
        flags,
        exact,
        expected_size + 1u);
    if (required != expected_size || strcmp(exact, expected) != 0) {
        fprintf(stderr, "%s: exact format got \"%s\" (%zu), expected \"%s\" (%zu)\n",
                name, exact, required, expected, expected_size);
        ++failures;
    }

    memset(roomy, 'X', sizeof(roomy));
    required = cdisasm_x86_format(
        instruction,
        flags,
        roomy,
        sizeof(roomy));
    if (required != expected_size || strcmp(roomy, expected) != 0) {
        fprintf(stderr, "%s: roomy format got \"%s\" (%zu), expected \"%s\" (%zu)\n",
                name, roomy, required, expected, expected_size);
        ++failures;
    }
}

static void expect_mode_formatted_instruction_with_flags(
    const char *name,
    const cdisasm_instruction *instruction,
    cdisasm_mode mode,
    uint32_t flags,
    const char *expected)
{
    char exact[256];
    char roomy[256];
    size_t expected_size = strlen(expected);
    size_t required;

    required = cdisasm_x86_format_mode(
        instruction, mode, flags, NULL, 0);
    if (required != expected_size) {
        fprintf(stderr, "%s: mode query returned %zu, expected %zu\n",
                name, required, expected_size);
        ++failures;
    }

    EXPECT(expected_size + 1u <= sizeof(exact));
    memset(exact, 'X', sizeof(exact));
    required = cdisasm_x86_format_mode(
        instruction,
        mode,
        flags,
        exact,
        expected_size + 1u);
    if (required != expected_size || strcmp(exact, expected) != 0) {
        fprintf(stderr,
                "%s: exact mode format got \"%s\" (%zu), expected \"%s\" (%zu)\n",
                name, exact, required, expected, expected_size);
        ++failures;
    }

    memset(roomy, 'X', sizeof(roomy));
    required = cdisasm_x86_format_mode(
        instruction, mode, flags, roomy, sizeof(roomy));
    if (required != expected_size || strcmp(roomy, expected) != 0) {
        fprintf(stderr,
                "%s: roomy mode format got \"%s\" (%zu), expected \"%s\" (%zu)\n",
                name, roomy, required, expected, expected_size);
        ++failures;
    }
}

static void expect_mode_intel_matches_legacy(
    const char *name,
    const cdisasm_instruction *instruction,
    cdisasm_mode mode)
{
    char legacy[256];
    char mode_aware[256];
    size_t legacy_size;
    size_t mode_size;

    legacy_size = cdisasm_x86_format(
        instruction,
        CDISASM_FORMAT_SYNTAX_INTEL,
        legacy,
        sizeof(legacy));
    mode_size = cdisasm_x86_format_mode(
        instruction,
        mode,
        CDISASM_FORMAT_SYNTAX_INTEL,
        mode_aware,
        sizeof(mode_aware));
    if (legacy_size != mode_size || strcmp(legacy, mode_aware) != 0) {
        fprintf(stderr,
                "%s: Intel mode format \"%s\" (%zu) differs from legacy \"%s\" (%zu)\n",
                name, mode_aware, mode_size, legacy, legacy_size);
        ++failures;
    }
}

static void expect_formatted_instruction(
    const char *name,
    const cdisasm_instruction *instruction,
    const char *expected)
{
    expect_formatted_instruction_with_flags(
        name, instruction, CDISASM_FORMAT_SYNTAX_INTEL, expected);
}

static void expect_decoded_text(
    const char *name,
    cdisasm_cpu_id cpu,
    cdisasm_mode mode,
    const uint8_t *bytes,
    size_t byte_count,
    uint64_t address,
    const char *expected)
{
    cdisasm_instruction instruction;
    uint32_t decoded_size = cdisasm_x86_decode(
        cpu,
        mode,
        bytes,
        byte_count,
        address,
        CDISASM_X86_TEST_ALL_FLAGS,
        &instruction);

    if (decoded_size != byte_count) {
        fprintf(stderr, "%s: decode returned %u/%zu (%s)\n",
                name,
                (unsigned int)decoded_size,
                byte_count,
                cdisasm_status_string((cdisasm_status)instruction.last_error_id));
        ++failures;
        return;
    }
    expect_formatted_instruction(name, &instruction, expected);
}

static void expect_decoded_text_with_flags(
    const char *name,
    cdisasm_cpu_id cpu,
    cdisasm_mode mode,
    const uint8_t *bytes,
    size_t byte_count,
    uint64_t address,
    uint32_t flags,
    const char *expected)
{
    cdisasm_instruction instruction;
    uint32_t decoded_size = cdisasm_x86_decode(
        cpu,
        mode,
        bytes,
        byte_count,
        address,
        CDISASM_X86_TEST_ALL_FLAGS,
        &instruction);

    if (decoded_size != byte_count) {
        fprintf(stderr, "%s: decode returned %u/%zu (%s)\n",
                name,
                (unsigned int)decoded_size,
                byte_count,
                cdisasm_status_string(
                    (cdisasm_status)instruction.last_error_id));
        ++failures;
        return;
    }
    expect_formatted_instruction_with_flags(
        name, &instruction, flags, expected);
}

static void test_retained_case_outputs(void)
{
    static const uint8_t nop[] = {0x90};
    static const uint8_t mov_registers[] = {0x48, 0x89, 0xe5};
    static const uint8_t mov_high_byte[] = {0x88, 0xe0};
    static const uint8_t mov_rex_byte[] = {0x40, 0x88, 0xe0};
    static const uint8_t sib_negative[] = {0x48, 0x8b, 0x44, 0x8b, 0xf0};
    static const uint8_t index_only[] = {
        0x8b, 0x04, 0x8d, 0x78, 0x56, 0x34, 0x12
    };
    static const uint8_t absolute_sign_extended[] = {
        0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x80
    };
    static const uint8_t fs_absolute[] = {
        0x64, 0x48, 0x8b, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00
    };
    static const uint8_t lea[] = {0x48, 0x8d, 0x54, 0x88, 0x10};
    static const uint8_t addressing_16[] = {0x8b, 0x40, 0x10};
    static const uint8_t rip_relative[] = {
        0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00
    };
    static const uint8_t movabs[] = {
        0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
    };
    static const uint8_t signed_immediate[] = {0x48, 0x83, 0xc0, 0xff};
    static const uint8_t signed_imul[] = {0x48, 0x6b, 0xc3, 0xf8};
    static const uint8_t shift_one[] = {0x48, 0xd1, 0xe0};
    static const uint8_t rep_movsb[] = {0xf3, 0xa4};
    static const uint8_t repe_cmpsb[] = {0xf3, 0xa6};
    static const uint8_t indirect_call[] = {0xff, 0x50, 0x08};
    static const uint8_t relative_call[] = {0xe8, 0x10, 0x00, 0x00, 0x00};
    static const uint8_t cmpxchg8b[] = {0x0f, 0xc7, 0x08};
    static const uint8_t cmpxchg16b[] = {0x48, 0x0f, 0xc7, 0x08};

    expect_decoded_text("nop", CDISASM_CPU_X86, CDISASM_MODE_64,
                        nop, sizeof(nop), UINT64_C(0x1000), "nop");
    expect_decoded_text("registers", CDISASM_CPU_X86, CDISASM_MODE_64,
                        mov_registers, sizeof(mov_registers), UINT64_C(0x1000),
                        "mov rbp, rsp");
    expect_decoded_text("legacy high byte", CDISASM_CPU_X86, CDISASM_MODE_64,
                        mov_high_byte, sizeof(mov_high_byte), UINT64_C(0x1000),
                        "mov al, ah");
    expect_decoded_text("REX low byte", CDISASM_CPU_X86, CDISASM_MODE_64,
                        mov_rex_byte, sizeof(mov_rex_byte), UINT64_C(0x1000),
                        "mov al, spl");
    expect_decoded_text("negative SIB displacement", CDISASM_CPU_X86,
                        CDISASM_MODE_64, sib_negative, sizeof(sib_negative),
                        UINT64_C(0x1000),
                        "mov rax, qword ptr [rbx + rcx*4 - 0x10]");
    expect_decoded_text("index-only SIB", CDISASM_CPU_X86, CDISASM_MODE_32,
                        index_only, sizeof(index_only), UINT64_C(0x1000),
                        "mov eax, dword ptr [ecx*4 + 0x12345678]");
    expect_decoded_text("sign-extended absolute", CDISASM_CPU_X86,
                        CDISASM_MODE_64, absolute_sign_extended,
                        sizeof(absolute_sign_extended), UINT64_C(0x1000),
                        "mov rax, qword ptr [0xffffffff80000000]");
    expect_decoded_text("explicit FS", CDISASM_CPU_X86, CDISASM_MODE_64,
                        fs_absolute, sizeof(fs_absolute), UINT64_C(0x1000),
                        "mov rax, qword ptr fs:[0x30]");
    expect_decoded_text("address-only memory", CDISASM_CPU_X86, CDISASM_MODE_64,
                        lea, sizeof(lea), UINT64_C(0x1000),
                        "lea rdx, [rax + rcx*4 + 0x10]");
    expect_decoded_text("16-bit addressing", CDISASM_CPU_X86, CDISASM_MODE_16,
                        addressing_16, sizeof(addressing_16), UINT64_C(0x1000),
                        "mov ax, word ptr [bx + si + 0x10]");
    expect_decoded_text("RIP-relative addressing", CDISASM_CPU_X86,
                        CDISASM_MODE_64, rip_relative, sizeof(rip_relative),
                        UINT64_C(0x1000),
                        "mov rax, qword ptr [rip + 0x10]");
    expect_decoded_text("unsigned immediate", CDISASM_CPU_X86, CDISASM_MODE_64,
                        movabs, sizeof(movabs), UINT64_C(0x1000),
                        "movabs rax, 0x1122334455667788");
    expect_decoded_text("signed immediate", CDISASM_CPU_X86, CDISASM_MODE_64,
                        signed_immediate, sizeof(signed_immediate),
                        UINT64_C(0x1000), "add rax, -0x1");
    expect_decoded_text("three operands", CDISASM_CPU_X86, CDISASM_MODE_64,
                        signed_imul, sizeof(signed_imul), UINT64_C(0x1000),
                        "imul rax, rbx, -0x8");
    expect_decoded_text("implicit one", CDISASM_CPU_X86, CDISASM_MODE_64,
                        shift_one, sizeof(shift_one), UINT64_C(0x1000),
                        "shl rax, 1");
    expect_decoded_text("implicit string operands", CDISASM_CPU_X86,
                        CDISASM_MODE_64, rep_movsb, sizeof(rep_movsb),
                        UINT64_C(0x1000),
                        "rep movsb byte ptr [rdi], byte ptr [rsi]");
    expect_decoded_text("repeat-equal", CDISASM_CPU_X86, CDISASM_MODE_64,
                        repe_cmpsb, sizeof(repe_cmpsb), UINT64_C(0x1000),
                        "repe cmpsb byte ptr [rsi], byte ptr [rdi]");
    expect_decoded_text("indirect call", CDISASM_CPU_X86, CDISASM_MODE_64,
                        indirect_call, sizeof(indirect_call), UINT64_C(0x1000),
                        "call qword ptr [rax + 0x8]");
    expect_decoded_text("resolved relative target", CDISASM_CPU_X86,
                        CDISASM_MODE_64, relative_call, sizeof(relative_call),
                        UINT64_C(0x1000), "call 0x1015");
    expect_decoded_text("baseline CMPXCHG8B", CDISASM_CPU_X86,
                        CDISASM_MODE_64, cmpxchg8b, sizeof(cmpxchg8b),
                        UINT64_C(0x1000), "cmpxchg8b qword ptr [rax]");
    expect_decoded_text("baseline CMPXCHG16B", CDISASM_CPU_X86,
                        CDISASM_MODE_64, cmpxchg16b, sizeof(cmpxchg16b),
                        UINT64_C(0x1000), "cmpxchg16b xmmword ptr [rax]");
}

static void test_pointer_sizes(void)
{
    static const struct pointer_case {
        uint8_t size;
        const char *expected;
    } cases[] = {
        {1, "mov byte ptr [rax]"},
        {2, "mov word ptr [rax]"},
        {4, "mov dword ptr [rax]"},
        {6, "mov fword ptr [rax]"},
        {8, "mov qword ptr [rax]"},
        {10, "mov tbyte ptr [rax]"},
        {16, "mov xmmword ptr [rax]"},
        {32, "mov ymmword ptr [rax]"},
        {64, "mov zmmword ptr [rax]"}
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_instruction instruction = {0};
        char name[48];

        instruction.opcode_size = 1;
        instruction.name_id = CDISASM_X86_NAME_MOV;
        instruction.last_error_id = (uint8_t)CDISASM_STATUS_OK;
        instruction.operand_count = 1;
        instruction.x86_group_count = 1;
        instruction.x86_group_ids[0] = CDISASM_X86_GROUP_AMD64;
        instruction.opcode[0].type = CDISASM_OPERAND_MEMORY;
        instruction.opcode[0].base_reg = CDISASM_X86_REG_RAX;
        instruction.opcode[0].size = cases[index].size;

        (void)snprintf(name, sizeof(name), "pointer size %u",
                       (unsigned int)cases[index].size);
        expect_formatted_instruction(name, &instruction, cases[index].expected);
    }
}

static cdisasm_instruction make_synthetic_instruction(void)
{
    cdisasm_instruction instruction = {0};

    instruction.opcode_size = 1;
    instruction.name_id = CDISASM_X86_NAME_MOV;
    instruction.last_error_id = (uint8_t)CDISASM_STATUS_OK;
    instruction.x86_group_count = 1;
    instruction.x86_group_ids[0] = CDISASM_X86_GROUP_APX_F;
    return instruction;
}

static void test_extended_register_names_and_decorators(void)
{
    static const struct register_case {
        const char *name;
        cdisasm_x86_reg_id first;
        cdisasm_x86_reg_id last;
        const char *expected;
    } register_cases[] = {
        {"x87 registers", CDISASM_X86_REG_ST0, CDISASM_X86_REG_ST7,
            "mov st0, st7"},
        {"MMX registers", CDISASM_X86_REG_MM0, CDISASM_X86_REG_MM7,
            "mov mm0, mm7"},
        {"XMM registers", CDISASM_X86_REG_XMM0, CDISASM_X86_REG_XMM31,
            "mov xmm0, xmm31"},
        {"YMM registers", CDISASM_X86_REG_YMM0, CDISASM_X86_REG_YMM31,
            "mov ymm0, ymm31"},
        {"ZMM registers", CDISASM_X86_REG_ZMM0, CDISASM_X86_REG_ZMM31,
            "mov zmm0, zmm31"},
        {"mask registers", CDISASM_X86_REG_K0, CDISASM_X86_REG_K7,
            "mov k0, k7"},
        {"MPX registers", CDISASM_X86_REG_BND0, CDISASM_X86_REG_BND3,
            "mov bnd0, bnd3"},
        {"AMX registers", CDISASM_X86_REG_TMM0, CDISASM_X86_REG_TMM7,
            "mov tmm0, tmm7"},
        {"APX byte registers", CDISASM_X86_REG_R16B,
            CDISASM_X86_REG_R31B, "mov r16b, r31b"},
        {"APX word registers", CDISASM_X86_REG_R16W,
            CDISASM_X86_REG_R31W, "mov r16w, r31w"},
        {"APX dword registers", CDISASM_X86_REG_R16D,
            CDISASM_X86_REG_R31D, "mov r16d, r31d"},
        {"APX qword registers", CDISASM_X86_REG_R16,
            CDISASM_X86_REG_R31, "mov r16, r31"}
    };
    cdisasm_instruction instruction;
    size_t index;

    for (index = 0;
         index < sizeof(register_cases) / sizeof(register_cases[0]);
         ++index) {
        instruction = make_synthetic_instruction();
        instruction.operand_count = 2;
        instruction.opcode[0].type = CDISASM_OPERAND_REGISTER;
        instruction.opcode[0].size = 8;
        instruction.opcode[0].reg = register_cases[index].first;
        instruction.opcode[1].type = CDISASM_OPERAND_REGISTER;
        instruction.opcode[1].size = 8;
        instruction.opcode[1].reg = register_cases[index].last;
        expect_formatted_instruction(
            register_cases[index].name,
            &instruction,
            register_cases[index].expected);
    }

    instruction = make_synthetic_instruction();
    instruction.operand_count = 2;
    instruction.opcode[0].type = CDISASM_OPERAND_REGISTER;
    instruction.opcode[0].size = 64;
    instruction.opcode[0].reg = CDISASM_X86_REG_ZMM0;
    instruction.opcode[0].access = CDISASM_OPERAND_ACCESS_WRITE;
    instruction.opcode[1].type = CDISASM_OPERAND_REGISTER;
    instruction.opcode[1].size = 64;
    instruction.opcode[1].reg = CDISASM_X86_REG_ZMM1;
    instruction.opcode[1].access = CDISASM_OPERAND_ACCESS_READ;
    instruction.mask_reg = CDISASM_X86_REG_K1;
    instruction.mask_mode = CDISASM_X86_MASK_ZERO;
    expect_formatted_instruction(
        "zeroing writemask", &instruction, "mov zmm0 {k1}{z}, zmm1");

    instruction = make_synthetic_instruction();
    instruction.operand_count = 2;
    instruction.opcode[0].type = CDISASM_OPERAND_REGISTER;
    instruction.opcode[0].size = 64;
    instruction.opcode[0].reg = CDISASM_X86_REG_ZMM0;
    instruction.opcode[1].type = CDISASM_OPERAND_MEMORY;
    instruction.opcode[1].size = 4;
    instruction.opcode[1].base_reg = CDISASM_X86_REG_RAX;
    instruction.opcode[1].broadcast = CDISASM_X86_BROADCAST_1_TO_8;
    expect_formatted_instruction(
        "memory broadcast",
        &instruction,
        "mov zmm0, dword ptr [rax]{1to8}");

    instruction = make_synthetic_instruction();
    instruction.operand_count = 2;
    instruction.opcode[0].type = CDISASM_OPERAND_REGISTER;
    instruction.opcode[0].size = 64;
    instruction.opcode[0].reg = CDISASM_X86_REG_ZMM0;
    instruction.opcode[1].type = CDISASM_OPERAND_REGISTER;
    instruction.opcode[1].size = 64;
    instruction.opcode[1].reg = CDISASM_X86_REG_ZMM1;
    instruction.rounding = CDISASM_X86_ROUNDING_RN;
    instruction.sae = CDISASM_X86_SAE_ENABLED;
    expect_formatted_instruction(
        "embedded rounding", &instruction, "mov zmm0, zmm1, {rn-sae}");
    expect_formatted_instruction_with_flags(
        "AT&T embedded rounding",
        &instruction,
        CDISASM_FORMAT_SYNTAX_ATT,
        "mov {rn-sae}, %zmm1, %zmm0");

    instruction.rounding = CDISASM_X86_ROUNDING_NONE;
    expect_formatted_instruction(
        "suppress all exceptions", &instruction, "mov zmm0, zmm1, {sae}");
    expect_formatted_instruction_with_flags(
        "AT&T suppress all exceptions",
        &instruction,
        CDISASM_FORMAT_SYNTAX_ATT,
        "mov {sae}, %zmm1, %zmm0");
}

static void test_prefix_order_and_aliases(void)
{
    static const uint8_t rep_then_lock[] = {0xf3, 0xf0, 0x01, 0x18};
    static const uint8_t lock_then_rep[] = {0xf0, 0xf3, 0x01, 0x18};
    static const uint8_t repne_then_lock[] = {0xf2, 0xf0, 0x01, 0x18};
    static const uint8_t lock_then_repne[] = {0xf0, 0xf2, 0x01, 0x18};
    static const uint8_t rightmost_release[] = {
        0xf2, 0xf3, 0xf0, 0x01, 0x18
    };
    static const uint8_t rightmost_acquire[] = {
        0xf3, 0xf2, 0xf0, 0x01, 0x18
    };
    static const uint8_t repne_then_rep_cmps[] = {0xf2, 0xf3, 0xa6};
    static const uint8_t rep_then_repne_cmps[] = {0xf3, 0xf2, 0xa6};
    static const uint8_t xacquire_xchg[] = {0xf2, 0x87, 0x18};
    static const uint8_t xrelease_xchg[] = {0xf3, 0x87, 0x18};
    static const uint8_t xrelease_mov[] = {0xf3, 0xc6, 0x00, 0x00};
    static const uint8_t ignored_rightmost_mov[] = {
        0xf3, 0xf2, 0xc6, 0x00, 0x00
    };
    static const uint8_t pause[] = {0xf3, 0x90};
    static const uint8_t tzcnt[] = {0xf3, 0x0f, 0xbc, 0xc3};
    static const uint8_t lzcnt[] = {0xf3, 0x0f, 0xbd, 0xc3};
    static const uint8_t popcnt[] = {0xf3, 0x0f, 0xb8, 0xc3};
    static const uint8_t endbr32[] = {0xf3, 0x0f, 0x1e, 0xfb};
    static const uint8_t repeat_nop[] = {0xf3, 0x0f, 0x1f, 0x00};

    expect_decoded_text("REP then LOCK", CDISASM_CPU_X86, CDISASM_MODE_64,
                        rep_then_lock, sizeof(rep_then_lock), UINT64_C(0x1000),
                        "xrelease lock add dword ptr [rax], ebx");
    expect_decoded_text("LOCK then REP", CDISASM_CPU_X86, CDISASM_MODE_64,
                        lock_then_rep, sizeof(lock_then_rep), UINT64_C(0x1000),
                        "xrelease lock add dword ptr [rax], ebx");
    expect_decoded_text("REPNE then LOCK", CDISASM_CPU_X86,
                        CDISASM_MODE_64, repne_then_lock,
                        sizeof(repne_then_lock), UINT64_C(0x1000),
                        "xacquire lock add dword ptr [rax], ebx");
    expect_decoded_text("LOCK then REPNE", CDISASM_CPU_X86,
                        CDISASM_MODE_64, lock_then_repne,
                        sizeof(lock_then_repne), UINT64_C(0x1000),
                        "xacquire lock add dword ptr [rax], ebx");
    expect_decoded_text("rightmost REP selects XRELEASE", CDISASM_CPU_X86,
                        CDISASM_MODE_64, rightmost_release,
                        sizeof(rightmost_release), UINT64_C(0x1000),
                        "xrelease lock add dword ptr [rax], ebx");
    expect_decoded_text("rightmost REPNE selects XACQUIRE", CDISASM_CPU_X86,
                        CDISASM_MODE_64, rightmost_acquire,
                        sizeof(rightmost_acquire), UINT64_C(0x1000),
                        "xacquire lock add dword ptr [rax], ebx");
    expect_decoded_text("HLE fallback before Haswell", CDISASM_CPU_IVY_BRIDGE,
                        CDISASM_MODE_64, rep_then_lock, sizeof(rep_then_lock),
                        UINT64_C(0x1000), "lock add dword ptr [rax], ebx");
    expect_decoded_text("REPNE then REP", CDISASM_CPU_X86, CDISASM_MODE_64,
                        repne_then_rep_cmps, sizeof(repne_then_rep_cmps),
                        UINT64_C(0x1000),
                        "repe cmpsb byte ptr [rsi], byte ptr [rdi]");
    expect_decoded_text("REP then REPNE", CDISASM_CPU_X86, CDISASM_MODE_64,
                        rep_then_repne_cmps, sizeof(rep_then_repne_cmps),
                        UINT64_C(0x1000),
                        "repne cmpsb byte ptr [rsi], byte ptr [rdi]");
    expect_decoded_text("XACQUIRE implicit-lock XCHG", CDISASM_CPU_X86,
                        CDISASM_MODE_64, xacquire_xchg,
                        sizeof(xacquire_xchg), UINT64_C(0x1000),
                        "xacquire xchg dword ptr [rax], ebx");
    expect_decoded_text("XRELEASE implicit-lock XCHG", CDISASM_CPU_X86,
                        CDISASM_MODE_64, xrelease_xchg,
                        sizeof(xrelease_xchg), UINT64_C(0x1000),
                        "xrelease xchg dword ptr [rax], ebx");
    expect_decoded_text("XRELEASE store", CDISASM_CPU_X86,
                        CDISASM_MODE_64, xrelease_mov,
                        sizeof(xrelease_mov), UINT64_C(0x1000),
                        "xrelease mov byte ptr [rax], 0x0");
    expect_decoded_text("rightmost F2 does not release store",
                        CDISASM_CPU_X86, CDISASM_MODE_64,
                        ignored_rightmost_mov, sizeof(ignored_rightmost_mov),
                        UINT64_C(0x1000), "mov byte ptr [rax], 0x0");

    expect_decoded_text("PAUSE mandatory prefix", CDISASM_CPU_X86,
                        CDISASM_MODE_64, pause, sizeof(pause), UINT64_C(0x1000),
                        "pause");
    expect_decoded_text("PAUSE fallback", CDISASM_CPU_PENTIUM_III,
                        CDISASM_MODE_32, pause, sizeof(pause), UINT64_C(0x1000),
                        "nop");
    expect_decoded_text("TZCNT mandatory prefix", CDISASM_CPU_X86,
                        CDISASM_MODE_64, tzcnt, sizeof(tzcnt), UINT64_C(0x1000),
                        "tzcnt eax, ebx");
    expect_decoded_text("TZCNT fallback", CDISASM_CPU_IVY_BRIDGE,
                        CDISASM_MODE_32, tzcnt, sizeof(tzcnt), UINT64_C(0x1000),
                        "bsf eax, ebx");
    expect_decoded_text("LZCNT mandatory prefix", CDISASM_CPU_X86,
                        CDISASM_MODE_64, lzcnt, sizeof(lzcnt), UINT64_C(0x1000),
                        "lzcnt eax, ebx");
    expect_decoded_text("LZCNT fallback", CDISASM_CPU_PENRYN,
                        CDISASM_MODE_32, lzcnt, sizeof(lzcnt), UINT64_C(0x1000),
                        "bsr eax, ebx");
    expect_decoded_text("POPCNT mandatory prefix", CDISASM_CPU_X86,
                        CDISASM_MODE_64, popcnt, sizeof(popcnt), UINT64_C(0x1000),
                        "popcnt eax, ebx");
    expect_decoded_text("ENDBR mandatory prefix", CDISASM_CPU_X86,
                        CDISASM_MODE_32, endbr32, sizeof(endbr32),
                        UINT64_C(0x1000), "endbr32");
    expect_decoded_text("ENDBR fallback", CDISASM_CPU_PENTIUM_PRO,
                        CDISASM_MODE_32, endbr32, sizeof(endbr32),
                        UINT64_C(0x1000), "nop");
    expect_decoded_text("ignored repeat prefix", CDISASM_CPU_X86,
                        CDISASM_MODE_64, repeat_nop, sizeof(repeat_nop),
                        UINT64_C(0x1000), "nop dword ptr [rax]");
}

static void test_buffer_contract(void)
{
    static const uint8_t bytes[] = {0x48, 0x8b, 0x44, 0x8b, 0xf0};
    static const char expected[] =
        "mov rax, qword ptr [rbx + rcx*4 - 0x10]";
    cdisasm_instruction instruction;
    char truncated[8];
    size_t required;

    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_X86,
               CDISASM_MODE_64,
               bytes,
               sizeof(bytes),
               UINT64_C(0x1000),
               CDISASM_X86_TEST_ALL_FLAGS,
               &instruction)
        == sizeof(bytes));

    memset(truncated, 'X', sizeof(truncated));
    required = cdisasm_x86_format(
        &instruction,
        CDISASM_FORMAT_SYNTAX_0,
        truncated,
        sizeof(truncated));
    EXPECT(required == strlen(expected));
    EXPECT(memcmp(truncated, expected, sizeof(truncated) - 1u) == 0);
    EXPECT(truncated[sizeof(truncated) - 1u] == '\0');

    truncated[0] = 'X';
    required = cdisasm_x86_format(
        &instruction, CDISASM_FORMAT_SYNTAX_0, truncated, 1);
    EXPECT(required == strlen(expected));
    EXPECT(truncated[0] == '\0');

    truncated[0] = 'X';
    required = cdisasm_x86_format(
        &instruction, CDISASM_FORMAT_SYNTAX_0, truncated, 0);
    EXPECT(required == strlen(expected));
    EXPECT(truncated[0] == 'X');

    EXPECT(cdisasm_x86_format(
        &instruction, CDISASM_FORMAT_SYNTAX_0, NULL, 1) == 0);
}

static void test_format_flags(void)
{
    static const uint8_t bytes[] = {0xf3, 0xf0, 0x01, 0x18};
    static const char canonical[] =
        "xrelease lock add dword ptr [rax], ebx";
    static const char att[] =
        "xrelease lock addl %ebx, (%rax)";
    static const char uppercase[] =
        "XRELEASE LOCK ADD dword ptr [rax], ebx";
    cdisasm_instruction instruction;
    char text[128];
    uint32_t syntax;

    EXPECT(CDISASM_FORMAT_SYNTAX_MASK == UINT32_C(0x07));
    EXPECT(CDISASM_FORMAT_SYNTAX_0 == UINT32_C(0x00));
    EXPECT(CDISASM_FORMAT_SYNTAX_1 == UINT32_C(0x01));
    EXPECT(CDISASM_FORMAT_SYNTAX_2 == UINT32_C(0x02));
    EXPECT(CDISASM_FORMAT_SYNTAX_3 == UINT32_C(0x03));
    EXPECT(CDISASM_FORMAT_SYNTAX_4 == UINT32_C(0x04));
    EXPECT(CDISASM_FORMAT_SYNTAX_5 == UINT32_C(0x05));
    EXPECT(CDISASM_FORMAT_SYNTAX_6 == UINT32_C(0x06));
    EXPECT(CDISASM_FORMAT_SYNTAX_7 == UINT32_C(0x07));
    EXPECT(CDISASM_FORMAT_SYNTAX_INTEL == CDISASM_FORMAT_SYNTAX_0);
    EXPECT(CDISASM_FORMAT_SYNTAX_ATT == CDISASM_FORMAT_SYNTAX_1);
    EXPECT(CDISASM_FORMAT_UPPERCASE_OPCODE == UINT32_C(0x08));
    EXPECT(CDISASM_FORMAT_KNOWN_FLAGS_MASK == UINT32_C(0x0f));

    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_X86,
               CDISASM_MODE_64,
               bytes,
               sizeof(bytes),
               UINT64_C(0x1000),
               CDISASM_X86_TEST_ALL_FLAGS,
               &instruction)
        == sizeof(bytes));

    for (syntax = CDISASM_FORMAT_SYNTAX_0;
         syntax <= CDISASM_FORMAT_SYNTAX_7;
         ++syntax) {
        if (syntax == CDISASM_FORMAT_SYNTAX_ATT) {
            continue;
        }
        EXPECT(cdisasm_x86_format(
                   &instruction, syntax, text, sizeof(text))
            == strlen(canonical));
        EXPECT(strcmp(text, canonical) == 0);
    }

    EXPECT(cdisasm_x86_format(
               &instruction,
               CDISASM_FORMAT_SYNTAX_ATT,
               text,
               sizeof(text))
        == strlen(att));
    EXPECT(strcmp(text, att) == 0);

    EXPECT(cdisasm_x86_format(
               &instruction,
               CDISASM_FORMAT_SYNTAX_3
                   | CDISASM_FORMAT_UPPERCASE_OPCODE,
               text,
               sizeof(text))
        == strlen(uppercase));
    EXPECT(strcmp(text, uppercase) == 0);

    EXPECT(cdisasm_format(
               &instruction,
               CDISASM_FORMAT_SYNTAX_7
                   | CDISASM_FORMAT_UPPERCASE_OPCODE,
               text,
               sizeof(text))
        == strlen(uppercase));
    EXPECT(strcmp(text, uppercase) == 0);

    memcpy(text, "invalid", sizeof("invalid"));
    EXPECT(cdisasm_x86_format(
               &instruction, UINT32_C(0x10), text, sizeof(text))
        == 0);
    EXPECT(text[0] == '\0');
}

static void test_att_syntax_outputs(void)
{
    static const uint8_t nop[] = {0x90};
    static const uint8_t mov_registers[] = {0x48, 0x89, 0xe5};
    static const uint8_t mov_byte[] = {0x88, 0xe0};
    static const uint8_t mov_word[] = {0x66, 0x89, 0xe5};
    static const uint8_t add_immediate[] = {0x48, 0x83, 0xc0, 0xff};
    static const uint8_t imul_immediate[] = {0x48, 0x6b, 0xc3, 0xf8};
    static const uint8_t sib_negative[] = {
        0x48, 0x8b, 0x44, 0x8b, 0xf0
    };
    static const uint8_t index_only[] = {
        0x8b, 0x04, 0x8d, 0x78, 0x56, 0x34, 0x12
    };
    static const uint8_t absolute[] = {
        0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x80
    };
    static const uint8_t rip_relative[] = {
        0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00
    };
    static const uint8_t fs_absolute[] = {
        0x64, 0x48, 0x8b, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00
    };
    static const uint8_t lea[] = {0x48, 0x8d, 0x54, 0x88, 0x10};
    static const uint8_t direct_call[] = {
        0xe8, 0x10, 0x00, 0x00, 0x00
    };
    static const uint8_t indirect_call[] = {0xff, 0x50, 0x08};
    static const uint8_t direct_jump[] = {
        0xe9, 0x10, 0x00, 0x00, 0x00
    };
    static const uint8_t indirect_jump[] = {0xff, 0xe0};
    static const uint8_t prefixed_add[] = {0xf3, 0xf0, 0x01, 0x18};
    static const uint8_t rep_movsb[] = {0xf3, 0xa4};
    static const uint8_t enter[] = {0xc8, 0x34, 0x12, 0x05};
    static const uint8_t invlpga[] = {0x0f, 0x01, 0xdf};
    static const uint8_t movabs[] = {
        0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
    };
    static const uint8_t movzbl[] = {0x0f, 0xb6, 0xc1};
    static const uint8_t movsbq[] = {0x48, 0x0f, 0xbe, 0xc1};
    static const uint8_t movslq[] = {0x48, 0x63, 0xc1};
    static const uint8_t cbtw[] = {0x66, 0x98};
    static const uint8_t cwtl[] = {0x98};
    static const uint8_t cltq[] = {0x48, 0x98};
    static const uint8_t cwtd[] = {0x66, 0x99};
    static const uint8_t cltd[] = {0x99};
    static const uint8_t cqto[] = {0x48, 0x99};
    static const uint8_t addps[] = {0x0f, 0x58, 0xc1};
    static const uint8_t movups_memory[] = {
        0x0f, 0x10, 0x44, 0x88, 0x20
    };
    static const uint8_t dpps[] = {
        0x66, 0x0f, 0x3a, 0x40, 0xc1, 0x7f
    };
    static const uint8_t crc32[] = {
        0xf2, 0x0f, 0x38, 0xf0, 0xc1
    };
    static const uint8_t cvtsi2ss_l[] = {0xf3, 0x0f, 0x2a, 0xc1};
    static const uint8_t cvtsi2sd_q[] = {
        0xf2, 0x48, 0x0f, 0x2a, 0xc1
    };

    expect_decoded_text_with_flags(
        "AT&T no operand",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        nop, sizeof(nop), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "nop");
    expect_decoded_text_with_flags(
        "AT&T register reversal and qword suffix",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        mov_registers, sizeof(mov_registers), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "movq %rsp, %rbp");
    expect_decoded_text_with_flags(
        "AT&T byte suffix",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        mov_byte, sizeof(mov_byte), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "movb %ah, %al");
    expect_decoded_text_with_flags(
        "AT&T word suffix",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        mov_word, sizeof(mov_word), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "movw %sp, %bp");
    expect_decoded_text_with_flags(
        "AT&T immediate marker and reversal",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        add_immediate, sizeof(add_immediate), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "addq $-0x1, %rax");
    expect_decoded_text_with_flags(
        "AT&T three-operand reversal",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        imul_immediate, sizeof(imul_immediate), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "imulq $-0x8, %rbx, %rax");
    expect_decoded_text_with_flags(
        "AT&T base index scale displacement",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        sib_negative, sizeof(sib_negative), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "movq -0x10(%rbx,%rcx,4), %rax");
    expect_decoded_text_with_flags(
        "AT&T index-only memory",
        CDISASM_CPU_X86, CDISASM_MODE_32,
        index_only, sizeof(index_only), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "movl 0x12345678(,%ecx,4), %eax");
    expect_decoded_text_with_flags(
        "AT&T absolute memory",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        absolute, sizeof(absolute), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "movq 0xffffffff80000000, %rax");
    expect_decoded_text_with_flags(
        "AT&T RIP-relative memory",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        rip_relative, sizeof(rip_relative), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "movq 0x10(%rip), %rax");
    expect_decoded_text_with_flags(
        "AT&T segment override",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        fs_absolute, sizeof(fs_absolute), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "movq %fs:0x30, %rax");
    expect_decoded_text_with_flags(
        "AT&T LEA address-only memory",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        lea, sizeof(lea), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "leaq 0x10(%rax,%rcx,4), %rdx");

    expect_decoded_text_with_flags(
        "AT&T direct call",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        direct_call, sizeof(direct_call), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "call 0x1015");
    expect_decoded_text_with_flags(
        "AT&T indirect memory call",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        indirect_call, sizeof(indirect_call), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "callq *0x8(%rax)");
    expect_decoded_text_with_flags(
        "AT&T direct jump",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        direct_jump, sizeof(direct_jump), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "jmp 0x1015");
    expect_decoded_text_with_flags(
        "AT&T indirect register jump",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        indirect_jump, sizeof(indirect_jump), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "jmpq *%rax");
    expect_decoded_text_with_flags(
        "AT&T instruction prefixes",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        prefixed_add, sizeof(prefixed_add), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "xrelease lock addl %ebx, (%rax)");
    expect_decoded_text_with_flags(
        "AT&T string prefix and operand reversal",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        rep_movsb, sizeof(rep_movsb), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "rep movsb (%rsi), (%rdi)");
    expect_decoded_text_with_flags(
        "AT&T uppercase instruction prefixes",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        prefixed_add, sizeof(prefixed_add), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT | CDISASM_FORMAT_UPPERCASE_OPCODE,
        "XRELEASE LOCK ADDL %ebx, (%rax)");
    expect_decoded_text_with_flags(
        "AT&T ENTER preserves immediate order",
        CDISASM_CPU_80186, CDISASM_MODE_16,
        enter, sizeof(enter), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "enter $0x1234, $0x5");
    expect_decoded_text_with_flags(
        "AT&T INVLPGA preserves architectural register order",
        CDISASM_CPU_AMD_V, CDISASM_MODE_64,
        invlpga, sizeof(invlpga), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "invlpga %rax, %ecx");

    expect_decoded_text_with_flags(
        "AT&T MOVABS alias",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        movabs, sizeof(movabs), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "movabsq $0x1122334455667788, %rax");
    expect_decoded_text_with_flags(
        "AT&T MOVZX width alias",
        CDISASM_CPU_X86, CDISASM_MODE_32,
        movzbl, sizeof(movzbl), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "movzbl %cl, %eax");
    expect_decoded_text_with_flags(
        "AT&T MOVSX width alias",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        movsbq, sizeof(movsbq), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "movsbq %cl, %rax");
    expect_decoded_text_with_flags(
        "AT&T MOVSXD width alias",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        movslq, sizeof(movslq), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "movslq %ecx, %rax");
    expect_decoded_text_with_flags(
        "AT&T CBW alias",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        cbtw, sizeof(cbtw), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "cbtw");
    expect_decoded_text_with_flags(
        "AT&T CWDE alias",
        CDISASM_CPU_X86, CDISASM_MODE_32,
        cwtl, sizeof(cwtl), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "cwtl");
    expect_decoded_text_with_flags(
        "AT&T CDQE alias",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        cltq, sizeof(cltq), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "cltq");
    expect_decoded_text_with_flags(
        "AT&T CWD alias",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        cwtd, sizeof(cwtd), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "cwtd");
    expect_decoded_text_with_flags(
        "AT&T CDQ alias",
        CDISASM_CPU_X86, CDISASM_MODE_32,
        cltd, sizeof(cltd), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "cltd");
    expect_decoded_text_with_flags(
        "AT&T CQO alias",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        cqto, sizeof(cqto), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "cqto");

    expect_decoded_text_with_flags(
        "AT&T SIMD register reversal",
        CDISASM_CPU_PENTIUM_III, CDISASM_MODE_32,
        addps, sizeof(addps), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "addps %xmm1, %xmm0");
    expect_decoded_text_with_flags(
        "AT&T SIMD memory",
        CDISASM_CPU_PENTIUM_III, CDISASM_MODE_32,
        movups_memory, sizeof(movups_memory), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "movups 0x20(%eax,%ecx,4), %xmm0");
    expect_decoded_text_with_flags(
        "AT&T SIMD immediate reversal",
        CDISASM_CPU_PENRYN, CDISASM_MODE_32,
        dpps, sizeof(dpps), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "dpps $0x7f, %xmm1, %xmm0");
    expect_decoded_text_with_flags(
        "AT&T CRC32 source width suffix",
        CDISASM_CPU_NEHALEM, CDISASM_MODE_32,
        crc32, sizeof(crc32), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "crc32b %cl, %eax");
    expect_decoded_text_with_flags(
        "AT&T CVTSI2SS dword source suffix",
        CDISASM_CPU_PENTIUM_III, CDISASM_MODE_32,
        cvtsi2ss_l, sizeof(cvtsi2ss_l), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "cvtsi2ssl %ecx, %xmm0");
    expect_decoded_text_with_flags(
        "AT&T CVTSI2SD qword source suffix",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        cvtsi2sd_q, sizeof(cvtsi2sd_q), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "cvtsi2sdq %rcx, %xmm0");

    expect_decoded_text_with_flags(
        "AT&T uppercase mnemonic only",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        mov_registers, sizeof(mov_registers), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT | CDISASM_FORMAT_UPPERCASE_OPCODE,
        "MOVQ %rsp, %rbp");
}

static void test_att_mode_aware_control_suffixes(void)
{
    typedef struct mode_format_case {
        const char *label;
        cdisasm_mode mode;
        uint8_t bytes[6];
        size_t size;
        const char *att;
    } mode_format_case;
    static const mode_format_case cases[] = {
        {"mode CALL 16", CDISASM_MODE_16,
            {0xe8, 0x00, 0x00}, 3, "callw 0x1003"},
        {"mode CALL 16 override", CDISASM_MODE_16,
            {0x66, 0xe8, 0x00, 0x00, 0x00, 0x00}, 6, "calll 0x1006"},
        {"mode CALL 32", CDISASM_MODE_32,
            {0xe8, 0x00, 0x00, 0x00, 0x00}, 5, "calll 0x1005"},
        {"mode CALL 32 override", CDISASM_MODE_32,
            {0x66, 0xe8, 0x00, 0x00}, 4, "callw 0x1004"},
        {"mode CALL 64", CDISASM_MODE_64,
            {0xe8, 0x00, 0x00, 0x00, 0x00}, 5, "callq 0x1005"},
        {"mode CALL 64 ignored override", CDISASM_MODE_64,
            {0x66, 0xe8, 0x00, 0x00, 0x00, 0x00}, 6, "callq 0x1006"},

        {"mode JMP 16", CDISASM_MODE_16,
            {0xe9, 0x00, 0x00}, 3, "jmpw 0x1003"},
        {"mode JMP 16 override", CDISASM_MODE_16,
            {0x66, 0xe9, 0x00, 0x00, 0x00, 0x00}, 6, "jmpl 0x1006"},
        {"mode JMP 32", CDISASM_MODE_32,
            {0xe9, 0x00, 0x00, 0x00, 0x00}, 5, "jmpl 0x1005"},
        {"mode JMP 32 override", CDISASM_MODE_32,
            {0x66, 0xe9, 0x00, 0x00}, 4, "jmpw 0x1004"},
        {"mode JMP 64", CDISASM_MODE_64,
            {0xe9, 0x00, 0x00, 0x00, 0x00}, 5, "jmpq 0x1005"},
        {"mode JMP 64 ignored override", CDISASM_MODE_64,
            {0x66, 0xe9, 0x00, 0x00, 0x00, 0x00}, 6, "jmpq 0x1006"},
        {"mode short JMP 16 ignored override", CDISASM_MODE_16,
            {0x66, 0xeb, 0x00}, 3, "jmpw 0x1003"},
        {"mode short JMP 32 ignored override", CDISASM_MODE_32,
            {0x66, 0xeb, 0x00}, 3, "jmpl 0x1003"},
        {"mode short JMP 64 ignored override", CDISASM_MODE_64,
            {0x66, 0xeb, 0x00}, 3, "jmpq 0x1003"},

        {"mode PUSH 16", CDISASM_MODE_16,
            {0x6a, 0x01}, 2, "pushw $0x1"},
        {"mode PUSH 16 override", CDISASM_MODE_16,
            {0x66, 0x6a, 0x01}, 3, "pushl $0x1"},
        {"mode PUSH 32", CDISASM_MODE_32,
            {0x6a, 0x01}, 2, "pushl $0x1"},
        {"mode PUSH 32 override", CDISASM_MODE_32,
            {0x66, 0x6a, 0x01}, 3, "pushw $0x1"},
        {"mode PUSH 64", CDISASM_MODE_64,
            {0x6a, 0x01}, 2, "pushq $0x1"},
        {"mode PUSH 64 override", CDISASM_MODE_64,
            {0x66, 0x6a, 0x01}, 3, "pushw $0x1"},

        {"mode RET 16", CDISASM_MODE_16,
            {0xc3}, 1, "retw"},
        {"mode RET 16 override", CDISASM_MODE_16,
            {0x66, 0xc3}, 2, "retl"},
        {"mode RET 32", CDISASM_MODE_32,
            {0xc3}, 1, "retl"},
        {"mode RET 32 override", CDISASM_MODE_32,
            {0x66, 0xc3}, 2, "retw"},
        {"mode RET 64", CDISASM_MODE_64,
            {0xc3}, 1, "retq"},
        {"mode RET 64 ignored override", CDISASM_MODE_64,
            {0x66, 0xc3}, 2, "retq"},
        {"mode RET immediate 16 override", CDISASM_MODE_16,
            {0x66, 0xc2, 0x34, 0x12}, 4, "retl $0x1234"},
        {"mode RET immediate 32 override", CDISASM_MODE_32,
            {0x66, 0xc2, 0x34, 0x12}, 4, "retw $0x1234"},
        {"mode RET immediate 64 ignored override", CDISASM_MODE_64,
            {0x66, 0xc2, 0x34, 0x12}, 4, "retq $0x1234"},

        {"mode RETF 16", CDISASM_MODE_16,
            {0xcb}, 1, "lretw"},
        {"mode RETF 16 override", CDISASM_MODE_16,
            {0x66, 0xcb}, 2, "lretl"},
        {"mode RETF 32", CDISASM_MODE_32,
            {0xcb}, 1, "lretl"},
        {"mode RETF 32 override", CDISASM_MODE_32,
            {0x66, 0xcb}, 2, "lretw"},
        {"mode RETF 64 default", CDISASM_MODE_64,
            {0xcb}, 1, "lretl"},
        {"mode RETF 64 override", CDISASM_MODE_64,
            {0x66, 0xcb}, 2, "lretw"},
        {"mode RETF 64 REX.W", CDISASM_MODE_64,
            {0x48, 0xcb}, 2, "lretq"},
        {"mode RETF immediate 64 default", CDISASM_MODE_64,
            {0xca, 0x34, 0x12}, 3, "lretl $0x1234"},
        {"mode RETF immediate 64 override", CDISASM_MODE_64,
            {0x66, 0xca, 0x34, 0x12}, 4, "lretw $0x1234"},
        {"mode RETF immediate 64 REX.W", CDISASM_MODE_64,
            {0x48, 0xca, 0x34, 0x12}, 4, "lretq $0x1234"},

        {"mode indirect CALL 16 remains operand-sized", CDISASM_MODE_16,
            {0xff, 0xd0}, 2, "callw *%ax"},
        {"mode indirect CALL 16 override remains operand-sized", CDISASM_MODE_16,
            {0x66, 0xff, 0xd0}, 3, "calll *%eax"},
        {"mode indirect CALL 32 remains operand-sized", CDISASM_MODE_32,
            {0xff, 0xd0}, 2, "calll *%eax"},
        {"mode indirect CALL 32 override remains operand-sized", CDISASM_MODE_32,
            {0x66, 0xff, 0xd0}, 3, "callw *%ax"},
        {"mode indirect CALL 64 remains operand-sized", CDISASM_MODE_64,
            {0xff, 0x50, 0x08}, 3, "callq *0x8(%rax)"},
        {"mode indirect CALL 64 ignores override", CDISASM_MODE_64,
            {0x66, 0xff, 0xd0}, 3, "callq *%rax"},
        {"mode indirect JMP 64 remains operand-sized", CDISASM_MODE_64,
            {0xff, 0xe0}, 2, "jmpq *%rax"},
        {"mode indirect JMP 64 ignores override", CDISASM_MODE_64,
            {0x66, 0xff, 0xe0}, 3, "jmpq *%rax"}
    };
    static const uint8_t legacy_push[] = {0x6a, 0x01};
    static const uint8_t legacy_ret[] = {0xc3};
    static const uint8_t legacy_retf[] = {0xcb};
    static const uint8_t nop[] = {0x90};
    cdisasm_instruction instruction;
    char invalid[32];
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const mode_format_case *test = &cases[index];
        uint32_t decoded_size = cdisasm_x86_decode(
            CDISASM_CPU_X86,
            test->mode,
            test->bytes,
            test->size,
            UINT64_C(0x1000),
            CDISASM_X86_TEST_ALL_FLAGS,
            &instruction);

        if (decoded_size != test->size) {
            fprintf(stderr, "%s: decode returned %u/%zu (%s)\n",
                    test->label,
                    (unsigned int)decoded_size,
                    test->size,
                    cdisasm_status_string(
                        (cdisasm_status)instruction.last_error_id));
            ++failures;
            continue;
        }
        expect_mode_formatted_instruction_with_flags(
            test->label,
            &instruction,
            test->mode,
            CDISASM_FORMAT_SYNTAX_ATT,
            test->att);
        expect_mode_intel_matches_legacy(
            test->label, &instruction, test->mode);
    }

    expect_decoded_text_with_flags(
        "legacy immediate PUSH remains unsuffixed",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        legacy_push, sizeof(legacy_push), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "push $0x1");
    expect_decoded_text_with_flags(
        "legacy RET remains unsuffixed",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        legacy_ret, sizeof(legacy_ret), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "ret");
    expect_decoded_text_with_flags(
        "legacy RETF remains unsuffixed",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        legacy_retf, sizeof(legacy_retf), UINT64_C(0x1000),
        CDISASM_FORMAT_SYNTAX_ATT,
        "lret");

    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_X86,
               CDISASM_MODE_64,
               nop,
               sizeof(nop),
               0,
               CDISASM_X86_TEST_ALL_FLAGS,
               &instruction)
        == sizeof(nop));
    memcpy(invalid, "invalid", sizeof("invalid"));
    EXPECT(cdisasm_x86_format_mode(
               &instruction,
               (cdisasm_mode)0,
               CDISASM_FORMAT_SYNTAX_ATT,
               invalid,
               sizeof(invalid))
        == 0);
    EXPECT(invalid[0] == '\0');
    memcpy(invalid, "invalid", sizeof("invalid"));
    EXPECT(cdisasm_x86_format_mode(
               &instruction,
               (cdisasm_mode)15,
               CDISASM_FORMAT_SYNTAX_ATT,
               invalid,
               sizeof(invalid))
        == 0);
    EXPECT(invalid[0] == '\0');
    EXPECT(cdisasm_x86_format_mode(
               &instruction,
               (cdisasm_mode)UINT32_MAX,
               CDISASM_FORMAT_SYNTAX_ATT,
               NULL,
               0)
        == 0);
    memcpy(invalid, "invalid", sizeof("invalid"));
    EXPECT(cdisasm_x86_format_mode(
               &instruction,
               CDISASM_MODE_64,
               UINT32_C(0x10),
               invalid,
               sizeof(invalid))
        == 0);
    EXPECT(invalid[0] == '\0');
}

static void test_att_buffer_and_compatibility(void)
{
    static const uint8_t bytes[] = {0x48, 0x8b, 0x44, 0x8b, 0xf0};
    static const char expected[] = "movq -0x10(%rbx,%rcx,4), %rax";
    cdisasm_instruction instruction;
    char full[128];
    char truncated[9];
    char untouched = 'X';
    size_t required;

    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_X86,
               CDISASM_MODE_64,
               bytes,
               sizeof(bytes),
               UINT64_C(0x1000),
               CDISASM_X86_TEST_ALL_FLAGS,
               &instruction)
        == sizeof(bytes));

    required = cdisasm_x86_format(
        &instruction, CDISASM_FORMAT_SYNTAX_ATT, NULL, 0);
    EXPECT(required == strlen(expected));

    memset(truncated, 'X', sizeof(truncated));
    EXPECT(cdisasm_x86_format(
               &instruction,
               CDISASM_FORMAT_SYNTAX_ATT,
               truncated,
               sizeof(truncated))
        == strlen(expected));
    EXPECT(memcmp(truncated, expected, sizeof(truncated) - 1u) == 0);
    EXPECT(truncated[sizeof(truncated) - 1u] == '\0');

    EXPECT(cdisasm_format(
               &instruction,
               CDISASM_FORMAT_SYNTAX_ATT,
               full,
               sizeof(full))
        == strlen(expected));
    EXPECT(strcmp(full, expected) == 0);

    EXPECT(cdisasm_format(
               &instruction,
               CDISASM_FORMAT_SYNTAX_ATT,
               &untouched,
               0)
        == strlen(expected));
    EXPECT(untouched == 'X');
}

static void expect_invalid(
    const char *name,
    const cdisasm_instruction *instruction)
{
    char buffer[16] = "not empty";
    size_t result = cdisasm_x86_format(
        instruction,
        CDISASM_FORMAT_SYNTAX_0,
        buffer,
        sizeof(buffer));

    if (result != 0 || buffer[0] != '\0') {
        fprintf(stderr, "%s: invalid metadata returned %zu and \"%s\"\n",
                name, result, buffer);
        ++failures;
    }
}

static void test_invalid_metadata(void)
{
    cdisasm_instruction instruction = {0};

    expect_invalid("NULL instruction", NULL);

    instruction.last_error_id = (uint8_t)CDISASM_STATUS_INVALID_INSTRUCTION;
    expect_invalid("decode failure", &instruction);

    instruction.last_error_id = (uint8_t)CDISASM_STATUS_OK;
    instruction.opcode_size = 1;
    instruction.x86_group_count = 1;
    instruction.x86_group_ids[0] = CDISASM_X86_GROUP_I86;
    instruction.name_id = CDISASM_X86_NAME_NONE;
    expect_invalid("missing name", &instruction);

    instruction.name_id = CDISASM_X86_NAME_MOV;
    instruction.operand_count = CDISASM_MAX_OPERANDS + 1u;
    expect_invalid("too many operands", &instruction);

    instruction.operand_count = 1;
    instruction.opcode[0].type = CDISASM_OPERAND_NONE;
    expect_invalid("NONE display operand", &instruction);

    instruction.opcode[0].type = CDISASM_OPERAND_REGISTER;
    instruction.opcode[0].reg = UINT16_C(78);
    expect_invalid("reserved register ID", &instruction);

    instruction.opcode[0].reg = CDISASM_X86_REG_RAX;
    instruction.opcode[0].size = 8;
    instruction.opcode[0].flags = CDISASM_OPERAND_FLAG_ABSOLUTE;
    expect_invalid("register with memory flags", &instruction);

    instruction.operand_count = 0;
    instruction.opcode_flags = CDISASM_PREFIX_EFFECTIVE_REP;
    expect_invalid("effective prefix without encountered prefix", &instruction);

    instruction.opcode_flags = CDISASM_PREFIX_XACQUIRE;
    expect_invalid("XACQUIRE without F2", &instruction);

    instruction.opcode_flags = CDISASM_PREFIX_REPNE
        | CDISASM_PREFIX_XACQUIRE | CDISASM_PREFIX_XRELEASE;
    expect_invalid("conflicting HLE semantics", &instruction);

    instruction.opcode_flags = CDISASM_PREFIX_REPNE
        | CDISASM_PREFIX_EFFECTIVE_REPNE
        | CDISASM_PREFIX_XACQUIRE;
    expect_invalid("HLE and effective REPNE conflict", &instruction);

    instruction.opcode_flags = 0;
    instruction.x86_group_count = 2;
    instruction.x86_group_ids[0] = CDISASM_X86_GROUP_I386;
    instruction.x86_group_ids[1] = CDISASM_X86_GROUP_I186;
    expect_invalid("unsorted x86 groups", &instruction);

    instruction.x86_group_count = 1;
    instruction.x86_group_ids[0] = CDISASM_X86_GROUP_I86;
    instruction.x86_group_ids[1] = CDISASM_X86_GROUP_I186;
    expect_invalid("nonzero unused x86 group", &instruction);

    instruction = make_synthetic_instruction();
    instruction.operand_count = 1;
    instruction.opcode[0].type = CDISASM_OPERAND_REGISTER;
    instruction.opcode[0].size = 8;
    instruction.opcode[0].reg = CDISASM_X86_REG_RAX;
    instruction.opcode[0].reserved[0] = 1;
    expect_invalid("nonzero operand reserved byte", &instruction);

    instruction.opcode[0].reserved[0] = 0;
    instruction.opcode[CDISASM_MAX_OPERANDS - 1u].reserved[0] = 1;
    expect_invalid("nonzero unused operand", &instruction);

    instruction.opcode[CDISASM_MAX_OPERANDS - 1u].reserved[0] = 0;
    instruction.opcode[0].access = (cdisasm_operand_access)4;
    expect_invalid("invalid operand access", &instruction);

    instruction.opcode[0].access = CDISASM_OPERAND_ACCESS_READ;
    instruction.opcode[0].broadcast = CDISASM_X86_BROADCAST_1_TO_8;
    expect_invalid("broadcast register", &instruction);

    instruction = make_synthetic_instruction();
    instruction.operand_count = 1;
    instruction.opcode[0].type = CDISASM_OPERAND_MEMORY;
    instruction.opcode[0].size = 4;
    instruction.opcode[0].base_reg = CDISASM_X86_REG_RAX;
    instruction.opcode[0].broadcast = (cdisasm_x86_broadcast)3;
    expect_invalid("invalid broadcast count", &instruction);

    instruction = make_synthetic_instruction();
    instruction.default_flags = UINT8_C(0x80);
    expect_invalid("nonzero instruction reserved byte", &instruction);

    instruction = make_synthetic_instruction();
    instruction.mask_reg = CDISASM_X86_REG_K1;
    expect_invalid("mask register without mask mode", &instruction);

    instruction = make_synthetic_instruction();
    instruction.mask_mode = CDISASM_X86_MASK_MERGE;
    expect_invalid("mask mode without mask register", &instruction);

    instruction.mask_reg = CDISASM_X86_REG_K0;
    expect_invalid("K0 writemask", &instruction);

    instruction.mask_reg = CDISASM_X86_REG_RAX;
    expect_invalid("non-mask writemask register", &instruction);

    instruction = make_synthetic_instruction();
    instruction.mask_reg = CDISASM_X86_REG_K1;
    instruction.mask_mode = CDISASM_X86_MASK_MERGE;
    expect_invalid("writemask without destination", &instruction);

    instruction = make_synthetic_instruction();
    instruction.rounding = CDISASM_X86_ROUNDING_RN;
    expect_invalid("rounding without SAE", &instruction);

    instruction.rounding = (cdisasm_x86_rounding_mode)5;
    expect_invalid("invalid rounding mode", &instruction);

    instruction = make_synthetic_instruction();
    instruction.sae = (cdisasm_x86_sae)2;
    expect_invalid("invalid SAE mode", &instruction);

    instruction.sae = CDISASM_X86_SAE_ENABLED;
    expect_invalid("SAE without operands", &instruction);

    instruction = make_synthetic_instruction();
    instruction.encoding.reserved = 1;
    expect_invalid("nonzero encoding reserved byte", &instruction);
}

static void test_decoder_formatter_compatibility(void)
{
    static const cdisasm_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint8_t code[CDISASM_MAX_INSTRUCTION_SIZE] = {0};
    cdisasm_instruction instruction;
    char text[512];
    size_t mode_index;
    unsigned int first;
    unsigned int second;

    for (mode_index = 0; mode_index < sizeof(modes) / sizeof(modes[0]);
         ++mode_index) {
        for (first = 0; first <= UINT8_MAX; ++first) {
            for (second = 0; second <= UINT8_MAX; ++second) {
                uint32_t decoded_size;
                size_t required;

                code[0] = (uint8_t)first;
                code[1] = (uint8_t)second;
                decoded_size = cdisasm_x86_decode(
                    CDISASM_CPU_X86,
                    modes[mode_index],
                    code,
                    sizeof(code),
                    UINT64_C(0x1000),
                    CDISASM_X86_TEST_ALL_FLAGS,
                    &instruction);
                if (decoded_size == 0) {
                    continue;
                }

                required = cdisasm_x86_format(
                    &instruction,
                    CDISASM_FORMAT_SYNTAX_0,
                    text,
                    sizeof(text));
                if (required == 0 || required >= sizeof(text)
                    || strlen(text) != required) {
                    fprintf(stderr,
                            "formatter compatibility failed for mode %u, "
                            "bytes %02x %02x\n",
                            (unsigned int)modes[mode_index], first, second);
                    ++failures;
                    return;
                }
            }
        }
    }
}

static void test_sse_outputs(void)
{
    static const uint8_t addps[] = {0x0f, 0x58, 0xc1};
    static const uint8_t addss[] = {0xf3, 0x0f, 0x58, 0xc1};
    static const uint8_t movsd[] = {0xf2, 0x0f, 0x10, 0xc1};
    static const uint8_t movups_memory[] = {
        0x0f, 0x10, 0x44, 0x88, 0x20
    };
    static const uint8_t pshufb[] = {0x66, 0x0f, 0x38, 0x00, 0xc1};
    static const uint8_t dpps[] = {
        0x66, 0x0f, 0x3a, 0x40, 0xc1, 0x7f
    };
    static const uint8_t crc32[] = {0xf2, 0x0f, 0x38, 0xf0, 0xc1};
    static const uint8_t movntss[] = {0xf3, 0x0f, 0x2b, 0x01};
    static const uint8_t movmskps_rex_w[] = {0x48, 0x0f, 0x50, 0xc1};
    static const uint8_t movmskpd_rex_w[] = {
        0x66, 0x48, 0x0f, 0x50, 0xc1
    };
    static const uint8_t pmovmskb_rex_w[] = {
        0x66, 0x48, 0x0f, 0xd7, 0xc1
    };
    static const uint8_t pblendvb[] = {0x66, 0x0f, 0x38, 0x10, 0xc1};
    static const uint8_t blendvps[] = {0x66, 0x0f, 0x38, 0x14, 0xc1};
    static const uint8_t blendvpd[] = {0x66, 0x0f, 0x38, 0x15, 0xc1};
    static const uint8_t extrq_immediate[] = {
        0x66, 0x0f, 0x78, 0xc1, 0x08, 0x04
    };
    static const uint8_t insertq_immediate[] = {
        0xf2, 0x0f, 0x78, 0xc1, 0x08, 0x04
    };
    static const uint8_t extrq_register[] = {0x66, 0x0f, 0x79, 0xc1};
    static const uint8_t insertq_register[] = {0xf2, 0x0f, 0x79, 0xc1};

    expect_decoded_text("SSE ADDPS", CDISASM_CPU_PENTIUM_III,
        CDISASM_MODE_32, addps, sizeof(addps), 0, "addps xmm0, xmm1");
    expect_decoded_text("SSE mandatory F3", CDISASM_CPU_PENTIUM_III,
        CDISASM_MODE_32, addss, sizeof(addss), 0, "addss xmm0, xmm1");
    expect_decoded_text("SSE2 MOVSD is not REPNE", CDISASM_CPU_PENTIUM_4,
        CDISASM_MODE_32, movsd, sizeof(movsd), 0, "movsd xmm0, xmm1");
    expect_decoded_text("SSE memory operand", CDISASM_CPU_PENTIUM_III,
        CDISASM_MODE_32, movups_memory, sizeof(movups_memory), 0,
        "movups xmm0, xmmword ptr [eax + ecx*4 + 0x20]");
    expect_decoded_text("SSSE3 map", CDISASM_CPU_CORE_2,
        CDISASM_MODE_32, pshufb, sizeof(pshufb), 0,
        "pshufb xmm0, xmm1");
    expect_decoded_text("SSE4.1 immediate", CDISASM_CPU_PENRYN,
        CDISASM_MODE_32, dpps, sizeof(dpps), 0,
        "dpps xmm0, xmm1, 0x7f");
    expect_decoded_text("SSE4.2 CRC32", CDISASM_CPU_NEHALEM,
        CDISASM_MODE_32, crc32, sizeof(crc32), 0, "crc32 eax, cl");
    expect_decoded_text("SSE4a store", CDISASM_CPU_AMD_BARCELONA,
        CDISASM_MODE_32, movntss, sizeof(movntss), 0,
        "movntss dword ptr [ecx], xmm0");
    expect_decoded_text("MOVMSKPS ignores REX.W", CDISASM_CPU_ATHLON_64,
        CDISASM_MODE_64, movmskps_rex_w, sizeof(movmskps_rex_w), 0,
        "movmskps eax, xmm1");
    expect_decoded_text("MOVMSKPD ignores REX.W", CDISASM_CPU_ATHLON_64,
        CDISASM_MODE_64, movmskpd_rex_w, sizeof(movmskpd_rex_w), 0,
        "movmskpd eax, xmm1");
    expect_decoded_text("PMOVMSKB ignores REX.W", CDISASM_CPU_ATHLON_64,
        CDISASM_MODE_64, pmovmskb_rex_w, sizeof(pmovmskb_rex_w), 0,
        "pmovmskb eax, xmm1");
    expect_decoded_text("PBLENDVB implicit XMM0", CDISASM_CPU_PENRYN,
        CDISASM_MODE_32, pblendvb, sizeof(pblendvb), 0,
        "pblendvb xmm0, xmm1, xmm0");
    expect_decoded_text("BLENDVPS implicit XMM0", CDISASM_CPU_PENRYN,
        CDISASM_MODE_32, blendvps, sizeof(blendvps), 0,
        "blendvps xmm0, xmm1, xmm0");
    expect_decoded_text("BLENDVPD implicit XMM0", CDISASM_CPU_PENRYN,
        CDISASM_MODE_32, blendvpd, sizeof(blendvpd), 0,
        "blendvpd xmm0, xmm1, xmm0");
    expect_decoded_text("SSE4a EXTRQ immediate",
        CDISASM_CPU_AMD_BARCELONA, CDISASM_MODE_32,
        extrq_immediate, sizeof(extrq_immediate), 0,
        "extrq xmm1, 0x8, 0x4");
    expect_decoded_text("SSE4a INSERTQ immediate",
        CDISASM_CPU_AMD_BARCELONA, CDISASM_MODE_32,
        insertq_immediate, sizeof(insertq_immediate), 0,
        "insertq xmm0, xmm1, 0x8, 0x4");
    expect_decoded_text("SSE4a EXTRQ register",
        CDISASM_CPU_AMD_BARCELONA, CDISASM_MODE_32,
        extrq_register, sizeof(extrq_register), 0,
        "extrq xmm0, xmm1");
    expect_decoded_text("SSE4a INSERTQ register",
        CDISASM_CPU_AMD_BARCELONA, CDISASM_MODE_32,
        insertq_register, sizeof(insertq_register), 0,
        "insertq xmm0, xmm1");
}

static void test_x87_outputs(void)
{
    static const uint8_t fadds[] = {0xd8, 0x00};
    static const uint8_t faddl[] = {0xdc, 0x00};
    static const uint8_t fiadds[] = {0xde, 0x00};
    static const uint8_t fiaddl[] = {0xda, 0x00};
    static const uint8_t fldt[] = {0xdb, 0x28};
    static const uint8_t fildll[] = {0xdf, 0x28};
    static const uint8_t fistpll[] = {0xdf, 0x38};
    static const uint8_t fisttpll[] = {0xdd, 0x08};
    static const uint8_t fsub_register[] = {0xd8, 0xe3};
    static const uint8_t fsubr_register[] = {0xdc, 0xe3};
    static const uint8_t fcmov[] = {0xda, 0xc1};
    static const uint8_t fstpnce[] = {0xd9, 0xd9};
    static const uint8_t compatibility_fcom[] = {0xdc, 0xd1};
    static const uint8_t compatibility_fxch[] = {0xdd, 0xc9};
    static const uint8_t compatibility_fstp[] = {0xdf, 0xd1};
    static const uint8_t fnclex[] = {0xdb, 0xe2};
    static const uint8_t fclex[] = {0x9b, 0xdb, 0xe2};
    static const uint8_t fnstsw_ax[] = {0xdf, 0xe0};
    static const uint8_t fstsw_ax[] = {0x9b, 0xdf, 0xe0};
    static const uint8_t fldenv16[] = {0xd9, 0x20};
    static const uint8_t fldenv32[] = {0xd9, 0x20};

    expect_decoded_text("x87 Intel real32", CDISASM_CPU_X86,
        CDISASM_MODE_32, fadds, sizeof(fadds), 0,
        "fadd dword ptr [eax]");
    expect_decoded_text_with_flags("x87 AT&T real32", CDISASM_CPU_X86,
        CDISASM_MODE_32, fadds, sizeof(fadds), 0,
        CDISASM_FORMAT_SYNTAX_ATT, "fadds (%eax)");
    expect_decoded_text_with_flags("x87 AT&T real64", CDISASM_CPU_X86,
        CDISASM_MODE_32, faddl, sizeof(faddl), 0,
        CDISASM_FORMAT_SYNTAX_ATT, "faddl (%eax)");
    expect_decoded_text_with_flags("x87 AT&T integer16", CDISASM_CPU_X86,
        CDISASM_MODE_32, fiadds, sizeof(fiadds), 0,
        CDISASM_FORMAT_SYNTAX_ATT, "fiadds (%eax)");
    expect_decoded_text_with_flags("x87 AT&T integer32", CDISASM_CPU_X86,
        CDISASM_MODE_32, fiaddl, sizeof(fiaddl), 0,
        CDISASM_FORMAT_SYNTAX_ATT, "fiaddl (%eax)");
    expect_decoded_text_with_flags("x87 AT&T real80", CDISASM_CPU_X86,
        CDISASM_MODE_32, fldt, sizeof(fldt), 0,
        CDISASM_FORMAT_SYNTAX_ATT, "fldt (%eax)");
    expect_decoded_text_with_flags("x87 AT&T integer64 load",
        CDISASM_CPU_X86, CDISASM_MODE_32,
        fildll, sizeof(fildll), 0, CDISASM_FORMAT_SYNTAX_ATT,
        "fildll (%eax)");
    expect_decoded_text_with_flags("x87 AT&T integer64 store",
        CDISASM_CPU_X86, CDISASM_MODE_32,
        fistpll, sizeof(fistpll), 0, CDISASM_FORMAT_SYNTAX_ATT,
        "fistpll (%eax)");
    expect_decoded_text_with_flags("x87 AT&T SSE3 integer64 store",
        CDISASM_CPU_PRESCOTT, CDISASM_MODE_32,
        fisttpll, sizeof(fisttpll), 0, CDISASM_FORMAT_SYNTAX_ATT,
        "fisttpll (%eax)");

    expect_decoded_text("x87 Intel stack arithmetic", CDISASM_CPU_X86,
        CDISASM_MODE_64, fsub_register, sizeof(fsub_register), 0,
        "fsub st0, st3");
    expect_decoded_text_with_flags("x87 AT&T stack arithmetic",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        fsub_register, sizeof(fsub_register), 0,
        CDISASM_FORMAT_SYNTAX_ATT, "fsub %st(3), %st");
    expect_decoded_text_with_flags("x87 AT&T reversed destination",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        fsubr_register, sizeof(fsubr_register), 0,
        CDISASM_FORMAT_SYNTAX_ATT, "fsubr %st, %st(3)");
    expect_decoded_text_with_flags("x87 AT&T conditional move",
        CDISASM_CPU_PENTIUM_PRO, CDISASM_MODE_32,
        fcmov, sizeof(fcmov), 0,
        CDISASM_FORMAT_SYNTAX_ATT, "fcmovb %st(1), %st");
    expect_decoded_text("x87 undocumented FSTPNCE Intel",
        CDISASM_CPU_80386_80387, CDISASM_MODE_32,
        fstpnce, sizeof(fstpnce), 0, "fstpnce st1, st0");
    expect_decoded_text_with_flags("x87 undocumented FSTPNCE AT&T",
        CDISASM_CPU_80386_80387, CDISASM_MODE_32,
        fstpnce, sizeof(fstpnce), 0,
        CDISASM_FORMAT_SYNTAX_ATT, "fstpnce %st, %st(1)");
    expect_decoded_text("x87 compatibility FCOM alias",
        CDISASM_CPU_80386_80387, CDISASM_MODE_32,
        compatibility_fcom, sizeof(compatibility_fcom), 0, "fcom st1");
    expect_decoded_text("x87 compatibility FXCH alias",
        CDISASM_CPU_80386_80387, CDISASM_MODE_32,
        compatibility_fxch, sizeof(compatibility_fxch), 0, "fxch st1");
    expect_decoded_text_with_flags("x87 compatibility FSTP alias",
        CDISASM_CPU_80386_80387, CDISASM_MODE_32,
        compatibility_fstp, sizeof(compatibility_fstp), 0,
        CDISASM_FORMAT_SYNTAX_ATT, "fstp %st(1)");

    expect_decoded_text("x87 no-wait spelling", CDISASM_CPU_X86,
        CDISASM_MODE_32, fnclex, sizeof(fnclex), 0, "fnclex");
    expect_decoded_text("x87 WAIT spelling", CDISASM_CPU_X86,
        CDISASM_MODE_32, fclex, sizeof(fclex), 0, "fclex");
    expect_decoded_text_with_flags("x87 WAIT spelling uppercase",
        CDISASM_CPU_X86, CDISASM_MODE_32,
        fclex, sizeof(fclex), 0,
        CDISASM_FORMAT_SYNTAX_ATT | CDISASM_FORMAT_UPPERCASE_OPCODE,
        "FCLEX");
    expect_decoded_text_with_flags("x87 no-wait status AX",
        CDISASM_CPU_80286_80287, CDISASM_MODE_16,
        fnstsw_ax, sizeof(fnstsw_ax), 0,
        CDISASM_FORMAT_SYNTAX_ATT, "fnstsw %ax");
    expect_decoded_text_with_flags("x87 WAIT status AX",
        CDISASM_CPU_80286_80287, CDISASM_MODE_16,
        fstsw_ax, sizeof(fstsw_ax), 0,
        CDISASM_FORMAT_SYNTAX_ATT, "fstsw %ax");

    expect_decoded_text("x87 Intel 14-byte environment", CDISASM_CPU_X86,
        CDISASM_MODE_16, fldenv16, sizeof(fldenv16), 0,
        "fldenv m14byte ptr [bx + si]");
    expect_decoded_text("x87 Intel 28-byte environment", CDISASM_CPU_X86,
        CDISASM_MODE_32, fldenv32, sizeof(fldenv32), 0,
        "fldenv m28byte ptr [eax]");
}

static void test_extra_opcode_formatting(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t packed[] = {0xc5, 0xec, 0x58, 0xcb};
    static const uint8_t scalar_memory[] = {0xc5, 0xea, 0x58, 0x08};
    static const uint8_t integer[] = {0xc5, 0xed, 0xfc, 0xcb};
    static const char *const names[] = {
        "vaddps", "vaddpd", "vaddss", "vaddsd",
        "vsubps", "vsubpd", "vsubss", "vsubsd",
        "vmulps", "vmulpd", "vmulss", "vmulsd",
        "vdivps", "vdivpd", "vdivss", "vdivsd",
        "vminps", "vminpd", "vminss", "vminsd",
        "vmaxps", "vmaxpd", "vmaxss", "vmaxsd",
        "vandps", "vandpd", "vandnps", "vandnpd",
        "vorps", "vorpd", "vxorps", "vxorpd",
        "vpaddb", "vpaddw", "vpaddd", "vpaddq",
        "vpsubb", "vpsubw", "vpsubd", "vpsubq",
        "vpand", "vpandn", "vpor", "vpxor",
        "vpcmpeqb", "vpcmpeqw", "vpcmpeqd",
        "vpcmpgtb", "vpcmpgtw", "vpcmpgtd",
        "vpmullw", "vpmuludq", "vpmaddwd",
        "vpavgb", "vpavgw", "vpmaxsw", "vpmaxub",
        "vpminsw", "vpminub", "vpsadbw"
    };
    cdisasm_instruction synthetic;
    size_t index;

    expect_decoded_text("AVX Intel packed", CDISASM_CPU_SANDY_BRIDGE,
        CDISASM_MODE_64, packed, sizeof(packed), 0,
        "vaddps ymm1, ymm2, ymm3");
    expect_decoded_text_with_flags("AVX AT&T packed",
        CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64,
        packed, sizeof(packed), 0, CDISASM_FORMAT_SYNTAX_ATT,
        "vaddps %ymm3, %ymm2, %ymm1");
    expect_decoded_text("AVX Intel scalar memory",
        CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64,
        scalar_memory, sizeof(scalar_memory), 0,
        "vaddss xmm1, xmm2, dword ptr [rax]");
    expect_decoded_text_with_flags("AVX AT&T scalar memory",
        CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64,
        scalar_memory, sizeof(scalar_memory), 0,
        CDISASM_FORMAT_SYNTAX_ATT,
        "vaddss (%rax), %xmm2, %xmm1");
    expect_decoded_text_with_flags("AVX2 uppercase",
        CDISASM_CPU_HASWELL, CDISASM_MODE_64,
        integer, sizeof(integer), 0,
        CDISASM_FORMAT_UPPERCASE_OPCODE,
        "VPADDB ymm1, ymm2, ymm3");

    EXPECT(sizeof(names) / sizeof(names[0])
        == (size_t)(CDISASM_X86_NAME_VPSADBW
            - CDISASM_X86_NAME_VADDPS + 1u));
    for (index = 0; index < sizeof(names) / sizeof(names[0]); ++index) {
        char expected[80];

        synthetic = make_synthetic_instruction();
        synthetic.name_id = (cdisasm_x86_name_id)
            (CDISASM_X86_NAME_VADDPS + index);
        synthetic.x86_group_ids[0] = CDISASM_X86_GROUP_AVX;
        synthetic.operand_count = 3;
        synthetic.opcode[0].type = CDISASM_OPERAND_REGISTER;
        synthetic.opcode[0].size = 16;
        synthetic.opcode[0].reg = CDISASM_X86_REG_XMM1;
        synthetic.opcode[0].access = CDISASM_OPERAND_ACCESS_WRITE;
        synthetic.opcode[1].type = CDISASM_OPERAND_REGISTER;
        synthetic.opcode[1].size = 16;
        synthetic.opcode[1].reg = CDISASM_X86_REG_XMM2;
        synthetic.opcode[1].access = CDISASM_OPERAND_ACCESS_READ;
        synthetic.opcode[2].type = CDISASM_OPERAND_REGISTER;
        synthetic.opcode[2].size = 16;
        synthetic.opcode[2].reg = CDISASM_X86_REG_XMM3;
        synthetic.opcode[2].access = CDISASM_OPERAND_ACCESS_READ;
        /* Exact packed add/sub, MIN/MAX, and compare schemas are covered
         * with real decoded fixtures by their focused family tests; the
         * generic synthetic shape here intentionally has no provenance. */
        if ((synthetic.name_id >= CDISASM_X86_NAME_VPADDB &&
                synthetic.name_id <= CDISASM_X86_NAME_VPSUBQ) ||
            (synthetic.name_id >= CDISASM_X86_NAME_VPMAXSW &&
                synthetic.name_id <= CDISASM_X86_NAME_VPMINUB) ||
            (synthetic.name_id >= CDISASM_X86_NAME_VPMINSB &&
                synthetic.name_id <= CDISASM_X86_NAME_VPMAXUQ) ||
            synthetic.name_id == CDISASM_X86_NAME_VPCMPEQB ||
            synthetic.name_id == CDISASM_X86_NAME_VPCMPEQW ||
            synthetic.name_id == CDISASM_X86_NAME_VPCMPEQD ||
            synthetic.name_id == CDISASM_X86_NAME_VPCMPGTB ||
            synthetic.name_id == CDISASM_X86_NAME_VPCMPGTW ||
            synthetic.name_id == CDISASM_X86_NAME_VPCMPGTD) {
            continue;
        }
        (void)snprintf(expected, sizeof(expected), "%s xmm1, xmm2, xmm3",
            names[index]);
        expect_formatted_instruction(names[index], &synthetic, expected);
    }
#else
    cdisasm_instruction instruction = make_synthetic_instruction();
    char buffer[32] = "not empty";

    instruction.name_id = CDISASM_X86_NAME_VADDPS;
    instruction.operand_count = 3;
    instruction.opcode[0].type = CDISASM_OPERAND_REGISTER;
    instruction.opcode[0].size = 16;
    instruction.opcode[0].reg = CDISASM_X86_REG_XMM1;
    instruction.opcode[1].type = CDISASM_OPERAND_REGISTER;
    instruction.opcode[1].size = 16;
    instruction.opcode[1].reg = CDISASM_X86_REG_XMM2;
    instruction.opcode[2].type = CDISASM_OPERAND_REGISTER;
    instruction.opcode[2].size = 16;
    instruction.opcode[2].reg = CDISASM_X86_REG_XMM3;
    EXPECT(cdisasm_x86_format(&instruction,
        CDISASM_FORMAT_SYNTAX_INTEL, buffer, sizeof(buffer)) == 0);
    EXPECT(buffer[0] == '\0');
#endif
}

int main(void)
{
    test_retained_case_outputs();
    test_pointer_sizes();
    test_extended_register_names_and_decorators();
    test_prefix_order_and_aliases();
    test_buffer_contract();
    test_format_flags();
    test_att_syntax_outputs();
    test_att_mode_aware_control_suffixes();
    test_att_buffer_and_compatibility();
    test_invalid_metadata();
    test_sse_outputs();
    test_x87_outputs();
    test_extra_opcode_formatting();
    test_decoder_formatter_compatibility();

    if (failures != 0) {
        fprintf(stderr, "%d formatter test(s) failed\n", failures);
        return 1;
    }
    puts("all formatter tests passed");
    return 0;
}
