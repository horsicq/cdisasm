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
            fprintf(stderr, "%s:%d: expectation failed: %s\n",            \
                __FILE__, __LINE__, #expression);                            \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(CDISASM_X86_NAME_INVLPGB == UINT16_C(1328),
    "INVLPGB name ID changed");
_Static_assert(CDISASM_X86_NAME_PSMASH == UINT16_C(1378),
    "PSMASH name ID changed");
_Static_assert(CDISASM_X86_NAME_PVALIDATE == UINT16_C(1383),
    "PVALIDATE name ID changed");
_Static_assert(CDISASM_X86_NAME_RMPADJUST == UINT16_C(1431),
    "RMPADJUST name ID changed");
_Static_assert(CDISASM_X86_NAME_RMPUPDATE == UINT16_C(1432),
    "RMPUPDATE name ID changed");
_Static_assert(CDISASM_X86_NAME_TLBSYNC == UINT16_C(1454),
    "TLBSYNC name ID changed");
_Static_assert(CDISASM_X86_GROUP_AMD_INVLPGB == UINT16_C(119),
    "AMD_INVLPGB group ID changed");
_Static_assert(CDISASM_X86_GROUP_SNP == UINT16_C(307),
    "SNP group ID changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AMD_INVLPGB == UINT32_C(67),
    "AMD_INVLPGB decode bit changed");
_Static_assert(CDISASM_X86_DECODE_BIT_SNP == UINT32_C(254),
    "SNP decode bit changed");

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
static cdisasm_x86_decode_flags exact_flags(
    cdisasm_x86_decode_bit_id bit_id,
    int include_apx)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_decode_flags_set_bit(&flags, bit_id));
    if (include_apx) {
        EXPECT(cdisasm_decode_flags_set_bit(
            &flags, CDISASM_X86_DECODE_BIT_APX));
    }
    return flags;
}

static void expect_register(
    const cdisasm_instruction *instruction,
    uint8_t index,
    cdisasm_x86_reg_id register_id,
    uint8_t size,
    cdisasm_operand_access access)
{
    EXPECT(index < instruction->operand_count);
    if (index >= instruction->operand_count) {
        return;
    }
    EXPECT(instruction->opcode[index].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[index].reg == register_id);
    EXPECT(instruction->opcode[index].size == size);
    EXPECT(instruction->opcode[index].access == access);
    EXPECT(instruction->opcode[index].flags
        == CDISASM_OPERAND_FLAG_IMPLICIT);
}

static void expect_common(
    const char *label,
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    size_t expected_size,
    cdisasm_x86_name_id name_id,
    cdisasm_x86_form_id form_id,
    cdisasm_x86_group_id group_id,
    int writes_status)
{
    if (decoded_size != expected_size
        || instruction->last_error_id != CDISASM_STATUS_OK) {
        fprintf(stderr, "%s: got size/status %u/%u, expected %u/0\n",
            label, (unsigned int)decoded_size,
            (unsigned int)instruction->last_error_id,
            (unsigned int)expected_size);
    }
    EXPECT(decoded_size == expected_size);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == name_id);
    EXPECT(instruction->form_id == form_id);
    EXPECT(cdisasm_instruction_has_x86_group(instruction, group_id));
    EXPECT((instruction->opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0u);
    EXPECT((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u);
    EXPECT((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE) == 0u);
    EXPECT(((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0u)
        == writes_status);
    EXPECT((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS) == 0u);
    EXPECT(instruction->encoding.modrm
        == (name_id == CDISASM_X86_NAME_INVLPGB
            || name_id == CDISASM_X86_NAME_RMPADJUST
            || name_id == CDISASM_X86_NAME_RMPUPDATE
            ? UINT8_C(0xfe) : UINT8_C(0xff)));
}

static void expect_text(
    const cdisasm_instruction *instruction,
    const char *expected)
{
#  if USE_DISASM_FORMAT
    char output[128];
    size_t required = cdisasm_x86_format(
        instruction, CDISASM_FORMAT_SYNTAX_INTEL, output, sizeof(output));

    if (required != strlen(expected) || strcmp(output, expected) != 0) {
        fprintf(stderr, "format: got %zu/'%s', expected %zu/'%s'\n",
            required, output, strlen(expected), expected);
    }
    EXPECT(required == strlen(expected));
    EXPECT(strcmp(output, expected) == 0);
#  else
    (void)instruction;
    (void)expected;
#  endif
}
#endif

static void test_canonical_forms(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t invlpgb16[] = {0x67, 0x0f, 0x01, 0xfe};
#endif
    static const uint8_t invlpgb[] = {0x0f, 0x01, 0xfe};
#if USE_EXTRA_OPCODES
    static const uint8_t invlpgb64_addr32[] = {0x67, 0x0f, 0x01, 0xfe};
#endif
    static const uint8_t tlbsync[] = {0x0f, 0x01, 0xff};
    static const uint8_t rmpupdate[] = {0xf2, 0x0f, 0x01, 0xfe};
    static const uint8_t pvalidate[] = {0xf2, 0x0f, 0x01, 0xff};
    static const uint8_t rmpadjust[] = {0xf3, 0x0f, 0x01, 0xfe};
    static const uint8_t psmash[] = {0xf3, 0x0f, 0x01, 0xff};
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags invlpgb_flags = exact_flags(
        CDISASM_X86_DECODE_BIT_AMD_INVLPGB, 0);
    cdisasm_x86_decode_flags snp_flags = exact_flags(
        CDISASM_X86_DECODE_BIT_SNP, 0);
    cdisasm_instruction instruction;
    uint32_t decoded_size;
    size_t index;
    static const struct {
        const char *label;
        cdisasm_x86_mode mode;
        const uint8_t *code;
        size_t size;
    } no_operand_cases[] = {
        {"INVLPGB mode16 EASZ32", CDISASM_MODE_16,
            invlpgb16, sizeof(invlpgb16)},
        {"INVLPGB mode32", CDISASM_MODE_32, invlpgb, sizeof(invlpgb)},
        {"INVLPGB mode64", CDISASM_MODE_64, invlpgb, sizeof(invlpgb)},
        {"INVLPGB mode64 EASZ32", CDISASM_MODE_64,
            invlpgb64_addr32, sizeof(invlpgb64_addr32)}
    };
    static const cdisasm_x86_mode tlbsync_modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };

    for (index = 0u;
         index < sizeof(no_operand_cases) / sizeof(no_operand_cases[0]);
         ++index) {
        instruction = decode(CDISASM_CPU_X86, no_operand_cases[index].mode,
            no_operand_cases[index].code, no_operand_cases[index].size,
            &invlpgb_flags, &decoded_size);
        expect_common(no_operand_cases[index].label, &instruction,
            decoded_size, no_operand_cases[index].size,
            CDISASM_X86_NAME_INVLPGB, UINT16_C(1410),
            CDISASM_X86_GROUP_AMD_INVLPGB, 0);
        EXPECT(instruction.operand_count == 0u);
        expect_text(&instruction, "invlpgb");
    }
    for (index = 0u; index < 3u; ++index) {
        instruction = decode(CDISASM_CPU_X86, tlbsync_modes[index],
            tlbsync, sizeof(tlbsync), &invlpgb_flags, &decoded_size);
        expect_common("TLBSYNC mode", &instruction, decoded_size,
            sizeof(tlbsync), CDISASM_X86_NAME_TLBSYNC, UINT16_C(3309),
            CDISASM_X86_GROUP_AMD_INVLPGB, 0);
        EXPECT(instruction.operand_count == 0u);
        expect_text(&instruction, "tlbsync");
    }

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        rmpupdate, sizeof(rmpupdate), &snp_flags, &decoded_size);
    expect_common("RMPUPDATE", &instruction, decoded_size,
        sizeof(rmpupdate), CDISASM_X86_NAME_RMPUPDATE, UINT16_C(2633),
        CDISASM_X86_GROUP_SNP, 1);
    EXPECT(instruction.operand_count == 2u);
    expect_register(&instruction, 0, CDISASM_X86_REG_RAX, 8u,
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    expect_register(&instruction, 1, CDISASM_X86_REG_RCX, 8u,
        CDISASM_OPERAND_ACCESS_READ);
    expect_text(&instruction, "rmpupdate rax, rcx");

    for (index = 0u; index < 3u; ++index) {
        instruction = decode(CDISASM_CPU_X86, tlbsync_modes[index],
            pvalidate, sizeof(pvalidate), &snp_flags, &decoded_size);
        expect_common("PVALIDATE mode", &instruction, decoded_size,
            sizeof(pvalidate), CDISASM_X86_NAME_PVALIDATE,
            UINT16_C(2487), CDISASM_X86_GROUP_SNP, 1);
        EXPECT(instruction.operand_count == 3u);
        expect_register(&instruction, 0, CDISASM_X86_REG_RAX, 8u,
            CDISASM_OPERAND_ACCESS_READ_WRITE);
        expect_register(&instruction, 1, CDISASM_X86_REG_ECX, 4u,
            CDISASM_OPERAND_ACCESS_READ);
        expect_register(&instruction, 2, CDISASM_X86_REG_EDX, 4u,
            CDISASM_OPERAND_ACCESS_READ);
        expect_text(&instruction, "pvalidate rax, ecx, edx");
    }

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        rmpadjust, sizeof(rmpadjust), &snp_flags, &decoded_size);
    expect_common("RMPADJUST", &instruction, decoded_size,
        sizeof(rmpadjust), CDISASM_X86_NAME_RMPADJUST, UINT16_C(2632),
        CDISASM_X86_GROUP_SNP, 1);
    EXPECT(instruction.operand_count == 3u);
    expect_register(&instruction, 0, CDISASM_X86_REG_RAX, 8u,
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    expect_register(&instruction, 1, CDISASM_X86_REG_RCX, 8u,
        CDISASM_OPERAND_ACCESS_READ);
    expect_register(&instruction, 2, CDISASM_X86_REG_RDX, 8u,
        CDISASM_OPERAND_ACCESS_READ);
    expect_text(&instruction, "rmpadjust rax, rcx, rdx");

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        psmash, sizeof(psmash), &snp_flags, &decoded_size);
    expect_common("PSMASH", &instruction, decoded_size,
        sizeof(psmash), CDISASM_X86_NAME_PSMASH, UINT16_C(2370),
        CDISASM_X86_GROUP_SNP, 1);
    EXPECT(instruction.operand_count == 1u);
    expect_register(&instruction, 0, CDISASM_X86_REG_RAX, 8u,
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    expect_text(&instruction, "psmash rax");
#else
    expect_error("INVLPGB extras OFF", CDISASM_CPU_X86, CDISASM_MODE_32,
        invlpgb, sizeof(invlpgb), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("TLBSYNC extras OFF", CDISASM_CPU_X86, CDISASM_MODE_64,
        tlbsync, sizeof(tlbsync), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("RMPUPDATE extras OFF", CDISASM_CPU_X86, CDISASM_MODE_64,
        rmpupdate, sizeof(rmpupdate), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("PVALIDATE extras OFF", CDISASM_CPU_X86, CDISASM_MODE_16,
        pvalidate, sizeof(pvalidate), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("RMPADJUST extras OFF", CDISASM_CPU_X86, CDISASM_MODE_64,
        rmpadjust, sizeof(rmpadjust), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("PSMASH extras OFF", CDISASM_CPU_X86, CDISASM_MODE_64,
        psmash, sizeof(psmash), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_prefix_and_mode_boundaries(void)
{
    static const uint8_t invlpgb_easz16[] = {0x67, 0x0f, 0x01, 0xfe};
    static const uint8_t invlpgb_66[] = {0x66, 0x0f, 0x01, 0xfe};
    static const uint8_t tlbsync_66[] = {0x66, 0x0f, 0x01, 0xff};
    static const uint8_t lock_invlpgb[] = {0xf0, 0x0f, 0x01, 0xfe};
    static const uint8_t lock_tlbsync[] = {0xf0, 0x0f, 0x01, 0xff};
    static const uint8_t rmpupdate[] = {0xf2, 0x0f, 0x01, 0xfe};
    static const uint8_t rmpadjust[] = {0xf3, 0x0f, 0x01, 0xfe};
    static const uint8_t psmash[] = {0xf3, 0x0f, 0x01, 0xff};
#if USE_EXTRA_OPCODES
    static const uint8_t pvalidate_66[] = {0x66, 0xf2, 0x0f, 0x01, 0xff};
    static const uint8_t rightmost_f2[] = {
        0xf3, 0xf2, 0x0f, 0x01, 0xff
    };
    static const uint8_t rightmost_f3[] = {
        0xf2, 0xf3, 0x0f, 0x01, 0xff
    };
    cdisasm_x86_decode_flags invlpgb_flags = exact_flags(
        CDISASM_X86_DECODE_BIT_AMD_INVLPGB, 0);
    cdisasm_x86_decode_flags snp_flags = exact_flags(
        CDISASM_X86_DECODE_BIT_SNP, 0);
    uint32_t decoded_size;
    cdisasm_instruction instruction;
#else
    const cdisasm_x86_decode_flags *invlpgb_flags = NULL;
    const cdisasm_x86_decode_flags *snp_flags = NULL;
#endif

    expect_error("INVLPGB mode16 EASZ16", CDISASM_CPU_X86,
        CDISASM_MODE_16, invlpgb_easz16 + 1,
        sizeof(invlpgb_easz16) - 1u,
#if USE_EXTRA_OPCODES
        &invlpgb_flags,
#else
        invlpgb_flags,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("INVLPGB mode32 EASZ16", CDISASM_CPU_X86,
        CDISASM_MODE_32, invlpgb_easz16, sizeof(invlpgb_easz16),
#if USE_EXTRA_OPCODES
        &invlpgb_flags,
#else
        invlpgb_flags,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("66 INVLPGB", CDISASM_CPU_X86, CDISASM_MODE_64,
        invlpgb_66, sizeof(invlpgb_66),
#if USE_EXTRA_OPCODES
        &invlpgb_flags,
#else
        invlpgb_flags,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("66 TLBSYNC", CDISASM_CPU_X86, CDISASM_MODE_64,
        tlbsync_66, sizeof(tlbsync_66),
#if USE_EXTRA_OPCODES
        &invlpgb_flags,
#else
        invlpgb_flags,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("LOCK INVLPGB", CDISASM_CPU_X86, CDISASM_MODE_64,
        lock_invlpgb, sizeof(lock_invlpgb),
#if USE_EXTRA_OPCODES
        &invlpgb_flags,
#else
        invlpgb_flags,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("LOCK TLBSYNC", CDISASM_CPU_X86, CDISASM_MODE_64,
        lock_tlbsync, sizeof(lock_tlbsync),
#if USE_EXTRA_OPCODES
        &invlpgb_flags,
#else
        invlpgb_flags,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("RMPUPDATE mode32", CDISASM_CPU_X86, CDISASM_MODE_32,
        rmpupdate, sizeof(rmpupdate),
#if USE_EXTRA_OPCODES
        &snp_flags,
#else
        snp_flags,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("RMPADJUST mode16", CDISASM_CPU_X86, CDISASM_MODE_16,
        rmpadjust, sizeof(rmpadjust),
#if USE_EXTRA_OPCODES
        &snp_flags,
#else
        snp_flags,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("PSMASH mode32", CDISASM_CPU_X86, CDISASM_MODE_32,
        psmash, sizeof(psmash),
#if USE_EXTRA_OPCODES
        &snp_flags,
#else
        snp_flags,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);

#if USE_EXTRA_OPCODES
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_16,
        pvalidate_66, sizeof(pvalidate_66), &snp_flags, &decoded_size);
    expect_common("66 PVALIDATE", &instruction, decoded_size,
        sizeof(pvalidate_66), CDISASM_X86_NAME_PVALIDATE,
        UINT16_C(2487), CDISASM_X86_GROUP_SNP, 1);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        rightmost_f2, sizeof(rightmost_f2), &snp_flags, &decoded_size);
    EXPECT(decoded_size == sizeof(rightmost_f2));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_PVALIDATE);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        rightmost_f3, sizeof(rightmost_f3), &snp_flags, &decoded_size);
    EXPECT(decoded_size == sizeof(rightmost_f3));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_PSMASH);
#endif
}

static void test_runtime_and_cpu_gates(void)
{
#if USE_EXTRA_OPCODES
    static const uint8_t invlpgb[] = {0x0f, 0x01, 0xfe};
    static const uint8_t pvalidate[] = {0xf2, 0x0f, 0x01, 0xff};
    cdisasm_x86_decode_flags invlpgb_flags = exact_flags(
        CDISASM_X86_DECODE_BIT_AMD_INVLPGB, 0);
    cdisasm_x86_decode_flags snp_flags = exact_flags(
        CDISASM_X86_DECODE_BIT_SNP, 0);
    cdisasm_x86_decode_flags system =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    cdisasm_x86_decode_flags mask;
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    system.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP] =
        CDISASM_X86_DECODE_FLAG_SYSTEM;
    expect_error("NULL flags are not AMD_INVLPGB", CDISASM_CPU_X86,
        CDISASM_MODE_32, invlpgb, sizeof(invlpgb), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("SYSTEM is not AMD_INVLPGB", CDISASM_CPU_X86,
        CDISASM_MODE_32, invlpgb, sizeof(invlpgb), &system,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("SNP is not AMD_INVLPGB", CDISASM_CPU_X86,
        CDISASM_MODE_32, invlpgb, sizeof(invlpgb), &snp_flags,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("NULL flags are not SNP", CDISASM_CPU_X86,
        CDISASM_MODE_64, pvalidate, sizeof(pvalidate), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("SYSTEM is not SNP", CDISASM_CPU_X86,
        CDISASM_MODE_64, pvalidate, sizeof(pvalidate), &system,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("AMD_INVLPGB is not SNP", CDISASM_CPU_X86,
        CDISASM_MODE_64, pvalidate, sizeof(pvalidate), &invlpgb_flags,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_X86, CDISASM_MODE_64, &mask) == CDISASM_STATUS_OK);
    EXPECT(cdisasm_decode_flags_test_bit(
        &mask, CDISASM_X86_DECODE_BIT_AMD_INVLPGB));
    EXPECT(cdisasm_decode_flags_test_bit(&mask, CDISASM_X86_DECODE_BIT_SNP));
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        pvalidate, sizeof(pvalidate), &mask, &decoded_size);
    EXPECT(decoded_size == sizeof(pvalidate));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_PVALIDATE);

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_AMD_ZEN_4, CDISASM_MODE_64, &mask)
        == CDISASM_STATUS_OK);
    EXPECT(!cdisasm_decode_flags_test_bit(
        &mask, CDISASM_X86_DECODE_BIT_AMD_INVLPGB));
    EXPECT(!cdisasm_decode_flags_test_bit(&mask, CDISASM_X86_DECODE_BIT_SNP));
    expect_error("Zen4 has no AMD_INVLPGB", CDISASM_CPU_AMD_ZEN_4,
        CDISASM_MODE_64, invlpgb, sizeof(invlpgb), &invlpgb_flags,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("Zen4 has no SNP", CDISASM_CPU_AMD_ZEN_4,
        CDISASM_MODE_64, pvalidate, sizeof(pvalidate), &snp_flags,
        CDISASM_STATUS_INVALID_INSTRUCTION);
#endif
}

static void test_rex2_and_truncation(void)
{
    static const uint8_t rex2_invlpgb[] = {0xd5, 0x80, 0x01, 0xfe};
    static const uint8_t rex2_pvalidate[] = {
        0xf2, 0xd5, 0x80, 0x01, 0xff
    };
    static const uint8_t truncated[] = {0xf2, 0x0f, 0x01};
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags invlpgb_flags = exact_flags(
        CDISASM_X86_DECODE_BIT_AMD_INVLPGB, 0);
    cdisasm_x86_decode_flags invlpgb_apx = exact_flags(
        CDISASM_X86_DECODE_BIT_AMD_INVLPGB, 1);
    cdisasm_x86_decode_flags snp_flags = exact_flags(
        CDISASM_X86_DECODE_BIT_SNP, 0);
    cdisasm_x86_decode_flags snp_apx = exact_flags(
        CDISASM_X86_DECODE_BIT_SNP, 1);
    uint32_t decoded_size;
    cdisasm_instruction instruction;
    unsigned int payload;

    expect_error("REX2 INVLPGB needs APX", CDISASM_CPU_X86,
        CDISASM_MODE_64, rex2_invlpgb, sizeof(rex2_invlpgb),
        &invlpgb_flags, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("REX2 PVALIDATE needs APX", CDISASM_CPU_X86,
        CDISASM_MODE_64, rex2_pvalidate, sizeof(rex2_pvalidate),
        &snp_flags, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    for (payload = UINT8_C(0x80); payload <= UINT8_MAX; ++payload) {
        uint8_t invlpgb[] = {0xd5, (uint8_t)payload, 0x01, 0xfe};
        uint8_t pvalidate[] = {
            0xf2, 0xd5, (uint8_t)payload, 0x01, 0xff
        };

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            invlpgb, sizeof(invlpgb), &invlpgb_apx, &decoded_size);
        EXPECT(decoded_size == sizeof(invlpgb));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_INVLPGB);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            pvalidate, sizeof(pvalidate), &snp_apx, &decoded_size);
        EXPECT(decoded_size == sizeof(pvalidate));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_PVALIDATE);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F));
    }
#else
    expect_error("REX2 INVLPGB extras OFF", CDISASM_CPU_X86,
        CDISASM_MODE_64, rex2_invlpgb, sizeof(rex2_invlpgb), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("REX2 PVALIDATE extras OFF", CDISASM_CPU_X86,
        CDISASM_MODE_64, rex2_pvalidate, sizeof(rex2_pvalidate), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    expect_error("truncated SNP", CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated, sizeof(truncated),
#if USE_EXTRA_OPCODES
        &snp_flags,
#else
        NULL,
#endif
        CDISASM_STATUS_TRUNCATED);
}

int main(void)
{
    test_canonical_forms();
    test_prefix_and_mode_boundaries();
    test_runtime_and_cpu_gates();
    test_rex2_and_truncation();

    if (failures != 0) {
        fprintf(stderr, "%d AMD INVLPGB/SNP test(s) failed\n", failures);
        return 1;
    }
    puts("x86 AMD INVLPGB/SNP tests passed");
    return 0;
}
