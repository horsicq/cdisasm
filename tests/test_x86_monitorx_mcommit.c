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

_Static_assert(CDISASM_X86_NAME_MCOMMIT == UINT16_C(1342),
    "MCOMMIT name ID changed");
_Static_assert(CDISASM_X86_NAME_MONITORX == UINT16_C(1343),
    "MONITORX name ID changed");
_Static_assert(CDISASM_X86_NAME_MWAITX == UINT16_C(1354),
    "MWAITX name ID changed");
_Static_assert(CDISASM_X86_GROUP_MCOMMIT == UINT16_C(282),
    "MCOMMIT group ID changed");
_Static_assert(CDISASM_X86_GROUP_MONITORX == UINT16_C(284),
    "MONITORX group ID changed");
_Static_assert(CDISASM_X86_DECODE_BIT_MCOMMIT == UINT32_C(229),
    "MCOMMIT decode bit changed");
_Static_assert(CDISASM_X86_DECODE_BIT_MONITORX == UINT32_C(231),
    "MONITORX decode bit changed");

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

static cdisasm_x86_decode_flags exact_apx_flags(
    cdisasm_x86_decode_bit_id bit_id)
{
    cdisasm_x86_decode_flags flags = one_bit(bit_id);

    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_APX));
    return flags;
}

static void check_family(
    const char *label,
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    size_t expected_size,
    cdisasm_x86_name_id name_id,
    uint8_t prefix_size,
    uint8_t opcode_size,
    int expect_rex2)
{
    const int is_mcommit = name_id == CDISASM_X86_NAME_MCOMMIT;
    const cdisasm_x86_form_id form_id = is_mcommit
        ? UINT16_C(1629)
        : (name_id == CDISASM_X86_NAME_MONITORX
            ? UINT16_C(1640) : UINT16_C(1822));
    const cdisasm_x86_group_id group_id = is_mcommit
        ? CDISASM_X86_GROUP_MCOMMIT : CDISASM_X86_GROUP_MONITORX;

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
    EXPECT(!cdisasm_instruction_has_x86_group(
        instruction, is_mcommit
            ? CDISASM_X86_GROUP_MONITORX : CDISASM_X86_GROUP_MCOMMIT));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_APX_F) == expect_rex2);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u);
    EXPECT((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE) == 0u);
    EXPECT(((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0u)
        == is_mcommit);
    EXPECT((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_PREFIX_EFFECTIVE_MASK | CDISASM_PREFIX_HLE_MASK)) == 0u);
    EXPECT(instruction->operand_count == 0u);
    EXPECT(instruction->encoding.prefix_size == prefix_size);
    EXPECT(instruction->encoding.opcode_offset == prefix_size);
    EXPECT(instruction->encoding.opcode_size == opcode_size);
    EXPECT(instruction->encoding.modrm_offset
        == (uint8_t)(prefix_size + opcode_size));
    EXPECT(instruction->encoding.modrm
        == (name_id == CDISASM_X86_NAME_MWAITX
            ? UINT8_C(0xfb) : UINT8_C(0xfa)));
    EXPECT(instruction->encoding.sib_offset == 0u);
    EXPECT(instruction->encoding.displacement_size == 0u);
    EXPECT(instruction->encoding.immediate_count == 0u);
    EXPECT(((instruction->opcode_flags & CDISASM_PREFIX_REX2) != 0u)
        == expect_rex2);
}
#endif

static void test_complete_group7_ownership(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    static const uint8_t prefixes[] = {0u, 0xf2, 0xf3, 0x66};
    size_t mode_index;
    size_t prefix_index;
    unsigned int fixed;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags all =
        CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER;
#endif

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        for (prefix_index = 0u; prefix_index < 4u; ++prefix_index) {
            for (fixed = 0u; fixed <= UINT8_MAX; ++fixed) {
                uint8_t code[4];
                size_t size = 0u;
                uint32_t decoded_size;
                cdisasm_instruction instruction;
                cdisasm_x86_name_id expected_name = CDISASM_X86_NAME_NONE;

                if (prefixes[prefix_index] != 0u) {
                    code[size++] = prefixes[prefix_index];
                }
                code[size++] = UINT8_C(0x0f);
                code[size++] = UINT8_C(0x01);
                code[size++] = (uint8_t)fixed;
                if (prefixes[prefix_index] == 0u
                    && fixed == UINT8_C(0xfa)) {
                    expected_name = CDISASM_X86_NAME_MONITORX;
                } else if (prefixes[prefix_index] == 0u
                    && fixed == UINT8_C(0xfb)) {
                    expected_name = CDISASM_X86_NAME_MWAITX;
                } else if (prefixes[prefix_index] == UINT8_C(0xf3)
                    && fixed == UINT8_C(0xfa)) {
                    expected_name = CDISASM_X86_NAME_MCOMMIT;
                }

                instruction = decode(
                    CDISASM_CPU_X86, modes[mode_index], code, size,
#if USE_EXTRA_OPCODES
                    &all,
#else
                    NULL,
#endif
                    &decoded_size);
                if (expected_name != CDISASM_X86_NAME_NONE) {
#if USE_EXTRA_OPCODES
                    check_family("Group-7 allocated cell", &instruction,
                        decoded_size, size, expected_name,
                        prefixes[prefix_index] == 0u ? 0u : 1u, 2u, 0);
#else
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(&instruction,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                } else {
                    EXPECT(instruction.name_id != CDISASM_X86_NAME_MCOMMIT);
                    EXPECT(instruction.name_id != CDISASM_X86_NAME_MONITORX);
                    EXPECT(instruction.name_id != CDISASM_X86_NAME_MWAITX);
                    EXPECT(!cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_MCOMMIT));
                    EXPECT(!cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_MONITORX));
                }
            }
        }
    }
}

static void test_legal_prefixes_and_suppressed_state(void)
{
    static const uint8_t monitorx[] = {0x0f, 0x01, 0xfa};
    static const uint8_t mwaitx[] = {0x0f, 0x01, 0xfb};
    static const uint8_t mcommit[] = {0xf3, 0x0f, 0x01, 0xfa};
    static const struct prefix_case {
        const char *label;
        uint8_t code[8];
        uint8_t size;
        cdisasm_x86_name_id name_id;
        uint32_t raw_flags;
    } cases[] = {
        {"MONITORX address32 state", {0x67, 0x0f, 0x01, 0xfa}, 4,
         CDISASM_X86_NAME_MONITORX, CDISASM_PREFIX_ADDRESS_SIZE},
        {"MONITORX segment", {0x64, 0x0f, 0x01, 0xfa}, 4,
         CDISASM_X86_NAME_MONITORX, CDISASM_PREFIX_SEGMENT},
        {"MWAITX address", {0x67, 0x0f, 0x01, 0xfb}, 4,
         CDISASM_X86_NAME_MWAITX, CDISASM_PREFIX_ADDRESS_SIZE},
        {"MWAITX segment", {0x2e, 0x0f, 0x01, 0xfb}, 4,
         CDISASM_X86_NAME_MWAITX, CDISASM_PREFIX_SEGMENT},
        {"MCOMMIT address", {0x67, 0xf3, 0x0f, 0x01, 0xfa}, 5,
         CDISASM_X86_NAME_MCOMMIT,
         CDISASM_PREFIX_ADDRESS_SIZE | CDISASM_PREFIX_REP},
        {"MCOMMIT segment", {0x65, 0xf3, 0x0f, 0x01, 0xfa}, 5,
         CDISASM_X86_NAME_MCOMMIT,
         CDISASM_PREFIX_SEGMENT | CDISASM_PREFIX_REP},
        {"MCOMMIT redundant 66", {0x66, 0xf3, 0x0f, 0x01, 0xfa}, 5,
         CDISASM_X86_NAME_MCOMMIT,
         CDISASM_PREFIX_OPERAND_SIZE | CDISASM_PREFIX_REP},
        {"MCOMMIT F3 then 66", {0xf3, 0x66, 0x0f, 0x01, 0xfa}, 5,
         CDISASM_X86_NAME_MCOMMIT,
         CDISASM_PREFIX_OPERAND_SIZE | CDISASM_PREFIX_REP},
        {"MCOMMIT rightmost F3", {0xf2, 0xf3, 0x0f, 0x01, 0xfa}, 5,
         CDISASM_X86_NAME_MCOMMIT,
         CDISASM_PREFIX_REPNE | CDISASM_PREFIX_REP}
    };
    size_t index;
    unsigned int rex;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags monitorx_flags = one_bit(
        CDISASM_X86_DECODE_BIT_MONITORX);
    cdisasm_x86_decode_flags mcommit_flags = one_bit(
        CDISASM_X86_DECODE_BIT_MCOMMIT);
#endif

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
#if USE_EXTRA_OPCODES
        const cdisasm_x86_decode_flags *flags =
            cases[index].name_id == CDISASM_X86_NAME_MCOMMIT
                ? &mcommit_flags : &monitorx_flags;
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size, flags, &decoded_size);

        check_family(cases[index].label, &instruction, decoded_size,
            cases[index].size, cases[index].name_id,
            (uint8_t)(cases[index].size - 3u), 2u, 0);
        EXPECT((instruction.opcode_flags & cases[index].raw_flags)
            == cases[index].raw_flags);
#else
        expect_error(cases[index].label, CDISASM_CPU_X86,
            CDISASM_MODE_64, cases[index].code, cases[index].size,
            NULL, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }

    for (rex = 0u; rex < 16u; ++rex) {
        const cdisasm_x86_name_id names[] = {
            CDISASM_X86_NAME_MONITORX,
            CDISASM_X86_NAME_MWAITX,
            CDISASM_X86_NAME_MCOMMIT
        };
        size_t name_index;

        for (name_index = 0u; name_index < 3u; ++name_index) {
            uint8_t code[5];
            size_t size = 0u;
#if USE_EXTRA_OPCODES
            const cdisasm_x86_decode_flags *flags =
                names[name_index] == CDISASM_X86_NAME_MCOMMIT
                    ? &mcommit_flags : &monitorx_flags;
            uint32_t decoded_size;
            cdisasm_instruction instruction;
#endif

            if (names[name_index] == CDISASM_X86_NAME_MCOMMIT) {
                code[size++] = UINT8_C(0xf3);
            }
            code[size++] = (uint8_t)(UINT8_C(0x40) + rex);
            code[size++] = UINT8_C(0x0f);
            code[size++] = UINT8_C(0x01);
            code[size++] = names[name_index] == CDISASM_X86_NAME_MWAITX
                ? UINT8_C(0xfb) : UINT8_C(0xfa);
#if USE_EXTRA_OPCODES
            instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64,
                code, size, flags, &decoded_size);
            check_family("ordinary REX sweep", &instruction, decoded_size,
                size, names[name_index],
                names[name_index] == CDISASM_X86_NAME_MCOMMIT ? 2u : 1u,
                2u, 0);
            EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REX) != 0u);
            EXPECT(((instruction.opcode_flags & CDISASM_PREFIX_REX_W) != 0u)
                == ((rex & 8u) != 0u));
#else
            expect_error("ordinary REX sweep OFF", CDISASM_CPU_X86,
                CDISASM_MODE_64, code, size, NULL,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }

#if USE_EXTRA_OPCODES
    for (index = 0u; index < 3u; ++index) {
        static const cdisasm_x86_mode modes[] = {
            CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
        };
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, modes[index], monitorx, sizeof(monitorx),
            &monitorx_flags, &decoded_size);

        check_family("MONITORX suppressed address register", &instruction,
            decoded_size, sizeof(monitorx), CDISASM_X86_NAME_MONITORX,
            0u, 2u, 0);
        instruction = decode(
            CDISASM_CPU_X86, modes[index], mwaitx, sizeof(mwaitx),
            &monitorx_flags, &decoded_size);
        check_family("MWAITX suppressed control state", &instruction,
            decoded_size, sizeof(mwaitx), CDISASM_X86_NAME_MWAITX,
            0u, 2u, 0);
        instruction = decode(
            CDISASM_CPU_X86, modes[index], mcommit, sizeof(mcommit),
            &mcommit_flags, &decoded_size);
        check_family("MCOMMIT all modes", &instruction, decoded_size,
            sizeof(mcommit), CDISASM_X86_NAME_MCOMMIT, 1u, 2u, 0);
    }
#else
    (void)monitorx;
    (void)mwaitx;
    (void)mcommit;
#endif
}

static void test_invalid_prefixes(void)
{
    static const struct invalid_case {
        const char *label;
        uint8_t code[7];
        uint8_t size;
    } cases[] = {
        {"LOCK MONITORX", {0xf0, 0x0f, 0x01, 0xfa}, 4},
        {"LOCK MWAITX", {0xf0, 0x0f, 0x01, 0xfb}, 4},
        {"LOCK MCOMMIT", {0xf0, 0xf3, 0x0f, 0x01, 0xfa}, 5},
        {"F2 MONITORX", {0xf2, 0x0f, 0x01, 0xfa}, 4},
        {"F2 MWAITX", {0xf2, 0x0f, 0x01, 0xfb}, 4},
        {"F3 MWAITX", {0xf3, 0x0f, 0x01, 0xfb}, 4},
        {"66 MONITORX", {0x66, 0x0f, 0x01, 0xfa}, 4},
        {"66 MWAITX", {0x66, 0x0f, 0x01, 0xfb}, 4},
        {"rightmost F2 rejects MCOMMIT",
         {0xf3, 0xf2, 0x0f, 0x01, 0xfa}, 5},
        {"66 plus NP is not MONITORX",
         {0xf3, 0xf2, 0x66, 0x0f, 0x01, 0xfa}, 6}
    };
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t case_index;
    size_t mode_index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags all =
        CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER;
#endif

    for (case_index = 0u;
         case_index < sizeof(cases) / sizeof(cases[0]);
         ++case_index) {
        for (mode_index = 0u; mode_index < 3u; ++mode_index) {
            expect_error(cases[case_index].label, CDISASM_CPU_X86,
                modes[mode_index], cases[case_index].code,
                cases[case_index].size,
#if USE_EXTRA_OPCODES
                &all,
#else
                NULL,
#endif
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
}

static void test_cpu_and_runtime_gates(void)
{
    static const uint8_t monitorx[] = {0x0f, 0x01, 0xfa};
    static const uint8_t mwaitx[] = {0x0f, 0x01, 0xfb};
    static const uint8_t mcommit[] = {0xf3, 0x0f, 0x01, 0xfa};
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t mode_index;
    cdisasm_cpu_id cpu;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags monitorx_flags = one_bit(
        CDISASM_X86_DECODE_BIT_MONITORX);
    cdisasm_x86_decode_flags mcommit_flags = one_bit(
        CDISASM_X86_DECODE_BIT_MCOMMIT);
    cdisasm_x86_decode_flags wrong = one_bit(
        CDISASM_X86_DECODE_BIT_CLZERO);
    cdisasm_x86_decode_flags system =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    system.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP] =
        CDISASM_X86_DECODE_FLAG_SYSTEM;
    expect_error("MONITORX needs exact bit", CDISASM_CPU_X86,
        CDISASM_MODE_64, monitorx, sizeof(monitorx), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("MWAITX needs exact bit", CDISASM_CPU_X86,
        CDISASM_MODE_64, mwaitx, sizeof(mwaitx), &wrong,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("MCOMMIT needs exact bit", CDISASM_CPU_X86,
        CDISASM_MODE_64, mcommit, sizeof(mcommit), &system,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("MONITORX bit is not MCOMMIT", CDISASM_CPU_X86,
        CDISASM_MODE_64, mcommit, sizeof(mcommit), &monitorx_flags,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("MCOMMIT bit is not MONITORX", CDISASM_CPU_X86,
        CDISASM_MODE_64, monitorx, sizeof(monitorx), &mcommit_flags,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        cdisasm_x86_decode_flags mask;

        EXPECT(cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_X86, modes[mode_index], &mask)
            == CDISASM_STATUS_OK);
        EXPECT(cdisasm_decode_flags_test_bit(
            &mask, CDISASM_X86_DECODE_BIT_MCOMMIT)
            == USE_EXTRA_OPCODES);
        EXPECT(cdisasm_decode_flags_test_bit(
            &mask, CDISASM_X86_DECODE_BIT_MONITORX)
            == USE_EXTRA_OPCODES);
#if USE_EXTRA_OPCODES
        {
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, modes[mode_index], monitorx,
                sizeof(monitorx), &monitorx_flags, &decoded_size);

            check_family("unrestricted MONITORX profile", &instruction,
                decoded_size, sizeof(monitorx),
                CDISASM_X86_NAME_MONITORX, 0u, 2u, 0);
            instruction = decode(
                CDISASM_CPU_X86, modes[mode_index], mcommit,
                sizeof(mcommit), &mcommit_flags, &decoded_size);
            check_family("unrestricted MCOMMIT profile", &instruction,
                decoded_size, sizeof(mcommit),
                CDISASM_X86_NAME_MCOMMIT, 1u, 2u, 0);
        }
#else
        expect_error("MONITORX extras-OFF ownership", CDISASM_CPU_X86,
            modes[mode_index], monitorx, sizeof(monitorx), NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("MWAITX extras-OFF ownership", CDISASM_CPU_X86,
            modes[mode_index], mwaitx, sizeof(mwaitx), NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("MCOMMIT extras-OFF ownership", CDISASM_CPU_X86,
            modes[mode_index], mcommit, sizeof(mcommit), NULL,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }

    for (cpu = CDISASM_CPU_FIRST; cpu <= CDISASM_CPU_LAST; ++cpu) {
        const cdisasm_x86_mode_mask mode_mask =
            cdisasm_x86_cpu_mode_mask(cpu);
        const cdisasm_x86_mode selected_mode =
            (mode_mask & CDISASM_X86_MODE_MASK_64) != 0u
                ? CDISASM_MODE_64
                : ((mode_mask & CDISASM_X86_MODE_MASK_32) != 0u
                    ? CDISASM_MODE_32 : CDISASM_MODE_16);
        cdisasm_x86_decode_flags mask;

        EXPECT(mode_mask != CDISASM_X86_MODE_MASK_NONE);
        EXPECT(cdisasm_x86_cpu_decode_flag_mask(
            cpu, selected_mode, &mask) == CDISASM_STATUS_OK);
        EXPECT(!cdisasm_decode_flags_test_bit(
            &mask, CDISASM_X86_DECODE_BIT_MCOMMIT));
        EXPECT(!cdisasm_decode_flags_test_bit(
            &mask, CDISASM_X86_DECODE_BIT_MONITORX));
        expect_error("named profile lacks AMD MCOMMIT", cpu, selected_mode,
            mcommit, sizeof(mcommit),
#if USE_EXTRA_OPCODES
            &mcommit_flags,
#else
            NULL,
#endif
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("named profile lacks AMD MONITORX", cpu, selected_mode,
            monitorx, sizeof(monitorx),
#if USE_EXTRA_OPCODES
            &monitorx_flags,
#else
            NULL,
#endif
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("named profile lacks AMD MWAITX", cpu, selected_mode,
            mwaitx, sizeof(mwaitx),
#if USE_EXTRA_OPCODES
            &monitorx_flags,
#else
            NULL,
#endif
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

static void test_rex2_promotions(void)
{
    static const cdisasm_x86_name_id names[] = {
        CDISASM_X86_NAME_MONITORX,
        CDISASM_X86_NAME_MWAITX,
        CDISASM_X86_NAME_MCOMMIT
    };
    unsigned int payload;
    size_t name_index;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags monitorx_apx = exact_apx_flags(
        CDISASM_X86_DECODE_BIT_MONITORX);
    cdisasm_x86_decode_flags mcommit_apx = exact_apx_flags(
        CDISASM_X86_DECODE_BIT_MCOMMIT);
#endif

    for (name_index = 0u; name_index < 3u; ++name_index) {
        for (payload = UINT8_C(0x80); payload <= UINT8_MAX; ++payload) {
            uint8_t code[5];
            size_t size = 0u;

            if (names[name_index] == CDISASM_X86_NAME_MCOMMIT) {
                code[size++] = UINT8_C(0xf3);
            }
            code[size++] = UINT8_C(0xd5);
            code[size++] = (uint8_t)payload;
            code[size++] = UINT8_C(0x01);
            code[size++] = names[name_index] == CDISASM_X86_NAME_MWAITX
                ? UINT8_C(0xfb) : UINT8_C(0xfa);
#if USE_EXTRA_OPCODES
            {
                const cdisasm_x86_decode_flags *flags =
                    names[name_index] == CDISASM_X86_NAME_MCOMMIT
                        ? &mcommit_apx : &monitorx_apx;
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(
                    CDISASM_CPU_X86, CDISASM_MODE_64,
                    code, size, flags, &decoded_size);

                check_family("REX2 payload sweep", &instruction,
                    decoded_size, size, names[name_index],
                    names[name_index] == CDISASM_X86_NAME_MCOMMIT ? 3u : 2u,
                    1u, 1);
            }
#else
            expect_error("REX2 payload sweep OFF", CDISASM_CPU_X86,
                CDISASM_MODE_64, code, size, NULL,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }

#if USE_EXTRA_OPCODES
    {
        static const uint8_t monitorx_rex2[] = {0xd5, 0x80, 0x01, 0xfa};
        static const uint8_t mcommit_rex2[] = {
            0xf3, 0xd5, 0x80, 0x01, 0xfa
        };
        cdisasm_x86_decode_flags monitorx = one_bit(
            CDISASM_X86_DECODE_BIT_MONITORX);
        cdisasm_x86_decode_flags mcommit = one_bit(
            CDISASM_X86_DECODE_BIT_MCOMMIT);
        cdisasm_x86_decode_flags apx = one_bit(
            CDISASM_X86_DECODE_BIT_APX);

        expect_error("REX2 MONITORX needs APX bit", CDISASM_CPU_X86,
            CDISASM_MODE_64, monitorx_rex2, sizeof(monitorx_rex2),
            &monitorx, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("REX2 MCOMMIT needs APX bit", CDISASM_CPU_X86,
            CDISASM_MODE_64, mcommit_rex2, sizeof(mcommit_rex2),
            &mcommit, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("REX2 family needs exact bit", CDISASM_CPU_X86,
            CDISASM_MODE_64, monitorx_rex2, sizeof(monitorx_rex2),
            &apx, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        expect_error("APX CPU lacks MONITORX", CDISASM_CPU_APX,
            CDISASM_MODE_64, monitorx_rex2, sizeof(monitorx_rex2),
            &monitorx_apx, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
#endif

    {
        static const uint8_t rex2_f2_monitorx[] = {
            0xf2, 0xd5, 0x80, 0x01, 0xfa
        };
        static const uint8_t rex2_66_monitorx[] = {
            0x66, 0xd5, 0x80, 0x01, 0xfa
        };
        static const uint8_t rex2_lock_mcommit[] = {
            0xf0, 0xf3, 0xd5, 0x80, 0x01, 0xfa
        };
#if USE_EXTRA_OPCODES
        cdisasm_x86_decode_flags all =
            CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER;
#endif

        expect_error("F2 REX2 MONITORX", CDISASM_CPU_X86,
            CDISASM_MODE_64, rex2_f2_monitorx,
            sizeof(rex2_f2_monitorx),
#if USE_EXTRA_OPCODES
            &all,
#else
            NULL,
#endif
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("66 REX2 MONITORX", CDISASM_CPU_X86,
            CDISASM_MODE_64, rex2_66_monitorx,
            sizeof(rex2_66_monitorx),
#if USE_EXTRA_OPCODES
            &all,
#else
            NULL,
#endif
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("LOCK REX2 MCOMMIT", CDISASM_CPU_X86,
            CDISASM_MODE_64, rex2_lock_mcommit,
            sizeof(rex2_lock_mcommit),
#if USE_EXTRA_OPCODES
            &all,
#else
            NULL,
#endif
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

static void test_collisions_and_truncation(void)
{
    static const uint8_t monitor[] = {0x0f, 0x01, 0xc8};
    static const uint8_t mwait[] = {0x0f, 0x01, 0xc9};
    static const uint8_t sgdt[] = {
        0x0f, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00
    };
    static const uint8_t truncated[] = {0x0f, 0x01};
    static const uint8_t truncated_f3[] = {0xf3, 0x0f, 0x01};
    static const uint8_t truncated_rex2[] = {0xd5, 0x80, 0x01};
    uint32_t decoded_size;
    cdisasm_instruction instruction;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags all =
        CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER;
#endif

    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        monitor, sizeof(monitor),
#if USE_EXTRA_OPCODES
        &all,
#else
        NULL,
#endif
        &decoded_size);
#if USE_EXTRA_OPCODES
    EXPECT(decoded_size == sizeof(monitor));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_MONITOR);
#else
    EXPECT(decoded_size == 0u);
#endif
    EXPECT(instruction.name_id != CDISASM_X86_NAME_MONITORX);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        mwait, sizeof(mwait),
#if USE_EXTRA_OPCODES
        &all,
#else
        NULL,
#endif
        &decoded_size);
#if USE_EXTRA_OPCODES
    EXPECT(decoded_size == sizeof(mwait));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_MWAIT);
#else
    EXPECT(decoded_size == 0u);
#endif
    EXPECT(instruction.name_id != CDISASM_X86_NAME_MWAITX);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        sgdt, sizeof(sgdt), NULL, &decoded_size);
    EXPECT(decoded_size == sizeof(sgdt));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_SGDT);
    EXPECT(instruction.operand_count == 1u);

    expect_error("truncated fixed Group-7 selector", CDISASM_CPU_X86,
        CDISASM_MODE_64, truncated, sizeof(truncated),
#if USE_EXTRA_OPCODES
        &all,
#else
        NULL,
#endif
        CDISASM_STATUS_TRUNCATED);
    expect_error("truncated F3 fixed selector", CDISASM_CPU_X86,
        CDISASM_MODE_64, truncated_f3, sizeof(truncated_f3),
#if USE_EXTRA_OPCODES
        &all,
#else
        NULL,
#endif
        CDISASM_STATUS_TRUNCATED);
    expect_error("truncated REX2 fixed selector", CDISASM_CPU_X86,
        CDISASM_MODE_64, truncated_rex2, sizeof(truncated_rex2),
#if USE_EXTRA_OPCODES
        &all,
#else
        NULL,
#endif
        CDISASM_STATUS_TRUNCATED);
}

static void test_formatting(void)
{
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    static const struct format_case {
        uint8_t code[4];
        uint8_t size;
        cdisasm_x86_name_id name_id;
        cdisasm_x86_decode_bit_id bit_id;
        const char *text;
    } cases[] = {
        {{0x0f, 0x01, 0xfa}, 3, CDISASM_X86_NAME_MONITORX,
         CDISASM_X86_DECODE_BIT_MONITORX, "monitorx"},
        {{0x0f, 0x01, 0xfb}, 3, CDISASM_X86_NAME_MWAITX,
         CDISASM_X86_DECODE_BIT_MONITORX, "mwaitx"},
        {{0xf3, 0x0f, 0x01, 0xfa}, 4, CDISASM_X86_NAME_MCOMMIT,
         CDISASM_X86_DECODE_BIT_MCOMMIT, "mcommit"}
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_x86_decode_flags flags = one_bit(cases[index].bit_id);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[index].code, cases[index].size, &flags, &decoded_size);
        char output[64];
        size_t required;

        EXPECT(decoded_size == cases[index].size);
        EXPECT(instruction.name_id == cases[index].name_id);
        required = cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output));
        EXPECT(required == strlen(cases[index].text));
        EXPECT(strcmp(output, cases[index].text) == 0);
        required = cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output));
        EXPECT(required == strlen(cases[index].text));
        EXPECT(strcmp(output, cases[index].text) == 0);
    }
#endif
}

int main(void)
{
    test_complete_group7_ownership();
    test_legal_prefixes_and_suppressed_state();
    test_invalid_prefixes();
    test_cpu_and_runtime_gates();
    test_rex2_promotions();
    test_collisions_and_truncation();
    test_formatting();

    if (failures != 0) {
        fprintf(stderr, "%d MONITORX/MWAITX/MCOMMIT test(s) failed\n",
            failures);
        return 1;
    }
    puts("x86 MONITORX/MWAITX/MCOMMIT tests passed "
         "(9 allocated mode/form cells; 3,063 non-family prefix/ModRM cells; "
         "384 REX2 payloads)");
    return 0;
}
