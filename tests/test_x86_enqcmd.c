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

_Static_assert(CDISASM_X86_NAME_ENQCMD == UINT16_C(1184),
    "ENQCMD name ID changed");
_Static_assert(CDISASM_X86_NAME_ENQCMDS == UINT16_C(1185),
    "ENQCMDS name ID changed");
_Static_assert(CDISASM_X86_GROUP_ENQCMD == UINT16_C(115),
    "ENQCMD group ID changed");
_Static_assert(CDISASM_X86_GROUP_APX_F_ENQCMD == UINT16_C(132),
    "APX_F_ENQCMD group ID changed");
_Static_assert(CDISASM_X86_DECODE_BIT_APX_F_ENQCMD == UINT32_C(80),
    "APX_F_ENQCMD decode bit changed");
_Static_assert(CDISASM_X86_DECODE_BIT_USER_MSR == UINT32_C(261),
    "USER_MSR decode bit changed");

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

static unsigned int effective_address_bits(
    cdisasm_x86_mode mode,
    int address_override)
{
    if (mode == CDISASM_MODE_16) {
        return address_override ? 32u : 16u;
    }
    if (mode == CDISASM_MODE_32) {
        return address_override ? 16u : 32u;
    }
    return address_override ? 32u : 64u;
}

/* Add a canonical payload that makes every memory ModRM control complete. */
static size_t append_address_payload(
    uint8_t *code,
    size_t size,
    unsigned int address_bits,
    uint8_t modrm,
    uint8_t *sib_size,
    uint8_t *displacement_size)
{
    const unsigned int mod = (unsigned int)(modrm >> 6);
    const unsigned int rm = (unsigned int)(modrm & UINT8_C(7));
    unsigned int bytes = 0u;

    *sib_size = 0u;
    *displacement_size = 0u;
    if (address_bits != 16u && rm == 4u) {
        /* No-index, stack-base SIB avoids the mod=0/base=5 special case. */
        code[size++] = UINT8_C(0x24);
        *sib_size = 1u;
    }
    if (mod == 0u
        && ((address_bits == 16u && rm == 6u)
            || (address_bits != 16u && rm == 5u))) {
        bytes = address_bits == 16u ? 2u : 4u;
    } else if (mod == 1u) {
        bytes = 1u;
    } else if (mod == 2u) {
        bytes = address_bits == 16u ? 2u : 4u;
    }
    while (bytes != 0u) {
        static const uint8_t displacement[4] = {
            UINT8_C(0x7f), UINT8_C(0x23), UINT8_C(0x45), UINT8_C(0x67)
        };
        unsigned int index = (unsigned int)*displacement_size;

        code[size++] = displacement[index];
        ++*displacement_size;
        --bytes;
    }
    return size;
}

#if USE_EXTRA_OPCODES
static cdisasm_x86_decode_flags one_bit(cdisasm_x86_decode_bit_id bit_id)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_decode_flags_set_bit(&flags, bit_id));
    return flags;
}

static cdisasm_x86_decode_flags system_flags(void)
{
    return one_bit(CDISASM_X86_DECODE_BIT_SYSTEM);
}

static cdisasm_x86_reg_id gpr_id(unsigned int index, unsigned int bits)
{
    if (bits == 16u) {
        return (cdisasm_x86_reg_id)(CDISASM_X86_REG_AX + index);
    }
    if (bits == 32u) {
        return (cdisasm_x86_reg_id)(CDISASM_X86_REG_EAX + index);
    }
    return (cdisasm_x86_reg_id)(CDISASM_X86_REG_RAX + index);
}

static void check_legacy_enq(
    const char *label,
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    size_t expected_size,
    cdisasm_x86_name_id name_id,
    unsigned int address_bits,
    unsigned int register_index,
    uint8_t modrm,
    uint8_t prefix_size,
    uint8_t sib_size,
    uint8_t displacement_size)
{
    const cdisasm_x86_form_id form_id = name_id == CDISASM_X86_NAME_ENQCMD
        ? UINT16_C(1144) : UINT16_C(1142);
    const int privileged = name_id == CDISASM_X86_NAME_ENQCMDS;

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
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_ENQCMD));
    EXPECT(((instruction->opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0u)
        == privileged);
    EXPECT((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0u);
    EXPECT((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS) == 0u);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
    EXPECT(instruction->operand_count == 2u);

    EXPECT(instruction->opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction->opcode[0].reg
        == gpr_id(register_index, address_bits));
    EXPECT(instruction->opcode[0].size == address_bits / 8u);
    EXPECT(instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[0].flags == CDISASM_OPERAND_FLAG_NONE);
    EXPECT(instruction->opcode[0].broadcast == CDISASM_X86_BROADCAST_NONE);

    EXPECT(instruction->opcode[1].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction->opcode[1].size == 64u);
    EXPECT(instruction->opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction->opcode[1].broadcast == CDISASM_X86_BROADCAST_NONE);

    EXPECT(instruction->encoding.prefix_size == prefix_size);
    EXPECT(instruction->encoding.opcode_offset == prefix_size);
    EXPECT(instruction->encoding.opcode_size == 3u);
    EXPECT(instruction->encoding.modrm_offset == prefix_size + 3u);
    EXPECT(instruction->encoding.modrm == modrm);
    EXPECT((instruction->encoding.sib_offset != 0u) == (sib_size != 0u));
    EXPECT(instruction->encoding.displacement_size == displacement_size);
    EXPECT(instruction->encoding.immediate_count == 0u);
}
#endif

static void test_exhaustive_legacy_memory_space(void)
{
    static const cdisasm_x86_mode modes[3] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t mode_index;
    unsigned int address_override;
    unsigned int operand_override;
    unsigned int operation;
    unsigned int modrm_value;
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags flags = system_flags();
#endif

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        for (address_override = 0u; address_override < 2u;
             ++address_override) {
            unsigned int address_bits = effective_address_bits(
                modes[mode_index], (int)address_override);

            for (operand_override = 0u; operand_override < 2u;
                 ++operand_override) {
                for (operation = 0u; operation < 2u; ++operation) {
                    for (modrm_value = 0u; modrm_value < UINT8_C(0xc0);
                         ++modrm_value) {
                        uint8_t code[15];
                        uint8_t sib_size;
                        uint8_t displacement_size;
                        size_t size = 0u;

                        if (address_override != 0u) {
                            code[size++] = UINT8_C(0x67);
                        }
                        if (operand_override != 0u) {
                            code[size++] = UINT8_C(0x66);
                        }
                        code[size++] = operation == 0u
                            ? UINT8_C(0xf2) : UINT8_C(0xf3);
                        code[size++] = UINT8_C(0x0f);
                        code[size++] = UINT8_C(0x38);
                        code[size++] = UINT8_C(0xf8);
                        code[size++] = (uint8_t)modrm_value;
                        size = append_address_payload(
                            code, size, address_bits, (uint8_t)modrm_value,
                            &sib_size, &displacement_size);
#if USE_EXTRA_OPCODES
                        {
                            uint32_t decoded_size;
                            cdisasm_instruction instruction = decode(
                                CDISASM_CPU_X86, modes[mode_index],
                                code, size, &flags, &decoded_size);

                            check_legacy_enq("exhaustive memory ModRM",
                                &instruction, decoded_size, size,
                                operation == 0u
                                    ? CDISASM_X86_NAME_ENQCMD
                                    : CDISASM_X86_NAME_ENQCMDS,
                                address_bits,
                                (modrm_value >> 3) & 7u,
                                (uint8_t)modrm_value,
                                (uint8_t)(1u + address_override
                                    + operand_override),
                                sib_size, displacement_size);
                            EXPECT(((instruction.opcode_flags
                                    & CDISASM_PREFIX_ADDRESS_SIZE) != 0u)
                                == (address_override != 0u));
                            EXPECT(((instruction.opcode_flags
                                    & CDISASM_PREFIX_OPERAND_SIZE) != 0u)
                                == (operand_override != 0u));
                            EXPECT((instruction.opcode_flags
                                    & (operation == 0u
                                        ? CDISASM_PREFIX_REPNE
                                        : CDISASM_PREFIX_REP)) != 0u);
                            EXPECT((instruction.opcode_flags
                                & CDISASM_PREFIX_EFFECTIVE_MASK) == 0u);
                        }
#else
                        expect_error("extras-off memory ModRM",
                            CDISASM_CPU_X86, modes[mode_index],
                            code, size, NULL,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
                    }
                }
            }
        }
    }
}

static void test_rex_wig_and_extensions(void)
{
    unsigned int operation;
    unsigned int rex_payload;

    for (operation = 0u; operation < 2u; ++operation) {
        for (rex_payload = 0u; rex_payload < 16u; ++rex_payload) {
            uint8_t code[9] = {
                operation == 0u ? UINT8_C(0xf2) : UINT8_C(0xf3),
                (uint8_t)(UINT8_C(0x40) | rex_payload),
                UINT8_C(0x0f), UINT8_C(0x38), UINT8_C(0xf8),
                UINT8_C(0x44), UINT8_C(0x88), UINT8_C(0x7f), UINT8_C(0)
            };
#if USE_EXTRA_OPCODES
            cdisasm_x86_decode_flags flags = system_flags();
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64,
                code, 8u, &flags, &decoded_size);

            check_legacy_enq("REX WIG/RXB sweep", &instruction,
                decoded_size, 8u,
                operation == 0u
                    ? CDISASM_X86_NAME_ENQCMD : CDISASM_X86_NAME_ENQCMDS,
                64u, (rex_payload & 4u) != 0u ? 8u : 0u,
                UINT8_C(0x44), 2u, 1u, 1u);
            EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REX) != 0u);
            EXPECT(((instruction.opcode_flags & CDISASM_PREFIX_REX_W) != 0u)
                == ((rex_payload & 8u) != 0u));
            EXPECT(instruction.opcode[1].base_reg
                == gpr_id((rex_payload & 1u) != 0u ? 8u : 0u, 64u));
            EXPECT(instruction.opcode[1].index_reg
                == gpr_id((rex_payload & 2u) != 0u ? 9u : 1u, 64u));
            EXPECT(instruction.opcode[1].scale == 4u);
#else
            expect_error("extras-off REX sweep", CDISASM_CPU_X86,
                CDISASM_MODE_64, code, 8u, NULL,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
        }
    }
}

static void test_user_msr_and_apx_collisions(void)
{
#if USE_EXTRA_OPCODES
    cdisasm_x86_decode_flags user = one_bit(
        CDISASM_X86_DECODE_BIT_USER_MSR);
    cdisasm_x86_decode_flags system = system_flags();
    unsigned int address_override;
    unsigned int operand_override;
    unsigned int operation;
    unsigned int modrm_value;

    for (address_override = 0u; address_override < 2u;
         ++address_override) {
        for (operand_override = 0u; operand_override < 2u;
             ++operand_override) {
            for (operation = 0u; operation < 2u; ++operation) {
                for (modrm_value = UINT8_C(0xc0); modrm_value <= UINT8_MAX;
                     ++modrm_value) {
                    uint8_t code[8];
                    size_t size = 0u;
                    uint32_t decoded_size;
                    cdisasm_instruction instruction;

                    if (address_override != 0u) {
                        code[size++] = UINT8_C(0x67);
                    }
                    if (operand_override != 0u) {
                        code[size++] = UINT8_C(0x66);
                    }
                    code[size++] = operation == 0u
                        ? UINT8_C(0xf2) : UINT8_C(0xf3);
                    code[size++] = UINT8_C(0x0f);
                    code[size++] = UINT8_C(0x38);
                    code[size++] = UINT8_C(0xf8);
                    code[size++] = (uint8_t)modrm_value;
                    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                        code, size, &user, &decoded_size);
                    EXPECT(decoded_size == size);
                    EXPECT(instruction.name_id == (operation == 0u
                        ? CDISASM_X86_NAME_URDMSR
                        : CDISASM_X86_NAME_UWRMSR));
                    EXPECT(instruction.form_id == (operation == 0u
                        ? UINT16_C(3353) : UINT16_C(3357)));
                    EXPECT(cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_USER_MSR));
                    EXPECT(!cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_ENQCMD));

                    expect_error("register half needs USER_MSR selector",
                        CDISASM_CPU_X86, CDISASM_MODE_64,
                        code, size, &system,
                        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
                }
            }
        }
    }

    {
        static const struct apx_case {
            uint8_t code[6];
            cdisasm_x86_name_id name_id;
            cdisasm_x86_form_id form_id;
            cdisasm_x86_decode_bit_id bit_id;
            cdisasm_x86_group_id group_id;
            int generated;
        } cases[] = {
            {{0x62, 0xf4, 0x7f, 0x08, 0xf8, 0xd8},
             CDISASM_X86_NAME_URDMSR, UINT16_C(3354),
             CDISASM_X86_DECODE_BIT_APX_F_USER_MSR,
             CDISASM_X86_GROUP_APX_F_USER_MSR, 0},
            {{0x62, 0xf4, 0x7e, 0x08, 0xf8, 0xd8},
             CDISASM_X86_NAME_UWRMSR, UINT16_C(3358),
             CDISASM_X86_DECODE_BIT_APX_F_USER_MSR,
             CDISASM_X86_GROUP_APX_F_USER_MSR, 0},
            {{0x62, 0xf4, 0x7f, 0x08, 0xf8, 0x18},
             CDISASM_X86_NAME_ENQCMD, UINT16_C(1145),
             CDISASM_X86_DECODE_BIT_APX_F_ENQCMD,
             CDISASM_X86_GROUP_APX_F_ENQCMD, 1},
            {{0x62, 0xf4, 0x7e, 0x08, 0xf8, 0x18},
             CDISASM_X86_NAME_ENQCMDS, UINT16_C(1143),
             CDISASM_X86_DECODE_BIT_APX_F_ENQCMD,
             CDISASM_X86_GROUP_APX_F_ENQCMD, 1}
        };
        size_t index;

        for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
            cdisasm_x86_decode_flags flags = one_bit(cases[index].bit_id);
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(
                CDISASM_CPU_X86, CDISASM_MODE_64,
                cases[index].code, sizeof(cases[index].code),
                &flags, &decoded_size);

            EXPECT(decoded_size == sizeof(cases[index].code));
            EXPECT(instruction.name_id == cases[index].name_id);
            EXPECT(instruction.form_id == cases[index].form_id);
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction, cases[index].group_id));
            EXPECT(((instruction.opcode_flags
                    & CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u)
                == cases[index].generated);
            if (cases[index].name_id == CDISASM_X86_NAME_ENQCMD
                || cases[index].name_id == CDISASM_X86_NAME_ENQCMDS) {
                EXPECT((instruction.opcode_flags
                    & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)
                    != 0u);
                EXPECT(instruction.opcode[1].type
                    == CDISASM_OPERAND_MEMORY);
            } else {
                EXPECT(instruction.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
            }
        }
    }
#else
    static const uint8_t legacy_register[] = {
        0x66, 0xf2, 0x0f, 0x38, 0xf8, 0xd8
    };
    static const uint8_t apx_register[] = {
        0x62, 0xf4, 0x7f, 0x08, 0xf8, 0xd8
    };
    static const uint8_t apx_memory[] = {
        0x62, 0xf4, 0x7f, 0x08, 0xf8, 0x18
    };

    expect_error("USER_MSR extras-off collision", CDISASM_CPU_X86,
        CDISASM_MODE_64, legacy_register, sizeof(legacy_register), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("APX USER_MSR extras-off collision", CDISASM_CPU_X86,
        CDISASM_MODE_64, apx_register, sizeof(apx_register), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("APX ENQCMD extras-off collision", CDISASM_CPU_X86,
        CDISASM_MODE_64, apx_memory, sizeof(apx_memory), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_cpu_runtime_and_malformed_boundaries(void)
{
    static const uint8_t enqcmd[] = {0xf2, 0x0f, 0x38, 0xf8, 0x00};
    static const uint8_t enqcmds[] = {0xf3, 0x0f, 0x38, 0xf8, 0x00};
    static const uint8_t osz_enqcmd[] = {
        0x66, 0xf2, 0x0f, 0x38, 0xf8, 0x00
    };
    static const uint8_t lock_enqcmd[] = {
        0xf0, 0xf2, 0x0f, 0x38, 0xf8, 0x00
    };
    static const uint8_t rex2_enqcmd[] = {
        0xf2, 0xd5, 0x80, 0x0f, 0x38, 0xf8, 0x00
    };
    static const uint8_t register_mode32[] = {
        0xf2, 0x0f, 0x38, 0xf8, 0xc0
    };
    static const uint8_t no_selector[] = {0x0f, 0x38, 0xf8, 0x00};
    static const uint8_t truncated_modrm[] = {0xf2, 0x0f, 0x38, 0xf8};
    static const uint8_t truncated_displacement[] = {
        0xf2, 0x0f, 0x38, 0xf8, 0x80
    };
#if USE_EXTRA_OPCODES
    static const cdisasm_x86_cpu_id supported[] = {
        CDISASM_CPU_SAPPHIRE_RAPIDS,
        CDISASM_CPU_GRANITE_RAPIDS,
        CDISASM_CPU_DIAMOND_RAPIDS
    };
    static const cdisasm_x86_cpu_id unsupported[] = {
        CDISASM_CPU_TIGER_LAKE,
        CDISASM_CPU_ALDER_LAKE,
        CDISASM_CPU_ARROW_LAKE,
        CDISASM_CPU_APX
    };
    cdisasm_x86_decode_flags flags = system_flags();
    size_t index;

    expect_error("ENQCMD needs SYSTEM", CDISASM_CPU_X86,
        CDISASM_MODE_64, enqcmd, sizeof(enqcmd), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    for (index = 0u; index < sizeof(supported) / sizeof(supported[0]);
         ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            supported[index], CDISASM_MODE_64,
            enqcmd, sizeof(enqcmd), &flags, &decoded_size);

        check_legacy_enq("supported named profile", &instruction,
            decoded_size, sizeof(enqcmd), CDISASM_X86_NAME_ENQCMD,
            64u, 0u, UINT8_C(0x00), 1u, 0u, 0u);
    }
    for (index = 0u; index < sizeof(unsupported) / sizeof(unsupported[0]);
         ++index) {
        expect_error("unsupported named profile", unsupported[index],
            CDISASM_MODE_64, enqcmd, sizeof(enqcmd), &flags,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, CDISASM_MODE_64,
            osz_enqcmd, sizeof(osz_enqcmd), &flags, &decoded_size);

        check_legacy_enq("ignored operand-size override", &instruction,
            decoded_size, sizeof(osz_enqcmd), CDISASM_X86_NAME_ENQCMD,
            64u, 0u, UINT8_C(0x00), 2u, 0u, 0u);
    }
#else
    expect_error("ENQCMD extras-off", CDISASM_CPU_X86,
        CDISASM_MODE_64, enqcmd, sizeof(enqcmd), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("ENQCMDS extras-off", CDISASM_CPU_X86,
        CDISASM_MODE_64, enqcmds, sizeof(enqcmds), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("OSZ ENQCMD extras-off", CDISASM_CPU_X86,
        CDISASM_MODE_64, osz_enqcmd, sizeof(osz_enqcmd), NULL,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif

    expect_error("LOCK is invalid", CDISASM_CPU_X86, CDISASM_MODE_64,
        lock_enqcmd, sizeof(lock_enqcmd),
#if USE_EXTRA_OPCODES
        &flags,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("REX2 is not legacy ENQCMD", CDISASM_CPU_X86,
        CDISASM_MODE_64, rex2_enqcmd, sizeof(rex2_enqcmd),
#if USE_EXTRA_OPCODES
        &flags,
#else
        NULL,
#endif
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("register half is invalid outside 64-bit mode",
        CDISASM_CPU_X86, CDISASM_MODE_32,
        register_mode32, sizeof(register_mode32),
#if USE_EXTRA_OPCODES
        &flags,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("missing mandatory selector", CDISASM_CPU_X86,
        CDISASM_MODE_64, no_selector, sizeof(no_selector),
#if USE_EXTRA_OPCODES
        &flags,
#else
        NULL,
#endif
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("truncated ModRM", CDISASM_CPU_X86, CDISASM_MODE_64,
        truncated_modrm, sizeof(truncated_modrm),
#if USE_EXTRA_OPCODES
        &flags,
#else
        NULL,
#endif
        CDISASM_STATUS_TRUNCATED);
    expect_error("truncated displacement", CDISASM_CPU_X86,
        CDISASM_MODE_64,
        truncated_displacement, sizeof(truncated_displacement),
#if USE_EXTRA_OPCODES
        &flags,
#else
        NULL,
#endif
        CDISASM_STATUS_TRUNCATED);

    (void)enqcmds;
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_text(
    const cdisasm_instruction *instruction,
    uint32_t syntax,
    const char *expected)
{
    char text[128];
    size_t required = cdisasm_x86_format(
        instruction, syntax, text, sizeof(text));

    if (required != strlen(expected) || strcmp(text, expected) != 0) {
        fprintf(stderr, "format: got %zu/'%s', expected %zu/'%s'\n",
            required, text, strlen(expected), expected);
    }
    EXPECT(required == strlen(expected));
    EXPECT(strcmp(text, expected) == 0);
}

static void test_formatting(void)
{
    static const struct format_case {
        cdisasm_x86_mode mode;
        uint8_t code[9];
        uint8_t size;
        const char *intel;
        const char *att;
    } cases[] = {
        {CDISASM_MODE_16, {0xf2, 0x0f, 0x38, 0xf8, 0x00}, 5,
         "enqcmd ax, zmmword ptr [bx + si]", "enqcmd (%bx,%si), %ax"},
        {CDISASM_MODE_32, {0x67, 0xf3, 0x0f, 0x38, 0xf8, 0x00}, 6,
         "enqcmds ax, zmmword ptr [bx + si]",
         "enqcmds (%bx,%si), %ax"},
        {CDISASM_MODE_64,
         {0x66, 0xf2, 0x4f, 0x0f, 0x38, 0xf8, 0x44, 0x88, 0x7f}, 9,
         "enqcmd r8, zmmword ptr [r8 + r9*4 + 0x7f]",
         "enqcmd 0x7f(%r8,%r9,4), %r8"}
    };
    cdisasm_x86_decode_flags flags = system_flags();
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, cases[index].mode,
            cases[index].code, cases[index].size,
            &flags, &decoded_size);

        EXPECT(decoded_size == cases[index].size);
        expect_text(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
            cases[index].intel);
        expect_text(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
            cases[index].att);
    }
}
#endif

int main(void)
{
    test_exhaustive_legacy_memory_space();
    test_rex_wig_and_extensions();
    test_user_msr_and_apx_collisions();
    test_cpu_runtime_and_malformed_boundaries();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_formatting();
#endif
    if (failures != 0) {
        fprintf(stderr, "%d ENQCMD test(s) failed\n", failures);
    }
    return failures != 0;
}
