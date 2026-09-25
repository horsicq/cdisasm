#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_ARM_NAME_TRN2 == UINT16_C(353),
               "established ARM mnemonic IDs moved");
_Static_assert(CDISASM_ARM_NAME_TBL == UINT16_C(354),
               "SVE table IDs must be append-only");
_Static_assert(CDISASM_ARM_NAME_TBXQ == UINT16_C(356),
               "established SVE table ID moved");
_Static_assert(CDISASM_ARM_NAME_TBLQ == UINT16_C(357),
               "SVE2.1 TBLQ ID must be append-only");
_Static_assert(CDISASM_ARM_NAME_COUNT >= UINT16_C(421),
               "SVE table name count changed");
_Static_assert(CDISASM_ARM_NAME_COUNT == CDISASM_ARM_NAME_LAST + 1u,
               "ARM mnemonic IDs must remain contiguous");

#if USE_EXTRA_OPCODES
typedef struct table_operation {
    cdisasm_arm_name_id name_id;
    const char *mnemonic;
    uint8_t list_count;
    cdisasm_operand_access destination_access;
} table_operation;

static const table_operation table_operations[4] = {
    { CDISASM_ARM_NAME_TBL, "tbl", UINT8_C(2),
      CDISASM_OPERAND_ACCESS_WRITE },
    { CDISASM_ARM_NAME_TBX, "tbx", UINT8_C(0),
      CDISASM_OPERAND_ACCESS_READ_WRITE },
    { CDISASM_ARM_NAME_TBL, "tbl", UINT8_C(1),
      CDISASM_OPERAND_ACCESS_WRITE },
    { CDISASM_ARM_NAME_TBXQ, "tbxq", UINT8_C(0),
      CDISASM_OPERAND_ACCESS_READ_WRITE }
};
#endif

static int failures;

#define EXPECT(condition) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "%s:%d: expectation failed: %s\n", \
                    __FILE__, __LINE__, #condition); \
            ++failures; \
        } \
    } while (0)

static uint32_t table_word(
    unsigned selector, unsigned size_code,
    unsigned zd, unsigned zn, unsigned zm)
{
    return UINT32_C(0x05200000)
        | ((uint32_t)size_code << 22)
        | ((uint32_t)selector << 10)
        | ((uint32_t)zm << 16)
        | ((uint32_t)zn << 5)
        | (uint32_t)zd;
}

static uint32_t dup_word(
    unsigned imm2, unsigned tsz, unsigned zd, unsigned zn)
{
    return UINT32_C(0x05202000)
        | ((uint32_t)(imm2 & 3u) << 22)
        | ((uint32_t)(tsz & 31u) << 16)
        | ((uint32_t)(zn & 31u) << 5)
        | (uint32_t)(zd & 31u);
}

#if USE_EXTRA_OPCODES
static uint8_t dup_element_size(unsigned tsz)
{
    uint8_t size = 1u;

    while ((tsz & 1u) == 0u) {
        size = (uint8_t)(size << 1);
        tsz >>= 1;
    }
    return size;
}

static unsigned dup_lane_index(unsigned imm2, unsigned tsz)
{
    unsigned shift = 1u;
    unsigned combined = ((imm2 & 3u) << 5) | (tsz & 31u);

    while ((tsz & 1u) == 0u) {
        ++shift;
        tsz >>= 1;
    }
    return combined >> shift;
}
#endif

static void word_to_le(uint32_t word, uint8_t bytes[4])
{
    bytes[0] = (uint8_t)word;
    bytes[1] = (uint8_t)(word >> 8);
    bytes[2] = (uint8_t)(word >> 16);
    bytes[3] = (uint8_t)(word >> 24);
}

static void word_to_be(uint32_t word, uint8_t bytes[4])
{
    bytes[0] = (uint8_t)(word >> 24);
    bytes[1] = (uint8_t)(word >> 16);
    bytes[2] = (uint8_t)(word >> 8);
    bytes[3] = (uint8_t)word;
}

static int instruction_is_error_only(
    const cdisasm_arm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static uint32_t decode_word(
    uint32_t word,
    cdisasm_arm_cpu_id cpu_id,
    cdisasm_arm_mode mode,
    cdisasm_arm_decode_option options,
    size_t code_size,
    cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(
        cpu_id, mode, bytes, code_size, UINT64_C(0x7000), options,
        instruction);
}

static int selector14_is_unpack(unsigned zm)
{
    return zm >= 16u && zm <= 19u;
}

#if USE_EXTRA_OPCODES
static void expect_z_operand(
    const cdisasm_arm_operand *operand,
    unsigned encoded,
    uint8_t element_size,
    cdisasm_operand_access access)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + encoded);
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.access = access;
    EXPECT(memcmp(operand, &expected, sizeof(expected)) == 0);
}

static void expect_zlist_operand(
    const cdisasm_arm_operand *operand,
    unsigned encoded,
    uint8_t element_size,
    uint8_t count)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    expected.type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST;
    expected.reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + encoded);
    expected.register_list = (uint16_t)(UINT16_C(0x0100) | count);
    expected.extend_type = (cdisasm_arm_extend_type)element_size;
    expected.access = CDISASM_OPERAND_ACCESS_READ;
    EXPECT(memcmp(operand, &expected, sizeof(expected)) == 0);
}

static void expect_success(
    cdisasm_arm_cpu_id cpu_id,
    unsigned selector,
    unsigned size_code,
    unsigned zd,
    unsigned zn,
    unsigned zm)
{
#if USE_DISASM_FORMAT
    static const char element_suffixes[4] = { 'b', 'h', 's', 'd' };
#endif
    const table_operation *operation = &table_operations[selector - 10u];
    cdisasm_arm_instruction instruction;
    uint32_t word = table_word(selector, size_code, zd, zn, zm);
    uint8_t element_size = (uint8_t)(UINT32_C(1) << size_code);

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        word, cpu_id, CDISASM_ARM_MODE_A64,
        CDISASM_ARM_DECODE_OPTION_NONE, 4u, &instruction) == 4u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == operation->name_id);
    EXPECT(instruction.address == UINT64_C(0x7000));
    EXPECT(instruction.raw_instruction == word);
    EXPECT(instruction.opcode_size == 4u);
    EXPECT(instruction.opcode_groups == CDISASM_GROUP_NONE);
    EXPECT(instruction.isa_id == CDISASM_ARM_ISA_A64);
    EXPECT(instruction.condition == CDISASM_ARM_CONDITION_AL);
    EXPECT(instruction.operand_count == 3u);
    EXPECT(instruction.instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    expect_z_operand(
        &instruction.operand[0], zd, element_size,
        operation->destination_access);
    if (operation->list_count != 0u) {
        expect_zlist_operand(
            &instruction.operand[1], zn, element_size,
            operation->list_count);
    } else {
        expect_z_operand(
            &instruction.operand[1], zn, element_size,
            CDISASM_OPERAND_ACCESS_READ);
    }
    expect_z_operand(
        &instruction.operand[2], zm, element_size,
        CDISASM_OPERAND_ACCESS_READ);

#if USE_DISASM_FORMAT
    {
        char expected[128];
        char text[128];
        int expected_size;
        char suffix = element_suffixes[size_code];

        if (operation->list_count == 2u) {
            expected_size = snprintf(
                expected, sizeof(expected),
                "%s z%u.%c, {z%u.%c, z%u.%c}, z%u.%c",
                operation->mnemonic, zd, suffix, zn, suffix,
                (zn + 1u) & 31u, suffix, zm, suffix);
        } else if (operation->list_count == 1u) {
            expected_size = snprintf(
                expected, sizeof(expected),
                "%s z%u.%c, {z%u.%c}, z%u.%c",
                operation->mnemonic, zd, suffix, zn, suffix, zm, suffix);
        } else {
            expected_size = snprintf(
                expected, sizeof(expected), "%s z%u.%c, z%u.%c, z%u.%c",
                operation->mnemonic, zd, suffix, zn, suffix, zm, suffix);
        }
        EXPECT(expected_size > 0);
        EXPECT((size_t)expected_size < sizeof(expected));
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            text, sizeof(text)) == (size_t)expected_size);
        EXPECT(strcmp(text, expected) == 0);
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            NULL, 0u) == (size_t)expected_size);
    }
#endif
}

static void expect_mov_success(
    cdisasm_arm_cpu_id cpu_id,
    unsigned size_code,
    unsigned zd,
    unsigned rn)
{
#if USE_DISASM_FORMAT
    static const char element_suffixes[4] = { 'b', 'h', 's', 'd' };
#endif
    cdisasm_arm_instruction instruction;
    cdisasm_arm_operand expected_source;
    uint32_t word = table_word(14u, size_code, zd, rn, 0u);
    uint8_t element_size = (uint8_t)(UINT32_C(1) << size_code);
    int is_64 = size_code == 3u;

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(
        word, cpu_id, CDISASM_ARM_MODE_A64,
        CDISASM_ARM_DECODE_OPTION_NONE, 4u, &instruction) == 4u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_ARM_NAME_MOV);
    EXPECT(instruction.address == UINT64_C(0x7000));
    EXPECT(instruction.raw_instruction == word);
    EXPECT(instruction.opcode_size == 4u);
    EXPECT(instruction.opcode_groups == CDISASM_GROUP_NONE);
    EXPECT(instruction.isa_id == CDISASM_ARM_ISA_A64);
    EXPECT(instruction.condition == CDISASM_ARM_CONDITION_AL);
    EXPECT(instruction.operand_count == 2u);
    EXPECT(instruction.instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
    expect_z_operand(
        &instruction.operand[0], zd, element_size,
        CDISASM_OPERAND_ACCESS_WRITE);

    memset(&expected_source, 0, sizeof(expected_source));
    expected_source.type = CDISASM_OPERAND_REGISTER;
    if (rn == 31u) {
        expected_source.reg = is_64
            ? CDISASM_ARM_REG_SP : CDISASM_ARM_REG_WSP;
    } else {
        expected_source.reg = (cdisasm_arm_reg_id)(
            (is_64 ? CDISASM_ARM_REG_X0 : CDISASM_ARM_REG_W0) + rn);
    }
    expected_source.size = is_64 ? 8u : 4u;
    expected_source.access = CDISASM_OPERAND_ACCESS_READ;
    EXPECT(memcmp(
        &instruction.operand[1], &expected_source,
        sizeof(expected_source)) == 0);

#if USE_DISASM_FORMAT
    {
        char expected[64];
        char text[64];
        const char *source_prefix = is_64 ? "x" : "w";
        int expected_size;

        if (rn == 31u) {
            expected_size = snprintf(
                expected, sizeof(expected), "mov z%u.%c, %s",
                zd, element_suffixes[size_code], is_64 ? "sp" : "wsp");
        } else {
            expected_size = snprintf(
                expected, sizeof(expected), "mov z%u.%c, %s%u",
                zd, element_suffixes[size_code], source_prefix, rn);
        }
        EXPECT(expected_size > 0);
        EXPECT((size_t)expected_size < sizeof(expected));
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            text, sizeof(text)) == (size_t)expected_size);
        EXPECT(strcmp(text, expected) == 0);
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            NULL, 0u) == (size_t)expected_size);
    }
#endif
}

static int selector14_is_unsupported(unsigned size_code, unsigned zm)
{
    return zm == 10u || zm == 12u
        || zm == 20u
        || (zm == 14u && size_code <= 1u)
        || (zm == 8u && size_code >= 1u);
}

static void expect_selector14_success(
    const cdisasm_arm_instruction *instruction, uint32_t word,
    unsigned size_code, unsigned zm)
{
    uint8_t element_size = (uint8_t)(UINT32_C(1) << size_code);
    unsigned zd = (size_code + zm) & 31u;
    unsigned zn = (size_code + zm + 7u) & 31u;

    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->address == UINT64_C(0x7000));
    EXPECT(instruction->raw_instruction == word);
    EXPECT(instruction->opcode_size == 4u);
    EXPECT(instruction->opcode_groups == CDISASM_GROUP_NONE);
    EXPECT(instruction->isa_id == CDISASM_ARM_ISA_A64);
    EXPECT(instruction->condition == CDISASM_ARM_CONDITION_AL);
    EXPECT(instruction->operand_count == 2u);

    if (selector14_is_unpack(zm)) {
        static const cdisasm_arm_name_id names[4] = {
            CDISASM_ARM_NAME_SUNPKLO,
            CDISASM_ARM_NAME_SUNPKHI,
            CDISASM_ARM_NAME_UUNPKLO,
            CDISASM_ARM_NAME_UUNPKHI
        };
        unsigned control = zm & 3u;

        EXPECT(size_code != 0u);
        EXPECT(instruction->name_id == names[control]);
        EXPECT(instruction->form_id == (cdisasm_arm_form_id)(
            UINT16_C(2456) + control));
        EXPECT(instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
        expect_z_operand(
            &instruction->operand[0], zd, element_size,
            CDISASM_OPERAND_ACCESS_WRITE);
        expect_z_operand(
            &instruction->operand[1], zn,
            (uint8_t)(element_size / 2u),
            CDISASM_OPERAND_ACCESS_READ);
    } else if (zm == 4u) {
        cdisasm_arm_operand expected_source;

        EXPECT(instruction->name_id == CDISASM_ARM_NAME_INSR);
        EXPECT(instruction->form_id == UINT16_C(2447));
        EXPECT(instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
        expect_z_operand(
            &instruction->operand[0], zd, element_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE);
        memset(&expected_source, 0, sizeof(expected_source));
        expected_source.type = CDISASM_OPERAND_REGISTER;
        expected_source.reg = (cdisasm_arm_reg_id)(
            (size_code == 3u ? CDISASM_ARM_REG_X0 : CDISASM_ARM_REG_W0)
            + zn);
        expected_source.size = size_code == 3u ? 8u : 4u;
        expected_source.access = CDISASM_OPERAND_ACCESS_READ;
        EXPECT(memcmp(
            &instruction->operand[1], &expected_source,
            sizeof(expected_source)) == 0);
    } else if (zm == 20u) {
        static const cdisasm_arm_reg_id scalar_bases[4] = {
            CDISASM_ARM_REG_B0, CDISASM_ARM_REG_H0,
            CDISASM_ARM_REG_S0, CDISASM_ARM_REG_D0
        };
        cdisasm_arm_operand expected_source;

        EXPECT(instruction->name_id == CDISASM_ARM_NAME_INSR);
        EXPECT(instruction->form_id == UINT16_C(2460));
        EXPECT(instruction->instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
        expect_z_operand(
            &instruction->operand[0], zd, element_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE);
        memset(&expected_source, 0, sizeof(expected_source));
        expected_source.type = CDISASM_OPERAND_REGISTER;
        expected_source.reg = (cdisasm_arm_reg_id)(
            scalar_bases[size_code] + zn);
        expected_source.size = element_size;
        expected_source.access = CDISASM_OPERAND_ACCESS_READ;
        EXPECT(memcmp(
            &instruction->operand[1], &expected_source,
            sizeof(expected_source)) == 0);
    } else {
        EXPECT(zm == 24u);
        EXPECT(instruction->name_id == CDISASM_ARM_NAME_REV);
        EXPECT(instruction->form_id == UINT16_C(2461));
        EXPECT(instruction->instruction_flags
            == (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                | CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK));
        expect_z_operand(
            &instruction->operand[0], zd, element_size,
            CDISASM_OPERAND_ACCESS_WRITE);
        expect_z_operand(
            &instruction->operand[1], zn, element_size,
            CDISASM_OPERAND_ACCESS_READ);
    }
}

static cdisasm_arm_reg_id dup_scalar_register(
    unsigned encoded, uint8_t element_size)
{
    if (element_size == 1u) {
        return (cdisasm_arm_reg_id)(CDISASM_ARM_REG_B0 + encoded);
    }
    if (element_size == 2u) {
        return (cdisasm_arm_reg_id)(CDISASM_ARM_REG_H0 + encoded);
    }
    if (element_size == 4u) {
        return (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0 + encoded);
    }
    if (element_size == 8u) {
        return (cdisasm_arm_reg_id)(CDISASM_ARM_REG_D0 + encoded);
    }
    return (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + encoded);
}

static void expect_dup_metadata(
    const cdisasm_arm_instruction *instruction,
    uint32_t word, unsigned imm2, unsigned tsz,
    unsigned zd, unsigned zn)
{
    cdisasm_arm_instruction expected;
    uint8_t element_size = dup_element_size(tsz);
    unsigned lane_index = dup_lane_index(imm2, tsz);

    memset(&expected, 0, sizeof(expected));
    expected.address = UINT64_C(0x7000);
    expected.opcode_size = 4u;
    expected.raw_instruction = word;
    expected.instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR;
    expected.name_id = CDISASM_ARM_NAME_MOV;
    expected.operand_count = 2u;
    expected.condition = CDISASM_ARM_CONDITION_AL;
    expected.isa_id = CDISASM_ARM_ISA_A64;
    expected.form_id = UINT16_C(2439);
    expected.operand[0].type =
        CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    expected.operand[0].reg =
        (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zd);
    expected.operand[0].extend_type =
        (cdisasm_arm_extend_type)element_size;
    expected.operand[0].access = CDISASM_OPERAND_ACCESS_WRITE;
    if (lane_index == 0u) {
        expected.operand[1].type = CDISASM_OPERAND_REGISTER;
        expected.operand[1].reg =
            dup_scalar_register(zn, element_size);
        expected.operand[1].size = element_size;
        expected.operand[1].access = CDISASM_OPERAND_ACCESS_READ;
    } else {
        expected.operand[1].type =
            CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
        expected.operand[1].reg =
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + zn);
        expected.operand[1].imm = lane_index;
        expected.operand[1].flags =
            CDISASM_ARM_OPERAND_FLAG_HAS_LANE;
        expected.operand[1].extend_type =
            (cdisasm_arm_extend_type)element_size;
        expected.operand[1].access = CDISASM_OPERAND_ACCESS_READ;
    }
    EXPECT(memcmp(instruction, &expected, sizeof(expected)) == 0);
}
#endif

static void test_dup_selector_domain(void)
{
    uint32_t allocated = 0u;
    uint32_t reserved = 0u;
    unsigned imm2;

    /* Exhaust imm2, tsz, both five-bit register fields, and the tsz=0
     * reserved row.  The lowest set tsz bit selects B/H/S/D/Q; all higher
     * bits, together with imm2, are the architectural lane index. */
    for (imm2 = 0u; imm2 < 4u; ++imm2) {
        unsigned tsz;

        for (tsz = 0u; tsz < 32u; ++tsz) {
            unsigned zd;

            for (zd = 0u; zd < 32u; ++zd) {
                unsigned zn;

                for (zn = 0u; zn < 32u; ++zn) {
                    cdisasm_arm_instruction instruction;
                    uint32_t word = dup_word(imm2, tsz, zd, zn);
                    uint32_t decoded;

                    EXPECT((word & UINT32_C(0xff20fc00))
                        == UINT32_C(0x05202000));
                    memset(&instruction, 0xa5, sizeof(instruction));
                    decoded = decode_word(
                        word, CDISASM_ARM_CPU_ANY,
                        CDISASM_ARM_MODE_A64,
                        CDISASM_ARM_DECODE_OPTION_NONE, 4u,
                        &instruction);
                    if (tsz == 0u) {
                        ++reserved;
                        EXPECT(decoded == 0u);
                        EXPECT(instruction_is_error_only(
                            &instruction,
                            CDISASM_STATUS_INVALID_INSTRUCTION));
                    } else {
                        ++allocated;
#if USE_EXTRA_OPCODES
                        EXPECT(decoded == 4u);
                        expect_dup_metadata(
                            &instruction, word, imm2, tsz, zd, zn);
#else
                        EXPECT(decoded == 0u);
                        EXPECT(instruction_is_error_only(
                            &instruction,
                            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
                    }
                }
            }
        }
    }
    EXPECT(allocated == UINT32_C(126976));
    EXPECT(reserved == UINT32_C(4096));
}

static void expect_profile_result(
    cdisasm_arm_cpu_id cpu_id,
    unsigned selector,
    int supported)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    if (supported) {
        EXPECT(decode_word(
            table_word(selector, 2u, 1u, 2u, 3u),
            cpu_id, CDISASM_ARM_MODE_A64,
            CDISASM_ARM_DECODE_OPTION_NONE, 4u, &instruction) == 4u);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    } else {
        EXPECT(decode_word(
            table_word(selector, 2u, 1u, 2u, 3u),
            cpu_id, CDISASM_ARM_MODE_A64,
            CDISASM_ARM_DECODE_OPTION_NONE, 4u, &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
    }
#else
    (void)supported;
    EXPECT(decode_word(
        table_word(selector, 2u, 1u, 2u, 3u),
        cpu_id, CDISASM_ARM_MODE_A64,
        CDISASM_ARM_DECODE_OPTION_NONE, 4u, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void expect_mov_profile_result(
    cdisasm_arm_cpu_id cpu_id,
    int supported)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    if (supported) {
        EXPECT(decode_word(
            table_word(14u, 2u, 1u, 2u, 0u),
            cpu_id, CDISASM_ARM_MODE_A64,
            CDISASM_ARM_DECODE_OPTION_NONE, 4u, &instruction) == 4u);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_MOV);
    } else {
        EXPECT(decode_word(
            table_word(14u, 2u, 1u, 2u, 0u),
            cpu_id, CDISASM_ARM_MODE_A64,
            CDISASM_ARM_DECODE_OPTION_NONE, 4u, &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
    }
#else
    (void)supported;
    EXPECT(decode_word(
        table_word(14u, 2u, 1u, 2u, 0u),
        cpu_id, CDISASM_ARM_MODE_A64,
        CDISASM_ARM_DECODE_OPTION_NONE, 4u, &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void expect_dup_profile_result(
    cdisasm_arm_cpu_id cpu_id, int supported)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
    if (supported) {
        EXPECT(decode_word(
            dup_word(3u, 16u, 31u, 31u), cpu_id,
            CDISASM_ARM_MODE_A64,
            CDISASM_ARM_DECODE_OPTION_NONE, 4u,
            &instruction) == 4u);
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_MOV);
        EXPECT(instruction.form_id == UINT16_C(2439));
    } else {
        EXPECT(decode_word(
            dup_word(3u, 16u, 31u, 31u), cpu_id,
            CDISASM_ARM_MODE_A64,
            CDISASM_ARM_DECODE_OPTION_NONE, 4u,
            &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
    }
#else
    (void)supported;
    EXPECT(decode_word(
        dup_word(3u, 16u, 31u, 31u), cpu_id,
        CDISASM_ARM_MODE_A64,
        CDISASM_ARM_DECODE_OPTION_NONE, 4u,
        &instruction) == 0u);
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_allocated_and_adjacent_selectors(void)
{
    unsigned selector;

    for (selector = 10u; selector < 14u; ++selector) {
        unsigned size_code;

        for (size_code = 0u; size_code < 4u; ++size_code) {
            unsigned zd = (selector + size_code) & 31u;
            unsigned zn = (selector + size_code + 9u) & 31u;
            unsigned zm = (selector + size_code + 19u) & 31u;
#if USE_EXTRA_OPCODES
            expect_success(
                CDISASM_ARM_CPU_ANY, selector, size_code, zd, zn, zm);
#else
            cdisasm_arm_instruction instruction;

            memset(&instruction, 0xa5, sizeof(instruction));
            EXPECT(decode_word(
                table_word(selector, size_code, zd, zn, zm),
                CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                CDISASM_ARM_DECODE_OPTION_NONE, 4u,
                &instruction) == 0u);
            EXPECT(instruction_is_error_only(
                &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        }
    }

    /*
     * Control 14 contains several disjoint instruction classes.  Beyond the
     * MOV-from-GPR subset below, Zm=4 is INSR, Zm=16..19 is the four-leaf
     * signed/unsigned unpack parent, and Zm=24 is REV.  The unpack parent
     * allocates sizes 1..3 and reserves size 0.  Exhaust these classes plus
     * the remaining historical residual controls.  The pinned SVE2.1/SME2.1
     * PMOV leaves also cross this coarse parent; accept those exact leaves
     * here and validate their full domain in test_arm_sve_pmov.c.  Control
     * 15 otherwise remains covered through the exact invalid descriptor.
     */
    for (selector = 14u; selector < 16u; ++selector) {
        unsigned size_code;

        for (size_code = 0u; size_code < 4u; ++size_code) {
            unsigned first_zm = selector == 14u ? 1u : 0u;
            unsigned zm;

            for (zm = first_zm; zm < 32u; ++zm) {
                cdisasm_arm_instruction instruction;
                uint32_t word = table_word(
                    selector, size_code, (size_code + zm) & 31u,
                    (size_code + zm + 7u) & 31u, zm);
                uint32_t decoded;

                memset(&instruction, 0xa5, sizeof(instruction));
                decoded = decode_word(
                    word,
                    CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
                    CDISASM_ARM_DECODE_OPTION_NONE, 4u,
                    &instruction);
#if USE_EXTRA_OPCODES
                if (selector == 14u
                    && (zm == 4u || zm == 20u || zm == 24u
                        || (selector14_is_unpack(zm)
                            && size_code != 0u))) {
                    EXPECT(decoded == 4u);
                    expect_selector14_success(
                        &instruction, word, size_code, zm);
                    continue;
                }
                /* The SVE logical-immediate parent crosses four points in
                 * this historical selector-14/15 residual sweep.  Those
                 * points are allocated AND/ORR/EOR leaves when their imm13
                 * payload decodes to a valid replicated bitmask. */
                if (decoded == 4u
                    && (instruction.name_id == CDISASM_ARM_NAME_AND
                        || instruction.name_id == CDISASM_ARM_NAME_ORR
                        || instruction.name_id == CDISASM_ARM_NAME_EOR)
                    && (instruction.instruction_flags
                        & (CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
                            | CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK))
                        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR) {
                    continue;
                }
                if (decoded == 4u
                    && instruction.name_id == CDISASM_ARM_NAME_PMOV
                    && instruction.form_id >= UINT16_C(2448)
                    && instruction.form_id <= UINT16_C(2455)
                    && instruction.operand_count == 2u
                    && instruction.instruction_flags
                        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR) {
                    continue;
                }
                EXPECT(decoded == 0u);
                EXPECT(instruction_is_error_only(
                    &instruction,
                    selector == 14u
                        && selector14_is_unsupported(size_code, zm)
                            ? CDISASM_STATUS_UNSUPPORTED_INSTRUCTION
                            : CDISASM_STATUS_INVALID_INSTRUCTION));
#else
                EXPECT(decoded == 0u);
                EXPECT(instruction_is_error_only(
                    &instruction,
                    selector == 14u
                        && (!selector14_is_unpack(zm)
                            || size_code != 0u)
                            ? CDISASM_STATUS_UNSUPPORTED_INSTRUCTION
                            : CDISASM_STATUS_INVALID_INSTRUCTION));
#endif
            }
        }
    }

    for (selector = 0u; selector < 4u; ++selector) {
#if USE_EXTRA_OPCODES
        expect_mov_success(
            CDISASM_ARM_CPU_ANY, selector,
            (selector == 0u || selector == 3u) ? 31u : selector,
            (selector == 0u || selector == 3u) ? 31u : selector + 4u);
#else
        cdisasm_arm_instruction instruction;
        unsigned encoded =
            (selector == 0u || selector == 3u) ? 31u : selector + 4u;

        memset(&instruction, 0xa5, sizeof(instruction));
        EXPECT(decode_word(
            table_word(14u, selector, selector, encoded, 0u),
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            CDISASM_ARM_DECODE_OPTION_NONE, 4u,
            &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

static void test_feature_and_cpu_profiles(void)
{
    static const cdisasm_arm_cpu_id sme_cpus[] = {
        CDISASM_ARM_CPU_APPLE_A18,
        CDISASM_ARM_CPU_APPLE_M4
    };
    cdisasm_arm_cpu_id cpu_id;
    size_t cpu_index;

    expect_profile_result(CDISASM_ARM_CPU_FUJITSU_A64FX, 12u, 1);
    expect_profile_result(CDISASM_ARM_CPU_FUJITSU_A64FX, 10u, 0);
    expect_profile_result(CDISASM_ARM_CPU_FUJITSU_A64FX, 11u, 0);
    expect_profile_result(CDISASM_ARM_CPU_FUJITSU_A64FX, 13u, 0);
    expect_mov_profile_result(CDISASM_ARM_CPU_FUJITSU_A64FX, 1);
    expect_dup_profile_result(CDISASM_ARM_CPU_FUJITSU_A64FX, 1);

    for (cpu_index = 0u;
         cpu_index < sizeof(sme_cpus) / sizeof(sme_cpus[0]);
         ++cpu_index) {
        expect_profile_result(sme_cpus[cpu_index], 10u, 1);
        expect_profile_result(sme_cpus[cpu_index], 11u, 1);
        expect_profile_result(sme_cpus[cpu_index], 12u, 1);
        expect_profile_result(sme_cpus[cpu_index], 13u, 0);
        expect_mov_profile_result(sme_cpus[cpu_index], 1);
        expect_dup_profile_result(sme_cpus[cpu_index], 1);
    }

    expect_profile_result(CDISASM_ARM_CPU_CORTEX_A53, 10u, 0);
    expect_profile_result(CDISASM_ARM_CPU_CORTEX_A53, 12u, 0);
    expect_mov_profile_result(CDISASM_ARM_CPU_CORTEX_A53, 0);
    expect_dup_profile_result(CDISASM_ARM_CPU_CORTEX_A53, 0);

    for (cpu_id = CDISASM_ARM_CPU_FIRST;
         cpu_id <= CDISASM_ARM_CPU_LAST;
         ++cpu_id) {
        if ((cdisasm_arm_cpu_mode_mask(cpu_id)
                & CDISASM_ARM_MODE_MASK_A64) != 0u) {
            expect_profile_result(cpu_id, 13u, 0);
        }
    }
}

static void test_boundaries_endian_truncation_and_dispatch(void)
{
    cdisasm_arm_instruction little;
    cdisasm_arm_instruction big;
    cdisasm_arm_instruction generic;
    uint8_t little_bytes[4];
    uint8_t big_bytes[4];
    uint32_t pair_word = table_word(10u, 3u, 31u, 31u, 0u);
    uint32_t tbxq_word = table_word(13u, 2u, 31u, 0u, 31u);
    uint32_t decoded;

    memset(&little, 0xa5, sizeof(little));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(
        pair_word, CDISASM_ARM_CPU_APPLE_M4, CDISASM_ARM_MODE_A64,
        CDISASM_ARM_DECODE_OPTION_NONE, 4u, &little) == 4u);
    EXPECT(little.name_id == CDISASM_ARM_NAME_TBL);
    EXPECT(little.operand[0].reg == CDISASM_ARM_REG_Z31);
    EXPECT(little.operand[1].reg == CDISASM_ARM_REG_Z31);
    EXPECT(little.operand[1].register_list == UINT16_C(0x0102));
    EXPECT(little.operand[2].reg == CDISASM_ARM_REG_Z0);
#else
    EXPECT(decode_word(
        pair_word, CDISASM_ARM_CPU_APPLE_M4, CDISASM_ARM_MODE_A64,
        CDISASM_ARM_DECODE_OPTION_NONE, 4u, &little) == 0u);
    EXPECT(instruction_is_error_only(
        &little, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif

    memset(&little, 0xa5, sizeof(little));
    decoded = decode_word(
        tbxq_word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        CDISASM_ARM_DECODE_OPTION_NONE, 4u, &little);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
#else
    EXPECT(decoded == 0u);
#endif
    word_to_be(tbxq_word, big_bytes);
    memset(&big, 0xa5, sizeof(big));
    decoded = cdisasm_arm_decode(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        big_bytes, sizeof(big_bytes), UINT64_C(0x7000),
        CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &big);
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
    EXPECT(memcmp(&big, &little, sizeof(big)) == 0);
#else
    EXPECT(decoded == 0u);
    EXPECT(memcmp(&big, &little, sizeof(big)) == 0);
#endif

    word_to_le(tbxq_word, little_bytes);
    memset(&generic, 0xa5, sizeof(generic));
    decoded = cdisasm_decode_checked(
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        little_bytes, sizeof(little_bytes), UINT64_C(0x7000),
        CDISASM_ARM_DECODE_OPTION_NONE, &generic, sizeof(generic));
#if USE_EXTRA_OPCODES
    EXPECT(decoded == 4u);
    EXPECT(memcmp(&generic, &little, sizeof(generic)) == 0);
#else
    EXPECT(decoded == 0u);
    EXPECT(memcmp(&generic, &little, sizeof(generic)) == 0);
#endif

    {
        cdisasm_arm_instruction mov_little;
        cdisasm_arm_instruction mov_big;
        uint32_t mov_word = table_word(14u, 0u, 31u, 31u, 0u);

        memset(&mov_little, 0xa5, sizeof(mov_little));
        decoded = decode_word(
            mov_word, CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_ARM_MODE_A64, CDISASM_ARM_DECODE_OPTION_NONE,
            4u, &mov_little);
#if USE_EXTRA_OPCODES
        EXPECT(decoded == 4u);
        EXPECT(mov_little.name_id == CDISASM_ARM_NAME_MOV);
        EXPECT(mov_little.operand[0].reg == CDISASM_ARM_REG_Z31);
        EXPECT(mov_little.operand[1].reg == CDISASM_ARM_REG_WSP);
#else
        EXPECT(decoded == 0u);
        EXPECT(instruction_is_error_only(
            &mov_little, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
        word_to_be(mov_word, big_bytes);
        memset(&mov_big, 0xa5, sizeof(mov_big));
        decoded = cdisasm_arm_decode(
            CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_ARM_MODE_A64, big_bytes, sizeof(big_bytes),
            UINT64_C(0x7000), CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN,
            &mov_big);
#if USE_EXTRA_OPCODES
        EXPECT(decoded == 4u);
#else
        EXPECT(decoded == 0u);
#endif
        EXPECT(memcmp(&mov_big, &mov_little, sizeof(mov_big)) == 0);
    }

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        tbxq_word, CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        CDISASM_ARM_DECODE_OPTION_NONE, 3u, &generic) == 0u);
    EXPECT(instruction_is_error_only(&generic, CDISASM_STATUS_TRUNCATED));

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        table_word(12u, 0u, 0u, 1u, 2u),
        CDISASM_ARM_CPU_FUJITSU_A64FX, CDISASM_ARM_MODE_A32,
        CDISASM_ARM_DECODE_OPTION_NONE, 4u, &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_ARGUMENT));

    memset(&generic, 0xa5, sizeof(generic));
    EXPECT(decode_word(
        table_word(12u, 0u, 0u, 1u, 2u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        UINT64_C(1) << 63, 4u, &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_INVALID_ARGUMENT));

    /* Selector 8 is DUP with preferred MOV spelling; selector 9 is DUPQ. */
    memset(&generic, 0xa5, sizeof(generic));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(
        table_word(8u, 0u, 0u, 1u, 2u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        CDISASM_ARM_DECODE_OPTION_NONE, 4u, &generic) == 4u);
    EXPECT(generic.name_id == CDISASM_ARM_NAME_MOV);
    EXPECT(generic.form_id == UINT16_C(2439));
    EXPECT(generic.operand[1].reg == CDISASM_ARM_REG_H1);
#else
    EXPECT(decode_word(
        table_word(8u, 0u, 0u, 1u, 2u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        CDISASM_ARM_DECODE_OPTION_NONE, 4u, &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif

    memset(&generic, 0xa5, sizeof(generic));
#if USE_EXTRA_OPCODES
    EXPECT(decode_word(
        table_word(9u, 0u, 0u, 1u, 2u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        CDISASM_ARM_DECODE_OPTION_NONE, 4u, &generic) == 4u);
    EXPECT(generic.last_error_id == CDISASM_STATUS_OK);
    EXPECT(generic.name_id == CDISASM_ARM_NAME_DUPQ);
    EXPECT(generic.form_id == UINT16_C(2440));
    EXPECT(generic.operand_count == 2u);
    EXPECT(generic.instruction_flags
        == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
#else
    EXPECT(decode_word(
        table_word(9u, 0u, 0u, 1u, 2u),
        CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
        CDISASM_ARM_DECODE_OPTION_NONE, 4u, &generic) == 0u);
    EXPECT(instruction_is_error_only(
        &generic, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    {
        char text[128];
        char short_text[5];
        static const char expected[] =
            "tbl z31.d, {z31.d, z0.d}, z0.d";
        static const char expected_upper[] =
            "TBL z31.d, {z31.d, z0.d}, z0.d";

        EXPECT(decode_word(
            pair_word, CDISASM_ARM_CPU_APPLE_M4, CDISASM_ARM_MODE_A64,
            CDISASM_ARM_DECODE_OPTION_NONE, 4u, &generic) == 4u);
        EXPECT(cdisasm_arm_format(
            &generic, CDISASM_FORMAT_SYNTAX_7,
            text, sizeof(text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(text, expected) == 0);
        EXPECT(cdisasm_arm_format(
            &generic, CDISASM_FORMAT_SYNTAX_0,
            short_text, sizeof(short_text)) == sizeof(expected) - 1u);
        EXPECT(strcmp(short_text, "tbl ") == 0);
        EXPECT(cdisasm_arm_format(
            &generic, CDISASM_FORMAT_SYNTAX_0
                | CDISASM_FORMAT_UPPERCASE_OPCODE,
            text, sizeof(text)) == sizeof(expected_upper) - 1u);
        EXPECT(strcmp(text, expected_upper) == 0);
    }
#endif
}

static void test_luti2_indexed_table(void)
{
    static const struct luti2_case {
        uint32_t word;
        uint8_t size, zd, zn, zm, lane;
    } cases[] = {
        { UINT32_C(0x45e2b020), 1u, 0u, 1u, 2u, 3u },
        { UINT32_C(0x4525b883), 2u, 3u, 4u, 5u, 1u }
    };
    cdisasm_arm_instruction instruction;
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const struct luti2_case *test = &cases[index];
        memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(test->word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, CDISASM_ARM_DECODE_OPTION_NONE, 4u,
            &instruction) == 4u);
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_LUTI2);
        EXPECT(instruction.instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
        EXPECT(instruction.operand_count == 3u);
        EXPECT(instruction.operand[0].reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + test->zd));
        EXPECT(instruction.operand[0].extend_type == test->size);
        EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        EXPECT(instruction.operand[1].type
            == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);
        EXPECT(instruction.operand[1].reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + test->zn));
        EXPECT(instruction.operand[1].register_list == UINT16_C(0x0101));
        EXPECT(instruction.operand[1].extend_type == test->size);
        EXPECT(instruction.operand[2].reg
            == (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + test->zm));
        EXPECT(instruction.operand[2].extend_type == test->size);
        EXPECT(instruction.operand[2].flags
            == CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
        EXPECT(instruction.operand[2].imm == test->lane);
#else
        EXPECT(decode_word(test->word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, CDISASM_ARM_DECODE_OPTION_NONE, 4u,
            &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(cases[0].word, CDISASM_ARM_CPU_CORTEX_A53,
        CDISASM_ARM_MODE_A64, CDISASM_ARM_DECODE_OPTION_NONE, 4u,
        &instruction) == 0u);
#if USE_EXTRA_OPCODES
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
#else
    EXPECT(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
}

static void test_advsimd_luti2(void)
{
    static const uint32_t words[2] = {
        UINT32_C(0x4e827020), UINT32_C(0x4ec51083)
    };
    static const uint8_t sizes[2] = { 1u, 2u };
    static const uint8_t lanes[2] = { 3u, 1u };
    cdisasm_arm_instruction instruction;
    size_t index;

#if !USE_EXTRA_OPCODES
    (void)sizes;
    (void)lanes;
#endif

    for (index = 0u; index < 2u; ++index) {
        memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(words[index], CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, CDISASM_ARM_DECODE_OPTION_NONE, 4u,
            &instruction) == 4u);
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_LUTI2);
        EXPECT(instruction.instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
        EXPECT(instruction.operand_count == 3u);
        EXPECT(instruction.operand[0].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction.operand[0].size == 16u);
        EXPECT(instruction.operand[0].extend_type == sizes[index]);
        EXPECT(instruction.operand[0].scale == 16u / sizes[index]);
        EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        EXPECT(instruction.operand[1].type
            == CDISASM_ARM_OPERAND_VECTOR_REGISTER_LIST);
        EXPECT(instruction.operand[1].register_list == 1u);
        EXPECT(instruction.operand[1].size == 16u);
        EXPECT(instruction.operand[1].extend_type == sizes[index]);
        EXPECT(instruction.operand[1].scale == 16u / sizes[index]);
        EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction.operand[2].flags
            == CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
        EXPECT(instruction.operand[2].imm == lanes[index]);
        EXPECT(instruction.operand[2].access == CDISASM_OPERAND_ACCESS_READ);
#  if USE_DISASM_FORMAT
        {
            static const char *const texts[2] = {
                "luti2 v0.16b, {v1.16b}, v2[3]",
                "luti2 v3.8h, {v4.8h}, v5[1]"
            };
            char text[96];
            size_t length = cdisasm_arm_format(
                &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
                text, sizeof(text));
            if (length != strlen(texts[index])
                || strcmp(text, texts[index]) != 0) {
                fprintf(stderr, "LUTI2 format got '%s' form %u\n",
                    text, (unsigned)instruction.form_id);
            }
            EXPECT(length == strlen(texts[index]));
            EXPECT(strcmp(text, texts[index]) == 0);
        }
#  endif
#else
        EXPECT(decode_word(words[index], CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, CDISASM_ARM_DECODE_OPTION_NONE, 4u,
            &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

static void test_sve_luti4(void)
{
    static const struct luti4_case {
        uint32_t word;
        uint8_t size, list_count, lane;
    } cases[] = {
        { UINT32_C(0x45e2a420), 1u, 1u, 1u },
        { UINT32_C(0x45e6b483), 2u, 2u, 3u },
        { UINT32_C(0x4569bd07), 2u, 1u, 1u }
    };
    cdisasm_arm_instruction instruction;
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const struct luti4_case *test = &cases[index];
        memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(test->word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, CDISASM_ARM_DECODE_OPTION_NONE, 4u,
            &instruction) == 4u);
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_LUTI4);
        EXPECT(instruction.instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR);
        EXPECT(instruction.operand_count == 3u);
        EXPECT(instruction.operand[0].extend_type == test->size);
        EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        EXPECT(instruction.operand[1].type
            == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST);
        EXPECT(CDISASM_ARM_SCALABLE_LIST_COUNT(&instruction.operand[1])
            == test->list_count);
        EXPECT(instruction.operand[1].extend_type == test->size);
        EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction.operand[2].extend_type == test->size);
        EXPECT(instruction.operand[2].flags
            == CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
        EXPECT(instruction.operand[2].imm == test->lane);
        EXPECT(instruction.operand[2].access == CDISASM_OPERAND_ACCESS_READ);
#else
        EXPECT(decode_word(test->word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, CDISASM_ARM_DECODE_OPTION_NONE, 4u,
            &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

static void test_advsimd_luti4(void)
{
    static const struct fixed_luti4_case {
        uint32_t word;
        uint8_t size, list_count, lane;
        const char *text;
    } cases[] = {
        { UINT32_C(0x4e437020), 2u, 2u, 3u,
          "luti4 v0.8h, {v1.8h, v2.8h}, v3[3]" },
        { UINT32_C(0x4e4660a4), 1u, 1u, 1u,
          "luti4 v4.16b, {v5.16b}, v6[1]" }
    };
    cdisasm_arm_instruction instruction;
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const struct fixed_luti4_case *test = &cases[index];
        memset(&instruction, 0xa5, sizeof(instruction));
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(test->word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, CDISASM_ARM_DECODE_OPTION_NONE, 4u,
            &instruction) == 4u);
        EXPECT(instruction.name_id == CDISASM_ARM_NAME_LUTI4);
        EXPECT(instruction.instruction_flags
            == CDISASM_ARM_INSTRUCTION_FLAG_SIMD);
        EXPECT(instruction.operand_count == 3u);
        EXPECT(instruction.operand[0].extend_type == test->size);
        EXPECT(instruction.operand[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        EXPECT(instruction.operand[1].type
            == CDISASM_ARM_OPERAND_VECTOR_REGISTER_LIST);
        EXPECT(instruction.operand[1].register_list == test->list_count);
        EXPECT(instruction.operand[1].extend_type == test->size);
        EXPECT(instruction.operand[1].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction.operand[2].flags
            == CDISASM_ARM_OPERAND_FLAG_HAS_LANE);
        EXPECT(instruction.operand[2].imm == test->lane);
#  if USE_DISASM_FORMAT
        {
            char text[96];
            EXPECT(cdisasm_arm_format(
                &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
                text, sizeof(text)) == strlen(test->text));
            EXPECT(strcmp(text, test->text) == 0);
        }
#  endif
#else
        (void)test->text;
        EXPECT(decode_word(test->word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64, CDISASM_ARM_DECODE_OPTION_NONE, 4u,
            &instruction) == 0u);
        EXPECT(instruction_is_error_only(
            &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION));
#endif
    }
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void test_dup_formatting(void)
{
    static const struct dup_format_vector {
        uint32_t word;
        const char *text;
    } vectors[] = {
        { UINT32_C(0x05212020), "mov z0.b, b1" },
        { UINT32_C(0x053f2062), "mov z2.b, z3.b[15]" },
        { UINT32_C(0x052220a4), "mov z4.h, h5" },
        { UINT32_C(0x053e20e6), "mov z6.h, z7.h[7]" },
        { UINT32_C(0x05242128), "mov z8.s, s9" },
        { UINT32_C(0x053c216a), "mov z10.s, z11.s[3]" },
        { UINT32_C(0x052821ac), "mov z12.d, d13" },
        { UINT32_C(0x053821ee), "mov z14.d, z15.d[1]" },
        { UINT32_C(0x053023e0), "mov z0.q, q31" },
        { UINT32_C(0x05f02020), "mov z0.q, z1.q[3]" }
    };
    size_t index;

    for (index = 0u; index < sizeof(vectors) / sizeof(vectors[0]);
         ++index) {
        cdisasm_arm_instruction instruction;
        char text[64];
        size_t expected_length = strlen(vectors[index].text);

        EXPECT(decode_word(
            vectors[index].word, CDISASM_ARM_CPU_ANY,
            CDISASM_ARM_MODE_A64,
            CDISASM_ARM_DECODE_OPTION_NONE, 4u,
            &instruction) == 4u);
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            text, sizeof(text)) == expected_length);
        EXPECT(strcmp(text, vectors[index].text) == 0);
        EXPECT(cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
            NULL, 0u) == expected_length);
    }
}
#endif

int main(void)
{
    test_dup_selector_domain();
    test_allocated_and_adjacent_selectors();
    test_feature_and_cpu_profiles();
    test_boundaries_endian_truncation_and_dispatch();
    test_luti2_indexed_table();
    test_advsimd_luti2();
    test_sve_luti4();
    test_advsimd_luti4();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
    test_dup_formatting();
#endif

    if (failures != 0) {
        fprintf(stderr, "%d ARM SVE table-lookup test(s) failed\n",
                failures);
        return 1;
    }
    printf("ARM SVE table-lookup tests passed "
           "(USE_EXTRA_OPCODES=%d)\n", USE_EXTRA_OPCODES);
    return 0;
}
