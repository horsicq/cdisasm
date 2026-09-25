#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

#define TEST_ADDRESS UINT64_C(0x171000)
#define SCALABLE_FLAGS CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR

enum count_kind {
    COUNT_VECTOR = 0,
    COUNT_X,
    COUNT_W,
    COUNT_X_W,
    COUNT_CNTP,
    COUNT_FIRST_LAST,
    COUNT_CNTP_COUNTER
};

typedef struct count_identity {
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    uint8_t kind;
} count_identity;

static int failures;

#define EXPECT(condition)                                                   \
    do {                                                                    \
        if (!(condition)) {                                                 \
            if (failures < 24) {                                           \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",       \
                        __FILE__, __LINE__, #condition);                    \
            }                                                               \
            ++failures;                                                     \
        }                                                                   \
    } while (0)

static void domain_expect(int condition, uint32_t word, const char *message)
{
    if (!condition) {
        if (failures < 24) {
            fprintf(stderr, "word %08x: %s\n", (unsigned)word, message);
        }
        ++failures;
    }
}

static void word_to_le(uint32_t word, uint8_t bytes[4])
{
    bytes[0] = (uint8_t)word;
    bytes[1] = (uint8_t)(word >> 8);
    bytes[2] = (uint8_t)(word >> 16);
    bytes[3] = (uint8_t)(word >> 24);
}

static uint32_t decode_word(
    uint32_t word, cdisasm_arm_cpu_id cpu_id, size_t size,
    cdisasm_arm_decode_option options, cdisasm_arm_instruction *instruction)
{
    uint8_t bytes[4];

    word_to_le(word, bytes);
    return cdisasm_arm_decode(
        cpu_id, CDISASM_ARM_MODE_A64, bytes, size, TEST_ADDRESS,
        options, instruction);
}

static int instruction_is_error_only(
    const cdisasm_arm_instruction *instruction, cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

#if USE_EXTRA_OPCODES
static cdisasm_arm_reg_id xreg(unsigned encoded)
{
    return encoded == 31u ? CDISASM_ARM_REG_XZR
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_X0 + encoded);
}

static cdisasm_arm_reg_id wreg(unsigned encoded)
{
    return encoded == 31u ? CDISASM_ARM_REG_WZR
        : (cdisasm_arm_reg_id)(CDISASM_ARM_REG_W0 + encoded);
}
#endif

static int saturating_identity(uint32_t word, count_identity *identity)
{
    static const cdisasm_arm_form_id scalar_forms[4][2][4] = {
        {
            { UINT16_C(2392), UINT16_C(2393), UINT16_C(2394), UINT16_C(2395) },
            { UINT16_C(2396), UINT16_C(2416), UINT16_C(2397), UINT16_C(2417) }
        },
        {
            { UINT16_C(2398), UINT16_C(2399), UINT16_C(2400), UINT16_C(2401) },
            { UINT16_C(2402), UINT16_C(2418), UINT16_C(2403), UINT16_C(2419) }
        },
        {
            { UINT16_C(2404), UINT16_C(2405), UINT16_C(2406), UINT16_C(2407) },
            { UINT16_C(2408), UINT16_C(2420), UINT16_C(2409), UINT16_C(2421) }
        },
        {
            { UINT16_C(2410), UINT16_C(2411), UINT16_C(2412), UINT16_C(2413) },
            { UINT16_C(2414), UINT16_C(2422), UINT16_C(2415), UINT16_C(2423) }
        }
    };
    static const cdisasm_arm_name_id names[4][4] = {
        {
            CDISASM_ARM_NAME_SQINCB, CDISASM_ARM_NAME_UQINCB,
            CDISASM_ARM_NAME_SQDECB, CDISASM_ARM_NAME_UQDECB
        },
        {
            CDISASM_ARM_NAME_SQINCH, CDISASM_ARM_NAME_UQINCH,
            CDISASM_ARM_NAME_SQDECH, CDISASM_ARM_NAME_UQDECH
        },
        {
            CDISASM_ARM_NAME_SQINCW, CDISASM_ARM_NAME_UQINCW,
            CDISASM_ARM_NAME_SQDECW, CDISASM_ARM_NAME_UQDECW
        },
        {
            CDISASM_ARM_NAME_SQINCD, CDISASM_ARM_NAME_UQINCD,
            CDISASM_ARM_NAME_SQDECD, CDISASM_ARM_NAME_UQDECD
        }
    };
    unsigned size = (word >> 22) & 3u;
    unsigned operation = (word >> 10) & 3u;
    unsigned scalar_x = (word >> 20) & 1u;

    if ((word & UINT32_C(0xff30f000)) == UINT32_C(0x0420c000)) {
        unsigned local;

        if (size == 0u) {
            return 0;
        }
        local = ((operation & 1u) << 1) | (operation >> 1);
        identity->form_id = (cdisasm_arm_form_id)(
            UINT16_C(2362) + (size - 1u) * 4u + local);
        identity->name_id = names[size][operation];
        identity->kind = COUNT_VECTOR;
        return 1;
    }
    if ((word & UINT32_C(0xff20f000)) != UINT32_C(0x0420f000)) {
        return 0;
    }
    identity->form_id = scalar_forms[size][scalar_x][operation];
    identity->name_id = names[size][operation];
    identity->kind = scalar_x ? COUNT_X
        : (operation & 1u) != 0u ? COUNT_W : COUNT_X_W;
    return 1;
}

static int predicate_identity(uint32_t word, count_identity *identity)
{
    static const uint32_t values[16] = {
        UINT32_C(0x25288000), UINT32_C(0x252a8000),
        UINT32_C(0x25298000), UINT32_C(0x252b8000),
        UINT32_C(0x252c8000), UINT32_C(0x252d8000),
        UINT32_C(0x25288800), UINT32_C(0x25298800),
        UINT32_C(0x252a8800), UINT32_C(0x252b8800),
        UINT32_C(0x25288c00), UINT32_C(0x252a8c00),
        UINT32_C(0x25298c00), UINT32_C(0x252b8c00),
        UINT32_C(0x252c8800), UINT32_C(0x252d8800)
    };
    static const cdisasm_arm_name_id names[16] = {
        CDISASM_ARM_NAME_SQINCP, CDISASM_ARM_NAME_SQDECP,
        CDISASM_ARM_NAME_UQINCP, CDISASM_ARM_NAME_UQDECP,
        CDISASM_ARM_NAME_INCP, CDISASM_ARM_NAME_DECP,
        CDISASM_ARM_NAME_SQINCP, CDISASM_ARM_NAME_UQINCP,
        CDISASM_ARM_NAME_SQDECP, CDISASM_ARM_NAME_UQDECP,
        CDISASM_ARM_NAME_SQINCP, CDISASM_ARM_NAME_SQDECP,
        CDISASM_ARM_NAME_UQINCP, CDISASM_ARM_NAME_UQDECP,
        CDISASM_ARM_NAME_INCP, CDISASM_ARM_NAME_DECP
    };
    static const uint8_t kinds[16] = {
        COUNT_VECTOR, COUNT_VECTOR, COUNT_VECTOR, COUNT_VECTOR,
        COUNT_VECTOR, COUNT_VECTOR, COUNT_X_W, COUNT_W,
        COUNT_X_W, COUNT_W, COUNT_X, COUNT_X, COUNT_X, COUNT_X,
        COUNT_X, COUNT_X
    };
    uint32_t fixed;
    unsigned index;

    if ((word & UINT32_C(0xff3fc200)) == UINT32_C(0x25208000)) {
        identity->form_id = UINT16_C(2597);
        identity->name_id = CDISASM_ARM_NAME_CNTP;
        identity->kind = COUNT_CNTP;
        return 1;
    }
    if ((word & UINT32_C(0xff3fc200)) == UINT32_C(0x25218000)
        || (word & UINT32_C(0xff3fc200)) == UINT32_C(0x25228000)) {
        int last = (word & UINT32_C(0x00010000)) == 0u;

        identity->form_id = last ? UINT16_C(2599) : UINT16_C(2598);
        identity->name_id = last
            ? CDISASM_ARM_NAME_LASTP : CDISASM_ARM_NAME_FIRSTP;
        identity->kind = COUNT_FIRST_LAST;
        return 1;
    }
    if ((word & UINT32_C(0xff3ffa00)) == UINT32_C(0x25208200)) {
        identity->form_id = UINT16_C(2600);
        identity->name_id = CDISASM_ARM_NAME_CNTP;
        identity->kind = COUNT_CNTP_COUNTER;
        return 1;
    }
    fixed = word & UINT32_C(0xff3ffe00);
    for (index = 0u; index < 16u; ++index) {
        if (fixed == values[index]) {
            if (kinds[index] == COUNT_VECTOR
                && ((word >> 22) & 3u) == 0u) {
                return 0;
            }
            identity->form_id = (cdisasm_arm_form_id)(2601u + index);
            identity->name_id = names[index];
            identity->kind = kinds[index];
            return 1;
        }
    }
    return 0;
}

#if USE_EXTRA_OPCODES
static void append_register(
    cdisasm_arm_instruction *expected, cdisasm_arm_reg_id reg,
    uint8_t size, cdisasm_operand_access access)
{
    cdisasm_arm_operand *operand =
        &expected->operand[expected->operand_count++];

    operand->type = CDISASM_OPERAND_REGISTER;
    operand->reg = reg;
    operand->size = size;
    operand->access = access;
}

static void append_zreg(
    cdisasm_arm_instruction *expected, unsigned encoded,
    uint8_t element_size, cdisasm_operand_access access)
{
    cdisasm_arm_operand *operand =
        &expected->operand[expected->operand_count++];

    operand->type = CDISASM_ARM_OPERAND_SCALABLE_REGISTER;
    operand->reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_Z0 + encoded);
    operand->extend_type = (cdisasm_arm_extend_type)element_size;
    operand->access = access;
}

static void append_predicate(
    cdisasm_arm_instruction *expected, cdisasm_arm_reg_id reg,
    uint8_t element_size, uint8_t flags)
{
    cdisasm_arm_operand *operand =
        &expected->operand[expected->operand_count++];

    operand->type = CDISASM_ARM_OPERAND_PREDICATE;
    operand->reg = reg;
    operand->extend_type = (cdisasm_arm_extend_type)element_size;
    operand->flags = flags;
    operand->access = CDISASM_OPERAND_ACCESS_READ;
}

static void append_immediate(
    cdisasm_arm_instruction *expected, uint64_t value)
{
    cdisasm_arm_operand *operand =
        &expected->operand[expected->operand_count++];

    operand->type = CDISASM_OPERAND_IMMEDIATE;
    operand->imm = value;
    operand->size = 1u;
    operand->access = CDISASM_OPERAND_ACCESS_READ;
}

static void initialize_expected(
    cdisasm_arm_instruction *expected, uint32_t word,
    const count_identity *identity, uint32_t flags)
{
    memset(expected, 0, sizeof(*expected));
    expected->address = TEST_ADDRESS;
    expected->opcode_size = 4u;
    expected->raw_instruction = word;
    expected->name_id = identity->name_id;
    expected->form_id = identity->form_id;
    expected->condition = CDISASM_ARM_CONDITION_AL;
    expected->isa_id = CDISASM_ARM_ISA_A64;
    expected->instruction_flags = flags;
}

static void expected_saturating(
    uint32_t word, const count_identity *identity,
    cdisasm_arm_instruction *expected)
{
    unsigned encoded = word & 31u;
    uint8_t element_size = (uint8_t)(UINT8_C(1)
        << ((word >> 22) & 3u));

    initialize_expected(expected, word, identity, SCALABLE_FLAGS);
    if (identity->kind == COUNT_VECTOR) {
        append_zreg(expected, encoded, element_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE);
    } else if (identity->kind == COUNT_X_W) {
        append_register(expected, xreg(encoded), 8u,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_register(expected, wreg(encoded), 4u,
            CDISASM_OPERAND_ACCESS_READ);
    } else {
        append_register(expected,
            identity->kind == COUNT_W ? wreg(encoded) : xreg(encoded),
            identity->kind == COUNT_W ? 4u : 8u,
            CDISASM_OPERAND_ACCESS_READ_WRITE);
    }
    append_immediate(expected, (word >> 5) & 31u);
    append_immediate(expected, ((word >> 16) & 15u) + 1u);
}

static void expected_predicate(
    uint32_t word, const count_identity *identity,
    cdisasm_arm_instruction *expected)
{
    unsigned encoded = word & 31u;
    unsigned predicate = (word >> 5) & 15u;
    uint8_t element_size = (uint8_t)(UINT8_C(1)
        << ((word >> 22) & 3u));
    uint32_t flags = SCALABLE_FLAGS
        | (identity->kind == COUNT_CNTP
                || identity->kind == COUNT_FIRST_LAST
            ? CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED : 0u);

    initialize_expected(expected, word, identity, flags);
    if (identity->kind == COUNT_CNTP
        || identity->kind == COUNT_FIRST_LAST) {
        append_register(expected, xreg(encoded), 8u,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_predicate(expected, (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_P0 + ((word >> 10) & 15u)),
            element_size, CDISASM_OPERAND_FLAG_NONE);
        append_predicate(expected, (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_P0 + predicate), element_size,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
        return;
    }
    if (identity->kind == COUNT_CNTP_COUNTER) {
        append_register(expected, xreg(encoded), 8u,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_predicate(expected, (cdisasm_arm_reg_id)(
            CDISASM_ARM_REG_PN0 + predicate), element_size,
            CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
        append_immediate(expected,
            (word & UINT32_C(0x00000400)) != 0u ? 4u : 2u);
        return;
    }
    if (identity->kind == COUNT_VECTOR) {
        append_zreg(expected, encoded, element_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE);
    } else if (identity->kind == COUNT_X_W) {
        append_register(expected, xreg(encoded), 8u,
            CDISASM_OPERAND_ACCESS_WRITE);
    } else {
        append_register(expected,
            identity->kind == COUNT_W ? wreg(encoded) : xreg(encoded),
            identity->kind == COUNT_W ? 4u : 8u,
            CDISASM_OPERAND_ACCESS_READ_WRITE);
    }
    append_predicate(expected, (cdisasm_arm_reg_id)(
        CDISASM_ARM_REG_P0 + predicate), element_size,
        CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED);
    if (identity->kind == COUNT_X_W) {
        append_register(expected, wreg(encoded), 4u,
            CDISASM_OPERAND_ACCESS_READ);
    }
}
#endif

static void expect_allocated(
    uint32_t word, const count_identity *identity, int predicate_family,
    uint32_t *allocated_count)
{
    cdisasm_arm_instruction instruction;
    uint32_t decoded;

    memset(&instruction, 0xa5, sizeof(instruction));
    decoded = decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction);
#if USE_EXTRA_OPCODES
    {
        cdisasm_arm_instruction expected;

        if (predicate_family) {
            expected_predicate(word, identity, &expected);
        } else {
            expected_saturating(word, identity, &expected);
        }
        domain_expect(decoded == 4u, word, "allocated word did not decode");
        domain_expect(memcmp(&instruction, &expected, sizeof(expected)) == 0,
            word, "allocated structured metadata mismatch");
        ++*allocated_count;
    }
#else
    (void)identity;
    (void)predicate_family;
    (void)allocated_count;
    domain_expect(decoded == 0u, word, "extras-OFF decoded allocated word");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION),
        word, "extras-OFF allocated ownership mismatch");
#endif
}

static void expect_reserved(uint32_t word, uint32_t *reserved_count)
{
    cdisasm_arm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    domain_expect(decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 0u,
        word, "reserved control decoded");
    domain_expect(instruction_is_error_only(
        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION),
        word, "reserved control was not INVALID");
    ++*reserved_count;
}

static void test_saturating_parent_envelopes(void)
{
    uint32_t allocated_count = 0u;
    uint32_t reserved_count = 0u;
    unsigned size;
    unsigned sf;
    unsigned operation;
    unsigned imm4;
    unsigned pattern;
    unsigned reg;

    for (size = 0u; size < 4u; ++size) {
        for (operation = 0u; operation < 4u; ++operation) {
            for (imm4 = 0u; imm4 < 16u; ++imm4) {
                for (pattern = 0u; pattern < 32u; ++pattern) {
                    for (reg = 0u; reg < 32u; ++reg) {
                        uint32_t word = UINT32_C(0x0420c000)
                            | ((uint32_t)size << 22)
                            | ((uint32_t)imm4 << 16)
                            | ((uint32_t)operation << 10)
                            | ((uint32_t)pattern << 5) | reg;
                        count_identity identity;

                        if (size == 0u) {
                            expect_reserved(word, &reserved_count);
                        } else {
                            domain_expect(saturating_identity(word, &identity),
                                word, "allocated saturating vector escaped leaf");
                            expect_allocated(word, &identity, 0,
                                &allocated_count);
                        }
                    }
                }
            }
        }
    }
    for (size = 0u; size < 4u; ++size) {
        for (sf = 0u; sf < 2u; ++sf) {
            for (operation = 0u; operation < 4u; ++operation) {
                for (imm4 = 0u; imm4 < 16u; ++imm4) {
                    for (pattern = 0u; pattern < 32u; ++pattern) {
                        for (reg = 0u; reg < 32u; ++reg) {
                            uint32_t word = UINT32_C(0x0420f000)
                                | ((uint32_t)size << 22)
                                | ((uint32_t)sf << 20)
                                | ((uint32_t)imm4 << 16)
                                | ((uint32_t)operation << 10)
                                | ((uint32_t)pattern << 5) | reg;
                            count_identity identity;

                            domain_expect(saturating_identity(word, &identity),
                                word, "allocated saturating scalar escaped leaf");
                            expect_allocated(word, &identity, 0,
                                &allocated_count);
                        }
                    }
                }
            }
        }
    }
#if USE_EXTRA_OPCODES
    EXPECT(allocated_count == UINT32_C(720896));
#else
    EXPECT(allocated_count == 0u);
#endif
    EXPECT(reserved_count == UINT32_C(65536));
}

static void test_predicate_parent_envelopes(void)
{
    uint32_t allocated_count = 0u;
    uint32_t reserved_count = 0u;
    unsigned size;
    unsigned opc;
    unsigned first;
    unsigned second;
    unsigned reg;

    for (size = 0u; size < 4u; ++size) {
        for (opc = 0u; opc < 8u; ++opc) {
            for (first = 0u; first < 16u; ++first) {
                for (second = 0u; second < 16u; ++second) {
                    for (reg = 0u; reg < 32u; ++reg) {
                        uint32_t word = UINT32_C(0x25208000)
                            | ((uint32_t)size << 22)
                            | ((uint32_t)opc << 16)
                            | ((uint32_t)first << 10)
                            | ((uint32_t)second << 5) | reg;

                        if (opc <= 2u) {
                            count_identity identity;

                            EXPECT(predicate_identity(word, &identity));
                            expect_allocated(word, &identity, 1,
                                &allocated_count);
                        } else {
                            expect_reserved(word, &reserved_count);
                        }
                    }
                }
            }
        }
    }
    for (size = 0u; size < 4u; ++size) {
        for (opc = 0u; opc < 8u; ++opc) {
            for (first = 0u; first < 2u; ++first) {
                for (second = 0u; second < 16u; ++second) {
                    for (reg = 0u; reg < 32u; ++reg) {
                        uint32_t word = UINT32_C(0x25208200)
                            | ((uint32_t)size << 22)
                            | ((uint32_t)opc << 16)
                            | ((uint32_t)first << 10)
                            | ((uint32_t)second << 5) | reg;

                        if (opc == 0u) {
                            count_identity identity;

                            EXPECT(predicate_identity(word, &identity));
                            expect_allocated(word, &identity, 1,
                                &allocated_count);
                        } else {
                            expect_reserved(word, &reserved_count);
                        }
                    }
                }
            }
        }
    }
    for (size = 0u; size < 4u; ++size) {
        unsigned operation;
        unsigned shape;

        for (operation = 0u; operation < 8u; ++operation) {
            for (shape = 0u; shape < 8u; ++shape) {
                for (first = 0u; first < 16u; ++first) {
                    for (reg = 0u; reg < 32u; ++reg) {
                        uint32_t word = UINT32_C(0x25288000)
                            | ((uint32_t)size << 22)
                            | ((uint32_t)operation << 16)
                            | ((uint32_t)shape << 9)
                            | ((uint32_t)first << 5) | reg;
                        count_identity identity;

                        if (predicate_identity(word, &identity)) {
                            expect_allocated(word, &identity, 1,
                                &allocated_count);
                        } else {
                            expect_reserved(word, &reserved_count);
                        }
                    }
                }
            }
        }
    }
#if USE_EXTRA_OPCODES
    EXPECT(allocated_count == UINT32_C(132096));
#else
    EXPECT(allocated_count == 0u);
#endif
    EXPECT(reserved_count == UINT32_C(293888));
}

static void expect_profile(
    uint32_t word, cdisasm_arm_cpu_id cpu_id, cdisasm_status status)
{
    cdisasm_arm_instruction instruction;
    cdisasm_status expected;

#if USE_EXTRA_OPCODES
    expected = status;
#else
    (void)status;
    expected = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, cpu_id, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction)
        == (expected == CDISASM_STATUS_OK ? 4u : 0u));
    if (expected != CDISASM_STATUS_OK) {
        EXPECT(instruction_is_error_only(&instruction, expected));
    }
}

static void test_feature_alternatives(void)
{
    static const uint32_t sve_words[] = {
        UINT32_C(0x0460c000), UINT32_C(0x04e0cc00),
        UINT32_C(0x0420f000), UINT32_C(0x04f0fc00),
        UINT32_C(0x25208000), UINT32_C(0x25688000),
        UINT32_C(0x25ed8000), UINT32_C(0x25288800),
        UINT32_C(0x25ed8800)
    };
    static const uint32_t counter_words[] = {
        UINT32_C(0x25208200), UINT32_C(0x25e087ff)
    };
    static const uint32_t sve2p2_words[] = {
        UINT32_C(0x25218000), UINT32_C(0x25e2bdff)
    };
    unsigned index;

    for (index = 0u; index < sizeof(sve_words) / sizeof(sve_words[0]);
         ++index) {
        expect_profile(sve_words[index], CDISASM_ARM_CPU_ANY,
            CDISASM_STATUS_OK);
        expect_profile(sve_words[index], CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_STATUS_OK);
        expect_profile(sve_words[index], CDISASM_ARM_CPU_APPLE_A18,
            CDISASM_STATUS_OK);
        expect_profile(sve_words[index], CDISASM_ARM_CPU_APPLE_M4,
            CDISASM_STATUS_OK);
        expect_profile(sve_words[index], CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    for (index = 0u;
         index < sizeof(counter_words) / sizeof(counter_words[0]); ++index) {
        expect_profile(counter_words[index], CDISASM_ARM_CPU_ANY,
            CDISASM_STATUS_OK);
        expect_profile(counter_words[index], CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_profile(counter_words[index], CDISASM_ARM_CPU_APPLE_A18,
            CDISASM_STATUS_OK);
        expect_profile(counter_words[index], CDISASM_ARM_CPU_APPLE_M4,
            CDISASM_STATUS_OK);
        expect_profile(counter_words[index], CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    for (index = 0u;
         index < sizeof(sve2p2_words) / sizeof(sve2p2_words[0]); ++index) {
        expect_profile(sve2p2_words[index], CDISASM_ARM_CPU_ANY,
            CDISASM_STATUS_OK);
        expect_profile(sve2p2_words[index], CDISASM_ARM_CPU_FUJITSU_A64FX,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_profile(sve2p2_words[index], CDISASM_ARM_CPU_APPLE_A18,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_profile(sve2p2_words[index], CDISASM_ARM_CPU_APPLE_M4,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_profile(sve2p2_words[index], CDISASM_ARM_CPU_CORTEX_A53,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

static void test_transport(void)
{
    static const uint32_t words[] = {
        UINT32_C(0x0421f083), UINT32_C(0x04e0cfff),
        UINT32_C(0x25a08861), UINT32_C(0x25608324),
        UINT32_C(0x25288907), UINT32_C(0x25218000),
        UINT32_C(0x25e2bdff)
    };
    unsigned index;

    for (index = 0u; index < sizeof(words) / sizeof(words[0]); ++index) {
        cdisasm_arm_instruction little;
        cdisasm_arm_instruction other;
        uint8_t bytes[4];
        unsigned boundary;

        memset(&little, 0xa5, sizeof(little));
#if USE_EXTRA_OPCODES
        EXPECT(decode_word(words[index], CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &little) == 4u);
#else
        EXPECT(decode_word(words[index], CDISASM_ARM_CPU_ANY, 4u,
            CDISASM_ARM_DECODE_OPTION_NONE, &little) == 0u);
#endif
        bytes[0] = (uint8_t)(words[index] >> 24);
        bytes[1] = (uint8_t)(words[index] >> 16);
        bytes[2] = (uint8_t)(words[index] >> 8);
        bytes[3] = (uint8_t)words[index];
        memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
        EXPECT(cdisasm_arm_decode(
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            bytes, sizeof(bytes), TEST_ADDRESS,
            CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 4u);
#else
        EXPECT(cdisasm_arm_decode(
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            bytes, sizeof(bytes), TEST_ADDRESS,
            CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN, &other) == 0u);
#endif
        EXPECT(memcmp(&little, &other, sizeof(little)) == 0);

        word_to_le(words[index], bytes);
        memset(&other, 0xa5, sizeof(other));
#if USE_EXTRA_OPCODES
        EXPECT(cdisasm_decode(
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            bytes, sizeof(bytes), TEST_ADDRESS,
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 4u);
#else
        EXPECT(cdisasm_decode(
            CDISASM_ARM_CPU_ANY, CDISASM_ARM_MODE_A64,
            bytes, sizeof(bytes), TEST_ADDRESS,
            CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
#endif
        EXPECT(memcmp(&little, &other, sizeof(little)) == 0);
        for (boundary = 0u; boundary < 4u; ++boundary) {
            cdisasm_status expected = boundary == 0u
                ? CDISASM_STATUS_END_OF_INPUT : CDISASM_STATUS_TRUNCATED;

            memset(&other, 0xa5, sizeof(other));
            EXPECT(decode_word(words[index], CDISASM_ARM_CPU_ANY, boundary,
                CDISASM_ARM_DECODE_OPTION_NONE, &other) == 0u);
            EXPECT(instruction_is_error_only(&other, expected));
        }
    }
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(uint32_t word, const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[80];

    memset(&instruction, 0xa5, sizeof(instruction));
    EXPECT(decode_word(word, CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == strlen(expected));
    EXPECT(strcmp(text, expected) == 0);
    EXPECT(cdisasm_arm_format(
        &instruction, CDISASM_FORMAT_SYNTAX_7, NULL, 0u)
        == strlen(expected));
}

static void reject_forgery(cdisasm_arm_instruction *instruction)
{
    char text[80];

    memset(text, 0xa5, sizeof(text));
    EXPECT(cdisasm_arm_format(
        instruction, CDISASM_FORMAT_SYNTAX_ARM_CANONICAL,
        text, sizeof(text)) == 0u);
    EXPECT(text[0] == '\0');
}

static void test_formatter(void)
{
    cdisasm_arm_instruction instruction;
    cdisasm_arm_instruction forged;

    expect_format(UINT32_C(0x0460c3e0), "sqinch z0.h");
    expect_format(UINT32_C(0x04a2c4bf), "uqincw z31.s, vl5, mul #3");
    expect_format(UINT32_C(0x0420f3e3), "sqincb x3, w3");
    expect_format(UINT32_C(0x0423f485), "uqincb w5, vl4, mul #4");
    expect_format(UINT32_C(0x0434f4e6), "uqincb x6, vl7, mul #5");
    expect_format(UINT32_C(0x25a08861), "cntp x1, p2, p3.s");
    expect_format(UINT32_C(0x25608324), "cntp x4, pn9.h, vlx2");
    expect_format(UINT32_C(0x25e087ff), "cntp xzr, pn15.d, vlx4");
    expect_format(UINT32_C(0x25218000), "firstp x0, p0, p0.b");
    expect_format(UINT32_C(0x25e2bdff), "lastp xzr, p15, p15.d");
    expect_format(UINT32_C(0x25688000), "sqincp z0.h, p0.h");
    expect_format(UINT32_C(0x25288907), "sqincp x7, p8.b, w7");
    expect_format(UINT32_C(0x25688d49), "sqincp x9, p10.h");
    expect_format(UINT32_C(0x252c8928), "incp x8, p9.b");

    EXPECT(decode_word(UINT32_C(0x25608324), CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    forged = instruction;
    forged.operand[1].reg = CDISASM_ARM_REG_P9;
    reject_forgery(&forged);
    forged = instruction;
    forged.operand[1].flags = CDISASM_OPERAND_FLAG_NONE;
    reject_forgery(&forged);
    forged = instruction;
    forged.operand[2].imm = 3u;
    reject_forgery(&forged);
    forged = instruction;
    forged.form_id = UINT16_C(2597);
    reject_forgery(&forged);

    EXPECT(decode_word(UINT32_C(0x0420f3e3), CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    forged = instruction;
    forged.operand[1].reg = CDISASM_ARM_REG_W4;
    reject_forgery(&forged);
    forged = instruction;
    forged.operand[0].access = CDISASM_OPERAND_ACCESS_READ_WRITE;
    reject_forgery(&forged);
    forged = instruction;
    forged.raw_instruction ^= UINT32_C(0x00010000);
    reject_forgery(&forged);

    EXPECT(decode_word(UINT32_C(0x25a08861), CDISASM_ARM_CPU_ANY, 4u,
        CDISASM_ARM_DECODE_OPTION_NONE, &instruction) == 4u);
    forged = instruction;
    forged.operand[1].flags = CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED;
    reject_forgery(&forged);
}
#else
static void test_formatter(void)
{
}
#endif

int main(void)
{
    test_saturating_parent_envelopes();
    test_predicate_parent_envelopes();
    test_feature_alternatives();
    test_transport();
    test_formatter();

    if (failures != 0) {
        fprintf(stderr, "%d SVE saturating/predicate-count test(s) failed\n",
            failures);
        return 1;
    }
    printf("SVE saturating/predicate-count tests passed "
           "(720896 saturating and 132096 predicate allocated; "
           "359424 reserved encodings)\n");
    return 0;
}
