#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm_arm.h"

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CORPUS_LINE_CAPACITY 4096
#define CORPUS_FIELD_COUNT 14
#define CORPUS_BYTE_CAPACITY 64

static int failures;

static void report_failure(size_t line_number, const char *case_name,
                           const char *message)
{
    fprintf(stderr, "ARM corpus line %zu (%s): %s\n",
            line_number,
            case_name != NULL && case_name[0] != '\0' ? case_name : "unknown",
            message);
    ++failures;
}

static int parse_u32(const char *text, uint32_t *value)
{
    char *end = NULL;
    unsigned long parsed;

    if (text == NULL || text[0] == '\0' || text[0] == '-') {
        return 0;
    }
    errno = 0;
    parsed = strtoul(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0' || parsed > UINT32_MAX) {
        return 0;
    }
    *value = (uint32_t)parsed;
    return 1;
}

static int parse_u64(const char *text, uint64_t *value)
{
    char *end = NULL;
    unsigned long long parsed;

    if (text == NULL || text[0] == '\0' || text[0] == '-') {
        return 0;
    }
    errno = 0;
    parsed = strtoull(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0') {
        return 0;
    }
    *value = (uint64_t)parsed;
    return 1;
}

static int parse_status(const char *text, cdisasm_status *status)
{
    static const struct status_name {
        const char *name;
        cdisasm_status value;
    } names[] = {
        {"OK", CDISASM_STATUS_OK},
        {"INVALID_ARGUMENT", CDISASM_STATUS_INVALID_ARGUMENT},
        {"END_OF_INPUT", CDISASM_STATUS_END_OF_INPUT},
        {"TRUNCATED", CDISASM_STATUS_TRUNCATED},
        {"INVALID_INSTRUCTION", CDISASM_STATUS_INVALID_INSTRUCTION},
        {"UNSUPPORTED_INSTRUCTION", CDISASM_STATUS_UNSUPPORTED_INSTRUCTION},
        {"INTERNAL_ERROR", CDISASM_STATUS_INTERNAL_ERROR},
        {"EXTRA_OK", USE_EXTRA_OPCODES
            ? CDISASM_STATUS_OK
            : CDISASM_STATUS_UNSUPPORTED_INSTRUCTION},
        {"EXTRA_INVALID", CDISASM_STATUS_INVALID_INSTRUCTION},
        {"EXTRA_FALLBACK_INVALID", USE_EXTRA_OPCODES
            ? CDISASM_STATUS_INVALID_INSTRUCTION
            : CDISASM_STATUS_UNSUPPORTED_INSTRUCTION},
        {"EXTRA_PROFILE", USE_EXTRA_OPCODES
            ? CDISASM_STATUS_INVALID_INSTRUCTION
            : CDISASM_STATUS_UNSUPPORTED_INSTRUCTION}
    };
    size_t index;

    for (index = 0; index < sizeof(names) / sizeof(names[0]); ++index) {
        if (strcmp(text, names[index].name) == 0) {
            *status = names[index].value;
            return 1;
        }
    }
    return 0;
}

static int hex_value(unsigned char character)
{
    if (character >= '0' && character <= '9') {
        return (int)(character - '0');
    }
    character = (unsigned char)tolower(character);
    if (character >= 'a' && character <= 'f') {
        return (int)(character - 'a') + 10;
    }
    return -1;
}

static int parse_hex_bytes(const char *text, uint8_t *bytes, size_t *byte_count)
{
    int high_nibble = -1;
    size_t count = 0;

    if (strcmp(text, "-") == 0) {
        *byte_count = 0;
        return 1;
    }
    while (*text != '\0') {
        int nibble;

        if (isspace((unsigned char)*text)) {
            ++text;
            continue;
        }
        nibble = hex_value((unsigned char)*text++);
        if (nibble < 0) {
            return 0;
        }
        if (high_nibble < 0) {
            high_nibble = nibble;
        } else {
            if (count == CORPUS_BYTE_CAPACITY) {
                return 0;
            }
            bytes[count++] = (uint8_t)((high_nibble << 4) | nibble);
            high_nibble = -1;
        }
    }
    if (high_nibble >= 0 || count == 0) {
        return 0;
    }
    *byte_count = count;
    return 1;
}

static int fixed_advsimd_shift_right_immediate(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand, uint8_t operand_index)
{
    uint32_t word = instruction->raw_instruction;
    uint32_t scalar_operation = word & UINT32_C(0xffc0fc00);
    uint32_t vector_operation = word & UINT32_C(0xbf80fc00);
    int scalar = (scalar_operation == UINT32_C(0x5f400400)
            && instruction->form_id == UINT16_C(5853)
            && instruction->name_id == CDISASM_ARM_NAME_SSHR)
        || (scalar_operation == UINT32_C(0x7f400400)
            && instruction->form_id == UINT16_C(5863)
            && instruction->name_id == CDISASM_ARM_NAME_USHR)
        || (scalar_operation == UINT32_C(0x5f401400)
            && instruction->form_id == UINT16_C(5854)
            && instruction->name_id == CDISASM_ARM_NAME_SSRA)
        || (scalar_operation == UINT32_C(0x7f401400)
            && instruction->form_id == UINT16_C(5864)
            && instruction->name_id == CDISASM_ARM_NAME_USRA)
        || (scalar_operation == UINT32_C(0x5f402400)
            && instruction->form_id == UINT16_C(5855)
            && instruction->name_id == CDISASM_ARM_NAME_SRSHR)
        || (scalar_operation == UINT32_C(0x7f402400)
            && instruction->form_id == UINT16_C(5865)
            && instruction->name_id == CDISASM_ARM_NAME_URSHR)
        || (scalar_operation == UINT32_C(0x5f403400)
            && instruction->form_id == UINT16_C(5856)
            && instruction->name_id == CDISASM_ARM_NAME_SRSRA)
        || (scalar_operation == UINT32_C(0x7f403400)
            && instruction->form_id == UINT16_C(5866)
            && instruction->name_id == CDISASM_ARM_NAME_URSRA)
        || (scalar_operation == UINT32_C(0x5f405400)
            && instruction->form_id == UINT16_C(5857)
            && instruction->name_id == CDISASM_ARM_NAME_SHL)
        || (scalar_operation == UINT32_C(0x7f404400)
            && instruction->form_id == UINT16_C(5867)
            && instruction->name_id == CDISASM_ARM_NAME_SRI)
        || (scalar_operation == UINT32_C(0x7f405400)
            && instruction->form_id == UINT16_C(5868)
            && instruction->name_id == CDISASM_ARM_NAME_SLI);
    int vector = (vector_operation == UINT32_C(0x0f000400)
            && instruction->form_id == UINT16_C(6215)
            && instruction->name_id == CDISASM_ARM_NAME_SSHR)
        || (vector_operation == UINT32_C(0x2f000400)
            && instruction->form_id == UINT16_C(6228)
            && instruction->name_id == CDISASM_ARM_NAME_USHR)
        || (vector_operation == UINT32_C(0x0f001400)
            && instruction->form_id == UINT16_C(6216)
            && instruction->name_id == CDISASM_ARM_NAME_SSRA)
        || (vector_operation == UINT32_C(0x2f001400)
            && instruction->form_id == UINT16_C(6229)
            && instruction->name_id == CDISASM_ARM_NAME_USRA)
        || (vector_operation == UINT32_C(0x0f002400)
            && instruction->form_id == UINT16_C(6217)
            && instruction->name_id == CDISASM_ARM_NAME_SRSHR)
        || (vector_operation == UINT32_C(0x2f002400)
            && instruction->form_id == UINT16_C(6230)
            && instruction->name_id == CDISASM_ARM_NAME_URSHR)
        || (vector_operation == UINT32_C(0x0f003400)
            && instruction->form_id == UINT16_C(6218)
            && instruction->name_id == CDISASM_ARM_NAME_SRSRA)
        || (vector_operation == UINT32_C(0x2f003400)
            && instruction->form_id == UINT16_C(6231)
            && instruction->name_id == CDISASM_ARM_NAME_URSRA)
        || (vector_operation == UINT32_C(0x0f005400)
            && instruction->form_id == UINT16_C(6219)
            && instruction->name_id == CDISASM_ARM_NAME_SHL)
        || (vector_operation == UINT32_C(0x2f004400)
            && instruction->form_id == UINT16_C(6232)
            && instruction->name_id == CDISASM_ARM_NAME_SRI)
        || (vector_operation == UINT32_C(0x2f005400)
            && instruction->form_id == UINT16_C(6233)
            && instruction->name_id == CDISASM_ARM_NAME_SLI);
    unsigned immh = (word >> 19) & 15u;
    unsigned q = (word >> 30) & 1u;
    unsigned element_bits;
    unsigned immediate;
    int left_shift = scalar_operation == UINT32_C(0x5f405400)
        || scalar_operation == UINT32_C(0x7f405400)
        || vector_operation == UINT32_C(0x0f005400)
        || vector_operation == UINT32_C(0x2f005400);

    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || operand_index != 2u || (!scalar && !vector)
        || (vector && (immh == 0u
            || (q == 0u && (immh & 8u) != 0u)))) {
        return 0;
    }
    element_bits = scalar || (immh & 8u) != 0u ? 64u
        : (immh & 4u) != 0u ? 32u
        : (immh & 2u) != 0u ? 16u : 8u;
    immediate = left_shift
        ? ((immh << 3) | ((word >> 16) & 7u)) - element_bits
        : 2u * element_bits - ((immh << 3) | ((word >> 16) & 7u));
    return (left_shift ? immediate < element_bits
                       : immediate >= 1u && immediate <= element_bits)
        && operand->type == CDISASM_OPERAND_IMMEDIATE
        && operand->imm == (uint64_t)immediate
        && operand->size == 1u
        && operand->access == CDISASM_OPERAND_ACCESS_READ
        && operand->reg == CDISASM_ARM_REG_NONE
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u
        && operand->address == 0u
        && operand->flags == CDISASM_OPERAND_FLAG_NONE
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u
        && operand->extend_type == CDISASM_ARM_EXTEND_NONE
        && operand->scale == 0u;
}

static int fixed_advsimd_ext_immediate(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand, uint8_t operand_index)
{
    uint32_t word = instruction->raw_instruction;
    if (instruction->isa_id == CDISASM_ARM_ISA_T32) {
        word = (word << 16) | (word >> 16);
    }
    unsigned q = (instruction->isa_id == CDISASM_ARM_ISA_A32
            || instruction->isa_id == CDISASM_ARM_ISA_T32)
        ? (word >> 6) & 1u : (word >> 30) & 1u;
    unsigned imm4 = (instruction->isa_id == CDISASM_ARM_ISA_A32
            || instruction->isa_id == CDISASM_ARM_ISA_T32)
        ? (word >> 8) & 15u : (word >> 11) & 15u;
    int recognized = (instruction->isa_id == CDISASM_ARM_ISA_A64
            && (word & UINT32_C(0xbfe08400)) == UINT32_C(0x2e000000)
            && instruction->form_id == UINT16_C(5910)
            && instruction->name_id == CDISASM_ARM_NAME_EXT)
        || (instruction->isa_id == CDISASM_ARM_ISA_A32
            && ((word & UINT32_C(0xffb00050)) == UINT32_C(0xf2b00000)
                || (word & UINT32_C(0xffb00050)) == UINT32_C(0xf2b00040))
            && instruction->name_id == CDISASM_ARM_NAME_VEXT)
        || (instruction->isa_id == CDISASM_ARM_ISA_T32
            && ((word & UINT32_C(0xffb00050)) == UINT32_C(0xefb00000)
                || (word & UINT32_C(0xffb00050)) == UINT32_C(0xefb00040))
            && instruction->name_id == CDISASM_ARM_NAME_VEXT);

    return recognized
        && (q != 0u || imm4 < 8u)
        && operand_index == 3u
        && operand->type == CDISASM_OPERAND_IMMEDIATE
        && operand->imm == imm4
        && operand->size == 1u
        && operand->access == CDISASM_OPERAND_ACCESS_READ
        && operand->reg == CDISASM_ARM_REG_NONE
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u
        && operand->address == 0u
        && operand->flags == CDISASM_OPERAND_FLAG_NONE
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u
        && operand->extend_type == CDISASM_ARM_EXTEND_NONE
        && operand->scale == 0u;
}

static int fixed_advsimd_shift_narrow_widen_immediate(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand, uint8_t operand_index)
{
    uint32_t word = instruction->raw_instruction;
    if (instruction->isa_id == CDISASM_ARM_ISA_T32) {
        word = (word << 16) | (word >> 16);
    }
    uint32_t operation = word & UINT32_C(0xbf80fc00);
    unsigned immh = (word >> 19) & 15u;
    unsigned narrow_bits;
    unsigned encoded;
    unsigned immediate;
    cdisasm_arm_form_id form_id;
    cdisasm_arm_name_id name_id;
    int widening;

    if ((instruction->isa_id == CDISASM_ARM_ISA_A32
            || instruction->isa_id == CDISASM_ARM_ISA_T32)
        && operand_index == 2u
        && (instruction->name_id == CDISASM_ARM_NAME_VSHRN
            || instruction->name_id == CDISASM_ARM_NAME_VRSHRN)
        && (((instruction->isa_id == CDISASM_ARM_ISA_A32)
                && ((word & UINT32_C(0xff800fd0))
                        == UINT32_C(0xf2800810)
                    || (word & UINT32_C(0xff800fd0))
                        == UINT32_C(0xf2800850)))
            || ((instruction->isa_id == CDISASM_ARM_ISA_T32)
                && ((word & UINT32_C(0xff800fd0))
                        == UINT32_C(0xef800810)
                    || (word & UINT32_C(0xff800fd0))
                        == UINT32_C(0xef800850))))) {
        unsigned imm6 = (word >> 16) & 63u;
        unsigned source_bits = (imm6 & 32u) != 0u ? 64u
            : (imm6 & 16u) != 0u ? 32u
            : (imm6 & 8u) != 0u ? 16u : 0u;
        unsigned a32_immediate = source_bits - imm6;

        return source_bits != 0u && a32_immediate >= 1u
            && a32_immediate <= source_bits / 2u
            && operand->type == CDISASM_OPERAND_IMMEDIATE
            && operand->imm == (uint64_t)a32_immediate
            && operand->size == 1u
            && operand->access == CDISASM_OPERAND_ACCESS_READ
            && operand->reg == CDISASM_ARM_REG_NONE
            && operand->base_reg == CDISASM_ARM_REG_NONE
            && operand->index_reg == CDISASM_ARM_REG_NONE
            && operand->register_list == 0u
            && operand->address == 0u
            && operand->flags == CDISASM_OPERAND_FLAG_NONE
            && operand->shift_type == CDISASM_ARM_SHIFT_NONE
            && operand->shift_amount == 0u
            && operand->extend_type == CDISASM_ARM_EXTEND_NONE
            && operand->scale == 0u;
    }

    switch (operation) {
        case UINT32_C(0x0f008400):
            form_id = UINT16_C(6221);
            name_id = CDISASM_ARM_NAME_SHRN;
            widening = 0;
            break;
        case UINT32_C(0x0f008c00):
            form_id = UINT16_C(6222);
            name_id = CDISASM_ARM_NAME_RSHRN;
            widening = 0;
            break;
        case UINT32_C(0x0f00a400):
            form_id = UINT16_C(6225);
            name_id = CDISASM_ARM_NAME_SSHLL;
            widening = 1;
            break;
        case UINT32_C(0x2f00a400):
            form_id = UINT16_C(6240);
            name_id = CDISASM_ARM_NAME_USHLL;
            widening = 1;
            break;
        default:
            return 0;
    }
    if (instruction->isa_id != CDISASM_ARM_ISA_A64
        || instruction->form_id != form_id
        || instruction->name_id != name_id
        || operand_index != 2u || immh < 1u || immh > 7u) {
        return 0;
    }
    narrow_bits = (immh & 4u) != 0u ? 32u
        : (immh & 2u) != 0u ? 16u : 8u;
    encoded = (immh << 3) | ((word >> 16) & 7u);
    immediate = widening ? encoded - narrow_bits
                         : 2u * narrow_bits - encoded;
    /* Shift-zero widening forms decode to the two-operand SXTL/UXTL
     * preferred aliases and therefore cannot reach this exception. */
    return (!widening || immediate != 0u)
        && operand->type == CDISASM_OPERAND_IMMEDIATE
        && operand->imm == (uint64_t)immediate
        && operand->size == 1u
        && operand->access == CDISASM_OPERAND_ACCESS_READ
        && operand->reg == CDISASM_ARM_REG_NONE
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u
        && operand->address == 0u
        && operand->flags == CDISASM_OPERAND_FLAG_NONE
        && operand->shift_type == CDISASM_ARM_SHIFT_NONE
        && operand->shift_amount == 0u
        && operand->extend_type == CDISASM_ARM_EXTEND_NONE
        && operand->scale == 0u;
}

static int fixed_advsimd_modified_immediate(
    const cdisasm_arm_instruction *instruction,
    const cdisasm_arm_operand *operand, uint8_t operand_index)
{
    uint32_t word = instruction->raw_instruction;
    unsigned cmode = (word >> 12) & 15u;
    unsigned encoded = (((word >> 16) & 7u) << 5)
        | ((word >> 5) & 31u);
    cdisasm_arm_form_id form_id = CDISASM_ARM_FORM_NONE;
    cdisasm_arm_name_id name_id = CDISASM_ARM_NAME_NONE;
    cdisasm_arm_shift_type shift_type = CDISASM_ARM_SHIFT_NONE;
    uint8_t shift_amount = 0u;
    uint64_t immediate = encoded;

    if ((instruction->isa_id == CDISASM_ARM_ISA_A32
            || instruction->isa_id == CDISASM_ARM_ISA_T32)
        && (instruction->name_id == CDISASM_ARM_NAME_VMOV
            || instruction->name_id == CDISASM_ARM_NAME_VMVN
            || instruction->name_id == CDISASM_ARM_NAME_VORR
            || instruction->name_id == CDISASM_ARM_NAME_VBIC)
        && operand_index == 1u) {
        return operand->type == CDISASM_OPERAND_IMMEDIATE
            && (operand->size == 2u || operand->size == 4u
                || operand->size == 8u)
            && operand->access == CDISASM_OPERAND_ACCESS_READ
            && operand->reg == CDISASM_ARM_REG_NONE
            && operand->base_reg == CDISASM_ARM_REG_NONE
            && operand->index_reg == CDISASM_ARM_REG_NONE
            && operand->register_list == 0u
            && operand->address == 0u
            && operand->flags == CDISASM_OPERAND_FLAG_NONE
            && operand->shift_type == CDISASM_ARM_SHIFT_NONE
            && operand->shift_amount == 0u
            && operand->extend_type == CDISASM_ARM_EXTEND_NONE
            && operand->scale == 0u;
    }

    if ((word & UINT32_C(0xbff8fc00)) == UINT32_C(0x0f00f400)
        || (word & UINT32_C(0xbff8fc00)) == UINT32_C(0x0f00fc00)
        || (word & UINT32_C(0xfff8fc00)) == UINT32_C(0x6f00f400)) {
        unsigned size = (word & UINT32_C(0xbff8fc00))
                == UINT32_C(0x0f00fc00) ? 2u
            : (word & UINT32_C(0xfff8fc00))
                == UINT32_C(0x6f00f400) ? 8u : 4u;
        unsigned total = size * 8u;
        unsigned exponent_bits = size == 2u ? 5u : size == 4u ? 8u : 11u;
        unsigned fraction_bits = total - exponent_bits - 1u;
        unsigned selector = (encoded >> 6) & 1u;
        uint64_t exponent = (uint64_t)(selector ^ 1u)
            << (exponent_bits - 1u);
        if (selector) exponent |= ((UINT64_C(1) << (exponent_bits - 3u)) - 1u) << 2u;
        exponent |= (encoded >> 4) & 3u;
        immediate = ((uint64_t)(encoded >> 7) << (total - 1u))
            | (exponent << fraction_bits)
            | ((uint64_t)(encoded & 15u) << (fraction_bits - 4u));
        form_id = size == 2u ? UINT16_C(6206)
            : size == 8u ? UINT16_C(6214) : UINT16_C(6205);
        name_id = CDISASM_ARM_NAME_FMOV;
    } else if ((word & UINT32_C(0xbff89c00)) == UINT32_C(0x0f001400)
        || (word & UINT32_C(0xbff89c00)) == UINT32_C(0x2f001400)) {
        form_id = (word & UINT32_C(0x20000000)) == 0u
            ? UINT16_C(6200) : UINT16_C(6208);
        name_id = (word & UINT32_C(0x20000000)) == 0u
            ? CDISASM_ARM_NAME_ORR : CDISASM_ARM_NAME_BIC;
        shift_amount = (uint8_t)(4u * (cmode & ~1u));
        shift_type = shift_amount == 0u
            ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL;
        immediate <<= shift_amount;
    } else if ((word & UINT32_C(0xbff8dc00))
            == UINT32_C(0x0f009400)
        || (word & UINT32_C(0xbff8dc00)) == UINT32_C(0x2f009400)) {
        form_id = (word & UINT32_C(0x20000000)) == 0u
            ? UINT16_C(6202) : UINT16_C(6210);
        name_id = (word & UINT32_C(0x20000000)) == 0u
            ? CDISASM_ARM_NAME_ORR : CDISASM_ARM_NAME_BIC;
        shift_amount = (cmode & 2u) != 0u ? 8u : 0u;
        shift_type = shift_amount == 0u
            ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL;
        immediate <<= shift_amount;
    } else if ((word & UINT32_C(0xbff89c00)) == UINT32_C(0x0f000400)
        || (word & UINT32_C(0xbff89c00)) == UINT32_C(0x2f000400)) {
        form_id = (word & UINT32_C(0x20000000)) == 0u
            ? UINT16_C(6199) : UINT16_C(6207);
        name_id = (word & UINT32_C(0x20000000)) == 0u
            ? CDISASM_ARM_NAME_MOVI : CDISASM_ARM_NAME_MVNI;
        shift_amount = (uint8_t)(4u * cmode);
        shift_type = shift_amount == 0u
            ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL;
        immediate <<= shift_amount;
    } else if ((word & UINT32_C(0xbff8dc00))
            == UINT32_C(0x0f008400)
        || (word & UINT32_C(0xbff8dc00)) == UINT32_C(0x2f008400)) {
        form_id = (word & UINT32_C(0x20000000)) == 0u
            ? UINT16_C(6201) : UINT16_C(6209);
        name_id = (word & UINT32_C(0x20000000)) == 0u
            ? CDISASM_ARM_NAME_MOVI : CDISASM_ARM_NAME_MVNI;
        shift_amount = (cmode & 2u) != 0u ? 8u : 0u;
        shift_type = shift_amount == 0u
            ? CDISASM_ARM_SHIFT_NONE : CDISASM_ARM_SHIFT_LSL;
        immediate <<= shift_amount;
    } else if ((word & UINT32_C(0xbff8ec00))
            == UINT32_C(0x0f00c400)
        || (word & UINT32_C(0xbff8ec00)) == UINT32_C(0x2f00c400)) {
        form_id = (word & UINT32_C(0x20000000)) == 0u
            ? UINT16_C(6203) : UINT16_C(6211);
        name_id = (word & UINT32_C(0x20000000)) == 0u
            ? CDISASM_ARM_NAME_MOVI : CDISASM_ARM_NAME_MVNI;
        shift_type = CDISASM_ARM_SHIFT_MSL;
        shift_amount = (cmode & 1u) != 0u ? 16u : 8u;
        immediate = (immediate << shift_amount)
            | ((UINT64_C(1) << shift_amount) - UINT64_C(1));
    } else if ((word & UINT32_C(0xbff8fc00))
            == UINT32_C(0x0f00e400)) {
        form_id = UINT16_C(6204);
        name_id = CDISASM_ARM_NAME_MOVI;
    } else if ((word & UINT32_C(0xfff8fc00))
            == UINT32_C(0x2f00e400)
        || (word & UINT32_C(0xfff8fc00)) == UINT32_C(0x6f00e400)) {
        form_id = (word & UINT32_C(0x40000000)) == 0u
            ? UINT16_C(6212) : UINT16_C(6213);
        name_id = CDISASM_ARM_NAME_MOVI;
        immediate = UINT64_C(0);
        for (unsigned bit = 0u; bit < 8u; ++bit) {
            if ((encoded & (1u << bit)) != 0u) {
                immediate |= UINT64_C(0xff) << (8u * bit);
            }
        }
    }
    return instruction->isa_id == CDISASM_ARM_ISA_A64
        && operand_index == 1u && form_id != CDISASM_ARM_FORM_NONE
        && instruction->form_id == form_id
        && instruction->name_id == name_id
        && operand->type == CDISASM_OPERAND_IMMEDIATE
        && operand->imm == immediate
        && operand->size == 1u
        && operand->access == CDISASM_OPERAND_ACCESS_READ
        && operand->reg == CDISASM_ARM_REG_NONE
        && operand->base_reg == CDISASM_ARM_REG_NONE
        && operand->index_reg == CDISASM_ARM_REG_NONE
        && operand->register_list == 0u
        && operand->address == 0u
        && operand->flags == CDISASM_OPERAND_FLAG_NONE
        && operand->shift_type == shift_type
        && operand->shift_amount == shift_amount
        && operand->extend_type == CDISASM_ARM_EXTEND_NONE
        && operand->scale == 0u;
}

static int split_fields(char *line, char **fields)
{
    size_t index;
    char *cursor = line;

    for (index = 0; index < CORPUS_FIELD_COUNT; ++index) {
        char *separator;

        fields[index] = cursor;
        separator = strchr(cursor, '\t');
        if (index + 1u == CORPUS_FIELD_COUNT) {
            return separator == NULL;
        }
        if (separator == NULL) {
            return 0;
        }
        *separator = '\0';
        cursor = separator + 1;
    }
    return 0;
}

static int failure_result_is_zeroed(
    const cdisasm_arm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_arm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static uint32_t read_u32_le(const uint8_t *bytes)
{
    return (uint32_t)bytes[0]
        | ((uint32_t)bytes[1] << 8)
        | ((uint32_t)bytes[2] << 16)
        | ((uint32_t)bytes[3] << 24);
}

static uint16_t read_u16_le(const uint8_t *bytes)
{
    return (uint16_t)((uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8));
}

static uint32_t read_u32_be(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24)
        | ((uint32_t)bytes[1] << 16)
        | ((uint32_t)bytes[2] << 8)
        | (uint32_t)bytes[3];
}

static uint16_t read_u16_be(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8) | (uint16_t)bytes[1]);
}

static void make_big_endian_bytes(
    cdisasm_arm_mode mode,
    const uint8_t *little_endian,
    uint8_t *big_endian,
    uint32_t decoded_size)
{
    uint32_t offset;

    if (mode == CDISASM_ARM_MODE_T32) {
        for (offset = 0; offset < decoded_size; offset += 2u) {
            big_endian[offset] = little_endian[offset + 1u];
            big_endian[offset + 1u] = little_endian[offset];
        }
    } else {
        for (offset = 0; offset < decoded_size; ++offset) {
            big_endian[offset] = little_endian[decoded_size - offset - 1u];
        }
    }
}

static int operand_is_zeroed(const cdisasm_arm_operand *operand)
{
    cdisasm_arm_operand expected;

    memset(&expected, 0, sizeof(expected));
    return memcmp(operand, &expected, sizeof(expected)) == 0;
}

static int register_pair_is_architecturally_consecutive(
    cdisasm_arm_reg_id first,
    cdisasm_arm_reg_id second)
{
    if (first >= CDISASM_ARM_REG_W0 && first <= CDISASM_ARM_REG_W30) {
        unsigned encoding = (unsigned)(first - CDISASM_ARM_REG_W0);
        cdisasm_arm_reg_id expected = encoding == 30u
            ? CDISASM_ARM_REG_WZR
            : (cdisasm_arm_reg_id)(first + 1u);

        return (encoding & 1u) == 0u && second == expected;
    }
    if (first >= CDISASM_ARM_REG_X0 && first <= CDISASM_ARM_REG_X30) {
        unsigned encoding = (unsigned)(first - CDISASM_ARM_REG_X0);
        cdisasm_arm_reg_id expected = encoding == 30u
            ? CDISASM_ARM_REG_XZR
            : (cdisasm_arm_reg_id)(first + 1u);

        return (encoding & 1u) == 0u && second == expected;
    }
    return 0;
}

static int fixed_advsimd_sha_special_register(
    const cdisasm_arm_instruction *instruction, uint8_t operand_index)
{
    static const cdisasm_arm_name_id names[8] = {
        CDISASM_ARM_NAME_SHA1C, CDISASM_ARM_NAME_SHA1P,
        CDISASM_ARM_NAME_SHA1M, CDISASM_ARM_NAME_SHA1SU0,
        CDISASM_ARM_NAME_SHA256H, CDISASM_ARM_NAME_SHA256H2,
        CDISASM_ARM_NAME_SHA256SU1, CDISASM_ARM_NAME_SHA1H
    };
    uint32_t word = instruction->raw_instruction;
    unsigned operation;

    if (instruction->isa_id != CDISASM_ARM_ISA_A64) {
        return 0;
    }
    if (operand_index < 2u
        && ((word & UINT32_C(0xffe0fc00))
                == UINT32_C(0xce608000)
            || (word & UINT32_C(0xffe0fc00))
                == UINT32_C(0xce608400))) {
        return (instruction->form_id == UINT16_C(6291)
                    && instruction->name_id == CDISASM_ARM_NAME_SHA512H)
            || (instruction->form_id == UINT16_C(6292)
                    && instruction->name_id == CDISASM_ARM_NAME_SHA512H2);
    }
    for (operation = 0u; operation < 7u; ++operation) {
        if ((word & UINT32_C(0xffe0fc00))
                == UINT32_C(0x5e000000)
                    + ((uint32_t)operation << 12)) {
            return instruction->form_id == UINT16_C(5731) + operation
                && instruction->name_id == names[operation]
                && operand_index < 2u
                && (operation <= 2u || operation == 4u
                    || operation == 5u);
        }
    }
    return (word & UINT32_C(0xfffffc00)) == UINT32_C(0x5e280800)
        && instruction->form_id == UINT16_C(5738)
        && instruction->name_id == names[7]
        && operand_index < 2u;
}

static int successful_result_is_well_formed(
    const cdisasm_arm_instruction *instruction,
    cdisasm_arm_mode mode,
    const uint8_t *bytes,
    size_t byte_count,
    uint64_t address,
    cdisasm_arm_decode_option flags,
    uint32_t decoded_size)
{
    uint8_t index;
    int found_relative_target = 0;
    unsigned atomic_memory_count = 0;
    cdisasm_operand_access atomic_memory_access =
        CDISASM_OPERAND_ACCESS_NONE;
    const uint32_t known_instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS
        | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
        | CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
        | CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
        | CDISASM_ARM_INSTRUCTION_FLAG_LINK
        | CDISASM_ARM_INSTRUCTION_FLAG_BYTE
        | CDISASM_ARM_INSTRUCTION_FLAG_USER_REGISTERS
        | CDISASM_ARM_INSTRUCTION_FLAG_UNPRIVILEGED
        | CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL
        | CDISASM_ARM_INSTRUCTION_FLAG_UNPREDICTABLE
        | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT
        | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT
        | CDISASM_ARM_INSTRUCTION_FLAG_SIMD
        | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
        | CDISASM_ARM_INSTRUCTION_FLAG_APPLE_PROPRIETARY
        | CDISASM_ARM_INSTRUCTION_FLAG_APPLE_AMX
        | CDISASM_ARM_INSTRUCTION_FLAG_APPLE_MUL53
        | CDISASM_ARM_INSTRUCTION_FLAG_APPLE_SYSTEM
        | CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
        | CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
        | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE
        | CDISASM_ARM_INSTRUCTION_FLAG_EXCLUSIVE
        | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR
        | CDISASM_ARM_INSTRUCTION_FLAG_PREDICATED
        | CDISASM_ARM_INSTRUCTION_FLAG_SME
        | CDISASM_ARM_INSTRUCTION_FLAG_STREAMING
        | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
        | CDISASM_ARM_INSTRUCTION_FLAG_MEMORY_TAGGING
        | CDISASM_ARM_INSTRUCTION_FLAG_POINTER_AUTH
        | CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC_PAIR
        | CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK;

    if (decoded_size == 0u || decoded_size > CDISASM_ARM_MAX_INSTRUCTION_SIZE
        || byte_count < decoded_size
        || instruction->address != address
        || instruction->opcode_size != decoded_size
        || instruction->raw_instruction
            != ((flags & CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN) != 0u
                    ? (decoded_size == 2u
                        ? (uint32_t)read_u16_be(bytes)
                        : mode == CDISASM_ARM_MODE_T32
                            ? (uint32_t)read_u16_be(bytes)
                                | ((uint32_t)read_u16_be(bytes + 2) << 16)
                            : read_u32_be(bytes))
                    : (decoded_size == 2u
                        ? (uint32_t)read_u16_le(bytes)
                        : read_u32_le(bytes)))
        || instruction->last_error_id != CDISASM_STATUS_OK
        || instruction->name_id < CDISASM_ARM_NAME_FIRST
        || instruction->name_id > CDISASM_ARM_NAME_LAST
        || instruction->operand_count > CDISASM_ARM_MAX_OPERANDS
        || instruction->condition > CDISASM_ARM_CONDITION_NV
        || (instruction->instruction_flags & ~known_instruction_flags) != 0u
        || (instruction->opcode_groups
            & ~(CDISASM_GROUP_JUMP | CDISASM_GROUP_CALL
                | CDISASM_GROUP_RETURN | CDISASM_GROUP_INTERRUPT
                | CDISASM_GROUP_INTERRUPT_RETURN
                | CDISASM_GROUP_PRIVILEGED
                | CDISASM_GROUP_RELATIVE_BRANCH
                | CDISASM_GROUP_CONDITIONAL)) != 0u) {
        return 0;
    }
    if (((instruction->instruction_flags
              & CDISASM_ARM_INSTRUCTION_FLAG_UNPREDICTABLE) != 0u
            && (instruction->instruction_flags
                & CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL) == 0u)
        || (instruction->instruction_flags
            & (CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX))
            == (CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX)
        || (instruction->instruction_flags
            & (CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT
                | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT))
            == (CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT
                | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT)) {
        return 0;
    }
    if ((mode == CDISASM_ARM_MODE_A32
            && instruction->isa_id != CDISASM_ARM_ISA_A32)
        || (mode == CDISASM_ARM_MODE_T32
            && instruction->isa_id != CDISASM_ARM_ISA_T32)
        || (mode == CDISASM_ARM_MODE_A64
            && instruction->isa_id != CDISASM_ARM_ISA_A64)) {
        return 0;
    }
    if (instruction->condition != CDISASM_ARM_CONDITION_AL
        && (instruction->opcode_groups & CDISASM_GROUP_CONDITIONAL) == 0u) {
        return 0;
    }
    if (instruction->isa_id == CDISASM_ARM_ISA_A64
        && instruction->form_id >= UINT16_C(4907)
        && instruction->form_id <= UINT16_C(4916)) {
        const cdisasm_arm_operand *data = &instruction->operand[0];
        const cdisasm_arm_operand *memory = &instruction->operand[1];
        unsigned pair = (unsigned)(instruction->form_id - UINT16_C(4907)) / 2u;
        int load = ((instruction->form_id - UINT16_C(4907)) & 1u) != 0u;
        uint8_t expected_size = pair == 1u ? 16u
            : (uint8_t)(UINT8_C(1) << (pair > 1u ? pair - 1u : pair));
        int data_register_ok = pair == 1u
            ? data->reg >= CDISASM_ARM_REG_V0
                && data->reg <= CDISASM_ARM_REG_V31
                && data->extend_type == 1u && data->scale == 16u
            : data->reg >= (pair == 0u ? CDISASM_ARM_REG_B0
                : pair == 2u ? CDISASM_ARM_REG_H0
                : pair == 3u ? CDISASM_ARM_REG_S0 : CDISASM_ARM_REG_D0)
                && data->reg <= (cdisasm_arm_reg_id)(
                    (pair == 0u ? CDISASM_ARM_REG_B0
                        : pair == 2u ? CDISASM_ARM_REG_H0
                        : pair == 3u ? CDISASM_ARM_REG_S0
                        : CDISASM_ARM_REG_D0) + 31u)
                && data->extend_type == expected_size && data->scale == 1u;
        return instruction->opcode_size == 4u
            && instruction->condition == CDISASM_ARM_CONDITION_AL
            && instruction->opcode_groups == CDISASM_GROUP_NONE
            && instruction->operand_count == 2u
            && instruction->name_id == (load
                ? CDISASM_ARM_NAME_LDAPUR : CDISASM_ARM_NAME_STLUR)
            && instruction->instruction_flags
                == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
                    | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
                    | CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
                    | (load ? CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
                            : CDISASM_ARM_INSTRUCTION_FLAG_RELEASE))
            && data->type == CDISASM_OPERAND_REGISTER
            && data->size == expected_size && data->access
                == (load ? CDISASM_OPERAND_ACCESS_WRITE
                          : CDISASM_OPERAND_ACCESS_READ)
            && data_register_ok
            && memory->type == CDISASM_OPERAND_MEMORY
            && memory->base_reg == CDISASM_ARM_REG_X0
            && memory->index_reg == CDISASM_ARM_REG_NONE
            && memory->size == expected_size
            && memory->imm == 0u && memory->flags == 0u
            && memory->access == (load ? CDISASM_OPERAND_ACCESS_READ
                                        : CDISASM_OPERAND_ACCESS_WRITE);
    }

    for (index = 0; index < instruction->operand_count; ++index) {
        const cdisasm_arm_operand *operand = &instruction->operand[index];
        const int scalable_operand =
            operand->type == CDISASM_ARM_OPERAND_SCALABLE_REGISTER
            || operand->type == CDISASM_ARM_OPERAND_PREDICATE
            || operand->type
                == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
            || operand->type == CDISASM_ARM_OPERAND_TILE
            || operand->type == CDISASM_ARM_OPERAND_PREDICATE_PAIR;
        const int whole_za_memory =
            operand->type == CDISASM_OPERAND_MEMORY
            && operand->size == 0u
            && (instruction->form_id == UINT16_C(4381)
                || instruction->form_id == UINT16_C(4382));
        const int whole_sve_memory =
            operand->type == CDISASM_OPERAND_MEMORY
            && operand->size == 0u
            && (instruction->form_id == UINT16_C(3214)
                || instruction->form_id == UINT16_C(3215)
                || instruction->form_id == UINT16_C(3469)
                || instruction->form_id == UINT16_C(3476));
        const int sve_prefetch_immediate_memory =
            operand->type == CDISASM_OPERAND_MEMORY
            && instruction->form_id >= UINT16_C(3216)
            && instruction->form_id <= UINT16_C(3219);
        const int contiguous_sve_memory =
            operand->type == CDISASM_OPERAND_MEMORY
            && ((instruction->form_id >= UINT16_C(3314)
                    && instruction->form_id <= UINT16_C(3345))
                || (instruction->form_id >= UINT16_C(3362)
                    && instruction->form_id <= UINT16_C(3365))
                || (instruction->form_id >= UINT16_C(3366)
                    && instruction->form_id <= UINT16_C(3377))
                || (instruction->form_id >= UINT16_C(3378)
                    && instruction->form_id <= UINT16_C(3380))
                || (instruction->form_id >= UINT16_C(3463)
                    && instruction->form_id <= UINT16_C(3465))
                || (instruction->form_id >= UINT16_C(3533)
                    && instruction->form_id <= UINT16_C(3536))
                || (instruction->form_id >= UINT16_C(3537)
                    && instruction->form_id <= UINT16_C(3548))
                || instruction->form_id == UINT16_C(3527)
                || instruction->form_id == UINT16_C(3528)
                || instruction->form_id == UINT16_C(3530)
                || instruction->form_id == UINT16_C(3532)
                || instruction->form_id == UINT16_C(3275)
                || instruction->form_id == UINT16_C(3276)
                || instruction->form_id == UINT16_C(3529)
                || instruction->form_id == UINT16_C(3531)
                || (instruction->form_id >= UINT16_C(3549)
                    && instruction->form_id <= UINT16_C(3676)
                    && (instruction->raw_instruction
                        & UINT32_C(0x00400000)) != 0u));
        const int multi_contiguous_memory =
            ((instruction->form_id >= UINT16_C(3366)
                    && instruction->form_id <= UINT16_C(3377))
                || (instruction->form_id >= UINT16_C(3378)
                    && instruction->form_id <= UINT16_C(3380))
                || (instruction->form_id >= UINT16_C(3463)
                    && instruction->form_id <= UINT16_C(3465))
                || (instruction->form_id >= UINT16_C(3537)
                    && instruction->form_id <= UINT16_C(3548))
                || (instruction->form_id >= UINT16_C(3549)
                    && instruction->form_id <= UINT16_C(3676)
                    && (instruction->raw_instruction
                        & UINT32_C(0x00400000)) != 0u));
        const int runtime_sized_za_memory = whole_za_memory
            || (operand->type == CDISASM_OPERAND_MEMORY
                && operand->size == 0u
                && ((instruction->form_id >= UINT16_C(4373)
                        && instruction->form_id <= UINT16_C(4380))
                    || instruction->form_id == UINT16_C(4385)
                    || instruction->form_id == UINT16_C(4386)));
        const int prefetch_memory = operand->type == CDISASM_OPERAND_MEMORY
            && operand->size == 0u
            && (instruction->name_id == CDISASM_ARM_NAME_PLD
                || instruction->name_id == CDISASM_ARM_NAME_PLDW
                || instruction->name_id == CDISASM_ARM_NAME_PLI);
        const int sizeless_operand = scalable_operand
            || operand->type == CDISASM_ARM_OPERAND_SYSTEM_REGISTER
            || operand->type == CDISASM_ARM_OPERAND_SYSTEM_OPERATION
            || runtime_sized_za_memory
            || whole_sve_memory
            || prefetch_memory;
        const int classic_counter_predicate =
            instruction->isa_id == CDISASM_ARM_ISA_A64
            && instruction->form_id == UINT16_C(2600)
            && instruction->name_id == CDISASM_ARM_NAME_CNTP
            && operand->reg >= CDISASM_ARM_REG_PN0
            && operand->reg <= CDISASM_ARM_REG_PN15;
        const int restricted_counter_predicate =
            instruction->isa_id == CDISASM_ARM_ISA_A64
            && ((instruction->form_id >= UINT16_C(2566)
                    && instruction->form_id <= UINT16_C(2573))
                || (instruction->form_id >= UINT16_C(2582)
                    && instruction->form_id <= UINT16_C(2584))
                || (instruction->form_id >= UINT16_C(3549)
                    && instruction->form_id <= UINT16_C(3676)
                    && ((instruction->form_id & UINT16_C(1)) != 0u
                        || (instruction->name_id >= CDISASM_ARM_NAME_STNT1B
                            && instruction->name_id <= CDISASM_ARM_NAME_STNT1W)
                        || instruction->name_id == CDISASM_ARM_NAME_LDNT1B
                        || instruction->name_id == CDISASM_ARM_NAME_LDNT1H
                        || instruction->name_id == CDISASM_ARM_NAME_LDNT1W
                        || instruction->name_id == CDISASM_ARM_NAME_LDNT1D))
                || instruction->form_id == UINT16_C(4215)
                || instruction->form_id == UINT16_C(4216))
            && operand->reg >= CDISASM_ARM_REG_PN8
            && operand->reg <= CDISASM_ARM_REG_PN15;
        const int pext_source = restricted_counter_predicate
            && instruction->name_id == CDISASM_ARM_NAME_PEXT
            && (instruction->form_id == UINT16_C(2582)
                || instruction->form_id == UINT16_C(2583))
            && operand->access == CDISASM_OPERAND_ACCESS_READ;
        const int indexed_psel =
            instruction->isa_id == CDISASM_ARM_ISA_A64
            && instruction->form_id == UINT16_C(2565)
            && instruction->name_id == CDISASM_ARM_NAME_PSEL
            && index == 2u;
        const int fixed_pmull_q_destination =
            instruction->isa_id == CDISASM_ARM_ISA_A64
            && instruction->form_id == UINT16_C(6103)
            && instruction->name_id == CDISASM_ARM_NAME_PMULL
            && index == 0u && operand->extend_type == 16u;
        const int fixed_sha_special_register =
            fixed_advsimd_sha_special_register(instruction, index);
        const int fixed_compare_zero_immediate =
            instruction->isa_id == CDISASM_ARM_ISA_A64
            && (instruction->form_id == UINT16_C(5777)
                || instruction->form_id == UINT16_C(5775)
                || instruction->form_id == UINT16_C(5776)
                || instruction->form_id == UINT16_C(5793)
                || instruction->form_id == UINT16_C(5794)
                || instruction->form_id == UINT16_C(5952)
                || instruction->form_id == UINT16_C(5953)
                || instruction->form_id == UINT16_C(5954)
                || instruction->form_id == UINT16_C(5967)
                || instruction->form_id == UINT16_C(5968)
                || instruction->form_id == UINT16_C(6011)
                || instruction->form_id == UINT16_C(6012)
                || instruction->form_id == UINT16_C(6013)
                || instruction->form_id == UINT16_C(6027)
                || instruction->form_id == UINT16_C(6028)
                || instruction->form_id == UINT16_C(6029)
                || instruction->form_id == UINT16_C(6044)
                || instruction->form_id == UINT16_C(6045)
                || instruction->form_id == UINT16_C(6063)
                || instruction->form_id == UINT16_C(6064))
            && (instruction->name_id == CDISASM_ARM_NAME_CMGT
                || instruction->name_id == CDISASM_ARM_NAME_CMEQ
                || instruction->name_id == CDISASM_ARM_NAME_CMGE
                || instruction->name_id == CDISASM_ARM_NAME_CMLT
                || instruction->name_id == CDISASM_ARM_NAME_CMLE
                || instruction->name_id == CDISASM_ARM_NAME_FCMGT
                || instruction->name_id == CDISASM_ARM_NAME_FCMEQ
                || instruction->name_id == CDISASM_ARM_NAME_FCMLT
                || instruction->name_id == CDISASM_ARM_NAME_FCMGE
                || instruction->name_id == CDISASM_ARM_NAME_FCMLE)
            && index == 2u
            && operand->type == CDISASM_OPERAND_IMMEDIATE;
        const int fixed_shll_immediate =
            instruction->isa_id == CDISASM_ARM_ISA_A64
            && instruction->form_id == UINT16_C(6048)
            && instruction->name_id == CDISASM_ARM_NAME_SHLL
            && index == 2u
            && operand->type == CDISASM_OPERAND_IMMEDIATE
            && (operand->imm == UINT64_C(8)
                || operand->imm == UINT64_C(16)
                || operand->imm == UINT64_C(32))
            && operand->size == 1u
            && operand->access == CDISASM_OPERAND_ACCESS_READ
            && operand->reg == CDISASM_ARM_REG_NONE
            && operand->base_reg == CDISASM_ARM_REG_NONE
            && operand->index_reg == CDISASM_ARM_REG_NONE
            && operand->register_list == 0u
            && operand->address == 0u
            && operand->flags == CDISASM_OPERAND_FLAG_NONE
            && operand->shift_type == CDISASM_ARM_SHIFT_NONE
            && operand->shift_amount == 0u
            && operand->extend_type == CDISASM_ARM_EXTEND_NONE
            && operand->scale == 0u;
        const int fixed_advsimd_scalar_immediate_shift_convert =
            instruction->isa_id == CDISASM_ARM_ISA_A64
            && index == 2u
            && operand->type == CDISASM_OPERAND_IMMEDIATE
            && (instruction->form_id == UINT16_C(5858)
                || instruction->form_id == UINT16_C(5861)
                || instruction->form_id == UINT16_C(5862)
                || instruction->form_id == UINT16_C(5869)
                || instruction->form_id == UINT16_C(5870)
                || instruction->form_id == UINT16_C(5875)
                || instruction->form_id == UINT16_C(5876))
            && operand->imm <= UINT64_C(64)
            && operand->size == 1u
            && operand->access == CDISASM_OPERAND_ACCESS_READ;
        const int fixed_a32_t32_vshll_immediate =
            (instruction->isa_id == CDISASM_ARM_ISA_A32
                || instruction->isa_id == CDISASM_ARM_ISA_T32)
            && instruction->name_id == CDISASM_ARM_NAME_VSHLL
            && index == 2u
            && operand->type == CDISASM_OPERAND_IMMEDIATE
            && operand->imm >= UINT64_C(1)
            && operand->imm <= UINT64_C(32)
            && operand->size == 1u
            && operand->access == CDISASM_OPERAND_ACCESS_READ
            && operand->reg == CDISASM_ARM_REG_NONE
            && operand->base_reg == CDISASM_ARM_REG_NONE
            && operand->index_reg == CDISASM_ARM_REG_NONE
            && operand->register_list == 0u
            && operand->address == 0u
            && operand->flags == CDISASM_OPERAND_FLAG_NONE
            && operand->shift_type == CDISASM_ARM_SHIFT_NONE
            && operand->shift_amount == 0u
            && operand->extend_type == CDISASM_ARM_EXTEND_NONE
            && operand->scale == 0u;
        const int fixed_a32_t32_vshl_immediate =
            (instruction->isa_id == CDISASM_ARM_ISA_A32
                || instruction->isa_id == CDISASM_ARM_ISA_T32)
            && (instruction->name_id == CDISASM_ARM_NAME_VSHL
                || instruction->name_id == CDISASM_ARM_NAME_VQSHL
                || instruction->name_id == CDISASM_ARM_NAME_VQSHLU
                || instruction->name_id == CDISASM_ARM_NAME_VSLI
                || instruction->name_id == CDISASM_ARM_NAME_VSRI
                || instruction->name_id == CDISASM_ARM_NAME_VSHR
                || instruction->name_id == CDISASM_ARM_NAME_VSRA
                || instruction->name_id == CDISASM_ARM_NAME_VRSHR
                || instruction->name_id == CDISASM_ARM_NAME_VRSRA
                || instruction->name_id == CDISASM_ARM_NAME_VQSHRN
                || instruction->name_id == CDISASM_ARM_NAME_VQRSHRN
                || instruction->name_id == CDISASM_ARM_NAME_VQSHRUN
                || instruction->name_id == CDISASM_ARM_NAME_VQRSHRUN)
            && index == 2u
            && operand->type == CDISASM_OPERAND_IMMEDIATE
            && operand->imm <= UINT64_C(64)
            && operand->size == 1u
            && operand->access == CDISASM_OPERAND_ACCESS_READ
            && operand->reg == CDISASM_ARM_REG_NONE
            && operand->base_reg == CDISASM_ARM_REG_NONE
            && operand->index_reg == CDISASM_ARM_REG_NONE
            && operand->register_list == 0u
            && operand->address == 0u
            && operand->flags == CDISASM_OPERAND_FLAG_NONE
            && operand->shift_type == CDISASM_ARM_SHIFT_NONE
            && operand->shift_amount == 0u
            && operand->extend_type == CDISASM_ARM_EXTEND_NONE
            && operand->scale == 0u;
        const int fixed_a32_t32_vcvt_fixed_immediate =
            (instruction->isa_id == CDISASM_ARM_ISA_A32
                || instruction->isa_id == CDISASM_ARM_ISA_T32)
            && instruction->name_id == CDISASM_ARM_NAME_VCVT
            && (instruction->instruction_flags
                & (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
                    | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT))
                == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
                    | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)
            && index == 2u
            && operand->type == CDISASM_OPERAND_IMMEDIATE
            && operand->imm >= UINT64_C(1)
            && operand->imm <= UINT64_C(32)
            && operand->size == 1u
            && operand->access == CDISASM_OPERAND_ACCESS_READ;
        const int fixed_shift_right_immediate =
            fixed_advsimd_shift_right_immediate(
                instruction, operand, index);
        const int fixed_ext_immediate =
            fixed_advsimd_ext_immediate(instruction, operand, index);
        const int fixed_shift_narrow_widen_immediate =
            fixed_advsimd_shift_narrow_widen_immediate(
                instruction, operand, index);
        const int fixed_sat_shift_convert_immediate =
            instruction->isa_id == CDISASM_ARM_ISA_A64
            && (instruction->form_id == UINT16_C(6220)
                || instruction->form_id == UINT16_C(5859)
                || instruction->form_id == UINT16_C(5860)
                || instruction->form_id == UINT16_C(5871)
                || instruction->form_id == UINT16_C(5872)
                || instruction->form_id == UINT16_C(5873)
                || instruction->form_id == UINT16_C(5874)
                || instruction->form_id == UINT16_C(6223)
                || instruction->form_id == UINT16_C(6224)
                || instruction->form_id == UINT16_C(6236)
                || instruction->form_id == UINT16_C(6237)
                || instruction->form_id == UINT16_C(6238)
                || instruction->form_id == UINT16_C(6239)
                || instruction->form_id == UINT16_C(6226)
                || instruction->form_id == UINT16_C(6227)
                || instruction->form_id == UINT16_C(6234)
                || instruction->form_id == UINT16_C(6235)
                || instruction->form_id == UINT16_C(6241)
                || instruction->form_id == UINT16_C(6242))
            && index == 2u
            && operand->type == CDISASM_OPERAND_IMMEDIATE
            && operand->size == 1u
            && operand->access == CDISASM_OPERAND_ACCESS_READ;
        const int fixed_modified_immediate =
            fixed_advsimd_modified_immediate(
                instruction, operand, index);
        const int fixed_xar_immediate =
            instruction->isa_id == CDISASM_ARM_ISA_A64
            && instruction->form_id == UINT16_C(6301)
            && instruction->name_id == CDISASM_ARM_NAME_XAR
            && index == 3u
            && operand->type == CDISASM_OPERAND_IMMEDIATE
            && operand->imm <= UINT64_C(63)
            && operand->size == 1u
            && operand->access == CDISASM_OPERAND_ACCESS_READ
            && operand->reg == CDISASM_ARM_REG_NONE
            && operand->base_reg == CDISASM_ARM_REG_NONE
            && operand->index_reg == CDISASM_ARM_REG_NONE
            && operand->register_list == 0u
            && operand->address == 0u
            && operand->flags == CDISASM_OPERAND_FLAG_NONE
            && operand->shift_type == CDISASM_ARM_SHIFT_NONE
            && operand->shift_amount == 0u
            && operand->extend_type == CDISASM_ARM_EXTEND_NONE
            && operand->scale == 0u;
        const int fixed_a32_vcmla_rotation =
            (instruction->isa_id == CDISASM_ARM_ISA_A32
                || instruction->isa_id == CDISASM_ARM_ISA_T32)
            && instruction->name_id == CDISASM_ARM_NAME_VCMLA
            && index == 3u
            && operand->type == CDISASM_OPERAND_IMMEDIATE
            && (operand->imm == UINT64_C(0)
                || operand->imm == UINT64_C(90)
                || operand->imm == UINT64_C(180)
                || operand->imm == UINT64_C(270))
            && operand->size == 1u
            && operand->access == CDISASM_OPERAND_ACCESS_READ;
        const int fixed_a64_fcmla_rotation =
            instruction->isa_id == CDISASM_ARM_ISA_A64
            && (instruction->name_id == CDISASM_ARM_NAME_FCMLA
                || instruction->name_id == CDISASM_ARM_NAME_FCADD)
            && (instruction->form_id == UINT16_C(5985)
                || instruction->form_id == UINT16_C(5986)
                || instruction->form_id == UINT16_C(6277))
            && index == 3u
            && operand->type == CDISASM_OPERAND_IMMEDIATE
            && (operand->imm == UINT64_C(0)
                || operand->imm == UINT64_C(90)
                || operand->imm == UINT64_C(180)
                || operand->imm == UINT64_C(270))
            && operand->size == 2u
            && operand->access == CDISASM_OPERAND_ACCESS_READ;
        const int fixed_a32_vdup_gpr =
            (instruction->isa_id == CDISASM_ARM_ISA_A32
                || instruction->isa_id == CDISASM_ARM_ISA_T32)
            && instruction->name_id == CDISASM_ARM_NAME_VDUP
            && index == 1u
            && operand->type == CDISASM_OPERAND_REGISTER
            && operand->reg >= CDISASM_ARM_REG_R0
            && operand->reg <= CDISASM_ARM_REG_R14
            && operand->size == 4u
            && operand->access == CDISASM_OPERAND_ACCESS_READ;
        const int fixed_a32_t32_vdup_scalar =
            (instruction->isa_id == CDISASM_ARM_ISA_A32
                || instruction->isa_id == CDISASM_ARM_ISA_T32)
            && instruction->name_id == CDISASM_ARM_NAME_VDUP
            && index == 1u
            && operand->type == CDISASM_OPERAND_REGISTER
            && operand->reg >= CDISASM_ARM_REG_D0
            && operand->reg <= CDISASM_ARM_REG_D31
            && operand->size == 8u
            && operand->access == CDISASM_OPERAND_ACCESS_READ
            && operand->flags == CDISASM_ARM_OPERAND_FLAG_HAS_LANE
            && (operand->extend_type == 1u
                || operand->extend_type == 2u
                || operand->extend_type == 4u)
            && operand->imm < 8u / operand->extend_type;
        const int fixed_a32_t32_vmov_lane =
            (instruction->isa_id == CDISASM_ARM_ISA_A32
                || instruction->isa_id == CDISASM_ARM_ISA_T32)
            && instruction->name_id == CDISASM_ARM_NAME_VMOV
            && instruction->operand_count == 2u
            && ((operand->reg >= CDISASM_ARM_REG_D0
                    && operand->reg <= CDISASM_ARM_REG_D31
                    && operand->size == 8u
                    && operand->flags == CDISASM_ARM_OPERAND_FLAG_HAS_LANE
                    && (operand->extend_type == 1u
                        || operand->extend_type == 2u
                        || operand->extend_type == 4u)
                    && operand->imm < 8u / operand->extend_type)
                || (operand->reg >= CDISASM_ARM_REG_R0
                    && operand->reg <= CDISASM_ARM_REG_R14
                    && operand->size == 4u
                    && operand->flags == CDISASM_OPERAND_FLAG_NONE))
            && (operand->access == CDISASM_OPERAND_ACCESS_READ
                || operand->access == CDISASM_OPERAND_ACCESS_WRITE);
        const int fixed_a32_t32_vfma_bf16_lane =
            (instruction->isa_id == CDISASM_ARM_ISA_A32
                || instruction->isa_id == CDISASM_ARM_ISA_T32)
            && instruction->name_id == CDISASM_ARM_NAME_VFMA
            && instruction->operand_count == 3u
            && (instruction->instruction_flags
                & (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
                    | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT))
                == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
                    | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)
            && index == 2u
            && operand->type == CDISASM_OPERAND_REGISTER
            && operand->reg >= CDISASM_ARM_REG_D0
            && operand->reg <= CDISASM_ARM_REG_D7
            && operand->size == 8u
            && operand->access == CDISASM_OPERAND_ACCESS_READ
            && operand->flags == CDISASM_ARM_OPERAND_FLAG_HAS_LANE
            && operand->extend_type == 2u
            && operand->scale == 4u
            && operand->imm < 4u;
        const int fixed_a32_t32_vcmla_lane =
            (instruction->isa_id == CDISASM_ARM_ISA_A32
                || instruction->isa_id == CDISASM_ARM_ISA_T32)
            && instruction->name_id == CDISASM_ARM_NAME_VCMLA
            && instruction->operand_count == 4u
            && (instruction->instruction_flags
                & (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
                    | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT))
                == (CDISASM_ARM_INSTRUCTION_FLAG_SIMD
                    | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT)
            && index == 2u
            && operand->type == CDISASM_OPERAND_REGISTER
            && operand->reg >= CDISASM_ARM_REG_D0
            && operand->reg <= CDISASM_ARM_REG_D31
            && operand->size == 8u
            && operand->access == CDISASM_OPERAND_ACCESS_READ
            && operand->flags == CDISASM_ARM_OPERAND_FLAG_HAS_LANE
            && (operand->extend_type == 2u
                || operand->extend_type == 4u)
            && operand->scale == 8u / operand->extend_type
            && (operand->extend_type == 2u ? operand->imm < 2u
                                           : operand->imm == 0u);
        const int fixed_a32_t32_dot_lane =
            (instruction->isa_id == CDISASM_ARM_ISA_A32
                || instruction->isa_id == CDISASM_ARM_ISA_T32)
            && (instruction->name_id == CDISASM_ARM_NAME_VDOT
                || instruction->name_id == CDISASM_ARM_NAME_VSDOT
                || instruction->name_id == CDISASM_ARM_NAME_VUDOT
                || instruction->name_id == CDISASM_ARM_NAME_VUSDOT
                || instruction->name_id == CDISASM_ARM_NAME_VSUDOT)
            && instruction->operand_count == 3u
            && (instruction->instruction_flags
                & CDISASM_ARM_INSTRUCTION_FLAG_SIMD) != 0u
            && (instruction->name_id != CDISASM_ARM_NAME_VDOT
                || (instruction->instruction_flags
                    & CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT) != 0u)
            && index == 2u
            && operand->type == CDISASM_OPERAND_REGISTER
            && operand->reg >= CDISASM_ARM_REG_D0
            && operand->reg <= CDISASM_ARM_REG_D7
            && operand->size == 8u
            && operand->access == CDISASM_OPERAND_ACCESS_READ
            && operand->flags == CDISASM_ARM_OPERAND_FLAG_HAS_LANE
            && (operand->extend_type == 1u
                || operand->extend_type == 2u)
            && operand->scale == 8u / operand->extend_type
            && operand->imm < 2u;
        const int fixed_advsimd_dup_gpr =
            instruction->isa_id == CDISASM_ARM_ISA_A64
            && instruction->form_id == UINT16_C(5912)
            && instruction->name_id == CDISASM_ARM_NAME_DUP
            && index == 1u
            && operand->type == CDISASM_OPERAND_REGISTER
            && ((operand->reg >= CDISASM_ARM_REG_W0
                    && operand->reg <= CDISASM_ARM_REG_W30)
                || operand->reg == CDISASM_ARM_REG_WZR
                || (operand->reg >= CDISASM_ARM_REG_X0
                    && operand->reg <= CDISASM_ARM_REG_X30)
                || operand->reg == CDISASM_ARM_REG_XZR)
            && (operand->size == 4u || operand->size == 8u)
            && operand->access == CDISASM_OPERAND_ACCESS_READ;
        const int fixed_advsimd_lane_to_gpr =
            instruction->isa_id == CDISASM_ARM_ISA_A64
            && (instruction->form_id == UINT16_C(5913)
                || instruction->form_id == UINT16_C(5914)
                || instruction->form_id == UINT16_C(5916)
                || instruction->form_id == UINT16_C(5917))
            && index == 0u
            && operand->type == CDISASM_OPERAND_REGISTER
            && (operand->size == 4u || operand->size == 8u)
            && operand->access == CDISASM_OPERAND_ACCESS_WRITE;
        const int fixed_fmov_lane64 =
            instruction->isa_id == CDISASM_ARM_ISA_A64
            && instruction->name_id == CDISASM_ARM_NAME_FMOV
            && (instruction->form_id == UINT16_C(6395)
                || instruction->form_id == UINT16_C(6396))
            && operand->type == CDISASM_OPERAND_REGISTER
            && (((operand->flags == CDISASM_ARM_OPERAND_FLAG_HAS_LANE)
                    && operand->reg >= CDISASM_ARM_REG_V0
                    && operand->reg <= CDISASM_ARM_REG_V31
                    && operand->size == 16u && operand->extend_type == 8u
                    && operand->scale == 2u && operand->imm == 1u)
                || (operand->flags == CDISASM_OPERAND_FLAG_NONE
                    && (((operand->reg >= CDISASM_ARM_REG_X0
                                && operand->reg <= CDISASM_ARM_REG_X30)
                            || operand->reg == CDISASM_ARM_REG_XZR)
                        && operand->size == 8u
                        && operand->extend_type == CDISASM_ARM_EXTEND_NONE
                        && operand->scale == 0u && operand->imm == 0u)));
        const int fixed_advsimd_ins_gpr =
            instruction->isa_id == CDISASM_ARM_ISA_A64
            && instruction->form_id == UINT16_C(5915)
            && instruction->name_id == CDISASM_ARM_NAME_INS
            && index == 1u
            && operand->type == CDISASM_OPERAND_REGISTER
            && (operand->size == 4u || operand->size == 8u)
            && operand->access == CDISASM_OPERAND_ACCESS_READ;
        const int fixed_a64_ldr_q_literal =
            instruction->isa_id == CDISASM_ARM_ISA_A64
            && instruction->form_id == UINT16_C(4922)
            && instruction->name_id == CDISASM_ARM_NAME_LDR
            && index == 0u && operand->type == CDISASM_OPERAND_REGISTER
            && ((operand->reg >= CDISASM_ARM_REG_Q0
                    && operand->reg <= CDISASM_ARM_REG_Q15)
                || (operand->reg >= CDISASM_ARM_REG_Q16
                    && operand->reg <= CDISASM_ARM_REG_Q31))
            && operand->size == 16u
            && operand->access == CDISASM_OPERAND_ACCESS_WRITE;
        const int fixed_advsimd_structure_memory =
            instruction->isa_id == CDISASM_ARM_ISA_A64
            && index == 1u
            && operand->type == CDISASM_OPERAND_MEMORY
            && ((instruction->form_id >= UINT16_C(4573)
                    && instruction->form_id <= UINT16_C(4724)
                    && (operand->size == 1u || operand->size == 2u
                        || operand->size == 3u || operand->size == 4u
                        || operand->size == 6u || operand->size == 8u
                        || operand->size == 12u || operand->size == 16u
                        || operand->size == 24u || operand->size == 32u
                        || operand->size == 48u || operand->size == 64u))
                || (instruction->form_id >= UINT16_C(4795)
                    && instruction->form_id <= UINT16_C(4801)
                    && (instruction->name_id == CDISASM_ARM_NAME_ST2G
                        || instruction->name_id == CDISASM_ARM_NAME_STZ2G)
                    && operand->size == 32u));
        const int fixed_sve_replicate_octaword_memory =
            instruction->isa_id == CDISASM_ARM_ISA_A64
            && instruction->form_id >= UINT16_C(3259)
            && instruction->form_id <= UINT16_C(3274)
            && (instruction->form_id & 1u) == 0u
            && index == 2u && operand->type == CDISASM_OPERAND_MEMORY
            && operand->size == 32u;
        const int fixed_fp_non_temporal_pair_memory =
            instruction->isa_id == CDISASM_ARM_ISA_A64
            && instruction->form_id >= UINT16_C(5078)
            && instruction->form_id <= UINT16_C(5085)
            && index == 2u && operand->type == CDISASM_OPERAND_MEMORY
            && (operand->size == 8u || operand->size == 16u
                || operand->size == 32u);
        const int fixed_lsui_pair_memory =
            instruction->isa_id == CDISASM_ARM_ISA_A64
            && ((instruction->form_id >= UINT16_C(5086)
                    && instruction->form_id <= UINT16_C(5089))
                || (instruction->form_id >= UINT16_C(5102)
                    && instruction->form_id <= UINT16_C(5105))
                || (instruction->form_id >= UINT16_C(5118)
                    && instruction->form_id <= UINT16_C(5121))
                || (instruction->form_id >= UINT16_C(5134)
                    && instruction->form_id <= UINT16_C(5137)))
            && index == 2u && operand->type == CDISASM_OPERAND_MEMORY
            && (operand->size == 16u || operand->size == 32u);
        const int fixed_lrcpc3_simd_memory =
            instruction->isa_id == CDISASM_ARM_ISA_A64
            && instruction->form_id >= UINT16_C(4907)
            && instruction->form_id <= UINT16_C(4916)
            && index == 1u && operand->type == CDISASM_OPERAND_MEMORY;

        if (operand->type < CDISASM_OPERAND_REGISTER
            || operand->type > CDISASM_ARM_OPERAND_VECTOR_REGISTER_LIST
            || (sizeless_operand ? operand->size != 0u
                                 : (operand->size == 0u
                                    || (operand->size > 16u
                                        && operand->size != 64u
                && !fixed_advsimd_structure_memory
                && !fixed_fp_non_temporal_pair_memory
                && !fixed_lsui_pair_memory
                && !fixed_lrcpc3_simd_memory
                                        && !fixed_sve_replicate_octaword_memory)))
            || operand->access < CDISASM_OPERAND_ACCESS_READ
            || operand->access > CDISASM_OPERAND_ACCESS_READ_WRITE
            || operand->reg >= CDISASM_ARM_REG_COUNT
            || operand->base_reg >= CDISASM_ARM_REG_COUNT
            || operand->index_reg >= CDISASM_ARM_REG_COUNT
            || operand->shift_type > CDISASM_ARM_SHIFT_MSL
            || (operand->extend_type > CDISASM_ARM_EXTEND_SXTX
                && !((operand->type
                          == CDISASM_ARM_OPERAND_SCALABLE_REGISTER
                        || operand->type == CDISASM_ARM_OPERAND_PREDICATE
                        || operand->type
                            == CDISASM_ARM_OPERAND_SCALABLE_REGISTER_LIST
                    || operand->type == CDISASM_ARM_OPERAND_TILE)
                    && operand->extend_type == 16u)
                && !fixed_pmull_q_destination
                && !fixed_sha_special_register)) {
            return 0;
        }
        if ((instruction->instruction_flags
                & CDISASM_ARM_INSTRUCTION_FLAG_SIMD) != 0u) {
            if (fixed_a32_t32_vdup_scalar || fixed_a32_t32_vmov_lane
                || fixed_a32_t32_vfma_bf16_lane
                || fixed_a32_t32_vcmla_lane
                || fixed_a32_t32_dot_lane) {
                /* The predicate above validates the exact indexed D-register
                 * shape, element arrangement, access, and lane boundary. */
            } else if (fixed_compare_zero_immediate) {
                if (operand->imm != 0u || operand->size != 1u) {
                    return 0;
                }
            } else if (!fixed_sha_special_register
                && !fixed_shll_immediate
                && !fixed_advsimd_scalar_immediate_shift_convert
                && !fixed_a32_t32_vshll_immediate
                && !fixed_a32_t32_vshl_immediate
                && !fixed_a32_t32_vcvt_fixed_immediate
                && !fixed_ext_immediate
                && !fixed_shift_right_immediate
                && !fixed_shift_narrow_widen_immediate
                && !fixed_sat_shift_convert_immediate
                && !fixed_modified_immediate
                && !fixed_xar_immediate
                && !fixed_a32_vcmla_rotation
                && !fixed_a64_fcmla_rotation
                && !fixed_a32_vdup_gpr
                && !fixed_advsimd_dup_gpr
                && !fixed_advsimd_lane_to_gpr
                && !fixed_fmov_lane64
                && !fixed_advsimd_ins_gpr
                && !fixed_a64_ldr_q_literal
                && !fixed_advsimd_structure_memory
                && !fixed_fp_non_temporal_pair_memory
                && !fixed_sve_replicate_octaword_memory) {
                uint8_t element_size =
                    CDISASM_ARM_VECTOR_ELEMENT_SIZE(operand);
                uint8_t element_count =
                    CDISASM_ARM_VECTOR_ELEMENT_COUNT(operand);

                if ((operand->type != CDISASM_OPERAND_REGISTER
                        && operand->type
                            != CDISASM_ARM_OPERAND_VECTOR_REGISTER_LIST)
                    || (element_size != 1u && element_size != 2u
                        && element_size != 4u && element_size != 8u
                        && !fixed_pmull_q_destination)
                    || element_count == 0u
                    || (uint32_t)element_size * element_count
                        != operand->size) {
                    return 0;
                }
            }
        }
        if (operand->type == CDISASM_OPERAND_REGISTER
            && operand->reg == CDISASM_ARM_REG_NONE) {
            return 0;
        }
        if (operand->type == CDISASM_ARM_OPERAND_PREDICATE
            && (!((operand->reg >= CDISASM_ARM_REG_P0
                        && operand->reg <= CDISASM_ARM_REG_P15)
                    || classic_counter_predicate
                    || restricted_counter_predicate)
                || (indexed_psel
                    ? operand->base_reg < CDISASM_ARM_REG_W12
                        || operand->base_reg > CDISASM_ARM_REG_W15
                    : operand->base_reg != CDISASM_ARM_REG_NONE)
                || operand->index_reg != CDISASM_ARM_REG_NONE
                || operand->register_list != 0u
                || operand->address != 0u
                || (indexed_psel
                    ? operand->imm > UINT64_C(15)
                    : pext_source
                        ? operand->imm >= (instruction->form_id
                                == UINT16_C(2582)
                            ? UINT64_C(4) : UINT64_C(2))
                        : operand->imm != 0u)
                || operand->scale != 0u
                || (pext_source
                    ? operand->extend_type != 0u
                    : (operand->extend_type != 1u
                    && operand->extend_type != 2u
                    && operand->extend_type != 4u
                    && operand->extend_type != 8u
                    && !(operand->extend_type == 16u
                        && (instruction->name_id == CDISASM_ARM_NAME_LD1Q
                            || instruction->name_id
                                == CDISASM_ARM_NAME_LD2Q
                            || instruction->name_id
                                == CDISASM_ARM_NAME_LD3Q
                            || instruction->name_id
                                == CDISASM_ARM_NAME_LD4Q
                            || instruction->name_id
                                == CDISASM_ARM_NAME_ST1Q
                            || instruction->name_id
                                == CDISASM_ARM_NAME_ST2Q
                            || instruction->name_id
                                == CDISASM_ARM_NAME_ST3Q
                            || instruction->name_id
                                == CDISASM_ARM_NAME_ST4Q
                            || instruction->name_id
                                == CDISASM_ARM_NAME_LD1W
                            || instruction->name_id
                                == CDISASM_ARM_NAME_LD1D
                            || instruction->name_id
                                == CDISASM_ARM_NAME_ST1W
                            || instruction->name_id
                                == CDISASM_ARM_NAME_ST1D
                            || instruction->name_id
                                == CDISASM_ARM_NAME_REVD
                            || (instruction->name_id
                                    == CDISASM_ARM_NAME_MOV
                                && (instruction->form_id == UINT16_C(3866)
                                    || instruction->form_id
                                        == UINT16_C(3881)))))))
                || operand->shift_type != CDISASM_ARM_SHIFT_NONE
                || operand->shift_amount != 0u
                || (pext_source
                    ? operand->flags
                        != CDISASM_ARM_OPERAND_FLAG_HAS_LANE
                    : ((classic_counter_predicate
                            || restricted_counter_predicate)
                            ? ((instruction->form_id >= UINT16_C(3549)
                                && instruction->form_id <= UINT16_C(3676))
                            ? (operand->flags != 0u
                                && operand->flags != CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO)
                            : operand->flags
                                != CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED)
                        : (operand->flags != 0u
                    && operand->flags
                        != CDISASM_ARM_OPERAND_FLAG_PREDICATE_MERGE
                    && operand->flags
                        != CDISASM_ARM_OPERAND_FLAG_PREDICATE_ZERO
                    && operand->flags
                        != CDISASM_ARM_OPERAND_FLAG_PREDICATE_TYPED))))) {
            return 0;
        }
        if (operand->type == CDISASM_OPERAND_MEMORY
            && operand->base_reg == CDISASM_ARM_REG_NONE) {
            return 0;
        }
        if (whole_za_memory) {
            const cdisasm_arm_operand *tile = &instruction->operand[0];
            uint8_t expected_flags = operand->imm == 0u
                ? CDISASM_OPERAND_FLAG_NONE
                : (uint8_t)(CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
                    | CDISASM_ARM_OPERAND_FLAG_VL_SCALED);

            if (instruction->isa_id != CDISASM_ARM_ISA_A64
                || instruction->operand_count != 2u
                || (instruction->instruction_flags
                    & (CDISASM_ARM_INSTRUCTION_FLAG_SME
                        | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
                        | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR))
                    != (CDISASM_ARM_INSTRUCTION_FLAG_SME
                        | CDISASM_ARM_INSTRUCTION_FLAG_MATRIX
                        | CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR)
                || tile->type != CDISASM_ARM_OPERAND_TILE
                || tile->reg != CDISASM_ARM_REG_ZA
                || tile->base_reg < CDISASM_ARM_REG_W12
                || tile->base_reg > CDISASM_ARM_REG_W15
                || tile->imm != operand->imm
                || operand->imm > UINT64_C(15)
                || operand->index_reg != CDISASM_ARM_REG_NONE
                || operand->flags != expected_flags) {
                return 0;
            }
        } else if (whole_sve_memory) {
            int64_t displacement = (int64_t)operand->imm;
            uint8_t expected_flags = displacement == 0
                ? CDISASM_OPERAND_FLAG_NONE
                : (uint8_t)(CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
                    | CDISASM_ARM_OPERAND_FLAG_VL_SCALED
                    | (displacement < 0
                        ? CDISASM_OPERAND_FLAG_SIGNED : 0u));

            if (instruction->isa_id != CDISASM_ARM_ISA_A64
                || instruction->operand_count != 2u
                || (instruction->instruction_flags
                    & CDISASM_ARM_INSTRUCTION_FLAG_SCALABLE_VECTOR) == 0u
                || displacement < -256 || displacement > 255
                || operand->index_reg != CDISASM_ARM_REG_NONE
                || operand->flags != expected_flags) {
                return 0;
            }
        } else if (contiguous_sve_memory) {
            int64_t displacement = (int64_t)operand->imm;
            uint8_t expected_flags = displacement == 0
                ? CDISASM_OPERAND_FLAG_NONE
                : (uint8_t)(CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
                    | CDISASM_ARM_OPERAND_FLAG_VL_SCALED
                    | (displacement < 0
                        ? CDISASM_OPERAND_FLAG_SIGNED : 0u));

            if (displacement < (multi_contiguous_memory ? -32 : -8)
                || displacement > (multi_contiguous_memory ? 28 : 7)
                || operand->index_reg != CDISASM_ARM_REG_NONE
                || operand->flags != expected_flags) {
                return 0;
            }
        } else if (sve_prefetch_immediate_memory) {
            int64_t displacement = (int64_t)operand->imm;
            uint8_t expected_flags = displacement == 0
                ? CDISASM_OPERAND_FLAG_NONE
                : (uint8_t)(CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
                    | CDISASM_ARM_OPERAND_FLAG_VL_SCALED
                    | (displacement < 0
                        ? CDISASM_OPERAND_FLAG_SIGNED : 0u));

            if (instruction->operand_count != 3u
                || displacement < -32 || displacement > 31
                || operand->index_reg != CDISASM_ARM_REG_NONE
                || operand->size != (uint8_t)(UINT8_C(1)
                    << (instruction->form_id - UINT16_C(3216)))
                || operand->flags != expected_flags) {
                return 0;
            }
        } else if (operand->type == CDISASM_OPERAND_MEMORY
            && (operand->flags
                & CDISASM_ARM_OPERAND_FLAG_VL_SCALED) != 0u) {
            return 0;
        }
        if (operand->type == CDISASM_OPERAND_MEMORY
            && (instruction->instruction_flags
                & CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC) != 0u) {
            int t32_exclusive_offset = instruction->isa_id
                    == CDISASM_ARM_ISA_T32
                && (instruction->form_id == UINT16_C(1726)
                    || instruction->form_id == UINT16_C(1727));
            int rcpc3_writeback = instruction->isa_id
                    == CDISASM_ARM_ISA_A64
                && (instruction->form_id == UINT16_C(4867)
                    || instruction->form_id == UINT16_C(4869)
                    || instruction->form_id == UINT16_C(4871)
                    || instruction->form_id == UINT16_C(4874)
                    || (instruction->form_id >= UINT16_C(4878)
                        && instruction->form_id <= UINT16_C(4881)));
            int64_t expected_rcpc3_displacement = rcpc3_writeback
                ? ((instruction->instruction_flags
                        & CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX) != 0u
                    ? 1 : -1) * operand->size
                : 0;
            uint8_t expected_atomic_memory_flags = rcpc3_writeback
                ? (uint8_t)(CDISASM_ARM_OPERAND_FLAG_WRITEBACK
                    | CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
                    | (expected_rcpc3_displacement < 0
                        ? CDISASM_OPERAND_FLAG_SIGNED : 0u))
                : (uint8_t)(t32_exclusive_offset && operand->imm != 0u
                    ? CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
                    : CDISASM_OPERAND_FLAG_NONE);

            ++atomic_memory_count;
            atomic_memory_access = operand->access;
            if (operand->index_reg != CDISASM_ARM_REG_NONE
                || (rcpc3_writeback
                    ? (int64_t)operand->imm
                        != expected_rcpc3_displacement
                    : (operand->imm != 0u && !t32_exclusive_offset))
                || operand->flags != expected_atomic_memory_flags) {
                return 0;
            }
        }
        if (operand->type == CDISASM_ARM_OPERAND_REGISTER_LIST
            && operand->register_list == 0u
            && (instruction->instruction_flags
                & (CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL
                    | CDISASM_ARM_INSTRUCTION_FLAG_UNPREDICTABLE))
                != (CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL
                    | CDISASM_ARM_INSTRUCTION_FLAG_UNPREDICTABLE)) {
            return 0;
        }
        if (operand->type == CDISASM_ARM_OPERAND_REGISTER_PAIR
            && (instruction->isa_id != CDISASM_ARM_ISA_A64
                || !register_pair_is_architecturally_consecutive(
                    operand->reg, operand->index_reg)
                || operand->size != (operand->reg <= CDISASM_ARM_REG_W30
                    ? 4u : 8u)
                || operand->base_reg != CDISASM_ARM_REG_NONE
                || operand->register_list != 0u)) {
            return 0;
        }
        if (operand->type == CDISASM_OPERAND_IMMEDIATE
            && (operand->flags & CDISASM_OPERAND_FLAG_PC_RELATIVE) != 0u
            && operand->imm == instruction->branch_target) {
            found_relative_target = 1;
        }
    }
    for (; index < CDISASM_ARM_MAX_OPERANDS; ++index) {
        if (!operand_is_zeroed(&instruction->operand[index])) {
            return 0;
        }
    }
    if ((instruction->opcode_groups & CDISASM_GROUP_RELATIVE_BRANCH) != 0u
        && !found_relative_target) {
        return 0;
    }
    if ((instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC) != 0u) {
        uint32_t ordering = instruction->instruction_flags
            & (CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
                | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE);

        if ((instruction->isa_id != CDISASM_ARM_ISA_A64
                && instruction->isa_id != CDISASM_ARM_ISA_A32
                && instruction->isa_id != CDISASM_ARM_ISA_T32)
            || instruction->opcode_groups != CDISASM_GROUP_NONE
            || atomic_memory_count != 1u
            || ((ordering & CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE) != 0u
                && atomic_memory_access != CDISASM_OPERAND_ACCESS_READ
                && atomic_memory_access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE)
            || ((ordering & CDISASM_ARM_INSTRUCTION_FLAG_RELEASE) != 0u
                && atomic_memory_access != CDISASM_OPERAND_ACCESS_WRITE
                && atomic_memory_access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE)) {
            return 0;
        }
    } else if ((instruction->instruction_flags
            & (CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
                | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE
                | CDISASM_ARM_INSTRUCTION_FLAG_EXCLUSIVE)) != 0u) {
        return 0;
    }
    if (instruction->name_id >= CDISASM_ARM_NAME_LDADDB
        && instruction->name_id <= CDISASM_ARM_NAME_SWPAL) {
        unsigned ordering =
            ((unsigned)(instruction->name_id - CDISASM_ARM_NAME_LDADDB)
                % 12u) / 3u;
        int result_is_zero_register = instruction->operand_count == 3u
            && (instruction->operand[1].reg == CDISASM_ARM_REG_WZR
                || instruction->operand[1].reg == CDISASM_ARM_REG_XZR);
        uint32_t expected_ordering_flags =
            ((ordering & 1u) != 0u && !result_is_zero_register
                ? CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE : 0u)
            | ((ordering & 2u) != 0u
                ? CDISASM_ARM_INSTRUCTION_FLAG_RELEASE : 0u);

        if ((instruction->instruction_flags
                & (CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
                    | CDISASM_ARM_INSTRUCTION_FLAG_RELEASE))
            != expected_ordering_flags) {
            return 0;
        }
    }
    return 1;
}

static void run_case(char **fields, size_t line_number)
{
    const char *case_name = fields[0];
    uint8_t bytes[CORPUS_BYTE_CAPACITY];
    size_t byte_count = 0;
    uint32_t cpu_id;
    uint32_t mode;
    uint64_t address;
    cdisasm_arm_decode_option flags;
    cdisasm_status expected_status;
    uint32_t expected_size;
    uint32_t expected_name;
    uint32_t expected_condition;
    uint32_t expected_operand_count;
    uint32_t expected_groups;
    uint32_t expected_instruction_flags;
    uint64_t expected_branch_target;
    cdisasm_arm_instruction first;
    cdisasm_arm_instruction second;
    cdisasm_arm_instruction big_endian_result;
    uint8_t big_endian_bytes[CDISASM_ARM_MAX_INSTRUCTION_SIZE];
    uint32_t first_size;
    uint32_t second_size;

    if (case_name[0] == '\0'
        || !parse_u32(fields[1], &cpu_id)
        || !parse_u32(fields[2], &mode)
        || !parse_u64(fields[3], &address)
        || !parse_u64(fields[4], &flags)
        || !parse_status(fields[5], &expected_status)
        || !parse_u32(fields[6], &expected_size)
        || !parse_u32(fields[7], &expected_name)
        || !parse_u32(fields[8], &expected_condition)
        || !parse_u32(fields[9], &expected_operand_count)
        || !parse_u32(fields[10], &expected_groups)
        || !parse_u32(fields[11], &expected_instruction_flags)
        || !parse_u64(fields[12], &expected_branch_target)
        || !parse_hex_bytes(fields[13], bytes, &byte_count)) {
        report_failure(line_number, case_name, "malformed corpus field");
        return;
    }
#if !USE_EXTRA_OPCODES
    if (strcmp(fields[5], "EXTRA_OK") == 0) {
        expected_size = 0u;
        expected_name = 0u;
        expected_condition = 0u;
        expected_operand_count = 0u;
        expected_groups = 0u;
        expected_instruction_flags = 0u;
        expected_branch_target = 0u;
    }
#endif
    if ((expected_status == CDISASM_STATUS_OK) != (expected_size != 0u)
        || (expected_status == CDISASM_STATUS_OK
            && ((mode == CDISASM_ARM_MODE_T32
                    && expected_size != 2u && expected_size != 4u)
                || (mode != CDISASM_ARM_MODE_T32
                    && expected_size != CDISASM_ARM_MAX_INSTRUCTION_SIZE)))
        || expected_name > CDISASM_ARM_NAME_LAST
        || expected_condition > CDISASM_ARM_CONDITION_NV
        || expected_operand_count > CDISASM_ARM_MAX_OPERANDS) {
        report_failure(line_number, case_name, "invalid expected metadata");
        return;
    }
    if (expected_status != CDISASM_STATUS_OK
        && (expected_name != 0u || expected_condition != 0u
            || expected_operand_count != 0u || expected_groups != 0u
            || expected_instruction_flags != 0u
            || expected_branch_target != 0u)) {
        report_failure(line_number, case_name,
                       "failure row contains successful metadata");
        return;
    }

    memset(&first, 0xa5, sizeof(first));
    first_size = cdisasm_arm_decode(
        (cdisasm_arm_cpu_id)cpu_id,
        (cdisasm_arm_mode)mode,
        byte_count != 0u ? bytes : NULL,
        byte_count,
        address,
        flags,
        &first);
    memset(&second, 0x5a, sizeof(second));
    second_size = cdisasm_arm_decode(
        (cdisasm_arm_cpu_id)cpu_id,
        (cdisasm_arm_mode)mode,
        byte_count != 0u ? bytes : NULL,
        byte_count,
        address,
        flags,
        &second);

    if (first_size != second_size
        || memcmp(&first, &second, sizeof(first)) != 0) {
        report_failure(line_number, case_name,
                       "decode result is not deterministic");
        return;
    }
    if (first_size != expected_size
        || first.last_error_id != expected_status) {
        char message[160];

        (void)snprintf(message, sizeof(message),
                       "got size/status %u/%u, expected %u/%u",
                       (unsigned int)first_size,
                       (unsigned int)first.last_error_id,
                       (unsigned int)expected_size,
                       (unsigned int)expected_status);
        report_failure(line_number, case_name, message);
        return;
    }
    if (expected_status != CDISASM_STATUS_OK) {
        if (!failure_result_is_zeroed(&first, expected_status)) {
            report_failure(line_number, case_name,
                           "failure result contains nonzero metadata");
        }
        return;
    }
    if (!successful_result_is_well_formed(
            &first, (cdisasm_arm_mode)mode, bytes, byte_count, address,
            flags, first_size)) {
        report_failure(line_number, case_name,
                       "successful result violates ABI invariants");
        return;
    }
    if (flags == CDISASM_ARM_DECODE_OPTION_NONE) {
        uint32_t big_endian_size;

        make_big_endian_bytes(
            (cdisasm_arm_mode)mode,
            bytes,
            big_endian_bytes,
            first_size);
        memset(&big_endian_result, 0xa5, sizeof(big_endian_result));
        big_endian_size = cdisasm_arm_decode(
            (cdisasm_arm_cpu_id)cpu_id,
            (cdisasm_arm_mode)mode,
            big_endian_bytes,
            first_size,
            address,
            CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN,
            &big_endian_result);
        if (big_endian_size != first_size
            || memcmp(&big_endian_result, &first, sizeof(first)) != 0) {
            report_failure(
                line_number,
                case_name,
                "big-endian decode does not match little-endian metadata");
            return;
        }
    }
    if (first.name_id != expected_name
        || first.condition != expected_condition
        || first.operand_count != expected_operand_count
        || first.opcode_groups != expected_groups
        || first.instruction_flags != expected_instruction_flags
        || first.branch_target != expected_branch_target) {
        char message[256];

        (void)snprintf(
            message,
            sizeof(message),
            "metadata got %u/%u/%u/0x%x/0x%x/0x%llx, expected "
            "%u/%u/%u/0x%x/0x%x/0x%llx",
            (unsigned int)first.name_id,
            (unsigned int)first.condition,
            (unsigned int)first.operand_count,
            (unsigned int)first.opcode_groups,
            (unsigned int)first.instruction_flags,
            (unsigned long long)first.branch_target,
            (unsigned int)expected_name,
            (unsigned int)expected_condition,
            (unsigned int)expected_operand_count,
            (unsigned int)expected_groups,
            (unsigned int)expected_instruction_flags,
            (unsigned long long)expected_branch_target);
        report_failure(line_number, case_name, message);
    }
}

int main(int argc, char **argv)
{
    char line[CORPUS_LINE_CAPACITY];
    size_t line_number = 0;
    size_t case_count = 0;
    FILE *file;

    if (argc != 2) {
        fprintf(stderr, "usage: %s arm-opcode-corpus.tsv\n", argv[0]);
        return 2;
    }
    file = fopen(argv[1], "r");
    if (file == NULL) {
        fprintf(stderr, "cannot open ARM corpus: %s\n", argv[1]);
        return 2;
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        char *fields[CORPUS_FIELD_COUNT];
        size_t length;

        ++line_number;
        length = strlen(line);
        if (length != 0u && line[length - 1u] != '\n' && !feof(file)) {
            report_failure(line_number, NULL, "line exceeds parser capacity");
            do {
                int character = fgetc(file);
                if (character == '\n' || character == EOF) {
                    break;
                }
            } while (1);
            continue;
        }
        while (length != 0u
               && (line[length - 1u] == '\n' || line[length - 1u] == '\r')) {
            line[--length] = '\0';
        }
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }
        if (!split_fields(line, fields)) {
            report_failure(line_number, NULL, "expected 14 tab-separated fields");
            continue;
        }
        ++case_count;
        run_case(fields, line_number);
    }
    if (ferror(file)) {
        report_failure(line_number, NULL, "read error");
    }
    (void)fclose(file);
    if (case_count == 0u) {
        report_failure(line_number, NULL, "corpus contains no cases");
    }
    if (failures != 0) {
        fprintf(stderr, "%d ARM corpus test(s) failed\n", failures);
        return 1;
    }
    printf("ARM opcode corpus: %zu cases passed\n", case_count);
    return 0;
}
