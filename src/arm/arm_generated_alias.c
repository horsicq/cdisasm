#include "arm_generated_alias.h"

#if USE_EXTRA_OPCODES

#include "generated/cdisasm_arm_alias_decode.inc"

_Static_assert(
    CDISASM_ARM_FEATURE_PMULL
        >= UINT16_C(36) + CDISASM_ARM_ALIASGEN_FEATURE_COUNT,
    "generated alias feature map overlaps private FEAT_PMULL ID");

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ARM_ALIAS_STACK_SIZE 64u
#define ARM_ALIAS_SET_MAX_MEMBERS 4u

typedef enum arm_alias_value_kind {
    ARM_ALIAS_SCALAR = 0,
    ARM_ALIAS_SIGNED = 1,
    ARM_ALIAS_PATTERN = 2,
    ARM_ALIAS_BOOLEAN = 3,
    ARM_ALIAS_FEATURE = 4,
    ARM_ALIAS_SET = 5,
    ARM_ALIAS_SLICE = 6
} arm_alias_value_kind;

typedef struct arm_alias_member {
    uint64_t value;
    uint64_t mask;
    uint8_t width;
} arm_alias_member;

typedef struct arm_alias_value {
    uint64_t value;
    uint64_t mask;
    uint8_t width;
    uint8_t kind;
    uint8_t count;
    arm_alias_member member[ARM_ALIAS_SET_MAX_MEMBERS];
} arm_alias_value;

static uint64_t arm_alias_width_mask(uint8_t width)
{
    return width == 0u || width >= 64u
        ? UINT64_MAX : (UINT64_C(1) << width) - UINT64_C(1);
}

static arm_alias_value arm_alias_scalar(
    uint64_t value,
    uint64_t mask,
    uint8_t width,
    arm_alias_value_kind kind)
{
    arm_alias_value result;

    memset(&result, 0, sizeof(result));
    result.value = value & arm_alias_width_mask(width);
    result.mask = mask & arm_alias_width_mask(width);
    result.width = width;
    result.kind = (uint8_t)kind;
    return result;
}

static int arm_alias_push(
    arm_alias_value *stack,
    size_t *stack_size,
    arm_alias_value value)
{
    if (*stack_size >= ARM_ALIAS_STACK_SIZE) {
        return 0;
    }
    stack[(*stack_size)++] = value;
    return 1;
}

static int arm_alias_pop(
    arm_alias_value *stack,
    size_t *stack_size,
    arm_alias_value *value)
{
    if (*stack_size == 0u) {
        return 0;
    }
    *value = stack[--(*stack_size)];
    return 1;
}

static int arm_alias_truth(const arm_alias_value *value, int *truth)
{
    if (value == NULL || truth == NULL
        || value->kind == ARM_ALIAS_FEATURE
        || value->kind == ARM_ALIAS_SET
        || value->kind == ARM_ALIAS_SLICE
        || (value->kind == ARM_ALIAS_PATTERN
            && value->mask != arm_alias_width_mask(value->width))) {
        return 0;
    }
    *truth = value->value != UINT64_C(0);
    return 1;
}

static int arm_alias_patterns_intersect(
    const arm_alias_value *left,
    const arm_alias_value *right)
{
    uint64_t common_mask = left->mask & right->mask;

    return ((left->value ^ right->value) & common_mask) == UINT64_C(0);
}

static int arm_alias_concrete(const arm_alias_value *value)
{
    return value->kind != ARM_ALIAS_FEATURE
        && value->kind != ARM_ALIAS_SET
        && value->kind != ARM_ALIAS_SLICE
        && value->mask == arm_alias_width_mask(value->width);
}

static uint64_t arm_alias_ror32(uint32_t value, unsigned amount)
{
    amount &= 31u;
    return amount == 0u
        ? value
        : (uint32_t)((value >> amount) | (value << (32u - amount)));
}

static uint32_t arm_alias_rol32(uint32_t value, unsigned amount)
{
    amount &= 31u;
    return amount == 0u
        ? value
        : (uint32_t)((value << amount) | (value >> (32u - amount)));
}

static uint32_t arm_alias_t32_expand_imm(uint32_t immediate)
{
    uint32_t byte = immediate & UINT32_C(0xff);

    if ((immediate & UINT32_C(0xc00)) == 0u) {
        switch ((immediate >> 8) & 3u) {
            case 0u:
                return byte;
            case 1u:
                return (byte << 16) | byte;
            case 2u:
                return (byte << 24) | (byte << 8);
            default:
                return byte * UINT32_C(0x01010101);
        }
    }
    return (uint32_t)arm_alias_ror32(
        UINT32_C(0x80) | (immediate & UINT32_C(0x7f)),
        (immediate >> 7) & UINT32_C(0x1f));
}

static int arm_alias_a32_encoding_exists(uint32_t immediate)
{
    unsigned rotate;

    for (rotate = 0u; rotate < 32u; rotate += 2u) {
        if (arm_alias_rol32(immediate, rotate) <= UINT32_C(0xff)) {
            return 1;
        }
    }
    return 0;
}

static int arm_alias_t32_encoding_exists(uint32_t immediate)
{
    uint32_t byte = immediate & UINT32_C(0xff);
    unsigned rotate;

    if (immediate <= UINT32_C(0xff)
        || (byte != 0u && immediate == ((byte << 16) | byte))
        || ((immediate & UINT32_C(0xff)) == 0u
            && (immediate >> 24) != 0u
            && immediate
                == (((immediate >> 24) << 24)
                    | ((immediate >> 24) << 8)))
        || (byte != 0u
            && immediate == byte * UINT32_C(0x01010101))) {
        return 1;
    }
    for (rotate = 8u; rotate < 32u; ++rotate) {
        uint32_t unrotated = arm_alias_rol32(immediate, rotate);

        if (unrotated >= UINT32_C(0x80)
            && unrotated <= UINT32_C(0xff)
            && arm_alias_ror32(unrotated, rotate) == immediate) {
            return 1;
        }
    }
    return 0;
}

static unsigned arm_alias_bit_count(uint64_t value)
{
    unsigned count = 0u;

    while (value != 0u) {
        value &= value - UINT64_C(1);
        ++count;
    }
    return count;
}

static int arm_alias_pop_arguments(
    arm_alias_value *stack,
    size_t *stack_size,
    arm_alias_value *arguments,
    size_t argument_count)
{
    size_t index;

    if (*stack_size < argument_count) {
        return 0;
    }
    for (index = argument_count; index != 0u; --index) {
        if (!arm_alias_pop(
                stack, stack_size, &arguments[index - 1u])
            || !arm_alias_concrete(&arguments[index - 1u])) {
            return 0;
        }
    }
    return 1;
}

static int arm_alias_bfx_preferred(
    const arm_alias_value arguments[4])
{
    uint64_t sf = arguments[0].value;
    uint64_t uns = arguments[1].value;
    uint64_t imms = arguments[2].value;
    uint64_t immr = arguments[3].value;

    if (sf > 1u || uns > 1u || imms > 63u || immr > 63u
        || imms < immr || imms == ((sf << 5) | UINT64_C(31))) {
        return 0;
    }
    if (immr == 0u) {
        if (sf == 0u && (imms == 7u || imms == 15u)) {
            return 0;
        }
        if (sf == 1u && uns == 0u
            && (imms == 7u || imms == 15u || imms == 31u)) {
            return 0;
        }
    }
    return 1;
}

static int arm_alias_move_wide_preferred(
    const arm_alias_value arguments[4])
{
    uint64_t sf = arguments[0].value;
    uint64_t imm_n = arguments[1].value;
    uint64_t imms = arguments[2].value;
    uint64_t immr = arguments[3].value;
    uint64_t width;

    if (sf > 1u || imm_n > 1u || imms > 63u || immr > 63u) {
        return 0;
    }
    width = sf != 0u ? UINT64_C(64) : UINT64_C(32);
    if ((sf != 0u && imm_n != 1u)
        || (sf == 0u && (imm_n != 0u || (imms & UINT64_C(32)) != 0u))) {
        return 0;
    }
    if (imms < 16u) {
        return ((UINT64_C(0) - immr) & UINT64_C(15))
            <= UINT64_C(15) - imms;
    }
    if (imms >= width - UINT64_C(15)) {
        return (immr & UINT64_C(15))
            <= imms - (width - UINT64_C(15));
    }
    return 0;
}

static int arm_alias_decode_bitmask64(uint16_t encoding, uint64_t *immediate)
{
    uint32_t imm_n = (encoding >> 12) & 1u;
    uint32_t imms = encoding & UINT32_C(0x3f);
    uint32_t immr = (encoding >> 6) & UINT32_C(0x3f);
    uint32_t length_source = (imm_n << 6) | ((~imms) & UINT32_C(0x3f));
    uint32_t length = 0u;
    uint32_t levels;
    uint32_t element_size;
    uint32_t ones_count;
    uint32_t rotate;
    uint64_t element_mask;
    uint64_t element;
    uint64_t result = UINT64_C(0);
    uint32_t offset;

    while ((length_source >> (length + 1u)) != 0u) {
        ++length;
    }
    if (length < 1u || length > 6u) {
        return 0;
    }
    levels = (UINT32_C(1) << length) - UINT32_C(1);
    if ((imms & levels) == levels) {
        return 0;
    }
    element_size = UINT32_C(1) << length;
    ones_count = (imms & levels) + UINT32_C(1);
    rotate = immr & levels;
    element_mask = element_size == 64u
        ? UINT64_MAX
        : (UINT64_C(1) << element_size) - UINT64_C(1);
    element = (UINT64_C(1) << ones_count) - UINT64_C(1);
    if (rotate != 0u) {
        element = ((element >> rotate)
            | (element << (element_size - rotate))) & element_mask;
    }
    for (offset = 0u; offset < 64u; offset += element_size) {
        result |= element << offset;
    }
    *immediate = result;
    return 1;
}

static int arm_alias_sve_move_mask_preferred(
    const arm_alias_value *argument,
    int *preferred)
{
    uint64_t immediate;
    uint32_t low32;
    uint16_t low16;

    if (argument->value > UINT16_C(0x1fff)
        || !arm_alias_decode_bitmask64(
            (uint16_t)argument->value, &immediate)) {
        return 0;
    }
    low32 = (uint32_t)immediate;
    low16 = (uint16_t)immediate;
    if ((immediate & UINT64_C(0xff)) != 0u) {
        if ((immediate >> 7) == 0u
            || (immediate >> 7) == (UINT64_MAX >> 7)) {
            *preferred = 0;
            return 1;
        }
        if ((uint32_t)(immediate >> 32) == low32
            && ((low32 >> 7) == 0u
                || (low32 >> 7) == (UINT32_MAX >> 7))) {
            *preferred = 0;
            return 1;
        }
        if ((uint32_t)(immediate >> 32) == low32
            && (uint16_t)(low32 >> 16) == low16
            && ((low16 >> 7) == 0u
                || (low16 >> 7) == (UINT16_MAX >> 7))) {
            *preferred = 0;
            return 1;
        }
        if ((uint32_t)(immediate >> 32) == low32
            && (uint16_t)(low32 >> 16) == low16
            && (uint8_t)(low16 >> 8) == (uint8_t)low16) {
            *preferred = 0;
            return 1;
        }
    } else {
        if ((immediate >> 15) == 0u
            || (immediate >> 15) == (UINT64_MAX >> 15)) {
            *preferred = 0;
            return 1;
        }
        if ((uint32_t)(immediate >> 32) == low32
            && ((low32 >> 15) == 0u
                || (low32 >> 15) == (UINT32_MAX >> 15))) {
            *preferred = 0;
            return 1;
        }
        if ((uint32_t)(immediate >> 32) == low32
            && (uint16_t)(low32 >> 16) == low16) {
            *preferred = 0;
            return 1;
        }
    }
    *preferred = 1;
    return 1;
}

static int arm_alias_eval_program(
    uint32_t program_id,
    uint32_t word,
    const cdisasm_arm_capabilities *capabilities,
    int in_it_block,
    int *result);

static int arm_alias_system_operation(
    uint8_t function_kind,
    const arm_alias_value arguments[4],
    const cdisasm_arm_capabilities *capabilities,
    int in_it_block,
    uint8_t *operation_kind)
{
    uint32_t encoding;
    uint32_t key;
    size_t first = 0u;
    size_t last = CDISASM_ARM_ALIASGEN_SYSTEM_OPERATION_COUNT;

    if (operation_kind == NULL
        || arguments[0].value >= 8u
        || arguments[1].value >= 16u
        || arguments[2].value >= 16u
        || arguments[3].value >= 8u) {
        return 0;
    }
    encoding = ((uint32_t)arguments[0].value << 11)
        | ((uint32_t)arguments[1].value << 7)
        | ((uint32_t)arguments[2].value << 3)
        | (uint32_t)arguments[3].value;
    key = ((uint32_t)function_kind << 14) | encoding;
    while (first < last) {
        size_t middle = first + (last - first) / 2u;
        uint32_t candidate =
            cdisasm_arm_aliasgen_system_operations[middle].key;

        if (candidate < key) {
            first = middle + 1u;
        } else {
            last = middle;
        }
    }
    *operation_kind = 0u;
    if (first < CDISASM_ARM_ALIASGEN_SYSTEM_OPERATION_COUNT
        && cdisasm_arm_aliasgen_system_operations[first].key == key) {
        const cdisasm_arm_aliasgen_system_operation *operation =
            &cdisasm_arm_aliasgen_system_operations[first];
        int available = 0;

        if (!arm_alias_eval_program(
                operation->condition_program_id, 0u, capabilities,
                in_it_block, &available)) {
            return 0;
        }
        if (available) {
            *operation_kind = operation->result;
        }
    }
    return 1;
}

static int arm_alias_call(
    uint8_t function_kind,
    uint32_t parameter_count,
    uint32_t argument_count,
    const cdisasm_arm_capabilities *capabilities,
    int in_it_block,
    arm_alias_value *stack,
    size_t *stack_size)
{
    arm_alias_value arguments[4];
    arm_alias_value value;
    uint64_t sign;

    if (parameter_count != 0u) {
        return 0;
    }
    if (function_kind == CDISASM_ARM_ALIASGEN_FUNCTION_IN_IT_BLOCK) {
        if (argument_count != 0u) {
            return 0;
        }
        return arm_alias_push(
            stack, stack_size,
            arm_alias_scalar(
                in_it_block != 0, UINT64_MAX, 1u, ARM_ALIAS_BOOLEAN));
    }
    if (function_kind == CDISASM_ARM_ALIASGEN_FUNCTION_BFX_PREFERRED
        || function_kind
            == CDISASM_ARM_ALIASGEN_FUNCTION_MOVE_WIDE_PREFERRED) {
        int preferred;

        if (argument_count != 4u
            || !arm_alias_pop_arguments(
                stack, stack_size, arguments, argument_count)) {
            return 0;
        }
        preferred = function_kind
                == CDISASM_ARM_ALIASGEN_FUNCTION_BFX_PREFERRED
            ? arm_alias_bfx_preferred(arguments)
            : arm_alias_move_wide_preferred(arguments);
        return arm_alias_push(
            stack, stack_size,
            arm_alias_scalar(
                preferred, UINT64_MAX, 1u, ARM_ALIAS_BOOLEAN));
    }
    if (function_kind
            == CDISASM_ARM_ALIASGEN_FUNCTION_SVE_MOVE_MASK_PREFERRED) {
        int preferred;

        if (argument_count != 1u
            || !arm_alias_pop(stack, stack_size, &value)
            || !arm_alias_concrete(&value)
            || !arm_alias_sve_move_mask_preferred(&value, &preferred)) {
            return 0;
        }
        return arm_alias_push(
            stack, stack_size,
            arm_alias_scalar(
                preferred, UINT64_MAX, 1u, ARM_ALIAS_BOOLEAN));
    }
    if (function_kind == CDISASM_ARM_ALIASGEN_FUNCTION_A32_ENCODING_EXISTS
        || function_kind
            == CDISASM_ARM_ALIASGEN_FUNCTION_T32_ENCODING_EXISTS) {
        int exists;

        if (argument_count != 1u
            || !arm_alias_pop(stack, stack_size, &value)
            || !arm_alias_concrete(&value)
            || value.value > UINT32_MAX) {
            return 0;
        }
        exists = function_kind
                == CDISASM_ARM_ALIASGEN_FUNCTION_A32_ENCODING_EXISTS
            ? arm_alias_a32_encoding_exists((uint32_t)value.value)
            : arm_alias_t32_encoding_exists((uint32_t)value.value);
        return arm_alias_push(
            stack, stack_size,
            arm_alias_scalar(
                exists, UINT64_MAX, 1u, ARM_ALIAS_BOOLEAN));
    }
    if (function_kind == CDISASM_ARM_ALIASGEN_FUNCTION_SYS_OP
        || function_kind == CDISASM_ARM_ALIASGEN_FUNCTION_SYSL_OP
        || function_kind == CDISASM_ARM_ALIASGEN_FUNCTION_SYS_OP128) {
        uint8_t operation_kind;

        if (argument_count != 4u
            || !arm_alias_pop_arguments(
                stack, stack_size, arguments, argument_count)
            || !arm_alias_system_operation(
                function_kind, arguments, capabilities, in_it_block,
                &operation_kind)) {
            return 0;
        }
        return arm_alias_push(
            stack, stack_size,
            arm_alias_scalar(
                operation_kind, UINT64_MAX, 8u, ARM_ALIAS_SCALAR));
    }
    if (argument_count != 1u
        || !arm_alias_pop(stack, stack_size, &value)) {
        return 0;
    }
    switch (function_kind) {
        case CDISASM_ARM_ALIASGEN_FUNCTION_FEATURE:
            if (value.kind != ARM_ALIAS_FEATURE
                || value.value >= CDISASM_ARM_ALIASGEN_FEATURE_COUNT) {
                return 0;
            }
            value = arm_alias_scalar(
                cdisasm_arm_capabilities_has_feature(
                    capabilities,
                    cdisasm_arm_aliasgen_feature_capability_ids[value.value]),
                UINT64_MAX, 1u, ARM_ALIAS_BOOLEAN);
            break;
        case CDISASM_ARM_ALIASGEN_FUNCTION_UINT:
            if (!arm_alias_concrete(&value)) {
                return 0;
            }
            value.kind = ARM_ALIAS_SCALAR;
            break;
        case CDISASM_ARM_ALIASGEN_FUNCTION_SINT:
            if (!arm_alias_concrete(&value) || value.width == 0u) {
                return 0;
            }
            sign = UINT64_C(1) << (value.width >= 64u
                ? 63u : value.width - 1u);
            if ((value.value & sign) != 0u && value.width < 64u) {
                value.value |= ~arm_alias_width_mask(value.width);
            }
            value.mask = UINT64_MAX;
            value.width = 64u;
            value.kind = ARM_ALIAS_SIGNED;
            break;
        case CDISASM_ARM_ALIASGEN_FUNCTION_T32_EXPAND_IMM:
            if (!arm_alias_concrete(&value) || value.value > 0xfffu) {
                return 0;
            }
            value = arm_alias_scalar(
                arm_alias_t32_expand_imm((uint32_t)value.value),
                UINT32_MAX, 32u, ARM_ALIAS_SCALAR);
            break;
        case CDISASM_ARM_ALIASGEN_FUNCTION_BIT_COUNT:
            if (!arm_alias_concrete(&value)) {
                return 0;
            }
            value = arm_alias_scalar(
                arm_alias_bit_count(value.value), UINT64_MAX, 64u,
                ARM_ALIAS_SCALAR);
            break;
        case CDISASM_ARM_ALIASGEN_FUNCTION_IS_ZERO:
        case CDISASM_ARM_ALIASGEN_FUNCTION_IS_ONES:
            if (!arm_alias_concrete(&value)) {
                return 0;
            }
            value = arm_alias_scalar(
                function_kind == CDISASM_ARM_ALIASGEN_FUNCTION_IS_ZERO
                    ? value.value == 0u
                    : value.value == arm_alias_width_mask(value.width),
                UINT64_MAX, 1u, ARM_ALIAS_BOOLEAN);
            break;
        default:
            return 0;
    }
    return arm_alias_push(stack, stack_size, value);
}

static int arm_alias_eval_program(
    uint32_t program_id,
    uint32_t word,
    const cdisasm_arm_capabilities *capabilities,
    int in_it_block,
    int *result)
{
    arm_alias_value stack[ARM_ALIAS_STACK_SIZE];
    const cdisasm_arm_aliasgen_span *program;
    size_t stack_size = 0u;
    uint32_t index;

    if (result == NULL || capabilities == NULL
        || program_id == CDISASM_ARM_ALIASGEN_NONE
        || program_id >= CDISASM_ARM_ALIASGEN_PROGRAM_COUNT) {
        return 0;
    }
    program = &cdisasm_arm_aliasgen_programs[program_id];
    if ((uint64_t)program->first + program->count
        > sizeof(cdisasm_arm_aliasgen_bytecode)
            / sizeof(cdisasm_arm_aliasgen_bytecode[0])) {
        return 0;
    }
    for (index = 0u; index < program->count; ++index) {
        const cdisasm_arm_aliasgen_bc *operation =
            &cdisasm_arm_aliasgen_bytecode[program->first + index];
        arm_alias_value left;
        arm_alias_value right;
        arm_alias_value value;
        int left_truth;
        int right_truth;

        switch (operation->opcode) {
            case CDISASM_ARM_ALIASGEN_PUSH_BOOL:
                value = arm_alias_scalar(
                    operation->a != 0, UINT64_MAX, 1u,
                    ARM_ALIAS_BOOLEAN);
                if (!arm_alias_push(stack, &stack_size, value)) {
                    return 0;
                }
                break;
            case CDISASM_ARM_ALIASGEN_PUSH_FIELD:
                if (operation->a < 0 || operation->a >= 32
                    || operation->b <= 0 || operation->b > 32
                    || operation->a + operation->b > 32) {
                    return 0;
                }
                value = arm_alias_scalar(
                    (uint64_t)(word >> operation->a),
                    arm_alias_width_mask((uint8_t)operation->b),
                    (uint8_t)operation->b, ARM_ALIAS_SCALAR);
                if (!arm_alias_push(stack, &stack_size, value)) {
                    return 0;
                }
                break;
            case CDISASM_ARM_ALIASGEN_PUSH_FEATURE:
                if (operation->a < 0
                    || (uint32_t)operation->a
                        >= CDISASM_ARM_ALIASGEN_FEATURE_COUNT) {
                    return 0;
                }
                value = arm_alias_scalar(
                    (uint32_t)operation->a, UINT64_MAX, 32u,
                    ARM_ALIAS_FEATURE);
                if (!arm_alias_push(stack, &stack_size, value)) {
                    return 0;
                }
                break;
            case CDISASM_ARM_ALIASGEN_PUSH_SYMBOL:
                if (operation->a < 0
                    || (uint32_t)operation->a
                        >= CDISASM_ARM_ALIASGEN_SYMBOL_COUNT
                    || cdisasm_arm_aliasgen_symbol_values[operation->a]
                        == 0u) {
                    return 0;
                }
                value = arm_alias_scalar(
                    cdisasm_arm_aliasgen_symbol_values[operation->a],
                    UINT64_MAX, 8u, ARM_ALIAS_SCALAR);
                if (!arm_alias_push(stack, &stack_size, value)) {
                    return 0;
                }
                break;
            case CDISASM_ARM_ALIASGEN_PUSH_VALUE: {
                const cdisasm_arm_aliasgen_value *pattern;

                if (operation->a < 0
                    || (size_t)operation->a
                        >= sizeof(cdisasm_arm_aliasgen_values)
                            / sizeof(cdisasm_arm_aliasgen_values[0])) {
                    return 0;
                }
                pattern = &cdisasm_arm_aliasgen_values[operation->a];
                value = arm_alias_scalar(
                    pattern->value, pattern->mask, pattern->width,
                    ARM_ALIAS_PATTERN);
                if (!arm_alias_push(stack, &stack_size, value)) {
                    return 0;
                }
                break;
            }
            case CDISASM_ARM_ALIASGEN_PUSH_INTEGER:
                value = arm_alias_scalar(
                    (uint64_t)(int64_t)operation->a,
                    UINT64_MAX, 64u,
                    operation->a < 0 ? ARM_ALIAS_SIGNED : ARM_ALIAS_SCALAR);
                if (!arm_alias_push(stack, &stack_size, value)) {
                    return 0;
                }
                break;
            case CDISASM_ARM_ALIASGEN_MAKE_SET: {
                size_t first;
                size_t member;

                if (operation->a < 0
                    || (uint32_t)operation->a > ARM_ALIAS_SET_MAX_MEMBERS
                    || stack_size < (size_t)operation->a) {
                    return 0;
                }
                first = stack_size - (size_t)operation->a;
                memset(&value, 0, sizeof(value));
                value.kind = ARM_ALIAS_SET;
                value.count = (uint8_t)operation->a;
                for (member = 0u; member < value.count; ++member) {
                    const arm_alias_value *source = &stack[first + member];

                    if (source->kind == ARM_ALIAS_SET
                        || source->kind == ARM_ALIAS_SLICE
                        || source->kind == ARM_ALIAS_FEATURE) {
                        return 0;
                    }
                    value.member[member].value = source->value;
                    value.member[member].mask = source->mask;
                    value.member[member].width = source->width;
                }
                stack_size = first;
                if (!arm_alias_push(stack, &stack_size, value)) {
                    return 0;
                }
                break;
            }
            case CDISASM_ARM_ALIASGEN_MAKE_SLICE:
                if (!arm_alias_pop(stack, &stack_size, &right)
                    || !arm_alias_pop(stack, &stack_size, &left)
                    || !arm_alias_concrete(&left)
                    || !arm_alias_concrete(&right)
                    || left.value > 63u || right.value > left.value) {
                    return 0;
                }
                value = arm_alias_scalar(
                    left.value, right.value, 0u, ARM_ALIAS_SLICE);
                if (!arm_alias_push(stack, &stack_size, value)) {
                    return 0;
                }
                break;
            case CDISASM_ARM_ALIASGEN_SQUARE: {
                uint8_t high;
                uint8_t low;
                uint8_t width;

                if (operation->a != 1
                    || !arm_alias_pop(stack, &stack_size, &right)
                    || !arm_alias_pop(stack, &stack_size, &left)
                    || !arm_alias_concrete(&left)) {
                    return 0;
                }
                if (right.kind == ARM_ALIAS_SLICE) {
                    high = (uint8_t)right.value;
                    low = (uint8_t)right.mask;
                } else if (arm_alias_concrete(&right)
                    && right.value < left.width) {
                    high = (uint8_t)right.value;
                    low = high;
                } else {
                    return 0;
                }
                width = (uint8_t)(high - low + 1u);
                value = arm_alias_scalar(
                    left.value >> low, arm_alias_width_mask(width),
                    width, ARM_ALIAS_SCALAR);
                if (!arm_alias_push(stack, &stack_size, value)) {
                    return 0;
                }
                break;
            }
            case CDISASM_ARM_ALIASGEN_LOGICAL_NOT:
                if (!arm_alias_pop(stack, &stack_size, &value)
                    || !arm_alias_truth(&value, &left_truth)) {
                    return 0;
                }
                value = arm_alias_scalar(
                    !left_truth, UINT64_MAX, 1u, ARM_ALIAS_BOOLEAN);
                if (!arm_alias_push(stack, &stack_size, value)) {
                    return 0;
                }
                break;
            case CDISASM_ARM_ALIASGEN_BIT_NOT:
                if (!arm_alias_pop(stack, &stack_size, &value)
                    || !arm_alias_concrete(&value)) {
                    return 0;
                }
                value.value = ~value.value & arm_alias_width_mask(value.width);
                if (!arm_alias_push(stack, &stack_size, value)) {
                    return 0;
                }
                break;
            case CDISASM_ARM_ALIASGEN_AND:
            case CDISASM_ARM_ALIASGEN_OR:
                if (!arm_alias_pop(stack, &stack_size, &right)
                    || !arm_alias_pop(stack, &stack_size, &left)
                    || !arm_alias_truth(&left, &left_truth)
                    || !arm_alias_truth(&right, &right_truth)) {
                    return 0;
                }
                value = arm_alias_scalar(
                    operation->opcode == CDISASM_ARM_ALIASGEN_AND
                        ? left_truth && right_truth
                        : left_truth || right_truth,
                    UINT64_MAX, 1u, ARM_ALIAS_BOOLEAN);
                if (!arm_alias_push(stack, &stack_size, value)) {
                    return 0;
                }
                break;
            case CDISASM_ARM_ALIASGEN_EQ:
            case CDISASM_ARM_ALIASGEN_NE:
                if (!arm_alias_pop(stack, &stack_size, &right)
                    || !arm_alias_pop(stack, &stack_size, &left)) {
                    return 0;
                }
                left_truth = arm_alias_patterns_intersect(&left, &right);
                if (operation->opcode == CDISASM_ARM_ALIASGEN_NE) {
                    left_truth = !left_truth;
                }
                value = arm_alias_scalar(
                    left_truth, UINT64_MAX, 1u, ARM_ALIAS_BOOLEAN);
                if (!arm_alias_push(stack, &stack_size, value)) {
                    return 0;
                }
                break;
            case CDISASM_ARM_ALIASGEN_LT:
            case CDISASM_ARM_ALIASGEN_GT:
            case CDISASM_ARM_ALIASGEN_GE:
                if (!arm_alias_pop(stack, &stack_size, &right)
                    || !arm_alias_pop(stack, &stack_size, &left)
                    || !arm_alias_concrete(&left)
                    || !arm_alias_concrete(&right)) {
                    return 0;
                }
                if (left.kind == ARM_ALIAS_SIGNED
                    || right.kind == ARM_ALIAS_SIGNED) {
                    int64_t signed_left = (int64_t)left.value;
                    int64_t signed_right = (int64_t)right.value;

                    left_truth = operation->opcode == CDISASM_ARM_ALIASGEN_LT
                        ? signed_left < signed_right
                        : operation->opcode == CDISASM_ARM_ALIASGEN_GT
                            ? signed_left > signed_right
                            : signed_left >= signed_right;
                } else {
                    left_truth = operation->opcode == CDISASM_ARM_ALIASGEN_LT
                        ? left.value < right.value
                        : operation->opcode == CDISASM_ARM_ALIASGEN_GT
                            ? left.value > right.value
                            : left.value >= right.value;
                }
                value = arm_alias_scalar(
                    left_truth, UINT64_MAX, 1u, ARM_ALIAS_BOOLEAN);
                if (!arm_alias_push(stack, &stack_size, value)) {
                    return 0;
                }
                break;
            case CDISASM_ARM_ALIASGEN_IN: {
                size_t member;

                if (!arm_alias_pop(stack, &stack_size, &right)
                    || !arm_alias_pop(stack, &stack_size, &left)
                    || right.kind != ARM_ALIAS_SET) {
                    return 0;
                }
                left_truth = 0;
                for (member = 0u; member < right.count; ++member) {
                    arm_alias_value set_value = arm_alias_scalar(
                        right.member[member].value,
                        right.member[member].mask,
                        right.member[member].width,
                        ARM_ALIAS_PATTERN);

                    if (arm_alias_patterns_intersect(&left, &set_value)) {
                        left_truth = 1;
                        break;
                    }
                }
                value = arm_alias_scalar(
                    left_truth, UINT64_MAX, 1u, ARM_ALIAS_BOOLEAN);
                if (!arm_alias_push(stack, &stack_size, value)) {
                    return 0;
                }
                break;
            }
            case CDISASM_ARM_ALIASGEN_CONCAT:
                if (!arm_alias_pop(stack, &stack_size, &right)
                    || !arm_alias_pop(stack, &stack_size, &left)
                    || left.width > 64u - right.width
                    || left.kind == ARM_ALIAS_SET
                    || right.kind == ARM_ALIAS_SET
                    || left.kind == ARM_ALIAS_SLICE
                    || right.kind == ARM_ALIAS_SLICE
                    || left.kind == ARM_ALIAS_FEATURE
                    || right.kind == ARM_ALIAS_FEATURE) {
                    return 0;
                }
                value = arm_alias_scalar(
                    (left.value << right.width) | right.value,
                    (left.mask << right.width) | right.mask,
                    (uint8_t)(left.width + right.width),
                    left.kind == ARM_ALIAS_PATTERN
                        || right.kind == ARM_ALIAS_PATTERN
                        ? ARM_ALIAS_PATTERN : ARM_ALIAS_SCALAR);
                if (!arm_alias_push(stack, &stack_size, value)) {
                    return 0;
                }
                break;
            case CDISASM_ARM_ALIASGEN_XOR:
            case CDISASM_ARM_ALIASGEN_MOD:
            case CDISASM_ARM_ALIASGEN_ADD:
                if (!arm_alias_pop(stack, &stack_size, &right)
                    || !arm_alias_pop(stack, &stack_size, &left)
                    || !arm_alias_concrete(&left)
                    || !arm_alias_concrete(&right)
                    || (operation->opcode == CDISASM_ARM_ALIASGEN_MOD
                        && right.value == 0u)) {
                    return 0;
                }
                if (operation->opcode == CDISASM_ARM_ALIASGEN_XOR) {
                    value.value = left.value ^ right.value;
                } else if (operation->opcode == CDISASM_ARM_ALIASGEN_MOD) {
                    value.value = left.value % right.value;
                } else {
                    value.value = left.value + right.value;
                }
                value.width = left.width > right.width
                    ? left.width : right.width;
                value.mask = arm_alias_width_mask(value.width);
                value.value &= value.mask;
                value.kind = (left.kind == ARM_ALIAS_SIGNED
                    || right.kind == ARM_ALIAS_SIGNED)
                    ? ARM_ALIAS_SIGNED : ARM_ALIAS_SCALAR;
                value.count = 0u;
                if (!arm_alias_push(stack, &stack_size, value)) {
                    return 0;
                }
                break;
            case CDISASM_ARM_ALIASGEN_CALL: {
                uint32_t parameter_count =
                    ((uint32_t)operation->b >> 16) & UINT32_C(0xffff);
                uint32_t argument_count =
                    (uint32_t)operation->b & UINT32_C(0xffff);

                if (operation->a < 0
                    || (size_t)operation->a
                        >= sizeof(cdisasm_arm_aliasgen_function_kinds)
                            / sizeof(cdisasm_arm_aliasgen_function_kinds[0])
                    || !arm_alias_call(
                        cdisasm_arm_aliasgen_function_kinds[operation->a],
                        parameter_count, argument_count, capabilities,
                        in_it_block,
                        stack, &stack_size)) {
                    return 0;
                }
                break;
            }
            default:
                return 0;
        }
    }
    if (stack_size != 1u
        || !arm_alias_truth(&stack[0], result)) {
        return 0;
    }
    return 1;
}

int cdisasm_arm_select_generated_alias(
    const cdisasm_arm_capabilities *capabilities,
    int in_it_block,
    cdisasm_arm_instruction *instruction)
{
    cdisasm_arm_name_id selected = CDISASM_ARM_NAME_NONE;
    uint32_t leaf_index;
    uint32_t word;
    size_t index;
    uint8_t selected_flags = 0u;
    int unresolved = 0;
    int it_alias_sets_flags = 0;

    if (capabilities == NULL || instruction == NULL
        || (instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK) == 0u
        || instruction->form_id == CDISASM_ARM_FORM_NONE
        || instruction->form_id > CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST) {
        return 0;
    }
    leaf_index = (uint32_t)instruction->form_id - UINT32_C(1);
    word = instruction->raw_instruction;
    if (instruction->isa_id == CDISASM_ARM_ISA_T32
        && instruction->opcode_size == 4u) {
        word = (word << 16) | (word >> 16);
    }
    for (index = 0u; index < CDISASM_ARM_ALIASGEN_ALIAS_COUNT; ++index) {
        const cdisasm_arm_aliasgen_alias *alias =
            &cdisasm_arm_aliasgen_aliases[index];
        int condition = 0;
        int preferred = 0;
        int condition_known;
        int preferred_known;

        if (alias->leaf_index != leaf_index) {
            continue;
        }
        if ((alias->flags & CDISASM_ARM_ALIASGEN_FLAG_IN_IT_BLOCK) != 0u
            && (alias->flags & CDISASM_ARM_ALIASGEN_FLAG_SETS_FLAGS) != 0u) {
            it_alias_sets_flags = 1;
        }
        if (alias->canonical_name_id != instruction->name_id) {
            return 0;
        }
        condition_known = arm_alias_eval_program(
            alias->condition_program_id, word, capabilities,
            in_it_block, &condition);
        preferred_known = arm_alias_eval_program(
            alias->preferred_program_id, word, capabilities,
            in_it_block, &preferred);
        if ((condition_known && !condition)
            || (preferred_known && !preferred)) {
            continue;
        }
        if (!condition_known || !preferred_known) {
            unresolved = 1;
            continue;
        }
        if (selected != CDISASM_ARM_NAME_NONE
            && selected != alias->public_name_id) {
            return 0;
        }
        selected = alias->public_name_id;
        selected_flags = alias->flags;
    }
    if (unresolved) {
        return 0;
    }
    if (in_it_block && it_alias_sets_flags) {
        instruction->instruction_flags &=
            ~CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
    }
    if (selected == CDISASM_ARM_NAME_NONE
        || selected == instruction->name_id) {
        return 0;
    }
    instruction->name_id = selected;
    if ((selected_flags & CDISASM_ARM_ALIASGEN_FLAG_SETS_FLAGS) != 0u) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
    }
    if (instruction->form_id == UINT16_C(4498)
        && (selected == CDISASM_ARM_NAME_SMSTART
            || selected == CDISASM_ARM_NAME_SMSTOP)) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_SME
            | CDISASM_ARM_INSTRUCTION_FLAG_STREAMING;
    }
    if ((instruction->form_id == UINT16_C(2429)
            || instruction->form_id == UINT16_C(2631))
        && selected == CDISASM_ARM_NAME_FMOV) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
    }
    if (selected == CDISASM_ARM_NAME_VPUSH
        && (instruction->form_id == UINT16_C(499)
            || instruction->form_id == UINT16_C(501)
            || instruction->form_id == UINT16_C(1484)
            || instruction->form_id == UINT16_C(1486))) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT;
    }
    if (selected == CDISASM_ARM_NAME_VPOP
        && (instruction->form_id == UINT16_C(506)
            || instruction->form_id == UINT16_C(508)
            || instruction->form_id == UINT16_C(1491)
            || instruction->form_id == UINT16_C(1493))) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
            | CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT;
    }
    if (selected == CDISASM_ARM_NAME_POP
        && (((instruction->form_id == UINT16_C(397)
                    || instruction->form_id == UINT16_C(1721))
                && (word & UINT32_C(0x8000)) != 0u)
            || ((instruction->form_id == UINT16_C(270)
                    || instruction->form_id == UINT16_C(2058))
                && ((word >> 12) & UINT32_C(15)) == UINT32_C(15)))) {
        instruction->opcode_groups |=
            CDISASM_GROUP_JUMP | CDISASM_GROUP_RETURN;
    }
    return 1;
}

int cdisasm_arm_apply_generated_it_context(
    const cdisasm_arm_capabilities *capabilities,
    cdisasm_arm_instruction *instruction)
{
    cdisasm_arm_name_id canonical = CDISASM_ARM_NAME_NONE;
    cdisasm_arm_name_id original;
    uint32_t leaf_index;
    size_t index;
    int recognized_name = 0;

    if (capabilities == NULL || instruction == NULL
        || instruction->isa_id != CDISASM_ARM_ISA_T32
        || instruction->form_id == CDISASM_ARM_FORM_NONE
        || instruction->form_id > CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST) {
        return 0;
    }
    leaf_index = (uint32_t)instruction->form_id - UINT32_C(1);
    for (index = 0u; index < CDISASM_ARM_ALIASGEN_ALIAS_COUNT; ++index) {
        const cdisasm_arm_aliasgen_alias *alias =
            &cdisasm_arm_aliasgen_aliases[index];

        if (alias->leaf_index != leaf_index
            || (alias->flags & CDISASM_ARM_ALIASGEN_FLAG_IN_IT_BLOCK) == 0u) {
            continue;
        }
        if (canonical != CDISASM_ARM_NAME_NONE
            && canonical != alias->canonical_name_id) {
            return 0;
        }
        canonical = alias->canonical_name_id;
        if (instruction->name_id == alias->canonical_name_id
            || instruction->name_id == alias->public_name_id) {
            recognized_name = 1;
        }
    }
    if (!recognized_name || canonical == CDISASM_ARM_NAME_NONE) {
        return 0;
    }
    original = instruction->name_id;
    instruction->name_id = canonical;
    if ((instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK) != 0u) {
        (void)cdisasm_arm_select_generated_alias(
            capabilities, 1, instruction);
    } else {
        uint32_t saved_flags = instruction->instruction_flags;

        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK;
        (void)cdisasm_arm_select_generated_alias(
            capabilities, 1, instruction);
        instruction->instruction_flags =
            (instruction->instruction_flags
                & ~CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK)
            | (saved_flags & CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK);
    }
    return instruction->name_id != original;
}

#else

int cdisasm_arm_select_generated_alias(
    const cdisasm_arm_capabilities *capabilities,
    int in_it_block,
    cdisasm_arm_instruction *instruction)
{
    (void)capabilities;
    (void)in_it_block;
    (void)instruction;
    return 0;
}

int cdisasm_arm_apply_generated_it_context(
    const cdisasm_arm_capabilities *capabilities,
    cdisasm_arm_instruction *instruction)
{
    (void)capabilities;
    (void)instruction;
    return 0;
}

#endif
