#include "arm_generated_formatter.h"
#include "arm_generated_decoder.h"
#include "arm_pstate_msr_format.h"

#if USE_DISASM_FORMAT && USE_ARCH_ARM && USE_EXTRA_OPCODES

#include "generated/cdisasm_arm_assembly_decode.inc"
#include "generated/cdisasm_arm_assembly_format.inc"

#include <stdint.h>

#define ARM_ASMGEN_STACK_SIZE 8u

typedef struct arm_asmgen_writer {
    char *buffer;
    size_t size;
    size_t length;
} arm_asmgen_writer;

typedef struct arm_asmgen_value {
    uint64_t value;
    uint8_t width;
} arm_asmgen_value;

static uint64_t arm_asmgen_width_mask(uint8_t width)
{
    return width == 0u || width >= 64u
        ? UINT64_MAX
        : (UINT64_C(1) << width) - UINT64_C(1);
}

static int64_t arm_asmgen_sign_extend(uint64_t value, uint8_t width)
{
    uint64_t sign = UINT64_C(1) << (width - 1u);
    uint64_t limit = UINT64_C(1) << width;

    value &= limit - UINT64_C(1);
    return (value & sign) != 0u
        ? -(int64_t)(limit - value) : (int64_t)value;
}

static void arm_asmgen_putc(arm_asmgen_writer *writer, char value)
{
    if (writer->buffer != NULL && writer->size != 0u
        && writer->length + 1u < writer->size) {
        writer->buffer[writer->length] = value;
    }
    ++writer->length;
}

static char arm_asmgen_ascii_lower(char value)
{
    return value >= 'A' && value <= 'Z'
        ? (char)(value + ('a' - 'A')) : value;
}

static char arm_asmgen_ascii_upper(char value)
{
    return value >= 'a' && value <= 'z'
        ? (char)(value - ('a' - 'A')) : value;
}

static int arm_asmgen_put_text(
    arm_asmgen_writer *writer,
    uint32_t text_id,
    int uppercase)
{
    uint32_t offset;

    if (text_id >= sizeof(cdisasm_arm_asmgen_text_offsets)
            / sizeof(cdisasm_arm_asmgen_text_offsets[0])) {
        return 0;
    }
    offset = cdisasm_arm_asmgen_text_offsets[text_id];
    if (offset >= sizeof(cdisasm_arm_asmgen_text_data)) {
        return 0;
    }
    while (offset < sizeof(cdisasm_arm_asmgen_text_data)
        && cdisasm_arm_asmgen_text_data[offset] != 0u) {
        char value = (char)cdisasm_arm_asmgen_text_data[offset++];

        arm_asmgen_putc(
            writer,
            uppercase ? arm_asmgen_ascii_upper(value)
                      : arm_asmgen_ascii_lower(value));
    }
    return offset < sizeof(cdisasm_arm_asmgen_text_data);
}

static void arm_asmgen_put_unsigned(
    arm_asmgen_writer *writer, uint64_t value)
{
    char digits[20];
    size_t count = 0u;

    do {
        digits[count++] = (char)('0' + value % UINT64_C(10));
        value /= UINT64_C(10);
    } while (value != 0u);
    while (count != 0u) {
        arm_asmgen_putc(writer, digits[--count]);
    }
}

/* A64/SVE imm8 floating constants have a five-bit significand and a small
 * power-of-two scale.  Decimal expansion therefore terminates exactly; no
 * host floating-point rounding or locale-dependent printf is involved. */
static void arm_asmgen_put_sve_fp_imm8(
    arm_asmgen_writer *writer, uint8_t imm8)
{
    int exponent = ((imm8 >> 6) & 1u) != 0u
        ? (int)((imm8 >> 4) & 3u) - 3
        : (int)((imm8 >> 4) & 3u) + 1;
    uint32_t numerator = 16u + (imm8 & 15u);
    uint32_t denominator = 1u;
    uint32_t integer_part;
    uint32_t remainder;

    if ((imm8 & UINT8_C(0x80)) != 0u) {
        arm_asmgen_putc(writer, '-');
    }
    if (exponent >= 4) {
        numerator <<= (unsigned)(exponent - 4);
    } else {
        denominator <<= (unsigned)(4 - exponent);
    }
    integer_part = numerator / denominator;
    remainder = numerator % denominator;
    arm_asmgen_put_unsigned(writer, integer_part);
    arm_asmgen_putc(writer, '.');
    if (remainder == 0u) {
        arm_asmgen_putc(writer, '0');
    } else {
        while (remainder != 0u) {
            remainder *= 10u;
            arm_asmgen_putc(writer,
                (char)('0' + remainder / denominator));
            remainder %= denominator;
        }
    }
}

static void arm_asmgen_put_a32_gpr(
    arm_asmgen_writer *writer, uint32_t register_number)
{
    if (register_number == 13u) {
        arm_asmgen_putc(writer, 's');
        arm_asmgen_putc(writer, 'p');
    } else if (register_number == 14u) {
        arm_asmgen_putc(writer, 'l');
        arm_asmgen_putc(writer, 'r');
    } else if (register_number == 15u) {
        arm_asmgen_putc(writer, 'p');
        arm_asmgen_putc(writer, 'c');
    } else {
        arm_asmgen_putc(writer, 'r');
        arm_asmgen_put_unsigned(writer, register_number);
    }
}

static uint32_t arm_asmgen_ror32(uint32_t value, uint32_t amount)
{
    amount &= 31u;
    return amount == 0u ? value
        : (value >> amount) | (value << (32u - amount));
}

static uint32_t arm_asmgen_thumb_expand_imm(uint32_t imm12)
{
    uint32_t imm8 = imm12 & UINT32_C(0xff);

    if ((imm12 & UINT32_C(0xc00)) == 0u) {
        switch ((imm12 >> 8) & 3u) {
            case 0u:
                return imm8;
            case 1u:
                return (imm8 << 16) | imm8;
            case 2u:
                return (imm8 << 24) | (imm8 << 8);
            default:
                return (imm8 << 24) | (imm8 << 16)
                    | (imm8 << 8) | imm8;
        }
    }
    return arm_asmgen_ror32(
        UINT32_C(0x80) | (imm12 & UINT32_C(0x7f)),
        (imm12 >> 7) & UINT32_C(31));
}

static int arm_asmgen_decode_logical_immediate(
    uint64_t encoded, uint32_t register_width, uint64_t *result)
{
    uint32_t n;
    uint32_t imms;
    uint32_t immr;
    uint32_t length_source;
    uint32_t length = 0u;
    uint32_t levels;
    uint32_t element_size;
    uint32_t s;
    uint32_t r;
    uint64_t element;
    uint64_t element_mask;
    uint64_t replicated = 0u;
    uint32_t position;

    if (result == NULL || (register_width != 32u && register_width != 64u)) {
        return 0;
    }
    if (register_width == 64u) {
        n = (uint32_t)((encoded >> 12) & UINT64_C(1));
        imms = (uint32_t)((encoded >> 6) & UINT64_C(0x3f));
    } else {
        n = 0u;
        imms = (uint32_t)((encoded >> 6) & UINT64_C(0x3f));
    }
    immr = (uint32_t)(encoded & UINT64_C(0x3f));
    length_source = (n << 6) | ((~imms) & UINT32_C(0x3f));
    while ((length_source >> (length + 1u)) != 0u) {
        ++length;
    }
    if (length < 1u) {
        return 0;
    }
    levels = (UINT32_C(1) << length) - 1u;
    s = imms & levels;
    r = immr & levels;
    if (s == levels) {
        return 0;
    }
    element_size = UINT32_C(1) << length;
    element_mask = element_size == 64u ? UINT64_MAX
        : (UINT64_C(1) << element_size) - UINT64_C(1);
    element = (UINT64_C(1) << (s + 1u)) - UINT64_C(1);
    if (r != 0u) {
        element = ((element >> r)
            | (element << (element_size - r))) & element_mask;
    }
    for (position = 0u; position < register_width;
         position += element_size) {
        replicated |= element << position;
    }
    *result = replicated;
    return 1;
}

static void arm_asmgen_put_hex(
    arm_asmgen_writer *writer, uint64_t value)
{
    static const char digits[] = "0123456789abcdef";
    char reversed[16];
    size_t count = 0u;

    arm_asmgen_putc(writer, '0');
    arm_asmgen_putc(writer, 'x');
    do {
        reversed[count++] = digits[value & UINT64_C(0xf)];
        value >>= 4;
    } while (value != 0u);
    while (count != 0u) {
        arm_asmgen_putc(writer, reversed[--count]);
    }
}

static void arm_asmgen_put_signed(
    arm_asmgen_writer *writer, uint64_t value, uint8_t width)
{
    uint64_t mask = arm_asmgen_width_mask(width);
    uint64_t sign;

    value &= mask;
    sign = width == 0u ? UINT64_C(0)
        : UINT64_C(1) << (width >= 64u ? 63u : width - 1u);
    if (sign != 0u && (value & sign) != 0u) {
        arm_asmgen_putc(writer, '-');
        value = ((~value) + UINT64_C(1)) & mask;
    }
    arm_asmgen_put_unsigned(writer, value);
}

static int arm_asmgen_eval_expression(
    uint32_t program_id,
    uint32_t word,
    arm_asmgen_value *result)
{
    arm_asmgen_value stack[ARM_ASMGEN_STACK_SIZE];
    const cdisasm_arm_asmgen_span *program;
    size_t count = 0u;
    uint32_t index;

    if (result == NULL
        || program_id >= sizeof(cdisasm_arm_asmgen_programs)
            / sizeof(cdisasm_arm_asmgen_programs[0])) {
        return 0;
    }
    program = &cdisasm_arm_asmgen_programs[program_id];
    if ((uint64_t)program->first + program->count
        > sizeof(cdisasm_arm_asmgen_bytecode)
            / sizeof(cdisasm_arm_asmgen_bytecode[0])) {
        return 0;
    }
    for (index = 0u; index < program->count; ++index) {
        const cdisasm_arm_asmgen_bc *operation =
            &cdisasm_arm_asmgen_bytecode[program->first + index];

        switch (operation->opcode) {
            case 2u: { /* PUSH_FIELD */
                uint8_t start;
                uint8_t width;

                if (count >= ARM_ASMGEN_STACK_SIZE
                    || operation->a < 0 || operation->a >= 32
                    || operation->b <= 0 || operation->b > 32
                    || operation->a + operation->b > 32) {
                    return 0;
                }
                start = (uint8_t)operation->a;
                width = (uint8_t)operation->b;
                stack[count].value = ((uint64_t)word >> start)
                    & arm_asmgen_width_mask(width);
                stack[count].width = width;
                ++count;
                break;
            }
            case 17u: /* UNARY_BIT_NOT */
                if (count == 0u) {
                    return 0;
                }
                stack[count - 1u].value = ~stack[count - 1u].value
                    & arm_asmgen_width_mask(stack[count - 1u].width);
                break;
            case 41u: { /* BINARY_XOR */
                uint8_t width;

                if (count < 2u) {
                    return 0;
                }
                width = stack[count - 2u].width > stack[count - 1u].width
                    ? stack[count - 2u].width : stack[count - 1u].width;
                stack[count - 2u].value =
                    (stack[count - 2u].value ^ stack[count - 1u].value)
                    & arm_asmgen_width_mask(width);
                stack[count - 2u].width = width;
                --count;
                break;
            }
            case 40u: { /* BINARY_CONCAT */
                uint8_t left_width;
                uint8_t right_width;

                if (count < 2u) {
                    return 0;
                }
                left_width = stack[count - 2u].width;
                right_width = stack[count - 1u].width;
                if (left_width > 64u - right_width) {
                    return 0;
                }
                stack[count - 2u].value =
                    ((stack[count - 2u].value
                        & arm_asmgen_width_mask(left_width)) << right_width)
                    | (stack[count - 1u].value
                        & arm_asmgen_width_mask(right_width));
                stack[count - 2u].width =
                    (uint8_t)(left_width + right_width);
                --count;
                break;
            }
            default:
                /* Direct recipes intentionally use only this closed subset. */
                return 0;
        }
    }
    if (count != 1u) {
        return 0;
    }
    *result = stack[0];
    return 1;
}

static const cdisasm_arm_asmgen_alias *arm_asmgen_find_alias(
    const cdisasm_arm_instruction *instruction)
{
    size_t index;
    uint32_t leaf_index = (uint32_t)instruction->form_id - UINT32_C(1);

    for (index = 0u;
         index < sizeof(cdisasm_arm_asmgen_aliases)
            / sizeof(cdisasm_arm_asmgen_aliases[0]);
         ++index) {
        const cdisasm_arm_asmgen_alias *alias =
            &cdisasm_arm_asmgen_aliases[index];

        if (alias->leaf_index == leaf_index
            && alias->public_name_id == instruction->name_id
            && alias->render_status != 0u
            && alias->recipe_count != 0u) {
            return alias;
        }
    }
    return NULL;
}

static size_t arm_asmgen_render_recipe(
    uint32_t recipe_first,
    uint16_t recipe_count,
    uint32_t word,
    uint8_t isa_id,
    uint64_t instruction_address,
    uint64_t branch_target,
    uint32_t flags,
    char *buffer,
    size_t buffer_size)
{
    static const char *const condition_names[15] = {
        "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
        "hi", "ls", "ge", "lt", "gt", "le", "al"
    };
    arm_asmgen_writer writer;
    uint32_t index;

    if ((uint64_t)recipe_first + recipe_count
        > sizeof(cdisasm_arm_asmgen_recipe_ops)
            / sizeof(cdisasm_arm_asmgen_recipe_ops[0])) {
        return 0u;
    }
    writer.buffer = buffer;
    writer.size = buffer_size;
    writer.length = 0u;
    for (index = 0u; index < recipe_count; ++index) {
        const cdisasm_arm_asmgen_recipe_op *operation =
            &cdisasm_arm_asmgen_recipe_ops[recipe_first + index];
        arm_asmgen_value value;

        if (operation->opcode == CDISASM_ARM_ASMGEN_MNEMONIC) {
            if (!arm_asmgen_put_text(
                    &writer,
                    operation->value,
                    (flags & CDISASM_FORMAT_UPPERCASE_OPCODE) != 0u)) {
                return 0u;
            }
        } else if (operation->opcode == CDISASM_ARM_ASMGEN_TEXT) {
            if (!arm_asmgen_put_text(&writer, operation->value, 0)) {
                return 0u;
            }
        } else if (operation->opcode == CDISASM_ARM_ASMGEN_UINT
            || operation->opcode == CDISASM_ARM_ASMGEN_SINT) {
            if (!arm_asmgen_eval_expression(operation->value, word, &value)) {
                return 0u;
            }
            if (operation->opcode == CDISASM_ARM_ASMGEN_UINT) {
                arm_asmgen_put_unsigned(&writer, value.value);
            } else {
                arm_asmgen_put_signed(&writer, value.value, value.width);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_UINT_RSHIFT1) {
            if (!arm_asmgen_eval_expression(operation->value, word, &value)
                || value.width == 0u) {
                return 0u;
            }
            arm_asmgen_put_unsigned(&writer, value.value >> 1u);
        } else if (operation->opcode == CDISASM_ARM_ASMGEN_GPR_LIST) {
            uint32_t list_start = operation->value & UINT32_C(0xff);
            uint32_t list_width = (operation->value >> 8) & UINT32_C(0xff);
            uint32_t extra_start =
                (operation->value >> 16) & UINT32_C(0xff);
            uint32_t extra_register = operation->value >> 24;
            uint32_t register_mask;
            uint32_t register_number;
            int emitted = 0;

            if (list_start >= 32u || list_width == 0u
                || list_width > 16u || list_start + list_width > 32u
                || (extra_start != 255u
                    && (extra_start >= 32u || extra_register >= 16u))) {
                return 0u;
            }
            register_mask = (word >> list_start)
                & (uint32_t)arm_asmgen_width_mask((uint8_t)list_width);
            if (extra_start != 255u
                && ((word >> extra_start) & 1u) != 0u) {
                register_mask |= UINT32_C(1) << extra_register;
            }
            if (register_mask == 0u) {
                return 0u;
            }
            arm_asmgen_putc(&writer, '{');
            for (register_number = 0u;
                 register_number < 16u;
                 ++register_number) {
                if ((register_mask
                        & (UINT32_C(1) << register_number)) == 0u) {
                    continue;
                }
                if (emitted) {
                    arm_asmgen_putc(&writer, ',');
                    arm_asmgen_putc(&writer, ' ');
                }
                arm_asmgen_put_a32_gpr(&writer, register_number);
                emitted = 1;
            }
            arm_asmgen_putc(&writer, '}');
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_GROUPED_ZREG) {
            uint32_t stride = operation->value & UINT32_C(0xff);
            uint32_t ordinal = (operation->value >> 8) & UINT32_C(0xff);
            uint32_t register_number;

            if ((operation->value & ~UINT32_C(0xffff)) != 0u
                || (stride != 4u && stride != 8u)
                || ordinal >= 16u / stride
                || (stride == 4u && (word & UINT32_C(4)) != 0u)) {
                return 0u;
            }
            register_number = (((word >> 4) & 1u) << 4)
                | (word & (stride - 1u));
            register_number += ordinal * stride;
            if (register_number > 31u
                || (register_number & (stride - 1u))
                    != (word & (stride - 1u))) {
                return 0u;
            }
            arm_asmgen_putc(&writer, 'z');
            arm_asmgen_put_unsigned(&writer, register_number);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_PN_GROUP) {
            uint32_t predicate_number;

            if (operation->value != 0u) {
                return 0u;
            }
            predicate_number = 8u + ((word >> 10) & 7u);
            if (predicate_number < 8u || predicate_number > 15u) {
                return 0u;
            }
            arm_asmgen_put_unsigned(&writer, predicate_number);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_TMOP_ZK) {
            uint32_t register_number;

            if (operation->value != 0u) {
                return 0u;
            }
            register_number = 20u + (((word >> 12) & 1u) << 3)
                + ((word >> 10) & 3u);
            if ((register_number < 20u || register_number > 23u)
                && (register_number < 28u || register_number > 31u)) {
                return 0u;
            }
            arm_asmgen_putc(&writer, 'z');
            arm_asmgen_put_unsigned(&writer, register_number);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_TMOP_ZN_PAIR) {
            uint32_t register_number;

            if (operation->value > 1u) {
                return 0u;
            }
            register_number = (((word >> 6) & 15u) << 1)
                + operation->value;
            if (register_number > 31u) {
                return 0u;
            }
            arm_asmgen_putc(&writer, 'z');
            arm_asmgen_put_unsigned(&writer, register_number);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SIMD_SHIFT64) {
            uint32_t immh = (word >> 19) & 15u;
            uint32_t immb = (word >> 16) & 7u;
            uint32_t encoded = (immh << 3) | immb;
            uint32_t amount;

            if (operation->value > 1u || (immh & 8u) == 0u) {
                return 0u;
            }
            amount = operation->value == 0u
                ? 128u - encoded : encoded - 64u;
            if ((operation->value == 0u && (amount < 1u || amount > 64u))
                || (operation->value == 1u && amount > 63u)) {
                return 0u;
            }
            arm_asmgen_put_unsigned(&writer, amount);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_BITFIELD_ALIAS_IMM) {
            uint32_t kind = operation->value & 7u;
            uint32_t width = (operation->value & 8u) != 0u ? 64u : 32u;
            uint32_t immr = (word >> 16) & 63u;
            uint32_t imms = (word >> 10) & 63u;
            uint32_t n = (word >> 22) & 1u;
            uint32_t amount;

            if ((operation->value & ~15u) != 0u || kind > 2u
                || n != (width == 64u ? 1u : 0u)
                || immr >= width || imms >= width
                || ((kind == 0u || kind == 1u) && imms >= immr)
                || (kind == 2u && imms < immr)) {
                return 0u;
            }
            amount = kind == 0u ? width - immr
                : kind == 1u ? imms + 1u : imms - immr + 1u;
            if (amount == 0u || amount > width) {
                return 0u;
            }
            arm_asmgen_put_unsigned(&writer, amount);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_VDUP_GPR_SIZE) {
            uint32_t b = (word >> 22) & 1u;
            uint32_t e = (word >> 5) & 1u;

            if (operation->value != 0u || (b != 0u && e != 0u)) {
                return 0u;
            }
            arm_asmgen_put_unsigned(&writer,
                b != 0u ? 8u : e != 0u ? 16u : 32u);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_VDUP_GPR_DEST) {
            uint32_t q = (word >> 21) & 1u;
            uint32_t d = (word >> 7) & 1u;
            uint32_t vd = (word >> 16) & 15u;
            uint32_t number = (d << 4) | vd;

            if (operation->value > 1u || q != operation->value
                || (q != 0u && (number & 1u) != 0u)) {
                return 0u;
            }
            arm_asmgen_putc(&writer, q != 0u ? 'q' : 'd');
            arm_asmgen_put_unsigned(&writer,
                q != 0u ? number >> 1 : number);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_VMOV_SM_NEXT) {
            uint32_t first = ((word & 15u) << 1)
                | ((word >> 5) & 1u);

            if (operation->value != 0u || first >= 31u) {
                return 0u;
            }
            arm_asmgen_putc(&writer, 's');
            arm_asmgen_put_unsigned(&writer, first + 1u);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_INDEXED_VM) {
            uint32_t size = (word >> 22) & 3u;
            uint32_t register_number = (word >> 16) & 15u;

            if (operation->value != 0u || (size != 1u && size != 2u)) {
                return 0u;
            }
            if (size == 2u) {
                register_number |= ((word >> 20) & 1u) << 4;
            }
            if (register_number > 31u
                || (size == 1u && register_number > 15u)) {
                return 0u;
            }
            arm_asmgen_put_unsigned(&writer, register_number);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_INDEXED_LANE) {
            uint32_t size = (word >> 22) & 3u;
            uint32_t h = (word >> 11) & 1u;
            uint32_t l = (word >> 21) & 1u;
            uint32_t m = (word >> 20) & 1u;
            uint32_t lane_index;

            if (operation->value != 0u || (size != 1u && size != 2u)) {
                return 0u;
            }
            lane_index = size == 1u ? ((h << 2) | (l << 1) | m)
                : ((h << 1) | l);
            if (lane_index > (size == 1u ? 7u : 3u)) {
                return 0u;
            }
            arm_asmgen_put_unsigned(&writer, lane_index);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_FP_INDEXED_LANE) {
            uint32_t sz = (word >> 22) & 1u;
            uint32_t l = (word >> 21) & 1u;
            uint32_t h = (word >> 11) & 1u;
            uint32_t lane_index;

            if (operation->value != 0u || (sz != 0u && l != 0u)) {
                return 0u;
            }
            lane_index = sz != 0u ? h : (h << 1) | l;
            arm_asmgen_put_unsigned(&writer, lane_index);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_DMX_LANE) {
            uint32_t size = (word >> 20) & 3u;
            uint32_t vm = word & 15u;
            uint32_t m = (word >> 5) & 1u;
            uint32_t register_number;
            uint32_t lane_index;

            if (operation->value != 0u || (size != 1u && size != 2u)) {
                return 0u;
            }
            if (size == 1u) {
                register_number = vm & 7u;
                lane_index = (m << 1) | (vm >> 3);
            } else {
                register_number = vm;
                lane_index = m;
            }
            if (register_number > (size == 1u ? 7u : 15u)
                || lane_index > (size == 1u ? 3u : 1u)) {
                return 0u;
            }
            arm_asmgen_putc(&writer, 'd');
            arm_asmgen_put_unsigned(&writer, register_number);
            arm_asmgen_putc(&writer, '[');
            arm_asmgen_put_unsigned(&writer, lane_index);
            arm_asmgen_putc(&writer, ']');
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_VDUP_LANE) {
            uint32_t imm4 = (word >> 16) & 15u;
            uint32_t register_number = (((word >> 5) & 1u) << 4)
                | (word & 15u);
            uint32_t lane_index;

            if (operation->value != 0u || (imm4 & 7u) == 0u) {
                return 0u;
            }
            lane_index = (imm4 & 1u) != 0u ? imm4 >> 1
                : (imm4 & 2u) != 0u ? imm4 >> 2 : imm4 >> 3;
            arm_asmgen_putc(&writer, 'd');
            arm_asmgen_put_unsigned(&writer, register_number);
            arm_asmgen_putc(&writer, '[');
            arm_asmgen_put_unsigned(&writer, lane_index);
            arm_asmgen_putc(&writer, ']');
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_VDUP_LANE_SIZE) {
            uint32_t imm4 = (word >> 16) & 15u;

            if (operation->value != 0u || (imm4 & 7u) == 0u) {
                return 0u;
            }
            arm_asmgen_put_unsigned(&writer,
                (imm4 & 1u) != 0u ? 8u
                : (imm4 & 2u) != 0u ? 16u : 32u);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_SPLIT_INDEXED_DM
            || operation->opcode
                == CDISASM_ARM_ASMGEN_A32_SPLIT_INDEXED_LANE) {
            uint32_t size = operation->value == 0u
                ? 1u : (word >> 20) & 3u;
            uint32_t vm = word & 15u;
            uint32_t m = (word >> 5) & 1u;

            if (operation->value > 1u || (size != 1u && size != 2u)) {
                return 0u;
            }
            if (operation->opcode == CDISASM_ARM_ASMGEN_A32_SPLIT_INDEXED_DM) {
                arm_asmgen_putc(&writer, 'd');
                arm_asmgen_put_unsigned(&writer,
                    size == 1u ? vm & 7u : vm);
            } else {
                arm_asmgen_put_unsigned(&writer,
                    size == 1u ? ((vm >> 3) << 1) | m : m);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_BF16_INDEXED_LANE) {
            uint32_t vm = word & 15u;
            uint32_t m = (word >> 5) & 1u;

            if (operation->value != 0u) {
                return 0u;
            }
            arm_asmgen_put_unsigned(&writer, (m << 1) | (vm >> 3));
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_T32_SHIFT_ALIAS_IMM) {
            uint32_t kind = operation->value;
            uint32_t encoded = (((word >> 12) & 7u) << 2)
                | ((word >> 6) & 3u);

            if (kind > 3u || ((word >> 4) & 3u) != kind
                || (kind == 3u && encoded == 0u)) {
                return 0u;
            }
            arm_asmgen_put_unsigned(&writer,
                encoded == 0u && kind != 0u ? 32u : encoded);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_T32_DATA_PROC_SHIFT_AMOUNT) {
            uint32_t mode = operation->value;
            uint32_t encoded = (((word >> 12) & 7u) << 2)
                | ((word >> 6) & 3u);
            uint32_t stype = (word >> 4) & 3u;

            if (mode == 0u) {
                if (encoded == 0u && (stype == 0u || stype == 3u)) {
                    return 0u;
                }
                arm_asmgen_put_unsigned(&writer,
                    encoded == 0u ? 32u : encoded);
            } else if (mode == 1u) {
                if (((word >> 21) & 1u) != 1u || encoded == 0u) {
                    return 0u;
                }
                arm_asmgen_put_unsigned(&writer, encoded);
            } else {
                return 0u;
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_T32_SSAT_WIDTH_PLUS1) {
            if (operation->value != 0u) {
                return 0u;
            }
            arm_asmgen_put_unsigned(&writer, (word & 31u) + 1u);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_VCVT_SDM) {
            uint32_t vd = (word >> 12) & 15u;
            uint32_t d = (word >> 22) & 1u;

            if (operation->value != 0u) {
                return 0u;
            }
            arm_asmgen_putc(&writer, 's');
            arm_asmgen_put_unsigned(&writer, (vd << 1) | d);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_VCVT_DDM) {
            uint32_t vd = (word >> 12) & 15u;
            uint32_t d = (word >> 22) & 1u;

            if (operation->value != 0u || ((word >> 8) & 3u) != 3u) {
                return 0u;
            }
            arm_asmgen_putc(&writer, 'd');
            arm_asmgen_put_unsigned(&writer, (d << 4) | vd);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_VFP_FP_IMM8) {
            uint32_t size = (word >> 8) & 3u;
            uint8_t imm8 = (uint8_t)((((word >> 16) & 15u) << 4)
                | (word & 15u));

            if (operation->value < 1u || operation->value > 3u
                || size != operation->value) {
                return 0u;
            }
            arm_asmgen_put_sve_fp_imm8(&writer, imm8);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_VCVT_FBITS) {
            uint32_t width = ((word >> 7) & 1u) != 0u ? 32u : 16u;
            uint32_t scale = ((word & 15u) << 1) | ((word >> 5) & 1u);

            if (operation->value != 0u || scale >= width) {
                return 0u;
            }
            arm_asmgen_put_unsigned(&writer, width - scale);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_ASIMD_OPTIONAL_LSL) {
            uint32_t cmode = (word >> 12) & 15u;
            uint32_t low_bit = operation->value >= 3u ? 1u : 0u;
            uint32_t shift;

            if (operation->value == 1u || operation->value == 3u) {
                if ((cmode & 9u) != low_bit) {
                    return 0u;
                }
                shift = (cmode >> 1) * 8u;
            } else if (operation->value == 2u || operation->value == 4u) {
                if ((cmode & 13u) != (8u | low_bit)) {
                    return 0u;
                }
                shift = ((cmode >> 1) & 1u) * 8u;
            } else {
                return 0u;
            }
            if (shift != 0u) {
                const char *spelling = ", lsl #";
                while (*spelling != '\0') {
                    arm_asmgen_putc(&writer, *spelling++);
                }
                arm_asmgen_put_unsigned(&writer, shift);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE_OPTIONAL_VL) {
            uint32_t imm9 = (((word >> 16) & 63u) << 3)
                | ((word >> 10) & 7u);

            if (operation->value != 0u) {
                return 0u;
            }
            if (imm9 != 0u) {
                const char *prefix = ", #";
                const char *suffix = ", mul vl";
                while (*prefix != '\0') {
                    arm_asmgen_putc(&writer, *prefix++);
                }
                arm_asmgen_put_signed(&writer, imm9, 9u);
                while (*suffix != '\0') {
                    arm_asmgen_putc(&writer, *suffix++);
                }
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE_EXTEND_T) {
            uint32_t size = (word >> 22) & 3u;

            if ((operation->value != 1u && operation->value != 2u)
                || size < (operation->value == 1u ? 2u : 1u)
                || size > 3u) {
                return 0u;
            }
            arm_asmgen_putc(&writer, size == 1u ? 'h'
                : size == 2u ? 's' : 'd');
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_ASIMD_INS_TS) {
            uint32_t imm5 = (word >> 16) & 31u;
            char type;

            if (operation->value != 0u) {
                return 0u;
            }
            if ((imm5 & 1u) != 0u) {
                type = 'b';
            } else if ((imm5 & 2u) != 0u) {
                type = 'h';
            } else if ((imm5 & 4u) != 0u) {
                type = 's';
            } else if ((imm5 & 8u) != 0u) {
                type = 'd';
            } else {
                return 0u;
            }
            arm_asmgen_putc(&writer, type);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_ASIMD_IMM5_SIZE) {
            uint32_t imm5 = (word >> 16) & 31u;
            uint32_t q = (word >> 30) & 1u;
            uint32_t element;
            static const char lower[] = "bhsd";

            if (operation->value > 3u || (imm5 & 15u) == 0u) {
                return 0u;
            }
            element = (imm5 & 1u) != 0u ? 0u
                : (imm5 & 2u) != 0u ? 1u
                : (imm5 & 4u) != 0u ? 2u : 3u;
            if (operation->value == 0u) {
                if (element == 3u && q == 0u) {
                    return 0u;
                }
                arm_asmgen_put_unsigned(&writer,
                    (8u << q) >> element);
                arm_asmgen_putc(&writer, lower[element]);
            } else {
                if ((operation->value == 2u && element > 1u)
                    || (operation->value == 3u && element > 2u)) {
                    return 0u;
                }
                arm_asmgen_putc(&writer, lower[element]);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_ASIMD_MSL_AMOUNT) {
            uint32_t cmode = (word >> 12) & 15u;

            if (operation->value != 0u || (cmode & 14u) != 12u) {
                return 0u;
            }
            arm_asmgen_put_unsigned(&writer,
                (cmode & 1u) != 0u ? 16u : 8u);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_ASIMD_INS_R) {
            uint32_t imm5 = (word >> 16) & 31u;

            if (operation->value != 0u || (imm5 & 15u) == 0u) {
                return 0u;
            }
            arm_asmgen_putc(&writer, (imm5 & 7u) != 0u ? 'w' : 'x');
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_ASIMD_INS_LANE) {
            uint32_t imm5 = (word >> 16) & 31u;
            uint32_t imm4 = (word >> 11) & 15u;
            uint32_t marker;

            if (operation->value > 1u || (imm5 & 15u) == 0u) {
                return 0u;
            }
            for (marker = 0u; marker < 4u; ++marker) {
                if ((imm5 & (1u << marker)) != 0u) {
                    break;
                }
            }
            if (operation->value == 0u) {
                arm_asmgen_put_unsigned(&writer, imm5 >> (marker + 1u));
            } else {
                if ((imm4 & ((1u << marker) - 1u)) != 0u) {
                    return 0u;
                }
                arm_asmgen_put_unsigned(&writer, imm4 >> marker);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_ASIMD_INS_RN) {
            uint32_t rn = (word >> 5) & 31u;

            if (operation->value != 0u) {
                return 0u;
            }
            if (rn == 31u) {
                arm_asmgen_putc(&writer, 'z');
                arm_asmgen_putc(&writer, 'r');
            } else {
                arm_asmgen_put_unsigned(&writer, rn);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_MRS_SPEC_REG) {
            uint32_t selector;

            if (operation->value != 20u && operation->value != 22u) {
                return 0u;
            }
            selector = (word >> operation->value) & 1u;
            if (selector == 0u) {
                arm_asmgen_putc(&writer, 'a');
                arm_asmgen_putc(&writer, 'p');
                arm_asmgen_putc(&writer, 's');
                arm_asmgen_putc(&writer, 'r');
            } else {
                arm_asmgen_putc(&writer, 's');
                arm_asmgen_putc(&writer, 'p');
                arm_asmgen_putc(&writer, 's');
                arm_asmgen_putc(&writer, 'r');
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_VFP_SPEC_REG) {
            uint32_t reg = (word >> 16) & 15u;
            const char *name;

            if (operation->value > 1u) {
                return 0u;
            }
            switch (reg) {
            case 0u: name = "fpsid"; break;
            case 1u: name = "fpscr"; break;
            case 5u: name = operation->value == 1u ? "mvfr2" : NULL; break;
            case 6u: name = operation->value == 1u ? "mvfr1" : NULL; break;
            case 7u: name = operation->value == 1u ? "mvfr0" : NULL; break;
            case 8u: name = "fpexc"; break;
            default: name = NULL; break;
            }
            if (name == NULL) {
                return 0u;
            }
            while (*name != '\0') {
                arm_asmgen_putc(&writer, *name++);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_VSHLL_SIGN) {
            if (operation->value != 24u && operation->value != 28u) {
                return 0u;
            }
            arm_asmgen_putc(&writer,
                ((word >> operation->value) & 1u) != 0u ? 'u' : 's');
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_VSHLL_IMM6) {
            uint32_t imm6 = (word >> 16) & 63u;
            uint32_t element_width;

            if (operation->value > 1u || imm6 < 8u) {
                return 0u;
            }
            element_width = imm6 >= 32u ? 32u
                : imm6 >= 16u ? 16u : 8u;
            arm_asmgen_put_unsigned(&writer,
                operation->value == 0u
                    ? element_width : imm6 - element_width);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_BARRIER_OPTION) {
            uint32_t option = word & 15u;
            const char *name;

            if (operation->value != 0u) {
                return 0u;
            }
            switch (option) {
            case 15u: name = "sy"; break;
            case 14u: name = "st"; break;
            case 13u: name = "ld"; break;
            case 11u: name = "ish"; break;
            case 10u: name = "ishst"; break;
            case 9u: name = "ishld"; break;
            case 7u: name = "nsh"; break;
            case 6u: name = "nshst"; break;
            case 5u: name = "nshld"; break;
            case 3u: name = "osh"; break;
            case 2u: name = "oshst"; break;
            case 1u: name = "oshld"; break;
            default: name = NULL; break;
            }
            if (name == NULL) {
                return 0u;
            }
            while (*name != '\0') {
                arm_asmgen_putc(&writer, *name++);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE_GPR_WIDTH) {
            if (operation->value != 0u) {
                return 0u;
            }
            arm_asmgen_putc(&writer,
                ((word >> 22) & 3u) == 3u ? 'x' : 'w');
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE_GPR_NUMBER) {
            uint32_t number;

            if (operation->value != 0u && operation->value != 5u
                && operation->value != 16u) {
                return 0u;
            }
            number = (word >> operation->value) & 31u;
            if (number == 31u) {
                arm_asmgen_putc(&writer, 'z');
                arm_asmgen_putc(&writer, 'r');
            } else {
                arm_asmgen_put_unsigned(&writer, number);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE_T_SIZE) {
            static const char letters[4] = { 'b', 'h', 's', 'd' };
            uint32_t shift = operation->value & 255u;
            uint32_t minimum = (operation->value >> 8) & 255u;
            uint32_t maximum = operation->value >> 16;
            uint32_t size;

            if ((shift != 12u && shift != 13u && shift != 17u
                    && shift != 21u && shift != 22u)
                || minimum < 1u || minimum > 2u
                || maximum < minimum || maximum > 3u) {
                return 0u;
            }
            size = (word >> shift) & 3u;
            if (size < minimum || size > maximum) {
                return 0u;
            }
            arm_asmgen_putc(&writer, letters[size]);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE_TSZHL_TYPE) {
            uint32_t selector = (((word >> 22) & 3u) << 2)
                | ((word >> 19) & 3u);

            if (operation->value != 0u || selector == 0u) {
                return 0u;
            }
            arm_asmgen_putc(&writer, selector >= 8u ? 'd'
                : selector >= 4u ? 's'
                : selector >= 2u ? 'h' : 'b');
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE_TSZHL_SHIFT) {
            uint32_t selector = (((word >> 22) & 3u) << 2)
                | ((word >> 19) & 3u);
            uint32_t width;
            uint32_t encoded;

            if (operation->value > 1u || selector == 0u) {
                return 0u;
            }
            width = selector >= 8u ? 64u
                : selector >= 4u ? 32u
                : selector >= 2u ? 16u : 8u;
            encoded = (selector << 3) | ((word >> 16) & 7u);
            if (encoded < width || encoded >= 2u * width) {
                return 0u;
            }
            arm_asmgen_put_unsigned(&writer,
                operation->value == 0u
                    ? 2u * width - encoded : encoded - width);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE_PTRUE_PATTERN) {
            static const char *const names[14] = {
                "pow2", "vl1", "vl2", "vl3", "vl4", "vl5", "vl6",
                "vl7", "vl8", "vl16", "vl32", "vl64", "vl128", "vl256"
            };
            uint32_t pattern = (word >> 5) & 31u;
            const char *name;

            if (operation->value != 0u) {
                return 0u;
            }
            if (pattern == 31u) {
                continue;
            }
            arm_asmgen_putc(&writer, ',');
            arm_asmgen_putc(&writer, ' ');
            if (pattern <= 13u) {
                name = names[pattern];
            } else if (pattern == 29u) {
                name = "mul4";
            } else if (pattern == 30u) {
                name = "mul3";
            } else {
                arm_asmgen_putc(&writer, '#');
                arm_asmgen_put_unsigned(&writer, pattern);
                continue;
            }
            while (*name != '\0') {
                arm_asmgen_putc(&writer, *name++);
            }
        } else if (operation->opcode
                == CDISASM_ARM_ASMGEN_A64_SVE_DUPQ_TYPE
            || operation->opcode
                == CDISASM_ARM_ASMGEN_A64_SVE_DUPQ_LANE) {
            static const char letters[4] = { 'b', 'h', 's', 'd' };
            uint32_t tsz = (word >> 16) & 15u;
            uint32_t marker;

            if (operation->value != 0u || tsz == 0u) {
                return 0u;
            }
            for (marker = 0u; marker < 4u; ++marker) {
                if ((tsz & (1u << marker)) != 0u) {
                    break;
                }
            }
            if (operation->opcode == CDISASM_ARM_ASMGEN_A64_SVE_DUPQ_TYPE) {
                arm_asmgen_putc(&writer, letters[marker]);
            } else {
                uint32_t i1 = (word >> 20) & 1u;

                arm_asmgen_put_unsigned(&writer,
                    ((i1 << 4) | tsz) >> (marker + 1u));
            }
        } else if (operation->opcode
                == CDISASM_ARM_ASMGEN_A64_SME_PSEL_TYPE
            || operation->opcode
                == CDISASM_ARM_ASMGEN_A64_SME_PSEL_LANE) {
            static const char letters[4] = { 'b', 'h', 's', 'd' };
            uint32_t selector = (((word >> 22) & 1u) << 3)
                | ((word >> 18) & 7u);
            uint32_t marker;

            if (operation->value != 0u || selector == 0u) {
                return 0u;
            }
            for (marker = 0u; marker < 4u; ++marker) {
                if ((selector & (1u << marker)) != 0u) {
                    break;
                }
            }
            if (operation->opcode == CDISASM_ARM_ASMGEN_A64_SME_PSEL_TYPE) {
                arm_asmgen_putc(&writer, letters[marker]);
            } else {
                uint32_t i1 = (word >> 23) & 1u;

                arm_asmgen_put_unsigned(&writer,
                    ((i1 << 4) | selector) >> (marker + 1u));
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SME_PSEL_WV) {
            if (operation->value != 0u) {
                return 0u;
            }
            arm_asmgen_putc(&writer, 'w');
            arm_asmgen_put_unsigned(&writer, 12u + ((word >> 16) & 3u));
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SME_LUTI6_STRIDE4_DEST) {
            uint32_t offset;

            if (operation->value > 7u
                || (operation->value < 4u
                    && (word & UINT32_C(0xfffffc6c))
                        != UINT32_C(0xc09a0000))
                || (operation->value >= 4u
                    && (word & UINT32_C(0xffa0fc0c))
                        != UINT32_C(0xc120fc00))) {
                return 0u;
            }
            offset = operation->value & 3u;
            arm_asmgen_putc(&writer, 'z');
            arm_asmgen_put_unsigned(&writer,
                (((word >> 4) & 1u) << 4) + (word & 3u)
                + (offset << 2));
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SME_LUTI6_TRIPLE_SOURCE) {
            if (operation->value > 1u
                || (word & UINT32_C(0xfffffc6c))
                    != UINT32_C(0xc09a0000)) {
                return 0u;
            }
            arm_asmgen_putc(&writer, 'z');
            arm_asmgen_put_unsigned(&writer,
                ((word >> 7) & 7u) + 2u * operation->value);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SME_LUTI6_PAIR_SOURCE) {
            uint32_t first;

            if (operation->value > 3u
                || (word & UINT32_C(0xffa0fc0c))
                    != UINT32_C(0xc120fc00)) {
                return 0u;
            }
            first = operation->value < 2u
                ? (word >> 5) & 31u : (word >> 16) & 31u;
            arm_asmgen_putc(&writer, 'z');
            arm_asmgen_put_unsigned(&writer,
                (first + (operation->value & 1u)) & 31u);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SME_LUTI4_ZD_GROUP) {
            arm_asmgen_putc(&writer, 'z');
            if (operation->value == 0u || operation->value == 3u) {
                arm_asmgen_put_unsigned(&writer,
                    (((word >> 2) & 7u) << 2) + operation->value);
            } else if (operation->value >= 4u && operation->value <= 7u
                       && (word & 3u) == 0u) {
                arm_asmgen_put_unsigned(&writer,
                    (((word >> 4) & 1u) << 4) + operation->value - 4u);
            } else if ((operation->value == 8u || operation->value == 9u)
                       && (word & 3u) == 0u) {
                arm_asmgen_put_unsigned(&writer,
                    (((word >> 6) & 15u) << 1) + operation->value - 8u);
            } else {
                return 0u;
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_BARRIER_OPTION) {
            static const char *const names[16] = {
                NULL, "oshld", "oshst", "osh",
                NULL, "nshld", "nshst", "nsh",
                NULL, "ishld", "ishst", "ish",
                NULL, "ld", "st", "sy"
            };
            uint32_t option = (word >> 8) & 15u;
            const char *name;

            if (operation->value != 0u) {
                return 0u;
            }
            name = names[option];
            if (name == NULL) {
                arm_asmgen_putc(&writer, '#');
                arm_asmgen_put_unsigned(&writer, option);
            } else {
                while (*name != '\0') {
                    arm_asmgen_putc(&writer, *name++);
                }
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_RPRFM_OPTION) {
            uint32_t option = (word >> 13) & 7u;
            uint32_t rt = word & 31u;
            uint32_t hint;
            const char *name;

            if (operation->value != 0u || (option & 2u) == 0u
                || (rt & 24u) != 24u) {
                return 0u;
            }
            hint = (((option >> 2) & 1u) << 5)
                | ((option & 1u) << 4)
                | (((word >> 12) & 1u) << 3) | (rt & 7u);
            switch (hint) {
            case 0u: name = "pldkeep"; break;
            case 4u: name = "pldstrm"; break;
            case 1u: name = "pstkeep"; break;
            case 5u: name = "pststrm"; break;
            default: name = NULL; break;
            }
            if (name == NULL) {
                arm_asmgen_putc(&writer, '#');
                arm_asmgen_put_unsigned(&writer, hint);
            } else {
                while (*name != '\0') {
                    arm_asmgen_putc(&writer, *name++);
                }
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_STSHH_POLICY) {
            uint32_t op2 = (word >> 5) & 7u;
            const char *name;

            if (operation->value != 0u || op2 > 1u) {
                return 0u;
            }
            name = op2 == 0u ? "keep" : "strm";
            while (*name != '\0') {
                arm_asmgen_putc(&writer, *name++);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SHUH_PRIORITY) {
            uint32_t op2 = (word >> 5) & 7u;

            if (operation->value != 0u || op2 < 2u || op2 > 3u
                || (word & UINT32_C(0xffffffdf))
                    != UINT32_C(0xd503265f)) {
                return 0u;
            }
            if (op2 == 3u) {
                arm_asmgen_putc(&writer, ' ');
                arm_asmgen_putc(&writer, 'p');
                arm_asmgen_putc(&writer, 'h');
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SME_STATE_ALIAS) {
            uint32_t crm = (word >> 8) & 15u;
            uint32_t state = crm >> 1;

            if (operation->value > 1u
                || (word & UINT32_C(0xfffff0ff))
                    != UINT32_C(0xd503407f)
                || (crm & 1u) != (operation->value == 0u ? 1u : 0u)
                || state < 1u || state > 3u) {
                return 0u;
            }
            if (state != 3u) {
                arm_asmgen_putc(&writer, ' ');
                arm_asmgen_putc(&writer, state == 1u ? 's' : 'z');
                arm_asmgen_putc(&writer, state == 1u ? 'm' : 'a');
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_PSTATE_MSR) {
            uint8_t field;
            uint8_t immediate;
            const char *name;

            if (operation->value != 0u
                || !arm_pstate_msr_decode_word(word, &field, &immediate)) {
                return 0u;
            }
            name = arm_pstate_msr_field_name(field);
            if (name == NULL) {
                return 0u;
            }
            arm_asmgen_putc(&writer, ' ');
            while (*name != '\0') {
                arm_asmgen_putc(&writer, *name++);
            }
            arm_asmgen_putc(&writer, ',');
            arm_asmgen_putc(&writer, ' ');
            arm_asmgen_putc(&writer, '#');
            arm_asmgen_put_hex(&writer, immediate);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_ISB_OPTION) {
            uint32_t option = (word >> 8) & 15u;

            if (operation->value != 0u) {
                return 0u;
            }
            if (option != 15u) {
                arm_asmgen_putc(&writer, ' ');
                arm_asmgen_putc(&writer, '#');
                arm_asmgen_put_unsigned(&writer, option);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_NEON_VCVT_SHIFT_BITS) {
            uint32_t op = (word >> 8) & 3u;
            uint32_t imm6 = (word >> 16) & 63u;
            uint32_t width = (op & 2u) != 0u ? 32u : 16u;
            uint32_t fraction_bits = 64u - imm6;

            if (operation->value != 0u || fraction_bits == 0u
                || fraction_bits > width) {
                return 0u;
            }
            arm_asmgen_put_unsigned(&writer, fraction_bits);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_NEON_VCVT_DATATYPE) {
            uint32_t size_bits;
            char kind;
            uint32_t width;

            if (operation->value == 0u) {
                uint32_t op = (word >> 7) & 3u;

                size_bits = (word >> 18) & 3u;
                if (size_bits != 1u && size_bits != 2u) {
                    return 0u;
                }
                width = size_bits == 1u ? 16u : 32u;
                kind = op < 2u ? 'f' : op == 2u ? 's' : 'u';
            } else if (operation->value == 1u
                       || operation->value == 2u) {
                uint32_t op = (word >> 8) & 3u;
                uint32_t unsigned_bit = (word >>
                    (operation->value == 2u ? 28u : 24u)) & 1u;

                width = (op & 2u) != 0u ? 32u : 16u;
                kind = (op & 1u) == 0u ? 'f'
                    : unsigned_bit != 0u ? 'u' : 's';
            } else {
                return 0u;
            }
            arm_asmgen_putc(&writer, kind);
            arm_asmgen_put_unsigned(&writer, width);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_NEON_VCVT_SOURCE_DATATYPE) {
            char kind;
            uint32_t width;

            if (operation->value == 0u) {
                uint32_t size_bits = (word >> 18) & 3u;
                uint32_t op = (word >> 7) & 3u;

                if (size_bits != 1u && size_bits != 2u) {
                    return 0u;
                }
                width = size_bits == 1u ? 16u : 32u;
                kind = (op & 2u) != 0u ? 'f'
                    : (op & 1u) != 0u ? 'u' : 's';
            } else if (operation->value == 1u
                       || operation->value == 2u) {
                uint32_t op = (word >> 8) & 3u;
                uint32_t unsigned_bit = (word >>
                    (operation->value == 2u ? 28u : 24u)) & 1u;

                width = (op & 2u) != 0u ? 32u : 16u;
                kind = (op & 1u) != 0u ? 'f'
                    : unsigned_bit != 0u ? 'u' : 's';
            } else {
                return 0u;
            }
            arm_asmgen_putc(&writer, kind);
            arm_asmgen_put_unsigned(&writer, width);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_NEON_MODIFIED_IMM) {
            uint32_t cmode = (word >> 8) & 15u;
            uint32_t op = (word >> 5) & 1u;
            uint32_t family = operation->value & UINT32_C(0xff);
            uint32_t thumb = operation->value >> 8;
            uint32_t imm8 = (((word >> (thumb ? 28u : 24u)) & 1u) << 7)
                | (((word >> 16) & 7u) << 4) | (word & 15u);
            uint64_t immediate;

            if (thumb > 1u
                || (family == 1u && (cmode > 6u || (cmode & 1u) != 0u
                    || op != 1u))
                || (family == 2u && (cmode > 7u || (cmode & 1u) == 0u
                    || op != 0u))
                || (family == 3u && (cmode > 7u || (cmode & 1u) == 0u
                    || op != 1u))
                || (family == 4u && ((cmode != 8u && cmode != 10u)
                    || op != 1u))
                || (family == 5u && ((cmode != 9u && cmode != 11u)
                    || op != 0u))
                || (family == 6u && ((cmode != 9u && cmode != 11u)
                    || op != 1u))
                || (family == 7u && ((cmode != 12u && cmode != 13u)
                    || op != 1u))
                || (family == 8u && (cmode > 6u || (cmode & 1u) != 0u
                    || op != 0u))
                || (family == 9u && ((cmode != 8u && cmode != 10u)
                    || op != 0u))
                || (family == 10u && (cmode != 14u || op != 1u))
                || (family == 11u && ((cmode != 12u && cmode != 13u)
                    || op != 0u))
                || family == 0u || family > 11u) {
                return 0u;
            }
            if (family <= 3u || family == 8u) {
                immediate = imm8 << ((cmode >> 1) * 8u);
            } else if (family <= 6u || family == 9u) {
                immediate = imm8 << (((cmode >> 1) & 1u) * 8u);
            } else if ((family == 7u || family == 11u)
                && cmode == 12u) {
                immediate = (imm8 << 8) | UINT32_C(0xff);
            } else if (family == 7u || family == 11u) {
                immediate = (imm8 << 16) | UINT32_C(0xffff);
            } else {
                uint32_t bit;

                immediate = 0u;
                for (bit = 0u; bit < 8u; ++bit) {
                    if ((imm8 & (1u << bit)) != 0u) {
                        immediate |= UINT64_C(0xff) << (bit * 8u);
                    }
                }
            }
            arm_asmgen_put_hex(&writer, immediate);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_NEON_VAND_ALIAS_IMM) {
            uint32_t cmode = (word >> 8) & 15u;
            uint32_t thumb = operation->value & 1u;
            uint32_t sixteen_bit = (operation->value >> 1) & 1u;
            uint32_t op = (word >> 5) & 1u;
            uint32_t imm8;
            uint32_t shift;
            uint32_t immediate;

            if (operation->value > 3u || op != 1u
                || (sixteen_bit != 0u
                    ? (cmode != 9u && cmode != 11u)
                    : (cmode > 7u || (cmode & 1u) == 0u))) {
                return 0u;
            }
            imm8 = (((word >> (thumb != 0u ? 28u : 24u)) & 1u) << 7)
                | (((word >> 16) & 7u) << 4) | (word & 15u);
            shift = sixteen_bit != 0u
                ? (((cmode >> 1) & 1u) * 8u)
                : ((cmode >> 1) * 8u);
            immediate = ~(imm8 << shift);
            if (sixteen_bit != 0u) {
                immediate &= UINT32_C(0xffff);
            }
            arm_asmgen_put_hex(&writer, immediate);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_CPS_IFLAGS) {
            uint32_t mask;

            if (operation->value != 0u && operation->value != 5u
                && operation->value != 6u) {
                return 0u;
            }
            mask = (word >> operation->value) & 7u;
            if (mask == 0u) {
                return 0u;
            }
            if ((mask & 4u) != 0u) {
                arm_asmgen_putc(&writer, 'a');
            }
            if ((mask & 2u) != 0u) {
                arm_asmgen_putc(&writer, 'i');
            }
            if ((mask & 1u) != 0u) {
                arm_asmgen_putc(&writer, 'f');
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_ASIMD_SHIFT_IMMEDIATE) {
            uint32_t immh = (word >> 19) & 15u;
            uint32_t immb = (word >> 16) & 7u;
            uint32_t q = (word >> 30) & 1u;
            uint32_t element_bits;
            uint32_t encoded;
            uint32_t shift;

            if (operation->value > 1u || immh == 0u
                || ((immh & 8u) != 0u && q == 0u)) {
                return 0u;
            }
            element_bits = (immh & 8u) != 0u ? 64u
                : (immh & 4u) != 0u ? 32u
                : (immh & 2u) != 0u ? 16u : 8u;
            encoded = (immh << 3) | immb;
            shift = operation->value == 0u
                ? encoded - element_bits
                : 2u * element_bits - encoded;
            if ((operation->value == 0u && shift >= element_bits)
                || (operation->value == 1u
                    && (shift == 0u || shift > element_bits))) {
                return 0u;
            }
            arm_asmgen_put_unsigned(&writer, shift);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_ASIMD_SHIFT_T) {
            uint32_t immh = (word >> 19) & 15u;
            uint32_t q = (word >> 30) & 1u;
            uint32_t lanes;
            char element;

            if (operation->value != 0u || immh == 0u) {
                return 0u;
            }
            if ((immh & 8u) != 0u) {
                if (q == 0u) {
                    return 0u;
                }
                lanes = 2u;
                element = 'd';
            } else if ((immh & 4u) != 0u) {
                lanes = q != 0u ? 4u : 2u;
                element = 's';
            } else if ((immh & 2u) != 0u) {
                lanes = q != 0u ? 8u : 4u;
                element = 'h';
            } else {
                lanes = q != 0u ? 16u : 8u;
                element = 'b';
            }
            arm_asmgen_put_unsigned(&writer, lanes);
            arm_asmgen_putc(&writer, element);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_ASIMD_NARROW_ARRANGEMENT) {
            uint32_t immh = (word >> 19) & 15u;
            uint32_t q = (word >> 30) & 1u;
            uint32_t lanes = 0u;
            char element;

            if (operation->value > 3u || immh == 0u || immh >= 8u) {
                return 0u;
            }
            if (operation->value == 0u) {
                lanes = (immh & 4u) != 0u ? (q != 0u ? 4u : 2u)
                    : (immh & 2u) != 0u ? (q != 0u ? 8u : 4u)
                    : (q != 0u ? 16u : 8u);
                element = (immh & 4u) != 0u ? 's'
                    : (immh & 2u) != 0u ? 'h' : 'b';
            } else if (operation->value == 1u) {
                lanes = (immh & 4u) != 0u ? 2u
                    : (immh & 2u) != 0u ? 4u : 8u;
                element = (immh & 4u) != 0u ? 'd'
                    : (immh & 2u) != 0u ? 's' : 'h';
            } else {
                element = (immh & 4u) != 0u
                    ? (operation->value == 2u ? 's' : 'd')
                    : (immh & 2u) != 0u
                    ? (operation->value == 2u ? 'h' : 's')
                    : (operation->value == 2u ? 'b' : 'h');
            }
            if (lanes != 0u) {
                arm_asmgen_put_unsigned(&writer, lanes);
            }
            arm_asmgen_putc(&writer, element);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_ASIMD_FIXED_FCVT_SIZE
            || operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SIMD_FIXED_FCVT_SIZE) {
            uint32_t immh = (word >> 19) & 15u;
            uint32_t q = (word >> 30) & 1u;
            uint32_t vector = operation->opcode
                == CDISASM_ARM_ASMGEN_A64_ASIMD_FIXED_FCVT_SIZE;
            uint32_t lanes = 0u;
            char element;

            if (operation->value != 0u || immh < 2u) {
                return 0u;
            }
            if ((immh & 8u) != 0u) {
                if (vector && q == 0u) {
                    return 0u;
                }
                lanes = 2u;
                element = 'd';
            } else if ((immh & 4u) != 0u) {
                lanes = q != 0u ? 4u : 2u;
                element = 's';
            } else {
                lanes = q != 0u ? 8u : 4u;
                element = 'h';
            }
            if (vector) {
                arm_asmgen_put_unsigned(&writer, lanes);
            }
            arm_asmgen_putc(&writer, element);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_VFP_MULTI_SIZE) {
            uint32_t size = (word >> 8) & 3u;

            if (operation->value != 0u || (size != 2u && size != 3u)) {
                return 0u;
            }
            arm_asmgen_putc(&writer, '.');
            arm_asmgen_put_unsigned(&writer, size == 2u ? 32u : 64u);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_VFP_MULTI_LIST) {
            uint32_t size = (word >> 8) & 3u;
            uint32_t count = word & 255u;
            uint32_t first_register;
            uint32_t base_register = (word >> 16) & 15u;
            uint32_t writeback = (word >> 21) & 1u;
            uint32_t list_index;

            if (operation->value > 1u
                || size != (operation->value == 0u ? 2u : 3u)
                || (base_register == 15u
                    && (isa_id != CDISASM_ARM_ISA_A32
                        || writeback != 0u))) {
                return 0u;
            }
            if (operation->value == 0u) {
                first_register = (((word >> 12) & 15u) << 1)
                    | ((word >> 22) & 1u);
                if (count == 0u || count > 32u
                    || first_register + count > 32u) {
                    return 0u;
                }
            } else {
                first_register = ((word >> 12) & 15u)
                    | (((word >> 22) & 1u) << 4);
                if ((count & 1u) != 0u) {
                    return 0u;
                }
                count >>= 1;
                if (count == 0u || count > 16u
                    || first_register + count > 32u) {
                    return 0u;
                }
            }
            arm_asmgen_putc(&writer, '{');
            for (list_index = 0u; list_index < count; ++list_index) {
                if (list_index != 0u) {
                    arm_asmgen_putc(&writer, ',');
                    arm_asmgen_putc(&writer, ' ');
                }
                arm_asmgen_putc(&writer,
                    operation->value == 0u ? 's' : 'd');
                arm_asmgen_put_unsigned(
                    &writer, first_register + list_index);
            }
            arm_asmgen_putc(&writer, '}');
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_VECTOR_D_LIST) {
            uint32_t low_shift = operation->value & UINT32_C(31);
            uint32_t high_shift = (operation->value >> 5) & UINT32_C(31);
            uint32_t count = (operation->value >> 10) & UINT32_C(7);
            uint32_t stride = 1u;
            uint32_t lane_shift = (operation->value >> 22) & UINT32_C(31);
            uint32_t first_register;
            uint32_t index;

            if ((operation->value & (UINT32_C(1) << 13)) != 0u) {
                count = ((word >> 8) & 3u) + 1u;
            }
            if ((operation->value & (UINT32_C(1) << 14)) != 0u) {
                uint32_t stride_shift =
                    (operation->value >> 17) & UINT32_C(31);

                stride += (word >> stride_shift) & 1u;
            }
            if ((operation->value & (UINT32_C(1) << 27)) != 0u) {
                count += (word >> 5) & 1u;
            }
            if (count == 0u || count > 4u
                || (operation->value & ~UINT32_C(0x0fffffff)) != 0u
                || ((operation->value & (UINT32_C(1) << 15)) != 0u
                    && (operation->value & (UINT32_C(1) << 16)) != 0u)
                || ((operation->value & (UINT32_C(1) << 16)) != 0u
                    && (lane_shift < 5u || lane_shift > 7u))) {
                return 0u;
            }
            first_register = ((word >> low_shift) & 15u)
                | (((word >> high_shift) & 1u) << 4);
            if (first_register + (count - 1u) * stride > 31u) {
                return 0u;
            }
            arm_asmgen_putc(&writer, '{');
            for (index = 0u; index < count; ++index) {
                if (index != 0u) {
                    arm_asmgen_putc(&writer, ',');
                    arm_asmgen_putc(&writer, ' ');
                }
                arm_asmgen_putc(&writer, 'd');
                arm_asmgen_put_unsigned(
                    &writer, first_register + index * stride);
                if ((operation->value & (UINT32_C(1) << 15)) != 0u) {
                    arm_asmgen_putc(&writer, '[');
                    arm_asmgen_putc(&writer, ']');
                } else if ((operation->value
                        & (UINT32_C(1) << 16)) != 0u) {
                    uint32_t lane_index = (word >> lane_shift)
                        & ((1u << (8u - lane_shift)) - 1u);

                    arm_asmgen_putc(&writer, '[');
                    arm_asmgen_put_unsigned(&writer, lane_index);
                    arm_asmgen_putc(&writer, ']');
                }
            }
            arm_asmgen_putc(&writer, '}');
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_FPX_D_LIST) {
            uint32_t first_register = ((word >> 12) & 15u)
                | (((word >> 22) & 1u) << 4);
            uint32_t count = (word & 255u) >> 1;
            uint32_t base_register = (word >> 16) & 15u;
            uint32_t writeback = (word >> 21) & 1u;
            uint32_t index;

            if (operation->value != 0u || (word & 1u) == 0u
                || count == 0u || count > 16u
                || first_register + count > 16u
                || (base_register == 15u
                    && (isa_id != CDISASM_ARM_ISA_A32
                        || writeback != 0u))) {
                return 0u;
            }
            arm_asmgen_putc(&writer, '{');
            for (index = 0u; index < count; ++index) {
                if (index != 0u) {
                    arm_asmgen_putc(&writer, ',');
                    arm_asmgen_putc(&writer, ' ');
                }
                arm_asmgen_putc(&writer, 'd');
                arm_asmgen_put_unsigned(&writer, first_register + index);
            }
            arm_asmgen_putc(&writer, '}');
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_NEON_ALIGNMENT) {
            uint32_t count = operation->value & 7u;
            uint32_t size;
            uint32_t alignment_bytes = 0u;

            if ((operation->value & ~UINT32_C(0x7f07)) != 0u
                || count == 0u || count > 4u) {
                return 0u;
            }
            if ((operation->value & (UINT32_C(1) << 11)) != 0u) {
                uint32_t list_count =
                    (operation->value >> 12) & UINT32_C(7);
                uint32_t encoded_align = (word >> 4) & 3u;

                size = (word >> 6) & 3u;
                if (list_count == 0u || list_count > 4u
                    || (count != 1u && size == 3u)
                    || (count == 1u
                        && (((list_count == 1u || list_count == 3u)
                                && encoded_align >= 2u)
                            || (list_count == 2u
                                && encoded_align == 3u)))
                    || (count == 2u && list_count == 2u
                        && encoded_align == 3u)
                    || (count == 3u && encoded_align >= 2u)) {
                    return 0u;
                }
                if (encoded_align != 0u) {
                    alignment_bytes = 4u << encoded_align;
                }
            } else if ((operation->value & (UINT32_C(1) << 10)) != 0u) {
                uint32_t align_bit = (word >> 4) & 1u;

                size = (word >> 6) & 3u;
                if (count == 3u
                    || (count != 4u && size > 2u)
                    || (count == 1u && size == 0u && align_bit != 0u)
                    || (count == 4u && size == 3u
                        && align_bit == 0u)) {
                    return 0u;
                }
                if (align_bit != 0u) {
                    alignment_bytes = count == 4u
                        ? (size == 3u ? 16u
                           : size == 2u ? 8u : 4u << size)
                        : count << size;
                }
            } else {
                uint32_t index_align = (word >> 4) & 15u;
                uint32_t low = index_align & 3u;

                size = (operation->value >> 8) & 3u;
                if (size > 2u || ((word >> 10) & 3u) != size) {
                    return 0u;
                }
                if (count == 1u) {
                    if ((size == 0u && (low & 1u) != 0u)
                        || (size == 1u && (low & 2u) != 0u)
                        || (size == 2u
                            && ((index_align & 4u) != 0u
                                || (low != 0u && low != 3u)))) {
                        return 0u;
                    }
                    if (size == 1u && (low & 1u) != 0u) {
                        alignment_bytes = 2u;
                    } else if (size == 2u && low == 3u) {
                        alignment_bytes = 4u;
                    }
                } else if (count == 2u) {
                    if (size == 2u && (low & 2u) != 0u) {
                        return 0u;
                    }
                    if ((low & 1u) != 0u) {
                        alignment_bytes = 2u << size;
                    }
                } else if (count == 3u) {
                    if ((size == 1u && (low & 1u) != 0u)
                        || (size == 2u && low != 0u)) {
                        return 0u;
                    }
                } else {
                    if (size == 2u) {
                        if (low == 3u) {
                            return 0u;
                        }
                        if (low != 0u) {
                            alignment_bytes = 4u << low;
                        }
                    } else if ((low & 1u) != 0u) {
                        alignment_bytes = 4u << size;
                    }
                }
            }
            if (alignment_bytes != 0u) {
                arm_asmgen_putc(&writer, ':');
                arm_asmgen_put_unsigned(&writer, alignment_bytes * 8u);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_THUMB_EXPAND_IMM) {
            if (!arm_asmgen_eval_expression(operation->value, word, &value)
                || value.width != 12u) {
                return 0u;
            }
            arm_asmgen_put_unsigned(
                &writer, arm_asmgen_thumb_expand_imm((uint32_t)value.value));
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_VSHLL_FULL_SHIFT) {
            uint32_t size = (word >> 18) & 3u;

            if (operation->value != 0u || size > 2u) {
                return 0u;
            }
            arm_asmgen_put_unsigned(&writer, UINT32_C(8) << size);
        } else if (operation->opcode
                == CDISASM_ARM_ASMGEN_A64_LOGICAL_IMM32
            || operation->opcode
                == CDISASM_ARM_ASMGEN_A64_LOGICAL_IMM64) {
            uint64_t logical_immediate;
            uint32_t register_width = operation->opcode
                == CDISASM_ARM_ASMGEN_A64_LOGICAL_IMM64 ? 64u : 32u;

            if (!arm_asmgen_eval_expression(operation->value, word, &value)
                || !arm_asmgen_decode_logical_immediate(
                    value.value, register_width, &logical_immediate)) {
                return 0u;
            }
            arm_asmgen_put_unsigned(&writer, logical_immediate);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_MOVWIDE_ALIAS_IMM) {
            uint32_t mode = operation->value;
            uint32_t hw = (word >> 21) & 3u;
            uint64_t immediate;

            if (mode > 3u || ((mode & 2u) == 0u && hw > 1u)) {
                return 0u;
            }
            immediate = (uint64_t)((word >> 5) & UINT32_C(0xffff))
                << (hw * 16u);
            if ((mode & 1u) == 0u) {
                immediate = ~immediate;
            }
            if ((mode & 2u) == 0u) {
                immediate &= UINT32_MAX;
            }
            arm_asmgen_put_unsigned(&writer, immediate);
        } else if (operation->opcode
                == CDISASM_ARM_ASMGEN_A64_SVE_FP_IMM8
            || operation->opcode
                == CDISASM_ARM_ASMGEN_A64_ASIMD_FMOV_IMM8) {
            if (!arm_asmgen_eval_expression(operation->value, word, &value)
                || value.width != 8u || value.value > UINT8_MAX) {
                return 0u;
            }
            arm_asmgen_put_sve_fp_imm8(&writer, (uint8_t)value.value);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_ASIMD_MOVI_BYTE_MASK) {
            uint64_t immediate = 0u;
            uint32_t bit;

            if (!arm_asmgen_eval_expression(operation->value, word, &value)
                || value.width != 8u || value.value > UINT8_MAX) {
                return 0u;
            }
            for (bit = 0u; bit < 8u; ++bit) {
                if ((value.value & (UINT64_C(1) << bit)) != 0u) {
                    immediate |= UINT64_C(0xff) << (bit * 8u);
                }
            }
            arm_asmgen_put_hex(&writer, immediate);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_ASIMD_EXT_INDEX) {
            uint32_t q = (word >> 30) & 1u;
            uint32_t index = (word >> 11) & 15u;

            if (operation->value != 0u || (q == 0u && index > 7u)) {
                return 0u;
            }
            arm_asmgen_put_unsigned(&writer, index);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_FCMLA_INDEX) {
            uint32_t size = (word >> 22) & 3u;
            uint32_t q = (word >> 30) & 1u;
            uint32_t h = (word >> 11) & 1u;
            uint32_t l = (word >> 21) & 1u;

            if (operation->value != 0u
                || (size != 1u && size != 2u)
                || (size == 2u && (q == 0u || l != 0u))) {
                return 0u;
            }
            arm_asmgen_put_unsigned(&writer,
                size == 1u ? (h << 1) | l : h);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_INVCOND) {
            uint32_t encoded_condition = (word >> 12) & 15u;
            const char *spelling;

            if (operation->value != 0u || encoded_condition >= 14u) {
                return 0u;
            }
            spelling = condition_names[encoded_condition ^ 1u];
            while (*spelling != '\0') {
                arm_asmgen_putc(&writer, *spelling++);
            }
        } else if (operation->opcode == CDISASM_ARM_ASMGEN_COND
            || operation->opcode == CDISASM_ARM_ASMGEN_COND_SUFFIX) {
            const char *spelling;

            if (!arm_asmgen_eval_expression(operation->value, word, &value)
                || value.value >= 15u) {
                return 0u;
            }
            if (operation->opcode == CDISASM_ARM_ASMGEN_COND_SUFFIX
                && value.value == CDISASM_ARM_CONDITION_AL) {
                continue;
            }
            spelling = condition_names[value.value];
            while (*spelling != '\0') {
                arm_asmgen_putc(&writer, *spelling++);
            }
        } else if (operation->opcode == CDISASM_ARM_ASMGEN_REG31) {
            const cdisasm_arm_asmgen_special_register *selection;

            if (operation->value
                    >= sizeof(cdisasm_arm_asmgen_special_registers)
                        / sizeof(cdisasm_arm_asmgen_special_registers[0])) {
                return 0u;
            }
            selection = &cdisasm_arm_asmgen_special_registers[
                operation->value];
            if (!arm_asmgen_eval_expression(
                    selection->program_id, word, &value)) {
                return 0u;
            }
            if (value.value == 31u) {
                if (!arm_asmgen_put_text(
                        &writer, selection->special_text_id, 0)) {
                    return 0u;
                }
            } else {
                if (!arm_asmgen_put_text(
                        &writer, selection->prefix_text_id, 0)) {
                    return 0u;
                }
                arm_asmgen_put_unsigned(&writer, value.value);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_OPTIONAL_REG31) {
            uint32_t selection_index = operation->value >> 16;
            uint32_t separator_text_id =
                operation->value & UINT32_C(0xffff);
            const cdisasm_arm_asmgen_special_register *selection;

            if (selection_index
                    >= sizeof(cdisasm_arm_asmgen_special_registers)
                        / sizeof(cdisasm_arm_asmgen_special_registers[0])) {
                return 0u;
            }
            selection = &cdisasm_arm_asmgen_special_registers[
                selection_index];
            if (!arm_asmgen_eval_expression(
                    selection->program_id, word, &value)) {
                return 0u;
            }
            if (value.value != 31u) {
                if (!arm_asmgen_put_text(
                        &writer, separator_text_id, 0)
                    || !arm_asmgen_put_text(
                        &writer, selection->prefix_text_id, 0)) {
                    return 0u;
                }
                arm_asmgen_put_unsigned(&writer, value.value);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_OPTIONAL_GPR_PAIR31) {
            if (!arm_asmgen_eval_expression(
                    operation->value, word, &value)
                || value.value > 31u
                || (value.value != 31u && (value.value & 1u) != 0u)) {
                return 0u;
            }
            if (value.value != 31u) {
                arm_asmgen_putc(&writer, ',');
                arm_asmgen_putc(&writer, ' ');
                arm_asmgen_putc(&writer, 'x');
                arm_asmgen_put_unsigned(&writer, value.value);
                arm_asmgen_putc(&writer, ',');
                arm_asmgen_putc(&writer, ' ');
                arm_asmgen_putc(&writer, 'x');
                arm_asmgen_put_unsigned(&writer, value.value + 1u);
            }
        } else if (operation->opcode == CDISASM_ARM_ASMGEN_SELECT) {
            const cdisasm_arm_asmgen_selection *selection;
            const cdisasm_arm_asmgen_selection_case *selected_case = NULL;
            uint32_t case_index;
            uint32_t text_index;

            if (operation->value
                    >= sizeof(cdisasm_arm_asmgen_selections)
                        / sizeof(cdisasm_arm_asmgen_selections[0])) {
                return 0u;
            }
            selection = &cdisasm_arm_asmgen_selections[operation->value];
            if (!arm_asmgen_eval_expression(
                    selection->program_id, word, &value)
                || (uint64_t)selection->first_case + selection->case_count
                    > sizeof(cdisasm_arm_asmgen_selection_cases)
                        / sizeof(cdisasm_arm_asmgen_selection_cases[0])) {
                return 0u;
            }
            for (case_index = 0u;
                 case_index < selection->case_count;
                 ++case_index) {
                const cdisasm_arm_asmgen_selection_case *candidate =
                    &cdisasm_arm_asmgen_selection_cases[
                        selection->first_case + case_index];

                if (candidate->selector == value.value) {
                    selected_case = candidate;
                    break;
                }
            }
            if (selected_case == NULL) {
                return 0u;
            }
            if ((uint64_t)selected_case->first + selected_case->count
                > sizeof(cdisasm_arm_asmgen_selection_text_ids)
                    / sizeof(cdisasm_arm_asmgen_selection_text_ids[0])) {
                return 0u;
            }
            for (text_index = 0u;
                 text_index < selected_case->count;
                 ++text_index) {
                if (!arm_asmgen_put_text(
                        &writer,
                        cdisasm_arm_asmgen_selection_text_ids[
                            selected_case->first + text_index],
                        0)) {
                    return 0u;
                }
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_MINUS_IF_ZERO) {
            if (!arm_asmgen_eval_expression(operation->value, word, &value)) {
                return 0u;
            }
            if (value.value == 0u) {
                arm_asmgen_putc(&writer, '-');
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_BRANCH_TARGET) {
            arm_asmgen_put_hex(&writer, branch_target);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_PC_LABEL) {
            uint64_t target;
            int64_t displacement;

            if (operation->value <= 1u) {
                uint64_t encoded =
                    ((uint64_t)((word >> 5) & UINT32_C(0x7ffff)) << 2)
                    | (uint64_t)((word >> 29) & 3u);

                displacement = arm_asmgen_sign_extend(encoded, 21u);
                if (operation->value == 1u) {
                    displacement *= INT64_C(4096);
                    target = instruction_address & ~UINT64_C(0xfff);
                } else {
                    target = instruction_address;
                }
            } else if (operation->value == 2u) {
                displacement = arm_asmgen_sign_extend(
                    (word >> 5) & UINT32_C(0x7ffff), 19u) * INT64_C(4);
                target = instruction_address;
            } else {
                return 0u;
            }
            arm_asmgen_put_hex(&writer, target + (uint64_t)displacement);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_PAUTH_LR_PC_LABEL) {
            uint64_t offset = (uint64_t)((word >> 5) & UINT32_C(0xffff))
                << 2;

            if (operation->value != 0u) {
                return 0u;
            }
            arm_asmgen_put_hex(&writer, instruction_address - offset);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_RT2_PLUS1) {
            uint32_t first_register = (word >> 12) & 15u;

            if (operation->value != 0u || first_register >= 14u) {
                return 0u;
            }
            arm_asmgen_put_unsigned(&writer, first_register + 1u);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_T32_PC_LABEL) {
            uint32_t mode = operation->value;
            uint32_t base;
            uint32_t offset;
            int64_t displacement;

            if (mode > 11u) {
                return 0u;
            }
            base = (uint32_t)instruction_address
                + (mode <= 3u || mode >= 10u ? 8u : 4u);
            if (mode >= 4u && mode <= 9u) {
                base &= ~UINT32_C(3); /* Thumb literal PC is word-aligned. */
            }
            if (mode == 0u) {
                offset = ((word >> 8) & 15u) << 4 | (word & 15u);
            } else if (mode == 1u || mode == 7u) {
                offset = word & UINT32_C(0xfff);
            } else if (mode == 2u || mode == 5u) {
                offset = (word & 255u) << 1;
            } else if (mode == 3u || mode == 4u || mode == 6u) {
                offset = (word & 255u) << 2;
            } else if (mode == 8u || mode == 9u) {
                offset = ((word >> 26) & 1u) << 11
                    | ((word >> 12) & 7u) << 8
                    | (word & 255u);
            } else {
                uint32_t encoded = word & UINT32_C(0xfff);
                uint32_t rotation = ((encoded >> 8) & 15u) << 1;

                offset = encoded & 255u;
                if (rotation != 0u) {
                    offset = (offset >> rotation)
                        | (offset << (32u - rotation));
                }
            }
            displacement = (int64_t)offset;
            if ((mode <= 3u || mode == 5u || mode == 6u || mode == 7u)
                    && ((word >> 23) & 1u) == 0u) {
                displacement = -displacement;
            } else if (mode == 9u || mode == 11u) {
                displacement = -displacement;
            }
            arm_asmgen_put_hex(
                &writer, (uint32_t)((int64_t)base + displacement));
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE_PATTERN) {
            static const char *const named_patterns[14] = {
                "pow2", "vl1", "vl2", "vl3", "vl4", "vl5", "vl6",
                "vl7", "vl8", "vl16", "vl32", "vl64", "vl128", "vl256"
            };
            uint32_t pattern = (word >> 5) & 31u;
            uint32_t multiplier = ((word >> 16) & 15u) + 1u;
            const char *spelling = NULL;

            if (operation->value != 0u) {
                return 0u;
            }
            if (pattern == 31u && multiplier == 1u) {
                continue;
            }
            arm_asmgen_putc(&writer, ',');
            arm_asmgen_putc(&writer, ' ');
            if (pattern < 14u) {
                spelling = named_patterns[pattern];
            } else if (pattern == 29u) {
                spelling = "mul4";
            } else if (pattern == 30u) {
                spelling = "mul3";
            } else if (pattern == 31u) {
                spelling = "all";
            }
            if (spelling != NULL) {
                while (*spelling != '\0') {
                    arm_asmgen_putc(&writer, *spelling++);
                }
            } else {
                arm_asmgen_putc(&writer, '#');
                arm_asmgen_put_unsigned(&writer, pattern);
            }
            if (multiplier != 1u) {
                arm_asmgen_putc(&writer, ',');
                arm_asmgen_putc(&writer, ' ');
                arm_asmgen_putc(&writer, 'm');
                arm_asmgen_putc(&writer, 'u');
                arm_asmgen_putc(&writer, 'l');
                arm_asmgen_putc(&writer, ' ');
                arm_asmgen_putc(&writer, '#');
                arm_asmgen_put_unsigned(&writer, multiplier);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SME_LUTI_SIZE) {
            uint32_t size = (word >> 12) & 3u;

            if (operation->value != 0u || size > 2u) {
                return 0u;
            }
            arm_asmgen_putc(&writer,
                size == 0u ? 'b' : size == 1u ? 'h' : 's');
        } else if (operation->opcode
                == CDISASM_ARM_ASMGEN_A64_SME_LUTI_STRIDE8_FIRST
            || operation->opcode
                == CDISASM_ARM_ASMGEN_A64_SME_LUTI_STRIDE8_SECOND) {
            uint32_t base = (((word >> 4) & 1u) << 4) | (word & 7u);
            uint32_t register_number = base +
                (operation->opcode
                    == CDISASM_ARM_ASMGEN_A64_SME_LUTI_STRIDE8_SECOND
                    ? 8u : 0u);

            if (operation->value != 0u || register_number > 31u) {
                return 0u;
            }
            arm_asmgen_putc(&writer, 'z');
            arm_asmgen_put_unsigned(&writer, register_number);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SME_LUTI_GROUP_REG) {
            uint32_t register_number;

            if (operation->value > 3u) {
                return 0u;
            }
            if (operation->value <= 1u) {
                register_number = (((word >> 1) & 15u) << 1)
                    + operation->value;
            } else {
                register_number = (((word >> 2) & 7u) << 2)
                    + (operation->value == 2u ? 0u : 3u);
            }
            if (register_number > 31u) {
                return 0u;
            }
            arm_asmgen_putc(&writer, 'z');
            arm_asmgen_put_unsigned(&writer, register_number);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SME_QRSHR_GROUP_REG) {
            uint32_t base = ((word >> 7) & 7u) << 2;

            if (operation->value > 1u || base > 28u) {
                return 0u;
            }
            arm_asmgen_putc(&writer, 'z');
            arm_asmgen_put_unsigned(&writer,
                base + (operation->value == 0u ? 0u : 3u));
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE2P3_QSHRN_PAIR_REG) {
            uint32_t pair = ((word >> 6) & 15u) << 1;

            if (operation->value > 1u) {
                return 0u;
            }
            arm_asmgen_putc(&writer, 'z');
            arm_asmgen_put_unsigned(&writer, pair + operation->value);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE2P3_QSHRN_TYPE_IMM) {
            uint32_t tsize = (word >> 19) & 3u;
            uint32_t imm3 = (word >> 16) & 7u;
            uint32_t source_width = tsize == 1u ? 16u : 32u;
            uint32_t shift = source_width - ((tsize << 3) | imm3);

            if (operation->value > 2u || tsize == 0u
                || shift == 0u || shift > source_width / 2u) {
                return 0u;
            }
            if (operation->value == 0u) {
                arm_asmgen_putc(&writer, tsize == 1u ? 'b' : 'h');
            } else if (operation->value == 1u) {
                arm_asmgen_putc(&writer, tsize == 1u ? 'h' : 's');
            } else {
                arm_asmgen_put_unsigned(&writer, shift);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SME_QRSHR_SIZE_IMM) {
            uint32_t tsize = (word >> 22) & 3u;
            uint32_t imm5 = (word >> 16) & 31u;
            uint32_t esize = tsize == 1u ? 8u : 16u;
            uint32_t shift = 8u * esize - ((tsize << 5) | imm5);

            if (operation->value > 2u || tsize == 0u
                || shift == 0u || shift > 4u * esize) {
                return 0u;
            }
            if (operation->value == 0u) {
                arm_asmgen_putc(&writer, tsize == 1u ? 'b' : 'h');
            } else if (operation->value == 1u) {
                arm_asmgen_putc(&writer, tsize == 1u ? 's' : 'd');
            } else {
                arm_asmgen_put_unsigned(&writer, shift);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE_LOGICAL_IMM) {
            uint32_t raw_imm = (word >> 5) & UINT32_C(0x1fff);
            uint32_t n = raw_imm >> 12;
            uint32_t immr = (raw_imm >> 6) & 63u;
            uint32_t imms = raw_imm & 63u;
            uint32_t length_source = (n << 6) | ((~imms) & 63u);
            uint32_t length = 0u;
            uint32_t element_width;
            uint64_t logical_value;
            uint64_t decoded;

            if (operation->value > 2u || length_source == 0u) {
                return 0u;
            }
            while ((length_source >> (length + 1u)) != 0u) {
                ++length;
            }
            if (length < 1u || length > 6u) {
                return 0u;
            }
            /* A 2/4-bit replicated mask still prints in a .b element. */
            element_width = UINT32_C(1) << (length < 3u ? 3u : length);
            if (!arm_asmgen_decode_logical_immediate(
                    ((uint64_t)n << 12)
                        | ((uint64_t)imms << 6) | immr,
                    64u, &decoded)) {
                return 0u;
            }
            logical_value = decoded
                & arm_asmgen_width_mask((uint8_t)element_width);
            if (operation->value == 0u) {
                arm_asmgen_putc(&writer,
                    element_width == 8u ? 'b'
                    : element_width == 16u ? 'h'
                    : element_width == 32u ? 's' : 'd');
            } else {
                if (operation->value == 2u) {
                    logical_value = (~logical_value)
                        & arm_asmgen_width_mask((uint8_t)element_width);
                }
                arm_asmgen_put_hex(&writer, logical_value);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE_FAST_REDUCE_SIZE) {
            uint32_t size = (word >> 22) & 3u;
            const char *spelling;

            if (operation->value > 1u || size == 0u) {
                return 0u;
            }
            spelling = operation->value == 0u
                ? (size == 1u ? "8h" : size == 2u ? "4s" : "2d")
                : (size == 1u ? "h" : size == 2u ? "s" : "d");
            while (*spelling != '\0') {
                arm_asmgen_putc(&writer, *spelling++);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE_NARROW_SHIFT_TSZ) {
            uint32_t tsz = (((word >> 22) & 1u) << 2)
                | ((word >> 19) & 3u);
            uint32_t encoded = (tsz << 3) | ((word >> 16) & 7u);
            uint32_t source_size;
            uint32_t shift;

            if (operation->value > 2u || tsz == 0u) {
                return 0u;
            }
            source_size = tsz >= 4u ? 64u : tsz >= 2u ? 32u : 16u;
            if (operation->value == 0u) {
                arm_asmgen_putc(&writer,
                    source_size == 16u ? 'b'
                    : source_size == 32u ? 'h' : 's');
            } else if (operation->value == 1u) {
                arm_asmgen_putc(&writer,
                    source_size == 16u ? 'h'
                    : source_size == 32u ? 's' : 'd');
            } else {
                shift = source_size - encoded;
                if (shift == 0u || shift > source_size / 2u) {
                    return 0u;
                }
                arm_asmgen_put_unsigned(&writer, shift);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_VMOV_ELEMENT_SUFFIX) {
            uint32_t opc1 = (word >> 21) & 3u;
            uint32_t opc2 = (word >> 5) & 3u;
            uint32_t u = (word >> 23) & 1u;
            uint32_t size;

            if (operation->value > 1u
                || (opc1 < 2u && opc2 == 2u)) {
                return 0u;
            }
            size = opc1 >= 2u ? 8u
                : (opc2 & 1u) != 0u ? 16u : 32u;
            arm_asmgen_putc(&writer, '.');
            if (operation->value == 1u && size != 32u) {
                arm_asmgen_putc(&writer, u != 0u ? 'u' : 's');
            }
            if (size == 8u) {
                arm_asmgen_putc(&writer, '8');
            } else {
                arm_asmgen_putc(&writer, size == 16u ? '1' : '3');
                arm_asmgen_putc(&writer, size == 16u ? '6' : '2');
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_VMOV_ELEMENT_REG) {
            uint32_t opc1 = (word >> 21) & 3u;
            uint32_t opc2 = (word >> 5) & 3u;
            uint32_t reg = (((word >> 7) & 1u) << 4)
                | ((word >> 16) & 15u);
            uint32_t lane;

            if (operation->value != 0u
                || (opc1 < 2u && opc2 == 2u)) {
                return 0u;
            }
            lane = opc1 >= 2u
                ? ((opc1 & 1u) << 2) | opc2
                : (opc2 & 1u) != 0u
                    ? ((opc1 & 1u) << 1) | (opc2 >> 1)
                    : opc1 & 1u;
            arm_asmgen_putc(&writer, 'd');
            arm_asmgen_put_unsigned(&writer, reg);
            arm_asmgen_putc(&writer, '[');
            arm_asmgen_put_unsigned(&writer, lane);
            arm_asmgen_putc(&writer, ']');
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_LDM_USER_REG_LIST) {
            uint32_t mask = word & UINT32_C(0xffff);
            uint32_t reg;
            int emitted = 0;

            if (operation->value > 1u || mask == 0u
                || (((mask >> 15) & 1u) != operation->value)) {
                return 0u;
            }
            arm_asmgen_putc(&writer, '{');
            for (reg = 0u; reg < 16u; ++reg) {
                if ((mask & (1u << reg)) == 0u) {
                    continue;
                }
                if (emitted) {
                    arm_asmgen_putc(&writer, ',');
                    arm_asmgen_putc(&writer, ' ');
                }
                arm_asmgen_put_a32_gpr(&writer, reg);
                emitted = 1;
            }
            arm_asmgen_putc(&writer, '}');
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_BLOCK_ADDRESS_MODE) {
            uint32_t p = (word >> 24) & 1u;
            uint32_t u = (word >> 23) & 1u;

            if (operation->value != 0u) {
                return 0u;
            }
            if (p != 0u || u == 0u) {
                arm_asmgen_putc(&writer,
                    p != 0u && u != 0u ? 'i' : 'd');
                arm_asmgen_putc(&writer, p != 0u ? 'b' : 'a');
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_T32_LDM_WRITEBACK) {
            uint32_t rn = (word >> 8) & 7u;
            uint32_t register_list = word & 255u;

            if (operation->value != 0u || register_list == 0u) {
                return 0u;
            }
            if ((register_list & (1u << rn)) == 0u) {
                arm_asmgen_putc(&writer, '!');
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_T32_IT_CONDITION) {
            uint32_t firstcond = (word >> 4) & 15u;
            const char *name;

            if (operation->value != 0u || firstcond >= 14u) {
                return 0u;
            }
            name = condition_names[firstcond];
            while (*name != '\0') {
                arm_asmgen_putc(&writer, *name++);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_T32_IT_CONDITION_SUFFIX) {
            uint32_t mask = word & 15u;
            uint32_t firstcond = (word >> 4) & 15u;
            uint32_t zeros = 0u;
            uint32_t slot;

            if (operation->value != 0u || mask == 0u
                || firstcond >= 14u) {
                return 0u;
            }
            while (((mask >> zeros) & 1u) == 0u) {
                ++zeros;
            }
            for (slot = 2u; slot <= 4u - zeros; ++slot) {
                uint32_t bit = (mask >> (5u - slot)) & 1u;
                arm_asmgen_putc(&writer,
                    bit == (firstcond & 1u) ? 't' : 'e');
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_T32_OPTIONAL_SHIFT_IMM5) {
            uint32_t encoded = (((word >> 12) & 7u) << 2)
                | ((word >> 6) & 3u);
            const char *name;

            if (operation->value > 1u || writer.length == 0u) {
                return 0u;
            }
            /* These four reviewed forms have OPT_SPACE immediately before
             * this optional choice. Remove it for either branch. */
            if (writer.buffer != NULL && writer.length < writer.size
                && writer.buffer[writer.length - 1u] != ' ') {
                return 0u;
            }
            --writer.length;
            if (operation->value == 0u && encoded == 0u) {
                continue;
            }
            name = operation->value == 0u ? "lsl" : "asr";
            arm_asmgen_putc(&writer, ',');
            arm_asmgen_putc(&writer, ' ');
            while (*name != '\0') {
                arm_asmgen_putc(&writer, *name++);
            }
            arm_asmgen_putc(&writer, ' ');
            arm_asmgen_putc(&writer, '#');
            arm_asmgen_put_unsigned(&writer,
                operation->value == 1u && encoded == 0u
                    ? 32u : encoded);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE_UNPRED_SHIFT_TSZ) {
            uint32_t tsz = (((word >> 22) & 3u) << 2)
                | ((word >> 19) & 3u);
            uint32_t encoded = (tsz << 3) | ((word >> 16) & 7u);
            uint32_t size;
            uint32_t shift;

            if (operation->value > 2u || tsz == 0u) {
                return 0u;
            }
            size = tsz >= 8u ? 64u : tsz >= 4u ? 32u
                : tsz >= 2u ? 16u : 8u;
            if (operation->value == 0u) {
                arm_asmgen_putc(&writer,
                    size == 8u ? 'b' : size == 16u ? 'h'
                    : size == 32u ? 's' : 'd');
                continue;
            }
            shift = operation->value == 1u
                ? 2u * size - encoded : encoded - size;
            if ((operation->value == 1u
                    && (shift == 0u || shift > size))
                || (operation->value == 2u && shift >= size)) {
                return 0u;
            }
            arm_asmgen_put_unsigned(&writer, shift);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SIMD_SCALAR_SHIFT_SIZE
            || operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SIMD_SCALAR_SHIFT_IMMEDIATE) {
            uint32_t immh = (word >> 19) & 15u;
            uint32_t immb = (word >> 16) & 7u;
            uint32_t size;

            if (operation->value != 0u || immh == 0u) {
                return 0u;
            }
            size = (immh & 8u) != 0u ? 64u
                : (immh & 4u) != 0u ? 32u
                : (immh & 2u) != 0u ? 16u : 8u;
            if (operation->opcode
                == CDISASM_ARM_ASMGEN_A64_SIMD_SCALAR_SHIFT_SIZE) {
                arm_asmgen_putc(&writer,
                    size == 8u ? 'b' : size == 16u ? 'h'
                    : size == 32u ? 's' : 'd');
            } else {
                uint32_t shift = (immh << 3) | immb;
                if (shift < size || shift >= 2u * size) {
                    return 0u;
                }
                arm_asmgen_put_unsigned(&writer, shift - size);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SIMD_FAMAX_ARRANGEMENT) {
            uint32_t size = (word >> 22) & 3u;
            uint32_t q = (word >> 30) & 1u;

            if (operation->value != 0u || size < 2u
                || (size == 3u && q == 0u)) {
                return 0u;
            }
            arm_asmgen_putc(&writer,
                size == 3u ? '2' : q != 0u ? '4' : '2');
            arm_asmgen_putc(&writer, size == 3u ? 'd' : 's');
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SME_LUTI_STRIDE8_SIZE) {
            uint32_t size = (word >> 12) & 3u;

            if (operation->value != 0u || size > 1u) {
                return 0u;
            }
            arm_asmgen_putc(&writer, size == 0u ? 'b' : 'h');
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_NEON_VMOV_MODIFIED_TYPE) {
            uint32_t cmode = (word >> 8) & 15u;

            if (operation->value != 0u || cmode < 12u) {
                return 0u;
            }
            arm_asmgen_putc(&writer, cmode == 15u ? 'f' : 'i');
            if (cmode == 14u) {
                arm_asmgen_putc(&writer, '8');
            } else {
                arm_asmgen_putc(&writer, '3');
                arm_asmgen_putc(&writer, '2');
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_NEON_SAT_NARROW_TYPE) {
            uint32_t op = (word >> 6) & 3u;
            uint32_t size = (word >> 18) & 3u;

            if (operation->value != 0u || op < 2u || size > 2u) {
                return 0u;
            }
            arm_asmgen_putc(&writer, op == 2u ? 's' : 'u');
            arm_asmgen_putc(&writer,
                size == 0u ? '1' : size == 1u ? '3' : '6');
            arm_asmgen_putc(&writer,
                size == 0u ? '6' : size == 1u ? '2' : '4');
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE_DUP_ELEMENT_TSZ) {
            uint32_t tsz = (word >> 16) & 31u;
            char size;

            if (operation->value > 1u || tsz == 0u) {
                return 0u;
            }
            size = (tsz & 1u) != 0u ? 'b'
                : (tsz & 2u) != 0u ? 'h'
                : (tsz & 4u) != 0u ? 's'
                : (tsz & 8u) != 0u ? 'd' : 'q';
            arm_asmgen_putc(&writer, size);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE_DUP_ELEMENT_LANE) {
            uint32_t tsz = (word >> 16) & 31u;
            uint32_t imm2 = (word >> 22) & 3u;
            uint32_t element_shift = 0u;

            if (operation->value != 0u || tsz == 0u) {
                return 0u;
            }
            while (((tsz >> element_shift) & 1u) == 0u) {
                ++element_shift;
            }
            arm_asmgen_put_unsigned(&writer,
                ((imm2 << 5) | tsz) >> (element_shift + 1u));
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE_SAT_NARROW_TSZ) {
            uint32_t tsz = (((word >> 22) & 1u) << 2)
                | ((word >> 19) & 3u);

            if (operation->value > 1u || tsz == 0u) {
                return 0u;
            }
            arm_asmgen_putc(&writer,
                operation->value == 0u
                    ? (tsz >= 4u ? 's' : tsz >= 2u ? 'h' : 'b')
                    : (tsz >= 4u ? 'd' : tsz >= 2u ? 's' : 'h'));
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE_SRA_TSZ
            || operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE_SHLL_TSZ) {
            uint32_t is_shll = operation->opcode
                == CDISASM_ARM_ASMGEN_A64_SVE_SHLL_TSZ;
            uint32_t tsz = (((word >> 22) & (is_shll ? 1u : 3u)) << 2)
                | ((word >> 19) & 3u);
            uint32_t encoded = (tsz << 3) | ((word >> 16) & 7u);
            uint32_t size;
            uint32_t shift;

            if (tsz == 0u || operation->value > (is_shll ? 2u : 1u)) {
                return 0u;
            }
            size = tsz >= 8u ? 64u : tsz >= 4u ? 32u
                : tsz >= 2u ? 16u : 8u;
            if (is_shll && size == 64u) {
                return 0u;
            }
            if (operation->value == 0u) {
                uint32_t printed_size = is_shll ? size * 2u : size;
                arm_asmgen_putc(&writer,
                    printed_size == 8u ? 'b'
                    : printed_size == 16u ? 'h'
                    : printed_size == 32u ? 's' : 'd');
                continue;
            }
            if (is_shll && operation->value == 1u) {
                arm_asmgen_putc(&writer,
                    size == 8u ? 'b' : size == 16u ? 'h' : 's');
                continue;
            }
            shift = is_shll ? encoded - size : 2u * size - encoded;
            if ((is_shll && shift >= size)
                || (!is_shll && (shift == 0u || shift > size))) {
                return 0u;
            }
            arm_asmgen_put_unsigned(&writer, shift);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE_SHIFT_TSZ) {
            uint32_t tsz = (((word >> 22) & 3u) << 2)
                | ((word >> 8) & 3u);
            uint32_t encoded = (tsz << 3) | ((word >> 5) & 7u);
            uint32_t element_size;
            uint32_t shift;

            if (operation->value > 2u || tsz == 0u) {
                return 0u;
            }
            element_size = tsz >= 8u ? 64u
                : tsz >= 4u ? 32u : tsz >= 2u ? 16u : 8u;
            if (operation->value == 0u) {
                arm_asmgen_putc(&writer,
                    element_size == 8u ? 'b' : element_size == 16u ? 'h'
                    : element_size == 32u ? 's' : 'd');
                continue;
            }
            shift = operation->value == 1u
                ? 2u * element_size - encoded : encoded - element_size;
            if ((operation->value == 1u
                    && (shift == 0u || shift > element_size))
                || (operation->value == 2u && shift >= element_size)) {
                return 0u;
            }
            arm_asmgen_put_unsigned(&writer, shift);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE_NARROW_DEST_TYPE) {
            uint32_t size = (word >> 22) & 3u;

            if (operation->value != 0u || size == 0u) {
                return 0u;
            }
            arm_asmgen_putc(&writer,
                size == 1u ? 'b' : size == 2u ? 'h' : 's');
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE_NARROW_SOURCE_TYPE) {
            uint32_t size = (word >> 22) & 3u;

            if (operation->value != 0u || size == 0u) {
                return 0u;
            }
            arm_asmgen_putc(&writer,
                size == 1u ? 'h' : size == 2u ? 's' : 'd');
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE_GPR_SP_SUFFIX) {
            uint32_t register_number = (word >> 5) & 31u;

            if (operation->value != 0u) {
                return 0u;
            }
            if (register_number == 31u) {
                arm_asmgen_putc(&writer, 's');
                arm_asmgen_putc(&writer, 'p');
            } else {
                arm_asmgen_put_unsigned(&writer, register_number);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE_GPR_SIZE_PREFIX) {
            uint32_t size = (word >> 22) & 3u;

            if (operation->value != 0u) {
                return 0u;
            }
            arm_asmgen_putc(&writer, size == 3u ? 'x' : 'w');
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE_GPR_SUFFIX) {
            uint32_t register_number;

            if (operation->value > 1u) {
                return 0u;
            }
            register_number = operation->value == 0u
                ? (word >> 5) & 31u : (word >> 16) & 31u;
            if (register_number == 31u) {
                arm_asmgen_putc(&writer, 'z');
                arm_asmgen_putc(&writer, 'r');
            } else {
                arm_asmgen_put_unsigned(&writer, register_number);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SME_ZERO_MASK) {
            uint32_t mask = word & 255u;
            uint32_t tile_mask;
            uint32_t tile_count;
            uint32_t tile;
            int first = 1;
            char arrangement;

            if (operation->value != 0u) {
                return 0u;
            }
            if (mask == 0u) {
                continue;
            }
            if (mask == 255u) {
                arm_asmgen_putc(&writer, 'z');
                arm_asmgen_putc(&writer, 'a');
                continue;
            }
            if (mask == 0x55u || mask == 0xaau) {
                arm_asmgen_putc(&writer, 'z');
                arm_asmgen_putc(&writer, 'a');
                arm_asmgen_putc(&writer, mask == 0x55u ? '0' : '1');
                arm_asmgen_putc(&writer, '.');
                arm_asmgen_putc(&writer, 'h');
                continue;
            }
            if ((mask & 15u) == (mask >> 4)) {
                tile_mask = mask & 15u;
                tile_count = 4u;
                arrangement = 's';
            } else {
                tile_mask = mask;
                tile_count = 8u;
                arrangement = 'd';
            }
            for (tile = 0u; tile < tile_count; ++tile) {
                if ((tile_mask & (1u << tile)) == 0u) {
                    continue;
                }
                if (!first) {
                    arm_asmgen_putc(&writer, ',');
                    arm_asmgen_putc(&writer, ' ');
                }
                arm_asmgen_putc(&writer, 'z');
                arm_asmgen_putc(&writer, 'a');
                arm_asmgen_put_unsigned(&writer, tile);
                arm_asmgen_putc(&writer, '.');
                arm_asmgen_putc(&writer, arrangement);
                first = 0;
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE_FADDA_SCALAR_V) {
            uint32_t size = (word >> 22) & 3u;

            if (operation->value != 0u || size == 0u) {
                return 0u;
            }
            arm_asmgen_putc(&writer,
                size == 1u ? 'h' : size == 2u ? 's' : 'd');
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE_ADR_SCALED_SHIFT) {
            uint32_t shift = (word >> 10) & 3u;

            if (operation->value != 0u) {
                return 0u;
            }
            if (shift != 0u) {
                arm_asmgen_putc(&writer, ',');
                arm_asmgen_putc(&writer, ' ');
                arm_asmgen_putc(&writer, 'l');
                arm_asmgen_putc(&writer, 's');
                arm_asmgen_putc(&writer, 'l');
                arm_asmgen_putc(&writer, ' ');
                arm_asmgen_putc(&writer, '#');
                arm_asmgen_put_unsigned(&writer, shift);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_TESTBRANCH_RT) {
            uint32_t register_number = word & 31u;

            if (operation->value != 0u) {
                return 0u;
            }
            if (register_number == 31u) {
                arm_asmgen_putc(&writer, 'z');
                arm_asmgen_putc(&writer, 'r');
            } else {
                arm_asmgen_put_unsigned(&writer, register_number);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SYSTEMREG_PAIR_SECOND) {
            uint32_t first = word & 31u;

            if (operation->value != 0u || first >= 31u
                || (first & 1u) != 0u) {
                return 0u;
            }
            arm_asmgen_putc(&writer, 'x');
            if (first == 30u) {
                arm_asmgen_putc(&writer, 'z');
                arm_asmgen_putc(&writer, 'r');
            } else {
                arm_asmgen_put_unsigned(&writer, first + 1u);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SYSTEMREG_NUMERIC) {
            if (operation->value != 0u) {
                return 0u;
            }
            arm_asmgen_putc(&writer, 's');
            arm_asmgen_put_unsigned(&writer, 2u + ((word >> 19) & 1u));
            arm_asmgen_putc(&writer, '_');
            arm_asmgen_put_unsigned(&writer, (word >> 16) & 7u);
            arm_asmgen_putc(&writer, '_');
            arm_asmgen_putc(&writer, 'c');
            arm_asmgen_put_unsigned(&writer, (word >> 12) & 15u);
            arm_asmgen_putc(&writer, '_');
            arm_asmgen_putc(&writer, 'c');
            arm_asmgen_put_unsigned(&writer, (word >> 8) & 15u);
            arm_asmgen_putc(&writer, '_');
            arm_asmgen_put_unsigned(&writer, (word >> 5) & 7u);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_BTI_TARGETS) {
            uint32_t encoded = (word >> 5) & 7u;

            if (operation->value != 0u || (encoded & 1u) != 0u) {
                return 0u;
            }
            if (encoded != 0u) {
                arm_asmgen_putc(&writer, ' ');
                if (encoded >= 4u) {
                    arm_asmgen_putc(&writer, 'j');
                }
                if (encoded == 2u || encoded == 6u) {
                    arm_asmgen_putc(&writer, 'c');
                }
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_PRFM_PIMM12) {
            if (operation->value != 0u) {
                return 0u;
            }
            arm_asmgen_put_unsigned(&writer,
                ((word >> 10) & UINT32_C(0xfff)) << 3);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_PAUTH_LDST_SIMM) {
            uint32_t encoded = (((word >> 22) & 1u) << 9)
                | ((word >> 12) & 511u);

            if (operation->value != 0u) {
                return 0u;
            }
            if (encoded != 0u) {
                arm_asmgen_putc(&writer, ',');
                arm_asmgen_putc(&writer, ' ');
                arm_asmgen_putc(&writer, '#');
                arm_asmgen_put_signed(&writer,
                    (uint64_t)encoded << 3, 13u);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_ADDSUB_EXT_REG_PREFIX) {
            uint32_t option = (word >> 13) & 7u;

            if (operation->value != 0u) {
                return 0u;
            }
            arm_asmgen_putc(&writer, (option & 3u) == 3u ? 'x' : 'w');
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_ADDSUB_EXT_REG_NUMBER) {
            uint32_t register_number = (word >> 16) & 31u;

            if (operation->value != 0u) {
                return 0u;
            }
            if (register_number == 31u) {
                arm_asmgen_putc(&writer, 'z');
                arm_asmgen_putc(&writer, 'r');
            } else {
                arm_asmgen_put_unsigned(&writer, register_number);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_ADDSUB_EXT_OPTION) {
            static const char *const extend_names[8] = {
                "uxtb", "uxth", "uxtw", "uxtx",
                "sxtb", "sxth", "sxtw", "sxtx",
            };
            uint32_t option = (word >> 13) & 7u;
            uint32_t amount = (word >> 10) & 7u;
            const char *spelling;

            if (operation->value > 1u || amount > 4u
                || (operation->value == 1u && (option & 3u) == 3u)) {
                return 0u;
            }
            arm_asmgen_putc(&writer, ',');
            arm_asmgen_putc(&writer, ' ');
            spelling = extend_names[option];
            while (*spelling != '\0') {
                arm_asmgen_putc(&writer, *spelling++);
            }
            arm_asmgen_putc(&writer, ' ');
            arm_asmgen_putc(&writer, '#');
            arm_asmgen_put_unsigned(&writer, amount);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_REGOFF_WORX) {
            uint32_t option = (word >> 13) & 7u;
            uint32_t register_number = (word >> 16) & 31u;

            if (operation->value != 0u
                || (option != 2u && option != 3u
                    && option != 6u && option != 7u)) {
                return 0u;
            }
            if (register_number == 31u) {
                const char *spelling = (option & 1u) != 0u ? "xzr" : "wzr";
                while (*spelling != '\0') {
                    arm_asmgen_putc(&writer, *spelling++);
                }
            } else {
                arm_asmgen_putc(&writer, (option & 1u) != 0u ? 'x' : 'w');
                arm_asmgen_put_unsigned(&writer, register_number);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_REGOFF_EXTEND_SHIFT) {
            static const char *const extend_names[4] = {
                "uxtw", "lsl", "sxtw", "sxtx"
            };
            uint32_t option = (word >> 13) & 7u;
            uint32_t scaled = (word >> 12) & 1u;
            uint32_t amount = (word >> 30) & 3u;
            const char *spelling;

            if (operation->value != 0u
                || (option != 2u && option != 3u
                    && option != 6u && option != 7u)) {
                return 0u;
            }
            if (option == 3u && scaled == 0u) {
                continue;
            }
            if (((word >> 26) & 1u) != 0u
                && ((word >> 22) & 3u) == 3u) {
                amount = 4u; /* Q-register memory transfer. */
            }
            arm_asmgen_putc(&writer, ',');
            arm_asmgen_putc(&writer, ' ');
            spelling = extend_names[((option >> 2) << 1) | (option & 1u)];
            while (*spelling != '\0') {
                arm_asmgen_putc(&writer, *spelling++);
            }
            if (scaled != 0u) {
                arm_asmgen_putc(&writer, ' ');
                arm_asmgen_putc(&writer, '#');
                arm_asmgen_put_unsigned(&writer, amount);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_T32_MODIFIED_REG_SHIFT) {
            static const char *const shift_names[4] = {
                "lsl", "lsr", "asr", "ror"
            };
            uint32_t stype = (word >> 4) & 3u;
            uint32_t amount = (((word >> 12) & 7u) << 2)
                | ((word >> 6) & 3u);
            const char *spelling;

            if (operation->value != 0u) {
                return 0u;
            }
            if (stype == 0u && amount == 0u) {
                continue;
            }
            arm_asmgen_putc(&writer, ',');
            arm_asmgen_putc(&writer, ' ');
            if (stype == 3u && amount == 0u) {
                spelling = "rrx";
            } else {
                spelling = shift_names[stype];
            }
            while (*spelling != '\0') {
                arm_asmgen_putc(&writer, *spelling++);
            }
            if (stype != 3u || amount != 0u) {
                if (amount == 0u) {
                    amount = 32u;
                }
                arm_asmgen_putc(&writer, ' ');
                arm_asmgen_putc(&writer, '#');
                arm_asmgen_put_unsigned(&writer, amount);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_LDST_REG_SHIFT) {
            static const char *const shift_names[4] = {
                "lsl", "lsr", "asr", "ror"
            };
            uint32_t stype = (word >> 5) & 3u;
            uint32_t amount = (word >> 7) & 31u;
            const char *spelling;

            if (operation->value != 0u) {
                return 0u;
            }
            if (stype == 0u && amount == 0u) {
                continue;
            }
            arm_asmgen_putc(&writer, ',');
            arm_asmgen_putc(&writer, ' ');
            spelling = (stype == 3u && amount == 0u)
                ? "rrx" : shift_names[stype];
            while (*spelling != '\0') {
                arm_asmgen_putc(&writer, *spelling++);
            }
            if (stype != 3u || amount != 0u) {
                if (amount == 0u) {
                    amount = 32u;
                }
                arm_asmgen_putc(&writer, ' ');
                arm_asmgen_putc(&writer, '#');
                arm_asmgen_put_unsigned(&writer, amount);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A64_SVE_PRFOP) {
            static const char *const named_ops[6] = {
                "pldl1keep", "pldl1strm", "pldl2keep",
                "pldl2strm", "pldl3keep", "pldl3strm"
            };
            static const char *const store_ops[6] = {
                "pstl1keep", "pstl1strm", "pstl2keep",
                "pstl2strm", "pstl3keep", "pstl3strm"
            };
            uint32_t encoded_op = word & 15u;
            const char *spelling = NULL;

            if (operation->value != 0u) {
                return 0u;
            }
            if (encoded_op < 6u) {
                spelling = named_ops[encoded_op];
            } else if (encoded_op >= 8u && encoded_op < 14u) {
                spelling = store_ops[encoded_op - 8u];
            }
            if (spelling != NULL) {
                while (*spelling != '\0') {
                    arm_asmgen_putc(&writer, *spelling++);
                }
            } else {
                arm_asmgen_putc(&writer, '#');
                arm_asmgen_put_unsigned(&writer, encoded_op);
            }
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_NEON_NARROW_SHIFT) {
            uint32_t encoded_shift = (word >> 16) & 63u;
            uint32_t element_size;

            if (operation->value > 1u || encoded_shift < 8u) {
                return 0u;
            }
            element_size = encoded_shift >= 32u ? 64u
                : encoded_shift >= 16u ? 32u : 16u;
            arm_asmgen_put_unsigned(&writer,
                operation->value == 0u ? element_size
                    : element_size - encoded_shift);
        } else if (operation->opcode
            == CDISASM_ARM_ASMGEN_A32_NEON_SHIFT_ELEMENT_SIZE) {
            uint32_t encoded_size = (((word >> 7) & 1u) << 6)
                | ((word >> 16) & 63u);
            uint32_t element_size;

            if (operation->value > 2u || encoded_size < 8u) {
                return 0u;
            }
            element_size = encoded_size >= 64u ? 64u
                : encoded_size >= 32u ? 32u
                : encoded_size >= 16u ? 16u : 8u;
            if (operation->value == 0u) {
                arm_asmgen_put_unsigned(&writer, element_size);
            } else if (operation->value == 1u) {
                uint32_t right_shift = 2u * element_size - encoded_size;

                if (right_shift == 0u || right_shift > element_size) {
                    return 0u;
                }
                arm_asmgen_put_unsigned(&writer, right_shift);
            } else {
                uint32_t left_shift = encoded_size - element_size;

                if (left_shift >= element_size) {
                    return 0u;
                }
                arm_asmgen_put_unsigned(&writer, left_shift);
            }
        } else {
            return 0u;
        }
    }
    if (buffer != NULL && buffer_size != 0u) {
        size_t terminator = writer.length < buffer_size
            ? writer.length : buffer_size - 1u;

        buffer[terminator] = '\0';
    }
    return writer.length;
}

size_t cdisasm_arm_format_generated(
    const cdisasm_arm_instruction *instruction,
    uint32_t flags,
    char *buffer,
    size_t buffer_size)
{
    const cdisasm_arm_asmgen_form *form;
    const cdisasm_arm_asmgen_alias *alias;
    uint32_t word;

    if (instruction == NULL
        || (instruction->instruction_flags
            & (CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
                | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE))
            != (CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
                | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE)
        || instruction->form_id == CDISASM_ARM_FORM_NONE
        || instruction->form_id > CDISASM_ARM_FORM_AARCHMRS_2026_03_LAST
        || !cdisasm_arm_generated_form_matches(instruction)) {
        return 0u;
    }
    form = &cdisasm_arm_asmgen_forms[instruction->form_id - 1u];
    word = instruction->raw_instruction;
    if (instruction->isa_id == CDISASM_ARM_ISA_T32
        && instruction->opcode_size == 4u) {
        word = (word << 16) | (word >> 16);
    }
    alias = arm_asmgen_find_alias(instruction);
    if (alias != NULL) {
        return arm_asmgen_render_recipe(
            alias->recipe_first, alias->recipe_count,
            word, instruction->isa_id, instruction->address, instruction->branch_target,
            flags, buffer, buffer_size);
    }
    if (form->public_name_id != instruction->name_id
        || form->render_status == 0u || form->recipe_count == 0u) {
        return 0u;
    }
    return arm_asmgen_render_recipe(
        form->recipe_first, form->recipe_count,
        word, instruction->isa_id, instruction->address, instruction->branch_target,
        flags, buffer, buffer_size);
}

#else

size_t cdisasm_arm_format_generated(
    const cdisasm_arm_instruction *instruction,
    uint32_t flags,
    char *buffer,
    size_t buffer_size)
{
    (void)instruction;
    (void)flags;
    (void)buffer;
    (void)buffer_size;
    return 0u;
}

#endif
