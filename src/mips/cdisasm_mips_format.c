#include "cdisasm/cdisasm_mips.h"
#include "cdisasm/cdisasm_format.h"
#include "mips_decoder.h"
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "generated/cdisasm_mips_mnemonics.inc"

typedef struct mips_text_writer {
    char *buffer;
    size_t capacity;
    size_t length;
    int failed;
} mips_text_writer;

static void append_text(mips_text_writer *writer, const char *text, size_t length)
{
    size_t copy;
    if (writer->failed) return;
    if (length > SIZE_MAX - writer->length) {
        writer->failed = 1;
        return;
    }
    if (writer->capacity != 0 && writer->length < writer->capacity - 1u) {
        copy = writer->capacity - 1u - writer->length;
        if (copy > length) copy = length;
        memcpy(writer->buffer + writer->length, text, copy);
    }
    writer->length += length;
}

static void append_number(mips_text_writer *writer, const char *format, ...)
{
    char temporary[96];
    int length;
    va_list args;
    va_start(args, format);
    length = vsnprintf(temporary, sizeof(temporary), format, args);
    va_end(args);
    if (length < 0 || (size_t)length >= sizeof(temporary)) {
        writer->failed = 1;
        return;
    }
    append_text(writer, temporary, (size_t)length);
}

static void finish_text(mips_text_writer *writer)
{
    if (writer->capacity != 0) {
        const size_t end = writer->length < writer->capacity ? writer->length : writer->capacity - 1u;
        writer->buffer[writer->failed ? 0u : end] = '\0';
    }
}

static void append_signed(mips_text_writer *writer, uint64_t value)
{
    if ((value & (UINT64_C(1) << 63)) != 0) append_number(writer, "-%" PRIu64, UINT64_C(0) - value);
    else append_number(writer, "%" PRIu64, value);
}

static void append_register(mips_text_writer *writer, cdisasm_mips_reg_id reg)
{
    if (reg >= CDISASM_MIPS_REG_GPR0 && reg <= CDISASM_MIPS_REG_GPR31) append_number(writer, "$%u", (unsigned)(reg - CDISASM_MIPS_REG_GPR0));
    else if (reg >= CDISASM_MIPS_REG_FPR0 && reg <= CDISASM_MIPS_REG_FPR31) append_number(writer, "$f%u", (unsigned)(reg - CDISASM_MIPS_REG_FPR0));
    else if (reg == CDISASM_MIPS_REG_HI) append_text(writer, "$hi", 3u);
    else if (reg == CDISASM_MIPS_REG_LO) append_text(writer, "$lo", 3u);
    else if (reg >= CDISASM_MIPS_REG_FCC0 && reg <= CDISASM_MIPS_REG_FCC7) append_number(writer, "$fcc%u", (unsigned)(reg - CDISASM_MIPS_REG_FCC0));
    else if (reg >= CDISASM_MIPS_REG_ACC0 && reg <= CDISASM_MIPS_REG_ACC3) append_number(writer, "$ac%u", (unsigned)(reg - CDISASM_MIPS_REG_ACC0));
    else if (reg >= CDISASM_MIPS_REG_MSA0 && reg <= CDISASM_MIPS_REG_MSA31) append_number(writer, "$w%u", (unsigned)(reg - CDISASM_MIPS_REG_MSA0));
    else if (reg >= CDISASM_MIPS_REG_FCR0 && reg <= CDISASM_MIPS_REG_FCR31) append_number(writer, "$fcr%u", (unsigned)(reg - CDISASM_MIPS_REG_FCR0));
    else if (reg >= CDISASM_MIPS_REG_MSACTRL_FIRST && reg <= CDISASM_MIPS_REG_MSACTRL_LAST) append_number(writer, "$%u", (unsigned)(reg - CDISASM_MIPS_REG_MSACTRL_FIRST));
    else if (reg >= CDISASM_MIPS_REG_MXU_FIRST && reg <= CDISASM_MIPS_REG_MXU_LAST) append_number(writer, "XR%u", (unsigned)(reg - CDISASM_MIPS_REG_MXU_FIRST));
    else if (reg == CDISASM_MIPS_REG_PC) append_text(writer, "$pc", 3u);
    else if (reg == CDISASM_MIPS_REG_LLBIT) append_text(writer, "$llbit", 6u);
    else if (reg >= CDISASM_MIPS_REG_CP0_FIRST && reg <= CDISASM_MIPS_REG_CP0_LAST) {
        const unsigned encoded = (unsigned)(reg - CDISASM_MIPS_REG_CP0_FIRST);
        append_number(writer, "$%u, %u", encoded / 8u, encoded % 8u);
    } else if (reg >= CDISASM_MIPS_REG_GUEST_CP0_FIRST && reg <= CDISASM_MIPS_REG_GUEST_CP0_LAST) {
        const unsigned encoded = (unsigned)(reg - CDISASM_MIPS_REG_GUEST_CP0_FIRST);
        append_number(writer, "$%u, %u", encoded / 8u, encoded % 8u);
    } else if (reg >= CDISASM_MIPS_REG_COP2_FIRST && reg <= CDISASM_MIPS_REG_COP2_LAST) append_number(writer, "$%u", (unsigned)(reg - CDISASM_MIPS_REG_COP2_FIRST) / 8u);
    else if (reg >= CDISASM_MIPS_REG_COP3_FIRST && reg <= CDISASM_MIPS_REG_COP3_LAST) append_number(writer, "$%u", (unsigned)(reg - CDISASM_MIPS_REG_COP3_FIRST));
    else if (reg >= CDISASM_MIPS_REG_FCR2_FIRST && reg <= CDISASM_MIPS_REG_FCR2_LAST) append_number(writer, "$%u", (unsigned)(reg - CDISASM_MIPS_REG_FCR2_FIRST));
    else if (reg >= CDISASM_MIPS_REG_FCR3_FIRST && reg <= CDISASM_MIPS_REG_FCR3_LAST) append_number(writer, "$%u", (unsigned)(reg - CDISASM_MIPS_REG_FCR3_FIRST));
    else if (reg >= CDISASM_MIPS_REG_COP2CC_FIRST && reg <= CDISASM_MIPS_REG_COP2CC_LAST) append_number(writer, "$cc%u", (unsigned)(reg - CDISASM_MIPS_REG_COP2CC_FIRST));
    else if (reg == CDISASM_MIPS_REG_COP0CC0 || reg == CDISASM_MIPS_REG_COP3CC0) append_text(writer, "$cc0", 4u);
    else if (reg == CDISASM_MIPS_REG_DSPCONTROL) append_text(writer, "$dspcontrol", 11u);
    else if (reg >= CDISASM_MIPS_REG_PREVIOUS_GPR_FIRST && reg <= CDISASM_MIPS_REG_PREVIOUS_GPR_LAST) append_number(writer, "$%u", (unsigned)(reg - CDISASM_MIPS_REG_PREVIOUS_GPR_FIRST));
    else if (reg >= CDISASM_MIPS_REG_CP0_CONTROL_FIRST && reg <= CDISASM_MIPS_REG_CP0_CONTROL_LAST) append_number(writer, "$%u", (unsigned)(reg - CDISASM_MIPS_REG_CP0_CONTROL_FIRST));
    else if (reg >= CDISASM_MIPS_REG_NANO_CP0_FIRST && reg <= CDISASM_MIPS_REG_NANO_CP0_LAST) {
        const unsigned encoded = (unsigned)(reg - CDISASM_MIPS_REG_NANO_CP0_FIRST);
        append_number(writer, "$%u, %u", encoded / 32u, encoded % 32u);
    }
    else if (reg >= CDISASM_MIPS_REG_MXU2_VR_FIRST && reg <= CDISASM_MIPS_REG_MXU2_VR_LAST)
        append_number(writer, "$vr%u", (unsigned)(reg - CDISASM_MIPS_REG_MXU2_VR_FIRST));
    else if (reg >= CDISASM_MIPS_REG_MXU3_VR_FIRST && reg <= CDISASM_MIPS_REG_MXU3_VR_LAST)
        append_number(writer, "$vr%u", (unsigned)(reg - CDISASM_MIPS_REG_MXU3_VR_FIRST));
    else if (reg >= CDISASM_MIPS_REG_MXU2_CTRL_FIRST && reg <= CDISASM_MIPS_REG_MXU2_CTRL_LAST)
        append_number(writer, "$%u", (unsigned)(reg - CDISASM_MIPS_REG_MXU2_CTRL_FIRST));
    else if (reg >= CDISASM_MIPS_REG_MXU3_CTRL_FIRST && reg <= CDISASM_MIPS_REG_MXU3_CTRL_LAST)
        append_number(writer, "$%u", (unsigned)(reg - CDISASM_MIPS_REG_MXU3_CTRL_FIRST));
    else if (reg >= CDISASM_MIPS_REG_MXU3_VSR_FIRST && reg <= CDISASM_MIPS_REG_MXU3_VSR_LAST)
        append_number(writer, "$vs%u", (unsigned)(reg - CDISASM_MIPS_REG_MXU3_VSR_FIRST));
    else if (reg >= CDISASM_MIPS_REG_MXU3_VWR_FIRST && reg <= CDISASM_MIPS_REG_MXU3_VWR_LAST)
        append_number(writer, "$vw%u", (unsigned)(reg - CDISASM_MIPS_REG_MXU3_VWR_FIRST));
    else if (reg >= CDISASM_MIPS_REG_MXU3_MCS_FIRST && reg <= CDISASM_MIPS_REG_MXU3_MCS_LAST)
        append_number(writer, "$mcs%u", (unsigned)(reg - CDISASM_MIPS_REG_MXU3_MCS_FIRST));
    else writer->failed = 1;
}

static void append_operand_register(mips_text_writer *writer, const cdisasm_mips_operand *operand, uint32_t instruction_flags)
{
    if (operand->reg >= CDISASM_MIPS_REG_VFPU_SCALAR_FIRST && operand->reg <= CDISASM_MIPS_REG_VFPU_CONTROL_LAST) {
        char name[64];
        const size_t length = cdisasm_mips_allegrex_register_name(operand, name, sizeof(name));
        if (length == 0 || length >= sizeof(name)) writer->failed = 1;
        else append_text(writer, name, length);
        return;
    }
    if ((operand->detail.flags & CDISASM_MIPS_OPERAND_DETAIL_REGISTER_SELECTOR) != 0) {
        append_number(writer, "0x%" PRIx64, operand->imm);
        return;
    }
    if ((operand->detail.flags & CDISASM_MIPS_OPERAND_DETAIL_REGISTER_LIST) != 0 &&
        !(operand->reg >= CDISASM_MIPS_REG_FCC0 && operand->reg <= CDISASM_MIPS_REG_FCC7)) {
        unsigned bit, count = 0;
        append_text(writer, "{", 1u);
        for (bit = 0; bit < 32u; ++bit) {
            if ((operand->imm & (UINT64_C(1) << bit)) == 0) continue;
            if (count++) append_text(writer, ", ", 2u);
            append_register(writer, (cdisasm_mips_reg_id)((operand->reg ? operand->reg : CDISASM_MIPS_REG_GPR0) + bit));
        }
        append_text(writer, "}", 1u);
        return;
    }
    if ((instruction_flags & CDISASM_MIPS_INSTRUCTION_FLAG_MDMX) != 0 &&
        operand->reg >= CDISASM_MIPS_REG_FPR0 && operand->reg <= CDISASM_MIPS_REG_FPR31)
        append_number(writer, "$v%u", (unsigned)(operand->reg - CDISASM_MIPS_REG_FPR0));
    else append_register(writer, operand->reg);
    if ((operand->detail.flags & CDISASM_MIPS_OPERAND_DETAIL_HAS_LANE) != 0) {
        append_text(writer, "[", 1u);
        if ((operand->detail.flags & CDISASM_MIPS_OPERAND_DETAIL_LANE_REGISTER) != 0) append_register(writer, operand->index_reg);
        else append_number(writer, "%u", (unsigned)operand->detail.lane_index);
        append_text(writer, "]", 1u);
    }
}

static int decimal_control(cdisasm_mips_name_id name)
{
    switch (name) {
        case CDISASM_MIPS_NAME_SLL: case CDISASM_MIPS_NAME_SRL: case CDISASM_MIPS_NAME_SRA:
        case CDISASM_MIPS_NAME_DSLL: case CDISASM_MIPS_NAME_DSRL: case CDISASM_MIPS_NAME_DSRA:
        case CDISASM_MIPS_NAME_DSLL32: case CDISASM_MIPS_NAME_DSRL32: case CDISASM_MIPS_NAME_DSRA32:
        case CDISASM_MIPS_NAME_ROTR: case CDISASM_MIPS_NAME_EXT: case CDISASM_MIPS_NAME_INS:
        case CDISASM_MIPS_NAME_DEXT: case CDISASM_MIPS_NAME_DEXTM: case CDISASM_MIPS_NAME_DEXTU:
        case CDISASM_MIPS_NAME_DINS: case CDISASM_MIPS_NAME_DINSM: case CDISASM_MIPS_NAME_DINSU:
        case CDISASM_MIPS_NAME_RDHWR: case CDISASM_MIPS_NAME_LSA: case CDISASM_MIPS_NAME_DLSA:
        case CDISASM_MIPS_NAME_DROTR: case CDISASM_MIPS_NAME_DROTR32: return 1;
        default: return 0;
    }
}

static size_t render_instruction(const cdisasm_mips_instruction *instruction, uint32_t flags, char *buffer, size_t buffer_size)
{
    mips_text_writer writer;
    const char *name;
    uint8_t index;
    unsigned visible_count = 0;
    if (buffer_size != 0 && buffer == NULL) return 0;
    if (buffer_size != 0) buffer[0] = '\0';
    if ((flags & ~CDISASM_FORMAT_KNOWN_FLAGS_MASK) != 0 || instruction == NULL) return 0;
    if (instruction->form_id >= 62000u)
        return cdisasm_mips_vu_format_instruction(instruction, flags, buffer, buffer_size);
    name = mips_mnemonics[instruction->name_id];
    if (name == NULL || name[0] == '\0') return 0;
    writer.buffer = buffer;
    writer.capacity = buffer_size;
    writer.length = 0;
    writer.failed = 0;
    while (*name != '\0') {
        char letter = *name++;
        if ((flags & CDISASM_FORMAT_UPPERCASE_OPCODE) != 0 && letter >= 'a' && letter <= 'z') letter = (char)(letter - 'a' + 'A');
        append_text(&writer, &letter, 1u);
    }
    for (index = 0; index < instruction->operand_count; ++index) {
        const cdisasm_mips_operand *operand = &instruction->operand[index];
        if ((operand->flags & CDISASM_OPERAND_FLAG_IMPLICIT) != 0) continue;
        append_text(&writer, visible_count == 0 ? " " : ", ", visible_count == 0 ? 1u : 2u);
        ++visible_count;
        {
            char specialized[256];
            size_t length = cdisasm_mips_allegrex_format_operand(instruction, index, specialized, sizeof(specialized));
            if (length == SIZE_MAX) continue; /* Handled empty prefix-control lane. */
            if (length != 0) {
                if (length >= sizeof(specialized)) writer.failed = 1;
                else append_text(&writer, specialized, length);
                continue;
            }
        }
        switch (operand->type) {
            case CDISASM_OPERAND_REGISTER:
                append_operand_register(&writer, operand, instruction->instruction_flags);
                if (operand->reg >= CDISASM_MIPS_REG_COP2_FIRST && operand->reg <= CDISASM_MIPS_REG_COP2_LAST &&
                    ((operand->reg - CDISASM_MIPS_REG_COP2_FIRST) % 8u) != 0)
                    append_number(&writer, ", %u", (unsigned)(operand->reg - CDISASM_MIPS_REG_COP2_FIRST) % 8u);
                break;
            case CDISASM_OPERAND_IMMEDIATE:
                if ((operand->flags & (CDISASM_MIPS_OPERAND_FLAG_RELATIVE | CDISASM_MIPS_OPERAND_FLAG_ABSOLUTE)) != 0) append_number(&writer, "0x%" PRIx64, operand->imm);
                else if ((operand->flags & CDISASM_MIPS_OPERAND_FLAG_SIGNED) != 0) append_signed(&writer, operand->imm);
                else if (decimal_control(instruction->name_id)) append_number(&writer, "%" PRIu64, operand->imm);
                else append_number(&writer, "0x%" PRIx64, operand->imm);
                break;
            case CDISASM_OPERAND_MEMORY:
                if ((operand->detail.flags & CDISASM_MIPS_OPERAND_DETAIL_BARE_BASE) != 0) {
                    append_register(&writer, operand->base_reg);
                    break;
                }
                if (operand->base_reg == CDISASM_MIPS_REG_NONE && (operand->flags & CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS) != 0) {
                    append_number(&writer, "0x%" PRIx64, operand->address);
                    break;
                }
                if (operand->index_reg != CDISASM_MIPS_REG_NONE &&
                    (operand->flags & CDISASM_MIPS_OPERAND_FLAG_HAS_DISPLACEMENT) != 0) {
                    append_signed(&writer, operand->imm);
                    append_text(&writer, "(", 1u);
                    append_register(&writer, operand->base_reg);
                    append_text(&writer, ", ", 2u);
                    append_register(&writer, operand->index_reg);
                    append_text(&writer, ")", 1u);
                    break;
                }
                if (operand->index_reg != CDISASM_MIPS_REG_NONE) append_register(&writer, operand->index_reg);
                else if ((operand->flags & CDISASM_MIPS_OPERAND_FLAG_HAS_DISPLACEMENT) != 0) append_signed(&writer, operand->imm);
                append_text(&writer, "(", 1u);
                append_register(&writer, operand->base_reg);
                append_text(&writer, ")", 1u);
                break;
            default: writer.failed = 1; break;
        }
    }
    finish_text(&writer);
    return writer.failed ? 0 : writer.length;
}

size_t CDISASM_CALL cdisasm_mips_format(const cdisasm_mips_instruction *instruction, uint32_t flags, char *buffer, size_t buffer_size)
{
    if (!cdisasm_mips_instruction_validate(instruction)) {
        if (buffer != NULL && buffer_size != 0) buffer[0] = '\0';
        return 0;
    }
    return render_instruction(instruction, flags, buffer, buffer_size);
}

size_t CDISASM_CALL cdisasm_mips_format_v2(const cdisasm_mips_instruction_v2 *instruction, uint32_t flags, char *buffer, size_t buffer_size)
{
    if (!cdisasm_mips_instruction_validate_v2(instruction)) {
        if (buffer != NULL && buffer_size != 0) buffer[0] = '\0';
        return 0;
    }
    return render_instruction(&instruction->instruction, flags, buffer, buffer_size);
}

size_t CDISASM_CALL cdisasm_mips_format_vu(const cdisasm_mips_vu_instruction *instruction,
    uint32_t flags, char *buffer, size_t buffer_size)
{
    mips_text_writer writer;
    char upper[512], lower[512];
    size_t upper_size, lower_size;
    if (buffer_size != 0 && buffer == NULL) return 0;
    if (buffer_size != 0) buffer[0] = '\0';
    if ((flags & ~CDISASM_FORMAT_KNOWN_FLAGS_MASK) != 0 || !cdisasm_mips_vu_instruction_validate(instruction)) return 0;
    upper_size = render_instruction(&instruction->upper.instruction, flags, upper, sizeof(upper));
    lower_size = render_instruction(&instruction->lower.instruction, flags, lower, sizeof(lower));
    if (upper_size == 0 || upper_size >= sizeof(upper) || lower_size == 0 || lower_size >= sizeof(lower)) return 0;
    writer.buffer = buffer;
    writer.capacity = buffer_size;
    writer.length = 0;
    writer.failed = 0;
    append_text(&writer, upper, upper_size);
    append_text(&writer, " | ", 3u);
    append_text(&writer, lower, lower_size);
    finish_text(&writer);
    return writer.failed ? 0 : writer.length;
}
