#include "mips_decoder.h"
#include <stdio.h>
#include <string.h>

#if USE_EXTRA_OPCODES

/* Render the encoded VFPU view, retaining legal overlapping-view aliases.
 * The physical scalar register effects are expanded separately. */
size_t cdisasm_mips_allegrex_register_name(const cdisasm_mips_operand *operand, char *buffer, size_t capacity)
{
    char name[32];
    int length = -1;
    unsigned encoded, m, x, y, dimension;
    if (operand->reg >= CDISASM_MIPS_REG_VFPU_CONTROL_FIRST && operand->reg <= CDISASM_MIPS_REG_VFPU_CONTROL_LAST) {
        static const char *const controls[16] = {
            "SPFX", "TPFX", "DPFX", "CC", "INF4", "RSV5", "RSV6", "REV",
            "RCX0", "RCX1", "RCX2", "RCX3", "RCX4", "RCX5", "RCX6", "RCX7"
        };
        encoded = operand->reg - CDISASM_MIPS_REG_VFPU_CONTROL_FIRST;
        if (encoded >= 16u) return 0;
        if (encoded == 3u && (operand->detail.flags & CDISASM_MIPS_OPERAND_DETAIL_HAS_LANE) != 0u)
            length = snprintf(name, sizeof(name), "%u", (unsigned)operand->detail.lane_index);
        else length = snprintf(name, sizeof(name), "%s", controls[encoded]);
    } else if (operand->reg >= CDISASM_MIPS_REG_VFPU_SCALAR_FIRST && operand->reg <= CDISASM_MIPS_REG_VFPU_SCALAR_LAST) {
        encoded = operand->reg - CDISASM_MIPS_REG_VFPU_SCALAR_FIRST;
        length = snprintf(name, sizeof(name), "S%u%u%u", (encoded >> 2) & 7u, encoded & 3u, encoded >> 5);
    } else if (operand->reg >= CDISASM_MIPS_REG_VFPU_VECTOR_FIRST && operand->reg <= CDISASM_MIPS_REG_VFPU_VECTOR_LAST) {
        encoded = operand->reg - CDISASM_MIPS_REG_VFPU_VECTOR_FIRST;
        dimension = operand->size / 4u;
        if (dimension < 2u || dimension > 4u) return 0;
        m = (encoded >> 2) & 7u;
        x = encoded & 3u;
        y = (encoded & 64u) ? (dimension == 3u ? 1u : 2u) : 0u;
        if (encoded & 32u) length = snprintf(name, sizeof(name), "R%u%u%u", m, y, x);
        else length = snprintf(name, sizeof(name), "C%u%u%u", m, x, y);
    } else if (operand->reg >= CDISASM_MIPS_REG_VFPU_MATRIX_FIRST && operand->reg <= CDISASM_MIPS_REG_VFPU_MATRIX_LAST) {
        encoded = operand->reg - CDISASM_MIPS_REG_VFPU_MATRIX_FIRST;
        dimension = operand->detail.lane_index;
        if (dimension < 1u || dimension > 4u || operand->size != dimension*dimension*4u) return 0;
        m = (encoded >> 2) & 7u;
        x = encoded & 3u;
        y = (encoded & 64u) ? (dimension == 3u ? 1u : 2u) : 0u;
        if (encoded & 32u) length = snprintf(name, sizeof(name), "E%u%u%u", m, y, x);
        else length = snprintf(name, sizeof(name), "M%u%u%u", m, x, y);
    }
    if (length <= 0 || (size_t)length >= sizeof(name)) return 0;
    if (buffer && capacity) {
        size_t copied = (size_t)length < capacity-1u ? (size_t)length : capacity-1u;
        memcpy(buffer, name, copied);
        buffer[copied] = '\0';
    }
    return (size_t)length;
}

/* Special assembly operands retain numeric semantics in the public record.
 * Returning zero means the ordinary numeric formatter should handle it. */
size_t cdisasm_mips_allegrex_format_operand(const cdisasm_mips_instruction *instruction, unsigned index,
                                         char *buffer, size_t capacity)
{
    char name[128];
    int length = -1;
    const cdisasm_mips_operand *o;
    if (index >= instruction->operand_count || instruction->form_id < 40000u || instruction->form_id >= 41000u) return 0;
    o = &instruction->operand[index];
    if (instruction->name_id == CDISASM_MIPS_NAME_SV_Q && index == 2u) {
        length = snprintf(name, sizeof(name), "wb");
    } else if ((instruction->name_id == CDISASM_MIPS_NAME_MFVC || instruction->name_id == CDISASM_MIPS_NAME_MTVC ||
         instruction->name_id == CDISASM_MIPS_NAME_VMFVC || instruction->name_id == CDISASM_MIPS_NAME_VMTVC) &&
        o->type == CDISASM_OPERAND_REGISTER && o->reg >= CDISASM_MIPS_REG_VFPU_CONTROL_FIRST && o->reg <= CDISASM_MIPS_REG_VFPU_CONTROL_LAST) {
        length = snprintf(name, sizeof(name), "$%u", 128u + (unsigned)(o->reg - CDISASM_MIPS_REG_VFPU_CONTROL_FIRST));
    } else if (instruction->name_id == CDISASM_MIPS_NAME_VPFXS || instruction->name_id == CDISASM_MIPS_NAME_VPFXT) {
        static const char *const swizzle[4] = {"x", "y", "z", "w"};
        static const char *const constants[8] = {"0", "1", "2", "1/2", "3", "1/3", "1/4", "1/6"};
        unsigned value = (unsigned)o->imm;
        unsigned constant = value & 8u, absolute = !constant && (value & 4u);
        const char *content = constant ? constants[(value & 3u) | ((value & 4u) ? 4u : 0u)] : swizzle[value & 3u];
        length = snprintf(name, sizeof(name), "%s%s%s%s", value & 16u ? "-" : "",
                          absolute ? "|" : "", content, absolute ? "|" : "");
    } else if (instruction->name_id == CDISASM_MIPS_NAME_VPFXD) {
        static const char *const saturation[4] = {"", "[0:1]", "X", "[-1:1]"};
        unsigned value = (unsigned)o->imm;
        length = snprintf(name, sizeof(name), "%s", value & 4u ? "m" : saturation[value & 3u]);
        if (length == 0) {
            if (buffer && capacity) buffer[0] = '\0';
            return SIZE_MAX; /* explicitly handled empty destination lane */
        }
    } else if ((instruction->name_id == CDISASM_MIPS_NAME_VCMP_S || instruction->name_id == CDISASM_MIPS_NAME_VCMP_P ||
                instruction->name_id == CDISASM_MIPS_NAME_VCMP_T || instruction->name_id == CDISASM_MIPS_NAME_VCMP_Q) && index == 0u) {
        static const char *const conditions[16] = {"FL", "EQ", "LT", "LE", "TR", "NE", "GE", "GT", "EZ", "EN", "EI", "ES", "NZ", "NN", "NI", "NS"};
        length = snprintf(name, sizeof(name), "%s", conditions[o->imm & 15u]);
    } else if ((instruction->name_id == CDISASM_MIPS_NAME_VROT_S || instruction->name_id == CDISASM_MIPS_NAME_VROT_P ||
                instruction->name_id == CDISASM_MIPS_NAME_VROT_T || instruction->name_id == CDISASM_MIPS_NAME_VROT_Q) && index == 2u) {
        unsigned lane, dimension = instruction->operand[0].size / 4u;
        unsigned cosine = (unsigned)o->imm & 3u, sine = ((unsigned)o->imm >> 2) & 3u;
        size_t used = 0u;
        name[used++] = '[';
        for (lane = 0u; lane < dimension; ++lane) {
            const char *item = lane == cosine ? "c" : (lane == sine || cosine == sine) ? (o->imm & 16u ? "-s" : "s") : "0";
            if (lane) { name[used++] = ','; name[used++] = ' '; }
            memcpy(name + used, item, strlen(item)); used += strlen(item);
        }
        name[used++] = ']'; name[used] = '\0'; length = (int)used;
    } else if (instruction->name_id == CDISASM_MIPS_NAME_VFIM_S && index == 1u) {
        unsigned half = (unsigned)o->imm;
        unsigned sign = half >> 15, exponent = (half >> 10) & 31u, mantissa = half & 1023u;
        if (exponent == 31u) length = snprintf(name, sizeof(name), "%s%s", sign ? "-" : "", mantissa ? "nan" : "inf");
        else if (exponent == 0u && mantissa == 0u) length = snprintf(name, sizeof(name), "%s0.0", sign ? "-" : "");
        else {
            union { uint32_t bits; float real; } binary32;
            unsigned adjusted;
            if (exponent) binary32.bits = (sign << 31) | ((exponent + 112u) << 23) | (mantissa << 13);
            else {
                adjusted = 113u;
                while ((mantissa & 1024u) == 0u) { mantissa <<= 1; --adjusted; }
                binary32.bits = (sign << 31) | (adjusted << 23) | ((mantissa & 1023u) << 13);
            }
            /* Nine significant decimal digits round-trip binary32 and hence
             * all finite binary16 values through the PSP assembler parser. */
            length = snprintf(name, sizeof(name), "%.9g", (double)binary32.real);
        }
    }
    if (length <= 0 || (size_t)length >= sizeof(name)) return 0;
    if (buffer && capacity) {
        size_t copied = (size_t)length < capacity-1u ? (size_t)length : capacity-1u;
        memcpy(buffer, name, copied); buffer[copied] = '\0';
    }
    return (size_t)length;
}
#else
size_t cdisasm_mips_allegrex_register_name(const cdisasm_mips_operand *operand, char *buffer, size_t capacity)
{
    (void)operand; (void)buffer; (void)capacity;
    return 0;
}
size_t cdisasm_mips_allegrex_format_operand(const cdisasm_mips_instruction *instruction, unsigned index, char *buffer, size_t capacity)
{
    (void)instruction; (void)index; (void)buffer; (void)capacity;
    return 0;
}
#endif
