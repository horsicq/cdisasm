/* Copyright (c) 2026 hors<horsicq@gmail.com>
 * SPDX-License-Identifier: MIT */
#include "mips_vu_internal.h"
#include "cdisasm/cdisasm_format.h"
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#if USE_EXTRA_OPCODES
#include "generated/mips_vu_mnemonics.inc"

typedef struct vu_text {
    char *buffer;
    size_t capacity, length;
    int failed;
} vu_text;

static void text(vu_text *w, const char *s)
{
    size_t count = strlen(s), copied;
    if (w->failed) return;
    if (count > SIZE_MAX - w->length) { w->failed = 1; return; }
    if (w->capacity && w->length < w->capacity - 1u) {
        copied = w->capacity - 1u - w->length;
        if (copied > count) copied = count;
        memcpy(w->buffer + w->length, s, copied);
    }
    w->length += count;
}

static void number(vu_text *w, const char *format, ...)
{
    char temporary[96];
    int count;
    va_list args;
    va_start(args, format);
    count = vsnprintf(temporary, sizeof(temporary), format, args);
    va_end(args);
    if (count < 0 || (size_t)count >= sizeof(temporary)) w->failed = 1;
    else text(w, temporary);
}

static void signed_number(vu_text *w, uint64_t value)
{
    if (value >> 63) number(w, "-%" PRIu64, UINT64_C(0) - value);
    else number(w, "%" PRIu64, value);
}

static void components(vu_text *w, unsigned mask, int uppercase)
{
    unsigned n;
    const char *letters = uppercase ? "XYZW" : "xyzw";
    for (n = 0; n < 4u; ++n) if (mask & (8u >> n)) {
        char letter[2] = { letters[n], '\0' };
        text(w, letter);
    }
}

static void reg_name(vu_text *w, unsigned reg)
{
    if (reg >= CDISASM_MIPS_REG_VU_VF_FIRST && reg <= CDISASM_MIPS_REG_VU_VF_LAST)
        number(w, "vf%u", reg - CDISASM_MIPS_REG_VU_VF_FIRST);
    else if (reg >= CDISASM_MIPS_REG_VU_VI_FIRST && reg <= CDISASM_MIPS_REG_VU_VI_LAST)
        number(w, "vi%u", reg - CDISASM_MIPS_REG_VU_VI_FIRST);
    else if (reg >= CDISASM_MIPS_REG_GPR0 && reg <= CDISASM_MIPS_REG_GPR31)
        number(w, "$%u", reg - CDISASM_MIPS_REG_GPR0);
    else {
        switch (reg) {
            case CDISASM_MIPS_REG_VU_ACC: text(w, "ACC"); break;
            case CDISASM_MIPS_REG_VU_Q: text(w, "Q"); break;
            case CDISASM_MIPS_REG_VU_I: text(w, "I"); break;
            case CDISASM_MIPS_REG_VU_P: text(w, "P"); break;
            case CDISASM_MIPS_REG_VU_R: text(w, "R"); break;
            case CDISASM_MIPS_REG_VU_STATUS: text(w, "STATUS"); break;
            case CDISASM_MIPS_REG_VU_MAC: text(w, "MAC"); break;
            case CDISASM_MIPS_REG_VU_CLIP: text(w, "CLIP"); break;
            case CDISASM_MIPS_REG_VU_TPC: text(w, "TPC"); break;
            case CDISASM_MIPS_REG_VU_CMSAR0: text(w, "CMSAR0"); break;
            case CDISASM_MIPS_REG_VU_FBRST: text(w, "FBRST"); break;
            case CDISASM_MIPS_REG_VU_VPU_STAT: text(w, "VPU_STAT"); break;
            case CDISASM_MIPS_REG_VU_CMSAR1: text(w, "CMSAR1"); break;
            default: w->failed = 1; break;
        }
    }
}

static const char *spelling(unsigned form)
{
    size_t n;
    if (form == 64998u || form == 64999u) return "loi";
    if (form >= 63500u && form < 64500u) form -= 1000u;
    for (n = 0; n < sizeof(vu_spellings) / sizeof(vu_spellings[0]); ++n)
        if (vu_spellings[n].form == form) return vu_spellings[n].name;
    return NULL;
}

static void local_memory(vu_text *w, const cdisasm_mips_instruction *i,
                         const cdisasm_mips_operand *o, const vu_form *f)
{
    unsigned mask = o->detail.reserved & 15u;
    int integer = i->operand[0].reg >= CDISASM_MIPS_REG_VU_VI_FIRST &&
                  i->operand[0].reg <= CDISASM_MIPS_REG_VU_VI_LAST;
    if (f->kind == 2u && (i->raw_instruction >> 25) < 64u) {
        unsigned encoded = i->raw_instruction & 2047u;
        int displacement = (int)(encoded ^ 1024u) - 1024;
        if (displacement < 0) number(w, "-%u", (unsigned)-displacement);
        else number(w, "%u", (unsigned)displacement);
    }
    text(w, "(");
    if (f->properties & VU_PROP_PRE) text(w, "--");
    reg_name(w, o->index_reg);
    if (f->properties & VU_PROP_POST) text(w, "++");
    text(w, ")");
    if (integer) components(w, mask, 0);
}

size_t cdisasm_mips_vu_format_instruction(const cdisasm_mips_instruction *i,
                                         uint32_t flags, char *buffer, size_t capacity)
{
    vu_text w = { buffer, capacity, 0u, 0 };
    const vu_form *f;
    const char *name;
    unsigned n, visible = 0u;
    int uppercase = (flags & CDISASM_FORMAT_UPPERCASE_OPCODE) != 0;
    if (capacity && !buffer) return 0;
    if (capacity) buffer[0] = '\0';
    if (!i || (flags & ~CDISASM_FORMAT_KNOWN_FLAGS_MASK)) return 0;
    f = cdisasm_mips_vu_form(i->form_id);
    name = spelling(i->form_id);
    if (!name || (!f && i->form_id != 64998u && i->form_id != 64999u)) return 0;
    while (*name) {
        char letter[2] = { *name++, '\0' };
        if (uppercase && letter[0] >= 'a' && letter[0] <= 'z') letter[0] -= 'a' - 'A';
        text(&w, letter);
    }
    if (f && (f->properties & VU_PROP_DEST_MASK)) {
        text(&w, ".");
        components(&w, (i->raw_instruction >> 21) & 15u, uppercase);
    }
    if (f && f->kind == 1u && (i->raw_instruction & CDISASM_MIPS_VU_CONTROL_MASK)) {
        static const char *const controls[5] = { "I", "E", "M", "D", "T" };
        text(&w, "[");
        for (n = 0; n < 5u; ++n) if (i->raw_instruction & (UINT32_C(1) << (31u - n))) text(&w, controls[n]);
        text(&w, "]");
    }
    for (n = 0; n < i->operand_count; ++n) {
        const cdisasm_mips_operand *o = &i->operand[n];
        if (o->flags & CDISASM_OPERAND_FLAG_IMPLICIT) continue;
        text(&w, visible++ ? ", " : " ");
        if (o->type == CDISASM_OPERAND_REGISTER) {
            reg_name(&w, o->reg);
            if (o->detail.flags & CDISASM_MIPS_OPERAND_DETAIL_COMPONENT_MASK) {
                unsigned mask = o->detail.lane_index;
                /* MR32's mnemonic uses the destination suffix on both visible
                 * operands; the typed source mask records the rotated fields
                 * actually read (Sony pp183/286). */
                if (n == 1u && (i->name_id == CDISASM_MIPS_NAME_MR32 || i->name_id == CDISASM_MIPS_NAME_VMR32))
                    mask = (i->raw_instruction >> 21) & 15u;
                components(&w, mask, 0);
            }
            else if (o->detail.flags & CDISASM_MIPS_OPERAND_DETAIL_HAS_LANE) {
                char letter[2] = { "xyzw"[o->detail.lane_index & 3u], '\0' };
                text(&w, letter);
            }
        } else if (o->type == CDISASM_OPERAND_MEMORY) {
            if (f && (f->properties & VU_PROP_LOCAL)) local_memory(&w, i, o, f);
            else { signed_number(&w, o->imm); text(&w, "("); reg_name(&w, o->base_reg); text(&w, ")"); }
        } else if (o->type == CDISASM_OPERAND_IMMEDIATE) {
            if (i->form_id == 64998u || i->form_id == 64999u)
                number(&w, "0x%08" PRIx64, o->imm); /* Lossless IEEE-754 payload, including NaNs. */
            else if (o->flags & CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS) number(&w, "0x%" PRIx64, o->imm);
            else if (o->flags & CDISASM_MIPS_OPERAND_FLAG_SIGNED) signed_number(&w, o->imm);
            else number(&w, "0x%" PRIx64, o->imm);
        } else w.failed = 1;
    }
    if (capacity) buffer[w.failed ? 0u : w.length < capacity ? w.length : capacity - 1u] = '\0';
    return w.failed ? 0u : w.length;
}
#else
size_t cdisasm_mips_vu_format_instruction(const cdisasm_mips_instruction *i,
                                         uint32_t flags, char *buffer, size_t capacity)
{
    (void)i; (void)flags;
    if (buffer && capacity) buffer[0] = '\0';
    return 0;
}
#endif
