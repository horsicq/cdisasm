/* Classic PowerPC decoder. Architectural facts originate in the descriptor
 * provenance; generated tables are shared with external encoding clients. */
#include "cdisasm/cdisasm_ppc.h"
#include <string.h>
#include "generated/ppc_forms.inc"
#include "generated/ppc_aliases.inc"
#include "generated/ppc_profiles.inc"

static uint64_t ppc_mask(unsigned width)
{
    return width >= 64 ? UINT64_MAX : (UINT64_C(1) << width) - 1u;
}
static int ppc_cpu_valid(cdisasm_ppc_cpu_id cpu)
{
    return CDISASM_CPU_GROUP_OF(cpu) == CDISASM_CPU_GROUP_PPC && CDISASM_CPU_ORDINAL_OF(cpu) < CDISASM_PPC_CPU_COUNT;
}
uint64_t CDISASM_CALL cdisasm_ppc_cpu_features(cdisasm_ppc_cpu_id cpu)
{
    return ppc_cpu_valid(cpu) ? ppc_profiles[CDISASM_CPU_ORDINAL_OF(cpu)].features : 0;
}
const char *CDISASM_CALL cdisasm_ppc_cpu_name(cdisasm_ppc_cpu_id cpu)
{
    return ppc_cpu_valid(cpu) ? ppc_profiles[CDISASM_CPU_ORDINAL_OF(cpu)].name : NULL;
}
static int ppc_equal(const char *a, const char *b)
{
    if (!a || !b) return 0;
    while (*a && *b) {
        char c = *a++;
        if (c >= 'A' && c <= 'Z') c = (char)(c + ('a' - 'A'));
        if (c != *b++) return 0;
    }
    return !*a && !*b;
}
cdisasm_ppc_cpu_id CDISASM_CALL cdisasm_ppc_cpu_from_name(const char *name)
{
    uint32_t i;
    if (ppc_equal(name, "ppc") || ppc_equal(name, "powerpc") || ppc_equal(name, "ppc32le")) return CDISASM_PPC_CPU_PPC32;
    if (ppc_equal(name, "ppc64le") || ppc_equal(name, "powerpc64") || ppc_equal(name, "powerpc64le")) return CDISASM_PPC_CPU_PPC64;
    if (ppc_equal(name, "g4")) return CDISASM_PPC_CPU_7450;
    if (!name) return CDISASM_CPU_UNKNOWN;
    for (i = 0; i < CDISASM_PPC_CPU_COUNT; ++i)
        if (ppc_equal(name, ppc_profiles[i].name)) return CDISASM_CPU_GROUP_PPC | i;
    if ((name[0] == 'p' || name[0] == 'P') && (name[1] == 'p' || name[1] == 'P') && (name[2] == 'c' || name[2] == 'C')) {
        for (i = 1; i < CDISASM_PPC_CPU_COUNT; ++i)
            if (ppc_equal(name + 3, ppc_profiles[i].name)) return CDISASM_CPU_GROUP_PPC | i;
    }
    return CDISASM_CPU_UNKNOWN;
}
uint32_t CDISASM_CALL cdisasm_ppc_cpu_mode_mask(cdisasm_ppc_cpu_id cpu)
{
    return ppc_cpu_valid(cpu) ? ppc_profiles[CDISASM_CPU_ORDINAL_OF(cpu)].modes : 0;
}
cdisasm_status CDISASM_CALL cdisasm_ppc_cpu_decode_flag_mask(cdisasm_ppc_cpu_id cpu, uint32_t mode, cdisasm_decode_flags *flags)
{
    if (!flags) return CDISASM_STATUS_INVALID_ARGUMENT;
    cdisasm_decode_flags_reset(flags);
    if (!mode) mode = 32;
    if (!ppc_cpu_valid(cpu) || (mode != 32 && mode != 64) ||
        !(cdisasm_ppc_cpu_mode_mask(cpu) & (mode == 64 ? CDISASM_PPC_MODE_MASK_64 : CDISASM_PPC_MODE_MASK_32))) return CDISASM_STATUS_INVALID_ARGUMENT;
    flags->bitmap[0] = CDISASM_PPC_DECODE_LITTLE_ENDIAN | CDISASM_PPC_DECODE_BIG_ENDIAN;
    if (cdisasm_ppc_cpu_features(cpu) & CDISASM_PPC_FEATURE_VLE) flags->bitmap[0] |= CDISASM_PPC_DECODE_VLE;
    flags->bitmap[1] = cdisasm_ppc_cpu_features(cpu);
    flags->bitmap[2] = flags->bitmap[1] & (CDISASM_PPC_FEATURE_FPU | CDISASM_PPC_FEATURE_VMX | CDISASM_PPC_FEATURE_PS |
        CDISASM_PPC_FEATURE_VSX | CDISASM_PPC_FEATURE_DFP | CDISASM_PPC_FEATURE_HTM | CDISASM_PPC_FEATURE_CRYPTO |
        CDISASM_PPC_FEATURE_PREFIXED | CDISASM_PPC_FEATURE_MMA | CDISASM_PPC_FEATURE_SPE | CDISASM_PPC_FEATURE_QPX);
    return CDISASM_STATUS_OK;
}
static int ppc_selection(cdisasm_ppc_cpu_id cpu, uint32_t mode, const cdisasm_decode_flags *flags, uint64_t *features)
{
    cdisasm_decode_flags accepted;
    unsigned i;
    if (cdisasm_ppc_cpu_decode_flag_mask(cpu, mode, &accepted) != CDISASM_STATUS_OK) return 0;
    *features = cdisasm_ppc_cpu_features(cpu);
    /* z0/z0h have no classic instruction storage mode. */
    if ((cpu == CDISASM_PPC_CPU_E200Z0 || cpu == CDISASM_PPC_CPU_E200Z0H) &&
        (!flags || !(flags->bitmap[0] & CDISASM_PPC_DECODE_VLE))) return 0;
    if (!flags) return 1;
    for (i = 0; i < CDISASM_DECODE_FLAGS_BITMAP_COUNT; ++i)
        if (flags->bitmap[i] & ~accepted.bitmap[i]) return 0;
    if ((flags->bitmap[0] & 3u) == 3u || (flags->bitmap[1] & flags->bitmap[2])) return 0;
    if ((flags->bitmap[0] & CDISASM_PPC_DECODE_VLE) && (flags->bitmap[0] & CDISASM_PPC_DECODE_LITTLE_ENDIAN)) return 0;
    *features = (*features | flags->bitmap[1]) & ~flags->bitmap[2];
    /* Keep dialect conflicts explicit even if future profile construction
     * or feature-selection APIs become more permissive. */
    {
        uint64_t vector = *features & (CDISASM_PPC_FEATURE_VMX | CDISASM_PPC_FEATURE_VSX);
        uint64_t dialect = *features & (CDISASM_PPC_FEATURE_PS | CDISASM_PPC_FEATURE_SPE | CDISASM_PPC_FEATURE_QPX);
        if ((vector && dialect) || (dialect && (dialect & (dialect - 1)))) return 0;
    }
    return 1;
}
uint32_t CDISASM_CALL cdisasm_ppc_form_count(void) { return PPC_FORM_COUNT; }
const cdisasm_ppc_form *CDISASM_CALL cdisasm_ppc_forms(void) { return ppc_forms; }
const char *CDISASM_CALL cdisasm_ppc_name(uint32_t id) { return id < PPC_NAME_COUNT ? ppc_names[id] : NULL; }
uint32_t CDISASM_CALL cdisasm_ppc_alias_count(void) { return PPC_ALIAS_COUNT; }
const cdisasm_ppc_alias *CDISASM_CALL cdisasm_ppc_aliases(void) { return ppc_aliases; }
uint64_t CDISASM_CALL cdisasm_ppc_field_get(const uint32_t words[2], const cdisasm_ppc_field *field)
{
    uint64_t value = 0;
    unsigned i;
    if (!words || !field || field->slice_count > CDISASM_PPC_MAX_FIELD_SLICES) return 0;
    if (!field->slice_count) return field->literal;
    for (i = 0; i < field->slice_count; ++i) {
        const cdisasm_ppc_slice *s = &field->slice[i];
        if (s->word >= 2 || !s->width || s->width > 32 || s->lsb + s->width > 32 || s->dst_lsb + s->width > 64) return 0;
        value |= (((uint64_t)words[s->word] >> s->lsb) & ppc_mask(s->width)) << s->dst_lsb;
    }
    return value;
}
int CDISASM_CALL cdisasm_ppc_field_set(uint32_t words[2], const cdisasm_ppc_field *field, uint64_t value)
{
    unsigned i;
    if (!words || !field || field->slice_count > CDISASM_PPC_MAX_FIELD_SLICES || field->width > 64) return 0;
    if (!field->slice_count) return value == field->literal;
    if (value & ~ppc_mask(field->width)) return 0;
    /* Validate before changing any word. */
    for (i = 0; i < field->slice_count; ++i) {
        const cdisasm_ppc_slice *s = &field->slice[i];
        if (s->word >= 2 || !s->width || s->width > 32 || s->lsb + s->width > 32 || s->dst_lsb + s->width > 64) return 0;
    }
    for (i = 0; i < field->slice_count; ++i) {
        const cdisasm_ppc_slice *s = &field->slice[i];
        uint32_t mask = (uint32_t)(ppc_mask(s->width) << s->lsb);
        words[s->word] = (words[s->word] & ~mask) | (uint32_t)(((value >> s->dst_lsb) << s->lsb) & mask);
    }
    return 1;
}
int CDISASM_CALL cdisasm_ppc_form_available(const cdisasm_ppc_form *form, cdisasm_ppc_cpu_id cpu, uint32_t mode, const cdisasm_decode_flags *flags)
{
    uint64_t features, profiles;
    if (!form || !ppc_selection(cpu, mode, flags, &features)) return 0;
    if (flags && (flags->bitmap[0] & CDISASM_PPC_DECODE_VLE)) {
        /* VLEPEM 2.2.1/Appendix B retain opcode 31 and the selected SPE
         * opcode-4 APU. GPR width for SPE does not imply 64-bit execution. */
        if (!form->encoding && form->match[0] >> 26 != 31u &&
            !(form->match[0] >> 26 == 4u && (form->features & CDISASM_PPC_FEATURE_SPE))) return 0;
    } else if (form->encoding) return 0;
    profiles = form->profile_mask | ((uint64_t)form->profile_mask_high[0] << 32) | ((uint64_t)form->profile_mask_high[1] << 40);
    return (form->mode_mask & (mode == 64 ? CDISASM_PPC_MODE_MASK_64 : CDISASM_PPC_MODE_MASK_32)) && (profiles & (UINT64_C(1) << CDISASM_CPU_ORDINAL_OF(cpu))) &&
           (features & form->features) == form->features && !(features & form->excluded);
}
static int ppc_constraints(const cdisasm_ppc_form *form, cdisasm_ppc_cpu_id cpu, const uint32_t words[2])
{
    unsigned i;
    if (form->constraint_count > 4) return 0;
    for (i = 0; i < form->constraint_count; ++i) {
        const cdisasm_ppc_constraint *c = &form->constraint[i];
        uint64_t a = cdisasm_ppc_field_get(words, &c->a), b = cdisasm_ppc_field_get(words, &c->b);
        switch (c->kind) {
        case CDISASM_PPC_CONSTRAINT_EQ: if (a != b) return 0; break;
        case CDISASM_PPC_CONSTRAINT_NE: if (a == b) return 0; break;
        case CDISASM_PPC_CONSTRAINT_LT: if (a >= b) return 0; break;
        case CDISASM_PPC_CONSTRAINT_BIT_SET: if ((a & b) != b) return 0; break;
        case CDISASM_PPC_CONSTRAINT_STRING: {
            uint64_t nb = cdisasm_ppc_field_get(words, &c->c);
            if (!nb) nb = 32;
            if (((b - a) & 31u) < (nb + 3u) / 4u) return 0;
            break;
        }
        case CDISASM_PPC_CONSTRAINT_LMW: if (a >= b) return 0; break;
        case CDISASM_PPC_CONSTRAINT_ONEOF: if (a != b && a != cdisasm_ppc_field_get(words, &c->c)) return 0; break;
        case CDISASM_PPC_CONSTRAINT_BO:
            /* PowerPC PEM64 v3.0 Tables 4-20/4-21; Power ISA 3.0C
             * Book I 2.3 Figures 40/41: server BO uses a/t prediction,
             * whose 01 combination is reserved; z bits are ignored.
             * Classic processors retain their earlier y/z interpretation. */
            if (cpu == CDISASM_PPC_CPU_476) {
                /* 476FP UM v2.2 Tables2-24/2-25 require classic z=0;
                 * section2.5.3 additionally defines CR-only at=10/11
                 * hints under CCR2[SPC5C1]. Their union is BO0..20. */
                if (a > 20) return 0;
            } else if ((cdisasm_ppc_cpu_features(cpu) & CDISASM_PPC_FEATURE_64) || cpu == CDISASM_PPC_CPU_E500MC) {
                /* E500MCRM Rev.3 Table3-24 uses the same a/t scheme;
                 * EREF Rev.1 Table5-28 reserves at=01 even on this
                 * 32-bit core, which ignores static prediction hints. */
                if (a > 31 || a == 5 || a == 13 || a == 17 || a == 19) return 0;
            } else if (a > 20 || ((a & 16u) && (a & 8u)) || ((a & 4u) && (a & 2u)) || ((a & 20u) == 20u && (a & 1u))) return 0;
            break;
        case CDISASM_PPC_CONSTRAINT_NONZERO: if (!a && !b) return 0; break;
        case CDISASM_PPC_CONSTRAINT_ZEROIF: if (b && a) return 0; break;
        case CDISASM_PPC_CONSTRAINT_CLEAR: if (a & b) return 0; break;
        case CDISASM_PPC_CONSTRAINT_MMA: if (b / 4u == a) return 0; break;
        case CDISASM_PPC_CONSTRAINT_ONEHOT: if (!a || (a & (a - 1u))) return 0; break;
        case CDISASM_PPC_CONSTRAINT_VALUES: if (a >= 64 || !(b & (UINT64_C(1) << a))) return 0; break;
        case CDISASM_PPC_CONSTRAINT_ROUND: if (!a && b != 0 && b != 3) return 0; break;
        default: return 0;
        }
    }
    /* Profile-dependent and cross-field restrictions from the instruction
     * definitions, shared by decode, encoding validation and catalog samples. */
    if (!form->encoding) {
        uint32_t word = words[0], op = word >> 26, xo = (word >> 1) & 1023u;
        unsigned cpu_index = CDISASM_CPU_ORDINAL_OF(cpu);
        if (op == 31 && xo == 86) {
            unsigned l = (word >> 21) & 7u;
            /* BookII2.02 p41 introduces local flush; ISA2.05 adds local
             * primary; ISA3.1 p1064 adds the two persistent-storage forms. */
            if (l && !((l == 1 && cpu_index >= 15 && cpu_index <= 20) ||
                (l == 3 && cpu_index >= 16 && cpu_index <= 20) ||
                ((l == 4 || l == 6) && cpu_index == 20))) return 0;
        }
        if (op == 31 && (xo == 278 || xo == 246) && !(form->features & CDISASM_PPC_FEATURE_BOOKE)) {
            unsigned th = (word >> 21) & 31u;
            /* BookII2.01 optional dcbt has a two-bit hint; 970FXUM1.7
             * pp84-85 additionally defines TH8. BookII2.02 p35 widens
             * dcbt to four bits. ISA2.05 BookI p20 gives both five bits.
             * Undefined hints within an implemented field remain encodings. */
            if (th && !((cpu_index >= 16 && cpu_index <= 20) ||
                (xo == 278 && ((cpu_index == 15 && th < 16) ||
                ((cpu_index == 13 || cpu_index == 14) && (th == 1 || th == 3)) ||
                (cpu_index == 13 && th == 8))))) return 0;
        }
        /* ISA3.0C pp1044-1045 introduces SLB read L; slbiag gains its
         * own L field only in ISA3.1 p1226, not ISA3.0C p1042. */
        if (op == 31 && (word & 0x10000u) &&
            (((xo == 915 || xo == 851) && (cpu_index < 19 || cpu_index > 20)) ||
             (xo == 850 && cpu_index != 20))) return 0;
        if (op == 19 && (xo == 16 || xo == 528 || xo == 560)) {
            unsigned bh = (word >> 11) & 3u;
            /* Power ISA3.1C BookI Figure2.7: BH10 is reserved, and
             * BH01 is meaningful only for the link-register target.
             * E500MCRM Rev.3 section3.4.5.1 also implements these BH
             * fields on its 32-bit core; prediction ignores the hint.
             * EREF Rev.1 Table5-29 supplies the same legal combinations. */
            if (bh == 2 || (bh == 1 && xo != 16) ||
                (bh && cpu != CDISASM_PPC_CPU_E500MC &&
                 !(cdisasm_ppc_cpu_features(cpu) & CDISASM_PPC_FEATURE_64))) return 0;
        }
        if (op == 31 && xo == 146 && (word & 0x10000u) &&
            !(cdisasm_ppc_cpu_features(cpu) & CDISASM_PPC_FEATURE_64)) return 0;
        if (op == 31 && (xo == 306 || xo == 274) && cpu_index >= 19 && cpu_index <= 20) {
            unsigned ric = (word >> 18) & 3u, prs = (word >> 17) & 1u, r = (word >> 16) & 1u;
            /* ISA3.1 BookIII6.9.4 tlbie/tlbiel invalid forms. */
            if ((!r && prs && ric != 2) || (!r && ric == 1) ||
                (ric == 3 && (r || xo == 274))) return 0;
        }
        if (op == 31 && xo == 30 && (word & 0x30000u) && ((word >> 21) & 3u) != 2) return 0;
        if (op == 31 && xo == 498) {
            unsigned ih = (word >> 21) & 7u;
            /* ISA3.1 BookIII6.9.3: IH5 is reserved. Earlier server
             * profiles retain the original all-entry form. */
            if (ih == 5 || (cpu_index < 16 && ih)) return 0;
        }
        if (form->word_count == 2 && word == UINT32_C(0x07000000)) {
            uint32_t suffix = words[1], sop = suffix >> 26, sx = (suffix >> 1) & 1023u;
            /* ISA3.1C BookI3.3.20: PNOP ignores its suffix except that
             * branch, rfebb, context-synchronizing (other than isync),
             * and Service Processor Attention instructions are forbidden. */
            if (sop == 16 || sop == 18 || sop == 17 || suffix == UINT32_C(0x00000200)) return 0;
            if (sop == 19 && (sx == 16 || sx == 528 || sx == 560 || sx == 146 ||
                sx == 18 || sx == 50 || sx == 82 || sx == 274 || sx == 306 || sx == 370)) return 0;
            if (sop == 31 && (sx == 146 || sx == 178) && !(suffix & 0x10000u)) return 0;
        }
    }
    return 1;
}
int CDISASM_CALL cdisasm_ppc_form_valid(const cdisasm_ppc_form *form, cdisasm_ppc_cpu_id cpu, uint32_t mode, const cdisasm_decode_flags *flags, const uint32_t words[2])
{
    unsigned i;
    if (!words || !cdisasm_ppc_form_available(form, cpu, mode, flags) || !form->word_count || form->word_count > 2) return 0;
    for (i = 0; i < form->word_count; ++i)
        if ((words[i] & form->mask[i]) != form->match[i]) return 0;
    return ppc_constraints(form, cpu, words);
}
static uint32_t ppc_read(const uint8_t *b, int little)
{
    if (little) return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
}
static int64_t ppc_signed(uint64_t value, unsigned width)
{
    uint64_t sign = UINT64_C(1) << (width - 1);
    return (int64_t)((value ^ sign) - sign);
}
static void ppc_operands(const cdisasm_ppc_form *form, cdisasm_ppc_instruction *out)
{
    unsigned i;
    for (i = 0; i < form->operand_count; ++i) {
        const cdisasm_ppc_form_operand *spec = &form->operand[i];
        cdisasm_ppc_operand *op = &out->operand[i];
        uint64_t raw = cdisasm_ppc_field_get(out->words, &spec->field[0]);
        op->type = spec->kind; op->access = spec->access; op->flags = spec->flags;
        op->width = spec->width; op->scale = spec->scale; op->size = spec->size;
        op->value = (spec->flags & CDISASM_PPC_OPERAND_SIGNED) ? ppc_signed(raw, spec->width) : (int64_t)raw;
        op->recipe = spec->recipe;
        if (spec->recipe == CDISASM_PPC_RECIPE_SCI8) {
            unsigned shift = (unsigned)((raw >> 8) & 3u) * 8u;
            uint32_t expanded = (raw & 0x400u) ? UINT32_MAX : 0;
            expanded = (expanded & ~(UINT32_C(255) << shift)) | ((uint32_t)(raw & 255u) << shift);
            op->value = (spec->flags & CDISASM_PPC_OPERAND_SIGNED) ? ppc_signed(expanded, 32) : (int64_t)expanded;
            op->disp = (int64_t)raw;
        }
        if (spec->flags & CDISASM_PPC_OPERAND_OFFSET_ONE) ++op->value;
        switch (spec->kind) {
        case CDISASM_PPC_OP_GPR: case CDISASM_PPC_OP_FPR: case CDISASM_PPC_OP_CRFIELD: case CDISASM_PPC_OP_CRBIT:
        case CDISASM_PPC_OP_VR: case CDISASM_PPC_OP_VSR: case CDISASM_PPC_OP_QPX: case CDISASM_PPC_OP_SEGMENT: case CDISASM_PPC_OP_ACC:
            if (spec->flags & CDISASM_PPC_OPERAND_REDUCED_GPR) raw = raw < 8 ? raw : raw + 16;
            if (spec->flags & CDISASM_PPC_OPERAND_ALT_GPR) raw += 8;
            raw <<= spec->scale;
            op->reg = (uint8_t)raw; op->value = (int64_t)raw;
            op->zero_base = (uint8_t)((spec->flags & CDISASM_PPC_OPERAND_ZERO_BASE) && !raw);
            break;
        case CDISASM_PPC_OP_MEM:
            op->base = (uint8_t)cdisasm_ppc_field_get(out->words, &spec->field[1]);
            if ((spec->flags & CDISASM_PPC_OPERAND_REDUCED_GPR) && op->base >= 8) op->base = (uint8_t)(op->base + 16);
            op->disp = op->value * (INT64_C(1) << spec->scale);
            op->zero_base = (uint8_t)((spec->flags & CDISASM_PPC_OPERAND_ZERO_BASE) && !op->base);
            break;
        case CDISASM_PPC_OP_MEMX:
            op->base = (uint8_t)raw; op->index = (uint8_t)cdisasm_ppc_field_get(out->words, &spec->field[1]);
            op->has_index = 1; op->zero_base = (uint8_t)((spec->flags & CDISASM_PPC_OPERAND_ZERO_BASE) && !op->base);
            break;
        case CDISASM_PPC_OP_BRANCH:
            op->disp = op->value * (INT64_C(1) << spec->scale);
            op->target = ((out->aa ? 0 : out->address) + (uint64_t)op->disp) & (out->mode == 64 ? UINT64_MAX : UINT64_C(0xffffffff));
            if (out->aa) op->flags |= CDISASM_PPC_OPERAND_ABSOLUTE;
            out->branch_target = op->target;
            break;
        case CDISASM_PPC_OP_SPR:
            if (raw & 16u) out->flags |= CDISASM_PPC_FLAG_PRIVILEGED;
            break;
        default: break;
        }
    }
}
uint32_t CDISASM_CALL cdisasm_ppc_decode(cdisasm_ppc_cpu_id cpu, uint32_t mode, const uint8_t *code, size_t size, uint64_t address,
                                         const cdisasm_decode_flags *flags, cdisasm_ppc_instruction *out)
{
    uint32_t words[2], primary, secondary, i, end, begin;
    const uint32_t *candidates;
    uint64_t features;
    int little, vle, short_vle = 0;
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    if (!code || !ppc_selection(cpu, mode, flags, &features)) return 0;
    vle = flags && (flags->bitmap[0] & CDISASM_PPC_DECODE_VLE);
    if (vle) {
        uint32_t half;
        if (size < 2 || (address & 1u)) return 0;
        half = ((uint32_t)code[0] << 8) | code[1];
        /* VLEPEM Appendix B: leading nibbles 1,3,5,7 select 32 bits. */
        short_vle = (half & 0x9000u) != 0x1000u;
        if (!short_vle && size < 4) return 0;
    } else if (size < 4) return 0;
    little = flags && (flags->bitmap[0] & CDISASM_PPC_DECODE_LITTLE_ENDIAN);
    words[0] = short_vle ? ((uint32_t)code[0] << 8) | code[1] : ppc_read(code, little);
    words[1] = !vle && size >= 8 ? ppc_read(code + 4, little) : 0;
    primary = words[0] >> 26; secondary = (words[0] >> 1) & 31u;
    end = ppc_primary_secondary[primary][secondary + 1];
    begin = ppc_primary_secondary[primary][secondary]; candidates = ppc_candidates;
    if (short_vle) {
        begin = ppc_vle16_bounds[words[0] >> 12]; end = ppc_vle16_bounds[(words[0] >> 12) + 1];
        candidates = ppc_vle16_candidates;
    }
    for (i = begin; i < end; ++i) {
        uint32_t id = candidates[i];
        const cdisasm_ppc_form *form = &ppc_forms[id];
        unsigned length = form->encoding == CDISASM_PPC_ENCODING_VLE16 ? 2u : 4u * form->word_count;
        /* Power ISA 3.1 Book I: a prefixed instruction cannot cross a
         * 64-byte boundary. Reject atomically, including truncation. */
        if (form->word_count == 2 && (address & 63u) > 56u) continue;
        if (size < length || !cdisasm_ppc_form_valid(form, cpu, mode, flags, words)) continue;
        out->address = address; out->features = form->features; out->length = length;
        out->flags = form->flags; out->form_id = id; out->name_id = form->name_id;
        out->words[0] = words[0]; out->words[1] = form->word_count > 1 ? words[1] : 0;
        out->cpu_id = cpu; out->mode = mode == 64 ? 64 : 32; out->operand_count = form->operand_count;
        out->rc = (uint8_t)cdisasm_ppc_field_get(words, &form->rc); out->oe = (uint8_t)cdisasm_ppc_field_get(words, &form->oe);
        out->aa = (uint8_t)cdisasm_ppc_field_get(words, &form->aa); out->lk = (uint8_t)cdisasm_ppc_field_get(words, &form->lk);
        if (out->lk) { out->flags |= CDISASM_PPC_FLAG_CALL; if (form->encoding) out->flags &= ~CDISASM_PPC_FLAG_RETURN; }
        if (primary == 16 || (primary == 19 && (form->flags & CDISASM_PPC_FLAG_BRANCH))) {
            if (primary == 19) out->bh = (uint8_t)((words[0] >> 11) & 3u);
            out->bo = (uint8_t)((words[0] >> 21) & 31u); out->bi = (uint8_t)((words[0] >> 16) & 31u);
            if ((out->bo & 20u) == 20u) out->flags &= ~CDISASM_PPC_FLAG_CONDITIONAL;
            if (primary == 19 && ((words[0] >> 1) & 1023u) == 16u && !out->lk && (out->bo & 20u) == 20u) out->flags |= CDISASM_PPC_FLAG_RETURN;
        }
        ppc_operands(form, out);
        if (form->encoding && (form->flags & CDISASM_PPC_FLAG_CONDITIONAL) && form->operand_count == 3) {
            out->bo = (uint8_t)out->operand[0].value; out->bi = (uint8_t)out->operand[1].value;
        }
        if ((form->features & CDISASM_PPC_FEATURE_PREFIXED) && form->operand_count &&
            form->operand[form->operand_count - 1].kind == CDISASM_PPC_OP_IMM &&
            form->operand[form->operand_count - 1].width == 1) {
            unsigned op_index;
            out->pcrel = (uint8_t)out->operand[form->operand_count - 1].value;
            if (out->pcrel) for (op_index = 0; op_index + 1 < form->operand_count; ++op_index) {
                cdisasm_ppc_operand *op = &out->operand[op_index];
                if (op->type == CDISASM_PPC_OP_MEM) {
                    op->flags = (uint8_t)((op->flags & ~CDISASM_PPC_OPERAND_ZERO_BASE) | CDISASM_PPC_OPERAND_PC_RELATIVE);
                    op->zero_base = 0;
                    op->target = (address + (uint64_t)op->disp) & (out->mode == 64 ? UINT64_MAX : UINT64_C(0xffffffff));
                } else if (op->type == CDISASM_PPC_OP_IMM && op->width == 34) {
                    op->flags |= CDISASM_PPC_OPERAND_PC_RELATIVE;
                    /* PADDI produces a 64-bit GPR result in either mode;
                     * only effective addresses are truncated in mode32. */
                    op->target = address + (uint64_t)op->value;
                }
            }
        }
        memcpy(out->bytes, code, out->length); return out->length;
    }
    return 0;
}
uint32_t CDISASM_CALL cdisasm_ppc_form_sample(cdisasm_ppc_cpu_id cpu, uint32_t mode, const cdisasm_decode_flags *flags,
                                              uint32_t form_id, uint32_t seed, uint8_t bytes[8])
{
    const cdisasm_ppc_form *form;
    uint32_t state = seed ^ UINT32_C(0x9e3779b9), words[2] = {0, 0};
    unsigned attempt, w, b;
    int little = flags && (flags->bitmap[0] & CDISASM_PPC_DECODE_LITTLE_ENDIAN);
    if (!bytes || form_id >= PPC_FORM_COUNT) return 0;
    form = &ppc_forms[form_id];
    if (!cdisasm_ppc_form_available(form, cpu, mode, flags)) return 0;
    for (attempt = 0; attempt < 65536; ++attempt) {
        for (w = 0; w < form->word_count; ++w) {
            uint32_t fill;
            state = state * UINT32_C(1664525) + UINT32_C(1013904223);
            fill = attempt ? state : seed == 0 ? 0 : seed == 1 ? UINT32_MAX : seed == 2 ? UINT32_C(0x80008000) : state;
            words[w] = form->match[w] | (fill & ~form->mask[w]);
        }
        /* A finite oneof constraint should not depend on finding its rare
         * field values by chance; seed chooses among the legal alternatives. */
        for (w = 0; w < form->constraint_count; ++w) {
            const cdisasm_ppc_constraint *c = &form->constraint[w];
            if (c->kind == CDISASM_PPC_CONSTRAINT_ONEOF)
                cdisasm_ppc_field_set(words, &c->a, cdisasm_ppc_field_get(words, (seed & 1u) ? &c->c : &c->b));
        }
        if (!ppc_constraints(form, cpu, words)) continue;
        memset(bytes, 0, 8);
        if (form->encoding == CDISASM_PPC_ENCODING_VLE16) {
            bytes[0] = (uint8_t)(words[0] >> 8); bytes[1] = (uint8_t)words[0]; return 2;
        }
        for (w = 0; w < form->word_count; ++w)
            for (b = 0; b < 4; ++b) bytes[4u * w + b] = (uint8_t)(words[w] >> (8u * (little ? b : 3u - b)));
        return 4u * form->word_count;
    }
    return 0;
}
/* IBM A2 UM v1.3 (2012-10-23), sections2.3.2-2.3.4 pp69-74 and
 * 2.11.1-2.11.3 pp114-119. Access bits gate named aliases; numeric SPR
 * selectors retain the raw mfspr/mtspr encoding for unknown registers. */
static const struct { uint16_t code; uint8_t access; const char *name; } ppc_a2_sprs[] = {
    {1,3,"xer"},
    {8,3,"lr"},
    {9,3,"ctr"},
    {259,1,"usprg3"},
    {260,1,"usprg4"},
    {261,1,"usprg5"},
    {262,1,"usprg6"},
    {263,1,"usprg7"},
    {272,3,"sprg0"},
    {273,3,"sprg1"},
    {274,3,"sprg2"},
    {275,3,"sprg3"},
    {276,3,"sprg4"},
    {277,3,"sprg5"},
    {278,3,"sprg6"},
    {279,3,"sprg7"},
    {286,1,"pir"},
    {368,3,"gsprg0"},
    {369,3,"gsprg1"},
    {370,3,"gsprg2"},
    {371,3,"gsprg3"},
    {382,3,"gpir"},
    {437,1,"tensr"},
    {438,3,"tens"},
    {439,3,"tenc"},
    {446,1,"tir"},
    {604,3,"sprg8"},
    {883,3,"iucr1"},
    {898,3,"ppr32"},
    {947,3,"eplc"},
    {948,3,"epsc"},
    {1008,3,"ccr0"},
    {1009,3,"ccr1"},
};
static int ppc_a2_cpu(cdisasm_ppc_cpu_id cpu)
{
    return cpu == CDISASM_PPC_CPU_A2 || cpu == CDISASM_PPC_CPU_A2QPX;
}
/* Insert before cdisasm_ppc_spr_name; dispatch for ordinals30..33 and34..39.
 * Architectural selector facts transcribed from E500MCRM Rev.3 Table2-2,
 * E6500RM Rev.0 Table2-2, IBM476FP UM v2.2 Table2-5/AppendixA, and
 * E200Z0CORERM Rev.0 Table2-22 (minimal shared e200 baseline).
 * Numeric selectors continue to be accepted independently of these names. */
static const char *ppc_job7_embedded_spr_name(cdisasm_ppc_cpu_id cpu, uint32_t spr)
{
    static const struct { uint16_t code; const char *name; } e500_common[] = {
        {1,"xer"},{8,"lr"},{9,"ctr"},{22,"dec"},{26,"srr0"},{27,"srr1"},
        {48,"pid"},{54,"decar"},{58,"csrr0"},{59,"csrr1"},{61,"dear"},
        {62,"esr"},{63,"ivpr"},{259,"sprg3"},{260,"sprg4"},{261,"sprg5"},
        {262,"sprg6"},{263,"sprg7"},{268,"tbl"},{269,"tbu"},
        {272,"sprg0"},{273,"sprg1"},{274,"sprg2"},{275,"sprg3"},
        {276,"sprg4"},{277,"sprg5"},{278,"sprg6"},{279,"sprg7"},
        {284,"tbl"},{285,"tbu"},{286,"pir"},{287,"pvr"},
        {304,"dbsr"},{306,"dbsrwr"},{307,"epcr"},{308,"dbcr0"},
        {309,"dbcr1"},{310,"dbcr2"},{311,"msrp"},{312,"iac1"},{313,"iac2"},
        {316,"dac1"},{317,"dac2"},{338,"lpidr"},{339,"mas5"},{341,"mas8"},
        {368,"gsprg0"},{369,"gsprg1"},{370,"gsprg2"},{371,"gsprg3"},
        {378,"gsrr0"},{379,"gsrr1"},{380,"gepr"},{381,"gdear"},
        {382,"gpir"},{383,"gesr"},{432,"ivor38"},{433,"ivor39"},
        {434,"ivor40"},{435,"ivor41"},{440,"givor2"},{441,"givor3"},
        {442,"givor4"},{443,"givor8"},{444,"givor13"},{445,"givor14"},
        {447,"givpr"},{515,"l1cfg0"},{516,"l1cfg1"},{517,"npidr"},
        {526,"atbl"},{527,"atbu"},{531,"ivor35"},{532,"ivor36"},{533,"ivor37"},
        {563,"dbcr4"},{569,"mcaru"},{570,"mcsrr0"},{571,"mcsrr1"},
        {572,"mcsr"},{573,"mcar"},{574,"dsrr0"},{575,"dsrr1"},{576,"ddam"},
        {606,"l1csr2"},{624,"mas0"},{625,"mas1"},{626,"mas2"},{627,"mas3"},
        {628,"mas4"},{630,"mas6"},{696,"cdcsr0"},{702,"epr"},
        {944,"mas7"},{947,"eplc"},{948,"epsc"},{975,"devent"},
        {983,"nspd"},{984,"nspc"},{1008,"hid0"},{1010,"l1csr0"},
        {1011,"l1csr1"},{1012,"mmucsr0"},{1013,"bucsr"},{1015,"mmucfg"}
    };
    static const struct { uint16_t code; const char *name; } e6500_only[] = {
        {56,"lper"},{57,"lperu"},{256,"vrsave"},{283,"cir"},
        {314,"iac3"},{315,"iac4"},{342,"lratcfg"},{343,"lratps"},
        {348,"mas5_mas6"},{349,"mas8_mas1"},{350,"eptcfg"},
        {372,"mas7_mas3"},{373,"mas0_mas1"},{436,"ivor42"},
        {437,"tensr"},{438,"tens"},{439,"tenc"},{464,"givor35"},
        {528,"ivor32"},{529,"ivor33"},{564,"dbcr5"},{565,"iac5"},
        {566,"iac6"},{567,"iac7"},{568,"iac8"},{604,"sprg8"},
        {637,"mcarua"},{638,"edbrac0"},{700,"dbrr0"},{898,"ppr32"},
        {1019,"pwrmgtcr0"},{1022,"sccsrbar"}
    };
    static const struct { uint16_t code; const char *name; } p476[] = {
        {1,"xer"},{8,"lr"},{9,"ctr"},{316,"dac1"},{317,"dac2"},
        {318,"dvc1"},{319,"dvc2"},{308,"dbcr0"},{309,"dbcr1"},{310,"dbcr2"},
        {850,"dcesr"},{851,"icesr"},{860,"ioccr"},{861,"iocr1"},{862,"iocr2"},
        {891,"dcripr"},{924,"dcdbtrl"},{925,"dcdbtrh"},
        {926,"icdbtrl"},{927,"icdbtrh"},{979,"icdbdr0"},{980,"icdbdr1"}
    };
    static const struct { uint16_t code; const char *name; } e200_minimal[] = {
        {1,"xer"},{8,"lr"},{9,"ctr"},{26,"srr0"},{27,"srr1"},
        {48,"pid0"},{58,"csrr0"},{59,"csrr1"},{61,"dear"},{62,"esr"},
        {63,"ivpr"},{272,"sprg0"},{273,"sprg1"},{286,"pir"},{287,"pvr"},
        {304,"dbsr"},{308,"dbcr0"},{309,"dbcr1"},{310,"dbcr2"},
        {312,"iac1"},{313,"iac2"},{314,"iac3"},{315,"iac4"},
        {316,"dac1"},{317,"dac2"},{515,"l1cfg0"},{572,"mcsr"},
        {574,"dsrr0"},{575,"dsrr1"},{1008,"hid0"},{1009,"hid1"},
        {1013,"bucsr"},{1015,"mmucfg"},{1023,"svr"}
    };
    static const char *const ivor[] = {"ivor0","ivor1","ivor2","ivor3", "ivor4","ivor5","ivor6","ivor7",
        "ivor8","ivor9","ivor10","ivor11","ivor12","ivor13","ivor14","ivor15"};
    unsigned ord=CDISASM_CPU_ORDINAL_OF(cpu); size_t i;
    if (ord>=30 && ord<=32) {
        if(spr>=400 && spr<=415) return ivor[spr-400];
        for(i=0;i<sizeof(e500_common)/sizeof(e500_common[0]);++i)
            if(e500_common[i].code==spr)return e500_common[i].name;
        if(ord==32)for(i=0;i<sizeof(e6500_only)/sizeof(e6500_only[0]);++i)
            if(e6500_only[i].code==spr)return e6500_only[i].name;
    } else if(ord==33) {
        for(i=0;i<sizeof(p476)/sizeof(p476[0]);++i)
            if(p476[i].code==spr)return p476[i].name;
    } else if(ord>=34 && ord<=39) {
        for(i=0;i<sizeof(e200_minimal)/sizeof(e200_minimal[0]);++i)
            if(e200_minimal[i].code==spr)return e200_minimal[i].name;
    }
    return NULL;
}


const char *CDISASM_CALL cdisasm_ppc_spr_name(cdisasm_ppc_cpu_id cpu, uint32_t spr)
{
    static const struct { uint16_t code; const char *name; } common[] = {
        {1,"xer"},{8,"lr"},{9,"ctr"},{18,"dsisr"},{19,"dar"},{22,"dec"},{25,"sdr1"},{26,"srr0"},{27,"srr1"},
        {272,"sprg0"},{273,"sprg1"},{274,"sprg2"},{275,"sprg3"},{282,"ear"},{287,"pvr"},
        {528,"ibat0u"},{529,"ibat0l"},{530,"ibat1u"},{531,"ibat1l"},{532,"ibat2u"},{533,"ibat2l"},{534,"ibat3u"},{535,"ibat3l"},
        {536,"dbat0u"},{537,"dbat0l"},{538,"dbat1u"},{539,"dbat1l"},{540,"dbat2u"},{541,"dbat2l"},{542,"dbat3u"},{543,"dbat3l"}
    };
    /* Power ISA 3.0C Book III Figure 21 SPR encodings. Architectural
     * names are scoped to generations providing the corresponding resource;
     * unknown numeric selectors remain encodable through mfspr/mtspr. */
    static const struct { uint16_t code; uint8_t first; const char *name; } server[] = {
        {310,14,"hdec"},{313,14,"hrmor"},{314,14,"hsrr0"},{315,14,"hsrr1"},
        {318,14,"lpcr"},{319,14,"lpidr"},{304,14,"hsprg0"},
        {309,15,"purr"},{136,15,"ctrl"},{152,15,"ctrl"},
        {3,16,"udscr"},{17,16,"dscr"},{13,16,"uamr"},{29,16,"amr"},
        {308,16,"spurr"},{349,16,"amor"},
        {128,18,"tfhar"},{129,18,"tfiar"},{130,18,"texasr"},{131,18,"texasru"},
        {153,18,"fscr"},{190,18,"hfscr"},{815,18,"tar"},
        {48,19,"pidr"},{464,19,"ptcr"},
        {800,18,"bescrs"},{801,18,"bescrsu"},{802,18,"bescrr"},{803,18,"bescrru"},
        {804,18,"ebbhr"},{805,18,"ebbrr"},{806,18,"bescr"},{898,16,"ppr32"},
        {28,16,"cfar"},
        {61,18,"iamr"},
        {157,19,"uamor"},
        {159,18,"pspb"},
        {176,18,"dpdes"},
        {180,18,"dawr0"},
        {181,20,"dawr1"},
        {186,19,"rpr"},
        {187,18,"ciabr"},
        {188,18,"dawrx0"},
        {189,20,"dawrx1"},
        {339,18,"heir"},
        {446,19,"tir"},
        {816,19,"asdr"},
        {823,19,"psscr"},
        {848,19,"ic"},
        {849,18,"vtb"},
        {855,19,"hpsscr"},
        {896,16,"ppr"},
        {496,19,"usprg0"},
        {497,19,"usprg1"},
        {505,19,"urmor"},
        {506,19,"usrr0"},
        {507,19,"usrr1"},
        {511,19,"smfctrl"},
        {736,20,"usier2"},
        {737,20,"usier3"},
        {738,20,"ummcr3"},
        {752,20,"sier2"},
        {753,20,"sier3"},
        {754,20,"mmcr3"},
        {768,17,"usier"},
        {769,18,"ummcr2"},
        {770,13,"ummcra"},
        {779,13,"ummcr0"},
        {780,13,"usiar"},
        {781,13,"usdar"},
        {782,13,"ummcr1"},
        {784,17,"sier"},
        {785,18,"mmcr2"},
        {786,13,"mmcra"},
        {795,13,"mmcr0"},
        {796,13,"siar"},
        {797,13,"sdar"},
        {798,13,"mmcr1"},
        {771,13,"upmc1"},
        {772,13,"upmc2"},
        {773,13,"upmc3"},
        {774,13,"upmc4"},
        {775,13,"upmc5"},
        {776,13,"upmc6"},
        {787,13,"pmc1"},
        {788,13,"pmc2"},
        {789,13,"pmc3"},
        {790,13,"pmc4"},
        {791,13,"pmc5"},
        {792,13,"pmc6"}
    };
    size_t i;
    if (!ppc_cpu_valid(cpu)) return NULL;
    if (CDISASM_CPU_ORDINAL_OF(cpu)>=30u && CDISASM_CPU_ORDINAL_OF(cpu)<=39u)
        return ppc_job7_embedded_spr_name(cpu, spr);
    if (ppc_a2_cpu(cpu)) {
        for (i = 0; i < sizeof(ppc_a2_sprs) / sizeof(ppc_a2_sprs[0]); ++i)
            if (spr == ppc_a2_sprs[i].code) return ppc_a2_sprs[i].name;
        return NULL;
    }
    if (CDISASM_CPU_ORDINAL_OF(cpu) >= 21u) {
        /* PowerPC UISA's XER/LR/CTR selectors are shared by the embedded
         * integer profiles. Other SPR names need a profile-specific audit:
         * desktop BAT selectors overlap e500 interrupt-vector resources.
         * E500CORERM Rev.1 Table 2-8 (2.7.1.5) assigns IVOR32..35 below.
         * Unlisted selectors remain available as numeric operands. */
        if (spr == 1) return "xer";
        if (spr == 8) return "lr";
        if (spr == 9) return "ctr";
        if (cpu == CDISASM_PPC_CPU_E500V1 || cpu == CDISASM_PPC_CPU_E500V2) {
            static const char *const ivor[] = {"ivor32","ivor33","ivor34","ivor35"};
            if (spr >= 528 && spr <= 531) return ivor[spr - 528];
        }
        return NULL;
    }
    if (cpu == CDISASM_PPC_CPU_970) {
        /* IBM970FX UM v1.7 sections2.1.4.7/8 and Table2-5. */
        if (spr == 304) return "hsprg0";
        if (spr == 305) return "hsprg1";
        if (spr == 310) return "hdec";
        if (spr == 313) return "hrmor";
        if (spr == 314) return "hsrr0";
        if (spr == 315) return "hsrr1";
    }
    for (i = 0; i < sizeof(server) / sizeof(server[0]); ++i)
        if (spr == server[i].code && CDISASM_CPU_ORDINAL_OF(cpu) >= server[i].first && CDISASM_CPU_ORDINAL_OF(cpu) <= 20u) return server[i].name;
    if (cdisasm_ppc_cpu_features(cpu) & CDISASM_PPC_FEATURE_VMX) {
        if (spr == 256) return "vrsave";
    }
    if (cdisasm_ppc_cpu_features(cpu) & CDISASM_PPC_FEATURE_64) {
        if (spr >= 528 && spr <= 543) return NULL; /* BATs are a 32-bit MMU facility. */
        if (spr == 1013 && CDISASM_CPU_ORDINAL_OF(cpu) <= 17) return "dabr";
    }
    if (cpu == CDISASM_PPC_CPU_601) {
        if (!spr) return "mq";
        if (spr == 4 || spr == 20) return "rtcu";
        if (spr == 5 || spr == 21) return "rtcl";
        if (spr >= 536 && spr <= 543) return NULL;
    } else {
        if (spr == 268 || spr == 284) return "tbl";
        if (spr == 269 || spr == 285) return "tbu";
    }
    for (i = 0; i < sizeof(common) / sizeof(common[0]); ++i) if (common[i].code == spr) return common[i].name;
    return NULL;
}

int32_t CDISASM_CALL cdisasm_ppc_spr_from_name(cdisasm_ppc_cpu_id cpu, const char *name, int write)
{
    uint32_t spr;
    if (!ppc_cpu_valid(cpu) || !name) return -1;
    if (CDISASM_CPU_ORDINAL_OF(cpu)>=30u && CDISASM_CPU_ORDINAL_OF(cpu)<=32u) {
        /* E500MCRM/E6500RM Table2-2 user-readable aliases and write selectors. */
        if (ppc_equal(name,"tbl")) return write ? 284 : 268;
        if (ppc_equal(name,"tbu")) return write ? 285 : 269;
        if (write && strlen(name)==5 && (name[0]=='s'||name[0]=='S') &&
            (name[1]=='p'||name[1]=='P') && (name[2]=='r'||name[2]=='R') &&
            (name[3]=='g'||name[3]=='G') && name[4]>='3' && name[4]<='7')
            return 272 + name[4]-'0';
    }

    if (ppc_a2_cpu(cpu)) {
        for (spr = 0; spr < sizeof(ppc_a2_sprs) / sizeof(ppc_a2_sprs[0]); ++spr)
            if (ppc_equal(name, ppc_a2_sprs[spr].name) &&
                (ppc_a2_sprs[spr].access & (write ? 2u : 1u))) return ppc_a2_sprs[spr].code;
        return -1;
    }
    if (CDISASM_CPU_ORDINAL_OF(cpu) >= 15 && CDISASM_CPU_ORDINAL_OF(cpu) <= 20u && ppc_equal(name, "ctrl")) return write ? 152 : 136;
    if (cpu == CDISASM_PPC_CPU_601) {
        if (ppc_equal(name, "rtcu")) return write ? 20 : 4;
        if (ppc_equal(name, "rtcl")) return write ? 21 : 5;
    } else if (CDISASM_CPU_ORDINAL_OF(cpu) <= 20u) {
        if (ppc_equal(name, "tbl")) return write ? 284 : 268;
        if (ppc_equal(name, "tbu")) return write ? 285 : 269;
    }
    for (spr = 0; spr < 1024; ++spr) {
        const char *candidate = cdisasm_ppc_spr_name(cpu, spr);
        if (candidate && ppc_equal(name, candidate)) return (int32_t)spr;
    }
    return -1;
}
