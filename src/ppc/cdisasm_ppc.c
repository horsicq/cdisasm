/* Classic PowerPC decoder. Architectural facts originate in the descriptor
 * provenance; generated tables are shared with external encoding clients. */
#include "cdisasm/cdisasm_ppc.h"
#include <string.h>
#include "generated/ppc_forms.inc"
#include "generated/ppc_aliases.inc"
#include "generated/ppc_profiles.inc"
#include "generated/ppc_sprs.inc"

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
            unsigned ric = (word >> 18) & 3u, prs = (word >> 17) & 1u;
            /* ISA3.1B BookIII6.9.3.3 / ISA3.1C pp1172,1176,1183:
             * effR is R in hypervisor state, otherwise LPCR[HR]. Neither
             * that state nor SF is supplied to this encoding decoder.
             * Reject only combinations invalid for every possible effR. */
            if (ric == 3 && (xo == 274 || prs)) return 0;
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
            /* ISA3.1C BookI6.3.2 p251: mtvscr is context synchronizing.
             * Trap/hash-check interrupt conditions are execution state. */
            if ((suffix & UINT32_C(0xffff07ff)) == UINT32_C(0x10000644)) return 0;
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
        if (spec->recipe == CDISASM_PPC_RECIPE_HASH_DISP)
            op->value = (int64_t)raw - 64;
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
/* Only the named inventory is constrained by the published implementation
 * tables. mfspr/mtspr numeric operands retain every ten-bit selector. */
const char *CDISASM_CALL cdisasm_ppc_spr_name(cdisasm_ppc_cpu_id cpu, uint32_t spr)
{
    size_t i;
    uint32_t ordinal = CDISASM_CPU_ORDINAL_OF(cpu);
    if (!ppc_cpu_valid(cpu) || spr >= 1024u) return NULL;
    if (ppc_spr_audited[ordinal]) {
        for (i = ppc_spr_bounds[ordinal]; i < ppc_spr_bounds[ordinal + 1u]; ++i)
            if (ppc_sprs[i].selector == spr) return ppc_sprs[i].name;
        return NULL;
    }
    return NULL;
}

int32_t CDISASM_CALL cdisasm_ppc_spr_from_name(cdisasm_ppc_cpu_id cpu, const char *name, int write)
{
    uint32_t spr;
    if (!ppc_cpu_valid(cpu) || !name) return -1;
    if (ppc_spr_audited[CDISASM_CPU_ORDINAL_OF(cpu)]) {
        uint32_t ordinal = CDISASM_CPU_ORDINAL_OF(cpu);
        for (spr = ppc_spr_bounds[ordinal]; spr < ppc_spr_bounds[ordinal + 1u]; ++spr)
            if (ppc_sprs[spr].name_lookup && (ppc_sprs[spr].access & (write ? 2u : 1u)) &&
                ppc_equal(name, ppc_sprs[spr].name)) return ppc_sprs[spr].selector;
        return -1;
    }
    return -1;
}
