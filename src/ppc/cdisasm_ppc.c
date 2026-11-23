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
    uint64_t features;
    if (!form || !ppc_selection(cpu, mode, flags, &features)) return 0;
    if (flags && (flags->bitmap[0] & CDISASM_PPC_DECODE_VLE)) {
        /* VLEPEM 2.2.1 and Appendix B: the ordinary base forms retained
         * by this baseline use opcode 31. Other opcodes are reallocated. */
        if (!form->encoding && form->match[0] >> 26 != 31u) return 0;
    } else if (form->encoding) return 0;
    return (form->mode_mask & (mode == 64 ? CDISASM_PPC_MODE_MASK_64 : CDISASM_PPC_MODE_MASK_32)) && (form->profile_mask & (1u << CDISASM_CPU_ORDINAL_OF(cpu))) &&
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
            if (cdisasm_ppc_cpu_features(cpu) & CDISASM_PPC_FEATURE_64) {
                if (a > 31 || a == 5 || a == 13 || a == 17 || a == 19) return 0;
            } else if (a > 20 || ((a & 16u) && (a & 8u)) || ((a & 4u) && (a & 2u)) || ((a & 20u) == 20u && (a & 1u))) return 0;
            break;
        case CDISASM_PPC_CONSTRAINT_NONZERO: if (!a && !b) return 0; break;
        case CDISASM_PPC_CONSTRAINT_ZEROIF: if (b && a) return 0; break;
        case CDISASM_PPC_CONSTRAINT_CLEAR: if (a & b) return 0; break;
        case CDISASM_PPC_CONSTRAINT_MMA: if (b / 4u == a) return 0; break;
        case CDISASM_PPC_CONSTRAINT_ONEHOT: if (!a || (a & (a - 1u))) return 0; break;
        case CDISASM_PPC_CONSTRAINT_ROUND: if (!a && b != 0 && b != 3) return 0; break;
        default: return 0;
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
        if (spec->flags & CDISASM_PPC_OPERAND_OFFSET_ONE) ++op->value;
        switch (spec->kind) {
        case CDISASM_PPC_OP_GPR: case CDISASM_PPC_OP_FPR: case CDISASM_PPC_OP_CRFIELD: case CDISASM_PPC_OP_CRBIT:
        case CDISASM_PPC_OP_VR: case CDISASM_PPC_OP_VSR: case CDISASM_PPC_OP_QPX: case CDISASM_PPC_OP_SEGMENT: case CDISASM_PPC_OP_ACC:
            if (spec->flags & CDISASM_PPC_OPERAND_REDUCED_GPR) raw = raw < 8 ? raw : raw + 16;
            if (spec->flags & CDISASM_PPC_OPERAND_ALT_GPR) raw += 8;
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
        {48,19,"pidr"},{464,19,"ptcr"}
    };
    size_t i;
    if (!ppc_cpu_valid(cpu)) return NULL;
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
