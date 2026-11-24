/* Reversible GNU-style PowerPC presentation. Canonical decoded operands are
 * unchanged; all preferred aliases come from the shared public recipe table. */
#include "cdisasm/cdisasm_ppc.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

typedef struct ppc_text { char *out; size_t capacity, length; int ok, named; } ppc_text;
static void ppc_put(ppc_text *t, const char *format, ...)
{
    int n;
    va_list args;
    if (!t->ok) return;
    va_start(args, format);
    n = vsnprintf(t->out + t->length, t->capacity - t->length, format, args);
    va_end(args);
    if (n < 0 || (size_t)n >= t->capacity - t->length) { t->ok = 0; return; }
    t->length += (size_t)n;
}
static void ppc_reg(ppc_text *t, const char *prefix, unsigned reg, int zero)
{
    if (t->named && !zero) ppc_put(t, "%s%u", prefix, reg);
    else ppc_put(t, "%u", reg);
}
static void ppc_operand(ppc_text *t, const cdisasm_ppc_operand *op)
{
    static const char *const condition[4] = {"lt", "gt", "eq", "so"};
    switch (op->type) {
    case CDISASM_PPC_OP_GPR: ppc_reg(t, "r", op->reg, op->zero_base); break;
    case CDISASM_PPC_OP_FPR: ppc_reg(t, "f", op->reg, 0); break;
    case CDISASM_PPC_OP_CRFIELD: ppc_reg(t, "cr", op->reg, 0); break;
    case CDISASM_PPC_OP_CRBIT:
        if (!t->named) ppc_put(t, "%u", op->reg);
        else if (op->reg < 4) ppc_put(t, "%s", condition[op->reg]);
        else ppc_put(t, "4*cr%u+%s", op->reg / 4u, condition[op->reg & 3u]);
        break;
    case CDISASM_PPC_OP_VR: ppc_reg(t, "v", op->reg, 0); break;
    case CDISASM_PPC_OP_VSR: ppc_reg(t, "vs", op->reg, 0); break;
    case CDISASM_PPC_OP_QPX: ppc_reg(t, "q", op->reg, 0); break;
    case CDISASM_PPC_OP_ACC: ppc_reg(t, "acc", op->reg, 0); break;
    case CDISASM_PPC_OP_SEGMENT: ppc_put(t, "%u", op->reg); break;
    case CDISASM_PPC_OP_MEM:
        ppc_put(t, "%lld(", (long long)op->disp); ppc_reg(t, "r", op->base, op->zero_base || (op->flags & CDISASM_PPC_OPERAND_PC_RELATIVE)); ppc_put(t, ")"); break;
    case CDISASM_PPC_OP_MEMX:
        ppc_reg(t, "r", op->base, op->zero_base); ppc_put(t, ","); ppc_reg(t, "r", op->index, 0); break;
    case CDISASM_PPC_OP_BRANCH: ppc_put(t, "0x%llx", (unsigned long long)op->target); break;
    case CDISASM_PPC_OP_IMM: case CDISASM_PPC_OP_SPR: case CDISASM_PPC_OP_TBR:
        ppc_put(t, "%lld", (long long)op->value);
        /* All SCI8 encodings are exact: only zero/all-ones have duplicate
         * byte placements. Preserve nonzero SCL in an optional operand. */
        if (op->recipe == CDISASM_PPC_RECIPE_SCI8 && (op->disp & 0x300) &&
            ((uint32_t)op->value == 0 || (uint32_t)op->value == UINT32_MAX))
            ppc_put(t, ",%u", (unsigned)(op->disp >> 8) & 3u);
        break;
    default: t->ok = 0; break;
    }
}
static int ppc_alias_match(const cdisasm_ppc_alias *a, const cdisasm_ppc_instruction *in)
{
    const cdisasm_ppc_operand *p = in->operand;
    if (!a->preferred || a->base_name_id != in->name_id) return 0;
    switch (a->kind) {
    case CDISASM_PPC_ALIAS_WCLR:
        /* Original A2 UM v1.3 p512: L0/1 ignores the address in execution,
         * but only zero address fields can be omitted in exact output. */
        return in->operand_count == 2 && p[1].type == CDISASM_PPC_OP_MEMX &&
            (a->param == 2 ? p[0].value == 2 :
             a->param == 0 && p[0].value < 2 && !p[1].base && !p[1].index);
    case CDISASM_PPC_ALIAS_ESYNC:
        /* EREF Rev.1 6-352 / TableB-36: E!=0 ignores L in execution,
         * but the alias may discard L only when it reproduces its bits. */
        return in->cpu_id == CDISASM_PPC_CPU_E6500 && a->param == 1 &&
            in->operand_count == 2 && p[1].value > 0 && p[1].value < 16 &&
            p[0].value == ((~((unsigned)p[1].value >> 1)) & 1u);
    case CDISASM_PPC_ALIAS_VSXPERM:
        /* ISA3.1C BookI p922: duplicate-source aliases must preserve XA/XB. */
        if (in->operand_count != 4) return 0;
        if (a->param == 4) return p[1].value == p[2].value && (p[3].value == 0 || p[3].value == 3);
        if (a->param == 2) return p[1].value == p[2].value && p[3].value == 2;
        return (a->param == 0 || a->param == 3) && p[3].value == a->param;
    case CDISASM_PPC_ALIAS_TLBWORD:
        return in->cpu_id == CDISASM_PPC_CPU_403GCX && in->operand_count == 3 && p[2].value == a->param;
    case CDISASM_PPC_ALIAS_TLBILX:
        /* EREF Rev.1 Table6-18: suppress only encoded zero addresses. */
        return in->operand_count == 2 && p[1].type == CDISASM_PPC_OP_MEMX &&
            p[0].value == a->param && (a->param == 3 || (!p[1].base && !p[1].index));
    case CDISASM_PPC_ALIAS_QPXLOGICAL:
        /* QPX Architecture (May 9 2012), section4.9 p42. Keep the base
         * spelling whenever a shorthand would discard an encoded source. */
        if (in->operand_count != 4 || p[3].value != a->param) return 0;
        if (a->param == 0 || a->param == 15)
            return p[0].value == p[1].value && p[1].value == p[2].value;
        if (a->param == 5 || a->param == 10) return p[1].value == p[2].value;
        return 1;
    case CDISASM_PPC_ALIAS_MEMIMM:
        return in->operand_count == 2 && p[0].type == CDISASM_PPC_OP_MEMX && p[1].value == a->param;
    case CDISASM_PPC_ALIAS_CONSTPAIR:
        /* Server SC and embedded elemental E occupy different fields. */
        return in->operand_count == 2 && p[1].width == 2 &&
            p[0].value == (a->param & 7u) && p[1].value == (a->param >> 3);
    case CDISASM_PPC_ALIAS_CONST:
        return (in->operand_count == 1 || in->operand_count == 2) && p[0].value == a->param &&
            (in->operand_count == 1 || p[1].value == 0);
    case CDISASM_PPC_ALIAS_PREPEND:
        return (in->operand_count == 2 || in->operand_count == 3) && p[0].value == a->param;
    case CDISASM_PPC_ALIAS_TRAP:
        return in->operand_count == 3 && p[0].value == a->param && !p[1].value && !p[2].value;
    case CDISASM_PPC_ALIAS_ROTATE32EXPR: return 0; /* source-only expression aliases */
    case CDISASM_PPC_ALIAS_LIL: return in->operand_count == 2 && !p[1].base;
    case CDISASM_PPC_ALIAS_SUBIMM: return 0; /* source-only; retain canonical ai */
    case CDISASM_PPC_ALIAS_LI: return in->operand_count == 3 && p[1].value == 0;
    case CDISASM_PPC_ALIAS_DUP: case CDISASM_PPC_ALIAS_CRDUP:
        return in->operand_count == 3 && p[1].value == p[2].value;
    case CDISASM_PPC_ALIAS_CRSET:
        return in->operand_count == 3 && p[0].value == p[1].value && p[1].value == p[2].value;
    case CDISASM_PPC_ALIAS_SPR_FROM:
        return in->operand_count == 2 && p[1].value == a->param &&
            cdisasm_ppc_spr_from_name(in->cpu_id,a->name+2,0) == (int32_t)a->param;
    case CDISASM_PPC_ALIAS_TBR_FROM:
        return in->operand_count == 2 && p[1].value == a->param;
    case CDISASM_PPC_ALIAS_SPR_TO: return in->operand_count == 2 && p[0].value == a->param &&
        cdisasm_ppc_spr_from_name(in->cpu_id,a->name+2,1) == (int32_t)a->param;
    case CDISASM_PPC_ALIAS_ROTATE:
        if (in->operand_count != 5) return 0;
        switch (a->param) {
        case 0: return p[3].value == 0 && p[4].value == 31 - p[2].value;
        case 1: return p[3].value > 0 && p[4].value == 31 && p[2].value == 32 - p[3].value;
        case 2: return p[2].value == 0 && p[4].value == 31;
        case 3: return p[3].value == 0 && p[4].value == 31;
        default: return 0;
        }
    case CDISASM_PPC_ALIAS_PREFIXLI:
        return in->operand_count == 4 && !p[1].value && p[3].value == a->param;
    case CDISASM_PPC_ALIAS_ROTATE64:
        if (in->operand_count != 4) return 0;
        switch (a->param) {
        case 0: return p[3].value == 63 - p[2].value;
        case 1: return p[3].value && p[2].value == 64 - p[3].value;
        case 2: return !p[2].value;
        case 3: return !p[2].value;
        case 4: case 6: return !p[3].value;
        default: return 0;
        }
    case CDISASM_PPC_ALIAS_BCOND:
        return in->operand_count == 3 && in->bo == a->param / 32u && (in->bi & 3u) == (a->param & 3u);
    case CDISASM_PPC_ALIAS_BCOUNT: return in->operand_count == 3 && in->bo == a->param && in->bi == 0;
    case CDISASM_PPC_ALIAS_BREG: return (in->operand_count == 3 || in->operand_count == 2) && in->bo == 20 && in->bi == 0;
    case CDISASM_PPC_ALIAS_BREGCOND:
        return (in->operand_count == 3 || in->operand_count == 2) && in->bo == a->param / 32u && (in->bi & 3u) == (a->param & 3u);
    case CDISASM_PPC_ALIAS_BREGTEST: return (in->operand_count == 3 || in->operand_count == 2) && in->bo == a->param;
    case CDISASM_PPC_ALIAS_BREGCOUNT: return (in->operand_count == 3 || in->operand_count == 2) && in->bo == a->param && in->bi == 0;
    case CDISASM_PPC_ALIAS_BTEST: return in->operand_count == 3 && in->bo == a->param;
    case CDISASM_PPC_ALIAS_NOP:
        return in->operand_count == (a->param == 2 ? 2 : 3) && !p[0].value && !p[1].value && (a->param == 2 || !p[2].value);
    default: return 0;
    }
}
static void ppc_suffix(ppc_text *t, const cdisasm_ppc_instruction *in, const char *name)
{
    if (in->lk) ppc_put(t, "l");
    if (in->aa) ppc_put(t, "a");
    if (in->oe) ppc_put(t, "o");
    if (in->rc && name[strlen(name) - 1] != '.') ppc_put(t, ".");
}
static void ppc_alias_operands(ppc_text *t, const cdisasm_ppc_alias *a, const cdisasm_ppc_instruction *in)
{
    const cdisasm_ppc_operand *p = in->operand;
    switch (a->kind) {
    case CDISASM_PPC_ALIAS_WCLR:
        ppc_put(t, " "); ppc_operand(t, &p[a->param == 2 ? 1 : 0]); break;
    case CDISASM_PPC_ALIAS_ESYNC:
        ppc_put(t, " "); ppc_operand(t, &p[1]); break;
    case CDISASM_PPC_ALIAS_VSXPERM:
        ppc_put(t, " "); ppc_operand(t, &p[0]); ppc_put(t, ","); ppc_operand(t, &p[1]);
        if (a->param == 4) ppc_put(t, ",%u", (unsigned)(p[3].value / 3));
        else if (a->param != 2) { ppc_put(t, ","); ppc_operand(t, &p[2]); }
        break;
    case CDISASM_PPC_ALIAS_TLBILX:
        if (a->param == 3) { ppc_put(t, " "); ppc_operand(t, &p[1]); }
        break;
    case CDISASM_PPC_ALIAS_QPXLOGICAL:
        ppc_put(t, " "); ppc_operand(t, &p[0]);
        if (a->param == 0 || a->param == 15) break;
        ppc_put(t, ","); ppc_operand(t, &p[1]);
        if (a->param == 5 || a->param == 10) break;
        ppc_put(t, ","); ppc_operand(t, &p[2]); break;
    case CDISASM_PPC_ALIAS_MEMIMM:
        ppc_put(t, " "); ppc_operand(t, &p[0]); break;
    case CDISASM_PPC_ALIAS_PREPEND:
        ppc_put(t, " "); ppc_operand(t, &p[1]);
        if (in->operand_count == 3) { ppc_put(t, ","); ppc_operand(t, &p[2]); }
        break;
    case CDISASM_PPC_ALIAS_LIL:
        ppc_put(t, " "); ppc_operand(t, &p[0]); ppc_put(t, ",%lld", (long long)p[1].disp); break;
    case CDISASM_PPC_ALIAS_LI:
        ppc_put(t, " "); ppc_operand(t, &p[0]); ppc_put(t, ","); ppc_operand(t, &p[2]); break;
    case CDISASM_PPC_ALIAS_TLBWORD:
    case CDISASM_PPC_ALIAS_DUP: case CDISASM_PPC_ALIAS_CRDUP:
        ppc_put(t, " "); ppc_operand(t, &p[0]); ppc_put(t, ","); ppc_operand(t, &p[1]); break;
    case CDISASM_PPC_ALIAS_CRSET: case CDISASM_PPC_ALIAS_SPR_FROM: case CDISASM_PPC_ALIAS_TBR_FROM:
        ppc_put(t, " "); ppc_operand(t, &p[0]); break;
    case CDISASM_PPC_ALIAS_SPR_TO:
        ppc_put(t, " "); ppc_operand(t, &p[1]); break;
    case CDISASM_PPC_ALIAS_ROTATE:
        ppc_put(t, " "); ppc_operand(t, &p[0]); ppc_put(t, ","); ppc_operand(t, &p[1]);
        ppc_put(t, ",%lld", (long long)((a->param == 1 || a->param == 2) ? p[3].value : p[2].value)); break;
    case CDISASM_PPC_ALIAS_PREFIXLI:
        ppc_put(t, " "); ppc_operand(t, &p[0]); ppc_put(t, ","); ppc_operand(t, &p[2]); break;
    case CDISASM_PPC_ALIAS_ROTATE64:
        ppc_put(t, " "); ppc_operand(t, &p[0]); ppc_put(t, ","); ppc_operand(t, &p[1]); ppc_put(t, ",");
        if (a->param == 6) ppc_operand(t, &p[2]);
        else ppc_put(t, "%lld", (long long)(a->param == 1 || a->param == 2 ? p[3].value :
            a->param == 3 ? 63 - p[3].value : p[2].value));
        break;
    case CDISASM_PPC_ALIAS_BCOND:
        ppc_put(t, " ");
        if (in->bi >= 4) { ppc_reg(t, "cr", in->bi / 4u, 0); ppc_put(t, ","); }
        ppc_operand(t, &p[2]); break;
    case CDISASM_PPC_ALIAS_BREGCOND:
        if (in->bi >= 4 || in->bh) { ppc_put(t, " "); ppc_reg(t,"cr",in->bi/4u,0); }
        if (in->bh) ppc_put(t,",%u",in->bh);
        break;
    case CDISASM_PPC_ALIAS_BREGTEST:
        ppc_put(t," "); ppc_operand(t,&p[1]);
        if (in->bh) ppc_put(t,",%u",in->bh);
        break;
    case CDISASM_PPC_ALIAS_BREG: case CDISASM_PPC_ALIAS_BREGCOUNT:
        if (in->bh) ppc_put(t," %u",in->bh);
        break;
    case CDISASM_PPC_ALIAS_BCOUNT: ppc_put(t, " "); ppc_operand(t, &p[2]); break;
    case CDISASM_PPC_ALIAS_BTEST:
        ppc_put(t, " "); ppc_operand(t, &p[1]); ppc_put(t, ","); ppc_operand(t, &p[2]); break;
    default: break;
    }
}
size_t CDISASM_CALL cdisasm_ppc_format_operand(const cdisasm_ppc_instruction *in, uint32_t index, uint32_t options, char *text, size_t capacity)
{
    ppc_text t;
    if (!text || !capacity) return 0;
    text[0] = 0;
    if (!in || index >= in->operand_count || in->operand_count > CDISASM_PPC_MAX_OPERANDS || (options & ~3u)) return 0;
    t.out = text; t.capacity = capacity; t.length = 0; t.ok = 1; t.named = (options & CDISASM_PPC_FORMAT_REGISTER_NAMES) != 0;
    ppc_operand(&t, &in->operand[index]);
    if (!t.ok) { text[0] = 0; return 0; }
    return t.length;
}
size_t CDISASM_CALL cdisasm_ppc_format(const cdisasm_ppc_instruction *in, uint32_t options, char *text, size_t capacity)
{
    const char *name;
    const cdisasm_ppc_alias *chosen = NULL;
    ppc_text t;
    uint32_t i;
    if (!text || !capacity) return 0;
    text[0] = 0;
    if (!in || !in->length || in->operand_count > CDISASM_PPC_MAX_OPERANDS || (options & ~3u)) return 0;
    name = cdisasm_ppc_name(in->name_id);
    if (!name) return 0;
    if (!(options & CDISASM_PPC_FORMAT_BASE_MNEMONICS)) {
        const cdisasm_ppc_alias *aliases = cdisasm_ppc_aliases();
        for (i = 0; i < cdisasm_ppc_alias_count(); ++i)
            if (ppc_alias_match(&aliases[i], in)) { chosen = &aliases[i]; name = chosen->name; break; }
    }
    t.out = text; t.capacity = capacity; t.length = 0; t.ok = 1; t.named = (options & CDISASM_PPC_FORMAT_REGISTER_NAMES) != 0;
    {
        size_t length = strlen(name);
        char hint = length && (name[length-1] == '+' || name[length-1] == '-') ? name[--length] : 0;
        ppc_put(&t,"%.*s",(int)length,name); ppc_suffix(&t,in,name);
        if (hint) ppc_put(&t,"%c",hint);
    }
    if (chosen) ppc_alias_operands(&t, chosen, in);
    else for (i = 0; i < in->operand_count; ++i) {
        if (!strcmp(name,"pnop") && !in->operand[0].value) break;
        if (!strcmp(name,"sync") && !in->operand[0].value && !in->operand[1].value) break;
        ppc_put(&t, i ? "," : " "); ppc_operand(&t, &in->operand[i]); }
    if (!t.ok) { text[0] = 0; return 0; }
    return t.length;
}
