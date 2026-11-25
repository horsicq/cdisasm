/* Motorola-syntax formatter for cdisasm_m68k_instruction.
 *
 * move.l (8,a0),d1   moveq #-1,d0   bra.w $1006   lea ($1006,pc),a0
 * ([16.w,a0,d1.l*4],-4.w)   ($1234).w   #$12345678   d0-d3/a0/a5-a7
 * Numbers: displacements in signed decimal; immediates in decimal below 10
 * and $hex otherwise (signed decimal for moveq, addq, link, k-factors);
 * addresses and PC-relative targets in $hex. */
#include "cdisasm/cdisasm_m68k.h"

#include <stdio.h>
#include <string.h>

typedef struct m68k_text {
    char *out;
    size_t capacity;
    size_t length;
    int ok;
    int prefix; /* %reg spelling */
} m68k_text;

static void m68k_put(m68k_text *t, const char *s)
{
    size_t n = strlen(s);
    if (!t->ok) return;
    if (t->length + n + 1 > t->capacity) {
        t->ok = 0;
        return;
    }
    memcpy(t->out + t->length, s, n + 1);
    t->length += n;
}

static void m68k_putf(m68k_text *t, const char *format, unsigned long long value)
{
    char buffer[64];
    snprintf(buffer, sizeof(buffer), format, value);
    m68k_put(t, buffer);
}

static void m68k_hex(m68k_text *t, uint64_t value)
{
    m68k_putf(t, t->prefix ? "0x%llx" : "$%llx", (unsigned long long)value);
}

static void m68k_signed(m68k_text *t, int64_t value)
{
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%lld", (long long)value);
    m68k_put(t, buffer);
}

static void m68k_number(m68k_text *t, uint64_t value)
{
    if (value < 10) m68k_putf(t, "%llu", (unsigned long long)value);
    else m68k_hex(t, value);
}

static void m68k_reg_prefix(m68k_text *t)
{
    if (t->prefix) m68k_put(t, "%");
}

static void m68k_named(m68k_text *t, const char *name)
{
    m68k_reg_prefix(t);
    m68k_put(t, name);
}

static void m68k_dreg(m68k_text *t, unsigned reg)
{
    m68k_reg_prefix(t);
    m68k_putf(t, "d%llu", reg & 7u);
}

static void m68k_areg(m68k_text *t, unsigned reg)
{
    m68k_reg_prefix(t);
    if ((reg & 7u) == 7u) m68k_put(t, "sp");
    else m68k_putf(t, "a%llu", reg & 7u);
}

static void m68k_rreg(m68k_text *t, unsigned reg)
{
    if (reg & 8u) m68k_areg(t, reg);
    else m68k_dreg(t, reg);
}

static void m68k_index(m68k_text *t, const cdisasm_m68k_operand *op)
{
    m68k_rreg(t, op->reg2);
    m68k_put(t, op->index_size == 4 ? ".l" : ".w");
    if (op->scale > 1) m68k_putf(t, "*%llu", op->scale);
}

static void m68k_sized(m68k_text *t, int64_t value, unsigned size)
{
    m68k_signed(t, value);
    m68k_put(t, size == 4 ? ".l" : ".w");
}

/* Modes 6 and 7.3, brief and full format. */
static void m68k_indexed(m68k_text *t, const cdisasm_m68k_operand *op, int pc)
{
    int base_suppressed = (op->ext_flags & CDISASM_M68K_EXT_BASE_SUPPRESS) != 0;
    int index_suppressed = (op->ext_flags & CDISASM_M68K_EXT_INDEX_SUPPRESS) != 0;
    int indirect = (op->ext_flags & CDISASM_M68K_EXT_MEM_INDIRECT) != 0;
    int post = (op->ext_flags & CDISASM_M68K_EXT_POST_INDEXED) != 0;
    int first = 1;
    if (!(op->ext_flags & CDISASM_M68K_EXT_FULL)) {
        m68k_put(t, "(");
        if (pc) m68k_hex(t, op->imm);
        else m68k_signed(t, op->disp);
        m68k_put(t, ",");
        if (pc) m68k_named(t, "pc");
        else m68k_areg(t, op->reg);
        m68k_put(t, ",");
        m68k_index(t, op);
        m68k_put(t, ")");
        return;
    }
    m68k_put(t, indirect ? "([" : "(");
    if (op->bd_size > 1) {
        if (pc && !base_suppressed) {
            m68k_hex(t, op->imm);
            m68k_put(t, op->bd_size == 4 ? ".l" : ".w");
        } else {
            m68k_sized(t, op->disp, op->bd_size);
        }
        first = 0;
    }
    if (!first) m68k_put(t, ",");
    if (base_suppressed) m68k_named(t, pc ? "zpc" : "z");
    if (base_suppressed && !pc) m68k_putf(t, "a%llu", op->reg & 7u);
    else if (!base_suppressed && pc) m68k_named(t, "pc");
    else if (!base_suppressed) m68k_areg(t, op->reg);
    if (!index_suppressed && !post) {
        m68k_put(t, ",");
        m68k_index(t, op);
    }
    if (indirect) {
        m68k_put(t, "]");
        if (!index_suppressed && post) {
            m68k_put(t, ",");
            m68k_index(t, op);
        }
        if (op->od_size > 1) {
            m68k_put(t, ",");
            m68k_sized(t, op->outer, op->od_size);
        }
    }
    m68k_put(t, ")");
}

static void m68k_immediate(m68k_text *t, const cdisasm_m68k_operand *op, char size)
{
    m68k_put(t, "#");
    switch (size) {
        case 's': m68k_putf(t, t->prefix ? "0x%08llx" : "$%08llx", op->imm & 0xffffffffu); return;
        case 'd': m68k_putf(t, t->prefix ? "0x%016llx" : "$%016llx", (unsigned long long)op->imm); return;
        case 'x':
        case 'p':
            m68k_putf(t, t->prefix ? "0x%08llx" : "$%08llx", op->imm_high);
            m68k_putf(t, "%016llx", (unsigned long long)op->imm);
            return;
        default: m68k_number(t, op->imm);
    }
}

static void m68k_ea(m68k_text *t, const cdisasm_m68k_operand *op, char size)
{
    switch (op->ea_mode) {
        case CDISASM_M68K_EA_DN: m68k_dreg(t, op->reg); break;
        case CDISASM_M68K_EA_AN: m68k_areg(t, op->reg); break;
        case CDISASM_M68K_EA_IND:
            m68k_put(t, "(");
            m68k_areg(t, op->reg);
            m68k_put(t, ")");
            break;
        case CDISASM_M68K_EA_POSTINC:
            m68k_put(t, "(");
            m68k_areg(t, op->reg);
            m68k_put(t, ")+");
            break;
        case CDISASM_M68K_EA_PREDEC:
            m68k_put(t, "-(");
            m68k_areg(t, op->reg);
            m68k_put(t, ")");
            break;
        case CDISASM_M68K_EA_DISP:
            m68k_put(t, "(");
            m68k_signed(t, op->disp);
            m68k_put(t, ",");
            m68k_areg(t, op->reg);
            m68k_put(t, ")");
            break;
        case CDISASM_M68K_EA_INDEX: m68k_indexed(t, op, 0); break;
        case CDISASM_M68K_EA_ABS_W:
            m68k_put(t, "(");
            m68k_hex(t, op->imm & 0xffffu);
            m68k_put(t, ").w");
            break;
        case CDISASM_M68K_EA_ABS_L:
            m68k_put(t, "(");
            m68k_hex(t, op->imm & 0xffffffffu);
            m68k_put(t, ").l");
            break;
        case CDISASM_M68K_EA_PC_DISP:
            m68k_put(t, "(");
            m68k_hex(t, op->imm);
            m68k_put(t, ",");
            m68k_named(t, "pc");
            m68k_put(t, ")");
            break;
        case CDISASM_M68K_EA_PC_INDEX: m68k_indexed(t, op, 1); break;
        case CDISASM_M68K_EA_IMM:
            /* fmovem.l #imm,<list> carries one long per register. */
            m68k_immediate(t, op, size == 'l' && op->size == 8 ? 'd' : size == 'l' && op->size == 12 ? 'x' : size);
            break;
        default: t->ok = 0;
    }
}

static void m68k_list(m68k_text *t, uint32_t mask, unsigned count, const char *prefix)
{
    unsigned i = 0;
    int first = 1;
    if (!mask) {
        m68k_put(t, "#0");
        return;
    }
    while (i < count) {
        unsigned j;
        if (!(mask & (1u << i))) {
            ++i;
            continue;
        }
        j = i;
        /* Ranges stay inside one register bank (d0-d7, a0-a7). */
        while (j + 1 < count && (mask & (1u << (j + 1))) && ((j + 1) & 7u)) ++j;
        if (!first) m68k_put(t, "/");
        first = 0;
        m68k_reg_prefix(t);
        if (prefix) m68k_put(t, prefix);
        else m68k_put(t, i < 8 ? "d" : "a");
        m68k_putf(t, "%llu", i & 7u);
        if (j > i) {
            m68k_put(t, "-");
            m68k_reg_prefix(t);
            if (prefix) m68k_put(t, prefix);
            else m68k_put(t, j < 8 ? "d" : "a");
            m68k_putf(t, "%llu", j & 7u);
        }
        i = j + 1;
    }
}

static void m68k_bitfield_part(m68k_text *t, unsigned value, int is_register, int width)
{
    if (is_register) m68k_dreg(t, value & 7u);
    else m68k_putf(t, "%llu", width && value == 0 ? 32u : value);
}

static void m68k_operand(m68k_text *t, const cdisasm_m68k_instruction *in, const cdisasm_m68k_operand *op)
{
    static const char *const caches[4] = {"nc", "dc", "ic", "bc"};
    static const char *const mmu[7] = {"tc", "srp", "crp", "mmusr", "tt0", "tt1", "val"};
    switch (op->type) {
        case CDISASM_M68K_OP_EA: m68k_ea(t, op, in->size); break;
        case CDISASM_M68K_OP_DREG: m68k_dreg(t, op->reg); break;
        case CDISASM_M68K_OP_AREG: m68k_areg(t, op->reg); break;
        case CDISASM_M68K_OP_RREG: m68k_rreg(t, op->reg); break;
        case CDISASM_M68K_OP_PREDEC:
            m68k_put(t, "-(");
            m68k_areg(t, op->reg);
            m68k_put(t, ")");
            break;
        case CDISASM_M68K_OP_POSTINC:
            m68k_put(t, "(");
            m68k_areg(t, op->reg);
            m68k_put(t, ")+");
            break;
        case CDISASM_M68K_OP_IND:
            m68k_put(t, "(");
            m68k_areg(t, op->reg);
            m68k_put(t, ")");
            break;
        case CDISASM_M68K_OP_DISP:
            m68k_put(t, "(");
            m68k_signed(t, op->disp);
            m68k_put(t, ",");
            m68k_areg(t, op->reg);
            m68k_put(t, ")");
            break;
        case CDISASM_M68K_OP_IMM: m68k_immediate(t, op, in->size); break;
        case CDISASM_M68K_OP_IMM_B:
        case CDISASM_M68K_OP_IMM_W:
        case CDISASM_M68K_OP_IMM_L:
        case CDISASM_M68K_OP_U16:
        case CDISASM_M68K_OP_U32:
        case CDISASM_M68K_OP_ROM:
            m68k_put(t, "#");
            m68k_number(t, op->imm);
            break;
        case CDISASM_M68K_OP_QUICK:
        case CDISASM_M68K_OP_SQ8:
        case CDISASM_M68K_OP_S16:
        case CDISASM_M68K_OP_S32:
        case CDISASM_M68K_OP_U4:
        case CDISASM_M68K_OP_U3:
        case CDISASM_M68K_OP_BITIMM:
        case CDISASM_M68K_OP_MASK:
        case CDISASM_M68K_OP_LEVEL:
            m68k_put(t, "#");
            m68k_signed(t, (int64_t)op->imm);
            break;
        case CDISASM_M68K_OP_CCR: m68k_named(t, "ccr"); break;
        case CDISASM_M68K_OP_SR: m68k_named(t, "sr"); break;
        case CDISASM_M68K_OP_USP: m68k_named(t, "usp"); break;
        case CDISASM_M68K_OP_BR8:
        case CDISASM_M68K_OP_BR16:
        case CDISASM_M68K_OP_BR32: m68k_hex(t, op->imm); break;
        case CDISASM_M68K_OP_RLIST: m68k_list(t, op->value, 16, NULL); break;
        case CDISASM_M68K_OP_CTL: {
            const char *name = cdisasm_m68k_control_register_name(op->value);
            if (!name) t->ok = 0;
            else m68k_named(t, name);
            break;
        }
        case CDISASM_M68K_OP_BITFIELD:
            m68k_put(t, "{");
            m68k_bitfield_part(t, op->value & 0x1fu, (op->value >> 16) & 1u, 0);
            m68k_put(t, ":");
            m68k_bitfield_part(t, (op->value >> 8) & 0x1fu, (op->value >> 17) & 1u, 1);
            m68k_put(t, "}");
            break;
        case CDISASM_M68K_OP_PAIR:
        case CDISASM_M68K_OP_DPAIR:
            m68k_dreg(t, op->reg);
            m68k_put(t, ":");
            m68k_dreg(t, op->reg2);
            break;
        case CDISASM_M68K_OP_RPAIR:
            m68k_put(t, "(");
            m68k_rreg(t, op->reg);
            m68k_put(t, "):(");
            m68k_rreg(t, op->reg2);
            m68k_put(t, ")");
            break;
        case CDISASM_M68K_OP_FPREG:
            m68k_reg_prefix(t);
            m68k_putf(t, "fp%llu", op->reg & 7u);
            break;
        case CDISASM_M68K_OP_FPCTL: {
            int first = 1;
            if (op->value & 4u) {
                m68k_named(t, "fpcr");
                first = 0;
            }
            if (op->value & 2u) {
                if (!first) m68k_put(t, "/");
                m68k_named(t, "fpsr");
                first = 0;
            }
            if (op->value & 1u) {
                if (!first) m68k_put(t, "/");
                m68k_named(t, "fpiar");
            }
            break;
        }
        case CDISASM_M68K_OP_FPLIST:
        case CDISASM_M68K_OP_FPLISTR: m68k_list(t, op->value, 8, "fp"); break;
        case CDISASM_M68K_OP_FPDYN: m68k_dreg(t, op->reg); break;
        case CDISASM_M68K_OP_FSC:
            m68k_reg_prefix(t);
            m68k_putf(t, "fp%llu", op->reg & 7u);
            m68k_put(t, ":");
            m68k_reg_prefix(t);
            m68k_putf(t, "fp%llu", op->reg2 & 7u);
            break;
        case CDISASM_M68K_OP_KFAC:
            m68k_put(t, "{#");
            m68k_signed(t, (int64_t)op->imm);
            m68k_put(t, "}");
            break;
        case CDISASM_M68K_OP_KDYN:
            m68k_put(t, "{");
            m68k_dreg(t, op->reg);
            m68k_put(t, "}");
            break;
        case CDISASM_M68K_OP_CACHE: m68k_put(t, caches[op->value & 3u]); break;
        case CDISASM_M68K_OP_ABSL:
            m68k_put(t, "(");
            m68k_hex(t, op->imm);
            m68k_put(t, ").l");
            break;
        case CDISASM_M68K_OP_MMU:
            if (op->reg < 7) m68k_named(t, mmu[op->reg]);
            else t->ok = 0;
            break;
        case CDISASM_M68K_OP_CFCTL: {
            const char *name = cdisasm_m68k_cf_control_register_name(op->value);
            if (!name) t->ok = 0;
            else m68k_named(t, name);
            break;
        }
        case CDISASM_M68K_OP_MACREG:
            /* Ry.u / Rx.l, shift factor attached to Rx (CFPRM: Ry,RxSF). */
            m68k_rreg(t, op->reg);
            if ((op->value & 3u) < 2u) m68k_put(t, (op->value & 3u) ? ".u" : ".l");
            if (((op->value >> 4) & 3u) == 1u) m68k_put(t, "<<");
            else if (((op->value >> 4) & 3u) == 3u) m68k_put(t, ">>");
            else if ((op->value >> 4) & 3u) t->ok = 0;
            break;
        case CDISASM_M68K_OP_MACMASK: m68k_put(t, "&"); break;
        case CDISASM_M68K_OP_ACC:
            m68k_reg_prefix(t);
            m68k_putf(t, "acc%llu", op->reg & 3u);
            break;
        case CDISASM_M68K_OP_MACCTL: {
            static const char *const mac[5] = {"acc", "macsr", "mask", "accext01", "accext23"};
            if (op->reg < 5) m68k_named(t, mac[op->reg]);
            else t->ok = 0;
            break;
        }
        case CDISASM_M68K_OP_Q3:
            m68k_put(t, "#");
            m68k_signed(t, (int64_t)op->imm);
            break;
        case CDISASM_M68K_OP_FC:
            if (op->reg == 0) m68k_named(t, "sfc");
            else if (op->reg == 1) m68k_named(t, "dfc");
            else if (op->reg == 2) m68k_dreg(t, op->reg2);
            else {
                m68k_put(t, "#");
                m68k_signed(t, (int64_t)op->imm);
            }
            break;
        default: t->ok = 0;
    }
}

/* Bit fields, k-factors and the MAC mask flag are written directly after the EA operand. */
static int m68k_attached(unsigned type)
{
    return type == CDISASM_M68K_OP_BITFIELD || type == CDISASM_M68K_OP_KFAC || type == CDISASM_M68K_OP_KDYN || type == CDISASM_M68K_OP_MACMASK;
}

size_t CDISASM_CALL cdisasm_m68k_format_operand(const cdisasm_m68k_instruction *instruction, uint32_t index, uint32_t options, char *text, size_t capacity)
{
    m68k_text t;
    if (!instruction || !text || !capacity || index >= instruction->operand_count) return 0;
    t.out = text;
    t.capacity = capacity;
    t.length = 0;
    t.ok = 1;
    t.prefix = (options & CDISASM_M68K_FORMAT_REGISTER_PREFIX) != 0;
    text[0] = 0;
    m68k_operand(&t, instruction, &instruction->operand[index]);
    if (!t.ok) {
        text[0] = 0;
        return 0;
    }
    return t.length;
}

size_t CDISASM_CALL cdisasm_m68k_format(const cdisasm_m68k_instruction *instruction, uint32_t options, char *text, size_t capacity)
{
    m68k_text t;
    const char *name;
    unsigned i;
    if (!instruction || !text || !capacity || !instruction->length) return 0;
    name = cdisasm_m68k_name(instruction->name_id);
    if (!name) return 0;
    t.out = text;
    t.capacity = capacity;
    t.length = 0;
    t.ok = 1;
    t.prefix = (options & CDISASM_M68K_FORMAT_REGISTER_PREFIX) != 0;
    text[0] = 0;
    m68k_put(&t, name);
    if (instruction->suffix && instruction->size) {
        char suffix[3] = {'.', instruction->size, 0};
        m68k_put(&t, suffix);
    }
    for (i = 0; i < instruction->operand_count; ++i) {
        if (!m68k_attached(instruction->operand[i].type)) m68k_put(&t, i ? "," : " ");
        m68k_operand(&t, instruction, &instruction->operand[i]);
    }
    if (!t.ok) {
        text[0] = 0;
        return 0;
    }
    return t.length;
}
