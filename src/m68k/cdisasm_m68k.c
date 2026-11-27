/* Copyright (c) 2026 hors<horsicq@gmail.com> */

/* Motorola 68000-family decoder: table-driven from the generated forms. */
#include "cdisasm/cdisasm_m68k.h"

#include <string.h>

#include "generated/m68k_forms.inc"

#define F(name) CDISASM_M68K_FEATURE_##name

/* 68000 integer set plus movep, shared by every member. */
#define M68K_COMMON (F(BASE) | F(MOVEP))
/* 68020-class integer additions present on every 68020+ CPU. */
#define M68K_020_INT (F(010) | F(EA020) | F(MULL) | F(LINKL) | F(TRAPCC) | F(BCCL) | F(FULLEA) | F(SCALE) | F(CAS) | F(BITFIELD) | F(PACK))
/* Removed on the 68060 (emulated by software there). */
#define M68K_PRE060 (F(MUL64) | F(CHK2) | F(CAS2) | F(MOVEP))
/* ColdFire ISA levels (CFPRM 3.1; GNU's isa-* machine names). */
#define CF_A (F(CF) | F(CFDIV))
#define CF_B (CF_A | F(CFB))

static const struct {
    const char *name;
    uint64_t features;
} m68k_cpus[CDISASM_M68K_CPU_COUNT] = {
    {"any", CDISASM_M68K_FEATURE_ALL_68K},
    {"68000", M68K_COMMON},
    {"68008", M68K_COMMON},
    {"68010", M68K_COMMON | F(010)},
    {"68020", M68K_COMMON | M68K_020_INT | M68K_PRE060 | F(CALLM)},
    {"68030", M68K_COMMON | M68K_020_INT | M68K_PRE060 | F(MMU030)},
    {"68040", M68K_COMMON | M68K_020_INT | M68K_PRE060 | F(MOVE16) | F(CACHE040) | F(MMU040) | F(PTEST040) | F(FPU) | F(FPU040)},
    {"68lc040", M68K_COMMON | M68K_020_INT | M68K_PRE060 | F(MOVE16) | F(CACHE040) | F(MMU040) | F(PTEST040)},
    {"68ec040", M68K_COMMON | M68K_020_INT | M68K_PRE060 | F(MOVE16) | F(CACHE040)},
    {"68060", F(BASE) | M68K_020_INT | F(MOVE16) | F(CACHE040) | F(MMU040) | F(PLPA) | F(LPSTOP) | F(FPU) | F(FPU040)},
    {"68lc060", F(BASE) | M68K_020_INT | F(MOVE16) | F(CACHE040) | F(MMU040) | F(PLPA) | F(LPSTOP)},
    {"68ec060", F(BASE) | M68K_020_INT | F(MOVE16) | F(CACHE040) | F(LPSTOP)},
    {"cpu32", M68K_COMMON | F(010) | F(EA020) | F(MULL) | F(MUL64) | F(LINKL) | F(TRAPCC) | F(CHK2) | F(SCALE) | F(BGND) | F(TBL) | F(LPSTOP)},
    {"68ec020", M68K_COMMON | M68K_020_INT | M68K_PRE060 | F(CALLM)},
    {"68ec030", M68K_COMMON | M68K_020_INT | M68K_PRE060},
    {"isa-a-nodiv", F(CF)},
    {"isa-a", CF_A},
    {"isa-aplus", CF_A | F(CFAPLUS) | F(CFUSP)},
    {"isa-b-nousp", CF_B},
    {"isa-b", CF_B | F(CFUSP)},
    {"isa-c-nodiv", F(CF) | F(CFAPLUS) | F(CFB) | F(CFUSP)},
    {"isa-c", CF_B | F(CFAPLUS) | F(CFUSP)},
    {"cfv4e", CF_B | F(CFUSP) | F(MAC) | F(EMAC) | F(CFFPU)},
    {"coldfire", CDISASM_M68K_FEATURE_ALL_CF},
};

/* GNU CPU names of common ColdFire parts (gas -mcpu), their profile and units. */
static const struct {
    const char *name;
    uint32_t ordinal;
    uint64_t options;
} m68k_cf_parts[] = {
    {"5202", 15, 0},
    {"5204", 15, 0},
    {"5206", 15, 0},
    {"5206e", 16, F(MAC)},
    {"5307", 16, F(MAC)},
    {"5407", 19, F(MAC)},
    {"5249", 16, F(MAC) | F(EMAC)},
    {"528x", 17, F(MAC) | F(EMAC)},
    {"521x", 17, 0},
    {"547x", 22, 0},
    {"548x", 22, 0},
    {"5475", 22, 0},
    {"5485", 22, 0},
};

uint64_t CDISASM_CALL cdisasm_m68k_cpu_features(cdisasm_m68k_cpu_id cpu_id)
{
    uint32_t ordinal = CDISASM_CPU_ORDINAL_OF(cpu_id);
    if (CDISASM_CPU_GROUP_OF(cpu_id) != CDISASM_CPU_GROUP_M68K || ordinal >= CDISASM_M68K_CPU_COUNT) return 0;
    return m68k_cpus[ordinal].features;
}

const char *CDISASM_CALL cdisasm_m68k_cpu_name(cdisasm_m68k_cpu_id cpu_id)
{
    uint32_t ordinal = CDISASM_CPU_ORDINAL_OF(cpu_id);
    if (CDISASM_CPU_GROUP_OF(cpu_id) != CDISASM_CPU_GROUP_M68K || ordinal >= CDISASM_M68K_CPU_COUNT) return NULL;
    return m68k_cpus[ordinal].name;
}

/* Case-insensitive; ':' matches '-' (GNU spells isa-a:nodiv). */
static int m68k_name_equal(const char *a, const char *b)
{
    for (; *a && *b; ++a, ++b) {
        char x = *a >= 'A' && *a <= 'Z' ? (char)(*a + 32) : *a;
        if (x == ':') x = '-';
        if (x != *b) return 0;
    }
    return !*a && !*b;
}

cdisasm_m68k_cpu_id CDISASM_CALL cdisasm_m68k_cpu_from_name(const char *name)
{
    uint32_t i;
    if (!name) return CDISASM_CPU_UNKNOWN;
    if ((name[0] == 'm' || name[0] == 'M') && name[1] >= '0' && name[1] <= '9') ++name; /* m68020 */
    if (m68k_name_equal(name, "68k") || m68k_name_equal(name, "m68k")) return CDISASM_M68K_CPU_68000;
    for (i = 0; i < CDISASM_M68K_CPU_COUNT; ++i)
        if (m68k_name_equal(name, m68k_cpus[i].name)) return CDISASM_CPU_GROUP_M68K | i;
    if (m68k_name_equal(name, "cf")) return CDISASM_M68K_CPU_COLDFIRE;
    if ((name[0] == 'm' || name[0] == 'M') && (name[1] == 'c' || name[1] == 'C') && (name[2] == 'f' || name[2] == 'F')) name += 3; /* mcf5407 */
    for (i = 0; i < sizeof(m68k_cf_parts) / sizeof(m68k_cf_parts[0]); ++i)
        if (m68k_name_equal(name, m68k_cf_parts[i].name)) return CDISASM_CPU_GROUP_M68K | m68k_cf_parts[i].ordinal;
    return CDISASM_CPU_UNKNOWN;
}

uint32_t CDISASM_CALL cdisasm_m68k_cpu_name_options(const char *name)
{
    size_t i;
    if (!name) return 0;
    if ((name[0] == 'm' || name[0] == 'M') && (name[1] == 'c' || name[1] == 'C') && (name[2] == 'f' || name[2] == 'F')) name += 3;
    for (i = 0; i < sizeof(m68k_cf_parts) / sizeof(m68k_cf_parts[0]); ++i)
        if (m68k_name_equal(name, m68k_cf_parts[i].name)) return (uint32_t)m68k_cf_parts[i].options;
    return 0;
}

cdisasm_status CDISASM_CALL cdisasm_m68k_cpu_decode_flag_mask(cdisasm_m68k_cpu_id cpu_id, uint32_t mode, cdisasm_decode_flags *flags)
{
    (void)mode;
    if (!flags) return CDISASM_STATUS_INVALID_ARGUMENT;
    cdisasm_decode_flags_reset(flags);
    return cdisasm_m68k_cpu_name(cpu_id) ? CDISASM_STATUS_OK : CDISASM_STATUS_INVALID_ARGUMENT;
}

uint32_t CDISASM_CALL cdisasm_m68k_form_count(void)
{
    return CDISASM_M68K_FORM_COUNT;
}

const cdisasm_m68k_form *CDISASM_CALL cdisasm_m68k_forms(void)
{
    return m68k_forms;
}

const char *CDISASM_CALL cdisasm_m68k_name(uint32_t name_id)
{
    return name_id < CDISASM_M68K_NAME_COUNT ? m68k_names[name_id] : NULL;
}

uint32_t CDISASM_CALL cdisasm_m68k_ea_class_modes(uint32_t ea_class)
{
    return ea_class < CDISASM_M68K_CLASS_COUNT ? m68k_class_modes[ea_class] : 0;
}

/* movec control registers: code, name, CPUs (feature tests in m68k_ctl_valid). */
static const struct {
    uint16_t code;
    const char *name;
} m68k_ctl_names[] = {
    {0x000, "sfc"}, {0x001, "dfc"}, {0x002, "cacr"}, {0x003, "tc"},  {0x004, "itt0"}, {0x005, "itt1"},  {0x006, "dtt0"}, {0x007, "dtt1"}, {0x008, "buscr"},
    {0x800, "usp"}, {0x801, "vbr"}, {0x802, "caar"}, {0x803, "msp"}, {0x804, "isp"},  {0x805, "mmusr"}, {0x806, "urp"},  {0x807, "srp"},  {0x808, "pcr"},
};

const char *CDISASM_CALL cdisasm_m68k_control_register_name(uint32_t code)
{
    size_t i;
    for (i = 0; i < sizeof(m68k_ctl_names) / sizeof(m68k_ctl_names[0]); ++i)
        if (m68k_ctl_names[i].code == code) return m68k_ctl_names[i].name;
    return NULL;
}

/* ColdFire MOVEC Rc codes (CFPRM 8, MOVEC; which ones a part implements
 * depends on its memories and MMU; 0x800 is OTHER_A7, the inactive stack
 * pointer, printed usp as GNU does). */
static const struct {
    uint16_t code;
    const char *name;
} m68k_cf_ctl_names[] = {
    {0x002, "cacr"},    {0x003, "asid"},    {0x004, "acr0"}, {0x005, "acr1"},     {0x006, "acr2"},    {0x007, "acr3"},
    {0x008, "mmubar"},  {0x800, "usp"},     {0x801, "vbr"},  {0x80f, "pc"},       {0xc00, "rombar0"}, {0xc01, "rombar1"},
    {0xc04, "rambar0"}, {0xc05, "rambar1"}, {0xc0c, "mpcr"}, {0xc0d, "edrambar"}, {0xc0e, "secmbar"}, {0xc0f, "mbar"},
};

const char *CDISASM_CALL cdisasm_m68k_cf_control_register_name(uint32_t code)
{
    size_t i;
    for (i = 0; i < sizeof(m68k_cf_ctl_names) / sizeof(m68k_cf_ctl_names[0]); ++i)
        if (m68k_cf_ctl_names[i].code == code) return m68k_cf_ctl_names[i].name;
    return NULL;
}

/* Which movec registers a feature set implements (MC68010/020/030/040/060
 * and CPU32 user's manuals, MOVEC tables). */
static int m68k_ctl_valid(uint64_t features, uint32_t code)
{
    int is020 = (features & F(BCCL)) != 0, is040 = (features & F(CACHE040)) != 0, is060 = (features & F(PLPA)) != 0 || ((features & F(LPSTOP)) && is020);
    if ((features & CDISASM_M68K_FEATURE_ALL_68K) == CDISASM_M68K_FEATURE_ALL_68K) return cdisasm_m68k_control_register_name(code) != NULL;
    switch (code) {
        case 0x000:
        case 0x001:
        case 0x800:
        case 0x801: return 1;
        case 0x002: return is020;
        case 0x802: return is020 && !is040;
        case 0x803:
        case 0x804: return is020 && !is060;
        case 0x003:
        case 0x004:
        case 0x005:
        case 0x006:
        case 0x007:
        case 0x806:
        case 0x807: return is040;
        case 0x805: return is040 && !is060;
        case 0x008:
        case 0x808: return is060;
        default: return 0;
    }
}

typedef struct m68k_reader {
    const uint8_t *code;
    size_t size;
    size_t offset;
    uint64_t address;
} m68k_reader;

static int m68k_word(m68k_reader *reader, uint32_t *value)
{
    if (reader->offset + 2 > reader->size || reader->offset + 2 > CDISASM_M68K_MAX_LENGTH) return 0;
    *value = ((uint32_t)reader->code[reader->offset] << 8) | reader->code[reader->offset + 1];
    reader->offset += 2;
    return 1;
}

static int m68k_long(m68k_reader *reader, uint32_t *value)
{
    uint32_t high, low;
    if (!m68k_word(reader, &high) || !m68k_word(reader, &low)) return 0;
    *value = (high << 16) | low;
    return 1;
}

static uint32_t m68k_field(const uint32_t *words, const cdisasm_m68k_field *field)
{
    if (!field->width) return field->literal;
    return (words[field->word] >> field->lsb) & ((1u << field->width) - 1u);
}

static int64_t m68k_sext(uint64_t value, unsigned bits)
{
    uint64_t sign = UINT64_C(1) << (bits - 1);
    value &= (sign << 1) - 1u;
    return (int64_t)((value ^ sign) - sign);
}

static uint8_t m68k_size_bytes(char size)
{
    switch (size) {
        case 'b': return 1;
        case 'w': return 2;
        case 'l':
        case 's': return 4;
        case 'q':
        case 'd': return 8;
        case 'x':
        case 'p': return 12;
        default: return 0;
    }
}

/* Reads an immediate of `bytes` (1 = byte in a word) into the operand. */
static int m68k_immediate(m68k_reader *reader, unsigned bytes, cdisasm_m68k_operand *operand)
{
    uint32_t word, value;
    if (bytes <= 2) {
        if (!m68k_word(reader, &word)) return 0;
        operand->imm = bytes == 1 ? (word & 0xffu) : word;
        return 1;
    }
    if (bytes == 4) {
        if (!m68k_long(reader, &value)) return 0;
        operand->imm = value;
        return 1;
    }
    if (bytes == 8) {
        uint32_t high;
        if (!m68k_long(reader, &high) || !m68k_long(reader, &value)) return 0;
        operand->imm = ((uint64_t)high << 32) | value;
        return 1;
    }
    if (bytes == 12) {
        uint32_t top, mid;
        if (!m68k_long(reader, &top) || !m68k_long(reader, &mid) || !m68k_long(reader, &value)) return 0;
        operand->imm_high = top;
        operand->imm = ((uint64_t)mid << 32) | value;
        return 1;
    }
    return 0;
}

/* Brief or full extension word of modes 6 and 7.3. */
static int m68k_index_ea(m68k_reader *reader, uint64_t features, int pc, cdisasm_m68k_operand *operand)
{
    uint32_t ext, value;
    uint64_t ext_address = reader->address + reader->offset;
    if (!m68k_word(reader, &ext)) return 0;
    operand->reg2 = (uint8_t)((ext >> 12) & 15u);
    operand->index_size = (ext & 0x800u) ? 4 : 2;
    operand->scale = (uint8_t)(1u << ((ext >> 9) & 3u));
    /* ColdFire (CFPRM 2.2.7): brief format only, a long index, and scale 8
     * only on cores with an FPU. */
    if (features & F(CF)) {
        if ((ext & 0x100u) || !(ext & 0x800u) || (((ext >> 9) & 3u) == 3u && !(features & F(CFFPU)))) return 0;
        operand->disp = m68k_sext(ext & 0xffu, 8);
        if (pc) operand->imm = ext_address + (uint64_t)operand->disp;
        return 1;
    }
    /* The 68000/68008/68010 ignore bits 10-8 of the brief extension word
     * (no scale, no full format); CPU32 scales but has no full format. */
    if (!(features & F(SCALE))) {
        operand->scale = 1;
        ext &= ~0x700u;
    }
    if (!(ext & 0x100u)) {
        operand->disp = m68k_sext(ext & 0xffu, 8);
        if (pc) operand->imm = ext_address + (uint64_t)operand->disp;
        return 1;
    }
    /* Full format (68020+): BS, IS, BD size, I/IS. */
    if (!(features & F(FULLEA)) || (ext & 0x8u)) return 0;
    {
        unsigned bd = (ext >> 4) & 3u, iis = ext & 7u, is = (ext >> 6) & 1u;
        operand->ext_flags = CDISASM_M68K_EXT_FULL;
        if (ext & 0x80u) operand->ext_flags |= CDISASM_M68K_EXT_BASE_SUPPRESS;
        if (is) {
            operand->ext_flags |= CDISASM_M68K_EXT_INDEX_SUPPRESS;
            if (iis > 3) return 0;
        } else if (iis == 4) {
            return 0;
        }
        if (bd == 0) return 0;
        operand->bd_size = bd == 1 ? 1 : bd == 2 ? 2 : 4;
        if (bd == 2) {
            if (!m68k_word(reader, &value)) return 0;
            operand->disp = m68k_sext(value, 16);
        } else if (bd == 3) {
            if (!m68k_long(reader, &value)) return 0;
            operand->disp = m68k_sext(value, 32);
        }
        if (iis) {
            unsigned od = iis & 3u;
            operand->ext_flags |= CDISASM_M68K_EXT_MEM_INDIRECT;
            if (!is && (iis & 4u)) operand->ext_flags |= CDISASM_M68K_EXT_POST_INDEXED;
            operand->od_size = od == 1 ? 1 : od == 2 ? 2 : 4;
            if (od == 2) {
                if (!m68k_word(reader, &value)) return 0;
                operand->outer = m68k_sext(value, 16);
            } else if (od == 3) {
                if (!m68k_long(reader, &value)) return 0;
                operand->outer = m68k_sext(value, 32);
            }
        }
        if (is) {
            operand->index_size = 0;
            operand->scale = 1;
            operand->reg2 = 0;
        }
        if (pc && !(operand->ext_flags & CDISASM_M68K_EXT_BASE_SUPPRESS)) operand->imm = ext_address + (uint64_t)operand->disp;
    }
    return 1;
}

static int m68k_ea(m68k_reader *reader, uint64_t features, uint32_t mode, uint32_t reg, uint32_t class_modes, unsigned imm_bytes, cdisasm_m68k_operand *operand)
{
    uint32_t index = mode < 7 ? mode : reg <= 4 ? 7 + reg : 12, value;
    if (index > 11 || !(class_modes & (1u << index))) return 0;
    operand->type = CDISASM_M68K_OP_EA;
    operand->ea_mode = (uint8_t)index;
    operand->reg = (uint8_t)reg;
    operand->ext_address = (uint32_t)(reader->address + reader->offset);
    switch (index) {
        case CDISASM_M68K_EA_DISP:
            if (!m68k_word(reader, &value)) return 0;
            operand->disp = m68k_sext(value, 16);
            return 1;
        case CDISASM_M68K_EA_INDEX: return m68k_index_ea(reader, features, 0, operand);
        case CDISASM_M68K_EA_ABS_W:
            if (!m68k_word(reader, &value)) return 0;
            operand->imm = value;
            return 1;
        case CDISASM_M68K_EA_ABS_L:
            if (!m68k_long(reader, &value)) return 0;
            operand->imm = value;
            return 1;
        case CDISASM_M68K_EA_PC_DISP:
            if (!m68k_word(reader, &value)) return 0;
            operand->disp = m68k_sext(value, 16);
            operand->imm = operand->ext_address + (uint64_t)operand->disp;
            operand->imm &= UINT64_C(0xffffffff);
            return 1;
        case CDISASM_M68K_EA_PC_INDEX:
            if (!m68k_index_ea(reader, features, 1, operand)) return 0;
            operand->imm &= UINT64_C(0xffffffff);
            return 1;
        case CDISASM_M68K_EA_IMM: return imm_bytes && m68k_immediate(reader, imm_bytes, operand);
        default: return 1;
    }
}

static unsigned m68k_popcount(uint32_t value)
{
    unsigned count = 0;
    for (; value; value &= value - 1u) ++count;
    return count;
}

/* Decodes the operands of `form`; 0 when they are not encodable. */
static int m68k_try(const cdisasm_m68k_form *form, uint64_t features, m68k_reader *reader, const uint32_t *words, cdisasm_m68k_instruction *instruction)
{
    unsigned i;
    unsigned imm_bytes = form->imm_bytes;
    if (form->size == 'b' && imm_bytes) imm_bytes = 1;
    for (i = 0; i < form->constraint_count; ++i) {
        const cdisasm_m68k_constraint *c = &form->constraint[i];
        uint32_t a = m68k_field(words, &c->a), b = m68k_field(words, &c->b);
        if (c->not_equal ? a == b : a != b) return 0;
    }
    for (i = 0; i < form->operand_count; ++i) {
        const cdisasm_m68k_form_operand *spec = &form->operand[i];
        cdisasm_m68k_operand *operand = &instruction->operand[i];
        uint32_t f0 = spec->field_count > 0 ? m68k_field(words, &spec->field[0]) : 0;
        uint32_t f1 = spec->field_count > 1 ? m68k_field(words, &spec->field[1]) : 0;
        uint32_t value;
        memset(operand, 0, sizeof(*operand));
        operand->type = spec->kind;
        operand->access = spec->access;
        operand->size = m68k_size_bytes(form->size);
        switch (spec->kind) {
            case CDISASM_M68K_OP_EA: {
                unsigned bytes = imm_bytes;
                if (!bytes) {
                    /* fmovem.l #imm,<control list>: one long per register. */
                    unsigned k;
                    for (k = 0; k < form->operand_count; ++k)
                        if (form->operand[k].kind == CDISASM_M68K_OP_FPCTL) bytes = 4u * m68k_popcount(m68k_field(words, &form->operand[k].field[0]));
                }
                if (!m68k_ea(reader, features, f0, f1, m68k_class_modes[spec->ea_class], bytes, operand)) return 0;
                if (operand->ea_mode == CDISASM_M68K_EA_IMM) operand->size = (uint8_t)(bytes == 1 ? 1 : bytes);
                break;
            }
            case CDISASM_M68K_OP_DREG:
            case CDISASM_M68K_OP_AREG:
            case CDISASM_M68K_OP_PREDEC:
            case CDISASM_M68K_OP_POSTINC:
            case CDISASM_M68K_OP_IND:
            case CDISASM_M68K_OP_FPREG:
            case CDISASM_M68K_OP_FPDYN:
            case CDISASM_M68K_OP_KDYN: operand->reg = (uint8_t)f0; break;
            case CDISASM_M68K_OP_RREG: operand->reg = (uint8_t)f0; break;
            case CDISASM_M68K_OP_DISP:
                operand->reg = (uint8_t)f0;
                if (!m68k_word(reader, &value)) return 0;
                operand->disp = m68k_sext(value, 16);
                break;
            case CDISASM_M68K_OP_IMM:
                if (!m68k_immediate(reader, imm_bytes ? imm_bytes : 2, operand)) return 0;
                break;
            case CDISASM_M68K_OP_IMM_B:
                operand->size = 1;
                if (!m68k_immediate(reader, 1, operand)) return 0;
                break;
            case CDISASM_M68K_OP_IMM_W:
                operand->size = 2;
                if (!m68k_immediate(reader, 2, operand)) return 0;
                break;
            case CDISASM_M68K_OP_IMM_L:
                operand->size = 4;
                if (!m68k_immediate(reader, 4, operand)) return 0;
                break;
            case CDISASM_M68K_OP_QUICK: operand->imm = f0 ? f0 : 8; break;
            case CDISASM_M68K_OP_SQ8: operand->imm = (uint64_t)m68k_sext(f0, 8); break;
            case CDISASM_M68K_OP_U4:
            case CDISASM_M68K_OP_U3: operand->imm = f0; break;
            case CDISASM_M68K_OP_S16:
                if (!m68k_word(reader, &value)) return 0;
                operand->imm = (uint64_t)m68k_sext(value, 16);
                break;
            case CDISASM_M68K_OP_S32:
                if (!m68k_long(reader, &value)) return 0;
                operand->imm = (uint64_t)m68k_sext(value, 32);
                break;
            case CDISASM_M68K_OP_U16:
                if (!m68k_word(reader, &value)) return 0;
                operand->imm = value;
                break;
            case CDISASM_M68K_OP_U32:
                if (!m68k_long(reader, &value)) return 0;
                operand->imm = value;
                break;
            case CDISASM_M68K_OP_BITIMM:
                /* Only the low byte is the bit number (taken modulo 8 or 32). */
                if (!m68k_word(reader, &value)) return 0;
                operand->imm = value & 0xffu;
                break;
            case CDISASM_M68K_OP_CCR:
            case CDISASM_M68K_OP_SR:
            case CDISASM_M68K_OP_USP: break;
            case CDISASM_M68K_OP_BR8:
                operand->imm = (instruction->address + 2u + (uint64_t)m68k_sext(words[0] & 0xffu, 8)) & UINT64_C(0xffffffff);
                instruction->branch_target = operand->imm;
                break;
            case CDISASM_M68K_OP_BR16: {
                uint64_t base = reader->address + reader->offset;
                if (!m68k_word(reader, &value)) return 0;
                operand->imm = (base + (uint64_t)m68k_sext(value, 16)) & UINT64_C(0xffffffff);
                instruction->branch_target = operand->imm;
                break;
            }
            case CDISASM_M68K_OP_BR32: {
                uint64_t base = reader->address + reader->offset;
                if (!m68k_long(reader, &value)) return 0;
                operand->imm = (base + value) & UINT64_C(0xffffffff);
                instruction->branch_target = operand->imm;
                break;
            }
            case CDISASM_M68K_OP_RLIST: {
                /* Predecrement EAs store the mask reversed (bit 0 = A7). */
                unsigned k;
                int reversed = 0;
                for (k = 0; k < form->operand_count; ++k)
                    if (form->operand[k].kind == CDISASM_M68K_OP_EA) {
                        uint32_t mode = m68k_field(words, &form->operand[k].field[0]);
                        reversed = mode == 4;
                    }
                if (reversed) {
                    uint32_t out = 0;
                    for (k = 0; k < 16; ++k)
                        if (f0 & (1u << k)) out |= 1u << (15 - k);
                    f0 = out;
                }
                operand->value = f0;
                break;
            }
            case CDISASM_M68K_OP_CTL:
                if (!m68k_ctl_valid(features, f0)) return 0;
                operand->reg = (uint8_t)(f0 & 0xffu);
                operand->value = f0;
                break;
            case CDISASM_M68K_OP_BITFIELD: {
                uint32_t width = spec->field_count > 3 ? m68k_field(words, &spec->field[3]) : 0;
                uint32_t dw = spec->field_count > 2 ? m68k_field(words, &spec->field[2]) : 0;
                /* With Do/Dw set only bits 2-0 name the register (the CPU ignores the rest). */
                if (f0) f1 &= 7u;
                if (dw) width &= 7u;
                /* value: offset | width << 8 | Do << 16 | Dw << 17. */
                operand->value = f1 | (width << 8) | (f0 << 16) | (dw << 17);
                break;
            }
            case CDISASM_M68K_OP_PAIR:
            case CDISASM_M68K_OP_DPAIR:
            case CDISASM_M68K_OP_RPAIR:
            case CDISASM_M68K_OP_FSC:
                operand->reg = (uint8_t)f0;
                operand->reg2 = (uint8_t)f1;
                break;
            case CDISASM_M68K_OP_FPCTL:
            case CDISASM_M68K_OP_CACHE: operand->value = f0; break;
            case CDISASM_M68K_OP_FPLIST: {
                /* Control/postincrement mask: bit 7 = FP0. */
                uint32_t out = 0;
                unsigned k;
                for (k = 0; k < 8; ++k)
                    if (f0 & (0x80u >> k)) out |= 1u << k;
                operand->value = out;
                break;
            }
            case CDISASM_M68K_OP_FPLISTR: operand->value = f0; break; /* predecrement: bit 0 = FP0 */
            case CDISASM_M68K_OP_KFAC: operand->imm = (uint64_t)m68k_sext(f0, 7); break;
            case CDISASM_M68K_OP_ROM: operand->imm = f0; break;
            case CDISASM_M68K_OP_ABSL:
                if (!m68k_long(reader, &value)) return 0;
                operand->imm = value;
                break;
            case CDISASM_M68K_OP_MMU: operand->reg = (uint8_t)f0; break;
            case CDISASM_M68K_OP_FC:
                /* 00000 sfc, 00001 dfc, 01rrr Dn, 10fff #fff (68030), 1ffff #ffff (68851). */
                if (f0 == 0) operand->reg = 0;
                else if (f0 == 1) operand->reg = 1;
                else if ((f0 & 0x18u) == 0x08u) operand->reg = 2, operand->reg2 = (uint8_t)(f0 & 7u);
                else if ((f0 & 0x18u) == 0x10u || ((f0 & 0x10u) && (features & F(MMU851)))) operand->reg = 3, operand->imm = f0 & 15u;
                else return 0;
                break;
            case CDISASM_M68K_OP_MASK:
            case CDISASM_M68K_OP_LEVEL: operand->imm = f0; break;
            case CDISASM_M68K_OP_CFCTL:
                /* 0x800 is the other stack pointer of cores with a USP. */
                if (!cdisasm_m68k_cf_control_register_name(f0) || (f0 == 0x800u && !(features & F(CFUSP)))) return 0;
                operand->reg = (uint8_t)(f0 & 0xffu);
                operand->value = f0;
                break;
            case CDISASM_M68K_OP_MACREG: {
                /* D/A bit, register, U/L (literal 2: no half), shift factor. */
                uint32_t half = spec->field_count > 2 ? m68k_field(words, &spec->field[2]) : 2u;
                uint32_t sf = spec->field_count > 3 ? m68k_field(words, &spec->field[3]) : 0u;
                operand->reg = (uint8_t)((f0 << 3) | f1);
                operand->value = half | (sf << 4);
                break;
            }
            case CDISASM_M68K_OP_MACMASK: break;
            case CDISASM_M68K_OP_ACC:
                /* One 2-bit field, or low bit + high bit (low bit inverted with a load). */
                operand->reg = (uint8_t)(spec->field_count > 1 ? (f1 << 1) | ((f0 ^ spec->ea_class) & 1u) : f0);
                break;
            case CDISASM_M68K_OP_MACCTL: operand->reg = (uint8_t)f0; break;
            case CDISASM_M68K_OP_Q3: operand->imm = f0 ? f0 : UINT64_MAX; break;
            default: return 0;
        }
    }
    return 1;
}

uint32_t CDISASM_CALL cdisasm_m68k_decode_features(uint64_t features, const uint8_t *code, size_t code_size, uint64_t address, cdisasm_m68k_instruction *instruction)
{
    uint32_t words[3], first;
    uint32_t index, last;
    m68k_reader probe;
    if (!instruction) return 0;
    memset(instruction, 0, sizeof(*instruction));
    if (!code || code_size < 2) return 0;
    if (features & F(EMAC)) features |= F(MAC);
    probe.code = code;
    probe.size = code_size;
    probe.offset = 0;
    probe.address = address;
    if (!m68k_word(&probe, &first)) return 0;
    words[0] = first;
    words[1] = code_size >= 4 ? ((uint32_t)code[2] << 8) | code[3] : 0;
    words[2] = code_size >= 6 ? ((uint32_t)code[4] << 8) | code[5] : 0;
    last = m68k_line_first[(first >> 12) + 1];
    for (index = m68k_line_first[first >> 12]; index < last; ++index) {
        const cdisasm_m68k_form *form = &m68k_forms[index];
        m68k_reader reader = probe;
        unsigned w;
        int ok = 1;
        if ((first & form->mask[0]) != form->match[0]) continue;
        if ((form->features & features) != form->features || (form->excluded & features)) continue;
        if (code_size < 2u * form->word_count) continue;
        for (w = 1; w < form->word_count; ++w)
            if ((words[w] & form->mask[w]) != form->match[w]) ok = 0;
        if (!ok) continue;
        reader.offset = 2u * form->word_count;
        instruction->address = address;
        instruction->branch_target = 0;
        if (!m68k_try(form, features, &reader, words, instruction)) continue;
        instruction->length = (uint32_t)reader.offset;
        instruction->flags = form->flags;
        instruction->features = form->features;
        instruction->form_id = (uint16_t)index;
        instruction->name_id = form->name_id;
        instruction->opcode = (uint16_t)first;
        instruction->size = form->size;
        instruction->suffix = form->suffix;
        instruction->operand_count = form->operand_count;
        memcpy(instruction->bytes, code, reader.offset);
        return instruction->length;
    }
    memset(instruction, 0, sizeof(*instruction));
    return 0;
}

uint32_t CDISASM_CALL cdisasm_m68k_decode(cdisasm_m68k_cpu_id cpu_id, uint32_t mode, const uint8_t *code, size_t code_size, uint64_t address,
                                          const cdisasm_decode_flags *flags, cdisasm_m68k_instruction *instruction)
{
    uint64_t features = cdisasm_m68k_cpu_features(cpu_id);
    (void)flags;
    if (!features) {
        if (instruction) memset(instruction, 0, sizeof(*instruction));
        return 0;
    }
    return cdisasm_m68k_decode_features(features | (mode & CDISASM_M68K_FEATURE_ALL), code, code_size, address, instruction);
}
