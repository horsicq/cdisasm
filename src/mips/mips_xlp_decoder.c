#include "mips_decoder.h"
#include <string.h>

/* Physical XLP ownership remains available when optional opcode tables are
 * disabled, preventing a selected XLP from falling into another vendor ISA. */
int cdisasm_mips_xlp_owns(uint32_t raw)
{
    uint32_t field = raw & UINT32_C(0xfc0007ff);
    if (field == UINT32_C(0x70000038) || field == UINT32_C(0x7000001c) ||
        field == UINT32_C(0x7000001d) || field == UINT32_C(0x70000006)) return 1;
    field = raw & UINT32_C(0xfc00ffff);
    if (field == UINT32_C(0x70000010) || field == UINT32_C(0x70000011) || field == UINT32_C(0x70000012) ||
        field == UINT32_C(0x70000014) || field == UINT32_C(0x70000015) || field == UINT32_C(0x70000016) ||
        field == UINT32_C(0x70000018) || field == UINT32_C(0x70000019)) return 1;
    field = raw & UINT32_C(0xffe007ff);
    if (field == UINT32_C(0x7000001e) || field == UINT32_C(0x7000001f) ||
        field == UINT32_C(0x4a000001) || field == UINT32_C(0x4a000002)) return 1;
    return (raw & UINT32_C(0xffe0ffff)) == UINT32_C(0x4a000003) || raw == UINT32_C(0x4a000004);
}

#if USE_EXTRA_OPCODES && USE_MIPS_XLP
typedef struct xlp_form {
    uint32_t mask, value;
    uint16_t name, form;
    uint8_t recipe, size, wide;
} xlp_form;
static const xlp_form xlp_forms[] = {
#include "generated/mips_xlp_forms.inc"
};

static void xlp_register(cdisasm_mips_instruction *i, unsigned reg, unsigned access)
{
    cdisasm_mips_operand *o = &i->operand[i->operand_count++];
    o->type = CDISASM_OPERAND_REGISTER;
    o->reg = (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0 + reg);
    o->size = 8;
    o->access = (uint8_t)access;
}
#endif

uint64_t cdisasm_mips_xlp_required_flags(cdisasm_mips_form_id form)
{
#if USE_EXTRA_OPCODES && USE_MIPS_XLP
    if (form >= 65020u && form <= 65037u)
        return CDISASM_MIPS_DECODE_FLAG_XLP | (form >= 65034u ? CDISASM_MIPS_DECODE_FLAG_COP2 : 0);
#else
    (void)form;
#endif
    return 0;
}

cdisasm_status cdisasm_mips_decode_xlp(uint32_t raw, uint64_t address, cdisasm_mips_mode mode,
    cdisasm_mips_revision revision, const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *i)
{
#if USE_EXTRA_OPCODES && USE_MIPS_XLP
    size_t n;
    if (revision != CDISASM_MIPS_REVISION_64R2) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    for (n = 0; n < sizeof(xlp_forms) / sizeof(xlp_forms[0]); ++n) {
        const xlp_form *f = &xlp_forms[n];
        const unsigned rs = (raw >> 21) & 31u, rt = (raw >> 16) & 31u, rd = (raw >> 11) & 31u;
        uint64_t required;
        if ((raw & f->mask) != f->value) continue;
        if (mode != CDISASM_MIPS_MODE_64) return CDISASM_STATUS_INVALID_INSTRUCTION;
        required = cdisasm_mips_xlp_required_flags(f->form);
        if (features == NULL || (features->bitmap[0] & required) != required)
            return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        memset(i, 0, sizeof(*i));
        i->address = address; i->raw_instruction = raw; i->opcode_size = 4;
        i->mode = (uint8_t)mode; i->revision = (uint8_t)revision;
        i->name_id = f->name; i->form_id = f->form;
        if (f->recipe == 1u) {
            /* CRC/DCRC widths describe whole GPR dependencies only. Their
             * lane semantics and polynomial are not established by pinfo. */
            xlp_register(i, rd, CDISASM_OPERAND_ACCESS_WRITE);
            xlp_register(i, rs, CDISASM_OPERAND_ACCESS_READ);
            xlp_register(i, rt, CDISASM_OPERAND_ACCESS_READ);
        } else if (f->recipe == 2u) {
            cdisasm_mips_operand *memory;
            xlp_register(i, rt, CDISASM_OPERAND_ACCESS_READ_WRITE);
            xlp_register(i, rs, CDISASM_OPERAND_ACCESS_READ);
            memory = &i->operand[i->operand_count++];
            memory->type = CDISASM_OPERAND_MEMORY;
            memory->base_reg = (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0 + rs);
            memory->size = f->size; memory->access = CDISASM_OPERAND_ACCESS_READ_WRITE;
            memory->flags = CDISASM_OPERAND_FLAG_IMPLICIT;
            i->instruction_flags = CDISASM_MIPS_INSTRUCTION_FLAG_ATOMIC;
        } else if (f->recipe == 3u || f->recipe == 4u) {
            xlp_register(i, rt, f->recipe == 3u ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ);
            xlp_register(i, rs, CDISASM_OPERAND_ACCESS_READ);
            i->opcode_groups = CDISASM_GROUP_PRIVILEGED;
        } else if (f->recipe == 5u || f->recipe == 6u) {
            cdisasm_mips_operand *encoded;
            xlp_register(i, rt, f->recipe == 5u ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ);
            /* Vendor t,d syntax does not establish an architectural UR bank
             * or GPRrd dependency. Retain those bits as an opaque parameter. */
            encoded = &i->operand[i->operand_count++];
            encoded->type = CDISASM_OPERAND_IMMEDIATE;
            encoded->imm = rd; encoded->size = 1; encoded->access = CDISASM_OPERAND_ACCESS_READ;
        } else {
            if (f->recipe == 7u) xlp_register(i, rd, CDISASM_OPERAND_ACCESS_WRITE);
            if (f->recipe != 9u) xlp_register(i, rt, CDISASM_OPERAND_ACCESS_READ);
            i->instruction_flags = CDISASM_MIPS_INSTRUCTION_FLAG_COP2;
        }
        return CDISASM_STATUS_OK;
    }
#else
    (void)raw; (void)address; (void)mode; (void)revision; (void)features; (void)i;
#endif
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}

size_t cdisasm_mips_xlp_effects(const cdisasm_mips_instruction *i, cdisasm_mips_register_effect *out, size_t capacity)
{
    cdisasm_mips_register_effect effects[8] = {{0}};
    size_t count = 0;
#if USE_EXTRA_OPCODES && USE_MIPS_XLP
#define EFFECT(reg_, access_, size_) do { effects[count].reg = (reg_); effects[count].access = (access_); effects[count].size = (size_); ++count; } while (0)
    if (i->form_id == 65020u) {
        EFFECT(CDISASM_MIPS_REG_CP0(12,0), CDISASM_OPERAND_ACCESS_READ_WRITE, 4);
    } else if (i->form_id == 65027u || i->form_id == 65028u) {
        EFFECT(CDISASM_MIPS_REG_XLP_CONTROL_BANK, i->form_id == 65027u ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_READ_WRITE, 0);
    } else if (i->form_id == 65034u || i->form_id == 65035u) {
        unsigned n;
        for (n = 0; n < 4; ++n)
            EFFECT(CDISASM_MIPS_REG_COP2(i->form_id == 65034u ? 0 : 1,n),
                i->form_id == 65034u ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_READ_WRITE, 8);
        /* XLP separates TX and RX status, unlike XLR's shared register2. */
        EFFECT(CDISASM_MIPS_REG_COP2(i->form_id == 65034u ? 2 : 3,0), CDISASM_OPERAND_ACCESS_READ_WRITE, 4);
        EFFECT(CDISASM_MIPS_REG_XLP_FMN_BANK, CDISASM_OPERAND_ACCESS_READ_WRITE, 0);
    } else if (i->form_id == 65036u) {
        EFFECT(CDISASM_MIPS_REG_XLP_FMN_BANK, CDISASM_OPERAND_ACCESS_READ, 0);
    }
    /* CRC/DCRC and DMFUR/DMTUR hidden effects remain unverified. MSGSYNC
     * pinfo0 supplies no evidence for a memory barrier or fixed FMN access. */
#undef EFFECT
#else
    (void)i;
#endif
    if (capacity > count) capacity = count;
    if (capacity && out) memcpy(out, effects, capacity * sizeof(*out));
    return count;
}
