#include "mips_decoder.h"
#include <string.h>

/* XLR/XLS assign SPECIAL2 and COP2 slots that have other vendor meanings.
 * Ownership survives the optional-table gate for an explicitly selected CPU. */
int cdisasm_mips_xlr_owns(uint32_t raw)
{
    uint32_t two = raw & UINT32_C(0xfc00ffff);
    if ((raw & UINT32_C(0xfc0007ff)) == UINT32_C(0x70000038)) return 1;
    if (two == UINT32_C(0x70000010) || two == UINT32_C(0x70000011) || two == UINT32_C(0x70000012) ||
        two == UINT32_C(0x70000014) || two == UINT32_C(0x70000015) || two == UINT32_C(0x70000016) ||
        two == UINT32_C(0x70000018) || two == UINT32_C(0x70000019)) return 1;
    two = raw & UINT32_C(0xffe0ffff);
    return two == UINT32_C(0x4a000001) || two == UINT32_C(0x4a000002) || two == UINT32_C(0x4a000003);
}

#if USE_EXTRA_OPCODES && USE_MIPS_XLR
typedef struct xlr_form {
    uint32_t mask, value;
    uint16_t name, form;
    uint8_t recipe, size, wide;
} xlr_form;
static const xlr_form xlr_forms[] = {
#include "generated/mips_xlr_forms.inc"
};

static void xlr_register(cdisasm_mips_instruction *i, unsigned reg, unsigned size, unsigned access)
{
    cdisasm_mips_operand *o = &i->operand[i->operand_count++];
    o->type = CDISASM_OPERAND_REGISTER;
    o->reg = (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0 + reg);
    o->size = (uint8_t)size;
    o->access = (uint8_t)access;
}
#endif

uint64_t cdisasm_mips_xlr_required_flags(cdisasm_mips_form_id form)
{
#if USE_EXTRA_OPCODES && USE_MIPS_XLR
    if (form >= 65000u && form <= 65011u)
        return CDISASM_MIPS_DECODE_FLAG_XLR | (form >= 65009u ? CDISASM_MIPS_DECODE_FLAG_COP2 : 0);
#else
    (void)form;
#endif
    return 0;
}

cdisasm_status cdisasm_mips_decode_xlr(uint32_t raw, uint64_t address, cdisasm_mips_mode mode,
    cdisasm_mips_revision revision, const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *i)
{
#if USE_EXTRA_OPCODES && USE_MIPS_XLR
    size_t n;
    if (revision != CDISASM_MIPS_REVISION_64R1) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    for (n = 0; n < sizeof(xlr_forms) / sizeof(xlr_forms[0]); ++n) {
        const xlr_form *f = &xlr_forms[n];
        const unsigned rs = (raw >> 21) & 31u, rt = (raw >> 16) & 31u, rd = (raw >> 11) & 31u;
        const unsigned gpr_size = mode == CDISASM_MIPS_MODE_64 ? 8u : 4u;
        uint64_t required;
        if ((raw & f->mask) != f->value) continue;
        if (f->wide && mode != CDISASM_MIPS_MODE_64) return CDISASM_STATUS_INVALID_INSTRUCTION;
        required = cdisasm_mips_xlr_required_flags(f->form);
        if (features == NULL || (features->bitmap[0] & required) != required)
            return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        memset(i, 0, sizeof(*i));
        i->address = address; i->raw_instruction = raw; i->opcode_size = 4;
        i->mode = (uint8_t)mode; i->revision = (uint8_t)revision;
        i->name_id = f->name; i->form_id = f->form;
        if (f->recipe == 1u) {
            xlr_register(i, rd, 8, CDISASM_OPERAND_ACCESS_WRITE);
            xlr_register(i, rs, 8, CDISASM_OPERAND_ACCESS_READ);
            xlr_register(i, rt, 8, CDISASM_OPERAND_ACCESS_READ);
        } else if (f->recipe == 2u) {
            cdisasm_mips_operand *memory;
            xlr_register(i, rt, gpr_size, CDISASM_OPERAND_ACCESS_READ_WRITE);
            xlr_register(i, rs, gpr_size, CDISASM_OPERAND_ACCESS_READ);
            /* Vendor assembly spells the base as a bare GPR. Preserve that
             * syntax and additionally expose its implicit atomic memory access. */
            memory = &i->operand[i->operand_count++];
            memory->type = CDISASM_OPERAND_MEMORY;
            memory->base_reg = (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0 + rs);
            memory->size = f->size; memory->access = CDISASM_OPERAND_ACCESS_READ_WRITE;
            memory->flags = CDISASM_OPERAND_FLAG_IMPLICIT;
            i->instruction_flags = CDISASM_MIPS_INSTRUCTION_FLAG_ATOMIC;
        } else if (f->recipe == 3u || f->recipe == 4u) {
            xlr_register(i, rt, 8, f->recipe == 3u ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ);
            xlr_register(i, rs, gpr_size, CDISASM_OPERAND_ACCESS_READ);
            i->opcode_groups = CDISASM_GROUP_PRIVILEGED;
        } else {
            xlr_register(i, rt, gpr_size, CDISASM_OPERAND_ACCESS_READ);
            i->instruction_flags = CDISASM_MIPS_INSTRUCTION_FLAG_COP2;
        }
        return CDISASM_STATUS_OK;
    }
#else
    (void)raw; (void)address; (void)mode; (void)revision; (void)features; (void)i;
#endif
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}

size_t cdisasm_mips_xlr_effects(const cdisasm_mips_instruction *i, cdisasm_mips_register_effect *out, size_t capacity)
{
    cdisasm_mips_register_effect effects[8] = {{0}};
    size_t count = 0;
#if USE_EXTRA_OPCODES && USE_MIPS_XLR
#define EFFECT(reg_, access_, size_) do { effects[count].reg = (reg_); effects[count].access = (access_); effects[count].size = (size_); ++count; } while (0)
    if (i->form_id == 65000u) {
        EFFECT(CDISASM_MIPS_REG_CP0(12,0), CDISASM_OPERAND_ACCESS_READ_WRITE, 4);
    } else if (i->form_id == 65007u || i->form_id == 65008u) {
        /* The GPR contains the control index, so no single statically named
         * control register can describe this access. Retain a bank dependency. */
        EFFECT(CDISASM_MIPS_REG_XLR_CONTROL_BANK, i->form_id == 65007u ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_READ_WRITE, 0);
    } else if (i->form_id >= 65009u && i->form_id <= 65011u) {
        unsigned n;
        if (i->form_id != 65011u) {
            for (n = 0; n < 4; ++n)
                EFFECT(CDISASM_MIPS_REG_COP2(i->form_id == 65009u ? 0 : 1,n),
                    i->form_id == 65009u ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_READ_WRITE, 8);
        }
        EFFECT(CDISASM_MIPS_REG_COP2(2,0), i->form_id == 65011u ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_READ_WRITE, 4);
        EFFECT(CDISASM_MIPS_REG_XLR_FMN_BANK, i->form_id == 65011u ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_READ_WRITE, 0);
    }
#undef EFFECT
#else
    (void)i;
#endif
    if (capacity > count) capacity = count;
    if (capacity && out) memcpy(out, effects, capacity * sizeof(*out));
    return count;
}
