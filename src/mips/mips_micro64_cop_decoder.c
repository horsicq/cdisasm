#include "mips_decoder.h"
#include <string.h>

#if USE_EXTRA_OPCODES
typedef struct micro64_cop_form {
    uint32_t mask, value;
    uint16_t name, form;
    uint8_t bank, to_cop, memory;
} micro64_cop_form;
static const micro64_cop_form micro64_cop_forms[] = {
#include "generated/mips_micro64_cop_forms.inc"
};

static int micro64_cop_revision(cdisasm_mips_revision revision)
{
    switch (revision) {
        case CDISASM_MIPS_REVISION_III: case CDISASM_MIPS_REVISION_IV: case CDISASM_MIPS_REVISION_V:
        case CDISASM_MIPS_REVISION_64R1: case CDISASM_MIPS_REVISION_64R2: case CDISASM_MIPS_REVISION_64R3:
        case CDISASM_MIPS_REVISION_64R5: case CDISASM_MIPS_REVISION_64R6: return 1;
        default: return 0;
    }
}
#endif

uint64_t cdisasm_mips_micro64_cop_required_flags(cdisasm_mips_form_id form)
{
#if USE_EXTRA_OPCODES
    switch (form) {
        case 31062u: case 31063u: return CDISASM_MIPS_DECODE_FLAG_FPU;
        case 31064u: case 31065u: case 31066u: case 31067u: return CDISASM_MIPS_DECODE_FLAG_COP2;
        default: break;
    }
#else
    (void)form;
#endif
    return 0;
}

cdisasm_status cdisasm_mips_micro64_cop(uint32_t raw, uint64_t address, cdisasm_mips_mode mode,
    cdisasm_mips_revision revision, const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *i)
{
#if USE_EXTRA_OPCODES
    size_t n;
    for (n = 0; n < sizeof(micro64_cop_forms) / sizeof(micro64_cop_forms[0]); ++n) {
        const micro64_cop_form *f = &micro64_cop_forms[n];
        const unsigned rt = (raw >> 21) & 31u, cop = (raw >> 16) & 31u, sel = (raw >> 11) & 7u;
        const uint64_t required = cdisasm_mips_micro64_cop_required_flags(f->form);
        const int fr32 = f->bank == 1u && features && (features->bitmap[0] & CDISASM_MIPS_DECODE_FLAG_FPR32) != 0;
        cdisasm_mips_operand *gpr, *resource;
        if ((raw & f->mask) != f->value) continue;
        if (f->memory) {
            unsigned valid_revision = micro64_cop_revision(revision) || revision == 1u || revision == 2u ||
                revision == 32u || revision == 33u || revision == 34u || revision == 36u;
            unsigned offset = raw & 4095u;
            int64_t displacement = (int64_t)(offset ^ 2048u) - 2048;
            if (!valid_revision || revision == CDISASM_MIPS_REVISION_64R6 || revision == CDISASM_MIPS_REVISION_32R6 ||
                (mode != CDISASM_MIPS_MODE_32 && mode != CDISASM_MIPS_MODE_64) ||
                (mode == CDISASM_MIPS_MODE_64 && !micro64_cop_revision(revision))) return CDISASM_STATUS_INVALID_INSTRUCTION;
            if (!features || (features->bitmap[0] & required) != required) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
            if (!i) return CDISASM_STATUS_INVALID_ARGUMENT;
            memset(i, 0, sizeof(*i));
            i->address = address; i->raw_instruction = raw; i->opcode_size = 4;
            i->mode = (uint8_t)mode; i->revision = (uint8_t)revision;
            i->name_id = f->name; i->form_id = f->form; i->operand_count = 2;
            i->instruction_flags = CDISASM_MIPS_INSTRUCTION_FLAG_COP2;
            resource = &i->operand[0];
            resource->type = CDISASM_OPERAND_REGISTER; resource->reg = CDISASM_MIPS_REG_COP2(rt, 0);
            resource->size = 8; resource->access = f->to_cop ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ;
            resource = &i->operand[1];
            resource->type = CDISASM_OPERAND_MEMORY; resource->base_reg = (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0 + cop);
            resource->size = 8; resource->access = f->to_cop ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE;
            resource->imm = (uint64_t)displacement;
            resource->flags = CDISASM_MIPS_OPERAND_FLAG_SIGNED | CDISASM_MIPS_OPERAND_FLAG_HAS_DISPLACEMENT;
            if (!cop) {
                resource->address = mode == CDISASM_MIPS_MODE_64 ? (uint64_t)displacement : (uint64_t)(uint32_t)displacement;
                resource->flags |= CDISASM_MIPS_OPERAND_FLAG_ABSOLUTE | CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS;
            }
            return CDISASM_STATUS_OK;
        }
        if (mode != CDISASM_MIPS_MODE_64 || !micro64_cop_revision(revision))
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        if (required && (!features || (features->bitmap[0] & required) != required))
            return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        if (fr32 && ((cop & 1u) || revision == CDISASM_MIPS_REVISION_64R6))
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        if (!i) return CDISASM_STATUS_INVALID_ARGUMENT;
        memset(i, 0, sizeof(*i));
        i->address = address; i->raw_instruction = raw; i->opcode_size = 4;
        i->mode = (uint8_t)mode; i->revision = (uint8_t)revision;
        i->name_id = f->name; i->form_id = f->form; i->operand_count = 2;
        gpr = &i->operand[0]; resource = &i->operand[1];
        gpr->type = resource->type = CDISASM_OPERAND_REGISTER;
        gpr->reg = (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0 + rt);
        gpr->size = resource->size = 8;
        gpr->access = f->to_cop ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE;
        resource->access = f->to_cop ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ;
        if (f->bank == 0u) {
            resource->reg = CDISASM_MIPS_REG_CP0(cop, sel);
            i->opcode_groups = CDISASM_GROUP_PRIVILEGED;
        } else if (f->bank == 1u) {
            resource->reg = (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_FPR0 + cop);
            i->instruction_flags = CDISASM_MIPS_INSTRUCTION_FLAG_FLOATING_POINT |
                (fr32 ? CDISASM_MIPS_INSTRUCTION_FLAG_FPR32 : 0);
        } else {
            /* MD00594 pp226/229: Impl is the five bits20..16. Its meaning
             * belongs to the implementation, not a guessed rd/sel split. */
            resource->reg = CDISASM_MIPS_REG_COP2_FIRST;
            resource->imm = cop;
            resource->detail.flags = CDISASM_MIPS_OPERAND_DETAIL_REGISTER_SELECTOR;
            i->instruction_flags = CDISASM_MIPS_INSTRUCTION_FLAG_COP2;
        }
        return CDISASM_STATUS_OK;
    }
#else
    (void)raw; (void)address; (void)mode; (void)revision; (void)features; (void)i;
#endif
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}
