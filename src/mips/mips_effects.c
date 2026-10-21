#include "mips_decoder.h"
#include <string.h>

_Static_assert(sizeof(cdisasm_mips_register_effect) == 16u, "MIPS effect ABI changed");

int cdisasm_mips_instruction_validate(const cdisasm_mips_instruction *instruction)
{
    cdisasm_mips_instruction canonical;
    cdisasm_mips_decode_flags features = CDISASM_MIPS_DECODE_FLAGS_NONE_INITIALIZER;
    if (instruction == NULL || instruction->last_error_id != CDISASM_STATUS_OK ||
        instruction->opcode_size != 4u || instruction->name_id == 0 || instruction->name_id >= CDISASM_MIPS_NAME_COUNT ||
        instruction->operand_count > CDISASM_MIPS_MAX_OPERANDS ||
        (instruction->mode != CDISASM_MIPS_MODE_32 && instruction->mode != CDISASM_MIPS_MODE_64)) return 0;
    switch (instruction->revision) {
        case CDISASM_MIPS_REVISION_I: case CDISASM_MIPS_REVISION_II:
        case CDISASM_MIPS_REVISION_32R1: case CDISASM_MIPS_REVISION_32R2: case CDISASM_MIPS_REVISION_32R3:
        case CDISASM_MIPS_REVISION_32R5: case CDISASM_MIPS_REVISION_32R6:
            if (instruction->mode != CDISASM_MIPS_MODE_32) return 0;
            break;
        case CDISASM_MIPS_REVISION_III: case CDISASM_MIPS_REVISION_IV: case CDISASM_MIPS_REVISION_V:
        case CDISASM_MIPS_REVISION_64R1: case CDISASM_MIPS_REVISION_64R2: case CDISASM_MIPS_REVISION_64R3:
        case CDISASM_MIPS_REVISION_64R5: case CDISASM_MIPS_REVISION_64R6: break;
        default: return 0;
    }
    if ((instruction->instruction_flags & CDISASM_MIPS_INSTRUCTION_FLAG_FPR32) != 0 &&
        (instruction->revision == CDISASM_MIPS_REVISION_32R6 || instruction->revision == CDISASM_MIPS_REVISION_64R6 ||
         (instruction->instruction_flags & CDISASM_MIPS_INSTRUCTION_FLAG_MSA) != 0)) return 0;
    features.bitmap[0] = cdisasm_mips_instruction_required_flags(instruction);
    if (cdisasm_mips_decode_core(instruction->raw_instruction, instruction->address, instruction->mode,
                               instruction->revision, &features, &canonical) != CDISASM_STATUS_OK) return 0;
    return memcmp(&canonical, instruction, sizeof(canonical)) == 0;
}

static void effect_add(cdisasm_mips_register_effect *list, size_t *count, cdisasm_mips_reg_id reg,
                       cdisasm_operand_access access, uint16_t size, uint8_t flags, uint64_t selector)
{
    size_t index;
    if (reg == CDISASM_MIPS_REG_NONE || access == CDISASM_OPERAND_ACCESS_NONE) return;
    for (index = 0; index < *count; ++index) {
        if (list[index].reg == reg && list[index].flags == flags && list[index].selector == selector) {
            list[index].access |= access;
            if (list[index].size < size) list[index].size = size;
            return;
        }
    }
    if (*count >= 64u) return;
    list[*count].reg = reg;
    list[*count].access = access;
    list[*count].size = size;
    list[*count].flags = flags;
    list[*count].selector = selector;
    ++*count;
}

static size_t effects_numeric(const cdisasm_mips_instruction *instruction, cdisasm_mips_register_effect *output, size_t capacity)
{
    cdisasm_mips_register_effect list[64] = {{0}};
    cdisasm_mips_register_effect generated[64] = {{0}};
    size_t count = 0, index, generated_count;
    int explicit_link_destination = 0;
    const uint16_t gpr_size = instruction->mode == CDISASM_MIPS_MODE_64 ? 8u : 4u;
    const uint32_t flags = instruction->instruction_flags;
    for (index = 0; index < instruction->operand_count; ++index) {
        const cdisasm_mips_operand *operand = &instruction->operand[index];
        if (operand->type == CDISASM_OPERAND_REGISTER) {
            if ((operand->access & CDISASM_OPERAND_ACCESS_WRITE) != 0 &&
                (operand->flags & CDISASM_OPERAND_FLAG_IMPLICIT) == 0 &&
                operand->reg >= CDISASM_MIPS_REG_GPR0 && operand->reg <= CDISASM_MIPS_REG_GPR31)
                explicit_link_destination = 1;
            if (operand->reg >= CDISASM_MIPS_REG_VFPU_SCALAR_FIRST && operand->reg <= CDISASM_MIPS_REG_VFPU_MATRIX_LAST)
                continue; /* Encoded overlapping views expand in the VFPU helper. */
            uint8_t effect_flags = (uint8_t)(operand->flags & CDISASM_MIPS_OPERAND_FLAG_THREAD_REGISTER);
            if ((operand->detail.flags & CDISASM_MIPS_OPERAND_DETAIL_REGISTER_SELECTOR) != 0)
                effect_flags |= CDISASM_MIPS_OPERAND_DETAIL_REGISTER_SELECTOR;
            if ((operand->detail.flags & CDISASM_MIPS_OPERAND_DETAIL_REGISTER_LIST) != 0) {
                unsigned bit;
                const cdisasm_mips_reg_id first = operand->reg ? operand->reg : CDISASM_MIPS_REG_GPR0;
                for (bit = 0; bit < 32u; ++bit)
                    if ((operand->imm & (UINT64_C(1) << bit)) != 0)
                        effect_add(list, &count, (cdisasm_mips_reg_id)(first + bit), operand->access, operand->size, effect_flags, 0);
            } else {
                effect_add(list, &count, operand->reg, operand->access, operand->size, effect_flags,
                           (effect_flags & CDISASM_MIPS_OPERAND_DETAIL_REGISTER_SELECTOR) ? operand->imm : 0);
                if ((flags & CDISASM_MIPS_INSTRUCTION_FLAG_FPR32) != 0 && operand->size == 8u &&
                    operand->reg >= CDISASM_MIPS_REG_FPR0 && operand->reg < CDISASM_MIPS_REG_FPR31) {
                    /* In FR=0 a double occupies an explicitly adjacent pair. */
                    size_t prior;
                    for (prior = 0; prior < count; ++prior) if (list[prior].reg == operand->reg) list[prior].size = 4;
                    effect_add(list, &count, (cdisasm_mips_reg_id)(operand->reg + 1u), operand->access, 4u, effect_flags, 0);
                }
            }
            if ((operand->detail.flags & CDISASM_MIPS_OPERAND_DETAIL_LANE_REGISTER) != 0)
                effect_add(list, &count, operand->index_reg, CDISASM_OPERAND_ACCESS_READ, gpr_size, 0, 0);
        } else if (operand->type == CDISASM_OPERAND_MEMORY) {
            effect_add(list, &count, operand->base_reg, CDISASM_OPERAND_ACCESS_READ,
                operand->base_reg >= CDISASM_MIPS_REG_VU_VI_FIRST && operand->base_reg <= CDISASM_MIPS_REG_VU_VI_LAST ? 2u : gpr_size, 0, 0);
            effect_add(list, &count, operand->index_reg, CDISASM_OPERAND_ACCESS_READ,
                operand->index_reg >= CDISASM_MIPS_REG_VU_VI_FIRST && operand->index_reg <= CDISASM_MIPS_REG_VU_VI_LAST ? 2u : gpr_size, 0, 0);
        }
    }
#define ADD_FLAG(flag_, reg_, access_, size_) do { if ((flags & (flag_)) != 0) effect_add(list, &count, (reg_), (access_), (size_), 0, 0); } while (0)
    ADD_FLAG(CDISASM_MIPS_INSTRUCTION_FLAG_READS_HI, CDISASM_MIPS_REG_HI, CDISASM_OPERAND_ACCESS_READ, gpr_size);
    ADD_FLAG(CDISASM_MIPS_INSTRUCTION_FLAG_READS_LO, CDISASM_MIPS_REG_LO, CDISASM_OPERAND_ACCESS_READ, gpr_size);
    ADD_FLAG(CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_HI, CDISASM_MIPS_REG_HI, CDISASM_OPERAND_ACCESS_WRITE, gpr_size);
    ADD_FLAG(CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_LO, CDISASM_MIPS_REG_LO, CDISASM_OPERAND_ACCESS_WRITE, gpr_size);
    if (!explicit_link_destination)
        ADD_FLAG(CDISASM_MIPS_INSTRUCTION_FLAG_LINK, CDISASM_MIPS_REG_RA, CDISASM_OPERAND_ACCESS_WRITE, gpr_size);
    ADD_FLAG(CDISASM_MIPS_INSTRUCTION_FLAG_READS_DSPCONTROL, CDISASM_MIPS_REG_DSPCONTROL, CDISASM_OPERAND_ACCESS_READ, 4u);
    ADD_FLAG(CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_DSPCONTROL, CDISASM_MIPS_REG_DSPCONTROL, CDISASM_OPERAND_ACCESS_WRITE, 4u);
    ADD_FLAG(CDISASM_MIPS_INSTRUCTION_FLAG_READS_FCSR, CDISASM_MIPS_REG_FCSR, CDISASM_OPERAND_ACCESS_READ, 4u);
    ADD_FLAG(CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_FCSR, CDISASM_MIPS_REG_FCSR, CDISASM_OPERAND_ACCESS_WRITE, 4u);
    ADD_FLAG(CDISASM_MIPS_INSTRUCTION_FLAG_READS_MSACSR, CDISASM_MIPS_REG_MSACSR, CDISASM_OPERAND_ACCESS_READ, 4u);
    ADD_FLAG(CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_MSACSR, CDISASM_MIPS_REG_MSACSR, CDISASM_OPERAND_ACCESS_WRITE, 4u);
#undef ADD_FLAG
    if (instruction->name_id == CDISASM_MIPS_NAME_LL || instruction->name_id == CDISASM_MIPS_NAME_LLD ||
        instruction->name_id == CDISASM_MIPS_NAME_LLE || instruction->name_id == CDISASM_MIPS_NAME_LLWP || instruction->name_id == CDISASM_MIPS_NAME_LLWPE)
        effect_add(list, &count, CDISASM_MIPS_REG_LLBIT, CDISASM_OPERAND_ACCESS_WRITE, 1u, 0, 0);
    if (instruction->name_id == CDISASM_MIPS_NAME_SC || instruction->name_id == CDISASM_MIPS_NAME_SCD ||
        instruction->name_id == CDISASM_MIPS_NAME_SCE || instruction->name_id == CDISASM_MIPS_NAME_SCWP || instruction->name_id == CDISASM_MIPS_NAME_SCWPE)
        effect_add(list, &count, CDISASM_MIPS_REG_LLBIT, CDISASM_OPERAND_ACCESS_READ_WRITE, 1u, 0, 0);
    generated_count = instruction->form_id >= 20000u && instruction->form_id < 25000u
        ? cdisasm_mips_generated_effects(instruction->form_id, generated, 64u) : 0;
    for (index = 0; index < generated_count && index < 64u; ++index)
        effect_add(list, &count, generated[index].reg, generated[index].access, generated[index].size, generated[index].flags, generated[index].selector);
    generated_count = instruction->form_id >= 30000u && instruction->form_id < 34000u
        ? cdisasm_mips_compact_effects(instruction, generated, 64u) : 0;
    for (index = 0; index < generated_count && index < 64u; ++index)
        effect_add(list, &count, generated[index].reg, generated[index].access, generated[index].size, generated[index].flags, generated[index].selector);
    generated_count = instruction->form_id >= 40000u && instruction->form_id < 45000u
        ? cdisasm_mips_allegrex_effects(instruction, generated, 64u) : 0;
    for (index = 0; index < generated_count && index < 64u; ++index)
        effect_add(list, &count, generated[index].reg, generated[index].access, generated[index].size, generated[index].flags, generated[index].selector);
    generated_count = instruction->form_id >= 45000u && instruction->form_id < 50000u
        ? cdisasm_mips_r5900_effects(instruction, generated, 64u) : 0;
    for (index = 0; index < generated_count && index < 64u; ++index)
        effect_add(list, &count, generated[index].reg, generated[index].access, generated[index].size, generated[index].flags, generated[index].selector);
    generated_count = instruction->form_id >= 50000u && instruction->form_id < 55000u
        ? cdisasm_mips_mxu_effects(instruction, generated, 64u) : 0;
    for (index = 0; index < generated_count && index < 64u; ++index)
        effect_add(list, &count, generated[index].reg, generated[index].access, generated[index].size, generated[index].flags, generated[index].selector);
    generated_count = instruction->form_id >= 56000u && instruction->form_id < 59000u
        ? cdisasm_mips_mxu_vector_effects(instruction, generated, 64u) : 0;
    for (index = 0; index < generated_count && index < 64u; ++index)
        effect_add(list, &count, generated[index].reg, generated[index].access, generated[index].size, generated[index].flags, generated[index].selector);
    generated_count = instruction->form_id >= 62000u
        ? cdisasm_mips_vu_effects(instruction, generated, 64u) : 0;
    for (index = 0; index < generated_count && index < 64u; ++index)
        effect_add(list, &count, generated[index].reg, generated[index].access, generated[index].size, generated[index].flags, generated[index].selector);
    if (capacity > count) capacity = count;
    if (capacity != 0) memcpy(output, list, capacity * sizeof(*output));
    return count;
}

size_t CDISASM_CALL cdisasm_mips_register_effects(const cdisasm_mips_instruction *instruction,
                                               cdisasm_mips_register_effect *effects, size_t capacity)
{
    if ((capacity != 0 && effects == NULL) || !cdisasm_mips_instruction_validate(instruction)) return 0;
    return effects_numeric(instruction, effects, capacity);
}

size_t CDISASM_CALL cdisasm_mips_register_effects_v2(const cdisasm_mips_instruction_v2 *instruction,
                                                  cdisasm_mips_register_effect *effects, size_t capacity)
{
    if ((capacity != 0 && effects == NULL) || !cdisasm_mips_instruction_validate_v2(instruction)) return 0;
    return effects_numeric(&instruction->instruction, effects, capacity);
}

size_t CDISASM_CALL cdisasm_mips_register_effects_vu(const cdisasm_mips_vu_instruction *instruction,
    cdisasm_mips_register_effect *effects, size_t capacity)
{
    cdisasm_mips_register_effect combined[64] = {{0}}, part[64] = {{0}};
    size_t count = 0, total, index;
    unsigned slot;
    if ((capacity != 0 && effects == NULL) || !cdisasm_mips_vu_instruction_validate(instruction)) return 0;
    for (slot = 0; slot < 2u; ++slot) {
        const cdisasm_mips_instruction *operation = slot ? &instruction->lower.instruction : &instruction->upper.instruction;
        total = effects_numeric(operation, part, 64u);
        for (index = 0; index < total && index < 64u; ++index)
            effect_add(combined, &count, part[index].reg, part[index].access, part[index].size, part[index].flags, part[index].selector);
    }
    if (capacity > count) capacity = count;
    if (capacity != 0) memcpy(effects, combined, capacity * sizeof(*effects));
    return count;
}
