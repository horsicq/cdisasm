#include "mips_decoder.h"

#include <string.h>

/* This backend contains only fully lowered numeric recipes. The much larger
 * upstream inventory is a build-time coverage denominator, never a successful
 * decode fallback for an unknown operand or predicate. */
#if USE_EXTRA_OPCODES
typedef struct mips_inventory_form {
    uint32_t mask;
    uint32_t value;
    uint32_t revisions;
    uint64_t required_flags;
    cdisasm_mips_name_id name;
    cdisasm_mips_form_id form;
    uint8_t recipe;
    uint8_t modes;
    uint8_t size;
    uint8_t access;
    uint8_t aux;
    uint8_t effect_reads;
    uint8_t effect_writes;
} mips_inventory_form;

#include "generated/mips_inventory_forms.inc"

static uint32_t inventory_revision_bit(cdisasm_mips_revision revision)
{
    switch (revision) {
        case 1u: return UINT32_C(1) << 0;
        case 2u: return UINT32_C(1) << 1;
        case 3u: return UINT32_C(1) << 2;
        case 4u: return UINT32_C(1) << 3;
        case 5u: return UINT32_C(1) << 4;
        case 32u: return UINT32_C(1) << 5;
        case 33u: return UINT32_C(1) << 6;
        case 34u: return UINT32_C(1) << 7;
        case 36u: return UINT32_C(1) << 8;
        case 37u: return UINT32_C(1) << 9;
        case 64u: return UINT32_C(1) << 10;
        case 65u: return UINT32_C(1) << 11;
        case 66u: return UINT32_C(1) << 12;
        case 68u: return UINT32_C(1) << 13;
        case 69u: return UINT32_C(1) << 14;
        default: return 0;
    }
}

static void inventory_register(cdisasm_mips_instruction *instruction, cdisasm_mips_reg_id reg,
                               uint8_t size, cdisasm_operand_access access)
{
    cdisasm_mips_operand *operand = &instruction->operand[instruction->operand_count++];
    operand->type = CDISASM_OPERAND_REGISTER;
    operand->reg = reg;
    operand->size = size;
    operand->access = access;
}

static void inventory_gpr(cdisasm_mips_instruction *instruction, unsigned reg,
                         uint8_t size, cdisasm_operand_access access)
{
    inventory_register(instruction, (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0 + reg), size, access);
}

static void inventory_immediate(cdisasm_mips_instruction *instruction, uint64_t value, uint8_t size)
{
    cdisasm_mips_operand *operand = &instruction->operand[instruction->operand_count++];
    operand->type = CDISASM_OPERAND_IMMEDIATE;
    operand->imm = value;
    operand->size = size;
}

static void inventory_vector(cdisasm_mips_instruction *instruction, unsigned reg,
                             uint8_t element_size, cdisasm_operand_access access)
{
    inventory_register(instruction, (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_FPR0 + reg), 8u, access);
    instruction->operand[instruction->operand_count - 1u].detail.element_size = element_size;
}

static int inventory_mdmx_selector(cdisasm_mips_instruction *instruction, uint32_t raw,
                                   uint8_t element_size)
{
    unsigned selector = (raw >> 21) & 31u, vt = (raw >> 16) & 31u;
    cdisasm_mips_operand *operand;
    /* The low format bits are 0 for octobyte or 01 for quad-halfword.
     * Selector prefixes 0, 10, 11 select an element, vector, or uimm5. */
    if ((selector & 3u) == 3u || (element_size == 2u && (selector & 3u) != 1u)) return 0;
    if ((selector & 24u) == 24u) {
        inventory_immediate(instruction, vt, 1u);
        return 1;
    }
    inventory_vector(instruction, vt, element_size, CDISASM_OPERAND_ACCESS_READ);
    if ((selector & 16u) == 0u) {
        operand = &instruction->operand[instruction->operand_count - 1u];
        operand->detail.flags = CDISASM_MIPS_OPERAND_DETAIL_HAS_LANE;
        operand->detail.lane_index = (uint8_t)((selector & 15u) >> element_size);
    }
    return 1;
}

static void inventory_eva_memory(cdisasm_mips_instruction *instruction, uint32_t raw,
                                uint8_t size, cdisasm_operand_access access)
{
    unsigned offset = (raw >> 7) & 511u;
    cdisasm_mips_operand *operand = &instruction->operand[instruction->operand_count++];
    operand->type = CDISASM_OPERAND_MEMORY;
    operand->base_reg = (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0 + ((raw >> 21) & 31u));
    operand->imm = offset & 256u ? (uint64_t)offset - UINT64_C(512) : offset;
    operand->size = size;
    operand->access = access;
    operand->flags = CDISASM_MIPS_OPERAND_FLAG_SIGNED | CDISASM_MIPS_OPERAND_FLAG_HAS_DISPLACEMENT;
    if (size == 0u) operand->flags |= CDISASM_OPERAND_FLAG_ADDRESS_ONLY;
}

static int inventory_lower(const mips_inventory_form *form, uint32_t raw, cdisasm_mips_mode mode,
                           cdisasm_mips_instruction *instruction)
{
    unsigned rt = (raw >> 16) & 31u, rd = (raw >> 11) & 31u;
    switch (form->recipe) {
        case 0: /* Exact operand-free system instructions. */
            instruction->opcode_groups = CDISASM_GROUP_PRIVILEGED;
            if (form->aux) instruction->opcode_groups |= CDISASM_GROUP_INTERRUPT_RETURN;
            break;
        case 1: /* EVA signed-nine-bit memory operations, including tied SCE. */
            inventory_gpr(instruction, rt, 4u, form->access);
            inventory_eva_memory(instruction, raw, form->size,
                                 (form->aux & 1u) ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ);
            if (form->aux & 2u) instruction->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_ATOMIC;
            break;
        case 2: /* CACHEE/PREFE hint followed by address-only memory. */
            inventory_immediate(instruction, rt, 1u);
            inventory_eva_memory(instruction, raw, 0u, CDISASM_OPERAND_ACCESS_READ);
            if (form->name == CDISASM_MIPS_NAME_CACHEE) instruction->opcode_groups = CDISASM_GROUP_PRIVILEGED;
            break;
        case 3: /* CP0 select is part of the guest register identity. */
        case 7:
            inventory_gpr(instruction, rt, form->size,
                          (form->aux & 1u) ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE);
            inventory_register(instruction,
                form->recipe == 3 ? CDISASM_MIPS_REG_GUEST_CP0(rd, raw & 7u) : CDISASM_MIPS_REG_CP0(rd, raw & 7u),
                form->size, (form->aux & 1u) ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ);
            if (form->recipe == 7 || form->name == CDISASM_MIPS_NAME_MFHGC0 || form->name == CDISASM_MIPS_NAME_MTHGC0)
                instruction->operand[1].detail.flags |= CDISASM_MIPS_OPERAND_DETAIL_HIGH_HALF;
            instruction->opcode_groups = CDISASM_GROUP_PRIVILEGED;
            break;
        case 4: /* CRC writes encoded rt and also reads its old accumulator. */
            inventory_gpr(instruction, rt, 4u, CDISASM_OPERAND_ACCESS_WRITE);
            inventory_gpr(instruction, (raw >> 21) & 31u, form->size, CDISASM_OPERAND_ACCESS_READ);
            inventory_gpr(instruction, rt, 4u, CDISASM_OPERAND_ACCESS_READ);
            break;
        case 5:
            inventory_gpr(instruction, (raw >> 21) & 31u, mode == CDISASM_MIPS_MODE_64 ? 8u : 4u, CDISASM_OPERAND_ACCESS_READ);
            if (form->aux) inventory_immediate(instruction, (raw >> 8) & 3u, 1u);
            instruction->opcode_groups = CDISASM_GROUP_PRIVILEGED;
            break;
        case 6:
            inventory_immediate(instruction, (raw >> 11) & 1023u, 2u);
            instruction->opcode_groups = CDISASM_GROUP_PRIVILEGED | CDISASM_GROUP_INTERRUPT;
            break;
        case 8:
            inventory_gpr(instruction, rd, 8u, CDISASM_OPERAND_ACCESS_WRITE);
            inventory_gpr(instruction, (raw >> 21) & 31u, 8u, CDISASM_OPERAND_ACCESS_READ);
            inventory_gpr(instruction, rt, 8u, CDISASM_OPERAND_ACCESS_READ);
            break;
        case 9: {
            uint64_t displacement = raw & 65535u;
            cdisasm_mips_operand *operand;
            if (displacement & 32768u) displacement -= UINT64_C(65536);
            displacement <<= 2;
            inventory_gpr(instruction, (raw >> 21) & 31u, 8u, CDISASM_OPERAND_ACCESS_READ);
            inventory_immediate(instruction, rt, 1u);
            inventory_immediate(instruction, 0u, 4u);
            operand = &instruction->operand[2];
            operand->address = displacement;
            operand->imm = instruction->address + UINT64_C(4) + displacement;
            operand->flags = CDISASM_MIPS_OPERAND_FLAG_RELATIVE | CDISASM_MIPS_OPERAND_FLAG_HAS_ADDRESS;
            instruction->branch_target = operand->imm;
            instruction->opcode_groups = CDISASM_GROUP_JUMP | CDISASM_GROUP_CONDITIONAL | CDISASM_GROUP_RELATIVE_BRANCH;
            instruction->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_DELAY_SLOT;
            break;
        }
        case 10: {
            unsigned pos = (raw >> 6) & 31u, length_minus_one = (raw >> 11) & 31u;
            if (form->aux && pos + length_minus_one >= 32u) return 0;
            inventory_gpr(instruction, rt, 8u, CDISASM_OPERAND_ACCESS_WRITE);
            inventory_gpr(instruction, (raw >> 21) & 31u, 8u, CDISASM_OPERAND_ACCESS_READ);
            inventory_immediate(instruction, pos, 1u);
            inventory_immediate(instruction, length_minus_one, 1u);
            break;
        }
        case 11:
            inventory_gpr(instruction, rt, 8u, form->aux ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE);
            inventory_register(instruction, CDISASM_MIPS_REG_COP2_FIRST, 8u,
                               form->aux ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ);
            instruction->operand[1].imm = raw & 65535u;
            instruction->operand[1].detail.flags = CDISASM_MIPS_OPERAND_DETAIL_REGISTER_SELECTOR;
            instruction->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_COP2;
            break;
        case 12: {
            cdisasm_mips_operand *operand;
            inventory_gpr(instruction, rt, form->size, CDISASM_OPERAND_ACCESS_READ);
            operand = &instruction->operand[instruction->operand_count++];
            operand->type = CDISASM_OPERAND_MEMORY;
            operand->base_reg = (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0 + ((raw >> 21) & 31u));
            operand->size = form->size;
            operand->access = CDISASM_OPERAND_ACCESS_READ_WRITE;
            instruction->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_ATOMIC;
            break;
        }
        case 13:
            inventory_gpr(instruction, (raw >> 21) & 31u, 8u, CDISASM_OPERAND_ACCESS_READ);
            break;
        case 14:
            inventory_gpr(instruction, rd, form->size, CDISASM_OPERAND_ACCESS_WRITE);
            inventory_gpr(instruction, (raw >> 21) & 31u, form->size, CDISASM_OPERAND_ACCESS_READ);
            break;
        case 15: {
            uint64_t value = (raw >> 6) & 1023u;
            if (value & 512u) value -= UINT64_C(1024);
            inventory_gpr(instruction, rt, 8u, CDISASM_OPERAND_ACCESS_WRITE);
            inventory_gpr(instruction, (raw >> 21) & 31u, 8u, CDISASM_OPERAND_ACCESS_READ);
            inventory_immediate(instruction, value, 2u);
            instruction->operand[2].flags = CDISASM_MIPS_OPERAND_FLAG_SIGNED;
            break;
        }
        case 16: {
            uint8_t size = mode == CDISASM_MIPS_MODE_64 ? 8u : 4u;
            inventory_register(instruction, (cdisasm_mips_reg_id)((form->aux ? CDISASM_MIPS_REG_PREVIOUS_GPR_FIRST : CDISASM_MIPS_REG_GPR0) + rd),
                               size, CDISASM_OPERAND_ACCESS_WRITE);
            inventory_register(instruction, (cdisasm_mips_reg_id)((form->aux ? CDISASM_MIPS_REG_GPR0 : CDISASM_MIPS_REG_PREVIOUS_GPR_FIRST) + rt),
                               size, CDISASM_OPERAND_ACCESS_READ);
            instruction->opcode_groups = CDISASM_GROUP_PRIVILEGED;
            break;
        }
        case 17: /* SmartMIPS extended HI/LO/ACX arithmetic and transfers. */
            if (form->aux == 0u) {
                inventory_gpr(instruction, rd, 4u, CDISASM_OPERAND_ACCESS_WRITE);
            } else {
                inventory_gpr(instruction, (raw >> 21) & 31u, 4u, CDISASM_OPERAND_ACCESS_READ);
                if (form->aux >= 2u) inventory_gpr(instruction, rt, 4u, CDISASM_OPERAND_ACCESS_READ);
            }
            instruction->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_HI | CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_LO;
            if (form->aux != 3u && form->aux != 6u)
                instruction->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_READS_HI | CDISASM_MIPS_INSTRUCTION_FLAG_READS_LO;
            break;
        case 18: { /* SmartMIPS LWXS scales the index by four before addition. */
            cdisasm_mips_operand *operand;
            inventory_gpr(instruction, rd, 4u, CDISASM_OPERAND_ACCESS_WRITE);
            operand = &instruction->operand[instruction->operand_count++];
            operand->type = CDISASM_OPERAND_MEMORY;
            operand->base_reg = (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0 + ((raw >> 21) & 31u));
            operand->index_reg = (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0 + rt);
            operand->detail.index_shift = 2u;
            operand->detail.flags = CDISASM_MIPS_OPERAND_DETAIL_INDEX_SCALED;
            operand->size = 4u;
            operand->access = CDISASM_OPERAND_ACCESS_READ;
            break;
        }
        case 19: /* SmartMIPS provides ROTR/ROTRV before base Release 2. */
            inventory_gpr(instruction, rd, 4u, CDISASM_OPERAND_ACCESS_WRITE);
            inventory_gpr(instruction, rt, 4u, CDISASM_OPERAND_ACCESS_READ);
            if (form->aux) inventory_gpr(instruction, (raw >> 21) & 31u, 4u, CDISASM_OPERAND_ACCESS_READ);
            else inventory_immediate(instruction, (raw >> 6) & 31u, 1u);
            break;
        case 20: { /* MCU byte bit-set/clear with signed twelve-bit displacement. */
            cdisasm_mips_operand *operand;
            uint64_t displacement = raw & 4095u;
            if (displacement & 2048u) displacement -= UINT64_C(4096);
            inventory_immediate(instruction, (raw >> 12) & 7u, 1u);
            operand = &instruction->operand[instruction->operand_count++];
            operand->type = CDISASM_OPERAND_MEMORY;
            operand->base_reg = (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0 + ((raw >> 21) & 31u));
            operand->imm = displacement;
            operand->size = 1u;
            operand->access = CDISASM_OPERAND_ACCESS_READ_WRITE;
            operand->flags = CDISASM_MIPS_OPERAND_FLAG_SIGNED | CDISASM_MIPS_OPERAND_FLAG_HAS_DISPLACEMENT;
            instruction->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_ATOMIC;
            break;
        }
        case 21: /* MDMX binary vectors, with element/vector/immediate source. */
            inventory_vector(instruction, (raw >> 6) & 31u, form->size, CDISASM_OPERAND_ACCESS_WRITE);
            inventory_vector(instruction, rd, form->size, CDISASM_OPERAND_ACCESS_READ);
            if (!inventory_mdmx_selector(instruction, raw, form->size)) return 0;
            break;
        case 22: /* The condition-code outputs are implicit architectural state. */
        case 23:
            inventory_vector(instruction, rd, form->size, CDISASM_OPERAND_ACCESS_READ);
            if (!inventory_mdmx_selector(instruction, raw, form->size)) return 0;
            break;
        case 24:
            inventory_vector(instruction, (raw >> 6) & 31u, form->size, CDISASM_OPERAND_ACCESS_WRITE);
            if (!inventory_mdmx_selector(instruction, raw, form->size)) return 0;
            break;
        case 25:
            inventory_vector(instruction, (raw >> 6) & 31u, form->size, CDISASM_OPERAND_ACCESS_WRITE);
            break;
        case 26:
            inventory_vector(instruction, rd, form->size, CDISASM_OPERAND_ACCESS_READ);
            if (form->aux) inventory_vector(instruction, rt, form->size, CDISASM_OPERAND_ACCESS_READ);
            break;
        case 27:
        case 28:
            inventory_vector(instruction, (raw >> 6) & 31u, form->size, CDISASM_OPERAND_ACCESS_WRITE);
            inventory_vector(instruction, rd, form->size, CDISASM_OPERAND_ACCESS_READ);
            inventory_vector(instruction, rt, form->size, CDISASM_OPERAND_ACCESS_READ);
            if (form->recipe == 27u) {
                if (form->aux) inventory_gpr(instruction, (raw >> 21) & 31u, 8u, CDISASM_OPERAND_ACCESS_READ);
                else inventory_immediate(instruction, (raw >> 21) & 7u, 1u);
            }
            break;
        case 29: { /* Loongson MMI arithmetic uses the physical FPR bank. */
            /* UM0447 AppendixC assigns complete64-bit FPRs and checks word
             * extension. Keep the independently reviewed2F correction apart
             * from the predecessor2E catalog. form->size is arithmetic size. */
            uint8_t resource_size = (form->required_flags & CDISASM_MIPS_DECODE_FLAG_LOONGSON2F) ? 8u : form->size;
            inventory_register(instruction, (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_FPR0 + ((raw >> 6) & 31u)), resource_size, CDISASM_OPERAND_ACCESS_WRITE);
            inventory_register(instruction, (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_FPR0 + rd), resource_size, CDISASM_OPERAND_ACCESS_READ);
            if (form->aux == 3u) inventory_register(instruction, (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_FPR0 + rt),
                resource_size == 4u && (form->name == CDISASM_MIPS_NAME_SLL || form->name == CDISASM_MIPS_NAME_SRA || form->name == CDISASM_MIPS_NAME_SRL) ? 8u : resource_size,
                CDISASM_OPERAND_ACCESS_READ);
            break;
        }
        case 30:
        case 35:
            inventory_register(instruction, (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_FPR0 + rd), form->size, CDISASM_OPERAND_ACCESS_READ);
            inventory_register(instruction, (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_FPR0 + rt), form->size, CDISASM_OPERAND_ACCESS_READ);
            break;
        case 31:
            /* The2F word-GPR operations sign-extend their results into64-bit
             * destinations; their arithmetic inputs remain low32-bit words
             * (UM0447 AppendixA). Doubleword operations already use size8. */
            inventory_gpr(instruction, rd, (form->required_flags & CDISASM_MIPS_DECODE_FLAG_LOONGSON2F) ? 8u : form->size, CDISASM_OPERAND_ACCESS_WRITE);
            inventory_gpr(instruction, (raw >> 21) & 31u, form->size, CDISASM_OPERAND_ACCESS_READ);
            inventory_gpr(instruction, rt, form->size, CDISASM_OPERAND_ACCESS_READ);
            break;
        case 32: /* The Loongson fused destination is also an input. */
        case 33:
        case 34:
            inventory_register(instruction, (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_FPR0 + ((raw >> 6) & 31u)), form->size,
                               form->recipe == 32u ? CDISASM_OPERAND_ACCESS_READ_WRITE : CDISASM_OPERAND_ACCESS_WRITE);
            inventory_register(instruction, (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_FPR0 + rd), form->size, CDISASM_OPERAND_ACCESS_READ);
            if (form->recipe != 34u) inventory_register(instruction, (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_FPR0 + rt), form->size, CDISASM_OPERAND_ACCESS_READ);
            break;
        case 36:
            inventory_gpr(instruction, rd, 8u, CDISASM_OPERAND_ACCESS_READ_WRITE);
            inventory_gpr(instruction, (raw >> 21) & 31u, 8u, CDISASM_OPERAND_ACCESS_READ);
            inventory_gpr(instruction, rt, 8u, CDISASM_OPERAND_ACCESS_READ);
            break;
        case 37:
            inventory_gpr(instruction, rd, form->size, CDISASM_OPERAND_ACCESS_WRITE);
            inventory_gpr(instruction, (raw >> 21) & 31u, form->size, CDISASM_OPERAND_ACCESS_READ);
            break;
        case 38:
            inventory_gpr(instruction, rd, 8u, form->aux ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE);
            inventory_gpr(instruction, (raw >> 21) & 31u, 8u, CDISASM_OPERAND_ACCESS_READ);
            if (form->aux) inventory_gpr(instruction, rt, 8u, CDISASM_OPERAND_ACCESS_READ);
            break;
        case 39:
            inventory_gpr(instruction, (raw >> 21) & 31u, 8u, CDISASM_OPERAND_ACCESS_READ);
            inventory_gpr(instruction, rt, 8u, CDISASM_OPERAND_ACCESS_READ);
            instruction->opcode_groups = CDISASM_GROUP_INTERRUPT | CDISASM_GROUP_CONDITIONAL;
            break;
        case 40: {
            cdisasm_mips_operand *memory;
            cdisasm_operand_access access = form->aux & 1u ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE;
            inventory_register(instruction, (cdisasm_mips_reg_id)((form->aux & 2u ? CDISASM_MIPS_REG_FPR0 : CDISASM_MIPS_REG_GPR0) + rt),
                               form->aux & 2u ? form->size : 8u, access);
            memory = &instruction->operand[instruction->operand_count++];
            memory->type = CDISASM_OPERAND_MEMORY;
            memory->base_reg = (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0 + ((raw >> 21) & 31u));
            memory->size = form->size;
            memory->access = form->aux & 1u ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ;
            memory->detail.flags = CDISASM_MIPS_OPERAND_DETAIL_BARE_BASE;
            inventory_gpr(instruction, rd, 8u, CDISASM_OPERAND_ACCESS_READ);
            break;
        }
        case 41:
        case 42:
        case 43: {
            cdisasm_mips_operand *memory;
            cdisasm_mips_reg_id bank = form->aux & 2u ? CDISASM_MIPS_REG_FPR0 : CDISASM_MIPS_REG_GPR0;
            cdisasm_operand_access access = form->aux & 1u ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE;
            uint64_t displacement;
            if (form->recipe == 43u) {
                inventory_register(instruction, (cdisasm_mips_reg_id)(bank + (raw & 31u)), 8u, access);
                inventory_register(instruction, (cdisasm_mips_reg_id)(bank + rt), 8u, access);
                displacement = (raw >> 6) & 511u;
                if (displacement & 256u) displacement -= UINT64_C(512);
                displacement <<= 4;
            } else {
                if (form->recipe == 41u && !(form->aux & 1u)) access = CDISASM_OPERAND_ACCESS_READ_WRITE;
                inventory_register(instruction, (cdisasm_mips_reg_id)(bank + rt), form->aux & 2u ? form->size : 8u, access);
                displacement = form->recipe == 41u ? (raw >> 6) & 255u : (raw >> 3) & 255u;
                if (displacement & 128u) displacement -= UINT64_C(256);
            }
            memory = &instruction->operand[instruction->operand_count++];
            memory->type = CDISASM_OPERAND_MEMORY;
            memory->base_reg = (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0 + ((raw >> 21) & 31u));
            if (form->recipe == 42u) memory->index_reg = (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0 + rd);
            memory->imm = displacement;
            memory->size = form->size;
            memory->access = form->aux & 1u ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ;
            memory->flags = CDISASM_MIPS_OPERAND_FLAG_SIGNED | CDISASM_MIPS_OPERAND_FLAG_HAS_DISPLACEMENT;
            break;
        }
        case 44: { /* Release6 paired word/doubleword atomics. */
            const uint8_t gpr_size = mode == CDISASM_MIPS_MODE_64 ? 8u : 4u;
            const int store = (form->aux & 1u) != 0;
            cdisasm_mips_operand *memory;
            inventory_gpr(instruction, rt, gpr_size,
                store ? CDISASM_OPERAND_ACCESS_READ_WRITE : CDISASM_OPERAND_ACCESS_WRITE);
            inventory_gpr(instruction, rd, store ? form->size : gpr_size,
                store ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE);
            memory = &instruction->operand[instruction->operand_count++];
            memory->type = CDISASM_OPERAND_MEMORY;
            memory->base_reg = (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_GPR0 + ((raw >> 21) & 31u));
            memory->size = (uint8_t)(2u * form->size);
            memory->access = store ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ;
            instruction->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_ATOMIC;
            break;
        }
        default: return 0; /* The generator rejects unregistered recipes. */
    }
    if (form->required_flags & CDISASM_MIPS_DECODE_FLAG_EVA) instruction->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_EVA;
    if (form->required_flags & CDISASM_MIPS_DECODE_FLAG_VZ) instruction->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_VZ;
    if (form->required_flags & CDISASM_MIPS_DECODE_FLAG_XPA) instruction->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_XPA;
    if (form->required_flags & CDISASM_MIPS_DECODE_FLAG_MDMX) instruction->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_MDMX;
    if (form->required_flags & CDISASM_MIPS_DECODE_FLAG_PAIRED_SINGLE) instruction->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_PAIRED_SINGLE;
    if (form->recipe == 32u || (form->recipe >= 33u && form->recipe <= 35u)) {
        instruction->instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_FLOATING_POINT;
        if (form->recipe != 34u) instruction->instruction_flags |=
            CDISASM_MIPS_INSTRUCTION_FLAG_READS_FCSR | CDISASM_MIPS_INSTRUCTION_FLAG_WRITES_FCSR;
    }
    return 1;
}
#endif

uint64_t cdisasm_mips_generated_required_flags(cdisasm_mips_form_id form_id)
{
#if USE_EXTRA_OPCODES
    size_t index;
    for (index = 0; index < sizeof(mips_inventory_forms) / sizeof(mips_inventory_forms[0]); ++index)
        if (mips_inventory_forms[index].form == form_id) return mips_inventory_forms[index].required_flags;
#else
    (void)form_id;
#endif
    return 0;
}

size_t cdisasm_mips_generated_effects(cdisasm_mips_form_id form_id, cdisasm_mips_register_effect *effects, size_t capacity)
{
#if USE_EXTRA_OPCODES
    size_t index;
    for (index = 0; index < sizeof(mips_inventory_forms) / sizeof(mips_inventory_forms[0]); ++index) {
        const mips_inventory_form *form = &mips_inventory_forms[index];
        size_t count = 0;
        unsigned resource;
        if (form->form != form_id) continue;
        for (resource = 0; resource < 8u; ++resource) {
            unsigned bit = 1u << resource;
            cdisasm_operand_access access = (cdisasm_operand_access)((form->effect_reads & bit ? CDISASM_OPERAND_ACCESS_READ : 0u) |
                                                                   (form->effect_writes & bit ? CDISASM_OPERAND_ACCESS_WRITE : 0u));
            if (access == 0u) continue;
            if (effects != NULL && count < capacity) {
                memset(&effects[count], 0, sizeof(effects[count]));
                effects[count].reg = resource == 7u ? CDISASM_MIPS_REG_MDMX_ACC : resource == 6u ? CDISASM_MIPS_REG_SMARTMIPS_ACX :
                    (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_OCTEON_MPL0 + resource);
                effects[count].access = access;
                effects[count].size = resource == 7u ? 24u : 8u;
            }
            ++count;
        }
        if (form->recipe == 22u || (form->recipe == 21u && form->aux) || form->recipe == 30u || form->recipe == 35u) {
            unsigned fcc;
            unsigned count_fcc = form->recipe == 30u ? 1u : form->recipe == 35u ? 2u : form->size == 1u ? 8u : 4u;
            for (fcc = 0; fcc < count_fcc; ++fcc) {
                if (effects != NULL && count < capacity) {
                    memset(&effects[count], 0, sizeof(effects[count]));
                    effects[count].reg = (cdisasm_mips_reg_id)(CDISASM_MIPS_REG_FCC0 + fcc);
                    effects[count].access = form->recipe == 21u ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE;
                    effects[count].size = 1u;
                }
                ++count;
            }
        }
        if (form->recipe == 44u) {
            /* Optional LLAddr implementation: retain a possible dependency
             * without asserting a physical width or a cache/coherence model. */
            if (effects != NULL && count < capacity) {
                memset(&effects[count], 0, sizeof(effects[count]));
                effects[count].reg = CDISASM_MIPS_REG_CP0(17,0);
                /* LLbit aliases LLAddr bit0. A conditional store reads the
                 * address and clears that bit, preserving its other bits. */
                effects[count].access = form->aux & 1u ? CDISASM_OPERAND_ACCESS_READ_WRITE : CDISASM_OPERAND_ACCESS_WRITE;
            }
            ++count;
        }
        return count;
    }
#else
    (void)form_id; (void)effects; (void)capacity;
#endif
    return 0;
}

cdisasm_status cdisasm_mips_decode_generated(uint32_t raw, uint64_t address, cdisasm_mips_mode mode,
                                           cdisasm_mips_revision revision, const cdisasm_mips_decode_flags *features,
                                           cdisasm_mips_instruction *instruction)
{
#if USE_EXTRA_OPCODES
    uint32_t revision_bit = inventory_revision_bit(revision);
    uint8_t mode_bit = mode == CDISASM_MIPS_MODE_32 ? 1u : mode == CDISASM_MIPS_MODE_64 ? 2u : 0u;
    uint64_t enabled = features != NULL ? features->bitmap[0] : 0;
    size_t index;
    int invalid = 0;
    if (instruction == NULL) return CDISASM_STATUS_INTERNAL_ERROR;
    if (revision_bit == 0u || mode_bit == 0u) return CDISASM_STATUS_INVALID_ARGUMENT;
    for (index = 0; index < sizeof(mips_inventory_forms) / sizeof(mips_inventory_forms[0]); ++index) {
        const mips_inventory_form *form = &mips_inventory_forms[index];
        cdisasm_mips_instruction result;
        if ((raw & form->mask) != form->value || !(revision_bit & form->revisions) || !(mode_bit & form->modes)) continue;
        if ((enabled & form->required_flags) != form->required_flags) continue;
        if ((form->required_flags & CDISASM_MIPS_DECODE_FLAG_MDMX) != 0 &&
            (enabled & CDISASM_MIPS_DECODE_FLAG_FPR32) != 0) { invalid = 1; continue; }
        if ((enabled & CDISASM_MIPS_DECODE_FLAG_FPR32) != 0) {
            if (form->recipe == 29u || form->recipe == 30u || (form->recipe >= 33u && form->recipe <= 35u) ||
                (form->recipe == 32u && (form->aux || (form->size == 8u && ((raw >> 6) | (raw >> 11) | (raw >> 16)) & 1u)))) {
                invalid = 1;
                continue;
            }
            if (form->recipe >= 40u && form->recipe <= 43u && (form->aux & 2u) != 0 &&
                (form->recipe == 43u || (form->size == 8u && ((raw >> 16) & 1u) != 0))) {
                invalid = 1;
                continue;
            }
        }
        memset(&result, 0, sizeof(result));
        result.address = address;
        result.raw_instruction = raw;
        result.opcode_size = 4u;
        result.mode = (uint8_t)mode;
        result.revision = (uint8_t)revision;
        result.name_id = form->name;
        result.form_id = form->form;
        if ((enabled & CDISASM_MIPS_DECODE_FLAG_FPR32) != 0 && form->recipe == 32u)
            result.instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_FPR32;
        if ((enabled & CDISASM_MIPS_DECODE_FLAG_FPR32) != 0 && form->recipe >= 40u && form->recipe <= 43u && (form->aux & 2u) != 0)
            result.instruction_flags |= CDISASM_MIPS_INSTRUCTION_FLAG_FPR32;
        if (!inventory_lower(form, raw, mode, &result)) { invalid = 1; continue; }
        *instruction = result;
        return CDISASM_STATUS_OK;
    }
    if (invalid) return CDISASM_STATUS_INVALID_INSTRUCTION;
#else
    (void)raw; (void)address; (void)mode; (void)revision; (void)features; (void)instruction;
#endif
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}
