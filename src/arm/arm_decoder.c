#include "arm_decoder.h"
#include "arm_apple_decoder.h"
#include "arm_modern_decoder.h"

#include <stddef.h>

/* Generated feature ordinal 55 is FEAT_LSUI; generated feature IDs begin
 * after the 36 legacy capability bits. */
#define ARM_FEATURE_LSUI UINT16_C(91)

static int64_t sign_extend(uint64_t value, unsigned bits)
{
    uint64_t sign = UINT64_C(1) << (bits - 1);
    return (int64_t)((value ^ sign) - sign);
}

static uint32_t rotate_right32(uint32_t value, unsigned amount)
{
    amount &= 31u;
    if (amount == 0) {
        return value;
    }
    return (value >> amount) | (value << (32u - amount));
}

#if USE_EXTRA_OPCODES
static uint64_t vfp_expand_immediate(
    unsigned encoded, uint8_t element_size)
{
    unsigned total_bits = 8u * element_size;
    unsigned exponent_bits = element_size == 2u ? 5u
        : element_size == 4u ? 8u : 11u;
    unsigned fraction_bits = total_bits - exponent_bits - 1u;
    unsigned selector = (encoded >> 6) & 1u;
    uint64_t exponent = (uint64_t)(selector ^ 1u)
        << (exponent_bits - 1u);

    if (selector != 0u) {
        exponent |= ((UINT64_C(1) << (exponent_bits - 3u))
                - UINT64_C(1))
            << 2u;
    }
    exponent |= (encoded >> 4) & 3u;
    return ((uint64_t)((encoded >> 7) & 1u) << (total_bits - 1u))
        | (exponent << fraction_bits)
        | ((uint64_t)(encoded & 15u) << (fraction_bits - 4u));
}
#endif

static cdisasm_arm_reg_id a32_reg(unsigned encoded)
{
    return (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0 + encoded);
}

static cdisasm_arm_reg_id a64_reg(unsigned encoded, int is_64, int use_sp)
{
    if (encoded == 31u) {
        if (use_sp) {
            return is_64 ? CDISASM_ARM_REG_SP : CDISASM_ARM_REG_WSP;
        }
        return is_64 ? CDISASM_ARM_REG_XZR : CDISASM_ARM_REG_WZR;
    }
    return (cdisasm_arm_reg_id)((is_64 ? CDISASM_ARM_REG_X0
                                       : CDISASM_ARM_REG_W0)
        + encoded);
}

static cdisasm_arm_reg_id a32_vector_reg(unsigned encoded_d, int is_quad)
{
    return (cdisasm_arm_reg_id)(
        (is_quad ? CDISASM_ARM_REG_Q0 : CDISASM_ARM_REG_D0)
        + (is_quad ? encoded_d / 2u : encoded_d));
}

static cdisasm_arm_reg_id a64_vector_reg(unsigned encoded)
{
    return (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + encoded);
}

static cdisasm_arm_operand *append_operand(
    cdisasm_arm_instruction *instruction)
{
    if (instruction->operand_count >= CDISASM_ARM_MAX_OPERANDS) {
        return NULL;
    }
    return &instruction->operand[instruction->operand_count++];
}

static cdisasm_arm_operand *append_register(
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_reg_id reg,
    uint8_t size,
    cdisasm_operand_access access)
{
    cdisasm_arm_operand *operand = append_operand(instruction);
    if (operand != NULL) {
        operand->type = CDISASM_OPERAND_REGISTER;
        operand->reg = reg;
        operand->size = size;
        operand->access = access;
    }
    return operand;
}

#if USE_EXTRA_OPCODES
static cdisasm_arm_operand *append_register_pair(
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_reg_id first_reg,
    cdisasm_arm_reg_id second_reg,
    uint8_t size,
    cdisasm_operand_access access)
{
    cdisasm_arm_operand *operand = append_operand(instruction);

    if (operand != NULL) {
        operand->type = CDISASM_ARM_OPERAND_REGISTER_PAIR;
        operand->reg = first_reg;
        operand->index_reg = second_reg;
        operand->size = size;
        operand->access = access;
    }
    return operand;
}
#endif

static cdisasm_arm_operand *append_vector_register(
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_reg_id reg,
    uint8_t total_size,
    uint8_t element_size,
    cdisasm_operand_access access)
{
    cdisasm_arm_operand *operand = append_register(
        instruction, reg, total_size, access);

    if (operand != NULL) {
        operand->extend_type = (cdisasm_arm_extend_type)element_size;
        operand->scale =
            (uint8_t)(total_size / element_size);
    }
    return operand;
}

static cdisasm_arm_operand *append_immediate(
    cdisasm_arm_instruction *instruction,
    uint64_t value,
    uint8_t size)
{
    cdisasm_arm_operand *operand = append_operand(instruction);
    if (operand != NULL) {
        operand->type = CDISASM_OPERAND_IMMEDIATE;
        operand->imm = value;
        operand->size = size;
        operand->access = CDISASM_OPERAND_ACCESS_READ;
    }
    return operand;
}

#if USE_EXTRA_OPCODES
static cdisasm_arm_operand *append_system_operand(
    cdisasm_arm_instruction *instruction,
    uint8_t type,
    uint16_t encoding,
    cdisasm_operand_access access)
{
    cdisasm_arm_operand *operand = append_operand(instruction);

    if (operand != NULL) {
        operand->type = type;
        operand->imm = encoding;
        operand->access = access;
    }
    return operand;
}
#endif

static void initialize_instruction(
    cdisasm_arm_instruction *instruction,
    uint32_t word,
    uint64_t address,
    cdisasm_arm_isa_id isa,
    cdisasm_arm_condition condition)
{
    instruction->address = address;
    instruction->opcode_size = 4;
    instruction->raw_instruction = word;
    instruction->isa_id = isa;
    instruction->condition = condition;
}

static void apply_condition_group(cdisasm_arm_instruction *instruction)
{
    if (instruction->condition != CDISASM_ARM_CONDITION_AL) {
        instruction->opcode_groups |= CDISASM_GROUP_CONDITIONAL;
    }
}

static int is_a32_vfp_scalar_memory_word(uint32_t word)
{
    uint32_t form = word & UINT32_C(0x0f300f00);

    return form == UINT32_C(0x0d000900)
        || form == UINT32_C(0x0d000a00)
        || form == UINT32_C(0x0d000b00)
        || form == UINT32_C(0x0d100900)
        || form == UINT32_C(0x0d100a00)
        || form == UINT32_C(0x0d100b00);
}

/* A32/T32 coprocessor register transfers are deliberately kept out of the
 * generated fallback: their p#/c# fields are architectural operands, not
 * opaque immediates.  Lower the fixed legacy MCR/MRC and MCRR/MRRC layouts
 * here so callers can inspect every encoded field without depending on text. */
cdisasm_status cdisasm_arm_decode_a32_coprocessor_transfer(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    int is_long;
    int is_read;
    int is_t32 = instruction != NULL
        && instruction->isa_id == CDISASM_ARM_ISA_T32;

    /* With optional VFP decoding disabled, the scalar memory owner returns
     * unsupported.  Do not reinterpret the same encoding as coprocessor IO. */
    if (is_a32_vfp_scalar_memory_word(word)) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }

    /* VMOV between a core register pair and an S/D register is in the
     * coprocessor envelope but is owned by the VFP lowering below.  Do not
     * let the generic MCRR/MRRC recognizer turn its split register fields
     * into an invalid coprocessor transfer. */
    if ((word & UINT32_C(0x0ff00fd0)) == UINT32_C(0x0c400a10)
        || (word & UINT32_C(0x0ff00fd0)) == UINT32_C(0x0c500a10)
        || (word & UINT32_C(0x0ff00fd0)) == UINT32_C(0x0c400b10)
        || (word & UINT32_C(0x0ff00fd0)) == UINT32_C(0x0c500b10)) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }

    /* LDC/STC share the coprocessor space with MCR/MRC, but have a
     * completely different operand layout.  Keep them here rather than
     * letting the generated fallback leave p#/c# and the address opaque.
     * The T32 caller has already put the first halfword in bits 31:16, so
     * the same field extraction works for both encodings. */
    {
        static const struct {
            uint32_t mask;
            uint32_t value;
            uint16_t form_a32;
            uint16_t form_t32;
            uint8_t load;
            uint8_t literal;
        } ldst[] = {
            { UINT32_C(0x0e5fff00), UINT32_C(0x0c1f5e00),
              UINT16_C(520), UINT16_C(1505), 1u, 1u },
            { UINT32_C(0x0f70ff00), UINT32_C(0x0d005e00),
              UINT16_C(521), UINT16_C(1506), 0u, 0u },
            { UINT32_C(0x0f70ff00), UINT32_C(0x0c205e00),
              UINT16_C(522), UINT16_C(1507), 0u, 0u },
            { UINT32_C(0x0f70ff00), UINT32_C(0x0d205e00),
              UINT16_C(523), UINT16_C(1508), 0u, 0u },
            { UINT32_C(0x0ff0ff00), UINT32_C(0x0c805e00),
              UINT16_C(524), UINT16_C(1509), 0u, 0u },
            { UINT32_C(0x0f70ff00), UINT32_C(0x0d105e00),
              UINT16_C(525), UINT16_C(1510), 1u, 0u },
            { UINT32_C(0x0f70ff00), UINT32_C(0x0c305e00),
              UINT16_C(526), UINT16_C(1511), 1u, 0u },
            { UINT32_C(0x0f70ff00), UINT32_C(0x0d305e00),
              UINT16_C(527), UINT16_C(1512), 1u, 0u },
            { UINT32_C(0x0ff0ff00), UINT32_C(0x0c905e00),
              UINT16_C(528), UINT16_C(1513), 1u, 0u }
        };
        size_t index;

        for (index = 0u; index < sizeof(ldst) / sizeof(ldst[0]); ++index) {
            const uint32_t mask = ldst[index].mask;

            if ((word & mask) != ldst[index].value) {
                continue;
            }
#if !USE_EXTRA_OPCODES
            (void)required_capabilities;
            return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
            {
                unsigned p = (word >> 24) & 1u;
                unsigned u = (word >> 23) & 1u;
                unsigned n = (word >> 22) & 1u;
                unsigned w = (word >> 21) & 1u;
                unsigned rn = (word >> 16) & 15u;
                unsigned crd = (word >> 12) & 15u;
                unsigned coprocessor = (word >> 8) & 15u;
                unsigned offset = word & 255u;
                int64_t displacement = u
                    ? (int64_t)(offset << 2)
                    : -(int64_t)(offset << 2);
                cdisasm_arm_operand *memory;

                /* LDC_l is the architectural literal form.  It is the only
                 * form whose generated recipe fixes Rn to PC; all other
                 * forms still reject PC as an ordinary base when the
                 * encoding is not the literal leaf. */
                if (ldst[index].literal) {
                    rn = 15u;
                } else if (rn == 15u && p == 0u) {
                    return CDISASM_STATUS_INVALID_INSTRUCTION;
                }
                instruction->name_id = ldst[index].load
                    ? CDISASM_ARM_NAME_LDC : CDISASM_ARM_NAME_STC;
                instruction->form_id = is_t32
                    ? ldst[index].form_t32 : ldst[index].form_a32;
                instruction->condition = is_t32
                    ? CDISASM_ARM_CONDITION_AL
                    : (cdisasm_arm_condition)(word >> 28);

                /* Pack p#/c# as p in the low nibble and c in the high
                 * nibble.  This preserves both architectural selectors in
                 * the fixed ABI without inventing a string operand type. */
                append_immediate(instruction,
                    ((uint64_t)coprocessor)
                        | ((uint64_t)crd << 4), 1u);
                memory = append_operand(instruction);
                if (memory != NULL) {
                    memory->type = CDISASM_OPERAND_MEMORY;
                    memory->base_reg = a32_reg(rn);
        /* The literal LDC form is the long (double-word) coprocessor
         * transfer even though its N bit is not set in the encoding. */
        memory->size = (ldst[index].literal || n != 0u) ? 8u : 4u;
                    memory->access = ldst[index].load
                        ? CDISASM_OPERAND_ACCESS_READ
                        : CDISASM_OPERAND_ACCESS_WRITE;
                    if (offset != 0u) {
                        memory->imm = (uint64_t)displacement;
                        memory->flags = CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;
                        if (!u) {
                            memory->flags |= CDISASM_OPERAND_FLAG_SIGNED;
                        }
                    }
                    if (rn == 15u) {
                        uint64_t base = instruction->address
                            + (is_t32 ? UINT64_C(4) : UINT64_C(8));
                        memory->address = u
                            ? base + (uint64_t)(offset << 2)
                            : base - (uint64_t)(offset << 2);
                        memory->flags |= CDISASM_OPERAND_FLAG_HAS_ADDRESS
                            | CDISASM_OPERAND_FLAG_PC_RELATIVE;
                    }
                }
                if (p != 0u) {
                    instruction->instruction_flags |=
                        CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX;
                } else if (w != 0u) {
                    instruction->instruction_flags |=
                        CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX;
                }
                if (w != 0u) {
                    instruction->instruction_flags |=
                        CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
                }
                instruction->instruction_flags |= u != 0u
                    ? CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT
                    : CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT;
                apply_condition_group(instruction);
                cdisasm_arm_requirements_set_legacy(
                    required_capabilities, CDISASM_ARM_CAP_V4);
                return CDISASM_STATUS_OK;
            }
#endif
        }
    }

    if ((word & UINT32_C(0x0ff00e00)) == UINT32_C(0x0c400e00)
        || (word & UINT32_C(0x0ff00e00)) == UINT32_C(0x0c500e00)) {
        is_long = 1;
        is_read = (word & UINT32_C(0x00100000)) != 0u;
    } else if ((word & UINT32_C(0x0f100e10)) == UINT32_C(0x0e000e10)
        || (word & UINT32_C(0x0f100e10)) == UINT32_C(0x0e100e10)) {
        is_long = 0;
        is_read = (word & UINT32_C(0x00100000)) != 0u;
    } else {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
#if !USE_EXTRA_OPCODES
    (void)instruction;
    (void)required_capabilities;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    instruction->name_id = is_long
        ? (is_read ? CDISASM_ARM_NAME_MRRC : CDISASM_ARM_NAME_MCRR)
        : (is_read ? CDISASM_ARM_NAME_MRC : CDISASM_ARM_NAME_MCR);
    instruction->condition = is_t32
        ? CDISASM_ARM_CONDITION_AL
        : (cdisasm_arm_condition)(word >> 28);
    instruction->opcode_groups |= CDISASM_GROUP_PRIVILEGED;
    apply_condition_group(instruction);

    /* The public ARM ABI has four operand slots.  Pack the p#/opc#/CR*
     * selectors into one fixed-width immediate, then keep the transferred
     * GPRs as normal register operands.  Layout: short = p[3:0], opc1[6:4],
     * CRn[10:7], CRm[14:11], opc2[17:15]; long = p[3:0], opc1[7:4],
     * CRm[11:8]. */
    {
        uint64_t selectors = (word >> 8) & 15u;
        if (is_long) {
            selectors |= ((uint64_t)((word >> 4) & 15u)) << 4;
            selectors |= ((uint64_t)(word & 15u)) << 8;
        } else {
            selectors |= ((uint64_t)((word >> 21) & 7u)) << 4;
            selectors |= ((uint64_t)((word >> 16) & 15u)) << 7;
            selectors |= ((uint64_t)(word & 15u)) << 11;
            selectors |= ((uint64_t)((word >> 5) & 7u)) << 15;
        }
        append_immediate(instruction, selectors, 3u);
    }
    append_register(instruction, a32_reg((word >> 12) & 15u), 4u,
        is_read ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ);
    if (is_long) {
        append_register(instruction, a32_reg((word >> 16) & 15u), 4u,
            is_read ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ);
    }
    cdisasm_arm_requirements_set_legacy(
        required_capabilities, CDISASM_ARM_CAP_V4);
    return CDISASM_STATUS_OK;
#endif
}

static void mark_unpredictable(cdisasm_arm_instruction *instruction)
{
    instruction->instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_ILLEGAL
        | CDISASM_ARM_INSTRUCTION_FLAG_UNPREDICTABLE;
}

static void append_relative_target(
    cdisasm_arm_instruction *instruction,
    uint64_t target,
    int64_t displacement,
    uint8_t size)
{
    cdisasm_arm_operand *operand = append_immediate(instruction, target, size);
    if (operand != NULL) {
        operand->address = (uint64_t)displacement;
        operand->flags = CDISASM_OPERAND_FLAG_SIGNED
            | CDISASM_OPERAND_FLAG_PC_RELATIVE
            | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
    }
    instruction->branch_target = target;
    instruction->opcode_groups |= CDISASM_GROUP_RELATIVE_BRANCH;
}

/* A32 and Thumb-2 VFP multiple-register transfers.  The public operand ABI
 * represents the contiguous S/D register range as a vector register list;
 * retaining the encoded precision, start register, count and addressing bits
 * avoids manufacturing assembly text while still making every numeric field
 * available to callers.  The ED Thumb transport is canonicalized by the T32
 * decoder before reaching this routine. */
static cdisasm_status decode_a32_vfp_multiple(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    static const struct {
        uint32_t mask;
        uint32_t value;
        cdisasm_arm_name_id name;
        uint16_t form_a32;
        uint16_t form_t32;
        uint8_t load;
    } legacy_forms[] = {
        { UINT32_C(0x0fb00f01), UINT32_C(0x0d200b01),
          CDISASM_ARM_NAME_FSTMDBX, UINT16_C(503), UINT16_C(1488), 0u },
        { UINT32_C(0x0f900f01), UINT32_C(0x0c800b01),
          CDISASM_ARM_NAME_FSTMIAX, UINT16_C(504), UINT16_C(1489), 0u },
        { UINT32_C(0x0fb00f01), UINT32_C(0x0d300b01),
          CDISASM_ARM_NAME_FLDMDBX, UINT16_C(509), UINT16_C(1494), 1u },
        { UINT32_C(0x0f900f01), UINT32_C(0x0c900b01),
          CDISASM_ARM_NAME_FLDMIAX, UINT16_C(510), UINT16_C(1495), 1u }
    };
    size_t legacy_index;
    int is_t32 = instruction != NULL
        && instruction->isa_id == CDISASM_ARM_ISA_T32;

    /* The deprecated FSTM/FLDM X aliases use bit 0 as the X selector;
     * bits 7:1 carry the byte count.  They are not ordinary VSTM forms,
     * whose byte count may be even and whose bit 0 is zero. */
    for (legacy_index = 0u;
         legacy_index < sizeof(legacy_forms) / sizeof(legacy_forms[0]);
         ++legacy_index) {
        const uint32_t mask = legacy_forms[legacy_index].mask;

        if ((word & mask) != legacy_forms[legacy_index].value) {
            continue;
        }
#if !USE_EXTRA_OPCODES
        (void)required_capabilities;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        {
            unsigned encoded_bytes = word & 255u;
            unsigned count = (encoded_bytes & ~1u) / 2u;
            unsigned rn = (word >> 16) & 15u;
            unsigned vd = (word >> 12) & 15u;
            unsigned d_bit = (word >> 22) & 1u;
            cdisasm_arm_operand *list;

            if ((encoded_bytes & 1u) == 0u || count == 0u
                || count > 16u || rn == 15u) {
                return CDISASM_STATUS_INVALID_INSTRUCTION;
            }
            vd |= d_bit << 4;
            if (vd + count > 32u) {
                return CDISASM_STATUS_INVALID_INSTRUCTION;
            }
            instruction->name_id = legacy_forms[legacy_index].name;
            instruction->form_id = is_t32
                ? legacy_forms[legacy_index].form_t32
                : legacy_forms[legacy_index].form_a32;
            instruction->condition = is_t32
                ? CDISASM_ARM_CONDITION_AL
                : (cdisasm_arm_condition)(word >> 28);
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
                | ((word & UINT32_C(0x01000000)) != 0u
                    ? CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
                    : CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX)
                | ((word & UINT32_C(0x00800000)) != 0u
                    ? CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT
                    : CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT)
                | ((word & UINT32_C(0x00200000)) != 0u
                    ? CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK : 0u);
            append_register(instruction, a32_reg(rn), 4u,
                (word & UINT32_C(0x00200000)) != 0u
                    ? CDISASM_OPERAND_ACCESS_READ_WRITE
                    : CDISASM_OPERAND_ACCESS_READ);
            list = append_operand(instruction);
            if (list != NULL) {
                list->type = CDISASM_ARM_OPERAND_VECTOR_REGISTER_LIST;
                list->reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_D0 + vd);
                list->register_list = (uint16_t)count;
                list->size = 8u;
                list->extend_type = 8u;
                list->scale = 1u;
                list->access = legacy_forms[legacy_index].load
                    ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ;
            }
            apply_condition_group(instruction);
            cdisasm_arm_requirements_set_legacy(
                required_capabilities, CDISASM_ARM_CAP_V7
                    | CDISASM_ARM_CAP_VFP);
            return CDISASM_STATUS_OK;
        }
#endif
    }

    /* Core-pair VMOV shares the EC coprocessor envelope but has register
     * fields, not a VFP register-list byte count.  The exact VMOV owner
     * below validates and lowers its operands. */
    if ((word & UINT32_C(0x0ff00fd0)) == UINT32_C(0x0c400a10)
        || (word & UINT32_C(0x0ff00fd0)) == UINT32_C(0x0c500a10)
        || (word & UINT32_C(0x0ff00fd0)) == UINT32_C(0x0c400b10)
        || (word & UINT32_C(0x0ff00fd0)) == UINT32_C(0x0c500b10)
        || (word & UINT32_C(0x0ff00fd0)) == UINT32_C(0x0c000a10)
        || (word & UINT32_C(0x0ff00fd0)) == UINT32_C(0x0c100a10)
        || (word & UINT32_C(0x0ff00fd0)) == UINT32_C(0x0c000b10)
        || (word & UINT32_C(0x0ff00fd0)) == UINT32_C(0x0c100b10)) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }

    if (is_a32_vfp_scalar_memory_word(word)) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }

    uint32_t envelope = word & UINT32_C(0x0f000f00);
    int is_multiple = envelope == UINT32_C(0x0c000a00)
        || envelope == UINT32_C(0x0c000b00)
        || envelope == UINT32_C(0x0d000a00)
        || envelope == UINT32_C(0x0d000b00);
    int pre;
    int up;
    int writeback;
    int load;
    int double_precision;
    unsigned rn;
    unsigned vd;
    unsigned d_bit;
    unsigned encoded_bytes;
    unsigned count;
    unsigned first_reg;
    cdisasm_arm_name_id name;
    cdisasm_arm_reg_id register_base;
    uint8_t register_size;
    cdisasm_arm_operand *list;

    if (!is_multiple) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }

    pre = (word & UINT32_C(0x01000000)) != 0u;
    up = (word & UINT32_C(0x00800000)) != 0u;
    writeback = (word & UINT32_C(0x00200000)) != 0u;
    load = (word & UINT32_C(0x00100000)) != 0u;
    double_precision = (word & UINT32_C(0x00000100)) != 0u;
    rn = (word >> 16) & 15u;
    vd = (word >> 12) & 15u;
    d_bit = (word >> 22) & 1u;
    encoded_bytes = word & 255u;

    /* Only increment-after and decrement-before are allocated for this
     * encoding class.  DB forms require writeback; IA may be explicit or
     * omitted.  The low field is measured in 32-bit words: one S register
     * consumes one word and one D register consumes two. */
    if ((pre == up) || (pre && !writeback) || rn == 15u
        || encoded_bytes == 0u) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
    register_size = double_precision ? 8u : 4u;
    if (double_precision && (encoded_bytes & 1u) != 0u) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
    /* The architectural imm8 is measured in words.  A single-precision
     * register occupies one word, while a double-precision register spans
     * two; e.g. imm8=4 denotes four S registers or two D registers. */
    count = double_precision ? encoded_bytes / 2u : encoded_bytes;
    if (count == 0u || count > 32u) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
    /* Vd is D<4:1>:D<0> for D lists, and S<4:1>:S<0> for S lists. */
    first_reg = double_precision
        ? ((d_bit << 4) | vd)
        : ((d_bit << 4) | (vd << 1));
    if (first_reg + count > 32u) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
#if !USE_EXTRA_OPCODES
    (void)instruction;
    (void)required_capabilities;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    if (pre && !up) {
        name = load ? CDISASM_ARM_NAME_VLDMDB : CDISASM_ARM_NAME_VSTMDB;
    } else {
        name = load ? CDISASM_ARM_NAME_VLDM : CDISASM_ARM_NAME_VSTM;
    }
    register_base = double_precision ? CDISASM_ARM_REG_D0
                                     : CDISASM_ARM_REG_S0;
    instruction->name_id = name;
    instruction->instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
        | (pre ? CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
               : CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX)
        | (up ? CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT
              : CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT)
        | (writeback ? CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK : 0u);
    append_register(
        instruction, a32_reg(rn), 4u,
        writeback ? CDISASM_OPERAND_ACCESS_READ_WRITE
                  : CDISASM_OPERAND_ACCESS_READ);
    list = append_operand(instruction);
    if (list != NULL) {
        list->type = CDISASM_ARM_OPERAND_VECTOR_REGISTER_LIST;
        list->reg = (cdisasm_arm_reg_id)(register_base + first_reg);
        list->register_list = (uint16_t)count;
        list->size = register_size;
        list->extend_type = (cdisasm_arm_extend_type)register_size;
        list->scale = 1u;
        list->access = load ? CDISASM_OPERAND_ACCESS_WRITE
                            : CDISASM_OPERAND_ACCESS_READ;
    }
    apply_condition_group(instruction);
    cdisasm_arm_requirements_set_legacy(
        required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_VFP);
    return CDISASM_STATUS_OK;
#endif
}

/* Scalar VFP/FP16 transfers have a compact fixed layout shared by A32 and
 * Thumb-2.  Keep this owner ahead of the generated coprocessor leaves: the
 * public ABI can represent the VFP register and effective address exactly,
 * while the generated assembly recipe intentionally leaves the address
 * transform opaque. */
static cdisasm_status decode_a32_vfp_scalar_memory(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    unsigned precision = (word >> 8) & 3u;
    unsigned rn;
    unsigned vd;
    unsigned imm8;
    unsigned scale;
    uint8_t size;
    cdisasm_arm_reg_id base;
    cdisasm_arm_operand *memory;
    int load;
    int up;
    int is_t32;

    if (!is_a32_vfp_scalar_memory_word(word)) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if (precision < 1u || precision > 3u) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
#if !USE_EXTRA_OPCODES
    (void)instruction;
    (void)required_capabilities;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    is_t32 = instruction != NULL
        && instruction->isa_id == CDISASM_ARM_ISA_T32;
    load = (word & UINT32_C(0x00100000)) != 0u;
    up = (word & UINT32_C(0x00800000)) != 0u;
    rn = (word >> 16) & 15u;
    vd = precision == 3u
        ? (((word >> 18) & 16u) | ((word >> 12) & 15u))
        : (((word >> 11) & 30u) | ((word >> 22) & 1u));
    size = precision == 1u ? 2u : precision == 2u ? 4u : 8u;
    scale = precision == 1u ? 2u : 4u;
    imm8 = word & UINT32_C(0xff);

    instruction->name_id = load
        ? CDISASM_ARM_NAME_VLDR : CDISASM_ARM_NAME_VSTR;
    instruction->instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
    base = precision == 1u ? CDISASM_ARM_REG_H0
        : precision == 2u ? CDISASM_ARM_REG_S0 : CDISASM_ARM_REG_D0;
    append_register(instruction, (cdisasm_arm_reg_id)(base + vd), size,
        load ? CDISASM_OPERAND_ACCESS_WRITE
             : CDISASM_OPERAND_ACCESS_READ);
    memory = append_operand(instruction);
    if (memory != NULL) {
        int64_t displacement = (int64_t)(imm8 * scale);

        memory->type = CDISASM_OPERAND_MEMORY;
        memory->size = size;
        memory->base_reg = a32_reg(rn);
        memory->imm = up ? (uint64_t)displacement
                         : (uint64_t)-displacement;
        memory->access = load ? CDISASM_OPERAND_ACCESS_READ
                              : CDISASM_OPERAND_ACCESS_WRITE;
        if (imm8 != 0u) {
            memory->flags = CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;
            if (!up) {
                memory->flags |= CDISASM_OPERAND_FLAG_SIGNED;
            }
        }
        if (rn == 15u) {
            uint64_t base_address = instruction->address
                + (is_t32 ? UINT64_C(4) : UINT64_C(8));
            memory->address = up
                ? base_address + (uint64_t)displacement
                : base_address - (uint64_t)displacement;
            memory->flags |= CDISASM_OPERAND_FLAG_PC_RELATIVE
                | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
        }
    }
    apply_condition_group(instruction);
    cdisasm_arm_requirements_set_legacy(
        required_capabilities,
        (precision == 1u ? CDISASM_ARM_CAP_V8 : CDISASM_ARM_CAP_V7)
            | CDISASM_ARM_CAP_VFP
            | (precision == 1u ? CDISASM_ARM_CAP_FP16 : 0u));
    return CDISASM_STATUS_OK;
#endif
}

/* A32 unconditional Advanced SIMD structure transfers.  These encodings
 * share the 0xf4xx envelope with the generated catalogue, but the generated
 * operand recipes intentionally do not lower the D-register list and the
 * post-index form into the fixed public ABI.  Keep this small decoder ahead
 * of the ordinary NEON table so every numeric field remains available to
 * callers (D bit, Vd, element size, Rn and Rm/W).
 */
static cdisasm_status decode_a32_advsimd_structure(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    static const struct {
        uint8_t op;
        cdisasm_arm_name_id load_name;
        cdisasm_arm_name_id store_name;
        uint8_t count;
    } forms[] = {
        {0u, CDISASM_ARM_NAME_VLD4, CDISASM_ARM_NAME_VST4, 4u},
        {2u, CDISASM_ARM_NAME_VLD1, CDISASM_ARM_NAME_VST1, 4u},
        {4u, CDISASM_ARM_NAME_VLD3, CDISASM_ARM_NAME_VST3, 3u},
        {6u, CDISASM_ARM_NAME_VLD1, CDISASM_ARM_NAME_VST1, 3u},
        {7u, CDISASM_ARM_NAME_VLD1, CDISASM_ARM_NAME_VST1, 1u},
        {8u, CDISASM_ARM_NAME_VLD2, CDISASM_ARM_NAME_VST2, 2u},
        {10u, CDISASM_ARM_NAME_VLD1, CDISASM_ARM_NAME_VST1, 2u}
    };
    uint32_t fixed = word & UINT32_C(0xffb00f00);
    uint32_t structure_class = word & UINT32_C(0x0ff00000);
    unsigned op = (word >> 8) & 15u;
    unsigned index;
    unsigned rn;
    unsigned vd;
    unsigned element_shift;
    unsigned element_size;
    unsigned count;
    unsigned rm;
    unsigned lane = 0u;
    int single_element;
    int all_lanes = 0;
    int load;
    cdisasm_arm_name_id load_name = CDISASM_ARM_NAME_VLD1;
    cdisasm_arm_name_id store_name = CDISASM_ARM_NAME_VST1;
    cdisasm_arm_operand *list;
    cdisasm_arm_operand *memory;

    if ((structure_class != UINT32_C(0x04a00000)
            && structure_class != UINT32_C(0x04800000)
            && structure_class != UINT32_C(0x04200000)
            && structure_class != UINT32_C(0x04000000))
        || (fixed & UINT32_C(0xff000000)) != UINT32_C(0xf4000000)) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    single_element = (word & UINT32_C(0x00800000)) != 0u;
    load = (word & UINT32_C(0x00200000)) != 0u;
    if (single_element) {
        /* The single-element/all-lanes encodings use bits 11:8 for the
         * structure count and element width.  Stores have no all-lanes
         * variant; opcodes c..f are load replication forms. */
        if (!load && op >= 12u) {
            return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        if (op > 15u) {
            return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        count = (op & 3u) + 1u;
        /* Bits 11:10 select the element width.  Bits 9:8 select the
         * structure count; bits 7:4 are the lane/alignment field. */
        element_shift = (op >> 2) & 3u;
        all_lanes = op >= 12u;
        if ((element_shift == 3u && (!all_lanes || count != 1u))
            || count > 4u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        load_name = (cdisasm_arm_name_id)(CDISASM_ARM_NAME_VLD1
            + (count - 1u));
        store_name = (cdisasm_arm_name_id)(CDISASM_ARM_NAME_VST1
            + (count - 1u));
    } else {
        for (index = 0u; index < sizeof(forms) / sizeof(forms[0]); ++index) {
            if (forms[index].op == op) {
                break;
            }
        }
        if (index == sizeof(forms) / sizeof(forms[0])) {
            return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        }
        count = forms[index].count;
        element_shift = (word >> 6) & 3u;
        /* .64 is valid only for a one-register VLD1/VST1 structure. */
        if (element_shift == 3u && count != 1u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        load_name = forms[index].load_name;
        store_name = forms[index].store_name;
    }
#if !USE_EXTRA_OPCODES
    (void)instruction;
    (void)required_capabilities;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    rn = (word >> 16) & 15u;
    vd = ((word >> 12) & 15u) | (((word >> 22) & 1u) << 4);
    element_size = 1u << element_shift;
    rm = word & 15u;
    if (single_element && !all_lanes) {
        /* Bits 7:4 encode lane << (size + 1); bit 4 is the
         * alignment/control bit shared by the structure encodings. */
        lane = ((word >> 4) & 15u) >> (element_shift + 1u);
        if (lane >= 8u / element_size) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
    }

    /* Rn==PC and a wrapped D register list are architecturally reserved. */
    if (rn == 15u || vd + count > 32u) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
    /* 1111 means no writeback, 1101 means immediate pre-index writeback,
     * and the remaining values are post-index register writeback. */

    instruction->name_id = load ? load_name : store_name;
    instruction->condition = CDISASM_ARM_CONDITION_AL;
    instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
    list = append_operand(instruction);
    if (list != NULL) {
        list->type = CDISASM_ARM_OPERAND_VECTOR_REGISTER_LIST;
        list->reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_D0 + vd);
        list->register_list = (uint16_t)count;
        list->size = 8u;
        list->extend_type = (cdisasm_arm_extend_type)element_size;
        list->scale = (uint8_t)(8u / element_size);
        if (single_element && !all_lanes) {
            list->flags = CDISASM_ARM_OPERAND_FLAG_HAS_LANE;
            list->imm = lane;
        }
        list->access = load ? CDISASM_OPERAND_ACCESS_WRITE
                            : CDISASM_OPERAND_ACCESS_READ;
    }
    memory = append_operand(instruction);
    if (memory != NULL) {
        memory->type = CDISASM_OPERAND_MEMORY;
        memory->base_reg = a32_reg(rn);
        /* The memory record describes one element transfer; the vector-list
         * operand carries the structure count.  This keeps size in the
         * fixed ABI data-size set even for VLD3/VLD4. */
        memory->size = (uint8_t)element_size;
        memory->access = load ? CDISASM_OPERAND_ACCESS_READ
                              : CDISASM_OPERAND_ACCESS_WRITE;
        if (rm == 15u) {
            /* no writeback */
        } else if (rm != 13u) {
            memory->index_reg = a32_reg(rm);
        }
    }
    if (rm == 13u) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
    } else if (rm != 15u) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
    }
    cdisasm_arm_requirements_set_legacy(
        required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
    return CDISASM_STATUS_OK;
#endif
}

cdisasm_status cdisasm_arm_decode_a32_neon(
    uint32_t canonical_word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    const uint32_t scalar_fp_form =
        canonical_word & UINT32_C(0x0fb00f50);
    const uint32_t scalar_fp_operation =
        scalar_fp_form & ~UINT32_C(0x00000300);
    const unsigned scalar_fp_precision = (canonical_word >> 8) & 3u;
    const uint32_t size_variable_form =
        canonical_word & UINT32_C(0xff800f10);
    const uint32_t fixed_size_form =
        canonical_word & UINT32_C(0xffb00f10);
    unsigned size_code = (canonical_word >> 20) & 3u;
    unsigned vd = ((canonical_word >> 18) & 16u)
        | ((canonical_word >> 12) & 15u);
    unsigned vn = ((canonical_word >> 3) & 16u)
        | ((canonical_word >> 16) & 15u);
    unsigned vm = ((canonical_word >> 1) & 16u)
        | (canonical_word & 15u);
    int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
    uint8_t total_size = is_quad ? 16u : 8u;
    uint8_t element_size;
    int floating_point = 0;
    int accumulator_destination = 0;

    {
        cdisasm_status scalar_memory_status =
            decode_a32_vfp_scalar_memory(
                canonical_word, instruction, required_capabilities);
        if (scalar_memory_status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
            return scalar_memory_status;
        }
    }

    {
        cdisasm_status vfp_multiple_status = decode_a32_vfp_multiple(
            canonical_word, instruction, required_capabilities);
        if (vfp_multiple_status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
            return vfp_multiple_status;
        }
    }

    {
        cdisasm_status structure_status = decode_a32_advsimd_structure(
            canonical_word, instruction, required_capabilities);
        if (structure_status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
            return structure_status;
        }
    }

    /* JSCVT overlaps broader scalar VFP classifiers below, so establish its
     * exact owner before those legacy families can reject the encoding. */
    if ((canonical_word & UINT32_C(0x0fbf0fd0))
            == UINT32_C(0x0eb90bc0)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned rd = ((canonical_word >> 11) & 30u)
            | ((canonical_word >> 22) & 1u);
        unsigned rm = ((canonical_word >> 1) & 16u)
            | (canonical_word & 15u);

        instruction->name_id = CDISASM_ARM_NAME_VJCVT;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_register(instruction,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0 + rd), 4u,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_register(instruction,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_D0 + rm), 8u,
            CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_VFP);
        (void)cdisasm_arm_requirements_add_feature(
            required_capabilities, CDISASM_ARM_FEATURE_JSCVT);
        return CDISASM_STATUS_OK;
#endif
    }

    /* This encoding overlaps broader legacy masks below, so route it to its
     * exact owner before those families can claim it. */
    if ((canonical_word & UINT32_C(0xffb00c50))
            == UINT32_C(0xf3b00800)
        || (canonical_word & UINT32_C(0xffb00c50))
            == UINT32_C(0xf3b00840)) {
        goto decode_advsimd_table_lookup;
    }
    if ((canonical_word & UINT32_C(0xffb00f90))
            == UINT32_C(0xf3b00c00)) {
        goto decode_advsimd_scalar_dup;
    }

    /* A32/T32 vector floating-point-to-integer conversions with explicit
     * rounding direction.  Bit 7 selects unsigned output, bits 9:8 select
     * A/N/P/M, and bit 6 selects D/Q width. */
    if ((canonical_word & UINT32_C(0xffb30c10))
            == UINT32_C(0xf3b30000)) {
        static const cdisasm_arm_name_id names[4] = {
            CDISASM_ARM_NAME_VCVTA, CDISASM_ARM_NAME_VCVTN,
            CDISASM_ARM_NAME_VCVTP, CDISASM_ARM_NAME_VCVTM
        };
        unsigned operation = (canonical_word >> 8) & 3u;

        if (is_quad && ((vd | vm) & 1u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)names;
        (void)operation;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = names[operation];
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            total_size, 4u, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            total_size, 4u, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    /* Advanced SIMD vector fixed-point conversion.  This space overlaps the
     * modified-immediate classifier below; imm6 encodes 64-fbits while bits
     * 24 and 8 select signedness and conversion direction. */
    if ((canonical_word & UINT32_C(0xfea00c90))
            == UINT32_C(0xf2a00c10)) {
        unsigned imm6 = (canonical_word >> 16) & 63u;

        if (is_quad && ((vd | vm) & 1u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)imm6;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_VCVT;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            total_size, 4u, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            total_size, 4u, CDISASM_OPERAND_ACCESS_READ);
        append_immediate(instruction, 64u - imm6, 1u);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    /* A32/T32 Advanced SIMD vector integer/single-precision conversion.
     * Bit 8 selects float-to-integer versus integer-to-float and bit 7
     * selects signed versus unsigned integer lanes.  Those type choices do
     * not change the structured operand shape, but the fixed form identity
     * and raw opcode preserve them exactly. */
    if ((canonical_word & UINT32_C(0xffb30e10))
            == UINT32_C(0xf3b30600)) {
        if (is_quad && ((vd | vm) & 1u) != 0u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_VCVT;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            total_size, 4u, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            total_size, 4u, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    /* A32/T32 Advanced SIMD half/single conversion.  The two directions
     * have asymmetric register widths: F16->F32 widens D to Q, while
     * F32->F16 narrows Q to D. */
    if ((canonical_word & UINT32_C(0xffb30ed0))
            == UINT32_C(0xf3b20600)) {
        int widening = (canonical_word & UINT32_C(0x100)) != 0u;

        if ((widening && (vd & 1u)) || (!widening && (vm & 1u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_VCVT;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_vector_register(instruction,
            a32_vector_reg(vd, widening), widening ? 16u : 8u,
            widening ? 4u : 2u, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction,
            a32_vector_reg(vm, !widening), widening ? 8u : 16u,
            widening ? 2u : 4u, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    /* FEAT_AA32BF16 vector narrowing conversion: four F32 elements in Qm
     * become four BF16 elements in Dd. */
    if ((canonical_word & UINT32_C(0xffbf0fd0))
            == UINT32_C(0xf3b60640)) {
        if ((vm & 1u) != 0u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_VCVT;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_vector_register(instruction, a32_vector_reg(vd, 0),
            8u, 2u, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vm, 1),
            16u, 4u, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_NEON);
        (void)cdisasm_arm_requirements_add_feature(
            required_capabilities, CDISASM_ARM_FEATURE_BF16);
        return CDISASM_STATUS_OK;
#endif
    }

    /* VMOVL is the zero-shift canonical owner of the widening-shift space. */
    if ((canonical_word & UINT32_C(0xfe870fd0))
            == UINT32_C(0xf2800a10)) {
        unsigned imm6 = (canonical_word >> 16) & 63u;
        unsigned source_element_size = imm6 == 8u ? 1u
            : imm6 == 16u ? 2u : imm6 == 32u ? 4u : 0u;
        unsigned destination = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned source = ((canonical_word >> 1) & 16u)
            | (canonical_word & 15u);

        if (source_element_size == 0u || (destination & 1u) != 0u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)source;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_VMOVL;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(destination, 1),
            16u, (uint8_t)(source_element_size * 2u),
            CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(source, 0),
            8u, (uint8_t)source_element_size,
            CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    /* VSHLL (immediate) has two encodings shared by A32 and T32.  A1/T1
     * carries imm6 in bits 21:16; the highest set bit selects the source
     * element width and the remaining bits are the shift.  A zero shift is
     * the VMOVL alias and is deliberately left to its canonical owner.  The
     * A2/T2 encoding represents the otherwise-unencodable full-width shift. */
    if ((canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b20300)
        || ((canonical_word & UINT32_C(0xfe800fd0))
                == UINT32_C(0xf2800a10)
            && (canonical_word & UINT32_C(0xfeb80df0))
                != UINT32_C(0xf2800810)
            && (canonical_word & UINT32_C(0xfeb80df0))
                != UINT32_C(0xf2800830))) {
        int full_width = (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b20300);
        unsigned source_element_shift;
        unsigned shift;
        unsigned destination = ((canonical_word >> 18) & 16u)
            | ((canonical_word >> 12) & 15u);

        if (full_width) {
            source_element_shift = (canonical_word >> 18) & 3u;
            if (source_element_shift == 3u) {
                return CDISASM_STATUS_INVALID_INSTRUCTION;
            }
            shift = 8u << source_element_shift;
        } else {
            unsigned imm6 = (canonical_word >> 16) & 63u;

            if (imm6 < 8u) {
                return CDISASM_STATUS_INVALID_INSTRUCTION;
            }
            source_element_shift = imm6 >= 32u ? 2u
                : imm6 >= 16u ? 1u : 0u;
            shift = imm6 - (8u << source_element_shift);
            if (shift == 0u) {
                return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
            }
        }
        if ((destination & 1u) != 0u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned source = ((canonical_word >> 1) & 16u)
            | (canonical_word & 15u);

        element_size = (uint8_t)(1u << source_element_shift);
        instruction->name_id = CDISASM_ARM_NAME_VSHLL;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(destination, 1),
            16u, (uint8_t)(element_size * 2u),
            CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(source, 0),
            8u, element_size, CDISASM_OPERAND_ACCESS_READ);
        append_immediate(instruction, shift, 1u);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    /* A32/T32 Advanced SIMD widening integer multiply and saturating
     * doubling multiply-long forms.  The destination is always a Q register
     * while both vector sources are D registers. */
    if ((canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf2800900)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf2800b00)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf2800d00)
        || (canonical_word & UINT32_C(0xfe800d50))
            == UINT32_C(0xf2800c00)) {
        int ordinary = (canonical_word & UINT32_C(0xfe800d50))
            == UINT32_C(0xf2800c00);
        unsigned element_shift = (canonical_word >> 20) & 3u;
        unsigned destination = ((canonical_word >> 18) & 16u)
            | ((canonical_word >> 12) & 15u);

        if ((!ordinary && element_shift != 1u && element_shift != 2u)
            || (ordinary && element_shift == 3u)
            || (destination & 1u) != 0u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        uint32_t saturating_form =
            canonical_word & UINT32_C(0xff800f50);
        unsigned first_source = ((canonical_word >> 3) & 16u)
            | ((canonical_word >> 16) & 15u);
        unsigned second_source = ((canonical_word >> 1) & 16u)
            | (canonical_word & 15u);
        cdisasm_operand_access destination_access;

        element_size = (uint8_t)(1u << element_shift);
        if (ordinary) {
            instruction->name_id = CDISASM_ARM_NAME_VMULL;
            destination_access = CDISASM_OPERAND_ACCESS_WRITE;
        } else if (saturating_form == UINT32_C(0xf2800900)) {
            instruction->name_id = CDISASM_ARM_NAME_VQDMLAL;
            destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        } else if (saturating_form == UINT32_C(0xf2800b00)) {
            instruction->name_id = CDISASM_ARM_NAME_VQDMLSL;
            destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        } else {
            instruction->name_id = CDISASM_ARM_NAME_VQDMULL;
            destination_access = CDISASM_OPERAND_ACCESS_WRITE;
        }
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(destination, 1),
            16u, (uint8_t)(element_size * 2u), destination_access);
        append_vector_register(instruction, a32_vector_reg(first_source, 0),
            8u, element_size, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(second_source, 0),
            8u, element_size, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    /* Indexed scalar companions of the widening multiply-long forms. */
    if ((canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf2800340)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf2800740)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf2800b40)
        || ((canonical_word & UINT32_C(0xfe800f50))
                == UINT32_C(0xf2800a40)
            && (canonical_word & UINT32_C(0xffb00050))
                != UINT32_C(0xf2b00000)
            && (canonical_word & UINT32_C(0xffb00050))
                != UINT32_C(0xf2b00040))) {
        unsigned element_shift = (canonical_word >> 20) & 3u;
        unsigned destination = ((canonical_word >> 18) & 16u)
            | ((canonical_word >> 12) & 15u);

        if ((element_shift != 1u && element_shift != 2u)
            || (destination & 1u) != 0u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        int ordinary = (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2800a40);
        uint32_t saturating_form =
            canonical_word & UINT32_C(0xff800f50);
        unsigned first_source = ((canonical_word >> 3) & 16u)
            | ((canonical_word >> 16) & 15u);
        unsigned indexed_register;
        uint64_t lane;
        cdisasm_operand_access destination_access;
        cdisasm_arm_operand *indexed_operand;

        element_size = (uint8_t)(1u << element_shift);
        if (element_shift == 1u) {
            indexed_register = (canonical_word >> 1) & 7u;
            lane = (uint64_t)(((canonical_word >> 5) & 1u) << 1)
                | (uint64_t)(canonical_word & 1u);
        } else {
            indexed_register = canonical_word & 15u;
            lane = (uint64_t)((canonical_word >> 5) & 1u);
        }
        if (ordinary) {
            instruction->name_id = CDISASM_ARM_NAME_VMULL;
            destination_access = CDISASM_OPERAND_ACCESS_WRITE;
        } else if (saturating_form == UINT32_C(0xf2800340)) {
            instruction->name_id = CDISASM_ARM_NAME_VQDMLAL;
            destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        } else if (saturating_form == UINT32_C(0xf2800740)) {
            instruction->name_id = CDISASM_ARM_NAME_VQDMLSL;
            destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        } else {
            instruction->name_id = CDISASM_ARM_NAME_VQDMULL;
            destination_access = CDISASM_OPERAND_ACCESS_WRITE;
        }
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(destination, 1),
            16u, (uint8_t)(element_size * 2u), destination_access);
        append_vector_register(instruction, a32_vector_reg(first_source, 0),
            8u, element_size, CDISASM_OPERAND_ACCESS_READ);
        indexed_operand = append_vector_register(instruction,
            a32_vector_reg(indexed_register, 0), 8u, element_size,
            CDISASM_OPERAND_ACCESS_READ);
        if (indexed_operand != NULL) {
            indexed_operand->flags = CDISASM_ARM_OPERAND_FLAG_HAS_LANE;
            indexed_operand->imm = lane;
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word >> 28) != CDISASM_ARM_CONDITION_NV
        && (((canonical_word & UINT32_C(0x0ff00fff))
                    == UINT32_C(0x0ee00a10))
            || ((canonical_word & UINT32_C(0x0ff00fff))
                    == UINT32_C(0x0ef00a10)))) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        int read_status = (canonical_word & UINT32_C(0x00100000)) != 0;
        unsigned rt = (canonical_word >> 12) & 15u;

        instruction->name_id = read_status
            ? CDISASM_ARM_NAME_VMRS : CDISASM_ARM_NAME_VMSR;
        if (instruction->isa_id == CDISASM_ARM_ISA_T32) {
            instruction->form_id = read_status
                ? UINT16_C(1519) : UINT16_C(1518);
        }
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        if (read_status) {
            append_register(instruction, a32_reg(rt), 4u,
                CDISASM_OPERAND_ACCESS_WRITE);
            append_system_operand(instruction,
                CDISASM_ARM_OPERAND_SYSTEM_REGISTER, 0u,
                CDISASM_OPERAND_ACCESS_READ);
        } else {
            append_system_operand(instruction,
                CDISASM_ARM_OPERAND_SYSTEM_REGISTER, 0u,
                CDISASM_OPERAND_ACCESS_WRITE);
            append_register(instruction, a32_reg(rt), 4u,
                CDISASM_OPERAND_ACCESS_READ);
        }
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_VFP);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word >> 28) != CDISASM_ARM_CONDITION_NV
        && (((canonical_word & UINT32_C(0x0fb00f5f))
                    == UINT32_C(0x0ea00b10))
            || ((canonical_word & UINT32_C(0x0fb00f5f))
                    == UINT32_C(0x0e800b10)))) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        int duplicate_quad = (canonical_word & UINT32_C(0x00200000)) != 0;
        unsigned duplicate_vd = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned rt = (canonical_word >> 12) & 15u;
        uint8_t duplicate_element =
            (canonical_word & UINT32_C(0x00400000)) != 0u ? 1u
            : (canonical_word & UINT32_C(0x20)) != 0u ? 2u : 4u;
        uint8_t duplicate_size = duplicate_quad ? 16u : 8u;

        if ((duplicate_quad && (duplicate_vd & 1u)) || rt == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = CDISASM_ARM_NAME_VDUP;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction,
            a32_vector_reg(duplicate_vd, duplicate_quad), duplicate_size,
            duplicate_element, CDISASM_OPERAND_ACCESS_WRITE);
        append_register(instruction, a32_reg(rt), 4u,
            CDISASM_OPERAND_ACCESS_READ);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word >> 28) != CDISASM_ARM_CONDITION_NV
        && (((canonical_word & UINT32_C(0x0fbf0fd0))
                    == UINT32_C(0x0eb20a40))
            || ((canonical_word & UINT32_C(0x0fbf0fd0))
                    == UINT32_C(0x0eb20b40))
            || ((canonical_word & UINT32_C(0x0fbf0fd0))
                    == UINT32_C(0x0eb30a40))
            || ((canonical_word & UINT32_C(0x0fbf0fd0))
                    == UINT32_C(0x0eb30b40))
            || ((canonical_word & UINT32_C(0x0fbf0fd0))
                    == UINT32_C(0x0eb20ac0))
            || ((canonical_word & UINT32_C(0x0fbf0fd0))
                    == UINT32_C(0x0eb20bc0))
            || ((canonical_word & UINT32_C(0x0fbf0fd0))
                    == UINT32_C(0x0eb30ac0))
            || ((canonical_word & UINT32_C(0x0fbf0fd0))
                    == UINT32_C(0x0eb30bc0))
            || ((canonical_word & UINT32_C(0x0fbf0fd0))
                    == UINT32_C(0x0eb30940))
            || ((canonical_word & UINT32_C(0x0fbf0fd0))
                    == UINT32_C(0x0eb309c0)))) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned precision = (canonical_word >> 8) & 3u;
        int top = (canonical_word & UINT32_C(0x00010000)) != 0;
        int use_top = (canonical_word & UINT32_C(0x80)) != 0;
        unsigned scalar_vd = ((canonical_word >> 11) & 30u)
            | ((canonical_word >> 22) & 1u);
        unsigned scalar_vm = ((canonical_word & 15u) << 1)
            | ((canonical_word >> 5) & 1u);
        unsigned double_vd = ((canonical_word >> 18) & 16u)
            | ((canonical_word >> 12) & 15u);
        unsigned double_vm = ((canonical_word >> 1) & 16u)
            | (canonical_word & 15u);
        cdisasm_arm_reg_id destination_base;
        cdisasm_arm_reg_id source_base;
        unsigned destination_index;
        unsigned source_index;
        uint8_t destination_size;
        uint8_t source_size;

        if (top) {
            destination_base = CDISASM_ARM_REG_H0;
            destination_index = scalar_vd;
            destination_size = 2u;
            source_base = precision == 3u
                ? CDISASM_ARM_REG_D0 : CDISASM_ARM_REG_S0;
            source_index = precision == 3u ? double_vm : scalar_vm;
            source_size = precision == 3u ? 8u : 4u;
        } else {
            destination_base = precision == 3u
                ? CDISASM_ARM_REG_D0 : CDISASM_ARM_REG_S0;
            destination_index = precision == 3u ? double_vd : scalar_vd;
            destination_size = precision == 3u ? 8u : 4u;
            source_base = CDISASM_ARM_REG_H0;
            source_index = scalar_vm;
            source_size = 2u;
        }

        instruction->name_id = use_top
            ? CDISASM_ARM_NAME_VCVTT : CDISASM_ARM_NAME_VCVTB;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_register(instruction,
            (cdisasm_arm_reg_id)(destination_base + destination_index),
            destination_size, CDISASM_OPERAND_ACCESS_WRITE);
        append_register(instruction,
            (cdisasm_arm_reg_id)(source_base + source_index),
            source_size, CDISASM_OPERAND_ACCESS_READ);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_VFP
                | CDISASM_ARM_CAP_FP16);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word >> 28) != CDISASM_ARM_CONDITION_NV
        && (((canonical_word & UINT32_C(0x0fbf0fd0))
                    == UINT32_C(0x0eb40940))
            || ((canonical_word & UINT32_C(0x0fbf0fd0))
                    == UINT32_C(0x0eb40a40))
            || ((canonical_word & UINT32_C(0x0fbf0fd0))
                    == UINT32_C(0x0eb40b40))
            || ((canonical_word & UINT32_C(0x0fbf0fd0))
                    == UINT32_C(0x0eb409c0))
            || ((canonical_word & UINT32_C(0x0fbf0fd0))
                    == UINT32_C(0x0eb40ac0))
            || ((canonical_word & UINT32_C(0x0fbf0fd0))
                    == UINT32_C(0x0eb40bc0))
            || ((canonical_word & UINT32_C(0x0fbf0fff))
                    == UINT32_C(0x0eb50940))
            || ((canonical_word & UINT32_C(0x0fbf0fff))
                    == UINT32_C(0x0eb50a40))
            || ((canonical_word & UINT32_C(0x0fbf0fff))
                    == UINT32_C(0x0eb50b40))
            || ((canonical_word & UINT32_C(0x0fbf0fff))
                    == UINT32_C(0x0eb509c0))
            || ((canonical_word & UINT32_C(0x0fbf0fff))
                    == UINT32_C(0x0eb50ac0))
            || ((canonical_word & UINT32_C(0x0fbf0fff))
                    == UINT32_C(0x0eb50bc0)))) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned precision = (canonical_word >> 8) & 3u;
        int with_exception = (canonical_word & UINT32_C(0x80)) != 0;
        int compare_zero = (canonical_word & UINT32_C(0x00010000)) != 0;
        int is_double = precision == 3u;
        unsigned fp_vd = is_double
            ? (((canonical_word >> 18) & 16u)
                | ((canonical_word >> 12) & 15u))
            : (((canonical_word >> 11) & 30u)
                | ((canonical_word >> 22) & 1u));
        unsigned fp_vm = is_double
            ? (((canonical_word >> 1) & 16u)
                | (canonical_word & 15u))
            : (((canonical_word & 15u) << 1)
                | ((canonical_word >> 5) & 1u));
        cdisasm_arm_reg_id base = precision == 1u ? CDISASM_ARM_REG_H0
            : precision == 2u ? CDISASM_ARM_REG_S0 : CDISASM_ARM_REG_D0;
        uint8_t size = precision == 1u ? 2u : precision == 2u ? 4u : 8u;

        instruction->name_id = with_exception
            ? CDISASM_ARM_NAME_VCMPE : CDISASM_ARM_NAME_VCMP;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
            | CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
        append_register(instruction, (cdisasm_arm_reg_id)(base + fp_vd),
            size, CDISASM_OPERAND_ACCESS_READ);
        if (compare_zero) {
            append_immediate(instruction, 0u, 1u);
        } else {
            append_register(instruction,
                (cdisasm_arm_reg_id)(base + fp_vm), size,
                CDISASM_OPERAND_ACCESS_READ);
        }
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities,
            (precision == 1u ? CDISASM_ARM_CAP_V8 : CDISASM_ARM_CAP_V7)
                | CDISASM_ARM_CAP_VFP
                | (precision == 1u ? CDISASM_ARM_CAP_FP16 : 0u));
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0x0f300f00))
            == UINT32_C(0x0d000900)
        || (canonical_word & UINT32_C(0x0f300f00))
            == UINT32_C(0x0d000a00)
        || (canonical_word & UINT32_C(0x0f300f00))
            == UINT32_C(0x0d000b00)
        || (canonical_word & UINT32_C(0x0f300f00))
            == UINT32_C(0x0d100900)
        || (canonical_word & UINT32_C(0x0f300f00))
            == UINT32_C(0x0d100a00)
        || (canonical_word & UINT32_C(0x0f300f00))
            == UINT32_C(0x0d100b00)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned precision = (canonical_word >> 8) & 3u;
        int load = (canonical_word & UINT32_C(0x00100000)) != 0;
        int up = (canonical_word & UINT32_C(0x00800000)) != 0;
        unsigned rn = (canonical_word >> 16) & 15u;
        unsigned fp_vd = precision == 3u
            ? (((canonical_word >> 18) & 16u)
                | ((canonical_word >> 12) & 15u))
            : (((canonical_word >> 11) & 30u)
                | ((canonical_word >> 22) & 1u));
        uint32_t displacement = (canonical_word & 0xffu)
            << (precision == 1u ? 1u : 2u);
        uint8_t data_size = precision == 1u ? 2u
            : precision == 2u ? 4u : 8u;
        cdisasm_arm_reg_id base = precision == 1u ? CDISASM_ARM_REG_H0
            : precision == 2u ? CDISASM_ARM_REG_S0 : CDISASM_ARM_REG_D0;
        cdisasm_arm_operand *memory;

        instruction->name_id = load
            ? CDISASM_ARM_NAME_VLDR : CDISASM_ARM_NAME_VSTR;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_register(instruction, (cdisasm_arm_reg_id)(base + fp_vd),
            data_size, load ? CDISASM_OPERAND_ACCESS_WRITE
                            : CDISASM_OPERAND_ACCESS_READ);
        memory = append_operand(instruction);
        if (memory != NULL) {
            memory->type = CDISASM_OPERAND_MEMORY;
            memory->size = data_size;
            memory->base_reg = a32_reg(rn);
            memory->imm = up ? displacement
                : (uint64_t)-(int64_t)displacement;
            memory->access = load ? CDISASM_OPERAND_ACCESS_READ
                                  : CDISASM_OPERAND_ACCESS_WRITE;
            if (displacement != 0u) {
                memory->flags |= CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;
                if (!up) {
                    memory->flags |= CDISASM_OPERAND_FLAG_SIGNED;
                }
            }
        }
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities,
            (precision == 1u ? CDISASM_ARM_CAP_V8 : CDISASM_ARM_CAP_V7)
                | CDISASM_ARM_CAP_VFP
                | (precision == 1u ? CDISASM_ARM_CAP_FP16 : 0u));
        return CDISASM_STATUS_OK;
#endif
    }

    /* FEAT_FHM indexed widening fused multiply-add/subtract.  D forms use
     * an S source split into two F16 lanes; Q forms use a four-lane D
     * source.  M and Vm<3> provide the otherwise-overloaded register/lane
     * selector bits. */
    if ((canonical_word & UINT32_C(0xffa00f10))
            == UINT32_C(0xfe000810)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0u;
        int subtract = (canonical_word & UINT32_C(0x00100000)) != 0u;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn_field = (canonical_word >> 16) & 15u;
        unsigned n = (canonical_word >> 7) & 1u;
        unsigned vm_field = canonical_word & 15u;
        unsigned m = (canonical_word >> 5) & 1u;
        unsigned source_reg;
        unsigned lane;
        cdisasm_arm_operand *source;

        if (is_quad && (vd & 1u) != 0u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = subtract
            ? CDISASM_ARM_NAME_VFMSL : CDISASM_ARM_NAME_VFMAL;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
            | CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            is_quad ? 16u : 8u, 4u,
            CDISASM_OPERAND_ACCESS_READ_WRITE);
        if (is_quad) {
            append_vector_register(instruction,
                a32_vector_reg(vn_field | (n << 4), 0), 8u, 2u,
                CDISASM_OPERAND_ACCESS_READ);
            source_reg = vm_field & 7u;
            lane = (m << 1) | (vm_field >> 3);
            source = append_vector_register(instruction,
                a32_vector_reg(source_reg, 0), 8u, 2u,
                CDISASM_OPERAND_ACCESS_READ);
        } else {
            append_vector_register(instruction,
                (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0
                    + (vn_field << 1) + n), 4u, 2u,
                CDISASM_OPERAND_ACCESS_READ);
            source_reg = ((vm_field & 7u) << 1) | m;
            lane = vm_field >> 3;
            source = append_vector_register(instruction,
                (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0 + source_reg),
                4u, 2u, CDISASM_OPERAND_ACCESS_READ);
        }
        if (source != NULL) {
            source->flags = CDISASM_ARM_OPERAND_FLAG_HAS_LANE;
            source->imm = lane;
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_NEON);
        (void)cdisasm_arm_requirements_add_feature(
            required_capabilities, CDISASM_ARM_FEATURE_FHM);
        return CDISASM_STATUS_OK;
#endif
    }

    /* FEAT_AA32BF16 VFMAB/VFMAT.  Bit 6 selects bottom/top half while
     * both encodings operate on Q registers; the indexed form packs Dm in
     * Vm<2:0> and the four-lane selector in M:Vm<3>. */
    if ((canonical_word & UINT32_C(0xffb00f10))
            == UINT32_C(0xfc300810)
        || (canonical_word & UINT32_C(0xffb00f10))
            == UINT32_C(0xfe300810)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        int indexed = (canonical_word & UINT32_C(0x02000000)) != 0u;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        cdisasm_arm_operand *source;

        if ((vd & 1u) != 0u || (vn & 1u) != 0u
            || (!indexed && (vm & 1u) != 0u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = CDISASM_ARM_NAME_VFMA;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
            | CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, 1),
            16u, 2u, CDISASM_OPERAND_ACCESS_READ_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, 1),
            16u, 2u, CDISASM_OPERAND_ACCESS_READ);
        if (indexed) {
            unsigned dm = canonical_word & 7u;
            unsigned lane = ((canonical_word >> 4) & 2u)
                | ((canonical_word >> 3) & 1u);

            source = append_vector_register(instruction,
                a32_vector_reg(dm, 0), 8u, 2u,
                CDISASM_OPERAND_ACCESS_READ);
            if (source != NULL) {
                source->flags = CDISASM_ARM_OPERAND_FLAG_HAS_LANE;
                source->imm = lane;
            }
        } else {
            append_vector_register(instruction, a32_vector_reg(vm, 1),
                16u, 2u, CDISASM_OPERAND_ACCESS_READ);
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_NEON);
        (void)cdisasm_arm_requirements_add_feature(
            required_capabilities, CDISASM_ARM_FEATURE_BF16);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffb00f50))
            == UINT32_C(0xfc200810)
        || (canonical_word & UINT32_C(0xffb00f50))
            == UINT32_C(0xfc200850)
        || (canonical_word & UINT32_C(0xffb00f50))
            == UINT32_C(0xfca00810)
        || (canonical_word & UINT32_C(0xffb00f50))
            == UINT32_C(0xfca00850)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        int subtract = (canonical_word & UINT32_C(0x00800000)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn_field = (canonical_word >> 16) & 15u;
        unsigned vm_field = canonical_word & 15u;
        unsigned n = (canonical_word >> 7) & 1u;
        unsigned m = (canonical_word >> 5) & 1u;
        uint8_t size = is_quad ? 16u : 8u;

        if (is_quad && (vd & 1u) != 0u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = subtract
            ? CDISASM_ARM_NAME_VFMSL : CDISASM_ARM_NAME_VFMAL;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
            | CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            size, 4u, CDISASM_OPERAND_ACCESS_READ_WRITE);
        if (is_quad) {
            append_vector_register(instruction,
                a32_vector_reg(vn_field | (n << 4), 0), 8u, 2u,
                CDISASM_OPERAND_ACCESS_READ);
            append_vector_register(instruction,
                a32_vector_reg(vm_field | (m << 4), 0), 8u, 2u,
                CDISASM_OPERAND_ACCESS_READ);
        } else {
            append_vector_register(instruction,
                (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0
                    + (vn_field << 1) + n), 4u, 2u,
                CDISASM_OPERAND_ACCESS_READ);
            append_vector_register(instruction,
                (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0
                    + (vm_field << 1) + m), 4u, 2u,
                CDISASM_OPERAND_ACCESS_READ);
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_NEON);
        (void)cdisasm_arm_requirements_add_feature(
            required_capabilities, CDISASM_ARM_FEATURE_FHM);
        return CDISASM_STATUS_OK;
#endif
    }

    /* FEAT_FCMA indexed complex multiply-add.  F16 selects one of two
     * complex pairs in Dm with M; F32 consumes the sole complex pair and
     * uses M as Dm<4>.  Bits 21:20 encode rotation/90. */
    if ((canonical_word & UINT32_C(0xff000f10))
            == UINT32_C(0xfe000800)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        int single_precision =
            (canonical_word & UINT32_C(0x00800000)) != 0u;
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0u;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm_field = canonical_word & 15u;
        unsigned m = (canonical_word >> 5) & 1u;
        unsigned vm = single_precision ? vm_field | (m << 4) : vm_field;
        unsigned lane = single_precision ? 0u : m;
        unsigned rotation = ((canonical_word >> 20) & 3u) * 90u;
        uint8_t total_size = is_quad ? 16u : 8u;
        uint8_t element_size = single_precision ? 4u : 2u;
        cdisasm_arm_operand *source;

        if (is_quad && ((vd | vn) & 1u) != 0u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = CDISASM_ARM_NAME_VCMLA;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
            | CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            total_size, element_size, CDISASM_OPERAND_ACCESS_READ_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, is_quad),
            total_size, element_size, CDISASM_OPERAND_ACCESS_READ);
        source = append_vector_register(instruction, a32_vector_reg(vm, 0),
            8u, element_size, CDISASM_OPERAND_ACCESS_READ);
        if (source != NULL) {
            source->flags = CDISASM_ARM_OPERAND_FLAG_HAS_LANE;
            source->imm = lane;
        }
        append_immediate(instruction, rotation, 1u);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_NEON);
        (void)cdisasm_arm_requirements_add_feature(
            required_capabilities, CDISASM_ARM_FEATURE_FCMA);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xfe200f50))
            == UINT32_C(0xfc200800)
        || (canonical_word & UINT32_C(0xfe200f50))
            == UINT32_C(0xfc200840)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        unsigned rotation = (((canonical_word >> 24) & 1u) << 1
            | ((canonical_word >> 20) & 1u)) * 90u;
        uint8_t size = is_quad ? 16u : 8u;

        if (is_quad && ((vd | vn | vm) & 1u) != 0) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = CDISASM_ARM_NAME_VCMLA;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
            | CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            size, 2u, CDISASM_OPERAND_ACCESS_READ_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, is_quad),
            size, 2u, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            size, 2u, CDISASM_OPERAND_ACCESS_READ);
        append_immediate(instruction, rotation, 1u);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_NEON);
        (void)cdisasm_arm_requirements_add_feature(
            required_capabilities, CDISASM_ARM_FEATURE_FCMA);
        return CDISASM_STATUS_OK;
#endif
    }

    /* Indexed AA32 dot products.  Dm is restricted to D0-D7 and M selects
     * one of the two source groups.  The accumulator always has 32-bit
     * lanes; the multiplicands are BF16 pairs or groups of four bytes. */
    if ((canonical_word & UINT32_C(0xffb00f10))
            == UINT32_C(0xfe000d00)
        || (canonical_word & UINT32_C(0xffb00f10))
            == UINT32_C(0xfe200d00)
        || (canonical_word & UINT32_C(0xffb00f10))
            == UINT32_C(0xfe200d10)
        || (canonical_word & UINT32_C(0xffb00f10))
            == UINT32_C(0xfe800d00)
        || (canonical_word & UINT32_C(0xffb00f10))
            == UINT32_C(0xfe800d10)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        uint32_t form = canonical_word & UINT32_C(0xffb00f10);
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0u;
        int bf16 = form == UINT32_C(0xfe000d00);
        int mixed = form == UINT32_C(0xfe800d00)
            || form == UINT32_C(0xfe800d10);
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = canonical_word & 7u;
        unsigned lane = (canonical_word >> 5) & 1u;
        uint8_t total_size = is_quad ? 16u : 8u;
        uint8_t source_element_size = bf16 ? 2u : 1u;
        cdisasm_arm_operand *source;

        if (is_quad && ((vd | vn) & 1u) != 0u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = bf16 ? CDISASM_ARM_NAME_VDOT
            : form == UINT32_C(0xfe200d00) ? CDISASM_ARM_NAME_VSDOT
            : form == UINT32_C(0xfe200d10) ? CDISASM_ARM_NAME_VUDOT
            : form == UINT32_C(0xfe800d00) ? CDISASM_ARM_NAME_VUSDOT
                                           : CDISASM_ARM_NAME_VSUDOT;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        if (bf16) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        }
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            total_size, 4u, CDISASM_OPERAND_ACCESS_READ_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, is_quad),
            total_size, source_element_size, CDISASM_OPERAND_ACCESS_READ);
        source = append_vector_register(instruction, a32_vector_reg(vm, 0),
            8u, source_element_size, CDISASM_OPERAND_ACCESS_READ);
        if (source != NULL) {
            source->flags = CDISASM_ARM_OPERAND_FLAG_HAS_LANE;
            source->imm = lane;
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_NEON);
        (void)cdisasm_arm_requirements_add_feature(required_capabilities,
            bf16 ? CDISASM_ARM_FEATURE_BF16
                 : mixed ? CDISASM_ARM_FEATURE_AA32I8MM
                         : CDISASM_ARM_FEATURE_DOTPROD);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffb00f50))
            == UINT32_C(0xfca00d00)
        || (canonical_word & UINT32_C(0xffb00f50))
            == UINT32_C(0xfca00d40)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t size = is_quad ? 16u : 8u;

        if (is_quad && ((vd | vn | vm) & 1u) != 0) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = CDISASM_ARM_NAME_VUSDOT;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            size, 4u, CDISASM_OPERAND_ACCESS_READ_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, is_quad),
            size, 1u, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            size, 1u, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_NEON);
        (void)cdisasm_arm_requirements_add_feature(
            required_capabilities, CDISASM_ARM_FEATURE_AA32I8MM);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffb00f50))
            == UINT32_C(0xfc200d00)
        || (canonical_word & UINT32_C(0xffb00f50))
            == UINT32_C(0xfc200d40)
        || (canonical_word & UINT32_C(0xffb00f50))
            == UINT32_C(0xfc200d10)
        || (canonical_word & UINT32_C(0xffb00f50))
            == UINT32_C(0xfc200d50)
        || (canonical_word & UINT32_C(0xffb00f50))
            == UINT32_C(0xfe800d10)
        || (canonical_word & UINT32_C(0xffb00f50))
            == UINT32_C(0xfe800d50)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        int is_unsigned = (canonical_word & UINT32_C(0x10)) != 0;
        int is_mixed = (canonical_word & UINT32_C(0xffb00f10))
            == UINT32_C(0xfe800d10);
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t size = is_quad ? 16u : 8u;

        if (is_quad && ((vd | vn | vm) & 1u) != 0) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = is_mixed ? CDISASM_ARM_NAME_VSUDOT
            : is_unsigned ? CDISASM_ARM_NAME_VUDOT : CDISASM_ARM_NAME_VSDOT;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            size, 4u, CDISASM_OPERAND_ACCESS_READ_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, is_quad),
            size, 1u, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            size, 1u, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_NEON);
        (void)cdisasm_arm_requirements_add_feature(required_capabilities,
            is_mixed ? CDISASM_ARM_FEATURE_AA32I8MM
                     : CDISASM_ARM_FEATURE_DOTPROD);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffb00f50))
            == UINT32_C(0xfc000d00)
        || (canonical_word & UINT32_C(0xffb00f50))
            == UINT32_C(0xfc000d40)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t size = is_quad ? 16u : 8u;

        if (is_quad && ((vd | vn | vm) & 1u) != 0) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = CDISASM_ARM_NAME_VDOT;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
            | CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            size, 4u, CDISASM_OPERAND_ACCESS_READ_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, is_quad),
            size, 2u, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            size, 2u, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_NEON);
        (void)cdisasm_arm_requirements_add_feature(
            required_capabilities, CDISASM_ARM_FEATURE_BF16);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffb00f50))
            == UINT32_C(0xfc200c40)
        || (canonical_word & UINT32_C(0xffb00f50))
            == UINT32_C(0xfc200c50)
        || (canonical_word & UINT32_C(0xffb00f50))
            == UINT32_C(0xfca00c40)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        uint32_t form = canonical_word & UINT32_C(0xffb00f50);
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);

        if (((vd | vn | vm) & 1u) != 0) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = form == UINT32_C(0xfc200c40)
            ? CDISASM_ARM_NAME_VSMMLA
            : form == UINT32_C(0xfc200c50)
                ? CDISASM_ARM_NAME_VUMMLA
                : CDISASM_ARM_NAME_VUSMMLA;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, 1),
            16u, 4u, CDISASM_OPERAND_ACCESS_READ_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, 1),
            16u, 1u, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, 1),
            16u, 1u, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_NEON);
        (void)cdisasm_arm_requirements_add_feature(
            required_capabilities, CDISASM_ARM_FEATURE_AA32I8MM);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffb00f50))
            == UINT32_C(0xfc000c40)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);

        if (((vd | vn | vm) & 1u) != 0) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = CDISASM_ARM_NAME_VMMLA;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
            | CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, 1),
            16u, 4u, CDISASM_OPERAND_ACCESS_READ_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, 1),
            16u, 2u, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, 1),
            16u, 2u, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_NEON);
        (void)cdisasm_arm_requirements_add_feature(
            required_capabilities, CDISASM_ARM_FEATURE_BF16);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xfea00f50))
            == UINT32_C(0xfc800800)
        || (canonical_word & UINT32_C(0xfea00f50))
            == UINT32_C(0xfc800840)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t size = is_quad ? 16u : 8u;
        uint8_t element_size = (canonical_word & UINT32_C(0x00100000))
            != 0u ? 4u : 2u;

        if (is_quad && ((vd | vn | vm) & 1u) != 0) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = CDISASM_ARM_NAME_VCADD;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
            | CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            size, element_size,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, is_quad),
            size, element_size,
            CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            size, element_size,
            CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_NEON);
        (void)cdisasm_arm_requirements_add_feature(
            required_capabilities, CDISASM_ARM_FEATURE_FCMA);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word >> 28) != CDISASM_ARM_CONDITION_NV
        && ((canonical_word & UINT32_C(0x0fbe0f50))
                == UINT32_C(0x0eba0a40)
            || (canonical_word & UINT32_C(0x0fbe0f50))
                == UINT32_C(0x0ebe0a40)
            || (canonical_word & UINT32_C(0x0fbe0f50))
                == UINT32_C(0x0eba0b40)
            || (canonical_word & UINT32_C(0x0fbe0f50))
                == UINT32_C(0x0ebe0b40))) {
        unsigned precision = (canonical_word >> 8) & 3u;
        int is_double = precision == 3u;
        unsigned integer_width =
            (canonical_word & UINT32_C(0x80)) != 0u ? 32u : 16u;
        unsigned imm5 = ((canonical_word & 15u) << 1)
            | ((canonical_word >> 5) & 1u);
        unsigned reg = is_double
            ? (((canonical_word >> 18) & 16u)
                | ((canonical_word >> 12) & 15u))
            : (((canonical_word >> 11) & 30u)
                | ((canonical_word >> 22) & 1u));
        cdisasm_arm_reg_id base = is_double
            ? CDISASM_ARM_REG_D0 : CDISASM_ARM_REG_S0;
        uint8_t size = is_double ? 8u : 4u;

        if (imm5 >= integer_width) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)instruction;
        (void)required_capabilities;
        (void)reg;
        (void)base;
        (void)size;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_VCVT;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_register(instruction, (cdisasm_arm_reg_id)(base + reg), size,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_register(instruction, (cdisasm_arm_reg_id)(base + reg), size,
            CDISASM_OPERAND_ACCESS_READ);
        append_immediate(instruction, integer_width - imm5, 1u);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_VFP);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word >> 28) != CDISASM_ARM_CONDITION_NV
        && ((canonical_word & UINT32_C(0x0fbe0f50))
                == UINT32_C(0x0eba0940)
            || (canonical_word & UINT32_C(0x0fbe0f50))
                == UINT32_C(0x0ebe0940))) {
        unsigned hd = ((canonical_word >> 11) & 30u)
            | ((canonical_word >> 22) & 1u);
        unsigned imm5 = ((canonical_word & 15u) << 1)
            | ((canonical_word >> 5) & 1u);

        if (imm5 > 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)instruction;
        (void)required_capabilities;
        (void)hd;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_VCVT;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_register(instruction,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_H0 + hd), 2u,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_register(instruction,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_H0 + hd), 2u,
            CDISASM_OPERAND_ACCESS_READ);
        append_immediate(instruction, 16u - imm5, 1u);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(required_capabilities,
            CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_VFP
                | CDISASM_ARM_CAP_FP16);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word >> 28) != CDISASM_ARM_CONDITION_NV
        && ((canonical_word & UINT32_C(0x0fbf0f50))
                == UINT32_C(0x0eb80940)
            || (canonical_word & UINT32_C(0x0fbf0f50))
                == UINT32_C(0x0eb80a40)
            || (canonical_word & UINT32_C(0x0fbf0f50))
                == UINT32_C(0x0eb80b40))) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned precision = (canonical_word >> 8) & 3u;
        int is_double = precision == 3u;
        unsigned rd = is_double
            ? (((canonical_word >> 18) & 16u)
                | ((canonical_word >> 12) & 15u))
            : (((canonical_word >> 11) & 30u)
                | ((canonical_word >> 22) & 1u));
        unsigned rm = ((canonical_word & 15u) << 1)
            | ((canonical_word >> 5) & 1u);

        instruction->name_id = CDISASM_ARM_NAME_VCVT;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_register(instruction,
            (cdisasm_arm_reg_id)((is_double ? CDISASM_ARM_REG_D0
                : precision == 1u ? CDISASM_ARM_REG_H0
                                  : CDISASM_ARM_REG_S0) + rd),
            is_double ? 8u : precision == 1u ? 2u : 4u,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_register(instruction,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0 + rm), 4u,
            CDISASM_OPERAND_ACCESS_READ);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities,
            (precision == 1u ? CDISASM_ARM_CAP_V8 : CDISASM_ARM_CAP_V7)
                | CDISASM_ARM_CAP_VFP
                | (precision == 1u ? CDISASM_ARM_CAP_FP16 : 0u));
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word >> 28) != CDISASM_ARM_CONDITION_NV
        && ((canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0ebc09c0)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0ebd09c0)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0ebc0ac0)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0ebd0ac0)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0ebc0bc0)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0ebd0bc0))) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned precision = (canonical_word >> 8) & 3u;
        int is_double = precision == 3u;
        unsigned rd = ((canonical_word >> 11) & 30u)
            | ((canonical_word >> 22) & 1u);
        unsigned rm = is_double
            ? (((canonical_word >> 1) & 16u)
                | (canonical_word & 15u))
            : (((canonical_word & 15u) << 1)
                | ((canonical_word >> 5) & 1u));

        instruction->name_id = CDISASM_ARM_NAME_VCVT;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_register(instruction,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0 + rd), 4u,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_register(instruction,
            (cdisasm_arm_reg_id)((is_double ? CDISASM_ARM_REG_D0
                : precision == 1u ? CDISASM_ARM_REG_H0
                                  : CDISASM_ARM_REG_S0) + rm),
            is_double ? 8u : precision == 1u ? 2u : 4u,
            CDISASM_OPERAND_ACCESS_READ);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities,
            (precision == 1u ? CDISASM_ARM_CAP_V8 : CDISASM_ARM_CAP_V7)
                | CDISASM_ARM_CAP_VFP
                | (precision == 1u ? CDISASM_ARM_CAP_FP16 : 0u));
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word >> 28) != CDISASM_ARM_CONDITION_NV
        && ((canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0ebc0940)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0ebd0940)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0ebc0a40)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0ebd0a40)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0ebc0b40)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0ebd0b40))) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned precision = (canonical_word >> 8) & 3u;
        int is_double = precision == 3u;
        unsigned rd = ((canonical_word >> 11) & 30u)
            | ((canonical_word >> 22) & 1u);
        unsigned rm = is_double
            ? (((canonical_word >> 1) & 16u)
                | (canonical_word & 15u))
            : (((canonical_word & 15u) << 1)
                | ((canonical_word >> 5) & 1u));

        instruction->name_id = CDISASM_ARM_NAME_VCVTR;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_register(instruction,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0 + rd), 4u,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_register(instruction,
            (cdisasm_arm_reg_id)((is_double ? CDISASM_ARM_REG_D0
                : precision == 1u ? CDISASM_ARM_REG_H0
                                  : CDISASM_ARM_REG_S0) + rm),
            is_double ? 8u : precision == 1u ? 2u : 4u,
            CDISASM_OPERAND_ACCESS_READ);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities,
            (precision == 1u ? CDISASM_ARM_CAP_V8 : CDISASM_ARM_CAP_V7)
                | CDISASM_ARM_CAP_VFP
                | (precision == 1u ? CDISASM_ARM_CAP_FP16 : 0u));
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffbf0fd0))
            == UINT32_C(0xfeb00a40)
        || (canonical_word & UINT32_C(0xffbf0fd0))
            == UINT32_C(0xfeb00ac0)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        uint32_t form = canonical_word & UINT32_C(0xffbf0fd0);
        unsigned vd = ((canonical_word >> 11) & 30u)
            | ((canonical_word >> 22) & 1u);
        unsigned vm = ((canonical_word & 15u) << 1)
            | ((canonical_word >> 5) & 1u);

        instruction->name_id = form == UINT32_C(0xfeb00a40)
            ? CDISASM_ARM_NAME_VMOVX : CDISASM_ARM_NAME_VINS;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_register(instruction,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0 + vd), 4u,
            form == UINT32_C(0xfeb00ac0)
                ? CDISASM_OPERAND_ACCESS_READ_WRITE
                : CDISASM_OPERAND_ACCESS_WRITE);
        append_register(instruction,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0 + vm), 4u,
            CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_VFP
                | CDISASM_ARM_CAP_FP16);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffbf0f50))
            == UINT32_C(0xfebc0940)
        || (canonical_word & UINT32_C(0xffbf0f50))
            == UINT32_C(0xfebd0940)
        || (canonical_word & UINT32_C(0xffbf0f50))
            == UINT32_C(0xfebe0940)
        || (canonical_word & UINT32_C(0xffbf0f50))
            == UINT32_C(0xfebf0940)
        || (canonical_word & UINT32_C(0xffbf0f50))
            == UINT32_C(0xfebc0a40)
        || (canonical_word & UINT32_C(0xffbf0f50))
            == UINT32_C(0xfebc0b40)
        || (canonical_word & UINT32_C(0xffbf0f50))
            == UINT32_C(0xfebd0a40)
        || (canonical_word & UINT32_C(0xffbf0f50))
            == UINT32_C(0xfebd0b40)
        || (canonical_word & UINT32_C(0xffbf0f50))
            == UINT32_C(0xfebe0a40)
        || (canonical_word & UINT32_C(0xffbf0f50))
            == UINT32_C(0xfebe0b40)
        || (canonical_word & UINT32_C(0xffbf0f50))
            == UINT32_C(0xfebf0a40)
        || (canonical_word & UINT32_C(0xffbf0f50))
            == UINT32_C(0xfebf0b40)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        uint32_t form = canonical_word & UINT32_C(0xffbf0f50);
        unsigned operation = (canonical_word >> 16) & 3u;
        unsigned precision = (canonical_word >> 8) & 3u;
        int is_double = precision == 3u;
        unsigned fp_vd = ((canonical_word >> 11) & 30u)
            | ((canonical_word >> 22) & 1u);
        unsigned fp_vm = is_double
            ? (((canonical_word >> 1) & 16u)
                | (canonical_word & 15u))
            : (((canonical_word & 15u) << 1)
                | ((canonical_word >> 5) & 1u));
        cdisasm_arm_reg_id source_base = is_double ? CDISASM_ARM_REG_D0
            : precision == 1u ? CDISASM_ARM_REG_H0 : CDISASM_ARM_REG_S0;
        uint8_t source_size = is_double ? 8u
            : precision == 1u ? 2u : 4u;

        (void)form;
        instruction->name_id = operation == 0u ? CDISASM_ARM_NAME_VCVTA
            : operation == 1u ? CDISASM_ARM_NAME_VCVTN
            : operation == 2u ? CDISASM_ARM_NAME_VCVTP
                              : CDISASM_ARM_NAME_VCVTM;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_register(instruction,
            (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0 + fp_vd), 4u,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_register(instruction,
            (cdisasm_arm_reg_id)(source_base + fp_vm), source_size,
            CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_VFP
                | (precision == 1u ? CDISASM_ARM_CAP_FP16 : 0u));
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word >> 28) != CDISASM_ARM_CONDITION_NV
        && ((canonical_word & UINT32_C(0x0fb00ff0))
                == UINT32_C(0x0eb00900)
            || (canonical_word & UINT32_C(0x0fb00ff0))
                == UINT32_C(0x0eb00a00)
            || (canonical_word & UINT32_C(0x0fb00ff0))
                == UINT32_C(0x0eb00b00))) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned precision = (canonical_word >> 8) & 3u;
        int is_double = precision == 3u;
        unsigned fp_vd = is_double
            ? (((canonical_word >> 18) & 16u)
                | ((canonical_word >> 12) & 15u))
            : (((canonical_word >> 11) & 30u)
                | ((canonical_word >> 22) & 1u));
        unsigned encoded_immediate;
        cdisasm_arm_reg_id base = is_double ? CDISASM_ARM_REG_D0
            : precision == 1u ? CDISASM_ARM_REG_H0 : CDISASM_ARM_REG_S0;
        uint8_t size = is_double ? 8u : precision == 1u ? 2u : 4u;

        /* imm8 is split as imm4H:imm4L; destination bits must not leak into
         * its high nibble. */
        encoded_immediate = (((canonical_word >> 16) & 15u) << 4)
            | (canonical_word & 15u);
        instruction->name_id = CDISASM_ARM_NAME_VMOV;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_register(instruction,
            (cdisasm_arm_reg_id)(base + fp_vd), size,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_immediate(instruction,
            vfp_expand_immediate(encoded_immediate, size), size);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(required_capabilities,
            (precision == 1u ? CDISASM_ARM_CAP_V8 : CDISASM_ARM_CAP_V7)
                | CDISASM_ARM_CAP_VFP
                | (precision == 1u ? CDISASM_ARM_CAP_FP16 : 0u));
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word >> 28) != CDISASM_ARM_CONDITION_NV
        && ((canonical_word & UINT32_C(0x0ff00fd0))
                == UINT32_C(0x0c400a10)
            || (canonical_word & UINT32_C(0x0ff00fd0))
                == UINT32_C(0x0c500a10)
            || (canonical_word & UINT32_C(0x0ff00fd0))
                == UINT32_C(0x0c400b10)
            || (canonical_word & UINT32_C(0x0ff00fd0))
                == UINT32_C(0x0c500b10)
            /* Thumb-2 uses the EC transport envelope, where bit 22 is
             * carried in the first halfword's split fields rather than the
             * A32 P/U position. */
            || (canonical_word & UINT32_C(0x0ff00fd0))
                == UINT32_C(0x0c000a10)
            || (canonical_word & UINT32_C(0x0ff00fd0))
                == UINT32_C(0x0c100a10)
            || (canonical_word & UINT32_C(0x0ff00fd0))
                == UINT32_C(0x0c000b10)
            || (canonical_word & UINT32_C(0x0ff00fd0))
                == UINT32_C(0x0c100b10))) {
        unsigned rt = (canonical_word >> 12) & 15u;
        unsigned rt2 = (canonical_word >> 16) & 15u;
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        int to_core = (canonical_word & UINT32_C(0x00100000)) != 0u;
        int double_form = (canonical_word & UINT32_C(0x100)) != 0u;

        if (rt == 15u || rt2 == 15u || rt == rt2) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)instruction;
        (void)required_capabilities;
        (void)vm;
        (void)to_core;
        (void)double_form;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_VMOV;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        if (to_core) {
            append_register(instruction, a32_reg(rt), 4u,
                CDISASM_OPERAND_ACCESS_WRITE);
            append_register(instruction, a32_reg(rt2), 4u,
                CDISASM_OPERAND_ACCESS_WRITE);
            if (double_form) {
                append_register(instruction,
                    (cdisasm_arm_reg_id)(CDISASM_ARM_REG_D0 + vm), 8u,
                    CDISASM_OPERAND_ACCESS_READ);
            } else {
                append_register(instruction,
                    (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0 + vm * 2u), 4u,
                    CDISASM_OPERAND_ACCESS_READ);
                append_register(instruction,
                    (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0 + vm * 2u + 1u),
                    4u, CDISASM_OPERAND_ACCESS_READ);
            }
        } else {
            if (double_form) {
                append_register(instruction,
                    (cdisasm_arm_reg_id)(CDISASM_ARM_REG_D0 + vm), 8u,
                    CDISASM_OPERAND_ACCESS_WRITE);
            } else {
                append_register(instruction,
                    (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0 + vm * 2u), 4u,
                    CDISASM_OPERAND_ACCESS_WRITE);
                append_register(instruction,
                    (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0 + vm * 2u + 1u),
                    4u, CDISASM_OPERAND_ACCESS_WRITE);
            }
            append_register(instruction, a32_reg(rt), 4u,
                CDISASM_OPERAND_ACCESS_READ);
            append_register(instruction, a32_reg(rt2), 4u,
                CDISASM_OPERAND_ACCESS_READ);
        }
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_VFP);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word >> 28) != CDISASM_ARM_CONDITION_NV
        && ((canonical_word & UINT32_C(0x0ff00f7f))
                == UINT32_C(0x0e000a10)
            || (canonical_word & UINT32_C(0x0ff00f7f))
                == UINT32_C(0x0e100a10))) {
        unsigned rt = (canonical_word >> 12) & 15u;
        unsigned sn = (((canonical_word >> 16) & 15u) << 1)
            | ((canonical_word >> 7) & 1u);
        int to_core = (canonical_word & UINT32_C(0x00100000)) != 0u;

        if (rt == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)instruction;
        (void)required_capabilities;
        (void)sn;
        (void)to_core;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_VMOV;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        if (to_core) {
            append_register(instruction, a32_reg(rt), 4u,
                CDISASM_OPERAND_ACCESS_WRITE);
            append_register(instruction,
                (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0 + sn), 4u,
                CDISASM_OPERAND_ACCESS_READ);
        } else {
            append_register(instruction,
                (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0 + sn), 4u,
                CDISASM_OPERAND_ACCESS_WRITE);
            append_register(instruction, a32_reg(rt), 4u,
                CDISASM_OPERAND_ACCESS_READ);
        }
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_VFP);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word >> 28) != CDISASM_ARM_CONDITION_NV
        && (((canonical_word & UINT32_C(0x0f900f1f))
                    == UINT32_C(0x0e000b10))
            || ((canonical_word & UINT32_C(0x0f100f1f))
                    == UINT32_C(0x0e100b10)))) {
        unsigned rt = (canonical_word >> 12) & 15u;
        unsigned dn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned opc1 = (canonical_word >> 21) & 3u;
        unsigned opc2 = (canonical_word >> 5) & 3u;
        unsigned element_shift;
        unsigned lane;
        int to_core = (canonical_word & UINT32_C(0x00100000)) != 0u;
        cdisasm_arm_operand *indexed_operand;

        if ((opc1 & 2u) != 0u) {
            element_shift = 0u;
            lane = ((opc1 & 1u) << 2) | opc2;
        } else if ((opc2 & 1u) != 0u) {
            element_shift = 1u;
            lane = (opc1 << 1) | (opc2 >> 1);
        } else if (opc2 == 0u) {
            element_shift = 2u;
            lane = opc1;
        } else {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        if (rt == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)instruction;
        (void)required_capabilities;
        (void)dn;
        (void)element_shift;
        (void)lane;
        (void)to_core;
        (void)indexed_operand;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_VMOV;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        if (to_core) {
            append_register(instruction, a32_reg(rt), 4u,
                CDISASM_OPERAND_ACCESS_WRITE);
            indexed_operand = append_vector_register(instruction,
                a32_vector_reg(dn, 0), 8u, (uint8_t)(1u << element_shift),
                CDISASM_OPERAND_ACCESS_READ);
        } else {
            indexed_operand = append_vector_register(instruction,
                a32_vector_reg(dn, 0), 8u, (uint8_t)(1u << element_shift),
                CDISASM_OPERAND_ACCESS_WRITE);
            append_register(instruction, a32_reg(rt), 4u,
                CDISASM_OPERAND_ACCESS_READ);
        }
        if (indexed_operand != NULL) {
            indexed_operand->flags = CDISASM_ARM_OPERAND_FLAG_HAS_LANE;
            indexed_operand->imm = lane;
        }
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word >> 28) != CDISASM_ARM_CONDITION_NV
        && ((canonical_word & UINT32_C(0x0ff00f7f))
                == UINT32_C(0x0e000910)
            || (canonical_word & UINT32_C(0x0ff00f7f))
                == UINT32_C(0x0e100910))) {
        unsigned rt = (canonical_word >> 12) & 15u;
        unsigned hn = (((canonical_word >> 16) & 15u) << 1)
            | ((canonical_word >> 7) & 1u);
        int to_core = (canonical_word & UINT32_C(0x00100000)) != 0u;

        if (rt == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)instruction;
        (void)required_capabilities;
        (void)hn;
        (void)to_core;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_VMOV;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        if (to_core) {
            append_register(instruction, a32_reg(rt), 4u,
                CDISASM_OPERAND_ACCESS_WRITE);
            append_register(instruction,
                (cdisasm_arm_reg_id)(CDISASM_ARM_REG_H0 + hn), 2u,
                CDISASM_OPERAND_ACCESS_READ);
        } else {
            append_register(instruction,
                (cdisasm_arm_reg_id)(CDISASM_ARM_REG_H0 + hn), 2u,
                CDISASM_OPERAND_ACCESS_WRITE);
            append_register(instruction, a32_reg(rt), 4u,
                CDISASM_OPERAND_ACCESS_READ);
        }
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(required_capabilities,
            CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_VFP
                | CDISASM_ARM_CAP_FP16);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word >> 28) != CDISASM_ARM_CONDITION_NV
        && ((canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0eb70ac0)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0eb70bc0))) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        int double_destination =
            (canonical_word & UINT32_C(0x100)) == 0u;
        unsigned vd = double_destination
            ? (((canonical_word >> 18) & 16u)
                | ((canonical_word >> 12) & 15u))
            : (((canonical_word >> 11) & 30u)
                | ((canonical_word >> 22) & 1u));
        unsigned vm = double_destination
            ? (((canonical_word & 15u) << 1)
                | ((canonical_word >> 5) & 1u))
            : (((canonical_word >> 1) & 16u)
                | (canonical_word & 15u));

        instruction->name_id = CDISASM_ARM_NAME_VCVT;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_register(instruction,
            (cdisasm_arm_reg_id)((double_destination
                ? CDISASM_ARM_REG_D0 : CDISASM_ARM_REG_S0) + vd),
            double_destination ? 8u : 4u,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_register(instruction,
            (cdisasm_arm_reg_id)((double_destination
                ? CDISASM_ARM_REG_S0 : CDISASM_ARM_REG_D0) + vm),
            double_destination ? 4u : 8u,
            CDISASM_OPERAND_ACCESS_READ);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_VFP);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word >> 28) != CDISASM_ARM_CONDITION_NV
        && ((canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0eb009c0)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0eb10940)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0eb109c0)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0eb60940)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0eb609c0)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0eb70940)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0eb00ac0)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0eb00bc0)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0eb10a40)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0eb10b40)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0eb10ac0)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0eb10bc0)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0eb60a40)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0eb60b40)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0eb60ac0)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0eb60bc0)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0eb70a40)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0eb70b40))) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        uint32_t form = canonical_word & UINT32_C(0x0fbf0fd0);
        unsigned precision = (canonical_word >> 8) & 3u;
        int is_double = (canonical_word & UINT32_C(0x100)) != 0;
        unsigned fp_vd = is_double
            ? (((canonical_word >> 18) & 16u)
                | ((canonical_word >> 12) & 15u))
            : (((canonical_word >> 11) & 30u)
                | ((canonical_word >> 22) & 1u));
        unsigned fp_vm = is_double
            ? (((canonical_word >> 1) & 16u)
                | (canonical_word & 15u))
            : (((canonical_word & 15u) << 1)
                | ((canonical_word >> 5) & 1u));
        cdisasm_arm_reg_id base = is_double ? CDISASM_ARM_REG_D0
            : precision == 1u ? CDISASM_ARM_REG_H0 : CDISASM_ARM_REG_S0;
        uint8_t size = is_double ? 8u : precision == 1u ? 2u : 4u;

        instruction->name_id = form == UINT32_C(0x0eb009c0)
                || form == UINT32_C(0x0eb00ac0)
                || form == UINT32_C(0x0eb00bc0)
            ? CDISASM_ARM_NAME_VABS
            : form == UINT32_C(0x0eb10940)
                    || form == UINT32_C(0x0eb10a40)
                    || form == UINT32_C(0x0eb10b40)
                ? CDISASM_ARM_NAME_VNEG
            : form == UINT32_C(0x0eb109c0)
                    || form == UINT32_C(0x0eb10ac0)
                    || form == UINT32_C(0x0eb10bc0)
                ? CDISASM_ARM_NAME_VSQRT
            : form == UINT32_C(0x0eb60940)
                    || form == UINT32_C(0x0eb60a40)
                    || form == UINT32_C(0x0eb60b40)
                ? CDISASM_ARM_NAME_VRINTR
            : form == UINT32_C(0x0eb609c0)
                    || form == UINT32_C(0x0eb60ac0)
                    || form == UINT32_C(0x0eb60bc0)
                ? CDISASM_ARM_NAME_VRINTZ
                : CDISASM_ARM_NAME_VRINTX;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_register(instruction,
            (cdisasm_arm_reg_id)(base + fp_vd), size,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_register(instruction,
            (cdisasm_arm_reg_id)(base + fp_vm), size,
            CDISASM_OPERAND_ACCESS_READ);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_VFP);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word >> 28) != CDISASM_ARM_CONDITION_NV
        && ((canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0eb00a40)
            || (canonical_word & UINT32_C(0x0fbf0fd0))
                == UINT32_C(0x0eb00b40))) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        int is_double = (canonical_word & UINT32_C(0x100)) != 0;
        unsigned fp_vd = is_double
            ? (((canonical_word >> 18) & 16u)
                | ((canonical_word >> 12) & 15u))
            : (((canonical_word >> 11) & 30u)
                | ((canonical_word >> 22) & 1u));
        unsigned fp_vm = is_double
            ? (((canonical_word >> 1) & 16u)
                | (canonical_word & 15u))
            : (((canonical_word & 15u) << 1)
                | ((canonical_word >> 5) & 1u));
        cdisasm_arm_reg_id base = is_double
            ? CDISASM_ARM_REG_D0 : CDISASM_ARM_REG_S0;
        uint8_t size = is_double ? 8u : 4u;

        instruction->name_id = CDISASM_ARM_NAME_VMOV;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_register(instruction,
            (cdisasm_arm_reg_id)(base + fp_vd), size,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_register(instruction,
            (cdisasm_arm_reg_id)(base + fp_vm), size,
            CDISASM_OPERAND_ACCESS_READ);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_VFP);
        return CDISASM_STATUS_OK;
#endif
    }

decode_advsimd_scalar_dup:
    if ((canonical_word & UINT32_C(0xffb00f90))
            == UINT32_C(0xf3b00c00)) {
        unsigned imm4 = (canonical_word >> 16) & 15u;
        unsigned element_shift = (imm4 & 1u) != 0u ? 0u
            : (imm4 & 2u) != 0u ? 1u
            : (imm4 & 4u) != 0u ? 2u : 3u;
        unsigned destination = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned source = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        unsigned quad = (canonical_word & UINT32_C(0x40)) != 0u;
        uint8_t element = (uint8_t)(1u << element_shift);
        cdisasm_arm_operand *indexed_operand;

        if (element_shift == 3u || (quad && (destination & 1u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)source;
        (void)element;
        (void)indexed_operand;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_VDUP;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction,
            a32_vector_reg(destination, (int)quad), quad ? 16u : 8u,
            element, CDISASM_OPERAND_ACCESS_WRITE);
        indexed_operand = append_vector_register(instruction,
            a32_vector_reg(source, 0), 8u, element,
            CDISASM_OPERAND_ACCESS_READ);
        if (indexed_operand != NULL) {
            indexed_operand->flags = CDISASM_ARM_OPERAND_FLAG_HAS_LANE;
            indexed_operand->imm = imm4 >> (element_shift + 1u);
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xfe000900)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xfe000a00)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xfe000b00)) {
#if !USE_EXTRA_OPCODES
        (void)instruction;
        (void)required_capabilities;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        static const cdisasm_arm_name_id names[4] = {
            CDISASM_ARM_NAME_VSELEQ, CDISASM_ARM_NAME_VSELVS,
            CDISASM_ARM_NAME_VSELGE, CDISASM_ARM_NAME_VSELGT
        };
        unsigned select = (canonical_word >> 20) & 3u;
        unsigned precision = (canonical_word >> 8) & 3u;
        int is_double = precision == 3u;
        unsigned fp_vd = is_double
            ? (((canonical_word >> 18) & 16u)
                | ((canonical_word >> 12) & 15u))
            : (((canonical_word >> 11) & 30u)
                | ((canonical_word >> 22) & 1u));
        unsigned fp_vn = is_double
            ? (((canonical_word >> 3) & 16u)
                | ((canonical_word >> 16) & 15u))
            : (((canonical_word >> 15) & 30u)
                | ((canonical_word >> 7) & 1u));
        unsigned fp_vm = is_double
            ? (((canonical_word >> 1) & 16u)
                | (canonical_word & 15u))
            : (((canonical_word & 15u) << 1)
                | ((canonical_word >> 5) & 1u));
        cdisasm_arm_reg_id reg_base = is_double
            ? CDISASM_ARM_REG_D0
            : precision == 2u ? CDISASM_ARM_REG_S0 : CDISASM_ARM_REG_H0;
        uint8_t fp_size = is_double ? 8u : precision == 2u ? 4u : 2u;

        instruction->name_id = names[select];
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_register(
            instruction, (cdisasm_arm_reg_id)(reg_base + fp_vd), fp_size,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_register(
            instruction, (cdisasm_arm_reg_id)(reg_base + fp_vn), fp_size,
            CDISASM_OPERAND_ACCESS_READ);
        append_register(
            instruction, (cdisasm_arm_reg_id)(reg_base + fp_vm), fp_size,
            CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_VFP
                | (precision == 1u ? CDISASM_ARM_CAP_FP16 : 0u));
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xff800f10))
            == UINT32_C(0xf3000810)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned element_shift = (canonical_word >> 20) & 3u;
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t vector_size = is_quad ? 16u : 8u;

        if (element_shift == 3u || (is_quad && ((vd | vn | vm) & 1u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = CDISASM_ARM_NAME_VCEQ;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, (uint8_t)(1u << element_shift),
            CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, is_quad),
            vector_size, (uint8_t)(1u << element_shift),
            CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, (uint8_t)(1u << element_shift),
            CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(required_capabilities,
            CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffb30b90))
            == UINT32_C(0xf3b10100)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned element_shift = (canonical_word >> 18) & 3u;
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t vector_size = is_quad ? 16u : 8u;

        if (element_shift == 3u || (is_quad && ((vd | vm) & 1u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = CDISASM_ARM_NAME_VCEQ;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, (uint8_t)(1u << element_shift),
            CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, (uint8_t)(1u << element_shift),
            CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(required_capabilities,
            CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffb30b90))
            == UINT32_C(0xf3b10300)
        || (canonical_word & UINT32_C(0xffb30b90))
            == UINT32_C(0xf3b10380)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned element_shift = (canonical_word >> 18) & 3u;
        int negate = (canonical_word & UINT32_C(0x80)) != 0;
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t vector_size = is_quad ? 16u : 8u;

        if (element_shift == 3u || (is_quad && ((vd | vm) & 1u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = negate ? CDISASM_ARM_NAME_VNEG
                                      : CDISASM_ARM_NAME_VABS;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, (uint8_t)(1u << element_shift),
            CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, (uint8_t)(1u << element_shift),
            CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(required_capabilities,
            CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffa00f10))
            == UINT32_C(0xf3000f10)
        || (canonical_word & UINT32_C(0xffa00f10))
            == UINT32_C(0xf3200f10)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        int minimum = (canonical_word & UINT32_C(0x00200000)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t vector_size = is_quad ? 16u : 8u;

        if (is_quad && ((vd | vn | vm) & 1u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = minimum ? CDISASM_ARM_NAME_VMINNM
                                       : CDISASM_ARM_NAME_VMAXNM;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, 4u, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, is_quad),
            vector_size, 4u, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, 4u, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(required_capabilities,
            CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffa00f50))
            == UINT32_C(0xf2000e00)
        || (canonical_word & UINT32_C(0xffa00f50))
            == UINT32_C(0xf2000e40)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned element_shift = (canonical_word >> 20) & 3u;
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t vector_size = is_quad ? 16u : 8u;
        uint8_t element_size;

        if (element_shift == 3u || (is_quad && ((vd | vn | vm) & 1u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        element_size = (uint8_t)(1u << element_shift);
        instruction->name_id = CDISASM_ARM_NAME_VCEQ;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffa00f50))
            == UINT32_C(0xf2000f00)
        || (canonical_word & UINT32_C(0xffa00f50))
            == UINT32_C(0xf2000f40)
        || (canonical_word & UINT32_C(0xffa00f50))
            == UINT32_C(0xf2000f10)
        || (canonical_word & UINT32_C(0xffa00f50))
            == UINT32_C(0xf2000f50)
        || (canonical_word & UINT32_C(0xffa00f50))
            == UINT32_C(0xf2200f00)
        || (canonical_word & UINT32_C(0xffa00f50))
            == UINT32_C(0xf2200f40)
        || (canonical_word & UINT32_C(0xffa00f50))
            == UINT32_C(0xf2200f10)
        || (canonical_word & UINT32_C(0xffa00f50))
            == UINT32_C(0xf2200f50)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        int reciprocal_step = (canonical_word & UINT32_C(0x10)) != 0;
        int minimum_family = (canonical_word & UINT32_C(0x00200000)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t vector_size = is_quad ? 16u : 8u;

        if (is_quad && ((vd | vn | vm) & 1u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = minimum_family
            ? (reciprocal_step ? CDISASM_ARM_NAME_VRSQRTS
                               : CDISASM_ARM_NAME_VMIN)
            : (reciprocal_step ? CDISASM_ARM_NAME_VRECPS
                               : CDISASM_ARM_NAME_VMAX);
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, 4u, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, is_quad),
            vector_size, 4u, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, 4u, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xfeb809b0))
            == UINT32_C(0xf2800010)
        || (canonical_word & UINT32_C(0xfeb809b0))
            == UINT32_C(0xf2800030)
        || (canonical_word & UINT32_C(0xfeb809b0))
            == UINT32_C(0xf2800110)
        || (canonical_word & UINT32_C(0xfeb809b0))
            == UINT32_C(0xf2800130)
        || (canonical_word & UINT32_C(0xfeb80db0))
            == UINT32_C(0xf2800810)
        || (canonical_word & UINT32_C(0xfeb80db0))
            == UINT32_C(0xf2800830)
        || (canonical_word & UINT32_C(0xfeb80db0))
            == UINT32_C(0xf2800910)
        || (canonical_word & UINT32_C(0xfeb80db0))
            == UINT32_C(0xf2800930)
        || (canonical_word & UINT32_C(0xfeb80cb0))
            == UINT32_C(0xf2800c10)
        || (canonical_word & UINT32_C(0xfeb80eb0))
            == UINT32_C(0xf2800c30)
        || (canonical_word & UINT32_C(0xfeb80fb0))
            == UINT32_C(0xf2800e30)) {
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);

        if (is_quad && (vd & 1u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned cmode = (canonical_word >> 8) & 15u;
        unsigned imm8 = ((canonical_word >> 17) & 0x80u)
            | ((canonical_word >> 12) & 0x70u)
            | (canonical_word & 15u);
        int bit_clear = (canonical_word & UINT32_C(0x20)) != 0;
        int move = (cmode & 1u) == 0u || cmode >= 12u;
        unsigned shift;
        uint64_t immediate;
        uint8_t element_size;

        if (cmode < 8u) {
            shift = (cmode >> 1) * 8u;
            immediate = (uint64_t)imm8 << shift;
            element_size = 4u;
        } else if (cmode < 12u) {
            shift = (cmode & 2u) * 4u;
            immediate = (uint64_t)imm8 << shift;
            element_size = 2u;
        } else if (cmode < 14u) {
            shift = (cmode & 1u) != 0u ? 16u : 8u;
            immediate = ((uint64_t)imm8 << shift)
                | ((UINT64_C(1) << shift) - 1u);
            element_size = 4u;
        } else {
            unsigned bit;

            immediate = 0u;
            for (bit = 0u; bit < 8u; ++bit) {
                if ((imm8 & (1u << bit)) != 0u) {
                    immediate |= UINT64_C(0xff) << (bit * 8u);
                }
            }
            element_size = 8u;
        }
        instruction->name_id = move
            ? (bit_clear && cmode != 14u
                    ? CDISASM_ARM_NAME_VMVN : CDISASM_ARM_NAME_VMOV)
            : (bit_clear ? CDISASM_ARM_NAME_VBIC : CDISASM_ARM_NAME_VORR);
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            is_quad ? 16u : 8u, element_size,
            move ? CDISASM_OPERAND_ACCESS_WRITE
                 : CDISASM_OPERAND_ACCESS_READ_WRITE);
        append_immediate(instruction, immediate, element_size);
        cdisasm_arm_requirements_set_legacy(required_capabilities,
            CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

decode_advsimd_table_lookup:
    /* Advanced SIMD byte table lookup and extending table lookup. */
    if ((canonical_word & UINT32_C(0xffb00c50))
            == UINT32_C(0xf3b00800)
        || (canonical_word & UINT32_C(0xffb00c50))
            == UINT32_C(0xf3b00840)) {
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        unsigned count = ((canonical_word >> 8) & 3u) + 1u;
        int extending = (canonical_word & UINT32_C(0x40)) != 0;

        if (vn + count > 32u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)vd;
        (void)vm;
        (void)extending;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        cdisasm_arm_operand *list;

        instruction->name_id = extending
            ? CDISASM_ARM_NAME_VTBX : CDISASM_ARM_NAME_VTBL;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, 0),
            8u, 1u, extending ? CDISASM_OPERAND_ACCESS_READ_WRITE
                              : CDISASM_OPERAND_ACCESS_WRITE);
        list = append_operand(instruction);
        if (list != NULL) {
            list->type = CDISASM_ARM_OPERAND_VECTOR_REGISTER_LIST;
            list->reg = a32_vector_reg(vn, 0);
            list->register_list = (uint16_t)count;
            list->size = 8u;
            list->extend_type = 1u;
            list->scale = 8u;
            list->access = CDISASM_OPERAND_ACCESS_READ;
        }
        append_vector_register(instruction, a32_vector_reg(vm, 0),
            8u, 1u, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    /* Advanced SIMD right shift, optional rounding, and accumulate forms. */
    if ((canonical_word & UINT32_C(0xfe800c10))
            == UINT32_C(0xf2800010)) {
        static const cdisasm_arm_name_id names[4] = {
            CDISASM_ARM_NAME_VSHR, CDISASM_ARM_NAME_VSRA,
            CDISASM_ARM_NAME_VRSHR, CDISASM_ARM_NAME_VRSRA
        };
        unsigned imm7 = ((canonical_word >> 16) & 63u)
            | ((canonical_word >> 1) & 64u);
        unsigned element_size;
        unsigned shift;
        unsigned operation = (canonical_word >> 8) & 3u;
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);

        if (imm7 < 8u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        element_size = imm7 >= 64u ? 8u
            : imm7 >= 32u ? 4u : imm7 >= 16u ? 2u : 1u;
        shift = element_size * 16u - imm7;
        if (is_quad && ((vd | vm) & 1u) != 0u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)names;
        (void)operation;
        (void)shift;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = names[operation];
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            is_quad ? 16u : 8u, (uint8_t)element_size,
            (operation & 1u) != 0u
                ? CDISASM_OPERAND_ACCESS_READ_WRITE
                : CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            is_quad ? 16u : 8u, (uint8_t)element_size,
            CDISASM_OPERAND_ACCESS_READ);
        append_immediate(instruction, shift, 1u);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    /* Advanced SIMD immediate left shift.  imm7 encodes the element width
     * in its highest set bit and the architectural shift in the remainder. */
    if ((canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf2800510)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf2800550)) {
        unsigned imm7 = ((canonical_word >> 16) & 63u)
            | ((canonical_word >> 1) & 64u);
        unsigned element_size;
        unsigned shift;
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);

        if (imm7 < 8u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        element_size = imm7 >= 64u ? 8u
            : imm7 >= 32u ? 4u : imm7 >= 16u ? 2u : 1u;
        shift = imm7 - element_size * 8u;
        if (is_quad && ((vd | vm) & 1u) != 0u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)shift;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_VSHL;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            is_quad ? 16u : 8u, (uint8_t)element_size,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            is_quad ? 16u : 8u, (uint8_t)element_size,
            CDISASM_OPERAND_ACCESS_READ);
        append_immediate(instruction, shift, 1u);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    /* Signed/unsigned saturating immediate left shift.  Bit 24 selects the
     * input signedness but does not alter the shared imm7 width encoding. */
    if ((canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2800710)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2800750)) {
        unsigned imm7 = ((canonical_word >> 16) & 63u)
            | ((canonical_word >> 1) & 64u);
        unsigned element_size;
        unsigned shift;
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);

        if (imm7 < 8u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        element_size = imm7 >= 64u ? 8u
            : imm7 >= 32u ? 4u : imm7 >= 16u ? 2u : 1u;
        shift = imm7 - element_size * 8u;
        if (is_quad && ((vd | vm) & 1u) != 0u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)shift;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_VQSHL;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            is_quad ? 16u : 8u, (uint8_t)element_size,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            is_quad ? 16u : 8u, (uint8_t)element_size,
            CDISASM_OPERAND_ACCESS_READ);
        append_immediate(instruction, shift, 1u);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    /* Signed input, unsigned saturating immediate left shift. */
    if ((canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf3800610)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf3800650)) {
        unsigned imm7 = ((canonical_word >> 16) & 63u)
            | ((canonical_word >> 1) & 64u);
        unsigned element_size;
        unsigned shift;
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);

        if (imm7 < 8u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        element_size = imm7 >= 64u ? 8u
            : imm7 >= 32u ? 4u : imm7 >= 16u ? 2u : 1u;
        shift = imm7 - element_size * 8u;
        if (is_quad && ((vd | vm) & 1u) != 0u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)shift;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_VQSHLU;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            is_quad ? 16u : 8u, (uint8_t)element_size,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            is_quad ? 16u : 8u, (uint8_t)element_size,
            CDISASM_OPERAND_ACCESS_READ);
        append_immediate(instruction, shift, 1u);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    /* Shift-left/right-and-insert immediate forms.  Both read the old
     * destination; right insertion encodes the complementary shift. */
    if ((canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf3800410)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf3800450)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf3800510)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf3800550)) {
        unsigned imm7 = ((canonical_word >> 16) & 63u)
            | ((canonical_word >> 1) & 64u);
        unsigned element_size;
        unsigned element_bits;
        unsigned shift;
        int insert_left = (canonical_word & UINT32_C(0x100)) != 0u;
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);

        if (imm7 < 8u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        element_size = imm7 >= 64u ? 8u
            : imm7 >= 32u ? 4u : imm7 >= 16u ? 2u : 1u;
        element_bits = element_size * 8u;
        shift = insert_left ? imm7 - element_bits
                            : element_bits * 2u - imm7;
        if (is_quad && ((vd | vm) & 1u) != 0u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)shift;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = insert_left
            ? CDISASM_ARM_NAME_VSLI : CDISASM_ARM_NAME_VSRI;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            is_quad ? 16u : 8u, (uint8_t)element_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            is_quad ? 16u : 8u, (uint8_t)element_size,
            CDISASM_OPERAND_ACCESS_READ);
        append_immediate(instruction, shift, 1u);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((((canonical_word & UINT32_C(0xfe800f50))
                == UINT32_C(0xf2800800))
            || ((canonical_word & UINT32_C(0xfe800f50))
                == UINT32_C(0xf2800a00)))
        && ((canonical_word >> 20) & 3u) != 3u) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned element_shift = (canonical_word >> 20) & 3u;
        int subtract = (canonical_word & UINT32_C(0x200)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t source_element_size = (uint8_t)(1u << element_shift);

        if (vd & 1u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = subtract
            ? CDISASM_ARM_NAME_VMLSL : CDISASM_ARM_NAME_VMLAL;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, 1),
            16u, (uint8_t)(source_element_size * 2u),
            CDISASM_OPERAND_ACCESS_READ_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, 0),
            8u, source_element_size, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, 0),
            8u, source_element_size, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((((canonical_word & UINT32_C(0xfe800f50))
                == UINT32_C(0xf2800100))
            || ((canonical_word & UINT32_C(0xfe800f50))
                == UINT32_C(0xf2800300)))
        && ((canonical_word >> 20) & 3u) != 3u) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned element_shift = (canonical_word >> 20) & 3u;
        int subtract = (canonical_word & UINT32_C(0x200)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t source_element_size = (uint8_t)(1u << element_shift);

        if ((vd | vn) & 1u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = subtract
            ? CDISASM_ARM_NAME_VSUBW : CDISASM_ARM_NAME_VADDW;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, 1),
            16u, (uint8_t)(source_element_size * 2u),
            CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, 1),
            16u, (uint8_t)(source_element_size * 2u),
            CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, 0),
            8u, source_element_size, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((((canonical_word & UINT32_C(0xfe800f50))
                == UINT32_C(0xf2800500))
            || ((canonical_word & UINT32_C(0xfe800f50))
                == UINT32_C(0xf2800700)))
        && ((canonical_word >> 20) & 3u) != 3u) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned element_shift = (canonical_word >> 20) & 3u;
        int accumulate = (canonical_word & UINT32_C(0x200)) == 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t source_element_size = (uint8_t)(1u << element_shift);

        if (vd & 1u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = accumulate
            ? CDISASM_ARM_NAME_VABAL : CDISASM_ARM_NAME_VABDL;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, 1),
            16u, (uint8_t)(source_element_size * 2u),
            accumulate ? CDISASM_OPERAND_ACCESS_READ_WRITE
                       : CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, 0),
            8u, source_element_size, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, 0),
            8u, source_element_size, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if (((canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf2800400)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf3800400)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf2800600)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf3800600))
        && ((canonical_word >> 20) & 3u) != 3u) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned element_shift = (canonical_word >> 20) & 3u;
        int rounding = (canonical_word & UINT32_C(0x01000000)) != 0;
        int subtract = (canonical_word & UINT32_C(0x200)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t destination_element_size;

        if ((vn | vm) & 1u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        destination_element_size = (uint8_t)(1u << element_shift);
        instruction->name_id = subtract
            ? (rounding ? CDISASM_ARM_NAME_VRSUBHN
                        : CDISASM_ARM_NAME_VSUBHN)
            : (rounding ? CDISASM_ARM_NAME_VRADDHN
                        : CDISASM_ARM_NAME_VADDHN);
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, 0),
            8u, destination_element_size, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, 1),
            16u, (uint8_t)(destination_element_size * 2u),
            CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, 1),
            16u, (uint8_t)(destination_element_size * 2u),
            CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if (((canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2800000)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2800200))
        && ((canonical_word >> 20) & 3u) != 3u) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned element_shift = (canonical_word >> 20) & 3u;
        int subtract = (canonical_word & UINT32_C(0x200)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t source_element_size;

        if (vd & 1u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        source_element_size = (uint8_t)(1u << element_shift);
        instruction->name_id = subtract
            ? CDISASM_ARM_NAME_VSUBL : CDISASM_ARM_NAME_VADDL;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, 1),
            16u, (uint8_t)(source_element_size * 2u),
            CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, 0),
            8u, source_element_size, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, 0),
            8u, source_element_size, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffb30ed0))
            == UINT32_C(0xf3b30400)
        || (canonical_word & UINT32_C(0xffb30ed0))
            == UINT32_C(0xf3b30440)
        || (canonical_word & UINT32_C(0xffb30ed0))
            == UINT32_C(0xf3b30480)
        || (canonical_word & UINT32_C(0xffb30ed0))
            == UINT32_C(0xf3b304c0)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        int reciprocal_sqrt = (canonical_word & UINT32_C(0x80)) != 0;
        int floating_point = (canonical_word & UINT32_C(0x100)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t vector_size = is_quad ? 16u : 8u;

        if (is_quad && ((vd | vm) & 1u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = reciprocal_sqrt
            ? CDISASM_ARM_NAME_VRSQRTE : CDISASM_ARM_NAME_VRECPE;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        if (floating_point) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        }
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, 4u, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, 4u, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf3000b10)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf3000b50)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf3000c10)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf3000c50)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned element_shift = (canonical_word >> 20) & 3u;
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        int subtract = (canonical_word & UINT32_C(0x100)) == 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t vector_size = is_quad ? 16u : 8u;
        uint8_t element_size;

        if (element_shift == 0u || element_shift == 3u
            || (is_quad && ((vd | vn | vm) & 1u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        element_size = (uint8_t)(1u << element_shift);
        instruction->name_id = subtract
            ? CDISASM_ARM_NAME_VQRDMLSH : CDISASM_ARM_NAME_VQRDMLAH;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b20080)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b200c0)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b20100)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b20140)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b20180)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b201c0)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        static const cdisasm_arm_name_id names[3] = {
            CDISASM_ARM_NAME_VTRN, CDISASM_ARM_NAME_VUZP,
            CDISASM_ARM_NAME_VZIP
        };
        uint32_t form = canonical_word & UINT32_C(0xffb30fd0);
        unsigned element_shift = (canonical_word >> 18) & 3u;
        unsigned operation = ((form >> 7) & 3u) - 1u;
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t vector_size = is_quad ? 16u : 8u;
        uint8_t element_size;

        if (element_shift == 3u || (is_quad && ((vd | vm) & 1u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        element_size = (uint8_t)(1u << element_shift);
        instruction->name_id = names[operation];
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ_WRITE);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ_WRITE);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffb30f50))
            == UINT32_C(0xf3b00600)
        || (canonical_word & UINT32_C(0xffb30f50))
            == UINT32_C(0xf3b00640)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned element_shift = (canonical_word >> 18) & 3u;
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t vector_size = is_quad ? 16u : 8u;
        uint8_t source_element_size;

        if (element_shift == 3u || (is_quad && ((vd | vm) & 1u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        source_element_size = (uint8_t)(1u << element_shift);
        instruction->name_id = CDISASM_ARM_NAME_VPADAL;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, (uint8_t)(source_element_size * 2u),
            CDISASM_OPERAND_ACCESS_READ_WRITE);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, source_element_size, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b00700)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b00740)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b00780)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b007c0)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned element_shift = (canonical_word >> 18) & 3u;
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        int negate = (canonical_word & UINT32_C(0x80)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t vector_size = is_quad ? 16u : 8u;
        uint8_t element_size;

        if (element_shift == 3u || (is_quad && ((vd | vm) & 1u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        element_size = (uint8_t)(1u << element_shift);
        instruction->name_id = negate
            ? CDISASM_ARM_NAME_VQNEG : CDISASM_ARM_NAME_VQABS;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffbf0fd0))
            == UINT32_C(0xf3b20000)
        || (canonical_word & UINT32_C(0xffbf0fd0))
            == UINT32_C(0xf3b20040)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t vector_size = is_quad ? 16u : 8u;

        if (is_quad && ((vd | vm) & 1u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = CDISASM_ARM_NAME_VSWP;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, 1u, CDISASM_OPERAND_ACCESS_READ_WRITE);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, 1u, CDISASM_OPERAND_ACCESS_READ_WRITE);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b20400)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b20440)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b20480)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b204c0)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b20500)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b20540)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b20580)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b205c0)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b20680)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b206c0)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b20780)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b207c0)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        uint32_t form = canonical_word & UINT32_C(0xffb30f90);
        unsigned precision = (canonical_word >> 18) & 3u;
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        cdisasm_arm_name_id name_id;
        uint8_t vector_size = is_quad ? 16u : 8u;
        uint8_t element_size;

        switch (form & ~UINT32_C(0x40)) {
            case UINT32_C(0xf3b20400):
                name_id = CDISASM_ARM_NAME_VRINTN;
                break;
            case UINT32_C(0xf3b20480):
                name_id = CDISASM_ARM_NAME_VRINTX;
                break;
            case UINT32_C(0xf3b20500):
                name_id = CDISASM_ARM_NAME_VRINTA;
                break;
            case UINT32_C(0xf3b20580):
                name_id = CDISASM_ARM_NAME_VRINTZ;
                break;
            case UINT32_C(0xf3b20680):
                name_id = CDISASM_ARM_NAME_VRINTM;
                break;
            default:
                name_id = CDISASM_ARM_NAME_VRINTP;
                break;
        }
        if ((precision != 1u && precision != 2u)
            || (is_quad && ((vd | vm) & 1u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        element_size = precision == 1u ? 2u : 4u;
        instruction->name_id = name_id;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(required_capabilities,
            CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_NEON
                | (precision == 1u ? CDISASM_ARM_CAP_FP16 : 0u));
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b00400)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b00440)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b00480)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b004c0)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b00500)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b00540)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b00580)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b005c0)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        static const cdisasm_arm_name_id names[4] = {
            CDISASM_ARM_NAME_VCLS, CDISASM_ARM_NAME_VCLZ,
            CDISASM_ARM_NAME_VCNT, CDISASM_ARM_NAME_VMVN
        };
        uint32_t form = canonical_word & UINT32_C(0xffb30fd0);
        unsigned element_shift = (canonical_word >> 18) & 3u;
        unsigned operation = (form >> 7) & 3u;
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t vector_size = is_quad ? 16u : 8u;
        uint8_t element_size;

        if (element_shift == 3u || (operation >= 2u && element_shift != 0u)
            || (is_quad && ((vd | vm) & 1u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        element_size = (uint8_t)(1u << element_shift);
        instruction->name_id = names[operation];
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b00000)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b00040)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b00080)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b000c0)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b00100)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b00140)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        uint32_t form = canonical_word & UINT32_C(0xffb30fd0);
        unsigned element_shift = (canonical_word >> 18) & 3u;
        unsigned operation = (form >> 7) & 3u;
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t vector_size = is_quad ? 16u : 8u;

        if (element_shift >= 3u - operation
            || (is_quad && ((vd | vm) & 1u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = operation == 0u
            ? CDISASM_ARM_NAME_VREV64
            : operation == 1u ? CDISASM_ARM_NAME_VREV32
                              : CDISASM_ARM_NAME_VREV16;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, (uint8_t)(1u << element_shift),
            CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, (uint8_t)(1u << element_shift),
            CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffb00050))
            == UINT32_C(0xf2b00000)
        || (canonical_word & UINT32_C(0xffb00050))
            == UINT32_C(0xf2b00040)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        unsigned immediate = (canonical_word >> 8) & 15u;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t vector_size = is_quad ? 16u : 8u;

        if ((!is_quad && immediate >= 8u)
            || (is_quad && ((vd | vn | vm) & 1u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = CDISASM_ARM_NAME_VEXT;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, 1u, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, is_quad),
            vector_size, 1u, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, 1u, CDISASM_OPERAND_ACCESS_READ);
        append_immediate(instruction, immediate, 1u);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffb00f50))
            == UINT32_C(0xf3100110)
        || (canonical_word & UINT32_C(0xffb00f50))
            == UINT32_C(0xf3100150)
        || (canonical_word & UINT32_C(0xffb00f50))
            == UINT32_C(0xf3200110)
        || (canonical_word & UINT32_C(0xffb00f50))
            == UINT32_C(0xf3200150)
        || (canonical_word & UINT32_C(0xffb00f50))
            == UINT32_C(0xf3300110)
        || (canonical_word & UINT32_C(0xffb00f50))
            == UINT32_C(0xf3300150)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        uint32_t form = canonical_word & UINT32_C(0xffb00f50);
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t vector_size = is_quad ? 16u : 8u;

        if (is_quad && ((vd | vn | vm) & 1u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = form == UINT32_C(0xf3100110)
                || form == UINT32_C(0xf3100150)
            ? CDISASM_ARM_NAME_VBSL
            : form == UINT32_C(0xf3200110)
                    || form == UINT32_C(0xf3200150)
                ? CDISASM_ARM_NAME_VBIT : CDISASM_ARM_NAME_VBIF;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, 1u, CDISASM_OPERAND_ACCESS_READ_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, is_quad),
            vector_size, 1u, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, 1u, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffa00f50))
            == UINT32_C(0xf3000e10)
        || (canonical_word & UINT32_C(0xffa00f50))
            == UINT32_C(0xf3000e50)
        || (canonical_word & UINT32_C(0xffa00f50))
            == UINT32_C(0xf3200e10)
        || (canonical_word & UINT32_C(0xffa00f50))
            == UINT32_C(0xf3200e50)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        int greater_than = (canonical_word & UINT32_C(0x00200000)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t vector_size = is_quad ? 16u : 8u;

        if (is_quad && ((vd | vn | vm) & 1u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = greater_than
            ? CDISASM_ARM_NAME_VACGT : CDISASM_ARM_NAME_VACGE;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, 4u, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, is_quad),
            vector_size, 4u, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, 4u, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffa00f50))
            == UINT32_C(0xf3200d00)
        || (canonical_word & UINT32_C(0xffa00f50))
            == UINT32_C(0xf3200d40)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t vector_size = is_quad ? 16u : 8u;

        if (is_quad && ((vd | vn | vm) & 1u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = CDISASM_ARM_NAME_VABD;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, 4u, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, is_quad),
            vector_size, 4u, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, 4u, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000700)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000740)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000710)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000750)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned element_shift = (canonical_word >> 20) & 3u;
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        int accumulate = (canonical_word & UINT32_C(0x10)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t vector_size = is_quad ? 16u : 8u;
        uint8_t element_size;

        if (element_shift == 3u || (is_quad && ((vd | vn | vm) & 1u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        element_size = (uint8_t)(1u << element_shift);
        instruction->name_id = accumulate
            ? CDISASM_ARM_NAME_VABA : CDISASM_ARM_NAME_VABD;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, element_size,
            accumulate ? CDISASM_OPERAND_ACCESS_READ_WRITE
                       : CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000600)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000640)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000610)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000650)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned element_shift = (canonical_word >> 20) & 3u;
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        int minimum = (canonical_word & UINT32_C(0x10)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t vector_size = is_quad ? 16u : 8u;
        uint8_t element_size;

        if (element_shift == 3u || (is_quad && ((vd | vn | vm) & 1u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        element_size = (uint8_t)(1u << element_shift);
        instruction->name_id = minimum
            ? CDISASM_ARM_NAME_VMIN : CDISASM_ARM_NAME_VMAX;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf2000b00)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf2000b40)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf3000b00)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf3000b40)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned element_shift = (canonical_word >> 20) & 3u;
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        int rounding = (canonical_word & UINT32_C(0x01000000)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t vector_size = is_quad ? 16u : 8u;
        uint8_t element_size;

        if (element_shift == 0u || element_shift == 3u
            || (is_quad && ((vd | vn | vm) & 1u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        element_size = (uint8_t)(1u << element_shift);
        instruction->name_id = rounding
            ? CDISASM_ARM_NAME_VQRDMULH : CDISASM_ARM_NAME_VQDMULH;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf2000810)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf2000850)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned element_shift = (canonical_word >> 20) & 3u;
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t vector_size = is_quad ? 16u : 8u;
        uint8_t element_size;

        if (element_shift == 3u || (is_quad && ((vd | vn | vm) & 1u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        element_size = (uint8_t)(1u << element_shift);
        instruction->name_id = CDISASM_ARM_NAME_VTST;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000400)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000440)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000410)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000450)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000500)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000540)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000510)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000550)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned element_shift = (canonical_word >> 20) & 3u;
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        int saturating = (canonical_word & UINT32_C(0x10)) != 0;
        int rounding = (canonical_word & UINT32_C(0x100)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t vector_size = is_quad ? 16u : 8u;
        uint8_t element_size;

        if (element_shift == 3u || (is_quad && ((vd | vn | vm) & 1u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        element_size = (uint8_t)(1u << element_shift);
        instruction->name_id = rounding
            ? (saturating ? CDISASM_ARM_NAME_VQRSHL : CDISASM_ARM_NAME_VRSHL)
            : (saturating ? CDISASM_ARM_NAME_VQSHL : CDISASM_ARM_NAME_VSHL);
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vn, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000000)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000040)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000010)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000050)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned element_shift = (canonical_word >> 20) & 3u;
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        int saturating = (canonical_word & UINT32_C(0x10)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t vector_size = is_quad ? 16u : 8u;
        uint8_t element_size;

        if (element_shift == 3u || (is_quad && ((vd | vn | vm) & 1u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        element_size = (uint8_t)(1u << element_shift);
        instruction->name_id = saturating
            ? CDISASM_ARM_NAME_VQADD : CDISASM_ARM_NAME_VHADD;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000100)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000140)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000200)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000240)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000210)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000250)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        uint32_t form = canonical_word & UINT32_C(0xfe800f50);
        unsigned element_shift = (canonical_word >> 20) & 3u;
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t vector_size = is_quad ? 16u : 8u;
        uint8_t element_size;

        if (element_shift == 3u || (is_quad && ((vd | vn | vm) & 1u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        element_size = (uint8_t)(1u << element_shift);
        instruction->name_id = (form & UINT32_C(0x00000300))
                == UINT32_C(0x00000100)
            ? CDISASM_ARM_NAME_VRHADD
            : (form & UINT32_C(0x10)) != 0
                ? CDISASM_ARM_NAME_VQSUB : CDISASM_ARM_NAME_VHSUB;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000300)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000340)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000310)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000350)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned element_shift = (canonical_word >> 20) & 3u;
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        int greater_equal = (canonical_word & UINT32_C(0x10)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t vector_size = is_quad ? 16u : 8u;
        uint8_t element_size;

        if (element_shift == 3u || (is_quad && ((vd | vn | vm) & 1u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        element_size = (uint8_t)(1u << element_shift);
        instruction->name_id = greater_equal
            ? CDISASM_ARM_NAME_VCGE : CDISASM_ARM_NAME_VCGT;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffa00f50))
            == UINT32_C(0xf3000e00)
        || (canonical_word & UINT32_C(0xffa00f50))
            == UINT32_C(0xf3000e40)
        || (canonical_word & UINT32_C(0xffa00f50))
            == UINT32_C(0xf3200e00)
        || (canonical_word & UINT32_C(0xffa00f50))
            == UINT32_C(0xf3200e40)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        int is_quad = (canonical_word & UINT32_C(0x40)) != 0;
        int greater_than = (canonical_word & UINT32_C(0x00200000)) != 0;
        unsigned vd = ((canonical_word >> 12) & 15u)
            | ((canonical_word >> 18) & 16u);
        unsigned vn = ((canonical_word >> 16) & 15u)
            | ((canonical_word >> 3) & 16u);
        unsigned vm = (canonical_word & 15u)
            | ((canonical_word >> 1) & 16u);
        uint8_t vector_size = is_quad ? 16u : 8u;

        if (is_quad && ((vd | vn | vm) & 1u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = greater_than
            ? CDISASM_ARM_NAME_VCGT : CDISASM_ARM_NAME_VCGE;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_SIMD
            | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_vector_register(instruction, a32_vector_reg(vd, is_quad),
            vector_size, 4u, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, is_quad),
            vector_size, 4u, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, is_quad),
            vector_size, 4u, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000a00)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2000a10)
        || (canonical_word & UINT32_C(0xffa00f50))
            == UINT32_C(0xf3000f00)
        || (canonical_word & UINT32_C(0xffa00f50))
            == UINT32_C(0xf3200f00)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        int floating_pair = (canonical_word & UINT32_C(0x01000500))
            == UINT32_C(0x01000500);
        int minimum = floating_pair
            ? (canonical_word & UINT32_C(0x00200000)) != 0
            : (canonical_word & UINT32_C(0x10)) != 0;
        unsigned pair_element_shift = (canonical_word >> 20) & 3u;
        uint8_t pair_element_size = floating_pair
            ? 4u : (uint8_t)(1u << pair_element_shift);

        if ((!floating_pair && pair_element_shift == 3u)
            || (vd | vn | vm) >= 32u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = minimum
            ? CDISASM_ARM_NAME_VPMIN : CDISASM_ARM_NAME_VPMAX;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        if (floating_pair) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        }
        append_vector_register(instruction, a32_vector_reg(vd, 0),
            8u, pair_element_size, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, 0),
            8u, pair_element_size, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, 0),
            8u, pair_element_size, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xff800f10))
            == UINT32_C(0xf2000b10)
        || (canonical_word & UINT32_C(0xffa00f10))
            == UINT32_C(0xf3000d00)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        int floating_pair_add = (canonical_word & UINT32_C(0x01000600))
            == UINT32_C(0x01000400);
        unsigned pair_add_shift = (canonical_word >> 20) & 3u;
        uint8_t pair_add_element = floating_pair_add
            ? 4u : (uint8_t)(1u << pair_add_shift);

        if ((!floating_pair_add && pair_add_shift == 3u)
            || (canonical_word & UINT32_C(0x40)) != 0u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = CDISASM_ARM_NAME_VPADD;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        if (floating_pair_add) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        }
        append_vector_register(instruction, a32_vector_reg(vd, 0),
            8u, pair_add_element, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vn, 0),
            8u, pair_add_element, CDISASM_OPERAND_ACCESS_READ);
        append_vector_register(instruction, a32_vector_reg(vm, 0),
            8u, pair_add_element, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffb30f50))
            == UINT32_C(0xf3b00200)
        || (canonical_word & UINT32_C(0xffb30f50))
            == UINT32_C(0xf3b00240)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned source_shift = (canonical_word >> 18) & 3u;
        int long_quad = (canonical_word & UINT32_C(0x40)) != 0;
        uint8_t vector_size = long_quad ? 16u : 8u;
        uint8_t source_element;

        if (source_shift == 3u || (long_quad && ((vd | vm) & 1u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        source_element = (uint8_t)(1u << source_shift);
        instruction->name_id = CDISASM_ARM_NAME_VPADDL;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, long_quad),
            vector_size, (uint8_t)(source_element * 2u),
            CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vm, long_quad),
            vector_size, source_element, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b20200)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned narrow_shift = (canonical_word >> 18) & 3u;
        uint8_t destination_element;

        if (narrow_shift == 3u || (vm & 1u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        destination_element = (uint8_t)(1u << narrow_shift);
        instruction->name_id = CDISASM_ARM_NAME_VMOVN;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, 0),
            8u, destination_element, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vm, 1),
            16u, (uint8_t)(destination_element * 2u),
            CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffb30f90))
            == UINT32_C(0xf3b20280)
        || (canonical_word & UINT32_C(0xffb30fd0))
            == UINT32_C(0xf3b20240)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned narrow_shift = (canonical_word >> 18) & 3u;
        int unsigned_destination =
            (canonical_word & UINT32_C(0xffb30fd0))
                == UINT32_C(0xf3b20240);
        uint8_t destination_element;

        if (narrow_shift == 3u || (vm & 1u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        destination_element = (uint8_t)(1u << narrow_shift);
        instruction->name_id = unsigned_destination
            ? CDISASM_ARM_NAME_VQMOVUN : CDISASM_ARM_NAME_VQMOVN;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, 0),
            8u, destination_element, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vm, 1),
            16u, (uint8_t)(destination_element * 2u),
            CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    /* Saturating narrowing right shifts, with optional rounding and
     * signed-to-unsigned destination conversion. */
    if ((canonical_word & UINT32_C(0xfe800fd0))
            == UINT32_C(0xf2800910)
        || (canonical_word & UINT32_C(0xfe800fd0))
            == UINT32_C(0xf2800950)
        || (canonical_word & UINT32_C(0xff800fd0))
            == UINT32_C(0xf3800810)
        || (canonical_word & UINT32_C(0xff800fd0))
            == UINT32_C(0xf3800850)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned imm6 = (canonical_word >> 16) & 63u;
        unsigned source_bits;
        unsigned shift;
        int rounding = (canonical_word & UINT32_C(0x40)) != 0;
        int unsigned_destination =
            (canonical_word & UINT32_C(0xff800f90))
                == UINT32_C(0xf3800810);

        if ((imm6 & 32u) != 0u) {
            source_bits = 64u;
        } else if ((imm6 & 16u) != 0u) {
            source_bits = 32u;
        } else if ((imm6 & 8u) != 0u) {
            source_bits = 16u;
        } else {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        shift = source_bits - imm6;
        if (shift == 0u || shift > source_bits / 2u || (vm & 1u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = unsigned_destination
            ? (rounding ? CDISASM_ARM_NAME_VQRSHRUN
                        : CDISASM_ARM_NAME_VQSHRUN)
            : (rounding ? CDISASM_ARM_NAME_VQRSHRN
                        : CDISASM_ARM_NAME_VQSHRN);
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, 0),
            8u, (uint8_t)(source_bits / 16u),
            CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vm, 1),
            16u, (uint8_t)(source_bits / 8u),
            CDISASM_OPERAND_ACCESS_READ);
        append_immediate(instruction, shift, 1u);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xff800fd0))
            == UINT32_C(0xf2800810)
        || (canonical_word & UINT32_C(0xff800fd0))
            == UINT32_C(0xf2800850)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned imm6 = (canonical_word >> 16) & 63u;
        unsigned source_bits;
        unsigned shift;
        int rounding = (canonical_word & UINT32_C(0x40)) != 0;

        if ((imm6 & 32u) != 0u) {
            source_bits = 64u;
        } else if ((imm6 & 16u) != 0u) {
            source_bits = 32u;
        } else if ((imm6 & 8u) != 0u) {
            source_bits = 16u;
        } else {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        shift = source_bits - imm6;
        if (shift == 0u || shift > source_bits / 2u || (vm & 1u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = rounding
            ? CDISASM_ARM_NAME_VRSHRN : CDISASM_ARM_NAME_VSHRN;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, 0),
            8u, (uint8_t)(source_bits / 16u),
            CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vm, 1),
            16u, (uint8_t)(source_bits / 8u),
            CDISASM_OPERAND_ACCESS_READ);
        append_immediate(instruction, shift, 1u);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if ((canonical_word & UINT32_C(0xffb00f10))
            == UINT32_C(0xfe800900)
        || (canonical_word & UINT32_C(0xffb00f10))
            == UINT32_C(0xfe800a00)
        || (canonical_word & UINT32_C(0xffb00f10))
            == UINT32_C(0xfe800b00)) {
#if !USE_EXTRA_OPCODES
        (void)instruction;
        (void)required_capabilities;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned precision = (canonical_word >> 8) & 3u;
        int is_double = precision == 3u;
        unsigned fp_vd = is_double
            ? (((canonical_word >> 18) & 16u)
                | ((canonical_word >> 12) & 15u))
            : (((canonical_word >> 11) & 30u)
                | ((canonical_word >> 22) & 1u));
        unsigned fp_vn = is_double
            ? (((canonical_word >> 3) & 16u)
                | ((canonical_word >> 16) & 15u))
            : (((canonical_word >> 15) & 30u)
                | ((canonical_word >> 7) & 1u));
        unsigned fp_vm = is_double
            ? (((canonical_word >> 1) & 16u)
                | (canonical_word & 15u))
            : (((canonical_word & 15u) << 1)
                | ((canonical_word >> 5) & 1u));
        cdisasm_arm_reg_id reg_base = is_double
            ? CDISASM_ARM_REG_D0
            : precision == 2u ? CDISASM_ARM_REG_S0 : CDISASM_ARM_REG_H0;
        uint8_t fp_size = is_double ? 8u : precision == 2u ? 4u : 2u;

        instruction->name_id = (canonical_word & UINT32_C(0x40)) != 0u
            ? CDISASM_ARM_NAME_VMINNM : CDISASM_ARM_NAME_VMAXNM;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_register(
            instruction, (cdisasm_arm_reg_id)(reg_base + fp_vd), fp_size,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_register(
            instruction, (cdisasm_arm_reg_id)(reg_base + fp_vn), fp_size,
            CDISASM_OPERAND_ACCESS_READ);
        append_register(
            instruction, (cdisasm_arm_reg_id)(reg_base + fp_vm), fp_size,
            CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_VFP
                | (precision == 1u ? CDISASM_ARM_CAP_FP16 : 0u));
        return CDISASM_STATUS_OK;
#endif
    }
    if ((canonical_word & UINT32_C(0xffbc0fd0))
            == UINT32_C(0xfeb80940)
        || (canonical_word & UINT32_C(0xffbc0fd0))
            == UINT32_C(0xfeb80a40)
        || (canonical_word & UINT32_C(0xffbc0fd0))
            == UINT32_C(0xfeb80b40)) {
#if !USE_EXTRA_OPCODES
        (void)instruction;
        (void)required_capabilities;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        static const cdisasm_arm_name_id names[4] = {
            CDISASM_ARM_NAME_VRINTA, CDISASM_ARM_NAME_VRINTN,
            CDISASM_ARM_NAME_VRINTP, CDISASM_ARM_NAME_VRINTM
        };
        unsigned operation = (canonical_word >> 16) & 3u;
        unsigned precision = (canonical_word >> 8) & 3u;
        int is_double = precision == 3u;
        unsigned fp_vd = is_double
            ? (((canonical_word >> 18) & 16u)
                | ((canonical_word >> 12) & 15u))
            : (((canonical_word >> 11) & 30u)
                | ((canonical_word >> 22) & 1u));
        unsigned fp_vm = is_double
            ? (((canonical_word >> 1) & 16u)
                | (canonical_word & 15u))
            : (((canonical_word & 15u) << 1)
                | ((canonical_word >> 5) & 1u));
        cdisasm_arm_reg_id reg_base = is_double
            ? CDISASM_ARM_REG_D0
            : precision == 2u ? CDISASM_ARM_REG_S0 : CDISASM_ARM_REG_H0;
        uint8_t fp_size = is_double ? 8u : precision == 2u ? 4u : 2u;

        instruction->name_id = names[operation];
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_register(
            instruction, (cdisasm_arm_reg_id)(reg_base + fp_vd), fp_size,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_register(
            instruction, (cdisasm_arm_reg_id)(reg_base + fp_vm), fp_size,
            CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_VFP
                | (precision == 1u ? CDISASM_ARM_CAP_FP16 : 0u));
        return CDISASM_STATUS_OK;
#endif
    }

    /* A32 and T32 share the canonical Advanced SIMD encoding after the
     * Thumb halfword transport has been normalized by arm_t32_decoder.c.
     * The public AARCHMRS leaves expose Q and size controls as fields, but
     * LLVM 21 and the architectural Q-register spelling establish the late
     * validity constraints: Q must be one and every encoded D-register
     * number must be even; the two-register class additionally fixes
     * size=10.  Claim the whole exact envelopes so reserved controls remain
     * INVALID even when optional semantics are compiled out. */
    if ((canonical_word & UINT32_C(0xffb30bd0))
            == UINT32_C(0xf3b10000)
        || (canonical_word & UINT32_C(0xffb30bd0))
            == UINT32_C(0xf3b10040)
        || (canonical_word & UINT32_C(0xffb30bd0))
            == UINT32_C(0xf3b10080)
        || (canonical_word & UINT32_C(0xffb30bd0))
            == UINT32_C(0xf3b100c0)
        || (canonical_word & UINT32_C(0xffb30bd0))
            == UINT32_C(0xf3b10180)
        || (canonical_word & UINT32_C(0xffb30bd0))
            == UINT32_C(0xf3b101c0)
        || (canonical_word & UINT32_C(0xffb30bd0))
            == UINT32_C(0xf3b10200)
        || (canonical_word & UINT32_C(0xffb30bd0))
            == UINT32_C(0xf3b10240)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        uint32_t operation = canonical_word & UINT32_C(0x00000380);
        unsigned element_shift = (canonical_word >> 18) & 3u;
        int zero_quad = (canonical_word & UINT32_C(0x40)) != 0;
        uint8_t vector_size = zero_quad ? 16u : 8u;
        uint8_t element_size;

        if (element_shift == 3u || (zero_quad && ((vd | vm) & 1u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        element_size = (uint8_t)(1u << element_shift);
        instruction->name_id = operation == UINT32_C(0x00000000)
            ? CDISASM_ARM_NAME_VCGT
            : operation == UINT32_C(0x00000080)
                ? CDISASM_ARM_NAME_VCGE
            : operation == UINT32_C(0x00000180)
                ? CDISASM_ARM_NAME_VCLE : CDISASM_ARM_NAME_VCLT;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction, a32_vector_reg(vd, zero_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_WRITE);
        append_vector_register(instruction, a32_vector_reg(vm, zero_quad),
            vector_size, element_size, CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    {
        static const uint32_t aes_values[4] = {
            UINT32_C(0xf3b00300), UINT32_C(0xf3b00340),
            UINT32_C(0xf3b00380), UINT32_C(0xf3b003c0)
        };
#if USE_EXTRA_OPCODES
        static const cdisasm_arm_name_id aes_names[4] = {
            CDISASM_ARM_NAME_AESE, CDISASM_ARM_NAME_AESD,
            CDISASM_ARM_NAME_AESMC, CDISASM_ARM_NAME_AESIMC
        };
#endif
        size_t operation;

        for (operation = 0u; operation < 4u; ++operation) {
            if ((canonical_word & UINT32_C(0xffb30fd0))
                    != aes_values[operation]) {
                continue;
            }
            if (((vd | vm) & 1u) != 0u) {
                return CDISASM_STATUS_INVALID_INSTRUCTION;
            }
#if !USE_EXTRA_OPCODES
            return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
            instruction->name_id = aes_names[operation];
            instruction->condition = CDISASM_ARM_CONDITION_AL;
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
            append_vector_register(
                instruction, a32_vector_reg(vd, 1), 16u, 1u,
                operation < 2u ? CDISASM_OPERAND_ACCESS_READ_WRITE
                               : CDISASM_OPERAND_ACCESS_WRITE);
            append_vector_register(
                instruction, a32_vector_reg(vm, 1), 16u, 1u,
                CDISASM_OPERAND_ACCESS_READ);
            cdisasm_arm_requirements_set_legacy(
                required_capabilities,
                CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_NEON);
            (void)cdisasm_arm_requirements_add_feature(
                required_capabilities, CDISASM_ARM_FEATURE_AES);
            return CDISASM_STATUS_OK;
#endif
        }
    }
    {
        static const uint32_t sha3_values[7] = {
            UINT32_C(0xf2000c00), UINT32_C(0xf2100c00),
            UINT32_C(0xf2200c00), UINT32_C(0xf2300c00),
            UINT32_C(0xf3000c00), UINT32_C(0xf3100c00),
            UINT32_C(0xf3200c00)
        };
#if USE_EXTRA_OPCODES
        static const cdisasm_arm_name_id sha3_names[7] = {
            CDISASM_ARM_NAME_SHA1C, CDISASM_ARM_NAME_SHA1P,
            CDISASM_ARM_NAME_SHA1M, CDISASM_ARM_NAME_SHA1SU0,
            CDISASM_ARM_NAME_SHA256H, CDISASM_ARM_NAME_SHA256H2,
            CDISASM_ARM_NAME_SHA256SU1
        };
#endif
        size_t operation;

        for (operation = 0u; operation < 7u; ++operation) {
            if ((canonical_word & UINT32_C(0xffb00f10))
                    != sha3_values[operation]) {
                continue;
            }
            if (!is_quad || ((vd | vn | vm) & 1u) != 0u) {
                return CDISASM_STATUS_INVALID_INSTRUCTION;
            }
#if !USE_EXTRA_OPCODES
            return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
            instruction->name_id = sha3_names[operation];
            instruction->condition = CDISASM_ARM_CONDITION_AL;
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
            append_vector_register(
                instruction, a32_vector_reg(vd, 1), 16u, 4u,
                CDISASM_OPERAND_ACCESS_READ_WRITE);
            append_vector_register(
                instruction, a32_vector_reg(vn, 1), 16u, 4u,
                CDISASM_OPERAND_ACCESS_READ);
            append_vector_register(
                instruction, a32_vector_reg(vm, 1), 16u, 4u,
                CDISASM_OPERAND_ACCESS_READ);
            cdisasm_arm_requirements_set_legacy(
                required_capabilities,
                CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_NEON);
            (void)cdisasm_arm_requirements_add_feature(
                required_capabilities,
                operation <= 3u ? CDISASM_ARM_FEATURE_SHA1
                                : CDISASM_ARM_FEATURE_SHA256);
            return CDISASM_STATUS_OK;
#endif
        }
    }
    {
        static const uint32_t sha2_values[3] = {
            UINT32_C(0xf3b102c0), UINT32_C(0xf3b20380),
            UINT32_C(0xf3b203c0)
        };
#if USE_EXTRA_OPCODES
        static const cdisasm_arm_name_id sha2_names[3] = {
            CDISASM_ARM_NAME_SHA1H, CDISASM_ARM_NAME_SHA1SU1,
            CDISASM_ARM_NAME_SHA256SU0
        };
#endif
        size_t operation;

        for (operation = 0u; operation < 3u; ++operation) {
            if ((canonical_word & UINT32_C(0xffb30fd0))
                    != sha2_values[operation]) {
                continue;
            }
            if (((canonical_word >> 18) & 3u) != 2u
                || ((vd | vm) & 1u) != 0u) {
                return CDISASM_STATUS_INVALID_INSTRUCTION;
            }
#if !USE_EXTRA_OPCODES
            return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
            instruction->name_id = sha2_names[operation];
            instruction->condition = CDISASM_ARM_CONDITION_AL;
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
            append_vector_register(
                instruction, a32_vector_reg(vd, 1), 16u, 4u,
                operation == 0u ? CDISASM_OPERAND_ACCESS_WRITE
                                : CDISASM_OPERAND_ACCESS_READ_WRITE);
            append_vector_register(
                instruction, a32_vector_reg(vm, 1), 16u, 4u,
                CDISASM_OPERAND_ACCESS_READ);
            cdisasm_arm_requirements_set_legacy(
                required_capabilities,
                CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_NEON);
            (void)cdisasm_arm_requirements_add_feature(
                required_capabilities,
                operation <= 1u ? CDISASM_ARM_FEATURE_SHA1
                                : CDISASM_ARM_FEATURE_SHA256);
            return CDISASM_STATUS_OK;
#endif
        }
    }

    if ((canonical_word >> 28) != CDISASM_ARM_CONDITION_NV
        && scalar_fp_precision != 0u
        && (scalar_fp_operation == UINT32_C(0x0e000800)
            || scalar_fp_operation == UINT32_C(0x0e000840)
            || scalar_fp_operation == UINT32_C(0x0e100800)
            || scalar_fp_operation == UINT32_C(0x0e100840)
            || scalar_fp_operation == UINT32_C(0x0e200800)
            || scalar_fp_operation == UINT32_C(0x0e200840)
            || scalar_fp_operation == UINT32_C(0x0e300800)
            || scalar_fp_operation == UINT32_C(0x0e300840)
            || scalar_fp_operation == UINT32_C(0x0e800800)
            || scalar_fp_operation == UINT32_C(0x0e900800)
            || scalar_fp_operation == UINT32_C(0x0e900840)
            || scalar_fp_operation == UINT32_C(0x0ea00800)
            || scalar_fp_operation == UINT32_C(0x0ea00840))) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        int is_double = scalar_fp_precision == 3u;
        unsigned fp_vd = is_double
            ? (((canonical_word >> 18) & 16u)
                | ((canonical_word >> 12) & 15u))
            : (((canonical_word >> 11) & 30u)
                | ((canonical_word >> 22) & 1u));
        unsigned fp_vn = is_double
            ? (((canonical_word >> 3) & 16u)
                | ((canonical_word >> 16) & 15u))
            : (((canonical_word >> 15) & 30u)
                | ((canonical_word >> 7) & 1u));
        unsigned fp_vm = is_double
            ? (((canonical_word >> 1) & 16u)
                | (canonical_word & 15u))
            : (((canonical_word & 15u) << 1)
                | ((canonical_word >> 5) & 1u));
        cdisasm_arm_reg_id reg_base = is_double ? CDISASM_ARM_REG_D0
            : scalar_fp_precision == 1u
                ? CDISASM_ARM_REG_H0 : CDISASM_ARM_REG_S0;
        uint8_t fp_size = is_double ? 8u
            : scalar_fp_precision == 1u ? 2u : 4u;
        int accumulate = scalar_fp_operation == UINT32_C(0x0e000800)
            || scalar_fp_operation == UINT32_C(0x0e000840)
            || scalar_fp_operation == UINT32_C(0x0e100800)
            || scalar_fp_operation == UINT32_C(0x0e100840)
            || scalar_fp_operation == UINT32_C(0x0e900800)
            || scalar_fp_operation == UINT32_C(0x0e900840)
            || scalar_fp_operation == UINT32_C(0x0ea00800)
            || scalar_fp_operation == UINT32_C(0x0ea00840);

        instruction->name_id =
            scalar_fp_operation == UINT32_C(0x0e000800)
                ? CDISASM_ARM_NAME_VMLA
            : scalar_fp_operation == UINT32_C(0x0e000840)
                ? CDISASM_ARM_NAME_VMLS
            : scalar_fp_operation == UINT32_C(0x0e100800)
                ? CDISASM_ARM_NAME_VNMLS
            : scalar_fp_operation == UINT32_C(0x0e100840)
                ? CDISASM_ARM_NAME_VNMLA
            : scalar_fp_operation == UINT32_C(0x0e200840)
                ? CDISASM_ARM_NAME_VNMUL
            : scalar_fp_operation == UINT32_C(0x0e900800)
                ? CDISASM_ARM_NAME_VFNMS
            : scalar_fp_operation == UINT32_C(0x0e900840)
                ? CDISASM_ARM_NAME_VFNMA
            : scalar_fp_operation == UINT32_C(0x0ea00800)
                ? CDISASM_ARM_NAME_VFMA
            : scalar_fp_operation == UINT32_C(0x0ea00840)
                ? CDISASM_ARM_NAME_VFMS
            : scalar_fp_operation == UINT32_C(0x0e200800)
                ? CDISASM_ARM_NAME_VMUL
            : scalar_fp_operation == UINT32_C(0x0e300800)
                ? CDISASM_ARM_NAME_VADD
            : scalar_fp_operation == UINT32_C(0x0e300840)
                ? CDISASM_ARM_NAME_VSUB
                : CDISASM_ARM_NAME_VDIV;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_register(
            instruction, (cdisasm_arm_reg_id)(reg_base + fp_vd), fp_size,
            accumulate ? CDISASM_OPERAND_ACCESS_READ_WRITE
                       : CDISASM_OPERAND_ACCESS_WRITE);
        append_register(
            instruction, (cdisasm_arm_reg_id)(reg_base + fp_vn), fp_size,
            CDISASM_OPERAND_ACCESS_READ);
        append_register(
            instruction, (cdisasm_arm_reg_id)(reg_base + fp_vm), fp_size,
            CDISASM_OPERAND_ACCESS_READ);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(required_capabilities,
            (scalar_fp_precision == 1u
                    ? CDISASM_ARM_CAP_V8 : CDISASM_ARM_CAP_V7)
                | CDISASM_ARM_CAP_VFP
                | (scalar_fp_precision == 1u
                    ? CDISASM_ARM_CAP_FP16 : 0u));
        return CDISASM_STATUS_OK;
#endif
    }

    /* Integer scalar-by-element multiply and multiply-accumulate forms. */
    if ((canonical_word & UINT32_C(0xff800e50))
            == UINT32_C(0xf2800040)
        || (canonical_word & UINT32_C(0xff800e50))
            == UINT32_C(0xf3800040)
        || (canonical_word & UINT32_C(0xff800e50))
            == UINT32_C(0xf2800440)
        || (canonical_word & UINT32_C(0xff800e50))
            == UINT32_C(0xf3800440)
        || (canonical_word & UINT32_C(0xff800e50))
            == UINT32_C(0xf2800840)
        || (canonical_word & UINT32_C(0xff800e50))
            == UINT32_C(0xf3800840)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2800240)
        || (canonical_word & UINT32_C(0xfe800f50))
            == UINT32_C(0xf2800640)) {
        uint32_t widening_form =
            canonical_word & UINT32_C(0xfe800f50);
        int widening = widening_form == UINT32_C(0xf2800240)
            || widening_form == UINT32_C(0xf2800640);
        int is_quad = !widening
            && (canonical_word & UINT32_C(0x01000000)) != 0;
        unsigned element_shift = (canonical_word >> 20) & 3u;
        unsigned destination = ((canonical_word >> 18) & 16u)
            | ((canonical_word >> 12) & 15u);
        unsigned first_source = ((canonical_word >> 3) & 16u)
            | ((canonical_word >> 16) & 15u);

        if ((element_shift != 1u && element_shift != 2u)
            || ((widening || is_quad) && (destination & 1u) != 0u)
            || (is_quad && (first_source & 1u) != 0u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        uint32_t form = widening ? widening_form
            : (canonical_word & UINT32_C(0xff800e50))
                & ~UINT32_C(0x01000000);
        unsigned indexed_register;
        uint64_t lane;
        uint8_t vector_size = (widening || is_quad) ? 16u : 8u;
        cdisasm_operand_access destination_access;
        cdisasm_arm_operand *indexed_operand;

        element_size = (uint8_t)(1u << element_shift);
        if (element_shift == 1u) {
            indexed_register = (canonical_word >> 1) & 7u;
            lane = (uint64_t)(((canonical_word >> 5) & 1u) << 1)
                | (uint64_t)(canonical_word & 1u);
        } else {
            indexed_register = canonical_word & 15u;
            lane = (uint64_t)((canonical_word >> 5) & 1u);
        }
        if (form == UINT32_C(0xf2800040)) {
            instruction->name_id = CDISASM_ARM_NAME_VMLA;
            destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        } else if (form == UINT32_C(0xf2800440)) {
            instruction->name_id = CDISASM_ARM_NAME_VMLS;
            destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        } else if (form == UINT32_C(0xf2800840)) {
            instruction->name_id = CDISASM_ARM_NAME_VMUL;
            destination_access = CDISASM_OPERAND_ACCESS_WRITE;
        } else if (form == UINT32_C(0xf2800240)) {
            instruction->name_id = CDISASM_ARM_NAME_VMLAL;
            destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        } else {
            instruction->name_id = CDISASM_ARM_NAME_VMLSL;
            destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
        }
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction,
            a32_vector_reg(destination, widening || is_quad), vector_size,
            widening ? (uint8_t)(element_size * 2u) : element_size,
            destination_access);
        append_vector_register(instruction,
            a32_vector_reg(first_source, is_quad), is_quad ? 16u : 8u,
            element_size, CDISASM_OPERAND_ACCESS_READ);
        indexed_operand = append_vector_register(instruction,
            a32_vector_reg(indexed_register, 0), 8u, element_size,
            CDISASM_OPERAND_ACCESS_READ);
        if (indexed_operand != NULL) {
            indexed_operand->flags = CDISASM_ARM_OPERAND_FLAG_HAS_LANE;
            indexed_operand->imm = lane;
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    /* Saturating doubling multiply-high scalar-by-element forms. */
    if ((canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf2800c40)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf3800c40)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf2800d40)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf3800d40)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf2800e40)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf3800e40)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf2800f40)
        || (canonical_word & UINT32_C(0xff800f50))
            == UINT32_C(0xf3800f40)) {
        int is_quad = (canonical_word & UINT32_C(0x01000000)) != 0;
        unsigned element_shift = (canonical_word >> 20) & 3u;
        unsigned destination = ((canonical_word >> 18) & 16u)
            | ((canonical_word >> 12) & 15u);
        unsigned first_source = ((canonical_word >> 3) & 16u)
            | ((canonical_word >> 16) & 15u);

        if ((element_shift != 1u && element_shift != 2u)
            || (is_quad && ((destination | first_source) & 1u) != 0u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        uint32_t form = canonical_word & UINT32_C(0xff800f50);
        unsigned indexed_register;
        uint64_t lane;
        uint8_t vector_size = is_quad ? 16u : 8u;
        unsigned operation = (form >> 8) & 3u;
        cdisasm_operand_access destination_access = operation >= 2u
            ? CDISASM_OPERAND_ACCESS_READ_WRITE
            : CDISASM_OPERAND_ACCESS_WRITE;
        cdisasm_arm_operand *indexed_operand;

        element_size = (uint8_t)(1u << element_shift);
        if (element_shift == 1u) {
            indexed_register = (canonical_word >> 1) & 7u;
            lane = (uint64_t)(((canonical_word >> 5) & 1u) << 1)
                | (uint64_t)(canonical_word & 1u);
        } else {
            indexed_register = canonical_word & 15u;
            lane = (uint64_t)((canonical_word >> 5) & 1u);
        }
        instruction->name_id = operation == 0u
            ? CDISASM_ARM_NAME_VQDMULH
            : operation == 1u ? CDISASM_ARM_NAME_VQRDMULH
            : operation == 2u ? CDISASM_ARM_NAME_VQRDMLAH
                              : CDISASM_ARM_NAME_VQRDMLSH;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
        append_vector_register(instruction,
            a32_vector_reg(destination, is_quad), vector_size, element_size,
            destination_access);
        append_vector_register(instruction,
            a32_vector_reg(first_source, is_quad), vector_size, element_size,
            CDISASM_OPERAND_ACCESS_READ);
        indexed_operand = append_vector_register(instruction,
            a32_vector_reg(indexed_register, 0), 8u, element_size,
            CDISASM_OPERAND_ACCESS_READ);
        if (indexed_operand != NULL) {
            indexed_operand->flags = CDISASM_ARM_OPERAND_FLAG_HAS_LANE;
            indexed_operand->imm = lane;
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities,
            (operation >= 2u ? CDISASM_ARM_CAP_V8 : CDISASM_ARM_CAP_V7)
                | CDISASM_ARM_CAP_NEON);
        return CDISASM_STATUS_OK;
#endif
    }

    if (size_variable_form == UINT32_C(0xf2000800)) {
        instruction->name_id = CDISASM_ARM_NAME_VADD;
        element_size = (uint8_t)(1u << size_code);
    } else if (size_variable_form == UINT32_C(0xf3000800)) {
        instruction->name_id = CDISASM_ARM_NAME_VSUB;
        element_size = (uint8_t)(1u << size_code);
    } else if (fixed_size_form == UINT32_C(0xf2000d00)) {
        instruction->name_id = CDISASM_ARM_NAME_VADD;
        element_size = 4u;
        floating_point = 1;
    } else if (fixed_size_form == UINT32_C(0xf2200d00)) {
        instruction->name_id = CDISASM_ARM_NAME_VSUB;
        element_size = 4u;
        floating_point = 1;
    } else if (fixed_size_form == UINT32_C(0xf2000110)) {
        instruction->name_id = CDISASM_ARM_NAME_VAND;
        element_size = 1u;
    } else if (fixed_size_form == UINT32_C(0xf2100110)) {
        instruction->name_id = CDISASM_ARM_NAME_VBIC;
        element_size = 1u;
    } else if (fixed_size_form == UINT32_C(0xf2200110)) {
        instruction->name_id = CDISASM_ARM_NAME_VORR;
        element_size = 1u;
    } else if (fixed_size_form == UINT32_C(0xf2300110)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_VORN;
        element_size = 1u;
#endif
    } else if (fixed_size_form == UINT32_C(0xf3000110)) {
        instruction->name_id = CDISASM_ARM_NAME_VEOR;
        element_size = 1u;
    } else if (size_variable_form == UINT32_C(0xf2000910)) {
        if (size_code == 3u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = CDISASM_ARM_NAME_VMUL;
        element_size = (uint8_t)(1u << size_code);
    } else if (fixed_size_form == UINT32_C(0xf3000d10)) {
        instruction->name_id = CDISASM_ARM_NAME_VMUL;
        element_size = 4u;
        floating_point = 1;
    } else if (size_variable_form == UINT32_C(0xf2000900)
        || size_variable_form == UINT32_C(0xf3000900)) {
        if (size_code == 3u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = size_variable_form == UINT32_C(0xf2000900)
            ? CDISASM_ARM_NAME_VMLA : CDISASM_ARM_NAME_VMLS;
        element_size = (uint8_t)(1u << size_code);
#endif
    } else if (fixed_size_form == UINT32_C(0xf2000d10)
        || fixed_size_form == UINT32_C(0xf2200d10)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = fixed_size_form == UINT32_C(0xf2000d10)
            ? CDISASM_ARM_NAME_VMLA : CDISASM_ARM_NAME_VMLS;
        element_size = 4u;
        floating_point = 1;
#endif
    } else if (fixed_size_form == UINT32_C(0xf2000c10)
        || fixed_size_form == UINT32_C(0xf2200c10)) {
        if (is_quad && ((vd | vn | vm) & 1u) != 0u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = fixed_size_form == UINT32_C(0xf2000c10)
            ? CDISASM_ARM_NAME_VFMA : CDISASM_ARM_NAME_VFMS;
        element_size = 4u;
        floating_point = 1;
        accumulator_destination = 1;
#endif
    } else {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }

    if (is_quad && ((vd | vn | vm) & 1u) != 0u) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
    instruction->condition = CDISASM_ARM_CONDITION_AL;
    instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
    if (floating_point) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
    }
    append_vector_register(
        instruction,
        a32_vector_reg(vd, is_quad),
        total_size,
        element_size,
        accumulator_destination ? CDISASM_OPERAND_ACCESS_READ_WRITE
                                : CDISASM_OPERAND_ACCESS_WRITE);
    append_vector_register(
        instruction,
        a32_vector_reg(vn, is_quad),
        total_size,
        element_size,
        CDISASM_OPERAND_ACCESS_READ);
    append_vector_register(
        instruction,
        a32_vector_reg(vm, is_quad),
        total_size,
        element_size,
        CDISASM_OPERAND_ACCESS_READ);
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_NEON);
    return CDISASM_STATUS_OK;
}

static cdisasm_status decode_a32_hint(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities,
    int *recognized)
{
    uint32_t fixed = word & UINT32_C(0x0fffffff);
    int dbg = (word & UINT32_C(0x0ffffff0))
        == UINT32_C(0x0320f0f0);

    *recognized = (fixed >= UINT32_C(0x0320f000)
            && fixed <= UINT32_C(0x0320f005))
        || fixed == UINT32_C(0x0320f010)
        || fixed == UINT32_C(0x0320f012)
        || fixed == UINT32_C(0x0320f014)
        || fixed == UINT32_C(0x0320f016)
        || dbg;
    if (!*recognized) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if (fixed == UINT32_C(0x0320f000)) {
        instruction->name_id = CDISASM_ARM_NAME_NOP;
    } else {
#if !USE_EXTRA_OPCODES
        (void)instruction;
        (void)required_capabilities;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        if (fixed <= UINT32_C(0x0320f005)) {
            static const cdisasm_arm_name_id hint_names[6] = {
                CDISASM_ARM_NAME_NOP, CDISASM_ARM_NAME_YIELD,
                CDISASM_ARM_NAME_WFE, CDISASM_ARM_NAME_WFI,
                CDISASM_ARM_NAME_SEV, CDISASM_ARM_NAME_SEVL
            };
            instruction->name_id = hint_names[fixed & 15u];
        } else {
        instruction->name_id = fixed == UINT32_C(0x0320f010)
            ? CDISASM_ARM_NAME_ESB
            : fixed == UINT32_C(0x0320f012)
                ? CDISASM_ARM_NAME_TSB
                : fixed == UINT32_C(0x0320f014)
                    ? CDISASM_ARM_NAME_CSDB
                    : fixed == UINT32_C(0x0320f016)
                        ? CDISASM_ARM_NAME_CLRBHB
                        : CDISASM_ARM_NAME_DBG;
        }
        if (dbg) {
            append_immediate(instruction, word & 15u, 1u);
        }
#endif
    }
    cdisasm_arm_requirements_set_legacy(
        required_capabilities,
#if USE_EXTRA_OPCODES
        /* CSDB is v6T2, for which this model has no distinct capability;
         * V7 is the conservative representable gate. DBG explicitly has
         * the architectural HasV7 requirement. */
        instruction->name_id == CDISASM_ARM_NAME_SEVL
            ? CDISASM_ARM_CAP_V8
            : instruction->name_id == CDISASM_ARM_NAME_YIELD
                || instruction->name_id == CDISASM_ARM_NAME_WFE
                || instruction->name_id == CDISASM_ARM_NAME_WFI
                || instruction->name_id == CDISASM_ARM_NAME_SEV
                || instruction->name_id == CDISASM_ARM_NAME_CSDB
                || instruction->name_id == CDISASM_ARM_NAME_DBG
            ? CDISASM_ARM_CAP_V7
            : CDISASM_ARM_CAP_V6);
#else
        CDISASM_ARM_CAP_V6);
#endif
#if USE_EXTRA_OPCODES
    if (instruction->name_id == CDISASM_ARM_NAME_ESB) {
        (void)cdisasm_arm_requirements_add_feature(
            required_capabilities, CDISASM_ARM_FEATURE_RAS);
    } else if (instruction->name_id == CDISASM_ARM_NAME_TSB) {
        (void)cdisasm_arm_requirements_add_feature(
            required_capabilities, CDISASM_ARM_FEATURE_TRF);
    } else if (instruction->name_id == CDISASM_ARM_NAME_CLRBHB) {
        (void)cdisasm_arm_requirements_add_feature(
            required_capabilities, CDISASM_ARM_FEATURE_CLRBHB);
    }
#endif
    apply_condition_group(instruction);
    return CDISASM_STATUS_OK;
}

static cdisasm_status decode_a32_branch_register(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    uint32_t kind = word & UINT32_C(0x0ffffff0);
    unsigned rm = word & 15u;

    if (kind == UINT32_C(0x012fff10)) {
        instruction->name_id = CDISASM_ARM_NAME_BX;
        instruction->opcode_groups |= CDISASM_GROUP_JUMP;
        if (rm == 14u) {
            instruction->opcode_groups |= CDISASM_GROUP_RETURN;
        }
        cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V4);
    } else if (kind == UINT32_C(0x012fff30)) {
        instruction->name_id = CDISASM_ARM_NAME_BLX;
        instruction->opcode_groups |= CDISASM_GROUP_CALL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_LINK;
        cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V5);
    } else {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    append_register(
        instruction, a32_reg(rm), 4, CDISASM_OPERAND_ACCESS_READ);
    apply_condition_group(instruction);
    return CDISASM_STATUS_OK;
}

static cdisasm_status decode_a32_bkpt(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    uint32_t immediate;

    if ((word & UINT32_C(0xfff000f0)) != UINT32_C(0xe1200070)) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    immediate = ((word >> 4) & UINT32_C(0xfff0)) | (word & 15u);
    instruction->name_id = CDISASM_ARM_NAME_BKPT;
    instruction->opcode_groups |= CDISASM_GROUP_INTERRUPT;
    append_immediate(instruction, immediate, 2);
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V5);
    return CDISASM_STATUS_OK;
}

static cdisasm_status decode_a32_branch_immediate(
    uint32_t word,
    uint64_t address,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    int link = (word & UINT32_C(0x01000000)) != 0;
    int64_t displacement = sign_extend(
        ((uint64_t)word & UINT64_C(0x00ffffff)) << 2, 26);
    uint64_t target = address + UINT64_C(8) + (uint64_t)displacement;

    instruction->name_id = link ? CDISASM_ARM_NAME_BL : CDISASM_ARM_NAME_B;
    instruction->opcode_groups |= link ? CDISASM_GROUP_CALL
                                        : CDISASM_GROUP_JUMP;
    if (link) {
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_LINK;
    }
    append_relative_target(instruction, target, displacement, 8);
    apply_condition_group(instruction);
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V4);
    return CDISASM_STATUS_OK;
}

static cdisasm_status decode_a32_svc(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    instruction->name_id = CDISASM_ARM_NAME_SVC;
    instruction->opcode_groups |= CDISASM_GROUP_INTERRUPT;
    append_immediate(instruction, word & UINT32_C(0x00ffffff), 3);
    apply_condition_group(instruction);
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V4);
    return CDISASM_STATUS_OK;
}

static cdisasm_status decode_a32_block_transfer(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    int pre = (word & UINT32_C(0x01000000)) != 0;
    int up = (word & UINT32_C(0x00800000)) != 0;
    int user = (word & UINT32_C(0x00400000)) != 0;
    int writeback = (word & UINT32_C(0x00200000)) != 0;
    int load = (word & UINT32_C(0x00100000)) != 0;
    unsigned rn = (word >> 16) & 15u;
    uint16_t register_list = (uint16_t)word;
    int push = register_list != 0 && pre && !up && !user && writeback
        && !load && rn == 13u;
    int pop = register_list != 0 && !pre && up && !user && writeback
        && load && rn == 13u;
    cdisasm_arm_operand *list_operand;

    if (register_list == 0) {
        mark_unpredictable(instruction);
    }
    if (rn == 15u
        || (load && writeback
            && (register_list & (UINT16_C(1) << rn)) != 0)) {
        mark_unpredictable(instruction);
    }
    if (push || pop) {
        instruction->name_id = push ? CDISASM_ARM_NAME_PUSH
                                    : CDISASM_ARM_NAME_POP;
    } else {
        if (!user && !pre && !up) {
            instruction->name_id = load
                ? CDISASM_ARM_NAME_LDMDA : CDISASM_ARM_NAME_STMDA;
        } else if (!user && pre && up) {
            instruction->name_id = load
                ? CDISASM_ARM_NAME_LDMIB : CDISASM_ARM_NAME_STMIB;
        } else if (load && pre && !up && !user) {
            instruction->name_id = CDISASM_ARM_NAME_LDMDB;
        } else {
            instruction->name_id = load
                ? CDISASM_ARM_NAME_LDM : CDISASM_ARM_NAME_STM;
        }
        append_register(
            instruction,
            a32_reg(rn),
            4,
            writeback ? CDISASM_OPERAND_ACCESS_READ_WRITE
                      : CDISASM_OPERAND_ACCESS_READ);
    }
    list_operand = append_operand(instruction);
    if (list_operand != NULL) {
        list_operand->type = CDISASM_ARM_OPERAND_REGISTER_LIST;
        list_operand->size = 4;
        list_operand->register_list = register_list;
        list_operand->access = load ? CDISASM_OPERAND_ACCESS_WRITE
                                    : CDISASM_OPERAND_ACCESS_READ;
    }
    if (writeback) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
    }
    if (pre) {
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX;
    } else {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX;
    }
    instruction->instruction_flags |= up
        ? CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT
        : CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT;
    if (user) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_USER_REGISTERS;
    }
    if (load && (register_list & UINT16_C(0x8000)) != 0) {
        instruction->opcode_groups |= CDISASM_GROUP_JUMP;
        if (pop) {
            instruction->opcode_groups |= CDISASM_GROUP_RETURN;
        }
    }
    apply_condition_group(instruction);
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V4);
    return CDISASM_STATUS_OK;
}

static cdisasm_status decode_a32_single_transfer(
    uint32_t word,
    uint64_t address,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    int pre = (word & UINT32_C(0x01000000)) != 0;
    int up = (word & UINT32_C(0x00800000)) != 0;
    int byte = (word & UINT32_C(0x00400000)) != 0;
    int writeback_bit = (word & UINT32_C(0x00200000)) != 0;
    int load = (word & UINT32_C(0x00100000)) != 0;
    int register_offset = (word & UINT32_C(0x02000000)) != 0;
    unsigned rn = (word >> 16) & 15u;
    unsigned rt = (word >> 12) & 15u;
    uint32_t immediate = register_offset
        ? 0u : word & UINT32_C(0x00000fff);
    int64_t displacement = up ? (int64_t)immediate : -(int64_t)immediate;
    cdisasm_arm_operand *memory;
    uint8_t data_size = byte ? 1u : 4u;

    if (register_offset
        && ((word & UINT32_C(0x00000010)) != 0 || (word & 15u) == 15u)) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }

    if (!pre && writeback_bit) {
        instruction->name_id = load
            ? (byte ? CDISASM_ARM_NAME_LDRBT : CDISASM_ARM_NAME_LDRT)
            : (byte ? CDISASM_ARM_NAME_STRBT : CDISASM_ARM_NAME_STRT);
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_UNPRIVILEGED;
    } else {
        instruction->name_id = load
            ? (byte ? CDISASM_ARM_NAME_LDRB : CDISASM_ARM_NAME_LDR)
            : (byte ? CDISASM_ARM_NAME_STRB : CDISASM_ARM_NAME_STR);
    }
    append_register(
        instruction,
        a32_reg(rt),
        data_size,
        load ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ);
    memory = append_operand(instruction);
    if (memory != NULL) {
        memory->type = CDISASM_OPERAND_MEMORY;
        memory->size = data_size;
        memory->base_reg = a32_reg(rn);
        memory->imm = (uint64_t)displacement;
        memory->access = load ? CDISASM_OPERAND_ACCESS_READ
                              : CDISASM_OPERAND_ACCESS_WRITE;
        if (register_offset) {
            unsigned shift = (word >> 5) & 3u;
            unsigned amount = (word >> 7) & 31u;

            memory->index_reg = a32_reg(word & 15u);
            if (!up) {
                memory->flags |= CDISASM_OPERAND_FLAG_SIGNED;
            }
            if (shift == 3u && amount == 0u) {
                memory->shift_type = CDISASM_ARM_SHIFT_RRX;
                memory->shift_amount = 1u;
            } else if (shift != 0u || amount != 0u) {
                memory->shift_type = (cdisasm_arm_shift_type)(
                    CDISASM_ARM_SHIFT_LSL + shift);
                if (amount == 0u) {
                    amount = 32u;
                }
                memory->shift_amount = (uint8_t)amount;
            }
        } else if (immediate != 0) {
            memory->flags |= CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;
            if (!up) {
                memory->flags |= CDISASM_OPERAND_FLAG_SIGNED;
            }
        }
        if (rn == 15u && pre) {
            memory->address = address + UINT64_C(8)
                + (uint64_t)displacement;
            memory->flags |= CDISASM_OPERAND_FLAG_HAS_ADDRESS
                | CDISASM_OPERAND_FLAG_PC_RELATIVE;
        }
    }
    if (byte) {
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_BYTE;
    }
    if (pre) {
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX;
    } else {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
    }
    if (writeback_bit) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
    }
    if (load && rt == 15u) {
        instruction->opcode_groups |= CDISASM_GROUP_JUMP;
    }
    apply_condition_group(instruction);
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V4);
    return CDISASM_STATUS_OK;
}

static cdisasm_status decode_a32_data_processing(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    static const cdisasm_arm_name_id names[16] = {
        CDISASM_ARM_NAME_AND, CDISASM_ARM_NAME_EOR,
        CDISASM_ARM_NAME_SUB, CDISASM_ARM_NAME_RSB,
        CDISASM_ARM_NAME_ADD, CDISASM_ARM_NAME_ADC,
        CDISASM_ARM_NAME_SBC, CDISASM_ARM_NAME_RSC,
        CDISASM_ARM_NAME_TST, CDISASM_ARM_NAME_TEQ,
        CDISASM_ARM_NAME_CMP, CDISASM_ARM_NAME_CMN,
        CDISASM_ARM_NAME_ORR, CDISASM_ARM_NAME_MOV,
        CDISASM_ARM_NAME_BIC, CDISASM_ARM_NAME_MVN
    };
    int immediate = (word & UINT32_C(0x02000000)) != 0;
    unsigned opcode = (word >> 21) & 15u;
    int set_flags = (word & UINT32_C(0x00100000)) != 0;
    unsigned rn = (word >> 16) & 15u;
    unsigned rd = (word >> 12) & 15u;
    int is_test = opcode >= 8u && opcode <= 11u;
    int is_move = opcode == 13u || opcode == 15u;
    cdisasm_arm_operand *source;

#if USE_EXTRA_OPCODES
    if ((word & UINT32_C(0x0fef0090)) == UINT32_C(0x01a00010)) {
        static const cdisasm_arm_name_id shift_names[2][4] = {
            {CDISASM_ARM_NAME_LSL, CDISASM_ARM_NAME_LSR,
                CDISASM_ARM_NAME_ASR, CDISASM_ARM_NAME_ROR},
            {CDISASM_ARM_NAME_LSLS, CDISASM_ARM_NAME_LSRS,
                CDISASM_ARM_NAME_ASRS, CDISASM_ARM_NAME_RORS}
        };
        unsigned rm = word & 15u;
        unsigned rs = (word >> 8) & 15u;
        unsigned shift = (word >> 5) & 3u;

        if (rd == 15u || rm == 15u || rs == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = shift_names[set_flags != 0][shift];
        instruction->form_id = set_flags
            ? UINT16_C(210) : UINT16_C(211);
        if (set_flags) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
        }
        append_register(instruction, a32_reg(rd), 4,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_register(instruction, a32_reg(rm), 4,
            CDISASM_OPERAND_ACCESS_READ);
        append_register(instruction, a32_reg(rs), 4,
            CDISASM_OPERAND_ACCESS_READ);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V4);
        return CDISASM_STATUS_OK;
    }
#endif

    if (is_test && !set_flags) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if ((is_move && rn != 0u) || (is_test && rd != 0u)) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
    if (!immediate && (word & UINT32_C(0x00000010)) != 0) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        if ((word & UINT32_C(0x00000080)) != 0) {
            return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        }
#endif
    }

    instruction->name_id = names[opcode];
    if (set_flags && !is_test) {
        static const cdisasm_arm_name_id flag_names[8] = {
            CDISASM_ARM_NAME_ANDS, CDISASM_ARM_NAME_EORS,
            CDISASM_ARM_NAME_SUBS, CDISASM_ARM_NAME_RSBS,
            CDISASM_ARM_NAME_ADDS, CDISASM_ARM_NAME_ADCS,
            CDISASM_ARM_NAME_SBCS, CDISASM_ARM_NAME_RSCS
        };
        if (opcode < 8u) {
            instruction->name_id = flag_names[opcode];
        } else if (opcode == 12u) {
            instruction->name_id = CDISASM_ARM_NAME_ORRS;
        } else if (opcode == 13u) {
            instruction->name_id = CDISASM_ARM_NAME_MOVS;
        } else if (opcode == 14u) {
            instruction->name_id = CDISASM_ARM_NAME_BICS;
        } else if (opcode == 15u) {
            instruction->name_id = CDISASM_ARM_NAME_MVNS;
        }
    }
    if (set_flags || is_test) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
    }
    if (!is_test) {
        append_register(
            instruction, a32_reg(rd), 4, CDISASM_OPERAND_ACCESS_WRITE);
    }
    if (!is_move) {
        append_register(
            instruction, a32_reg(rn), 4, CDISASM_OPERAND_ACCESS_READ);
    }
    if (immediate) {
        unsigned rotate = ((word >> 8) & 15u) * 2u;
        uint32_t value = rotate_right32(word & 255u, rotate);
        source = append_immediate(instruction, value, 4);
        if (source != NULL && rotate != 0) {
            source->shift_type = CDISASM_ARM_SHIFT_ROR;
            source->shift_amount = (uint8_t)rotate;
        }
    } else {
        unsigned rm = word & 15u;
        unsigned shift = (word >> 5) & 3u;
        unsigned amount = (word >> 7) & 31u;

        if ((word & UINT32_C(0x00000010)) != 0) {
            unsigned rs = (word >> 8) & 15u;

            if (rm == 15u || rs == 15u
                || (!is_test && rd == 15u)
                || (!is_move && rn == 15u)) {
                return CDISASM_STATUS_INVALID_INSTRUCTION;
            }
            append_register(instruction, a32_reg(rm), 4,
                CDISASM_OPERAND_ACCESS_READ);
            append_register(instruction, a32_reg(rs), 4,
                CDISASM_OPERAND_ACCESS_READ);
            apply_condition_group(instruction);
            cdisasm_arm_requirements_set_legacy(
                required_capabilities, CDISASM_ARM_CAP_V4);
            return CDISASM_STATUS_OK;
        }
        source = append_register(
            instruction, a32_reg(rm), 4, CDISASM_OPERAND_ACCESS_READ);
        if (source != NULL) {
            if (shift == 0u && amount == 0u) {
                source->shift_type = CDISASM_ARM_SHIFT_NONE;
            } else if (shift == 3u && amount == 0u) {
                source->shift_type = CDISASM_ARM_SHIFT_RRX;
                source->shift_amount = 1;
            } else {
                source->shift_type = (cdisasm_arm_shift_type)(
                    CDISASM_ARM_SHIFT_LSL + shift);
                if (amount == 0u) {
                    amount = 32u;
                }
                source->shift_amount = (uint8_t)amount;
            }
        }
    }
    if (!is_test && rd == 15u) {
        instruction->opcode_groups |= CDISASM_GROUP_JUMP;
        if (opcode == 13u && !immediate && (word & 15u) == 14u) {
            instruction->opcode_groups |= CDISASM_GROUP_RETURN;
        }
    }
    apply_condition_group(instruction);
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V4);
    return CDISASM_STATUS_OK;
}

static cdisasm_status decode_a32_extra(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities,
    int *recognized)
{
    cdisasm_arm_condition condition = (cdisasm_arm_condition)(word >> 28);

#if !USE_EXTRA_OPCODES
    (void)instruction;
    (void)required_capabilities;
#endif
    *recognized = 0;
    if ((word & UINT32_C(0xff70f010)) == UINT32_C(0xf710f000)) {
        unsigned rn = (word >> 16) & 15u;
        unsigned rm = word & 15u;

        *recognized = 1;
        if (rn == 15u || rm == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned add = (word >> 23) & 1u;
        unsigned shift = (word >> 5) & 3u;
        unsigned amount = (word >> 7) & 31u;
        int rrx = shift == 3u && amount == 0u;
        cdisasm_arm_operand *memory;

        instruction->name_id = CDISASM_ARM_NAME_PLDW;
        instruction->form_id = rrx ? UINT16_C(967) : UINT16_C(966);
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        memory = append_operand(instruction);
        if (memory != NULL) {
            memory->type = CDISASM_OPERAND_MEMORY;
            memory->base_reg = a32_reg(rn);
            memory->index_reg = a32_reg(rm);
            memory->access = CDISASM_OPERAND_ACCESS_READ;
            if (add == 0u) {
                memory->flags = CDISASM_OPERAND_FLAG_SIGNED;
            }
            if (rrx) {
                memory->shift_type = CDISASM_ARM_SHIFT_RRX;
                memory->shift_amount = 1u;
            } else if (shift != 0u || amount != 0u) {
                memory->shift_type = (cdisasm_arm_shift_type)(
                    CDISASM_ARM_SHIFT_LSL + shift);
                if (amount == 0u) {
                    amount = 32u;
                }
                memory->shift_amount = (uint8_t)amount;
            }
        }
        cdisasm_arm_requirements_set_legacy(required_capabilities,
            CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_MP);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0xfe70f010)) == UINT32_C(0xf650f000)) {
        unsigned rn = (word >> 16) & 15u;
        unsigned rm = word & 15u;

        *recognized = 1;
        if (rn == 15u || rm == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned add = (word >> 23) & 1u;
        unsigned shift = (word >> 5) & 3u;
        unsigned amount = (word >> 7) & 31u;
        int instruction_prefetch = (word & UINT32_C(0x01000000)) == 0u;
        int rrx = shift == 3u && amount == 0u;
        cdisasm_arm_operand *memory;

        instruction->name_id = instruction_prefetch
            ? CDISASM_ARM_NAME_PLI : CDISASM_ARM_NAME_PLD;
        instruction->form_id = instruction_prefetch
            ? (rrx ? UINT16_C(962) : UINT16_C(963))
            : (rrx ? UINT16_C(965) : UINT16_C(964));
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        memory = append_operand(instruction);
        if (memory != NULL) {
            memory->type = CDISASM_OPERAND_MEMORY;
            memory->base_reg = a32_reg(rn);
            memory->index_reg = a32_reg(rm);
            memory->access = CDISASM_OPERAND_ACCESS_READ;
            if (add == 0u) {
                memory->flags = CDISASM_OPERAND_FLAG_SIGNED;
            }
            if (rrx) {
                memory->shift_type = CDISASM_ARM_SHIFT_RRX;
                memory->shift_amount = 1u;
            } else if (shift != 0u || amount != 0u) {
                memory->shift_type = (cdisasm_arm_shift_type)(
                    CDISASM_ARM_SHIFT_LSL + shift);
                if (amount == 0u) {
                    amount = 32u;
                }
                memory->shift_amount = (uint8_t)amount;
            }
        }
        cdisasm_arm_requirements_set_legacy(required_capabilities,
            instruction_prefetch ? CDISASM_ARM_CAP_V7
                                 : CDISASM_ARM_CAP_V5);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0xff70f000)) == UINT32_C(0xf550f000)) {
        *recognized = 1;
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned add = (word >> 23) & 1u;
        unsigned rn = (word >> 16) & 15u;
        uint32_t offset = word & UINT32_C(0x0fff);
        cdisasm_arm_operand *memory;

        instruction->name_id = CDISASM_ARM_NAME_PLD;
        instruction->form_id = rn == 15u ? UINT16_C(959) : UINT16_C(960);
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        memory = append_operand(instruction);
        if (memory != NULL) {
            memory->type = CDISASM_OPERAND_MEMORY;
            memory->base_reg = a32_reg(rn);
            memory->access = CDISASM_OPERAND_ACCESS_READ;
            if (offset != 0u) {
                memory->imm = add != 0u
                    ? offset : (uint64_t)(-(int64_t)offset);
                memory->flags |= CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;
                if (add == 0u) {
                    memory->flags |= CDISASM_OPERAND_FLAG_SIGNED;
                }
            }
            if (rn == 15u) {
                uint64_t base = instruction->address + UINT64_C(8);

                memory->address = add != 0u
                    ? base + offset : base - offset;
                memory->flags |= CDISASM_OPERAND_FLAG_PC_RELATIVE
                    | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
            }
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V5);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0xff70f000)) == UINT32_C(0xf510f000)) {
        unsigned rn = (word >> 16) & 15u;

        *recognized = 1;
        if (rn == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned add = (word >> 23) & 1u;
        uint32_t offset = word & UINT32_C(0x0fff);
        cdisasm_arm_operand *memory;

        instruction->name_id = CDISASM_ARM_NAME_PLDW;
        instruction->form_id = UINT16_C(961);
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        memory = append_operand(instruction);
        if (memory != NULL) {
            memory->type = CDISASM_OPERAND_MEMORY;
            memory->base_reg = a32_reg(rn);
            memory->access = CDISASM_OPERAND_ACCESS_READ;
            if (offset != 0u) {
                memory->imm = add != 0u
                    ? offset : (uint64_t)(-(int64_t)offset);
                memory->flags |= CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;
                if (add == 0u) {
                    memory->flags |= CDISASM_OPERAND_FLAG_SIGNED;
                }
            }
        }
        cdisasm_arm_requirements_set_legacy(required_capabilities,
            CDISASM_ARM_CAP_V7 | CDISASM_ARM_CAP_MP);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0xff70f000)) == UINT32_C(0xf450f000)) {
        *recognized = 1;
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        unsigned add = (word >> 23) & 1u;
        unsigned rn = (word >> 16) & 15u;
        uint32_t offset = word & UINT32_C(0x0fff);
        cdisasm_arm_operand *memory;

        instruction->name_id = CDISASM_ARM_NAME_PLI;
        instruction->form_id = UINT16_C(958);
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        memory = append_operand(instruction);
        if (memory != NULL) {
            memory->type = CDISASM_OPERAND_MEMORY;
            memory->base_reg = a32_reg(rn);
            memory->access = CDISASM_OPERAND_ACCESS_READ;
            if (offset != 0u) {
                memory->imm = add != 0u
                    ? offset : (uint64_t)(-(int64_t)offset);
                memory->flags |= CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;
                if (add == 0u) {
                    memory->flags |= CDISASM_OPERAND_FLAG_SIGNED;
                }
            }
            if (rn == 15u) {
                uint64_t base = instruction->address + UINT64_C(8);

                memory->address = add != 0u
                    ? base + offset : base - offset;
                memory->flags |= CDISASM_OPERAND_FLAG_PC_RELATIVE
                    | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
            }
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0xfffffe20)) == UINT32_C(0xf1080000)
        || (word & UINT32_C(0xfffffe20)) == UINT32_C(0xf10a0000)
        || (word & UINT32_C(0xfffffe20)) == UINT32_C(0xf10c0000)
        || (word & UINT32_C(0xfffffe20)) == UINT32_C(0xf10e0000)) {
        unsigned disable = (word >> 18) & 1u;
        unsigned has_mode = (word >> 17) & 1u;
        unsigned interrupt_mask = (word >> 6) & 7u;
        unsigned mode = word & 31u;
        int valid_mode = mode == 16u || mode == 17u || mode == 18u
            || mode == 19u || mode == 22u || mode == 23u
            || mode == 26u || mode == 27u || mode == 31u;

        *recognized = 1;
        if (interrupt_mask == 0u
            || (has_mode ? !valid_mode : mode != 0u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)disable;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = disable != 0u
            ? CDISASM_ARM_NAME_CPSID : CDISASM_ARM_NAME_CPSIE;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->opcode_groups |= CDISASM_GROUP_PRIVILEGED;
        append_immediate(instruction, interrupt_mask, 1u);
        if (has_mode) {
            append_immediate(instruction, mode, 1u);
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0x0ff0fff0)) == UINT32_C(0x0180fc90)
        || (word & UINT32_C(0x0ff0fff0)) == UINT32_C(0x01c0fc90)
        || (word & UINT32_C(0x0ff0fff0)) == UINT32_C(0x01e0fc90)
        || (word & UINT32_C(0x0ff00fff)) == UINT32_C(0x01900c9f)
        || (word & UINT32_C(0x0ff00fff)) == UINT32_C(0x01d00c9f)
        || (word & UINT32_C(0x0ff00fff)) == UINT32_C(0x01f00c9f)) {
        int load = (word & UINT32_C(0x00100000)) != 0;
        unsigned rn = (word >> 16) & 15u;
        unsigned rt = load ? (word >> 12) & 15u : word & 15u;
        unsigned size_selector = (word >> 21) & 3u;
        uint8_t size = size_selector == 2u ? 1u
            : size_selector == 3u ? 2u : 4u;

        *recognized = 1;
        if (condition == CDISASM_ARM_CONDITION_NV
            || rn == 15u || rt == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)size;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        cdisasm_arm_operand *memory;

        instruction->name_id = load
            ? (size == 1u ? CDISASM_ARM_NAME_LDAB
                          : size == 2u ? CDISASM_ARM_NAME_LDAH
                                       : CDISASM_ARM_NAME_LDA)
            : (size == 1u ? CDISASM_ARM_NAME_STLB
                          : size == 2u ? CDISASM_ARM_NAME_STLH
                                       : CDISASM_ARM_NAME_STL);
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
            | (load ? CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
                    : CDISASM_ARM_INSTRUCTION_FLAG_RELEASE);
        append_register(
            instruction, a32_reg(rt), size,
            load ? CDISASM_OPERAND_ACCESS_WRITE
                 : CDISASM_OPERAND_ACCESS_READ);
        memory = append_operand(instruction);
        if (memory != NULL) {
            memory->type = CDISASM_OPERAND_MEMORY;
            memory->size = size;
            memory->base_reg = a32_reg(rn);
            memory->access = load ? CDISASM_OPERAND_ACCESS_READ
                                  : CDISASM_OPERAND_ACCESS_WRITE;
        }
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x01800e90)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x01800f90)
        || (word & UINT32_C(0x0ff00fff)) == UINT32_C(0x01900e9f)
        || (word & UINT32_C(0x0ff00fff)) == UINT32_C(0x01900f9f)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x01a00e90)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x01a00f90)
        || (word & UINT32_C(0x0ff00fff)) == UINT32_C(0x01b00e9f)
        || (word & UINT32_C(0x0ff00fff)) == UINT32_C(0x01b00f9f)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x01c00e90)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x01c00f90)
        || (word & UINT32_C(0x0ff00fff)) == UINT32_C(0x01d00e9f)
        || (word & UINT32_C(0x0ff00fff)) == UINT32_C(0x01d00f9f)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x01e00e90)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x01e00f90)
        || (word & UINT32_C(0x0ff00fff)) == UINT32_C(0x01f00e9f)
        || (word & UINT32_C(0x0ff00fff)) == UINT32_C(0x01f00f9f)) {
        unsigned class_selector = (word >> 20) & 15u;
        unsigned ordering_selector = (word >> 8) & 15u;
        int load = (class_selector & 1u) != 0u;
        int pair = class_selector == 10u || class_selector == 11u;
        int ordered = ordering_selector == 14u;
        unsigned rn = (word >> 16) & 15u;
        unsigned status = (word >> 12) & 15u;
        unsigned rt = load ? status : word & 15u;
        unsigned rt2 = rt + 1u;
        uint8_t size = class_selector >= 14u ? 2u
            : class_selector >= 12u ? 1u : 4u;

        *recognized = 1;
        if (condition == CDISASM_ARM_CONDITION_NV
            || rn == 15u || rt == 15u
            || (pair && (rt >= 14u || (rt & 1u) != 0u))
            || (!load && (status == 15u || status == rn
                || status == rt || (pair && status == rt2)))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)size;
        (void)ordered;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        cdisasm_arm_operand *memory;

        if (load) {
            instruction->name_id = pair
                ? (ordered ? CDISASM_ARM_NAME_LDAEXD
                           : CDISASM_ARM_NAME_LDREXD)
                : size == 1u
                    ? (ordered ? CDISASM_ARM_NAME_LDAEXB
                               : CDISASM_ARM_NAME_LDREXB)
                    : size == 2u
                        ? (ordered ? CDISASM_ARM_NAME_LDAEXH
                                   : CDISASM_ARM_NAME_LDREXH)
                        : (ordered ? CDISASM_ARM_NAME_LDAEX
                                   : CDISASM_ARM_NAME_LDREX);
        } else {
            instruction->name_id = pair
                ? (ordered ? CDISASM_ARM_NAME_STLEXD
                           : CDISASM_ARM_NAME_STREXD)
                : size == 1u
                    ? (ordered ? CDISASM_ARM_NAME_STLEXB
                               : CDISASM_ARM_NAME_STREXB)
                    : size == 2u
                        ? (ordered ? CDISASM_ARM_NAME_STLEXH
                                   : CDISASM_ARM_NAME_STREXH)
                        : (ordered ? CDISASM_ARM_NAME_STLEX
                                   : CDISASM_ARM_NAME_STREX);
            append_register(
                instruction, a32_reg(status), 4u,
                CDISASM_OPERAND_ACCESS_WRITE);
        }
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC
            | CDISASM_ARM_INSTRUCTION_FLAG_EXCLUSIVE
            | (ordered
                ? (load ? CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
                        : CDISASM_ARM_INSTRUCTION_FLAG_RELEASE)
                : 0u);
        append_register(
            instruction, a32_reg(rt), size,
            load ? CDISASM_OPERAND_ACCESS_WRITE
                 : CDISASM_OPERAND_ACCESS_READ);
        if (pair) {
            append_register(
                instruction, a32_reg(rt2), 4u,
                load ? CDISASM_OPERAND_ACCESS_WRITE
                     : CDISASM_OPERAND_ACCESS_READ);
        }
        memory = append_operand(instruction);
        if (memory != NULL) {
            memory->type = CDISASM_OPERAND_MEMORY;
            memory->size = pair ? 8u : size;
            memory->base_reg = a32_reg(rn);
            memory->access = load ? CDISASM_OPERAND_ACCESS_READ
                                  : CDISASM_OPERAND_ACCESS_WRITE;
        }
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities,
            ordered ? CDISASM_ARM_CAP_V8 : CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if (word == UINT32_C(0xf57ff070)) {
        *recognized = 1;
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_SB;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8);
        return CDISASM_STATUS_OK;
#endif
    }
    if (word == UINT32_C(0xe160006e)) {
        *recognized = 1;
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_ERET;
        instruction->opcode_groups |= CDISASM_GROUP_RETURN
            | CDISASM_GROUP_INTERRUPT_RETURN | CDISASM_GROUP_PRIVILEGED;
        cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V7);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0xfff000f0)) == UINT32_C(0xe1000070)) {
        uint32_t immediate = ((word >> 4) & UINT32_C(0xfff0))
            | (word & UINT32_C(0x0f));

        *recognized = 1;
#if !USE_EXTRA_OPCODES
        (void)immediate;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_HLT;
        instruction->opcode_groups |= CDISASM_GROUP_INTERRUPT;
        append_immediate(instruction, immediate, 2);
        cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0x0ff003f0)) == UINT32_C(0x06800070)
        || (word & UINT32_C(0x0ff003f0)) == UINT32_C(0x06a00070)
        || (word & UINT32_C(0x0ff003f0)) == UINT32_C(0x06b00070)
        || (word & UINT32_C(0x0ff003f0)) == UINT32_C(0x06c00070)
        || (word & UINT32_C(0x0ff003f0)) == UINT32_C(0x06e00070)
        || (word & UINT32_C(0x0ff003f0)) == UINT32_C(0x06f00070)) {
        uint32_t selector = word & UINT32_C(0x0ff003f0);
        unsigned rn = (word >> 16) & 15u;
        unsigned rd = (word >> 12) & 15u;
        unsigned rotation = ((word >> 10) & 3u) * 8u;
        unsigned rm = word & 15u;
        int extend_alias = rn == 15u;

        *recognized = 1;
        if (condition == CDISASM_ARM_CONDITION_NV
            || rd == 15u || rm == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)selector;
        (void)rotation;
        (void)extend_alias;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = selector == UINT32_C(0x06800070)
            ? (extend_alias ? CDISASM_ARM_NAME_SXTB16
                            : CDISASM_ARM_NAME_SXTAB16)
            : selector == UINT32_C(0x06a00070)
                ? (extend_alias ? CDISASM_ARM_NAME_SXTB
                                : CDISASM_ARM_NAME_SXTAB)
                : selector == UINT32_C(0x06b00070)
                    ? (extend_alias ? CDISASM_ARM_NAME_SXTH
                                    : CDISASM_ARM_NAME_SXTAH)
                    : selector == UINT32_C(0x06c00070)
                        ? (extend_alias ? CDISASM_ARM_NAME_UXTB16
                                        : CDISASM_ARM_NAME_UXTAB16)
                        : selector == UINT32_C(0x06e00070)
                            ? (extend_alias ? CDISASM_ARM_NAME_UXTB
                                            : CDISASM_ARM_NAME_UXTAB)
                            : (extend_alias ? CDISASM_ARM_NAME_UXTH
                                            : CDISASM_ARM_NAME_UXTAH);
        append_register(instruction, a32_reg(rd), 4u,
            CDISASM_OPERAND_ACCESS_WRITE);
        if (!extend_alias) {
            append_register(instruction, a32_reg(rn), 4u,
                CDISASM_OPERAND_ACCESS_READ);
        }
        {
            cdisasm_arm_operand *rotated = append_register(
                instruction, a32_reg(rm), 4u,
                CDISASM_OPERAND_ACCESS_READ);
            if (rotated != NULL && rotation != 0u) {
                rotated->shift_type = CDISASM_ARM_SHIFT_ROR;
                rotated->shift_amount = (uint8_t)rotation;
            }
        }
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0x0ff000f0)) == UINT32_C(0x01200080)
        || (word & UINT32_C(0x0ff000f0)) == UINT32_C(0x012000c0)
        || (word & UINT32_C(0x0ff0f0f0)) == UINT32_C(0x012000a0)
        || (word & UINT32_C(0x0ff0f0f0)) == UINT32_C(0x012000e0)) {
        uint32_t selector = word & UINT32_C(0x0ff000f0);
        unsigned rd = (word >> 16) & 15u;
        unsigned ra = (word >> 12) & 15u;
        unsigned rs = (word >> 8) & 15u;
        unsigned rm = word & 15u;
        int multiply = selector == UINT32_C(0x012000a0)
            || selector == UINT32_C(0x012000e0);

        *recognized = 1;
        if (condition == CDISASM_ARM_CONDITION_NV || rd == 15u
            || rs == 15u || rm == 15u || (!multiply && ra == 15u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)selector;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = selector == UINT32_C(0x01200080)
            ? CDISASM_ARM_NAME_SMLAWB
            : selector == UINT32_C(0x012000c0)
                ? CDISASM_ARM_NAME_SMLAWT
                : selector == UINT32_C(0x012000a0)
                    ? CDISASM_ARM_NAME_SMULWB : CDISASM_ARM_NAME_SMULWT;
        append_register(instruction, a32_reg(rd), 4u,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_register(instruction, a32_reg(rm), 4u,
            CDISASM_OPERAND_ACCESS_READ);
        append_register(instruction, a32_reg(rs), 4u,
            CDISASM_OPERAND_ACCESS_READ);
        if (!multiply) {
            append_register(instruction, a32_reg(ra), 4u,
                CDISASM_OPERAND_ACCESS_READ);
        }
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V5);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0x0ff000f0)) == UINT32_C(0x01400080)
        || (word & UINT32_C(0x0ff000f0)) == UINT32_C(0x014000a0)
        || (word & UINT32_C(0x0ff000f0)) == UINT32_C(0x014000c0)
        || (word & UINT32_C(0x0ff000f0)) == UINT32_C(0x014000e0)) {
        uint32_t selector = word & UINT32_C(0x0ff000f0);
        unsigned rd_hi = (word >> 16) & 15u;
        unsigned rd_lo = (word >> 12) & 15u;
        unsigned rs = (word >> 8) & 15u;
        unsigned rm = word & 15u;

        *recognized = 1;
        if (condition == CDISASM_ARM_CONDITION_NV || rd_lo == rd_hi
            || rd_lo == 15u || rd_hi == 15u || rs == 15u || rm == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)selector;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = selector == UINT32_C(0x01400080)
            ? CDISASM_ARM_NAME_SMLALBB
            : selector == UINT32_C(0x014000c0)
                ? CDISASM_ARM_NAME_SMLALBT
                : selector == UINT32_C(0x014000a0)
                    ? CDISASM_ARM_NAME_SMLALTB
                    : CDISASM_ARM_NAME_SMLALTT;
        append_register(instruction, a32_reg(rd_lo), 4u,
            CDISASM_OPERAND_ACCESS_READ_WRITE);
        append_register(instruction, a32_reg(rd_hi), 4u,
            CDISASM_OPERAND_ACCESS_READ_WRITE);
        append_register(instruction, a32_reg(rm), 4u,
            CDISASM_OPERAND_ACCESS_READ);
        append_register(instruction, a32_reg(rs), 4u,
            CDISASM_OPERAND_ACCESS_READ);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V5);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0x0ff000f0)) == UINT32_C(0x01000080)
        || (word & UINT32_C(0x0ff000f0)) == UINT32_C(0x010000a0)
        || (word & UINT32_C(0x0ff000f0)) == UINT32_C(0x010000c0)
        || (word & UINT32_C(0x0ff000f0)) == UINT32_C(0x010000e0)
        || (word & UINT32_C(0x0ff0f0f0)) == UINT32_C(0x01600080)
        || (word & UINT32_C(0x0ff0f0f0)) == UINT32_C(0x016000a0)
        || (word & UINT32_C(0x0ff0f0f0)) == UINT32_C(0x016000c0)
        || (word & UINT32_C(0x0ff0f0f0)) == UINT32_C(0x016000e0)) {
        uint32_t selector = word & UINT32_C(0x0ff000f0);
        unsigned rd = (word >> 16) & 15u;
        unsigned ra = (word >> 12) & 15u;
        unsigned rs = (word >> 8) & 15u;
        unsigned rm = word & 15u;
        int multiply = (selector & UINT32_C(0x00600000))
            == UINT32_C(0x00600000);

        *recognized = 1;
        if (condition == CDISASM_ARM_CONDITION_NV || rd == 15u
            || rs == 15u || rm == 15u || (!multiply && ra == 15u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)selector;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        if (multiply) {
            instruction->name_id = selector == UINT32_C(0x01600080)
                ? CDISASM_ARM_NAME_SMULBB
                : selector == UINT32_C(0x016000a0)
                    ? CDISASM_ARM_NAME_SMULTB
                    : selector == UINT32_C(0x016000c0)
                        ? CDISASM_ARM_NAME_SMULBT
                        : CDISASM_ARM_NAME_SMULTT;
        } else {
            instruction->name_id = selector == UINT32_C(0x01000080)
                ? CDISASM_ARM_NAME_SMLABB
                : selector == UINT32_C(0x010000a0)
                    ? CDISASM_ARM_NAME_SMLATB
                    : selector == UINT32_C(0x010000c0)
                        ? CDISASM_ARM_NAME_SMLABT
                        : CDISASM_ARM_NAME_SMLATT;
        }
        append_register(instruction, a32_reg(rd), 4u,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_register(instruction, a32_reg(rm), 4u,
            CDISASM_OPERAND_ACCESS_READ);
        append_register(instruction, a32_reg(rs), 4u,
            CDISASM_OPERAND_ACCESS_READ);
        if (!multiply) {
            append_register(instruction, a32_reg(ra), 4u,
                CDISASM_OPERAND_ACCESS_READ);
        }
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V5);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0x0ff000f0)) == UINT32_C(0x00400090)) {
        unsigned rd_hi = (word >> 16) & 15u;
        unsigned rd_lo = (word >> 12) & 15u;
        unsigned rs = (word >> 8) & 15u;
        unsigned rm = word & 15u;

        *recognized = 1;
        if (condition == CDISASM_ARM_CONDITION_NV || rd_lo == rd_hi
            || rd_lo == 15u || rd_hi == 15u || rs == 15u || rm == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_UMAAL;
        append_register(instruction, a32_reg(rd_lo), 4u,
            CDISASM_OPERAND_ACCESS_READ_WRITE);
        append_register(instruction, a32_reg(rd_hi), 4u,
            CDISASM_OPERAND_ACCESS_READ_WRITE);
        append_register(instruction, a32_reg(rm), 4u,
            CDISASM_OPERAND_ACCESS_READ);
        append_register(instruction, a32_reg(rs), 4u,
            CDISASM_OPERAND_ACCESS_READ);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0x0ff000f0)) == UINT32_C(0x07800010)) {
        unsigned rd = (word >> 16) & 15u;
        unsigned ra = (word >> 12) & 15u;
        unsigned rm = (word >> 8) & 15u;
        unsigned rn = word & 15u;

        *recognized = 1;
        if (condition == CDISASM_ARM_CONDITION_NV
            || rd == 15u || rn == 15u || rm == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)ra;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = ra == 15u
            ? CDISASM_ARM_NAME_USAD8 : CDISASM_ARM_NAME_USADA8;
        append_register(
            instruction, a32_reg(rd), 4u, CDISASM_OPERAND_ACCESS_WRITE);
        append_register(
            instruction, a32_reg(rn), 4u, CDISASM_OPERAND_ACCESS_READ);
        append_register(
            instruction, a32_reg(rm), 4u, CDISASM_OPERAND_ACCESS_READ);
        if (ra != 15u) {
            append_register(
                instruction, a32_reg(ra), 4u,
                CDISASM_OPERAND_ACCESS_READ);
        }
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0x0ff0f0f0)) == UINT32_C(0x0700f010)
        || (word & UINT32_C(0x0ff0f0f0)) == UINT32_C(0x0700f030)
        || (word & UINT32_C(0x0ff0f0f0)) == UINT32_C(0x0700f050)
        || (word & UINT32_C(0x0ff0f0f0)) == UINT32_C(0x0700f070)
        || (word & UINT32_C(0x0ff0f0f0)) == UINT32_C(0x0750f010)
        || (word & UINT32_C(0x0ff0f0f0)) == UINT32_C(0x0750f030)) {
        uint32_t selector = word & UINT32_C(0x0ff0f0f0);
        unsigned rd = (word >> 16) & 15u;
        unsigned rm = (word >> 8) & 15u;
        unsigned rn = word & 15u;

        *recognized = 1;
        if (condition == CDISASM_ARM_CONDITION_NV
            || rd == 15u || rn == 15u || rm == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)selector;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = selector == UINT32_C(0x0700f010)
            ? CDISASM_ARM_NAME_SMUAD
            : selector == UINT32_C(0x0700f030)
                ? CDISASM_ARM_NAME_SMUADX
                : selector == UINT32_C(0x0700f050)
                    ? CDISASM_ARM_NAME_SMUSD
                    : selector == UINT32_C(0x0700f070)
                        ? CDISASM_ARM_NAME_SMUSDX
                        : selector == UINT32_C(0x0750f010)
                            ? CDISASM_ARM_NAME_SMMUL
                            : CDISASM_ARM_NAME_SMMULR;
        append_register(
            instruction, a32_reg(rd), 4u, CDISASM_OPERAND_ACCESS_WRITE);
        append_register(
            instruction, a32_reg(rn), 4u, CDISASM_OPERAND_ACCESS_READ);
        append_register(
            instruction, a32_reg(rm), 4u, CDISASM_OPERAND_ACCESS_READ);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0x0ff000f0)) == UINT32_C(0x07500010)
        || (word & UINT32_C(0x0ff000f0)) == UINT32_C(0x07500030)
        || (word & UINT32_C(0x0ff000f0)) == UINT32_C(0x075000d0)
        || (word & UINT32_C(0x0ff000f0)) == UINT32_C(0x075000f0)) {
        uint32_t selector = word & UINT32_C(0x0ff000f0);
        unsigned rd = (word >> 16) & 15u;
        unsigned ra = (word >> 12) & 15u;
        unsigned rm = (word >> 8) & 15u;
        unsigned rn = word & 15u;

        *recognized = 1;
        if (condition == CDISASM_ARM_CONDITION_NV || rd == 15u
            || ra == 15u || rm == 15u || rn == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)selector;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = selector == UINT32_C(0x07500010)
            ? CDISASM_ARM_NAME_SMMLA
            : selector == UINT32_C(0x07500030)
                ? CDISASM_ARM_NAME_SMMLAR
                : selector == UINT32_C(0x075000d0)
                    ? CDISASM_ARM_NAME_SMMLS
                    : CDISASM_ARM_NAME_SMMLSR;
        append_register(
            instruction, a32_reg(rd), 4u, CDISASM_OPERAND_ACCESS_WRITE);
        append_register(
            instruction, a32_reg(rn), 4u, CDISASM_OPERAND_ACCESS_READ);
        append_register(
            instruction, a32_reg(rm), 4u, CDISASM_OPERAND_ACCESS_READ);
        append_register(
            instruction, a32_reg(ra), 4u, CDISASM_OPERAND_ACCESS_READ);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0x0ff000f0)) == UINT32_C(0x07000010)
        || (word & UINT32_C(0x0ff000f0)) == UINT32_C(0x07000030)
        || (word & UINT32_C(0x0ff000f0)) == UINT32_C(0x07000050)
        || (word & UINT32_C(0x0ff000f0)) == UINT32_C(0x07000070)) {
        uint32_t selector = word & UINT32_C(0x0ff000f0);
        unsigned rd = (word >> 16) & 15u;
        unsigned ra = (word >> 12) & 15u;
        unsigned rm = (word >> 8) & 15u;
        unsigned rn = word & 15u;

        *recognized = 1;
        if (condition == CDISASM_ARM_CONDITION_NV || ra == 15u
            || rd == 15u || rn == 15u || rm == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)selector;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = selector == UINT32_C(0x07000010)
            ? CDISASM_ARM_NAME_SMLAD
            : selector == UINT32_C(0x07000030)
                ? CDISASM_ARM_NAME_SMLADX
                : selector == UINT32_C(0x07000050)
                    ? CDISASM_ARM_NAME_SMLSD : CDISASM_ARM_NAME_SMLSDX;
        append_register(instruction, a32_reg(rd), 4u,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_register(instruction, a32_reg(rn), 4u,
            CDISASM_OPERAND_ACCESS_READ);
        append_register(instruction, a32_reg(rm), 4u,
            CDISASM_OPERAND_ACCESS_READ);
        append_register(instruction, a32_reg(ra), 4u,
            CDISASM_OPERAND_ACCESS_READ);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0x0ff000f0)) == UINT32_C(0x07400010)
        || (word & UINT32_C(0x0ff000f0)) == UINT32_C(0x07400030)
        || (word & UINT32_C(0x0ff000f0)) == UINT32_C(0x07400050)
        || (word & UINT32_C(0x0ff000f0)) == UINT32_C(0x07400070)) {
        uint32_t selector = word & UINT32_C(0x0ff000f0);
        unsigned rd_hi = (word >> 16) & 15u;
        unsigned rd_lo = (word >> 12) & 15u;
        unsigned rm = (word >> 8) & 15u;
        unsigned rn = word & 15u;

        *recognized = 1;
        if (condition == CDISASM_ARM_CONDITION_NV || rd_lo == rd_hi
            || rd_lo == 15u || rd_hi == 15u || rn == 15u || rm == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)selector;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = selector == UINT32_C(0x07400010)
            ? CDISASM_ARM_NAME_SMLALD
            : selector == UINT32_C(0x07400030)
                ? CDISASM_ARM_NAME_SMLALDX
                : selector == UINT32_C(0x07400050)
                    ? CDISASM_ARM_NAME_SMLSLD : CDISASM_ARM_NAME_SMLSLDX;
        append_register(instruction, a32_reg(rd_lo), 4u,
            CDISASM_OPERAND_ACCESS_READ_WRITE);
        append_register(instruction, a32_reg(rd_hi), 4u,
            CDISASM_OPERAND_ACCESS_READ_WRITE);
        append_register(instruction, a32_reg(rn), 4u,
            CDISASM_OPERAND_ACCESS_READ);
        append_register(instruction, a32_reg(rm), 4u,
            CDISASM_OPERAND_ACCESS_READ);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06100f10)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06100f30)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06100f50)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06100f70)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06100f90)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06100ff0)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06200f10)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06200f30)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06200f50)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06200f70)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06200f90)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06200ff0)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06300f10)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06300f30)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06300f50)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06300f70)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06300f90)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06300ff0)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06500f10)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06500f30)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06500f50)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06500f70)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06500f90)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06500ff0)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06600f10)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06600f30)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06600f50)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06600f70)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06600f90)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06600ff0)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06700f10)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06700f30)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06700f50)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06700f70)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06700f90)
        || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06700ff0)) {
        uint32_t selector = word & UINT32_C(0x0ff00ff0);
        unsigned rn = (word >> 16) & 15u;
        unsigned rd = (word >> 12) & 15u;
        unsigned rm = word & 15u;

        *recognized = 1;
        if (condition == CDISASM_ARM_CONDITION_NV
            || rd == 15u || rn == 15u || rm == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)selector;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = selector == UINT32_C(0x06100f10)
            ? CDISASM_ARM_NAME_SADD16
            : selector == UINT32_C(0x06100f30)
                ? CDISASM_ARM_NAME_SASX
                : selector == UINT32_C(0x06100f50)
                    ? CDISASM_ARM_NAME_SSAX
            : selector == UINT32_C(0x06100f70)
                ? CDISASM_ARM_NAME_SSUB16
                : selector == UINT32_C(0x06100f90)
                    ? CDISASM_ARM_NAME_SADD8
                    : selector == UINT32_C(0x06100ff0)
                        ? CDISASM_ARM_NAME_SSUB8
                        : selector == UINT32_C(0x06200f10)
                            ? CDISASM_ARM_NAME_QADD16
                            : selector == UINT32_C(0x06200f30)
                                ? CDISASM_ARM_NAME_QASX
                                : selector == UINT32_C(0x06200f50)
                                    ? CDISASM_ARM_NAME_QSAX
                            : selector == UINT32_C(0x06200f70)
                                ? CDISASM_ARM_NAME_QSUB16
                                : selector == UINT32_C(0x06200f90)
                                    ? CDISASM_ARM_NAME_QADD8
                                    : selector == UINT32_C(0x06200ff0)
                                        ? CDISASM_ARM_NAME_QSUB8
                                        : selector == UINT32_C(0x06300f10)
                                            ? CDISASM_ARM_NAME_SHADD16
                                            : selector == UINT32_C(0x06300f30)
                                                ? CDISASM_ARM_NAME_SHASX
                                                : selector == UINT32_C(0x06300f50)
                                                    ? CDISASM_ARM_NAME_SHSAX
                                            : selector == UINT32_C(0x06300f70)
                                                ? CDISASM_ARM_NAME_SHSUB16
                                                : selector == UINT32_C(0x06300f90)
                                                    ? CDISASM_ARM_NAME_SHADD8
                                                    : selector == UINT32_C(0x06300ff0)
                                                        ? CDISASM_ARM_NAME_SHSUB8
                        : selector == UINT32_C(0x06500f10)
                            ? CDISASM_ARM_NAME_UADD16
                            : selector == UINT32_C(0x06500f30)
                                ? CDISASM_ARM_NAME_UASX
                                : selector == UINT32_C(0x06500f50)
                                    ? CDISASM_ARM_NAME_USAX
                            : selector == UINT32_C(0x06500f70)
                                ? CDISASM_ARM_NAME_USUB16
                                : selector == UINT32_C(0x06500f90)
                                    ? CDISASM_ARM_NAME_UADD8
                                    : selector == UINT32_C(0x06500ff0)
                                        ? CDISASM_ARM_NAME_USUB8
                                        : selector == UINT32_C(0x06600f10)
                                            ? CDISASM_ARM_NAME_UQADD16
                                            : selector == UINT32_C(0x06600f30)
                                                ? CDISASM_ARM_NAME_UQASX
                                                : selector == UINT32_C(0x06600f50)
                                                    ? CDISASM_ARM_NAME_UQSAX
                                            : selector == UINT32_C(0x06600f70)
                                                ? CDISASM_ARM_NAME_UQSUB16
                                                : selector == UINT32_C(0x06600f90)
                                                    ? CDISASM_ARM_NAME_UQADD8
                                                    : selector == UINT32_C(0x06600ff0)
                                                        ? CDISASM_ARM_NAME_UQSUB8
                                                        : selector == UINT32_C(0x06700f10)
                                                            ? CDISASM_ARM_NAME_UHADD16
                                                            : selector == UINT32_C(0x06700f30)
                                                                ? CDISASM_ARM_NAME_UHASX
                                                                : selector == UINT32_C(0x06700f50)
                                                                    ? CDISASM_ARM_NAME_UHSAX
                                                            : selector == UINT32_C(0x06700f70)
                                                                ? CDISASM_ARM_NAME_UHSUB16
                                                                : selector == UINT32_C(0x06700f90)
                                                                    ? CDISASM_ARM_NAME_UHADD8
                                                                    : CDISASM_ARM_NAME_UHSUB8;
        append_register(
            instruction, a32_reg(rd), 4u, CDISASM_OPERAND_ACCESS_WRITE);
        append_register(
            instruction, a32_reg(rn), 4u, CDISASM_OPERAND_ACCESS_READ);
        append_register(
            instruction, a32_reg(rm), 4u, CDISASM_OPERAND_ACCESS_READ);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0x0fe00070)) == UINT32_C(0x07c00010)) {
        unsigned msb = (word >> 16) & 31u;
        unsigned rd = (word >> 12) & 15u;
        unsigned lsb = (word >> 7) & 31u;
        unsigned rm = word & 15u;
        int clear_alias = rm == 15u;

        *recognized = 1;
        if (condition == CDISASM_ARM_CONDITION_NV || rd == 15u
            || (!clear_alias && rm == 15u) || msb < lsb) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = clear_alias
            ? CDISASM_ARM_NAME_BFC : CDISASM_ARM_NAME_BFI;
        append_register(
            instruction, a32_reg(rd), 4u,
            CDISASM_OPERAND_ACCESS_READ_WRITE);
        if (!clear_alias) {
            append_register(
                instruction, a32_reg(rm), 4u,
                CDISASM_OPERAND_ACCESS_READ);
        }
        append_immediate(instruction, lsb, 1u);
        append_immediate(instruction, msb - lsb + 1u, 1u);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0x0ff0f0f0)) == UINT32_C(0x0710f010)
        || (word & UINT32_C(0x0ff0f0f0)) == UINT32_C(0x0730f010)) {
        unsigned rd = (word >> 16) & 15u;
        unsigned rm = (word >> 8) & 15u;
        unsigned rn = word & 15u;

        *recognized = 1;
        if (condition == CDISASM_ARM_CONDITION_NV
            || rd == 15u || rn == 15u || rm == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = (word & UINT32_C(0x00200000)) != 0u
            ? CDISASM_ARM_NAME_UDIV : CDISASM_ARM_NAME_SDIV;
        append_register(
            instruction, (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0 + rd),
            4u, CDISASM_OPERAND_ACCESS_WRITE);
        append_register(
            instruction, (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0 + rn),
            4u, CDISASM_OPERAND_ACCESS_READ);
        append_register(
            instruction, (cdisasm_arm_reg_id)(CDISASM_ARM_REG_R0 + rm),
            4u, CDISASM_OPERAND_ACCESS_READ);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0xfffffdff)) == UINT32_C(0xf1100000)) {
        unsigned pan = (word >> 9) & 1u;

        *recognized = 1;
#if !USE_EXTRA_OPCODES
        (void)pan;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_SETPAN;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->opcode_groups |= CDISASM_GROUP_PRIVILEGED;
        append_immediate(instruction, pan, 1u);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8);
        (void)cdisasm_arm_requirements_add_feature(
            required_capabilities, CDISASM_ARM_FEATURE_PAN);
        return CDISASM_STATUS_OK;
#endif
    }
    if (word == UINT32_C(0xf57ff01f)) {
        *recognized = 1;
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_CLREX;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0xfffffdff)) == UINT32_C(0xf1010000)) {
        unsigned big_endian = (word >> 9) & 1u;

        *recognized = 1;
#if !USE_EXTRA_OPCODES
        (void)big_endian;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_SETEND;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        append_immediate(instruction, big_endian, 1u);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0x0ff000f0)) == UINT32_C(0x01400070)
        && condition == CDISASM_ARM_CONDITION_AL) {
        unsigned immediate = ((word >> 4) & UINT32_C(0xfff0))
            | (word & 15u);

        *recognized = 1;
#if !USE_EXTRA_OPCODES
        (void)immediate;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_HVC;
        instruction->opcode_groups |=
            CDISASM_GROUP_INTERRUPT | CDISASM_GROUP_PRIVILEGED;
        append_immediate(instruction, immediate, 2u);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0x0ffffff0)) == UINT32_C(0x01600070)
        && condition != CDISASM_ARM_CONDITION_NV) {
        unsigned immediate = word & 15u;

        *recognized = 1;
#if !USE_EXTRA_OPCODES
        (void)immediate;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_SMC;
        instruction->opcode_groups |=
            CDISASM_GROUP_INTERRUPT | CDISASM_GROUP_PRIVILEGED;
        append_immediate(instruction, immediate, 1u);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7);
        return CDISASM_STATUS_OK;
#endif
    }
    if (((word & UINT32_C(0x0fff03f0)) == UINT32_C(0x06af0070)
            || (word & UINT32_C(0x0fff03f0)) == UINT32_C(0x06bf0070)
            || (word & UINT32_C(0x0fff03f0)) == UINT32_C(0x06ef0070)
            || (word & UINT32_C(0x0fff03f0)) == UINT32_C(0x06ff0070))
        && condition != CDISASM_ARM_CONDITION_NV) {
        unsigned selector = (word >> 20) & 15u;
        unsigned rd = (word >> 12) & 15u;
        unsigned rotation = ((word >> 10) & 3u) * 8u;
        unsigned rm = word & 15u;

        *recognized = 1;
        if (rd == 15u || rm == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)selector;
        (void)rotation;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        cdisasm_arm_operand *source;

        instruction->name_id = selector == 10u ? CDISASM_ARM_NAME_SXTB
            : selector == 11u ? CDISASM_ARM_NAME_SXTH
            : selector == 14u ? CDISASM_ARM_NAME_UXTB
                              : CDISASM_ARM_NAME_UXTH;
        append_register(
            instruction, a32_reg(rd), 4u, CDISASM_OPERAND_ACCESS_WRITE);
        source = append_register(
            instruction, a32_reg(rm), 4u, CDISASM_OPERAND_ACCESS_READ);
        if (source != NULL && rotation != 0u) {
            source->shift_type = CDISASM_ARM_SHIFT_ROR;
            source->shift_amount = (uint8_t)rotation;
        }
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06800fb0)
        && condition != CDISASM_ARM_CONDITION_NV) {
        unsigned rn = (word >> 16) & 15u;
        unsigned rd = (word >> 12) & 15u;
        unsigned rm = word & 15u;

        *recognized = 1;
        if (rn == 15u || rd == 15u || rm == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_SEL;
        append_register(
            instruction, a32_reg(rd), 4u, CDISASM_OPERAND_ACCESS_WRITE);
        append_register(
            instruction, a32_reg(rn), 4u, CDISASM_OPERAND_ACCESS_READ);
        append_register(
            instruction, a32_reg(rm), 4u, CDISASM_OPERAND_ACCESS_READ);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if (((word & UINT32_C(0x0fff0ff0)) == UINT32_C(0x06bf0f30)
            || (word & UINT32_C(0x0fff0ff0)) == UINT32_C(0x06bf0fb0)
            || (word & UINT32_C(0x0fff0ff0)) == UINT32_C(0x06ff0f30)
            || (word & UINT32_C(0x0fff0ff0)) == UINT32_C(0x06ff0fb0))
        && condition != CDISASM_ARM_CONDITION_NV) {
        static const cdisasm_arm_name_id names[4] = {
            CDISASM_ARM_NAME_REV, CDISASM_ARM_NAME_REV16,
            CDISASM_ARM_NAME_RBIT, CDISASM_ARM_NAME_REVSH
        };
        unsigned operation = ((word >> 21) & 2u) | ((word >> 7) & 1u);
        unsigned rd = (word >> 12) & 15u;
        unsigned rm = word & 15u;

        *recognized = 1;
        if (rd == 15u || rm == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)names;
        (void)operation;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = names[operation];
        append_register(
            instruction, a32_reg(rd), 4u, CDISASM_OPERAND_ACCESS_WRITE);
        append_register(
            instruction, a32_reg(rm), 4u, CDISASM_OPERAND_ACCESS_READ);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if (((word & UINT32_C(0x0ff00070)) == UINT32_C(0x06800010)
            || (word & UINT32_C(0x0ff00070)) == UINT32_C(0x06800050))
        && condition != CDISASM_ARM_CONDITION_NV) {
        unsigned top = (word >> 6) & 1u;
        unsigned rn = (word >> 16) & 15u;
        unsigned rd = (word >> 12) & 15u;
        unsigned amount = (word >> 7) & 31u;
        unsigned rm = word & 15u;

        *recognized = 1;
        if (rn == 15u || rd == 15u || rm == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)top;
        (void)amount;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        cdisasm_arm_operand *shifted;

        instruction->name_id = top
            ? CDISASM_ARM_NAME_PKHTB : CDISASM_ARM_NAME_PKHBT;
        append_register(
            instruction, a32_reg(rd), 4u, CDISASM_OPERAND_ACCESS_WRITE);
        append_register(
            instruction, a32_reg(rn), 4u, CDISASM_OPERAND_ACCESS_READ);
        shifted = append_register(
            instruction, a32_reg(rm), 4u, CDISASM_OPERAND_ACCESS_READ);
        if (shifted != NULL && (top || amount != 0u)) {
            shifted->shift_type = top
                ? CDISASM_ARM_SHIFT_ASR : CDISASM_ARM_SHIFT_LSL;
            shifted->shift_amount = (uint8_t)(amount ? amount : 32u);
        }
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if (((word & UINT32_C(0x0fe00070)) == UINT32_C(0x07a00050)
            || (word & UINT32_C(0x0fe00070)) == UINT32_C(0x07e00050))
        && condition != CDISASM_ARM_CONDITION_NV) {
        unsigned is_unsigned = (word & UINT32_C(0x00400000)) != 0u;
        unsigned width = ((word >> 16) & 31u) + 1u;
        unsigned rd = (word >> 12) & 15u;
        unsigned lsb = (word >> 7) & 31u;
        unsigned rn = word & 15u;

        *recognized = 1;
        if (rd == 15u || rn == 15u || lsb + width > 32u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)is_unsigned;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = is_unsigned
            ? CDISASM_ARM_NAME_UBFX : CDISASM_ARM_NAME_SBFX;
        append_register(
            instruction, a32_reg(rd), 4u, CDISASM_OPERAND_ACCESS_WRITE);
        append_register(
            instruction, a32_reg(rn), 4u, CDISASM_OPERAND_ACCESS_READ);
        append_immediate(instruction, lsb, 1u);
        append_immediate(instruction, width, 1u);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if (((word & UINT32_C(0x0fe00070)) == UINT32_C(0x06a00010)
            || (word & UINT32_C(0x0fe00070)) == UINT32_C(0x06a00050)
            || (word & UINT32_C(0x0fe00070)) == UINT32_C(0x06e00010)
            || (word & UINT32_C(0x0fe00070)) == UINT32_C(0x06e00050))
        && condition != CDISASM_ARM_CONDITION_NV) {
        unsigned is_unsigned = (word & UINT32_C(0x00400000)) != 0u;
        unsigned saturation = (word >> 16) & 31u;
        unsigned rd = (word >> 12) & 15u;
        unsigned amount = (word >> 7) & 31u;
        unsigned asr = (word & UINT32_C(0x40)) != 0u;
        unsigned rn = word & 15u;

        *recognized = 1;
        if (rd == 15u || rn == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)is_unsigned;
        (void)saturation;
        (void)amount;
        (void)asr;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = is_unsigned
            ? CDISASM_ARM_NAME_USAT : CDISASM_ARM_NAME_SSAT;
        append_register(
            instruction, a32_reg(rd), 4u, CDISASM_OPERAND_ACCESS_WRITE);
        append_immediate(
            instruction, saturation + (is_unsigned ? 0u : 1u), 1u);
        {
            cdisasm_arm_operand *source = append_register(
                instruction, a32_reg(rn), 4u,
                CDISASM_OPERAND_ACCESS_READ);
            if (source != NULL && (asr || amount != 0u)) {
                source->shift_type = asr
                    ? CDISASM_ARM_SHIFT_ASR : CDISASM_ARM_SHIFT_LSL;
                source->shift_amount = (uint8_t)(
                    asr && amount == 0u ? 32u : amount);
            }
        }
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if (((word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06a00f30)
            || (word & UINT32_C(0x0ff00ff0)) == UINT32_C(0x06e00f30))
        && condition != CDISASM_ARM_CONDITION_NV) {
        unsigned is_unsigned = (word & UINT32_C(0x00400000)) != 0u;
        unsigned saturation = (word >> 16) & 15u;
        unsigned rd = (word >> 12) & 15u;
        unsigned rn = word & 15u;

        *recognized = 1;
        if (rd == 15u || rn == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)is_unsigned;
        (void)saturation;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = is_unsigned
            ? CDISASM_ARM_NAME_USAT16 : CDISASM_ARM_NAME_SSAT16;
        append_register(
            instruction, a32_reg(rd), 4u, CDISASM_OPERAND_ACCESS_WRITE);
        append_immediate(
            instruction, saturation + (is_unsigned ? 0u : 1u), 1u);
        append_register(
            instruction, a32_reg(rn), 4u, CDISASM_OPERAND_ACCESS_READ);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0x0f900ff0)) == UINT32_C(0x01000050)
        && condition != CDISASM_ARM_CONDITION_NV) {
        static const cdisasm_arm_name_id names[4] = {
            CDISASM_ARM_NAME_QADD, CDISASM_ARM_NAME_QSUB,
            CDISASM_ARM_NAME_QDADD, CDISASM_ARM_NAME_QDSUB
        };
        unsigned operation = (word >> 21) & 3u;
        unsigned rn = (word >> 16) & 15u;
        unsigned rd = (word >> 12) & 15u;
        unsigned rm = word & 15u;

        *recognized = 1;
        if (rd == 15u || rn == 15u || rm == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)names;
        (void)operation;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = names[operation];
        append_register(
            instruction, a32_reg(rd), 4u, CDISASM_OPERAND_ACCESS_WRITE);
        append_register(
            instruction, a32_reg(rm), 4u, CDISASM_OPERAND_ACCESS_READ);
        append_register(
            instruction, a32_reg(rn), 4u, CDISASM_OPERAND_ACCESS_READ);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0xfff000f0)) == UINT32_C(0xe7f000f0)) {
        unsigned immediate = ((word >> 4) & UINT32_C(0xfff0))
            | (word & UINT32_C(0x000f));

        *recognized = 1;
#if !USE_EXTRA_OPCODES
        (void)immediate;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_UDF;
        instruction->opcode_groups |= CDISASM_GROUP_INTERRUPT;
        append_immediate(instruction, immediate, 2u);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V4);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0xffdfffe0)) == UINT32_C(0xf84d0500)
        || (word & UINT32_C(0xffdfffe0)) == UINT32_C(0xf8cd0500)
        || (word & UINT32_C(0xffdfffe0)) == UINT32_C(0xf94d0500)
        || (word & UINT32_C(0xffdfffe0)) == UINT32_C(0xf9cd0500)) {
        unsigned mode = word & 31u;
        unsigned writeback = (word >> 21) & 1u;
        uint32_t fixed = word & UINT32_C(0xffdfffe0);

        *recognized = 1;
        if (mode != 0x11u && mode != 0x12u && mode != 0x13u
            && mode != 0x16u && mode != 0x17u && mode != 0x1au
            && mode != 0x1bu) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)instruction;
        (void)required_capabilities;
        (void)writeback;
        (void)fixed;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = fixed == UINT32_C(0xf84d0500)
            ? CDISASM_ARM_NAME_SRSDA
            : (fixed == UINT32_C(0xf8cd0500)
                ? CDISASM_ARM_NAME_SRS
            : (fixed == UINT32_C(0xf94d0500)
                ? CDISASM_ARM_NAME_SRSDB : CDISASM_ARM_NAME_SRSIB));
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->opcode_groups |= CDISASM_GROUP_PRIVILEGED;
        append_register(
            instruction, CDISASM_ARM_REG_SP, 4u,
            writeback != 0u ? CDISASM_OPERAND_ACCESS_READ_WRITE
                            : CDISASM_OPERAND_ACCESS_READ);
        append_immediate(instruction, mode, 1u);
        if (writeback != 0u) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
        }
        if (fixed == UINT32_C(0xf84d0500)) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT;
        } else if (fixed == UINT32_C(0xf94d0500)) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT;
        } else if (fixed == UINT32_C(0xf9cd0500)) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT;
        } else {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT;
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0xffd0ffff)) == UINT32_C(0xf8100a00)
        || (word & UINT32_C(0xffd0ffff)) == UINT32_C(0xf8900a00)
        || (word & UINT32_C(0xffd0ffff)) == UINT32_C(0xf9100a00)
        || (word & UINT32_C(0xffd0ffff)) == UINT32_C(0xf9900a00)) {
        unsigned rn = (word >> 16) & 15u;
        unsigned writeback = (word >> 21) & 1u;
        uint32_t fixed = word & UINT32_C(0xffd0ffff);

        *recognized = 1;
        if (rn == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)instruction;
        (void)required_capabilities;
        (void)writeback;
        (void)fixed;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = fixed == UINT32_C(0xf8100a00)
            ? CDISASM_ARM_NAME_RFEDA
            : (fixed == UINT32_C(0xf8900a00)
                ? CDISASM_ARM_NAME_RFE
            : (fixed == UINT32_C(0xf9100a00)
                ? CDISASM_ARM_NAME_RFEDB : CDISASM_ARM_NAME_RFEIB));
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        instruction->opcode_groups |= CDISASM_GROUP_PRIVILEGED
            | CDISASM_GROUP_RETURN | CDISASM_GROUP_INTERRUPT_RETURN;
        append_register(
            instruction, a32_reg(rn), 4u,
            writeback != 0u ? CDISASM_OPERAND_ACCESS_READ_WRITE
                            : CDISASM_OPERAND_ACCESS_READ);
        if (writeback != 0u) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
        }
        if (fixed == UINT32_C(0xf8100a00)) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT;
        } else if (fixed == UINT32_C(0xf9100a00)) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT;
        } else if (fixed == UINT32_C(0xf9900a00)) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT;
        } else {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT;
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V7);
        return CDISASM_STATUS_OK;
#endif
    }
    {
        static const uint32_t crc_values[6] = {
            UINT32_C(0x01000040), UINT32_C(0x01200040),
            UINT32_C(0x01400040), UINT32_C(0x01000240),
            UINT32_C(0x01200240), UINT32_C(0x01400240)
        };
#if USE_EXTRA_OPCODES
        static const cdisasm_arm_name_id crc_names[6] = {
            CDISASM_ARM_NAME_CRC32B, CDISASM_ARM_NAME_CRC32H,
            CDISASM_ARM_NAME_CRC32W, CDISASM_ARM_NAME_CRC32CB,
            CDISASM_ARM_NAME_CRC32CH, CDISASM_ARM_NAME_CRC32CW
        };
#endif
        uint32_t fixed = word & UINT32_C(0x0ff00ff0);
        size_t operation;

        for (operation = 0u; operation < 6u; ++operation) {
            if (fixed == crc_values[operation]) {
                break;
            }
        }
        if (operation < 6u && condition != CDISASM_ARM_CONDITION_NV) {
            unsigned rd = (word >> 12) & 15u;
            unsigned rn = (word >> 16) & 15u;
            unsigned rm = word & 15u;

            *recognized = 1;
            /* PC is architecturally UNPREDICTABLE in every A32 CRC32
             * operand position.  Report it as an invalid structured
             * instruction instead of exposing a usable PC operand. */
            if (rd == 15u || rn == 15u || rm == 15u) {
                return CDISASM_STATUS_INVALID_INSTRUCTION;
            }
#if !USE_EXTRA_OPCODES
            return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
            instruction->name_id = crc_names[operation];
            append_register(
                instruction, a32_reg(rd), 4u,
                CDISASM_OPERAND_ACCESS_WRITE);
            append_register(
                instruction, a32_reg(rn), 4u,
                CDISASM_OPERAND_ACCESS_READ);
            append_register(
                instruction, a32_reg(rm),
                (uint8_t)(UINT32_C(1) << (operation % 3u)),
                CDISASM_OPERAND_ACCESS_READ);
            apply_condition_group(instruction);
            cdisasm_arm_requirements_set_legacy(
                required_capabilities, CDISASM_ARM_CAP_V8);
            (void)cdisasm_arm_requirements_add_feature(
                required_capabilities, CDISASM_ARM_FEATURE_CRC32);
            return CDISASM_STATUS_OK;
#endif
        }
    }
    if ((word & UINT32_C(0x0f8000f0)) == UINT32_C(0x00800090)
        && condition != CDISASM_ARM_CONDITION_NV) {
        static const cdisasm_arm_name_id names[2][2] = {
            {CDISASM_ARM_NAME_UMULL, CDISASM_ARM_NAME_UMLAL},
            {CDISASM_ARM_NAME_SMULL, CDISASM_ARM_NAME_SMLAL}
        };
        unsigned signed_result = (word >> 22) & 1u;
        unsigned accumulate = (word >> 21) & 1u;
        unsigned set_flags = (word >> 20) & 1u;
        unsigned rd_hi = (word >> 16) & 15u;
        unsigned rd_lo = (word >> 12) & 15u;
        unsigned rn = word & 15u;
        unsigned rm = (word >> 8) & 15u;
        cdisasm_operand_access destination_access = accumulate != 0u
            ? CDISASM_OPERAND_ACCESS_READ_WRITE
            : CDISASM_OPERAND_ACCESS_WRITE;

        *recognized = 1;
        if (rd_hi == 15u || rd_lo == 15u || rn == 15u || rm == 15u
            || rd_hi == rd_lo) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)names;
        (void)signed_result;
        (void)set_flags;
        (void)destination_access;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        if (set_flags != 0u) {
            static const cdisasm_arm_name_id flag_names[2][2] = {
                {CDISASM_ARM_NAME_UMULLS, CDISASM_ARM_NAME_UMLALS},
                {CDISASM_ARM_NAME_SMULLS, CDISASM_ARM_NAME_SMLALS}
            };
            instruction->name_id = flag_names[signed_result][accumulate];
        } else {
            instruction->name_id = names[signed_result][accumulate];
        }
        if (set_flags != 0u) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
        }
        append_register(
            instruction, a32_reg(rd_lo), 4u, destination_access);
        append_register(
            instruction, a32_reg(rd_hi), 4u, destination_access);
        append_register(
            instruction, a32_reg(rn), 4u,
            CDISASM_OPERAND_ACCESS_READ);
        append_register(
            instruction, a32_reg(rm), 4u,
            CDISASM_OPERAND_ACCESS_READ);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V4);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0x0fc000f0)) == UINT32_C(0x00000090)
        && condition != CDISASM_ARM_CONDITION_NV) {
        unsigned accumulate = (word >> 21) & 1u;
        unsigned set_flags = (word >> 20) & 1u;
        unsigned rd = (word >> 16) & 15u;
        unsigned rn = (word >> 12) & 15u;
        unsigned rs = (word >> 8) & 15u;
        unsigned rm = word & 15u;

        *recognized = 1;
        if (accumulate == 0u && rn != 0u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        if (rd == 15u || rs == 15u || rm == 15u
            || (accumulate != 0u && rn == 15u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)set_flags;
        (void)rd;
        (void)rs;
        (void)rm;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = accumulate != 0u
            ? (set_flags != 0u
                ? CDISASM_ARM_NAME_MLAS : CDISASM_ARM_NAME_MLA)
            : (set_flags != 0u
                ? CDISASM_ARM_NAME_MULS : CDISASM_ARM_NAME_MUL);
        if (set_flags != 0u) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
        }
        append_register(
            instruction, a32_reg(rd), 4, CDISASM_OPERAND_ACCESS_WRITE);
        append_register(
            instruction, a32_reg(rm), 4, CDISASM_OPERAND_ACCESS_READ);
        append_register(
            instruction, a32_reg(rs), 4, CDISASM_OPERAND_ACCESS_READ);
        if (accumulate != 0u) {
            append_register(
                instruction, a32_reg(rn), 4, CDISASM_OPERAND_ACCESS_READ);
        }
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V4);
        return CDISASM_STATUS_OK;
#endif
    }
    if (((word & UINT32_C(0x0ff00000)) == UINT32_C(0x03000000)
            || (word & UINT32_C(0x0ff00000)) == UINT32_C(0x03400000))
        && condition != CDISASM_ARM_CONDITION_NV) {
        unsigned rd = (word >> 12) & 15u;
        uint16_t immediate = (uint16_t)(((word >> 4) & UINT32_C(0xf000))
            | (word & UINT32_C(0x0fff)));

        *recognized = 1;
        if (rd == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)rd;
        (void)immediate;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = (word & UINT32_C(0x00400000)) != 0u
            ? CDISASM_ARM_NAME_MOVT : CDISASM_ARM_NAME_MOVW;
        append_register(
            instruction, a32_reg(rd), 4,
            (word & UINT32_C(0x00400000)) != 0u
                ? CDISASM_OPERAND_ACCESS_READ_WRITE
                : CDISASM_OPERAND_ACCESS_WRITE);
        append_immediate(instruction, immediate, 2);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if (((word & UINT32_C(0x0fff0ff0)) == UINT32_C(0x016f0f10)
            || (word & UINT32_C(0x0fff0ff0)) == UINT32_C(0x06bf0f30))
        && condition != CDISASM_ARM_CONDITION_NV) {
        unsigned rd = (word >> 12) & 15u;
        unsigned rm = word & 15u;

        *recognized = 1;
        if (rd == 15u || rm == 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)rd;
        (void)rm;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = (word & UINT32_C(0x0fff0ff0))
                == UINT32_C(0x016f0f10)
            ? CDISASM_ARM_NAME_CLZ : CDISASM_ARM_NAME_REV;
        append_register(
            instruction, a32_reg(rd), 4, CDISASM_OPERAND_ACCESS_WRITE);
        append_register(
            instruction, a32_reg(rm), 4, CDISASM_OPERAND_ACCESS_READ);
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(required_capabilities, instruction->name_id == CDISASM_ARM_NAME_CLZ
            ? CDISASM_ARM_CAP_V5 : CDISASM_ARM_CAP_V6);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0x0e000090)) == UINT32_C(0x00000090)
        && (word & UINT32_C(0x00000060)) != 0u
        && condition != CDISASM_ARM_CONDITION_NV) {
        unsigned pre_index = (word >> 24) & 1u;
        unsigned add = (word >> 23) & 1u;
        unsigned immediate_form = (word >> 22) & 1u;
        unsigned writeback = (word >> 21) & 1u;
        unsigned rn = (word >> 16) & 15u;
        unsigned rt = (word >> 12) & 15u;
#if USE_EXTRA_OPCODES
        unsigned load = (word >> 20) & 1u;
        unsigned operation = (word >> 5) & 3u;
        unsigned unprivileged = pre_index == 0u && writeback != 0u;
        unsigned pair = load == 0u && operation >= 2u;
        uint32_t offset;
        cdisasm_arm_operand *memory;
#endif

        *recognized = 1;
        if (immediate_form == 0u
            && (word & UINT32_C(0x00000f00)) != 0u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        (void)pre_index;
        (void)add;
        (void)writeback;
        (void)rn;
        (void)rt;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        if (operation == 1u) {
            instruction->name_id = unprivileged != 0u
                ? (load != 0u ? CDISASM_ARM_NAME_LDRHT
                              : CDISASM_ARM_NAME_STRHT)
                : (load != 0u ? CDISASM_ARM_NAME_LDRH
                              : CDISASM_ARM_NAME_STRH);
        } else if (load != 0u) {
            instruction->name_id = unprivileged != 0u
                ? (operation == 2u ? CDISASM_ARM_NAME_LDRSBT
                                   : CDISASM_ARM_NAME_LDRSHT)
                : (operation == 2u ? CDISASM_ARM_NAME_LDRSB
                                   : CDISASM_ARM_NAME_LDRSH);
        } else {
            instruction->name_id = operation == 2u
                ? CDISASM_ARM_NAME_LDRD : CDISASM_ARM_NAME_STRD;
        }
        if (rt == 15u
            || (immediate_form == 0u && (word & 15u) == 15u)
            || (rn == 15u
                && (pre_index == 0u || writeback != 0u
                    || immediate_form == 0u))
            || (writeback != 0u
                && (rn == rt || (pair != 0u && rn == rt + 1u)))
            || (pair != 0u && ((rt & 1u) != 0u || rt >= 14u))) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        append_register(
            instruction, a32_reg(rt), pair != 0u ? 4u
                : operation == 2u ? 1u : 2u,
            load != 0u || instruction->name_id == CDISASM_ARM_NAME_LDRD
                ? CDISASM_OPERAND_ACCESS_WRITE
                : CDISASM_OPERAND_ACCESS_READ);
        if (pair != 0u) {
            append_register(
                instruction, a32_reg(rt + 1u), 4u,
                instruction->name_id == CDISASM_ARM_NAME_LDRD
                    ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ);
        }
        memory = append_operand(instruction);
        offset = immediate_form != 0u
            ? ((word >> 4) & UINT32_C(0xf0)) | (word & UINT32_C(0x0f))
            : 0u;
        if (memory != NULL) {
            memory->type = CDISASM_OPERAND_MEMORY;
            memory->size = pair != 0u ? 8u
                : operation == 2u ? 1u : 2u;
            memory->base_reg = a32_reg(rn);
            memory->access = load != 0u
                ? CDISASM_OPERAND_ACCESS_READ
                : CDISASM_OPERAND_ACCESS_WRITE;
            if (immediate_form != 0u && offset != 0u) {
                memory->imm = add != 0u
                    ? offset : (uint64_t)(-(int64_t)offset);
                memory->flags = CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;
                if (add == 0u) {
                    memory->flags |= CDISASM_OPERAND_FLAG_SIGNED;
                }
            } else if (immediate_form == 0u) {
                memory->index_reg = a32_reg(word & 15u);
                if (add == 0u) {
                    memory->flags |= CDISASM_OPERAND_FLAG_SIGNED;
                }
            }
            if (rn == 15u && immediate_form != 0u
                && pre_index != 0u && writeback == 0u) {
                uint64_t base = instruction->address + UINT64_C(8);

                memory->address = add != 0u
                    ? base + offset : base - offset;
                memory->flags |= CDISASM_OPERAND_FLAG_PC_RELATIVE
                    | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
            }
        }
        if (pre_index == 0u) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
        } else if (writeback != 0u) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
        }
        if (unprivileged != 0u) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_UNPRIVILEGED;
        }
        apply_condition_group(instruction);
        cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V4);
        return CDISASM_STATUS_OK;
#endif
    }
    if ((word & UINT32_C(0xfffffff0)) == UINT32_C(0xf57ff040)
        || (word & UINT32_C(0xfffffff0)) == UINT32_C(0xf57ff050)
        || (word & UINT32_C(0xfffffff0)) == UINT32_C(0xf57ff060)) {
        unsigned option = word & 15u;

        *recognized = 1;
        if ((word & UINT32_C(0xfffffff0)) == UINT32_C(0xf57ff060)
            && option != 15u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = (word & UINT32_C(0xfffffff0))
                == UINT32_C(0xf57ff040)
            ? (option == 0u ? CDISASM_ARM_NAME_SSBB
                : option == 4u ? CDISASM_ARM_NAME_PSSBB
                               : CDISASM_ARM_NAME_DSB)
            : (word & UINT32_C(0xfffffff0)) == UINT32_C(0xf57ff050)
                ? CDISASM_ARM_NAME_DMB : CDISASM_ARM_NAME_ISB;
        instruction->condition = CDISASM_ARM_CONDITION_AL;
        if (instruction->name_id == CDISASM_ARM_NAME_SSBB) {
            instruction->form_id = UINT16_C(953);
        } else if (instruction->name_id == CDISASM_ARM_NAME_PSSBB) {
            instruction->form_id = UINT16_C(954);
        } else {
            append_immediate(instruction, option, 1);
        }
        cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V7);
        return CDISASM_STATUS_OK;
#endif
    }
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}

/* MRS/MSR expose a PSR selector and MSR's four field-mask bits.  These
 * architectural operands must not be reduced to an opaque opcode number. */
static cdisasm_status decode_a32_psr_transfer(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    int read_psr = (word & UINT32_C(0x0fbf0fff))
        == UINT32_C(0x010f0000);
    int write_register = (word & UINT32_C(0x0fb0fff0))
        == UINT32_C(0x0120f000);
    int write_immediate = (word & UINT32_C(0x0fb0f000))
        == UINT32_C(0x0320f000);
    unsigned saved;
    unsigned mask;
    unsigned reg;

    if (!read_psr && !write_register && !write_immediate) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if (instruction->condition == CDISASM_ARM_CONDITION_NV) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    saved = (word >> 22) & 1u;
    mask = (word >> 16) & 15u;
    reg = read_psr ? (word >> 12) & 15u : word & 15u;
    /* The immediate-MSR envelope also contains architectural hints such
     * as NOP when the field mask is zero.  Leave those for their decoder. */
    if (write_immediate && mask == 0u) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if ((read_psr && reg == 15u)
        || (!read_psr && (mask == 0u
            || (write_register && reg == 15u)))) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
#if !USE_EXTRA_OPCODES
    (void)saved;
    (void)required_capabilities;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    instruction->name_id = read_psr
        ? CDISASM_ARM_NAME_MRS : CDISASM_ARM_NAME_MSR;
    instruction->form_id = read_psr ? UINT16_C(94)
        : write_register ? UINT16_C(96) : UINT16_C(240);
    if (saved || (!read_psr && (mask & 7u) != 0u)) {
        instruction->opcode_groups |= CDISASM_GROUP_PRIVILEGED;
    }
    if (read_psr) {
        append_register(instruction, a32_reg(reg), 4u,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_system_operand(instruction,
            CDISASM_ARM_OPERAND_SYSTEM_REGISTER,
            (uint16_t)(saved << 4), CDISASM_OPERAND_ACCESS_READ);
    } else {
        append_system_operand(instruction,
            CDISASM_ARM_OPERAND_SYSTEM_REGISTER,
            (uint16_t)((saved << 4) | mask),
            CDISASM_OPERAND_ACCESS_WRITE);
        if (write_register) {
            append_register(instruction, a32_reg(reg), 4u,
                CDISASM_OPERAND_ACCESS_READ);
        } else {
            unsigned rotation = ((word >> 8) & 15u) * 2u;
            uint32_t immediate = rotate_right32(word & 255u, rotation);

            append_immediate(instruction, immediate, 4u);
        }
    }
    apply_condition_group(instruction);
    cdisasm_arm_requirements_set_legacy(
        required_capabilities, CDISASM_ARM_CAP_V4);
    return CDISASM_STATUS_OK;
#endif
}

static cdisasm_status decode_a32(
    uint32_t word,
    uint64_t address,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    cdisasm_status status;
    int extra_recognized = 0;
    cdisasm_arm_condition condition = (cdisasm_arm_condition)(word >> 28);

    initialize_instruction(
        instruction, word, address, CDISASM_ARM_ISA_A32, condition);

    status = decode_a32_psr_transfer(
        word, instruction, required_capabilities);
    if (status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        return status;
    }

    status = decode_a32_bkpt(word, instruction, required_capabilities);
    if (status == CDISASM_STATUS_OK) {
        return status;
    }
    status = decode_a32_extra(
        word, instruction, required_capabilities, &extra_recognized);
    if (extra_recognized
        || status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        return status;
    }
    /* VFP scalar/AdvSIMD transfers share the coprocessor envelope.  Let the
     * structured NEON owner claim them before the broader MCR/LDC classifier
     * can turn an otherwise valid VLDR/VSTR into INVALID_INSTRUCTION. */
    status = cdisasm_arm_decode_a32_neon(
        word, instruction, required_capabilities);
    if (status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        return status;
    }
    status = cdisasm_arm_decode_a32_coprocessor_transfer(
        word, instruction, required_capabilities);
    if (status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        return status;
    }
    if (condition == CDISASM_ARM_CONDITION_NV) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    status = decode_a32_hint(
        word, instruction, required_capabilities, &extra_recognized);
    if (extra_recognized
        || status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        return status;
    }
    status = decode_a32_branch_register(word, instruction, required_capabilities);
    if (status == CDISASM_STATUS_OK) {
        return status;
    }
    if ((word & UINT32_C(0x0e000000)) == UINT32_C(0x0a000000)) {
        return decode_a32_branch_immediate(
            word, address, instruction, required_capabilities);
    }
    if ((word & UINT32_C(0x0f000000)) == UINT32_C(0x0f000000)) {
        return decode_a32_svc(word, instruction, required_capabilities);
    }
    if ((word & UINT32_C(0x0e000000)) == UINT32_C(0x08000000)) {
        return decode_a32_block_transfer(
            word, instruction, required_capabilities);
    }
    if ((word & UINT32_C(0x0c000000)) == UINT32_C(0x04000000)) {
        return decode_a32_single_transfer(
            word, address, instruction, required_capabilities);
    }
    if ((word & UINT32_C(0x0c000000)) == 0) {
        return decode_a32_data_processing(
            word, instruction, required_capabilities);
    }
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}

static cdisasm_status decode_a64_exception(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    uint32_t form = word & UINT32_C(0xffe0001f);

    switch (form) {
        case UINT32_C(0xd4000001):
            instruction->name_id = CDISASM_ARM_NAME_SVC;
            break;
        case UINT32_C(0xd4000002):
            instruction->name_id = CDISASM_ARM_NAME_HVC;
            instruction->opcode_groups |= CDISASM_GROUP_PRIVILEGED;
            break;
        case UINT32_C(0xd4000003):
            instruction->name_id = CDISASM_ARM_NAME_SMC;
            instruction->opcode_groups |= CDISASM_GROUP_PRIVILEGED;
            break;
        case UINT32_C(0xd4200000):
            instruction->name_id = CDISASM_ARM_NAME_BRK;
            break;
        default:
            return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    instruction->opcode_groups |= CDISASM_GROUP_INTERRUPT;
    append_immediate(instruction, (word >> 5) & UINT32_C(0xffff), 2);
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8);
    return CDISASM_STATUS_OK;
}

static cdisasm_status decode_a64_udf(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    /* Pinned AARCHMRS UDF_only_perm_undef (form 4387).  UDF is an
     * architecturally allocated disassembly which raises an Undefined
     * Instruction exception when executed.  The generated leaf semantics
     * therefore place it in the interrupt group without inventing an
     * ILLEGAL/unpredictable flag or any execution-state side effect. */
#if !USE_EXTRA_OPCODES
    (void)word;
    (void)instruction;
    (void)required_capabilities;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    instruction->name_id = CDISASM_ARM_NAME_UDF;
    instruction->opcode_groups |= CDISASM_GROUP_INTERRUPT;
    append_immediate(instruction, word & UINT32_C(0xffff), 2u);
    cdisasm_arm_requirements_set_legacy(
        required_capabilities, CDISASM_ARM_CAP_V8);
    return CDISASM_STATUS_OK;
#endif
}

static cdisasm_status decode_a64_branch_register(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    uint32_t form = word & UINT32_C(0xfffffc1f);
    unsigned rn = (word >> 5) & 31u;

    if (word == UINT32_C(0xd6bf03e0)) {
#if !USE_EXTRA_OPCODES
        (void)instruction;
        (void)required_capabilities;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = CDISASM_ARM_NAME_DRPS;
        instruction->opcode_groups |= CDISASM_GROUP_RETURN
            | CDISASM_GROUP_INTERRUPT_RETURN
            | CDISASM_GROUP_PRIVILEGED;
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8);
        return CDISASM_STATUS_OK;
#endif
    }
    if (word == UINT32_C(0xd65f0bff)
        || word == UINT32_C(0xd65f0fff)
        || word == UINT32_C(0xd69f0bff)
        || word == UINT32_C(0xd69f0fff)) {
#if !USE_EXTRA_OPCODES
        (void)instruction;
        (void)required_capabilities;
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        const int exception_return =
            (word & UINT32_C(0x00800000)) != 0u;
        const int key_b = (word & UINT32_C(0x00000400)) != 0u;

        instruction->name_id = exception_return
            ? (key_b ? CDISASM_ARM_NAME_ERETAB
                     : CDISASM_ARM_NAME_ERETAA)
            : (key_b ? CDISASM_ARM_NAME_RETAB
                     : CDISASM_ARM_NAME_RETAA);
        instruction->opcode_groups |= CDISASM_GROUP_RETURN;
        if (exception_return) {
            instruction->opcode_groups |= CDISASM_GROUP_INTERRUPT_RETURN
                | CDISASM_GROUP_PRIVILEGED;
        }
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_POINTER_AUTH;
        cdisasm_arm_requirements_add_legacy(
            required_capabilities, CDISASM_ARM_CAP_PAUTH);
        return CDISASM_STATUS_OK;
#endif
    }

    if (form == UINT32_C(0xd61f0000)) {
        instruction->name_id = CDISASM_ARM_NAME_BR;
        instruction->opcode_groups |= CDISASM_GROUP_JUMP;
    } else if (form == UINT32_C(0xd63f0000)) {
        instruction->name_id = CDISASM_ARM_NAME_BLR;
        instruction->opcode_groups |= CDISASM_GROUP_CALL;
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_LINK;
    } else if (form == UINT32_C(0xd65f0000)) {
        instruction->name_id = CDISASM_ARM_NAME_RET;
        instruction->opcode_groups |= CDISASM_GROUP_RETURN;
    } else {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    append_register(
        instruction,
        a64_reg(rn, 1, 0),
        8,
        CDISASM_OPERAND_ACCESS_READ);
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8);
    return CDISASM_STATUS_OK;
}

static cdisasm_status decode_a64_branch_immediate(
    uint32_t word,
    uint64_t address,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    int link = (word & UINT32_C(0x80000000)) != 0;
    int64_t displacement = sign_extend(
        ((uint64_t)word & UINT64_C(0x03ffffff)) << 2, 28);
    uint64_t target = address + (uint64_t)displacement;

    instruction->name_id = link ? CDISASM_ARM_NAME_BL : CDISASM_ARM_NAME_B;
    instruction->opcode_groups |= link ? CDISASM_GROUP_CALL
                                        : CDISASM_GROUP_JUMP;
    if (link) {
        instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_LINK;
    }
    append_relative_target(instruction, target, displacement, 8);
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8);
    return CDISASM_STATUS_OK;
}

static cdisasm_status decode_a64_conditional_branch(
    uint32_t word,
    uint64_t address,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    int64_t displacement = sign_extend(
        ((uint64_t)((word >> 5) & UINT32_C(0x7ffff))) << 2, 21);
    uint64_t target = address + (uint64_t)displacement;

    instruction->name_id = CDISASM_ARM_NAME_B;
    instruction->condition = (cdisasm_arm_condition)(word & 15u);
    instruction->opcode_groups |= CDISASM_GROUP_JUMP | CDISASM_GROUP_CONDITIONAL;
    append_relative_target(instruction, target, displacement, 8);
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8);
    return CDISASM_STATUS_OK;
}

static cdisasm_status decode_a64_compare_branch(
    uint32_t word,
    uint64_t address,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    int is_64 = (word & UINT32_C(0x80000000)) != 0;
    int nonzero = (word & UINT32_C(0x01000000)) != 0;
    unsigned rt = word & 31u;
    int64_t displacement = sign_extend(
        ((uint64_t)((word >> 5) & UINT32_C(0x7ffff))) << 2, 21);
    uint64_t target = address + (uint64_t)displacement;

    instruction->name_id = nonzero ? CDISASM_ARM_NAME_CBNZ
                                   : CDISASM_ARM_NAME_CBZ;
    instruction->opcode_groups |= CDISASM_GROUP_JUMP | CDISASM_GROUP_CONDITIONAL;
    append_register(
        instruction,
        a64_reg(rt, is_64, 0),
        is_64 ? 8u : 4u,
        CDISASM_OPERAND_ACCESS_READ);
    append_relative_target(instruction, target, displacement, 8);
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8);
    return CDISASM_STATUS_OK;
}

static cdisasm_status decode_a64_test_branch(
    uint32_t word,
    uint64_t address,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    unsigned bit_number = ((word >> 26) & 32u) | ((word >> 19) & 31u);
    int nonzero = (word & UINT32_C(0x01000000)) != 0;
    unsigned rt = word & 31u;
    int64_t displacement = sign_extend(
        ((uint64_t)((word >> 5) & UINT32_C(0x3fff))) << 2, 16);
    uint64_t target = address + (uint64_t)displacement;
    int is_64 = bit_number >= 32u;

    instruction->name_id = nonzero ? CDISASM_ARM_NAME_TBNZ
                                   : CDISASM_ARM_NAME_TBZ;
    instruction->opcode_groups |= CDISASM_GROUP_JUMP | CDISASM_GROUP_CONDITIONAL;
    append_register(
        instruction,
        a64_reg(rt, is_64, 0),
        is_64 ? 8u : 4u,
        CDISASM_OPERAND_ACCESS_READ);
    append_immediate(instruction, bit_number, 1);
    append_relative_target(instruction, target, displacement, 8);
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8);
    return CDISASM_STATUS_OK;
}

static cdisasm_status decode_a64_pc_relative(
    uint32_t word,
    uint64_t address,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    int page = (word & UINT32_C(0x80000000)) != 0;
    uint64_t encoded = ((uint64_t)((word >> 5) & UINT32_C(0x7ffff)) << 2)
        | ((word >> 29) & 3u);
    int64_t immediate = sign_extend(encoded, 21);
    int64_t displacement = page ? immediate * INT64_C(4096) : immediate;
    uint64_t base = page ? (address & ~UINT64_C(0xfff)) : address;
    uint64_t target = base + (uint64_t)displacement;
    cdisasm_arm_operand *operand;

    instruction->name_id = page ? CDISASM_ARM_NAME_ADRP
                                : CDISASM_ARM_NAME_ADR;
    append_register(
        instruction,
        a64_reg(word & 31u, 1, 0),
        8,
        CDISASM_OPERAND_ACCESS_WRITE);
    operand = append_immediate(instruction, target, 8);
    if (operand != NULL) {
        operand->address = (uint64_t)displacement;
        operand->flags = CDISASM_OPERAND_FLAG_SIGNED
            | CDISASM_OPERAND_FLAG_PC_RELATIVE
            | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
    }
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8);
    return CDISASM_STATUS_OK;
}

static cdisasm_status decode_a64_load_literal(
    uint32_t word,
    uint64_t address,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
#if !USE_EXTRA_OPCODES
    (void)word;
    (void)address;
    (void)instruction;
    (void)required_capabilities;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    uint32_t operation = word & UINT32_C(0xff000000);
    int64_t displacement = sign_extend((word >> 5) & UINT32_C(0x7ffff), 19)
        * INT64_C(4);
    uint64_t target = address + (uint64_t)displacement;
    unsigned rt = word & 31u;
    cdisasm_arm_operand *operand;

    instruction->name_id = operation == UINT32_C(0xd8000000)
        ? CDISASM_ARM_NAME_PRFM
        : operation == UINT32_C(0x98000000)
            ? CDISASM_ARM_NAME_LDRSW : CDISASM_ARM_NAME_LDR;
    if (operation == UINT32_C(0xd8000000)) {
        instruction->form_id = UINT16_C(4923);
        append_immediate(instruction, rt, 1u);
    } else if (operation == UINT32_C(0x18000000)) {
        instruction->form_id = UINT16_C(4917);
        append_register(instruction, a64_reg(rt, 0, 0), 4,
            CDISASM_OPERAND_ACCESS_WRITE);
    } else if (operation == UINT32_C(0x58000000)) {
        instruction->form_id = UINT16_C(4919);
        append_register(instruction, a64_reg(rt, 1, 0), 8,
            CDISASM_OPERAND_ACCESS_WRITE);
    } else if (operation == UINT32_C(0x98000000)) {
        instruction->form_id = UINT16_C(4921);
        append_register(instruction, a64_reg(rt, 1, 0), 8,
            CDISASM_OPERAND_ACCESS_WRITE);
    } else {
        uint8_t size = operation == UINT32_C(0x1c000000) ? 4u
            : operation == UINT32_C(0x5c000000) ? 8u : 16u;
        cdisasm_arm_reg_id reg = (cdisasm_arm_reg_id)(
            (size == 4u ? CDISASM_ARM_REG_S0
                : size == 8u ? CDISASM_ARM_REG_D0
                : rt < 16u ? CDISASM_ARM_REG_Q0
                : CDISASM_ARM_REG_Q16 - 16u) + rt);

        instruction->form_id = size == 4u ? UINT16_C(4918)
            : size == 8u ? UINT16_C(4920) : UINT16_C(4922);
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_register(instruction, reg, size,
            CDISASM_OPERAND_ACCESS_WRITE);
    }
    operand = append_immediate(instruction, target, 8u);
    if (operand != NULL) {
        operand->address = (uint64_t)displacement;
        operand->flags = CDISASM_OPERAND_FLAG_SIGNED
            | CDISASM_OPERAND_FLAG_PC_RELATIVE
            | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
    }
    cdisasm_arm_requirements_add_legacy(required_capabilities, CDISASM_ARM_CAP_V8);
    return CDISASM_STATUS_OK;
#endif
}

static cdisasm_status decode_a64_add_sub_immediate(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    int is_64 = (word & UINT32_C(0x80000000)) != 0;
    int subtract = (word & UINT32_C(0x40000000)) != 0;
    int set_flags = (word & UINT32_C(0x20000000)) != 0;
    int shift_12 = (word & UINT32_C(0x00400000)) != 0;
    uint64_t immediate = (uint64_t)((word >> 10) & UINT32_C(0xfff));
    unsigned rn = (word >> 5) & 31u;
    unsigned rd = word & 31u;
    int compare_alias = set_flags && rd == 31u;
    cdisasm_arm_operand *operand;
    uint8_t size = is_64 ? 8u : 4u;

    if (shift_12) {
        immediate <<= 12;
    }
    if (compare_alias) {
        instruction->name_id = subtract ? CDISASM_ARM_NAME_CMP
                                        : CDISASM_ARM_NAME_CMN;
    } else if (subtract) {
        instruction->name_id = set_flags ? CDISASM_ARM_NAME_SUBS
                                         : CDISASM_ARM_NAME_SUB;
    } else {
        instruction->name_id = set_flags ? CDISASM_ARM_NAME_ADDS
                                         : CDISASM_ARM_NAME_ADD;
    }
    if (set_flags) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
    }
    if (!compare_alias) {
        append_register(
            instruction,
            a64_reg(rd, is_64, !set_flags),
            size,
            CDISASM_OPERAND_ACCESS_WRITE);
    }
    append_register(
        instruction,
        a64_reg(rn, is_64, 1),
        size,
        CDISASM_OPERAND_ACCESS_READ);
    operand = append_immediate(instruction, immediate, size);
    if (operand != NULL && shift_12) {
        operand->shift_type = CDISASM_ARM_SHIFT_LSL;
        operand->shift_amount = 12;
    }
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8);
    return CDISASM_STATUS_OK;
}

static cdisasm_status decode_a64_move_wide(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    int is_64 = (word & UINT32_C(0x80000000)) != 0;
    unsigned opcode = (word >> 29) & 3u;
    unsigned halfword = (word >> 21) & 3u;
    uint64_t immediate = (uint64_t)((word >> 5) & UINT32_C(0xffff))
        << (halfword * 16u);
    cdisasm_operand_access destination_access;
    cdisasm_arm_operand *operand;

    if (opcode == 1u || (!is_64 && halfword >= 2u)) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
    if (opcode == 0u) {
        instruction->name_id = CDISASM_ARM_NAME_MOVN;
        destination_access = CDISASM_OPERAND_ACCESS_WRITE;
    } else if (opcode == 2u) {
        instruction->name_id = CDISASM_ARM_NAME_MOVZ;
        destination_access = CDISASM_OPERAND_ACCESS_WRITE;
    } else {
        instruction->name_id = CDISASM_ARM_NAME_MOVK;
        destination_access = CDISASM_OPERAND_ACCESS_READ_WRITE;
    }
    append_register(
        instruction,
        a64_reg(word & 31u, is_64, 0),
        is_64 ? 8u : 4u,
        destination_access);
    operand = append_immediate(
        instruction, immediate, is_64 ? 8u : 4u);
    if (operand != NULL && halfword != 0u) {
        operand->shift_type = CDISASM_ARM_SHIFT_LSL;
        operand->shift_amount = (uint8_t)(halfword * 16u);
    }
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8);
    return CDISASM_STATUS_OK;
}

static cdisasm_status decode_a64_logical_register(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    static const cdisasm_arm_name_id names[4] = {
        CDISASM_ARM_NAME_AND, CDISASM_ARM_NAME_ORR,
        CDISASM_ARM_NAME_EOR, CDISASM_ARM_NAME_ANDS
    };
    static const cdisasm_arm_name_id inverted_names[4] = {
        CDISASM_ARM_NAME_BIC, CDISASM_ARM_NAME_ORN,
        CDISASM_ARM_NAME_EON, CDISASM_ARM_NAME_BICS
    };
    static const cdisasm_arm_form_id forms[2][4][2] = {
        {
            { UINT16_C(5654), UINT16_C(5655) },
            { UINT16_C(5656), UINT16_C(5657) },
            { UINT16_C(5658), UINT16_C(5659) },
            { UINT16_C(5660), UINT16_C(5661) }
        }, {
            { UINT16_C(5662), UINT16_C(5663) },
            { UINT16_C(5664), UINT16_C(5665) },
            { UINT16_C(5666), UINT16_C(5667) },
            { UINT16_C(5668), UINT16_C(5669) }
        }
    };
    int is_64 = (word & UINT32_C(0x80000000)) != 0;
    unsigned opcode = (word >> 29) & 3u;
    unsigned invert = (word >> 21) & 1u;
    unsigned shift = (word >> 22) & 3u;
    unsigned rm = (word >> 16) & 31u;
    unsigned amount = (word >> 10) & 63u;
    unsigned rn = (word >> 5) & 31u;
    unsigned rd = word & 31u;
    int move_alias = opcode == 1u && invert == 0u && rn == 31u && shift == 0u
        && amount == 0u;
    int mvn_alias = opcode == 1u && invert != 0u && rn == 31u;
    int test_alias = opcode == 3u && invert == 0u && rd == 31u;
    uint8_t size = is_64 ? 8u : 4u;
    cdisasm_arm_operand *source;

    if (!is_64 && amount >= 32u) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
    instruction->name_id = move_alias ? CDISASM_ARM_NAME_MOV
        : mvn_alias ? CDISASM_ARM_NAME_MVN
        : test_alias ? CDISASM_ARM_NAME_TST
        : invert != 0u ? inverted_names[opcode] : names[opcode];
    instruction->form_id = forms[is_64 != 0][opcode][invert];
    if (opcode == 3u) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
    }
    if (!test_alias) {
        append_register(
            instruction,
            a64_reg(rd, is_64, 0),
            size,
            CDISASM_OPERAND_ACCESS_WRITE);
    }
    if (!move_alias && !mvn_alias) {
        append_register(
            instruction,
            a64_reg(rn, is_64, 0),
            size,
            CDISASM_OPERAND_ACCESS_READ);
    }
    source = append_register(
        instruction,
        a64_reg(rm, is_64, 0),
        size,
        CDISASM_OPERAND_ACCESS_READ);
    if (source != NULL && (shift != 0u || amount != 0u)) {
        source->shift_type = (cdisasm_arm_shift_type)(
            CDISASM_ARM_SHIFT_LSL + shift);
        source->shift_amount = (uint8_t)amount;
    }
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8);
    return CDISASM_STATUS_OK;
}

typedef enum a64_scalar_register_form {
    A64_SCALAR_REGISTER_NONE = 0,
    A64_SCALAR_REGISTER_ADD_SUB_EXTENDED,
    A64_SCALAR_REGISTER_ADD_SUB_POINTER,
    A64_SCALAR_REGISTER_ADD_SUB_SHIFTED,
    A64_SCALAR_REGISTER_ADD_SUB_CARRY,
    A64_SCALAR_REGISTER_CONDITIONAL_SELECT,
    A64_SCALAR_REGISTER_TWO_SOURCE,
    A64_SCALAR_REGISTER_MULTIPLY_ADD
} a64_scalar_register_form;

static a64_scalar_register_form classify_a64_scalar_register(
    uint32_t word)
{
    if ((word & UINT32_C(0xbfe0e000)) == UINT32_C(0x9a002000)) {
        return A64_SCALAR_REGISTER_ADD_SUB_POINTER;
    }
    if ((word & UINT32_C(0x1f200000)) == UINT32_C(0x0b200000)) {
        return A64_SCALAR_REGISTER_ADD_SUB_EXTENDED;
    }
    if ((word & UINT32_C(0x1f200000)) == UINT32_C(0x0b000000)) {
        return A64_SCALAR_REGISTER_ADD_SUB_SHIFTED;
    }
    if ((word & UINT32_C(0x1fe0fc00)) == UINT32_C(0x1a000000)) {
        return A64_SCALAR_REGISTER_ADD_SUB_CARRY;
    }
    if ((word & UINT32_C(0x3fe00800)) == UINT32_C(0x1a800000)) {
        return A64_SCALAR_REGISTER_CONDITIONAL_SELECT;
    }
    if ((word & UINT32_C(0x7fe00000)) == UINT32_C(0x1ac00000)) {
        unsigned opcode = (word >> 10) & 63u;

        if (opcode == 2u || opcode == 3u
            || (opcode >= 8u && opcode <= 11u)) {
            return A64_SCALAR_REGISTER_TWO_SOURCE;
        }
        return A64_SCALAR_REGISTER_NONE;
    }
    if ((word & UINT32_C(0x7fe00000)) == UINT32_C(0x1b000000)) {
        return A64_SCALAR_REGISTER_MULTIPLY_ADD;
    }
    return A64_SCALAR_REGISTER_NONE;
}

static int a64_scalar_register_encoding_is_valid(
    a64_scalar_register_form form,
    uint32_t word)
{
    if (form == A64_SCALAR_REGISTER_ADD_SUB_EXTENDED) {
        return ((word >> 10) & 7u) <= 4u;
    }
    if (form == A64_SCALAR_REGISTER_ADD_SUB_SHIFTED) {
        unsigned shift = (word >> 22) & 3u;
        unsigned amount = (word >> 10) & 63u;
        int is_64 = (word & UINT32_C(0x80000000)) != 0u;

        return shift != 3u && (is_64 || amount < 32u);
    }
    return 1;
}

#if USE_EXTRA_OPCODES
static void decode_a64_add_sub_extended_extra(
    uint32_t word,
    cdisasm_arm_instruction *instruction)
{
    int is_64=(word>>31)&1,subtract=(word>>30)&1,set_flags=(word>>29)&1;unsigned rm=(word>>16)&31,option=(word>>13)&7,amount=(word>>10)&7,rn=(word>>5)&31,rd=word&31;int compare_alias=set_flags&&rd==31;uint8_t size=is_64?8:4;cdisasm_arm_operand*source;
    instruction->form_id=(uint16_t)(5678u+(is_64?4u:0u)+(subtract?2u:0u)+(set_flags?1u:0u));
    if(compare_alias)instruction->name_id=subtract?CDISASM_ARM_NAME_CMP:CDISASM_ARM_NAME_CMN;else if(subtract)instruction->name_id=set_flags?CDISASM_ARM_NAME_SUBS:CDISASM_ARM_NAME_SUB;else instruction->name_id=set_flags?CDISASM_ARM_NAME_ADDS:CDISASM_ARM_NAME_ADD;
    if(set_flags)instruction->instruction_flags|=CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
    if(!compare_alias)append_register(instruction,a64_reg(rd,is_64,!set_flags),size,CDISASM_OPERAND_ACCESS_WRITE);
    append_register(instruction,a64_reg(rn,is_64,1),size,CDISASM_OPERAND_ACCESS_READ);
    source=append_register(instruction,a64_reg(rm,is_64&&(option==3u||option==7u),0),(uint8_t)(is_64&&(option==3u||option==7u)?8:4),CDISASM_OPERAND_ACCESS_READ);
    if(source!=NULL){if(is_64&&option==3u){source->shift_type=CDISASM_ARM_SHIFT_LSL;source->shift_amount=(uint8_t)amount;}else{source->extend_type=(cdisasm_arm_extend_type)(CDISASM_ARM_EXTEND_UXTB+option);source->scale=(uint8_t)amount;}}
}

static void decode_a64_add_sub_pointer_extra(
    uint32_t word,
    cdisasm_arm_instruction *instruction)
{
    int subtract=(word>>30)&1;unsigned rm=(word>>16)&31,amount=(word>>10)&7,rn=(word>>5)&31,rd=word&31;cdisasm_arm_operand*source;
    instruction->name_id=subtract?CDISASM_ARM_NAME_SUBPT:CDISASM_ARM_NAME_ADDPT;
    instruction->form_id=(uint16_t)(subtract?5695:5694);
    append_register(instruction,a64_reg(rd,1,1),8,CDISASM_OPERAND_ACCESS_WRITE);
    append_register(instruction,a64_reg(rn,1,1),8,CDISASM_OPERAND_ACCESS_READ);
    source=append_register(instruction,a64_reg(rm,1,0),8,CDISASM_OPERAND_ACCESS_READ);
    if(source!=NULL&&amount!=0u){source->shift_type=CDISASM_ARM_SHIFT_LSL;source->shift_amount=(uint8_t)amount;}
}

static void decode_a64_add_sub_shifted_extra(
    uint32_t word,
    cdisasm_arm_instruction *instruction)
{
    int is_64 = (word & UINT32_C(0x80000000)) != 0u;
    int subtract = (word & UINT32_C(0x40000000)) != 0u;
    int set_flags = (word & UINT32_C(0x20000000)) != 0u;
    unsigned shift = (word >> 22) & 3u;
    unsigned rm = (word >> 16) & 31u;
    unsigned amount = (word >> 10) & 63u;
    unsigned rn = (word >> 5) & 31u;
    unsigned rd = word & 31u;
    int compare_alias = set_flags && rd == 31u;
    int negate_alias = subtract && rn == 31u && !compare_alias;
    uint8_t size = is_64 ? 8u : 4u;
    cdisasm_arm_operand *source;

    if (compare_alias) {
        instruction->name_id = subtract ? CDISASM_ARM_NAME_CMP
                                        : CDISASM_ARM_NAME_CMN;
    } else if (negate_alias) {
        instruction->name_id = set_flags ? CDISASM_ARM_NAME_NEGS
                                         : CDISASM_ARM_NAME_NEG;
    } else if (subtract) {
        instruction->name_id = set_flags ? CDISASM_ARM_NAME_SUBS
                                         : CDISASM_ARM_NAME_SUB;
    } else {
        instruction->name_id = set_flags ? CDISASM_ARM_NAME_ADDS
                                         : CDISASM_ARM_NAME_ADD;
    }
    if (set_flags) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
    }
    if (!compare_alias) {
        append_register(
            instruction, a64_reg(rd, is_64, 0), size,
            CDISASM_OPERAND_ACCESS_WRITE);
    }
    if (!negate_alias) {
        append_register(
            instruction, a64_reg(rn, is_64, 0), size,
            CDISASM_OPERAND_ACCESS_READ);
    }
    source = append_register(
        instruction, a64_reg(rm, is_64, 0), size,
        CDISASM_OPERAND_ACCESS_READ);
    if (source != NULL && (shift != 0u || amount != 0u)) {
        source->shift_type = (cdisasm_arm_shift_type)(
            CDISASM_ARM_SHIFT_LSL + shift);
        source->shift_amount = (uint8_t)amount;
    }
}

static void decode_a64_add_sub_carry_extra(
    uint32_t word,
    cdisasm_arm_instruction *instruction)
{
    int is_64 = (word & UINT32_C(0x80000000)) != 0u;
    int subtract = (word & UINT32_C(0x40000000)) != 0u;
    int set_flags = (word & UINT32_C(0x20000000)) != 0u;
    unsigned rm = (word >> 16) & 31u;
    unsigned rn = (word >> 5) & 31u;
    unsigned rd = word & 31u;
    int negate_alias = subtract && rn == 31u;
    uint8_t size = is_64 ? 8u : 4u;

    if (negate_alias) {
        instruction->name_id = set_flags ? CDISASM_ARM_NAME_NGCS
                                         : CDISASM_ARM_NAME_NGC;
    } else if (subtract) {
        instruction->name_id = set_flags ? CDISASM_ARM_NAME_SBCS
                                         : CDISASM_ARM_NAME_SBC;
    } else {
        instruction->name_id = set_flags ? CDISASM_ARM_NAME_ADCS
                                         : CDISASM_ARM_NAME_ADC;
    }
    if (set_flags) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
    }
    append_register(
        instruction, a64_reg(rd, is_64, 0), size,
        CDISASM_OPERAND_ACCESS_WRITE);
    if (!negate_alias) {
        append_register(
            instruction, a64_reg(rn, is_64, 0), size,
            CDISASM_OPERAND_ACCESS_READ);
    }
    append_register(
        instruction, a64_reg(rm, is_64, 0), size,
        CDISASM_OPERAND_ACCESS_READ);
}

static void decode_a64_conditional_select_extra(
    uint32_t word,
    cdisasm_arm_instruction *instruction)
{
    static const cdisasm_arm_name_id names[4] = {
        CDISASM_ARM_NAME_CSEL, CDISASM_ARM_NAME_CSINC,
        CDISASM_ARM_NAME_CSINV, CDISASM_ARM_NAME_CSNEG
    };
    int is_64 = (word & UINT32_C(0x80000000)) != 0u;
    unsigned operation = ((word >> 30) & 1u) * 2u
        + ((word >> 10) & 1u);
    unsigned rm = (word >> 16) & 31u;
    unsigned condition = (word >> 12) & 15u;
    unsigned rn = (word >> 5) & 31u;
    unsigned rd = word & 31u;
    int same_source_alias = operation != 0u && rn == rm
        && condition < CDISASM_ARM_CONDITION_AL;
    int zero_source_alias = same_source_alias && rn == 31u;
    int omit_source = zero_source_alias && operation != 3u;
    uint8_t size = is_64 ? 8u : 4u;

    if (zero_source_alias && operation == 1u) {
        instruction->name_id = CDISASM_ARM_NAME_CSET;
    } else if (zero_source_alias && operation == 2u) {
        instruction->name_id = CDISASM_ARM_NAME_CSETM;
    } else if (same_source_alias && operation == 1u) {
        instruction->name_id = CDISASM_ARM_NAME_CINC;
    } else if (same_source_alias && operation == 2u) {
        instruction->name_id = CDISASM_ARM_NAME_CINV;
    } else if (same_source_alias) {
        instruction->name_id = CDISASM_ARM_NAME_CNEG;
    } else {
        instruction->name_id = names[operation];
    }
    append_register(
        instruction, a64_reg(rd, is_64, 0), size,
        CDISASM_OPERAND_ACCESS_WRITE);
    if (!omit_source) {
        append_register(
            instruction, a64_reg(rn, is_64, 0), size,
            CDISASM_OPERAND_ACCESS_READ);
    }
    if (!same_source_alias) {
        append_register(
            instruction, a64_reg(rm, is_64, 0), size,
            CDISASM_OPERAND_ACCESS_READ);
    }
    append_immediate(
        instruction,
        same_source_alias ? (condition ^ 1u) : condition,
        1u);
}

static void decode_a64_two_source_extra(
    uint32_t word,
    cdisasm_arm_instruction *instruction)
{
    unsigned opcode = (word >> 10) & 63u;
    int is_64 = (word & UINT32_C(0x80000000)) != 0u;
    unsigned rm = (word >> 16) & 31u;
    unsigned rn = (word >> 5) & 31u;
    unsigned rd = word & 31u;
    uint8_t size = is_64 ? 8u : 4u;

    switch (opcode) {
        case 2u:
            instruction->name_id = CDISASM_ARM_NAME_UDIV;
            break;
        case 3u:
            instruction->name_id = CDISASM_ARM_NAME_SDIV;
            break;
        case 8u:
            instruction->name_id = CDISASM_ARM_NAME_LSL;
            break;
        case 9u:
            instruction->name_id = CDISASM_ARM_NAME_LSR;
            break;
        case 10u:
            instruction->name_id = CDISASM_ARM_NAME_ASR;
            break;
        default:
            instruction->name_id = CDISASM_ARM_NAME_ROR;
            break;
    }
    append_register(
        instruction, a64_reg(rd, is_64, 0), size,
        CDISASM_OPERAND_ACCESS_WRITE);
    append_register(
        instruction, a64_reg(rn, is_64, 0), size,
        CDISASM_OPERAND_ACCESS_READ);
    append_register(
        instruction, a64_reg(rm, is_64, 0), size,
        CDISASM_OPERAND_ACCESS_READ);
}

static void decode_a64_multiply_add_extra(
    uint32_t word,
    cdisasm_arm_instruction *instruction)
{
    int is_64 = (word & UINT32_C(0x80000000)) != 0u;
    int subtract = (word & UINT32_C(0x00008000)) != 0u;
    unsigned rm = (word >> 16) & 31u;
    unsigned ra = (word >> 10) & 31u;
    unsigned rn = (word >> 5) & 31u;
    unsigned rd = word & 31u;
    int alias = ra == 31u;
    uint8_t size = is_64 ? 8u : 4u;

    instruction->name_id = alias
        ? (subtract ? CDISASM_ARM_NAME_MNEG : CDISASM_ARM_NAME_MUL)
        : (subtract ? CDISASM_ARM_NAME_MSUB : CDISASM_ARM_NAME_MADD);
    append_register(
        instruction, a64_reg(rd, is_64, 0), size,
        CDISASM_OPERAND_ACCESS_WRITE);
    append_register(
        instruction, a64_reg(rn, is_64, 0), size,
        CDISASM_OPERAND_ACCESS_READ);
    append_register(
        instruction, a64_reg(rm, is_64, 0), size,
        CDISASM_OPERAND_ACCESS_READ);
    if (!alias) {
        append_register(
            instruction, a64_reg(ra, is_64, 0), size,
            CDISASM_OPERAND_ACCESS_READ);
    }
}
#endif

static cdisasm_status decode_a64_scalar_register_extra(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities,
    int *recognized)
{
    a64_scalar_register_form form = classify_a64_scalar_register(word);

    *recognized = form != A64_SCALAR_REGISTER_NONE;
    if (!*recognized) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if (!a64_scalar_register_encoding_is_valid(form, word)) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
#if !USE_EXTRA_OPCODES
    (void)instruction;
    (void)required_capabilities;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    switch (form) {
        case A64_SCALAR_REGISTER_ADD_SUB_EXTENDED:
            decode_a64_add_sub_extended_extra(word, instruction);
            break;
        case A64_SCALAR_REGISTER_ADD_SUB_POINTER:
            decode_a64_add_sub_pointer_extra(word, instruction);
            cdisasm_arm_requirements_set_legacy(required_capabilities,
                CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_CPA);
            return CDISASM_STATUS_OK;
        case A64_SCALAR_REGISTER_ADD_SUB_SHIFTED:
            decode_a64_add_sub_shifted_extra(word, instruction);
            break;
        case A64_SCALAR_REGISTER_ADD_SUB_CARRY:
            decode_a64_add_sub_carry_extra(word, instruction);
            break;
        case A64_SCALAR_REGISTER_CONDITIONAL_SELECT:
            decode_a64_conditional_select_extra(word, instruction);
            break;
        case A64_SCALAR_REGISTER_TWO_SOURCE:
            decode_a64_two_source_extra(word, instruction);
            break;
        case A64_SCALAR_REGISTER_MULTIPLY_ADD:
            decode_a64_multiply_add_extra(word, instruction);
            break;
        default:
            return CDISASM_STATUS_INTERNAL_ERROR;
    }
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8);
    return CDISASM_STATUS_OK;
#endif
}

static uint64_t a64_low_bits_mask(unsigned count)
{
    if (count == 64u) {
        return UINT64_MAX;
    }
    return (UINT64_C(1) << count) - UINT64_C(1);
}

static uint64_t a64_rotate_right_width(
    uint64_t value,
    unsigned amount,
    unsigned width)
{
    uint64_t mask = a64_low_bits_mask(width);

    amount &= width - 1u;
    value &= mask;
    if (amount == 0u) {
        return value;
    }
    return ((value >> amount) | (value << (width - amount))) & mask;
}

static int decode_a64_logical_bitmask(
    uint32_t word,
    uint64_t *immediate)
{
    int is_64 = (word & UINT32_C(0x80000000)) != 0u;
    unsigned n = (word >> 22) & 1u;
    unsigned immr = (word >> 16) & 63u;
    unsigned imms = (word >> 10) & 63u;
    unsigned combined;
    unsigned length = 0u;
    unsigned element_size;
    unsigned levels;
    unsigned set_bits;
    uint64_t element;
    uint64_t result = UINT64_C(0);
    unsigned offset;

    if (!is_64 && n != 0u) {
        return 0;
    }
    combined = (n << 6) | ((~imms) & 63u);
    while ((combined >> (length + 1u)) != 0u) {
        ++length;
    }
    if (length < 1u) {
        return 0;
    }
    element_size = 1u << length;
    levels = element_size - 1u;
    set_bits = imms & levels;
    if (set_bits == levels) {
        return 0;
    }
    element = a64_rotate_right_width(
        a64_low_bits_mask(set_bits + 1u), immr & levels, element_size);
    for (offset = 0u; offset < (is_64 ? 64u : 32u);
         offset += element_size) {
        result |= element << offset;
    }
    *immediate = result;
    return 1;
}

#if USE_EXTRA_OPCODES
static int a64_move_wide_preferred(uint64_t value, unsigned width)
{
    uint64_t width_mask = a64_low_bits_mask(width);
    unsigned shift;

    value &= width_mask;
    for (shift = 0u; shift < width; shift += 16u) {
        uint64_t chunk_mask = UINT64_C(0xffff) << shift;
        uint64_t outside_mask = width_mask ^ chunk_mask;

        if ((value & outside_mask) == 0u
            || (value | chunk_mask) == width_mask) {
            return 1;
        }
    }
    return 0;
}
#endif

static cdisasm_status decode_a64_logical_immediate_extra(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities,
    int *recognized)
{
    uint64_t immediate;

    *recognized = (word & UINT32_C(0x1f800000))
        == UINT32_C(0x12000000);
    if (!*recognized) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if (!decode_a64_logical_bitmask(word, &immediate)) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
#if !USE_EXTRA_OPCODES
    (void)instruction;
    (void)required_capabilities;
    (void)immediate;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    static const cdisasm_arm_name_id names[4] = {
        CDISASM_ARM_NAME_AND, CDISASM_ARM_NAME_ORR,
        CDISASM_ARM_NAME_EOR, CDISASM_ARM_NAME_ANDS
    };
    int is_64 = (word & UINT32_C(0x80000000)) != 0u;
    unsigned opcode = (word >> 29) & 3u;
    unsigned rn = (word >> 5) & 31u;
    unsigned rd = word & 31u;
    unsigned width = is_64 ? 64u : 32u;
    uint8_t size = is_64 ? 8u : 4u;
    int test_alias = opcode == 3u && rd == 31u;
    int move_alias = opcode == 1u && rn == 31u
        && !a64_move_wide_preferred(immediate, width);
    cdisasm_arm_operand *immediate_operand;

    instruction->name_id = test_alias ? CDISASM_ARM_NAME_TST
        : (move_alias ? CDISASM_ARM_NAME_MOV : names[opcode]);
    if (opcode == 3u) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
    }
    if (!test_alias) {
        append_register(
            instruction,
            a64_reg(rd, is_64, opcode != 3u),
            size,
            CDISASM_OPERAND_ACCESS_WRITE);
    }
    if (!move_alias) {
        append_register(
            instruction,
            a64_reg(rn, is_64, 0),
            size,
            CDISASM_OPERAND_ACCESS_READ);
    }
    if (move_alias && (immediate & (UINT64_C(1) << (width - 1u))) != 0u) {
        if (!is_64) {
            immediate |= UINT64_C(0xffffffff00000000);
        }
        immediate_operand = append_immediate(instruction, immediate, size);
        if (immediate_operand != NULL) {
            immediate_operand->flags |= CDISASM_OPERAND_FLAG_SIGNED;
        }
    } else {
        append_immediate(instruction, immediate, size);
    }
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8);
    return CDISASM_STATUS_OK;
#endif
}

static cdisasm_arm_name_id load_store_name(
    int load,
    int unscaled,
    unsigned size_code)
{
    if (unscaled) {
        if (size_code == 0u) {
            return load ? CDISASM_ARM_NAME_LDURB : CDISASM_ARM_NAME_STURB;
        }
        if (size_code == 1u) {
            return load ? CDISASM_ARM_NAME_LDURH : CDISASM_ARM_NAME_STURH;
        }
        return load ? CDISASM_ARM_NAME_LDUR : CDISASM_ARM_NAME_STUR;
    }
    if (size_code == 0u) {
        return load ? CDISASM_ARM_NAME_LDRB : CDISASM_ARM_NAME_STRB;
    }
    if (size_code == 1u) {
        return load ? CDISASM_ARM_NAME_LDRH : CDISASM_ARM_NAME_STRH;
    }
    return load ? CDISASM_ARM_NAME_LDR : CDISASM_ARM_NAME_STR;
}

static void append_a64_atomic_memory(
    cdisasm_arm_instruction *instruction,
    unsigned rn,
    uint8_t data_size,
    cdisasm_operand_access access)
{
    cdisasm_arm_operand *memory = append_operand(instruction);

    if (memory != NULL) {
        memory->type = CDISASM_OPERAND_MEMORY;
        memory->size = data_size;
        memory->base_reg = a64_reg(rn, 1, 1);
        memory->access = access;
    }
}

static cdisasm_status decode_a64_atomic_memory(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    static const cdisasm_arm_name_id ordered_load_names[4] = {
        CDISASM_ARM_NAME_LDARB,
        CDISASM_ARM_NAME_LDARH,
        CDISASM_ARM_NAME_LDAR,
        CDISASM_ARM_NAME_LDAR
    };
    static const cdisasm_arm_name_id ordered_store_names[4] = {
        CDISASM_ARM_NAME_STLRB,
        CDISASM_ARM_NAME_STLRH,
        CDISASM_ARM_NAME_STLR,
        CDISASM_ARM_NAME_STLR
    };
    static const cdisasm_arm_name_id exclusive_load_names[4] = {
        CDISASM_ARM_NAME_LDXRB,
        CDISASM_ARM_NAME_LDXRH,
        CDISASM_ARM_NAME_LDXR,
        CDISASM_ARM_NAME_LDXR
    };
    static const cdisasm_arm_name_id acquire_load_names[4] = {
        CDISASM_ARM_NAME_LDAXRB,
        CDISASM_ARM_NAME_LDAXRH,
        CDISASM_ARM_NAME_LDAXR,
        CDISASM_ARM_NAME_LDAXR
    };
    static const cdisasm_arm_name_id exclusive_store_names[4] = {
        CDISASM_ARM_NAME_STXRB,
        CDISASM_ARM_NAME_STXRH,
        CDISASM_ARM_NAME_STXR,
        CDISASM_ARM_NAME_STXR
    };
    static const cdisasm_arm_name_id release_store_names[4] = {
        CDISASM_ARM_NAME_STLXRB,
        CDISASM_ARM_NAME_STLXRH,
        CDISASM_ARM_NAME_STLXR,
        CDISASM_ARM_NAME_STLXR
    };
    unsigned size_code = word >> 30;
    unsigned ordered = (word >> 23) & 1u;
    unsigned load = (word >> 22) & 1u;
    unsigned pair = (word >> 21) & 1u;
    unsigned status_reg = (word >> 16) & 31u;
    unsigned ordered_bit = (word >> 15) & 1u;
    unsigned second_reg = (word >> 10) & 31u;
    unsigned base_reg = (word >> 5) & 31u;
    unsigned transfer_reg = word & 31u;
    unsigned unprivileged = (word >> 24) & 1u;
    int is_64 = size_code == 3u;
    uint8_t data_size = (uint8_t)(1u << size_code);
    uint32_t flags = CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC;

    if (unprivileged != 0u) {
        if (ordered != 0u) {
            if (pair != 0u || second_reg != 31u
                || (size_code != 1u && size_code != 3u)
                || (size_code == 1u
                    && (((status_reg | transfer_reg) & 1u) != 0u))) {
                return CDISASM_STATUS_INVALID_INSTRUCTION;
            }
#if !USE_EXTRA_OPCODES
            return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
            unsigned ordering = load | (ordered_bit << 1);
            static const cdisasm_arm_name_id scalar_names[4] = {
                CDISASM_ARM_NAME_CAST, CDISASM_ARM_NAME_CASAT,
                CDISASM_ARM_NAME_CASLT, CDISASM_ARM_NAME_CASALT
            };
            static const cdisasm_arm_name_id pair_names[4] = {
                CDISASM_ARM_NAME_CASPT, CDISASM_ARM_NAME_CASPAT,
                CDISASM_ARM_NAME_CASPLT, CDISASM_ARM_NAME_CASPALT
            };
            static const cdisasm_arm_form_id scalar_forms[4] = {
                4781, 4783, 4782, 4784
            };
            static const cdisasm_arm_form_id pair_forms[4] = {
                4777, 4779, 4778, 4780
            };

            data_size = 8u;
            is_64 = 1;
            instruction->name_id = size_code == 3u
                ? scalar_names[ordering] : pair_names[ordering];
            instruction->form_id = size_code == 3u
                ? scalar_forms[ordering] : pair_forms[ordering];
            if (load != 0u) {
                flags |= CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE;
            }
            if (ordered_bit != 0u) {
                flags |= CDISASM_ARM_INSTRUCTION_FLAG_RELEASE;
            }
            instruction->instruction_flags |= flags;
            if (size_code == 3u) {
                append_register(instruction, a64_reg(status_reg, 1, 0),
                    data_size, CDISASM_OPERAND_ACCESS_READ_WRITE);
                append_register(instruction, a64_reg(transfer_reg, 1, 0),
                    data_size, CDISASM_OPERAND_ACCESS_READ);
            } else {
                append_register_pair(instruction,
                    a64_reg(status_reg, 1, 0),
                    a64_reg(status_reg + 1u, 1, 0), data_size,
                    CDISASM_OPERAND_ACCESS_READ_WRITE);
                append_register_pair(instruction,
                    a64_reg(transfer_reg, 1, 0),
                    a64_reg(transfer_reg + 1u, 1, 0), data_size,
                    CDISASM_OPERAND_ACCESS_READ);
            }
            append_a64_atomic_memory(instruction, base_reg, data_size,
                CDISASM_OPERAND_ACCESS_READ_WRITE);
            cdisasm_arm_requirements_set_legacy(
                required_capabilities, CDISASM_ARM_CAP_V8);
            (void)cdisasm_arm_requirements_add_feature(
                required_capabilities, ARM_FEATURE_LSUI);
            return CDISASM_STATUS_OK;
#endif
        }
        if (size_code < 2u || pair != 0u || second_reg != 31u
            || (load != 0u && status_reg != 31u)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        static const cdisasm_arm_name_id store_names[2] = {
            CDISASM_ARM_NAME_STTXR, CDISASM_ARM_NAME_STLTXR
        };
        static const cdisasm_arm_name_id load_names[2] = {
            CDISASM_ARM_NAME_LDTXR, CDISASM_ARM_NAME_LDATXR
        };

        instruction->name_id = load != 0u
            ? load_names[ordered_bit] : store_names[ordered_bit];
        instruction->form_id = (cdisasm_arm_form_id)(UINT16_C(4811)
            + (size_code - 2u) * 4u + load * 2u + ordered_bit);
        flags |= CDISASM_ARM_INSTRUCTION_FLAG_EXCLUSIVE;
        if (ordered_bit != 0u) {
            flags |= load != 0u ? CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
                                : CDISASM_ARM_INSTRUCTION_FLAG_RELEASE;
        }
        instruction->instruction_flags |= flags;
        if (load == 0u) {
            append_register(instruction, a64_reg(status_reg, 0, 0), 4u,
                CDISASM_OPERAND_ACCESS_WRITE);
            if (status_reg != 31u
                && (status_reg == transfer_reg || status_reg == base_reg)) {
                mark_unpredictable(instruction);
            }
        }
        append_register(instruction, a64_reg(transfer_reg, is_64, 0),
            data_size, load != 0u ? CDISASM_OPERAND_ACCESS_WRITE
                                  : CDISASM_OPERAND_ACCESS_READ);
        append_a64_atomic_memory(instruction, base_reg, data_size,
            load != 0u ? CDISASM_OPERAND_ACCESS_READ
                       : CDISASM_OPERAND_ACCESS_WRITE);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8);
        (void)cdisasm_arm_requirements_add_feature(
            required_capabilities, ARM_FEATURE_LSUI);
        return CDISASM_STATUS_OK;
#endif
    }

    if (ordered != 0u) {
        if (pair != 0u) {
#if USE_EXTRA_OPCODES
            unsigned ordering = load | (ordered_bit << 1);
#endif

            if (second_reg != 31u) {
                return CDISASM_STATUS_INVALID_INSTRUCTION;
            }
#if !USE_EXTRA_OPCODES
            return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
            instruction->name_id = (cdisasm_arm_name_id)(
                CDISASM_ARM_NAME_CASB + ordering * 3u
                + (size_code < 2u ? size_code : 2u));
            if (load != 0u) {
                flags |= CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE;
            }
            if (ordered_bit != 0u) {
                flags |= CDISASM_ARM_INSTRUCTION_FLAG_RELEASE;
            }
            instruction->instruction_flags |= flags;
            append_register(
                instruction,
                a64_reg(status_reg, is_64, 0),
                data_size,
                CDISASM_OPERAND_ACCESS_READ_WRITE);
            append_register(
                instruction,
                a64_reg(transfer_reg, is_64, 0),
                data_size,
                CDISASM_OPERAND_ACCESS_READ);
            append_a64_atomic_memory(
                instruction,
                base_reg,
                data_size,
                CDISASM_OPERAND_ACCESS_READ_WRITE);
            cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8
                | CDISASM_ARM_CAP_LSE);
            return CDISASM_STATUS_OK;
#endif
        }
        if (ordered_bit == 0u) {
            if (status_reg != 31u || second_reg != 31u) {
                return CDISASM_STATUS_INVALID_INSTRUCTION;
            }
#if !USE_EXTRA_OPCODES
            return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
            instruction->name_id = load != 0u
                ? (cdisasm_arm_name_id)(CDISASM_ARM_NAME_LDLARB
                    + (size_code < 2u ? size_code : 2u))
                : (cdisasm_arm_name_id)(CDISASM_ARM_NAME_STLLRB
                    + (size_code < 2u ? size_code : 2u));
            flags |= load != 0u ? CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
                                : CDISASM_ARM_INSTRUCTION_FLAG_RELEASE;
            instruction->instruction_flags |= flags;
            append_register(
                instruction,
                a64_reg(transfer_reg, is_64, 0),
                data_size,
                load != 0u ? CDISASM_OPERAND_ACCESS_WRITE
                           : CDISASM_OPERAND_ACCESS_READ);
            append_a64_atomic_memory(
                instruction,
                base_reg,
                data_size,
                load != 0u ? CDISASM_OPERAND_ACCESS_READ
                           : CDISASM_OPERAND_ACCESS_WRITE);
            cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8
                | CDISASM_ARM_CAP_LOR);
            return CDISASM_STATUS_OK;
#endif
        }
        if (status_reg != 31u || second_reg != 31u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = load != 0u
            ? ordered_load_names[size_code]
            : ordered_store_names[size_code];
        flags |= load != 0u ? CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
                            : CDISASM_ARM_INSTRUCTION_FLAG_RELEASE;
        instruction->instruction_flags |= flags;
        append_register(
            instruction,
            a64_reg(transfer_reg, is_64, 0),
            data_size,
            load != 0u ? CDISASM_OPERAND_ACCESS_WRITE
                       : CDISASM_OPERAND_ACCESS_READ);
        append_a64_atomic_memory(
            instruction,
            base_reg,
            data_size,
            load != 0u ? CDISASM_OPERAND_ACCESS_READ
                       : CDISASM_OPERAND_ACCESS_WRITE);
        cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8);
        return CDISASM_STATUS_OK;
    }

    if (pair != 0u && size_code < 2u) {
#if USE_EXTRA_OPCODES
        unsigned ordering = load | (ordered_bit << 1);
#endif

        if (second_reg != 31u
            || (status_reg & 1u) != 0u
            || (transfer_reg & 1u) != 0u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        data_size = size_code == 0u ? 4u : 8u;
        is_64 = size_code != 0u;
        instruction->name_id = (cdisasm_arm_name_id)(
            CDISASM_ARM_NAME_CASP + ordering);
        if (load != 0u) {
            flags |= CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE;
        }
        if (ordered_bit != 0u) {
            flags |= CDISASM_ARM_INSTRUCTION_FLAG_RELEASE;
        }
        instruction->instruction_flags |= flags;
        append_register_pair(
            instruction,
            a64_reg(status_reg, is_64, 0),
            a64_reg(status_reg + 1u, is_64, 0),
            data_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE);
        append_register_pair(
            instruction,
            a64_reg(transfer_reg, is_64, 0),
            a64_reg(transfer_reg + 1u, is_64, 0),
            data_size,
            CDISASM_OPERAND_ACCESS_READ);
        append_a64_atomic_memory(
            instruction,
            base_reg,
            data_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE);
        cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8
            | CDISASM_ARM_CAP_LSE);
        return CDISASM_STATUS_OK;
#endif
    }

    flags |= CDISASM_ARM_INSTRUCTION_FLAG_EXCLUSIVE;
    if (load != 0u && status_reg != 31u) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
    if (pair == 0u && second_reg != 31u) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }

    if (pair != 0u) {
        instruction->name_id = load != 0u
            ? (ordered_bit != 0u ? CDISASM_ARM_NAME_LDAXP
                                 : CDISASM_ARM_NAME_LDXP)
            : (ordered_bit != 0u ? CDISASM_ARM_NAME_STLXP
                                 : CDISASM_ARM_NAME_STXP);
    } else if (load != 0u) {
        instruction->name_id = ordered_bit != 0u
            ? acquire_load_names[size_code]
            : exclusive_load_names[size_code];
    } else {
        instruction->name_id = ordered_bit != 0u
            ? release_store_names[size_code]
            : exclusive_store_names[size_code];
    }
    if (ordered_bit != 0u) {
        flags |= load != 0u ? CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE
                            : CDISASM_ARM_INSTRUCTION_FLAG_RELEASE;
    }
    instruction->instruction_flags |= flags;

    if (load == 0u) {
        append_register(
            instruction,
            a64_reg(status_reg, 0, 0),
            4,
            CDISASM_OPERAND_ACCESS_WRITE);
        if (status_reg != 31u
            && (status_reg == transfer_reg || status_reg == base_reg
                || (pair != 0u && status_reg == second_reg))) {
            mark_unpredictable(instruction);
        }
    }
    append_register(
        instruction,
        a64_reg(transfer_reg, is_64, 0),
        data_size,
        load != 0u ? CDISASM_OPERAND_ACCESS_WRITE
                   : CDISASM_OPERAND_ACCESS_READ);
    if (pair != 0u) {
        append_register(
            instruction,
            a64_reg(second_reg, is_64, 0),
            data_size,
            load != 0u ? CDISASM_OPERAND_ACCESS_WRITE
                       : CDISASM_OPERAND_ACCESS_READ);
        if (load != 0u && transfer_reg == second_reg) {
            mark_unpredictable(instruction);
        }
    }
    append_a64_atomic_memory(
        instruction,
        base_reg,
        data_size,
        load != 0u ? CDISASM_OPERAND_ACCESS_READ
                   : CDISASM_OPERAND_ACCESS_WRITE);
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8);
    return CDISASM_STATUS_OK;
}

static cdisasm_status decode_a64_lse_rmw(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    unsigned acquire = (word >> 23) & 1u;
    unsigned release = (word >> 22) & 1u;
    unsigned source_reg = (word >> 16) & 31u;
    unsigned opcode = (word >> 12) & 15u;
    unsigned size_code = word >> 30;
    int unprivileged = ((word >> 29) & 1u) == 0u;
#if !USE_EXTRA_OPCODES
    (void)instruction;
    (void)required_capabilities;

    if (unprivileged && size_code > 1u) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
    if (opcode == 12u
        && (acquire == 0u || release != 0u || source_reg != 31u)) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    static const cdisasm_arm_name_id operation_names[9] = {
        CDISASM_ARM_NAME_LDADDB,
        CDISASM_ARM_NAME_LDCLRB,
        CDISASM_ARM_NAME_LDEORB,
        CDISASM_ARM_NAME_LDSETB,
        CDISASM_ARM_NAME_LDSMAXB,
        CDISASM_ARM_NAME_LDSMINB,
        CDISASM_ARM_NAME_LDUMAXB,
        CDISASM_ARM_NAME_LDUMINB,
        CDISASM_ARM_NAME_SWPB
    };
    unsigned base_reg = (word >> 5) & 31u;
    unsigned result_reg = word & 31u;
    unsigned ordering = acquire | (release << 1);
    int is_64 = size_code == 3u;
    uint8_t data_size = (uint8_t)(1u << size_code);
    uint32_t flags = CDISASM_ARM_INSTRUCTION_FLAG_ATOMIC;

    if (unprivileged) {
        static const cdisasm_arm_name_id names[4][4] = {
            {CDISASM_ARM_NAME_LDTADD, CDISASM_ARM_NAME_LDTADDL,
             CDISASM_ARM_NAME_LDTADDA, CDISASM_ARM_NAME_LDTADDAL},
            {CDISASM_ARM_NAME_LDTCLR, CDISASM_ARM_NAME_LDTCLRL,
             CDISASM_ARM_NAME_LDTCLRA, CDISASM_ARM_NAME_LDTCLRAL},
            {CDISASM_ARM_NAME_LDTSET, CDISASM_ARM_NAME_LDTSETL,
             CDISASM_ARM_NAME_LDTSETA, CDISASM_ARM_NAME_LDTSETAL},
            {CDISASM_ARM_NAME_SWPT, CDISASM_ARM_NAME_SWPTL,
             CDISASM_ARM_NAME_SWPTA, CDISASM_ARM_NAME_SWPTAL}
        };
        unsigned operation_index;
        unsigned form_ordering = release | (acquire << 1);

        if (size_code > 1u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        is_64 = size_code != 0u;
        data_size = (uint8_t)(4u << size_code);
        if (opcode == 0u) operation_index = 0u;
        else if (opcode == 1u) operation_index = 1u;
        else if (opcode == 3u) operation_index = 2u;
        else if (opcode == 8u) operation_index = 3u;
        else return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
        instruction->name_id = names[operation_index][form_ordering];
        instruction->form_id = (cdisasm_arm_form_id)(UINT16_C(5044)
            + size_code * 16u + form_ordering * 4u
            + operation_index);
        if (acquire != 0u && result_reg != 31u) {
            flags |= CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE;
        }
        if (release != 0u) {
            flags |= CDISASM_ARM_INSTRUCTION_FLAG_RELEASE;
        }
        instruction->instruction_flags |= flags;
        append_register(instruction, a64_reg(source_reg, is_64, 0),
            data_size, CDISASM_OPERAND_ACCESS_READ);
        append_register(instruction, a64_reg(result_reg, is_64, 0),
            data_size, CDISASM_OPERAND_ACCESS_WRITE);
        append_a64_atomic_memory(instruction, base_reg, data_size,
            CDISASM_OPERAND_ACCESS_READ_WRITE);
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8);
        (void)cdisasm_arm_requirements_add_feature(
            required_capabilities, ARM_FEATURE_LSUI);
        return CDISASM_STATUS_OK;
    }

    if (opcode == 12u) {
        if (acquire == 0u || release != 0u || source_reg != 31u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = (cdisasm_arm_name_id)(
            CDISASM_ARM_NAME_LDAPRB
            + (size_code < 2u ? size_code : 2u));
        instruction->instruction_flags |= flags
            | CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE;
        append_register(
            instruction,
            a64_reg(result_reg, is_64, 0),
            data_size,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_a64_atomic_memory(
            instruction,
            base_reg,
            data_size,
            CDISASM_OPERAND_ACCESS_READ);
        cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8
            | CDISASM_ARM_CAP_RCPC);
        return CDISASM_STATUS_OK;
    }

    if (opcode > 8u) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }

    instruction->name_id = (cdisasm_arm_name_id)(
        operation_names[opcode] + ordering * 3u
        + (size_code < 2u ? size_code : 2u));
    if (acquire != 0u && result_reg != 31u) {
        flags |= CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE;
    }
    if (release != 0u) {
        flags |= CDISASM_ARM_INSTRUCTION_FLAG_RELEASE;
    }
    instruction->instruction_flags |= flags;
    append_register(
        instruction,
        a64_reg(source_reg, is_64, 0),
        data_size,
        CDISASM_OPERAND_ACCESS_READ);
    append_register(
        instruction,
        a64_reg(result_reg, is_64, 0),
        data_size,
        CDISASM_OPERAND_ACCESS_WRITE);
    append_a64_atomic_memory(
        instruction,
        base_reg,
        data_size,
        CDISASM_OPERAND_ACCESS_READ_WRITE);
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_LSE);
    return CDISASM_STATUS_OK;
#endif
}

static cdisasm_status decode_a64_single_memory(
    uint32_t word,
    int unscaled,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    unsigned size_code = word >> 30;
    unsigned opcode = (word >> 22) & 3u;
    int load;
    unsigned rt = word & 31u;
    unsigned rn = (word >> 5) & 31u;
    uint8_t data_size = (uint8_t)(1u << size_code);
    int64_t displacement;
    cdisasm_arm_operand *memory;

    if (opcode == 2u && size_code == 3u && !unscaled) {
#if USE_EXTRA_OPCODES
        instruction->name_id = CDISASM_ARM_NAME_PRFM;
        instruction->form_id = UINT16_C(5573);
        append_immediate(instruction, rt, 1u);
        displacement = (int64_t)(((word >> 10) & UINT32_C(0xfff)) << 3);
        memory = append_operand(instruction);
        if (memory != NULL) {
            memory->type = CDISASM_OPERAND_MEMORY;
            memory->size = 1u;
            memory->base_reg = a64_reg(rn, 1, 1);
            memory->imm = (uint64_t)displacement;
            memory->access = CDISASM_OPERAND_ACCESS_READ;
            if (displacement != 0) memory->flags |= CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;
        }
        cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8);
        return CDISASM_STATUS_OK;
#else
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
    }
    if (opcode > 1u) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    load = opcode != 0u;
    if (unscaled) {
        displacement = sign_extend((word >> 12) & UINT32_C(0x1ff), 9);
    } else {
        displacement = (int64_t)(((word >> 10) & UINT32_C(0xfff))
            << size_code);
    }
    instruction->name_id = load_store_name(load, unscaled, size_code);
    append_register(
        instruction,
        a64_reg(rt, size_code == 3u, 0),
        data_size,
        load ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ);
    memory = append_operand(instruction);
    if (memory != NULL) {
        memory->type = CDISASM_OPERAND_MEMORY;
        memory->size = data_size;
        memory->base_reg = a64_reg(rn, 1, 1);
        memory->imm = (uint64_t)displacement;
        memory->access = load ? CDISASM_OPERAND_ACCESS_READ
                              : CDISASM_OPERAND_ACCESS_WRITE;
        if (displacement != 0) {
            memory->flags |= CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;
            if (displacement < 0) {
                memory->flags |= CDISASM_OPERAND_FLAG_SIGNED;
            }
        }
    }
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8);
    return CDISASM_STATUS_OK;
}

static cdisasm_status decode_a64_pair_memory(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    unsigned opcode = word >> 30;
    unsigned address_mode = (word >> 23) & 3u;
    int load = (word & UINT32_C(0x00400000)) != 0;
    unsigned rt = word & 31u;
    unsigned rn = (word >> 5) & 31u;
    unsigned rt2 = (word >> 10) & 31u;
    int is_64;
    uint8_t data_size;
    int64_t displacement;
    cdisasm_arm_operand *memory;

    if (opcode != 0u && opcode != 2u && opcode != 3u) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if (opcode == 3u) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        static const uint16_t forms[4][2] = {
            {5086, 5087}, {5102, 5103}, {5118, 5119}, {5134, 5135}
        };
        unsigned mode_index = address_mode == 0u ? 0u
            : address_mode == 1u ? 1u
            : address_mode == 2u ? 2u : 3u;

        is_64 = 1;
        data_size = 8u;
        displacement = sign_extend(
            (word >> 15) & UINT32_C(0x7f), 7) * INT64_C(8);
        instruction->name_id = address_mode == 0u
            ? (load ? CDISASM_ARM_NAME_LDTNP : CDISASM_ARM_NAME_STTNP)
            : (load ? CDISASM_ARM_NAME_LDTP : CDISASM_ARM_NAME_STTP);
        instruction->form_id = forms[mode_index][load];
        if ((load && rt == rt2)
            || (address_mode != 0u && address_mode != 2u
                && rn != 31u && (rn == rt || rn == rt2))) {
            mark_unpredictable(instruction);
        }
        append_register(instruction, a64_reg(rt, 1, 0), data_size,
            load ? CDISASM_OPERAND_ACCESS_WRITE
                 : CDISASM_OPERAND_ACCESS_READ);
        append_register(instruction, a64_reg(rt2, 1, 0), data_size,
            load ? CDISASM_OPERAND_ACCESS_WRITE
                 : CDISASM_OPERAND_ACCESS_READ);
        memory = append_operand(instruction);
        if (memory != NULL) {
            memory->type = CDISASM_OPERAND_MEMORY;
            memory->size = 2u * data_size;
            memory->base_reg = a64_reg(rn, 1, 1);
            memory->imm = (uint64_t)displacement;
            memory->access = load ? CDISASM_OPERAND_ACCESS_READ
                                  : CDISASM_OPERAND_ACCESS_WRITE;
            if (displacement != 0) {
                memory->flags |= CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;
                if (displacement < 0) {
                    memory->flags |= CDISASM_OPERAND_FLAG_SIGNED;
                }
            }
        }
        if (address_mode == 1u) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
        } else if (address_mode == 3u) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8);
        (void)cdisasm_arm_requirements_add_feature(
            required_capabilities, ARM_FEATURE_LSUI);
        return CDISASM_STATUS_OK;
#endif
    }
    is_64 = opcode == 2u;
    data_size = is_64 ? 8u : 4u;
    displacement = sign_extend((word >> 15) & UINT32_C(0x7f), 7)
        * (int64_t)data_size;
    if (address_mode == 0u) {
#if USE_EXTRA_OPCODES
        instruction->name_id = load ? CDISASM_ARM_NAME_LDNP
                                    : CDISASM_ARM_NAME_STNP;
        instruction->form_id = is_64
            ? (load ? UINT16_C(5083) : UINT16_C(5082))
            : (load ? UINT16_C(5077) : UINT16_C(5076));
        if (load && rt == rt2) {
            mark_unpredictable(instruction);
        }
        append_register(
            instruction, a64_reg(rt, is_64, 0), data_size,
            load ? CDISASM_OPERAND_ACCESS_WRITE
                 : CDISASM_OPERAND_ACCESS_READ);
        append_register(
            instruction, a64_reg(rt2, is_64, 0), data_size,
            load ? CDISASM_OPERAND_ACCESS_WRITE
                 : CDISASM_OPERAND_ACCESS_READ);
        memory = append_operand(instruction);
        if (memory != NULL) {
            memory->type = CDISASM_OPERAND_MEMORY;
            memory->size = (uint8_t)(2u * data_size);
            memory->base_reg = a64_reg(rn, 1, 1);
            memory->imm = (uint64_t)displacement;
            memory->access = load ? CDISASM_OPERAND_ACCESS_READ
                                  : CDISASM_OPERAND_ACCESS_WRITE;
            if (displacement != 0) {
                memory->flags |= CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;
                if (displacement < 0) {
                    memory->flags |= CDISASM_OPERAND_FLAG_SIGNED;
                }
            }
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8);
        return CDISASM_STATUS_OK;
#else
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
    }
    instruction->name_id = load ? CDISASM_ARM_NAME_LDP
                                : CDISASM_ARM_NAME_STP;
    if ((load && rt == rt2)
        || (address_mode != 2u && rn != 31u
            && (rn == rt || rn == rt2))) {
        mark_unpredictable(instruction);
    }
    append_register(
        instruction,
        a64_reg(rt, is_64, 0),
        data_size,
        load ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ);
    append_register(
        instruction,
        a64_reg(rt2, is_64, 0),
        data_size,
        load ? CDISASM_OPERAND_ACCESS_WRITE : CDISASM_OPERAND_ACCESS_READ);
    memory = append_operand(instruction);
    if (memory != NULL) {
        memory->type = CDISASM_OPERAND_MEMORY;
        memory->size = data_size;
        memory->base_reg = a64_reg(rn, 1, 1);
        memory->imm = (uint64_t)displacement;
        memory->access = load ? CDISASM_OPERAND_ACCESS_READ
                              : CDISASM_OPERAND_ACCESS_WRITE;
        if (displacement != 0) {
            memory->flags |= CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;
            if (displacement < 0) {
                memory->flags |= CDISASM_OPERAND_FLAG_SIGNED;
            }
        }
    }
    if (address_mode == 1u) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
    } else if (address_mode == 3u) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
            | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
    }
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8);
    return CDISASM_STATUS_OK;
}

static cdisasm_status decode_a64_fp_pair_memory(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
#if !USE_EXTRA_OPCODES
    (void)word;(void)instruction;(void)required_capabilities;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    unsigned size_code=word>>30,address_mode=(word>>23)&3u,load=(word>>22)&1u,rt=word&31u,rn=(word>>5)&31u,rt2=(word>>10)&31u;uint8_t size;int64_t displacement;cdisasm_arm_reg_id base;cdisasm_arm_operand *memory;
    static const uint16_t forms[3][3][2]={{{5092,5093},{5108,5109},{5124,5125}},{{5096,5097},{5112,5113},{5128,5129}},{{5100,5101},{5116,5117},{5132,5133}}};
    static const uint16_t non_temporal_forms[3][2] = {
        {5078, 5079}, {5080, 5081}, {5084, 5085}
    };
    unsigned mode_index;
    if (size_code == 3u) {
        static const uint16_t forms[4][2] = {
            {5088, 5089}, {5104, 5105}, {5120, 5121}, {5136, 5137}
        };
        unsigned lsui_mode = address_mode == 0u ? 0u
            : address_mode == 1u ? 1u
            : address_mode == 2u ? 2u : 3u;

        size = 16u;
        instruction->name_id = address_mode == 0u
            ? (load ? CDISASM_ARM_NAME_LDTNP : CDISASM_ARM_NAME_STTNP)
            : (load ? CDISASM_ARM_NAME_LDTP : CDISASM_ARM_NAME_STTP);
        instruction->form_id = forms[lsui_mode][load];
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        if ((load && rt == rt2)
            || (address_mode != 0u && address_mode != 2u
                && rn != 31u && (rn == rt || rn == rt2))) {
            mark_unpredictable(instruction);
        }
        append_register(instruction,
            (cdisasm_arm_reg_id)((rt < 16u ? CDISASM_ARM_REG_Q0
                : CDISASM_ARM_REG_Q16 - 16u) + rt), size,
            load ? CDISASM_OPERAND_ACCESS_WRITE
                 : CDISASM_OPERAND_ACCESS_READ);
        append_register(instruction,
            (cdisasm_arm_reg_id)((rt2 < 16u ? CDISASM_ARM_REG_Q0
                : CDISASM_ARM_REG_Q16 - 16u) + rt2), size,
            load ? CDISASM_OPERAND_ACCESS_WRITE
                 : CDISASM_OPERAND_ACCESS_READ);
        displacement = sign_extend(
            (word >> 15) & UINT32_C(0x7f), 7) * INT64_C(16);
        memory = append_operand(instruction);
        if (memory != NULL) {
            memory->type = CDISASM_OPERAND_MEMORY;
            memory->size = 2u * size;
            memory->base_reg = a64_reg(rn, 1, 1);
            memory->imm = (uint64_t)displacement;
            memory->access = load ? CDISASM_OPERAND_ACCESS_READ
                                  : CDISASM_OPERAND_ACCESS_WRITE;
            if (displacement != 0) {
                memory->flags |= CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;
                if (displacement < 0) {
                    memory->flags |= CDISASM_OPERAND_FLAG_SIGNED;
                }
            }
        }
        if (address_mode == 1u) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
        } else if (address_mode == 3u) {
            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
        }
        cdisasm_arm_requirements_set_legacy(required_capabilities,
            CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_VFP);
        (void)cdisasm_arm_requirements_add_feature(
            required_capabilities, ARM_FEATURE_LSUI);
        return CDISASM_STATUS_OK;
    }
    if (size_code > 2u) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    if (address_mode == 0u) {
        size = (uint8_t)(4u << size_code);
        instruction->name_id = load
            ? CDISASM_ARM_NAME_LDNP : CDISASM_ARM_NAME_STNP;
        instruction->form_id = non_temporal_forms[size_code][load];
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        base = (cdisasm_arm_reg_id)((size == 4u ? CDISASM_ARM_REG_S0
            : size == 8u ? CDISASM_ARM_REG_D0
            : rt < 16u ? CDISASM_ARM_REG_Q0
            : CDISASM_ARM_REG_Q16 - 16u) + rt);
        append_register(instruction, base, size,
            load ? CDISASM_OPERAND_ACCESS_WRITE
                 : CDISASM_OPERAND_ACCESS_READ);
        base = (cdisasm_arm_reg_id)((size == 4u ? CDISASM_ARM_REG_S0
            : size == 8u ? CDISASM_ARM_REG_D0
            : rt2 < 16u ? CDISASM_ARM_REG_Q0
            : CDISASM_ARM_REG_Q16 - 16u) + rt2);
        append_register(instruction, base, size,
            load ? CDISASM_OPERAND_ACCESS_WRITE
                 : CDISASM_OPERAND_ACCESS_READ);
        displacement = sign_extend(
            (word >> 15) & UINT32_C(0x7f), 7) * (int64_t)size;
        memory = append_operand(instruction);
        if (memory != NULL) {
            memory->type = CDISASM_OPERAND_MEMORY;
            memory->size = (uint8_t)(2u * size);
            memory->base_reg = a64_reg(rn, 1, 1);
            memory->imm = (uint64_t)displacement;
            memory->access = load ? CDISASM_OPERAND_ACCESS_READ
                                  : CDISASM_OPERAND_ACCESS_WRITE;
            if (displacement != 0) {
                memory->flags |= CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;
                if (displacement < 0) {
                    memory->flags |= CDISASM_OPERAND_FLAG_SIGNED;
                }
            }
        }
        cdisasm_arm_requirements_set_legacy(
            required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_VFP);
        return CDISASM_STATUS_OK;
    }
    size=(uint8_t)(4u<<size_code);mode_index=address_mode==1u?0u:address_mode==2u?1u:2u;
    base=(cdisasm_arm_reg_id)((size==4u?CDISASM_ARM_REG_S0:size==8u?CDISASM_ARM_REG_D0:rt<16u?CDISASM_ARM_REG_Q0:CDISASM_ARM_REG_Q16-16u)+rt);
    instruction->name_id=load?CDISASM_ARM_NAME_LDP:CDISASM_ARM_NAME_STP;instruction->form_id=forms[size_code][mode_index][load];instruction->instruction_flags|=CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
    if(load&&rt==rt2)mark_unpredictable(instruction);
    append_register(instruction,base,size,load?CDISASM_OPERAND_ACCESS_WRITE:CDISASM_OPERAND_ACCESS_READ);
    base=(cdisasm_arm_reg_id)((size==4u?CDISASM_ARM_REG_S0:size==8u?CDISASM_ARM_REG_D0:rt2<16u?CDISASM_ARM_REG_Q0:CDISASM_ARM_REG_Q16-16u)+rt2);
    append_register(instruction,base,size,load?CDISASM_OPERAND_ACCESS_WRITE:CDISASM_OPERAND_ACCESS_READ);
    displacement=sign_extend((word>>15)&UINT32_C(0x7f),7)*(int64_t)size;memory=append_operand(instruction);
    if(memory!=NULL){memory->type=CDISASM_OPERAND_MEMORY;memory->size=size;memory->base_reg=a64_reg(rn,1,1);memory->imm=(uint64_t)displacement;memory->access=load?CDISASM_OPERAND_ACCESS_READ:CDISASM_OPERAND_ACCESS_WRITE;if(displacement!=0){memory->flags|=CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;if(displacement<0)memory->flags|=CDISASM_OPERAND_FLAG_SIGNED;}}
    if(address_mode==1u)instruction->instruction_flags|=CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX|CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;else if(address_mode==3u)instruction->instruction_flags|=CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX|CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
    cdisasm_arm_requirements_set_legacy(required_capabilities,CDISASM_ARM_CAP_V8);return CDISASM_STATUS_OK;
#endif
}

static cdisasm_status decode_a64_fp_signed_memory(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
#if !USE_EXTRA_OPCODES
    (void)word;(void)instruction;(void)required_capabilities;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    unsigned sc=word>>30,q=(word>>23)&1u,load=(word>>22)&1u,mode=(word>>10)&3u,rt=word&31u,rn=(word>>5)&31u,type,mi;static const uint8_t sizes[5]={1,16,2,4,8};static const cdisasm_arm_reg_id bases[5]={CDISASM_ARM_REG_B0,CDISASM_ARM_REG_Q0,CDISASM_ARM_REG_H0,CDISASM_ARM_REG_S0,CDISASM_ARM_REG_D0};static const uint16_t forms[5][3][2]={{{5142,5143},{5166,5167},{5202,5203}},{{5144,5145},{5168,5169},{5204,5205}},{{5150,5151},{5174,5175},{5210,5211}},{{5155,5156},{5179,5180},{5215,5216}},{{5160,5161},{5183,5184},{5219,5220}}};int64_t displacement;cdisasm_arm_reg_id reg;cdisasm_arm_operand *memory;
    if((q&&sc!=0u)||mode==2u)return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;type=sc==0u?q:sc+1u;mi=mode==0u?0u:mode==1u?1u:2u;reg=(cdisasm_arm_reg_id)((type==1u&&rt>=16u?CDISASM_ARM_REG_Q16-16u:bases[type])+rt);
    instruction->name_id=mode==0u?(load?CDISASM_ARM_NAME_LDUR:CDISASM_ARM_NAME_STUR):(load?CDISASM_ARM_NAME_LDR:CDISASM_ARM_NAME_STR);instruction->form_id=forms[type][mi][load];instruction->instruction_flags|=CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;if(mode==1u)instruction->instruction_flags|=CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX|CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;else if(mode==3u)instruction->instruction_flags|=CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX|CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;append_register(instruction,reg,sizes[type],load?CDISASM_OPERAND_ACCESS_WRITE:CDISASM_OPERAND_ACCESS_READ);
    displacement=sign_extend((word>>12)&UINT32_C(0x1ff),9);memory=append_operand(instruction);if(memory!=NULL){memory->type=CDISASM_OPERAND_MEMORY;memory->size=sizes[type];memory->base_reg=a64_reg(rn,1,1);memory->imm=(uint64_t)displacement;memory->access=load?CDISASM_OPERAND_ACCESS_READ:CDISASM_OPERAND_ACCESS_WRITE;if(displacement!=0){memory->flags|=CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;if(displacement<0)memory->flags|=CDISASM_OPERAND_FLAG_SIGNED;}}
    cdisasm_arm_requirements_set_legacy(required_capabilities,CDISASM_ARM_CAP_V8);return CDISASM_STATUS_OK;
#endif
}

static cdisasm_status decode_a64_fp_unsigned_memory(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
#if !USE_EXTRA_OPCODES
    (void)word;(void)instruction;(void)required_capabilities;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    unsigned sc=word>>30,q=(word>>23)&1u,load=(word>>22)&1u,rt=word&31u,rn=(word>>5)&31u,type;static const uint8_t sizes[5]={1,16,2,4,8};static const cdisasm_arm_reg_id bases[5]={CDISASM_ARM_REG_B0,CDISASM_ARM_REG_Q0,CDISASM_ARM_REG_H0,CDISASM_ARM_REG_S0,CDISASM_ARM_REG_D0};static const uint16_t forms[5][2]={{5556,5557},{5558,5559},{5564,5565},{5569,5570},{5574,5575}};uint64_t displacement;cdisasm_arm_reg_id reg;cdisasm_arm_operand *memory;
    if(q&&sc!=0u)return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;type=sc==0u?q:sc+1u;reg=(cdisasm_arm_reg_id)((type==1u&&rt>=16u?CDISASM_ARM_REG_Q16-16u:bases[type])+rt);displacement=((word>>10)&UINT32_C(0xfff))*sizes[type];
    instruction->name_id=load?CDISASM_ARM_NAME_LDR:CDISASM_ARM_NAME_STR;instruction->form_id=forms[type][load];instruction->instruction_flags|=CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;append_register(instruction,reg,sizes[type],load?CDISASM_OPERAND_ACCESS_WRITE:CDISASM_OPERAND_ACCESS_READ);
    memory=append_operand(instruction);if(memory!=NULL){memory->type=CDISASM_OPERAND_MEMORY;memory->size=sizes[type];memory->base_reg=a64_reg(rn,1,1);memory->imm=displacement;memory->access=load?CDISASM_OPERAND_ACCESS_READ:CDISASM_OPERAND_ACCESS_WRITE;if(displacement!=0)memory->flags|=CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;}
    cdisasm_arm_requirements_set_legacy(required_capabilities,CDISASM_ARM_CAP_V8);return CDISASM_STATUS_OK;
#endif
}

static cdisasm_status decode_a64_fp_register_memory(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    unsigned option=(word>>13)&7u;
    if(option!=2u&&option!=3u&&option!=6u&&option!=7u)return CDISASM_STATUS_INVALID_INSTRUCTION;
#if !USE_EXTRA_OPCODES
    (void)instruction;(void)required_capabilities;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    unsigned sc=word>>30,q=(word>>23)&1u,load=(word>>22)&1u,s=(word>>12)&1u,rm=(word>>16)&31u,rt=word&31u,rn=(word>>5)&31u,type,shift;static const uint8_t sizes[5]={1,16,2,4,8};static const uint8_t shifts[5]={0,4,1,2,3};static const cdisasm_arm_reg_id bases[5]={CDISASM_ARM_REG_B0,CDISASM_ARM_REG_Q0,CDISASM_ARM_REG_H0,CDISASM_ARM_REG_S0,CDISASM_ARM_REG_D0};static const uint16_t forms[5][2]={{5525,5527},{5529,5530},{5535,5536},{5540,5541},{5546,5547}};cdisasm_arm_reg_id reg;cdisasm_arm_operand *memory;
    if(q&&sc!=0u)return CDISASM_STATUS_INVALID_INSTRUCTION;type=sc==0u?q:sc+1u;shift=shifts[type];reg=(cdisasm_arm_reg_id)((type==1u&&rt>=16u?CDISASM_ARM_REG_Q16-16u:bases[type])+rt);
    instruction->name_id=load?CDISASM_ARM_NAME_LDR:CDISASM_ARM_NAME_STR;instruction->form_id=(cdisasm_arm_form_id)(type==0u&&option==3u?(load?5528u:5526u):forms[type][load]);instruction->instruction_flags|=CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;append_register(instruction,reg,sizes[type],load?CDISASM_OPERAND_ACCESS_WRITE:CDISASM_OPERAND_ACCESS_READ);
    memory=append_operand(instruction);if(memory!=NULL){memory->type=CDISASM_OPERAND_MEMORY;memory->size=sizes[type];memory->base_reg=a64_reg(rn,1,1);memory->index_reg=a64_reg(rm,(option&1u)!=0u,0);memory->access=load?CDISASM_OPERAND_ACCESS_READ:CDISASM_OPERAND_ACCESS_WRITE;if(option==3u){if(s){memory->shift_type=CDISASM_ARM_SHIFT_LSL;memory->shift_amount=(uint8_t)shift;}}else{memory->extend_type=(cdisasm_arm_extend_type)(option==2u?CDISASM_ARM_EXTEND_UXTW:option==6u?CDISASM_ARM_EXTEND_SXTW:CDISASM_ARM_EXTEND_SXTX);if(s)memory->scale=(uint8_t)shift;}}
    cdisasm_arm_requirements_set_legacy(required_capabilities,CDISASM_ARM_CAP_V8);return CDISASM_STATUS_OK;
#endif
}

static cdisasm_status decode_a64_register_memory(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    unsigned option=(word>>13)&7u;
    if(option!=2u&&option!=3u&&option!=6u&&option!=7u)return CDISASM_STATUS_INVALID_INSTRUCTION;
#if !USE_EXTRA_OPCODES
    (void)instruction;(void)required_capabilities;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    unsigned size=word>>30,opc=(word>>22)&3u,s=(word>>12)&1u,rm=(word>>16)&31u,rt=word&31u,rn=(word>>5)&31u,reg64=0,mem_size=1u<<size;uint16_t form=0;cdisasm_arm_name_id name=CDISASM_ARM_NAME_NONE;cdisasm_arm_operand*memory;
    if(size==0u){if(opc==0u){name=CDISASM_ARM_NAME_STRB;form=option==3u?5518:5517;}else if(opc==1u){name=CDISASM_ARM_NAME_LDRB;form=option==3u?5520:5519;}else{name=CDISASM_ARM_NAME_LDRSB;reg64=opc==2u;form=opc==2u?(option==3u?5522:5521):(option==3u?5524:5523);}}
    else if(size==1u){if(opc==0u){name=CDISASM_ARM_NAME_STRH;form=5531;}else if(opc==1u){name=CDISASM_ARM_NAME_LDRH;form=5532;}else{name=CDISASM_ARM_NAME_LDRSH;reg64=opc==2u;form=opc==2u?5533:5534;}}
    else if(size==2u){if(opc==0u){name=CDISASM_ARM_NAME_STR;form=5537;}else if(opc==1u){name=CDISASM_ARM_NAME_LDR;form=5538;}else if(opc==2u){name=CDISASM_ARM_NAME_LDRSW;reg64=1;form=5539;}else return CDISASM_STATUS_INVALID_INSTRUCTION;}
    else{if(opc==0u){name=CDISASM_ARM_NAME_STR;reg64=1;form=5542;}else if(opc==1u){name=CDISASM_ARM_NAME_LDR;reg64=1;form=5543;}else if(opc==2u){name=CDISASM_ARM_NAME_PRFM;form=5544;mem_size=1;}else return CDISASM_STATUS_INVALID_INSTRUCTION;}
    instruction->name_id=name;instruction->form_id=form;if(name==CDISASM_ARM_NAME_PRFM)append_immediate(instruction,rt,1);else append_register(instruction,a64_reg(rt,reg64,0),(uint8_t)(reg64?8:4),opc==0u?CDISASM_OPERAND_ACCESS_READ:CDISASM_OPERAND_ACCESS_WRITE);
    memory=append_operand(instruction);if(memory!=NULL){memory->type=CDISASM_OPERAND_MEMORY;memory->size=(uint8_t)mem_size;memory->base_reg=a64_reg(rn,1,1);memory->index_reg=a64_reg(rm,(option&1u)!=0u,0);memory->access=CDISASM_OPERAND_ACCESS_READ;if(opc==0u)memory->access=CDISASM_OPERAND_ACCESS_WRITE;if(option==3u){if(s){memory->shift_type=CDISASM_ARM_SHIFT_LSL;memory->shift_amount=(uint8_t)size;}}else{memory->extend_type=(cdisasm_arm_extend_type)(option==2u?CDISASM_ARM_EXTEND_UXTW:option==6u?CDISASM_ARM_EXTEND_SXTW:CDISASM_ARM_EXTEND_SXTX);if(s)memory->scale=(uint8_t)size;}}
    cdisasm_arm_requirements_set_legacy(required_capabilities,CDISASM_ARM_CAP_V8);return CDISASM_STATUS_OK;
#endif
}

static cdisasm_status decode_a64_scalar_saturating_widening_multiply(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    unsigned size_code=(word>>22)&3u;
    if(size_code!=1u&&size_code!=2u)return CDISASM_STATUS_INVALID_INSTRUCTION;
#if !USE_EXTRA_OPCODES
    (void)instruction;(void)required_capabilities;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    uint32_t operation=word&UINT32_C(0xff20fc00);unsigned rm=(word>>16)&31u,rn=(word>>5)&31u,rd=word&31u,index;uint8_t source_size=(uint8_t)(1u<<size_code),result_size=(uint8_t)(source_size*2u);static const cdisasm_arm_name_id names[3]={CDISASM_ARM_NAME_SQDMLAL,CDISASM_ARM_NAME_SQDMLSL,CDISASM_ARM_NAME_SQDMULL};static const cdisasm_arm_reg_id bases[3]={CDISASM_ARM_REG_H0,CDISASM_ARM_REG_S0,CDISASM_ARM_REG_D0};cdisasm_arm_operand*operand;
    index=operation==UINT32_C(0x5e209000)?0u:operation==UINT32_C(0x5e20b000)?1u:2u;instruction->name_id=names[index];instruction->form_id=(uint16_t)(5819u+index);instruction->instruction_flags|=CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
    operand=append_register(instruction,(cdisasm_arm_reg_id)(bases[size_code]+rd),result_size,index<2u?CDISASM_OPERAND_ACCESS_READ_WRITE:CDISASM_OPERAND_ACCESS_WRITE);if(operand!=NULL){operand->extend_type=(cdisasm_arm_extend_type)result_size;operand->scale=1;}
    operand=append_register(instruction,(cdisasm_arm_reg_id)(bases[size_code-1u]+rn),source_size,CDISASM_OPERAND_ACCESS_READ);if(operand!=NULL){operand->extend_type=(cdisasm_arm_extend_type)source_size;operand->scale=1;}
    operand=append_register(instruction,(cdisasm_arm_reg_id)(bases[size_code-1u]+rm),source_size,CDISASM_OPERAND_ACCESS_READ);if(operand!=NULL){operand->extend_type=(cdisasm_arm_extend_type)source_size;operand->scale=1;}
    cdisasm_arm_requirements_set_legacy(required_capabilities,CDISASM_ARM_CAP_V8|CDISASM_ARM_CAP_NEON);return CDISASM_STATUS_OK;
#endif
}

static cdisasm_status decode_a64_scalar_immediate_shift_convert(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    uint32_t operation=word&UINT32_C(0xff80fc00);unsigned encoded=(word>>16)&127u;int convert=operation==UINT32_C(0x5f00e400)||operation==UINT32_C(0x5f00fc00)||operation==UINT32_C(0x7f00e400)||operation==UINT32_C(0x7f00fc00);if(encoded<8u||(convert&&encoded<32u))return CDISASM_STATUS_INVALID_INSTRUCTION;
#if !USE_EXTRA_OPCODES
    (void)instruction;(void)required_capabilities;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    unsigned element_bits=encoded>=64u?64u:encoded>=32u?32u:encoded>=16u?16u:8u,rn=(word>>5)&31u,rd=word&31u,index;uint8_t es=(uint8_t)(element_bits/8u);uint64_t immediate=convert?2u*element_bits-encoded:encoded-element_bits;static const uint32_t operations[7]={UINT32_C(0x5f007400),UINT32_C(0x5f00e400),UINT32_C(0x5f00fc00),UINT32_C(0x7f006400),UINT32_C(0x7f007400),UINT32_C(0x7f00e400),UINT32_C(0x7f00fc00)};static const cdisasm_arm_name_id names[7]={CDISASM_ARM_NAME_SQSHL,CDISASM_ARM_NAME_SCVTF,CDISASM_ARM_NAME_FCVTZS,CDISASM_ARM_NAME_SQSHLU,CDISASM_ARM_NAME_UQSHL,CDISASM_ARM_NAME_UCVTF,CDISASM_ARM_NAME_FCVTZU};static const uint16_t forms[7]={5858,5861,5862,5869,5870,5875,5876};static const cdisasm_arm_reg_id bases[4]={CDISASM_ARM_REG_B0,CDISASM_ARM_REG_H0,CDISASM_ARM_REG_S0,CDISASM_ARM_REG_D0};cdisasm_arm_operand*operand;
    for(index=0;index<7u&&operations[index]!=operation;++index){}if(index==7u)return CDISASM_STATUS_INTERNAL_ERROR;instruction->name_id=names[index];instruction->form_id=forms[index];instruction->instruction_flags|=CDISASM_ARM_INSTRUCTION_FLAG_SIMD|(convert?CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT:0u);
    operand=append_register(instruction,(cdisasm_arm_reg_id)(bases[element_bits==8?0:element_bits==16?1:element_bits==32?2:3]+rd),es,CDISASM_OPERAND_ACCESS_WRITE);if(operand!=NULL){operand->extend_type=(cdisasm_arm_extend_type)es;operand->scale=1;}
    operand=append_register(instruction,(cdisasm_arm_reg_id)(bases[element_bits==8?0:element_bits==16?1:element_bits==32?2:3]+rn),es,CDISASM_OPERAND_ACCESS_READ);if(operand!=NULL){operand->extend_type=(cdisasm_arm_extend_type)es;operand->scale=1;}
    append_immediate(instruction,immediate,1u);cdisasm_arm_requirements_set_legacy(required_capabilities,CDISASM_ARM_CAP_V8|CDISASM_ARM_CAP_NEON);return CDISASM_STATUS_OK;
#endif
}

static cdisasm_status decode_a64_scalar_sqrdml_accumulate(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    unsigned size_code=(word>>22)&3u;
    if(size_code!=1u&&size_code!=2u)return CDISASM_STATUS_INVALID_INSTRUCTION;
#if !USE_EXTRA_OPCODES
    (void)instruction;(void)required_capabilities;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    uint8_t es=(uint8_t)(1u<<size_code);cdisasm_arm_reg_id base=size_code==1u?CDISASM_ARM_REG_H0:CDISASM_ARM_REG_S0;unsigned rd=word&31u,rn=(word>>5)&31u,rm=(word>>16)&31u;int subtract=(word&UINT32_C(0x00000800))!=0u;cdisasm_arm_operand*operand;
    instruction->name_id=subtract?CDISASM_ARM_NAME_SQRDMLSH:CDISASM_ARM_NAME_SQRDMLAH;instruction->form_id=(uint16_t)(subtract?5772u:5771u);instruction->instruction_flags|=CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
    operand=append_register(instruction,(cdisasm_arm_reg_id)(base+rd),es,CDISASM_OPERAND_ACCESS_READ_WRITE);if(operand!=NULL){operand->extend_type=(cdisasm_arm_extend_type)es;operand->scale=1;}
    operand=append_register(instruction,(cdisasm_arm_reg_id)(base+rn),es,CDISASM_OPERAND_ACCESS_READ);if(operand!=NULL){operand->extend_type=(cdisasm_arm_extend_type)es;operand->scale=1;}
    operand=append_register(instruction,(cdisasm_arm_reg_id)(base+rm),es,CDISASM_OPERAND_ACCESS_READ);if(operand!=NULL){operand->extend_type=(cdisasm_arm_extend_type)es;operand->scale=1;}
    cdisasm_arm_requirements_set_legacy(required_capabilities,CDISASM_ARM_CAP_V8|CDISASM_ARM_CAP_NEON);return CDISASM_STATUS_OK;
#endif
}

static int a64_scalar_by_element_operation(uint32_t word)
{
    static const uint32_t masks[15]={UINT32_C(0xff00f400),UINT32_C(0xff00f400),UINT32_C(0xff00f400),UINT32_C(0xff00f400),UINT32_C(0xff00f400),UINT32_C(0xffc0f400),UINT32_C(0xffc0f400),UINT32_C(0xffc0f400),UINT32_C(0xff80f400),UINT32_C(0xff80f400),UINT32_C(0xff80f400),UINT32_C(0xff00f400),UINT32_C(0xff00f400),UINT32_C(0xffc0f400),UINT32_C(0xff80f400)};
    static const uint32_t values[15]={UINT32_C(0x5f003000),UINT32_C(0x5f007000),UINT32_C(0x5f00b000),UINT32_C(0x5f00c000),UINT32_C(0x5f00d000),UINT32_C(0x5f001000),UINT32_C(0x5f005000),UINT32_C(0x5f009000),UINT32_C(0x5f801000),UINT32_C(0x5f805000),UINT32_C(0x5f809000),UINT32_C(0x7f00d000),UINT32_C(0x7f00f000),UINT32_C(0x7f009000),UINT32_C(0x7f809000)};unsigned i;
    for(i=0;i<15u;++i)if((word&masks[i])==values[i])return (int)i;return -1;
}

static cdisasm_status decode_a64_scalar_by_element(
    uint32_t word,cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    int op=a64_scalar_by_element_operation(word);unsigned sc=(word>>22)&3u,precision=(word>>22)&1u;int fp_h=(op>=5&&op<=7)||op==13,fp_sd=(op>=8&&op<=10)||op==14;if(op<0)return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;if((!fp_h&&!fp_sd&&(sc!=1u&&sc!=2u))||(fp_sd&&precision==1u&&(word&UINT32_C(0x00200000))!=0u))return CDISASM_STATUS_INVALID_INSTRUCTION;
#if !USE_EXTRA_OPCODES
    (void)instruction;(void)required_capabilities;return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    static const cdisasm_arm_name_id names[15]={CDISASM_ARM_NAME_SQDMLAL,CDISASM_ARM_NAME_SQDMLSL,CDISASM_ARM_NAME_SQDMULL,CDISASM_ARM_NAME_SQDMULH,CDISASM_ARM_NAME_SQRDMULH,CDISASM_ARM_NAME_FMLA,CDISASM_ARM_NAME_FMLS,CDISASM_ARM_NAME_FMUL,CDISASM_ARM_NAME_FMLA,CDISASM_ARM_NAME_FMLS,CDISASM_ARM_NAME_FMUL,CDISASM_ARM_NAME_SQRDMLAH,CDISASM_ARM_NAME_SQRDMLSH,CDISASM_ARM_NAME_FMULX,CDISASM_ARM_NAME_FMULX};unsigned rd=word&31u,rn=(word>>5)&31u,rm,lane;uint8_t source_size=fp_h?2u:fp_sd?(uint8_t)(4u<<precision):(uint8_t)(1u<<sc),dest_size=op<=2?source_size*2u:source_size;cdisasm_arm_reg_id source_base=source_size==2?CDISASM_ARM_REG_H0:source_size==4?CDISASM_ARM_REG_S0:CDISASM_ARM_REG_D0,dest_base=dest_size==4?CDISASM_ARM_REG_S0:dest_size==8?CDISASM_ARM_REG_D0:CDISASM_ARM_REG_H0;cdisasm_operand_access da=(op==0||op==1||op==5||op==6||op==8||op==9||op==11||op==12)?CDISASM_OPERAND_ACCESS_READ_WRITE:CDISASM_OPERAND_ACCESS_WRITE;cdisasm_arm_operand*o;
    if(source_size==2u){rm=(word>>16)&15u;lane=((word>>11)&1u)*4u+((word>>21)&1u)*2u+((word>>20)&1u);}else if(source_size==4u){rm=(word>>16)&31u;lane=((word>>11)&1u)*2u+((word>>21)&1u);}else{rm=(word>>16)&31u;lane=(word>>11)&1u;}
    instruction->name_id=names[op];instruction->form_id=(uint16_t)(5877+op);instruction->instruction_flags|=CDISASM_ARM_INSTRUCTION_FLAG_SIMD|((fp_h||fp_sd)?CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT:0u);
    o=append_register(instruction,(cdisasm_arm_reg_id)(dest_base+rd),dest_size,da);if(o!=NULL){o->extend_type=(cdisasm_arm_extend_type)dest_size;o->scale=1;}
    o=append_register(instruction,(cdisasm_arm_reg_id)(source_base+rn),source_size,CDISASM_OPERAND_ACCESS_READ);if(o!=NULL){o->extend_type=(cdisasm_arm_extend_type)source_size;o->scale=1;}
    o=append_vector_register(instruction,(cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0+rm),16u,source_size,CDISASM_OPERAND_ACCESS_READ);if(o!=NULL){o->flags=CDISASM_ARM_OPERAND_FLAG_HAS_LANE;o->imm=lane;}
    cdisasm_arm_requirements_set_legacy(required_capabilities,CDISASM_ARM_CAP_V8|CDISASM_ARM_CAP_NEON|(fp_h?CDISASM_ARM_CAP_FP16:0u));return CDISASM_STATUS_OK;
#endif
}

static cdisasm_status decode_a64_advsimd_table_lookup(
    uint32_t word, cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    unsigned control = (word >> 12) & 7u;
#if !USE_EXTRA_OPCODES
    (void)instruction;
    (void)required_capabilities;
    (void)control;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    unsigned q = (word >> 30) & 1u;
    unsigned vd = word & 31u;
    unsigned vn = (word >> 5) & 31u;
    unsigned vm = (word >> 16) & 31u;
    unsigned count = (control >> 1) + 1u;
    int extending = (control & 1u) != 0;
    uint8_t vector_size = q ? 16u : 8u;
    cdisasm_arm_operand *list;

    instruction->name_id = extending
        ? CDISASM_ARM_NAME_TBX : CDISASM_ARM_NAME_TBL;
    instruction->form_id = (uint16_t)(5892u + control);
    instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
    append_vector_register(instruction,
        (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + vd),
        vector_size, 1u, extending ? CDISASM_OPERAND_ACCESS_READ_WRITE
                                  : CDISASM_OPERAND_ACCESS_WRITE);
    list = append_operand(instruction);
    if (list != NULL) {
        list->type = CDISASM_ARM_OPERAND_VECTOR_REGISTER_LIST;
        list->reg = (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + vn);
        list->register_list = (uint16_t)count;
        list->size = 16u;
        list->extend_type = 1u;
        list->scale = 16u;
        list->access = CDISASM_OPERAND_ACCESS_READ;
    }
    append_vector_register(instruction,
        (cdisasm_arm_reg_id)(CDISASM_ARM_REG_V0 + vm),
        vector_size, 1u, CDISASM_OPERAND_ACCESS_READ);
    cdisasm_arm_requirements_set_legacy(
        required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_NEON);
    return CDISASM_STATUS_OK;
#endif
}

typedef enum a64_base_system_form {
    A64_BASE_SYSTEM_NONE = 0,
    A64_BASE_SYSTEM_BITFIELD,
    A64_BASE_SYSTEM_EXTR,
    A64_BASE_SYSTEM_CONDITIONAL_REGISTER,
    A64_BASE_SYSTEM_CONDITIONAL_IMMEDIATE,
    A64_BASE_SYSTEM_CRC32,
    A64_BASE_SYSTEM_MRS,
    A64_BASE_SYSTEM_MSR,
    A64_BASE_SYSTEM_SYS,
    A64_BASE_SYSTEM_SYSL,
    A64_BASE_SYSTEM_HINT,
    A64_BASE_SYSTEM_DMB,
    A64_BASE_SYSTEM_DSB,
    A64_BASE_SYSTEM_ISB,
    A64_BASE_SYSTEM_CLREX,
    A64_BASE_SYSTEM_ERET
} a64_base_system_form;

static a64_base_system_form classify_a64_base_system(uint32_t word)
{
    uint32_t bitfield = word & UINT32_C(0x7f800000);
    uint32_t conditional = word & UINT32_C(0x3fe00c10);
    uint32_t barrier = word & UINT32_C(0xfffff0ff);

    if (bitfield == UINT32_C(0x13000000)
        || bitfield == UINT32_C(0x33000000)
        || bitfield == UINT32_C(0x53000000)) {
        return A64_BASE_SYSTEM_BITFIELD;
    }
    if ((word & UINT32_C(0x7fa00000)) == UINT32_C(0x13800000)) {
        return A64_BASE_SYSTEM_EXTR;
    }
    if (conditional == UINT32_C(0x3a400000)) {
        return A64_BASE_SYSTEM_CONDITIONAL_REGISTER;
    }
    if (conditional == UINT32_C(0x3a400800)) {
        return A64_BASE_SYSTEM_CONDITIONAL_IMMEDIATE;
    }
    if ((word & UINT32_C(0x7fe0e000)) == UINT32_C(0x1ac04000)) {
        return A64_BASE_SYSTEM_CRC32;
    }
    if ((word & UINT32_C(0xfff00000)) == UINT32_C(0xd5300000)) {
        return A64_BASE_SYSTEM_MRS;
    }
    if ((word & UINT32_C(0xfff00000)) == UINT32_C(0xd5100000)) {
        return A64_BASE_SYSTEM_MSR;
    }
    if ((word & UINT32_C(0xfff80000)) == UINT32_C(0xd5080000)) {
        return A64_BASE_SYSTEM_SYS;
    }
    if ((word & UINT32_C(0xfff80000)) == UINT32_C(0xd5280000)) {
        return A64_BASE_SYSTEM_SYSL;
    }
    if (word == UINT32_C(0xd69f03e0)) {
        return A64_BASE_SYSTEM_ERET;
    }
    if (barrier == UINT32_C(0xd50330bf)) {
        return A64_BASE_SYSTEM_DMB;
    }
    if (barrier == UINT32_C(0xd503309f)) {
        return A64_BASE_SYSTEM_DSB;
    }
    if (barrier == UINT32_C(0xd50330df)) {
        return A64_BASE_SYSTEM_ISB;
    }
    if (barrier == UINT32_C(0xd503305f)) {
        return A64_BASE_SYSTEM_CLREX;
    }
    if ((word & UINT32_C(0xfffff01f)) == UINT32_C(0xd503201f)) {
        return A64_BASE_SYSTEM_HINT;
    }
    return A64_BASE_SYSTEM_NONE;
}

static int a64_base_system_encoding_is_valid(
    a64_base_system_form form,
    uint32_t word)
{
    if (form == A64_BASE_SYSTEM_BITFIELD
        || form == A64_BASE_SYSTEM_EXTR) {
        unsigned sf = word >> 31;
        unsigned n = (word >> 22) & 1u;

        if (sf != n) {
            return 0;
        }
        if (sf == 0u
            && (((word >> 21) & 1u) != 0u
                || ((word >> 15) & 1u) != 0u)) {
            return 0;
        }
    }
    if (form == A64_BASE_SYSTEM_CRC32) {
        unsigned sf = word >> 31;
        unsigned size_code = (word >> 10) & 3u;

        return sf == (size_code == 3u ? 1u : 0u);
    }
    return 1;
}

static cdisasm_status decode_a64_base_system_extra(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities,
    int *recognized)
{
    a64_base_system_form form = classify_a64_base_system(word);

    *recognized = form != A64_BASE_SYSTEM_NONE;
    if (!*recognized) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if (!a64_base_system_encoding_is_valid(form, word)) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
#if !USE_EXTRA_OPCODES
    (void)instruction;
    (void)required_capabilities;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    if (form == A64_BASE_SYSTEM_BITFIELD) {
        static const cdisasm_arm_name_id names[3] = {
            CDISASM_ARM_NAME_SBFM,
            CDISASM_ARM_NAME_BFM,
            CDISASM_ARM_NAME_UBFM
        };
        unsigned sf = word >> 31;
        unsigned opc = (word >> 29) & 3u;
        unsigned immr = (word >> 16) & 63u;
        unsigned imms = (word >> 10) & 63u;
        unsigned rn = (word >> 5) & 31u;
        unsigned rd = word & 31u;
        uint8_t size = sf != 0u ? 8u : 4u;

        if (opc > 2u) {
            return CDISASM_STATUS_INTERNAL_ERROR;
        }
        instruction->name_id = names[opc];
        append_register(
            instruction, a64_reg(rd, sf != 0u, 0), size,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_register(
            instruction, a64_reg(rn, sf != 0u, 0), size,
            CDISASM_OPERAND_ACCESS_READ);
        append_immediate(instruction, immr, 1u);
        append_immediate(instruction, imms, 1u);
    } else if (form == A64_BASE_SYSTEM_EXTR) {
        unsigned sf = word >> 31;
        unsigned rm = (word >> 16) & 31u;
        unsigned lsb = (word >> 10) & 63u;
        unsigned rn = (word >> 5) & 31u;
        unsigned rd = word & 31u;
        uint8_t size = sf != 0u ? 8u : 4u;

        instruction->name_id = CDISASM_ARM_NAME_EXTR;
        append_register(
            instruction, a64_reg(rd, sf != 0u, 0), size,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_register(
            instruction, a64_reg(rn, sf != 0u, 0), size,
            CDISASM_OPERAND_ACCESS_READ);
        append_register(
            instruction, a64_reg(rm, sf != 0u, 0), size,
            CDISASM_OPERAND_ACCESS_READ);
        append_immediate(instruction, lsb, 1u);
    } else if (form == A64_BASE_SYSTEM_CONDITIONAL_REGISTER
        || form == A64_BASE_SYSTEM_CONDITIONAL_IMMEDIATE) {
        unsigned sf = word >> 31;
        unsigned source = (word >> 16) & 31u;
        unsigned condition = (word >> 12) & 15u;
        unsigned rn = (word >> 5) & 31u;
        unsigned nzcv = word & 15u;
        uint8_t size = sf != 0u ? 8u : 4u;

        instruction->name_id = ((word >> 30) & 1u) != 0u
            ? CDISASM_ARM_NAME_CCMP : CDISASM_ARM_NAME_CCMN;
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
        instruction->opcode_groups |= CDISASM_GROUP_CONDITIONAL;
        append_register(
            instruction, a64_reg(rn, sf != 0u, 0), size,
            CDISASM_OPERAND_ACCESS_READ);
        if (form == A64_BASE_SYSTEM_CONDITIONAL_IMMEDIATE) {
            append_immediate(instruction, source, 1u);
        } else {
            append_register(
                instruction, a64_reg(source, sf != 0u, 0), size,
                CDISASM_OPERAND_ACCESS_READ);
        }
        append_immediate(instruction, nzcv, 1u);
        append_immediate(instruction, condition, 1u);
    } else if (form == A64_BASE_SYSTEM_CRC32) {
        static const cdisasm_arm_name_id names[8] = {
            CDISASM_ARM_NAME_CRC32B,
            CDISASM_ARM_NAME_CRC32H,
            CDISASM_ARM_NAME_CRC32W,
            CDISASM_ARM_NAME_CRC32X,
            CDISASM_ARM_NAME_CRC32CB,
            CDISASM_ARM_NAME_CRC32CH,
            CDISASM_ARM_NAME_CRC32CW,
            CDISASM_ARM_NAME_CRC32CX
        };
        unsigned size_code = (word >> 10) & 3u;
        unsigned rm = (word >> 16) & 31u;
        unsigned rn = (word >> 5) & 31u;
        unsigned rd = word & 31u;
        unsigned castagnoli = (word >> 12) & 1u;

        instruction->name_id = names[castagnoli * 4u + size_code];
        append_register(
            instruction, a64_reg(rd, 0, 0), 4u,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_register(
            instruction, a64_reg(rn, 0, 0), 4u,
            CDISASM_OPERAND_ACCESS_READ);
        append_register(
            instruction, a64_reg(rm, size_code == 3u, 0),
            (uint8_t)(UINT32_C(1) << size_code),
            CDISASM_OPERAND_ACCESS_READ);
    } else if (form == A64_BASE_SYSTEM_MRS
        || form == A64_BASE_SYSTEM_MSR) {
        unsigned rt = word & 31u;
        uint16_t system_register = (uint16_t)((word >> 5) & 0xffffu);

        instruction->name_id = form == A64_BASE_SYSTEM_MRS
            ? CDISASM_ARM_NAME_MRS : CDISASM_ARM_NAME_MSR;
        instruction->opcode_groups |= CDISASM_GROUP_PRIVILEGED;
        if (form == A64_BASE_SYSTEM_MRS) {
            append_register(
                instruction, a64_reg(rt, 1, 0), 8u,
                CDISASM_OPERAND_ACCESS_WRITE);
            append_system_operand(
                instruction,
                CDISASM_ARM_OPERAND_SYSTEM_REGISTER,
                system_register,
                CDISASM_OPERAND_ACCESS_READ);
        } else {
            append_system_operand(
                instruction,
                CDISASM_ARM_OPERAND_SYSTEM_REGISTER,
                system_register,
                CDISASM_OPERAND_ACCESS_WRITE);
            append_register(
                instruction, a64_reg(rt, 1, 0), 8u,
                CDISASM_OPERAND_ACCESS_READ);
        }
    } else if (form == A64_BASE_SYSTEM_SYS
        || form == A64_BASE_SYSTEM_SYSL) {
        unsigned rt = word & 31u;
        uint16_t operation = (uint16_t)((word >> 5) & 0x3fffu);

        instruction->name_id = form == A64_BASE_SYSTEM_SYS
            ? CDISASM_ARM_NAME_SYS : CDISASM_ARM_NAME_SYSL;
        instruction->opcode_groups |= CDISASM_GROUP_PRIVILEGED;
        if (form == A64_BASE_SYSTEM_SYSL) {
            append_register(
                instruction, a64_reg(rt, 1, 0), 8u,
                CDISASM_OPERAND_ACCESS_WRITE);
        }
        append_system_operand(
            instruction,
            CDISASM_ARM_OPERAND_SYSTEM_OPERATION,
            operation,
            CDISASM_OPERAND_ACCESS_READ);
        if (form == A64_BASE_SYSTEM_SYS && rt != 31u) {
            append_register(
                instruction, a64_reg(rt, 1, 0), 8u,
                CDISASM_OPERAND_ACCESS_READ);
        }
    } else if (form == A64_BASE_SYSTEM_HINT) {
        unsigned hint = (word >> 5) & 0x7fu;

        switch (hint) {
            case 1u:
                instruction->name_id = CDISASM_ARM_NAME_YIELD;
                break;
            case 2u:
                instruction->name_id = CDISASM_ARM_NAME_WFE;
                break;
            case 3u:
                instruction->name_id = CDISASM_ARM_NAME_WFI;
                break;
            case 4u:
                instruction->name_id = CDISASM_ARM_NAME_SEV;
                break;
            case 5u:
                instruction->name_id = CDISASM_ARM_NAME_SEVL;
                break;
            case 16u:
                instruction->name_id = CDISASM_ARM_NAME_ESB;
                break;
            case 18u:
                instruction->name_id = CDISASM_ARM_NAME_TSB;
                break;
            case 20u:
                instruction->name_id = CDISASM_ARM_NAME_CSDB;
                break;
            case 22u:
                instruction->name_id = CDISASM_ARM_NAME_CLRBHB;
                break;
            default:
                instruction->name_id = CDISASM_ARM_NAME_HINT;
                append_immediate(instruction, hint, 1u);
                break;
        }
    } else if (form == A64_BASE_SYSTEM_DMB
        || form == A64_BASE_SYSTEM_DSB
        || form == A64_BASE_SYSTEM_ISB
        || form == A64_BASE_SYSTEM_CLREX) {
        unsigned option = (word >> 8) & 15u;

        if (form == A64_BASE_SYSTEM_DMB) {
            instruction->name_id = CDISASM_ARM_NAME_DMB;
        } else if (form == A64_BASE_SYSTEM_DSB) {
            instruction->name_id = CDISASM_ARM_NAME_DSB;
        } else if (form == A64_BASE_SYSTEM_ISB) {
            instruction->name_id = CDISASM_ARM_NAME_ISB;
        } else {
            instruction->name_id = CDISASM_ARM_NAME_CLREX;
        }
        if (option != 15u
            || (form != A64_BASE_SYSTEM_ISB
                && form != A64_BASE_SYSTEM_CLREX)) {
            append_immediate(instruction, option, 1u);
        }
    } else if (form == A64_BASE_SYSTEM_ERET) {
        instruction->name_id = CDISASM_ARM_NAME_ERET;
        instruction->opcode_groups |= CDISASM_GROUP_RETURN
            | CDISASM_GROUP_INTERRUPT_RETURN
            | CDISASM_GROUP_PRIVILEGED;
    } else {
        return CDISASM_STATUS_INTERNAL_ERROR;
    }
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8);
    if (form == A64_BASE_SYSTEM_CRC32) {
        (void)cdisasm_arm_requirements_add_feature(
            required_capabilities, CDISASM_ARM_FEATURE_CRC32);
    } else if (form == A64_BASE_SYSTEM_HINT
        && instruction->name_id == CDISASM_ARM_NAME_ESB) {
        (void)cdisasm_arm_requirements_add_feature(
            required_capabilities, CDISASM_ARM_FEATURE_RAS);
    } else if (form == A64_BASE_SYSTEM_HINT
        && instruction->name_id == CDISASM_ARM_NAME_TSB) {
        (void)cdisasm_arm_requirements_add_feature(
            required_capabilities, CDISASM_ARM_FEATURE_TRF);
    } else if (form == A64_BASE_SYSTEM_HINT
        && instruction->name_id == CDISASM_ARM_NAME_CLRBHB) {
        (void)cdisasm_arm_requirements_add_feature(
            required_capabilities, CDISASM_ARM_FEATURE_CLRBHB);
    }
    return CDISASM_STATUS_OK;
#endif
}

#if USE_EXTRA_OPCODES
static cdisasm_arm_reg_id a64_fp_reg(unsigned encoded, unsigned type)
{
    if (type == 3u) {
        return (cdisasm_arm_reg_id)(CDISASM_ARM_REG_H0 + encoded);
    }
    if (type == 0u) {
        return (cdisasm_arm_reg_id)(CDISASM_ARM_REG_S0 + encoded);
    }
    return (cdisasm_arm_reg_id)(CDISASM_ARM_REG_D0 + encoded);
}
#endif

static cdisasm_status decode_a64_scalar_fp_extra(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities,
    int *recognized)
{
    uint32_t one_source = word & UINT32_C(0xff3ffc00);
    uint32_t compare = word & UINT32_C(0xff20fc0f);
    uint32_t compare_zero = word & UINT32_C(0xff3ffc0f);
    uint32_t conditional_compare = word & UINT32_C(0xff200c00);
    uint32_t immediate_move = word & UINT32_C(0xff201fe0);
    uint32_t select = word & UINT32_C(0xff200c00);
    unsigned type = (word >> 22) & 3u;
    unsigned rd = word & 31u;
    unsigned rn = (word >> 5) & 31u;
    unsigned rm = (word >> 16) & 31u;
#if USE_EXTRA_OPCODES
    uint8_t size;
#endif

    *recognized = one_source == UINT32_C(0x1e20c000)
        || one_source == UINT32_C(0x1e214000)
        || one_source == UINT32_C(0x1e21c000)
        || compare == UINT32_C(0x1e202000)
        || compare_zero == UINT32_C(0x1e202008)
        || conditional_compare == UINT32_C(0x1e200400)
        || immediate_move == UINT32_C(0x1e201000)
        || select == UINT32_C(0x1e200c00);
    if (!*recognized) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    if (type == 2u) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
#if !USE_EXTRA_OPCODES
    (void)instruction;
    (void)required_capabilities;
    (void)rd;
    (void)rn;
    (void)rm;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    size = type == 3u ? 2u : type == 0u ? 4u : 8u;
    if (immediate_move == UINT32_C(0x1e201000)) {
        instruction->name_id = CDISASM_ARM_NAME_FMOV;
        if (type == 0u) {
            instruction->form_id = UINT16_C(6519);
        } else if (type == 1u) {
            instruction->form_id = UINT16_C(6520);
        }
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
        append_register(instruction, a64_fp_reg(rd, type), size,
            CDISASM_OPERAND_ACCESS_WRITE);
        append_immediate(instruction,
            vfp_expand_immediate((word >> 13) & 255u, size), 1u);
        cdisasm_arm_requirements_set_legacy(required_capabilities,
            CDISASM_ARM_CAP_V8
                | (type == 3u ? CDISASM_ARM_CAP_FP16 : 0u));
        return CDISASM_STATUS_OK;
    }
    if (conditional_compare == UINT32_C(0x1e200400)) {
        static const cdisasm_arm_form_id forms[3][2] = {
            { UINT16_C(6522), UINT16_C(6523) },
            { UINT16_C(6524), UINT16_C(6525) },
            { UINT16_C(6526), UINT16_C(6527) }
        };
        unsigned precision = type == 0u ? 0u : type == 1u ? 1u : 2u;
        unsigned signaling = (word >> 4) & 1u;

        instruction->name_id = signaling != 0u
            ? CDISASM_ARM_NAME_FCCMPE : CDISASM_ARM_NAME_FCCMP;
        instruction->form_id = forms[precision][signaling];
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
            | CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS;
        instruction->opcode_groups |= CDISASM_GROUP_CONDITIONAL;
        append_register(instruction, a64_fp_reg(rn, type), size,
            CDISASM_OPERAND_ACCESS_READ);
        append_register(instruction, a64_fp_reg(rm, type), size,
            CDISASM_OPERAND_ACCESS_READ);
        append_immediate(instruction, word & 15u, 1u);
        append_immediate(instruction, (word >> 12) & 15u, 1u);
        cdisasm_arm_requirements_set_legacy(required_capabilities,
            CDISASM_ARM_CAP_V8
                | (type == 3u ? CDISASM_ARM_CAP_FP16 : 0u));
        return CDISASM_STATUS_OK;
    }
    instruction->name_id = one_source == UINT32_C(0x1e20c000)
        ? CDISASM_ARM_NAME_FABS
        : one_source == UINT32_C(0x1e214000)
            ? CDISASM_ARM_NAME_FNEG
            : one_source == UINT32_C(0x1e21c000)
                ? CDISASM_ARM_NAME_FSQRT
                : (compare == UINT32_C(0x1e202000)
                    || compare_zero == UINT32_C(0x1e202008))
                    ? ((word & UINT32_C(0x10)) != 0u
                        ? CDISASM_ARM_NAME_FCMPE : CDISASM_ARM_NAME_FCMP)
                    : CDISASM_ARM_NAME_FCSEL;
    instruction->instruction_flags |=
        CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT
        | ((compare == UINT32_C(0x1e202000)
                || compare_zero == UINT32_C(0x1e202008))
            ? CDISASM_ARM_INSTRUCTION_FLAG_SETS_FLAGS : 0u);
    if (select == UINT32_C(0x1e200c00)
        || one_source == UINT32_C(0x1e20c000)
        || one_source == UINT32_C(0x1e214000)
        || one_source == UINT32_C(0x1e21c000)) {
        append_register(
            instruction, a64_fp_reg(rd, type), size,
            CDISASM_OPERAND_ACCESS_WRITE);
    }
    append_register(
        instruction, a64_fp_reg(rn, type), size,
        CDISASM_OPERAND_ACCESS_READ);
    if (compare_zero == UINT32_C(0x1e202008)) {
        append_immediate(instruction, 0u, 1u);
    } else if (one_source != UINT32_C(0x1e20c000)
        && one_source != UINT32_C(0x1e214000)
        && one_source != UINT32_C(0x1e21c000)) {
        append_register(
            instruction, a64_fp_reg(rm, type), size,
            CDISASM_OPERAND_ACCESS_READ);
    }
    if (select == UINT32_C(0x1e200c00)) {
        append_immediate(instruction, (word >> 12) & 15u, 1u);
    }
    if (compare == UINT32_C(0x1e202000)
        || compare_zero == UINT32_C(0x1e202008)) {
        static const cdisasm_arm_form_id compare_forms[3][4] = {
            { UINT16_C(6507), UINT16_C(6508),
              UINT16_C(6509), UINT16_C(6510) },
            { UINT16_C(6511), UINT16_C(6512),
              UINT16_C(6513), UINT16_C(6514) },
            { UINT16_C(6515), UINT16_C(6516),
              UINT16_C(6517), UINT16_C(6518) }
        };
        unsigned precision = type == 0u ? 0u : type == 1u ? 1u : 2u;
        unsigned variant = ((word & UINT32_C(0x10)) != 0u ? 2u : 0u)
            | (compare_zero == UINT32_C(0x1e202008) ? 1u : 0u);
        instruction->form_id = compare_forms[precision][variant];
    }
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8
        | (type == 3u ? CDISASM_ARM_CAP_FP16 : 0u));
    return CDISASM_STATUS_OK;
#endif
}

static cdisasm_status decode_a64_neon(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    const uint32_t permute_family =
        word & UINT32_C(0xbf208c00);
    const uint32_t size_variable_form =
        word & UINT32_C(0xbf20fc00);
    const uint32_t bitwise_form = word & UINT32_C(0xbfe0fc00);
    const uint32_t floating_form = word & UINT32_C(0xbfa0fc00);
    unsigned size_code = (word >> 22) & 3u;
    unsigned vm = (word >> 16) & 31u;
    unsigned vn = (word >> 5) & 31u;
    unsigned vd = word & 31u;
    int is_quad = (word & UINT32_C(0x40000000)) != 0;
    uint8_t total_size = is_quad ? 16u : 8u;
    uint8_t element_size;
    int floating_point = 0;
    int move_alias = 0;

    if (permute_family == UINT32_C(0x0e000800)) {
        const unsigned operation = (word >> 12) & 7u;

        /* The AdvSIMD ZIP/UZP/TRN operation field is sparse.  Selectors
         * zero and four are unallocated, and Q=0,size=3 would describe an
         * unavailable one-lane 64-bit arrangement.  Keep these structural
         * checks active when the optional semantic tables are disabled. */
        if (operation == 0u || operation == 4u
            || (size_code == 3u && !is_quad)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        switch (operation) {
            case 1u:
                instruction->name_id = CDISASM_ARM_NAME_UZP1;
                break;
            case 2u:
                instruction->name_id = CDISASM_ARM_NAME_TRN1;
                break;
            case 3u:
                instruction->name_id = CDISASM_ARM_NAME_ZIP1;
                break;
            case 5u:
                instruction->name_id = CDISASM_ARM_NAME_UZP2;
                break;
            case 6u:
                instruction->name_id = CDISASM_ARM_NAME_TRN2;
                break;
            default:
                instruction->name_id = CDISASM_ARM_NAME_ZIP2;
                break;
        }
        element_size = (uint8_t)(UINT32_C(1) << size_code);
#endif
    } else if (size_variable_form == UINT32_C(0x0e208400)) {
        instruction->name_id = CDISASM_ARM_NAME_ADD;
        element_size = (uint8_t)(1u << size_code);
        if (size_code == 3u && !is_quad) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
    } else if (size_variable_form == UINT32_C(0x2e208400)) {
        instruction->name_id = CDISASM_ARM_NAME_SUB;
        element_size = (uint8_t)(1u << size_code);
        if (size_code == 3u && !is_quad) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
    } else if (size_variable_form == UINT32_C(0x0e209c00)) {
        if (size_code == 3u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        instruction->name_id = CDISASM_ARM_NAME_MUL;
        element_size = (uint8_t)(1u << size_code);
    } else if (bitwise_form == UINT32_C(0x0e201c00)) {
        instruction->name_id = CDISASM_ARM_NAME_AND;
        element_size = 1u;
    } else if (bitwise_form == UINT32_C(0x0ea01c00)) {
        move_alias = vn == vm;
        instruction->name_id = move_alias ? CDISASM_ARM_NAME_MOV
                                          : CDISASM_ARM_NAME_ORR;
        element_size = 1u;
    } else if (bitwise_form == UINT32_C(0x2e201c00)) {
        instruction->name_id = CDISASM_ARM_NAME_EOR;
        element_size = 1u;
    } else if (floating_form == UINT32_C(0x0e20d400)) {
        instruction->name_id = CDISASM_ARM_NAME_FADD;
        element_size = (word & UINT32_C(0x00400000)) != 0 ? 8u : 4u;
        floating_point = 1;
    } else if (floating_form == UINT32_C(0x0ea0d400)) {
        instruction->name_id = CDISASM_ARM_NAME_FSUB;
        element_size = (word & UINT32_C(0x00400000)) != 0 ? 8u : 4u;
        floating_point = 1;
    } else if (floating_form == UINT32_C(0x2e20dc00)) {
        instruction->name_id = CDISASM_ARM_NAME_FMUL;
        element_size = (word & UINT32_C(0x00400000)) != 0 ? 8u : 4u;
        floating_point = 1;
    } else if (floating_form == UINT32_C(0x2e20fc00)) {
        instruction->name_id = CDISASM_ARM_NAME_FDIV;
        element_size = (word & UINT32_C(0x00400000)) != 0 ? 8u : 4u;
        floating_point = 1;
    } else if (size_variable_form == UINT32_C(0x0e209400)
        || size_variable_form == UINT32_C(0x2e209400)
        || size_variable_form == UINT32_C(0x0e206400)
        || size_variable_form == UINT32_C(0x2e206400)
        || size_variable_form == UINT32_C(0x0e206c00)
        || size_variable_form == UINT32_C(0x2e206c00)) {
        if (size_code == 3u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id =
            size_variable_form == UINT32_C(0x0e209400)
                ? CDISASM_ARM_NAME_MLA
                : size_variable_form == UINT32_C(0x2e209400)
                    ? CDISASM_ARM_NAME_MLS
                    : size_variable_form == UINT32_C(0x0e206400)
                        ? CDISASM_ARM_NAME_SMAX
                        : size_variable_form == UINT32_C(0x2e206400)
                            ? CDISASM_ARM_NAME_UMAX
                            : size_variable_form == UINT32_C(0x0e206c00)
                                ? CDISASM_ARM_NAME_SMIN
                                : CDISASM_ARM_NAME_UMIN;
        element_size = (uint8_t)(1u << size_code);
#endif
    } else if (floating_form == UINT32_C(0x0e20cc00)
        || floating_form == UINT32_C(0x0ea0cc00)) {
#if !USE_EXTRA_OPCODES
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
        instruction->name_id = floating_form == UINT32_C(0x0e20cc00)
            ? CDISASM_ARM_NAME_FMLA : CDISASM_ARM_NAME_FMLS;
        element_size = (word & UINT32_C(0x00400000)) != 0 ? 8u : 4u;
        floating_point = 1;
#endif
    } else {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }

    if (floating_point && element_size == 8u && !is_quad) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
    instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;
    if (floating_point) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT;
    }
    append_vector_register(
        instruction,
        a64_vector_reg(vd),
        total_size,
        element_size,
        CDISASM_OPERAND_ACCESS_WRITE);
    append_vector_register(
        instruction,
        a64_vector_reg(vn),
        total_size,
        element_size,
        CDISASM_OPERAND_ACCESS_READ);
    if (!move_alias) {
        append_vector_register(
            instruction,
            a64_vector_reg(vm),
            total_size,
            element_size,
            CDISASM_OPERAND_ACCESS_READ);
    }
    cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_NEON);
    return CDISASM_STATUS_OK;
}

/* A64 Advanced SIMD replicated loads.  The generated catalogue carries the
 * LD1R/LD2R/LD3R/LD4R base-register leaves, but their aggregate V-register
 * operand is not lowered by the generic operand recipes.  Keep the exact
 * numeric list and arrangement in the fixed ABI.  The post-index siblings
 * use different addressing fields and are intentionally handled separately
 * when their immediate/register semantics are available. */
static cdisasm_status decode_a64_advsimd_replicate_load(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    static const struct {
        uint32_t value;
        uint8_t count;
        cdisasm_arm_name_id name;
        cdisasm_arm_form_id form;
    } forms[] = {
        { UINT32_C(0x0d40c000), 1u, CDISASM_ARM_NAME_LD1R,
          UINT16_C(4639) },
        { UINT32_C(0x0d60c000), 2u, CDISASM_ARM_NAME_LD2R,
          UINT16_C(4650) },
        { UINT32_C(0x0d40e000), 3u, CDISASM_ARM_NAME_LD3R,
          UINT16_C(4640) },
        { UINT32_C(0x0d60e000), 4u, CDISASM_ARM_NAME_LD4R,
          UINT16_C(4651) }
    };
    const uint32_t masked = word & UINT32_C(0xbffff000);
    const uint8_t q = (uint8_t)((word >> 30) & 1u);
    const unsigned element_code = (word >> 10) & 3u;
    const uint8_t element_size = (uint8_t)(1u << element_code);
    const uint8_t vector_size = q != 0u ? 16u : 8u;
    unsigned index;
    unsigned vd;
    unsigned rn;
    cdisasm_arm_operand *list;
    cdisasm_arm_operand *memory;

    for (index = 0u; index < sizeof(forms) / sizeof(forms[0]); ++index) {
        if (masked == forms[index].value) {
            break;
        }
    }
    if (index == sizeof(forms) / sizeof(forms[0])) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }

    vd = word & 31u;
    rn = (word >> 5) & 31u;
    if (vd + forms[index].count > 32u) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
#if !USE_EXTRA_OPCODES
    (void)instruction;
    (void)required_capabilities;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    instruction->name_id = forms[index].name;
    instruction->form_id = forms[index].form;
    instruction->instruction_flags |= CDISASM_ARM_INSTRUCTION_FLAG_SIMD;

    list = append_operand(instruction);
    if (list != NULL) {
        list->type = CDISASM_ARM_OPERAND_VECTOR_REGISTER_LIST;
        list->reg = a64_vector_reg(vd);
        list->register_list = forms[index].count;
        list->size = vector_size;
        list->extend_type = (cdisasm_arm_extend_type)element_size;
        list->scale = (uint8_t)(vector_size / element_size);
        list->access = CDISASM_OPERAND_ACCESS_WRITE;
    }
    memory = append_operand(instruction);
    if (memory != NULL) {
        memory->type = CDISASM_OPERAND_MEMORY;
        memory->base_reg = a64_reg(rn, 1, 1);
        memory->size = element_size;
        memory->access = CDISASM_OPERAND_ACCESS_READ;
    }
    cdisasm_arm_requirements_set_legacy(
        required_capabilities, CDISASM_ARM_CAP_V8 | CDISASM_ARM_CAP_NEON);
    return CDISASM_STATUS_OK;
#endif
}

static cdisasm_status decode_a64(
    uint32_t word,
    uint64_t address,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    cdisasm_status status;
    int modern_recognized = 0;
    int base_system_recognized = 0;
    int fp_recognized = 0;
    int scalar_register_recognized = 0;
    int logical_immediate_recognized = 0;

    initialize_instruction(
        instruction,
        word,
        address,
        CDISASM_ARM_ISA_A64,
        CDISASM_ARM_CONDITION_AL);

    if (word == UINT32_C(0xd503201f)) {
        instruction->name_id = CDISASM_ARM_NAME_NOP;
        cdisasm_arm_requirements_set_legacy(required_capabilities, CDISASM_ARM_CAP_V8);
        return CDISASM_STATUS_OK;
    }
    if ((word & UINT32_C(0xffff0000)) == UINT32_C(0x00000000)) {
        return decode_a64_udf(
            word, instruction, required_capabilities);
    }
    if ((word & UINT32_C(0xff20fc00)) == UINT32_C(0x5e209000)
        || (word & UINT32_C(0xff20fc00)) == UINT32_C(0x5e20b000)
        || (word & UINT32_C(0xff20fc00)) == UINT32_C(0x5e20d000)) {
        return decode_a64_scalar_saturating_widening_multiply(
            word, instruction, required_capabilities);
    }
    if ((word & UINT32_C(0xff80fc00)) == UINT32_C(0x5f007400)
        || (word & UINT32_C(0xff80fc00)) == UINT32_C(0x5f00e400)
        || (word & UINT32_C(0xff80fc00)) == UINT32_C(0x5f00fc00)
        || (word & UINT32_C(0xff80fc00)) == UINT32_C(0x7f006400)
        || (word & UINT32_C(0xff80fc00)) == UINT32_C(0x7f007400)
        || (word & UINT32_C(0xff80fc00)) == UINT32_C(0x7f00e400)
        || (word & UINT32_C(0xff80fc00)) == UINT32_C(0x7f00fc00)) {
        return decode_a64_scalar_immediate_shift_convert(
            word, instruction, required_capabilities);
    }
    if ((word & UINT32_C(0xff20f400)) == UINT32_C(0x7e008400)) {
        return decode_a64_scalar_sqrdml_accumulate(
            word, instruction, required_capabilities);
    }
    if (a64_scalar_by_element_operation(word) >= 0) {
        return decode_a64_scalar_by_element(
            word, instruction, required_capabilities);
    }
    if ((word & UINT32_C(0xbfe08c00)) == UINT32_C(0x0e000000)) {
        return decode_a64_advsimd_table_lookup(
            word, instruction, required_capabilities);
    }
    status = decode_a64_advsimd_replicate_load(
        word, instruction, required_capabilities);
    if (status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        return status;
    }
    status = cdisasm_arm_decode_a64_modern(
        word, instruction, required_capabilities, &modern_recognized);
    if (modern_recognized
        || status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        return status;
    }
    status = cdisasm_arm_decode_a64_apple(
        word, instruction, required_capabilities);
    if (status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        return status;
    }
    status = decode_a64_base_system_extra(
        word, instruction, required_capabilities, &base_system_recognized);
    if (base_system_recognized
        || status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        return status;
    }
    status = decode_a64_scalar_fp_extra(
        word, instruction, required_capabilities, &fp_recognized);
    if (fp_recognized
        || status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        return status;
    }
    status = decode_a64_neon(word, instruction, required_capabilities);
    if (status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        return status;
    }
    status = decode_a64_scalar_register_extra(
        word, instruction, required_capabilities,
        &scalar_register_recognized);
    if (scalar_register_recognized
        || status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        return status;
    }
    status = decode_a64_logical_immediate_extra(
        word, instruction, required_capabilities,
        &logical_immediate_recognized);
    if (logical_immediate_recognized
        || status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION) {
        return status;
    }
    status = decode_a64_exception(word, instruction, required_capabilities);
    if (status == CDISASM_STATUS_OK) {
        return status;
    }
    status = decode_a64_branch_register(
        word, instruction, required_capabilities);
    if (status == CDISASM_STATUS_OK) {
        return status;
    }
    if ((word & UINT32_C(0x7c000000)) == UINT32_C(0x14000000)) {
        return decode_a64_branch_immediate(
            word, address, instruction, required_capabilities);
    }
    if ((word & UINT32_C(0xff000010)) == UINT32_C(0x54000000)) {
        return decode_a64_conditional_branch(
            word, address, instruction, required_capabilities);
    }
    if ((word & UINT32_C(0x7e000000)) == UINT32_C(0x34000000)) {
        return decode_a64_compare_branch(
            word, address, instruction, required_capabilities);
    }
    if ((word & UINT32_C(0x7e000000)) == UINT32_C(0x36000000)) {
        return decode_a64_test_branch(
            word, address, instruction, required_capabilities);
    }
    if ((word & UINT32_C(0x1f000000)) == UINT32_C(0x10000000)) {
        return decode_a64_pc_relative(
            word, address, instruction, required_capabilities);
    }
    if ((word & UINT32_C(0xff000000)) == UINT32_C(0x18000000)
        || (word & UINT32_C(0xff000000)) == UINT32_C(0x1c000000)
        || (word & UINT32_C(0xff000000)) == UINT32_C(0x58000000)
        || (word & UINT32_C(0xff000000)) == UINT32_C(0x5c000000)
        || (word & UINT32_C(0xff000000)) == UINT32_C(0x98000000)
        || (word & UINT32_C(0xff000000)) == UINT32_C(0x9c000000)
        || (word & UINT32_C(0xff000000)) == UINT32_C(0xd8000000)) {
        return decode_a64_load_literal(
            word, address, instruction, required_capabilities);
    }
    if ((word & UINT32_C(0x1f800000)) == UINT32_C(0x11000000)) {
        return decode_a64_add_sub_immediate(
            word, instruction, required_capabilities);
    }
    if ((word & UINT32_C(0x1f800000)) == UINT32_C(0x12800000)) {
        return decode_a64_move_wide(word, instruction, required_capabilities);
    }
    if ((word & UINT32_C(0x1f000000)) == UINT32_C(0x0a000000)) {
        return decode_a64_logical_register(
            word, instruction, required_capabilities);
    }
    if ((word & UINT32_C(0x3e000000)) == UINT32_C(0x08000000)) {
        return decode_a64_atomic_memory(
            word, instruction, required_capabilities);
    }
    if ((word & UINT32_C(0x3f200c00)) == UINT32_C(0x38200000)) {
        return decode_a64_lse_rmw(
            word, instruction, required_capabilities);
    }
    if ((word & UINT32_C(0x3f200c00)) == UINT32_C(0x19200400)) {
        return decode_a64_lse_rmw(
            word, instruction, required_capabilities);
    }
    if ((word & UINT32_C(0x3e000000)) == UINT32_C(0x28000000)) {
        return decode_a64_pair_memory(
            word, instruction, required_capabilities);
    }
    if ((word & UINT32_C(0x3e000000)) == UINT32_C(0x2c000000)) {
        return decode_a64_fp_pair_memory(
            word, instruction, required_capabilities);
    }
    if ((word & UINT32_C(0x3f200000)) == UINT32_C(0x3c000000)) {
        return decode_a64_fp_signed_memory(
            word, instruction, required_capabilities);
    }
    if ((word & UINT32_C(0x3f000000)) == UINT32_C(0x3d000000)) {
        return decode_a64_fp_unsigned_memory(
            word, instruction, required_capabilities);
    }
    if ((word & UINT32_C(0x3f200c00)) == UINT32_C(0x3c200800)) {
        return decode_a64_fp_register_memory(
            word, instruction, required_capabilities);
    }
    if ((word & UINT32_C(0x3f200c00)) == UINT32_C(0x38200800)) {
        return decode_a64_register_memory(
            word, instruction, required_capabilities);
    }
    if ((word & UINT32_C(0x3f000000)) == UINT32_C(0x39000000)) {
        return decode_a64_single_memory(
            word, 0, instruction, required_capabilities);
    }
    if ((word & UINT32_C(0x3f200c00)) == UINT32_C(0x38000000)) {
        return decode_a64_single_memory(
            word, 1, instruction, required_capabilities);
    }
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}

cdisasm_status cdisasm_arm_decode_core(
    uint32_t raw_instruction,
    uint64_t address,
    cdisasm_arm_mode mode,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities)
{
    if (instruction == NULL || required_capabilities == NULL) {
        return CDISASM_STATUS_INTERNAL_ERROR;
    }
    if (mode == CDISASM_ARM_MODE_A32) {
        return decode_a32(
            raw_instruction,
            address,
            instruction,
            required_capabilities);
    }
    if (mode == CDISASM_ARM_MODE_A64) {
        return decode_a64(
            raw_instruction,
            address,
            instruction,
            required_capabilities);
    }
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}
