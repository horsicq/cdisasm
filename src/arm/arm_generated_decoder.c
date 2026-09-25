#include "arm_generated_decoder.h"
#include "arm_pstate_msr.h"
#include "arm_generated_alias.h"
#include "arm_generated_operands.h"

#if USE_EXTRA_OPCODES

#include "generated/cdisasm_arm_isa_decode.inc"
#include "generated/cdisasm_arm_leaf_semantics.inc"
#include "generated/cdisasm_arm_leaf_requirements.inc"
#include "arm_mnemonic_pool_ids_generated.inc"

#include <string.h>

#define ARM_GEN_EVAL_STACK_SIZE 64u
#define ARM_GEN_SET_MAX_MEMBERS 3u
#define ARM_GEN_IDENTITY_FEATURE_MAX 8u
#define ARM_GEN_FIRST_EXTENDED_FEATURE_ID UINT16_C(36)

_Static_assert(
    CDISASM_ARM_FEATURE_PMULL
        >= ARM_GEN_FIRST_EXTENDED_FEATURE_ID
            + CDISASM_ARM_GEN_FEATURE_COUNT,
    "generated ISA feature map overlaps private FEAT_PMULL ID");

/* Arm 2026-06 FEAT_HINTE is the one instruction-file addition after the open
 * 2026-03 AARCHMRS baseline. Its public encoding was independently checked
 * against LLVM's upstream Armv9.6 implementation. */
#define ARM_GEN_HINTE_MASK UINT32_C(0xffd8f000)
#define ARM_GEN_HINTE_VALUE UINT32_C(0xd5002000)

#if CDISASM_ARM_GEN_FORM_ID_COUNT != CDISASM_ARM_GEN_LEAF_SEMANTICS_COUNT
#  error "ARM generated decode and semantics catalogs disagree"
#endif
#if CDISASM_ARM_GEN_FORM_ID_COUNT != CDISASM_ARM_REQGEN_FORM_COUNT
#  error "ARM generated decode and requirement catalogs disagree"
#endif

typedef enum arm_gen_value_kind {
    ARM_GEN_VALUE_SCALAR = 0,
    ARM_GEN_VALUE_PATTERN = 1,
    ARM_GEN_VALUE_BOOLEAN = 2,
    ARM_GEN_VALUE_FEATURE = 3,
    ARM_GEN_VALUE_SET = 4,
    ARM_GEN_VALUE_SLICE = 5
} arm_gen_value_kind;

typedef struct arm_gen_pattern {
    uint64_t value;
    uint64_t mask;
    uint8_t width;
} arm_gen_pattern;

typedef struct arm_gen_eval_value {
    uint64_t value;
    uint64_t mask;
    uint8_t width;
    uint8_t kind;
    uint8_t count;
    arm_gen_pattern member[ARM_GEN_SET_MAX_MEMBERS];
} arm_gen_eval_value;

static uint64_t arm_gen_width_mask(uint8_t width)
{
    if (width == 0u) {
        return UINT64_MAX;
    }
    if (width >= 64u) {
        return UINT64_MAX;
    }
    return (UINT64_C(1) << width) - UINT64_C(1);
}

static arm_gen_eval_value arm_gen_scalar(
    uint64_t value, uint64_t mask, uint8_t width, arm_gen_value_kind kind)
{
    arm_gen_eval_value result;

    memset(&result, 0, sizeof(result));
    result.value = value & arm_gen_width_mask(width);
    result.mask = mask & arm_gen_width_mask(width);
    result.width = width;
    result.kind = (uint8_t)kind;
    return result;
}

static int arm_gen_truth(const arm_gen_eval_value *value)
{
    return value->value != UINT64_C(0);
}

static int arm_gen_patterns_intersect(
    const arm_gen_eval_value *left,
    const arm_gen_eval_value *right)
{
    uint64_t common_mask = left->mask & right->mask;

    return ((left->value ^ right->value) & common_mask) == UINT64_C(0);
}

static cdisasm_arm_feature_id arm_gen_capability_id(uint32_t feature_id)
{
    switch (feature_id) {
        case CDISASM_ARM_GEN_FEATURE_FEAT_AA32BF16:
        case CDISASM_ARM_GEN_FEATURE_FEAT_BF16:
            return UINT16_C(34);
        case CDISASM_ARM_GEN_FEATURE_FEAT_ADVSIMD:
            return UINT16_C(5);
        case CDISASM_ARM_GEN_FEATURE_FEAT_BTI:
            return UINT16_C(21);
        case CDISASM_ARM_GEN_FEATURE_FEAT_CPA:
            return UINT16_C(28);
        case CDISASM_ARM_GEN_FEATURE_FEAT_CSSC:
            return UINT16_C(26);
        case CDISASM_ARM_GEN_FEATURE_FEAT_F64MM:
            return UINT16_C(33);
        case CDISASM_ARM_GEN_FEATURE_FEAT_FP:
            return UINT16_C(27);
        case CDISASM_ARM_GEN_FEATURE_FEAT_FP16:
            return UINT16_C(13);
        case CDISASM_ARM_GEN_FEATURE_FEAT_FP8:
            return UINT16_C(35);
        case CDISASM_ARM_GEN_FEATURE_FEAT_LOR:
            return UINT16_C(11);
        case CDISASM_ARM_GEN_FEATURE_FEAT_LRCPC:
        case CDISASM_ARM_GEN_FEATURE_FEAT_LRCPC2:
            return UINT16_C(12);
        case CDISASM_ARM_GEN_FEATURE_FEAT_LRCPC3:
            return UINT16_C(20);
        case CDISASM_ARM_GEN_FEATURE_FEAT_LS64:
        case CDISASM_ARM_GEN_FEATURE_FEAT_LS64_ACCDATA:
        case CDISASM_ARM_GEN_FEATURE_FEAT_LS64_V:
            return UINT16_C(25);
        case CDISASM_ARM_GEN_FEATURE_FEAT_LSE:
            return UINT16_C(10);
        case CDISASM_ARM_GEN_FEATURE_FEAT_LSE128:
            return UINT16_C(19);
        case CDISASM_ARM_GEN_FEATURE_FEAT_MOPS:
        case CDISASM_ARM_GEN_FEATURE_FEAT_MOPS_GO:
            return UINT16_C(24);
        case CDISASM_ARM_GEN_FEATURE_FEAT_MTE:
        case CDISASM_ARM_GEN_FEATURE_FEAT_MTE2:
            return UINT16_C(23);
        case CDISASM_ARM_GEN_FEATURE_FEAT_PAUTH:
        case CDISASM_ARM_GEN_FEATURE_FEAT_PAUTH_LR:
            return UINT16_C(22);
        case CDISASM_ARM_GEN_FEATURE_FEAT_SME:
            return UINT16_C(16);
        case CDISASM_ARM_GEN_FEATURE_FEAT_SME2:
            return UINT16_C(17);
        case CDISASM_ARM_GEN_FEATURE_FEAT_SME2P1:
            return UINT16_C(30);
        case CDISASM_ARM_GEN_FEATURE_FEAT_SME2P2:
            return UINT16_C(32);
        case CDISASM_ARM_GEN_FEATURE_FEAT_SVE:
            return UINT16_C(14);
        case CDISASM_ARM_GEN_FEATURE_FEAT_SVE2:
            return UINT16_C(15);
        case CDISASM_ARM_GEN_FEATURE_FEAT_SVE2P1:
            return UINT16_C(29);
        case CDISASM_ARM_GEN_FEATURE_FEAT_SVE2P2:
            return UINT16_C(31);
        default:
            return (cdisasm_arm_feature_id)(
                ARM_GEN_FIRST_EXTENDED_FEATURE_ID + feature_id);
    }
}

static int arm_gen_feature_available(
    const cdisasm_arm_capabilities *capabilities,
    uint32_t feature_id)
{
    if (feature_id >= CDISASM_ARM_GEN_FEATURE_COUNT) {
        return 0;
    }
    return cdisasm_arm_capabilities_has_feature(
        capabilities, arm_gen_capability_id(feature_id));
}

static int arm_gen_pstate_msr_admit(
    uint32_t word,
    const cdisasm_arm_capabilities *capabilities,
    int unrestricted_analysis)
{
    uint8_t field;
    uint8_t immediate;

    if (!arm_pstate_msr_decode_word(word, &field, &immediate)) {
        return 0;
    }
    (void)immediate;
    switch (field) {
        case CDISASM_ARM_PSTATE_FIELD_SPSEL:
        case CDISASM_ARM_PSTATE_FIELD_DAIFSET:
        case CDISASM_ARM_PSTATE_FIELD_DAIFCLR:
            return 1;
        case CDISASM_ARM_PSTATE_FIELD_PAN:
            return cdisasm_arm_capabilities_has_feature(
                capabilities, CDISASM_ARM_FEATURE_PAN);
        case CDISASM_ARM_PSTATE_FIELD_SVCRSM:
        case CDISASM_ARM_PSTATE_FIELD_SVCRZA:
        case CDISASM_ARM_PSTATE_FIELD_SVCRSMZA:
            return (capabilities->bitmap[0] & CDISASM_ARM_CAP_SME) != 0u;
        case CDISASM_ARM_PSTATE_FIELD_TCO:
            return (capabilities->bitmap[0] & CDISASM_ARM_CAP_MTE) != 0u;
        default:
            /* UAO, NMI, EBEP, SSBS and DIT are absent from named-CPU
             * profiles.  Do not infer their presence from a model year. */
            return unrestricted_analysis;
    }
}

static int arm_gen_leaf_requirements_admit(
    const cdisasm_arm_gen_leaf *leaf,
    const cdisasm_arm_capabilities *capabilities,
    int allow_unresolved_architecture)
{
    const cdisasm_arm_reqgen_form *requirements;
    size_t leaf_index;
    uint32_t feature_index;

    if (leaf == NULL || capabilities == NULL
        || leaf < cdisasm_arm_gen_leaves
        || leaf >= cdisasm_arm_gen_leaves + CDISASM_ARM_GEN_FORM_ID_COUNT) {
        return 0;
    }
    leaf_index = (size_t)(leaf - cdisasm_arm_gen_leaves);
    requirements = &cdisasm_arm_reqgen_forms[leaf_index];
    if (requirements->minimum_arch_bit == UINT8_MAX) {
        if (!allow_unresolved_architecture) {
            return 0;
        }
    } else if (!cdisasm_arm_capabilities_has_feature(
                   capabilities, requirements->minimum_arch_bit)) {
        return 0;
    }
    if ((uint64_t)requirements->first_feature
            + requirements->feature_count
        > sizeof(cdisasm_arm_reqgen_feature_ids)
            / sizeof(cdisasm_arm_reqgen_feature_ids[0])) {
        return 0;
    }
    for (feature_index = 0u;
         feature_index < requirements->feature_count;
         ++feature_index) {
        uint32_t generated_feature_id =
            cdisasm_arm_reqgen_feature_ids[
                requirements->first_feature + feature_index];

        if (!arm_gen_feature_available(
                capabilities, generated_feature_id)) {
            return 0;
        }
    }
    return 1;
}

static int arm_gen_leaf_encoding_valid(
    const cdisasm_arm_gen_leaf *leaf,
    uint32_t raw_instruction,
    cdisasm_arm_mode mode)
{
    uint32_t register_number;

    if (leaf == NULL) {
        return 0;
    }

    /*
     * SYSP encodes an X register pair in Rt.  Architectural register pairs
     * start at an even register; 31 is the separate XZR/default spelling.
     * The public AARCHMRS leaf currently has no decode-time assertion for
     * this constraint, so retain it beside the generated leaf admission.
     */
    if (mode == CDISASM_ARM_MODE_A64
        && leaf->form_id == UINT16_C(4506)) {
        register_number = raw_instruction & UINT32_C(31);
        if (register_number != UINT32_C(31)
            && (register_number & UINT32_C(1)) != 0u) {
            return 0;
        }
    }
    /* FEAT_D128 MSRR/MRRS likewise encode the first of an even/odd X pair.
     * X30,XZR is legal; a starting XZR or any odd Rt is not. */
    if (mode == CDISASM_ARM_MODE_A64
        && (leaf->form_id == UINT16_C(4507)
            || leaf->form_id == UINT16_C(4508))) {
        register_number = raw_instruction & UINT32_C(31);
        if ((register_number & UINT32_C(1)) != 0u) {
            return 0;
        }
    }
    return 1;
}

static int arm_gen_push(
    arm_gen_eval_value *stack,
    size_t *stack_size,
    arm_gen_eval_value value)
{
    if (*stack_size >= ARM_GEN_EVAL_STACK_SIZE) {
        return 0;
    }
    stack[(*stack_size)++] = value;
    return 1;
}

static int arm_gen_pop(
    arm_gen_eval_value *stack,
    size_t *stack_size,
    arm_gen_eval_value *value)
{
    if (*stack_size == 0u) {
        return 0;
    }
    *value = stack[--(*stack_size)];
    return 1;
}

static int arm_gen_eval_program(
    uint32_t program_id,
    uint32_t word,
    const cdisasm_arm_capabilities *capabilities,
    int *result)
{
    arm_gen_eval_value stack[ARM_GEN_EVAL_STACK_SIZE];
    const cdisasm_arm_gen_program *program;
    size_t stack_size = 0u;
    uint32_t index;

    if (result == NULL || capabilities == NULL) {
        return 0;
    }
    if (program_id == CDISASM_ARM_GEN_NONE) {
        *result = 1;
        return 1;
    }
    if (program_id >= sizeof(cdisasm_arm_gen_programs)
            / sizeof(cdisasm_arm_gen_programs[0])) {
        return 0;
    }
    program = &cdisasm_arm_gen_programs[program_id];
    if (program->first_instruction + program->instruction_count
        > sizeof(cdisasm_arm_gen_bytecode)
            / sizeof(cdisasm_arm_gen_bytecode[0])) {
        return 0;
    }
    for (index = 0u; index < program->instruction_count; ++index) {
        const cdisasm_arm_gen_bc *instruction =
            &cdisasm_arm_gen_bytecode[program->first_instruction + index];
        arm_gen_eval_value left;
        arm_gen_eval_value right;
        arm_gen_eval_value value;

        switch (instruction->opcode) {
            case CDISASM_ARM_GEN_BC_PUSH_BOOL:
                if (!arm_gen_push(
                        stack, &stack_size,
                        arm_gen_scalar(
                            instruction->a != 0, UINT64_MAX, 1u,
                            ARM_GEN_VALUE_BOOLEAN))) {
                    return 0;
                }
                break;
            case CDISASM_ARM_GEN_BC_PUSH_FIELD: {
                uint8_t start;
                uint8_t width;
                uint64_t mask;

                if (instruction->a < 0 || instruction->a >= 32
                    || instruction->b <= 0 || instruction->b > 32
                    || instruction->a + instruction->b > 32) {
                    return 0;
                }
                start = (uint8_t)instruction->a;
                width = (uint8_t)instruction->b;
                mask = arm_gen_width_mask(width);
                if (!arm_gen_push(
                        stack, &stack_size,
                        arm_gen_scalar(
                            ((uint64_t)word >> start) & mask,
                            mask, width, ARM_GEN_VALUE_SCALAR))) {
                    return 0;
                }
                break;
            }
            case CDISASM_ARM_GEN_BC_PUSH_FEATURE:
                if (instruction->a < 0
                    || (uint32_t)instruction->a
                        >= CDISASM_ARM_GEN_FEATURE_COUNT
                    || !arm_gen_push(
                        stack, &stack_size,
                        arm_gen_scalar(
                            (uint32_t)instruction->a,
                            UINT64_MAX, 32u, ARM_GEN_VALUE_FEATURE))) {
                    return 0;
                }
                break;
            case CDISASM_ARM_GEN_BC_PUSH_VALUE: {
                const cdisasm_arm_gen_value *pattern;

                if (instruction->a < 0
                    || (size_t)instruction->a
                        >= sizeof(cdisasm_arm_gen_values)
                            / sizeof(cdisasm_arm_gen_values[0])) {
                    return 0;
                }
                pattern = &cdisasm_arm_gen_values[instruction->a];
                if (!arm_gen_push(
                        stack, &stack_size,
                        arm_gen_scalar(
                            pattern->value, pattern->mask, pattern->width,
                            ARM_GEN_VALUE_PATTERN))) {
                    return 0;
                }
                break;
            }
            case CDISASM_ARM_GEN_BC_PUSH_INTEGER:
                if (!arm_gen_push(
                        stack, &stack_size,
                        arm_gen_scalar(
                            (uint64_t)(int64_t)instruction->a,
                            UINT64_MAX, 64u, ARM_GEN_VALUE_SCALAR))) {
                    return 0;
                }
                break;
            case CDISASM_ARM_GEN_BC_MAKE_SET: {
                size_t member_count;
                size_t first_member;
                size_t member_index;

                if (instruction->a < 0
                    || (uint32_t)instruction->a > ARM_GEN_SET_MAX_MEMBERS) {
                    return 0;
                }
                member_count = (size_t)instruction->a;
                if (stack_size < member_count) {
                    return 0;
                }
                first_member = stack_size - member_count;
                memset(&value, 0, sizeof(value));
                value.kind = ARM_GEN_VALUE_SET;
                value.count = (uint8_t)member_count;
                for (member_index = 0u;
                     member_index < member_count;
                     ++member_index) {
                    const arm_gen_eval_value *member =
                        &stack[first_member + member_index];

                    if (member->kind == ARM_GEN_VALUE_SET
                        || member->kind == ARM_GEN_VALUE_SLICE) {
                        return 0;
                    }
                    value.member[member_index].value = member->value;
                    value.member[member_index].mask = member->mask;
                    value.member[member_index].width = member->width;
                }
                stack_size = first_member;
                if (!arm_gen_push(stack, &stack_size, value)) {
                    return 0;
                }
                break;
            }
            case CDISASM_ARM_GEN_BC_MAKE_SLICE:
                if (!arm_gen_pop(stack, &stack_size, &right)
                    || !arm_gen_pop(stack, &stack_size, &left)
                    || left.value > 63u || right.value > left.value) {
                    return 0;
                }
                value = arm_gen_scalar(
                    left.value, right.value, 0u, ARM_GEN_VALUE_SLICE);
                if (!arm_gen_push(stack, &stack_size, value)) {
                    return 0;
                }
                break;
            case CDISASM_ARM_GEN_BC_SQUARE: {
                uint8_t high;
                uint8_t low;
                uint8_t width;

                if (instruction->a != 1
                    || !arm_gen_pop(stack, &stack_size, &right)
                    || !arm_gen_pop(stack, &stack_size, &left)
                    || right.kind != ARM_GEN_VALUE_SLICE) {
                    return 0;
                }
                high = (uint8_t)right.value;
                low = (uint8_t)right.mask;
                width = (uint8_t)(high - low + 1u);
                value = arm_gen_scalar(
                    left.value >> low,
                    arm_gen_width_mask(width), width,
                    ARM_GEN_VALUE_SCALAR);
                if (!arm_gen_push(stack, &stack_size, value)) {
                    return 0;
                }
                break;
            }
            case CDISASM_ARM_GEN_BC_UNARY_LOGICAL_NOT:
                if (!arm_gen_pop(stack, &stack_size, &value)) {
                    return 0;
                }
                value = arm_gen_scalar(
                    !arm_gen_truth(&value), UINT64_MAX, 1u,
                    ARM_GEN_VALUE_BOOLEAN);
                if (!arm_gen_push(stack, &stack_size, value)) {
                    return 0;
                }
                break;
            case CDISASM_ARM_GEN_BC_BINARY_AND:
            case CDISASM_ARM_GEN_BC_BINARY_OR:
            case CDISASM_ARM_GEN_BC_BINARY_EQ:
            case CDISASM_ARM_GEN_BC_BINARY_NE:
            case CDISASM_ARM_GEN_BC_BINARY_IN:
                if (!arm_gen_pop(stack, &stack_size, &right)
                    || !arm_gen_pop(stack, &stack_size, &left)) {
                    return 0;
                }
                if (instruction->opcode == CDISASM_ARM_GEN_BC_BINARY_AND) {
                    value.value = arm_gen_truth(&left)
                        && arm_gen_truth(&right);
                } else if (instruction->opcode
                    == CDISASM_ARM_GEN_BC_BINARY_OR) {
                    value.value = arm_gen_truth(&left)
                        || arm_gen_truth(&right);
                } else if (instruction->opcode
                    == CDISASM_ARM_GEN_BC_BINARY_IN) {
                    size_t member_index;

                    value.value = 0u;
                    if (right.kind != ARM_GEN_VALUE_SET) {
                        return 0;
                    }
                    for (member_index = 0u;
                         member_index < right.count;
                         ++member_index) {
                        arm_gen_eval_value member = arm_gen_scalar(
                            right.member[member_index].value,
                            right.member[member_index].mask,
                            right.member[member_index].width,
                            ARM_GEN_VALUE_PATTERN);
                        if (arm_gen_patterns_intersect(&left, &member)) {
                            value.value = 1u;
                            break;
                        }
                    }
                } else {
                    value.value = arm_gen_patterns_intersect(&left, &right);
                    if (instruction->opcode
                        == CDISASM_ARM_GEN_BC_BINARY_NE) {
                        value.value = !value.value;
                    }
                }
                value.mask = UINT64_MAX;
                value.width = 1u;
                value.kind = ARM_GEN_VALUE_BOOLEAN;
                value.count = 0u;
                if (!arm_gen_push(stack, &stack_size, value)) {
                    return 0;
                }
                break;
            case CDISASM_ARM_GEN_BC_CALL: {
                uint32_t parameter_count =
                    ((uint32_t)instruction->b >> 16) & UINT32_C(0xffff);
                uint32_t argument_count =
                    (uint32_t)instruction->b & UINT32_C(0xffff);

                if (instruction->a
                        != CDISASM_ARM_GEN_FUNCTION_ISFEATUREIMPLEMENTED
                    || parameter_count != 0u || argument_count != 1u
                    || !arm_gen_pop(stack, &stack_size, &value)
                    || value.kind != ARM_GEN_VALUE_FEATURE) {
                    return 0;
                }
                value = arm_gen_scalar(
                    arm_gen_feature_available(
                        capabilities, (uint32_t)value.value),
                    UINT64_MAX, 1u, ARM_GEN_VALUE_BOOLEAN);
                if (!arm_gen_push(stack, &stack_size, value)) {
                    return 0;
                }
                break;
            }
            default:
                /* Canonical decode-tree predicates deliberately use only the
                 * closed subset above. Other bytecodes belong to alias
                 * preference formatting and are not approximated here. */
                return 0;
        }
    }
    if (stack_size != 1u) {
        return 0;
    }
    *result = arm_gen_truth(&stack[0]);
    return 1;
}

static int arm_gen_collect_condition_features(
    uint32_t program_id,
    cdisasm_arm_feature_id feature_ids[ARM_GEN_IDENTITY_FEATURE_MAX],
    size_t *feature_count)
{
    const cdisasm_arm_gen_program *program;
    uint32_t index;

    if (feature_count == NULL) {
        return 0;
    }
    if (program_id == CDISASM_ARM_GEN_NONE) {
        return 1;
    }
    if (program_id >= sizeof(cdisasm_arm_gen_programs)
            / sizeof(cdisasm_arm_gen_programs[0])) {
        return 0;
    }
    program = &cdisasm_arm_gen_programs[program_id];
    if (program->first_instruction + program->instruction_count
        > sizeof(cdisasm_arm_gen_bytecode)
            / sizeof(cdisasm_arm_gen_bytecode[0])) {
        return 0;
    }
    for (index = 0u; index < program->instruction_count; ++index) {
        const cdisasm_arm_gen_bc *instruction =
            &cdisasm_arm_gen_bytecode[program->first_instruction + index];
        cdisasm_arm_feature_id feature_id;
        size_t feature_index;

        if (instruction->opcode != CDISASM_ARM_GEN_BC_PUSH_FEATURE) {
            continue;
        }
        if (instruction->a < 0
            || (uint32_t)instruction->a >= CDISASM_ARM_GEN_FEATURE_COUNT) {
            return 0;
        }
        feature_id = arm_gen_capability_id((uint32_t)instruction->a);
        for (feature_index = 0u;
             feature_index < *feature_count;
             ++feature_index) {
            if (feature_ids[feature_index] == feature_id) {
                break;
            }
        }
        if (feature_index != *feature_count) {
            continue;
        }
        if (*feature_count >= ARM_GEN_IDENTITY_FEATURE_MAX) {
            return 0;
        }
        feature_ids[(*feature_count)++] = feature_id;
    }
    return 1;
}

static uint32_t arm_gen_find_leaf(
    uint32_t node_index,
    uint32_t word,
    uint16_t width,
    const cdisasm_arm_capabilities *capabilities,
    int is_root);

static int arm_gen_collect_matching_tree_features(
    uint32_t node_index,
    uint32_t word,
    uint16_t width,
    int is_root,
    cdisasm_arm_feature_id feature_ids[ARM_GEN_IDENTITY_FEATURE_MAX],
    size_t *feature_count,
    uint32_t depth)
{
    const cdisasm_arm_gen_node *node;
    uint32_t child;
    uint32_t sibling_count = 0u;

    if (node_index >= CDISASM_ARM_GEN_NODE_COUNT
        || depth >= CDISASM_ARM_GEN_NODE_COUNT) {
        return 0;
    }
    node = &cdisasm_arm_gen_nodes[node_index];
    if ((!is_root && node->width != width)
        || (word & node->resolved_mask) != node->resolved_value) {
        return 1;
    }
    if (!arm_gen_collect_condition_features(
            node->condition_program_id, feature_ids, feature_count)) {
        return 0;
    }
    child = node->first_child;
    while (child != CDISASM_ARM_GEN_NONE) {
        if (child >= CDISASM_ARM_GEN_NODE_COUNT
            || sibling_count++ >= CDISASM_ARM_GEN_NODE_COUNT
            || !arm_gen_collect_matching_tree_features(
                child, word, width, 0,
                feature_ids, feature_count, depth + UINT32_C(1))) {
            return 0;
        }
        child = cdisasm_arm_gen_nodes[child].next_sibling;
    }
    return 1;
}

/* Formatting has no CPU profile.  A generated form identity is valid when
 * one consistent assignment of all feature atoms on mask-compatible decode
 * branches makes the canonical tree select that exact leaf.  The pinned
 * catalog uses at most three distinct relevant atoms; keep a small explicit
 * ceiling so a future unexpectedly complex predicate fails closed instead
 * of causing an unbounded formatter search. */
static int arm_gen_form_identity_admitted(
    uint32_t leaf_index,
    uint32_t instruction_set,
    uint32_t word,
    uint16_t width)
{
    cdisasm_arm_feature_id
        feature_ids[ARM_GEN_IDENTITY_FEATURE_MAX];
    size_t feature_count = 0u;
    uint32_t assignment;
    uint32_t assignment_count;
    uint32_t root_index;

    if (instruction_set >= sizeof(cdisasm_arm_gen_roots)
            / sizeof(cdisasm_arm_gen_roots[0])) {
        return 0;
    }
    root_index = cdisasm_arm_gen_roots[instruction_set];
    if (!arm_gen_collect_matching_tree_features(
            root_index, word, width, 1,
            feature_ids, &feature_count, 0u)) {
        return 0;
    }

    assignment_count = UINT32_C(1) << feature_count;
    for (assignment = 0u;
         assignment < assignment_count;
         ++assignment) {
        cdisasm_arm_capabilities capabilities =
            CDISASM_ARM_CAPABILITIES_NONE_INITIALIZER;
        size_t feature_index;

        for (feature_index = 0u;
             feature_index < feature_count;
             ++feature_index) {
            if ((assignment & (UINT32_C(1) << feature_index)) != 0u
                && !cdisasm_arm_capabilities_add_feature(
                    &capabilities, feature_ids[feature_index])) {
                return 0;
            }
        }
        if (arm_gen_find_leaf(
                root_index, word, width, &capabilities, 1)
            == leaf_index) {
            return 1;
        }
    }
    return 0;
}

static int arm_gen_node_matches(
    const cdisasm_arm_gen_node *node,
    uint32_t word,
    uint16_t width,
    const cdisasm_arm_capabilities *capabilities,
    int allow_width_transition)
{
    int condition;

    if (!allow_width_transition && node->width != width) {
        return 0;
    }
    if ((word & node->resolved_mask) != node->resolved_value) {
        return 0;
    }
    return arm_gen_eval_program(
        node->condition_program_id, word, capabilities, &condition)
        && condition;
}

static uint32_t arm_gen_find_leaf(
    uint32_t node_index,
    uint32_t word,
    uint16_t width,
    const cdisasm_arm_capabilities *capabilities,
    int is_root)
{
    const cdisasm_arm_gen_node *node;
    uint32_t child;

    if (node_index >= CDISASM_ARM_GEN_NODE_COUNT) {
        return CDISASM_ARM_GEN_NONE;
    }
    node = &cdisasm_arm_gen_nodes[node_index];
    if (!arm_gen_node_matches(
            node, word, width, capabilities, is_root)) {
        return CDISASM_ARM_GEN_NONE;
    }
    child = node->first_child;
    while (child != CDISASM_ARM_GEN_NONE) {
        uint32_t result = arm_gen_find_leaf(
            child, word, width, capabilities, 0);

        if (result != CDISASM_ARM_GEN_NONE) {
            return result;
        }
        if (child >= CDISASM_ARM_GEN_NODE_COUNT) {
            return CDISASM_ARM_GEN_NONE;
        }
        child = cdisasm_arm_gen_nodes[child].next_sibling;
    }
    return node->kind == CDISASM_ARM_GEN_LEAF
        ? node->leaf_index : CDISASM_ARM_GEN_NONE;
}

static int arm_gen_mode_index(cdisasm_arm_mode mode, uint32_t *index)
{
    switch (mode) {
        case CDISASM_ARM_MODE_A32:
            *index = CDISASM_ARM_GEN_A32;
            return 1;
        case CDISASM_ARM_MODE_T32:
            *index = CDISASM_ARM_GEN_T32;
            return 1;
        case CDISASM_ARM_MODE_A64:
            *index = CDISASM_ARM_GEN_A64;
            return 1;
        default:
            return 0;
    }
}

static int64_t arm_gen_sign_extend(uint64_t value, unsigned int width)
{
    uint64_t sign = UINT64_C(1) << (width - 1u);
    uint64_t mask = (UINT64_C(1) << width) - UINT64_C(1);

    value &= mask;
    return (value & sign) != 0u
        ? -(int64_t)(((~value) + UINT64_C(1)) & mask)
        : (int64_t)value;
}

static uint32_t arm_gen_semantic_word(
    uint32_t raw_instruction,
    cdisasm_arm_mode mode,
    uint32_t opcode_size)
{
    if (mode == CDISASM_ARM_MODE_T32 && opcode_size == 4u) {
        return (raw_instruction << 16) | (raw_instruction >> 16);
    }
    return raw_instruction;
}

static void arm_gen_apply_wide_block_address(
    uint32_t word,
    cdisasm_arm_instruction *instruction)
{
    instruction->instruction_flags |=
        (word & UINT32_C(0x01000000)) != 0u
            ? CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
            : CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX;
    instruction->instruction_flags |=
        (word & UINT32_C(0x00800000)) != 0u
            ? CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT
            : CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT;
    if ((word & UINT32_C(0x00200000)) != 0u) {
        instruction->instruction_flags |=
            CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
    }
}

static void arm_gen_apply_leaf_semantics(
    const cdisasm_arm_gen_leaf *leaf,
    uint32_t raw_instruction,
    uint64_t address,
    cdisasm_arm_mode mode,
    cdisasm_arm_instruction *instruction)
{
    const cdisasm_arm_gen_leaf_semantics *semantics;
    size_t leaf_index;
    int64_t displacement = 0;
    uint64_t target_base = address;
    uint16_t first;
    uint16_t second;
    uint32_t sign;
    uint32_t j1;
    uint32_t j2;
    uint32_t i1;
    uint32_t i2;
    uint32_t encoded;
    uint32_t semantic_word;

    if (leaf == NULL || instruction == NULL
        || leaf < cdisasm_arm_gen_leaves
        || leaf >= cdisasm_arm_gen_leaves + CDISASM_ARM_GEN_FORM_ID_COUNT) {
        return;
    }
    leaf_index = (size_t)(leaf - cdisasm_arm_gen_leaves);
    semantics = &cdisasm_arm_gen_leaf_semantics_table[leaf_index];
    instruction->opcode_groups |= semantics->opcode_groups;
    instruction->instruction_flags |= semantics->instruction_flags;

    semantic_word = arm_gen_semantic_word(
        raw_instruction, mode, instruction->opcode_size);

    switch (semantics->dynamic_kind) {
        case CDISASM_ARM_GEN_DYNAMIC_A64_LSE_ORDER:
            if ((raw_instruction & UINT32_C(0x00800000)) != 0u
                && (raw_instruction & UINT32_C(0x1f))
                    != UINT32_C(0x1f)) {
                instruction->instruction_flags |=
                    CDISASM_ARM_INSTRUCTION_FLAG_ACQUIRE;
            }
            if ((raw_instruction & UINT32_C(0x00400000)) != 0u) {
                instruction->instruction_flags |=
                    CDISASM_ARM_INSTRUCTION_FLAG_RELEASE;
            }
            break;
        case CDISASM_ARM_GEN_DYNAMIC_A32_GPR_BLOCK:
            arm_gen_apply_wide_block_address(semantic_word, instruction);
            if ((semantic_word & UINT32_C(0x00400000)) != 0u) {
                instruction->instruction_flags |=
                    CDISASM_ARM_INSTRUCTION_FLAG_USER_REGISTERS;
            }
            if ((semantic_word & UINT32_C(0x00108000))
                    == UINT32_C(0x00108000)) {
                instruction->opcode_groups |= CDISASM_GROUP_JUMP;
            }
            break;
        case CDISASM_ARM_GEN_DYNAMIC_T16_GPR_BLOCK: {
            uint32_t rn = (semantic_word >> 8) & UINT32_C(7);
            uint32_t register_list = semantic_word & UINT32_C(0xff);
            int load = (semantic_word & UINT32_C(0x0800)) != 0u;

            instruction->instruction_flags |=
                CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT;
            if (!load
                || (register_list & (UINT32_C(1) << rn)) == 0u) {
                instruction->instruction_flags |=
                    CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK;
            }
            break;
        }
        case CDISASM_ARM_GEN_DYNAMIC_T32_GPR_BLOCK:
            arm_gen_apply_wide_block_address(semantic_word, instruction);
            if ((semantic_word & UINT32_C(0x00108000))
                    == UINT32_C(0x00108000)) {
                instruction->opcode_groups |= CDISASM_GROUP_JUMP;
            }
            break;
        case CDISASM_ARM_GEN_DYNAMIC_AA32_FP_BLOCK:
            arm_gen_apply_wide_block_address(semantic_word, instruction);
            break;
        default:
            break;
    }

    if (mode == CDISASM_ARM_MODE_A32
        && instruction->condition <= CDISASM_ARM_CONDITION_LE) {
        instruction->opcode_groups |= CDISASM_GROUP_CONDITIONAL;
    }
    if (instruction->name_id == CDISASM_ARM_NAME_BX) {
        unsigned int encoded_register = mode == CDISASM_ARM_MODE_A32
            ? raw_instruction & 15u
            : (raw_instruction >> 3) & 15u;

        if (encoded_register == 14u) {
            instruction->opcode_groups |= CDISASM_GROUP_RETURN;
        }
    }

    first = (uint16_t)raw_instruction;
    second = (uint16_t)(raw_instruction >> 16);
    switch (semantics->target_kind) {
        case CDISASM_ARM_GEN_TARGET_NONE:
            return;
        case CDISASM_ARM_GEN_TARGET_A32_BRANCH24:
            displacement = arm_gen_sign_extend(
                ((uint64_t)raw_instruction & UINT64_C(0x00ffffff)) << 2,
                26u);
            target_base += UINT64_C(8);
            break;
        case CDISASM_ARM_GEN_TARGET_A32_BLX24:
            encoded = ((raw_instruction & UINT32_C(0x00ffffff)) << 2)
                | ((raw_instruction >> 23) & UINT32_C(2));
            displacement = arm_gen_sign_extend(encoded, 26u);
            target_base += UINT64_C(8);
            break;
        case CDISASM_ARM_GEN_TARGET_T16_CB:
            displacement = (int64_t)(
                ((uint32_t)(first & UINT16_C(0x0200)) >> 3)
                | ((uint32_t)(first & UINT16_C(0x00f8)) >> 2));
            target_base += UINT64_C(4);
            break;
        case CDISASM_ARM_GEN_TARGET_T16_COND8:
            instruction->condition =
                (cdisasm_arm_condition)((first >> 8) & 15u);
            displacement = arm_gen_sign_extend(
                (uint64_t)(first & UINT16_C(0x00ff)) << 1,
                9u);
            target_base += UINT64_C(4);
            break;
        case CDISASM_ARM_GEN_TARGET_T16_BRANCH11:
            displacement = arm_gen_sign_extend(
                (uint64_t)(first & UINT16_C(0x07ff)) << 1,
                12u);
            target_base += UINT64_C(4);
            break;
        case CDISASM_ARM_GEN_TARGET_T32_COND:
            sign = (first >> 10) & 1u;
            j1 = (second >> 13) & 1u;
            j2 = (second >> 11) & 1u;
            encoded = (sign << 20)
                | (j2 << 19)
                | (j1 << 18)
                | ((uint32_t)(first & UINT16_C(0x003f)) << 12)
                | ((uint32_t)(second & UINT16_C(0x07ff)) << 1);
            instruction->condition =
                (cdisasm_arm_condition)((first >> 6) & 15u);
            displacement = arm_gen_sign_extend(encoded, 21u);
            target_base += UINT64_C(4);
            break;
        case CDISASM_ARM_GEN_TARGET_T32_BRANCH:
        case CDISASM_ARM_GEN_TARGET_T32_BL:
            sign = (first >> 10) & 1u;
            j1 = (second >> 13) & 1u;
            j2 = (second >> 11) & 1u;
            i1 = (j1 ^ sign) ^ 1u;
            i2 = (j2 ^ sign) ^ 1u;
            encoded = (sign << 24)
                | (i1 << 23)
                | (i2 << 22)
                | ((uint32_t)(first & UINT16_C(0x03ff)) << 12)
                | ((uint32_t)(second & UINT16_C(0x07ff)) << 1);
            displacement = arm_gen_sign_extend(encoded, 25u);
            target_base += UINT64_C(4);
            break;
        case CDISASM_ARM_GEN_TARGET_T32_BLX:
            sign = (first >> 10) & 1u;
            j1 = (second >> 13) & 1u;
            j2 = (second >> 11) & 1u;
            i1 = (j1 ^ sign) ^ 1u;
            i2 = (j2 ^ sign) ^ 1u;
            encoded = (sign << 24)
                | (i1 << 23)
                | (i2 << 22)
                | ((uint32_t)(first & UINT16_C(0x03ff)) << 12)
                | ((uint32_t)(second & UINT16_C(0x07fe)) << 1);
            displacement = arm_gen_sign_extend(encoded, 25u);
            target_base = (address + UINT64_C(4)) & ~UINT64_C(3);
            break;
        case CDISASM_ARM_GEN_TARGET_A64_COND19:
            instruction->condition =
                (cdisasm_arm_condition)(raw_instruction & 15u);
            displacement = arm_gen_sign_extend(
                ((uint64_t)(raw_instruction >> 5) & UINT64_C(0x7ffff))
                    << 2,
                21u);
            break;
        case CDISASM_ARM_GEN_TARGET_A64_BRANCH26:
            displacement = arm_gen_sign_extend(
                ((uint64_t)raw_instruction & UINT64_C(0x03ffffff)) << 2,
                28u);
            break;
        case CDISASM_ARM_GEN_TARGET_A64_COMPARE19:
            displacement = arm_gen_sign_extend(
                ((uint64_t)(raw_instruction >> 5) & UINT64_C(0x7ffff))
                    << 2,
                21u);
            break;
        case CDISASM_ARM_GEN_TARGET_A64_TEST14:
            displacement = arm_gen_sign_extend(
                ((uint64_t)(raw_instruction >> 5) & UINT64_C(0x3fff))
                    << 2,
                16u);
            break;
        case CDISASM_ARM_GEN_TARGET_A64_COMPARE9:
            displacement = arm_gen_sign_extend(
                ((uint64_t)(raw_instruction >> 5) & UINT64_C(0x1ff))
                    << 2,
                11u);
            break;
        default:
            return;
    }
    instruction->branch_target = target_base + (uint64_t)displacement;
}

cdisasm_status cdisasm_arm_decode_generated_priority(
    uint32_t raw_instruction,
    uint32_t opcode_size,
    uint64_t address,
    cdisasm_arm_mode mode,
    cdisasm_arm_instruction *instruction)
{
    uint32_t immediate;

    if (instruction == NULL || mode != CDISASM_ARM_MODE_A64
        || opcode_size != 4u
        || (raw_instruction & ARM_GEN_HINTE_MASK)
            != ARM_GEN_HINTE_VALUE) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    /* This excluded progression retains generic MSR/MRS system-register
     * meaning and must fall through to the pre-existing decoder. */
    if (((raw_instruction >> 21) & UINT32_C(1)) == 0u
        && ((raw_instruction >> 16) & UINT32_C(7)) == 3u
        && (raw_instruction & UINT32_C(31)) == UINT32_C(31)) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    immediate = ((raw_instruction >> 21) & UINT32_C(1)) << 15;
    immediate |= ((raw_instruction >> 16) & UINT32_C(7)) << 12;
    immediate |= ((raw_instruction >> 5) & UINT32_C(127)) << 5;
    immediate |= raw_instruction & UINT32_C(31);

    memset(instruction, 0, sizeof(*instruction));
    instruction->address = address;
    instruction->opcode_size = opcode_size;
    instruction->raw_instruction = raw_instruction;
    instruction->name_id = CDISASM_ARM_NAME_HINTE;
    instruction->condition = CDISASM_ARM_CONDITION_AL;
    instruction->isa_id = CDISASM_ARM_ISA_A64;
    instruction->form_id = CDISASM_ARM_FORM_HINTE;
    instruction->instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK;
    instruction->operand_count = 1u;
    instruction->operand[0].type = CDISASM_OPERAND_IMMEDIATE;
    instruction->operand[0].size = 2u;
    instruction->operand[0].access = CDISASM_OPERAND_ACCESS_READ;
    instruction->operand[0].imm = immediate;
    return CDISASM_STATUS_OK;
}

static const cdisasm_arm_gen_leaf *arm_gen_lookup_leaf(
    uint32_t raw_instruction,
    uint32_t opcode_size,
    cdisasm_arm_mode mode,
    const cdisasm_arm_capabilities *capabilities)
{
    uint32_t normalized_word = raw_instruction;
    uint32_t root_index;
    uint32_t leaf_index;
    uint32_t instruction_set;
    uint16_t width;

    if (capabilities == NULL
        || !arm_gen_mode_index(mode, &instruction_set)) {
        return NULL;
    }
    if (mode == CDISASM_ARM_MODE_T32) {
        if (opcode_size == 2u) {
            normalized_word &= UINT32_C(0xffff);
            width = 16u;
        } else if (opcode_size == 4u) {
            normalized_word = (raw_instruction << 16)
                | (raw_instruction >> 16);
            width = 32u;
        } else {
            return NULL;
        }
    } else {
        if (opcode_size != 4u) {
            return NULL;
        }
        width = 32u;
    }
    root_index = cdisasm_arm_gen_roots[instruction_set];
    leaf_index = arm_gen_find_leaf(
        root_index, normalized_word, width, capabilities, 1);
    if (leaf_index == CDISASM_ARM_GEN_NONE
        || leaf_index >= sizeof(cdisasm_arm_gen_leaves)
            / sizeof(cdisasm_arm_gen_leaves[0])) {
        return NULL;
    }
    return &cdisasm_arm_gen_leaves[leaf_index];
}

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    const cdisasm_arm_gen_leaf *leaf;
    const cdisasm_arm_gen_node *node;
    uint32_t leaf_index;
    uint32_t instruction_set;
    uint32_t word;
    uint16_t width;
    cdisasm_arm_mode mode;

    if (instruction == NULL
        || instruction->form_id == CDISASM_ARM_FORM_NONE
        || instruction->form_id > CDISASM_ARM_GEN_FORM_ID_COUNT) {
        return 0;
    }
    word = instruction->raw_instruction;
    switch (instruction->isa_id) {
        case CDISASM_ARM_ISA_A32:
            if (instruction->opcode_size != 4u) {
                return 0;
            }
            instruction_set = CDISASM_ARM_GEN_A32;
            width = 32u;
            mode = CDISASM_ARM_MODE_A32;
            break;
        case CDISASM_ARM_ISA_T32:
            instruction_set = CDISASM_ARM_GEN_T32;
            if (instruction->opcode_size == 2u) {
                if ((word & UINT32_C(0xffff0000)) != 0u) {
                    return 0;
                }
                width = 16u;
            } else if (instruction->opcode_size == 4u) {
                word = (word << 16) | (word >> 16);
                width = 32u;
            } else {
                return 0;
            }
            mode = CDISASM_ARM_MODE_T32;
            break;
        case CDISASM_ARM_ISA_A64:
            if (instruction->opcode_size != 4u) {
                return 0;
            }
            instruction_set = CDISASM_ARM_GEN_A64;
            width = 32u;
            mode = CDISASM_ARM_MODE_A64;
            break;
        default:
            return 0;
    }

    leaf_index = (uint32_t)instruction->form_id - UINT32_C(1);
    leaf = &cdisasm_arm_gen_leaves[leaf_index];
    if (leaf->form_id != instruction->form_id
        || leaf->node_index >= CDISASM_ARM_GEN_NODE_COUNT) {
        return 0;
    }
    node = &cdisasm_arm_gen_nodes[leaf->node_index];
    return node->kind == CDISASM_ARM_GEN_LEAF
        && node->leaf_index == leaf_index
        && node->instruction_set == instruction_set
        && node->width == width
        && (word & node->resolved_mask) == node->resolved_value
        && arm_gen_form_identity_admitted(
            leaf_index, instruction_set, word, width)
        && arm_gen_leaf_encoding_valid(
            leaf, instruction->raw_instruction, mode);
}

int cdisasm_arm_attach_generated_identity(
    uint32_t raw_instruction,
    uint32_t opcode_size,
    cdisasm_arm_mode mode,
    const cdisasm_arm_capabilities *capabilities,
    cdisasm_arm_instruction *instruction)
{
    const cdisasm_arm_gen_leaf *leaf = arm_gen_lookup_leaf(
        raw_instruction, opcode_size, mode, capabilities);

    if (instruction == NULL || leaf == NULL
        || leaf->mnemonic_pool_id >= CDISASM_ARM_GEN_MNEMONIC_COUNT) {
        return 0;
    }
    /* Hand-written decoders carry the public form identity that corresponds
     * to their structured operand lowering.  Keep it authoritative: the
     * generated catalog may recognize the same encoding, but its leaf index
     * is not necessarily the public form selected by the manual decoder
     * (notably for newer SVE/SME forms such as LUTI6).  Generated fallback
     * decodes already set form_id themselves, so this also remains a no-op
     * for those instructions. */
    if (instruction->form_id != 0u) {
        return 1;
    }
    instruction->form_id = leaf->form_id;
    return 1;
}

cdisasm_status cdisasm_arm_decode_generated(
    uint32_t raw_instruction,
    uint32_t opcode_size,
    uint64_t address,
    cdisasm_arm_mode mode,
    const cdisasm_arm_capabilities *capabilities,
    int allow_unresolved_architecture,
    int in_it_block,
    cdisasm_arm_instruction *instruction)
{
    const cdisasm_arm_gen_leaf *leaf;

    if (instruction == NULL || capabilities == NULL) {
        return CDISASM_STATUS_INTERNAL_ERROR;
    }
    leaf = arm_gen_lookup_leaf(
        raw_instruction, opcode_size, mode, capabilities);
    if (leaf == NULL) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
    if (!arm_gen_leaf_requirements_admit(
            leaf, capabilities, allow_unresolved_architecture)) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
    if (!arm_gen_leaf_encoding_valid(leaf, raw_instruction, mode)) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
    if (leaf->form_id == UINT16_C(4498)
        && !arm_gen_pstate_msr_admit(
            raw_instruction, capabilities, allow_unresolved_architecture)) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
    if (leaf->mnemonic_pool_id >= CDISASM_ARM_GEN_MNEMONIC_COUNT) {
        return CDISASM_STATUS_INTERNAL_ERROR;
    }
    memset(instruction, 0, sizeof(*instruction));
    instruction->address = address;
    instruction->opcode_size = opcode_size;
    instruction->raw_instruction = raw_instruction;
    instruction->name_id = (cdisasm_arm_name_id)
        cdisasm_arm_gen_mnemonic_name_ids[leaf->mnemonic_pool_id];
    instruction->form_id = leaf->form_id;
    instruction->condition = CDISASM_ARM_CONDITION_AL;
    if (mode == CDISASM_ARM_MODE_A32
        && (raw_instruction >> 28) <= CDISASM_ARM_CONDITION_AL) {
        /* The A32 1111 encoding space contains unconditional instructions;
         * it is not the obsolete NV predicate suffix. */
        instruction->condition =
            (cdisasm_arm_condition)(raw_instruction >> 28);
    }
    instruction->isa_id = mode == CDISASM_ARM_MODE_A32
        ? CDISASM_ARM_ISA_A32
        : mode == CDISASM_ARM_MODE_T32
            ? CDISASM_ARM_ISA_T32 : CDISASM_ARM_ISA_A64;
    instruction->instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
        | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
    if (instruction->name_id == CDISASM_ARM_NAME_NONE) {
        return CDISASM_STATUS_INTERNAL_ERROR;
    }
    arm_gen_apply_leaf_semantics(
        leaf, raw_instruction, address, mode, instruction);
    if (!cdisasm_arm_select_generated_alias(
            capabilities, in_it_block, instruction)) {
        (void)cdisasm_arm_lower_generated_operands(instruction);
    }
    if ((instruction->instruction_flags
            & CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE) != 0u) {
        /* Recognition without exact public operands is not a successful
         * structured decode.  Keep the generated tree useful for forms whose
         * operands can be lowered, but do not commit partial metadata. */
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    return CDISASM_STATUS_OK;
}

#else

cdisasm_status cdisasm_arm_decode_generated(
    uint32_t raw_instruction,
    uint32_t opcode_size,
    uint64_t address,
    cdisasm_arm_mode mode,
    const cdisasm_arm_capabilities *capabilities,
    int allow_unresolved_architecture,
    int in_it_block,
    cdisasm_arm_instruction *instruction)
{
    (void)raw_instruction;
    (void)opcode_size;
    (void)address;
    (void)mode;
    (void)capabilities;
    (void)allow_unresolved_architecture;
    (void)in_it_block;
    (void)instruction;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}

cdisasm_status cdisasm_arm_decode_generated_priority(
    uint32_t raw_instruction,
    uint32_t opcode_size,
    uint64_t address,
    cdisasm_arm_mode mode,
    cdisasm_arm_instruction *instruction)
{
    (void)raw_instruction;
    (void)opcode_size;
    (void)address;
    (void)mode;
    (void)instruction;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}

int cdisasm_arm_attach_generated_identity(
    uint32_t raw_instruction,
    uint32_t opcode_size,
    cdisasm_arm_mode mode,
    const cdisasm_arm_capabilities *capabilities,
    cdisasm_arm_instruction *instruction)
{
    (void)raw_instruction;
    (void)opcode_size;
    (void)mode;
    (void)capabilities;
    (void)instruction;
    return 0;
}

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    (void)instruction;
    return 0;
}

#endif
