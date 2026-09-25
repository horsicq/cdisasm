#include "cdisasm/cdisasm_format.h"
#include "arm_generated_alias.h"
#include "arm_generated_decoder.h"

#include <stdio.h>
#include <string.h>

static int check_format_metadata(
    cdisasm_arm_form_id form_id,
    cdisasm_arm_name_id name_id,
    cdisasm_arm_isa_id isa_id,
    uint32_t opcode_size,
    uint32_t raw_instruction,
    uint32_t flags,
    uint32_t opcode_groups,
    uint64_t branch_target,
    const char *expected)
{
    cdisasm_arm_instruction instruction;
    char text[128];
    size_t length;

    memset(&instruction, 0, sizeof(instruction));
    instruction.opcode_size = opcode_size;
    instruction.raw_instruction = raw_instruction;
    instruction.opcode_groups = opcode_groups;
    instruction.branch_target = branch_target;
    instruction.name_id = name_id;
    instruction.condition = CDISASM_ARM_CONDITION_AL;
    instruction.isa_id = isa_id;
    instruction.form_id = form_id;
    instruction.instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
        | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
    length = cdisasm_arm_format(&instruction, flags, text, sizeof(text));
    if (length != strlen(expected) || strcmp(text, expected) != 0) {
        fprintf(stderr, "form %u: got '%s', expected '%s'\n",
            (unsigned)form_id, text, expected);
        return 0;
    }
    return 1;
}

static int check_format(
    cdisasm_arm_form_id form_id,
    cdisasm_arm_name_id name_id,
    cdisasm_arm_isa_id isa_id,
    uint32_t opcode_size,
    uint32_t raw_instruction,
    uint32_t flags,
    const char *expected)
{
    return check_format_metadata(
        form_id, name_id, isa_id, opcode_size, raw_instruction, flags,
        UINT32_C(0), UINT64_C(0), expected);
}

static int check_rejected_format(
    cdisasm_arm_form_id form_id,
    cdisasm_arm_name_id name_id,
    cdisasm_arm_isa_id isa_id,
    uint32_t opcode_size,
    uint32_t raw_instruction)
{
    cdisasm_arm_instruction instruction;
    char text[128] = "not empty";
    size_t queried;
    size_t written;

    memset(&instruction, 0, sizeof(instruction));
    instruction.opcode_size = opcode_size;
    instruction.raw_instruction = raw_instruction;
    instruction.name_id = name_id;
    instruction.condition = CDISASM_ARM_CONDITION_EQ;
    instruction.isa_id = isa_id;
    instruction.form_id = form_id;
    instruction.instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
        | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
    queried = cdisasm_arm_format(
        &instruction, UINT32_C(0), NULL, UINT32_C(0));
    written = cdisasm_arm_format(
        &instruction, UINT32_C(0), text, sizeof(text));
    if (queried != 0u || written != 0u || text[0] != '\0') {
        fprintf(stderr,
            "opaque form %u: query %u/write %u/text '%s', expected rejection\n",
            (unsigned)form_id, (unsigned)queried, (unsigned)written, text);
        return 0;
    }
    return 1;
}

static int check_alias(
    cdisasm_arm_form_id form_id,
    cdisasm_arm_name_id canonical_name,
    cdisasm_arm_name_id expected_name,
    cdisasm_arm_isa_id isa_id,
    uint32_t opcode_size,
    uint32_t raw_instruction,
    int in_it_block,
    int expected_change,
    int all_features)
{
    cdisasm_arm_capabilities capabilities =
        CDISASM_ARM_CAPABILITIES_NONE_INITIALIZER;
    cdisasm_arm_instruction instruction;
    size_t bitmap_index;
    int changed;

    if (all_features) {
        for (bitmap_index = 0u;
             bitmap_index < CDISASM_ARM_FEATURE_WORD_COUNT;
             ++bitmap_index) {
            capabilities.bitmap[bitmap_index] = UINT64_MAX;
        }
    }
    memset(&instruction, 0, sizeof(instruction));
    instruction.opcode_size = opcode_size;
    instruction.raw_instruction = raw_instruction;
    instruction.name_id = canonical_name;
    instruction.isa_id = isa_id;
    instruction.form_id = form_id;
    instruction.instruction_flags =
        CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
        | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE;
    changed = cdisasm_arm_select_generated_alias(
        &capabilities, in_it_block, &instruction);
    if (changed != expected_change || instruction.name_id != expected_name) {
        fprintf(stderr,
            "alias form %u: change %d/name %u, expected %d/%u\n",
            (unsigned)form_id, changed, (unsigned)instruction.name_id,
            expected_change, (unsigned)expected_name);
        return 0;
    }
    return 1;
}

static int check_generated_semantics(
    uint32_t raw_instruction,
    uint32_t opcode_size,
    cdisasm_arm_mode mode,
    cdisasm_arm_form_id expected_form,
    cdisasm_arm_name_id expected_name,
    uint32_t required_flags,
    uint32_t forbidden_flags,
    uint32_t expected_groups)
{
    cdisasm_arm_capabilities capabilities =
        CDISASM_ARM_CAPABILITIES_NONE_INITIALIZER;
    cdisasm_arm_instruction instruction;
    char formatted[128];
    cdisasm_status status;
    size_t bitmap_index;

    for (bitmap_index = 0u;
         bitmap_index < CDISASM_ARM_FEATURE_WORD_COUNT;
         ++bitmap_index) {
        capabilities.bitmap[bitmap_index] = UINT64_MAX;
    }
    memset(&instruction, 0, sizeof(instruction));
    status = cdisasm_arm_decode_generated(
        raw_instruction, opcode_size, UINT64_C(0x1000), mode,
        &capabilities, 1, 0, &instruction);
    if ((status != CDISASM_STATUS_OK
            && status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION)
        || ((instruction.instruction_flags
                & CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE) != 0u)
            != (status == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION)
        || instruction.form_id != expected_form
        || instruction.name_id != expected_name
        || (instruction.instruction_flags & required_flags) != required_flags
        || (instruction.instruction_flags & forbidden_flags) != 0u
        || instruction.opcode_groups != expected_groups) {
        fprintf(stderr,
            "semantic raw 0x%08x: status %u/form %u/name %u/flags 0x%08x/groups 0x%08x\n",
            (unsigned)raw_instruction, (unsigned)status,
            (unsigned)instruction.form_id, (unsigned)instruction.name_id,
            (unsigned)instruction.instruction_flags,
            (unsigned)instruction.opcode_groups);
        return 0;
    }
    strcpy(formatted, "not empty");
    if (cdisasm_arm_format(
            &instruction, UINT32_C(0), formatted, sizeof(formatted)) == 0u
        && (status == CDISASM_STATUS_OK || formatted[0] != '\0')) {
        fprintf(stderr,
            "semantic raw 0x%08x: formatter violated structured/opaque contract\n",
            (unsigned)raw_instruction);
        return 0;
    }
    return 1;
}

static int check_generated_format_result(
    uint32_t raw_instruction,
    cdisasm_status expected_status,
    cdisasm_arm_form_id expected_form,
    cdisasm_arm_name_id expected_name,
    const char *expected_text)
{
    cdisasm_arm_capabilities capabilities =
        CDISASM_ARM_CAPABILITIES_NONE_INITIALIZER;
    cdisasm_arm_instruction instruction;
    cdisasm_status status;
    char formatted[128] = {0};
    size_t bitmap_index;
    size_t length;

    for (bitmap_index = 0u;
         bitmap_index < CDISASM_ARM_FEATURE_WORD_COUNT;
         ++bitmap_index) {
        capabilities.bitmap[bitmap_index] = UINT64_MAX;
    }
    memset(&instruction, 0, sizeof(instruction));
    status = cdisasm_arm_decode_generated(
        raw_instruction, UINT32_C(4), UINT64_C(0x1000),
        CDISASM_ARM_MODE_A64, &capabilities, 1, 0, &instruction);
    if (status != expected_status) {
        fprintf(stderr,
            "generated raw 0x%08x: status %u, expected %u\n",
            (unsigned)raw_instruction, (unsigned)status,
            (unsigned)expected_status);
        return 0;
    }
    if (status != CDISASM_STATUS_OK
        && (status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION
            || expected_text == NULL
            || (instruction.instruction_flags
                & (CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE))
                != (CDISASM_ARM_INSTRUCTION_FLAG_GENERATED_FALLBACK
                    | CDISASM_ARM_INSTRUCTION_FLAG_OPERANDS_OPAQUE))) {
        return 1;
    }
    length = cdisasm_arm_format(
        &instruction, UINT32_C(0), formatted, sizeof(formatted));
    if (instruction.form_id != expected_form
        || instruction.name_id != expected_name
        || expected_text == NULL
        || length != strlen(expected_text)
        || strcmp(formatted, expected_text) != 0) {
        fprintf(stderr,
            "generated raw 0x%08x: form %u/name %u/text '%s'\n",
            (unsigned)raw_instruction, (unsigned)instruction.form_id,
            (unsigned)instruction.name_id, formatted);
        return 0;
    }
    return 1;
}

int main(void)
{
    const uint32_t pre_decrement_writeback =
        CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
        | CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
        | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT;
    const uint32_t post_increment_writeback =
        CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
        | CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
        | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT;
    const uint32_t opposite_stack_address =
        CDISASM_ARM_INSTRUCTION_FLAG_PRE_INDEX
        | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_DECREMENT;

    /* Generated AA32 block transfers retain exact P/U/W metadata.  A POP
     * which restores PC is additionally a subroutine return. */
    if (!check_generated_semantics(
            UINT32_C(0xe92d4010), UINT32_C(4), CDISASM_ARM_MODE_A32,
            UINT16_C(399), CDISASM_ARM_NAME_PUSH,
            pre_decrement_writeback,
            CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT,
            CDISASM_GROUP_NONE)
        || !check_generated_semantics(
            UINT32_C(0xe8c10001), UINT32_C(4), CDISASM_ARM_MODE_A32,
            UINT16_C(398), CDISASM_ARM_NAME_STM,
            CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT
                | CDISASM_ARM_INSTRUCTION_FLAG_USER_REGISTERS,
            CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
                | opposite_stack_address,
            CDISASM_GROUP_NONE)
        || !check_generated_semantics(
            UINT32_C(0xe8bd8010), UINT32_C(4), CDISASM_ARM_MODE_A32,
            UINT16_C(397), CDISASM_ARM_NAME_POP,
            post_increment_writeback,
            opposite_stack_address,
            CDISASM_GROUP_JUMP | CDISASM_GROUP_RETURN)
        || !check_generated_semantics(
            UINT32_C(0x0000ca04), UINT32_C(2), CDISASM_ARM_MODE_T32,
            UINT16_C(1178), CDISASM_ARM_NAME_LDM,
            CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT,
            CDISASM_ARM_INSTRUCTION_FLAG_WRITEBACK
                | opposite_stack_address,
            CDISASM_GROUP_NONE)
        || !check_generated_semantics(
            UINT32_C(0x8010e8bd), UINT32_C(4), CDISASM_ARM_MODE_T32,
            UINT16_C(1721), CDISASM_ARM_NAME_POP,
            post_increment_writeback,
            opposite_stack_address,
            CDISASM_GROUP_JUMP | CDISASM_GROUP_RETURN)
        || !check_generated_semantics(
            UINT32_C(0xed2d8b04), UINT32_C(4), CDISASM_ARM_MODE_A32,
            UINT16_C(501), CDISASM_ARM_NAME_VPUSH,
            pre_decrement_writeback
                | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT,
            CDISASM_ARM_INSTRUCTION_FLAG_POST_INDEX
                | CDISASM_ARM_INSTRUCTION_FLAG_ADDRESS_INCREMENT,
            CDISASM_GROUP_NONE)
        || !check_generated_semantics(
            UINT32_C(0xecbd8b04), UINT32_C(4), CDISASM_ARM_MODE_A32,
            UINT16_C(508), CDISASM_ARM_NAME_VPOP,
            post_increment_writeback
                | CDISASM_ARM_INSTRUCTION_FLAG_FLOATING_POINT,
            opposite_stack_address,
            CDISASM_GROUP_NONE)) {
        return 1;
    }

    /* T32 stores its two halfwords in fetch order; the formatter normalizes it. */
    if (!check_format(
            UINT16_C(1853), CDISASM_ARM_NAME_DCPS1,
            CDISASM_ARM_ISA_T32, UINT32_C(4), UINT32_C(0x8001f78f),
            UINT32_C(0), "dcps1")) {
        return 1;
    }
    if (!check_format(
            UINT16_C(2224), CDISASM_ARM_NAME_ADDPT,
            CDISASM_ARM_ISA_A64, UINT32_C(4), UINT32_C(0x04c40000),
            UINT32_C(0),
            "addpt z0.d, p0/m, z0.d, z0.d")) {
        return 1;
    }
    /* Non-adjacent i3h:i3l fragments form the indexed SVE lane. */
    if (!check_format(
            UINT16_C(2722), CDISASM_ARM_NAME_MLA,
            CDISASM_ARM_ISA_A64, UINT32_C(4), UINT32_C(0x447d0800),
            UINT32_C(0), "mla z0.h, z0.h, z5.h[7]")) {
        return 1;
    }
    if (!check_format(
            UINT16_C(52), CDISASM_ARM_NAME_MLA,
            CDISASM_ARM_ISA_A32, UINT32_C(4), UINT32_C(0x00200090),
            UINT32_C(0), "mlaeq r0, r0, r0, r0")) {
        return 1;
    }
    if (!check_format(
            UINT16_C(1), CDISASM_ARM_NAME_STRH,
            CDISASM_ARM_ISA_A32, UINT32_C(4), UINT32_C(0xe10000b0),
            UINT32_C(0), "strh r0, [r0, -r0]")) {
        return 1;
    }
    /* Ordered encoded_in fragments imm4H:imm4L form one immediate. */
    if (!check_format(
            UINT16_C(31), CDISASM_ARM_NAME_STRH,
            CDISASM_ARM_ISA_A32, UINT32_C(4), UINT32_C(0xe0c21ab5),
            UINT32_C(0), "strh r1, [r2], #165")) {
        return 1;
    }
    if (!check_format(
            UINT16_C(1102), CDISASM_ARM_NAME_ADD,
            CDISASM_ARM_ISA_T32, UINT32_C(2), UINT32_C(0x00001c00),
            UINT32_C(0), "add r0, r0, #0")) {
        return 1;
    }
    if (!check_format(
            UINT16_C(4391), CDISASM_ARM_NAME_EXTR,
            CDISASM_ARM_ISA_A64, UINT32_C(4), UINT32_C(0x93df07ff),
            CDISASM_FORMAT_UPPERCASE_OPCODE,
            "EXTR xzr, xzr, xzr, #1")) {
        return 1;
    }
    if (!check_format_metadata(
            UINT16_C(4436), CDISASM_ARM_NAME_CBBGT,
            CDISASM_ARM_ISA_A64, UINT32_C(4), UINT32_C(0x7412bfe3),
            UINT32_C(0),
            CDISASM_GROUP_JUMP | CDISASM_GROUP_RELATIVE_BRANCH
                | CDISASM_GROUP_CONDITIONAL,
            UINT64_C(0xffc),
            "cbbgt w3, w18, #0xffc")) {
        return 1;
    }
    /* Opaque metadata may still format when the generated catalog has an
     * exact text recipe for the encoded fields. */
    if (!check_format(
            UINT16_C(4453), CDISASM_ARM_NAME_DCPS1,
            CDISASM_ARM_ISA_A64, UINT32_C(4), UINT32_C(0xd4a24681),
            UINT32_C(0),
            "dcps1 #4660")) {
        return 1;
    }
    /* Unknown opaque metadata must not be rendered as a plausible mnemonic. */
    if (!check_rejected_format(
            UINT16_C(94), CDISASM_ARM_NAME_MRS,
            CDISASM_ARM_ISA_A32, UINT32_C(4), UINT32_C(0x010f0000))) {
        return 1;
    }
    if (!check_alias(
            UINT16_C(4391), CDISASM_ARM_NAME_EXTR,
            CDISASM_ARM_NAME_ROR, CDISASM_ARM_ISA_A64,
            UINT32_C(4), UINT32_C(0x93df07ff), 0, 1, 1)) {
        return 1;
    }
    if (!check_alias(
            UINT16_C(2322), CDISASM_ARM_NAME_ORR,
            CDISASM_ARM_NAME_MOV, CDISASM_ARM_ISA_A64,
            UINT32_C(4), UINT32_C(0x04603000), 0, 1, 1)
        || !check_alias(
            UINT16_C(2322), CDISASM_ARM_NAME_ORR,
            CDISASM_ARM_NAME_ORR, CDISASM_ARM_ISA_A64,
            UINT32_C(4), UINT32_C(0x04603000), 0, 0, 0)) {
        return 1;
    }
    /* Shared-pseudocode preferred-form helpers are evaluated numerically. */
    if (!check_alias(
            UINT16_C(4426), CDISASM_ARM_NAME_SBFM,
            CDISASM_ARM_NAME_SBFX, CDISASM_ARM_ISA_A64,
            UINT32_C(4), UINT32_C(0x13083c20), 0, 1, 1)
        || !check_alias(
            UINT16_C(4426), CDISASM_ARM_NAME_SBFM,
            CDISASM_ARM_NAME_SXTB, CDISASM_ARM_ISA_A64,
            UINT32_C(4), UINT32_C(0x13001c20), 0, 1, 1)
        || !check_alias(
            UINT16_C(4413), CDISASM_ARM_NAME_ORR,
            CDISASM_ARM_NAME_ORR, CDISASM_ARM_ISA_A64,
            UINT32_C(4), UINT32_C(0x320003e0), 0, 0, 1)
        || !check_alias(
            UINT16_C(4413), CDISASM_ARM_NAME_ORR,
            CDISASM_ARM_NAME_MOV, CDISASM_ARM_ISA_A64,
            UINT32_C(4), UINT32_C(0x320043e0), 0, 1, 1)) {
        return 1;
    }
    if (!check_alias(
            UINT16_C(2427), CDISASM_ARM_NAME_DUPM,
            CDISASM_ARM_NAME_DUPM, CDISASM_ARM_ISA_A64,
            UINT32_C(4), UINT32_C(0x05c20000), 0, 0, 1)
        || !check_alias(
            UINT16_C(2427), CDISASM_ARM_NAME_DUPM,
            CDISASM_ARM_NAME_MOV, CDISASM_ARM_ISA_A64,
            UINT32_C(4), UINT32_C(0x05c001e0), 0, 1, 1)) {
        return 1;
    }
    if (!check_alias(
            UINT16_C(238), CDISASM_ARM_NAME_MOV,
            CDISASM_ARM_NAME_MOVW, CDISASM_ARM_ISA_A32,
            UINT32_C(4), UINT32_C(0xe30000ff), 0, 1, 1)
        || !check_alias(
            UINT16_C(238), CDISASM_ARM_NAME_MOV,
            CDISASM_ARM_NAME_MOV, CDISASM_ARM_ISA_A32,
            UINT32_C(4), UINT32_C(0xe3010234), 0, 0, 1)
        || !check_alias(
            UINT16_C(1901), CDISASM_ARM_NAME_MOV,
            CDISASM_ARM_NAME_MOVW, CDISASM_ARM_ISA_T32,
            UINT32_C(4), UINT32_C(0x08fff240), 0, 1, 1)
        || !check_alias(
            UINT16_C(1901), CDISASM_ARM_NAME_MOV,
            CDISASM_ARM_NAME_MOV, CDISASM_ARM_ISA_T32,
            UINT32_C(4), UINT32_C(0x2834f241), 0, 0, 1)) {
        return 1;
    }
    /* The caller supplies the T32 IT state, so the preferred alias is exact
     * both outside and inside an active IT block. */
    if (!check_alias(
            UINT16_C(1102), CDISASM_ARM_NAME_ADD,
            CDISASM_ARM_NAME_ADDS, CDISASM_ARM_ISA_T32,
            UINT32_C(2), UINT32_C(0x1c00), 0, 1, 1)
        || !check_alias(
            UINT16_C(1102), CDISASM_ARM_NAME_ADD,
            CDISASM_ARM_NAME_ADD, CDISASM_ARM_ISA_T32,
            UINT32_C(2), UINT32_C(0x1c00), 1, 0, 1)) {
        return 1;
    }
    /* Named system-operation aliases are selected only for exact allocated
     * tuples; a generic SYS encoding remains canonical. */
    if (!check_alias(
            UINT16_C(4502), CDISASM_ARM_NAME_SYS,
            CDISASM_ARM_NAME_DC, CDISASM_ARM_ISA_A64,
            UINT32_C(4), UINT32_C(0xd5087620), 0, 1, 1)
        || !check_alias(
            UINT16_C(4503), CDISASM_ARM_NAME_SYSL,
            CDISASM_ARM_NAME_GICR, CDISASM_ARM_ISA_A64,
            UINT32_C(4), UINT32_C(0xd528c300), 0, 1, 1)
        || !check_alias(
            UINT16_C(4506), CDISASM_ARM_NAME_SYSP,
            CDISASM_ARM_NAME_TLBIP, CDISASM_ARM_ISA_A64,
            UINT32_C(4), UINT32_C(0xd5488120), 0, 1, 1)
        || !check_alias(
            UINT16_C(4502), CDISASM_ARM_NAME_SYS,
            CDISASM_ARM_NAME_SYS, CDISASM_ARM_ISA_A64,
            UINT32_C(4), UINT32_C(0xd5080000), 0, 0, 1)) {
        return 1;
    }
    /* SYSP's optional Rt pair is present only for an even pair base.  Rt=31
     * selects the architecturally omitted/default form; odd pair bases are
     * invalid encodings rather than formatter failures. */
    if (!check_generated_format_result(
            UINT32_C(0xd5480002), CDISASM_STATUS_UNSUPPORTED_INSTRUCTION,
            UINT16_C(4506), CDISASM_ARM_NAME_SYSP,
            "sysp #0, c0, c0, #0, x2, x3")
        || !check_generated_format_result(
            UINT32_C(0xd548001f), CDISASM_STATUS_UNSUPPORTED_INSTRUCTION,
            UINT16_C(4506), CDISASM_ARM_NAME_SYSP,
            "sysp #0, c0, c0, #0")
        || !check_generated_format_result(
            UINT32_C(0xd5480001), CDISASM_STATUS_INVALID_INSTRUCTION,
            CDISASM_ARM_FORM_NONE, CDISASM_ARM_NAME_NONE, NULL)) {
        return 1;
    }
    return 0;
}
