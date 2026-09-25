#ifndef CDISASM_ARM_GENERATED_DECODER_H
#define CDISASM_ARM_GENERATED_DECODER_H

#include "arm_decoder.h"

cdisasm_status cdisasm_arm_decode_generated(
    uint32_t raw_instruction,
    uint32_t opcode_size,
    uint64_t address,
    cdisasm_arm_mode mode,
    const cdisasm_arm_capabilities *capabilities,
    int allow_unresolved_architecture,
    int in_it_block,
    cdisasm_arm_instruction *instruction);

/* Decode reviewed post-AARCHMRS forms whose encodings overlap an older
 * generic instruction class and therefore must run before that class. */
cdisasm_status cdisasm_arm_decode_generated_priority(
    uint32_t raw_instruction,
    uint32_t opcode_size,
    uint64_t address,
    cdisasm_arm_mode mode,
    cdisasm_arm_instruction *instruction);

int cdisasm_arm_attach_generated_identity(
    uint32_t raw_instruction,
    uint32_t opcode_size,
    cdisasm_arm_mode mode,
    const cdisasm_arm_capabilities *capabilities,
    cdisasm_arm_instruction *instruction);

/* Verify that an instruction's raw bits, ISA, width, and satisfiable decode
 * conditions identify the exact generated form carried in form_id.  This is
 * intentionally independent of a particular CPU profile so the formatter
 * can validate decoded identities. */
int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction);

#endif
