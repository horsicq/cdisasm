#ifndef CDISASM_ARM_T32_DECODER_H
#define CDISASM_ARM_T32_DECODER_H

#include "arm_decoder.h"

/** Returns the byte width implied by the first Thumb halfword (2 or 4). */
uint32_t cdisasm_arm_t32_instruction_size(uint16_t first_halfword);

cdisasm_status cdisasm_arm_decode_t32_core(
    uint32_t raw_instruction,
    uint32_t opcode_size,
    uint64_t address,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities);

#endif
