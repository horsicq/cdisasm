#ifndef CDISASM_ARM_MODERN_DECODER_H
#define CDISASM_ARM_MODERN_DECODER_H

#include "arm_decoder.h"

cdisasm_status cdisasm_arm_decode_a64_modern(
    uint32_t word,
    cdisasm_arm_instruction *instruction,
    cdisasm_arm_requirements *required_capabilities,
    int *recognized);

#endif
