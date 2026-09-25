#ifndef CDISASM_ARM_GENERATED_FORMATTER_H
#define CDISASM_ARM_GENERATED_FORMATTER_H

#include "cdisasm/cdisasm_format.h"

/*
 * Formats an exact generated AARCHMRS recipe. Zero means that the form remains
 * opaque (or that the supplied generated record is inconsistent), in which
 * case the ordinary mnemonic-only fallback remains available.
 */
size_t cdisasm_arm_format_generated(
    const cdisasm_arm_instruction *instruction,
    uint32_t flags,
    char *buffer,
    size_t buffer_size);

#endif
