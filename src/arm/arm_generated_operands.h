#ifndef CDISASM_ARM_GENERATED_OPERANDS_H
#define CDISASM_ARM_GENERATED_OPERANDS_H

#include "arm_decoder.h"

/*
 * Populate an exact, independently validated structured-operand record for a
 * generated AARCHMRS form.  Returns one only when every displayed operand,
 * register-31 interpretation, size, and access mode is known.  A zero return
 * leaves the instruction byte-for-byte unchanged and therefore opaque.
 */
int cdisasm_arm_lower_generated_operands(
    cdisasm_arm_instruction *instruction);

#endif
