#ifndef CDISASM_X86_GENERATED_DECODER_H
#define CDISASM_X86_GENERATED_DECODER_H

#include "x86_decoder.h"

cdisasm_status cdisasm_x86_decode_generated(
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    cdisasm_mode mode,
    cdisasm_cpu_id cpu_id,
    const cdisasm_x86_decode_flags *selected_flags,
    cdisasm_instruction *instruction);

int cdisasm_x86_attach_generated_identity(
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    cdisasm_mode mode,
    cdisasm_cpu_id cpu_id,
    cdisasm_instruction *instruction);

#endif
