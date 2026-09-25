#ifndef CDISASM_X86_DECODER_H
#define CDISASM_X86_DECODER_H

#include "cdisasm/cdisasm_x86.h"

cdisasm_status cdisasm_x86_decode_core(
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    cdisasm_mode mode,
    cdisasm_cpu_id cpu_id,
    cdisasm_instruction *instruction);

cdisasm_x86_decode_option cdisasm_x86_cpu_decode_flag_mask_core(
    cdisasm_cpu_id cpu_id,
    cdisasm_mode mode);

int cdisasm_x86_cpu_admits_generated_core(
    cdisasm_cpu_id cpu_id,
    cdisasm_x86_name_id name_id,
    cdisasm_x86_group_id group_id);

#endif
