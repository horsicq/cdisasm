#ifndef CDISASM_MIPS_DECODER_H
#define CDISASM_MIPS_DECODER_H

#include "cdisasm/cdisasm_mips_v2.h"

/* Wrapper-only physical CPU policy. Public flag snapshots must leave all
 * upper bitmap words zero; this private word never escapes a decode call. */
#define CDISASM_MIPS_INTERNAL_POLICY_WORD 7u

/* Internal entry points receive an already normalized fixed-width instruction.
 * Public argument validation and transactional output clearing live in the
 * wrapper.  Feature flags here contain the active CPU-supported families. */
cdisasm_status cdisasm_mips_decode_core(uint32_t raw, uint64_t address, cdisasm_mips_mode mode,
                                      cdisasm_mips_revision revision, const cdisasm_mips_decode_flags *features,
                                      cdisasm_mips_instruction *instruction);
cdisasm_status cdisasm_mips_decode_extra(uint32_t raw, uint64_t address, cdisasm_mips_mode mode,
                                       cdisasm_mips_revision revision, const cdisasm_mips_decode_flags *features,
                                       cdisasm_mips_instruction *instruction);
cdisasm_status cdisasm_mips_decode_generated(uint32_t raw, uint64_t address, cdisasm_mips_mode mode,
                                           cdisasm_mips_revision revision, const cdisasm_mips_decode_flags *features,
                                           cdisasm_mips_instruction *instruction);
uint64_t cdisasm_mips_extra_required_flags(cdisasm_mips_form_id form);
uint64_t cdisasm_mips_generated_required_flags(cdisasm_mips_form_id form);
size_t cdisasm_mips_generated_effects(cdisasm_mips_form_id form, cdisasm_mips_register_effect *effects, size_t capacity);
uint64_t cdisasm_mips_instruction_required_flags(const cdisasm_mips_instruction *instruction);
int cdisasm_mips_instruction_validate(const cdisasm_mips_instruction *instruction);
int cdisasm_mips_instruction_validate_v2(const cdisasm_mips_instruction_v2 *instruction);
cdisasm_status cdisasm_mips_decode_compact(uint64_t raw, uint32_t size, cdisasm_mips_encoding encoding, uint64_t address,
                                         cdisasm_mips_mode mode, cdisasm_mips_revision revision,
                                         const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *instruction);
uint32_t cdisasm_mips_compact_size(cdisasm_mips_encoding encoding, uint16_t first);
uint64_t cdisasm_mips_compact_required_flags(cdisasm_mips_form_id form);
cdisasm_status cdisasm_mips_decode_mips16e2(uint32_t raw, uint32_t size, uint64_t address,
    cdisasm_mips_mode mode, cdisasm_mips_revision revision,
    const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *instruction);
int cdisasm_mips_mips16e2_owns(uint32_t raw);
uint64_t cdisasm_mips_mips16e2_required_flags(cdisasm_mips_form_id form);
size_t cdisasm_mips_compact_effects(const cdisasm_mips_instruction *instruction, cdisasm_mips_register_effect *effects, size_t capacity);
cdisasm_status cdisasm_mips_decode_nano(uint64_t raw, uint32_t size, uint64_t address,
                                      cdisasm_mips_mode mode, cdisasm_mips_revision revision,
                                      const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *instruction);
uint32_t cdisasm_mips_nano_size(uint16_t first);
uint64_t cdisasm_mips_nano_required_flags(cdisasm_mips_form_id form);
cdisasm_status cdisasm_mips_decode_allegrex(uint32_t raw, uint64_t address, cdisasm_mips_mode mode,
    cdisasm_mips_revision revision, const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *instruction);
uint64_t cdisasm_mips_allegrex_required_flags(cdisasm_mips_form_id form);
int cdisasm_mips_allegrex_encoding_allowed(uint32_t raw);
int cdisasm_mips_allegrex_owns(uint32_t raw);
size_t cdisasm_mips_allegrex_effects(const cdisasm_mips_instruction *instruction, cdisasm_mips_register_effect *effects, size_t capacity);
cdisasm_status cdisasm_mips_decode_r5900(uint32_t raw, uint64_t address, cdisasm_mips_mode mode,
    cdisasm_mips_revision revision, const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *instruction);
uint64_t cdisasm_mips_r5900_required_flags(cdisasm_mips_form_id form);
int cdisasm_mips_r5900_owns(uint32_t raw);
size_t cdisasm_mips_r5900_effects(const cdisasm_mips_instruction *instruction, cdisasm_mips_register_effect *effects, size_t capacity);
cdisasm_status cdisasm_mips_decode_mxu(uint32_t raw, uint64_t address, cdisasm_mips_mode mode,
    cdisasm_mips_revision revision, const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *instruction);
uint64_t cdisasm_mips_mxu_required_flags(cdisasm_mips_form_id form);
size_t cdisasm_mips_mxu_effects(const cdisasm_mips_instruction *instruction, cdisasm_mips_register_effect *effects, size_t capacity);
cdisasm_status cdisasm_mips_decode_mxu_vector(uint32_t raw, uint64_t address, cdisasm_mips_mode mode,
    cdisasm_mips_revision revision, const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *instruction);
int cdisasm_mips_mxu_vector_owns(uint32_t raw, const cdisasm_mips_decode_flags *features);
uint64_t cdisasm_mips_mxu_vector_required_flags(cdisasm_mips_form_id form);
size_t cdisasm_mips_mxu_vector_effects(const cdisasm_mips_instruction *instruction, cdisasm_mips_register_effect *effects, size_t capacity);
cdisasm_status cdisasm_mips_decode_loongsimd(uint32_t raw, uint64_t address, cdisasm_mips_mode mode,
    cdisasm_mips_revision revision, const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *instruction);
int cdisasm_mips_loongsimd_owns(uint32_t raw);
uint64_t cdisasm_mips_loongsimd_required_flags(cdisasm_mips_form_id form);
cdisasm_status cdisasm_mips_decode_vu_macro(uint32_t raw, uint64_t address, cdisasm_mips_mode mode,
    cdisasm_mips_revision revision, const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *instruction);
cdisasm_status cdisasm_mips_decode_vu_word(uint32_t raw, uint64_t address, cdisasm_mips_encoding encoding,
    uint32_t unit, cdisasm_mips_mode mode, cdisasm_mips_revision revision,
    const cdisasm_mips_decode_flags *features, cdisasm_mips_instruction *instruction);
int cdisasm_mips_vu_macro_owns(uint32_t raw);
uint64_t cdisasm_mips_vu_required_flags(cdisasm_mips_form_id form);
size_t cdisasm_mips_vu_effects(const cdisasm_mips_instruction *instruction, cdisasm_mips_register_effect *effects, size_t capacity);
int cdisasm_mips_vu_instruction_validate(const cdisasm_mips_vu_instruction *instruction);
#if USE_DISASM_FORMAT
size_t cdisasm_mips_vu_format_instruction(const cdisasm_mips_instruction *instruction, uint32_t flags, char *buffer, size_t capacity);
size_t cdisasm_mips_allegrex_format_operand(const cdisasm_mips_instruction *instruction, unsigned index, char *buffer, size_t capacity);
size_t cdisasm_mips_allegrex_register_name(const cdisasm_mips_operand *operand, char *buffer, size_t capacity);
#endif

#endif
