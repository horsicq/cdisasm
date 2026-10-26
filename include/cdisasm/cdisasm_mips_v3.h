#ifndef CDISASM_CDISASM_MIPS_V3_H
#define CDISASM_CDISASM_MIPS_V3_H

#include "cdisasm_mips_v2.h"

/* V3 keeps complete bytes and the unchanged numeric operand representation,
 * but stores all eight requirement words. V1/V2 layouts and APIs are unchanged.
 * Word1 bit0 opts into uncertain Allegrex source views when the library was
 * built with USE_MIPS_ALLEGREX_UNVERIFIED. Other bits in words1..7 are invalid.
 * V1/V2 reject all nonzero upper words, including this V3-only selection. */
#define CDISASM_MIPS_DECODE_BIT_ALLEGREX_UNVERIFIED UINT32_C(64)
#define CDISASM_MIPS_DECODE_WORD_ALLEGREX_UNVERIFIED UINT32_C(1)
#define CDISASM_MIPS_DECODE_FLAG_ALLEGREX_UNVERIFIED UINT64_C(1)
#define CDISASM_MIPS_V3_STRUCTURE_VERSION UINT32_C(1)
#define CDISASM_MIPS_V3_MAX_INSTRUCTION_SIZE CDISASM_MIPS_V2_MAX_INSTRUCTION_SIZE
#define CDISASM_MIPS_INSTRUCTION_V3_SIZE 320u
#define CDISASM_MIPS_DECODE_CONTEXT_V3_SIZE 112u

typedef struct cdisasm_mips_instruction_v3 {
    cdisasm_mips_instruction instruction;
    uint8_t raw_bytes[CDISASM_MIPS_V3_MAX_INSTRUCTION_SIZE];
    cdisasm_mips_encoding encoding;
    uint32_t structure_version;
    uint32_t structure_size;
    uint32_t reserved;
    cdisasm_mips_decode_flags required_flags;
} cdisasm_mips_instruction_v3;

/* Explicit reusable policy. Initialize with cpu_decode_context_v3; select
 * families with add/remove_family_v3. flags retains byte order, FPR layout,
 * exact ISA/encoding selectors and all feature words. family_mask/value use
 * the existing stable FAMILY_MASK_* namespace. reserved must remain zero. */
typedef struct cdisasm_mips_decode_context_v3 {
    uint32_t structure_version;
    uint32_t structure_size;
    cdisasm_mips_cpu_id cpu_id;
    cdisasm_mips_mode mode;
    cdisasm_mips_revision revision;
    cdisasm_mips_encoding encoding;
    cdisasm_mips_decode_flags flags;
    cdisasm_mips_family_mask family_mask;
    cdisasm_mips_family_mask family_value;
    uint64_t reserved;
} cdisasm_mips_decode_context_v3;

#if defined(__cplusplus) && __cplusplus >= 201103L
static_assert(sizeof(cdisasm_mips_instruction_v3) == CDISASM_MIPS_INSTRUCTION_V3_SIZE, "unexpected MIPS v3 result ABI");
static_assert(sizeof(cdisasm_mips_decode_context_v3) == CDISASM_MIPS_DECODE_CONTEXT_V3_SIZE, "unexpected MIPS v3 context ABI");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(cdisasm_mips_instruction_v3) == CDISASM_MIPS_INSTRUCTION_V3_SIZE, "unexpected MIPS v3 result ABI");
_Static_assert(sizeof(cdisasm_mips_decode_context_v3) == CDISASM_MIPS_DECODE_CONTEXT_V3_SIZE, "unexpected MIPS v3 context ABI");
#endif

#ifdef __cplusplus
extern "C" {
#endif

CDISASM_MIPS_API cdisasm_status CDISASM_CALL cdisasm_mips_cpu_decode_flag_mask_v3(cdisasm_mips_cpu_id cpu_id, cdisasm_mips_mode mode, cdisasm_mips_decode_flags *flags);
CDISASM_MIPS_API cdisasm_status CDISASM_CALL cdisasm_mips_cpu_decode_context_v3(cdisasm_mips_cpu_id cpu_id, cdisasm_mips_mode mode, cdisasm_mips_revision revision, cdisasm_mips_encoding encoding, cdisasm_mips_decode_context_v3 *context);
CDISASM_MIPS_API int CDISASM_CALL cdisasm_mips_decode_context_add_family_v3(cdisasm_mips_decode_context_v3 *context, cdisasm_mips_family_id family_id);
CDISASM_MIPS_API int CDISASM_CALL cdisasm_mips_decode_context_remove_family_v3(cdisasm_mips_decode_context_v3 *context, cdisasm_mips_family_id family_id);
CDISASM_MIPS_API cdisasm_mips_family_mask CDISASM_CALL cdisasm_mips_decode_context_get_available_families_v3(const cdisasm_mips_decode_context_v3 *context);
CDISASM_MIPS_API cdisasm_mips_family_mask CDISASM_CALL cdisasm_mips_decode_context_get_set_families_v3(const cdisasm_mips_decode_context_v3 *context);
/* Decode failure clears the complete result, retaining only last_error_id.
 * The structure header, bytes, operands and every requirement word take part
 * in strict replay validation. Unknown versions, sizes, bits and nonzero
 * reserved fields are invalid, including for formatting and effect queries. */
CDISASM_MIPS_API uint32_t CDISASM_CALL cdisasm_mips_decode_v3(cdisasm_mips_cpu_id cpu_id, cdisasm_mips_mode mode, const uint8_t *code, size_t code_size, uint64_t address, const cdisasm_mips_decode_flags *flags, cdisasm_mips_instruction_v3 *instruction);
CDISASM_MIPS_API uint32_t CDISASM_CALL cdisasm_mips_decode_with_context_v3(const cdisasm_mips_decode_context_v3 *context, const uint8_t *code, size_t code_size, uint64_t address, cdisasm_mips_instruction_v3 *instruction);
CDISASM_MIPS_API int CDISASM_CALL cdisasm_mips_instruction_validate_v3(const cdisasm_mips_instruction_v3 *instruction);
/* Validated identification of an opt-in uncertain source view. Such results
 * describe encoded register views: operand sizes are encoded view sizes,
 * accesses are NONE, and no physical register footprint, prefix effects,
 * numerical behavior or hardware legality is established. Their effects query
 * returns zero and all three tracked effect-limitations bits are set. Typed
 * standard instructions and exact established aliases keep this query false,
 * even when the caller selected the opt-in policy. */
CDISASM_MIPS_API int CDISASM_CALL cdisasm_mips_instruction_is_unverified_v3(const cdisasm_mips_instruction_v3 *instruction);
/* Reconstructs and compares the complete canonical instruction. A valid input
 * returns its byte size and the canonical result; invalid input returns zero
 * with INVALID_ARGUMENT. In-place replay is supported. */
CDISASM_MIPS_API uint32_t CDISASM_CALL cdisasm_mips_replay_v3(const cdisasm_mips_instruction_v3 *instruction, cdisasm_mips_instruction_v3 *result);
CDISASM_MIPS_API size_t CDISASM_CALL cdisasm_mips_register_effects_v3(const cdisasm_mips_instruction_v3 *instruction, cdisasm_mips_register_effect *effects, size_t capacity);
CDISASM_MIPS_API cdisasm_mips_effect_limitations CDISASM_CALL cdisasm_mips_register_effect_limitations_v3(const cdisasm_mips_instruction_v3 *instruction);
CDISASM_MIPS_API cdisasm_mips_family_mask CDISASM_CALL cdisasm_mips_instruction_family_mask_v3(const cdisasm_mips_instruction_v3 *instruction);
CDISASM_MIPS_API cdisasm_mips_family_id CDISASM_CALL cdisasm_mips_instruction_family_v3(const cdisasm_mips_instruction_v3 *instruction);
#if USE_DISASM_FORMAT
CDISASM_MIPS_API size_t CDISASM_CALL cdisasm_mips_format_v3(const cdisasm_mips_instruction_v3 *instruction, uint32_t flags, char *buffer, size_t buffer_size);
#endif

#ifdef __cplusplus
}
#endif
#endif
