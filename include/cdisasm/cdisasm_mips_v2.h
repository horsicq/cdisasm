#ifndef CDISASM_CDISASM_MIPS_V2_H
#define CDISASM_CDISASM_MIPS_V2_H

#include "cdisasm_mips.h"

/* The original 232-byte result/API remains available for standard four-byte
 * instructions. This separately versioned envelope retains complete encoded
 * bytes for variable-length instruction sets, including 48-bit nanoMIPS. */
typedef uint32_t cdisasm_mips_encoding;
#define CDISASM_MIPS_ENCODING_STANDARD UINT32_C(0)
#define CDISASM_MIPS_ENCODING_MIPS16 UINT32_C(1)
#define CDISASM_MIPS_ENCODING_MICROMIPS UINT32_C(2)
#define CDISASM_MIPS_ENCODING_NANOMIPS UINT32_C(3)
#define CDISASM_MIPS_ENCODING_VU_UPPER UINT32_C(4)
#define CDISASM_MIPS_ENCODING_VU_LOWER UINT32_C(5)
#define CDISASM_MIPS_ENCODING_VU_LOWER_LOI UINT32_C(6)
#define CDISASM_MIPS_V2_MAX_INSTRUCTION_SIZE 8u
#define CDISASM_MIPS_V2_STRUCTURE_VERSION UINT32_C(1)
#define CDISASM_MIPS_INSTRUCTION_V2_SIZE 256u

typedef struct cdisasm_mips_instruction_v2 {
    /* Numeric operands and effects use the same stable representation. For
     * six-byte instructions raw_instruction holds only the low 32 normalized
     * bits; raw_bytes is the authoritative complete encoding in input order. */
    cdisasm_mips_instruction instruction;
    uint8_t raw_bytes[CDISASM_MIPS_V2_MAX_INSTRUCTION_SIZE];
    cdisasm_mips_encoding encoding;
    uint32_t structure_version;
    uint64_t required_flags;
} cdisasm_mips_instruction_v2;

typedef uint32_t cdisasm_mips_vu_unit;
#define CDISASM_MIPS_VU_UNIT_0 UINT32_C(0)
#define CDISASM_MIPS_VU_UNIT_1 UINT32_C(1)
#define CDISASM_MIPS_VU_INSTRUCTION_SIZE 528u
#define CDISASM_MIPS_VU_CONTROL_I (UINT32_C(1) << 31)
#define CDISASM_MIPS_VU_CONTROL_E (UINT32_C(1) << 30)
#define CDISASM_MIPS_VU_CONTROL_M (UINT32_C(1) << 29)
#define CDISASM_MIPS_VU_CONTROL_D (UINT32_C(1) << 28)
#define CDISASM_MIPS_VU_CONTROL_T (UINT32_C(1) << 27)
#define CDISASM_MIPS_VU_CONTROL_MASK UINT32_C(0xf8000000)

/* VU microprograms issue upper and lower operations together. Input bytes are
 * lower word followed by upper word; both records retain the pair address.
 * The upper I control bit selects a typed LOI literal in the lower record.
 * Failure clears the complete pair and retains only last_error_id. */
typedef struct cdisasm_mips_vu_instruction {
    cdisasm_mips_instruction_v2 upper;
    cdisasm_mips_instruction_v2 lower;
    uint8_t raw_bytes[8];
    uint32_t control_flags;
    uint32_t last_error_id;
} cdisasm_mips_vu_instruction;

#if defined(__cplusplus) && __cplusplus >= 201103L
static_assert(sizeof(cdisasm_mips_instruction_v2) == CDISASM_MIPS_INSTRUCTION_V2_SIZE, "unexpected MIPS v2 result ABI");
static_assert(sizeof(cdisasm_mips_vu_instruction) == CDISASM_MIPS_VU_INSTRUCTION_SIZE, "unexpected VU pair ABI");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(cdisasm_mips_instruction_v2) == CDISASM_MIPS_INSTRUCTION_V2_SIZE, "unexpected MIPS v2 result ABI");
_Static_assert(sizeof(cdisasm_mips_vu_instruction) == CDISASM_MIPS_VU_INSTRUCTION_SIZE, "unexpected VU pair ABI");
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* MIPS16/MICROMIPS/NANOMIPS or VU_UPPER/VU_LOWER/VU_LOWER_LOI decode flags
 * select exactly one encoding. With no encoding flag the standard fixed-width
 * decoder is selected. VU word encodings consume one endian-aware 32-bit word;
 * use decode_vu for an eight-byte upper/lower issue pair. No encoding is guessed
 * from instruction bytes. Failures clear the complete envelope and retain only
 * instruction.last_error_id. */
CDISASM_MIPS_API cdisasm_status CDISASM_CALL cdisasm_mips_cpu_decode_context_v2(cdisasm_mips_cpu_id cpu_id, cdisasm_mips_mode mode, cdisasm_mips_revision revision, cdisasm_mips_encoding encoding, cdisasm_mips_decode_context *context);
CDISASM_MIPS_API uint32_t CDISASM_CALL cdisasm_mips_decode_v2(cdisasm_mips_cpu_id cpu_id, cdisasm_mips_mode mode, const uint8_t *code, size_t code_size, uint64_t address, const cdisasm_mips_decode_flags *flags, cdisasm_mips_instruction_v2 *instruction);
CDISASM_MIPS_API uint32_t CDISASM_CALL cdisasm_mips_decode_with_context_v2(const cdisasm_mips_decode_context *context, const uint8_t *code, size_t code_size, uint64_t address, cdisasm_mips_instruction_v2 *instruction);
CDISASM_MIPS_API size_t CDISASM_CALL cdisasm_mips_register_effects_v2(const cdisasm_mips_instruction_v2 *instruction, cdisasm_mips_register_effect *effects, size_t capacity);
/* The V1 effect-limitations contract also applies to complete V2 envelopes. */
CDISASM_MIPS_API cdisasm_mips_effect_limitations CDISASM_CALL cdisasm_mips_register_effect_limitations_v2(const cdisasm_mips_instruction_v2 *instruction);
/* The V1 family-query contract also applies to complete V2 envelopes and
 * paired VU results. Pair masks combine the two issued operations. Invalid
 * envelopes/pairs return FAMILY_NONE or FAMILY_MASK_NONE after strict replay
 * validation. */
CDISASM_MIPS_API cdisasm_mips_family_mask CDISASM_CALL cdisasm_mips_instruction_family_mask_v2(const cdisasm_mips_instruction_v2 *instruction);
CDISASM_MIPS_API cdisasm_mips_family_id CDISASM_CALL cdisasm_mips_instruction_family_v2(const cdisasm_mips_instruction_v2 *instruction);
CDISASM_MIPS_API uint32_t CDISASM_CALL cdisasm_mips_decode_vu(cdisasm_mips_vu_unit unit, const uint8_t *code, size_t code_size, uint64_t address, const cdisasm_mips_decode_flags *flags, cdisasm_mips_vu_instruction *instruction);
CDISASM_MIPS_API size_t CDISASM_CALL cdisasm_mips_register_effects_vu(const cdisasm_mips_vu_instruction *instruction, cdisasm_mips_register_effect *effects, size_t capacity);
CDISASM_MIPS_API cdisasm_mips_family_mask CDISASM_CALL cdisasm_mips_instruction_family_mask_vu(const cdisasm_mips_vu_instruction *instruction);
CDISASM_MIPS_API cdisasm_mips_family_id CDISASM_CALL cdisasm_mips_instruction_family_vu(const cdisasm_mips_vu_instruction *instruction);
#if USE_DISASM_FORMAT
CDISASM_MIPS_API size_t CDISASM_CALL cdisasm_mips_format_v2(const cdisasm_mips_instruction_v2 *instruction, uint32_t flags, char *buffer, size_t buffer_size);
CDISASM_MIPS_API size_t CDISASM_CALL cdisasm_mips_format_vu(const cdisasm_mips_vu_instruction *instruction, uint32_t flags, char *buffer, size_t buffer_size);
#endif

#ifdef __cplusplus
}
#endif
#endif
