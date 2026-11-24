#ifndef CDISASM_CDISASM_SPU_H
#define CDISASM_CDISASM_SPU_H

/* IBM Synergistic Processor Unit, a separate architecture from PowerPC.
 * Instructions are exactly four bytes in big-endian storage. The 128
 * registers contain 128 bits; execution addresses are 32 bits. This API
 * describes encodings, not execution, privilege or floating-point results.
 * Authority: SPU ISA v1.2 (2007-01-27), Assembly Language Specification
 * v1.6 (2007-09-03), and SPU ABI v1.8 (2007-09-03). */
#include "cdisasm_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef cdisasm_cpu_id cdisasm_spu_cpu_id;
#ifndef CDISASM_CPU_GROUP_SPU
#define CDISASM_CPU_GROUP_SPU UINT32_C(0x00060000)
#endif
#define CDISASM_SPU_CPU_SPU (CDISASM_CPU_GROUP_SPU | UINT32_C(0))
#define CDISASM_SPU_CPU_CELL_SPU (CDISASM_CPU_GROUP_SPU | UINT32_C(1))
#define CDISASM_SPU_CPU_SPU12_DP (CDISASM_CPU_GROUP_SPU | UINT32_C(2))
#define CDISASM_SPU_CPU_COUNT 3u
#define CDISASM_SPU_MODE_32 32u
#define CDISASM_SPU_MODE_MASK_32 1u
#define CDISASM_SPU_FEATURE_BASE UINT32_C(1)
#define CDISASM_SPU_FEATURE_MFC UINT32_C(2)
#define CDISASM_SPU_FEATURE_DP_COMPARE UINT32_C(4)
#define CDISASM_SPU_DEFAULT_LOCAL_STORE_MASK UINT32_C(0x0003ffff)
/* Reserved, deliberately unsupported: flags containing this bit fail.
 * There is no byte-swapped instruction-buffer mode in this API. */
#define CDISASM_SPU_DECODE_LITTLE_ENDIAN UINT64_C(1)

#define CDISASM_SPU_OP_NONE 0u
#define CDISASM_SPU_OP_REGISTER 1u
#define CDISASM_SPU_OP_IMMEDIATE 2u
#define CDISASM_SPU_OP_CHANNEL 3u
#define CDISASM_SPU_OP_SPR 4u
#define CDISASM_SPU_OP_ADDRESS 5u
#define CDISASM_SPU_OP_MEMORY 6u
#define CDISASM_SPU_OP_HINT 7u
#define CDISASM_SPU_ACCESS_READ 1u
#define CDISASM_SPU_ACCESS_WRITE 2u
#define CDISASM_SPU_OPERAND_SIGNED 1u
#define CDISASM_SPU_OPERAND_RELATIVE 2u
#define CDISASM_SPU_OPERAND_ABSOLUTE 4u
#define CDISASM_SPU_OPERAND_SCALE_NEGATE 8u
/* A conversion scale outside 0..127 is an encoded but undefined operation,
 * not a reserved opcode (ISA conversion definitions). */
#define CDISASM_SPU_OPERAND_EXECUTION_UNDEFINED 16u
#define CDISASM_SPU_FLAG_JUMP 1u
#define CDISASM_SPU_FLAG_BRANCH 2u
#define CDISASM_SPU_FLAG_CALL 4u
#define CDISASM_SPU_FLAG_RETURN 8u
#define CDISASM_SPU_FLAG_STOP 16u
#define CDISASM_SPU_FLAG_LOAD 32u
#define CDISASM_SPU_FLAG_STORE 64u
#define CDISASM_SPU_FLAG_HINT 128u
#define CDISASM_SPU_CONTROL_DISABLE UINT32_C(0x00080000)
#define CDISASM_SPU_CONTROL_ENABLE UINT32_C(0x00040000)
#define CDISASM_SPU_CONTROL_PREFETCH UINT32_C(0x00100000)
#define CDISASM_SPU_CONTROL_CHANNEL_SYNC UINT32_C(0x00100000)
#define CDISASM_SPU_CONSTRAINT_NONE 0u
#define CDISASM_SPU_CONSTRAINT_DE 1u
#define CDISASM_SPU_CONSTRAINT_HBR 2u
#define CDISASM_SPU_MAX_OPERANDS 4u
#define CDISASM_SPU_MAX_LENGTH 4u

/* C bit numbering, least-significant bit zero. A logical field is the OR
 * of each ((word >> lsb) & ((1 << width)-1)) << value_lsb. This also
 * represents the split signed nine-bit branch-hint RO field. */
typedef struct cdisasm_spu_field {
    uint8_t lsb, width, value_lsb, reserved;
} cdisasm_spu_field;

typedef struct cdisasm_spu_form_operand {
    uint8_t kind, access, bits, shift;
    uint16_t flags;
    int16_t bias;
    uint8_t field_count, base_lsb, base_width, reserved;
    cdisasm_spu_field field[2];
} cdisasm_spu_form_operand;

/* Public read-only recipes are the sole encoder catalog. Immediate value is
 * sign_extend(raw,bits)*2^shift, or (bias-raw)*2^shift for SCALE_NEGATE.
 * Memory has an independent base register at base_lsb/base_width.
 * IDs are append-only within this catalog, never shared with PPC. */
typedef struct cdisasm_spu_form {
    uint32_t mask, match, name_id, profile_mask, flags, control_mask;
    uint8_t operand_count, constraint, reserved[2];
    cdisasm_spu_form_operand operand[CDISASM_SPU_MAX_OPERANDS];
} cdisasm_spu_form;

typedef struct cdisasm_spu_alias {
    const char *name;
    uint32_t form_id, mask, match;
    uint8_t operand_count, operand_index[CDISASM_SPU_MAX_OPERANDS];
} cdisasm_spu_alias;

typedef struct cdisasm_spu_profile {
    uint32_t cpu_id, profile_mask, features, local_store_mask;
    const char *name;
} cdisasm_spu_profile;

typedef struct cdisasm_spu_channel {
    const char *name;
    uint16_t number;
    uint8_t profile_mask, access;
} cdisasm_spu_channel;

typedef struct cdisasm_spu_operand {
    /* size is16 for registers/quadword transfers and0 for address-only
     * generate-controls operands, channels, selectors and immediates. */
    uint8_t type, access, size, reg;
    uint8_t base, bits, shift, reserved;
    uint16_t flags, reserved2;
    uint32_t raw;      /* Complete logical field, including ignored bits. */
    int64_t value;     /* Encoded immediate/displacement after its recipe. */
    uint64_t target;   /* Effective masked target, independent of value. */
} cdisasm_spu_operand;

typedef struct cdisasm_spu_instruction {
    uint64_t address, branch_target;
    uint32_t cpu_id, length, form_id, name_id, word, flags, controls;
    uint32_t local_store_mask;
    uint8_t operand_count, reserved[3];
    cdisasm_spu_operand operand[CDISASM_SPU_MAX_OPERANDS];
    uint8_t bytes[CDISASM_SPU_MAX_LENGTH];
} cdisasm_spu_instruction;

CDISASM_API const char *CDISASM_CALL cdisasm_spu_cpu_name(cdisasm_spu_cpu_id cpu);
CDISASM_API cdisasm_spu_cpu_id CDISASM_CALL cdisasm_spu_cpu_from_name(const char *name);
CDISASM_API uint32_t CDISASM_CALL cdisasm_spu_cpu_features(cdisasm_spu_cpu_id cpu);
CDISASM_API uint32_t CDISASM_CALL cdisasm_spu_cpu_mode_mask(cdisasm_spu_cpu_id cpu);
CDISASM_API uint32_t CDISASM_CALL cdisasm_spu_profile_count(void);
CDISASM_API const cdisasm_spu_profile *CDISASM_CALL cdisasm_spu_profiles(void);
CDISASM_API const cdisasm_spu_profile *CDISASM_CALL cdisasm_spu_profile_at(uint32_t index);
CDISASM_API cdisasm_status CDISASM_CALL cdisasm_spu_cpu_decode_flag_mask(cdisasm_spu_cpu_id cpu, uint32_t mode, cdisasm_decode_flags *flags);
/* mode=0 and mode=32 select 32-bit addressing. All flag bits are rejected.
 * The ordinary entry point uses the conventional 256KiB LSLR, not a claim
 * that the generic ISA requires that size. The explicit entry point accepts
 * any mask 2^n-1, 4<=n<=32 (ISA section3); arithmetic wraps at that mask.
 * Encoded address bits and signed displacements remain available verbatim.
 * On any failure the non-NULL result is cleared. */
CDISASM_API uint32_t CDISASM_CALL cdisasm_spu_decode(cdisasm_spu_cpu_id cpu, uint32_t mode, const uint8_t *code, size_t code_size, uint64_t address, const cdisasm_decode_flags *flags, cdisasm_spu_instruction *instruction);
CDISASM_API uint32_t CDISASM_CALL cdisasm_spu_decode_lslr(cdisasm_spu_cpu_id cpu, uint32_t mode, const uint8_t *code, size_t code_size, uint64_t address, const cdisasm_decode_flags *flags, uint32_t local_store_mask, cdisasm_spu_instruction *instruction);
CDISASM_API uint32_t CDISASM_CALL cdisasm_spu_form_count(void);
CDISASM_API const cdisasm_spu_form *CDISASM_CALL cdisasm_spu_forms(void);
CDISASM_API const char *CDISASM_CALL cdisasm_spu_name(uint32_t name_id);
CDISASM_API uint32_t CDISASM_CALL cdisasm_spu_alias_count(void);
CDISASM_API const cdisasm_spu_alias *CDISASM_CALL cdisasm_spu_aliases(void);
CDISASM_API uint32_t CDISASM_CALL cdisasm_spu_field_get(uint32_t word, const cdisasm_spu_form_operand *operand);
CDISASM_API int CDISASM_CALL cdisasm_spu_field_set(uint32_t *word, const cdisasm_spu_form_operand *operand, uint32_t raw);
CDISASM_API int CDISASM_CALL cdisasm_spu_form_available(const cdisasm_spu_form *form, cdisasm_spu_cpu_id cpu, uint32_t mode, const cdisasm_decode_flags *flags);
CDISASM_API int CDISASM_CALL cdisasm_spu_form_valid(const cdisasm_spu_form *form, cdisasm_spu_cpu_id cpu, uint32_t mode, const cdisasm_decode_flags *flags, uint32_t word);
/* Source vocabularies are profile- and direction-aware; unknown numeric
 * channels 0..127 remain representable and do not promise implementation.
 * write=0 selects read names, write>0 write names, write<0 either direction
 * (rchcnt can query both read and write channels). */
CDISASM_API uint32_t CDISASM_CALL cdisasm_spu_channel_count(void);
CDISASM_API const cdisasm_spu_channel *CDISASM_CALL cdisasm_spu_channels(void);
CDISASM_API const char *CDISASM_CALL cdisasm_spu_channel_name(cdisasm_spu_cpu_id cpu, uint32_t channel, int write);
CDISASM_API int32_t CDISASM_CALL cdisasm_spu_channel_from_name(cdisasm_spu_cpu_id cpu, const char *name, int write);

#define CDISASM_SPU_FORMAT_REGISTER_NAMES 1u
#define CDISASM_SPU_FORMAT_BASE_MNEMONICS 2u
/* Numeric or IBM $N / $LR / $SP register names; named channels fall back to
 * $chN and numeric SPR selectors use GNU $spN. NOP always uses $N when an explicit false target is present because
 * GNU interprets a bare number as a repeat count. Base mode suppresses
 * convenience aliases but retains architectural d/e/c/p control spellings.
 * Relative addresses print .+/-displacement to preserve wrap encodings.
 * All encoded bits remain represented. Explicit ignored HBRP registers and
 * undefined conversion scales extend the conventional source subset;
 * external assemblers may reject those lossless spellings. */
CDISASM_API size_t CDISASM_CALL cdisasm_spu_format(const cdisasm_spu_instruction *instruction, uint32_t options, char *text, size_t capacity);
CDISASM_API size_t CDISASM_CALL cdisasm_spu_format_operand(const cdisasm_spu_instruction *instruction, uint32_t index, uint32_t options, char *text, size_t capacity);

#ifdef __cplusplus
}
#endif
#endif
