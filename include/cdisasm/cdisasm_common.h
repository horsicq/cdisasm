#ifndef CDISASM_CDISASM_COMMON_H
#define CDISASM_CDISASM_COMMON_H

#include <stddef.h>
#include <stdint.h>

#include <cdisasm/cdisasm_config.h>
#include <cdisasm/cdisasm_version.h>

#if defined(_WIN32) || defined(__CYGWIN__)
#  if defined(CDISASM_STATIC)
#    define CDISASM_API
#  elif defined(CDISASM_BUILDING_LIBRARY)
#    define CDISASM_API __declspec(dllexport)
#  else
#    define CDISASM_API __declspec(dllimport)
#  endif
#  define CDISASM_CALL __cdecl
#elif defined(__GNUC__) || defined(__clang__)
#  if defined(CDISASM_STATIC)
#    define CDISASM_API __attribute__((visibility("hidden")))
#  else
#    define CDISASM_API __attribute__((visibility("default")))
#  endif
#  define CDISASM_CALL
#else
#  define CDISASM_API
#  define CDISASM_CALL
#endif

/**
 * Architecture namespace encoded in the upper 16 bits of every CPU ID.
 * The lower 16 bits are an architecture-local, append-only CPU ordinal.
 */
typedef uint32_t cdisasm_cpu_group;
/** Complete CPU profile ID, including its architecture group. */
typedef uint32_t cdisasm_cpu_id;
/** No reliable named CPU profile could be identified. */
#define CDISASM_CPU_UNKNOWN UINT32_C(0)
#define CDISASM_CPU_GROUP_MASK UINT32_C(0xffff0000)
#define CDISASM_CPU_ORDINAL_MASK UINT32_C(0x0000ffff)
#define CDISASM_CPU_GROUP_X86 UINT32_C(0x00010000)
#define CDISASM_CPU_GROUP_ARM UINT32_C(0x00020000)
#define CDISASM_CPU_GROUP_OF(cpu_id) \
    ((uint32_t)(cpu_id) & CDISASM_CPU_GROUP_MASK)
#define CDISASM_CPU_ORDINAL_OF(cpu_id) \
    ((uint32_t)(cpu_id) & CDISASM_CPU_ORDINAL_MASK)

/** One 64-bit word in an architecture-specific decode-flags bitmap. */
typedef uint64_t cdisasm_decode_flag_bitmap;

/**
 * Architecture-neutral storage passed to the generic decoder.
 *
 * Every architecture uses the same 64-byte layout, but assigns its own
 * meanings to the bits.  Bitmap 0 contains the original 64-bit option space;
 * the remaining bitmaps allow new independently selectable families without
 * changing the decoder ABI again.  A NULL flags pointer means that every
 * bitmap is zero.
 */
#define CDISASM_DECODE_FLAGS_BITMAP_COUNT 8u
#define CDISASM_DECODE_FLAGS_BIT_CAPACITY 512u
#define CDISASM_DECODE_FLAGS_SIZE 64u
typedef struct cdisasm_decode_flags {
    uint64_t bitmap[CDISASM_DECODE_FLAGS_BITMAP_COUNT];
} cdisasm_decode_flags;

/** Initializes bitmap 0 and zero-initializes every remaining bitmap word. */
#define CDISASM_DECODE_FLAGS_INITIALIZER(bitmap0_)                         \
    {{(uint64_t)(bitmap0_)}}
#define CDISASM_DECODE_FLAGS_NONE_INITIALIZER                             \
    CDISASM_DECODE_FLAGS_INITIALIZER(UINT64_C(0))

/** Clears every bitmap word. A NULL pointer is ignored. */
static inline void cdisasm_decode_flags_reset(cdisasm_decode_flags *flags)
{
    uint32_t index;

    if (flags == NULL) {
        return;
    }
    for (index = 0; index < CDISASM_DECODE_FLAGS_BITMAP_COUNT; ++index) {
        flags->bitmap[index] = UINT64_C(0);
    }
}

/** Sets one logical architecture-specific bit; returns zero if out of range. */
static inline int cdisasm_decode_flags_set_bit(
    cdisasm_decode_flags *flags,
    uint32_t bit_id)
{
    if (flags == NULL || bit_id >= CDISASM_DECODE_FLAGS_BIT_CAPACITY) {
        return 0;
    }
    flags->bitmap[bit_id / UINT32_C(64)]
        |= UINT64_C(1) << (bit_id % UINT32_C(64));
    return 1;
}

/** Clears one logical architecture-specific bit; returns zero if invalid. */
static inline int cdisasm_decode_flags_clear_bit(
    cdisasm_decode_flags *flags,
    uint32_t bit_id)
{
    if (flags == NULL || bit_id >= CDISASM_DECODE_FLAGS_BIT_CAPACITY) {
        return 0;
    }
    flags->bitmap[bit_id / UINT32_C(64)]
        &= ~(UINT64_C(1) << (bit_id % UINT32_C(64)));
    return 1;
}

/** Returns nonzero when one logical architecture-specific bit is set. */
static inline int cdisasm_decode_flags_test_bit(
    const cdisasm_decode_flags *flags,
    uint32_t bit_id)
{
    return flags != NULL
        && bit_id < CDISASM_DECODE_FLAGS_BIT_CAPACITY
        && (flags->bitmap[bit_id / UINT32_C(64)]
            & (UINT64_C(1) << (bit_id % UINT32_C(64)))) != 0;
}

/* Legacy spelling retained for source that stores one bitmap word.  It is
 * not the type accepted by cdisasm_decode in version 12 and later. */
typedef cdisasm_decode_flag_bitmap cdisasm_decode_option;
#define CDISASM_DECODE_OPTION_NONE UINT64_C(0)

typedef uint32_t cdisasm_status;
#define CDISASM_STATUS_OK UINT32_C(0)
#define CDISASM_STATUS_INVALID_ARGUMENT UINT32_C(1)
#define CDISASM_STATUS_END_OF_INPUT UINT32_C(2)
#define CDISASM_STATUS_TRUNCATED UINT32_C(3)
#define CDISASM_STATUS_INVALID_INSTRUCTION UINT32_C(4)
#define CDISASM_STATUS_UNSUPPORTED_INSTRUCTION UINT32_C(5)
#define CDISASM_STATUS_INTERNAL_ERROR UINT32_C(6)

/** Structured operand kinds shared by architecture decoders. */
typedef uint8_t cdisasm_operand_type;
enum {
    CDISASM_OPERAND_NONE = 0,
    CDISASM_OPERAND_REGISTER = 1,
    CDISASM_OPERAND_IMMEDIATE = 2,
    CDISASM_OPERAND_MEMORY = 3
};

/** Per-operand metadata flags. */
typedef uint8_t cdisasm_operand_flag;
enum {
    CDISASM_OPERAND_FLAG_NONE = 0,
    CDISASM_OPERAND_FLAG_SIGNED = 1u << 0,
    CDISASM_OPERAND_FLAG_IMPLICIT = 1u << 1,
    CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT = 1u << 2,
    CDISASM_OPERAND_FLAG_ABSOLUTE = 1u << 3,
    CDISASM_OPERAND_FLAG_PC_RELATIVE = 1u << 4,
    CDISASM_OPERAND_FLAG_HAS_ADDRESS = 1u << 5,
    CDISASM_OPERAND_FLAG_ADDRESS_ONLY = 1u << 6,
    CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT = 1u << 7
};

/** Data-flow access performed through one structured operand. */
typedef uint8_t cdisasm_operand_access;
enum {
    CDISASM_OPERAND_ACCESS_NONE = 0,
    CDISASM_OPERAND_ACCESS_READ = 1,
    CDISASM_OPERAND_ACCESS_WRITE = 2,
    CDISASM_OPERAND_ACCESS_READ_WRITE = 3
};

/** Architecture-independent instruction classification flags. */
typedef uint32_t cdisasm_group;
#define CDISASM_GROUP_NONE UINT32_C(0)
#define CDISASM_GROUP_JUMP (UINT32_C(1) << 0)
#define CDISASM_GROUP_CALL (UINT32_C(1) << 1)
#define CDISASM_GROUP_RETURN (UINT32_C(1) << 2)
#define CDISASM_GROUP_INTERRUPT (UINT32_C(1) << 3)
#define CDISASM_GROUP_INTERRUPT_RETURN (UINT32_C(1) << 4)
#define CDISASM_GROUP_PRIVILEGED (UINT32_C(1) << 5)
#define CDISASM_GROUP_RELATIVE_BRANCH (UINT32_C(1) << 6)
#define CDISASM_GROUP_CONDITIONAL (UINT32_C(1) << 7)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Returns the closest named cdisasm CPU profile visible to this process.
 *
 * The result describes the current execution environment, so a hypervisor or
 * ISA translation layer may expose a different CPU than the physical host.
 * It is an advisory catalog identity, not a complete runtime feature probe.
 * CDISASM_CPU_UNKNOWN is returned when the architecture is disabled, native
 * identification is unavailable, or no safe named profile is known. The
 * unrestricted CDISASM_CPU_X86 and CDISASM_ARM_CPU_ANY profiles are never
 * returned. Detection never changes decoder selection implicitly.
 */
CDISASM_API cdisasm_cpu_id CDISASM_CALL cdisasm_current_cpu(void);

/** Encodes the library version as 0x00MMmmpp (major, minor, patch). */
CDISASM_API uint32_t CDISASM_CALL cdisasm_version(void);

CDISASM_API const char *CDISASM_CALL cdisasm_version_string(void);

CDISASM_API const char *CDISASM_CALL cdisasm_status_string(cdisasm_status status);

/**
 * Returns the result-structure size required by the architecture in cpu_id.
 * The value is zero when that architecture is unknown or disabled.
 */
CDISASM_API size_t CDISASM_CALL cdisasm_instruction_size(
    cdisasm_cpu_id cpu_id);

/**
 * Writes every decode flag accepted for cpu_id and mode by this build.
 *
 * The output is cleared first. Architecture-specific meanings are selected by
 * the CPU group. Returns CDISASM_STATUS_INVALID_ARGUMENT for a NULL output,
 * unknown/disabled CPU group, invalid CPU, or unavailable mode.
 */
CDISASM_API cdisasm_status CDISASM_CALL cdisasm_cpu_decode_flag_mask(
    cdisasm_cpu_id cpu_id,
    uint32_t mode,
    cdisasm_decode_flags *flags);

/**
 * Decodes one instruction by dispatching on the architecture group in cpu_id.
 *
 * mode and instruction are architecture-specific. instruction must point to a
 * cdisasm_x86_instruction for an x86 CPU ID or a cdisasm_arm_instruction for
 * an ARM CPU ID. An unknown or disabled architecture returns zero without
 * accessing or modifying the result buffer. The selected architecture decoder
 * validates every bitmap in flags without narrowing it. Passing NULL selects
 * the architecture's base/default decoding policy.
 */
CDISASM_API uint32_t CDISASM_CALL cdisasm_decode(
    cdisasm_cpu_id cpu_id,
    uint32_t mode,
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    const cdisasm_decode_flags *flags,
    void *instruction);

/**
 * Size-checked generic decoder.
 *
 * For a non-NULL result, instruction_size must equal the value returned
 * by cdisasm_instruction_size(cpu_id). A size mismatch, unknown group, or
 * disabled architecture returns zero without accessing the result buffer.
 * A size-valid call applies the selected decoder's complete bitmap validation
 * exactly as cdisasm_decode does.
 * The unchecked cdisasm_decode entry point remains available when the caller
 * already has an architecture-specific type.
 */
CDISASM_API uint32_t CDISASM_CALL cdisasm_decode_checked(
    cdisasm_cpu_id cpu_id,
    uint32_t mode,
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    const cdisasm_decode_flags *flags,
    void *instruction,
    size_t instruction_size);

#ifdef __cplusplus
}
#endif

#endif
