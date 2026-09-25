#ifndef CDISASM_CDISASM_FORMAT_H
#define CDISASM_CDISASM_FORMAT_H

#include <stddef.h>

#include "cdisasm_common.h"

#if !USE_DISASM_FORMAT
#  error "cdisasm formatting is disabled in this build"
#elif !USE_ARCH_X86 && !USE_ARCH_ARM
#  error "cdisasm formatting requires an enabled architecture"
#endif

#if USE_DISASM_FORMAT && USE_ARCH_X86
#  include "cdisasm_x86.h"
#endif

#if USE_DISASM_FORMAT && USE_ARCH_ARM
#  include "cdisasm_arm.h"
#endif

/* Formatter exports are owned by the same cdisasm library as decoder exports. */
#define CDISASM_FORMAT_API CDISASM_API

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Formatter options. The low three bits select syntax 0 through syntax 7.
 * For x86, syntax 0 is Intel and syntax 1 is AT&T. Syntax 2 through 7 are
 * permanent compatibility aliases for Intel syntax; their observable meaning
 * will not be reassigned. For ARM, selectors 0 through 7 are permanent aliases
 * for the canonical architecture syntax. New dialects require new option
 * space instead of changing an existing numeric selector. Syntax 0 preserves
 * the default syntax emitted by cdisasm 8.x and earlier.
 * CDISASM_FORMAT_UPPERCASE_OPCODE uppercases the mnemonic/opcode token and
 * its attached suffixes (and emitted x86 instruction-prefix words), while
 * leaving operands in canonical case.
 *
 * Bits at and above 0x10 are reserved for future formatter options and must
 * be zero. Callers can use CDISASM_FORMAT_KNOWN_FLAGS_MASK when validating or
 * forwarding options across an API boundary.
 */
#define CDISASM_FORMAT_SYNTAX_MASK UINT32_C(0x07)
#define CDISASM_FORMAT_SYNTAX_0 UINT32_C(0x00)
#define CDISASM_FORMAT_SYNTAX_1 UINT32_C(0x01)
#define CDISASM_FORMAT_SYNTAX_2 UINT32_C(0x02)
#define CDISASM_FORMAT_SYNTAX_3 UINT32_C(0x03)
#define CDISASM_FORMAT_SYNTAX_4 UINT32_C(0x04)
#define CDISASM_FORMAT_SYNTAX_5 UINT32_C(0x05)
#define CDISASM_FORMAT_SYNTAX_6 UINT32_C(0x06)
#define CDISASM_FORMAT_SYNTAX_7 UINT32_C(0x07)
#define CDISASM_FORMAT_SYNTAX_INTEL CDISASM_FORMAT_SYNTAX_0
#define CDISASM_FORMAT_SYNTAX_ATT CDISASM_FORMAT_SYNTAX_1
#define CDISASM_FORMAT_SYNTAX_X86_INTEL CDISASM_FORMAT_SYNTAX_0
#define CDISASM_FORMAT_SYNTAX_X86_ATT CDISASM_FORMAT_SYNTAX_1
#define CDISASM_FORMAT_SYNTAX_ARM_CANONICAL CDISASM_FORMAT_SYNTAX_0
#define CDISASM_FORMAT_UPPERCASE_OPCODE UINT32_C(0x08)
#define CDISASM_FORMAT_KNOWN_FLAGS_MASK UINT32_C(0x0f)

/**
 * Formatter calls return the complete output length excluding the terminating
 * NUL. A zero buffer_size performs a size query and does not access buffer.
 * Nonempty buffers are always NUL-terminated, including on failure.
 */

#if USE_DISASM_FORMAT && USE_ARCH_X86
/** Formats one successfully decoded x86 instruction using the selected syntax. */
CDISASM_FORMAT_API size_t CDISASM_CALL cdisasm_x86_format(
    const cdisasm_x86_instruction *instruction,
    uint32_t flags,
    char *buffer,
    size_t buffer_size);

/**
 * Formats one x86 instruction with its decode mode available to the formatter.
 *
 * The mode supplies the operand width for AT&T control-transfer and stack
 * forms whose structured operands do not retain it. An invalid mode fails with
 * the same zero-length, NUL-termination contract as invalid formatter flags.
 * Intel output is identical to cdisasm_x86_format for the same instruction and
 * flags.
 */
CDISASM_FORMAT_API size_t CDISASM_CALL cdisasm_x86_format_mode(
    const cdisasm_x86_instruction *instruction,
    cdisasm_mode mode,
    uint32_t flags,
    char *buffer,
    size_t buffer_size);

/** Compatibility spelling for cdisasm_x86_format. */
CDISASM_FORMAT_API size_t CDISASM_CALL cdisasm_format(
    const cdisasm_instruction *instruction,
    uint32_t flags,
    char *buffer,
    size_t buffer_size);
#endif

#if USE_DISASM_FORMAT && USE_ARCH_ARM
/**
 * Formats one successfully decoded ARM instruction using the selected syntax.
 * For an instruction whose operands are opaque, a nonzero return guarantees
 * that an exact generated recipe rendered every operand; otherwise the call
 * returns zero and leaves a nonempty buffer as an empty string.
 */
CDISASM_FORMAT_API size_t CDISASM_CALL cdisasm_arm_format(
    const cdisasm_arm_instruction *instruction,
    uint32_t flags,
    char *buffer,
    size_t buffer_size);
#endif

#ifdef __cplusplus
}
#endif

#endif
