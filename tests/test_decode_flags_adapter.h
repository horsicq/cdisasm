#ifndef CDISASM_TESTS_TEST_DECODE_FLAGS_ADAPTER_H
#define CDISASM_TESTS_TEST_DECODE_FLAGS_ADAPTER_H

/*
 * Keep the large behavioral corpus focused on instruction semantics while the
 * public version-12 API carries its former bitmap-0 masks in fixed-size flag
 * sets.  Contract tests call the public entry points directly and therefore
 * do not include this adapter.
 */
#include "cdisasm/cdisasm.h"

static inline const cdisasm_decode_flags *
cdisasm_test_decode_flags_from_word0(
    cdisasm_decode_option word0,
    cdisasm_decode_flags *storage)
{
    if (word0 == CDISASM_DECODE_OPTION_NONE) {
        return NULL;
    }
    *storage = (cdisasm_decode_flags)
        CDISASM_DECODE_FLAGS_INITIALIZER(word0);
    return storage;
}

static inline uint32_t cdisasm_test_decode(
    cdisasm_cpu_id cpu_id,
    uint32_t mode,
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    cdisasm_decode_option word0,
    void *instruction)
{
    cdisasm_decode_flags flags;

    return cdisasm_decode(
        cpu_id, mode, code, code_size, address,
        cdisasm_test_decode_flags_from_word0(word0, &flags), instruction);
}

static inline uint32_t cdisasm_test_decode_checked(
    cdisasm_cpu_id cpu_id,
    uint32_t mode,
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    cdisasm_decode_option word0,
    void *instruction,
    size_t instruction_size)
{
    cdisasm_decode_flags flags;

    return cdisasm_decode_checked(
        cpu_id, mode, code, code_size, address,
        cdisasm_test_decode_flags_from_word0(word0, &flags), instruction,
        instruction_size);
}

#if USE_ARCH_X86
static inline uint32_t cdisasm_test_x86_decode_exact_flags(
    cdisasm_x86_cpu_id cpu_id,
    cdisasm_x86_mode mode,
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    const cdisasm_x86_decode_flags *flags,
    cdisasm_x86_instruction *instruction)
{
    return cdisasm_x86_decode(
        cpu_id, mode, code, code_size, address, flags, instruction);
}

static inline cdisasm_x86_decode_option
cdisasm_test_x86_cpu_decode_flag_mask(
    cdisasm_x86_cpu_id cpu_id,
    cdisasm_x86_mode mode)
{
    cdisasm_x86_decode_flags flags;

    (void)cdisasm_x86_cpu_decode_flag_mask(cpu_id, mode, &flags);
    return flags.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP];
}

static inline uint32_t cdisasm_test_x86_decode(
    cdisasm_x86_cpu_id cpu_id,
    cdisasm_x86_mode mode,
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    cdisasm_x86_decode_option word0,
    cdisasm_x86_instruction *instruction)
{
    cdisasm_x86_decode_flags flags;

    return cdisasm_x86_decode(
        cpu_id, mode, code, code_size, address,
        (const cdisasm_x86_decode_flags *)
            cdisasm_test_decode_flags_from_word0(word0, &flags),
        instruction);
}
#endif

#if USE_ARCH_ARM
static inline uint32_t cdisasm_test_arm_decode(
    cdisasm_arm_cpu_id cpu_id,
    cdisasm_arm_mode mode,
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    cdisasm_arm_decode_option word0,
    cdisasm_arm_instruction *instruction)
{
    cdisasm_arm_decode_flags flags;

    return cdisasm_arm_decode(
        cpu_id, mode, code, code_size, address,
        (const cdisasm_arm_decode_flags *)
            cdisasm_test_decode_flags_from_word0(word0, &flags),
        instruction);
}
#endif

#define cdisasm_decode cdisasm_test_decode
#define cdisasm_decode_checked cdisasm_test_decode_checked
#if USE_ARCH_X86
#  define cdisasm_x86_decode cdisasm_test_x86_decode
#  define cdisasm_x86_cpu_decode_flag_mask \
    cdisasm_test_x86_cpu_decode_flag_mask
#endif
#if USE_ARCH_ARM
#  define cdisasm_arm_decode cdisasm_test_arm_decode
#endif

#endif
