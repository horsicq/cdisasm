#include <cdisasm/cdisasm.h>

#if USE_DISASM_FORMAT && (USE_ARCH_X86 || USE_ARCH_ARM)
#  include <cdisasm/cdisasm_format.h>
#endif

#include <stddef.h>
#include <stdint.h>

#ifndef CDISASM_STATIC
#  error "the installed static target does not propagate CDISASM_STATIC"
#endif
#if USE_ARCH_X86 != CDISASM_STATIC_EMBED_EXPECT_X86
#  error "installed x86 feature does not match the embedding expectation"
#endif
#if USE_ARCH_ARM != CDISASM_STATIC_EMBED_EXPECT_ARM
#  error "installed ARM feature does not match the embedding expectation"
#endif
#if USE_DISASM_FORMAT != CDISASM_STATIC_EMBED_EXPECT_FORMAT
#  error "installed formatter feature does not match the embedding expectation"
#endif
#if USE_EXTRA_OPCODES != CDISASM_STATIC_EMBED_EXPECT_EXTRA
#  error "installed extra-opcode feature does not match the embedding expectation"
#endif
#if USE_ARCH_X86
#  if CDISASM_X86_DECODE_FLAG_FPU != UINT64_C(0x00000001) \
      || CDISASM_X86_DECODE_FLAG_AVX != UINT64_C(0x00000100) \
      || CDISASM_X86_DECODE_FLAG_UNDOCUMENTED != UINT64_C(0x40000000) \
      || CDISASM_X86_DECODE_FLAG_AVX512_VBMI2 != UINT64_C(0x200000000) \
      || CDISASM_X86_DECODE_FLAG_AVX512_VPOPCNTDQ \
          != UINT64_C(0x400000000) \
      || CDISASM_X86_DECODE_FLAG_AVX512_BITALG != UINT64_C(0x800000000) \
      || CDISASM_X86_DECODE_FLAG_COMPRESS_EXPAND \
          != UINT64_C(0x1000000000) \
      || CDISASM_X86_DECODE_FLAG_BMI2 != UINT64_C(0x800000000000000) \
      || CDISASM_X86_DECODE_FLAG_AVX512_CD \
          != UINT64_C(0x1000000000000000) \
      || CDISASM_X86_DECODE_FLAG_AVX_VNNI \
          != UINT64_C(0x2000000000000000) \
      || CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT8 \
          != UINT64_C(0x4000000000000000) \
      || CDISASM_X86_DECODE_FLAG_AVX_VNNI_INT16 \
          != UINT64_C(0x8000000000000000) \
      || CDISASM_X86_DECODE_FLAG_ALL != UINT64_C(0xffffffffffffffff) \
      || CDISASM_X86_DECODE_FLAG_KNOWN_MASK \
          != UINT64_C(0xffffffffffffffff)
#    error "installed static package has unexpected x86 decode-family flags"
#  endif
#endif

_Static_assert(sizeof(cdisasm_decode_option) == 8,
               "installed generic decode-option width changed");
_Static_assert(sizeof(cdisasm_decode_flags) == CDISASM_DECODE_FLAGS_SIZE,
               "installed generic decode-flags ABI size changed");
#if USE_ARCH_X86
_Static_assert(sizeof(cdisasm_x86_decode_option) == 8,
               "installed x86 decode-option width changed");
_Static_assert(sizeof(cdisasm_x86_decode_flags)
                   == sizeof(cdisasm_decode_flags),
               "installed x86 decode-flags ABI size changed");
#endif
#if USE_ARCH_ARM
_Static_assert(sizeof(cdisasm_arm_decode_option) == 8,
               "installed ARM decode-option width changed");
_Static_assert(sizeof(cdisasm_arm_decode_flags)
                   == sizeof(cdisasm_decode_flags),
               "installed ARM decode-flags ABI size changed");
#endif

#if defined(__GNUC__) || defined(__clang__)
#  define STATIC_EMBED_EXPORT __attribute__((visibility("default")))
#else
#  define STATIC_EMBED_EXPORT
#endif

/*
 * This is deliberately the wrapper's only exported symbol. Calling every
 * enabled public entry point pulls the common facade, architecture adapters,
 * decoder engines, and formatter objects out of the installed static archive.
 */
STATIC_EMBED_EXPORT uint32_t package_static_embed_probe(void)
{
    uint32_t value = cdisasm_version();
    const char *version = cdisasm_version_string();
    const char *status = cdisasm_status_string(CDISASM_STATUS_OK);
    cdisasm_decode_flags generic_flags =
        CDISASM_DECODE_FLAGS_NONE_INITIALIZER;

    value ^= version != NULL ? UINT32_C(0x01000000) : UINT32_C(0);
    value ^= status != NULL ? UINT32_C(0x02000000) : UINT32_C(0);
    value ^= cdisasm_current_cpu();
    value ^= (uint32_t)cdisasm_instruction_size(UINT32_C(0));
    value ^= cdisasm_cpu_decode_flag_mask(
        UINT32_C(0), UINT32_C(0), &generic_flags);
    value ^= cdisasm_decode(
        UINT32_C(0), UINT32_C(0), NULL, 0, 0, NULL, NULL);
    value ^= cdisasm_decode_checked(
        UINT32_C(0), UINT32_C(0), NULL, 0, 0, NULL, NULL, 0);

#if USE_ARCH_X86
    {
        static const uint8_t code[] = { UINT8_C(0x90) };
        cdisasm_x86_instruction instruction = {0};
        cdisasm_x86_decode_flags available =
            CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

        value ^= cdisasm_x86_cpu_mode_mask(CDISASM_CPU_80386);
        value ^= cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_80386, CDISASM_X86_MODE_32, &available);
        value ^= (uint32_t)available.bitmap[0];
        value ^= cdisasm_x86_decode(
            CDISASM_CPU_80386,
            CDISASM_X86_MODE_32,
            code,
            sizeof(code),
            UINT64_C(0x1000),
            NULL,
            &instruction);
#  if USE_DISASM_FORMAT
        value ^= (uint32_t)cdisasm_x86_format(
            &instruction, CDISASM_FORMAT_SYNTAX_INTEL, NULL, 0);
        value ^= (uint32_t)cdisasm_x86_format_mode(
            &instruction,
            CDISASM_X86_MODE_32,
            CDISASM_FORMAT_SYNTAX_ATT,
            NULL,
            0);
        value ^= (uint32_t)cdisasm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_INTEL, NULL, 0);
#  endif
    }
#endif

#if USE_ARCH_ARM
    {
        static const uint8_t code[] = {
            UINT8_C(0x05), UINT8_C(0x00), UINT8_C(0x81), UINT8_C(0xe2)
        };
        cdisasm_arm_instruction instruction = {0};
        cdisasm_arm_decode_flags available =
            CDISASM_ARM_DECODE_FLAGS_NONE_INITIALIZER;

        value ^= cdisasm_arm_cpu_mode_mask(CDISASM_ARM_CPU_CORTEX_A7);
        value ^= cdisasm_arm_decoder_mode_mask(CDISASM_ARM_CPU_CORTEX_A7);
        value ^= cdisasm_arm_cpu_decode_flag_mask(
            CDISASM_ARM_CPU_CORTEX_A7,
            CDISASM_ARM_MODE_A32,
            &available);
        value ^= (uint32_t)available.bitmap[0];
        value ^= cdisasm_arm_decode(
            CDISASM_ARM_CPU_CORTEX_A7,
            CDISASM_ARM_MODE_A32,
            code,
            sizeof(code),
            UINT64_C(0x2000),
            NULL,
            &instruction);
#  if USE_DISASM_FORMAT
        value ^= (uint32_t)cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_0, NULL, 0);
#  endif
    }
#endif

    return value;
}
