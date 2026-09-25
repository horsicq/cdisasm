#include <stddef.h>
#include <stdint.h>

#include <cdisasm/cdisasm.h>
#if USE_DISASM_FORMAT
#  include <cdisasm/cdisasm_format.h>
#endif

#if defined(_WIN32) || defined(__CYGWIN__)
#  define CDISASM_WRAPPER_EXPORT __declspec(dllexport)
#elif defined(__GNUC__) || defined(__clang__)
#  define CDISASM_WRAPPER_EXPORT __attribute__((visibility("default")))
#else
#  define CDISASM_WRAPPER_EXPORT
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

/*
 * Keep a real reference to every public entry point compiled into this
 * package. The calls use invalid/empty inputs deliberately; all decoder and
 * formatter APIs define those paths as zero-returning and non-dereferencing.
 */
CDISASM_WRAPPER_EXPORT int cdisasm_package_wrapper_probe(void)
{
    uint32_t value = cdisasm_version();
    cdisasm_decode_flags generic_flags =
        CDISASM_DECODE_FLAGS_NONE_INITIALIZER;

    value += cdisasm_version_string() != NULL;
    value += cdisasm_status_string(CDISASM_STATUS_OK) != NULL;
    value += cdisasm_current_cpu();
    value += (uint32_t)cdisasm_instruction_size(0);
    value += cdisasm_cpu_decode_flag_mask(0, 0, &generic_flags);
    value += cdisasm_decode(0, 0, NULL, 0, 0, NULL, NULL);
    value += cdisasm_decode_checked(0, 0, NULL, 0, 0, NULL, NULL, 0);

#if USE_ARCH_X86
    {
        cdisasm_x86_decode_flags flags =
            CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

        value += cdisasm_x86_cpu_mode_mask((cdisasm_x86_cpu_id)0);
        value += cdisasm_x86_cpu_decode_flag_mask(
            (cdisasm_x86_cpu_id)0, (cdisasm_x86_mode)0, &flags);
        value += (uint32_t)flags.bitmap[0];
        value += cdisasm_x86_decode(
            CDISASM_CPU_X86, CDISASM_MODE_32, NULL, 0, 0, NULL, NULL);
    }
#endif

#if USE_ARCH_ARM
    {
        cdisasm_arm_decode_flags flags =
            CDISASM_ARM_DECODE_FLAGS_NONE_INITIALIZER;

        value += cdisasm_arm_cpu_mode_mask((cdisasm_arm_cpu_id)0);
        value += cdisasm_arm_decoder_mode_mask((cdisasm_arm_cpu_id)0);
        value += cdisasm_arm_cpu_decode_flag_mask(
            (cdisasm_arm_cpu_id)0, (cdisasm_arm_mode)0, &flags);
        value += (uint32_t)flags.bitmap[0];
        value += cdisasm_arm_decode(
            (cdisasm_arm_cpu_id)0,
            (cdisasm_arm_mode)0,
            NULL,
            0,
            0,
            NULL,
            NULL);
    }
#endif

#if USE_DISASM_FORMAT && USE_ARCH_X86
    value += (uint32_t)cdisasm_x86_format(NULL, 0, NULL, 0);
    value += (uint32_t)cdisasm_x86_format_mode(
        NULL, CDISASM_MODE_32, 0, NULL, 0);
    value += (uint32_t)cdisasm_format(NULL, 0, NULL, 0);
#endif

#if USE_DISASM_FORMAT && USE_ARCH_ARM
    value += (uint32_t)cdisasm_arm_format(NULL, 0, NULL, 0);
#endif

    return (int)(value & UINT32_C(0x7fffffff));
}
