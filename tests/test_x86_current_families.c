#include "cdisasm/cdisasm_x86.h"

#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>

static const char *family_name(cdisasm_x86_family_id family_id)
{
    switch (family_id) {
        case CDISASM_X86_FAMILY_AVX512_EVEX:
            return "AVX512_EVEX";
        case CDISASM_X86_FAMILY_APX_EVEX:
            return "APX_EVEX";
        case CDISASM_X86_FAMILY_AVX2_GATHER:
            return "AVX2_GATHER";
        case CDISASM_X86_FAMILY_FRED:
            return "FRED";
        case CDISASM_X86_FAMILY_TDX:
            return "TDX";
        case CDISASM_X86_FAMILY_VIA_PADLOCK:
            return "VIA_PADLOCK";
        case CDISASM_X86_FAMILY_X87:
            return "X87";
        case CDISASM_X86_FAMILY_MOVRS:
            return "MOVRS";
        case CDISASM_X86_FAMILY_INTEL_VMX:
            return "INTEL_VMX";
        case CDISASM_X86_FAMILY_AMD_SVM:
            return "AMD_SVM";
        case CDISASM_X86_FAMILY_MMX:
            return "MMX";
        case CDISASM_X86_FAMILY_3DNOW:
            return "3DNOW";
        case CDISASM_X86_FAMILY_SSE:
            return "SSE";
        case CDISASM_X86_FAMILY_SSE2:
            return "SSE2";
        case CDISASM_X86_FAMILY_SSE3:
            return "SSE3";
        case CDISASM_X86_FAMILY_SSSE3:
            return "SSSE3";
        case CDISASM_X86_FAMILY_SSE4:
            return "SSE4";
        case CDISASM_X86_FAMILY_AVX:
            return "AVX";
        case CDISASM_X86_FAMILY_AVX2:
            return "AVX2";
        case CDISASM_X86_FAMILY_F16C:
            return "F16C";
        case CDISASM_X86_FAMILY_FMA3:
            return "FMA3";
        case CDISASM_X86_FAMILY_XOP:
            return "XOP";
        case CDISASM_X86_FAMILY_FMA4:
            return "FMA4";
        case CDISASM_X86_FAMILY_AES:
            return "AES";
        case CDISASM_X86_FAMILY_PCLMUL:
            return "PCLMUL";
        case CDISASM_X86_FAMILY_SHA:
            return "SHA";
        case CDISASM_X86_FAMILY_GFNI:
            return "GFNI";
        case CDISASM_X86_FAMILY_BITMANIP:
            return "BITMANIP";
        case CDISASM_X86_FAMILY_AVX10:
            return "AVX10";
        case CDISASM_X86_FAMILY_AMX:
            return "AMX";
        default:
            return "UNKNOWN";
    }
}

static cdisasm_x86_mode select_mode(cdisasm_x86_mode_mask modes)
{
    if ((modes & CDISASM_X86_MODE_MASK_64) != 0) {
        return CDISASM_MODE_64;
    }
    if ((modes & CDISASM_X86_MODE_MASK_32) != 0) {
        return CDISASM_MODE_32;
    }
    return CDISASM_MODE_16;
}

/* Family IDs are append-only ABI values.  Keep their presentation order
 * independent from those values so ISA generations read naturally. */
static const cdisasm_x86_family_id family_print_order[] = {
    CDISASM_X86_FAMILY_X87,
    CDISASM_X86_FAMILY_MMX,
    CDISASM_X86_FAMILY_3DNOW,
    CDISASM_X86_FAMILY_SSE,
    CDISASM_X86_FAMILY_SSE2,
    CDISASM_X86_FAMILY_SSE3,
    CDISASM_X86_FAMILY_SSSE3,
    CDISASM_X86_FAMILY_SSE4,
    CDISASM_X86_FAMILY_AVX,
    CDISASM_X86_FAMILY_AVX2,
    CDISASM_X86_FAMILY_AVX2_GATHER,
    CDISASM_X86_FAMILY_F16C,
    CDISASM_X86_FAMILY_FMA3,
    CDISASM_X86_FAMILY_AVX512_EVEX,
    CDISASM_X86_FAMILY_APX_EVEX,
    CDISASM_X86_FAMILY_XOP,
    CDISASM_X86_FAMILY_FMA4,
    CDISASM_X86_FAMILY_AES,
    CDISASM_X86_FAMILY_PCLMUL,
    CDISASM_X86_FAMILY_SHA,
    CDISASM_X86_FAMILY_GFNI,
    CDISASM_X86_FAMILY_BITMANIP,
    CDISASM_X86_FAMILY_AVX10,
    CDISASM_X86_FAMILY_AMX,
    CDISASM_X86_FAMILY_INTEL_VMX,
    CDISASM_X86_FAMILY_AMD_SVM,
    CDISASM_X86_FAMILY_FRED,
    CDISASM_X86_FAMILY_TDX,
    CDISASM_X86_FAMILY_VIA_PADLOCK,
    CDISASM_X86_FAMILY_MOVRS
};

static void print_families(
    const char *label,
    cdisasm_x86_family_mask mask)
{
    size_t index;
    int printed = 0;

    printf("%s (0x%016" PRIx64 "):\n", label, (uint64_t)mask);
    for (index = 0;
         index < sizeof(family_print_order) / sizeof(family_print_order[0]);
         ++index) {
        const cdisasm_x86_family_id family_id = family_print_order[index];
        const cdisasm_x86_family_mask bit =
            UINT64_C(1) << ((uint32_t)family_id - UINT32_C(1));
        if ((mask & bit) != 0) {
            printf("  - %s (id=%u)\n",
                   family_name(family_id),
                   (unsigned)family_id);
            printed = 1;
        }
    }
    if (!printed) {
        puts("  - none");
    }
}

int main(void)
{
    const cdisasm_cpu_id cpu_id = cdisasm_current_cpu();
    const cdisasm_x86_mode_mask modes =
        cdisasm_x86_cpu_mode_mask(cpu_id);
    cdisasm_x86_decode_context context;
    cdisasm_x86_family_mask available;
    cdisasm_x86_family_mask selected;
    cdisasm_x86_mode mode;

    printf("current CPU: 0x%08" PRIx32 "\n", (uint32_t)cpu_id);
    if (CDISASM_CPU_GROUP_OF(cpu_id) != CDISASM_CPU_GROUP_X86
        || modes == CDISASM_X86_MODE_MASK_NONE) {
        puts("current CPU is not an identified x86 processor; skipped");
        return 0;
    }
    mode = select_mode(modes);
    printf("mode: %u-bit\n", (unsigned)mode);
    if (cdisasm_x86_cpu_decode_context(cpu_id, mode, &context)
        != CDISASM_STATUS_OK) {
        fputs("failed to initialize x86 decode context\n", stderr);
        return 1;
    }

    available = cdisasm_x86_decode_context_get_available_families(&context);
    selected = cdisasm_x86_decode_context_get_set_families(&context);
    if ((selected & ~available) != 0) {
        fputs("selected families are not a subset of available families\n",
              stderr);
        return 1;
    }
    print_families("available families", available);
    print_families("default families", selected);
    return 0;
}
