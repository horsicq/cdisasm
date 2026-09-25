#include "cdisasm/cdisasm_arm.h"

#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>

static const char *family_name(cdisasm_arm_family_id family_id)
{
    switch (family_id) {
        case CDISASM_ARM_FAMILY_V4: return "V4";
        case CDISASM_ARM_FAMILY_V5: return "V5";
        case CDISASM_ARM_FAMILY_V6: return "V6";
        case CDISASM_ARM_FAMILY_V7: return "V7";
        case CDISASM_ARM_FAMILY_V8: return "V8";
        case CDISASM_ARM_FAMILY_NEON: return "NEON";
        case CDISASM_ARM_FAMILY_VFP: return "VFP";
        case CDISASM_ARM_FAMILY_FP16: return "FP16";
        case CDISASM_ARM_FAMILY_SVE: return "SVE";
        case CDISASM_ARM_FAMILY_SVE2: return "SVE2";
        case CDISASM_ARM_FAMILY_SME: return "SME";
        case CDISASM_ARM_FAMILY_SME2: return "SME2";
        case CDISASM_ARM_FAMILY_LSE: return "LSE";
        case CDISASM_ARM_FAMILY_LSE2: return "LSE2";
        case CDISASM_ARM_FAMILY_LSE128: return "LSE128";
        case CDISASM_ARM_FAMILY_RCPC: return "RCPC";
        case CDISASM_ARM_FAMILY_RCPC3: return "RCPC3";
        case CDISASM_ARM_FAMILY_BTI: return "BTI";
        case CDISASM_ARM_FAMILY_PAUTH: return "PAUTH";
        case CDISASM_ARM_FAMILY_MTE: return "MTE";
        case CDISASM_ARM_FAMILY_MOPS: return "MOPS";
        case CDISASM_ARM_FAMILY_LS64: return "LS64";
        case CDISASM_ARM_FAMILY_CSSC: return "CSSC";
        case CDISASM_ARM_FAMILY_BF16: return "BF16";
        case CDISASM_ARM_FAMILY_FP8: return "FP8";
        case CDISASM_ARM_FAMILY_F64MM: return "F64MM";
        case CDISASM_ARM_FAMILY_APPLE_MUL53: return "APPLE_MUL53";
        case CDISASM_ARM_FAMILY_APPLE_AMX: return "APPLE_AMX";
        case CDISASM_ARM_FAMILY_APPLE_SYS: return "APPLE_SYS";
        case CDISASM_ARM_FAMILY_APPLE_A7_SYSREG: return "APPLE_A7_SYSREG";
        case CDISASM_ARM_FAMILY_CPA: return "CPA";
        case CDISASM_ARM_FAMILY_MP: return "MP";
        case CDISASM_ARM_FAMILY_CRC32: return "CRC32";
        case CDISASM_ARM_FAMILY_AES: return "AES";
        case CDISASM_ARM_FAMILY_PMULL: return "PMULL";
        case CDISASM_ARM_FAMILY_SHA: return "SHA";
        case CDISASM_ARM_FAMILY_SM3: return "SM3";
        case CDISASM_ARM_FAMILY_SM4: return "SM4";
        case CDISASM_ARM_FAMILY_DOTPROD: return "DOTPROD";
        case CDISASM_ARM_FAMILY_FCMA: return "FCMA";
        case CDISASM_ARM_FAMILY_FHM: return "FHM";
        case CDISASM_ARM_FAMILY_AA32I8MM: return "AA32I8MM";
        case CDISASM_ARM_FAMILY_PAN: return "PAN";
        case CDISASM_ARM_FAMILY_RAS: return "RAS";
        case CDISASM_ARM_FAMILY_TRF: return "TRF";
        case CDISASM_ARM_FAMILY_CLRBHB: return "CLRBHB";
        case CDISASM_ARM_FAMILY_GCS: return "GCS";
        case CDISASM_ARM_FAMILY_PAUTH_LR: return "PAUTH_LR";
        case CDISASM_ARM_FAMILY_SVE2P1: return "SVE2P1";
        case CDISASM_ARM_FAMILY_SME2P1: return "SME2P1";
        case CDISASM_ARM_FAMILY_SVE2P2: return "SVE2P2";
        case CDISASM_ARM_FAMILY_SME2P2: return "SME2P2";
        case CDISASM_ARM_FAMILY_SVE2P3: return "SVE2P3";
        case CDISASM_ARM_FAMILY_SME2P3: return "SME2P3";
        case CDISASM_ARM_FAMILY_FAMINMAX: return "FAMINMAX";
        case CDISASM_ARM_FAMILY_FPRCVT: return "FPRCVT";
        case CDISASM_ARM_FAMILY_JSCVT: return "JSCVT";
        case CDISASM_ARM_FAMILY_CHK: return "CHK";
        case CDISASM_ARM_FAMILY_DGH: return "DGH";
        case CDISASM_ARM_FAMILY_SPE: return "SPE";
        default: return "UNKNOWN";
    }
}

static const char *mode_name(cdisasm_arm_mode mode)
{
    switch (mode) {
        case CDISASM_ARM_MODE_A32: return "A32";
        case CDISASM_ARM_MODE_T32: return "T32";
        case CDISASM_ARM_MODE_A64: return "A64";
        default: return "unknown";
    }
}

static cdisasm_arm_mode select_mode(cdisasm_arm_mode_mask modes)
{
    if ((modes & CDISASM_ARM_MODE_MASK_A64) != 0) {
        return CDISASM_ARM_MODE_A64;
    }
    if ((modes & CDISASM_ARM_MODE_MASK_T32) != 0) {
        return CDISASM_ARM_MODE_T32;
    }
    return CDISASM_ARM_MODE_A32;
}

static void print_families(const char *label, cdisasm_arm_family_mask mask)
{
    cdisasm_arm_family_id family_id;
    int printed = 0;

    printf("%s (0x%016" PRIx64 "):\n", label, (uint64_t)mask);
    for (family_id = CDISASM_ARM_FAMILY_FIRST;
         family_id <= CDISASM_ARM_FAMILY_LAST;
         ++family_id) {
        const cdisasm_arm_family_mask bit =
            UINT64_C(1) << ((uint32_t)family_id - UINT32_C(1));
        if ((mask & bit) != 0) {
            printf("  - %s (id=%u)\n",
                   family_name(family_id), (unsigned)family_id);
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
    const cdisasm_arm_mode_mask modes = cdisasm_arm_cpu_mode_mask(cpu_id);
    cdisasm_arm_decode_context context;
    cdisasm_arm_family_mask available;
    cdisasm_arm_family_mask selected;
    cdisasm_arm_mode mode;
    cdisasm_arm_family_id first_family;

    printf("current CPU: 0x%08" PRIx32 "\n", (uint32_t)cpu_id);
    if (CDISASM_CPU_GROUP_OF(cpu_id) != CDISASM_CPU_GROUP_ARM
        || modes == CDISASM_ARM_MODE_MASK_NONE) {
        puts("current CPU is not an identified ARM processor; skipped");
        return 0;
    }
    mode = select_mode(modes);
    printf("mode: %s\n", mode_name(mode));
    if (cdisasm_arm_cpu_decode_context(cpu_id, mode, &context)
        != CDISASM_STATUS_OK) {
        fputs("failed to initialize ARM decode context\n", stderr);
        return 1;
    }

    available = cdisasm_arm_decode_context_get_available_families(&context);
    selected = cdisasm_arm_decode_context_get_set_families(&context);
    if (available == CDISASM_ARM_FAMILY_MASK_NONE
        || (selected & ~available) != 0) {
        fputs("invalid ARM family context masks\n", stderr);
        return 1;
    }
    print_families("available families", available);
    print_families("default families", selected);

    first_family = CDISASM_ARM_FAMILY_FIRST;
    while (first_family <= CDISASM_ARM_FAMILY_LAST
           && (available & (UINT64_C(1) << (first_family - 1))) == 0) {
        ++first_family;
    }
    if (first_family <= CDISASM_ARM_FAMILY_LAST) {
        if (!cdisasm_arm_decode_context_remove_family(&context, first_family)
            || (cdisasm_arm_decode_context_get_set_families(&context)
                & (UINT64_C(1) << (first_family - 1))) != 0
            || !cdisasm_arm_decode_context_add_family(&context, first_family)
            || (cdisasm_arm_decode_context_get_set_families(&context)
                & (UINT64_C(1) << (first_family - 1))) == 0) {
            fputs("ARM family add/remove context helpers failed\n", stderr);
            return 1;
        }
    }
    return 0;
}
