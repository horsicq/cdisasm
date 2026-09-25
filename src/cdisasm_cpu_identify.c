#include "cdisasm_cpu_detect_internal.h"

#include <string.h>

#if USE_ARCH_X86
#define X86_VENDOR_INTEL_EBX UINT32_C(0x756e6547)
#define X86_VENDOR_INTEL_EDX UINT32_C(0x49656e69)
#define X86_VENDOR_INTEL_ECX UINT32_C(0x6c65746e)
#define X86_VENDOR_AMD_EBX UINT32_C(0x68747541)
#define X86_VENDOR_AMD_EDX UINT32_C(0x69746e65)
#define X86_VENDOR_AMD_ECX UINT32_C(0x444d4163)

#define X86_LEAF1_ECX_SSE3 (UINT32_C(1) << 0)
#define X86_LEAF1_ECX_VMX (UINT32_C(1) << 5)
#define X86_LEAF1_ECX_AVX (UINT32_C(1) << 28)
#define X86_LEAF1_EDX_FPU (UINT32_C(1) << 0)
#define X86_LEAF1_EDX_MMX (UINT32_C(1) << 23)
#define X86_LEAF1_EDX_SSE (UINT32_C(1) << 25)
#define X86_LEAF7_EBX_AVX512F (UINT32_C(1) << 16)
#define X86_EXT1_ECX_SVM (UINT32_C(1) << 2)
#define X86_EXT1_EDX_LM (UINT32_C(1) << 29)
#define X86_EXT1_EDX_3DNOW (UINT32_C(1) << 31)

static int x86_is_vendor(
    const cdisasm_internal_x86_cpu_snapshot *snapshot,
    uint32_t ebx,
    uint32_t edx,
    uint32_t ecx)
{
    return snapshot->vendor_ebx == ebx
        && snapshot->vendor_edx == edx
        && snapshot->vendor_ecx == ecx;
}

static uint32_t x86_leaf7_ebx(
    const cdisasm_internal_x86_cpu_snapshot *snapshot)
{
    return snapshot->max_basic_leaf >= UINT32_C(7)
        ? snapshot->leaf7_ebx
        : UINT32_C(0);
}

static uint32_t x86_extended1_ecx(
    const cdisasm_internal_x86_cpu_snapshot *snapshot)
{
    return snapshot->max_extended_leaf >= UINT32_C(0x80000001)
        ? snapshot->extended1_ecx
        : UINT32_C(0);
}

static uint32_t x86_extended1_edx(
    const cdisasm_internal_x86_cpu_snapshot *snapshot)
{
    return snapshot->max_extended_leaf >= UINT32_C(0x80000001)
        ? snapshot->extended1_edx
        : UINT32_C(0);
}

static void x86_display_family_model(
    uint32_t signature,
    uint32_t *family,
    uint32_t *model)
{
    const uint32_t base_family = (signature >> 8) & UINT32_C(0x0f);
    const uint32_t base_model = (signature >> 4) & UINT32_C(0x0f);

    *family = base_family;
    if (base_family == UINT32_C(0x0f)) {
        *family += (signature >> 20) & UINT32_C(0xff);
    }

    *model = base_model;
    if (base_family == UINT32_C(0x06)
        || base_family == UINT32_C(0x0f)) {
        *model |= ((signature >> 16) & UINT32_C(0x0f)) << 4;
    }
}

static cdisasm_cpu_id x86_classify_intel(
    const cdisasm_internal_x86_cpu_snapshot *snapshot,
    uint32_t family,
    uint32_t model)
{
    const int has_avx =
        (snapshot->leaf1_ecx & X86_LEAF1_ECX_AVX) != 0;

    if (family == UINT32_C(0x04)) {
        return (snapshot->leaf1_edx & X86_LEAF1_EDX_FPU) != 0
            ? CDISASM_CPU_80486_CPUID
            : CDISASM_CPU_UNKNOWN;
    }
    if (family == UINT32_C(0x05)) {
        return (snapshot->leaf1_edx & X86_LEAF1_EDX_MMX) != 0
            ? CDISASM_CPU_PENTIUM_MMX
            : CDISASM_CPU_PENTIUM;
    }
    if (family == UINT32_C(0x0f)) {
        const int is_prescott = model >= UINT32_C(0x03)
            && (snapshot->leaf1_ecx & X86_LEAF1_ECX_SSE3) != 0
            && (x86_extended1_edx(snapshot) & X86_EXT1_EDX_LM) != 0;

        if (!is_prescott) {
            return CDISASM_CPU_PENTIUM_4;
        }
        return (snapshot->leaf1_ecx & X86_LEAF1_ECX_VMX) != 0
            ? CDISASM_CPU_INTEL_VT_X
            : CDISASM_CPU_PRESCOTT;
    }
    if (family == UINT32_C(0x13) && model == UINT32_C(0x01)) {
        return CDISASM_CPU_DIAMOND_RAPIDS;
    }
    if (family != UINT32_C(0x06)) {
        return CDISASM_CPU_UNKNOWN;
    }

    switch (model) {
        case 0x01:
            return CDISASM_CPU_PENTIUM_PRO;
        case 0x03:
            return CDISASM_CPU_PENTIUM_II;
        case 0x05:
        case 0x06:
            return (snapshot->leaf1_edx & X86_LEAF1_EDX_SSE) != 0
                ? CDISASM_CPU_PENTIUM_III
                : CDISASM_CPU_PENTIUM_II;
        case 0x07:
        case 0x08:
        case 0x0a:
        case 0x0b:
            return CDISASM_CPU_PENTIUM_III;
        case 0x0f:
        case 0x16:
            return CDISASM_CPU_CORE_2;
        case 0x17:
        case 0x1d:
            return CDISASM_CPU_PENRYN;
        case 0x1a:
        case 0x1e:
        case 0x1f:
        case 0x2e:
            return CDISASM_CPU_NEHALEM;
        case 0x25:
        case 0x2c:
        case 0x2f:
            return CDISASM_CPU_WESTMERE;
        case 0x2a:
        case 0x2d:
            return CDISASM_CPU_SANDY_BRIDGE;
        case 0x3a:
        case 0x3e:
            return CDISASM_CPU_IVY_BRIDGE;
        case 0x3c:
        case 0x3f:
        case 0x45:
        case 0x46:
            return has_avx
                ? CDISASM_CPU_HASWELL
                : CDISASM_CPU_CELERON_G1840;
        case 0x3d:
        case 0x47:
        case 0x4f:
        case 0x56:
            return has_avx
                ? CDISASM_CPU_BROADWELL
                : CDISASM_CPU_CELERON_G1840;
        case 0x4e:
        case 0x5e:
        case 0x8e:
        case 0x9e:
            return has_avx
                ? CDISASM_CPU_SKYLAKE
                : CDISASM_CPU_CELERON_G3900;
        case 0xa5:
        case 0xa6:
            return has_avx
                ? CDISASM_CPU_SKYLAKE
                : CDISASM_CPU_CELERON_G5900;
        case 0x55:
            return CDISASM_CPU_SKYLAKE_SP;
        case 0x5c:
            return CDISASM_CPU_CELERON_N3350;
        case 0x5f:
            return CDISASM_CPU_GOLDMONT;
        case 0x7a:
            return CDISASM_CPU_CELERON_N4020;
        case 0x9c:
            return CDISASM_CPU_PENTIUM_SILVER_N6000;
        case 0x6a:
        case 0x6c:
        case 0x7d:
        case 0x7e:
            return CDISASM_CPU_ICE_LAKE;
        case 0x8c:
        case 0x8d:
        case 0xa7:
            return CDISASM_CPU_TIGER_LAKE;
        case 0x97:
        case 0x9a:
        case 0xaa:
        case 0xac:
        case 0xb7:
        case 0xba:
        case 0xbe:
        case 0xbf:
            return CDISASM_CPU_ALDER_LAKE;
        case 0x8f:
        case 0xcf:
            return CDISASM_CPU_SAPPHIRE_RAPIDS;
        case 0xad:
        case 0xae:
            return CDISASM_CPU_GRANITE_RAPIDS;
        case 0xb5:
        case 0xc5:
        case 0xc6:
            return CDISASM_CPU_ARROW_LAKE;
        case 0x85:
            return CDISASM_CPU_KNIGHTS_MILL;
        default:
            return CDISASM_CPU_UNKNOWN;
    }
}

static cdisasm_cpu_id x86_classify_amd(
    const cdisasm_internal_x86_cpu_snapshot *snapshot,
    uint32_t family,
    uint32_t model)
{
    switch (family) {
        case 0x05:
            if ((model == UINT32_C(0x08)
                    || model == UINT32_C(0x09)
                    || model == UINT32_C(0x0d))
                && (x86_extended1_edx(snapshot) & X86_EXT1_EDX_3DNOW) != 0) {
                return CDISASM_CPU_AMD_K6_2;
            }
            return CDISASM_CPU_UNKNOWN;
        case 0x0f:
            if ((x86_extended1_edx(snapshot) & X86_EXT1_EDX_LM) == 0) {
                return CDISASM_CPU_UNKNOWN;
            }
            return (x86_extended1_ecx(snapshot) & X86_EXT1_ECX_SVM) != 0
                ? CDISASM_CPU_AMD_V
                : CDISASM_CPU_ATHLON_64;
        case 0x10:
        case 0x12:
            return CDISASM_CPU_AMD_BARCELONA;
        case 0x15:
            return CDISASM_CPU_AMD_BULLDOZER;
        case 0x17:
            return CDISASM_CPU_AMD_ZEN;
        case 0x19:
            if ((model >= UINT32_C(0x10) && model <= UINT32_C(0x1f))
                || (model >= UINT32_C(0x60) && model <= UINT32_C(0xaf))
                || (x86_leaf7_ebx(snapshot) & X86_LEAF7_EBX_AVX512F) != 0) {
                return CDISASM_CPU_AMD_ZEN_4;
            }
            return CDISASM_CPU_AMD_ZEN;
        case 0x1a:
            return (x86_leaf7_ebx(snapshot) & X86_LEAF7_EBX_AVX512F) != 0
                ? CDISASM_CPU_AMD_ZEN_4
                : CDISASM_CPU_AMD_ZEN;
        default:
            return CDISASM_CPU_UNKNOWN;
    }
}

cdisasm_cpu_id cdisasm_internal_classify_x86_cpu(
    const cdisasm_internal_x86_cpu_snapshot *snapshot)
{
    uint32_t family;
    uint32_t model;

    if (snapshot == NULL || snapshot->max_basic_leaf < UINT32_C(1)) {
        return CDISASM_CPU_UNKNOWN;
    }

    x86_display_family_model(snapshot->leaf1_eax, &family, &model);

    if (x86_is_vendor(snapshot,
            X86_VENDOR_INTEL_EBX,
            X86_VENDOR_INTEL_EDX,
            X86_VENDOR_INTEL_ECX)) {
        return x86_classify_intel(snapshot, family, model);
    }
    if (x86_is_vendor(snapshot,
            X86_VENDOR_AMD_EBX,
            X86_VENDOR_AMD_EDX,
            X86_VENDOR_AMD_ECX)) {
        return x86_classify_amd(snapshot, family, model);
    }
    return CDISASM_CPU_UNKNOWN;
}
#endif

#if USE_ARCH_ARM
static cdisasm_cpu_id arm_neon_profile(
    cdisasm_cpu_id plain_profile,
    int has_neon)
{
    if (!has_neon) {
        return plain_profile;
    }
    if (plain_profile == CDISASM_ARM_CPU_CORTEX_A7) {
        return CDISASM_ARM_CPU_CORTEX_A7_NEON;
    }
    if (plain_profile == CDISASM_ARM_CPU_CORTEX_A9) {
        return CDISASM_ARM_CPU_CORTEX_A9_NEON;
    }
    return plain_profile;
}

cdisasm_cpu_id cdisasm_internal_classify_arm_midr(
    uint32_t midr,
    int has_neon)
{
    const uint32_t implementer = (midr >> 24) & UINT32_C(0xff);
    const uint32_t part = (midr >> 4) & UINT32_C(0x0fff);

    if (implementer == UINT32_C(0x41)) {
        switch (part) {
            case 0x770:
                return CDISASM_ARM_CPU_ARM7TDMI;
            case 0xc07:
                return arm_neon_profile(
                    CDISASM_ARM_CPU_CORTEX_A7, has_neon);
            case 0xc09:
                return arm_neon_profile(
                    CDISASM_ARM_CPU_CORTEX_A9, has_neon);
            case 0xd01:
                return CDISASM_ARM_CPU_CORTEX_A32;
            case 0xd02:
                return CDISASM_ARM_CPU_CORTEX_A34;
            case 0xd03:
                return CDISASM_ARM_CPU_CORTEX_A53;
            case 0xd04:
                return CDISASM_ARM_CPU_CORTEX_A35;
            default:
                return CDISASM_CPU_UNKNOWN;
        }
    }
    if (implementer == UINT32_C(0x46) && part == UINT32_C(0x001)) {
        return CDISASM_ARM_CPU_A64FX;
    }
    if (implementer != UINT32_C(0x61)) {
        return CDISASM_CPU_UNKNOWN;
    }

    switch (part) {
        case 0x002:
        case 0x003:
            return CDISASM_ARM_CPU_APPLE_A8;
        case 0x004:
        case 0x005:
            return CDISASM_ARM_CPU_APPLE_A9;
        case 0x006:
        case 0x007:
            return CDISASM_ARM_CPU_APPLE_A10;
        case 0x008:
        case 0x009:
            return CDISASM_ARM_CPU_APPLE_A11;
        case 0x00b:
        case 0x00c:
        case 0x010:
        case 0x011:
            return CDISASM_ARM_CPU_APPLE_A12;
        case 0x012:
        case 0x013:
            return CDISASM_ARM_CPU_APPLE_A13;
        case 0x020:
        case 0x021:
            return CDISASM_ARM_CPU_APPLE_A14;
        case 0x022:
        case 0x023:
        case 0x024:
        case 0x025:
        case 0x028:
        case 0x029:
            return CDISASM_ARM_CPU_APPLE_M1;
        case 0x030:
        case 0x031:
            return CDISASM_ARM_CPU_APPLE_A15;
        case 0x032:
        case 0x033:
        case 0x034:
        case 0x035:
        case 0x038:
        case 0x039:
            return CDISASM_ARM_CPU_APPLE_M2;
        case 0x040:
        case 0x041:
            return CDISASM_ARM_CPU_APPLE_A16;
        case 0x042:
        case 0x043:
        case 0x044:
        case 0x045:
        case 0x048:
        case 0x049:
            return CDISASM_ARM_CPU_APPLE_M3;
        case 0x050:
        case 0x051:
            return CDISASM_ARM_CPU_APPLE_A17;
        case 0x052:
        case 0x053:
        case 0x054:
        case 0x055:
        case 0x058:
        case 0x059:
            return CDISASM_ARM_CPU_APPLE_M4;
        default:
            return CDISASM_CPU_UNKNOWN;
    }
}

static const char *arm_cpuinfo_value(
    const char *line,
    const char *key,
    int *matched)
{
    const char *line_cursor = line;
    const char *key_cursor = key;

    *matched = 0;
    while (*key_cursor != '\0' && *line_cursor == *key_cursor) {
        ++line_cursor;
        ++key_cursor;
    }
    if (*key_cursor != '\0'
        || (*line_cursor != '\0' && *line_cursor != ' '
            && *line_cursor != '\t' && *line_cursor != ':')) {
        return NULL;
    }

    *matched = 1;
    while (*line_cursor == ' ' || *line_cursor == '\t') {
        ++line_cursor;
    }
    if (*line_cursor != ':') {
        return NULL;
    }
    ++line_cursor;
    while (*line_cursor == ' ' || *line_cursor == '\t') {
        ++line_cursor;
    }
    return line_cursor;
}

int cdisasm_internal_arm_cpuinfo_line_is_relevant(const char *line)
{
    static const char *const keys[] = {
        "processor",
        "CPU implementer",
        "CPU part"
    };
    size_t index;

    if (line == NULL) {
        return 0;
    }
    for (index = 0; index < sizeof(keys) / sizeof(keys[0]); ++index) {
        int matched;

        (void)arm_cpuinfo_value(line, keys[index], &matched);
        if (matched) {
            return 1;
        }
    }
    return 0;
}

static int arm_cpuinfo_parse_hex(const char *text, uint32_t *value)
{
    uint32_t result = 0;
    int found_digit = 0;

    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        text += 2;
    }
    for (;;) {
        uint32_t digit;

        if (*text >= '0' && *text <= '9') {
            digit = (uint32_t)(*text - '0');
        } else if (*text >= 'a' && *text <= 'f') {
            digit = (uint32_t)(*text - 'a') + UINT32_C(10);
        } else if (*text >= 'A' && *text <= 'F') {
            digit = (uint32_t)(*text - 'A') + UINT32_C(10);
        } else {
            break;
        }
        if (result > (UINT32_MAX - digit) / UINT32_C(16)) {
            return 0;
        }
        result = result * UINT32_C(16) + digit;
        found_digit = 1;
        ++text;
    }
    while (*text == ' ' || *text == '\t'
        || *text == '\r' || *text == '\n') {
        ++text;
    }
    if (!found_digit || *text != '\0') {
        return 0;
    }
    *value = result;
    return 1;
}

static int arm_cpuinfo_finish_record(
    cdisasm_internal_arm_cpuinfo_state *state)
{
    cdisasm_cpu_id candidate;

    if (!state->record_started) {
        return 1;
    }
    if (!state->have_implementer || !state->have_part) {
        state->invalid = 1;
        return 0;
    }

    candidate = cdisasm_internal_classify_arm_midr(
        (state->implementer << 24)
            | ((state->part & UINT32_C(0x0fff)) << 4),
        state->has_neon);
    if (candidate == CDISASM_CPU_UNKNOWN
        || (state->found && state->selected != candidate)) {
        state->invalid = 1;
        return 0;
    }

    state->selected = candidate;
    state->found = 1;
    state->implementer = 0;
    state->part = 0;
    state->have_implementer = 0;
    state->have_part = 0;
    state->record_started = 0;
    return 1;
}

void cdisasm_internal_arm_cpuinfo_init(
    cdisasm_internal_arm_cpuinfo_state *state,
    int has_neon)
{
    if (state == NULL) {
        return;
    }
    state->selected = CDISASM_CPU_UNKNOWN;
    state->implementer = 0;
    state->part = 0;
    state->has_neon = has_neon != 0;
    state->have_implementer = 0;
    state->have_part = 0;
    state->record_started = 0;
    state->found = 0;
    state->invalid = 0;
}

int cdisasm_internal_arm_cpuinfo_feed(
    cdisasm_internal_arm_cpuinfo_state *state,
    const char *line)
{
    const char *value_text;
    uint32_t value;
    int matched;

    if (state == NULL || line == NULL || state->invalid) {
        return 0;
    }
    if (line[0] == '\0' || line[0] == '\r' || line[0] == '\n') {
        return arm_cpuinfo_finish_record(state);
    }

    value_text = arm_cpuinfo_value(line, "processor", &matched);
    if (matched) {
        if (value_text == NULL
            || (state->record_started
                && !arm_cpuinfo_finish_record(state))) {
            state->invalid = 1;
            return 0;
        }
        state->record_started = 1;
        return 1;
    }

    value_text = arm_cpuinfo_value(line, "CPU implementer", &matched);
    if (matched) {
        if (value_text == NULL || state->have_implementer
            || !arm_cpuinfo_parse_hex(value_text, &value)
            || value > UINT32_C(0xff)) {
            state->invalid = 1;
            return 0;
        }
        state->implementer = value;
        state->have_implementer = 1;
        state->record_started = 1;
        return 1;
    }

    value_text = arm_cpuinfo_value(line, "CPU part", &matched);
    if (matched) {
        if (value_text == NULL || state->have_part
            || !arm_cpuinfo_parse_hex(value_text, &value)
            || value > UINT32_C(0x0fff)) {
            state->invalid = 1;
            return 0;
        }
        state->part = value;
        state->have_part = 1;
        state->record_started = 1;
        return 1;
    }
    return 1;
}

cdisasm_cpu_id cdisasm_internal_arm_cpuinfo_finish(
    cdisasm_internal_arm_cpuinfo_state *state)
{
    if (state == NULL || state->invalid
        || !arm_cpuinfo_finish_record(state) || !state->found) {
        return CDISASM_CPU_UNKNOWN;
    }
    return state->selected;
}

static cdisasm_cpu_id apple_generation_profile(char series, unsigned int value)
{
    if (series == 'A') {
        switch (value) {
            case 4: return CDISASM_ARM_CPU_APPLE_A4;
            case 5: return CDISASM_ARM_CPU_APPLE_A5;
            case 6: return CDISASM_ARM_CPU_APPLE_A6;
            case 7: return CDISASM_ARM_CPU_APPLE_A7;
            case 8: return CDISASM_ARM_CPU_APPLE_A8;
            case 9: return CDISASM_ARM_CPU_APPLE_A9;
            case 10: return CDISASM_ARM_CPU_APPLE_A10;
            case 11: return CDISASM_ARM_CPU_APPLE_A11;
            case 12: return CDISASM_ARM_CPU_APPLE_A12;
            case 13: return CDISASM_ARM_CPU_APPLE_A13;
            case 14: return CDISASM_ARM_CPU_APPLE_A14;
            case 15: return CDISASM_ARM_CPU_APPLE_A15;
            case 16: return CDISASM_ARM_CPU_APPLE_A16;
            case 17: return CDISASM_ARM_CPU_APPLE_A17;
            case 18: return CDISASM_ARM_CPU_APPLE_A18;
            case 19: return CDISASM_ARM_CPU_APPLE_A19;
            default: return CDISASM_CPU_UNKNOWN;
        }
    }
    if (series == 'M') {
        switch (value) {
            case 1: return CDISASM_ARM_CPU_APPLE_M1;
            case 2: return CDISASM_ARM_CPU_APPLE_M2;
            case 3: return CDISASM_ARM_CPU_APPLE_M3;
            case 4: return CDISASM_ARM_CPU_APPLE_M4;
            case 5: return CDISASM_ARM_CPU_APPLE_M5;
            default: return CDISASM_CPU_UNKNOWN;
        }
    }
    if (series == 'S') {
        switch (value) {
            case 4: return CDISASM_ARM_CPU_APPLE_S4;
            case 5: return CDISASM_ARM_CPU_APPLE_S5;
            case 6: return CDISASM_ARM_CPU_APPLE_S6;
            case 7: return CDISASM_ARM_CPU_APPLE_S7;
            case 8: return CDISASM_ARM_CPU_APPLE_S8;
            case 9: return CDISASM_ARM_CPU_APPLE_S9;
            case 10: return CDISASM_ARM_CPU_APPLE_S10;
            default: return CDISASM_CPU_UNKNOWN;
        }
    }
    return CDISASM_CPU_UNKNOWN;
}

cdisasm_cpu_id cdisasm_internal_classify_apple_brand(const char *brand)
{
    unsigned int generation;
    size_t position;
    const char *suffix;

    if (brand == NULL
        || brand[0] != 'A' || brand[1] != 'p' || brand[2] != 'p'
        || brand[3] != 'l' || brand[4] != 'e' || brand[5] != ' ') {
        return CDISASM_CPU_UNKNOWN;
    }
    if (brand[6] != 'A' && brand[6] != 'M' && brand[6] != 'S') {
        return CDISASM_CPU_UNKNOWN;
    }
    if (brand[7] < '0' || brand[7] > '9') {
        return CDISASM_CPU_UNKNOWN;
    }

    generation = (unsigned int)(brand[7] - '0');
    position = 8;
    if (brand[position] >= '0' && brand[position] <= '9') {
        if (generation == 0u) {
            return CDISASM_CPU_UNKNOWN;
        }
        generation = generation * 10u
            + (unsigned int)(brand[position] - '0');
        ++position;
    }
    if (brand[position] >= '0' && brand[position] <= '9') {
        return CDISASM_CPU_UNKNOWN;
    }
    suffix = brand + position;
    if (*suffix != '\0') {
        if (brand[6] == 'M') {
            if (strcmp(suffix, " Pro") != 0
                && strcmp(suffix, " Max") != 0
                && strcmp(suffix, " Ultra") != 0) {
                return CDISASM_CPU_UNKNOWN;
            }
        } else if (brand[6] == 'A') {
            if (strcmp(suffix, " Pro") != 0) {
                return CDISASM_CPU_UNKNOWN;
            }
        } else {
            return CDISASM_CPU_UNKNOWN;
        }
    }
    return apple_generation_profile(brand[6], generation);
}

cdisasm_cpu_id cdisasm_internal_classify_apple_family(
    uint32_t family,
    cdisasm_cpu_id brand_profile)
{
    if (CDISASM_ARM_CPU_IS_APPLE(brand_profile)) {
        return brand_profile;
    }

    switch (family) {
        case CDISASM_INTERNAL_APPLE_CPUFAMILY_ARM_13:
            return CDISASM_ARM_CPU_APPLE_A4;
        case CDISASM_INTERNAL_APPLE_CPUFAMILY_ARM_14:
            return CDISASM_ARM_CPU_APPLE_A5;
        case CDISASM_INTERNAL_APPLE_CPUFAMILY_ARM_15:
            return CDISASM_ARM_CPU_CORTEX_A7;
        case CDISASM_INTERNAL_APPLE_CPUFAMILY_SWIFT:
            return CDISASM_ARM_CPU_APPLE_A6;
        case CDISASM_INTERNAL_APPLE_CPUFAMILY_CYCLONE:
            return CDISASM_ARM_CPU_APPLE_A7;
        case CDISASM_INTERNAL_APPLE_CPUFAMILY_TYPHOON:
            return CDISASM_ARM_CPU_APPLE_A8;
        case CDISASM_INTERNAL_APPLE_CPUFAMILY_TWISTER:
            return CDISASM_ARM_CPU_APPLE_A9;
        case CDISASM_INTERNAL_APPLE_CPUFAMILY_HURRICANE:
            return CDISASM_ARM_CPU_APPLE_A10;
        case CDISASM_INTERNAL_APPLE_CPUFAMILY_MONSOON_MISTRAL:
            return CDISASM_ARM_CPU_APPLE_A11;
        case CDISASM_INTERNAL_APPLE_CPUFAMILY_VORTEX_TEMPEST:
            return CDISASM_ARM_CPU_APPLE_A12;
        case CDISASM_INTERNAL_APPLE_CPUFAMILY_LIGHTNING_THUNDER:
            return CDISASM_ARM_CPU_APPLE_A13;
        case CDISASM_INTERNAL_APPLE_CPUFAMILY_FIRESTORM_ICESTORM:
            /* Shared by A14 and M1; A14 is the safe common ISA profile. */
            return CDISASM_ARM_CPU_APPLE_A14;
        case CDISASM_INTERNAL_APPLE_CPUFAMILY_BLIZZARD_AVALANCHE:
            /* Shared by A15 and M2; A15 avoids assuming M-series AMX. */
            return CDISASM_ARM_CPU_APPLE_A15;
        case CDISASM_INTERNAL_APPLE_CPUFAMILY_EVEREST_SAWTOOTH:
            return CDISASM_ARM_CPU_APPLE_A16;
        case CDISASM_INTERNAL_APPLE_CPUFAMILY_IBIZA:
        case CDISASM_INTERNAL_APPLE_CPUFAMILY_PALMA:
        case CDISASM_INTERNAL_APPLE_CPUFAMILY_LOBOS:
            return CDISASM_ARM_CPU_APPLE_M3;
        case CDISASM_INTERNAL_APPLE_CPUFAMILY_COLL:
            return CDISASM_ARM_CPU_APPLE_A17;
        case CDISASM_INTERNAL_APPLE_CPUFAMILY_DONAN:
        case CDISASM_INTERNAL_APPLE_CPUFAMILY_BRAVA:
            return CDISASM_ARM_CPU_APPLE_M4;
        case CDISASM_INTERNAL_APPLE_CPUFAMILY_TUPAI:
        case CDISASM_INTERNAL_APPLE_CPUFAMILY_TAHITI:
            return CDISASM_ARM_CPU_APPLE_A18;
        case CDISASM_INTERNAL_APPLE_CPUFAMILY_HIDRA:
            return CDISASM_ARM_CPU_APPLE_M5;
        case CDISASM_INTERNAL_APPLE_CPUFAMILY_TILOS:
        case CDISASM_INTERNAL_APPLE_CPUFAMILY_THERA:
            return CDISASM_ARM_CPU_APPLE_A19;
        default:
            return CDISASM_CPU_UNKNOWN;
    }
}
#endif
