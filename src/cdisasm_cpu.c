#include "cdisasm/cdisasm.h"
#include "cdisasm_cpu_detect_internal.h"

#if USE_ARCH_X86 \
    && (defined(__i386__) || defined(__x86_64__) \
        || defined(_M_IX86) || defined(_M_X64)) \
    && !defined(_M_ARM64EC)
#  define CDISASM_NATIVE_X86 1
#else
#  define CDISASM_NATIVE_X86 0
#endif

#if USE_ARCH_ARM \
    && (defined(__arm__) || defined(__aarch64__) \
        || defined(_M_ARM) || defined(_M_ARM64))
#  define CDISASM_NATIVE_ARM 1
#else
#  define CDISASM_NATIVE_ARM 0
#endif

#if CDISASM_NATIVE_X86
#  if defined(_MSC_VER)
#    include <intrin.h>
#  else
#    include <cpuid.h>
#  endif

static int x86_cpuid_supported(void)
{
#  if defined(_MSC_VER) && defined(_M_IX86)
    const unsigned int original = (unsigned int)__readeflags();
    unsigned int changed;

    __writeeflags(original ^ UINT32_C(0x00200000));
    changed = (unsigned int)__readeflags();
    __writeeflags(original);
    return ((changed ^ original) & UINT32_C(0x00200000)) != 0;
#  elif defined(_MSC_VER)
    return 1;
#  else
    return __get_cpuid_max(UINT32_C(0), NULL) != 0;
#  endif
}

static void x86_cpuid(
    uint32_t leaf,
    uint32_t subleaf,
    uint32_t registers[4])
{
#  if defined(_MSC_VER)
    int values[4];

    __cpuidex(values, (int)leaf, (int)subleaf);
    registers[0] = (uint32_t)values[0];
    registers[1] = (uint32_t)values[1];
    registers[2] = (uint32_t)values[2];
    registers[3] = (uint32_t)values[3];
#  else
    unsigned int eax;
    unsigned int ebx;
    unsigned int ecx;
    unsigned int edx;

    __cpuid_count(leaf, subleaf, eax, ebx, ecx, edx);
    registers[0] = (uint32_t)eax;
    registers[1] = (uint32_t)ebx;
    registers[2] = (uint32_t)ecx;
    registers[3] = (uint32_t)edx;
#  endif
}

static cdisasm_cpu_id current_x86_cpu(void)
{
    cdisasm_internal_x86_cpu_snapshot snapshot = {0};
    uint32_t registers[4];

    if (!x86_cpuid_supported()) {
        return CDISASM_CPU_UNKNOWN;
    }

    x86_cpuid(UINT32_C(0), UINT32_C(0), registers);
    snapshot.max_basic_leaf = registers[0];
    snapshot.vendor_ebx = registers[1];
    snapshot.vendor_ecx = registers[2];
    snapshot.vendor_edx = registers[3];
    if (snapshot.max_basic_leaf < UINT32_C(1)) {
        return CDISASM_CPU_UNKNOWN;
    }

    x86_cpuid(UINT32_C(1), UINT32_C(0), registers);
    snapshot.leaf1_eax = registers[0];
    snapshot.leaf1_ecx = registers[2];
    snapshot.leaf1_edx = registers[3];

    if (snapshot.max_basic_leaf >= UINT32_C(7)) {
        uint32_t max_subleaf;

        x86_cpuid(UINT32_C(7), UINT32_C(0), registers);
        max_subleaf = registers[0];
        snapshot.leaf7_ebx = registers[1];
        snapshot.leaf7_ecx = registers[2];
        snapshot.leaf7_edx = registers[3];
        if (max_subleaf >= UINT32_C(1)) {
            x86_cpuid(UINT32_C(7), UINT32_C(1), registers);
            snapshot.leaf7_1_eax = registers[0];
            snapshot.leaf7_1_edx = registers[3];
        }
    }

    if (snapshot.max_basic_leaf >= UINT32_C(0x24)) {
        x86_cpuid(UINT32_C(0x24), UINT32_C(0), registers);
        snapshot.leaf24_ebx = registers[1];
    }

    x86_cpuid(UINT32_C(0x80000000), UINT32_C(0), registers);
    if (registers[0] >= UINT32_C(0x80000000)) {
        snapshot.max_extended_leaf = registers[0];
    }
    if (snapshot.max_extended_leaf >= UINT32_C(0x80000001)) {
        x86_cpuid(UINT32_C(0x80000001), UINT32_C(0), registers);
        snapshot.extended1_ecx = registers[2];
        snapshot.extended1_edx = registers[3];
    }

    return cdisasm_internal_classify_x86_cpu(&snapshot);
}
#endif

#if CDISASM_NATIVE_ARM && defined(__linux__)
#  include <dirent.h>
#  include <stdio.h>
#  include <string.h>
#  include <sys/auxv.h>
#  if defined(__arm__)
#    include <asm/hwcap.h>
#  endif

static int arm_process_has_neon(void)
{
#  if defined(__aarch64__) || defined(_M_ARM64)
    /* Advanced SIMD is part of the AArch64 base execution environment. */
    return 1;
#  elif defined(HWCAP_NEON) && defined(AT_HWCAP)
    return (getauxval(AT_HWCAP) & (unsigned long)HWCAP_NEON) != 0;
#  else
    return 0;
#  endif
}

static int merge_arm_profile(
    cdisasm_cpu_id candidate,
    cdisasm_cpu_id *selected,
    int *found)
{
    if (candidate == CDISASM_CPU_UNKNOWN) {
        return 0;
    }
    if (!*found) {
        *selected = candidate;
        *found = 1;
        return 1;
    }
    return *selected == candidate;
}

static int arm_sysfs_cpu_is_offline(
    const char *cpu_root,
    const char *cpu_name)
{
    char path[192];
    int path_size;
    unsigned int online;
    FILE *stream;

    path_size = snprintf(path, sizeof(path),
        "%s/%s/online", cpu_root, cpu_name);
    if (path_size < 0 || (size_t)path_size >= sizeof(path)) {
        return 0;
    }
    stream = fopen(path, "r");
    if (stream == NULL) {
        /* cpu0 and non-hotpluggable CPUs commonly omit this file. */
        return 0;
    }
    if (fscanf(stream, "%u", &online) != 1) {
        online = 1;
    }
    fclose(stream);
    return online == 0;
}

static cdisasm_cpu_id arm_cpu_from_sysfs(
    int has_neon,
    int *had_evidence)
{
    static const char cpu_root[] = "/sys/devices/system/cpu";
    cdisasm_cpu_id selected = CDISASM_CPU_UNKNOWN;
    DIR *directory;
    int found = 0;
    int incomplete = 0;

    *had_evidence = 0;
    directory = opendir(cpu_root);
    if (directory == NULL) {
        return CDISASM_CPU_UNKNOWN;
    }

    for (;;) {
        struct dirent *entry = readdir(directory);
        const char *digit;
        char path[192];
        int path_size;
        unsigned long long value;
        FILE *stream;

        if (entry == NULL) {
            break;
        }
        if (entry->d_name[0] != 'c'
            || entry->d_name[1] != 'p'
            || entry->d_name[2] != 'u') {
            continue;
        }
        digit = entry->d_name + 3;
        if (*digit < '0' || *digit > '9') {
            continue;
        }
        do {
            ++digit;
        } while (*digit >= '0' && *digit <= '9');
        if (*digit != '\0') {
            continue;
        }
        if (arm_sysfs_cpu_is_offline(cpu_root, entry->d_name)) {
            continue;
        }

        path_size = snprintf(path, sizeof(path),
            "%s/%s/regs/identification/midr_el1",
            cpu_root, entry->d_name);
        if (path_size < 0 || (size_t)path_size >= sizeof(path)) {
            *had_evidence = 1;
            closedir(directory);
            return CDISASM_CPU_UNKNOWN;
        }
        stream = fopen(path, "r");

        if (stream == NULL) {
            incomplete = 1;
            continue;
        }
        *had_evidence = 1;
        if (fscanf(stream, "%llx", &value) != 1
            || value > (unsigned long long)UINT32_MAX) {
            fclose(stream);
            closedir(directory);
            return CDISASM_CPU_UNKNOWN;
        }
        fclose(stream);
        if (!merge_arm_profile(
                cdisasm_internal_classify_arm_midr(
                    (uint32_t)value, has_neon),
                &selected,
                &found)) {
            closedir(directory);
            return CDISASM_CPU_UNKNOWN;
        }
    }

    closedir(directory);
    if (found && incomplete) {
        return CDISASM_CPU_UNKNOWN;
    }
    return found ? selected : CDISASM_CPU_UNKNOWN;
}

static cdisasm_cpu_id arm_cpu_from_proc_cpuinfo(int has_neon)
{
    FILE *stream = fopen("/proc/cpuinfo", "r");
    cdisasm_internal_arm_cpuinfo_state state;
    char line[256];
    cdisasm_cpu_id result;

    if (stream == NULL) {
        return CDISASM_CPU_UNKNOWN;
    }
    cdisasm_internal_arm_cpuinfo_init(&state, has_neon);

    while (fgets(line, sizeof(line), stream) != NULL) {
        const size_t length = strlen(line);

        if (length != 0u && line[length - 1u] != '\n' && !feof(stream)) {
            int character;

            if (cdisasm_internal_arm_cpuinfo_line_is_relevant(line)) {
                fclose(stream);
                return CDISASM_CPU_UNKNOWN;
            }
            do {
                character = fgetc(stream);
            } while (character != '\n' && character != EOF);
            if (ferror(stream)) {
                fclose(stream);
                return CDISASM_CPU_UNKNOWN;
            }
            continue;
        }
        if (!cdisasm_internal_arm_cpuinfo_feed(&state, line)) {
            fclose(stream);
            return CDISASM_CPU_UNKNOWN;
        }
    }

    if (ferror(stream)) {
        fclose(stream);
        return CDISASM_CPU_UNKNOWN;
    }
    result = cdisasm_internal_arm_cpuinfo_finish(&state);
    fclose(stream);
    return result;
}

static cdisasm_cpu_id current_linux_arm_cpu(void)
{
    const int has_neon = arm_process_has_neon();
    int had_sysfs_evidence;
    cdisasm_cpu_id cpu_id = arm_cpu_from_sysfs(
        has_neon, &had_sysfs_evidence);

    if (had_sysfs_evidence) {
        return cpu_id;
    }
    return arm_cpu_from_proc_cpuinfo(has_neon);
}
#endif

#if CDISASM_NATIVE_ARM && defined(__APPLE__)
#  include <sys/types.h>
#  include <sys/sysctl.h>

static cdisasm_cpu_id current_apple_arm_cpu(void)
{
    uint32_t family = 0;
    size_t family_size = sizeof(family);
    cdisasm_cpu_id brand_profile = CDISASM_CPU_UNKNOWN;
    char brand[128] = {0};
    size_t brand_size = sizeof(brand);

    if (sysctlbyname(
            "machdep.cpu.brand_string", brand, &brand_size, NULL, 0) == 0) {
        brand[sizeof(brand) - 1u] = '\0';
        brand_profile = cdisasm_internal_classify_apple_brand(brand);
    }
    if (sysctlbyname("hw.cpufamily", &family, &family_size, NULL, 0) != 0
        || family_size != sizeof(family)) {
        family = 0;
    }
    return cdisasm_internal_classify_apple_family(family, brand_profile);
}
#endif

cdisasm_cpu_id CDISASM_CALL cdisasm_current_cpu(void)
{
#if CDISASM_NATIVE_X86
    return current_x86_cpu();
#elif CDISASM_NATIVE_ARM && defined(__linux__)
    return current_linux_arm_cpu();
#elif CDISASM_NATIVE_ARM && defined(__APPLE__)
    return current_apple_arm_cpu();
#else
    return CDISASM_CPU_UNKNOWN;
#endif
}

#undef CDISASM_NATIVE_X86
#undef CDISASM_NATIVE_ARM
