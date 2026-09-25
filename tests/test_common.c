#include "cdisasm/cdisasm.h"

#include <stdio.h>
#include <string.h>

#if (USE_ARCH_X86 != 0) && (USE_ARCH_X86 != 1)
#  error "USE_ARCH_X86 must be zero or one"
#endif

#if (USE_ARCH_ARM != 0) && (USE_ARCH_ARM != 1)
#  error "USE_ARCH_ARM must be zero or one"
#endif

#if (USE_DISASM_FORMAT != 0) && (USE_DISASM_FORMAT != 1)
#  error "USE_DISASM_FORMAT must be zero or one"
#endif

#if (USE_EXTRA_OPCODES != 0) && (USE_EXTRA_OPCODES != 1)
#  error "USE_EXTRA_OPCODES must be zero or one"
#endif

static int failures = 0;

#define EXPECT(condition) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "%s:%d: expectation failed: %s\n", \
                __FILE__, __LINE__, #condition); \
            ++failures; \
        } \
    } while (0)

static void test_version(void)
{
    EXPECT(cdisasm_version()
        == ((uint32_t)CDISASM_VERSION_MAJOR << 16
            | (uint32_t)CDISASM_VERSION_MINOR << 8
            | (uint32_t)CDISASM_VERSION_PATCH));
    EXPECT(strcmp(cdisasm_version_string(), CDISASM_VERSION_STRING) == 0);
}

static void test_architecture_configuration(void)
{
    EXPECT(USE_ARCH_X86 == 0 || USE_ARCH_X86 == 1);
    EXPECT(USE_ARCH_ARM == 0 || USE_ARCH_ARM == 1);
    EXPECT(USE_DISASM_FORMAT == 0 || USE_DISASM_FORMAT == 1);
    EXPECT(USE_EXTRA_OPCODES == 0 || USE_EXTRA_OPCODES == 1);
}

static void test_status_strings(void)
{
    static const struct {
        cdisasm_status status;
        const char *text;
    } cases[] = {
        { CDISASM_STATUS_OK, "success" },
        { CDISASM_STATUS_INVALID_ARGUMENT, "invalid argument" },
        { CDISASM_STATUS_END_OF_INPUT, "end of input" },
        { CDISASM_STATUS_TRUNCATED, "truncated instruction" },
        { CDISASM_STATUS_INVALID_INSTRUCTION, "invalid instruction" },
        { CDISASM_STATUS_UNSUPPORTED_INSTRUCTION,
          "unsupported instruction" },
        { CDISASM_STATUS_INTERNAL_ERROR, "internal error" },
        { UINT32_MAX, "unknown status" }
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const char *text = cdisasm_status_string(cases[i].status);
        EXPECT(text != NULL);
        EXPECT(strcmp(text, cases[i].text) == 0);
    }
}

static void test_common_ids(void)
{
    uint32_t grouped_cpu = CDISASM_CPU_GROUP_X86 | UINT32_C(0x1234);

    EXPECT(CDISASM_CPU_UNKNOWN == UINT32_C(0));
    EXPECT(CDISASM_CPU_GROUP_OF(CDISASM_CPU_UNKNOWN) == UINT32_C(0));
    EXPECT(CDISASM_CPU_GROUP_MASK == UINT32_C(0xffff0000));
    EXPECT(CDISASM_CPU_ORDINAL_MASK == UINT32_C(0x0000ffff));
    EXPECT(CDISASM_CPU_GROUP_X86 == UINT32_C(0x00010000));
    EXPECT(CDISASM_CPU_GROUP_ARM == UINT32_C(0x00020000));
    EXPECT(CDISASM_CPU_GROUP_X86 != CDISASM_CPU_GROUP_ARM);
    EXPECT(CDISASM_CPU_GROUP_OF(grouped_cpu) == CDISASM_CPU_GROUP_X86);
    EXPECT(CDISASM_CPU_ORDINAL_OF(grouped_cpu) == UINT32_C(0x1234));
    EXPECT(CDISASM_OPERAND_NONE == 0);
    EXPECT(CDISASM_OPERAND_REGISTER == 1);
    EXPECT(CDISASM_OPERAND_IMMEDIATE == 2);
    EXPECT(CDISASM_OPERAND_MEMORY == 3);
    EXPECT(CDISASM_OPERAND_ACCESS_NONE == 0);
    EXPECT(CDISASM_OPERAND_ACCESS_READ == 1);
    EXPECT(CDISASM_OPERAND_ACCESS_WRITE == 2);
    EXPECT(CDISASM_OPERAND_ACCESS_READ_WRITE == 3);
    EXPECT((CDISASM_GROUP_JUMP & CDISASM_GROUP_CALL) == 0);
    EXPECT((CDISASM_GROUP_RETURN & CDISASM_GROUP_CONDITIONAL) == 0);
    EXPECT((CDISASM_OPERAND_FLAG_PC_RELATIVE
            & CDISASM_OPERAND_FLAG_HAS_ADDRESS)
        == 0);
}

static void test_current_cpu(void)
{
    const cdisasm_cpu_id cpu_id = cdisasm_current_cpu();

    if (cpu_id == CDISASM_CPU_UNKNOWN) {
        return;
    }

    switch (CDISASM_CPU_GROUP_OF(cpu_id)) {
#if USE_ARCH_X86
        case CDISASM_CPU_GROUP_X86:
            EXPECT(cpu_id != CDISASM_CPU_X86);
            EXPECT(cdisasm_x86_cpu_mode_mask(cpu_id)
                != CDISASM_X86_MODE_MASK_NONE);
            break;
#endif
#if USE_ARCH_ARM
        case CDISASM_CPU_GROUP_ARM:
            EXPECT(cpu_id != CDISASM_ARM_CPU_ANY);
            EXPECT(cdisasm_arm_cpu_mode_mask(cpu_id)
                != CDISASM_ARM_MODE_MASK_NONE);
            break;
#endif
        default:
            EXPECT(0);
            break;
    }
}

int main(void)
{
    test_version();
    test_architecture_configuration();
    test_status_strings();
    test_common_ids();
    test_current_cpu();

    if (failures != 0) {
        fprintf(stderr, "%d common test(s) failed\n", failures);
        return 1;
    }
    puts("all common tests passed");
    return 0;
}
