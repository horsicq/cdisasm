#include "cdisasm/cdisasm_arm.h"

#include <stdio.h>

static int failures;

#define EXPECT(expression) \
    do { \
        if (!(expression)) { \
            fprintf(stderr, "%s:%d: expectation failed: %s\n", \
                    __FILE__, __LINE__, #expression); \
            ++failures; \
        } \
    } while (0)

static void check_profile(
    cdisasm_arm_cpu_id cpu_id,
    cdisasm_arm_mode mode,
    cdisasm_arm_family_mask required,
    cdisasm_arm_family_mask forbidden)
{
    cdisasm_arm_decode_context context;
    const cdisasm_arm_family_mask available =
        cdisasm_arm_cpu_family_mask(cpu_id, mode);

    EXPECT(available != CDISASM_ARM_FAMILY_MASK_NONE);
    EXPECT((available & required) == required);
    EXPECT((available & forbidden) == 0);
    EXPECT(cdisasm_arm_cpu_decode_context(cpu_id, mode, &context)
        == CDISASM_STATUS_OK);
    EXPECT(context.cpu_id == cpu_id);
    EXPECT(context.mode == mode);
    EXPECT(context.family_mask == available);
    EXPECT((context.family_value & ~context.family_mask) == 0);
    EXPECT(cdisasm_arm_decode_context_get_available_families(&context)
        == available);
    EXPECT(cdisasm_arm_decode_context_get_set_families(&context)
        == context.family_value);

    EXPECT(cdisasm_arm_decode_context_remove_family(
        &context, CDISASM_ARM_FAMILY_V8) ==
        ((available & CDISASM_ARM_FAMILY_MASK_V8) != 0));
    if ((available & CDISASM_ARM_FAMILY_MASK_V8) != 0) {
        EXPECT((cdisasm_arm_decode_context_get_set_families(&context)
                & CDISASM_ARM_FAMILY_MASK_V8) == 0);
        EXPECT(cdisasm_arm_decode_context_add_family(
            &context, CDISASM_ARM_FAMILY_V8) != 0);
        EXPECT((cdisasm_arm_decode_context_get_set_families(&context)
                & CDISASM_ARM_FAMILY_MASK_V8) != 0);
    }
}

int main(void)
{
    cdisasm_arm_family_id family_id;

    EXPECT(cdisasm_arm_family_descriptor_get(
        CDISASM_ARM_FAMILY_NONE) == NULL);
    EXPECT(cdisasm_arm_family_descriptor_get(
        CDISASM_ARM_FAMILY_LAST + UINT16_C(1)) == NULL);
    for (family_id = CDISASM_ARM_FAMILY_FIRST;
         family_id <= CDISASM_ARM_FAMILY_LAST;
         ++family_id) {
        const cdisasm_arm_family_descriptor *descriptor =
            cdisasm_arm_family_descriptor_get(family_id);
        EXPECT(descriptor != NULL);
        if (descriptor != NULL) {
            EXPECT(descriptor->family_id == family_id);
            EXPECT(descriptor->allowed_modes != CDISASM_ARM_MODE_MASK_NONE);
        }
    }

    EXPECT(cdisasm_arm_cpu_family_mask(
        CDISASM_ARM_CPU_ARM7TDMI, CDISASM_ARM_MODE_A64)
        == CDISASM_ARM_FAMILY_MASK_NONE);
    check_profile(
        CDISASM_ARM_CPU_ARM7TDMI,
        CDISASM_ARM_MODE_A32,
        CDISASM_ARM_FAMILY_MASK_V4,
        CDISASM_ARM_FAMILY_MASK_V8 | CDISASM_ARM_FAMILY_MASK_NEON);
    check_profile(
        CDISASM_ARM_CPU_CORTEX_A53,
        CDISASM_ARM_MODE_A64,
        CDISASM_ARM_FAMILY_MASK_V8 | CDISASM_ARM_FAMILY_MASK_NEON,
        CDISASM_ARM_FAMILY_MASK_APPLE);

    EXPECT(cdisasm_arm_cpu_decode_context(
        CDISASM_ARM_CPU_CORTEX_A53,
        CDISASM_ARM_MODE_A32,
        NULL) == CDISASM_STATUS_INVALID_ARGUMENT);
    EXPECT(cdisasm_arm_decode_context_get_available_families(NULL)
        == CDISASM_ARM_FAMILY_MASK_NONE);
    EXPECT(cdisasm_arm_decode_context_get_set_families(NULL)
        == CDISASM_ARM_FAMILY_MASK_NONE);
    return failures == 0 ? 0 : 1;
}
