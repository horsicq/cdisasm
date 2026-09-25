#ifndef CDISASM_ARM_PSTATE_MSR_FORMAT_H
#define CDISASM_ARM_PSTATE_MSR_FORMAT_H

#include "arm_pstate_msr.h"

/* Spelling belongs only in formatter translation units. */
static inline const char *arm_pstate_msr_field_name(uint8_t field)
{
    static const char *const names[] = {
        NULL, "uao", "pan", "spsel", "allint", "pm", "ssbs", "dit",
        "svcrsm", "svcrza", "svcrsmza", "tco", "daifset", "daifclr"
    };

    return field < sizeof(names) / sizeof(names[0])
        ? names[field] : NULL;
}

#endif
