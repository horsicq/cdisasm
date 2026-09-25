#ifndef CDISASM_ARM_PSTATE_MSR_H
#define CDISASM_ARM_PSTATE_MSR_H

#include "cdisasm/cdisasm_arm.h"

/* Pinned AARCHMRS Registers.json, A64.MSRimmediate encodings.  The generic
 * MSR (immediate) leaf supplies op1, CRm and op2; some fields constrain CRm
 * and use only its low bit as the displayed immediate. */
static inline int arm_pstate_msr_decode_word(
    uint32_t word, uint8_t *field, uint8_t *immediate)
{
    uint32_t op1;
    uint32_t op2;
    uint32_t crm;
    uint8_t selected = CDISASM_ARM_PSTATE_FIELD_NONE;
    uint8_t value;

    if (field == NULL || immediate == NULL
        || (word & UINT32_C(0xfff8f01f)) != UINT32_C(0xd500401f)) {
        return 0;
    }
    op1 = (word >> 16) & 7u;
    op2 = (word >> 5) & 7u;
    crm = (word >> 8) & 15u;
    value = (uint8_t)crm;
    if (op1 == 0u) {
        switch (op2) {
            case 3u: selected = CDISASM_ARM_PSTATE_FIELD_UAO; break;
            case 4u: selected = CDISASM_ARM_PSTATE_FIELD_PAN; break;
            case 5u: selected = CDISASM_ARM_PSTATE_FIELD_SPSEL; break;
            default: break;
        }
    } else if (op1 == 1u && op2 == 0u) {
        if (crm <= 1u) {
            selected = CDISASM_ARM_PSTATE_FIELD_ALLINT;
            value = (uint8_t)(crm & 1u);
        } else if (crm == 2u || crm == 3u) {
            selected = CDISASM_ARM_PSTATE_FIELD_PM;
            value = (uint8_t)(crm & 1u);
        }
    } else if (op1 == 3u) {
        switch (op2) {
            case 1u: selected = CDISASM_ARM_PSTATE_FIELD_SSBS; break;
            case 2u: selected = CDISASM_ARM_PSTATE_FIELD_DIT; break;
            case 3u:
                if (crm >= 2u && crm <= 7u) {
                    selected = (cdisasm_arm_pstate_field_id)(
                        CDISASM_ARM_PSTATE_FIELD_SVCRSM
                        + ((crm >> 1) - 1u));
                    value = (uint8_t)(crm & 1u);
                }
                break;
            case 4u: selected = CDISASM_ARM_PSTATE_FIELD_TCO; break;
            case 6u: selected = CDISASM_ARM_PSTATE_FIELD_DAIFSET; break;
            case 7u: selected = CDISASM_ARM_PSTATE_FIELD_DAIFCLR; break;
            default: break;
        }
    }
    if (selected == CDISASM_ARM_PSTATE_FIELD_NONE) {
        return 0;
    }
    *field = selected;
    *immediate = value;
    return 1;
}

#endif
