#ifndef CDISASM_MIPS_VU_INTERNAL_H
#define CDISASM_MIPS_VU_INTERNAL_H

#include "mips_decoder.h"

#define VU_PROP_FLOAT 1u
#define VU_PROP_DEST_MASK 2u
#define VU_PROP_UNIT1_ONLY 4u
#define VU_PROP_BRANCH 8u
#define VU_PROP_CONDITIONAL 16u
#define VU_PROP_CALL 32u
#define VU_PROP_LIKELY 64u
#define VU_PROP_PRE 128u
#define VU_PROP_POST 256u
#define VU_PROP_LOCAL 512u
#define VU_PROP_STORE 1024u
#define VU_PROP_ACC_READ 2048u

typedef struct vu_resource {
    uint16_t reg;
    uint8_t access, size;
} vu_resource;
typedef struct vu_form {
    uint32_t mask, value;
    uint16_t name, form;
    uint8_t recipe, kind;
    uint16_t properties;
    uint8_t effect_count;
    vu_resource effect[4];
} vu_form;

#include "generated/mips_vu_recipes.inc"

/* Shared only by the VU decoder and its specialized text renderer. */
const vu_form *cdisasm_mips_vu_form(cdisasm_mips_form_id form);

#endif
