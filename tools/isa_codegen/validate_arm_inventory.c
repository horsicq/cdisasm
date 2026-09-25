#include "../../src/arm/generated/cdisasm_arm_isa_decode.inc"
#include "../../src/arm/generated/cdisasm_arm_isa_format.inc"

#define ARRAY_COUNT(value) (sizeof(value) / sizeof((value)[0]))

_Static_assert(ARRAY_COUNT(cdisasm_arm_gen_roots) == 3, "root count");
_Static_assert(ARRAY_COUNT(cdisasm_arm_gen_nodes) == 7592, "node count");
_Static_assert(ARRAY_COUNT(cdisasm_arm_gen_leaves) == 6569, "leaf count");
_Static_assert(ARRAY_COUNT(cdisasm_arm_gen_aliases) == 611, "alias count");
_Static_assert(CDISASM_ARM_GEN_FORM_ID_COUNT == 6569, "form id count");
_Static_assert(ARRAY_COUNT(cdisasm_arm_gen_form_to_leaf) == 6570, "form map count");
_Static_assert(ARRAY_COUNT(cdisasm_arm_gen_leaf_to_form) == 6569, "leaf map count");

int cdisasm_validate_generated_arm_inventory(void)
{
    return (int)cdisasm_arm_gen_roots[0];
}
