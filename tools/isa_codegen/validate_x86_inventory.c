#include "../../src/x86/generated/cdisasm_x86_iform_decode.inc"
#include "../../src/x86/generated/cdisasm_x86_iform_format.inc"

#define ARRAY_COUNT(value) (sizeof(value) / sizeof((value)[0]))

_Static_assert(CDISASM_X86_GEN_IFORM_ID_COUNT == 9001, "iform id count");
_Static_assert(CDISASM_X86_GEN_DESCRIPTOR_COUNT == 10994, "descriptor count");
_Static_assert(ARRAY_COUNT(cdisasm_x86_gen_descriptor_to_iform) == 10994,
               "descriptor map count");
_Static_assert(ARRAY_COUNT(cdisasm_x86_gen_iform_spans) == 9002,
               "iform reverse span count");
_Static_assert(ARRAY_COUNT(cdisasm_x86_gen_iform_to_iclass) == 9002,
               "iform ICLASS map count");
_Static_assert(ARRAY_COUNT(cdisasm_x86_gen_iform_texts) == 9002,
               "iform text count");

int cdisasm_validate_generated_x86_inventory(void)
{
    return (int)cdisasm_x86_gen_descriptor_to_iform[0];
}
