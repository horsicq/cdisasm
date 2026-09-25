#include <stdio.h>
#include <string.h>

/* Exercise the exact alias recipe, separately from alias preference. */
#include "../src/arm/arm_generated_formatter.c"

int cdisasm_arm_generated_form_matches(
    const cdisasm_arm_instruction *instruction)
{
    return instruction != NULL;
}

typedef struct invcond_case {
    uint32_t word;
    uint16_t form_id;
    cdisasm_arm_name_id name_id;
    const char *expected;
} invcond_case;

static const invcond_case cases[] = {
    { UINT32_C(0x1a9f17e0), 5708u, CDISASM_ARM_NAME_CSET,
      "cset w0, eq" },
    { UINT32_C(0x1a820441), 5708u, CDISASM_ARM_NAME_CINC,
      "cinc w1, w2, ne" },
    { UINT32_C(0x5a9f33e3), 5709u, CDISASM_ARM_NAME_CSETM,
      "csetm w3, cs" },
    { UINT32_C(0x5a8550a4), 5709u, CDISASM_ARM_NAME_CINV,
      "cinv w4, w5, mi" },
    { UINT32_C(0x5a8744e6), 5710u, CDISASM_ARM_NAME_CNEG,
      "cneg w6, w7, pl" },
    { UINT32_C(0x9a9f17e0), 5712u, CDISASM_ARM_NAME_CSET,
      "cset x0, eq" },
    { UINT32_C(0x9a820441), 5712u, CDISASM_ARM_NAME_CINC,
      "cinc x1, x2, ne" },
    { UINT32_C(0xda9f33e3), 5713u, CDISASM_ARM_NAME_CSETM,
      "csetm x3, cs" },
    { UINT32_C(0xda8550a4), 5713u, CDISASM_ARM_NAME_CINV,
      "cinv x4, x5, mi" },
    { UINT32_C(0xda8744e6), 5714u, CDISASM_ARM_NAME_CNEG,
      "cneg x6, x7, pl" },
};

static const cdisasm_arm_asmgen_alias *find_alias(
    uint16_t form_id, cdisasm_arm_name_id name_id)
{
    size_t index;

    for (index = 0u; index < sizeof(cdisasm_arm_asmgen_aliases)
            / sizeof(cdisasm_arm_asmgen_aliases[0]); ++index) {
        const cdisasm_arm_asmgen_alias *alias =
            &cdisasm_arm_asmgen_aliases[index];

        if (alias->leaf_index == (uint32_t)form_id - 1u
            && alias->public_name_id == name_id) {
            return alias;
        }
    }
    return NULL;
}

int main(void)
{
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const invcond_case *item = &cases[index];
        const cdisasm_arm_asmgen_alias *alias =
            find_alias(item->form_id, item->name_id);
        char buffer[96] = {0};
        size_t length;

        if (alias == NULL || alias->render_status == 0u) {
            fprintf(stderr, "missing direct conditional alias at case %zu\n",
                index);
            return 1;
        }
        length = arm_asmgen_render_recipe(
            alias->recipe_first, alias->recipe_count, item->word,
            CDISASM_ARM_ISA_A64, 0u, 0u, 0u,
            buffer, sizeof(buffer));
        if (length != strlen(item->expected)
            || strcmp(buffer, item->expected) != 0) {
            fprintf(stderr, "conditional alias case %zu: got '%s'\n",
                index, length != 0u ? buffer : "<no recipe>");
            return 1;
        }
    }
    {
        const cdisasm_arm_asmgen_alias *alias =
            find_alias(5708u, CDISASM_ARM_NAME_CSET);
        char buffer[96];
        uint32_t invalid = (cases[0].word & ~UINT32_C(0xf000))
            | UINT32_C(0xe000);

        if (alias == NULL || arm_asmgen_render_recipe(
                alias->recipe_first, alias->recipe_count, invalid,
                CDISASM_ARM_ISA_A64, 0u, 0u, 0u,
                buffer, sizeof(buffer)) != 0u) {
            fputs("invalid AL condition was rendered as an alias\n", stderr);
            return 1;
        }
    }
    puts("ARM generated inverse-condition alias tests passed");
    return 0;
}
