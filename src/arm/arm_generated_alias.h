#ifndef CDISASM_ARM_GENERATED_ALIAS_H
#define CDISASM_ARM_GENERATED_ALIAS_H

#include "arm_decoder.h"

/*
 * Selects one exact preferred architectural alias for a generated canonical
 * leaf. The caller supplies architectural context used by alias predicates;
 * the instruction remains unchanged when any other required context is not
 * available or when preference is ambiguous. Returns nonzero only when
 * name_id changes.
 */
int cdisasm_arm_select_generated_alias(const cdisasm_arm_capabilities *capabilities, int in_it_block, cdisasm_arm_instruction *instruction);

/* Re-selects only aliases whose spelling depends on T32 IT state.  This is
 * used after a hand decoder has attached the canonical generated form ID. */
int cdisasm_arm_apply_generated_it_context(const cdisasm_arm_capabilities *capabilities, cdisasm_arm_instruction *instruction);

/* Test one alias's applicability, without requiring it to be the preferred
 * disassembly spelling. IDs are one-based arm_tree_aliases.tsv indices. */
int cdisasm_arm_generated_alias_matches(const cdisasm_arm_capabilities *capabilities, cdisasm_arm_mode mode, uint32_t raw_instruction, cdisasm_arm_form_id form_id,
                                        uint16_t alias_id);

#endif
