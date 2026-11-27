/* Copyright (c) 2026 hors<horsicq@gmail.com> */

/* Reversible IBM/GNU SPU syntax. Architectural control suffixes retain
 * D/E/P/C bits even when convenience aliases are disabled. */
#include "cdisasm/cdisasm_spu.h"

#include <stdio.h>
#include <string.h>

typedef struct spu_text {
    char *out;
    size_t capacity, length;
    uint32_t options;
    int ok;
} spu_text;

static void spu_put(spu_text *text, const char *value)
{
    size_t length;
    if (!text->ok) return;
    length = strlen(value);
    if (length >= text->capacity - text->length) {
        text->ok = 0;
        return;
    }
    memcpy(text->out + text->length, value, length + 1u);
    text->length += length;
}

static void spu_number(spu_text *text, int64_t value)
{
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%lld", (long long)value);
    spu_put(text, buffer);
}

static void spu_register(spu_text *text, uint32_t reg, int force_prefix)
{
    if (reg > 127) {
        text->ok = 0;
        return;
    }
    if (text->options & CDISASM_SPU_FORMAT_REGISTER_NAMES) {
        if (reg == 0) {
            spu_put(text, "$LR");
            return;
        }
        if (reg == 1) {
            spu_put(text, "$SP");
            return;
        }
        spu_put(text, "$");
    } else if (force_prefix) spu_put(text, "$");
    spu_number(text, reg);
}

static void spu_operand(spu_text *text, const cdisasm_spu_instruction *instruction, uint32_t index)
{
    const cdisasm_spu_operand *operand = &instruction->operand[index];
    const char *base = cdisasm_spu_name(instruction->name_id);
    switch (operand->type) {
        case CDISASM_SPU_OP_REGISTER:
            /* GNU treats bare 'nop N' as repetition, not the false RT. */
            spu_register(text, operand->reg, base && !strcmp(base, "nop"));
            break;
        case CDISASM_SPU_OP_IMMEDIATE: spu_number(text, operand->value); break;
        case CDISASM_SPU_OP_SPR:
            if (operand->raw > 127) {
                text->ok = 0;
                break;
            }
            if (text->options & CDISASM_SPU_FORMAT_REGISTER_NAMES) spu_put(text, "$sp");
            spu_number(text, operand->raw);
            break;
        case CDISASM_SPU_OP_CHANNEL:
            if (operand->raw > 127) {
                text->ok = 0;
                break;
            }
            if (text->options & CDISASM_SPU_FORMAT_REGISTER_NAMES) {
                int direction = base && !strcmp(base, "rchcnt") ? -1 : (operand->access & CDISASM_SPU_ACCESS_WRITE) != 0;
                const char *name = cdisasm_spu_channel_name(instruction->cpu_id, operand->raw, direction);
                if (name) {
                    if (*name != '$') spu_put(text, "$");
                    spu_put(text, name);
                } else {
                    spu_put(text, "$ch");
                    spu_number(text, operand->raw);
                }
            } else spu_number(text, operand->raw);
            break;
        case CDISASM_SPU_OP_MEMORY:
            spu_number(text, operand->value);
            spu_put(text, "(");
            spu_register(text, operand->base, 0);
            spu_put(text, ")");
            break;
        case CDISASM_SPU_OP_ADDRESS:
        case CDISASM_SPU_OP_HINT:
            if (operand->flags & CDISASM_SPU_OPERAND_RELATIVE) {
                spu_put(text, ".");
                if (operand->value >= 0) spu_put(text, "+");
            }
            spu_number(text, operand->value);
            break;
        default: text->ok = 0; break;
    }
}

static int spu_begin(spu_text *text, const cdisasm_spu_instruction *instruction, uint32_t options, char *out, size_t capacity)
{
    const cdisasm_spu_form *form;
    if (out && capacity) out[0] = 0;
    if (!instruction || !out || !capacity || instruction->length != 4 || instruction->operand_count > CDISASM_SPU_MAX_OPERANDS ||
        instruction->form_id >= cdisasm_spu_form_count() || (options & ~(CDISASM_SPU_FORMAT_REGISTER_NAMES | CDISASM_SPU_FORMAT_BASE_MNEMONICS)))
        return 0;
    form = &cdisasm_spu_forms()[instruction->form_id];
    if (instruction->name_id != form->name_id || instruction->operand_count != form->operand_count) return 0;
    text->out = out;
    text->capacity = capacity;
    text->length = 0;
    text->options = options;
    text->ok = 1;
    return 1;
}

size_t CDISASM_CALL cdisasm_spu_format_operand(const cdisasm_spu_instruction *instruction, uint32_t index, uint32_t options, char *text, size_t capacity)
{
    spu_text out;
    if (!spu_begin(&out, instruction, options, text, capacity) || index >= instruction->operand_count) return 0;
    spu_operand(&out, instruction, index);
    if (!out.ok) {
        text[0] = 0;
        return 0;
    }
    return out.length;
}

size_t CDISASM_CALL cdisasm_spu_format(const cdisasm_spu_instruction *instruction, uint32_t options, char *text, size_t capacity)
{
    spu_text out;
    const cdisasm_spu_form *form;
    const cdisasm_spu_alias *alias = NULL;
    const char *name;
    uint32_t index, count;
    if (!spu_begin(&out, instruction, options, text, capacity)) return 0;
    form = &cdisasm_spu_forms()[instruction->form_id];
    name = cdisasm_spu_name(instruction->name_id);
    if (!name) return 0;
    if (!(options & CDISASM_SPU_FORMAT_BASE_MNEMONICS) || (form->constraint == CDISASM_SPU_CONSTRAINT_HBR && (instruction->controls & CDISASM_SPU_CONTROL_PREFETCH))) {
        const cdisasm_spu_alias *aliases = cdisasm_spu_aliases();
        for (index = 0; index < cdisasm_spu_alias_count(); ++index) {
            /* HBRP has no conventional explicit-operand spelling. Its
             * zero-operand control variant preserves all bits when RA=0,
             * so it remains usable in base mode (Assembly v1.6 p14). */
            if ((options & CDISASM_SPU_FORMAT_BASE_MNEMONICS) && aliases[index].operand_count) continue;
            if (aliases[index].form_id == instruction->form_id && (instruction->word & aliases[index].mask) == aliases[index].match) {
                alias = &aliases[index];
                name = alias->name;
                break;
            }
        }
    }
    spu_put(&out, name);
    /* Aliases with a control predicate already carry the suffix. */
    if (!alias || !(alias->mask & form->control_mask)) {
        if (form->constraint == CDISASM_SPU_CONSTRAINT_DE) {
            if (instruction->controls & CDISASM_SPU_CONTROL_DISABLE) spu_put(&out, "d");
            else if (instruction->controls & CDISASM_SPU_CONTROL_ENABLE) spu_put(&out, "e");
        } else if (instruction->controls & CDISASM_SPU_CONTROL_PREFETCH) {
            spu_put(&out, form->constraint == CDISASM_SPU_CONSTRAINT_HBR ? "p" : "c");
        }
    }
    count = alias ? alias->operand_count : instruction->operand_count;
    if (count > CDISASM_SPU_MAX_OPERANDS) out.ok = 0;
    for (index = 0; index < count && out.ok; ++index) {
        uint32_t operand = alias ? alias->operand_index[index] : index;
        if (operand >= instruction->operand_count) {
            out.ok = 0;
            break;
        }
        spu_put(&out, index ? "," : " ");
        spu_operand(&out, instruction, operand);
    }
    if (!out.ok) {
        text[0] = 0;
        return 0;
    }
    return out.length;
}
