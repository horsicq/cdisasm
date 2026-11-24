/* SPU fixed-word decoder. Architectural facts come from the manual-sourced
 * generated catalog, shared through the public form API with encoders. */
#include "cdisasm/cdisasm_spu.h"

#include <string.h>

#include "generated/spu_forms.inc"
#include "generated/spu_aliases.inc"
#include "generated/spu_profiles.inc"
#include "generated/spu_channels.inc"

static int spu_equal(const char *a, const char *b)
{
    if (!a || !b) return 0;
    for (; *a && *b; ++a, ++b) {
        unsigned x = (unsigned char)*a, y = (unsigned char)*b;
        if (x >= 'A' && x <= 'Z') x += 'a' - 'A';
        if (y >= 'A' && y <= 'Z') y += 'a' - 'A';
        if (x != y) return 0;
    }
    return !*a && !*b;
}

static const cdisasm_spu_profile *spu_cpu(cdisasm_spu_cpu_id cpu)
{
    uint32_t ordinal = CDISASM_CPU_ORDINAL_OF(cpu);
    if (CDISASM_CPU_GROUP_OF(cpu) != CDISASM_CPU_GROUP_SPU || ordinal >= CDISASM_SPU_PROFILE_COUNT) return NULL;
    return &spu_profiles[ordinal];
}

const char *CDISASM_CALL cdisasm_spu_cpu_name(cdisasm_spu_cpu_id cpu)
{
    const cdisasm_spu_profile *profile = spu_cpu(cpu);
    return profile ? profile->name : NULL;
}

cdisasm_spu_cpu_id CDISASM_CALL cdisasm_spu_cpu_from_name(const char *name)
{
    uint32_t index;
    for (index = 0; index < CDISASM_SPU_PROFILE_COUNT; ++index)
        if (spu_equal(name, spu_profiles[index].name)) return spu_profiles[index].cpu_id;
    return CDISASM_CPU_UNKNOWN;
}

uint32_t CDISASM_CALL cdisasm_spu_cpu_features(cdisasm_spu_cpu_id cpu)
{
    const cdisasm_spu_profile *profile = spu_cpu(cpu);
    return profile ? profile->features : 0;
}

uint32_t CDISASM_CALL cdisasm_spu_cpu_mode_mask(cdisasm_spu_cpu_id cpu)
{
    return spu_cpu(cpu) ? CDISASM_SPU_MODE_MASK_32 : 0;
}

uint32_t CDISASM_CALL cdisasm_spu_profile_count(void) { return CDISASM_SPU_PROFILE_COUNT; }
const cdisasm_spu_profile *CDISASM_CALL cdisasm_spu_profiles(void) { return spu_profiles; }
const cdisasm_spu_profile *CDISASM_CALL cdisasm_spu_profile_at(uint32_t index)
{
    return index < CDISASM_SPU_PROFILE_COUNT ? &spu_profiles[index] : NULL;
}
uint32_t CDISASM_CALL cdisasm_spu_form_count(void) { return CDISASM_SPU_FORM_COUNT; }
const cdisasm_spu_form *CDISASM_CALL cdisasm_spu_forms(void) { return spu_forms; }
const char *CDISASM_CALL cdisasm_spu_name(uint32_t name_id)
{
    return name_id < CDISASM_SPU_NAME_COUNT ? spu_names[name_id] : NULL;
}
uint32_t CDISASM_CALL cdisasm_spu_alias_count(void) { return CDISASM_SPU_ALIAS_COUNT; }
const cdisasm_spu_alias *CDISASM_CALL cdisasm_spu_aliases(void) { return spu_aliases; }
uint32_t CDISASM_CALL cdisasm_spu_channel_count(void) { return CDISASM_SPU_CHANNEL_COUNT; }
const cdisasm_spu_channel *CDISASM_CALL cdisasm_spu_channels(void) { return spu_channels; }

cdisasm_status CDISASM_CALL cdisasm_spu_cpu_decode_flag_mask(cdisasm_spu_cpu_id cpu, uint32_t mode, cdisasm_decode_flags *flags)
{
    if (!flags) return CDISASM_STATUS_INVALID_ARGUMENT;
    cdisasm_decode_flags_reset(flags);
    return spu_cpu(cpu) && (!mode || mode == CDISASM_SPU_MODE_32) ? CDISASM_STATUS_OK : CDISASM_STATUS_INVALID_ARGUMENT;
}

static int spu_context(cdisasm_spu_cpu_id cpu, uint32_t mode, const cdisasm_decode_flags *flags)
{
    unsigned index;
    if (!spu_cpu(cpu) || (mode && mode != CDISASM_SPU_MODE_32)) return 0;
    if (flags)
        for (index = 0; index < CDISASM_DECODE_FLAGS_BITMAP_COUNT; ++index)
            if (flags->bitmap[index]) return 0;
    return 1;
}

static uint32_t spu_mask(unsigned bits)
{
    return bits >= 32 ? UINT32_MAX : (UINT32_C(1) << bits) - 1u;
}

static int spu_field_valid(const cdisasm_spu_form_operand *operand)
{
    unsigned index;
    uint32_t used = 0, encoded = 0;
    if (!operand || operand->field_count > 2 || operand->bits > 32) return 0;
    for (index = 0; index < operand->field_count; ++index) {
        const cdisasm_spu_field *field = &operand->field[index];
        uint32_t source, value;
        if (!field->width || field->width > 32 || field->lsb >= 32 || field->value_lsb >= 32 ||
            field->width > 32u - field->lsb || field->width > 32u - field->value_lsb) return 0;
        source = spu_mask(field->width) << field->lsb;
        value = spu_mask(field->width) << field->value_lsb;
        if ((source & encoded) || (value & used)) return 0;
        encoded |= source;
        used |= value;
    }
    return used == spu_mask(operand->bits);
}

uint32_t CDISASM_CALL cdisasm_spu_field_get(uint32_t word, const cdisasm_spu_form_operand *operand)
{
    uint32_t value = 0;
    unsigned index;
    if (!spu_field_valid(operand)) return 0;
    for (index = 0; index < operand->field_count; ++index) {
        const cdisasm_spu_field *field = &operand->field[index];
        value |= ((word >> field->lsb) & spu_mask(field->width)) << field->value_lsb;
    }
    return value;
}

int CDISASM_CALL cdisasm_spu_field_set(uint32_t *word, const cdisasm_spu_form_operand *operand, uint32_t raw)
{
    unsigned index;
    uint32_t result;
    if (!word || !spu_field_valid(operand) || (raw & ~spu_mask(operand->bits))) return 0;
    result = *word;
    for (index = 0; index < operand->field_count; ++index) {
        const cdisasm_spu_field *field = &operand->field[index];
        uint32_t mask = spu_mask(field->width);
        result = (result & ~(mask << field->lsb)) | (((raw >> field->value_lsb) & mask) << field->lsb);
    }
    *word = result;
    return 1;
}

int CDISASM_CALL cdisasm_spu_form_available(const cdisasm_spu_form *form, cdisasm_spu_cpu_id cpu, uint32_t mode, const cdisasm_decode_flags *flags)
{
    const cdisasm_spu_profile *profile = spu_cpu(cpu);
    return form && profile && spu_context(cpu, mode, flags) && (form->profile_mask & profile->profile_mask) != 0;
}

int CDISASM_CALL cdisasm_spu_form_valid(const cdisasm_spu_form *form, cdisasm_spu_cpu_id cpu, uint32_t mode, const cdisasm_decode_flags *flags, uint32_t word)
{
    unsigned index;
    if (!cdisasm_spu_form_available(form, cpu, mode, flags) || (word & form->mask) != form->match || form->operand_count > CDISASM_SPU_MAX_OPERANDS) return 0;
    if (form->constraint == CDISASM_SPU_CONSTRAINT_DE &&
        (word & (CDISASM_SPU_CONTROL_DISABLE | CDISASM_SPU_CONTROL_ENABLE)) == (CDISASM_SPU_CONTROL_DISABLE | CDISASM_SPU_CONTROL_ENABLE)) return 0;
    if (form->constraint == CDISASM_SPU_CONSTRAINT_HBR && (word & CDISASM_SPU_CONTROL_PREFETCH)) {
        for (index = 0; index < form->operand_count; ++index)
            if (form->operand[index].kind == CDISASM_SPU_OP_HINT && cdisasm_spu_field_get(word, &form->operand[index])) return 0;
    }
    return form->constraint <= CDISASM_SPU_CONSTRAINT_HBR;
}

const char *CDISASM_CALL cdisasm_spu_channel_name(cdisasm_spu_cpu_id cpu, uint32_t channel, int write)
{
    const cdisasm_spu_profile *profile = spu_cpu(cpu);
    uint32_t index, access = write < 0 ? 3u : write ? CDISASM_SPU_ACCESS_WRITE : CDISASM_SPU_ACCESS_READ;
    if (!profile || channel > 127) return NULL;
    for (index = 0; index < CDISASM_SPU_CHANNEL_COUNT; ++index)
        if (spu_channels[index].number == channel && (spu_channels[index].profile_mask & profile->profile_mask) && (spu_channels[index].access & access))
            return spu_channels[index].name;
    return NULL;
}

int32_t CDISASM_CALL cdisasm_spu_channel_from_name(cdisasm_spu_cpu_id cpu, const char *name, int write)
{
    const cdisasm_spu_profile *profile = spu_cpu(cpu);
    uint32_t index, access = write < 0 ? 3u : write ? CDISASM_SPU_ACCESS_WRITE : CDISASM_SPU_ACCESS_READ;
    if (!profile || !name) return -1;
    if (*name == '$') ++name;
    if ((name[0] == 'c' || name[0] == 'C') && (name[1] == 'h' || name[1] == 'H')) {
        const char *p = name + 2;
        uint32_t value = 0;
        if (!*p) return -1;
        for (; *p; ++p) {
            if (*p < '0' || *p > '9' || value > 127) return -1;
            value = value * 10u + (uint32_t)(*p - '0');
        }
        return value < 128 ? (int32_t)value : -1;
    }
    for (index = 0; index < CDISASM_SPU_CHANNEL_COUNT; ++index) {
        const char *candidate = spu_channels[index].name;
        if (*candidate == '$') ++candidate;
        if ((spu_channels[index].profile_mask & profile->profile_mask) && (spu_channels[index].access & access) && spu_equal(name, candidate))
            return spu_channels[index].number;
    }
    return -1;
}

static int64_t spu_value(uint32_t raw, const cdisasm_spu_form_operand *operand)
{
    int64_t value = raw;
    if (operand->flags & CDISASM_SPU_OPERAND_SCALE_NEGATE) value = (int64_t)operand->bias - raw;
    else if ((operand->flags & CDISASM_SPU_OPERAND_SIGNED) && operand->bits && (raw & (UINT32_C(1) << (operand->bits - 1u))))
        value -= INT64_C(1) << operand->bits;
    return value * (INT64_C(1) << operand->shift);
}

uint32_t CDISASM_CALL cdisasm_spu_decode_lslr(cdisasm_spu_cpu_id cpu, uint32_t mode, const uint8_t *code, size_t code_size, uint64_t address,
                                            const cdisasm_decode_flags *flags, uint32_t local_store_mask, cdisasm_spu_instruction *instruction)
{
    uint32_t word, slot, last;
    if (!instruction) return 0;
    memset(instruction, 0, sizeof(*instruction));
    if (!code || code_size < 4 || (address & 3u) || !spu_context(cpu, mode, flags) || local_store_mask < 15u ||
        (local_store_mask & (local_store_mask + UINT32_C(1)))) return 0;
    word = ((uint32_t)code[0] << 24) | ((uint32_t)code[1] << 16) | ((uint32_t)code[2] << 8) | code[3];
    last = spu_bucket_first[(word >> 21) + 1u];
    for (slot = spu_bucket_first[word >> 21]; slot < last; ++slot) {
        uint32_t form_id = spu_bucket_forms[slot];
        const cdisasm_spu_form *form = &spu_forms[form_id];
        unsigned index;
        if (!cdisasm_spu_form_valid(form, cpu, mode, flags, word)) continue;
        instruction->address = address;
        instruction->cpu_id = cpu;
        instruction->length = 4;
        instruction->form_id = form_id;
        instruction->name_id = form->name_id;
        instruction->word = word;
        instruction->flags = form->flags;
        instruction->controls = word & form->control_mask;
        instruction->local_store_mask = local_store_mask;
        instruction->operand_count = form->operand_count;
        memcpy(instruction->bytes, code, 4);
        for (index = 0; index < form->operand_count; ++index) {
            const cdisasm_spu_form_operand *spec = &form->operand[index];
            cdisasm_spu_operand *operand = &instruction->operand[index];
            operand->type = spec->kind;
            operand->access = spec->access;
            operand->bits = spec->bits;
            operand->shift = spec->shift;
            operand->flags = spec->flags;
            operand->raw = cdisasm_spu_field_get(word, spec);
            operand->value = spu_value(operand->raw, spec);
            if (spec->kind == CDISASM_SPU_OP_REGISTER) {
                operand->reg = (uint8_t)operand->raw;
                operand->size = 16;
            } else if (spec->kind == CDISASM_SPU_OP_MEMORY) {
                operand->base = (uint8_t)((word >> spec->base_lsb) & spu_mask(spec->base_width));
                /* Generate-controls instructions use address syntax but do
                 * not access memory (ISA pp40-47). */
                operand->size = (form->flags & (CDISASM_SPU_FLAG_LOAD | CDISASM_SPU_FLAG_STORE)) ? 16 : 0;
            } else if (spec->kind == CDISASM_SPU_OP_ADDRESS || spec->kind == CDISASM_SPU_OP_HINT) {
                uint32_t target = (uint32_t)operand->value;
                if (spec->flags & CDISASM_SPU_OPERAND_RELATIVE) target += (uint32_t)address;
                target &= local_store_mask;
                if ((form->flags & (CDISASM_SPU_FLAG_LOAD | CDISASM_SPU_FLAG_STORE)) && spec->kind == CDISASM_SPU_OP_ADDRESS) {
                    target &= ~UINT32_C(15);
                    operand->size = 16;
                } else target &= ~UINT32_C(3);
                operand->target = target;
                if ((form->flags & CDISASM_SPU_FLAG_JUMP) && spec->kind == CDISASM_SPU_OP_ADDRESS) instruction->branch_target = target;
            }
            if ((spec->flags & CDISASM_SPU_OPERAND_SCALE_NEGATE) && (operand->value < 0 || operand->value > 127))
                operand->flags |= CDISASM_SPU_OPERAND_EXECUTION_UNDEFINED;
        }
        return 4;
    }
    return 0;
}

uint32_t CDISASM_CALL cdisasm_spu_decode(cdisasm_spu_cpu_id cpu, uint32_t mode, const uint8_t *code, size_t code_size, uint64_t address,
                                       const cdisasm_decode_flags *flags, cdisasm_spu_instruction *instruction)
{
    return cdisasm_spu_decode_lslr(cpu, mode, code, code_size, address, flags, CDISASM_SPU_DEFAULT_LOCAL_STORE_MASK, instruction);
}
