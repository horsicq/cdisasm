#include "cdisasm/cdisasm_mips.h"
#include <string.h>

#if USE_EXTRA_OPCODES && USE_MIPS_ALLEGREX
static const cdisasm_mips_encoding_pattern allegrex_patterns[] = {
#include "generated/mips_allegrex_pattern_catalog.inc"
};
#endif

size_t CDISASM_CALL cdisasm_mips_allegrex_pattern_count(void)
{
#if USE_EXTRA_OPCODES && USE_MIPS_ALLEGREX
    return sizeof(allegrex_patterns) / sizeof(allegrex_patterns[0]);
#else
    return 0;
#endif
}

const cdisasm_mips_encoding_pattern *CDISASM_CALL cdisasm_mips_allegrex_pattern_get(size_t index)
{
#if USE_EXTRA_OPCODES && USE_MIPS_ALLEGREX
    if (index < cdisasm_mips_allegrex_pattern_count()) return &allegrex_patterns[index];
#else
    (void)index;
#endif
    return NULL;
}

const cdisasm_mips_encoding_pattern *CDISASM_CALL cdisasm_mips_allegrex_pattern_find(uint32_t word)
{
#if USE_EXTRA_OPCODES && USE_MIPS_ALLEGREX
    size_t n;
    for (n = 0; n < cdisasm_mips_allegrex_pattern_count(); ++n)
        if ((word & allegrex_patterns[n].mask) == allegrex_patterns[n].value)
            return &allegrex_patterns[n];
#else
    (void)word;
#endif
    return NULL;
}

cdisasm_status CDISASM_CALL cdisasm_mips_allegrex_pattern_field_value(
    const cdisasm_mips_encoding_pattern *pattern, uint32_t word, size_t field_index, int64_t *value)
{
    if (value == NULL) return CDISASM_STATUS_INVALID_ARGUMENT;
    *value = 0;
#if USE_EXTRA_OPCODES && USE_MIPS_ALLEGREX
    {
        size_t n;
        for (n = 0; n < cdisasm_mips_allegrex_pattern_count(); ++n) {
            if (pattern == &allegrex_patterns[n]) {
                const cdisasm_mips_encoding_field *field;
                uint32_t bits;
                int64_t decoded;
                if (field_index >= pattern->field_count) return CDISASM_STATUS_INVALID_ARGUMENT;
                if ((word & pattern->mask) != pattern->value) return CDISASM_STATUS_INVALID_INSTRUCTION;
                field = &pattern->field[field_index];
                bits = (word >> field->lsb) & ((UINT32_C(1) << field->bits) - 1u);
                decoded = (int64_t)bits;
                if (field->kind == CDISASM_MIPS_PATTERN_FIELD_DISPLACEMENT &&
                    (bits & (UINT32_C(1) << (field->bits - 1u))))
                    decoded -= INT64_C(1) << field->bits;
                *value = decoded * field->scale;
                return CDISASM_STATUS_OK;
            }
        }
    }
    return CDISASM_STATUS_INVALID_ARGUMENT;
#else
    (void)pattern; (void)word; (void)field_index;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
}

uint32_t CDISASM_CALL cdisasm_mips_allegrex_pattern_decode(
    const uint8_t *code, size_t code_size, uint64_t address, uint32_t byte_order,
    cdisasm_mips_pattern_instruction *instruction)
{
    uint8_t bytes[4];
    if (instruction == NULL) return 0;
    if (code == NULL || byte_order > CDISASM_MIPS_PATTERN_BIG_ENDIAN) {
        memset(instruction, 0, sizeof(*instruction));
        instruction->last_error_id = CDISASM_STATUS_INVALID_ARGUMENT;
        return 0;
    }
    if (code_size < sizeof(bytes)) {
        memset(instruction, 0, sizeof(*instruction));
        instruction->last_error_id = code_size == 0 ? CDISASM_STATUS_END_OF_INPUT : CDISASM_STATUS_TRUNCATED;
        return 0;
    }
    /* Read before clearing so callers may reuse an overlapping input buffer. */
    memcpy(bytes, code, sizeof(bytes));
    memset(instruction, 0, sizeof(*instruction));
#if USE_EXTRA_OPCODES && USE_MIPS_ALLEGREX
    {
        uint32_t word;
        size_t n;
        const cdisasm_mips_encoding_pattern *pattern;
        if (byte_order == CDISASM_MIPS_PATTERN_BIG_ENDIAN)
            word = ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
                ((uint32_t)bytes[2] << 8) | bytes[3];
        else
            word = bytes[0] | ((uint32_t)bytes[1] << 8) |
                ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
        pattern = cdisasm_mips_allegrex_pattern_find(word);
        if (pattern == NULL) {
            instruction->last_error_id = CDISASM_STATUS_INVALID_INSTRUCTION;
            return 0;
        }
        for (n = 0; n < pattern->field_count; ++n) {
            if (cdisasm_mips_allegrex_pattern_field_value(pattern, word, n,
                    &instruction->field_value[n]) != CDISASM_STATUS_OK) {
                memset(instruction, 0, sizeof(*instruction));
                instruction->last_error_id = CDISASM_STATUS_INVALID_INSTRUCTION;
                return 0;
            }
        }
        instruction->address = address;
        instruction->pattern = *pattern;
        instruction->raw = word;
        memcpy(instruction->raw_bytes, bytes, sizeof(bytes));
        instruction->byte_order = byte_order;
        return 4;
    }
#else
    (void)address;
    instruction->last_error_id = CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    return 0;
#endif
}

int CDISASM_CALL cdisasm_mips_allegrex_pattern_validate(
    const cdisasm_mips_pattern_instruction *instruction)
{
    cdisasm_mips_pattern_instruction replay;
    if (instruction == NULL || instruction->last_error_id != CDISASM_STATUS_OK ||
        instruction->reserved != 0) return 0;
    return cdisasm_mips_allegrex_pattern_decode(instruction->raw_bytes,
        sizeof(instruction->raw_bytes), instruction->address,
        instruction->byte_order, &replay) == 4 &&
        memcmp(instruction, &replay, sizeof(replay)) == 0;
}
