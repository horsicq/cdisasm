#include "cdisasm/cdisasm_mips.h"

#if USE_EXTRA_OPCODES
static const cdisasm_mips_encoding_pattern allegrex_patterns[] = {
#include "generated/mips_allegrex_pattern_catalog.inc"
};
#endif

size_t CDISASM_CALL cdisasm_mips_allegrex_pattern_count(void)
{
#if USE_EXTRA_OPCODES
    return sizeof(allegrex_patterns) / sizeof(allegrex_patterns[0]);
#else
    return 0;
#endif
}

const cdisasm_mips_encoding_pattern *CDISASM_CALL cdisasm_mips_allegrex_pattern_get(size_t index)
{
#if USE_EXTRA_OPCODES
    if (index < cdisasm_mips_allegrex_pattern_count()) return &allegrex_patterns[index];
#else
    (void)index;
#endif
    return NULL;
}

const cdisasm_mips_encoding_pattern *CDISASM_CALL cdisasm_mips_allegrex_pattern_find(uint32_t word)
{
#if USE_EXTRA_OPCODES
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
#if USE_EXTRA_OPCODES
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
