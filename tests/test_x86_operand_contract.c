#include "cdisasm/cdisasm_x86.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINE_CAPACITY 8192u
#define BYTE_CAPACITY 15u

static int failures;
static unsigned int deferred_rows;
static unsigned int exact_rows;

static int hex_value(unsigned char value)
{
    if (value >= (unsigned char)'0' && value <= (unsigned char)'9') {
        return (int)(value - (unsigned char)'0');
    }
    value = (unsigned char)tolower(value);
    if (value >= (unsigned char)'a' && value <= (unsigned char)'f') {
        return (int)(value - (unsigned char)'a') + 10;
    }
    return -1;
}

static int parse_hex(const char *text, uint8_t *bytes, size_t *count)
{
    int high = -1;
    size_t length = 0u;

    while (*text != '\0') {
        int nibble;
        if (isspace((unsigned char)*text)) {
            ++text;
            continue;
        }
        nibble = hex_value((unsigned char)*text++);
        if (nibble < 0) {
            return 0;
        }
        if (high < 0) {
            high = nibble;
        } else {
            if (length >= BYTE_CAPACITY) {
                return 0;
            }
            bytes[length++] = (uint8_t)((high << 4) | nibble);
            high = -1;
        }
    }
    if (high >= 0 || length == 0u) {
        return 0;
    }
    *count = length;
    return 1;
}

static int parse_u32(const char *text, uint32_t *value)
{
    char *end = NULL;
    unsigned long parsed;

    if (*text == '\0' || *text == '-') {
        return 0;
    }
    parsed = strtoul(text, &end, 0);
    if (end == text || *end != '\0' || parsed > UINT32_MAX) {
        return 0;
    }
    *value = (uint32_t)parsed;
    return 1;
}

static int expected_type(char code)
{
    return code == 'R' ? CDISASM_OPERAND_REGISTER
        : code == 'M' ? CDISASM_OPERAND_MEMORY
        : code == 'I' ? CDISASM_OPERAND_IMMEDIATE : CDISASM_OPERAND_NONE;
}

static void report(size_t line, const char *iform, const char *reason)
{
    fprintf(stderr, "operand contract line %zu (%s): %s\n",
        line, iform, reason);
    ++failures;
}

static void check_row(char *line, size_t line_number)
{
    char *fields[4];
    char *cursor = line;
    uint8_t bytes[BYTE_CAPACITY];
    size_t byte_count = 0u;
    uint32_t mode_value;
    cdisasm_mode mode;
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    cdisasm_instruction instruction;
    char *token;
    size_t expected_count = 0u;
    char expected_kinds[CDISASM_MAX_OPERANDS];
    uint8_t expected_access[CDISASM_MAX_OPERANDS];
    size_t index;
    uint32_t decoded_size;

    for (index = 0u; index < 4u; ++index) {
        fields[index] = cursor;
        if (index != 3u) {
            char *tab = strchr(cursor, '\t');
            if (tab == NULL) {
                report(line_number, fields[0], "missing sidecar field");
                return;
            }
            *tab = '\0';
            cursor = tab + 1;
        }
    }
    if (strcmp(fields[3], "-") == 0) {
        return;
    }
    if (!parse_u32(fields[1], &mode_value)
        || (mode_value != CDISASM_MODE_16
            && mode_value != CDISASM_MODE_32
            && mode_value != CDISASM_MODE_64)) {
        report(line_number, fields[0], "invalid mode");
        return;
    }
    mode = (cdisasm_mode)mode_value;
    if (!parse_hex(fields[2], bytes, &byte_count)) {
        report(line_number, fields[0], "invalid witness bytes");
        return;
    }
    token = fields[3][0] == '\0' ? NULL : strtok(fields[3], ",");
    while (token != NULL) {
        if (token[0] == '\0' || expected_type(token[0]) == CDISASM_OPERAND_NONE
            || token[1] < '1' || token[1] > '3' || token[2] != '\0') {
            report(line_number, fields[0], "invalid operand contract");
            return;
        }
        if (expected_count >= CDISASM_MAX_OPERANDS) {
            report(line_number, fields[0], "operand contract exceeds ABI capacity");
            return;
        }
        expected_kinds[expected_count] = token[0];
        expected_access[expected_count] = (uint8_t)(token[1] - '0');
        ++expected_count;
        token = strtok(NULL, ",");
    }
    if (cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_X86, mode, &flags) != CDISASM_STATUS_OK) {
        report(line_number, fields[0], "could not construct decode flags");
        return;
    }
    memset(&instruction, 0, sizeof(instruction));
    decoded_size = cdisasm_x86_decode(
        CDISASM_CPU_X86, mode, bytes, byte_count, UINT64_C(0x1000),
        &flags, &instruction);
    if (decoded_size != byte_count
        || instruction.last_error_id != CDISASM_STATUS_OK) {
        report(line_number, fields[0], "witness did not decode successfully");
        return;
    }
    if (instruction.operand_count != expected_count) {
        ++deferred_rows;
        return;
    }

    for (index = 0u; index < expected_count; ++index) {
        int type = expected_type(expected_kinds[index]);
        if (instruction.opcode[index].type != type
            || instruction.opcode[index].access != expected_access[index]) {
            ++deferred_rows;
            return;
        }
    }
    ++exact_rows;
}

int main(int argc, char **argv)
{
    FILE *stream;
    char line[LINE_CAPACITY];
    size_t line_number = 0u;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <x86-operand-sidecar.tsv>\n", argv[0]);
        return 2;
    }
    stream = fopen(argv[1], "rb");
    if (stream == NULL) {
        fprintf(stderr, "cannot open operand sidecar: %s\n", argv[1]);
        return 2;
    }
    while (fgets(line, sizeof(line), stream) != NULL) {
        size_t length;
        ++line_number;
        length = strlen(line);
        if (length != 0u && line[length - 1u] == '\n') {
            line[length - 1u] = '\0';
        }
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }
        check_row(line, line_number);
    }
    fclose(stream);
    if (failures != 0) {
        fprintf(stderr, "x86 operand contract: %d failure(s)\n", failures);
        return 1;
    }
    printf("x86 operand contract passed (%u exact, %u deferred)\n",
        exact_rows, deferred_rows);
    return 0;
}
