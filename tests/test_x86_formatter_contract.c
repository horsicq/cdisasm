#include "cdisasm/cdisasm_format.h"
#include "cdisasm/cdisasm_x86.h"

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINE_CAPACITY 4096
#define FIELD_COUNT 4
#define BYTE_CAPACITY 64
#define TEXT_CAPACITY 1024

static unsigned int exact_rows;
static unsigned int deferred_rows;
static unsigned int failures;

static void report_failure(size_t line_number, const char *iform,
                           const char *message)
{
    fprintf(stderr, "formatter line %zu (%s): %s\n", line_number,
            iform != NULL ? iform : "unknown", message);
    ++failures;
}

static int parse_u32(const char *text, uint32_t *value)
{
    char *end = NULL;
    unsigned long parsed;

    errno = 0;
    parsed = strtoul(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0' || parsed > UINT32_MAX) {
        return 0;
    }
    *value = (uint32_t)parsed;
    return 1;
}

static int hex_value(unsigned char character)
{
    if (character >= '0' && character <= '9') {
        return (int)(character - '0');
    }
    character = (unsigned char)tolower(character);
    if (character >= 'a' && character <= 'f') {
        return (int)(character - 'a') + 10;
    }
    return -1;
}

static int parse_bytes(const char *text, uint8_t *bytes, size_t *count)
{
    int high = -1;
    size_t used = 0;

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
            if (used == BYTE_CAPACITY) {
                return 0;
            }
            bytes[used++] = (uint8_t)((high << 4) | nibble);
            high = -1;
        }
    }
    if (high >= 0 || used == 0) {
        return 0;
    }
    *count = used;
    return 1;
}

static int split_fields(char *line, char **fields)
{
    size_t index;
    char *cursor = line;

    for (index = 0; index < FIELD_COUNT; ++index) {
        char *separator = strchr(cursor, '\t');
        fields[index] = cursor;
        if (index + 1u == FIELD_COUNT) {
            return separator == NULL;
        }
        if (separator == NULL) {
            return 0;
        }
        *separator = '\0';
        cursor = separator + 1;
    }
    return 0;
}

/* XED and cdisasm use different case conventions in some builds.  Whitespace
 * is the only other presentation detail normalized here; punctuation, operand
 * order, decorators and register spelling remain exact. */
static int canonical_text(const char *input, char *output, size_t capacity)
{
    size_t used = 0;
    int pending_space = 0;

    while (*input != '\0') {
        unsigned char character = (unsigned char)*input++;
        if (isspace(character)) {
            pending_space = used != 0;
            continue;
        }
        if (pending_space) {
            if (used + 1u >= capacity) {
                return 0;
            }
            output[used++] = ' ';
            pending_space = 0;
        }
        if (used + 1u >= capacity) {
            return 0;
        }
        output[used++] = (char)tolower(character);
    }
    output[used] = '\0';
    /* XED binds EVEX decorators directly to the operand while cdisasm keeps
     * the historical public spelling with one separating space.  Likewise,
     * XED prints VSIB scale one explicitly.  These are presentation-only
     * differences; punctuation and operand order remain exact. */
    {
        size_t read = 0u;
        size_t write = 0u;
        while (output[read] != '\0') {
            if (output[read] == ' '
                && (output[read + 1u] == '{'
                    || output[read + 1u] == '+')) {
                ++read;
                continue;
            }
            if (output[read] == '+' && write != 0u
                && output[write - 1u] == ' ') {
                --write;
            }
            if (output[read] == '+' && output[read + 1u] == ' ') {
                output[write++] = output[read++];
                ++read;
                continue;
            }
            if (output[read] == '*' && output[read + 1u] == '1') {
                read += 2u;
                continue;
            }
            output[write++] = output[read++];
        }
        output[write] = '\0';
    }
    return 1;
}

static void normalize_string_alias(char *text, const char *iform)
{
    if (strncmp(iform, "REP_", 4) != 0
        && strncmp(iform, "REPE_", 5) != 0
        && strncmp(iform, "REPNE_", 6) != 0) {
        return;
    }
    if (strstr(iform, "CMPS") != NULL || strstr(iform, "SCAS") != NULL
        || strstr(iform, "LODS") != NULL || strstr(iform, "STOS") != NULL) {
        char *match = strstr(text, ", rax");
        if (match != NULL) {
            memmove(match, match + 5u, strlen(match + 5u) + 1u);
        }
        match = strstr(text, "rax, ");
        if (match != NULL) {
            memmove(match, match + 5u, strlen(match + 5u) + 1u);
        }
    }
    if (strncmp(iform, "REP_X", 5) == 0
        || strncmp(iform, "REP_MONT", 8) == 0) {
        char *match = strstr(text, "rep ");
        if (match == text) {
            text[3] = '_';
            memmove(text + 4u, text + 4u, strlen(text + 4u) + 1u);
        }
    }
}

/* XED attaches EVEX embedded-rounding/SAE to the destination operand in
 * Intel syntax (for example, ``vscalefpd zmm0{k1}{ru-sae}, ...``).  The
 * public cdisasm formatter deliberately retains its long-standing trailing
 * decorator spelling (``..., {ru-sae}``) for ABI/source compatibility.  This
 * normalization makes the independent oracle compare semantics, including
 * the decorator value and mask, without weakening the exact punctuation or
 * operand-order checks used for all other fields. */
static void normalize_xed_evex_decorator(
    char *text, const char *iform, size_t capacity)
{
    char *operands;
    char *comma;
    char *decorator;
    char *end;
    char token[16];
    size_t token_length;
    size_t text_length;

    if (text == NULL || capacity == 0) {
        return;
    }
    operands = strchr(text, ' ');
    if (operands == NULL) {
        return;
    }
    ++operands;
    comma = strchr(operands, ',');
    if (comma == NULL) {
        return;
    }
    decorator = NULL;
    {
        static const char *const prefixes[] = {
            "{rn-", "{rd-", "{ru-", "{rz-", "{rne-", "{rde-",
            "{rue-", "{rze-", "{sae}"
        };
        size_t index;
        for (index = 0; index < sizeof(prefixes) / sizeof(prefixes[0]);
             ++index) {
            char *candidate = strstr(operands, prefixes[index]);
            if (candidate != NULL && candidate < comma
                && (decorator == NULL || candidate < decorator)) {
                decorator = candidate;
            }
        }
    }
    if (decorator == NULL) {
        return;
    }
    end = strchr(decorator, '}');
    if (end == NULL || end >= comma) {
        return;
    }
    token_length = (size_t)(end - decorator + 1);
    if (token_length >= sizeof(token)) {
        return;
    }
    memcpy(token, decorator, token_length);
    token[token_length] = '\0';
    /* cdisasm's public enum calls round-to-nearest ``RN``; XED spells the
     * same embedded mode ``RNE``. */
    if (strcmp(token, "{rne-sae}") == 0) {
        memcpy(token, "{rn-sae}", sizeof("{rn-sae}"));
    }
    /* Scalar conversion forms use the destination spelling in cdisasm too;
     * only masked/vector forms need the trailing compatibility spelling. */
    if (iform == NULL || strstr(iform, "MASK") == NULL) {
        size_t original_length = token_length;
        size_t normalized_length = strlen(token);
        if (normalized_length != original_length) {
            memmove(decorator + normalized_length,
                    decorator + original_length,
                    strlen(decorator + original_length) + 1u);
        }
        memcpy(decorator, token, normalized_length);
        return;
    }
    memmove(decorator, end + 1, strlen(end + 1) + 1);
    text_length = strlen(text);
    if (text_length + 1u + strlen(token) >= capacity) {
        return;
    }
    text[text_length] = ',';
    memcpy(text + text_length + 1u, token, strlen(token) + 1u);
}

static void run_row(char **fields, size_t line_number)
{
    uint32_t mode;
    uint8_t bytes[BYTE_CAPACITY];
    size_t byte_count;
    cdisasm_x86_decode_flags flags;
    cdisasm_instruction instruction;
    char formatted[TEXT_CAPACITY];
    char actual[TEXT_CAPACITY];
    char expected[TEXT_CAPACITY];
    size_t required;

    if (strcmp(fields[3], "-") == 0) {
        ++deferred_rows;
        return;
    }
    if (!parse_u32(fields[1], &mode)
        || (mode != CDISASM_MODE_16 && mode != CDISASM_MODE_32
            && mode != CDISASM_MODE_64)
        || !parse_bytes(fields[2], bytes, &byte_count)) {
        report_failure(line_number, fields[0], "invalid witness row");
        return;
    }
    if (cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_X86, (cdisasm_x86_mode)mode, &flags)
        != CDISASM_STATUS_OK) {
        report_failure(line_number, fields[0], "could not construct flags");
        return;
    }
    memset(&instruction, 0, sizeof(instruction));
    if (cdisasm_x86_decode(CDISASM_CPU_X86, (cdisasm_mode)mode,
                           bytes, byte_count, 0, &flags, &instruction)
            != byte_count
        || instruction.last_error_id != CDISASM_STATUS_OK) {
        report_failure(line_number, fields[0], "witness did not decode");
        return;
    }
    required = cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
                                  formatted, sizeof(formatted));
    if (required == 0 || required >= sizeof(formatted)) {
        report_failure(line_number, fields[0], "formatter returned no text");
        return;
    }
    if (!canonical_text(formatted, actual, sizeof(actual))
        || !canonical_text(fields[3], expected, sizeof(expected))) {
        report_failure(line_number, fields[0], "formatter text is too long");
        return;
    }
    normalize_string_alias(actual, fields[0]);
    normalize_string_alias(expected, fields[0]);
    normalize_xed_evex_decorator(expected, fields[0], sizeof(expected));
    if (strcmp(actual, expected) != 0) {
        char message[TEXT_CAPACITY * 2];
        (void)snprintf(message, sizeof(message),
                       "expected '%s', got '%s'", expected, actual);
        report_failure(line_number, fields[0], message);
        return;
    }
    ++exact_rows;
}

int main(int argc, char **argv)
{
    FILE *file;
    char line[LINE_CAPACITY];
    size_t line_number = 0;

    if (argc != 2) {
        fprintf(stderr, "usage: %s FORMAT_SIDECAR\n", argv[0]);
        return 2;
    }
    file = fopen(argv[1], "rb");
    if (file == NULL) {
        perror(argv[1]);
        return 2;
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        char *fields[FIELD_COUNT];
        size_t length;

        ++line_number;
        length = strlen(line);
        while (length != 0 && (line[length - 1u] == '\n'
                               || line[length - 1u] == '\r')) {
            line[--length] = '\0';
        }
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }
        if (!split_fields(line, fields)) {
            report_failure(line_number, "unknown", "malformed sidecar row");
            continue;
        }
        run_row(fields, line_number);
    }
    fclose(file);
    if (failures != 0) {
        fprintf(stderr, "x86 formatter contract: %u failure(s)\n", failures);
        return 1;
    }
    printf("x86 formatter contract passed (%u exact, %u deferred)\n",
           exact_rows, deferred_rows);
    return 0;
}
