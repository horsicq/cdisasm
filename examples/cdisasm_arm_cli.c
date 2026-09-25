#include "cdisasm/cdisasm_format.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_mode(const char *text, cdisasm_arm_mode *mode)
{
    if (strcmp(text, "a32") == 0 || strcmp(text, "32") == 0) {
        *mode = CDISASM_ARM_MODE_A32;
        return 1;
    }
    if (strcmp(text, "t32") == 0 || strcmp(text, "thumb") == 0) {
        *mode = CDISASM_ARM_MODE_T32;
        return 1;
    }
    if (strcmp(text, "a64") == 0 || strcmp(text, "64") == 0) {
        *mode = CDISASM_ARM_MODE_A64;
        return 1;
    }
    return 0;
}

static int parse_byte(const char *text, uint8_t *byte)
{
    char *end = NULL;
    unsigned long value;

    errno = 0;
    value = strtoul(text, &end, 16);
    if (errno != 0 || end == text || *end != '\0' || value > 0xff) {
        return 0;
    }
    *byte = (uint8_t)value;
    return 1;
}

int main(int argc, char **argv)
{
    cdisasm_arm_mode mode;
    uint8_t *code;
    size_t code_size;
    size_t offset;
    size_t index;

    if (argc < 3 || !parse_mode(argv[1], &mode)) {
        fprintf(stderr,
                "usage: %s <a32|t32|thumb|a64> <hex-byte> [hex-byte ...]\n",
                argv[0]);
        return 2;
    }
    code_size = (size_t)argc - 2;
    code = (uint8_t *)malloc(code_size);
    if (code == NULL) {
        fputs("allocation failed\n", stderr);
        return 1;
    }
    for (index = 0; index < code_size; ++index) {
        if (!parse_byte(argv[index + 2], &code[index])) {
            fprintf(stderr, "invalid byte: %s\n", argv[index + 2]);
            free(code);
            return 2;
        }
    }

    for (offset = 0; offset < code_size;) {
        cdisasm_arm_instruction instruction;
        char *text;
        size_t text_size;
        uint32_t decoded = cdisasm_arm_decode(
            CDISASM_ARM_CPU_ANY,
            mode,
            code + offset,
            code_size - offset,
            UINT64_C(0x1000) + offset,
            NULL,
            &instruction);

        if (decoded == 0) {
            fprintf(stderr,
                    "decode stopped at byte %zu: %s\n",
                    offset,
                    cdisasm_status_string(
                        (cdisasm_status)instruction.last_error_id));
            free(code);
            return 1;
        }

        text_size = cdisasm_arm_format(
            &instruction, CDISASM_FORMAT_SYNTAX_0, NULL, 0);
        if (text_size == 0) {
            fprintf(stderr, "format failed at byte %zu\n", offset);
            free(code);
            return 1;
        }
        text = (char *)malloc(text_size + 1u);
        if (text == NULL) {
            fputs("allocation failed\n", stderr);
            free(code);
            return 1;
        }
        if (cdisasm_arm_format(
                &instruction,
                CDISASM_FORMAT_SYNTAX_0,
                text,
                text_size + 1u)
            != text_size) {
            fprintf(stderr, "format failed at byte %zu\n", offset);
            free(text);
            free(code);
            return 1;
        }
        printf("%08" PRIx64 "  %08" PRIx32 "  %s\n",
               instruction.address,
               instruction.raw_instruction,
               text);
        free(text);
        offset += decoded;
    }
    free(code);
    return 0;
}
