#include "cdisasm/cdisasm_x86.h"
#include "cdisasm/cdisasm_format.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_mode(const char *text, cdisasm_mode *mode)
{
    if (strcmp(text, "16") == 0) {
        *mode = CDISASM_MODE_16;
        return 1;
    }
    if (strcmp(text, "32") == 0) {
        *mode = CDISASM_MODE_32;
        return 1;
    }
    if (strcmp(text, "64") == 0) {
        *mode = CDISASM_MODE_64;
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

static int parse_decode_flags(
    const char *text,
    cdisasm_x86_decode_flags *flags)
{
    char *end = NULL;
    uintmax_t value;

    errno = 0;
    value = strtoumax(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0'
        || value > (uintmax_t)UINT64_MAX) {
        return 0;
    }
    flags->bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP] =
        (cdisasm_x86_decode_option)value;
    return 1;
}

static void print_usage(const char *program)
{
    fprintf(stderr,
            "usage: %s <16|32|64> [--flags <word0-mask>] "
            "<hex-byte> [hex-byte ...]\n",
            program);
    fputs("       word0-mask is numeric (for example 0, 0x100, or "
          "0xffffffffffffffff)\n",
          stderr);
}

int main(int argc, char **argv)
{
    uint8_t *code = NULL;
    cdisasm_mode mode;
    cdisasm_x86_decode_flags decode_flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    size_t code_size;
    size_t consumed = 0;
    size_t index;
    int first_byte = 2;
    int exit_code = 1;

    if (argc < 3 || !parse_mode(argv[1], &mode)) {
        print_usage(argv[0]);
        return 2;
    }

    if (strcmp(argv[2], "--flags") == 0) {
        if (argc < 4) {
            print_usage(argv[0]);
            return 2;
        }
        if (!parse_decode_flags(argv[3], &decode_flags)) {
            fprintf(stderr, "invalid x86 decode mask: %s\n", argv[3]);
            print_usage(argv[0]);
            return 2;
        }
        first_byte = 4;
    }

    if (argc <= first_byte) {
        print_usage(argv[0]);
        return 2;
    }

    code_size = (size_t)(argc - first_byte);
    code = (uint8_t *)malloc(code_size);
    if (code == NULL) {
        fputs("allocation failed\n", stderr);
        goto cleanup;
    }

    for (index = 0; index < code_size; ++index) {
        if (!parse_byte(argv[index + (size_t)first_byte], &code[index])) {
            fprintf(stderr, "invalid byte: %s\n",
                    argv[index + (size_t)first_byte]);
            exit_code = 2;
            goto cleanup;
        }
    }

    while (consumed < code_size) {
        cdisasm_instruction instruction;
        char formatted[512];
        uint32_t decoded_size = cdisasm_x86_decode(
            CDISASM_CPU_X86,
            mode,
            code + consumed,
            code_size - consumed,
            UINT64_C(0x1000) + consumed,
            &decode_flags,
            &instruction);
        size_t byte_index;
        size_t formatted_size;

        if (decoded_size == 0) {
            fprintf(
                stderr,
                "decode stopped after %zu of %zu bytes: %s\n",
                consumed,
                code_size,
                cdisasm_status_string((cdisasm_status)instruction.last_error_id));
            goto cleanup;
        }

        formatted_size = cdisasm_x86_format(
            &instruction,
            CDISASM_FORMAT_SYNTAX_INTEL,
            formatted,
            sizeof(formatted));
        if (formatted_size == 0 || formatted_size >= sizeof(formatted)) {
            fputs("formatter rejected decoded instruction or output was too long\n",
                  stderr);
            goto cleanup;
        }

        printf("%08" PRIx64 "  ", instruction.address);
        for (byte_index = 0; byte_index < decoded_size; ++byte_index) {
            printf("%02x ", code[consumed + byte_index]);
        }
        for (; byte_index < CDISASM_MAX_INSTRUCTION_SIZE; ++byte_index) {
            fputs("   ", stdout);
        }
        puts(formatted);

        consumed += decoded_size;
    }

    exit_code = 0;

cleanup:
    free(code);
    return exit_code;
}
