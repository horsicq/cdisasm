#include "cdisasm/cdisasm_x86.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CORPUS_LINE_CAPACITY 4096
#define CORPUS_FIELD_COUNT 9
#define CORPUS_BYTE_CAPACITY 64
#define CORPUS_TEXT_CAPACITY 512

static int failures;

static uint32_t expected_legacy_status_flags(
    const cdisasm_instruction *instruction)
{
    cdisasm_x86_name_id name_id = instruction->name_id;

    if (name_id == CDISASM_X86_NAME_CMPSD
        && instruction->operand_count == 2
        && instruction->opcode[0].type == CDISASM_OPERAND_MEMORY
        && instruction->opcode[1].type == CDISASM_OPERAND_MEMORY) {
        return CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
    }
    switch (name_id) {
        case CDISASM_X86_NAME_AAA:
        case CDISASM_X86_NAME_AAS:
        case CDISASM_X86_NAME_CMC:
        case CDISASM_X86_NAME_DAA:
        case CDISASM_X86_NAME_DAS:
            return CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
                | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
        case CDISASM_X86_NAME_INTO:
        case CDISASM_X86_NAME_LAHF:
        case CDISASM_X86_NAME_LOOPE:
        case CDISASM_X86_NAME_LOOPNE:
        case CDISASM_X86_NAME_PUSHF:
        case CDISASM_X86_NAME_PUSHFD:
        case CDISASM_X86_NAME_PUSHFQ:
            return CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS;
        case CDISASM_X86_NAME_AAD:
        case CDISASM_X86_NAME_AAM:
        case CDISASM_X86_NAME_ARPL:
        case CDISASM_X86_NAME_BSF:
        case CDISASM_X86_NAME_BSR:
        case CDISASM_X86_NAME_BT:
        case CDISASM_X86_NAME_BTC:
        case CDISASM_X86_NAME_BTR:
        case CDISASM_X86_NAME_BTS:
        case CDISASM_X86_NAME_CLC:
        case CDISASM_X86_NAME_CLD:
        case CDISASM_X86_NAME_CLI:
        case CDISASM_X86_NAME_DEC:
        case CDISASM_X86_NAME_INC:
        case CDISASM_X86_NAME_CMPSB:
        case CDISASM_X86_NAME_CMPSQ:
        case CDISASM_X86_NAME_CMPSW:
        case CDISASM_X86_NAME_SCASB:
        case CDISASM_X86_NAME_SCASD:
        case CDISASM_X86_NAME_SCASQ:
        case CDISASM_X86_NAME_SCASW:
        case CDISASM_X86_NAME_SAHF:
        case CDISASM_X86_NAME_POPF:
        case CDISASM_X86_NAME_POPFD:
        case CDISASM_X86_NAME_POPFQ:
        case CDISASM_X86_NAME_STC:
        case CDISASM_X86_NAME_STD:
        case CDISASM_X86_NAME_STI:
            return CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
        default:
            return 0;
    }
}

static void report_failure(size_t line_number, const char *case_name,
                           const char *message)
{
    fprintf(stderr, "corpus line %zu (%s): %s\n",
            line_number,
            case_name != NULL && case_name[0] != '\0' ? case_name : "unknown",
            message);
    ++failures;
}

static int parse_u32(const char *text, uint32_t *value)
{
    char *end = NULL;
    unsigned long parsed;

    if (text == NULL || text[0] == '\0' || text[0] == '-') {
        return 0;
    }
    errno = 0;
    parsed = strtoul(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0' || parsed > UINT32_MAX) {
        return 0;
    }
    *value = (uint32_t)parsed;
    return 1;
}

static int parse_u64(const char *text, uint64_t *value)
{
    char *end = NULL;
    unsigned long long parsed;

    if (text == NULL || text[0] == '\0' || text[0] == '-') {
        return 0;
    }
    errno = 0;
    parsed = strtoull(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0') {
        return 0;
    }
    *value = (uint64_t)parsed;
    return 1;
}

static int parse_status(const char *text, cdisasm_status *status)
{
    static const struct status_name {
        const char *name;
        cdisasm_status value;
    } names[] = {
        {"OK", CDISASM_STATUS_OK},
        {"INVALID_ARGUMENT", CDISASM_STATUS_INVALID_ARGUMENT},
        {"END_OF_INPUT", CDISASM_STATUS_END_OF_INPUT},
        {"TRUNCATED", CDISASM_STATUS_TRUNCATED},
        {"INVALID_INSTRUCTION", CDISASM_STATUS_INVALID_INSTRUCTION},
        {"UNSUPPORTED_INSTRUCTION", CDISASM_STATUS_UNSUPPORTED_INSTRUCTION},
        {"INTERNAL_ERROR", CDISASM_STATUS_INTERNAL_ERROR},
        {"EXTRA_OK", USE_EXTRA_OPCODES
            ? CDISASM_STATUS_OK
            : CDISASM_STATUS_UNSUPPORTED_INSTRUCTION},
        {"EXTRA_INVALID", CDISASM_STATUS_INVALID_INSTRUCTION},
        {"EXTRA_TRUNCATED", USE_EXTRA_OPCODES
            ? CDISASM_STATUS_TRUNCATED
            : CDISASM_STATUS_UNSUPPORTED_INSTRUCTION},
        {"EXTRA_PROFILE", USE_EXTRA_OPCODES
            ? CDISASM_STATUS_INVALID_INSTRUCTION
            : CDISASM_STATUS_UNSUPPORTED_INSTRUCTION},
        /* CPU-feature gate witnesses are intentionally unsupported by the
         * selected processor profile, but their bytes are allocated and
         * already proven by a positive corpus row.  Keep them in the runtime
         * corpus while excluding them from missing-encoding coverage. */
        {"COVERAGE_PROFILE", CDISASM_STATUS_UNSUPPORTED_INSTRUCTION}
    };
    size_t index;

    for (index = 0; index < sizeof(names) / sizeof(names[0]); ++index) {
        if (strcmp(text, names[index].name) == 0) {
            *status = names[index].value;
            return 1;
        }
    }
    return 0;
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

static int parse_hex_bytes(const char *text, uint8_t *bytes, size_t *byte_count)
{
    int high_nibble = -1;
    size_t count = 0;

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
        if (high_nibble < 0) {
            high_nibble = nibble;
        } else {
            if (count == CORPUS_BYTE_CAPACITY) {
                return 0;
            }
            bytes[count++] = (uint8_t)((high_nibble << 4) | nibble);
            high_nibble = -1;
        }
    }
    if (high_nibble >= 0 || count == 0) {
        return 0;
    }
    *byte_count = count;
    return 1;
}

static int split_fields(char *line, char **fields)
{
    size_t index;
    char *cursor = line;

    for (index = 0; index < CORPUS_FIELD_COUNT; ++index) {
        char *separator;

        fields[index] = cursor;
        separator = strchr(cursor, '\t');
        if (index + 1u == CORPUS_FIELD_COUNT) {
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

static int failure_result_is_zeroed(const cdisasm_instruction *instruction,
                                    cdisasm_status status)
{
    cdisasm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static void run_case(char **fields, size_t line_number)
{
    const char *case_name = fields[0];
    uint8_t bytes[CORPUS_BYTE_CAPACITY];
    size_t byte_count = 0;
    uint32_t cpu_id;
    uint32_t mode;
    uint64_t address;
    cdisasm_status expected_status;
    uint32_t expected_size;
    int has_success_oracle;
    int is_extra_ok;
    cdisasm_instruction first;
    cdisasm_instruction second;
    cdisasm_x86_decode_flags selected_flags;
    uint32_t first_size;
    uint32_t second_size;

    if (case_name[0] == '\0') {
        report_failure(line_number, case_name, "empty case name");
        return;
    }
    if (!parse_u32(fields[1], &cpu_id)
        || CDISASM_CPU_GROUP_OF(cpu_id) != CDISASM_CPU_GROUP_X86
        || (cpu_id != CDISASM_CPU_X86
            && (cpu_id < CDISASM_CPU_FIRST
                || cpu_id > CDISASM_CPU_LAST))) {
        report_failure(line_number, case_name, "invalid CPU ID");
        return;
    }
    if (!parse_u32(fields[2], &mode)
        || (mode != CDISASM_MODE_16
            && mode != CDISASM_MODE_32
            && mode != CDISASM_MODE_64)) {
        report_failure(line_number, case_name, "invalid mode");
        return;
    }
    if (!parse_u64(fields[3], &address)) {
        report_failure(line_number, case_name, "invalid address");
        return;
    }
    if (!parse_status(fields[4], &expected_status)) {
        report_failure(line_number, case_name, "invalid status name");
        return;
    }
    is_extra_ok = strcmp(fields[4], "EXTRA_OK") == 0;
    has_success_oracle = expected_status == CDISASM_STATUS_OK || is_extra_ok;
    if (!parse_u32(fields[5], &expected_size)
        || expected_size > CDISASM_MAX_INSTRUCTION_SIZE
        || has_success_oracle != (expected_size != 0)) {
        report_failure(line_number, case_name, "invalid expected size/status");
        return;
    }
    if ((has_success_oracle
         && (strcmp(fields[6], "-") == 0 || strcmp(fields[7], "-") == 0))
        || (!has_success_oracle
            && (strcmp(fields[6], "-") != 0
                || strcmp(fields[7], "-") != 0))) {
        report_failure(line_number, case_name,
                       "invalid Intel/AT&T expected text fields");
        return;
    }
    if (!parse_hex_bytes(fields[8], bytes, &byte_count)) {
        report_failure(line_number, case_name, "invalid hexadecimal byte list");
        return;
    }
#if !USE_EXTRA_OPCODES
    /* EXTRA_OK retains its ON-build formatting oracle in the checked-in TSV,
     * but an OFF build must return a zeroed unsupported result. */
    if (is_extra_ok) {
        expected_size = 0;
    }
#endif

    if (cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_X86, (cdisasm_x86_mode)mode, &selected_flags)
        != CDISASM_STATUS_OK) {
        report_failure(line_number, case_name,
                       "could not construct full-family decode flags");
        return;
    }

    memset(&first, 0xa5, sizeof(first));
    first_size = cdisasm_x86_decode(
        (cdisasm_cpu_id)cpu_id,
        (cdisasm_mode)mode,
        bytes,
        byte_count,
        address,
        &selected_flags,
        &first);
    memset(&second, 0x5a, sizeof(second));
    second_size = cdisasm_x86_decode(
        (cdisasm_cpu_id)cpu_id,
        (cdisasm_mode)mode,
        bytes,
        byte_count,
        address,
        &selected_flags,
        &second);

    if (first_size != expected_size
        || second_size != expected_size
        || first.last_error_id != expected_status
        || second.last_error_id != expected_status) {
        char message[256];
        (void)snprintf(
            message,
            sizeof(message),
            "got size/status %u/%s, expected %u/%s",
            (unsigned int)first_size,
            cdisasm_status_string((cdisasm_status)first.last_error_id),
            (unsigned int)expected_size,
            cdisasm_status_string(expected_status));
        report_failure(line_number, case_name, message);
        return;
    }
    if (memcmp(&first, &second, sizeof(first)) != 0) {
        report_failure(line_number, case_name, "decode result is not deterministic");
        return;
    }

    if (expected_status != CDISASM_STATUS_OK) {
#if USE_DISASM_FORMAT
        char formatted[16] = "not empty";
#endif

        if (!failure_result_is_zeroed(&first, expected_status)) {
            report_failure(line_number, case_name,
                           "failure result contains nonzero metadata");
        }
#if USE_DISASM_FORMAT
        if (cdisasm_x86_format(
                &first,
                CDISASM_FORMAT_SYNTAX_0,
                formatted,
                sizeof(formatted)) != 0
            || formatted[0] != '\0') {
            report_failure(line_number, case_name,
                           "formatter accepted a failed decode");
        }
#endif
        return;
    }

    if (first.opcode_size != expected_size || expected_size > byte_count) {
        report_failure(line_number, case_name, "inconsistent successful size");
        return;
    }
    {
        const uint32_t status_mask =
            CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS
            | CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
        const uint32_t expected_flags =
            expected_legacy_status_flags(&first);

        if (expected_flags != 0
            && (first.opcode_flags & CDISASM_PREFIX_APX_NF) == 0
            && (first.opcode_flags & status_mask) != expected_flags) {
            report_failure(line_number, case_name,
                           "incorrect architectural status-flag metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_BT
            && (first.operand_count != 2
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_READ
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ)) {
            report_failure(line_number, case_name,
                           "incorrect BT operand-access metadata");
            return;
        }
        if (strncmp(case_name, "mov_moffs_", 10) == 0
            && (first.name_id != CDISASM_X86_NAME_MOV
                || first.operand_count != 2
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_flags & status_mask) != 0
                || (first.opcode[0].size == 4
                    && !cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_I386))
                || (first.opcode[0].size == 1
                    && cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_I386)))) {
            report_failure(line_number, case_name,
                           "incorrect MOV moffs family/access/flag metadata");
            return;
        }
        if (strncmp(case_name, "adc_lock_", 9) == 0
            && (first.name_id != CDISASM_X86_NAME_ADC
                || first.operand_count != 2
                || first.opcode[0].access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_flags & (CDISASM_PREFIX_LOCK
                    | CDISASM_PREFIX_EFFECTIVE_LOCK))
                    != (CDISASM_PREFIX_LOCK
                        | CDISASM_PREFIX_EFFECTIVE_LOCK))) {
            report_failure(line_number, case_name,
                           "incorrect locked ADC family/access/flag metadata");
            return;
        }
        if (strncmp(case_name, "add_lock_", 9) == 0
            && (first.name_id != CDISASM_X86_NAME_ADD
                || first.operand_count != 2
                || first.opcode[0].access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_flags & (CDISASM_PREFIX_LOCK
                    | CDISASM_PREFIX_EFFECTIVE_LOCK))
                    != (CDISASM_PREFIX_LOCK
                        | CDISASM_PREFIX_EFFECTIVE_LOCK))) {
            report_failure(line_number, case_name,
                           "incorrect locked ADD family/access/flag metadata");
            return;
        }
        if (strncmp(case_name, "and_lock_", 9) == 0
            && (first.name_id != CDISASM_X86_NAME_AND
                || first.operand_count != 2
                || first.opcode[0].access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_flags & (CDISASM_PREFIX_LOCK
                    | CDISASM_PREFIX_EFFECTIVE_LOCK))
                    != (CDISASM_PREFIX_LOCK
                        | CDISASM_PREFIX_EFFECTIVE_LOCK))) {
            report_failure(line_number, case_name,
                           "incorrect locked AND family/access/flag metadata");
            return;
        }
        if (strncmp(case_name, "or_lock_", 8) == 0
            && (first.name_id != CDISASM_X86_NAME_OR
                || first.operand_count != 2
                || first.opcode[0].access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_flags & (CDISASM_PREFIX_LOCK
                    | CDISASM_PREFIX_EFFECTIVE_LOCK))
                    != (CDISASM_PREFIX_LOCK
                        | CDISASM_PREFIX_EFFECTIVE_LOCK))) {
            report_failure(line_number, case_name,
                           "incorrect locked OR family/access/flag metadata");
            return;
        }
        if (strncmp(case_name, "xor_lock_", 9) == 0
            && (first.name_id != CDISASM_X86_NAME_XOR
                || first.operand_count != 2
                || first.opcode[0].access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_flags & (CDISASM_PREFIX_LOCK
                    | CDISASM_PREFIX_EFFECTIVE_LOCK))
                    != (CDISASM_PREFIX_LOCK
                        | CDISASM_PREFIX_EFFECTIVE_LOCK))) {
            report_failure(line_number, case_name,
                           "incorrect locked XOR family/access/flag metadata");
            return;
        }
        if (strncmp(case_name, "sbb_lock_", 9) == 0
            && (first.name_id != CDISASM_X86_NAME_SBB
                || first.operand_count != 2
                || first.opcode[0].access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_flags & (CDISASM_PREFIX_LOCK
                    | CDISASM_PREFIX_EFFECTIVE_LOCK))
                    != (CDISASM_PREFIX_LOCK
                        | CDISASM_PREFIX_EFFECTIVE_LOCK))) {
            report_failure(line_number, case_name,
                           "incorrect locked SBB family/access/flag metadata");
            return;
        }
        if (strncmp(case_name, "sub_lock_", 9) == 0
            && (first.name_id != CDISASM_X86_NAME_SUB
                || first.operand_count != 2
                || first.opcode[0].access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_flags & (CDISASM_PREFIX_LOCK
                    | CDISASM_PREFIX_EFFECTIVE_LOCK))
                    != (CDISASM_PREFIX_LOCK
                        | CDISASM_PREFIX_EFFECTIVE_LOCK))) {
            report_failure(line_number, case_name,
                           "incorrect locked SUB family/access/flag metadata");
            return;
        }
        if ((strcmp(case_name, "mov_eax_cs_exact") == 0
                || strcmp(case_name, "mov_ds_eax_exact") == 0
                || strcmp(case_name, "mov_memory16_cs_exact") == 0
                || strcmp(case_name, "mov_ds_memory16_exact") == 0)
            && (first.name_id != CDISASM_X86_NAME_MOV
                || first.operand_count != 2
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_flags & status_mask) != 0)) {
            report_failure(line_number, case_name,
                           "incorrect segment MOV family/access/flag metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_BTC
                || first.name_id == CDISASM_X86_NAME_BTR
                || first.name_id == CDISASM_X86_NAME_BTS)
            && (first.operand_count != 2
                || first.opcode[0].access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ)) {
            report_failure(line_number, case_name,
                           "incorrect modifying bit-test operand access");
            return;
        }
        if ((strncmp(case_name, "btc_lock_", 9) == 0
                || strncmp(case_name, "btr_lock_", 9) == 0
                || strncmp(case_name, "bts_lock_", 9) == 0)
            && (first.opcode_flags & (CDISASM_PREFIX_LOCK
                    | CDISASM_PREFIX_EFFECTIVE_LOCK))
                != (CDISASM_PREFIX_LOCK
                    | CDISASM_PREFIX_EFFECTIVE_LOCK)) {
            report_failure(line_number, case_name,
                           "incorrect locked bit-test family flags");
            return;
        }
        if ((strncmp(case_name, "inc_lock_", 9) == 0
                || strncmp(case_name, "dec_lock_", 9) == 0)
            && (first.operand_count != 1
                || first.opcode[0].access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE
                || (first.opcode_flags & (CDISASM_PREFIX_LOCK
                    | CDISASM_PREFIX_EFFECTIVE_LOCK))
                    != (CDISASM_PREFIX_LOCK
                        | CDISASM_PREFIX_EFFECTIVE_LOCK))) {
            report_failure(line_number, case_name,
                           "incorrect locked INC/DEC family/access flags");
            return;
        }
        if ((strncmp(case_name, "neg_lock_", 9) == 0
                || strncmp(case_name, "not_lock_", 9) == 0)
            && (first.operand_count != 1
                || first.opcode[0].access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE
                || (first.opcode_flags & (CDISASM_PREFIX_LOCK
                    | CDISASM_PREFIX_EFFECTIVE_LOCK))
                    != (CDISASM_PREFIX_LOCK
                        | CDISASM_PREFIX_EFFECTIVE_LOCK))) {
            report_failure(line_number, case_name,
                           "incorrect locked NEG/NOT family/access flags");
            return;
        }
        if ((strncmp(case_name, "xadd_lock_", 10) == 0
                || strncmp(case_name, "cmpxchg_lock_", 13) == 0)
            && (first.opcode_flags & (CDISASM_PREFIX_LOCK
                    | CDISASM_PREFIX_EFFECTIVE_LOCK))
                != (CDISASM_PREFIX_LOCK
                    | CDISASM_PREFIX_EFFECTIVE_LOCK)) {
            report_failure(line_number, case_name,
                           "incorrect XADD/CMPXCHG effective-lock flags");
            return;
        }
        if ((strncmp(case_name, "cmpxchg8b_lock_", 15) == 0
                || strncmp(case_name, "cmpxchg16b_lock_", 16) == 0)
            && (first.operand_count != 1
                || first.opcode[0].access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE
                || (first.opcode_flags & (CDISASM_PREFIX_LOCK
                    | CDISASM_PREFIX_EFFECTIVE_LOCK))
                    != (CDISASM_PREFIX_LOCK
                        | CDISASM_PREFIX_EFFECTIVE_LOCK))) {
            report_failure(line_number, case_name,
                           "incorrect CMPXCHG8B/16B family/access flags");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_BSWAP
            && (first.operand_count != 1
                || first.opcode[0].access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE
                || (first.opcode_flags & status_mask) != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_I486)
                || (mode == 64
                    && !cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_AMD64)))) {
            report_failure(line_number, case_name,
                           "incorrect BSWAP family/access/flag metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_CMPSB
                || (first.name_id == CDISASM_X86_NAME_CMPSD
                    && first.operand_count == 2
                    && first.opcode[0].type == CDISASM_OPERAND_MEMORY
                    && first.opcode[1].type == CDISASM_OPERAND_MEMORY)
                || first.name_id == CDISASM_X86_NAME_CMPSQ
                || first.name_id == CDISASM_X86_NAME_CMPSW)
            && (first.operand_count != 2
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_READ
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || ((first.name_id == CDISASM_X86_NAME_CMPSB
                        || first.name_id == CDISASM_X86_NAME_CMPSW)
                    && !cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_I86)))) {
            report_failure(line_number, case_name,
                           "incorrect CMPS family/access metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_LODSB
                || first.name_id == CDISASM_X86_NAME_LODSD
                || first.name_id == CDISASM_X86_NAME_LODSQ
                || first.name_id == CDISASM_X86_NAME_LODSW)
            && (first.operand_count != 2
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_flags & status_mask) != 0
                || ((first.name_id == CDISASM_X86_NAME_LODSB
                        || first.name_id == CDISASM_X86_NAME_LODSW)
                    && !cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_I86)))) {
            report_failure(line_number, case_name,
                           "incorrect LODS family/access/flag metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_STOSB
                || first.name_id == CDISASM_X86_NAME_STOSD
                || first.name_id == CDISASM_X86_NAME_STOSQ
                || first.name_id == CDISASM_X86_NAME_STOSW)
            && (first.operand_count != 2
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_flags & status_mask) != 0
                || ((first.name_id == CDISASM_X86_NAME_STOSB
                        || first.name_id == CDISASM_X86_NAME_STOSW)
                    && !cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_I86)))) {
            report_failure(line_number, case_name,
                           "incorrect STOS family/access/flag metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_SCASB
                || first.name_id == CDISASM_X86_NAME_SCASD
                || first.name_id == CDISASM_X86_NAME_SCASQ
                || first.name_id == CDISASM_X86_NAME_SCASW)
            && (first.operand_count != 2
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_READ
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || ((first.name_id == CDISASM_X86_NAME_SCASB
                        || first.name_id == CDISASM_X86_NAME_SCASW)
                    && !cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_I86)))) {
            report_failure(line_number, case_name,
                           "incorrect SCAS family/access/flag metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_MOVSB
                || (first.name_id == CDISASM_X86_NAME_MOVSD
                    && first.operand_count == 2
                    && first.opcode[0].type == CDISASM_OPERAND_MEMORY
                    && first.opcode[1].type == CDISASM_OPERAND_MEMORY)
                || first.name_id == CDISASM_X86_NAME_MOVSQ
                || first.name_id == CDISASM_X86_NAME_MOVSW)
            && (first.operand_count != 2
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_flags & status_mask) != 0
                || ((first.name_id == CDISASM_X86_NAME_MOVSB
                        || first.name_id == CDISASM_X86_NAME_MOVSW)
                    && !cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_I86)))) {
            report_failure(line_number, case_name,
                           "incorrect MOVS family/access/flag metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_INSB
                || first.name_id == CDISASM_X86_NAME_INSD
                || first.name_id == CDISASM_X86_NAME_INSW)
            && (first.operand_count != 2
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_flags & status_mask) != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_I186))) {
            report_failure(line_number, case_name,
                           "incorrect INS family/access/flag metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_OUTSB
                || first.name_id == CDISASM_X86_NAME_OUTSD
                || first.name_id == CDISASM_X86_NAME_OUTSW)
            && (first.operand_count != 2
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_READ
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_flags & status_mask) != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_I186))) {
            report_failure(line_number, case_name,
                           "incorrect OUTS family/access/flag metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_ENTER
            && (first.operand_count != 2
                || first.opcode[0].type != CDISASM_OPERAND_IMMEDIATE
                || first.opcode[1].type != CDISASM_OPERAND_IMMEDIATE
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_READ
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_flags & status_mask) != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_I186))) {
            report_failure(line_number, case_name,
                           "incorrect ENTER family/access/flag metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_LEAVE
            && (first.operand_count != 0
                || (first.opcode_flags & status_mask) != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_I186))) {
            report_failure(line_number, case_name,
                           "incorrect LEAVE family/access/flag metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_LAHF
                || first.name_id == CDISASM_X86_NAME_SAHF)
            && (first.operand_count != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_LAHF))) {
            report_failure(line_number, case_name,
                           "incorrect LAHF/SAHF family metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_PUSHF
                || first.name_id == CDISASM_X86_NAME_POPF)
            && (first.operand_count != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_I86))) {
            report_failure(line_number, case_name,
                           "incorrect PUSHF/POPF baseline family metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_PUSHFD
                || first.name_id == CDISASM_X86_NAME_POPFD)
            && (first.operand_count != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_I386))) {
            report_failure(line_number, case_name,
                           "incorrect PUSHFD/POPFD family metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_PUSHFQ
                || first.name_id == CDISASM_X86_NAME_POPFQ)
            && (first.operand_count != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AMD64))) {
            report_failure(line_number, case_name,
                           "incorrect PUSHFQ/POPFQ family metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_PUSHA
                || first.name_id == CDISASM_X86_NAME_POPA)
            && (first.operand_count != 0
                || (first.opcode_flags & status_mask) != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_I186))) {
            report_failure(line_number, case_name,
                           "incorrect PUSHA/POPA family/flag metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_PUSHAD
                || first.name_id == CDISASM_X86_NAME_POPAD)
            && (first.operand_count != 0
                || (first.opcode_flags & status_mask) != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_I386))) {
            report_failure(line_number, case_name,
                           "incorrect PUSHAD/POPAD family/flag metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_JCXZ
                || first.name_id == CDISASM_X86_NAME_JECXZ
                || first.name_id == CDISASM_X86_NAME_JRCXZ)
            && (first.operand_count != 1
                || first.opcode[0].type != CDISASM_OPERAND_IMMEDIATE
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_groups & CDISASM_GROUP_CONDITIONAL) == 0
                || (first.opcode_groups & CDISASM_GROUP_JUMP) == 0
                || (first.opcode_flags & status_mask) != 0
                || ((first.name_id == CDISASM_X86_NAME_JCXZ
                        || first.name_id == CDISASM_X86_NAME_JECXZ)
                    && !cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_I386))
                || (first.name_id == CDISASM_X86_NAME_JRCXZ
                    && !cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_AMD64)))) {
            report_failure(line_number, case_name,
                           "incorrect JCXZ-family branch/flag metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_LOOP
                || first.name_id == CDISASM_X86_NAME_LOOPE
                || first.name_id == CDISASM_X86_NAME_LOOPNE)
            && (first.operand_count != 1
                || first.opcode[0].type != CDISASM_OPERAND_IMMEDIATE
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_groups & CDISASM_GROUP_CONDITIONAL) == 0
                || (first.opcode_groups & CDISASM_GROUP_JUMP) == 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_I86)
                || (first.name_id == CDISASM_X86_NAME_LOOP
                    && (first.opcode_flags & status_mask) != 0))) {
            report_failure(line_number, case_name,
                           "incorrect LOOP-family branch/flag metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_IN
            && (first.operand_count != 2
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_flags & status_mask) != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_I86))) {
            report_failure(line_number, case_name,
                           "incorrect IN family/access/flag metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_OUT
            && (first.operand_count != 2
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_READ
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_flags & status_mask) != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_I86))) {
            report_failure(line_number, case_name,
                           "incorrect OUT family/access/flag metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_XCHG
            && (first.operand_count != 2
                || first.opcode[0].access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE
                || first.opcode[1].access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE
                || (first.opcode_flags & status_mask) != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_I86))) {
            report_failure(line_number, case_name,
                           "incorrect XCHG family/access/flag metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_HLT
            && (first.operand_count != 0
                || (first.opcode_groups & CDISASM_GROUP_PRIVILEGED) == 0
                || (first.opcode_flags & status_mask) != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_I86))) {
            report_failure(line_number, case_name,
                           "incorrect HLT family/privilege/flag metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_CLTS
            && (first.operand_count != 0
                || (first.opcode_groups & CDISASM_GROUP_PRIVILEGED) == 0
                || (first.opcode_flags & status_mask) != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_I286REAL))) {
            report_failure(line_number, case_name,
                           "incorrect CLTS family/privilege/flag metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_CLI
                || first.name_id == CDISASM_X86_NAME_STI)
            && (first.operand_count != 0
                || (first.opcode_groups & CDISASM_GROUP_PRIVILEGED) == 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_I86))) {
            report_failure(line_number, case_name,
                           "incorrect CLI/STI family/privilege metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_INVD
            && (first.operand_count != 0
                || (first.opcode_groups & CDISASM_GROUP_PRIVILEGED) == 0
                || (first.opcode_flags & status_mask) != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_I486REAL))) {
            report_failure(line_number, case_name,
                           "incorrect INVD family/privilege/flag metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_EMMS
            && (first.operand_count != 0
                || (first.opcode_flags & status_mask) != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_PENTIUMMMX))) {
            report_failure(line_number, case_name,
                           "incorrect EMMS family/flag metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_LFENCE
            && (first.operand_count != 0
                || (first.opcode_flags & status_mask) != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_SSE2))) {
            report_failure(line_number, case_name,
                           "incorrect LFENCE family/flag metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_SFENCE
            && (first.operand_count != 0
                || (first.opcode_flags & status_mask) != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_SSE))) {
            report_failure(line_number, case_name,
                           "incorrect SFENCE family/flag metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_FNOP
            && (first.operand_count != 0
                || (first.opcode_flags & status_mask) != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87))) {
            report_failure(line_number, case_name,
                           "incorrect FNOP family/flag metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_FABS
                || first.name_id == CDISASM_X86_NAME_FCHS)
            && (first.operand_count != 0
                || (first.opcode_flags & status_mask) != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87))) {
            report_failure(line_number, case_name,
                           "incorrect FABS/FCHS family/flag metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_FLD1
                || first.name_id == CDISASM_X86_NAME_FLDL2T
                || first.name_id == CDISASM_X86_NAME_FLDL2E
                || first.name_id == CDISASM_X86_NAME_FLDPI
                || first.name_id == CDISASM_X86_NAME_FLDLG2
                || first.name_id == CDISASM_X86_NAME_FLDLN2
                || first.name_id == CDISASM_X86_NAME_FLDZ)
            && (first.operand_count != 0
                || (first.opcode_flags & status_mask) != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87))) {
            report_failure(line_number, case_name,
                           "incorrect x87 constant-load family/flag metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_F2XM1
                || first.name_id == CDISASM_X86_NAME_FSQRT
                || first.name_id == CDISASM_X86_NAME_FSINCOS
                || first.name_id == CDISASM_X86_NAME_FSIN
                || first.name_id == CDISASM_X86_NAME_FCOS)
            && (first.operand_count != 0
                || (first.opcode_flags & status_mask) != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87))) {
            report_failure(line_number, case_name,
                           "incorrect x87 unary family/flag metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_FPTAN
                || first.name_id == CDISASM_X86_NAME_FPATAN
                || first.name_id == CDISASM_X86_NAME_FXTRACT
                || first.name_id == CDISASM_X86_NAME_FPREM
                || first.name_id == CDISASM_X86_NAME_FRNDINT)
            && (first.operand_count != 0
                || (first.opcode_flags & status_mask) != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87))) {
            report_failure(line_number, case_name,
                           "incorrect x87 stack-op family/flag metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_FTST
                || first.name_id == CDISASM_X86_NAME_FXAM
                || first.name_id == CDISASM_X86_NAME_FYL2X
                || first.name_id == CDISASM_X86_NAME_FYL2XP1
                || first.name_id == CDISASM_X86_NAME_FSCALE)
            && (first.operand_count != 0
                || (first.opcode_flags & status_mask) != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87))) {
            report_failure(line_number, case_name,
                           "incorrect x87 implicit-op family/flag metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_FDECSTP
                || first.name_id == CDISASM_X86_NAME_FINCSTP)
            && (first.operand_count != 0
                || (first.opcode_flags & status_mask) != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87))) {
            report_failure(line_number, case_name,
                           "incorrect x87 stack-pointer family metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_FFREE
            && (first.operand_count != 1
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_WRITE
                || (first.opcode_flags & status_mask) != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87))) {
            report_failure(line_number, case_name,
                           "incorrect FFREE operand/family metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_FLD
            && (first.operand_count != 1
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_READ
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87))) {
            report_failure(line_number, case_name,
                           "incorrect x87 FLD register metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_FXCH
            && (first.operand_count != 1
                || first.opcode[0].access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87))) {
            report_failure(line_number, case_name,
                           "incorrect FXCH register/family metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_FST
                || first.name_id == CDISASM_X86_NAME_FSTP)
            && (first.operand_count != 1
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_WRITE
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87))) {
            report_failure(line_number, case_name,
                           "incorrect x87 FST/FSTP register metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_FADDP
                || first.name_id == CDISASM_X86_NAME_FMULP
                || first.name_id == CDISASM_X86_NAME_FSUBP
                || first.name_id == CDISASM_X86_NAME_FSUBRP
                || first.name_id == CDISASM_X86_NAME_FDIVP
                || first.name_id == CDISASM_X86_NAME_FDIVRP)
            && (first.operand_count != 2
                || first.opcode[0].access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87))) {
            report_failure(line_number, case_name,
                           "incorrect x87 pop-arithmetic register metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_FCMOVB
                || first.name_id == CDISASM_X86_NAME_FCMOVE
                || first.name_id == CDISASM_X86_NAME_FCMOVBE
                || first.name_id == CDISASM_X86_NAME_FCMOVU
                || first.name_id == CDISASM_X86_NAME_FCMOVNB
                || first.name_id == CDISASM_X86_NAME_FCMOVNE
                || first.name_id == CDISASM_X86_NAME_FCMOVNBE
                || first.name_id == CDISASM_X86_NAME_FCMOVNU)
            && (first.operand_count != 2
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_groups & CDISASM_GROUP_CONDITIONAL) == 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87))) {
            report_failure(line_number, case_name,
                           "incorrect x87 FCMOV family metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_FUCOM
                || first.name_id == CDISASM_X86_NAME_FUCOMP)
            && (first.operand_count != 1
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_READ
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87))) {
            report_failure(line_number, case_name,
                           "incorrect x87 FUCOM family metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_FBLD
                || first.name_id == CDISASM_X86_NAME_FBSTP)
            && (first.operand_count != 1
                || first.opcode[0].access
                    != (first.name_id == CDISASM_X86_NAME_FBLD
                        ? CDISASM_OPERAND_ACCESS_READ
                        : CDISASM_OPERAND_ACCESS_WRITE)
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87))) {
            report_failure(line_number, case_name,
                           "incorrect x87 packed-BCD memory metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_FLDCW
                || first.name_id == CDISASM_X86_NAME_FNSTCW)
            && (first.operand_count != 1
                || first.opcode[0].access
                    != (first.name_id == CDISASM_X86_NAME_FLDCW
                        ? CDISASM_OPERAND_ACCESS_READ
                        : CDISASM_OPERAND_ACCESS_WRITE)
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87))) {
            report_failure(line_number, case_name,
                           "incorrect x87 control-word memory metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_FNINIT
            && (first.operand_count != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87))) {
            report_failure(line_number, case_name,
                           "incorrect x87 FNINIT family metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_FNSTSW
            && (first.operand_count != 1
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_WRITE
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87))) {
            report_failure(line_number, case_name,
                           "incorrect x87 FNSTSW destination metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_FADD
                || first.name_id == CDISASM_X86_NAME_FMUL)
            && ((first.operand_count == 1
                    && first.opcode[0].access != CDISASM_OPERAND_ACCESS_READ)
                || (first.operand_count == 2
                    && (first.opcode[0].access
                            != CDISASM_OPERAND_ACCESS_READ_WRITE
                        || first.opcode[1].access
                            != CDISASM_OPERAND_ACCESS_READ))
                || (first.operand_count != 1 && first.operand_count != 2)
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87))) {
            report_failure(line_number, case_name,
                           "incorrect x87 FADD/FMUL operand metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_FSUB
                || first.name_id == CDISASM_X86_NAME_FSUBR)
            && ((first.operand_count == 1
                    && first.opcode[0].access != CDISASM_OPERAND_ACCESS_READ)
                || (first.operand_count == 2
                    && (first.opcode[0].access
                            != CDISASM_OPERAND_ACCESS_READ_WRITE
                        || first.opcode[1].access
                            != CDISASM_OPERAND_ACCESS_READ))
                || (first.operand_count != 1 && first.operand_count != 2)
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87))) {
            report_failure(line_number, case_name,
                           "incorrect x87 FSUB/FSUBR operand metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_FDIV
                || first.name_id == CDISASM_X86_NAME_FDIVR)
            && ((first.operand_count == 1
                    && first.opcode[0].access != CDISASM_OPERAND_ACCESS_READ)
                || (first.operand_count == 2
                    && (first.opcode[0].access
                            != CDISASM_OPERAND_ACCESS_READ_WRITE
                        || first.opcode[1].access
                            != CDISASM_OPERAND_ACCESS_READ))
                || (first.operand_count != 1 && first.operand_count != 2)
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87))) {
            report_failure(line_number, case_name,
                           "incorrect x87 FDIV/FDIVR operand metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_FIADD
                || first.name_id == CDISASM_X86_NAME_FIMUL
                || first.name_id == CDISASM_X86_NAME_FICOM
                || first.name_id == CDISASM_X86_NAME_FICOMP)
            && (first.operand_count != 1
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_READ
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87))) {
            report_failure(line_number, case_name,
                           "incorrect x87 integer-memory arithmetic metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_FISUB
                || first.name_id == CDISASM_X86_NAME_FISUBR
                || first.name_id == CDISASM_X86_NAME_FIDIV
                || first.name_id == CDISASM_X86_NAME_FIDIVR)
            && (first.operand_count != 1
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_READ
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87))) {
            report_failure(line_number, case_name,
                           "incorrect x87 integer-memory sub/div metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_FILD
                || first.name_id == CDISASM_X86_NAME_FIST
                || first.name_id == CDISASM_X86_NAME_FISTP
                || first.name_id == CDISASM_X86_NAME_FISTTP)
            && (first.operand_count != 1
                || first.opcode[0].access
                    != (first.name_id == CDISASM_X86_NAME_FILD
                        ? CDISASM_OPERAND_ACCESS_READ
                        : CDISASM_OPERAND_ACCESS_WRITE)
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87)
                || (first.name_id == CDISASM_X86_NAME_FISTTP
                    && !cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_SSE3)))) {
            report_failure(line_number, case_name,
                           "incorrect x87 integer load/store metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_FCOM
                || first.name_id == CDISASM_X86_NAME_FCOMP)
            && (first.operand_count != 1
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_READ
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87))) {
            report_failure(line_number, case_name,
                           "incorrect x87 FCOM/FCOMP operand metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_FLDENV
                || first.name_id == CDISASM_X86_NAME_FNSTENV
                || first.name_id == CDISASM_X86_NAME_FRSTOR
                || first.name_id == CDISASM_X86_NAME_FNSAVE)
            && (first.operand_count != 1
                || first.opcode[0].access
                    != ((first.name_id == CDISASM_X86_NAME_FLDENV
                            || first.name_id == CDISASM_X86_NAME_FRSTOR)
                        ? CDISASM_OPERAND_ACCESS_READ
                        : CDISASM_OPERAND_ACCESS_WRITE)
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87))) {
            report_failure(line_number, case_name,
                           "incorrect x87 environment/state metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_ADDPS
                || first.name_id == CDISASM_X86_NAME_ADDPD)
            && (first.operand_count != 2
                || first.opcode[0].access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || !cdisasm_instruction_has_x86_group(
                    &first, first.name_id == CDISASM_X86_NAME_ADDPS
                        ? CDISASM_X86_GROUP_SSE
                        : CDISASM_X86_GROUP_SSE2))) {
            report_failure(line_number, case_name,
                           "incorrect ADDPS/ADDPD family metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_ADDSS
                || first.name_id == CDISASM_X86_NAME_ADDSD)
            && (first.operand_count != 2
                || first.opcode[0].access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || !cdisasm_instruction_has_x86_group(
                    &first, first.name_id == CDISASM_X86_NAME_ADDSS
                        ? CDISASM_X86_GROUP_SSE
                        : CDISASM_X86_GROUP_SSE2))) {
            report_failure(line_number, case_name,
                           "incorrect ADDSS/ADDSD family metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_ADCX
                || first.name_id == CDISASM_X86_NAME_ADOX)
            && (((first.opcode_flags & CDISASM_PREFIX_APX_NDD) != 0
                    && (first.operand_count != 3
                        || first.opcode[0].access
                            != CDISASM_OPERAND_ACCESS_WRITE
                        || first.opcode[1].access
                            != CDISASM_OPERAND_ACCESS_READ
                        || first.opcode[2].access
                            != CDISASM_OPERAND_ACCESS_READ))
                || ((first.opcode_flags & CDISASM_PREFIX_APX_NDD) == 0
                    && (first.operand_count != 2
                        || first.opcode[0].access
                            != CDISASM_OPERAND_ACCESS_READ_WRITE
                        || first.opcode[1].access
                            != CDISASM_OPERAND_ACCESS_READ))
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_ADX))) {
            report_failure(line_number, case_name,
                           "incorrect ADCX/ADOX family metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_ADDSUBPD
                || first.name_id == CDISASM_X86_NAME_ADDSUBPS)
            && (first.operand_count != 2
                || first.opcode[0].access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_SSE3))) {
            report_failure(line_number, case_name,
                           "incorrect ADDSUBPD/ADDSUBPS family metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_AESDEC
                || first.name_id == CDISASM_X86_NAME_AESDECLAST
                || first.name_id == CDISASM_X86_NAME_AESENC
                || first.name_id == CDISASM_X86_NAME_AESENCLAST
                || first.name_id == CDISASM_X86_NAME_AESIMC
                || first.name_id == CDISASM_X86_NAME_AESKEYGENASSIST)
            && (!cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_AES)
                || first.operand_count < 2
                || first.opcode[0].access
                    != ((first.name_id == CDISASM_X86_NAME_AESIMC
                            || first.name_id
                                == CDISASM_X86_NAME_AESKEYGENASSIST)
                        ? CDISASM_OPERAND_ACCESS_WRITE
                        : CDISASM_OPERAND_ACCESS_READ_WRITE)
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ)) {
            report_failure(line_number, case_name,
                           "incorrect AES-NI family metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_ANDPS
                || first.name_id == CDISASM_X86_NAME_ANDNPS
                || first.name_id == CDISASM_X86_NAME_ANDPD
                || first.name_id == CDISASM_X86_NAME_ANDNPD)
            && (first.operand_count != 2
                || first.opcode[0].access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || !cdisasm_instruction_has_x86_group(
                    &first,
                    (first.name_id == CDISASM_X86_NAME_ANDPS
                        || first.name_id == CDISASM_X86_NAME_ANDNPS)
                        ? CDISASM_X86_GROUP_SSE
                        : CDISASM_X86_GROUP_SSE2))) {
            report_failure(line_number, case_name,
                           "incorrect packed AND family metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_ANDN
            && (first.operand_count != 3
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || first.opcode[2].access != CDISASM_OPERAND_ACCESS_READ
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_BMI1))) {
            report_failure(line_number, case_name,
                           "incorrect ANDN BMI1 family metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_BEXTR
            && (first.operand_count != 3
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || first.opcode[2].access != CDISASM_OPERAND_ACCESS_READ
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_BMI1))) {
            report_failure(line_number, case_name,
                           "incorrect BEXTR BMI1 family metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_BLSI
                || first.name_id == CDISASM_X86_NAME_BLSMSK
                || first.name_id == CDISASM_X86_NAME_BLSR)
            && (first.operand_count != 2
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_BMI1))) {
            report_failure(line_number, case_name,
                           "incorrect BLS* BMI1 family metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_BZHI
            && (first.operand_count != 3
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || first.opcode[2].access != CDISASM_OPERAND_ACCESS_READ
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_BMI2))) {
            report_failure(line_number, case_name,
                           "incorrect BZHI BMI2 family metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_CMOVB
                || first.name_id == CDISASM_X86_NAME_CMOVBE
                || first.name_id == CDISASM_X86_NAME_CMOVL
                || first.name_id == CDISASM_X86_NAME_CMOVLE
                || first.name_id == CDISASM_X86_NAME_CMOVNO
                || first.name_id == CDISASM_X86_NAME_CMOVNP
                || first.name_id == CDISASM_X86_NAME_CMOVNS
                || first.name_id == CDISASM_X86_NAME_CMOVO
                || first.name_id == CDISASM_X86_NAME_CMOVP
                || first.name_id == CDISASM_X86_NAME_CMOVS
                || first.name_id == CDISASM_X86_NAME_CMOVNB
                || first.name_id == CDISASM_X86_NAME_CMOVNBE
                || first.name_id == CDISASM_X86_NAME_CMOVNL
                || first.name_id == CDISASM_X86_NAME_CMOVNLE
                || first.name_id == CDISASM_X86_NAME_CMOVNZ
                || first.name_id == CDISASM_X86_NAME_CMOVZ)
            && (((first.opcode_flags & CDISASM_PREFIX_APX_NDD) == 0
                    && first.operand_count != 2)
                || ((first.opcode_flags & CDISASM_PREFIX_APX_NDD) != 0
                    && (first.operand_count != 3
                        || first.opcode[2].access
                            != CDISASM_OPERAND_ACCESS_READ))
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_CMOV))) {
            report_failure(line_number, case_name,
                           "incorrect CMOV family metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_SETB
                || first.name_id == CDISASM_X86_NAME_SETBE
                || first.name_id == CDISASM_X86_NAME_SETL
                || first.name_id == CDISASM_X86_NAME_SETLE
                || first.name_id == CDISASM_X86_NAME_SETNO
                || first.name_id == CDISASM_X86_NAME_SETNP
                || first.name_id == CDISASM_X86_NAME_SETNS
                || first.name_id == CDISASM_X86_NAME_SETO
                || first.name_id == CDISASM_X86_NAME_SETP
                || first.name_id == CDISASM_X86_NAME_SETS)
            && (first.operand_count != 1
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_WRITE
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_I386))) {
            report_failure(line_number, case_name,
                           "incorrect SETcc family/access metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_JB
                || first.name_id == CDISASM_X86_NAME_JBE
                || first.name_id == CDISASM_X86_NAME_JL
                || first.name_id == CDISASM_X86_NAME_JLE
                || first.name_id == CDISASM_X86_NAME_JNO
                || first.name_id == CDISASM_X86_NAME_JNP
                || first.name_id == CDISASM_X86_NAME_JNS
                || first.name_id == CDISASM_X86_NAME_JO
                || first.name_id == CDISASM_X86_NAME_JP
                || first.name_id == CDISASM_X86_NAME_JS)
            && (first.operand_count != 1
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_READ
                || !cdisasm_instruction_has_x86_group(
                    &first,
                    first.opcode_size == 2
                        ? CDISASM_X86_GROUP_I86
                        : CDISASM_X86_GROUP_I386))) {
            report_failure(line_number, case_name,
                           "incorrect Jcc family/access metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_JMP
            && (first.operand_count != 1
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_READ
                || !cdisasm_instruction_has_x86_group(
                    &first,
                    first.opcode[0].type == CDISASM_OPERAND_IMMEDIATE
                        ? CDISASM_X86_GROUP_I86
                        : (mode == 64
                            ? CDISASM_X86_GROUP_AMD64
                            : CDISASM_X86_GROUP_I386)))) {
            report_failure(line_number, case_name,
                           "incorrect JMP family/access metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_CMPXCHG
            && (first.operand_count != 2
                || first.opcode[0].access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_I486))) {
            report_failure(line_number, case_name,
                           "incorrect CMPXCHG family/access metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_MOVSX
            && (first.operand_count != 2
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_I386))) {
            report_failure(line_number, case_name,
                           "incorrect MOVSX family/access metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_MOVZX
            && (first.operand_count != 2
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_I386))) {
            report_failure(line_number, case_name,
                           "incorrect MOVZX family/access metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_NEG
            && (((first.opcode_flags & CDISASM_PREFIX_APX_NDD) != 0
                    && (first.operand_count != 2
                        || first.opcode[0].access
                            != CDISASM_OPERAND_ACCESS_WRITE
                        || first.opcode[1].access
                            != CDISASM_OPERAND_ACCESS_READ))
                || ((first.opcode_flags & CDISASM_PREFIX_APX_NDD) == 0
                    && (first.operand_count != 1
                        || first.opcode[0].access
                            != CDISASM_OPERAND_ACCESS_READ_WRITE))
                || (first.opcode_flags & status_mask)
                    != ((first.opcode_flags & CDISASM_PREFIX_APX_NF) != 0
                        ? 0u
                        : CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)
                || (cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_APX_F)
                    ? (!cdisasm_instruction_has_x86_group(
                           &first, CDISASM_X86_GROUP_X86_64)
                        || (((first.opcode_flags
                                & (CDISASM_PREFIX_APX_NDD
                                    | CDISASM_PREFIX_APX_NF)) != 0)
                            && !cdisasm_instruction_has_x86_group(
                                &first, CDISASM_X86_GROUP_APX_F_N3)))
                    : !cdisasm_instruction_has_x86_group(
                        &first,
                        first.opcode[0].type == CDISASM_OPERAND_REGISTER
                                && first.opcode[0].size == 1
                            ? CDISASM_X86_GROUP_I86
                            : first.opcode[0].size == 8
                                ? CDISASM_X86_GROUP_X86_64
                                : CDISASM_X86_GROUP_I386)))) {
            report_failure(line_number, case_name,
                           "incorrect NEG family/access metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_NOT
            && (((first.opcode_flags & CDISASM_PREFIX_APX_NDD) != 0
                    && (first.operand_count != 2
                        || first.opcode[0].access
                            != CDISASM_OPERAND_ACCESS_WRITE
                        || first.opcode[1].access
                            != CDISASM_OPERAND_ACCESS_READ
                        || !cdisasm_instruction_has_x86_group(
                            &first, CDISASM_X86_GROUP_APX_F_N3)))
                || ((first.opcode_flags & CDISASM_PREFIX_APX_NDD) == 0
                    && (first.operand_count != 1
                        || first.opcode[0].access
                            != CDISASM_OPERAND_ACCESS_READ_WRITE))
                || (first.opcode_flags & status_mask) != 0
                || (cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_APX_F)
                    ? !cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_X86_64)
                    : !cdisasm_instruction_has_x86_group(
                        &first,
                        first.opcode[0].type == CDISASM_OPERAND_REGISTER
                                && first.opcode[0].size == 1
                            ? CDISASM_X86_GROUP_I86
                            : first.opcode[0].size == 8
                                ? CDISASM_X86_GROUP_X86_64
                                : CDISASM_X86_GROUP_I386)))) {
            report_failure(line_number, case_name,
                           "incorrect NOT family/access/flag metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_MUL
            && (first.operand_count != 1
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_READ
                || (cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_APX_F)
                    ? (!cdisasm_instruction_has_x86_group(
                           &first, CDISASM_X86_GROUP_X86_64)
                        || ((first.opcode_flags & CDISASM_PREFIX_APX_NF) != 0
                            && !cdisasm_instruction_has_x86_group(
                                &first, CDISASM_X86_GROUP_APX_F_N3)))
                    : !cdisasm_instruction_has_x86_group(
                        &first,
                        first.opcode[0].type == CDISASM_OPERAND_REGISTER
                                && first.opcode[0].size == 1
                            ? CDISASM_X86_GROUP_I86
                            : first.opcode[0].size == 8
                                ? CDISASM_X86_GROUP_X86_64
                                : CDISASM_X86_GROUP_I386)))) {
            report_failure(line_number, case_name,
                           "incorrect MUL family/access metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_DIV
            && (first.operand_count != 1
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_READ
                || (cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_APX_F)
                    ? (!cdisasm_instruction_has_x86_group(
                           &first, CDISASM_X86_GROUP_X86_64)
                        || ((first.opcode_flags & CDISASM_PREFIX_APX_NF) != 0
                            && !cdisasm_instruction_has_x86_group(
                                &first, CDISASM_X86_GROUP_APX_F_N3)))
                    : !cdisasm_instruction_has_x86_group(
                        &first,
                        first.opcode[0].type == CDISASM_OPERAND_REGISTER
                                && first.opcode[0].size == 1
                            ? CDISASM_X86_GROUP_I86
                            : first.opcode[0].size == 8
                                ? CDISASM_X86_GROUP_X86_64
                                : CDISASM_X86_GROUP_I386)))) {
            report_failure(line_number, case_name,
                           "incorrect DIV family/access metadata");
            return;
        }
        if (first.name_id == CDISASM_X86_NAME_IDIV
            && (first.operand_count != 1
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_READ
                || (cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_APX_F)
                    ? (!cdisasm_instruction_has_x86_group(
                           &first, CDISASM_X86_GROUP_X86_64)
                        || ((first.opcode_flags & CDISASM_PREFIX_APX_NF) != 0
                            && !cdisasm_instruction_has_x86_group(
                                &first, CDISASM_X86_GROUP_APX_F_N3)))
                    : !cdisasm_instruction_has_x86_group(
                        &first,
                        first.opcode[0].type == CDISASM_OPERAND_REGISTER
                                && first.opcode[0].size == 1
                            ? CDISASM_X86_GROUP_I86
                            : first.opcode[0].size == 8
                                ? CDISASM_X86_GROUP_X86_64
                                : CDISASM_X86_GROUP_I386)))) {
            report_failure(line_number, case_name,
                           "incorrect IDIV family/access metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_INC
                || first.name_id == CDISASM_X86_NAME_DEC)
            && (((first.opcode_flags & CDISASM_PREFIX_APX_NDD) != 0
                    && (first.operand_count != 2
                        || first.opcode[0].access
                            != CDISASM_OPERAND_ACCESS_WRITE
                        || first.opcode[1].access
                            != CDISASM_OPERAND_ACCESS_READ))
                || ((first.opcode_flags & CDISASM_PREFIX_APX_NDD) == 0
                    && (first.operand_count != 1
                        || first.opcode[0].access
                            != CDISASM_OPERAND_ACCESS_READ_WRITE))
                || (first.opcode_flags & status_mask)
                    != ((first.opcode_flags & CDISASM_PREFIX_APX_NF) != 0
                        ? 0u
                        : CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)
                || (cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_APX_F)
                    ? (!cdisasm_instruction_has_x86_group(
                           &first, CDISASM_X86_GROUP_X86_64)
                        || (((first.opcode_flags
                                & (CDISASM_PREFIX_APX_NDD
                                    | CDISASM_PREFIX_APX_NF)) != 0)
                            && !cdisasm_instruction_has_x86_group(
                                &first, CDISASM_X86_GROUP_APX_F_N3)))
                    : !cdisasm_instruction_has_x86_group(
                        &first,
                        first.opcode[0].type == CDISASM_OPERAND_REGISTER
                                && first.opcode[0].size == 1
                            ? CDISASM_X86_GROUP_I86
                            : first.opcode[0].size == 8
                                ? CDISASM_X86_GROUP_X86_64
                                : CDISASM_X86_GROUP_I386)))) {
            report_failure(line_number, case_name,
                           "incorrect INC/DEC family/access/flag metadata");
            return;
        }
        if ((strncmp(case_name, "extra_apx_ccmp", 14) == 0
                || strncmp(case_name, "extra_apx_ctest", 15) == 0)
            && (first.operand_count != 2
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_READ
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_flags & status_mask) != status_mask
                || (first.opcode_groups & CDISASM_GROUP_CONDITIONAL) == 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_APX_F)
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_APX_F_N3))) {
            report_failure(line_number, case_name,
                           "incorrect APX conditional compare/test metadata");
            return;
        }
        if (cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_APX_F)
            && (first.name_id == CDISASM_X86_NAME_ADD
                || first.name_id == CDISASM_X86_NAME_OR
                || first.name_id == CDISASM_X86_NAME_ADC
                || first.name_id == CDISASM_X86_NAME_SBB
                || first.name_id == CDISASM_X86_NAME_AND
                || first.name_id == CDISASM_X86_NAME_SUB
                || first.name_id == CDISASM_X86_NAME_XOR)
            && (first.operand_count
                    != ((first.opcode_flags & CDISASM_PREFIX_APX_NDD) != 0
                        ? 3 : 2)
                || first.opcode[0].access
                    != ((first.opcode_flags & CDISASM_PREFIX_APX_NDD) != 0
                        ? CDISASM_OPERAND_ACCESS_WRITE
                        : CDISASM_OPERAND_ACCESS_READ_WRITE)
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.operand_count == 3
                    && first.opcode[2].access != CDISASM_OPERAND_ACCESS_READ)
                || (first.opcode_flags & status_mask)
                    != ((first.opcode_flags & CDISASM_PREFIX_APX_NF) != 0
                        ? 0u
                        : (first.name_id == CDISASM_X86_NAME_ADC
                                || first.name_id == CDISASM_X86_NAME_SBB
                            ? status_mask
                            : CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X86_64)
                || (((first.opcode_flags
                        & (CDISASM_PREFIX_APX_NDD
                            | CDISASM_PREFIX_APX_NF)) != 0)
                    && !cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_APX_F_N3)))) {
            report_failure(line_number, case_name,
                           "incorrect APX ALU family/access/flag metadata");
            return;
        }
        if (cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_APX_F)
            && (first.name_id == CDISASM_X86_NAME_ROL
                || first.name_id == CDISASM_X86_NAME_ROR
                || first.name_id == CDISASM_X86_NAME_RCL
                || first.name_id == CDISASM_X86_NAME_RCR
                || first.name_id == CDISASM_X86_NAME_SHL
                || first.name_id == CDISASM_X86_NAME_SHR
                || first.name_id == CDISASM_X86_NAME_SAR)
            && (first.operand_count
                    != ((first.opcode_flags & CDISASM_PREFIX_APX_NDD) != 0
                        ? 3 : 2)
                || first.opcode[0].access
                    != ((first.opcode_flags & CDISASM_PREFIX_APX_NDD) != 0
                        ? CDISASM_OPERAND_ACCESS_WRITE
                        : CDISASM_OPERAND_ACCESS_READ_WRITE)
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.operand_count == 3
                    && first.opcode[2].access != CDISASM_OPERAND_ACCESS_READ)
                || (first.opcode_flags & status_mask)
                    != ((first.opcode_flags & CDISASM_PREFIX_APX_NF) != 0
                        ? 0u
                        : (first.name_id == CDISASM_X86_NAME_RCL
                                || first.name_id == CDISASM_X86_NAME_RCR
                            ? status_mask
                            : CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS))
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X86_64)
                || (((first.opcode_flags
                        & (CDISASM_PREFIX_APX_NDD
                            | CDISASM_PREFIX_APX_NF)) != 0)
                    && !cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_APX_F_N3)))) {
            report_failure(line_number, case_name,
                           "incorrect APX rotate/shift metadata");
            return;
        }
        if (cdisasm_instruction_has_x86_group(
                &first, CDISASM_X86_GROUP_APX_F)
            && (first.name_id == CDISASM_X86_NAME_SHLD
                || first.name_id == CDISASM_X86_NAME_SHRD)
            && (first.operand_count
                    != ((first.opcode_flags & CDISASM_PREFIX_APX_NDD) != 0
                        ? 4 : 3)
                || first.opcode[0].access
                    != ((first.opcode_flags & CDISASM_PREFIX_APX_NDD) != 0
                        ? CDISASM_OPERAND_ACCESS_WRITE
                        : CDISASM_OPERAND_ACCESS_READ_WRITE)
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || first.opcode[2].access != CDISASM_OPERAND_ACCESS_READ
                || (first.operand_count == 4
                    && first.opcode[3].access != CDISASM_OPERAND_ACCESS_READ)
                || (first.opcode_flags & status_mask)
                    != ((first.opcode_flags & CDISASM_PREFIX_APX_NF) != 0
                        ? 0u
                        : CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS)
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X86_64)
                || (((first.opcode_flags
                        & (CDISASM_PREFIX_APX_NDD
                            | CDISASM_PREFIX_APX_NF)) != 0)
                    && !cdisasm_instruction_has_x86_group(
                        &first, CDISASM_X86_GROUP_APX_F_N3)))) {
            report_failure(line_number, case_name,
                           "incorrect APX double-shift metadata");
            return;
        }
        if (strncmp(case_name, "sbb_", 4) == 0
            && first.name_id == CDISASM_X86_NAME_SBB
            && (first.operand_count != 2
                || first.opcode[0].access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_flags & status_mask) != status_mask
                || !cdisasm_instruction_has_x86_group(
                    &first,
                    strstr(case_name, "opcode82") != NULL
                            || (first.opcode[0].type
                                    == CDISASM_OPERAND_REGISTER
                            && first.opcode[0].size == 1
                            && first.opcode[1].type
                                != CDISASM_OPERAND_MEMORY)
                        ? CDISASM_X86_GROUP_I86
                        : CDISASM_X86_GROUP_I386))) {
            report_failure(line_number, case_name,
                           "incorrect SBB family/access/flag metadata");
            return;
        }
        if (strncmp(case_name, "sub_", 4) == 0
            && first.name_id == CDISASM_X86_NAME_SUB
            && (first.operand_count != 2
                || first.opcode[0].access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_flags & status_mask)
                    != CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS
                || !cdisasm_instruction_has_x86_group(
                    &first,
                    strstr(case_name, "opcode82") != NULL
                            || (first.opcode[0].type
                                    == CDISASM_OPERAND_REGISTER
                                && first.opcode[0].size == 1
                                && first.opcode[1].type
                                    != CDISASM_OPERAND_MEMORY)
                        ? CDISASM_X86_GROUP_I86
                        : CDISASM_X86_GROUP_I386))) {
            report_failure(line_number, case_name,
                           "incorrect SUB family/access/flag metadata");
            return;
        }
        if (strncmp(case_name, "cmp_", 4) == 0
            && first.name_id == CDISASM_X86_NAME_CMP
            && (first.operand_count != 2
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_READ
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_flags & status_mask)
                    != CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS
                || !cdisasm_instruction_has_x86_group(
                    &first,
                    strstr(case_name, "opcode82") != NULL
                            || (first.opcode[0].type
                                    == CDISASM_OPERAND_REGISTER
                                && first.opcode[0].size == 1
                                && first.opcode[1].type
                                    != CDISASM_OPERAND_MEMORY)
                        ? CDISASM_X86_GROUP_I86
                        : CDISASM_X86_GROUP_I386))) {
            report_failure(line_number, case_name,
                           "incorrect CMP family/access/flag metadata");
            return;
        }
        if (strncmp(case_name, "xor_", 4) == 0
            && first.name_id == CDISASM_X86_NAME_XOR
            && (first.operand_count != 2
                || first.opcode[0].access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_flags & status_mask)
                    != CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS
                || !cdisasm_instruction_has_x86_group(
                    &first,
                    strstr(case_name, "opcode82") != NULL
                            || (first.opcode[0].type
                                    == CDISASM_OPERAND_REGISTER
                                && first.opcode[0].size == 1
                                && first.opcode[1].type
                                    != CDISASM_OPERAND_MEMORY)
                        ? CDISASM_X86_GROUP_I86
                        : CDISASM_X86_GROUP_I386))) {
            report_failure(line_number, case_name,
                           "incorrect XOR family/access/flag metadata");
            return;
        }
        if (strncmp(case_name, "or_", 3) == 0
            && first.name_id == CDISASM_X86_NAME_OR
            && (first.operand_count != 2
                || first.opcode[0].access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_flags & status_mask)
                    != CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS
                || !cdisasm_instruction_has_x86_group(
                    &first,
                    strstr(case_name, "opcode82") != NULL
                            || (first.opcode[0].type
                                    == CDISASM_OPERAND_REGISTER
                                && first.opcode[0].size == 1
                                && first.opcode[1].type
                                    != CDISASM_OPERAND_MEMORY)
                        ? CDISASM_X86_GROUP_I86
                        : CDISASM_X86_GROUP_I386))) {
            report_failure(line_number, case_name,
                           "incorrect OR family/access/flag metadata");
            return;
        }
        if (strncmp(case_name, "and_", 4) == 0
            && first.name_id == CDISASM_X86_NAME_AND
            && (first.operand_count != 2
                || first.opcode[0].access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_flags & status_mask)
                    != CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS
                || !cdisasm_instruction_has_x86_group(
                    &first,
                    strstr(case_name, "opcode82") != NULL
                            || (first.opcode[0].type
                                    == CDISASM_OPERAND_REGISTER
                                && first.opcode[0].size == 1
                                && first.opcode[1].type
                                    != CDISASM_OPERAND_MEMORY)
                        ? CDISASM_X86_GROUP_I86
                        : CDISASM_X86_GROUP_I386))) {
            report_failure(line_number, case_name,
                           "incorrect AND family/access/flag metadata");
            return;
        }
        if (strncmp(case_name, "test_", 5) == 0
            && first.name_id == CDISASM_X86_NAME_TEST
            && (first.operand_count != 2
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_READ
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || (first.opcode_flags & status_mask)
                    != CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS
                || !cdisasm_instruction_has_x86_group(
                    &first,
                    strstr(case_name, "group1") != NULL
                            || (first.opcode[0].type
                                    == CDISASM_OPERAND_REGISTER
                                && first.opcode[0].size == 1)
                        ? CDISASM_X86_GROUP_I86
                        : CDISASM_X86_GROUP_I386))) {
            report_failure(line_number, case_name,
                           "incorrect TEST family/access/flag metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_BLENDPD
                || first.name_id == CDISASM_X86_NAME_BLENDPS
                || first.name_id == CDISASM_X86_NAME_BLENDVPD
                || first.name_id == CDISASM_X86_NAME_BLENDVPS)
            && (first.operand_count != 3
                || first.opcode[0].access
                    != CDISASM_OPERAND_ACCESS_READ_WRITE
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || first.opcode[2].access != CDISASM_OPERAND_ACCESS_READ
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_SSE41))) {
            report_failure(line_number, case_name,
                           "incorrect SSE4.1 BLEND family metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_FCOMPP
                || first.name_id == CDISASM_X86_NAME_FUCOMPP)
            && (first.operand_count != 0
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87))) {
            report_failure(line_number, case_name,
                           "incorrect x87 double-pop compare metadata");
            return;
        }
        if ((first.name_id == CDISASM_X86_NAME_FCOMI
                || first.name_id == CDISASM_X86_NAME_FCOMIP
                || first.name_id == CDISASM_X86_NAME_FUCOMI
                || first.name_id == CDISASM_X86_NAME_FUCOMIP)
            && (first.operand_count != 2
                || first.opcode[0].access != CDISASM_OPERAND_ACCESS_READ
                || first.opcode[1].access != CDISASM_OPERAND_ACCESS_READ
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_X87)
                || !cdisasm_instruction_has_x86_group(
                    &first, CDISASM_X86_GROUP_FCOMI))) {
            report_failure(line_number, case_name,
                           "incorrect x87 FCOMI family metadata");
            return;
        }
    }
#if USE_DISASM_FORMAT
    {
        char formatted[CORPUS_TEXT_CAPACITY];
        /* A generated gap probe deliberately has no spelling oracle.  It is
         * still a decode/metadata witness; formatter coverage for late XED
         * aliases remains a separate exact-text evidence stream. */
        if (strcmp(fields[6], "@") == 0) {
            goto skip_intel_format;
        }
        size_t required = cdisasm_x86_format(
            &first,
            CDISASM_FORMAT_SYNTAX_0,
            formatted,
            sizeof(formatted));

        if (required == 0 || required >= sizeof(formatted)) {
            report_failure(line_number, case_name, "formatter rejected result");
        } else if (strcmp(fields[6], "@") != 0
                   && (required != strlen(fields[6])
                       || strcmp(formatted, fields[6]) != 0)) {
            char message[CORPUS_TEXT_CAPACITY + 64];
            (void)snprintf(message, sizeof(message),
                           "formatted as \"%s\", expected \"%s\"",
                           formatted, fields[6]);
            report_failure(line_number, case_name, message);
        }
    }
skip_intel_format:
    {
        char att[CORPUS_TEXT_CAPACITY];
        char repeated[CORPUS_TEXT_CAPACITY];
        if (strcmp(fields[7], "@") == 0) {
            goto skip_att_format;
        }
        size_t queried = cdisasm_x86_format(
            &first,
            CDISASM_FORMAT_SYNTAX_ATT,
            NULL,
            0);
        size_t required = cdisasm_x86_format(
            &first,
            CDISASM_FORMAT_SYNTAX_ATT,
            att,
            sizeof(att));
        size_t repeated_size = cdisasm_x86_format(
            &first,
            CDISASM_FORMAT_SYNTAX_ATT,
            repeated,
            sizeof(repeated));

        if (queried == 0 || queried >= sizeof(att)
            || required != queried || repeated_size != queried
            || strlen(att) != queried || strcmp(att, repeated) != 0) {
            report_failure(
                line_number,
                case_name,
                "AT&T formatter size/determinism contract failed");
        } else if (strcmp(fields[7], "@") != 0
                   && (required != strlen(fields[7])
                       || strcmp(att, fields[7]) != 0)) {
            char message[CORPUS_TEXT_CAPACITY + 64];
            (void)snprintf(message, sizeof(message),
                           "AT&T formatted as \"%s\", expected \"%s\"",
                           att, fields[7]);
            report_failure(line_number, case_name, message);
        }
    }
skip_att_format:;
#endif
}

#if USE_DISASM_FORMAT
static void run_two_byte_formatter_sweep(void)
{
    static const cdisasm_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    static const uint32_t syntaxes[] = {
        CDISASM_FORMAT_SYNTAX_INTEL, CDISASM_FORMAT_SYNTAX_ATT
    };
    uint8_t code[CDISASM_MAX_INSTRUCTION_SIZE] = {0};
    cdisasm_instruction instruction;
    char text[CORPUS_TEXT_CAPACITY];
    size_t mode_index;
    unsigned int first_byte;
    unsigned int second_byte;

    for (mode_index = 0; mode_index < sizeof(modes) / sizeof(modes[0]);
         ++mode_index) {
        cdisasm_x86_decode_flags selected_flags;

        if (cdisasm_x86_cpu_decode_flag_mask(
                CDISASM_CPU_X86, modes[mode_index], &selected_flags)
            != CDISASM_STATUS_OK) {
            report_failure(
                0, "two-byte formatter sweep",
                "could not construct full-family decode flags");
            return;
        }
        for (first_byte = 0; first_byte <= UINT8_MAX; ++first_byte) {
            for (second_byte = 0; second_byte <= UINT8_MAX; ++second_byte) {
                uint32_t decoded_size;
                size_t syntax_index;

                code[0] = (uint8_t)first_byte;
                code[1] = (uint8_t)second_byte;
                decoded_size = cdisasm_x86_decode(
                    CDISASM_CPU_X86,
                    modes[mode_index],
                    code,
                    sizeof(code),
                    UINT64_C(0x1000),
                    &selected_flags,
                    &instruction);
                if (decoded_size == 0) {
                    continue;
                }

                for (syntax_index = 0;
                     syntax_index < sizeof(syntaxes) / sizeof(syntaxes[0]);
                     ++syntax_index) {
                    size_t queried = cdisasm_x86_format(
                        &instruction, syntaxes[syntax_index], NULL, 0);
                    size_t required = cdisasm_x86_format(
                        &instruction,
                        syntaxes[syntax_index],
                        text,
                        sizeof(text));

                    if (queried == 0 || queried >= sizeof(text)
                        || required != queried || strlen(text) != queried) {
                        char message[256];
                        (void)snprintf(
                            message,
                            sizeof(message),
                            "mode %u, bytes %02x %02x, syntax %u failed",
                            (unsigned int)modes[mode_index],
                            first_byte,
                            second_byte,
                            (unsigned int)syntaxes[syntax_index]);
                        report_failure(0, "two-byte formatter sweep", message);
                        return;
                    }
                }
            }
        }
    }
}
#endif

int main(int argc, char **argv)
{
    char line[CORPUS_LINE_CAPACITY];
    const char *case_prefix = NULL;
    size_t case_prefix_length = 0;
    FILE *corpus;
    size_t line_number = 0;
    size_t case_count = 0;

    if (argc != 2 && argc != 3) {
        fprintf(stderr,
                "usage: %s <x86-opcode-corpus.tsv> [case-prefix]\n",
                argv[0]);
        return 2;
    }
    if (argc == 3) {
        case_prefix = argv[2];
        case_prefix_length = strlen(case_prefix);
        if (case_prefix_length == 0) {
            fprintf(stderr, "case prefix must not be empty\n");
            return 2;
        }
    }
    corpus = fopen(argv[1], "rb");
    if (corpus == NULL) {
        fprintf(stderr, "could not open opcode corpus: %s\n", argv[1]);
        return 2;
    }

    while (fgets(line, sizeof(line), corpus) != NULL) {
        size_t length;
        char *fields[CORPUS_FIELD_COUNT];

        ++line_number;
        length = strlen(line);
        if (length == sizeof(line) - 1u && line[length - 1u] != '\n') {
            report_failure(line_number, "unknown", "line is too long");
            break;
        }
        while (length != 0
               && (line[length - 1u] == '\n' || line[length - 1u] == '\r')) {
            line[--length] = '\0';
        }
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }
        if (!split_fields(line, fields)) {
            report_failure(line_number, "unknown", "expected exactly 9 tab fields");
            continue;
        }
        if (case_prefix != NULL
            && strncmp(fields[0], case_prefix, case_prefix_length) != 0) {
            continue;
        }
        run_case(fields, line_number);
        ++case_count;
    }
    if (ferror(corpus)) {
        report_failure(line_number, "unknown", "I/O error while reading corpus");
    }
    (void)fclose(corpus);

    if (case_count < 32u) {
        report_failure(line_number, "corpus", "corpus unexpectedly has fewer than 32 cases");
    }
#if USE_DISASM_FORMAT
    run_two_byte_formatter_sweep();
#endif
    if (failures != 0) {
        fprintf(stderr, "%d opcode-corpus test(s) failed across %zu cases\n",
                failures, case_count);
        return 1;
    }
    printf("all %zu data-driven opcode corpus cases passed\n", case_count);
    return 0;
}
