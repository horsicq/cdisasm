#include "cdisasm/cdisasm.h"

_Static_assert(sizeof(cdisasm_decode_flags) == CDISASM_DECODE_FLAGS_SIZE,
               "decode-flags ABI size does not match its public constant");

size_t CDISASM_CALL cdisasm_instruction_size(cdisasm_cpu_id cpu_id)
{
    switch (CDISASM_CPU_GROUP_OF(cpu_id)) {
#if USE_ARCH_X86
        case CDISASM_CPU_GROUP_X86:
            return sizeof(cdisasm_x86_instruction);
#endif
#if USE_ARCH_ARM
        case CDISASM_CPU_GROUP_ARM:
            return sizeof(cdisasm_arm_instruction);
#endif
        default:
            return 0;
    }
}

cdisasm_status CDISASM_CALL cdisasm_cpu_decode_flag_mask(
    cdisasm_cpu_id cpu_id,
    uint32_t mode,
    cdisasm_decode_flags *flags)
{
    (void)mode;

    if (flags == NULL) {
        return CDISASM_STATUS_INVALID_ARGUMENT;
    }
    cdisasm_decode_flags_reset(flags);

    switch (CDISASM_CPU_GROUP_OF(cpu_id)) {
#if USE_ARCH_X86
        case CDISASM_CPU_GROUP_X86:
            return cdisasm_x86_cpu_decode_flag_mask(
                (cdisasm_x86_cpu_id)cpu_id,
                (cdisasm_x86_mode)mode,
                (cdisasm_x86_decode_flags *)flags);
#endif
#if USE_ARCH_ARM
        case CDISASM_CPU_GROUP_ARM:
            return cdisasm_arm_cpu_decode_flag_mask(
                (cdisasm_arm_cpu_id)cpu_id,
                (cdisasm_arm_mode)mode,
                (cdisasm_arm_decode_flags *)flags);
#endif
        default:
            return CDISASM_STATUS_INVALID_ARGUMENT;
    }
}

uint32_t CDISASM_CALL cdisasm_decode(
    cdisasm_cpu_id cpu_id,
    uint32_t mode,
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    const cdisasm_decode_flags *flags,
    void *instruction)
{
    (void)mode;
    (void)code;
    (void)code_size;
    (void)address;
    (void)flags;
    (void)instruction;

    switch (CDISASM_CPU_GROUP_OF(cpu_id)) {
#if USE_ARCH_X86
        case CDISASM_CPU_GROUP_X86:
            return cdisasm_x86_decode(
                (cdisasm_x86_cpu_id)cpu_id,
                (cdisasm_x86_mode)mode,
                code,
                code_size,
                address,
                flags,
                (cdisasm_x86_instruction *)instruction);
#endif
#if USE_ARCH_ARM
        case CDISASM_CPU_GROUP_ARM:
            return cdisasm_arm_decode(
                (cdisasm_arm_cpu_id)cpu_id,
                (cdisasm_arm_mode)mode,
                code,
                code_size,
                address,
                flags,
                (cdisasm_arm_instruction *)instruction);
#endif
        default:
            return 0;
    }
}

uint32_t CDISASM_CALL cdisasm_decode_checked(
    cdisasm_cpu_id cpu_id,
    uint32_t mode,
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    const cdisasm_decode_flags *flags,
    void *instruction,
    size_t instruction_size)
{
    const size_t required_size = cdisasm_instruction_size(cpu_id);

    if (required_size == 0
        || instruction == NULL
        || instruction_size != required_size) {
        return 0;
    }

    return cdisasm_decode(
        cpu_id,
        mode,
        code,
        code_size,
        address,
        flags,
        instruction);
}

uint32_t CDISASM_CALL cdisasm_version(void)
{
    return ((uint32_t)CDISASM_VERSION_MAJOR << 16)
        | ((uint32_t)CDISASM_VERSION_MINOR << 8)
        | (uint32_t)CDISASM_VERSION_PATCH;
}

const char *CDISASM_CALL cdisasm_version_string(void)
{
    return CDISASM_VERSION_STRING;
}

const char *CDISASM_CALL cdisasm_status_string(cdisasm_status status)
{
    switch (status) {
        case CDISASM_STATUS_OK:
            return "success";
        case CDISASM_STATUS_INVALID_ARGUMENT:
            return "invalid argument";
        case CDISASM_STATUS_END_OF_INPUT:
            return "end of input";
        case CDISASM_STATUS_TRUNCATED:
            return "truncated instruction";
        case CDISASM_STATUS_INVALID_INSTRUCTION:
            return "invalid instruction";
        case CDISASM_STATUS_UNSUPPORTED_INSTRUCTION:
            return "unsupported instruction";
        case CDISASM_STATUS_INTERNAL_ERROR:
            return "internal error";
        default:
            return "unknown status";
    }
}
