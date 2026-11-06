/* Copyright (c) 2026 hors<horsicq@gmail.com>
 * SPDX-License-Identifier: MIT */
#include "cdisasm/cdisasm_mips_v3.h"
#include "mips_decoder.h"
#include <string.h>

static int flags_known(const cdisasm_mips_decode_flags *flags)
{
    unsigned index;
    if ((flags->bitmap[0] & ~CDISASM_MIPS_DECODE_FLAG_KNOWN_MASK_0) != 0) return 0;
    if ((flags->bitmap[1] & ~CDISASM_MIPS_DECODE_FLAG_KNOWN_MASK_1) != 0) return 0;
    for (index = 2; index < CDISASM_DECODE_FLAGS_BITMAP_COUNT; ++index)
        if (flags->bitmap[index] != 0) return 0;
    return 1;
}

static uint32_t fail_v3(cdisasm_mips_instruction_v3 *instruction, cdisasm_status status)
{
    memset(instruction, 0, sizeof(*instruction));
    instruction->instruction.last_error_id = (uint8_t)status;
    return 0;
}

static void from_v2(const cdisasm_mips_instruction_v2 *source, cdisasm_mips_instruction_v3 *target)
{
    memset(target, 0, sizeof(*target));
    target->instruction = source->instruction;
    memcpy(target->raw_bytes, source->raw_bytes, sizeof(target->raw_bytes));
    target->encoding = source->encoding;
    target->structure_version = CDISASM_MIPS_V3_STRUCTURE_VERSION;
    target->structure_size = (uint32_t)sizeof(*target);
    target->required_flags.bitmap[0] = source->required_flags;
}

/* Only the V3 result can retain this policy bit. The canonical legacy envelope
 * for ordinary instructions continues to carry exactly its old requirements. */
static int is_unverified(const cdisasm_mips_instruction_v3 *instruction)
{
    return instruction->required_flags.bitmap[1] == CDISASM_MIPS_DECODE_FLAG_ALLEGREX_UNVERIFIED;
}

static int is_mr2(const cdisasm_mips_instruction_v3 *instruction)
{
    return instruction->required_flags.bitmap[1] == CDISASM_MIPS_DECODE_FLAG_INTERAPTIV_MR2;
}

#define V3_FAMILIES (CDISASM_MIPS_FAMILY_MASK_INTERAPTIV_MR2 | CDISASM_MIPS_FAMILY_MASK_CNMIPS2 | CDISASM_MIPS_FAMILY_MASK_CNMIPS3)
#define V3_SELECTORS (CDISASM_MIPS_DECODE_FLAG_INTERAPTIV_MR2 | CDISASM_MIPS_DECODE_FLAG_CNMIPS2 | CDISASM_MIPS_DECODE_FLAG_CNMIPS3)

static const struct { cdisasm_mips_family_id family; uint64_t selector; } upper_families[] = {
    {CDISASM_MIPS_FAMILY_INTERAPTIV_MR2, CDISASM_MIPS_DECODE_FLAG_INTERAPTIV_MR2},
    {CDISASM_MIPS_FAMILY_CNMIPS2, CDISASM_MIPS_DECODE_FLAG_CNMIPS2},
    {CDISASM_MIPS_FAMILY_CNMIPS3, CDISASM_MIPS_DECODE_FLAG_CNMIPS3}
};

cdisasm_status CDISASM_CALL cdisasm_mips_family_decode_flags_v3(cdisasm_mips_family_id family,
    cdisasm_mips_decode_flags *flags)
{
    const cdisasm_mips_family_descriptor *descriptor;
    if (flags == NULL) return CDISASM_STATUS_INVALID_ARGUMENT;
    memset(flags, 0, sizeof(*flags));
    if (family < CDISASM_MIPS_FAMILY_FIRST || family > CDISASM_MIPS_FAMILY_LAST)
        return CDISASM_STATUS_INVALID_ARGUMENT;
    descriptor = cdisasm_mips_family_descriptor_get(family);
    flags->bitmap[0] = descriptor->required_flags;
    if (family == CDISASM_MIPS_FAMILY_INTERAPTIV_MR2) flags->bitmap[1] = CDISASM_MIPS_DECODE_FLAG_INTERAPTIV_MR2;
    if (family == CDISASM_MIPS_FAMILY_CNMIPS2) flags->bitmap[1] = CDISASM_MIPS_DECODE_FLAG_CNMIPS2;
    if (family == CDISASM_MIPS_FAMILY_CNMIPS3) flags->bitmap[1] = CDISASM_MIPS_DECODE_FLAG_CNMIPS2 | CDISASM_MIPS_DECODE_FLAG_CNMIPS3;
    return CDISASM_STATUS_OK;
}

cdisasm_mips_family_mask CDISASM_CALL cdisasm_mips_family_mask_from_flags_v3(const cdisasm_mips_decode_flags *flags)
{
    cdisasm_mips_decode_flags lower;
    cdisasm_mips_family_mask families;
    size_t n;
    if (flags == NULL || !flags_known(flags)) return CDISASM_MIPS_FAMILY_MASK_NONE;
    lower = *flags;
    lower.bitmap[1] = 0;
    families = cdisasm_mips_family_mask_from_flags(&lower);
    for (n = 0; n < sizeof(upper_families)/sizeof(upper_families[0]); ++n)
        if ((flags->bitmap[1] & upper_families[n].selector) != 0)
            families |= UINT64_C(1) << (upper_families[n].family - 1u);
    return families;
}

static uint64_t upper_selectors(cdisasm_mips_family_mask families)
{
    uint64_t selectors = 0;
    size_t n;
    for (n = 0; n < sizeof(upper_families)/sizeof(upper_families[0]); ++n)
        if ((families & (UINT64_C(1) << (upper_families[n].family - 1u))) != 0)
            selectors |= upper_families[n].selector;
    return selectors;
}

/* Processor/ISA applicability is separate from build availability so a
 * compiled-out selection has an unsupported status instead of a false CPU. */
static cdisasm_mips_family_mask upper_physical(cdisasm_mips_cpu_id cpu, cdisasm_mips_mode mode,
    cdisasm_mips_revision revision, cdisasm_mips_encoding encoding)
{
    cdisasm_mips_family_mask result = 0;
    if (mode == CDISASM_MIPS_MODE_32 && revision == CDISASM_MIPS_REVISION_32R3 &&
        (cpu == CDISASM_MIPS_CPU_ANY || cpu == CDISASM_MIPS_CPU_INTERAPTIV_MR2 || cpu == CDISASM_MIPS_CPU_INTERAPTIV_MR2_FPU) &&
        (encoding == CDISASM_MIPS_ENCODING_STANDARD || encoding == CDISASM_MIPS_ENCODING_MIPS16))
        result |= CDISASM_MIPS_FAMILY_MASK_INTERAPTIV_MR2;
    if (mode == CDISASM_MIPS_MODE_64 && encoding == CDISASM_MIPS_ENCODING_STANDARD &&
        ((cpu == CDISASM_MIPS_CPU_ANY && (revision == CDISASM_MIPS_REVISION_64R2 || revision == CDISASM_MIPS_REVISION_64R5)) ||
         (cpu == CDISASM_MIPS_CPU_OCTEON2 && revision == CDISASM_MIPS_REVISION_64R2) ||
         (cpu == CDISASM_MIPS_CPU_OCTEON3 && revision == CDISASM_MIPS_REVISION_64R5))) {
        result |= CDISASM_MIPS_FAMILY_MASK_CNMIPS2;
        if (revision == CDISASM_MIPS_REVISION_64R5) result |= CDISASM_MIPS_FAMILY_MASK_CNMIPS3;
    }
    return result;
}

static cdisasm_mips_family_mask upper_available(cdisasm_mips_cpu_id cpu, cdisasm_mips_mode mode,
    cdisasm_mips_revision revision, cdisasm_mips_encoding encoding)
{
#if USE_EXTRA_OPCODES
    cdisasm_mips_family_mask result = upper_physical(cpu, mode, revision, encoding) & CDISASM_MIPS_BUILD_FAMILY_MASK;
    if (encoding == CDISASM_MIPS_ENCODING_MIPS16 && !USE_MIPS_MIPS16E2)
        result &= ~CDISASM_MIPS_FAMILY_MASK_INTERAPTIV_MR2;
    return result;
#else
    (void)cpu; (void)mode; (void)revision; (void)encoding;
    return 0;
#endif
}

static cdisasm_mips_family_mask upper_dependencies(cdisasm_mips_family_id family, cdisasm_mips_encoding encoding)
{
    cdisasm_mips_decode_flags required;
    cdisasm_mips_family_mask result;
    if (cdisasm_mips_family_decode_flags_v3(family, &required) != CDISASM_STATUS_OK) return 0;
    result = cdisasm_mips_family_mask_from_flags_v3(&required);
    if (family == CDISASM_MIPS_FAMILY_INTERAPTIV_MR2 && encoding == CDISASM_MIPS_ENCODING_MIPS16)
        result |= CDISASM_MIPS_FAMILY_MASK_MIPS16E2;
    return result;
}

static int upper_selection_valid(const cdisasm_mips_decode_context_v3 *context)
{
    size_t n;
    for (n = 0; n < sizeof(upper_families)/sizeof(upper_families[0]); ++n) {
        cdisasm_mips_family_mask own = UINT64_C(1) << (upper_families[n].family - 1u);
        cdisasm_mips_family_mask required;
        if ((context->family_value & own) == 0) continue;
        required = upper_dependencies(upper_families[n].family, context->encoding);
        if ((context->family_value & required) != required ||
            (context->flags.bitmap[1] & upper_families[n].selector) == 0) return 0;
    }
    if ((context->family_value & (CDISASM_MIPS_FAMILY_MASK_CNMIPS2 | CDISASM_MIPS_FAMILY_MASK_CNMIPS3)) != 0 &&
        (context->family_value & ~(CDISASM_MIPS_FAMILY_MASK_CNMIPS | CDISASM_MIPS_FAMILY_MASK_CNMIPSP |
            CDISASM_MIPS_FAMILY_MASK_COP2 | CDISASM_MIPS_FAMILY_MASK_VZ |
            CDISASM_MIPS_FAMILY_MASK_CNMIPS2 | CDISASM_MIPS_FAMILY_MASK_CNMIPS3)) != 0) return 0;
    return 1;
}

static int is_octeon(const cdisasm_mips_instruction_v3 *instruction)
{
    return (instruction->required_flags.bitmap[1] & (CDISASM_MIPS_DECODE_FLAG_CNMIPS2 | CDISASM_MIPS_DECODE_FLAG_CNMIPS3)) != 0;
}

static int mr2_available(cdisasm_mips_cpu_id cpu, cdisasm_mips_mode mode, cdisasm_mips_revision revision,
    cdisasm_mips_encoding encoding)
{
#if USE_EXTRA_OPCODES && USE_MIPS_INTERAPTIV_MR2
    return mode == CDISASM_MIPS_MODE_32 && revision == CDISASM_MIPS_REVISION_32R3 &&
        (cpu == CDISASM_MIPS_CPU_ANY || cpu == CDISASM_MIPS_CPU_INTERAPTIV_MR2 || cpu == CDISASM_MIPS_CPU_INTERAPTIV_MR2_FPU) &&
        (encoding == CDISASM_MIPS_ENCODING_STANDARD || (encoding == CDISASM_MIPS_ENCODING_MIPS16 && USE_MIPS_MIPS16E2));
#else
    (void)cpu; (void)mode; (void)revision; (void)encoding;
    return 0;
#endif
}

static void to_v2(const cdisasm_mips_instruction_v3 *source, cdisasm_mips_instruction_v2 *target)
{
    memset(target, 0, sizeof(*target));
    target->instruction = source->instruction;
    memcpy(target->raw_bytes, source->raw_bytes, sizeof(target->raw_bytes));
    target->encoding = source->encoding;
    target->structure_version = CDISASM_MIPS_V2_STRUCTURE_VERSION;
    target->required_flags = source->required_flags.bitmap[0];
}

static int replay_v3(const cdisasm_mips_instruction_v3 *instruction, cdisasm_mips_instruction_v3 *canonical)
{
    cdisasm_mips_decode_flags flags;
    if (instruction == NULL || instruction->structure_version != CDISASM_MIPS_V3_STRUCTURE_VERSION ||
        instruction->structure_size != sizeof(*instruction) || instruction->reserved != 0 ||
        instruction->instruction.opcode_size > sizeof(instruction->raw_bytes) ||
        !flags_known(&instruction->required_flags)) return 0;
    flags = instruction->required_flags;
    flags.bitmap[0] |= CDISASM_MIPS_DECODE_FLAG_EXPLICIT_FAMILIES;
    if (cdisasm_mips_decode_v3(CDISASM_MIPS_CPU_ANY, instruction->instruction.mode,
        instruction->raw_bytes, instruction->instruction.opcode_size, instruction->instruction.address,
        &flags, canonical) == 0) return 0;
    return memcmp(instruction, canonical, sizeof(*canonical)) == 0;
}

/* A real supported VFPU instruction validates the active processor, exact ISA,
 * encoding and family policy. An available CPU capability alone is insufficient
 * when the caller disabled Allegrex in an explicit selection. */
static cdisasm_status unverified_policy(cdisasm_mips_cpu_id cpu_id, cdisasm_mips_mode mode,
    uint64_t address, const cdisasm_mips_decode_flags *flags, cdisasm_mips_instruction_v2 *probe)
{
#if USE_EXTRA_OPCODES && USE_MIPS_ALLEGREX && USE_MIPS_ALLEGREX_UNVERIFIED
    const uint8_t little[] = {0, 0, 0, 0x60}, big[] = {0x60, 0, 0, 0};
    const uint8_t *bytes = flags->bitmap[0] & CDISASM_MIPS_DECODE_FLAG_BIG_ENDIAN ? big : little;
    if (mode != CDISASM_MIPS_MODE_32 || (flags->bitmap[0] & CDISASM_MIPS_DECODE_FLAG_ENCODING_MASK) != 0)
        return CDISASM_STATUS_INVALID_ARGUMENT;
    if ((flags->bitmap[0] & (CDISASM_MIPS_DECODE_FLAG_FEATURE_MASK | CDISASM_MIPS_DECODE_FLAG_EXPLICIT_FAMILIES)) != 0 &&
        (flags->bitmap[0] & CDISASM_MIPS_DECODE_FLAG_ALLEGREX) == 0)
        return CDISASM_STATUS_INVALID_ARGUMENT;
    if (!cdisasm_mips_decode_v2(cpu_id, mode, bytes, 4, address, flags, probe))
        return probe->instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION ?
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION : CDISASM_STATUS_INVALID_ARGUMENT;
    if (probe->instruction.revision != CDISASM_MIPS_REVISION_32R1 ||
        (probe->required_flags & CDISASM_MIPS_DECODE_FLAG_ALLEGREX) == 0)
        return CDISASM_STATUS_INVALID_ARGUMENT;
    return CDISASM_STATUS_OK;
#else
    (void)cpu_id; (void)mode; (void)address; (void)flags; (void)probe;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
}

/* Rebuild immutable policy fields from the current CPU/build capabilities.
 * The zero-byte decode validates selected-family dependencies and FPR layout
 * without reading caller code or accepting a merely plausible context. */
static int context_to_v2(const cdisasm_mips_decode_context_v3 *context, cdisasm_mips_decode_context *target)
{
    cdisasm_mips_decode_context expected;
    cdisasm_mips_instruction_v2 probe;
    uint64_t option_mask;
    cdisasm_mips_family_mask upper_family;
    if (context == NULL || context->structure_version != CDISASM_MIPS_V3_STRUCTURE_VERSION ||
        context->structure_size != sizeof(*context) || context->reserved != 0 || !flags_known(&context->flags) ||
        cdisasm_mips_cpu_decode_context_v2(context->cpu_id, context->mode, context->revision,
            context->encoding, &expected) != CDISASM_STATUS_OK) return 0;
    upper_family = upper_available(context->cpu_id, context->mode, context->revision, context->encoding);
    option_mask = CDISASM_MIPS_DECODE_FLAG_ISA_MASK | CDISASM_MIPS_DECODE_FLAG_ENCODING_MASK;
    if (context->revision != expected.revision || context->family_mask != (expected.family_mask | upper_family) ||
        (context->family_value & ~context->family_mask) != 0 ||
        (context->flags.bitmap[0] & option_mask) != (expected.flags.bitmap[0] & option_mask) ||
        (context->flags.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_EXPLICIT_FAMILIES) == 0 ||
        (context->flags.bitmap[0] & ~(expected.flags.bitmap[0] | CDISASM_MIPS_DECODE_FLAG_BIG_ENDIAN |
            CDISASM_MIPS_DECODE_FLAG_FPR32)) != 0) return 0;
    *target = expected;
    target->flags = context->flags;
    target->flags.bitmap[1] = 0;
    if ((context->flags.bitmap[1] & CDISASM_MIPS_DECODE_FLAG_ALLEGREX_UNVERIFIED) != 0) {
#if USE_EXTRA_OPCODES && USE_MIPS_ALLEGREX && USE_MIPS_ALLEGREX_UNVERIFIED
        if (context->mode != CDISASM_MIPS_MODE_32 || context->encoding != CDISASM_MIPS_ENCODING_STANDARD ||
            (context->family_mask & CDISASM_MIPS_FAMILY_MASK_ALLEGREX) == 0) return 0;
#else
        return 0;
#endif
    }
    if ((context->flags.bitmap[1] & V3_SELECTORS & ~upper_selectors(upper_family)) != 0 ||
        !upper_selection_valid(context)) return 0;
    target->family_value = context->family_value & ~V3_FAMILIES;
    cdisasm_mips_decode_with_context_v2(target, NULL, 0, 0, &probe);
    return probe.instruction.last_error_id == CDISASM_STATUS_END_OF_INPUT;
}

cdisasm_status CDISASM_CALL cdisasm_mips_cpu_decode_flag_mask_v3(cdisasm_mips_cpu_id cpu_id,
    cdisasm_mips_mode mode, cdisasm_mips_decode_flags *flags)
{
    cdisasm_status status = cdisasm_mips_cpu_decode_flag_mask(cpu_id, mode, flags);
#if USE_EXTRA_OPCODES && USE_MIPS_ALLEGREX && USE_MIPS_ALLEGREX_UNVERIFIED
    if (status == CDISASM_STATUS_OK && mode == CDISASM_MIPS_MODE_32 &&
        (flags->bitmap[0] & CDISASM_MIPS_DECODE_FLAG_ALLEGREX) != 0)
        flags->bitmap[1] = CDISASM_MIPS_DECODE_FLAG_ALLEGREX_UNVERIFIED;
#endif
    if (status == CDISASM_STATUS_OK) {
        cdisasm_mips_family_mask upper = upper_available(cpu_id, mode, CDISASM_MIPS_REVISION_32R3, CDISASM_MIPS_ENCODING_STANDARD) |
            upper_available(cpu_id, mode, CDISASM_MIPS_REVISION_64R2, CDISASM_MIPS_ENCODING_STANDARD) |
            upper_available(cpu_id, mode, CDISASM_MIPS_REVISION_64R5, CDISASM_MIPS_ENCODING_STANDARD);
        flags->bitmap[1] |= upper_selectors(upper);
    }
    return status;
}

cdisasm_status CDISASM_CALL cdisasm_mips_cpu_decode_context_v3(cdisasm_mips_cpu_id cpu_id,
    cdisasm_mips_mode mode, cdisasm_mips_revision revision, cdisasm_mips_encoding encoding,
    cdisasm_mips_decode_context_v3 *context)
{
    cdisasm_mips_decode_context legacy;
    cdisasm_status status;
    if (context == NULL) return CDISASM_STATUS_INVALID_ARGUMENT;
    memset(context, 0, sizeof(*context));
    status = cdisasm_mips_cpu_decode_context_v2(cpu_id, mode, revision, encoding, &legacy);
    if (status != CDISASM_STATUS_OK) return status;
    context->structure_version = CDISASM_MIPS_V3_STRUCTURE_VERSION;
    context->structure_size = (uint32_t)sizeof(*context);
    context->cpu_id = legacy.cpu_id;
    context->mode = legacy.mode;
    context->revision = legacy.revision;
    context->encoding = encoding;
    context->flags = legacy.flags;
    context->family_mask = legacy.family_mask;
    context->family_value = legacy.family_value;
    {
        cdisasm_mips_family_mask upper = upper_available(cpu_id, mode, legacy.revision, encoding);
        context->family_mask |= upper;
        context->flags.bitmap[1] |= upper_selectors(upper);
        if (cpu_id != CDISASM_MIPS_CPU_ANY) context->family_value |= upper;
    }
    return CDISASM_STATUS_OK;
}

int CDISASM_CALL cdisasm_mips_decode_context_add_family_v3(cdisasm_mips_decode_context_v3 *context,
    cdisasm_mips_family_id family_id)
{
    cdisasm_mips_decode_context legacy;
    cdisasm_mips_decode_context_v3 proposed;
    cdisasm_mips_family_mask own;
    if (!context_to_v2(context, &legacy) || family_id < CDISASM_MIPS_FAMILY_FIRST || family_id > CDISASM_MIPS_FAMILY_LAST) return 0;
    own = UINT64_C(1) << (family_id - 1u);
    proposed = *context;
    if ((own & V3_FAMILIES) != 0) {
        cdisasm_mips_family_mask required = upper_dependencies(family_id, context->encoding);
        if ((required & context->family_mask) != required ||
            (upper_selectors(required) & context->flags.bitmap[1]) != upper_selectors(required)) return 0;
        proposed.family_value |= required;
    } else {
        if (!cdisasm_mips_decode_context_add_family(&legacy, family_id)) return 0;
        proposed.family_value = legacy.family_value | (context->family_value & V3_FAMILIES);
    }
    if (!context_to_v2(&proposed, &legacy)) return 0;
    *context = proposed;
    return 1;
}

int CDISASM_CALL cdisasm_mips_decode_context_remove_family_v3(cdisasm_mips_decode_context_v3 *context,
    cdisasm_mips_family_id family_id)
{
    cdisasm_mips_decode_context legacy;
    cdisasm_mips_family_mask own;
    size_t n;
    if (!context_to_v2(context, &legacy) || family_id < CDISASM_MIPS_FAMILY_FIRST || family_id > CDISASM_MIPS_FAMILY_LAST) return 0;
    own = UINT64_C(1) << (family_id - 1u);
    if ((own & V3_FAMILIES) != 0) {
        if ((context->family_mask & own) == 0) return 0;
        context->family_value &= ~own;
    }
    else {
        if (!cdisasm_mips_decode_context_remove_family(&legacy, family_id)) return 0;
        context->family_value = legacy.family_value | (context->family_value & V3_FAMILIES);
    }
    for (n = 0; n < sizeof(upper_families)/sizeof(upper_families[0]); ++n) {
        cdisasm_mips_family_mask required = upper_dependencies(upper_families[n].family, context->encoding);
        if ((context->family_value & required) != required)
            context->family_value &= ~(UINT64_C(1) << (upper_families[n].family - 1u));
    }
    return 1;
}

cdisasm_mips_family_mask CDISASM_CALL cdisasm_mips_decode_context_get_available_families_v3(
    const cdisasm_mips_decode_context_v3 *context)
{
    cdisasm_mips_decode_context legacy;
    return context_to_v2(context, &legacy) ? context->family_mask : CDISASM_MIPS_FAMILY_MASK_NONE;
}

cdisasm_mips_family_mask CDISASM_CALL cdisasm_mips_decode_context_get_set_families_v3(
    const cdisasm_mips_decode_context_v3 *context)
{
    cdisasm_mips_decode_context legacy;
    return context_to_v2(context, &legacy) ? context->family_value : CDISASM_MIPS_FAMILY_MASK_NONE;
}

uint32_t CDISASM_CALL cdisasm_mips_decode_v3(cdisasm_mips_cpu_id cpu_id, cdisasm_mips_mode mode,
    const uint8_t *code, size_t code_size, uint64_t address, const cdisasm_mips_decode_flags *flags,
    cdisasm_mips_instruction_v3 *instruction)
{
    cdisasm_mips_decode_flags snapshot = CDISASM_MIPS_DECODE_FLAGS_NONE_INITIALIZER;
    cdisasm_mips_instruction_v2 legacy, probe = {0};
    cdisasm_status status;
    uint32_t size;
    int requested, requested_mr2, default_mr2 = 0, default_octeon = 0;
    uint64_t requested_octeon;

    if (instruction == NULL) return 0;
    if (flags != NULL) snapshot = *flags;
    if (!flags_known(&snapshot)) return fail_v3(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
    if ((cpu_id == CDISASM_MIPS_CPU_INTERAPTIV_MR2 || cpu_id == CDISASM_MIPS_CPU_INTERAPTIV_MR2_FPU) &&
        (snapshot.bitmap[0] & (CDISASM_MIPS_DECODE_FLAG_FEATURE_MASK | CDISASM_MIPS_DECODE_FLAG_EXPLICIT_FAMILIES)) == 0 &&
        mode == CDISASM_MIPS_MODE_32 &&
        ((snapshot.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_ENCODING_MASK) == 0 ||
         (snapshot.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_ENCODING_MASK) == CDISASM_MIPS_DECODE_FLAG_MIPS16))
    {
        snapshot.bitmap[1] |= CDISASM_MIPS_DECODE_FLAG_INTERAPTIV_MR2;
        default_mr2 = 1;
    }
    if ((cpu_id == CDISASM_MIPS_CPU_OCTEON2 || cpu_id == CDISASM_MIPS_CPU_OCTEON3) &&
        (snapshot.bitmap[0] & (CDISASM_MIPS_DECODE_FLAG_FEATURE_MASK | CDISASM_MIPS_DECODE_FLAG_EXPLICIT_FAMILIES)) == 0 &&
        (snapshot.bitmap[1] & V3_SELECTORS) == 0 && mode == CDISASM_MIPS_MODE_64 &&
        (snapshot.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_ENCODING_MASK) == 0) {
        cdisasm_mips_revision default_revision = cpu_id == CDISASM_MIPS_CPU_OCTEON3 ?
            CDISASM_MIPS_REVISION_64R5 : CDISASM_MIPS_REVISION_64R2;
        snapshot.bitmap[1] |= upper_selectors(upper_available(cpu_id, mode, default_revision, CDISASM_MIPS_ENCODING_STANDARD));
        default_octeon = 1;
    }
    requested_octeon = snapshot.bitmap[1] & (CDISASM_MIPS_DECODE_FLAG_CNMIPS2 | CDISASM_MIPS_DECODE_FLAG_CNMIPS3);
    requested = (snapshot.bitmap[1] & CDISASM_MIPS_DECODE_FLAG_ALLEGREX_UNVERIFIED) != 0;
    requested_mr2 = (snapshot.bitmap[1] & CDISASM_MIPS_DECODE_FLAG_INTERAPTIV_MR2) != 0;
    snapshot.bitmap[1] = 0;
    if ((requested && requested_mr2) || (requested_octeon != 0 && (requested || requested_mr2)))
        return fail_v3(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
    size = cdisasm_mips_decode_v2(cpu_id, mode, code, code_size, address, &snapshot, &legacy);
    if (!size && legacy.instruction.last_error_id != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION &&
        legacy.instruction.last_error_id != CDISASM_STATUS_INVALID_INSTRUCTION)
        return fail_v3(instruction, legacy.instruction.last_error_id);
    if (requested) {
        status = unverified_policy(cpu_id, mode, address, &snapshot, &probe);
        if (status != CDISASM_STATUS_OK) return fail_v3(instruction, status);
    }
    if (requested_octeon != 0) {
        cdisasm_mips_decode_context context;
        cdisasm_mips_revision revision = CDISASM_MIPS_REVISION_NONE;
        cdisasm_mips_family_mask physical, available;
        const uint64_t isa = snapshot.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_ISA_MASK;
        const uint64_t allowed = CDISASM_MIPS_DECODE_FLAG_CNMIPS | CDISASM_MIPS_DECODE_FLAG_CNMIPSP |
            CDISASM_MIPS_DECODE_FLAG_COP2 | CDISASM_MIPS_DECODE_FLAG_VZ;
        unsigned generation = (requested_octeon & CDISASM_MIPS_DECODE_FLAG_CNMIPS3) != 0 ? 3u : 2u;
        uint32_t raw = 0;
        if (mode != CDISASM_MIPS_MODE_64 || (snapshot.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_ENCODING_MASK) != 0 ||
            (isa != 0 && isa != CDISASM_MIPS_DECODE_FLAG_ISA_64R2 && isa != CDISASM_MIPS_DECODE_FLAG_ISA_64R5) ||
            (snapshot.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_FEATURE_MASK & ~allowed) != 0 ||
            (!default_octeon && (snapshot.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_CNMIPS) == 0) ||
            ((requested_octeon & CDISASM_MIPS_DECODE_FLAG_CNMIPS3) != 0 &&
             (requested_octeon & CDISASM_MIPS_DECODE_FLAG_CNMIPS2) == 0))
            return fail_v3(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
        if (isa == CDISASM_MIPS_DECODE_FLAG_ISA_64R2) revision = CDISASM_MIPS_REVISION_64R2;
        if (isa == CDISASM_MIPS_DECODE_FLAG_ISA_64R5) revision = CDISASM_MIPS_REVISION_64R5;
        if (cdisasm_mips_cpu_decode_context_v2(cpu_id, mode, revision, CDISASM_MIPS_ENCODING_STANDARD, &context) != CDISASM_STATUS_OK)
            return fail_v3(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
        physical = upper_physical(cpu_id, mode, context.revision, CDISASM_MIPS_ENCODING_STANDARD);
        available = upper_available(cpu_id, mode, context.revision, CDISASM_MIPS_ENCODING_STANDARD);
        if ((requested_octeon & ~upper_selectors(physical)) != 0 ||
            (context.revision != CDISASM_MIPS_REVISION_64R5 && (snapshot.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_VZ) != 0))
            return fail_v3(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
        if (code != NULL && code_size >= 4u) {
            raw = snapshot.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_BIG_ENDIAN ?
                ((uint32_t)code[0] << 24) | ((uint32_t)code[1] << 16) | ((uint32_t)code[2] << 8) | code[3] :
                code[0] | ((uint32_t)code[1] << 8) | ((uint32_t)code[2] << 16) | ((uint32_t)code[3] << 24);
        }
        if ((requested_octeon & ~upper_selectors(available)) != 0) {
            if (default_octeon && size && !cdisasm_mips_octeon_owns(raw, generation)) {
                from_v2(&legacy, instruction);
                return size;
            }
            return fail_v3(instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        }
        if (code != NULL && code_size >= 4u) {
            cdisasm_mips_instruction_v2 source;
            memset(&source, 0, sizeof(source));
            source.instruction.address = address;
            status = cdisasm_mips_octeon_decode(raw, mode, context.revision, generation, &source.instruction);
            if (status == CDISASM_STATUS_OK) {
                memcpy(source.raw_bytes, code, 4u);
                source.encoding = CDISASM_MIPS_ENCODING_STANDARD;
                source.required_flags = (context.flags.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_ISA_MASK) |
                    CDISASM_MIPS_DECODE_FLAG_CNMIPS | (snapshot.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_BIG_ENDIAN);
                from_v2(&source, instruction);
                instruction->required_flags.bitmap[1] = CDISASM_MIPS_DECODE_FLAG_CNMIPS2;
                if (cdisasm_mips_octeon_form_generation(source.instruction.form_id) == 3u)
                    instruction->required_flags.bitmap[1] |= CDISASM_MIPS_DECODE_FLAG_CNMIPS3;
                return 4u;
            }
            if (status != CDISASM_STATUS_UNSUPPORTED_INSTRUCTION || cdisasm_mips_octeon_owns(raw, generation))
                return fail_v3(instruction, status);
        }
    }
    if (requested_mr2) {
        cdisasm_mips_decode_context context;
        cdisasm_mips_encoding encoding = (snapshot.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_MIPS16) ? CDISASM_MIPS_ENCODING_MIPS16 :
            (snapshot.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_ENCODING_MASK) ? UINT32_MAX : CDISASM_MIPS_ENCODING_STANDARD;
        uint64_t isa = snapshot.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_ISA_MASK;
        if (requested || mode != CDISASM_MIPS_MODE_32 ||
            (cpu_id != CDISASM_MIPS_CPU_ANY && cpu_id != CDISASM_MIPS_CPU_INTERAPTIV_MR2 && cpu_id != CDISASM_MIPS_CPU_INTERAPTIV_MR2_FPU) ||
            (isa != 0 && isa != CDISASM_MIPS_DECODE_FLAG_ISA_32R3) || (cpu_id == CDISASM_MIPS_CPU_ANY && isa == 0) ||
            cdisasm_mips_cpu_decode_context_v2(cpu_id, mode, CDISASM_MIPS_REVISION_32R3, encoding, &context) != CDISASM_STATUS_OK)
            return fail_v3(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
        if ((snapshot.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_FEATURE_MASK &
            ~(CDISASM_MIPS_DECODE_FLAG_FPU | CDISASM_MIPS_DECODE_FLAG_DSP | CDISASM_MIPS_DECODE_FLAG_DSPR2 |
              CDISASM_MIPS_DECODE_FLAG_MT | CDISASM_MIPS_DECODE_FLAG_EVA | CDISASM_MIPS_DECODE_FLAG_MIPS16E2)) != 0)
            return fail_v3(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
        if ((cdisasm_mips_family_mask_from_flags(&snapshot) & ~CDISASM_MIPS_BUILD_FAMILY_MASK) != 0)
            return fail_v3(instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        if (!mr2_available(cpu_id, mode, context.revision, encoding)) {
            if (default_mr2 && size) {
                from_v2(&legacy, instruction);
                return size;
            }
            return fail_v3(instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        }
        if (encoding == CDISASM_MIPS_ENCODING_MIPS16 &&
            (snapshot.bitmap[0] & (CDISASM_MIPS_DECODE_FLAG_FEATURE_MASK | CDISASM_MIPS_DECODE_FLAG_EXPLICIT_FAMILIES)) != 0 &&
            (snapshot.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_MIPS16E2) == 0)
            return fail_v3(instruction, CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
        if (code != NULL && code_size >= 4u) {
            int big = (snapshot.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_BIG_ENDIAN) != 0;
            uint32_t raw;
            cdisasm_mips_instruction_v2 source;
            if (encoding == CDISASM_MIPS_ENCODING_MIPS16) {
                uint32_t first = big ? ((uint32_t)code[0] << 8) | code[1] : ((uint32_t)code[1] << 8) | code[0];
                uint32_t second = big ? ((uint32_t)code[2] << 8) | code[3] : ((uint32_t)code[3] << 8) | code[2];
                raw = (first << 16) | second;
            } else raw = big ? ((uint32_t)code[0] << 24) | ((uint32_t)code[1] << 16) | ((uint32_t)code[2] << 8) | code[3] :
                code[0] | ((uint32_t)code[1] << 8) | ((uint32_t)code[2] << 16) | ((uint32_t)code[3] << 24);
            memset(&source, 0, sizeof(source));
            source.instruction.address = address;
            source.instruction.opcode_size = 4u;
            source.instruction.mode = (uint8_t)mode;
            source.instruction.revision = CDISASM_MIPS_REVISION_32R3;
            if (cdisasm_mips_interaptiv_mr2_decode(raw, encoding, &source.instruction)) {
                memcpy(source.raw_bytes, code, 4u);
                source.encoding = encoding;
                source.required_flags = CDISASM_MIPS_DECODE_FLAG_ISA_32R3 |
                    (big ? CDISASM_MIPS_DECODE_FLAG_BIG_ENDIAN : 0) |
                    (encoding == CDISASM_MIPS_ENCODING_MIPS16 ? CDISASM_MIPS_DECODE_FLAG_MIPS16 | CDISASM_MIPS_DECODE_FLAG_MIPS16E2 : 0);
                from_v2(&source, instruction);
                instruction->required_flags.bitmap[1] = CDISASM_MIPS_DECODE_FLAG_INTERAPTIV_MR2;
                return 4u;
            }
        }
    }
    if (size) {
        /* A recognized ordinary instruction or exact alias never gains an
         * uncertainty marker solely because the caller enabled the policy. */
        from_v2(&legacy, instruction);
        return size;
    }
#if USE_EXTRA_OPCODES && USE_MIPS_ALLEGREX && USE_MIPS_ALLEGREX_UNVERIFIED
    if (requested && code_size >= 4 && code != NULL) {
        uint32_t raw = snapshot.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_BIG_ENDIAN ?
            ((uint32_t)code[0] << 24) | ((uint32_t)code[1] << 16) | ((uint32_t)code[2] << 8) | code[3] :
            code[0] | ((uint32_t)code[1] << 8) | ((uint32_t)code[2] << 16) | ((uint32_t)code[3] << 24);
        cdisasm_mips_instruction_v2 source;
        memset(&source, 0, sizeof(source));
        source.instruction.address = address;
        source.instruction.opcode_size = 4;
        source.instruction.mode = probe.instruction.mode;
        source.instruction.revision = probe.instruction.revision;
        source.instruction.instruction_flags = probe.instruction.instruction_flags & CDISASM_MIPS_INSTRUCTION_FLAG_FPR32;
        if (cdisasm_mips_allegrex_unverified_decode(raw, &source.instruction)) {
            memcpy(source.raw_bytes, code, 4);
            source.encoding = CDISASM_MIPS_ENCODING_STANDARD;
            source.structure_version = CDISASM_MIPS_V2_STRUCTURE_VERSION;
            source.required_flags = probe.required_flags;
            from_v2(&source, instruction);
            instruction->required_flags.bitmap[1] = CDISASM_MIPS_DECODE_FLAG_ALLEGREX_UNVERIFIED;
            return 4;
        }
    }
#endif
    return fail_v3(instruction, legacy.instruction.last_error_id);
}

uint32_t CDISASM_CALL cdisasm_mips_decode_with_context_v3(const cdisasm_mips_decode_context_v3 *context,
    const uint8_t *code, size_t code_size, uint64_t address, cdisasm_mips_instruction_v3 *instruction)
{
    cdisasm_mips_decode_context_v3 snapshot;
    cdisasm_mips_decode_context legacy_context;
    cdisasm_mips_instruction_v2 legacy;
    uint32_t size;
    if (instruction == NULL) return 0;
    if (context == NULL) return fail_v3(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
    snapshot = *context;
    if (!context_to_v2(&snapshot, &legacy_context)) return fail_v3(instruction, CDISASM_STATUS_INVALID_ARGUMENT);
    if (snapshot.flags.bitmap[1] != 0) {
        cdisasm_mips_decode_flags selected = snapshot.flags;
        uint64_t available = selected.bitmap[0] & CDISASM_MIPS_DECODE_FLAG_FEATURE_MASK;
        unsigned family;
        if ((snapshot.family_value & CDISASM_MIPS_FAMILY_MASK_ALLEGREX) == 0)
            selected.bitmap[1] &= ~CDISASM_MIPS_DECODE_FLAG_ALLEGREX_UNVERIFIED;
        selected.bitmap[1] = (selected.bitmap[1] & ~V3_SELECTORS) |
            (selected.bitmap[1] & upper_selectors(snapshot.family_value));
        selected.bitmap[0] &= ~CDISASM_MIPS_DECODE_FLAG_FEATURE_MASK;
        for (family = CDISASM_MIPS_FAMILY_FIRST; family <= CDISASM_MIPS_FAMILY_LAST; ++family) {
            if ((snapshot.family_value & (UINT64_C(1) << (family - 1))) != 0) {
                const cdisasm_mips_family_descriptor *descriptor = cdisasm_mips_family_descriptor_get((cdisasm_mips_family_id)family);
                selected.bitmap[0] |= descriptor->required_flags & available;
            }
        }
        return cdisasm_mips_decode_v3(snapshot.cpu_id, snapshot.mode, code, code_size, address, &selected, instruction);
    }
    size = cdisasm_mips_decode_with_context_v2(&legacy_context, code, code_size, address, &legacy);
    if (size == 0) return fail_v3(instruction, legacy.instruction.last_error_id);
    from_v2(&legacy, instruction);
    return size;
}

int CDISASM_CALL cdisasm_mips_instruction_validate_v3(const cdisasm_mips_instruction_v3 *instruction)
{
    cdisasm_mips_instruction_v3 canonical;
    return replay_v3(instruction, &canonical);
}

int CDISASM_CALL cdisasm_mips_instruction_is_unverified_v3(const cdisasm_mips_instruction_v3 *instruction)
{
    cdisasm_mips_instruction_v3 canonical;
    return replay_v3(instruction, &canonical) && is_unverified(&canonical);
}

uint32_t CDISASM_CALL cdisasm_mips_replay_v3(const cdisasm_mips_instruction_v3 *instruction,
    cdisasm_mips_instruction_v3 *result)
{
    cdisasm_mips_instruction_v3 canonical;
    if (result == NULL) return 0;
    if (!replay_v3(instruction, &canonical)) return fail_v3(result, CDISASM_STATUS_INVALID_ARGUMENT);
    *result = canonical;
    return canonical.instruction.opcode_size;
}

size_t CDISASM_CALL cdisasm_mips_register_effects_v3(const cdisasm_mips_instruction_v3 *instruction,
    cdisasm_mips_register_effect *effects, size_t capacity)
{
    cdisasm_mips_instruction_v3 canonical;
    cdisasm_mips_instruction_v2 legacy;
    if (!replay_v3(instruction, &canonical) || is_unverified(&canonical)) return 0;
    if (is_mr2(&canonical)) return cdisasm_mips_v3_effects_numeric(&canonical.instruction, effects, capacity);
    if (is_octeon(&canonical)) return cdisasm_mips_octeon_effects(&canonical.instruction, effects, capacity);
    to_v2(&canonical, &legacy);
    return cdisasm_mips_register_effects_v2(&legacy, effects, capacity);
}

cdisasm_mips_effect_limitations CDISASM_CALL cdisasm_mips_register_effect_limitations_v3(
    const cdisasm_mips_instruction_v3 *instruction)
{
    cdisasm_mips_instruction_v3 canonical;
    cdisasm_mips_instruction_v2 legacy;
    if (!replay_v3(instruction, &canonical)) return CDISASM_MIPS_EFFECT_LIMITATION_INVALID;
    if (is_unverified(&canonical)) return CDISASM_MIPS_EFFECT_LIMITATION_EXPLICIT_OPERANDS |
        CDISASM_MIPS_EFFECT_LIMITATION_IMPLICIT_EFFECTS | CDISASM_MIPS_EFFECT_LIMITATION_REGISTER_ALIASES;
    if (is_mr2(&canonical)) return CDISASM_MIPS_EFFECT_LIMITATION_IMPLICIT_EFFECTS;
    if (is_octeon(&canonical)) return cdisasm_mips_octeon_effect_limitations(canonical.instruction.form_id);
    to_v2(&canonical, &legacy);
    return cdisasm_mips_register_effect_limitations_v2(&legacy);
}

cdisasm_mips_family_mask CDISASM_CALL cdisasm_mips_instruction_family_mask_v3(
    const cdisasm_mips_instruction_v3 *instruction)
{
    cdisasm_mips_instruction_v3 canonical;
    cdisasm_mips_instruction_v2 legacy;
    if (!replay_v3(instruction, &canonical)) return CDISASM_MIPS_FAMILY_MASK_NONE;
    if (is_unverified(&canonical)) return CDISASM_MIPS_FAMILY_MASK_ALLEGREX;
    if (is_octeon(&canonical)) return cdisasm_mips_family_mask_from_flags_v3(&canonical.required_flags);
    if (is_mr2(&canonical)) return CDISASM_MIPS_FAMILY_MASK_INTERAPTIV_MR2 |
        (canonical.encoding == CDISASM_MIPS_ENCODING_MIPS16 ? CDISASM_MIPS_FAMILY_MASK_MIPS16E2 : 0);
    to_v2(&canonical, &legacy);
    return cdisasm_mips_instruction_family_mask_v2(&legacy);
}

cdisasm_mips_family_id CDISASM_CALL cdisasm_mips_instruction_family_v3(const cdisasm_mips_instruction_v3 *instruction)
{
    cdisasm_mips_instruction_v3 canonical;
    cdisasm_mips_instruction_v2 legacy;
    if (!replay_v3(instruction, &canonical)) return CDISASM_MIPS_FAMILY_NONE;
    if (is_unverified(&canonical)) return CDISASM_MIPS_FAMILY_ALLEGREX;
    if (is_octeon(&canonical)) return cdisasm_mips_octeon_form_generation(canonical.instruction.form_id) == 3u ?
        CDISASM_MIPS_FAMILY_CNMIPS3 : CDISASM_MIPS_FAMILY_CNMIPS2;
    if (is_mr2(&canonical)) return CDISASM_MIPS_FAMILY_INTERAPTIV_MR2;
    to_v2(&canonical, &legacy);
    return cdisasm_mips_instruction_family_v2(&legacy);
}

#if USE_DISASM_FORMAT
size_t CDISASM_CALL cdisasm_mips_format_v3(const cdisasm_mips_instruction_v3 *instruction,
    uint32_t flags, char *buffer, size_t buffer_size)
{
    cdisasm_mips_instruction_v3 canonical;
    cdisasm_mips_instruction_v2 legacy;
    if (!replay_v3(instruction, &canonical)) {
        if (buffer != NULL && buffer_size != 0) buffer[0] = '\0';
        return 0;
    }
    if (is_unverified(&canonical))
        return cdisasm_mips_allegrex_unverified_format(&canonical.instruction, flags, buffer, buffer_size);
    if (is_mr2(&canonical) || is_octeon(&canonical)) return cdisasm_mips_v3_format_numeric(&canonical.instruction, flags, buffer, buffer_size);
    to_v2(&canonical, &legacy);
    return cdisasm_mips_format_v2(&legacy, flags, buffer, buffer_size);
}
#endif
