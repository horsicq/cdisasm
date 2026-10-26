#include "mips_decoder.h"
#include <string.h>

/* Later Loongson MIPS processors retain the 64-bit multimedia COP2 bank.
 * No strings/tables are needed to preserve namespace ownership when optional
 * opcodes are excluded. A different ISA's LSX/LASX words are never matched. */
int cdisasm_mips_loongsimd_owns(uint32_t raw)
{
    return (raw & UINT32_C(0xff000000)) == UINT32_C(0x4b000000);
}

/* Selected-family ownership survives builds without optional opcode tables.
 * The primary memory macros allocate all ten displacement bits. Nonaligned
 * offsets are source-defined syntax with unverified execution legality. Other fields
 * are bounded exactly; dispatch selects this owner only for explicit ASX. */
int cdisasm_mips_loongasx_owns(uint32_t raw, const cdisasm_mips_decode_flags *features)
{
    uint32_t memory = raw & UINT32_C(0xfc00f83f);
    if (memory == UINT32_C(0xc8000819) || memory == UINT32_C(0xe8000819)) return 1;
    if ((raw & UINT32_C(0xfffef83f)) == UINT32_C(0x793a0819)) return 1;
    if ((raw & UINT32_C(0xfffe07ff)) == UINT32_C(0x78ba0059)) return 1;
    /* The primary COPY/INSERT macros define four 64-bit lane selectors. Low lanes
     * share ordinary MSA words: an explicit ASX request selects this syntax
     * only when MSA is absent. Active ASX also authenticates legacy API
     * replay, which has required flags but no private request marker. Named-CPU
     * defaults never activate ASX and keep their MSA identity. */
    if (((raw & UINT32_C(0xfffe07ff)) == UINT32_C(0x78b80059) ||
         (raw & UINT32_C(0xfffef83f)) == UINT32_C(0x79380819)) && features != NULL &&
        ((features->bitmap[0] | features->bitmap[CDISASM_MIPS_INTERNAL_POLICY_WORD]) &
         CDISASM_MIPS_DECODE_FLAG_LOONGASX) != 0 &&
        (features->bitmap[0] & CDISASM_MIPS_DECODE_FLAG_MSA) == 0) return 1;
    return (raw & UINT32_C(0xfff0003f)) == UINT32_C(0xed00000a);
}

#if USE_EXTRA_OPCODES && (USE_MIPS_LOONGSIMD || USE_MIPS_LOONGASX)
typedef struct loongsimd_form {
    uint32_t mask, value;
    uint16_t name, form;
    uint8_t kind, size, element, source_element, third_element;
} loongsimd_form;

static const loongsimd_form loongsimd_forms[] = {
#include "generated/mips_loongsimd_forms.inc"
};

typedef struct loongasx_kernel_form {
    uint32_t mask, value;
    uint16_t name, form;
    uint8_t kind;
} loongasx_kernel_form;

static const loongasx_kernel_form loongasx_kernel_forms[] = {
#include "generated/mips_loongasx_kernel_forms.inc"
};

static void loongsimd_register(cdisasm_mips_instruction *i, unsigned reg,
                               unsigned size, unsigned element, unsigned access, int hidden)
{
    cdisasm_mips_operand *o = &i->operand[i->operand_count++];
    o->type = CDISASM_OPERAND_REGISTER;
    o->reg = (cdisasm_mips_reg_id)reg;
    o->size = (uint8_t)size;
    o->detail.element_size = (uint8_t)element;
    o->access = (uint8_t)access;
    if (hidden) o->flags = CDISASM_OPERAND_FLAG_IMPLICIT;
}

static int loongsimd_revision(cdisasm_mips_revision revision)
{
    return revision == CDISASM_MIPS_REVISION_64R2 || revision == CDISASM_MIPS_REVISION_64R3 ||
           revision == CDISASM_MIPS_REVISION_64R5;
}
#endif

cdisasm_status cdisasm_mips_decode_loongsimd(uint32_t raw, uint64_t address, cdisasm_mips_mode mode,
                                           cdisasm_mips_revision revision, const cdisasm_mips_decode_flags *features,
                                           cdisasm_mips_instruction *instruction)
{
#if USE_EXTRA_OPCODES && (USE_MIPS_LOONGSIMD || USE_MIPS_LOONGASX)
    const uint64_t required = CDISASM_MIPS_DECODE_FLAG_LOONGSIMD |
                              CDISASM_MIPS_DECODE_FLAG_LOONGSON | CDISASM_MIPS_DECODE_FLAG_FPU;
    unsigned fd = (raw >> 6) & 31u, fs = (raw >> 11) & 31u, ft = (raw >> 16) & 31u;
    size_t n;
    int reserved = 0;
    if (!instruction || !features) return CDISASM_STATUS_INVALID_ARGUMENT;
    if (!cdisasm_mips_loongsimd_owns(raw)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    if ((features->bitmap[0] & required) != required) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    if (mode != CDISASM_MIPS_MODE_64 || !loongsimd_revision(revision)) return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    for (n = 0; n < sizeof(loongsimd_forms)/sizeof(loongsimd_forms[0]); ++n) {
        const loongsimd_form *f = &loongsimd_forms[n];
        cdisasm_mips_instruction candidate;
        /* Unused compare-result/unary-source fields are reserved zero. This
         * also distinguishes known malformed forms from unverified later
         * custom vector opcodes sharing the broad vendor namespace. */
        if ((raw & UINT32_C(0xffe0003f)) != f->value) continue;
        if ((raw & f->mask) != f->value) { reserved = 1; continue; }
        if (features->bitmap[0] & CDISASM_MIPS_DECODE_FLAG_FPR32) return CDISASM_STATUS_INVALID_INSTRUCTION;
        memset(&candidate, 0, sizeof(candidate));
        candidate.address = address;
        candidate.raw_instruction = raw;
        candidate.opcode_size = 4u;
        candidate.mode = (uint8_t)mode;
        candidate.revision = (uint8_t)revision;
        candidate.name_id = f->name;
        candidate.form_id = f->form;
        candidate.instruction_flags = CDISASM_MIPS_INSTRUCTION_FLAG_FLOATING_POINT;
        if (f->kind != 3u)
            loongsimd_register(&candidate, CDISASM_MIPS_REG_FPR0+fd, f->size, f->element, CDISASM_OPERAND_ACCESS_WRITE, 0);
        loongsimd_register(&candidate, CDISASM_MIPS_REG_FPR0+fs, f->size, f->source_element, CDISASM_OPERAND_ACCESS_READ, 0);
        if (f->kind != 2u) {
            /* Word arithmetic still assigns a complete64-bit FPR. Resource
             * widths are separate from the32-bit arithmetic operation. */
            loongsimd_register(&candidate, CDISASM_MIPS_REG_FPR0+ft, f->size, f->third_element, CDISASM_OPERAND_ACCESS_READ, 0);
        }
        if (f->kind == 3u)
            loongsimd_register(&candidate, CDISASM_MIPS_REG_FCC0, 1u, 0u, CDISASM_OPERAND_ACCESS_WRITE, 1);
        *instruction = candidate;
        return CDISASM_STATUS_OK;
    }
    return reserved ? CDISASM_STATUS_INVALID_INSTRUCTION : CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    (void)raw; (void)address; (void)mode; (void)revision; (void)features; (void)instruction;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
}

uint64_t cdisasm_mips_loongsimd_required_flags(cdisasm_mips_form_id form)
{
#if USE_EXTRA_OPCODES && (USE_MIPS_LOONGSIMD || USE_MIPS_LOONGASX)
    if (form >= 59000u && form < 59080u)
        return CDISASM_MIPS_DECODE_FLAG_LOONGSIMD | CDISASM_MIPS_DECODE_FLAG_LOONGSON | CDISASM_MIPS_DECODE_FLAG_FPU;
#else
    (void)form;
#endif
    return 0;
}

cdisasm_status cdisasm_mips_decode_loongasx(uint32_t raw, uint64_t address, cdisasm_mips_mode mode,
                                         cdisasm_mips_revision revision, const cdisasm_mips_decode_flags *features,
                                         cdisasm_mips_instruction *instruction)
{
#if USE_EXTRA_OPCODES && (USE_MIPS_LOONGSIMD || USE_MIPS_LOONGASX)
    const uint64_t required = CDISASM_MIPS_DECODE_FLAG_LOONGASX |
        CDISASM_MIPS_DECODE_FLAG_LOONGSON | CDISASM_MIPS_DECODE_FLAG_FPU;
    const unsigned vector = (raw >> 6) & 31u;
    size_t n;
    if (!instruction || !features) return CDISASM_STATUS_INVALID_ARGUMENT;
    if (!cdisasm_mips_loongasx_owns(raw, features) || (features->bitmap[0] & required) != required)
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    if (mode != CDISASM_MIPS_MODE_64 || revision != CDISASM_MIPS_REVISION_64R2)
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    if (features->bitmap[0] & CDISASM_MIPS_DECODE_FLAG_FPR32) return CDISASM_STATUS_INVALID_INSTRUCTION;
    for (n = 0; n < sizeof(loongasx_kernel_forms)/sizeof(loongasx_kernel_forms[0]); ++n) {
        const loongasx_kernel_form *form = &loongasx_kernel_forms[n];
        cdisasm_mips_instruction candidate;
        if ((raw & form->mask) != form->value) continue;
        memset(&candidate, 0, sizeof(candidate));
        candidate.address = address;
        candidate.raw_instruction = raw;
        candidate.opcode_size = 4u;
        candidate.mode = (uint8_t)mode;
        candidate.revision = (uint8_t)revision;
        candidate.name_id = form->name;
        candidate.form_id = form->form;
        candidate.instruction_flags = CDISASM_MIPS_INSTRUCTION_FLAG_FLOATING_POINT;
        if (form->kind == 5u) {
            /* Source-defined COPY syntax selected by explicit family policy. Keep a conservative
             * whole-vector read; the primary macro does not establish an
             * exact physical read footprint or hidden control effects. */
            loongsimd_register(&candidate, CDISASM_MIPS_REG_GPR1, 8u, 0u, CDISASM_OPERAND_ACCESS_WRITE, 0);
            loongsimd_register(&candidate, CDISASM_MIPS_REG_LOONGASX_FIRST + ((raw >> 11) & 31u),
                32u, 8u, CDISASM_OPERAND_ACCESS_READ, 0);
            candidate.operand[1].detail.flags = CDISASM_MIPS_OPERAND_DETAIL_HAS_LANE;
            candidate.operand[1].detail.lane_index = (uint8_t)((raw >> 16) & 3u);
        } else {
            loongsimd_register(&candidate, CDISASM_MIPS_REG_LOONGASX_FIRST + vector, 32u,
                form->kind <= 2u ? 1u : 8u, form->kind == 1u ? CDISASM_OPERAND_ACCESS_WRITE :
                form->kind == 2u ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_READ_WRITE, 0);
            if (form->kind <= 2u) {
                int displacement = (int)((raw >> 16) & 1023u);
                cdisasm_mips_operand *memory = &candidate.operand[candidate.operand_count++];
                if (displacement & 512) displacement -= 1024;
                memory->type = CDISASM_OPERAND_MEMORY;
                memory->base_reg = CDISASM_MIPS_REG_GPR1;
                memory->imm = (uint64_t)(int64_t)displacement;
                memory->size = 32u;
                memory->detail.element_size = 1u;
                memory->access = form->kind == 1u ? CDISASM_OPERAND_ACCESS_READ : CDISASM_OPERAND_ACCESS_WRITE;
                memory->flags = CDISASM_MIPS_OPERAND_FLAG_SIGNED | CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;
            } else if (form->kind == 3u) {
                /* Low-lane ASX syntax uses conservative whole-vector RW;
                 * upper128 preservation is established only for lanes2/3. */
                candidate.operand[0].detail.flags = CDISASM_MIPS_OPERAND_DETAIL_HAS_LANE;
                candidate.operand[0].detail.lane_index = (uint8_t)((raw >> 16) & 3u);
                loongsimd_register(&candidate, CDISASM_MIPS_REG_GPR1, 8u, 0u, CDISASM_OPERAND_ACCESS_READ, 0);
            } else {
                cdisasm_mips_operand *pattern;
                /* Macro-defined four-bit selector syntax uses whole-vector
                 * resources. Only the recorded kernel patterns establish
                 * exact lane preservation, never a general truth table. */
                loongsimd_register(&candidate, CDISASM_MIPS_REG_LOONGASX_FIRST + ((raw >> 11) & 31u),
                    32u, 8u, CDISASM_OPERAND_ACCESS_READ, 0);
                pattern = &candidate.operand[candidate.operand_count++];
                pattern->type = CDISASM_OPERAND_IMMEDIATE;
                pattern->size = 1u;
                pattern->imm = (raw >> 16) & 15u;
                pattern->access = CDISASM_OPERAND_ACCESS_READ;
            }
        }
        *instruction = candidate;
        return CDISASM_STATUS_OK;
    }
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#else
    (void)raw; (void)address; (void)mode; (void)revision; (void)features; (void)instruction;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
#endif
}

uint64_t cdisasm_mips_loongasx_required_flags(cdisasm_mips_form_id form)
{
#if USE_EXTRA_OPCODES && (USE_MIPS_LOONGSIMD || USE_MIPS_LOONGASX)
    if (form == 60000u || form == 60001u || form == 60003u || form == 60004u || form == 60005u)
        return CDISASM_MIPS_DECODE_FLAG_LOONGASX | CDISASM_MIPS_DECODE_FLAG_LOONGSON | CDISASM_MIPS_DECODE_FLAG_FPU;
#else
    (void)form;
#endif
    return 0;
}
