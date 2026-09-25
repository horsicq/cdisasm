#include "cdisasm/cdisasm_x86.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define EXPECT(expression) \
    do { \
        if (!(expression)) { \
            fprintf(stderr, "%s:%d: expectation failed: %s\n", \
                    __FILE__, __LINE__, #expression); \
            ++failures; \
        } \
    } while (0)

static cdisasm_instruction instruction_with_group(cdisasm_x86_group_id group)
{
    cdisasm_instruction instruction;

    memset(&instruction, 0, sizeof(instruction));
    instruction.x86_group_count = 1;
    instruction.x86_group_ids[0] = group;
    return instruction;
}

static void check_descriptor(
    cdisasm_x86_family_id family_id,
    uint64_t required_flags,
    cdisasm_x86_mode_mask modes,
    cdisasm_x86_operand_rule_id operand_rule,
    cdisasm_x86_legality_rule_id legality_rule,
    uint8_t privilege,
    uint8_t vendor)
{
    const cdisasm_x86_family_descriptor *descriptor =
        cdisasm_x86_family_descriptor_get(family_id);

    EXPECT(descriptor != NULL);
    if (descriptor == NULL) {
        return;
    }
    EXPECT(descriptor->family_id == family_id);
    EXPECT(descriptor->required_flags == required_flags);
    EXPECT(descriptor->allowed_modes == modes);
    EXPECT(descriptor->operand_rule == operand_rule);
    EXPECT(descriptor->legality_rule == legality_rule);
    EXPECT(descriptor->privilege_level == privilege);
    EXPECT(descriptor->vendor == vendor);
}

int main(void)
{
    cdisasm_instruction instruction;
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    cdisasm_x86_family_mask family_mask;

    EXPECT(cdisasm_x86_family_descriptor_get(
        CDISASM_X86_FAMILY_NONE) == NULL);
    EXPECT(cdisasm_x86_family_descriptor_get(
        CDISASM_X86_FAMILY_LAST + UINT16_C(1)) == NULL);

    check_descriptor(
        CDISASM_X86_FAMILY_AVX512_EVEX,
        CDISASM_X86_DECODE_FLAG_AVX512,
        CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_EVEX_VECTOR_MASK,
        CDISASM_X86_LEGALITY_RULE_AVX512_EVEX,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_ANY);
    check_descriptor(
        CDISASM_X86_FAMILY_APX_EVEX,
        CDISASM_X86_DECODE_FLAG_APX,
        CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_APX_N3,
        CDISASM_X86_LEGALITY_RULE_APX_F_N3,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_ANY);
    check_descriptor(
        CDISASM_X86_FAMILY_AVX2_GATHER,
        CDISASM_X86_DECODE_FLAG_AVX2,
        CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_VSIB_GATHER,
        CDISASM_X86_LEGALITY_RULE_AVX2_VSIB,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_ANY);
    check_descriptor(
        CDISASM_X86_FAMILY_FRED,
        CDISASM_X86_DECODE_FLAG_SYSTEM,
        CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_ZERO_OPERANDS,
        CDISASM_X86_LEGALITY_RULE_FRED,
        CDISASM_X86_PRIVILEGE_RING0,
        CDISASM_X86_VENDOR_INTEL);
    check_descriptor(
        CDISASM_X86_FAMILY_TDX,
        CDISASM_X86_DECODE_FLAG_SYSTEM,
        CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_ZERO_OPERANDS,
        CDISASM_X86_LEGALITY_RULE_TDX,
        CDISASM_X86_PRIVILEGE_VMX_ROOT,
        CDISASM_X86_VENDOR_INTEL);
    check_descriptor(
        CDISASM_X86_FAMILY_VIA_PADLOCK,
        CDISASM_X86_DECODE_FLAG_SYSTEM,
        CDISASM_X86_MODE_MASK_32 | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_VIA_PADLOCK,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_VIA);
    check_descriptor(
        CDISASM_X86_FAMILY_X87,
        CDISASM_X86_DECODE_FLAG_FPU,
        CDISASM_X86_MODE_MASK_16 | CDISASM_X86_MODE_MASK_32
            | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_X87_STACK,
        CDISASM_X86_LEGALITY_RULE_X87,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_ANY);
    check_descriptor(
        CDISASM_X86_FAMILY_INTEL_VMX,
        CDISASM_X86_DECODE_FLAG_VMX,
        CDISASM_X86_MODE_MASK_32 | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_INTEL_VMX,
        CDISASM_X86_PRIVILEGE_VMX_ROOT,
        CDISASM_X86_VENDOR_INTEL);
    check_descriptor(
        CDISASM_X86_FAMILY_AMD_SVM,
        CDISASM_X86_DECODE_FLAG_SVM,
        CDISASM_X86_MODE_MASK_32 | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_AMD_SVM,
        CDISASM_X86_PRIVILEGE_SVM_HOST,
        CDISASM_X86_VENDOR_AMD);

    /* Direct ISA families are always descriptor-backed, even though their
     * detailed legality is still selected by the full decode flag bitmap. */
    {
        cdisasm_x86_family_id family_id;

        for (family_id = CDISASM_X86_FAMILY_MMX;
             family_id <= CDISASM_X86_FAMILY_AMX;
             ++family_id) {
            const cdisasm_x86_family_descriptor *descriptor =
                cdisasm_x86_family_descriptor_get(family_id);

            EXPECT(descriptor != NULL);
            if (descriptor != NULL) {
                EXPECT(descriptor->family_id == family_id);
                EXPECT(descriptor->legality_rule
                    == CDISASM_X86_LEGALITY_RULE_NONE);
                EXPECT(descriptor->operand_rule
                    == CDISASM_X86_OPERAND_RULE_NONE);
            }
        }
    }
    check_descriptor(
        CDISASM_X86_FAMILY_FMA3,
        CDISASM_X86_DECODE_FLAG_FMA3,
        CDISASM_X86_MODE_MASK_32 | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_NONE,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_ANY);
    check_descriptor(
        CDISASM_X86_FAMILY_AES,
        CDISASM_X86_DECODE_FLAG_AES,
        CDISASM_X86_MODE_MASK_32 | CDISASM_X86_MODE_MASK_64,
        CDISASM_X86_OPERAND_RULE_NONE,
        CDISASM_X86_LEGALITY_RULE_NONE,
        CDISASM_X86_PRIVILEGE_ANY,
        CDISASM_X86_VENDOR_ANY);

    EXPECT(cdisasm_x86_family_mask_from_flags(NULL)
        == CDISASM_X86_FAMILY_MASK_NONE);
    family_mask = cdisasm_x86_family_mask_from_flags(&flags);
    EXPECT(family_mask == CDISASM_X86_FAMILY_MASK_NONE);
    flags.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP] =
        CDISASM_X86_DECODE_FLAG_ALL;
    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_AVX2GATHER));
    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_FRED));
    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_TDX));
    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_CMPCCXADD));
    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_APX_F_AMX_MOVRS));
    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_VIA_PADLOCK_SHA));
    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_MOVRS));
    family_mask = cdisasm_x86_family_mask_from_flags(&flags);
    EXPECT((family_mask & CDISASM_X86_FAMILY_MASK_FMA3) != 0);
    EXPECT((family_mask & CDISASM_X86_FAMILY_MASK_AES) != 0);
    EXPECT((family_mask & CDISASM_X86_FAMILY_MASK_BITMANIP) != 0);
    EXPECT((family_mask & CDISASM_X86_FAMILY_MASK_AVX10) != 0);
    EXPECT((family_mask & CDISASM_X86_FAMILY_MASK_AMX) != 0);
    EXPECT((family_mask & CDISASM_X86_FAMILY_MASK_X87) != 0);
    EXPECT((family_mask & CDISASM_X86_FAMILY_MASK_AVX512_EVEX) != 0);
    EXPECT((family_mask & CDISASM_X86_FAMILY_MASK_APX_EVEX) != 0);
    EXPECT((family_mask & CDISASM_X86_FAMILY_MASK_AVX2_GATHER) != 0);
    EXPECT((family_mask & CDISASM_X86_FAMILY_MASK_FRED) != 0);
    EXPECT((family_mask & CDISASM_X86_FAMILY_MASK_TDX) != 0);
    EXPECT((family_mask & CDISASM_X86_FAMILY_MASK_VIA_PADLOCK) != 0);
    EXPECT((family_mask & CDISASM_X86_FAMILY_MASK_MOVRS) != 0);
    EXPECT((family_mask & CDISASM_X86_FAMILY_MASK_INTEL_VMX) != 0);
    EXPECT((family_mask & CDISASM_X86_FAMILY_MASK_AMD_SVM) != 0);
    EXPECT((family_mask & CDISASM_X86_FAMILY_MASK_ALL)
        == CDISASM_X86_FAMILY_MASK_ALL);

    /* Exact late ISA_SET selectors must work without any bitmap-0 umbrella. */
    cdisasm_decode_flags_reset(&flags);
    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_AVX512F_512));
    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_APX_F_CMPCCXADD));
    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_AVX2GATHER));
    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_FRED));
    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_TDX));
    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_VIA_PADLOCK_AES));
    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_APX_F_AMX_MOVRS));
    EXPECT(cdisasm_decode_flags_set_bit(
        &flags, CDISASM_X86_DECODE_BIT_VTX));
    flags.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP] =
        CDISASM_X86_DECODE_FLAG_SVM;
    family_mask = cdisasm_x86_family_mask_from_flags(&flags);
    {
        const cdisasm_x86_family_mask special_expected =
            CDISASM_X86_FAMILY_MASK_AVX512_EVEX
            | CDISASM_X86_FAMILY_MASK_APX_EVEX
            | CDISASM_X86_FAMILY_MASK_AVX2_GATHER
            | CDISASM_X86_FAMILY_MASK_FRED
            | CDISASM_X86_FAMILY_MASK_TDX
            | CDISASM_X86_FAMILY_MASK_VIA_PADLOCK
            | CDISASM_X86_FAMILY_MASK_MOVRS
            | CDISASM_X86_FAMILY_MASK_INTEL_VMX
            | CDISASM_X86_FAMILY_MASK_AMD_SVM;

        EXPECT((family_mask & CDISASM_X86_FAMILY_MASK_ALL)
            == special_expected);
    }
    EXPECT((family_mask & CDISASM_X86_FAMILY_MASK_X87) == 0);

    instruction = instruction_with_group(CDISASM_X86_GROUP_AVX512F_512);
    EXPECT(cdisasm_x86_instruction_family(&instruction)
        == CDISASM_X86_FAMILY_AVX512_EVEX);
    instruction = instruction_with_group(CDISASM_X86_GROUP_APX_F_N3);
    EXPECT(cdisasm_x86_instruction_family(&instruction)
        == CDISASM_X86_FAMILY_APX_EVEX);
    instruction = instruction_with_group(CDISASM_X86_GROUP_AVX2GATHER);
    EXPECT(cdisasm_x86_instruction_family(&instruction)
        == CDISASM_X86_FAMILY_AVX2_GATHER);
    instruction = instruction_with_group(CDISASM_X86_GROUP_FRED);
    EXPECT(cdisasm_x86_instruction_family(&instruction)
        == CDISASM_X86_FAMILY_FRED);
    instruction = instruction_with_group(CDISASM_X86_GROUP_TDX);
    EXPECT(cdisasm_x86_instruction_family(&instruction)
        == CDISASM_X86_FAMILY_TDX);
    instruction = instruction_with_group(CDISASM_X86_GROUP_VIA_PADLOCK_AES);
    EXPECT(cdisasm_x86_instruction_family(&instruction)
        == CDISASM_X86_FAMILY_VIA_PADLOCK);
    instruction = instruction_with_group(CDISASM_X86_GROUP_X87);
    EXPECT(cdisasm_x86_instruction_family(&instruction)
        == CDISASM_X86_FAMILY_X87);
    instruction = instruction_with_group(CDISASM_X86_GROUP_MOVRS);
    EXPECT(cdisasm_x86_instruction_family(&instruction)
        == CDISASM_X86_FAMILY_MOVRS);
    instruction = instruction_with_group(CDISASM_X86_GROUP_VMX);
    EXPECT(cdisasm_x86_instruction_family(&instruction)
        == CDISASM_X86_FAMILY_INTEL_VMX);
    instruction = instruction_with_group(CDISASM_X86_GROUP_VTX);
    EXPECT(cdisasm_x86_instruction_family(&instruction)
        == CDISASM_X86_FAMILY_INTEL_VMX);
    instruction = instruction_with_group(CDISASM_X86_GROUP_SVM);
    EXPECT(cdisasm_x86_instruction_family(&instruction)
        == CDISASM_X86_FAMILY_AMD_SVM);
    memset(&instruction, 0, sizeof(instruction));
    EXPECT(cdisasm_x86_instruction_family(&instruction)
        == CDISASM_X86_FAMILY_NONE);
    EXPECT(cdisasm_x86_instruction_family(NULL)
        == CDISASM_X86_FAMILY_NONE);

#if USE_EXTRA_OPCODES
    {
        static const uint8_t raw[] = {
            0x62, 0xf1, 0x7c, 0x48, 0x58, 0xc0
        };
        cdisasm_x86_decode_context context;
        uint32_t decoded_size;

        EXPECT(cdisasm_x86_cpu_decode_context(
            CDISASM_CPU_X86,
            CDISASM_MODE_64,
            &context) == CDISASM_STATUS_OK);
        EXPECT(context.cpu_id == CDISASM_CPU_X86);
        EXPECT(context.mode == CDISASM_MODE_64);
        EXPECT(context.family_mask == CDISASM_X86_FAMILY_MASK_ALL);
        EXPECT(context.family_value == CDISASM_X86_FAMILY_MASK_DEFAULT);
        EXPECT(cdisasm_x86_decode_context_get_available_families(NULL)
            == CDISASM_X86_FAMILY_MASK_NONE);
        EXPECT(cdisasm_x86_decode_context_get_set_families(NULL)
            == CDISASM_X86_FAMILY_MASK_NONE);
        EXPECT(cdisasm_x86_decode_context_get_available_families(&context)
            == context.family_mask);
        EXPECT(cdisasm_x86_decode_context_get_set_families(&context)
            == context.family_value);
        EXPECT(cdisasm_x86_decode_context_add_family(
            NULL, CDISASM_X86_FAMILY_AVX512_EVEX) == 0);
        EXPECT(cdisasm_x86_decode_context_remove_family(
            NULL, CDISASM_X86_FAMILY_AVX512_EVEX) == 0);
        EXPECT(cdisasm_x86_decode_context_add_family(
            &context, CDISASM_X86_FAMILY_NONE) == 0);
        EXPECT(cdisasm_x86_decode_context_remove_family(
            &context, CDISASM_X86_FAMILY_LAST + UINT16_C(1)) == 0);
        EXPECT(cdisasm_x86_decode_context_add_family(
            &context, CDISASM_X86_FAMILY_FRED) != 0);
        EXPECT((context.family_value & CDISASM_X86_FAMILY_MASK_FRED) != 0);
        EXPECT(cdisasm_x86_decode_context_remove_family(
            &context, CDISASM_X86_FAMILY_FRED) != 0);
        EXPECT((context.family_value & CDISASM_X86_FAMILY_MASK_FRED) == 0);
        EXPECT(cdisasm_x86_decode_context_remove_family(
            &context, CDISASM_X86_FAMILY_APX_EVEX) != 0);
        EXPECT((context.family_value & CDISASM_X86_FAMILY_MASK_APX_EVEX) == 0);
        EXPECT(cdisasm_x86_decode_context_add_family(
            &context, CDISASM_X86_FAMILY_APX_EVEX) != 0);
        EXPECT((context.family_value & CDISASM_X86_FAMILY_MASK_APX_EVEX) != 0);
        EXPECT(cdisasm_x86_decode_context_get_set_families(&context)
            == context.family_value);
        decoded_size = cdisasm_x86_decode_with_context(
            &context,
            raw,
            sizeof(raw),
            UINT64_C(0x1000),
            &instruction);
        EXPECT(decoded_size == sizeof(raw));
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VADDPS);
        EXPECT(cdisasm_x86_instruction_family(&instruction)
            == CDISASM_X86_FAMILY_AVX512_EVEX);

        {
            cdisasm_x86_decode_context mode32_context;

            EXPECT(cdisasm_x86_cpu_decode_context(
                CDISASM_CPU_X86,
                CDISASM_MODE_32,
                &mode32_context) == CDISASM_STATUS_OK);
            EXPECT((mode32_context.family_mask
                    & CDISASM_X86_FAMILY_MASK_AMX) == 0);
        }
    }
#else
    {
        cdisasm_x86_decode_context context;

        EXPECT(cdisasm_x86_cpu_decode_context(
            CDISASM_CPU_X86,
            CDISASM_MODE_64,
            &context) == CDISASM_STATUS_OK);
        EXPECT(context.family_mask == CDISASM_X86_FAMILY_MASK_NONE);
        EXPECT(context.family_value == CDISASM_X86_FAMILY_MASK_NONE);
        EXPECT(cdisasm_x86_decode_context_get_available_families(&context)
            == CDISASM_X86_FAMILY_MASK_NONE);
        EXPECT(cdisasm_x86_decode_context_get_set_families(&context)
            == CDISASM_X86_FAMILY_MASK_NONE);
        EXPECT(cdisasm_x86_decode_context_add_family(
            &context, CDISASM_X86_FAMILY_X87) == 0);
        EXPECT(cdisasm_x86_decode_context_remove_family(
            &context, CDISASM_X86_FAMILY_X87) == 0);
    }
#endif

    return failures == 0 ? 0 : 1;
}
