#include <cdisasm/cdisasm_x86.h>

#include <stddef.h>

typedef struct x86_descriptor_family_probe {
    uint16_t name_id;
    uint16_t group_id;
    uint32_t bit_id;
} x86_descriptor_family_probe;

#define CDISASM_X86_DESCRIPTOR_FAMILY(index_, name_, group_, bit_) \
    {(uint16_t)(name_), (uint16_t)(group_), (uint32_t)(bit_)},
static const x86_descriptor_family_probe descriptor_families[] = {
#include "../../src/x86/generated/cdisasm_x86_descriptor_families.inc"
};
#undef CDISASM_X86_DESCRIPTOR_FAMILY

_Static_assert(CDISASM_X86_GROUP_ENQCMD == UINT16_C(115),
               "existing x86 group IDs changed");
_Static_assert(CDISASM_X86_GROUP_COUNT == UINT16_C(323),
               "pinned x86 ISA_SET group count changed");
_Static_assert(CDISASM_X86_DECODE_BIT_AVX_VNNI_INT16 == UINT32_C(63),
               "existing x86 decode-bit IDs changed");
_Static_assert(CDISASM_X86_DECODE_BIT_COUNT == UINT32_C(271),
               "pinned x86 ISA_SET decode-bit count changed");
_Static_assert(CDISASM_X86_DECODE_BIT_COUNT <= CDISASM_DECODE_FLAGS_BIT_CAPACITY,
               "x86 family bitmap capacity exceeded");
_Static_assert(sizeof(descriptor_families) / sizeof(descriptor_families[0])
                   == 10994u,
               "pinned x86 descriptor-family count changed");

int main(void)
{
    cdisasm_x86_decode_flags flags = CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    cdisasm_x86_decode_flags low_end = CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    cdisasm_x86_decode_flags barcelona = CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    cdisasm_x86_decode_flags penryn = CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    cdisasm_x86_decode_flags tiger = CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    cdisasm_x86_decode_flags apx = CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    size_t index;

    if (cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_X86, CDISASM_X86_MODE_64, &flags)
        != CDISASM_STATUS_OK) {
        return 1;
    }
    if (flags.bitmap[0] != CDISASM_X86_DECODE_FLAG_KNOWN_MASK_0
        /* XED ISA_SET AMD has only 16/32-bit encodings. */
        || flags.bitmap[1]
            != (CDISASM_X86_DECODE_FLAG_KNOWN_MASK_1
                & ~(UINT64_C(1) << (CDISASM_X86_DECODE_BIT_AMD % 64u)))
        || flags.bitmap[2] != CDISASM_X86_DECODE_FLAG_KNOWN_MASK_2
        || flags.bitmap[3] != CDISASM_X86_DECODE_FLAG_KNOWN_MASK_3
        || flags.bitmap[4] != CDISASM_X86_DECODE_FLAG_KNOWN_MASK_4
        || flags.bitmap[5] != CDISASM_X86_DECODE_FLAG_KNOWN_MASK_5
        || flags.bitmap[6] != CDISASM_X86_DECODE_FLAG_KNOWN_MASK_6
        || flags.bitmap[7] != CDISASM_X86_DECODE_FLAG_KNOWN_MASK_7
        || !cdisasm_decode_flags_test_bit(
            &flags, CDISASM_X86_DECODE_BIT_LAST)) {
        return 2;
    }

    if (cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_CELERON_G1840, CDISASM_X86_MODE_64, &low_end)
            != CDISASM_STATUS_OK
        || cdisasm_decode_flags_test_bit(
            &low_end, CDISASM_X86_DECODE_BIT_AVX2GATHER)
        || cdisasm_decode_flags_test_bit(
            &low_end, CDISASM_X86_DECODE_BIT_AVX512F_128)
        || (low_end.bitmap[0]
            & (CDISASM_X86_DECODE_FLAG_AVX
                | CDISASM_X86_DECODE_FLAG_AVX2
                | CDISASM_X86_DECODE_FLAG_F16C
                | CDISASM_X86_DECODE_FLAG_FMA3)) != 0) {
        return 4;
    }
    if (cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_AMD_BARCELONA, CDISASM_X86_MODE_64, &barcelona)
            != CDISASM_STATUS_OK
        || !cdisasm_decode_flags_test_bit(
            &barcelona, CDISASM_X86_DECODE_BIT_SSE4A)
        || cdisasm_decode_flags_test_bit(
            &barcelona, CDISASM_X86_DECODE_BIT_SSE4_ISA_SET)) {
        return 5;
    }
    if (cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_PENRYN, CDISASM_X86_MODE_64, &penryn)
            != CDISASM_STATUS_OK
        || !cdisasm_decode_flags_test_bit(
            &penryn, CDISASM_X86_DECODE_BIT_SSE4_ISA_SET)) {
        return 6;
    }
    if (cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_TIGER_LAKE, CDISASM_X86_MODE_64, &tiger)
            != CDISASM_STATUS_OK
        || !cdisasm_decode_flags_test_bit(
            &tiger, CDISASM_X86_DECODE_BIT_CET_ISA_SET)) {
        return 7;
    }
    if (cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_APX, CDISASM_X86_MODE_64, &apx)
            != CDISASM_STATUS_OK
        || !cdisasm_decode_flags_test_bit(
            &apx, CDISASM_X86_DECODE_BIT_APX_F_N3)
        || cdisasm_decode_flags_test_bit(
            &apx, CDISASM_X86_DECODE_BIT_APX_F_AMX)) {
        return 8;
    }

    for (index = 0;
         index < sizeof(descriptor_families) / sizeof(descriptor_families[0]);
         ++index) {
        const x86_descriptor_family_probe *entry = &descriptor_families[index];

        if (entry->name_id == CDISASM_X86_NAME_NONE
            || entry->name_id >= CDISASM_X86_NAME_COUNT
            || entry->group_id < CDISASM_X86_GROUP_FIRST
            || entry->group_id > CDISASM_X86_GROUP_LAST
            || (entry->bit_id != CDISASM_X86_DECODE_BIT_NONE
                && entry->bit_id >= CDISASM_X86_DECODE_BIT_COUNT)) {
            return 3;
        }
    }
    return 0;
}
