#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm_x86.h"
#include "x86_test_flags.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdio.h>
#include <string.h>

static int failures;

#define EXPECT(condition) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "%s:%d: expectation failed: %s\n", \
                    __FILE__, __LINE__, #condition); \
            ++failures; \
        } \
    } while (0)

_Static_assert(CDISASM_X86_NAME_ICEBP == CDISASM_X86_NAME_INT1,
               "ICEBP must remain an INT1 alias");
_Static_assert(CDISASM_X86_NAME_LOADALLD == CDISASM_X86_NAME_LOADALL,
               "LOADALLD must remain a LOADALL alias");
_Static_assert(CDISASM_X86_NAME_SETALC == CDISASM_X86_NAME_SALC,
               "SETALC must remain a SALC alias");
_Static_assert(CDISASM_NAME_ICEBP == CDISASM_NAME_INT1,
               "legacy ICEBP alias changed");
_Static_assert(CDISASM_NAME_LOADALLD == CDISASM_NAME_LOADALL,
               "legacy LOADALLD alias changed");
_Static_assert(CDISASM_NAME_SETALC == CDISASM_NAME_SALC,
               "legacy SETALC alias changed");

/* This older broad behavioral suite supplies a bitmap-0 mask through the
 * compatibility adapter.  Preserve that call shape while selecting every
 * exact ISA-set word too, including the VTX bit required by forms 5997--6003. */
#undef cdisasm_x86_decode
static uint32_t decode_with_all_exact_flags(
    cdisasm_x86_cpu_id cpu_id,
    cdisasm_x86_mode mode,
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    cdisasm_x86_decode_option word0,
    cdisasm_x86_instruction *instruction)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_ALL_INITIALIZER;

    flags.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP] = word0;
    return cdisasm_x86_decode(
        cpu_id, mode, code, code_size, address,
        word0 == CDISASM_X86_DECODE_OPTION_NONE ? NULL : &flags,
        instruction);
}
#define cdisasm_x86_decode decode_with_all_exact_flags

typedef struct opcode_case {
    const char *label;
    cdisasm_cpu_id cpu_id;
    cdisasm_mode mode;
    uint8_t bytes[8];
    size_t size;
    cdisasm_x86_name_id name_id;
    const char *text;
    cdisasm_x86_group_id x86_group;
    uint32_t opcode_groups;
} opcode_case;

static int decode_success(
    const opcode_case *test,
    cdisasm_instruction *instruction)
{
#if USE_DISASM_FORMAT
    char text[128] = {0};
#endif
    uint32_t decoded_size = cdisasm_x86_decode(
        test->cpu_id,
        test->mode,
        test->bytes,
        test->size,
        UINT64_C(0x1000),
        CDISASM_X86_TEST_ALL_FLAGS,
        instruction);

    if (decoded_size != test->size
        || instruction->last_error_id != CDISASM_STATUS_OK
        || instruction->name_id != test->name_id
        || instruction->opcode_groups != test->opcode_groups
        || !cdisasm_instruction_has_x86_group(
            instruction,
            test->x86_group)) {
        fprintf(
            stderr,
            "%s: decode=%u status=%u name=%u groups=0x%x\n",
            test->label,
            (unsigned int)decoded_size,
            (unsigned int)instruction->last_error_id,
            (unsigned int)instruction->name_id,
            (unsigned int)instruction->opcode_groups);
        ++failures;
        return 0;
    }
#if USE_DISASM_FORMAT
    if (cdisasm_x86_format(
            instruction,
            CDISASM_FORMAT_SYNTAX_0,
            text,
            sizeof(text)) != strlen(test->text)
        || strcmp(text, test->text) != 0) {
        fprintf(
            stderr,
            "%s: formatted as \"%s\", expected \"%s\"\n",
            test->label,
            text,
            test->text);
        ++failures;
        return 0;
    }
#endif
    return 1;
}

static void expect_failure(
    const char *label,
    cdisasm_cpu_id cpu_id,
    cdisasm_mode mode,
    const uint8_t *bytes,
    size_t size,
    cdisasm_status status)
{
    cdisasm_instruction instruction;
    uint32_t decoded_size = cdisasm_x86_decode(
        cpu_id,
        mode,
        bytes,
        size,
        0,
        CDISASM_X86_TEST_ALL_FLAGS,
        &instruction);

    if (decoded_size != 0 || instruction.last_error_id != status) {
        fprintf(
            stderr,
            "%s: decode=%u status=%u, expected status=%u\n",
            label,
            (unsigned int)decoded_size,
            (unsigned int)instruction.last_error_id,
            (unsigned int)status);
        ++failures;
    }
}

static void test_intel_vmx(void)
{
    static const opcode_case cases[] = {
        {"VMCALL", CDISASM_CPU_INTEL_VT_X, CDISASM_MODE_32,
            {0x0f, 0x01, 0xc1}, 3, CDISASM_X86_NAME_VMCALL,
            "vmcall", CDISASM_X86_GROUP_VMX, CDISASM_GROUP_PRIVILEGED},
        {"VMCLEAR", CDISASM_CPU_INTEL_VT_X, CDISASM_MODE_32,
            {0x66, 0x0f, 0xc7, 0x30}, 4, CDISASM_X86_NAME_VMCLEAR,
            "vmclear qword ptr [eax]", CDISASM_X86_GROUP_VMX,
            CDISASM_GROUP_PRIVILEGED},
        {"VMLAUNCH", CDISASM_CPU_INTEL_VT_X, CDISASM_MODE_32,
            {0x0f, 0x01, 0xc2}, 3, CDISASM_X86_NAME_VMLAUNCH,
            "vmlaunch", CDISASM_X86_GROUP_VMX, CDISASM_GROUP_PRIVILEGED},
        {"VMPTRLD", CDISASM_CPU_INTEL_VT_X, CDISASM_MODE_32,
            {0x0f, 0xc7, 0x30}, 3, CDISASM_X86_NAME_VMPTRLD,
            "vmptrld qword ptr [eax]", CDISASM_X86_GROUP_VMX,
            CDISASM_GROUP_PRIVILEGED},
        {"VMPTRST", CDISASM_CPU_INTEL_VT_X, CDISASM_MODE_32,
            {0x0f, 0xc7, 0x38}, 3, CDISASM_X86_NAME_VMPTRST,
            "vmptrst qword ptr [eax]", CDISASM_X86_GROUP_VMX,
            CDISASM_GROUP_PRIVILEGED},
        {"VMREAD fixed 32-bit", CDISASM_CPU_INTEL_VT_X, CDISASM_MODE_16,
            {0x0f, 0x78, 0xc1}, 3, CDISASM_X86_NAME_VMREAD,
            "vmread ecx, eax", CDISASM_X86_GROUP_VMX,
            CDISASM_GROUP_PRIVILEGED},
        {"VMREAD memory", CDISASM_CPU_INTEL_VT_X, CDISASM_MODE_64,
            {0x0f, 0x78, 0x01}, 3, CDISASM_X86_NAME_VMREAD,
            "vmread qword ptr [rcx], rax", CDISASM_X86_GROUP_VMX,
            CDISASM_GROUP_PRIVILEGED},
        {"VMRESUME", CDISASM_CPU_INTEL_VT_X, CDISASM_MODE_32,
            {0x0f, 0x01, 0xc3}, 3, CDISASM_X86_NAME_VMRESUME,
            "vmresume", CDISASM_X86_GROUP_VMX, CDISASM_GROUP_PRIVILEGED},
        {"VMWRITE fixed 32-bit", CDISASM_CPU_INTEL_VT_X, CDISASM_MODE_16,
            {0x0f, 0x79, 0xc1}, 3, CDISASM_X86_NAME_VMWRITE,
            "vmwrite eax, ecx", CDISASM_X86_GROUP_VMX,
            CDISASM_GROUP_PRIVILEGED},
        {"VMWRITE memory", CDISASM_CPU_INTEL_VT_X, CDISASM_MODE_64,
            {0x0f, 0x79, 0x01}, 3, CDISASM_X86_NAME_VMWRITE,
            "vmwrite rax, qword ptr [rcx]", CDISASM_X86_GROUP_VMX,
            CDISASM_GROUP_PRIVILEGED},
        {"VMXOFF", CDISASM_CPU_INTEL_VT_X, CDISASM_MODE_32,
            {0x0f, 0x01, 0xc4}, 3, CDISASM_X86_NAME_VMXOFF,
            "vmxoff", CDISASM_X86_GROUP_VMX, CDISASM_GROUP_PRIVILEGED},
        {"VMXON", CDISASM_CPU_INTEL_VT_X, CDISASM_MODE_32,
            {0xf3, 0x0f, 0xc7, 0x30}, 4, CDISASM_X86_NAME_VMXON,
            "vmxon qword ptr [eax]", CDISASM_X86_GROUP_VMX,
            CDISASM_GROUP_PRIVILEGED},
        {"INVEPT", CDISASM_CPU_NEHALEM, CDISASM_MODE_32,
            {0x66, 0x0f, 0x38, 0x80, 0x08}, 5,
            CDISASM_X86_NAME_INVEPT,
            "invept ecx, xmmword ptr [eax]", CDISASM_X86_GROUP_VMX,
            CDISASM_GROUP_PRIVILEGED},
        {"INVVPID", CDISASM_CPU_NEHALEM, CDISASM_MODE_32,
            {0x66, 0x0f, 0x38, 0x81, 0x08}, 5,
            CDISASM_X86_NAME_INVVPID,
            "invvpid ecx, xmmword ptr [eax]", CDISASM_X86_GROUP_VMX,
            CDISASM_GROUP_PRIVILEGED},
        {"VMFUNC", CDISASM_CPU_HASWELL, CDISASM_MODE_64,
            {0x0f, 0x01, 0xd4}, 3, CDISASM_X86_NAME_VMFUNC,
            "vmfunc", CDISASM_X86_GROUP_VMX, CDISASM_GROUP_NONE},
        {"VMREAD extended registers", CDISASM_CPU_HASWELL, CDISASM_MODE_64,
            {0x45, 0x0f, 0x78, 0xc8}, 4, CDISASM_X86_NAME_VMREAD,
            "vmread r8, r9", CDISASM_X86_GROUP_VMX,
            CDISASM_GROUP_PRIVILEGED},
        {"VMWRITE extended registers", CDISASM_CPU_HASWELL, CDISASM_MODE_64,
            {0x45, 0x0f, 0x79, 0xc8}, 4, CDISASM_X86_NAME_VMWRITE,
            "vmwrite r9, r8", CDISASM_X86_GROUP_VMX,
            CDISASM_GROUP_PRIVILEGED},
    };
    static const uint8_t vmcall[] = {0x0f, 0x01, 0xc1};
    static const uint8_t vmcall_66[] = {0x66, 0x0f, 0x01, 0xc1};
    static const uint8_t vmlaunch_f3[] = {0xf3, 0x0f, 0x01, 0xc2};
    static const uint8_t invept[] = {0x66, 0x0f, 0x38, 0x80, 0x08};
    static const uint8_t invvpid[] = {0x66, 0x0f, 0x38, 0x81, 0x08};
    static const uint8_t vmfunc[] = {0x0f, 0x01, 0xd4};
    static const uint8_t vmfunc_66[] = {0x66, 0x0f, 0x01, 0xd4};
    static const uint8_t vmclear_register[] = {0x66, 0x0f, 0xc7, 0xf0};
    static const uint8_t vmxon_f2[] = {0xf2, 0x0f, 0xc7, 0x30};
    static const uint8_t vmptrst_66[] = {0x66, 0x0f, 0xc7, 0x38};
    static const uint8_t invept_no_66[] = {0x0f, 0x38, 0x80, 0x08};
    static const uint8_t invept_register[] = {0x66, 0x0f, 0x38, 0x80, 0xc0};
    static const uint8_t extrq_collision[] = {
        0x66, 0x0f, 0x78, 0xc1, 0x08, 0x04
    };
    static const uint8_t vmwrite_f3[] = {0xf3, 0x0f, 0x79, 0xc1};
    static const uint8_t truncated_map[] = {0x66, 0x0f, 0x38};
    static const cdisasm_cpu_id later_intel_profiles[] = {
        CDISASM_CPU_X86,
        CDISASM_CPU_CORE_2,
        CDISASM_CPU_NEHALEM,
        CDISASM_CPU_HASWELL,
        CDISASM_CPU_TIGER_LAKE,
        CDISASM_CPU_SAPPHIRE_RAPIDS,
        CDISASM_CPU_APX,
        CDISASM_CPU_CELERON_G1840,
        CDISASM_CPU_CELERON_G3900,
        CDISASM_CPU_CELERON_N3350,
        CDISASM_CPU_CELERON_N4020,
        CDISASM_CPU_CELERON_G5900,
        CDISASM_CPU_PENTIUM_SILVER_N6000
    };
    static const cdisasm_cpu_id atom_no_avx_profiles[] = {
        CDISASM_CPU_CELERON_N3350,
        CDISASM_CPU_CELERON_N4020,
        CDISASM_CPU_PENTIUM_SILVER_N6000
    };
    static const cdisasm_cpu_id desktop_no_avx_profiles[] = {
        CDISASM_CPU_CELERON_G1840,
        CDISASM_CPU_CELERON_G3900,
        CDISASM_CPU_CELERON_G5900
    };
    cdisasm_instruction instruction;
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        decode_success(&cases[index], &instruction);
    }
    for (index = 0;
         index < sizeof(later_intel_profiles) / sizeof(later_intel_profiles[0]);
         ++index) {
        EXPECT(cdisasm_x86_decode(
                   later_intel_profiles[index],
                   CDISASM_MODE_32,
                   vmcall,
                   sizeof(vmcall),
                   0,
                   CDISASM_X86_TEST_ALL_FLAGS,
                   &instruction)
            == sizeof(vmcall));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VMCALL);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction,
            CDISASM_X86_GROUP_VMX));
    }
    for (index = 0;
         index < sizeof(atom_no_avx_profiles)
             / sizeof(atom_no_avx_profiles[0]);
         ++index) {
        EXPECT(cdisasm_x86_decode(
                   atom_no_avx_profiles[index],
                   CDISASM_MODE_64,
                   vmfunc,
                   sizeof(vmfunc),
                   0,
                   CDISASM_X86_TEST_ALL_FLAGS,
                   &instruction)
            == sizeof(vmfunc));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VMFUNC);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction,
            CDISASM_X86_GROUP_VMX));
    }
    for (index = 0;
         index < sizeof(desktop_no_avx_profiles)
             / sizeof(desktop_no_avx_profiles[0]);
         ++index) {
        expect_failure("VMFUNC conservatively absent on exact G-series",
            desktop_no_avx_profiles[index], CDISASM_MODE_64,
            vmfunc, sizeof(vmfunc), CDISASM_STATUS_INVALID_INSTRUCTION);
    }

    expect_failure("VMX before VT-x", CDISASM_CPU_PRESCOTT,
        CDISASM_MODE_32, vmcall, sizeof(vmcall),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("VMX on AMD-V profile", CDISASM_CPU_AMD_V,
        CDISASM_MODE_32, vmcall, sizeof(vmcall),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("VMCALL has no refining prefix", CDISASM_CPU_INTEL_VT_X,
        CDISASM_MODE_32, vmcall_66, sizeof(vmcall_66),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("VMLAUNCH has no refining prefix", CDISASM_CPU_INTEL_VT_X,
        CDISASM_MODE_32, vmlaunch_f3, sizeof(vmlaunch_f3),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("INVEPT before Nehalem", CDISASM_CPU_PENRYN,
        CDISASM_MODE_32, invept, sizeof(invept),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("INVVPID before Nehalem", CDISASM_CPU_PENRYN,
        CDISASM_MODE_32, invvpid, sizeof(invvpid),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("VMFUNC before Haswell", CDISASM_CPU_IVY_BRIDGE,
        CDISASM_MODE_64, vmfunc, sizeof(vmfunc),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("VMFUNC is NP", CDISASM_CPU_HASWELL,
        CDISASM_MODE_64, vmfunc_66, sizeof(vmfunc_66),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("RDRAND overlap is unavailable before Ivy Bridge",
        CDISASM_CPU_INTEL_VT_X,
        CDISASM_MODE_32, vmclear_register, sizeof(vmclear_register),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("F2 does not select VMXON", CDISASM_CPU_INTEL_VT_X,
        CDISASM_MODE_32, vmxon_f2, sizeof(vmxon_f2),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("66 VMPTRST is invalid", CDISASM_CPU_INTEL_VT_X,
        CDISASM_MODE_32, vmptrst_66, sizeof(vmptrst_66),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("INVEPT requires 66", CDISASM_CPU_NEHALEM,
        CDISASM_MODE_32, invept_no_66, sizeof(invept_no_66),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("INVEPT requires memory", CDISASM_CPU_NEHALEM,
        CDISASM_MODE_32, invept_register, sizeof(invept_register),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("66 0F78 is SSE4a EXTRQ, not VMREAD",
        CDISASM_CPU_INTEL_VT_X,
        CDISASM_MODE_32, extrq_collision, sizeof(extrq_collision),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("VMWRITE is NP", CDISASM_CPU_INTEL_VT_X,
        CDISASM_MODE_32, vmwrite_f3, sizeof(vmwrite_f3),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("truncated 0F38 map", CDISASM_CPU_NEHALEM,
        CDISASM_MODE_32, truncated_map, sizeof(truncated_map),
        CDISASM_STATUS_TRUNCATED);
}

static void test_amd_svm(void)
{
    static const opcode_case cases[] = {
        {"VMRUN", CDISASM_CPU_AMD_V, CDISASM_MODE_64,
            {0x0f, 0x01, 0xd8}, 3, CDISASM_X86_NAME_VMRUN,
            "vmrun rax", CDISASM_X86_GROUP_SVM, CDISASM_GROUP_PRIVILEGED},
        {"VMMCALL", CDISASM_CPU_AMD_V, CDISASM_MODE_64,
            {0x0f, 0x01, 0xd9}, 3, CDISASM_X86_NAME_VMMCALL,
            "vmmcall", CDISASM_X86_GROUP_SVM, CDISASM_GROUP_NONE},
        {"VMLOAD", CDISASM_CPU_AMD_V, CDISASM_MODE_64,
            {0x0f, 0x01, 0xda}, 3, CDISASM_X86_NAME_VMLOAD,
            "vmload rax", CDISASM_X86_GROUP_SVM, CDISASM_GROUP_PRIVILEGED},
        {"VMSAVE", CDISASM_CPU_AMD_V, CDISASM_MODE_64,
            {0x0f, 0x01, 0xdb}, 3, CDISASM_X86_NAME_VMSAVE,
            "vmsave", CDISASM_X86_GROUP_SVM, CDISASM_GROUP_PRIVILEGED},
        {"STGI", CDISASM_CPU_AMD_V, CDISASM_MODE_64,
            {0x0f, 0x01, 0xdc}, 3, CDISASM_X86_NAME_STGI,
            "stgi", CDISASM_X86_GROUP_SVM, CDISASM_GROUP_PRIVILEGED},
        {"CLGI", CDISASM_CPU_AMD_V, CDISASM_MODE_64,
            {0x0f, 0x01, 0xdd}, 3, CDISASM_X86_NAME_CLGI,
            "clgi", CDISASM_X86_GROUP_SVM, CDISASM_GROUP_PRIVILEGED},
        {"SKINIT", CDISASM_CPU_AMD_V, CDISASM_MODE_64,
            {0x0f, 0x01, 0xde}, 3, CDISASM_X86_NAME_SKINIT,
            "skinit eax", CDISASM_X86_GROUP_SVM, CDISASM_GROUP_PRIVILEGED},
        {"INVLPGA", CDISASM_CPU_AMD_V, CDISASM_MODE_64,
            {0x0f, 0x01, 0xdf}, 3, CDISASM_X86_NAME_INVLPGA,
            "invlpga rax, ecx", CDISASM_X86_GROUP_SVM,
            CDISASM_GROUP_PRIVILEGED},
        {"VMRUN mode16", CDISASM_CPU_AMD_V, CDISASM_MODE_16,
            {0x0f, 0x01, 0xd8}, 3, CDISASM_X86_NAME_VMRUN,
            "vmrun ax", CDISASM_X86_GROUP_SVM, CDISASM_GROUP_PRIVILEGED},
        {"VMRUN mode16 address override", CDISASM_CPU_AMD_V,
            CDISASM_MODE_16, {0x67, 0x0f, 0x01, 0xd8}, 4,
            CDISASM_X86_NAME_VMRUN, "vmrun eax", CDISASM_X86_GROUP_SVM,
            CDISASM_GROUP_PRIVILEGED},
        {"VMRUN mode32 address override", CDISASM_CPU_AMD_V,
            CDISASM_MODE_32, {0x67, 0x0f, 0x01, 0xd8}, 4,
            CDISASM_X86_NAME_VMRUN, "vmrun ax", CDISASM_X86_GROUP_SVM,
            CDISASM_GROUP_PRIVILEGED},
        {"VMRUN mode64 address override", CDISASM_CPU_AMD_V,
            CDISASM_MODE_64, {0x67, 0x0f, 0x01, 0xd8}, 4,
            CDISASM_X86_NAME_VMRUN, "vmrun eax", CDISASM_X86_GROUP_SVM,
            CDISASM_GROUP_PRIVILEGED},
        {"VMGEXIT F2", CDISASM_CPU_AMD_ZEN_4, CDISASM_MODE_64,
            {0xf2, 0x0f, 0x01, 0xd9}, 4, CDISASM_X86_NAME_VMGEXIT,
            "vmgexit", CDISASM_X86_GROUP_SVM, CDISASM_GROUP_NONE},
        {"VMGEXIT F3", CDISASM_CPU_AMD_ZEN_4, CDISASM_MODE_64,
            {0xf3, 0x0f, 0x01, 0xd9}, 4, CDISASM_X86_NAME_VMGEXIT,
            "vmgexit", CDISASM_X86_GROUP_SVM, CDISASM_GROUP_NONE},
        {"VMGEXIT fallback", CDISASM_CPU_AMD_ZEN, CDISASM_MODE_64,
            {0xf2, 0x0f, 0x01, 0xd9}, 4, CDISASM_X86_NAME_VMMCALL,
            "vmmcall", CDISASM_X86_GROUP_SVM, CDISASM_GROUP_NONE},
    };
    static const uint8_t vmrun[] = {0x0f, 0x01, 0xd8};
    static const cdisasm_cpu_id amd_svm_profiles[] = {
        CDISASM_CPU_X86,
        CDISASM_CPU_AMD_V,
        CDISASM_CPU_AMD_BARCELONA,
        CDISASM_CPU_AMD_BULLDOZER,
        CDISASM_CPU_AMD_ZEN,
        CDISASM_CPU_AMD_ZEN_4
    };
    cdisasm_instruction instruction;
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        if (decode_success(&cases[index], &instruction)) {
            size_t operand_index;
            for (operand_index = 0;
                 operand_index < instruction.operand_count;
                 ++operand_index) {
                EXPECT((instruction.opcode[operand_index].flags
                    & CDISASM_OPERAND_FLAG_IMPLICIT) != 0);
            }
        }
    }
    for (index = 0;
         index < sizeof(amd_svm_profiles) / sizeof(amd_svm_profiles[0]);
         ++index) {
        EXPECT(cdisasm_x86_decode(
                   amd_svm_profiles[index],
                   CDISASM_MODE_64,
                   vmrun,
                   sizeof(vmrun),
                   0,
                   CDISASM_X86_TEST_ALL_FLAGS,
                   &instruction)
            == sizeof(vmrun));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VMRUN);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction,
            CDISASM_X86_GROUP_SVM));
    }

    expect_failure("SVM before AMD-V", CDISASM_CPU_ATHLON_64,
        CDISASM_MODE_64, vmrun, sizeof(vmrun),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("SVM on Intel VT-x", CDISASM_CPU_INTEL_VT_X,
        CDISASM_MODE_64, vmrun, sizeof(vmrun),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("SVM on later Intel", CDISASM_CPU_HASWELL,
        CDISASM_MODE_64, vmrun, sizeof(vmrun),
        CDISASM_STATUS_INVALID_INSTRUCTION);
}

static void test_undocumented_and_reserved(void)
{
    static const opcode_case cases[] = {
        {"SALC mode16", CDISASM_CPU_8086, CDISASM_MODE_16,
            {0xd6}, 1, CDISASM_X86_NAME_SALC, "salc",
            CDISASM_X86_GROUP_I86, CDISASM_GROUP_NONE},
        {"SALC mode32", CDISASM_CPU_80386, CDISASM_MODE_32,
            {0xd6}, 1, CDISASM_X86_NAME_SALC, "salc",
            CDISASM_X86_GROUP_I86, CDISASM_GROUP_NONE},
        {"UDB mode64", CDISASM_CPU_X86, CDISASM_MODE_64,
            {0xd6}, 1, CDISASM_X86_NAME_UDB, "udb",
            CDISASM_X86_GROUP_AMD64, CDISASM_GROUP_NONE},
        {"UD0 Pentium Pro short", CDISASM_CPU_PENTIUM_PRO,
            CDISASM_MODE_16, {0x0f, 0xff}, 2, CDISASM_X86_NAME_UD0,
            "ud0", CDISASM_X86_GROUP_P6, CDISASM_GROUP_NONE},
        {"UD0 Pentium 4 long fixed dword", CDISASM_CPU_PENTIUM_4,
            CDISASM_MODE_16, {0x0f, 0xff, 0xc1}, 3,
            CDISASM_X86_NAME_UD0, "ud0 eax, ecx",
            CDISASM_X86_GROUP_P6, CDISASM_GROUP_NONE},
        {"UD0 Goldmont short", CDISASM_CPU_GOLDMONT, CDISASM_MODE_64,
            {0x0f, 0xff}, 2, CDISASM_X86_NAME_UD0, "ud0",
            CDISASM_X86_GROUP_P6, CDISASM_GROUP_NONE},
        {"UD0 Celeron G1840 long", CDISASM_CPU_CELERON_G1840,
            CDISASM_MODE_64, {0x0f, 0xff, 0xc1}, 3,
            CDISASM_X86_NAME_UD0, "ud0 eax, ecx",
            CDISASM_X86_GROUP_P6, CDISASM_GROUP_NONE},
        {"UD0 Celeron G3900 long", CDISASM_CPU_CELERON_G3900,
            CDISASM_MODE_64, {0x0f, 0xff, 0xc1}, 3,
            CDISASM_X86_NAME_UD0, "ud0 eax, ecx",
            CDISASM_X86_GROUP_P6, CDISASM_GROUP_NONE},
        {"UD0 Celeron N3350 short", CDISASM_CPU_CELERON_N3350,
            CDISASM_MODE_64, {0x0f, 0xff}, 2,
            CDISASM_X86_NAME_UD0, "ud0",
            CDISASM_X86_GROUP_P6, CDISASM_GROUP_NONE},
        {"UD0 Celeron N4020 short", CDISASM_CPU_CELERON_N4020,
            CDISASM_MODE_64, {0x0f, 0xff}, 2,
            CDISASM_X86_NAME_UD0, "ud0",
            CDISASM_X86_GROUP_P6, CDISASM_GROUP_NONE},
        {"UD0 Celeron G5900 long", CDISASM_CPU_CELERON_G5900,
            CDISASM_MODE_64, {0x0f, 0xff, 0xc1}, 3,
            CDISASM_X86_NAME_UD0, "ud0 eax, ecx",
            CDISASM_X86_GROUP_P6, CDISASM_GROUP_NONE},
        {"UD0 Pentium Silver N6000 short",
            CDISASM_CPU_PENTIUM_SILVER_N6000, CDISASM_MODE_64,
            {0x0f, 0xff}, 2, CDISASM_X86_NAME_UD0, "ud0",
            CDISASM_X86_GROUP_P6, CDISASM_GROUP_NONE},
        {"UD1 Pentium Pro ModRM", CDISASM_CPU_PENTIUM_PRO,
            CDISASM_MODE_16, {0x0f, 0xb9, 0xc1}, 3,
            CDISASM_X86_NAME_UD1, "ud1 eax, ecx",
            CDISASM_X86_GROUP_P6, CDISASM_GROUP_NONE},
        {"UD1 Pentium II ModRM", CDISASM_CPU_PENTIUM_II,
            CDISASM_MODE_32, {0x0f, 0xb9, 0xc1}, 3,
            CDISASM_X86_NAME_UD1, "ud1 eax, ecx",
            CDISASM_X86_GROUP_P6, CDISASM_GROUP_NONE},
        {"UD1 SIB memory", CDISASM_CPU_X86, CDISASM_MODE_32,
            {0x0f, 0xb9, 0x44, 0x88, 0x10}, 5,
            CDISASM_X86_NAME_UD1,
            "ud1 eax, dword ptr [eax + ecx*4 + 0x10]",
            CDISASM_X86_GROUP_P6, CDISASM_GROUP_NONE},
        {"UD0 ignores REX.W operand width", CDISASM_CPU_X86,
            CDISASM_MODE_64, {0x4d, 0x0f, 0xff, 0xc1}, 4,
            CDISASM_X86_NAME_UD0, "ud0 r8d, r9d",
            CDISASM_X86_GROUP_P6, CDISASM_GROUP_NONE},
        {"UD1 RIP relative", CDISASM_CPU_X86, CDISASM_MODE_64,
            {0x0f, 0xb9, 0x05, 0x34, 0x12, 0x00, 0x00}, 7,
            CDISASM_X86_NAME_UD1,
            "ud1 eax, dword ptr [rip + 0x1234]",
            CDISASM_X86_GROUP_P6, CDISASM_GROUP_NONE},
        {"LOADALL286", CDISASM_CPU_80286, CDISASM_MODE_16,
            {0x0f, 0x05}, 2, CDISASM_X86_NAME_LOADALL286, "loadall286",
            CDISASM_X86_GROUP_I286, CDISASM_GROUP_PRIVILEGED},
        {"LOADALL386 mode16", CDISASM_CPU_80386, CDISASM_MODE_16,
            {0x0f, 0x07}, 2, CDISASM_X86_NAME_LOADALL, "loadall",
            CDISASM_X86_GROUP_I386, CDISASM_GROUP_PRIVILEGED},
        {"LOADALL386 mode32", CDISASM_CPU_80386, CDISASM_MODE_32,
            {0x0f, 0x07}, 2, CDISASM_X86_NAME_LOADALL, "loadall",
            CDISASM_X86_GROUP_I386, CDISASM_GROUP_PRIVILEGED},
        {"generic 0F05 remains SYSCALL", CDISASM_CPU_X86,
            CDISASM_MODE_64, {0x0f, 0x05}, 2, CDISASM_X86_NAME_SYSCALL,
            "syscall", CDISASM_X86_GROUP_AMD64, CDISASM_GROUP_INTERRUPT},
        {"generic 0F07 remains SYSRET", CDISASM_CPU_X86,
            CDISASM_MODE_64, {0x0f, 0x07}, 2, CDISASM_X86_NAME_SYSRET,
            "sysret", CDISASM_X86_GROUP_AMD64,
            CDISASM_GROUP_INTERRUPT_RETURN | CDISASM_GROUP_PRIVILEGED},
        {"ICEBP canonical INT1", CDISASM_CPU_80386, CDISASM_MODE_32,
            {0xf1}, 1, CDISASM_X86_NAME_ICEBP, "int1",
            CDISASM_X86_GROUP_I386, CDISASM_GROUP_INTERRUPT},
        {"opcode 82 alias", CDISASM_CPU_8086, CDISASM_MODE_16,
            {0x82, 0xc0, 0x7f}, 3, CDISASM_X86_NAME_ADD,
            "add al, 0x7f", CDISASM_X86_GROUP_I86, CDISASM_GROUP_NONE},
        {"shift group /6 alias", CDISASM_CPU_80186, CDISASM_MODE_16,
            {0xd0, 0xf0}, 2, CDISASM_X86_NAME_SHL,
            "shl al, 1", CDISASM_X86_GROUP_I186, CDISASM_GROUP_NONE},
        {"shift immediate /6 alias", CDISASM_CPU_80186, CDISASM_MODE_16,
            {0xc1, 0xf0, 0x04}, 3, CDISASM_X86_NAME_SHL,
            "shl ax, 0x4", CDISASM_X86_GROUP_I186, CDISASM_GROUP_NONE},
        {"F6 TEST /1 alias", CDISASM_CPU_8086, CDISASM_MODE_16,
            {0xf6, 0xc8, 0x7f}, 3, CDISASM_X86_NAME_TEST,
            "test al, 0x7f", CDISASM_X86_GROUP_I86, CDISASM_GROUP_NONE},
        {"F7 TEST /1 alias", CDISASM_CPU_X86, CDISASM_MODE_64,
            {0x48, 0xf7, 0xc8, 0xff, 0xff, 0xff, 0xff}, 7,
            CDISASM_X86_NAME_TEST, "test rax, -0x1",
            CDISASM_X86_GROUP_AMD64, CDISASM_GROUP_NONE},
    };
    static const uint8_t icebp[] = {0xf1};
    static const uint8_t loadall286[] = {0x0f, 0x05};
    static const uint8_t loadall386[] = {0x0f, 0x07};
    static const uint8_t opcode82[] = {0x82, 0xc0, 0x7f};
    static const uint8_t shift6[] = {0xd0, 0xf0};
    static const uint8_t ud0_long[] = {0x0f, 0xff, 0xc1};
    static const uint8_t ud0_short[] = {0x0f, 0xff};
    static const uint8_t ud1[] = {0x0f, 0xb9, 0xc1};
    static const uint8_t ud1_sib[] = {0x0f, 0xb9, 0x44, 0x88, 0x10};
    static const uint8_t ud1_truncated[] = {0x0f, 0xb9};
    static const uint8_t ud0_displacement_truncated[] = {
        0x0f, 0xff, 0x05, 0x34, 0x12
    };
    cdisasm_instruction instruction;
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        decode_success(&cases[index], &instruction);
    }

    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_X86,
               CDISASM_MODE_32,
               ud1_sib,
               sizeof(ud1_sib),
               0,
               CDISASM_X86_TEST_ALL_FLAGS,
               &instruction)
        == sizeof(ud1_sib));
    EXPECT(instruction.opcode_size == 5);
    EXPECT(instruction.operand_count == 2);
    EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_EAX);
    EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_EAX);
    EXPECT(instruction.opcode[1].index_reg == CDISASM_X86_REG_ECX);
    EXPECT(instruction.opcode[1].scale == 4);
    EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.encoding.opcode_offset == 0);
    EXPECT(instruction.encoding.opcode_size == 2);
    EXPECT(instruction.encoding.modrm_offset == 2);
    EXPECT(instruction.encoding.sib_offset == 3);
    EXPECT(instruction.encoding.displacement_offset == 4);
    EXPECT(instruction.encoding.displacement_size == 1);

    expect_failure("INT1 before 386", CDISASM_CPU_80286,
        CDISASM_MODE_16, icebp, sizeof(icebp),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("0F05 is not LOADALL on 386", CDISASM_CPU_80386,
        CDISASM_MODE_16, loadall286, sizeof(loadall286),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("0F07 is not LOADALL on 286", CDISASM_CPU_80286,
        CDISASM_MODE_16, loadall386, sizeof(loadall386),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("LOADALL does not extend to 486", CDISASM_CPU_80486,
        CDISASM_MODE_32, loadall386, sizeof(loadall386),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("opcode 82 is invalid in mode64", CDISASM_CPU_X86,
        CDISASM_MODE_64, opcode82, sizeof(opcode82),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("8086 /6 is not the later SHL alias", CDISASM_CPU_8086,
        CDISASM_MODE_16, shift6, sizeof(shift6),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_PENTIUM_PRO,
               CDISASM_MODE_16,
               ud0_long,
               sizeof(ud0_long),
               0,
               CDISASM_X86_TEST_ALL_FLAGS,
               &instruction)
        == sizeof(ud0_short));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_UD0);
    EXPECT(instruction.operand_count == 0);
    EXPECT(instruction.encoding.modrm_offset == 0);
    EXPECT(instruction.encoding.modrm == 0);

    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_GOLDMONT,
               CDISASM_MODE_64,
               ud0_long,
               sizeof(ud0_long),
               0,
               CDISASM_X86_TEST_ALL_FLAGS,
               &instruction)
        == sizeof(ud0_short));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_UD0);
    EXPECT(instruction.operand_count == 0);

    EXPECT(cdisasm_x86_decode(
               CDISASM_CPU_PENTIUM_4,
               CDISASM_MODE_32,
               ud0_long,
               sizeof(ud0_long),
               0,
               CDISASM_X86_TEST_ALL_FLAGS,
               &instruction)
        == sizeof(ud0_long));
    EXPECT(instruction.operand_count == 2);
    EXPECT(instruction.encoding.modrm_offset == 2);

    expect_failure("UD0 before P6", CDISASM_CPU_PENTIUM,
        CDISASM_MODE_16, ud0_long, sizeof(ud0_long),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("UD0 absent from Pentium II XED profile",
        CDISASM_CPU_PENTIUM_II, CDISASM_MODE_32,
        ud0_long, sizeof(ud0_long), CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("UD0 absent from Pentium III XED profile",
        CDISASM_CPU_PENTIUM_III, CDISASM_MODE_32,
        ud0_long, sizeof(ud0_long), CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("UD0 is not an AMD K6-2 feature", CDISASM_CPU_AMD_K6_2,
        CDISASM_MODE_32, ud0_long, sizeof(ud0_long),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("UD0 is not an AMD64 profile feature",
        CDISASM_CPU_ATHLON_64, CDISASM_MODE_64,
        ud0_long, sizeof(ud0_long), CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("UD1 before P6", CDISASM_CPU_PENTIUM,
        CDISASM_MODE_16, ud1, sizeof(ud1),
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_failure("truncated UD1 ModRM", CDISASM_CPU_PENTIUM_PRO,
        CDISASM_MODE_32, ud1_truncated, sizeof(ud1_truncated),
        CDISASM_STATUS_TRUNCATED);
    expect_failure("generic UD0 chooses modern long form", CDISASM_CPU_X86,
        CDISASM_MODE_32, ud0_short, sizeof(ud0_short),
        CDISASM_STATUS_TRUNCATED);
    expect_failure("Pentium 4 UD0 requires ModRM", CDISASM_CPU_PENTIUM_4,
        CDISASM_MODE_32, ud0_short, sizeof(ud0_short),
        CDISASM_STATUS_TRUNCATED);
    expect_failure("truncated UD0 displacement", CDISASM_CPU_X86,
        CDISASM_MODE_32, ud0_displacement_truncated,
        sizeof(ud0_displacement_truncated), CDISASM_STATUS_TRUNCATED);
}

int main(void)
{
    test_intel_vmx();
    test_amd_svm();
    test_undocumented_and_reserved();

    if (failures != 0) {
        fprintf(stderr, "%d virtualization/undocumented test(s) failed\n", failures);
        return 1;
    }
    puts("all virtualization and undocumented opcode tests passed");
    return 0;
}
