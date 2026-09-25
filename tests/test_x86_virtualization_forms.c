#include "cdisasm/cdisasm_x86.h"

#if USE_DISASM_FORMAT
#  include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if !USE_EXTRA_OPCODES

int main(void)
{
    static const struct {
        uint8_t code[8];
        size_t size;
        cdisasm_x86_mode mode;
        cdisasm_status status;
    } cases[] = {
        {{0x0f,0xc7,0x30},3,CDISASM_MODE_64,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION},
        {{0x0f,0x78,0xc1},3,CDISASM_MODE_64,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION},
        {{0x0f,0x79,0xc1},3,CDISASM_MODE_32,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION},
        {{0x0f,0x79,0x01},3,CDISASM_MODE_32,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION},
        {{0x0f,0x79,0xc1},3,CDISASM_MODE_64,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION},
        {{0x0f,0x79,0x01},3,CDISASM_MODE_64,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION},
        {{0x0f,0x01,0xc4},3,CDISASM_MODE_64,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION},
        {{0xf3,0x0f,0xc7,0x30},4,CDISASM_MODE_64,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION},
        {{0xd5,0xff,0x79,0xc1},4,CDISASM_MODE_64,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION},
        {{0xd5,0xff,0x01,0xc4},4,CDISASM_MODE_64,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION},
        {{0xf3,0xd5,0xff,0xc7,0x30},5,CDISASM_MODE_64,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION},
        {{0x66,0x0f,0x79,0xc1,0x00,0x00},6,CDISASM_MODE_64,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION},
        {{0xf2,0xd5,0xff,0x79,0xc1,0x00,0x00},7,CDISASM_MODE_64,
            CDISASM_STATUS_UNSUPPORTED_INSTRUCTION},
        {{0xf3,0x0f,0x79,0xc1},4,CDISASM_MODE_64,
            CDISASM_STATUS_INVALID_INSTRUCTION},
        {{0x66,0x0f,0x01,0xc4},4,CDISASM_MODE_64,
            CDISASM_STATUS_INVALID_INSTRUCTION},
        {{0xf3,0x0f,0x79,0x04},4,CDISASM_MODE_64,
            CDISASM_STATUS_TRUNCATED},
        {{0xd5,0xff,0x79,0x04},4,CDISASM_MODE_64,
            CDISASM_STATUS_TRUNCATED}
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_x86_decode_flags flags =
            CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
        cdisasm_instruction instruction;
        cdisasm_instruction expected;
        uint32_t decoded_size;

        if (cdisasm_x86_cpu_decode_flag_mask(
                CDISASM_CPU_X86, cases[index].mode, &flags)
            != CDISASM_STATUS_OK) {
            return 1;
        }
        memset(&instruction, 0xa5, sizeof(instruction));
        decoded_size = cdisasm_x86_decode(
            CDISASM_CPU_X86, cases[index].mode,
            cases[index].code, cases[index].size, UINT64_C(0x1000),
            &flags, &instruction);
        memset(&expected, 0, sizeof(expected));
        expected.last_error_id = (uint8_t)cases[index].status;
        if (decoded_size != 0u
            || memcmp(&instruction, &expected, sizeof(expected)) != 0) {
            fprintf(stderr,
                "OFF virtualization case %zu did not return zeroed status %u\n",
                index, (unsigned int)cases[index].status);
            return 1;
        }
    }
    puts("x86 virtualization-form OFF contract passed");
    return 0;
}

#else

static int failures;

#define EXPECT(expression)                                                   \
    do {                                                                     \
        if (!(expression)) {                                                 \
            if (failures < 64) {                                             \
                fprintf(stderr, "%s:%d: expectation failed: %s\n",        \
                    __FILE__, __LINE__, #expression);                        \
            }                                                                \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

_Static_assert(CDISASM_X86_NAME_VMPTRLD == UINT16_C(232)
        && CDISASM_X86_NAME_VMPTRST == UINT16_C(233)
        && CDISASM_X86_NAME_VMREAD == UINT16_C(234)
        && CDISASM_X86_NAME_VMRESUME == UINT16_C(235)
        && CDISASM_X86_NAME_VMRUN == UINT16_C(236)
        && CDISASM_X86_NAME_VMSAVE == UINT16_C(237)
        && CDISASM_X86_NAME_VMWRITE == UINT16_C(238)
        && CDISASM_X86_NAME_VMXOFF == UINT16_C(239)
        && CDISASM_X86_NAME_VMXON == UINT16_C(240),
    "virtualization name IDs changed");
_Static_assert(CDISASM_X86_GROUP_VMX == UINT16_C(26)
        && CDISASM_X86_GROUP_SVM == UINT16_C(27)
        && CDISASM_X86_GROUP_APX_F == UINT16_C(91)
        && CDISASM_X86_GROUP_VTX == UINT16_C(321),
    "virtualization/APX group IDs changed");
_Static_assert(CDISASM_X86_DECODE_BIT_APX == UINT32_C(22)
        && CDISASM_X86_DECODE_BIT_VMX == UINT32_C(53)
        && CDISASM_X86_DECODE_BIT_SVM == UINT32_C(54)
        && CDISASM_X86_DECODE_BIT_VTX == UINT32_C(267),
    "virtualization/APX decode bits changed");
_Static_assert(CDISASM_CPU_LAST == CDISASM_CPU_KNIGHTS_MILL,
    "update virtualization profile sweeps");

static int is_error_only(
    const cdisasm_instruction *instruction,
    cdisasm_status status)
{
    cdisasm_instruction expected;

    memset(&expected, 0, sizeof(expected));
    expected.last_error_id = (uint8_t)status;
    return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static cdisasm_instruction decode(
    cdisasm_x86_cpu_id cpu_id,
    cdisasm_x86_mode mode,
    const uint8_t *code,
    size_t size,
    const cdisasm_x86_decode_flags *flags,
    uint32_t *decoded_size)
{
    cdisasm_instruction instruction;

    memset(&instruction, 0xa5, sizeof(instruction));
    *decoded_size = cdisasm_x86_decode(
        cpu_id, mode, code, size, UINT64_C(0x1000), flags, &instruction);
    return instruction;
}

static void expect_error(
    const char *label,
    cdisasm_x86_cpu_id cpu_id,
    cdisasm_x86_mode mode,
    const uint8_t *code,
    size_t size,
    const cdisasm_x86_decode_flags *flags,
    cdisasm_status status)
{
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode(
        cpu_id, mode, code, size, flags, &decoded_size);

    if (decoded_size != 0u || !is_error_only(&instruction, status)) {
        fprintf(stderr, "%s: got size/status %u/%u, expected 0/%u\n",
            label, (unsigned int)decoded_size,
            (unsigned int)instruction.last_error_id,
            (unsigned int)status);
    }
    EXPECT(decoded_size == 0u);
    EXPECT(is_error_only(&instruction, status));
}

static cdisasm_x86_decode_flags one_bit(cdisasm_x86_decode_bit_id bit_id)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_decode_flags_set_bit(&flags, bit_id));
    return flags;
}

static cdisasm_x86_decode_flags all_flags(cdisasm_x86_mode mode)
{
    cdisasm_x86_decode_flags flags =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;

    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
        CDISASM_CPU_X86, mode, &flags) == CDISASM_STATUS_OK);
    return flags;
}

static int is_vtx_form(cdisasm_x86_form_id form_id)
{
    return (form_id >= UINT16_C(5997) && form_id <= UINT16_C(6003))
        || (form_id >= UINT16_C(6048) && form_id <= UINT16_C(6053));
}

static void check_common(
    const char *label,
    const cdisasm_instruction *instruction,
    uint32_t decoded_size,
    cdisasm_x86_name_id name_id,
    cdisasm_x86_form_id form_id,
    unsigned int operand_count,
    cdisasm_x86_group_id family,
    int apx)
{
    if (decoded_size == 0u
        || instruction->last_error_id != CDISASM_STATUS_OK
        || instruction->name_id != name_id
        || instruction->form_id != form_id) {
        fprintf(stderr,
            "%s: size/status/name/form %u/%u/%u/%u, expected nonzero/0/%u/%u\n",
            label, (unsigned int)decoded_size,
            (unsigned int)instruction->last_error_id,
            (unsigned int)instruction->name_id,
            (unsigned int)instruction->form_id,
            (unsigned int)name_id, (unsigned int)form_id);
    }
    EXPECT(decoded_size != 0u);
    EXPECT(instruction->last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction->name_id == name_id);
    EXPECT(instruction->form_id == form_id);
    EXPECT(instruction->operand_count == operand_count);
    EXPECT((instruction->opcode_flags
        & (CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK
            | CDISASM_X86_INSTRUCTION_FLAG_OPERANDS_OPAQUE)) == 0u);
    EXPECT((instruction->opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0u);
    EXPECT(cdisasm_instruction_has_x86_group(instruction, family));
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_APX_F) == apx);
    EXPECT(cdisasm_instruction_has_x86_group(
        instruction, CDISASM_X86_GROUP_VTX)
        == is_vtx_form(form_id));
    EXPECT(((instruction->opcode_flags
        & CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS) != 0u)
        == is_vtx_form(form_id));
}

static void test_exact_forms(void)
{
    static const struct {
        const char *label;
        cdisasm_x86_mode mode;
        uint8_t code[4];
        size_t size;
        cdisasm_x86_name_id name_id;
        cdisasm_x86_form_id form_id;
        unsigned int operand_count;
        cdisasm_x86_group_id family;
    } cases[] = {
        {"5997 VMPTRLD", CDISASM_MODE_64, {0x0f,0xc7,0x30,0}, 3,
            CDISASM_X86_NAME_VMPTRLD, UINT16_C(5997), 1,
            CDISASM_X86_GROUP_VMX},
        {"5998 VMPTRST", CDISASM_MODE_64, {0x0f,0xc7,0x38,0}, 3,
            CDISASM_X86_NAME_VMPTRST, UINT16_C(5998), 1,
            CDISASM_X86_GROUP_VMX},
        {"5999 VMREAD rr32", CDISASM_MODE_32, {0x0f,0x78,0xc1,0}, 3,
            CDISASM_X86_NAME_VMREAD, UINT16_C(5999), 2,
            CDISASM_X86_GROUP_VMX},
        {"6000 VMREAD rr64", CDISASM_MODE_64, {0x0f,0x78,0xc1,0}, 3,
            CDISASM_X86_NAME_VMREAD, UINT16_C(6000), 2,
            CDISASM_X86_GROUP_VMX},
        {"6001 VMREAD md", CDISASM_MODE_32, {0x0f,0x78,0x00,0}, 3,
            CDISASM_X86_NAME_VMREAD, UINT16_C(6001), 2,
            CDISASM_X86_GROUP_VMX},
        {"6002 VMREAD mq", CDISASM_MODE_64, {0x0f,0x78,0x00,0}, 3,
            CDISASM_X86_NAME_VMREAD, UINT16_C(6002), 2,
            CDISASM_X86_GROUP_VMX},
        {"6003 VMRESUME", CDISASM_MODE_64, {0x0f,0x01,0xc3,0}, 3,
            CDISASM_X86_NAME_VMRESUME, UINT16_C(6003), 0,
            CDISASM_X86_GROUP_VMX},
        {"6004 VMRUN", CDISASM_MODE_64, {0x0f,0x01,0xd8,0}, 3,
            CDISASM_X86_NAME_VMRUN, UINT16_C(6004), 1,
            CDISASM_X86_GROUP_SVM},
        {"6005 VMSAVE", CDISASM_MODE_64, {0x0f,0x01,0xdb,0}, 3,
            CDISASM_X86_NAME_VMSAVE, UINT16_C(6005), 0,
            CDISASM_X86_GROUP_SVM},
        {"6048 VMWRITE rr32", CDISASM_MODE_16, {0x0f,0x79,0xc1,0}, 3,
            CDISASM_X86_NAME_VMWRITE, UINT16_C(6048), 2,
            CDISASM_X86_GROUP_VMX},
        {"6049 VMWRITE md", CDISASM_MODE_32, {0x0f,0x79,0x01,0}, 3,
            CDISASM_X86_NAME_VMWRITE, UINT16_C(6049), 2,
            CDISASM_X86_GROUP_VMX},
        {"6050 VMWRITE rr64", CDISASM_MODE_64, {0x0f,0x79,0xc1,0}, 3,
            CDISASM_X86_NAME_VMWRITE, UINT16_C(6050), 2,
            CDISASM_X86_GROUP_VMX},
        {"6051 VMWRITE mq", CDISASM_MODE_64, {0x0f,0x79,0x01,0}, 3,
            CDISASM_X86_NAME_VMWRITE, UINT16_C(6051), 2,
            CDISASM_X86_GROUP_VMX},
        {"6052 VMXOFF", CDISASM_MODE_16, {0x0f,0x01,0xc4,0}, 3,
            CDISASM_X86_NAME_VMXOFF, UINT16_C(6052), 0,
            CDISASM_X86_GROUP_VMX},
        {"6053 VMXON", CDISASM_MODE_32, {0xf3,0x0f,0xc7,0x30}, 4,
            CDISASM_X86_NAME_VMXON, UINT16_C(6053), 1,
            CDISASM_X86_GROUP_VMX}
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_x86_decode_flags flags = all_flags(cases[index].mode);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(
            CDISASM_CPU_X86, cases[index].mode,
            cases[index].code, cases[index].size, &flags, &decoded_size);

        check_common(cases[index].label, &instruction, decoded_size,
            cases[index].name_id, cases[index].form_id,
            cases[index].operand_count, cases[index].family, 0);
        EXPECT(decoded_size == cases[index].size);
        EXPECT(instruction.encoding.prefix_size
            == (cases[index].form_id == UINT16_C(6053) ? 1u : 0u));
        EXPECT(instruction.encoding.opcode_offset
            == (cases[index].form_id == UINT16_C(6053) ? 1u : 0u));
        EXPECT(instruction.encoding.opcode_size == 2u);
        EXPECT(instruction.encoding.modrm_offset
            == (cases[index].form_id == UINT16_C(6053) ? 3u : 2u));
        EXPECT(instruction.encoding.modrm == cases[index].code[
            cases[index].form_id == UINT16_C(6053) ? 3u : 2u]);
        EXPECT(instruction.encoding.immediate_count == 0u);

        if (is_vtx_form(cases[index].form_id)) {
            cdisasm_x86_decode_flags exact =
                one_bit(CDISASM_X86_DECODE_BIT_VTX);

            instruction = decode(CDISASM_CPU_X86, cases[index].mode,
                cases[index].code, cases[index].size,
                &exact, &decoded_size);
            check_common("exact VTX runtime bit", &instruction,
                decoded_size, cases[index].name_id, cases[index].form_id,
                cases[index].operand_count, CDISASM_X86_GROUP_VMX, 0);
        }
    }

    {
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            CDISASM_MODE_64, cases[0].code, cases[0].size,
            &flags, &decoded_size);

        EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.opcode[0].size == 8u);
        EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[1].code, cases[1].size, &flags, &decoded_size);
        EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.opcode[0].size == 8u);
        EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[3].code, cases[3].size, &flags, &decoded_size);
        EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_RCX);
        EXPECT(instruction.opcode[0].size == 8u);
        EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
        EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_RAX);
        EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[7].code, cases[7].size, &flags, &decoded_size);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_RAX);
        EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT((instruction.opcode[0].flags
            & CDISASM_OPERAND_FLAG_IMPLICIT) != 0u);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[11].code, cases[11].size, &flags, &decoded_size);
        EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_RAX);
        EXPECT(instruction.opcode[0].size == 8u);
        EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_RCX);
        EXPECT(instruction.opcode[1].size == 8u);
        EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[12].code, cases[12].size, &flags, &decoded_size);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_RAX);
        EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_RCX);
        EXPECT(instruction.opcode[1].size == 8u);
        EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            cases[14].code, cases[14].size, &flags, &decoded_size);
        EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_MEMORY);
        EXPECT(instruction.opcode[0].size == 8u);
        EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
    }
}

static void test_vmread_allocations(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint64_t legacy_counts[4] = {0,0,0,0};
    uint64_t rex2_counts[2] = {0,0};
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
        unsigned int modrm;

        for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
            uint8_t code[15] = {0x0f,0x78,(uint8_t)modrm};
            const int wide = modes[mode_index] == CDISASM_MODE_64;
            const int memory = (modrm & 0xc0u) != 0xc0u;
            const cdisasm_x86_form_id form_id = memory
                ? (wide ? UINT16_C(6002) : UINT16_C(6001))
                : (wide ? UINT16_C(6000) : UINT16_C(5999));
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
                modes[mode_index], code, sizeof(code), &flags, &decoded_size);

            check_common("legacy VMREAD ModRM sweep", &instruction,
                decoded_size, CDISASM_X86_NAME_VMREAD, form_id, 2,
                CDISASM_X86_GROUP_VMX, 0);
            EXPECT(instruction.opcode[0].type == (memory
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
            EXPECT(instruction.opcode[0].size == (wide ? 8u : 4u));
            EXPECT(instruction.opcode[0].access
                == CDISASM_OPERAND_ACCESS_WRITE);
            EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_REGISTER);
            EXPECT(instruction.opcode[1].size == (wide ? 8u : 4u));
            EXPECT(instruction.opcode[1].access
                == CDISASM_OPERAND_ACCESS_READ);
            ++legacy_counts[form_id - UINT16_C(5999)];
        }
    }
    EXPECT(legacy_counts[0] == UINT64_C(128));
    EXPECT(legacy_counts[1] == UINT64_C(64));
    EXPECT(legacy_counts[2] == UINT64_C(384));
    EXPECT(legacy_counts[3] == UINT64_C(192));

    {
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
        unsigned int payload;

        for (payload = UINT8_C(0x80); payload <= UINT8_MAX; ++payload) {
            unsigned int modrm;

            for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                uint8_t code[15] = {
                    0xd5,(uint8_t)payload,0x78,(uint8_t)modrm
                };
                const int memory = (modrm & 0xc0u) != 0xc0u;
                const cdisasm_x86_form_id form_id = memory
                    ? UINT16_C(6002) : UINT16_C(6000);
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
                    CDISASM_MODE_64, code, sizeof(code), &flags,
                    &decoded_size);

                check_common("REX2 VMREAD payload/ModRM sweep",
                    &instruction, decoded_size, CDISASM_X86_NAME_VMREAD,
                    form_id, 2, CDISASM_X86_GROUP_VMX, 1);
                EXPECT((instruction.opcode_flags
                    & CDISASM_PREFIX_REX2) != 0u);
                EXPECT(((instruction.opcode_flags
                    & CDISASM_PREFIX_REX_W) != 0u)
                    == ((payload & UINT8_C(0x08)) != 0u));
                EXPECT(instruction.encoding.prefix_size == 2u);
                EXPECT(instruction.encoding.opcode_offset == 2u);
                EXPECT(instruction.encoding.opcode_size == 1u);
                EXPECT(instruction.encoding.modrm_offset == 3u);
                EXPECT(instruction.opcode[0].type == (memory
                    ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
                EXPECT(instruction.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_WRITE);
                EXPECT(instruction.opcode[1].type
                    == CDISASM_OPERAND_REGISTER);
                EXPECT(instruction.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                ++rex2_counts[memory ? 1u : 0u];
            }
        }
    }
    EXPECT(rex2_counts[0] == UINT64_C(8192));
    EXPECT(rex2_counts[1] == UINT64_C(24576));

    {
        static const uint8_t high_registers[] = {0xd5,0xff,0x78,0xc1};
        static const uint8_t high_address[] = {
            0xd5,0xb0,0x78,0x04,0xa0
        };
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            CDISASM_MODE_64, high_registers, sizeof(high_registers),
            &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(high_registers));
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_R25);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_R24);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            high_address, sizeof(high_address), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(high_address));
        EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_R16);
        EXPECT(instruction.opcode[0].index_reg == CDISASM_X86_REG_R20);
        EXPECT(instruction.opcode[0].scale == 4u);
    }
}

static void test_vmwrite_allocations(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    uint64_t legacy_counts[4] = {0,0,0,0};
    uint64_t rex2_counts[2] = {0,0};
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
        unsigned int modrm;

        for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
            uint8_t code[15] = {0x0f,0x79,(uint8_t)modrm};
            const int wide = modes[mode_index] == CDISASM_MODE_64;
            const int memory = (modrm & 0xc0u) != 0xc0u;
            const cdisasm_x86_form_id form_id = memory
                ? (wide ? UINT16_C(6051) : UINT16_C(6049))
                : (wide ? UINT16_C(6050) : UINT16_C(6048));
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
                modes[mode_index], code, sizeof(code), &flags, &decoded_size);

            check_common("legacy VMWRITE ModRM sweep", &instruction,
                decoded_size, CDISASM_X86_NAME_VMWRITE, form_id, 2,
                CDISASM_X86_GROUP_VMX, 0);
            EXPECT(instruction.encoding.opcode_size == 2u);
            EXPECT(instruction.encoding.modrm_offset == 2u);
            EXPECT(instruction.encoding.modrm == (uint8_t)modrm);
            EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_REGISTER);
            EXPECT(instruction.opcode[0].size == (wide ? 8u : 4u));
            EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
            EXPECT(instruction.opcode[1].type == (memory
                ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
            EXPECT(instruction.opcode[1].size == (wide ? 8u : 4u));
            EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
            ++legacy_counts[form_id - UINT16_C(6048)];
        }
    }
    EXPECT(legacy_counts[0] == UINT64_C(128));
    EXPECT(legacy_counts[1] == UINT64_C(384));
    EXPECT(legacy_counts[2] == UINT64_C(64));
    EXPECT(legacy_counts[3] == UINT64_C(192));

    {
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
        unsigned int payload;

        for (payload = UINT8_C(0x80); payload <= UINT8_MAX; ++payload) {
            unsigned int modrm;

            for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                uint8_t code[15] = {
                    0xd5,(uint8_t)payload,0x79,(uint8_t)modrm
                };
                const int memory = (modrm & 0xc0u) != 0xc0u;
                const cdisasm_x86_form_id form_id = memory
                    ? UINT16_C(6051) : UINT16_C(6050);
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
                    CDISASM_MODE_64, code, sizeof(code), &flags,
                    &decoded_size);

                check_common("REX2 VMWRITE payload/ModRM sweep",
                    &instruction, decoded_size, CDISASM_X86_NAME_VMWRITE,
                    form_id, 2, CDISASM_X86_GROUP_VMX, 1);
                EXPECT((instruction.opcode_flags
                    & CDISASM_PREFIX_REX2) != 0u);
                EXPECT(((instruction.opcode_flags
                    & CDISASM_PREFIX_REX_W) != 0u)
                    == ((payload & UINT8_C(0x08)) != 0u));
                EXPECT(instruction.encoding.prefix_size == 2u);
                EXPECT(instruction.encoding.opcode_offset == 2u);
                EXPECT(instruction.encoding.opcode_size == 1u);
                EXPECT(instruction.encoding.modrm_offset == 3u);
                EXPECT(instruction.opcode[0].type
                    == CDISASM_OPERAND_REGISTER);
                EXPECT(instruction.opcode[0].access
                    == CDISASM_OPERAND_ACCESS_READ);
                EXPECT(instruction.opcode[1].type == (memory
                    ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
                EXPECT(instruction.opcode[1].access
                    == CDISASM_OPERAND_ACCESS_READ);
                ++rex2_counts[memory ? 1u : 0u];
            }
        }
    }
    EXPECT(rex2_counts[0] == UINT64_C(8192));
    EXPECT(rex2_counts[1] == UINT64_C(24576));

    {
        static const uint8_t high_registers[] = {0xd5,0xff,0x79,0xc1};
        static const uint8_t high_address[] = {
            0xd5,0xb0,0x79,0x04,0xa0
        };
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            CDISASM_MODE_64, high_registers, sizeof(high_registers),
            &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(high_registers));
        EXPECT(instruction.form_id == UINT16_C(6050));
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_R24);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_R25);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            high_address, sizeof(high_address), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(high_address));
        EXPECT(instruction.form_id == UINT16_C(6051));
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_RAX);
        EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_R16);
        EXPECT(instruction.opcode[1].index_reg == CDISASM_X86_REG_R20);
        EXPECT(instruction.opcode[1].scale == 4u);
    }
}

static void test_pointer_and_fixed_rex2_allocations(void)
{
    uint64_t pointer_counts[3] = {0,0,0};
    uint64_t fixed_counts[4] = {0,0,0,0};
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    unsigned int payload;

    for (payload = UINT8_C(0x80); payload <= UINT8_MAX; ++payload) {
        unsigned int selector;

        for (selector = 0u; selector < 3u; ++selector) {
            unsigned int rm;

            for (rm = 0u; rm < 8u; ++rm) {
                uint8_t code[15] = {0};
                const size_t prefix = selector == 2u ? 1u : 0u;
                const cdisasm_x86_name_id name_id = selector == 0u
                    ? CDISASM_X86_NAME_VMPTRLD
                    : selector == 1u
                        ? CDISASM_X86_NAME_VMPTRST
                        : CDISASM_X86_NAME_VMXON;
                const cdisasm_x86_form_id form_id = selector == 0u
                    ? UINT16_C(5997)
                    : selector == 1u ? UINT16_C(5998) : UINT16_C(6053);
                uint32_t decoded_size;
                cdisasm_instruction instruction;

                if (prefix != 0u) {
                    code[0] = UINT8_C(0xf3);
                }
                code[prefix] = UINT8_C(0xd5);
                code[prefix + 1u] = (uint8_t)payload;
                code[prefix + 2u] = UINT8_C(0xc7);
                code[prefix + 3u] = (uint8_t)((selector == 1u
                    ? UINT8_C(0x38) : UINT8_C(0x30)) | rm);
                instruction = decode(CDISASM_CPU_X86,
                    CDISASM_MODE_64, code, sizeof(code), &flags,
                    &decoded_size);

                check_common("REX2 pointer payload/rm sweep", &instruction,
                    decoded_size, name_id, form_id, 1,
                    CDISASM_X86_GROUP_VMX, 1);
                EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_MEMORY);
                EXPECT(instruction.opcode[0].size == 8u);
                EXPECT(instruction.opcode[0].access == (selector == 1u
                    ? CDISASM_OPERAND_ACCESS_WRITE
                    : CDISASM_OPERAND_ACCESS_READ));
                ++pointer_counts[selector];
            }
        }

        {
            static const uint8_t fixed[] = {0xc3,0xc4,0xd8,0xdb};
            static const cdisasm_x86_name_id names[] = {
                CDISASM_X86_NAME_VMRESUME,
                CDISASM_X86_NAME_VMXOFF,
                CDISASM_X86_NAME_VMRUN,
                CDISASM_X86_NAME_VMSAVE
            };
            static const cdisasm_x86_form_id forms[] = {
                UINT16_C(6003), UINT16_C(6052),
                UINT16_C(6004), UINT16_C(6005)
            };
            unsigned int index;

            for (index = 0u; index < 4u; ++index) {
                uint8_t code[] = {
                    0xd5,(uint8_t)payload,0x01,fixed[index]
                };
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
                    CDISASM_MODE_64, code, sizeof(code), &flags,
                    &decoded_size);

                check_common("REX2 fixed virtualization payload sweep",
                    &instruction, decoded_size, names[index], forms[index],
                    index == 2u ? 1u : 0u,
                    index <= 1u ? CDISASM_X86_GROUP_VMX
                                : CDISASM_X86_GROUP_SVM,
                    1);
                EXPECT(decoded_size == sizeof(code));
                if (index == 2u) {
                    EXPECT(instruction.opcode[0].reg
                        == CDISASM_X86_REG_RAX);
                    EXPECT((instruction.opcode[0].flags
                        & CDISASM_OPERAND_FLAG_IMPLICIT) != 0u);
                }
                ++fixed_counts[index];
            }
        }
    }
    EXPECT(pointer_counts[0] == UINT64_C(1024));
    EXPECT(pointer_counts[1] == UINT64_C(1024));
    EXPECT(pointer_counts[2] == UINT64_C(1024));
    EXPECT(fixed_counts[0] == UINT64_C(128));
    EXPECT(fixed_counts[1] == UINT64_C(128));
    EXPECT(fixed_counts[2] == UINT64_C(128));
    EXPECT(fixed_counts[3] == UINT64_C(128));

    {
        static const uint8_t high_address[] = {
            0xd5,0xb0,0xc7,0x34,0xa0
        };
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            CDISASM_MODE_64, high_address, sizeof(high_address),
            &flags, &decoded_size);

        EXPECT(decoded_size == sizeof(high_address));
        EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_R16);
        EXPECT(instruction.opcode[0].index_reg == CDISASM_X86_REG_R20);
        EXPECT(instruction.opcode[0].scale == 4u);
    }
}

static void test_vmxoff_allocation(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
        uint64_t vmxoff_count = 0u;
        unsigned int modrm;

        for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
            uint8_t code[15] = {0x0f,0x01,(uint8_t)modrm};
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
                modes[mode_index], code, sizeof(code), &flags, &decoded_size);

            if (decoded_size != 0u
                && instruction.name_id == CDISASM_X86_NAME_VMXOFF) {
                ++vmxoff_count;
                check_common("legacy Group-7 VMXOFF allocation",
                    &instruction, decoded_size, CDISASM_X86_NAME_VMXOFF,
                    UINT16_C(6052), 0, CDISASM_X86_GROUP_VMX, 0);
                EXPECT(modrm == UINT8_C(0xc4));
                EXPECT(decoded_size == 3u);
            }
        }
        EXPECT(vmxoff_count == UINT64_C(1));
    }

    {
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
        uint64_t vmxoff_count = 0u;
        unsigned int payload;

        for (payload = UINT8_C(0x80); payload <= UINT8_MAX; ++payload) {
            unsigned int modrm;

            for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                uint8_t code[] = {
                    0xd5,(uint8_t)payload,0x01,(uint8_t)modrm
                };
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
                    CDISASM_MODE_64, code, sizeof(code), &flags,
                    &decoded_size);

                if (decoded_size != 0u
                    && instruction.name_id == CDISASM_X86_NAME_VMXOFF) {
                    ++vmxoff_count;
                    check_common("REX2 Group-7 VMXOFF allocation",
                        &instruction, decoded_size,
                        CDISASM_X86_NAME_VMXOFF, UINT16_C(6052), 0,
                        CDISASM_X86_GROUP_VMX, 1);
                    EXPECT(modrm == UINT8_C(0xc4));
                    EXPECT(decoded_size == sizeof(code));
                }
            }
        }
        EXPECT(vmxoff_count == UINT64_C(128));
    }
}

static void test_modes_prefixes_and_collisions(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    static const cdisasm_x86_reg_id default_arax[] = {
        CDISASM_X86_REG_AX, CDISASM_X86_REG_EAX, CDISASM_X86_REG_RAX
    };
    static const cdisasm_x86_reg_id override_arax[] = {
        CDISASM_X86_REG_EAX, CDISASM_X86_REG_AX, CDISASM_X86_REG_EAX
    };
    static const uint8_t ignored_prefixes[] = {0x66,0xf2,0xf3};
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
        uint8_t vmrun[] = {0x0f,0x01,0xd8};
        uint8_t vmrun_67[] = {0x67,0x0f,0x01,0xd8};
        uint8_t vmsave[] = {0x0f,0x01,0xdb};
        unsigned int prefix_index;
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            modes[mode_index], vmrun, sizeof(vmrun), &flags, &decoded_size);

        check_common("VMRUN mode", &instruction, decoded_size,
            CDISASM_X86_NAME_VMRUN, UINT16_C(6004), 1,
            CDISASM_X86_GROUP_SVM, 0);
        EXPECT(instruction.opcode[0].reg == default_arax[mode_index]);
        instruction = decode(CDISASM_CPU_X86, modes[mode_index],
            vmrun_67, sizeof(vmrun_67), &flags, &decoded_size);
        check_common("VMRUN address override", &instruction, decoded_size,
            CDISASM_X86_NAME_VMRUN, UINT16_C(6004), 1,
            CDISASM_X86_GROUP_SVM, 0);
        EXPECT(instruction.opcode[0].reg == override_arax[mode_index]);
        instruction = decode(CDISASM_CPU_X86, modes[mode_index],
            vmsave, sizeof(vmsave), &flags, &decoded_size);
        check_common("VMSAVE mode", &instruction, decoded_size,
            CDISASM_X86_NAME_VMSAVE, UINT16_C(6005), 0,
            CDISASM_X86_GROUP_SVM, 0);

        for (prefix_index = 0u; prefix_index < 3u; ++prefix_index) {
            uint8_t prefixed_vmrun[] = {
                ignored_prefixes[prefix_index],0x0f,0x01,0xd8
            };
            uint8_t prefixed_vmsave[] = {
                ignored_prefixes[prefix_index],0x0f,0x01,0xdb
            };

            instruction = decode(CDISASM_CPU_X86, modes[mode_index],
                prefixed_vmrun, sizeof(prefixed_vmrun), &flags,
                &decoded_size);
            check_common("prefixed VMRUN", &instruction, decoded_size,
                CDISASM_X86_NAME_VMRUN, UINT16_C(6004), 1,
                CDISASM_X86_GROUP_SVM, 0);
            EXPECT((instruction.opcode_flags
                & CDISASM_PREFIX_EFFECTIVE_MASK) == 0u);
            instruction = decode(CDISASM_CPU_X86, modes[mode_index],
                prefixed_vmsave, sizeof(prefixed_vmsave), &flags,
                &decoded_size);
            check_common("prefixed VMSAVE", &instruction, decoded_size,
                CDISASM_X86_NAME_VMSAVE, UINT16_C(6005), 0,
                CDISASM_X86_GROUP_SVM, 0);
            EXPECT((instruction.opcode_flags
                & CDISASM_PREFIX_EFFECTIVE_MASK) == 0u);
        }
    }

    {
        static const uint8_t vmclear[] = {0x66,0x0f,0xc7,0x30};
        static const uint8_t vmxon[] = {0xf3,0x0f,0xc7,0x30};
        static const uint8_t extrq[] = {0x66,0x0f,0x78,0xc1,0x08,0x04};
        static const uint8_t insertq[] = {0xf2,0x0f,0x78,0xc1,0x08,0x04};
        static const uint8_t insertq_66_f2[] = {
            0x66,0xf2,0x0f,0x78,0xc1,0x00,0x00
        };
        static const uint8_t insertq_f2_66[] = {
            0xf2,0x66,0x0f,0x78,0xc1,0x00,0x00
        };
        static const uint8_t rex2_extrq[] = {
            0x66,0xd5,0x81,0x78,0xc1,0x00,0x00
        };
        static const uint8_t rex2_insertq[] = {
            0xf2,0xd5,0x84,0x78,0xc1,0x00,0x00
        };
        static const uint8_t rex2_insertq_66_f2[] = {
            0x66,0xf2,0xd5,0xff,0x78,0xc1,0x00,0x00
        };
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            CDISASM_MODE_64, vmclear, sizeof(vmclear), &flags,
            &decoded_size);

        EXPECT(decoded_size == sizeof(vmclear));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VMCLEAR);
        EXPECT(!cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_VTX));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            vmxon, sizeof(vmxon), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(vmxon));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_VMXON);
        EXPECT(instruction.form_id == UINT16_C(6053));
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_VTX));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            extrq, sizeof(extrq), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(extrq));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_EXTRQ);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            insertq, sizeof(insertq), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(insertq));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_INSERTQ);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            insertq_66_f2, sizeof(insertq_66_f2), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(insertq_66_f2));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_INSERTQ);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            insertq_f2_66, sizeof(insertq_f2_66), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(insertq_f2_66));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_INSERTQ);

        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            rex2_extrq, sizeof(rex2_extrq), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(rex2_extrq));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_EXTRQ);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM9);
        EXPECT(cdisasm_instruction_has_x86_group(
            &instruction, CDISASM_X86_GROUP_APX_F));
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            rex2_insertq, sizeof(rex2_insertq), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(rex2_insertq));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_INSERTQ);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM8);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM1);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            rex2_insertq_66_f2, sizeof(rex2_insertq_66_f2), &flags,
            &decoded_size);
        EXPECT(decoded_size == sizeof(rex2_insertq_66_f2));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_INSERTQ);
        EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM8);
        EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM9);
    }
}

static void test_vmwrite_vmx_prefixes_and_collisions(void)
{
    static const cdisasm_x86_mode modes[] = {
        CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64
    };
    size_t mode_index;

    for (mode_index = 0u; mode_index < 3u; ++mode_index) {
        static const uint8_t vmwrite[] = {0x0f,0x79,0xc1};
        static const uint8_t vmxoff[] = {0x0f,0x01,0xc4};
        static const uint8_t vmxon[] = {0xf3,0x0f,0xc7,0x30};
        const int wide = modes[mode_index] == CDISASM_MODE_64;
        cdisasm_x86_decode_flags flags = all_flags(modes[mode_index]);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            modes[mode_index], vmwrite, sizeof(vmwrite), &flags,
            &decoded_size);

        check_common("VMWRITE mode", &instruction, decoded_size,
            CDISASM_X86_NAME_VMWRITE,
            wide ? UINT16_C(6050) : UINT16_C(6048), 2,
            CDISASM_X86_GROUP_VMX, 0);
        EXPECT(instruction.opcode[0].size == (wide ? 8u : 4u));
        EXPECT(instruction.opcode[1].size == (wide ? 8u : 4u));
        instruction = decode(CDISASM_CPU_X86, modes[mode_index],
            vmxoff, sizeof(vmxoff), &flags, &decoded_size);
        check_common("VMXOFF mode", &instruction, decoded_size,
            CDISASM_X86_NAME_VMXOFF, UINT16_C(6052), 0,
            CDISASM_X86_GROUP_VMX, 0);
        instruction = decode(CDISASM_CPU_X86, modes[mode_index],
            vmxon, sizeof(vmxon), &flags, &decoded_size);
        check_common("VMXON mode", &instruction, decoded_size,
            CDISASM_X86_NAME_VMXON, UINT16_C(6053), 1,
            CDISASM_X86_GROUP_VMX, 0);
        EXPECT(instruction.opcode[0].size == 8u);
        EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
    }

    {
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
        unsigned int rex;

        for (rex = UINT8_C(0x40); rex <= UINT8_C(0x4f); ++rex) {
            uint8_t vmwrite[] = {(uint8_t)rex,0x0f,0x79,0xc1};
            uint8_t vmxoff[] = {(uint8_t)rex,0x0f,0x01,0xc4};
            uint8_t vmxon[] = {0xf3,(uint8_t)rex,0x0f,0xc7,0x30};
            uint32_t decoded_size;
            cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
                CDISASM_MODE_64, vmwrite, sizeof(vmwrite), &flags,
                &decoded_size);

            check_common("REX VMWRITE sweep", &instruction, decoded_size,
                CDISASM_X86_NAME_VMWRITE, UINT16_C(6050), 2,
                CDISASM_X86_GROUP_VMX, 0);
            EXPECT(instruction.opcode[0].reg == (cdisasm_x86_reg_id)(
                CDISASM_X86_REG_RAX + ((rex & 4u) != 0u ? 8u : 0u)));
            EXPECT(instruction.opcode[1].reg == (cdisasm_x86_reg_id)(
                CDISASM_X86_REG_RCX + ((rex & 1u) != 0u ? 8u : 0u)));
            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                vmxoff, sizeof(vmxoff), &flags, &decoded_size);
            check_common("REX VMXOFF sweep", &instruction, decoded_size,
                CDISASM_X86_NAME_VMXOFF, UINT16_C(6052), 0,
                CDISASM_X86_GROUP_VMX, 0);
            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                vmxon, sizeof(vmxon), &flags, &decoded_size);
            check_common("REX VMXON sweep", &instruction, decoded_size,
                CDISASM_X86_NAME_VMXON, UINT16_C(6053), 1,
                CDISASM_X86_GROUP_VMX, 0);
            EXPECT(instruction.opcode[0].base_reg
                == (cdisasm_x86_reg_id)(CDISASM_X86_REG_RAX
                    + ((rex & 1u) != 0u ? 8u : 0u)));
        }
    }

    {
        static const uint8_t vmwrite_67[] = {0x67,0x0f,0x79,0x00};
        static const uint8_t vmwrite_fs[] = {0x64,0x0f,0x79,0x00};
        static const uint8_t vmxoff_67[] = {0x67,0x0f,0x01,0xc4};
        static const uint8_t vmxoff_cs[] = {0x2e,0x0f,0x01,0xc4};
        static const uint8_t vmxon_f3_66[] = {0xf3,0x66,0x0f,0xc7,0x30};
        static const uint8_t vmxon_66_f3[] = {0x66,0xf3,0x0f,0xc7,0x30};
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            CDISASM_MODE_64, vmwrite_67, sizeof(vmwrite_67), &flags,
            &decoded_size);

        check_common("address-size VMWRITE", &instruction, decoded_size,
            CDISASM_X86_NAME_VMWRITE, UINT16_C(6051), 2,
            CDISASM_X86_GROUP_VMX, 0);
        EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_EAX);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            vmwrite_fs, sizeof(vmwrite_fs), &flags, &decoded_size);
        check_common("segment VMWRITE", &instruction, decoded_size,
            CDISASM_X86_NAME_VMWRITE, UINT16_C(6051), 2,
            CDISASM_X86_GROUP_VMX, 0);
        EXPECT(instruction.opcode[1].segment_reg == CDISASM_X86_REG_FS);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            vmxoff_67, sizeof(vmxoff_67), &flags, &decoded_size);
        check_common("address-size VMXOFF", &instruction, decoded_size,
            CDISASM_X86_NAME_VMXOFF, UINT16_C(6052), 0,
            CDISASM_X86_GROUP_VMX, 0);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            vmxoff_cs, sizeof(vmxoff_cs), &flags, &decoded_size);
        check_common("segment VMXOFF", &instruction, decoded_size,
            CDISASM_X86_NAME_VMXOFF, UINT16_C(6052), 0,
            CDISASM_X86_GROUP_VMX, 0);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            vmxon_f3_66, sizeof(vmxon_f3_66), &flags, &decoded_size);
        check_common("VMXON ignores 66 after F3", &instruction, decoded_size,
            CDISASM_X86_NAME_VMXON, UINT16_C(6053), 1,
            CDISASM_X86_GROUP_VMX, 0);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            vmxon_66_f3, sizeof(vmxon_66_f3), &flags, &decoded_size);
        check_common("VMXON ignores 66 before F3", &instruction, decoded_size,
            CDISASM_X86_NAME_VMXON, UINT16_C(6053), 1,
            CDISASM_X86_GROUP_VMX, 0);
    }

    {
        static const uint8_t extrq[] = {0x66,0x0f,0x79,0xc1};
        static const uint8_t insertq[] = {0xf2,0x0f,0x79,0xc1};
        static const uint8_t insertq_66_f2[] = {
            0x66,0xf2,0x0f,0x79,0xc1
        };
        static const uint8_t insertq_f2_66[] = {
            0xf2,0x66,0x0f,0x79,0xc1
        };
        static const uint8_t rex2_extrq[] = {
            0x66,0xd5,0xff,0x79,0xc1
        };
        static const uint8_t rex2_insertq_66_f2[] = {
            0x66,0xf2,0xd5,0xff,0x79,0xc1
        };
        static const uint8_t rex2_insertq_f2_66[] = {
            0xf2,0x66,0xd5,0xff,0x79,0xc1
        };
        static const uint8_t vmwrite_f3[] = {0xf3,0x0f,0x79,0xc1};
        static const uint8_t vmxoff_bad[][4] = {
            {0x66,0x0f,0x01,0xc4}, {0xf2,0x0f,0x01,0xc4},
            {0xf3,0x0f,0x01,0xc4}
        };
        static const uint8_t senduipi[] = {0xf3,0x0f,0xc7,0xf0};
        static const uint8_t vmxon_last_f3[] = {
            0xf2,0xf3,0x0f,0xc7,0x30
        };
        static const uint8_t vmxon_last_f2[] = {
            0xf3,0xf2,0x0f,0xc7,0x30
        };
        cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
        const uint8_t *const collision_codes[] = {
            extrq, insertq, insertq_66_f2, insertq_f2_66,
            rex2_extrq, rex2_insertq_66_f2, rex2_insertq_f2_66
        };
        const size_t collision_sizes[] = {
            sizeof(extrq), sizeof(insertq), sizeof(insertq_66_f2),
            sizeof(insertq_f2_66), sizeof(rex2_extrq),
            sizeof(rex2_insertq_66_f2), sizeof(rex2_insertq_f2_66)
        };
        size_t index;
        uint32_t decoded_size;
        cdisasm_instruction instruction;

        for (index = 0u; index < 7u; ++index) {
            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                collision_codes[index], collision_sizes[index], &flags,
                &decoded_size);
            EXPECT(decoded_size == collision_sizes[index]);
            EXPECT(instruction.name_id == (index == 0u || index == 4u
                ? CDISASM_X86_NAME_EXTRQ : CDISASM_X86_NAME_INSERTQ));
            EXPECT(!cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_VTX));
        }
        expect_error("F3 VMWRITE reserved", CDISASM_CPU_X86,
            CDISASM_MODE_64, vmwrite_f3, sizeof(vmwrite_f3), &flags,
            CDISASM_STATUS_INVALID_INSTRUCTION);
        for (index = 0u; index < 3u; ++index) {
            expect_error("mandatory-prefix VMXOFF reserved",
                CDISASM_CPU_X86, CDISASM_MODE_64, vmxoff_bad[index],
                sizeof(vmxoff_bad[index]), &flags,
                CDISASM_STATUS_INVALID_INSTRUCTION);
        }
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            senduipi, sizeof(senduipi), &flags, &decoded_size);
        EXPECT(decoded_size == sizeof(senduipi));
        EXPECT(instruction.name_id == CDISASM_X86_NAME_SENDUIPI);
        instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
            vmxon_last_f3, sizeof(vmxon_last_f3), &flags, &decoded_size);
        check_common("last F3 selects VMXON", &instruction, decoded_size,
            CDISASM_X86_NAME_VMXON, UINT16_C(6053), 1,
            CDISASM_X86_GROUP_VMX, 0);
        expect_error("last F2 rejects VMXON", CDISASM_CPU_X86,
            CDISASM_MODE_64, vmxon_last_f2, sizeof(vmxon_last_f2), &flags,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
}

static void test_extrq_reserved_partition(void)
{
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    unsigned int modrm;

    for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
        uint8_t code[15] = {0x66,0x0f,0x78,(uint8_t)modrm};
        const int valid = modrm >= UINT8_C(0xc0)
            && modrm <= UINT8_C(0xc7);
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            CDISASM_MODE_64, code, sizeof(code), &flags, &decoded_size);

        if (valid) {
            EXPECT(decoded_size == 6u);
            EXPECT(instruction.name_id == CDISASM_X86_NAME_EXTRQ);
            EXPECT(instruction.operand_count == 3u);
            EXPECT(instruction.opcode[0].reg
                == (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0
                    + (modrm & 7u)));
        } else {
            EXPECT(decoded_size == 0u);
            EXPECT(is_error_only(
                &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
        }
    }

    {
        unsigned int payload;

        for (payload = UINT8_C(0x80); payload <= UINT8_MAX; ++payload) {
            for (modrm = 0u; modrm <= UINT8_MAX; ++modrm) {
                uint8_t code[15] = {
                    0x66,0xd5,(uint8_t)payload,0x78,(uint8_t)modrm
                };
                const int valid = modrm >= UINT8_C(0xc0)
                    && modrm <= UINT8_C(0xc7);
                uint32_t decoded_size;
                cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
                    CDISASM_MODE_64, code, sizeof(code), &flags,
                    &decoded_size);

                if (valid) {
                    const unsigned int xmm = (modrm & 7u)
                        + ((payload & 1u) != 0u ? 8u : 0u);

                    EXPECT(decoded_size == 7u);
                    EXPECT(instruction.name_id == CDISASM_X86_NAME_EXTRQ);
                    EXPECT(instruction.opcode[0].reg
                        == (cdisasm_x86_reg_id)(
                            CDISASM_X86_REG_XMM0 + xmm));
                    EXPECT(cdisasm_instruction_has_x86_group(
                        &instruction, CDISASM_X86_GROUP_APX_F));
                } else {
                    EXPECT(decoded_size == 0u);
                    EXPECT(is_error_only(
                        &instruction, CDISASM_STATUS_INVALID_INSTRUCTION));
                }
            }
        }
    }
}

static void test_reserved_profiles_and_runtime_gates(void)
{
    static const uint8_t vmptrld[] = {0x0f,0xc7,0x30};
    static const uint8_t vmptrst_bad[][4] = {
        {0x66,0x0f,0xc7,0x38}, {0xf2,0x0f,0xc7,0x38},
        {0xf3,0x0f,0xc7,0x38}
    };
    static const uint8_t vmread_f3[] = {0xf3,0x0f,0x78,0xc1};
    static const uint8_t vmwrite_f3[] = {0xf3,0x0f,0x79,0xc1};
    static const uint8_t vmresume_bad[][4] = {
        {0x66,0x0f,0x01,0xc3}, {0xf2,0x0f,0x01,0xc3},
        {0xf3,0x0f,0x01,0xc3}
    };
    static const uint8_t locked[][4] = {
        {0xf0,0x0f,0xc7,0x30}, {0xf0,0x0f,0xc7,0x38},
        {0xf0,0x0f,0x78,0xc1}, {0xf0,0x0f,0x01,0xc3},
        {0xf0,0x0f,0x79,0xc1}, {0xf0,0x0f,0x01,0xc4},
        {0xf0,0x0f,0x01,0xd8}, {0xf0,0x0f,0x01,0xdb}
    };
    static const uint8_t locked_vmxon[] = {0xf0,0xf3,0x0f,0xc7,0x30};
    static const uint8_t rex2_vmptrld[] = {0xd5,0x90,0xc7,0x30};
    static const uint8_t rex2_vmread[] = {0xd5,0x90,0x78,0xc1};
    static const uint8_t rex2_vmwrite[] = {0xd5,0x90,0x79,0xc1};
    static const uint8_t rex2_vmresume[] = {0xd5,0x80,0x01,0xc3};
    static const uint8_t rex2_vmxoff[] = {0xd5,0x80,0x01,0xc4};
    static const uint8_t rex2_vmxon[] = {0xf3,0xd5,0x90,0xc7,0x30};
    static const uint8_t rex2_vmrun[] = {0xd5,0x80,0x01,0xd8};
    cdisasm_x86_decode_flags all = all_flags(CDISASM_MODE_64);
    cdisasm_x86_decode_flags vmx = one_bit(CDISASM_X86_DECODE_BIT_VMX);
    cdisasm_x86_decode_flags vtx = one_bit(CDISASM_X86_DECODE_BIT_VTX);
    cdisasm_x86_decode_flags svm = one_bit(CDISASM_X86_DECODE_BIT_SVM);
    cdisasm_x86_decode_flags apx = one_bit(CDISASM_X86_DECODE_BIT_APX);
    cdisasm_x86_decode_flags vtx_apx = vtx;
    cdisasm_x86_decode_flags svm_apx = svm;
    size_t index;
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    EXPECT(cdisasm_decode_flags_set_bit(
        &vtx_apx, CDISASM_X86_DECODE_BIT_APX));
    EXPECT(cdisasm_decode_flags_set_bit(
        &svm_apx, CDISASM_X86_DECODE_BIT_APX));

    expect_error("F2 VMPTRLD", CDISASM_CPU_X86, CDISASM_MODE_64,
        (const uint8_t[]){0xf2,0x0f,0xc7,0x30}, 4u, &all,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    for (index = 0u; index < 3u; ++index) {
        expect_error("prefixed VMPTRST", CDISASM_CPU_X86,
            CDISASM_MODE_64, vmptrst_bad[index], sizeof(vmptrst_bad[index]),
            &all, CDISASM_STATUS_INVALID_INSTRUCTION);
        expect_error("prefixed VMRESUME", CDISASM_CPU_X86,
            CDISASM_MODE_64, vmresume_bad[index], sizeof(vmresume_bad[index]),
            &all, CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    expect_error("F3 VMREAD", CDISASM_CPU_X86, CDISASM_MODE_64,
        vmread_f3, sizeof(vmread_f3), &all,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("F3 VMWRITE", CDISASM_CPU_X86, CDISASM_MODE_64,
        vmwrite_f3, sizeof(vmwrite_f3), &all,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    for (index = 0u; index < sizeof(locked) / sizeof(locked[0]); ++index) {
        expect_error("LOCK virtualization", CDISASM_CPU_X86,
            CDISASM_MODE_64, locked[index], sizeof(locked[index]), &all,
            CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    expect_error("LOCK VMXON", CDISASM_CPU_X86, CDISASM_MODE_64,
        locked_vmxon, sizeof(locked_vmxon), &all,
        CDISASM_STATUS_INVALID_INSTRUCTION);

    {
        static const uint8_t vmwrite[] = {0x0f,0x79,0xc1};
        static const uint8_t vmxoff[] = {0x0f,0x01,0xc4};
        static const uint8_t vmxon[] = {0xf3,0x0f,0xc7,0x30};
        static const uint8_t *const exact_vtx_cases[] = {
            vmptrld, vmwrite, vmxoff, vmxon
        };
        static const size_t exact_vtx_sizes[] = {
            sizeof(vmptrld), sizeof(vmwrite), sizeof(vmxoff), sizeof(vmxon)
        };

        for (index = 0u; index < 4u; ++index) {
            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                exact_vtx_cases[index], exact_vtx_sizes[index], &vtx,
                &decoded_size);
            EXPECT(decoded_size == exact_vtx_sizes[index]);
            EXPECT(cdisasm_instruction_has_x86_group(
                &instruction, CDISASM_X86_GROUP_VTX));
            expect_error("VMX umbrella is not exact VTX",
                CDISASM_CPU_X86, CDISASM_MODE_64,
                exact_vtx_cases[index], exact_vtx_sizes[index], &vmx,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            expect_error("VMX runtime isolation", CDISASM_CPU_X86,
                CDISASM_MODE_64, exact_vtx_cases[index],
                exact_vtx_sizes[index], &svm,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            expect_error("VTX profile isolation", CDISASM_CPU_AMD_V,
                CDISASM_MODE_64, exact_vtx_cases[index],
                exact_vtx_sizes[index], &all,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            expect_error("VTX unavailable before VT-x",
                CDISASM_CPU_PRESCOTT, CDISASM_MODE_64,
                exact_vtx_cases[index], exact_vtx_sizes[index], &all,
                CDISASM_STATUS_INVALID_INSTRUCTION);
            instruction = decode(CDISASM_CPU_INTEL_VT_X,
                CDISASM_MODE_64, exact_vtx_cases[index],
                exact_vtx_sizes[index], &all, &decoded_size);
            EXPECT(decoded_size == exact_vtx_sizes[index]);
        }
    }
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2_vmptrld, sizeof(rex2_vmptrld), &vtx_apx, &decoded_size);
    EXPECT(decoded_size == sizeof(rex2_vmptrld));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F));
    expect_error("REX2 VMX is not selected by APX alone", CDISASM_CPU_X86,
        CDISASM_MODE_64, rex2_vmptrld, sizeof(rex2_vmptrld), &apx,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("REX2 VMX also requires APX", CDISASM_CPU_X86,
        CDISASM_MODE_64, rex2_vmptrld, sizeof(rex2_vmptrld), &vtx,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
        rex2_vmrun, sizeof(rex2_vmrun), &svm_apx, &decoded_size);
    EXPECT(decoded_size == sizeof(rex2_vmrun));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F));
    expect_error("REX2 SVM is not selected by APX alone", CDISASM_CPU_X86,
        CDISASM_MODE_64, rex2_vmrun, sizeof(rex2_vmrun), &apx,
        CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    {
        static const uint8_t *const rex2_vmx_cases[] = {
            rex2_vmptrld, rex2_vmread, rex2_vmwrite,
            rex2_vmresume, rex2_vmxoff, rex2_vmxon
        };
        static const size_t rex2_vmx_sizes[] = {
            sizeof(rex2_vmptrld), sizeof(rex2_vmread),
            sizeof(rex2_vmwrite), sizeof(rex2_vmresume),
            sizeof(rex2_vmxoff), sizeof(rex2_vmxon)
        };
        static const cdisasm_x86_cpu_id admitted[] = {
            CDISASM_CPU_X86, CDISASM_CPU_APX, CDISASM_CPU_DIAMOND_RAPIDS
        };
        size_t case_index;
        size_t cpu_index;

        for (case_index = 0u; case_index < 6u; ++case_index) {
            instruction = decode(CDISASM_CPU_X86, CDISASM_MODE_64,
                rex2_vmx_cases[case_index], rex2_vmx_sizes[case_index],
                &vtx_apx, &decoded_size);
            EXPECT(decoded_size == rex2_vmx_sizes[case_index]);
            expect_error("REX2 VTX runtime lacks APX", CDISASM_CPU_X86,
                CDISASM_MODE_64, rex2_vmx_cases[case_index],
                rex2_vmx_sizes[case_index], &vtx,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            expect_error("REX2 APX runtime lacks VTX", CDISASM_CPU_X86,
                CDISASM_MODE_64, rex2_vmx_cases[case_index],
                rex2_vmx_sizes[case_index], &apx,
                CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
            for (cpu_index = 0u;
                 cpu_index < sizeof(admitted) / sizeof(admitted[0]);
                 ++cpu_index) {
                cdisasm_x86_decode_flags available =
                    all_flags(CDISASM_MODE_64);

                if (admitted[cpu_index] != CDISASM_CPU_X86) {
                    EXPECT(cdisasm_x86_cpu_decode_flag_mask(
                        admitted[cpu_index], CDISASM_MODE_64, &available)
                        == CDISASM_STATUS_OK);
                }
                instruction = decode(admitted[cpu_index], CDISASM_MODE_64,
                    rex2_vmx_cases[case_index], rex2_vmx_sizes[case_index],
                    &available, &decoded_size);
                EXPECT(decoded_size == rex2_vmx_sizes[case_index]);
            }
            expect_error("REX2 VTX profile lacks APX",
                CDISASM_CPU_INTEL_VT_X, CDISASM_MODE_64,
                rex2_vmx_cases[case_index], rex2_vmx_sizes[case_index],
                &all, CDISASM_STATUS_INVALID_INSTRUCTION);
        }
    }
    expect_error("legacy VMX on AMD-V profile", CDISASM_CPU_AMD_V,
        CDISASM_MODE_64, vmptrld, sizeof(vmptrld), &all,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("REX2 VMX profile lacks APX", CDISASM_CPU_INTEL_VT_X,
        CDISASM_MODE_64, rex2_vmptrld, sizeof(rex2_vmptrld), &all,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("REX2 SVM profile lacks APX", CDISASM_CPU_AMD_ZEN_4,
        CDISASM_MODE_64, rex2_vmrun, sizeof(rex2_vmrun), &all,
        CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("REX2 SVM APX profile lacks SVM", CDISASM_CPU_APX,
        CDISASM_MODE_64, rex2_vmrun, sizeof(rex2_vmrun), &all,
        CDISASM_STATUS_INVALID_INSTRUCTION);
}

static void test_truncation(void)
{
    static const struct {
        uint8_t code[8];
        size_t size;
    } cases[] = {
        {{0x0f},1},
        {{0x0f,0xc7},2},
        {{0x0f,0xc7,0x34},3},
        {{0xf3,0x0f,0xc7},3},
        {{0xf3,0x0f,0xc7,0x34},4},
        {{0xf3,0x0f,0x78},3},
        {{0xf3,0x0f,0x78,0x04},4},
        {{0x0f,0x79},2},
        {{0x0f,0x79,0x04},3},
        {{0x0f,0x79,0x40},3},
        {{0x0f,0x79,0x80,0,0,0},6},
        {{0xf3,0x0f,0x79,0x04},4},
        {{0x66,0x0f,0x79,0x04},4},
        {{0xd5},1},
        {{0xd5,0x80},2},
        {{0xd5,0x80,0x78},3},
        {{0xd5,0x80,0x78,0x04},4},
        {{0xd5,0x80,0x79},3},
        {{0xd5,0x80,0x79,0x04},4},
        {{0xf3,0xd5,0x80,0x79,0x04},5},
        {{0xf3,0xd5,0x80,0xc7,0x34},5},
        {{0xd5,0x80,0x01},3}
    };
    cdisasm_x86_decode_flags flags = all_flags(CDISASM_MODE_64);
    cdisasm_x86_decode_flags none =
        CDISASM_X86_DECODE_FLAGS_NONE_INITIALIZER;
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        expect_error("virtualization truncation", CDISASM_CPU_X86,
            CDISASM_MODE_64, cases[index].code, cases[index].size,
            &flags, CDISASM_STATUS_TRUNCATED);
    }

    expect_error("truncation precedes VTX runtime rejection",
        CDISASM_CPU_X86, CDISASM_MODE_64,
        (const uint8_t[]){0x0f,0x79,0x04}, 3u,
        &none,
        CDISASM_STATUS_TRUNCATED);
    expect_error("truncation precedes VMX profile rejection",
        CDISASM_CPU_AMD_V, CDISASM_MODE_64,
        (const uint8_t[]){0xf3,0x0f,0xc7,0x34}, 4u, &flags,
        CDISASM_STATUS_TRUNCATED);
}

static void test_formatting(void)
{
#if USE_DISASM_FORMAT
    static const struct {
        uint8_t code[8];
        size_t size;
        cdisasm_x86_mode mode;
        cdisasm_x86_form_id form_id;
        const char *intel;
        const char *att;
    } cases[] = {
        {{0x0f,0xc7,0x30},3,CDISASM_MODE_64,UINT16_C(5997),
            "vmptrld qword ptr [rax]","vmptrld (%rax)"},
        {{0x0f,0xc7,0x38},3,CDISASM_MODE_64,UINT16_C(5998),
            "vmptrst qword ptr [rax]","vmptrst (%rax)"},
        {{0x0f,0x78,0xc1},3,CDISASM_MODE_64,UINT16_C(6000),
            "vmread rcx, rax","vmread %rax, %rcx"},
        {{0xd5,0xd0,0x78,0xc1},4,CDISASM_MODE_64,UINT16_C(6000),
            "vmread r17, r16","vmread %r16, %r17"},
        {{0x0f,0x79,0xc1},3,CDISASM_MODE_32,UINT16_C(6048),
            "vmwrite eax, ecx","vmwrite %ecx, %eax"},
        {{0x0f,0x79,0x48,0x7f},4,CDISASM_MODE_64,UINT16_C(6051),
            "vmwrite rcx, qword ptr [rax + 0x7f]",
            "vmwrite 0x7f(%rax), %rcx"},
        {{0x45,0x0f,0x79,0xc8},4,CDISASM_MODE_64,UINT16_C(6050),
            "vmwrite r9, r8","vmwrite %r8, %r9"},
        {{0xd5,0xff,0x79,0xc1},4,CDISASM_MODE_64,UINT16_C(6050),
            "vmwrite r24, r25","vmwrite %r25, %r24"},
        {{0xd5,0xb0,0x79,0x04,0xa0},5,CDISASM_MODE_64,UINT16_C(6051),
            "vmwrite rax, qword ptr [r16 + r20*4]",
            "vmwrite (%r16,%r20,4), %rax"},
        {{0x0f,0x01,0xc3},3,CDISASM_MODE_64,UINT16_C(6003),
            "vmresume","vmresume"},
        {{0x0f,0x01,0xc4},3,CDISASM_MODE_64,UINT16_C(6052),
            "vmxoff","vmxoff"},
        {{0xf3,0x0f,0xc7,0x30},4,CDISASM_MODE_64,UINT16_C(6053),
            "vmxon qword ptr [rax]","vmxon (%rax)"},
        {{0xf3,0xd5,0xb0,0xc7,0x34,0xa0},6,CDISASM_MODE_64,
            UINT16_C(6053),
            "vmxon qword ptr [r16 + r20*4]","vmxon (%r16,%r20,4)"},
        {{0x0f,0x01,0xd8},3,CDISASM_MODE_64,UINT16_C(6004),
            "vmrun rax","vmrun %rax"},
        {{0x0f,0x01,0xdb},3,CDISASM_MODE_64,UINT16_C(6005),
            "vmsave","vmsave"}
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cdisasm_x86_decode_flags flags = all_flags(cases[index].mode);
        uint32_t decoded_size;
        char output[160];
        char tiny[4] = {'x','x','x','x'};
        size_t required;
        cdisasm_instruction instruction = decode(CDISASM_CPU_X86,
            cases[index].mode, cases[index].code, cases[index].size,
            &flags, &decoded_size);

        EXPECT(decoded_size == cases[index].size);
        EXPECT(instruction.form_id == cases[index].form_id);
        required = cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL, NULL, 0u);
        EXPECT(required == strlen(cases[index].intel));
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_INTEL,
            output, sizeof(output)) == required);
        if (strcmp(output, cases[index].intel) != 0) {
            fprintf(stderr, "Intel format: got '%s', expected '%s'\n",
                output, cases[index].intel);
            EXPECT(0);
        }
        required = cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_ATT, NULL, 0u);
        EXPECT(required == strlen(cases[index].att));
        EXPECT(cdisasm_x86_format(&instruction, CDISASM_FORMAT_SYNTAX_ATT,
            output, sizeof(output)) == required);
        if (strcmp(output, cases[index].att) != 0) {
            fprintf(stderr, "AT&T format: got '%s', expected '%s'\n",
                output, cases[index].att);
            EXPECT(0);
        }
        EXPECT(cdisasm_x86_format(&instruction,
            CDISASM_FORMAT_SYNTAX_INTEL, tiny, sizeof(tiny))
            == strlen(cases[index].intel));
        EXPECT(tiny[sizeof(tiny) - 1u] == '\0');
    }
#endif
}

int main(void)
{
#define RUN_TEST(function)                                                   \
    do {                                                                     \
        int before = failures;                                               \
        function();                                                          \
        if (failures != before) {                                            \
            fprintf(stderr, #function ": %d new failure(s)\n",             \
                failures - before);                                          \
        }                                                                    \
    } while (0)

    RUN_TEST(test_exact_forms);
    RUN_TEST(test_vmread_allocations);
    RUN_TEST(test_vmwrite_allocations);
    RUN_TEST(test_pointer_and_fixed_rex2_allocations);
    RUN_TEST(test_vmxoff_allocation);
    RUN_TEST(test_modes_prefixes_and_collisions);
    RUN_TEST(test_vmwrite_vmx_prefixes_and_collisions);
    RUN_TEST(test_extrq_reserved_partition);
    RUN_TEST(test_reserved_profiles_and_runtime_gates);
    RUN_TEST(test_truncation);
    RUN_TEST(test_formatting);
#undef RUN_TEST

    if (failures != 0) {
        fprintf(stderr, "x86 virtualization-form tests: %d failure(s)\n",
            failures);
        return 1;
    }
    puts("x86 virtualization-form tests passed "
         "(15 forms; 1,536 legacy and 65,536 REX2 VMREAD/VMWRITE tuples; "
         "3,584 REX2 pointer/fixed tuples; 33,536 VMXOFF classifiers)");
    return 0;
}

#endif
