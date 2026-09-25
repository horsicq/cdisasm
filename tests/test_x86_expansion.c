#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_X86_NAME_VFMADD213PD == UINT16_C(743) &&
                   CDISASM_X86_NAME_VFNMSUB231SD == UINT16_C(796),
               "expanded FMA3 mnemonic IDs changed");
_Static_assert(CDISASM_X86_NAME_VAESENCLAST == UINT16_C(797) &&
                   CDISASM_X86_NAME_VAESKEYGENASSIST == UINT16_C(801) &&
                   CDISASM_X86_NAME_TDPFP16PS == UINT16_C(802) &&
                   CDISASM_X86_NAME_JMPABS == UINT16_C(803) &&
                   CDISASM_X86_NAME_VPSHAQ == UINT16_C(827) &&
                   CDISASM_X86_NAME_COUNT >= UINT16_C(828),
               "x86 expansion mnemonic tail changed");
_Static_assert(CDISASM_X86_GROUP_AMX_FP16 == UINT16_C(93),
               "AMX-FP16 group ID changed");

static int failures;

#define EXPECT(expression)                                                     \
  do {                                                                         \
    if (!(expression)) {                                                       \
      fprintf(stderr, "%s:%d: expectation failed: %s\n", __FILE__, __LINE__,   \
              #expression);                                                    \
      ++failures;                                                              \
    }                                                                          \
  } while (0)

static cdisasm_instruction decode_mode(cdisasm_cpu_id cpu, cdisasm_mode mode,
                                       const uint8_t *bytes, size_t size,
                                       cdisasm_x86_decode_option flags,
                                       uint32_t *decoded_size) {
  cdisasm_instruction instruction;

  memset(&instruction, UINT8_C(0xa5), sizeof(instruction));
  *decoded_size = cdisasm_x86_decode(cpu, mode, bytes, size, UINT64_C(0x1000),
                                     flags, &instruction);
  return instruction;
}

#if USE_EXTRA_OPCODES
static cdisasm_instruction decode64(cdisasm_cpu_id cpu, const uint8_t *bytes,
                                    size_t size,
                                    cdisasm_x86_decode_option flags,
                                    uint32_t *decoded_size) {
  return decode_mode(cpu, CDISASM_MODE_64, bytes, size, flags, decoded_size);
}

static cdisasm_instruction decode64_with_exact_bit(
    cdisasm_cpu_id cpu, const uint8_t *bytes, size_t size,
    cdisasm_x86_decode_option word0, cdisasm_x86_decode_bit_id bit_id,
    uint32_t *decoded_size) {
  cdisasm_x86_decode_flags flags =
      CDISASM_X86_DECODE_FLAGS_INITIALIZER(word0);
  cdisasm_instruction instruction;

  EXPECT(cdisasm_decode_flags_set_bit(&flags, bit_id));
  memset(&instruction, UINT8_C(0xa5), sizeof(instruction));
  *decoded_size = cdisasm_test_x86_decode_exact_flags(
      cpu, CDISASM_MODE_64, bytes, size, UINT64_C(0x1000), &flags,
      &instruction);
  return instruction;
}
#endif

static int is_error_only(const cdisasm_instruction *instruction,
                         cdisasm_status status) {
  cdisasm_instruction expected;

  memset(&expected, 0, sizeof(expected));
  expected.last_error_id = (uint8_t)status;
  return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static void expect_error_mode(cdisasm_cpu_id cpu, cdisasm_mode mode,
                              const uint8_t *bytes, size_t size,
                              cdisasm_x86_decode_option flags,
                              cdisasm_status status) {
  uint32_t decoded_size;
  cdisasm_instruction instruction =
      decode_mode(cpu, mode, bytes, size, flags, &decoded_size);

  if (decoded_size != 0 || !is_error_only(&instruction, status)) {
    fprintf(stderr,
            "unexpected status: cpu=0x%08x mode=%u bytes=%02x%02x%02x%02x "
            "size=%u expected=%u actual=%u decoded=%u\n",
            (unsigned int)cpu, (unsigned int)mode,
            size > 0 ? (unsigned int)bytes[0] : 0u,
            size > 1 ? (unsigned int)bytes[1] : 0u,
            size > 2 ? (unsigned int)bytes[2] : 0u,
            size > 3 ? (unsigned int)bytes[3] : 0u, (unsigned int)size,
            (unsigned int)status, (unsigned int)instruction.last_error_id,
            (unsigned int)decoded_size);
  }
  EXPECT(decoded_size == 0);
  EXPECT(is_error_only(&instruction, status));
}

static void expect_error(cdisasm_cpu_id cpu, const uint8_t *bytes, size_t size,
                         cdisasm_x86_decode_option flags,
                         cdisasm_status status) {
  expect_error_mode(cpu, CDISASM_MODE_64, bytes, size, flags, status);
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(const cdisasm_instruction *instruction,
                          uint32_t syntax, const char *expected) {
  char text[192];
  size_t length = cdisasm_x86_format(instruction, syntax, text, sizeof(text));

  EXPECT(length == strlen(expected));
  EXPECT(strcmp(text, expected) == 0);
}
#endif

typedef struct fma3_opcode_case {
  uint8_t opcode;
  uint8_t scalar;
  cdisasm_x86_name_id w0_name;
  cdisasm_x86_name_id w1_name;
} fma3_opcode_case;

static const fma3_opcode_case fma3_cases[] = {
    {0x96, 0, CDISASM_X86_NAME_VFMADDSUB132PS, CDISASM_X86_NAME_VFMADDSUB132PD},
    {0x97, 0, CDISASM_X86_NAME_VFMSUBADD132PS, CDISASM_X86_NAME_VFMSUBADD132PD},
    {0x98, 0, CDISASM_X86_NAME_VFMADD132PS, CDISASM_X86_NAME_VFMADD132PD},
    {0x99, 1, CDISASM_X86_NAME_VFMADD132SS, CDISASM_X86_NAME_VFMADD132SD},
    {0x9a, 0, CDISASM_X86_NAME_VFMSUB132PS, CDISASM_X86_NAME_VFMSUB132PD},
    {0x9b, 1, CDISASM_X86_NAME_VFMSUB132SS, CDISASM_X86_NAME_VFMSUB132SD},
    {0x9c, 0, CDISASM_X86_NAME_VFNMADD132PS, CDISASM_X86_NAME_VFNMADD132PD},
    {0x9d, 1, CDISASM_X86_NAME_VFNMADD132SS, CDISASM_X86_NAME_VFNMADD132SD},
    {0x9e, 0, CDISASM_X86_NAME_VFNMSUB132PS, CDISASM_X86_NAME_VFNMSUB132PD},
    {0x9f, 1, CDISASM_X86_NAME_VFNMSUB132SS, CDISASM_X86_NAME_VFNMSUB132SD},
    {0xa6, 0, CDISASM_X86_NAME_VFMADDSUB213PS, CDISASM_X86_NAME_VFMADDSUB213PD},
    {0xa7, 0, CDISASM_X86_NAME_VFMSUBADD213PS, CDISASM_X86_NAME_VFMSUBADD213PD},
    {0xa8, 0, CDISASM_X86_NAME_VFMADD213PS, CDISASM_X86_NAME_VFMADD213PD},
    {0xa9, 1, CDISASM_X86_NAME_VFMADD213SS, CDISASM_X86_NAME_VFMADD213SD},
    {0xaa, 0, CDISASM_X86_NAME_VFMSUB213PS, CDISASM_X86_NAME_VFMSUB213PD},
    {0xab, 1, CDISASM_X86_NAME_VFMSUB213SS, CDISASM_X86_NAME_VFMSUB213SD},
    {0xac, 0, CDISASM_X86_NAME_VFNMADD213PS, CDISASM_X86_NAME_VFNMADD213PD},
    {0xad, 1, CDISASM_X86_NAME_VFNMADD213SS, CDISASM_X86_NAME_VFNMADD213SD},
    {0xae, 0, CDISASM_X86_NAME_VFNMSUB213PS, CDISASM_X86_NAME_VFNMSUB213PD},
    {0xaf, 1, CDISASM_X86_NAME_VFNMSUB213SS, CDISASM_X86_NAME_VFNMSUB213SD},
    {0xb6, 0, CDISASM_X86_NAME_VFMADDSUB231PS, CDISASM_X86_NAME_VFMADDSUB231PD},
    {0xb7, 0, CDISASM_X86_NAME_VFMSUBADD231PS, CDISASM_X86_NAME_VFMSUBADD231PD},
    {0xb8, 0, CDISASM_X86_NAME_VFMADD231PS, CDISASM_X86_NAME_VFMADD231PD},
    {0xb9, 1, CDISASM_X86_NAME_VFMADD231SS, CDISASM_X86_NAME_VFMADD231SD},
    {0xba, 0, CDISASM_X86_NAME_VFMSUB231PS, CDISASM_X86_NAME_VFMSUB231PD},
    {0xbb, 1, CDISASM_X86_NAME_VFMSUB231SS, CDISASM_X86_NAME_VFMSUB231SD},
    {0xbc, 0, CDISASM_X86_NAME_VFNMADD231PS, CDISASM_X86_NAME_VFNMADD231PD},
    {0xbd, 1, CDISASM_X86_NAME_VFNMADD231SS, CDISASM_X86_NAME_VFNMADD231SD},
    {0xbe, 0, CDISASM_X86_NAME_VFNMSUB231PS, CDISASM_X86_NAME_VFNMSUB231PD},
    {0xbf, 1, CDISASM_X86_NAME_VFNMSUB231SS, CDISASM_X86_NAME_VFNMSUB231SD}};

static void test_fma3_matrix(void) {
  size_t case_index;

  EXPECT(sizeof(fma3_cases) / sizeof(fma3_cases[0]) == 30u);
  for (case_index = 0; case_index < sizeof(fma3_cases) / sizeof(fma3_cases[0]);
       ++case_index) {
    unsigned int w;

    for (w = 0; w != 2; ++w) {
      unsigned int l;

      for (l = 0; l != 2; ++l) {
        uint8_t code[5] = {0xc4, 0xe2, (uint8_t)(0x69u | (w << 7) | (l << 2)),
                           fma3_cases[case_index].opcode, 0xcb};
#if USE_EXTRA_OPCODES
        const unsigned int ymm = l != 0 && fma3_cases[case_index].scalar == 0;
        const cdisasm_x86_reg_id register_base =
            ymm ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
        const unsigned int register_size = ymm ? 32u : 16u;
        const cdisasm_x86_name_id expected_name =
            w != 0 ? fma3_cases[case_index].w1_name
                   : fma3_cases[case_index].w0_name;
        uint32_t decoded_size;
        cdisasm_instruction instruction =
            decode64(CDISASM_CPU_HASWELL, code, sizeof(code),
                     CDISASM_X86_DECODE_FLAG_FMA3, &decoded_size);

        EXPECT(decoded_size == sizeof(code));
        EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
        EXPECT(instruction.name_id == expected_name);
        EXPECT((instruction.opcode_flags & CDISASM_PREFIX_VEX) != 0);
        EXPECT(cdisasm_instruction_has_x86_group(&instruction,
                                                 CDISASM_X86_GROUP_FMA3));
        EXPECT(instruction.operand_count == 3);
        EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_REGISTER);
        EXPECT(instruction.opcode[0].reg == register_base + 1u);
        EXPECT(instruction.opcode[1].reg == register_base + 2u);
        EXPECT(instruction.opcode[2].reg == register_base + 3u);
        EXPECT(instruction.opcode[0].size == register_size);
        EXPECT(instruction.opcode[1].size == register_size);
        EXPECT(instruction.opcode[2].size == register_size);
        EXPECT(instruction.opcode[0].access ==
               CDISASM_OPERAND_ACCESS_READ_WRITE);
        EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction.opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
        EXPECT(instruction.encoding.prefix_size == 3);
        EXPECT(instruction.encoding.opcode_offset == 3);
        EXPECT(instruction.encoding.opcode_size == 1);
        EXPECT(instruction.encoding.modrm_offset == 4);
        EXPECT(instruction.encoding.modrm == UINT8_C(0xcb));
#else
        expect_error(CDISASM_CPU_X86, code, sizeof(code),
                     CDISASM_X86_DECODE_FLAG_BASE,
                     CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
      }

      {
        uint8_t truncated[4] = {0xc4, 0xe2, (uint8_t)(0x69u | (w << 7)),
                                fma3_cases[case_index].opcode};

        expect_error(CDISASM_CPU_X86, truncated, sizeof(truncated),
                     CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
      }
    }
  }
}

static void test_fma3_policy_memory_and_format(void) {
  static const uint8_t packed[] = {0xc4, 0xe2, 0xd5, 0xac, 0xe6};
  static const uint8_t scalar32_memory[] = {0xc4, 0xe2, 0x69, 0x9b, 0x08};
  static const uint8_t scalar64_memory[] = {0xc4, 0xe2, 0xe9, 0x9b, 0x08};
  static const uint8_t packed_memory[] = {0xc4, 0xe2, 0x6d, 0x9a, 0x08};
  static const uint8_t formatted[] = {0xc4, 0xe2, 0xe9, 0xbf, 0xcb};
  static const uint8_t locked[] = {0xf0, 0xc4, 0xe2, 0x69, 0x9a, 0xcb};

  (void)formatted;
  expect_error(CDISASM_CPU_X86, locked, sizeof(locked),
               CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_INVALID_INSTRUCTION);

#if USE_EXTRA_OPCODES
  {
    uint32_t decoded_size;
    cdisasm_instruction instruction =
        decode64(CDISASM_CPU_HASWELL, packed, sizeof(packed),
                 CDISASM_X86_DECODE_FLAG_FMA3, &decoded_size);

    EXPECT(decoded_size == sizeof(packed));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VFNMADD213PD);
    expect_error(CDISASM_CPU_IVY_BRIDGE, packed, sizeof(packed),
                 CDISASM_X86_DECODE_FLAG_FMA3,
                 CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_AMD_BULLDOZER, packed, sizeof(packed),
                 CDISASM_X86_DECODE_FLAG_FMA3,
                 CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, packed, sizeof(packed),
                 CDISASM_X86_DECODE_FLAG_AVX,
                 CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    instruction =
        decode64(CDISASM_CPU_HASWELL, scalar32_memory, sizeof(scalar32_memory),
                 CDISASM_X86_DECODE_FLAG_FMA3, &decoded_size);
    EXPECT(decoded_size == sizeof(scalar32_memory));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VFMSUB132SS);
    EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.opcode[2].size == 4);

    instruction =
        decode64(CDISASM_CPU_HASWELL, scalar64_memory, sizeof(scalar64_memory),
                 CDISASM_X86_DECODE_FLAG_FMA3, &decoded_size);
    EXPECT(decoded_size == sizeof(scalar64_memory));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VFMSUB132SD);
    EXPECT(instruction.opcode[2].size == 8);

    instruction =
        decode64(CDISASM_CPU_HASWELL, packed_memory, sizeof(packed_memory),
                 CDISASM_X86_DECODE_FLAG_FMA3, &decoded_size);
    EXPECT(decoded_size == sizeof(packed_memory));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VFMSUB132PS);
    EXPECT(instruction.opcode[2].size == 32);

#if USE_DISASM_FORMAT
    instruction = decode64(CDISASM_CPU_HASWELL, formatted, sizeof(formatted),
                           CDISASM_X86_DECODE_FLAG_FMA3, &decoded_size);
    EXPECT(decoded_size == sizeof(formatted));
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
                  "vfnmsub231sd xmm1, xmm2, xmm3");
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
                  "vfnmsub231sd %xmm3, %xmm2, %xmm1");
#endif
  }
#else
  (void)scalar32_memory;
  (void)scalar64_memory;
  (void)packed_memory;
  (void)formatted;
  expect_error(CDISASM_CPU_X86, packed, sizeof(packed),
               CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

typedef struct vaes_round_case {
  uint8_t opcode;
  cdisasm_x86_name_id name_id;
} vaes_round_case;

static const vaes_round_case vaes_rounds[] = {
    {0xdc, CDISASM_X86_NAME_VAESENC},
    {0xdd, CDISASM_X86_NAME_VAESENCLAST},
    {0xde, CDISASM_X86_NAME_VAESDEC},
    {0xdf, CDISASM_X86_NAME_VAESDECLAST}};

static void test_vaes_vex(void) {
  static const uint8_t vaesenc_xmm[] = {0xc4, 0xe2, 0x69, 0xdc, 0xcb};
  static const uint8_t vaesenc_ymm[] = {0xc4, 0xe2, 0x6d, 0xdc, 0xcb};
  static const uint8_t vaesimc[] = {0xc4, 0xe2, 0x79, 0xdb, 0xcb};
  static const uint8_t vaeskeygen[] = {0xc4, 0xe3, 0x79, 0xdf, 0xcb, 0x1b};
  static const uint8_t vaesimc_memory[] =
      {0xc4, 0xe2, 0x79, 0xdb, 0x48, 0x10};
  static const uint8_t vaeskeygen_memory[] =
      {0xc4, 0xe3, 0x79, 0xdf, 0x53, 0x20, 0x1b};
  static const uint8_t bad_imc_vvvv[] = {0xc4, 0xe2, 0x69, 0xdb, 0xcb};
  static const uint8_t bad_imc_l[] = {0xc4, 0xe2, 0x7d, 0xdb, 0xcb};
  static const uint8_t bad_key_vvvv[] = {0xc4, 0xe3, 0x69, 0xdf, 0xcb, 0x1b};
  static const uint8_t truncated_key[] = {0xc4, 0xe3, 0x79, 0xdf, 0xcb};
  size_t index;

#if !USE_EXTRA_OPCODES
  (void)vaesimc_memory;
  (void)vaeskeygen_memory;
#endif

  for (index = 0; index < sizeof(vaes_rounds) / sizeof(vaes_rounds[0]);
       ++index) {
    unsigned int l;

    for (l = 0; l != 2; ++l) {
      uint8_t code[5] = {0xc4, 0xe2, (uint8_t)(0x69u | (l << 2)),
                         vaes_rounds[index].opcode, 0xcb};
#if USE_EXTRA_OPCODES
      const cdisasm_x86_reg_id register_base =
          l != 0 ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_XMM0;
      const cdisasm_cpu_id supporting_cpu =
          l != 0 ? CDISASM_CPU_ICE_LAKE : CDISASM_CPU_SANDY_BRIDGE;
      const cdisasm_x86_group_id feature_group =
          l != 0 ? CDISASM_X86_GROUP_VAES : CDISASM_X86_GROUP_AESNI;
      uint32_t decoded_size;
      cdisasm_instruction instruction =
          decode64(supporting_cpu, code, sizeof(code),
                   CDISASM_X86_DECODE_FLAG_AES, &decoded_size);

      EXPECT(decoded_size == sizeof(code));
      EXPECT(instruction.name_id == vaes_rounds[index].name_id);
      EXPECT(instruction.operand_count == 3);
      EXPECT(instruction.opcode[0].reg == register_base + 1u);
      EXPECT(instruction.opcode[1].reg == register_base + 2u);
      EXPECT(instruction.opcode[2].reg == register_base + 3u);
      EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
      EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
      EXPECT(instruction.opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
      EXPECT(cdisasm_instruction_has_x86_group(&instruction, feature_group));
#else
      expect_error(CDISASM_CPU_X86, code, sizeof(code),
                   CDISASM_X86_DECODE_FLAG_BASE,
                   CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
  }

  expect_error(CDISASM_CPU_X86, bad_imc_vvvv, sizeof(bad_imc_vvvv),
               CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_INVALID_INSTRUCTION);
  expect_error(CDISASM_CPU_X86, bad_imc_l, sizeof(bad_imc_l),
               CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_INVALID_INSTRUCTION);
  expect_error(CDISASM_CPU_X86, bad_key_vvvv, sizeof(bad_key_vvvv),
               CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_INVALID_INSTRUCTION);
  expect_error(CDISASM_CPU_X86, truncated_key, sizeof(truncated_key),
               CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);

#if USE_EXTRA_OPCODES
  {
    uint32_t decoded_size;
    cdisasm_instruction instruction =
        decode64(CDISASM_CPU_SANDY_BRIDGE, vaesimc, sizeof(vaesimc),
                 CDISASM_X86_DECODE_FLAG_AES, &decoded_size);

    EXPECT(decoded_size == sizeof(vaesimc));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VAESIMC);
    EXPECT(instruction.operand_count == 2);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM1);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM3);
    EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(cdisasm_instruction_has_x86_group(&instruction,
                                             CDISASM_X86_GROUP_AESNI));

    instruction =
        decode64(CDISASM_CPU_SANDY_BRIDGE, vaeskeygen, sizeof(vaeskeygen),
                 CDISASM_X86_DECODE_FLAG_AES, &decoded_size);
    EXPECT(decoded_size == sizeof(vaeskeygen));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VAESKEYGENASSIST);
    EXPECT(instruction.operand_count == 3);
    EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction.opcode[2].size == 1);
    EXPECT(instruction.opcode[2].imm == UINT64_C(0x1b));
    EXPECT(cdisasm_instruction_has_x86_group(&instruction,
                                             CDISASM_X86_GROUP_AESNI));

    instruction = decode64(CDISASM_CPU_SANDY_BRIDGE, vaesimc_memory,
                           sizeof(vaesimc_memory),
                           CDISASM_X86_DECODE_FLAG_AES, &decoded_size);
    EXPECT(decoded_size == sizeof(vaesimc_memory));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VAESIMC);
    EXPECT(instruction.operand_count == 2);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM1);
    EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_RAX);
    EXPECT(instruction.opcode[1].size == 16);
    EXPECT(instruction.opcode[1].imm == UINT64_C(0x10));
    EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(cdisasm_instruction_has_x86_group(&instruction,
                                             CDISASM_X86_GROUP_AESNI));

    instruction = decode64(CDISASM_CPU_SANDY_BRIDGE, vaeskeygen_memory,
                           sizeof(vaeskeygen_memory),
                           CDISASM_X86_DECODE_FLAG_AES, &decoded_size);
    EXPECT(decoded_size == sizeof(vaeskeygen_memory));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VAESKEYGENASSIST);
    EXPECT(instruction.operand_count == 3);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM2);
    EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.opcode[1].type == CDISASM_OPERAND_MEMORY);
    EXPECT(instruction.opcode[1].base_reg == CDISASM_X86_REG_RBX);
    EXPECT(instruction.opcode[1].size == 16);
    EXPECT(instruction.opcode[1].imm == UINT64_C(0x20));
    EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction.opcode[2].size == 1);
    EXPECT(instruction.opcode[2].imm == UINT64_C(0x1b));
    EXPECT(cdisasm_instruction_has_x86_group(&instruction,
                                             CDISASM_X86_GROUP_AESNI));

    expect_error(CDISASM_CPU_WESTMERE, vaesimc, sizeof(vaesimc),
                 CDISASM_X86_DECODE_FLAG_AES,
                 CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_WESTMERE, vaesenc_xmm, sizeof(vaesenc_xmm),
                 CDISASM_X86_DECODE_FLAG_AES,
                 CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_SKYLAKE, vaesenc_ymm, sizeof(vaesenc_ymm),
                 CDISASM_X86_DECODE_FLAG_AES,
                 CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, vaesimc, sizeof(vaesimc),
                 CDISASM_X86_DECODE_FLAG_PCLMUL,
                 CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

#if USE_DISASM_FORMAT
    instruction =
        decode64(CDISASM_CPU_SANDY_BRIDGE, vaeskeygen, sizeof(vaeskeygen),
                 CDISASM_X86_DECODE_FLAG_AES, &decoded_size);
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
                  "vaeskeygenassist xmm1, xmm3, 0x1b");
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
                  "vaeskeygenassist $0x1b, %xmm3, %xmm1");

    {
      static const uint8_t declast[] = {0xc4, 0xe2, 0x6d, 0xdf, 0xcb};

      instruction = decode64(CDISASM_CPU_ICE_LAKE, declast, sizeof(declast),
                             CDISASM_X86_DECODE_FLAG_AES, &decoded_size);
      expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
                    "vaesdeclast ymm1, ymm2, ymm3");
      expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
                    "vaesdeclast %ymm3, %ymm2, %ymm1");
    }
#endif
  }
#else
  (void)vaesenc_xmm;
  (void)vaesenc_ymm;
  expect_error(CDISASM_CPU_X86, vaesimc, sizeof(vaesimc),
               CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
  expect_error(CDISASM_CPU_X86, vaeskeygen, sizeof(vaeskeygen),
               CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_evex_crypto(void) {
  static const uint8_t vpclmul[] = {0x62, 0xf3, 0x6d, 0x48, 0x44, 0xcb, 0x11};
  static const uint8_t bad_mask[] = {0x62, 0xf2, 0x6d, 0x49, 0xdc, 0xcb};
  static const uint8_t bad_b[] = {0x62, 0xf2, 0x6d, 0x58, 0xdc, 0xcb};
  static const uint8_t bad_ll[] = {0x62, 0xf2, 0x6d, 0x68, 0xdc, 0xcb};
  static const uint8_t truncated_vaes[] = {0x62, 0xf2, 0x6d, 0x48, 0xde};
  static const uint8_t truncated_clmul[] = {0x62, 0xf3, 0x6d, 0x48, 0x44, 0xcb};
  size_t index;

  expect_error(CDISASM_CPU_X86, bad_mask, sizeof(bad_mask),
               CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_INVALID_INSTRUCTION);
  expect_error(CDISASM_CPU_X86, bad_b, sizeof(bad_b),
               CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_INVALID_INSTRUCTION);
  expect_error(CDISASM_CPU_X86, bad_ll, sizeof(bad_ll),
               CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_INVALID_INSTRUCTION);
  expect_error(CDISASM_CPU_X86, truncated_vaes, sizeof(truncated_vaes),
               CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
  expect_error(CDISASM_CPU_X86, truncated_clmul, sizeof(truncated_clmul),
               CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);

  for (index = 0; index < sizeof(vaes_rounds) / sizeof(vaes_rounds[0]);
       ++index) {
    unsigned int ll;

    for (ll = 0; ll != 3; ++ll) {
      uint8_t code[6] = {0x62,
                         0xf2,
                         0x6d,
                         (uint8_t)(0x08u | (ll << 5)),
                         vaes_rounds[index].opcode,
                         0xcb};
#if USE_EXTRA_OPCODES
      const cdisasm_x86_reg_id register_base =
          ll == 0 ? CDISASM_X86_REG_XMM0
                  : (ll == 1 ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_ZMM0);
      const unsigned int register_size = 16u << ll;
      uint32_t decoded_size;
      cdisasm_instruction instruction =
          decode64(CDISASM_CPU_ICE_LAKE, code, sizeof(code),
                   CDISASM_X86_DECODE_FLAG_AES, &decoded_size);

      EXPECT(decoded_size == sizeof(code));
      EXPECT(instruction.name_id == vaes_rounds[index].name_id);
      EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EVEX) != 0);
      EXPECT(instruction.mask_mode == CDISASM_X86_MASK_NONE);
      EXPECT(instruction.mask_reg == CDISASM_X86_REG_NONE);
      EXPECT(instruction.operand_count == 3);
      EXPECT(instruction.opcode[0].reg == register_base + 1u);
      EXPECT(instruction.opcode[1].reg == register_base + 2u);
      EXPECT(instruction.opcode[2].reg == register_base + 3u);
      EXPECT(instruction.opcode[0].size == register_size);
      EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
      EXPECT(cdisasm_instruction_has_x86_group(&instruction,
                                               CDISASM_X86_GROUP_VAES));
      EXPECT(cdisasm_instruction_has_x86_group(&instruction,
                                               CDISASM_X86_GROUP_AVX512F));
      if (ll != 2) {
        EXPECT(cdisasm_instruction_has_x86_group(&instruction,
                                                 CDISASM_X86_GROUP_AVX512VL));
      }
#else
      expect_error(CDISASM_CPU_X86, code, sizeof(code),
                   CDISASM_X86_DECODE_FLAG_BASE,
                   CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }
  }

#if USE_EXTRA_OPCODES
  {
    uint32_t decoded_size;
    cdisasm_instruction instruction;
    unsigned int ll;

    for (ll = 0; ll != 3; ++ll) {
      uint8_t code[7] = {0x62, 0xf3, 0x6d, (uint8_t)(0x08u | (ll << 5)),
                         0x44, 0xcb, 0x11};
      const cdisasm_x86_reg_id register_base =
          ll == 0 ? CDISASM_X86_REG_XMM0
                  : (ll == 1 ? CDISASM_X86_REG_YMM0 : CDISASM_X86_REG_ZMM0);

      instruction = decode64(CDISASM_CPU_ICE_LAKE, code, sizeof(code),
                             CDISASM_X86_DECODE_FLAG_PCLMUL, &decoded_size);
      EXPECT(decoded_size == sizeof(code));
      EXPECT(instruction.name_id == CDISASM_X86_NAME_VPCLMULQDQ);
      EXPECT(instruction.operand_count == 4);
      EXPECT(instruction.opcode[0].reg == register_base + 1u);
      EXPECT(instruction.opcode[1].reg == register_base + 2u);
      EXPECT(instruction.opcode[2].reg == register_base + 3u);
      EXPECT(instruction.opcode[3].type == CDISASM_OPERAND_IMMEDIATE);
      EXPECT(instruction.opcode[3].imm == UINT64_C(0x11));
      EXPECT(cdisasm_instruction_has_x86_group(&instruction,
                                               CDISASM_X86_GROUP_VPCLMULQDQ));
      EXPECT(cdisasm_instruction_has_x86_group(&instruction,
                                               CDISASM_X86_GROUP_AVX512F));
      if (ll != 2) {
        EXPECT(cdisasm_instruction_has_x86_group(&instruction,
                                                 CDISASM_X86_GROUP_AVX512VL));
      }
    }

    {
      static const uint8_t avx10_vaes_ymm[] = {0x62, 0xf2, 0x6d,
                                               0x28, 0xdc, 0xcb};

      instruction =
          decode64(CDISASM_CPU_AVX10, avx10_vaes_ymm, sizeof(avx10_vaes_ymm),
                   CDISASM_X86_DECODE_FLAG_AVX10, &decoded_size);
      EXPECT(decoded_size == sizeof(avx10_vaes_ymm));
      EXPECT(instruction.name_id == CDISASM_X86_NAME_VAESENC);
      EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_YMM1);
      EXPECT(cdisasm_instruction_has_x86_group(&instruction,
                                               CDISASM_X86_GROUP_VAES));
      EXPECT(cdisasm_instruction_has_x86_group(&instruction,
                                               CDISASM_X86_GROUP_AVX10_1));
      EXPECT(!cdisasm_instruction_has_x86_group(
          &instruction, CDISASM_X86_GROUP_AVX512F));
      EXPECT(!cdisasm_instruction_has_x86_group(
          &instruction, CDISASM_X86_GROUP_AVX512VL));
    }

    instruction = decode64(CDISASM_CPU_AVX10, vpclmul, sizeof(vpclmul),
                           CDISASM_X86_DECODE_FLAG_AVX10, &decoded_size);
    EXPECT(decoded_size == sizeof(vpclmul));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPCLMULQDQ);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_ZMM1);
    EXPECT(cdisasm_instruction_has_x86_group(&instruction,
                                             CDISASM_X86_GROUP_VPCLMULQDQ));
    EXPECT(cdisasm_instruction_has_x86_group(&instruction,
                                             CDISASM_X86_GROUP_AVX10_1));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512F));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512VL));

    expect_error(CDISASM_CPU_SKYLAKE_SP, vpclmul, sizeof(vpclmul),
                 CDISASM_X86_DECODE_FLAG_PCLMUL,
                 CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, vpclmul, sizeof(vpclmul),
                 CDISASM_X86_DECODE_FLAG_AVX512,
                 CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

#if USE_DISASM_FORMAT
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
                  "vpclmulqdq zmm1, zmm2, zmm3, 0x11");
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
                  "vpclmulqdq $0x11, %zmm3, %zmm2, %zmm1");

    {
      static const uint8_t vaesdec[] = {0x62, 0xf2, 0x6d, 0x48, 0xde, 0xcb};

      instruction = decode64(CDISASM_CPU_ICE_LAKE, vaesdec, sizeof(vaesdec),
                             CDISASM_X86_DECODE_FLAG_AES, &decoded_size);
      expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
                    "vaesdec zmm1, zmm2, zmm3");
      expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
                    "vaesdec %zmm3, %zmm2, %zmm1");
    }
#endif
  }
#else
  expect_error(CDISASM_CPU_X86, vpclmul, sizeof(vpclmul),
               CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

typedef struct evex_arithmetic_case {
  uint8_t bytes[7];
  uint8_t size;
  cdisasm_x86_name_id name_id;
  cdisasm_x86_reg_id destination;
  cdisasm_x86_reg_id source1;
  cdisasm_x86_reg_id source2;
  cdisasm_x86_reg_id memory_base;
  uint8_t vector_size;
  uint8_t memory_size;
  uint8_t mask_number;
  uint8_t zeroing;
  uint8_t broadcast;
  uint8_t rounding;
#if USE_DISASM_FORMAT
  const char *intel;
  const char *att;
#endif
} evex_arithmetic_case;

static const evex_arithmetic_case evex_arithmetic_cases[] = {
    {{0x62, 0xf1, 0xed, 0xc9, 0x58, 0xcb, 0x00}, 6,
     CDISASM_X86_NAME_VADDPD, CDISASM_X86_REG_ZMM1,
     CDISASM_X86_REG_ZMM2, CDISASM_X86_REG_ZMM3, CDISASM_X86_REG_NONE,
     64, 0, 1, 1, 0, CDISASM_X86_ROUNDING_NONE,
#if USE_DISASM_FORMAT
     "vaddpd zmm1 {k1}{z}, zmm2, zmm3",
     "vaddpd %zmm3, %zmm2, %zmm1{%k1}{z}"
#endif
    },
    {{0x62, 0xf1, 0x54, 0x3a, 0x59, 0xe6, 0x00}, 6,
     CDISASM_X86_NAME_VMULPS, CDISASM_X86_REG_ZMM4,
     CDISASM_X86_REG_ZMM5, CDISASM_X86_REG_ZMM6, CDISASM_X86_REG_NONE,
     64, 0, 2, 0, 0, CDISASM_X86_ROUNDING_RD,
#if USE_DISASM_FORMAT
     "vmulps zmm4 {k2}, zmm5, zmm6, {rd-sae}",
     "vmulps {rd-sae}, %zmm6, %zmm5, %zmm4{%k2}"
#endif
    },
    {{0x62, 0xf1, 0xbd, 0xbb, 0x59, 0x38, 0x00}, 6,
     CDISASM_X86_NAME_VMULPD, CDISASM_X86_REG_YMM7,
     CDISASM_X86_REG_YMM8, CDISASM_X86_REG_NONE, CDISASM_X86_REG_RAX,
     32, 8, 3, 1, CDISASM_X86_BROADCAST_1_TO_4,
     CDISASM_X86_ROUNDING_NONE,
#if USE_DISASM_FORMAT
     "vmulpd ymm7 {k3}{z}, ymm8, qword ptr [rax]{1to4}",
     "vmulpd (%rax){1to4}, %ymm8, %ymm7{%k3}{z}"
#endif
    },
    {{0x62, 0x51, 0x2c, 0x0c, 0x5c, 0x4b, 0x02}, 7,
     CDISASM_X86_NAME_VSUBPS, CDISASM_X86_REG_XMM9,
     CDISASM_X86_REG_XMM10, CDISASM_X86_REG_NONE, CDISASM_X86_REG_R11,
     16, 16, 4, 0, 0, CDISASM_X86_ROUNDING_NONE,
#if USE_DISASM_FORMAT
     "vsubps xmm9 {k4}, xmm10, xmmword ptr [r11 + 0x20]",
     "vsubps 0x20(%r11), %xmm10, %xmm9{%k4}"
#endif
    },
    {{0x62, 0x51, 0x9d, 0xcd, 0x5c, 0xdd, 0x00}, 6,
     CDISASM_X86_NAME_VSUBPD, CDISASM_X86_REG_ZMM11,
     CDISASM_X86_REG_ZMM12, CDISASM_X86_REG_ZMM13, CDISASM_X86_REG_NONE,
     64, 0, 5, 1, 0, CDISASM_X86_ROUNDING_NONE,
#if USE_DISASM_FORMAT
     "vsubpd zmm11 {k5}{z}, zmm12, zmm13",
     "vsubpd %zmm13, %zmm12, %zmm11{%k5}{z}"
#endif
    },
    {{0x62, 0x71, 0x04, 0x3e, 0x5e, 0x31, 0x00}, 6,
     CDISASM_X86_NAME_VDIVPS, CDISASM_X86_REG_YMM14,
     CDISASM_X86_REG_YMM15, CDISASM_X86_REG_NONE, CDISASM_X86_REG_RCX,
     32, 4, 6, 0, CDISASM_X86_BROADCAST_1_TO_8,
     CDISASM_X86_ROUNDING_NONE,
#if USE_DISASM_FORMAT
     "vdivps ymm14 {k6}, ymm15, dword ptr [rcx]{1to8}",
     "vdivps (%rcx){1to8}, %ymm15, %ymm14{%k6}"
#endif
    },
    {{0x62, 0xa1, 0xf5, 0x87, 0x5e, 0xc2, 0x00}, 6,
     CDISASM_X86_NAME_VDIVPD, CDISASM_X86_REG_XMM16,
     CDISASM_X86_REG_XMM17, CDISASM_X86_REG_XMM18, CDISASM_X86_REG_NONE,
     16, 0, 7, 1, 0, CDISASM_X86_ROUNDING_NONE,
#if USE_DISASM_FORMAT
     "vdivpd xmm16 {k7}{z}, xmm17, xmm18",
     "vdivpd %xmm18, %xmm17, %xmm16{%k7}{z}"
#endif
    },
    {{0x62, 0xc1, 0xdd, 0xd1, 0xd4, 0x5d, 0x00}, 7,
     CDISASM_X86_NAME_VPADDQ, CDISASM_X86_REG_ZMM19,
     CDISASM_X86_REG_ZMM20, CDISASM_X86_REG_NONE, CDISASM_X86_REG_R13,
     64, 8, 1, 1, CDISASM_X86_BROADCAST_1_TO_8,
     CDISASM_X86_ROUNDING_NONE,
#if USE_DISASM_FORMAT
     "vpaddq zmm19 {k1}{z}, zmm20, qword ptr [r13]{1to8}",
     "vpaddq (%r13){1to8}, %zmm20, %zmm19{%k1}{z}"
#endif
    },
    {{0x62, 0xa1, 0x4d, 0x22, 0xfa, 0xef, 0x00}, 6,
     CDISASM_X86_NAME_VPSUBD, CDISASM_X86_REG_YMM21,
     CDISASM_X86_REG_YMM22, CDISASM_X86_REG_YMM23, CDISASM_X86_REG_NONE,
     32, 0, 2, 0, 0, CDISASM_X86_ROUNDING_NONE,
#if USE_DISASM_FORMAT
     "vpsubd ymm21 {k2}, ymm22, ymm23",
     "vpsubd %ymm23, %ymm22, %ymm21{%k2}"
#endif
    },
    {{0x62, 0x41, 0xb5, 0x93, 0xfb, 0x00, 0x00}, 6,
     CDISASM_X86_NAME_VPSUBQ, CDISASM_X86_REG_XMM24,
     CDISASM_X86_REG_XMM25, CDISASM_X86_REG_NONE, CDISASM_X86_REG_R8,
     16, 8, 3, 1, CDISASM_X86_BROADCAST_1_TO_2,
     CDISASM_X86_ROUNDING_NONE,
#if USE_DISASM_FORMAT
     "vpsubq xmm24 {k3}{z}, xmm25, qword ptr [r8]{1to2}",
     "vpsubq (%r8){1to2}, %xmm25, %xmm24{%k3}{z}"
#endif
    }};

#if USE_EXTRA_OPCODES
static cdisasm_x86_decode_bit_id evex_arithmetic_exact_bit(
    const evex_arithmetic_case *test) {
  if (test->name_id != CDISASM_X86_NAME_VMULPS &&
      test->name_id != CDISASM_X86_NAME_VMULPD) {
    return CDISASM_X86_DECODE_BIT_NONE;
  }
  return test->vector_size == 64u ? CDISASM_X86_DECODE_BIT_AVX512F_512
       : test->vector_size == 32u ? CDISASM_X86_DECODE_BIT_AVX512F_256
                                  : CDISASM_X86_DECODE_BIT_AVX512F_128;
}
#endif

static void test_evex_arithmetic_avx10(void) {
  static const uint8_t truncated[] = {0x62, 0xf1, 0xed, 0xc9, 0x58};
  static const uint8_t bad_w[] = {0x62, 0xf1, 0x6d, 0xc9, 0x58, 0xcb};
  static const uint8_t wrong_shape_w[] = {0x62, 0xf1, 0xec, 0xc9, 0x58, 0xcb};
  static const uint8_t bad_fixed[] = {0x62, 0xf1, 0xe9, 0xc9, 0x58, 0xcb};
  static const uint8_t bad_ll[] = {0x62, 0xf1, 0xed, 0xe9, 0x58, 0xcb};
  static const uint8_t zero_without_mask[] = {0x62, 0xf1, 0xed, 0xc8, 0x58, 0xcb};
  static const uint8_t integer_rounding[] = {0x62, 0xa1, 0x4d, 0x32, 0xfa, 0xef};
  static const uint8_t broadcast_ll3[] = {0x62, 0x71, 0x04, 0x7e, 0x5e, 0x31};
  size_t index;

  expect_error(CDISASM_CPU_X86, truncated, sizeof(truncated),
               CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
  expect_error(CDISASM_CPU_X86, bad_w, sizeof(bad_w),
               CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_INVALID_INSTRUCTION);
  expect_error(CDISASM_CPU_X86, wrong_shape_w, sizeof(wrong_shape_w),
               CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_INVALID_INSTRUCTION);
  expect_error(CDISASM_CPU_X86, bad_fixed, sizeof(bad_fixed),
               CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_INVALID_INSTRUCTION);
  expect_error(CDISASM_CPU_X86, bad_ll, sizeof(bad_ll),
               CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_INVALID_INSTRUCTION);
  expect_error(CDISASM_CPU_X86, zero_without_mask, sizeof(zero_without_mask),
               CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_INVALID_INSTRUCTION);
  expect_error(CDISASM_CPU_X86, integer_rounding, sizeof(integer_rounding),
               CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_INVALID_INSTRUCTION);
  expect_error(CDISASM_CPU_X86, broadcast_ll3, sizeof(broadcast_ll3),
               CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_INVALID_INSTRUCTION);

  EXPECT(sizeof(evex_arithmetic_cases) / sizeof(evex_arithmetic_cases[0])
         == 10u);
  for (index = 0;
       index < sizeof(evex_arithmetic_cases) / sizeof(evex_arithmetic_cases[0]);
       ++index) {
    const evex_arithmetic_case *test = &evex_arithmetic_cases[index];
#if USE_EXTRA_OPCODES
    const cdisasm_x86_decode_bit_id exact_bit =
        evex_arithmetic_exact_bit(test);
    uint32_t decoded_size;
    cdisasm_instruction instruction = exact_bit == CDISASM_X86_DECODE_BIT_NONE
        ? decode64(CDISASM_CPU_GRANITE_RAPIDS, test->bytes, test->size,
                   CDISASM_X86_DECODE_FLAG_AVX512, &decoded_size)
        : decode64_with_exact_bit(
              CDISASM_CPU_GRANITE_RAPIDS, test->bytes, test->size,
              CDISASM_X86_DECODE_FLAG_AVX512, exact_bit, &decoded_size);

    EXPECT(decoded_size == test->size);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == test->name_id);
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_EVEX) != 0);
    EXPECT(instruction.operand_count == 3);
    EXPECT(instruction.opcode[0].reg == test->destination);
    EXPECT(instruction.opcode[1].reg == test->source1);
    EXPECT(instruction.opcode[0].size == test->vector_size);
    EXPECT(instruction.mask_reg == CDISASM_X86_REG_K0 + test->mask_number);
    EXPECT(instruction.mask_mode ==
           (test->zeroing ? CDISASM_X86_MASK_ZERO
                          : CDISASM_X86_MASK_MERGE));
    EXPECT(instruction.rounding == test->rounding);
    EXPECT(instruction.sae == (test->rounding != CDISASM_X86_ROUNDING_NONE
                                   ? CDISASM_X86_SAE_ENABLED
                                   : CDISASM_X86_SAE_NONE));
    if (test->memory_base == CDISASM_X86_REG_NONE) {
      EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_REGISTER);
      EXPECT(instruction.opcode[2].reg == test->source2);
    } else {
      EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_MEMORY);
      EXPECT(instruction.opcode[2].base_reg == test->memory_base);
      EXPECT(instruction.opcode[2].size == test->memory_size);
      EXPECT(instruction.opcode[2].broadcast == test->broadcast);
    }
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512F));
    EXPECT(cdisasm_instruction_has_x86_group(
               &instruction, CDISASM_X86_GROUP_AVX512VL)
           == (test->vector_size < 64));

#if USE_DISASM_FORMAT
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL, test->intel);
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT, test->att);
#endif

    instruction = exact_bit == CDISASM_X86_DECODE_BIT_NONE
        ? decode64(CDISASM_CPU_AVX10, test->bytes, test->size,
                   CDISASM_X86_DECODE_FLAG_AVX10, &decoded_size)
        : decode64_with_exact_bit(
              CDISASM_CPU_AVX10, test->bytes, test->size,
              CDISASM_X86_DECODE_FLAG_AVX10, exact_bit, &decoded_size);
    EXPECT(decoded_size == test->size);
    EXPECT(instruction.name_id == test->name_id);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX10_1));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512F));
    EXPECT(!cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX512VL));
#else
    expect_error(CDISASM_CPU_X86, test->bytes, test->size,
                 CDISASM_X86_DECODE_FLAG_BASE,
                 CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
  }
#if USE_EXTRA_OPCODES
  {
    static const struct compressed_disp_case {
      uint8_t bytes[10];
      uint8_t size;
      int64_t displacement;
      uint8_t memory_size;
      uint8_t broadcast;
    } compressed_cases[] = {
        {{0x62, 0xf1, 0x6c, 0x09, 0x5c, 0x48, 0x7f}, 7,
         INT64_C(2032), 16, CDISASM_X86_BROADCAST_NONE},
        {{0x62, 0xf1, 0x6c, 0x09, 0x5c, 0x88, 0x00, 0x08, 0x00, 0x00}, 10,
         INT64_C(2048), 16, CDISASM_X86_BROADCAST_NONE},
        {{0x62, 0xf1, 0x6c, 0x39, 0x5e, 0x48, 0x7f}, 7,
         INT64_C(508), 4, CDISASM_X86_BROADCAST_1_TO_8},
        {{0x62, 0xf1, 0xed, 0x39, 0x5e, 0x48, 0x80}, 7,
         INT64_C(-1024), 8, CDISASM_X86_BROADCAST_1_TO_4},
        {{0x62, 0xf1, 0xed, 0x39, 0x5e, 0x88, 0xf8, 0xfb, 0xff, 0xff}, 10,
         INT64_C(-1032), 8, CDISASM_X86_BROADCAST_1_TO_4}};

    for (index = 0;
         index < sizeof(compressed_cases) / sizeof(compressed_cases[0]);
         ++index) {
      uint32_t decoded_size;
      cdisasm_instruction instruction = decode64(
          CDISASM_CPU_GRANITE_RAPIDS,
          compressed_cases[index].bytes,
          compressed_cases[index].size,
          CDISASM_X86_DECODE_FLAG_AVX512,
          &decoded_size);

      EXPECT(decoded_size == compressed_cases[index].size);
      EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_MEMORY);
      EXPECT((int64_t)instruction.opcode[2].imm
             == compressed_cases[index].displacement);
      EXPECT(instruction.opcode[2].size
             == compressed_cases[index].memory_size);
      EXPECT(instruction.opcode[2].broadcast
             == compressed_cases[index].broadcast);
    }
  }
#endif
}

static void test_vpclmul_vex_gate_split(void) {
  static const uint8_t xmm[] = {0xc4, 0xe3, 0x69, 0x44, 0xcb, 0x11};
  static const uint8_t ymm[] = {0xc4, 0xe3, 0x6d, 0x44, 0xcb, 0x11};
  static const uint8_t truncated[] = {0xc4, 0xe3, 0x69, 0x44, 0xcb};

  expect_error(CDISASM_CPU_X86, truncated, sizeof(truncated),
               CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);

#if USE_EXTRA_OPCODES
  {
    uint32_t decoded_size;
    cdisasm_instruction instruction =
        decode64(CDISASM_CPU_SANDY_BRIDGE, xmm, sizeof(xmm),
                 CDISASM_X86_DECODE_FLAG_PCLMUL, &decoded_size);

    EXPECT(decoded_size == sizeof(xmm));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_VPCLMULQDQ);
    EXPECT(instruction.operand_count == 4);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_XMM1);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_XMM2);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_XMM3);
    EXPECT(instruction.opcode[3].imm == UINT64_C(0x11));
    EXPECT(cdisasm_instruction_has_x86_group(&instruction,
                                             CDISASM_X86_GROUP_PCLMULQDQ));

    instruction = decode64(CDISASM_CPU_ICE_LAKE, ymm, sizeof(ymm),
                           CDISASM_X86_DECODE_FLAG_PCLMUL, &decoded_size);
    EXPECT(decoded_size == sizeof(ymm));
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_YMM1);
    EXPECT(cdisasm_instruction_has_x86_group(&instruction,
                                             CDISASM_X86_GROUP_VPCLMULQDQ));

    expect_error(CDISASM_CPU_WESTMERE, xmm, sizeof(xmm),
                 CDISASM_X86_DECODE_FLAG_PCLMUL,
                 CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_SKYLAKE, ymm, sizeof(ymm),
                 CDISASM_X86_DECODE_FLAG_PCLMUL,
                 CDISASM_STATUS_INVALID_INSTRUCTION);
  }
#else
  expect_error(CDISASM_CPU_X86, xmm, sizeof(xmm), CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
  expect_error(CDISASM_CPU_X86, ymm, sizeof(ymm), CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_amx_fp16(void) {
  static const uint8_t tdpfp16ps[] = {0xc4, 0xe2, 0x63, 0x5c, 0xca};
  static const uint8_t bad_w[] = {0xc4, 0xe2, 0xe3, 0x5c, 0xca};
  static const uint8_t bad_l[] = {0xc4, 0xe2, 0x67, 0x5c, 0xca};
  static const uint8_t duplicate_tile[] = {0xc4, 0xe2, 0x63, 0x5c, 0xc9};
  static const uint8_t truncated[] = {0xc4, 0xe2, 0x63, 0x5c};

  expect_error(CDISASM_CPU_X86, bad_w, sizeof(bad_w),
               CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_INVALID_INSTRUCTION);
  expect_error(CDISASM_CPU_X86, bad_l, sizeof(bad_l),
               CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_INVALID_INSTRUCTION);
  expect_error(CDISASM_CPU_X86, duplicate_tile, sizeof(duplicate_tile),
               CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_INVALID_INSTRUCTION);
  expect_error(CDISASM_CPU_X86, truncated, sizeof(truncated),
               CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);

#if USE_EXTRA_OPCODES
  {
    uint32_t decoded_size;
    cdisasm_instruction instruction =
        decode64(CDISASM_CPU_GRANITE_RAPIDS, tdpfp16ps, sizeof(tdpfp16ps),
                 CDISASM_X86_DECODE_FLAG_AMX, &decoded_size);

    EXPECT(decoded_size == sizeof(tdpfp16ps));
    EXPECT(instruction.name_id == CDISASM_X86_NAME_TDPFP16PS);
    EXPECT(instruction.operand_count == 3);
    EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_TMM1);
    EXPECT(instruction.opcode[1].reg == CDISASM_X86_REG_TMM2);
    EXPECT(instruction.opcode[2].reg == CDISASM_X86_REG_TMM3);
    EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_READ_WRITE);
    EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(cdisasm_instruction_has_x86_group(&instruction,
                                             CDISASM_X86_GROUP_AMX_FP16));
    EXPECT(cdisasm_instruction_has_x86_group(&instruction,
                                             CDISASM_X86_GROUP_AMX_TILE));
    EXPECT((cdisasm_x86_cpu_decode_flag_mask(CDISASM_CPU_GRANITE_RAPIDS,
                                             CDISASM_MODE_64) &
            CDISASM_X86_DECODE_FLAG_AMX) != 0);

    expect_error(CDISASM_CPU_SAPPHIRE_RAPIDS, tdpfp16ps, sizeof(tdpfp16ps),
                 CDISASM_X86_DECODE_FLAG_AMX,
                 CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error_mode(CDISASM_CPU_GRANITE_RAPIDS, CDISASM_MODE_32, tdpfp16ps,
                      sizeof(tdpfp16ps), CDISASM_X86_DECODE_FLAG_AMX,
                      CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, tdpfp16ps, sizeof(tdpfp16ps),
                 CDISASM_X86_DECODE_FLAG_FMA3,
                 CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

#if USE_DISASM_FORMAT
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
                  "tdpfp16ps tmm1, tmm2, tmm3");
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
                  "tdpfp16ps %tmm3, %tmm2, %tmm1");
#endif
  }
#else
  expect_error(CDISASM_CPU_X86, tdpfp16ps, sizeof(tdpfp16ps),
               CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_apx_jmpabs(void) {
  static const uint8_t jmpabs[] = {0xd5, 0x00, 0xa1, 0x88, 0x77, 0x66,
                                   0x55, 0x44, 0x33, 0x22, 0x11};
  static const uint8_t truncated[] = {0xd5, 0x00, 0xa1, 0x88, 0x77,
                                      0x66, 0x55, 0x44, 0x33, 0x22};
  static const uint8_t locked[] = {0xf0, 0xd5, 0x00, 0xa1, 0x88, 0x77,
                                   0x66, 0x55, 0x44, 0x33, 0x22, 0x11};

  expect_error(CDISASM_CPU_X86, truncated, sizeof(truncated),
               CDISASM_X86_DECODE_FLAG_BASE, CDISASM_STATUS_TRUNCATED);
  expect_error(CDISASM_CPU_X86, locked, sizeof(locked),
               CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_INVALID_INSTRUCTION);

  {
    uint32_t decoded_size;
    cdisasm_instruction collision =
        decode_mode(CDISASM_CPU_APX, CDISASM_MODE_32, jmpabs, sizeof(jmpabs),
#if USE_EXTRA_OPCODES
                    CDISASM_X86_DECODE_FLAG_APX,
#else
                    CDISASM_X86_DECODE_FLAG_BASE,
#endif
                    &decoded_size);

    /* Outside long mode D5 00 is the complete legacy AAD instruction;
     * the following A1 byte starts the next instruction. */
    EXPECT(decoded_size == 2);
    EXPECT(collision.last_error_id == CDISASM_STATUS_OK);
    EXPECT(collision.name_id == CDISASM_X86_NAME_AAD);
    EXPECT(collision.operand_count == 1);
    EXPECT(collision.opcode[0].imm == 0);
  }

#if USE_EXTRA_OPCODES
  {
    uint32_t decoded_size;
    cdisasm_instruction instruction =
        decode64(CDISASM_CPU_APX, jmpabs, sizeof(jmpabs),
                 CDISASM_X86_DECODE_FLAG_APX, &decoded_size);

    EXPECT(decoded_size == sizeof(jmpabs));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_JMPABS);
    EXPECT(instruction.opcode_groups == CDISASM_GROUP_JUMP);
    EXPECT(instruction.branch_target == UINT64_C(0x1122334455667788));
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REX2) != 0);
    EXPECT(instruction.operand_count == 1);
    EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction.opcode[0].size == 8);
    EXPECT(instruction.opcode[0].imm == UINT64_C(0x1122334455667788));
    EXPECT(cdisasm_instruction_has_x86_group(&instruction,
                                             CDISASM_X86_GROUP_AMD64));
    EXPECT(cdisasm_instruction_has_x86_group(&instruction,
                                             CDISASM_X86_GROUP_APX_F));
    EXPECT(instruction.encoding.prefix_size == 2);
    EXPECT(instruction.encoding.opcode_offset == 2);
    EXPECT(instruction.encoding.opcode_size == 1);
    EXPECT(instruction.encoding.immediate_count == 1);
    EXPECT(instruction.encoding.immediate_offset[0] == 3);
    EXPECT(instruction.encoding.immediate_size[0] == 8);

    expect_error(CDISASM_CPU_AVX10, jmpabs, sizeof(jmpabs),
                 CDISASM_X86_DECODE_FLAG_APX,
                 CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error(CDISASM_CPU_X86, jmpabs, sizeof(jmpabs),
                 CDISASM_X86_DECODE_FLAG_BASE,
                 CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

#if USE_DISASM_FORMAT
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
                  "jmpabs 0x1122334455667788");
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
                  "jmpabs $0x1122334455667788");
#endif
  }
#else
  expect_error(CDISASM_CPU_X86, jmpabs, sizeof(jmpabs),
               CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_vex_avx_ifma(void) {
  static const uint8_t cases[][5] = {
      {0xc4, 0xe2, 0xe9, 0xb4, 0xcb},
      {0xc4, 0xe2, 0xe9, 0xb5, 0x08},
      {0xc4, 0xe2, 0xed, 0xb4, 0xcb},
      {0xc4, 0xe2, 0xed, 0xb5, 0x08}};

#if USE_EXTRA_OPCODES
  size_t index;

  for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
    const unsigned int vector_size = index < 2 ? 16u : 32u;
    const int memory_source = (index & 1u) != 0u;
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode64_with_exact_bit(
        CDISASM_CPU_AVX10, cases[index], sizeof(cases[index]),
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_X86_DECODE_BIT_AVX_IFMA,
        &decoded_size);

    EXPECT(decoded_size == sizeof(cases[index]));
    EXPECT(instruction.name_id == ((index == 1u || index == 3u)
        ? CDISASM_X86_NAME_VPMADD52HUQ
        : CDISASM_X86_NAME_VPMADD52LUQ));
    EXPECT(instruction.operand_count == 3);
    EXPECT(instruction.opcode[0].size == vector_size);
    EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_READ_WRITE);
    EXPECT(instruction.opcode[1].size == vector_size);
    EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.opcode[2].size == vector_size);
    EXPECT(instruction.opcode[2].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.opcode[2].type == (memory_source
        ? CDISASM_OPERAND_MEMORY : CDISASM_OPERAND_REGISTER));
    if (memory_source) {
      EXPECT(instruction.opcode[2].base_reg == CDISASM_X86_REG_RAX);
    }
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_AVX_IFMA));
  }
  {
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode64_with_exact_bit(
        CDISASM_CPU_ICE_LAKE, cases[0], sizeof(cases[0]),
        CDISASM_X86_DECODE_FLAG_BASE, CDISASM_X86_DECODE_BIT_AVX_IFMA,
        &decoded_size);

    EXPECT(decoded_size == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
  }
#else
  expect_error(CDISASM_CPU_X86, cases[0], sizeof(cases[0]),
               CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_vex_byte_lane_shifts(void) {
  static const uint8_t cases[][6] = {
      {0xc5, 0xf1, 0x73, 0xfa, 0x05, 0x00},
      {0xc5, 0xe1, 0x73, 0xdc, 0x07, 0x00},
      {0xc5, 0xd5, 0x73, 0xfe, 0x09, 0x00},
      {0xc4, 0xc1, 0x45, 0x73, 0xd8, 0x0b}};
  static const uint8_t lengths[] = {5, 5, 5, 6};
  size_t index;

  for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
    const int ymm = index >= 2u;
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode_mode(
        ymm ? CDISASM_CPU_HASWELL : CDISASM_CPU_SANDY_BRIDGE,
        CDISASM_MODE_64, cases[index], lengths[index],
#if USE_EXTRA_OPCODES
        ymm ? CDISASM_X86_DECODE_FLAG_AVX2 : CDISASM_X86_DECODE_FLAG_AVX,
#else
        CDISASM_X86_DECODE_FLAG_BASE,
#endif
        &decoded_size);

#if USE_EXTRA_OPCODES
    EXPECT(decoded_size == lengths[index]);
    EXPECT(instruction.name_id == ((index & 1u) != 0u
        ? CDISASM_X86_NAME_VPSRLDQ : CDISASM_X86_NAME_VPSLLDQ));
    EXPECT(instruction.operand_count == 3);
    EXPECT(instruction.opcode[0].size == (ymm ? 32u : 16u));
    EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE);
    EXPECT(instruction.opcode[1].size == (ymm ? 32u : 16u));
    EXPECT(instruction.opcode[1].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(instruction.opcode[2].type == CDISASM_OPERAND_IMMEDIATE);
    EXPECT(instruction.opcode[2].size == 1u);
    EXPECT(instruction.opcode[2].imm == (UINT64_C(5) + 2u * index));
    EXPECT(cdisasm_instruction_has_x86_group(&instruction,
        ymm ? CDISASM_X86_GROUP_AVX2 : CDISASM_X86_GROUP_AVX));
#else
    EXPECT(decoded_size == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
  }
#if USE_EXTRA_OPCODES
  {
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode_mode(
        CDISASM_CPU_SANDY_BRIDGE, CDISASM_MODE_64, cases[2], lengths[2],
        CDISASM_X86_DECODE_FLAG_AVX2, &decoded_size);

    EXPECT(decoded_size == 0u);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
  }
#endif
}

int main(void) {
  test_fma3_matrix();
  test_fma3_policy_memory_and_format();
  test_vaes_vex();
  test_vpclmul_vex_gate_split();
  test_evex_crypto();
  test_evex_arithmetic_avx10();
  test_amx_fp16();
  test_apx_jmpabs();
  test_vex_avx_ifma();
  test_vex_byte_lane_shifts();

  if (failures != 0) {
    fprintf(stderr, "x86 expansion tests failed: %d (extra=%d, format=%d)\n",
            failures, USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
    return 1;
  }
  printf("x86 expansion tests passed (extra=%d, format=%d)\n",
         USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
  return 0;
}
