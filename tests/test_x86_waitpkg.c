#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_X86_NAME_UMONITOR == UINT16_C(840)
                   && CDISASM_X86_NAME_UMWAIT == UINT16_C(841)
                   && CDISASM_X86_NAME_TPAUSE == UINT16_C(842)
                   && CDISASM_X86_NAME_COUNT >= UINT16_C(843),
               "WAITPKG mnemonic IDs changed");
_Static_assert(CDISASM_X86_GROUP_WAITPKG == UINT16_C(94),
               "WAITPKG group ID changed");

static int failures;

#define EXPECT(expression)                                                     \
  do {                                                                         \
    if (!(expression)) {                                                       \
      fprintf(stderr, "%s:%d: expectation failed: %s\n", __FILE__, __LINE__, \
              #expression);                                                    \
      ++failures;                                                              \
    }                                                                          \
  } while (0)

typedef struct waitpkg_case {
  const char *label;
  uint8_t bytes[8];
  uint8_t size;
  cdisasm_mode mode;
  cdisasm_x86_name_id name_id;
  cdisasm_x86_reg_id reg;
  uint8_t operand_size;
  uint8_t address_override;
  uint8_t rex_w;
} waitpkg_case;

static const waitpkg_case mode_cases[] = {
    {"UMONITOR mode 16", {0xf3, 0x0f, 0xae, 0xf0}, 4, CDISASM_MODE_16,
     CDISASM_X86_NAME_UMONITOR, CDISASM_X86_REG_AX, 2, 0, 0},
    {"UMONITOR mode 16 address 32", {0x67, 0xf3, 0x0f, 0xae, 0xf0}, 5,
     CDISASM_MODE_16, CDISASM_X86_NAME_UMONITOR, CDISASM_X86_REG_EAX, 4, 1,
     0},
    {"UMONITOR mode 32", {0xf3, 0x0f, 0xae, 0xf0}, 4, CDISASM_MODE_32,
     CDISASM_X86_NAME_UMONITOR, CDISASM_X86_REG_EAX, 4, 0, 0},
    {"UMONITOR mode 32 address 16", {0x67, 0xf3, 0x0f, 0xae, 0xf0}, 5,
     CDISASM_MODE_32, CDISASM_X86_NAME_UMONITOR, CDISASM_X86_REG_AX, 2, 1,
     0},
    {"UMONITOR mode 64", {0xf3, 0x0f, 0xae, 0xf0}, 4, CDISASM_MODE_64,
     CDISASM_X86_NAME_UMONITOR, CDISASM_X86_REG_RAX, 8, 0, 0},
    {"UMONITOR mode 64 address 32", {0x67, 0xf3, 0x0f, 0xae, 0xf0}, 5,
     CDISASM_MODE_64, CDISASM_X86_NAME_UMONITOR, CDISASM_X86_REG_EAX, 4, 1,
     0},
    {"UMONITOR r8", {0xf3, 0x41, 0x0f, 0xae, 0xf0}, 5, CDISASM_MODE_64,
     CDISASM_X86_NAME_UMONITOR, CDISASM_X86_REG_R8, 8, 0, 0},
    {"UMONITOR r8d address 32", {0x67, 0xf3, 0x41, 0x0f, 0xae, 0xf0}, 6,
     CDISASM_MODE_64, CDISASM_X86_NAME_UMONITOR, CDISASM_X86_REG_R8D, 4, 1,
     0},
    {"UMWAIT mode 16", {0xf2, 0x0f, 0xae, 0xf1}, 4, CDISASM_MODE_16,
     CDISASM_X86_NAME_UMWAIT, CDISASM_X86_REG_ECX, 4, 0, 0},
    {"UMWAIT mode 32", {0xf2, 0x0f, 0xae, 0xf1}, 4, CDISASM_MODE_32,
     CDISASM_X86_NAME_UMWAIT, CDISASM_X86_REG_ECX, 4, 0, 0},
    {"UMWAIT mode 64", {0xf2, 0x0f, 0xae, 0xf1}, 4, CDISASM_MODE_64,
     CDISASM_X86_NAME_UMWAIT, CDISASM_X86_REG_ECX, 4, 0, 0},
    {"UMWAIT r8d ignores REX.W", {0xf2, 0x49, 0x0f, 0xae, 0xf0}, 5,
     CDISASM_MODE_64, CDISASM_X86_NAME_UMWAIT, CDISASM_X86_REG_R8D, 4, 0,
     1},
    {"TPAUSE mode 16", {0x66, 0x0f, 0xae, 0xf1}, 4, CDISASM_MODE_16,
     CDISASM_X86_NAME_TPAUSE, CDISASM_X86_REG_ECX, 4, 0, 0},
    {"TPAUSE mode 32", {0x66, 0x0f, 0xae, 0xf1}, 4, CDISASM_MODE_32,
     CDISASM_X86_NAME_TPAUSE, CDISASM_X86_REG_ECX, 4, 0, 0},
    {"TPAUSE mode 64", {0x66, 0x0f, 0xae, 0xf1}, 4, CDISASM_MODE_64,
     CDISASM_X86_NAME_TPAUSE, CDISASM_X86_REG_ECX, 4, 0, 0},
    {"TPAUSE r8d ignores REX.W", {0x66, 0x49, 0x0f, 0xae, 0xf0}, 5,
     CDISASM_MODE_64, CDISASM_X86_NAME_TPAUSE, CDISASM_X86_REG_R8D, 4, 0,
     1}};

static cdisasm_instruction decode_mode(cdisasm_cpu_id cpu, cdisasm_mode mode,
                                       const uint8_t *bytes, size_t size,
                                       cdisasm_x86_decode_option flags,
                                       uint32_t *decoded_size) {
  cdisasm_instruction instruction;

  memset(&instruction, UINT8_C(0xa5), sizeof(instruction));
  *decoded_size = cdisasm_x86_decode(cpu, mode, bytes, size,
                                     UINT64_C(0x1000), flags, &instruction);
  return instruction;
}

static int is_error_only(const cdisasm_instruction *instruction,
                         cdisasm_status status) {
  cdisasm_instruction expected;

  memset(&expected, 0, sizeof(expected));
  expected.last_error_id = (uint8_t)status;
  return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static void expect_error(const char *label, cdisasm_cpu_id cpu,
                         cdisasm_mode mode, const uint8_t *bytes, size_t size,
                         cdisasm_x86_decode_option flags,
                         cdisasm_status status) {
  uint32_t decoded_size;
  cdisasm_instruction instruction =
      decode_mode(cpu, mode, bytes, size, flags, &decoded_size);

  if (decoded_size != 0 || !is_error_only(&instruction, status)) {
    fprintf(stderr,
            "%s: expected status %u, got status %u and decoded size %u\n",
            label, (unsigned int)status,
            (unsigned int)instruction.last_error_id,
            (unsigned int)decoded_size);
  }
  EXPECT(decoded_size == 0);
  EXPECT(is_error_only(&instruction, status));
}

#if USE_EXTRA_OPCODES
static cdisasm_instruction expect_success(cdisasm_cpu_id cpu,
                                          const waitpkg_case *test) {
  uint32_t decoded_size;
  cdisasm_instruction instruction =
      decode_mode(cpu, test->mode, test->bytes, test->size,
                  CDISASM_X86_DECODE_FLAG_SYSTEM, &decoded_size);

  if (decoded_size != test->size
      || instruction.last_error_id != CDISASM_STATUS_OK
      || instruction.name_id != test->name_id) {
    fprintf(stderr,
            "%s: expected name %u and size %u, got name %u, status %u, "
            "size %u\n",
            test->label, (unsigned int)test->name_id,
            (unsigned int)test->size, (unsigned int)instruction.name_id,
            (unsigned int)instruction.last_error_id,
            (unsigned int)decoded_size);
  }
  EXPECT(decoded_size == test->size);
  EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
  EXPECT(instruction.name_id == test->name_id);
  EXPECT(instruction.operand_count == 1);
  EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_REGISTER);
  EXPECT(instruction.opcode[0].reg == test->reg);
  EXPECT(instruction.opcode[0].size == test->operand_size);
  EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
  EXPECT(cdisasm_instruction_has_x86_group(
      &instruction, CDISASM_X86_GROUP_WAITPKG));
  EXPECT((instruction.opcode_groups & CDISASM_GROUP_PRIVILEGED) == 0);
  EXPECT(instruction.encoding.modrm_offset == test->size - 1u);
  EXPECT(instruction.encoding.modrm == test->bytes[test->size - 1u]);
  EXPECT((instruction.opcode_flags
          & (CDISASM_PREFIX_EFFECTIVE_REP
             | CDISASM_PREFIX_EFFECTIVE_REPNE)) == 0);
  EXPECT(((instruction.opcode_flags & CDISASM_PREFIX_ADDRESS_SIZE) != 0)
         == test->address_override);
  EXPECT(((instruction.opcode_flags & CDISASM_PREFIX_REX_W) != 0)
         == test->rex_w);
  return instruction;
}
#endif

static void test_modes_registers_and_access(void) {
  size_t index;

  EXPECT(sizeof(mode_cases) / sizeof(mode_cases[0]) == 16u);
  for (index = 0; index < sizeof(mode_cases) / sizeof(mode_cases[0]); ++index) {
#if USE_EXTRA_OPCODES
    (void)expect_success(CDISASM_CPU_X86, &mode_cases[index]);
#else
    expect_error(mode_cases[index].label, CDISASM_CPU_X86,
                 mode_cases[index].mode, mode_cases[index].bytes,
                 mode_cases[index].size, CDISASM_X86_DECODE_FLAG_BASE,
                 CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
  }
}

static void test_prefix_selection(void) {
  static const struct prefix_case {
    const char *label;
    uint8_t bytes[7];
    uint8_t size;
    cdisasm_x86_name_id name_id;
  } cases[] = {
      {"last F3 selects UMONITOR", {0xf2, 0xf3, 0x0f, 0xae, 0xf0}, 5,
       CDISASM_X86_NAME_UMONITOR},
      {"last F2 selects UMWAIT", {0xf3, 0xf2, 0x0f, 0xae, 0xf0}, 5,
       CDISASM_X86_NAME_UMWAIT},
      {"F2 wins before 66", {0xf2, 0x66, 0x0f, 0xae, 0xf0}, 5,
       CDISASM_X86_NAME_UMWAIT},
      {"F2 wins after 66", {0x66, 0xf2, 0x0f, 0xae, 0xf0}, 5,
       CDISASM_X86_NAME_UMWAIT},
      {"F3 wins after 66", {0x66, 0xf3, 0x0f, 0xae, 0xf0}, 5,
       CDISASM_X86_NAME_UMONITOR},
      {"F3 wins before 66", {0xf3, 0x66, 0x0f, 0xae, 0xf0}, 5,
       CDISASM_X86_NAME_UMONITOR}};
  size_t index;

  for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
#if USE_EXTRA_OPCODES
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode_mode(
        CDISASM_CPU_X86, CDISASM_MODE_64, cases[index].bytes,
        cases[index].size, CDISASM_X86_DECODE_FLAG_SYSTEM, &decoded_size);

    EXPECT(decoded_size == cases[index].size);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == cases[index].name_id);
    EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_WAITPKG));
    EXPECT((instruction.opcode_flags
            & (CDISASM_PREFIX_EFFECTIVE_REP
               | CDISASM_PREFIX_EFFECTIVE_REPNE)) == 0);
#else
    expect_error(cases[index].label, CDISASM_CPU_X86, CDISASM_MODE_64,
                 cases[index].bytes, cases[index].size,
                 CDISASM_X86_DECODE_FLAG_BASE,
                 CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
  }
}

static void test_rex2_waitpkg(void) {
  static const struct rex2_case {
    const char *label;
    uint8_t bytes[6];
    uint8_t size;
    cdisasm_x86_name_id name_id;
    cdisasm_x86_reg_id reg;
    uint8_t operand_size;
    uint8_t rex_w;
    uint8_t prefix_size;
    uint8_t address_override;
  } cases[] = {
      {"REX2 UMONITOR r16", {0xf3, 0xd5, 0x90, 0xae, 0xf0},
       5, CDISASM_X86_NAME_UMONITOR, CDISASM_X86_REG_R16, 8, 0, 3, 0},
      {"REX2 UMONITOR r24", {0xf3, 0xd5, 0x91, 0xae, 0xf0},
       5, CDISASM_X86_NAME_UMONITOR, CDISASM_X86_REG_R24, 8, 0, 3, 0},
      {"REX2 UMONITOR ignores W", {0xf3, 0xd5, 0x88, 0xae, 0xf0},
       5, CDISASM_X86_NAME_UMONITOR, CDISASM_X86_REG_RAX, 8, 1, 3, 0},
      {"REX2 UMONITOR r16d address 32",
       {0x67, 0xf3, 0xd5, 0x90, 0xae, 0xf0},
       6, CDISASM_X86_NAME_UMONITOR, CDISASM_X86_REG_R16D, 4, 0, 4, 1},
      {"REX2 UMWAIT r16d", {0xf2, 0xd5, 0x90, 0xae, 0xf0},
       5, CDISASM_X86_NAME_UMWAIT, CDISASM_X86_REG_R16D, 4, 0, 3, 0},
      {"REX2 TPAUSE r16d", {0x66, 0xd5, 0x90, 0xae, 0xf0},
       5, CDISASM_X86_NAME_TPAUSE, CDISASM_X86_REG_R16D, 4, 0, 3, 0}};
  size_t index;

  for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
#if USE_EXTRA_OPCODES
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode_mode(
        CDISASM_CPU_X86, CDISASM_MODE_64, cases[index].bytes,
        cases[index].size, CDISASM_X86_DECODE_FLAG_SYSTEM,
        &decoded_size);

    EXPECT(decoded_size == cases[index].size);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == cases[index].name_id);
    EXPECT(instruction.operand_count == 1);
    EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_REGISTER);
    EXPECT(instruction.opcode[0].reg == cases[index].reg);
    EXPECT(instruction.opcode[0].size == cases[index].operand_size);
    EXPECT(instruction.opcode[0].access == CDISASM_OPERAND_ACCESS_READ);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_WAITPKG));
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_APX_F));
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REX2) != 0);
    EXPECT(((instruction.opcode_flags & CDISASM_PREFIX_REX_W) != 0)
           == cases[index].rex_w);
    EXPECT(((instruction.opcode_flags & CDISASM_PREFIX_ADDRESS_SIZE) != 0)
           == cases[index].address_override);
    EXPECT((instruction.opcode_flags
            & (CDISASM_PREFIX_EFFECTIVE_REP
               | CDISASM_PREFIX_EFFECTIVE_REPNE)) == 0);
    EXPECT(instruction.encoding.prefix_size == cases[index].prefix_size);
    EXPECT(instruction.encoding.opcode_offset == cases[index].prefix_size);
    EXPECT(instruction.encoding.opcode_size == 1);
    EXPECT(instruction.encoding.modrm_offset == cases[index].size - 1u);
    EXPECT(instruction.encoding.modrm == UINT8_C(0xf0));
#else
    expect_error(cases[index].label, CDISASM_CPU_X86, CDISASM_MODE_64,
                 cases[index].bytes, cases[index].size,
                 CDISASM_X86_DECODE_FLAG_BASE,
                 CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
  }

#if USE_EXTRA_OPCODES
  {
    static const uint8_t rex2_umonitor[] = {
        0xf3, 0xd5, 0x90, 0xae, 0xf0};
    static const cdisasm_cpu_id waitpkg_without_apx[] = {
        CDISASM_CPU_PENTIUM_SILVER_N6000, CDISASM_CPU_ALDER_LAKE,
        CDISASM_CPU_SAPPHIRE_RAPIDS, CDISASM_CPU_GRANITE_RAPIDS,
        CDISASM_CPU_ARROW_LAKE};

    for (index = 0;
         index < sizeof(waitpkg_without_apx) / sizeof(waitpkg_without_apx[0]);
         ++index) {
      expect_error("REX2 WAITPKG APX cross-gate", waitpkg_without_apx[index],
                   CDISASM_MODE_64, rex2_umonitor, sizeof(rex2_umonitor),
                   CDISASM_X86_DECODE_FLAG_SYSTEM,
                   CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    expect_error("REX2 WAITPKG feature cross-gate", CDISASM_CPU_APX,
                 CDISASM_MODE_64, rex2_umonitor, sizeof(rex2_umonitor),
                 CDISASM_X86_DECODE_FLAG_SYSTEM,
                 CDISASM_STATUS_INVALID_INSTRUCTION);
    expect_error("REX2 WAITPKG runtime family", CDISASM_CPU_X86,
                 CDISASM_MODE_64, rex2_umonitor, sizeof(rex2_umonitor),
                 CDISASM_X86_DECODE_FLAG_APX,
                 CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

    {
      uint32_t decoded_size;
      cdisasm_instruction instruction = decode_mode(
          CDISASM_CPU_DIAMOND_RAPIDS, CDISASM_MODE_64,
          rex2_umonitor, sizeof(rex2_umonitor),
          CDISASM_X86_DECODE_FLAG_SYSTEM, &decoded_size);

      EXPECT(decoded_size == sizeof(rex2_umonitor));
      EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
      EXPECT(instruction.name_id == CDISASM_X86_NAME_UMONITOR);
      EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_R16);
      EXPECT(cdisasm_instruction_has_x86_group(
          &instruction, CDISASM_X86_GROUP_WAITPKG));
      EXPECT(cdisasm_instruction_has_x86_group(
          &instruction, CDISASM_X86_GROUP_APX_F));
    }
  }
#endif

  {
    static const struct rex2_cet_case {
      const char *label;
      uint8_t bytes[5];
      cdisasm_x86_name_id name_id;
      uint8_t operand_type;
      cdisasm_x86_reg_id reg;
      cdisasm_x86_reg_id base_reg;
      uint8_t operand_size;
      cdisasm_operand_access access;
      uint8_t privileged;
    } cet_cases[] = {
        {"REX2 INCSSPD r16d", {0xf3, 0xd5, 0x90, 0xae, 0xe8},
         CDISASM_X86_NAME_INCSSPD, CDISASM_OPERAND_REGISTER,
         CDISASM_X86_REG_R16D, CDISASM_X86_REG_NONE, 4,
         CDISASM_OPERAND_ACCESS_READ, 0},
        {"REX2 INCSSPQ r16", {0xf3, 0xd5, 0x98, 0xae, 0xe8},
         CDISASM_X86_NAME_INCSSPQ, CDISASM_OPERAND_REGISTER,
         CDISASM_X86_REG_R16, CDISASM_X86_REG_NONE, 8,
         CDISASM_OPERAND_ACCESS_READ, 0},
        {"REX2 CLRSSBSY r16 memory", {0xf3, 0xd5, 0x90, 0xae, 0x30},
         CDISASM_X86_NAME_CLRSSBSY, CDISASM_OPERAND_MEMORY,
         CDISASM_X86_REG_NONE, CDISASM_X86_REG_R16, 8,
         CDISASM_OPERAND_ACCESS_READ_WRITE, 1}};

    for (index = 0;
         index < sizeof(cet_cases) / sizeof(cet_cases[0]); ++index) {
#if USE_EXTRA_OPCODES
      uint32_t decoded_size;
      cdisasm_instruction instruction = decode_mode(
          CDISASM_CPU_X86, CDISASM_MODE_64, cet_cases[index].bytes,
          sizeof(cet_cases[index].bytes), CDISASM_X86_DECODE_FLAG_CET,
          &decoded_size);

      EXPECT(decoded_size == sizeof(cet_cases[index].bytes));
      EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
      EXPECT(instruction.name_id == cet_cases[index].name_id);
      EXPECT(instruction.operand_count == 1);
      EXPECT(instruction.opcode[0].type == cet_cases[index].operand_type);
      EXPECT(instruction.opcode[0].size == cet_cases[index].operand_size);
      EXPECT(instruction.opcode[0].access == cet_cases[index].access);
      if (cet_cases[index].operand_type == CDISASM_OPERAND_REGISTER) {
        EXPECT(instruction.opcode[0].reg == cet_cases[index].reg);
      } else {
        EXPECT(instruction.opcode[0].base_reg == cet_cases[index].base_reg);
      }
      EXPECT(((instruction.opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0)
             == cet_cases[index].privileged);
      EXPECT(cdisasm_instruction_has_x86_group(
          &instruction, CDISASM_X86_GROUP_CET_SS));
      EXPECT(cdisasm_instruction_has_x86_group(
          &instruction, CDISASM_X86_GROUP_APX_F));
      EXPECT(!cdisasm_instruction_has_x86_group(
          &instruction, CDISASM_X86_GROUP_WAITPKG));
      EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REX2) != 0);
      EXPECT((instruction.opcode_flags
              & (CDISASM_PREFIX_EFFECTIVE_REP
                 | CDISASM_PREFIX_EFFECTIVE_REPNE)) == 0);

      expect_error("REX2 CET runtime family", CDISASM_CPU_X86,
                   CDISASM_MODE_64, cet_cases[index].bytes,
                   sizeof(cet_cases[index].bytes),
                   CDISASM_X86_DECODE_FLAG_SYSTEM,
                   CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#else
      expect_error(cet_cases[index].label, CDISASM_CPU_X86,
                   CDISASM_MODE_64, cet_cases[index].bytes,
                   sizeof(cet_cases[index].bytes),
                   CDISASM_X86_DECODE_FLAG_BASE,
                   CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
    }

#if USE_EXTRA_OPCODES
    {
      static const uint8_t sib_no_base[] = {
          0xf3, 0xd5, 0x90, 0xae, 0x34, 0x25,
          0x20, 0x00, 0x00, 0x00};
      uint32_t decoded_size;
      cdisasm_instruction instruction = decode_mode(
          CDISASM_CPU_X86, CDISASM_MODE_64,
          sib_no_base, sizeof(sib_no_base),
          CDISASM_X86_DECODE_FLAG_CET, &decoded_size);

      EXPECT(decoded_size == sizeof(sib_no_base));
      EXPECT(instruction.name_id == CDISASM_X86_NAME_CLRSSBSY);
      EXPECT(instruction.operand_count == 1);
      EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_MEMORY);
      EXPECT(instruction.opcode[0].base_reg == CDISASM_X86_REG_NONE);
      EXPECT(instruction.opcode[0].index_reg == CDISASM_X86_REG_NONE);
      EXPECT((instruction.opcode[0].flags
              & (CDISASM_OPERAND_FLAG_ABSOLUTE
                 | CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT))
             == (CDISASM_OPERAND_FLAG_ABSOLUTE
                 | CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT));
      EXPECT(instruction.opcode[0].address == UINT64_C(0x20));
      EXPECT(instruction.encoding.sib_offset == 5);
      EXPECT(instruction.encoding.sib == UINT8_C(0x25));
      EXPECT(cdisasm_instruction_has_x86_group(
          &instruction, CDISASM_X86_GROUP_CET_SS));
      EXPECT(cdisasm_instruction_has_x86_group(
          &instruction, CDISASM_X86_GROUP_APX_F));
    }

    {
      uint32_t decoded_size;
      cdisasm_instruction instruction = decode_mode(
          CDISASM_CPU_APX, CDISASM_MODE_64,
          cet_cases[0].bytes, sizeof(cet_cases[0].bytes),
          CDISASM_X86_DECODE_FLAG_CET, &decoded_size);

      EXPECT(decoded_size == sizeof(cet_cases[0].bytes));
      EXPECT(instruction.name_id == CDISASM_X86_NAME_INCSSPD);
      expect_error("REX2 CET APX cross-gate", CDISASM_CPU_ALDER_LAKE,
                   CDISASM_MODE_64, cet_cases[0].bytes,
                   sizeof(cet_cases[0].bytes),
                   CDISASM_X86_DECODE_FLAG_CET,
                   CDISASM_STATUS_INVALID_INSTRUCTION);
    }
#endif
  }
}

static void test_cpu_profiles_and_runtime_gate(void) {
  static const uint8_t umonitor[] = {0xf3, 0x0f, 0xae, 0xf0};
#if USE_EXTRA_OPCODES
  static const cdisasm_cpu_id supporting_cpus[] = {
      CDISASM_CPU_X86, CDISASM_CPU_PENTIUM_SILVER_N6000,
      CDISASM_CPU_ALDER_LAKE, CDISASM_CPU_SAPPHIRE_RAPIDS,
      CDISASM_CPU_GRANITE_RAPIDS, CDISASM_CPU_ARROW_LAKE,
      CDISASM_CPU_DIAMOND_RAPIDS};
  static const cdisasm_cpu_id rejecting_cpus[] = {
      CDISASM_CPU_ICE_LAKE, CDISASM_CPU_TIGER_LAKE,
      CDISASM_CPU_AMD_ZEN_4, CDISASM_CPU_AVX10, CDISASM_CPU_APX};
  size_t index;

  for (index = 0;
       index < sizeof(supporting_cpus) / sizeof(supporting_cpus[0]); ++index) {
    uint32_t decoded_size;
    cdisasm_instruction instruction;

    EXPECT((cdisasm_x86_cpu_decode_flag_mask(supporting_cpus[index],
                                             CDISASM_MODE_64)
            & CDISASM_X86_DECODE_FLAG_SYSTEM) != 0);
    instruction = decode_mode(supporting_cpus[index], CDISASM_MODE_64,
                              umonitor, sizeof(umonitor),
                              CDISASM_X86_DECODE_FLAG_SYSTEM, &decoded_size);
    EXPECT(decoded_size == sizeof(umonitor));
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == CDISASM_X86_NAME_UMONITOR);
    EXPECT(cdisasm_instruction_has_x86_group(
        &instruction, CDISASM_X86_GROUP_WAITPKG));

    expect_error("WAITPKG base gate", supporting_cpus[index],
                 CDISASM_MODE_64, umonitor, sizeof(umonitor),
                 CDISASM_X86_DECODE_FLAG_BASE,
                 CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
    expect_error("WAITPKG unrelated gate", supporting_cpus[index],
                 CDISASM_MODE_64, umonitor, sizeof(umonitor),
                 CDISASM_X86_DECODE_FLAG_CET,
                 CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
  }

  for (index = 0;
       index < sizeof(rejecting_cpus) / sizeof(rejecting_cpus[0]); ++index) {
    expect_error("WAITPKG CPU gate", rejecting_cpus[index],
                 CDISASM_MODE_64, umonitor, sizeof(umonitor),
                 CDISASM_X86_DECODE_FLAG_SYSTEM,
                 CDISASM_STATUS_INVALID_INSTRUCTION);
  }
#else
  expect_error("WAITPKG build ownership", CDISASM_CPU_X86,
               CDISASM_MODE_64, umonitor, sizeof(umonitor),
               CDISASM_X86_DECODE_FLAG_BASE,
               CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
  expect_error("WAITPKG unavailable runtime flag", CDISASM_CPU_X86,
               CDISASM_MODE_64, umonitor, sizeof(umonitor),
               CDISASM_X86_DECODE_FLAG_SYSTEM,
               CDISASM_STATUS_INVALID_ARGUMENT);
#endif
}

static void test_collisions_invalid_and_truncated(void) {
  static const struct error_case {
    const char *label;
    uint8_t bytes[8];
    uint8_t size;
    cdisasm_status status;
  } cases[] = {
      {"locked UMONITOR", {0xf0, 0xf3, 0x0f, 0xae, 0xf0}, 5,
       CDISASM_STATUS_INVALID_INSTRUCTION},
      {"locked UMWAIT", {0xf0, 0xf2, 0x0f, 0xae, 0xf0}, 5,
       CDISASM_STATUS_INVALID_INSTRUCTION},
      {"locked TPAUSE", {0xf0, 0x66, 0x0f, 0xae, 0xf0}, 5,
       CDISASM_STATUS_INVALID_INSTRUCTION},
      {"F3 memory is CLRSSBSY", {0xf3, 0x0f, 0xae, 0x30}, 4,
       CDISASM_STATUS_UNSUPPORTED_INSTRUCTION},
      {"F2 memory is reserved", {0xf2, 0x0f, 0xae, 0x30}, 4,
       CDISASM_STATUS_INVALID_INSTRUCTION},
      {"F2 wrong register extension", {0xf2, 0x0f, 0xae, 0xf8}, 4,
       CDISASM_STATUS_INVALID_INSTRUCTION},
      {"66 wrong register extension", {0x66, 0x0f, 0xae, 0xf8}, 4,
       CDISASM_STATUS_INVALID_INSTRUCTION},
      {"66 memory is CLWB", {0x66, 0x0f, 0xae, 0x30}, 4,
       CDISASM_STATUS_UNSUPPORTED_INSTRUCTION},
      {"REX2 66 memory is CLWB", {0x66, 0xd5, 0x80, 0xae, 0x30}, 5,
       CDISASM_STATUS_UNSUPPORTED_INSTRUCTION},
      {"truncated UMONITOR", {0xf3, 0x0f, 0xae}, 3,
       CDISASM_STATUS_TRUNCATED},
      {"truncated UMWAIT", {0xf2, 0x0f, 0xae}, 3,
       CDISASM_STATUS_TRUNCATED},
      {"truncated TPAUSE", {0x66, 0x0f, 0xae}, 3,
       CDISASM_STATUS_TRUNCATED},
      {"truncated UMONITOR after REX", {0xf3, 0x41, 0x0f, 0xae}, 4,
       CDISASM_STATUS_TRUNCATED},
      {"truncated REX2 WAITPKG ModRM", {0xf3, 0xd5, 0x80, 0xae}, 4,
       CDISASM_STATUS_TRUNCATED},
      {"truncated REX2 CET SIB displacement",
       {0xf3, 0xd5, 0x90, 0xae, 0x34, 0x25}, 6,
       CDISASM_STATUS_TRUNCATED}};
  size_t index;

  for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
    expect_error(cases[index].label, CDISASM_CPU_X86, CDISASM_MODE_64,
                 cases[index].bytes, cases[index].size,
#if USE_EXTRA_OPCODES
                 CDISASM_X86_DECODE_FLAG_SYSTEM,
#else
                 CDISASM_X86_DECODE_FLAG_BASE,
#endif
                 cases[index].status);
  }
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(const cdisasm_instruction *instruction,
                          uint32_t syntax, const char *expected) {
  char text[128];
  size_t length = cdisasm_x86_format(instruction, syntax, text, sizeof(text));

  if (strcmp(text, expected) != 0) {
    fprintf(stderr, "expected format '%s', got '%s'\n", expected, text);
  }
  EXPECT(length == strlen(expected));
  EXPECT(strcmp(text, expected) == 0);
}

static void test_formatting(void) {
  static const struct format_case {
    uint8_t bytes[7];
    uint8_t size;
    cdisasm_x86_name_id name_id;
    const char *intel;
    const char *att;
  } cases[] = {
      {{0xf3, 0x41, 0x0f, 0xae, 0xf1}, 5,
       CDISASM_X86_NAME_UMONITOR, "umonitor r9", "umonitor %r9"},
      {{0x67, 0xf3, 0x41, 0x0f, 0xae, 0xf1}, 6,
       CDISASM_X86_NAME_UMONITOR, "umonitor r9d", "umonitor %r9d"},
      {{0xf2, 0x49, 0x0f, 0xae, 0xf2}, 5,
       CDISASM_X86_NAME_UMWAIT, "umwait r10d", "umwait %r10d"},
      {{0x66, 0x49, 0x0f, 0xae, 0xf3}, 5,
       CDISASM_X86_NAME_TPAUSE, "tpause r11d", "tpause %r11d"}};
  size_t index;

  for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode_mode(
        CDISASM_CPU_X86, CDISASM_MODE_64, cases[index].bytes,
        cases[index].size, CDISASM_X86_DECODE_FLAG_SYSTEM, &decoded_size);

    EXPECT(decoded_size == cases[index].size);
    EXPECT(instruction.name_id == cases[index].name_id);
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_INTEL,
                  cases[index].intel);
    expect_format(&instruction, CDISASM_FORMAT_SYNTAX_X86_ATT,
                  cases[index].att);
  }
}
#endif

int main(void) {
  test_modes_registers_and_access();
  test_prefix_selection();
  test_rex2_waitpkg();
  test_cpu_profiles_and_runtime_gate();
  test_collisions_invalid_and_truncated();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
  test_formatting();
#endif

  if (failures != 0) {
    fprintf(stderr, "%d WAITPKG test(s) failed (extra=%d, format=%d)\n",
            failures, USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
    return 1;
  }
  printf("x86 WAITPKG tests passed (extra=%d, format=%d)\n",
         USE_EXTRA_OPCODES, USE_DISASM_FORMAT);
  return 0;
}
