#include "test_decode_flags_adapter.h"

#include "cdisasm/cdisasm.h"

#if USE_DISASM_FORMAT
#include "cdisasm/cdisasm_format.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

_Static_assert(CDISASM_X86_NAME_CLRSSBSY == UINT16_C(828)
                   && CDISASM_X86_NAME_WRUSSQ == UINT16_C(839)
                   && CDISASM_X86_NAME_COUNT >= UINT16_C(840),
               "CET shadow-stack mnemonic IDs changed");
_Static_assert(CDISASM_X86_GROUP_CET_SS == UINT16_C(82),
               "CET shadow-stack group ID changed");

static int failures;

#define EXPECT(expression)                                                     \
  do {                                                                         \
    if (!(expression)) {                                                       \
      fprintf(stderr, "%s:%d: expectation failed: %s\n", __FILE__, __LINE__,   \
              #expression);                                                    \
      ++failures;                                                              \
    }                                                                          \
  } while (0)

typedef struct cet_case {
  const char *label;
  uint8_t bytes[6];
  uint8_t size;
  cdisasm_mode mode;
  cdisasm_x86_name_id name_id;
  uint8_t operand_count;
  uint8_t first_type;
  uint8_t first_size;
  cdisasm_operand_access first_access;
  cdisasm_x86_reg_id first_reg;
  cdisasm_x86_reg_id first_base;
  uint8_t second_type;
  uint8_t second_size;
  cdisasm_operand_access second_access;
  cdisasm_x86_reg_id second_reg;
  uint8_t privileged;
  uint8_t mandatory_f3;
  uint8_t mandatory_66;
} cet_case;

static const cet_case cet_cases[] = {
    {"CLRSSBSY", {0xf3, 0x0f, 0xae, 0x30}, 4, CDISASM_MODE_64,
     CDISASM_X86_NAME_CLRSSBSY, 1, CDISASM_OPERAND_MEMORY, 8,
     CDISASM_OPERAND_ACCESS_READ_WRITE, CDISASM_X86_REG_NONE,
     CDISASM_X86_REG_RAX, 0, 0, CDISASM_OPERAND_ACCESS_NONE,
     CDISASM_X86_REG_NONE, 1, 1, 0},
    {"INCSSPD", {0xf3, 0x0f, 0xae, 0xe8}, 4, CDISASM_MODE_32,
     CDISASM_X86_NAME_INCSSPD, 1, CDISASM_OPERAND_REGISTER, 4,
     CDISASM_OPERAND_ACCESS_READ, CDISASM_X86_REG_EAX,
     CDISASM_X86_REG_NONE, 0, 0, CDISASM_OPERAND_ACCESS_NONE,
     CDISASM_X86_REG_NONE, 0, 1, 0},
    {"INCSSPQ", {0xf3, 0x48, 0x0f, 0xae, 0xe8}, 5, CDISASM_MODE_64,
     CDISASM_X86_NAME_INCSSPQ, 1, CDISASM_OPERAND_REGISTER, 8,
     CDISASM_OPERAND_ACCESS_READ, CDISASM_X86_REG_RAX,
     CDISASM_X86_REG_NONE, 0, 0, CDISASM_OPERAND_ACCESS_NONE,
     CDISASM_X86_REG_NONE, 0, 1, 0},
    {"RDSSPD", {0xf3, 0x0f, 0x1e, 0xc8}, 4, CDISASM_MODE_32,
     CDISASM_X86_NAME_RDSSPD, 1, CDISASM_OPERAND_REGISTER, 4,
     CDISASM_OPERAND_ACCESS_WRITE, CDISASM_X86_REG_EAX,
     CDISASM_X86_REG_NONE, 0, 0, CDISASM_OPERAND_ACCESS_NONE,
     CDISASM_X86_REG_NONE, 0, 1, 0},
    {"RDSSPQ", {0xf3, 0x48, 0x0f, 0x1e, 0xc8}, 5, CDISASM_MODE_64,
     CDISASM_X86_NAME_RDSSPQ, 1, CDISASM_OPERAND_REGISTER, 8,
     CDISASM_OPERAND_ACCESS_WRITE, CDISASM_X86_REG_RAX,
     CDISASM_X86_REG_NONE, 0, 0, CDISASM_OPERAND_ACCESS_NONE,
     CDISASM_X86_REG_NONE, 0, 1, 0},
    {"RSTORSSP", {0xf3, 0x0f, 0x01, 0x28}, 4, CDISASM_MODE_64,
     CDISASM_X86_NAME_RSTORSSP, 1, CDISASM_OPERAND_MEMORY, 8,
     CDISASM_OPERAND_ACCESS_READ_WRITE, CDISASM_X86_REG_NONE,
     CDISASM_X86_REG_RAX, 0, 0, CDISASM_OPERAND_ACCESS_NONE,
     CDISASM_X86_REG_NONE, 0, 1, 0},
    {"SAVEPREVSSP", {0xf3, 0x0f, 0x01, 0xea}, 4, CDISASM_MODE_64,
     CDISASM_X86_NAME_SAVEPREVSSP, 0, 0, 0,
     CDISASM_OPERAND_ACCESS_NONE, CDISASM_X86_REG_NONE,
     CDISASM_X86_REG_NONE, 0, 0, CDISASM_OPERAND_ACCESS_NONE,
     CDISASM_X86_REG_NONE, 0, 1, 0},
    {"SETSSBSY", {0xf3, 0x0f, 0x01, 0xe8}, 4, CDISASM_MODE_64,
     CDISASM_X86_NAME_SETSSBSY, 0, 0, 0,
     CDISASM_OPERAND_ACCESS_NONE, CDISASM_X86_REG_NONE,
     CDISASM_X86_REG_NONE, 0, 0, CDISASM_OPERAND_ACCESS_NONE,
     CDISASM_X86_REG_NONE, 1, 1, 0},
    {"WRSSD", {0x0f, 0x38, 0xf6, 0x00}, 4, CDISASM_MODE_32,
     CDISASM_X86_NAME_WRSSD, 2, CDISASM_OPERAND_MEMORY, 4,
     CDISASM_OPERAND_ACCESS_WRITE, CDISASM_X86_REG_NONE,
     CDISASM_X86_REG_EAX, CDISASM_OPERAND_REGISTER, 4,
     CDISASM_OPERAND_ACCESS_READ, CDISASM_X86_REG_EAX, 0, 0, 0},
    {"WRSSQ", {0x48, 0x0f, 0x38, 0xf6, 0x00}, 5, CDISASM_MODE_64,
     CDISASM_X86_NAME_WRSSQ, 2, CDISASM_OPERAND_MEMORY, 8,
     CDISASM_OPERAND_ACCESS_WRITE, CDISASM_X86_REG_NONE,
     CDISASM_X86_REG_RAX, CDISASM_OPERAND_REGISTER, 8,
     CDISASM_OPERAND_ACCESS_READ, CDISASM_X86_REG_RAX, 0, 0, 0},
    {"WRUSSD", {0x66, 0x0f, 0x38, 0xf5, 0x00}, 5, CDISASM_MODE_32,
     CDISASM_X86_NAME_WRUSSD, 2, CDISASM_OPERAND_MEMORY, 4,
     CDISASM_OPERAND_ACCESS_WRITE, CDISASM_X86_REG_NONE,
     CDISASM_X86_REG_EAX, CDISASM_OPERAND_REGISTER, 4,
     CDISASM_OPERAND_ACCESS_READ, CDISASM_X86_REG_EAX, 1, 0, 1},
    {"WRUSSQ", {0x66, 0x48, 0x0f, 0x38, 0xf5, 0x00}, 6,
     CDISASM_MODE_64, CDISASM_X86_NAME_WRUSSQ, 2,
     CDISASM_OPERAND_MEMORY, 8, CDISASM_OPERAND_ACCESS_WRITE,
     CDISASM_X86_REG_NONE, CDISASM_X86_REG_RAX,
     CDISASM_OPERAND_REGISTER, 8, CDISASM_OPERAND_ACCESS_READ,
     CDISASM_X86_REG_RAX, 1, 0, 1}};

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

static int is_error_only(const cdisasm_instruction *instruction,
                         cdisasm_status status) {
  cdisasm_instruction expected;

  memset(&expected, 0, sizeof(expected));
  expected.last_error_id = (uint8_t)status;
  return memcmp(instruction, &expected, sizeof(expected)) == 0;
}

static void expect_error_mode(const char *label, cdisasm_cpu_id cpu,
                              cdisasm_mode mode, const uint8_t *bytes,
                              size_t size, cdisasm_x86_decode_option flags,
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
static void expect_success_case(cdisasm_cpu_id cpu, const cet_case *test) {
  uint32_t decoded_size;
  cdisasm_instruction instruction =
      decode_mode(cpu, test->mode, test->bytes, test->size,
                  CDISASM_X86_DECODE_FLAG_CET, &decoded_size);
  const int privileged =
      (instruction.opcode_groups & CDISASM_GROUP_PRIVILEGED) != 0;

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
  EXPECT(instruction.operand_count == test->operand_count);
  EXPECT(cdisasm_instruction_has_x86_group(
      &instruction, CDISASM_X86_GROUP_CET_SS));
  EXPECT(privileged == test->privileged);
  EXPECT(instruction.encoding.modrm_offset == test->size - 1u);
  EXPECT(instruction.encoding.modrm == test->bytes[test->size - 1u]);
  EXPECT((instruction.opcode_flags
          & (CDISASM_PREFIX_EFFECTIVE_REP
             | CDISASM_PREFIX_EFFECTIVE_REPNE)) == 0);

  if (test->mandatory_f3) {
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REP) != 0);
  }
  if (test->mandatory_66) {
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_OPERAND_SIZE) != 0);
  }
  if (test->operand_count > 0) {
    EXPECT(instruction.opcode[0].type == test->first_type);
    EXPECT(instruction.opcode[0].size == test->first_size);
    EXPECT(instruction.opcode[0].access == test->first_access);
    if (test->first_type == CDISASM_OPERAND_REGISTER) {
      EXPECT(instruction.opcode[0].reg == test->first_reg);
    } else {
      EXPECT(instruction.opcode[0].base_reg == test->first_base);
    }
  }
  if (test->operand_count > 1) {
    EXPECT(instruction.opcode[1].type == test->second_type);
    EXPECT(instruction.opcode[1].size == test->second_size);
    EXPECT(instruction.opcode[1].access == test->second_access);
    EXPECT(instruction.opcode[1].reg == test->second_reg);
  }
}
#endif

static void test_twelve_forms_and_ownership(void) {
  size_t index;

  EXPECT(sizeof(cet_cases) / sizeof(cet_cases[0]) == 12u);
  for (index = 0; index < sizeof(cet_cases) / sizeof(cet_cases[0]); ++index) {
#if USE_EXTRA_OPCODES
    expect_success_case(CDISASM_CPU_X86, &cet_cases[index]);
#else
    expect_error_mode(cet_cases[index].label, CDISASM_CPU_X86,
                      cet_cases[index].mode, cet_cases[index].bytes,
                      cet_cases[index].size, CDISASM_X86_DECODE_FLAG_BASE,
                      CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
  }
}

static void test_modes(void) {
  static const struct mode_case {
    const char *label;
    uint8_t bytes[5];
    uint8_t size;
    cdisasm_x86_name_id name_id;
  } dword_cases[] = {
      {"CLRSSBSY mode", {0xf3, 0x0f, 0xae, 0x30}, 4,
       CDISASM_X86_NAME_CLRSSBSY},
      {"INCSSPD mode", {0xf3, 0x0f, 0xae, 0xe8}, 4,
       CDISASM_X86_NAME_INCSSPD},
      {"RDSSPD mode", {0xf3, 0x0f, 0x1e, 0xc8}, 4,
       CDISASM_X86_NAME_RDSSPD},
      {"RSTORSSP mode", {0xf3, 0x0f, 0x01, 0x28}, 4,
       CDISASM_X86_NAME_RSTORSSP},
      {"SAVEPREVSSP mode", {0xf3, 0x0f, 0x01, 0xea}, 4,
       CDISASM_X86_NAME_SAVEPREVSSP},
      {"SETSSBSY mode", {0xf3, 0x0f, 0x01, 0xe8}, 4,
       CDISASM_X86_NAME_SETSSBSY},
      {"WRSSD mode", {0x0f, 0x38, 0xf6, 0x00}, 4,
       CDISASM_X86_NAME_WRSSD},
      {"WRUSSD mode", {0x66, 0x0f, 0x38, 0xf5, 0x00}, 5,
       CDISASM_X86_NAME_WRUSSD}};
  static const struct qword_case {
    const char *label;
    uint8_t bytes[6];
    uint8_t size;
    cdisasm_x86_name_id forbidden_name;
  } qword_cases[] = {
      {"INCSSPQ in 32-bit mode", {0xf3, 0x48, 0x0f, 0xae, 0xe8}, 5,
       CDISASM_X86_NAME_INCSSPQ},
      {"RDSSPQ in 32-bit mode", {0xf3, 0x48, 0x0f, 0x1e, 0xc8}, 5,
       CDISASM_X86_NAME_RDSSPQ},
      {"WRSSQ in 32-bit mode", {0x48, 0x0f, 0x38, 0xf6, 0x00}, 5,
       CDISASM_X86_NAME_WRSSQ},
      {"WRUSSQ in 32-bit mode", {0x66, 0x48, 0x0f, 0x38, 0xf5, 0x00}, 6,
       CDISASM_X86_NAME_WRUSSQ}};
  size_t index;

  for (index = 0;
       index < sizeof(dword_cases) / sizeof(dword_cases[0]); ++index) {
#if USE_EXTRA_OPCODES
    {
      static const cdisasm_mode modes[] = {
          CDISASM_MODE_16, CDISASM_MODE_32, CDISASM_MODE_64};
      size_t mode_index;

      for (mode_index = 0; mode_index < sizeof(modes) / sizeof(modes[0]);
           ++mode_index) {
        uint32_t decoded_size;
        cdisasm_instruction instruction = decode_mode(
            CDISASM_CPU_X86, modes[mode_index], dword_cases[index].bytes,
            dword_cases[index].size, CDISASM_X86_DECODE_FLAG_CET,
            &decoded_size);

        EXPECT(decoded_size == dword_cases[index].size);
        EXPECT(instruction.name_id == dword_cases[index].name_id);
      }
    }
#else
    expect_error_mode(dword_cases[index].label, CDISASM_CPU_X86,
                      CDISASM_MODE_16, dword_cases[index].bytes,
                      dword_cases[index].size,
                      CDISASM_X86_DECODE_FLAG_BASE,
                      CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
  }

  for (index = 0;
       index < sizeof(qword_cases) / sizeof(qword_cases[0]); ++index) {
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode_mode(
        CDISASM_CPU_X86, CDISASM_MODE_32, qword_cases[index].bytes,
        qword_cases[index].size, CDISASM_X86_DECODE_FLAG_BASE,
        &decoded_size);

    if (decoded_size == qword_cases[index].size) {
      EXPECT(instruction.name_id != qword_cases[index].forbidden_name);
    }
  }
}

static void test_redundant_operand_size_prefix(void) {
  static const struct prefix_case {
    const char *label;
    uint8_t bytes[6];
    uint8_t size;
    cdisasm_x86_name_id name_id;
  } cases[] = {
      {"66 CLRSSBSY", {0x66, 0xf3, 0x0f, 0xae, 0x30}, 5,
       CDISASM_X86_NAME_CLRSSBSY},
      {"66 INCSSPD", {0x66, 0xf3, 0x0f, 0xae, 0xe8}, 5,
       CDISASM_X86_NAME_INCSSPD},
      {"66 RDSSPD", {0x66, 0xf3, 0x0f, 0x1e, 0xc8}, 5,
       CDISASM_X86_NAME_RDSSPD},
      {"66 RSTORSSP", {0x66, 0xf3, 0x0f, 0x01, 0x28}, 5,
       CDISASM_X86_NAME_RSTORSSP},
      {"66 SAVEPREVSSP", {0x66, 0xf3, 0x0f, 0x01, 0xea}, 5,
       CDISASM_X86_NAME_SAVEPREVSSP},
      {"66 SETSSBSY", {0x66, 0xf3, 0x0f, 0x01, 0xe8}, 5,
       CDISASM_X86_NAME_SETSSBSY}};
  size_t index;

  for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
#if USE_EXTRA_OPCODES
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode_mode(
        CDISASM_CPU_TIGER_LAKE, CDISASM_MODE_64, cases[index].bytes,
        cases[index].size, CDISASM_X86_DECODE_FLAG_CET, &decoded_size);

    EXPECT(decoded_size == cases[index].size);
    EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
    EXPECT(instruction.name_id == cases[index].name_id);
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_OPERAND_SIZE) != 0);
    EXPECT((instruction.opcode_flags & CDISASM_PREFIX_REP) != 0);
    EXPECT((instruction.opcode_flags
            & (CDISASM_PREFIX_EFFECTIVE_REP
               | CDISASM_PREFIX_EFFECTIVE_REPNE)) == 0);
#else
    expect_error_mode(cases[index].label, CDISASM_CPU_TIGER_LAKE,
                      CDISASM_MODE_64, cases[index].bytes,
                      cases[index].size, CDISASM_X86_DECODE_FLAG_BASE,
                      CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
  }
}

static void test_cpu_and_runtime_gates(void) {
#if USE_EXTRA_OPCODES
  static const cdisasm_cpu_id supporting_cpus[] = {
      CDISASM_CPU_TIGER_LAKE, CDISASM_CPU_ALDER_LAKE,
      CDISASM_CPU_AMD_ZEN_4, CDISASM_CPU_SAPPHIRE_RAPIDS,
      CDISASM_CPU_GRANITE_RAPIDS};
  size_t cpu_index;
  size_t case_index;

  for (cpu_index = 0;
       cpu_index < sizeof(supporting_cpus) / sizeof(supporting_cpus[0]);
       ++cpu_index) {
    EXPECT((cdisasm_x86_cpu_decode_flag_mask(
                supporting_cpus[cpu_index], CDISASM_MODE_64)
            & CDISASM_X86_DECODE_FLAG_CET) != 0);
    for (case_index = 0;
         case_index < sizeof(cet_cases) / sizeof(cet_cases[0]); ++case_index) {
      expect_success_case(supporting_cpus[cpu_index],
                          &cet_cases[case_index]);
    }
  }
  EXPECT((cdisasm_x86_cpu_decode_flag_mask(
              CDISASM_CPU_TIGER_LAKE, CDISASM_MODE_32)
          & CDISASM_X86_DECODE_FLAG_CET) != 0);
  EXPECT((cdisasm_x86_cpu_decode_flag_mask(
              CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64)
          & CDISASM_X86_DECODE_FLAG_CET) == 0);

  for (case_index = 0;
       case_index < sizeof(cet_cases) / sizeof(cet_cases[0]); ++case_index) {
    if (cet_cases[case_index].name_id != CDISASM_X86_NAME_RDSSPD
        && cet_cases[case_index].name_id != CDISASM_X86_NAME_RDSSPQ) {
      expect_error_mode(cet_cases[case_index].label, CDISASM_CPU_ICE_LAKE,
                        cet_cases[case_index].mode,
                        cet_cases[case_index].bytes,
                        cet_cases[case_index].size,
                        CDISASM_X86_DECODE_FLAG_CET,
                        CDISASM_STATUS_INVALID_INSTRUCTION);
    }
    expect_error_mode(cet_cases[case_index].label, CDISASM_CPU_TIGER_LAKE,
                      cet_cases[case_index].mode,
                      cet_cases[case_index].bytes,
                      cet_cases[case_index].size,
                      CDISASM_X86_DECODE_FLAG_BASE,
                      CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
  }

  {
    static const uint8_t rdsspd[] = {0xf3, 0x0f, 0x1e, 0xc8};
    static const uint8_t rdsspq[] = {0xf3, 0x48, 0x0f, 0x1e, 0xc8};
    const uint8_t *codes[] = {rdsspd, rdsspq};
    const size_t sizes[] = {sizeof(rdsspd), sizeof(rdsspq)};
    size_t index;

    for (index = 0; index < sizeof(codes) / sizeof(codes[0]); ++index) {
      uint32_t decoded_size;
      cdisasm_instruction instruction = decode_mode(
          CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64, codes[index], sizes[index],
          CDISASM_X86_DECODE_FLAG_CET, &decoded_size);

      EXPECT(decoded_size == sizes[index]);
      EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
      EXPECT(instruction.name_id == CDISASM_X86_NAME_NOP);
      EXPECT(instruction.operand_count == 0);
      EXPECT(!cdisasm_instruction_has_x86_group(
          &instruction, CDISASM_X86_GROUP_CET_SS));
    }
  }
#else
  static const uint8_t rdsspd[] = {0xf3, 0x0f, 0x1e, 0xc8};

  expect_error_mode("RDSSP expansion ownership", CDISASM_CPU_ICE_LAKE,
                    CDISASM_MODE_64, rdsspd, sizeof(rdsspd),
                    CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
#endif
}

static void test_collisions(void) {
  static const uint8_t umonitor[] = {0xf3, 0x0f, 0xae, 0xf0};
  static const uint8_t nop_memory[] = {0xf3, 0x0f, 0x1e, 0x08};
  static const uint8_t nop_memory_alt[] = {0xf3, 0x0f, 0x1e, 0x10};
  static const uint8_t nop_register[] = {0xf3, 0x0f, 0x1e, 0xc0};
  static const uint8_t adcx[] = {0x66, 0x0f, 0x38, 0xf6, 0x00};
  static const uint8_t adox[] = {0xf3, 0x0f, 0x38, 0xf6, 0x00};
  static const uint8_t unprefixed_f5[] = {0x0f, 0x38, 0xf5, 0x00};
  static const uint8_t unprefixed_group7[] = {0x0f, 0x01, 0xe8};
  uint32_t decoded_size;
  cdisasm_instruction instruction;

  expect_error_mode("UMONITOR collision", CDISASM_CPU_X86,
                    CDISASM_MODE_64, umonitor, sizeof(umonitor),
                    CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
  expect_error_mode("UMONITOR collision in mode 16", CDISASM_CPU_X86,
                    CDISASM_MODE_16, umonitor, sizeof(umonitor),
                    CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
  expect_error_mode("ADCX collision", CDISASM_CPU_X86, CDISASM_MODE_64,
                    adcx, sizeof(adcx), CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
  expect_error_mode("ADOX collision", CDISASM_CPU_X86, CDISASM_MODE_64,
                    adox, sizeof(adox), CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
  expect_error_mode("unprefixed 0F38 F5 collision", CDISASM_CPU_X86,
                    CDISASM_MODE_64, unprefixed_f5,
                    sizeof(unprefixed_f5), CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);
  expect_error_mode("unprefixed Group 7 collision", CDISASM_CPU_X86,
                    CDISASM_MODE_64, unprefixed_group7,
                    sizeof(unprefixed_group7),
                    CDISASM_X86_DECODE_FLAG_BASE,
                    CDISASM_STATUS_UNSUPPORTED_INSTRUCTION);

  instruction = decode_mode(CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
                            nop_memory, sizeof(nop_memory),
                            CDISASM_X86_DECODE_FLAG_BASE, &decoded_size);
  EXPECT(decoded_size == sizeof(nop_memory));
  EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
  EXPECT(instruction.name_id == CDISASM_X86_NAME_NOP);
  EXPECT(instruction.operand_count == 1);
  EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_MEMORY);
  EXPECT(!cdisasm_instruction_has_x86_group(
      &instruction, CDISASM_X86_GROUP_CET_SS));

  instruction = decode_mode(CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
                            nop_memory_alt, sizeof(nop_memory_alt),
                            CDISASM_X86_DECODE_FLAG_BASE, &decoded_size);
  EXPECT(decoded_size == sizeof(nop_memory_alt));
  EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
  EXPECT(instruction.name_id == CDISASM_X86_NAME_NOP);
  EXPECT(instruction.operand_count == 1);
  EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_MEMORY);

  instruction = decode_mode(CDISASM_CPU_ICE_LAKE, CDISASM_MODE_64,
                            nop_register, sizeof(nop_register),
                            CDISASM_X86_DECODE_FLAG_BASE, &decoded_size);
  EXPECT(decoded_size == sizeof(nop_register));
  EXPECT(instruction.last_error_id == CDISASM_STATUS_OK);
  EXPECT(instruction.name_id == CDISASM_X86_NAME_NOP);
  EXPECT(instruction.operand_count == 1);
  EXPECT(instruction.opcode[0].type == CDISASM_OPERAND_REGISTER);
  EXPECT(instruction.opcode[0].reg == CDISASM_X86_REG_EAX);
}

static void test_invalid_and_truncated(void) {
  static const struct error_case {
    const char *label;
    uint8_t bytes[8];
    uint8_t size;
    cdisasm_status status;
  } cases[] = {
      {"CLRSSBSY register", {0xf3, 0x0f, 0xae, 0xf0}, 4,
       CDISASM_STATUS_UNSUPPORTED_INSTRUCTION},
      {"INCSSP memory /5", {0xf3, 0x0f, 0xae, 0x28}, 4,
       CDISASM_STATUS_INVALID_INSTRUCTION},
      {"Group 7 reserved register", {0xf3, 0x0f, 0x01, 0xe9}, 4,
       CDISASM_STATUS_INVALID_INSTRUCTION},
      {"WRSSD register", {0x0f, 0x38, 0xf6, 0xc0}, 4,
       CDISASM_STATUS_INVALID_INSTRUCTION},
      {"WRSSQ register", {0x48, 0x0f, 0x38, 0xf6, 0xc0}, 5,
       CDISASM_STATUS_INVALID_INSTRUCTION},
      {"WRUSSD register", {0x66, 0x0f, 0x38, 0xf5, 0xc0}, 5,
       CDISASM_STATUS_INVALID_INSTRUCTION},
      {"WRUSSQ register", {0x66, 0x48, 0x0f, 0x38, 0xf5, 0xc0}, 6,
       CDISASM_STATUS_INVALID_INSTRUCTION},
      {"locked CLRSSBSY", {0xf0, 0xf3, 0x0f, 0xae, 0x30}, 5,
       CDISASM_STATUS_INVALID_INSTRUCTION},
      {"locked WRSSD", {0xf0, 0x0f, 0x38, 0xf6, 0x00}, 5,
       CDISASM_STATUS_INVALID_INSTRUCTION},
      {"locked 0F 1E WIDENOP", {0xf0, 0xf3, 0x0f, 0x1e, 0xc0}, 5,
       CDISASM_STATUS_INVALID_INSTRUCTION},
      {"truncated 0F AE", {0xf3, 0x0f, 0xae}, 3,
       CDISASM_STATUS_TRUNCATED},
      {"truncated CLRSSBSY disp8", {0xf3, 0x0f, 0xae, 0x70}, 4,
       CDISASM_STATUS_TRUNCATED},
      {"truncated RDSSP", {0xf3, 0x0f, 0x1e}, 3,
       CDISASM_STATUS_TRUNCATED},
      {"truncated Group 7", {0xf3, 0x0f, 0x01}, 3,
       CDISASM_STATUS_TRUNCATED},
      {"truncated RSTORSSP SIB", {0xf3, 0x0f, 0x01, 0x6c, 0x24}, 5,
       CDISASM_STATUS_TRUNCATED},
      {"truncated WRSSD ModRM", {0x0f, 0x38, 0xf6}, 3,
       CDISASM_STATUS_TRUNCATED},
      {"truncated WRSSD SIB", {0x0f, 0x38, 0xf6, 0x04}, 4,
       CDISASM_STATUS_TRUNCATED},
      {"truncated WRUSSD ModRM", {0x66, 0x0f, 0x38, 0xf5}, 4,
       CDISASM_STATUS_TRUNCATED},
      {"truncated WRUSSD disp32",
       {0x66, 0x0f, 0x38, 0xf5, 0x85, 0x01, 0x02, 0x03}, 8,
       CDISASM_STATUS_TRUNCATED}};
  size_t index;

  for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
    expect_error_mode(cases[index].label, CDISASM_CPU_X86,
                      CDISASM_MODE_64, cases[index].bytes,
                      cases[index].size, CDISASM_X86_DECODE_FLAG_BASE,
                      cases[index].status);
  }
}

#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
static void expect_format(const cdisasm_instruction *instruction,
                          uint32_t syntax, const char *expected) {
  char text[160];
  size_t length = cdisasm_x86_format(instruction, syntax, text, sizeof(text));

  if (strcmp(text, expected) != 0) {
    fprintf(stderr, "expected format '%s', got '%s'\n", expected, text);
  }
  EXPECT(length == strlen(expected));
  EXPECT(strcmp(text, expected) == 0);
}

static void test_formatting_and_extended_registers(void) {
  static const struct format_case {
    uint8_t bytes[7];
    uint8_t size;
    cdisasm_x86_name_id name_id;
    const char *intel;
    const char *att;
  } cases[] = {
      {{0xf3, 0x41, 0x0f, 0xae, 0x71, 0x10}, 6,
       CDISASM_X86_NAME_CLRSSBSY, "clrssbsy qword ptr [r9 + 0x10]",
       "clrssbsy 0x10(%r9)"},
      {{0xf3, 0x49, 0x0f, 0xae, 0xe9}, 5,
       CDISASM_X86_NAME_INCSSPQ, "incsspq r9", "incsspq %r9"},
      {{0xf3, 0x49, 0x0f, 0x1e, 0xc9}, 5,
       CDISASM_X86_NAME_RDSSPQ, "rdsspq r9", "rdsspq %r9"},
      {{0xf3, 0x41, 0x0f, 0x01, 0x69, 0x10}, 6,
       CDISASM_X86_NAME_RSTORSSP, "rstorssp qword ptr [r9 + 0x10]",
       "rstorssp 0x10(%r9)"},
      {{0x4d, 0x0f, 0x38, 0xf6, 0x51, 0x10}, 6,
       CDISASM_X86_NAME_WRSSQ, "wrssq qword ptr [r9 + 0x10], r10",
       "wrssq %r10, 0x10(%r9)"},
      {{0x66, 0x4d, 0x0f, 0x38, 0xf5, 0x51, 0x10}, 7,
       CDISASM_X86_NAME_WRUSSQ, "wrussq qword ptr [r9 + 0x10], r10",
       "wrussq %r10, 0x10(%r9)"}};
  size_t index;

  for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
    uint32_t decoded_size;
    cdisasm_instruction instruction = decode_mode(
        CDISASM_CPU_TIGER_LAKE, CDISASM_MODE_64, cases[index].bytes,
        cases[index].size, CDISASM_X86_DECODE_FLAG_CET, &decoded_size);

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
  test_twelve_forms_and_ownership();
  test_modes();
  test_redundant_operand_size_prefix();
  test_cpu_and_runtime_gates();
  test_collisions();
  test_invalid_and_truncated();
#if USE_EXTRA_OPCODES && USE_DISASM_FORMAT
  test_formatting_and_extended_registers();
#endif

  if (failures != 0) {
    fprintf(stderr, "%d CET shadow-stack test(s) failed\n", failures);
    return 1;
  }
  puts("x86 CET shadow-stack tests passed");
  return 0;
}
