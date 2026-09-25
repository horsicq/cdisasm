#include <cdisasm/cdisasm.h>

#if USE_ARCH_X86
#  include <cdisasm/cdisasm_x86.h>
#endif
#if USE_ARCH_ARM
#  include <cdisasm/cdisasm_arm.h>
#endif
#if USE_DISASM_FORMAT && (USE_ARCH_X86 || USE_ARCH_ARM)
#  include <cdisasm/cdisasm_format.h>
#endif

#include <array>
#include <cstdint>
#include <cstdio>
#include <string_view>
#include <type_traits>

#if !defined(USE_ARCH_X86) || !defined(USE_ARCH_ARM) \
    || !defined(USE_DISASM_FORMAT) || !defined(USE_EXTRA_OPCODES)
#  error "cdisasm package does not expose feature defines to C++ consumers"
#endif
#if USE_ARCH_X86 != CDISASM_PACKAGE_EXPECT_X86
#  error "cdisasm x86 package feature disagrees with the C++ expectation"
#endif
#if USE_ARCH_ARM != CDISASM_PACKAGE_EXPECT_ARM
#  error "cdisasm ARM package feature disagrees with the C++ expectation"
#endif
#if USE_DISASM_FORMAT != CDISASM_PACKAGE_EXPECT_FORMAT
#  error "cdisasm formatter package feature disagrees with the C++ expectation"
#endif
#if USE_EXTRA_OPCODES != CDISASM_PACKAGE_EXPECT_EXTRA
#  error "cdisasm extra-opcode package feature disagrees with the C++ expectation"
#endif
#if CDISASM_PACKAGE_EXPECT_SHARED
#  if defined(CDISASM_STATIC)
#    error "shared cdisasm package unexpectedly defines CDISASM_STATIC"
#  endif
#elif !defined(CDISASM_STATIC)
#  error "static cdisasm package does not define CDISASM_STATIC"
#endif

static_assert(sizeof(cdisasm_decode_option) == 8,
              "installed generic decode-option width changed");
static_assert(sizeof(cdisasm_decode_flags) == CDISASM_DECODE_FLAGS_SIZE,
              "installed generic decode-flags ABI size changed");
static_assert(CDISASM_DECODE_FLAGS_SIZE == 64u,
              "installed decode-flags ABI is not 64 bytes");
using current_cpu_function = cdisasm_cpu_id (CDISASM_CALL *)();
static_assert(std::is_same_v<decltype(&cdisasm_current_cpu),
                  current_cpu_function>,
              "installed current-CPU query signature changed");
using generic_decode_function = uint32_t (CDISASM_CALL *)(
    cdisasm_cpu_id,
    uint32_t,
    const uint8_t *,
    size_t,
    uint64_t,
    const cdisasm_decode_flags *,
    void *);
using generic_flag_query_function = cdisasm_status (CDISASM_CALL *)(
    cdisasm_cpu_id,
    std::uint32_t,
    cdisasm_decode_flags *);
using generic_decode_checked_function = uint32_t (CDISASM_CALL *)(
    cdisasm_cpu_id,
    uint32_t,
    const uint8_t *,
    size_t,
    uint64_t,
    const cdisasm_decode_flags *,
    void *,
    size_t);
static_assert(std::is_same_v<decltype(&cdisasm_decode),
                  generic_decode_function>,
              "installed generic decode signature changed");
static_assert(std::is_same_v<decltype(&cdisasm_cpu_decode_flag_mask),
                  generic_flag_query_function>,
              "installed generic flag-query signature changed");
static_assert(std::is_same_v<decltype(&cdisasm_decode_checked),
                  generic_decode_checked_function>,
              "installed checked generic decode signature changed");
#if USE_ARCH_X86
static_assert(sizeof(cdisasm_x86_decode_option) == 8,
              "installed x86 decode-option width changed");
static_assert(sizeof(cdisasm_x86_decode_flags)
                  == sizeof(cdisasm_decode_flags),
              "installed x86 decode-flags ABI size changed");
using x86_decode_function = uint32_t (CDISASM_CALL *)(
    cdisasm_cpu_id,
    cdisasm_mode,
    const uint8_t *,
    size_t,
    uint64_t,
    const cdisasm_x86_decode_flags *,
    cdisasm_instruction *);
using x86_flag_query_function = cdisasm_status (CDISASM_CALL *)(
    cdisasm_x86_cpu_id,
    cdisasm_x86_mode,
    cdisasm_x86_decode_flags *);
static_assert(std::is_same_v<decltype(&cdisasm_x86_decode),
                  x86_decode_function>,
              "installed x86 decode signature changed");
static_assert(std::is_same_v<decltype(&cdisasm_x86_cpu_decode_flag_mask),
                  x86_flag_query_function>,
              "installed x86 decode-flag query signature changed");
#endif
#if USE_ARCH_ARM
static_assert(sizeof(cdisasm_arm_decode_option) == 8,
              "installed ARM decode-option width changed");
static_assert(std::is_same_v<cdisasm_arm_decode_option, std::uint64_t>,
              "installed ARM decode-option type changed");
static_assert(sizeof(cdisasm_arm_decode_flags)
                  == sizeof(cdisasm_decode_flags),
              "installed ARM decode-flags ABI size changed");
using arm_decode_function = uint32_t (CDISASM_CALL *)(
    cdisasm_arm_cpu_id,
    cdisasm_arm_mode,
    const uint8_t *,
    size_t,
    uint64_t,
    const cdisasm_arm_decode_flags *,
    cdisasm_arm_instruction *);
using arm_flag_query_function = cdisasm_status (CDISASM_CALL *)(
    cdisasm_arm_cpu_id,
    cdisasm_arm_mode,
    cdisasm_arm_decode_flags *);
static_assert(std::is_same_v<decltype(&cdisasm_arm_decode),
                  arm_decode_function>,
              "installed ARM decode signature changed");
static_assert(std::is_same_v<decltype(&cdisasm_arm_cpu_decode_flag_mask),
                  arm_flag_query_function>,
              "installed ARM flag-query signature changed");
#endif

#if (defined(CDISASM_PACKAGE_CPP_SCOPE_CORE) \
        + defined(CDISASM_PACKAGE_CPP_SCOPE_X86) \
        + defined(CDISASM_PACKAGE_CPP_SCOPE_ARM) \
        + defined(CDISASM_PACKAGE_CPP_SCOPE_FORMAT)) != 1
#  error "select exactly one C++ package-consumer scope"
#endif

#if defined(CDISASM_PACKAGE_CPP_SCOPE_X86) && !USE_ARCH_X86
#  error "the x86 proxy consumer requires x86 support"
#endif
#if defined(CDISASM_PACKAGE_CPP_SCOPE_ARM) && !USE_ARCH_ARM
#  error "the ARM proxy consumer requires ARM support"
#endif
#if defined(CDISASM_PACKAGE_CPP_SCOPE_FORMAT) \
        && !(USE_DISASM_FORMAT && (USE_ARCH_X86 || USE_ARCH_ARM))
#  error "the formatter proxy consumer requires an enabled formatter"
#endif

namespace {

int failures;

void check(bool condition, const char *expression, int line)
{
    if (!condition) {
        std::fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, line,
            expression);
        ++failures;
    }
}

#define CHECK(condition) check((condition), #condition, __LINE__)

void check_current_cpu()
{
    const cdisasm_cpu_id cpu_id = cdisasm_current_cpu();

    if (cpu_id == CDISASM_CPU_UNKNOWN) {
        return;
    }

    switch (CDISASM_CPU_GROUP_OF(cpu_id)) {
#if USE_ARCH_X86
        case CDISASM_CPU_GROUP_X86:
            CHECK(cpu_id >= CDISASM_CPU_FIRST);
            CHECK(cpu_id <= CDISASM_CPU_LAST);
            CHECK(cpu_id != CDISASM_CPU_X86);
            CHECK(cdisasm_x86_cpu_mode_mask(cpu_id)
                != CDISASM_X86_MODE_MASK_NONE);
            break;
#endif
#if USE_ARCH_ARM
        case CDISASM_CPU_GROUP_ARM:
            CHECK(cpu_id >= CDISASM_ARM_CPU_FIRST);
            CHECK(cpu_id <= CDISASM_ARM_CPU_LAST);
            CHECK(cpu_id != CDISASM_ARM_CPU_ANY);
            CHECK(cdisasm_arm_cpu_mode_mask(cpu_id)
                != CDISASM_ARM_MODE_MASK_NONE);
            break;
#endif
        default:
            CHECK(false);
            break;
    }
}

#if USE_ARCH_X86 \
        && (defined(CDISASM_PACKAGE_CPP_SCOPE_CORE) \
            || defined(CDISASM_PACKAGE_CPP_SCOPE_X86) \
            || defined(CDISASM_PACKAGE_CPP_SCOPE_FORMAT))
void check_x86()
{
    constexpr std::array<std::uint8_t, 1> code = { UINT8_C(0x90) };
    cdisasm_x86_instruction instruction{};
    cdisasm_x86_decode_flags available{};
    cdisasm_decode_flags generic_available{};

    CHECK(cdisasm_x86_cpu_mode_mask(CDISASM_CPU_80386)
        == (CDISASM_X86_MODE_MASK_16 | CDISASM_X86_MODE_MASK_32));
    CHECK(cdisasm_cpu_decode_flag_mask(
              CDISASM_CPU_80386,
              CDISASM_X86_MODE_32,
              &generic_available)
        == CDISASM_STATUS_OK);
#  if USE_EXTRA_OPCODES
    CHECK(cdisasm_x86_cpu_decode_flag_mask(
              CDISASM_CPU_PENTIUM_III, CDISASM_X86_MODE_32, &available)
        == CDISASM_STATUS_OK);
    CHECK((available.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP]
            & CDISASM_X86_DECODE_FLAG_SSE)
        != 0u);
#  else
    CHECK(cdisasm_x86_cpu_decode_flag_mask(
              CDISASM_CPU_PENTIUM_III, CDISASM_X86_MODE_32, &available)
        == CDISASM_STATUS_OK);
    CHECK(available.bitmap[CDISASM_X86_DECODE_FLAGS_FAMILY_BITMAP]
        == 0u);
#  endif

    CHECK(cdisasm_x86_decode(
              CDISASM_CPU_80386,
              CDISASM_X86_MODE_32,
              code.data(),
              code.size(),
              UINT64_C(0x1000),
              nullptr,
              &instruction)
        == code.size());
    CHECK(instruction.last_error_id == CDISASM_STATUS_OK);
    CHECK(instruction.address == UINT64_C(0x1000));
    CHECK(instruction.name_id == CDISASM_X86_NAME_NOP);

#  if USE_DISASM_FORMAT
    std::array<char, 16> text{};
    CHECK(cdisasm_x86_format(
              &instruction,
              CDISASM_FORMAT_SYNTAX_INTEL,
              text.data(),
              text.size())
        == std::string_view("nop").size());
    CHECK(std::string_view(text.data()) == "nop");
    CHECK(cdisasm_x86_format_mode(
              &instruction,
              CDISASM_MODE_32,
              CDISASM_FORMAT_SYNTAX_ATT,
              text.data(),
              text.size())
        == std::string_view("nop").size());
    CHECK(std::string_view(text.data()) == "nop");
#  endif
}
#endif

#if USE_ARCH_ARM \
        && (defined(CDISASM_PACKAGE_CPP_SCOPE_CORE) \
            || defined(CDISASM_PACKAGE_CPP_SCOPE_ARM) \
            || defined(CDISASM_PACKAGE_CPP_SCOPE_FORMAT))
void check_arm()
{
    constexpr std::array<std::uint8_t, 4> code = {
        UINT8_C(0x05), UINT8_C(0x00), UINT8_C(0x81), UINT8_C(0xe2)
    };
    cdisasm_arm_instruction instruction{};
    cdisasm_arm_decode_flags available{};

    CHECK(cdisasm_arm_cpu_decode_flag_mask(
              CDISASM_ARM_CPU_CORTEX_A7,
              CDISASM_ARM_MODE_A32,
              &available)
        == CDISASM_STATUS_OK);
    CHECK(available.bitmap[CDISASM_ARM_DECODE_FLAGS_OPTION_BITMAP]
        == CDISASM_ARM_DECODE_OPTION_BIG_ENDIAN);
    CHECK(cdisasm_arm_decode(
              CDISASM_ARM_CPU_CORTEX_A7,
              CDISASM_ARM_MODE_A32,
              code.data(),
              code.size(),
              UINT64_C(0x2000),
              nullptr,
              &instruction)
        == code.size());
    CHECK(instruction.last_error_id == CDISASM_STATUS_OK);
    CHECK(instruction.address == UINT64_C(0x2000));
    CHECK(instruction.name_id == CDISASM_ARM_NAME_ADD);
    CHECK(instruction.operand_count == 3);
    CHECK(instruction.operand[0].reg == CDISASM_ARM_REG_R0);
    CHECK(instruction.operand[1].reg == CDISASM_ARM_REG_R1);
    CHECK(instruction.operand[2].imm == UINT64_C(5));

#  if USE_DISASM_FORMAT
    std::array<char, 32> text{};
    constexpr std::string_view expected = "add r0, r1, #0x5";
    CHECK(cdisasm_arm_format(
              &instruction,
              CDISASM_FORMAT_SYNTAX_0,
              text.data(),
              text.size())
        == expected.size());
    CHECK(std::string_view(text.data()) == expected);
#  endif
}
#endif

const char *scope_name()
{
#if defined(CDISASM_PACKAGE_CPP_SCOPE_CORE)
    return "core";
#elif defined(CDISASM_PACKAGE_CPP_SCOPE_X86)
    return "x86 proxy";
#elif defined(CDISASM_PACKAGE_CPP_SCOPE_ARM)
    return "ARM proxy";
#else
    return "formatter proxy";
#endif
}

} // namespace

int main()
{
    CHECK(cdisasm_version()
        == (static_cast<std::uint32_t>(CDISASM_VERSION_MAJOR) << 16
            | static_cast<std::uint32_t>(CDISASM_VERSION_MINOR) << 8
            | static_cast<std::uint32_t>(CDISASM_VERSION_PATCH)));
    CHECK(std::string_view(cdisasm_version_string())
        == CDISASM_VERSION_STRING);
    check_current_cpu();

#if USE_ARCH_X86 \
        && (defined(CDISASM_PACKAGE_CPP_SCOPE_CORE) \
            || defined(CDISASM_PACKAGE_CPP_SCOPE_X86) \
            || defined(CDISASM_PACKAGE_CPP_SCOPE_FORMAT))
    check_x86();
#endif
#if USE_ARCH_ARM \
        && (defined(CDISASM_PACKAGE_CPP_SCOPE_CORE) \
            || defined(CDISASM_PACKAGE_CPP_SCOPE_ARM) \
            || defined(CDISASM_PACKAGE_CPP_SCOPE_FORMAT))
    check_arm();
#endif

    if (failures != 0) {
        std::fprintf(stderr, "%d C++ %s package check(s) failed\n", failures,
            scope_name());
        return 1;
    }

    std::printf("cdisasm C++ %s package smoke test passed\n", scope_name());
    return 0;
}
