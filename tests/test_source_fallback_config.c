#include <cdisasm/cdisasm.h>

#if CDISASM_CONFIG_USE_ARCH_X86 != 1
#  error "The source-tree fallback must enable x86"
#endif

#if CDISASM_CONFIG_USE_ARCH_ARM != 1
#  error "The source-tree fallback must enable ARM"
#endif

#if CDISASM_CONFIG_USE_DISASM_FORMAT != 1
#  error "The source-tree fallback must enable formatting"
#endif

#if CDISASM_CONFIG_USE_EXTRA_OPCODES != 1
#  error "The source-tree fallback must enable extra opcodes"
#endif

#if USE_ARCH_X86 != 1 || USE_ARCH_ARM != 1 \
        || USE_DISASM_FORMAT != 1 || USE_EXTRA_OPCODES != 1
#  error "The public fallback feature macros must all be numeric one"
#endif

_Static_assert(sizeof(cdisasm_x86_name_id) == sizeof(uint16_t),
    "The fallback umbrella must expose x86 IDs");
_Static_assert(sizeof(cdisasm_arm_name_id) == sizeof(uint16_t),
    "The fallback umbrella must expose ARM IDs");
_Static_assert(CDISASM_X86_NAME_NOP != CDISASM_X86_NAME_NONE,
    "The fallback umbrella must expose x86 names");
_Static_assert(CDISASM_ARM_NAME_NOP != CDISASM_ARM_NAME_NONE,
    "The fallback umbrella must expose ARM names");
