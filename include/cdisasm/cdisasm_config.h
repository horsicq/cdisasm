#ifndef CDISASM_CDISASM_CONFIG_H
#define CDISASM_CDISASM_CONFIG_H

#define CDISASM_CONFIG_USE_ARCH_X86 1
#define CDISASM_CONFIG_USE_ARCH_ARM 1
#define CDISASM_CONFIG_USE_DISASM_FORMAT \
    (CDISASM_CONFIG_USE_ARCH_X86 || CDISASM_CONFIG_USE_ARCH_ARM)
#define CDISASM_CONFIG_USE_EXTRA_OPCODES \
    (CDISASM_CONFIG_USE_ARCH_X86 || CDISASM_CONFIG_USE_ARCH_ARM)

#if defined(USE_ARCH_X86)
#  if USE_ARCH_X86 != CDISASM_CONFIG_USE_ARCH_X86
#    error "USE_ARCH_X86 conflicts with the configured cdisasm library"
#  endif
#else
#  define USE_ARCH_X86 CDISASM_CONFIG_USE_ARCH_X86
#endif

#if defined(USE_ARCH_ARM)
#  if USE_ARCH_ARM != CDISASM_CONFIG_USE_ARCH_ARM
#    error "USE_ARCH_ARM conflicts with the configured cdisasm library"
#  endif
#else
#  define USE_ARCH_ARM CDISASM_CONFIG_USE_ARCH_ARM
#endif

#if defined(USE_DISASM_FORMAT)
#  if USE_DISASM_FORMAT != CDISASM_CONFIG_USE_DISASM_FORMAT
#    error "USE_DISASM_FORMAT conflicts with the configured cdisasm library"
#  endif
#else
#  define USE_DISASM_FORMAT CDISASM_CONFIG_USE_DISASM_FORMAT
#endif

#if defined(USE_EXTRA_OPCODES)
#  if USE_EXTRA_OPCODES != CDISASM_CONFIG_USE_EXTRA_OPCODES
#    error "USE_EXTRA_OPCODES conflicts with the configured cdisasm library"
#  endif
#else
#  define USE_EXTRA_OPCODES CDISASM_CONFIG_USE_EXTRA_OPCODES
#endif

#endif
