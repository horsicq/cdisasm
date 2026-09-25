#ifndef CDISASM_TESTS_X86_TEST_FLAGS_H
#define CDISASM_TESTS_X86_TEST_FLAGS_H

/* The older broad decoder suites intentionally exercise every compiled x86
 * family.  Focused option-policy tests use exact masks in test_x86_flags.c. */
#if USE_EXTRA_OPCODES
#  define CDISASM_X86_TEST_ALL_FLAGS CDISASM_X86_DECODE_FLAG_ALL
#else
#  define CDISASM_X86_TEST_ALL_FLAGS CDISASM_X86_DECODE_FLAG_BASE
#endif

#endif
