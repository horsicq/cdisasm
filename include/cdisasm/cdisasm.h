#ifndef CDISASM_CDISASM_H
#define CDISASM_CDISASM_H

/* Umbrella for the common API and every decoder enabled in this build. New
 * code may include the specific architecture header it uses instead. */
#include "cdisasm_common.h"

#if USE_ARCH_X86
#  include "cdisasm_x86.h"
#endif

#if USE_ARCH_ARM
#  include "cdisasm_arm.h"
#endif

#endif
