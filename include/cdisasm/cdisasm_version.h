#ifndef CDISASM_CDISASM_VERSION_H
#define CDISASM_CDISASM_VERSION_H

/*
 * This header is the single authoritative source for the cdisasm version.
 * CMake reads these three numeric definitions when configuring the project;
 * keep their simple decimal form so both C and CMake can consume them.
 */
#define CDISASM_VERSION_MAJOR 12
#define CDISASM_VERSION_MINOR 0
#define CDISASM_VERSION_PATCH 0

#define CDISASM_VERSION_STRINGIFY_DETAIL(value) #value
#define CDISASM_VERSION_STRINGIFY(value) \
    CDISASM_VERSION_STRINGIFY_DETAIL(value)
#define CDISASM_VERSION_STRING \
    CDISASM_VERSION_STRINGIFY(CDISASM_VERSION_MAJOR) "." \
    CDISASM_VERSION_STRINGIFY(CDISASM_VERSION_MINOR) "." \
    CDISASM_VERSION_STRINGIFY(CDISASM_VERSION_PATCH)

#endif
