cmake_minimum_required(VERSION 3.16)

project(cdisasm_package_consumer LANGUAGES C CXX)

include(CTest)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_CXX_EXTENSIONS NO)

set(
    CDISASM_PACKAGE_COMPONENTS
    "common"
    CACHE STRING
    "cdisasm components that this package-consumer configuration requires")
set(
    CDISASM_PACKAGE_EXPECT_VERSION
    ""
    CACHE STRING
    "Exact cdisasm package version required by this consumer")

option(
    CDISASM_PACKAGE_EXPECT_SHARED
    "Expect the installed cdisasm core target to be a shared library"
    ON)
option(
    CDISASM_PACKAGE_EXPECT_X86
    "Expect the cdisasm package to provide the x86 decoder"
    ON)
option(
    CDISASM_PACKAGE_EXPECT_ARM
    "Expect the cdisasm package to provide the ARM decoder"
    ON)
option(
    CDISASM_PACKAGE_EXPECT_FORMAT
    "Expect the cdisasm package to provide effective formatter support"
    ON)
option(
    CDISASM_PACKAGE_EXPECT_REQUESTED_EXTRA
    "Expect the cdisasm package to report extra opcodes requested"
    ON)
option(
    CDISASM_PACKAGE_EXPECT_EXTRA
    "Expect the cdisasm package to provide effective extra-opcode support"
    ON)

if(NOT CDISASM_PACKAGE_EXPECT_VERSION MATCHES
        "^([0-9]+)\\.([0-9]+)\\.([0-9]+)$")
    message(FATAL_ERROR
        "CDISASM_PACKAGE_EXPECT_VERSION must be a complete numeric version")
endif()
set(_cdisasm_expected_major "${CMAKE_MATCH_1}")
if(_cdisasm_expected_major GREATER 0)
    math(EXPR _cdisasm_incompatible_major "${_cdisasm_expected_major} - 1")
    set(_cdisasm_expected_package_dir "${cdisasm_DIR}")
    find_package(cdisasm ${_cdisasm_incompatible_major}.0 CONFIG QUIET)
    if(cdisasm_FOUND)
        message(FATAL_ERROR
            "cdisasm ${CDISASM_PACKAGE_EXPECT_VERSION} incorrectly accepted "
            "incompatible major ${_cdisasm_incompatible_major}")
    endif()
    set(
        cdisasm_DIR
        "${_cdisasm_expected_package_dir}"
        CACHE PATH
        "Directory containing cdisasmConfig.cmake"
        FORCE)
    unset(cdisasm_FOUND)
endif()

find_package(
    cdisasm ${CDISASM_PACKAGE_EXPECT_VERSION} EXACT CONFIG REQUIRED
    COMPONENTS ${CDISASM_PACKAGE_COMPONENTS})
if(NOT cdisasm_VERSION VERSION_EQUAL CDISASM_PACKAGE_EXPECT_VERSION)
    message(FATAL_ERROR
        "cdisasm package version '${cdisasm_VERSION}' does not equal expected "
        "'${CDISASM_PACKAGE_EXPECT_VERSION}'")
endif()

if(NOT TARGET cdisasm::cdisasm)
    message(FATAL_ERROR "cdisasm package does not export its common target")
endif()

if(NOT DEFINED cdisasm_USE_ARCH_X86
        OR NOT DEFINED cdisasm_USE_ARCH_ARM
        OR NOT DEFINED cdisasm_REQUESTED_USE_DISASM_FORMAT
        OR NOT DEFINED cdisasm_USE_DISASM_FORMAT
        OR NOT DEFINED cdisasm_REQUESTED_USE_EXTRA_OPCODES
        OR NOT DEFINED cdisasm_USE_EXTRA_OPCODES
        OR NOT DEFINED cdisasm_BUILD_SHARED_LIBS)
    message(FATAL_ERROR
        "cdisasm package does not report all compiled features")
endif()

foreach(_cdisasm_reported_boolean IN ITEMS
        cdisasm_USE_ARCH_X86
        cdisasm_USE_ARCH_ARM
        cdisasm_REQUESTED_USE_DISASM_FORMAT
        cdisasm_USE_DISASM_FORMAT
        cdisasm_REQUESTED_USE_EXTRA_OPCODES
        cdisasm_USE_EXTRA_OPCODES
        cdisasm_BUILD_SHARED_LIBS)
    if(NOT "${${_cdisasm_reported_boolean}}" STREQUAL "ON"
            AND NOT "${${_cdisasm_reported_boolean}}" STREQUAL "OFF")
        message(FATAL_ERROR
            "${_cdisasm_reported_boolean} is not canonical ON/OFF package metadata: "
            "'${${_cdisasm_reported_boolean}}'")
    endif()
endforeach()

# A consumer must not be able to override the ABI-affecting public option.
# Compile a separate external translation unit with the opposite value and
# require both rejection and the focused diagnostic from cdisasm_config.h.
if(cdisasm_USE_EXTRA_OPCODES)
    set(_cdisasm_conflicting_extra_value 0)
else()
    set(_cdisasm_conflicting_extra_value 1)
endif()
try_compile(
    _cdisasm_conflicting_extra_accepted
    "${CMAKE_CURRENT_BINARY_DIR}/extra-option-conflict"
    "${CMAKE_CURRENT_SOURCE_DIR}/extra_option_conflict.c"
    CMAKE_FLAGS
        -DCMAKE_C_STANDARD:STRING=11
        -DCMAKE_C_STANDARD_REQUIRED:BOOL=ON
        -DCMAKE_C_EXTENSIONS:BOOL=OFF
    COMPILE_DEFINITIONS
        "-DUSE_EXTRA_OPCODES=${_cdisasm_conflicting_extra_value}"
    LINK_LIBRARIES cdisasm::cdisasm
    OUTPUT_VARIABLE _cdisasm_conflicting_extra_log)
if(_cdisasm_conflicting_extra_accepted)
    message(FATAL_ERROR
        "An external consumer compiled with a conflicting USE_EXTRA_OPCODES value")
endif()
if(NOT _cdisasm_conflicting_extra_log MATCHES
        "USE_EXTRA_OPCODES conflicts with the configured cdisasm library")
    message(FATAL_ERROR
        "The conflicting USE_EXTRA_OPCODES probe failed without the public "
        "configuration diagnostic.\n${_cdisasm_conflicting_extra_log}")
endif()

if(CDISASM_PACKAGE_EXPECT_REQUESTED_EXTRA)
    if(NOT cdisasm_REQUESTED_USE_EXTRA_OPCODES)
        message(FATAL_ERROR
            "cdisasm package reports extra opcodes not requested; the consumer expected them requested")
    endif()
elseif(cdisasm_REQUESTED_USE_EXTRA_OPCODES)
    message(FATAL_ERROR
        "cdisasm package reports extra opcodes requested; the consumer expected them not requested")
endif()

if(CDISASM_PACKAGE_EXPECT_EXTRA)
    set(_cdisasm_package_use_extra 1)
    if(NOT cdisasm_USE_EXTRA_OPCODES)
        message(FATAL_ERROR
            "cdisasm package reports extra opcodes disabled; the consumer expected them enabled")
    endif()
else()
    set(_cdisasm_package_use_extra 0)
    if(cdisasm_USE_EXTRA_OPCODES)
        message(FATAL_ERROR
            "cdisasm package reports extra opcodes enabled; the consumer expected them disabled")
    endif()
endif()

if(CDISASM_PACKAGE_EXPECT_X86)
    set(_cdisasm_package_use_x86 1)
    if(NOT cdisasm_USE_ARCH_X86)
        message(FATAL_ERROR
            "cdisasm package reports x86 disabled; the consumer expected it enabled")
    endif()
else()
    set(_cdisasm_package_use_x86 0)
    if(cdisasm_USE_ARCH_X86)
        message(FATAL_ERROR
            "cdisasm package reports x86 enabled; the consumer expected it disabled")
    endif()
endif()

if(CDISASM_PACKAGE_EXPECT_ARM)
    set(_cdisasm_package_use_arm 1)
    if(NOT cdisasm_USE_ARCH_ARM)
        message(FATAL_ERROR
            "cdisasm package reports ARM disabled; the consumer expected it enabled")
    endif()
else()
    set(_cdisasm_package_use_arm 0)
    if(cdisasm_USE_ARCH_ARM)
        message(FATAL_ERROR
            "cdisasm package reports ARM enabled; the consumer expected it disabled")
    endif()
endif()

if(CDISASM_PACKAGE_EXPECT_FORMAT)
    set(_cdisasm_package_use_format 1)
    if(NOT cdisasm_USE_DISASM_FORMAT)
        message(FATAL_ERROR
            "cdisasm package reports formatting disabled; the consumer expected it enabled")
    endif()
else()
    set(_cdisasm_package_use_format 0)
    if(cdisasm_USE_DISASM_FORMAT)
        message(FATAL_ERROR
            "cdisasm package reports formatting enabled; the consumer expected it disabled")
    endif()
endif()

# The formatter header is a stable public include in every package variant.
# Its own diagnostic must make a direct include compile exactly when effective
# formatter support is available.
include(CheckCXXSourceCompiles)
set(_cdisasm_saved_required_libraries "${CMAKE_REQUIRED_LIBRARIES}")
set(CMAKE_REQUIRED_LIBRARIES cdisasm::cdisasm)
unset(_cdisasm_format_header_discoverable CACHE)
check_cxx_source_compiles(
    "#if !defined(__has_include)\n#  error \"C++17 compiler does not provide __has_include\"\n#endif\n#if !__has_include(<cdisasm/cdisasm_format.h>)\n#  error \"cdisasm_format.h is not discoverable\"\n#endif\nint main() { return 0; }"
    _cdisasm_format_header_discoverable)
if(NOT _cdisasm_format_header_discoverable)
    message(FATAL_ERROR
        "cdisasm_format.h is not discoverable through the package target")
endif()

unset(_cdisasm_format_header_direct_include CACHE)
check_cxx_source_compiles(
    "#include <cdisasm/cdisasm_format.h>\nint main() {\n#if USE_ARCH_X86\n    auto formatter = &cdisasm_x86_format;\n#elif USE_ARCH_ARM\n    auto formatter = &cdisasm_arm_format;\n#endif\n#if USE_ARCH_X86 || USE_ARCH_ARM\n    (void)formatter;\n#endif\n    return 0;\n}"
    _cdisasm_format_header_direct_include)
if(CDISASM_PACKAGE_EXPECT_FORMAT)
    if(NOT _cdisasm_format_header_direct_include)
        message(FATAL_ERROR
            "cdisasm_format.h does not compile with effective formatting enabled")
    endif()
elseif(_cdisasm_format_header_direct_include)
    message(FATAL_ERROR
        "cdisasm_format.h compiles even though effective formatting is disabled")
endif()
set(CMAKE_REQUIRED_LIBRARIES "${_cdisasm_saved_required_libraries}")
unset(_cdisasm_saved_required_libraries)

get_target_property(_cdisasm_facade_type cdisasm::cdisasm TYPE)
if(CDISASM_PACKAGE_EXPECT_SHARED)
    set(_cdisasm_expected_facade_type SHARED_LIBRARY)
    set(_cdisasm_package_expect_shared 1)
    if(NOT cdisasm_BUILD_SHARED_LIBS)
        message(FATAL_ERROR
            "cdisasm package reports a static build; a shared build was expected")
    endif()
else()
    set(_cdisasm_expected_facade_type STATIC_LIBRARY)
    set(_cdisasm_package_expect_shared 0)
    if(cdisasm_BUILD_SHARED_LIBS)
        message(FATAL_ERROR
            "cdisasm package reports a shared build; a static build was expected")
    endif()
endif()
if(NOT "${_cdisasm_facade_type}" STREQUAL
        "${_cdisasm_expected_facade_type}")
    message(FATAL_ERROR
        "cdisasm facade target type is ${_cdisasm_facade_type}; expected ${_cdisasm_expected_facade_type}")
endif()

# A static package must propagate CDISASM_STATIC through its core target so
# consumers do not select dllimport declarations. A shared package must not
# leak that definition.
get_target_property(
    _cdisasm_interface_definitions
    cdisasm::cdisasm
    INTERFACE_COMPILE_DEFINITIONS)
if(_cdisasm_interface_definitions)
    list(FIND
        _cdisasm_interface_definitions
        CDISASM_STATIC
        _cdisasm_static_definition_index)
else()
    set(_cdisasm_static_definition_index -1)
endif()
if(CDISASM_PACKAGE_EXPECT_SHARED
        AND NOT _cdisasm_static_definition_index EQUAL -1)
    message(FATAL_ERROR
        "shared cdisasm target unexpectedly propagates CDISASM_STATIC")
elseif(NOT CDISASM_PACKAGE_EXPECT_SHARED
        AND _cdisasm_static_definition_index EQUAL -1)
    message(FATAL_ERROR
        "static cdisasm target does not propagate CDISASM_STATIC")
endif()

# Version 9 folds every enabled decoder and formatter into the core library.
# Compatibility target spellings may be aliases to the facade or interface
# proxies, but must never identify another physical library.
function(cdisasm_check_compatibility_target target_name)
    if(NOT TARGET "${target_name}")
        message(FATAL_ERROR
            "enabled cdisasm package omits ${target_name}")
    endif()

    get_target_property(_cdisasm_aliased_target
        "${target_name}" ALIASED_TARGET)
    if(_cdisasm_aliased_target)
        if(NOT _cdisasm_aliased_target STREQUAL "cdisasm::cdisasm")
            message(FATAL_ERROR
                "${target_name} aliases ${_cdisasm_aliased_target}, not the facade")
        endif()
    else()
        get_target_property(_cdisasm_compatibility_type
            "${target_name}" TYPE)
        if(NOT _cdisasm_compatibility_type STREQUAL "INTERFACE_LIBRARY")
            message(FATAL_ERROR
                "${target_name} names a physical decoder library")
        endif()
        get_target_property(_cdisasm_compatibility_links
            "${target_name}" INTERFACE_LINK_LIBRARIES)
        if(NOT _cdisasm_compatibility_links STREQUAL "cdisasm::cdisasm")
            message(FATAL_ERROR
                "${target_name} does not point exclusively to cdisasm::cdisasm")
        endif()
    endif()
endfunction()

if(cdisasm_USE_ARCH_X86)
    cdisasm_check_compatibility_target(cdisasm::cdisasm_x86)
else()
    if(TARGET cdisasm::cdisasm_x86)
        message(FATAL_ERROR
            "x86-disabled package exposes an x86 compatibility target")
    endif()
endif()

if(cdisasm_USE_ARCH_ARM)
    cdisasm_check_compatibility_target(cdisasm::cdisasm_arm)
elseif(TARGET cdisasm::cdisasm_arm)
    message(FATAL_ERROR
        "ARM-disabled package exposes an ARM compatibility target")
endif()

if(cdisasm_USE_DISASM_FORMAT
        AND (cdisasm_USE_ARCH_X86 OR cdisasm_USE_ARCH_ARM))
    if(NOT TARGET cdisasm::cdisasm_format)
        message(FATAL_ERROR
            "formatter-enabled package omits its compatibility target")
    endif()

    get_target_property(
        _cdisasm_format_type cdisasm::cdisasm_format TYPE)
    if(NOT _cdisasm_format_type STREQUAL "INTERFACE_LIBRARY")
        message(FATAL_ERROR
            "cdisasm formatter compatibility target is not an interface library")
    endif()

    get_target_property(
        _cdisasm_format_links
        cdisasm::cdisasm_format
        INTERFACE_LINK_LIBRARIES)
    if(NOT _cdisasm_format_links STREQUAL "cdisasm::cdisasm")
        message(FATAL_ERROR
            "cdisasm formatter compatibility target does not point exclusively to cdisasm::cdisasm")
    endif()
elseif(TARGET cdisasm::cdisasm_format)
    message(FATAL_ERROR
        "formatter-disabled package unexpectedly exports a formatter target")
endif()

add_executable(cdisasm_package_smoke main.c)
target_compile_features(cdisasm_package_smoke PRIVATE c_std_11)
target_link_libraries(
    cdisasm_package_smoke
    PRIVATE cdisasm::cdisasm)

# Compile the public numeric ABI guards separately so an installed package
# cannot silently omit or renumber append-only IDs even when the runtime smoke
# path does not happen to use them.
add_executable(cdisasm_package_id_smoke smoke.c)
target_compile_features(cdisasm_package_id_smoke PRIVATE c_std_11)
target_link_libraries(
    cdisasm_package_id_smoke
    PRIVATE cdisasm::cdisasm)

# Exercise the architecture-group dispatcher through only the facade library.
add_executable(cdisasm_package_dispatch_smoke dispatch.c)
target_compile_features(cdisasm_package_dispatch_smoke PRIVATE c_std_11)
target_link_libraries(
    cdisasm_package_dispatch_smoke
    PRIVATE cdisasm::cdisasm)

# Explicit architecture APIs must also be owned by the facade. Do not link the
# formatter or either optional compatibility target into this executable.
add_executable(cdisasm_package_explicit_smoke explicit.c)
target_compile_features(cdisasm_package_explicit_smoke PRIVATE c_std_11)
target_link_libraries(
    cdisasm_package_explicit_smoke
    PRIVATE cdisasm::cdisasm)

add_executable(cdisasm_package_cpp_core_smoke cpp_smoke.cpp)
target_compile_features(cdisasm_package_cpp_core_smoke PRIVATE cxx_std_17)
target_compile_definitions(
    cdisasm_package_cpp_core_smoke
    PRIVATE CDISASM_PACKAGE_CPP_SCOPE_CORE=1)
target_link_libraries(
    cdisasm_package_cpp_core_smoke
    PRIVATE cdisasm::cdisasm)

set(
    _cdisasm_package_targets
        cdisasm_package_smoke
        cdisasm_package_id_smoke
        cdisasm_package_dispatch_smoke
        cdisasm_package_explicit_smoke
        cdisasm_package_cpp_core_smoke)

# Each compatibility consumer names only its proxy target. Besides exercising
# the proxy's runtime API, the C++ compile checks prove that usage requirements
# such as CDISASM_STATIC reach consumers transitively through that proxy.
if(cdisasm_USE_ARCH_X86)
    add_executable(cdisasm_package_cpp_x86_proxy_smoke cpp_smoke.cpp)
    target_compile_features(
        cdisasm_package_cpp_x86_proxy_smoke PRIVATE cxx_std_17)
    target_compile_definitions(
        cdisasm_package_cpp_x86_proxy_smoke
        PRIVATE CDISASM_PACKAGE_CPP_SCOPE_X86=1)
    target_link_libraries(
        cdisasm_package_cpp_x86_proxy_smoke
        PRIVATE cdisasm::cdisasm_x86)
    list(APPEND
        _cdisasm_package_targets
        cdisasm_package_cpp_x86_proxy_smoke)
endif()

if(cdisasm_USE_ARCH_ARM)
    add_executable(cdisasm_package_cpp_arm_proxy_smoke cpp_smoke.cpp)
    target_compile_features(
        cdisasm_package_cpp_arm_proxy_smoke PRIVATE cxx_std_17)
    target_compile_definitions(
        cdisasm_package_cpp_arm_proxy_smoke
        PRIVATE CDISASM_PACKAGE_CPP_SCOPE_ARM=1)
    target_link_libraries(
        cdisasm_package_cpp_arm_proxy_smoke
        PRIVATE cdisasm::cdisasm_arm)
    list(APPEND
        _cdisasm_package_targets
        cdisasm_package_cpp_arm_proxy_smoke)
endif()

if(cdisasm_USE_DISASM_FORMAT
        AND (cdisasm_USE_ARCH_X86 OR cdisasm_USE_ARCH_ARM))
    add_executable(cdisasm_package_cpp_format_proxy_smoke cpp_smoke.cpp)
    target_compile_features(
        cdisasm_package_cpp_format_proxy_smoke PRIVATE cxx_std_17)
    target_compile_definitions(
        cdisasm_package_cpp_format_proxy_smoke
        PRIVATE CDISASM_PACKAGE_CPP_SCOPE_FORMAT=1)
    target_link_libraries(
        cdisasm_package_cpp_format_proxy_smoke
        PRIVATE cdisasm::cdisasm_format)
    list(APPEND
        _cdisasm_package_targets
        cdisasm_package_cpp_format_proxy_smoke)
endif()

function(cdisasm_add_package_runtime_test target_name)
    if(cdisasm_BUILD_SHARED_LIBS)
        if(WIN32)
            add_test(
                NAME "${target_name}"
                COMMAND
                    "${CMAKE_COMMAND}" -E env
                    "PATH=$<TARGET_FILE_DIR:cdisasm::cdisasm>;$ENV{PATH}"
                    "$<TARGET_FILE:${target_name}>")
        elseif(APPLE)
            add_test(
                NAME "${target_name}"
                COMMAND
                    "${CMAKE_COMMAND}" -E env
                    "DYLD_LIBRARY_PATH=$<TARGET_FILE_DIR:cdisasm::cdisasm>:$ENV{DYLD_LIBRARY_PATH}"
                    "$<TARGET_FILE:${target_name}>")
        elseif(UNIX)
            add_test(
                NAME "${target_name}"
                COMMAND
                    "${CMAKE_COMMAND}" -E env
                    "LD_LIBRARY_PATH=$<TARGET_FILE_DIR:cdisasm::cdisasm>:$ENV{LD_LIBRARY_PATH}"
                    "$<TARGET_FILE:${target_name}>")
        else()
            add_test(
                NAME "${target_name}"
                COMMAND "$<TARGET_FILE:${target_name}>")
        endif()
    else()
        add_test(
            NAME "${target_name}"
            COMMAND "$<TARGET_FILE:${target_name}>")
    endif()

    set_tests_properties(
        "${target_name}"
        PROPERTIES
            LABELS "package;install"
            TIMEOUT 30)
endfunction()

foreach(_cdisasm_package_target IN LISTS _cdisasm_package_targets)
    target_compile_definitions(
        ${_cdisasm_package_target}
        PRIVATE
            CDISASM_PACKAGE_EXPECT_X86=${_cdisasm_package_use_x86}
            CDISASM_PACKAGE_EXPECT_ARM=${_cdisasm_package_use_arm}
            CDISASM_PACKAGE_EXPECT_FORMAT=${_cdisasm_package_use_format}
            CDISASM_PACKAGE_EXPECT_EXTRA=${_cdisasm_package_use_extra}
            CDISASM_PACKAGE_EXPECT_SHARED=${_cdisasm_package_expect_shared})

    if(BUILD_TESTING)
        cdisasm_add_package_runtime_test("${_cdisasm_package_target}")
    endif()
endforeach()
