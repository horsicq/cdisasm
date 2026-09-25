cmake_minimum_required(VERSION 3.16)

set(_cdisasm_version_header
    "${CMAKE_CURRENT_SOURCE_DIR}/include/cdisasm/cdisasm_version.h")
foreach(_cdisasm_version_part IN ITEMS MAJOR MINOR PATCH)
    file(STRINGS
        "${_cdisasm_version_header}"
        _cdisasm_version_line
        REGEX
            "^#define CDISASM_VERSION_${_cdisasm_version_part} [0-9]+$")
    if(NOT _cdisasm_version_line)
        message(FATAL_ERROR
            "Missing numeric CDISASM_VERSION_${_cdisasm_version_part} in "
            "${_cdisasm_version_header}")
    endif()
    string(REGEX REPLACE
        "^#define CDISASM_VERSION_${_cdisasm_version_part} ([0-9]+)$"
        "\\1"
        CDISASM_VERSION_${_cdisasm_version_part}
        "${_cdisasm_version_line}")
endforeach()
set(_cdisasm_project_version
    "${CDISASM_VERSION_MAJOR}.${CDISASM_VERSION_MINOR}.${CDISASM_VERSION_PATCH}")

project(
    cdisasm
    VERSION "${_cdisasm_project_version}"
    DESCRIPTION "Standalone structured disassembler library in C"
    LANGUAGES C)

foreach(_cdisasm_version_part IN ITEMS MAJOR MINOR PATCH)
    if(PROJECT_VERSION_${_cdisasm_version_part} GREATER 255)
        message(FATAL_ERROR
            "cdisasm version components must fit the packed 8-bit runtime "
            "version: ${PROJECT_VERSION}")
    endif()
endforeach()

unset(_cdisasm_project_version)
unset(_cdisasm_version_header)
unset(_cdisasm_version_line)
unset(_cdisasm_version_part)

include(CTest)
include(GNUInstallDirs)

set(_cdisasm_is_top_level OFF)
if("${CMAKE_CURRENT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    set(_cdisasm_is_top_level ON)
endif()

if(_cdisasm_is_top_level)
    option(BUILD_SHARED_LIBS "Build cdisasm as a shared library" ON)
    set(CDISASM_BUILD_SHARED_LIBS "${BUILD_SHARED_LIBS}")
else()
    set(_cdisasm_shared_default ON)
    if(DEFINED BUILD_SHARED_LIBS)
        set(_cdisasm_shared_default "${BUILD_SHARED_LIBS}")
    endif()
    option(
        CDISASM_BUILD_SHARED_LIBS
        "Build the embedded cdisasm target as a shared library"
        "${_cdisasm_shared_default}")
    unset(_cdisasm_shared_default)
endif()

option(USE_ARCH_X86 "Build the x86 decoder" ON)
option(USE_ARCH_ARM "Build the ARM decoder" ON)
option(USE_DISASM_FORMAT "Build instruction formatting into cdisasm" ON)
option(USE_EXTRA_OPCODES "Build extended opcode coverage into cdisasm" ON)
option(CDISASM_BUILD_EXAMPLES "Build the cdisasm command-line example" ON)
option(CDISASM_BUILD_FUZZERS "Build the Clang libFuzzer harness" OFF)

set(_cdisasm_verify_generated_default OFF)
if(_cdisasm_is_top_level AND BUILD_TESTING)
    set(_cdisasm_verify_generated_default ON)
endif()
option(
    CDISASM_VERIFY_GENERATED
    "Verify checked-in generated-source invariants while building and testing"
    ${_cdisasm_verify_generated_default})
unset(_cdisasm_verify_generated_default)
set(
    CDISASM_ARM_AARCHMRS_ROOT
    ""
    CACHE PATH
    "Pinned AARCHMRS checkout used by the optional full ARM freshness check")
set(
    CDISASM_XED_DEC
    ""
    CACHE FILEPATH
    "Pinned xed-dec executable used by the optional exact x86 witness check")
set(
    CDISASM_XED
    ""
    CACHE FILEPATH
    "Pinned xed executable used by the optional exact x86 formatter check")
if(NOT "${CDISASM_XED_DEC}" STREQUAL ""
        AND NOT EXISTS "${CDISASM_XED_DEC}")
    message(FATAL_ERROR
        "CDISASM_XED_DEC was set but does not exist: ${CDISASM_XED_DEC}")
endif()
if(NOT "${CDISASM_XED}" STREQUAL ""
        AND NOT EXISTS "${CDISASM_XED}")
    message(FATAL_ERROR
        "CDISASM_XED was set but does not exist: ${CDISASM_XED}")
endif()

if(CDISASM_VERIFY_GENERATED)
    find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
endif()

# Cache BOOL entries preserve the spelling supplied by a caller (for example,
# TRUE or 1).  Public package metadata and the install-variant fingerprint must
# not treat those equivalent spellings as different ABIs, so serialize every
# requested feature and the physical linkage through canonical ON/OFF values.
foreach(_cdisasm_boolean IN ITEMS
        USE_ARCH_X86
        USE_ARCH_ARM
        USE_DISASM_FORMAT
        USE_EXTRA_OPCODES
        CDISASM_BUILD_SHARED_LIBS)
    if(${_cdisasm_boolean})
        set(CDISASM_NORMALIZED_${_cdisasm_boolean} ON)
    else()
        set(CDISASM_NORMALIZED_${_cdisasm_boolean} OFF)
    endif()
endforeach()
unset(_cdisasm_boolean)

set(CDISASM_EFFECTIVE_USE_DISASM_FORMAT OFF)
if(CDISASM_NORMALIZED_USE_DISASM_FORMAT
        AND (CDISASM_NORMALIZED_USE_ARCH_X86
            OR CDISASM_NORMALIZED_USE_ARCH_ARM))
    set(CDISASM_EFFECTIVE_USE_DISASM_FORMAT ON)
endif()

set(CDISASM_EFFECTIVE_USE_EXTRA_OPCODES OFF)
if(CDISASM_NORMALIZED_USE_EXTRA_OPCODES
        AND (CDISASM_NORMALIZED_USE_ARCH_X86
            OR CDISASM_NORMALIZED_USE_ARCH_ARM))
    set(CDISASM_EFFECTIVE_USE_EXTRA_OPCODES ON)
endif()

set(_cdisasm_package_tests_default OFF)
if("${CMAKE_CURRENT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    set(_cdisasm_package_tests_default ON)
endif()
option(
    CDISASM_BUILD_PACKAGE_TESTS
    "Run the isolated shared/static package feature matrix"
    ${_cdisasm_package_tests_default})
unset(_cdisasm_package_tests_default)

set(_cdisasm_generated_include_dir
    "${CMAKE_CURRENT_BINARY_DIR}/generated/include")
file(MAKE_DIRECTORY "${_cdisasm_generated_include_dir}/cdisasm")
set(CDISASM_CONFIG_USE_ARCH_X86 ${CDISASM_NORMALIZED_USE_ARCH_X86})
set(CDISASM_CONFIG_USE_ARCH_ARM ${CDISASM_NORMALIZED_USE_ARCH_ARM})
set(CDISASM_CONFIG_USE_DISASM_FORMAT
    ${CDISASM_EFFECTIVE_USE_DISASM_FORMAT})
set(CDISASM_CONFIG_USE_EXTRA_OPCODES
    ${CDISASM_EFFECTIVE_USE_EXTRA_OPCODES})
configure_file(
    cmake/cdisasm_config.h.in
    "${_cdisasm_generated_include_dir}/cdisasm/cdisasm_config.h")
unset(CDISASM_CONFIG_USE_ARCH_X86)
unset(CDISASM_CONFIG_USE_ARCH_ARM)
unset(CDISASM_CONFIG_USE_DISASM_FORMAT)
unset(CDISASM_CONFIG_USE_EXTRA_OPCODES)

set(
    CDISASM_FUZZ_SANITIZERS
    "address,undefined"
    CACHE STRING
    "Additional sanitizers for fuzz targets (comma-separated, or empty)")

function(cdisasm_configure_library target)
    target_compile_features(${target} PRIVATE c_std_11)
    if(CDISASM_BUILD_SHARED_LIBS)
        target_compile_definitions(${target} PRIVATE CDISASM_BUILDING_LIBRARY)
    else()
        # This must be public: installed CMake consumers on Windows must select
        # normal declarations rather than __declspec(dllimport).
        target_compile_definitions(${target} PUBLIC CDISASM_STATIC)
    endif()
    target_include_directories(
        ${target}
        PUBLIC
            "$<BUILD_INTERFACE:${_cdisasm_generated_include_dir}>"
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
            "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

    set_target_properties(
        ${target}
        PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED YES
            C_EXTENSIONS NO
            C_VISIBILITY_PRESET hidden)

    if(CDISASM_BUILD_SHARED_LIBS)
        set_target_properties(
            ${target}
            PROPERTIES
                VERSION "${PROJECT_VERSION}"
                SOVERSION "${PROJECT_VERSION_MAJOR}"
                WINDOWS_EXPORT_ALL_SYMBOLS OFF)
    endif()

    if(MSVC)
        target_compile_options(${target} PRIVATE /W4)
        target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endfunction()

set(
    _cdisasm_sources
    src/cdisasm.c
    src/cdisasm_cpu.c
    src/cdisasm_cpu_identify.c)
if(USE_ARCH_X86)
    list(APPEND
        _cdisasm_sources
        src/x86/cdisasm_x86.c
        src/x86/x86_decoder.c
        src/x86/x86_generated_decoder.c)
endif()
if(USE_ARCH_ARM)
    list(APPEND
        _cdisasm_sources
        src/arm/cdisasm_arm.c
        src/arm/arm_apple_decoder.c
        src/arm/arm_decoder.c
        src/arm/arm_generated_alias.c
        src/arm/arm_generated_decoder.c
        src/arm/arm_generated_operands.c
        src/arm/arm_modern_decoder.c
        src/arm/arm_t32_decoder.c)
endif()
if(CDISASM_EFFECTIVE_USE_DISASM_FORMAT)
    if(USE_ARCH_X86)
        list(APPEND _cdisasm_sources src/x86/cdisasm_format.c)
    endif()
    if(USE_ARCH_ARM)
        list(APPEND
            _cdisasm_sources
            src/arm/arm_generated_formatter.c
            src/arm/cdisasm_arm_format.c)
    endif()
endif()

if(CDISASM_BUILD_SHARED_LIBS)
    set(_cdisasm_library_type SHARED)
else()
    set(_cdisasm_library_type STATIC)
endif()
add_library(cdisasm ${_cdisasm_library_type} ${_cdisasm_sources})
unset(_cdisasm_library_type)
unset(_cdisasm_sources)
add_library(cdisasm::cdisasm ALIAS cdisasm)
cdisasm_configure_library(cdisasm)

if(CDISASM_VERIFY_GENERATED)
    add_custom_target(
        cdisasm_check_generated
        COMMAND
            "${Python3_EXECUTABLE}"
            -B
            "${CMAKE_CURRENT_SOURCE_DIR}/tools/isa_codegen/check_arm_recipe_opcodes.py"
            --quiet
        COMMENT "Checking generated ARM recipe-opcode synchronization"
        VERBATIM)
    add_custom_command(
        TARGET cdisasm_check_generated
        POST_BUILD
        COMMAND
            "${Python3_EXECUTABLE}"
            -B
            "${CMAKE_CURRENT_SOURCE_DIR}/tools/coverage/check_x86_coverage.py"
            --strict
            --quiet
        COMMENT "Auditing generated x86 fallback and coverage metadata"
        VERBATIM)
    add_dependencies(cdisasm cdisasm_check_generated)

    if(NOT "${CDISASM_ARM_AARCHMRS_ROOT}" STREQUAL "")
        add_custom_target(
            cdisasm_check_arm_catalog
            COMMAND
                "${Python3_EXECUTABLE}"
                -B
                "${CMAKE_CURRENT_SOURCE_DIR}/tools/isa_codegen/generate_arm_assembly_catalog.py"
                --arm-root "${CDISASM_ARM_AARCHMRS_ROOT}"
                --check
            COMMENT "Checking the complete generated ARM assembly catalog"
            VERBATIM)
        add_dependencies(
            cdisasm_check_arm_catalog
            cdisasm_check_generated)
    endif()
endif()

if(USE_ARCH_X86)
    # Compatibility target: x86 decoder symbols now live in cdisasm itself.
    add_library(cdisasm_x86 INTERFACE)
    add_library(cdisasm::cdisasm_x86 ALIAS cdisasm_x86)
    target_link_libraries(cdisasm_x86 INTERFACE cdisasm)
endif()

if(USE_ARCH_ARM)
    # Compatibility target: ARM decoder symbols now live in cdisasm itself.
    add_library(cdisasm_arm INTERFACE)
    add_library(cdisasm::cdisasm_arm ALIAS cdisasm_arm)
    target_link_libraries(cdisasm_arm INTERFACE cdisasm)
endif()

if(CDISASM_EFFECTIVE_USE_DISASM_FORMAT)
    # Compatibility target: formatter symbols now live in cdisasm itself.
    add_library(cdisasm_format INTERFACE)
    add_library(cdisasm::cdisasm_format ALIAS cdisasm_format)
    target_link_libraries(cdisasm_format INTERFACE cdisasm)
endif()

# Windows has no soname mechanism. Keep accidental cross-major DLL binding
# impossible for the single decoder/formatter runtime.
if(WIN32 AND CDISASM_BUILD_SHARED_LIBS)
    set_target_properties(
        cdisasm
        PROPERTIES RUNTIME_OUTPUT_NAME "cdisasm-${PROJECT_VERSION_MAJOR}")
endif()

if(BUILD_TESTING)
    if(CDISASM_VERIFY_GENERATED)
        add_test(
            NAME cdisasm_arm_recipe_opcode_checker_tests
            COMMAND
                "${Python3_EXECUTABLE}"
                -B
                "${CMAKE_CURRENT_SOURCE_DIR}/tools/isa_codegen/check_arm_recipe_opcodes.py"
                --self-test
                --quiet)
        add_test(
            NAME cdisasm_arm_recipe_opcode_freshness_tests
            COMMAND
                "${Python3_EXECUTABLE}"
                -B
                "${CMAKE_CURRENT_SOURCE_DIR}/tools/isa_codegen/check_arm_recipe_opcodes.py"
                --quiet)
        add_test(
            NAME cdisasm_x86_coverage_audit_tests
            COMMAND
                "${Python3_EXECUTABLE}"
                -B
                "${CMAKE_CURRENT_SOURCE_DIR}/tools/coverage/check_x86_coverage.py"
                --strict
                --quiet)
        add_test(
            NAME cdisasm_arm_assembly_audit_classes_tests
            COMMAND
                "${Python3_EXECUTABLE}"
                -B
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_arm_assembly_audit_classes.py")
        add_test(
            NAME cdisasm_arm_assembly_vorn_audit_tests
            COMMAND
                "${Python3_EXECUTABLE}"
                -B
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_arm_assembly_vorn_audit.py")
        set_tests_properties(
            cdisasm_arm_recipe_opcode_checker_tests
            cdisasm_arm_recipe_opcode_freshness_tests
            cdisasm_arm_assembly_audit_classes_tests
            cdisasm_arm_assembly_vorn_audit_tests
            cdisasm_x86_coverage_audit_tests
            PROPERTIES LABELS "codegen;generated")

        if(TARGET cdisasm_check_arm_catalog)
            add_test(
                NAME cdisasm_arm_catalog_freshness_tests
                COMMAND
                    "${Python3_EXECUTABLE}"
                    -B
                    "${CMAKE_CURRENT_SOURCE_DIR}/tools/isa_codegen/generate_arm_assembly_catalog.py"
                    --arm-root "${CDISASM_ARM_AARCHMRS_ROOT}"
                    --check)
            set_tests_properties(
                cdisasm_arm_catalog_freshness_tests
                PROPERTIES LABELS "codegen;generated")
        endif()
    endif()

    # Compile the checked-in source-tree fallback without linking cdisasm and
    # without exposing the generated build-tree configuration header. This
    # keeps manual builds and editor indexing aligned with the default tuple.
    add_library(
        cdisasm_source_fallback_config_probe
        OBJECT
        tests/test_source_fallback_config.c)
    target_compile_features(
        cdisasm_source_fallback_config_probe
        PRIVATE c_std_11)
    target_include_directories(
        cdisasm_source_fallback_config_probe
        PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")

    add_test(
        NAME cdisasm_subproject_linkage_tests
        COMMAND
            "${CMAKE_COMMAND}"
            "-DCDISASM_SOURCE_DIR:PATH=${CMAKE_CURRENT_SOURCE_DIR}"
            "-DCDISASM_BINARY_DIR:PATH=${CMAKE_CURRENT_BINARY_DIR}"
            -P
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/test_subproject_linkage.cmake")
    set_tests_properties(
        cdisasm_subproject_linkage_tests
        PROPERTIES LABELS "cmake;integration" TIMEOUT 300)

    if(CMAKE_CONFIGURATION_TYPES)
        set(_cdisasm_overlay_multi_config ON)
    else()
        set(_cdisasm_overlay_multi_config OFF)
    endif()
    set(_cdisasm_overlay_config "${CMAKE_BUILD_TYPE}")
    if(_cdisasm_overlay_config STREQUAL "")
        set(_cdisasm_overlay_config Release)
    endif()
    add_test(
        NAME cdisasm_variant_overlay_tests
        COMMAND
            "${CMAKE_COMMAND}"
            "-DCDISASM_SOURCE_DIR:PATH=${CMAKE_CURRENT_SOURCE_DIR}"
            "-DCDISASM_BINARY_DIR:PATH=${CMAKE_CURRENT_BINARY_DIR}"
            "-DCDISASM_OVERLAY_GENERATOR:STRING=${CMAKE_GENERATOR}"
            "-DCDISASM_OVERLAY_GENERATOR_PLATFORM:STRING=${CMAKE_GENERATOR_PLATFORM}"
            "-DCDISASM_OVERLAY_GENERATOR_TOOLSET:STRING=${CMAKE_GENERATOR_TOOLSET}"
            "-DCDISASM_OVERLAY_GENERATOR_INSTANCE:STRING=${CMAKE_GENERATOR_INSTANCE}"
            "-DCDISASM_OVERLAY_MAKE_PROGRAM:FILEPATH=${CMAKE_MAKE_PROGRAM}"
            "-DCDISASM_OVERLAY_C_COMPILER:FILEPATH=${CMAKE_C_COMPILER}"
            "-DCDISASM_OVERLAY_TOOLCHAIN_FILE:FILEPATH=${CMAKE_TOOLCHAIN_FILE}"
            "-DCDISASM_OVERLAY_MULTI_CONFIG:BOOL=${_cdisasm_overlay_multi_config}"
            "-DCDISASM_OVERLAY_CONFIG:STRING=${_cdisasm_overlay_config}"
            -P
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/test_variant_overlay.cmake")
    set_tests_properties(
        cdisasm_variant_overlay_tests
        PROPERTIES LABELS "cmake;install;integration" TIMEOUT 600)
    unset(_cdisasm_overlay_config)
    unset(_cdisasm_overlay_multi_config)

    add_executable(cdisasm_common_tests tests/test_common.c)
    target_compile_features(cdisasm_common_tests PRIVATE c_std_11)
    target_link_libraries(cdisasm_common_tests PRIVATE cdisasm)
    add_test(NAME cdisasm_common_tests COMMAND cdisasm_common_tests)

    add_executable(
        cdisasm_current_cpu_tests
        tests/test_current_cpu.c
        src/cdisasm_cpu_identify.c)
    target_compile_features(cdisasm_current_cpu_tests PRIVATE c_std_11)
    target_include_directories(
        cdisasm_current_cpu_tests
        PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(cdisasm_current_cpu_tests PRIVATE cdisasm)
    add_test(NAME cdisasm_current_cpu_tests COMMAND cdisasm_current_cpu_tests)
    set_tests_properties(
        cdisasm_current_cpu_tests
        PROPERTIES LABELS "cpu-detection")

    add_executable(cdisasm_decode_tests tests/test_decode.c)
    target_compile_features(cdisasm_decode_tests PRIVATE c_std_11)
    target_link_libraries(cdisasm_decode_tests PRIVATE cdisasm)
    add_test(NAME cdisasm_decode_tests COMMAND cdisasm_decode_tests)

    if(USE_ARCH_X86 OR USE_ARCH_ARM)
        add_test(
            NAME cdisasm_fuzz_corpus_seed_tests
            COMMAND
                "${CMAKE_COMMAND}"
                "-DCDISASM_SOURCE_DIR:PATH=${CMAKE_CURRENT_SOURCE_DIR}"
                "-DCDISASM_AUDIT_X86:BOOL=${USE_ARCH_X86}"
                "-DCDISASM_AUDIT_ARM:BOOL=${USE_ARCH_ARM}"
                -P
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/test_fuzz_corpus_seeds.cmake")
        set_tests_properties(
            cdisasm_fuzz_corpus_seed_tests
            PROPERTIES LABELS "corpus;fuzz")
    endif()

    if(USE_ARCH_X86 OR USE_ARCH_ARM)
        add_executable(
            cdisasm_extra_opcode_contract_tests
            tests/test_extra_opcode_contract.c)
        target_compile_features(
            cdisasm_extra_opcode_contract_tests
            PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_extra_opcode_contract_tests
            PRIVATE cdisasm)
        add_test(
            NAME cdisasm_extra_opcode_contract_tests
            COMMAND cdisasm_extra_opcode_contract_tests)
        set_tests_properties(
            cdisasm_extra_opcode_contract_tests
            PROPERTIES LABELS "abi;extra-opcodes")
    endif()

    if(USE_ARCH_X86)
        add_executable(cdisasm_x86_flag_tests tests/test_x86_flags.c)
        target_compile_features(cdisasm_x86_flag_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_x86_flag_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_x86_flag_tests COMMAND cdisasm_x86_flag_tests)
        set_tests_properties(
            cdisasm_x86_flag_tests
            PROPERTIES LABELS "abi;extra-opcodes;x86")

        if(CDISASM_EFFECTIVE_USE_EXTRA_OPCODES)
            add_executable(cdisasm_tests tests/test_x86.c)
            target_compile_features(cdisasm_tests PRIVATE c_std_11)
            target_link_libraries(cdisasm_tests PRIVATE cdisasm)
            add_test(NAME cdisasm_tests COMMAND cdisasm_tests)
        endif()

        add_executable(cdisasm_x86_modern_tests tests/test_x86_modern.c)
        target_compile_features(cdisasm_x86_modern_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_x86_modern_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_x86_modern_tests COMMAND cdisasm_x86_modern_tests)
        set_tests_properties(
            cdisasm_x86_modern_tests
            PROPERTIES LABELS "extra-opcodes;x86")

        add_executable(cdisasm_x86_cet_tests tests/test_x86_cet.c)
        target_compile_features(cdisasm_x86_cet_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_x86_cet_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_x86_cet_tests COMMAND cdisasm_x86_cet_tests)
        set_tests_properties(
            cdisasm_x86_cet_tests
            PROPERTIES LABELS "cet;extra-opcodes;x86")

        add_executable(cdisasm_x86_mpx_tests tests/test_x86_mpx.c)
        target_compile_features(cdisasm_x86_mpx_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_x86_mpx_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_x86_mpx_tests COMMAND cdisasm_x86_mpx_tests)
        set_tests_properties(cdisasm_x86_mpx_tests
            PROPERTIES LABELS "extra-opcodes;mpx;x86")

        add_executable(cdisasm_x86_apx_movbe_tests tests/test_x86_apx_movbe.c)
        target_compile_features(cdisasm_x86_apx_movbe_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_x86_apx_movbe_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_x86_apx_movbe_tests
            COMMAND cdisasm_x86_apx_movbe_tests)
        set_tests_properties(cdisasm_x86_apx_movbe_tests
            PROPERTIES LABELS "apx;extra-opcodes;movbe;x86")

        add_executable(cdisasm_x86_waitpkg_tests tests/test_x86_waitpkg.c)
        target_compile_features(cdisasm_x86_waitpkg_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_x86_waitpkg_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_waitpkg_tests
            COMMAND cdisasm_x86_waitpkg_tests)
        set_tests_properties(
            cdisasm_x86_waitpkg_tests
            PROPERTIES LABELS "extra-opcodes;system;waitpkg;x86")

        add_executable(
            cdisasm_x86_system_modern_tests
            tests/test_x86_system_modern.c)
        target_compile_features(
            cdisasm_x86_system_modern_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_system_modern_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_system_modern_tests
            COMMAND cdisasm_x86_system_modern_tests)
        set_tests_properties(
            cdisasm_x86_system_modern_tests
            PROPERTIES LABELS "extra-opcodes;memory-hints;system;x86")

        add_executable(
            cdisasm_x86_expansion_tests
            tests/test_x86_expansion.c)
        target_compile_features(
            cdisasm_x86_expansion_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_expansion_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_expansion_tests
            COMMAND cdisasm_x86_expansion_tests)
        set_tests_properties(
            cdisasm_x86_expansion_tests
            PROPERTIES LABELS "extra-opcodes;x86")

        add_executable(
            cdisasm_x86_evex_fma_tests
            tests/test_x86_evex_fma.c)
        target_compile_features(
            cdisasm_x86_evex_fma_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_evex_fma_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_evex_fma_tests
            COMMAND cdisasm_x86_evex_fma_tests)
        set_tests_properties(
            cdisasm_x86_evex_fma_tests
            PROPERTIES LABELS "avx512;evex;extra-opcodes;fma3;x86")

        add_executable(
            cdisasm_x86_amd_expansion_tests
            tests/test_x86_amd_expansion.c)
        target_compile_features(
            cdisasm_x86_amd_expansion_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_amd_expansion_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_amd_expansion_tests
            COMMAND cdisasm_x86_amd_expansion_tests)
        set_tests_properties(
            cdisasm_x86_amd_expansion_tests
            PROPERTIES LABELS "extra-opcodes;x86;amd")

        add_executable(
            cdisasm_x86_xop_map9_tests
            tests/test_x86_xop_map9.c)
        target_compile_features(
            cdisasm_x86_xop_map9_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_xop_map9_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_xop_map9_tests
            COMMAND cdisasm_x86_xop_map9_tests)
        set_tests_properties(
            cdisasm_x86_xop_map9_tests
            PROPERTIES LABELS "amd;extra-opcodes;x86;xop")

        add_executable(
            cdisasm_x86_xop_remaining_tests
            tests/test_x86_xop_remaining.c)
        target_compile_features(
            cdisasm_x86_xop_remaining_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_xop_remaining_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_xop_remaining_tests
            COMMAND cdisasm_x86_xop_remaining_tests)
        set_tests_properties(
            cdisasm_x86_xop_remaining_tests
            PROPERTIES LABELS "amd;extra-opcodes;x86;xop")

        add_executable(
            cdisasm_x86_crypto_modern_tests
            tests/test_x86_crypto_modern.c)
        target_compile_features(
            cdisasm_x86_crypto_modern_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_crypto_modern_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_crypto_modern_tests
            COMMAND cdisasm_x86_crypto_modern_tests)
        set_tests_properties(
            cdisasm_x86_crypto_modern_tests
            PROPERTIES LABELS "crypto;evex;extra-opcodes;sm3;sm4;x86")

        add_executable(
            cdisasm_x86_avx_core_tests
            tests/test_x86_avx_core.c)
        target_compile_features(
            cdisasm_x86_avx_core_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_avx_core_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_avx_core_tests
            COMMAND cdisasm_x86_avx_core_tests)
        set_tests_properties(
            cdisasm_x86_avx_core_tests
            PROPERTIES LABELS "avx;avx512;evex;extra-opcodes;x86")

        add_executable(
            cdisasm_x86_vmovdqa32_tests
            tests/test_x86_vmovdqa32.c)
        target_compile_features(
            cdisasm_x86_vmovdqa32_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vmovdqa32_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vmovdqa32_tests
            COMMAND cdisasm_x86_vmovdqa32_tests)
        set_tests_properties(
            cdisasm_x86_vmovdqa32_tests
            PROPERTIES LABELS "avx512;evex;extra-opcodes;x86")

        add_executable(
            cdisasm_x86_kmask_tests
            tests/test_x86_kmask.c)
        target_compile_features(
            cdisasm_x86_kmask_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_kmask_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_kmask_tests
            COMMAND cdisasm_x86_kmask_tests)
        set_tests_properties(
            cdisasm_x86_kmask_tests
            PROPERTIES LABELS "avx512;extra-opcodes;kmask;vex;x86")

        add_executable(
            cdisasm_x86_evex_compare_tests
            tests/test_x86_evex_compare.c)
        target_compile_features(
            cdisasm_x86_evex_compare_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_evex_compare_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_evex_compare_tests
            COMMAND cdisasm_x86_evex_compare_tests)
        set_tests_properties(
            cdisasm_x86_evex_compare_tests
            PROPERTIES LABELS
                "avx10;avx512;compare;evex;extra-opcodes;x86")

        add_executable(
            cdisasm_x86_evex_integer_minmax_tests
            tests/test_x86_evex_integer_minmax.c)
        target_compile_features(
            cdisasm_x86_evex_integer_minmax_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_evex_integer_minmax_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_evex_integer_minmax_tests
            COMMAND cdisasm_x86_evex_integer_minmax_tests)
        set_tests_properties(
            cdisasm_x86_evex_integer_minmax_tests
            PROPERTIES LABELS
                "avx10;avx512;evex;extra-opcodes;integer;vex;x86")

        add_executable(
            cdisasm_x86_gfni_tests
            tests/test_x86_gfni.c)
        target_compile_features(
            cdisasm_x86_gfni_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_gfni_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_gfni_tests
            COMMAND cdisasm_x86_gfni_tests)
        set_tests_properties(
            cdisasm_x86_gfni_tests
            PROPERTIES LABELS
                "apx;avx;avx10;avx512;evex;extra-opcodes;gfni;vex;x86")

        add_executable(
            cdisasm_x86_evex_integer_add_sub_tests
            tests/test_x86_evex_integer_add_sub.c)
        target_compile_features(
            cdisasm_x86_evex_integer_add_sub_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_evex_integer_add_sub_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_evex_integer_add_sub_tests
            COMMAND cdisasm_x86_evex_integer_add_sub_tests)
        set_tests_properties(
            cdisasm_x86_evex_integer_add_sub_tests
            PROPERTIES LABELS
                "add-sub;avx10;avx512;evex;extra-opcodes;integer;x86")

        add_executable(
            cdisasm_x86_evex_integer_logical_tests
            tests/test_x86_evex_integer_logical.c)
        target_compile_features(
            cdisasm_x86_evex_integer_logical_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_evex_integer_logical_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_evex_integer_logical_tests
            COMMAND cdisasm_x86_evex_integer_logical_tests)
        set_tests_properties(
            cdisasm_x86_evex_integer_logical_tests
            PROPERTIES LABELS
                "apx;avx10;avx512;evex;extra-opcodes;integer;logical;x86")

        add_executable(
            cdisasm_x86_evex_average_tests
            tests/test_x86_evex_average.c)
        target_compile_features(
            cdisasm_x86_evex_average_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_evex_average_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_evex_average_tests
            COMMAND cdisasm_x86_evex_average_tests)
        set_tests_properties(
            cdisasm_x86_evex_average_tests
            PROPERTIES LABELS
                "apx;avx10;avx512;evex;extra-opcodes;integer;x86")

        add_executable(
            cdisasm_x86_variable_shift_tests
            tests/test_x86_variable_shift.c)
        target_compile_features(
            cdisasm_x86_variable_shift_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_variable_shift_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_variable_shift_tests
            COMMAND cdisasm_x86_variable_shift_tests)
        set_tests_properties(
            cdisasm_x86_variable_shift_tests
            PROPERTIES LABELS
                "apx;avx10;avx2;avx512;evex;extra-opcodes;integer;shift;vex;x86")

        add_executable(
            cdisasm_x86_variable_word_shift_tests
            tests/test_x86_variable_word_shift.c)
        target_compile_features(
            cdisasm_x86_variable_word_shift_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_variable_word_shift_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_variable_word_shift_tests
            COMMAND cdisasm_x86_variable_word_shift_tests)
        set_tests_properties(
            cdisasm_x86_variable_word_shift_tests
            PROPERTIES LABELS
                "apx;avx10;avx512;avx512bw;evex;extra-opcodes;integer;shift;x86")

        add_executable(
            cdisasm_x86_variable_rotate_tests
            tests/test_x86_variable_rotate.c)
        target_compile_features(
            cdisasm_x86_variable_rotate_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_variable_rotate_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_variable_rotate_tests
            COMMAND cdisasm_x86_variable_rotate_tests)
        set_tests_properties(
            cdisasm_x86_variable_rotate_tests
            PROPERTIES LABELS
                "apx;avx10;avx512;evex;extra-opcodes;integer;rotate;x86")

        add_executable(
            cdisasm_x86_immediate_rotate_tests
            tests/test_x86_immediate_rotate.c)
        target_compile_features(
            cdisasm_x86_immediate_rotate_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_immediate_rotate_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_immediate_rotate_tests
            COMMAND cdisasm_x86_immediate_rotate_tests)
        set_tests_properties(
            cdisasm_x86_immediate_rotate_tests
            PROPERTIES LABELS
                "apx;avx10;avx512;evex;extra-opcodes;immediate;integer;rotate;x86")

        add_executable(
            cdisasm_x86_immediate_shift_tests
            tests/test_x86_immediate_shift.c)
        target_compile_features(
            cdisasm_x86_immediate_shift_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_immediate_shift_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_immediate_shift_tests
            COMMAND cdisasm_x86_immediate_shift_tests)
        set_tests_properties(
            cdisasm_x86_immediate_shift_tests
            PROPERTIES LABELS
                "apx;avx10;avx512;evex;extra-opcodes;immediate;integer;shift;x86")

        add_executable(
            cdisasm_x86_immediate_shift_group_tests
            tests/test_x86_immediate_shift_groups.c)
        target_compile_features(
            cdisasm_x86_immediate_shift_group_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_immediate_shift_group_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_immediate_shift_group_tests
            COMMAND cdisasm_x86_immediate_shift_group_tests)
        set_tests_properties(
            cdisasm_x86_immediate_shift_group_tests
            PROPERTIES LABELS
                "apx;avx10;avx512;avx512bw;evex;extra-opcodes;immediate;integer;shift;x86")

        add_executable(
            cdisasm_x86_evex_vbmi2_double_shift_tests
            tests/test_x86_evex_vbmi2_double_shift.c)
        target_compile_features(
            cdisasm_x86_evex_vbmi2_double_shift_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_evex_vbmi2_double_shift_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_evex_vbmi2_double_shift_tests
            COMMAND cdisasm_x86_evex_vbmi2_double_shift_tests)
        set_tests_properties(
            cdisasm_x86_evex_vbmi2_double_shift_tests
            PROPERTIES LABELS
                "avx10;avx512;avx512vbmi2;evex;extra-opcodes;integer;shift;x86")

        add_executable(
            cdisasm_x86_evex_compress_expand_tests
            tests/test_x86_evex_compress_expand.c)
        target_compile_features(
            cdisasm_x86_evex_compress_expand_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_evex_compress_expand_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_evex_compress_expand_tests
            COMMAND cdisasm_x86_evex_compress_expand_tests)
        set_tests_properties(
            cdisasm_x86_evex_compress_expand_tests
            PROPERTIES LABELS
                "apx;avx10;avx512;avx512vbmi2;compress-expand;evex;extra-opcodes;x86")

        add_executable(
            cdisasm_x86_evex_bitalg_popcount_tests
            tests/test_x86_evex_bitalg_popcount.c)
        target_compile_features(
            cdisasm_x86_evex_bitalg_popcount_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_evex_bitalg_popcount_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_evex_bitalg_popcount_tests
            COMMAND cdisasm_x86_evex_bitalg_popcount_tests)
        set_tests_properties(
            cdisasm_x86_evex_bitalg_popcount_tests
            PROPERTIES LABELS
                "apx;avx10;avx512;avx512bitalg;avx512vpopcntdq;evex;extra-opcodes;integer;popcount;x86")

        add_executable(
            cdisasm_x86_evex_avx512cd_tests
            tests/test_x86_evex_avx512cd.c)
        target_compile_features(
            cdisasm_x86_evex_avx512cd_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_evex_avx512cd_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_evex_avx512cd_tests
            COMMAND cdisasm_x86_evex_avx512cd_tests)
        set_tests_properties(
            cdisasm_x86_evex_avx512cd_tests
            PROPERTIES LABELS
                "apx;avx10;avx512;avx512cd;evex;extra-opcodes;integer;x86")

        add_executable(
            cdisasm_x86_evex_avx512vnni_tests
            tests/test_x86_evex_avx512vnni.c)
        target_compile_features(
            cdisasm_x86_evex_avx512vnni_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_evex_avx512vnni_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_evex_avx512vnni_tests
            COMMAND cdisasm_x86_evex_avx512vnni_tests)
        set_tests_properties(
            cdisasm_x86_evex_avx512vnni_tests
            PROPERTIES LABELS
                "apx;avx10;avx512;avx512vnni;evex;extra-opcodes;integer;x86")

        add_executable(
            cdisasm_x86_avx_vnni_tests
            tests/test_x86_avx_vnni.c)
        target_compile_features(
            cdisasm_x86_avx_vnni_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_avx_vnni_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_avx_vnni_tests
            COMMAND cdisasm_x86_avx_vnni_tests)
        set_tests_properties(
            cdisasm_x86_avx_vnni_tests
            PROPERTIES LABELS
                "avx;avx-vnni;extra-opcodes;integer;vex;x86")

        add_executable(
            cdisasm_x86_avx_vnni_int8_tests
            tests/test_x86_avx_vnni_int8.c)
        target_compile_features(
            cdisasm_x86_avx_vnni_int8_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_avx_vnni_int8_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_avx_vnni_int8_tests
            COMMAND cdisasm_x86_avx_vnni_int8_tests)
        set_tests_properties(
            cdisasm_x86_avx_vnni_int8_tests
            PROPERTIES LABELS
                "avx;avx-vnni;avx-vnni-int8;extra-opcodes;integer;vex;x86")

        add_executable(
            cdisasm_x86_avx_vnni_int16_tests
            tests/test_x86_avx_vnni_int16.c)
        target_compile_features(
            cdisasm_x86_avx_vnni_int16_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_avx_vnni_int16_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_avx_vnni_int16_tests
            COMMAND cdisasm_x86_avx_vnni_int16_tests)
        set_tests_properties(
            cdisasm_x86_avx_vnni_int16_tests
            PROPERTIES LABELS
                "avx;avx-vnni;avx-vnni-int16;extra-opcodes;integer;vex;x86")

        add_executable(
            cdisasm_x86_avx512_4vnniw_tests
            tests/test_x86_avx512_4vnniw.c)
        target_compile_features(
            cdisasm_x86_avx512_4vnniw_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_avx512_4vnniw_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_avx512_4vnniw_tests
            COMMAND cdisasm_x86_avx512_4vnniw_tests)
        set_tests_properties(
            cdisasm_x86_avx512_4vnniw_tests
            PROPERTIES LABELS
                "avx512;avx512-4vnniw;evex;extra-opcodes;integer;knights-mill;x86")

        add_executable(
            cdisasm_x86_avx512_4fmaps_tests
            tests/test_x86_avx512_4fmaps.c)
        target_compile_features(
            cdisasm_x86_avx512_4fmaps_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_avx512_4fmaps_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_avx512_4fmaps_tests
            COMMAND cdisasm_x86_avx512_4fmaps_tests)
        set_tests_properties(
            cdisasm_x86_avx512_4fmaps_tests
            PROPERTIES LABELS
                "avx512;avx512-4fmaps;evex;extra-opcodes;fma;knights-mill;x86")

        add_executable(
            cdisasm_x86_evex_vgetexp_tests
            tests/test_x86_evex_vgetexp.c)
        target_compile_features(
            cdisasm_x86_evex_vgetexp_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_evex_vgetexp_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_evex_vgetexp_tests
            COMMAND cdisasm_x86_evex_vgetexp_tests)
        set_tests_properties(
            cdisasm_x86_evex_vgetexp_tests
            PROPERTIES LABELS
                "avx10;avx512;avx512f;evex;extra-opcodes;floating-point;x86")

        add_executable(
            cdisasm_x86_evex_vgetexp16_tests
            tests/test_x86_evex_vgetexp16.c)
        target_compile_features(
            cdisasm_x86_evex_vgetexp16_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_evex_vgetexp16_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_evex_vgetexp16_tests
            COMMAND cdisasm_x86_evex_vgetexp16_tests)
        set_tests_properties(
            cdisasm_x86_evex_vgetexp16_tests
            PROPERTIES LABELS
                "avx10;avx10.2;avx512;avx512fp16;bf16;evex;extra-opcodes;floating-point;x86")

        add_executable(
            cdisasm_x86_evex_avx512vbmi_tests
            tests/test_x86_evex_avx512vbmi.c)
        target_compile_features(
            cdisasm_x86_evex_avx512vbmi_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_evex_avx512vbmi_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_evex_avx512vbmi_tests
            COMMAND cdisasm_x86_evex_avx512vbmi_tests)
        set_tests_properties(
            cdisasm_x86_evex_avx512vbmi_tests
            PROPERTIES LABELS
                "apx;avx10;avx512;avx512vbmi;evex;extra-opcodes;integer;permute;x86")

        add_executable(
            cdisasm_x86_expanded_family_flag_tests
            tests/test_x86_expanded_family_flags.c)
        target_compile_features(
            cdisasm_x86_expanded_family_flag_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_expanded_family_flag_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_expanded_family_flag_tests
            COMMAND cdisasm_x86_expanded_family_flag_tests)
        set_tests_properties(
            cdisasm_x86_expanded_family_flag_tests
            PROPERTIES LABELS
                "amx;avx512;cpu-gates;extra-opcodes;flags;runtime;x86")

        add_executable(
            cdisasm_x86_family_descriptor_tests
            tests/test_x86_families.c)
        target_compile_features(
            cdisasm_x86_family_descriptor_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_family_descriptor_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_family_descriptor_tests
            COMMAND cdisasm_x86_family_descriptor_tests)
        set_tests_properties(
            cdisasm_x86_family_descriptor_tests
            PROPERTIES LABELS
                "cpu-gates;families;metadata;x86")

        add_executable(
            cdisasm_x86_current_families_tests
            tests/test_x86_current_families.c)
        target_compile_features(
            cdisasm_x86_current_families_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_current_families_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_current_families_tests
            COMMAND cdisasm_x86_current_families_tests)
        set_tests_properties(
            cdisasm_x86_current_families_tests
            PROPERTIES LABELS
                "cpu-detection;cpu-gates;families;runtime;x86")

        add_executable(
            cdisasm_x86_saturating_add_sub_tests
            tests/test_x86_saturating_add_sub.c)
        target_compile_features(
            cdisasm_x86_saturating_add_sub_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_saturating_add_sub_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_saturating_add_sub_tests
            COMMAND cdisasm_x86_saturating_add_sub_tests)
        set_tests_properties(
            cdisasm_x86_saturating_add_sub_tests
            PROPERTIES LABELS
                "add-sub;avx;avx10;avx2;avx512;evex;extra-opcodes;integer;saturating;vex;x86")

        add_executable(
            cdisasm_x86_evex_integer_multiply_tests
            tests/test_x86_evex_integer_multiply.c)
        target_compile_features(
            cdisasm_x86_evex_integer_multiply_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_evex_integer_multiply_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_evex_integer_multiply_tests
            COMMAND cdisasm_x86_evex_integer_multiply_tests)
        set_tests_properties(
            cdisasm_x86_evex_integer_multiply_tests
            PROPERTIES LABELS
                "avx10;avx512;evex;extra-opcodes;integer;multiply;x86")

        add_executable(
            cdisasm_x86_nextgen_tests
            tests/test_x86_nextgen.c)
        target_compile_features(
            cdisasm_x86_nextgen_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_nextgen_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_nextgen_tests
            COMMAND cdisasm_x86_nextgen_tests)
        set_tests_properties(
            cdisasm_x86_nextgen_tests
            PROPERTIES LABELS
                "amx;apx;avx10;evex;extra-opcodes;x86")

        add_executable(
            cdisasm_x86_rao_int_tests
            tests/test_x86_rao_int.c)
        target_compile_features(
            cdisasm_x86_rao_int_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_rao_int_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_rao_int_tests
            COMMAND cdisasm_x86_rao_int_tests)
        set_tests_properties(
            cdisasm_x86_rao_int_tests
            PROPERTIES LABELS
                "atomic;extra-opcodes;legacy;rao-int;x86")

        add_executable(
            cdisasm_x86_bsr_user_msr_tests
            tests/test_x86_bsr_user_msr.c)
        target_compile_features(
            cdisasm_x86_bsr_user_msr_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_bsr_user_msr_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_bsr_user_msr_tests
            COMMAND cdisasm_x86_bsr_user_msr_tests)
        set_tests_properties(
            cdisasm_x86_bsr_user_msr_tests
            PROPERTIES LABELS
                "ace;apx;extra-opcodes;state;system;user-msr;x86")

        add_executable(
            cdisasm_x86_msr_system_tests
            tests/test_x86_msr_system.c)
        target_compile_features(
            cdisasm_x86_msr_system_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_msr_system_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_msr_system_tests
            COMMAND cdisasm_x86_msr_system_tests)
        set_tests_properties(
            cdisasm_x86_msr_system_tests
            PROPERTIES LABELS
                "apx;extra-opcodes;msr;privileged;rex2;system;x86")

        add_executable(
            cdisasm_x86_enqcmd_tests
            tests/test_x86_enqcmd.c)
        target_compile_features(
            cdisasm_x86_enqcmd_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_enqcmd_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_enqcmd_tests
            COMMAND cdisasm_x86_enqcmd_tests)
        set_tests_properties(
            cdisasm_x86_enqcmd_tests
            PROPERTIES LABELS
                "apx;enqcmd;extra-opcodes;legacy;system;user-msr;x86")

        add_executable(
            cdisasm_x86_keylocker_aes_tests
            tests/test_x86_keylocker_aes.c)
        target_compile_features(
            cdisasm_x86_keylocker_aes_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_keylocker_aes_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_keylocker_aes_tests
            COMMAND cdisasm_x86_keylocker_aes_tests)
        set_tests_properties(
            cdisasm_x86_keylocker_aes_tests
            PROPERTIES LABELS
                "aes;extra-opcodes;key-management;keylocker;legacy;security;x86")

        add_executable(
            cdisasm_x86_hreset_tests
            tests/test_x86_hreset.c)
        target_compile_features(
            cdisasm_x86_hreset_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_hreset_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_hreset_tests
            COMMAND cdisasm_x86_hreset_tests)
        set_tests_properties(
            cdisasm_x86_hreset_tests
            PROPERTIES LABELS
                "extra-opcodes;hreset;legacy;privileged;system;x86")

        add_executable(
            cdisasm_x86_cldemote_tests
            tests/test_x86_cldemote.c)
        target_compile_features(
            cdisasm_x86_cldemote_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_cldemote_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_cldemote_tests
            COMMAND cdisasm_x86_cldemote_tests)
        set_tests_properties(
            cdisasm_x86_cldemote_tests
            PROPERTIES LABELS
                "apx;cldemote;extra-opcodes;legacy;memory-hint;nop;rex2;x86")

        add_executable(
            cdisasm_x86_clzero_tests
            tests/test_x86_clzero.c)
        target_compile_features(
            cdisasm_x86_clzero_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_clzero_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_clzero_tests
            COMMAND cdisasm_x86_clzero_tests)
        set_tests_properties(
            cdisasm_x86_clzero_tests
            PROPERTIES LABELS
                "amd;apx;clzero;extra-opcodes;legacy;rex2;x86")

        add_executable(
            cdisasm_x86_rdpru_tests
            tests/test_x86_rdpru.c)
        target_compile_features(
            cdisasm_x86_rdpru_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_rdpru_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_rdpru_tests
            COMMAND cdisasm_x86_rdpru_tests)
        set_tests_properties(
            cdisasm_x86_rdpru_tests
            PROPERTIES LABELS
                "amd;apx;extra-opcodes;legacy;rdpru;rex2;x86")

        add_executable(
            cdisasm_x86_prefetchrst2_wt1_tests
            tests/test_x86_prefetchrst2_wt1.c)
        target_compile_features(
            cdisasm_x86_prefetchrst2_wt1_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_prefetchrst2_wt1_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_prefetchrst2_wt1_tests
            COMMAND cdisasm_x86_prefetchrst2_wt1_tests)
        set_tests_properties(
            cdisasm_x86_prefetchrst2_wt1_tests
            PROPERTIES LABELS
                "apx;extra-opcodes;legacy;memory-hint;movrs;nop;prefetchwt1;rex2;x86")

        add_executable(
            cdisasm_x86_ptwrite_tests
            tests/test_x86_ptwrite.c)
        target_compile_features(
            cdisasm_x86_ptwrite_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_ptwrite_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_ptwrite_tests
            COMMAND cdisasm_x86_ptwrite_tests)
        set_tests_properties(
            cdisasm_x86_ptwrite_tests
            PROPERTIES LABELS
                "apx;extra-opcodes;legacy;ptwrite;rex2;x86")

        add_executable(
            cdisasm_x86_movnti_tests
            tests/test_x86_movnti.c)
        target_compile_features(
            cdisasm_x86_movnti_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_movnti_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_movnti_tests
            COMMAND cdisasm_x86_movnti_tests)
        set_tests_properties(
            cdisasm_x86_movnti_tests
            PROPERTIES LABELS
                "apx;extra-opcodes;legacy;movnti;rex2;sse2;x86")

        add_executable(
            cdisasm_x86_non_temporal_simd_store_tests
            tests/test_x86_non_temporal_simd_stores.c)
        target_compile_features(
            cdisasm_x86_non_temporal_simd_store_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_non_temporal_simd_store_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_non_temporal_simd_store_tests
            COMMAND cdisasm_x86_non_temporal_simd_store_tests)
        set_tests_properties(
            cdisasm_x86_non_temporal_simd_store_tests
            PROPERTIES LABELS
                "apx;avx;avx512;extra-opcodes;legacy;movnt;rex2;simd;x86")

        add_executable(
            cdisasm_x86_movntdqa_tests
            tests/test_x86_movntdqa.c)
        target_compile_features(
            cdisasm_x86_movntdqa_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_movntdqa_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_movntdqa_tests
            COMMAND cdisasm_x86_movntdqa_tests)
        set_tests_properties(
            cdisasm_x86_movntdqa_tests
            PROPERTIES LABELS
                "apx;avx;avx2;avx512;extra-opcodes;legacy;movnt;simd;x86")

        add_executable(
            cdisasm_x86_lddqu_tests
            tests/test_x86_lddqu.c)
        target_compile_features(
            cdisasm_x86_lddqu_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_lddqu_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_lddqu_tests
            COMMAND cdisasm_x86_lddqu_tests)
        set_tests_properties(
            cdisasm_x86_lddqu_tests
            PROPERTIES LABELS
                "apx;avx;extra-opcodes;lddqu;legacy;rex2;simd;sse3;x86")

        add_executable(
            cdisasm_x86_vmovmsk_tests
            tests/test_x86_vmovmsk.c)
        target_compile_features(
            cdisasm_x86_vmovmsk_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vmovmsk_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vmovmsk_tests
            COMMAND cdisasm_x86_vmovmsk_tests)
        set_tests_properties(
            cdisasm_x86_vmovmsk_tests
            PROPERTIES LABELS
                "avx;extra-opcodes;movmsk;simd;vex;x86")

        add_executable(
            cdisasm_x86_vpmovmskb_tests
            tests/test_x86_vpmovmskb.c)
        target_compile_features(
            cdisasm_x86_vpmovmskb_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vpmovmskb_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vpmovmskb_tests
            COMMAND cdisasm_x86_vpmovmskb_tests)
        set_tests_properties(
            cdisasm_x86_vpmovmskb_tests
            PROPERTIES LABELS
                "avx;avx2;extra-opcodes;integer;move-mask;simd;vex;vpmovmskb;x86")

        add_executable(
            cdisasm_x86_vmovq_tests
            tests/test_x86_vmovq.c)
        target_compile_features(
            cdisasm_x86_vmovq_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vmovq_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vmovq_tests
            COMMAND cdisasm_x86_vmovq_tests)
        set_tests_properties(
            cdisasm_x86_vmovq_tests
            PROPERTIES LABELS
                "apx;avx;avx512;extra-opcodes;movq;simd;vex;x86")

        add_executable(
            cdisasm_x86_vmovrs_tests
            tests/test_x86_vmovrs.c)
        target_compile_features(
            cdisasm_x86_vmovrs_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vmovrs_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vmovrs_tests
            COMMAND cdisasm_x86_vmovrs_tests)
        set_tests_properties(
            cdisasm_x86_vmovrs_tests
            PROPERTIES LABELS
                "apx;avx10;evex;extra-opcodes;movrs;simd;x86")

        add_executable(
            cdisasm_x86_vmovsd_tests
            tests/test_x86_vmovsd.c)
        target_compile_features(
            cdisasm_x86_vmovsd_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vmovsd_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vmovsd_tests
            COMMAND cdisasm_x86_vmovsd_tests)
        set_tests_properties(
            cdisasm_x86_vmovsd_tests
            PROPERTIES LABELS
                "apx;avx;avx512;evex;extra-opcodes;movsd;simd;vex;x86")

        add_executable(
            cdisasm_x86_vmovss_tests
            tests/test_x86_vmovss.c)
        target_compile_features(
            cdisasm_x86_vmovss_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vmovss_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vmovss_tests
            COMMAND cdisasm_x86_vmovss_tests)
        set_tests_properties(
            cdisasm_x86_vmovss_tests
            PROPERTIES LABELS
                "apx;avx;avx512;evex;extra-opcodes;movss;simd;vex;x86")

        add_executable(
            cdisasm_x86_vmov_fp16_dup_tests
            tests/test_x86_vmov_fp16_dup.c)
        target_compile_features(
            cdisasm_x86_vmov_fp16_dup_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vmov_fp16_dup_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vmov_fp16_dup_tests
            COMMAND cdisasm_x86_vmov_fp16_dup_tests)
        set_tests_properties(
            cdisasm_x86_vmov_fp16_dup_tests
            PROPERTIES LABELS
                "apx;avx;avx512;avx512fp16;evex;extra-opcodes;simd;vex;x86")

        add_executable(
            cdisasm_x86_vmovupd_ups_tests
            tests/test_x86_vmovupd_ups.c)
        target_compile_features(
            cdisasm_x86_vmovupd_ups_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vmovupd_ups_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vmovupd_ups_tests
            COMMAND cdisasm_x86_vmovupd_ups_tests)
        set_tests_properties(
            cdisasm_x86_vmovupd_ups_tests
            PROPERTIES LABELS
                "apx;avx;avx512;evex;extra-opcodes;simd;vex;vmovupd;vmovups;x86")

        add_executable(
            cdisasm_x86_vmovw_tests
            tests/test_x86_vmovw.c)
        target_compile_features(
            cdisasm_x86_vmovw_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vmovw_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vmovw_tests
            COMMAND cdisasm_x86_vmovw_tests)
        set_tests_properties(
            cdisasm_x86_vmovw_tests
            PROPERTIES LABELS
                "apx;avx;avx512;avx512fp16;evex;extra-opcodes;movzxc;simd;vmovw;x86")

        add_executable(
            cdisasm_x86_vmpsadbw_tests
            tests/test_x86_vmpsadbw.c)
        target_compile_features(
            cdisasm_x86_vmpsadbw_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vmpsadbw_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vmpsadbw_tests
            COMMAND cdisasm_x86_vmpsadbw_tests)
        set_tests_properties(
            cdisasm_x86_vmpsadbw_tests
            PROPERTIES LABELS
                "apx;avx;avx2;avx10;avx512;evex;extra-opcodes;mediax;simd;vex;vmpsadbw;x86")

        add_executable(
            cdisasm_x86_vdbpsadbw_tests
            tests/test_x86_vdbpsadbw.c)
        target_compile_features(
            cdisasm_x86_vdbpsadbw_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vdbpsadbw_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vdbpsadbw_tests
            COMMAND cdisasm_x86_vdbpsadbw_tests)
        set_tests_properties(
            cdisasm_x86_vdbpsadbw_tests
            PROPERTIES LABELS
                "apx;avx;avx10;avx512;avx512bw;evex;extra-opcodes;simd;vdbpsadbw;x86")

        add_executable(
            cdisasm_x86_vpternlog_tests
            tests/test_x86_vpternlog.c)
        target_compile_features(
            cdisasm_x86_vpternlog_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vpternlog_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vpternlog_tests
            COMMAND cdisasm_x86_vpternlog_tests)
        set_tests_properties(
            cdisasm_x86_vpternlog_tests
            PROPERTIES LABELS
                "apx;avx;avx10;avx512;avx512f;evex;extra-opcodes;simd;vpternlog;x86")

        add_executable(
            cdisasm_x86_vmulbf16_tests
            tests/test_x86_vmulbf16.c)
        target_compile_features(
            cdisasm_x86_vmulbf16_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vmulbf16_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vmulbf16_tests
            COMMAND cdisasm_x86_vmulbf16_tests)
        set_tests_properties(
            cdisasm_x86_vmulbf16_tests
            PROPERTIES LABELS
                "apx;avx;avx10;avx10.2;bf16;evex;extra-opcodes;simd;vmulbf16;x86")

        add_executable(
            cdisasm_x86_vcvtneps2bf16_tests
            tests/test_x86_vcvtneps2bf16.c)
        target_compile_features(
            cdisasm_x86_vcvtneps2bf16_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vcvtneps2bf16_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vcvtneps2bf16_tests
            COMMAND cdisasm_x86_vcvtneps2bf16_tests)
        set_tests_properties(
            cdisasm_x86_vcvtneps2bf16_tests
            PROPERTIES LABELS
                "avx;avx512;avx512bf16;evex;extra-opcodes;simd;vcvtneps2bf16;x86")

        add_executable(
            cdisasm_x86_vbroadcast_block_tests
            tests/test_x86_vbroadcast_blocks.c)
        target_compile_features(
            cdisasm_x86_vbroadcast_block_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vbroadcast_block_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vbroadcast_block_tests
            COMMAND cdisasm_x86_vbroadcast_block_tests)
        set_tests_properties(
            cdisasm_x86_vbroadcast_block_tests
            PROPERTIES LABELS
                "avx;avx512;avx512dq;evex;extra-opcodes;simd;vbroadcast;x86")

        add_executable(
            cdisasm_x86_vbroadcast_x2_tests
            tests/test_x86_vbroadcast_x2.c)
        target_compile_features(
            cdisasm_x86_vbroadcast_x2_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vbroadcast_x2_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vbroadcast_x2_tests
            COMMAND cdisasm_x86_vbroadcast_x2_tests)
        set_tests_properties(
            cdisasm_x86_vbroadcast_x2_tests
            PROPERTIES LABELS
                "avx;avx512;avx512dq;evex;extra-opcodes;simd;vbroadcast;x86")

        add_executable(
            cdisasm_x86_vextract_x8_tests
            tests/test_x86_vextract_x8.c)
        target_compile_features(
            cdisasm_x86_vextract_x8_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vextract_x8_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vextract_x8_tests
            COMMAND cdisasm_x86_vextract_x8_tests)
        set_tests_properties(
            cdisasm_x86_vextract_x8_tests
            PROPERTIES LABELS
                "avx;avx512;avx512dq;evex;extra-opcodes;simd;vextract;x86")

        add_executable(
            cdisasm_x86_vextract_x4_tests
            tests/test_x86_vextract_x4.c)
        target_compile_features(
            cdisasm_x86_vextract_x4_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vextract_x4_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vextract_x4_tests
            COMMAND cdisasm_x86_vextract_x4_tests)
        set_tests_properties(
            cdisasm_x86_vextract_x4_tests
            PROPERTIES LABELS
                "avx;avx512;avx512dq;evex;extra-opcodes;simd;vextract;x86")

        add_executable(
            cdisasm_x86_vmul_fp16_tests
            tests/test_x86_vmul_fp16.c)
        target_compile_features(
            cdisasm_x86_vmul_fp16_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vmul_fp16_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vmul_fp16_tests
            COMMAND cdisasm_x86_vmul_fp16_tests)
        set_tests_properties(
            cdisasm_x86_vmul_fp16_tests
            PROPERTIES LABELS
                "apx;avx;avx10;avx512;avx512fp16;evex;extra-opcodes;fp16;simd;vmulph;vmulsh;x86")

        add_executable(
            cdisasm_x86_vor_fp_tests
            tests/test_x86_vor_fp.c)
        target_compile_features(
            cdisasm_x86_vor_fp_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vor_fp_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vor_fp_tests
            COMMAND cdisasm_x86_vor_fp_tests)
        set_tests_properties(
            cdisasm_x86_vor_fp_tests
            PROPERTIES LABELS
                "apx;avx;avx10;avx512;avx512dq;evex;extra-opcodes;floating-point;logical;simd;vex;vorpd;vorps;x86")

        add_executable(
            cdisasm_x86_vp2intersect_tests
            tests/test_x86_vp2intersect.c)
        target_compile_features(
            cdisasm_x86_vp2intersect_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vp2intersect_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vp2intersect_tests
            COMMAND cdisasm_x86_vp2intersect_tests)
        set_tests_properties(
            cdisasm_x86_vp2intersect_tests
            PROPERTIES LABELS
                "apx;avx512;avx512vp2intersect;evex;extra-opcodes;multidest;simd;vp2intersectd;vp2intersectq;x86")

        add_executable(
            cdisasm_x86_vpabs_tests
            tests/test_x86_vpabs.c)
        target_compile_features(
            cdisasm_x86_vpabs_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vpabs_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vpabs_tests
            COMMAND cdisasm_x86_vpabs_tests)
        set_tests_properties(
            cdisasm_x86_vpabs_tests
            PROPERTIES LABELS
                "apx;avx;avx2;avx10;avx512;avx512bw;evex;extra-opcodes;integer;simd;vex;vpabsb;vpabsd;vpabsq;vpabsw;x86")

        add_executable(
            cdisasm_x86_vpack_tests
            tests/test_x86_vpack.c)
        target_compile_features(
            cdisasm_x86_vpack_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vpack_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vpack_tests
            COMMAND cdisasm_x86_vpack_tests)
        set_tests_properties(
            cdisasm_x86_vpack_tests
            PROPERTIES LABELS
                "apx;avx;avx2;avx10;avx512;avx512bw;evex;extra-opcodes;integer;pack;saturating;simd;vex;vpackssdw;vpacksswb;vpackusdw;vpackuswb;x86")

        add_executable(
            cdisasm_x86_vpcmpeqq_tests
            tests/test_x86_vpcmpeqq.c)
        target_compile_features(
            cdisasm_x86_vpcmpeqq_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vpcmpeqq_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vpcmpeqq_tests
            COMMAND cdisasm_x86_vpcmpeqq_tests)
        set_tests_properties(
            cdisasm_x86_vpcmpeqq_tests
            PROPERTIES LABELS
                "avx;avx2;compare;extra-opcodes;integer;simd;vex;vpcmpeqq;x86")

        add_executable(
            cdisasm_x86_vpcmpgtq_tests
            tests/test_x86_vpcmpgtq.c)
        target_compile_features(
            cdisasm_x86_vpcmpgtq_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vpcmpgtq_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vpcmpgtq_tests
            COMMAND cdisasm_x86_vpcmpgtq_tests)
        set_tests_properties(
            cdisasm_x86_vpcmpgtq_tests
            PROPERTIES LABELS
                "avx;avx2;compare;extra-opcodes;integer;simd;vex;vpcmpgtq;x86")

        add_executable(
            cdisasm_x86_packed_compare_tests
            tests/test_x86_packed_compare.c)
        target_compile_features(
            cdisasm_x86_packed_compare_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_packed_compare_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_packed_compare_tests
            COMMAND cdisasm_x86_packed_compare_tests)
        set_tests_properties(
            cdisasm_x86_packed_compare_tests
            PROPERTIES LABELS
                "avx;avx2;avx512;compare;extra-opcodes;integer;simd;vex;x86")

        add_executable(
            cdisasm_x86_vpaddsub_tests
            tests/test_x86_vpaddsub.c)
        target_compile_features(
            cdisasm_x86_vpaddsub_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vpaddsub_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vpaddsub_tests
            COMMAND cdisasm_x86_vpaddsub_tests)
        set_tests_properties(
            cdisasm_x86_vpaddsub_tests
            PROPERTIES LABELS
                "add;avx;avx2;extra-opcodes;integer;simd;sub;vex;vpadd;vpsub;x86")

        add_executable(
            cdisasm_x86_vpcmpgtw_tests
            tests/test_x86_vpcmpgtw.c)
        target_compile_features(
            cdisasm_x86_vpcmpgtw_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vpcmpgtw_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vpcmpgtw_tests
            COMMAND cdisasm_x86_vpcmpgtw_tests)
        set_tests_properties(
            cdisasm_x86_vpcmpgtw_tests
            PROPERTIES LABELS
                "avx;avx2;compare;extra-opcodes;integer;simd;vex;vpcmpgtw;x86")

        add_executable(
            cdisasm_x86_vpmaskmov_tests
            tests/test_x86_vpmaskmov.c)
        target_compile_features(
            cdisasm_x86_vpmaskmov_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vpmaskmov_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vpmaskmov_tests
            COMMAND cdisasm_x86_vpmaskmov_tests)
        set_tests_properties(
            cdisasm_x86_vpmaskmov_tests
            PROPERTIES LABELS
                "avx2;extra-opcodes;integer;masked-memory;simd;vex;vpmaskmov;x86")

        add_executable(
            cdisasm_x86_vblend_tests
            tests/test_x86_vblend.c)
        target_compile_features(
            cdisasm_x86_vblend_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vblend_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vblend_tests
            COMMAND cdisasm_x86_vblend_tests)
        set_tests_properties(
            cdisasm_x86_vblend_tests
            PROPERTIES LABELS
                "avx;blend;extra-opcodes;immediate;simd;vblendpd;vblendps;vex;x86")

        add_executable(
            cdisasm_x86_vdpp_tests
            tests/test_x86_vdpp.c)
        target_compile_features(
            cdisasm_x86_vdpp_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vdpp_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vdpp_tests
            COMMAND cdisasm_x86_vdpp_tests)
        set_tests_properties(
            cdisasm_x86_vdpp_tests
            PROPERTIES LABELS
                "avx;dot-product;extra-opcodes;floating-point;immediate;simd;vdppd;vdpps;vex;x86")

        add_executable(
            cdisasm_x86_vmxcsr_tests
            tests/test_x86_vmxcsr.c)
        target_compile_features(
            cdisasm_x86_vmxcsr_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vmxcsr_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vmxcsr_tests
            COMMAND cdisasm_x86_vmxcsr_tests)
        set_tests_properties(
            cdisasm_x86_vmxcsr_tests
            PROPERTIES LABELS
                "avx;extra-opcodes;mxcsr;simd;vex;vldmxcsr;vstmxcsr;x86")

        add_executable(
            cdisasm_x86_vmaskmov_tests
            tests/test_x86_vmaskmov.c)
        target_compile_features(
            cdisasm_x86_vmaskmov_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vmaskmov_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vmaskmov_tests
            COMMAND cdisasm_x86_vmaskmov_tests)
        set_tests_properties(
            cdisasm_x86_vmaskmov_tests
            PROPERTIES LABELS
                "avx;extra-opcodes;mask-move;simd;vex;vmaskmovpd;vmaskmovps;x86")

        add_executable(
            cdisasm_x86_vpblend_tests
            tests/test_x86_vpblend.c)
        target_compile_features(
            cdisasm_x86_vpblend_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vpblend_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vpblend_tests
            COMMAND cdisasm_x86_vpblend_tests)
        set_tests_properties(
            cdisasm_x86_vpblend_tests
            PROPERTIES LABELS
                "avx;avx2;blend;extra-opcodes;immediate;simd;vex;vpblendd;vpblendw;x86")

        add_executable(
            cdisasm_x86_vpblendvb_tests
            tests/test_x86_vpblendvb.c)
        target_compile_features(
            cdisasm_x86_vpblendvb_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vpblendvb_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vpblendvb_tests
            COMMAND cdisasm_x86_vpblendvb_tests)
        set_tests_properties(
            cdisasm_x86_vpblendvb_tests
            PROPERTIES LABELS
                "avx;avx2;blend;extra-opcodes;selector;simd;vex;vpblendvb;x86")

        add_executable(
            cdisasm_x86_vblendv_tests
            tests/test_x86_vblendv.c)
        target_compile_features(
            cdisasm_x86_vblendv_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vblendv_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vblendv_tests
            COMMAND cdisasm_x86_vblendv_tests)
        set_tests_properties(
            cdisasm_x86_vblendv_tests
            PROPERTIES LABELS
                "avx;blend;extra-opcodes;selector;simd;vblendvpd;vblendvps;vex;x86")

        add_executable(
            cdisasm_x86_vbroadcast128_tests
            tests/test_x86_vbroadcast128.c)
        target_compile_features(
            cdisasm_x86_vbroadcast128_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vbroadcast128_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vbroadcast128_tests
            COMMAND cdisasm_x86_vbroadcast128_tests)
        set_tests_properties(
            cdisasm_x86_vbroadcast128_tests
            PROPERTIES LABELS
                "avx;avx2;broadcast;extra-opcodes;simd;vbroadcastf128;vbroadcasti128;vex;x86")

        add_executable(
            cdisasm_x86_lane_insert_extract_tests
            tests/test_x86_lane_insert_extract.c)
        target_compile_features(
            cdisasm_x86_lane_insert_extract_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_lane_insert_extract_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_lane_insert_extract_tests
            COMMAND cdisasm_x86_lane_insert_extract_tests)
        set_tests_properties(
            cdisasm_x86_lane_insert_extract_tests
            PROPERTIES LABELS
                "avx;avx2;extra-opcodes;extract;immediate;insert;simd;vex;vextractf128;vextracti128;vinsertf128;vinserti128;x86")

        add_executable(
            cdisasm_x86_vextractps_vinsertps_tests
            tests/test_x86_vextractps_vinsertps.c)
        target_compile_features(
            cdisasm_x86_vextractps_vinsertps_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vextractps_vinsertps_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vextractps_vinsertps_tests
            COMMAND cdisasm_x86_vextractps_vinsertps_tests)
        set_tests_properties(
            cdisasm_x86_vextractps_vinsertps_tests
            PROPERTIES LABELS
                "avx;extra-opcodes;extract;immediate;insert;simd;vex;vextractps;vinsertps;x86")

        add_executable(
            cdisasm_x86_vperm2_128_tests
            tests/test_x86_vperm2_128.c)
        target_compile_features(
            cdisasm_x86_vperm2_128_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vperm2_128_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vperm2_128_tests
            COMMAND cdisasm_x86_vperm2_128_tests)
        set_tests_properties(
            cdisasm_x86_vperm2_128_tests
            PROPERTIES LABELS
                "avx;avx2;extra-opcodes;immediate;permute;simd;vex;vperm2f128;vperm2i128;x86")

        add_executable(
            cdisasm_x86_vpermd_vpermps_tests
            tests/test_x86_vpermd_vpermps.c)
        target_compile_features(
            cdisasm_x86_vpermd_vpermps_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vpermd_vpermps_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vpermd_vpermps_tests
            COMMAND cdisasm_x86_vpermd_vpermps_tests)
        set_tests_properties(
            cdisasm_x86_vpermd_vpermps_tests
            PROPERTIES LABELS
                "avx;avx2;extra-opcodes;permute;simd;vex;vpermd;vpermps;x86")

        add_executable(
            cdisasm_x86_vpermilpd_vpermilps_tests
            tests/test_x86_vpermilpd_vpermilps.c)
        target_compile_features(
            cdisasm_x86_vpermilpd_vpermilps_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vpermilpd_vpermilps_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vpermilpd_vpermilps_tests
            COMMAND cdisasm_x86_vpermilpd_vpermilps_tests)
        set_tests_properties(
            cdisasm_x86_vpermilpd_vpermilps_tests
            PROPERTIES LABELS
                "avx;extra-opcodes;immediate;nds;permute;simd;vex;vpermilpd;vpermilps;x86")

        add_executable(
            cdisasm_x86_vpermpd_vpermq_tests
            tests/test_x86_vpermpd_vpermq.c)
        target_compile_features(
            cdisasm_x86_vpermpd_vpermq_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vpermpd_vpermq_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vpermpd_vpermq_tests
            COMMAND cdisasm_x86_vpermpd_vpermq_tests)
        set_tests_properties(
            cdisasm_x86_vpermpd_vpermq_tests
            PROPERTIES LABELS
                "avx;avx2;extra-opcodes;immediate;permute;simd;vex;vpermpd;vpermq;x86")

        add_executable(
            cdisasm_x86_vround_tests
            tests/test_x86_vround.c)
        target_compile_features(
            cdisasm_x86_vround_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vround_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vround_tests
            COMMAND cdisasm_x86_vround_tests)
        set_tests_properties(
            cdisasm_x86_vround_tests
            PROPERTIES LABELS
                "avx;extra-opcodes;floating-point;immediate;round;simd;vex;vroundpd;vroundps;vroundsd;vroundss;x86")

        add_executable(
            cdisasm_x86_vshuf_tests
            tests/test_x86_vshuf.c)
        target_compile_features(
            cdisasm_x86_vshuf_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vshuf_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vshuf_tests
            COMMAND cdisasm_x86_vshuf_tests)
        set_tests_properties(
            cdisasm_x86_vshuf_tests
            PROPERTIES LABELS
                "avx;extra-opcodes;floating-point;immediate;nds;shuffle;simd;vex;vshufpd;vshufps;x86")

        add_executable(
            cdisasm_x86_vtest_tests
            tests/test_x86_vtest.c)
        target_compile_features(
            cdisasm_x86_vtest_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vtest_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vtest_tests
            COMMAND cdisasm_x86_vtest_tests)
        set_tests_properties(
            cdisasm_x86_vtest_tests
            PROPERTIES LABELS
                "avx;extra-opcodes;floating-point;logical;simd;status-flags;vex;vtestpd;vtestps;x86")

        add_executable(
            cdisasm_x86_vptest_tests
            tests/test_x86_vptest.c)
        target_compile_features(
            cdisasm_x86_vptest_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vptest_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vptest_tests
            COMMAND cdisasm_x86_vptest_tests)
        set_tests_properties(
            cdisasm_x86_vptest_tests
            PROPERTIES LABELS
                "avx;extra-opcodes;integer;logical;simd;status-flags;vex;vptest;x86")

        add_executable(
            cdisasm_x86_vucomi_tests
            tests/test_x86_vucomi.c)
        target_compile_features(
            cdisasm_x86_vucomi_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vucomi_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vucomi_tests
            COMMAND cdisasm_x86_vucomi_tests)
        set_tests_properties(
            cdisasm_x86_vucomi_tests
            PROPERTIES LABELS
                "avx;compare;extra-opcodes;floating-point;simd;status-flags;vex;vucomisd;vucomiss;x86")

        add_executable(
            cdisasm_x86_vcomis_tests
            tests/test_x86_vcomis.c)
        target_compile_features(
            cdisasm_x86_vcomis_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vcomis_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vcomis_tests
            COMMAND cdisasm_x86_vcomis_tests)
        set_tests_properties(
            cdisasm_x86_vcomis_tests
            PROPERTIES LABELS
                "avx;compare;extra-opcodes;floating-point;simd;status-flags;vcomisd;vcomiss;vex;x86")

        add_executable(
            cdisasm_x86_vcmp_tests
            tests/test_x86_vcmp.c)
        target_compile_features(
            cdisasm_x86_vcmp_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vcmp_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vcmp_tests
            COMMAND cdisasm_x86_vcmp_tests)
        set_tests_properties(
            cdisasm_x86_vcmp_tests
            PROPERTIES LABELS
                "avx;compare;extra-opcodes;floating-point;immediate;simd;vcmppd;vcmpps;vcmpsd;vcmpss;vex;x86")

        add_executable(
            cdisasm_x86_vunpck_tests
            tests/test_x86_vunpck.c)
        target_compile_features(
            cdisasm_x86_vunpck_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vunpck_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vunpck_tests
            COMMAND cdisasm_x86_vunpck_tests)
        set_tests_properties(
            cdisasm_x86_vunpck_tests
            PROPERTIES LABELS
                "avx;extra-opcodes;floating-point;simd;unpack;vex;vunpckhpd;vunpckhps;vunpcklpd;vunpcklps;x86")

        add_executable(
            cdisasm_x86_vpunpck_tests
            tests/test_x86_vpunpck.c)
        target_compile_features(
            cdisasm_x86_vpunpck_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vpunpck_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vpunpck_tests
            COMMAND cdisasm_x86_vpunpck_tests)
        set_tests_properties(
            cdisasm_x86_vpunpck_tests
            PROPERTIES LABELS
                "avx;avx2;extra-opcodes;integer;simd;unpack;vex;vpunpckhbw;vpunpckhdq;vpunpckhqdq;vpunpckhwd;vpunpcklbw;vpunpckldq;vpunpcklqdq;vpunpcklwd;x86")

        add_executable(
            cdisasm_x86_vpsign_tests
            tests/test_x86_vpsign.c)
        target_compile_features(
            cdisasm_x86_vpsign_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vpsign_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vpsign_tests
            COMMAND cdisasm_x86_vpsign_tests)
        set_tests_properties(
            cdisasm_x86_vpsign_tests
            PROPERTIES LABELS
                "avx;avx2;extra-opcodes;integer;sign;simd;vex;vpsignb;vpsignd;vpsignw;x86")

        add_executable(
            cdisasm_x86_vpshuf_integer_tests
            tests/test_x86_vpshuf_integer.c)
        target_compile_features(
            cdisasm_x86_vpshuf_integer_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vpshuf_integer_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vpshuf_integer_tests
            COMMAND cdisasm_x86_vpshuf_integer_tests)
        set_tests_properties(
            cdisasm_x86_vpshuf_integer_tests
            PROPERTIES LABELS
                "avx;avx2;extra-opcodes;immediate;integer;shuffle;simd;vex;vpshufd;vpshufhw;vpshuflw;x86")

        add_executable(
            cdisasm_x86_horizontal_integer_tests
            tests/test_x86_horizontal_integer.c)
        target_compile_features(
            cdisasm_x86_horizontal_integer_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_horizontal_integer_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_horizontal_integer_tests
            COMMAND cdisasm_x86_horizontal_integer_tests)
        set_tests_properties(
            cdisasm_x86_horizontal_integer_tests
            PROPERTIES LABELS
                "avx;avx2;extra-opcodes;horizontal;integer;simd;vex;vphadd;vphsub;x86")

        add_executable(
            cdisasm_x86_vphminposuw_tests
            tests/test_x86_vphminposuw.c)
        target_compile_features(
            cdisasm_x86_vphminposuw_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vphminposuw_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vphminposuw_tests
            COMMAND cdisasm_x86_vphminposuw_tests)
        set_tests_properties(
            cdisasm_x86_vphminposuw_tests
            PROPERTIES LABELS
                "avx;extra-opcodes;integer;minimum;position;simd;vex;vphminposuw;x86")

        add_executable(
            cdisasm_x86_vpinsr_tests
            tests/test_x86_vpinsr.c)
        target_compile_features(
            cdisasm_x86_vpinsr_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vpinsr_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vpinsr_tests
            COMMAND cdisasm_x86_vpinsr_tests)
        set_tests_properties(
            cdisasm_x86_vpinsr_tests
            PROPERTIES LABELS
                "avx;extra-opcodes;immediate;insert;integer;simd;vex;vpinsrb;vpinsrd;vpinsrq;vpinsrw;x86")

        add_executable(
            cdisasm_x86_vpextr_tests
            tests/test_x86_vpextr.c)
        target_compile_features(
            cdisasm_x86_vpextr_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vpextr_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vpextr_tests
            COMMAND cdisasm_x86_vpextr_tests)
        set_tests_properties(
            cdisasm_x86_vpextr_tests
            PROPERTIES LABELS
                "avx;extra-opcodes;extract;immediate;integer;simd;vex;vpextrb;vpextrd;vpextrq;vpextrw;x86")

        add_executable(
            cdisasm_x86_vpmovsx_tests
            tests/test_x86_vpmovsx.c)
        target_compile_features(
            cdisasm_x86_vpmovsx_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vpmovsx_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vpmovsx_tests
            COMMAND cdisasm_x86_vpmovsx_tests)
        set_tests_properties(
            cdisasm_x86_vpmovsx_tests
            PROPERTIES LABELS
                "avx;avx2;extra-opcodes;integer;move;sign-extension;simd;vex;vpmovsxbd;vpmovsxbq;vpmovsxbw;vpmovsxdq;vpmovsxwd;vpmovsxwq;x86")

        add_executable(
            cdisasm_x86_vpmovzx_tests
            tests/test_x86_vpmovzx.c)
        target_compile_features(
            cdisasm_x86_vpmovzx_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vpmovzx_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vpmovzx_tests
            COMMAND cdisasm_x86_vpmovzx_tests)
        set_tests_properties(
            cdisasm_x86_vpmovzx_tests
            PROPERTIES LABELS
                "avx;avx2;extra-opcodes;integer;move;simd;vex;vpmovzxbd;vpmovzxbq;vpmovzxbw;vpmovzxdq;vpmovzxwd;vpmovzxwq;x86;zero-extension")

        add_executable(
            cdisasm_x86_vbroadcast_scalar_tests
            tests/test_x86_vbroadcast_scalar.c)
        target_compile_features(
            cdisasm_x86_vbroadcast_scalar_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vbroadcast_scalar_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vbroadcast_scalar_tests
            COMMAND cdisasm_x86_vbroadcast_scalar_tests)
        set_tests_properties(
            cdisasm_x86_vbroadcast_scalar_tests
            PROPERTIES LABELS
                "avx;avx2;broadcast;extra-opcodes;simd;vbroadcastsd;vbroadcastss;vex;x86")

        add_executable(
            cdisasm_x86_vpbroadcastb_tests
            tests/test_x86_vpbroadcastb.c)
        target_compile_features(
            cdisasm_x86_vpbroadcastb_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vpbroadcastb_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vpbroadcastb_tests
            COMMAND cdisasm_x86_vpbroadcastb_tests)
        set_tests_properties(
            cdisasm_x86_vpbroadcastb_tests
            PROPERTIES LABELS
                "avx;avx2;broadcast;extra-opcodes;simd;vex;vpbroadcastb;vpbroadcastw;x86")

        add_executable(
            cdisasm_x86_vpbroadcastdq_tests
            tests/test_x86_vpbroadcastdq.c)
        target_compile_features(
            cdisasm_x86_vpbroadcastdq_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vpbroadcastdq_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vpbroadcastdq_tests
            COMMAND cdisasm_x86_vpbroadcastdq_tests)
        set_tests_properties(
            cdisasm_x86_vpbroadcastdq_tests
            PROPERTIES LABELS
                "avx;avx2;broadcast;extra-opcodes;simd;vex;vpbroadcastd;vpbroadcastq;x86")

        add_executable(
            cdisasm_x86_vpcmov_tests
            tests/test_x86_vpcmov.c)
        target_compile_features(
            cdisasm_x86_vpcmov_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vpcmov_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vpcmov_tests
            COMMAND cdisasm_x86_vpcmov_tests)
        set_tests_properties(
            cdisasm_x86_vpcmov_tests
            PROPERTIES LABELS
                "amd;avx;extra-opcodes;selector;simd;vpcmov;x86;xop")

        add_executable(
            cdisasm_x86_vpperm_tests
            tests/test_x86_vpperm.c)
        target_compile_features(
            cdisasm_x86_vpperm_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vpperm_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vpperm_tests
            COMMAND cdisasm_x86_vpperm_tests)
        set_tests_properties(
            cdisasm_x86_vpperm_tests
            PROPERTIES LABELS
                "amd;avx;extra-opcodes;selector;simd;vpperm;x86;xop")

        add_executable(
            cdisasm_x86_vmul_fp_tests
            tests/test_x86_vmul_fp.c)
        target_compile_features(
            cdisasm_x86_vmul_fp_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_vmul_fp_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_vmul_fp_tests
            COMMAND cdisasm_x86_vmul_fp_tests)
        set_tests_properties(
            cdisasm_x86_vmul_fp_tests
            PROPERTIES LABELS
                "apx;avx;avx10;avx512;evex;extra-opcodes;floating-point;simd;vex;vmulpd;vmulps;vmulsd;vmulss;x86")

        add_executable(
            cdisasm_x86_virtualization_form_tests
            tests/test_x86_virtualization_forms.c)
        target_compile_features(
            cdisasm_x86_virtualization_form_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_virtualization_form_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_virtualization_form_tests
            COMMAND cdisasm_x86_virtualization_form_tests)
        set_tests_properties(
            cdisasm_x86_virtualization_form_tests
            PROPERTIES LABELS
                "amd;apx;extra-opcodes;intel;legacy;privileged;rex2;svm;vmwrite;vmx;vmxoff;vmxon;vtx;x86")

        add_executable(
            cdisasm_x86_pconfig_tests
            tests/test_x86_pconfig.c)
        target_compile_features(
            cdisasm_x86_pconfig_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_pconfig_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_pconfig_tests
            COMMAND cdisasm_x86_pconfig_tests)
        set_tests_properties(
            cdisasm_x86_pconfig_tests
            PROPERTIES LABELS
                "apx;extra-opcodes;legacy;pconfig;privileged;rex2;system;x86")

        add_executable(
            cdisasm_x86_smap_tests
            tests/test_x86_smap.c)
        target_compile_features(
            cdisasm_x86_smap_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_smap_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_smap_tests
            COMMAND cdisasm_x86_smap_tests)
        set_tests_properties(
            cdisasm_x86_smap_tests
            PROPERTIES LABELS
                "apx;extra-opcodes;fred;legacy;privileged;rex2;smap;system;x86")

        add_executable(
            cdisasm_x86_fred_lkgs_tests
            tests/test_x86_fred_lkgs.c)
        target_compile_features(
            cdisasm_x86_fred_lkgs_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_fred_lkgs_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_fred_lkgs_tests
            COMMAND cdisasm_x86_fred_lkgs_tests)
        set_tests_properties(
            cdisasm_x86_fred_lkgs_tests
            PROPERTIES LABELS
                "extra-opcodes;fred;lkgs;privileged;system;x86")

        add_executable(
            cdisasm_x86_pbndkb_prefetchit_tests
            tests/test_x86_pbndkb_prefetchit.c)
        target_compile_features(
            cdisasm_x86_pbndkb_prefetchit_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_pbndkb_prefetchit_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_pbndkb_prefetchit_tests
            COMMAND cdisasm_x86_pbndkb_prefetchit_tests)
        set_tests_properties(
            cdisasm_x86_pbndkb_prefetchit_tests
            PROPERTIES LABELS
                "apx;extra-opcodes;icache-prefetch;legacy;memory-hint;nop;pbndkb;privileged;rex2;system;x86")

        add_executable(
            cdisasm_x86_monitorx_mcommit_tests
            tests/test_x86_monitorx_mcommit.c)
        target_compile_features(
            cdisasm_x86_monitorx_mcommit_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_monitorx_mcommit_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_monitorx_mcommit_tests
            COMMAND cdisasm_x86_monitorx_mcommit_tests)
        set_tests_properties(
            cdisasm_x86_monitorx_mcommit_tests
            PROPERTIES LABELS
                "amd;apx;extra-opcodes;legacy;mcommit;monitorx;rex2;x86")

        add_executable(
            cdisasm_x86_amd_invlpgb_snp_tests
            tests/test_x86_amd_invlpgb_snp.c)
        target_compile_features(
            cdisasm_x86_amd_invlpgb_snp_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_x86_amd_invlpgb_snp_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_x86_amd_invlpgb_snp_tests
            COMMAND cdisasm_x86_amd_invlpgb_snp_tests)
        set_tests_properties(
            cdisasm_x86_amd_invlpgb_snp_tests
            PROPERTIES LABELS
                "amd;apx;extra-opcodes;invlpgb;legacy;privileged;rex2;snp;system;x86")

        if(CDISASM_EFFECTIVE_USE_EXTRA_OPCODES
           AND CDISASM_EFFECTIVE_USE_DISASM_FORMAT)
            add_executable(cdisasm_format_tests tests/test_format.c)
            target_compile_features(cdisasm_format_tests PRIVATE c_std_11)
            target_link_libraries(cdisasm_format_tests PRIVATE cdisasm)
            add_test(NAME cdisasm_format_tests COMMAND cdisasm_format_tests)
        endif()

        if(CDISASM_EFFECTIVE_USE_EXTRA_OPCODES)
            add_executable(cdisasm_x86_apx_n3_tests tests/test_x86_apx_n3.c)
            target_compile_features(cdisasm_x86_apx_n3_tests PRIVATE c_std_11)
            target_link_libraries(cdisasm_x86_apx_n3_tests PRIVATE cdisasm)
            add_test(NAME cdisasm_x86_apx_n3_tests COMMAND cdisasm_x86_apx_n3_tests)
            set_tests_properties(
                cdisasm_x86_apx_n3_tests
                PROPERTIES LABELS "apx;generated;n3;extra-opcodes;x86")

            add_executable(cdisasm_x86_group_tests tests/test_x86_groups.c)
            target_compile_features(
                cdisasm_x86_group_tests PRIVATE c_std_11)
            target_link_libraries(cdisasm_x86_group_tests PRIVATE cdisasm)
            add_test(
                NAME cdisasm_x86_group_tests
                COMMAND cdisasm_x86_group_tests)

            add_executable(
                cdisasm_virtualization_undocumented_tests
                tests/test_virtualization_undocumented.c)
            target_compile_features(
                cdisasm_virtualization_undocumented_tests
                PRIVATE c_std_11)
            target_link_libraries(
                cdisasm_virtualization_undocumented_tests
                PRIVATE cdisasm)
            add_test(
                NAME cdisasm_virtualization_undocumented_tests
                COMMAND cdisasm_virtualization_undocumented_tests)

            add_executable(cdisasm_3dnow_tests tests/test_3dnow.c)
            target_compile_features(cdisasm_3dnow_tests PRIVATE c_std_11)
            target_link_libraries(cdisasm_3dnow_tests PRIVATE cdisasm)
            add_test(NAME cdisasm_3dnow_tests COMMAND cdisasm_3dnow_tests)

            add_executable(
                cdisasm_x86_catalog_fp16_tests
                tests/test_x86_catalog_fp16.c)
            target_compile_features(
                cdisasm_x86_catalog_fp16_tests PRIVATE c_std_11)
            target_link_libraries(
                cdisasm_x86_catalog_fp16_tests PRIVATE cdisasm)
            add_test(
                NAME cdisasm_x86_catalog_fp16_tests
                COMMAND cdisasm_x86_catalog_fp16_tests)
            set_tests_properties(
                cdisasm_x86_catalog_fp16_tests
                PROPERTIES LABELS "avx512;fp16;generated;extra-opcodes;x86")

        endif()

        # The corpus runner deliberately maps EXTRA_OK rows to
        # UNSUPPORTED_INSTRUCTION when optional semantic tables are absent.
        # Keep it registered in both option variants so OFF builds continue
        # to validate structural ownership, just like the ARM corpus runner.
        add_executable(
            cdisasm_opcode_corpus_tests
            tests/test_opcode_corpus.c)
        target_compile_features(
            cdisasm_opcode_corpus_tests PRIVATE c_std_11)
        if(WIN32)
            target_compile_definitions(
                cdisasm_opcode_corpus_tests
                PRIVATE _CRT_SECURE_NO_WARNINGS)
        endif()
        target_link_libraries(
            cdisasm_opcode_corpus_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_opcode_corpus_tests
            COMMAND
                cdisasm_opcode_corpus_tests
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/data/x86_opcodes.tsv")
        if(CDISASM_EFFECTIVE_USE_EXTRA_OPCODES AND CDISASM_VERIFY_GENERATED)
            # The checked-in XED catalog contains 2,095 catalog-only forms
            # spanning EVEX/APX, VEX, legacy, system and vendor families that
            # do not have a hand-written corpus row. Generate one structural
            # witness per IFORM and run it through the same decoder/metadata
            # contract as the normal corpus. This keeps the broad late-ISA
            # surface measurable without storing a generated fixture in the
            # source tree.
            add_test(
                NAME cdisasm_x86_catalog_gap_tests
                COMMAND
                    "${Python3_EXECUTABLE}"
                    "${CMAKE_CURRENT_SOURCE_DIR}/tools/generate_x86_gap_probe.py"
                    --output
                    "${CMAKE_CURRENT_BINARY_DIR}/x86_catalog_gap_probes.tsv"
                    --check
                    "$<TARGET_FILE:cdisasm_opcode_corpus_tests>")
            set_tests_properties(
                cdisasm_x86_catalog_gap_tests
                PROPERTIES LABELS "apx;avx512;catalog;corpus;evex;extra-opcodes;legacy;vex;x86")
            # Keep the promotion ledger visible in CI.  This is deliberately
            # non-strict while catalog/source/profile rows remain; enabling
            # --strict is the final completion gate once those buckets reach
            # zero.
            add_test(
                NAME cdisasm_x86_evidence_ledger_tests
                COMMAND
                    "${Python3_EXECUTABLE}"
                    "${CMAKE_CURRENT_SOURCE_DIR}/tools/coverage/x86_evidence_ledger.py")
            set_tests_properties(
                cdisasm_x86_evidence_ledger_tests
                PROPERTIES LABELS "catalog;coverage;generated;x86")
            if(NOT "${CDISASM_XED_DEC}" STREQUAL "")
                add_executable(
                    cdisasm_x86_operand_contract_tests
                    tests/test_x86_operand_contract.c)
                target_compile_features(
                    cdisasm_x86_operand_contract_tests PRIVATE c_std_11)
                if(WIN32)
                    target_compile_definitions(
                        cdisasm_x86_operand_contract_tests
                        PRIVATE _CRT_SECURE_NO_WARNINGS)
                endif()
                target_link_libraries(
                    cdisasm_x86_operand_contract_tests PRIVATE cdisasm)
                if(CDISASM_EFFECTIVE_USE_DISASM_FORMAT
                        AND NOT "${CDISASM_XED}" STREQUAL "")
                    add_executable(
                        cdisasm_x86_formatter_contract_tests
                        tests/test_x86_formatter_contract.c)
                    target_compile_features(
                        cdisasm_x86_formatter_contract_tests PRIVATE c_std_11)
                    if(WIN32)
                        target_compile_definitions(
                            cdisasm_x86_formatter_contract_tests
                            PRIVATE _CRT_SECURE_NO_WARNINGS)
                    endif()
                    target_link_libraries(
                        cdisasm_x86_formatter_contract_tests PRIVATE cdisasm)
                endif()
                # Keep the generated structural probe and independently ask
                # pinned XED to decode every witness to the intended IFORM and
                # exact instruction length. This is opt-in because XED is an
                # external audit dependency, not a cdisasm runtime dependency.
                add_test(
                    NAME cdisasm_x86_catalog_xed_tests
                    COMMAND
                        "${Python3_EXECUTABLE}"
                        "${CMAKE_CURRENT_SOURCE_DIR}/tools/generate_x86_gap_probe.py"
                        --output
                        "${CMAKE_CURRENT_BINARY_DIR}/x86_catalog_xed_probes.tsv"
                        --xed-dec
                        "${CDISASM_XED_DEC}"
                        --operand-output
                        "${CMAKE_CURRENT_BINARY_DIR}/x86_catalog_xed_operands.tsv"
                        --operand-check
                        "$<TARGET_FILE:cdisasm_x86_operand_contract_tests>"
                        --check
                        "$<TARGET_FILE:cdisasm_opcode_corpus_tests>")
                set_tests_properties(
                    cdisasm_x86_catalog_xed_tests
                    PROPERTIES LABELS
                        "apx;avx512;catalog;corpus;evex;extra-opcodes;legacy;vex;x86;xed")
                if(CDISASM_EFFECTIVE_USE_DISASM_FORMAT
                        AND NOT "${CDISASM_XED}" STREQUAL "")
                    add_test(
                        NAME cdisasm_x86_catalog_xed_formatter_tests
                        COMMAND
                            "${Python3_EXECUTABLE}"
                            "${CMAKE_CURRENT_SOURCE_DIR}/tools/generate_x86_gap_probe.py"
                            --output
                            "${CMAKE_CURRENT_BINARY_DIR}/x86_catalog_xed_formatter_probes.tsv"
                            --xed-dec
                            "${CDISASM_XED_DEC}"
                            --xed-format
                            "${CDISASM_XED}"
                            --operand-output
                            "${CMAKE_CURRENT_BINARY_DIR}/x86_catalog_xed_formatter_operands.tsv"
                            --operand-check
                            "$<TARGET_FILE:cdisasm_x86_operand_contract_tests>"
                            --format-output
                            "${CMAKE_CURRENT_BINARY_DIR}/x86_catalog_xed_formats.tsv"
                            --format-check
                            "$<TARGET_FILE:cdisasm_x86_formatter_contract_tests>"
                            --check
                            "$<TARGET_FILE:cdisasm_opcode_corpus_tests>")
                    set_tests_properties(
                        cdisasm_x86_catalog_xed_formatter_tests
                        PROPERTIES LABELS
                            "apx;avx512;catalog;corpus;evex;extra-opcodes;legacy;vex;x86;xed;formatter")
                endif()
            endif()
        endif()
    endif()

    if(USE_ARCH_ARM)
        add_executable(cdisasm_arm_tests tests/test_arm.c)
        target_compile_features(cdisasm_arm_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_tests COMMAND cdisasm_arm_tests)

        if(CDISASM_EFFECTIVE_USE_EXTRA_OPCODES
                AND CDISASM_EFFECTIVE_USE_DISASM_FORMAT)
            add_executable(
                cdisasm_arm_pstate_msr_decode_tests
                tests/test_arm_pstate_msr_decode.c)
            target_compile_features(
                cdisasm_arm_pstate_msr_decode_tests PRIVATE c_std_11)
            target_link_libraries(
                cdisasm_arm_pstate_msr_decode_tests PRIVATE cdisasm)
            add_test(
                NAME cdisasm_arm_pstate_msr_decode_tests
                COMMAND cdisasm_arm_pstate_msr_decode_tests)
            set_tests_properties(
                cdisasm_arm_pstate_msr_decode_tests
                PROPERTIES LABELS "a64;arm;extra-opcodes;format;pstate")

            add_executable(
                cdisasm_arm_generated_pc_labels_tests
                tests/test_arm_generated_pc_labels.c
                src/arm/arm_generated_formatter.c)
            target_compile_features(
                cdisasm_arm_generated_pc_labels_tests PRIVATE c_std_11)
            target_include_directories(
                cdisasm_arm_generated_pc_labels_tests PRIVATE
                "${CMAKE_CURRENT_SOURCE_DIR}/include"
                "${CMAKE_CURRENT_SOURCE_DIR}/src/arm"
                "${_cdisasm_generated_include_dir}")
            add_test(
                NAME cdisasm_arm_generated_pc_labels_tests
                COMMAND cdisasm_arm_generated_pc_labels_tests)
            set_tests_properties(
                cdisasm_arm_generated_pc_labels_tests
                PROPERTIES LABELS "a64;arm;extra-opcodes;generated;pc-relative")

            add_executable(
                cdisasm_arm_generated_pc_labels_a32_t32_tests
                tests/test_arm_generated_pc_labels_a32_t32.c)
            target_compile_features(
                cdisasm_arm_generated_pc_labels_a32_t32_tests PRIVATE c_std_11)
            target_include_directories(
                cdisasm_arm_generated_pc_labels_a32_t32_tests PRIVATE
                "${CMAKE_CURRENT_SOURCE_DIR}/include"
                "${CMAKE_CURRENT_SOURCE_DIR}/src/arm"
                "${_cdisasm_generated_include_dir}")
            add_test(
                NAME cdisasm_arm_generated_pc_labels_a32_t32_tests
                COMMAND cdisasm_arm_generated_pc_labels_a32_t32_tests)
            set_tests_properties(
                cdisasm_arm_generated_pc_labels_a32_t32_tests
                PROPERTIES LABELS "a32;arm;extra-opcodes;generated;pc-relative;t32")

            foreach(_cdisasm_arm_direct_recipe_test IN ITEMS
                    sve_pattern neon_shift_size prfop worx invcond t32_shift
                    a32_ldst_shift neon_narrow_shift addsub_ext
                    sve_gpr_suffix sve_pred_shift sve_narrow_shift
                    sve_fast_reduce_size sve_fast_reduce_scalar
                    sve_logical_imm sve_gpr_size sme_qrshr sme_luti
                    sve_sra_shll concat_round5 sve_dup_narrow
                    neon_sat_narrow_alias final_selectors
                    thumb_orn_imm vmull_index fp16_fixed_convert
                    prfm_numeric bti_targets systemreg_numeric
                    testbranch_rt sve_adr_scaled sve_fadda_scalar
                    sve_dupm_mask sve2p3_qshrn sme_zero_tiles
                    a64_simd_lane_choices a64_pmov
                    mov_dup_scalar_alias
                    a32_t32_choices
                    vmov_a4_t4 bf16_index thumb_shift_amount
                    thumb_ror_alias a64_alias_immediates
                    a64_simd_concat vorr_vmov_alias neon_vand_alias
                    neon_vorn_boundary)
                add_executable(
                    cdisasm_arm_generated_${_cdisasm_arm_direct_recipe_test}_tests
                    tests/test_arm_generated_${_cdisasm_arm_direct_recipe_test}.c)
                target_compile_features(
                    cdisasm_arm_generated_${_cdisasm_arm_direct_recipe_test}_tests
                    PRIVATE c_std_11)
                target_include_directories(
                    cdisasm_arm_generated_${_cdisasm_arm_direct_recipe_test}_tests
                    PRIVATE
                    "${CMAKE_CURRENT_SOURCE_DIR}/include"
                    "${CMAKE_CURRENT_SOURCE_DIR}/src/arm"
                    "${_cdisasm_generated_include_dir}")
                add_test(
                    NAME cdisasm_arm_generated_${_cdisasm_arm_direct_recipe_test}_tests
                    COMMAND cdisasm_arm_generated_${_cdisasm_arm_direct_recipe_test}_tests)
                set_tests_properties(
                    cdisasm_arm_generated_${_cdisasm_arm_direct_recipe_test}_tests
                    PROPERTIES LABELS "arm;extra-opcodes;generated;recipe")
            endforeach()

            foreach(_cdisasm_arm_recipe_test IN ITEMS
                    vector_lists grouped_zreg fpx_lists
                    indexed_simd modified_imm vfp_multi
                    tmop_control scalar_shifts asimd_shift_arrangement
                    asimd_narrow cps_iflags bitfield_alias vdup_gpr_size
                    vmov_sm_next vcvt_scalar_lane pauth_ldst_offset
                    optional_suffixes vfp_concat sve_narrow_source
                    vdup_lane split_indexed thumb_shift_alias
                    extend_ins vcvt_datatype asimd_widen_shift
                    system_choices sve_residual
                    a64_control_aliases pstate_msr)
                add_executable(
                    cdisasm_arm_generated_${_cdisasm_arm_recipe_test}_tests
                    tests/test_arm_generated_${_cdisasm_arm_recipe_test}.c
                    src/arm/arm_generated_formatter.c)
                target_compile_features(
                    cdisasm_arm_generated_${_cdisasm_arm_recipe_test}_tests
                    PRIVATE c_std_11)
                target_include_directories(
                    cdisasm_arm_generated_${_cdisasm_arm_recipe_test}_tests
                    PRIVATE
                    "${CMAKE_CURRENT_SOURCE_DIR}/include"
                    "${CMAKE_CURRENT_SOURCE_DIR}/src/arm"
                    "${_cdisasm_generated_include_dir}")
                add_test(
                    NAME cdisasm_arm_generated_${_cdisasm_arm_recipe_test}_tests
                    COMMAND cdisasm_arm_generated_${_cdisasm_arm_recipe_test}_tests)
                set_tests_properties(
                    cdisasm_arm_generated_${_cdisasm_arm_recipe_test}_tests
                    PROPERTIES LABELS "arm;extra-opcodes;generated;recipe")
            endforeach()
        endif()

        add_executable(
            cdisasm_arm_advsimd_structure_tests
            tests/test_arm_advsimd_structure.c)
        target_compile_features(
            cdisasm_arm_advsimd_structure_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_structure_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_structure_tests
            COMMAND cdisasm_arm_advsimd_structure_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_structure_tests
            PROPERTIES LABELS "advsimd;arm;extra-opcodes;neon;structure-load-store")

        add_executable(
            cdisasm_arm_advsimd_replicate_load_tests
            tests/test_arm_advsimd_replicate_load.c)
        target_compile_features(
            cdisasm_arm_advsimd_replicate_load_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_replicate_load_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_replicate_load_tests
            COMMAND cdisasm_arm_advsimd_replicate_load_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_replicate_load_tests
            PROPERTIES LABELS "advsimd;arm;extra-opcodes;load;neon;replicate")

        add_executable(
            cdisasm_arm_vfp_multiple_tests
            tests/test_arm_vfp_multiple.c)
        target_compile_features(
            cdisasm_arm_vfp_multiple_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_vfp_multiple_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_vfp_multiple_tests
            COMMAND cdisasm_arm_vfp_multiple_tests)
        set_tests_properties(
            cdisasm_arm_vfp_multiple_tests
            PROPERTIES LABELS "arm;extra-opcodes;vfp;load-store;multiple-register")

        add_executable(
            cdisasm_arm_vfp_scalar_memory_tests
            tests/test_arm_vfp_scalar_memory.c)
        target_compile_features(
            cdisasm_arm_vfp_scalar_memory_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_vfp_scalar_memory_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_vfp_scalar_memory_tests
            COMMAND cdisasm_arm_vfp_scalar_memory_tests)
        set_tests_properties(
            cdisasm_arm_vfp_scalar_memory_tests
            PROPERTIES LABELS "arm;extra-opcodes;vfp;load-store;scalar;t32")

        add_executable(
            cdisasm_arm_advsimd_structure_t32_tests
            tests/test_arm_advsimd_structure_t32.c)
        target_compile_features(
            cdisasm_arm_advsimd_structure_t32_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_structure_t32_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_structure_t32_tests
            COMMAND cdisasm_arm_advsimd_structure_t32_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_structure_t32_tests
            PROPERTIES LABELS "advsimd;arm;extra-opcodes;neon;structure-load-store;t32")

        add_executable(
            cdisasm_arm_coprocessor_transfer_tests
            tests/test_arm_coprocessor_transfer.c)
        target_compile_features(
            cdisasm_arm_coprocessor_transfer_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_coprocessor_transfer_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_coprocessor_transfer_tests
            COMMAND cdisasm_arm_coprocessor_transfer_tests)
        set_tests_properties(
            cdisasm_arm_coprocessor_transfer_tests
            PROPERTIES LABELS "arm;coprocessor;extra-opcodes;system")

        add_executable(
            cdisasm_arm_coprocessor_ldst_tests
            tests/test_arm_coprocessor_ldst.c)
        target_compile_features(
            cdisasm_arm_coprocessor_ldst_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_coprocessor_ldst_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_coprocessor_ldst_tests
            COMMAND cdisasm_arm_coprocessor_ldst_tests)
        set_tests_properties(
            cdisasm_arm_coprocessor_ldst_tests
            PROPERTIES LABELS "arm;coprocessor;extra-opcodes;load-store")

        add_executable(
            cdisasm_arm_family_descriptor_tests
            tests/test_arm_families.c)
        target_compile_features(
            cdisasm_arm_family_descriptor_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_family_descriptor_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_family_descriptor_tests
            COMMAND cdisasm_arm_family_descriptor_tests)
        set_tests_properties(
            cdisasm_arm_family_descriptor_tests
            PROPERTIES LABELS "arm;cpu-gates;families;metadata;runtime")

        add_executable(
            cdisasm_arm_current_families_tests
            tests/test_arm_current_families.c)
        target_compile_features(
            cdisasm_arm_current_families_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_current_families_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_current_families_tests
            COMMAND cdisasm_arm_current_families_tests)
        set_tests_properties(
            cdisasm_arm_current_families_tests
            PROPERTIES LABELS "arm;cpu-detection;cpu-gates;families;runtime")

        add_executable(cdisasm_arm_modern_tests tests/test_arm_modern.c)
        target_compile_features(cdisasm_arm_modern_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_modern_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_modern_tests COMMAND cdisasm_arm_modern_tests)
        set_tests_properties(
            cdisasm_arm_modern_tests
            PROPERTIES LABELS "arm;extra-opcodes")

        add_executable(cdisasm_arm_sve_luti6_tests tests/test_arm_sve_luti6.c)
        target_compile_features(cdisasm_arm_sve_luti6_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_luti6_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_luti6_tests
            COMMAND cdisasm_arm_sve_luti6_tests)
        set_tests_properties(
            cdisasm_arm_sve_luti6_tests
            PROPERTIES LABELS "arm;extra-opcodes;sve;sve2;sve2p3")

        add_executable(cdisasm_arm_lsfe_tests tests/test_arm_lsfe.c)
        target_compile_features(cdisasm_arm_lsfe_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_lsfe_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_lsfe_tests COMMAND cdisasm_arm_lsfe_tests)
        set_tests_properties(
            cdisasm_arm_lsfe_tests
            PROPERTIES LABELS "arm;atomic;extra-opcodes;fp;lsfe;lse")

        add_executable(cdisasm_arm_rcw_tests tests/test_arm_rcw.c)
        target_compile_features(cdisasm_arm_rcw_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_rcw_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_rcw_tests COMMAND cdisasm_arm_rcw_tests)
        set_tests_properties(
            cdisasm_arm_rcw_tests
            PROPERTIES LABELS "arm;atomic;extra-opcodes;lse2;the")

        add_executable(cdisasm_arm_rcw_cas_tests tests/test_arm_rcw_cas.c)
        target_compile_features(cdisasm_arm_rcw_cas_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_rcw_cas_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_rcw_cas_tests COMMAND cdisasm_arm_rcw_cas_tests)
        set_tests_properties(
            cdisasm_arm_rcw_cas_tests
            PROPERTIES LABELS "arm;atomic;extra-opcodes;the")

        add_executable(cdisasm_arm_sme_tmop_tests tests/test_arm_sme_tmop.c)
        target_compile_features(cdisasm_arm_sme_tmop_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sme_tmop_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sme_tmop_tests COMMAND cdisasm_arm_sme_tmop_tests)
        set_tests_properties(
            cdisasm_arm_sme_tmop_tests
            PROPERTIES LABELS "arm;extra-opcodes;sme;tmop")

        add_executable(cdisasm_arm_stcph_tests tests/test_arm_stcph.c)
        target_compile_features(cdisasm_arm_stcph_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_stcph_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_stcph_tests COMMAND cdisasm_arm_stcph_tests)
        set_tests_properties(
            cdisasm_arm_stcph_tests
            PROPERTIES LABELS "arm;cmh;extra-opcodes;system")

        add_executable(cdisasm_arm_lrcpc3_tests tests/test_arm_lrcpc3.c)
        target_compile_features(cdisasm_arm_lrcpc3_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_lrcpc3_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_lrcpc3_tests COMMAND cdisasm_arm_lrcpc3_tests)
        set_tests_properties(
            cdisasm_arm_lrcpc3_tests
            PROPERTIES LABELS "arm;atomic;extra-opcodes;fp;lrcpc3;neon")

        add_executable(
            cdisasm_arm_length_reverse_reduction_tests
            tests/test_arm_length_reverse_reduction.c)
        target_compile_features(
            cdisasm_arm_length_reverse_reduction_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_length_reverse_reduction_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_length_reverse_reduction_tests
            COMMAND cdisasm_arm_length_reverse_reduction_tests)
        set_tests_properties(
            cdisasm_arm_length_reverse_reduction_tests
            PROPERTIES LABELS
                "advsimd;arm;extra-opcodes;integer;neon;predicate;reduction;sme;sve")

        add_executable(
            cdisasm_arm_advsimd_bitcount_tests
            tests/test_arm_advsimd_bitcount.c)
        target_compile_features(
            cdisasm_arm_advsimd_bitcount_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_bitcount_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_bitcount_tests
            COMMAND cdisasm_arm_advsimd_bitcount_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_bitcount_tests
            PROPERTIES LABELS
                "advsimd;arm;bitcount;extra-opcodes;integer;neon")

        add_executable(
            cdisasm_arm_advsimd_ext_tests
            tests/test_arm_advsimd_ext.c)
        target_compile_features(
            cdisasm_arm_advsimd_ext_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_ext_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_ext_tests
            COMMAND cdisasm_arm_advsimd_ext_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_ext_tests
            PROPERTIES LABELS
                "advsimd;arm;ext;extra-opcodes;integer;neon;permute;vector")

        add_executable(
            cdisasm_arm_crc32_tests
            tests/test_arm_crc32.c)
        target_compile_features(
            cdisasm_arm_crc32_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_crc32_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_crc32_tests
            COMMAND cdisasm_arm_crc32_tests)
        set_tests_properties(
            cdisasm_arm_crc32_tests
            PROPERTIES LABELS
                "a32;a64;arm;crc32;crypto;extra-opcodes;t32")

        add_executable(
            cdisasm_arm_extra_load_store_tests
            tests/test_arm_extra_load_store.c)
        target_compile_features(
            cdisasm_arm_extra_load_store_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_extra_load_store_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_extra_load_store_tests
            COMMAND cdisasm_arm_extra_load_store_tests)
        set_tests_properties(
            cdisasm_arm_extra_load_store_tests
            PROPERTIES LABELS
                "a32;arm;extra-opcodes;load-store;memory")

        add_executable(
            cdisasm_arm_advsimd_sha_tests
            tests/test_arm_advsimd_sha.c)
        target_compile_features(
            cdisasm_arm_advsimd_sha_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_sha_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_sha_tests
            COMMAND cdisasm_arm_advsimd_sha_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_sha_tests
            PROPERTIES LABELS
                "advsimd;arm;crypto;extra-opcodes;neon;sha1;sha256")

        add_executable(
            cdisasm_arm_advsimd_crypto_fixed_tests
            tests/test_arm_advsimd_crypto_fixed.c)
        target_compile_features(
            cdisasm_arm_advsimd_crypto_fixed_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_crypto_fixed_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_crypto_fixed_tests
            COMMAND cdisasm_arm_advsimd_crypto_fixed_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_crypto_fixed_tests
            PROPERTIES LABELS
                "advsimd;arm;crypto;extra-opcodes;neon;sha3;sha512;sm3;sm4")

        add_executable(
            cdisasm_arm_advsimd_bitwise_select_tests
            tests/test_arm_advsimd_bitwise_select.c)
        target_compile_features(
            cdisasm_arm_advsimd_bitwise_select_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_bitwise_select_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_bitwise_select_tests
            COMMAND cdisasm_arm_advsimd_bitwise_select_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_bitwise_select_tests
            PROPERTIES LABELS
                "advsimd;arm;bif;bit;bitwise;bsl;extra-opcodes;integer;neon;vector")

        add_executable(
            cdisasm_arm_advsimd_absolute_difference_long_tests
            tests/test_arm_advsimd_absolute_difference_long.c)
        target_compile_features(
            cdisasm_arm_advsimd_absolute_difference_long_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_absolute_difference_long_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_absolute_difference_long_tests
            COMMAND cdisasm_arm_advsimd_absolute_difference_long_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_absolute_difference_long_tests
            PROPERTIES LABELS
                "absolute-difference;advsimd;arm;extra-opcodes;integer;neon;sabal;sabdl;uabal;uabdl;vector;widening")

        add_executable(
            cdisasm_arm_advsimd_widening_multiply_tests
            tests/test_arm_advsimd_widening_multiply.c)
        target_compile_features(
            cdisasm_arm_advsimd_widening_multiply_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_widening_multiply_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_widening_multiply_tests
            COMMAND cdisasm_arm_advsimd_widening_multiply_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_widening_multiply_tests
            PROPERTIES LABELS
                "advsimd;arm;extra-opcodes;integer;neon;smlal;smlsl;smull;umlal;umlsl;umull;vector;widening")

        add_executable(
            cdisasm_arm_advsimd_saturating_widening_multiply_tests
            tests/test_arm_advsimd_saturating_widening_multiply.c)
        target_compile_features(
            cdisasm_arm_advsimd_saturating_widening_multiply_tests
            PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_saturating_widening_multiply_tests
            PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_saturating_widening_multiply_tests
            COMMAND cdisasm_arm_advsimd_saturating_widening_multiply_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_saturating_widening_multiply_tests
            PROPERTIES LABELS
                "advsimd;arm;extra-opcodes;integer;neon;saturating;sqdmlal;sqdmlsl;sqdmull;vector;widening")

        add_executable(
            cdisasm_arm_advsimd_saturating_mulh_tests
            tests/test_arm_advsimd_saturating_mulh.c)
        target_compile_features(
            cdisasm_arm_advsimd_saturating_mulh_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_saturating_mulh_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_saturating_mulh_tests
            COMMAND cdisasm_arm_advsimd_saturating_mulh_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_saturating_mulh_tests
            PROPERTIES LABELS
                "advsimd;arm;extra-opcodes;integer;neon;saturating;sqdmulh;sqrdmulh;vector")

        add_executable(
            cdisasm_arm_advsimd_pmull_tests
            tests/test_arm_advsimd_pmull.c)
        target_compile_features(
            cdisasm_arm_advsimd_pmull_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_pmull_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_pmull_tests
            COMMAND cdisasm_arm_advsimd_pmull_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_pmull_tests
            PROPERTIES LABELS
                "advsimd;arm;crypto;extra-opcodes;neon;pmull;pmull2;polynomial;vector;widening")

        add_executable(
            cdisasm_arm_advsimd_pmul_tests
            tests/test_arm_advsimd_pmul.c)
        target_compile_features(
            cdisasm_arm_advsimd_pmul_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_pmul_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_pmul_tests
            COMMAND cdisasm_arm_advsimd_pmul_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_pmul_tests
            PROPERTIES LABELS
                "advsimd;arm;extra-opcodes;integer;neon;pmul;polynomial;vector")

        add_executable(
            cdisasm_arm_advsimd_addp_tests
            tests/test_arm_advsimd_addp.c)
        target_compile_features(
            cdisasm_arm_advsimd_addp_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_addp_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_addp_tests
            COMMAND cdisasm_arm_advsimd_addp_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_addp_tests
            PROPERTIES LABELS
                "addp;advsimd;arm;extra-opcodes;integer;neon;pairwise;scalar;vector")

        add_executable(
            cdisasm_arm_advsimd_addv_tests
            tests/test_arm_advsimd_addv.c)
        target_compile_features(
            cdisasm_arm_advsimd_addv_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_addv_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_addv_tests
            COMMAND cdisasm_arm_advsimd_addv_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_addv_tests
            PROPERTIES LABELS
                "addv;advsimd;arm;extra-opcodes;integer;neon;reduction;scalar;vector")

        add_executable(
            cdisasm_arm_advsimd_addlv_tests
            tests/test_arm_advsimd_addlv.c)
        target_compile_features(
            cdisasm_arm_advsimd_addlv_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_addlv_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_addlv_tests
            COMMAND cdisasm_arm_advsimd_addlv_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_addlv_tests
            PROPERTIES LABELS
                "addlv;advsimd;arm;extra-opcodes;integer;neon;reduction;saddlv;scalar;uaddlv;vector;widening")

        add_executable(
            cdisasm_arm_advsimd_pairwise_add_long_tests
            tests/test_arm_advsimd_pairwise_add_long.c)
        target_compile_features(
            cdisasm_arm_advsimd_pairwise_add_long_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_pairwise_add_long_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_pairwise_add_long_tests
            COMMAND cdisasm_arm_advsimd_pairwise_add_long_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_pairwise_add_long_tests
            PROPERTIES LABELS
                "advsimd;arm;extra-opcodes;integer;neon;pairwise;sadalp;saddlp;uadalp;uaddlp;vector;widening")

        add_executable(
            cdisasm_arm_advsimd_pairwise_minmax_tests
            tests/test_arm_advsimd_pairwise_minmax.c)
        target_compile_features(
            cdisasm_arm_advsimd_pairwise_minmax_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_pairwise_minmax_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_pairwise_minmax_tests
            COMMAND cdisasm_arm_advsimd_pairwise_minmax_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_pairwise_minmax_tests
            PROPERTIES LABELS
                "advsimd;arm;extra-opcodes;integer;maximum;minimum;neon;pairwise;smaxp;sminp;umaxp;uminp;vector")

        add_executable(
            cdisasm_arm_advsimd_minmax_tests
            tests/test_arm_advsimd_minmax.c)
        target_compile_features(
            cdisasm_arm_advsimd_minmax_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_minmax_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_minmax_tests
            COMMAND cdisasm_arm_advsimd_minmax_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_minmax_tests
            PROPERTIES LABELS
                "advsimd;arm;extra-opcodes;integer;maximum;minimum;neon;smax;smin;umax;umin;vector")

        add_executable(
            cdisasm_arm_advsimd_compare_tests
            tests/test_arm_advsimd_compare.c)
        target_compile_features(
            cdisasm_arm_advsimd_compare_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_compare_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_compare_tests
            COMMAND cdisasm_arm_advsimd_compare_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_compare_tests
            PROPERTIES LABELS
                "advsimd;arm;cmeq;cmge;cmgt;cmhi;cmhs;compare;extra-opcodes;integer;neon;vector")

        add_executable(
            cdisasm_arm_advsimd_compare_zero_tests
            tests/test_arm_advsimd_compare_zero.c)
        target_compile_features(
            cdisasm_arm_advsimd_compare_zero_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_compare_zero_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_compare_zero_tests
            COMMAND cdisasm_arm_advsimd_compare_zero_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_compare_zero_tests
            PROPERTIES LABELS
                "advsimd;arm;cmle;cmlt;compare;extra-opcodes;integer;neon;scalar;vector;zero")

        add_executable(
            cdisasm_arm_advsimd_cmtst_tests
            tests/test_arm_advsimd_cmtst.c)
        target_compile_features(
            cdisasm_arm_advsimd_cmtst_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_cmtst_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_cmtst_tests
            COMMAND cdisasm_arm_advsimd_cmtst_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_cmtst_tests
            PROPERTIES LABELS
                "advsimd;arm;cmtst;compare;extra-opcodes;integer;neon;scalar;vector")

        add_executable(
            cdisasm_arm_advsimd_variable_shift_tests
            tests/test_arm_advsimd_variable_shift.c)
        target_compile_features(
            cdisasm_arm_advsimd_variable_shift_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_variable_shift_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_variable_shift_tests
            COMMAND cdisasm_arm_advsimd_variable_shift_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_variable_shift_tests
            PROPERTIES LABELS
                "advsimd;arm;extra-opcodes;integer;neon;scalar;shift;sshl;ushl;vector")

        add_executable(
            cdisasm_arm_advsimd_shift_right_immediate_tests
            tests/test_arm_advsimd_shift_right_immediate.c)
        target_compile_features(
            cdisasm_arm_advsimd_shift_right_immediate_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_shift_right_immediate_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_shift_right_immediate_tests
            COMMAND cdisasm_arm_advsimd_shift_right_immediate_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_shift_right_immediate_tests
            PROPERTIES LABELS
                "advsimd;arm;extra-opcodes;immediate;integer;neon;scalar;shift;sshr;ushr;vector")

        add_executable(
            cdisasm_arm_advsimd_sat_shift_convert_immediate_tests
            tests/test_arm_advsimd_sat_shift_convert_immediate.c)
        target_compile_features(
            cdisasm_arm_advsimd_sat_shift_convert_immediate_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_sat_shift_convert_immediate_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_sat_shift_convert_immediate_tests
            COMMAND cdisasm_arm_advsimd_sat_shift_convert_immediate_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_sat_shift_convert_immediate_tests
            PROPERTIES LABELS
                "advsimd;arm;convert;extra-opcodes;floating-point;immediate;neon;saturating;shift;vector")

        add_executable(cdisasm_arm_advsimd_fmov_immediate_tests
            tests/test_arm_advsimd_fmov_immediate.c)
        target_compile_features(cdisasm_arm_advsimd_fmov_immediate_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_advsimd_fmov_immediate_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_advsimd_fmov_immediate_tests
            COMMAND cdisasm_arm_advsimd_fmov_immediate_tests)
        set_tests_properties(cdisasm_arm_advsimd_fmov_immediate_tests PROPERTIES
            LABELS "advsimd;arm;extra-opcodes;floating-point;fmov;fp16;immediate;neon;vector")

        add_executable(cdisasm_arm_advsimd_multiply_element_tests
            tests/test_arm_advsimd_multiply_element.c)
        target_compile_features(cdisasm_arm_advsimd_multiply_element_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_advsimd_multiply_element_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_advsimd_multiply_element_tests
            COMMAND cdisasm_arm_advsimd_multiply_element_tests)
        set_tests_properties(cdisasm_arm_advsimd_multiply_element_tests PROPERTIES
            LABELS "advsimd;arm;by-element;extra-opcodes;integer;mul;neon;saturating;vector")

        add_executable(cdisasm_arm_advsimd_dot_element_tests
            tests/test_arm_advsimd_dot_element.c)
        target_compile_features(cdisasm_arm_advsimd_dot_element_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_advsimd_dot_element_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_advsimd_dot_element_tests
            COMMAND cdisasm_arm_advsimd_dot_element_tests)
        set_tests_properties(cdisasm_arm_advsimd_dot_element_tests PROPERTIES
            LABELS "advsimd;arm;by-element;dotprod;extra-opcodes;i8mm;integer;neon;vector")

        add_executable(cdisasm_arm_advsimd_fp_dot_element_tests
            tests/test_arm_advsimd_fp_dot_element.c)
        target_compile_features(cdisasm_arm_advsimd_fp_dot_element_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_advsimd_fp_dot_element_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_advsimd_fp_dot_element_tests
            COMMAND cdisasm_arm_advsimd_fp_dot_element_tests)
        set_tests_properties(cdisasm_arm_advsimd_fp_dot_element_tests PROPERTIES
            LABELS "advsimd;arm;bf16;by-element;dotprod;extra-opcodes;floating-point;fp8;neon;vector")

        add_executable(cdisasm_arm_advsimd_bfmlal_element_tests
            tests/test_arm_advsimd_bfmlal_element.c)
        target_compile_features(cdisasm_arm_advsimd_bfmlal_element_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_advsimd_bfmlal_element_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_advsimd_bfmlal_element_tests
            COMMAND cdisasm_arm_advsimd_bfmlal_element_tests)
        set_tests_properties(cdisasm_arm_advsimd_bfmlal_element_tests PROPERTIES
            LABELS "advsimd;arm;bf16;bfmlal;by-element;extra-opcodes;floating-point;neon;vector;widening")

        add_executable(cdisasm_arm_advsimd_fp8_widening_element_tests
            tests/test_arm_advsimd_fp8_widening_element.c)
        target_compile_features(cdisasm_arm_advsimd_fp8_widening_element_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_advsimd_fp8_widening_element_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_advsimd_fp8_widening_element_tests
            COMMAND cdisasm_arm_advsimd_fp8_widening_element_tests)
        set_tests_properties(cdisasm_arm_advsimd_fp8_widening_element_tests PROPERTIES
            LABELS "advsimd;arm;by-element;extra-opcodes;floating-point;fp8;neon;vector;widening")

        add_executable(cdisasm_arm_sve_widening_fp_mla_indexed_tests
            tests/test_arm_sve_widening_fp_mla_indexed.c)
        target_compile_features(cdisasm_arm_sve_widening_fp_mla_indexed_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_widening_fp_mla_indexed_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_widening_fp_mla_indexed_tests
            COMMAND cdisasm_arm_sve_widening_fp_mla_indexed_tests)
        set_tests_properties(cdisasm_arm_sve_widening_fp_mla_indexed_tests PROPERTIES
            LABELS "arm;bf16;by-element;extra-opcodes;floating-point;indexed;sme;sve;sve2;sve2p1;widening")

        add_executable(cdisasm_arm_sve_fp8_widening_fp_mla_indexed_tests
            tests/test_arm_sve_fp8_widening_fp_mla_indexed.c)
        target_compile_features(cdisasm_arm_sve_fp8_widening_fp_mla_indexed_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_fp8_widening_fp_mla_indexed_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_fp8_widening_fp_mla_indexed_tests
            COMMAND cdisasm_arm_sve_fp8_widening_fp_mla_indexed_tests)
        set_tests_properties(cdisasm_arm_sve_fp8_widening_fp_mla_indexed_tests PROPERTIES
            LABELS "arm;by-element;extra-opcodes;floating-point;fp8;indexed;ssve;sve;sve2;widening")

        add_executable(cdisasm_arm_sve_fp8_widening_tests tests/test_arm_sve_fp8_widening.c)
        target_compile_features(cdisasm_arm_sve_fp8_widening_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_fp8_widening_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_fp8_widening_tests COMMAND cdisasm_arm_sve_fp8_widening_tests)
        set_tests_properties(cdisasm_arm_sve_fp8_widening_tests PROPERTIES LABELS "arm;extra-opcodes;floating-point;fp8;ssve;sve;sve2;widening")

        add_executable(cdisasm_arm_sve_widening_fp_mla_tests
            tests/test_arm_sve_widening_fp_mla.c)
        target_compile_features(cdisasm_arm_sve_widening_fp_mla_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_widening_fp_mla_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_widening_fp_mla_tests
            COMMAND cdisasm_arm_sve_widening_fp_mla_tests)
        set_tests_properties(cdisasm_arm_sve_widening_fp_mla_tests PROPERTIES
            LABELS "arm;bf16;extra-opcodes;floating-point;sme;sve;sve2;sve2p1;widening")

        add_executable(cdisasm_arm_advsimd_fp_multiply_element_tests
            tests/test_arm_advsimd_fp_multiply_element.c)
        target_compile_features(cdisasm_arm_advsimd_fp_multiply_element_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_advsimd_fp_multiply_element_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_advsimd_fp_multiply_element_tests
            COMMAND cdisasm_arm_advsimd_fp_multiply_element_tests)
        set_tests_properties(cdisasm_arm_advsimd_fp_multiply_element_tests PROPERTIES
            LABELS "advsimd;arm;by-element;extra-opcodes;floating-point;fmla;fmls;fmul;fp16;neon;vector")

        add_executable(
            cdisasm_arm_advsimd_shift_narrow_widen_tests
            tests/test_arm_advsimd_shift_narrow_widen.c)
        target_compile_features(
            cdisasm_arm_advsimd_shift_narrow_widen_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_shift_narrow_widen_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_shift_narrow_widen_tests
            COMMAND cdisasm_arm_advsimd_shift_narrow_widen_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_shift_narrow_widen_tests
            PROPERTIES LABELS
                "advsimd;arm;extra-opcodes;immediate;integer;neon;narrow;rshrn;shift;shrn;sshll;sxtl;ushll;uxtl;vector;widen")

        add_executable(
            cdisasm_arm_advsimd_modified_immediate_tests
            tests/test_arm_advsimd_modified_immediate.c)
        target_compile_features(
            cdisasm_arm_advsimd_modified_immediate_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_modified_immediate_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_modified_immediate_tests
            COMMAND cdisasm_arm_advsimd_modified_immediate_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_modified_immediate_tests
            PROPERTIES LABELS
                "advsimd;arm;extra-opcodes;immediate;integer;movi;mvni;neon;scalar;vector")

        add_executable(
            cdisasm_arm_advsimd_absolute_difference_tests
            tests/test_arm_advsimd_absolute_difference.c)
        target_compile_features(
            cdisasm_arm_advsimd_absolute_difference_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_absolute_difference_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_absolute_difference_tests
            COMMAND cdisasm_arm_advsimd_absolute_difference_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_absolute_difference_tests
            PROPERTIES LABELS
                "absolute-difference;advsimd;arm;extra-opcodes;integer;neon;sabd;uabd;vector")

        add_executable(
            cdisasm_arm_advsimd_absolute_difference_accumulate_tests
            tests/test_arm_advsimd_absolute_difference_accumulate.c)
        target_compile_features(
            cdisasm_arm_advsimd_absolute_difference_accumulate_tests
            PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_absolute_difference_accumulate_tests
            PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_absolute_difference_accumulate_tests
            COMMAND cdisasm_arm_advsimd_absolute_difference_accumulate_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_absolute_difference_accumulate_tests
            PROPERTIES LABELS
                "absolute-difference;accumulate;advsimd;arm;extra-opcodes;integer;neon;saba;uaba;vector")

        add_executable(
            cdisasm_arm_advsimd_multiply_accumulate_tests
            tests/test_arm_advsimd_multiply_accumulate.c)
        target_compile_features(
            cdisasm_arm_advsimd_multiply_accumulate_tests
            PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_multiply_accumulate_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_multiply_accumulate_tests
            COMMAND cdisasm_arm_advsimd_multiply_accumulate_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_multiply_accumulate_tests
            PROPERTIES LABELS
                "accumulate;advsimd;arm;extra-opcodes;integer;mla;mls;multiply;neon;vector")

        add_executable(
            cdisasm_arm_advsimd_fused_multiply_accumulate_tests
            tests/test_arm_advsimd_fused_multiply_accumulate.c)
        target_compile_features(
            cdisasm_arm_advsimd_fused_multiply_accumulate_tests
            PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_fused_multiply_accumulate_tests
            PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_fused_multiply_accumulate_tests
            COMMAND cdisasm_arm_advsimd_fused_multiply_accumulate_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_fused_multiply_accumulate_tests
            PROPERTIES LABELS
                "accumulate;advsimd;arm;extra-opcodes;floating-point;fused-multiply-add;neon;vfma;vfms;vector")

        add_executable(cdisasm_arm_scalar_fp16_arithmetic_tests
            tests/test_arm_scalar_fp16_arithmetic.c)
        target_compile_features(cdisasm_arm_scalar_fp16_arithmetic_tests
            PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_scalar_fp16_arithmetic_tests
            PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_scalar_fp16_arithmetic_tests
            COMMAND cdisasm_arm_scalar_fp16_arithmetic_tests)
        set_tests_properties(cdisasm_arm_scalar_fp16_arithmetic_tests
            PROPERTIES LABELS
                "arm;extra-opcodes;floating-point;fp16;scalar;vfma;vfms;vmla;vmls")

        add_executable(
            cdisasm_arm_advsimd_multiply_accumulate_element_tests
            tests/test_arm_advsimd_multiply_accumulate_element.c)
        target_compile_features(
            cdisasm_arm_advsimd_multiply_accumulate_element_tests
            PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_multiply_accumulate_element_tests
            PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_multiply_accumulate_element_tests
            COMMAND cdisasm_arm_advsimd_multiply_accumulate_element_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_multiply_accumulate_element_tests
            PROPERTIES LABELS
                "accumulate;advsimd;arm;by-element;extra-opcodes;integer;mla;mls;multiply;neon;smlal;smlsl;smull;sqdmlal;sqdmlsl;sqdmull;umlal;umlsl;umull;vector;widening")

        add_executable(
            cdisasm_arm_advsimd_high_narrow_tests
            tests/test_arm_advsimd_high_narrow.c)
        target_compile_features(
            cdisasm_arm_advsimd_high_narrow_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_high_narrow_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_high_narrow_tests
            COMMAND cdisasm_arm_advsimd_high_narrow_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_high_narrow_tests
            PROPERTIES LABELS
                "addhn;advsimd;arm;extra-opcodes;integer;neon;narrow;raddhn;rsubhn;subhn;vector")

        add_executable(
            cdisasm_arm_advsimd_narrow_widen_move_tests
            tests/test_arm_advsimd_narrow_widen_move.c)
        target_compile_features(
            cdisasm_arm_advsimd_narrow_widen_move_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_narrow_widen_move_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_narrow_widen_move_tests
            COMMAND cdisasm_arm_advsimd_narrow_widen_move_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_narrow_widen_move_tests
            PROPERTIES LABELS
                "advsimd;arm;extra-opcodes;integer;move;narrow;neon;shll;vector;widening;xtn")

        add_executable(
            cdisasm_arm_advsimd_widening_add_sub_tests
            tests/test_arm_advsimd_widening_add_sub.c)
        target_compile_features(
            cdisasm_arm_advsimd_widening_add_sub_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_widening_add_sub_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_widening_add_sub_tests
            COMMAND cdisasm_arm_advsimd_widening_add_sub_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_widening_add_sub_tests
            PROPERTIES LABELS
                "advsimd;arm;extra-opcodes;integer;neon;saddl;saddw;ssubl;ssubw;uaddl;uaddw;usubl;usubw;vector;widening")

        add_executable(
            cdisasm_arm_pauth_branch_tests
            tests/test_arm_pauth_branch.c)
        target_compile_features(
            cdisasm_arm_pauth_branch_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_pauth_branch_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_pauth_branch_tests
            COMMAND cdisasm_arm_pauth_branch_tests)
        set_tests_properties(
            cdisasm_arm_pauth_branch_tests
            PROPERTIES LABELS
                "arm;braa;braaz;brab;brabz;branch;call;control-flow;extra-opcodes;pauth;pointer-authentication")

        add_executable(
            cdisasm_arm_sme_fmul_tests
            tests/test_arm_sme_fmul.c)
        target_compile_features(
            cdisasm_arm_sme_fmul_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sme_fmul_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sme_fmul_tests
            COMMAND cdisasm_arm_sme_fmul_tests)
        set_tests_properties(
            cdisasm_arm_sme_fmul_tests
            PROPERTIES LABELS
                "arm;bf16;extra-opcodes;floating-point;scalable-vector;sme;sme2;sme2p2")

        add_executable(
            cdisasm_arm_sme_za_load_store_tests
            tests/test_arm_sme_za_load_store.c)
        target_compile_features(
            cdisasm_arm_sme_za_load_store_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sme_za_load_store_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sme_za_load_store_tests
            COMMAND cdisasm_arm_sme_za_load_store_tests)
        set_tests_properties(
            cdisasm_arm_sme_za_load_store_tests
            PROPERTIES LABELS
                "arm;extra-opcodes;load-store;matrix;memory;scalable-vector;sme;za")

        add_executable(
            cdisasm_arm_sme_za_contiguous_tests
            tests/test_arm_sme_za_contiguous.c)
        target_compile_features(
            cdisasm_arm_sme_za_contiguous_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sme_za_contiguous_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sme_za_contiguous_tests
            COMMAND cdisasm_arm_sme_za_contiguous_tests)
        set_tests_properties(
            cdisasm_arm_sme_za_contiguous_tests
            PROPERTIES LABELS
                "arm;extra-opcodes;load-store;matrix;memory;predicate;scalable-vector;sme;za")

        add_executable(
            cdisasm_arm_sme_mova_predicated_tests
            tests/test_arm_sme_mova_predicated.c)
        target_compile_features(
            cdisasm_arm_sme_mova_predicated_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sme_mova_predicated_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sme_mova_predicated_tests
            COMMAND cdisasm_arm_sme_mova_predicated_tests)
        set_tests_properties(
            cdisasm_arm_sme_mova_predicated_tests
            PROPERTIES LABELS
                "arm;extra-opcodes;matrix;mov;mova;predicate;scalable-vector;sme;za")

        add_executable(
            cdisasm_arm_sme2_mova_multi_tests
            tests/test_arm_sme2_mova_multi.c)
        target_compile_features(
            cdisasm_arm_sme2_mova_multi_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sme2_mova_multi_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sme2_mova_multi_tests
            COMMAND cdisasm_arm_sme2_mova_multi_tests)
        set_tests_properties(
            cdisasm_arm_sme2_mova_multi_tests
            PROPERTIES LABELS
                "arm;extra-opcodes;matrix;mov;mova;scalable-vector;sme;sme2;za")

        add_executable(
            cdisasm_arm_sme2p1_movaz_tests
            tests/test_arm_sme2p1_movaz.c)
        target_compile_features(
            cdisasm_arm_sme2p1_movaz_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sme2p1_movaz_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sme2p1_movaz_tests
            COMMAND cdisasm_arm_sme2p1_movaz_tests)
        set_tests_properties(
            cdisasm_arm_sme2p1_movaz_tests
            PROPERTIES LABELS
                "arm;extra-opcodes;matrix;movaz;scalable-vector;sme;sme2p1;za")

        add_executable(
            cdisasm_arm_sme2_zt0_load_store_tests
            tests/test_arm_sme2_zt0_load_store.c)
        target_compile_features(
            cdisasm_arm_sme2_zt0_load_store_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sme2_zt0_load_store_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sme2_zt0_load_store_tests
            COMMAND cdisasm_arm_sme2_zt0_load_store_tests)
        set_tests_properties(
            cdisasm_arm_sme2_zt0_load_store_tests
            PROPERTIES LABELS
                "arm;extra-opcodes;load-store;matrix;memory;sme;sme2;zt0")

        add_executable(
            cdisasm_arm_a64_udf_tests
            tests/test_arm_a64_udf.c)
        target_compile_features(
            cdisasm_arm_a64_udf_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_a64_udf_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_a64_udf_tests
            COMMAND cdisasm_arm_a64_udf_tests)
        set_tests_properties(
            cdisasm_arm_a64_udf_tests
            PROPERTIES LABELS
                "a64;arm;exception;extra-opcodes;system;udf")

        add_executable(
            cdisasm_arm_wfxt_tests
            tests/test_arm_wfxt.c)
        target_compile_features(
            cdisasm_arm_wfxt_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_wfxt_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_wfxt_tests
            COMMAND cdisasm_arm_wfxt_tests)
        set_tests_properties(
            cdisasm_arm_wfxt_tests
            PROPERTIES LABELS
                "a64;arm;extra-opcodes;system;wait;wfxt")

        add_executable(
            cdisasm_arm_flagm_tests
            tests/test_arm_flagm.c)
        target_compile_features(
            cdisasm_arm_flagm_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_flagm_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_flagm_tests
            COMMAND cdisasm_arm_flagm_tests)
        set_tests_properties(
            cdisasm_arm_flagm_tests
            PROPERTIES LABELS
                "a64;arm;extra-opcodes;flagm;flags;system")

        add_executable(
            cdisasm_arm_sve_ffr_tests
            tests/test_arm_sve_ffr.c)
        target_compile_features(
            cdisasm_arm_sve_ffr_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_ffr_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_ffr_tests
            COMMAND cdisasm_arm_sve_ffr_tests)
        set_tests_properties(
            cdisasm_arm_sve_ffr_tests
            PROPERTIES LABELS
                "a64;arm;extra-opcodes;ffr;flags;predicate;sve")

        add_executable(
            cdisasm_arm_sve_element_count_tests
            tests/test_arm_sve_element_count.c)
        target_compile_features(
            cdisasm_arm_sve_element_count_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_element_count_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_element_count_tests
            COMMAND cdisasm_arm_sve_element_count_tests)
        set_tests_properties(
            cdisasm_arm_sve_element_count_tests
            PROPERTIES LABELS
                "a64;arm;count;extra-opcodes;pattern;sve")

        add_executable(
            cdisasm_arm_sve_saturating_predicate_count_tests
            tests/test_arm_sve_saturating_predicate_count.c)
        target_compile_features(
            cdisasm_arm_sve_saturating_predicate_count_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_saturating_predicate_count_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_saturating_predicate_count_tests
            COMMAND cdisasm_arm_sve_saturating_predicate_count_tests)
        set_tests_properties(
            cdisasm_arm_sve_saturating_predicate_count_tests
            PROPERTIES LABELS
                "a64;arm;count;extra-opcodes;predicate;saturation;sve")

        add_executable(
            cdisasm_arm_sve_first_last_tests
            tests/test_arm_sve_first_last.c)
        target_compile_features(
            cdisasm_arm_sve_first_last_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_first_last_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_first_last_tests
            COMMAND cdisasm_arm_sve_first_last_tests)
        set_tests_properties(
            cdisasm_arm_sve_first_last_tests
            PROPERTIES LABELS
                "a64;arm;count;extra-opcodes;predicate;sve;sve2p2")

        add_executable(
            cdisasm_arm_sve_while_single_tests
            tests/test_arm_sve_while_single.c)
        target_compile_features(
            cdisasm_arm_sve_while_single_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_while_single_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_while_single_tests
            COMMAND cdisasm_arm_sve_while_single_tests)
        set_tests_properties(
            cdisasm_arm_sve_while_single_tests
            PROPERTIES LABELS
                "a64;arm;extra-opcodes;flags;predicate;sme;sve;sve2")

        add_executable(
            cdisasm_arm_sve_while_pair_tests
            tests/test_arm_sve_while_pair.c)
        target_compile_features(
            cdisasm_arm_sve_while_pair_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_while_pair_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_while_pair_tests
            COMMAND cdisasm_arm_sve_while_pair_tests)
        set_tests_properties(
            cdisasm_arm_sve_while_pair_tests
            PROPERTIES LABELS
                "a64;arm;extra-opcodes;flags;predicate;sme2;sve2p1")

        add_executable(
            cdisasm_arm_sve_while_counter_tests
            tests/test_arm_sve_while_counter.c)
        target_compile_features(
            cdisasm_arm_sve_while_counter_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_while_counter_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_while_counter_tests
            COMMAND cdisasm_arm_sve_while_counter_tests)
        set_tests_properties(
            cdisasm_arm_sve_while_counter_tests
            PROPERTIES LABELS
                "a64;arm;counter;extra-opcodes;flags;predicate;sme2;sve2p1")

        add_executable(
            cdisasm_arm_sve_counter_mask_tests
            tests/test_arm_sve_counter_mask.c)
        target_compile_features(
            cdisasm_arm_sve_counter_mask_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_counter_mask_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_counter_mask_tests
            COMMAND cdisasm_arm_sve_counter_mask_tests)
        set_tests_properties(
            cdisasm_arm_sve_counter_mask_tests
            PROPERTIES LABELS
                "a64;arm;counter;extra-opcodes;pext;predicate;ptrue;sme2;sve2p1")

        add_executable(
            cdisasm_arm_sve_predicate_control_tests
            tests/test_arm_sve_predicate_control.c)
        target_compile_features(
            cdisasm_arm_sve_predicate_control_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_predicate_control_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_predicate_control_tests
            COMMAND cdisasm_arm_sve_predicate_control_tests)
        set_tests_properties(
            cdisasm_arm_sve_predicate_control_tests
            PROPERTIES LABELS
                "a64;arm;extra-opcodes;flags;predicate;sme;sve")

        add_executable(
            cdisasm_arm_sve_psel_tests
            tests/test_arm_sve_psel.c)
        target_compile_features(
            cdisasm_arm_sve_psel_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_psel_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_psel_tests
            COMMAND cdisasm_arm_sve_psel_tests)
        set_tests_properties(
            cdisasm_arm_sve_psel_tests
            PROPERTIES LABELS
                "a64;arm;extra-opcodes;predicate;psel;sme;sve2p1")

        add_executable(
            cdisasm_arm_sve_punpk_tests
            tests/test_arm_sve_punpk.c)
        target_compile_features(
            cdisasm_arm_sve_punpk_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_punpk_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_punpk_tests
            COMMAND cdisasm_arm_sve_punpk_tests)
        set_tests_properties(
            cdisasm_arm_sve_punpk_tests
            PROPERTIES LABELS
                "a64;arm;extra-opcodes;permute;predicate;punpk;sme;sve")

        add_executable(
            cdisasm_arm_sve_unpack_tests
            tests/test_arm_sve_unpack.c)
        target_compile_features(
            cdisasm_arm_sve_unpack_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_unpack_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_unpack_tests
            COMMAND cdisasm_arm_sve_unpack_tests)
        set_tests_properties(
            cdisasm_arm_sve_unpack_tests
            PROPERTIES LABELS
                "a64;arm;extra-opcodes;permute;sme;sunpk;sve;uunpk;unpack")

        add_executable(
            cdisasm_arm_sve_predicate_break_tests
            tests/test_arm_sve_predicate_break.c)
        target_compile_features(
            cdisasm_arm_sve_predicate_break_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_predicate_break_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_predicate_break_tests
            COMMAND cdisasm_arm_sve_predicate_break_tests)
        set_tests_properties(
            cdisasm_arm_sve_predicate_break_tests
            PROPERTIES LABELS
                "a64;arm;break;extra-opcodes;flags;predicate;sme;sve")

        add_executable(
            cdisasm_arm_sve_cterm_tests
            tests/test_arm_sve_cterm.c)
        target_compile_features(
            cdisasm_arm_sve_cterm_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_cterm_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_cterm_tests
            COMMAND cdisasm_arm_sve_cterm_tests)
        set_tests_properties(
            cdisasm_arm_sve_cterm_tests
            PROPERTIES LABELS
                "a64;arm;extra-opcodes;flags;sme;sve")

        add_executable(
            cdisasm_arm_sve_whilewr_rw_tests
            tests/test_arm_sve_whilewr_rw.c)
        target_compile_features(
            cdisasm_arm_sve_whilewr_rw_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_whilewr_rw_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_whilewr_rw_tests
            COMMAND cdisasm_arm_sve_whilewr_rw_tests)
        set_tests_properties(
            cdisasm_arm_sve_whilewr_rw_tests
            PROPERTIES LABELS
                "a64;arm;extra-opcodes;flags;predicate;sme;sve2")

        add_executable(
            cdisasm_arm_neon_vector_permute_tests
            tests/test_arm_neon_vector_permute.c)
        target_compile_features(
            cdisasm_arm_neon_vector_permute_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_neon_vector_permute_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_neon_vector_permute_tests
            COMMAND cdisasm_arm_neon_vector_permute_tests)
        set_tests_properties(
            cdisasm_arm_neon_vector_permute_tests
            PROPERTIES LABELS "a64;arm;extra-opcodes;neon;permute")

        add_executable(
            cdisasm_arm_sve_predicate_logical_tests
            tests/test_arm_sve_predicate_logical.c)
        target_compile_features(
            cdisasm_arm_sve_predicate_logical_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_predicate_logical_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_predicate_logical_tests
            COMMAND cdisasm_arm_sve_predicate_logical_tests)
        set_tests_properties(
            cdisasm_arm_sve_predicate_logical_tests
            PROPERTIES LABELS "arm;extra-opcodes;predicate;sve")

        add_executable(
            cdisasm_arm_sve_integer_compare_tests
            tests/test_arm_sve_integer_compare.c)
        target_compile_features(
            cdisasm_arm_sve_integer_compare_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_integer_compare_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_integer_compare_tests
            COMMAND cdisasm_arm_sve_integer_compare_tests)
        set_tests_properties(
            cdisasm_arm_sve_integer_compare_tests
            PROPERTIES LABELS
                "arm;compare;extra-opcodes;integer;predicate;sme;sve")

        add_executable(
            cdisasm_arm_sve_integer_compare_immediate_tests
            tests/test_arm_sve_integer_compare_immediate.c)
        target_compile_features(
            cdisasm_arm_sve_integer_compare_immediate_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_integer_compare_immediate_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_integer_compare_immediate_tests
            COMMAND cdisasm_arm_sve_integer_compare_immediate_tests)
        set_tests_properties(
            cdisasm_arm_sve_integer_compare_immediate_tests
            PROPERTIES LABELS
                "arm;compare;extra-opcodes;immediate;integer;predicate;sme;sve")

        add_executable(
            cdisasm_arm_sve_floating_compare_zero_tests
            tests/test_arm_sve_floating_compare_zero.c)
        target_compile_features(
            cdisasm_arm_sve_floating_compare_zero_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_floating_compare_zero_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_floating_compare_zero_tests
            COMMAND cdisasm_arm_sve_floating_compare_zero_tests)
        set_tests_properties(
            cdisasm_arm_sve_floating_compare_zero_tests
            PROPERTIES LABELS
                "arm;compare;extra-opcodes;floating-point;predicate;sme;sve")

        add_executable(
            cdisasm_arm_sve_floating_compare_vectors_tests
            tests/test_arm_sve_floating_compare_vectors.c)
        target_compile_features(
            cdisasm_arm_sve_floating_compare_vectors_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_floating_compare_vectors_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_floating_compare_vectors_tests
            COMMAND cdisasm_arm_sve_floating_compare_vectors_tests)
        set_tests_properties(
            cdisasm_arm_sve_floating_compare_vectors_tests
            PROPERTIES LABELS
                "arm;compare;extra-opcodes;floating-point;predicate;sme;sve;vector")

        add_executable(
            cdisasm_arm_sve_predicated_fp_binary_tests
            tests/test_arm_sve_predicated_fp_binary.c)
        target_compile_features(
            cdisasm_arm_sve_predicated_fp_binary_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_predicated_fp_binary_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_predicated_fp_binary_tests
            COMMAND cdisasm_arm_sve_predicated_fp_binary_tests)
        set_tests_properties(
            cdisasm_arm_sve_predicated_fp_binary_tests
            PROPERTIES LABELS
                "arm;arithmetic;extra-opcodes;floating-point;predicate;sme;sve;vector")

        add_executable(
            cdisasm_arm_sve_fp_fast_reduction_tests
            tests/test_arm_sve_fp_fast_reduction.c)
        target_compile_features(
            cdisasm_arm_sve_fp_fast_reduction_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_fp_fast_reduction_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_fp_fast_reduction_tests
            COMMAND cdisasm_arm_sve_fp_fast_reduction_tests)
        set_tests_properties(
            cdisasm_arm_sve_fp_fast_reduction_tests
            PROPERTIES LABELS
                "arm;extra-opcodes;floating-point;predicate;reduction;sme;sve;vector")

        add_executable(
            cdisasm_arm_sve_fp_serial_reduction_tests
            tests/test_arm_sve_fp_serial_reduction.c)
        target_compile_features(
            cdisasm_arm_sve_fp_serial_reduction_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_fp_serial_reduction_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_fp_serial_reduction_tests
            COMMAND cdisasm_arm_sve_fp_serial_reduction_tests)
        set_tests_properties(
            cdisasm_arm_sve_fp_serial_reduction_tests
            PROPERTIES LABELS
                "arm;extra-opcodes;floating-point;predicate;reduction;sve;vector")

        add_executable(
            cdisasm_arm_sve_predicated_fp_unary_tests
            tests/test_arm_sve_predicated_fp_unary.c)
        target_compile_features(
            cdisasm_arm_sve_predicated_fp_unary_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_predicated_fp_unary_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_predicated_fp_unary_tests
            COMMAND cdisasm_arm_sve_predicated_fp_unary_tests)
        set_tests_properties(
            cdisasm_arm_sve_predicated_fp_unary_tests
            PROPERTIES LABELS
                "arm;extra-opcodes;floating-point;predicate;sme;sme2p2;sve;sve2p2;unary;vector")

        add_executable(
            cdisasm_arm_advsimd_fp_estimate_tests
            tests/test_arm_advsimd_fp_estimate.c)
        target_compile_features(
            cdisasm_arm_advsimd_fp_estimate_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_fp_estimate_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_fp_estimate_tests
            COMMAND cdisasm_arm_advsimd_fp_estimate_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_fp_estimate_tests
            PROPERTIES LABELS
                "advsimd;arm;estimate;extra-opcodes;floating-point;neon;scalar;vector")

        add_executable(
            cdisasm_arm_advsimd_fcvtns_tests
            tests/test_arm_advsimd_fcvtns.c)
        target_compile_features(
            cdisasm_arm_advsimd_fcvtns_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_fcvtns_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_fcvtns_tests
            COMMAND cdisasm_arm_advsimd_fcvtns_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_fcvtns_tests
            PROPERTIES LABELS
                "advsimd;arm;conversion;extra-opcodes;floating-point;fp16;neon;scalar;vector")

        add_executable(
            cdisasm_arm_advsimd_i8mm_mmla_tests
            tests/test_arm_advsimd_i8mm_mmla.c)
        target_compile_features(
            cdisasm_arm_advsimd_i8mm_mmla_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_i8mm_mmla_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_i8mm_mmla_tests
            COMMAND cdisasm_arm_advsimd_i8mm_mmla_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_i8mm_mmla_tests
            PROPERTIES LABELS
                "advsimd;arm;extra-opcodes;i8mm;matrix;neon;vector")

        add_executable(
            cdisasm_arm_advsimd_frintts_tests
            tests/test_arm_advsimd_frintts.c)
        target_compile_features(
            cdisasm_arm_advsimd_frintts_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_frintts_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_frintts_tests
            COMMAND cdisasm_arm_advsimd_frintts_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_frintts_tests
            PROPERTIES LABELS
                "advsimd;arm;extra-opcodes;floating-point;frintts;neon;vector")

        add_executable(
            cdisasm_arm_a64_fp_compare_tests
            tests/test_arm_a64_fp_compare.c)
        target_compile_features(
            cdisasm_arm_a64_fp_compare_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_a64_fp_compare_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_a64_fp_compare_tests
            COMMAND cdisasm_arm_a64_fp_compare_tests)
        set_tests_properties(
            cdisasm_arm_a64_fp_compare_tests
            PROPERTIES LABELS
                "arm;compare;extra-opcodes;floating-point;fp16;scalar")

        add_executable(
            cdisasm_arm_a64_fp_conditional_compare_tests
            tests/test_arm_a64_fp_conditional_compare.c)
        target_compile_features(
            cdisasm_arm_a64_fp_conditional_compare_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_a64_fp_conditional_compare_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_a64_fp_conditional_compare_tests
            COMMAND cdisasm_arm_a64_fp_conditional_compare_tests)
        set_tests_properties(
            cdisasm_arm_a64_fp_conditional_compare_tests
            PROPERTIES LABELS
                "arm;compare;conditional;extra-opcodes;floating-point;fp16;scalar")

        add_executable(
            cdisasm_arm_a64_logical_inverted_tests
            tests/test_arm_a64_logical_inverted.c)
        target_compile_features(
            cdisasm_arm_a64_logical_inverted_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_a64_logical_inverted_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_a64_logical_inverted_tests
            COMMAND cdisasm_arm_a64_logical_inverted_tests)
        set_tests_properties(
            cdisasm_arm_a64_logical_inverted_tests
            PROPERTIES LABELS
                "a64;arm;bic;bics;eon;logical;orn;shift")

        add_executable(
            cdisasm_arm_advsimd_fp_unary_sd_tests
            tests/test_arm_advsimd_fp_unary_sd.c)
        target_compile_features(
            cdisasm_arm_advsimd_fp_unary_sd_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_fp_unary_sd_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_fp_unary_sd_tests
            COMMAND cdisasm_arm_advsimd_fp_unary_sd_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_fp_unary_sd_tests
            PROPERTIES LABELS
                "advsimd;arm;extra-opcodes;fabs;floating-point;fneg;fsqrt;neon;vector")

        add_executable(cdisasm_arm_advsimd_fp_convert_vector_tests
            tests/test_arm_advsimd_fp_convert_vector.c)
        target_compile_features(cdisasm_arm_advsimd_fp_convert_vector_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_advsimd_fp_convert_vector_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_advsimd_fp_convert_vector_tests
            COMMAND cdisasm_arm_advsimd_fp_convert_vector_tests)
        set_tests_properties(cdisasm_arm_advsimd_fp_convert_vector_tests PROPERTIES LABELS
            "advsimd;arm;convert;extra-opcodes;floating-point;neon;round;vector")

        add_executable(cdisasm_arm_advsimd_fhm_three_same_tests
            tests/test_arm_advsimd_fhm_three_same.c)
        target_compile_features(cdisasm_arm_advsimd_fhm_three_same_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_advsimd_fhm_three_same_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_advsimd_fhm_three_same_tests
            COMMAND cdisasm_arm_advsimd_fhm_three_same_tests)
        set_tests_properties(cdisasm_arm_advsimd_fhm_three_same_tests PROPERTIES LABELS
            "advsimd;arm;extra-opcodes;fhm;floating-point;fmlal;fmlsl;vector")

        add_executable(
            cdisasm_arm_advsimd_fp_three_same_sd_tests
            tests/test_arm_advsimd_fp_three_same_sd.c)
        target_compile_features(
            cdisasm_arm_advsimd_fp_three_same_sd_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_fp_three_same_sd_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_fp_three_same_sd_tests
            COMMAND cdisasm_arm_advsimd_fp_three_same_sd_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_fp_three_same_sd_tests
            PROPERTIES LABELS
                "advsimd;arm;compare;extra-opcodes;floating-point;minmax;neon;pairwise;vector")

        add_executable(
            cdisasm_arm_advsimd_integer_three_same_tests
            tests/test_arm_advsimd_integer_three_same.c)
        target_compile_features(
            cdisasm_arm_advsimd_integer_three_same_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_integer_three_same_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_integer_three_same_tests
            COMMAND cdisasm_arm_advsimd_integer_three_same_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_integer_three_same_tests
            PROPERTIES LABELS
                "advsimd;arm;extra-opcodes;halving;integer;neon;saturating;shift;vector")

        add_executable(
            cdisasm_arm_advsimd_fp_three_same_scalar_sd_tests
            tests/test_arm_advsimd_fp_three_same_scalar_sd.c)
        target_compile_features(
            cdisasm_arm_advsimd_fp_three_same_scalar_sd_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_fp_three_same_scalar_sd_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_fp_three_same_scalar_sd_tests
            COMMAND cdisasm_arm_advsimd_fp_three_same_scalar_sd_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_fp_three_same_scalar_sd_tests
            PROPERTIES LABELS
                "advsimd;arm;compare;extra-opcodes;floating-point;neon;scalar")

        add_executable(
            cdisasm_arm_advsimd_fp_reciprocal_step_tests
            tests/test_arm_advsimd_fp_reciprocal_step.c)
        target_compile_features(
            cdisasm_arm_advsimd_fp_reciprocal_step_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_fp_reciprocal_step_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_fp_reciprocal_step_tests
            COMMAND cdisasm_arm_advsimd_fp_reciprocal_step_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_fp_reciprocal_step_tests
            PROPERTIES LABELS
                "advsimd;arm;extra-opcodes;floating-point;fp16;frecps;frsqrts;neon;reciprocal;scalar;vector")

        add_executable(cdisasm_arm_sve_fp_reciprocal_step_tests
            tests/test_arm_sve_fp_reciprocal_step.c)
        target_compile_features(cdisasm_arm_sve_fp_reciprocal_step_tests
            PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_fp_reciprocal_step_tests
            PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_fp_reciprocal_step_tests
            COMMAND cdisasm_arm_sve_fp_reciprocal_step_tests)
        set_tests_properties(cdisasm_arm_sve_fp_reciprocal_step_tests
            PROPERTIES LABELS
                "arm;extra-opcodes;floating-point;frecps;frsqrts;reciprocal;sme;sve")

        add_executable(cdisasm_arm_sve_ftsmul_tests
            tests/test_arm_sve_ftsmul.c)
        target_compile_features(cdisasm_arm_sve_ftsmul_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_ftsmul_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_ftsmul_tests
            COMMAND cdisasm_arm_sve_ftsmul_tests)
        set_tests_properties(cdisasm_arm_sve_ftsmul_tests PROPERTIES
            LABELS "arm;extra-opcodes;floating-point;ftsmul;sve")

        add_executable(cdisasm_arm_sve_fcmla_tests
            tests/test_arm_sve_fcmla.c)
        target_compile_features(cdisasm_arm_sve_fcmla_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_fcmla_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_fcmla_tests
            COMMAND cdisasm_arm_sve_fcmla_tests)
        set_tests_properties(cdisasm_arm_sve_fcmla_tests PROPERTIES
            LABELS "arm;complex;extra-opcodes;fcmla;floating-point;sme;sve")

        add_executable(cdisasm_arm_sve_whole_register_load_store_tests
            tests/test_arm_sve_whole_register_load_store.c)
        target_compile_features(cdisasm_arm_sve_whole_register_load_store_tests
            PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_whole_register_load_store_tests
            PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_whole_register_load_store_tests
            COMMAND cdisasm_arm_sve_whole_register_load_store_tests)
        set_tests_properties(cdisasm_arm_sve_whole_register_load_store_tests
            PROPERTIES LABELS
                "arm;extra-opcodes;load-store;memory;sme;sve")

        add_executable(cdisasm_arm_sve_contiguous_load_tests
            tests/test_arm_sve_contiguous_load.c)
        target_compile_features(cdisasm_arm_sve_contiguous_load_tests
            PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_contiguous_load_tests
            PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_contiguous_load_tests
            COMMAND cdisasm_arm_sve_contiguous_load_tests)
        set_tests_properties(cdisasm_arm_sve_contiguous_load_tests PROPERTIES
            LABELS "arm;extra-opcodes;ld1;load-store;memory;sme;sve")

        add_executable(cdisasm_arm_sve_contiguous_store_tests
            tests/test_arm_sve_contiguous_store.c)
        target_compile_features(cdisasm_arm_sve_contiguous_store_tests
            PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_contiguous_store_tests
            PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_contiguous_store_tests
            COMMAND cdisasm_arm_sve_contiguous_store_tests)
        set_tests_properties(cdisasm_arm_sve_contiguous_store_tests PROPERTIES
            LABELS "arm;extra-opcodes;load-store;memory;sme;st1;sve")

        add_executable(cdisasm_arm_sve_contiguous_load_register_tests
            tests/test_arm_sve_contiguous_load_register.c)
        target_compile_features(cdisasm_arm_sve_contiguous_load_register_tests
            PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_contiguous_load_register_tests
            PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_contiguous_load_register_tests
            COMMAND cdisasm_arm_sve_contiguous_load_register_tests)
        set_tests_properties(cdisasm_arm_sve_contiguous_load_register_tests
            PROPERTIES LABELS
                "arm;extra-opcodes;ld1;load-store;memory;sme;sve")

        add_executable(cdisasm_arm_sve_first_fault_load_tests
            tests/test_arm_sve_first_fault_load.c)
        target_compile_features(cdisasm_arm_sve_first_fault_load_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_first_fault_load_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_first_fault_load_tests
            COMMAND cdisasm_arm_sve_first_fault_load_tests)
        set_tests_properties(cdisasm_arm_sve_first_fault_load_tests PROPERTIES
            LABELS "arm;extra-opcodes;first-fault;load;memory;sve;vector")

        add_executable(cdisasm_arm_sve_non_faulting_load_tests
            tests/test_arm_sve_non_faulting_load.c)
        target_compile_features(cdisasm_arm_sve_non_faulting_load_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_non_faulting_load_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_non_faulting_load_tests
            COMMAND cdisasm_arm_sve_non_faulting_load_tests)
        set_tests_properties(cdisasm_arm_sve_non_faulting_load_tests PROPERTIES
            LABELS "arm;extra-opcodes;load;memory;non-faulting;sve;vector")

        add_executable(cdisasm_arm_sve_non_temporal_load_tests
            tests/test_arm_sve_non_temporal_load.c)
        target_compile_features(cdisasm_arm_sve_non_temporal_load_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_non_temporal_load_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_non_temporal_load_tests
            COMMAND cdisasm_arm_sve_non_temporal_load_tests)
        set_tests_properties(cdisasm_arm_sve_non_temporal_load_tests PROPERTIES
            LABELS "arm;extra-opcodes;load;memory;non-temporal;sme;sve;vector")

        add_executable(cdisasm_arm_sve_gather_load_tests
            tests/test_arm_sve_gather_load.c)
        target_compile_features(cdisasm_arm_sve_gather_load_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_gather_load_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_gather_load_tests
            COMMAND cdisasm_arm_sve_gather_load_tests)
        set_tests_properties(cdisasm_arm_sve_gather_load_tests PROPERTIES
            LABELS "arm;extra-opcodes;gather;load;memory;sve;vector")

        add_executable(cdisasm_arm_sve_gather_load_scaled_tests
            tests/test_arm_sve_gather_load_scaled.c)
        target_compile_features(cdisasm_arm_sve_gather_load_scaled_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_gather_load_scaled_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_gather_load_scaled_tests
            COMMAND cdisasm_arm_sve_gather_load_scaled_tests)
        set_tests_properties(cdisasm_arm_sve_gather_load_scaled_tests PROPERTIES
            LABELS "arm;extra-opcodes;gather;load;memory;scaled;sve;vector")

        add_executable(cdisasm_arm_sve_gather_load_vector_immediate_tests
            tests/test_arm_sve_gather_load_vector_immediate.c)
        target_compile_features(cdisasm_arm_sve_gather_load_vector_immediate_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_gather_load_vector_immediate_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_gather_load_vector_immediate_tests
            COMMAND cdisasm_arm_sve_gather_load_vector_immediate_tests)
        set_tests_properties(cdisasm_arm_sve_gather_load_vector_immediate_tests PROPERTIES
            LABELS "arm;extra-opcodes;gather;immediate;load;memory;sve;vector")

        add_executable(cdisasm_arm_sve_gather_load64_x32_unscaled_tests
            tests/test_arm_sve_gather_load64_x32_unscaled.c)
        target_compile_features(cdisasm_arm_sve_gather_load64_x32_unscaled_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_gather_load64_x32_unscaled_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_gather_load64_x32_unscaled_tests
            COMMAND cdisasm_arm_sve_gather_load64_x32_unscaled_tests)
        set_tests_properties(cdisasm_arm_sve_gather_load64_x32_unscaled_tests PROPERTIES
            LABELS "arm;extra-opcodes;gather;load;memory;sve;unscaled;vector")

        add_executable(cdisasm_arm_sve_gather_load64_x32_scaled_tests
            tests/test_arm_sve_gather_load64_x32_scaled.c)
        target_compile_features(cdisasm_arm_sve_gather_load64_x32_scaled_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_gather_load64_x32_scaled_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_gather_load64_x32_scaled_tests
            COMMAND cdisasm_arm_sve_gather_load64_x32_scaled_tests)
        set_tests_properties(cdisasm_arm_sve_gather_load64_x32_scaled_tests PROPERTIES
            LABELS "arm;extra-opcodes;gather;load;memory;scaled;sve;vector")

        add_executable(cdisasm_arm_sve_gather_load64_x64_unscaled_tests
            tests/test_arm_sve_gather_load64_x64_unscaled.c)
        target_compile_features(cdisasm_arm_sve_gather_load64_x64_unscaled_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_gather_load64_x64_unscaled_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_gather_load64_x64_unscaled_tests
            COMMAND cdisasm_arm_sve_gather_load64_x64_unscaled_tests)
        set_tests_properties(cdisasm_arm_sve_gather_load64_x64_unscaled_tests PROPERTIES
            LABELS "arm;extra-opcodes;gather;load;memory;sve;unscaled;vector")

        add_executable(cdisasm_arm_sve_gather_load64_x64_scaled_tests
            tests/test_arm_sve_gather_load64_x64_scaled.c)
        target_compile_features(cdisasm_arm_sve_gather_load64_x64_scaled_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_gather_load64_x64_scaled_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_gather_load64_x64_scaled_tests
            COMMAND cdisasm_arm_sve_gather_load64_x64_scaled_tests)
        set_tests_properties(cdisasm_arm_sve_gather_load64_x64_scaled_tests PROPERTIES
            LABELS "arm;extra-opcodes;gather;load;memory;scaled;sve;vector")

        add_executable(cdisasm_arm_sve_gather_load64_vector_immediate_tests
            tests/test_arm_sve_gather_load64_vector_immediate.c)
        target_compile_features(cdisasm_arm_sve_gather_load64_vector_immediate_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_gather_load64_vector_immediate_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_gather_load64_vector_immediate_tests
            COMMAND cdisasm_arm_sve_gather_load64_vector_immediate_tests)
        set_tests_properties(cdisasm_arm_sve_gather_load64_vector_immediate_tests PROPERTIES
            LABELS "arm;extra-opcodes;gather;immediate;load;memory;sve;vector")

        add_executable(cdisasm_arm_sve_gather_prefetch_tests
            tests/test_arm_sve_gather_prefetch.c)
        target_compile_features(cdisasm_arm_sve_gather_prefetch_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_gather_prefetch_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_gather_prefetch_tests
            COMMAND cdisasm_arm_sve_gather_prefetch_tests)
        set_tests_properties(cdisasm_arm_sve_gather_prefetch_tests PROPERTIES
            LABELS "arm;extra-opcodes;gather;memory;prefetch;sve;vector")

        add_executable(cdisasm_arm_sve_gather_prefetch64_tests
            tests/test_arm_sve_gather_prefetch64.c)
        target_compile_features(cdisasm_arm_sve_gather_prefetch64_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_gather_prefetch64_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_gather_prefetch64_tests
            COMMAND cdisasm_arm_sve_gather_prefetch64_tests)
        set_tests_properties(cdisasm_arm_sve_gather_prefetch64_tests PROPERTIES
            LABELS "arm;extra-opcodes;gather;memory;prefetch;scaled;sve;vector")

        add_executable(cdisasm_arm_sve_gather_prefetch64_x32_tests
            tests/test_arm_sve_gather_prefetch64_x32.c)
        target_compile_features(cdisasm_arm_sve_gather_prefetch64_x32_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_gather_prefetch64_x32_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_gather_prefetch64_x32_tests
            COMMAND cdisasm_arm_sve_gather_prefetch64_x32_tests)
        set_tests_properties(cdisasm_arm_sve_gather_prefetch64_x32_tests PROPERTIES
            LABELS "arm;extra-opcodes;gather;memory;prefetch;scaled;sve;vector")

        add_executable(cdisasm_arm_sve_prefetch_immediate_tests
            tests/test_arm_sve_prefetch_immediate.c)
        target_compile_features(cdisasm_arm_sve_prefetch_immediate_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_prefetch_immediate_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_prefetch_immediate_tests
            COMMAND cdisasm_arm_sve_prefetch_immediate_tests)
        set_tests_properties(cdisasm_arm_sve_prefetch_immediate_tests PROPERTIES
            LABELS "arm;extra-opcodes;immediate;memory;prefetch;sve;vector")

        add_executable(cdisasm_arm_sve_prefetch_scalar_register_tests
            tests/test_arm_sve_prefetch_scalar_register.c)
        target_compile_features(cdisasm_arm_sve_prefetch_scalar_register_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_prefetch_scalar_register_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_prefetch_scalar_register_tests
            COMMAND cdisasm_arm_sve_prefetch_scalar_register_tests)
        set_tests_properties(cdisasm_arm_sve_prefetch_scalar_register_tests PROPERTIES
            LABELS "arm;extra-opcodes;memory;prefetch;register;sve;vector")

        add_executable(cdisasm_arm_sve_prefetch_vector_immediate_tests
            tests/test_arm_sve_prefetch_vector_immediate.c)
        target_compile_features(cdisasm_arm_sve_prefetch_vector_immediate_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_prefetch_vector_immediate_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_prefetch_vector_immediate_tests
            COMMAND cdisasm_arm_sve_prefetch_vector_immediate_tests)
        set_tests_properties(cdisasm_arm_sve_prefetch_vector_immediate_tests PROPERTIES
            LABELS "arm;extra-opcodes;immediate;memory;prefetch;sve;vector")

        add_executable(cdisasm_arm_sve_prefetch64_vector_immediate_tests
            tests/test_arm_sve_prefetch64_vector_immediate.c)
        target_compile_features(cdisasm_arm_sve_prefetch64_vector_immediate_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_prefetch64_vector_immediate_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_prefetch64_vector_immediate_tests
            COMMAND cdisasm_arm_sve_prefetch64_vector_immediate_tests)
        set_tests_properties(cdisasm_arm_sve_prefetch64_vector_immediate_tests PROPERTIES
            LABELS "arm;extra-opcodes;immediate;memory;prefetch;sve;vector")

        add_executable(cdisasm_arm_sve_non_temporal_store_tests
            tests/test_arm_sve_non_temporal_store.c)
        target_compile_features(cdisasm_arm_sve_non_temporal_store_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_non_temporal_store_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_non_temporal_store_tests
            COMMAND cdisasm_arm_sve_non_temporal_store_tests)
        set_tests_properties(cdisasm_arm_sve_non_temporal_store_tests PROPERTIES
            LABELS "arm;extra-opcodes;memory;non-temporal;sme;store;sve;vector")

        add_executable(cdisasm_arm_sve_multi_contiguous_load_tests
            tests/test_arm_sve_multi_contiguous_load.c)
        target_compile_features(cdisasm_arm_sve_multi_contiguous_load_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_multi_contiguous_load_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_multi_contiguous_load_tests
            COMMAND cdisasm_arm_sve_multi_contiguous_load_tests)
        set_tests_properties(cdisasm_arm_sve_multi_contiguous_load_tests PROPERTIES
            LABELS "arm;extra-opcodes;load;memory;multi-register;sme;sve;vector")

        add_executable(cdisasm_arm_sve_multi_contiguous_store_tests
            tests/test_arm_sve_multi_contiguous_store.c)
        target_compile_features(cdisasm_arm_sve_multi_contiguous_store_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_multi_contiguous_store_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_multi_contiguous_store_tests
            COMMAND cdisasm_arm_sve_multi_contiguous_store_tests)
        set_tests_properties(cdisasm_arm_sve_multi_contiguous_store_tests PROPERTIES
            LABELS "arm;extra-opcodes;memory;multi-register;sme;store;sve;vector")

        add_executable(cdisasm_arm_sve_contiguous_store_register_tests
            tests/test_arm_sve_contiguous_store_register.c)
        target_compile_features(cdisasm_arm_sve_contiguous_store_register_tests
            PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_contiguous_store_register_tests
            PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_contiguous_store_register_tests
            COMMAND cdisasm_arm_sve_contiguous_store_register_tests)
        set_tests_properties(cdisasm_arm_sve_contiguous_store_register_tests
            PROPERTIES LABELS
                "arm;extra-opcodes;load-store;memory;sme;st1;sve")

        add_executable(cdisasm_arm_sve2p1_q_load_store_tests
            tests/test_arm_sve2p1_q_load_store.c)
        target_compile_features(cdisasm_arm_sve2p1_q_load_store_tests
            PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve2p1_q_load_store_tests
            PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve2p1_q_load_store_tests
            COMMAND cdisasm_arm_sve2p1_q_load_store_tests)
        set_tests_properties(cdisasm_arm_sve2p1_q_load_store_tests PROPERTIES
            LABELS "arm;extra-opcodes;load-store;memory;sve;sve2p1")

        add_executable(cdisasm_arm_sve_replicate_load_tests
            tests/test_arm_sve_replicate_load.c)
        target_compile_features(cdisasm_arm_sve_replicate_load_tests
            PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_replicate_load_tests
            PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_replicate_load_tests
            COMMAND cdisasm_arm_sve_replicate_load_tests)
        set_tests_properties(cdisasm_arm_sve_replicate_load_tests PROPERTIES
            LABELS "arm;extra-opcodes;load;memory;sme;sve;vector")

        add_executable(cdisasm_arm_sve_replicate_block_load_tests
            tests/test_arm_sve_replicate_block_load.c)
        target_compile_features(cdisasm_arm_sve_replicate_block_load_tests
            PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_replicate_block_load_tests
            PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_replicate_block_load_tests
            COMMAND cdisasm_arm_sve_replicate_block_load_tests)
        set_tests_properties(cdisasm_arm_sve_replicate_block_load_tests PROPERTIES
            LABELS "arm;extra-opcodes;f64mm;load;memory;sme;sve;vector")

        add_executable(cdisasm_arm_sve2p1_multi_contiguous_load_store_tests
            tests/test_arm_sve2p1_multi_contiguous_load_store.c)
        target_compile_features(cdisasm_arm_sve2p1_multi_contiguous_load_store_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve2p1_multi_contiguous_load_store_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve2p1_multi_contiguous_load_store_tests
            COMMAND cdisasm_arm_sve2p1_multi_contiguous_load_store_tests)
        set_tests_properties(cdisasm_arm_sve2p1_multi_contiguous_load_store_tests PROPERTIES
            LABELS "arm;extra-opcodes;load-store;memory;sme2;sve;sve2p1")

        add_executable(cdisasm_arm_t32_wide_cps_tests tests/test_arm_t32_wide_cps.c)
        target_compile_features(cdisasm_arm_t32_wide_cps_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_t32_wide_cps_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_t32_wide_cps_tests COMMAND cdisasm_arm_t32_wide_cps_tests)
        set_tests_properties(cdisasm_arm_t32_wide_cps_tests PROPERTIES LABELS "arm;extra-opcodes;privileged;t32")

        add_executable(cdisasm_arm_sme_fmopa_variant_tests tests/test_arm_sme_fmopa_variants.c)
        target_compile_features(cdisasm_arm_sme_fmopa_variant_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sme_fmopa_variant_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sme_fmopa_variant_tests COMMAND cdisasm_arm_sme_fmopa_variant_tests)
        set_tests_properties(cdisasm_arm_sme_fmopa_variant_tests PROPERTIES LABELS "arm;extra-opcodes;floating-point;sme")
        add_executable(cdisasm_arm_sme_product_tests tests/test_arm_sme_product.c)
        target_compile_features(cdisasm_arm_sme_product_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sme_product_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sme_product_tests COMMAND cdisasm_arm_sme_product_tests)
        set_tests_properties(cdisasm_arm_sme_product_tests PROPERTIES LABELS "arm;extra-opcodes;sme;matrix;product")
        add_executable(cdisasm_arm_sme2_zero_zt0_tests tests/test_arm_sme2_zero_zt0.c)
        target_compile_features(cdisasm_arm_sme2_zero_zt0_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sme2_zero_zt0_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sme2_zero_zt0_tests COMMAND cdisasm_arm_sme2_zero_zt0_tests)
        set_tests_properties(cdisasm_arm_sme2_zero_zt0_tests PROPERTIES LABELS "arm;extra-opcodes;sme2;zt0")
        add_executable(cdisasm_arm_sme2_luti_zt0_tests tests/test_arm_sme2_luti_zt0.c)
        target_compile_features(cdisasm_arm_sme2_luti_zt0_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sme2_luti_zt0_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sme2_luti_zt0_tests COMMAND cdisasm_arm_sme2_luti_zt0_tests)
        set_tests_properties(cdisasm_arm_sme2_luti_zt0_tests PROPERTIES LABELS "arm;extra-opcodes;sme2;zt0;lookup")
        add_executable(cdisasm_arm_sme2_indexed_long_mla_tests tests/test_arm_sme2_indexed_long_mla.c)
        target_compile_features(cdisasm_arm_sme2_indexed_long_mla_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sme2_indexed_long_mla_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sme2_indexed_long_mla_tests COMMAND cdisasm_arm_sme2_indexed_long_mla_tests)
        set_tests_properties(cdisasm_arm_sme2_indexed_long_mla_tests PROPERTIES LABELS "arm;extra-opcodes;sme2;matrix;multiply")
        add_executable(cdisasm_arm_sme_fvdot_indexed_tests tests/test_arm_sme_fvdot_indexed.c)
        target_compile_features(cdisasm_arm_sme_fvdot_indexed_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sme_fvdot_indexed_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sme_fvdot_indexed_tests COMMAND cdisasm_arm_sme_fvdot_indexed_tests)
        set_tests_properties(cdisasm_arm_sme_fvdot_indexed_tests PROPERTIES LABELS "arm;extra-opcodes;sme;sme2;matrix;floating-point;indexed")

        add_executable(cdisasm_arm_advsimd_fcmla_tests
            tests/test_arm_advsimd_fcmla.c)
        target_compile_features(cdisasm_arm_advsimd_fcmla_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_advsimd_fcmla_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_advsimd_fcmla_tests
            COMMAND cdisasm_arm_advsimd_fcmla_tests)
        set_tests_properties(cdisasm_arm_advsimd_fcmla_tests PROPERTIES
            LABELS "advsimd;arm;complex;extra-opcodes;fcma;fcmla;floating-point;neon")

        add_executable(cdisasm_arm_sve_aes2_multi_tests
            tests/test_arm_sve_aes2_multi.c)
        target_compile_features(cdisasm_arm_sve_aes2_multi_tests
            PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_sve_aes2_multi_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_sve_aes2_multi_tests
            COMMAND cdisasm_arm_sve_aes2_multi_tests)
        set_tests_properties(cdisasm_arm_sve_aes2_multi_tests PROPERTIES
            LABELS "aes;aes2;arm;crypto;extra-opcodes;multi-vector;pmull;sve")

        add_executable(
            cdisasm_arm_advsimd_fcvtxn_tests
            tests/test_arm_advsimd_fcvtxn.c)
        target_compile_features(cdisasm_arm_advsimd_fcvtxn_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_advsimd_fcvtxn_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_advsimd_fcvtxn_tests
            COMMAND cdisasm_arm_advsimd_fcvtxn_tests)
        set_tests_properties(cdisasm_arm_advsimd_fcvtxn_tests PROPERTIES
            LABELS "advsimd;arm;extra-opcodes;fcvtxn;floating-point;narrow;neon;scalar;vector")

        add_executable(cdisasm_arm_advsimd_dup_element_tests
            tests/test_arm_advsimd_dup_element.c)
        target_compile_features(cdisasm_arm_advsimd_dup_element_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_advsimd_dup_element_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_advsimd_dup_element_tests
            COMMAND cdisasm_arm_advsimd_dup_element_tests)
        set_tests_properties(cdisasm_arm_advsimd_dup_element_tests PROPERTIES
            LABELS "advsimd;arm;copy;dup;extra-opcodes;lane;neon;scalar;vector")

        add_executable(cdisasm_arm_advsimd_dup_gpr_tests
            tests/test_arm_advsimd_dup_gpr.c)
        target_compile_features(cdisasm_arm_advsimd_dup_gpr_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_advsimd_dup_gpr_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_advsimd_dup_gpr_tests
            COMMAND cdisasm_arm_advsimd_dup_gpr_tests)
        set_tests_properties(cdisasm_arm_advsimd_dup_gpr_tests PROPERTIES
            LABELS "advsimd;arm;copy;dup;extra-opcodes;gpr;neon;vector")

        add_executable(cdisasm_arm_advsimd_lane_to_gpr_tests
            tests/test_arm_advsimd_lane_to_gpr.c)
        target_compile_features(cdisasm_arm_advsimd_lane_to_gpr_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_advsimd_lane_to_gpr_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_advsimd_lane_to_gpr_tests
            COMMAND cdisasm_arm_advsimd_lane_to_gpr_tests)
        set_tests_properties(cdisasm_arm_advsimd_lane_to_gpr_tests PROPERTIES
            LABELS "advsimd;arm;copy;extra-opcodes;gpr;lane;neon;smov;umov")

        add_executable(cdisasm_arm_advsimd_ins_tests
            tests/test_arm_advsimd_ins.c)
        target_compile_features(cdisasm_arm_advsimd_ins_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_advsimd_ins_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_advsimd_ins_tests
            COMMAND cdisasm_arm_advsimd_ins_tests)
        set_tests_properties(cdisasm_arm_advsimd_ins_tests PROPERTIES
            LABELS "advsimd;arm;copy;extra-opcodes;gpr;ins;lane;neon;vector")

        add_executable(cdisasm_arm_advsimd_structure_ldst_single_tests
            tests/test_arm_advsimd_structure_ldst_single.c)
        target_compile_features(cdisasm_arm_advsimd_structure_ldst_single_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_advsimd_structure_ldst_single_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_advsimd_structure_ldst_single_tests
            COMMAND cdisasm_arm_advsimd_structure_ldst_single_tests)
        set_tests_properties(cdisasm_arm_advsimd_structure_ldst_single_tests PROPERTIES
            LABELS "advsimd;arm;extra-opcodes;ld1;load;memory;neon;st1;store;structure")

        add_executable(cdisasm_arm_advsimd_structure_ldst_pair_tests
            tests/test_arm_advsimd_structure_ldst_pair.c)
        target_compile_features(cdisasm_arm_advsimd_structure_ldst_pair_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_advsimd_structure_ldst_pair_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_advsimd_structure_ldst_pair_tests
            COMMAND cdisasm_arm_advsimd_structure_ldst_pair_tests)
        set_tests_properties(cdisasm_arm_advsimd_structure_ldst_pair_tests PROPERTIES
            LABELS "advsimd;arm;extra-opcodes;ld1;ld2;load;memory;neon;st1;st2;store;structure")

        add_executable(cdisasm_arm_advsimd_structure_ldst_multi_tests
            tests/test_arm_advsimd_structure_ldst_multi.c)
        target_compile_features(cdisasm_arm_advsimd_structure_ldst_multi_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_advsimd_structure_ldst_multi_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_advsimd_structure_ldst_multi_tests
            COMMAND cdisasm_arm_advsimd_structure_ldst_multi_tests)
        set_tests_properties(cdisasm_arm_advsimd_structure_ldst_multi_tests PROPERTIES
            LABELS "advsimd;arm;extra-opcodes;ld1;ld3;ld4;load;memory;neon;st1;st3;st4;store;structure")

        add_executable(cdisasm_arm_advsimd_structure_ldst_postindex_tests
            tests/test_arm_advsimd_structure_ldst_postindex.c)
        target_compile_features(cdisasm_arm_advsimd_structure_ldst_postindex_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_advsimd_structure_ldst_postindex_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_advsimd_structure_ldst_postindex_tests
            COMMAND cdisasm_arm_advsimd_structure_ldst_postindex_tests)
        set_tests_properties(cdisasm_arm_advsimd_structure_ldst_postindex_tests PROPERTIES
            LABELS "advsimd;arm;extra-opcodes;ld1;ld2;ld3;ld4;load;memory;neon;post-index;st1;st2;st3;st4;store;structure;writeback")

        add_executable(cdisasm_arm_advsimd_structure_ldst_lane_tests
            tests/test_arm_advsimd_structure_ldst_lane.c)
        target_compile_features(cdisasm_arm_advsimd_structure_ldst_lane_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_advsimd_structure_ldst_lane_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_advsimd_structure_ldst_lane_tests
            COMMAND cdisasm_arm_advsimd_structure_ldst_lane_tests)
        set_tests_properties(cdisasm_arm_advsimd_structure_ldst_lane_tests PROPERTIES
            LABELS "advsimd;arm;extra-opcodes;lane;ld1;ld2;ld3;ld4;load;memory;neon;st1;st2;st3;st4;store;structure")

        add_executable(
            cdisasm_arm_advsimd_integer_unary_tests
            tests/test_arm_advsimd_integer_unary.c)
        target_compile_features(
            cdisasm_arm_advsimd_integer_unary_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_integer_unary_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_integer_unary_tests
            COMMAND cdisasm_arm_advsimd_integer_unary_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_integer_unary_tests
            PROPERTIES LABELS
                "advsimd;arm;compare;extra-opcodes;integer;neon;saturating;unary;vector")

        add_executable(
            cdisasm_arm_advsimd_fp_compare_zero_sd_tests
            tests/test_arm_advsimd_fp_compare_zero_sd.c)
        target_compile_features(
            cdisasm_arm_advsimd_fp_compare_zero_sd_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_fp_compare_zero_sd_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_fp_compare_zero_sd_tests
            COMMAND cdisasm_arm_advsimd_fp_compare_zero_sd_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_fp_compare_zero_sd_tests
            PROPERTIES LABELS
                "advsimd;arm;compare;extra-opcodes;floating-point;neon;vector;zero")

        add_executable(
            cdisasm_arm_advsimd_bitwise_remaining_tests
            tests/test_arm_advsimd_bitwise_remaining.c)
        target_compile_features(
            cdisasm_arm_advsimd_bitwise_remaining_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_bitwise_remaining_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_bitwise_remaining_tests
            COMMAND cdisasm_arm_advsimd_bitwise_remaining_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_bitwise_remaining_tests
            PROPERTIES LABELS
                "advsimd;arm;bic;bitwise;extra-opcodes;neon;not;orn;rbit;vector")

        add_executable(
            cdisasm_arm_sve_frintts_tests
            tests/test_arm_sve_frintts.c)
        target_compile_features(
            cdisasm_arm_sve_frintts_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_frintts_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_frintts_tests
            COMMAND cdisasm_arm_sve_frintts_tests)
        set_tests_properties(
            cdisasm_arm_sve_frintts_tests
            PROPERTIES LABELS
                "arm;extra-opcodes;floating-point;frintts;predicate;sme2p2;sve;sve2p2;vector")

        add_executable(
            cdisasm_arm_sve_fp_estimate_tests
            tests/test_arm_sve_fp_estimate.c)
        target_compile_features(
            cdisasm_arm_sve_fp_estimate_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_fp_estimate_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_fp_estimate_tests
            COMMAND cdisasm_arm_sve_fp_estimate_tests)
        set_tests_properties(
            cdisasm_arm_sve_fp_estimate_tests
            PROPERTIES LABELS
                "arm;estimate;extra-opcodes;floating-point;sme;sve;unpredicated;vector")

        add_executable(
            cdisasm_arm_sve_int_to_fp16_tests
            tests/test_arm_sve_int_to_fp16.c)
        target_compile_features(
            cdisasm_arm_sve_int_to_fp16_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_int_to_fp16_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_int_to_fp16_tests
            COMMAND cdisasm_arm_sve_int_to_fp16_tests)
        set_tests_properties(
            cdisasm_arm_sve_int_to_fp16_tests
            PROPERTIES LABELS
                "arm;conversion;extra-opcodes;floating-point;integer;predicate;sme;sve;vector")

        add_executable(
            cdisasm_arm_sve_int_to_fp_tests
            tests/test_arm_sve_int_to_fp.c)
        target_compile_features(
            cdisasm_arm_sve_int_to_fp_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_int_to_fp_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_int_to_fp_tests
            COMMAND cdisasm_arm_sve_int_to_fp_tests)
        set_tests_properties(
            cdisasm_arm_sve_int_to_fp_tests
            PROPERTIES LABELS
                "arm;conversion;extra-opcodes;floating-point;integer;predicate;sme;sve;vector")

        add_executable(
            cdisasm_arm_sve_fcvt_tests
            tests/test_arm_sve_fcvt.c)
        target_compile_features(
            cdisasm_arm_sve_fcvt_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_fcvt_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_fcvt_tests
            COMMAND cdisasm_arm_sve_fcvt_tests)
        set_tests_properties(
            cdisasm_arm_sve_fcvt_tests
            PROPERTIES LABELS
                "arm;conversion;extra-opcodes;floating-point;predicate;sme;sve;vector")

        add_executable(
            cdisasm_arm_sve_bfcvt_tests
            tests/test_arm_sve_bfcvt.c)
        target_compile_features(
            cdisasm_arm_sve_bfcvt_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_bfcvt_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_bfcvt_tests
            COMMAND cdisasm_arm_sve_bfcvt_tests)
        set_tests_properties(
            cdisasm_arm_sve_bfcvt_tests
            PROPERTIES LABELS
                "arm;bf16;conversion;extra-opcodes;floating-point;predicate;sme;sve;vector")

        add_executable(
            cdisasm_arm_sme2_bfcvt_multi_tests
            tests/test_arm_sme2_bfcvt_multi.c)
        target_compile_features(
            cdisasm_arm_sme2_bfcvt_multi_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sme2_bfcvt_multi_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sme2_bfcvt_multi_tests
            COMMAND cdisasm_arm_sme2_bfcvt_multi_tests)
        set_tests_properties(
            cdisasm_arm_sme2_bfcvt_multi_tests
            PROPERTIES LABELS
                "arm;bf16;conversion;extra-opcodes;floating-point;fp8;sme2;sve2;vector")

        add_executable(
            cdisasm_arm_multi_narrow_frint_tests
            tests/test_arm_multi_narrow_frint.c)
        target_compile_features(
            cdisasm_arm_multi_narrow_frint_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_multi_narrow_frint_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_multi_narrow_frint_tests
            COMMAND cdisasm_arm_multi_narrow_frint_tests)
        set_tests_properties(
            cdisasm_arm_multi_narrow_frint_tests
            PROPERTIES LABELS
                "arm;conversion;extra-opcodes;floating-point;sme;sme-f16f16;sme2;sve2p1;vector")

        add_executable(
            cdisasm_arm_sme2_multi4_convert_tests
            tests/test_arm_sme2_multi4_convert.c)
        target_compile_features(
            cdisasm_arm_sme2_multi4_convert_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sme2_multi4_convert_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sme2_multi4_convert_tests
            COMMAND cdisasm_arm_sme2_multi4_convert_tests)
        set_tests_properties(
            cdisasm_arm_sme2_multi4_convert_tests
            PROPERTIES LABELS
                "arm;conversion;extra-opcodes;floating-point;fp8;sme2;vector")

        add_executable(
            cdisasm_arm_sme2_multi4_qrshrn_tests
            tests/test_arm_sme2_multi4_qrshrn.c)
        target_compile_features(
            cdisasm_arm_sme2_multi4_qrshrn_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sme2_multi4_qrshrn_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sme2_multi4_qrshrn_tests
            COMMAND cdisasm_arm_sme2_multi4_qrshrn_tests)
        set_tests_properties(
            cdisasm_arm_sme2_multi4_qrshrn_tests
            PROPERTIES LABELS
                "arm;extra-opcodes;integer;narrowing;sme2;vector")

        add_executable(
            cdisasm_arm_advsimd_f16_dot_matrix_tests
            tests/test_arm_advsimd_f16_dot_matrix.c)
        target_compile_features(
            cdisasm_arm_advsimd_f16_dot_matrix_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_f16_dot_matrix_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_f16_dot_matrix_tests
            COMMAND cdisasm_arm_advsimd_f16_dot_matrix_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_f16_dot_matrix_tests
            PROPERTIES LABELS
                "advsimd;arm;dot-product;extra-opcodes;floating-point;fp16;matrix;vector")

        add_executable(
            cdisasm_arm_sve_integer_arithmetic_tests
            tests/test_arm_sve_integer_arithmetic.c)
        target_compile_features(
            cdisasm_arm_sve_integer_arithmetic_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_integer_arithmetic_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_integer_arithmetic_tests
            COMMAND cdisasm_arm_sve_integer_arithmetic_tests)
        set_tests_properties(
            cdisasm_arm_sve_integer_arithmetic_tests
            PROPERTIES LABELS "arm;cpa;extra-opcodes;sve")

        add_executable(
            cdisasm_arm_sve_unpredicated_logical_tests
            tests/test_arm_sve_unpredicated_logical.c)
        target_compile_features(
            cdisasm_arm_sve_unpredicated_logical_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_unpredicated_logical_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_unpredicated_logical_tests
            COMMAND cdisasm_arm_sve_unpredicated_logical_tests)
        set_tests_properties(
            cdisasm_arm_sve_unpredicated_logical_tests
            PROPERTIES LABELS
                "arm;bitwise;extra-opcodes;logical;sme;sve;vector")

        add_executable(
            cdisasm_arm_architectural_hint_tests
            tests/test_arm_architectural_hints.c)
        target_compile_features(
            cdisasm_arm_architectural_hint_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_architectural_hint_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_architectural_hint_tests
            COMMAND cdisasm_arm_architectural_hint_tests)
        set_tests_properties(
            cdisasm_arm_architectural_hint_tests
            PROPERTIES LABELS
                "a32;a64;arm;extra-opcodes;hint;system;t32")

        add_executable(
            cdisasm_arm_sve_integer_immediate_tests
            tests/test_arm_sve_integer_immediate.c)
        target_compile_features(
            cdisasm_arm_sve_integer_immediate_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_integer_immediate_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_integer_immediate_tests
            COMMAND cdisasm_arm_sve_integer_immediate_tests)
        set_tests_properties(
            cdisasm_arm_sve_integer_immediate_tests
            PROPERTIES LABELS
                "arm;extra-opcodes;immediate;sme;sve;vector")

        add_executable(
            cdisasm_arm_sve_dup_immediate_tests
            tests/test_arm_sve_dup_immediate.c)
        target_compile_features(
            cdisasm_arm_sve_dup_immediate_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_dup_immediate_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_dup_immediate_tests
            COMMAND cdisasm_arm_sve_dup_immediate_tests)
        set_tests_properties(
            cdisasm_arm_sve_dup_immediate_tests
            PROPERTIES LABELS
                "arm;extra-opcodes;immediate;sme;sve;vector")

        add_executable(
            cdisasm_arm_sve_dot_product_tests
            tests/test_arm_sve_dot_product.c)
        target_compile_features(
            cdisasm_arm_sve_dot_product_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_dot_product_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_dot_product_tests
            COMMAND cdisasm_arm_sve_dot_product_tests)
        set_tests_properties(
            cdisasm_arm_sve_dot_product_tests
            PROPERTIES LABELS
                "arm;dot-product;extra-opcodes;integer;sme;sve;vector")

        add_executable(
            cdisasm_arm_sve_complex_muladd_tests
            tests/test_arm_sve_complex_muladd.c)
        target_compile_features(
            cdisasm_arm_sve_complex_muladd_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_complex_muladd_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_complex_muladd_tests
            COMMAND cdisasm_arm_sve_complex_muladd_tests)
        set_tests_properties(
            cdisasm_arm_sve_complex_muladd_tests
            PROPERTIES LABELS
                "arm;complex;extra-opcodes;integer;sme;sve;vector")

        add_executable(
            cdisasm_arm_sve_widening_muladd_tests
            tests/test_arm_sve_widening_muladd.c)
        target_compile_features(
            cdisasm_arm_sve_widening_muladd_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_widening_muladd_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_widening_muladd_tests
            COMMAND cdisasm_arm_sve_widening_muladd_tests)
        set_tests_properties(
            cdisasm_arm_sve_widening_muladd_tests
            PROPERTIES LABELS
                "arm;extra-opcodes;integer;multiply-add;sme;sve;vector;widening")

        add_executable(
            cdisasm_arm_sve_mla_indexed_tests
            tests/test_arm_sve_mla_indexed.c)
        target_compile_features(
            cdisasm_arm_sve_mla_indexed_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_mla_indexed_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_mla_indexed_tests
            COMMAND cdisasm_arm_sve_mla_indexed_tests)
        set_tests_properties(
            cdisasm_arm_sve_mla_indexed_tests
            PROPERTIES LABELS
                "a64;arm;extra-opcodes;indexed;integer;mla;mls;sme;sve;sve2;vector")

        add_executable(
            cdisasm_arm_sve_sqrdml_indexed_tests
            tests/test_arm_sve_sqrdml_indexed.c)
        target_compile_features(
            cdisasm_arm_sve_sqrdml_indexed_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_sqrdml_indexed_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_sqrdml_indexed_tests
            COMMAND cdisasm_arm_sve_sqrdml_indexed_tests)
        set_tests_properties(
            cdisasm_arm_sve_sqrdml_indexed_tests
            PROPERTIES LABELS
                "a64;arm;extra-opcodes;indexed;integer;saturation;sme;sqrdmlah;sqrdmlsh;sve;sve2;vector")

        add_executable(
            cdisasm_arm_sve_usdot_tests
            tests/test_arm_sve_usdot.c)
        target_compile_features(
            cdisasm_arm_sve_usdot_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_usdot_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_usdot_tests
            COMMAND cdisasm_arm_sve_usdot_tests)
        set_tests_properties(
            cdisasm_arm_sve_usdot_tests
            PROPERTIES LABELS
                "arm;dot-product;extra-opcodes;i8mm;integer;mixed-sign;sme;sve;vector")

        add_executable(
            cdisasm_arm_sve_sudot_indexed_tests
            tests/test_arm_sve_sudot_indexed.c)
        target_compile_features(
            cdisasm_arm_sve_sudot_indexed_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_sudot_indexed_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_sudot_indexed_tests
            COMMAND cdisasm_arm_sve_sudot_indexed_tests)
        set_tests_properties(
            cdisasm_arm_sve_sudot_indexed_tests
            PROPERTIES LABELS
                "a64;arm;dot-product;extra-opcodes;i8mm;indexed;integer;mixed-sign;sme;sve;vector")

        add_executable(
            cdisasm_arm_sve_aes_unary_tests
            tests/test_arm_sve_aes_unary.c)
        target_compile_features(
            cdisasm_arm_sve_aes_unary_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_aes_unary_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_aes_unary_tests
            COMMAND cdisasm_arm_sve_aes_unary_tests)
        set_tests_properties(
            cdisasm_arm_sve_aes_unary_tests
            PROPERTIES LABELS
                "a64;aes;arm;crypto;extra-opcodes;sve;sve-aes;vector")

        add_executable(
            cdisasm_arm_sve_crypto_binary_tests
            tests/test_arm_sve_crypto_binary.c)
        target_compile_features(
            cdisasm_arm_sve_crypto_binary_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_crypto_binary_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_crypto_binary_tests
            COMMAND cdisasm_arm_sve_crypto_binary_tests)
        set_tests_properties(
            cdisasm_arm_sve_crypto_binary_tests
            PROPERTIES LABELS
                "a64;aes;arm;crypto;extra-opcodes;sm4;sve;sve-aes;sve-sm4;vector")

        add_executable(
            cdisasm_arm_sve_predicated_shift_sat_round_tests
            tests/test_arm_sve_predicated_shift_sat_round.c)
        target_compile_features(
            cdisasm_arm_sve_predicated_shift_sat_round_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_predicated_shift_sat_round_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_predicated_shift_sat_round_tests
            COMMAND cdisasm_arm_sve_predicated_shift_sat_round_tests)
        set_tests_properties(
            cdisasm_arm_sve_predicated_shift_sat_round_tests
            PROPERTIES LABELS
                "arm;extra-opcodes;integer;predicate;rounding;saturating;shift;sme;sve;sve2")

        add_executable(
            cdisasm_arm_sve_predicated_sat_unary_tests
            tests/test_arm_sve_predicated_sat_unary.c)
        target_compile_features(
            cdisasm_arm_sve_predicated_sat_unary_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_predicated_sat_unary_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_predicated_sat_unary_tests
            COMMAND cdisasm_arm_sve_predicated_sat_unary_tests)
        set_tests_properties(
            cdisasm_arm_sve_predicated_sat_unary_tests
            PROPERTIES LABELS
                "a64;arm;estimate;extra-opcodes;integer;predicate;saturating;sme;sme2p2;sve;sve2;sve2p2;unary;vector")

        add_executable(
            cdisasm_arm_sve_predicated_accumulate_long_tests
            tests/test_arm_sve_predicated_accumulate_long.c)
        target_compile_features(
            cdisasm_arm_sve_predicated_accumulate_long_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_predicated_accumulate_long_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_predicated_accumulate_long_tests
            COMMAND cdisasm_arm_sve_predicated_accumulate_long_tests)
        set_tests_properties(
            cdisasm_arm_sve_predicated_accumulate_long_tests
            PROPERTIES LABELS
                "a64;accumulate;arm;extra-opcodes;integer;pairwise;predicate;sme;sve;sve2;vector;widening")

        add_executable(
            cdisasm_arm_sve_predicated_halving_tests
            tests/test_arm_sve_predicated_halving.c)
        target_compile_features(
            cdisasm_arm_sve_predicated_halving_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_predicated_halving_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_predicated_halving_tests
            COMMAND cdisasm_arm_sve_predicated_halving_tests)
        set_tests_properties(
            cdisasm_arm_sve_predicated_halving_tests
            PROPERTIES LABELS
                "a64;arm;extra-opcodes;halving;integer;predicate;sme;sve;sve2;vector")

        add_executable(
            cdisasm_arm_sve_predicated_integer_tests
            tests/test_arm_sve_predicated_integer.c)
        target_compile_features(
            cdisasm_arm_sve_predicated_integer_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_predicated_integer_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_predicated_integer_tests
            COMMAND cdisasm_arm_sve_predicated_integer_tests)
        set_tests_properties(
            cdisasm_arm_sve_predicated_integer_tests
            PROPERTIES LABELS
                "arm;cpa;extra-opcodes;integer;predicate;sme;sve")

        add_executable(
            cdisasm_arm_sve_predicated_unary_tests
            tests/test_arm_sve_predicated_unary.c)
        target_compile_features(
            cdisasm_arm_sve_predicated_unary_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_predicated_unary_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_predicated_unary_tests
            COMMAND cdisasm_arm_sve_predicated_unary_tests)
        set_tests_properties(
            cdisasm_arm_sve_predicated_unary_tests
            PROPERTIES LABELS
                "arm;extra-opcodes;floating-point;integer;predicate;sme;sve;unary")

        add_executable(
            cdisasm_arm_sve_predicated_pairwise_tests
            tests/test_arm_sve_predicated_pairwise.c)
        target_compile_features(
            cdisasm_arm_sve_predicated_pairwise_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_predicated_pairwise_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_predicated_pairwise_tests
            COMMAND cdisasm_arm_sve_predicated_pairwise_tests)
        set_tests_properties(
            cdisasm_arm_sve_predicated_pairwise_tests
            PROPERTIES LABELS
                "a64;arm;extra-opcodes;integer;pairwise;predicate;sme;sme2p3;sve;sve2;sve2p3;vector")

        add_executable(
            cdisasm_arm_sve_predicated_saturating_tests
            tests/test_arm_sve_predicated_saturating.c)
        target_compile_features(
            cdisasm_arm_sve_predicated_saturating_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_predicated_saturating_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_predicated_saturating_tests
            COMMAND cdisasm_arm_sve_predicated_saturating_tests)
        set_tests_properties(
            cdisasm_arm_sve_predicated_saturating_tests
            PROPERTIES LABELS
                "a64;arm;extra-opcodes;integer;predicate;saturating;sme;sve;sve2;vector")

        add_executable(
            cdisasm_arm_sve_clamp_tests
            tests/test_arm_sve_clamp.c)
        target_compile_features(
            cdisasm_arm_sve_clamp_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_clamp_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_clamp_tests
            COMMAND cdisasm_arm_sve_clamp_tests)
        set_tests_properties(
            cdisasm_arm_sve_clamp_tests
            PROPERTIES LABELS
                "a64;arm;clamp;extra-opcodes;integer;sme;sve;sve2p1;vector")

        add_executable(
            cdisasm_arm_sve_pointer_muladd_tests
            tests/test_arm_sve_pointer_muladd.c)
        target_compile_features(
            cdisasm_arm_sve_pointer_muladd_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_pointer_muladd_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_pointer_muladd_tests
            COMMAND cdisasm_arm_sve_pointer_muladd_tests)
        set_tests_properties(
            cdisasm_arm_sve_pointer_muladd_tests
            PROPERTIES LABELS
                "a64;arm;cpa;extra-opcodes;integer;sve;vector")

        add_executable(
            cdisasm_arm_sve_quad_permute_tests
            tests/test_arm_sve_quad_permute.c)
        target_compile_features(
            cdisasm_arm_sve_quad_permute_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_quad_permute_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_quad_permute_tests
            COMMAND cdisasm_arm_sve_quad_permute_tests)
        set_tests_properties(
            cdisasm_arm_sve_quad_permute_tests
            PROPERTIES LABELS
                "a64;arm;extra-opcodes;permute;sme2p1;sve2p1;vector")

        add_executable(
            cdisasm_arm_sve_pmov_tests
            tests/test_arm_sve_pmov.c)
        target_compile_features(
            cdisasm_arm_sve_pmov_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_pmov_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_pmov_tests
            COMMAND cdisasm_arm_sve_pmov_tests)
        set_tests_properties(
            cdisasm_arm_sve_pmov_tests
            PROPERTIES LABELS
                "a64;arm;extra-opcodes;pmov;predicate;sme2p1;sve2p1;vector")

        add_executable(
            cdisasm_arm_sve_predicated_vector_shift_tests
            tests/test_arm_sve_predicated_vector_shift.c)
        target_compile_features(
            cdisasm_arm_sve_predicated_vector_shift_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_predicated_vector_shift_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_predicated_vector_shift_tests
            COMMAND cdisasm_arm_sve_predicated_vector_shift_tests)
        set_tests_properties(
            cdisasm_arm_sve_predicated_vector_shift_tests
            PROPERTIES LABELS
                "arm;extra-opcodes;integer;predicate;shift;sme;sve")

        add_executable(
            cdisasm_arm_sve_predicated_immediate_shift_tests
            tests/test_arm_sve_predicated_immediate_shift.c)
        target_compile_features(
            cdisasm_arm_sve_predicated_immediate_shift_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_predicated_immediate_shift_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_predicated_immediate_shift_tests
            COMMAND cdisasm_arm_sve_predicated_immediate_shift_tests)
        set_tests_properties(
            cdisasm_arm_sve_predicated_immediate_shift_tests
            PROPERTIES LABELS
                "arm;extra-opcodes;integer;predicate;shift;sme;sve;sve2")

        add_executable(
            cdisasm_arm_sve_shift_insert_tests
            tests/test_arm_sve_shift_insert.c)
        target_compile_features(
            cdisasm_arm_sve_shift_insert_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_shift_insert_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_shift_insert_tests
            COMMAND cdisasm_arm_sve_shift_insert_tests)
        set_tests_properties(
            cdisasm_arm_sve_shift_insert_tests
            PROPERTIES LABELS
                "a64;arm;extra-opcodes;immediate;integer;shift;sli;sme;sri;sve;sve2;vector")

        add_executable(
            cdisasm_arm_sve_bitperm_tests
            tests/test_arm_sve_bitperm.c)
        target_compile_features(
            cdisasm_arm_sve_bitperm_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_bitperm_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_bitperm_tests
            COMMAND cdisasm_arm_sve_bitperm_tests)
        set_tests_properties(
            cdisasm_arm_sve_bitperm_tests
            PROPERTIES LABELS
                "a64;arm;bdep;bext;bgrp;bitperm;extra-opcodes;integer;sve;sve2;vector")

        add_executable(
            cdisasm_arm_sve_vector_permute_tests
            tests/test_arm_sve_vector_permute.c)
        target_compile_features(
            cdisasm_arm_sve_vector_permute_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_vector_permute_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_vector_permute_tests
            COMMAND cdisasm_arm_sve_vector_permute_tests)
        set_tests_properties(
            cdisasm_arm_sve_vector_permute_tests
            PROPERTIES LABELS "arm;extra-opcodes;permute;sme;sve")

        add_executable(
            cdisasm_arm_f64mm_permute_tests
            tests/test_arm_f64mm_permute.c)
        target_compile_features(
            cdisasm_arm_f64mm_permute_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_f64mm_permute_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_f64mm_permute_tests
            COMMAND cdisasm_arm_f64mm_permute_tests)
        set_tests_properties(
            cdisasm_arm_f64mm_permute_tests
            PROPERTIES LABELS "a64;arm;extra-opcodes;f64mm;permute;sve")

        add_executable(
            cdisasm_arm_sve_table_lookup_tests
            tests/test_arm_sve_table_lookup.c)
        target_compile_features(
            cdisasm_arm_sve_table_lookup_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_table_lookup_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_table_lookup_tests
            COMMAND cdisasm_arm_sve_table_lookup_tests)
        set_tests_properties(
            cdisasm_arm_sve_table_lookup_tests
            PROPERTIES LABELS
                "arm;extra-opcodes;permute;sme;sme2p1;sve;sve2;sve2p1;table")

        add_executable(
            cdisasm_arm_advsimd_table_lookup_tests
            tests/test_arm_advsimd_table_lookup.c)
        target_compile_features(
            cdisasm_arm_advsimd_table_lookup_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_table_lookup_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_table_lookup_tests
            COMMAND cdisasm_arm_advsimd_table_lookup_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_table_lookup_tests
            PROPERTIES LABELS "a64;arm;advsimd;extra-opcodes;permute;table")

        add_executable(
            cdisasm_arm_advsimd_dot_rdm_same_tests
            tests/test_arm_advsimd_dot_rdm_same.c)
        target_compile_features(
            cdisasm_arm_advsimd_dot_rdm_same_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_advsimd_dot_rdm_same_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_advsimd_dot_rdm_same_tests
            COMMAND cdisasm_arm_advsimd_dot_rdm_same_tests)
        set_tests_properties(
            cdisasm_arm_advsimd_dot_rdm_same_tests
            PROPERTIES LABELS "a64;arm;advsimd;dotprod;extra-opcodes;rdm")

        add_executable(
            cdisasm_arm_sve_tblq_tests
            tests/test_arm_sve_tblq.c)
        target_compile_features(
            cdisasm_arm_sve_tblq_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_sve_tblq_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_sve_tblq_tests
            COMMAND cdisasm_arm_sve_tblq_tests)
        set_tests_properties(
            cdisasm_arm_sve_tblq_tests
            PROPERTIES LABELS
                "arm;extra-opcodes;permute;sme2p1;sve2p1;table")

        add_executable(
            cdisasm_arm_a32_t32_psr_transfer_tests
            tests/test_arm_a32_t32_psr_transfer.c)
        target_compile_features(
            cdisasm_arm_a32_t32_psr_transfer_tests PRIVATE c_std_11)
        target_link_libraries(
            cdisasm_arm_a32_t32_psr_transfer_tests PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_a32_t32_psr_transfer_tests
            COMMAND cdisasm_arm_a32_t32_psr_transfer_tests)
        set_tests_properties(
            cdisasm_arm_a32_t32_psr_transfer_tests
            PROPERTIES LABELS "a32;arm;extra-opcodes;system;t32")

        if(CDISASM_EFFECTIVE_USE_DISASM_FORMAT)
            add_executable(cdisasm_arm_format_tests tests/test_arm_format.c)
            target_compile_features(cdisasm_arm_format_tests PRIVATE c_std_11)
            target_link_libraries(cdisasm_arm_format_tests PRIVATE cdisasm)
            add_test(
                NAME cdisasm_arm_format_tests
                COMMAND cdisasm_arm_format_tests)
        endif()

        add_executable(cdisasm_arm_apple_tests tests/test_arm_apple.c)
        target_compile_features(cdisasm_arm_apple_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_apple_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_arm_apple_tests COMMAND cdisasm_arm_apple_tests)

        add_executable(cdisasm_t32_tests tests/test_t32.c)
        target_compile_features(cdisasm_t32_tests PRIVATE c_std_11)
        target_link_libraries(cdisasm_t32_tests PRIVATE cdisasm)
        add_test(NAME cdisasm_t32_tests COMMAND cdisasm_t32_tests)

        add_executable(
            cdisasm_arm_opcode_corpus_tests
            tests/test_arm_opcode_corpus.c)
        target_compile_features(
            cdisasm_arm_opcode_corpus_tests
            PRIVATE c_std_11)
        if(WIN32)
            target_compile_definitions(
                cdisasm_arm_opcode_corpus_tests
                PRIVATE _CRT_SECURE_NO_WARNINGS)
        endif()
        target_link_libraries(
            cdisasm_arm_opcode_corpus_tests
            PRIVATE cdisasm)
        add_test(
            NAME cdisasm_arm_opcode_corpus_tests
            COMMAND
                cdisasm_arm_opcode_corpus_tests
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/data/arm_opcodes.tsv")
    endif()

    if(CDISASM_BUILD_PACKAGE_TESTS)
        if(CMAKE_CROSSCOMPILING)
            message(STATUS
                "Installed-package runtime tests are disabled while cross-compiling")
        else()
            if(CMAKE_CONFIGURATION_TYPES)
                set(_cdisasm_package_multi_config ON)
            else()
                set(_cdisasm_package_multi_config OFF)
            endif()
            set(_cdisasm_package_fallback_config "${CMAKE_BUILD_TYPE}")
            if("${_cdisasm_package_fallback_config}" STREQUAL "")
                set(_cdisasm_package_fallback_config Release)
            endif()

            foreach(_cdisasm_package_shared IN ITEMS ON OFF)
                if(_cdisasm_package_shared)
                    set(_cdisasm_package_linkage shared)
                else()
                    set(_cdisasm_package_linkage static)
                endif()

                set(_cdisasm_package_test
                    "cdisasm_package_${_cdisasm_package_linkage}_e2e")
                add_test(
                    NAME "${_cdisasm_package_test}"
                    COMMAND
                        "${CMAKE_COMMAND}"
                        "-DCDISASM_PACKAGE_SOURCE_DIR:PATH=${CMAKE_CURRENT_SOURCE_DIR}"
                        "-DCDISASM_PACKAGE_WORK_DIR:PATH=${CMAKE_CURRENT_BINARY_DIR}/package-test-build/${_cdisasm_package_linkage}"
                        "-DCDISASM_PACKAGE_VERSION:STRING=${PROJECT_VERSION}"
                        "-DCDISASM_PACKAGE_SHARED:BOOL=${_cdisasm_package_shared}"
                        "-DCDISASM_PACKAGE_CONFIG:STRING=$<CONFIG>"
                        "-DCDISASM_PACKAGE_FALLBACK_CONFIG:STRING=${_cdisasm_package_fallback_config}"
                        "-DCDISASM_PACKAGE_GENERATOR:STRING=${CMAKE_GENERATOR}"
                        "-DCDISASM_PACKAGE_GENERATOR_PLATFORM:STRING=${CMAKE_GENERATOR_PLATFORM}"
                        "-DCDISASM_PACKAGE_GENERATOR_TOOLSET:STRING=${CMAKE_GENERATOR_TOOLSET}"
                        "-DCDISASM_PACKAGE_GENERATOR_INSTANCE:STRING=${CMAKE_GENERATOR_INSTANCE}"
                        "-DCDISASM_PACKAGE_MAKE_PROGRAM:FILEPATH=${CMAKE_MAKE_PROGRAM}"
                        "-DCDISASM_PACKAGE_TOOLCHAIN_FILE:FILEPATH=${CMAKE_TOOLCHAIN_FILE}"
                        "-DCDISASM_PACKAGE_C_COMPILER:FILEPATH=${CMAKE_C_COMPILER}"
                        "-DCDISASM_PACKAGE_CXX_COMPILER:FILEPATH=${CMAKE_CXX_COMPILER}"
                        "-DCDISASM_PACKAGE_MULTI_CONFIG:BOOL=${_cdisasm_package_multi_config}"
                        "-DCDISASM_PACKAGE_CTEST_COMMAND:FILEPATH=${CMAKE_CTEST_COMMAND}"
                        -P
                        "${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/test_installed_package.cmake")
                set_tests_properties(
                    "${_cdisasm_package_test}"
                    PROPERTIES
                        LABELS "package;install"
                        RUN_SERIAL TRUE
                        TIMEOUT 4800)
            endforeach()

            unset(_cdisasm_package_linkage)
            unset(_cdisasm_package_fallback_config)
            unset(_cdisasm_package_multi_config)
            unset(_cdisasm_package_shared)
            unset(_cdisasm_package_test)
        endif()
    endif()
endif()

if(CDISASM_BUILD_EXAMPLES AND CDISASM_EFFECTIVE_USE_DISASM_FORMAT)
    if(USE_ARCH_X86)
        add_executable(cdisasm_cli examples/cdisasm_cli.c)
        target_compile_features(cdisasm_cli PRIVATE c_std_11)
        target_link_libraries(cdisasm_cli PRIVATE cdisasm)
    endif()
    if(USE_ARCH_ARM)
        add_executable(cdisasm_arm_cli examples/cdisasm_arm_cli.c)
        target_compile_features(cdisasm_arm_cli PRIVATE c_std_11)
        target_link_libraries(cdisasm_arm_cli PRIVATE cdisasm)
    endif()
endif()

if(CDISASM_BUILD_FUZZERS)
    if(NOT USE_ARCH_X86 AND NOT USE_ARCH_ARM)
        message(FATAL_ERROR
            "CDISASM_BUILD_FUZZERS requires USE_ARCH_X86 or USE_ARCH_ARM")
    endif()

    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR
            "CDISASM_BUILD_FUZZERS requires Clang with compiler-rt libFuzzer")
    endif()

    set(_cdisasm_fuzz_compile_sanitizers "fuzzer-no-link")
    set(_cdisasm_fuzz_link_sanitizers "fuzzer")
    if(NOT CDISASM_FUZZ_SANITIZERS STREQUAL "")
        string(APPEND
            _cdisasm_fuzz_compile_sanitizers
            ",${CDISASM_FUZZ_SANITIZERS}")
        string(APPEND
            _cdisasm_fuzz_link_sanitizers
            ",${CDISASM_FUZZ_SANITIZERS}")
    endif()

    # Clang may be installed without compiler-rt's libFuzzer archive (notably
    # in some Windows toolchains).  Fail during configuration with a focused
    # diagnostic instead of producing an opaque linker error later.
    include(CheckCSourceCompiles)
    set(_cdisasm_saved_required_flags "${CMAKE_REQUIRED_FLAGS}")
    set(_cdisasm_saved_required_link_options
        "${CMAKE_REQUIRED_LINK_OPTIONS}")
    string(APPEND CMAKE_REQUIRED_FLAGS
        " -fsanitize=${_cdisasm_fuzz_compile_sanitizers}")
    set(CMAKE_REQUIRED_LINK_OPTIONS
        "-fsanitize=${_cdisasm_fuzz_link_sanitizers}")
    unset(_cdisasm_libfuzzer_available CACHE)
    check_c_source_compiles(
        "#include <stddef.h>\n#include <stdint.h>\nint LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { (void)data; (void)size; return 0; }"
        _cdisasm_libfuzzer_available)
    set(CMAKE_REQUIRED_FLAGS "${_cdisasm_saved_required_flags}")
    set(CMAKE_REQUIRED_LINK_OPTIONS
        "${_cdisasm_saved_required_link_options}")
    unset(_cdisasm_saved_required_flags)
    unset(_cdisasm_saved_required_link_options)
    if(NOT _cdisasm_libfuzzer_available)
        message(FATAL_ERROR
            "CDISASM_BUILD_FUZZERS requires Clang compiler-rt with "
            "libFuzzer and the requested sanitizers")
    endif()
    unset(_cdisasm_libfuzzer_available CACHE)

    # libFuzzer writes new coverage entries to its first corpus directory.
    # Prepare a build-local working corpus so the checked-in seeds stay clean.
    if(USE_ARCH_X86)
        file(
            COPY "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus/"
            DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/fuzz-corpus"
            FILES_MATCHING
            PATTERN "*.hex")

        # Compile a private static copy so every selected decoder/formatter
        # edge is instrumented without changing the normal library artifact.
        set(
            _cdisasm_x86_fuzz_sources
            src/x86/cdisasm_x86.c
            src/x86/x86_decoder.c
            src/x86/x86_generated_decoder.c)
        if(CDISASM_EFFECTIVE_USE_DISASM_FORMAT)
            list(APPEND _cdisasm_x86_fuzz_sources src/x86/cdisasm_format.c)
        endif()
        add_library(
            cdisasm_fuzz_runtime
            STATIC
            ${_cdisasm_x86_fuzz_sources})
        unset(_cdisasm_x86_fuzz_sources)
        target_compile_features(cdisasm_fuzz_runtime PRIVATE c_std_11)
        target_compile_definitions(
            cdisasm_fuzz_runtime
            PRIVATE
                CDISASM_STATIC
                CDISASM_X86_STATIC)
        target_include_directories(
            cdisasm_fuzz_runtime
            PRIVATE
                "${_cdisasm_generated_include_dir}"
                "${CMAKE_CURRENT_SOURCE_DIR}/include")
        target_compile_options(
            cdisasm_fuzz_runtime
            PRIVATE
                "-fsanitize=${_cdisasm_fuzz_compile_sanitizers}"
                -fno-omit-frame-pointer)
        set_target_properties(
            cdisasm_fuzz_runtime
            PROPERTIES
                C_STANDARD 11
                C_STANDARD_REQUIRED YES
                C_EXTENSIONS NO)

        add_executable(cdisasm_decode_fuzzer fuzz/fuzz_decode2.c)
        target_compile_features(cdisasm_decode_fuzzer PRIVATE c_std_11)
        target_include_directories(
            cdisasm_decode_fuzzer
            PRIVATE
                "${_cdisasm_generated_include_dir}"
                "${CMAKE_CURRENT_SOURCE_DIR}/include")
        target_compile_definitions(
            cdisasm_decode_fuzzer
            PRIVATE
                CDISASM_STATIC
                CDISASM_X86_STATIC)
        target_compile_options(
            cdisasm_decode_fuzzer
            PRIVATE
                "-fsanitize=${_cdisasm_fuzz_compile_sanitizers}"
                -fno-omit-frame-pointer)
        target_link_options(
            cdisasm_decode_fuzzer
            PRIVATE "-fsanitize=${_cdisasm_fuzz_link_sanitizers}")
        target_link_libraries(
            cdisasm_decode_fuzzer
            PRIVATE cdisasm_fuzz_runtime)
    endif()

    if(USE_ARCH_ARM)
        file(
            COPY "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/arm_corpus/"
            DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/fuzz-arm-corpus"
            FILES_MATCHING
            PATTERN "*.hex")

        # ARM has a separate runtime and corpus so its coverage discoveries
        # remain independently reproducible.
        set(
            _cdisasm_arm_fuzz_sources
            src/arm/cdisasm_arm.c
            src/arm/arm_apple_decoder.c
            src/arm/arm_decoder.c
            src/arm/arm_generated_alias.c
            src/arm/arm_generated_decoder.c
            src/arm/arm_generated_operands.c
            src/arm/arm_modern_decoder.c
            src/arm/arm_t32_decoder.c)
        if(CDISASM_EFFECTIVE_USE_DISASM_FORMAT)
            list(APPEND
                _cdisasm_arm_fuzz_sources
                src/arm/arm_generated_formatter.c
                src/arm/cdisasm_arm_format.c)
        endif()
        add_library(
            cdisasm_arm_fuzz_runtime
            STATIC
            ${_cdisasm_arm_fuzz_sources})
        unset(_cdisasm_arm_fuzz_sources)
        target_compile_features(cdisasm_arm_fuzz_runtime PRIVATE c_std_11)
        target_compile_definitions(
            cdisasm_arm_fuzz_runtime
            PRIVATE
                CDISASM_STATIC
                CDISASM_ARM_STATIC)
        target_include_directories(
            cdisasm_arm_fuzz_runtime
            PRIVATE
                "${_cdisasm_generated_include_dir}"
                "${CMAKE_CURRENT_SOURCE_DIR}/include")
        target_compile_options(
            cdisasm_arm_fuzz_runtime
            PRIVATE
                "-fsanitize=${_cdisasm_fuzz_compile_sanitizers}"
                -fno-omit-frame-pointer)
        set_target_properties(
            cdisasm_arm_fuzz_runtime
            PROPERTIES
                C_STANDARD 11
                C_STANDARD_REQUIRED YES
                C_EXTENSIONS NO)

        add_executable(cdisasm_arm_decode_fuzzer fuzz/fuzz_arm_decode2.c)
        target_compile_features(cdisasm_arm_decode_fuzzer PRIVATE c_std_11)
        target_include_directories(
            cdisasm_arm_decode_fuzzer
            PRIVATE
                "${_cdisasm_generated_include_dir}"
                "${CMAKE_CURRENT_SOURCE_DIR}/include")
        target_compile_definitions(
            cdisasm_arm_decode_fuzzer
            PRIVATE
                CDISASM_STATIC
                CDISASM_ARM_STATIC)
        target_compile_options(
            cdisasm_arm_decode_fuzzer
            PRIVATE
                "-fsanitize=${_cdisasm_fuzz_compile_sanitizers}"
                -fno-omit-frame-pointer)
        target_link_options(
            cdisasm_arm_decode_fuzzer
            PRIVATE "-fsanitize=${_cdisasm_fuzz_link_sanitizers}")
        target_link_libraries(
            cdisasm_arm_decode_fuzzer
            PRIVATE cdisasm_arm_fuzz_runtime)
    endif()

    unset(_cdisasm_fuzz_compile_sanitizers)
    unset(_cdisasm_fuzz_link_sanitizers)
endif()

set(_cdisasm_install_targets cdisasm)
set(_cdisasm_public_headers
    include/cdisasm/cdisasm_version.h
    include/cdisasm/cdisasm_common.h
    include/cdisasm/cdisasm.h
    include/cdisasm/cdisasm_format.h)
if(USE_ARCH_X86)
    list(APPEND _cdisasm_install_targets cdisasm_x86)
    list(APPEND _cdisasm_public_headers
        include/cdisasm/cdisasm_ids.h
        include/cdisasm/cdisasm_x86.h
        include/cdisasm/cdisasm_x86_ids.h
        include/cdisasm/cdisasm_x86_iclass_ids.inc
        include/cdisasm/cdisasm_x86_isa_set_ids.inc
        include/cdisasm/cdisasm_x86_isa_set_bits.inc)
endif()
if(USE_ARCH_ARM)
    list(APPEND _cdisasm_install_targets cdisasm_arm)
    list(APPEND _cdisasm_public_headers
        include/cdisasm/cdisasm_arm.h
        include/cdisasm/cdisasm_arm_ids.h
        include/cdisasm/cdisasm_arm_mnemonic_ids_generated.h)
endif()
if(CDISASM_EFFECTIVE_USE_DISASM_FORMAT)
    list(APPEND _cdisasm_install_targets cdisasm_format)
endif()

if(CDISASM_BUILD_SHARED_LIBS)
    set(CDISASM_PACKAGE_LINKAGE shared)
else()
    set(CDISASM_PACKAGE_LINKAGE static)
endif()
configure_file(
    cmake/cdisasm-variant.txt.in
    "${CMAKE_CURRENT_BINARY_DIR}/cdisasm-variant.txt"
    @ONLY)
unset(CDISASM_PACKAGE_LINKAGE)

# One install prefix represents exactly one linkage/feature tuple. Refuse a
# different overlay before installing any target so stale headers, import
# libraries, or package targets cannot survive from another variant.
install(CODE "
set(_cdisasm_install_libdir \"${CMAKE_INSTALL_LIBDIR}\")
if(IS_ABSOLUTE \"\${_cdisasm_install_libdir}\")
    set(_cdisasm_install_libroot
        \"\$ENV{DESTDIR}\${_cdisasm_install_libdir}\")
else()
    set(_cdisasm_install_libroot
        \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/\${_cdisasm_install_libdir}\")
endif()
set(_cdisasm_install_includedir \"${CMAKE_INSTALL_INCLUDEDIR}\")
if(IS_ABSOLUTE \"\${_cdisasm_install_includedir}\")
    set(_cdisasm_install_includeroot
        \"\$ENV{DESTDIR}\${_cdisasm_install_includedir}\")
else()
    set(_cdisasm_install_includeroot
        \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/\${_cdisasm_install_includedir}\")
endif()
set(_cdisasm_existing_variant
    \"\${_cdisasm_install_libroot}/cmake/cdisasm/cdisasm-variant.txt\")
if(EXISTS \"\${_cdisasm_existing_variant}\")
    file(READ \"\${_cdisasm_existing_variant}\" _cdisasm_existing_text)
    file(READ
        \"${CMAKE_CURRENT_BINARY_DIR}/cdisasm-variant.txt\"
        _cdisasm_expected_text)
    if(NOT _cdisasm_existing_text STREQUAL _cdisasm_expected_text)
        message(FATAL_ERROR
            \"Refusing to overlay a different cdisasm build variant at \"
            \"\${CMAKE_INSTALL_PREFIX}. Use a clean, isolated prefix.\")
    endif()
else()
    set(_cdisasm_unfingerprinted_markers
        \"\${_cdisasm_install_includeroot}/cdisasm/cdisasm_common.h\"
        \"\${_cdisasm_install_libroot}/cmake/cdisasm/cdisasmConfig.cmake\")
    foreach(_cdisasm_unfingerprinted_marker
            IN LISTS _cdisasm_unfingerprinted_markers)
        if(EXISTS \"\${_cdisasm_unfingerprinted_marker}\")
            message(FATAL_ERROR
                \"Refusing to overlay an unfingerprinted cdisasm installation \"
                \"at \${CMAKE_INSTALL_PREFIX}. Use a clean, isolated prefix.\")
        endif()
    endforeach()
endif()
unset(_cdisasm_install_libdir)
unset(_cdisasm_install_libroot)
unset(_cdisasm_install_includedir)
unset(_cdisasm_install_includeroot)
")

install(
    TARGETS ${_cdisasm_install_targets}
    EXPORT cdisasmTargets
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(
    FILES ${_cdisasm_public_headers}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/cdisasm")
install(
    FILES "${_cdisasm_generated_include_dir}/cdisasm/cdisasm_config.h"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/cdisasm")
install(
    FILES "${CMAKE_CURRENT_BINARY_DIR}/cdisasm-variant.txt"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/cdisasm")
install(
    FILES README.md LICENSE THIRD_PARTY_NOTICES.md
    DESTINATION "${CMAKE_INSTALL_DATADIR}/cdisasm")
install(
    DIRECTORY LICENSES/
    DESTINATION "${CMAKE_INSTALL_DATADIR}/cdisasm/LICENSES")
install(
    DIRECTORY docs/
    DESTINATION "${CMAKE_INSTALL_DATADIR}/cdisasm/docs")
install(
    FILES fuzz/README.md
    DESTINATION "${CMAKE_INSTALL_DATADIR}/cdisasm/fuzz")
if(USE_ARCH_X86)
    install(
        FILES fuzz/fuzz_decode2.c
        DESTINATION "${CMAKE_INSTALL_DATADIR}/cdisasm/fuzz")
    install(
        DIRECTORY fuzz/corpus/
        DESTINATION "${CMAKE_INSTALL_DATADIR}/cdisasm/fuzz/corpus"
        FILES_MATCHING
        PATTERN "*.hex")
    install(
        FILES tests/data/x86_opcodes.tsv
        DESTINATION "${CMAKE_INSTALL_DATADIR}/cdisasm/tests/data")
endif()
if(USE_ARCH_ARM)
    install(
        FILES fuzz/fuzz_arm_decode2.c
        DESTINATION "${CMAKE_INSTALL_DATADIR}/cdisasm/fuzz")
    install(
        DIRECTORY fuzz/arm_corpus/
        DESTINATION "${CMAKE_INSTALL_DATADIR}/cdisasm/fuzz/arm_corpus"
        FILES_MATCHING
        PATTERN "*.hex")
    install(
        FILES tests/data/arm_opcodes.tsv
        DESTINATION "${CMAKE_INSTALL_DATADIR}/cdisasm/tests/data")
endif()

unset(_cdisasm_install_targets)
unset(_cdisasm_public_headers)

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/cdisasmConfigVersion.cmake"
    VERSION "${PROJECT_VERSION}"
    COMPATIBILITY SameMajorVersion)
configure_package_config_file(
    cmake/cdisasmConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/cdisasmConfig.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/cdisasm")

export(
    EXPORT cdisasmTargets
    FILE "${CMAKE_CURRENT_BINARY_DIR}/cdisasmTargets.cmake"
    NAMESPACE cdisasm::)

install(
    EXPORT cdisasmTargets
    FILE cdisasmTargets.cmake
    NAMESPACE cdisasm::
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/cdisasm")
install(
    FILES
        "${CMAKE_CURRENT_BINARY_DIR}/cdisasmConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/cdisasmConfigVersion.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/cdisasm")
