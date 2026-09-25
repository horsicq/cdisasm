cmake_minimum_required(VERSION 3.16)

project(cdisasm_package_static_embed LANGUAGES C)

include(CTest)

if(WIN32 OR NOT UNIX)
    message(FATAL_ERROR
        "The static-embedding visibility fixture requires ELF or Mach-O")
endif()

option(
    CDISASM_STATIC_EMBED_EXPECT_X86
    "Expect the installed static package to contain the x86 decoder"
    ON)
option(
    CDISASM_STATIC_EMBED_EXPECT_ARM
    "Expect the installed static package to contain the ARM decoder"
    ON)
option(
    CDISASM_STATIC_EMBED_EXPECT_FORMAT
    "Expect the installed static package to contain effective formatting"
    ON)
option(
    CDISASM_STATIC_EMBED_EXPECT_REQUESTED_EXTRA
    "Expect the installed static package to report extra opcodes requested"
    ON)
option(
    CDISASM_STATIC_EMBED_EXPECT_EXTRA
    "Expect the installed static package to contain effective extra opcodes"
    ON)

if(CDISASM_STATIC_EMBED_EXPECT_FORMAT
        AND NOT (CDISASM_STATIC_EMBED_EXPECT_X86
            OR CDISASM_STATIC_EMBED_EXPECT_ARM))
    message(FATAL_ERROR
        "Effective formatting cannot be expected without an architecture")
endif()
if(CDISASM_STATIC_EMBED_EXPECT_EXTRA
        AND NOT (CDISASM_STATIC_EMBED_EXPECT_X86
            OR CDISASM_STATIC_EMBED_EXPECT_ARM))
    message(FATAL_ERROR
        "Effective extra opcodes cannot be expected without an architecture")
endif()

set(_cdisasm_static_embed_components common)
if(CDISASM_STATIC_EMBED_EXPECT_X86)
    list(APPEND _cdisasm_static_embed_components x86)
endif()
if(CDISASM_STATIC_EMBED_EXPECT_ARM)
    list(APPEND _cdisasm_static_embed_components arm)
endif()
if(CDISASM_STATIC_EMBED_EXPECT_FORMAT)
    list(APPEND _cdisasm_static_embed_components format)
endif()

find_package(
    cdisasm CONFIG REQUIRED
    COMPONENTS ${_cdisasm_static_embed_components})

if(NOT TARGET cdisasm::cdisasm)
    message(FATAL_ERROR "cdisasm package does not export its core target")
endif()
if(NOT DEFINED cdisasm_BUILD_SHARED_LIBS
        OR NOT DEFINED cdisasm_USE_ARCH_X86
        OR NOT DEFINED cdisasm_USE_ARCH_ARM
        OR NOT DEFINED cdisasm_USE_DISASM_FORMAT
        OR NOT DEFINED cdisasm_REQUESTED_USE_EXTRA_OPCODES
        OR NOT DEFINED cdisasm_USE_EXTRA_OPCODES)
    message(FATAL_ERROR
        "cdisasm package does not report linkage and effective features")
endif()
if(cdisasm_BUILD_SHARED_LIBS)
    message(FATAL_ERROR
        "The static-embedding fixture requires an installed static package")
endif()

get_target_property(_cdisasm_static_embed_core_type cdisasm::cdisasm TYPE)
if(NOT _cdisasm_static_embed_core_type STREQUAL "STATIC_LIBRARY")
    message(FATAL_ERROR
        "cdisasm::cdisasm is ${_cdisasm_static_embed_core_type}, not static")
endif()

foreach(_cdisasm_static_embed_feature IN ITEMS X86 ARM FORMAT)
    if(CDISASM_STATIC_EMBED_EXPECT_${_cdisasm_static_embed_feature})
        set(_cdisasm_static_embed_expected_value "enabled")
    else()
        set(_cdisasm_static_embed_expected_value "disabled")
    endif()

    if(_cdisasm_static_embed_feature STREQUAL "FORMAT")
        set(_cdisasm_static_embed_package_variable
            cdisasm_USE_DISASM_FORMAT)
    else()
        set(_cdisasm_static_embed_package_variable
            cdisasm_USE_ARCH_${_cdisasm_static_embed_feature})
    endif()

    if(CDISASM_STATIC_EMBED_EXPECT_${_cdisasm_static_embed_feature})
        if(NOT ${_cdisasm_static_embed_package_variable})
            message(FATAL_ERROR
                "${_cdisasm_static_embed_package_variable} is "
                "${${_cdisasm_static_embed_package_variable}}; expected "
                "${_cdisasm_static_embed_expected_value}")
        endif()
    elseif(${_cdisasm_static_embed_package_variable})
        message(FATAL_ERROR
            "${_cdisasm_static_embed_package_variable} is "
            "${${_cdisasm_static_embed_package_variable}}; expected "
            "${_cdisasm_static_embed_expected_value}")
    endif()
endforeach()

foreach(_cdisasm_static_embed_extra_kind IN ITEMS REQUESTED EFFECTIVE)
    if(_cdisasm_static_embed_extra_kind STREQUAL "REQUESTED")
        set(_cdisasm_static_embed_extra_expected
            CDISASM_STATIC_EMBED_EXPECT_REQUESTED_EXTRA)
        set(_cdisasm_static_embed_extra_actual
            cdisasm_REQUESTED_USE_EXTRA_OPCODES)
    else()
        set(_cdisasm_static_embed_extra_expected
            CDISASM_STATIC_EMBED_EXPECT_EXTRA)
        set(_cdisasm_static_embed_extra_actual cdisasm_USE_EXTRA_OPCODES)
    endif()
    if(${_cdisasm_static_embed_extra_expected})
        if(NOT ${_cdisasm_static_embed_extra_actual})
            message(FATAL_ERROR
                "${_cdisasm_static_embed_extra_actual} is disabled; expected enabled")
        endif()
    elseif(${_cdisasm_static_embed_extra_actual})
        message(FATAL_ERROR
            "${_cdisasm_static_embed_extra_actual} is enabled; expected disabled")
    endif()
endforeach()

if(CDISASM_STATIC_EMBED_EXPECT_X86)
    set(_cdisasm_static_embed_expect_x86 1)
else()
    set(_cdisasm_static_embed_expect_x86 0)
endif()
if(CDISASM_STATIC_EMBED_EXPECT_ARM)
    set(_cdisasm_static_embed_expect_arm 1)
else()
    set(_cdisasm_static_embed_expect_arm 0)
endif()
if(CDISASM_STATIC_EMBED_EXPECT_FORMAT)
    set(_cdisasm_static_embed_expect_format 1)
else()
    set(_cdisasm_static_embed_expect_format 0)
endif()
if(CDISASM_STATIC_EMBED_EXPECT_EXTRA)
    set(_cdisasm_static_embed_expect_extra 1)
else()
    set(_cdisasm_static_embed_expect_extra 0)
endif()

add_library(cdisasm_package_static_embed_wrapper SHARED wrapper.c)
target_compile_features(
    cdisasm_package_static_embed_wrapper PRIVATE c_std_11)
target_compile_definitions(
    cdisasm_package_static_embed_wrapper
    PRIVATE
        CDISASM_STATIC_EMBED_EXPECT_X86=${_cdisasm_static_embed_expect_x86}
        CDISASM_STATIC_EMBED_EXPECT_ARM=${_cdisasm_static_embed_expect_arm}
        CDISASM_STATIC_EMBED_EXPECT_FORMAT=${_cdisasm_static_embed_expect_format}
        CDISASM_STATIC_EMBED_EXPECT_EXTRA=${_cdisasm_static_embed_expect_extra})
target_link_libraries(
    cdisasm_package_static_embed_wrapper
    PRIVATE cdisasm::cdisasm)
set_target_properties(
    cdisasm_package_static_embed_wrapper
    PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO
        C_VISIBILITY_PRESET hidden
        POSITION_INDEPENDENT_CODE ON
        OUTPUT_NAME package_static_embed)

if(APPLE)
    set(_cdisasm_static_embed_object_format MACHO)
    target_link_options(
        cdisasm_package_static_embed_wrapper
        PRIVATE "-Wl,-undefined,error")
else()
    set(_cdisasm_static_embed_object_format ELF)
    target_link_options(
        cdisasm_package_static_embed_wrapper
        PRIVATE "-Wl,--no-undefined")
endif()

set(_cdisasm_static_embed_nm "${CMAKE_NM}")
if(_cdisasm_static_embed_nm STREQUAL ""
        OR NOT EXISTS "${_cdisasm_static_embed_nm}")
    unset(_cdisasm_static_embed_nm)
    find_program(_cdisasm_static_embed_nm NAMES nm llvm-nm)
endif()

set(_cdisasm_static_embed_readelf "${CMAKE_READELF}")
if(NOT APPLE AND (_cdisasm_static_embed_readelf STREQUAL ""
        OR NOT EXISTS "${_cdisasm_static_embed_readelf}"))
    unset(_cdisasm_static_embed_readelf)
    find_program(_cdisasm_static_embed_readelf NAMES readelf llvm-readelf)
endif()

if(APPLE AND (_cdisasm_static_embed_nm STREQUAL ""
        OR NOT EXISTS "${_cdisasm_static_embed_nm}"))
    message(FATAL_ERROR "No usable nm implementation was found")
elseif(NOT APPLE
        AND (_cdisasm_static_embed_nm STREQUAL ""
            OR NOT EXISTS "${_cdisasm_static_embed_nm}")
        AND (_cdisasm_static_embed_readelf STREQUAL ""
            OR NOT EXISTS "${_cdisasm_static_embed_readelf}"))
    message(FATAL_ERROR "No usable nm or readelf implementation was found")
endif()

if(BUILD_TESTING)
    add_test(
        NAME cdisasm_package_static_embed_symbols
        COMMAND
            "${CMAKE_COMMAND}"
            "-DCDISASM_STATIC_EMBED_LIBRARY:FILEPATH=$<TARGET_FILE:cdisasm_package_static_embed_wrapper>"
            "-DCDISASM_STATIC_EMBED_NM:FILEPATH=${_cdisasm_static_embed_nm}"
            "-DCDISASM_STATIC_EMBED_READELF:FILEPATH=${_cdisasm_static_embed_readelf}"
            "-DCDISASM_STATIC_EMBED_OBJECT_FORMAT:STRING=${_cdisasm_static_embed_object_format}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/audit_symbols.cmake")
    set_tests_properties(
        cdisasm_package_static_embed_symbols
        PROPERTIES
            LABELS "package;install;visibility"
            TIMEOUT 30)
endif()
