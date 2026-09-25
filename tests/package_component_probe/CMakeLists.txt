cmake_minimum_required(VERSION 3.16)

project(cdisasm_package_component_probe LANGUAGES NONE)

if(NOT DEFINED CDISASM_COMPONENT_PROBE_COMPONENTS
        OR "${CDISASM_COMPONENT_PROBE_COMPONENTS}" STREQUAL "")
    message(FATAL_ERROR
        "CDISASM_COMPONENT_PROBE_COMPONENTS must name at least one component")
endif()

foreach(_cdisasm_probe_required
        CDISASM_COMPONENT_PROBE_EXPECT_FOUND
        CDISASM_COMPONENT_PROBE_EXPECT_SHARED
        CDISASM_COMPONENT_PROBE_EXPECT_X86
        CDISASM_COMPONENT_PROBE_EXPECT_ARM
        CDISASM_COMPONENT_PROBE_EXPECT_REQUESTED_FORMAT
        CDISASM_COMPONENT_PROBE_EXPECT_FORMAT
        CDISASM_COMPONENT_PROBE_EXPECT_REQUESTED_EXTRA
        CDISASM_COMPONENT_PROBE_EXPECT_EXTRA)
    if(NOT DEFINED ${_cdisasm_probe_required})
        message(FATAL_ERROR "${_cdisasm_probe_required} must be provided")
    endif()
endforeach()

if(CDISASM_COMPONENT_PROBE_EXPECT_FOUND)
    find_package(
        cdisasm CONFIG REQUIRED
        COMPONENTS ${CDISASM_COMPONENT_PROBE_COMPONENTS})
else()
    # Load quietly first so the driver can distinguish an intentional required
    # component rejection from an unrelated configure failure. After the
    # feature checks below, a second REQUIRED request must stop configuration.
    find_package(
        cdisasm CONFIG QUIET
        COMPONENTS ${CDISASM_COMPONENT_PROBE_COMPONENTS})
endif()

# A negative probe must fail because a requested component is unavailable,
# not because the package configuration was never loaded.
foreach(_cdisasm_package_feature
        cdisasm_USE_ARCH_X86
        cdisasm_USE_ARCH_ARM
        cdisasm_REQUESTED_USE_DISASM_FORMAT
        cdisasm_USE_DISASM_FORMAT
        cdisasm_REQUESTED_USE_EXTRA_OPCODES
        cdisasm_USE_EXTRA_OPCODES
        cdisasm_BUILD_SHARED_LIBS)
    if(NOT DEFINED ${_cdisasm_package_feature})
        message(FATAL_ERROR
            "The selected cdisasm package did not report ${_cdisasm_package_feature}")
    endif()
endforeach()

function(_cdisasm_probe_expect_boolean actual expected description)
    if(${actual})
        set(_cdisasm_actual ON)
    else()
        set(_cdisasm_actual OFF)
    endif()
    if(${expected})
        set(_cdisasm_expected ON)
    else()
        set(_cdisasm_expected OFF)
    endif()
    if(NOT _cdisasm_actual STREQUAL _cdisasm_expected)
        message(FATAL_ERROR
            "${description} is ${_cdisasm_actual}; expected ${_cdisasm_expected}")
    endif()
endfunction()

_cdisasm_probe_expect_boolean(
    cdisasm_BUILD_SHARED_LIBS
    CDISASM_COMPONENT_PROBE_EXPECT_SHARED
    "Package linkage")
_cdisasm_probe_expect_boolean(
    cdisasm_USE_ARCH_X86
    CDISASM_COMPONENT_PROBE_EXPECT_X86
    "Package x86 feature")
_cdisasm_probe_expect_boolean(
    cdisasm_USE_ARCH_ARM
    CDISASM_COMPONENT_PROBE_EXPECT_ARM
    "Package ARM feature")
_cdisasm_probe_expect_boolean(
    cdisasm_REQUESTED_USE_DISASM_FORMAT
    CDISASM_COMPONENT_PROBE_EXPECT_REQUESTED_FORMAT
    "Package requested formatter feature")
_cdisasm_probe_expect_boolean(
    cdisasm_USE_DISASM_FORMAT
    CDISASM_COMPONENT_PROBE_EXPECT_FORMAT
    "Package effective formatter feature")
_cdisasm_probe_expect_boolean(
    cdisasm_REQUESTED_USE_EXTRA_OPCODES
    CDISASM_COMPONENT_PROBE_EXPECT_REQUESTED_EXTRA
    "Package requested extra-opcode feature")
_cdisasm_probe_expect_boolean(
    cdisasm_USE_EXTRA_OPCODES
    CDISASM_COMPONENT_PROBE_EXPECT_EXTRA
    "Package effective extra-opcode feature")
_cdisasm_probe_expect_boolean(
    cdisasm_FOUND
    CDISASM_COMPONENT_PROBE_EXPECT_FOUND
    "Component request result")

if(NOT CDISASM_COMPONENT_PROBE_EXPECT_FOUND)
    message(STATUS
        "CDISASM_EXPECTED_COMPONENT_REJECTION: "
        "${CDISASM_COMPONENT_PROBE_COMPONENTS}")
    find_package(
        cdisasm CONFIG REQUIRED
        COMPONENTS ${CDISASM_COMPONENT_PROBE_COMPONENTS})
    message(FATAL_ERROR
        "Required unavailable component request unexpectedly succeeded")
endif()

if(CDISASM_COMPONENT_PROBE_EXPECT_FOUND)
    foreach(_cdisasm_component IN LISTS CDISASM_COMPONENT_PROBE_COMPONENTS)
        if(_cdisasm_component STREQUAL "common")
            set(_cdisasm_component_target cdisasm::cdisasm)
        elseif(_cdisasm_component STREQUAL "x86")
            set(_cdisasm_component_target cdisasm::cdisasm_x86)
        elseif(_cdisasm_component STREQUAL "arm")
            set(_cdisasm_component_target cdisasm::cdisasm_arm)
        elseif(_cdisasm_component STREQUAL "format")
            set(_cdisasm_component_target cdisasm::cdisasm_format)
        else()
            message(FATAL_ERROR
                "Positive probe unexpectedly used unknown component '${_cdisasm_component}'")
        endif()
        if(NOT TARGET "${_cdisasm_component_target}")
            message(FATAL_ERROR
                "Available component '${_cdisasm_component}' does not provide "
                "${_cdisasm_component_target}")
        endif()
    endforeach()
endif()
