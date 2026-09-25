cmake_minimum_required(VERSION 3.16)

project(cdisasm_package_symbol_probe LANGUAGES C)

set(
    CDISASM_SYMBOL_PROBE_COMPONENTS
    "common"
    CACHE STRING
    "Enabled components of the relocated static package")

find_package(
    cdisasm CONFIG REQUIRED
    COMPONENTS ${CDISASM_SYMBOL_PROBE_COMPONENTS})

add_library(cdisasm_package_static_wrapper SHARED wrapper.c)
target_compile_features(cdisasm_package_static_wrapper PRIVATE c_std_11)
target_link_libraries(
    cdisasm_package_static_wrapper
    PRIVATE cdisasm::cdisasm)
set_target_properties(
    cdisasm_package_static_wrapper
    PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO
        C_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN YES)

file(GENERATE
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/cdisasm-wrapper-$<CONFIG>.path"
    CONTENT "$<TARGET_FILE:cdisasm_package_static_wrapper>\n")
