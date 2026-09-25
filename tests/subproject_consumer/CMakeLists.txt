cmake_minimum_required(VERSION 3.16)

project(cdisasm_subproject_consumer LANGUAGES C)

if(NOT DEFINED CDISASM_SOURCE_DIR
        OR NOT IS_ABSOLUTE "${CDISASM_SOURCE_DIR}")
    message(FATAL_ERROR "CDISASM_SOURCE_DIR must be an absolute path")
endif()
if(NOT DEFINED CDISASM_EXPECT_LIBRARY_TYPE
        OR NOT DEFINED CDISASM_EXPECT_SIBLING_TYPE)
    message(FATAL_ERROR "Expected target types must be provided")
endif()

set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(CDISASM_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(CDISASM_BUILD_FUZZERS OFF CACHE BOOL "" FORCE)
set(CDISASM_BUILD_PACKAGE_TESTS OFF CACHE BOOL "" FORCE)

add_subdirectory("${CDISASM_SOURCE_DIR}" cdisasm-build)
add_library(cdisasm_unrelated_sibling sibling.c)

get_target_property(_cdisasm_type cdisasm TYPE)
get_target_property(_cdisasm_sibling_type cdisasm_unrelated_sibling TYPE)
if(NOT _cdisasm_type STREQUAL CDISASM_EXPECT_LIBRARY_TYPE)
    message(FATAL_ERROR
        "embedded cdisasm type is ${_cdisasm_type}; expected "
        "${CDISASM_EXPECT_LIBRARY_TYPE}")
endif()
if(NOT _cdisasm_sibling_type STREQUAL CDISASM_EXPECT_SIBLING_TYPE)
    message(FATAL_ERROR
        "unrelated sibling type is ${_cdisasm_sibling_type}; expected "
        "${CDISASM_EXPECT_SIBLING_TYPE}")
endif()
