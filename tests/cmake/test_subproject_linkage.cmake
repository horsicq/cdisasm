cmake_minimum_required(VERSION 3.16)

foreach(_required IN ITEMS CDISASM_SOURCE_DIR CDISASM_BINARY_DIR)
    if(NOT DEFINED ${_required} OR NOT IS_ABSOLUTE "${${_required}}")
        message(FATAL_ERROR "${_required} must be an absolute path")
    endif()
endforeach()

set(_fixture "${CDISASM_SOURCE_DIR}/tests/subproject_consumer")
set(_root "${CDISASM_BINARY_DIR}/subproject-linkage-test")
get_filename_component(_binary_absolute "${CDISASM_BINARY_DIR}" ABSOLUTE)
get_filename_component(_root "${_root}" ABSOLUTE)
get_filename_component(_root_parent "${_root}" DIRECTORY)
get_filename_component(_root_leaf "${_root}" NAME)
if(NOT _root_parent STREQUAL _binary_absolute
        OR NOT _root_leaf STREQUAL "subproject-linkage-test"
        OR IS_SYMLINK "${_root_parent}"
        OR IS_SYMLINK "${_root}")
    message(FATAL_ERROR "Refusing unsafe subproject test cleanup: ${_root}")
endif()
if(EXISTS "${_root}")
    file(REMOVE_RECURSE "${_root}")
endif()

function(_cdisasm_check_subproject_case name expected_core expected_sibling)
    set(_extra ${ARGN})
    execute_process(
        COMMAND
            "${CMAKE_COMMAND}"
            -S "${_fixture}"
            -B "${_root}/${name}"
            "-DCDISASM_SOURCE_DIR:PATH=${CDISASM_SOURCE_DIR}"
            "-DCDISASM_EXPECT_LIBRARY_TYPE:STRING=${expected_core}"
            "-DCDISASM_EXPECT_SIBLING_TYPE:STRING=${expected_sibling}"
            ${_extra}
        RESULT_VARIABLE _result
        OUTPUT_VARIABLE _output
        ERROR_VARIABLE _error)
    if(NOT _result EQUAL 0)
        message(FATAL_ERROR
            "Subproject linkage case '${name}' failed.\n"
            "stdout:\n${_output}\nstderr:\n${_error}")
    endif()
endfunction()

# With no parent-wide default, embedded cdisasm defaults shared but must not
# create BUILD_SHARED_LIBS and thereby change a later untyped sibling.
_cdisasm_check_subproject_case(
    isolated_default SHARED_LIBRARY STATIC_LIBRARY)

# A parent-wide default remains a useful default for both projects.
_cdisasm_check_subproject_case(
    parent_static STATIC_LIBRARY STATIC_LIBRARY
    -DBUILD_SHARED_LIBS:BOOL=OFF)

# The project-scoped option may override cdisasm without changing the sibling.
_cdisasm_check_subproject_case(
    scoped_static STATIC_LIBRARY SHARED_LIBRARY
    -DBUILD_SHARED_LIBS:BOOL=ON
    -DCDISASM_BUILD_SHARED_LIBS:BOOL=OFF)
