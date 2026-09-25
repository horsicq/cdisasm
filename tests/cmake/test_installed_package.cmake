cmake_minimum_required(VERSION 3.16)

function(
    _cdisasm_require_process_success
    description
    result_variable
    output_variable
    error_variable)
    if(NOT "${${result_variable}}" STREQUAL "0")
        message(FATAL_ERROR
            "${description} failed with result ${${result_variable}}.\n"
            "stdout:\n${${output_variable}}\n"
            "stderr:\n${${error_variable}}")
    endif()
endfunction()

function(
    _cdisasm_require_process_failure
    description
    result_variable
    output_variable
    error_variable)
    if("${${result_variable}}" STREQUAL "0")
        message(FATAL_ERROR
            "${description} unexpectedly succeeded.\n"
            "stdout:\n${${output_variable}}\n"
            "stderr:\n${${error_variable}}")
    endif()
endfunction()

foreach(_cdisasm_required_variable
        CDISASM_PACKAGE_SOURCE_DIR
        CDISASM_PACKAGE_WORK_DIR
        CDISASM_PACKAGE_VERSION
        CDISASM_PACKAGE_SHARED
        CDISASM_PACKAGE_GENERATOR
        CDISASM_PACKAGE_MULTI_CONFIG
        CDISASM_PACKAGE_CTEST_COMMAND)
    if(NOT DEFINED ${_cdisasm_required_variable}
            OR "${${_cdisasm_required_variable}}" STREQUAL "")
        message(FATAL_ERROR
            "${_cdisasm_required_variable} must be provided to the installed-package test")
    endif()
endforeach()

if(NOT CDISASM_PACKAGE_VERSION MATCHES
        "^([0-9]+)\\.([0-9]+)\\.([0-9]+)$")
    message(FATAL_ERROR
        "CDISASM_PACKAGE_VERSION must be a complete numeric version, not "
        "'${CDISASM_PACKAGE_VERSION}'")
endif()
set(_cdisasm_package_version_major "${CMAKE_MATCH_1}")

if(NOT IS_ABSOLUTE "${CDISASM_PACKAGE_SOURCE_DIR}")
    message(FATAL_ERROR "CDISASM_PACKAGE_SOURCE_DIR must be absolute")
endif()
if(NOT IS_ABSOLUTE "${CDISASM_PACKAGE_WORK_DIR}")
    message(FATAL_ERROR "CDISASM_PACKAGE_WORK_DIR must be absolute")
endif()

get_filename_component(
    _cdisasm_source_dir
    "${CDISASM_PACKAGE_SOURCE_DIR}"
    ABSOLUTE)
get_filename_component(
    _cdisasm_work_dir
    "${CDISASM_PACKAGE_WORK_DIR}"
    ABSOLUTE)
file(TO_CMAKE_PATH "${_cdisasm_source_dir}" _cdisasm_source_dir)
file(TO_CMAKE_PATH "${_cdisasm_work_dir}" _cdisasm_work_dir)

foreach(_cdisasm_required_source_file
        CMakeLists.txt
        tests/package_consumer/CMakeLists.txt
        tests/package_consumer/extra_option_conflict.c
        tests/package_component_probe/CMakeLists.txt
        tests/package_symbol_probe/CMakeLists.txt
        tests/package_symbol_probe/wrapper.c
        tests/package_static_embed/CMakeLists.txt
        tests/package_static_embed/wrapper.c
        tests/package_static_embed/audit_symbols.cmake)
    if(NOT EXISTS
            "${_cdisasm_source_dir}/${_cdisasm_required_source_file}")
        message(FATAL_ERROR
            "CDISASM_PACKAGE_SOURCE_DIR does not identify the complete "
            "cdisasm source tree; missing ${_cdisasm_required_source_file} in "
            "'${_cdisasm_source_dir}'")
    endif()
endforeach()

string(TOUPPER "${CDISASM_PACKAGE_SHARED}" _cdisasm_shared_value)
if(_cdisasm_shared_value STREQUAL "1"
        OR _cdisasm_shared_value STREQUAL "ON"
        OR _cdisasm_shared_value STREQUAL "TRUE"
        OR _cdisasm_shared_value STREQUAL "YES")
    set(_cdisasm_shared ON)
    set(_cdisasm_linkage shared)
elseif(_cdisasm_shared_value STREQUAL "0"
        OR _cdisasm_shared_value STREQUAL "OFF"
        OR _cdisasm_shared_value STREQUAL "FALSE"
        OR _cdisasm_shared_value STREQUAL "NO")
    set(_cdisasm_shared OFF)
    set(_cdisasm_linkage static)
else()
    message(FATAL_ERROR
        "CDISASM_PACKAGE_SHARED must be a CMake boolean, not "
        "'${CDISASM_PACKAGE_SHARED}'")
endif()

get_filename_component(_cdisasm_work_leaf "${_cdisasm_work_dir}" NAME)
get_filename_component(
    _cdisasm_work_parent
    "${_cdisasm_work_dir}"
    DIRECTORY)
get_filename_component(
    _cdisasm_work_parent_leaf
    "${_cdisasm_work_parent}"
    NAME)
if(NOT _cdisasm_work_leaf STREQUAL _cdisasm_linkage
        OR NOT _cdisasm_work_parent_leaf STREQUAL "package-test-build")
    message(FATAL_ERROR
        "Refusing to clean '${_cdisasm_work_dir}'. "
        "CDISASM_PACKAGE_WORK_DIR must be the exact "
        "package-test-build/${_cdisasm_linkage} leaf")
endif()
if(IS_SYMLINK "${_cdisasm_work_parent}")
    message(FATAL_ERROR
        "Refusing to clean through symlinked package-test parent "
        "'${_cdisasm_work_parent}'")
endif()

# Never remove a directory that contains the source tree, even if a caller has
# deliberately given it the expected leaf spelling.
file(RELATIVE_PATH
    _cdisasm_source_from_work
    "${_cdisasm_work_dir}"
    "${_cdisasm_source_dir}")
if(_cdisasm_source_from_work STREQUAL ""
        OR (NOT IS_ABSOLUTE "${_cdisasm_source_from_work}"
            AND NOT _cdisasm_source_from_work STREQUAL ".."
            AND NOT _cdisasm_source_from_work MATCHES "^\\.\\./"))
    message(FATAL_ERROR
        "Refusing to clean '${_cdisasm_work_dir}' because it contains the "
        "source tree '${_cdisasm_source_dir}'")
endif()

if(IS_SYMLINK "${_cdisasm_work_dir}")
    message(FATAL_ERROR
        "Refusing to clean symlinked work directory '${_cdisasm_work_dir}'")
endif()
if(EXISTS "${_cdisasm_work_dir}")
    file(REMOVE_RECURSE "${_cdisasm_work_dir}")
endif()
if(EXISTS "${_cdisasm_work_dir}")
    message(FATAL_ERROR
        "Could not clean installed-package work directory "
        "'${_cdisasm_work_dir}'")
endif()
file(MAKE_DIRECTORY "${_cdisasm_work_dir}")

set(_cdisasm_config "${CDISASM_PACKAGE_CONFIG}")
if(_cdisasm_config STREQUAL "")
    set(_cdisasm_config "${CDISASM_PACKAGE_FALLBACK_CONFIG}")
endif()
if(_cdisasm_config STREQUAL "")
    set(_cdisasm_config Release)
endif()
if(_cdisasm_config MATCHES ";")
    message(FATAL_ERROR
        "The installed-package configuration must not contain semicolons")
endif()

string(TOUPPER
    "${CDISASM_PACKAGE_MULTI_CONFIG}"
    _cdisasm_multi_config_value)
if(_cdisasm_multi_config_value STREQUAL "1"
        OR _cdisasm_multi_config_value STREQUAL "ON"
        OR _cdisasm_multi_config_value STREQUAL "TRUE"
        OR _cdisasm_multi_config_value STREQUAL "YES")
    set(_cdisasm_multi_config ON)
elseif(_cdisasm_multi_config_value STREQUAL "0"
        OR _cdisasm_multi_config_value STREQUAL "OFF"
        OR _cdisasm_multi_config_value STREQUAL "FALSE"
        OR _cdisasm_multi_config_value STREQUAL "NO")
    set(_cdisasm_multi_config OFF)
else()
    message(FATAL_ERROR
        "CDISASM_PACKAGE_MULTI_CONFIG must be a CMake boolean, not "
        "'${CDISASM_PACKAGE_MULTI_CONFIG}'")
endif()

set(
    _cdisasm_generator_arguments
    -G "${CDISASM_PACKAGE_GENERATOR}")
if(NOT "${CDISASM_PACKAGE_GENERATOR_PLATFORM}" STREQUAL "")
    list(APPEND
        _cdisasm_generator_arguments
        -A "${CDISASM_PACKAGE_GENERATOR_PLATFORM}")
endif()
if(NOT "${CDISASM_PACKAGE_GENERATOR_TOOLSET}" STREQUAL "")
    list(APPEND
        _cdisasm_generator_arguments
        -T "${CDISASM_PACKAGE_GENERATOR_TOOLSET}")
endif()

set(_cdisasm_identity_arguments)
if(NOT "${CDISASM_PACKAGE_GENERATOR_INSTANCE}" STREQUAL "")
    list(APPEND
        _cdisasm_identity_arguments
        "-DCMAKE_GENERATOR_INSTANCE:STRING=${CDISASM_PACKAGE_GENERATOR_INSTANCE}")
endif()
if(NOT "${CDISASM_PACKAGE_MAKE_PROGRAM}" STREQUAL "")
    list(APPEND
        _cdisasm_identity_arguments
        "-DCMAKE_MAKE_PROGRAM:FILEPATH=${CDISASM_PACKAGE_MAKE_PROGRAM}")
endif()
if(NOT "${CDISASM_PACKAGE_TOOLCHAIN_FILE}" STREQUAL "")
    list(APPEND
        _cdisasm_identity_arguments
        "-DCMAKE_TOOLCHAIN_FILE:FILEPATH=${CDISASM_PACKAGE_TOOLCHAIN_FILE}")
endif()
if(NOT "${CDISASM_PACKAGE_C_COMPILER}" STREQUAL "")
    list(APPEND
        _cdisasm_identity_arguments
        "-DCMAKE_C_COMPILER:FILEPATH=${CDISASM_PACKAGE_C_COMPILER}")
endif()
if(DEFINED CDISASM_PACKAGE_CXX_COMPILER
        AND NOT "${CDISASM_PACKAGE_CXX_COMPILER}" STREQUAL "")
    list(APPEND
        _cdisasm_identity_arguments
        "-DCMAKE_CXX_COMPILER:FILEPATH=${CDISASM_PACKAGE_CXX_COMPILER}")
endif()
if(NOT _cdisasm_multi_config)
    list(APPEND
        _cdisasm_identity_arguments
        "-DCMAKE_BUILD_TYPE:STRING=${_cdisasm_config}")
else()
    # check_*_source_compiles() creates a nested try-compile project. Without
    # this setting a Release package test can silently select Debug and then
    # look for a producer artifact that was never built.
    list(APPEND
        _cdisasm_identity_arguments
        "-DCMAKE_TRY_COMPILE_CONFIGURATION:STRING=${_cdisasm_config}")
endif()

function(_cdisasm_validate_package_files description package_dir)
    if(NOT EXISTS "${package_dir}/cdisasmConfig.cmake"
            OR NOT EXISTS "${package_dir}/cdisasmConfigVersion.cmake"
            OR NOT EXISTS "${package_dir}/cdisasmTargets.cmake")
        message(FATAL_ERROR
            "${description} does not contain a complete cdisasm package at "
            "'${package_dir}'")
    endif()
endfunction()

function(
    _cdisasm_run_consumer
    context
    package_dir
    consumer_build_dir
    expected_x86
    expected_arm
    expected_format
    expected_requested_extra
    expected_extra
    components)
    _cdisasm_validate_package_files("${context}" "${package_dir}")

    execute_process(
        COMMAND
            "${CMAKE_COMMAND}"
            -S "${_cdisasm_source_dir}/tests/package_consumer"
            -B "${consumer_build_dir}"
            ${_cdisasm_generator_arguments}
            ${_cdisasm_identity_arguments}
            -DBUILD_TESTING:BOOL=ON
            -DCMAKE_FIND_USE_PACKAGE_REGISTRY:BOOL=OFF
            -DCMAKE_FIND_PACKAGE_NO_PACKAGE_REGISTRY:BOOL=ON
            -DCMAKE_FIND_PACKAGE_NO_SYSTEM_PACKAGE_REGISTRY:BOOL=ON
            "-Dcdisasm_DIR:PATH=${package_dir}"
            "-DCDISASM_PACKAGE_EXPECT_VERSION:STRING=${CDISASM_PACKAGE_VERSION}"
            "-DCDISASM_PACKAGE_COMPONENTS:STRING=${components}"
            "-DCDISASM_PACKAGE_EXPECT_SHARED:BOOL=${_cdisasm_shared}"
            "-DCDISASM_PACKAGE_EXPECT_X86:BOOL=${expected_x86}"
            "-DCDISASM_PACKAGE_EXPECT_ARM:BOOL=${expected_arm}"
            "-DCDISASM_PACKAGE_EXPECT_FORMAT:BOOL=${expected_format}"
            "-DCDISASM_PACKAGE_EXPECT_REQUESTED_EXTRA:BOOL=${expected_requested_extra}"
            "-DCDISASM_PACKAGE_EXPECT_EXTRA:BOOL=${expected_extra}"
        RESULT_VARIABLE _cdisasm_consumer_configure_result
        OUTPUT_VARIABLE _cdisasm_consumer_configure_output
        ERROR_VARIABLE _cdisasm_consumer_configure_error)
    _cdisasm_require_process_success(
        "${context} consumer configure"
        _cdisasm_consumer_configure_result
        _cdisasm_consumer_configure_output
        _cdisasm_consumer_configure_error)

    execute_process(
        COMMAND
            "${CMAKE_COMMAND}"
            --build "${consumer_build_dir}"
            --config "${_cdisasm_config}"
        RESULT_VARIABLE _cdisasm_consumer_build_result
        OUTPUT_VARIABLE _cdisasm_consumer_build_output
        ERROR_VARIABLE _cdisasm_consumer_build_error)
    _cdisasm_require_process_success(
        "${context} consumer build"
        _cdisasm_consumer_build_result
        _cdisasm_consumer_build_output
        _cdisasm_consumer_build_error)

    execute_process(
        COMMAND
            "${CDISASM_PACKAGE_CTEST_COMMAND}"
            -C "${_cdisasm_config}"
            --show-only=json-v1
        WORKING_DIRECTORY "${consumer_build_dir}"
        RESULT_VARIABLE _cdisasm_ctest_list_result
        OUTPUT_VARIABLE _cdisasm_ctest_list_output
        ERROR_VARIABLE _cdisasm_ctest_list_error)
    _cdisasm_require_process_success(
        "${context} consumer CTest JSON listing"
        _cdisasm_ctest_list_result
        _cdisasm_ctest_list_output
        _cdisasm_ctest_list_error)

    set(
        _cdisasm_expected_consumer_tests
        cdisasm_package_smoke
        cdisasm_package_id_smoke
        cdisasm_package_dispatch_smoke
        cdisasm_package_explicit_smoke
        cdisasm_package_cpp_core_smoke)
    if(expected_x86)
        list(APPEND
            _cdisasm_expected_consumer_tests
            cdisasm_package_cpp_x86_proxy_smoke)
    endif()
    if(expected_arm)
        list(APPEND
            _cdisasm_expected_consumer_tests
            cdisasm_package_cpp_arm_proxy_smoke)
    endif()
    if(expected_format)
        list(APPEND
            _cdisasm_expected_consumer_tests
            cdisasm_package_cpp_format_proxy_smoke)
    endif()

    set(
        _cdisasm_all_consumer_tests
        cdisasm_package_smoke
        cdisasm_package_id_smoke
        cdisasm_package_dispatch_smoke
        cdisasm_package_explicit_smoke
        cdisasm_package_cpp_core_smoke
        cdisasm_package_cpp_x86_proxy_smoke
        cdisasm_package_cpp_arm_proxy_smoke
        cdisasm_package_cpp_format_proxy_smoke)
    foreach(_cdisasm_consumer_test IN LISTS _cdisasm_all_consumer_tests)
        string(REGEX MATCH
            "\"name\"[ \t\r\n]*:[ \t\r\n]*\"${_cdisasm_consumer_test}\""
            _cdisasm_consumer_test_match
            "${_cdisasm_ctest_list_output}")
        list(FIND
            _cdisasm_expected_consumer_tests
            "${_cdisasm_consumer_test}"
            _cdisasm_expected_test_index)
        if(_cdisasm_expected_test_index EQUAL -1)
            if(NOT _cdisasm_consumer_test_match STREQUAL "")
                message(FATAL_ERROR
                    "${context} unexpectedly lists disabled consumer test "
                    "'${_cdisasm_consumer_test}'.\n"
                    "CTest JSON:\n${_cdisasm_ctest_list_output}")
            endif()
        elseif(_cdisasm_consumer_test_match STREQUAL "")
            message(FATAL_ERROR
                "${context} does not list expected consumer test "
                "'${_cdisasm_consumer_test}'.\n"
                "CTest JSON:\n${_cdisasm_ctest_list_output}")
        endif()
    endforeach()

    string(REGEX MATCHALL
        "\"name\"[ \t\r\n]*:[ \t\r\n]*\"cdisasm_package_[A-Za-z0-9_]+\""
        _cdisasm_listed_consumer_tests
        "${_cdisasm_ctest_list_output}")
    list(LENGTH
        _cdisasm_listed_consumer_tests
        _cdisasm_listed_consumer_test_count)
    list(LENGTH
        _cdisasm_expected_consumer_tests
        _cdisasm_expected_consumer_test_count)
    if(NOT _cdisasm_listed_consumer_test_count EQUAL
            _cdisasm_expected_consumer_test_count)
        message(FATAL_ERROR
            "${context} lists ${_cdisasm_listed_consumer_test_count} package "
            "tests; expected exactly ${_cdisasm_expected_consumer_test_count}.\n"
            "CTest JSON:\n${_cdisasm_ctest_list_output}")
    endif()

    execute_process(
        COMMAND
            "${CDISASM_PACKAGE_CTEST_COMMAND}"
            -C "${_cdisasm_config}"
            --output-on-failure
        WORKING_DIRECTORY "${consumer_build_dir}"
        RESULT_VARIABLE _cdisasm_ctest_result
        OUTPUT_VARIABLE _cdisasm_ctest_output
        ERROR_VARIABLE _cdisasm_ctest_error)
    _cdisasm_require_process_success(
        "${context} consumer CTest run"
        _cdisasm_ctest_result
        _cdisasm_ctest_output
        _cdisasm_ctest_error)
endfunction()

function(
    _cdisasm_run_component_probe
    context
    package_dir
    probe_build_dir
    components
    expected_found
    expected_x86
    expected_arm
    expected_requested_format
    expected_format
    expected_requested_extra
    expected_extra)
    execute_process(
        COMMAND
            "${CMAKE_COMMAND}"
            -S "${_cdisasm_source_dir}/tests/package_component_probe"
            -B "${probe_build_dir}"
            ${_cdisasm_generator_arguments}
            ${_cdisasm_identity_arguments}
            -DCMAKE_FIND_USE_PACKAGE_REGISTRY:BOOL=OFF
            -DCMAKE_FIND_PACKAGE_NO_PACKAGE_REGISTRY:BOOL=ON
            -DCMAKE_FIND_PACKAGE_NO_SYSTEM_PACKAGE_REGISTRY:BOOL=ON
            "-Dcdisasm_DIR:PATH=${package_dir}"
            "-DCDISASM_COMPONENT_PROBE_COMPONENTS:STRING=${components}"
            "-DCDISASM_COMPONENT_PROBE_EXPECT_FOUND:BOOL=${expected_found}"
            "-DCDISASM_COMPONENT_PROBE_EXPECT_SHARED:BOOL=${_cdisasm_shared}"
            "-DCDISASM_COMPONENT_PROBE_EXPECT_X86:BOOL=${expected_x86}"
            "-DCDISASM_COMPONENT_PROBE_EXPECT_ARM:BOOL=${expected_arm}"
            "-DCDISASM_COMPONENT_PROBE_EXPECT_REQUESTED_FORMAT:BOOL=${expected_requested_format}"
            "-DCDISASM_COMPONENT_PROBE_EXPECT_FORMAT:BOOL=${expected_format}"
            "-DCDISASM_COMPONENT_PROBE_EXPECT_REQUESTED_EXTRA:BOOL=${expected_requested_extra}"
            "-DCDISASM_COMPONENT_PROBE_EXPECT_EXTRA:BOOL=${expected_extra}"
        RESULT_VARIABLE _cdisasm_probe_result
        OUTPUT_VARIABLE _cdisasm_probe_output
        ERROR_VARIABLE _cdisasm_probe_error)
    if(expected_found)
        _cdisasm_require_process_success(
            "${context} positive component probe (${components})"
            _cdisasm_probe_result
            _cdisasm_probe_output
            _cdisasm_probe_error)
    else()
        _cdisasm_require_process_failure(
            "${context} negative component probe (${components})"
            _cdisasm_probe_result
            _cdisasm_probe_output
            _cdisasm_probe_error)
        set(_cdisasm_probe_log
            "${_cdisasm_probe_output}\n${_cdisasm_probe_error}")
        if(NOT _cdisasm_probe_log MATCHES
                "CDISASM_EXPECTED_COMPONENT_REJECTION")
            message(FATAL_ERROR
                "${context} negative component probe (${components}) failed "
                "before validating the intended package rejection.\n"
                "stdout:\n${_cdisasm_probe_output}\n"
                "stderr:\n${_cdisasm_probe_error}")
        endif()
    endif()
endfunction()

function(
    _cdisasm_audit_installed_corpus
    context
    prefix
    corpus_name
    source_directory
    expected_enabled)
    set(_cdisasm_installed_corpus
        "${prefix}/share/cdisasm/fuzz/${corpus_name}")
    if(NOT expected_enabled)
        if(EXISTS "${_cdisasm_installed_corpus}")
            message(FATAL_ERROR
                "${context} unexpectedly installed disabled ${corpus_name} corpus")
        endif()
        return()
    endif()

    if(NOT IS_DIRECTORY "${_cdisasm_installed_corpus}")
        message(FATAL_ERROR
            "${context} is missing enabled ${corpus_name} corpus")
    endif()
    file(GLOB
        _cdisasm_expected_corpus_files
        RELATIVE "${source_directory}"
        "${source_directory}/*.hex")
    if(NOT _cdisasm_expected_corpus_files)
        message(FATAL_ERROR
            "${context} source ${corpus_name} corpus contains no reviewed "
            ".hex seeds")
    endif()
    file(GLOB
        _cdisasm_actual_corpus_files
        RELATIVE "${_cdisasm_installed_corpus}"
        "${_cdisasm_installed_corpus}/*")
    foreach(_cdisasm_corpus_file IN LISTS _cdisasm_actual_corpus_files)
        if(IS_DIRECTORY
                "${_cdisasm_installed_corpus}/${_cdisasm_corpus_file}")
            message(FATAL_ERROR
                "${context} installed unexpected ${corpus_name} corpus directory "
                "'${_cdisasm_corpus_file}'")
        endif()
    endforeach()
    list(SORT _cdisasm_expected_corpus_files)
    list(SORT _cdisasm_actual_corpus_files)
    if(NOT "${_cdisasm_actual_corpus_files}" STREQUAL
            "${_cdisasm_expected_corpus_files}")
        message(FATAL_ERROR
            "${context} ${corpus_name} corpus is not the exact reviewed .hex set.\n"
            "actual:   ${_cdisasm_actual_corpus_files}\n"
            "expected: ${_cdisasm_expected_corpus_files}")
    endif()
endfunction()

function(
    _cdisasm_audit_install
    context
    prefix
    expected_x86
    expected_arm
    out_library_artifact)
    set(
        _cdisasm_expected_headers
        cdisasm.h
        cdisasm_common.h
        cdisasm_config.h
        cdisasm_format.h
        cdisasm_version.h)
    if(expected_x86)
        list(APPEND
            _cdisasm_expected_headers
            cdisasm_ids.h
            cdisasm_x86.h
            cdisasm_x86_ids.h
            cdisasm_x86_iclass_ids.inc
            cdisasm_x86_isa_set_bits.inc
            cdisasm_x86_isa_set_ids.inc)
    endif()
    if(expected_arm)
        list(APPEND
            _cdisasm_expected_headers
            cdisasm_arm.h
            cdisasm_arm_ids.h
            cdisasm_arm_mnemonic_ids_generated.h)
    endif()
    list(SORT _cdisasm_expected_headers)

    set(_cdisasm_header_dir "${prefix}/include/cdisasm")
    if(NOT IS_DIRECTORY "${_cdisasm_header_dir}")
        message(FATAL_ERROR
            "${context} is missing '${_cdisasm_header_dir}'")
    endif()
    file(GLOB
        _cdisasm_header_entries
        RELATIVE "${_cdisasm_header_dir}"
        "${_cdisasm_header_dir}/*")
    set(_cdisasm_actual_headers)
    foreach(_cdisasm_header_entry IN LISTS _cdisasm_header_entries)
        if(IS_DIRECTORY
                "${_cdisasm_header_dir}/${_cdisasm_header_entry}")
            message(FATAL_ERROR
                "${context} contains unexpected public-header directory "
                "'${_cdisasm_header_entry}'")
        endif()
        list(APPEND _cdisasm_actual_headers "${_cdisasm_header_entry}")
    endforeach()
    list(SORT _cdisasm_actual_headers)
    if(NOT "${_cdisasm_actual_headers}" STREQUAL
            "${_cdisasm_expected_headers}")
        message(FATAL_ERROR
            "${context} public headers are not exact.\n"
            "actual:   ${_cdisasm_actual_headers}\n"
            "expected: ${_cdisasm_expected_headers}")
    endif()

    _cdisasm_audit_installed_corpus(
        "${context}"
        "${prefix}"
        corpus
        "${_cdisasm_source_dir}/fuzz/corpus"
        "${expected_x86}")
    _cdisasm_audit_installed_corpus(
        "${context}"
        "${prefix}"
        arm_corpus
        "${_cdisasm_source_dir}/fuzz/arm_corpus"
        "${expected_arm}")

    set(_cdisasm_bin_files)
    if(IS_DIRECTORY "${prefix}/bin")
        file(GLOB
            _cdisasm_bin_entries
            RELATIVE "${prefix}"
            "${prefix}/bin/*")
        foreach(_cdisasm_entry IN LISTS _cdisasm_bin_entries)
            if(IS_DIRECTORY "${prefix}/${_cdisasm_entry}")
                message(FATAL_ERROR
                    "${context} contains unexpected bin directory "
                    "'${_cdisasm_entry}'")
            endif()
            list(APPEND _cdisasm_bin_files "${_cdisasm_entry}")
        endforeach()
    endif()

    set(_cdisasm_lib_files)
    if(NOT IS_DIRECTORY "${prefix}/lib")
        message(FATAL_ERROR "${context} is missing its lib directory")
    endif()
    file(GLOB
        _cdisasm_lib_entries
        RELATIVE "${prefix}"
        "${prefix}/lib/*")
    foreach(_cdisasm_entry IN LISTS _cdisasm_lib_entries)
        if(IS_DIRECTORY "${prefix}/${_cdisasm_entry}")
            if(NOT _cdisasm_entry STREQUAL "lib/cmake")
                message(FATAL_ERROR
                    "${context} contains unexpected lib directory "
                    "'${_cdisasm_entry}'")
            endif()
        else()
            list(APPEND _cdisasm_lib_files "${_cdisasm_entry}")
        endif()
    endforeach()

    foreach(_cdisasm_library_file
            IN LISTS _cdisasm_bin_files _cdisasm_lib_files)
        string(TOLOWER
            "${_cdisasm_library_file}"
            _cdisasm_library_file_lower)
        if(_cdisasm_library_file_lower MATCHES
                "cdisasm_(x86|arm|format)")
            message(FATAL_ERROR
                "${context} installed a forbidden compatibility library "
                "'${_cdisasm_library_file}'")
        endif()
    endforeach()

    if(WIN32)
        list(LENGTH _cdisasm_bin_files _cdisasm_bin_file_count)
        list(LENGTH _cdisasm_lib_files _cdisasm_lib_file_count)
        if(_cdisasm_shared)
            if(NOT _cdisasm_bin_file_count EQUAL 1
                    OR NOT _cdisasm_lib_file_count EQUAL 1)
                message(FATAL_ERROR
                    "${context} must contain exactly one DLL and one import "
                    "library; bin=${_cdisasm_bin_files}, lib=${_cdisasm_lib_files}")
            endif()
            list(GET _cdisasm_bin_files 0 _cdisasm_runtime_file)
            list(GET _cdisasm_lib_files 0 _cdisasm_import_file)
            string(TOLOWER "${_cdisasm_runtime_file}" _cdisasm_runtime_lower)
            string(TOLOWER "${_cdisasm_import_file}" _cdisasm_import_lower)
            if(NOT _cdisasm_runtime_lower MATCHES
                    "(^|/)(lib)?cdisasm-${_cdisasm_package_version_major}\\.dll$")
                message(FATAL_ERROR
                    "${context} runtime does not carry ABI major "
                    "${_cdisasm_package_version_major}: "
                    "'${_cdisasm_runtime_file}'")
            endif()
            if(NOT _cdisasm_import_lower MATCHES
                    "(^|/)(lib)?cdisasm[^/]*(\\.lib|\\.dll\\.a)$")
                message(FATAL_ERROR
                    "${context} unexpected import library "
                    "'${_cdisasm_import_file}'")
            endif()
            set(_cdisasm_library_artifact
                "${prefix}/${_cdisasm_runtime_file}")
        else()
            if(NOT _cdisasm_bin_file_count EQUAL 0
                    OR NOT _cdisasm_lib_file_count EQUAL 1)
                message(FATAL_ERROR
                    "${context} must contain exactly one static archive and "
                    "no runtime; bin=${_cdisasm_bin_files}, lib=${_cdisasm_lib_files}")
            endif()
            list(GET _cdisasm_lib_files 0 _cdisasm_archive_file)
            string(TOLOWER "${_cdisasm_archive_file}" _cdisasm_archive_lower)
            if(NOT _cdisasm_archive_lower MATCHES
                    "(^|/)(lib)?cdisasm[^/]*(\\.lib|\\.a)$"
                    OR _cdisasm_archive_lower MATCHES "\\.dll\\.a$")
                message(FATAL_ERROR
                    "${context} unexpected static archive "
                    "'${_cdisasm_archive_file}'")
            endif()
            set(_cdisasm_library_artifact
                "${prefix}/${_cdisasm_archive_file}")
        endif()
    elseif(APPLE)
        if(_cdisasm_bin_files)
            message(FATAL_ERROR
                "${context} unexpectedly installed bin files: "
                "${_cdisasm_bin_files}")
        endif()
        if(_cdisasm_shared)
            if(NOT _cdisasm_lib_files)
                message(FATAL_ERROR "${context} installed no shared library")
            endif()
            foreach(_cdisasm_library_file IN LISTS _cdisasm_lib_files)
                if(NOT _cdisasm_library_file MATCHES
                        "^lib/libcdisasm(\\.[0-9.]+)?\\.dylib$")
                    message(FATAL_ERROR
                        "${context} unexpected library '${_cdisasm_library_file}'")
                endif()
            endforeach()
            if(NOT EXISTS
                    "${prefix}/lib/libcdisasm.${_cdisasm_package_version_major}.dylib")
                message(FATAL_ERROR
                    "${context} is missing the major-version Mach-O link "
                    "libcdisasm.${_cdisasm_package_version_major}.dylib")
            endif()
            if(EXISTS "${prefix}/lib/libcdisasm.dylib")
                set(_cdisasm_library_artifact
                    "${prefix}/lib/libcdisasm.dylib")
            else()
                list(GET _cdisasm_lib_files 0 _cdisasm_library_file)
                set(_cdisasm_library_artifact
                    "${prefix}/${_cdisasm_library_file}")
            endif()
        else()
            if(NOT "${_cdisasm_lib_files}" STREQUAL "lib/libcdisasm.a")
                message(FATAL_ERROR
                    "${context} static layout is not exact: "
                    "${_cdisasm_lib_files}")
            endif()
            set(_cdisasm_library_artifact "${prefix}/lib/libcdisasm.a")
        endif()
    elseif(UNIX)
        if(_cdisasm_bin_files)
            message(FATAL_ERROR
                "${context} unexpectedly installed bin files: "
                "${_cdisasm_bin_files}")
        endif()
        if(_cdisasm_shared)
            if(NOT _cdisasm_lib_files)
                message(FATAL_ERROR "${context} installed no shared library")
            endif()
            foreach(_cdisasm_library_file IN LISTS _cdisasm_lib_files)
                if(NOT _cdisasm_library_file MATCHES
                        "^lib/libcdisasm\\.so(\\.[0-9.]+)?$")
                    message(FATAL_ERROR
                        "${context} unexpected library '${_cdisasm_library_file}'")
                endif()
            endforeach()
            if(NOT EXISTS
                    "${prefix}/lib/libcdisasm.so.${_cdisasm_package_version_major}")
                message(FATAL_ERROR
                    "${context} is missing the major-version ELF link "
                    "libcdisasm.so.${_cdisasm_package_version_major}")
            endif()
            if(EXISTS "${prefix}/lib/libcdisasm.so")
                set(_cdisasm_library_artifact
                    "${prefix}/lib/libcdisasm.so")
            else()
                list(GET _cdisasm_lib_files 0 _cdisasm_library_file)
                set(_cdisasm_library_artifact
                    "${prefix}/${_cdisasm_library_file}")
            endif()
        else()
            if(NOT "${_cdisasm_lib_files}" STREQUAL "lib/libcdisasm.a")
                message(FATAL_ERROR
                    "${context} static layout is not exact: "
                    "${_cdisasm_lib_files}")
            endif()
            set(_cdisasm_library_artifact "${prefix}/lib/libcdisasm.a")
        endif()
    else()
        message(FATAL_ERROR
            "${context} cannot audit libraries on this host platform")
    endif()

    if(NOT EXISTS "${_cdisasm_library_artifact}")
        message(FATAL_ERROR
            "${context} selected missing library artifact "
            "'${_cdisasm_library_artifact}'")
    endif()
    set(${out_library_artifact}
        "${_cdisasm_library_artifact}"
        PARENT_SCOPE)
endfunction()

function(
    _cdisasm_read_symbols
    context
    artifact
    dynamic_symbols
    out_symbols)
    set(_cdisasm_inspector)
    set(_cdisasm_inspector_arguments)
    if(WIN32 AND dynamic_symbols)
        find_program(_cdisasm_llvm_readobj NAMES llvm-readobj)
        if(_cdisasm_llvm_readobj)
            set(_cdisasm_inspector "${_cdisasm_llvm_readobj}")
            set(_cdisasm_inspector_arguments --coff-exports "${artifact}")
        else()
            find_program(_cdisasm_dumpbin NAMES dumpbin)
            if(_cdisasm_dumpbin)
                set(_cdisasm_inspector "${_cdisasm_dumpbin}")
                set(_cdisasm_inspector_arguments /exports "${artifact}")
            endif()
        endif()
    elseif(WIN32)
        find_program(_cdisasm_llvm_nm NAMES llvm-nm nm)
        if(_cdisasm_llvm_nm)
            set(_cdisasm_inspector "${_cdisasm_llvm_nm}")
            set(_cdisasm_inspector_arguments --defined-only "${artifact}")
        else()
            find_program(_cdisasm_dumpbin NAMES dumpbin)
            if(_cdisasm_dumpbin)
                set(_cdisasm_inspector "${_cdisasm_dumpbin}")
                set(_cdisasm_inspector_arguments /symbols "${artifact}")
            endif()
        endif()
    elseif(APPLE)
        find_program(_cdisasm_nm NAMES nm llvm-nm)
        if(_cdisasm_nm)
            set(_cdisasm_inspector "${_cdisasm_nm}")
            if(dynamic_symbols)
                set(_cdisasm_inspector_arguments -gU "${artifact}")
            else()
                set(_cdisasm_inspector_arguments -g "${artifact}")
            endif()
        endif()
    elseif(UNIX)
        find_program(_cdisasm_nm NAMES nm llvm-nm)
        if(_cdisasm_nm)
            set(_cdisasm_inspector "${_cdisasm_nm}")
            if(dynamic_symbols)
                set(_cdisasm_inspector_arguments
                    -D --defined-only "${artifact}")
            else()
                set(_cdisasm_inspector_arguments
                    -g --defined-only "${artifact}")
            endif()
        elseif(dynamic_symbols)
            find_program(_cdisasm_readelf NAMES readelf llvm-readelf)
            if(_cdisasm_readelf)
                set(_cdisasm_inspector "${_cdisasm_readelf}")
                set(_cdisasm_inspector_arguments
                    --dyn-syms --wide "${artifact}")
            endif()
        endif()
    endif()

    if(NOT _cdisasm_inspector)
        message(FATAL_ERROR
            "${context} requires a supported symbol inspector "
            "(llvm-readobj, dumpbin, nm, or readelf)")
    endif()

    execute_process(
        COMMAND "${_cdisasm_inspector}" ${_cdisasm_inspector_arguments}
        RESULT_VARIABLE _cdisasm_inspector_result
        OUTPUT_VARIABLE _cdisasm_inspector_output
        ERROR_VARIABLE _cdisasm_inspector_error)
    _cdisasm_require_process_success(
        "${context} symbol inspection with ${_cdisasm_inspector}"
        _cdisasm_inspector_result
        _cdisasm_inspector_output
        _cdisasm_inspector_error)
    set(${out_symbols}
        "${_cdisasm_inspector_output}\n${_cdisasm_inspector_error}"
        PARENT_SCOPE)
endfunction()

function(_cdisasm_symbol_is_present symbol_text symbol out_present)
    string(REGEX MATCH
        "(^|[^A-Za-z0-9_])_?${symbol}([^A-Za-z0-9_]|$)"
        _cdisasm_symbol_match
        "${symbol_text}")
    if(_cdisasm_symbol_match STREQUAL "")
        set(${out_present} OFF PARENT_SCOPE)
    else()
        set(${out_present} ON PARENT_SCOPE)
    endif()
endfunction()

set(
    _cdisasm_all_public_symbols
    cdisasm_version
    cdisasm_version_string
    cdisasm_status_string
    cdisasm_current_cpu
    cdisasm_instruction_size
    cdisasm_cpu_decode_flag_mask
    cdisasm_decode
    cdisasm_decode_checked
    cdisasm_x86_cpu_mode_mask
    cdisasm_x86_cpu_decode_flag_mask
    cdisasm_x86_decode
    cdisasm_arm_cpu_mode_mask
    cdisasm_arm_decoder_mode_mask
    cdisasm_arm_cpu_decode_flag_mask
    cdisasm_arm_decode
    cdisasm_x86_format
    cdisasm_x86_format_mode
    cdisasm_format
    cdisasm_arm_format)

function(
    _cdisasm_audit_core_symbols
    context
    library_artifact
    expected_x86
    expected_arm
    expected_format)
    _cdisasm_read_symbols(
        "${context}"
        "${library_artifact}"
        "${_cdisasm_shared}"
        _cdisasm_core_symbol_text)

    set(
        _cdisasm_expected_symbols
        cdisasm_version
        cdisasm_version_string
        cdisasm_status_string
        cdisasm_current_cpu
        cdisasm_instruction_size
        cdisasm_cpu_decode_flag_mask
        cdisasm_decode
        cdisasm_decode_checked)
    if(expected_x86)
        list(APPEND
            _cdisasm_expected_symbols
            cdisasm_x86_cpu_mode_mask
            cdisasm_x86_cpu_decode_flag_mask
            cdisasm_x86_decode)
    endif()
    if(expected_arm)
        list(APPEND
            _cdisasm_expected_symbols
            cdisasm_arm_cpu_mode_mask
            cdisasm_arm_decoder_mode_mask
            cdisasm_arm_cpu_decode_flag_mask
            cdisasm_arm_decode)
    endif()
    if(expected_format AND expected_x86)
        list(APPEND
            _cdisasm_expected_symbols
            cdisasm_x86_format
            cdisasm_x86_format_mode
            cdisasm_format)
    endif()
    if(expected_format AND expected_arm)
        list(APPEND _cdisasm_expected_symbols cdisasm_arm_format)
    endif()

    foreach(_cdisasm_symbol IN LISTS _cdisasm_all_public_symbols)
        _cdisasm_symbol_is_present(
            "${_cdisasm_core_symbol_text}"
            "${_cdisasm_symbol}"
            _cdisasm_symbol_present)
        list(FIND
            _cdisasm_expected_symbols
            "${_cdisasm_symbol}"
            _cdisasm_expected_symbol_index)
        if(_cdisasm_expected_symbol_index EQUAL -1)
            if(_cdisasm_symbol_present)
                message(FATAL_ERROR
                    "${context} unexpectedly defines disabled symbol "
                    "'${_cdisasm_symbol}'.\n"
                    "inspector output:\n${_cdisasm_core_symbol_text}")
            endif()
        elseif(NOT _cdisasm_symbol_present)
            message(FATAL_ERROR
                "${context} does not define enabled symbol "
                "'${_cdisasm_symbol}'.\n"
                "inspector output:\n${_cdisasm_core_symbol_text}")
        endif()
    endforeach()
endfunction()

function(
    _cdisasm_build_and_audit_static_wrapper
    context
    package_dir
    wrapper_build_dir
    expected_x86
    expected_arm
    expected_format
    components)
    execute_process(
        COMMAND
            "${CMAKE_COMMAND}"
            -S "${_cdisasm_source_dir}/tests/package_symbol_probe"
            -B "${wrapper_build_dir}"
            ${_cdisasm_generator_arguments}
            ${_cdisasm_identity_arguments}
            -DCMAKE_FIND_USE_PACKAGE_REGISTRY:BOOL=OFF
            -DCMAKE_FIND_PACKAGE_NO_PACKAGE_REGISTRY:BOOL=ON
            -DCMAKE_FIND_PACKAGE_NO_SYSTEM_PACKAGE_REGISTRY:BOOL=ON
            "-Dcdisasm_DIR:PATH=${package_dir}"
            "-DCDISASM_SYMBOL_PROBE_COMPONENTS:STRING=${components}"
        RESULT_VARIABLE _cdisasm_wrapper_configure_result
        OUTPUT_VARIABLE _cdisasm_wrapper_configure_output
        ERROR_VARIABLE _cdisasm_wrapper_configure_error)
    _cdisasm_require_process_success(
        "${context} static-wrapper configure"
        _cdisasm_wrapper_configure_result
        _cdisasm_wrapper_configure_output
        _cdisasm_wrapper_configure_error)

    execute_process(
        COMMAND
            "${CMAKE_COMMAND}"
            --build "${wrapper_build_dir}"
            --config "${_cdisasm_config}"
        RESULT_VARIABLE _cdisasm_wrapper_build_result
        OUTPUT_VARIABLE _cdisasm_wrapper_build_output
        ERROR_VARIABLE _cdisasm_wrapper_build_error)
    _cdisasm_require_process_success(
        "${context} static-wrapper build"
        _cdisasm_wrapper_build_result
        _cdisasm_wrapper_build_output
        _cdisasm_wrapper_build_error)

    set(_cdisasm_wrapper_path_file
        "${wrapper_build_dir}/cdisasm-wrapper-${_cdisasm_config}.path")
    if(NOT EXISTS "${_cdisasm_wrapper_path_file}")
        message(FATAL_ERROR
            "${context} static-wrapper build did not generate "
            "'${_cdisasm_wrapper_path_file}'")
    endif()
    file(READ "${_cdisasm_wrapper_path_file}" _cdisasm_wrapper_artifact)
    string(STRIP
        "${_cdisasm_wrapper_artifact}"
        _cdisasm_wrapper_artifact)
    if(NOT EXISTS "${_cdisasm_wrapper_artifact}")
        message(FATAL_ERROR
            "${context} static-wrapper artifact does not exist: "
            "'${_cdisasm_wrapper_artifact}'")
    endif()

    _cdisasm_read_symbols(
        "${context} static wrapper"
        "${_cdisasm_wrapper_artifact}"
        ON
        _cdisasm_wrapper_symbol_text)
    _cdisasm_symbol_is_present(
        "${_cdisasm_wrapper_symbol_text}"
        cdisasm_package_wrapper_probe
        _cdisasm_wrapper_export_present)
    if(NOT _cdisasm_wrapper_export_present)
        message(FATAL_ERROR
            "${context} static wrapper does not export its probe symbol.\n"
            "inspector output:\n${_cdisasm_wrapper_symbol_text}")
    endif()
    foreach(_cdisasm_symbol IN LISTS _cdisasm_all_public_symbols)
        _cdisasm_symbol_is_present(
            "${_cdisasm_wrapper_symbol_text}"
            "${_cdisasm_symbol}"
            _cdisasm_wrapper_leak_present)
        if(_cdisasm_wrapper_leak_present)
            message(FATAL_ERROR
                "${context} static wrapper leaks '${_cdisasm_symbol}'.\n"
                "inspector output:\n${_cdisasm_wrapper_symbol_text}")
        endif()
    endforeach()
endfunction()

function(
    _cdisasm_build_and_test_static_embed
    context
    package_dir
    embed_build_dir
    expected_x86
    expected_arm
    expected_format
    expected_requested_extra
    expected_extra)
    execute_process(
        COMMAND
            "${CMAKE_COMMAND}"
            -S "${_cdisasm_source_dir}/tests/package_static_embed"
            -B "${embed_build_dir}"
            ${_cdisasm_generator_arguments}
            ${_cdisasm_identity_arguments}
            -DBUILD_TESTING:BOOL=ON
            -DCMAKE_FIND_USE_PACKAGE_REGISTRY:BOOL=OFF
            -DCMAKE_FIND_PACKAGE_NO_PACKAGE_REGISTRY:BOOL=ON
            -DCMAKE_FIND_PACKAGE_NO_SYSTEM_PACKAGE_REGISTRY:BOOL=ON
            "-Dcdisasm_DIR:PATH=${package_dir}"
            "-DCDISASM_STATIC_EMBED_EXPECT_X86:BOOL=${expected_x86}"
            "-DCDISASM_STATIC_EMBED_EXPECT_ARM:BOOL=${expected_arm}"
            "-DCDISASM_STATIC_EMBED_EXPECT_FORMAT:BOOL=${expected_format}"
            "-DCDISASM_STATIC_EMBED_EXPECT_REQUESTED_EXTRA:BOOL=${expected_requested_extra}"
            "-DCDISASM_STATIC_EMBED_EXPECT_EXTRA:BOOL=${expected_extra}"
        RESULT_VARIABLE _cdisasm_embed_configure_result
        OUTPUT_VARIABLE _cdisasm_embed_configure_output
        ERROR_VARIABLE _cdisasm_embed_configure_error)
    _cdisasm_require_process_success(
        "${context} static-embedding configure"
        _cdisasm_embed_configure_result
        _cdisasm_embed_configure_output
        _cdisasm_embed_configure_error)

    execute_process(
        COMMAND
            "${CMAKE_COMMAND}"
            --build "${embed_build_dir}"
            --config "${_cdisasm_config}"
        RESULT_VARIABLE _cdisasm_embed_build_result
        OUTPUT_VARIABLE _cdisasm_embed_build_output
        ERROR_VARIABLE _cdisasm_embed_build_error)
    _cdisasm_require_process_success(
        "${context} static-embedding build"
        _cdisasm_embed_build_result
        _cdisasm_embed_build_output
        _cdisasm_embed_build_error)

    execute_process(
        COMMAND
            "${CDISASM_PACKAGE_CTEST_COMMAND}"
            -C "${_cdisasm_config}"
            --show-only=json-v1
        WORKING_DIRECTORY "${embed_build_dir}"
        RESULT_VARIABLE _cdisasm_embed_list_result
        OUTPUT_VARIABLE _cdisasm_embed_list_output
        ERROR_VARIABLE _cdisasm_embed_list_error)
    _cdisasm_require_process_success(
        "${context} static-embedding CTest JSON listing"
        _cdisasm_embed_list_result
        _cdisasm_embed_list_output
        _cdisasm_embed_list_error)
    string(REGEX MATCHALL
        "\"name\"[ \t\r\n]*:[ \t\r\n]*\"cdisasm_package_static_embed_[A-Za-z0-9_]+\""
        _cdisasm_embed_listed_tests
        "${_cdisasm_embed_list_output}")
    list(LENGTH _cdisasm_embed_listed_tests _cdisasm_embed_test_count)
    if(NOT _cdisasm_embed_test_count EQUAL 1
            OR NOT _cdisasm_embed_list_output MATCHES
                "\"name\"[ \t\r\n]*:[ \t\r\n]*\"cdisasm_package_static_embed_symbols\"")
        message(FATAL_ERROR
            "${context} static-embedding fixture must list exactly "
            "cdisasm_package_static_embed_symbols.\n"
            "CTest JSON:\n${_cdisasm_embed_list_output}")
    endif()

    execute_process(
        COMMAND
            "${CDISASM_PACKAGE_CTEST_COMMAND}"
            -C "${_cdisasm_config}"
            --output-on-failure
        WORKING_DIRECTORY "${embed_build_dir}"
        RESULT_VARIABLE _cdisasm_embed_ctest_result
        OUTPUT_VARIABLE _cdisasm_embed_ctest_output
        ERROR_VARIABLE _cdisasm_embed_ctest_error)
    _cdisasm_require_process_success(
        "${context} static-embedding CTest run"
        _cdisasm_embed_ctest_result
        _cdisasm_embed_ctest_output
        _cdisasm_embed_ctest_error)
endfunction()

function(
    _cdisasm_run_matrix_cell
    cell_name
    expected_x86
    expected_arm
    requested_format
    requested_extra)
    set(_cdisasm_effective_format OFF)
    if(requested_format AND (expected_x86 OR expected_arm))
        set(_cdisasm_effective_format ON)
    endif()
    set(_cdisasm_effective_extra OFF)
    if(requested_extra AND (expected_x86 OR expected_arm))
        set(_cdisasm_effective_extra ON)
    endif()

    set(_cdisasm_cell_dir "${_cdisasm_work_dir}/${cell_name}")
    set(_cdisasm_producer_build_dir "${_cdisasm_cell_dir}/producer")
    set(_cdisasm_original_prefix "${_cdisasm_cell_dir}/original-prefix")
    set(_cdisasm_relocated_prefix "${_cdisasm_cell_dir}/relocated-prefix")
    set(_cdisasm_context "${_cdisasm_linkage}/${cell_name}")

    set(_cdisasm_enabled_components common)
    if(expected_x86)
        list(APPEND _cdisasm_enabled_components x86)
    endif()
    if(expected_arm)
        list(APPEND _cdisasm_enabled_components arm)
    endif()
    if(_cdisasm_effective_format)
        list(APPEND _cdisasm_enabled_components format)
    endif()

    message(STATUS
        "[${_cdisasm_context}] x86=${expected_x86}, ARM=${expected_arm}, "
        "requested format=${requested_format}, effective format=${_cdisasm_effective_format}, "
        "requested extra=${requested_extra}, effective extra=${_cdisasm_effective_extra}")

    if(_cdisasm_shared)
        set(_cdisasm_position_independent_code OFF)
    else()
        # The static visibility audit embeds the archive into a shared wrapper.
        set(_cdisasm_position_independent_code ON)
    endif()

    execute_process(
        COMMAND
            "${CMAKE_COMMAND}"
            -S "${_cdisasm_source_dir}"
            -B "${_cdisasm_producer_build_dir}"
            ${_cdisasm_generator_arguments}
            ${_cdisasm_identity_arguments}
            "-DBUILD_SHARED_LIBS:BOOL=${_cdisasm_shared}"
            -DBUILD_TESTING:BOOL=OFF
            -DCDISASM_BUILD_EXAMPLES:BOOL=OFF
            -DCDISASM_BUILD_FUZZERS:BOOL=OFF
            -DCDISASM_BUILD_PACKAGE_TESTS:BOOL=OFF
            "-DUSE_ARCH_X86:BOOL=${expected_x86}"
            "-DUSE_ARCH_ARM:BOOL=${expected_arm}"
            "-DUSE_DISASM_FORMAT:BOOL=${requested_format}"
            "-DUSE_EXTRA_OPCODES:BOOL=${requested_extra}"
            "-DCMAKE_POSITION_INDEPENDENT_CODE:BOOL=${_cdisasm_position_independent_code}"
            "-DCMAKE_INSTALL_PREFIX:PATH=${_cdisasm_original_prefix}"
            -DCMAKE_INSTALL_BINDIR:PATH=bin
            -DCMAKE_INSTALL_LIBDIR:PATH=lib
        RESULT_VARIABLE _cdisasm_producer_configure_result
        OUTPUT_VARIABLE _cdisasm_producer_configure_output
        ERROR_VARIABLE _cdisasm_producer_configure_error)
    _cdisasm_require_process_success(
        "${_cdisasm_context} producer configure"
        _cdisasm_producer_configure_result
        _cdisasm_producer_configure_output
        _cdisasm_producer_configure_error)

    execute_process(
        COMMAND
            "${CMAKE_COMMAND}"
            --build "${_cdisasm_producer_build_dir}"
            --config "${_cdisasm_config}"
        RESULT_VARIABLE _cdisasm_producer_build_result
        OUTPUT_VARIABLE _cdisasm_producer_build_output
        ERROR_VARIABLE _cdisasm_producer_build_error)
    _cdisasm_require_process_success(
        "${_cdisasm_context} producer build"
        _cdisasm_producer_build_result
        _cdisasm_producer_build_output
        _cdisasm_producer_build_error)

    _cdisasm_run_consumer(
        "${_cdisasm_context} build-tree package"
        "${_cdisasm_producer_build_dir}"
        "${_cdisasm_cell_dir}/consumer-build-tree"
        "${expected_x86}"
        "${expected_arm}"
        "${_cdisasm_effective_format}"
        "${requested_extra}"
        "${_cdisasm_effective_extra}"
        "${_cdisasm_enabled_components}")

    execute_process(
        COMMAND
            "${CMAKE_COMMAND}"
            --install "${_cdisasm_producer_build_dir}"
            --config "${_cdisasm_config}"
        RESULT_VARIABLE _cdisasm_install_result
        OUTPUT_VARIABLE _cdisasm_install_output
        ERROR_VARIABLE _cdisasm_install_error)
    _cdisasm_require_process_success(
        "${_cdisasm_context} producer install"
        _cdisasm_install_result
        _cdisasm_install_output
        _cdisasm_install_error)

    set(_cdisasm_original_package_dir
        "${_cdisasm_original_prefix}/lib/cmake/cdisasm")
    _cdisasm_validate_package_files(
        "${_cdisasm_context} original install"
        "${_cdisasm_original_package_dir}")
    if(EXISTS "${_cdisasm_relocated_prefix}")
        message(FATAL_ERROR
            "${_cdisasm_context} relocation destination already exists: "
            "'${_cdisasm_relocated_prefix}'")
    endif()
    file(RENAME
        "${_cdisasm_original_prefix}"
        "${_cdisasm_relocated_prefix}")
    if(EXISTS "${_cdisasm_original_prefix}")
        message(FATAL_ERROR
            "${_cdisasm_context} original install prefix still exists after "
            "relocation: '${_cdisasm_original_prefix}'")
    endif()
    if(NOT IS_DIRECTORY "${_cdisasm_relocated_prefix}")
        message(FATAL_ERROR
            "${_cdisasm_context} relocated prefix does not exist: "
            "'${_cdisasm_relocated_prefix}'")
    endif()

    set(_cdisasm_relocated_package_dir
        "${_cdisasm_relocated_prefix}/lib/cmake/cdisasm")
    _cdisasm_validate_package_files(
        "${_cdisasm_context} relocated install"
        "${_cdisasm_relocated_package_dir}")
    _cdisasm_audit_install(
        "${_cdisasm_context} relocated install"
        "${_cdisasm_relocated_prefix}"
        "${expected_x86}"
        "${expected_arm}"
        _cdisasm_installed_library_artifact)
    _cdisasm_audit_core_symbols(
        "${_cdisasm_context} core library"
        "${_cdisasm_installed_library_artifact}"
        "${expected_x86}"
        "${expected_arm}"
        "${_cdisasm_effective_format}")

    foreach(_cdisasm_component IN LISTS _cdisasm_enabled_components)
        _cdisasm_run_component_probe(
            "${_cdisasm_context} relocated package"
            "${_cdisasm_relocated_package_dir}"
            "${_cdisasm_cell_dir}/component-positive-${_cdisasm_component}"
            "${_cdisasm_component}"
            ON
            "${expected_x86}"
            "${expected_arm}"
            "${requested_format}"
            "${_cdisasm_effective_format}"
            "${requested_extra}"
            "${_cdisasm_effective_extra}")
    endforeach()
    list(LENGTH
        _cdisasm_enabled_components
        _cdisasm_enabled_component_count)
    if(_cdisasm_enabled_component_count GREATER 1)
        _cdisasm_run_component_probe(
            "${_cdisasm_context} relocated package"
            "${_cdisasm_relocated_package_dir}"
            "${_cdisasm_cell_dir}/component-positive-all"
            "${_cdisasm_enabled_components}"
            ON
            "${expected_x86}"
            "${expected_arm}"
            "${requested_format}"
            "${_cdisasm_effective_format}"
            "${requested_extra}"
            "${_cdisasm_effective_extra}")
    endif()

    set(_cdisasm_disabled_components)
    if(NOT expected_x86)
        list(APPEND _cdisasm_disabled_components x86)
    endif()
    if(NOT expected_arm)
        list(APPEND _cdisasm_disabled_components arm)
    endif()
    if(NOT _cdisasm_effective_format)
        list(APPEND _cdisasm_disabled_components format)
    endif()
    list(APPEND _cdisasm_disabled_components unknown)
    foreach(_cdisasm_component IN LISTS _cdisasm_disabled_components)
        _cdisasm_run_component_probe(
            "${_cdisasm_context} relocated package"
            "${_cdisasm_relocated_package_dir}"
            "${_cdisasm_cell_dir}/component-negative-${_cdisasm_component}"
            "${_cdisasm_component}"
            OFF
            "${expected_x86}"
            "${expected_arm}"
            "${requested_format}"
            "${_cdisasm_effective_format}"
            "${requested_extra}"
            "${_cdisasm_effective_extra}")
    endforeach()

    _cdisasm_run_consumer(
        "${_cdisasm_context} relocated package"
        "${_cdisasm_relocated_package_dir}"
        "${_cdisasm_cell_dir}/consumer-relocated"
        "${expected_x86}"
        "${expected_arm}"
        "${_cdisasm_effective_format}"
        "${requested_extra}"
        "${_cdisasm_effective_extra}"
        "${_cdisasm_enabled_components}")

    if(NOT _cdisasm_shared)
        if(WIN32)
            _cdisasm_build_and_audit_static_wrapper(
                "${_cdisasm_context} relocated package"
                "${_cdisasm_relocated_package_dir}"
                "${_cdisasm_cell_dir}/static-wrapper"
                "${expected_x86}"
                "${expected_arm}"
                "${_cdisasm_effective_format}"
                "${_cdisasm_enabled_components}")
        elseif(APPLE OR UNIX)
            _cdisasm_build_and_test_static_embed(
                "${_cdisasm_context} relocated package"
                "${_cdisasm_relocated_package_dir}"
                "${_cdisasm_cell_dir}/static-embed"
                "${expected_x86}"
                "${expected_arm}"
                "${_cdisasm_effective_format}"
                "${requested_extra}"
                "${_cdisasm_effective_extra}")
        else()
            message(FATAL_ERROR
                "${_cdisasm_context} has no static-embedding visibility "
                "fixture for this host platform")
        endif()
    endif()

    if(EXISTS "${_cdisasm_original_prefix}")
        message(FATAL_ERROR
            "${_cdisasm_context} recreated the original install prefix")
    endif()
    message(STATUS "[${_cdisasm_context}] passed")
endfunction()

foreach(_cdisasm_architecture_cell IN ITEMS dual x86 arm common)
    if(_cdisasm_architecture_cell STREQUAL "dual")
        set(_cdisasm_cell_x86 ON)
        set(_cdisasm_cell_arm ON)
    elseif(_cdisasm_architecture_cell STREQUAL "x86")
        set(_cdisasm_cell_x86 ON)
        set(_cdisasm_cell_arm OFF)
    elseif(_cdisasm_architecture_cell STREQUAL "arm")
        set(_cdisasm_cell_x86 OFF)
        set(_cdisasm_cell_arm ON)
    else()
        set(_cdisasm_cell_x86 OFF)
        set(_cdisasm_cell_arm OFF)
    endif()

    foreach(_cdisasm_requested_format IN ITEMS ON OFF)
        if(_cdisasm_requested_format)
            set(_cdisasm_format_cell_name format-on)
        else()
            set(_cdisasm_format_cell_name format-off)
        endif()
        foreach(_cdisasm_requested_extra IN ITEMS ON OFF)
            if(_cdisasm_requested_extra)
                set(_cdisasm_extra_cell_name extra-on)
            else()
                set(_cdisasm_extra_cell_name extra-off)
            endif()
            _cdisasm_run_matrix_cell(
                "${_cdisasm_architecture_cell}-${_cdisasm_format_cell_name}-${_cdisasm_extra_cell_name}"
                "${_cdisasm_cell_x86}"
                "${_cdisasm_cell_arm}"
                "${_cdisasm_requested_format}"
                "${_cdisasm_requested_extra}")
        endforeach()
    endforeach()
endforeach()

message(STATUS
    "Installed ${_cdisasm_linkage} package passed all 16 feature-matrix "
    "cells for configuration '${_cdisasm_config}'")
