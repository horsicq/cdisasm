cmake_minimum_required(VERSION 3.16)

foreach(_cdisasm_required IN ITEMS
        CDISASM_SOURCE_DIR
        CDISASM_BINARY_DIR
        CDISASM_OVERLAY_GENERATOR)
    if(NOT DEFINED ${_cdisasm_required}
            OR "${${_cdisasm_required}}" STREQUAL "")
        message(FATAL_ERROR "${_cdisasm_required} must be provided")
    endif()
endforeach()
if(NOT IS_ABSOLUTE "${CDISASM_SOURCE_DIR}"
        OR NOT IS_ABSOLUTE "${CDISASM_BINARY_DIR}")
    message(FATAL_ERROR
        "CDISASM_SOURCE_DIR and CDISASM_BINARY_DIR must be absolute")
endif()

get_filename_component(_cdisasm_binary_root "${CDISASM_BINARY_DIR}" ABSOLUTE)
set(_cdisasm_root "${_cdisasm_binary_root}/variant-overlay-test")
get_filename_component(_cdisasm_root "${_cdisasm_root}" ABSOLUTE)
get_filename_component(_cdisasm_root_parent "${_cdisasm_root}" DIRECTORY)
get_filename_component(_cdisasm_root_leaf "${_cdisasm_root}" NAME)
if(NOT _cdisasm_root_parent STREQUAL _cdisasm_binary_root
        OR NOT _cdisasm_root_leaf STREQUAL "variant-overlay-test"
        OR IS_SYMLINK "${_cdisasm_root_parent}"
        OR IS_SYMLINK "${_cdisasm_root}")
    message(FATAL_ERROR
        "Refusing unsafe variant-overlay test cleanup: ${_cdisasm_root}")
endif()
if(EXISTS "${_cdisasm_root}")
    file(REMOVE_RECURSE "${_cdisasm_root}")
endif()
if(EXISTS "${_cdisasm_root}")
    message(FATAL_ERROR "Could not clean ${_cdisasm_root}")
endif()

set(_cdisasm_prefix "${_cdisasm_root}/prefix")
set(_cdisasm_static_build "${_cdisasm_root}/static")
set(_cdisasm_shared_build "${_cdisasm_root}/shared")
set(_cdisasm_extra_off_build "${_cdisasm_root}/extra-off")

set(_cdisasm_generator_args -G "${CDISASM_OVERLAY_GENERATOR}")
if(NOT "${CDISASM_OVERLAY_GENERATOR_PLATFORM}" STREQUAL "")
    list(APPEND
        _cdisasm_generator_args
        -A "${CDISASM_OVERLAY_GENERATOR_PLATFORM}")
endif()
if(NOT "${CDISASM_OVERLAY_GENERATOR_TOOLSET}" STREQUAL "")
    list(APPEND
        _cdisasm_generator_args
        -T "${CDISASM_OVERLAY_GENERATOR_TOOLSET}")
endif()

set(_cdisasm_identity_args)
foreach(_cdisasm_identity IN ITEMS
        GENERATOR_INSTANCE
        MAKE_PROGRAM
        C_COMPILER
        TOOLCHAIN_FILE)
    if(NOT "${CDISASM_OVERLAY_${_cdisasm_identity}}" STREQUAL "")
        if(_cdisasm_identity STREQUAL "GENERATOR_INSTANCE")
            set(_cdisasm_cache_type STRING)
            set(_cdisasm_cache_name CMAKE_GENERATOR_INSTANCE)
        elseif(_cdisasm_identity STREQUAL "MAKE_PROGRAM")
            set(_cdisasm_cache_type FILEPATH)
            set(_cdisasm_cache_name CMAKE_MAKE_PROGRAM)
        elseif(_cdisasm_identity STREQUAL "C_COMPILER")
            set(_cdisasm_cache_type FILEPATH)
            set(_cdisasm_cache_name CMAKE_C_COMPILER)
        else()
            set(_cdisasm_cache_type FILEPATH)
            set(_cdisasm_cache_name CMAKE_TOOLCHAIN_FILE)
        endif()
        list(APPEND
            _cdisasm_identity_args
            "-D${_cdisasm_cache_name}:${_cdisasm_cache_type}=${CDISASM_OVERLAY_${_cdisasm_identity}}")
    endif()
endforeach()

set(_cdisasm_config "${CDISASM_OVERLAY_CONFIG}")
if(_cdisasm_config STREQUAL "")
    set(_cdisasm_config Release)
endif()
if(NOT CDISASM_OVERLAY_MULTI_CONFIG)
    list(APPEND
        _cdisasm_identity_args
        "-DCMAKE_BUILD_TYPE:STRING=${_cdisasm_config}")
endif()

function(_cdisasm_run_success description)
    execute_process(
        COMMAND ${ARGN}
        RESULT_VARIABLE _cdisasm_result
        OUTPUT_VARIABLE _cdisasm_output
        ERROR_VARIABLE _cdisasm_error)
    if(NOT _cdisasm_result EQUAL 0)
        message(FATAL_ERROR
            "${description} failed (${_cdisasm_result}).\n"
            "stdout:\n${_cdisasm_output}\n"
            "stderr:\n${_cdisasm_error}")
    endif()
endfunction()

function(
    _cdisasm_configure_variant
    build_dir
    shared
    extra_opcodes
    disabled_feature_spelling)
    set(_cdisasm_variant_prefix "${_cdisasm_prefix}")
    set(_cdisasm_variant_libdir lib)
    set(_cdisasm_variant_includedir include)
    if(ARGC GREATER 4)
        set(_cdisasm_variant_prefix "${ARGV4}")
    endif()
    if(ARGC GREATER 5)
        set(_cdisasm_variant_libdir "${ARGV5}")
    endif()
    if(ARGC GREATER 6)
        set(_cdisasm_variant_includedir "${ARGV6}")
    endif()
    _cdisasm_run_success(
        "Configure ${shared} variant"
        "${CMAKE_COMMAND}"
        -S "${CDISASM_SOURCE_DIR}"
        -B "${build_dir}"
        ${_cdisasm_generator_args}
        ${_cdisasm_identity_args}
        "-DBUILD_SHARED_LIBS:BOOL=${shared}"
        -DBUILD_TESTING:BOOL=OFF
        -DCDISASM_BUILD_EXAMPLES:BOOL=OFF
        -DCDISASM_BUILD_FUZZERS:BOOL=OFF
        -DCDISASM_BUILD_PACKAGE_TESTS:BOOL=OFF
        "-DUSE_ARCH_X86:BOOL=${disabled_feature_spelling}"
        "-DUSE_ARCH_ARM:BOOL=${disabled_feature_spelling}"
        "-DUSE_DISASM_FORMAT:BOOL=${disabled_feature_spelling}"
        "-DUSE_EXTRA_OPCODES:BOOL=${extra_opcodes}"
        "-DCMAKE_INSTALL_PREFIX:PATH=${_cdisasm_variant_prefix}"
        -DCMAKE_INSTALL_BINDIR:PATH=bin
        "-DCMAKE_INSTALL_LIBDIR:PATH=${_cdisasm_variant_libdir}"
        "-DCMAKE_INSTALL_INCLUDEDIR:PATH=${_cdisasm_variant_includedir}")
    _cdisasm_run_success(
        "Build ${shared} variant"
        "${CMAKE_COMMAND}"
        --build "${build_dir}"
        --config "${_cdisasm_config}")
endfunction()

function(_cdisasm_require_file_text file_path expected_text description)
    if(NOT EXISTS "${file_path}")
        message(FATAL_ERROR "${description} file is missing: ${file_path}")
    endif()
    file(READ "${file_path}" _cdisasm_serialized_text)
    string(FIND
        "${_cdisasm_serialized_text}"
        "${expected_text}"
        _cdisasm_serialized_index)
    if(_cdisasm_serialized_index EQUAL -1)
        message(FATAL_ERROR
            "${description} is not canonically serialized as "
            "'${expected_text}'.\nFile: ${file_path}\n"
            "Contents:\n${_cdisasm_serialized_text}")
    endif()
endfunction()

function(_cdisasm_assert_canonical_static_common_variant build_dir)
    set(_cdisasm_variant_file "${build_dir}/cdisasm-variant.txt")
    foreach(_cdisasm_variant_line IN ITEMS
            "linkage=static"
            "x86=OFF"
            "arm=OFF"
            "format-requested=OFF"
            "format-effective=OFF"
            "extra-opcodes-requested=ON"
            "extra-opcodes-effective=OFF")
        _cdisasm_require_file_text(
            "${_cdisasm_variant_file}"
            "${_cdisasm_variant_line}"
            "Variant fingerprint")
    endforeach()

    set(_cdisasm_package_file "${build_dir}/cdisasmConfig.cmake")
    foreach(_cdisasm_package_line IN ITEMS
            "set(cdisasm_USE_ARCH_X86 OFF)"
            "set(cdisasm_USE_ARCH_ARM OFF)"
            "set(cdisasm_REQUESTED_USE_DISASM_FORMAT OFF)"
            "set(cdisasm_USE_DISASM_FORMAT OFF)"
            "set(cdisasm_REQUESTED_USE_EXTRA_OPCODES ON)"
            "set(cdisasm_USE_EXTRA_OPCODES OFF)"
            "set(cdisasm_BUILD_SHARED_LIBS OFF)")
        _cdisasm_require_file_text(
            "${_cdisasm_package_file}"
            "${_cdisasm_package_line}"
            "Package metadata")
    endforeach()
endfunction()

function(_cdisasm_snapshot_prefix prefix out_snapshot)
    file(GLOB_RECURSE
        _cdisasm_entries
        LIST_DIRECTORIES FALSE
        RELATIVE "${prefix}"
        "${prefix}/*")
    list(SORT _cdisasm_entries)
    set(_cdisasm_snapshot "")
    foreach(_cdisasm_entry IN LISTS _cdisasm_entries)
        file(SHA256
            "${prefix}/${_cdisasm_entry}"
            _cdisasm_hash)
        string(APPEND
            _cdisasm_snapshot
            "${_cdisasm_entry}=${_cdisasm_hash}\n")
    endforeach()
    set(${out_snapshot} "${_cdisasm_snapshot}" PARENT_SCOPE)
endfunction()

_cdisasm_configure_variant("${_cdisasm_static_build}" OFF ON OFF)
_cdisasm_assert_canonical_static_common_variant("${_cdisasm_static_build}")
_cdisasm_run_success(
    "Install initial static variant"
    "${CMAKE_COMMAND}"
    --install "${_cdisasm_static_build}"
    --config "${_cdisasm_config}")

set(_cdisasm_fingerprint
    "${_cdisasm_prefix}/lib/cmake/cdisasm/cdisasm-variant.txt")
if(NOT EXISTS "${_cdisasm_fingerprint}")
    message(FATAL_ERROR "Initial install omitted its variant fingerprint")
endif()

# Reinstalling the exact tuple is intentionally supported.
_cdisasm_run_success(
    "Reinstall identical static variant"
    "${CMAKE_COMMAND}"
    --install "${_cdisasm_static_build}"
    --config "${_cdisasm_config}")

# BOOL cache values retain a caller's spelling.  Every conventional spelling
# of true and false must nevertheless produce the same package tuple and be
# accepted as an equivalent overlay.
set(_cdisasm_equivalent_boolean_pairs
    "TRUE|FALSE"
    "YES|NO"
    "1|0")
foreach(_cdisasm_boolean_pair IN LISTS _cdisasm_equivalent_boolean_pairs)
    string(REPLACE "|" ";" _cdisasm_boolean_values
        "${_cdisasm_boolean_pair}")
    list(GET _cdisasm_boolean_values 0 _cdisasm_true_spelling)
    list(GET _cdisasm_boolean_values 1 _cdisasm_false_spelling)
    string(TOLOWER
        "${_cdisasm_true_spelling}"
        _cdisasm_equivalent_leaf)
    set(_cdisasm_equivalent_build
        "${_cdisasm_root}/equivalent-${_cdisasm_equivalent_leaf}")
    _cdisasm_configure_variant(
        "${_cdisasm_equivalent_build}"
        "${_cdisasm_false_spelling}"
        "${_cdisasm_true_spelling}"
        "${_cdisasm_false_spelling}")
    _cdisasm_assert_canonical_static_common_variant(
        "${_cdisasm_equivalent_build}")
    _cdisasm_run_success(
        "Install equivalent ${_cdisasm_true_spelling}/${_cdisasm_false_spelling} spelling"
        "${CMAKE_COMMAND}"
        --install "${_cdisasm_equivalent_build}"
        --config "${_cdisasm_config}")
endforeach()
_cdisasm_snapshot_prefix(
    "${_cdisasm_prefix}"
    _cdisasm_before_overlay)

_cdisasm_configure_variant("${_cdisasm_shared_build}" ON ON OFF)
execute_process(
    COMMAND
        "${CMAKE_COMMAND}"
        --install "${_cdisasm_shared_build}"
        --config "${_cdisasm_config}"
    RESULT_VARIABLE _cdisasm_overlay_result
    OUTPUT_VARIABLE _cdisasm_overlay_output
    ERROR_VARIABLE _cdisasm_overlay_error)
if(_cdisasm_overlay_result EQUAL 0)
    message(FATAL_ERROR
        "A shared variant unexpectedly overlaid the static prefix")
endif()
set(_cdisasm_overlay_log
    "${_cdisasm_overlay_output}\n${_cdisasm_overlay_error}")
if(NOT _cdisasm_overlay_log MATCHES
        "Refusing to overlay a different cdisasm build variant")
    message(FATAL_ERROR
        "Overlay failed for an unexpected reason.\n${_cdisasm_overlay_log}")
endif()

_cdisasm_snapshot_prefix(
    "${_cdisasm_prefix}"
    _cdisasm_after_overlay)
if(NOT _cdisasm_after_overlay STREQUAL _cdisasm_before_overlay)
    message(FATAL_ERROR
        "Rejected overlay changed the installed prefix.\n"
        "Before:\n${_cdisasm_before_overlay}\n"
        "After:\n${_cdisasm_after_overlay}")
endif()

# Requested features are part of the tuple even when no architecture is
# enabled and the corresponding public feature is therefore ineffective.
# This prevents a later architecture-bearing overlay from inheriting package
# metadata that described a different original request.
_cdisasm_configure_variant("${_cdisasm_extra_off_build}" OFF OFF OFF)
execute_process(
    COMMAND
        "${CMAKE_COMMAND}"
        --install "${_cdisasm_extra_off_build}"
        --config "${_cdisasm_config}"
    RESULT_VARIABLE _cdisasm_extra_overlay_result
    OUTPUT_VARIABLE _cdisasm_extra_overlay_output
    ERROR_VARIABLE _cdisasm_extra_overlay_error)
if(_cdisasm_extra_overlay_result EQUAL 0)
    message(FATAL_ERROR
        "An extra-opcode-OFF variant unexpectedly overlaid the prefix")
endif()
set(_cdisasm_extra_overlay_log
    "${_cdisasm_extra_overlay_output}\n${_cdisasm_extra_overlay_error}")
if(NOT _cdisasm_extra_overlay_log MATCHES
        "Refusing to overlay a different cdisasm build variant")
    message(FATAL_ERROR
        "Extra-opcode overlay failed for an unexpected reason.\n"
        "${_cdisasm_extra_overlay_log}")
endif()
_cdisasm_snapshot_prefix(
    "${_cdisasm_prefix}"
    _cdisasm_after_extra_overlay)
if(NOT _cdisasm_after_extra_overlay STREQUAL _cdisasm_before_overlay)
    message(FATAL_ERROR
        "Rejected extra-opcode overlay changed the installed prefix")
endif()

# A pre-fingerprint cdisasm tree is also unsafe to overlay. Simulate one in a
# separate prefix and prove that the guard rejects it without recreating the
# missing fingerprint or changing any remaining artifact.
set(_cdisasm_legacy_prefix "${_cdisasm_root}/legacy-prefix")
file(COPY "${_cdisasm_prefix}/" DESTINATION "${_cdisasm_legacy_prefix}")
set(_cdisasm_legacy_fingerprint
    "${_cdisasm_legacy_prefix}/lib/cmake/cdisasm/cdisasm-variant.txt")
if(NOT EXISTS "${_cdisasm_legacy_fingerprint}")
    message(FATAL_ERROR "Could not prepare unfingerprinted install fixture")
endif()
file(REMOVE "${_cdisasm_legacy_fingerprint}")
_cdisasm_snapshot_prefix(
    "${_cdisasm_legacy_prefix}"
    _cdisasm_before_legacy_overlay)
execute_process(
    COMMAND
        "${CMAKE_COMMAND}"
        --install "${_cdisasm_static_build}"
        --config "${_cdisasm_config}"
        --prefix "${_cdisasm_legacy_prefix}"
    RESULT_VARIABLE _cdisasm_legacy_result
    OUTPUT_VARIABLE _cdisasm_legacy_output
    ERROR_VARIABLE _cdisasm_legacy_error)
if(_cdisasm_legacy_result EQUAL 0)
    message(FATAL_ERROR
        "An unfingerprinted cdisasm prefix unexpectedly accepted an overlay")
endif()
set(_cdisasm_legacy_log
    "${_cdisasm_legacy_output}\n${_cdisasm_legacy_error}")
if(NOT _cdisasm_legacy_log MATCHES
        "Refusing to overlay an unfingerprinted cdisasm installation")
    message(FATAL_ERROR
        "Unfingerprinted overlay failed for an unexpected reason.\n"
        "${_cdisasm_legacy_log}")
endif()
if(EXISTS "${_cdisasm_legacy_fingerprint}")
    message(FATAL_ERROR
        "Rejected legacy overlay recreated the missing fingerprint")
endif()
_cdisasm_snapshot_prefix(
    "${_cdisasm_legacy_prefix}"
    _cdisasm_after_legacy_overlay)
if(NOT _cdisasm_after_legacy_overlay STREQUAL
        _cdisasm_before_legacy_overlay)
    message(FATAL_ERROR
        "Rejected unfingerprinted overlay changed the installed prefix")
endif()

# GNUInstallDirs permits absolute library and include destinations. CMake's
# installer ignores CMAKE_INSTALL_PREFIX for those destinations, so the guard
# must inspect the same absolute paths for both fingerprinted and legacy trees.
#
# Keep that synthetic absolute destination outside the source tree even when
# the caller deliberately uses an in-source-tree binary directory. Otherwise
# CMake rejects the generated install interface before this fixture reaches the
# overlay checks: an absolute INCLUDEDIR below the source is not exportable.
get_filename_component(
    _cdisasm_absolute_parent "${CDISASM_SOURCE_DIR}" DIRECTORY)
string(SHA256 _cdisasm_absolute_hash "${CDISASM_BINARY_DIR}")
string(SUBSTRING "${_cdisasm_absolute_hash}" 0 12 _cdisasm_absolute_hash)
set(_cdisasm_absolute_leaf
    ".cdisasm-variant-overlay-absolute-${_cdisasm_absolute_hash}")
set(_cdisasm_absolute_destination
    "${_cdisasm_absolute_parent}/${_cdisasm_absolute_leaf}")
get_filename_component(
    _cdisasm_absolute_destination "${_cdisasm_absolute_destination}" ABSOLUTE)
get_filename_component(
    _cdisasm_absolute_destination_parent
    "${_cdisasm_absolute_destination}" DIRECTORY)
get_filename_component(
    _cdisasm_absolute_destination_leaf
    "${_cdisasm_absolute_destination}" NAME)
if(NOT _cdisasm_absolute_destination_parent STREQUAL
        _cdisasm_absolute_parent
        OR NOT _cdisasm_absolute_destination_leaf STREQUAL
            _cdisasm_absolute_leaf
        OR IS_SYMLINK "${_cdisasm_absolute_destination_parent}"
        OR IS_SYMLINK "${_cdisasm_absolute_destination}")
    message(FATAL_ERROR
        "Refusing unsafe absolute-destination cleanup: "
        "${_cdisasm_absolute_destination}")
endif()
if(EXISTS "${_cdisasm_absolute_destination}")
    file(REMOVE_RECURSE "${_cdisasm_absolute_destination}")
endif()
if(EXISTS "${_cdisasm_absolute_destination}")
    message(FATAL_ERROR
        "Could not clean ${_cdisasm_absolute_destination}")
endif()
set(_cdisasm_absolute_prefix
    "${_cdisasm_root}/absolute-prefix")
set(_cdisasm_absolute_libdir
    "${_cdisasm_absolute_destination}/lib")
set(_cdisasm_absolute_includedir
    "${_cdisasm_absolute_destination}/include")
set(_cdisasm_absolute_static_build
    "${_cdisasm_root}/absolute-static")
set(_cdisasm_absolute_shared_build
    "${_cdisasm_root}/absolute-shared")

_cdisasm_configure_variant(
    "${_cdisasm_absolute_static_build}"
    OFF ON OFF
    "${_cdisasm_absolute_prefix}"
    "${_cdisasm_absolute_libdir}"
    "${_cdisasm_absolute_includedir}")
_cdisasm_configure_variant(
    "${_cdisasm_absolute_shared_build}"
    ON ON OFF
    "${_cdisasm_absolute_prefix}"
    "${_cdisasm_absolute_libdir}"
    "${_cdisasm_absolute_includedir}")
_cdisasm_run_success(
    "Install initial absolute-destination variant"
    "${CMAKE_COMMAND}"
    --install "${_cdisasm_absolute_static_build}"
    --config "${_cdisasm_config}")

set(_cdisasm_absolute_fingerprint
    "${_cdisasm_absolute_libdir}/cmake/cdisasm/cdisasm-variant.txt")
if(NOT EXISTS "${_cdisasm_absolute_fingerprint}")
    message(FATAL_ERROR
        "Absolute-destination install omitted its variant fingerprint")
endif()
_cdisasm_snapshot_prefix(
    "${_cdisasm_absolute_destination}"
    _cdisasm_before_absolute_overlay)
_cdisasm_snapshot_prefix(
    "${_cdisasm_absolute_prefix}"
    _cdisasm_before_absolute_prefix_overlay)
execute_process(
    COMMAND
        "${CMAKE_COMMAND}"
        --install "${_cdisasm_absolute_shared_build}"
        --config "${_cdisasm_config}"
    RESULT_VARIABLE _cdisasm_absolute_overlay_result
    OUTPUT_VARIABLE _cdisasm_absolute_overlay_output
    ERROR_VARIABLE _cdisasm_absolute_overlay_error)
if(_cdisasm_absolute_overlay_result EQUAL 0)
    message(FATAL_ERROR
        "A different variant unexpectedly overlaid absolute destinations")
endif()
set(_cdisasm_absolute_overlay_log
    "${_cdisasm_absolute_overlay_output}\n${_cdisasm_absolute_overlay_error}")
if(NOT _cdisasm_absolute_overlay_log MATCHES
        "Refusing to overlay a different cdisasm build variant")
    message(FATAL_ERROR
        "Absolute-destination overlay failed for an unexpected reason.\n"
        "${_cdisasm_absolute_overlay_log}")
endif()
_cdisasm_snapshot_prefix(
    "${_cdisasm_absolute_destination}"
    _cdisasm_after_absolute_overlay)
_cdisasm_snapshot_prefix(
    "${_cdisasm_absolute_prefix}"
    _cdisasm_after_absolute_prefix_overlay)
if(NOT _cdisasm_after_absolute_overlay STREQUAL
        _cdisasm_before_absolute_overlay
        OR NOT _cdisasm_after_absolute_prefix_overlay STREQUAL
            _cdisasm_before_absolute_prefix_overlay)
    message(FATAL_ERROR
        "Rejected absolute-destination overlay changed installed files")
endif()

file(REMOVE "${_cdisasm_absolute_fingerprint}")
_cdisasm_snapshot_prefix(
    "${_cdisasm_absolute_destination}"
    _cdisasm_before_absolute_legacy_overlay)
_cdisasm_snapshot_prefix(
    "${_cdisasm_absolute_prefix}"
    _cdisasm_before_absolute_legacy_prefix_overlay)
execute_process(
    COMMAND
        "${CMAKE_COMMAND}"
        --install "${_cdisasm_absolute_static_build}"
        --config "${_cdisasm_config}"
    RESULT_VARIABLE _cdisasm_absolute_legacy_result
    OUTPUT_VARIABLE _cdisasm_absolute_legacy_output
    ERROR_VARIABLE _cdisasm_absolute_legacy_error)
if(_cdisasm_absolute_legacy_result EQUAL 0)
    message(FATAL_ERROR
        "An unfingerprinted absolute installation accepted an overlay")
endif()
set(_cdisasm_absolute_legacy_log
    "${_cdisasm_absolute_legacy_output}\n${_cdisasm_absolute_legacy_error}")
if(NOT _cdisasm_absolute_legacy_log MATCHES
        "Refusing to overlay an unfingerprinted cdisasm installation")
    message(FATAL_ERROR
        "Absolute unfingerprinted overlay failed for an unexpected reason.\n"
        "${_cdisasm_absolute_legacy_log}")
endif()
if(EXISTS "${_cdisasm_absolute_fingerprint}")
    message(FATAL_ERROR
        "Rejected absolute legacy overlay recreated the fingerprint")
endif()
_cdisasm_snapshot_prefix(
    "${_cdisasm_absolute_destination}"
    _cdisasm_after_absolute_legacy_overlay)
_cdisasm_snapshot_prefix(
    "${_cdisasm_absolute_prefix}"
    _cdisasm_after_absolute_legacy_prefix_overlay)
if(NOT _cdisasm_after_absolute_legacy_overlay STREQUAL
        _cdisasm_before_absolute_legacy_overlay
        OR NOT _cdisasm_after_absolute_legacy_prefix_overlay STREQUAL
            _cdisasm_before_absolute_legacy_prefix_overlay)
    message(FATAL_ERROR
        "Rejected absolute unfingerprinted overlay changed installed files")
endif()

# Remove the recognized library marker as well, leaving the public header as
# the only guard input. This independently proves absolute INCLUDEDIR lookup.
set(_cdisasm_absolute_package_config
    "${_cdisasm_absolute_libdir}/cmake/cdisasm/cdisasmConfig.cmake")
if(NOT EXISTS "${_cdisasm_absolute_package_config}")
    message(FATAL_ERROR
        "Absolute install omitted the package marker needed by the fixture")
endif()
file(REMOVE "${_cdisasm_absolute_package_config}")
_cdisasm_snapshot_prefix(
    "${_cdisasm_absolute_destination}"
    _cdisasm_before_absolute_header_overlay)
_cdisasm_snapshot_prefix(
    "${_cdisasm_absolute_prefix}"
    _cdisasm_before_absolute_header_prefix_overlay)
execute_process(
    COMMAND
        "${CMAKE_COMMAND}"
        --install "${_cdisasm_absolute_static_build}"
        --config "${_cdisasm_config}"
    RESULT_VARIABLE _cdisasm_absolute_header_result
    OUTPUT_VARIABLE _cdisasm_absolute_header_output
    ERROR_VARIABLE _cdisasm_absolute_header_error)
if(_cdisasm_absolute_header_result EQUAL 0)
    message(FATAL_ERROR
        "An absolute header-only legacy marker accepted an overlay")
endif()
set(_cdisasm_absolute_header_log
    "${_cdisasm_absolute_header_output}\n${_cdisasm_absolute_header_error}")
if(NOT _cdisasm_absolute_header_log MATCHES
        "Refusing to overlay an unfingerprinted cdisasm installation")
    message(FATAL_ERROR
        "Absolute header-marker overlay failed for an unexpected reason.\n"
        "${_cdisasm_absolute_header_log}")
endif()
if(EXISTS "${_cdisasm_absolute_fingerprint}"
        OR EXISTS "${_cdisasm_absolute_package_config}")
    message(FATAL_ERROR
        "Rejected absolute header-marker overlay recreated package metadata")
endif()
_cdisasm_snapshot_prefix(
    "${_cdisasm_absolute_destination}"
    _cdisasm_after_absolute_header_overlay)
_cdisasm_snapshot_prefix(
    "${_cdisasm_absolute_prefix}"
    _cdisasm_after_absolute_header_prefix_overlay)
if(NOT _cdisasm_after_absolute_header_overlay STREQUAL
        _cdisasm_before_absolute_header_overlay
        OR NOT _cdisasm_after_absolute_header_prefix_overlay STREQUAL
            _cdisasm_before_absolute_header_prefix_overlay)
    message(FATAL_ERROR
        "Rejected absolute header-marker overlay changed installed files")
endif()
file(REMOVE_RECURSE "${_cdisasm_absolute_destination}")
if(EXISTS "${_cdisasm_absolute_destination}")
    message(FATAL_ERROR
        "Could not clean ${_cdisasm_absolute_destination}")
endif()

if(UNIX)
    # Exercise both path branches under staging: LIBDIR is absolute while
    # INCLUDEDIR is relative to the logical prefix. Nothing may escape the
    # disposable DESTDIR root, and the staged fingerprint must still reject a
    # different tuple before any staged artifact changes.
    set(_cdisasm_destdir_stage "${_cdisasm_root}/destdir-stage")
    set(_cdisasm_destdir_prefix "/opt/cdisasm-destdir-prefix")
    set(_cdisasm_destdir_libdir "/opt/cdisasm-destdir-lib")
    set(_cdisasm_destdir_static_build
        "${_cdisasm_root}/destdir-static")
    set(_cdisasm_destdir_shared_build
        "${_cdisasm_root}/destdir-shared")
    _cdisasm_configure_variant(
        "${_cdisasm_destdir_static_build}"
        OFF ON OFF
        "${_cdisasm_destdir_prefix}"
        "${_cdisasm_destdir_libdir}"
        include)
    _cdisasm_configure_variant(
        "${_cdisasm_destdir_shared_build}"
        ON ON OFF
        "${_cdisasm_destdir_prefix}"
        "${_cdisasm_destdir_libdir}"
        include)
    _cdisasm_run_success(
        "Install staged absolute/relative-destination variant"
        "${CMAKE_COMMAND}" -E env
        "DESTDIR=${_cdisasm_destdir_stage}"
        "${CMAKE_COMMAND}"
        --install "${_cdisasm_destdir_static_build}"
        --config "${_cdisasm_config}")
    set(_cdisasm_destdir_fingerprint
        "${_cdisasm_destdir_stage}${_cdisasm_destdir_libdir}/cmake/cdisasm/cdisasm-variant.txt")
    set(_cdisasm_destdir_header
        "${_cdisasm_destdir_stage}${_cdisasm_destdir_prefix}/include/cdisasm/cdisasm_common.h")
    if(NOT EXISTS "${_cdisasm_destdir_fingerprint}"
            OR NOT EXISTS "${_cdisasm_destdir_header}")
        message(FATAL_ERROR
            "Staged install did not honor absolute/relative destinations")
    endif()
    _cdisasm_snapshot_prefix(
        "${_cdisasm_destdir_stage}"
        _cdisasm_before_destdir_overlay)
    execute_process(
        COMMAND
            "${CMAKE_COMMAND}" -E env
            "DESTDIR=${_cdisasm_destdir_stage}"
            "${CMAKE_COMMAND}"
            --install "${_cdisasm_destdir_shared_build}"
            --config "${_cdisasm_config}"
        RESULT_VARIABLE _cdisasm_destdir_overlay_result
        OUTPUT_VARIABLE _cdisasm_destdir_overlay_output
        ERROR_VARIABLE _cdisasm_destdir_overlay_error)
    if(_cdisasm_destdir_overlay_result EQUAL 0)
        message(FATAL_ERROR
            "A different variant unexpectedly overlaid a DESTDIR stage")
    endif()
    set(_cdisasm_destdir_overlay_log
        "${_cdisasm_destdir_overlay_output}\n${_cdisasm_destdir_overlay_error}")
    if(NOT _cdisasm_destdir_overlay_log MATCHES
            "Refusing to overlay a different cdisasm build variant")
        message(FATAL_ERROR
            "Staged overlay failed for an unexpected reason.\n"
            "${_cdisasm_destdir_overlay_log}")
    endif()
    _cdisasm_snapshot_prefix(
        "${_cdisasm_destdir_stage}"
        _cdisasm_after_destdir_overlay)
    if(NOT _cdisasm_after_destdir_overlay STREQUAL
            _cdisasm_before_destdir_overlay)
        message(FATAL_ERROR
            "Rejected DESTDIR overlay changed staged installed files")
    endif()
endif()

# An in-source configure used to overwrite include/cdisasm/cdisasm_config.h.
# Configure a selective tuple in a disposable source copy and require the
# checked-in fallback to remain byte-identical while the tuple-specific header
# is generated under generated/include.
set(_cdisasm_in_source_root "${_cdisasm_root}/in-source")
file(MAKE_DIRECTORY "${_cdisasm_in_source_root}")
file(COPY
    "${CDISASM_SOURCE_DIR}/CMakeLists.txt"
    "${CDISASM_SOURCE_DIR}/LICENSE"
    "${CDISASM_SOURCE_DIR}/README.md"
    "${CDISASM_SOURCE_DIR}/cmake"
    "${CDISASM_SOURCE_DIR}/include"
    "${CDISASM_SOURCE_DIR}/src"
    DESTINATION "${_cdisasm_in_source_root}")
set(_cdisasm_in_source_fallback
    "${_cdisasm_in_source_root}/include/cdisasm/cdisasm_config.h")
file(SHA256
    "${_cdisasm_in_source_fallback}"
    _cdisasm_in_source_fallback_before)
_cdisasm_run_success(
    "Configure selective tuple in source"
    "${CMAKE_COMMAND}"
    -S "${_cdisasm_in_source_root}"
    -B "${_cdisasm_in_source_root}"
    ${_cdisasm_generator_args}
    ${_cdisasm_identity_args}
    -DBUILD_TESTING:BOOL=OFF
    -DCDISASM_BUILD_EXAMPLES:BOOL=OFF
    -DCDISASM_BUILD_FUZZERS:BOOL=OFF
    -DCDISASM_BUILD_PACKAGE_TESTS:BOOL=OFF
    -DUSE_ARCH_X86:BOOL=ON
    -DUSE_ARCH_ARM:BOOL=OFF
    -DUSE_DISASM_FORMAT:BOOL=OFF
    -DUSE_EXTRA_OPCODES:BOOL=OFF)
file(SHA256
    "${_cdisasm_in_source_fallback}"
    _cdisasm_in_source_fallback_after)
if(NOT _cdisasm_in_source_fallback_after STREQUAL
        _cdisasm_in_source_fallback_before)
    message(FATAL_ERROR
        "In-source configure modified the checked-in fallback header")
endif()
set(_cdisasm_in_source_generated
    "${_cdisasm_in_source_root}/generated/include/cdisasm/cdisasm_config.h")
if(NOT EXISTS "${_cdisasm_in_source_generated}")
    message(FATAL_ERROR
        "In-source configure omitted the generated tuple-specific header")
endif()
_cdisasm_require_file_text(
    "${_cdisasm_in_source_generated}"
    "#define CDISASM_CONFIG_USE_ARCH_X86 1"
    "In-source generated configuration")
_cdisasm_require_file_text(
    "${_cdisasm_in_source_generated}"
    "#define CDISASM_CONFIG_USE_ARCH_ARM 0"
    "In-source generated configuration")

message(STATUS
    "Variant fingerprint accepted ON/TRUE/YES/1 and OFF/FALSE/NO/0 "
    "equivalent spellings, and rejected shared/static, extra-opcode-request, "
    "unfingerprinted, absolute-destination, and staged overlays without "
    "modifying their installations; in-source configuration preserved the "
    "fallback")
