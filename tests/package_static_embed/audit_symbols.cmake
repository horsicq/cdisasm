cmake_minimum_required(VERSION 3.16)

foreach(_cdisasm_static_embed_required
        CDISASM_STATIC_EMBED_LIBRARY
        CDISASM_STATIC_EMBED_OBJECT_FORMAT)
    if(NOT DEFINED ${_cdisasm_static_embed_required}
            OR "${${_cdisasm_static_embed_required}}" STREQUAL "")
        message(FATAL_ERROR
            "${_cdisasm_static_embed_required} must be provided")
    endif()
endforeach()

if(NOT EXISTS "${CDISASM_STATIC_EMBED_LIBRARY}")
    message(FATAL_ERROR
        "Static-embedding wrapper does not exist: "
        "${CDISASM_STATIC_EMBED_LIBRARY}")
endif()
if(CDISASM_STATIC_EMBED_OBJECT_FORMAT STREQUAL "MACHO")
    if(NOT DEFINED CDISASM_STATIC_EMBED_NM
            OR "${CDISASM_STATIC_EMBED_NM}" STREQUAL ""
            OR NOT EXISTS "${CDISASM_STATIC_EMBED_NM}")
        message(FATAL_ERROR "Mach-O symbol inspection requires nm")
    endif()
    execute_process(
        COMMAND
            "${CDISASM_STATIC_EMBED_NM}"
            -gU
            "${CDISASM_STATIC_EMBED_LIBRARY}"
        RESULT_VARIABLE _cdisasm_static_embed_result
        OUTPUT_VARIABLE _cdisasm_static_embed_symbols
        ERROR_VARIABLE _cdisasm_static_embed_error)
elseif(CDISASM_STATIC_EMBED_OBJECT_FORMAT STREQUAL "ELF")
    set(_cdisasm_static_embed_result 1)
    if(DEFINED CDISASM_STATIC_EMBED_NM
            AND NOT "${CDISASM_STATIC_EMBED_NM}" STREQUAL ""
            AND EXISTS "${CDISASM_STATIC_EMBED_NM}")
        execute_process(
            COMMAND
                "${CDISASM_STATIC_EMBED_NM}"
                -D
                --defined-only
                "${CDISASM_STATIC_EMBED_LIBRARY}"
            RESULT_VARIABLE _cdisasm_static_embed_result
            OUTPUT_VARIABLE _cdisasm_static_embed_symbols
            ERROR_VARIABLE _cdisasm_static_embed_error)
    endif()

    if(NOT _cdisasm_static_embed_result EQUAL 0
            AND DEFINED CDISASM_STATIC_EMBED_READELF
            AND NOT "${CDISASM_STATIC_EMBED_READELF}" STREQUAL ""
            AND EXISTS "${CDISASM_STATIC_EMBED_READELF}")
        execute_process(
            COMMAND
                "${CDISASM_STATIC_EMBED_READELF}"
                --dyn-syms
                --wide
                "${CDISASM_STATIC_EMBED_LIBRARY}"
            RESULT_VARIABLE _cdisasm_static_embed_result
            OUTPUT_VARIABLE _cdisasm_static_embed_symbols
            ERROR_VARIABLE _cdisasm_static_embed_error)
    endif()
else()
    message(FATAL_ERROR
        "Unsupported object format: ${CDISASM_STATIC_EMBED_OBJECT_FORMAT}")
endif()

if(NOT _cdisasm_static_embed_result EQUAL 0)
    message(FATAL_ERROR
        "Could not inspect dynamic symbols in "
        "${CDISASM_STATIC_EMBED_LIBRARY}.\n"
        "${_cdisasm_static_embed_error}")
endif()

string(REGEX MATCH
    "(^|[\r\n])[^\r\n]*[ \t]_?package_static_embed_probe([^A-Za-z0-9_]|[\r\n]|$)"
    _cdisasm_static_embed_wrapper_match
    "${_cdisasm_static_embed_symbols}")
if(_cdisasm_static_embed_wrapper_match STREQUAL "")
    message(FATAL_ERROR
        "The wrapper export package_static_embed_probe is absent.\n"
        "Dynamic symbols:\n${_cdisasm_static_embed_symbols}")
endif()

string(REGEX MATCH
    "(^|[\r\n])[^\r\n]*[ \t]_?cdisasm_[A-Za-z0-9_]*([^A-Za-z0-9_]|[\r\n]|$)"
    _cdisasm_static_embed_leak
    "${_cdisasm_static_embed_symbols}")
if(NOT _cdisasm_static_embed_leak STREQUAL "")
    message(FATAL_ERROR
        "Static cdisasm symbols leaked into the wrapper's dynamic ABI.\n"
        "First leak: ${_cdisasm_static_embed_leak}\n"
        "Dynamic symbols:\n${_cdisasm_static_embed_symbols}")
endif()

message(STATUS
    "Static cdisasm embedding exports only the explicit wrapper ABI")
