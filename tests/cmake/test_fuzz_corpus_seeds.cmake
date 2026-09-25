cmake_minimum_required(VERSION 3.16)

if(NOT DEFINED CDISASM_SOURCE_DIR)
    message(FATAL_ERROR "CDISASM_SOURCE_DIR is required")
endif()

function(cdisasm_audit_hex_corpus corpus_name relative_directory raw_limit)
    set(corpus_directory
        "${CDISASM_SOURCE_DIR}/${relative_directory}")
    if(NOT IS_DIRECTORY "${corpus_directory}")
        message(FATAL_ERROR
            "${corpus_name} corpus directory is missing: ${corpus_directory}")
    endif()

    file(GLOB_RECURSE corpus_entries
        RELATIVE "${corpus_directory}"
        "${corpus_directory}/*")
    set(seed_count 0)
    set(maximum_size 0)
    foreach(seed_relative IN LISTS corpus_entries)
        set(seed_path "${corpus_directory}/${seed_relative}")
        if(IS_DIRECTORY "${seed_path}")
            message(FATAL_ERROR
                "${corpus_name} corpus contains a directory: ${seed_relative}")
        endif()
        if(NOT seed_relative MATCHES "^[^/\\\\]+[.]hex$")
            message(FATAL_ERROR
                "${corpus_name} corpus contains a non-.hex artifact: ${seed_relative}")
        endif()

        file(SIZE "${seed_path}" raw_size)
        if(raw_size LESS 1 OR raw_size GREATER raw_limit)
            message(FATAL_ERROR
                "${corpus_name} seed ${seed_relative} is ${raw_size} bytes; "
                "the supported raw-text range is 1..${raw_limit}")
        endif()
        if(raw_size GREATER maximum_size)
            set(maximum_size "${raw_size}")
        endif()

        file(READ "${seed_path}" seed_text)
        string(REGEX REPLACE "[ \t\r\n]" "" compact_hex "${seed_text}")
        if(compact_hex STREQUAL ""
           OR NOT compact_hex MATCHES "^[0-9A-Fa-f]+$")
            message(FATAL_ERROR
                "${corpus_name} seed ${seed_relative} is not whitespace-separated hexadecimal")
        endif()
        string(LENGTH "${compact_hex}" digit_count)
        math(EXPR odd_digit_count "${digit_count} % 2")
        math(EXPR decoded_size "${digit_count} / 2")
        if(odd_digit_count OR decoded_size GREATER 64)
            message(FATAL_ERROR
                "${corpus_name} seed ${seed_relative} does not normalize to 1..64 bytes")
        endif()
        math(EXPR seed_count "${seed_count} + 1")
    endforeach()

    if(seed_count EQUAL 0)
        message(FATAL_ERROR "${corpus_name} corpus contains no .hex seeds")
    endif()
    message(STATUS
        "${corpus_name} fuzz corpus: ${seed_count} seeds, maximum ${maximum_size} raw bytes")
endfunction()

if(CDISASM_AUDIT_X86)
    # libFuzzer applies -max_len to the readable text before normalization.
    cdisasm_audit_hex_corpus("x86" "fuzz/corpus" 192)
endif()
if(CDISASM_AUDIT_ARM)
    cdisasm_audit_hex_corpus("ARM" "fuzz/arm_corpus" 64)
endif()
