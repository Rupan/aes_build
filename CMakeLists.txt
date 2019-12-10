cmake_minimum_required(VERSION 3.10)
project(aes_code VERSION 1.0.0 DESCRIPTION "AES code in C and assembly")

include(CheckCCompilerFlag)
include(CheckSymbolExists)

set(LIB_SOURCES
    ${CMAKE_SOURCE_DIR}/aes/aeskey.c
    ${CMAKE_SOURCE_DIR}/aes/aes_modes.c
    ${CMAKE_SOURCE_DIR}/aes/aestab.c
    ${CMAKE_SOURCE_DIR}/aes/aescrypt.c
    # Encryption / Authentication Modes
    ${CMAKE_SOURCE_DIR}/modes/eax.c
    ${CMAKE_SOURCE_DIR}/modes/ccm.c
    ${CMAKE_SOURCE_DIR}/modes/cwc.c
    ${CMAKE_SOURCE_DIR}/modes/gcm.c
    ${CMAKE_SOURCE_DIR}/modes/gf128mul.c
    # Message Authentication Modes
    ${CMAKE_SOURCE_DIR}/modes/omac.c
    ${CMAKE_SOURCE_DIR}/modes/cmac.c
    # Disc Encryption modes -- gf_mulx copied, so linking fails.
    ${CMAKE_SOURCE_DIR}/modes/eme2.c
    ${CMAKE_SOURCE_DIR}/modes/xts.c
    ${CMAKE_SOURCE_DIR}/modes/gf_mulx.c
)

# FIXME: why are both needed?!
include_directories(
    ${CMAKE_SOURCE_DIR}/aes
    ${CMAKE_SOURCE_DIR}/modes
)
list(APPEND CMAKE_REQUIRED_INCLUDES
    ${CMAKE_SOURCE_DIR}/aes
    ${CMAKE_SOURCE_DIR}/modes
)

if(WIN32)
    set(AES64_OPTIMIZED_CPU "AMD64")
elseif(UNIX)
    set(AES64_OPTIMIZED_CPU "x86_64")
endif()

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "${AES64_OPTIMIZED_CPU}")
    if(UNIX)
        # Check if we can enable AVX and AES on clang/gcc
        check_c_compiler_flag("-mavx -maes" HAS_AVX_AES)
        if(HAS_AVX_AES)
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx -maes")
            set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -mavx -maes")
        endif()
    endif()
    # Add AES_NI source code if the define INTEL_AES_POSSIBLE exists in aesopt.h
    check_symbol_exists(INTEL_AES_POSSIBLE aesopt.h TARGET_SUPPORTS_AESNI)
    if(TARGET_SUPPORTS_AESNI)
        list(APPEND LIB_SOURCES ${CMAKE_SOURCE_DIR}/aes/aes_ni.c)
    endif()
    # Enable assembly code
    if(WIN32)
        set(YASM_POSSIBLE_PATHS
            "$ENV{ProgramFiles}/yasm"
            "$ENV{ProgramFiles}/yasm/bin"
        )
    else()
        set(YASM_POSSIBLE_PATHS
            "$ENV{HOME}/bin"
            "/usr/local/bin"
        )
    endif()
    find_program(YASM_BIN yasm HINTS ${YASM_POSSIBLE_PATHS})
    message(STATUS "YASM path: ${YASM_BIN}")
    set(CMAKE_ASM_NASM_COMPILER "${YASM_BIN}")
    enable_language(ASM_NASM)
    set(CMAKE_ASM_NASM_COMPILER "${YASM_BIN}")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DASM_AMD64_C")
    if(WIN32)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DDLL_EXPORT")
    endif()
    list(APPEND LIB_SOURCES ${CMAKE_SOURCE_DIR}/aes/aes_amd64.asm)
    if(TARGET_SUPPORTS_AESNI)
        set(CMAKE_ASM_NASM_FLAGS "${CMAKE_ASM_NASM_FLAGS} -DINTEL_AES_POSSIBLE")
    endif()
    # On UNIX-like systems, use the System V AMD64 ABI
    if(UNIX)
        set(CMAKE_ASM_NASM_FLAGS "${CMAKE_ASM_NASM_FLAGS} -D__GNUC__")
    endif()
    # Enable debugging symbols on Linux -- others possible?
    if(CMAKE_BUILD_TYPE MATCHES Debug OR CMAKE_BUILD_TYPE MATCHES RelWithDebInfo)
        if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
            set(CMAKE_ASM_NASM_FLAGS "${CMAKE_ASM_NASM_FLAGS} -g dwarf2")
        endif()
    endif()
endif()

add_library(aes_dynamic SHARED ${LIB_SOURCES})
set_target_properties(aes_dynamic PROPERTIES
    OUTPUT_NAME aes
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/dynamic"
)
if(UNIX AND NOT APPLE)
    set_target_properties(aes_dynamic PROPERTIES
        SOVERSION 0
        VERSION ${PROJECT_VERSION}
    )
endif()
add_library(aes_static STATIC ${LIB_SOURCES})
set_target_properties(aes_static PROPERTIES
    OUTPUT_NAME aes
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/static"
)

add_executable(aesxam_d ${CMAKE_SOURCE_DIR}/aes/aesxam.c)
target_link_libraries(aesxam_d aes_dynamic)
add_executable(aesxam_s ${CMAKE_SOURCE_DIR}/aes/aesxam.c)
target_link_libraries(aesxam_s aes_static)

add_executable(tablegen
    ${CMAKE_SOURCE_DIR}/aes/tablegen.c
    ${CMAKE_SOURCE_DIR}/aes/aesaux.c
)

set(AESGAV_SOURCES
    ${CMAKE_SOURCE_DIR}/aes/aesgav.c
    ${CMAKE_SOURCE_DIR}/aes/aesaux.c
)
add_executable(aesgav_d ${AESGAV_SOURCES})
target_link_libraries(aesgav_d aes_dynamic)
add_executable(aesgav_s ${AESGAV_SOURCES})
target_link_libraries(aesgav_s aes_static)

set(AES_AVS_SOURCES
    ${CMAKE_SOURCE_DIR}/aes/aes_avs.c
    ${CMAKE_SOURCE_DIR}/aes/aesaux.c
)
add_executable(aes_avs_d ${AES_AVS_SOURCES})
target_link_libraries(aes_avs_d aes_dynamic)
add_executable(aes_avs_s  ${AES_AVS_SOURCES})
target_link_libraries(aes_avs_s aes_static)

set(AESRAV_SOURCES
    ${CMAKE_SOURCE_DIR}/aes/aesrav.c
    ${CMAKE_SOURCE_DIR}/aes/aesaux.c
)
add_executable(aesrav_d ${AESRAV_SOURCES})
target_link_libraries(aesrav_d aes_dynamic)
add_executable(aesrav_s ${AESRAV_SOURCES})
target_link_libraries(aesrav_s aes_static)

set(AESTST_SOURCES ${CMAKE_SOURCE_DIR}/aes/aestst.c)
add_executable(aestst_d ${AESTST_SOURCES})
target_link_libraries(aestst_d aes_dynamic)
add_executable(aestst_s ${AESTST_SOURCES})
target_link_libraries(aestst_s aes_static)

set(RFC3686_SOURCES ${CMAKE_SOURCE_DIR}/aes/rfc3686.c)
add_executable(rfc3686_d ${RFC3686_SOURCES})
target_link_libraries(rfc3686_d aes_dynamic)
add_executable(rfc3686_s ${RFC3686_SOURCES})
target_link_libraries(rfc3686_s aes_static)

# Explicit thread to processor binding is not supported on OS X
if(NOT APPLE)
    set(AESTMR_SOURCES
        ${CMAKE_SOURCE_DIR}/aes/aestmr.c
        ${CMAKE_SOURCE_DIR}/aes/aesaux.c
    )
    add_executable(aestmr_d ${AESTMR_SOURCES})
    add_executable(aestmr_s ${AESTMR_SOURCES})

    set(MODETEST_SOURCES
        ${CMAKE_SOURCE_DIR}/aes/modetest.c
        ${CMAKE_SOURCE_DIR}/aes/aesaux.c
    )
    add_executable(modetest_d ${MODETEST_SOURCES})
    add_executable(modetest_s ${MODETEST_SOURCES})
    if(WIN32)
        target_link_libraries(aestmr_d aes_dynamic)
        target_link_libraries(aestmr_s aes_static)
        target_link_libraries(modetest_d aes_dynamic)
        target_link_libraries(modetest_s aes_static)
    elseif(UNIX)
        target_link_libraries(aestmr_d aes_dynamic m)
        target_link_libraries(aestmr_s aes_static m)
        target_link_libraries(modetest_d aes_dynamic m)
        target_link_libraries(modetest_s aes_static m)
    endif()
endif()
