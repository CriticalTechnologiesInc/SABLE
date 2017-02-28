cmake_minimum_required (VERSION 3.0.2)
project (SABLE C ASM)
set (SABLE_VERSION_MAJOR 0)
set (SABLE_VERSION_MINOR 4)

message("CMAKE_BUILD_TYPE is '${CMAKE_BUILD_TYPE}'")

configure_file (
  "${PROJECT_SOURCE_DIR}/include/version.h.in"
  "${PROJECT_BINARY_DIR}/include/version.h"
  )
add_subdirectory(tools)

set (CMAKE_C_FLAGS
  "${CMAKE_C_FLAGS} \
  -D__FILENAME__='\"$(subst ${CMAKE_SOURCE_DIR}/,,$(abspath $<))\"' \
  -Wall \
  -Werror \
  -Wno-main \
  -fno-builtin \
  -nostdlib \
  -fno-stack-protector \
  -fno-asynchronous-unwind-tables \
  -fpack-struct \
  -m32 \
  -std=gnu99 \
  -mregparm=3 \
  -fomit-frame-pointer \
  -minline-all-stringops \
  --param max-inline-insns-single=50 \
  -fstrict-aliasing \
  -Wstrict-aliasing=0"
  )

set (CMAKE_ASM_FLAGS ${CMAKE_C_FLAGS})

set (CMAKE_EXE_LINKER_FLAGS
  "${CMAKE_EXE_LINKER_FLAGS} \
  -gc-sections \
  -Wl,--build-id=none \
  -T ${PROJECT_SOURCE_DIR}/src/sable.ld"
  )

add_executable (sable
  src/asm.S
  src/alloc.c
  src/dev.c
  src/elf.c
  src/hmac.c
  src/keyboard.c
  src/mp.c
  src/sha.c
  src/tis.c
  src/tpm.c
  src/tpm_error.c
  src/tpm_struct.c
  src/util.c
  src/sable.c
  src/sable_verified.c
  )

target_include_directories (sable PUBLIC
  "${PROJECT_SOURCE_DIR}/include/"
  "${PROJECT_BINARY_DIR}/include/"
  )
set_property (TARGET sable PROPERTY LINK_DEPENDS ${PROJECT_SOURCE_DIR}/src/sable.ld)
add_dependencies (sable macros sable_verified_h)

# These are include files used to generate sable.h only
set (SABLE_H_HEADER_FILES
  ${PROJECT_SOURCE_DIR}/include/asm.h
  ${PROJECT_SOURCE_DIR}/include/option.h
  ${PROJECT_SOURCE_DIR}/include/platform.h
  ${PROJECT_SOURCE_DIR}/include/exception.h
  ${PROJECT_SOURCE_DIR}/include/alloc.h
  ${PROJECT_SOURCE_DIR}/include/dev.h
  ${PROJECT_SOURCE_DIR}/include/mbi.h
  ${PROJECT_SOURCE_DIR}/include/elf.h
  ${PROJECT_SOURCE_DIR}/include/mp.h
  ${PROJECT_SOURCE_DIR}/include/tcg.h
  ${PROJECT_SOURCE_DIR}/include/keyboard.h
  ${PROJECT_SOURCE_DIR}/include/sha.h
  ${PROJECT_SOURCE_DIR}/include/hmac.h
  ${PROJECT_SOURCE_DIR}/include/tis.h
  ${PROJECT_SOURCE_DIR}/include/tpm.h
  ${PROJECT_SOURCE_DIR}/include/tpm_error.h
  ${PROJECT_SOURCE_DIR}/include/tpm_ordinal.h
  ${PROJECT_SOURCE_DIR}/include/tpm_struct.h
  ${PROJECT_SOURCE_DIR}/include/util.h
  )

set (DEFINITIONS "")
if (${CMAKE_BUILD_TYPE} STREQUAL "RELEASE")
  set (DEFINITIONS "${DEFINITIONS}" "-DNDEBUG")
endif (${CMAKE_BUILD_TYPE} STREQUAL "RELEASE")


find_package( PythonInterp 3.4 REQUIRED )

file( MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/intermediate )

# generate macro.h, which contains all header-defined macros
add_custom_command (
  OUTPUT ${PROJECT_BINARY_DIR}/include/macro.h
  COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/cat_macros.py ${SABLE_H_HEADER_FILES}
    > ${PROJECT_BINARY_DIR}/include/macro.h
  DEPENDS ${SABLE_H_HEADER_FILES}
  )
add_custom_target (macros DEPENDS ${PROJECT_BINARY_DIR}/include/macro.h)

# generate all_headers.h, i.e. all source headers concatenated together
add_custom_command (
  OUTPUT ${PROJECT_BINARY_DIR}/intermediate/all_headers.h
  COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/cat_c.py ${SABLE_H_HEADER_FILES}
    > ${PROJECT_BINARY_DIR}/intermediate/all_headers.h
  DEPENDS ${SABLE_H_HEADER_FILES}
  )

# generate all_headers_pp.h, i.e. all source headers concatenated together, preprocessed
add_custom_command (
  OUTPUT ${PROJECT_BINARY_DIR}/intermediate/all_headers_pp.h
  COMMAND ${CMAKE_C_COMPILER} ${DEFINITIONS} -E
    -o ${PROJECT_BINARY_DIR}/intermediate/all_headers_pp.h
    ${PROJECT_BINARY_DIR}/intermediate/all_headers.h
  DEPENDS ${PROJECT_BINARY_DIR}/intermediate/all_headers.h
  )

# generate sable_verified.h
add_custom_command (
  OUTPUT ${PROJECT_BINARY_DIR}/include/sable_verified.h
  COMMAND ${PROJECT_BINARY_DIR}/tools/makeheaders/makeheaders
    ${PROJECT_SOURCE_DIR}/src/sable_verified.c:${PROJECT_BINARY_DIR}/include/sable_verified.h
    ${PROJECT_BINARY_DIR}/intermediate/all_headers_pp.h
  DEPENDS makeheaders ${PROJECT_BINARY_DIR}/intermediate/all_headers_pp.h ${PROJECT_SOURCE_DIR}/src/sable_verified.c
  )
add_custom_target (sable_verified_h DEPENDS ${PROJECT_BINARY_DIR}/include/sable_verified.h)

# Build the input file for Isabelle/HOL
# custom command and target to generate sable_verified_pp.c
if (${CMAKE_BUILD_TYPE} STREQUAL "RELEASE")
add_custom_command (
  OUTPUT ${PROJECT_BINARY_DIR}/sable_verified_pp.c
  COMMAND ${CMAKE_C_COMPILER} -E -DNDEBUG -DISABELLE
    -I${PROJECT_BINARY_DIR}/include/
    -o ${PROJECT_BINARY_DIR}/sable_verified_pp.c
    ${PROJECT_SOURCE_DIR}/src/sable_verified.c
  DEPENDS ${PROJECT_SOURCE_DIR}/src/sable_verified.c macros sable_verified_h
  )
add_custom_target (sable-isa DEPENDS ${PROJECT_BINARY_DIR}/sable_verified_pp.c)
endif (${CMAKE_BUILD_TYPE} STREQUAL "RELEASE")
