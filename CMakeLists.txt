cmake_minimum_required (VERSION 3.0.2)
project (SABLE C ASM)
set (SABLE_VERSION_MAJOR 0)
set (SABLE_VERSION_MINOR 3)

configure_file (
  "${PROJECT_SOURCE_DIR}/include/version.h.in"
  "${PROJECT_BINARY_DIR}/include/version.h"
  )
add_subdirectory(tools)

set (CMAKE_C_FLAGS
  "${CMAKE_C_FLAGS} \
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
  src/string.c
  )

target_include_directories (sable PUBLIC
  "${PROJECT_SOURCE_DIR}/include/"
  "${PROJECT_BINARY_DIR}/include/"
  )
set_property (TARGET sable PROPERTY LINK_DEPENDS ${PROJECT_SOURCE_DIR}/src/sable.ld)
add_dependencies (sable sable_verified_h)

# These are include files used to generate sable.h only
set (SABLE_H_HEADER_FILES
  ${PROJECT_SOURCE_DIR}/include/macro.h
  ${PROJECT_SOURCE_DIR}/include/asm.h
  ${PROJECT_SOURCE_DIR}/include/dev.h
  ${PROJECT_SOURCE_DIR}/include/elf.h
  ${PROJECT_SOURCE_DIR}/include/sha.h
  ${PROJECT_SOURCE_DIR}/include/hmac.h
  ${PROJECT_SOURCE_DIR}/include/keyboard.h
  ${PROJECT_SOURCE_DIR}/include/mbi.h
  ${PROJECT_SOURCE_DIR}/include/mp.h
  ${PROJECT_SOURCE_DIR}/include/platform.h
  ${PROJECT_SOURCE_DIR}/include/tcg.h
  ${PROJECT_SOURCE_DIR}/include/tis.h
  ${PROJECT_SOURCE_DIR}/include/tpm_error.h
  ${PROJECT_SOURCE_DIR}/include/tpm_ordinal.h
  ${PROJECT_SOURCE_DIR}/include/tpm_struct.h
  ${PROJECT_SOURCE_DIR}/include/tpm.h
  ${PROJECT_SOURCE_DIR}/include/util.h
  ${PROJECT_BINARY_DIR}/include/version.h
  )

# Header dependencies for sable.c
set (SABLE_C_HEADER_FILES
  ${PROJECT_BINARY_DIR}/include/sable_verified.h
  ${PROJECT_SOURCE_DIR}/include/string.h
  )

# custom command and target to generate sable.h
add_custom_command (
  OUTPUT ${PROJECT_BINARY_DIR}/include/sable_verified.h
  COMMAND ${PROJECT_BINARY_DIR}/tools/makeheaders/makeheaders
    ${PROJECT_SOURCE_DIR}/src/sable_verified.c:${PROJECT_BINARY_DIR}/include/sable_verified.h
    ${SABLE_H_HEADER_FILES}
  DEPENDS ${PROJECT_SOURCE_DIR}/src/sable_verified.c ${SABLE_HEADER_FILES}
  )
add_custom_target (sable_verified_h DEPENDS makeheaders ${PROJECT_BINARY_DIR}/include/sable_verified.h)

# custom command and target to generate sable.cpp
add_custom_command (
  OUTPUT ${PROJECT_BINARY_DIR}/sable_verified.cpp
  COMMAND ${CMAKE_C_COMPILER} -E
    ${PROJECT_SOURCE_DIR}/src/sable_verified.c
    -DISABELLE
    -I${PROJECT_SOURCE_DIR}/include/
    -I${PROJECT_BINARY_DIR}/include/
    > ${PROJECT_BINARY_DIR}/sable_verified.cpp
  DEPENDS ${PROJECT_SOURCE_DIR}/src/sable_verified.c ${SABLE_C_HEADER_FILES}
  )
add_custom_target (sable-isa DEPENDS ${PROJECT_BINARY_DIR}/sable_verified.cpp)
