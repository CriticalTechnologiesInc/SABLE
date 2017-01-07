cmake_minimum_required (VERSION 2.8)
project (SABLE C ASM)
set (SABLE_VERSION_MAJOR 0)
set (SABLE_VERSION_MINOR 2)

configure_file (
  "${PROJECT_SOURCE_DIR}/include/version.h.in"
  "${PROJECT_BINARY_DIR}/include/version.h"
  )
include_directories (
  "${PROJECT_SOURCE_DIR}/include/"
  "${PROJECT_BINARY_DIR}/include/"
  )

set (CMAKE_C_FLAGS
  "${CMAKE_C_FLAGS} \
  -Wall \
  -Werror \
  -Wno-main \
  -fno-builtin \
  -nostdlib \
  -fno-stack-protector \
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

add_definitions (
  "-DEXEC"
  )

set (CMAKE_ASM_FLAGS ${CMAKE_C_FLAGS})

set (CMAKE_EXE_LINKER_FLAGS
  "${CMAKE_EXE_LINKER_FLAGS} \
  -gc-sections \
  -Wl,--build-id=none \
  -T ${PROJECT_SOURCE_DIR}/src/sable.ld"
  )

add_executable (sable
  src/sable.ld
  src/alloc.c
  src/asm.S
  src/dev.c
  src/elf.c
  src/hmac.c
  src/keyboard.c
  src/mp.c
  src/sha.c
  src/string.c
  src/tis.c
  src/tpm.c
  src/tpm_error.c
  src/util.c
  src/sable.c
  )
