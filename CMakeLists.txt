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

file (GLOB C_SOURCES ${PROJECT_SOURCE_DIR}/src/*.c)

file (GLOB ASM_SOURCES ${PROJECT_SOURCE_DIR}/src/*.S)

set (CMAKE_EXE_LINKER_FLAGS
  "${CMAKE_EXE_LINKER_FLAGS} \
  -gc-sections \
  -Wl,--build-id=none \
  -T ${PROJECT_SOURCE_DIR}/src/sable.ld"
  )

add_executable (sable
  ${C_SOURCES}
  ${ASM_SOURCES}
  )

target_include_directories (sable PUBLIC
  "${PROJECT_SOURCE_DIR}/include/"
  "${PROJECT_BINARY_DIR}/include/"
  )
set_property (TARGET sable PROPERTY LINK_DEPENDS ${PROJECT_SOURCE_DIR}/src/sable.ld)

option (GENERATE_ISABELLE "Enable Isabelle/HOL code generation")

# Build the input file for Isabelle/HOL
# custom command and target to generate sable_isa.c
if (${GENERATE_ISABELLE})

find_package (PythonInterp 3.4 REQUIRED)

# NOTE: order of header files is very important, since we do not employ
# automatic dependency analysis
set (HEADER_FILES
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

file (MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/isabelle/intermediate)

# generate macro.h, which contains all header-defined macros
add_custom_command (
  OUTPUT ${PROJECT_BINARY_DIR}/isabelle/intermediate/macro.h
  COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/cat_macros.py ${HEADER_FILES}
    > ${PROJECT_BINARY_DIR}/isabelle/intermediate/macro.h
    DEPENDS ${HEADER_FILES}
  )

# generate all_sources.c, i.e. all source files, concatenated together
add_custom_command (
  OUTPUT ${PROJECT_BINARY_DIR}/isabelle/intermediate/all_sources.c
  COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/cat_c.py -n
    ${PROJECT_BINARY_DIR}/isabelle/intermediate/macro.h
    ${C_SOURCES}
    > ${PROJECT_BINARY_DIR}/isabelle/intermediate/all_sources.c
    DEPENDS ${PROJECT_BINARY_DIR}/isabelle/intermediate/macro.h ${C_SOURCES}
  )

# generate all_sources_pp.h, i.e. all source files concatenated together, preprocessed
add_custom_command (
  OUTPUT ${PROJECT_BINARY_DIR}/isabelle/intermediate/all_sources_pp.c
  COMMAND ${CMAKE_C_COMPILER} -E -DNDEBUG -DISABELLE
    -o ${PROJECT_BINARY_DIR}/isabelle/intermediate/all_sources_pp.c
    ${PROJECT_BINARY_DIR}/isabelle/intermediate/all_sources.c
    DEPENDS ${PROJECT_BINARY_DIR}/isabelle/intermediate/all_sources.c
  )

# generate all_headers.h, i.e. all source headers concatenated together
add_custom_command (
  OUTPUT ${PROJECT_BINARY_DIR}/isabelle/intermediate/all_headers.h
  COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/cat_c.py ${HEADER_FILES}
    > ${PROJECT_BINARY_DIR}/isabelle/intermediate/all_headers.h
    DEPENDS ${HEADER_FILES}
  )

# generate all_headers_pp.h, i.e. all source headers concatenated together, preprocessed
add_custom_command (
  OUTPUT ${PROJECT_BINARY_DIR}/isabelle/intermediate/all_headers_pp.h
  COMMAND ${CMAKE_C_COMPILER} -E -DNDEBUG -DISABELLE
    -o ${PROJECT_BINARY_DIR}/isabelle/intermediate/all_headers_pp.h
    ${PROJECT_BINARY_DIR}/isabelle/intermediate/all_headers.h
    DEPENDS ${PROJECT_BINARY_DIR}/isabelle/intermediate/all_headers.h
  )

# generate sable_isa.h
add_custom_command (
  OUTPUT ${PROJECT_BINARY_DIR}/isabelle/intermediate/sable_isa.h
  COMMAND ${PROJECT_BINARY_DIR}/tools/makeheaders/makeheaders
    ${PROJECT_BINARY_DIR}/isabelle/intermediate/all_sources_pp.c:${PROJECT_BINARY_DIR}/isabelle/intermediate/sable_isa.h
    ${PROJECT_BINARY_DIR}/isabelle/intermediate/all_headers_pp.h
  DEPENDS
    makeheaders
    ${PROJECT_BINARY_DIR}/isabelle/intermediate/all_headers_pp.h
    ${PROJECT_BINARY_DIR}/isabelle/intermediate/all_sources_pp.c
  )

# generate sable_isa_cat.c, which is the following concatenated together:
# sable_isa.h
# macro.h
# all_sources_pp.c
add_custom_command (
  OUTPUT ${PROJECT_BINARY_DIR}/isabelle/intermediate/sable_isa_cat.c
  COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/cat_c.py
    ${PROJECT_BINARY_DIR}/isabelle/intermediate/sable_isa.h
    ${PROJECT_BINARY_DIR}/isabelle/intermediate/macro.h
    ${PROJECT_BINARY_DIR}/isabelle/intermediate/all_sources_pp.c
    > ${PROJECT_BINARY_DIR}/isabelle/intermediate/sable_isa_cat.c
    DEPENDS
      ${PROJECT_BINARY_DIR}/isabelle/intermediate/sable_isa.h
      ${PROJECT_BINARY_DIR}/isabelle/intermediate/macro.h
      ${PROJECT_BINARY_DIR}/isabelle/intermediate/all_sources_pp.c
  )

# generate sable_isa.c
add_custom_command (
  OUTPUT ${PROJECT_BINARY_DIR}/isabelle/sable_isa.c
  COMMAND ${CMAKE_C_COMPILER} -E -DNDEBUG -DISABELLE
    -I${PROJECT_BINARY_DIR}/isabelle/intermediate/
    -o ${PROJECT_BINARY_DIR}/isabelle/sable_isa.c
    ${PROJECT_BINARY_DIR}/isabelle/intermediate/sable_isa_cat.c
  DEPENDS ${PROJECT_BINARY_DIR}/isabelle/intermediate/sable_isa_cat.c
  )
add_custom_target (sable-isa DEPENDS ${PROJECT_BINARY_DIR}/isabelle/sable_isa.c)

endif (${GENERATE_ISABELLE})
