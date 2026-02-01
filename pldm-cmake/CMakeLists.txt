cmake_minimum_required(VERSION 3.20)

# Wrapper to compile a subset of files from the libpldm submodule without
# invoking Meson. It creates a STATIC library target `libpldm` that other
# targets can link against. The list of source patterns can be overridden
# by setting the CMake cache variable `PLDM_SRC_PATTERNS` (semicolon-separated
# list of glob patterns).

set(PLDM_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../pldm")

# Compatibility include dir (absolute)
set(PLDM_COMPAT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/compat")

if(NOT DEFINED PLDM_SRC_PATTERNS)
  # Default selection: a small, commonly-needed set of C files. Adjust as
  # necessary for your use-case.
  set(PLDM_SRC_PATTERNS
    "${PLDM_ROOT}/src/bcd.c"
    "${PLDM_ROOT}/src/control.c"
    "${PLDM_ROOT}/src/edac.c"
    "${PLDM_ROOT}/src/responder.c"
    "${PLDM_ROOT}/src/utils.c"
    # include DSP helpers (header/decoder/encoder helpers) required by
    # control.c and other callers (e.g. unpack_pldm_header, encode_* / decode_*)
    "${PLDM_ROOT}/src/dsp/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/reent_stub.c"
  )
endif()

set(PLDM_SRCS)
foreach(pat IN LISTS PLDM_SRC_PATTERNS)
  file(GLOB matched "${pat}")
  list(APPEND PLDM_SRCS ${matched})
endforeach()

list(REMOVE_DUPLICATES PLDM_SRCS)

if(NOT PLDM_SRCS)
  message(FATAL_ERROR "pldm-cmake: no source files found for libpldm (check PLDM_SRC_PATTERNS)")
endif()

add_library(libpldm STATIC ${PLDM_SRCS})

# Prefer to inherit compile options and definitions from the Zephyr `app`
# target when this wrapper is added as a subdirectory of the application.
# This avoids hardcoding architecture-specific flags (like -mthumb) while
# ensuring libpldm is built with the same toolchain flags as the app.
if(TARGET app)
  target_compile_options(libpldm PUBLIC $<TARGET_PROPERTY:app,COMPILE_OPTIONS>)
  target_compile_definitions(libpldm PUBLIC $<TARGET_PROPERTY:app,COMPILE_DEFINITIONS>)
  message(STATUS "pldm-cmake: inheriting compile options/defs from 'app'")
else()
  message(STATUS "pldm-cmake: 'app' target not found; building libpldm with default CMake flags")
endif()

# Expose the upstream include directories so callers can include <pldm/...>
target_include_directories(libpldm
  PUBLIC
    ${PLDM_ROOT}/include
    ${PLDM_ROOT}/src
)

# Expose local compatibility headers (e.g., asm-generic/errno.h)
target_include_directories(libpldm
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/compat
)

# Also add compat dir to the global include path as a fallback so angle-
# bracket includes like <asm-generic/errno.h> resolve regardless of how the
# build system compiles the files.
include_directories(${PLDM_COMPAT_DIR})

# Force-include a minimal config header to provide ABI macros similar to
# the Meson-generated `config.h` used by libpldm. Also enable _GNU_SOURCE
# which libpldm expects for some headers.
# Options to control whether deprecated/testing APIs generate compiler warnings
option(PLDM_WARN_DEPRECATED "Emit warnings for deprecated libpldm APIs" ON)
option(PLDM_WARN_TESTING "Emit warnings for libpldm testing APIs" OFF)
option(PLDM_WARN_DEPRECATED_UNSAFE "Emit warnings for unsafe/deeply-deprecated libpldm APIs" OFF)

# Propagate selected feature toggles to the compile line so the header can
# decide whether to attach `deprecated` attributes to ABI macros.
if(PLDM_WARN_DEPRECATED)
  target_compile_definitions(libpldm PUBLIC PLDM_WARN_DEPRECATED=1)
endif()
if(PLDM_WARN_TESTING)
  target_compile_definitions(libpldm PUBLIC PLDM_WARN_TESTING=1)
endif()
if(PLDM_WARN_DEPRECATED_UNSAFE)
  target_compile_definitions(libpldm PUBLIC PLDM_WARN_DEPRECATED_UNSAFE=1)
endif()

# Force-include minimal config header and define _GNU_SOURCE
target_compile_options(libpldm PUBLIC -D_GNU_SOURCE -include ${CMAKE_CURRENT_SOURCE_DIR}/pldm_config.h)

message(STATUS "pldm-cmake: building libpldm from ${PLDM_SRCS}")
