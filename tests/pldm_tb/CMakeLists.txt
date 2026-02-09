cmake_minimum_required(VERSION 3.20)
project(pldm_tb C)

file(GLOB TB_SRCS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.c)
# Exclude native-only test helper `test_fru.c` from the JSON-driven `pldm_tb` runner
list(REMOVE_ITEM TB_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/test_fru.c)
add_executable(pldm_tb ${TB_SRCS})

# Include libpldm headers from the tree
target_include_directories(pldm_tb PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../pldm/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../pldm/src
)

# Provide compatibility headers and force-include the minimal pldm config
target_include_directories(pldm_tb PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../pldm-cmake/compat
)
target_compile_options(pldm_tb PRIVATE -D_GNU_SOURCE -include ${CMAKE_CURRENT_SOURCE_DIR}/../../pldm-cmake/pldm_config.h)

# Always compile a minimal set of libpldm sources directly into this
# test binary to keep the native build minimal and self-contained.
set(MINIMAL_PLDM_SRCS
  ${CMAKE_CURRENT_SOURCE_DIR}/../../pldm/src/control.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../pldm/src/utils.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../pldm/src/bcd.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../pldm/src/dsp/base.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../pldm/src/dsp/fru.c
)
foreach(s ${MINIMAL_PLDM_SRCS})
  if(EXISTS "${s}")
    target_sources(pldm_tb PRIVATE ${s})
  endif()
endforeach()

# Include the built FRU table data so tests can access __fru_data
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../src/pdrs/config.c")
  target_sources(pldm_tb PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src/pdrs/config.c)
endif()

# Native FRU unit test: build as a separate executable so it can define its own main()
add_executable(test_fru ${CMAKE_CURRENT_SOURCE_DIR}/test_fru.c)
target_include_directories(test_fru PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../pldm/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../pldm/src
  ${CMAKE_CURRENT_SOURCE_DIR}/../../pldm-cmake/compat
)
target_compile_options(test_fru PRIVATE -D_GNU_SOURCE -include ${CMAKE_CURRENT_SOURCE_DIR}/../../pldm-cmake/pldm_config.h)

# Link minimal PLDM sources needed by test_fru (include edac.c and fru dsp)
set(TEST_PLDM_SRCS
  ${MINIMAL_PLDM_SRCS}
  ${CMAKE_CURRENT_SOURCE_DIR}/../../pldm/src/edac.c
)
foreach(s ${TEST_PLDM_SRCS})
  if(EXISTS "${s}")
    target_sources(test_fru PRIVATE ${s})
  endif()
endforeach()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../src/pdrs/config.c")
  target_sources(test_fru PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src/pdrs/config.c)
endif()

set_target_properties(test_fru PROPERTIES C_STANDARD 17)

set_target_properties(pldm_tb PROPERTIES C_STANDARD 17)
