cmake_minimum_required(VERSION 3.20)
project(pldm_tb C)

file(GLOB TB_SRCS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.c)
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
)
foreach(s ${MINIMAL_PLDM_SRCS})
  if(EXISTS "${s}")
    target_sources(pldm_tb PRIVATE ${s})
  endif()
endforeach()

set_target_properties(pldm_tb PROPERTIES C_STANDARD 17)
