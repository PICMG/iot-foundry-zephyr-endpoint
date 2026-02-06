# Copyright (c) 2026 PICMG

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(iot_foundry_zephyr_endpoint)

zephyr_syscall_include_directories(include)
zephyr_include_directories(include)

# Option to include PLDM support (use -DINCLUDE_PLDM=ON to enable)
option(INCLUDE_PLDM "Enable building and linking libpldm" OFF)

message(STATUS "INCLUDE_PLDM=${INCLUDE_PLDM}")

target_sources(app PRIVATE src/main.c src/mctp_control.c)

# Option to build host-only tools (like iot_builder). Disabled by default.
option(BUILD_HOST_TOOLS "Build host-only tools (not for cross/Zephyr builds)" OFF)

if(INCLUDE_PLDM)
  # Expose the option to the C compiler so `#ifdef INCLUDE_PLDM` works
  target_compile_definitions(app PRIVATE INCLUDE_PLDM=1)
  # Prefer a lightweight CMake wrapper shipped in the superproject that
  # compiles selected libpldm sources. If not present, fall back to the
  # upstream `pldm` directory (which uses Meson and may not be usable here).
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/pldm-cmake/CMakeLists.txt")
    add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/pldm-cmake")
  elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/pldm/CMakeLists.txt")
    add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/pldm")
  endif()

  if(TARGET libpldm)
    target_link_libraries(app PRIVATE libpldm)
  elseif(TARGET pldm)
    target_link_libraries(app PRIVATE pldm)
  endif()

  # Add platform handler sources and FRU implementation into the Zephyr app
  # when PLDM support is enabled. Use CONFIGURE_DEPENDS so CMake re-globs
  # when files are added/removed during development.
  file(GLOB PLATFORM_SRCS CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/src/process_pldm.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/platform_*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/fru.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/build_timestamp.c
  )
  if(PLATFORM_SRCS)
    target_sources(app PRIVATE ${PLATFORM_SRCS})
  endif()
endif()

# after project(...) include the platform-specific PDR source files
if(INCLUDE_PLDM)
    file(GLOB PDR_SRCS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/pdrs/*.c)
    if(PDR_SRCS)
    target_sources(app PRIVATE ${PDR_SRCS})
    endif()
endif()

# If requested, build host tools (iot_builder) for native Linux only
if(BUILD_HOST_TOOLS AND NOT CMAKE_CROSSCOMPILING)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tools/iot_builder/CMakeLists.txt")
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tools/iot_builder ${CMAKE_BINARY_DIR}/tools/iot_builder_build)
    if(TARGET iot_builder)
      # Ensure the Zephyr app depends on generator outputs if the tool provides a gen target
      if(TARGET iot_builder_gen)
        add_dependencies(app iot_builder_gen)
      endif()
    endif()
  endif()
endif()