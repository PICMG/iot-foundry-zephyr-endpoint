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

  # -- iot_builder strict invocation (non-negotiable requirements) --
  # Per project policy: when PLDM is enabled we must run a compiled
  # iot_builder binary and fail configure immediately on any missing
  # artifact. The README documents building the host tool into
  # build-host/iot_builder/iot_builder — use that exact path.
  set(IOT_BUILDER_BIN ${CMAKE_CURRENT_SOURCE_DIR}/build-host/iot_builder/iot_builder)
  if(NOT EXISTS "${IOT_BUILDER_BIN}")
    message(FATAL_ERROR "INCLUDE_PLDM requested but iot_builder binary not found at ${IOT_BUILDER_BIN}. Build it per README before running Zephyr build.")
  endif()

  # Determine the required input JSON: it must exactly match the overlay/.conf
  # filename used for the build. Use BOARD or ZEPHYR_BOARD and normalize
  # slashes to underscores to form the basename (exact match required).
  # Prefer the full Zephyr board identifier when available; it typically
  # contains the qualified name (e.g. vendor/part/variant). Use that to
  # produce an underscore-joined basename per policy. If ZEPHYR_BOARD is
  # not set, fall back to BOARD but still require exact matching.
  # Select which variable to use per policy:
  # - If ZEPHYR_BOARD contains '/', use it (no fallback to BOARD).
  # - Else if BOARD contains '/', use BOARD.
  # - Else if ZEPHYR_BOARD is defined, use it as-is.
  # - Else if BOARD is defined, use it as-is.
  # - Otherwise fatal.
  # Use BOARD if present, else fall back to ZEPHYR_BOARD. Then, if the chosen
  # value contains '/', replace '/' with '_' to create the JSON basename.
  if(DEFINED BOARD)
    set(IOT_BOARD_RAW ${BOARD})
  elseif(DEFINED ZEPHYR_BOARD)
    set(IOT_BOARD_RAW ${ZEPHYR_BOARD})
  else()
    message(FATAL_ERROR "INCLUDE_PLDM requested but neither BOARD nor ZEPHYR_BOARD is defined; cannot determine boards/<name>.json")
  endif()

  # If the chosen value contains '/', convert tokens to underscores; otherwise use unchanged.
  string(FIND "${IOT_BOARD_RAW}" "/" _has_slash)
  if(NOT _has_slash EQUAL -1)
    # Split the qualified board identifier into parts.
    string(REPLACE "/" ";" _iot_parts ${IOT_BOARD_RAW})
    list(LENGTH _iot_parts _iot_parts_count)

    # If BOARD_DIR is available, use its basename as the vendor prefix
    # and join the remaining BOARD tokens with underscores. This yields
    # names like vendor_part_variant -> nrf54l15dk_nrf54l15_cpuapp.
    if(DEFINED BOARD_DIR)
      get_filename_component(_board_dir_basename ${BOARD_DIR} NAME)
      list(GET _iot_parts 0 _first_part)
      if(_first_part STREQUAL _board_dir_basename)
        list(REMOVE_AT _iot_parts 0)
        if(_iot_parts)
          list(JOIN _iot_parts "_" _rest)
          set(IOT_BOARD_BASENAME ${_board_dir_basename}_${_rest})
        else()
          set(IOT_BOARD_BASENAME ${_board_dir_basename})
        endif()
      else()
        # If the first token doesn't match the BOARD_DIR basename, join all parts.
        list(JOIN _iot_parts "_" IOT_BOARD_BASENAME)
      endif()
    else()
      # No BOARD_DIR available; join all parts as a fallback.
      list(JOIN _iot_parts "_" IOT_BOARD_BASENAME)
    endif()
  else()
    set(IOT_BOARD_BASENAME ${IOT_BOARD_RAW})
  endif()
  message(STATUS "IOT_BOARD_RAW='${IOT_BOARD_RAW}'")
  message(STATUS "IOT_BOARD_BASENAME='${IOT_BOARD_BASENAME}'")
  set(IOT_BUILDER_INPUT ${CMAKE_CURRENT_SOURCE_DIR}/boards/${IOT_BOARD_BASENAME}.json)
  if(NOT EXISTS "${IOT_BUILDER_INPUT}")
    # If the exact basename file is missing, and the original BOARD value
    # did not contain slashes, attempt to locate a single candidate that
    # starts with the board dirname as a prefix (e.g. nrf54l15dk_*.json).
    string(FIND "${IOT_BOARD_RAW}" "/" _orig_has_slash)
    if(_orig_has_slash EQUAL -1)
      file(GLOB _iot_candidates RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}/boards "${CMAKE_CURRENT_SOURCE_DIR}/boards/${IOT_BOARD_RAW}_*.json")
      list(LENGTH _iot_candidates _cnt)
      if(_cnt EQUAL 1)
        list(GET _iot_candidates 0 _sel)
        set(IOT_BUILDER_INPUT ${CMAKE_CURRENT_SOURCE_DIR}/boards/${_sel})
        message(STATUS "Selected builder input via single-prefix match: ${IOT_BUILDER_INPUT}")
      else()
        message(FATAL_ERROR "INCLUDE_PLDM requested but required input JSON not found: ${IOT_BUILDER_INPUT} (also found ${_cnt} prefix candidates)")
      endif()
    else()
      message(FATAL_ERROR "INCLUDE_PLDM requested but required input JSON not found: ${IOT_BUILDER_INPUT}")
    endif()
  endif()

  # Ensure output directory exists and run the builder at configure time.
  file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/pldms)
  execute_process(
    COMMAND "${IOT_BUILDER_BIN}" "${IOT_BUILDER_INPUT}" "${CMAKE_CURRENT_SOURCE_DIR}/src/pdrs/"
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    RESULT_VARIABLE _IOT_BUILDER_EXIT
    OUTPUT_VARIABLE _IOT_BUILDER_OUT
    ERROR_VARIABLE _IOT_BUILDER_ERR
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_STRIP_TRAILING_WHITESPACE
  )
  if(NOT _IOT_BUILDER_EXIT EQUAL 0)
    message(FATAL_ERROR "iot_builder failed (exit ${_IOT_BUILDER_EXIT}): ${_IOT_BUILDER_ERR}")
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