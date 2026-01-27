cmake_minimum_required(VERSION 3.13.1)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(mctp_posix_uart_stub)

target_sources(app PRIVATE src/test_mctp_posix.c ../../src/mctp_control.c)
target_include_directories(app PRIVATE include ../../src)
target_compile_definitions(app PRIVATE MCTP_POSIX_UNIT_TEST=1)
