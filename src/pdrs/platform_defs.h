/**
 * @file platfform_defs.h
 * @brief Platform-specific type definitions for PICMG IoT firmware
 * This header provides platform-specific type definitions and macros
 * used by the auto-generated firmware builder code for IoT devices.
 * These macros may be overridden by platform-specific headers to or
 * build-time definitions to suit the target environment.
 * @author Doug Sandy
 * @date January 2026
 * 
 * SPDX-License-Identifier: Apache-2.0 
 */
#pragma once
#include <stdint.h>

#ifndef PDR_BYTE_TYPE
#define PDR_BYTE_TYPE const uint8_t
#endif

#ifndef PDR_DATA_ATTRIBUTES
#define PDR_DATA_ATTRIBUTES __attribute__((aligned(1), section(".pdr_data")))
#endif

#ifndef FRU_BYTE_TYPE
#define FRU_BYTE_TYPE const uint8_t
#endif

#ifndef FRU_DATA_ATTRIBUTES
#define FRU_DATA_ATTRIBUTES __attribute__((aligned(1), section(".pdr_data")))
#endif

#ifndef LINTABLE_TYPE
#define LINTABLE_TYPE const int32_t
#endif

#ifndef LINTABLE_DATA_ATTRIBUTES
#define LINTABLE_DATA_ATTRIBUTES __attribute__((aligned(1), section(".pdr_data")))
#endif
