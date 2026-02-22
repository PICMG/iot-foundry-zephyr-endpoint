/* pdr_utils.c - simple helpers for accessing builder-generated PDR data
 *
 * Minimal implementation to locate records inside the __pdr_data[] blob
 * produced by the iot_builder. This file is intentionally small and
 * relies on the macros emitted into config.h by the builder.
 */

#include "pdr_utils.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Builder-generated config.h declares extern __pdr_data[] and PDR_* macros. */
#include "config.h"

/* Define the per-record header size used by the builder (10 bytes). */
#ifndef PDR_HEADER_SIZE
#define PDR_HEADER_SIZE 10u
#endif

/* Compute repository bytes. Builder emits PDR_TOTAL_SIZE as payload-only; the
 * actual repository layout contains a per-record header. Use available macros
 * when present to compute the total repository size.
 */
size_t pdr_repo_bytes(void)
{
#ifdef PDR_TOTAL_SIZE
# ifdef PDR_NUMBER_OF_RECORDS
    return (size_t)PDR_TOTAL_SIZE + ((size_t)PDR_NUMBER_OF_RECORDS * PDR_HEADER_SIZE);
# else
    return (size_t)PDR_TOTAL_SIZE;
# endif
#else
    return 0;
#endif
}

bool pdr_read_record_at(size_t offset, uint32_t *handle, size_t *record_size)
{
    size_t repo = pdr_repo_bytes();
    if (repo == 0) return false;

    /* need at least a header's worth of bytes at offset */
    if (offset + PDR_HEADER_SIZE > repo) return false;

    /* __pdr_data is defined by the generated config.c; treat it as bytes */
    const uint8_t *base = (const uint8_t *)__pdr_data;

    uint32_t h = (uint32_t)base[offset] | ((uint32_t)base[offset+1] << 8) |
                 ((uint32_t)base[offset+2] << 16) | ((uint32_t)base[offset+3] << 24);
    uint16_t len = (uint16_t)base[offset + 8] | ((uint16_t)base[offset + 9] << 8);
    size_t recsz = (size_t)len + PDR_HEADER_SIZE;
    if (offset + recsz > repo) return false;
    if (handle) *handle = h;
    if (record_size) *record_size = recsz;
    return true;
}
