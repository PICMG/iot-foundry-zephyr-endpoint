/* Minimal endian compatibility header for builds that lack <endian.h>
 * Provides htole16/le16toh and htole32/le32toh (and 64-bit) when missing.
 * This header is placed in pldm-cmake/compat and the wrapper already
 * adds that directory to the include path.
 */
#ifndef PLDM_COMPAT_ENDIAN_H
#define PLDM_COMPAT_ENDIAN_H

#include <stdint.h>

/* Prefer compiler-provided macros when available, otherwise provide
 * portable fallbacks based on __BYTE_ORDER__ / __ORDER_* macros.
 */

#ifndef htole16
# if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#  define htole16(x) ((uint16_t)(x))
#  define le16toh(x) ((uint16_t)(x))
# else
#  define htole16(x) (uint16_t)((((uint16_t)(x) & 0x00FFU) << 8) | (((uint16_t)(x) & 0xFF00U) >> 8))
#  define le16toh(x) htole16(x)
# endif
#endif

#ifndef htole32
# if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#  define htole32(x) ((uint32_t)(x))
#  define le32toh(x) ((uint32_t)(x))
# else
#  define htole32(x) (uint32_t)((((uint32_t)(x) & 0x000000FFU) << 24) |
+                                 (((uint32_t)(x) & 0x0000FF00U) << 8)  |
+                                 (((uint32_t)(x) & 0x00FF0000U) >> 8)  |
+                                 (((uint32_t)(x) & 0xFF000000U) >> 24))
#  define le32toh(x) htole32(x)
# endif
#endif

#ifndef htole64
# if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#  define htole64(x) ((uint64_t)(x))
#  define le64toh(x) ((uint64_t)(x))
# else
#  define htole64(x) (uint64_t)((((uint64_t)(x) & 0x00000000000000FFULL) << 56) |
+                                   (((uint64_t)(x) & 0x000000000000FF00ULL) << 40) |
+                                   (((uint64_t)(x) & 0x0000000000FF0000ULL) << 24) |
+                                   (((uint64_t)(x) & 0x00000000FF000000ULL) << 8)  |
+                                   (((uint64_t)(x) & 0x000000FF00000000ULL) >> 8)  |
+                                   (((uint64_t)(x) & 0x0000FF0000000000ULL) >> 24) |
+                                   (((uint64_t)(x) & 0x00FF000000000000ULL) >> 40) |
+                                   (((uint64_t)(x) & 0xFF00000000000000ULL) >> 56))
#  define le64toh(x) htole64(x)
# endif
#endif

#endif /* PLDM_COMPAT_ENDIAN_H */
