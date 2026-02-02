/* Compatibility shim for <asm/byteorder.h> expected by libpldm.
 * Provides basic byte-order detection and byte-swap helpers using
 * compiler builtins where available.
 */
#ifndef PLDM_CMAKE_COMPAT_ASM_BYTEORDER_H
#define PLDM_CMAKE_COMPAT_ASM_BYTEORDER_H

#include <stdint.h>

/* Try to include system endian header if available */
#if defined(__has_include)
#  if __has_include(<endian.h>)
#    include <endian.h>
#  elif __has_include(<sys/endian.h>)
#    include <sys/endian.h>
#  endif
#endif

/* Define byte order macros if not defined by system headers */
#ifndef __LITTLE_ENDIAN
#  define __LITTLE_ENDIAN 1234
#endif
#ifndef __BIG_ENDIAN
#  define __BIG_ENDIAN 4321
#endif

#ifndef __BYTE_ORDER
#  if defined(__BYTE_ORDER__)
#    define __BYTE_ORDER __BYTE_ORDER__
#  elif defined(__ORDER_LITTLE_ENDIAN__)
#    define __BYTE_ORDER __ORDER_LITTLE_ENDIAN__
#  else
#    /* Fallback to little-endian on most embedded targets */
#    define __BYTE_ORDER __LITTLE_ENDIAN
#  endif
#endif

/* Define bitfield ordering macros expected by kernel-style headers used
 * by libpldm. If the toolchain doesn't provide them, set them based on
 * the detected byte order; default to little-endian for embedded targets.
 */
#if !defined(__LITTLE_ENDIAN_BITFIELD) && !defined(__BIG_ENDIAN_BITFIELD)
# if (__BYTE_ORDER == __LITTLE_ENDIAN)
#  define __LITTLE_ENDIAN_BITFIELD
# elif (__BYTE_ORDER == __BIG_ENDIAN)
#  define __BIG_ENDIAN_BITFIELD
# else
#  define __LITTLE_ENDIAN_BITFIELD
# endif
#endif

/* Byte-swap helpers */
#ifndef __swab16
#  define __swab16(x) ((uint16_t)__builtin_bswap16((uint16_t)(x)))
#endif
#ifndef __swab32
#  define __swab32(x) ((uint32_t)__builtin_bswap32((uint32_t)(x)))
#endif
#ifndef __swab64
#  define __swab64(x) ((uint64_t)__builtin_bswap64((uint64_t)(x)))
#endif

/* Conversion helpers: little-endian / big-endian to cpu and vice-versa */
#if __BYTE_ORDER == __LITTLE_ENDIAN
#  define le16_to_cpu(x) (x)
#  define cpu_to_le16(x) (x)
#  define le32_to_cpu(x) (x)
#  define cpu_to_le32(x) (x)
#  define le64_to_cpu(x) (x)
#  define cpu_to_le64(x) (x)

#  define be16_to_cpu(x) __swab16(x)
#  define cpu_to_be16(x) __swab16(x)
#  define be32_to_cpu(x) __swab32(x)
#  define cpu_to_be32(x) __swab32(x)
#  define be64_to_cpu(x) __swab64(x)
#  define cpu_to_be64(x) __swab64(x)
#else
#  define be16_to_cpu(x) (x)
#  define cpu_to_be16(x) (x)
#  define be32_to_cpu(x) (x)
#  define cpu_to_be32(x) (x)
#  define be64_to_cpu(x) (x)
#  define cpu_to_be64(x) (x)

#  define le16_to_cpu(x) __swab16(x)
#  define cpu_to_le16(x) __swab16(x)
#  define le32_to_cpu(x) __swab32(x)
#  define cpu_to_le32(x) __swab32(x)
#  define le64_to_cpu(x) __swab64(x)
#  define cpu_to_le64(x) __swab64(x)
#endif

#endif /* PLDM_CMAKE_COMPAT_ASM_BYTEORDER_H */
