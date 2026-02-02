/* Minimal compatibility header for <uchar.h> when libc doesn't provide it.
 * This supplies `char16_t` and `char32_t` typedefs used by libpldm.
 */
#ifndef PLDM_CMAKE_COMPAT_UCHAR_H
#define PLDM_CMAKE_COMPAT_UCHAR_H

#include <stdint.h>

/* If the compiler already provides these types via __STDC_UTF_16__ etc.,
 * prefer the built-ins. Otherwise define them as fixed-width integers.
 */
#if !defined(__CHAR16_TYPE__)
typedef uint16_t char16_t;
#else
typedef __CHAR16_TYPE__ char16_t;
#endif

#if !defined(__CHAR32_TYPE__)
typedef uint32_t char32_t;
#else
typedef __CHAR32_TYPE__ char32_t;
#endif

#endif /* PLDM_CMAKE_COMPAT_UCHAR_H */
