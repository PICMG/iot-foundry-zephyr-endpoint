/* Minimal limits compatibility header for libpldm builds.
 * Provides SSIZE_MAX fallback when the C library/headers for the
 * cross-compile target don't define it.
 */
#ifndef PLDM_COMPAT_LIMITS_H
#define PLDM_COMPAT_LIMITS_H

#include <limits.h>
#include <sys/types.h>

#ifndef SSIZE_MAX
# ifdef SIZE_MAX
#  include <stdint.h>
#  define SSIZE_MAX ((ssize_t)(SIZE_MAX >> 1))
# else
#  if defined(LLONG_MAX)
#    define SSIZE_MAX ((ssize_t)LLONG_MAX)
#  else
#    define SSIZE_MAX ((ssize_t)0x7fffffff)
#  endif
# endif
#endif

#ifndef INT_MIN
# include <stdint.h>
# if defined(INT32_MIN)
#  define INT_MIN INT32_MIN
# else
#  define INT_MIN (-2147483647 - 1)
# endif
#endif

#endif /* PLDM_COMPAT_LIMITS_H */
