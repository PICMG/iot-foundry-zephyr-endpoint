/* Minimal errno compatibility header for libpldm builds on platforms
 * that don't define all Linux errno values. This header is intended to be
 * included via the wrapper's include path so existing source can use
 * POSIX errno names like EUCLEAN.
 */
#ifndef PLDM_COMPAT_ERRNO_H
#define PLDM_COMPAT_ERRNO_H

#include <errno.h>

#ifndef EUCLEAN
/* EUCLEAN (structure needs cleaning) is defined on Linux as 117 on many
 * architectures. If errno.h doesn't provide it, choose a value unlikely to
 * collide with other platform-specific errors. Adjust if your platform
 * reserves a different value.
 */
#define EUCLEAN 117
#endif

#ifndef EINVAL
/* Invalid argument (standard POSIX value) */
#define EINVAL 22
#endif

#ifndef EPROTO
/* Protocol error (Linux common value) */
#define EPROTO 71
#endif

#ifndef EOVERFLOW
/* Value too large for defined data type (common Linux value) */
#define EOVERFLOW 75
#endif

#ifndef EBADMSG
/* Bad message (protocol error parsing message contents) */
#define EBADMSG 77
#endif

#ifndef ENOTSUP
/* Operation not supported (often aliased to EOPNOTSUPP on some systems) */
#define ENOTSUP 95
#endif

#ifndef ENOMSG
/* No message of desired type (POSIX value) */
#define ENOMSG 42
#endif

#ifndef ENOMEM
/* Out of memory (standard POSIX value) */
#define ENOMEM 12
#endif

#ifndef ENOENT
/* No such file or directory (standard POSIX value) */
#define ENOENT 2
#endif

#ifndef ENOSPC
/* No space left on device (standard POSIX value) */
#define ENOSPC 28
#endif

#ifndef EBUSY
/* Device or resource busy (standard POSIX value) */
#define EBUSY 16
#endif

#ifndef ENOSYS
/* Function not implemented (standard POSIX value) */
#define ENOSYS 38
#endif

#endif /* PLDM_COMPAT_ERRNO_H */
