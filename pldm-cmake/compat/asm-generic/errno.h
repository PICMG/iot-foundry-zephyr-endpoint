/* Compatibility header to satisfy includes of <asm-generic/errno.h>
 * Maps to the standard <errno.h> and defines missing codes used by
 * libpldm when building in Zephyr.
 */
#ifndef PLDM_CMAKE_COMPAT_ASM_GENERIC_ERRNO_H
#define PLDM_CMAKE_COMPAT_ASM_GENERIC_ERRNO_H

#include <errno.h>

/* Provide EUCLEAN if missing (common value on Linux is 117). */
#ifndef EUCLEAN
#define EUCLEAN 117
#endif

#endif /* PLDM_CMAKE_COMPAT_ASM_GENERIC_ERRNO_H */
