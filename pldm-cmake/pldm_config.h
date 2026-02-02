/* Minimal config header to emulate Meson's generated config.h for libpldm
 * Provides ABI visibility macros used throughout the source.
 */
#ifndef PLDM_CMAKE_PLDM_CONFIG_H
#define PLDM_CMAKE_PLDM_CONFIG_H

/* Always expose stable ABI symbols */
#ifndef LIBPLDM_ABI_STABLE
#define LIBPLDM_ABI_STABLE __attribute__((visibility("default")))
#endif

/* Deprecated/testing macros: optionally attach a `deprecated` attribute so
 * uses of those APIs will emit a compiler warning when enabled via CMake.
 * The wrapper adds `-DPLDM_WARN_DEPRECATED=1` and/or
 * `-DPLDM_WARN_TESTING=1` to enable these warnings.
 */
#ifndef LIBPLDM_ABI_DEPRECATED
#  ifndef PLDM_WARN_DEPRECATED
#    define LIBPLDM_ABI_DEPRECATED __attribute__((visibility("default")))
#  else
#    define LIBPLDM_ABI_DEPRECATED __attribute__((visibility("default"))) __attribute__((deprecated("libpldm deprecated API")))
#  endif
#endif

#ifndef LIBPLDM_ABI_TESTING
#  ifndef PLDM_WARN_TESTING
#    define LIBPLDM_ABI_TESTING __attribute__((visibility("default")))
#  else
#    define LIBPLDM_ABI_TESTING __attribute__((visibility("default"))) __attribute__((deprecated("libpldm testing API")))
#  endif
#endif

/* Unsafe/deeply-deprecated APIs: enable with PLDM_WARN_DEPRECATED_UNSAFE
 * when building to cause uses to emit warnings.
 */
#ifndef LIBPLDM_ABI_DEPRECATED_UNSAFE
#  ifndef PLDM_WARN_DEPRECATED_UNSAFE
#    define LIBPLDM_ABI_DEPRECATED_UNSAFE __attribute__((visibility("default")))
#  else
#    define LIBPLDM_ABI_DEPRECATED_UNSAFE __attribute__((visibility("default"))) __attribute__((deprecated("libpldm deprecated-unsafe API")))
#  endif
#endif

#endif /* PLDM_CMAKE_PLDM_CONFIG_H */
