/* Minimal libmctp stub for unit tests (test-only). Placed under the test
 * include dir so it does not override the real library header when that
 * module is present in the workspace.
 */
#ifndef LIBMCTP_H
#define LIBMCTP_H

#include <stdint.h>

typedef uint8_t mctp_eid_t;

#define MCTP_EID_NULL 0x00
#define MCTP_EID_BROADCAST 0xFF

#endif /* LIBMCTP_H */
