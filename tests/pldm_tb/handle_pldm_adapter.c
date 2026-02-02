#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <libpldm/pldm.h>
#include <libpldm/control.h>
#include "control-internal.h"

/* Test-only adapter: provide a `handle_pldm_message` symbol that mirrors
 * the behavior the higher-level code expects but delegates to the
 * existing `pldm_control_handle_msg`. This lets the test call
 * `handle_pldm_message(...)` without pulling in Zephyr or MCTP.
 */
int handle_pldm_message(struct pldm_control *control, const void *req_msg,
                        size_t req_len, void *resp_msg, size_t *resp_len)
{
    const struct pldm_msg *req = req_msg;
    struct pldm_header_info hdr;
    int rc = unpack_pldm_header(&req->hdr, &hdr);
    if (rc != PLDM_SUCCESS) return rc;
    /* If this is a BASE type request delegate to the control handler
     * which implements the real behavior. For other PLDM types (FRU,
     * PLATFORM, etc.) synthesize an ERROR_UNSUPPORTED_PLDM_CMD CC-only
     * response so JSON vectors can assert the expected protocol-level
     * completion code without pulling the full Zephyr stack into the
     * native test.
     */
    if (hdr.pldm_type == PLDM_BASE) {
        rc = pldm_control_handle_msg(control, req_msg, req_len, resp_msg, resp_len);
        if (rc == 0 && *resp_len >= 2 && resp_msg) {
            uint8_t *r = (uint8_t *)resp_msg;
            r[1] = (r[1] & 0xC0) | (hdr.pldm_type & 0x3F);
        }
        return rc;
    }

    /* Synthesize CC-only response for unsupported non-base types */
    if (resp_msg == NULL || resp_len == NULL || *resp_len < 4) {
        return -EOVERFLOW;
    }
    /* Pack header: instance (response), header byte (preserve header_ver=0)|type, command */
    uint8_t *r = (uint8_t *)resp_msg;
    r[0] = hdr.instance & 0x1F; /* instance in response */
    r[1] = hdr.pldm_type & 0x3F; /* header_ver=0 | type */
    r[2] = hdr.command;
    r[3] = PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
    *resp_len = 4;
    return 0;
}
