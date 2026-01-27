/* Minimal native_posix test: stub `mctp_message_tx` to capture responses
 * in-memory and verify the control response fields. Keeps test focused and
 * avoids PTY/framing complexity.
 */

#include <zephyr/kernel.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "mctp_control.h"

static uint8_t capture_buf[512];
static size_t capture_len;

/* Dummy mctp instance shared by tests */
static struct mctp_bus test_bus;
static struct mctp test_mctp_inst;

/* Stub transport: capture outgoing payload into `capture_buf`. */
int mctp_message_tx(struct mctp *mctp, uint8_t remote_eid, bool tag_owner, uint8_t msg_tag, const void *msg, size_t msg_len)
{
    if (msg_len > sizeof(capture_buf)) return -1;
    memcpy(capture_buf, msg, msg_len);
    capture_len = msg_len;
    return 0;
}

/* Helper to send a request (raw buffer) and return captured completion code */
static int send_and_get_completion(struct mctp *mctp_ptr, const uint8_t *reqbuf, size_t reqlen)
{
    capture_len = 0;
    (void)send_control_message(mctp_ptr, 0x01, true, 0x01, reqbuf, reqlen);
    if (capture_len >= 4) {
        return (int)capture_buf[3];
    }
    return 0xff;
}

/* Compare the captured response to a known-good byte sequence. Returns 0 on match, 1 on mismatch. */
static int compare_capture(const uint8_t *expected, size_t expected_len, const char *name)
{
    if (capture_len != expected_len) {
        printf("%s: length mismatch actual=%zu expected=%zu\n", name, capture_len, expected_len);
        return 1;
    }
    if (memcmp(capture_buf, expected, expected_len) != 0) {
        printf("%s: content mismatch\n", name);
        /* print hex diff */
        printf(" got: ");
        for (size_t i = 0; i < capture_len; i++) printf("%02x ", capture_buf[i]);
        printf("\n exp: ");
        for (size_t i = 0; i < expected_len; i++) printf("%02x ", expected[i]);
        printf("\n");
        return 1;
    }
    printf("%s: PASS\n", name);
    return 0;
}

int main(void)
{
    int failures = 0;
    capture_len = 0;
    /* Construct a dummy mctp instance with one bus and an EID */
    test_bus.eid = 0x42;
    test_mctp_inst.n_busses = 1;
    test_mctp_inst.busses = &test_bus;

    /* Test 1: Get Endpoint ID (raw request bytes) */
    uint8_t get_req[] = { MCTP_CTRL_HDR_MSG_TYPE, 0x80, CONTROL_MSG_GET_ENDPOINT_ID };
    int comp = send_and_get_completion(&test_mctp_inst, get_req, sizeof(get_req));
    uint8_t expect_get[] = { 0x00, 0x00, CONTROL_MSG_GET_ENDPOINT_ID, CONTROL_COMPLETE_SUCCESS, 0x42, 0x00, 0x00 };
    if (comp != CONTROL_COMPLETE_SUCCESS) {
        printf("GET EID: unexpected completion %d\n", comp); failures++;
    } else {
        failures += compare_capture(expect_get, sizeof(expect_get), "GET EID");
    }

    /* Test 2: Set Endpoint ID valid (operation 0, endpoint 0x10) */
    uint8_t set_req[] = { MCTP_CTRL_HDR_MSG_TYPE, 0x80, CONTROL_MSG_SET_ENDPOINT_ID, 0x00, 0x10 };
    comp = send_and_get_completion(&test_mctp_inst, set_req, sizeof(set_req));
    uint8_t expect_set[] = { 0x00, 0x00, CONTROL_MSG_SET_ENDPOINT_ID, CONTROL_COMPLETE_SUCCESS, 0x00, 0x10, 0x00 };
    if (comp != CONTROL_COMPLETE_SUCCESS) {
        printf("SET EID: unexpected completion %d\n", comp); failures++;
    } else {
        failures += compare_capture(expect_set, sizeof(expect_set), "SET EID");
    }

    /* Verify new EID via Get */
    comp = send_and_get_completion(&test_mctp_inst, get_req, sizeof(get_req));
    uint8_t expect_get_after_set[] = { 0x00, 0x00, CONTROL_MSG_GET_ENDPOINT_ID, CONTROL_COMPLETE_SUCCESS, 0x10, 0x00, 0x00 };
    if (comp != CONTROL_COMPLETE_SUCCESS) { printf("GET after SET: unexpected completion %d\n", comp); failures++; }
    else { failures += compare_capture(expect_get_after_set, sizeof(expect_get_after_set), "GET EID after SET"); }

    /* Test 3: Set Endpoint ID invalid operation (operation=0x02) */
    uint8_t set_req_bad[] = { MCTP_CTRL_HDR_MSG_TYPE, 0x80, CONTROL_MSG_SET_ENDPOINT_ID, 0x02, 0x11 };
    comp = send_and_get_completion(&test_mctp_inst, set_req_bad, sizeof(set_req_bad));
    uint8_t expect_set_bad[] = { 0x00, 0x00, CONTROL_MSG_SET_ENDPOINT_ID, CONTROL_COMPLETE_INVALID_DATA };
    if (comp != CONTROL_COMPLETE_INVALID_DATA) { printf("SET EID invalid op: unexpected completion %d\n", comp); failures++; }
    else { failures += compare_capture(expect_set_bad, sizeof(expect_set_bad), "SET EID invalid op"); }

    /* Test 4: Get MCTP Version Support (msg_type 0xff for base) */
    uint8_t ver_req[] = { MCTP_CTRL_HDR_MSG_TYPE, 0x80, CONTROL_MSG_GET_MCTP_VERSION_SUPPORT, 0xff };
    comp = send_and_get_completion(&test_mctp_inst, ver_req, sizeof(ver_req));
    uint8_t expect_ver_header[] = { 0x00, 0x00, CONTROL_MSG_GET_MCTP_VERSION_SUPPORT, CONTROL_COMPLETE_SUCCESS, 0x04 };
    /* expected versions appended after header: 4 entries */
    uint8_t expect_ver_tail[] = { 0xf1, 0xf0, 0xff, 0x00,
                                  0xf1, 0xf1, 0xff, 0x00,
                                  0xf1, 0xf2, 0xff, 0x00,
                                  0xf1, 0xf3, 0xf1, 0x00 };
    if (comp != CONTROL_COMPLETE_SUCCESS) { printf("GET VERSION: unexpected completion %d\n", comp); failures++; }
    else {
        /* compare header first (as a prefix) and then the tail entries */
        size_t header_len = sizeof(expect_ver_header);
        size_t tail_len = sizeof(expect_ver_tail);
        if (capture_len < header_len + tail_len) {
            printf("GET VERSION: too short (%zu)\n", capture_len);
            failures++;
        } else {
            if (memcmp(capture_buf, expect_ver_header, header_len) != 0) {
                printf("GET VERSION header: content mismatch\n");
                printf(" got: "); for (size_t i = 0; i < header_len; i++) printf("%02x ", capture_buf[i]);
                printf("\n exp: "); for (size_t i = 0; i < header_len; i++) printf("%02x ", expect_ver_header[i]);
                printf("\n");
                failures++;
            } else {
                printf("GET VERSION header: PASS\n");
            }
            if (memcmp(capture_buf + header_len, expect_ver_tail, tail_len) != 0) {
                printf("GET VERSION entries: content mismatch\n");
                printf(" got: "); for (size_t i = 0; i < tail_len; i++) printf("%02x ", capture_buf[header_len + i]);
                printf("\n exp: "); for (size_t i = 0; i < tail_len; i++) printf("%02x ", expect_ver_tail[i]);
                printf("\n");
                failures++;
            } else {
                printf("GET VERSION entries: PASS\n");
            }
        }
    }

    /* Test 5: Get Message Type Support */
    uint8_t types_req[] = { MCTP_CTRL_HDR_MSG_TYPE, 0x80, CONTROL_MSG_GET_MESSAGE_TYPE_SUPPORT };
    comp = send_and_get_completion(&test_mctp_inst, types_req, sizeof(types_req));
    uint8_t expect_types[] = { 0x00, 0x00, CONTROL_MSG_GET_MESSAGE_TYPE_SUPPORT, CONTROL_COMPLETE_SUCCESS, 0x01, 0x00 };
    if (comp != CONTROL_COMPLETE_SUCCESS) { printf("GET TYPES: unexpected completion %d\n", comp); failures++; }
    else { failures += compare_capture(expect_types, sizeof(expect_types), "GET TYPES"); }

    /* Test 6: Unsupported command */
    uint8_t raw_hdr[3] = { MCTP_CTRL_HDR_MSG_TYPE, 0x80, 0x99 };
    comp = send_and_get_completion(&test_mctp_inst, raw_hdr, sizeof(raw_hdr));
    uint8_t expect_unsupported[] = { 0x00, 0x00, 0x99, CONTROL_COMPLETE_UNSUPPORTED_CMD };
    if (comp != CONTROL_COMPLETE_UNSUPPORTED_CMD) { printf("UNSUPPORTED CMD: unexpected completion %d\n", comp); failures++; }
    else { failures += compare_capture(expect_unsupported, sizeof(expect_unsupported), "UNSUPPORTED CMD"); }

    /* exit with non-zero if any failures occurred so CI can detect failures */
    if (failures) {
        printf("TESTS FAILED: %d\n", failures);
        exit(1);
    }
    printf("ALL TESTS PASSED\n");
    exit(0);
}
