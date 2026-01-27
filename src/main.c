/**
 * @file main.c
 * @brief Zephyr Endpoint for IoT-Foundry project
 * This is a simple MCTP endpoint implementation using Zephyr RTOS.
 * It uses MCTP over UART for communication and handles basic
 * MCTP control messages such as Get Endpoint ID.
 * @author Doug Sandy
 * @date January 2026
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <zephyr/kernel.h>
#include <zephyr/types.h>
#include <zephyr/pmci/mctp/mctp_uart.h>
#include <libmctp.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/logging/log.h>
#include "mctp_control.h"

LOG_MODULE_REGISTER(mctp_endpoint, LOG_LEVEL_DBG);

/* Duplicate of libmctp control header structures/macros.
 * These are intentionally local copies for development/testing when
 * the upstream libmctp headers are not available on the include path.
 */
struct mctp_ctrl_msg_hdr {
	uint8_t ic_msg_type;
	uint8_t rq_dgram_inst;
	uint8_t command_code;
} __packed;

#define MCTP_CTRL_HDR_MSG_TYPE	       0
#define MCTP_CTRL_HDR_FLAG_REQUEST     (1 << 7)
#define MCTP_CTRL_HDR_FLAG_DGRAM       (1 << 6)
#define MCTP_CTRL_HDR_INSTANCE_ID_MASK 0x1F

#define ECHO_Q_DEPTH 4
#define RX_BUF_SZ 256

struct echo_msg {
	uint8_t remote_eid;
	uint8_t destination_eid;
	bool tag_owner;
	uint8_t msg_tag;
	size_t len;
	uint8_t data[RX_BUF_SZ];
};

// message queue for received echo messages
K_MSGQ_DEFINE(echo_q, sizeof(struct echo_msg), ECHO_Q_DEPTH, 4);

// define the MCTP UART binding
MCTP_UART_DT_DEFINE(mctp_endpoint, DEVICE_DT_GET(DT_NODELABEL(arduino_serial)));

/**
 * @brief MCTP receive message handler
 * Handles incoming MCTP messages by enqueueing them for processing.
 * @param remote_eid The source endpoint ID of the message sender.
 * @param tag_owner The tag owner bit of the message.
 * @param msg_tag The message tag of the message.
 * @param data Pointer to user data (not used).
 * @param msg Pointer to the full message including header.
 * @param len Length of the message in bytes.
 */
static void rx_message(uint8_t remote_eid, bool tag_owner, uint8_t msg_tag, void *data, void *msg, size_t len)
{
	struct echo_msg emsg;

	// ignore non requests
	if (!tag_owner) {
		return;
	}

	emsg.remote_eid = remote_eid;
	emsg.tag_owner = !tag_owner; /* reply toggles tag owner */
	emsg.msg_tag = msg_tag;
	emsg.len = MIN(len, (size_t)RX_BUF_SZ);
	if (msg && emsg.len) {
		memcpy(emsg.data, msg, emsg.len);
	}

	k_msgq_put(&echo_q, &emsg, K_NO_WAIT); 
}

/**
 * @brief Main function
 * Initializes MCTP over UART and enters the main processing loop.
 */
int main(void)
{
	LOG_INF("mctp_endpoint: main() start");

	mctp_set_alloc_ops(malloc, free, realloc);
	
	struct mctp *mctp_ctx = mctp_init(); 
	__ASSERT_NO_MSG(mctp_ctx != NULL);

	// set the mctp bus binding for our uart - initial EID 0x00 (unconfigured)
	mctp_register_bus(mctp_ctx, &mctp_endpoint.binding, 0x00);
	
	// set the default rx message handler
	mctp_set_rx_all(mctp_ctx, rx_message, NULL);

	/* MCTP poll loop: dequeue echo messages and send replies from thread context */
	mctp_uart_start_rx(&mctp_endpoint);

	struct echo_msg em;
	while (true) {
		if (k_msgq_get(&echo_q, &em, K_FOREVER) == 0) {
			LOG_DBG("dequeued echo for eid %d len %zu tag %u", em.remote_eid, em.len, em.msg_tag);
		
			const struct mctp_ctrl_msg_hdr *hdr = (const struct mctp_ctrl_msg_hdr *)em.data;
			if ((em.len >= sizeof(struct mctp_ctrl_msg_hdr)) && 
				(hdr->ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE)) {
				// this is a control message - process it
				LOG_DBG("Control message: type %u", hdr->command_code); k_msleep(1000);
				int ret = send_control_message(mctp_ctx, em.remote_eid, em.tag_owner, em.msg_tag, em.data, em.len);
				if (ret) {
					LOG_DBG("send_control_message failed: %d", ret);
				}
			} else {
				LOG_WRN("message not a control message, dropping");
				continue;
			}			
		}
	}

	return 0;
}
