#include <stdio.h>
#include <zephyr/types.h>
#include <libmctp.h>
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include <string.h>
#include <libpldm/base.h>
#include <libpldm/platform.h>
#include <libpldm/control.h>
#include <libpldm/fru.h>
#include <libpldm/pdr.h>
#include <../pldm/src/control-internal.h>
#include "pdrs/config.h"
#include "mctp_control.h"

LOG_MODULE_REGISTER(process_pldm, LOG_LEVEL_DBG);

static struct pldm_pdr *pdr_repo = NULL;
static struct pldm_pdr *fru_repo = NULL;
static struct pldm_control pldm_control_ctx;

#ifndef PLDM_RX_BUF_SZ
#define PLDM_RX_BUF_SZ 512
#endif
uint8_t pldm_rx_buf[PLDM_RX_BUF_SZ];

/**
 * SUPPORTED VERSIONS AND COMMANDS
 */
#define PLDM_FRU_VERSIONS_COUNT 1
static const uint32_t PLDM_FRU_VERSIONS[PLDM_FRU_VERSIONS_COUNT+1] = {
	/* PLDM 1.1.0 is current implemented. */
	0xf2f0f000,
	/* CRC. Calculated with python:
	hex(crccheck.crc.Crc32.calc(struct.pack('<I', 0xf2f0f000)))
	*/
	0xD38FDE41
};

const bitfield8_t PLDM_FRU_COMMANDS[32] = {
	{ .byte = (1 << PLDM_GET_FRU_RECORD_TABLE_METADATA | 1 << PLDM_GET_FRU_RECORD_TABLE |
		   1 << PLDM_SET_FRU_RECORD_TABLE | 1 << PLDM_GET_FRU_RECORD_BY_OPTION) }
};
#define PLDM_PLATFORM_VERSIONS_COUNT 1
static const uint32_t PLDM_PLATFORM_VERSIONS[PLDM_PLATFORM_VERSIONS_COUNT+1] = {
	/* PLDM 1.1.0 is current implemented. */
	0xf1f3f000,
	/* CRC. Calculated with python:
	hex(crccheck.crc.Crc32.calc(struct.pack('<I', 0xf1f3f000)))
	*/
	0x61ABDC38
};

/* Build a 32-byte command bitmap where command N sets bit (N%8) in byte N/8.
 * Use designated initializers so the table is constant and clear at compile time.
 */
const bitfield8_t PLDM_PLATFORM_COMMANDS[32] = {
	/* byte 0: commands 0x00..0x07 */
	[0] = { .byte = (uint8_t)(
		(1U << (PLDM_GET_TERMINUS_UID & 7)) |
		(1U << (PLDM_SET_EVENT_RECEIVER & 7)) |
		(1U << (PLDM_GET_EVENT_RECEIVER & 7))
	) },

	/* byte 1: commands 0x08..0x0f */
	[1] = { .byte = (uint8_t)(
		(1U << (PLDM_PLATFORM_EVENT_MESSAGE & 7)) |
		(1U << (PLDM_POLL_FOR_PLATFORM_EVENT_MESSAGE & 7)) |
		(1U << (PLDM_EVENT_MESSAGE_SUPPORTED & 7)) |
		(1U << (PLDM_EVENT_MESSAGE_BUFFER_SIZE & 7))
	) },

	/* byte 2: commands 0x10..0x17 */
	[2] = { .byte = (uint8_t)(
		(1U << (PLDM_SET_NUMERIC_SENSOR_ENABLE & 7)) |
		(1U << (PLDM_GET_SENSOR_READING & 7)) |
		(1U << (PLDM_GET_SENSOR_THRESHOLDS & 7)) |
		(1U << (PLDM_SET_SENSOR_THRESHOLDS & 7)) |
		(1U << (PLDM_RESTORE_SENSOR_THRESHOLDS & 7)) |
		(1U << (PLDM_GET_SENSOR_HYSTERESIS & 7)) |
		(1U << (PLDM_SET_SENSOR_HYSTERESIS & 7)) |
		(1U << (PLDM_INIT_NUMERIC_SENSOR & 7))
	) },

	/* byte 4: commands 0x20..0x27 */
	[4] = { .byte = (uint8_t)(
		(1U << (PLDM_SET_STATE_SENSOR_ENABLES & 7)) |
		(1U << (PLDM_GET_STATE_SENSOR_READINGS & 7)) |
		(1U << (PLDM_INIT_STATE_SENSOR & 7))
	) },

	/* byte 6: commands 0x30..0x37 */
	[6] = { .byte = (uint8_t)(
		(1U << (PLDM_SET_NUMERIC_EFFECTER_ENABLE & 7)) |
		(1U << (PLDM_SET_NUMERIC_EFFECTER_VALUE & 7)) |
		(1U << (PLDM_GET_NUMERIC_EFFECTER_VALUE & 7))
	) },

	/* byte 7: commands 0x38..0x3f */
	[7] = { .byte = (uint8_t)(
		(1U << (PLDM_SET_STATE_EFFECTER_ENABLES & 7)) |
		(1U << (PLDM_SET_STATE_EFFECTER_STATES & 7)) |
		(1U << (PLDM_GET_STATE_EFFECTER_STATES & 7))
	) },

	/* byte 8: commands 0x40..0x47 */
	[8] = { .byte = (uint8_t)(
		(1U << (PLDM_GET_PLDM_EVENT_LOG_INFO & 7)) |
		(1U << (PLDM_ENABLE_PLDM_EVENT_LOGGING & 7)) |
		(1U << (PLDM_CLEAR_PLDM_EVENT_LOG & 7)) |
		(1U << (PLDM_GET_PLDM_EVENT_LOG_TIMESTAMP & 7)) |
		(1U << (PLDM_SET_PLDM_EVENT_LOG_TIMESTAMP & 7)) |
		(1U << (PLDM_READ_PLDM_EVENT_LOG & 7)) |
		(1U << (PLDM_GET_PLDM_EVENT_LOG_POLICY_INFO & 7)) |
		(1U << (PLDM_SET_PLDM_EVENT_LOG_POLICY & 7))
	) },

	/* byte 9: commands 0x48..0x4f */
	[9] = { .byte = (uint8_t)(
		(1U << (PLDM_FIND_PLDM_EVENT_LOG_ENTRY & 7))
	) },

	/* byte 10: commands 0x50..0x57 */
	[10] = { .byte = (uint8_t)(
		(1U << (PLDM_GET_PDR_REPOSITORY_INFO & 7)) |
		(1U << (PLDM_GET_PDR & 7)) |
		(1U << (PLDM_FIND_PDR & 7)) |
		(1U << (PLDM_GET_PDR_REPOSITORY_SIGNATURE & 7))
	) },

	/* byte 11: commands 0x58..0x5f */
	[11] = { .byte = (uint8_t)(
		(1U << (PLDM_RUN_INIT_AGENT & 7))
	) }
};

int handle_platform_get_terminus_uid(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_set_event_receiver(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_get_event_receiver(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_platform_event_message(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_poll_for_platform_event_message(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_event_message_supported(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_event_message_buffer_size(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_set_numeric_sensor_enable(struct pldm_header_info *hdr, const void *req_msg,	 size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_get_sensor_reading(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_get_sensor_thresholds(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_set_sensor_thresholds(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_restore_sensor_thresholds(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_get_sensor_hysteresis(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_set_sensor_hysteresis(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_init_numeric_sensor(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_set_state_sensor_enables(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_get_state_sensor_readings(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_init_state_sensor(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_set_numeric_effecter_enable(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_set_numeric_effecter_value(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_get_numeric_effecter_value(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_set_state_effecter_enables(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_set_state_effecter_states(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_get_state_effecter_states(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_get_pldm_event_log_info(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_enable_pldm_event_logging(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_clear_pldm_event_log(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_get_pldm_event_log_timestamp(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_set_pldm_event_log_timestamp(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_read_pldm_event_log(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_get_pldm_event_log_policy_info(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_set_pldm_event_log_policy(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_find_pldm_event_log_entry(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_get_pdr_repository_info(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_get_pdr(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_find_pdr(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_run_init_agent(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_get_pdr_repository_signature(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}


/**
 * @brief Handle an incoming platform message.
 * 
 * This function processes an incoming platform message and generates
 * the appropriate response.
 * 
 * @param req_msg Pointer to the incoming PLDM request message.
 * @param req_len Length of the incoming PLDM request message.
 * @param resp_msg Pointer to the buffer for the PLDM response message.
 * @param resp_len Pointer to the length of the response buffer; updated with actual response length.
 * @return 0 on success, non-zero on failure.
 */
int handle_platform_msg(const void *req_msg, size_t req_len, void *resp_msg, size_t *resp_len)
{
	/* is there room in the response buffer for the header plus completion code */
	if (*resp_len < sizeof(struct pldm_msg_hdr) + 1) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

    // extract the request header
	const struct pldm_msg *msg_hdr = req_msg;
	struct pldm_header_info hdr;
	int rc = unpack_pldm_header(&msg_hdr->hdr, &hdr); // unpack bitfields into our struct
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	/* handle each command */
	switch (hdr.command) {
	case PLDM_GET_TERMINUS_UID:
		rc = handle_platform_get_terminus_uid(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_SET_EVENT_RECEIVER:
		rc = handle_platform_set_event_receiver(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_GET_EVENT_RECEIVER:
		rc = handle_platform_get_event_receiver(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_PLATFORM_EVENT_MESSAGE:
		rc = handle_platform_platform_event_message(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_POLL_FOR_PLATFORM_EVENT_MESSAGE:
		rc = handle_platform_poll_for_platform_event_message(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_EVENT_MESSAGE_SUPPORTED:
		rc = handle_platform_event_message_supported(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_EVENT_MESSAGE_BUFFER_SIZE:
		rc = handle_platform_event_message_buffer_size(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_SET_NUMERIC_SENSOR_ENABLE:
		rc = handle_platform_set_numeric_sensor_enable(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_GET_SENSOR_READING:
		rc = handle_platform_get_sensor_reading(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_GET_SENSOR_THRESHOLDS:
		rc = handle_platform_get_sensor_thresholds(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_SET_SENSOR_THRESHOLDS:
		rc = handle_platform_set_sensor_thresholds(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_RESTORE_SENSOR_THRESHOLDS:
		rc = handle_platform_restore_sensor_thresholds(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_GET_SENSOR_HYSTERESIS:
		rc = handle_platform_get_sensor_hysteresis(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_SET_SENSOR_HYSTERESIS:
		rc = handle_platform_set_sensor_hysteresis(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_INIT_NUMERIC_SENSOR:
		rc = handle_platform_init_numeric_sensor(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_SET_STATE_SENSOR_ENABLES:
		rc = handle_platform_set_state_sensor_enables(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_GET_STATE_SENSOR_READINGS:
		rc = handle_platform_get_state_sensor_readings(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_INIT_STATE_SENSOR:
		rc = handle_platform_init_state_sensor(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_SET_NUMERIC_EFFECTER_ENABLE:
		rc = handle_platform_set_numeric_effecter_enable(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_SET_NUMERIC_EFFECTER_VALUE:
		rc = handle_platform_set_numeric_effecter_value(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_GET_NUMERIC_EFFECTER_VALUE:
		rc = handle_platform_get_numeric_effecter_value(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_SET_STATE_EFFECTER_ENABLES:
		rc = handle_platform_set_state_effecter_enables(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_SET_STATE_EFFECTER_STATES:
		rc = handle_platform_set_state_effecter_states(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_GET_STATE_EFFECTER_STATES:
		rc = handle_platform_get_state_effecter_states(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_GET_PLDM_EVENT_LOG_INFO:
		rc = handle_platform_get_pldm_event_log_info(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_ENABLE_PLDM_EVENT_LOGGING:
		rc = handle_platform_enable_pldm_event_logging(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_CLEAR_PLDM_EVENT_LOG:
		rc = handle_platform_clear_pldm_event_log(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_GET_PLDM_EVENT_LOG_TIMESTAMP:
		rc = handle_platform_get_pldm_event_log_timestamp(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_SET_PLDM_EVENT_LOG_TIMESTAMP:
		rc = handle_platform_set_pldm_event_log_timestamp(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_READ_PLDM_EVENT_LOG:
		rc = handle_platform_read_pldm_event_log(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_GET_PLDM_EVENT_LOG_POLICY_INFO:
		rc = handle_platform_get_pldm_event_log_policy_info(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_SET_PLDM_EVENT_LOG_POLICY:
		rc = handle_platform_set_pldm_event_log_policy(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_FIND_PLDM_EVENT_LOG_ENTRY:
		rc = handle_platform_find_pldm_event_log_entry(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_GET_PDR_REPOSITORY_INFO:
		rc = handle_platform_get_pdr_repository_info(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_GET_PDR:
		rc = handle_platform_get_pdr(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_FIND_PDR:
		rc = handle_platform_find_pdr(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_RUN_INIT_AGENT:
		rc = handle_platform_run_init_agent(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	case PLDM_GET_PDR_REPOSITORY_SIGNATURE:
		rc = handle_platform_get_pdr_repository_signature(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	default:
		rc = PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
	}
	return rc;
}

static int fru_get_metadata(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len) 
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

static int fru_get_record_table(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

static int fru_set_record_table(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

static int fru_get_record_by_option(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

/**
 * @brief Handle an incoming FRU message.
 * 
 * This function processes an incoming FRU message and generates
 * the appropriate response.
 * 
 * @param req_msg Pointer to the incoming PLDM request message.
 * @param req_len Length of the incoming PLDM request message.
 * @param resp_msg Pointer to the buffer for the PLDM response message.
 * @param resp_len Pointer to the length of the response buffer; updated with actual response length.
 * @return 0 on success, non-zero on failure.
 */
int handle_fru_msg(const void *req_msg, size_t req_len, void *resp_msg, size_t *resp_len)
{
	/* is there room in the response buffer for the header plus completion code */
	if (*resp_len < sizeof(struct pldm_msg_hdr) + 1) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

    // extract the request header
	const struct pldm_msg *msg_hdr = req_msg;
	struct pldm_header_info hdr;
	int rc = unpack_pldm_header(&msg_hdr->hdr, &hdr); // unpack bitfields into our struct
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	/* handle each command */
	switch (hdr.command) {
	case PLDM_GET_FRU_RECORD_TABLE_METADATA:
		rc = fru_get_metadata(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
    case PLDM_GET_FRU_RECORD_TABLE:
		rc = fru_get_record_table(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
    case PLDM_SET_FRU_RECORD_TABLE:
		rc = fru_set_record_table(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
    case PLDM_GET_FRU_RECORD_BY_OPTION:
		rc = fru_get_record_by_option(&hdr, req_msg, req_len, resp_msg, resp_len);
		break;
	default:
		rc = PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
	}
	return rc;
}

/**
 * @brief Initialize the PLDM processing module.
 * 
 * Sets up the PLDM control context and configures the PDR repository.
 * 
 * @return 0 on success, negative error code on failure.
 */
int init_pldm() {
    // Initialize the PLDM control processing module
	pldm_control_setup(&pldm_control_ctx, sizeof(struct pldm_control));
	
    // add support for PLDM Message Type 1 (PLDM Base)
	mctp_versions_map_add(MCTP_PLDM_HDR_MSG_TYPE, &(struct mctp_version_entry){ .major_version = 0xf1, .minor_version = 0xf1, .update_version = 0xff, .alpha_version = 0 });
	mctp_versions_map_add(MCTP_PLDM_HDR_MSG_TYPE, &(struct mctp_version_entry){ .major_version = 0xf1, .minor_version = 0xf0, .update_version = 0xff, .alpha_version = 0 });
	
	// add the supported types/commands - PLDM Base already exists
	// PLDM FRU
	pldm_control_add_type(&pldm_control_ctx, PLDM_FRU, &PLDM_FRU_VERSIONS,PLDM_FRU_VERSIONS_COUNT,PLDM_FRU_COMMANDS);
	
	// PLDM PLATFORM_MONITORING / PDR
	pldm_control_add_type(&pldm_control_ctx, PLDM_PLATFORM, &PLDM_PLATFORM_VERSIONS, PLDM_PLATFORM_VERSIONS_COUNT, PLDM_PLATFORM_COMMANDS);

	/**
	 * Create the PDR Repository
	 */
    if (pdr_repo != NULL) {
        LOG_WRN("PDRs already configured");
        return 0;
    }
    pdr_repo = pldm_pdr_init();
	if (pdr_repo == NULL) {
		LOG_ERR("Failed to initialize PLDM PDR repository");
		return -ENOMEM;
	}

	#ifdef PDR_NUMBER_OF_RECORDS
	if (PDR_NUMBER_OF_RECORDS > 0) {
		LOG_INF("Configuring PDRs");

		// walk through the PDR data and add each record to the repository
		size_t offset = 0;
		while (offset < PDR_TOTAL_SIZE) {
			size_t record_size = __pdr_data[8]+(size_t)(__pdr_data[9]<<8)+10;
			int rc = pldm_pdr_add(pdr_repo, &__pdr_data[offset], record_size, false, 0x0001, NULL);
			if (rc != 0) {
				LOG_ERR("Failed to add PDR record at offset %zu, size %zu: %d", offset, record_size, rc);
				return rc;
			}
			offset += record_size;
		}
		LOG_INF("PDRs configured successfully");
	}
	#endif

	/**
	 * Set up the FRU Record Table
	 */
	if (fru_repo != NULL) {
        LOG_WRN("FRU repository already configured");
        return 0;
    }
    fru_repo = pldm_pdr_init();
	if (fru_repo == NULL) {
		LOG_ERR("Failed to initialize PLDM FRU repository");
		return -ENOMEM;
	}
	return 0;
}


int handle_pldm_message(struct mctp *mctp, uint8_t remote_eid, bool tag_owner, uint8_t msg_tag, const void *msg, size_t msg_len) {    
    /* Space for header plus completion code */
	if (msg_len < sizeof(struct pldm_msg_hdr) + 1) {
        LOG_ERR("PLDM message too short: %zu", msg_len);
        send_completion_response(mctp, remote_eid, tag_owner, msg_tag, msg, msg_len, PLDM_ERROR_INVALID_LENGTH);
        return PLDM_ERROR_INVALID_LENGTH;
	}

    /* Get the pldm header */
	const struct pldm_msg *req = (const struct pldm_msg *)msg;
	struct pldm_header_info hdr;
	int rc = unpack_pldm_header(&req->hdr, &hdr);
	if (rc != PLDM_SUCCESS) {
        LOG_ERR("Failed to unpack PLDM header");
        send_completion_response(mctp, remote_eid, tag_owner, msg_tag, msg, msg_len, rc);
        return rc;
    }

    rc = PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
    size_t resp_len = PLDM_RX_BUF_SZ;
    memset(pldm_rx_buf, 0, PLDM_RX_BUF_SZ);
    switch (hdr.pldm_type) {
        case PLDM_BASE:
            LOG_DBG("PLDM message: type BASE");
            rc = pldm_control_handle_msg(&pldm_control_ctx, (const void *)msg, msg_len, pldm_rx_buf, &resp_len);
            break;
        case PLDM_FRU:
            LOG_DBG("PLDM message: type FRU");
            rc = handle_fru_msg((const void *)msg, msg_len, pldm_rx_buf, &resp_len);
            break;
        case PLDM_PLATFORM:
            LOG_DBG("PLDM message: type PLATFORM");
            rc = handle_platform_msg((const void *)msg, msg_len, pldm_rx_buf, &resp_len);
            break;
        default:
            LOG_DBG("Unsupported PLDM message type: %u", hdr.pldm_type);
    }
    if (rc != PLDM_SUCCESS) {
        LOG_DBG("Sending Error Response: %u", rc);
        send_completion_response(mctp, remote_eid, tag_owner, msg_tag, msg, msg_len, rc);
    }
    return rc;
}