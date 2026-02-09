/**
 * @file fru.c
 * @brief FRU command handlers for IoT-Foundry firmware
 *
 * This file implements the PLDM FRU command handlers
 * for the IoT-Foundry Zephyr-based MCTP endpoint firmware.
 * @author Doug Sandy
 * @date February 2026
 * SPDX-License-Identifier: Apache-2.0 
 */
#include <zephyr/types.h>
#include <libmctp.h>
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include <string.h>
#include <libpldm/base.h>
#include <libpldm/platform.h>
#include <libpldm/control.h>
#include <libpldm/fru.h>
#include <libpldm/edac.h>
#include <libpldm/pdr.h>
#include <../pldm/src/control-internal.h>
#include "pdrs/config.h"
#include "mctp_control.h"
#include "platform.h"

LOG_MODULE_REGISTER(fru_cmds, LOG_LEVEL_DBG);

/* TransferOperation flags are provided by libpldm as `PLDM_XFER_*` enums.
 * Use those definitions (PLDM_XFER_FIRST_PART, PLDM_XFER_NEXT_PART, etc.)
 * to match libpldm / DSP0240 semantics for MultipartReceive.
 */

/* Simple transfer-state table for Get FRU multipart transfers */
#define FRU_XFER_TABLE_SIZE 6
struct fru_xfer_entry {
	uint32_t handle;
	uint32_t offset;
	uint32_t expiry_ms;
	bool in_use;
};
static struct fru_xfer_entry fru_xfer_table[FRU_XFER_TABLE_SIZE];
static uint32_t fru_next_handle = 1;

static void fru_xfer_cleanup_expired(void)
{
	uint32_t now = k_uptime_get_32();
	for (int i = 0; i < FRU_XFER_TABLE_SIZE; ++i) {
		if (fru_xfer_table[i].in_use && fru_xfer_table[i].expiry_ms != 0 && fru_xfer_table[i].expiry_ms <= now) {
			fru_xfer_table[i].in_use = false;
		}
	}
}

static uint32_t fru_xfer_alloc(void)
{
	fru_xfer_cleanup_expired();
	for (int i = 0; i < FRU_XFER_TABLE_SIZE; ++i) {
		if (!fru_xfer_table[i].in_use) {
			uint32_t h = ++fru_next_handle;
			if (h == 0) h = ++fru_next_handle;
			fru_xfer_table[i].handle = h | 0x80000000u;
			fru_xfer_table[i].offset = 0;
			fru_xfer_table[i].expiry_ms = k_uptime_get_32() + 60000u;
			fru_xfer_table[i].in_use = true;
			return fru_xfer_table[i].handle;
		}
	}
	return 0;
}

static struct fru_xfer_entry *fru_xfer_find(uint32_t handle)
{
	fru_xfer_cleanup_expired();
	for (int i = 0; i < FRU_XFER_TABLE_SIZE; ++i) {
		if (fru_xfer_table[i].in_use && fru_xfer_table[i].handle == handle) {
			return &fru_xfer_table[i];
		}
	}
	return NULL;
}

static void fru_xfer_free_handle(uint32_t handle)
{
	for (int i = 0; i < FRU_XFER_TABLE_SIZE; ++i) {
		if (fru_xfer_table[i].in_use && fru_xfer_table[i].handle == handle) {
			fru_xfer_table[i].in_use = false;
			return;
		}
	}
}

/**
 * @brief Handle PLDM Get FRU Record Table Metadata command
 * 
 * This function processes the PLDM Get FRU Record Table Metadata command
 * and generates an appropriate response.
 * 
 * @param hdr Pointer to the PLDM header info structure.
 * @param req_msg Pointer to the incoming PLDM request message.
 * @param req_len Length of the incoming PLDM request message.
 * @param resp Pointer to the buffer for the PLDM response message.
 * @param resp_len Pointer to the length of the response buffer; updated with actual response length
 * @return PLDM_SUCCESS on success, or appropriate PLDM error code on failure.
 */
int fru_get_metadata(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len) 
{
	if (!hdr || !resp || !resp_len) {
		return PLDM_ERROR_INVALID_DATA;
	}

	/* Retrieve counts/sizes from generated config.h macros */
#ifdef FRU_NUMBER_OF_RECORDS
	uint16_t total_table_records = (uint16_t)FRU_NUMBER_OF_RECORDS;
#else
	uint16_t total_table_records = 0;
#endif
#ifdef FRU_TOTAL_RECORD_SETS
	uint16_t total_record_set_identifiers = (uint16_t)FRU_TOTAL_RECORD_SETS;
#else
	uint16_t total_record_set_identifiers = 0;
#endif
#ifdef FRU_MAX_RECORD_SIZE
	uint32_t fru_table_maximum_size = (uint32_t)FRU_MAX_RECORD_SIZE;
#else
	uint32_t fru_table_maximum_size = 0;
#endif
#ifdef FRU_TOTAL_SIZE
	uint32_t fru_table_length = (uint32_t)FRU_TOTAL_SIZE;
#else
	uint32_t fru_table_length = 0;
#endif

	/* Compute integrity checksum over the FRU Record Table bytes */
	uint32_t checksum = 0;
	if (fru_table_length > 0) {
		checksum = pldm_edac_crc32((const void *)__fru_data, (size_t)fru_table_length);
	}

	/* FRU table data version: builder/runtime convention — use 1.0 */
	uint8_t fru_data_major_version = 1;
	uint8_t fru_data_minor_version = 0;

	/* Build PLDM response using libpldm helper */
	PLDM_MSG_BUFFER(msg_buf, MCTP_PAYLOAD_MAX);
	memset(msg_buf, 0, sizeof(msg_buf));
	struct pldm_msg *msg = (struct pldm_msg *)msg_buf;
	int rc = encode_get_fru_record_table_metadata_resp(hdr->instance, PLDM_SUCCESS, fru_data_major_version, fru_data_minor_version, fru_table_maximum_size, fru_table_length, total_record_set_identifiers, total_table_records, checksum, msg);
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	size_t msg_size = sizeof(struct pldm_msg_hdr) + PLDM_GET_FRU_RECORD_TABLE_METADATA_RESP_BYTES;
	if (*resp_len < msg_size) return PLDM_ERROR_INVALID_LENGTH;
	memcpy(resp, msg, msg_size);
	*resp_len = msg_size;
	return PLDM_SUCCESS;
}

/**
 * @brief Handle PLDM Get FRU Record Table command
 * 
 * This function processes the PLDM Get FRU Record Table command
 * and generates an appropriate response.
 * 
 * @param hdr Pointer to the PLDM header info structure.
 * @param req_msg Pointer to the incoming PLDM request message.
 * @param req_len Length of the incoming PLDM request message.
 * @param resp Pointer to the buffer for the PLDM response message.
 * @param resp_len Pointer to the length of the response buffer; updated with actual response length
 * @return PLDM_SUCCESS on success, or appropriate PLDM error code on failure.
 */
int fru_get_record_table(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	if (!hdr || !req_msg || !resp || !resp_len) {
		return PLDM_ERROR_INVALID_DATA;
	}

	const struct pldm_msg *req = req_msg;
	uint32_t data_transfer_hndl = 0;
	uint8_t transfer_op_flag = 0;

	/* Clamp payload length passed to libpldm decoder to the defined request size
	 * to avoid libpldm returning PLDM_ERROR_INVALID_LENGTH when callers pass
	 * padded or larger buffers. */
	size_t payload_len = 0;
	if (req_len > sizeof(struct pldm_msg_hdr))
		payload_len = req_len - sizeof(struct pldm_msg_hdr);
	if (payload_len > PLDM_GET_FRU_RECORD_TABLE_REQ_BYTES)
		payload_len = PLDM_GET_FRU_RECORD_TABLE_REQ_BYTES;
	int rc = decode_get_fru_record_table_req(req, payload_len, &data_transfer_hndl, &transfer_op_flag);
	if (rc != PLDM_SUCCESS) {
		/* encode error completion-only response */
		PLDM_MSG_BUFFER(msg_buf, MCTP_PAYLOAD_MAX);
		memset(msg_buf, 0, sizeof(msg_buf));
		struct pldm_msg *msg = (struct pldm_msg *)msg_buf;
		int enc = encode_get_fru_record_table_resp(hdr->instance, (uint8_t)rc, 0, PLDM_PLATFORM_TRANSFER_START_AND_END, msg);
		if (enc != PLDM_SUCCESS) return enc;
		size_t msg_sz = sizeof(struct pldm_msg_hdr) + PLDM_GET_FRU_RECORD_TABLE_MIN_RESP_BYTES;
		if (*resp_len < msg_sz) return PLDM_ERROR_INVALID_LENGTH;
		memcpy(resp, msg, msg_sz);
		*resp_len = msg_sz;
		return rc;
	}

	const uint8_t *table = (const uint8_t *)__fru_data;
	size_t table_len = (size_t)FRU_TOTAL_SIZE;

	/* Compute available payload for 'data' (excluding PLDM header and fixed resp fields),
	 * and reserve 4 bytes for the PLDM DataIntegrityChecksum which must be appended
	 * for every data part. We also reserve space for an optional 4-byte FRU CRC when
	 * sending the final fragment of a multipart transfer.
	 */
	size_t base_overhead = sizeof(struct pldm_msg_hdr) + (sizeof(struct pldm_get_fru_record_table_resp) - 1);
	size_t max_payload = (size_t)MCTP_PAYLOAD_MAX - 1; /* leading MCTP type byte */
	if (max_payload <= base_overhead + sizeof(uint32_t)) return PLDM_ERROR; /* no room for data+checksum */
	size_t avail_data = max_payload - base_overhead - sizeof(uint32_t); /* space for data, excluding PLDM DataIntegrityChecksum */

	uint32_t returned_next_transfer_handle = 0;
	uint8_t transfer_flag = PLDM_PLATFORM_TRANSFER_START_AND_END;
	size_t transfer_offset = 0;
	size_t data_len = 0;
	uint32_t fru_payload_crc = 0; /* FRUDataStructureIntegrityChecksum if appended */
	const size_t fru_crc_size = FRU_TABLE_CHECKSUM_SIZE;

	/* Validate transfer operation flags per PLDM Get semantics */
	if (data_transfer_hndl == 0) {
		if (transfer_op_flag != PLDM_XFER_FIRST_PART) {
			PLDM_MSG_BUFFER(msg_buf, MCTP_PAYLOAD_MAX);
			memset(msg_buf, 0, sizeof(msg_buf));
			struct pldm_msg *msg = (struct pldm_msg *)msg_buf;
			int enc = encode_get_fru_record_table_resp(hdr->instance, PLDM_FRU_INVALID_TRANSFER_FLAG, 0, PLDM_PLATFORM_TRANSFER_START_AND_END, msg);
			if (enc != PLDM_SUCCESS) return enc;
			size_t msg_sz = sizeof(struct pldm_msg_hdr) + PLDM_GET_FRU_RECORD_TABLE_MIN_RESP_BYTES;
			if (*resp_len < msg_sz) return PLDM_ERROR_INVALID_LENGTH;
			memcpy(resp, msg, msg_sz);
			*resp_len = msg_sz;
			return PLDM_FRU_INVALID_TRANSFER_FLAG;
		}

		/* Decide whether the whole table fits in one response (single-part).
		 * Single-part replies MUST include the PLDM DataIntegrityChecksum but
		 * MUST NOT append the FRU payload CRC-32 per DSP0257.
		 */
		if (table_len <= avail_data) {
			transfer_flag = PLDM_PLATFORM_TRANSFER_START_AND_END;
			returned_next_transfer_handle = 0;
			transfer_offset = 0;
			data_len = table_len;
			fru_payload_crc = 0; /* not appended for single-frame */
		} else {
			/* multipart: allocate a transfer handle and send the first chunk */
			uint32_t h = fru_xfer_alloc();
			if (h == 0) return PLDM_ERROR; /* no resources */
			transfer_flag = PLDM_PLATFORM_TRANSFER_START;
			returned_next_transfer_handle = h;
			transfer_offset = 0;
			data_len = avail_data; /* send as much as fits (dataIntegrityChecksum appended separately) */
			fru_payload_crc = 0;
			/* record offset for continuation */
			struct fru_xfer_entry *ne = fru_xfer_find(returned_next_transfer_handle);
			if (ne) {
				ne->offset = transfer_offset + data_len;
				ne->expiry_ms = k_uptime_get_32() + 60000u;
			}
		}
	} else {
		/* Continuation: expect GetNextPart */
		if (transfer_op_flag != PLDM_XFER_NEXT_PART) {
			PLDM_MSG_BUFFER(msg_buf, MCTP_PAYLOAD_MAX);
			memset(msg_buf, 0, sizeof(msg_buf));
			struct pldm_msg *msg = (struct pldm_msg *)msg_buf;
			int enc = encode_get_fru_record_table_resp(hdr->instance, PLDM_FRU_INVALID_TRANSFER_FLAG, 0, PLDM_PLATFORM_TRANSFER_START_AND_END, msg);
			if (enc != PLDM_SUCCESS) return enc;
			size_t msg_sz = sizeof(struct pldm_msg_hdr) + PLDM_GET_FRU_RECORD_TABLE_MIN_RESP_BYTES;
			if (*resp_len < msg_sz) return PLDM_ERROR_INVALID_LENGTH;
			memcpy(resp, msg, msg_sz);
			*resp_len = msg_sz;
			return PLDM_FRU_INVALID_TRANSFER_FLAG;
		}

		struct fru_xfer_entry *e = fru_xfer_find(data_transfer_hndl);
		if (!e) {
			PLDM_MSG_BUFFER(msg_buf, MCTP_PAYLOAD_MAX);
			memset(msg_buf, 0, sizeof(msg_buf));
			struct pldm_msg *msg = (struct pldm_msg *)msg_buf;
			int enc = encode_get_fru_record_table_resp(hdr->instance, PLDM_FRU_INVALID_DATA_TRANSFER_HANDLE, 0, PLDM_PLATFORM_TRANSFER_START_AND_END, msg);
			if (enc != PLDM_SUCCESS) return enc;
			size_t msg_sz = sizeof(struct pldm_msg_hdr) + PLDM_GET_FRU_RECORD_TABLE_MIN_RESP_BYTES;
			if (*resp_len < msg_sz) return PLDM_ERROR_INVALID_LENGTH;
			memcpy(resp, msg, msg_sz);
			*resp_len = msg_sz;
			return PLDM_FRU_INVALID_DATA_TRANSFER_HANDLE;
		}

		transfer_offset = e->offset;
		size_t remaining = (transfer_offset < table_len) ? (table_len - transfer_offset) : 0;
		if (remaining == 0) {
			/* Nothing left: return an empty success START_AND_END */
			PLDM_MSG_BUFFER(msg_buf, MCTP_PAYLOAD_MAX);
			memset(msg_buf, 0, sizeof(msg_buf));
			struct pldm_msg *msg = (struct pldm_msg *)msg_buf;
			int enc = encode_get_fru_record_table_resp(hdr->instance, PLDM_SUCCESS, 0, PLDM_PLATFORM_TRANSFER_START_AND_END, msg);
			if (enc != PLDM_SUCCESS) return enc;
			size_t msg_sz = sizeof(struct pldm_msg_hdr) + PLDM_GET_FRU_RECORD_TABLE_MIN_RESP_BYTES;
			if (*resp_len < msg_sz) return PLDM_ERROR_INVALID_LENGTH;
			memcpy(resp, msg, msg_sz);
			*resp_len = msg_sz;
			return PLDM_SUCCESS;
		}

		/* Compute pad bytes for FRU CRC alignment (0..3) based on total FRU table length */
		size_t pad_bytes = 0;
		if (table_len % 4 != 0) pad_bytes = 4 - (table_len % 4);

		/* If remaining fits including the pad and FRU payload CRC then this is END */
		if (remaining + pad_bytes + fru_crc_size <= avail_data) {
			transfer_flag = PLDM_PLATFORM_TRANSFER_END;
			returned_next_transfer_handle = 0;
			data_len = remaining;
			/* FRU payload CRC is computed over the entire table */
			fru_payload_crc = pldm_edac_crc32(table, table_len);
			fru_xfer_free_handle(e->handle);
		} else {
			transfer_flag = PLDM_PLATFORM_TRANSFER_MIDDLE;
			returned_next_transfer_handle = e->handle;
			data_len = avail_data;
			if (data_len > remaining) data_len = remaining;
			e->offset = transfer_offset + data_len;
			e->expiry_ms = k_uptime_get_32() + 60000u;
			fru_payload_crc = 0;
		}
	}

	/* Build response: encode header then copy data, optional FRU CRC (only for END), then append PLDM DataIntegrityChecksum (uint32 LE).
	 */
	PLDM_MSG_BUFFER(msg_buf, MCTP_PAYLOAD_MAX);
	memset(msg_buf, 0, sizeof(msg_buf));
	struct pldm_msg *msg = (struct pldm_msg *)msg_buf;

	rc = encode_get_fru_record_table_resp(hdr->instance, PLDM_SUCCESS, returned_next_transfer_handle, transfer_flag, msg);
	if (rc != PLDM_SUCCESS) return rc;

	/* pointer to start of variable data in encoded payload */
	struct pldm_get_fru_record_table_resp *resp_struct = (struct pldm_get_fru_record_table_resp *)msg->payload;
	uint8_t *dst = resp_struct->fru_record_table_data;

	/* copy data bytes */
	if (data_len > 0) {
		memcpy(dst, table + transfer_offset, data_len);
		dst += data_len;
	}

	/* append FRU payload CRC only for multi-part END fragments, with pad bytes preceding it */
	size_t pad_bytes = 0;
	if (transfer_flag == PLDM_PLATFORM_TRANSFER_END && fru_payload_crc != 0) {
		/* pad is computed from the full FRU table length to align the FRU CRC */
		if (table_len % 4 != 0) pad_bytes = 4 - (table_len % 4);
		if (pad_bytes > 0) {
			memset(dst, 0x00, pad_bytes);
			dst += pad_bytes;
		}
		uint32_t c = htole32(fru_payload_crc);
		memcpy(dst, &c, sizeof(c));
		dst += sizeof(c);
	}

	/* compute PLDM DataIntegrityChecksum over the DATA bytes only (exclude appended FRU CRC)
	 * That is, checksum over table[0 .. transfer_offset+data_len-1]
	 */
	uint32_t data_integrity = 0;
	if ((transfer_offset + data_len) > 0) {
		data_integrity = pldm_edac_crc32(table, transfer_offset + data_len);
	}
	uint32_t di_le = htole32(data_integrity);
	memcpy(dst, &di_le, sizeof(di_le));
	dst += sizeof(di_le);

	/* compute final message size and ensure it fits */
	size_t msg_size = sizeof(struct pldm_msg_hdr) + (sizeof(struct pldm_get_fru_record_table_resp) - 1) + data_len + ((transfer_flag == PLDM_PLATFORM_TRANSFER_END && fru_payload_crc != 0) ? (pad_bytes + fru_crc_size) : 0) + sizeof(uint32_t);

	/* If it doesn't fit in MCTP_PAYLOAD_MAX, trim data_len and re-encode loop similar to platform_pdr logic */
	while ((1 + msg_size) > MCTP_PAYLOAD_MAX) {
		if (data_len == 0) return PLDM_ERROR; /* cannot fit */
		/* shrink by one and recompute semantics */
		data_len--;
		/* if we shrank below end threshold, switch to MIDDLE and remove FRU CRC */
		if (transfer_flag == PLDM_PLATFORM_TRANSFER_END && (transfer_offset + data_len) < table_len) {
			transfer_flag = PLDM_PLATFORM_TRANSFER_MIDDLE;
			fru_payload_crc = 0;
			returned_next_transfer_handle = fru_xfer_alloc();
			if (returned_next_transfer_handle == 0) return PLDM_ERROR;
			struct fru_xfer_entry *ne = fru_xfer_find(returned_next_transfer_handle);
			if (ne) {
				ne->offset = transfer_offset + data_len;
				ne->expiry_ms = k_uptime_get_32() + 60000u;
			}
		}

		/* re-encode header and copy trimmed data */
		memset(msg_buf, 0, sizeof(msg_buf));
		rc = encode_get_fru_record_table_resp(hdr->instance, PLDM_SUCCESS, returned_next_transfer_handle, transfer_flag, msg);
		if (rc != PLDM_SUCCESS) return rc;
		resp_struct = (struct pldm_get_fru_record_table_resp *)msg->payload;
		dst = resp_struct->fru_record_table_data;
		if (data_len > 0) memcpy(dst, table + transfer_offset, data_len);
		if (transfer_flag == PLDM_PLATFORM_TRANSFER_END && fru_payload_crc != 0) {
			/* recompute pad for trimmed data and append pad + FRU CRC */
			size_t pad_trim = 0;
			if (table_len % 4 != 0) pad_trim = 4 - (table_len % 4);
			if (pad_trim > 0) memset(dst + data_len, 0x00, pad_trim);
			uint32_t c = htole32(fru_payload_crc);
			memcpy(dst + data_len + pad_trim, &c, sizeof(c));
		}
		/* recompute data_integrity over table up to new length */
		if ((transfer_offset + data_len) > 0) data_integrity = pldm_edac_crc32(table, transfer_offset + data_len);
		uint32_t di_le2 = htole32(data_integrity);
		memcpy(dst + data_len + ((transfer_flag == PLDM_PLATFORM_TRANSFER_END && fru_payload_crc != 0) ? ((table_len % 4 != 0 ? 4 - (table_len % 4) : 0) + fru_crc_size) : 0), &di_le2, sizeof(di_le2));
		msg_size = sizeof(struct pldm_msg_hdr) + (sizeof(struct pldm_get_fru_record_table_resp) - 1) + data_len + ((transfer_flag == PLDM_PLATFORM_TRANSFER_END && fru_payload_crc != 0) ? ((table_len % 4 != 0 ? 4 - (table_len % 4) : 0) + fru_crc_size) : 0) + sizeof(uint32_t);
	}

	if (*resp_len < msg_size) return PLDM_ERROR_INVALID_LENGTH;
	memcpy(resp, msg, msg_size);

	/* If we allocated a transfer handle for a START fragment, update its offset */
	if (returned_next_transfer_handle != 0 && transfer_flag == PLDM_PLATFORM_TRANSFER_START) {
		struct fru_xfer_entry *ne = fru_xfer_find(returned_next_transfer_handle);
		if (ne) {
			ne->offset = data_len;
			ne->expiry_ms = k_uptime_get_32() + 60000u;
		}
	}

	*resp_len = msg_size;
	return PLDM_SUCCESS;

}

/**
 * @brief Handle PLDM Set FRU Record Table command
 * 
 * This function processes the PLDM Set FRU Record Table command
 * and generates an appropriate response.
 * 
 * @param hdr Pointer to the PLDM header info structure.
 * @param req_msg Pointer to the incoming PLDM request message.
 * @param req_len Length of the incoming PLDM request message.
 * @param resp Pointer to the buffer for the PLDM response message.
 * @param resp_len Pointer to the length of the response buffer; updated with actual response length
 * @return PLDM_SUCCESS on success, or appropriate PLDM error code on failure.
 */
int fru_set_record_table(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len) {
        if (hdr == NULL || req_msg == NULL || resp == NULL || resp_len == NULL) {
                return PLDM_ERROR_INVALID_DATA;
        }

        PLDM_MSG_BUFFER(msg_buf, MCTP_PAYLOAD_MAX);
        memset(msg_buf, 0, sizeof(msg_buf));
        struct pldm_msg *msg = (struct pldm_msg *)msg_buf;
		struct pldm_header_info header = {0};
        header.msg_type = PLDM_RESPONSE;
        header.instance = hdr->instance;
		header.pldm_type = PLDM_FRU;
        header.command = PLDM_SET_FRU_RECORD_TABLE;
        if (pack_pldm_header(&header, &msg->hdr) != PLDM_SUCCESS) return PLDM_ERROR;
        msg->payload[0] = PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
        size_t msg_sz = sizeof(struct pldm_msg_hdr) + 1;
        if (*resp_len < msg_sz) return PLDM_ERROR_INVALID_LENGTH;
        memcpy(resp, msg, msg_sz);
        *resp_len = msg_sz;
        return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

/**
 * @brief Handle PLDM Get FRU Record By Option command
 * 
 * This function processes the PLDM Get FRU Record By Option command
 * and generates an appropriate response.
 * 
 * @param hdr Pointer to the PLDM header info structure.
 * @param req_msg Pointer to the incoming PLDM request message.
 * @param req_len Length of the incoming PLDM request message.
 * @param resp Pointer to the buffer for the PLDM response message.
 * @param resp_len Pointer to the length of the response buffer; updated with actual response length
 * @return PLDM_SUCCESS on success, or appropriate PLDM error code on failure.
 */
int fru_get_record_by_option(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len) {
        if (hdr == NULL || req_msg == NULL || resp == NULL || resp_len == NULL) {
                return PLDM_ERROR_INVALID_DATA;
        }

        PLDM_MSG_BUFFER(msg_buf, MCTP_PAYLOAD_MAX);
        memset(msg_buf, 0, sizeof(msg_buf));
        struct pldm_msg *msg = (struct pldm_msg *)msg_buf;
		struct pldm_header_info header = {0};
        header.msg_type = PLDM_RESPONSE;
        header.instance = hdr->instance;
		header.pldm_type = PLDM_FRU;
        header.command = PLDM_GET_FRU_RECORD_BY_OPTION;
        if (pack_pldm_header(&header, &msg->hdr) != PLDM_SUCCESS) return PLDM_ERROR;
        msg->payload[0] = PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
        size_t msg_sz = sizeof(struct pldm_msg_hdr) + 1;
        if (*resp_len < msg_sz) return PLDM_ERROR_INVALID_LENGTH;
        memcpy(resp, msg, msg_sz);
        *resp_len = msg_sz;
        return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}
