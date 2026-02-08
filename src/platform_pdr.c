/**
 * @file platform_pdr.c
 * @brief Platform PDR command handlers for IoT-Foundry firmware
 *
 * This file implements the PLDM Platform PDR command handlers
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
#include <libpldm/pdr.h>
#include <../pldm/src/control-internal.h>
#include "pdrs/config.h"
#include "pdrs/pdr_utils.h"
#include "mctp_control.h"
#include "platform.h"
#include <libpldm/edac.h>

LOG_MODULE_REGISTER(platform_pdr, LOG_LEVEL_DBG);


/* Simple transfer-state table for GetPDR multipart transfers */
#define PDR_XFER_TABLE_SIZE 8
struct pdr_xfer_entry {
	uint32_t handle;
	uint32_t record_handle;
	uint32_t offset;
	uint32_t expiry_ms; /* k_uptime_get_32() + timeout */
	bool in_use;
};
static struct pdr_xfer_entry pdr_xfer_table[PDR_XFER_TABLE_SIZE];
static uint32_t pdr_next_handle = 1;

/**
 * @brief Clean up expired entries from the PDR transfer table
 * This function is called before any allocation or lookup to ensure that
 * expired entries are removed and their slots can be reused.
 */
static void pdr_xfer_cleanup_expired(void)
{
	uint32_t now = k_uptime_get_32();
	for (int i = 0; i < PDR_XFER_TABLE_SIZE; ++i) {
		if (pdr_xfer_table[i].in_use && pdr_xfer_table[i].expiry_ms != 0 && pdr_xfer_table[i].expiry_ms <= now) {
			pdr_xfer_table[i].in_use = false;
		}
	}
}

/**
 * @brief Allocate a new PDR transfer entry for a multipart GetPDR operation
 * 
 * @param record_handle The PDR record handle associated with this transfer
 * @return A unique transfer handle to be used in GetPDR requests, or 0 if allocation failed
 */
static uint32_t pdr_xfer_alloc(uint32_t record_handle)
{
	pdr_xfer_cleanup_expired();
	for (int i = 0; i < PDR_XFER_TABLE_SIZE; ++i) {
		if (!pdr_xfer_table[i].in_use) {
			uint32_t h = ++pdr_next_handle;
			if (h == 0) h = ++pdr_next_handle; /* avoid zero */
			pdr_xfer_table[i].handle = h | 0x80000000u; /* mark high bit to avoid accidental small values */
			pdr_xfer_table[i].record_handle = record_handle;
			pdr_xfer_table[i].offset = 0;
			pdr_xfer_table[i].expiry_ms = k_uptime_get_32() + 60000u; /* 60s default timeout */
			pdr_xfer_table[i].in_use = true;
			return pdr_xfer_table[i].handle;
		}
	}
	return 0; /* allocation failed */
}

/**
 * @brief Find a PDR transfer entry by its transfer handle
 * 
 * @param handle The transfer handle to look up
 * @return Pointer to the transfer entry if found and valid, or NULL if not found
 */
static struct pdr_xfer_entry *pdr_xfer_find(uint32_t handle)
{
	pdr_xfer_cleanup_expired();
	for (int i = 0; i < PDR_XFER_TABLE_SIZE; ++i) {
		if (pdr_xfer_table[i].in_use && pdr_xfer_table[i].handle == handle) {
			return &pdr_xfer_table[i];
		}
	}
	return NULL;
}

/**
 * @brief Free a PDR transfer entry by its transfer handle
 * 
 * @param handle The transfer handle of the entry to free
 */
static void pdr_xfer_free_handle(uint32_t handle)
{
	for (int i = 0; i < PDR_XFER_TABLE_SIZE; ++i) {
		if (pdr_xfer_table[i].in_use && pdr_xfer_table[i].handle == handle) {
			pdr_xfer_table[i].in_use = false;
			return;
		}
	}
}

/**
 * @brief Find a PDR record in the __pdr_data[] array by handle
 * This is a simple linear search through the __pdr_data[] array, which is
 * sufficient for IoT-Foundry endpoints since they have a small number of records. 
 * 
 * @param want_handle The PDR record handle to find, or 0 to get the first record
 * @param rec_ptr Output pointer to the start of the found record (including 10-byte
 *                header), or NULL if not found
 * @param rec_size Output size of the found record (including 10-byte header), or 0 if not found
 * @param next_handle Output next record handle after the found record, or 0 if no more records
 */
static void find_pdr_record_by_handle(uint32_t want_handle, const uint8_t **rec_ptr, size_t *rec_size, uint32_t *next_handle)
{
	size_t offset = 0;
	*rec_ptr = NULL;
	*rec_size = 0;
	*next_handle = 0;
	/* Interpret builder-provided PDR_TOTAL_SIZE as payload-only. The
	 * actual repository bytes in __pdr_data[] include a 10-byte header
	 * per record. Compute the true repo byte length here and use it for
	 * all bounds checks. */
	const size_t repo_bytes = pdr_repo_bytes();

	while (offset < repo_bytes) {
		uint32_t handle_v;
		size_t record_size_v;
		if (!pdr_read_record_at(offset, &handle_v, &record_size_v)) {
			break; /* malformed or out of bounds */
		}
		uint32_t handle = handle_v;
		size_t record_size = record_size_v;
		if (want_handle == 0) {
			/* caller wants first record */
			*rec_ptr = &__pdr_data[offset];
			*rec_size = record_size;
			/* determine next handle */
			uint32_t nh = 0;
			if (pdr_read_record_at(offset + record_size, &nh, NULL)) {
				*next_handle = nh;
			} else {
				*next_handle = 0;
			}
			return;
		}

		if (handle == want_handle) {
			*rec_ptr = &__pdr_data[offset];
			*rec_size = record_size;
			uint32_t nh = 0;
			if (pdr_read_record_at(offset + record_size, &nh, NULL)) {
				*next_handle = nh;
			} else {
				*next_handle = 0;
			}
			return;
		}

		offset += record_size;
	}
}


/**
 * @brief Handle PLDM Get PDR Repository Info command
 * 
 * This function processes the PLDM Get PDR Repository Info command
 * and generates an appropriate response.
 * 
 * @param hdr Pointer to the PLDM header info structure.
 * @param req_msg Pointer to the incoming PLDM request message.
 * @param req_len Length of the incoming PLDM request message.
 * @param resp Pointer to the buffer for the PLDM response message.
 * @param resp_len Pointer to the length of the response buffer; updated with actual response length
 * @return PLDM_SUCCESS on success, or appropriate PLDM error code on failure.
 */
int handle_platform_get_pdr_repository_info(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	if (!resp || !resp_len || !hdr) {
		return PLDM_ERROR_INVALID_DATA;
	}

	uint32_t record_count = PDR_NUMBER_OF_RECORDS;
	/* Builder emits PDR_TOTAL_SIZE as payload-only; return the actual
	 * repository byte length (payload + per-record headers). */
	uint32_t repository_size = (uint32_t)pdr_repo_bytes();
	uint32_t largest_record_size = PDR_MAX_RECORD_SIZE;

	/* encode response. leave update_time/oem_update_time NULL */
	PLDM_MSG_BUFFER(msg_buf, MCTP_PAYLOAD_MAX);
	memset(msg_buf, 0, sizeof(msg_buf));
	struct pldm_msg *msg = (struct pldm_msg *)msg_buf;
	int rc = encode_get_pdr_repository_info_resp(hdr->instance, PLDM_SUCCESS, PLDM_AVAILABLE, get_build_timestamp104(), get_build_timestamp104(), record_count, repository_size, largest_record_size, PLDM_NO_TIMEOUT, msg);
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	/* copy into resp buffer if it fits */
	size_t msg_size = sizeof(struct pldm_msg_hdr) + PLDM_GET_PDR_REPOSITORY_INFO_RESP_BYTES;
	if (*resp_len < msg_size) {
		return PLDM_ERROR_INVALID_LENGTH;
	}
	memcpy(resp, msg, msg_size);
	*resp_len = msg_size;
	return PLDM_SUCCESS;
}

/**
 * @brief Handle PLDM Get PDR command
 * 
 * This function processes the PLDM Get PDR command
 * and generates an appropriate response.
 * 
 * @param hdr Pointer to the PLDM header info structure.
 * @param req_msg Pointer to the incoming PLDM request message.
 * @param req_len Length of the incoming PLDM request message.
 * @param resp Pointer to the buffer for the PLDM response message.
 * @param resp_len Pointer to the length of the response buffer; updated with actual response length
 * @return PLDM_SUCCESS on success, or appropriate PLDM error code on failure.
 */
int handle_platform_get_pdr(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	if (!hdr || !req_msg || !resp || !resp_len) {
		return PLDM_ERROR_INVALID_DATA;
	}

	int rc;
	uint32_t record_hndl = 0;
	uint32_t data_transfer_hndl = 0;
	uint8_t transfer_op_flag = 0;
	uint16_t request_cnt = 0;
	uint16_t record_chg_num = 0;

	const struct pldm_msg *req = req_msg;
	rc = decode_get_pdr_req(req, req_len - sizeof(struct pldm_msg_hdr), &record_hndl, &data_transfer_hndl, &transfer_op_flag, &request_cnt, &record_chg_num);
	if (rc != PLDM_SUCCESS) {
		/* Encode an error response so caller can transmit a PLDM completion code */
		PLDM_MSG_BUFFER(msg_buf, MCTP_PAYLOAD_MAX);
		memset(msg_buf, 0, sizeof(msg_buf));
		struct pldm_msg *msg = (struct pldm_msg *)msg_buf;
		int enc = encode_get_pdr_resp(hdr->instance, (uint8_t)rc, 0, 0, PLDM_PLATFORM_TRANSFER_START_AND_END, 0, NULL, 0, msg);
		if (enc != PLDM_SUCCESS) return enc;
		size_t msg_sz = sizeof(struct pldm_msg_hdr) + PLDM_GET_PDR_MIN_RESP_BYTES;
		if (*resp_len < msg_sz) return PLDM_ERROR_INVALID_LENGTH;
		memcpy(resp, msg, msg_sz);
		*resp_len = msg_sz;
		return rc;
	}

	/* Log decoded request values for debugging */
	LOG_DBG("GetPDR req: record_hndl=0x%08x data_xfer_hndl=0x%08x transfer_op_flag=0x%02x request_cnt=%u record_chg_num=%u",
		record_hndl, data_transfer_hndl, transfer_op_flag, request_cnt, record_chg_num);

	/* Validate transfer operation flag per DSP0248: GetFirstPart=0x01, GetNextPart=0x00
	 * If data_transfer_hndl == 0 (new transfer) we expect GetFirstPart (0x01).
	 * If data_transfer_hndl != 0 (continuation) we expect GetNextPart (0x00).
	 */
	if (data_transfer_hndl == 0) {
		if (transfer_op_flag != 0x01) {
			PLDM_MSG_BUFFER(msg_buf, MCTP_PAYLOAD_MAX);
			memset(msg_buf, 0, sizeof(msg_buf));
			struct pldm_msg *msg = (struct pldm_msg *)msg_buf;
			int enc = encode_get_pdr_resp(hdr->instance, PLDM_PLATFORM_INVALID_DATA_TRANSFER_HANDLE, 0, 0, PLDM_PLATFORM_TRANSFER_START_AND_END, 0, NULL, 0, msg);
			if (enc != PLDM_SUCCESS) return enc;
			size_t msg_sz = sizeof(struct pldm_msg_hdr) + PLDM_GET_PDR_MIN_RESP_BYTES;
			if (*resp_len < msg_sz) return PLDM_ERROR_INVALID_LENGTH;
			memcpy(resp, msg, msg_sz);
			*resp_len = msg_sz;
			return PLDM_PLATFORM_INVALID_DATA_TRANSFER_HANDLE;
		}
	} else {
		if (transfer_op_flag != 0x00) {
			PLDM_MSG_BUFFER(msg_buf, MCTP_PAYLOAD_MAX);
			memset(msg_buf, 0, sizeof(msg_buf));
			struct pldm_msg *msg = (struct pldm_msg *)msg_buf;
			int enc = encode_get_pdr_resp(hdr->instance, PLDM_PLATFORM_INVALID_DATA_TRANSFER_HANDLE, 0, 0, PLDM_PLATFORM_TRANSFER_START_AND_END, 0, NULL, 0, msg);
			if (enc != PLDM_SUCCESS) return enc;
			size_t msg_sz = sizeof(struct pldm_msg_hdr) + PLDM_GET_PDR_MIN_RESP_BYTES;
			if (*resp_len < msg_sz) return PLDM_ERROR_INVALID_LENGTH;
			memcpy(resp, msg, msg_sz);
			*resp_len = msg_sz;
			return PLDM_PLATFORM_INVALID_DATA_TRANSFER_HANDLE;
		}
	}

	/* find record data in __pdr_data[] */
	const uint8_t *record_ptr = NULL;
	size_t record_size = 0;
	uint32_t next_record_handle = 0;
	if (record_hndl == 0) {
		find_pdr_record_by_handle(0, &record_ptr, &record_size, &next_record_handle);
	} else {
		find_pdr_record_by_handle(record_hndl, &record_ptr, &record_size, &next_record_handle);
	}

	if (!record_ptr || record_size == 0) {
		PLDM_MSG_BUFFER(msg_buf, MCTP_PAYLOAD_MAX);
		memset(msg_buf, 0, sizeof(msg_buf));
		struct pldm_msg *msg = (struct pldm_msg *)msg_buf;
		rc = encode_get_pdr_resp(hdr->instance, PLDM_PLATFORM_INVALID_RECORD_HANDLE, 0, 0, PLDM_PLATFORM_TRANSFER_START_AND_END, 0, NULL, 0, msg);
		if (rc != PLDM_SUCCESS)
			return rc;
		size_t msg_sz = sizeof(struct pldm_msg_hdr) + PLDM_GET_PDR_MIN_RESP_BYTES;
		if (*resp_len < msg_sz)
			return PLDM_ERROR_INVALID_LENGTH;
		memcpy(resp, msg, msg_sz);
		*resp_len = msg_sz;
		return PLDM_PLATFORM_INVALID_RECORD_HANDLE;
	}

	/* Calculate maximum available bytes for record_data taking MCTP baseline into account */
	size_t header_overhead = sizeof(struct pldm_msg_hdr) + (sizeof(struct pldm_get_pdr_resp) - 1);
	/* Reserve one byte for the leading MCTP type byte which is prepended
	 * when calling `mctp_message_tx()`. Ensure the encoded PLDM message
	 * plus that leading byte does not exceed the binding MTU. */
	size_t mctp_payload_max = (MCTP_PAYLOAD_MAX > 0) ? (MCTP_PAYLOAD_MAX - 1) : 0;
	size_t max_data_by_mctp = (mctp_payload_max > header_overhead) ? (mctp_payload_max - header_overhead) : 0;

	if (*resp_len > 0) {
		size_t avail = *resp_len;
		if (avail > header_overhead) {
			size_t max_by_buf = avail - header_overhead;
			if (max_by_buf < max_data_by_mctp) max_data_by_mctp = max_by_buf;
		} else {
			max_data_by_mctp = 0;
		}
	}

	uint16_t resp_cnt = request_cnt;
	if (resp_cnt > (uint16_t)max_data_by_mctp) resp_cnt = (uint16_t)max_data_by_mctp;

	size_t record_payload_size = record_size - 10;

	/* If the request asks for the whole record (or more), ensure resp_cnt
	 * matches the actual record payload size when sending START_AND_END to
	 * avoid encoding beyond the record boundary. */
	if ((size_t)resp_cnt >= record_payload_size) {
		resp_cnt = (uint16_t)record_payload_size;
	}

	uint32_t transfer_offset = 0;
	uint32_t returned_next_transfer_handle = 0;
	uint8_t transfer_flag = PLDM_PLATFORM_TRANSFER_MIDDLE;
	uint8_t transfer_crc = 0;

	if (data_transfer_hndl == 0) {
		/* New transfer */
			if ((size_t)resp_cnt >= record_payload_size) {
			transfer_flag = PLDM_PLATFORM_TRANSFER_START_AND_END;
			transfer_offset = 0;
			returned_next_transfer_handle = 0;
		} else {
			uint32_t h = pdr_xfer_alloc(record_hndl);
			if (h == 0) {
				return PLDM_ERROR; /* no resources */
			}
			transfer_flag = PLDM_PLATFORM_TRANSFER_START;
			transfer_offset = 0;
			returned_next_transfer_handle = h;
		}
	} else {
		struct pdr_xfer_entry *e = pdr_xfer_find(data_transfer_hndl);
		if (!e) {
			PLDM_MSG_BUFFER(msg_buf, MCTP_PAYLOAD_MAX);
			memset(msg_buf, 0, sizeof(msg_buf));
			struct pldm_msg *msg = (struct pldm_msg *)msg_buf;
			rc = encode_get_pdr_resp(hdr->instance, PLDM_PLATFORM_INVALID_DATA_TRANSFER_HANDLE, 0, 0, PLDM_PLATFORM_TRANSFER_START_AND_END, 0, NULL, 0, msg);
			if (rc != PLDM_SUCCESS) return rc;
			size_t msg_sz = sizeof(struct pldm_msg_hdr) + PLDM_GET_PDR_MIN_RESP_BYTES;
			if (*resp_len < msg_sz) return PLDM_ERROR_INVALID_LENGTH;
			memcpy(resp, msg, msg_sz);
			*resp_len = msg_sz;
			return PLDM_PLATFORM_INVALID_DATA_TRANSFER_HANDLE;
		}
		if (e->record_handle != record_hndl) {
			PLDM_MSG_BUFFER(msg_buf, MCTP_PAYLOAD_MAX);
			memset(msg_buf, 0, sizeof(msg_buf));
			struct pldm_msg *msg = (struct pldm_msg *)msg_buf;
			rc = encode_get_pdr_resp(hdr->instance, PLDM_PLATFORM_INVALID_RECORD_HANDLE, 0, 0, PLDM_PLATFORM_TRANSFER_START_AND_END, 0, NULL, 0, msg);
			if (rc != PLDM_SUCCESS) return rc;
			size_t msg_sz = sizeof(struct pldm_msg_hdr) + PLDM_GET_PDR_MIN_RESP_BYTES;
			if (*resp_len < msg_sz) return PLDM_ERROR_INVALID_LENGTH;
			memcpy(resp, msg, msg_sz);
			*resp_len = msg_sz;
			return PLDM_PLATFORM_INVALID_RECORD_HANDLE;
		}
		transfer_offset = e->offset;
		size_t remaining = record_payload_size - transfer_offset;
		if (resp_cnt > remaining) resp_cnt = (uint16_t)remaining;
		/* Safety: if resp_cnt becomes zero while there is remaining data,
		 * make forward progress by returning at least one byte. This
		 * prevents a stuck transfer where the same handle is returned
		 * repeatedly with zero-length payload. */
		if ((resp_cnt == 0) && (remaining > 0)) {
			LOG_WRN("GetPDR: resp_cnt clamped to zero but %zu bytes remain, returning 1", remaining);
			resp_cnt = (uint16_t)MIN(remaining, (size_t)1);
		}
		if (transfer_offset + resp_cnt >= record_payload_size) {
			transfer_flag = PLDM_PLATFORM_TRANSFER_END;
			returned_next_transfer_handle = 0;
			transfer_crc = pldm_edac_crc8(record_ptr + 10, record_payload_size);
			pdr_xfer_free_handle(e->handle);
		} else {
			transfer_flag = PLDM_PLATFORM_TRANSFER_MIDDLE;
			returned_next_transfer_handle = e->handle;
			e->offset = transfer_offset + resp_cnt;
			e->expiry_ms = k_uptime_get_32() + 60000u;
		}
	}

	PLDM_MSG_BUFFER(msg_buf, MCTP_PAYLOAD_MAX);
	memset(msg_buf, 0, sizeof(msg_buf));
	struct pldm_msg *msg = (struct pldm_msg *)msg_buf;
	const uint8_t *record_payload = record_ptr + 10 + transfer_offset;

	rc = encode_get_pdr_resp(hdr->instance, PLDM_SUCCESS, next_record_handle, returned_next_transfer_handle, transfer_flag, resp_cnt, record_payload, transfer_crc, msg);
	if (rc != PLDM_SUCCESS) return rc;

	/* compute encoded message size */
	size_t msg_size = sizeof(struct pldm_msg_hdr) + (sizeof(struct pldm_get_pdr_resp) - 1) + resp_cnt + ((transfer_flag == PLDM_PLATFORM_TRANSFER_END) ? 1 : 0);

	/* Ensure the final unescaped MCTP payload (leading MCTP type byte + encoded PLDM msg)
	 * fits into the binding MTU. If it doesn't, reduce `resp_cnt` and re-encode until it does.
	 * This handles off-by-one cases where an END CRC or header layout pushes the packet
	 * just over the `MCTP_PAYLOAD_MAX` boundary. */
	while ((1 + msg_size) > MCTP_PAYLOAD_MAX) {
		if (resp_cnt == 0) {
			/* cannot make any forward progress */
			LOG_WRN("GetPDR: cannot fit any payload into MCTP_PAYLOAD_MAX=%u", MCTP_PAYLOAD_MAX);
			return PLDM_ERROR;
		}
		/* shrink returned data by one byte and recompute transfer semantics */
		resp_cnt--;
		/* recompute transfer flag / next handle / crc depending on new resp_cnt */
		if ((transfer_offset + resp_cnt) >= record_payload_size) {
			transfer_flag = PLDM_PLATFORM_TRANSFER_END;
			returned_next_transfer_handle = 0;
			transfer_crc = pldm_edac_crc8(record_ptr + 10, record_payload_size);
		} else {
			/* not the end anymore */
			transfer_crc = 0;
			if (data_transfer_hndl == 0) {
				/* new transfer: ensure we have an allocation for continuation */
				if (returned_next_transfer_handle == 0) {
					uint32_t h = pdr_xfer_alloc(record_hndl);
					if (h == 0) return PLDM_ERROR;
					returned_next_transfer_handle = h;
				}
				transfer_flag = PLDM_PLATFORM_TRANSFER_START;
				struct pdr_xfer_entry *ne = pdr_xfer_find(returned_next_transfer_handle);
				if (ne) {
					ne->offset = resp_cnt;
					ne->expiry_ms = k_uptime_get_32() + 60000u;
				}
			} else {
				/* continuation: keep using the provided handle if available */
				struct pdr_xfer_entry *e = pdr_xfer_find(data_transfer_hndl);
				if (e) {
					returned_next_transfer_handle = e->handle;
					e->offset = transfer_offset + resp_cnt;
					e->expiry_ms = k_uptime_get_32() + 60000u;
				} else {
					/* allocate a new continuation handle if original entry vanished */
					uint32_t h = pdr_xfer_alloc(record_hndl);
					if (h == 0) return PLDM_ERROR;
					returned_next_transfer_handle = h;
					struct pdr_xfer_entry *ne = pdr_xfer_find(returned_next_transfer_handle);
					if (ne) {
						ne->offset = transfer_offset + resp_cnt;
						ne->expiry_ms = k_uptime_get_32() + 60000u;
					}
				}
				transfer_flag = PLDM_PLATFORM_TRANSFER_MIDDLE;
			}
		}

		/* re-encode with the smaller resp_cnt */
		memset(msg_buf, 0, sizeof(msg_buf));
		rc = encode_get_pdr_resp(hdr->instance, PLDM_SUCCESS, next_record_handle, returned_next_transfer_handle, transfer_flag, resp_cnt, record_payload, transfer_crc, msg);
		if (rc != PLDM_SUCCESS) return rc;
		msg_size = sizeof(struct pldm_msg_hdr) + (sizeof(struct pldm_get_pdr_resp) - 1) + resp_cnt + ((transfer_flag == PLDM_PLATFORM_TRANSFER_END) ? 1 : 0);
	}

	if (*resp_len < msg_size) return PLDM_ERROR_INVALID_LENGTH;
	memcpy(resp, msg, msg_size);

	/* If we allocated a transfer handle for a START fragment, record
	 * the number of bytes we returned so the next continuation will
	 * begin after this offset. */
	if (returned_next_transfer_handle != 0 && transfer_flag == PLDM_PLATFORM_TRANSFER_START) {
		struct pdr_xfer_entry *e = pdr_xfer_find(returned_next_transfer_handle);
		if (e) {
			e->offset = resp_cnt;
			e->expiry_ms = k_uptime_get_32() + 60000u;
		}
	}
	*resp_len = msg_size;
	return PLDM_SUCCESS;
}

/**
 * @brief Handle PLDM Find PDR command
 * 
 * This function processes the PLDM Find PDR command
 * and generates an appropriate response.
 * 
 * @param hdr Pointer to the PLDM header info structure.
 * @param req_msg Pointer to the incoming PLDM request message.
 * @param req_len Length of the incoming PLDM request message.
 * @param resp Pointer to the buffer for the PLDM response message.
 * @param resp_len Pointer to the length of the response buffer; updated with actual response length
 * @return PLDM_SUCCESS on success, or appropriate PLDM error code on failure.
 */
int handle_platform_find_pdr(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	/* an Unsupported Command completion
	 * code and write the minimal PLDM response (completion code only) into the
	 * provided response buffer so the caller can transmit it. */
	if (!hdr || !req_msg || !resp || !resp_len) {
		return PLDM_ERROR_INVALID_DATA;
	}
	PLDM_MSG_BUFFER(msg_buf, MCTP_PAYLOAD_MAX);
	memset(msg_buf, 0, sizeof(msg_buf));
	struct pldm_msg *msg = (struct pldm_msg *)msg_buf;
	struct pldm_header_info header = {0};
	header.msg_type = PLDM_RESPONSE;
	header.instance = hdr->instance;
	header.pldm_type = PLDM_PLATFORM;
	header.command = PLDM_FIND_PDR;
	if (pack_pldm_header(&header, &msg->hdr) != PLDM_SUCCESS) return PLDM_ERROR;
	msg->payload[0] = PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
	size_t msg_sz = sizeof(struct pldm_msg_hdr) + 1;
	if (*resp_len < msg_sz) return PLDM_ERROR_INVALID_LENGTH;
	memcpy(resp, msg, msg_sz);
	*resp_len = msg_sz;
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

/**
 * @brief Handle PLDM Run Init Agent command
 * 
 * This function processes the PLDM Run Init Agent command
 * and generates an appropriate response.
 * 
 * @param hdr Pointer to the PLDM header info structure.
 * @param req_msg Pointer to the incoming PLDM request message.
 * @param req_len Length of the incoming PLDM request message.
 * @param resp Pointer to the buffer for the PLDM response message.
 * @param resp_len Pointer to the length of the response buffer; updated with actual response length
 * @return PLDM_SUCCESS on success, or appropriate PLDM error code on failure.
 */
int handle_platform_run_init_agent(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	/* Command is optional; respond with ERROR_UNSUPPORTED_PLDM_CMD (minimal
	 * completion-code-only PLDM response) so the caller can transmit it. */
	if (!hdr || !req_msg || !resp || !resp_len) {
		return PLDM_ERROR_INVALID_DATA;
	}
	PLDM_MSG_BUFFER(msg_buf, MCTP_PAYLOAD_MAX);
	memset(msg_buf, 0, sizeof(msg_buf));
	struct pldm_msg *msg = (struct pldm_msg *)msg_buf;
	struct pldm_header_info header = {0};
	header.msg_type = PLDM_RESPONSE;
	header.instance = hdr->instance;
	header.pldm_type = hdr->pldm_type;
	header.command = PLDM_RUN_INIT_AGENT;
	if (pack_pldm_header(&header, &msg->hdr) != PLDM_SUCCESS) return PLDM_ERROR;
	msg->payload[0] = PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
	size_t msg_sz = sizeof(struct pldm_msg_hdr) + 1;
	if (*resp_len < msg_sz) return PLDM_ERROR_INVALID_LENGTH;
	memcpy(resp, msg, msg_sz);
	*resp_len = msg_sz;
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

/**
 * @brief Handle PLDM Get PDR Repository Signature command
 * 
 * This function processes the PLDM Get PDR Repository Signature command
 * and generates an appropriate response.
 * 
 * @param hdr Pointer to the PLDM header info structure.
 * @param req_msg Pointer to the incoming PLDM request message.
 * @param req_len Length of the incoming PLDM request message.
 * @param resp Pointer to the buffer for the PLDM response message.
 * @param resp_len Pointer to the length of the response buffer; updated with actual response length
 * @return PLDM_SUCCESS on success, or appropriate PLDM error code on failure.
 */
int handle_platform_get_pdr_repository_signature(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	/* Optional command; return ERROR_UNSUPPORTED_PLDM_CMD with a minimal
	 * completion-code-only PLDM response. */
	if (!hdr || !req_msg || !resp || !resp_len) {
		return PLDM_ERROR_INVALID_DATA;
	}
	PLDM_MSG_BUFFER(msg_buf, MCTP_PAYLOAD_MAX);
	memset(msg_buf, 0, sizeof(msg_buf));
	struct pldm_msg *msg = (struct pldm_msg *)msg_buf;
	struct pldm_header_info header = {0};
	header.msg_type = PLDM_RESPONSE;
	header.instance = hdr->instance;
	header.pldm_type = PLDM_PLATFORM;
	header.command = PLDM_GET_PDR_REPOSITORY_SIGNATURE;
	if (pack_pldm_header(&header, &msg->hdr) != PLDM_SUCCESS) return PLDM_ERROR;
	msg->payload[0] = PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
	size_t msg_sz = sizeof(struct pldm_msg_hdr) + 1;
	if (*resp_len < msg_sz) return PLDM_ERROR_INVALID_LENGTH;
	memcpy(resp, msg, msg_sz);
	*resp_len = msg_sz;
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}
