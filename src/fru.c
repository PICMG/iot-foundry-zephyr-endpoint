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
#include <libpldm/pdr.h>
#include <../pldm/src/control-internal.h>
#include "pdrs/config.h"
#include "mctp_control.h"

LOG_MODULE_REGISTER(fru_cmds, LOG_LEVEL_DBG);

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
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
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
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
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
int fru_set_record_table(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
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
int fru_get_record_by_option(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}
