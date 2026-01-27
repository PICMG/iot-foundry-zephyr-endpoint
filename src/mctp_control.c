/**
 * @file mctp_control.c
 * @brief MCTP Control Message handling for Zephyr MCTP Endpoints.
 * 
 * This file implements the handling of MCTP control messages
 * such as Set Endpoint ID, Get Endpoint ID, Get MCTP Version Support, 
 * and Get Message Type Support.
 * It provides functions to process incoming control messages
 * and send appropriate responses.
 * 
 * @author Doug Sandy
 * @date January 2026
 * 
 */
#include <stdio.h>
#include <zephyr/types.h>
#include <libmctp.h>
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include <string.h>
#include "mctp_control.h"

LOG_MODULE_REGISTER(mctp_control, LOG_LEVEL_DBG);


// structures for maintaining supported versions per message type
#ifndef MCTP_MAX_MSG_TYPES
#define MCTP_MAX_MSG_TYPES 4
#endif

#ifndef MCTP_MAX_VERSIONS_PER_TYPE
#define MCTP_MAX_VERSIONS_PER_TYPE 8
#endif

struct mctp_versions_entry {
    uint8_t used;
    uint8_t msg_type;
    struct mctp_version_entry entries[MCTP_MAX_VERSIONS_PER_TYPE];
    size_t count;
};

static bool mctp_versions_initialized = false;
static struct mctp_versions_entry mctp_versions_map[MCTP_MAX_MSG_TYPES];

// Control message request/response structures
struct control_msg_request {
    uint8_t ic_msg_type;
    uint8_t rq_dgram_inst;
    uint8_t command_code;
} __packed;

struct set_endpoint_id_request {
    uint8_t ic_msg_type;
    uint8_t rq_dgram_inst;
    uint8_t command_code;
    uint8_t operation;
    uint8_t endpoint_id;
} __packed;

struct set_endpoint_id_response {
    uint8_t ic_msg_type;
    uint8_t rq_dgram_inst;
    uint8_t command_code;
    uint8_t completion_code;
    uint8_t status;
    uint8_t eid_setting;
    uint8_t eid_pool_size;
} __packed;

struct get_endpoint_id_request {
    uint8_t ic_msg_type;
    uint8_t rq_dgram_inst;
    uint8_t command_code;
} __packed;

struct get_endpoint_id_response {
    uint8_t ic_msg_type;
    uint8_t rq_dgram_inst;
    uint8_t command_code;
    uint8_t completion_code;
    uint8_t endpoint_id;
    uint8_t endpoint_type;
    uint8_t medium_specific;
} __packed;

struct get_mctp_version_support_request {
    uint8_t ic_msg_type;
    uint8_t rq_dgram_inst;
    uint8_t command_code;
    uint8_t msg_type;
} __packed;

struct get_mctp_version_support_response {
    uint8_t ic_msg_type;
    uint8_t rq_dgram_inst;
    uint8_t command_code;
    uint8_t completion_code;
    uint8_t version_number_entry_count;
    struct mctp_version_entry versions[MCTP_MAX_VERSIONS_PER_TYPE];
} __packed;

struct get_message_type_support_request {
    uint8_t ic_msg_type;
    uint8_t rq_dgram_inst;
    uint8_t command_code;
} __packed;

struct get_message_type_support_response {
    uint8_t ic_msg_type;
    uint8_t rq_dgram_inst;
    uint8_t command_code;
    uint8_t completion_code;
    uint8_t type_count;
    uint8_t types[MCTP_MAX_MSG_TYPES];
} __packed;

struct control_completion_response {
    uint8_t ic_msg_type;
    uint8_t rq_dgram_inst;
    uint8_t command_code;
    uint8_t completion_code;
} __packed;

/**
 * TODO:
 * the currently version of libmctp supported by zephyr does not include a mechanism to
 * set the eid of a bus without releasing and re-registering the bus.  For control messages
 * that need to report/change the current eid, we need access to the mctp struct.  For now, we
 * duplicated the relevant mctp struct definitions here to allow access to the eid field.
 * This should be removed when libmctp is updated to include a proper API for this. 
 */
/* When running the posix unit test build the minimal `struct mctp` and
 * access macros are provided by `mctp_control.h`. Avoid redefining them
 * here to prevent duplicate-definition errors.
 */
#ifndef MCTP_POSIX_UNIT_TEST
struct mctp_bus {
    mctp_eid_t eid;
};

struct mctp {
    int n_busses;
    struct mctp_bus *busses;
};

// Macro to get/set EID from/in mctp struct
/* TODO - update, but don't replace when libmctp is updated */
#define GET_EID_FROM_MCTP(mctp_ptr) (((struct mctp_bus *)(mctp_ptr->busses))->eid)
#define SET_EID_IN_MCTP(mctp_ptr, new_eid) ((((struct mctp_bus *)(mctp_ptr->busses))->eid) = (new_eid))
/* end TODO */
#endif /* MCTP_POSIX_UNIT_TEST */

/**
 * @brief Send a control completion response message.
 * 
 * Constructs and sends a control completion response message
 * with the specified parameters.
 * 
 * @param mctp Pointer to the MCTP instance.
 * @param remote_eid The destination endpoint ID for the response.
 * @param tag_owner The tag owner bit for the response.
 * @param msg_tag The message tag for the response.
 * @param command_code The command code of the original request.
 * @param completion_code The completion code to include in the response.
 */
static void send_control_completion_response(struct mctp *mctp, uint8_t remote_eid, bool tag_owner, uint8_t msg_tag, const void *msg, size_t len, uint8_t completion_code) {
    if (len<sizeof(struct control_msg_request)) {
        // silently drop packet
        return;
    }
    struct control_msg_request *req = (struct control_msg_request *)msg;
    struct control_completion_response resp;
    resp.ic_msg_type = req->ic_msg_type;
    resp.rq_dgram_inst = req->rq_dgram_inst & ~0x80;  // clear request bit
    resp.command_code = req->command_code;
    resp.completion_code = completion_code;

    // send the response
    mctp_message_tx(mctp, remote_eid, !tag_owner, msg_tag,
                    &resp, sizeof(struct control_completion_response));        
}

/**
 * @brief Initialize the MCTP versions map with default entries.
 * 
 * This function populates the versions map with predefined
 * version entries for supported MCTP message types.
 * 
 * This function is called internally to set up the initial state
 * of the versions map before any other operations are performed.
 */
static void initialize_versions_map(void)
{
    for (size_t i = 0; i < MCTP_MAX_MSG_TYPES; i++) {
        mctp_versions_map[i].used = 0;
        mctp_versions_map[i].count = 0;
    }
    mctp_versions_initialized = true;

    mctp_versions_map_add(0x00, &(struct mctp_version_entry){ .major_version = 0xf1, .minor_version = 0xf0, .update_version = 0xff, .alpha_version = 0 });
    mctp_versions_map_add(0x00, &(struct mctp_version_entry){ .major_version = 0xf1, .minor_version = 0xf1, .update_version = 0xff, .alpha_version = 0 });
    mctp_versions_map_add(0x00, &(struct mctp_version_entry){ .major_version = 0xf1, .minor_version = 0xf2, .update_version = 0xff, .alpha_version = 0 });
    mctp_versions_map_add(0x00, &(struct mctp_version_entry){ .major_version = 0xf1, .minor_version = 0xf3, .update_version = 0xf1, .alpha_version = 0 });
}

/**
 * @brief Add a version entry for a given MCTP message type.
 * 
 * Adds the specified version entry to the versions map
 * 
 * @param msg_type The MCTP message type to add the version for.
 * @param ver Pointer to the version entry to add.
 * @return int 0 on success, -1 on failure (no slot or capacity).
 */
int mctp_versions_map_add(uint8_t msg_type, const struct mctp_version_entry *ver)
{
    if (!ver) return -1;

    if (!mctp_versions_initialized) {
        initialize_versions_map();
        mctp_versions_initialized = true;
    }

    /* find existing */
    int idx = -1;
    for (size_t i = 0; i < MCTP_MAX_MSG_TYPES; i++) {
        if (mctp_versions_map[i].used && mctp_versions_map[i].msg_type == msg_type) {
            idx = (int)i;
            break;
        }
    }

    /* create new slot if not found */
    if (idx < 0) {
        for (size_t i = 0; i < MCTP_MAX_MSG_TYPES; i++) {
            if (!mctp_versions_map[i].used) {
                mctp_versions_map[i].used = 1;
                mctp_versions_map[i].msg_type = msg_type;
                mctp_versions_map[i].count = 0;
                idx = (int)i;
                break;
            }
        }
    }

    if (idx < 0) 
        return -1; /* no slot available */

    if (mctp_versions_map[idx].count >= MCTP_MAX_VERSIONS_PER_TYPE) 
        return -1; /* full */

    mctp_versions_map[idx].entries[mctp_versions_map[idx].count++] = *ver;
    return 0;
}

/**
 * @brief Retrieve the versions entry for a given MCTP message type.
 * 
 * Searches the versions map for the specified message type
 * and returns a pointer to the corresponding versions entry.
 * 
 * @param msg_type The MCTP message type to look up.
 * @return struct mctp_versions_entry* Pointer to the versions entry if found, NULL otherwise.
 */
struct mctp_versions_entry *mctp_versions_map_get(uint8_t msg_type)
{
    if (!mctp_versions_initialized) {
        initialize_versions_map();
        mctp_versions_initialized = true;
    }

    for (size_t i = 0; i < MCTP_MAX_MSG_TYPES; i++) {
        if (mctp_versions_map[i].used && mctp_versions_map[i].msg_type == msg_type) {
            return &mctp_versions_map[i];
        }
    }
    return NULL;
}

/**
 * @brief Handle a Set Endpoint ID control request.
 *
 * Attempts to set the endpoint ID as requested in the message payload.
 * Sends a response indicating success or failure.
 * 
 * @param mctp Pointer to the MCTP instance.
 * @param remote_eid The source endpoint ID of the message sender.
 * @param tag_owner The tag owner bit of the message.
 * @param msg_tag The message tag of the message.
 * @param data Pointer to the message payload.
 * @param msg Pointer to the full message including header.
 * @param len Length of the message in bytes.
 * @return int CONTROL_COMPLETE_SUCCESS on success, error code otherwise.
 */
static int process_set_endpoint_id_control_message(struct mctp *mctp, uint8_t remote_eid, bool tag_owner, uint8_t msg_tag, const void *msg, uint16_t len) {
    const struct set_endpoint_id_request *req = (const struct set_endpoint_id_request *)msg;
    if (len < sizeof(struct set_endpoint_id_request)) {
        return CONTROL_COMPLETE_INVALID_LENGTH;
    }

    // get the requested endpoint id from the message payload
    if ((req->operation & 0x03) == 0x02) {
        // this is a request to reset static EID value.  Since this endpoint does
        // not support static ID values, the proper response is to send an
        // ERROR_INVALID_DATA response
        return CONTROL_COMPLETE_INVALID_DATA;
    } 
    if ((req->operation & 0x03) == 0x03) {
        // this is a request to set discovery flag.  Since this endpoint does
        // not support discovery flag, the proper response is to send an
        // ERROR_INVALID_DATA response
        return CONTROL_COMPLETE_INVALID_DATA;
    } 
    if ((req->endpoint_id == MCTP_EID_NULL) || (req->endpoint_id == MCTP_EID_BROADCAST)) {
        return CONTROL_COMPLETE_INVALID_DATA;
    } 

    // attempt to set the endpoint ID
    SET_EID_IN_MCTP(mctp, req->endpoint_id);
    LOG_INF("Set Endpoint ID to %u", req->endpoint_id);

    // message body for response
    struct set_endpoint_id_response resp;
    resp.ic_msg_type = req->ic_msg_type;
    resp.rq_dgram_inst = req->rq_dgram_inst & ~0x80;  // clear request bit
    resp.command_code = req->command_code;
    resp.completion_code = CONTROL_COMPLETE_SUCCESS;
    resp.eid_setting = req->endpoint_id;
    resp.status = 0x00;
    resp.eid_pool_size = 0x00;

    // send the response
    mctp_message_tx(mctp, remote_eid, !tag_owner, msg_tag,
                    &resp, sizeof(struct set_endpoint_id_response));        
    LOG_INF("sent Set Endpoint ID response");

    return CONTROL_COMPLETE_SUCCESS;
}

/**
 * @brief Handle a Get Endpoint ID control request.
 *
 * Responds with the current endpoint ID and type.
 * 
 * @param mctp Pointer to the MCTP instance.
 * @param remote_eid The source endpoint ID of the message sender.
 * @param tag_owner The tag owner bit of the message.
 * @param msg_tag The message tag of the message.
 * @param msg Pointer to the full message including header.
 * @param len Length of the message in bytes.
 * @return int CONTROL_COMPLETE_SUCCESS on success, error code otherwise.
 */
static int process_get_endpoint_id_control_message(struct mctp *mctp, uint8_t remote_eid, bool tag_owner, uint8_t msg_tag, const void *msg, uint16_t len) {
    if (len < sizeof(struct get_endpoint_id_request)) {
        return CONTROL_COMPLETE_INVALID_LENGTH;
    }
    const struct get_endpoint_id_request *req = (const struct get_endpoint_id_request *)msg;

    // message body for response
    struct get_endpoint_id_response resp;
    resp.ic_msg_type = req->ic_msg_type;
    resp.rq_dgram_inst = req->rq_dgram_inst & ~0x80;  // clear request bit
    resp.command_code = req->command_code;
    resp.completion_code = CONTROL_COMPLETE_SUCCESS;
    resp.endpoint_id = GET_EID_FROM_MCTP(mctp);
    resp.endpoint_type = 0x00;   // simple, dynamic endpoint
    resp.medium_specific = 0x00; // no medium specific info

    // send the response
    mctp_message_tx(mctp, remote_eid, !tag_owner, msg_tag,
                    &resp, sizeof(struct get_endpoint_id_response));        
    return CONTROL_COMPLETE_SUCCESS;
}

/**
 * @brief Handle a Get MCTP Version Support control request.
 *
 * Determines the supported version(s) for the requested message type
 * and constructs a response containing version entries.
 *
 * @param mctp Pointer to the MCTP instance.
 * @param remote_eid The source endpoint ID of the message sender.
 * @param tag_owner The tag owner bit of the message.
 * @param msg_tag The message tag of the message.
 * @param msg Pointer to the full message including header.
 * @param len Length of the message in bytes.
 * @return int CONTROL_COMPLETE_SUCCESS on success, error code otherwise.
 */
static int process_get_mctp_version_support_control_message(struct mctp *mctp, uint8_t remote_eid, bool tag_owner, uint8_t msg_tag, const void *msg, uint16_t len) {
    if (len < sizeof(struct get_mctp_version_support_request)) {
        return CONTROL_COMPLETE_INVALID_LENGTH;
    }
    const struct get_mctp_version_support_request *req = (const struct get_mctp_version_support_request *)msg;

    struct mctp_versions_entry *versions;
    if (req->msg_type==0xff) {
        // version entries for base mctp spec (for us it is the same as control)
        versions = mctp_versions_map_get(0x00);
    } else {
        versions = mctp_versions_map_get(req->msg_type);
    }
    
    if (!versions) {
        // no versions found for requested message type
        return CONTROL_COMPLETE_INVALID_DATA;
    }

    // message body for response
    struct get_mctp_version_support_response resp;
    resp.ic_msg_type = req->ic_msg_type;
    resp.rq_dgram_inst = req->rq_dgram_inst & ~0x80;  // clear request bit
    resp.command_code = req->command_code;
    resp.completion_code = CONTROL_COMPLETE_SUCCESS;
    resp.version_number_entry_count = versions->count;
    for (size_t i = 0; i < versions->count; i++) {
        resp.versions[i] = versions->entries[i];
    }

    // send the response
    mctp_message_tx(mctp, remote_eid, !tag_owner, msg_tag,
                    &resp, sizeof(struct get_mctp_version_support_response)-
                          (MCTP_MAX_VERSIONS_PER_TYPE - versions->count) * sizeof(struct mctp_version_entry));        

    return CONTROL_COMPLETE_SUCCESS;
}

/**
 * @brief Handle a Get Message Type Support control request.
 *
 * Responds with a list of MCTP message types supported by this
 * endpoint (control, PLDM if enabled, etc.).
 *
 * @param mctp Pointer to the MCTP instance.
 * @param remote_eid The source endpoint ID of the message sender.
 * @param tag_owner The tag owner bit of the message.
 * @param msg_tag The message tag of the message.
 * @param msg Pointer to the full message including header.
 * @param len Length of the message in bytes.
 * @return int CONTROL_COMPLETE_SUCCESS on success, error code otherwise.
 */
int process_get_message_type_support_control_message(struct mctp *mctp, uint8_t remote_eid, bool tag_owner, uint8_t msg_tag, const void *msg, uint16_t len) {
    if (len < sizeof(struct get_message_type_support_request)) {
        return CONTROL_COMPLETE_INVALID_LENGTH;
    }
    const struct get_message_type_support_request *req = (const struct get_message_type_support_request *)msg;

    // message body for response
    struct get_message_type_support_response resp;
    resp.ic_msg_type = req->ic_msg_type;
    resp.rq_dgram_inst = req->rq_dgram_inst & ~0x80;  // clear request bit
    resp.command_code = req->command_code;
    resp.completion_code = CONTROL_COMPLETE_SUCCESS;
    
    if (!mctp_versions_initialized) {
        initialize_versions_map();
        mctp_versions_initialized = true;
    }
    resp.type_count = 0;
    for (int i = 0; i < MCTP_MAX_MSG_TYPES; i++) {
        if (mctp_versions_map[i].used) {
            resp.types[resp.type_count++] = mctp_versions_map[i].msg_type;
        }
    }

    // send the response
    mctp_message_tx(mctp, remote_eid, !tag_owner, msg_tag,
                    &resp, sizeof(struct get_message_type_support_response)-
                          (MCTP_MAX_MSG_TYPES - resp.type_count) * sizeof(uint8_t));        

    return CONTROL_COMPLETE_SUCCESS;
}

/**
 * @brief Process an incoming MCTP control message.
 * 
 * Dispatches the control message to the appropriate handler based
 * on the command code in the message header.  
 * 
 * @param remote_eid The source endpoint ID of the message sender.
 * @param tag_owner The tag owner bit of the message.
 * @param msg_tag The message tag of the message.
 * @param msg Pointer to the full message including header.
 * @param len Length of the message in bytes.
 */
int send_control_message(struct mctp *mctp, uint8_t eid, bool tag_owner, uint8_t msg_tag, const void *msg, size_t msg_len)
{
    const struct control_msg_request *hdr = (const struct control_msg_request *)msg;
    if (msg_len < sizeof(struct control_msg_request)) {
        LOG_ERR("Control message too short: %zu", msg_len);
        send_control_completion_response(mctp, eid, tag_owner, msg_tag, msg, msg_len, CONTROL_COMPLETE_INVALID_LENGTH);
        return CONTROL_COMPLETE_INVALID_LENGTH;
    }

    LOG_DBG("Control message: type %u", hdr->command_code);
    int completion_code = CONTROL_COMPLETE_UNSUPPORTED_CMD;
    switch (hdr->command_code) {
        case CONTROL_MSG_SET_ENDPOINT_ID:
            completion_code = process_set_endpoint_id_control_message(mctp, eid, tag_owner, msg_tag, msg, msg_len);
            break;
        case CONTROL_MSG_GET_ENDPOINT_ID:
            completion_code = process_get_endpoint_id_control_message(mctp, eid, tag_owner, msg_tag, msg, msg_len);
            break;
        case CONTROL_MSG_GET_MCTP_VERSION_SUPPORT:
            completion_code = process_get_mctp_version_support_control_message(mctp, eid, tag_owner, msg_tag, msg, msg_len);
            break;
        case CONTROL_MSG_GET_MESSAGE_TYPE_SUPPORT:
            completion_code = process_get_message_type_support_control_message(mctp, eid, tag_owner, msg_tag, msg, msg_len);
            break;
        default:
            LOG_DBG("Unsupported control message: %u", hdr->command_code);
    }
    if (completion_code != CONTROL_COMPLETE_SUCCESS) {
        LOG_DBG("Sending Error Response: %u", completion_code);
        send_control_completion_response(mctp, eid, tag_owner, msg_tag, msg, msg_len, completion_code);
    }
    return completion_code;
}
