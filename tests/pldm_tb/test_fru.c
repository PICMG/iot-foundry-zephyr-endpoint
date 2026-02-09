#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <libpldm/fru.h>
#include <libpldm/edac.h>

/* Include generated FRU table macros and data */
#include "../../src/pdrs/config.h"

int main(void)
{
    int failures = 0;

    /* Test 1: compute CRC over __fru_data and verify non-zero */
    uint32_t crc = 0;
    if (FRU_TOTAL_SIZE > 0) {
        crc = pldm_edac_crc32((const void *)__fru_data, (size_t)FRU_TOTAL_SIZE);
    }
    printf("FRU table length=%d crc=0x%08x\n", FRU_TOTAL_SIZE, crc);
    if (crc == 0) {
        printf("FAIL: FRU CRC is zero (unexpected)\n");
        failures++;
    } else {
        printf("PASS: FRU CRC computed\n");
    }

    /* Test 2: Encode/Get metadata response and decode it back */
    uint8_t msg_buf[256];
    struct pldm_msg *msg = (struct pldm_msg *)msg_buf;
    memset(msg_buf, 0, sizeof(msg_buf));

    uint8_t rc = encode_get_fru_record_table_metadata_resp(0 /*instance*/, PLDM_SUCCESS, 1, 0, FRU_TABLE_MAXIMUM_SIZE, FRU_TOTAL_SIZE, FRU_TOTAL_RECORD_SETS, FRU_NUMBER_OF_RECORDS, crc, msg);
    if (rc != PLDM_SUCCESS) {
        printf("FAIL: encode_get_fru_record_table_metadata_resp() rc=%d\n", rc);
        failures++;
    } else {
        uint8_t completion = 0;
        uint8_t maj=0, min=0;
        uint32_t max_size=0, table_len=0;
        uint16_t total_sets=0, total_records=0;
        uint32_t decoded_crc=0;
        int d = decode_get_fru_record_table_metadata_resp(msg, PLDM_GET_FRU_RECORD_TABLE_METADATA_RESP_BYTES, &completion, &maj, &min, &max_size, &table_len, &total_sets, &total_records, &decoded_crc);
        if (d != PLDM_SUCCESS) {
            printf("FAIL: decode_get_fru_record_table_metadata_resp() rc=%d\n", d);
            failures++;
        } else {
            printf("Decoded: completion=%u table_len=%u crc=0x%08x\n", completion, (unsigned)table_len, decoded_crc);
            if (completion != PLDM_SUCCESS) {
                printf("FAIL: completion code != PLDM_SUCCESS\n"); failures++; }
            if (table_len != FRU_TOTAL_SIZE) { printf("FAIL: table_len mismatch\n"); failures++; }
            if (decoded_crc != crc) { printf("FAIL: checksum mismatch 0x%08x != 0x%08x\n", decoded_crc, crc); failures++; }
            if (failures==0) printf("PASS: metadata encode/decode roundtrip\n");
        }
    }

    if (failures) {
        printf("%d tests failed\n", failures);
        return 1;
    }
    printf("all FRU tests passed\n");
    return 0;
}
