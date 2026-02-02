#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <stddef.h>

#include <libpldm/control.h>
/* Include the internal control definition so tests can allocate storage */
#include "control-internal.h"

/* Adapter provided by tests/handle_pldm_adapter.c */
int handle_pldm_message(struct pldm_control *control, const void *req_msg,
                        size_t req_len, void *resp_msg, size_t *resp_len);

/* Simple test runner: reads a JSON array of objects with keys:
 *  - "msg": hex string for request message
 *  - "expected": hex string for expected response
 *  - "rc": integer expected return code
 *
 * This is a very small, tolerant JSON scanner (not a full parser) that
 * expects well-formed test files under tests/pldm_tb/tests.json.
 */

static void hex_to_bytes(const char *hex, uint8_t *out, size_t *out_len)
{
    size_t hlen = strlen(hex);
    size_t i = 0, j = 0;
    while (i < hlen) {
        while (i < hlen && isspace((unsigned char)hex[i])) i++;
        if (i >= hlen) break;
        int hi = tolower((unsigned char)hex[i]);
        if (hi >= '0' && hi <= '9') hi = hi - '0'; else hi = hi - 'a' + 10;
        i++;
        while (i < hlen && isspace((unsigned char)hex[i])) i++;
        if (i >= hlen) break;
        int lo = tolower((unsigned char)hex[i]);
        if (lo >= '0' && lo <= '9') lo = lo - '0'; else lo = lo - 'a' + 10;
        i++;
        out[j++] = (uint8_t)((hi << 4) | (lo & 0xf));
    }
    *out_len = j;
}

static char *read_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(sz + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, sz, f) != (size_t)sz) { fclose(f); free(buf); return NULL; }
    buf[sz] = '\0';
    fclose(f);
    return buf;
}

/* Find next JSON string value for key (e.g., "msg") starting at `p`.
 * Returns pointer to allocated string (caller frees) or NULL. */
static char *find_json_str(const char *p, const char *key)
{
    const char *kp = strstr(p, key);
    if (!kp) return NULL;
    const char *colon = strchr(kp, ':');
    if (!colon) return NULL;
    const char *quote = strchr(colon, '"');
    if (!quote) return NULL;
    quote++;
    const char *end = quote;
    while (*end && *end != '"') end++;
    size_t len = end - quote;
    char *out = malloc(len + 1);
    if (!out) return NULL;
    memcpy(out, quote, len);
    out[len] = '\0';
    return out;
}

static int find_json_int(const char *p, const char *key, int *val)
{
    const char *kp = strstr(p, key);
    if (!kp) return 0;
    const char *colon = strchr(kp, ':');
    if (!colon) return 0;
    int n; if (sscanf(colon + 1, " %d", &n) != 1) return 0;
    *val = n; return 1;
}

int main(int argc, char **argv)
{
    const char *path = "tests.json";
    int verbose = 0;
    if (argc > 1) path = argv[1];
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) verbose = 1;
    }

    char *json = read_file(path);
    if (!json) { fprintf(stderr, "Failed to read %s\n", path); return 2; }

    /* Create a simple pldm_control and call pldm_control_setup */
    unsigned char ctrl_buf[sizeof(struct pldm_control)];
    struct pldm_control *ctrl = (struct pldm_control *)ctrl_buf;
    int rc = pldm_control_setup(ctrl, sizeof(*ctrl));
    if (rc != 0) { fprintf(stderr, "pldm_control_setup() failed: %d\n", rc); free(json); return 3; }

    /* Ensure the control has PLDM Base version information available for
     * GetPLDMVersion requests. Use uint32_t array (little-endian layout)
     * to avoid converting large integer literals into the packed
     * ver32_t struct which produced overflow warnings. */
    uint32_t base_versions[] = { 0xf1f1f000u, 0x539dbebau };
    /* Provide a commands bitfield for PLDM Base so GetPLDMCommands can
     * return which commands are supported. The library's control
     * implementation ignores the requested `version` field currently
     * (SelectPLDMVersion isn't implemented), so we only need to supply
     * the commands buffer here. */
    bitfield8_t base_commands[32];
    memset(base_commands, 0, sizeof(base_commands));
    /* Mark support for GET_TID, GET_PLDM_VERSION, GET_PLDM_TYPES,
     * GET_PLDM_COMMANDS */
    base_commands[PLDM_GET_TID / 8].byte |= (1 << (PLDM_GET_TID % 8));
    base_commands[PLDM_GET_PLDM_VERSION / 8].byte |= (1 << (PLDM_GET_PLDM_VERSION % 8));
    base_commands[PLDM_GET_PLDM_TYPES / 8].byte |= (1 << (PLDM_GET_PLDM_TYPES % 8));
    base_commands[PLDM_GET_PLDM_COMMANDS / 8].byte |= (1 << (PLDM_GET_PLDM_COMMANDS % 8));

    rc = pldm_control_add_type(ctrl, PLDM_BASE, base_versions, 2, base_commands);
    if (rc != 0) { fprintf(stderr, "pldm_control_add_type() failed: %d\n", rc); free(json); return 4; }

    /* Iterate through occurrences of "message" in the JSON */
    const char *p = json;
    int test_no = 0;
    int failed = 0;
    while ((p = strstr(p, "\"message\"")) != NULL) {
        /* Find the start of the enclosing JSON object so we search for
         * other keys (name/expected/completion_code) within the same
         * object rather than the next one. */
        const char *obj_start = json;
        for (const char *q = json; q < p; ++q) {
            if (*q == '{') obj_start = q;
        }
        char *name = find_json_str(obj_start, "\"name\"");
        char *message_hex = find_json_str(p, "\"message\"");
        char *exp_hex = find_json_str(obj_start, "\"expected\"");
        int exp_completion = 0; find_json_int(obj_start, "\"completion_code\"", &exp_completion);

        if (!message_hex) break;
        uint8_t msg_buf[1024]; size_t msg_len=0;
        hex_to_bytes(message_hex, msg_buf, &msg_len);

        uint8_t resp_buf[1024]; size_t resp_len = sizeof(resp_buf);
        int rc = handle_pldm_message(ctrl, msg_buf, msg_len, resp_buf, &resp_len);

        int ok = 1;
        if (rc != exp_completion) ok = 0;
        if (exp_hex) {
            uint8_t exp_buf[1024]; size_t exp_len=0;
            hex_to_bytes(exp_hex, exp_buf, &exp_len);
            if (exp_len != resp_len) ok = 0;
            else if (memcmp(exp_buf, resp_buf, exp_len) != 0) ok = 0;
        }

        /* Build response hex string */
        char resp_hex_str[4096]; size_t rhp = 0;
        for (size_t i=0;i<resp_len && rhp + 3 < sizeof(resp_hex_str); i++) {
            rhp += snprintf(resp_hex_str + rhp, sizeof(resp_hex_str) - rhp, "%02x", resp_buf[i]);
        }
        resp_hex_str[rhp] = '\0';

        printf("test %d (%s): %s\n", ++test_no, name ? name : "(unnamed)", ok ? "PASS" : "FAIL");
        if (verbose || !ok) {
            failed += !ok;
            printf("  input: %s\n", message_hex);
            printf("  expected completion_code=%d\n", exp_completion);
            printf("  expected resp: %s\n", exp_hex ? exp_hex : "(null)");
            printf("  got rc=%d, resp_len=%zu\n", rc, resp_len);
            printf("  got resp: %s\n", resp_hex_str);
        }
        free(message_hex); free(exp_hex); if (name) free(name);
        p = p + 9; /* move past this occurrence */
    }

    free(json);
    if (failed) {
        printf("%d tests failed\n", failed);
        return 1;
    }
    printf("all %d tests passed\n", test_no);
    return 0;
}
