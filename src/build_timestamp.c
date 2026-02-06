/**
 * @file build_timestamp.c
 * @brief Build-time timestamp derived from __DATE__ and __TIME__
 *
 * Produces a 13-byte PLDM TIMESTAMP104 value: 8-byte little-endian
 * seconds since epoch followed by 5 zero bytes. The compile-time
 * macros __DATE__ and __TIME__ are parsed to construct the UTC
 * timestamp.
 */
#include <stdint.h>
#include <string.h>
#include "platform.h"
#include <stdio.h>

/* Convert 3-letter month to month number (1-12) */
static int month_str_to_num(const char *m)
{
    if (memcmp(m, "Jan", 3) == 0) return 1;
    if (memcmp(m, "Feb", 3) == 0) return 2;
    if (memcmp(m, "Mar", 3) == 0) return 3;
    if (memcmp(m, "Apr", 3) == 0) return 4;
    if (memcmp(m, "May", 3) == 0) return 5;
    if (memcmp(m, "Jun", 3) == 0) return 6;
    if (memcmp(m, "Jul", 3) == 0) return 7;
    if (memcmp(m, "Aug", 3) == 0) return 8;
    if (memcmp(m, "Sep", 3) == 0) return 9;
    if (memcmp(m, "Oct", 3) == 0) return 10;
    if (memcmp(m, "Nov", 3) == 0) return 11;
    if (memcmp(m, "Dec", 3) == 0) return 12;
    return 0;
}

/* days_from_civil: convert civil date to days since Unix epoch (1970-01-01)
 * Implementation based on Howard Hinnant's algorithm (portable, handles
 * Gregorian proleptic calendar).
 */
static int64_t days_from_civil(int y, unsigned m, unsigned d)
{
    y -= m <= 2;
    const int era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = (unsigned)(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return (int64_t)era * 146097 + (int64_t)doe - 719468;
}

const uint8_t *get_build_timestamp104(void)
{
    static uint8_t ts[13] = {0};
    static int initialized = 0;
    if (initialized) return ts;

    /* Parse __DATE__ "Mmm dd yyyy" and __TIME__ "hh:mm:ss" */
    const char *date = __DATE__; /* e.g. "Feb  6 2026" */
    const char *time = __TIME__; /* e.g. "14:23:05" */

    char month[4] = {0};
    int day = 0;
    int year = 0;
    int hour = 0, min = 0, sec = 0;

    /* Safe sscanf replacement: use sscanf if available */
#if defined(__STDC_LIB_EXT1__) || 1
    sscanf(date, "%3s %d %d", month, &day, &year);
    sscanf(time, "%d:%d:%d", &hour, &min, &sec);
#else
    /* Fallback naive parse (unlikely to be needed) */
    memcpy(month, date, 3);
    day = (date[4] == ' ') ? (date[5] - '0') : ((date[4]-'0')*10 + (date[5]-'0'));
    year = (date[7]-'0')*1000 + (date[8]-'0')*100 + (date[9]-'0')*10 + (date[10]-'0');
    hour = (time[0]-'0')*10 + (time[1]-'0');
    min  = (time[3]-'0')*10 + (time[4]-'0');
    sec  = (time[6]-'0')*10 + (time[7]-'0');
#endif

    int mon = month_str_to_num(month);
    if (mon < 1 || mon > 12) mon = 1;

    int64_t days = days_from_civil(year, (unsigned)mon, (unsigned)day);
    int64_t seconds = days * 86400 + (int64_t)hour * 3600 + (int64_t)min * 60 + sec;

    uint64_t s = (uint64_t)seconds;
    for (int i = 0; i < 8; ++i) {
        ts[i] = (uint8_t)((s >> (8 * i)) & 0xFF);
    }
    /* remaining 5 bytes leave as zero (subseconds/timezone/oem fields) */
    initialized = 1;
    return ts;
}
