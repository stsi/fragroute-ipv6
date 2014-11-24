#include "config.h"
#include "iputil.h"
#include "err.h"
#include <dnet.h>
#include <errno.h>
#include <stdio.h>

ssize_t
inet_add_option(uint16_t eth_type, void *buf, size_t len,
                int proto, const void *optbuf, size_t optlen)
{
    if (eth_type == ETH_TYPE_IP) {
        return ip_add_option(buf, len, proto, optbuf, optlen);
    } else if (eth_type == ETH_TYPE_IPV6) {
        return ip6_add_option(buf, len, proto, optbuf, optlen);
    } else {
        errno = EINVAL;
        return -1;
    }
}

void
inet_checksum(uint16_t eth_type, void *buf, size_t len)
{
    if (eth_type == ETH_TYPE_IP) {
        return ip_checksum(buf, len);
    } else if (eth_type == ETH_TYPE_IPV6) {
        return ip6_checksum(buf, len);
    }
}

int
raw_ip_opt_parse(int argc, char *argv[], uint8_t *opt_type, uint8_t *opt_len,
        uint8_t *buff, int buff_len)
{
    int i, j;

    if (sscanf(argv[0], "%hhx", opt_type) != 1) {
        warnx("invalid opt_type");
        return -1;
    }
    if (sscanf(argv[1], "%hhx", opt_len) != 1) {
        warnx("invalid opt_len");
        return -1;
    }
    j = 0;
    for (i = 2; i < argc && j < buff_len; ++i, ++j) {
        if (sscanf(argv[i], "%hhx", &buff[j]) != 1) {
            warnx("invalid opt_data");
            return -1;
        }
    }
    if (*opt_len != j + 2) {
        warnx("invalid opt->len (%d) doesn't match data length (%d)",
                *opt_len, j);
        return -1;
    }
    return 0;
}

int
raw_ip6_opt_parse(int argc, char *argv[], uint8_t *proto, int *len,
        uint8_t *buff, int buff_len)
{
    int i, j;

    if (sscanf(argv[0], "%hhx", proto) != 1) {
        warnx("invalid protocol");
        return -1;
    }

    j = 0;
    for (i = 1; i < argc && j < buff_len; ++i, ++j) {
        if (sscanf(argv[i], "%hhx", &buff[j]) != 1) {
            warnx("invalid opt_data");
            return -1;
        }
    }
    *len = j;
    if ((j + 2) % 8 != 0) {
        warnx("(opt_len + 2) % 8 != 0", j);
        return -1;
    }
    return 0;
}
