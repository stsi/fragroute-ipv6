/*
 * pcaputil.h
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: pcaputil.h,v 1.1 2002/01/17 21:33:55 dugsong Exp $
 */

#ifndef PCAPUTIL_H
#define PCAPUTIL_H

pcap_t *pcap_open(char *device);
int	pcap_dloff(pcap_t *pcap);
int	pcap_filter(pcap_t *pcap, const char *fmt, ...);

#endif /* PCAPUTIL_H */
