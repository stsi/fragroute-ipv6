/*
 * pkt.h
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: pkt.h,v 1.8 2002/04/07 22:55:20 dugsong Exp $
 */

#ifndef PKT_H
#define PKT_H

#include <sys/time.h>
#include <dnet.h>
#include <event.h>
#include "queue.h"

#define PKT_BUF_LEN	(ETH_HDR_LEN + ETH_MTU)
#define PKT_BUF_ALIGN	2

struct pkt {
	struct timeval	 pkt_ts;
	struct event	 pkt_ev;
	
	struct eth_hdr	*pkt_eth;
	union {
		u_char		*eth_data;
		struct ip_hdr	*ip;
		struct ip6_hdr	*ip6;
	} pkt_n_hdr_u;
	union {
		u_char		*ip_data;
		struct icmp_hdr	*icmp;
		struct tcp_hdr	*tcp;
		struct udp_hdr	*udp;
	} pkt_t_hdr_u;
	union {
		u_char		*t_data;
		union icmp_msg	*icmp;
	} pkt_t_data_u;

	u_char		 pkt_buf[PKT_BUF_ALIGN + PKT_BUF_LEN];
	u_char		*pkt_data;
	u_char		*pkt_end;

	TAILQ_ENTRY(pkt) pkt_next;
};
#define pkt_ip		 pkt_n_hdr_u.ip
#define pkt_ip6		 pkt_n_hdr_u.ip6
#define pkt_eth_data	 pkt_n_hdr_u.eth_data

#define pkt_icmp	 pkt_t_hdr_u.icmp
#define pkt_tcp		 pkt_t_hdr_u.tcp
#define pkt_udp		 pkt_t_hdr_u.udp
#define pkt_ip_data	 pkt_t_hdr_u.ip_data

#define pkt_tcp_data	 pkt_t_data_u.t_data
#define pkt_udp_data	 pkt_t_data_u.t_data
#define pkt_icmp_msg	 pkt_t_data_u.icmp

TAILQ_HEAD(pktq, pkt);

void		 pkt_init(int size);

struct pkt	*pkt_new(void);
struct pkt	*pkt_dup(struct pkt *);
void		 pkt_decorate(struct pkt *pkt);
void		 pkt_free(struct pkt *pkt);

void		 pktq_reverse(struct pktq *pktq);
void		 pktq_shuffle(rand_t *r, struct pktq *pktq);
struct pkt	*pktq_random(rand_t *r, struct pktq *pktq);

#endif /* PKT_H */
