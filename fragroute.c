/*
 * fragroute.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: fragroute.c,v 1.16 2002/04/07 22:55:20 dugsong Exp $
 */

#include "config.h"

#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pkt.h"
#include "mod.h"
#include "tun.h"

struct fr_ctx {
	struct addr	 src;
	struct addr	 dst;
	struct addr	 smac;
	struct addr	 dmac;

	uint16_t eth_type;

	int		 mtu;
	
	arp_t		*arp;
	ndisc_t		*ndisc;
	eth_t		*eth;
	intf_t		*intf;
	route_t		*route;
	tun_t		*tun;
};

static struct fr_ctx 	 ctx;

#if 0
/* XXX - these should be in event.h */
extern int		(*event_sigcb)(void);
extern int		 event_gotsig;
#endif

struct options
{
	const char *intf_name;
	const char *dst;
	const char *dst_mac;
};

static void
usage(void)
{
	fprintf(stderr, "Usage: fragroute [-f file] [-I interface] [-D dst mac] dst\n\n");
	fprintf(stderr, "-D is required for IPv6 traffic\n\n");
	fprintf(stderr, "Rules:\n");
	mod_usage();
	exit(1);
}

#ifndef WIN32
#define SOCKET		int
#define closesocket(x)	close(x)
#endif

static void _resend_outgoing(struct pkt *pkt);

static void
_timed_outgoing(int fd, short event, void *arg)
{
	struct pkt *pkt = (struct pkt *)arg;
	
	memset(&pkt->pkt_ts, 0, sizeof(pkt->pkt_ts));
	_resend_outgoing(pkt);
}

static void
_resend_outgoing(struct pkt *pkt)
{
	if (timerisset(&pkt->pkt_ts)) {
		timeout_set(&pkt->pkt_ev, _timed_outgoing, pkt);
		timeout_add(&pkt->pkt_ev, &pkt->pkt_ts);
	} else {
		eth_pack_hdr(pkt->pkt_eth, ctx.dmac.addr_eth, ctx.smac.addr_eth,
				ctx.eth_type);
		if (eth_send(ctx.eth, pkt->pkt_data,
		    pkt->pkt_end - pkt->pkt_data) < 0)
			warn("eth_send");
		pkt_free(pkt);
	}
}

static int
fragroute_close(void)
{
	if (ctx.tun != NULL)	tun_close(ctx.tun);
	if (ctx.route != NULL)	route_close(ctx.route);
	if (ctx.intf != NULL)	intf_close(ctx.intf);
	if (ctx.eth != NULL)	eth_close(ctx.eth);
	if (ctx.arp != NULL)	arp_close(ctx.arp);
#ifdef WIN32
	WSACleanup();
#endif
	return (-1);
}

static void
fragroute_process(void *buf, size_t len, void *arg)
{
	struct pktq pktq;
	struct pkt *pkt, *next;
	
	if ((pkt = pkt_new()) == NULL) {
		warn("pkt_new");
		return;
	}
	if (ETH_HDR_LEN + len > PKT_BUF_LEN) {
		warn("dropping oversized packet");
		return;
	}
	memcpy(pkt->pkt_data + ETH_HDR_LEN, buf, len);
	pkt->pkt_end = pkt->pkt_data + ETH_HDR_LEN + len;

	pkt->pkt_eth = (struct eth_hdr *)pkt->pkt_data;
	pkt->pkt_eth->eth_type = htons(ctx.eth_type);

	pkt_decorate(pkt);
	
	if (pkt->pkt_ip == NULL) {
		warn("dropping non-IP packet");
		return;
	}
	eth_pack_hdr(pkt->pkt_eth, ctx.dmac.addr_eth, ctx.smac.addr_eth, ctx.eth_type);

	if (ctx.eth_type == ETH_TYPE_IP) {
		pkt->pkt_ip->ip_src = ctx.src.addr_ip;
		ip_checksum(pkt->pkt_ip, len);
	}

	TAILQ_INIT(&pktq);
	TAILQ_INSERT_TAIL(&pktq, pkt, pkt_next);
	
	mod_apply(&pktq);

	for (pkt = TAILQ_FIRST(&pktq); pkt != TAILQ_END(&pktq); pkt = next) {
		next = TAILQ_NEXT(pkt, pkt_next);
		_resend_outgoing(pkt);
	}
}

#ifdef WIN32
static BOOL CALLBACK
fragroute_signal(DWORD sig)
{
	warnx("exiting at user request");
	event_gotsig++;
	return (TRUE);
}
#else
static void
fragroute_signal(int sig)
{
	warnx("exiting on signal %d", sig);
#if 0
	event_gotsig++;
#else
	_exit(0);
#endif
}
#endif

#ifdef __linux__
/* ctx.eth has the index, but we have no access to it from here */
int get_intf_index(const char* krn_if_name);
#endif

static int init_mac(int exit_on_err, const char* intf_name, struct arp_entry *arpent)
{
	struct route_entry rtent;

	if (ctx.dst.addr_type == ADDR_TYPE_IP) {
		if (arp_get(ctx.arp, arpent) < 0) {
			memcpy(&rtent.route_dst, &ctx.dst, sizeof(rtent.route_dst));

			if (route_get(ctx.route, &rtent) < 0) {
				if (exit_on_err) {
					err(1, "no route to %s", addr_ntoa(&rtent.route_dst));
				} else {
					return -1;
				}
			}

			memcpy(&arpent->arp_pa, &rtent.route_gw, sizeof(arpent->arp_pa));

			if (arp_get(ctx.arp, arpent) < 0) {
				if (exit_on_err) {
					err(1, "no ARP entry for %s", addr_ntoa(&arpent->arp_pa));
				} else {
					return -1;
				}
			}
		}
	} else if (ctx.dst.addr_type == ADDR_TYPE_IP6) {
#if 0
		struct ndisc_entry nent;

#ifdef __linux__
		nent.intf_index = get_intf_index(intf_name);
#else
		nent.intf_index = 0;
#endif
		nent.ndisc_pa = arpent->arp_pa;

		/* ndisc_get - not implementated yet */
		if (ndisc_get(ctx.ndisc, &nent) < 0) {
			memcpy(&rtent.route_dst, &ctx.dst, sizeof(rtent.route_dst));

			if (route_get(ctx.route, &rtent) < 0) {
				if (exit_on_err) {
					err(1, "no route to %s", addr_ntoa(&rtent.route_dst));
				} else {
					return -1;
				}
			}

			memcpy(&arpent->arp_pa, &rtent.route_gw, sizeof(arpent->arp_pa));

			if (ndisc_get(ctx.ndisc, &nent) < 0) {
				if (exit_on_err) {
					err(1, "no ndisc entry for %s", addr_ntoa(&nent.ndisc_pa));
				} else {
					return -1;
				}
			}
		}
		arpent->arp_ha = nent.ndisc_ha;
#else
		if (exit_on_err) {
			err(1, "NDISC for %s - not yet; use -D <mac>",
					addr_ntoa(&arpent->arp_pa));
		} else {
			return -1;
		}
#endif
	}
	return 0;
}

#ifdef __linux__
static void probe_host(struct options *options)
{
	char command[1024];
	int n;

	n = snprintf(command, sizeof(command), 
			"%s -c1 -w1 -I %s %s 2>&1 >/dev/null",
			ctx.dst.addr_type == ADDR_TYPE_IP6 ? "ping6" : "ping",
			options->intf_name, options->dst);

	if (n >= sizeof(command)) {
		err(1, "something is wrong - check dest address or interface name");
	}

	system(command);
}
#endif

#ifdef __linux__
void remove_prev_route(struct options *options)
{
	char command[1024];
	sprintf(command, "ip route del %s >/dev/null 2>&1", options->dst);
	system(command);
}
#endif

static void
fragroute_init(struct options *options)
{
	struct arp_entry arpent;
	struct intf_entry ifent;

#ifdef WIN32
	WSADATA wsdata;
	
	if (WSAStartup(MAKEWORD(2, 2), &wsdata) != 0)
		err(1, "couldn't initialize Winsock");

	SetConsoleCtrlHandler(fragroute_signal, TRUE);
#else
	signal(SIGINT, fragroute_signal);
	signal(SIGTERM, fragroute_signal);
#endif
	if (addr_aton(options->dst, &ctx.dst) < 0)
		err(1, "destination address invalid");

	if (ctx.dst.addr_bits != IP_ADDR_BITS && ctx.dst.addr_bits != IP6_ADDR_BITS)
		errx(1, "only /32 or /128 destinations supported at this time");

	pkt_init(128);
	
	event_init();
#if 0
	event_sigcb = fragroute_close;
#endif
	
	if ((ctx.arp = arp_open()) == NULL ||
	    (ctx.ndisc = ndisc_open()) == NULL ||
	    (ctx.intf = intf_open()) == NULL ||
	    (ctx.route = route_open()) == NULL)
		err(1, "couldn't open kernel networking interfaces");
	
	/* Find outgoing interface, addresses, and MTU. */
	if (options->intf_name) {
		strcpy(ifent.intf_name, options->intf_name);
		if (intf_get(ctx.intf, &ifent) < 0) {
			err(1, "couldn't open outgoing interface");
		}
	} else {
		ifent.intf_len = sizeof(ifent);
		if (intf_get_dst(ctx.intf, &ifent, &ctx.dst) < 0)
			err(1, "couldn't determine outgoing interface");
	}

	memcpy(&ctx.src, &ifent.intf_addr, sizeof(ctx.src));
	ctx.src.addr_bits = ctx.dst.addr_bits;
	memcpy(&ctx.smac, &ifent.intf_link_addr, sizeof(ctx.smac));
	ctx.mtu = ifent.intf_mtu;

	ctx.eth_type = ctx.dst.addr_type == ADDR_TYPE_IP6 ? ETH_TYPE_IPV6 : ETH_TYPE_IP;

#ifdef __linux__
	if (!options->dst_mac) {
		remove_prev_route(options);
	}
#endif

	/* Open outgoing interface for sending. */
	if ((ctx.eth = eth_open(ifent.intf_name)) == NULL)
		err(1, "couldn't open %s for sending", ifent.intf_name);
	
	/* Find destination MAC address. */
	memcpy(&arpent.arp_pa, &ctx.dst, sizeof(arpent.arp_pa));

	if (options->dst_mac) {
		addr_pton(options->dst_mac, &arpent.arp_ha);
	} else {
#ifdef __linux__
		int i;
		for (i = 0; i <= 2; ++i) {
			if (init_mac(i == 2, options->intf_name, &arpent) == 0) {
				break;
			}
			probe_host(options);
		}
#else
		init_mac(1, options->intf_name, &arpent);
#endif
	}

	memcpy(&ctx.dmac, &arpent.arp_ha, sizeof(ctx.dmac));
	
	/* Setup our tunnel. */
	if ((ctx.tun = tun_open(&ctx.src, &ctx.dst, ctx.mtu)) == NULL)
		err(1, "couldn't initialize tunnel interface");
	
	tun_register(ctx.tun, fragroute_process, &ctx);
}

static void
fragroute_config(char *config)
{
	if (mod_open(config) < 0) {
		fragroute_close();
		exit(1);
	}
}

static void
fragroute_dispatch(void)
{
	event_dispatch();
}

int
main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	char *conf;
	int c;
	struct options options;

	memset(&options, 0, sizeof(options));

	conf = FRAGROUTE_CONF;

	while ((c = getopt(argc, argv, "Lf:D:I:h?")) != -1) {
		switch (c) {
		case 'f':
			conf = optarg;
			break;
		case 'I':
			options.intf_name = optarg;
			break;
		case 'D':
			options.dst_mac = optarg;
			break;
		case 'L': /* leave for backward compatibility */
			fprintf(stderr, "-L option is deprecated\n");
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	
	if (argc != 1)
		usage();

	options.dst = argv[0];

	fragroute_init(&options);
	fragroute_config(conf);
	fragroute_dispatch();
	
	exit(0);
}
