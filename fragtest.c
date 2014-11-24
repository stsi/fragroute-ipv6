/*
 * fragtest.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: fragtest.c,v 1.17 2002/04/07 22:55:20 dugsong Exp $
 */

#include "config.h"

#include <pcap.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mod.h"
#include "pcaputil.h"

#define TEST_PING		0x01
#define TEST_IP_OPT		0x02
#define TEST_IP_TRACERT		0x04
#define TEST_FRAG		0x08
#define TEST_FRAG_NEW		0x10
#define TEST_FRAG_OLD		0x20
#define TEST_FRAG_TIMEOUT	0x40

#define READ_TIMEOUT		2
#define FRAG_TIMEOUT		300

struct ft_ctx {
	struct addr		 src, dst;
	struct pktq		 pktq;
	ip_t			*ip;
	pcap_t			*pcap;
	rand_t			*rnd;
	int			 dloff;
};

extern struct mod mod_ip_frag;

static struct ft_ctx	 ctx;
static struct pkt	*ping;
static struct timeval	 read_tv = { READ_TIMEOUT, 0 };

static void
usage(void)
{
	fprintf(stderr, "Usage: fragtest TESTS ... <host>\n\n");
	fprintf(stderr, "  where TESTS is any combination of the following "
	    "(or \"all\"):\n\n");
	fprintf(stderr, "  ping\t\tprerequisite for all tests\n");
	fprintf(stderr, "  ip-opt\tdetermine supported IP options\n");
	fprintf(stderr, "  ip-tracert\tdetermine path to target\n");
	fprintf(stderr, "  frag\t\ttry 8-byte IP fragments\n");
	fprintf(stderr, "  frag-new\ttry 8-byte fwd-overlapping IP "
	    "fragments, favoring new data\n");
	fprintf(stderr, "  frag-old\ttry 8-byte fwd-overlapping IP "
	    "fragments, favoring old data\n");
	fprintf(stderr, "  frag-timeout\tdetermine IP fragment "
	    "reassembly timeout\n");
	fprintf(stderr, "\n");
	exit(1);
}

static char *
timeval_ntoa(struct timeval *tv)
{
	static char buf[128];
	uint64_t usec;

	usec = (tv->tv_sec * 1000000) + tv->tv_usec;

	if (usec > 1000000) {
		snprintf(buf, sizeof(buf), "%d.%03d sec",
		    (int)(usec / 1000000), (int)(usec % 1000000));
	} else {
		snprintf(buf, sizeof(buf), "%d.%03d ms",
		    (int)(usec / 1000), (int)(usec % 1000));
	}
	return (buf);
}

static int
send_pkt(struct pkt *pkt)
{
	int i;

	i = ip_send(ctx.ip, pkt->pkt_ip, pkt->pkt_end - pkt->pkt_eth_data);
	pkt_free(pkt);
	return (i);
}

static void
send_pktq(struct pktq *pktq)
{
	struct pkt *pkt, *next;
	
	for (pkt = TAILQ_FIRST(pktq); pkt != TAILQ_END(pktq); pkt = next) {
		next = TAILQ_NEXT(pkt, pkt_next);
		TAILQ_REMOVE(pktq, pkt, pkt_next);
		send_pkt(pkt);
	}
}

static struct pkt *
recv_pkt(struct timeval *tv)
{
	struct pcap_pkthdr phdr;
	struct timeval now, start;
	struct pkt *pkt;
	u_char *p;
	long timeout_usec;
	int i;
	
	timeout_usec = tv->tv_sec * 1000000 + tv->tv_usec;
	gettimeofday(&start, NULL);
	
	/*
	 * XXX - can't select() on pcap_fileno on Solaris,
	 * seems to be unreliable on Linux as well. *sigh*
	 */
	for (;;) {
		gettimeofday(&now, NULL);
		
		if ((p = (u_char *)pcap_next(ctx.pcap, &phdr)) != NULL ||
		    (now.tv_sec - start.tv_sec) * 1000000 +
		    now.tv_usec - start.tv_usec > timeout_usec)
			break;
	}
	if (p == NULL)
		return (NULL);
	
	p += ctx.dloff;
	i = phdr.caplen - ctx.dloff;
	
	pkt = pkt_new();
	memcpy(pkt->pkt_eth_data, p, i);
	pkt->pkt_end = pkt->pkt_eth_data + i;
	pkt_decorate(pkt);
	
	tv->tv_sec = phdr.ts.tv_sec - start.tv_sec;
	tv->tv_usec = phdr.ts.tv_usec - start.tv_usec;
	
	return (pkt);
}

static int
test_ping(void)
{
	struct pkt *pkt;
	struct timeval tv;
	
	printf("ping: "); fflush(stdout);

	ping->pkt_icmp_msg->echo.icmp_id = rand_uint16(ctx.rnd);
	pkt = pkt_dup(ping);
	pkt->pkt_ip->ip_id = rand_uint16(ctx.rnd);
	ip_checksum(pkt->pkt_ip, pkt->pkt_end - pkt->pkt_eth_data);
	
	pcap_filter(ctx.pcap, "icmp[0] = 0 and src %s and dst %s",
	    addr_ntoa(&ctx.dst), addr_ntoa(&ctx.src));

	send_pkt(pkt);

	for (tv = read_tv; (pkt = recv_pkt(&tv)) != NULL; tv = read_tv) {
		if (memcmp(&pkt->pkt_icmp_msg->echo,
		    &ping->pkt_icmp_msg->echo, 8) == 0)
			break;
	}
	printf("%s\n", pkt ? timeval_ntoa(&tv) : "no reply");

	return (0);
}

static char *optnames[] = {
	"eol", "nop", "sec", "lsrr", "ts", "esec", "cipso", "rr",
	"satid", "ssrr", "zsu", "mtup", "mtur", "finn", "visa",
	"encode", "imitd", "eip", "tr", "addext", "rtralt", "sdb",
	"nsapa", "dps", "ump", NULL
};

static int
test_ip_opt(void)
{
	struct pkt *pkt;
	struct timeval tv;
	struct ip_opt opts[IP_OPT_MAX];
	int i, len, max;
	
	printf("ip-opt: "); fflush(stdout);
	
	memset(&opts, 0, sizeof(opts));
	max = 0;
	opts[max].opt_type = IP_OPT_SEC;
	opts[max].opt_len = IP_OPT_LEN + 9;
	max++;
	opts[max].opt_type = IP_OPT_LSRR;
	opts[max].opt_len = IP_OPT_LEN + 1 + 4;
	opts[max].opt_data.rr.ptr = 8;
	opts[max].opt_data.rr.iplist[0] = ping->pkt_ip->ip_src;
	max++;
	opts[max].opt_type = IP_OPT_TS;
	opts[max].opt_len = IP_OPT_LEN + 1 + 1 + 4;
	opts[max].opt_data.ts.ptr = 5;
	opts[max].opt_data.ts.flg = IP_OPT_TS_TSONLY;
	max++;
	opts[max].opt_type = IP_OPT_ESEC;
	opts[max].opt_len = IP_OPT_LEN;
	max++;
	opts[max].opt_type = IP_OPT_CIPSO;
	opts[max].opt_len = IP_OPT_LEN;
	max++;
	opts[max].opt_type = IP_OPT_RR;
	opts[max].opt_len = IP_OPT_LEN + 1 + 4;
	opts[max].opt_data.rr.ptr = 4;
	max++;
	opts[max].opt_type = IP_OPT_SATID;
	opts[max].opt_len = IP_OPT_LEN + 2;
	max++;
	opts[max].opt_type = IP_OPT_SSRR;
	opts[max].opt_len = IP_OPT_LEN + 1 + 4;
	opts[max].opt_data.rr.ptr = 8;
	opts[max].opt_data.rr.iplist[0] = ping->pkt_ip->ip_src;
	max++;
	
	pcap_filter(ctx.pcap, "icmp and src %s and dst %s",
	    addr_ntoa(&ctx.dst), addr_ntoa(&ctx.src));

	ping->pkt_icmp_msg->echo.icmp_id = rand_uint16(ctx.rnd);
	
	for (i = 0; i < max; i++) {
		pkt = pkt_dup(ping);
		pkt->pkt_ip->ip_id = rand_uint16(ctx.rnd);
		pkt->pkt_icmp_msg->echo.icmp_seq = opts[i].opt_type;
		len = ip_add_option(pkt->pkt_ip, PKT_BUF_LEN - ETH_HDR_LEN +
		    IP_HDR_LEN, IP_PROTO_IP, &opts[i], opts[i].opt_len);
		pkt->pkt_end += len;
		
		ip_checksum(pkt->pkt_ip, pkt->pkt_end - pkt->pkt_eth_data);
		
		send_pkt(pkt);
	}
	i = 0;
	for (tv = read_tv; (pkt = recv_pkt(&tv)) != NULL; tv = read_tv) {
		if (pkt->pkt_icmp->icmp_type == ICMP_ECHOREPLY &&
		    pkt->pkt_icmp_msg->echo.icmp_id ==
		    ping->pkt_icmp_msg->echo.icmp_id) {
			i = IP_OPT_NUMBER(pkt->pkt_icmp_msg->echo.icmp_seq);
			printf("%s ", optnames[i]);
		}
	}
	printf("%s\n", i ? "" : "none");
	
	return (0);
}

struct hop {
	struct addr	addr;
	struct icmp_hdr	icmp;
	int		rtt;
	int		ttl;
};

static int
test_ip_tracert(void)
{
	struct timeval tv;
	struct hop hops[IP_TTL_DEFAULT];
	struct pkt *pkt;
	struct icmp_msg_echo *echo;
	int i, hopcnt, max_ttl;

	printf("ip-tracert: "); fflush(stdout);

	pcap_filter(ctx.pcap, "icmp[0] = 0 and src %s and dst %s",
	    addr_ntoa(&ctx.dst), addr_ntoa(&ctx.src));
	
	ping->pkt_icmp_msg->echo.icmp_id = rand_uint16(ctx.rnd);
	pkt = pkt_dup(ping);
	pkt->pkt_ip->ip_id = rand_uint16(ctx.rnd);
	ip_checksum(pkt->pkt_ip, pkt->pkt_end - pkt->pkt_eth_data);
	
	send_pkt(pkt);
	tv = read_tv;
	
	if ((pkt = recv_pkt(&tv)) == NULL) {
		printf("no reply\n");
		return (0);
	}
	/* XXX - guess remote stack's starting TTL */
	for (i = 2; pkt->pkt_ip->ip_ttl > i; i <<= 1)
		;
	
	if ((max_ttl = i - pkt->pkt_ip->ip_ttl + 1) > IP_TTL_DEFAULT)
		max_ttl = IP_TTL_DEFAULT;

	printf("%s, %d hops max\n", ip_ntoa(&ping->pkt_ip->ip_dst), max_ttl);
	pcap_filter(ctx.pcap, "icmp and dst %s", addr_ntoa(&ctx.src));

	for (i = 1; i < max_ttl + 1; i++) {
		pkt = pkt_dup(ping);
		pkt->pkt_ip->ip_id = rand_uint16(ctx.rnd);
		pkt->pkt_ip->ip_ttl = i;
		pkt->pkt_icmp_msg->echo.icmp_seq = htons(i);
		ip_checksum(pkt->pkt_ip, pkt->pkt_end - pkt->pkt_eth_data);
		send_pkt(pkt);
		usleep(42);	/* XXX */
	}
	memset(&hops, 0, sizeof(hops));
	hopcnt = 0;
	
	for (tv = read_tv; (pkt = recv_pkt(&tv)) != NULL; tv = read_tv) {
		if ((pkt->pkt_icmp->icmp_type == ICMP_TIMEXCEED ||
		    pkt->pkt_icmp->icmp_type == ICMP_UNREACH) &&
		    pkt->pkt_end - pkt->pkt_eth_data >=
		    (IP_HDR_LEN + ICMP_LEN_MIN) * 2) {
			echo = (struct icmp_msg_echo *)
			    (pkt->pkt_icmp_msg->timexceed.icmp_ip +
				IP_HDR_LEN + ICMP_HDR_LEN);
		} else if (pkt->pkt_icmp->icmp_type == ICMP_ECHOREPLY) {
			echo = &pkt->pkt_icmp_msg->echo;
		} else
			continue;

		if (echo->icmp_id != ping->pkt_icmp_msg->echo.icmp_id)
			continue;
		
		i = ntohs(echo->icmp_seq);
		addr_pack(&hops[i].addr, ADDR_TYPE_IP, IP_ADDR_BITS,
		    &pkt->pkt_ip->ip_src, IP_ADDR_LEN);
		memcpy(&hops[i].icmp, pkt->pkt_icmp, ICMP_HDR_LEN);
		hops[i].ttl = pkt->pkt_ip->ip_ttl;
		hopcnt++;
		
		if (pkt->pkt_ip->ip_src == ping->pkt_ip->ip_dst)
			break;
	}
	for (i = 1; i < hopcnt + 1; i++) {
		if (hops[i].addr.addr_type == ADDR_TYPE_IP) {
			printf("%2d  %s (%d)\n",
			    i, addr_ntoa(&hops[i].addr), hops[i].ttl);
		} else
			printf("%2d  *\n", i);
	}
	return (0);
}

static int
test_frag(char *overlap, int drop)
{
	struct timeval tv, save_tv = read_tv;
	struct pkt *pkt;
	struct icmp_msg_echo *echo;
	char *frag_argv[4];

	if (overlap != NULL)
		printf("frag-%s: ", overlap);
	else if (drop)
		printf("frag-timeout (please wait): ");
	else
		printf("frag: ");
	fflush(stdout);

	ping->pkt_ip->ip_id = rand_uint16(ctx.rnd);
	ping->pkt_icmp_msg->echo.icmp_id = rand_uint16(ctx.rnd);
	pkt = pkt_dup(ping);
	ip_checksum(pkt->pkt_ip, pkt->pkt_end - pkt->pkt_eth_data);
	TAILQ_INSERT_TAIL(&ctx.pktq, pkt, pkt_next);
	
	frag_argv[0] = "ip_frag";
	frag_argv[1] = "8";
	frag_argv[2] = overlap;
	frag_argv[3] = NULL;
	
	mod_ip_frag.open(overlap ? 3 : 2, frag_argv, NULL);
	mod_ip_frag.apply(NULL, &ctx.pktq, NULL);

	if (drop) {
		pkt = TAILQ_LAST(&ctx.pktq, pktq);
		TAILQ_REMOVE(&ctx.pktq, pkt, pkt_next);
		pkt_free(pkt);
		save_tv.tv_sec = FRAG_TIMEOUT;
	}
	pcap_filter(ctx.pcap, "icmp[0] = %d and src %s and dst %s",
	    drop ? 11 : 0, addr_ntoa(&ctx.dst), addr_ntoa(&ctx.src));

	send_pktq(&ctx.pktq);

	for (tv = save_tv; (pkt = recv_pkt(&tv)) != NULL; tv = save_tv) {
		if (drop) {
			echo = (struct icmp_msg_echo *)
			    (pkt->pkt_icmp_msg->timexceed.icmp_ip +
				IP_HDR_LEN + ICMP_HDR_LEN);
		} else {
			echo = &pkt->pkt_icmp_msg->echo;
		}
		if (echo->icmp_id == ping->pkt_icmp_msg->echo.icmp_id)
			break;
	}
	printf("%s\n", pkt ? timeval_ntoa(&tv) : "no reply");
	
	return (0);
}

int
main(int argc, char *argv[])
{
	struct intf_entry ifent;
	intf_t *intf;
	int i, tests;
	char *cmd;
	
	if (argc < 3)
		usage();

	for (tests = 0, i = 1; i < argc - 1; i++) {
		cmd = argv[i];
		
		if (strcmp(cmd, "all") == 0)
			tests = ~0;
		else if (strcmp(cmd, "ping") == 0)
			tests |= TEST_PING;
		else if (strcmp(cmd, "ip-opt") == 0)
			tests |= TEST_IP_OPT;
		else if (strcmp(cmd, "ip-tracert") == 0)
			tests |= TEST_IP_TRACERT;
		else if (strcmp(cmd, "frag") == 0)
			tests |= TEST_FRAG;
		else if (strcmp(cmd, "frag-new") == 0)
			tests |= TEST_FRAG_NEW;
		else if (strcmp(cmd, "frag-old") == 0)
			tests |= TEST_FRAG_OLD;
		else if (strcmp(cmd, "frag-timeout") == 0)
			tests |= TEST_FRAG_TIMEOUT;
		else
			usage();
	}
	if (addr_aton(argv[i], &ctx.dst) < 0)
		err(1, "invalid host %s", argv[i]);

	if ((intf = intf_open()) == NULL)
		err(1, "couldn't open interface handle");

	ifent.intf_len = sizeof(ifent);
	
	if (intf_get_dst(intf, &ifent, &ctx.dst) < 0)
		err(1, "couldn't find interface for %s", addr_ntoa(&ctx.dst));
	
	memcpy(&ctx.src, &ifent.intf_addr, sizeof(ctx.src));
	ctx.src.addr_bits = IP_ADDR_BITS;
	
	intf_close(intf);
	
	if ((ctx.ip = ip_open()) == NULL)
		err(1, "couldn't open raw IP interface");

	if ((ctx.pcap = pcap_open(ifent.intf_name)) == NULL)
		err(1, "couldn't open %s for sniffing", ifent.intf_name);
	
	if ((ctx.dloff = pcap_dloff(ctx.pcap)) < 0)
		err(1, "couldn't determine link layer offset");
	
	ctx.rnd = rand_open();
	pkt_init(16);
	TAILQ_INIT(&ctx.pktq);

	ping = pkt_new();
	ip_pack_hdr(ping->pkt_ip, 0, IP_HDR_LEN + 8 + 24, 666, 0,
	    IP_TTL_DEFAULT, IP_PROTO_ICMP, ctx.src.addr_ip, ctx.dst.addr_ip);
	icmp_pack_hdr_echo(ping->pkt_icmp, ICMP_ECHO, ICMP_CODE_NONE,
	    666, 1, "AAAAAAAABBBBBBBBCCCCCCCC", 24);
	ping->pkt_end = ping->pkt_eth_data + IP_HDR_LEN + 8 + 24;
	pkt_decorate(ping);
	
	if ((tests & TEST_PING) != 0)
		test_ping();
	if ((tests & TEST_IP_OPT) != 0)
		test_ip_opt();
	if ((tests & TEST_IP_TRACERT) != 0)
		test_ip_tracert();
	if ((tests & TEST_FRAG) != 0)
		test_frag(NULL, 0);
	if ((tests & TEST_FRAG_NEW) != 0)
		test_frag("new", 0);
	if ((tests & TEST_FRAG_OLD) != 0)
		test_frag("old", 0);
	if ((tests & TEST_FRAG_TIMEOUT) != 0)
		test_frag(NULL, 1);

	rand_close(ctx.rnd);
	pcap_close(ctx.pcap);
	ip_close(ctx.ip);
	
	exit(0);
}
