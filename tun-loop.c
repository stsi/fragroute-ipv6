/*
 * tun-loop.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: tun-loop.c,v 1.5 2002/03/09 04:41:20 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>
#include <sys/time.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dnet.h>
#include <event.h>
#include <pcap.h>

#include "pcaputil.h"
#include "tun.h"

#ifdef __linux__
#include <net/if.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <linux/kdev_t.h>
#endif

#ifdef __linux__
#define LOOPBACK_DEV	"lo"
#else
#define LOOPBACK_DEV	"lo0"
#endif

struct tun {
	intf_t			*intf;
	pcap_t			*pcap;
	route_t			*route;
	int 			 loopback;

	struct route_entry	 rtent;
	struct intf_entry	*ifent;
	u_char			 buf[1024];
	int			 dloff;
	
	int			 fd;
	struct event		 ev;
	tun_handler		 callback;
	void			*arg;
};

#ifdef __linux__

int tun_use_loopback = 0;

#define TUN_DEV "/dev/net/tun"

static int
tun_open_fd(char* name, int len)
{
	int fd = -1;
	struct ifreq ifr;

	if (access(TUN_DEV, F_OK)) {
		dev_t dev = MKDEV(10, 200);
		int ret;

		ret = mknod(TUN_DEV, S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP |
				S_IROTH | S_IWOTH, dev);
		if (ret) {
			return -1;
		}
	}

	if ((fd = open(TUN_DEV, O_RDWR)) < 0) {
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name) - 1);

	if (ioctl(fd, TUNSETIFF, (void*)&ifr) < 0) {
		return -1;
	}

	strncpy(name, ifr.ifr_name, len);
	name[len - 1] = 0;

	return fd;
}

static int proc_write_int(const char* file, int value)
{
	char buf[32];
	int fd = open(file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	int n;

	if (fd == -1) {
		return 0;
	}

	n = snprintf(buf, sizeof(buf), "%d\n", value);
	if (write(fd, buf, n) != n) {
		n = 0;
	} else {
		n = 1;
	}

	close(fd);
	return n;
}

static int proc_write_intf_conf(int family, const char* intf_name, const char* key,
		int value)
{
	char buff[1024];
	int n;

	n = snprintf(buff, sizeof(buff), "/proc/sys/net/ipv%d/conf/%s/%s",
			family == PF_INET6 ? 6 : 4, intf_name, key);
	if (n >= sizeof(buff)) {
		return -1;
	}
	return proc_write_int(buff, value);
}

static int get_ctl_fd()
{
	static int fd = -1;

	if (fd < 0) {
		fd = socket(PF_INET, SOCK_DGRAM, 0);
	}
	return fd;
}

int get_intf_index(const char* krn_if_name)
{
	struct ifreq ifr;

	int fd = get_ctl_fd();
	if (fd < 0) {
		goto err;
	}

	strcpy(ifr.ifr_name, krn_if_name);
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		goto err;
	} else {
		return ifr.ifr_mtu;
	}

err:
	return -1;
}

static int change_intf_flags(const char* krn_if_name, uint32_t mask, uint32_t flags)
{
	struct ifreq ifr;
	int ret;
	static int fd = -1;

	fd = get_ctl_fd();
	if (fd < 0) {
		goto err;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, krn_if_name, IFNAMSIZ);

	ret = ioctl(fd, SIOCGIFFLAGS, &ifr);
	if (ret) {
		goto err;
	}

	if ((ifr.ifr_flags ^ flags) & mask) {
		ifr.ifr_flags &= ~mask;
		ifr.ifr_flags |= mask & flags;
		ret = ioctl(fd, SIOCSIFFLAGS, &ifr);
		if (ret) {
			goto err;
		}
	}

err:
	return -1;
}

static tun_t *
tun_dev_open(struct addr *src, struct addr *dst, int mtu)
{
	struct tun *tun;
	struct ndisc_entry ndiscent;
	ndisc_t *ndisc;
	int intf_index;

	if ((tun = calloc(1, sizeof(*tun))) == NULL)
		return (NULL);

	tun->ifent = (struct intf_entry *)tun->buf;
	tun->ifent->intf_len = sizeof(tun->buf);

	char* intf_name = tun->ifent->intf_name;
	sprintf(intf_name, "fr%%d");
	tun->fd = tun_open_fd(intf_name, sizeof(tun->ifent->intf_name));
	if (tun->fd == -1) {
		return NULL;
	}

	intf_index = get_intf_index(intf_name);

	if (dst->addr_type == ADDR_TYPE_IP6) {
		proc_write_intf_conf(AF_INET6, intf_name, "autoconf", 0);
		proc_write_intf_conf(AF_INET6, intf_name, "dad_transmits", 0);
		proc_write_intf_conf(AF_INET6, intf_name, "accept_ra", 0);
		proc_write_intf_conf(AF_INET6, intf_name, "router_solicitations", 0);
	}
	change_intf_flags(intf_name, IFF_MULTICAST, ~IFF_MULTICAST);

	change_intf_flags(intf_name, IFF_UP, IFF_UP);

	/* Get interface information. */
	if ((tun->intf = intf_open()) == NULL)
		return (NULL);

	if (intf_get(tun->intf, tun->ifent) < 0)
		return (tun_close(tun));

	/* Delete any existing route for destination. */
	if ((tun->route = route_open()) == NULL)
		return (tun_close(tun));

	/* Add dummy NDISC entry for destination. */
	if ((ndisc = ndisc_open()) != NULL) {
		memcpy(&ndiscent.ndisc_pa, dst, sizeof(*dst));
		memset(&ndiscent.ndisc_ha.addr_data8, 0, ETH_ADDR_LEN);
		ndiscent.intf_index = intf_index;
		ndisc_add(ndisc, &ndiscent);
		ndisc_close(ndisc);
	}
	/* Add route for destination via tun. */
	memcpy(&tun->rtent.route_dst, dst, sizeof(*dst));

	if (dst->addr_type == ADDR_TYPE_IP) {
		addr_aton("0.0.0.0", &tun->rtent.route_gw);
		if (route_add_dev(tun->route, &tun->rtent, intf_name) < 0)
			return (tun_close(tun));
	} else if (dst->addr_type == ADDR_TYPE_IP6) {
		addr_aton("::", &tun->rtent.route_gw);
		if (route6_add(tun->route, &tun->rtent, intf_index) < 0)
			return (tun_close(tun));
	}

	tun->dloff = ETH_HDR_LEN;

	return (tun);
}

#endif

tun_t *
tun_open(struct addr *src, struct addr *dst, int mtu)
{
	struct tun *tun;
	struct arp_entry arpent;
	struct intf_entry ifent;
	arp_t *arp;

#ifdef __linux__
	if (dst->addr_type == ADDR_TYPE_IP6)
		return tun_dev_open(src, dst, mtu); /* UPDATE: doesn't work for ipv4 */
#endif

	if ((tun = calloc(1, sizeof(*tun))) == NULL)
		return (NULL);
	
	tun->ifent = (struct intf_entry *)tun->buf;
	tun->ifent->intf_len = sizeof(tun->buf);
	strlcpy(tun->ifent->intf_name, LOOPBACK_DEV,
	    sizeof(tun->ifent->intf_name));

	tun->loopback = 1;

	/* Get interface information. */
	if ((tun->intf = intf_open()) == NULL)
		return (NULL);
	
	if (intf_get(tun->intf, tun->ifent) < 0)
		return (tun_close(tun));

	memcpy(&tun->rtent.route_dst, dst, sizeof(*dst));
#ifdef __linux__
	/* XXX - Linux sets the routed src IP regardless of assigned addr */
	addr_aton("127.0.0.1", &tun->rtent.route_gw);
#else
	memcpy(&tun->rtent.route_gw, src, sizeof(*src));
#endif
	/* Set interface address and MTU. */
	memset(&ifent, 0, sizeof(ifent));
	strcpy(ifent.intf_name, tun->ifent->intf_name);
	ifent.intf_flags = tun->ifent->intf_flags | INTF_FLAG_UP;
	ifent.intf_mtu = mtu;
	memcpy(&ifent.intf_addr, &tun->rtent.route_gw,
	    sizeof(ifent.intf_addr));
	
	if (intf_set(tun->intf, &ifent) < 0)
		return (tun_close(tun));
	
	/* Delete any existing route for destination. */
	if ((tun->route = route_open()) == NULL)
		return (tun_close(tun));
	route_delete(tun->route, &tun->rtent);
	
	/* Delete any existing ARP entry for destination. */
	if ((arp = arp_open()) != NULL) {
		memcpy(&arpent.arp_pa, dst, sizeof(*dst));
		arp_delete(arp, &arpent);
		arp_close(arp);
	}
	/* Add route for destination via loopback. */
	if (route_add(tun->route, &tun->rtent) < 0)
		return (tun_close(tun));
	
	/* Set up to sniff on loopback. */
	if ((tun->pcap = pcap_open(tun->ifent->intf_name)) == NULL)
		return (tun_close(tun));
	
	if (pcap_filter(tun->pcap, "ip dst %s", addr_ntoa(dst)) < 0)
		return (tun_close(tun));
	
	tun->dloff = pcap_dloff(tun->pcap);
	tun->fd = pcap_fileno(tun->pcap);
	
	return (tun);
}

static void
_pcap_recv(u_char *u, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
	tun_t *tun = (tun_t *)u;

	/*
	 * XXX - if we wanted to be a real tunnel device,
	 * we would forcibly rewrite the addresses here...
	 */
	(*tun->callback)((u_char *)pkt + tun->dloff,
	    hdr->caplen - tun->dloff, tun->arg);
}

static void
_tun_recv(int fd, short event, void *arg)
{
	tun_t *tun = (tun_t *)arg;
	
	event_add(&tun->ev, NULL);
	pcap_dispatch(tun->pcap, -1, _pcap_recv, (u_char *)tun);
}

#ifdef __linux__
static void
_tun_dev_recv(int fd, short event, void *arg)
{
	tun_t *tun = (tun_t *)arg;
	int n;
	u_char pkt[2048];

	event_add(&tun->ev, NULL);

	n = read(fd, &pkt, sizeof(pkt));
	if (n >= tun->dloff) {
		(*tun->callback)((u_char *)pkt + tun->dloff, n - tun->dloff, tun->arg);
	}
}
#endif

int
tun_register(tun_t *tun, tun_handler callback, void *arg)
{
	tun->callback = callback;
	tun->arg = arg;

	if (tun->pcap) {
		event_set(&tun->ev, tun->fd, EV_READ, _tun_recv, tun);
	} else {
#ifdef __linux__
		event_set(&tun->ev, tun->fd, EV_READ, _tun_dev_recv, tun);
#else
		return -1;
#endif
	}
	event_add(&tun->ev, NULL);
	
	return (0);
}

tun_t *
tun_close(tun_t *tun)
{
	if (event_initialized(&tun->ev))
		event_del(&tun->ev);

	/* Stop sniffing. */
	if (tun->pcap != NULL)
		pcap_close(tun->pcap);
	
	/* Delete loopback route. */
	if (tun->route != NULL && tun->loopback) {
		if (route_delete(tun->route, &tun->rtent) < 0)
			warnx("couldn't delete loopback route");
		route_close(tun->route);
	}
	/* Restore interface address and MTU. */
	if (tun->intf != NULL && tun->loopback) {
		if (tun->ifent != NULL) {
			if (intf_set(tun->intf, tun->ifent) < 0)
				warnx("couldn't restore loopback settings");
		}
		intf_close(tun->intf);
	}
	free(tun);
	
	return (NULL);
}
