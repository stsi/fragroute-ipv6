/*
 * tun-solaris.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: tun-solaris.c,v 1.3 2002/03/09 04:41:40 dugsong Exp $
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>

#include <net/if.h>
#include <net/if_tun.h>

#include <dnet.h>
#include <event.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stropts.h>
#include <unistd.h>

#include "tun.h"

#define DEV_TUN		"/dev/tun"
#define DEV_IP		"/dev/ip"

struct tun {
	int		 fd;
	int		 ip_fd;
	int		 if_fd;

	struct event	 ev;
	tun_handler	 callback;
	void		*arg;
};

tun_t *
tun_open(struct addr *src, struct addr *dst, int mtu)
{
	tun_t *tun;
	char cmd[512];
	int ppa;

	if ((tun = calloc(1, sizeof(*tun))) == NULL)
		return (NULL);

	if ((tun->fd = open(DEV_TUN, O_RDWR, 0)) < 0)
		return (tun_close(tun));

	if ((tun->ip_fd = open(DEV_IP, O_RDWR, 0)) < 0)
		return (tun_close(tun));
	
	if ((ppa = ioctl(tun->fd, TUNNEWPPA, ppa)) < 0)
		return (tun_close(tun));

	if ((tun->if_fd = open(DEV_TUN, O_RDWR, 0)) < 0)
		return (tun_close(tun));

	if (ioctl(tun->if_fd, I_PUSH, "ip") < 0)
		return (tun_close(tun));
	
	if (ioctl(tun->if_fd, IF_UNITSEL, (char *)&ppa) < 0)
		return (tun_close(tun));

	if (ioctl(tun->ip_fd, I_LINK, tun->if_fd) < 0)
		return (tun_close(tun));

	snprintf(cmd, sizeof(cmd), "ifconfig tun%d %s/32 %s mtu %d up",
		ppa, addr_ntoa(src), addr_ntoa(dst), mtu);

	if (system(cmd) < 0)
		return (tun_close(tun));

	return (tun);
}

static void
_tun_recv(int fd, short event, void *arg)
{
	tun_t *tun = (tun_t *)arg;
	struct strbuf sbuf;
	u_char buf[4096];
	int flags = 0;
	
	event_add(&tun->ev, NULL);

	sbuf.buf = buf;
	sbuf.maxlen = sizeof(buf);
	
	if (getmsg(fd, NULL, &sbuf, &flags) >= 0)
		(*tun->callback)(sbuf.buf, sbuf.len, tun->arg);
}

int
tun_register(tun_t *tun, tun_handler callback, void *arg)
{
	tun->callback = callback;
	tun->arg = arg;
	
	event_set(&tun->ev, tun->fd, EV_READ, _tun_recv, tun);
	event_add(&tun->ev, NULL);
	
	return (0);
}

tun_t *
tun_close(tun_t *tun)
{
	if (event_initialized(&tun->ev))
		event_del(&tun->ev);
	if (tun->if_fd > 0)
		close(tun->if_fd);
	if (tun->ip_fd > 0)
		close(tun->ip_fd);
	if (tun->fd > 0)
		close(tun->fd);
	free(tun);
	
	return (NULL);
}
