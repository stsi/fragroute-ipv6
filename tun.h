/*
 * tun.h
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: tun.h,v 1.3 2002/01/22 20:59:02 dugsong Exp $
 */

#ifndef TUN_H
#define TUN_H

#ifndef DNET_TUN_H
typedef struct tun tun_t;
#endif

typedef void (*tun_handler)(void *buf, size_t len, void *arg);

tun_t	*tun_open(struct addr *src, struct addr *dst, int mtu);
int	tun_register(tun_t *tun, tun_handler callback, void *arg);
tun_t	*tun_close(tun_t *tun);

#endif /* TUN_H */
