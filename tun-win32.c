/*
 * tun-win32.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: tun-win32.c,v 1.1 2002/02/25 06:21:59 dugsong Exp $
 */

#include "config.h"

#include <dnet.h>
#include <event.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tun.h"

#define USER_DEVICE_DIR		"\\\\.\\"
#define NETCARD_REG_KEY_2000	"SYSTEM\\CurrentControlSet\\Control\\Class" \
				"\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#if 0
#define NETCARD_REG_KEY		"SOFTWARE\\Microsoft\\Windows NT" \
				"\\CurrentVersion\\NetworkCards"
#endif

struct tun {
	arp_t			*arp;
	intf_t			*intf;
	route_t			*route;
	
	struct arp_entry	 arpent;
	struct intf_entry	 ifent;
	struct route_entry	 rtent;
	
	struct addr		 dst;
	HANDLE			 handle;
	struct event		 ev;
	tun_handler		 callback;
	void			*arg;
};

static int
reg_query_compare(HKEY key, char *name, char *text)
{
	char value[512];
	u_long size;
	
	size = sizeof(value);
	
	if (RegQueryValueEx(key, name, 0, 0, value, &size) != ERROR_SUCCESS)
		return (-1);
	
	return (strcmp(text, value));
}

tun_t *
tun_open(struct addr *src, struct addr *dst, int mtu)
{
	HKEY Key, AdapterKey;
	FILETIME ltime;
	tun_t *tun;
	ip_addr_t mask;
	u_long i, len;
	char device[64], AdapterId[512], Value[512];

	if ((tun = calloc(1, sizeof(*tun))) == NULL)
		return (NULL);

	if ((tun->arp = arp_open()) == NULL ||
	    (tun->intf = intf_open()) == NULL ||
	    (tun->route = route_open()) == NULL)
		return (tun_close(tun));

	tun->ifent.intf_len = sizeof(tun->ifent);
	strlcpy(tun->ifent.intf_name, "DKW Heavy Industries VPN Adapter.",
	    sizeof(tun->ifent.intf_name));
	
	if (intf_get(tun->intf, &tun->ifent) < 0 ||
	    tun->ifent.intf_addr.addr_type != ADDR_TYPE_IP)
		return (tun_close(tun));
	
	/* Add fake tunnel gateway. */
	tun->arpent.arp_pa = tun->ifent.intf_addr;
	addr_btom(tun->ifent.intf_addr.addr_bits, &mask, sizeof(mask));
	tun->arpent.arp_pa.addr_ip &= mask;
	tun->arpent.arp_pa.addr_ip |= htonl(1);
	tun->arpent.arp_pa.addr_bits = IP_ADDR_BITS;
	addr_aton("0:d:e:a:d:0", &tun->arpent.arp_ha);
	
	if (arp_add(tun->arp, &tun->arpent) < 0)
		return (tun_close(tun));
	
	/* Add route for destination thru tunnel. */
	tun->rtent.route_dst = *dst;
	tun->rtent.route_gw = tun->arpent.arp_pa;
	
	if (route_add(tun->route, &tun->rtent) < 0)
		return (tun_close(tun));
	
	tun->dst = *dst;
	tun->handle = INVALID_HANDLE_VALUE;

	/* Open CIPE device for reading. */
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, NETCARD_REG_KEY_2000,
	    0, KEY_READ, &Key) != ERROR_SUCCESS)
		return (tun_close(tun));
	
	for (i = 0; i < 666; i++) {
		len = sizeof(AdapterId);
		if (RegEnumKeyEx(Key, i, AdapterId, &len,
		    0, 0, 0, &ltime) != ERROR_SUCCESS)
			break;
		
		if (RegOpenKeyEx(Key, AdapterId, 0, KEY_READ,
		    &AdapterKey) != ERROR_SUCCESS)
			break;
		
		len = sizeof(Value);
		if (reg_query_compare(AdapterKey,
		        "Manufacturer", "DKWHeavyIndustries") == 0 &&
		    reg_query_compare(AdapterKey,
			"ProductName", "CIPE") == 0 &&
		    RegQueryValueEx(AdapterKey, "NetCfgInstanceId",
			0, 0, Value, &len) == ERROR_SUCCESS) {

			snprintf(device, sizeof(device),
			    USER_DEVICE_DIR "%s.tap", Value);
			
			tun->handle = CreateFile(device, GENERIC_READ,
			    FILE_SHARE_READ, 0, OPEN_EXISTING,
			    FILE_FLAG_OVERLAPPED|FILE_ATTRIBUTE_SYSTEM, 0);

			RegCloseKey(AdapterKey);
			break;
		}
		RegCloseKey(AdapterKey);
	}
	RegCloseKey(Key);
	
	if (tun->handle == INVALID_HANDLE_VALUE)
		return (tun_close(tun));

	return (tun);
}

static void
_tun_recv(int fd, short event, void *arg)
{
	struct event_iov *eio = (struct event_iov *)fd;
	tun_t *tun = (tun_t *)arg;
	struct ip_hdr *ip;
	
	ip = (struct ip_hdr *)(eio->buf + ETH_HDR_LEN);

	if (eio->len > ETH_HDR_LEN + IP_HDR_LEN &&
	    ip->ip_dst == tun->dst.addr_ip) {
		(*tun->callback)(eio->buf + ETH_HDR_LEN,
		    eio->len - ETH_HDR_LEN, tun->arg);
	}
	event_add(&tun->ev, NULL);
}

int
tun_register(tun_t *tun, tun_handler callback, void *arg)
{
	tun->callback = callback;
	tun->arg = arg;
	
	event_set(&tun->ev, (int)tun->handle, EV_READ, _tun_recv, tun);
	event_add(&tun->ev, NULL);
	
	return (0);
}

tun_t *
tun_close(tun_t *tun)
{
	if (event_initialized(&tun->ev))
		event_del(&tun->ev);
	if (tun->handle != INVALID_HANDLE_VALUE)
		CloseHandle(tun->handle);
	if (tun->dst.addr_type == ADDR_TYPE_IP) {
		route_delete(tun->route, &tun->rtent);
		arp_delete(tun->arp, &tun->arpent);
	}
	if (tun->route != NULL)
		route_close(tun->route);
	if (tun->arp != NULL)
		arp_close(tun->arp);
	
	free(tun);
	
	return (NULL);
}
