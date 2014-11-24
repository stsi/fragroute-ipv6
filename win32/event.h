/*
 * event.h
 *
 * Sleazy win32 libevent hack.
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: event.h,v 1.1 2002/02/25 06:21:59 dugsong Exp $
 */

#ifndef EVENT_H
#define EVENT_H

#define EV_TIMEOUT	0x01
#define EV_READ		0x02

struct event {
	HANDLE		  handle;
	OVERLAPPED	  overlap;
	short		  event;
	void		(*callback)(int, short, void *);
	void		 *arg;
	u_char		  buf[4192];
};	

struct event_iov {
	u_char		 *buf;
	int		  len;
};

void	event_init(void);
int	event_dispatch(void);

/*
 * XXX - overload fd with overlapped file HANDLE,
 * overload callback fd with pointer to event_iov struct
 */
void	event_set(struct event *ev, int fd, short event,
	    void (*callback)(int, short, void *), void *arg);
int	event_add(struct event *ev, struct timeval *tv);
void	event_del(struct event *ev);
int	event_initialized(struct event *ev);

void	timeout_set(struct event *ev,
	    void (*callback)(int, short, void *), void *arg);
void	timeout_add(struct event *ev, struct timeval *tv);

#endif /* EVENT_H */
	
