/*
 * event-win32.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: event-win32.c,v 1.1 2002/02/25 06:21:59 dugsong Exp $
 */

#include <windows.h>
#include <winsock.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include "event.h"

#define WT_EXECUTEINIOTHREAD	0x0000001
#define WT_EXECUTEONLYONCE	0x0000006

typedef HANDLE (WINAPI *pCreateTimerQueue)(VOID);
typedef BOOL (WINAPI *pDeleteTimerQueue)(HANDLE TimerQueue);
typedef BOOL (WINAPI *pCreateTimerQueueTimer)(PHANDLE phNewTimer,
    HANDLE TimerQueue, void CALLBACK (*pfnCallback)(PVOID, BOOL),
    PVOID pvContext, DWORD DueTime, DWORD Period, ULONG Flags);
typedef BOOL (WINAPI *pDeleteTimerQueueTimer)(HANDLE TimerQueue, HANDLE Timer,
    HANDLE CompletionEvent);

static HINSTANCE		 lib_inst;
static HANDLE			 timer_queue;
static pCreateTimerQueue	 create_timer_queue;
static pDeleteTimerQueue	 delete_timer_queue;
static pCreateTimerQueueTimer	 create_timer;
static pDeleteTimerQueueTimer	 delete_timer;

int	event_gotsig;
int	(*event_sigcb)(void);

int
os_version(void)
{
	OSVERSIONINFO info;
	
	info.dwOSVersionInfoSize = sizeof(info);

	if (GetVersionEx(&info) == TRUE &&
	    info.dwPlatformId == VER_PLATFORM_WIN32_NT)
		return (info.dwMajorVersion);
	
	return (32767);
}

static int
timeval_to_ms(struct timeval *tv)
{
	return ((tv->tv_sec * 1000) + (tv->tv_usec / 1000));
}

void
event_init(void)
{
	if (os_version() <= 4)
		errx(1, "this program must be run on Windows 2000 or greater");
	
	lib_inst = LoadLibrary("kernel32.dll");
	if (lib_inst < (HINSTANCE)HINSTANCE_ERROR)
		errx(1, "couldn't load kernel32.dll");

	create_timer_queue = (pCreateTimerQueue)GetProcAddress(lib_inst,
	    "CreateTimerQueue");
	delete_timer_queue = (pDeleteTimerQueue)GetProcAddress(lib_inst,
	    "DeleteTimerQueue");	
	create_timer = (pCreateTimerQueueTimer)GetProcAddress(lib_inst,
	    "CreateTimerQueueTimer");
	delete_timer = (pDeleteTimerQueueTimer)GetProcAddress(lib_inst,
	    "DeleteTimerQueueTimer");
	if (create_timer_queue == NULL || delete_timer_queue == NULL ||
	    create_timer == NULL || delete_timer == NULL)
		errx(1, "couldn't map timer functions - not Windows 2000?");

	timer_queue = create_timer_queue();
}

void CALLBACK
event_callback(DWORD errcode, DWORD len, OVERLAPPED *overlap)
{
	struct event *ev = (struct event *)overlap->hEvent;
	struct event_iov eio;
	
	eio.buf = ev->buf;
	eio.len = len;
	
	ev->callback((int)&eio, ev->event, ev->arg);
}

void
event_set(struct event *ev, int fd, short event,
    void (*callback)(int, short, void *), void *arg)
{
	memset(ev, 0, sizeof(*ev));
	
	ev->handle = (HANDLE)fd;
	ev->overlap.hEvent = (HANDLE)ev;
	ev->event = event;
	ev->callback = callback;
	ev->arg = arg;
}

int
event_add(struct event *ev, struct timeval *tv)
{
	if (tv != NULL || ev->event != EV_READ)
		return (-1);	/* XXX - UNIMPLEMENTED */
	
	ReadFileEx(ev->handle, ev->buf, sizeof(ev->buf),
	    &ev->overlap, event_callback);
	
	return (0);
}

int
event_initialized(struct event *ev)
{
	return (ev->handle != INVALID_HANDLE_VALUE);
}

void
event_del(struct event *ev)
{
	/* XXX - UNIMPLEMENTED */
}

void
timeout_set(struct event *ev, void (*callback)(int, short, void *), void *arg)
{
	memset(ev, 0, sizeof(*ev));
	
	ev->event = EV_TIMEOUT;
	ev->callback = callback;
	ev->arg = arg;
}

void CALLBACK
timeout_callback(PVOID arg, BOOL TimerFired)
{
	struct event *ev = (struct event *)arg;

	delete_timer(timer_queue, ev->handle, NULL);
	ev->handle = INVALID_HANDLE_VALUE;
	
	ev->callback(-1, EV_TIMEOUT, ev->arg);
}

void
timeout_add(struct event *ev, struct timeval *tv)
{
	if (create_timer(&ev->handle, timer_queue, timeout_callback, ev,
	    timeval_to_ms(tv), 0, WT_EXECUTEINIOTHREAD) == 0)
		errx(1, "CreateTimerQueueTimer failed");
}

int
event_dispatch(void)
{
	for (;;) {
		while (event_gotsig) {
			event_gotsig = 0;
			if (event_sigcb != NULL) {
				if ((*event_sigcb)() == -1) {
					delete_timer_queue(timer_queue);
					return (-1);
				}
			}
		}
		/* XXX - i'm a lazy bum */
		SleepEx(100, TRUE);
	}
	return (0);
}
