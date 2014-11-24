## $Id: Makefile.am,v 1.19 2002/04/15 14:42:49 dugsong Exp $

AUTOMAKE_OPTIONS = foreign no-dependencies

SUBDIRS = scripts win32

INCLUDES = @DNETINC@ @PCAPINC@ @EVENTINC@

LDADD = @LIBOBJS@ @DNETLIB@ @PCAPLIB@ @EVENTLIB@

sbin_PROGRAMS = fragroute fragtest

fragroute_SOURCES = fragroute.c argv.c argv.h bget.c bget.h err.h mod.c mod.h \
	pcaputil.c pcaputil.h pkt.c pkt.h queue.h randutil.c randutil.h tun.h \
	iputil.c iputil.h \
	mod_delay.c mod_drop.c mod_dup.c mod_echo.c mod_ip_chaff.c \
	mod_ip_frag.c mod_ip_opt.c mod_ip_ttl.c mod_ip_tos.c mod_order.c \
	mod_print.c mod_tcp_chaff.c mod_tcp_opt.c mod_tcp_seg.c \
	mod_ip6_opt.c mod_ip6_qos.c mod_jmp.c

fragtest_SOURCES = fragtest.c bget.c mod_ip_frag.c pcaputil.c pkt.c randutil.c iputil.c

man_MANS = fragroute.8 fragtest.8

fragroute.8.txt: fragroute.8
	groff -t -e -man -Tascii fragroute.8 | col -bx > $@

fragtest.8.txt: fragtest.8
	groff -t -e -man -Tascii fragtest.8 | col -bx > $@

sysconf_DATA = fragroute.conf

EXTRA_DIST = LICENSE acconfig.h fragroute.conf $(man_MANS)

DISTCLEANFILES = *~
