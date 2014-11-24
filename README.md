fragroute-ipv6
==============

fragroute intercepts, modifies, and rewrites egress traffic destined for a specified host, implementing most of the attacks described in the Secure Networks "Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection" paper of January 1998. 

fragroute-ipv6 does the same for ipv6 traffic. 

## required libraries / drivers

[libdnet](https://github.com/stsi/libdnet-ipv6)
[libpcap](http://www.tcpdump.org/)
[libevent](http://www.monkey.org/~provos/libevent/) (for non-Win2k only) 
[TUN/TAP](http://vtun.sourceforge.net/tun/) (for Solaris only) 
[CIPE-win32](http://cipe-win32.sourceforge.net/) (for Win2k only) 

Libdnet 1.12 or later required. libdnet-1.12.ipv6.patch must be applied to include ndisc cache manipulation and tcp options over ipv6. 

IPv6 code - built and tested on Linux (CentOS 5.x / 6.x). 

Original code - built and tested on OpenBSD, FreeBSD, Linux, Solaris, and Windows 2000. 

[Official site] (http://www.monkey.org/~dugsong/fragroute/)

## News

2014-11-14 - Moved to GitHub
2012-12-06 - Added version 1.2.6 - support automake>1.9 and use shared libraries. 
2012-06-06 - Added version 1.2.5 - added script flow control - 'label', 'jump' and 'break' commands. 
2012-05-22 - Added version 1.2.4 - fixed minor errors. 
2009-09-02 - Added version 1.2.3 - fixed ip_frag's processing of all L4 protocols. 
2009-09-02 - Added libdnet patch - fixed compilation error on FreeBSD. 
2009-07-23 - Added version 1.2.2 - minor bug fixes. 


## Contact

Stas Grabois,
 finpushack,
 gmail.com 
