@BOTTOM@
/* XXX - for strl* definitions below */
#include <sys/types.h>

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_WINDOWS_H
#include <windows.h>
#endif

#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif

#ifndef HAVE_GETOPT
int	getopt(int argc, char * const *argv, const char *optstring);
#endif

#ifndef HAVE_STRLCAT
size_t  strlcat(char *, const char *, size_t);
#endif

#ifndef HAVE_STRLCPY
size_t  strlcpy(char *, const char *, size_t);
#endif
