/*
 * mod_echo.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: mod_echo.c,v 1.4 2002/04/07 22:55:20 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "argv.h"
#include "mod.h"

void *
echo_open(int argc, char *argv[], struct rule *rule)
{
	char *p;
	
	if (argc < 2)
		return (NULL);

	if ((p = argv_copy(argv + 1)) == NULL)
		return (NULL);

	return (p);
}

int
echo_apply(void *d, struct pktq *pktq, struct rule **next_rule)
{
	char *p = (char *)d;

	printf("%s\n", p);
	return (0);
}

void *
echo_close(void *d)
{
	if (d != NULL)
		free(d);
	return (NULL);
}

struct mod mod_echo = {
	"echo",				/* name */
	"echo <string> ...",		/* usage */
	echo_open,			/* open */
	NULL,				/* init */
	echo_apply,			/* apply */
	echo_close			/* close */
};
