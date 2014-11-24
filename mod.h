/*
 * mod.h
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: mod.h,v 1.3 2002/04/07 22:55:20 dugsong Exp $
 */

#ifndef MOD_H
#define MOD_H

#include "pkt.h"

struct rule;

struct mod {
	char	 *name;
	char	 *usage;
	void	*(*open)(int argc, char *argv[], struct rule *rule);
	int	 (*init)(void *data);
	int	 (*apply)(void *data, struct pktq *pktq, struct rule **next);
	void	*(*close)(void *data);
};

void	mod_usage(void);
int	mod_open(const char *script);
int	mod_init(void);
void	mod_apply(struct pktq *pktq);
void	mod_close(void);

#endif /* MOD_H */
