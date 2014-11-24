/*
 * mod_order.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: mod_order.c,v 1.9 2002/04/07 22:55:20 dugsong Exp $
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mod.h"

#define ORDER_RANDOM	1
#define ORDER_REVERSE	2

struct order_data {
	rand_t	*rnd;
	int	 type;
};

void *
order_close(void *d)
{
	struct order_data *data = (struct order_data *)d;

	if (data != NULL) {
		rand_close(data->rnd);
		free(data);
	}
	return (NULL);
}

void *
order_open(int argc, char *argv[], struct rule *rule)
{
	struct order_data *data;
	
	if (argc < 2)
		return (NULL);
	
	if ((data = malloc(sizeof(*data))) == NULL)
		return (NULL);

	data->rnd = rand_open();
	
	if (strcasecmp(argv[1], "random") == 0) {
		data->type = ORDER_RANDOM;
	} else if (strcasecmp(argv[1], "reverse") == 0) {
		data->type = ORDER_REVERSE;
	} else
		return (order_close(data));

	return (data);
}

int
order_apply(void *d, struct pktq *pktq, struct rule **next_rule)
{
	struct order_data *data = (struct order_data *)d;
	
	if (data->type == ORDER_RANDOM)
		pktq_shuffle(data->rnd, pktq);
	else
		pktq_reverse(pktq);
	
	return (0);
}

struct mod mod_order = {
	"order",			/* name */
	"order random|reverse",		/* usage */
	order_open,			/* open */
	NULL,				/* init */
	order_apply,			/* apply */
	order_close			/* close */
};
