/*
 * mod_jmp.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 * Copyright (c) 2012 Stas Grabois <finpushrst@gmail.com>
 *
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>

#include "err.h"
#include "argv.h"
#include "mod.h"

struct label_data 
{
	char *label;
	struct rule *rule;

	TAILQ_ENTRY(label_data) next;
};

struct jump_data 
{
	char *label;
	struct rule *dst_rule;
	struct bpf_program filter;
	int jump_mode;
};

static int labels_initialized;
static TAILQ_HEAD(head, label_data) labels;

void *
label_close(void *d)
{
	struct label_data *data = (struct label_data *)d;

	if (data != NULL)
		free(data->label);
	free(data);

	return (NULL);
}

void *
label_open(int argc, char *argv[], struct rule *rule)
{
	struct label_data *data;
	
	if (argc < 2)
		return (NULL);

	if ((data = calloc(1, sizeof(*data))) == NULL)
		return (NULL);
	
	if ((data->label = strdup(argv[1])) == NULL)
		return (label_close(data));

	data->rule = rule;

	if (!labels_initialized) {
		labels_initialized = 1;
		TAILQ_INIT(&labels);
	}

	TAILQ_INSERT_TAIL(&labels, data, next);

	return (data);
}

static struct rule * get_rule_by_name(const char* name)
{
	struct label_data *label;

	TAILQ_FOREACH(label, &labels, next) {
		if (strcmp(label->label, name) == 0)
			return label->rule;
	}

	return NULL;
}

int
label_apply(void *d, struct pktq *pktq, struct rule **next)
{
	return (0);
}

int
break_apply(void *d, struct pktq *pktq, struct rule **next)
{
	*next = NULL;
	return (0);
}

void *
jump_close(void *d)
{
	struct jump_data *data = (struct jump_data *)d;

	if (data != NULL) {
		free(data->label);
		pcap_freecode(&data->filter);
	}

	free(data);

	return (NULL);
}

void *
jump_open(int argc, char *argv[], struct rule *rule)
{
	struct jump_data *data = NULL;
	char* filter;

	if (argc < 2 || argc == 3)
		goto err;

	if ((data = calloc(1, sizeof(*data))) == NULL)
		goto err;
	
	if ((data->label = strdup(argv[1])) == NULL)
		goto err;

	if (argc == 2)
		goto out;

	if (!strcmp(argv[2], "if")) {
		data->jump_mode = 0;
	} else if (!strcmp(argv[2], "unless")) {
		data->jump_mode = 1;
	} else {
		goto err;
	}

	if ((filter = argv_copy(argv + 3)) == NULL)
		goto err;

	if (pcap_compile_nopcap(PKT_BUF_LEN, DLT_EN10MB, &data->filter, filter, 1, 0) != 0)
		goto err;

out:
	return data;

err:
	if (data)
		return (jump_close(data));
	data = NULL;
	
	return NULL;
}

int
jump_init(void *d)
{
	struct jump_data *data = (struct jump_data *)d;

	if (data->label == NULL)
		return (0);

	data->dst_rule = get_rule_by_name(data->label);
	if (!data->dst_rule) {
		warnx("couldn't find rule '%s'", data->label);
		return (-1);
	}

	return (0);
}

int
jump_apply(void *d, struct pktq *pktq, struct rule **next)
{
	struct jump_data *data = (struct jump_data *)d;
	struct bpf_insn *fcode;
	int status;
	int len;

	struct pkt *pkt = TAILQ_FIRST(pktq);
	if (pkt == NULL)
		return (0);

	fcode = data->filter.bf_insns;

	if (fcode == NULL)
		return (0);

	len = pkt->pkt_end - pkt->pkt_data;
	status = bpf_filter(fcode, pkt->pkt_data, len, len);

	if ((status ^ data->jump_mode) != 0)
		*next = data->dst_rule;

	return (0);
}

struct mod mod_label = {
	"label",			/* name */
	"label <string>",		/* usage */
	label_open,			/* open */
	NULL,				/* init */
	label_apply,			/* apply */
	label_close			/* close */
};

struct mod mod_jump = {
	"jump",			/* name */
	"jump <label> [ <if|unless> <filter> ]",		/* usage */
	jump_open,			/* open */
	jump_init,			/* init */
	jump_apply,			/* apply */
	jump_close			/* close */
};

struct mod mod_break = {
	"break",			/* name */
	"break",		/* usage */
	NULL,			/* open */
	NULL,				/* init */
	break_apply,			/* apply */
	NULL			/* close */
};
