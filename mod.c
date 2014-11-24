/*
 * mod.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: mod.c,v 1.19 2002/04/07 22:55:20 dugsong Exp $
 */

#include "config.h"

#include <ctype.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "argv.h"
#include "mod.h"

#define MAX_ARGS		 128	/* XXX */

struct rule {
	struct mod		*mod;
	void			*data;
	TAILQ_ENTRY(rule)	 next;
};

/*
 * XXX - new modules must be registered here.
 */
extern struct mod	 mod_delay;
extern struct mod	 mod_drop;
extern struct mod	 mod_dup;
extern struct mod	 mod_echo;
extern struct mod	 mod_ip_chaff;
extern struct mod	 mod_ip_frag;
extern struct mod	 mod_ip_opt;
extern struct mod	 mod_ip_ttl;
extern struct mod	 mod_ip_tos;
extern struct mod	 mod_ip6_qos;
extern struct mod	 mod_ip6_opt;
extern struct mod	 mod_order;
extern struct mod	 mod_print;
extern struct mod	 mod_tcp_chaff;
extern struct mod	 mod_tcp_opt;
extern struct mod	 mod_tcp_seg;
extern struct mod	 mod_label;
extern struct mod	 mod_break;
extern struct mod	 mod_jump;

static struct mod *mods[] = {
	&mod_delay,
	&mod_drop,
	&mod_dup,
	&mod_echo,
	&mod_ip_chaff,
	&mod_ip_frag,
	&mod_ip_opt,
	&mod_ip_ttl,
	&mod_ip_tos,
	&mod_ip6_qos,
	&mod_ip6_opt,
	&mod_order,
	&mod_print,
	&mod_tcp_chaff,
	&mod_tcp_opt,
	&mod_tcp_seg,
	&mod_label,
	&mod_break,
	&mod_jump,
	NULL
};

static TAILQ_HEAD(head, rule) rules;

void
mod_usage(void)
{
	struct mod **m;

	for (m = mods; *m != NULL; m++) {
		fprintf(stderr, "       %s\n", (*m)->usage);
	}
}

int
mod_open(const char *script)
{
	FILE *fp;
	struct mod **m;
	struct rule *rule;
	char *argv[MAX_ARGS], buf[BUFSIZ];
	int i, argc, ret = 0;

	TAILQ_INIT(&rules);
	
	if ((fp = fopen(script, "r")) == NULL) {
		warnx("couldn't open %s", script);
		return (-1);
	}
	for (i = 1; fgets(buf, sizeof(buf), fp) != NULL; i++) {
		if (*buf == '#' || *buf == '\r' || *buf == '\n')
			continue;
		
		if ((argc = argv_create(buf, MAX_ARGS, argv)) < 1) {
			warnx("couldn't parse arguments (line %d)", i);
			ret = -1;
			break;
		}
		for (m = mods; *m != NULL; m++) {
			if (strcasecmp((*m)->name, argv[0]) == 0)
				break;
		}
		if (*m == NULL) {
			warnx("unknown directive '%s' (line %d)", argv[0], i);
			ret = -1;
			break;
		}
		if ((rule = calloc(1, sizeof(*rule))) == NULL) {
			warn("calloc");
			ret = -1;
			break;
		}
		rule->mod = *m;

		if (rule->mod->open != NULL &&
		    (rule->data = rule->mod->open(argc, argv, rule)) == NULL) {
			warnx("invalid argument to directive '%s' (line %d)",
			    rule->mod->name, i);
			ret = -1;
			break;
		}
		TAILQ_INSERT_TAIL(&rules, rule, next);
	}
	fclose(fp);

	if (ret == 0) {
		buf[0] = '\0';
		TAILQ_FOREACH(rule, &rules, next) {
			strlcat(buf, rule->mod->name, sizeof(buf));
			strlcat(buf, " -> ", sizeof(buf));
		}
		buf[strlen(buf) - 4] = '\0';
		warnx("%s", buf);

		if (mod_init() < 0) {
			ret = -1;
		}
	}
	return (ret);
}

int
mod_init(void)
{
	struct rule *rule;
	
	TAILQ_FOREACH(rule, &rules, next) {
		if (rule->mod->init) {
			if (rule->mod->init(rule->data) < 0) {
				warnx("Module initialization failed - '%s'", rule->mod->name);
				return -1;
			}
		}
	}

	return (0);
}

void
mod_apply(struct pktq *pktq)
{
	struct rule *rule;
	struct rule *next_rule;
	
	rule = TAILQ_FIRST(&rules);

	for (; rule != TAILQ_END(&rules); rule = next_rule) {
		next_rule = TAILQ_NEXT(rule, next);
		rule->mod->apply(rule->data, pktq, &next_rule);
	}
}

void
mod_close(void)
{
	struct rule *rule;
	
	TAILQ_FOREACH_REVERSE(rule, &rules, next, head) {
		if (rule->mod->close != NULL)
			rule->data = rule->mod->close(rule->data);
		TAILQ_REMOVE(&rules, rule, next);
		free(rule);
	}
}
