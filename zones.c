/*
 * firewall3 - 3rd OpenWrt UCI firewall implementation
 *
 *   Copyright (C) 2013 Jo-Philipp Wich <jo@mein.io>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "zones.h"
#include "ubus.h"
#include "helpers.h"


#define C(f, tbl, tgt, fmt) \
	{ FW3_FAMILY_##f, FW3_TABLE_##tbl, FW3_FLAG_##tgt, fmt }

static const struct fw3_chain_spec zone_chains[] = {
	C(ANY, FILTER, UNSPEC,        "zone_?_input"),
	C(ANY, FILTER, UNSPEC,        "zone_?_output"),
	C(ANY, FILTER, UNSPEC,        "zone_?_forward"),

	C(ANY, FILTER, SRC_ACCEPT,    "zone_?_src_ACCEPT"),
	C(ANY, FILTER, SRC_REJECT,    "zone_?_src_REJECT"),
	C(ANY, FILTER, SRC_DROP,      "zone_?_src_DROP"),

	C(ANY, FILTER, ACCEPT,        "zone_?_dest_ACCEPT"),
	C(ANY, FILTER, REJECT,        "zone_?_dest_REJECT"),
	C(ANY, FILTER, DROP,          "zone_?_dest_DROP"),

	C(V4,  NAT,    SNAT,          "zone_?_postrouting"),
	C(V4,  NAT,    DNAT,          "zone_?_prerouting"),

	C(ANY, RAW,    HELPER,        "zone_?_helper"),
	C(ANY, RAW,    NOTRACK,       "zone_?_notrack"),

	C(ANY, FILTER, CUSTOM_CHAINS, "input_?_rule"),
	C(ANY, FILTER, CUSTOM_CHAINS, "output_?_rule"),
	C(ANY, FILTER, CUSTOM_CHAINS, "forwarding_?_rule"),

	C(V4,  NAT,    CUSTOM_CHAINS, "prerouting_?_rule"),
	C(V4,  NAT,    CUSTOM_CHAINS, "postrouting_?_rule"),

	{ }
};

enum fw3_zone_logmask {
	FW3_ZONE_LOG_FILTER = (1 << 0),
	FW3_ZONE_LOG_MANGLE = (1 << 1),
};

const struct fw3_option fw3_zone_opts[] = {
	FW3_OPT("enabled",             bool,     zone,     enabled),

	FW3_OPT("name",                string,   zone,     name),
	FW3_OPT("family",              family,   zone,     family),

	FW3_LIST("network",            device,   zone,     networks),
	FW3_LIST("device",             device,   zone,     devices),
	FW3_LIST("subnet",             network,  zone,     subnets),

	FW3_OPT("input",               target,   zone,     policy_input),
	FW3_OPT("forward",             target,   zone,     policy_forward),
	FW3_OPT("output",              target,   zone,     policy_output),

	FW3_OPT("masq",                bool,     zone,     masq),
	FW3_OPT("masq_allow_invalid",  bool,     zone,     masq_allow_invalid),
	FW3_LIST("masq_src",           network,  zone,     masq_src),
	FW3_LIST("masq_dest",          network,  zone,     masq_dest),

	FW3_OPT("extra",               string,   zone,     extra_src),
	FW3_OPT("extra_src",           string,   zone,     extra_src),
	FW3_OPT("extra_dest",          string,   zone,     extra_dest),

	FW3_OPT("mtu_fix",             bool,     zone,     mtu_fix),
	FW3_OPT("custom_chains",       bool,     zone,     custom_chains),

	FW3_OPT("log",                 int,      zone,     log),
	FW3_OPT("log_limit",           limit,    zone,     log_limit),

	FW3_OPT("auto_helper",         bool,     zone,     auto_helper),
	FW3_LIST("helper",             cthelper, zone,     cthelpers),

	FW3_OPT("__flags_v4",          int,      zone,     flags[0]),
	FW3_OPT("__flags_v6",          int,      zone,     flags[1]),

	FW3_LIST("__addrs",            address,  zone,     old_addrs),

	{ }
};

static void
check_policy(struct uci_element *e, enum fw3_flag *pol, enum fw3_flag def,
             const char *name)
{
	if (*pol == FW3_FLAG_UNSPEC)
	{
		warn_elem(e, "has no %s policy specified, using default", name);
		*pol = def;
	}
	else if (*pol > FW3_FLAG_DROP)
	{
		warn_elem(e, "has invalid %s policy, using default", name);
		*pol = def;
	}
}

static bool
check_masq_addrs(struct list_head *head)
{
	struct fw3_address *addr;
	int n_addr = 0, n_failed = 0;

	list_for_each_entry(addr, head, list)
	{
		if (addr->invert)
			continue;

		n_addr++;

		if (!addr->set && addr->resolved)
			n_failed++;
	}

	return (n_addr == 0 || n_failed < n_addr);
}

static void
resolve_networks(struct uci_element *e, struct fw3_zone *zone)
{
	struct fw3_device *net, *dev, *tmp;

	list_for_each_entry(net, &zone->networks, list)
	{
		tmp = fw3_ubus_device(net->name);

		if (!tmp)
		{
			warn_elem(e, "cannot resolve device of network '%s'", net->name);
			continue;
		}

		list_for_each_entry(dev, &zone->devices, list)
			if (!strcmp(dev->name, tmp->name))
				goto alias;

		snprintf(tmp->network, sizeof(tmp->network), "%s", net->name);
		list_add_tail(&tmp->list, &zone->devices);
		continue;
alias:
		free(tmp);
	}
}

static void
resolve_cthelpers(struct fw3_state *s, struct uci_element *e, struct fw3_zone *zone)
{
	struct fw3_cthelpermatch *match;

	if (list_empty(&zone->cthelpers))
	{
		if (!zone->masq && zone->auto_helper)
		{
			fw3_setbit(zone->flags[0], FW3_FLAG_HELPER);
			fw3_setbit(zone->flags[1], FW3_FLAG_HELPER);
		}

		return;
	}

	list_for_each_entry(match, &zone->cthelpers, list)
	{
		if (match->invert)
		{
			warn_elem(e, "must not use a negated helper match");
			continue;
		}

		match->ptr = fw3_lookup_cthelper(s, match->name);

		if (!match->ptr)
		{
			warn_elem(e, "refers to not existing helper '%s'", match->name);
			continue;
		}

		if (fw3_is_family(match->ptr, FW3_FAMILY_V4))
			fw3_setbit(zone->flags[0], FW3_FLAG_HELPER);

		if (fw3_is_family(match->ptr, FW3_FAMILY_V6))
			fw3_setbit(zone->flags[1], FW3_FLAG_HELPER);
	}
}

struct fw3_zone *
fw3_alloc_zone(void)
{
	struct fw3_zone *zone;

	zone = calloc(1, sizeof(*zone));
	if (!zone)
		return NULL;

	INIT_LIST_HEAD(&zone->networks);
	INIT_LIST_HEAD(&zone->devices);
	INIT_LIST_HEAD(&zone->subnets);
	INIT_LIST_HEAD(&zone->masq_src);
	INIT_LIST_HEAD(&zone->masq_dest);
	INIT_LIST_HEAD(&zone->cthelpers);

	INIT_LIST_HEAD(&zone->old_addrs);

	zone->enabled = true;
	zone->auto_helper = true;
	zone->custom_chains = true;
	zone->log_limit.rate = 10;

	return zone;
}

void
fw3_load_zones(struct fw3_state *state, struct uci_package *p)
{
	struct uci_section *s;
	struct uci_element *e;
	struct fw3_zone *zone;
	struct fw3_defaults *defs = &state->defaults;

	INIT_LIST_HEAD(&state->zones);

	uci_foreach_element(&p->sections, e)
	{
		s = uci_to_section(e);

		if (strcmp(s->type, "zone"))
			continue;

		zone = fw3_alloc_zone();

		if (!zone)
			continue;

		if (!fw3_parse_options(zone, fw3_zone_opts, s))
			warn_elem(e, "has invalid options");

		if (!zone->enabled)
		{
			fw3_free_zone(zone);
			continue;
		}

		if (!zone->extra_dest)
			zone->extra_dest = zone->extra_src;

		if (!defs->custom_chains && zone->custom_chains)
			zone->custom_chains = false;

		if (!defs->auto_helper && zone->auto_helper)
			zone->auto_helper = false;

		if (!zone->name || !*zone->name)
		{
			warn_elem(e, "has no name - ignoring");
			fw3_free_zone(zone);
			continue;
		}

		if (strlen(zone->name) > FW3_ZONE_MAXNAMELEN)
		{
			warn_elem(e, "must not have a name longer than %u characters",
			             FW3_ZONE_MAXNAMELEN);
			fw3_free_zone(zone);
			continue;
		}

		fw3_ubus_zone_devices(zone);

		if (list_empty(&zone->networks) && list_empty(&zone->devices) &&
		    list_empty(&zone->subnets) && !zone->extra_src)
		{
			warn_elem(e, "has no device, network, subnet or extra options");
		}

		if (!check_masq_addrs(&zone->masq_src))
		{
			warn_elem(e, "has unresolved masq_src, disabling masq");
			zone->masq = false;
		}

		if (!check_masq_addrs(&zone->masq_dest))
		{
			warn_elem(e, "has unresolved masq_dest, disabling masq");
			zone->masq = false;
		}

		check_policy(e, &zone->policy_input, defs->policy_input, "input");
		check_policy(e, &zone->policy_output, defs->policy_output, "output");
		check_policy(e, &zone->policy_forward, defs->policy_forward, "forward");

		resolve_networks(e, zone);

		if (zone->masq)
		{
			fw3_setbit(zone->flags[0], FW3_FLAG_SNAT);
		}

		if (zone->custom_chains)
		{
			fw3_setbit(zone->flags[0], FW3_FLAG_SNAT);
			fw3_setbit(zone->flags[0], FW3_FLAG_DNAT);
		}

		resolve_cthelpers(state, e, zone);

		fw3_setbit(zone->flags[0], fw3_to_src_target(zone->policy_input));
		fw3_setbit(zone->flags[0], zone->policy_forward);
		fw3_setbit(zone->flags[0], zone->policy_output);

		fw3_setbit(zone->flags[1], fw3_to_src_target(zone->policy_input));
		fw3_setbit(zone->flags[1], zone->policy_forward);
		fw3_setbit(zone->flags[1], zone->policy_output);

		list_add_tail(&zone->list, &state->zones);
	}
}


static char *
format_chain(const char *fmt, const char *zonename)
{
	static char chain[32];
	size_t rem;
	char *p;
	int len;

	for (p = chain, rem = sizeof(chain); *fmt; fmt++) {
		if (*fmt == '?') {
			len = snprintf(p, rem, "%s", zonename);

			if (len < 0 || len >= rem)
				break;

			rem -= len;
			p += len;
		}
		else {
			if (rem <= 1)
				break;

			*p++ = *fmt;
			rem--;
		}
	}

	*p = 0;

	return chain;
}

static void
print_zone_chain(struct fw3_ipt_handle *handle, struct fw3_state *state,
                 bool reload, struct fw3_zone *zone)
{
	int i;
	struct fw3_ipt_rule *r;
	const struct fw3_chain_spec *c;

	const char *flt_chains[] = {
		"input",   "input",
		"output",  "output",
		"forward", "forwarding",
	};

	const char *nat_chains[] = {
		"prerouting",  "prerouting",
		"postrouting", "postrouting",
	};

	if (!fw3_is_family(zone, handle->family))
		return;

	set(zone->flags, handle->family, handle->table);

	if (zone->custom_chains)
		set(zone->flags, handle->family, FW3_FLAG_CUSTOM_CHAINS);

	for (c = zone_chains; c->format; c++)
	{
		if (!fw3_is_family(c, handle->family))
			continue;

		if (c->table != handle->table)
			continue;

		if (c->flag &&
		    !fw3_hasbit(zone->flags[handle->family == FW3_FAMILY_V6], c->flag))
			continue;

		fw3_ipt_create_chain(handle, reload, format_chain(c->format, zone->name));
	}

	if (zone->custom_chains)
	{
		if (handle->table == FW3_TABLE_FILTER)
		{
			for (i = 0; i < sizeof(flt_chains)/sizeof(flt_chains[0]); i += 2)
			{
				r = fw3_ipt_rule_new(handle);
				fw3_ipt_rule_comment(r, "Custom %s %s rule chain", zone->name, flt_chains[i+1]);
				fw3_ipt_rule_target(r, "%s_%s_rule", flt_chains[i+1], zone->name);
				fw3_ipt_rule_append(r, "zone_%s_%s", zone->name, flt_chains[i]);
			}
		}
		else if (handle->table == FW3_TABLE_NAT)
		{
			for (i = 0; i < sizeof(nat_chains)/sizeof(nat_chains[0]); i += 2)
			{
				r = fw3_ipt_rule_new(handle);
				fw3_ipt_rule_comment(r, "Custom %s %s rule chain", zone->name, nat_chains[i+1]);
				fw3_ipt_rule_target(r, "%s_%s_rule", nat_chains[i+1], zone->name);
				fw3_ipt_rule_append(r, "zone_%s_%s", zone->name, nat_chains[i]);
			}
		}
	}

	set(zone->flags, handle->family, handle->table);
}

static void
print_interface_rule(struct fw3_ipt_handle *handle, struct fw3_state *state,
					 bool reload, struct fw3_zone *zone,
                     struct fw3_device *dev, struct fw3_address *sub)
{
	struct fw3_protocol tcp = { .protocol = 6 };
	struct fw3_ipt_rule *r;
	enum fw3_flag t;

	char buf[32];

	int i;

	const char *chains[] = {
		"input", "INPUT",
		"output", "OUTPUT",
		"forward", "FORWARD",
	};

#define jump_target(t) \
	((t == FW3_FLAG_REJECT) ? "reject" : fw3_flag_names[t])

	if (handle->table == FW3_TABLE_FILTER)
	{
		for (t = FW3_FLAG_ACCEPT; t <= FW3_FLAG_DROP; t++)
		{
			if (t > FW3_FLAG_ACCEPT && zone->log & FW3_ZONE_LOG_FILTER)
			{
				if (has(zone->flags, handle->family, fw3_to_src_target(t)))
				{
					r = fw3_ipt_rule_create(handle, NULL, dev, NULL, sub, NULL);

					snprintf(buf, sizeof(buf) - 1, "%s %s in: ",
					         fw3_flag_names[t], zone->name);

					fw3_ipt_rule_limit(r, &zone->log_limit);
					fw3_ipt_rule_target(r, "LOG");
					fw3_ipt_rule_addarg(r, false, "--log-prefix", buf);
					fw3_ipt_rule_replace(r, "zone_%s_src_%s",
					                     zone->name, fw3_flag_names[t]);
				}

				if (has(zone->flags, handle->family, t))
				{
					r = fw3_ipt_rule_create(handle, NULL, NULL, dev, NULL, sub);

					snprintf(buf, sizeof(buf) - 1, "%s %s out: ",
					         fw3_flag_names[t], zone->name);

					fw3_ipt_rule_limit(r, &zone->log_limit);
					fw3_ipt_rule_target(r, "LOG");
					fw3_ipt_rule_addarg(r, false, "--log-prefix", buf);
					fw3_ipt_rule_replace(r, "zone_%s_dest_%s",
					                     zone->name, fw3_flag_names[t]);
				}
			}

			if (has(zone->flags, handle->family, fw3_to_src_target(t)))
			{
				r = fw3_ipt_rule_create(handle, NULL, dev, NULL, sub, NULL);
				fw3_ipt_rule_target(r, jump_target(t));
				fw3_ipt_rule_extra(r, zone->extra_src);

				if (t == FW3_FLAG_ACCEPT && !state->defaults.drop_invalid)
					fw3_ipt_rule_extra(r,
					                   "-m conntrack --ctstate NEW,UNTRACKED");

				fw3_ipt_rule_replace(r, "zone_%s_src_%s", zone->name,
				                     fw3_flag_names[t]);
			}

			if (has(zone->flags, handle->family, t))
			{
				if (t == FW3_FLAG_ACCEPT &&
				    zone->masq && !zone->masq_allow_invalid)
				{
					r = fw3_ipt_rule_create(handle, NULL, NULL, dev, NULL, sub);
					fw3_ipt_rule_extra(r, "-m conntrack --ctstate INVALID");
					fw3_ipt_rule_comment(r, "Prevent NAT leakage");
					fw3_ipt_rule_target(r, fw3_flag_names[FW3_FLAG_DROP]);
					fw3_ipt_rule_replace(r, "zone_%s_dest_%s", zone->name,
					                     fw3_flag_names[t]);
				}

				r = fw3_ipt_rule_create(handle, NULL, NULL, dev, NULL, sub);
				fw3_ipt_rule_target(r, jump_target(t));
				fw3_ipt_rule_extra(r, zone->extra_dest);
				fw3_ipt_rule_replace(r, "zone_%s_dest_%s", zone->name,
				                     fw3_flag_names[t]);
			}
		}

		for (i = 0; i < sizeof(chains)/sizeof(chains[0]); i += 2)
		{
			if (*chains[i] == 'o')
				r = fw3_ipt_rule_create(handle, NULL, NULL, dev, NULL, sub);
			else
				r = fw3_ipt_rule_create(handle, NULL, dev, NULL, sub, NULL);

			fw3_ipt_rule_target(r, "zone_%s_%s", zone->name, chains[i]);

			if (*chains[i] == 'o')
				fw3_ipt_rule_extra(r, zone->extra_dest);
			else
				fw3_ipt_rule_extra(r, zone->extra_src);

			fw3_ipt_rule_replace(r, chains[i + 1]);
		}
	}
	else if (handle->table == FW3_TABLE_NAT)
	{
		if (has(zone->flags, handle->family, FW3_FLAG_DNAT))
		{
			r = fw3_ipt_rule_create(handle, NULL, dev, NULL, sub, NULL);
			fw3_ipt_rule_target(r, "zone_%s_prerouting", zone->name);
			fw3_ipt_rule_extra(r, zone->extra_src);
			fw3_ipt_rule_replace(r, "PREROUTING");
		}

		if (has(zone->flags, handle->family, FW3_FLAG_SNAT))
		{
			r = fw3_ipt_rule_create(handle, NULL, NULL, dev, NULL, sub);
			fw3_ipt_rule_target(r, "zone_%s_postrouting", zone->name);
			fw3_ipt_rule_extra(r, zone->extra_dest);
			fw3_ipt_rule_replace(r, "POSTROUTING");
		}
	}
	else if (handle->table == FW3_TABLE_MANGLE)
	{
		if (zone->mtu_fix)
		{
			if (zone->log & FW3_ZONE_LOG_MANGLE)
			{
				snprintf(buf, sizeof(buf) - 1, "MSSFIX %s out: ", zone->name);

				r = fw3_ipt_rule_create(handle, &tcp, NULL, dev, NULL, sub);
				fw3_ipt_rule_addarg(r, false, "--tcp-flags", "SYN,RST");
				fw3_ipt_rule_addarg(r, false, "SYN", NULL);
				fw3_ipt_rule_limit(r, &zone->log_limit);
				fw3_ipt_rule_comment(r, "Zone %s MTU fix logging", zone->name);
				fw3_ipt_rule_target(r, "LOG");
				fw3_ipt_rule_addarg(r, false, "--log-prefix", buf);
				fw3_ipt_rule_replace(r, "FORWARD");
			}

			r = fw3_ipt_rule_create(handle, &tcp, NULL, dev, NULL, sub);
			fw3_ipt_rule_addarg(r, false, "--tcp-flags", "SYN,RST");
			fw3_ipt_rule_addarg(r, false, "SYN", NULL);
			fw3_ipt_rule_comment(r, "Zone %s MTU fixing", zone->name);
			fw3_ipt_rule_target(r, "TCPMSS");
			fw3_ipt_rule_addarg(r, false, "--clamp-mss-to-pmtu", NULL);
			fw3_ipt_rule_replace(r, "POSTROUTING");

			r = fw3_ipt_rule_create(handle, &tcp, dev, NULL, sub, NULL);
			fw3_ipt_rule_addarg(r, false, "--tcp-flags", "SYN,RST");
			fw3_ipt_rule_addarg(r, false, "SYN", NULL);
			fw3_ipt_rule_comment(r, "Zone %s MTU fixing", zone->name);
			fw3_ipt_rule_target(r, "TCPMSS");
			fw3_ipt_rule_addarg(r, false, "--clamp-mss-to-pmtu", NULL);
			fw3_ipt_rule_replace(r, "FORWARD");
		}
	}
	else if (handle->table == FW3_TABLE_RAW)
	{
		bool loopback_dev = (dev != NULL && !dev->any &&
				     !dev->invert && fw3_check_loopback_dev(dev->name));
		char *chain = loopback_dev || (sub != NULL && !sub->invert && fw3_check_loopback_addr(sub)) ?
			      "OUTPUT" : "PREROUTING";

		if (has(zone->flags, handle->family, FW3_FLAG_HELPER))
		{
			r = fw3_ipt_rule_create(handle, NULL, loopback_dev ? NULL : dev, NULL, sub, NULL);
			fw3_ipt_rule_comment(r, "%s CT helper assignment", zone->name);
			fw3_ipt_rule_target(r, "zone_%s_helper", zone->name);
			fw3_ipt_rule_extra(r, zone->extra_src);
			fw3_ipt_rule_replace(r, chain);
		}

		if (has(zone->flags, handle->family, FW3_FLAG_NOTRACK))
		{
			r = fw3_ipt_rule_create(handle, NULL, loopback_dev ? NULL : dev, NULL, sub, NULL);
			fw3_ipt_rule_comment(r, "%s CT bypass", zone->name);
			fw3_ipt_rule_target(r, "zone_%s_notrack", zone->name);
			fw3_ipt_rule_extra(r, zone->extra_src);
			fw3_ipt_rule_replace(r, chain);
		}
	}
}

static void
print_interface_rules(struct fw3_ipt_handle *handle, struct fw3_state *state,
                      bool reload, struct fw3_zone *zone)
{
	struct fw3_device *dev;
	struct fw3_address *sub;

	fw3_foreach(dev, &zone->devices)
	fw3_foreach(sub, &zone->subnets)
	{
		if (!fw3_is_family(sub, handle->family))
			continue;

		if (!dev && !sub && !zone->extra_src && !zone->extra_dest)
			continue;

		print_interface_rule(handle, state, reload, zone, dev, sub);
	}
}

static struct fw3_address *
next_addr(struct fw3_address *addr, struct list_head *list,
                enum fw3_family family, bool invert)
{
	struct list_head *p;
	struct fw3_address *rv;

	for (p = addr ? addr->list.next : list->next; p != list; p = p->next)
	{
		rv = list_entry(p, struct fw3_address, list);

		if (fw3_is_family(rv, family) && rv->set && rv->invert == invert)
			return rv;
	}

	return NULL;
}

static void
print_zone_rule(struct fw3_ipt_handle *handle, struct fw3_state *state,
                bool reload, struct fw3_zone *zone)
{
	bool first_src, first_dest;
	struct fw3_address *msrc;
	struct fw3_address *mdest;
	struct fw3_ipt_rule *r;

	if (!fw3_is_family(zone, handle->family))
		return;

	info("   * Zone '%s'", zone->name);

	switch (handle->table)
	{
	case FW3_TABLE_FILTER:
		if (has(zone->flags, handle->family, FW3_FLAG_DNAT))
		{
			r = fw3_ipt_rule_new(handle);
			fw3_ipt_rule_extra(r, "-m conntrack --ctstate DNAT");
			fw3_ipt_rule_comment(r, "Accept port redirections");
			fw3_ipt_rule_target(r, fw3_flag_names[FW3_FLAG_ACCEPT]);
			fw3_ipt_rule_append(r, "zone_%s_input", zone->name);

			r = fw3_ipt_rule_new(handle);
			fw3_ipt_rule_extra(r, "-m conntrack --ctstate DNAT");
			fw3_ipt_rule_comment(r, "Accept port forwards");
			fw3_ipt_rule_target(r, fw3_flag_names[FW3_FLAG_ACCEPT]);
			fw3_ipt_rule_append(r, "zone_%s_forward", zone->name);
		}

		r = fw3_ipt_rule_new(handle);
		fw3_ipt_rule_target(r, "zone_%s_src_%s", zone->name,
		                     fw3_flag_names[zone->policy_input]);
		fw3_ipt_rule_append(r, "zone_%s_input", zone->name);

		r = fw3_ipt_rule_new(handle);
		fw3_ipt_rule_target(r, "zone_%s_dest_%s", zone->name,
		                     fw3_flag_names[zone->policy_forward]);
		fw3_ipt_rule_append(r, "zone_%s_forward", zone->name);

		r = fw3_ipt_rule_new(handle);
		fw3_ipt_rule_target(r, "zone_%s_dest_%s", zone->name,
		                     fw3_flag_names[zone->policy_output]);
		fw3_ipt_rule_append(r, "zone_%s_output", zone->name);

		break;

	case FW3_TABLE_NAT:
		if (zone->masq && handle->family == FW3_FAMILY_V4)
		{
			/* for any negated masq_src ip, emit -s addr -j RETURN rules */
			for (msrc = NULL;
			     (msrc = next_addr(msrc, &zone->masq_src,
			                       handle->family, true)) != NULL; )
			{
				msrc->invert = false;
				r = fw3_ipt_rule_new(handle);
				fw3_ipt_rule_src_dest(r, msrc, NULL);
				fw3_ipt_rule_target(r, "RETURN");
				fw3_ipt_rule_append(r, "zone_%s_postrouting", zone->name);
				msrc->invert = true;
			}

			/* for any negated masq_dest ip, emit -d addr -j RETURN rules */
			for (mdest = NULL;
			     (mdest = next_addr(mdest, &zone->masq_dest,
			                        handle->family, true)) != NULL; )
			{
				mdest->invert = false;
				r = fw3_ipt_rule_new(handle);
				fw3_ipt_rule_src_dest(r, NULL, mdest);
				fw3_ipt_rule_target(r, "RETURN");
				fw3_ipt_rule_append(r, "zone_%s_postrouting", zone->name);
				mdest->invert = true;
			}

			/* emit masquerading entries for non-negated addresses
			   and ensure that both src and dest loops run at least once,
			   even if there are no relevant addresses */
			for (first_src = true, msrc = NULL;
			     (msrc = next_addr(msrc, &zone->masq_src,
				                   handle->family, false)) || first_src;
			     first_src = false)
			{
				for (first_dest = true, mdest = NULL;
				     (mdest = next_addr(mdest, &zone->masq_dest,
					                    handle->family, false)) || first_dest;
				     first_dest = false)
				{
					r = fw3_ipt_rule_new(handle);
					fw3_ipt_rule_src_dest(r, msrc, mdest);
					fw3_ipt_rule_target(r, "MASQUERADE");
					fw3_ipt_rule_append(r, "zone_%s_postrouting", zone->name);
				}
			}
		}
		break;

	case FW3_TABLE_RAW:
		fw3_print_cthelpers(handle, state, zone);
		break;

	case FW3_TABLE_MANGLE:
		break;
	}

	print_interface_rules(handle, state, reload, zone);
}

void
fw3_print_zone_chains(struct fw3_ipt_handle *handle, struct fw3_state *state,
                      bool reload)
{
	struct fw3_zone *zone;

	list_for_each_entry(zone, &state->zones, list)
		print_zone_chain(handle, state, reload, zone);
}

void
fw3_print_zone_rules(struct fw3_ipt_handle *handle, struct fw3_state *state,
                     bool reload)
{
	struct fw3_zone *zone;

	list_for_each_entry(zone, &state->zones, list)
		print_zone_rule(handle, state, reload, zone);
}

void
fw3_flush_zones(struct fw3_ipt_handle *handle, struct fw3_state *state,
                bool reload)
{
	struct fw3_zone *z, *tmp;
	const struct fw3_chain_spec *c;

	list_for_each_entry_safe(z, tmp, &state->zones, list)
	{
		if (!has(z->flags, handle->family, handle->table))
			continue;

		/* first flush all rules ... */
		for (c = zone_chains; c->format; c++)
		{
			/* don't touch user chains on selective stop */
			if (reload && c->flag == FW3_FLAG_CUSTOM_CHAINS)
				continue;

			if (!fw3_is_family(c, handle->family))
				continue;

			if (c->table != handle->table)
				continue;

			if (c->flag && !has(z->flags, handle->family, c->flag))
				continue;

			fw3_ipt_flush_chain(handle, format_chain(c->format, z->name));
		}

		/* ... then remove the chains */
		for (c = zone_chains; c->format; c++)
		{
			if (!fw3_is_family(c, handle->family))
				continue;

			if (c->table != handle->table)
				continue;

			if (c->flag && !has(z->flags, handle->family, c->flag))
				continue;

			fw3_ipt_delete_chain(handle, reload,
			                     format_chain(c->format, z->name));
		}

		del(z->flags, handle->family, handle->table);
	}
}

void
fw3_hotplug_zones(struct fw3_state *state, bool add)
{
	struct fw3_zone *z;
	struct fw3_device *d;

	list_for_each_entry(z, &state->zones, list)
	{
		if (add != fw3_hasbit(z->flags[0], FW3_FLAG_HOTPLUG))
		{
			list_for_each_entry(d, &z->devices, list)
				fw3_hotplug(add, z, d);

			if (add)
				fw3_setbit(z->flags[0], FW3_FLAG_HOTPLUG);
			else
				fw3_delbit(z->flags[0], FW3_FLAG_HOTPLUG);
		}
	}
}

struct fw3_zone *
fw3_lookup_zone(struct fw3_state *state, const char *name)
{
	struct fw3_zone *z;

	if (list_empty(&state->zones))
		return NULL;

	list_for_each_entry(z, &state->zones, list)
	{
		if (strcmp(z->name, name))
			continue;

		return z;
	}

	return NULL;
}

struct list_head *
fw3_resolve_zone_addresses(struct fw3_zone *zone, struct fw3_address *addr)
{
	struct fw3_device *net;
	struct fw3_address *cur, *tmp;
	struct list_head *all;

	all = calloc(1, sizeof(*all));
	if (!all)
		return NULL;

	INIT_LIST_HEAD(all);

	if (addr && addr->set)
	{
		tmp = malloc(sizeof(*tmp));

		if (tmp)
		{
			*tmp = *addr;
			list_add_tail(&tmp->list, all);
		}
	}
	else
	{
		list_for_each_entry(net, &zone->networks, list)
			fw3_ubus_address(all, net->name);

		list_for_each_entry(cur, &zone->subnets, list)
		{
			tmp = malloc(sizeof(*tmp));

			if (!tmp)
				continue;

			*tmp = *cur;
			list_add_tail(&tmp->list, all);
		}
	}

	return all;
}
