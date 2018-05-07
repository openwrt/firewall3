/*
 * firewall3 - 3rd OpenWrt UCI firewall implementation
 *
 *   Copyright (C) 2018 Jo-Philipp Wich <jo@mein.io>
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

#include "helpers.h"


const struct fw3_option fw3_cthelper_opts[] = {
	FW3_OPT("enabled",     bool,     cthelper, enabled),
	FW3_OPT("name",        string,   cthelper, name),
	FW3_OPT("module",      string,   cthelper, module),
	FW3_OPT("description", string,   cthelper, description),
	FW3_OPT("family",      family,   cthelper, family),
	FW3_LIST("proto",      protocol, cthelper, proto),
	FW3_OPT("port",        port,     cthelper, port),

	{ }
};


static bool
test_module(struct fw3_cthelper *helper)
{
	struct stat s;
	char path[sizeof("/sys/module/nf_conntrack_xxxxxxxxxxxxxxxx")];

	snprintf(path, sizeof(path), "/sys/module/%s", helper->module);

	if (stat(path, &s) || !S_ISDIR(s.st_mode))
		return false;

	return true;
}

static bool
check_cthelper_proto(const struct fw3_cthelper *helper)
{
	struct fw3_protocol	*proto;

	if (list_empty(&helper->proto))
		return false;

	list_for_each_entry(proto, &helper->proto, list)
	{
		if (!proto->protocol || proto->any || proto->invert)
			return false;
	}

	return true;
}

static bool
check_cthelper(struct fw3_state *state, struct fw3_cthelper *helper, struct uci_element *e)
{
	if (!helper->name || !*helper->name)
	{
		warn_section("helper", helper, e, "must have a name assigned");
	}
	else if (!helper->module || !*helper->module)
	{
		warn_section("helper", helper, e, "must have a module assigned");
	}
	else if (!check_cthelper_proto(helper))
	{
		warn_section("helper", helper, e, "must specify a protocol");
	}
	else if (helper->port.set && helper->port.invert)
	{
		warn_section("helper", helper, e, "must not specify negated ports");
	}
	else
	{
		return true;
	}

	return false;
}

static struct fw3_cthelper *
fw3_alloc_cthelper(struct fw3_state *state)
{
	struct fw3_cthelper *helper;

	helper = calloc(1, sizeof(*helper));
	if (!helper)
		return NULL;

	helper->enabled = true;
	helper->family  = FW3_FAMILY_ANY;
	INIT_LIST_HEAD(&helper->proto);

	list_add_tail(&helper->list, &state->cthelpers);

	return helper;
}

static void
load_cthelpers(struct fw3_state *state, struct uci_package *p)
{
	struct fw3_cthelper *helper;
	struct uci_section *s;
	struct uci_element *e;

	uci_foreach_element(&p->sections, e)
	{
		s = uci_to_section(e);

		if (strcmp(s->type, "helper"))
			continue;

		helper = fw3_alloc_cthelper(state);

		if (!helper)
			continue;

		if (!fw3_parse_options(helper, fw3_cthelper_opts, s))
			warn_elem(e, "has invalid options");

		if (!check_cthelper(state, helper, e))
			fw3_free_cthelper(helper);
	}
}

void
fw3_load_cthelpers(struct fw3_state *state, struct uci_package *p)
{
	struct uci_package *hp = NULL;
	FILE *fp;

	INIT_LIST_HEAD(&state->cthelpers);

	fp = fopen(FW3_HELPERCONF, "r");

	if (fp) {
		uci_import(state->uci, fp, "fw3_ct_helpers", &hp, true);
		fclose(fp);

		if (hp)
			load_cthelpers(state, hp);
	}

	load_cthelpers(state, p);
}

struct fw3_cthelper *
fw3_lookup_cthelper(struct fw3_state *state, const char *name)
{
	struct fw3_cthelper *h;

	if (list_empty(&state->cthelpers))
		return NULL;

	list_for_each_entry(h, &state->cthelpers, list)
	{
		if (strcasecmp(h->name, name))
			continue;

		return h;
	}

	return NULL;
}

bool
fw3_cthelper_check_proto(const struct fw3_cthelper *h, const struct fw3_protocol *proto)
{
	struct fw3_protocol	*p;

	list_for_each_entry(p, &h->proto, list)
	{
		if (p->protocol == proto->protocol)
			return true;
	}

	return false;
}

struct fw3_cthelper *
fw3_lookup_cthelper_by_proto_port(struct fw3_state *state,
                                  struct fw3_protocol *proto,
                                  struct fw3_port *port)
{
	struct fw3_cthelper *h;

	if (list_empty(&state->cthelpers))
		return NULL;

	if (!proto || !proto->protocol || proto->any || proto->invert)
		return NULL;

	if (port && port->invert)
		return NULL;

	list_for_each_entry(h, &state->cthelpers, list)
	{
		if (!h->enabled)
			continue;

		if (!fw3_cthelper_check_proto(h, proto))
			continue;

		if (h->port.set && (!port || !port->set))
			continue;

		if (!h->port.set && (!port || !port->set))
			return h;

		if (h->port.set && port && port->set &&
		    h->port.port_min <= port->port_min &&
		    h->port.port_max >= port->port_max)
		    return h;
	}

	return NULL;
}

static void
print_helper_rule(struct fw3_ipt_handle *handle, struct fw3_cthelper *helper,
                  struct fw3_zone *zone, struct fw3_protocol *proto)
{
	struct fw3_ipt_rule *r;

	r = fw3_ipt_rule_create(handle, proto, NULL, NULL, NULL, NULL);

	if (helper->description && *helper->description)
		fw3_ipt_rule_comment(r, helper->description);
	else
		fw3_ipt_rule_comment(r, helper->name);

	fw3_ipt_rule_sport_dport(r, NULL, &helper->port);
	fw3_ipt_rule_target(r, "CT");
	fw3_ipt_rule_addarg(r, false, "--helper", helper->name);
	fw3_ipt_rule_replace(r, "zone_%s_helper", zone->name);
}

static void
expand_helper_rule(struct fw3_ipt_handle *handle, struct fw3_cthelper *helper,
                  struct fw3_zone *zone)
{
	struct fw3_protocol *proto;

	list_for_each_entry(proto, &helper->proto, list)
		print_helper_rule(handle, helper, zone, proto);
}

void
fw3_print_cthelpers(struct fw3_ipt_handle *handle, struct fw3_state *state,
                    struct fw3_zone *zone)
{
	struct fw3_cthelper *helper;
	struct fw3_cthelpermatch *match;

	if (handle->table != FW3_TABLE_RAW)
		return;

	if (!fw3_is_family(zone, handle->family))
		return;

	if (list_empty(&zone->cthelpers))
	{
		if (zone->masq || !zone->auto_helper)
			return;

		if (list_empty(&state->cthelpers))
			return;

		info("     - Using automatic conntrack helper attachment");

		list_for_each_entry(helper, &state->cthelpers, list)
		{
			if (!helper || !helper->enabled)
				continue;

			if (!fw3_is_family(helper, handle->family))
				continue;

			if (!test_module(helper))
				continue;

			expand_helper_rule(handle, helper, zone);
		}
	}
	else
	{
		list_for_each_entry(match, &zone->cthelpers, list)
		{
			helper = match->ptr;

			if (!helper || !helper->enabled)
				continue;

			if (!fw3_is_family(helper, handle->family))
				continue;

			if (!test_module(helper))
			{
				info("     ! Conntrack module '%s' for helper '%s' is not loaded",
				     helper->module, helper->name);
				continue;
			}

			expand_helper_rule(handle, helper, zone);
		}
	}
}
