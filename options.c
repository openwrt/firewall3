/*
 * firewall3 - 3rd OpenWrt UCI firewall implementation
 *
 *   Copyright (C) 2013 Jo-Philipp Wich <jow@openwrt.org>
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

#include "options.h"


static bool
parse_enum(void *ptr, const char *val, const char **values, int min, int max)
{
	int i, l = strlen(val);

	if (l > 0)
	{
		for (i = 0; i <= (max - min); i++)
		{
			if (!strncasecmp(val, values[i], l))
			{
				*((int *)ptr) = min + i;
				return true;
			}
		}
	}

	return false;
}


const char *fw3_flag_names[FW3_DEFAULT_DROP_INVALID + 1] = {
	"filter",
	"nat",
	"mangle",
	"raw",

	"IPv4",
	"IPv6",

	"ACCEPT",
	"REJECT",
	"DROP",
	"NOTRACK",
	"DNAT",
	"SNAT",
};

static const char *limit_units[] = {
	"second",
	"minute",
	"hour",
	"day",
};

static const char *ipset_methods[] = {
	"bitmap",
	"hash",
	"list",
};

static const char *ipset_types[] = {
	"ip",
	"port",
	"mac",
	"net",
	"set",
};

static const char *weekdays[] = {
	"monday",
	"tuesday",
	"wednesday",
	"thursday",
	"friday",
	"saturday",
	"sunday",
};

static const char *include_types[] = {
	"script",
	"restore",
};


bool
fw3_parse_bool(void *ptr, const char *val)
{
	if (!strcmp(val, "true") || !strcmp(val, "yes") || !strcmp(val, "1"))
		*((bool *)ptr) = true;
	else
		*((bool *)ptr) = false;

	return true;
}

bool
fw3_parse_int(void *ptr, const char *val)
{
	int n = strtol(val, NULL, 10);

	if (errno == ERANGE || errno == EINVAL)
		return false;

	*((int *)ptr) = n;

	return true;
}

bool
fw3_parse_string(void *ptr, const char *val)
{
	*((char **)ptr) = (char *)val;
	return true;
}

bool
fw3_parse_target(void *ptr, const char *val)
{
	return parse_enum(ptr, val, &fw3_flag_names[FW3_TARGET_ACCEPT],
	                  FW3_TARGET_ACCEPT, FW3_TARGET_SNAT);
}

bool
fw3_parse_limit(void *ptr, const char *val)
{
	struct fw3_limit *limit = ptr;
	enum fw3_limit_unit u = FW3_LIMIT_UNIT_SECOND;
	char *e;
	int n;

	if (*val == '!')
	{
		limit->invert = true;
		while (isspace(*++val));
	}

	n = strtol(val, &e, 10);

	if (errno == ERANGE || errno == EINVAL)
		return false;

	if (*e && *e++ != '/')
		return false;

	if (!strlen(e))
		return false;

	if (!parse_enum(&u, e, limit_units, 0, FW3_LIMIT_UNIT_DAY))
		return false;

	limit->rate = n;
	limit->unit = u;

	return true;
}

bool
fw3_parse_device(void *ptr, const char *val)
{
	struct fw3_device *dev = ptr;

	if (*val == '*')
	{
		dev->set = true;
		dev->any = true;
		return true;
	}

	if (*val == '!')
	{
		dev->invert = true;
		while (isspace(*++val));
	}

	if (*val)
		snprintf(dev->name, sizeof(dev->name), "%s", val);
	else
		return false;

	dev->set = true;
	return true;
}

bool
fw3_parse_address(void *ptr, const char *val)
{
	struct fw3_address *addr = ptr;
	struct in_addr v4;
	struct in6_addr v6;
	char *p, *s, *e;
	int i, m = -1;

	if (*val == '!')
	{
		addr->invert = true;
		while (isspace(*++val));
	}

	s = strdup(val);

	if (!s)
		return false;

	if ((p = strchr(s, '/')) != NULL)
	{
		*p++ = 0;
		m = strtoul(p, &e, 10);

		if ((e == p) || (*e != 0))
		{
			if (strchr(s, ':') || !inet_pton(AF_INET, p, &v4))
			{
				free(s);
				return false;
			}

			for (i = 0, m = 32; !(v4.s_addr & 1) && (i < 32); i++)
			{
				m--;
				v4.s_addr >>= 1;
			}
		}
	}
	else if ((p = strchr(s, '-')) != NULL)
	{
		*p++ = 0;

		if (inet_pton(AF_INET6, p, &v6))
		{
			addr->family = FW3_FAMILY_V6;
			addr->address2.v6 = v6;
			addr->range = true;
		}
		else if (inet_pton(AF_INET, p, &v4))
		{
			addr->family = FW3_FAMILY_V4;
			addr->address2.v4 = v4;
			addr->range = true;
		}
		else
		{
			free(s);
			return false;
		}
	}

	if (inet_pton(AF_INET6, s, &v6))
	{
		addr->family = FW3_FAMILY_V6;
		addr->address.v6 = v6;
		addr->mask = (m >= 0) ? m : 128;
	}
	else if (inet_pton(AF_INET, s, &v4))
	{
		addr->family = FW3_FAMILY_V4;
		addr->address.v4 = v4;
		addr->mask = (m >= 0) ? m : 32;
	}
	else
	{
		free(s);
		return false;
	}

	free(s);
	addr->set = true;
	return true;
}

bool
fw3_parse_mac(void *ptr, const char *val)
{
	struct fw3_mac *addr = ptr;
	struct ether_addr *mac;

	if (*val == '!')
	{
		addr->invert = true;
		while (isspace(*++val));
	}

	if ((mac = ether_aton(val)) != NULL)
	{
		addr->mac = *mac;
		addr->set = true;
		return true;
	}

	return false;
}

bool
fw3_parse_port(void *ptr, const char *val)
{
	struct fw3_port *range = ptr;
	uint16_t n;
	uint16_t m;
	char *p;

	if (*val == '!')
	{
		range->invert = true;
		while (isspace(*++val));
	}

	n = strtoul(val, &p, 10);

	if (errno == ERANGE || errno == EINVAL)
		return false;

	if (*p && *p != '-' && *p != ':')
		return false;

	if (*p)
	{
		m = strtoul(++p, NULL, 10);

		if (errno == ERANGE || errno == EINVAL || m < n)
			return false;

		range->port_min = n;
		range->port_max = m;
	}
	else
	{
		range->port_min = n;
		range->port_max = n;
	}

	range->set = true;
	return true;
}

bool
fw3_parse_family(void *ptr, const char *val)
{
	if (!strcmp(val, "any"))
		*((enum fw3_family *)ptr) = FW3_FAMILY_ANY;
	else if (!strcmp(val, "inet") || strrchr(val, '4'))
		*((enum fw3_family *)ptr) = FW3_FAMILY_V4;
	else if (!strcmp(val, "inet6") || strrchr(val, '6'))
		*((enum fw3_family *)ptr) = FW3_FAMILY_V6;
	else
		return false;

	return true;
}

bool
fw3_parse_icmptype(void *ptr, const char *val)
{
	struct fw3_icmptype *icmp = ptr;
	bool v4 = false;
	bool v6 = false;
	char *p;
	int i;

	for (i = 0; i < ARRAY_SIZE(fw3_icmptype_list_v4); i++)
	{
		if (!strcmp(val, fw3_icmptype_list_v4[i].name))
		{
			icmp->type     = fw3_icmptype_list_v4[i].type;
			icmp->code_min = fw3_icmptype_list_v4[i].code_min;
			icmp->code_max = fw3_icmptype_list_v4[i].code_max;

			v4 = true;
			break;
		}
	}

	for (i = 0; i < ARRAY_SIZE(fw3_icmptype_list_v6); i++)
	{
		if (!strcmp(val, fw3_icmptype_list_v6[i].name))
		{
			icmp->type6     = fw3_icmptype_list_v6[i].type;
			icmp->code6_min = fw3_icmptype_list_v6[i].code_min;
			icmp->code6_max = fw3_icmptype_list_v6[i].code_max;

			v6 = true;
			break;
		}
	}

	if (!v4 && !v6)
	{
		i = strtoul(val, &p, 10);

		if ((p == val) || (*p != '/' && *p != 0) || (i > 0xFF))
			return false;

		icmp->type = i;

		if (*p == '/')
		{
			val = ++p;
			i = strtoul(val, &p, 10);

			if ((p == val) || (*p != 0) || (i > 0xFF))
				return false;

			icmp->code_min = i;
			icmp->code_max = i;
		}
		else
		{
			icmp->code_min = 0;
			icmp->code_max = 0xFF;
		}

		icmp->type6     = icmp->type;
		icmp->code6_min = icmp->code_max;
		icmp->code6_max = icmp->code_max;

		v4 = true;
		v6 = true;
	}

	icmp->family = (v4 && v6) ? FW3_FAMILY_ANY
	                          : (v6 ? FW3_FAMILY_V6 : FW3_FAMILY_V4);

	return true;
}

bool
fw3_parse_protocol(void *ptr, const char *val)
{
	struct fw3_protocol *proto = ptr;
	struct protoent *ent;

	if (*val == '!')
	{
		proto->invert = true;
		while (isspace(*++val));
	}

	if (!strcmp(val, "all"))
	{
		proto->any = true;
		return true;
	}
	else if (!strcmp(val, "icmpv6"))
	{
		val = "ipv6-icmp";
	}

	ent = getprotobyname(val);

	if (ent)
	{
		proto->protocol = ent->p_proto;
		return true;
	}

	proto->protocol = strtoul(val, NULL, 10);
	return (errno != ERANGE && errno != EINVAL);
}

bool
fw3_parse_ipset_method(void *ptr, const char *val)
{
	return parse_enum(ptr, val, ipset_methods,
	                  FW3_IPSET_METHOD_BITMAP, FW3_IPSET_METHOD_LIST);
}

bool
fw3_parse_ipset_datatype(void *ptr, const char *val)
{
	struct fw3_ipset_datatype *type = ptr;

	if (!strncmp(val, "dest_", 5))
	{
		val += 5;
		type->dest = true;
	}
	else if (!strncmp(val, "dst_", 4))
	{
		val += 4;
		type->dest = true;
	}
	else if (!strncmp(val, "src_", 4))
	{
		val += 4;
		type->dest = false;
	}

	return parse_enum(&type->type, val, ipset_types,
	                  FW3_IPSET_TYPE_IP, FW3_IPSET_TYPE_SET);
}

bool
fw3_parse_date(void *ptr, const char *val)
{
	unsigned int year = 1970, mon = 1, day = 1, hour = 0, min = 0, sec = 0;
	struct tm tm = { 0 };
	char *p;

	year = strtoul(val, &p, 10);
	if ((*p != '-' && *p) || year < 1970 || year > 2038)
		goto fail;
	else if (!*p)
		goto ret;

	mon = strtoul(++p, &p, 10);
	if ((*p != '-' && *p) || mon > 12)
		goto fail;
	else if (!*p)
		goto ret;

	day = strtoul(++p, &p, 10);
	if ((*p != 'T' && *p) || day > 31)
		goto fail;
	else if (!*p)
		goto ret;

	hour = strtoul(++p, &p, 10);
	if ((*p != ':' && *p) || hour > 23)
		goto fail;
	else if (!*p)
		goto ret;

	min = strtoul(++p, &p, 10);
	if ((*p != ':' && *p) || min > 59)
		goto fail;
	else if (!*p)
		goto ret;

	sec = strtoul(++p, &p, 10);
	if (*p || sec > 59)
		goto fail;

ret:
	tm.tm_year = year - 1900;
	tm.tm_mon  = mon - 1;
	tm.tm_mday = day;
	tm.tm_hour = hour;
	tm.tm_min  = min;
	tm.tm_sec  = sec;

	if (mktime(&tm) >= 0)
	{
		*((struct tm *)ptr) = tm;
		return true;
	}

fail:
	return false;
}

bool
fw3_parse_time(void *ptr, const char *val)
{
	unsigned int hour = 0, min = 0, sec = 0;
	char *p;

	hour = strtoul(val, &p, 10);
	if (*p != ':' || hour > 23)
		goto fail;

	min = strtoul(++p, &p, 10);
	if ((*p != ':' && *p) || min > 59)
		goto fail;
	else if (!*p)
		goto ret;

	sec = strtoul(++p, &p, 10);
	if (*p || sec > 59)
		goto fail;

ret:
	*((int *)ptr) = 60 * 60 * hour + 60 * min + sec;
	return true;

fail:
	return false;
}

bool
fw3_parse_weekdays(void *ptr, const char *val)
{
	unsigned int w = 0;
	char *p, *s;

	if (*val == '!')
	{
		setbit(*(uint8_t *)ptr, 0);
		while (isspace(*++val));
	}

	if (!(s = strdup(val)))
		return false;

	for (p = strtok(s, " \t"); p; p = strtok(NULL, " \t"))
	{
		if (!parse_enum(&w, p, weekdays, 1, 7))
		{
			w = strtoul(p, &p, 10);

			if (*p || w < 1 || w > 7)
			{
				free(s);
				return false;
			}
		}

		setbit(*(uint8_t *)ptr, w);
	}

	free(s);
	return true;
}

bool
fw3_parse_monthdays(void *ptr, const char *val)
{
	unsigned int d;
	char *p, *s;

	if (*val == '!')
	{
		setbit(*(uint32_t *)ptr, 0);
		while (isspace(*++val));
	}

	if (!(s = strdup(val)))
		return false;

	for (p = strtok((char *)val, " \t"); p; p = strtok(NULL, " \t"))
	{
		d = strtoul(p, &p, 10);

		if (*p || d < 1 || d > 31)
		{
			free(s);
			return false;
		}

		setbit(*(uint32_t *)ptr, d);
	}

	free(s);
	return true;
}

bool
fw3_parse_include_type(void *ptr, const char *val)
{
	return parse_enum(ptr, val, include_types,
	                  FW3_INC_TYPE_SCRIPT, FW3_INC_TYPE_RESTORE);
}


void
fw3_parse_options(void *s, const struct fw3_option *opts,
                  struct uci_section *section)
{
	char *p;
	bool known;
	struct uci_element *e, *l;
	struct uci_option *o;
	const struct fw3_option *opt;
	struct list_head *item;
	struct list_head *dest;

	uci_foreach_element(&section->options, e)
	{
		o = uci_to_option(e);
		known = false;

		for (opt = opts; opt->name; opt++)
		{
			if (!opt->parse)
				continue;

			if (strcmp(opt->name, e->name))
				continue;

			if (o->type == UCI_TYPE_LIST)
			{
				if (!opt->elem_size)
				{
					warn_elem(e, "must not be a list");
				}
				else
				{
					uci_foreach_element(&o->v.list, l)
					{
						if (!l->name)
							continue;

						item = malloc(opt->elem_size);

						if (!item)
							continue;

						memset(item, 0, opt->elem_size);

						if (!opt->parse(item, l->name))
						{
							warn_elem(e, "has invalid value '%s'", l->name);
							free(item);
							continue;
						}

						dest = (struct list_head *)((char *)s + opt->offset);
						list_add_tail(item, dest);
					}
				}
			}
			else
			{
				if (!o->v.string)
					continue;

				if (!opt->elem_size)
				{
					if (!opt->parse((char *)s + opt->offset, o->v.string))
						warn_elem(e, "has invalid value '%s'", o->v.string);
				}
				else
				{
					for (p = strtok(o->v.string, " \t");
					     p != NULL;
					     p = strtok(NULL, " \t"))
					{
						item = malloc(opt->elem_size);

						if (!item)
							continue;

						memset(item, 0, opt->elem_size);

						if (!opt->parse(item, p))
						{
							warn_elem(e, "has invalid value '%s'", p);
							free(item);
							continue;
						}

						dest = (struct list_head *)((char *)s + opt->offset);
						list_add_tail(item, dest);
					}
				}
			}

			known = true;
			break;
		}

		if (!known)
			warn_elem(e, "is unknown");
	}
}


void
fw3_format_in_out(struct fw3_device *in, struct fw3_device *out)
{
	if (in && !in->any)
		fw3_pr(" %s-i %s", in->invert ? "! " : "", in->name);

	if (out && !out->any)
		fw3_pr(" %s-o %s", out->invert ? "! " : "", out->name);
}

void
fw3_format_src_dest(struct fw3_address *src, struct fw3_address *dest)
{
	char s[INET6_ADDRSTRLEN];

	if ((src && src->range) || (dest && dest->range))
		fw3_pr(" -m iprange");

	if (src && src->set)
	{
		if (src->range)
		{
			inet_ntop(src->family == FW3_FAMILY_V4 ? AF_INET : AF_INET6,
					  &src->address.v4, s, sizeof(s));

			fw3_pr(" %s--src-range %s", src->invert ? "! " : "", s);

			inet_ntop(src->family == FW3_FAMILY_V4 ? AF_INET : AF_INET6,
					  &src->address2.v4, s, sizeof(s));

			fw3_pr("-%s", s);
		}
		else
		{
			inet_ntop(src->family == FW3_FAMILY_V4 ? AF_INET : AF_INET6,
					  &src->address.v4, s, sizeof(s));

			fw3_pr(" %s-s %s/%u", src->invert ? "! " : "", s, src->mask);
		}
	}

	if (dest && dest->set)
	{
		if (dest->range)
		{
			inet_ntop(dest->family == FW3_FAMILY_V4 ? AF_INET : AF_INET6,
					  &dest->address.v4, s, sizeof(s));

			fw3_pr(" %s--dst-range %s", dest->invert ? "! " : "", s);

			inet_ntop(dest->family == FW3_FAMILY_V4 ? AF_INET : AF_INET6,
					  &dest->address2.v4, s, sizeof(s));

			fw3_pr("-%s", s);
		}
		else
		{
			inet_ntop(dest->family == FW3_FAMILY_V4 ? AF_INET : AF_INET6,
					  &dest->address.v4, s, sizeof(s));

			fw3_pr(" %s-d %s/%u", dest->invert ? "! " : "", s, dest->mask);
		}
	}
}

void
fw3_format_sport_dport(struct fw3_port *sp, struct fw3_port *dp)
{
	if (sp && sp->set)
	{
		if (sp->port_min == sp->port_max)
			fw3_pr(" %s--sport %u", sp->invert ? "! " : "", sp->port_min);
		else
			fw3_pr(" %s--sport %u:%u",
			       sp->invert ? "! " : "", sp->port_min, sp->port_max);
	}

	if (dp && dp->set)
	{
		if (dp->port_min == dp->port_max)
			fw3_pr(" %s--dport %u", dp->invert ? "! " : "", dp->port_min);
		else
			fw3_pr(" %s--dport %u:%u",
			       dp->invert ? "! " : "", dp->port_min, dp->port_max);
	}
}

void
fw3_format_mac(struct fw3_mac *mac)
{
	if (!mac)
		return;

	fw3_pr(" -m mac %s--mac-source %s",
	       mac->invert ? "! " : "", ether_ntoa(&mac->mac));
}

void
fw3_format_protocol(struct fw3_protocol *proto, enum fw3_family family)
{
	uint16_t pr;

	if (!proto)
		return;

	pr = proto->protocol;

	if (pr == 1 && family == FW3_FAMILY_V6)
		pr = 58;

	if (proto->any)
		fw3_pr(" -p all");
	else
		fw3_pr(" %s-p %u", proto->invert ? "! " : "", pr);
}

void
fw3_format_icmptype(struct fw3_icmptype *icmp, enum fw3_family family)
{
	if (!icmp)
		return;

	if (family != FW3_FAMILY_V6)
	{
		if (icmp->code_min == 0 && icmp->code_max == 0xFF)
			fw3_pr(" %s--icmp-type %u", icmp->invert ? "! " : "", icmp->type);
		else
			fw3_pr(" %s--icmp-type %u/%u",
				   icmp->invert ? "! " : "", icmp->type, icmp->code_min);
	}
	else
	{
		if (icmp->code6_min == 0 && icmp->code6_max == 0xFF)
			fw3_pr(" %s--icmpv6-type %u", icmp->invert ? "! " : "", icmp->type6);
		else
			fw3_pr(" %s--icmpv6-type %u/%u",
				   icmp->invert ? "! " : "", icmp->type6, icmp->code6_min);
	}
}

void
fw3_format_limit(struct fw3_limit *limit)
{
	if (!limit)
		return;

	if (limit->rate > 0)
	{
		fw3_pr(" -m limit %s--limit %u/%s",
		       limit->invert ? "! " : "",
		       limit->rate, limit_units[limit->unit]);

		if (limit->burst > 0)
			fw3_pr(" --limit-burst %u", limit->burst);
	}
}

void
fw3_format_ipset(struct fw3_ipset *ipset, bool invert)
{
	bool first = true;
	const char *name = NULL;
	struct fw3_ipset_datatype *type;

	if (!ipset)
		return;

	if (ipset->external && *ipset->external)
		name = ipset->external;
	else
		name = ipset->name;

	fw3_pr(" -m set %s--match-set %s", invert ? "! " : "", name);

	list_for_each_entry(type, &ipset->datatypes, list)
	{
		fw3_pr("%c%s", first ? ' ' : ',', type->dest ? "dst" : "src");
		first = false;
	}
}

void
fw3_format_time(struct fw3_time *time)
{
	int i;
	struct tm empty = { 0 };
	char buf[sizeof("9999-99-99T23:59:59\0")];
	bool d1 = memcmp(&time->datestart, &empty, sizeof(empty));
	bool d2 = memcmp(&time->datestop, &empty, sizeof(empty));
	bool first;

	if (!d1 && !d2 && !time->timestart && !time->timestop &&
	    !(time->monthdays & 0xFFFFFFFE) && !(time->weekdays & 0xFE))
	{
		return;
	}

	fw3_pr(" -m time");

	if (time->utc)
		fw3_pr(" --utc");

	if (d1)
	{
		strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &time->datestart);
		fw3_pr(" --datestart %s", buf);
	}

	if (d2)
	{
		strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &time->datestop);
		fw3_pr(" --datestop %s", buf);
	}

	if (time->timestart)
	{
		fw3_pr(" --timestart %02d:%02d:%02d",
		       time->timestart / 3600,
		       time->timestart % 3600 / 60,
		       time->timestart % 60);
	}

	if (time->timestop)
	{
		fw3_pr(" --timestop %02d:%02d:%02d",
		       time->timestop / 3600,
		       time->timestop % 3600 / 60,
		       time->timestop % 60);
	}

	if (time->monthdays & 0xFFFFFFFE)
	{
		fw3_pr(" %s--monthdays", hasbit(time->monthdays, 0) ? "! " : "");

		for (i = 1, first = true; i < 32; i++)
		{
			if (hasbit(time->monthdays, i))
			{
				fw3_pr("%c%u", first ? ' ' : ',', i);
				first = false;
			}
		}
	}

	if (time->weekdays & 0xFE)
	{
		fw3_pr(" %s--weekdays", hasbit(time->weekdays, 0) ? "! " : "");

		for (i = 1, first = true; i < 8; i++)
		{
			if (hasbit(time->weekdays, i))
			{
				fw3_pr("%c%u", first ? ' ' : ',', i);
				first = false;
			}
		}
	}
}

void
__fw3_format_comment(const char *comment, ...)
{
	va_list ap;
	int len = 0;
	const char *c;

	if (!comment || !*comment)
		return;

	fw3_pr(" -m comment --comment \"");

	c = comment;

	va_start(ap, comment);

	do
	{
		while (*c)
		{
			switch (*c)
			{
			case '"':
			case '$':
			case '`':
			case '\\':
				fw3_pr("\\");
				/* fall through */

			default:
				fw3_pr("%c", *c);
				break;
			}

			c++;

			if (len++ >= 255)
				goto end;
		}

		c = va_arg(ap, const char *);
	}
	while (c);

end:
	va_end(ap);
	fw3_pr("\"");
}

void
fw3_format_extra(const char *extra)
{
	if (!extra || !*extra)
		return;

	fw3_pr(" %s", extra);
}