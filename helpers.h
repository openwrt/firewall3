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

#ifndef __FW3_HELPERS_H
#define __FW3_HELPERS_H

#include "options.h"
#include "utils.h"
#include "iptables.h"


extern const struct fw3_option fw3_cthelper_opts[];

void
fw3_load_cthelpers(struct fw3_state *state, struct uci_package *p);

struct fw3_cthelper *
fw3_lookup_cthelper(struct fw3_state *state, const char *name);

struct fw3_cthelper *
fw3_lookup_cthelper_by_proto_port(struct fw3_state *state,
                                  struct fw3_protocol *proto,
                                  struct fw3_port *port);

void
fw3_print_cthelpers(struct fw3_ipt_handle *handle, struct fw3_state *state,
                    struct fw3_zone *zone);

static inline void fw3_free_cthelper(struct fw3_cthelper *helper)
{
	list_del(&helper->list);
	fw3_free_object(helper, fw3_cthelper_opts);
}

#endif
