/*
 * imc module - instant messaging conferencing implementation
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
 *
 * This file is part of Kamailio, a free SIP server.
 *
 * Kamailio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * Kamailio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */



#ifndef _IRC_H_
#define _IRC_H_

#include "../../modules/tm/tm_load.h"
#include "../../core/parser/msg_parser.h"

extern str irc_cmd_start_str;
extern char irc_cmd_start_char;
extern struct tm_binds tmb;
extern str outbound_proxy;
extern str all_hdrs;
extern str extra_hdrs;
extern int irc_create_on_join;
extern int irc_check_on_create;

struct irc_uri {
	str uri;
	struct sip_uri parsed;
};

// #define LM_DBG LM_INFO

#endif
