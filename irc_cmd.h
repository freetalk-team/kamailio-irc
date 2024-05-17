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




#ifndef _IRC_CMD_H_
#define _IRC_CMD_H_

#include "../../core/parser/parse_uri.h"
#include "../../core/str.h"
#include "irc_mng.h"
#include "irc.h"

#define IRC_CMD_START		'#'
#define IRC_CMD_START_STR	"#"

#define IRC_CMDID_CREATE	1
#define IRC_CMDID_INVITE	2
#define IRC_CMDID_JOIN		3
#define IRC_CMDID_LEAVE		4
#define IRC_CMDID_ACCEPT	5
#define IRC_CMDID_REJECT	6
#define IRC_CMDID_REMOVE	7
#define IRC_CMDID_DESTROY	8
#define IRC_CMDID_HELP		9
#define IRC_CMDID_MEMBERS	10
#define IRC_CMDID_UNKNOWN	11
#define IRC_CMDID_ADD		12
#define IRC_CMDID_ROOMS		13


#define IRC_CMD_CREATE	"create"
#define IRC_CMD_INVITE	"invite"
#define IRC_CMD_JOIN	"join"
#define IRC_CMD_LEAVE	"leave"
#define IRC_CMD_ACCEPT	"accept"
#define IRC_CMD_REJECT	"reject"
#define IRC_CMD_REMOVE	"remove"
#define IRC_CMD_DESTROY	"destroy"
#define IRC_CMD_MEMBERS	"members"
#define IRC_CMD_ADD	    "add"
#define IRC_CMD_ROOMS	"rooms"

#define IRC_ROOM_PRIVATE		"private"
#define IRC_ROOM_PRIVATE_LEN	(sizeof(IRC_ROOM_PRIVATE)-1)

#define IRC_HELP_MSG	"\r\n"IRC_CMD_START_STR IRC_CMD_CREATE" <room_name> - \
create new conference room\r\n\
"IRC_CMD_START_STR IRC_CMD_JOIN" [<room_name>] - \
join the conference room\r\n\
"IRC_CMD_START_STR IRC_CMD_INVITE" <user_name> [<room_name>] - \
invite a user to join a conference room\r\n\
"IRC_CMD_START_STR IRC_CMD_ADD" <user_name> [<room_name>] - \
add a user to a conference room\r\n\
"IRC_CMD_START_STR IRC_CMD_ACCEPT" - \
accept invitation to join a conference room\r\n\
"IRC_CMD_START_STR IRC_CMD_REJECT" - \
reject invitation to join a conference room\r\n\
"IRC_CMD_START_STR IRC_CMD_REMOVE" <user_name> [<room_name>] - \
remove an user from the conference room\r\n\
"IRC_CMD_START_STR IRC_CMD_MEMBERS" - \
list members is a conference room\r\n\
"IRC_CMD_START_STR IRC_CMD_ROOMS" - \
list existing conference rooms\r\n\
"IRC_CMD_START_STR IRC_CMD_LEAVE" [<room_name>] - \
leave from a conference room\r\n\
"IRC_CMD_START_STR IRC_CMD_DESTROY" [<room_name>] - \
destroy conference room\r\n"

#define IRC_HELP_MSG_LEN (sizeof(IRC_HELP_MSG)-1)


#define IRC_CMD_MAX_PARAM   25
typedef struct _irc_cmd
{
	str name;
	int type;
	str param[IRC_CMD_MAX_PARAM];
} irc_cmd_t, *irc_cmd_p;

int irc_parse_cmd(char *buf, int len, irc_cmd_p cmd);

int irc_handle_create(struct sip_msg* msg, irc_cmd_t *cmd,
		struct irc_uri *src, struct irc_uri *dst);
int irc_handle_join(struct sip_msg* msg, irc_cmd_t *cmd,
		struct irc_uri *src, struct irc_uri *dst);
int irc_handle_invite(struct sip_msg* msg, irc_cmd_t *cmd,
		struct irc_uri *src, struct irc_uri *dst);
int irc_handle_add(struct sip_msg* msg, irc_cmd_t *cmd,
		struct irc_uri *src, struct irc_uri *dst);
int irc_handle_accept(struct sip_msg* msg, irc_cmd_t *cmd,
		struct irc_uri *src, struct irc_uri *dst);
int irc_handle_reject(struct sip_msg* msg, irc_cmd_t *cmd,
		struct irc_uri *src, struct irc_uri *dst);
int irc_handle_remove(struct sip_msg* msg, irc_cmd_t *cmd,
		struct irc_uri *src, struct irc_uri *dst);
int irc_handle_members(struct sip_msg* msg, irc_cmd_t *cmd,
		struct irc_uri *src, struct irc_uri *dst);
int irc_handle_rooms(struct sip_msg* msg, irc_cmd_t *cmd,
		struct irc_uri *src, struct irc_uri *dst);
int irc_handle_leave(struct sip_msg* msg, irc_cmd_t *cmd,
		struct irc_uri *src, struct irc_uri *dst);
int irc_handle_destroy(struct sip_msg* msg, irc_cmd_t *cmd,
		struct irc_uri *src, struct irc_uri *dst);
int irc_handle_unknown(struct sip_msg* msg, irc_cmd_t *cmd,
		struct irc_uri *src, struct irc_uri *dst);
int irc_handle_help(struct sip_msg* msg, irc_cmd_t *cmd,
		struct irc_uri *src, struct irc_uri *dst);
int irc_handle_message(struct sip_msg* msg, str *msgbody,
		struct irc_uri *src, struct irc_uri *dst, int push);

#endif
