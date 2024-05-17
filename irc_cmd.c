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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>

#include <sys/types.h>
#include "../../core/mem/shm_mem.h"
#include "../../core/mem/mem.h"
#include "../../core/sr_module.h"
#include "../../core/dprint.h"
#include "../../core/parser/parse_uri.h"
#include "../../core/parser/msg_parser.h"

#include "irc.h"
#include "irc_cmd.h"

#define ROOMS "Rooms:\n"
#define MEMBERS "Members:\n"

#define PREFIX "*** "

#define IRC_BUF_SIZE 32768
static char irc_body_buf[IRC_BUF_SIZE];

static str irc_msg_type = { "MESSAGE", 7 };

static str msg_room_created       = STR_STATIC_INIT(PREFIX "Room was created");
static str msg_room_destroyed     = STR_STATIC_INIT(PREFIX "Room has been destroyed");
static str msg_room_not_found     = STR_STATIC_INIT(PREFIX "Room not found");
static str msg_room_exists        = STR_STATIC_INIT(PREFIX "Room already exists");
static str msg_leave_error        = STR_STATIC_INIT(PREFIX "You are the room's owner and cannot leave. Use #destroy if you wish to destroy the room.");
static str msg_room_exists_priv   = STR_STATIC_INIT(PREFIX "A private room with the same name already exists");
static str msg_room_exists_member = STR_STATIC_INIT(PREFIX "Room already exists and you are a member");
static str msg_user_joined        = STR_STATIC_INIT(PREFIX "%.*s has joined the room");
static str msg_already_joined     = STR_STATIC_INIT(PREFIX "You are in the room already");
static str msg_user_left          = STR_STATIC_INIT(PREFIX "%.*s has left the room");
static str msg_join_attempt_bcast = STR_STATIC_INIT(PREFIX "%.*s attempted to join the room");
static str msg_join_attempt_ucast = STR_STATIC_INIT(PREFIX "Private rooms are by invitation only. Room owners have been notified.");
static str msg_invite             = STR_STATIC_INIT(PREFIX "%.*s invites you to join the room (send '%.*saccept' or '%.*sreject')");
static str msg_add_reject         = STR_STATIC_INIT(PREFIX "You don't have the permmission to add members to this room");
#if 0
static str msg_rejected           = STR_STATIC_INIT(PREFIX "%.*s has rejected invitation");
#endif
static str msg_user_removed       = STR_STATIC_INIT(PREFIX "You have been removed from the room");
static str msg_invalid_command    = STR_STATIC_INIT(PREFIX "Invalid command '%.*s' (send '%.*shelp' for help)");

int irc_send_message(str *src, str *dst, str *headers, str *body);
int irc_room_broadcast(irc_room_p room, str *ctype, str *body);
void irc_inv_callback( struct cell *t, int type, struct tmcb_params *ps);


extern irc_hentry_p _irc_htable;
extern int irc_hash_size;


static str *get_callid(struct sip_msg *msg)
{
	if ((parse_headers(msg, HDR_CALLID_F, 0) != -1)
		&& msg->callid) {
		return &msg->callid->body;
	}
	return NULL;
}

static str *get_timestamp(struct sip_msg *msg) {
	if ((parse_headers(msg, HDR_EXPIRES_F, 0) != -1)
		&& msg->expires) {
		return &msg->expires->body;
	}
	return NULL;
}

static str get_from_name(struct sip_msg *msg) {

	str display;

	if (parse_from_header(msg) < 0 || !msg->from->parsed) {
		LM_ERR("failed to parse From header\n");
		display.len = 0;
	}
	else {

		display = ((struct to_body *) msg->from->parsed)->display;

		display.s += 1;
		display.len -= 2;

	}

	return display;
	
}

static str *build_headers(struct sip_msg *msg, int add_push)
{
	static str name = STR_STATIC_INIT("In-Reply-To: ");
	static str from = STR_STATIC_INIT("\r\nX-from: ");
	static str push = STR_STATIC_INIT("\r\nX-push: 1");
	static char buf[2048], *p = buf;
	static str rv;
	str *callid, display;

	if ((callid = get_callid(msg)) == NULL)
		return &all_hdrs;

	if (parse_from_header(msg) < 0 || !msg->from->parsed) {
		LM_ERR("failed to parse From header\n");
		return NULL;
	}


	rv.s = buf;
	rv.len = all_hdrs.len + name.len + callid->len;

	if (rv.len > sizeof(buf)) {
		LM_ERR("Header buffer too small for In-Reply-To header\n");
		return &all_hdrs;
	}

	memcpy(p, all_hdrs.s, all_hdrs.len);
	p += all_hdrs.len;

	memcpy(p, name.s, name.len);
	p += name.len;

	memcpy(p, callid->s, callid->len);
	p += callid->len;

	if (add_push) {
		display = get_from_name(msg);

		rv.len += push.len;

		if (display.len > 0) {
			rv.len += from.len + display.len;

			memcpy(p, from.s, from.len);
			p += from.len;

			memcpy(p, display.s, display.len);
			p += display.len;

		}

		memcpy(p, push.s, push.len);
		p += push.len;
	}


	return &rv;
}


static str *format_uri(str uri)
{
	static char buf[512];
	static str rv;
	struct sip_uri parsed;

	rv.s = NULL;
	rv.len = 0;

	if (parse_uri(uri.s, uri.len, &parsed) != 0) {
		LM_ERR("bad uri [%.*s]!\n", STR_FMT(&uri));
	} else {
		rv.s = buf;
		rv.len = snprintf(buf, sizeof(buf), "[%.*s]", STR_FMT(&parsed.user));
		if (rv.len >= sizeof(buf)) {
			LM_ERR("Buffer too small\n");
			rv.len = 0;
		}
	}
	return &rv;
}


/*
 * Given string in value and a parsed URI in template, build a full
 * URI as follows:
 * 1) If value has no URI scheme, add sip:
 * 2) If value has no domain, add domain from template
 * 3) Use the string in value for the username portion
 *
 * This function is intended for converting a URI or number provided
 * by the user in a command to a full SIP URI. The caller is
 * responsible for freeing the buffer in res->s which will be
 * allocated with pkg_malloc.
 */
static int build_uri(str *res, str value, struct sip_uri *template)
{
	int len = value.len, add_domain = 0, add_scheme = 0;

	if (memchr(value.s, ':', value.len) == NULL) {
		add_scheme = 1;
		len += 4; /* sip: */
	}

	if (memchr(value.s, '@', value.len) == NULL) {
		add_domain = 1;
		len += 1 + template->host.len;
	}

	if ((res->s = (char*)pkg_malloc(len)) == NULL) {
		LM_ERR("No memory left\n");
		return -1;
	}
	res->len = len;
	len = 0;

	if (add_scheme) {
		strcpy(res->
			   s, "sip:");
		len += 4;
	}

	memcpy(res->s + len, value.s, value.len);
	len += value.len;

	if (add_domain) {
		res->s[len++] = '@';
		memcpy(res->s + len, template->host.s, template->host.len);
	}
	return 0;
}


/*
 * Return a struct irc_uri which contains a SIP URI both in string
 * form and parsed to components. Calls build_uri internally and then
 * parses the resulting URI with parse_uri. See the description of
 * build_uri for more detail on arguments.
 *
 * The caller is responsible for pkg_freeing res->uri.s
 */
static int build_irc_uri(struct irc_uri *res, str value, struct sip_uri *template)
{
	int rc;

	rc = build_uri(&res->uri, value, template);
	if (rc != 0) return rc;

	if (parse_uri(res->uri.s, res->uri.len, &res->parsed) != 0) {
		LM_ERR("bad uri [%.*s]!\n", STR_FMT(&res->uri));
		pkg_free(res->uri.s);
		res->uri.s = NULL;
		res->uri.len = 0;
		return -1;
	}
	return 0;
}


/**
 * parse cmd
 */
int irc_parse_cmd(char *buf, int len, irc_cmd_p cmd)
{
	char *p;
	int i;
	if(buf==NULL || len<=0 || cmd==NULL)
	{
		LM_ERR("invalid parameters\n");
		return -1;
	}

	memset(cmd, 0, sizeof(irc_cmd_t));
	if(buf[0]!=irc_cmd_start_char)
	{
		LM_ERR("invalid command [%.*s]\n", len, buf);
		return -1;
	}
	p = &buf[1];
	cmd->name.s = p;
	while(*p && p<buf+len)
	{
		if(*p==' ' || *p=='\t' || *p=='\r' || *p=='\n')
			break;
		p++;
	}
	if(cmd->name.s == p)
	{
		LM_ERR("no command in [%.*s]\n", len, buf);
		return -1;
	}
	cmd->name.len = p - cmd->name.s;

	/* identify the command */
	if(cmd->name.len==(sizeof("create")-1)
			&& !strncasecmp(cmd->name.s, "create", cmd->name.len))
	{
		cmd->type = IRC_CMDID_CREATE;
	} else if(cmd->name.len==(sizeof("join")-1)
				&& !strncasecmp(cmd->name.s, "join", cmd->name.len)) {
		cmd->type = IRC_CMDID_JOIN;
	} else if(cmd->name.len==(sizeof("invite")-1)
				&& !strncasecmp(cmd->name.s, "invite", cmd->name.len)) {
		cmd->type = IRC_CMDID_INVITE;
	} else if(cmd->name.len==(sizeof("add")-1)
				&& !strncasecmp(cmd->name.s, "add", cmd->name.len)) {
		cmd->type = IRC_CMDID_ADD;
	} else if(cmd->name.len==(sizeof("accept")-1)
				&& !strncasecmp(cmd->name.s, "accept", cmd->name.len)) {
		cmd->type = IRC_CMDID_ACCEPT;
	} else if(cmd->name.len==(sizeof("reject")-1)
				&& !strncasecmp(cmd->name.s, "reject", cmd->name.len)) {
		cmd->type = IRC_CMDID_REJECT;
	} else if(cmd->name.len==(sizeof("deny")-1)
				&& !strncasecmp(cmd->name.s, "deny", cmd->name.len)) {
		cmd->type = IRC_CMDID_REJECT;
	} else if(cmd->name.len==(sizeof("remove")-1)
				&& !strncasecmp(cmd->name.s, "remove", cmd->name.len)) {
		cmd->type = IRC_CMDID_REMOVE;
	} else if(cmd->name.len==(sizeof("leave")-1)
				&& !strncasecmp(cmd->name.s, "leave", cmd->name.len)) {
		cmd->type = IRC_CMDID_LEAVE;
	} else if(cmd->name.len==(sizeof("exit")-1)
				&& !strncasecmp(cmd->name.s, "exit", cmd->name.len)) {
		cmd->type = IRC_CMDID_LEAVE;
	} else if(cmd->name.len==(sizeof("members")-1)
				&& !strncasecmp(cmd->name.s, "members", cmd->name.len)) {
		cmd->type = IRC_CMDID_MEMBERS;
	} else if(cmd->name.len==(sizeof("rooms")-1)
				&& !strncasecmp(cmd->name.s, "rooms", cmd->name.len)) {
		cmd->type = IRC_CMDID_ROOMS;
	} else if(cmd->name.len==(sizeof("list")-1)
				&& !strncasecmp(cmd->name.s, "list", cmd->name.len)) {
		cmd->type = IRC_CMDID_MEMBERS;
	} else if(cmd->name.len==(sizeof("destroy")-1)
				&& !strncasecmp(cmd->name.s, "destroy", cmd->name.len)) {
		cmd->type = IRC_CMDID_DESTROY;
	} else if(cmd->name.len==(sizeof("help")-1)
				&& !strncasecmp(cmd->name.s, "help", cmd->name.len)) {
		cmd->type = IRC_CMDID_HELP;
		goto done;
	} else {
		cmd->type = IRC_CMDID_UNKNOWN;
		goto done;
	}


	if(*p=='\0' || p>=buf+len)
		goto done;

	i=0;
	do {
		while(p<buf+len && (*p==' ' || *p=='\t'))
			p++;
		if(p>=buf+len || *p=='\0' || *p=='\r' || *p=='\n')
			goto done;
		cmd->param[i].s = p;
		while(p<buf+len)
		{
			if(*p=='\0' || *p==' ' || *p=='\t' || *p=='\r' || *p=='\n')
				break;
			p++;
		}
		cmd->param[i].len =  p - cmd->param[i].s;
		i++;
		if(i>=IRC_CMD_MAX_PARAM)
			break;
	} while(1);

done:
	LM_DBG("command: [%.*s]\n", STR_FMT(&cmd->name));
	for(i=0; i<IRC_CMD_MAX_PARAM; i++)
	{
		if(cmd->param[i].len<=0)
			break;
		LM_DBG("parameter %d=[%.*s]\n", i, STR_FMT(&cmd->param[i]));
	}
	return 0;
}



int irc_handle_create(struct sip_msg* msg, irc_cmd_t *cmd,
					  struct irc_uri *src, struct irc_uri *dst)
{
	int rv = -1;
	irc_room_p rm = 0;
	irc_member_p member = 0;
	int flag_room = 0;
	int flag_member = 0;
	str body;
	struct irc_uri room;
	int params = 0;
	str rs = STR_NULL, ps = STR_NULL;

	memset(&room, '\0', sizeof(room));

	if (cmd->param[0].s) {
		params++;
		if (cmd->param[1].s) {
			params++;
		}
	}

	switch(params) {
	case 0:
		/* With no parameter, use To for the room uri and create a public room */
		break;

	case 1:
		/* With one parameter, if the value is "private", it indicates
		 * a private room, otherwise it is the URI of the room and we
		 * create a public room. */
		if (cmd->param[0].len == IRC_ROOM_PRIVATE_LEN
				&& !strncasecmp(cmd->param[0].s, IRC_ROOM_PRIVATE,
					cmd->param[0].len)) {
			ps = cmd->param[0];
		} else {
			rs = cmd->param[0];
		}
		break;

	case 2:
		/* With two parameters, the first parameter is room URI and
		 * the second parameter must be "private". */
		rs = cmd->param[0];
		ps = cmd->param[1];
		break;

	default:
		LM_ERR("Invalid number of parameters %d\n", params);
		goto error;
	}

	if (build_irc_uri(&room, rs.s ? rs : dst->parsed.user, &dst->parsed) != 0)
		goto error;

	if (ps.s) {
		if (ps.len == IRC_ROOM_PRIVATE_LEN
				&& !strncasecmp(ps.s, IRC_ROOM_PRIVATE, ps.len)) {
			flag_room |= IRC_ROOM_PRIV;
			LM_DBG("Room with private flag on\n");
		} else {
			LM_ERR("Second argument to command 'create' must be string 'private'\n");
			goto error;
		}
	}

	rm = irc_get_room(&room.parsed.user, &room.parsed.host);
	if (rm == NULL) {
		LM_DBG("Creating new room [%.*s]\n", STR_FMT(&room.uri));

		rm = irc_add_room(&room.parsed.user, &room.parsed.host, flag_room);
		if (rm == NULL) {
			LM_ERR("Failed to add new room\n");
			goto error;
		}
		LM_DBG("Added room [%.*s]\n", STR_FMT(&rm->uri));

		flag_member |= IRC_MEMBER_OWNER;
		/* adding the owner as the first member*/
		member = irc_add_member(rm, &src->parsed.user, &src->parsed.host, flag_member);
		if (member == NULL) {
			LM_ERR("failed to add owner [%.*s]\n", STR_FMT(&src->uri));
			goto error;
		}
		LM_DBG("Added [%.*s] as the first member in room [%.*s]\n",
			   STR_FMT(&member->uri), STR_FMT(&rm->uri));

		goto done;
	}

	LM_DBG("Room [%.*s] already exists\n", STR_FMT(&rm->uri));

	if (irc_check_on_create) {
		goto done;
	}

	if (rm->flags & IRC_ROOM_PRIV) {
		goto done;
	}

	LM_DBG("Checking if user [%.*s] is a member\n", STR_FMT(&src->uri));
	member = irc_get_member(rm, &src->parsed.user, &src->parsed.host);

	if (member) {
		goto done;
	}

	member = irc_add_member(rm, &src->parsed.user, &src->parsed.host, flag_member);
	if (member == NULL) {
		LM_ERR("Failed to add member [%.*s]\n", STR_FMT(&src->uri));
		goto error;
	}
	LM_DBG("Added [%.*s] as member to room [%.*s]\n", STR_FMT(&member->uri),
			STR_FMT(&rm->uri));

	body.s = irc_body_buf;
	body.len = snprintf(body.s, sizeof(irc_body_buf), msg_user_joined.s,
			STR_FMT(format_uri(member->uri)));

	if (body.len < 0) {
		LM_ERR("Error while building response\n");
		goto error;
	}

	if (body.len > 0)
		irc_room_broadcast(rm, build_headers(msg, 0), &body);

	if (body.len >= sizeof(irc_body_buf))
		LM_ERR("Truncated message '%.*s'\n", STR_FMT(&body));

done:
	rv = 0;
error:
	if (room.uri.s) pkg_free(room.uri.s);
	if (rm != NULL) irc_release_room(rm);
	return rv;
}


int irc_handle_join(struct sip_msg* msg, irc_cmd_t *cmd,
		struct irc_uri *src, struct irc_uri *dst)
{
	int rv = -1;
	irc_room_p rm = 0;
	irc_member_p member = 0;
	int flag_room = 0;
	int flag_member = 0;
	str body;
	struct irc_uri room;

	if(cmd==NULL || src==NULL || dst==NULL) {
		return -1;
	}

	memset(&room, '\0', sizeof(room));
	if (build_irc_uri(&room, cmd->param[0].s ? cmd->param[0] : dst->parsed.user, &dst->parsed))
		goto error;

	rm = irc_get_room(&room.parsed.user, &room.parsed.host);
	if (rm == NULL || (rm->flags & IRC_ROOM_DELETED)) {
		LM_DBG("Room [%.*s] not found\n", STR_FMT(&room.uri));

		if (!irc_create_on_join) {
			goto done;
		}

		LM_DBG("Creating room [%.*s]\n", STR_FMT(&room.uri));
		rm = irc_add_room(&room.parsed.user, &room.parsed.host, flag_room);
		if (rm == NULL) {
			LM_ERR("Failed to add new room [%.*s]\n", STR_FMT(&room.uri));
			goto error;
		}
		LM_DBG("Created a new room [%.*s]\n", STR_FMT(&rm->uri));
		flag_member |= IRC_MEMBER_OWNER;
		member = irc_add_member(rm, &src->parsed.user, &src->parsed.host, flag_member);
		if (member == NULL) {
			LM_ERR("Failed to add new member [%.*s]\n", STR_FMT(&src->uri));
			goto error;
		}
		/* send info message */
		goto done;
	}

	LM_DBG("Found room [%.*s]\n", STR_FMT(&rm->uri));

	member = irc_get_member(rm, &src->parsed.user, &src->parsed.host);
	if (member && !(member->flags & IRC_MEMBER_DELETED)) {
		LM_DBG("User [%.*s] is already in the room\n", STR_FMT(&member->uri));
		goto done;
	}

	body.s = irc_body_buf;
	if (!(rm->flags & IRC_ROOM_PRIV)) {
		LM_DBG("adding new member [%.*s]\n", STR_FMT(&src->uri));
		member = irc_add_member(rm, &src->parsed.user, &src->parsed.host, flag_member);
		if (member == NULL) {
			LM_ERR("Failed to add new user [%.*s]\n", STR_FMT(&src->uri));
			goto error;
		}

		body.len = snprintf(body.s, sizeof(irc_body_buf), msg_user_joined.s,
				STR_FMT(format_uri(src->uri)));
	} else {
		LM_DBG("Attept to join private room [%.*s] by [%.*s]\n",
			STR_FMT(&rm->uri), STR_FMT(&src->uri));

		body.len = snprintf(body.s, sizeof(irc_body_buf), msg_join_attempt_bcast.s,
				STR_FMT(format_uri(src->uri)));
	}

	if (body.len < 0) {
		LM_ERR("Error while building response\n");
		goto error;
	}

	if (body.len > 0)
		irc_room_broadcast(rm, build_headers(msg, 0), &body);

	if (body.len >= sizeof(irc_body_buf))
		LM_ERR("Truncated message '%.*s'\n", STR_FMT(&body));

done:
	if (member != NULL && (member->flags & IRC_MEMBER_INVITED))
		member->flags &= ~IRC_MEMBER_INVITED;

	rv = 0;
error:
	if (room.uri.s != NULL) pkg_free(room.uri.s);
	if (rm != NULL) irc_release_room(rm);
	return rv;
}


int irc_handle_invite(struct sip_msg* msg, irc_cmd_t *cmd,
		struct irc_uri *src, struct irc_uri *dst)
{
	int rv = -1;
	irc_room_p rm = 0;
	irc_member_p member = 0;
	int flag_member = 0;
	str body;
	del_member_t *cback_param = NULL;
	int result, i;
	uac_req_t uac_r;
	struct irc_uri user, room;

	memset(&user, '\0', sizeof(user));
	memset(&room, '\0', sizeof(room));

	if (cmd->param[0].s == NULL) {
		LM_INFO("Invite command with missing argument from [%.*s]\n", STR_FMT(&src->uri));
		goto error;
	}

	if (build_irc_uri(&room, dst->parsed.user, &dst->parsed))
		goto error;

	rm = irc_get_room(&room.parsed.user, &room.parsed.host);
	if (rm == NULL) {

		rm = irc_add_room(&room.parsed.user, &room.parsed.host, 0);

		if (rm == NULL) {
			LM_ERR("Room [%.*s] does not exist!\n", STR_FMT(&room.uri));
			goto error;
		}

		member = irc_add_member(rm, &src->parsed.user, &src->parsed.host, flag_member);
		if (member == NULL) {
			LM_ERR("Failed to add new user [%.*s]\n", STR_FMT(&src->uri));
			goto error;
		}
	}

	for (i = 0; cmd->param[i].s; ++i) {

		if (build_irc_uri(&user, cmd->param[i], &dst->parsed))
			goto error;
		
		member = irc_get_member(rm, &user.parsed.user, &user.parsed.host);
		if (member != NULL) {
			continue;
		}

		// flag_member |= IRC_MEMBER_INVITED;
		member = irc_add_member(rm, &user.parsed.user, &user.parsed.host, flag_member);

	}

	rv = 0;
error:
	if (user.uri.s != NULL) pkg_free(user.uri.s);
	if (room.uri.s != NULL) pkg_free(room.uri.s);
	if (rm != NULL) irc_release_room(rm);
	return rv;
}


int irc_handle_add(struct sip_msg* msg, irc_cmd_t *cmd,
		struct irc_uri *src, struct irc_uri *dst)
{
	int rv = -1;
	irc_room_p rm = 0;
	irc_member_p member = 0;
	str body;
	struct irc_uri user, room;

	memset(&user, '\0', sizeof(user));
	memset(&room, '\0', sizeof(room));

	if (cmd->param[0].s == NULL) {
		LM_INFO("Add command with missing argument from [%.*s]\n", STR_FMT(&src->uri));
		goto error;
	}

	if (build_irc_uri(&user, cmd->param[0], &dst->parsed))
		goto error;

	if (build_irc_uri(&room, cmd->param[1].s ? cmd->param[1] : dst->parsed.user, &dst->parsed))
		goto error;

	rm = irc_get_room(&room.parsed.user, &room.parsed.host);
	if (rm == NULL || (rm->flags & IRC_ROOM_DELETED)) {
		LM_ERR("Room [%.*s] does not exist!\n", STR_FMT(&room.uri));
		goto error;
	}
	member = irc_get_member(rm, &src->parsed.user, &src->parsed.host);

	if (member == NULL) {
		LM_ERR("User [%.*s] is not member of room [%.*s]!\n",
			STR_FMT(&src->uri), STR_FMT(&room.uri));
		goto error;
	}

	if (!(member->flags & IRC_MEMBER_OWNER) &&
			!(member->flags & IRC_MEMBER_ADMIN)) {
		LM_ERR("User [%.*s] has no right to add others!\n", STR_FMT(&member->uri));
		irc_send_message(&rm->uri, &member->uri, build_headers(msg, 0), &msg_add_reject);
		goto done;
	}

	member = irc_get_member(rm, &user.parsed.user, &user.parsed.host);
	if (member != NULL) {
		LM_ERR("User [%.*s] is already in room [%.*s]!\n", STR_FMT(&member->uri), STR_FMT(&rm->uri));
		goto error;
	}

	member = irc_add_member(rm, &user.parsed.user, &user.parsed.host, 0);
	if (member == NULL) {
		LM_ERR("Adding member [%.*s] failed\n", STR_FMT(&user.uri));
		goto error;
	}

	body.s = irc_body_buf;
	body.len = snprintf(body.s, sizeof(irc_body_buf), msg_user_joined.s, STR_FMT(format_uri(member->uri)));

	if (body.len < 0) {
		LM_ERR("Error while building response\n");
		goto error;
	}

	if (body.len > 0)
		irc_room_broadcast(rm, build_headers(msg, 0), &body);

	if (body.len >= sizeof(irc_body_buf))
		LM_ERR("Truncated message '%.*s'\n", STR_FMT(&body));

done:
	rv = 0;
error:
	if (user.uri.s != NULL) pkg_free(user.uri.s);
	if (room.uri.s != NULL) pkg_free(room.uri.s);
	if (rm != NULL) irc_release_room(rm);
	return rv;
}


int irc_handle_accept(struct sip_msg* msg, irc_cmd_t *cmd,
		struct irc_uri *src, struct irc_uri *dst)
{
	int rv = -1;
	irc_room_p rm = 0;
	irc_member_p member = 0;
	str body;
	struct irc_uri room;

	memset(&room, '\0', sizeof(room));

	if (build_irc_uri(&room, cmd->param[0].s ? cmd->param[0] : dst->parsed.user, &dst->parsed))
		goto error;

	rm = irc_get_room(&room.parsed.user, &room.parsed.host);
	if (rm == NULL || (rm->flags & IRC_ROOM_DELETED)) {
		LM_ERR("Room [%.*s] does not exist!\n",	STR_FMT(&room.uri));
		goto error;
	}

	/* if aready invited add as a member */
	member = irc_get_member(rm, &src->parsed.user, &src->parsed.host);
	if (member == NULL || !(member->flags & IRC_MEMBER_INVITED)) {
		LM_ERR("User [%.*s] not invited to the room!\n", STR_FMT(&src->uri));
		goto error;
	}

	member->flags &= ~IRC_MEMBER_INVITED;

	body.s = irc_body_buf;
	body.len = snprintf(body.s, sizeof(irc_body_buf), msg_user_joined.s, STR_FMT(format_uri(member->uri)));

	if (body.len < 0) {
		LM_ERR("Error while building response\n");
		goto error;
	}

	if (body.len > 0)
		irc_room_broadcast(rm, build_headers(msg, 0), &body);

	if (body.len >= sizeof(irc_body_buf))
		LM_ERR("Truncated message '%.*s'\n", STR_FMT(&body));

	rv = 0;
error:
	if (room.uri.s != NULL) pkg_free(room.uri.s);
	if (rm != NULL) irc_release_room(rm);
	return rv;
}


int irc_handle_remove(struct sip_msg* msg, irc_cmd_t *cmd,
		struct irc_uri *src, struct irc_uri *dst)
{
	int rv = -1;
	irc_room_p rm = 0;
	irc_member_p member = 0;
	str body;
	struct irc_uri user, room;

	memset(&user, '\0', sizeof(user));
	memset(&room, '\0', sizeof(room));

	if (build_irc_uri(&user, cmd->param[0], &dst->parsed))
		goto error;

	if (build_irc_uri(&room, cmd->param[1].s ? cmd->param[1] : dst->parsed.user, &dst->parsed))
		goto error;

	rm = irc_get_room(&room.parsed.user, &room.parsed.host);
	if (rm == NULL || (rm->flags & IRC_ROOM_DELETED)) {
		LM_ERR("Room [%.*s] does not exist!\n", STR_FMT(&room.uri));
		goto error;
	}

	/* verify if the user who sent the request is a member in the room
	 * and has the right to remove other users */
	member = irc_get_member(rm, &src->parsed.user, &src->parsed.host);
	if (member == NULL) {
		LM_ERR("User [%.*s] is not member of room [%.*s]!\n",
				STR_FMT(&src->uri), STR_FMT(&rm->uri));
		goto error;
	}

	if (!(member->flags & IRC_MEMBER_OWNER) && !(member->flags & IRC_MEMBER_ADMIN)) {
		LM_ERR("User [%.*s] has no right to remove from room [%.*s]!\n",
			   STR_FMT(&src->uri), STR_FMT(&rm->uri));
		goto error;
	}

	/* verify if the user that is to be removed is a member of the room */
	member = irc_get_member(rm, &user.parsed.user, &user.parsed.host);
	if (member == NULL) {
		LM_ERR("User [%.*s] is not member of room [%.*s]!\n",
				STR_FMT(&user.uri), STR_FMT(&rm->uri));
		goto error;
	}

	if (member->flags & IRC_MEMBER_OWNER) {
		LM_ERR("User [%.*s] is owner of room [%.*s] and cannot be removed!\n",
			   STR_FMT(&member->uri), STR_FMT(&rm->uri));
		goto error;
	}

	LM_DBG("to: [%.*s]\nfrom: [%.*s]\nbody: [%.*s]\n",
			STR_FMT(&member->uri) , STR_FMT(&rm->uri),
			STR_FMT(&msg_user_removed));
	irc_send_message(&rm->uri, &member->uri, build_headers(msg, 0), &msg_user_removed);

	member->flags |= IRC_MEMBER_DELETED;
	irc_del_member(rm, &user.parsed.user, &user.parsed.host);

	body.s = irc_body_buf;
	body.len = snprintf(body.s, sizeof(irc_body_buf), msg_user_left.s, STR_FMT(format_uri(member->uri)));

	if (body.len < 0) {
		LM_ERR("Error while building response\n");
		goto error;
	}

	if (body.len > 0)
		irc_room_broadcast(rm, build_headers(msg, 0), &body);

	if (body.len >= sizeof(irc_body_buf))
		LM_ERR("Truncated message '%.*s'\n", STR_FMT(&body));

	rv = 0;
error:
	if (user.uri.s != NULL) pkg_free(user.uri.s);
	if (room.uri.s != NULL) pkg_free(room.uri.s);
	if (rm != NULL) irc_release_room(rm);
	return rv;
}


int irc_handle_reject(struct sip_msg* msg, irc_cmd_t *cmd,
		struct irc_uri *src, struct irc_uri *dst)
{
	int rv = -1;
	irc_room_p rm = 0;
	irc_member_p member = 0;
	struct irc_uri room;

	memset(&room, '\0', sizeof(room));
	if (build_irc_uri(&room, cmd->param[0].s ? cmd->param[0] : dst->parsed.user, &dst->parsed))
		goto error;

	rm = irc_get_room(&room.parsed.user, &room.parsed.host);
	if (rm == NULL || (rm->flags & IRC_ROOM_DELETED)) {
		LM_ERR("Room [%.*s] does not exist!\n", STR_FMT(&room.uri));
		goto error;
	}

	/* If the user is an invited member, delete it from the list */
	member = irc_get_member(rm, &src->parsed.user, &src->parsed.host);
	if (member == NULL || !(member->flags & IRC_MEMBER_INVITED)) {
		LM_ERR("User [%.*s] was not invited to room [%.*s]!\n",
				STR_FMT(&src->uri), STR_FMT(&rm->uri));
		goto error;
	}

#if 0
	body.s = irc_body_buf;
	body.len = snprintf(body.s, sizeof(irc_body_buf), msg_rejected.s, STR_FMT(format_uri(src->uri)));
	if (body.len > 0)
	    irc_send_message(&rm->uri, &member->uri, build_headers(msg), &body);
#endif

	LM_DBG("User [%.*s] rejected invitation to room [%.*s]!\n",
			STR_FMT(&src->uri), STR_FMT(&rm->uri));

	irc_del_member(rm, &src->parsed.user, &src->parsed.host);

	rv = 0;
error:
	if (room.uri.s != NULL) pkg_free(room.uri.s);
	if (rm != NULL) irc_release_room(rm);
	return rv;
}


int irc_handle_members(struct sip_msg* msg, irc_cmd_t *cmd,
		struct irc_uri *src, struct irc_uri *dst)
{
	int rv = -1;
	irc_room_p rm = 0;
	irc_member_p member = 0;
	irc_member_p imp = 0;
	str body, *name;
	char *p;
	size_t left;
	struct irc_uri room;

	memset(&room, '\0', sizeof(room));
	if (build_irc_uri(&room, cmd->param[0].s ? cmd->param[0] : dst->parsed.user,
				&dst->parsed)) {
		goto done;
	}

	rm = irc_get_room(&room.parsed.user, &room.parsed.host);
	if (rm == NULL || (rm->flags & IRC_ROOM_DELETED)) {
		LM_ERR("Room [%.*s] does not exist!\n",	STR_FMT(&room.uri));
		goto done;
	}

	/* verify if the user is a member of the room */
	member = irc_get_member(rm, &src->parsed.user, &src->parsed.host);
	if (member == NULL) {
		LM_ERR("User [%.*s] is not member of room [%.*s]!\n",
				STR_FMT(&src->uri), STR_FMT(&rm->uri));
		goto done;
	}

	p = irc_body_buf;
	irc_body_buf[IRC_BUF_SIZE - 1] = '\0';
	left = sizeof(irc_body_buf) - 1;

	memcpy(p, MEMBERS, sizeof(MEMBERS) - 1);
	p += sizeof(MEMBERS) - 1;
	left -= sizeof(MEMBERS) - 1;

	imp = rm->members;
	while (imp) {
		if ((imp->flags & IRC_MEMBER_INVITED) || (imp->flags & IRC_MEMBER_DELETED)
			|| (imp->flags & IRC_MEMBER_SKIP)) {
			imp = imp->next;
			continue;
		}

		if (imp->flags & IRC_MEMBER_OWNER) {
			if (left < 2) goto overrun;
			*p++ = '*';
			left--;
		} else if (imp->flags & IRC_MEMBER_ADMIN) {
			if (left < 2) goto overrun;
			*p++ = '~';
			left--;
		}

		name = format_uri(imp->uri);
		if (left < name->len + 1) goto overrun;
		strncpy(p, name->s, name->len);
		p += name->len;
		left -= name->len;

		if (left < 2) goto overrun;
		*p++ = '\n';
		left--;

		imp = imp->next;
	}

	/* write over last '\n' */
	*(--p) = 0;
	body.s   = irc_body_buf;
	body.len = p - body.s;

	LM_DBG("members = '%.*s'\n", STR_FMT(&body));
	LM_DBG("Message-ID: '%.*s'\n", STR_FMT(get_callid(msg)));
	irc_send_message(&rm->uri, &member->uri, build_headers(msg, 0), &body);

	rv = 0;
	goto done;

overrun:
	LM_ERR("Buffer too small for member list message\n");

done:
	if (room.uri.s != NULL) pkg_free(room.uri.s);
	if (rm != NULL) irc_release_room(rm);
	return rv;
}


int irc_handle_rooms(struct sip_msg* msg, irc_cmd_t *cmd,
		struct irc_uri *src, struct irc_uri *dst)
{
	int i, rv = -1;
	irc_room_p room;
	str body, *name;
	char *p;
	size_t left;

	p = irc_body_buf;
	left = sizeof(irc_body_buf) - 2;

	memcpy(p, ROOMS, sizeof(ROOMS) - 1);
	p += sizeof(ROOMS) - 1;
	left -= sizeof(ROOMS) - 1;

	for (i = 0; i < irc_hash_size; i++) {
		lock_get(&_irc_htable[i].lock);
		for (room = _irc_htable[i].rooms; room != NULL ; room = room->next) {
			if (room->flags & IRC_ROOM_DELETED) continue;

			name = format_uri(room->uri);
			if (left < name->len) {
				lock_release(&_irc_htable[i].lock);
				goto error;
			}
			strncpy(p, name->s, name->len);
			p += name->len;
			left -= name->len;

			if (left < 1) {
				lock_release(&_irc_htable[i].lock);
				goto error;
			}
			*p++ = '\n';
			left--;
		}
		lock_release(&_irc_htable[i].lock);
	}

	/* write over last '\n' */
	*(--p) = 0;
	body.s   = irc_body_buf;
	body.len = p - body.s;

	LM_DBG("rooms = '%.*s'\n", STR_FMT(&body));
	irc_send_message(&dst->uri, &src->uri, build_headers(msg, 0), &body);

	return 0;

error:
	LM_ERR("Buffer too small for member list message\n");
	return rv;
}


int irc_handle_leave(struct sip_msg* msg, irc_cmd_t *cmd,
		struct irc_uri *src, struct irc_uri *dst)
{
	int rv = -1;
	irc_room_p rm = 0;
	irc_member_p member = 0;
	str body;
	struct irc_uri room;

	memset(&room, '\0', sizeof(room));
	if (build_irc_uri(&room, cmd->param[0].s ? cmd->param[0] : dst->parsed.user, &dst->parsed))
		goto error;

	rm = irc_get_room(&room.parsed.user, &room.parsed.host);
	if (rm == NULL || (rm->flags & IRC_ROOM_DELETED)) {
		LM_ERR("Room [%.*s] does not exist!\n",	STR_FMT(&room.uri));
		goto error;
	}

	/* verify if the user is a member of the room */
	member = irc_get_member(rm, &src->parsed.user, &src->parsed.host);
	if (member == NULL) {
		LM_ERR("User [%.*s] is not member of room [%.*s]!\n",
				STR_FMT(&src->uri), STR_FMT(&rm->uri));
		goto error;
	}

	if (member->flags & IRC_MEMBER_OWNER) {
		irc_send_message(&rm->uri, &member->uri, build_headers(msg, 0), &msg_leave_error);
        goto done;
    }

	body.s = irc_body_buf;
	body.len = snprintf(body.s, sizeof(irc_body_buf), msg_user_left.s, STR_FMT(format_uri(member->uri)));

	if (body.len < 0) {
		LM_ERR("Error while building response\n");
		goto error;
	}

	if (body.len > 0)
		irc_room_broadcast(rm, build_headers(msg, 0), &body);

	if (body.len >= sizeof(irc_body_buf))
		LM_ERR("Truncated message '%.*s'\n", STR_FMT(&body));

	member->flags |= IRC_MEMBER_DELETED;
	irc_del_member(rm, &src->parsed.user, &src->parsed.host);

done:
	rv = 0;
error:
	if (room.uri.s != NULL) pkg_free(room.uri.s);
	if (rm != NULL) irc_release_room(rm);
	return rv;
}


int irc_handle_destroy(struct sip_msg* msg, irc_cmd_t *cmd,
		struct irc_uri *src, struct irc_uri *dst)
{
	int rv = -1;
	irc_room_p rm = 0;
	irc_member_p member = 0;
	struct irc_uri room;

	memset(&room, '\0', sizeof(room));
	if (build_irc_uri(&room, cmd->param[0].s ? cmd->param[0] : dst->parsed.user, &dst->parsed))
		goto error;

	rm = irc_get_room(&room.parsed.user, &room.parsed.host);
	if (rm == NULL || (rm->flags & IRC_ROOM_DELETED)) {
		LM_ERR("Room [%.*s] does not exist!\n",	STR_FMT(&room.uri));
		goto error;
	}

	/* verify is the user is a member of the room*/
	member = irc_get_member(rm, &src->parsed.user, &src->parsed.host);
	if (member == NULL) {
		LM_ERR("User [%.*s] is not a member of room [%.*s]!\n",
				STR_FMT(&src->uri), STR_FMT(&rm->uri));
		goto error;
	}

	if (!(member->flags & IRC_MEMBER_OWNER)) {
		LM_ERR("User [%.*s] is not owner of room [%.*s] and cannot destroy it!\n",
			   STR_FMT(&src->uri), STR_FMT(&rm->uri));
		goto error;
	}
	rm->flags |= IRC_ROOM_DELETED;

	/* braodcast message */
	irc_room_broadcast(rm, build_headers(msg, 0), &msg_room_destroyed);

	irc_release_room(rm);
	rm = NULL;

	LM_DBG("Deleting room [%.*s]\n", STR_FMT(&room.uri));
	irc_del_room(&room.parsed.user, &room.parsed.host);

	rv = 0;
error:
	if (room.uri.s != NULL) pkg_free(room.uri.s);
	if (rm != NULL) irc_release_room(rm);
	return rv;
}


int irc_handle_help(struct sip_msg* msg, irc_cmd_t *cmd, struct irc_uri *src, struct irc_uri *dst)
{
	str body;
	uac_req_t uac_r;

	body.s   = IRC_HELP_MSG;
	body.len = IRC_HELP_MSG_LEN;

	LM_DBG("to: [%.*s] from: [%.*s]\n", STR_FMT(&src->uri), STR_FMT(&dst->uri));
	set_uac_req(&uac_r, &irc_msg_type, build_headers(msg, 0), &body, 0, 0, 0, 0);
	tmb.t_request(&uac_r,
				NULL,									/* Request-URI */
				&src->uri,								/* To */
				&dst->uri,								/* From */
				(outbound_proxy.s)?&outbound_proxy:NULL/* outbound proxy */
				);
	return 0;
}


int irc_handle_unknown(struct sip_msg* msg, irc_cmd_t *cmd, struct irc_uri *src, struct irc_uri *dst)
{
	str body;
	uac_req_t uac_r;

	body.s   = irc_body_buf;
	body.len = snprintf(body.s, sizeof(irc_body_buf), msg_invalid_command.s,
		STR_FMT(&cmd->name), STR_FMT(&irc_cmd_start_str));

	if (body.len < 0 || body.len >= sizeof(irc_body_buf)) {
		LM_ERR("Unable to print message\n");
		return -1;
	}

	LM_DBG("to: [%.*s] from: [%.*s]\n", STR_FMT(&src->uri), STR_FMT(&dst->uri));
	set_uac_req(&uac_r, &irc_msg_type, build_headers(msg, 0), &body, 0, 0, 0, 0);
	tmb.t_request(&uac_r,
				NULL,									/* Request-URI */
				&src->uri,								/* To */
				&dst->uri,								/* From */
				(outbound_proxy.s)?&outbound_proxy:NULL /* outbound proxy */
			);
	return 0;
}


int irc_handle_message(struct sip_msg* msg, str *msgbody,
		struct irc_uri *src, struct irc_uri *dst, int push)
{
	int add_member = strncmp(src->parsed.user.s, "alice", 5) != 0;
	int rv = -1; 
	irc_room_p room = 0;
	irc_member_p member = 0;
	str body, *user;

	LM_INFO("IRC handle message");

	room = irc_get_room(&dst->parsed.user, &dst->parsed.host);
	if (room == NULL || (room->flags & IRC_ROOM_DELETED)) {
		room = irc_add_room(&dst->parsed.user, &dst->parsed.host, 0);
		if (room == NULL) {
			LM_ERR("Failed to add new room [%.*s]\n", STR_FMT(&dst->parsed.user));
			goto error;
		}
	}
	else {
		member = irc_get_member(room, &src->parsed.user, &src->parsed.host);
	}

	if (!member && add_member) {
		member = irc_add_member(room, &src->parsed.user, &src->parsed.host, 0);
		if (member == NULL) {
			LM_ERR("Adding member [%.*s] failed\n", STR_FMT(&src->uri));
			goto error;
		}
	}

	LM_DBG("Broadcast to room [%.*s]\n", STR_FMT(&room->uri));

	user = format_uri(member->uri);

	body.s = irc_body_buf;
	body.len = snprintf(body.s, sizeof(irc_body_buf), "%.*s: %.*s", STR_FMT(user), STR_FMT(msgbody));

	if (body.len < 0) {
		LM_ERR("Error while printing message\n");
		goto error;
	}

	if (body.len >= sizeof(irc_body_buf)) {
		LM_ERR("Buffer too small for message '%.*s'\n", STR_FMT(&body));
		goto error;
	}

	member->flags |= IRC_MEMBER_SKIP;
	irc_room_broadcast(room, build_headers(msg, push), &body);
	member->flags &= ~IRC_MEMBER_SKIP;

	rv = 0;
error:
	if (room != NULL) irc_release_room(room);
	return rv;
}


int irc_room_broadcast(irc_room_p room, str *ctype, str *body)
{
	irc_member_p imp;

	if (room == NULL || body == NULL)
		return -1;

	imp = room->members;

	LM_DBG("nr = %d\n", room->nr_of_members);

	while(imp) {
		LM_DBG("to uri = %.*s\n", STR_FMT(&imp->uri));
		if ((imp->flags & IRC_MEMBER_INVITED) || (imp->flags & IRC_MEMBER_DELETED)
				|| (imp->flags & IRC_MEMBER_SKIP)) {
			imp = imp->next;
			continue;
		}

		/* to-do: callback to remove user if delivery fails */
		irc_send_message(&room->uri, &imp->uri, ctype, body);

		imp = imp->next;
	}
	return 0;
}


int irc_send_message(str *src, str *dst, str *headers, str *body)
{
	uac_req_t uac_r;

	if (src == NULL || dst == NULL || body == NULL)
		return -1;

	/* to-do: callback to remove user if delivery fails */
	set_uac_req(&uac_r, &irc_msg_type, headers, body, 0, 0, 0, 0);
	tmb.t_request(&uac_r,
			NULL,										/* Request-URI */
			dst,										/* To */
			src,										/* From */
			(outbound_proxy.s)?&outbound_proxy:NULL  	/* outbound proxy */
		);
	return 0;
}


void irc_inv_callback(struct cell *t, int type, struct tmcb_params *ps)
{
	str body_final;
	char from_uri_buf[256];
	char to_uri_buf[256];
	char body_buf[256];
	str from_uri_s, to_uri_s;
	irc_member_p member= NULL;
	irc_room_p room = NULL;
	uac_req_t uac_r;

	if (ps->param == NULL || *ps->param == NULL ||
		(del_member_t*)(*ps->param) == NULL) {
		LM_DBG("member not received\n");
		return;
	}

	LM_DBG("completed with status %d [member name domain:"
			"%p/%.*s/%.*s]\n",ps->code, ps->param,
			STR_FMT(&((del_member_t *)(*ps->param))->member_name),
			STR_FMT(&((del_member_t *)(*ps->param))->member_domain));
	if (ps->code < 300) {
		return;
	} else {
		room = irc_get_room(&((del_member_t *)(*ps->param))->room_name,
						&((del_member_t *)(*ps->param))->room_domain);
		if (room ==NULL) {
			LM_ERR("The room does not exist!\n");
			goto error;
		}
		/*verify if the user who sent the request is a member in the room
		 * and has the right to remove other users */
		member = irc_get_member(room,
				&((del_member_t *)(*ps->param))->member_name,
				&((del_member_t *)(*ps->param))->member_domain);

		if( member == NULL) {
			LM_ERR("The user is not a member of the room!\n");
			goto error;
		}
		irc_del_member(room,
				&((del_member_t *)(*ps->param))->member_name,
				&((del_member_t *)(*ps->param))->member_domain);
		goto build_inform;
	}

build_inform:
	body_final.s = body_buf;
	body_final.len = member->uri.len - 4 /* sip: part of URI */ + 20;
	memcpy(body_final.s, member->uri.s + 4, member->uri.len - 4);
	memcpy(body_final.s + member->uri.len - 4," is not registered.  ", 21);

	goto send_message;

send_message:

	from_uri_s.s = from_uri_buf;
	from_uri_s.len = room->uri.len;
	strncpy(from_uri_s.s, room->uri.s, room->uri.len);

	LM_DBG("sending message\n");

	to_uri_s.s = to_uri_buf;
	to_uri_s.len = ((del_member_t *)(*ps->param))->inv_uri.len;
	strncpy(to_uri_s.s, ((del_member_t *)(*ps->param))->inv_uri.s,
			((del_member_t *)(*ps->param))->inv_uri.len);

	LM_DBG("to: %.*s\nfrom: %.*s\nbody: %.*s\n", STR_FMT(&to_uri_s),
			STR_FMT(&from_uri_s), STR_FMT(&body_final));
	set_uac_req(&uac_r, &irc_msg_type, &extra_hdrs, &body_final, 0, 0, 0, 0);
	tmb.t_request(&uac_r,
					NULL,									/* Request-URI */
					&to_uri_s,								/* To */
					&from_uri_s,							/* From */
					(outbound_proxy.s)?&outbound_proxy:NULL /* outbound proxy*/
				);

error:
	if (room != NULL) irc_release_room(room);
	if ((del_member_t *)(*ps->param)) shm_free(*ps->param);
}
