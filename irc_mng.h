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



#ifndef _IRC_MNG_H_
#define _IRC_MNG_H_



#include "../../core/locking.h"
#include "../../core/str.h"
#include "../../core/parser/parse_from.h"

#define IRC_MEMBER_OWNER	(1<<0)
#define IRC_MEMBER_ADMIN	(1<<1)
#define IRC_MEMBER_INVITED	(1<<2)
#define IRC_MEMBER_DELETED  (1<<3)
#define IRC_MEMBER_SKIP     (1<<4)

typedef struct _irc_member
{
	unsigned int hashid;
	str uri;
	str user;
	str domain;
	int flags;
	struct _irc_member * next;
	struct _irc_member * prev;
} irc_member_t, *irc_member_p;

#define IRC_ROOM_PRIV		(1<<0)
#define IRC_ROOM_DELETED	(1<<1)
typedef struct del_member
{
	str room_name;
	str room_domain;
	str inv_uri;
	str member_name;
	str member_domain;
}del_member_t;


typedef struct _irc_room
{
	unsigned int hashid;
	str uri;
	str name;
	str domain;
	int flags;
	int nr_of_members;
	irc_member_p members;
	struct _irc_room * next;
	struct _irc_room * prev;
} irc_room_t, *irc_room_p;

typedef struct _irc_hentry
{
	irc_room_p rooms;
	gen_lock_t lock;
} irc_hentry_t, *irc_hentry_p;

irc_member_p irc_add_member(irc_room_p room, str* user, str* domain, int flags);
irc_member_p irc_get_member(irc_room_p room, str* user, str* domain);
int irc_del_member(irc_room_p room, str* user, str* domain);

irc_room_p irc_add_room(str* name, str* domain, int flags);
irc_room_p irc_get_room(str* name, str* domain);
int irc_del_room(str* name, str* domain);
int irc_release_room(irc_room_p room);

int irc_htable_init(void);
int irc_htable_destroy(void);



#endif

