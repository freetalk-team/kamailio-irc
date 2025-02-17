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


#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "../../core/mem/mem.h"
#include "../../core/mem/shm_mem.h"
#include "../../core/dprint.h"
#include "../../core/hashes.h"

#include "irc_mng.h"
/* imc hash table */
extern irc_hentry_p _irc_htable;
extern int irc_hash_size;
extern char irc_cmd_start_char;
#define irc_get_hentry(_hid, _size) ((_hid)&(_size-1))

/**
 * hash thable init
 */
int irc_htable_init(void)
{
	int i;

	if(irc_hash_size<=0)
	{
		LM_ERR("invalid hash table size\n");
		return -1;
	}
	_irc_htable = (irc_hentry_p)shm_malloc(irc_hash_size*sizeof(irc_hentry_t));
	if(_irc_htable == NULL)
	{
		LM_ERR("no more shm memory\n");
		return -1;
	}
	memset(_irc_htable, 0, irc_hash_size*sizeof(irc_hentry_t));
	for(i=0; i<irc_hash_size; i++)
	{
		if (lock_init(&_irc_htable[i].lock)==0)
		{
			LM_CRIT("failed to initialize lock [%d]\n", i);
			goto error;
		}
	}
	
	return 0;

error:
	if(_irc_htable!=NULL)
	{
		shm_free(_irc_htable);
		_irc_htable = NULL;
	}

	return -1;
}

/**
 * destroy hash table
 */
int irc_htable_destroy(void)
{
	int i;
	irc_room_p irp = NULL, irp_temp=NULL;
	if(_irc_htable==NULL)
		return -1;
	
	for(i=0; i<irc_hash_size; i++)
	{
		lock_destroy(&_irc_htable[i].lock);
		if(_irc_htable[i].rooms==NULL) {
			continue;
		}
		irp = _irc_htable[i].rooms;
		while(irp){
			irp_temp = irp->next;
			irc_del_room(&irp->name, &irp->domain);
			irp = irp_temp;
		}
	}
	shm_free(_irc_htable);
	_irc_htable = NULL;
	return 0;
}

/**
 * add room
 */
irc_room_p irc_add_room(str* name, str* domain, int flags)
{
	irc_room_p irp = NULL;
	int size;
	int hidx;
	
	if(name == NULL || name->s==NULL || name->len<=0
			|| domain == NULL || domain->s==NULL || domain->len<=0)
	{
		LM_ERR("invalid parameters\n");
		return NULL;
	}

	/* struct size + "sip:" + name len + "@" + domain len + '\0' */
	size = sizeof(irc_room_t) + (name->len+domain->len+6)*sizeof(char);
	irp = (irc_room_p)shm_malloc(size);
	if(irp==NULL)
	{
		LM_ERR("no more shm memory left\n");
		return NULL;
	}
	memset(irp, 0, size);
	
	irp->uri.len = 4 /*sip:*/ + name->len + 1 /*@*/ + domain->len;
	irp->uri.s = (char*)(((char*)irp)+sizeof(irc_room_t));
	memcpy(irp->uri.s, "sip:", 4);
	memcpy(irp->uri.s+4, name->s, name->len);
	irp->uri.s[4+name->len] = '@';
	memcpy(irp->uri.s+5+name->len, domain->s, domain->len);
	irp->uri.s[irp->uri.len] = '\0';

	irp->name.len = name->len;
	irp->name.s = irp->uri.s+4;
	irp->domain.len = domain->len;
	irp->domain.s = irp->uri.s+5+name->len;
	
	irp->flags  = flags;
	irp->hashid = core_case_hash(&irp->name, &irp->domain, 0);
	
	hidx = irc_get_hentry(irp->hashid, irc_hash_size);

	lock_get(&_irc_htable[hidx].lock);
	
	if(_irc_htable[hidx].rooms!=NULL)
	{
		irp->next = _irc_htable[hidx].rooms;
		_irc_htable[hidx].rooms->prev = irp;
		_irc_htable[hidx].rooms = irp;
	} else {
		_irc_htable[hidx].rooms = irp;
	}	
	
	return irp;
}

/**
 * release room
 */
int irc_release_room(irc_room_p room)
{
	unsigned int hidx;
	
	if(room==NULL)
	{
		LM_ERR("invalid parameters\n");
		return -1;
	}
	
	hidx = irc_get_hentry(room->hashid, irc_hash_size);
	lock_release(&_irc_htable[hidx].lock);

	return 0;
}

/**
 * search room
 */
irc_room_p irc_get_room(str* name, str* domain)
{
	irc_room_p irp = NULL;
	unsigned int hashid;
	int hidx;
	
	if(name == NULL || name->s==NULL || name->len<=0
			|| domain == NULL || domain->s==NULL || domain->len<=0)
	{
		LM_ERR("invalid parameters\n");
		return NULL;
	}
	
	hashid = core_case_hash(name, domain, 0);
	
	hidx = irc_get_hentry(hashid, irc_hash_size);

	lock_get(&_irc_htable[hidx].lock);
	irp = _irc_htable[hidx].rooms;

	while(irp)
	{
		if(irp->hashid==hashid && irp->name.len==name->len
				&& irp->domain.len==domain->len
				&& !strncasecmp(irp->name.s, name->s, name->len)
				&& !strncasecmp(irp->domain.s, domain->s, domain->len))
		{
			return irp;
		}
		irp = irp->next;
	}

	/* no room */
	lock_release(&_irc_htable[hidx].lock);

	return NULL;
}

/**
 * delete room
 */
int irc_del_room(str* name, str* domain)
{
	irc_room_p irp = NULL;
	irc_member_p imp=NULL, imp_temp=NULL;
	unsigned int hashid;
	int hidx;	
	
	if(name == NULL || name->s==NULL || name->len<=0
			|| domain == NULL || domain->s==NULL || domain->len<=0)
	{
		LM_ERR("invalid parameters\n");
		return -1;
	}
	
	hashid = core_case_hash(name, domain, 0);
	
	hidx = irc_get_hentry(hashid, irc_hash_size);
	
	lock_get(&_irc_htable[hidx].lock);
	irp = _irc_htable[hidx].rooms;
	while(irp)
	{
		if(irp->hashid==hashid && irp->name.len==name->len
				&& irp->domain.len==domain->len
				&& !strncasecmp(irp->name.s, name->s, name->len)
				&& !strncasecmp(irp->domain.s, domain->s, domain->len))
		{
			if(irp->prev==NULL) {
				_irc_htable[hidx].rooms = irp->next;
			} else {
				irp->prev->next = irp->next;
			}
			if(irp->next!=NULL) {
				irp->next->prev = irp->prev;
			}

			/* delete members */
			imp = irp->members;
			while(imp){
				imp_temp = imp->next;
				shm_free(imp);
				imp = imp_temp;
			}		

			shm_free(irp);

			goto done;
		}
		irp = irp->next;
	}

done:	
	lock_release(&_irc_htable[hidx].lock);

	return 0;
}

/**
 * add member
 */
irc_member_p irc_add_member(irc_room_p room, str* user, str* domain, int flags)
{
	irc_member_p imp = NULL;
	int size;
	
	if(room==NULL || user == NULL || user->s==NULL || user->len<=0
			|| domain == NULL || domain->s==NULL || domain->len<=0)
	{
		LM_ERR("invalid parameters\n");
		return NULL;
	}
	
	/* struct size + "sip:" + user name len + "@" + domain len + '\0' */
	size = sizeof(irc_member_t) + (user->len+domain->len+6)*sizeof(char);
	imp = (irc_member_p)shm_malloc(size);
	if(imp== NULL)
	{
		LM_ERR("out of shm memory\n");
		return NULL;
	}
	memset(imp, 0, size);
	
	imp->uri.len = 4 /*sip:*/ + user->len + 1 /*@*/ + domain->len;
	imp->uri.s = (char*)(((char*)imp)+sizeof(irc_member_t));
	memcpy(imp->uri.s, "sip:", 4);
	memcpy(imp->uri.s+4, user->s, user->len);
	imp->uri.s[4+user->len] = '@';
	memcpy(imp->uri.s+5+user->len, domain->s, domain->len);
	imp->uri.s[imp->uri.len] = '\0';
	
	LM_DBG("[uri]= %.*s\n", STR_FMT(&imp->uri));
	imp->user.len = user->len;
	imp->user.s = imp->uri.s+4;
	
	LM_DBG("[user]= %.*s\n", STR_FMT(&imp->user));
	imp->domain.len = domain->len;
	imp->domain.s = imp->uri.s+5+user->len;

	imp->flags  = flags;
	imp->hashid = core_case_hash(&imp->user, &imp->domain, 0);

	room->nr_of_members++;
	
	if(room->members==NULL) {
		room->members = imp;
	} else {
		imp->next = room->members->next;
		if((room->members)->next!=NULL)
			((room->members)->next)->prev = imp;
		imp->prev = room->members;
		
		room->members->next=imp;
	}

	return imp;
}

/**
 * search memeber
 */
irc_member_p irc_get_member(irc_room_p room, str* user, str* domain)
{
	irc_member_p imp = NULL;
	unsigned int hashid;

	if(room==NULL || user == NULL || user->s==NULL || user->len<=0
			|| domain == NULL || domain->s==NULL || domain->len<=0)
	{
		LM_ERR("invalid parameters\n");
		return NULL;
	}
	
	hashid = core_case_hash(user, domain, 0);
	imp = room->members;
	while(imp)
	{
		if(imp->hashid==hashid && imp->user.len==user->len
				&& imp->domain.len==domain->len
				&& !strncasecmp(imp->user.s, user->s, user->len)
				&& !strncasecmp(imp->domain.s, domain->s, domain->len))
		{
			LM_DBG("found member\n");
			return imp;
		}
		imp = imp->next;
	}

	return NULL;
}

/**
 * delete member
 */
int irc_del_member(irc_room_p room, str* user, str* domain)
{
	irc_member_p imp = NULL;
	unsigned int hashid;
	
	if(room==NULL || user == NULL || user->s==NULL || user->len<=0
			|| domain == NULL || domain->s==NULL || domain->len<=0)
	{
		LM_ERR("invalid parameters\n");
		return -1;
	}
	
	hashid = core_case_hash(user, domain, 0);
	imp = room->members;
	while(imp)
	{
		if(imp->hashid==hashid && imp->user.len==user->len
				&& imp->domain.len==domain->len
				&& !strncasecmp(imp->user.s, user->s, user->len)
				&& !strncasecmp(imp->domain.s, domain->s, domain->len))
		{
			if(imp->prev==NULL)
				room->members = imp->next;
			else
				imp->prev->next = imp->next;
			if(imp->next!=NULL)
				imp->next->prev = imp->prev;
			shm_free(imp);
			room->nr_of_members--;
			return 0;
		}
		imp = imp->next;
	}
	
	return 0;
}
