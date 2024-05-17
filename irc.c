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
#include <sys/types.h>
#include <sys/ipc.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include "../../lib/srdb1/db.h"
#include "../../lib/srdb1/db_res.h"
#include "../../core/sr_module.h"
#include "../../core/dprint.h"
#include "../../core/ut.h"
#include "../../core/timer.h"
#include "../../core/str.h"
#include "../../core/mem/shm_mem.h"
#include "../../lib/srdb1/db.h"
#include "../../core/parser/parse_from.h"
#include "../../core/parser/parse_content.h"
#include "../../core/parser/contact/parse_contact.h"
#include "../../core/resolve.h"
#include "../../core/hashes.h"
#include "../../core/rpc.h"
#include "../../core/rpc_lookup.h"
#include "../../core/kemi.h"

#include "../../modules/tm/tm_load.h"


#include "irc_mng.h"
#include "irc_cmd.h"

MODULE_VERSION

/** header variables */
str irc_hdrs = str_init("Content-Type: text/plain\r\nSupported: kamailio/irc\r\n");
char hdr_buf[1024];
str all_hdrs;

/** parameters */

db1_con_t *irc_db = NULL;
db_func_t irc_dbf;
static str db_url  = str_init(DEFAULT_DB_URL);
str outbound_proxy = {NULL, 0};

static str rooms_table   = str_init("irc_rooms");
static str members_table = str_init("irc_members");

static str irc_col_username = str_init("username");
static str irc_col_domain   = str_init("domain");
static str irc_col_flag     = str_init("flag");
static str irc_col_room     = str_init("room");
static str irc_col_name     = str_init("name");

irc_hentry_p _irc_htable = NULL;
int irc_hash_size = 4;
str irc_cmd_start_str = str_init(IRC_CMD_START_STR);
char irc_cmd_start_char;
str extra_hdrs = {NULL, 0};
int irc_create_on_join = 1;
int irc_check_on_create = 0;

/** module functions */
static int mod_init(void);
static int child_init(int);

static int w_irc_manager(struct sip_msg*, char *, char *);
static int w_irc_manager_push(struct sip_msg*, char *, char *);

static int irc_rpc_init(void);

static void destroy(void);

/** TM bind */
struct tm_binds tmb;

/** TM callback function */
void inv_callback( struct cell *t, int type, struct tmcb_params *ps);

static cmd_export_t cmds[]={
	{"irc_manager",  (cmd_function)w_irc_manager, 0, 0, 0, REQUEST_ROUTE},
	{"irc_manager_push",  (cmd_function)w_irc_manager_push, 0, 0, 0, REQUEST_ROUTE},
	{0,0,0,0,0,0}
};


static param_export_t params[]={
	{"db_url",				PARAM_STR, &db_url},
	{"hash_size",			INT_PARAM, &irc_hash_size},
	{"irc_cmd_start_char",	PARAM_STR, &irc_cmd_start_str},
	{"rooms_table",			PARAM_STR, &rooms_table},
	{"members_table",		PARAM_STR, &members_table},
	{"outbound_proxy",		PARAM_STR, &outbound_proxy},
	{"extra_hdrs",        PARAM_STR, &extra_hdrs},
	{"create_on_join", INT_PARAM, &irc_create_on_join},
	{"check_on_create", INT_PARAM, &irc_check_on_create},
	{0,0,0}
};

#ifdef STATISTICS
#include "../../core/counters.h"

stat_var* irc_active_rooms;

stat_export_t irc_stats[] = {
	{"active_rooms" ,  0,  &irc_active_rooms  },
	{0,0,0}
};

#endif

/** module exports */
struct module_exports exports= {
	"irc",      /* module name */
	DEFAULT_DLFLAGS, /* dlopen flags */
	cmds,       /* exported commands */
	params,     /* exported parameters */
	0,          /* exported rpc functions */
	0,          /* exported pseudo-variables */
	0,          /* response handling function */
	mod_init,   /* module init function */
	child_init, /* child init function */
	destroy     /* module destroy function */
};

/**
 * the initiating function
 */
int add_from_db(void)
{
	irc_member_p member = NULL;
	int i, j, flag;
	db_key_t mq_result_cols[4], mquery_cols[2];
	db_key_t rq_result_cols[4];
	db_val_t mquery_vals[2];
	db1_res_t *r_res= NULL;
	db1_res_t *m_res= NULL;
	db_row_t *m_row = NULL, *r_row = NULL;
	db_val_t *m_row_vals, *r_row_vals = NULL;
	str name, domain;
	irc_room_p room = NULL;
	int er_ret = -1;

	rq_result_cols[0] = &irc_col_name;
	rq_result_cols[1] = &irc_col_domain;
	rq_result_cols[2] = &irc_col_flag;

	mq_result_cols[0] = &irc_col_username;
	mq_result_cols[1] = &irc_col_domain;
	mq_result_cols[2] = &irc_col_flag;

	mquery_cols[0] = &irc_col_room;
	mquery_vals[0].type = DB1_STR;
	mquery_vals[0].nul = 0;

	if(irc_dbf.use_table(irc_db, &rooms_table)< 0)
	{
		LM_ERR("use_table failed\n");
		return -1;
	}

	if(irc_dbf.query(irc_db,0, 0, 0, rq_result_cols,0, 3, 0,&r_res)< 0)
	{
		LM_ERR("failed to querry table\n");
		return -1;
	}
	if(r_res==NULL || r_res->n<=0)
	{
		LM_INFO("the query returned no result\n");
		if(r_res) irc_dbf.free_result(irc_db, r_res);
		r_res = NULL;
		return 0;
	}

	LM_DBG("found %d rooms\n", r_res->n);

	for(i =0 ; i< r_res->n ; i++)
	{
		/*add rooms*/
		r_row = &r_res->rows[i];
		r_row_vals = ROW_VALUES(r_row);

		name.s = 	r_row_vals[0].val.str_val.s;
		name.len = strlen(name.s);

		domain.s = 	r_row_vals[1].val.str_val.s;
		domain.len = strlen(domain.s);

		flag = 	r_row_vals[2].val.int_val;

		room = irc_add_room(&name, &domain, flag);
		if(room == NULL)
		{
			LM_ERR("failed to add room\n ");
			goto error;
		}

		/* add members */
		if(irc_dbf.use_table(irc_db, &members_table)< 0)
		{
			LM_ERR("use_table failed\n ");
			goto error;
		}

		mquery_vals[0].val.str_val= room->uri;

		if(irc_dbf.query(irc_db, mquery_cols, 0, mquery_vals, mq_result_cols,
					1, 3, 0, &m_res)< 0)
		{
			LM_ERR("failed to querry table\n");
			goto error;
		}

		if(m_res==NULL || m_res->n<=0)
		{
			LM_INFO("the query returned no result\n");
			er_ret = 0;
			goto error; /* each room must have at least one member*/
		}
		for(j =0; j< m_res->n; j++)
		{
			m_row = &m_res->rows[j];
			m_row_vals = ROW_VALUES(m_row);

			name.s = m_row_vals[0].val.str_val.s;
			name.len = strlen(name.s);

			domain.s = m_row_vals[1].val.str_val.s;
			domain.len = strlen(domain.s);

			flag = m_row_vals[2].val.int_val;

			LM_DBG("adding memeber: [name]=%.*s [domain]=%.*s"
					" in [room]= %.*s\n", STR_FMT(&name), STR_FMT(&domain),
					STR_FMT(&room->uri));

			member = irc_add_member(room, &name, &domain, flag);
			if(member == NULL)
			{
				LM_ERR("failed to adding member\n ");
				goto error;
			}
			irc_release_room(room);
		}

		if(m_res)
		{
			irc_dbf.free_result(irc_db, m_res);
			m_res = NULL;
		}
	}

	// if(irc_dbf.use_table(irc_db, &members_table)< 0)
	// {
	// 	LM_ERR("use table failed\n ");
	// 	goto error;
	// }

	// if(irc_dbf.delete(irc_db, 0, 0 , 0, 0) < 0)
	// {
	// 	LM_ERR("failed to delete information from db\n");
	// 	goto error;
	// }

	// if(irc_dbf.use_table(irc_db, &rooms_table)< 0)
	// {
	// 	LM_ERR("use table failed\n ");
	// 	goto error;
	// }

	// if(irc_dbf.delete(irc_db, 0, 0 , 0, 0) < 0)
	// {
	// 	LM_ERR("failed to delete information from db\n");
	// 	goto error;
	// }

	if(r_res)
	{
		irc_dbf.free_result(irc_db, r_res);
		r_res = NULL;
	}

	return 0;

error:
	if(r_res)
	{
		irc_dbf.free_result(irc_db, r_res);
		r_res = NULL;
	}
	if(m_res)
	{
		irc_dbf.free_result(irc_db, m_res);
		m_res = NULL;
	}
	if(room)
		irc_release_room(room);
	return er_ret;

}


static int mod_init(void)
{
#ifdef STATISTICS
	/* register statistics */
	if (register_module_stats( exports.name, irc_stats)!=0 ) {
		LM_ERR("failed to register core statistics\n");
		return -1;
	}
#endif

	if(irc_rpc_init()<0)
	{
		LM_ERR("failed to register RPC commands\n");
		return -1;
	}

	if(irc_hash_size <= 0)
	{
		LM_ERR("invalid hash size\n");
		return -1;
	}

	irc_hash_size = 1 << irc_hash_size;

	if(irc_htable_init() < 0)
	{
		LM_ERR("initializing hash table\n");
		return -1;
	}

	if (extra_hdrs.s) {
		if (extra_hdrs.len + irc_hdrs.len > 1024) {
			LM_ERR("extra_hdrs too long\n");
			return -1;
		}
		all_hdrs.s = &(hdr_buf[0]);
		memcpy(all_hdrs.s, irc_hdrs.s, irc_hdrs.len);
		memcpy(all_hdrs.s + irc_hdrs.len, extra_hdrs.s,
				extra_hdrs.len);
		all_hdrs.len = extra_hdrs.len + irc_hdrs.len;
	} else {
		all_hdrs = irc_hdrs;
	}

	/*  binding to mysql module */
	LM_DBG("db_url=%s/%d/%p\n", ZSW(db_url.s), db_url.len, db_url.s);

	if (db_bind_mod(&db_url, &irc_dbf))
	{
		LM_DBG("database module not found\n");
		return -1;
	}

	irc_db = irc_dbf.init(&db_url);
	if (!irc_db)
	{
		LM_ERR("failed to connect to the database\n");
		return -1;
	}
	/* read the informations stored in db */
	if(add_from_db() <0)
	{
		LM_ERR("failed to get information from db\n");
		return -1;
	}

	/* load TM API */
	if (load_tm_api(&tmb)!=0) {
		LM_ERR("unable to load tm api\n");
		return -1;
	}

	irc_cmd_start_char = irc_cmd_start_str.s[0];

	if(irc_db)
	 	irc_dbf.close(irc_db);
	irc_db = NULL;

	return 0;
}

/**
 * child init
 */
static int child_init(int rank)
{
	if (rank==PROC_INIT || rank==PROC_TCP_MAIN)
		return 0; /* do nothing for the main process */

	if (irc_dbf.init==0)
	{
		LM_ERR("database not bound\n");
		return -1;
	}
	irc_db = irc_dbf.init(&db_url);
	if (!irc_db)
	{
		LM_ERR("child %d: Error while connecting database\n", rank);
		return -1;
	}
	else
	{
		if (irc_dbf.use_table(irc_db, &rooms_table) < 0)
		{
			LM_ERR("child %d: Error in use_table '%.*s'\n", rank, STR_FMT(&rooms_table));
			return -1;
		}
		if (irc_dbf.use_table(irc_db, &members_table) < 0)
		{
			LM_ERR("child %d: Error in use_table '%.*s'\n", rank, STR_FMT(&members_table));
			return -1;
		}

		LM_DBG("child %d: Database connection opened successfully\n", rank);
	}

	return 0;
}


static int ki_irc_manager(struct sip_msg* msg, int push)
{
	irc_cmd_t cmd;
	str body;
	struct irc_uri src, dst;
	int ret = -1;

	LM_INFO("IRC manager");

	body.s = get_body( msg );
	if (body.s==0)
	{
		LM_ERR("cannot extract body from msg\n");
		goto error;
	}

	/* lungimea corpului mesajului */
	if (!msg->content_length)
	{
		LM_ERR("no Content-Length\n");
		goto error;
	}
	body.len = get_content_length( msg );

	if(body.len <= 0)
	{
		LM_ERR("empty body!\n");
		goto error;
	}

	dst.uri = *GET_RURI(msg);
	if(parse_sip_msg_uri(msg)<0)
	{
		LM_ERR("failed to parse r-uri\n");
		goto error;
	}
	dst.parsed = msg->parsed_uri;

	if(parse_from_header(msg)<0)
	{
		LM_ERR("failed to parse From header\n");
		goto error;
	}
	src.uri = ((struct to_body*)msg->from->parsed)->uri;
	if (parse_uri(src.uri.s, src.uri.len, &src.parsed)<0){
		LM_ERR("failed to parse From URI\n");
		goto error;
	}

	if(body.s[0]== irc_cmd_start_char)
	{
		LM_DBG("found command\n");
		if(irc_parse_cmd(body.s, body.len, &cmd)<0)
		{
			LM_ERR("failed to parse imc cmd!\n");
			ret = -20;
			goto error;
		}

		switch(cmd.type)
		{
		case IRC_CMDID_CREATE:
			if(irc_handle_create(msg, &cmd, &src, &dst)<0)
			{
				LM_ERR("failed to handle 'create'\n");
				ret = -30;
				goto error;
			}
		break;
		case IRC_CMDID_JOIN:
			if(irc_handle_join(msg, &cmd, &src, &dst)<0)
			{
				LM_ERR("failed to handle 'join'\n");
				ret = -40;
				goto error;
			}
		break;
		case IRC_CMDID_INVITE:
			if(irc_handle_invite(msg, &cmd, &src, &dst)<0)
			{
				LM_ERR("failed to handle 'invite'\n");
				ret = -50;
				goto error;
			}
		break;
		case IRC_CMDID_ADD:
			if(irc_handle_add(msg, &cmd, &src, &dst)<0)
			{
				LM_ERR("failed to handle 'add'\n");
				ret = -50;
				goto error;
			}
		break;
		case IRC_CMDID_ACCEPT:
			if(irc_handle_accept(msg, &cmd, &src, &dst)<0)
			{
				LM_ERR("failed to handle 'accept'\n");
				ret = -60;
				goto error;
			}
		break;
		case IRC_CMDID_REJECT:
			if(irc_handle_reject(msg, &cmd, &src, &dst)<0)
			{
				LM_ERR("failed to handle 'reject'\n");
				ret = -70;
				goto error;
			}
		break;
		case IRC_CMDID_REMOVE:
			if(irc_handle_remove(msg, &cmd, &src, &dst)<0)
			{
				LM_ERR("failed to handle 'remove'\n");
				ret = -80;
				goto error;
			}
		break;
		case IRC_CMDID_LEAVE:
			if(irc_handle_leave(msg, &cmd, &src, &dst)<0)
			{
				LM_ERR("failed to handle 'leave'\n");
				ret = -90;
				goto error;
			}
		break;
		case IRC_CMDID_MEMBERS:
			if(irc_handle_members(msg, &cmd, &src, &dst)<0)
			{
				LM_ERR("failed to handle 'members'\n");
				ret = -100;
				goto error;
			}
		break;
		case IRC_CMDID_ROOMS:
			if(irc_handle_rooms(msg, &cmd, &src, &dst)<0)
			{
				LM_ERR("failed to handle 'rooms'\n");
				ret = -100;
				goto error;
			}
		break;
		case IRC_CMDID_DESTROY:
			if(irc_handle_destroy(msg, &cmd, &src, &dst)<0)
			{
				LM_ERR("failed to handle 'destroy'\n");
				ret = -110;
				goto error;
			}
		break;
		case IRC_CMDID_HELP:
			if(irc_handle_help(msg, &cmd, &src, &dst)<0)
			{
				LM_ERR("failed to handle 'help'\n");
				ret = -120;
				goto error;
			}
		break;
		default:
			if(irc_handle_unknown(msg, &cmd, &src, &dst)<0)
			{
				LM_ERR("failed to handle 'unknown'\n");
				ret = -130;
				goto error;
			}
		}

		goto done;
	}

	if(irc_handle_message(msg, &body, &src, &dst, push)<0)
	{
		LM_ERR("failed to handle 'message'\n");
		ret = -200;
		goto error;
	}

done:
	return 1;

error:
	return ret;
}

static int w_irc_manager(struct sip_msg* msg, char *str1, char *str2)
{
	return ki_irc_manager(msg, 0);
}

static int w_irc_manager_push(struct sip_msg* msg, char *str1, char *str2)
{
	return ki_irc_manager(msg, 1);
}

/**
 * destroy module
 */
static void destroy(void)
{
	irc_htable_destroy();
}


/************************* RPC ***********************/
static void  irc_rpc_list_rooms(rpc_t* rpc, void* ctx)
{
	int i;
	irc_room_p irp = NULL;
	void *vh;
	static str unknown = STR_STATIC_INIT("");

	for(i=0; i<irc_hash_size; i++)
	{
		lock_get(&_irc_htable[i].lock);
		irp = _irc_htable[i].rooms;
		while(irp){
			if (rpc->add(ctx, "{", &vh) < 0) {
				lock_release(&_irc_htable[i].lock);
				rpc->fault(ctx, 500, "Server error");
				return;
			}
			rpc->struct_add(vh, "SdS",
					"room", &irp->uri,
					"members", irp->nr_of_members,
					"owner", (irp->nr_of_members > 0) ? &irp->members->uri : &unknown);

			irp = irp->next;
		}
		lock_release(&_irc_htable[i].lock);
	}

}

static void  irc_rpc_list_members(rpc_t* rpc, void* ctx)
{
	irc_room_p room = NULL;
	void *vh;
	void *ih;
	struct sip_uri inv_uri, *pinv_uri;
	irc_member_p imp=NULL;
	str room_name;

	if (rpc->scan(ctx, "S", &room_name) < 1) {
		rpc->fault(ctx, 500, "No room name");
		return;
	}
	if(room_name.s == NULL || room_name.len == 0
			|| *room_name.s=='\0' || *room_name.s=='.') {
		LM_ERR("empty room name!\n");
		rpc->fault(ctx, 500, "Empty room name");
		return;
	}
	/* find room */
	if(parse_uri(room_name.s,room_name.len, &inv_uri)<0) {
		LM_ERR("invalid room name!\n");
		rpc->fault(ctx, 500, "Invalid room name");
		return;
	}
	pinv_uri=&inv_uri;
	room=irc_get_room(&pinv_uri->user, &pinv_uri->host);

	if(room==NULL) {
		LM_ERR("no such room!\n");
		rpc->fault(ctx, 500, "Room not found");
		return;
	}
	if (rpc->add(ctx, "{", &vh) < 0) {
		irc_release_room(room);
		rpc->fault(ctx, 500, "Server error");
		return;
	}
	rpc->struct_add(vh, "S[d",
			"room", &room->uri,
			"members", &ih,
			"count", room->nr_of_members);

	imp = room->members;
	while(imp) {
		rpc->array_add(ih, "S", &imp->uri);
		imp = imp->next;
	}
	irc_release_room(room);
}

static const char* irc_rpc_list_rooms_doc[2] = {
	"List irc rooms.",
	0
};

static const char* irc_rpc_list_members_doc[2] = {
	"List members in an irc room.",
	0
};

rpc_export_t irc_rpc[] = {
	{"irc.list_rooms", irc_rpc_list_rooms, irc_rpc_list_rooms_doc, RET_ARRAY},
	{"irc.list_members", irc_rpc_list_members, irc_rpc_list_members_doc, 0},
	{0, 0, 0, 0}
};

static int irc_rpc_init(void)
{
	if (rpc_register_array(irc_rpc)!=0)
	{
		LM_ERR("failed to register RPC commands\n");
		return -1;
	}
	return 0;
}

/**
 *
 */
/* clang-format off */
static sr_kemi_t sr_kemi_irc_exports[] = {
	{ str_init("irc"), str_init("irc_manager"),
		SR_KEMIP_INT, ki_irc_manager,
		{ SR_KEMIP_NONE, SR_KEMIP_NONE, SR_KEMIP_NONE,
			SR_KEMIP_NONE, SR_KEMIP_NONE, SR_KEMIP_NONE }
	},

	{ {0, 0}, {0, 0}, 0, NULL, { 0, 0, 0, 0, 0, 0 } }
};
/* clang-format on */

/**
 *
 */
int mod_register(char *path, int *dlflags, void *p1, void *p2)
{
	sr_kemi_modules_add(sr_kemi_irc_exports);
	return 0;
}
