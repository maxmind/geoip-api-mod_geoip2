/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2002 MaxMind.com.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        MaxMind (http://www.maxmind.com/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "MaxMind" and "GeoIP" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact support@maxmind.com.
 *
 * 5. Products derived from this software may not be called "GeoIP",
 *    nor may "MaxMind" appear in their name, without prior written
 *    permission of the MaxMind.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 */

/* geoip module
 *
 * Version 1.0.5
 *
 * This module sets an environment variable to the remote country
 * based on the requestor's IP address.  It uses the GeoIP library
 * to lookup the country by IP address.
 *
 * Copyright 2002, MaxMind.com
 * June 26th, 2002
 *
 * Contributed by Corris Randall <corris@cpan.org>
 *
 */

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"
#include <GeoIP.h>

typedef struct {
	GeoIP *gip;
	char *filename;
	int enabled;
} geoip_server_config_rec;

module AP_MODULE_DECLARE_DATA geoip_module;

static void *create_geoip_server_config( apr_pool_t *p, server_rec *d )
{
	return apr_pcalloc(p, sizeof(geoip_server_config_rec));
}


static apr_status_t geoip_cleanup(void *cfgdata)
{
	geoip_server_config_rec *cfg = (geoip_server_config_rec *)cfgdata;
	GeoIP_delete( cfg->gip );
	return APR_SUCCESS;
}


static void geoip_child_init(apr_pool_t *p, server_rec *s)
{
	geoip_server_config_rec *cfg;

	cfg = (geoip_server_config_rec *)
		ap_get_module_config(s->module_config,  &geoip_module);

	if ( !cfg->gip ) {
		if ( cfg->filename != NULL ) {
			cfg->gip = GeoIP_open(cfg->filename, GEOIP_STANDARD);
		}
		else {
			cfg->gip = GeoIP_new( GEOIP_STANDARD );
		}
		if ( ! cfg->gip ) {
			ap_log_error(APLOG_MARK,APLOG_ERR, 0, s, "Error while opening data file");
			return;
		}
	}

	apr_pool_cleanup_register(p, (void *)cfg, geoip_cleanup, geoip_cleanup);

}


static int geoip_post_read_request(request_rec *r)
{
	char *ipaddr;
	short int country_id;
	GeoIP *gip;
	const char *country_code;
	const char *country_name;

	geoip_server_config_rec *cfg;

	cfg = ap_get_module_config(r->server->module_config, &geoip_module);

	if ( !cfg ) 
		return DECLINED;

	if ( !cfg->enabled ) 
		return DECLINED;

	ipaddr = r->connection->remote_ip;

	if ( !cfg->gip ) {
		if ( cfg->filename != NULL ) {
			cfg->gip = GeoIP_open(cfg->filename, GEOIP_STANDARD);
		}
		else {
			cfg->gip = GeoIP_new( GEOIP_STANDARD );
		}
		if ( ! cfg->gip ) {
			ap_log_rerror(APLOG_MARK,APLOG_ERR, 0, r, "Error while opening data file");
			return DECLINED;
		}
	}

	/* Get the Country ID */
	country_id = GeoIP_country_id_by_addr( cfg->gip, ipaddr );

	/* Lookup the Code and the Name with the ID */
	country_code = GeoIP_country_code[country_id];
	country_name = GeoIP_country_name[country_id];

	/* Set it for our user */
	apr_table_setn( r->notes,          "GEOIP_COUNTRY_CODE", country_code );
	apr_table_setn( r->notes,          "GEOIP_COUNTRY_NAME", country_name );
	apr_table_setn( r->subprocess_env, "GEOIP_COUNTRY_CODE", country_code );
	apr_table_setn( r->subprocess_env, "GEOIP_COUNTRY_NAME", country_name );

	return OK;
}


static const char *set_geoip_enable(cmd_parms *cmd, void *dummy, int arg)
{
	geoip_server_config_rec *conf = (geoip_server_config_rec *)
	ap_get_module_config(cmd->server->module_config, &geoip_module);

	if (!conf)
		return "mod_geoip: server structure not allocated";


	conf->enabled = arg;
	return NULL;
}


static const char *set_geoip_filename(cmd_parms *cmd, void *dummy, const char *filename)
{
	geoip_server_config_rec *conf = (geoip_server_config_rec *)
		ap_get_module_config(cmd->server->module_config, &geoip_module);

	if ( ! filename )
		return NULL;

	conf->filename = (char *)apr_pstrdup(cmd->pool,filename);

	return NULL;
}


static void *make_geoip(apr_pool_t *p, server_rec *d)
{
	geoip_server_config_rec *dcfg;

	dcfg = (geoip_server_config_rec *) apr_pcalloc(p, sizeof(geoip_server_config_rec));
	dcfg->gip = NULL;
	dcfg->enabled = 0;
	return dcfg;
}


static const command_rec geoip_cmds[] = 
{
	AP_INIT_FLAG( "GeoIPEnable", set_geoip_enable,   NULL, OR_FILEINFO, "Turn on mod_geoip"),
	AP_INIT_TAKE1("GeoIPDBFile", set_geoip_filename, NULL, OR_FILEINFO, "Path to GeoIP Data File"),
	{NULL}
};


static void geoip_register_hooks(apr_pool_t *p)
{
	ap_hook_post_read_request( geoip_post_read_request, NULL, NULL, APR_HOOK_MIDDLE );
	ap_hook_child_init(        geoip_child_init,        NULL, NULL, APR_HOOK_MIDDLE );
}


/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA geoip_module = {
	STANDARD20_MODULE_STUFF, 
	NULL,                        /* create per-dir    config structures */
	NULL,                        /* merge  per-dir    config structures */
	make_geoip,                  /* create per-server config structures */
	NULL,                        /* merge  per-server config structures */
	geoip_cmds,                  /* table of config file commands       */
	geoip_register_hooks         /* register hooks                      */
};

