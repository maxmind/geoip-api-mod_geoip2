/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2004 MaxMind LLC.  All rights reserved.
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
 * Version 1.1.1
 *
 * This module sets an environment variable to the remote country
 * based on the requestor's IP address.  It uses the GeoIP library
 * to lookup the country by IP address.
 *
 * Copyright 2004, MaxMind LLC
 * July 12th 2004
 *
 * Initial port Contributed by Corris Randall <corris@cpan.org>
 *
 */

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_strings.h"
#include <GeoIP.h>
#include <GeoIPCity.h>

typedef struct {
	GeoIP **gips;
	int numGeoIPFiles;
	char **GeoIPFilenames;
	int GeoIPEnabled;
	char GeoIPOutput;
	int GeoIPFlags;
	int *GeoIPFlags2;
} geoip_server_config_rec;

static const int GEOIP_NONE    = 0;
static const int GEOIP_DEFAULT = 1;
static const int GEOIP_NOTES   = 2;
static const int GEOIP_ENV     = 4;
static const int GEOIP_ALL     = 6;
static const int GEOIP_INIT    = 7;

static const int GEOIP_UNKNOWN = -1;

char dmacodestr[100];
char areacodestr[100];
char latstr[100];
char lonstr[100];
const char *netspeedstring;

module AP_MODULE_DECLARE_DATA geoip_module;

static void *create_geoip_server_config( apr_pool_t *p, server_rec *d )
{
	geoip_server_config_rec *conf = apr_pcalloc(p, sizeof(geoip_server_config_rec));
	if (!conf){
		return NULL;
	}
	
	conf->gips = NULL;
	conf->numGeoIPFiles = 0;
	conf->GeoIPFilenames = NULL;
	conf->GeoIPEnabled = 0;
	conf->GeoIPOutput = GEOIP_INIT;
	conf->GeoIPFlags = GEOIP_STANDARD;
	conf->GeoIPFlags2 = NULL;
	return (void *)conf;
}


static apr_status_t geoip_cleanup(void *cfgdata)
{
	int i;
	geoip_server_config_rec *cfg = (geoip_server_config_rec *)cfgdata;
	for (i = 0;i < cfg->numGeoIPFiles;i++){
		GeoIP_delete( cfg->gips[i] );
	}
	return APR_SUCCESS;
}


static void geoip_child_init(apr_pool_t *p, server_rec *s)
{
	geoip_server_config_rec *cfg;
	int i;

	cfg = (geoip_server_config_rec *)
		ap_get_module_config(s->module_config,  &geoip_module);

	if ( !cfg->gips ) {
		if ( cfg->GeoIPFilenames != NULL ) {
			cfg->gips = malloc(sizeof(GeoIP *) * cfg->numGeoIPFiles);
			for (i = 0;i < cfg->numGeoIPFiles;i++){
				cfg->gips[i] = GeoIP_open(cfg->GeoIPFilenames[i], (cfg->GeoIPFlags2[i] == GEOIP_UNKNOWN) ? cfg->GeoIPFlags : cfg->GeoIPFlags2[i]);
				if(!cfg->gips[i]) {
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "[mod_geoip]: Error while opening data file %s", cfg->GeoIPFilenames[i]);
					return;
				}
			}
		}
		else {
			cfg->gips = malloc(sizeof(GeoIP *));
			cfg->gips[0] = GeoIP_new( GEOIP_STANDARD );
			if (!cfg->gips[0]){
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "[mod_geoip]: Error while opening data file");
				return;
			}
			cfg->numGeoIPFiles = 1;
		}
	}


	apr_pool_cleanup_register(p, (void *)cfg, geoip_cleanup, geoip_cleanup);

}



static int geoip_post_read_request(request_rec *r)
{
	char *orgorisp;
	char *ipaddr;
	short int country_id;
	GeoIP *gip;
	const char *country_code;
	const char *country_name;

	geoip_server_config_rec *cfg;
	unsigned char databaseType;
	GeoIPRecord * gir;
	GeoIPRegion * giregion;
	int i;
	int netspeed;


	cfg = ap_get_module_config(r->server->module_config, &geoip_module);

	if ( !cfg ) 
		return DECLINED;

	if ( !cfg->GeoIPEnabled ) 
		return DECLINED;

	ipaddr = r->connection->remote_ip;

	if ( !cfg->gips ) {
		if ( cfg->GeoIPFilenames != NULL ) {
			cfg->gips = malloc(sizeof(GeoIP *) * cfg->numGeoIPFiles);
			for (i = 0;i < cfg->numGeoIPFiles;i++){
				cfg->gips[i] = GeoIP_open(cfg->GeoIPFilenames[i], (cfg->GeoIPFlags2[i] == GEOIP_UNKNOWN) ? cfg->GeoIPFlags : cfg->GeoIPFlags2[i]);
				if(!cfg->gips[i]) {
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "[mod_geoip]: Error while opening data file %s", cfg->GeoIPFilenames[i]);
					return DECLINED;
				}
			}
		}
		else {
			cfg->gips = malloc(sizeof(GeoIP *));
			cfg->gips[0] = GeoIP_new( GEOIP_STANDARD );
			if (!cfg->gips[0]){
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "[mod_geoip]: Error while opening data file");
				return DECLINED;
			}
			cfg->numGeoIPFiles = 1;
		}
	}
	for (i = 0; i < cfg->numGeoIPFiles;i++){
        	databaseType = GeoIP_database_edition(cfg->gips[i]);
		switch (databaseType){
                case GEOIP_NETSPEED_EDITION:
			netspeed = GeoIP_id_by_addr (cfg->gips[i], ipaddr);
			if (netspeed == GEOIP_UNKNOWN_SPEED) {
        	              	netspeedstring = "unknown";
      			}
                        else if (netspeed == GEOIP_DIALUP_SPEED) {
        			netspeedstring = "dialup";
      			}
      			else if (netspeed == GEOIP_CABLEDSL_SPEED) {
        			netspeedstring = "cabledsl";
      			}
      			else if (netspeed == GEOIP_CORPORATE_SPEED) {
        			netspeedstring = "corporate";
      			}
			if (cfg->GeoIPOutput & GEOIP_NOTES){
        		        apr_table_setn(r->notes,"GEOIP_NETSPEED",netspeedstring);
        		}
			if (cfg->GeoIPOutput & GEOIP_ENV){
			        apr_table_setn(r->subprocess_env,"GEOIP_NETSPEED",netspeedstring);
			}
                break;
		case GEOIP_COUNTRY_EDITION:
			/* Get the Country ID */
			country_id = GeoIP_country_id_by_addr( cfg->gips[i], ipaddr );

			/* Lookup the Code and the Name with the ID */
			country_code = GeoIP_country_code[country_id];
			country_name = GeoIP_country_name[country_id];

			if (cfg->numGeoIPFiles == 0){cfg->numGeoIPFiles = 0;}
			if (cfg->GeoIPFilenames == 0){cfg->GeoIPFilenames = 0;}
			/* Set it for our user */
			if (cfg->GeoIPOutput & GEOIP_NOTES){
			        apr_table_setn( r->notes,          "GEOIP_COUNTRY_CODE", country_code );
			        apr_table_setn( r->notes,          "GEOIP_COUNTRY_NAME", country_name );
			}
			if (cfg->GeoIPOutput & GEOIP_ENV){
				apr_table_setn( r->subprocess_env, "GEOIP_COUNTRY_CODE", country_code );
				apr_table_setn( r->subprocess_env, "GEOIP_COUNTRY_NAME", country_name );
			}
			break;
		case GEOIP_REGION_EDITION_REV0:
		case GEOIP_REGION_EDITION_REV1:
			giregion = GeoIP_region_by_name( cfg->gips[i], ipaddr);
			if (giregion != NULL){
				if (cfg->GeoIPOutput & GEOIP_NOTES){
					apr_table_set(r->notes, "GEOIP_COUNTRY_CODE", giregion->country_code);
					apr_table_set(r->notes, "GEOIP_REGION", giregion->region);
				}
				if (cfg->GeoIPOutput & GEOIP_ENV){
					apr_table_set(r->subprocess_env, "GEOIP_COUNTRY_CODE", giregion->country_code);
					apr_table_set(r->subprocess_env, "GEOIP_REGION", giregion->region);
				}
				GeoIPRegion_delete(giregion);
			}
			break;
		case GEOIP_CITY_EDITION_REV0:
		case GEOIP_CITY_EDITION_REV1:
			gir = GeoIP_record_by_addr(cfg->gips[i], ipaddr);
		if (gir != NULL) {
			sprintf(dmacodestr,"%d",gir->dma_code);
			sprintf(areacodestr,"%d",gir->area_code);
			if (cfg->GeoIPOutput & GEOIP_NOTES){
				apr_table_setn(r->notes, "GEOIP_COUNTRY_CODE", gir->country_code);
				apr_table_setn(r->notes, "GEOIP_COUNTRY_NAME", gir->country_name);
				if (gir->region != NULL){
					apr_table_set(r->notes, "GEOIP_REGION", gir->region);
				}
				if (gir->city != NULL){
					apr_table_set(r->notes, "GEOIP_CITY", gir->city);
				}
				apr_table_setn(r->notes,"GEOIP_DMA_CODE",dmacodestr);
				apr_table_setn(r->notes,"GEOIP_AREA_CODE",areacodestr);
			}
			if (cfg->GeoIPOutput & GEOIP_ENV){
				apr_table_setn(r->subprocess_env, "GEOIP_COUNTRY_CODE", gir->country_code);
				apr_table_setn(r->subprocess_env, "GEOIP_COUNTRY_NAME", gir->country_name);
				if (gir->region != NULL){
					apr_table_set(r->subprocess_env, "GEOIP_REGION", gir->region);
				}
				if (gir->city != NULL){
					apr_table_set(r->subprocess_env, "GEOIP_CITY", gir->city);
				}
				apr_table_setn(r->subprocess_env,"GEOIP_DMA_CODE",dmacodestr);
				apr_table_setn(r->subprocess_env,"GEOIP_AREA_CODE",areacodestr);
			}
			sprintf(latstr,"%f",gir->latitude);
			sprintf(lonstr,"%f",gir->longitude);
			if (cfg->GeoIPOutput & GEOIP_NOTES){
				apr_table_setn(r->notes,"GEOIP_LATITUDE",latstr);
			}
			if (cfg->GeoIPOutput & GEOIP_ENV){
				apr_table_setn(r->subprocess_env,"GEOIP_LATITUDE",latstr);
			}
			if (cfg->GeoIPOutput & GEOIP_NOTES){
				apr_table_setn(r->notes,"GEOIP_LONGITUDE",lonstr);
			}
			if (cfg->GeoIPOutput & GEOIP_ENV){
				apr_table_setn(r->subprocess_env,"GEOIP_LONGITUDE",lonstr);
			}
			if (gir->postal_code != NULL){
				if (cfg->GeoIPOutput & GEOIP_NOTES){
					apr_table_set(r->notes,"GEOIP_POSTAL_CODE",gir->postal_code);
				}
				if (cfg->GeoIPOutput & GEOIP_ENV){
					apr_table_set(r->subprocess_env,"GEOIP_POSTAL_CODE",gir->postal_code);
				}
			}
			GeoIPRecord_delete(gir);
		}			
		break;
		case GEOIP_ORG_EDITION:
			orgorisp = GeoIP_name_by_addr(cfg->gips[i],ipaddr);
			if (orgorisp != NULL){
				if (cfg->GeoIPOutput & GEOIP_NOTES){
					apr_table_setn(r->notes, "GEOIP_ORGANIZATION", orgorisp);
				}
				if (cfg->GeoIPOutput & GEOIP_ENV){
					apr_table_setn(r->subprocess_env, "GEOIP_ORGANIZATION", orgorisp);
				}
			}
			break;
		case GEOIP_ISP_EDITION:
			orgorisp = GeoIP_name_by_addr(cfg->gips[i],ipaddr);
			if (orgorisp != NULL){
				if (cfg->GeoIPOutput & GEOIP_NOTES){
					apr_table_setn(r->notes, "GEOIP_ISP", orgorisp);
				}
				if (cfg->GeoIPOutput & GEOIP_ENV){
					apr_table_setn(r->subprocess_env, "GEOIP_ISP", orgorisp);
				}
			}
			break;
		}
	}
	
	return OK;
}


static const char *set_geoip_enable(cmd_parms *cmd, void *dummy, int arg)
{
	geoip_server_config_rec *conf = (geoip_server_config_rec *)
	ap_get_module_config(cmd->server->module_config, &geoip_module);

	if (!conf)
		return "mod_geoip: server structure not allocated";


	conf->GeoIPEnabled = arg;
	return NULL;
}


static const char *set_geoip_filename(cmd_parms *cmd, void *dummy, const char *filename,const char *arg2)
{
	int i;
	geoip_server_config_rec *conf = (geoip_server_config_rec *)
		ap_get_module_config(cmd->server->module_config, &geoip_module);

	if ( ! filename )
		return NULL;

	i = conf->numGeoIPFiles;
	conf->numGeoIPFiles++;
	conf->GeoIPFilenames = realloc(conf->GeoIPFilenames, conf->numGeoIPFiles * sizeof(char *));
	conf->GeoIPFilenames[i] = (char *)apr_pstrdup(cmd->pool,filename);
	conf->GeoIPFlags2 = realloc(conf->GeoIPFlags2, conf->numGeoIPFiles * sizeof(int));
	if (arg2 == NULL){
		conf->GeoIPFlags2[i] = GEOIP_UNKNOWN;
	} else if (!strcmp(arg2, "Standard")){
		conf->GeoIPFlags2[i] = GEOIP_STANDARD;
	} else if (!strcmp(arg2, "MemoryCache")){
		conf->GeoIPFlags2[i] = GEOIP_MEMORY_CACHE;
	} else if (!strcmp(arg2, "CheckCache")){
		conf->GeoIPFlags2[i] = GEOIP_CHECK_CACHE;
	} else if (!strcmp(arg2, "IndexCache")){
		conf->GeoIPFlags2[i] = GEOIP_INDEX_CACHE;
	}
	return NULL;
}

static const char *set_geoip_output(cmd_parms *cmd, void *dummy,const char *arg) {
       	geoip_server_config_rec *cfg = (geoip_server_config_rec *) ap_get_module_config(cmd->server->module_config, &geoip_module);
  	if (cfg->GeoIPOutput & GEOIP_DEFAULT) {
    		/* was set to default, clear so can be reset with user specified values */
    		cfg->GeoIPOutput = GEOIP_NONE;
  	}
  	if (!strcmp(arg, "Notes")) {
   	 	cfg->GeoIPOutput |= GEOIP_NOTES;
  	} else if (!strcmp(arg, "Env")) {
    		cfg->GeoIPOutput |= GEOIP_ENV;
  	} else if (!strcmp(arg, "All")) {
    		cfg->GeoIPOutput |= GEOIP_ALL;
  	}
  	return NULL;
}

static void *make_geoip(apr_pool_t *p, server_rec *d)
{
	geoip_server_config_rec *dcfg;

	dcfg = (geoip_server_config_rec *) apr_pcalloc(p, sizeof(geoip_server_config_rec));
	dcfg->gips = NULL;
	dcfg->numGeoIPFiles = 0;
	dcfg->GeoIPFilenames = NULL;
	dcfg->GeoIPEnabled = 0;
	dcfg->GeoIPOutput = GEOIP_INIT;
	dcfg->GeoIPFlags = GEOIP_STANDARD;
	dcfg->GeoIPFlags2 = NULL;
	return dcfg;
}


static const command_rec geoip_cmds[] = 
{
	AP_INIT_FLAG( "GeoIPEnable", set_geoip_enable,   NULL, OR_FILEINFO, "Turn on mod_geoip"),
	AP_INIT_TAKE12("GeoIPDBFile", set_geoip_filename, NULL, OR_FILEINFO, "Path to GeoIP Data File"),
	AP_INIT_ITERATE("GeoIPOutput", set_geoip_output, NULL, OR_FILEINFO, "Specify output method(s)"),
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

