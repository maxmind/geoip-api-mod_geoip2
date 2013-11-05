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
 * Version 1.2.8
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
#include "util_script.h"
#include <arpa/inet.h>
#include <GeoIP.h>
#include <GeoIPCity.h>

typedef struct {
    int GeoIPEnabled;
} geoip_dir_config_rec;

typedef struct {
    GeoIP **gips;
    int numGeoIPFiles;
    char **GeoIPFilenames;
    int GeoIPEnabled;
    int GeoIPEnableUTF8;
    char GeoIPOutput;
    int GeoIPFlags;
    int *GeoIPFlags2;
    int scanProxyHeaders;
    int proxyHeaderMode;
} geoip_server_config_rec;

static const int GEOIP_PROXY_HEADER_MODE_FIRST_IP = 0;
static const int GEOIP_PROXY_HEADER_MODE_LAST_IP = 1;
static const int GEOIP_PROXY_HEADER_MODE_FIRST_NON_PRIVATE_IP = 2;
static const int GEOIP_PROXY_HEADER_MODE_DEFAULT = 0;

static const int GEOIP_NONE = 0;
static const int GEOIP_DEFAULT = 1;
static const int GEOIP_NOTES = 2;
static const int GEOIP_ENV = 4;
static const int GEOIP_ALL = 6;
static const int GEOIP_INIT = 7;

static const int GEOIP_UNKNOWN = -1;

char metrocodestr[100];
char areacodestr[100];
char latstr[100];
char lonstr[100];
const char *netspeedstring;

module AP_MODULE_DECLARE_DATA geoip_module;

uint32_t _private_ipv4_networks[] = {
    167772160U, 184549375U,     // 10.0.0.0/8
    1681915904U, 1686110207U,   // 100.64.0.0/10
    2130706432U, 2147483647U,   // 127.0.0.0/8
    2886729728U, 2887778303U,   // 172.16.0.0/12
    3221225984U, 3221226239U,   // 192.0.2.0/24
    3227017984U, 3227018239U,   // 192.88.99.0/24
    3232235520U, 3232301055U,   // 192.168.0.0/16
    2851995648U, 2852061183U,   // 169.254.0.0/16
    0U, 0U
};

static int _is_private(uint32_t ipnum)
{
    uint32_t min, max;
    uint32_t *p = _private_ipv4_networks;
    while ((min = *p++)) {
        max = *p++;
        if (ipnum < min || ipnum > max)
            continue;
        return 1;
    }
    return 0;
}

char *_get_ip_from_xff(const char *xffheader)
{
    char *xff = strdup(xffheader);
    char *xff_ip, *break_ptr;
    uint32_t ipnum;
    if (xff) {
        for (xff_ip = strtok_r(xff, " \t,", &break_ptr); xff_ip;
             xff_ip = strtok_r(NULL, " \t,", &break_ptr)) {
            if (1 != inet_pton(AF_INET, xff_ip, &ipnum))
                continue;
            ipnum = htonl(ipnum);
            if (!_is_private(ipnum)) {
                char *found = strdup(xff_ip);
                free(xff);
                return found;
            }
        }
        free(xff);
    }
    return NULL;
}

/* create a disabled directory entry */

static void *geoip_create_dir_config(apr_pool_t * p, char *d)
{

    geoip_dir_config_rec *dcfg;

    dcfg =
        (geoip_dir_config_rec *) apr_pcalloc(p, sizeof(geoip_dir_config_rec));
    dcfg->GeoIPEnabled = 0;

    return dcfg;
}

/* create a standard disabled server entry */

static void *create_geoip_server_config(apr_pool_t * p, server_rec * d)
{
    geoip_server_config_rec *conf =
        apr_pcalloc(p, sizeof(geoip_server_config_rec));
    if (!conf) {
        return NULL;
    }

    conf->gips = NULL;
    conf->numGeoIPFiles = 0;
    conf->GeoIPFilenames = NULL;
    conf->GeoIPEnabled = 0;
    conf->GeoIPEnableUTF8 = 0;
    conf->GeoIPOutput = GEOIP_INIT;
    conf->GeoIPFlags = GEOIP_STANDARD;
    conf->GeoIPFlags2 = NULL;
    conf->scanProxyHeaders = 0;
    conf->proxyHeaderMode = 0;
    return (void *)conf;
}

static apr_status_t geoip_cleanup(void *cfgdata)
{
    int i;
    geoip_server_config_rec *cfg = (geoip_server_config_rec *) cfgdata;
    if (cfg->gips) {
        for (i = 0; i < cfg->numGeoIPFiles; i++) {
            if (cfg->gips[i]) {
                GeoIP_delete(cfg->gips[i]);
                cfg->gips[i] = NULL;
            }
        }
        free(cfg->gips);
        cfg->gips = NULL;
    }
    return APR_SUCCESS;
}

/* initialize geoip once per server ( even virtal server! ) */
static void geoip_server_init(apr_pool_t * p, server_rec * s)
{
    geoip_server_config_rec *cfg;
    int i;
    cfg = (geoip_server_config_rec *)
        ap_get_module_config(s->module_config, &geoip_module);

    if (!cfg->gips) {
        if (cfg->GeoIPFilenames != NULL) {
            cfg->gips = malloc(sizeof(GeoIP *) * cfg->numGeoIPFiles);
            for (i = 0; i < cfg->numGeoIPFiles; i++) {
                cfg->gips[i] =
                    GeoIP_open(cfg->GeoIPFilenames[i],
                               (cfg->GeoIPFlags2[i] ==
                                GEOIP_UNKNOWN) ? cfg->GeoIPFlags
                               : cfg->GeoIPFlags2[i]);

                if (cfg->gips[i]) {
                    if (cfg->GeoIPEnableUTF8) {
                        GeoIP_set_charset(cfg->gips[i], GEOIP_CHARSET_UTF8);
                    }
                } else {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0,
                                 s,
                                 "[mod_geoip]: Error while opening data file %s",
                                 cfg->GeoIPFilenames[i]);
                    continue;
                }
            }
        } else {
            cfg->gips = malloc(sizeof(GeoIP *));
            cfg->gips[0] = GeoIP_new(GEOIP_STANDARD);
            if (!cfg->gips[0]) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                             "[mod_geoip]: Error while opening data file");
            }
            cfg->numGeoIPFiles = 1;
        }
    }

    apr_pool_cleanup_register(p, (void *)cfg, geoip_cleanup, geoip_cleanup);

}

static void geoip_child_init(apr_pool_t * p, server_rec * s)
{
    geoip_server_config_rec *cfg;
    int i, flags;

    cfg = (geoip_server_config_rec *)
        ap_get_module_config(s->module_config, &geoip_module);

    if (cfg->gips) {
        if (cfg->GeoIPFilenames != NULL) {
            for (i = 0; i < cfg->numGeoIPFiles; i++) {
                flags =
                    (cfg->GeoIPFlags2[i] ==
                     GEOIP_UNKNOWN) ? cfg->GeoIPFlags : cfg->GeoIPFlags2[i];
                if (flags & (GEOIP_MEMORY_CACHE | GEOIP_MMAP_CACHE))
                    continue;
                if (cfg->gips[i]) {
                    GeoIP_delete(cfg->gips[i]);
                }
                cfg->gips[i] = GeoIP_open(cfg->GeoIPFilenames[i], flags);

                if (cfg->gips[i]) {
                    if (cfg->GeoIPEnableUTF8) {
                        GeoIP_set_charset(cfg->gips[i], GEOIP_CHARSET_UTF8);
                    }
                } else {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0,
                                 s,
                                 "[mod_geoip]: Error while opening data file %s",
                                 cfg->GeoIPFilenames[i]);
                    continue;
                }
            }
        } else {
            if (cfg->gips[0])
                GeoIP_delete(cfg->gips[0]);
            cfg->gips[0] = GeoIP_new(GEOIP_STANDARD);
            if (!cfg->gips[0]) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                             "[mod_geoip]: Error while opening data file");
            }
            cfg->numGeoIPFiles = 1;
        }
    }
}

/* map into the first apache */
static int
geoip_post_config(apr_pool_t * p, apr_pool_t * plog,
                  apr_pool_t * ptemp, server_rec * s)
{

    geoip_server_init(p, s);
    return OK;
}

static int geoip_header_parser(request_rec * r);

static int geoip_post_read_request(request_rec * r)
{
    geoip_server_config_rec *cfg;
    cfg = ap_get_module_config(r->server->module_config, &geoip_module);

    if (!cfg)
        return DECLINED;

    if (!cfg->GeoIPEnabled)
        return DECLINED;

    return geoip_header_parser(r);
}

static int geoip_per_dir(request_rec * r)
{

    geoip_dir_config_rec *dcfg;

    geoip_server_config_rec *cfg =
        ap_get_module_config(r->server->module_config, &geoip_module);
    if (cfg && cfg->GeoIPEnabled)
        return DECLINED;

    dcfg = ap_get_module_config(r->per_dir_config, &geoip_module);
    if (!dcfg)
        return DECLINED;

    if (!dcfg->GeoIPEnabled)
        return DECLINED;

    return geoip_header_parser(r);
}

char *_get_client_ip(request_rec * r)
{
# if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER == 4
    return r->useragent_ip;
# else
    return r->connection->remote_ip;
#endif
}

static void set_geoip_output(geoip_server_config_rec * cfg, request_rec * r,
                             const char *key, const char *value)
{
    if (value) {
        if (cfg->GeoIPOutput & GEOIP_NOTES) {
            apr_table_set(r->notes, key, value);
        }
        if (cfg->GeoIPOutput & GEOIP_ENV) {
            apr_table_set(r->subprocess_env, value, key);
        }
    }
}

static void setn_geoip_output(geoip_server_config_rec * cfg, request_rec * r,
                              const char *key, const char *value)
{
    if (value) {
        if (cfg->GeoIPOutput & GEOIP_NOTES) {
            apr_table_setn(r->notes, key, value);
        }
        if (cfg->GeoIPOutput & GEOIP_ENV) {
            apr_table_setn(r->subprocess_env, value, key);
        }
    }
}

static int geoip_header_parser(request_rec * r)
{
    char *orgorisp;
    char *ipaddr;
    char *free_me = NULL;
    short int country_id;
    const char *continent_code;
    const char *country_code;
    const char *country_name;
    const char *region_name;

    geoip_server_config_rec *cfg;

    unsigned char databaseType;
    GeoIPRecord *gir;
    GeoIPRegion *giregion;
    int i;
    int netspeed;
    /* For splitting proxy headers */
    char *ipaddr_ptr = NULL;
    char *comma_ptr;
    cfg = ap_get_module_config(r->server->module_config, &geoip_module);

    if (!cfg)
        return DECLINED;

    if (!cfg->scanProxyHeaders) {
        ipaddr = _get_client_ip(r);
    } else {
        ap_add_common_vars(r);
        if (apr_table_get(r->subprocess_env, "HTTP_CLIENT_IP")) {
            ipaddr_ptr =
                (char *)apr_table_get(r->subprocess_env, "HTTP_CLIENT_IP");
        } else if (apr_table_get(r->subprocess_env, "HTTP_X_FORWARDED_FOR")) {
            ipaddr_ptr =
                (char *)apr_table_get(r->subprocess_env,
                                      "HTTP_X_FORWARDED_FOR");
        } else if (apr_table_get(r->headers_in, "X-Forwarded-For")) {
            ipaddr_ptr =
                (char *)apr_table_get(r->headers_in, "X-Forwarded-For");
        } else if (apr_table_get(r->subprocess_env, "HTTP_REMOTE_ADDR")) {
            ipaddr_ptr =
                (char *)apr_table_get(r->subprocess_env, "HTTP_REMOTE_ADDR");
        }
        if (!ipaddr_ptr) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0,
                         r->server,
                         "[mod_geoip]: Error while getting ipaddr from proxy headers. Using REMOTE_ADDR.");
            ipaddr = _get_client_ip(r);
        } else {
            /* Found XFF like header */
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0,
                         r->server, "[mod_geoip]: IPADDR_PTR: %s", ipaddr_ptr);

            if (cfg->proxyHeaderMode ==
                GEOIP_PROXY_HEADER_MODE_FIRST_NON_PRIVATE_IP) {
                ipaddr = free_me = _get_ip_from_xff(ipaddr_ptr);
                if (!ipaddr)
                    ipaddr = _get_client_ip(r);
            } else {
                ipaddr = free_me = (char *)calloc(8 * 4 + 7 + 1, sizeof(char));
                /* proxyHeaderMode is
                 * GEOIP_PROXY_HEADER_MODE_LAST_IP or GEOIP_PROXY_HEADER_MODE_FIRST_IP
                 */

                /*
                 * Check to ensure that the HTTP_CLIENT_IP or
                 * X-Forwarded-For header is not a comma separated
                 * list of addresses, which would cause mod_geoip to
                 * return no country code. If the header is a comma
                 * separated list, return the first IP address in the
                 * list, which is (hopefully!) the real client IP.
                 */

                if (cfg->proxyHeaderMode == GEOIP_PROXY_HEADER_MODE_LAST_IP) {
                    comma_ptr = strrchr(ipaddr_ptr, ',');
                    if (comma_ptr) {
                        /* skip over whitespace */
                        ipaddr_ptr = comma_ptr + strspn(comma_ptr, ", \t");
                    }
                }

                strncpy(ipaddr, ipaddr_ptr, 8 * 4 + 7);
                comma_ptr = strchr(ipaddr, ',');
                if (comma_ptr != 0)
                    *comma_ptr = '\0';
            }
        }
    }

/* this block should be removed! */
#if 1
    if (!cfg->gips) {
        if (cfg->GeoIPFilenames != NULL) {
            cfg->gips = malloc(sizeof(GeoIP *) * cfg->numGeoIPFiles);
            for (i = 0; i < cfg->numGeoIPFiles; i++) {
                cfg->gips[i] =
                    GeoIP_open(cfg->GeoIPFilenames[i],
                               (cfg->GeoIPFlags2[i] ==
                                GEOIP_UNKNOWN) ? cfg->GeoIPFlags
                               : cfg->GeoIPFlags2[i]);

                if (cfg->gips[i]) {
                    if (cfg->GeoIPEnableUTF8) {
                        GeoIP_set_charset(cfg->gips[i], GEOIP_CHARSET_UTF8);
                    }
                } else {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0,
                                 r->server,
                                 "[mod_geoip]: Error while opening data file %s",
                                 cfg->GeoIPFilenames[i]);
                    return DECLINED;
                }
            }
        } else {
            cfg->gips = malloc(sizeof(GeoIP *));
            cfg->gips[0] = GeoIP_new(GEOIP_STANDARD);
            if (!cfg->gips[0]) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0,
                             r->server,
                             "[mod_geoip]: Error while opening data file");
                return DECLINED;
            }
            cfg->numGeoIPFiles = 1;
        }
    }
#endif

    set_geoip_output(cfg, r, "GEOIP_ADDR", ipaddr);

    for (i = 0; i < cfg->numGeoIPFiles; i++) {

        /*
         * skip database handles that can not be opned for some
         * reason
         */
        if (cfg->gips[i] == NULL)
            continue;

        databaseType = cfg->gips[i] ? GeoIP_database_edition(cfg->gips[i]) : -1;        /* -1 is "magic value"
                                                                                         * in case file not
                                                                                         * found */
        switch (databaseType) {
        case GEOIP_NETSPEED_EDITION_REV1:
            orgorisp = GeoIP_name_by_addr(cfg->gips[i], ipaddr);
            setn_geoip_output(cfg, r, "GEOIP_NETSPEED", orgorisp);
            break;

        case GEOIP_NETSPEED_EDITION:
            netspeed = GeoIP_id_by_addr(cfg->gips[i], ipaddr);
            if (netspeed == GEOIP_UNKNOWN_SPEED) {
                netspeedstring = "unknown";
            } else if (netspeed == GEOIP_DIALUP_SPEED) {
                netspeedstring = "dialup";
            } else if (netspeed == GEOIP_CABLEDSL_SPEED) {
                netspeedstring = "cabledsl";
            } else if (netspeed == GEOIP_CORPORATE_SPEED) {
                netspeedstring = "corporate";
            }
            setn_geoip_output(cfg, r, "GEOIP_NETSPEED", netspeedstring);
            break;
        case GEOIP_COUNTRY_EDITION_V6:
            /* Get the Country ID */
            country_id = GeoIP_id_by_addr_v6(cfg->gips[i], ipaddr);

            if (country_id > 0) {
                /* Lookup the Code and the Name with the ID */
                continent_code = GeoIP_country_continent[country_id];
                country_code = GeoIP_country_code[country_id];
                country_name = GeoIP_country_name[country_id];

                if (cfg->numGeoIPFiles == 0) {
                    cfg->numGeoIPFiles = 0;
                }
                if (cfg->GeoIPFilenames == 0) {
                    cfg->GeoIPFilenames = 0;
                }
                /* Set it for our user */
                setn_geoip_output(cfg, r, "GEOIP_CONTINENT_CODE_V6",
                                  continent_code);
                setn_geoip_output(cfg, r, "GEOIP_COUNTRY_CODE_V6",
                                  country_code);
                setn_geoip_output(cfg, r, "GEOIP_COUNTRY_NAME_V6",
                                  country_name);
            }
            break;
        case GEOIP_COUNTRY_EDITION:
            /* Get the Country ID */
            country_id = GeoIP_country_id_by_addr(cfg->gips[i], ipaddr);

            if (country_id > 0) {
                /* Lookup the Code and the Name with the ID */
                continent_code = GeoIP_country_continent[country_id];
                country_code = GeoIP_country_code[country_id];
                country_name = GeoIP_country_name[country_id];

                if (cfg->numGeoIPFiles == 0) {
                    cfg->numGeoIPFiles = 0;
                }
                if (cfg->GeoIPFilenames == 0) {
                    cfg->GeoIPFilenames = 0;
                }
                /* Set it for our user */
                setn_geoip_output(cfg, r, "GEOIP_CONTINENT_CODE",
                                  continent_code);
                setn_geoip_output(cfg, r, "GEOIP_COUNTRY_CODE", country_code);
                setn_geoip_output(cfg, r, "GEOIP_COUNTRY_NAME", country_name);
            }

            break;
        case GEOIP_REGION_EDITION_REV0:
        case GEOIP_REGION_EDITION_REV1:
            giregion = GeoIP_region_by_name(cfg->gips[i], ipaddr);
            if (giregion != NULL) {
                region_name = NULL;
                if (giregion->country_code[0]) {
                    region_name =
                        GeoIP_region_name_by_code
                        (giregion->country_code, giregion->region);
                    setn_geoip_output(cfg, r, "GEOIP_COUNTRY_CODE",
                                      giregion->country_code);
                    country_id = GeoIP_id_by_code(giregion->country_code);
                    setn_geoip_output(cfg, r, "GEOIP_COUNTRY_NAME",
                                      GeoIP_country_name[country_id]);
                    setn_geoip_output(cfg, r, "GEOIP_CONTINENT_CODE",
                                      GeoIP_country_continent[country_id]);
                }
                if (giregion->region[0]) {
                    setn_geoip_output(cfg, r, "GEOIP_REGION", giregion->region);
                }
                setn_geoip_output(cfg, r, "GEOIP_REGION_NAME", region_name);
                if (region_name != NULL) {
                    apr_table_set(r->notes, "GEOIP_REGION_NAME", region_name);
                }
                GeoIPRegion_delete(giregion);
            }
            break;
        case GEOIP_CITY_EDITION_REV0_V6:
        case GEOIP_CITY_EDITION_REV1_V6:
            gir = GeoIP_record_by_addr_v6(cfg->gips[i], ipaddr);
            if (gir != NULL) {
                if (gir->country_code != NULL) {
                    region_name =
                        GeoIP_region_name_by_code(gir->country_code,
                                                  gir->region);
                }
                sprintf(metrocodestr, "%d", gir->dma_code);
                sprintf(areacodestr, "%d", gir->area_code);
                setn_geoip_output(cfg, r, "GEOIP_CONTINENT_CODE_V6",
                                  gir->continent_code);
                setn_geoip_output(cfg, r, "GEOIP_COUNTRY_CODE_V6",
                                  gir->country_code);
                setn_geoip_output(cfg, r, "GEOIP_COUNTRY_NAME_V6",
                                  gir->country_name);
                setn_geoip_output(cfg, r, "GEOIP_REGION_V6", gir->region);
                setn_geoip_output(cfg, r, "GEOIP_REGION_NAME_V6", region_name);
                setn_geoip_output(cfg, r, "GEOIP_CITY_V6", gir->city);
                set_geoip_output(cfg, r, "GEOIP_DMA_CODE_V6", metrocodestr);
                set_geoip_output(cfg, r, "GEOIP_METRO_CODE_V6", metrocodestr);
                set_geoip_output(cfg, r, "GEOIP_AREA_CODE_V6", areacodestr);
                sprintf(latstr, "%f", gir->latitude);
                sprintf(lonstr, "%f", gir->longitude);
                set_geoip_output(cfg, r, "GEOIP_LATITUDE_V6", latstr);
                set_geoip_output(cfg, r, "GEOIP_LONGITUDE_V6", lonstr);

                setn_geoip_output(cfg, r, "GEOIP_POSTAL_CODE_V6",
                                  gir->postal_code);
                setn_geoip_output(cfg, r, "GEOIP_POSTAL_CODE_V6",
                                  gir->postal_code);
                GeoIPRecord_delete(gir);
            }

            break;
        case GEOIP_CITY_EDITION_REV0:
        case GEOIP_CITY_EDITION_REV1:
            gir = GeoIP_record_by_addr(cfg->gips[i], ipaddr);
            if (gir != NULL) {
                if (gir->country_code != NULL) {
                    region_name =
                        GeoIP_region_name_by_code(gir->country_code,
                                                  gir->region);
                }
                sprintf(metrocodestr, "%d", gir->dma_code);
                sprintf(areacodestr, "%d", gir->area_code);
                setn_geoip_output(cfg, r, "GEOIP_CONTINENT_CODE",
                                  gir->continent_code);
                setn_geoip_output(cfg, r, "GEOIP_COUNTRY_CODE",
                                  gir->country_code);
                setn_geoip_output(cfg, r, "GEOIP_COUNTRY_NAME",
                                  gir->country_name);
                setn_geoip_output(cfg, r, "GEOIP_REGION", gir->region);
                setn_geoip_output(cfg, r, "GEOIP_REGION_NAME", region_name);
                setn_geoip_output(cfg, r, "GEOIP_CITY", gir->city);
                set_geoip_output(cfg, r, "GEOIP_DMA_CODE", metrocodestr);
                set_geoip_output(cfg, r, "GEOIP_METRO_CODE", metrocodestr);
                set_geoip_output(cfg, r, "GEOIP_AREA_CODE", areacodestr);
                sprintf(latstr, "%f", gir->latitude);
                sprintf(lonstr, "%f", gir->longitude);
                set_geoip_output(cfg, r, "GEOIP_LATITUDE", latstr);
                set_geoip_output(cfg, r, "GEOIP_LONGITUDE", lonstr);
                setn_geoip_output(cfg, r, "GEOIP_POSTAL_CODE",
                                  gir->postal_code);
                GeoIPRecord_delete(gir);
            }

            break;
        case GEOIP_ORG_EDITION:
            orgorisp = GeoIP_name_by_addr(cfg->gips[i], ipaddr);
            setn_geoip_output(cfg, r, "GEOIP_ORGANIZATION", orgorisp);
            break;
        case GEOIP_ISP_EDITION:
            orgorisp = GeoIP_name_by_addr(cfg->gips[i], ipaddr);
            setn_geoip_output(cfg, r, "GEOIP_ISP", orgorisp);
            break;
        case GEOIP_DOMAIN_EDITION:
            orgorisp = GeoIP_name_by_addr(cfg->gips[i], ipaddr);
            setn_geoip_output(cfg, r, "GEOIP_DOMAIN", orgorisp);
            break;
        }
    }

    if (free_me)
        free(free_me);
    return OK;
}

static const char *geoip_use_first_non_private_x_forwarded_for_ip(cmd_parms *
                                                                  cmd,
                                                                  void *dummy,
                                                                  int arg)
{
    geoip_server_config_rec *conf = (geoip_server_config_rec *)
        ap_get_module_config(cmd->server->module_config, &geoip_module);

    if (!conf)
        return "mod_geoip: server structure not allocated";

    conf->proxyHeaderMode =
        arg ? GEOIP_PROXY_HEADER_MODE_FIRST_NON_PRIVATE_IP :
        GEOIP_PROXY_HEADER_MODE_DEFAULT;
    return NULL;
}

static const char *geoip_use_first_x_forwarded_for_ip(cmd_parms * cmd,
                                                      void *dummy, int arg)
{
    geoip_server_config_rec *conf = (geoip_server_config_rec *)
        ap_get_module_config(cmd->server->module_config, &geoip_module);

    if (!conf)
        return "mod_geoip: server structure not allocated";

    conf->proxyHeaderMode =
        arg ? GEOIP_PROXY_HEADER_MODE_FIRST_IP :
        GEOIP_PROXY_HEADER_MODE_DEFAULT;
    return NULL;
}

static const char *geoip_use_last_x_forwarded_for_ip(cmd_parms * cmd,
                                                     void *dummy, int arg)
{
    geoip_server_config_rec *conf = (geoip_server_config_rec *)
        ap_get_module_config(cmd->server->module_config, &geoip_module);

    if (!conf)
        return "mod_geoip: server structure not allocated";

    conf->proxyHeaderMode =
        arg ? GEOIP_PROXY_HEADER_MODE_LAST_IP : GEOIP_PROXY_HEADER_MODE_DEFAULT;
    return NULL;
}

static const char *geoip_scanproxy(cmd_parms * cmd, void *dummy, int arg)
{
    geoip_server_config_rec *conf = (geoip_server_config_rec *)
        ap_get_module_config(cmd->server->module_config, &geoip_module);

    if (!conf)
        return "mod_geoip: server structure not allocated";

    conf->scanProxyHeaders = arg;
    return NULL;
}

static const char *set_geoip_enable(cmd_parms * cmd, void *dummy, int arg)
{
    geoip_server_config_rec *conf;

    /* is per directory config? */
    if (cmd->path) {
        geoip_dir_config_rec *dcfg = dummy;
        dcfg->GeoIPEnabled = arg;
        return NULL;
    }
    /* no then it is server config */
    conf = (geoip_server_config_rec *)
        ap_get_module_config(cmd->server->module_config, &geoip_module);

    if (!conf)
        return "mod_geoip: server structure not allocated";

    conf->GeoIPEnabled = arg;
    return NULL;
}

static const char *set_geoip_enable_utf8(cmd_parms * cmd, void *dummy, int arg)
{
    geoip_server_config_rec *conf = (geoip_server_config_rec *)
        ap_get_module_config(cmd->server->module_config, &geoip_module);

    if (!conf)
        return "mod_geoip: server structure not allocated";

    conf->GeoIPEnableUTF8 = arg;
    return NULL;
}

static const char *set_geoip_filename(cmd_parms * cmd, void *dummy,
                                      const char *filename, const char *arg2)
{
    int i;
    geoip_server_config_rec *conf = (geoip_server_config_rec *)
        ap_get_module_config(cmd->server->module_config, &geoip_module);

    if (!filename)
        return NULL;

    i = conf->numGeoIPFiles;
    conf->numGeoIPFiles++;
    conf->GeoIPFilenames =
        realloc(conf->GeoIPFilenames, conf->numGeoIPFiles * sizeof(char *));
    conf->GeoIPFilenames[i] = (char *)apr_pstrdup(cmd->pool, filename);
    conf->GeoIPFlags2 =
        realloc(conf->GeoIPFlags2, conf->numGeoIPFiles * sizeof(int));
    if (arg2 == NULL) {
        conf->GeoIPFlags2[i] = GEOIP_UNKNOWN;
    } else if (!strcmp(arg2, "Standard")) {
        conf->GeoIPFlags2[i] = GEOIP_STANDARD;
    } else if (!strcmp(arg2, "MemoryCache")) {
        conf->GeoIPFlags2[i] = GEOIP_MEMORY_CACHE;
    } else if (!strcmp(arg2, "CheckCache")) {
        conf->GeoIPFlags2[i] = GEOIP_CHECK_CACHE;
    } else if (!strcmp(arg2, "IndexCache")) {
        conf->GeoIPFlags2[i] = GEOIP_INDEX_CACHE;
    } else if (!strcmp(arg2, "MMapCache")) {
        conf->GeoIPFlags2[i] = GEOIP_MMAP_CACHE;
    }
    return NULL;
}

static const char *set_geoip_output_mode(cmd_parms * cmd, void *dummy,
                                         const char *arg)
{
    geoip_server_config_rec *cfg =
        (geoip_server_config_rec *) ap_get_module_config(cmd->
                                                         server->module_config,
                                                         &geoip_module);

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

static void *make_geoip(apr_pool_t * p, server_rec * d)
{
    geoip_server_config_rec *dcfg;

    dcfg =
        (geoip_server_config_rec *) apr_pcalloc(p,
                                                sizeof
                                                (geoip_server_config_rec));
    dcfg->gips = NULL;
    dcfg->numGeoIPFiles = 0;
    dcfg->GeoIPFilenames = NULL;
    dcfg->GeoIPEnabled = 0;
    dcfg->GeoIPEnableUTF8 = 0;
    dcfg->GeoIPOutput = GEOIP_INIT;
    dcfg->GeoIPFlags = GEOIP_STANDARD;
    dcfg->GeoIPFlags2 = NULL;
    return dcfg;
}

static const command_rec geoip_cmds[] = {
    AP_INIT_FLAG("GeoIPScanProxyHeaders", geoip_scanproxy, NULL, RSRC_CONF,
                 "Get IP from HTTP_CLIENT IP or X-Forwarded-For"),
    AP_INIT_FLAG("GeoIPUseFirstNonPrivateXForwardedForIP",
                 geoip_use_first_non_private_x_forwarded_for_ip, NULL,
                 RSRC_CONF,
                 "For more IP's in X-Forwarded-For, use the first non private IP"),
    AP_INIT_FLAG("GeoIPUseFirstXForwardedForIP",
                 geoip_use_first_x_forwarded_for_ip, NULL, RSRC_CONF,
                 "For more IP's in X-Forwarded-For, use the first"),
    AP_INIT_FLAG("GeoIPUseLastXForwardedForIP",
                 geoip_use_last_x_forwarded_for_ip, NULL, RSRC_CONF,
                 "For more IP's in X-Forwarded-For, use the last"),
    AP_INIT_FLAG("GeoIPEnable", set_geoip_enable, NULL,
                 RSRC_CONF | OR_FILEINFO, "Turn on mod_geoip"),
    AP_INIT_FLAG("GeoIPEnableUTF8", set_geoip_enable_utf8, NULL, RSRC_CONF,
                 "Turn on utf8 characters for city names"),
    AP_INIT_TAKE12("GeoIPDBFile", set_geoip_filename, NULL, RSRC_CONF,
                   "Path to GeoIP Data File"),
    AP_INIT_ITERATE("GeoIPOutput", set_geoip_output_mode, NULL, RSRC_CONF,
                    "Specify output method(s)"),
    {NULL}
};

static void geoip_register_hooks(apr_pool_t * p)
{
    /* make sure we run before mod_rewrite's handler */
    static const char *const aszSucc[] =
        { "mod_setenvif.c", "mod_rewrite.c", NULL };

    /* we have two entry points, the header_parser hook, right before
     * the authentication hook used for Dirctory specific enabled geoiplookups
     * or right before directory rewrite rules.
     */
    ap_hook_header_parser(geoip_per_dir, NULL, aszSucc, APR_HOOK_FIRST);

    /* and the servectly wide hook, after reading the request. Perfecly
     * suitable to serve serverwide mod_rewrite actions
     */
    ap_hook_post_read_request(geoip_post_read_request, NULL, aszSucc,
                              APR_HOOK_MIDDLE);

    /* setup our childs GeoIP database once for every child */
    ap_hook_child_init(geoip_child_init, NULL, NULL, APR_HOOK_MIDDLE);

    /* static const char * const list[]={ "mod_geoip.c", NULL }; */
    /* mmap the database(s) into the master process */
    ap_hook_post_config(geoip_post_config, NULL, NULL, APR_HOOK_MIDDLE);

}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA geoip_module = {
    STANDARD20_MODULE_STUFF,
    geoip_create_dir_config,    /* create per-dir    config structures */
    NULL,                       /* merge  per-dir    config structures */
    make_geoip,                 /* create per-server config structures */
    NULL,                       /* merge  per-server config structures */
    geoip_cmds,                 /* table of config file commands       */
    geoip_register_hooks        /* register hooks                      */
};
