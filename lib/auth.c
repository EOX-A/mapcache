/******************************************************************************
 * $Id$
 *
 * Project:  MapServer
 * Purpose:  Authorization
 * Author:   Thomas Bonfort and the MapServer team.
 *
 ******************************************************************************
 * Copyright (c) 1996-2011 Regents of the University of Minnesota.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies of this Software or works derived from this Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *****************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "mapcache.h"


static int mapcache_auth_command_line(mapcache_context *ctx, mapcache_tileset *tileset, mapcache_auth_method *auth_method, const char *user);

#if USE_MEMCACHE

mapcache_auth_cache_lookup_type mapcache_autch_cache_memcache_lookup(mapcache_context *ctx, mapcache_auth_cache *auth_cache, mapcache_tileset *tileset, const char *user);
void mapcache_autch_cache_memcache_store(mapcache_context *ctx, mapcache_auth_cache *auth_cache, mapcache_tileset *tileset, const char *user, int value);

#endif /* USE_MEMCACHE */


void mapcache_authorization(mapcache_context *ctx, mapcache_cfg *config, mapcache_request *request, apr_table_t *headers) {
  int ntilesets = 0, i;
  mapcache_tileset **tilesets = NULL;

  /* TODO: implement
  if (!config->use_auth) return;*/

  switch(request->type) {
    case MAPCACHE_REQUEST_GET_CAPABILITIES:
      /* capabilities not tied to a tileset, therefore no auth */
      break;

    case MAPCACHE_REQUEST_GET_TILE: {
      int i;
      mapcache_request_get_tile *request_get_tile = (mapcache_request_get_tile*)request;
      ntilesets = request_get_tile->ntiles;
      tilesets = apr_pcalloc(ctx->pool, ntilesets * sizeof(mapcache_tileset*));
      for(i=0; i < ntilesets; ++i) {
        tilesets[i] = request_get_tile->tiles[i]->tileset;
      }
      break;
    }
    case MAPCACHE_REQUEST_GET_MAP: {
      int i;
      mapcache_request_get_map *request_get_map = (mapcache_request_get_map*)request;
      ntilesets = request_get_map->nmaps;
      tilesets = apr_pcalloc(ctx->pool, ntilesets * sizeof(mapcache_tileset*));
      for(i=0; i < ntilesets; ++i) {
        tilesets[i] = request_get_map->maps[i]->tileset;
      }
      break;
    }
    case MAPCACHE_REQUEST_GET_FEATUREINFO: {
      /**/
    }
    default:
      ctx->set_error(ctx,500,"###BUG### unknown request type");
      return;
  }

  for (i=0; i < ntilesets; ++i) {
    mapcache_tileset *tileset = tilesets[i];

    /* an error was already set, so quit */
    if (GC_HAS_ERROR(ctx)) {
      return;
    }

    if (tileset->auth_method) {
      /* actually invoke the auth method */
      int status = MAPCACHE_FAILURE;
      mapcache_auth_method *auth_method = tileset->auth_method;
      const char *user = apr_table_get(headers, auth_method->user_header);
      /*char *mc_key;*/

      if (!user) {
        ctx->set_error(ctx, 403, "Required user-header field '%s' not set.", auth_method->user_header);
        return;
      }


      if (auth_method->auth_cache) {
        mapcache_auth_cache_lookup_type lookup;
        lookup = auth_method->auth_cache->lookup_func(ctx, auth_method->auth_cache, tileset, user);
        if (lookup == MAPCACHE_AUTH_CACHE_AUTHORIZED) {
          continue;
        }
        else if(lookup == MAPCACHE_AUTH_CACHE_NOT_AUTHORIZED) {
          ctx->set_error(ctx, 403, "Authorization failed.");
          return;
        }
      }

      /* PDP invocation methods*/
      if (auth_method->type == MAPCACHE_AUTH_METHOD_COMMAND) {
        status = mapcache_auth_command_line(ctx, tileset, auth_method, user);
      }
      /* TODO: other auth methods */

      if (status == MAPCACHE_FAILURE) {
        ctx->set_error(ctx, 403, "Authorization failed.");
      }

      if (auth_method->auth_cache) {
        auth_method->auth_cache->store_func(ctx, auth_method->auth_cache, tileset, user, status);
      }
    }
  }
}


static int mapcache_auth_command_line(mapcache_context *ctx, mapcache_tileset *tileset, mapcache_auth_method *auth_method, const char *user) {
  mapcache_auth_method_cmd *auth_method_cmd = (mapcache_auth_method_cmd*)auth_method;
  
  char * command = auth_method_cmd->template;

  command = mapcache_util_str_replace(ctx->pool, command, ":tileset", tileset->name);
  command = mapcache_util_str_replace(ctx->pool, command, ":user", user);

  int ret_val = system(command);

  if (ret_val != 0) {
    /* Error code translation? */
    return MAPCACHE_FAILURE;
  }
  return MAPCACHE_SUCCESS;
}


mapcache_auth_method *mapcache_auth_method_command_line_create(mapcache_context *ctx) {
  mapcache_auth_method_cmd *auth_method_cmd = apr_pcalloc(ctx->pool, sizeof(mapcache_auth_method_cmd));
  auth_method_cmd->auth_method.type = MAPCACHE_AUTH_METHOD_COMMAND;
  return (mapcache_auth_method *)auth_method_cmd;
}

#if USE_MEMCACHE

mapcache_auth_cache *mapcache_auth_cache_memcache_create(mapcache_context *ctx, ezxml_t node) {
  ezxml_t cur_node;
  int servercount = 0;

  mapcache_auth_cache_memcache *auth_cache =  apr_pcalloc(ctx->pool, sizeof(mapcache_auth_cache_memcache));
  auth_cache->auth_cache.type = MAPCACHE_AUTH_CACHE_MEMCACHE;
  auth_cache->auth_cache.lookup_func = mapcache_autch_cache_memcache_lookup;
  auth_cache->auth_cache.store_func = mapcache_autch_cache_memcache_store;

  if ((cur_node = ezxml_child(node,"expires")) == NULL || !cur_node->txt) {
    ctx->set_error(ctx,400,"memcache auth cache has no <expires>s configured");
    return NULL;
  }
  else {
    char *endptr;
    auth_cache->auth_cache.expires = (int)strtol(cur_node->txt,&endptr,10);
    if(*endptr != 0) {
      ctx->set_error(ctx,400,"failed to parse value %s for memcache auth cache", cur_node->txt);
      return NULL;
    }
  }

  /* copied from cache_memcache.c */

  for(cur_node = ezxml_child(node,"server"); cur_node; cur_node = cur_node->next) {
    servercount++;
  }
  if(!servercount) {
    ctx->set_error(ctx,400,"memcache auth cache has no <server>s configured");
    return NULL;
  }
  if(APR_SUCCESS != apr_memcache_create(ctx->pool, servercount, 0, &auth_cache->auth_memcache)) {
    ctx->set_error(ctx,400,"auth cache: failed to create memcache backend");
    return NULL;
  }
  for(cur_node = ezxml_child(node,"server"); cur_node; cur_node = cur_node->next) {
    ezxml_t xhost = ezxml_child(cur_node,"host");
    ezxml_t xport = ezxml_child(cur_node,"port");
    const char *host;
    apr_memcache_server_t *server;
    apr_port_t port;
    if(!xhost || !xhost->txt || ! *xhost->txt) {
      ctx->set_error(ctx,400,"auth cache: <server> with no <host>");
      return NULL;
    } else {
      host = apr_pstrdup(ctx->pool,xhost->txt);
    }

    if(!xport || !xport->txt || ! *xport->txt) {
      ctx->set_error(ctx,400,"auth cache: <server> with no <port>");
      return NULL;
    } else {
      char *endptr;
      int iport = (int)strtol(xport->txt,&endptr,10);
      if(*endptr != 0) {
        ctx->set_error(ctx,400,"failed to parse value %s for memcache auth cache", xport->txt);
        return NULL;
      }
      port = iport;
    }
    if(APR_SUCCESS != apr_memcache_server_create(ctx->pool,host,port,4,5,50,10000,&server)) {
      ctx->set_error(ctx,400,"cache: failed to create server %s:%d",host,port);
      return NULL;
    }
    if(APR_SUCCESS != apr_memcache_add_server(auth_cache->auth_memcache,server)) {
      ctx->set_error(ctx,400,"cache: failed to add server %s:%d",host,port);
      return NULL;
    }
    if(APR_SUCCESS != apr_memcache_set(auth_cache->auth_memcache,"mapcache_test_key","mapcache",8,0,0)) {
      ctx->set_error(ctx,400,"cache: failed to add test key to server %s:%d",host,port);
      return NULL;
    }
  }
  return (mapcache_auth_cache *) auth_cache;
}


mapcache_auth_cache_lookup_type mapcache_autch_cache_memcache_lookup(mapcache_context *ctx, mapcache_auth_cache *auth_cache, mapcache_tileset *tileset, const char *user) {
  char *data;
  apr_size_t size = sizeof("auth//") + strlen(user) + strlen(tileset->name);
  apr_status_t status;
  char *key = apr_pcalloc(ctx->pool, size);
  snprintf(key, size, "auth/%s/%s", tileset->name, user);
  status = apr_memcache_getp(((mapcache_auth_cache_memcache*)auth_cache)->auth_memcache, ctx->pool, key, &data, &size, 0);

  if (status == APR_SUCCESS && data != NULL) {
    if (strncmp(data, "TRUE", 4) == 0) {
      return MAPCACHE_AUTH_CACHE_AUTHORIZED;
    }
    else {
      return MAPCACHE_AUTH_CACHE_NOT_AUTHORIZED;
    }
  }
  else {
    return MAPCACHE_AUTH_CACHE_UNKNOWN;
  }
}

void mapcache_autch_cache_memcache_store(mapcache_context *ctx, mapcache_auth_cache *auth_cache, mapcache_tileset *tileset, const char *user, int status) {
  apr_size_t size = sizeof("auth//") + strlen(user) + strlen(tileset->name);
  char *key = apr_pcalloc(ctx->pool, size);
  char *value = ((status) ? "TRUE" : "FALSE");
  apr_memcache_set(((mapcache_auth_cache_memcache *)auth_cache)->auth_memcache, key, value, strlen(value), auth_cache->expires, 0);
}

#endif /* USE_MEMCACHE */