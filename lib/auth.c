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


static int mapcache_auth_command_line(mapcache_context *ctx, mapcache_tileset *tileset, mapcache_auth_method *auth_method, char *user);

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
      char *user = apr_table_get(headers, auth_method->user_header);
      char *mc_key;

      if (!user) {
        ctx->set_error(ctx, 403, "Required user-header field '%s' not set.", auth_method->user_header);
        return;
      }


      /* get a cache auth result */
      /*if (auth_method->memcache) {
        char *data;
        apr_size_t size;
        apr_status_t mc_status;

        mc_key = apr_pmalloc(ctx->pool, sizeof("auth//") + strlen(user) + strlen(tileset->name));
        snprintf(key, strlen(mc_key), "auth/%s/%s", tileset->name, user);
        mc_status = apr_memcache_getp(auth_method->memcache, ctx->pool, key, &data, &size, 0):

        if (mc_status == APR_SUCCESS && data != NULL && strncmp(data, "TRUE", 4) == 0) {
          continue;
        }
        else if (mc_status == APR_SUCCESS && data != NULL && strncmp(data, "FALSE", 5) == 0) {
          ctx->set_error(ctx, 403, "Authorization failed.");
          return;
        }
      }*/

      /* PDP invocation methods*/
      if (auth_method->type == MAPCACHE_AUTH_METHOD_COMMAND) {
        status = mapcache_auth_command_line(ctx, tileset, auth_method, user);
      }
      /* TODO: other auth methods */

      if (status == MAPCACHE_FAILURE) {
        ctx->set_error(ctx, 403, "Authorization failed.");
      }

      /* store the result in the auth cache */
      /*if (auth_method->memcache) {
        char *value = (status ? "TRUE" : "FALSE");
        apr_memcache_set(auth_method->memcache, mc_key, value, strlen(value), auth_method->memcache_timeout, 0):
      }*/
    }
  }
}


static int mapcache_auth_command_line(mapcache_context *ctx, mapcache_tileset *tileset, mapcache_auth_method *auth_method, char *user) {
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
  return auth_method_cmd;
}
