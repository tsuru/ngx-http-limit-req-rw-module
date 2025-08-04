// Copyright 2025 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/**
 * @file ngx_http_limit_req_rw_module.c
 * @brief Implementation of the ngx_http_limit_req_rw_module for NGINX.
 *
 * This module provides read/write access to the shared memory zones used by
 * the ngx_http_limit_req_module for rate limiting. It allows external tools
 * to inspect and modify the state of rate limiting zones via HTTP requests.
 *
 * The module supports GET requests for reading the state of all or specific
 * rate limit zones, and POST requests for updating the state of a zone.
 */

#include <nginx.h>
#include <ngx_conf_file.h>
#include <ngx_config.h>
#include <ngx_log.h>
#include <ngx_string.h>
#include <ngx_times.h>

#include <stdio.h>
#include <time.h>

#include <msgpack.h>

#include "ngx_http_limit_req_rw_module.h"

/**
 * @brief Handler for HTTP requests to read or write rate limit zones.
 *
 * This function determines the type of request (GET or POST) and calls the
 * appropriate handler for reading or writing the rate limit zone state.
 *
 * @param r The HTTP request.
 * @return NGX_OK if the request was handled successfully, or an appropriate
 *         NGINX HTTP error code.
 */
static ngx_int_t ngx_http_limit_req_handler(ngx_http_request_t *r);

/**
 * @brief Deserialize a MessagePack-encoded request body into ngx_zone_data_t.
 *
 * @param r         The HTTP request.
 * @param msg_pack  Pointer to ngx_zone_data_t to populate.
 * @return NGX_OK on success, NGX_HTTP_INTERNAL_SERVER_ERROR on failure.
 */
static ngx_int_t ngx_decode_msg_pack(ngx_http_request_t *r,
                                     ngx_zone_data_t *msg_pack);

/**
 * @brief Handler for HTTP GET requests to read rate limit zone state.
 *
 * @param r The HTTP request.
 * @return NGX_OK or an appropriate NGINX HTTP error code.
 */
static ngx_int_t ngx_http_limit_req_read_handler(ngx_http_request_t *r);

/**
 * @brief Post-handler for HTTP POST requests to write rate limit zone state.
 *
 * @param r The HTTP request.
 */
static void ngx_http_limit_req_write_post_handler(ngx_http_request_t *r);

/**
 * @brief Handler for writing/updating rate limit zone state.
 *
 * @param r The HTTP request.
 * @return NGX_OK or an appropriate NGINX HTTP error code.
 */
static ngx_int_t ngx_http_limit_req_write_handler(ngx_http_request_t *r);

/**
 * @brief Configuration handler for the limit_req_rw_handler directive.
 *
 * @param cf   NGINX configuration context.
 * @param cmd  The command.
 * @param conf Module configuration.
 * @return NGX_CONF_OK or an error string.
 */
static char *ngx_http_limit_req_rw_handler(ngx_conf_t *cf, ngx_command_t *cmd,
                                           void *conf);

/**
 * @brief Extract the zone name from the request URI.
 *
 * @param uri       The request URI.
 * @param zone_name Output parameter for the extracted zone name.
 */
static void strip_zone_name_from_uri(ngx_str_t *uri, ngx_str_t *zone_name);

/**
 * @brief Serialize all rate limit zones into a buffer using MessagePack.
 *
 * @param r The HTTP request.
 * @param b The buffer to write to.
 * @return NGX_OK or an appropriate NGINX HTTP error code.
 */
static ngx_int_t dump_rate_limit_zones(ngx_http_request_t *r, ngx_buf_t *b);

/**
 * @brief Find a rate limit shared memory zone by its name.
 *
 * @param r         The HTTP request.
 * @param zone_name The name of the zone to find.
 * @return Pointer to ngx_shm_zone_t if found, NULL otherwise.
 */
static ngx_shm_zone_t *find_rate_limit_shm_zone_by_name(ngx_http_request_t *r,
                                                        ngx_str_t zone_name);

/**
 * @brief Serialize the state of a specific rate limit zone into a buffer.
 *
 * @param pool                Memory pool for allocations.
 * @param shm_zone            The shared memory zone.
 * @param buf                 The buffer to write to.
 * @param last_greater_equal  Only include entries with 'last' >= this value.
 * @return NGX_OK or an appropriate NGINX HTTP error code.
 */
static ngx_int_t dump_req_limits(ngx_pool_t *pool, ngx_shm_zone_t *shm_zone,
                                 ngx_buf_t *buf, ngx_uint_t last_greater_equal);

/**
 * @brief Module directives for ngx_http_limit_req_rw_module.
 *
 * This array defines the configuration directives accepted by the module.
 * Currently, it includes the "limit_req_rw_handler" directive, which sets up
 * the HTTP handler for read/write access to rate limit zones.
 */
static ngx_command_t ngx_http_limit_req_rw_commands[] = {
    {ngx_string("limit_req_rw_handler"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_NOARGS | NGX_CONF_TAKE1,
     ngx_http_limit_req_rw_handler, 0, 0, NULL},
    ngx_null_command};

/**
 * @brief Module context for ngx_http_limit_req_rw_module.
 *
 * This structure provides callbacks for module initialization and configuration
 * phases. All callbacks are set to NULL as this module does not require custom
 * configuration or initialization steps.
 */
static ngx_http_module_t ngx_http_limit_req_rw_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

/**
 * @brief Module definition for ngx_http_limit_req_rw_module.
 *
 * This structure registers the module with NGINX, providing pointers to the
 * module context, directives, and lifecycle hooks. Most hooks are set to NULL
 * as this module does not require custom initialization or cleanup.
 */
ngx_module_t ngx_http_limit_req_rw_module = {NGX_MODULE_V1,
                                             &ngx_http_limit_req_rw_module_ctx,
                                             ngx_http_limit_req_rw_commands,
                                             NGX_HTTP_MODULE,
                                             NULL,
                                             NULL,
                                             NULL,
                                             NULL,
                                             NULL,
                                             NULL,
                                             NULL,
                                             NGX_MODULE_V1_PADDING};

static ngx_int_t ngx_http_limit_req_handler(ngx_http_request_t *r) {
  if (r->method == NGX_HTTP_GET) {
    return ngx_http_limit_req_read_handler(r);
  }
  if (r->method == NGX_HTTP_POST) {
    r->request_body_in_single_buf = 1;
    return ngx_http_read_client_request_body(
        r, ngx_http_limit_req_write_post_handler);
  }
  return NGX_HTTP_SERVICE_UNAVAILABLE;
}

static ngx_int_t ngx_decode_msg_pack(ngx_http_request_t *r,
                                     ngx_zone_data_t *ngx_zone_data) {
  ngx_chain_t *cl;
  size_t len = 0;
  u_char *data, *p;
  size_t size, deserialized_size;
  msgpack_zone mempool;
  msgpack_object deserialized;
  uint32_t i;

  // Ensure request body is present
  if (r->request_body == NULL || r->request_body->bufs == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "no request body found");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  // Calculate total length of request body
  for (cl = r->request_body->bufs; cl; cl = cl->next) {
    len += cl->buf->last - cl->buf->pos;
  }

  // Allocate buffer for request body data
  data = ngx_pnalloc(r->pool, len);
  if (data == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "failed to allocate memory for request body");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  // Copy request body data into buffer
  p = data;
  for (cl = r->request_body->bufs; cl; cl = cl->next) {
    size = cl->buf->last - cl->buf->pos;
    ngx_memcpy(p, cl->buf->pos, size);
    p += size;
  }

  // Initialize msgpack memory pool
  msgpack_zone_init(&mempool, 2048);

  // Unpack MessagePack data
  msgpack_unpack((char *)data, len, NULL, &mempool, &deserialized);
  ngx_log_error(
      NGX_LOG_DEBUG, r->connection->log, 0,
      "ngx_http_limit_req_rw_module: deserialized type: %d - size: %d",
      deserialized.type, deserialized.via.array.size);
  if (deserialized.type != MSGPACK_OBJECT_ARRAY) {
    msgpack_zone_destroy(&mempool);
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }
  deserialized_size = deserialized.via.array.size;
  if (deserialized_size < 1) {
    msgpack_zone_destroy(&mempool);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "msgpack array must have at least one element (header)");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }
  if (deserialized_size > MAX_NUMBER_OF_RATE_LIMIT_ELEMENTS + 1) {
    msgpack_zone_destroy(&mempool);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "msgpack array too large: %d", (int)deserialized_size);
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }
  msgpack_object *items = deserialized.via.array.ptr;

  // Check header element is an array with at least 3 elements
  if (items[0].type != MSGPACK_OBJECT_ARRAY || items[0].via.array.size < 3) {
    msgpack_zone_destroy(&mempool);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "header element must be array of at least 3 elements");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  // Allocate and populate header structure
  header *hdr = ngx_pnalloc(r->pool, sizeof(header));
  if (hdr == NULL) {
    msgpack_zone_destroy(&mempool);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "failed to allocate memory for header");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  // Parse header from first array element
  msgpack_object hdrKey = items[0].via.array.ptr[0];
  msgpack_object hdrNow = items[0].via.array.ptr[1];
  msgpack_object hdrNowMonotonic = items[0].via.array.ptr[2];

  // Type checks for header fields
  if (hdrKey.type != MSGPACK_OBJECT_STR ||
      hdrNow.type != MSGPACK_OBJECT_POSITIVE_INTEGER ||
      hdrNowMonotonic.type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
    msgpack_zone_destroy(&mempool);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "invalid header types in msgpack");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  hdr->Key.len = hdrKey.via.str.size;
  u_char *keyData = ngx_palloc(r->pool, hdrKey.via.str.size);
  if (keyData == NULL) {
    msgpack_zone_destroy(&mempool);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "failed to allocate memory for key");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }
  ngx_memcpy(keyData, hdrKey.via.str.ptr, hdrKey.via.str.size);
  hdr->Key.data = keyData;
  hdr->Now = hdrNow.via.u64;
  hdr->NowMonotonic = hdrNowMonotonic.via.u64;
  ngx_zone_data->Header = hdr;

  // Allocate array for entities (deserialized_size - 1)
  if (deserialized_size > 1) {
    uint32_t entities_count = deserialized_size - 1;
    entities *arr = ngx_pnalloc(r->pool, entities_count * sizeof(entities));
    if (arr == NULL) {
      msgpack_zone_destroy(&mempool);
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "failed to allocate memory for entities array");
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_zone_data->EntitiesSize = entities_count;
    ngx_zone_data->Entities = arr;

    // Parse each entity from the array (skipping header at index 0)
    for (i = 1; i < deserialized_size; i++) {
      if (items[i].type != MSGPACK_OBJECT_ARRAY ||
          items[i].via.array.size != 3) {
        ngx_zone_data->Entities = NULL;
        ngx_zone_data->EntitiesSize = 0;
        msgpack_zone_destroy(&mempool);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "invalid number of items in array at index %d", i);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
      }

      msgpack_object iItemKey = items[i].via.array.ptr[0];
      msgpack_object iItemLast = items[i].via.array.ptr[1];
      msgpack_object iItemExcess = items[i].via.array.ptr[2];

      // Type checks for entity fields
      if (iItemKey.type != MSGPACK_OBJECT_STR ||
          iItemLast.type != MSGPACK_OBJECT_POSITIVE_INTEGER ||
          iItemExcess.type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        ngx_zone_data->Entities = NULL;
        ngx_zone_data->EntitiesSize = 0;
        msgpack_zone_destroy(&mempool);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "invalid entity types in msgpack at index %d", i);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
      }

      // Allocate and copy key data for entity
      u_char *entityKeyData = ngx_palloc(r->pool, iItemKey.via.str.size);
      if (entityKeyData == NULL) {
        ngx_zone_data->Entities = NULL;
        ngx_zone_data->EntitiesSize = 0;
        msgpack_zone_destroy(&mempool);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "failed to allocate memory for key");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
      }
      ngx_memcpy(entityKeyData, iItemKey.via.str.ptr, iItemKey.via.str.size);

      arr[i - 1].Key.len = iItemKey.via.str.size;
      arr[i - 1].Key.data = entityKeyData;
      arr[i - 1].Last = iItemLast.via.u64;
      arr[i - 1].Excess = iItemExcess.via.u64;
    }
  } else {
    ngx_zone_data->EntitiesSize = 0;
    ngx_zone_data->Entities = NULL;
  }

  // Clean up msgpack memory pool
  msgpack_zone_destroy(&mempool);
  return NGX_OK;
}

static void ngx_http_limit_req_write_post_handler(ngx_http_request_t *r) {
  ngx_int_t rc;

  // Call the write handler to process the POST request body and update the zone
  rc = ngx_http_limit_req_write_handler(r);

  // If the write handler failed, finalize the request with the error code
  if (rc != NGX_OK) {
    ngx_http_finalize_request(r, rc);
    return;
  }

  // Prepare a simple "OK\n" response
  ngx_str_t response = ngx_string("OK\n");
  r->headers_out.status = NGX_HTTP_OK;
  r->headers_out.content_length_n = response.len;
  rc = ngx_http_send_header(r);
  if (rc != NGX_OK) {
    ngx_http_finalize_request(r, rc);
    return;
  }

  // Allocate a buffer for the response body and copy the response text
  ngx_buf_t *b = ngx_create_temp_buf(r->pool, response.len);
  ngx_memcpy(b->pos, response.data, response.len);
  b->last = b->pos + response.len;
  b->last_buf = 1;

  // Send the response body and finalize the request
  ngx_chain_t out = {.buf = b, .next = NULL};
  ngx_http_output_filter(r, &out);
  ngx_http_finalize_request(r, NGX_OK);
}

static ngx_int_t ngx_http_limit_req_write_handler(ngx_http_request_t *r) {
  ngx_int_t rc, found;
  ngx_zone_data_t *msg_pack = NULL;
  ngx_str_t zone_name;
  ngx_shm_zone_t *shm_zone;
  ngx_http_limit_req_ctx_t *ctx;
  ngx_str_t key;
  size_t size;
  uint32_t hash;
  ngx_rbtree_node_t *node, *sentinel;
  ngx_http_limit_req_node_t *lr = NULL;

  if (r != r->main) {
    return NGX_DECLINED;
  }

  msg_pack = ngx_pnalloc(r->pool, sizeof(ngx_zone_data_t));
  if (msg_pack == NULL) {
    ngx_log_error(
        NGX_LOG_ERR, r->connection->log, 0,
        "ngx_http_limit_req_rw_module: failed to allocate memory for msg_pack");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  rc = ngx_decode_msg_pack(r, msg_pack);
  if (rc != NGX_OK) {
    return rc;
  }

  strip_zone_name_from_uri(&r->uri, &zone_name);
  shm_zone = find_rate_limit_shm_zone_by_name(r, zone_name);
  if (shm_zone == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "ngx_http_limit_req_rw_module: rate limit zone %*s not found",
                  zone_name);
    return NGX_HTTP_NOT_FOUND;
  }

  ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                "ngx_http_limit_req_rw_module: Header Key: %*s",
                msg_pack->Header->Key);
  for (uint32_t i = 0; i < msg_pack->EntitiesSize; i++) {
    ctx = shm_zone->data;
    ngx_shmtx_lock(&ctx->shpool->mutex);

    key = msg_pack->Entities[i].Key;

    hash = ngx_crc32_short(key.data, key.len);

    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;

    found = 0;
    while (node != sentinel) {
      if (hash < node->key) {
        node = node->left;
        continue;
      }
      if (hash > node->key) {
        node = node->right;
        continue;
      }

      /* hash == node->key */

      lr = (ngx_http_limit_req_node_t *)&node->color;

      rc = ngx_memn2cmp(key.data, lr->data, key.len, lr->len);

      if (rc == 0) {
        found = 1;
        break;
      }

      node = (rc < 0) ? node->left : node->right;
    }

    if (found) {
      ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                    "ngx_http_limit_req_rw_module: existing node found %ul",
                    lr->excess);
      lr->last = msg_pack->Entities[i].Last;
      lr->excess = msg_pack->Entities[i].Excess;
      ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                    "ngx_http_limit_req_rw_module: existing node updated %ul",
                    lr->excess);
    } else {
      size = offsetof(ngx_rbtree_node_t, color) +
             offsetof(ngx_http_limit_req_node_t, data) + key.len;
      node = ngx_slab_alloc_locked(ctx->shpool, size);
      if (node == NULL) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "failed to allocate memory for rate limit node");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
      }
      node->key = hash;

      lr = (ngx_http_limit_req_node_t *)&node->color;

      lr->len = (u_short)key.len;
      lr->excess = msg_pack->Entities[i].Excess;
      lr->last = msg_pack->Entities[i].Last;
      lr->count = 0;

      ngx_memcpy(lr->data, key.data, key.len);

      ngx_rbtree_insert(&ctx->sh->rbtree, node);

      ngx_queue_insert_head(&ctx->sh->queue, &lr->queue);

      ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                    "ngx_http_limit_req_rw_module: new node excess set to %ul",
                    lr->excess);
    }
    ngx_shmtx_unlock(&ctx->shpool->mutex);
  }
  return NGX_OK;
}

static ngx_int_t ngx_http_limit_req_read_handler(ngx_http_request_t *r) {
  ngx_str_t content_type, zone_name, last_greater_equal_arg;
  ngx_int_t last_greater_equal;
  ngx_int_t rc;
  ngx_buf_t *b;
  ngx_chain_t out;
  ngx_http_core_loc_conf_t *clcf;
  ngx_shm_zone_t *shm_zone;

  clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
  b = ngx_create_temp_buf(r->pool, 1024 * 1024);
  if (b == NULL) {
    ngx_log_error(
        NGX_LOG_ERR, r->connection->log, 0,
        "ngx_http_limit_req_rw_module: failed to create temporary buffer");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  if (clcf == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "ngx_http_limit_req_rw_module: clcf is NULL");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }
  ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                "ngx_http_limit_req_rw_module: request URI: %*s", r->uri);
  ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                "ngx_http_limit_req_rw_module: clcf->name: %*s", clcf->name);
  if (clcf->name.len == r->uri.len) {
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "ngx_http_limit_req_rw_module: dumping rate limit zones");
    rc = dump_rate_limit_zones(r, b);
  } else {
    strip_zone_name_from_uri(&r->uri, &zone_name);
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "zone name: %*s",
                  zone_name);
    last_greater_equal_arg.len = 0;
    last_greater_equal = 0;
    if (r->args.len) {
      if (ngx_http_arg(r, (u_char *)"last_greater_equal", 18,
                       &last_greater_equal_arg) == NGX_OK) {
        last_greater_equal =
            ngx_atoi(last_greater_equal_arg.data, last_greater_equal_arg.len);
        if (last_greater_equal == NGX_ERROR || last_greater_equal < 0) {
          return NGX_HTTP_BAD_REQUEST;
        }
      }
    }
    shm_zone = find_rate_limit_shm_zone_by_name(r, zone_name);
    if (shm_zone == NULL) {
      ngx_log_error(
          NGX_LOG_ERR, r->connection->log, 0,
          "ngx_http_limit_req_rw_module: rate limit zone %*s not found",
          zone_name);
      return NGX_HTTP_NOT_FOUND;
    }
    rc = dump_req_limits(r->pool, shm_zone, b, last_greater_equal);
  }

  if (rc != NGX_OK) {
    return rc;
  }

  ngx_str_set(&content_type, "application/vnd.msgpack");
  r->headers_out.content_type = content_type;
  r->headers_out.content_length_n = b->last - b->pos;
  r->headers_out.status = NGX_HTTP_OK; /* 200 OK */

  b->last_buf = (r == r->main) ? 1 : 0; /* if subrequest 0 else 1 */
  b->last_in_chain = 1;

  out.buf = b;
  out.next = NULL;

  rc = ngx_http_send_header(r);
  if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
    return rc;
  }

  return ngx_http_output_filter(r, &out);
}

static char *ngx_http_limit_req_rw_handler(ngx_conf_t *cf, ngx_command_t *cmd,
                                           void *conf) {
  ngx_http_core_loc_conf_t *clcf;

  clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
  clcf->handler = ngx_http_limit_req_handler;

  return NGX_CONF_OK;
}

static void strip_zone_name_from_uri(ngx_str_t *uri, ngx_str_t *zone_name) {
  zone_name->data = (u_char *)ngx_strlchr(uri->data, uri->data + uri->len, '/');
  zone_name->len = 0;

  if (zone_name->data) {
    zone_name->data =
        (u_char *)(ngx_strlchr(zone_name->data + 1, uri->data + uri->len, '/') +
                   1);
    zone_name->len = uri->len - (zone_name->data - uri->data);
  }
}

static inline int msgpack_ngx_buf_write(void *data, const char *buf,
                                        size_t len) {
  ngx_buf_t *b = (ngx_buf_t *)data;
  b->last = ngx_cpymem(b->last, buf, len);
  return 0;
}

static ngx_int_t dump_rate_limit_zones(ngx_http_request_t *r, ngx_buf_t *buf) {
  ngx_array_t *zones;
  ngx_str_t **zone_name;
  ngx_uint_t i;
  ngx_shm_zone_t *shm_zone;
  volatile ngx_list_part_t *part;

  if (ngx_cycle == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "ngx_http_limit_req_rw_module: ngx_cycle is NULL");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  msgpack_packer pk;
  msgpack_packer_init(&pk, buf, msgpack_ngx_buf_write);
  zones = ngx_array_create(r->pool, 0, sizeof(ngx_str_t *));
  if (zones == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "ngx_http_limit_req_rw_module: failed to create zones array");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  part = &ngx_cycle->shared_memory.part;
  ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                "ngx_http_limit_req_rw_module: part->nelts %d", part->nelts);
  shm_zone = part->elts;

  for (i = 0; /* void */; i++) {

    if (i >= part->nelts) {
      if (part->next == NULL) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                      "ngx_http_limit_req_rw_module: part->next is NULL, "
                      "breaking out of loop");
        break;
      }
      ngx_log_error(
          NGX_LOG_DEBUG, r->connection->log, 0,
          "ngx_http_limit_req_rw_module: part->next is not NULL, advancing");
      part = part->next;
      shm_zone = part->elts;
      i = 0;
      ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                    "ngx_http_limit_req_rw_module: new part->nelts %d",
                    part->nelts);
    }

    if (shm_zone == NULL) {
      ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                    "ngx_http_limit_req_rw_module: shm_zone is NULL, skipping");
      continue;
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "ngx_http_limit_req_rw_module: comparing shm_zone tag");
    if (shm_zone[i].tag != &ngx_http_limit_req_module) {
      ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                    "ngx_http_limit_req_rw_module: shm_zone tag is not "
                    "limit_req_module, skipping");
      continue;
    }

    ngx_log_error(
        NGX_LOG_DEBUG, r->connection->log, 0,
        "ngx_http_limit_req_rw_module: pushing new zone struct to array");
    zone_name = ngx_array_push(zones);
    if (zone_name == NULL) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "ngx_http_limit_req_rw_module: failed to push zone name");
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "ngx_http_limit_req_rw_module: copying zone name");
    *zone_name = &shm_zone[i].shm.name;
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "ngx_http_limit_req_rw_module: zone name copied");
  }

  ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                "ngx_http_limit_req_rw_module: packing array of zones");
  msgpack_pack_array(&pk, zones->nelts);
  zone_name = zones->elts;
  for (i = 0; i < zones->nelts; i++) {
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "ngx_http_limit_req_rw_module: packing zone %*s",
                  *zone_name[i]);
    msgpack_pack_str(&pk, zone_name[i]->len);
    msgpack_pack_str_body(&pk, zone_name[i]->data, zone_name[i]->len);
  }

  return NGX_OK;
}

static ngx_shm_zone_t *find_rate_limit_shm_zone_by_name(ngx_http_request_t *r,
                                                        ngx_str_t zone_name) {
  ngx_uint_t i;
  ngx_shm_zone_t *shm_zone;
  volatile ngx_list_part_t *part;

  if (ngx_cycle == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "ngx_http_limit_req_rw_module: ngx_cycle is NULL");
    return NULL;
  }

  part = &ngx_cycle->shared_memory.part;
  shm_zone = part->elts;

  for (i = 0; /* void */; i++) {

    if (i >= part->nelts) {
      if (part->next == NULL) {
        break;
      }
      part = part->next;
      shm_zone = part->elts;
      i = 0;
    }

    if (shm_zone == NULL) {
      continue;
    }

    if (shm_zone[i].tag != &ngx_http_limit_req_module) {
      continue;
    }

    if (shm_zone[i].shm.name.len != zone_name.len) {
      continue;
    }

    if (ngx_strncmp(zone_name.data, shm_zone[i].shm.name.data, zone_name.len) ==
        0) {
      return shm_zone;
    }
  }
  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_limit_req_rw_module: rate limit zone %*s not found",
                zone_name);
  return NULL;
}

static ngx_int_t dump_req_limits(ngx_pool_t *pool, ngx_shm_zone_t *shm_zone,
                                 ngx_buf_t *buf,
                                 ngx_uint_t last_greater_equal) {
  ngx_http_limit_req_ctx_t *ctx;
  ngx_queue_t *head, *q, *last;
  ngx_http_limit_req_node_t *lr;
  time_t now, now_monotonic;
  int i;

  now_monotonic = ngx_current_msec;
  // retrieving current timestamp in milliseconds
  now = ngx_cached_time->sec * 1000 + ngx_cached_time->msec;

  ctx = shm_zone->data;

  msgpack_packer pk;
  msgpack_packer_init(&pk, buf, msgpack_ngx_buf_write);

  // Including header
  msgpack_pack_array(&pk, 3);
  msgpack_pack_str(&pk, ctx->key.value.len);
  msgpack_pack_str_body(&pk, ctx->key.value.data, ctx->key.value.len);
  msgpack_pack_uint64(&pk, now);
  msgpack_pack_uint64(&pk, now_monotonic);

  ngx_shmtx_lock(&ctx->shpool->mutex);

  if (ngx_queue_empty(&ctx->sh->queue)) {
    ngx_shmtx_unlock(&ctx->shpool->mutex);
    return NGX_OK;
  }

  head = ngx_queue_head(&ctx->sh->queue);
  last = ngx_queue_last(head);
  q = head;

  for (i = 0; q != last && i < MAX_NUMBER_OF_RATE_LIMIT_ELEMENTS; i++) {
    lr = ngx_queue_data(q, ngx_http_limit_req_node_t, queue);
    if (last_greater_equal != 0 && lr->last < last_greater_equal) {
      break;
    }
    msgpack_pack_array(&pk, 3);

    msgpack_pack_str(&pk, lr->len);
    msgpack_pack_str_body(&pk, lr->data, lr->len);
    msgpack_pack_uint64(&pk, lr->last);
    msgpack_pack_int(&pk, lr->excess);

    q = q->next;
  }

  ngx_shmtx_unlock(&ctx->shpool->mutex);

  return NGX_OK;
}
