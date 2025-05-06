/*
TODO: copyright
*/

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_buf.h>
#include <ngx_conf_file.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http_request.h>
#include <ngx_string.h>
#include <ngx_times.h>
#include <ngx_http.h>
#include <ngx_log.h>
#include <stdio.h>
#include <time.h>
#include <msgpack.h>

#include "ngx_http_limit_req_module.h"

const int MAX_NUMBER_OF_RATE_LIMIT_ELEMENTS = 30 * 1000;

static ngx_int_t ngx_http_limit_req_read_handler(ngx_http_request_t *r);

static char *ngx_http_limit_req_rw_handler(ngx_conf_t *cf, ngx_command_t *cmd,
                                           void *conf);
static void strip_zone_name_from_uri(ngx_str_t *uri, ngx_str_t *zone_name);
static ngx_int_t dump_rate_limit_zones(ngx_http_request_t *r, ngx_buf_t *b);
static ngx_int_t dump_req_zone(ngx_pool_t *pool, ngx_buf_t *b,
                               ngx_str_t *zone_name, ngx_uint_t last_greater_equal);
static ngx_int_t dump_req_limits(ngx_pool_t *pool, ngx_shm_zone_t *shm_zone,
                                 ngx_buf_t *buf, ngx_uint_t last_greater_equal);
static ngx_command_t ngx_http_limit_req_rw_commands[] = {
    {ngx_string("limit_req_rw_handler"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_NOARGS | NGX_CONF_TAKE1,
     ngx_http_limit_req_rw_handler, 0, 0, NULL},
    ngx_null_command};

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
  if (r->method != NGX_HTTP_GET) {
    return NGX_HTTP_NOT_ALLOWED;
  }

  return ngx_http_limit_req_read_handler(r);
}

static ngx_int_t ngx_http_limit_req_read_handler(ngx_http_request_t *r) {
  ngx_str_t content_type, zone_name, last_greater_equal_arg;
  ngx_int_t last_greater_equal;
  ngx_int_t rc;
  ngx_buf_t *b;
  ngx_chain_t out;
  ngx_http_core_loc_conf_t *clcf;

  if (r->method != NGX_HTTP_GET) {
    return NGX_HTTP_NOT_ALLOWED;
  }

  clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

  b = ngx_create_temp_buf(r->pool, 1024 * 1024);
  if (b == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  if (clcf == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "ngx_http_limit_req_rw_module: clcf is NULL");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }
  ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "ngx_http_limit_req_rw_module: Processing request for URI: %V", &r->uri);
  ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                "ngx_http_limit_req_rw_module: clcf->name: %V", &clcf->name);
  // When request location is /api
  if (clcf->name.len == r->uri.len) {
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "ngx_http_limit_req_rw_module: dumping rate limit zones");
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "ngx_http_limit_req_rw_module: r: %p", r);
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "ngx_http_limit_req_rw_module: r->pool: %p", r->pool);
    rc = dump_rate_limit_zones(r, b);
    // When request location is /api/{zone_name}
  } else {
    strip_zone_name_from_uri(&r->uri, &zone_name);
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "zone name: %.*s",
                   (int)zone_name.len, zone_name.data);
    last_greater_equal_arg.len = 0;
    last_greater_equal = 0;
    if (r->args.len) {
      if (ngx_http_arg(r, (u_char *) "last_greater_equal", 18, &last_greater_equal_arg) == NGX_OK) {
          last_greater_equal = ngx_atoi(last_greater_equal_arg.data, last_greater_equal_arg.len);
          if (last_greater_equal == NGX_ERROR || last_greater_equal < 0) {
              return NGX_HTTP_BAD_REQUEST;
          }
      }
    }
    rc = dump_req_zone(r->pool, b, &zone_name, (ngx_uint_t) last_greater_equal);
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
  ngx_str_t *zone_name;
  ngx_uint_t i;
  ngx_shm_zone_t *shm_zone;
  volatile ngx_list_part_t *part;

  ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                "ngx_http_limit_req_rw_module: dump_rate_limit_zones called");

  if (ngx_cycle == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "ngx_http_limit_req_rw_module: ngx_cycle is NULL");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  msgpack_packer pk;
  msgpack_packer_init(&pk, buf, msgpack_ngx_buf_write);
  zones = ngx_array_create(r->pool, 0, sizeof(ngx_str_t));
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
                      "ngx_http_limit_req_rw_module: part->next is NULL, breaking out of loop");
        break;
      }
      ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                    "ngx_http_limit_req_rw_module: part->next is not NULL, advancing");
      part = part->next;
      shm_zone = part->elts;
      i = 0;
      ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                    "ngx_http_limit_req_rw_module: new part->nelts %d", part->nelts);
    }

    if (shm_zone == NULL) {
      ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                    "ngx_http_limit_req_rw_module: shm_zone is NULL, continuing");
      continue;
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "ngx_http_limit_req_rw_module: comparing shm_zone tag");
    if (shm_zone[i].tag != &ngx_http_limit_req_module) {
      ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                    "ngx_http_limit_req_rw_module: shm_zone tag is not limit_req_module, continuing");
      continue;
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "ngx_http_limit_req_rw_module: pushing new zone struct to array");
    zone_name = ngx_array_push(zones);
    if (zone_name == NULL) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "ngx_http_limit_req_rw_module: failed to push zone name");
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "ngx_http_limit_req_rw_module: copying shm name len to new zone struct");
    zone_name->len = shm_zone[i].shm.name.len;
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "ngx_http_limit_req_rw_module: allocating memory for zone name string");
    zone_name->data = ngx_pnalloc(r->pool, zone_name->len);
    if (zone_name->data == NULL) {
      zones->nelts--;
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "ngx_http_limit_req_rw_module: copying zone name string");
    ngx_memcpy(zone_name->data, shm_zone[i].shm.name.data, zone_name->len);
  }

  ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                "ngx_http_limit_req_rw_module: packing array of zones");
  msgpack_pack_array(&pk, zones->nelts);
  ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                "ngx_http_limit_req_rw_module: packing zone name");
  zone_name = zones->elts;
  for (i = 0; i < zones->nelts; i++) {
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "ngx_http_limit_req_rw_module: packing zone name %.*s",
                  (int)zone_name[i].len, zone_name[i].data);
    msgpack_pack_str(&pk, zone_name[i].len);
    msgpack_pack_str_body(&pk, zone_name[i].data, zone_name[i].len);
  }

  return NGX_OK;
}

static ngx_int_t dump_req_zone(ngx_pool_t *pool, ngx_buf_t *b,
                               ngx_str_t *zone_name, ngx_uint_t last_greater_equal) {
  ngx_uint_t i;
  ngx_shm_zone_t *shm_zone;
  volatile ngx_list_part_t *part;

  if (ngx_cycle == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
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

    if (ngx_strncmp(zone_name->data, shm_zone[i].shm.name.data, shm_zone[i].shm.name.len) == 0) {
      return dump_req_limits(pool, &shm_zone[i], b, last_greater_equal);
    }
  }
  return NGX_HTTP_NOT_FOUND;
}

static ngx_int_t dump_req_limits(ngx_pool_t *pool, ngx_shm_zone_t *shm_zone,
                                 ngx_buf_t *buf, ngx_uint_t last_greater_equal) {
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

  ngx_log_debug4(
      NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "shm.name %p -> %.*s - rate: %lu",
      ctx, (int)shm_zone->shm.name.len, shm_zone->shm.name.data, ctx->rate);

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
