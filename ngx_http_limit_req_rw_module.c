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
#include <stdio.h>
#include <time.h>
#include <msgpack.h>

#include "ngx_http_limit_req_module.h"


static ngx_int_t ngx_http_limit_req_read_handler(ngx_http_request_t *r);

static char *ngx_http_limit_req_rw_handler(ngx_conf_t *cf, ngx_command_t *cmd,
                                           void *conf);
static void strip_zone_name_from_uri(ngx_str_t *uri, ngx_str_t *zone_name);
static ngx_int_t dump_req_zone(ngx_pool_t *pool, ngx_buf_t *b,
                               ngx_str_t *zone_name);
static ngx_int_t dump_req_limits(ngx_pool_t *pool, ngx_shm_zone_t *shm_zone,
                                 ngx_buf_t *buf);
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
  ngx_str_t content_type, zone_name;
  ngx_int_t rc;
  ngx_buf_t *b;
  ngx_chain_t out;
  ngx_http_core_loc_conf_t* clcf;

  if (r->method != NGX_HTTP_GET) {
    return NGX_HTTP_NOT_ALLOWED;
  }

  clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

  printf("TODO: detect zone name by location suffix, location: %.*s, uri: %.*s\n", (int) clcf->name.len, clcf->name.data, (int) r->uri.len, r->uri.data);

  printf("TODO: if empty zone name, show only zone names\n");

  strip_zone_name_from_uri(&r->uri, &zone_name);
  printf("ZoneName: %.*s", (int)zone_name.len, zone_name.data);

  b = ngx_create_temp_buf(r->pool, 1024 * 10);
  if (b == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  rc = dump_req_zone(r->pool, b, &zone_name);
  if (rc != NGX_OK) {
    return rc;
  }

  ngx_str_set(&content_type, "application/vnd.msgpack");
  r->headers_out.content_type = content_type;
  printf("Content-Length: %lu\n", b->last - b->pos);
  r->headers_out.content_length_n = b->last - b->pos;
  r->headers_out.status = NGX_HTTP_OK; /* 200 OK */

  b->last_buf = (r == r->main) ? 1 : 0; /* if subrequest 0 else 1 */
  b->last_in_chain = 1;

  out.buf = b;
  out.next = NULL;

  rc = ngx_http_send_header(r);
  printf("RC: %li - headers only: %u - header sent %u\n", rc, r->header_only,
         r->header_sent);
  if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
    return rc;
  }
  printf("Content-Length: %lu\n", b->last - b->pos);

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

static ngx_int_t dump_req_zone(ngx_pool_t *pool, ngx_buf_t *b,
                               ngx_str_t *zone_name) {
  ngx_uint_t i;
  ngx_shm_zone_t *shm_zone;
  volatile ngx_list_part_t *part;


  if (ngx_cycle == NULL) {
    printf("ngx_cycle is NULL\n");
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

    if (ngx_strcmp(zone_name, &shm_zone[i].shm.name) == 0) {
      return dump_req_limits(pool, &shm_zone[i], b);
    }
  }
  return NGX_HTTP_NOT_FOUND;
}

static inline int msgpack_ngx_buf_write(void* data, const char* buf, size_t len)
{
  ngx_buf_t* b = (ngx_buf_t*)data;
  b->last = ngx_cpymem(b->last, buf, len);
  return 0;
}

static ngx_int_t dump_req_limits(ngx_pool_t *pool, ngx_shm_zone_t *shm_zone,
                                 ngx_buf_t *buf) {
  ngx_http_limit_req_ctx_t *ctx;
  ngx_queue_t *head, *q, *last;
  ngx_http_limit_req_node_t *lr;
  char str_addr[INET_ADDRSTRLEN];
  time_t now, now_monotonic, last_request_timestamp;

  ctx = shm_zone->data;
  printf("shm.name %p -> %.*s - rate: %lu \n", ctx, (int)shm_zone->shm.name.len,
         shm_zone->shm.name.data, ctx->rate);

  ngx_shmtx_lock(&ctx->shpool->mutex);

  if (ngx_queue_empty(&ctx->sh->queue)) {
    ngx_shmtx_unlock(&ctx->shpool->mutex);
    return NGX_HTTP_NO_CONTENT;
  }

  head = ngx_queue_head(&ctx->sh->queue);
  last = ngx_queue_last(head);
  q = head;

  // retrieving current timestamp in milliseconds
  now = ngx_cached_time->sec * 1000 + ngx_cached_time->msec;

  msgpack_packer pk;
  msgpack_packer_init(&pk, buf, msgpack_ngx_buf_write);

  while (q != last) {
    lr = ngx_queue_data(q, ngx_http_limit_req_node_t, queue);
    // retrieving current monotonic timestamp in milliseconds
    now_monotonic = ngx_current_msec;
    // calculate last request timestamp based on this equation:
    // NOW - (NOW_MONOTONIC - LAST_MONOTONIC)
    last_request_timestamp = now - (now_monotonic - lr->last);

    if (inet_ntop(AF_INET, lr->data, str_addr, sizeof(str_addr)) == NULL) {
      perror("inet_ntop");
    } else {
      printf("key: %s - excess: %lu - last_request_timestamp: %lu - now(var): "
             "%lu\n",
             str_addr, lr->excess, last_request_timestamp, now);
    }

    msgpack_pack_array(&pk, 3);

    msgpack_pack_str(&pk, lr->len);
    msgpack_pack_str_body(&pk, lr->data, lr->len);
    msgpack_pack_uint64(&pk, last_request_timestamp);
    msgpack_pack_int(&pk, lr->excess);

    q = q->next;
  }


  ngx_shmtx_unlock(&ctx->shpool->mutex);

  return NGX_OK;
}