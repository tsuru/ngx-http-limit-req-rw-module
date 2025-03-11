/*
TODO: copyright
*/

#include "ngx_http_limit_req_rw_module.h"
#include "ngx_buf.h"
#include "ngx_conf_file.h"
#include "ngx_core.h"
#include "ngx_http_limit_req_module.h"
#include "ngx_http_limit_req_rw_message.pb-c.h"
#include "ngx_string.h"
#include "ngx_times.h"
#include <ngx_http.h>
#include <stdio.h>
#include <time.h>

typedef struct {
  ProtobufCBuffer base;
  ngx_buf_t *b;
} BufferAppendToNginx;

static void nginx_buffer_append(ProtobufCBuffer *buffer, size_t len,
                                const uint8_t *data) {
  BufferAppendToNginx *nginx_buf = (BufferAppendToNginx *)buffer;
  nginx_buf->b->last = ngx_sprintf(nginx_buf->b->last, "LENGTH: %lu\n", len);
  // BufferAppendToNginx *file_buf = (BufferAppendToNginx *) buffer;
  // fwrite(data, len, 1, file_buf->fp); // XXX: No error handling!
}

static ngx_int_t ngx_http_limit_req_read_handler(ngx_http_request_t *r);

static char *ngx_http_limit_req_rw_handler(ngx_conf_t *cf, ngx_command_t *cmd,
                                           void *conf);

static void dump_req_limits(ngx_buf_t *b);
static void dump_req_limit(ngx_shm_zone_t *shm_zone, BufferAppendToNginx *buf);

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
  ngx_int_t rc;
  ngx_buf_t *b;
  ngx_chain_t out;

  b = ngx_create_temp_buf(r->pool, 1024);
  if (b == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  dump_req_limits(b);
  printf("Content-Length: %lu\n", b->last - b->pos);

  r->headers_out.content_type_len = sizeof("text/plain") - 1;
  r->headers_out.content_type.data = (u_char *)"text/plain";

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

static void dump_req_limits(ngx_buf_t *b) {
  ngx_uint_t i;
  ngx_shm_zone_t *shm_zone;
  volatile ngx_list_part_t *part;

  BufferAppendToNginx buf = {};
  buf.b = b;
  buf.base.append = nginx_buffer_append;

  if (ngx_cycle == NULL) {
    printf("ngx_cycle is NULL\n");
    return;
  }

  part = &ngx_cycle->shared_memory.part;
  shm_zone = part->elts;

  printf("\n");
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

    dump_req_limit(&shm_zone[i], &buf);
  }

  return;
}

static void dump_req_limit(ngx_shm_zone_t *shm_zone, BufferAppendToNginx *buf) {
  ngx_http_limit_req_ctx_t *ctx;
  ngx_queue_t *head, *q, *last;
  ngx_http_limit_req_node_t *lr;
  char str_addr[INET_ADDRSTRLEN];
  time_t now, now_monotonic, last_request_timestamp;
  RateLimitValues rate_limit;

  ctx = shm_zone->data;
  printf("shm.name %p -> %.*s - rate: %lu \n", shm_zone->data,
         (int)shm_zone->shm.name.len, shm_zone->shm.name.data, ctx->rate);

  rate_limit_values__init(&rate_limit);

  ngx_shmtx_lock(&ctx->shpool->mutex);

  if (ngx_queue_empty(&ctx->sh->queue)) {
    ngx_shmtx_unlock(&ctx->shpool->mutex);
    return;
  }

  head = ngx_queue_head(&ctx->sh->queue);
  last = ngx_queue_last(head);
  q = head;

  // retrieving current timestamp in milliseconds
  now = ngx_cached_time->sec * 1000 + ngx_cached_time->msec;

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
    rate_limit.key.len = lr->len;
    rate_limit.key.data = lr->data;
    rate_limit.excess = lr->excess;
    rate_limit.last = last_request_timestamp;

    rate_limit_values__pack_to_buffer(&rate_limit, (ProtobufCBuffer *)buf);
    q = q->next;
  }

  ngx_shmtx_unlock(&ctx->shpool->mutex);
}
