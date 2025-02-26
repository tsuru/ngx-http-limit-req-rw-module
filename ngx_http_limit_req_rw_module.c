/*
TODO: copyright
*/

#include "ngx_http_limit_req_rw_module.h"
#include "ngx_conf_file.h"
#include "ngx_core.h"
#include "ngx_http_limit_req_module.h"
#include <ngx_http.h>
#include <stdio.h>

static ngx_int_t ngx_http_limit_req_read_handler(ngx_http_request_t *r);

static char *ngx_http_limit_req_rw_handler(ngx_conf_t *cf, ngx_command_t *cmd,
                                           void *conf);

static void dump_req_limits();
static void dump_req_limit(ngx_shm_zone_t *shm_zone);

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

  dump_req_limits();

  ngx_buf_t *b;
  ngx_chain_t out;
  ngx_str_t response = ngx_string("Hello World");
  ngx_str_t content_type = ngx_string("text/plain");

  r->headers_out.content_type = content_type;
  r->headers_out.content_length_n = response.len;
  r->headers_out.status = NGX_HTTP_OK; /* 200 OK */

  ngx_http_send_header(r);

  b = ngx_create_temp_buf(r->pool, response.len);
  if (b == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  ngx_memcpy(b->pos, response.data, response.len);
  b->last = b->pos + response.len;
  b->last_buf = 1;

  out.buf = b;
  out.next = NULL;

  return ngx_http_output_filter(r, &out);
}

static char *ngx_http_limit_req_rw_handler(ngx_conf_t *cf, ngx_command_t *cmd,
                                           void *conf) {
  ngx_http_core_loc_conf_t *clcf;

  clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
  clcf->handler = ngx_http_limit_req_handler;

  return NGX_CONF_OK;
}

static void dump_req_limits() {
  ngx_uint_t i;
  ngx_shm_zone_t *shm_zone;
  volatile ngx_list_part_t *part;

  if (ngx_cycle == NULL) {
    printf("ngx_cycle is NULL\n");
    return;
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

    dump_req_limit(&shm_zone[i]);
  }
}

static void dump_req_limit(ngx_shm_zone_t *shm_zone) {
  ngx_http_limit_req_ctx_t *ctx;
  ngx_queue_t *head, *q;
  ngx_http_limit_req_node_t *lr;
  char str_addr[INET_ADDRSTRLEN];

  ctx = shm_zone->data;
  printf("shm.name %p -> %.*s - rate: %lu \n", shm_zone->data,
         (int)shm_zone->shm.name.len, shm_zone->shm.name.data, ctx->rate);

  ngx_shmtx_lock(&ctx->shpool->mutex);

  if (ngx_queue_empty(&ctx->sh->queue)) {
    ngx_shmtx_unlock(&ctx->shpool->mutex);
    return;
  }

  head = ngx_queue_head(&ctx->sh->queue);
  q = ngx_queue_last(head);

  while (q != head) {
    lr = ngx_queue_data(q, ngx_http_limit_req_node_t, queue);

    if (inet_ntop(AF_INET, lr->data, str_addr, sizeof(str_addr)) == NULL) {
      perror("inet_ntop");
    } else {
      printf("key: %s - excess: %lu - count: %lu \n", str_addr, lr->excess,
             lr->last);
    }
    q = q->prev;
  }

  ngx_shmtx_unlock(&ctx->shpool->mutex);
}
