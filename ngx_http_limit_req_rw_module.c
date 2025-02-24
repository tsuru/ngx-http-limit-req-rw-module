/*
TODO: copyright
*/

#include "ngx_http_limit_req_rw_module.h"
#include <ngx_http.h>
#include <stdio.h>

static ngx_int_t ngx_http_limit_req_read_handler(ngx_http_request_t *r);

static void *ngx_http_limit_req_rw_create_main_conf(ngx_conf_t *cf);

static void *ngx_http_limit_req_rw_create_loc_conf(ngx_conf_t *cf);

static ngx_int_t ngx_http_limit_req_rw_init(ngx_conf_t *cf) {
  ngx_http_handler_pt *h;
  ngx_http_core_main_conf_t *cmcf;

  ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, "http vts init");

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  /* limit handler */
  h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }

  *h = ngx_http_limit_req_read_handler;

  return NGX_OK;
}

static ngx_http_module_t ngx_http_limit_req_rw_module_ctx = {
    NULL,                       /* preconfiguration */
    ngx_http_limit_req_rw_init, /* postconfiguration */

    ngx_http_limit_req_rw_create_main_conf, /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_limit_req_rw_create_loc_conf, /* create location configuration */
    NULL                                   /* merge location configuration */
};

ngx_module_t ngx_http_limit_req_rw_module = {
    NGX_MODULE_V1, &ngx_http_limit_req_rw_module_ctx,
    NULL,          NGX_HTTP_MODULE,
    NULL,          NULL,
    NULL,          NULL,
    NULL,          NULL,
    NULL,          NGX_MODULE_V1_PADDING};

static ngx_int_t ngx_http_limit_req_read_handler(ngx_http_request_t *r) {
  ngx_http_limit_req_rw_ctx_t *ctx;
  ngx_http_limit_req_rw_loc_conf_t *conf;

  ctx = ngx_http_get_module_main_conf(r, ngx_http_limit_req_rw_module);

  conf = ngx_http_get_module_loc_conf(r, ngx_http_limit_req_rw_module);

  printf("read handler\n");
  printf("uri: %s\n", r->uri.data);
  printf("tsuru-conf: %lu\n", ctx->tsuru);
  printf("tsuru-loc-conf: %d\n", conf->tsuru_conf);
  return NGX_OK;
}

static void *ngx_http_limit_req_rw_create_main_conf(ngx_conf_t *cf) {
  ngx_http_limit_req_rw_ctx_t *ctx;

  ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_req_rw_ctx_t));
  if (ctx == NULL) {
    return NULL;
  }

  ctx->tsuru = 2025;

  return ctx;
}

static void *ngx_http_limit_req_rw_create_loc_conf(ngx_conf_t *cf) {
  ngx_http_limit_req_rw_loc_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_req_rw_loc_conf_t));
  if (conf == NULL) {
    return NULL;
  }

  conf->tsuru_conf = 1;

  return conf;
}
