/*
TODO: copyright
*/

#include "ngx_http_limit_req_rw_module.h"
#include "ngx_http_limit_req_module.h"
#include "ngx_conf_file.h"
#include "ngx_core.h"
#include <ngx_http.h>
#include <stdio.h>

static ngx_int_t ngx_http_limit_req_read_handler(ngx_http_request_t *r);

char *ngx_http_limit_req_rw_handler(ngx_conf_t *cf, ngx_command_t *cmd,
                                    void *conf);
char *ngx_http_limit_req_global_zone(ngx_conf_t *cf, ngx_command_t *cmd,
                                    void *conf);

static ngx_command_t ngx_http_limit_req_rw_commands[] = {
    {ngx_string("limit_req_rw_handler"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS | NGX_CONF_TAKE1,
     ngx_http_limit_req_rw_handler, 0, 0, NULL},
    {ngx_string("limit_req_global_zone"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS | NGX_CONF_TAKE1,
     ngx_http_limit_req_global_zone, 0, 0, NULL},
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

static ngx_int_t ngx_http_limit_req_handler(ngx_http_request_t *r)
{
  if (r->method != NGX_HTTP_GET)
  {
    return NGX_HTTP_NOT_ALLOWED;
  }

  return ngx_http_limit_req_read_handler(r);
}

static ngx_int_t ngx_http_limit_req_read_handler(ngx_http_request_t *r)
{
  ngx_http_limit_req_conf_t *main_limit_req_config;
  main_limit_req_config = ngx_http_get_module_loc_conf(r, ngx_http_limit_req_module);


  printf("HELP! HELP!, size of config: %lu\n", main_limit_req_config->limits.size);
  printf("HELP! HELP!, found module! %p\n", main_limit_req_config);
  printf("HELP! HELP!, module index %lu\n", ngx_http_limit_req_module.index);
  printf("HELP! HELP!, module ctx index %p\n", r->ctx);

  ngx_buf_t *b;
  ngx_chain_t out;
  ngx_str_t response = ngx_string("Hello World");
  ngx_str_t content_type = ngx_string("text/plain");

  r->headers_out.content_type = content_type;
  r->headers_out.content_length_n = response.len;
  r->headers_out.status = NGX_HTTP_OK; /* 200 OK */

  ngx_http_send_header(r);

  b = ngx_create_temp_buf(r->pool, response.len);
  if (b == NULL)
  {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  ngx_memcpy(b->pos, response.data, response.len);
  b->last = b->pos + response.len;
  b->last_buf = 1;

  out.buf = b;
  out.next = NULL;

  return ngx_http_output_filter(r, &out);
}

char *ngx_http_limit_req_rw_handler(ngx_conf_t *cf, ngx_command_t *cmd,
                                    void *conf)
{
  ngx_http_core_loc_conf_t *clcf;

  clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
  clcf->handler = ngx_http_limit_req_handler;

  return NGX_CONF_OK;
}

char *ngx_http_limit_req_global_zone(ngx_conf_t *cf, ngx_command_t *cmd,
                                    void *conf)
{
  ngx_http_limit_req_conf_t *clcf;
  clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_limit_req_module);

  printf("HELP! HELP!, found global zone! %li\n", clcf->status_code);

  for(ngx_uint_t i = 0; i < clcf->limits.nelts; i++) {
    printf("HELP! HELP!, limit %lu\n", i);
  }

  return NGX_CONF_OK;
}
