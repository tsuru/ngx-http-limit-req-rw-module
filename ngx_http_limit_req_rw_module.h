

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
  ngx_int_t tsuru;
} ngx_http_limit_req_rw_ctx_t;

typedef struct {
  int tsuru_conf;
} ngx_http_limit_req_rw_loc_conf_t;
