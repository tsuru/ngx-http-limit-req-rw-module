/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

 #include <ngx_core.h>

 typedef struct {
    ngx_array_t                  limits;
    ngx_uint_t                   limit_log_level;
    ngx_uint_t                   delay_log_level;
    ngx_uint_t                   status_code;
    ngx_flag_t                   dry_run;
} ngx_http_limit_req_conf_t;


extern ngx_module_t ngx_http_limit_req_module;