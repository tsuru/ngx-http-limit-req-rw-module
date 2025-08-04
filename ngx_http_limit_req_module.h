// Copyright 2025 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
 * ngx_http_limit_req_module.h
 *
 * This header defines the core data structures and configuration types
 * used by the NGINX limit_req module for request rate limiting.
 * It provides definitions for configuration, shared memory, and
 * runtime structures that manage rate limiting state and logic.
 *
 * Structures:
 * - ngx_http_limit_req_conf_t: Per-location configuration for rate limiting.
 * - ngx_http_limit_req_limit_t: Defines a single rate limit and its parameters.
 * - ngx_http_limit_req_node_t: Represents a single rate limit entry in shared
 * memory.
 * - ngx_http_limit_req_shctx_t: Shared context for a rate limit zone (rbtree
 * and queue).
 * - ngx_http_limit_req_ctx_t: Runtime context for a rate limit zone.
 *
 * This file is intended to be included by both the module implementation
 * and any code that needs to interact with the limit_req shared memory zones.
 */

#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
  ngx_array_t limits;         // Array of ngx_http_limit_req_limit_t
  ngx_uint_t limit_log_level; // Log level for rate limiting events
  ngx_uint_t delay_log_level; // Log level for delayed requests
  ngx_uint_t status_code;     // HTTP status code to return when limiting
  ngx_flag_t dry_run;         // If set, only log but do not enforce limits
} ngx_http_limit_req_conf_t;

typedef struct {
  ngx_shm_zone_t *shm_zone; // Pointer to the shared memory zone for this limit
  ngx_uint_t burst;         // Allowed burst size (1 = 0.001 r/s)
  ngx_uint_t delay;         // Delay in milliseconds before enforcing limit
} ngx_http_limit_req_limit_t;

typedef struct {
  u_char color;      // Red-black tree node color
  u_char dummy;      // Padding for alignment
  u_short len;       // Length of the key
  ngx_queue_t queue; // Queue node for LRU (Least Recently Used) node management
  ngx_msec_t last;   // Last access time in milliseconds
  ngx_uint_t excess; // Excess requests over the rate limit (1 = 0.001 r/s)
  ngx_uint_t count;  // Number of requests in the current period
  u_char data[1];    // Key data (variable length)
} ngx_http_limit_req_node_t;

typedef struct {
  ngx_rbtree_t rbtree;        // Red-black tree for fast key lookup
  ngx_rbtree_node_t sentinel; // Sentinel node for the rbtree
  ngx_queue_t queue; // Queue for LRU (Least Recently Used) node eviction
} ngx_http_limit_req_shctx_t;

typedef struct {
  ngx_http_limit_req_shctx_t *sh; // Pointer to shared context (rbtree, queue)
  ngx_slab_pool_t *shpool;        // Slab pool for shared memory allocations
  ngx_uint_t rate;                // Rate limit (1 = 0.001 r/s)
  ngx_http_complex_value_t key; // Complex value for extracting the limiting key
  ngx_http_limit_req_node_t *node; // Pointer to the current node (if any)
} ngx_http_limit_req_ctx_t;

extern ngx_module_t ngx_http_limit_req_module;
