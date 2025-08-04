// Copyright 2025 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
This header defines the data structures and constants used by the
ngx_http_limit_req_rw_module, which provides read/write access to NGINX's
limit_req shared memory zones for rate limiting. It is intended to be used with
the ngx_http_limit_req_rw_module.c implementation.

Structures:
- entities: Represents a single rate limit entry (key, last access time, excess
count).
- header: Contains metadata for a batch of rate limit entries (zone key,
timestamps).
- ngx_zone_data_t: Container for a header and an array of entities, used for
serialization/deserialization.

Constants:
- MAX_NUMBER_OF_RATE_LIMIT_ELEMENTS: Maximum number of rate limit entries to
process in a single operation.
*/

#include "ngx_http_limit_req_module.h"
#include <nginx.h>
#include <ngx_conf_file.h>
#include <ngx_config.h>
#include <ngx_log.h>
#include <ngx_string.h>

#define MAX_NUMBER_OF_RATE_LIMIT_ELEMENTS (30000)

/**
 * Represents a single rate limit entity.
 * Key:      The identifier for the rate limit entry.
 * Last:     The last access timestamp (milliseconds).
 * Excess:   The excess count for the rate limit.
 */
typedef struct {
  ngx_str_t Key;
  uint64_t Last;
  uint64_t Excess;
} entities;

/**
 * Header metadata for a batch of rate limit entities.
 * Key:           The key of the rate limit zone.
 * Now:           The current timestamp in milliseconds.
 * NowMonotonic:  The current monotonic timestamp in milliseconds.
 */
typedef struct {
  ngx_str_t Key;         // Key of the rate limit zone
  uint64_t Now;          // Current timestamp in milliseconds
  uint64_t NowMonotonic; // Current monotonic timestamp in milliseconds
} header;

/**
 * Container for header and entities array, used for
 * serialization/deserialization. Header:        Pointer to header metadata.
 * Entities:      Pointer to array of entities.
 * EntitiesSize:  Number of entities in the array.
 */
typedef struct {
  header *Header;        // Header information
  entities *Entities;    // Array of entities
  uint32_t EntitiesSize; // Size of the entities array
} ngx_zone_data_t;
