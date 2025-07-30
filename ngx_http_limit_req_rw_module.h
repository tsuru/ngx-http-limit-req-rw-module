/*
TODO: copyright
*/

#include "ngx_http_limit_req_module.h"
#include <nginx.h>
#include <ngx_conf_file.h>
#include <ngx_config.h>
#include <ngx_log.h>
#include <ngx_string.h>

#define MAX_NUMBER_OF_RATE_LIMIT_ELEMENTS (30000)

typedef struct {
  ngx_str_t Key;
  uint64_t Last;
  uint64_t Excess;
} entities;

typedef struct {
  ngx_str_t Key;         // Key of the rate limit zone
  uint64_t Now;          // Current timestamp in milliseconds
  uint64_t NowMonotonic; // Current monotonic timestamp in milliseconds
} header;

typedef struct {
  header *Header;        // Header information
  entities *Entities;    // Array of entities
  uint32_t EntitiesSize; // Size of the entities array
} ngx_zone_data_t;
