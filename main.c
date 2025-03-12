#include "ngx_http_limit_req_rw_message.pb-c.h"
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

uint8_t *read_binary_file(const char *filename, size_t *len) {
  FILE *file = fopen(filename, "rb");
  if (!file) {
    perror("Error opening file");
    return NULL;
  }

  // Park at position 0 counting from end of file
  fseek(file, 0, SEEK_END);
  // Get file length
  *len = ftell(file);
  if (*len == 0) {
    fprintf(stderr, "Error: File is empty\n");
    fclose(file);
    return NULL;
  }
  rewind(file);

  printf("File Size: %lu\n", *len);

  uint8_t *data = (uint8_t *)malloc(*len);
  if (!data) {
    perror("Memory allocation failed");
    fclose(file);
    return NULL;
  }

  size_t bytesRead = fread(data, 1, *len, file);
  if (bytesRead != *len) {
    fprintf(stderr, "Error: Read %zu of %zu bytes\n", bytesRead, *len);
    free(data);
    fclose(file);
    return NULL;
  }

  fclose(file);
  return data;
}

int main(int argc, char *argv[]) {
  size_t len, i;
  uint8_t *data;
  RateLimitZone *rateLimitZone;
  RateLimitValues *rateLimitValues;
  char str_addr[INET_ADDRSTRLEN];

  if (argc != 2) {
    fprintf(stderr, "Usage: %s <binary_file>\n", argv[0]);
    return EXIT_FAILURE;
  }

  data = read_binary_file(argv[1], &len);
  if (!data) {
    return EXIT_FAILURE;
  }
  printf("Read %zu bytes from %s\n", len, argv[1]);

  rateLimitZone = rate_limit_zone__unpack(NULL, len, data);
  if (rateLimitZone == NULL) {
    perror("Rate Limit Values Unpack Failed");
    free(data);
    return EXIT_FAILURE;
  }

  printf(
      "Sucessfully read rate limit zone - number of rate limit values: %lu\n",
      rateLimitZone->n_ratelimits);
  for (i = 0; i < rateLimitZone->n_ratelimits; i++) {
    rateLimitValues = rateLimitZone->ratelimits[i];
    if (inet_ntop(AF_INET, rateLimitValues->key.data, str_addr,
                  sizeof(str_addr)) == NULL) {
      perror("inet_ntop");
      rate_limit_zone__free_unpacked(rateLimitZone, NULL);
      return EXIT_FAILURE;
    } else {
      printf("key: %s - excess: %llu - last_request_timestamp: %llu\n",
             str_addr, rateLimitValues->excess, rateLimitValues->last);
    }
  }

  rate_limit_zone__free_unpacked(rateLimitZone, NULL);

  free(data);
  return EXIT_SUCCESS;
}
