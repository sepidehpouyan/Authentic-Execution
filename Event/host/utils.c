#include "utils.h"

#include <stdlib.h>

void *malloc_aligned(size_t size) {
  size += size % 2;

  return malloc(size);
}
