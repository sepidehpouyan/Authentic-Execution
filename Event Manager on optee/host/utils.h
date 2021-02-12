#ifndef __UTILS_H__
#define __UTILS_H__

#include <stddef.h>

#define REVERSE_INT32(n) ((n << 24) | (((n>>16)<<24)>>16) | \
                                                (((n<<16)>>24)<<16) | (n>>24))
void *malloc_aligned(size_t size);

#endif
