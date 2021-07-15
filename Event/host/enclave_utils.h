#ifndef __ENCLAVE_UTILS_H__
#define __ENCLAVE_UTILS_H__

#include <stdint.h>

#include "networking.h"

typedef uint16_t io_index;
typedef uint16_t conn_index;

ResultMessage load_enclave(unsigned char* buf, uint32_t size);

void reactive_handle_output(conn_index conn_id, unsigned char *encrypt, uint32_t size, unsigned char *tag);
//void reactive_handle_input(sm_id sm, conn_index conn_id, void* data, size_t len);


#endif
