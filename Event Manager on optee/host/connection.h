#ifndef __CONNECTION_H__
#define __CONNECTION_H__

#include <stdint.h>

#include "addr.h"

#include "enclave_utils.h"
#include "tee_client_api.h"


typedef struct
{
    conn_index    conn_id;
    unsigned char  to_sm[16];
    uint16_t      to_node;
    uint16_t      to_port;
    ipv4_addr_t   to_address;
} Connection;

// Copies connection so may be stack allocated.
int connections_add(Connection* connection);

// We keep ownership of the returned Connection. May return NULL.
Connection* connections_get(uint16_t conn_id);


#endif
