#ifndef __UUID_H__
#define __UUID_H__

#include <stdint.h>

#include "tee_client_api.h"


typedef struct
{
    TEEC_UUID     uuid;
    uint16_t      module_id;
} UUID;

int uuid_add(UUID* uuid);


UUID* uuid_get(uint16_t module_id);


#endif
