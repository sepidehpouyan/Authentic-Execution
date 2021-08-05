#ifndef BUTTON_DRIVER_H
#define BUTTON_DRIVER_H

#include <tee_internal_api.h>

#define BUTTON_DRIVER_UUID \
	{ 0xd3bc8433, 0x2eb5, 0x4c00, { 0xa0, 0x05, 0x3f, 0x87, 0xc1, 0xd3, 0xb4, 0x05} }


TEE_Result entry(void *session, uint32_t param_types, TEE_Param params[4]);
void find_input_func(uint16_t io_id, unsigned char* data);

void button_pressed(void *session, unsigned char *data, uint32_t data_len);

#endif 
