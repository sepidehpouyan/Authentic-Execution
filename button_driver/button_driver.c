#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <button_driver.h>
#include <authentic_execution.h>

void find_input_func(uint16_t io_id, unsigned char* data){
	switch (io_id)
	{
	  	default:
		  	break;
	}
}

void button_pressed(void *session, unsigned char *data, uint32_t data_len){
	//struct aes_cipher *sess;
	//sess = (struct aes_cipher *)session;
	uint16_t output_id = 0;
	handle_output(session, data, data_len, output_id);
}

TEE_Result entry(void *session, uint32_t param_types, TEE_Param params[4]){

	const uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_MEMREF_INOUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT);

	//struct aes_cipher *sess;
	//sess = (struct aes_cipher *)session;
	uint32_t data_len = params[0].value.a;

	unsigned char *data;
	data = malloc(data_len);
	memcpy(data, params[2].memref.buffer, data_len);
	printf("***************Button is Pressed inside entry func****************\n");
	//unsigned char data[16] = {0};
	//data[0]= 0x01;
	button_pressed(session, data, data_len);
	free(data);
	return TEE_SUCCESS;
}



